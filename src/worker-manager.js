'use strict';
// ════════════════════════════════════════════════════════════════════════════
// worker-manager.js — Host-side spawner for `src/workers/*.worker.js`
//
// This file is the **only** sanctioned home for `new Worker(...)` outside
// `src/workers/*.worker.js` itself. The build-time gate in
// `scripts/build.py::_check_worker_spawn_allowlist` enforces this.
//
// Lifecycle, fallback, and preemption contract
// --------------------------------------------
//   1. `_probe()` runs once per session. It tries to spawn a trivial worker
//      from a `blob:` URL; the browser may refuse (Firefox's `file://`
//      default is to deny `Worker(blob:)`). If construction throws, the
//      probe persistently caches `false` and every subsequent call rejects
//      with `Error('workers-unavailable')` — callers fall back to the
//      synchronous in-tree path.
//   2. Each `run*` call spawns one worker, transfers the buffer, and
//      resolves on `{event:'done'}` or rejects on `{event:'error'}` /
//      `onerror`. The worker is `terminate()`-d in every terminal branch
//      so we never leak.
//   3. A monotonic per-channel token is bumped on every call. Stale
//      messages from a superseded worker are dropped at receive time.
//      The matching `cancel*()` helper bumps the token and terminates the
//      active worker — `_loadFile` calls every canceller on entry so
//      each new file abandons every previous in-flight job. **Supersession
//      releases the prior job's resources synchronously**: the pending
//      `setTimeout`, the `reject` callback, and the captured payload
//      buffer reference are all cleared, and the prior promise is rejected
//      with `Error('superseded')`. Without this release the closure of a
//      superseded job would pin a multi-megabyte buffer for up to
//      `WORKER_TIMEOUT_MS` (5 min) until the timer fired with a spurious
//      "watchdog timeout" toast for a job the user already moved past.
//      Callers recognise the `'superseded'` message and exit silently
//      (no sync fallback, no error UI) the same way they recognise
//      `'workers-unavailable'`.
//   4. **Timeout.** Every job is bracketed by a
//      `PARSER_LIMITS.WORKER_TIMEOUT_MS` (5 min) deadline. On expiry the
//      worker is `terminate()`-d (real preemption — the worker's JS
//      engine is killed mid-iteration, unlike the post-hoc main-thread
//      `ParserWatchdog`) and the promise rejects with a watchdog-shaped
//      error carrying the same sentinel fields `ParserWatchdog.run`
//      uses (`_watchdogTimeout`, `_watchdogName`, `_watchdogTimeoutMs`)
//      so callers that already branch on `err._watchdogTimeout` continue
//      to work without modification. Callers fall back to the synchronous
//      in-tree path on **any** rejection — workers-unavailable, worker-
//      reported error, or watchdog timeout — so adding the timeout does
//      not change the host-side recovery shape.
//
// Buffer ownership
// ----------------
// `postMessage(buffer, [buffer])` **transfers** ownership: the worker
// gains the bytes, the main thread loses them. Auto-YARA happens on every
// load, and the rest of the pipeline still needs the buffer, so the
// caller must pass a `buffer.slice(0)` copy. The cost is one memcpy of the
// scan buffer; cheap relative to the scan itself.
//
// Centralisation
// --------------
// All public `run*` methods funnel through the private `_runWorkerJob`
// helper below. The helper owns: probe gating, supersession (token +
// terminate), spawn-failure → "workers-unavailable" demotion, message /
// error wiring, stale-token drops, **timeout-via-terminate**, and the
// finalisation/cleanup path. Each public `runYara` / `runTimeline` /
// `runEncoded` is a thin wrapper that supplies the per-channel state and
// payload shape; adding a new worker channel takes ~25 lines instead of
// ~80.
// ════════════════════════════════════════════════════════════════════════════

window.WorkerManager = (function () {

  // ── Probe state (per session) ────────────────────────────────────────────
  // null = untested; true / false = cached result. The probe is cheap (one
  // worker that immediately self-closes), but caching keeps the negative
  // path from throwing a console error every time `runYara` is called on a
  // file:// browser that refuses Worker(blob:).
  let _available = null;

  // ── Active worker tracking ───────────────────────────────────────────────
  // We supersede on each call — the most-recent scan is what the analyst
  // sees in the sidebar. The token-and-terminate pattern guarantees that a
  // stale `done` from a previous scan never overwrites the current results.
  // Each channel has its own slot: an active-worker handle (or null), a
  // monotonic token that's bumped on supersession / cancellation, and a
  // `currentJob` record carrying the per-call cleanup hook so a
  // superseding call (or `_cancelChannel`) can release the prior job's
  // `setTimeout`, `reject`, and captured payload reference instead of
  // letting them sit in the closure for the full timeout window.
  const _channels = {
    yara:       { active: null, token: 0, currentJob: null },
    timeline:   { active: null, token: 0, currentJob: null },
    encoded:    { active: null, token: 0, currentJob: null },
    iocExtract: { active: null, token: 0, currentJob: null },
  };

  function _probe() {
    if (_available !== null) return _available;
    // No-op worker source: just close. Successful construction means the
    // browser permits `Worker(blob:)` from this origin.
    const probeSrc = 'self.close();';
    let url = null;
    try {
      url = URL.createObjectURL(new Blob([probeSrc], { type: 'text/javascript' }));
      const w = new Worker(url);
      try { w.terminate(); } catch (_) { /* best-effort */ }
      _available = true;
    } catch (_) {
      _available = false;
    } finally {
      if (url) { try { URL.revokeObjectURL(url); } catch (_) {} }
    }
    return _available;
  }

  /**
   * Spawn a worker from one of the inlined bundle constants.
   * The build script (`scripts/build.py`) prepends each constant
   * (`__YARA_WORKER_BUNDLE_SRC`, `__TIMELINE_WORKER_BUNDLE_SRC`,
   * `__ENCODED_WORKER_BUNDLE_SRC`) to the top of the application script
   * block. Each bundle is a self-contained concatenation of: shim →
   * vendored deps (if any) → in-tree deps → `*.worker.js` dispatcher.
   *
   * @param {string} bundleSrc  the `__*_WORKER_BUNDLE_SRC` string
   * @param {string} channel    'yara' | 'timeline' | 'encoded'
   *                            (used only in the missing-bundle error)
   */
  function _spawnFromBundle(bundleSrc, channel) {
    if (typeof bundleSrc !== 'string' || !bundleSrc) {
      throw new Error(
        `worker bundle missing — build.py did not inject the ` +
        `${channel} worker bundle constant`
      );
    }
    const blob = new Blob([bundleSrc], { type: 'text/javascript' });
    const url  = URL.createObjectURL(blob);
    let w;
    try {
      w = new Worker(url);
    } finally {
      // Safe to revoke immediately — the Worker holds an internal reference
      // to the resource, the URL handle is only needed for construction.
      try { URL.revokeObjectURL(url); } catch (_) {}
    }
    return w;
  }

  /**
   * Internal job runner shared by every public `run*` method. Owns:
   *   • probe gating + spawn-failure demotion
   *   • supersession (token bump + terminate of any prior active worker)
   *   • message / error wiring and stale-token drops
   *   • timeout-via-terminate
   *   • cleanup (terminate + clear active handle on every terminal branch)
   *
   * @param {object}   spec
   * @param {string}   spec.channel       'yara' | 'timeline' | 'encoded'
   * @param {string}   spec.bundleSrc     the `__*_WORKER_BUNDLE_SRC` constant
   * @param {object}   spec.payload       the body of `postMessage()` (no buffers)
   * @param {Transferable[]} [spec.transfers]  optional transfer list
   * @param {(msg:any)=>any} spec.decodeDone  build the resolved value
   *                                          from a `{event:'done', ...}` msg
   * @param {number}  [spec.timeoutMs]    deadline; defaults to
   *                                      `PARSER_LIMITS.WORKER_TIMEOUT_MS`
   *                                      (5 min). Pass 0 / negative to opt out.
   * @param {(batch:any)=>void} [spec.onBatch]  optional sink for streaming
   *                                      worker events (e.g. `{event:'rows',
   *                                      batch:[...]}` from the timeline
   *                                      worker). Each non-terminal event
   *                                      whose `event` is not `'done'` /
   *                                      `'error'` is forwarded here so
   *                                      large jobs can hand rows back in
   *                                      pieces instead of one giant
   *                                      structured-clone postback at the
   *                                      end. The hook may throw — the job
   *                                      is rejected with the thrown error.
   * @returns {Promise<*>}
   */
  function _runWorkerJob(spec) {
    if (!_probe()) return Promise.reject(new Error('workers-unavailable'));

    const ch = _channels[spec.channel];
    if (!ch) return Promise.reject(new Error('runWorkerJob: unknown channel ' + spec.channel));

    // Supersede any in-flight job from a previous call on this channel
    // BEFORE capturing our token. Releasing the prior `currentJob`
    // clears its pending `setTimeout`, rejects its promise with
    // `Error('superseded')`, and drops the closure's reference to the
    // captured payload — without this the buffer would stay live (and
    // the spurious 5-min watchdog timer would still be queued) until
    // the prior timer fired naturally.
    //
    // Critically, `prior.abort()` bumps `ch.token` itself (so any
    // racing onmessage / onerror from the prior worker is treated as
    // stale on arrival). Capturing OUR `myToken` afterwards ensures it
    // reflects the post-abort counter — otherwise our own onmessage
    // would see `myToken !== ch.token` and be silently dropped, leaving
    // the new promise to hang indefinitely. Production code masks this
    // by always calling `cancelYara()` (which empties `currentJob`)
    // before `runYara()`; the bug surfaces on any back-to-back
    // `_runWorkerJob` call without an intervening cancel.
    if (ch.currentJob) {
      const prior = ch.currentJob;
      ch.currentJob = null;
      try { prior.abort(new Error('superseded')); } catch (_) {}
    }
    if (ch.active) {
      try { ch.active.terminate(); } catch (_) {}
      ch.active = null;
    }
    const myToken = ++ch.token;

    let w;
    try {
      w = _spawnFromBundle(spec.bundleSrc, spec.channel);
    } catch (_) {
      // Spawn failure post-probe (e.g. resource exhaustion, late CSP veto).
      // Demote to "workers-unavailable" so the caller falls back permanently
      // for the rest of the session.
      _available = false;
      return Promise.reject(new Error('workers-unavailable'));
    }
    ch.active = w;

    // `PARSER_LIMITS.WORKER_TIMEOUT_MS` is defined unconditionally in
    // `src/constants.js` and `worker-manager.js` already requires the rest
    // of the constants bundle to be loaded at runtime — falling back to a
    // hard-coded literal here was drift bait (the literal would silently
    // diverge from the canonical constant). Read the constant directly.
    const timeoutMs = (typeof spec.timeoutMs === 'number')
      ? spec.timeoutMs
      : PARSER_LIMITS.WORKER_TIMEOUT_MS;

    return new Promise((resolve, reject) => {
      let settled = false;
      let timer   = null;
      // Holds the current job's externally-visible cleanup hook. Cleared
      // on every terminal branch so the closure can release `spec.payload`
      // (and therefore the transferred buffer view we still hold a name
      // for here) immediately rather than waiting for the GC sweep that
      // follows the next `_runWorkerJob` call.
      let jobRecord = null;

      const cleanup = () => {
        if (timer !== null) { clearTimeout(timer); timer = null; }
        try { w.terminate(); } catch (_) {}
        if (ch.active === w) ch.active = null;
        if (jobRecord && ch.currentJob === jobRecord) ch.currentJob = null;
      };
      const finish = (fn, val) => {
        if (settled) return;
        settled = true;
        cleanup();
        fn(val);
      };

      // Register the supersession / cancellation hook. Calling
      // `abort(err)` clears the pending timer, terminates the worker,
      // detaches the active-handle slot, and rejects this promise with
      // `err` — releasing the closure's reference to `spec.payload` so
      // a multi-megabyte transferred buffer is no longer pinned for the
      // remainder of the timeout window. Callers that recognise
      // `err.message === 'superseded'` should bail silently the same
      // way they bail on `'workers-unavailable'`.
      jobRecord = {
        abort: (err) => {
          if (settled) return;
          // Bump the token so any in-flight onmessage / onerror that
          // races us is treated as stale and dropped on arrival.
          ch.token++;
          finish(reject, err || new Error('superseded'));
        },
      };
      ch.currentJob = jobRecord;

      // ── Timeout — real preemption via worker.terminate() ──
      // The error shape deliberately mirrors `ParserWatchdog.run`'s
      // sentinel fields so callers that already branch on
      // `err._watchdogTimeout` (e.g. `app-load.js`'s renderer dispatch
      // catch) continue to work without modification.
      if (timeoutMs > 0) {
        timer = setTimeout(() => {
          if (settled) return;
          // Bump the token so any onmessage / onerror that fires between
          // now and the next event-loop tick is treated as stale.
          ch.token++;
          settled = true;
          cleanup();
          const secs = (timeoutMs / 1000) | 0;
          const err = new Error(
            `Worker "${spec.channel}" timed out after ${secs}s — ` +
            `terminated to preempt a hostile or runaway scan.`
          );
          err._watchdogTimeout   = true;
          err._watchdogName      = spec.channel;
          err._watchdogTimeoutMs = timeoutMs;
          // Surface the worker-side preemption to the dev-mode breadcrumb
          // ribbon. Guarded so a missing mixin or pre-init termination can
          // never break the existing reject path.
          try {
            if (typeof window !== 'undefined' &&
                window.app &&
                typeof window.app._breadcrumb === 'function') {
              window.app._breadcrumb('worker:' + spec.channel, 'timeout', { timeoutMs });
            }
          } catch (_) { /* breadcrumb best-effort, never block reject */ }
          reject(err);
        }, timeoutMs);
      }

      w.onmessage = (ev) => {
        // Drop stale results from a superseded job.
        if (myToken !== ch.token) {
          if (!settled) { settled = true; cleanup(); }
          return;
        }
        const m = ev && ev.data ? ev.data : {};
        if (m.event === 'done') {
          let decoded;
          try { decoded = spec.decodeDone(m); }
          catch (decodeErr) { finish(reject, decodeErr); return; }
          finish(resolve, decoded);
        } else if (m.event === 'error') {
          finish(reject, new Error(m.message || 'worker reported error'));
        } else if (typeof spec.onBatch === 'function') {
          // Streaming non-terminal event (e.g. {event:'rows', batch:[...]}).
          // Forward to the caller's sink. Sink errors abort the job.
          try { spec.onBatch(m); }
          catch (sinkErr) { finish(reject, sinkErr); return; }
        }
        // Other events without an `onBatch` sink are silently ignored —
        // future channels may emit progress updates that the host doesn't
        // care to consume.
      };
      w.onerror = (e) => {
        if (myToken !== ch.token) {
          if (!settled) { settled = true; cleanup(); }
          return;
        }
        const msg = (e && e.message) ? e.message : 'worker error';
        finish(reject, new Error(msg));
      };

      // Transfer the buffer(s). Caller is responsible for sending a copy
      // if it needs the bytes again — every in-tree caller does exactly
      // that.
      try {
        w.postMessage(spec.payload, spec.transfers || []);
      } catch (e) {
        finish(reject, e);
      }
    });
  }

  /**
   * Cancel any in-flight job on the named channel. Idempotent — safe to
   * call when nothing is in flight. The `_loadFile` entry point calls
   * every channel's canceller so a new file abandons every previous
   * scan / parse.
   *
   * @param {string} channel  'yara' | 'timeline' | 'encoded'
   */
  function _cancelChannel(channel) {
    const ch = _channels[channel];
    if (!ch) return;
    ch.token++;
    // Release the prior job synchronously — this rejects its promise
    // with `Error('superseded')`, clears its pending timer, and drops
    // the closure's reference to the captured payload so the buffer is
    // no longer pinned for the remainder of the timeout window.
    if (ch.currentJob) {
      const prior = ch.currentJob;
      ch.currentJob = null;
      try { prior.abort(new Error('superseded')); } catch (_) {}
    }
    if (ch.active) {
      try { ch.active.terminate(); } catch (_) {}
      ch.active = null;
    }
  }

  // ── Public per-channel wrappers ──────────────────────────────────────────
  // Each wrapper is a thin shim over `_runWorkerJob` that supplies the
  // channel name, the inlined bundle constant, the per-message payload
  // shape, and the `decodeDone` reducer. Default timeout is
  // `PARSER_LIMITS.WORKER_TIMEOUT_MS` for every channel.

  /** Run a YARA scan in a worker. Returns a Promise.
   *  Resolves with `{ results, scanErrors, parseMs, scanMs, ruleCount }`.
   *  `scanErrors` is the optional per-string diagnostics list emitted by
   *  `YaraEngine.scan(..., { errors })` (invalid regex, iteration cap,
   *  wall-clock cap). Empty array when nothing tripped.
   *  Rejects with `Error('workers-unavailable')` when the probe failed
   *  (caller falls back to the synchronous path), `Error(...)` with
   *  `_watchdogTimeout=true` on timeout, or with the worker's reported
   *  error otherwise.
   *  @param {ArrayBuffer} buffer  bytes to scan; will be transferred
   *  @param {string} source       YARA rule source (parseRules input)
   *  @param {object} [opts]       optional: `{ formatTag: string }` —
   *                                Loupe's detected file format (the
   *                                `dispatchId` produced by
   *                                `RendererRegistry.detect()`, or a
   *                                script-language sniff for plaintext).
   *                                Forwarded to the worker so rule
   *                                conditions can evaluate `is_*`
   *                                predicates and `meta: applies_to`
   *                                gates. Omit on legacy callers — the
   *                                engine treats absence safely (no
   *                                `is_*` matches; `applies_to` rules
   *                                skip). */
  function runYara(buffer, source, opts) {
    const formatTag = (opts && typeof opts.formatTag === 'string') ? opts.formatTag : null;
    const payload = { buffer, source };
    if (formatTag) payload.formatTag = formatTag;
    return _runWorkerJob({
      channel:   'yara',
      bundleSrc: typeof __YARA_WORKER_BUNDLE_SRC !== 'undefined' ? __YARA_WORKER_BUNDLE_SRC : '',
      payload,
      transfers: [buffer],
      decodeDone: (m) => ({
        results:    m.results    || [],
        scanErrors: m.scanErrors || [],
        parseMs:    m.parseMs    || 0,
        scanMs:     m.scanMs     || 0,
        ruleCount:  m.ruleCount  || 0,
      }),
    });
  }
  function cancelYara() { _cancelChannel('yara'); }

  /** Run a curated YARA pass against a list of decoded encoded-content
   *  payloads. Returns a Promise.
   *
   *  Resolves with `{ hits, parseMs, scanMs, payloadCount, ruleCount }` —
   *  `hits` is `[{ id, results }]` (only payloads with ≥1 rule match are
   *  included; empty match sets are pruned worker-side to keep the
   *  postback tight). `id` is the host-supplied key passed in the
   *  matching slot of `payloads`.
   *
   *  Rejects with `Error('workers-unavailable')` when the probe failed
   *  (caller should skip the gate — decoded findings stay as-is),
   *  `Error('superseded')` when a newer load supersedes us, `Error(...)`
   *  with `_watchdogTimeout=true` on timeout, or with the worker's reported
   *  error otherwise.
   *
   *  Implementation: the payloads are concatenated into one Uint8Array
   *  with an offsets table (length = N+1). The single resulting
   *  ArrayBuffer is **transferred** — there's typically no host-side use
   *  for the packed buffer after the postMessage call (the original
   *  per-payload Uint8Array views are still owned by the host's findings
   *  tree, separate from the packed copy made here). One ArrayBuffer
   *  transfer instead of N is significantly cheaper at structured-clone
   *  time on hundreds of small decoded payloads.
   *
   *  @param {Array<{id: string|number, bytes: Uint8Array}>} payloads
   *  @param {string}    source     YARA rule source (parseRules input)
   *  @param {object}    [opts]     `{ formatTag?: string }` — defaults to
   *                                `'decoded-payload'`. The synthetic
   *                                tag is registered in
   *                                `YaraEngine.FORMAT_PREDICATES.is_decoded_payload`
   *                                and rules opt in via
   *                                `meta: applies_to = "decoded-payload"`. */
  function runDecodedYara(payloads, source, opts) {
    if (!Array.isArray(payloads) || payloads.length === 0) {
      // Nothing to scan — resolve to an empty result so callers don't have
      // to special-case the empty-input branch.
      return Promise.resolve({
        hits: [], parseMs: 0, scanMs: 0, payloadCount: 0, ruleCount: 0,
      });
    }
    const formatTag = (opts && typeof opts.formatTag === 'string')
      ? opts.formatTag
      : 'decoded-payload';

    // Compute total size + offsets table. Empty payloads collapse to a
    // zero-length slice (no offset advancement) so `_dispatchMulti` skips
    // them cheaply.
    let total = 0;
    const offsets = new Array(payloads.length + 1);
    const ids     = new Array(payloads.length);
    offsets[0] = 0;
    for (let i = 0; i < payloads.length; i++) {
      const p = payloads[i];
      const len = (p && p.bytes && p.bytes.byteLength) || 0;
      total += len;
      offsets[i + 1] = total;
      ids[i] = (p && p.id !== undefined) ? p.id : i;
    }
    const packed = new Uint8Array(total);
    for (let i = 0; i < payloads.length; i++) {
      const p = payloads[i];
      const len = offsets[i + 1] - offsets[i];
      if (len > 0) packed.set(p.bytes, offsets[i]);
    }

    return _runWorkerJob({
      channel:   'yara',                      // shares the yara channel —
                                              // a newer file load's
                                              // auto-YARA supersedes us
                                              // automatically, which is
                                              // the desired behaviour.
      bundleSrc: typeof __YARA_WORKER_BUNDLE_SRC !== 'undefined' ? __YARA_WORKER_BUNDLE_SRC : '',
      payload: {
        mode:    'multi',
        source,
        formatTag,
        packed:  packed.buffer,
        offsets,
        ids,
      },
      transfers: [packed.buffer],
      decodeDone: (m) => ({
        hits:         m.hits         || [],
        parseMs:      m.parseMs      || 0,
        scanMs:       m.scanMs       || 0,
        payloadCount: m.payloadCount || 0,
        ruleCount:    m.ruleCount    || 0,
      }),
    });
  }

  /** Run a Timeline parse in a worker. Returns a Promise.
   *  Resolves with the worker's `done` payload (shape varies by `kind`):
   *    { kind, columns, rows, formatLabel, truncated, originalRowCount,
   *      parseMs, ...kind-specific extras }
   *  CSV/TSV  → no extras
   *  EVTX     → `evtxEvents` (parsed events minus `rawRecord`),
   *             `defaultTimeColIdx`, `defaultStackColIdx`
   *  SQLite   → `browserType`, `defaultTimeColIdx`, `defaultStackColIdx`
   *  Rejects with `Error('workers-unavailable')` when the probe failed
   *  (caller falls back to the synchronous path), `Error(...)` with
   *  `_watchdogTimeout=true` on timeout, or with the worker's reported
   *  error otherwise.
   *
   *  The buffer is **transferred**; pass `buffer.slice(0)` if the caller
   *  still needs the bytes for downstream analyser code. The Timeline
   *  caller does — `_loadFileInTimeline` keeps reading the buffer to
   *  drive the analyser sidebar after the parse returns.
   *
   *  @param {ArrayBuffer} buffer  bytes to parse; will be transferred
   *  @param {string}      kind    'csv' | 'evtx' | 'sqlite'
   *  @param {object}      [opts]  kind-specific options:
   *                                 csv: { explicitDelim?: ','|';'|'\t'|'|'|' ',
   *                                        kindHint?: 'log' | 'syslog3164' | null,
   *                                        fileLastModified?: number }
   *
   *  `kindHint: 'log'` is passed by the Timeline router for `.log` drops
   *  (and extensionless drops the CLF sniffer matched). It activates
   *  Apache / Nginx Common Log Format handling in the worker's CSV path
   *  — the bracketed-date pair is re-merged, the first row is treated
   *  as data, and canonical column names are applied.
   *
   *  Other `kindHint` values are structured-log dispatch tags
   *  (currently `'syslog3164'`; CEF/LEEF/logfmt/JSONL/Zeek are added
   *  in subsequent commits). They route the buffer to a dedicated
   *  per-format tokeniser inside the worker's CSV dispatcher and
   *  bypass the RFC-4180 state machine entirely. `fileLastModified`
   *  travels alongside so RFC 3164 timestamps (which lack a year)
   *  parse deterministically against the file's mtime. */
  function runTimeline(buffer, kind, opts) {
    if (kind !== 'csv' && kind !== 'evtx' && kind !== 'sqlite') {
      return Promise.reject(new Error('runTimeline: unknown kind ' + kind));
    }
    const explicitDelim = (opts && opts.explicitDelim) || undefined;
    const kindHint = (opts && opts.kindHint) || undefined;
    const fileLastModified = (opts && opts.fileLastModified) || undefined;
    const payload = { kind, buffer };
    if (explicitDelim) payload.explicitDelim = explicitDelim;
    if (kindHint)      payload.kindHint = kindHint;
    if (fileLastModified) payload.fileLastModified = fileLastModified;
    // `opts.onBatch(msg)` — optional sink for `{event:'rows', batch:[...]}`
    // streaming events from the worker. The CSV path uses this to ship rows
    // back in 50_000-row batches instead of one giant structured-clone
    // postback at the end (which doubles peak memory for hundreds-of-MB
    // inputs). EVTX / SQLite still hand back a single `done` payload.
    //
    // `opts.timeoutMs` — per-call override of `PARSER_LIMITS.WORKER_TIMEOUT_MS`.
    // The Timeline router scales this with file size for multi-hundred-MB
    // CSV / TSV files so legitimate large parses don't false-positive at the
    // default 5 min cap.
    return _runWorkerJob({
      channel:   'timeline',
      bundleSrc: typeof __TIMELINE_WORKER_BUNDLE_SRC !== 'undefined' ? __TIMELINE_WORKER_BUNDLE_SRC : '',
      payload,
      transfers: [buffer],
      decodeDone: (m) => m,   // Timeline payload is forwarded verbatim
      onBatch:   (opts && typeof opts.onBatch === 'function') ? opts.onBatch : undefined,
      timeoutMs: (opts && typeof opts.timeoutMs === 'number') ? opts.timeoutMs : undefined,
    });
  }
  function cancelTimeline() { _cancelChannel('timeline'); }

  /** Run an EncodedContentDetector scan in a worker. Returns a Promise.
   *  Resolves with `{ findings, parseMs }` — `findings` is the array
   *  returned by `EncodedContentDetector.scan()` with `_rawBytes` stripped
   *  from each entry (see `src/workers/encoded.worker.js`). The host
   *  `_loadFile` post-scan loop is responsible for re-stamping `_rawBytes`
   *  on compressed findings, merging `finding.iocs` into
   *  `findings.interestingStrings`, and threading `_sourceOffset` /
   *  `_highlightText` / `_decodedFrom` / `_encodedFinding` back-references.
   *
   *  Rejects with `Error('workers-unavailable')` when the probe failed
   *  (caller falls back to the synchronous path), `Error(...)` with
   *  `_watchdogTimeout=true` on timeout, or with the worker's reported
   *  error otherwise.
   *
   *  The buffer is **transferred**; pass `buffer.slice(0)` if the caller
   *  still needs the bytes. The `_loadFile` caller does — every downstream
   *  step (renderer, hashing, YARA, sidebar) reads the buffer after the
   *  scan returns.
   *
   *  @param {ArrayBuffer} buffer        bytes to scan; will be transferred
   *  @param {string}      textContent   decoded text passed to `scan()`
   *  @param {object}      [options]     forwarded to the detector:
   *                                       fileType?, mimeAttachments?,
   *                                       maxRecursionDepth?, maxCandidatesPerType? */
  /** Run an IOC mass-extract pass in a worker. Returns a Promise.
   *  Resolves with `{ findings, droppedByType, totalSeenByType, parseMs }`
   *  — the same triple `extractInterestingStringsCore` returns on the host
   *  side, with `droppedByType` / `totalSeenByType` rehydrated as Maps by
   *  this decoder (the worker postbacks them as plain `[k,v][]` arrays
   *  because Maps don't survive structured cloning cleanly across all
   *  browsers we target).
   *
   *  Rejects with `Error('workers-unavailable')` when the probe failed,
   *  `Error('superseded')` when a newer load supersedes us,
   *  `Error(...)` with `_watchdogTimeout=true` on timeout, or the worker's
   *  reported error otherwise. Callers fall back to the synchronous
   *  in-tree `_extractInterestingStrings` shim on any rejection.
   *
   *  Unlike the other channels this one does NOT take an ArrayBuffer —
   *  the IOC pass operates on `_rawText` (already decoded host-side) and
   *  a small flat `vbaModuleSources` string array. Both are passed by
   *  structured clone; nothing is transferred. The host keeps the text
   *  for the renderer / YARA / hashing pipeline.
   *
   *  This channel is intentionally **never** invoked for timeline-routed
   *  files (CSV / TSV / EVTX / SQLite browser-history) — those routes
   *  short-circuit `_loadFile` before the analyser block at
   *  `src/app/app-load.js:367` and never call `_extractInterestingStrings`.
   *  See the bypass invariant at `src/app/timeline/timeline-router.js:16-24`.
   *
   *  @param {string}   text                    augmented `_rawText`
   *  @param {object}   [opts]
   *  @param {string[]} [opts.vbaModuleSources] flattened VBA module sources
   *  @param {string[]} [opts.existingValues]   pre-seeded `seen` set so the
   *                                            worker dedupes against rows
   *                                            already pushed by the renderer
   *                                            (`findings.externalRefs` +
   *                                            `findings.interestingStrings`).
   *                                            Without this, the worker's
   *                                            per-type drop counts and
   *                                            `totalSeenByType` over-report
   *                                            on files where renderer-pushed
   *                                            URLs also appear in body text
   *                                            — the host re-dedup catches
   *                                            them at patch time, but the
   *                                            "Showing N of M URL" sidebar
   *                                            note ends up wrong. Marshalled
   *                                            as a flat string array.
   *  @param {boolean}  [opts.formatIsHtml]     true when the renderer
   *                                            already extracted URLs from
   *                                            HTML href/src attrs (caller
   *                                            still does that on the host) */
  function runIocExtract(text, opts) {
    const safeOpts = opts || {};
    return _runWorkerJob({
      channel:   'iocExtract',
      bundleSrc: typeof __IOC_EXTRACT_WORKER_BUNDLE_SRC !== 'undefined' ? __IOC_EXTRACT_WORKER_BUNDLE_SRC : '',
      payload: {
        text:             typeof text === 'string' ? text : '',
        vbaModuleSources: Array.isArray(safeOpts.vbaModuleSources) ? safeOpts.vbaModuleSources : [],
        existingValues:   Array.isArray(safeOpts.existingValues)   ? safeOpts.existingValues   : [],
        formatIsHtml:     !!safeOpts.formatIsHtml,
      },
      transfers: [],
      decodeDone: (m) => ({
        findings:         m.findings || [],
        droppedByType:    new Map(Array.isArray(m.droppedByType)    ? m.droppedByType    : []),
        totalSeenByType:  new Map(Array.isArray(m.totalSeenByType)  ? m.totalSeenByType  : []),
        parseMs:          m.parseMs  || 0,
      }),
    });
  }
  function cancelIocExtract() { _cancelChannel('iocExtract'); }

  function runEncoded(buffer, textContent, options) {
    return _runWorkerJob({
      channel:   'encoded',
      bundleSrc: typeof __ENCODED_WORKER_BUNDLE_SRC !== 'undefined' ? __ENCODED_WORKER_BUNDLE_SRC : '',
      payload: {
        textContent: typeof textContent === 'string' ? textContent : '',
        rawBytes:    buffer,
        options:     options || {},
      },
      transfers: [buffer],
      decodeDone: (m) => ({
        findings: m.findings || [],
        parseMs:  m.parseMs  || 0,
      }),
    });
  }
  function cancelEncoded() { _cancelChannel('encoded'); }

  /** Returns true when `Worker(blob:)` is usable for the rest of the
   *  session. Cached after first call. Auto-YARA uses this to decide
   *  whether the `SYNC_YARA_FALLBACK_MAX_BYTES` size gate still applies
   *  (the gate exists to protect the synchronous fallback; with a worker
   *  the scan can run on arbitrary sizes without freezing the UI). */
  function workersAvailable() {
    return _probe();
  }

  return {
    runYara,
    cancelYara,
    runDecodedYara,
    runTimeline,
    cancelTimeline,
    runEncoded,
    cancelEncoded,
    runIocExtract,
    cancelIocExtract,
    workersAvailable,
  };


})();
