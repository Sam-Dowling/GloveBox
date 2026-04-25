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
//      each new file abandons every previous in-flight job.
//   4. **Timeout.** Every job is bracketed by a
//      `PARSER_LIMITS.WORKER_TIMEOUT_MS` (2 min) deadline. On expiry the
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
  // Each channel has its own pair: an active-worker handle (or null) and a
  // monotonic token that's bumped on supersession / cancellation.
  const _channels = {
    yara:     { active: null, token: 0 },
    timeline: { active: null, token: 0 },
    encoded:  { active: null, token: 0 },
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
   *                                      (2 min). Pass 0 / negative to opt out.
   * @returns {Promise<*>}
   */
  function _runWorkerJob(spec) {
    if (!_probe()) return Promise.reject(new Error('workers-unavailable'));

    const ch = _channels[spec.channel];
    if (!ch) return Promise.reject(new Error('runWorkerJob: unknown channel ' + spec.channel));

    const myToken = ++ch.token;
    // Supersede any in-flight job from a previous call on this channel.
    if (ch.active) {
      try { ch.active.terminate(); } catch (_) {}
      ch.active = null;
    }

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

    const timeoutMs = (typeof spec.timeoutMs === 'number')
      ? spec.timeoutMs
      : (typeof PARSER_LIMITS !== 'undefined' && PARSER_LIMITS.WORKER_TIMEOUT_MS)
        ? PARSER_LIMITS.WORKER_TIMEOUT_MS
        : 120_000;

    return new Promise((resolve, reject) => {
      let settled = false;
      let timer   = null;

      const cleanup = () => {
        if (timer !== null) { clearTimeout(timer); timer = null; }
        try { w.terminate(); } catch (_) {}
        if (ch.active === w) ch.active = null;
      };
      const finish = (fn, val) => {
        if (settled) return;
        settled = true;
        cleanup();
        fn(val);
      };

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
        }
        // Ignore other events (progress, etc.) — none defined today, but
        // future channels may stream incremental updates without
        // resolving the promise.
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
   *  Resolves with `{ results, parseMs, scanMs, ruleCount }`.
   *  Rejects with `Error('workers-unavailable')` when the probe failed
   *  (caller falls back to the synchronous path), `Error(...)` with
   *  `_watchdogTimeout=true` on timeout, or with the worker's reported
   *  error otherwise.
   *  @param {ArrayBuffer} buffer  bytes to scan; will be transferred
   *  @param {string} source       YARA rule source (parseRules input) */
  function runYara(buffer, source) {
    return _runWorkerJob({
      channel:   'yara',
      bundleSrc: typeof __YARA_WORKER_BUNDLE_SRC !== 'undefined' ? __YARA_WORKER_BUNDLE_SRC : '',
      payload:   { buffer, source },
      transfers: [buffer],
      decodeDone: (m) => ({
        results:   m.results   || [],
        parseMs:   m.parseMs   || 0,
        scanMs:    m.scanMs    || 0,
        ruleCount: m.ruleCount || 0,
      }),
    });
  }
  function cancelYara() { _cancelChannel('yara'); }

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
   *                                 csv: { explicitDelim?: ','|';'|'\t'|'|' } */
  function runTimeline(buffer, kind, opts) {
    if (kind !== 'csv' && kind !== 'evtx' && kind !== 'sqlite') {
      return Promise.reject(new Error('runTimeline: unknown kind ' + kind));
    }
    const explicitDelim = (opts && opts.explicitDelim) || undefined;
    const payload = { kind, buffer };
    if (explicitDelim) payload.explicitDelim = explicitDelim;
    return _runWorkerJob({
      channel:   'timeline',
      bundleSrc: typeof __TIMELINE_WORKER_BUNDLE_SRC !== 'undefined' ? __TIMELINE_WORKER_BUNDLE_SRC : '',
      payload,
      transfers: [buffer],
      decodeDone: (m) => m,   // Timeline payload is forwarded verbatim
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
    runTimeline,
    cancelTimeline,
    runEncoded,
    cancelEncoded,
    workersAvailable,
  };


})();
