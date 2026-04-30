'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-router.js — App.prototype mixin: Timeline routing + lifecycle.
//
// Split out of the legacy app-timeline.js monolith. Provides:
//   _initTimelineState, _isTimelineExt, _sniffTimelineContent,
//   _timelineTryHandle, _loadFileInTimeline,
//   _buildTimelineViewFromWorker, _clearTimelineFile.
//
// Every CSV / TSV / EVTX / SQLite (browser-history) file routes through
// the Timeline view unconditionally via `_timelineTryHandle(file)`
// from `App._loadFile`. Returning truthy short-circuits the analyser
// pipeline — the file has been (or is being) rendered in the Timeline
// surface.
//
// **Analysis-bypass guard.** This file does NOT push IOCs, mutate
// `app.findings`, run `EncodedContentDetector`, or invoke `pushIOC`.
// EVTX *is* the sole exception, but only via
// `EvtxDetector.analyzeForSecurity` (called on the main thread after
// the worker hands back parsed events) and only to feed the in-view
// Detections + Entities sections inside `TimelineView` — never the
// global sidebar. Adding any IOC sweep / encoded-content pass here
// would silently turn forensic logs into analyser inputs and break
// the route's intentional analyser-free property.
//
// Worker-first loading: `_loadFileInTimeline` dispatches to
// `WorkerManager.runTimeline(buffer.slice(0), kind, opts)` and falls
// back to the synchronous `TimelineView.from{Csv,Evtx,Sqlite}`
// factories on `Error('workers-unavailable')` (Firefox file://) or
// any worker rejection. See `src/workers/timeline.worker.js` and
// `src/worker-manager.js`.
//
// Loads AFTER timeline-view.js (which declares `class TimelineView`
// and the mixins) and AFTER `app-core.js` (which declares `App`).
// ════════════════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════════════
// App mixin — Timeline routing + container lifecycle.
//
// Every CSV / TSV / EVTX file routes through the Timeline view unconditionally.
// There is no "Timeline mode" state on the App any more — a Timeline file is
// considered loaded iff `this._timelineCurrent` is non-null. `_loadFile`
// calls `_timelineTryHandle(file)`; if it returns truthy, the file has been
// (or is being) rendered in the Timeline surface and the analyser pipeline
// is skipped.
//
// Extensionless dispatch: `_sniffTimelineContent(buffer)` recognises the
// EVTX `ElfFile\0` magic and performs a light CSV / TSV text sniff so a
// dropped log with a missing or mislabelled extension still lands here
// instead of falling through to the plaintext renderer.
// ════════════════════════════════════════════════════════════════════════════
extendApp({

  _initTimelineState() {
    this._timelineCurrent = null;
  },

  // Pure extension check — used by the fast path in `_loadFile` before the
  // buffer is even read. EVTX files are also caught by the magic-byte pass
  // in `_sniffTimelineContent` so a renamed .evtx still lands here.
  _isTimelineExt(file) {
    if (!file || !file.name) return false;
    const ext = file.name.split('.').pop().toLowerCase();
    return TIMELINE_EXTS.has(ext);
  },

  // Content sniff for extensionless (or mis-named) timeline files. Returns
  // the ext to use (`'evtx'`, `'csv'`, `'tsv'`, `'log'`) or null.
  //
  // * EVTX: first 8 bytes = `ElfFile\0`.
  // * Apache / Nginx CLF: ≥ 60 % of the first 5 non-empty lines contain
  //   the bracketed CLF date token `[DD/Mon/YYYY:HH:MM:SS ±ZZZZ]`. This
  //   is unambiguous — the bracketed-date+timezone shape is essentially
  //   a magic string. Returned as `'log'` so the router applies the
  //   space delimiter and CLF cell-merge.
  // * CSV / TSV: decode the first ~4 KB as UTF-8, reject blobs that look
  //   like JSON / XML / shebangs, then try each of `,\t;|` and keep the
  //   delimiter that yields ≥ 2 consistent columns across ≥ 80% of the
  //   first ~20 non-empty lines. TSV wins if the tab version has more
  //   columns than the comma version.
  _sniffTimelineContent(buffer) {
    if (!buffer || buffer.byteLength < 8) return null;
    const bytes = new Uint8Array(buffer);
    // EVTX magic
    if (bytes.length >= 8
      && bytes[0] === 0x45 && bytes[1] === 0x6C && bytes[2] === 0x66
      && bytes[3] === 0x46 && bytes[4] === 0x69 && bytes[5] === 0x6C
      && bytes[6] === 0x65 && bytes[7] === 0x00) return 'evtx';

    // SQLite magic: "SQLite format 3\0" (first 16 bytes).
    // Only route to Timeline if the database is a browser history file
    // (Chrome / Edge / Firefox), otherwise fall through so the regular
    // SqliteRenderer's tabbed-grid view handles generic databases.
    if (bytes.length >= 16
      && bytes[0] === 0x53 && bytes[1] === 0x51 && bytes[2] === 0x4C
      && bytes[3] === 0x69 && bytes[4] === 0x74 && bytes[5] === 0x65
      && bytes[6] === 0x20 && bytes[7] === 0x66 && bytes[8] === 0x6F
      && bytes[9] === 0x72 && bytes[10] === 0x6D && bytes[11] === 0x61
      && bytes[12] === 0x74 && bytes[13] === 0x20 && bytes[14] === 0x33
      && bytes[15] === 0x00) {
      try {
        const r = new SqliteRenderer();
        const db = r._parseDb(new Uint8Array(buffer));
        if (db.browserType) return 'sqlite';
      } catch (_) { /* parse failed — fall through */ }
      return null;
    }

    // Text sniff — decode only the first 4 KB, tolerate a leading BOM.
    let text;
    try {
      const head = bytes.subarray(0, Math.min(bytes.length, 4096));
      text = new TextDecoder('utf-8', { fatal: false }).decode(head);
    } catch (_) { return null; }
    if (!text) return null;
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
    const trimmed = text.trimStart();
    if (!trimmed) return null;
    // Reject obvious non-tabular shapes: JSON, XML, shebangs, HTML fragments.
    //
    // Syslog RFC 3164 lines start with `<PRI>` — a 1-3 digit number in
    // angle brackets. The HTML/XML reject below would catch them too
    // (it triggers on a leading `<`), so we run a quick syslog probe
    // first and let those lines through. Other `<…>` content is still
    // rejected as before.
    const firstCh = trimmed.charAt(0);
    const _looksLikeSyslogHead =
      firstCh === '<' && /^<\d{1,3}>/.test(trimmed);
    // JSONL probe — runs BEFORE the JSON reject so newline-delimited
    // JSON streams (CloudTrail, container logs, fluentd / vector
    // sinks, application structured logging, etc.) get a dedicated
    // route rather than being rejected as "looks like JSON". A
    // single-line `[ ... ]` array or top-level `{ ... }` object is
    // still rejected as before — the discriminator is multiple
    // newline-separated `{...}` records each parseable on their own.
    //
    // Strategy: take the first 5 non-empty lines (after BOM
    // stripping) and try to `JSON.parse` each as an object. If
    // ≥60% succeed (matching the existing sniff threshold for
    // CLF / syslog), return 'jsonl'. We do NOT call `JSON.parse`
    // on the whole trimmed buffer — that would succeed for a single
    // multi-line JSON value (a non-JSONL file the analyser pipeline
    // would handle better).
    if (firstCh === '{') {
      const head = text.split(/\r\n|\r|\n/)
        .filter(l => l.length > 0).slice(0, 5);
      if (head.length >= 2) {
        let hits = 0;
        for (let i = 0; i < head.length; i++) {
          const t = head[i].trimStart();
          if (t.charCodeAt(0) !== 0x7B) continue;
          try {
            const v = JSON.parse(t);
            if (v && typeof v === 'object' && !Array.isArray(v)) hits++;
          } catch (_) { /* not a complete object on this line */ }
        }
        if (hits / head.length >= 0.6) return 'jsonl';
      }
    }
    if (firstCh === '{' || firstCh === '[') return null;
    if (firstCh === '<' && !_looksLikeSyslogHead) return null;
    if (trimmed.startsWith('#!') || trimmed.startsWith('<?')) return null;
    // C-family line comments (`//`) are a strong signal of source code
    // (JS, JXA, C, C#, Java, etc.) — not tabular data.  Without this
    // guard, semicolon-terminated languages consistently produce a 2-col
    // split on `;` that passes the 80 % confidence gate below.
    if (trimmed.startsWith('//')) return null;
    // Reject binary-ish heads (NUL in the first kB).
    if (text.indexOf('\u0000') !== -1) return null;
    // Reject tabular-but-not-CSV formats that happen to use `;` or tabs
    // as separators and would otherwise pass the delimiter probe:
    //   - SLK (Symbolic Link) — starts with `ID;` and uses `;`-delimited
    //     records; belongs to `IqySlkRenderer`, not the CSV viewer.
    //   - IQY (Excel Web Query) — starts with `WEB` on its own line and
    //     is handled by `IqySlkRenderer`.
    // Extensions for these land here only when the file is renamed /
    // extensionless, so sniffing is our only defence against mis-routing.
    if (trimmed.startsWith('ID;')) return null;
    if (/^WEB\s*\r?\n/.test(trimmed)) return null;


    const lines = text.split(/\r\n|\r|\n/).map(l => l).filter(l => l.length > 0).slice(0, 20);
    if (lines.length < 2) return null;
    // Apache / Nginx CLF sniff. The bracketed `[DD/Mon/YYYY:HH:MM:SS ±ZZZZ]`
    // token is essentially a magic signature — when ≥ 60 % of the first
    // 5 non-empty lines carry it the file is a web access log. Runs
    // before the delimiter-confidence loop because space-delimited
    // CLF lines would otherwise be rejected outright (the `,\t;|`
    // candidates all yield 1 column on a CLF line).
    const _CLF_LINE_RE = /\[\d{1,2}\/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]/i;
    {
      const head = lines.slice(0, 5);
      let hits = 0;
      for (let i = 0; i < head.length; i++) {
        if (_CLF_LINE_RE.test(head[i])) hits++;
      }
      if (head.length >= 2 && hits / head.length >= 0.6) return 'log';
    }
    // Zeek TSV sniff. Zeek files begin with a `#separator \x09`
    // directive on line 0 (literally — the value is `\x09`, the
    // 4-char escape sequence as written in the file, not an actual
    // tab byte). This is a magic prefix; nothing else uses it. The
    // Zeek sniff has to win against:
    //   - the syslog 3164 / 5424 sniffs (they don't match `#`-prefixed
    //     lines, so no conflict — we still place this first so the
    //     `'log'` ext upgrade loop short-circuits on the strongest
    //     signal first), and
    //   - the delimiter-confidence loop (Zeek's tab-separated rows
    //     would otherwise come back as `'tsv'`, which would parse
    //     correctly via CsvRenderer but lose the schema-aware column
    //     names + `#path`-derived format label + NILVALUE handling).
    if (lines[0] && /^#separator\s/.test(lines[0])) return 'zeek';
    // Syslog RFC 5424 sniff — runs BEFORE 3164 because the 5424
    // shape (`<PRI>VER ` with a digit version field) is a strict
    // superset of 3164's `<PRI>` prefix and we want the more specific
    // match to win. The discriminator is the digit-version+space
    // immediately after `>`; 3164 has a 3-letter month token there
    // instead, so the two regexes never both match the same line.
    const _SYSLOG5424_LINE_RE = /^<\d{1,3}>\d{1,2}\s\S/;
    {
      const head = lines.slice(0, 5);
      let hits = 0;
      for (let i = 0; i < head.length; i++) {
        if (_SYSLOG5424_LINE_RE.test(head[i])) hits++;
      }
      if (head.length >= 2 && hits / head.length >= 0.6) return 'syslog5424';
    }
    // Syslog RFC 3164 sniff. The `<PRI>MMM DD HH:MM:SS host …` shape
    // is essentially a magic prefix — there is no other format in the
    // wild that combines `<\d{1,3}>` with a 3-letter month, day, and
    // colon-separated time. Threshold matches the CLF sniff (≥60 % of
    // first 5 non-empty lines). Returned as `'syslog3164'` so the
    // router passes a dedicated `kindHint` through to the worker.
    const _SYSLOG3164_LINE_RE =
      /^<\d{1,3}>\s*(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+/i;
    {
      const head = lines.slice(0, 5);
      let hits = 0;
      for (let i = 0; i < head.length; i++) {
        if (_SYSLOG3164_LINE_RE.test(head[i])) hits++;
      }
      if (head.length >= 2 && hits / head.length >= 0.6) return 'syslog3164';
    }
    const candidates = [',', '\t', ';', '|'];
    let best = { delim: null, cols: 0, confidence: 0 };
    for (const d of candidates) {
      const counts = lines.map(l => l.split(d).length);
      const maxC = Math.max(...counts);
      if (maxC < 2) continue;
      const consistent = counts.filter(n => n === maxC).length;
      const confidence = consistent / counts.length;
      if (confidence >= 0.8 && maxC > best.cols) {
        best = { delim: d, cols: maxC, confidence };
      }
    }
    if (!best.delim) return null;
    return best.delim === '\t' ? 'tsv' : 'csv';
  },

  // Attempt to route `file` into the Timeline view. Called from `_loadFile`.
  //   - If the extension is one of csv / tsv / evtx / sqlite / db → always
  //     load (no gate). SQLite files that are NOT browser history databases
  //     return zero rows from `fromSqlite()`, which triggers the fallback
  //     escape hatch in `_loadFileInTimeline` back to the regular analyser.
  //   - Otherwise return `false` so the regular analyser pipeline runs.
  //
  // Extensionless files are handled separately inside `_loadFile` via the
  // magic + text sniff (see `_sniffTimelineContent`).
  _timelineTryHandle(file) {
    if (!this._isTimelineExt(file)) return false;
    // Fire-and-forget: `_loadFile` returns synchronously after we kick
    // the Timeline mount so the drop-zone unblocks. Track the promise
    // on the App so the test API can await full settlement before the
    // next load starts — without this, the zero-row escape's outer
    // `try { await _loadFile } finally { _skipTimelineRoute=false }`
    // can leak `_skipTimelineRoute=true` into the next file's load
    // (waitForIdle resolves on the inner `currentResult` set, before
    // the outer `finally` runs). Promise rejections are intentionally
    // swallowed here — the inner load's error path already toasts and
    // logs; this catch exists only to keep the unhandled-rejection
    // tracker quiet during tests.
    const p = this._loadFileInTimeline(file)
      .catch(() => { /* error already surfaced by _loadFileInTimeline */ });
    this._timelineLoadInFlight = p;
    p.then(() => {
      // Only clear if no later call has overwritten us.
      if (this._timelineLoadInFlight === p) this._timelineLoadInFlight = null;
    });
    return true;
  },

  async _loadFileInTimeline(file, prefetchedBuffer /* optional */) {
    // ── Chromium heap-budget pre-flight gate ──────────────────────────
    // The Timeline path's RowStore peaks at roughly
    // `file.size * ROWSTORE_HEAP_OVERHEAD_FACTOR` bytes on the main
    // heap. When the browser exposes `performance.memory.jsHeapSizeLimit`
    // (Chromium-only — Firefox / Safari intentionally don't expose it
    // and skip this gate silently) we refuse loads whose projected
    // footprint would exceed `jsHeapSizeLimit * ROWSTORE_HEAP_BUDGET_FRACTION`.
    // Refusing here surfaces an actionable toast instead of an OOM
    // tab-crash partway through parsing — the analyst can split or
    // pre-process the file, or close other heavy tabs to free heap.
    //
    // The non-Timeline path keeps its own coarser `LARGE_FILE_THRESHOLD`
    // gate (200 MB) and the existing sync-fallback refusal lower in
    // this method — both still fire as belt-and-braces guards on the
    // Chromium path AND as the only memory protection on
    // Firefox / Safari.
    try {
      const heapLimit = (typeof performance !== 'undefined'
        && performance.memory
        && typeof performance.memory.jsHeapSizeLimit === 'number')
        ? performance.memory.jsHeapSizeLimit : 0;
      if (heapLimit > 0 && file && typeof file.size === 'number') {
        const budget = heapLimit * RENDER_LIMITS.ROWSTORE_HEAP_BUDGET_FRACTION;
        const projected = file.size * RENDER_LIMITS.ROWSTORE_HEAP_OVERHEAD_FACTOR;
        if (projected > budget) {
          const sizeMb = (file.size / (1024 * 1024)).toFixed(0);
          const budgetMb = (budget / (1024 * 1024)).toFixed(0);
          this._toast(
            `File too large for available memory: ${sizeMb} MB needs ` +
            `~${(projected / (1024 * 1024)).toFixed(0)} MB but only ` +
            `~${budgetMb} MB heap is available. Close other tabs or ` +
            `split the file before loading.`,
            'error');
          return;
        }
      }
    } catch (_) { /* heap-introspection failure → skip gate, fall through */ }

    // Warn (non-blocking) for very large files so the analyst knows to
    // expect a longer load. The toast auto-dismisses after 5 s.
    if (file.size >= RENDER_LIMITS.HUGE_FILE_WARN) {
      const mb = (file.size / (1024 * 1024)).toFixed(0);
      this._toast(
        `Large file (${mb} MB) — loading may take a moment.`, 'info');
    }
    this._setLoading(true);
    try {
      if (this._timelineCurrent) {
        try { this._timelineCurrent.destroy(); } catch (_) { /* noop */ }
        this._timelineCurrent = null;
      }
      // Clear sidebar highlight active-view back-references — the previous
      // Timeline view's GridViewer is now destroyed, and the regular
      // `_setRenderResult` chokepoint (app-load.js) is skipped on the
      // Timeline → Timeline path. Without this, a stranded YARA / IOC
      // clear callback would call into the destroyed grid.
      this._yaraHighlightActiveView = null;
      this._iocCsvHighlightActiveView = null;
      const buffer = prefetchedBuffer
        || await ParserWatchdog.run(() => file.arrayBuffer());
      // Perf marker — buffer is now available; the next sub-phase is
      // worker dispatch + parse. No-op in release builds (the global
      // is only defined when `app-test-api.js` is concatenated into
      // the bundle by `scripts/build.py --test-api`).
      if (typeof window !== 'undefined' && window.__loupePerfMark) {
        window.__loupePerfMark('fileBufferReady');
      }
      // Resolve the effective extension — may come from the filename or,
      // for extensionless inputs, from the magic-byte / text sniff.
      //
      // `.log` is special-cased: real-world syslog files almost always
      // carry a `.log` extension (e.g. `/var/log/messages`,
      // `/var/log/auth.log`), so we run the content sniff over `.log`
      // inputs as well and let it upgrade us to a more specific
      // structured-log kind ('syslog3164', etc.) when the magic-prefix
      // pattern matches. CLF stays the default for `.log` when no
      // structured-log sniff fires.
      let ext = (file.name && file.name.indexOf('.') !== -1)
        ? file.name.split('.').pop().toLowerCase() : '';
      if (!TIMELINE_EXTS.has(ext)) {
        const sniffed = this._sniffTimelineContent(buffer);
        if (sniffed) ext = sniffed;
      } else if (ext === 'log') {
        const sniffed = this._sniffTimelineContent(buffer);
        // Only upgrade — don't downgrade. If the sniff returned 'log'
        // (CLF) or anything that's still in TIMELINE_EXTS, keep the
        // filename ext. Structured-log sniffs return strings outside
        // TIMELINE_EXTS ('syslog3164', etc.) so this filter promotes
        // them while preserving the CLF default.
        if (sniffed && !TIMELINE_EXTS.has(sniffed) && sniffed !== 'log') {
          ext = sniffed;
        }
      } else if (ext === 'jsonl' || ext === 'ndjson') {
        // The `.jsonl` / `.ndjson` extensions both unambiguously mean
        // newline-delimited JSON. Map them to the canonical `'jsonl'`
        // kindHint without re-sniffing — the parser handles invalid
        // lines gracefully (returns `null` and the line is skipped).
        ext = 'jsonl';
      }

      this._fileMeta = {
        name: file.name, size: file.size,
        mimeType: file.type || '',
        lastModified: file.lastModified
          ? new Date(file.lastModified).toISOString() : '',
      };
      this._renderBreadcrumbs();

      // ── Worker-first parse ───────────────────────────────
      // Try `WorkerManager.runTimeline(...)` first. The worker bundle is
      // parse-only — EVTX threat-detection and CSV obvious-malware
      // sweeps stay on the main thread (this method runs them after
      // the worker `done`). On `Error('workers-unavailable')` (Firefox
      // file:// or any spawn refusal) or any other failure we fall
      // through to the legacy synchronous TimelineView factories so
      // every load path stays usable. See `src/workers/timeline.worker.js`.
      let view = null;
      let workerKind = null;
      if (ext === 'evtx') workerKind = 'evtx';
      else if (ext === 'csv' || ext === 'tsv' || ext === 'log'
            || ext === 'syslog3164' || ext === 'syslog5424'
            || ext === 'zeek' || ext === 'jsonl') workerKind = 'csv';
      else if (ext === 'sqlite' || ext === 'db') workerKind = 'sqlite';

      if (workerKind && window.WorkerManager
          && typeof window.WorkerManager.runTimeline === 'function'
          && window.WorkerManager.workersAvailable && window.WorkerManager.workersAvailable()) {
        try {
          // ── Buffer ownership ──
          // `transferOriginal` controls only whether we hand the worker
          // the live ArrayBuffer (zero-copy) or a `slice(0)` duplicate.
          // It is independent of row streaming — Phase 6 promoted EVTX
          // and SQLite to the same `rows-chunk` protocol CSV uses, so
          // every kind streams now.
          //
          // Why CSV transfers and EVTX / SQLite copy:
          //   - CSV / TSV: the host has no further use for the buffer
          //     post-parse (no analyzer side-channel; the zero-row
          //     escape hatch re-reads via `_loadFile`'s re-fetch path).
          //     Transferring saves a 318 MB memcpy on multi-hundred-MB
          //     drops — empirically halves peak memory there.
          //   - EVTX: main thread still needs the buffer to drive
          //     `EvtxDetector.analyzeForSecurity` post-parse.
          //   - SQLite: the zero-row escape hatch passes `buffer` to
          //     `_loadFile` so the file isn't re-read from disk.
          const transferOriginal = (workerKind === 'csv');
          const transfer = transferOriginal ? buffer : buffer.slice(0);

          // ── Streaming RowStore builder (every kind) ──
          // The worker emits `{event:'rows-chunk', bytes, offsets,
          // rowCount}` every `WORKER_CHUNK_ROWS` rows. Each chunk's
          // two ArrayBuffers ride the postMessage transfer list
          // (zero-copy across the worker boundary), so we wrap them
          // in typed-array views and hand them straight to
          // `RowStoreBuilder.addChunk`. The structured-clone of the
          // legacy `string[][]` batch — which doubled main-thread peak
          // memory on the postback hand-off — is gone for every kind.
          //
          // W4: the worker now emits a `{event:'columns', columns}`
          // event AHEAD of the first `rows-chunk`, so we can construct
          // `RowStoreBuilder` and `addChunk` straight into it as the
          // chunks land — no buffering. `pendingChunks` is the legacy
          // fallback path: if a future worker bundle (or one that
          // failed mid-header) never emits the early columns event,
          // chunks accumulate in `pendingChunks` until the terminal
          // `done` provides columns, then we replay them. Empty header
          // files also hit the fallback (the worker skips
          // `_postColumns` when `columns.length === 0`).
          let builder = null;
          const pendingChunks = [];
          let rowsSeen = 0;
          let lastSubtitleAt = 0;
          // Perf-marker latches — flipped on the FIRST observation of
          // each event kind so the harness sees worker→host first-byte
          // and first-row deltas separately. Subsequent events don't
          // re-stamp (we want the FIRST arrival, not the last).
          let perfColumnsSeen = false;
          let perfFirstChunkSeen = false;
          const onBatch = (m) => {
            if (!m) return;
            if (m.event === 'columns') {
              if (!perfColumnsSeen && typeof window !== 'undefined'
                  && window.__loupePerfMark) {
                window.__loupePerfMark('workerColumnsEvent');
                perfColumnsSeen = true;
              }
              // W4 early-mount path. Build the RowStoreBuilder NOW
              // and replay any chunks that snuck in before the
              // columns event (shouldn't happen with the current
              // worker, but the worker → host event order isn't
              // strictly guaranteed by the postMessage contract, so
              // tolerate either ordering).
              const cols = Array.isArray(m.columns) ? m.columns : [];
              if (cols.length && !builder) {
                builder = new RowStoreBuilder(cols);
                if (pendingChunks.length) {
                  for (let i = 0; i < pendingChunks.length; i++) {
                    builder.addChunk(pendingChunks[i]);
                  }
                  pendingChunks.length = 0;
                }
              }
              return;
            }
            if (m.event !== 'rows-chunk') return;
            if (!perfFirstChunkSeen && typeof window !== 'undefined'
                && window.__loupePerfMark) {
              window.__loupePerfMark('workerFirstChunk');
              perfFirstChunkSeen = true;
            }
            // Wrap the transferred buffers as typed-array views.
            // Buffers are detached on the worker side post-transfer,
            // so this is a zero-copy view into the bytes we own now.
            const rc = m.rowCount | 0;
            if (rc <= 0) return;
            const chunk = {
              bytes:    new Uint8Array(m.bytes),
              offsets:  new Uint32Array(m.offsets),
              rowCount: rc,
            };
            if (builder) {
              // W4 fast path — chunks land directly into the builder
              // as they arrive, so the post-`done` "assemble" loop
              // becomes a single `finalize()` call instead of an
              // O(chunks) replay of buffered references.
              builder.addChunk(chunk);
            } else {
              // Legacy fallback — buffer until the terminal `done`
              // (or a late `columns` event) provides the column list.
              pendingChunks.push(chunk);
            }
            rowsSeen += rc;
            // Live progress subtitle. Throttle updates to roughly
            // one per 100 ms via a wall-clock comparison so high-
            // frequency chunk flushes don't churn the DOM.
            const now = (typeof performance !== 'undefined'
              && performance.now) ? performance.now() : Date.now();
            if (now - lastSubtitleAt >= 100) {
              lastSubtitleAt = now;
              try {
                if (typeof this._setLoadingSubtitle === 'function') {
                  this._setLoadingSubtitle(
                    rowsSeen.toLocaleString() + ' rows…');
                }
              } catch (_) { /* best-effort progress UI */ }
            }
          };

          // ── Per-call timeout ──
          // Default `PARSER_LIMITS.WORKER_TIMEOUT_MS` is 5 min; for
          // very large CSV / TSV files we scale roughly with size
          // (~500 ms per MB of input plus the 5 min floor) so a 318 MB
          // parse on a slow disk doesn't false-positive at the cap.
          // Cap at 30 min — beyond that the user should pre-process
          // the file rather than wait inside the analyser.
          const baseTimeout = (typeof PARSER_LIMITS !== 'undefined'
            && PARSER_LIMITS.WORKER_TIMEOUT_MS) || 300_000;
          const sizeTimeout = Math.min(
            30 * 60_000,
            Math.max(baseTimeout, ((file && file.size) || 0) / 1_000_000 * 500)
          );

          // `.log` (Apache / Nginx CLF) is space-delimited; pass the
          // delimiter explicitly because `CsvRenderer._delim` only
          // probes `, ; \t |`. `kindHint: 'log'` switches the worker
          // into log-mode: the bracketed CLF date cell is re-merged
          // post-parse, the first row is treated as data (CLF has no
          // header), and canonical column names are applied when the
          // row width matches 9 (Combined) or 7 (Common).
          //
          // `kindHint: 'syslog3164'` (and the other structured-log
          // hints introduced alongside) bypass CsvRenderer entirely
          // and feed the buffer to a dedicated per-format tokeniser
          // (see the matching `if (kindHint === ...)` branch in
          // `timeline.worker.js::_parseCsv`). Structured-log loads
          // also pass `fileLastModified` so the parser can infer the
          // year for RFC 3164 timestamps deterministically.
          const _structuredLog = (ext === 'syslog3164' || ext === 'syslog5424'
                                  || ext === 'zeek' || ext === 'jsonl');
          const opts = (workerKind === 'csv')
            ? { explicitDelim: ext === 'tsv' ? '\t'
                  : (ext === 'log' ? ' ' : null),
                kindHint:    ext === 'log' ? 'log'
                  : (_structuredLog ? ext : null),
                fileLastModified: file && file.lastModified || 0,
                onBatch, timeoutMs: sizeTimeout }
            : { onBatch, timeoutMs: sizeTimeout };
          const msg = await window.WorkerManager.runTimeline(transfer, workerKind, opts);
          // Perf markers — terminal `done` resolved. Also stamp the
          // worker's self-reported `parseMs` (added in
          // `timeline.worker.js::onmessage`) onto the dedicated
          // perf-state slot.
          if (typeof window !== 'undefined' && window.__loupePerfMark) {
            window.__loupePerfMark('workerDone');
            if (msg && typeof msg.parseMs === 'number'
                && window.__loupePerfWorkerParseMs) {
              window.__loupePerfWorkerParseMs(msg.parseMs);
            }
            // Worker-internal marker bag + counters (additive — older
            // worker bundles omit them, the host setter no-ops on
            // missing/non-object). Surfaced via `perfState()` for the
            // perf harness to attribute time inside the worker without
            // a host-side `performance.now()` for every event.
            if (msg && msg.workerMarks
                && typeof msg.workerMarks === 'object'
                && window.__loupePerfWorkerMarks) {
              window.__loupePerfWorkerMarks(msg.workerMarks);
            }
            if (msg && msg.workerCounters
                && typeof msg.workerCounters === 'object'
                && window.__loupePerfWorkerCounters) {
              window.__loupePerfWorkerCounters(msg.workerCounters);
            }
          }
          // Clear the live "N rows…" subtitle the moment the worker
          // hands back the terminal `done` — the build / mount phase
          // has its own dedicated phrases so a stale row-count would
          // be misleading. `_setLoading(false)` clears defensively too,
          // but doing it here keeps the spinner clean during the
          // intermediate RowStore-build window below.
          try {
            if (typeof this._setLoadingSubtitle === 'function') {
              this._setLoadingSubtitle('');
            }
          } catch (_) { /* best-effort */ }
          // Assemble the streamed `rows-chunk` payloads into a
          // `RowStore` keyed by the columns the worker resolved from
          // the header / schema. The terminal `msg` carries metadata
          // only — its `rows` array is empty by contract. We splice
          // the RowStore onto `msg.rowStore` and hand the (still-
          // rowless) msg to `_buildTimelineViewFromWorker`.
          //
          // W4: in the common case the builder was constructed during
          // streaming (on the early `columns` event) and chunks were
          // applied as they arrived, so this block becomes a single
          // `finalize()` call. The fallback branch handles two cases:
          // (a) the worker never emitted a `columns` event (older
          // bundle, or an empty-header file), and (b) chunks arrived
          // before the columns event for some reason — they're then
          // replayed into a freshly-constructed builder here.
          {
            if (!builder) {
              const cols = Array.isArray(msg.columns) ? msg.columns : [];
              builder = new RowStoreBuilder(cols);
            }
            if (pendingChunks.length) {
              for (let i = 0; i < pendingChunks.length; i++) {
                builder.addChunk(pendingChunks[i]);
              }
              // Drop the chunk list so the typed arrays are uniquely
              // owned by the builder (and, after finalize, by the
              // resulting RowStore).
              pendingChunks.length = 0;
            }
            msg.rowStore = builder.finalize();
            builder = null;
          }
          // Perf marker — `RowStore` is now sealed; next sub-phase is
          // `TimelineView` construction (which runs the synchronous
          // post-load passes: `_parseAllTimestamps`,
          // `_buildStableStackColorMap`, `_rebuildSusBitmap`,
          // `_rebuildDetectionBitmap`, `_recomputeFilter`, `_buildDOM`).
          if (typeof window !== 'undefined' && window.__loupePerfMark) {
            window.__loupePerfMark('rowStoreFinalized');
            window.__loupePerfMark('timelineViewCtorStart');
          }
          view = this._buildTimelineViewFromWorker(
            file, workerKind, msg, transferOriginal ? null : buffer);
          if (typeof window !== 'undefined' && window.__loupePerfMark) {
            window.__loupePerfMark('timelineViewCtorEnd');
          }
        } catch (e) {
          // A newer file load has bumped the timeline-channel token and
          // aborted this parse. Bail out entirely — `_loadFile` has
          // already kicked off the new view, and falling through to the
          // synchronous main-thread parse here would waste CPU on a
          // file the user has already moved on from, then potentially
          // mount a stale view over the new one.
          if (e && e.message === 'superseded') {
            this._setLoading(false);
            return;
          }
          if (!e || e.message !== 'workers-unavailable') {
            console.warn('[timeline] worker parse failed; falling back to main-thread parse:', e);
          }
          view = null; // fall through to sync path
        }
      }

      // ── Synchronous fallback (legacy path) ─────────────────────────
      // Size-gate: the synchronous main-thread parse will OOM the tab
      // on multi-hundred-MB CSVs (the entire decoded UTF-16 string
      // plus the rows array plus DOM materialisation all sit in the
      // main heap). For files at or above `LARGE_FILE_THRESHOLD`
      // (200 MB) we refuse to fall back and surface an actionable
      // toast instead — the analyst can split / pre-process the file
      // rather than crash the tab. EVTX / SQLite are usually denser
      // than raw CSV but still fall under the same heuristic.
      if (!view) {
        const tooLargeForFallback = file
          && file.size >= RENDER_LIMITS.LARGE_FILE_THRESHOLD;
        if (tooLargeForFallback) {
          const mb = (file.size / (1024 * 1024)).toFixed(0);
          const reason = (workerKind && window.WorkerManager
              && window.WorkerManager.workersAvailable
              && window.WorkerManager.workersAvailable())
            ? 'worker parse failed or timed out'
            : 'workers unavailable on this browser/origin';
          throw new Error(
            `Cannot fall back to main-thread parse for a ${mb} MB file ` +
            `(${reason}). Split or pre-process the file before loading.`);
        }
        if (ext === 'evtx') {
          view = await TimelineView.fromEvtx(file, buffer);
        } else if (ext === 'csv' || ext === 'tsv' || ext === 'log') {
          const explicit = ext === 'tsv' ? '\t' : (ext === 'log' ? ' ' : null);
          view = await TimelineView.fromCsvAsync(
            file, buffer, explicit, ext === 'log' ? 'log' : null);
        } else if (ext === 'syslog3164' || ext === 'syslog5424'
                || ext === 'zeek' || ext === 'jsonl') {
          // Structured-log fallback — mirrors the worker's
          // `_parseStructuredLog` for environments where workers
          // can't spawn (Firefox `file://`).
          view = await TimelineView.fromStructuredLogAsync(file, buffer, ext);
        } else if (ext === 'sqlite' || ext === 'db') {
          view = TimelineView.fromSqlite(file, buffer);
        } else {
          throw new Error('Unsupported Timeline format: .' + ext);
        }
      }


      // If the factory returned zero rows AND no pre-parsed events (EVTX
      // with an unreadable header, empty CSV) fall back to the analyser
      // pipeline so the file isn't a dead-end. The analyser can still
      // render a hex dump + strings.
      //
      // Pass the already-read `buffer` through to `_loadFile` so it
      // doesn't re-read the file from scratch. For very large files the
      // double-read was the primary cause of OOM / silent empty-string
      // returns from `file.text()`.
      const rowCount = view && view.store ? view.store.rowCount : 0;
      const evtCount = view && view._evtxEvents ? view._evtxEvents.length : 0;
      if (rowCount === 0 && evtCount === 0) {
        if (view) { try { view.destroy(); } catch (_) { /* noop */ } }
        this._setLoading(false);
        // The previous file may have set body.has-timeline (which hides
        // #viewer via CSS).  The earlier `destroy()` already nulled
        // `_timelineCurrent`, so the teardown guard in `_loadFile` won't
        // fire.  Remove the class and restore toolbar visibility here
        // before re-entering the regular loader.
        document.body.classList.remove('has-timeline');
        const vt = document.getElementById('viewer-toolbar');
        if (vt) vt.classList.remove('hidden');
        // Re-enter the regular loader by calling `_loadFile` with a flag
        // that skips the timeline re-route.  Pass the buffer we already
        // have so the file isn't read a second time — UNLESS the buffer
        // was transferred to a CSV/TSV worker (now detached on the main
        // thread); in that case `_loadFile` re-reads from the original
        // `File` itself.
        this._skipTimelineRoute = true;
        const reusableBuffer = (buffer && buffer.byteLength > 0) ? buffer : undefined;
        try { await this._loadFile(file, reusableBuffer); } finally { this._skipTimelineRoute = false; }
        return;
      }


      // Let the view emit toasts through the app.
      view._app = this;

      // The constructor ran a self-scheduled `_runGeoipEnrichment()` 100 ms
      // after mount, but `_app` was only assigned just now, so that call
      // bailed early (the mixin no-ops when `_app` is null). Re-trigger
      // enrichment now that the provider link is live. Idempotent — the
      // mixin's done-marker + per-source dedup short-circuit subsequent
      // calls on files that were already enriched.
      if (typeof view._runGeoipEnrichment === 'function') {
        setTimeout(() => {
          try { view._runGeoipEnrichment(); } catch (_) { /* additive */ }
        }, 0);
      }

      // Mount the view into #timeline-root, creating it on demand. The
      // container exists purely to host the Timeline surface — there is
      // no persistent "Timeline mode" any more.
      let host = document.getElementById('timeline-root');
      if (!host) {
        host = document.createElement('div');
        host.id = 'timeline-root';
        const main = document.getElementById('main-area') || document.body;
        main.appendChild(host);
      }
      host.innerHTML = '';
      host.appendChild(view.root());
      this._timelineCurrent = view;

      // Hide the analyser chrome that doesn't belong on a Timeline screen:
      // sidebar (close if open), viewer toolbar. The toolbar Close button
      // stays visible so the analyst can return to the drop-zone.
      if (this.sidebarOpen) { try { this._toggleSidebar(); } catch (_) { /* noop */ } }
      const btnClose = document.getElementById('btn-close');
      if (btnClose) btnClose.classList.remove('hidden');
      const vt = document.getElementById('viewer-toolbar');
      if (vt) vt.classList.add('hidden');
      document.body.classList.add('has-timeline');
    } catch (e) {
      console.error('[timeline] load failed:', e);
      this._toast(`Failed to open in Timeline: ${e && e.message ? e.message : e}`,
        'error');
      // Clean up any partial Timeline state so the user lands back on
      // the drop-zone instead of a half-mounted surface with stale
      // breadcrumbs and no close button.  `_clearFile()` restores the
      // canonical empty state (drop-zone, hidden toolbar, nulled
      // _fileMeta) and is safe to call even when no view was mounted.
      const host = document.getElementById('timeline-root');
      if (host) host.innerHTML = '';
      document.body.classList.remove('has-timeline');
      this._clearFile();
    } finally {
      this._setLoading(false);
    }
  },

  // Construct a TimelineView from a parse-only worker `done` payload.
  // The worker ships back `{ columns, rows, formatLabel,
  // truncated, originalRowCount, defaultTimeColIdx?, defaultStackColIdx?,
  // evtxEvents?, browserType? }` — i.e. the same shape the legacy
  // `TimelineView.from{Csv,Evtx,Sqlite}` factories pass into the
  // `TimelineView` constructor, minus the analyzer side-channel for
  // EVTX. We run `EvtxDetector.analyzeForSecurity` on the main thread
  // here (with the worker-pre-parsed events to skip a re-parse) so the
  // Detections / Entities sections stay populated. CSV / TSV / SQLite
  // have no analyzer side-channel — the worker output drops straight
  // into the constructor.
  //
  // `originalBuffer` is the live ArrayBuffer the caller still holds
  // (the worker received a `buffer.slice(0)` copy that was transferred
  // and consumed). EvtxDetector only needs it as a fallback parse target
  // when `prebuiltEvents` is missing — passing it keeps the contract
  // intact even if the worker ever started omitting `evtxEvents`.
  _buildTimelineViewFromWorker(file, kind, msg, originalBuffer) {
    if (!msg) return null;
    const columns = msg.columns || [];
    // Phase 6: every worker kind streams rows via `rows-chunk`. The
    // host caller (`_loadFileInTimeline`) assembles them into a
    // `RowStore` and parks it on `msg.rowStore`; the terminal `msg`
    // carries metadata + (for EVTX) the `evtxEvents` analyzer side-
    // channel only. `msg.rows` is empty by contract.
    //
    // Defence in depth: if `rowStore` is somehow missing (a future
    // worker bug, or a kind we haven't migrated yet) we fall through
    // to an empty store so downstream code sees a coherent
    // `RowStore`-shaped object instead of `undefined` exploding inside
    // `TimelineView`. The zero-row escape hatch in
    // `_loadFileInTimeline` then re-routes the file to the analyser
    // pipeline, matching the existing failure semantics.
    const rowStore = (msg.rowStore && typeof msg.rowStore.rowCount === 'number')
      ? msg.rowStore
      : RowStore.empty(columns);
    if (kind === 'evtx') {
      let securityFindings = null;
      try {
        securityFindings = EvtxDetector.analyzeForSecurity(
          originalBuffer, file && file.name, msg.evtxEvents || []);
      } catch (e) {
        console.warn('[timeline] EVTX analyzeForSecurity failed (worker path):', e);
      }
      return new TimelineView({
        file, columns,
        store: rowStore,
        formatLabel: msg.formatLabel || 'EVTX',
        truncated: !!msg.truncated,
        originalRowCount: msg.originalRowCount || rowStore.rowCount,
        defaultTimeColIdx: Number.isInteger(msg.defaultTimeColIdx) ? msg.defaultTimeColIdx : 0,
        defaultStackColIdx: Number.isInteger(msg.defaultStackColIdx) ? msg.defaultStackColIdx : 1,
        evtxEvents: msg.evtxEvents || [],
        evtxFindings: securityFindings,
      });
    }
    if (kind === 'sqlite') {
      // Generic SQLite (non-browser-history) returns zero rows from the
      // worker — caller's zero-row fallback re-routes to the regular
      // analyser. Only the browser-history path emits `defaultTimeColIdx`.
      const out = {
        file, columns,
        store: rowStore,
        formatLabel: msg.formatLabel || 'SQLite',
        truncated: !!msg.truncated,
        originalRowCount: msg.originalRowCount || rowStore.rowCount,
      };
      if (Number.isInteger(msg.defaultTimeColIdx)) out.defaultTimeColIdx = msg.defaultTimeColIdx;
      if (Number.isInteger(msg.defaultStackColIdx)) out.defaultStackColIdx = msg.defaultStackColIdx;
      return new TimelineView(out);
    }
    // csv / tsv / structured-log — no analyzer side-channel. Pass the
    // RowStore straight through to `TimelineView`.
    //
    // Structured-log payloads (`syslog3164`, etc.) come back through
    // the `kind === 'csv'` worker channel but with their own
    // `formatLabel` ('Syslog (RFC 3164)') and explicit
    // `defaultTimeColIdx` / `defaultStackColIdx` values. Honour them
    // when present so the histogram opens stacked-by Severity rather
    // than re-running the heuristic 2000-row probe.
    const csvOut = {
      file, columns,
      store: rowStore,
      formatLabel: msg.formatLabel || (kind === 'csv' ? 'CSV' : 'TSV'),
      truncated: !!msg.truncated,
      originalRowCount: msg.originalRowCount || rowStore.rowCount,
    };
    if (Number.isInteger(msg.defaultTimeColIdx)) csvOut.defaultTimeColIdx = msg.defaultTimeColIdx;
    if (Number.isInteger(msg.defaultStackColIdx)) csvOut.defaultStackColIdx = msg.defaultStackColIdx;
    return new TimelineView(csvOut);
  },

  _clearTimelineFile() {
    // Tear down the Timeline surface itself. The drop-zone is Loupe's

    // canonical empty state, so we don't render a Timeline-specific
    // placeholder here.
    if (this._timelineCurrent) {
      try { this._timelineCurrent.destroy(); } catch (_) { /* noop */ }
      this._timelineCurrent = null;
    }
    const host = document.getElementById('timeline-root');
    if (host) host.innerHTML = '';
    document.body.classList.remove('has-timeline');

    // Delegate the rest of the reset to the generic _clearFile(). This
    // matters when the Timeline was mounted on top of a prior analyser
    // view (e.g. open .sqlite → open .csv): _loadFile() leaves the old
    // SQLite DOM sitting inside #page-container and only hides it via
    // body.has-timeline. Without this call, dropping .has-timeline here
    // would reveal that stale DOM, while _fileMeta / breadcrumbs / the
    // ✕ button had already been nulled — so the user would land on the
    // old SQLite view with no toolbar entry. _clearFile() clears
    // #page-container, restores the drop-zone, hides viewer-toolbar /
    // btn-close, closes the sidebar, nulls _fileMeta / _navStack /
    // findings, re-renders breadcrumbs, clears search, and resets zoom.
    this._clearFile();
  },

});
