'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline.worker.js — Timeline parse-only worker
//
// Pure WorkerGlobalScope module: no DOM, no `window`, no `app.*` references.
// Runs CSV / TSV / EVTX / SQLite-browser-history parsing off the main thread
// so multi-hundred-MB drops no longer freeze the UI for tens of seconds.
//
// Scope = parsing only. **No analysis.**
// ────────────────────────────────────────────────────────────────────────────
// EVTX threat-detection (`EvtxDetector.analyzeForSecurity`), the CSV / TSV
// "obvious malware" pre-scan, and any IOC sweep stay on the main thread.
// The worker hands back raw `evtxEvents` (full event objects with parsed
// EventData minus the per-event `rawRecord` Uint8Array) and the analyzer
// is invoked on the main thread post-parse. This keeps the worker bundle
// small (~130 KB instead of ~240 KB) and means
// `EvtxDetector._SUSPICIOUS_PATTERNS` / `_extractEvtxIOCs` are never
// concatenated into this bundle — see `src/evtx-detector.js` (split out
// specifically for this) and `JS_FILES` in `scripts/build.py`.
//
// Build-time inlining
// -------------------
// `scripts/build.py` reads each "worker-safe parser" source — today:
//   1. src/workers/timeline-worker-shim.js   (constants + IOC/risk stubs)
//   2. src/renderers/csv-renderer.js         (CsvRenderer — _delim, _splitQuoted)
//   3. src/renderers/sqlite-renderer.js      (SqliteRenderer — _parseDb)
//   4. src/renderers/evtx-renderer.js        (EvtxRenderer — _parse, _parseAsync)
//   5. src/workers/timeline.worker.js        (this file — parse fns + dispatcher)
// concatenates them, and emits the result as the JS template-literal
// constant `__TIMELINE_WORKER_BUNDLE_SRC` injected at the top of the
// application script block. `src/worker-manager.js::runTimeline()` is the
// only sanctioned spawn site, identical pattern to the YARA worker (C1).
//
// The renderers' `render()` / `_buildView()` / `analyzeForSecurity()` /
// `_buildCsvBar()` etc. methods all reference `document.*` / `navigator.*` /
// `window.*`. None of those ever execute in the worker — `onmessage` only
// calls `_parse` / `_parseAsync` / `_parseDb` / `_delim` / `_splitQuoted`
// — so the unreachable DOM code parses fine and is dead weight at runtime.
// A future track (E1) may extract pure-parse modules to drop bundle size
// further, but the current concatenation is sufficient for C2.
//
// postMessage protocol
// --------------------
// in:  { kind: 'csv', buffer: ArrayBuffer (transferred),
//        explicitDelim?: string, kindHint?: 'log' | null }
//      { kind: 'evtx', buffer: ArrayBuffer (transferred) }
//      { kind: 'sqlite', buffer: ArrayBuffer (transferred) }
//
// `kindHint: 'log'` switches the CSV path into Apache / Nginx CLF mode:
// the bracketed-date pair is re-merged into a single timestamp cell
// (CLF separates `[20/Jun/2012:19:05:12` and `+0200]` with a space —
// our delimiter), the first physical row is treated as data not
// header, and canonical column names are synthesised when the row
// width is 9 (combined) or 7 (common).
//
// out (CSV/TSV/EVTX/SQLite) — STREAMING:
//   Zero or more intermediate packed-chunk events. Each chunk is the
//   output of `packRowChunk(...)` (see `src/row-store.js`); both
//   ArrayBuffers ride the postMessage transfer list (zero-copy):
//     { event: 'rows-chunk',
//       bytes:   ArrayBuffer (transferred — Uint8Array payload, UTF-8),
//       offsets: ArrayBuffer (transferred — Uint32Array of length
//                              rowCount * (colCount + 1)),
//       rowCount: number }
//   Then exactly one terminal `done` (one per kind):
//     csv:    { event: 'done', kind: 'csv', columns, rows: [],
//               formatLabel: 'CSV'|'TSV', truncated, originalRowCount,
//               parseMs }
//     evtx:   { event: 'done', kind: 'evtx', columns, rows: [],
//               evtxEvents: [...],            ← analyzer side-channel
//               formatLabel: 'EVTX', truncated, originalRowCount,
//               defaultTimeColIdx: 0, defaultStackColIdx: 1, parseMs }
//     sqlite: { event: 'done', kind: 'sqlite', columns, rows: [],
//               formatLabel, browserType, truncated, originalRowCount,
//               defaultTimeColIdx, defaultStackColIdx, parseMs }
//   Phase 6: EVTX and SQLite were promoted from the legacy "rows
//   shipped inside `done` as `string[][]`" shape to the streaming
//   shape that CSV adopted in Phase 3. The terminal `done.rows` is
//   now always `[]` for every kind — row data arrives only via
//   `rows-chunk`. The host caller must register an `onBatch(msg)`
//   sink via `WorkerManager.runTimeline(buffer, kind, { onBatch })`
//   to feed the streamed chunks into a `RowStoreBuilder`; without
//   one the rows are silently dropped on the floor. See
//   `src/app/timeline/timeline-router.js::_loadFileInTimeline`.
//
// out (any error):
//   { event: 'error', message: string }
//
// The buffer is **transferred** (caller loses access). Callers that need the
// bytes again — `_loadFileInTimeline` keeps reading
// `this.currentResult.buffer` after the timeline factory returns to feed
// `_loadFile` for the analyser sidebar — pass a `buffer.slice(0)` copy.
// See `src/worker-manager.js::runTimeline`.
//
// Failure surface
// ---------------
// Any thrown exception is caught and posted as `{event:'error'}`. The worker
// never throws — every terminal path posts exactly one of `{event:'done'}`
// or `{event:'error'}` then exits. Host falls back to the existing
// sync-on-main-thread parse path (`_loadFileInTimelineSync`) when this
// worker emits `error`, mirroring the C1 fallback contract.
//
// CSP note
// --------
// Workers inherit the host CSP, so `default-src 'none'` continues to deny
// network access from inside the worker. The host ↔ worker boundary is
// `postMessage` only.
// ════════════════════════════════════════════════════════════════════════════
//
// Constants (RENDER_LIMITS, EVTX_COLUMN_ORDER, TIMELINE_MAX_ROWS, IOC stub,
// escalateRisk / pushIOC / lfNormalize stubs, EVTX_EVENT_DESCRIPTIONS stub)
// are all defined by `src/workers/timeline-worker-shim.js`, which the
// build concatenates immediately above. The renderer sources are
// concatenated next, so by the time control reaches the parse functions
// below `CsvRenderer`, `SqliteRenderer`, and `EvtxRenderer` are all in
// scope.
// ════════════════════════════════════════════════════════════════════════════

// ── Worker-internal perf instrumentation (test-only, additive) ────────────
//
// Mirrors the host-side `__loupePerfMark` pattern but lives entirely
// inside the worker — `window` is unavailable here, and the host's
// stamps cannot reach into the worker's monotonic clock. The dispatcher
// ships `_workerMarks` and `_workerCounters` on the terminal `done`
// payload alongside the existing `parseMs` field so older bundles ignore
// them (additive — no PerfReport schema bump). Release builds tolerate
// the cost (one object init at parse start, ~half-a-dozen `performance.
// now()` calls per parse, two integer increments per row); none are
// gated on `__test_api__` because the parser path is single-purpose
// (worker only) and we want the markers stamped even when a release-
// build host swallows them silently.
//
// Marker semantics: FIRST observation wins (matches the host's
// `workerColumnsEvent` / `workerFirstChunk` latches). Counters are
// monotonic integers; both bags are reset to fresh objects at the top
// of every dispatcher call so back-to-back parses never leak state.
let _workerMarks = null;
let _workerCounters = null;

function _workerMark(name) {
  if (!_workerMarks) return;                  // dispatcher not initialised
  if (_workerMarks[name] !== undefined) return;
  _workerMarks[name] =
    (typeof performance !== 'undefined' && performance.now)
      ? performance.now() : Date.now();
}

function _workerBumpCounter(name, by) {
  if (!_workerCounters) return;
  _workerCounters[name] = (_workerCounters[name] || 0) + (by | 0);
}

// Rows-per-chunk target for every streaming parse path. Matches the
// `RowStoreBuilder` chunk-rows target so the host-side rebuild produces
// chunk boundaries identical to what a sync `addRow`-driven build would
// have produced. Promoted from a `_parseCsv` local in Phase 6 so the
// EVTX and SQLite parsers can share it without forking the constant.
const WORKER_CHUNK_ROWS = 50_000;

// W1: ship the FIRST rows batch at a much smaller size so the host
// thread can begin constructing `RowStoreBuilder` (and unblock its
// `'columns-known'` mount preamble — see W4) while the worker is still
// parsing the rest of the file. The host's `addChunk` path is cheap
// (it just stores typed-array refs) but the *first* `rows-chunk`
// arrival also triggers `RowStoreBuilder` construction, the column
// count validation, and downstream RowStore wiring — work that must
// happen in series with parsing on the worker. Sending the first
// batch at 5 000 rows (≈10 % of the steady-state target) lets the
// host land that one-time setup ~10× sooner. Steady-state continues
// at WORKER_CHUNK_ROWS so we don't pay extra postMessage overhead
// across the rest of the file.
const WORKER_FIRST_CHUNK_ROWS = 5_000;

// Pack one batch of `string[][]` rows and post a `rows-chunk` event with
// both ArrayBuffers in the transfer list (zero-copy). `colCount` must
// match the columns declared in the terminal `done` payload — the host
// `RowStoreBuilder.addChunk` validates the offsets array's length
// against `rowCount * (colCount + 1)` and throws on mismatch.
function _postRowsChunk(rows, colCount) {
  if (!rows.length || !colCount) return;
  const packed = packRowChunk(rows, colCount);
  self.postMessage(
    {
      event:    'rows-chunk',
      bytes:    packed.bytes.buffer,
      offsets:  packed.offsets.buffer,
      rowCount: packed.rowCount,
    },
    [packed.bytes.buffer, packed.offsets.buffer],
  );
}

// W4: emit the resolved column list AHEAD of the first `rows-chunk` so
// the host can construct `RowStoreBuilder` immediately rather than
// buffering chunks until the terminal `done` arrives. The terminal
// `done` payload still carries `columns` (host validates / falls back
// when the early event is missing); this is purely additive — older
// host bundles ignore the event silently per `worker-manager.js`'s
// "events without an onBatch sink are dropped" contract.
//
// Posted exactly once per parse, after the header row has been
// resolved (CSV/CLF) or after the column schema is known (EVTX/SQLite).
// A no-op if `columns` is empty (the file had no parseable header) —
// the host's existing fallback path constructs an empty-columns
// RowStore from the terminal `done`.
function _postColumns(columns) {
  if (!Array.isArray(columns) || !columns.length) return;
  self.postMessage({
    event:   'columns',
    columns: columns,
  });
}

// P3-G: streaming-rows helper used by EVTX and SQLite (which build
// rows in a tight `for (i = 0; i < list.length; i++)` loop with no
// header / padding / truncation logic to interleave). The CSV / CLF
// paths can't use this helper as-is because their per-row logic
// (header detection, row-count cap, padOrTrimCells, multi-byte tail
// buffer) is interwoven with the threshold check; they keep their
// own `pendingRows` + `firstBatchPending` flag, which still exercises
// the same W1 small-first-batch behaviour.
//
// The helper returns an opaque object with `push(row)` and `flush()`.
// Steady-state threshold is `WORKER_CHUNK_ROWS`; the FIRST batch
// fires at `WORKER_FIRST_CHUNK_ROWS` so the host can land its
// `RowStoreBuilder` setup early (see W1).
function _makeRowStreamer(colCount) {
  let pending = [];
  let firstFlush = true;
  return {
    push(row) {
      pending.push(row);
      const threshold = firstFlush ? WORKER_FIRST_CHUNK_ROWS : WORKER_CHUNK_ROWS;
      if (pending.length >= threshold) {
        _postRowsChunk(pending, colCount);
        pending = [];
        firstFlush = false;
      }
    },
    flush() {
      if (pending.length) {
        _postRowsChunk(pending, colCount);
        pending = [];
      }
      firstFlush = false;
    },
  };
}

// ── CSV / TSV parse (streaming chunk-decode + packed-chunk emit) ───────────
//
// Memory-conscious rewrite of the legacy "decode into one giant string,
// then walk it" parser. Four differences from the prior implementation:
//
//   1. We never materialise the entire decoded UTF-8 text — only the
//      current decoded chunk plus a small tail buffer that holds the
//      partial last line spilling into the next chunk. For a 318 MB
//      ASCII CSV the prior code peaked at ~1.3 GB transient (full UTF-16
//      string ≈ 636 MB plus the `parts.join('')` doubling); the streaming
//      version stays under ~50 MB on top of the input.
//   2. Rows are packed into `RowStore` chunks of 50 000 via
//      `packRowChunk(...)` and shipped to the host as
//      `{event:'rows-chunk', bytes, offsets, rowCount}` with both
//      ArrayBuffers in the postMessage transfer list. The structured-
//      clone of the `string[][]` batch (which used to double main-thread
//      peak memory at hand-off) is gone — the receiver wraps the
//      transferred buffers in `Uint8Array` / `Uint32Array` views.
//   3. The terminal `done` payload only carries metadata (`columns`,
//      `formatLabel`, `truncated`, `originalRowCount`) plus an empty
//      `rows: []`; the row data is entirely in the streamed chunks.
//   4. The legacy "if a quote-aware split throws, fall back to a
//      line-by-line split" branch is preserved: we wrap each chunk's
//      row-extraction loop in try/catch and on the rare pathological
//      input the chunk is skipped instead of taking the rest of the
//      stream down with it. Errors from outside the splitter still
//      bubble.
//
// The `explicitDelim` argument lets the host force a delimiter (TSV
// uses `\t`); when omitted we sniff using `CsvRenderer._delim` over the
// first decoded chunk only — sufficient signal for any real CSV.
// ── Structured-log parse (syslog 3164 / CEF / LEEF / logfmt) ───────────────
//
// One-line-per-record formats with a fixed per-format tokeniser. Each
// `kindHint` selects a `(tokenizeLine, getColumns)` pair from the
// `STRUCTURED_LOG_KINDS` registry below; the rest of the pipeline is
// the chunked-decode, line-split, pad-or-trim, packed-chunk emit
// loop CLF uses.
//
// Why a separate function rather than another `if (isLog)` branch
// inside `_parseCsv`: structured-log formats DO NOT use the
// `CsvRenderer` state machine at all (none of them are RFC-4180 cells
// separated by a delimiter), so the entry path doesn't share any
// CSV setup. Keeping them in their own function keeps the CSV path
// readable as it grows.
//
// `getColumns(width)` is called once when the first valid line is
// tokenised. Most formats have a fixed canonical column list and
// ignore the width; LEEF passes the width through to support both
// 1.0 and 2.0 layouts.
async function _parseStructuredLog(buffer, kindHint, fileLastModified) {
  _workerMark('structuredLogParseStart');
  const kindCfg = STRUCTURED_LOG_KINDS[kindHint];
  if (!kindCfg) throw new Error('unknown structured-log kindHint: ' + kindHint);
  const formatLabel = kindCfg.label;

  // Per-parse state. Stateless formats (3164/5424) use the static
  // `tokenize` + `columns` pair on the kind config. Stateful formats
  // (Zeek — schema is defined inline in a `#fields` header that
  // precedes the data rows) provide a `makeTokenizer()` factory that
  // returns `{tokenize, getColumns, getDefaultStackColIdx?, getFormatLabel?}`
  // closing over per-parse state. The factory is called once per
  // `_parseStructuredLog` invocation so state can't leak between
  // files. `getColumns` is called on the first valid data row, after
  // the tokeniser has already stashed schema bits from any `#`-prefixed
  // header lines (which the tokeniser returns `null` for).
  let tokenizeLine, getColumns;
  let getDefaultStackColIdx = null;
  let getFormatLabel = null;
  if (typeof kindCfg.makeTokenizer === 'function') {
    const tk = kindCfg.makeTokenizer();
    tokenizeLine = tk.tokenize;
    getColumns = tk.getColumns;
    getDefaultStackColIdx = tk.getDefaultStackColIdx || null;
    getFormatLabel = tk.getFormatLabel || null;
  } else {
    tokenizeLine = kindCfg.tokenize;
    getColumns = kindCfg.columns;
  }

  const bytes = new Uint8Array(buffer);
  const DECODE_CHUNK = RENDER_LIMITS.DECODE_CHUNK_BYTES;
  const decoder = new TextDecoder('utf-8', { fatal: false });

  // Pass the raw mtime ms through to the per-line tokeniser. The
  // tokeniser handles the "missing mtime → current UTC year" fallback
  // internally, and uses the mtime as the upper-bound boundary for
  // its 30-day future-roll heuristic.
  const nowMs = fileLastModified | 0;

  let columns = [];
  let colLen = 0;
  let headerSeen = false;
  let rowCount = 0;
  let truncated = false;
  let bytesConsumed = 0;
  let pendingRows = [];
  let firstBatchPending = true;

  const flushBatch = () => {
    if (!pendingRows.length) return;
    if (!colLen) { pendingRows = []; return; }
    _postRowsChunk(pendingRows, colLen);
    pendingRows = [];
    firstBatchPending = false;
  };
  const currentBatchThreshold = () =>
    firstBatchPending ? WORKER_FIRST_CHUNK_ROWS : WORKER_CHUNK_ROWS;
  const padOrTrim = (cells) => {
    if (!colLen) return cells;
    if (cells.length < colLen) {
      while (cells.length < colLen) cells.push('');
    } else if (cells.length > colLen) {
      cells.length = colLen;
    }
    return cells;
  };

  let tail = '';
  let firstChunk = true;
  outerLog:
  for (let pos = 0; pos < bytes.length; pos += DECODE_CHUNK) {
    const end = Math.min(pos + DECODE_CHUNK, bytes.length);
    const stream = end < bytes.length;
    let chunk = decoder.decode(bytes.subarray(pos, end), { stream });
    if (firstChunk) {
      if (chunk.charCodeAt(0) === 0xFEFF) chunk = chunk.slice(1);
      firstChunk = false;
    }
    if (chunk.indexOf('\r') !== -1) chunk = chunk.replace(/\r\n?/g, '\n');
    bytesConsumed = end;
    const text = tail + chunk;
    let lineStart = 0;
    while (lineStart < text.length) {
      const nl = text.indexOf('\n', lineStart);
      if (nl < 0) { tail = text.slice(lineStart); break; }
      const line = text.slice(lineStart, nl);
      lineStart = nl + 1;
      if (!line) continue;
      const cells = tokenizeLine(line, nowMs);
      if (!cells) continue;
      if (!headerSeen) {
        columns = getColumns(cells.length);
        colLen = columns.length;
        headerSeen = true;
        _postColumns(columns);
      }
      if (rowCount >= TIMELINE_MAX_ROWS) { truncated = true; break outerLog; }
      pendingRows.push(padOrTrim(cells));
      rowCount++;
      if (pendingRows.length >= currentBatchThreshold()) flushBatch();
    }
    if (lineStart >= text.length) tail = '';
  }
  if (!truncated && tail) {
    const cells = tokenizeLine(tail, nowMs);
    if (cells) {
      if (!headerSeen) {
        columns = getColumns(cells.length);
        colLen = columns.length;
        headerSeen = true;
        _postColumns(columns);
      }
      if (rowCount < TIMELINE_MAX_ROWS) {
        pendingRows.push(padOrTrim(cells));
        rowCount++;
      }
    }
  }
  flushBatch();
  if (!headerSeen) { columns = []; colLen = 0; }
  const originalRowCount = truncated
    ? Math.round(rowCount * (bytes.length / Math.max(1, bytesConsumed)))
    : rowCount;
  // Stateful tokenisers can override the histogram defaults +
  // format label after they've seen the file's schema (Zeek picks
  // `proto` / `qtype_name` / `method` based on `#path`, and the
  // formatLabel becomes 'Zeek (<path>)').
  const dynStack = (typeof getDefaultStackColIdx === 'function')
    ? getDefaultStackColIdx() : null;
  const dynLabel = (typeof getFormatLabel === 'function')
    ? getFormatLabel() : null;
  return {
    columns,
    rows: [],
    formatLabel: dynLabel || formatLabel,
    truncated,
    originalRowCount,
    // Stateless syslog formats default to Severity (col 1) for the
    // histogram stack — see `_TL_STACK_EXACT` in timeline-helpers.js,
    // which would pick it up automatically too, but stating it
    // explicitly skips the 2000-row cardinality probe on the host
    // side. Stateful kinds may override via `getDefaultStackColIdx()`.
    defaultTimeColIdx: 0,
    defaultStackColIdx: Number.isInteger(dynStack) ? dynStack : 1,
  };
}

// Per-kind registry of structured-log tokenisers. Each entry binds a
// `kindHint` string to its `(tokenize, columns, label)` triple.
// Tokenisers are defined in `timeline-worker-shim.js` (mirrored from
// `timeline-helpers.js`); columns helpers + labels are inlined here.
const STRUCTURED_LOG_KINDS = {
  syslog3164: {
    tokenize: (line, assumedYear) => _tlTokenizeSyslog3164(line, assumedYear),
    columns:  () => _TL_SYSLOG3164_COLS.slice(),
    label:    'Syslog (RFC 3164)',
  },
  syslog5424: {
    tokenize: (line, mtimeMs) => _tlTokenizeSyslog5424(line, mtimeMs),
    columns:  () => _TL_SYSLOG5424_COLS.slice(),
    label:    'Syslog (RFC 5424)',
  },
  zeek: {
    // Stateful — schema lives inside the file's `#fields` header
    // line. The factory closes over per-parse state; columns +
    // formatLabel + default stack column resolve after the first
    // header pass.
    makeTokenizer: () => _tlMakeZeekTokenizer(),
    label: 'Zeek',
  },
  jsonl: {
    // Stateful — schema is the dotted-path key list of the first
    // valid record. Subsequent records pad / overflow into the
    // synthetic `_extra` column.
    makeTokenizer: () => _tlMakeJsonlTokenizer(),
    label: 'JSONL',
  },
  cloudtrail: {
    // Stateful — JSONL with a canonical CloudTrail schema seeded
    // up front. The router unwraps `{"Records":[...]}` documents
    // into a JSONL byte stream before dispatch, so this branch
    // sees one event per line in both code paths.
    makeTokenizer: () => _tlMakeCloudTrailTokenizer(),
    label: 'AWS CloudTrail',
  },
  cef: {
    // Stateful — header is fixed (7 cols), extension schema is
    // locked from the first record's `key=value` block. New keys
    // in later records spill to `_extra`. Strips any leading
    // syslog wrapper before parsing.
    makeTokenizer: () => _tlMakeCEFTokenizer(),
    label: 'CEF',
  },
  leef: {
    // Stateful — same idea as CEF: 5 fixed header cols, dynamic
    // ext schema locked from first record. LEEF 1.0 always uses
    // tab as the ext delimiter; LEEF 2.0 carries a 6th header
    // field specifying the delimiter character (consumed, not
    // emitted as a column). Strips any leading syslog wrapper.
    makeTokenizer: () => _tlMakeLEEFTokenizer(),
    label: 'LEEF',
  },
  logfmt: {
    // Stateful — flat `key=value key="quoted"` lines, no header.
    // Schema locks from the first valid line's key set; later
    // lines spill unknown keys into `_extra`. Used by Heroku
    // routers, Logrus, Hashicorp tools (Consul/Vault/Nomad), and
    // many Go services.
    makeTokenizer: () => _tlMakeLogfmtTokenizer(),
    label: 'logfmt',
  },
  w3c: {
    // Stateful — W3C Extended Log File Format. Schema is
    // declared by `#Fields:` directives at the top of the file
    // (and may reset mid-file). Source-specific labelling:
    // `IIS W3C`, `AWS ALB`, `AWS ELB`, `AWS CloudFront`, or
    // generic `W3C Extended` when no fingerprint matches.
    // Delimiter (space vs tab) auto-detected per `#Fields:`
    // block; `+` decoded to space inside values per IIS
    // convention; synthesised `Timestamp` column at index 0
    // when both `date` and `time` are declared.
    makeTokenizer: () => _tlMakeW3CTokenizer(),
    // Default label; runtime tokeniser refines via
    // `getFormatLabel()` once `#Fields:` and `#Software` lines
    // are observed.
    label: 'W3C Extended',
  },
  'apache-error': {
    // Stateless — Apache HTTP Server's error log (the
    // `ErrorLog` directive output, distinct from access logs).
    // Bracketed metadata + free-text message:
    //   [Tue Apr 30 14:23:11.123456 2024] [core:error]
    //   [pid 12345] [client 10.0.0.5:51234] AH00037: ...
    // Fixed 8-column schema (Timestamp · Module · Severity ·
    // PID · TID · Client · ErrorCode · Message). Stack column
    // pinned to Severity.
    makeTokenizer: () => _tlMakeApacheErrorTokenizer(),
    label: 'Apache error_log',
  },
  'access-log': {
    // Stateful — generic space-delimited access log. Covers
    // formats that are NOT Apache / Nginx CLF (no bracketed
    // `[date]` token) but DO lead with a recognisable timestamp
    // — notably Pulse Secure / Ivanti Connect Secure exports,
    // custom proxy logs, and any hand-rolled access log. Tokenises
    // on space + CLF-style quoted runs; the "TLS access log"
    // fingerprint (8 cols — ts, ip, TLS proto, cipher, request,
    // bytes, referer, UA) gets friendly column names. Other
    // shapes fall back to `time`, `field_2`, …, `field_N`.
    makeTokenizer: () => _tlMakeAccessLogTokenizer(),
    label: 'Access Log',
  },
};

async function _parseCsv(buffer, explicitDelim, kindHint) {
  _workerMark('csvParseStart');
  const bytes = new Uint8Array(buffer);
  const DECODE_CHUNK = RENDER_LIMITS.DECODE_CHUNK_BYTES;

  const decoder = new TextDecoder('utf-8', { fatal: false });
  const r = new CsvRenderer();

  // Parser state. The state-machine parser carries any partial cell /
  // partial row across chunk boundaries — including multi-line quoted
  // cells where a `"..."` value spans several physical lines. This
  // replaces the legacy `tail` buffer (which prepended the partial last
  // line of each chunk to the next): with the new parser, the partial
  // row IS the tail, so we never re-scan or copy text across chunks.
  const parserState = CsvRenderer.initParserState();

  // `kindHint === 'log'` switches into a dedicated CLF tokeniser
  // path that bypasses CsvRenderer entirely (see the `if (isLog)`
  // block below for the rationale and `_tlTokenizeClfLine` for the
  // line-level parser). `_tlTokenizeClfLine` and
  // `_tlCanonicalLogColumns` live in `timeline-worker-shim.js` and
  // are bundled ahead of this file.
  const isLog = kindHint === 'log';
  // True once we've consumed and parsed the header row.
  let headerSeen = false;
  let columns = [];
  let colLen = 0;
  let delim = explicitDelim || null;
  // Format label is fixed once the delimiter is resolved.
  let formatLabel = (delim === '\t') ? 'TSV' : 'CSV';

  let rowCount = 0;
  let truncated = false;
  let bytesConsumed = 0;                // for `originalRowCount` extrapolation
  let firstChunk = true;
  // Pending `string[][]` rows accumulated for the next chunk flush. Once
  // full (BATCH_ROWS rows or end-of-stream) we hand the batch to
  // `packRowChunk(...)` to produce two fresh ArrayBuffers and post them
  // to the host with the transfer list — the source `string[][]` is
  // then dropped so the GC can reclaim the per-cell strings immediately.
  let pendingRows = [];
  // W1: small threshold for the first `rows-chunk` so the host can
  // start its `RowStoreBuilder` setup early; subsequent flushes use
  // the full-size threshold. Flipped to false after the first
  // successful `flushBatch()`.
  let firstBatchPending = true;

  const flushBatch = () => {
    if (!pendingRows.length) return;
    // Defensive: a colLen of 0 means we never resolved a header (empty
    // first row). `_postRowsChunk` would dutifully pack zero-cell rows,
    // discarding the data — bail instead and surface the degenerate
    // input via the empty-columns path in the terminal `done` payload.
    if (!colLen) { pendingRows = []; return; }
    const packStart = (typeof performance !== 'undefined' && performance.now)
      ? performance.now() : 0;
    _postRowsChunk(pendingRows, colLen);
    if (packStart) {
      const packEnd = performance.now();
      _workerBumpCounter('packAndPostMs', Math.round(packEnd - packStart));
      _workerBumpCounter('chunksPosted', 1);
    }
    if (firstBatchPending) _workerMark('csvFirstChunkPosted');
    // Drop reference to the source `string[][]` so the per-cell strings
    // can be GC'd before the next chunk's pack pass starts.
    pendingRows = [];
    firstBatchPending = false;
  };

  // W1: chunk-rows threshold the next `flushBatch` should fire at.
  // Returns the small first-batch target until the first batch has
  // been posted, then the steady-state target.
  const currentBatchThreshold = () =>
    firstBatchPending ? WORKER_FIRST_CHUNK_ROWS : WORKER_CHUNK_ROWS;

  const padOrTrimCells = (cells) => {
    if (!colLen) return cells;
    if (cells.length < colLen) {
      // Short rows (common when a CSV is assembled from multiple sources)
      // get padded silently. The renderer's malformed-row counter only
      // flags rows that are *wider* than the header.
      while (cells.length < colLen) cells.push('');
    } else if (cells.length > colLen) {
      const tailCells = cells.slice(colLen - 1).join(delim);
      cells.length = colLen;
      cells[colLen - 1] = tailCells;
    }
    return cells;
  };

  const ingestRows = (rows) => {
    for (let i = 0; i < rows.length; i++) {
      const cells = rows[i];
      if (!headerSeen) {
        columns = cells.map(c => String(c == null ? '' : c).trim());
        colLen = columns.length;
        headerSeen = true;
        // W4: announce columns AHEAD of the first rows-chunk so the
        // host can construct RowStoreBuilder while the worker is
        // still parsing the body. Additive — host falls back to the
        // terminal `done` columns if the event is missed.
        _postColumns(columns);
        continue;
      }
      if (rowCount >= TIMELINE_MAX_ROWS) {
        truncated = true;
        return true;                    // signal break-outer to caller
      }
      pendingRows.push(padOrTrimCells(cells));
      rowCount++;
      if (pendingRows.length >= currentBatchThreshold()) flushBatch();
    }
    return false;
  };

  // ── CLF (`.log`) path — bypass CsvRenderer entirely ──────────────────
  //
  // Apache / Nginx Common (and Combined) Log Format uses backslash-
  // escaped quotes, not RFC4180 doubled quotes. Feeding it through the
  // generic CSV parser corrupts state on roughly 6 % of real lines
  // (the `\"` in any User-Agent string ends the quoted cell prematurely)
  // and the rest of the file gets glued onto a single mega-cell. We
  // run a fixed-shape CLF tokeniser per physical line instead — see
  // `_tlTokenizeClfLine` in `timeline-worker-shim.js` (and the
  // canonical impl in `src/app/timeline/timeline-helpers.js`).
  //
  // The chunked-decode loop below mirrors the CSV path's structure so
  // memory stays bounded on multi-hundred-MB drops: we keep a `tail`
  // string for the unterminated last line of each chunk, parse only
  // complete lines, and stream packed batches via `flushBatch()`.
  if (isLog) {
    let tail = '';
    let firstChunkLog = true;
    formatLabel = 'LOG';
    outerLog:
    for (let pos = 0; pos < bytes.length; pos += DECODE_CHUNK) {
      const end = Math.min(pos + DECODE_CHUNK, bytes.length);
      const stream = end < bytes.length;
      let chunk = decoder.decode(bytes.subarray(pos, end), { stream });
      if (firstChunkLog) {
        if (chunk.charCodeAt(0) === 0xFEFF) chunk = chunk.slice(1);
        firstChunkLog = false;
      }
      if (chunk.indexOf('\r') !== -1) chunk = chunk.replace(/\r\n?/g, '\n');
      bytesConsumed = end;
      const text = tail + chunk;
      let lineStart = 0;
      while (lineStart < text.length) {
        const nl = text.indexOf('\n', lineStart);
        if (nl < 0) {
          // Partial last line — stash for the next chunk. (At EOF
          // this gets flushed below.)
          tail = text.slice(lineStart);
          break;
        }
        const line = text.slice(lineStart, nl);
        lineStart = nl + 1;
        if (!line) continue;
        const cells = _tlTokenizeClfLine(line);
        if (!cells) continue;             // skip malformed lines
        if (!headerSeen) {
          columns = _tlCanonicalLogColumns(cells.length);
          colLen = columns.length;
          headerSeen = true;
          // W4: see CSV ingestRows — announce columns ahead of the
          // first rows-chunk so the host can construct RowStoreBuilder
          // early. The CLF tail-flush below also resolves the header
          // when the file has only one short line; that branch posts
          // columns there too.
          _postColumns(columns);
        }
        if (rowCount >= TIMELINE_MAX_ROWS) {
          truncated = true;
          break outerLog;
        }
        pendingRows.push(padOrTrimCells(cells));
        rowCount++;
        if (pendingRows.length >= currentBatchThreshold()) flushBatch();
      }
      if (lineStart >= text.length) tail = '';
    }
    // Flush trailing partial line (no newline at EOF).
    if (!truncated && tail) {
      const cells = _tlTokenizeClfLine(tail);
      if (cells) {
        if (!headerSeen) {
          columns = _tlCanonicalLogColumns(cells.length);
          colLen = columns.length;
          headerSeen = true;
          // W4 — see header-set branch above for rationale.
          _postColumns(columns);
        }
        if (rowCount < TIMELINE_MAX_ROWS) {
          pendingRows.push(padOrTrimCells(cells));
          rowCount++;
        }
      }
    }
    flushBatch();
    if (!headerSeen) { columns = []; colLen = 0; }
    const originalRowCountLog = truncated
      ? Math.round(rowCount * (bytes.length / Math.max(1, bytesConsumed)))
      : rowCount;
    return {
      columns,
      rows: [],
      formatLabel,
      truncated,
      originalRowCount: originalRowCountLog,
    };
  }

  // Counters object passed through every `parseChunk` call so the
  // parser can record fast-vs-slow path hits per emitted row. The
  // shape is `{ fastPathRows: N, slowPathRows: N }`; parseChunk
  // increments either field per row — diagnostic only, no behaviour.
  const csvCounters = { fastPathRows: 0, slowPathRows: 0 };

  let firstDecodeStamped = false;
  outer:
  for (let pos = 0; pos < bytes.length; pos += DECODE_CHUNK) {
    const end = Math.min(pos + DECODE_CHUNK, bytes.length);
    const stream = end < bytes.length;
    let chunk = decoder.decode(bytes.subarray(pos, end), { stream });
    if (!firstDecodeStamped) { _workerMark('csvFirstDecodeEnd'); firstDecodeStamped = true; }

    if (firstChunk) {
      if (chunk.charCodeAt(0) === 0xFEFF) chunk = chunk.slice(1);
      // Sniff delimiter from the first chunk. _delim is quote-aware
      // and bounds itself to ~4 KB so this is cheap.
      if (!delim) {
        try { delim = r._delim(chunk); } catch (_) { delim = ','; }
        formatLabel = (delim === '\t') ? 'TSV' : 'CSV';
      }
      firstChunk = false;
    }
    // Normalise CRLF / bare CR. We do this per chunk; a `\r` at the very
    // end of one chunk followed by `\n` at the start of the next would
    // become two newlines after this regex, but the parser skips blank
    // physical lines so the worst case is a single phantom row break —
    // not a row-count corruption.
    if (chunk.indexOf('\r') !== -1) chunk = chunk.replace(/\r\n?/g, '\n');

    bytesConsumed = end;

    // Feed the chunk to the parser. State threads across calls so a
    // multi-line quoted cell spanning chunk boundaries is handled
    // transparently. baseOffset:0 — the worker streams cells, not byte
    // ranges, so rowOffsets are unused.
    try {
      const result = CsvRenderer.parseChunk(chunk, 0, parserState, delim, {
        baseOffset: 0,
        maxRows:    0,
        flush:      false,
        counters:   csvCounters,
      });
      if (ingestRows(result.rows)) break outer;
    } catch (_) {
      // Pathological chunk — skip and continue. We deliberately don't
      // fall back to a whole-file forgiving split here as the legacy
      // code did: a single bad chunk should not lose the rest of the
      // stream.
    }
  }
  _workerMark('csvParseLoopEnd');

  // Final flush — any partial row (file without trailing newline, or
  // an unterminated quoted cell at EOF) gets emitted now.
  if (!truncated) {
    try {
      const flushResult = CsvRenderer.parseChunk('', 0, parserState, delim || ',', {
        baseOffset: 0,
        maxRows:    0,
        flush:      true,
        counters:   csvCounters,
      });
      ingestRows(flushResult.rows);
    } catch (_) { /* ignore */ }
  }
  // Drain the last partial batch.
  flushBatch();
  _workerMark('csvFlushEnd');
  _workerBumpCounter('fastPathRows', csvCounters.fastPathRows);
  _workerBumpCounter('slowPathRows', csvCounters.slowPathRows);

  // If the file had no header row at all, synthesise column names from
  // the widest emitted row. (We can't actually backfill the rows we
  // already postMessage'd, so this only matters for files that arrived
  // header-only.) When `columns` is empty the host falls back to
  // generic `col N` labels via the same path as before.
  if (!headerSeen) {
    columns = [];
    colLen = 0;
  }

  // Extrapolate originalRowCount when we hit the row cap mid-file: ratio
  // bytes-consumed-at-cutoff vs. total bytes, applied to the cap.
  const originalRowCount = truncated
    ? Math.round(rowCount * (bytes.length / Math.max(1, bytesConsumed)))
    : rowCount;

  return {
    columns,
    rows: [],                            // streamed via {event:'rows'} batches
    formatLabel,
    truncated,
    originalRowCount,
  };
}

// ── EVTX parse (mirrors TimelineView.fromEvtx minus analyzer call) ─────────
//
// Phase 6: row data is now streamed via `rows-chunk` in batches of
// `WORKER_CHUNK_ROWS`, matching the CSV path. The terminal `done`
// payload carries metadata + the analyzer side-channel (`evtxEvents`)
// only; its `rows: []` is empty by contract.
async function _parseEvtx(buffer) {
  _workerMark('evtxParseStart');
  const r = new EvtxRenderer();
  let events = [];
  try {
    events = await r._parseAsync(new Uint8Array(buffer)) || [];
  } catch (_) {
    events = [];
  }

  const columns = [...EVTX_COLUMN_ORDER];
  const colCount = columns.length;
  // W4: announce columns ahead of the first rows-chunk so the host
  // can construct RowStoreBuilder while we're still iterating events.
  // EVTX has a fixed schema so we can post immediately.
  _postColumns(columns);
  let truncated = false;
  let list = events;
  if (events.length > TIMELINE_MAX_ROWS) {
    list = events.slice(0, TIMELINE_MAX_ROWS);
    truncated = true;
  }

  // Stream rows in batches. We never materialise the full `string[][]`
  // — once a batch reaches the chunk threshold it's packed and posted,
  // then the array is dropped so the per-cell strings can GC before
  // the next batch is built.
  // P3-G: shared `_makeRowStreamer` encapsulates the W1 first-batch
  // small-threshold + steady-state cadence so EVTX and SQLite share a
  // single implementation.
  const stream = _makeRowStreamer(colCount);
  for (let i = 0; i < list.length; i++) {
    const ev = list[i] || {};
    stream.push([
      ev.timestamp ? ev.timestamp.replace('T', ' ').replace('Z', '') : '',
      ev.eventId || '', ev.level || '', ev.provider || '',
      ev.channel || '', ev.computer || '', ev.eventData || '',
    ]);
  }
  stream.flush();

  // Strip the per-event `rawRecord` Uint8Array before transferring — those
  // copies sum to most of the file size and the Detections / view code on
  // the main thread doesn't need them (they live in the parsed `events`
  // returned from `_parseAsync` only for the "Raw Record" drawer pane,
  // which is a renderer-mode-only feature, not Timeline).
  const trimmedEvents = new Array(list.length);
  for (let i = 0; i < list.length; i++) {
    const ev = list[i];
    if (!ev) { trimmedEvents[i] = ev; continue; }
    // shallow clone, drop rawRecord (idiomatic destructure-omit — the
    // `_rawRecord` binding is the prefix-marker that explicitly signals
    // "extract this key but don't reference it").
    const { rawRecord: _rawRecord, ...rest } = ev;
    trimmedEvents[i] = rest;
  }

  return {
    columns,
    rows: [],                              // streamed via {event:'rows-chunk'}
    evtxEvents: trimmedEvents,
    formatLabel: 'EVTX',
    truncated,
    originalRowCount: events.length,
    defaultTimeColIdx: 0,
    defaultStackColIdx: 1,
  };
}

// ── PCAP / PCAPNG capture (mirrors TimelineView.fromPcap) ──────────────────
//
// Hybrid path: the analyser (`PcapRenderer._analyzePcapInfo`) DOES NOT
// run here — it lives on the main thread because it calls `pushIOC` /
// `IOC.*` / `escalateRisk` (globals defined only in the main bundle).
// We ship the parsed result minus `pkts` as `pcapInfo` and the host's
// `_buildTimelineViewFromWorker` invokes the analyser before
// constructing the TimelineView. Mirrors EVTX's hybrid contract.
function _parsePcap(buffer) {
  _workerMark('pcapParseStart');
  const bytes = new Uint8Array(buffer);

  // `PcapRenderer._parse` handles magic-byte sniff + libpcap LE/BE/ms/ns
  // + PCAPNG dispatch in one call, returning the same `_emptyResult`-
  // shaped object on bad/truncated magic. The host treats a zero-row
  // result as a failed parse and triggers the legacy escape-hatch
  // (re-route to `PcapRenderer.render` card view).
  const parsed = PcapRenderer._parse(bytes);

  const columns = [...PcapRenderer.TIMELINE_COLUMNS];
  const colCount = columns.length;
  // W4: announce columns ahead of the first rows-chunk so the host
  // can construct RowStoreBuilder while we're still iterating packets.
  // PCAP has a fixed schema so we can post immediately.
  _postColumns(columns);

  const allPkts = parsed.pkts || [];
  let truncated = parsed.truncated || false;
  let pkts = allPkts;
  if (allPkts.length > TIMELINE_MAX_ROWS) {
    pkts = allPkts.slice(0, TIMELINE_MAX_ROWS);
    truncated = true;
  }

  // Stream rows in batches via the shared `_makeRowStreamer` helper —
  // identical packing cadence to EVTX / SQLite so the host's
  // `RowStoreBuilder.addChunk` validation succeeds without special
  // casing. `_streamPacketRows` polls a no-op `throwIfAborted` shim
  // every 256 packets (the worker has no real AbortSignal — the host
  // pre-empts via WorkerManager.terminate on watchdog timeout).
  const stream = _makeRowStreamer(colCount);
  PcapRenderer._streamPacketRows(pkts, (row) => stream.push(row), null);
  stream.flush();

  // Strip the per-packet records before transferring — once their rows
  // are packed and posted as `rows-chunk`, the host's
  // `_buildTimelineViewFromWorker` only needs the parse metadata to
  // construct `pcapInfo` for the main-thread `_analyzePcapInfo` call.
  // Sending 1 M `pkt` objects through structured-clone would dominate
  // the postMessage budget for no benefit.
  const pcapInfo = { ...parsed };
  delete pcapInfo.pkts;

  return {
    columns,
    rows: [],                              // streamed via {event:'rows-chunk'}
    pcapInfo,
    // Stable tag — see fromPcap factory for rationale. Variant info
    // ("libpcap", "PCAPNG 1.0 (LE)") rides on `pcapInfo.formatLabel`.
    formatLabel: 'PCAP',
    truncated,
    originalRowCount: allPkts.length,
    defaultTimeColIdx: PcapRenderer.TIMELINE_TIME_COL_IDX,
    defaultStackColIdx: PcapRenderer.TIMELINE_STACK_COL_IDX,
  };
}

// ── SQLite browser-history parse (mirrors TimelineView.fromSqlite) ─────────
//
// Phase 6: row data is now streamed via `rows-chunk` in batches of
// `WORKER_CHUNK_ROWS`, matching the CSV / EVTX paths. The terminal
// `done` payload carries metadata only; its `rows: []` is empty by
// contract.
function _parseSqlite(buffer) {
  _workerMark('sqliteParseStart');
  const r = new SqliteRenderer();
  let db;
  try {
    db = r._parseDb(new Uint8Array(buffer));
  } catch (_) {
    return {
      columns: [], rows: [],
      formatLabel: 'SQLite',
      browserType: null,
      truncated: false, originalRowCount: 0,
      defaultTimeColIdx: null, defaultStackColIdx: null,
    };
  }

  const useEvents = db.historyEventRows && db.historyEventRows.length > 0;
  const srcCols = useEvents ? db.historyEventColumns : db.historyColumns;
  const srcRows = useEvents ? db.historyEventRows : db.historyRows;

  if (!db.browserType || !srcRows || srcRows.length === 0) {
    return {
      columns: [], rows: [],
      formatLabel: 'SQLite',
      browserType: db.browserType || null,
      truncated: false, originalRowCount: 0,
      defaultTimeColIdx: null, defaultStackColIdx: null,
    };
  }

  const columns = srcCols;
  const colCount = columns.length;
  // W4: announce columns ahead of the first rows-chunk — see
  // _parseEvtx for rationale. Posted only when we have a non-empty
  // schema; the empty-cols early-return above handles the degenerate
  // case via the terminal `done` payload alone.
  _postColumns(columns);
  let truncated = false;
  let list = srcRows;
  if (list.length > TIMELINE_MAX_ROWS) {
    list = list.slice(0, TIMELINE_MAX_ROWS);
    truncated = true;
  }

  // Stream rows in batches (see `_parseEvtx` for rationale, including
  // the W1 first-batch dynamic-threshold motivation). P3-G: shared
  // `_makeRowStreamer` helper.
  const stream = _makeRowStreamer(colCount);
  for (let i = 0; i < list.length; i++) {
    const src = list[i] || [];
    const row = new Array(colCount);
    for (let j = 0; j < colCount; j++) {
      row[j] = src[j] != null ? String(src[j]) : '';
    }
    stream.push(row);
  }
  stream.flush();

  const browserLabel = db.browserType === 'firefox' ? 'Firefox' : 'Chrome';
  const timeColIdx = useEvents ? 0 : 3;
  const stackColIdx = useEvents ? 1 : null;

  return {
    columns,
    rows: [],                              // streamed via {event:'rows-chunk'}
    formatLabel: 'SQLite \u2013 ' + browserLabel + ' History',
    browserType: db.browserType,
    truncated,
    originalRowCount: srcRows.length,
    defaultTimeColIdx: timeColIdx,
    defaultStackColIdx: stackColIdx,
  };
}

// ── Dispatcher ──────────────────────────────────────────────────────────────
self.onmessage = async function (ev) {
  const msg = ev && ev.data ? ev.data : {};
  const buffer = msg.buffer;
  const kind = msg.kind || '';

  // Reset the per-parse marker bag + counters at the top of every
  // dispatcher call. Both objects are plain `Object.create(null)`s so a
  // `for…in` over them yields only stamped keys (no prototype clutter
  // bleeding into the JSON the host serialises). Held in module-scope
  // locals so `_workerMark` / `_workerBumpCounter` (called from helper
  // functions defined far above the dispatcher) can find them without
  // a parameter-passing chain.
  _workerMarks = Object.create(null);
  _workerCounters = Object.create(null);

  const t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
  _workerMark('dispatchStart');
  try {
    if (!buffer) {
      self.postMessage({ event: 'error', message: 'no buffer transferred to worker' });
      return;
    }

    let out;
    if (kind === 'csv') {
      // Structured-log kindHints (`syslog3164`, eventually
      // `cef` / `leef` / `logfmt` / `zeek` / `jsonl-log`) bypass
      // CsvRenderer entirely — they use per-format tokenisers and
      // share the line-streaming pipeline in `_parseStructuredLog`.
      // The `'log'` (CLF) kindHint stays in `_parseCsv` where it has
      // historically lived; CLF tokenisation has been there since
      // Phase 6 and the structured-log family was added later.
      if (msg.kindHint && STRUCTURED_LOG_KINDS[msg.kindHint]) {
        out = await _parseStructuredLog(buffer, msg.kindHint, msg.fileLastModified);
      } else {
        if (typeof CsvRenderer === 'undefined') {
          self.postMessage({ event: 'error', message: 'CsvRenderer missing from worker bundle' });
          return;
        }
        out = await _parseCsv(buffer, msg.explicitDelim, msg.kindHint);
      }
    } else if (kind === 'evtx') {
      if (typeof EvtxRenderer === 'undefined') {
        self.postMessage({ event: 'error', message: 'EvtxRenderer missing from worker bundle' });
        return;
      }
      out = await _parseEvtx(buffer);
    } else if (kind === 'sqlite') {
      if (typeof SqliteRenderer === 'undefined') {
        self.postMessage({ event: 'error', message: 'SqliteRenderer missing from worker bundle' });
        return;
      }
      out = _parseSqlite(buffer);
    } else if (kind === 'pcap') {
      if (typeof PcapRenderer === 'undefined') {
        self.postMessage({ event: 'error', message: 'PcapRenderer missing from worker bundle' });
        return;
      }
      out = _parsePcap(buffer);
    } else {
      self.postMessage({ event: 'error', message: 'unknown timeline kind: ' + kind });
      return;
    }

    const t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    _workerMark('dispatchEnd');
    out.event = 'done';
    out.kind = kind;
    out.parseMs = Math.max(0, t1 - t0);
    // Ship the worker-internal marker bag + counters alongside the
    // existing `parseMs`. Both are additive optional fields — older
    // host bundles that don't know about them ignore the keys
    // silently. The objects are plain dictionaries (no Map / Set /
    // class instances) so structured-clone across the postMessage
    // boundary is cheap and round-trips exactly. Cloned once into
    // plain objects so the receiver doesn't see the
    // `Object.create(null)` prototype (which has historically tripped
    // up JSON.stringify in some toolchains).
    out.workerMarks = Object.assign({}, _workerMarks);
    out.workerCounters = Object.assign({}, _workerCounters);
    self.postMessage(out);
  } catch (e) {
    const message = (e && e.message) ? e.message : String(e);
    self.postMessage({ event: 'error', message });
  } finally {
    _workerMarks = null;
    _workerCounters = null;
  }
};
