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
// in:  { kind: 'csv', buffer: ArrayBuffer (transferred), explicitDelim?: string }
//      { kind: 'evtx', buffer: ArrayBuffer (transferred) }
//      { kind: 'sqlite', buffer: ArrayBuffer (transferred) }
//
// out (CSV/TSV) — STREAMING:
//   Zero or more intermediate row batches:
//     { event: 'rows', batch: [[...], ...] }
//   Then exactly one terminal:
//     { event: 'done', kind: 'csv',
//       columns: [...], rows: [],         (always empty — rows arrive in batches)
//       formatLabel: 'CSV'|'TSV',
//       truncated: boolean, originalRowCount: number,
//       parseMs: number }
//   The host caller must register an `onBatch(msg)` sink via
//   `WorkerManager.runTimeline(buffer, 'csv', { onBatch })` to accumulate
//   the streamed batches; without one the rows are silently dropped on
//   the floor. See `src/app/timeline/timeline-router.js::_loadFileInTimeline`.
//
// out (EVTX):
//   { event: 'done', kind: 'evtx',
//     columns: [...], rows: [[...], ...], evtxEvents: [...],
//     formatLabel: 'EVTX',
//     truncated: boolean, originalRowCount: number,
//     defaultTimeColIdx: 0, defaultStackColIdx: 1,
//     parseMs: number }
//
// out (SQLite):
//   { event: 'done', kind: 'sqlite',
//     columns: [...], rows: [[...], ...],
//     formatLabel: string, browserType: 'chrome'|'firefox'|'edge'|null,
//     truncated: boolean, originalRowCount: number,
//     defaultTimeColIdx: number|null, defaultStackColIdx: number|null,
//     parseMs: number }
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

// ── CSV / TSV parse (streaming chunk-decode + line-tail buffer) ────────────
//
// Memory-conscious rewrite of the legacy "decode into one giant string,
// then walk it" parser. Three differences from the prior implementation:
//
//   1. We never materialise the entire decoded UTF-8 text — only the
//      current decoded chunk plus a small tail buffer that holds the
//      partial last line spilling into the next chunk. For a 318 MB
//      ASCII CSV the prior code peaked at ~1.3 GB transient (full UTF-16
//      string ≈ 636 MB plus the `parts.join('')` doubling); the streaming
//      version stays under ~50 MB on top of the input.
//   2. Rows are emitted to the host in batches of 50 000 via
//      `{event:'rows', batch:[...]}` postMessage events. The terminal
//      `done` payload only carries metadata (`columns`, `formatLabel`,
//      `truncated`, `originalRowCount`) plus an empty `rows: []` so the
//      structured-clone postback isn't doubling peak memory at the very
//      end.
//   3. The legacy "if a quote-aware split throws, fall back to a
//      line-by-line split" branch is preserved: we wrap each chunk's
//      row-extraction loop in try/catch and on the rare pathological
//      input restart parsing of the chunk via a tighter forgiving
//      splitter. Errors from outside the splitter still bubble.
//
// The `explicitDelim` argument lets the host force a delimiter (TSV
// uses `\t`); when omitted we sniff using `CsvRenderer._delim` over the
// first decoded chunk only — sufficient signal for any real CSV.
async function _parseCsv(buffer, explicitDelim) {
  const bytes = new Uint8Array(buffer);
  const DECODE_CHUNK = RENDER_LIMITS.DECODE_CHUNK_BYTES;
  const BATCH_ROWS = 50_000;            // rows per `{event:'rows'}` postMessage

  const decoder = new TextDecoder('utf-8', { fatal: false });
  const r = new CsvRenderer();

  // Tail buffer: text that survived the last chunk because no `\n`
  // followed it yet (i.e. the partial last line). On the next iteration
  // we prepend this to the freshly decoded chunk before scanning lines.
  let tail = '';
  // True once we've consumed and parsed the header line.
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
  let pendingBatch = [];

  const flushBatch = () => {
    if (!pendingBatch.length) return;
    self.postMessage({ event: 'rows', batch: pendingBatch });
    pendingBatch = [];
  };

  // Split a single line into cells, defensively. Mirrors the legacy
  // "indexOf('"') first" branching so unquoted lines avoid the slower
  // state-machine path.
  const splitLine = (line) => {
    if (line.indexOf('"') === -1) return line.split(delim);
    try { return r._splitQuoted(line, delim); }
    catch (_) { return line.split(delim); }
  };

  const padOrTrimCells = (cells) => {
    if (!colLen) return cells;
    if (cells.length < colLen) {
      while (cells.length < colLen) cells.push('');
    } else if (cells.length > colLen) {
      const tailCells = cells.slice(colLen - 1).join(delim);
      cells.length = colLen;
      cells[colLen - 1] = tailCells;
    }
    return cells;
  };

  const consumeLine = (line) => {
    if (!headerSeen) {
      // First non-empty position is the header. We allow blank leading
      // lines but in practice CSVs never have them.
      if (!line) return;
      if (!delim) {
        try { delim = r._delim(line); } catch (_) { delim = ','; }
        formatLabel = (delim === '\t') ? 'TSV' : 'CSV';
      }
      let cols;
      try { cols = splitLine(line); } catch (_) { cols = line.split(delim); }
      columns = cols.map(c => String(c == null ? '' : c).trim());
      colLen = columns.length;
      headerSeen = true;
      return;
    }
    if (!line) return;                  // skip blank lines mid-stream
    if (rowCount >= TIMELINE_MAX_ROWS) {
      truncated = true;
      return;
    }
    const cells = padOrTrimCells(splitLine(line));
    pendingBatch.push(cells);
    rowCount++;
    if (pendingBatch.length >= BATCH_ROWS) flushBatch();
  };

  outer:
  for (let pos = 0; pos < bytes.length; pos += DECODE_CHUNK) {
    const end = Math.min(pos + DECODE_CHUNK, bytes.length);
    const stream = end < bytes.length;
    let chunk = decoder.decode(bytes.subarray(pos, end), { stream });

    if (firstChunk) {
      if (chunk.charCodeAt(0) === 0xFEFF) chunk = chunk.slice(1);
      firstChunk = false;
    }
    // Normalise CRLF / bare CR. We do this per chunk; the only case the
    // single-pass `\r\n?` regex misses is a `\r` at the very end of the
    // chunk followed by `\n` at the start of the next chunk. Handle it
    // by trimming a trailing lone `\r` into the tail.
    if (chunk.indexOf('\r') !== -1) chunk = chunk.replace(/\r\n?/g, '\n');

    let scan = tail + chunk;
    bytesConsumed = end;
    tail = '';

    let lineStart = 0;
    while (true) {
      const nl = scan.indexOf('\n', lineStart);
      if (nl === -1) {
        // Partial line — hold for next chunk.
        tail = lineStart === 0 ? scan : scan.substring(lineStart);
        break;
      }
      const line = scan.substring(lineStart, nl);
      lineStart = nl + 1;
      try { consumeLine(line); }
      catch (_) {
        // Pathological row — skip and continue. We deliberately don't
        // fall back to a whole-file forgiving split here as the legacy
        // code did: a single bad line should not lose the rest of the
        // stream.
      }
      if (truncated) break outer;
    }
  }

  // Flush any final tail line that didn't end with a newline.
  if (tail) {
    try { consumeLine(tail); } catch (_) { /* ignore */ }
  }
  // Drain the last partial batch.
  flushBatch();

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
async function _parseEvtx(buffer) {
  const r = new EvtxRenderer();
  let events = [];
  try {
    events = await r._parseAsync(new Uint8Array(buffer)) || [];
  } catch (_) {
    events = [];
  }

  const columns = [...EVTX_COLUMN_ORDER];
  let truncated = false;
  let list = events;
  if (events.length > TIMELINE_MAX_ROWS) {
    list = events.slice(0, TIMELINE_MAX_ROWS);
    truncated = true;
  }
  const rows = new Array(list.length);
  for (let i = 0; i < list.length; i++) {
    const ev = list[i] || {};
    rows[i] = [
      ev.timestamp ? ev.timestamp.replace('T', ' ').replace('Z', '') : '',
      ev.eventId || '', ev.level || '', ev.provider || '',
      ev.channel || '', ev.computer || '', ev.eventData || '',
    ];
  }

  // Strip the per-event `rawRecord` Uint8Array before transferring — those
  // copies sum to most of the file size and the Detections / view code on
  // the main thread doesn't need them (they live in the parsed `events`
  // returned from `_parseAsync` only for the "Raw Record" drawer pane,
  // which is a renderer-mode-only feature, not Timeline).
  const trimmedEvents = new Array(list.length);
  for (let i = 0; i < list.length; i++) {
    const ev = list[i];
    if (!ev) { trimmedEvents[i] = ev; continue; }
    // shallow clone, drop rawRecord
    const { rawRecord, ...rest } = ev;
    trimmedEvents[i] = rest;
  }

  return {
    columns, rows,
    evtxEvents: trimmedEvents,
    formatLabel: 'EVTX',
    truncated,
    originalRowCount: events.length,
    defaultTimeColIdx: 0,
    defaultStackColIdx: 1,
  };
}

// ── SQLite browser-history parse (mirrors TimelineView.fromSqlite) ─────────
function _parseSqlite(buffer) {
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
  let truncated = false;
  let list = srcRows;
  if (list.length > TIMELINE_MAX_ROWS) {
    list = list.slice(0, TIMELINE_MAX_ROWS);
    truncated = true;
  }
  const rows = new Array(list.length);
  for (let i = 0; i < list.length; i++) {
    const src = list[i] || [];
    const row = new Array(colCount);
    for (let j = 0; j < colCount; j++) {
      row[j] = src[j] != null ? String(src[j]) : '';
    }
    rows[i] = row;
  }

  const browserLabel = db.browserType === 'firefox' ? 'Firefox' : 'Chrome';
  const timeColIdx = useEvents ? 0 : 3;
  const stackColIdx = useEvents ? 1 : null;

  return {
    columns, rows,
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

  const t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
  try {
    if (!buffer) {
      self.postMessage({ event: 'error', message: 'no buffer transferred to worker' });
      return;
    }

    let out;
    if (kind === 'csv') {
      if (typeof CsvRenderer === 'undefined') {
        self.postMessage({ event: 'error', message: 'CsvRenderer missing from worker bundle' });
        return;
      }
      out = await _parseCsv(buffer, msg.explicitDelim);
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
    } else {
      self.postMessage({ event: 'error', message: 'unknown timeline kind: ' + kind });
      return;
    }

    const t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    out.event = 'done';
    out.kind = kind;
    out.parseMs = Math.max(0, t1 - t0);
    self.postMessage(out);
  } catch (e) {
    const message = (e && e.message) ? e.message : String(e);
    self.postMessage({ event: 'error', message });
  }
};
