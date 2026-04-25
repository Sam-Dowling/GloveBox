'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline.worker.js — Timeline parse-only worker (PLAN C2)
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
// out (CSV/TSV):
//   { event: 'done', kind: 'csv',
//     columns: [...], rows: [[...], ...],
//     formatLabel: 'CSV'|'TSV',
//     truncated: boolean, originalRowCount: number,
//     parseMs: number }
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
// bytes again — `_loadFileInTimeline` keeps reading `_fileBuffer` after the
// timeline factory returns to feed `_loadFile` for the analyser sidebar —
// pass a `buffer.slice(0)` copy. See `src/worker-manager.js::runTimeline`.
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

// ── CSV / TSV parse (mirrors TimelineView.fromCsvAsync minus DOM) ──────────
async function _parseCsv(buffer, explicitDelim) {
  const bytes = new Uint8Array(buffer);
  const DECODE_CHUNK = RENDER_LIMITS.DECODE_CHUNK_BYTES;

  // Chunked UTF-8 decode + LF-normalisation (same algorithm as the main
  // thread; see `app-timeline.js::fromCsvAsync` for the rationale).
  let norm;
  if (bytes.length <= DECODE_CHUNK) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const noBom = text.charCodeAt(0) === 0xFEFF ? text.slice(1) : text;
    norm = noBom.indexOf('\r') !== -1 ? noBom.replace(/\r\n?/g, '\n') : noBom;
  } else {
    const decoder = new TextDecoder('utf-8', { fatal: false });
    const parts = [];
    let first = true;
    for (let pos = 0; pos < bytes.length; pos += DECODE_CHUNK) {
      const end = Math.min(pos + DECODE_CHUNK, bytes.length);
      const stream = end < bytes.length;
      let chunk = decoder.decode(bytes.subarray(pos, end), { stream });
      if (first) {
        if (chunk.charCodeAt(0) === 0xFEFF) chunk = chunk.slice(1);
        first = false;
      }
      if (chunk.indexOf('\r') !== -1) chunk = chunk.replace(/\r\n?/g, '\n');
      parts.push(chunk);
    }
    norm = parts.join('');
  }

  if (!norm || !norm.trim()) {
    return { columns: [], rows: [], formatLabel: 'CSV', truncated: false, originalRowCount: 0 };
  }

  const r = new CsvRenderer();
  let delim = explicitDelim;
  if (!delim) {
    try { delim = r._delim(norm); } catch (_) { delim = ','; }
  }
  const firstNl = norm.indexOf('\n');
  const headerLine = firstNl === -1 ? norm : norm.substring(0, firstNl);
  let columns = [];
  try {
    columns = headerLine.indexOf('"') === -1
      ? headerLine.split(delim)
      : r._splitQuoted(headerLine, delim);
  } catch (_) {
    columns = headerLine.split(delim);
  }
  columns = columns.map(c => String(c == null ? '' : c).trim());

  const len = norm.length;
  let offset = firstNl === -1 ? len : firstNl + 1;
  const rows = [];
  const colLen = columns.length;

  // No yieldTick needed — we're already off the main thread, so a
  // synchronous tight loop is the right call. `await` between chunks on
  // the main thread existed only to keep the UI painting; we don't have
  // a UI here.
  try {
    while (offset < len && rows.length < TIMELINE_MAX_ROWS) {
      let lineEnd = norm.indexOf('\n', offset);
      if (lineEnd === -1) lineEnd = len;
      if (lineEnd > offset) {
        const line = norm.substring(offset, lineEnd);
        const cells = line.indexOf('"') === -1
          ? line.split(delim)
          : r._splitQuoted(line, delim);
        if (colLen) {
          if (cells.length < colLen) {
            while (cells.length < colLen) cells.push('');
          } else if (cells.length > colLen) {
            const tail = cells.slice(colLen - 1).join(delim);
            cells.length = colLen;
            cells[colLen - 1] = tail;
          }
        }
        rows.push(cells);
      }
      offset = lineEnd + 1;
    }
  } catch (e) {
    // Pathological line — fall back to forgiving line-by-line split.
    rows.length = 0;
    const lines = norm.split('\n');
    for (let i = 1; i < lines.length && rows.length < TIMELINE_MAX_ROWS; i++) {
      const ln = lines[i];
      if (!ln) continue;
      const cells = ln.indexOf('"') === -1 ? ln.split(delim) : r._splitQuoted(ln, delim);
      if (colLen) {
        if (cells.length < colLen) {
          while (cells.length < colLen) cells.push('');
        } else if (cells.length > colLen) {
          const tail = cells.slice(colLen - 1).join(delim);
          cells.length = colLen;
          cells[colLen - 1] = tail;
        }
      }
      rows.push(cells);
    }
  }

  if (colLen) {
    for (let i = 0; i < rows.length; i++) {
      if (!rows[i]) rows[i] = new Array(colLen).fill('');
    }
  } else if (rows.length) {
    const n = Math.max(...rows.map(r => (r && r.length) || 0));
    columns = [];
    for (let i = 0; i < n; i++) columns.push(`col ${i + 1}`);
  }

  const truncated = rows.length >= TIMELINE_MAX_ROWS && offset < len;
  const originalRowCount = truncated
    ? Math.round(rows.length * (len / Math.max(1, offset)))
    : rows.length;

  return {
    columns, rows,
    formatLabel: delim === '\t' ? 'TSV' : 'CSV',
    truncated, originalRowCount,
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
