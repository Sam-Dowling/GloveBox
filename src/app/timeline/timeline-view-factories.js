'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-factories.js — TimelineView static factory mixin (B2a).
//
// Hosts the three static factories that build a fully-populated
// TimelineView from a parsed file buffer:
//
//   - TimelineView.fromCsvAsync(file, buffer, explicitDelim)
//   - TimelineView.fromEvtx(file, buffer)
//   - TimelineView.fromSqlite(file, buffer)
//
// Each is a pure factory: every body ends with `return new
// TimelineView({...})` and never touches instance state. They reach
// only into globals (RowStore / RowStoreBuilder, EVTX_COLUMN_ORDER,
// CsvRenderer / EvtxRenderer / SqliteRenderer, RENDER_LIMITS,
// TIMELINE_MAX_ROWS) — all of which load before this file in the
// concatenated bundle.
//
// Loads AFTER timeline-view.js (which declares `class TimelineView`).
// `Object.assign(TimelineView, {...})` attaches enumerable own
// properties on the constructor — invisible to callers (`TimelineView
// .fromCsvAsync(...)` works whether the method was declared with the
// `static` keyword or attached here). No callers do
// `Object.getOwnPropertyDescriptor(TimelineView, 'fromCsvAsync')`.
//
// Analysis-bypass guard: like the rest of src/app/timeline/, these
// factories never push to `app.findings`, never call `pushIOC`, and
// never instantiate `EncodedContentDetector`. The lone exception is
// the EVTX path's `EvtxRenderer.analyzeForSecurity` call, whose result
// is threaded into the TimelineView constructor purely to feed the
// in-view Detections + Entities sections (see timeline-detections.js).
// ════════════════════════════════════════════════════════════════════════════

// Structured-log kind registry — mirrors `STRUCTURED_LOG_KINDS` in
// `src/workers/timeline.worker.js`. The factory uses this to pick a
// `(tokenize, columns, label)` triple for the sync `file://` fallback.
// **Keep in lockstep with the worker copy.** Both copies exist so the
// sync and async paths produce identical row matrices.
TimelineView._STRUCTURED_LOG_KINDS = {
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
    makeTokenizer: () => _tlMakeZeekTokenizer(),
    label: 'Zeek',
  },
  jsonl: {
    makeTokenizer: () => _tlMakeJsonlTokenizer(),
    label: 'JSONL',
  },
  cloudtrail: {
    makeTokenizer: () => _tlMakeCloudTrailTokenizer(),
    label: 'AWS CloudTrail',
  },
  cef: {
    makeTokenizer: () => _tlMakeCEFTokenizer(),
    label: 'CEF',
  },
  leef: {
    makeTokenizer: () => _tlMakeLEEFTokenizer(),
    label: 'LEEF',
  },
  logfmt: {
    makeTokenizer: () => _tlMakeLogfmtTokenizer(),
    label: 'logfmt',
  },
  w3c: {
    makeTokenizer: () => _tlMakeW3CTokenizer(),
    label: 'W3C Extended',
  },
  'apache-error': {
    makeTokenizer: () => _tlMakeApacheErrorTokenizer(),
    label: 'Apache error_log',
  },
};

Object.assign(TimelineView, {

  // Parse a CSV / TSV buffer resiliently. Janky inputs (unescaped JSON or XML
  // in cells, ragged row widths, embedded newlines, mixed CRLF/LF) must not
  // fall through to the plaintext viewer — forensic exports routinely carry
  // all of the above. We lean on `CsvRenderer._parse`, which already handles
  // RFC-4180 quoting + embedded newlines, but wrap every step in a try /
  // catch so a single bad chunk degrades into "fewer rows" rather than
  // "nothing at all". The header row is tolerated with 0 columns so that
  // headerless inputs (no named columns at all) still render as col-1,
  // col-2, … and the view stays usable.
  // Async CSV factory — parses in chunks of CHUNK_ROWS lines, yielding to
  // the event loop between chunks so the browser stays responsive for large
  // files.
  //
  // For files above DECODE_CHUNK_BYTES (16 MB) the text is decoded in
  // slices via `TextDecoder({ stream: true })` with inline CRLF
  // normalisation so we never allocate a single string anywhere near
  // V8's ~512 M-character limit. For smaller files the whole buffer is
  // decoded in one shot (fast path — no overhead).
  async fromCsvAsync(file, buffer, explicitDelim, kindHint) {
    const bytes = new Uint8Array(buffer);
    const DECODE_CHUNK = RENDER_LIMITS.DECODE_CHUNK_BYTES; // 16 MB

    // ── Chunked UTF-8 decode with inline CRLF strip ───────────────────
    // Decodes `bytes` into a single LF-normalised string. For buffers
    // larger than DECODE_CHUNK we slice into 16 MB pieces and use the
    // streaming TextDecoder mode so each intermediate string is small.
    // CRLF → LF replacement happens per-chunk to avoid a second full-
    // string regex pass.
    let norm;
    if (bytes.length <= DECODE_CHUNK) {
      // Fast path — small file, decode in one shot.
      const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      const noBom = text.charCodeAt(0) === 0xFEFF ? text.slice(1) : text;
      norm = noBom.indexOf('\r') !== -1 ? noBom.replace(/\r\n?/g, '\n') : noBom;
    } else {
      // Chunked path — large file.  Decode 16 MB at a time, strip BOM
      // from the very first chunk, normalise CRLF per-chunk, and
      // concatenate.  Each intermediate string is ≤ 16 M chars, well
      // within V8's limit.
      const decoder = new TextDecoder('utf-8', { fatal: false });
      const parts = [];
      let first = true;
      for (let pos = 0; pos < bytes.length; pos += DECODE_CHUNK) {
        const end = Math.min(pos + DECODE_CHUNK, bytes.length);
        const stream = end < bytes.length; // keep state if more data follows
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
      return new TimelineView({
        file, columns: [], store: RowStore.empty([]),
        formatLabel: 'CSV', truncated: false, originalRowCount: 0,
      });
    }
    const r = new CsvRenderer();
    const isLog = kindHint === 'log';

    // ── CLF (`.log`) sync path — bypass CsvRenderer entirely ───────────
    //
    // The worker-first path in the router does the same thing in
    // `timeline.worker.js::_parseCsv` (the `if (isLog)` block). This
    // sync fallback fires when workers are unavailable (Firefox
    // file://). See `_tlTokenizeClfLine` for the rationale: Apache /
    // Nginx CLF uses backslash-escaped quotes, not RFC4180 doubled
    // quotes, so the generic CSV parser corrupts state on ~6 % of
    // real lines. We tokenise per-line instead.
    if (isLog) {
      const rowsLog = [];
      let columnsLog = [];
      let lineStart = 0;
      let truncatedLog = false;
      const lenLog = norm.length;
      while (lineStart < lenLog && rowsLog.length < TIMELINE_MAX_ROWS) {
        const nl = norm.indexOf('\n', lineStart);
        const lineEnd = nl < 0 ? lenLog : nl;
        const line = norm.slice(lineStart, lineEnd);
        lineStart = nl < 0 ? lenLog : nl + 1;
        if (!line) continue;
        const cells = _tlTokenizeClfLine(line);
        if (!cells) continue;
        if (!columnsLog.length) {
          columnsLog = _tlCanonicalLogColumns(cells.length);
        }
        // Pad / trim to the canonical width so RowStore receives a
        // dense matrix (mirrors the CSV path's `padOrTrim`).
        const width = columnsLog.length;
        if (cells.length < width) {
          while (cells.length < width) cells.push('');
        } else if (cells.length > width) {
          cells.length = width;
        }
        rowsLog.push(cells);
      }
      truncatedLog = rowsLog.length >= TIMELINE_MAX_ROWS && lineStart < lenLog;
      const originalRowCountLog = truncatedLog
        ? Math.round(rowsLog.length * (lenLog / Math.max(1, lineStart)))
        : rowsLog.length;
      const storeLog = RowStore.fromStringMatrix(columnsLog, rowsLog);
      rowsLog.length = 0;
      return new TimelineView({
        file, columns: columnsLog, store: storeLog,
        formatLabel: 'LOG',
        truncated: truncatedLog,
        originalRowCount: originalRowCountLog,
      });
    }

    let delim = explicitDelim;
    if (!delim) {
      try { delim = r._delim(norm); } catch (_) { delim = ','; }
    }
    // ── Header extraction ──────────────────────────────────────────────
    // Use the shared RFC-4180 state-machine parser so a header that
    // includes a multi-line quoted cell parses correctly (the legacy
    // `norm.indexOf('\n')` slice would chop the header in half on the
    // first embedded newline). Same parser drives the body loop below.
    let columns = [];
    let bodyStartIdx;
    const headerState = CsvRenderer.initParserState();
    const headerResult = CsvRenderer.parseChunk(norm, 0, headerState, delim, {
      baseOffset: 0, maxRows: 1, flush: false,
    });
    if (headerResult.rows.length) {
      columns = headerResult.rows[0];
      bodyStartIdx = headerResult.endIdx;
    } else if (norm.length) {
      // Single-line file (no trailing newline). Flush to extract.
      const flushResult = CsvRenderer.parseChunk(norm, headerResult.endIdx, headerState, delim, {
        baseOffset: 0, maxRows: 0, flush: true,
      });
      if (flushResult.rows.length) columns = flushResult.rows[0];
      bodyStartIdx = norm.length;
    } else {
      bodyStartIdx = 0;
    }
    // Trim and de-noise column names — whitespace / stray quotes from
    // hand-edited exports throw off `_tlAutoDetectTimestampCol` otherwise.
    columns = columns.map(c => String(c == null ? '' : c).trim());

    // ── Chunked parse ─────────────────────────────────────────────────
    // Parse CHUNK_ROWS rows at a time, yielding to the event loop between
    // chunks via MessageChannel (zero-delay, matches the existing
    // _parseStreaming pattern in CsvRenderer). State threads across
    // yields so multi-line quoted cells straddling a chunk boundary work.
    const CHUNK_ROWS = 50000;
    const len = norm.length;
    let offset = bodyStartIdx;
    const rows = [];
    const colLen = columns.length;
    const bodyState = CsvRenderer.initParserState();

    const padOrTrim = (cells) => {
      if (!colLen) return cells;
      if (cells.length < colLen) {
        while (cells.length < colLen) cells.push('');
      } else if (cells.length > colLen) {
        const tail = cells.slice(colLen - 1).join(delim);
        cells.length = colLen;
        cells[colLen - 1] = tail;
      }
      return cells;
    };

    // Zero-delay yield helper — returns a Promise that resolves on the
    // next microtask boundary via MessageChannel (or setTimeout
    // fallback), giving the browser a chance to paint / handle input.
    const yieldTick = () => new Promise(resolve => {
      if (typeof MessageChannel !== 'undefined') {
        const ch = new MessageChannel();
        ch.port1.onmessage = () => { ch.port1.close(); resolve(); };
        ch.port2.postMessage(null);
      } else {
        setTimeout(resolve, 0);
      }
    });

    try {
      while (offset < len && rows.length < TIMELINE_MAX_ROWS) {
        const cap = Math.min(CHUNK_ROWS, TIMELINE_MAX_ROWS - rows.length);
        const result = CsvRenderer.parseChunk(norm, offset, bodyState, delim, {
          baseOffset: 0, maxRows: cap, flush: false,
        });
        offset = result.endIdx;
        for (let i = 0; i < result.rows.length; i++) {
          rows.push(padOrTrim(result.rows[i]));
        }
        // Yield to the event loop so the browser can paint / stay responsive.
        if (offset < len && rows.length < TIMELINE_MAX_ROWS) {
          await yieldTick();
        }
      }
      // Final flush — emit any trailing partial row (file without
      // newline at EOF, or unterminated quoted cell).
      if (rows.length < TIMELINE_MAX_ROWS) {
        const flushResult = CsvRenderer.parseChunk(norm, offset, bodyState, delim, {
          baseOffset: 0, maxRows: 0, flush: true,
        });
        for (let i = 0; i < flushResult.rows.length; i++) {
          if (rows.length >= TIMELINE_MAX_ROWS) break;
          rows.push(padOrTrim(flushResult.rows[i]));
        }
      }
    } catch (e) {
      // The state-machine parser is robust against malformed input
      // (it never throws on quote/delimiter combos), so this catch is
      // belt-and-braces only. Log and surface what we managed to parse.
      console.warn('[timeline] CSV parser failed:', e);
    }

    // Null-row normalisation (for rows that somehow ended up null).
    if (colLen) {
      for (let i = 0; i < rows.length; i++) {
        if (!rows[i]) rows[i] = new Array(colLen).fill('');
      }
    } else if (rows.length) {
      // Headerless input — synthesise generic column names.
      const n = Math.max(...rows.map(r => (r && r.length) || 0));
      columns = [];
      for (let i = 0; i < n; i++) columns.push(`col ${i + 1}`);
    }
    const truncated = rows.length >= TIMELINE_MAX_ROWS && offset < len;
    // `originalRowCount` should reflect the true file row count. For
    // non-truncated files, rows.length is exact. For truncated files, we
    // can estimate from the fraction of the file consumed.
    const originalRowCount = truncated
      ? Math.round(rows.length * (len / Math.max(1, offset)))
      : rows.length;
    // Phase 8: build the RowStore here (the headerless-fallback above
    // mutates `columns` after the parse loop, so we can't stream rows
    // into a `RowStoreBuilder` mid-parse without losing that path).
    // `RowStore.fromStringMatrix` preserves the same peak as the
    // pre-Phase-8 constructor did internally.
    const store = RowStore.fromStringMatrix(columns, rows);
    rows.length = 0;
    return new TimelineView({
      file, columns, store,
      formatLabel: delim === '\t' ? 'TSV' : 'CSV',
      truncated, originalRowCount,
    });
  },

  // ── Structured-log sync factory (Firefox file:// fallback) ────────────
  //
  // Mirrors the worker-side `_parseStructuredLog` in
  // `src/workers/timeline.worker.js` for environments where workers
  // can't spawn (Firefox `file://`). Same chunked-decode + per-line
  // tokeniser pipeline; per-format `tokenizeLine` and `getColumns`
  // come from the small registry below.
  //
  // `kindHint` is the same string the worker accepts ('syslog3164',
  // and friends as we add them). Throws on unknown hints — the router
  // is the single dispatch site, so a typo there should fail loudly
  // rather than silently produce a 0-row view.
  async fromStructuredLogAsync(file, buffer, kindHint) {
    const cfg = TimelineView._STRUCTURED_LOG_KINDS[kindHint];
    if (!cfg) {
      throw new Error('fromStructuredLogAsync: unknown kindHint: ' + kindHint);
    }
    // Stateless kinds expose `tokenize` + `columns` on the config;
    // stateful kinds (Zeek) expose `makeTokenizer()` returning the
    // same pair (plus optional `getDefaultStackColIdx` /
    // `getFormatLabel` for post-schema overrides). Resolve once per
    // parse so state can't leak across files.
    let tokenizeLine, getColumns;
    let getDefaultStackColIdx = null;
    let getFormatLabel = null;
    if (typeof cfg.makeTokenizer === 'function') {
      const tk = cfg.makeTokenizer();
      tokenizeLine = tk.tokenize;
      getColumns = tk.getColumns;
      getDefaultStackColIdx = tk.getDefaultStackColIdx || null;
      getFormatLabel = tk.getFormatLabel || null;
    } else {
      tokenizeLine = cfg.tokenize;
      getColumns = cfg.columns;
    }
    const bytes = new Uint8Array(buffer);
    const DECODE_CHUNK = RENDER_LIMITS.DECODE_CHUNK_BYTES;
    const decoder = new TextDecoder('utf-8', { fatal: false });
    // Mtime ms threads through the tokeniser; see the worker copy
    // (`timeline.worker.js::_parseStructuredLog`) and the canonical
    // `_tlTokenizeSyslog3164` for the year-inference rule.
    const nowMs = (file && file.lastModified) | 0;
    const yieldTick = () => new Promise(resolve => {
      if (typeof MessageChannel !== 'undefined') {
        const ch = new MessageChannel();
        ch.port1.onmessage = () => { ch.port1.close(); resolve(); };
        ch.port2.postMessage(null);
      } else {
        setTimeout(resolve, 0);
      }
    });
    let columns = [];
    let colLen = 0;
    let headerSeen = false;
    const rows = [];
    let truncated = false;
    let bytesConsumed = 0;
    let tail = '';
    let firstChunk = true;
    const padOrTrim = (cells) => {
      if (!colLen) return cells;
      if (cells.length < colLen) {
        while (cells.length < colLen) cells.push('');
      } else if (cells.length > colLen) {
        cells.length = colLen;
      }
      return cells;
    };
    outerStruct:
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
        }
        if (rows.length >= TIMELINE_MAX_ROWS) { truncated = true; break outerStruct; }
        rows.push(padOrTrim(cells));
      }
      if (lineStart >= text.length) tail = '';
      // Yield to keep the tab responsive on large files.
      if (end < bytes.length) await yieldTick();
    }
    if (!truncated && tail) {
      const cells = tokenizeLine(tail, nowMs);
      if (cells) {
        if (!headerSeen) {
          columns = getColumns(cells.length);
          colLen = columns.length;
          headerSeen = true;
        }
        if (rows.length < TIMELINE_MAX_ROWS) rows.push(padOrTrim(cells));
      }
    }
    if (!headerSeen) { columns = []; colLen = 0; }
    const originalRowCount = truncated
      ? Math.round(rows.length * (bytes.length / Math.max(1, bytesConsumed)))
      : rows.length;
    const store = RowStore.fromStringMatrix(columns, rows);
    rows.length = 0;
    // Stateful tokenisers can override label + default stack column
    // after seeing the file's schema (Zeek picks the format label
    // 'Zeek (<path>)' from `#path` and the stack column from
    // `_TL_ZEEK_STACK_BY_PATH`).
    const dynStack = (typeof getDefaultStackColIdx === 'function')
      ? getDefaultStackColIdx() : null;
    const dynLabel = (typeof getFormatLabel === 'function')
      ? getFormatLabel() : null;
    return new TimelineView({
      file, columns, store,
      formatLabel: dynLabel || cfg.label,
      truncated,
      originalRowCount,
      defaultTimeColIdx: 0,
      defaultStackColIdx: Number.isInteger(dynStack) ? dynStack : 1,
    });
  },

  // Parse an EVTX buffer resiliently. `EvtxRenderer._parseAsync` already
  // skips truncated chunks and malformed BinXml templates, but a hard
  // failure on the file header would otherwise bubble up and abort the
  // load. We attach the parsed events + an `EvtxRenderer.analyzeForSecurity`
  // result to the view so Detections / Entities sections can read them
  // without a second parse pass.
  //
  // Uses the async parser with cooperative yielding so the browser stays
  // responsive during large EVTX files (10–30+ seconds of parse time).
  async fromEvtx(file, buffer) {
    const r = new EvtxRenderer();
    let events = [];
    try {
      events = await r._parseAsync(new Uint8Array(buffer)) || [];
    } catch (e) {
      console.warn('[timeline] EVTX parse failed:', e);
      events = [];
    }
    // Run the Sigma-style analyzer against the events we already have so
    // the Detections / Entities sections get a full threat-hunt yield
    // without re-parsing a multi-hundred-MB log.
    let securityFindings = null;
    try {
      securityFindings = r.analyzeForSecurity(buffer, file && file.name, events);
    } catch (e) {
      console.warn('[timeline] EVTX analyzeForSecurity failed:', e);
    }

    const columns = [...EVTX_COLUMN_ORDER];
    let truncated = false;
    let list = events;
    if (events.length > TIMELINE_MAX_ROWS) {
      list = events.slice(0, TIMELINE_MAX_ROWS);
      truncated = true;
    }
    // Phase 8: stream rows directly into a `RowStoreBuilder` so the
    // parallel `string[][]` accumulator is no longer needed. Each
    // batch of `_ROWSTORE_CHUNK_ROWS_TARGET` rows (50 K) is packed
    // into typed arrays as it forms; the per-row cell strings can GC
    // before the builder reaches the next batch.
    const builder = new RowStoreBuilder(columns);
    for (let i = 0; i < list.length; i++) {
      const ev = list[i] || {};
      builder.addRow([
        ev.timestamp ? ev.timestamp.replace('T', ' ').replace('Z', '') : '',
        ev.eventId || '', ev.level || '', ev.provider || '',
        ev.channel || '', ev.computer || '', ev.eventData || '',
      ]);
    }
    // `evtxEvents` MUST be the same length as the RowStore (`list.length`),
    // not the original `events.length`. Consumers in `timeline-summary.js`
    // and `timeline-detections.js` walk `_evtxEvents` in parallel with
    // `_timeMs[i]` and `store.getRow(i)`; both of those are sized to
    // `list.length` (the truncated-to-`TIMELINE_MAX_ROWS` slice). The
    // worker path in `timeline.worker.js::_parseEvtx` already slices
    // `trimmedEvents` to `list.length` for the same reason; the sync path
    // must match. Without the slice, EVTX > TIMELINE_MAX_ROWS taking the
    // sync fallback (worker rejected, file:// Firefox) would walk past
    // `_timeMs.length` and read `undefined` timestamps and empty rows.
    return new TimelineView({
      file, columns, store: builder.finalize(),
      formatLabel: 'EVTX', truncated, originalRowCount: events.length,
      defaultTimeColIdx: 0, defaultStackColIdx: 1,
      evtxEvents: list === events ? events : list,
      evtxFindings: securityFindings,
    });
  },

  // ── SQLite browser history ──────────────────────────────────────────────
  //
  // Reuses SqliteRenderer._parseDb() to extract the browser-history rows,
  // then projects them into the same { columns, rows } shape the
  // TimelineView constructor expects.  Generic (non-browser) SQLite
  // databases return a zero-row view so the fallback escape hatch in
  // _loadFileInTimeline re-routes them to the regular SqliteRenderer
  // tabbed-grid pipeline.

  fromSqlite(file, buffer) {
    const r = new SqliteRenderer();
    let db;
    try {
      db = r._parseDb(new Uint8Array(buffer));
    } catch (e) {
      console.warn('[timeline] SQLite parse failed:', e);
      // Return zero-row view — triggers fallback to regular analyser.
      return new TimelineView({
        file, columns: [], store: RowStore.empty([]),
        formatLabel: 'SQLite', truncated: false, originalRowCount: 0,
      });
    }

    // Only browser history databases get the Timeline treatment.
    // Prefer per-event rows (historyEventRows) when available; fall
    // back to the legacy URL-aggregated view (historyRows) otherwise.
    const useEvents = db.historyEventRows && db.historyEventRows.length > 0;
    const srcCols = useEvents ? db.historyEventColumns : db.historyColumns;
    const srcRows = useEvents ? db.historyEventRows : db.historyRows;

    if (!db.browserType || !srcRows || srcRows.length === 0) {
      return new TimelineView({
        file, columns: [], store: RowStore.empty([]),
        formatLabel: 'SQLite', truncated: false, originalRowCount: 0,
      });
    }

    const columns = srcCols;
    const colCount = columns.length;
    let truncated = false;
    let list = srcRows;
    if (list.length > TIMELINE_MAX_ROWS) {
      list = list.slice(0, TIMELINE_MAX_ROWS);
      truncated = true;
    }

    // Phase 8: stream rows directly into a `RowStoreBuilder` (see
    // `fromEvtx` above for rationale). Each cell is normalised to a
    // string here because `visit_count` and other numeric columns
    // come through as numbers from the SQLite parser.
    const builder = new RowStoreBuilder(columns);
    for (let i = 0; i < list.length; i++) {
      const src = list[i] || [];
      const row = new Array(colCount);
      for (let j = 0; j < colCount; j++) {
        row[j] = src[j] != null ? String(src[j]) : '';
      }
      builder.addRow(row);
    }

    const browserLabel = db.browserType === 'firefox' ? 'Firefox' : 'Chrome';
    // Per-event: time is col 0 ("Timestamp"), stack-by col 1 ("Type").
    // Legacy:    time is col 3 ("Last Visited"), no default stack.
    const timeColIdx = useEvents ? 0 : 3;
    const stackColIdx = useEvents ? 1 : null;
    return new TimelineView({
      file, columns, store: builder.finalize(),
      formatLabel: 'SQLite \u2013 ' + browserLabel + ' History',
      truncated,
      originalRowCount: srcRows.length,
      defaultTimeColIdx: timeColIdx,
      defaultStackColIdx: stackColIdx,
    });
  },

  // ── PCAP / PCAPNG capture ───────────────────────────────────────────────
  //
  // Sync main-thread fallback used when the worker path is unavailable
  // (Firefox at `file://` denies `new Worker(blob:)` and `WorkerManager`
  // falls through to this factory). Mirrors the worker path in
  // `timeline.worker.js::_parsePcap` step-for-step:
  //
  //   • magic sniff via `PcapRenderer._parse` (handles libpcap LE/BE/ms/ns
  //     + PCAPNG dispatch internally; returns the same `_emptyResult`-
  //     shaped object on bad / truncated magic)
  //   • truncate `pkts` to `TIMELINE_MAX_ROWS` if needed
  //   • stream rows via the shared `_streamPacketRows(pkts, addRow)` helper
  //     into a `RowStoreBuilder`
  //   • run `_analyzePcapInfo` on the SAME thread (sidebar IOCs in the
  //     hybrid model live on a side-channel `_pcapFindings` so the
  //     Timeline view can drive ⚡ Summarize without polluting
  //     `app.findings`)
  //
  // A zero-row return triggers the legacy escape-hatch fallback in
  // `_loadFileInTimeline` (re-route to `PcapRenderer.render` card view).
  fromPcap(file, buffer) {
    const bytes = new Uint8Array(buffer);
    const parsed = PcapRenderer._parse(bytes);

    // Run the main-thread analyser on the parsed result so the synthetic
    // findings populate `_copyAnalysisPcap`'s expected shape. This is
    // the ONLY path on which `pushIOC` / `IOC.*` / `escalateRisk` run
    // for pcap — the worker path stages `pcapInfo` for an equivalent
    // call inside `_buildTimelineViewFromWorker`.
    let pcapFindings = null;
    try {
      pcapFindings = PcapRenderer._analyzePcapInfo(parsed, file && file.name);
    } catch (e) {
      console.warn('[timeline] PCAP analyzePcapInfo failed:', e);
    }

    const columns = [...PcapRenderer.TIMELINE_COLUMNS];
    const allPkts = parsed.pkts || [];
    let truncated = parsed.truncated || false;
    let pkts = allPkts;
    if (allPkts.length > TIMELINE_MAX_ROWS) {
      pkts = allPkts.slice(0, TIMELINE_MAX_ROWS);
      truncated = true;
    }

    // Stream rows directly into a `RowStoreBuilder` — same shape as
    // `fromEvtx` / `fromSqlite`. The builder allocates packed
    // typed-array chunks every `_ROWSTORE_CHUNK_ROWS_TARGET` rows so
    // the per-row `string[]` cells GC before the next batch.
    const builder = new RowStoreBuilder(columns);
    PcapRenderer._streamPacketRows(pkts, (row) => builder.addRow(row), null);

    // `pcapInfo` for the in-view detections panel + ⚡ Summarize. We
    // strip `pkts` because the per-packet records are now live inside
    // the RowStore — keeping them around as an array would double the
    // memory footprint of a 1 M-packet capture.
    const pcapInfo = { ...parsed };
    delete pcapInfo.pkts;

    return new TimelineView({
      file, columns, store: builder.finalize(),
      // Stable tag — variant info ("libpcap", "PCAPNG 1.0 (LE)") lives
      // on `pcapInfo.formatLabel` for the ⚡ Summarize markdown header.
      // Matches EVTX's stable `"EVTX"` formatLabel so the snapshot
      // matrix's `formatTag` assertion is stable across libpcap /
      // PCAPNG / nanosecond-pcap variants.
      formatLabel: 'PCAP',
      truncated,
      originalRowCount: allPkts.length,
      defaultTimeColIdx: PcapRenderer.TIMELINE_TIME_COL_IDX,
      defaultStackColIdx: PcapRenderer.TIMELINE_STACK_COL_IDX,
      pcapInfo,
      pcapFindings,
    });
  },

});
