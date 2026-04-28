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
  async fromCsvAsync(file, buffer, explicitDelim) {
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
    let delim = explicitDelim;
    if (!delim) {
      try { delim = r._delim(norm); } catch (_) { delim = ','; }
    }
    // ── Header extraction ──────────────────────────────────────────────
    // Use the shared RFC-4180 state-machine parser so a header that
    // includes a multi-line quoted cell parses correctly (the legacy
    // `norm.indexOf('\n')` slice would chop the header in half on the
    // first embedded newline). Same parser drives the body loop below.
    const headerState = CsvRenderer.initParserState();
    const headerResult = CsvRenderer.parseChunk(norm, 0, headerState, delim, {
      baseOffset: 0, maxRows: 1, flush: false,
    });
    let columns = [];
    let bodyStartIdx;
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

});
