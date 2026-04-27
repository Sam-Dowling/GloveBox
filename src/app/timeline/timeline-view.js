'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view.js — TimelineView class core.
//
// Split out of the legacy app-timeline.js monolith. Owns all
// DOM + state for a single loaded file: virtual scroll grid, scrubber,
// stacked-bar histogram, top-values cards, query chips, pivot table,
// extraction dialog, exports.
//
// The static factories `fromCsvAsync` / `fromEvtx` / `fromSqlite` stay
// inside this file (they construct via `new TimelineView({...})` and
// reach into the same column-/row-shape contract).
//
// Two prototype mixins extend this class AFTER its declaration:
//   - timeline-detections.js  → _renderDetections, _renderEntities,
//                                _collectEntities, _pivotOnEntity,
//                                _pivotAnyContainsToggle (EVTX-only
//                                in-view sections; consume the
//                                EvtxDetector.analyzeForSecurity result;
//                                no global findings mutation).
//   - timeline-drawer.js      → _jsonCollectLeafPaths, JSON-leaf
//                                extracted-column helpers, regex
//                                extract dedup + persistence.
//
// Analysis-bypass guard: this file (and its mixins) does NOT import or
// call pushIOC / EncodedContentDetector / sidebar mutators. The
// Timeline route is intentionally analyser-free (see
// timeline-router.js header).
// ════════════════════════════════════════════════════════════════════════════

// TimelineView — owns all DOM + state for a single loaded file.
// ════════════════════════════════════════════════════════════════════════════
class TimelineView {

  // ── Factories ────────────────────────────────────────────────────────────

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
  static async fromCsvAsync(file, buffer, explicitDelim) {
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
        file, columns: [], rows: [],
        formatLabel: 'CSV', truncated: false, originalRowCount: 0,
      });
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
    // Trim and de-noise column names — whitespace / stray quotes from
    // hand-edited exports throw off `_tlAutoDetectTimestampCol` otherwise.
    columns = columns.map(c => String(c == null ? '' : c).trim());

    // ── Chunked parse ─────────────────────────────────────────────────
    // Parse CHUNK_ROWS lines at a time, yielding to the event loop
    // between chunks via MessageChannel (zero-delay, matches the
    // existing _parseStreaming pattern in CsvRenderer).
    const CHUNK_ROWS = 50000;
    const len = norm.length;
    let offset = firstNl === -1 ? len : firstNl + 1;
    const rows = [];
    const colLen = columns.length;

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
        const chunkEnd = Math.min(rows.length + CHUNK_ROWS, TIMELINE_MAX_ROWS);
        while (offset < len && rows.length < chunkEnd) {
          let lineEnd = norm.indexOf('\n', offset);
          if (lineEnd === -1) lineEnd = len;
          if (lineEnd > offset) {
            const line = norm.substring(offset, lineEnd);
            const cells = line.indexOf('"') === -1
              ? line.split(delim)
              : r._splitQuoted(line, delim);
            // Inline row-width normalisation (avoids a second full-array pass).
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
        // Yield to the event loop so the browser can paint / stay responsive.
        if (offset < len && rows.length < TIMELINE_MAX_ROWS) {
          await yieldTick();
        }
      }
    } catch (e) {
      // Parser blew up on a pathological chunk. Fall back to a very
      // forgiving line-by-line split — loses quoted-newline handling,
      // but keeps the analyst looking at real data instead of hex.
      console.warn('[timeline] CSV parser failed, using fallback split:', e);
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
    return new TimelineView({
      file, columns, rows,
      formatLabel: delim === '\t' ? 'TSV' : 'CSV',
      truncated, originalRowCount,
    });
  }

  // Parse an EVTX buffer resiliently. `EvtxRenderer._parseAsync` already
  // skips truncated chunks and malformed BinXml templates, but a hard
  // failure on the file header would otherwise bubble up and abort the
  // load. We attach the parsed events + an `EvtxRenderer.analyzeForSecurity`
  // result to the view so Detections / Entities sections can read them
  // without a second parse pass.
  //
  // Uses the async parser with cooperative yielding so the browser stays
  // responsive during large EVTX files (10–30+ seconds of parse time).
  static async fromEvtx(file, buffer) {
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
    const rows = new Array(list.length);
    for (let i = 0; i < list.length; i++) {
      const ev = list[i] || {};
      rows[i] = [
        ev.timestamp ? ev.timestamp.replace('T', ' ').replace('Z', '') : '',
        ev.eventId || '', ev.level || '', ev.provider || '',
        ev.channel || '', ev.computer || '', ev.eventData || '',
      ];
    }
    return new TimelineView({
      file, columns, rows,
      formatLabel: 'EVTX', truncated, originalRowCount: events.length,
      defaultTimeColIdx: 0, defaultStackColIdx: 1,
      evtxEvents: events, evtxFindings: securityFindings,
    });
  }

  // ── SQLite browser history ──────────────────────────────────────────────
  //
  // Reuses SqliteRenderer._parseDb() to extract the browser-history rows,
  // then projects them into the same { columns, rows } shape the
  // TimelineView constructor expects.  Generic (non-browser) SQLite
  // databases return a zero-row view so the fallback escape hatch in
  // _loadFileInTimeline re-routes them to the regular SqliteRenderer
  // tabbed-grid pipeline.

  static fromSqlite(file, buffer) {
    const r = new SqliteRenderer();
    let db;
    try {
      db = r._parseDb(new Uint8Array(buffer));
    } catch (e) {
      console.warn('[timeline] SQLite parse failed:', e);
      // Return zero-row view — triggers fallback to regular analyser.
      return new TimelineView({
        file, columns: [], rows: [],
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
        file, columns: [], rows: [],
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

    // Ensure every cell is a string (visit_count comes through as a number).
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
    // Per-event: time is col 0 ("Timestamp"), stack-by col 1 ("Type").
    // Legacy:    time is col 3 ("Last Visited"), no default stack.
    const timeColIdx = useEvents ? 0 : 3;
    const stackColIdx = useEvents ? 1 : null;
    return new TimelineView({
      file, columns, rows,
      formatLabel: 'SQLite \u2013 ' + browserLabel + ' History',
      truncated,
      originalRowCount: srcRows.length,
      defaultTimeColIdx: timeColIdx,
      defaultStackColIdx: stackColIdx,
    });
  }


  // ── Construction ─────────────────────────────────────────────────────────
  constructor(opts) {
    this.file = opts.file;
    this._baseColumns = opts.columns || [];
    this.rows = opts.rows || [];
    this.formatLabel = opts.formatLabel || '';
    this.truncated = !!opts.truncated;
    this.originalRowCount = opts.originalRowCount || this.rows.length;
    this._fileKey = _tlFileKey(this.file);

    // EVTX-only side-channel — the parsed event array (same indices as
    // `this.rows`) and the Sigma-style `analyzeForSecurity` findings
    // object. Used by the Detections + Entities sections below to render
    // Sigma-rule hits, click-to-filter on Event ID, and entity pivots
    // without re-parsing the file. Both are `null` for CSV / TSV.
    this._evtxEvents = Array.isArray(opts.evtxEvents) ? opts.evtxEvents : null;
    this._evtxFindings = opts.evtxFindings && typeof opts.evtxFindings === 'object'
      ? opts.evtxFindings : null;

    // Extracted / regex virtual columns — each entry:

    //   { name, kind: 'json'|'regex'|'auto', sourceCol, path?, pattern?, flags?,
    //     group?, values: string[] }  — `values[rowIdx]` is the extracted value
    //   (pre-materialised once).
    this._extractedCols = [];

    // Per-row parsed-JSON cache (only populated as rows are inspected).
    this._jsonCache = new Map();

    // Time parsing
    this._timeCol = Number.isInteger(opts.defaultTimeColIdx)
      ? opts.defaultTimeColIdx
      : _tlAutoDetectTimestampCol(this._baseColumns, this.rows);
    this._stackCol = Number.isInteger(opts.defaultStackColIdx)
      ? opts.defaultStackColIdx
      : _tlAutoDetectStackCol(this._baseColumns, this.rows, this._timeCol);
    this._stackColorMap = null;
    this._buildStableStackColorMap();
    this._bucketId = TimelineView._loadBucketPref();
    this._timeMs = new Float64Array(this.rows.length);
    // `_timeIsNumeric` — switches the axis / bucket / tick formatters from
    // wall-clock ms into a plain numeric domain. Set by `_parseAllTimestamps`
    // based on the column's parse-ability. When true, `_timeMs[i]` holds the
    // raw numeric value (NOT milliseconds since epoch).
    this._timeIsNumeric = false;
    this._parseAllTimestamps();
    this._dataRange = this._computeDataRange();
    this._window = null;

    // Suspicious marks — `[{ colName, val }]`. Persisted by column NAME
    // so an extracted column that rebuilds under a different index on
    // reload still re-hydrates its 🚩 marks. Resolved to a live colIdx
    // at filter-time via `_susMarksResolved()`. Sus marks are a PURE
    // tint — they never filter the grid (filtering is the query's job).
    this._susMarks = TimelineView._loadSusMarksFor(this._fileKey);

    // Query language state — the analyst-authored filter DSL that lives
    // in the `.tl-query` editor above the chips strip. The query bar is
    // now the SINGLE SOURCE OF TRUTH for every filter on the grid.
    // Parsed incrementally by `TimelineQueryEditor.onChange` →
    // `_tlTokenize` → `_tlParseQuery` → `_tlCompileAst`, then applied as
    // the sole row predicate in `_recomputeFilter` / `_indexIgnoringColumn`.
    // `_queryPred` is the hot predicate closure `(dataIdx) => bool`
    // (null = no filter). Every click-pivot (right-click Include /
    // Exclude / Only, column-card click, column-menu Apply, pivot
    // double-click, detection drill-down, legend click) MUTATES THE
    // QUERY STRING via the AST-edit helpers below (`_queryToggleClause`,
    // `_queryReplaceEqForCol`, …) rather than pushing onto a separate
    // chip list.

    this._queryStr = TimelineView._loadQueryFor(this._fileKey) || '';
    this._queryAst = null;
    this._queryPred = null;
    this._queryError = null;
    this._queryEditor = null;

    // Filter cache — rows that satisfy the non-sus chip predicate + window.
    this._filteredIdx = null;
    // Same set, but computed IGNORING the current time window — cached so
    // that time-window changes (scrubber / chart rubber-band / chart drill)
    // can re-derive `_filteredIdx` in O(n) without re-running chip predicates.
    // Invalidated whenever the query AST, `_timeCol`, or the extracted column
    // set changes.
    this._chipFilteredIdx = null;
    // Sus bitmap over rows[] (1 if row matches ≥ 1 sus chip, 0 otherwise).
    // Built eagerly by `_rebuildSusBitmap()` so the query compiler can
    // reference it for `is:sus`.
    this._susBitmap = null;
    this._susAny = false;      // true if ≥ 1 sus chip exists
    // Intersection of filteredIdx and susBitmap (rows visible AND sus).
    this._susFilteredIdx = null;
    // Detection bitmap (EVTX-only) — 1 if the row's Event ID appears in at
    // least one Sigma-style detection from `_evtxFindings.externalRefs`.
    // Built once at construction via `_rebuildDetectionBitmap()` and never
    // invalidated (detections are static for a given file). `null` for
    // CSV/TSV (no findings) — `is:detection` simply matches nothing.
    this._detectionBitmap = null;
    // Red-line cursor on the histogram / scrubber / sus chart — which row
    // is "currently focused" by the analyst (set on grid-row click). null =
    // no cursor. Cleared on Esc and Reset. Purely decorative: does not
    // affect filtering, bucketing, or the filteredIdx pipeline.
    this._cursorDataIdx = null;
    // True while the analyst is click+dragging the cursor handle on the
    // chart histogram.  While set, `_updateCursorFromGridScroll` is
    // suppressed so the scroll-driven anchor doesn't fight the drag.
    this._cursorDragging = false;
    // Live-drag state — when true, `_scheduleRender` runs only lightweight
    // tasks (scrubber + chart) and skips grid / columns / sus. Committed on
    // pointer-up via `_commitWindowDrag()`.
    this._windowDragging = false;

    // Column stats — invalidated on any filter change.
    this._colStats = null;
    this._colStatsGen = 0;   // generation counter for async cancellation

    // Grid sort + rowsConcat caches — invalidated by _invalidateGridCache()
    // whenever _timeMs content changes. Avoids the O(n log n) re-sort and
    // O(n) rowsConcat rebuild on filter-clear for 1M-row datasets.
    this._sortedFullIdx = null;
    this._cachedRowsConcat = null;
    this._cachedRowsConcatExtLen = -1;

    // Grid
    this._grid = null;

    // Splitter
    this._gridH = TimelineView._loadGridH();
    this._chartH = TimelineView._loadChartH();

    // Collapsible section state (persisted).
    this._sections = TimelineView._loadSections();

    // Top-values card zoom (S / M / L) + per-card width overrides.
    this._cardSize = TIMELINE_CARD_SIZE_DEFAULT;
    this._cardWidths = TimelineView._loadCardWidthsFor(this._fileKey);
    this._cardOrder = TimelineView._loadCardOrderFor(this._fileKey);
    this._pinnedCols = TimelineView._loadPinnedColsFor(this._fileKey);
    // Entities-section parity with Top values: pinned types + drag-reorder
    // saved per-file under their own keys so they don't collide with
    // `pinnedCols` / `cardOrder` (which key on column names — entity cards
    // key on IOC type identifiers like `IOC.USERNAME`).
    this._pinnedEntities = TimelineView._loadEntPinnedFor(this._fileKey);
    this._entOrder = TimelineView._loadEntOrderFor(this._fileKey);
    // Detections "Group by ATT&CK tactic" toggle — global, not per-file
    // (analysts who turn it on once tend to want it on every file).
    this._detectionsGroup = TimelineView._loadDetectionsGroup();
    // Detections severity-filter — `null` means "show all tiers"; clicking
    // a summary pill toggles this between `null` and one of
    // 'critical' | 'high' | 'medium' | 'low' | 'info'. Session-only
    // (no localStorage) — this is a momentary lens, not a saved preference.
    this._detectionsSevFilter = null;
    this._pendingCtrlSelect = null; // { colIdx, values: Set, rows: [] }


    // Load any persisted regex extractors for this file.
    const persistedRegex = TimelineView._loadRegexExtractsFor(this._fileKey);
    for (const p of persistedRegex) this._addRegexExtractNoRender(p);

    // Pivot last-used spec.
    this._pivotSpec = TimelineView._loadPivotSpec();

    // DOM
    this._root = null;
    this._els = {};
    this._destroyed = false;
    this._resizeObs = null;
    this._rafPending = false;
    this._colStatsRaf = 0;
    this._pendingTasks = new Set();
    this._openPopover = null;
    this._openDialog = null;

    this._buildDOM();
    this._wireEvents();
    this._rebuildSusBitmap();
    this._rebuildDetectionBitmap();
    this._recomputeFilter();
    this._scheduleRender(['chart', 'scrubber', 'chips', 'grid', 'columns', 'detections', 'entities', 'pivot', 'sections']);
    // Auto-extract nudge — run one tick later so the initial render has
    // painted and the user isn't staring at a nudge before the grid.
    // Persisted suppression (`loupe_timeline_autoextract_nudged_hard`) is
    // checked inside `_renderAutoExtractNudge`.
    this._autoExtractNudgeDismissed = false;
    setTimeout(() => this._renderAutoExtractNudge(), 60);
  }


  root() { return this._root; }

  destroy() {
    if (this._destroyed) return;
    this._destroyed = true;
    cancelAnimationFrame(this._colStatsRaf);
    this._colStatsRaf = 0;
    if (this._grid && typeof this._grid.destroy === 'function') {
      try { this._grid.destroy(); } catch (_) { /* noop */ }
    }
    if (this._resizeObs) { try { this._resizeObs.disconnect(); } catch (_) { /* noop */ } }
    if (this._queryEditor && typeof this._queryEditor.destroy === 'function') {
      try { this._queryEditor.destroy(); } catch (_) { /* noop */ }
    }
    this._queryEditor = null;
    this._closePopover();
    this._closeDialog();

    // Tear down the document / window listeners wired in `_wireEvents`.
    // Missing teardown would leak across tab switches and route stale
    // popover-close calls at a destroyed view.
    if (this._onDocClick) document.removeEventListener('mousedown', this._onDocClick, true);
    if (this._onDocKey) document.removeEventListener('keydown', this._onDocKey, true);
    if (this._onDocScroll) window.removeEventListener('scroll', this._onDocScroll, true);
    if (this._onDocKeyUp) document.removeEventListener('keyup', this._onDocKeyUp, true);
    this._onDocClick = this._onDocKey = this._onDocScroll = this._onDocKeyUp = null;

    // Reset drag-state flags + strip any document-level cursor classes the
    // active drag installed on <body>. If destroy interrupts a live drag,
    // the pointerup/onUp handler is on a `handle` element that's GC'd with
    // `_root` below — it never fires, leaving `_cursorDragging` /
    // `_windowDragging` true on the dead view (cosmetic) AND a stuck
    // `ns-resize` cursor / `tl-chart-resizing` class on <body> that
    // outlives the timeline pane (visible to the user).
    this._cursorDragging = false;
    this._windowDragging = false;
    if (typeof document !== 'undefined' && document.body) {
      document.body.classList.remove(
        'tl-chart-resizing',
        'tl-col-resizing',
        'tl-col-dragging',
        'tl-splitter-dragging',
      );
    }

    this._grid = null;
    this._resizeObs = null;
    this._els = {};
    if (this._root && this._root.parentNode) this._root.parentNode.removeChild(this._root);
    this._root = null;

    // ── Release heavy data arrays ────────────────────────────────────────
    // Without explicit nulling, any transient reference to this view
    // (pending RAF callback, closure in a setTimeout, back-reference from
    // the query editor) keeps the entire parsed dataset alive until that
    // reference is collected. For an 80 MB CSV with 500 k rows this is
    // easily 300+ MB of JS heap — repeated load/clear cycles OOM the tab.
    this.rows = null;
    this._baseColumns = null;
    this._extractedCols = null;
    this._colStats = null;
    this._sortedFullIdx = null;
    this._cachedRowsConcat = null;
    this._filteredIdx = null;
    this._susBitmap = null;
    this._detectionBitmap = null;
    this.file = null;
    this._evtxEvents = null;
    this._evtxFindings = null;
    this._app = null;
  }

  // ── Columns accessor (base + extracted) ─────────────────────────────────
  get columns() {
    if (!this._extractedCols || !this._extractedCols.length) return this._baseColumns;
    const out = this._baseColumns.slice();
    for (const e of this._extractedCols) out.push(e.name);
    return out;
  }

  _isExtractedCol(colIdx) { return colIdx >= this._baseColumns.length; }
  _extractedColFor(colIdx) { return this._extractedCols[colIdx - this._baseColumns.length] || null; }

  // Cell access — unified base + extracted lookup. Returns a string or ''.
  _cellAt(dataIdx, colIdx) {
    if (colIdx < this._baseColumns.length) {
      const r = this.rows[dataIdx];
      if (!r) return '';
      const v = r[colIdx];
      return v == null ? '' : String(v);
    }
    const e = this._extractedColFor(colIdx);
    if (!e) return '';
    const v = e.values[dataIdx];
    return v == null ? '' : String(v);
  }

  // Does `colIdx` look like a timestamp / numeric-axis column? Drives the
  // "Use as Timestamp" entry in the column ▾ menu. Samples via `_cellAt`
  // so extracted (virtual) columns work alongside base columns. Mirrors
  // the thresholds used by `_tlAutoDetectTimestampCol`: ≥ 50 % parse as
  // real timestamps OR ≥ 80 % parse as bare numbers (numeric-axis).
  _columnLooksLikeTimestamp(colIdx) {
    if (!this.rows || !this.rows.length) return false;
    const N = Math.min(this.rows.length, 200);
    let seen = 0, ok = 0, numOk = 0;
    for (let i = 0; i < N; i++) {
      const v = this._cellAt(i, colIdx);
      if (v === '' || v == null) continue;
      seen++;
      if (Number.isFinite(_tlParseTimestamp(v))) ok++;
      const s = String(v).trim();
      if (/^-?\d+(?:\.\d+)?$/.test(s) && Number.isFinite(+s)) numOk++;
    }
    if (!seen) return false;
    return (ok / seen) >= 0.5 || (numOk / seen) >= 0.8;
  }

  // ── Persistence helpers ─────────────────────────────────────────────────
  static _loadBucketPref() {
    const v = safeStorage.get(TIMELINE_KEYS.BUCKET);
    if (v && TIMELINE_BUCKET_OPTIONS.some(o => o.id === v)) return v;
    return 'auto';
  }
  static _saveBucketPref(id) {
    safeStorage.set(TIMELINE_KEYS.BUCKET, id);
  }
  static _loadGridH() {
    const v = parseInt(safeStorage.get(TIMELINE_KEYS.GRID_H), 10);
    if (Number.isFinite(v) && v >= TIMELINE_GRID_MIN_H) return v;
    return TIMELINE_GRID_DEFAULT_H;
  }
  static _saveGridH(h) {
    safeStorage.set(TIMELINE_KEYS.GRID_H, String(h));
  }
  static _loadChartH() {
    const v = parseInt(safeStorage.get(TIMELINE_KEYS.CHART_H), 10);
    if (Number.isFinite(v) && v >= TIMELINE_CHART_MIN_H && v <= TIMELINE_CHART_MAX_H) return v;
    return TIMELINE_CHART_DEFAULT_H;
  }
  static _saveChartH(h) {
    safeStorage.set(TIMELINE_KEYS.CHART_H, String(h));
  }
  static _loadSections() {
    const obj = safeStorage.getJSON(TIMELINE_KEYS.SECTIONS, {});
    return obj && typeof obj === 'object' ? obj : {};
  }
  static _saveSections(obj) {
    safeStorage.setJSON(TIMELINE_KEYS.SECTIONS, obj);
  }
  static _loadCardWidthsFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.CARD_WIDTHS, null);
    return (all && all[fileKey]) || {};
  }
  static _saveCardWidthsFor(fileKey, widths) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.CARD_WIDTHS, {}) || {};
    all[fileKey] = widths;
    safeStorage.setJSON(TIMELINE_KEYS.CARD_WIDTHS, all);
  }
  static _loadCardOrderFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.CARD_ORDER, null);
    const arr = all && all[fileKey];
    return Array.isArray(arr) ? arr : null;
  }
  static _saveCardOrderFor(fileKey, order) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.CARD_ORDER, {}) || {};
    if (order && order.length) all[fileKey] = order;
    else delete all[fileKey];
    safeStorage.setJSON(TIMELINE_KEYS.CARD_ORDER, all);
  }
  static _loadPinnedColsFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.PINNED_COLS, null);
    const arr = all && all[fileKey];
    return Array.isArray(arr) ? arr : [];
  }
  static _savePinnedColsFor(fileKey, cols) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.PINNED_COLS, {}) || {};
    if (cols && cols.length) all[fileKey] = cols;
    else delete all[fileKey];
    safeStorage.setJSON(TIMELINE_KEYS.PINNED_COLS, all);
  }
  // Entities-section state — mirrors the `_loadPinnedColsFor` /
  // `_loadCardOrderFor` shapes but keys on the IOC-type identifier instead
  // of a column name. Stored under the dedicated ENT_PINNED / ENT_ORDER
  // namespaces so the Top-values column state stays uncoupled.
  static _loadEntPinnedFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.ENT_PINNED, null);
    const arr = all && all[fileKey];
    return Array.isArray(arr) ? arr : [];
  }
  static _saveEntPinnedFor(fileKey, types) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.ENT_PINNED, {}) || {};
    if (types && types.length) all[fileKey] = types;
    else delete all[fileKey];
    safeStorage.setJSON(TIMELINE_KEYS.ENT_PINNED, all);
  }
  static _loadEntOrderFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.ENT_ORDER, null);
    const arr = all && all[fileKey];
    return Array.isArray(arr) ? arr : null;
  }
  static _saveEntOrderFor(fileKey, order) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.ENT_ORDER, {}) || {};
    if (order && order.length) all[fileKey] = order;
    else delete all[fileKey];
    safeStorage.setJSON(TIMELINE_KEYS.ENT_ORDER, all);
  }
  // Global "group Detections by ATT&CK tactic" toggle. Cross-file because
  // analysts who turn it on once tend to want it on for every EVTX they
  // open. Boolean stored as 0/1.
  static _loadDetectionsGroup() {
    const raw = safeStorage.get(TIMELINE_KEYS.DETECTIONS_GROUP);
    return raw === '1';
  }
  static _saveDetectionsGroup(on) {
    safeStorage.set(TIMELINE_KEYS.DETECTIONS_GROUP, on ? '1' : '0');
  }
  static _loadRegexExtractsFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.REGEX_EXTRACTS, null);
    const list = (all && all[fileKey]) || [];
    return Array.isArray(list) ? list : [];
  }
  static _saveRegexExtractsFor(fileKey, list) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.REGEX_EXTRACTS, {}) || {};
    all[fileKey] = list;
    safeStorage.setJSON(TIMELINE_KEYS.REGEX_EXTRACTS, all);
  }
  static _loadPivotSpec() {
    const obj = safeStorage.getJSON(TIMELINE_KEYS.PIVOT, null);
    return obj && typeof obj === 'object' ? obj : null;
  }
  static _savePivotSpec(obj) {
    safeStorage.setJSON(TIMELINE_KEYS.PIVOT, obj);
  }


  // Per-file last-typed query — keyed by `_fileKey` so a large CSV the
  // analyst revisits tomorrow still has their last filter stuck in the
  // editor when they re-open it. Read on construction (see `_queryStr`
  // init), written every time the query is committed (Enter key).
  static _loadQueryFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.QUERY, null);
    return (all && typeof all[fileKey] === 'string') ? all[fileKey] : '';
  }
  static _saveQueryFor(fileKey, q) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.QUERY, {}) || {};
    if (q) all[fileKey] = q;
    else delete all[fileKey];
    safeStorage.setJSON(TIMELINE_KEYS.QUERY, all);
  }


  // Per-file suspicious marks — `[{ colName, val }]`. Persisted by column
  // NAME (not index) so an extracted column that rebuilds under a different
  // index on reload still re-hydrates its 🚩 marks. The view resolves the
  // name back to a live colIdx at filter-time (`_susMarksResolved`).
  static _loadSusMarksFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.SUS_MARKS, null);
    const arr = all && Array.isArray(all[fileKey]) ? all[fileKey] : [];
    // Two shapes are persisted: column-scoped marks carry `colName`, and
    // "Any column" marks carry `any: true` with `colName: null`. Filter
    // on the presence of a usable discriminator + value.
    return arr
      .filter(m => m && m.val != null && (m.any === true || typeof m.colName === 'string'))
      .map(m => (m.any === true
        ? { any: true, colName: null, val: String(m.val) }
        : { colName: String(m.colName), val: String(m.val) }));
  }
  static _saveSusMarksFor(fileKey, marks) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.SUS_MARKS, {}) || {};
    if (marks && marks.length) {
      all[fileKey] = marks.map(m => (m.any === true
        ? { any: true, colName: null, val: String(m.val) }
        : { colName: String(m.colName), val: String(m.val) }));
    } else {
      delete all[fileKey];
    }
    safeStorage.setJSON(TIMELINE_KEYS.SUS_MARKS, all);
  }




  // ── Timestamp parsing ────────────────────────────────────────────────────
  // Also (re-)derives `_timeIsNumeric` from the column's shape. When the
  // chosen column parses better as bare numbers than as wall-clock
  // timestamps (ids, indices, periods, …), `_timeMs[i]` stores the number
  // directly and every downstream bucket / tick / label path consults
  // `_timeIsNumeric` to format as numbers rather than UTC dates.
  _parseAllTimestamps() {
    // The sorted index cache depends on _timeMs — invalidate it whenever
    // timestamps are re-parsed (time-column change, reset, etc.).
    this._invalidateGridCache();
    const col = this._timeCol;
    const rows = this.rows;
    const out = this._timeMs;
    if (col == null) {
      out.fill(NaN);
      this._timeIsNumeric = false;
      return;
    }
    // Decide numeric vs. timestamp for THIS column. Extracted columns are
    // skipped for the numeric path — the sample lives in `rows` which is
    // base-only — they always go through `_tlParseTimestamp`.
    const numeric = (col < this._baseColumns.length)
      && _tlColumnIsNumericAxis(rows, col);
    this._timeIsNumeric = numeric;
    if (numeric) {
      for (let i = 0; i < rows.length; i++) {
        const r = rows[i];
        if (!r) { out[i] = NaN; continue; }
        const c = r[col];
        if (c == null || c === '') { out[i] = NaN; continue; }
        const n = Number(String(c).trim());
        out[i] = Number.isFinite(n) ? n : NaN;
      }
    } else {
      // Detect the dominant timestamp format from a small sample and use
      // the specialised fast-path parser that skips the full regex
      // waterfall. Falls back to `_tlParseTimestamp` for outlier cells.
      // Use `_cellAt` so extracted (virtual) columns resolve correctly —
      // `rows[i][col]` would be undefined for extracted columns since the
      // row arrays only hold `_baseColumns.length` cells.
      const isExtracted = col >= this._baseColumns.length;
      const fmt = isExtracted ? 'generic' : _tlDetectTimestampFormat(rows, col, 30);
      if (fmt === 'generic') {
        for (let i = 0; i < rows.length; i++) {
          const v = isExtracted ? this._cellAt(i, col) : (rows[i] ? rows[i][col] : null);
          out[i] = (v == null || v === '') ? NaN : _tlParseTimestamp(v);
        }
      } else {
        for (let i = 0; i < rows.length; i++) {
          const r = rows[i];
          out[i] = r ? _tlParseTimestampFast(r[col], fmt) : NaN;
        }
      }
    }
  }

  _computeDataRange() {
    const t = this._timeMs;
    let lo = Infinity, hi = -Infinity;
    for (let i = 0; i < t.length; i++) {
      const v = t[i];
      if (Number.isFinite(v)) { if (v < lo) lo = v; if (v > hi) hi = v; }
    }
    if (!Number.isFinite(lo) || !Number.isFinite(hi) || lo === hi) {
      if (Number.isFinite(lo) && Number.isFinite(hi) && lo === hi) {
        return { min: lo - 500, max: hi + 500 };
      }
      return null;
    }
    return { min: lo, max: hi };
  }

  // ── Filter compilation + application ─────────────────────────────────────
  // Splits chips into "filter" chips (eq/ne/contains) which actually filter
  // the grid, and "sus" chips which only tint.
  //
  // This is the full recompute path — runs chip predicates over every row and
  // then clips by the current time window. It also populates
  // `_chipFilteredIdx` (the chip-only result, ignoring the window) which lets
  // `_applyWindowOnly()` re-clip in O(visible) without re-running chip
  // predicates. Callers that only change the time window (scrubber drag,
  // chart rubber-band / drill-down, range-chip remove) should call
  // `_applyWindowOnly()` instead.
  // Apply a (possibly partial) query string — parse + compile + recompute.
  // Safe to call with invalid syntax: the AST is cleared, `_queryError`
  // holds the error for the status line, and the row pipeline reverts to
  // chip-only (so the view isn't left in a broken "nothing matches" state
  // while the analyst is mid-edit).
  _applyQueryString(q) {
    const prev = this._queryStr;
    this._queryStr = q == null ? '' : String(q);
    const raw = this._queryStr;
    if (!raw.trim()) {
      this._queryAst = null;
      this._queryPred = null;
      this._queryError = null;
    } else {
      try {
        const tokens = _tlTokenize(raw);
        const ast = _tlParseQuery(tokens, () => this.columns);
        this._queryAst = ast;
        this._queryPred = _tlCompileAst(ast, this);
        this._queryError = null;
      } catch (e) {
        this._queryAst = null;
        this._queryPred = null;
        this._queryError = e;
      }
    }
    this._recomputeFilter();
    this._scheduleRender(['chart', 'scrubber', 'chips', 'grid', 'columns']);
    // Status line on the editor — only update if the editor is mounted.
    if (this._queryEditor) {
      if (this._queryError) {
        const msg = this._queryError.userMsg || this._queryError.message || 'syntax error';
        const col = Number.isFinite(this._queryError.col) ? this._queryError.col : 0;
        this._queryEditor.setStatus(
          `<span class="tl-query-status-msg">✗ ${_tlEsc(msg)}</span>` +
          `<span class="tl-query-status-col">at col ${col + 1}</span>`,
          'error'
        );
      } else if (!raw.trim()) {
        this._queryEditor.setStatus('', null);
      } else {
        const vis = this._filteredIdx ? this._filteredIdx.length : 0;
        const tot = this.rows.length;
        this._queryEditor.setStatus(
          `<span class="tl-query-status-msg">✓ ${vis.toLocaleString()} / ${tot.toLocaleString()} rows</span>`,
          'ok'
        );
      }
    }
    // If nothing changed, don't thrash localStorage — the editor's
    // `onCommit` path handles explicit save-on-Enter.
    if (raw !== prev) {
      try { TimelineView._saveQueryFor(this._fileKey, raw); } catch (_) { /* noop */ }
    }
  }

  _recomputeFilter() {
    // Query bar is now the single source of truth for row filtering —
    // every click-pivot (right-click Include / Exclude / Only, column
    // card click, column-menu Apply, pivot drill-down, detection drill,
    // legend click) mutates `this._queryStr` via the AST-edit helpers
    // below rather than pushing onto a separate chip list. Sus marks
    // (`this._susMarks`, persisted by colName) are orthogonal — they
    // tint matching rows red but never filter them out.
    const n = this.rows.length;
    const queryPred = this._queryPred;

    if (!queryPred) {
      // Fast path — no active query. Reuse a cached identity index
      // (0, 1, 2, …, n-1) instead of allocating + filling a fresh
      // Uint32Array every time. Saves ~4MB allocation + O(n) fill for
      // 1M rows on every filter-clear.
      if (!this._identityIdx || this._identityIdx.length !== n) {
        const id = new Uint32Array(n);
        for (let i = 0; i < n; i++) id[i] = i;
        this._identityIdx = id;
      }
      this._chipFilteredIdx = this._identityIdx;
    } else {
      const buf = new Uint32Array(n);
      let w = 0;
      for (let i = 0; i < n; i++) {
        if (queryPred(i)) buf[w++] = i;
      }
      this._chipFilteredIdx = buf.subarray(0, w);
    }

    // Sus bitmap is now maintained eagerly by `_rebuildSusBitmap()` (called
    // whenever marks are toggled/cleared) so the query predicate's `is:sus`
    // can reference it. No inline rebuild needed here.

    // Clip by window + materialise sus-visible index.
    this._applyWindowOnly();
  }

  // Resolve the name-keyed `_susMarks` array to live `{ colIdx, val }` pairs
  // against the current column set. Marks whose column has disappeared (e.g.
  // extracted column removed) silently drop out of the resolve — they stay
  // persisted so they rehydrate automatically if the column returns.
  _susMarksResolved() {
    const out = [];
    const cols = this.columns;
    for (const m of this._susMarks) {
      // Normalise to lower-case so the bitmap pass can do a
      // case-insensitive substring check via `.includes()`.
      const lc = String(m.val).toLowerCase();
      // "Any column" marks carry `any: true` + null colName — they fan
      // out over every column in the bitmap pass.
      if (m.any) { out.push({ any: true, val: lc }); continue; }
      const ix = cols.indexOf(m.colName);
      if (ix >= 0) out.push({ colIdx: ix, val: lc });
    }
    return out;
  }

  // (Re)build the `_susBitmap` eagerly from the current `_susMarks`.
  // Called once at construction, and again whenever sus marks are
  // added / removed / cleared. The bitmap must exist BEFORE the query
  // compiler runs so that `is:sus` can reference it.
  _rebuildSusBitmap() {
    const n = this.rows.length;
    const susResolved = this._susMarksResolved();
    this._susAny = susResolved.length > 0;
    if (this._susAny) {
      const bm = new Uint8Array(n);
      const nCols = this.columns.length;
      for (let i = 0; i < n; i++) {
        for (let s = 0; s < susResolved.length; s++) {
          const spec = susResolved[s];
          // Case-insensitive substring match: spec.val is already
          // lower-cased by `_susMarksResolved()`.
          if (spec.any) {
            let hit = false;
            for (let c = 0; c < nCols; c++) {
              if (this._cellAt(i, c).toLowerCase().includes(spec.val)) { hit = true; break; }
            }
            if (hit) { bm[i] = 1; break; }
          } else {
            if (this._cellAt(i, spec.colIdx).toLowerCase().includes(spec.val)) { bm[i] = 1; break; }
          }
        }
      }
      this._susBitmap = bm;
    } else {
      this._susBitmap = null;
    }
  }

  // Build `_detectionBitmap` from EVTX Sigma-style findings. Each row
  // whose Event ID column matches at least one `IOC.PATTERN` detection
  // gets flagged. CSV/TSV files have no findings → bitmap stays `null`
  // and `is:detection` matches nothing. Called once at construction —
  // detection results are static for the lifetime of a view.
  _rebuildDetectionBitmap() {
    if (!this._evtxFindings || !Array.isArray(this._evtxFindings.externalRefs)) {
      this._detectionBitmap = null;
      return;
    }
    const refs = this._evtxFindings.externalRefs;
    const eids = new Set();
    for (let i = 0; i < refs.length; i++) {
      const r = refs[i];
      if (r && r.type === IOC.PATTERN && r.eventId != null) {
        eids.add(String(r.eventId));
      }
    }
    if (!eids.size) { this._detectionBitmap = null; return; }
    const eventIdCol = this._baseColumns.indexOf(EVTX_COLUMNS.EVENT_ID);
    if (eventIdCol < 0) { this._detectionBitmap = null; return; }
    const n = this.rows.length;
    const bm = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      if (eids.has(this._cellAt(i, eventIdCol))) bm[i] = 1;
    }
    this._detectionBitmap = bm;
  }

  // Fast path — re-derives `_filteredIdx` + `_susFilteredIdx` from the cached
  // `_chipFilteredIdx` + `_susBitmap` using only the current `_window`.
  // Call this whenever the only thing that changed is `_window` (scrubber
  // drag, chart rubber-band / drill-down, range-chip remove). Roughly one
  // order of magnitude cheaper than `_recomputeFilter()` on wide datasets
  // because it skips the per-cell chip predicate loop.
  _applyWindowOnly() {
    if (!this._chipFilteredIdx) { this._recomputeFilter(); return; }
    const src = this._chipFilteredIdx;
    const win = this._window;
    const tCol = this._timeCol;
    const times = this._timeMs;
    const bm = this._susBitmap;

    if (!win || tCol == null) {
      this._filteredIdx = src;
    } else {
      const buf = new Uint32Array(src.length);
      let w = 0;
      const lo = win.min, hi = win.max;
      for (let i = 0; i < src.length; i++) {
        const di = src[i];
        const t = times[di];
        if (!Number.isFinite(t) || t < lo || t > hi) continue;
        buf[w++] = di;
      }
      this._filteredIdx = buf.subarray(0, w);
    }

    if (this._susAny && bm) {
      const fi = this._filteredIdx;
      const buf2 = new Uint32Array(fi.length);
      let w2 = 0;
      for (let i = 0; i < fi.length; i++) {
        const di = fi[i];
        if (bm[di]) buf2[w2++] = di;
      }
      this._susFilteredIdx = buf2.subarray(0, w2);
    } else {
      this._susFilteredIdx = null;
    }

    this._colStats = null;
    // Cancel any pending column-stats rAF — without this, the rAF
    // started in `_scheduleRender(['columns'])` would still fire and
    // launch a fresh O(rows × cols) async pass that the generation
    // counter only bails *between* chunks (so one full ~50 K-row chunk
    // is wasted per filter keystroke on million-row datasets). The
    // rAF callback re-arms itself when the next 'columns' render is
    // scheduled, so cancelling here just skips the wasted first chunk.
    if (this._colStatsRaf) {
      cancelAnimationFrame(this._colStatsRaf);
      this._colStatsRaf = 0;
    }
    // Bump the generation counter so any in-flight async column-stats
    // computation detects it has been superseded and bails early.
    this._colStatsGen++;
  }

  /** Synchronous fallback for small datasets (< 50 K rows). */
  _computeColumnStatsSync(idx) {
    const cols = this.columns.length;
    const stats = new Array(cols);
    for (let c = 0; c < cols; c++) stats[c] = new Map();
    const total = idx.length;
    for (let i = 0; i < total; i++) {
      const di = idx[i];
      for (let c = 0; c < cols; c++) {
        const v = this._cellAt(di, c);
        stats[c].set(v, (stats[c].get(v) || 0) + 1);
      }
    }
    const out = new Array(cols);
    for (let c = 0; c < cols; c++) {
      const arr = Array.from(stats[c].entries());
      arr.sort((a, b) => b[1] - a[1]);
      out[c] = { total, distinct: arr.length, values: arr.slice(0, TIMELINE_COL_TOP_N) };
    }
    return out;
  }

  /** Cooperative-yielding column stats — processes `idx` in chunks of
   *  ~50 K rows, yielding between chunks via MessageChannel so the
   *  browser can process events and repaint. For 1 M rows × 7 cols this
   *  turns a 1-3 s main-thread freeze into many short ≈30 ms bursts.
   *
   *  Callers pass a `generation` counter; if `this._colStatsGen` has
   *  moved on by the time a chunk resumes, the computation bails early
   *  (superseded by a newer filter change). Returns `null` on cancel. */
  _computeColumnStatsAsync(idx, generation) {
    const CHUNK = 50000;
    const cols = this.columns.length;
    const stats = new Array(cols);
    for (let c = 0; c < cols; c++) stats[c] = new Map();
    const total = idx.length;
    const self = this;

    const yieldTick = () => new Promise(resolve => {
      if (typeof MessageChannel !== 'undefined') {
        const ch = new MessageChannel();
        ch.port1.onmessage = () => { ch.port1.close(); resolve(); };
        ch.port2.postMessage(null);
      } else {
        setTimeout(resolve, 0);
      }
    });

    return (async () => {
      let i = 0;
      while (i < total) {
        const end = Math.min(i + CHUNK, total);
        for (; i < end; i++) {
          const di = idx[i];
          for (let c = 0; c < cols; c++) {
            const v = self._cellAt(di, c);
            stats[c].set(v, (stats[c].get(v) || 0) + 1);
          }
        }
        // Yield between chunks so the browser stays responsive.
        if (i < total) {
          await yieldTick();
          // Stale check — bail if a newer computation was requested.
          if (self._colStatsGen !== generation || self._destroyed) return null;
        }
      }
      const out = new Array(cols);
      for (let c = 0; c < cols; c++) {
        const arr = Array.from(stats[c].entries());
        arr.sort((a, b) => b[1] - a[1]);
        out[c] = { total, distinct: arr.length, values: arr.slice(0, TIMELINE_COL_TOP_N) };
      }
      return out;
    })();
  }

  // Compute distinct values for a single column — used by column menu.
  // Returns an `Array<[value, count]>` (ordered by descending count). When a
  // `cap` is supplied and the true distinct set exceeds it, the returned
  // array carries two extra properties on the instance: `truncated` (bool)
  // and `totalDistinct` (number). Callers that need to reason about the
  // full-vs-capped distinction (e.g. the column menu's IN/NOT IN picker)
  // inspect those; destructuring callers keep working unchanged.
  _distinctValuesFor(colIdx, fromIdxArr, cap) {
    const m = new Map();
    const arr = fromIdxArr || this._filteredIdx || [];
    for (let i = 0; i < arr.length; i++) {
      const v = this._cellAt(arr[i], colIdx);
      m.set(v, (m.get(v) || 0) + 1);
    }
    const list = Array.from(m.entries()).sort((a, b) => b[1] - a[1]);
    const out = cap ? list.slice(0, cap) : list;
    out.totalDistinct = list.length;
    out.truncated = cap != null && list.length > cap;
    return out;
  }

  // Build an index of rows that would be visible if every filter EXCEPT the
  // chips targeting `excludeColIdx` were applied. Used by the column-menu
  // value list so that once an analyst has narrowed a column to e.g.
  // ["foo","bar"], re-opening the menu still shows the full set of values
  // (with counts that reflect the *other* query predicates + time window)
  // — Excel-parity. Without this, the value list shrinks to the already-
  // selected entries and the user can never broaden the selection without
  // hitting "All" first.
  //
  // Semantics: compiles the query AST with clauses targeting
  // `excludeColIdx` stripped (see `_tlCompileAstExcluding`) so predicates
  // on other columns still apply, then clips by the time window. Sus
  // marks are irrelevant — they only tint, they don't filter.
  _indexIgnoringColumn(excludeColIdx) {
    const n = this.rows.length;
    const buf = new Uint32Array(n);
    let w = 0;
    const qp = this._queryAst ? _tlCompileAstExcluding(this._queryAst, this, excludeColIdx) : null;
    if (!qp) {
      for (let i = 0; i < n; i++) buf[w++] = i;
    } else {
      for (let i = 0; i < n; i++) {
        if (qp(i)) buf[w++] = i;
      }
    }

    // Clip by the current time window, same as _applyWindowOnly.
    const win = this._window;
    const tCol = this._timeCol;
    const times = this._timeMs;
    if (!win || tCol == null) return buf.subarray(0, w);
    const out = new Uint32Array(w);
    let w2 = 0;
    const lo = win.min, hi = win.max;
    for (let i = 0; i < w; i++) {
      const di = buf[i];
      const t = times[di];
      if (!Number.isFinite(t) || t < lo || t > hi) continue;
      out[w2++] = di;
    }
    return out.subarray(0, w2);
  }

  // ── Chart bucket aggregation ─────────────────────────────────────────────
  // In numeric-axis mode, the bucket preset dropdown's time-based options
  // (1 sec / 1 min / 1 hour / …) are meaningless; always pick a nice
  // numeric step via `_tlAutoBucketNumeric` regardless of what the user
  // picked. Time-based presets remain in the dropdown for convenience of
  // switching back — they simply have no effect while numeric.
  _bucketMs(rangeMs) {
    if (this._timeIsNumeric) return _tlAutoBucketNumeric(rangeMs, TIMELINE_BUCKETS_TARGET);
    if (this._bucketId === 'auto') return _tlAutoBucketMs(rangeMs, TIMELINE_BUCKETS_TARGET);
    const opt = TIMELINE_BUCKET_OPTIONS.find(o => o.id === this._bucketId);
    return opt && opt.ms ? opt.ms : _tlAutoBucketMs(rangeMs, TIMELINE_BUCKETS_TARGET);
  }

  _computeChartData(predicateIdx) {
    const dr = this._dataRange;
    if (!dr) return null;
    const idx = predicateIdx || this._filteredIdx;
    if (!idx) return null;
    const viewLo = this._window ? this._window.min : dr.min;
    const viewHi = this._window ? this._window.max : dr.max;
    const rangeMs = Math.max(1, viewHi - viewLo);
    const bucketMs = this._bucketMs(rangeMs);
    const bucketCount = Math.max(1, Math.ceil(rangeMs / bucketMs));
    const times = this._timeMs;
    const stackCol = this._stackCol;

    let stackKeys = null;
    let stackKeyOf = null;
    if (Number.isInteger(stackCol)) {
      const counts = new Map();
      for (let i = 0; i < idx.length; i++) {
        const v = this._cellAt(idx[i], stackCol);
        counts.set(v, (counts.get(v) || 0) + 1);
      }
      // Every unique value gets its own stack key — no "Other" bucket.
      const sorted = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
      stackKeys = sorted.map(e => e[0]);
      const keySet = new Set(stackKeys);
      stackKeyOf = (dataIdx) => {
        const v = this._cellAt(dataIdx, stackCol);
        return keySet.has(v) ? v : stackKeys[stackKeys.length - 1];
      };
    }

    const k = stackKeys ? stackKeys.length : 1;
    // Build a Map for O(1) stack-key → index lookup instead of O(n) indexOf.
    const stackKeyIdx = stackKeys ? new Map(stackKeys.map((sk, si) => [sk, si])) : null;
    const buckets = new Int32Array(bucketCount * k);
    for (let i = 0; i < idx.length; i++) {
      const di = idx[i];
      const t = times[di];
      if (!Number.isFinite(t)) continue;
      const rel = t - viewLo;
      if (rel < 0 || rel > rangeMs) continue;
      let b = Math.floor(rel / bucketMs);
      if (b >= bucketCount) b = bucketCount - 1;
      if (stackKeyOf) {
        const key = stackKeyOf(di);
        const ki = stackKeyIdx.get(key);
        buckets[b * k + (ki !== undefined ? ki : 0)]++;
      } else {
        buckets[b]++;
      }
    }

    let maxTotal = 0;
    for (let b = 0; b < bucketCount; b++) {
      let s = 0;
      for (let j = 0; j < k; j++) s += buckets[b * k + j];
      if (s > maxTotal) maxTotal = s;
    }

    // Parallel bucket of 🚩-flagged rows, so the main histogram can draw
    // a red overlay proportional to the sus count in each bucket. Only
    // populated for the main chart (the sus mini-chart is already all-sus).
    // The sus overlay is gated on `_susAny` in `_renderChartInto`.
    let susBuckets = null;
    if (this._susAny && this._susBitmap && predicateIdx === this._filteredIdx) {
      const bm = this._susBitmap;
      susBuckets = new Int32Array(bucketCount);
      for (let i = 0; i < idx.length; i++) {
        const di = idx[i];
        if (!bm[di]) continue;
        const t = times[di];
        if (!Number.isFinite(t)) continue;
        const rel = t - viewLo;
        if (rel < 0 || rel > rangeMs) continue;
        let b = Math.floor(rel / bucketMs);
        if (b >= bucketCount) b = bucketCount - 1;
        susBuckets[b]++;
      }
    }

    return { viewLo, viewHi, rangeMs, bucketMs, bucketCount, buckets, stackKeys, maxTotal, susBuckets };
  }

  // ── DOM ──────────────────────────────────────────────────────────────────
  _buildDOM() {
    const root = document.createElement('div');
    root.className = 'timeline-view';
    root.style.setProperty('--tl-grid-h', this._gridH + 'px');
    root.style.setProperty('--tl-chart-h', this._chartH + 'px');
    root.style.setProperty('--tl-card-min-w', (TIMELINE_CARD_SIZES[this._cardSize] || TIMELINE_CARD_SIZES.M) + 'px');

    // Scrollable host — the page scrolls vertically so all sections
    // (chart, grid, top-lists, pivot) can be seen by scrolling.
    const host = document.createElement('div');
    host.className = 'tl-host';
    root.appendChild(host);

    // Mouse-wheel continuation: once the user is mid-scroll on the
    // outer host, keep wheels going to it even if the cursor drifts
    // over a nested scroller (GridViewer, top-value cards, etc.).
    // See src/app/timeline/timeline-wheel.js for the rationale.
    if (typeof window !== 'undefined' &&
        typeof window.installTimelineWheelContinuation === 'function') {
        window.installTimelineWheelContinuation(host);
    }

    // Toolbar
    const toolbar = document.createElement('div');
    toolbar.className = 'tl-toolbar';
    toolbar.innerHTML = `
      <span class="tl-row-stat"></span>
      <span class="tl-sep"></span>
      <label class="tl-field">
        <span class="tl-field-label">Timestamp</span>
        <select class="tl-field-select" data-field="time-col"></select>
      </label>
      <label class="tl-field">
        <span class="tl-field-label">Stack by</span>
        <select class="tl-field-select" data-field="stack-col"></select>
      </label>
      <label class="tl-field">
        <span class="tl-field-label">Bucket</span>
        <select class="tl-field-select" data-field="bucket"></select>
      </label>
      <span class="tl-spacer"></span>
      <button class="tl-tb-btn tl-summarize-btn" type="button" data-act="summarize" hidden title="Copy AI-ready Markdown summary of this EVTX timeline (events, detections, entities, relationships, ATT&amp;CK, beacon cadence) to clipboard. Honours the global ⚡ Summarize target setting.">⚡ Summarize</button>
      <button class="tl-tb-btn" type="button" data-act="extract" title="Extract values (URLs, hostnames, Key=Value fields, regex) into new columns">ƒx Extract values</button>
      <button class="tl-reset-btn" type="button" title="Reset view: clear query, range window, column hides, 🚩 Suspicious marks, stack column, pivot, extracted columns, AND every saved Timeline preference (grid/chart heights, bucket, section collapse, card widths, query history, drawer width, grid column widths)">↺ Reset</button>

    `;
    host.appendChild(toolbar);

    // Scrubber
    const scrubber = this._buildSection('scrubber', null, () => {
      const el = document.createElement('div');
      el.className = 'tl-scrubber';
      el.innerHTML = `
        <span class="tl-scrubber-label tl-scrubber-label-left">—</span>
        <div class="tl-scrubber-track">
          <div class="tl-scrubber-window"></div>
          <div class="tl-scrubber-handle tl-scrubber-handle-l"></div>
          <div class="tl-scrubber-handle tl-scrubber-handle-r"></div>
        </div>
        <span class="tl-scrubber-label tl-scrubber-label-right">—</span>
      `;
      return el;
    });
    host.appendChild(scrubber.wrapper);

    // Chart section
    const chart = this._buildSection('chart', '📊 Timeline histogram', () => {
      const el = document.createElement('div');
      el.className = 'tl-chart';
      el.innerHTML = `
        <canvas class="tl-chart-canvas"></canvas>
        <div class="tl-chart-legend"></div>
        <div class="tl-chart-tooltip" hidden></div>
        <div class="tl-chart-empty hidden">No parseable timestamps in the current filter.</div>
        <div class="tl-chart-resize" role="separator" aria-orientation="horizontal" title="Drag to resize histogram"></div>
      `;
      return el;
    }, {
      actions: [
        { label: '⬇ PNG', act: 'chart-png', title: 'Download chart as PNG' },
        { label: '⬇ CSV', act: 'chart-csv', title: 'Download bucket counts as CSV' },
      ],
    });
    host.appendChild(chart.wrapper);

    // Range banner — shown only when a time window is active (scrubber
    // drag / chart rubber-band selection / query `range:`). Promoted out
    // of the chips strip into a prominent full-width banner so the
    // active window is always visible at a glance. Hidden via the
    // `.hidden` class when `this._window == null`; see
    // `_renderRangeBanner` for the render site and `_scheduleRender`
    // (chips task) for the dispatch wiring.
    const rangeBanner = document.createElement('div');
    rangeBanner.className = 'tl-range-banner hidden';
    rangeBanner.innerHTML = `
      <span class="tl-range-banner-icon">🕒</span>
      <span class="tl-range-banner-label">Showing</span>
      <span class="tl-range-banner-text">—</span>
      <button class="tl-range-banner-clear" type="button" title="Clear time window">✕ Clear</button>
    `;
    host.appendChild(rangeBanner);

    // Query bar — mount point for TimelineQueryEditor. The editor itself
    // is constructed in `_wireEvents` (after columns are known) and its
    // `.root` is appended into this container. Kept as a thin shell here
    // so the layout ordering (scrubber → chart → range → query → chips → grid)
    // is visible from `_buildDOM`.
    const queryBar = document.createElement('div');
    queryBar.className = 'tl-query-mount';
    host.appendChild(queryBar);

    // Chips strip. The query bar above is the sole source of truth for
    // row filtering now (see `_applyQueryString`), so this strip only
    // hosts: the "＋ Add Suspicious Indicator" affordance (anchored
    // left, never moves) and zero-or-more 🚩 sus chips flowing to its
    // right (from `_susMarks`, tint-only). The active time window got
    // promoted to the banner above.
    const chips = document.createElement('div');
    chips.className = 'tl-chips';
    host.appendChild(chips);


    // Grid section (collapsible)
    const gridSec = this._buildSection('grid', '📋 Events', () => {
      const el = document.createElement('div');
      el.className = 'tl-grid';
      return el;
    }, {
      actions: [
        { label: '⬇ CSV', act: 'grid-csv', title: 'Download filtered rows as CSV' },
      ],
    });
    host.appendChild(gridSec.wrapper);

    const splitter = document.createElement('div');
    splitter.className = 'tl-splitter';
    splitter.setAttribute('role', 'separator');
    splitter.setAttribute('aria-orientation', 'horizontal');
    splitter.title = 'Drag to resize';
    host.appendChild(splitter);

    // Columns section (collapsible)
    const colsSec = this._buildSection('columns', '🏆 Top values', () => {
      const el = document.createElement('div');
      el.className = 'tl-columns';
      return el;
    }, {
      actions: [
        { label: '⬇ CSV', act: 'columns-csv', title: 'Download all top-values as CSV' },
      ],
    });

    // Detections section — EVTX Sigma-style rule hits, hidden when empty.
    const detectionsSec = this._buildSection('detections', '🎯 Detections', () => {
      const el = document.createElement('div');
      el.className = 'tl-detections';
      el.innerHTML = '<div class="tl-detections-empty">No detections for this file.</div>';
      return el;
    }, {
      extraClass: 'tl-sec-detections',
      actions: [
        { label: '⬇ CSV', act: 'detections-csv', title: 'Download detections as CSV' },
      ],
    });
    detectionsSec.wrapper.classList.add('hidden');

    // Entities section — hostnames / users / URLs / hashes / processes, hidden when empty.
    const entitiesSec = this._buildSection('entities', '🧩 Entities', () => {
      const el = document.createElement('div');
      el.className = 'tl-entities';
      el.innerHTML = '<div class="tl-entities-empty">No entities extracted from this file.</div>';
      return el;
    }, {
      extraClass: 'tl-sec-entities',
      actions: [
        { label: '⬇ CSV', act: 'entities-csv', title: 'Download entities as CSV' },
      ],
    });
    entitiesSec.wrapper.classList.add('hidden');

    // Section order:
    //   CSV / TSV  → Top values → Detections → Entities
    //   EVTX       → Detections → Entities   → Top values
    // EVTX is detected by the presence of the `_evtxFindings` side-channel
    // attached in `TimelineView.fromEvtx`. The Detections + Entities sections
    // are always built but stay hidden on CSV / TSV (their render methods
    // early-return when `_evtxFindings` is null), so the conditional only
    // changes append order — every `this._els` ref below keeps working.
    if (this._evtxFindings) {
      host.appendChild(detectionsSec.wrapper);
      host.appendChild(entitiesSec.wrapper);
      host.appendChild(colsSec.wrapper);
    } else {
      host.appendChild(colsSec.wrapper);
      host.appendChild(detectionsSec.wrapper);
      host.appendChild(entitiesSec.wrapper);
    }


    // Pivot section
    const pivotSec = this._buildSection('pivot', '🧮 Pivot table', () => {
      const el = document.createElement('div');
      el.className = 'tl-pivot';
      el.innerHTML = `
        <div class="tl-pivot-bar">
          <label class="tl-field"><span class="tl-field-label">Rows</span>
            <select class="tl-field-select" data-field="pv-rows"></select>
          </label>
          <label class="tl-field"><span class="tl-field-label">Columns</span>
            <select class="tl-field-select" data-field="pv-cols"></select>
          </label>
          <label class="tl-field"><span class="tl-field-label">Aggregate</span>
            <select class="tl-field-select" data-field="pv-agg"></select>
          </label>
          <label class="tl-field" data-v="pv-agg-col-wrap"><span class="tl-field-label">of</span>
            <select class="tl-field-select" data-field="pv-agg-col"></select>
          </label>
          <button class="tl-tb-btn" data-act="pv-build" type="button">Build</button>
          <button class="tl-tb-btn" data-act="pv-reset" type="button">Reset</button>
        </div>
        <div class="tl-pivot-body">
          <div class="tl-pivot-empty">Pick Rows + Columns + Aggregate → Build.</div>
        </div>
      `;
      return el;
    }, {
      startCollapsed: true,
      actions: [
        { label: '⬇ CSV', act: 'pivot-csv', title: 'Download pivot as CSV' },
      ],
    });
    host.appendChild(pivotSec.wrapper);

    this._root = root;
    this._els = {
      host, toolbar,
      scrubber: scrubber.body,
      scrubberSection: scrubber,
      chart: chart.body, chartSection: chart,
      queryBar,
      chips, gridSection: gridSec, gridWrap: gridSec.body,
      rangeBanner,
      rangeBannerText: rangeBanner.querySelector('.tl-range-banner-text'),
      rangeBannerClear: rangeBanner.querySelector('.tl-range-banner-clear'),
      splitter,
      columnsSection: colsSec, cols: colsSec.body,
      detectionsSection: detectionsSec, detectionsBody: detectionsSec.body,
      entitiesSection: entitiesSec, entitiesBody: entitiesSec.body,
      pivotSection: pivotSec, pivotBody: pivotSec.body,
      rowStat: toolbar.querySelector('.tl-row-stat'),
      timeColSelect: toolbar.querySelector('[data-field="time-col"]'),
      stackColSelect: toolbar.querySelector('[data-field="stack-col"]'),
      bucketSelect: toolbar.querySelector('[data-field="bucket"]'),
      resetBtn: toolbar.querySelector('.tl-reset-btn'),
      extractBtn: toolbar.querySelector('[data-act="extract"]'),
      summarizeBtn: toolbar.querySelector('[data-act="summarize"]'),
      chartCanvas: chart.body.querySelector('.tl-chart-canvas'),
      chartLegend: chart.body.querySelector('.tl-chart-legend'),
      chartEmpty: chart.body.querySelector('.tl-chart-empty'),
      chartTooltip: chart.body.querySelector('.tl-chart-tooltip'),
      chipsEmpty: chips.querySelector('.tl-chips-empty'),
      scrubLabelL: scrubber.body.querySelector('.tl-scrubber-label-left'),
      scrubLabelR: scrubber.body.querySelector('.tl-scrubber-label-right'),
      scrubTrack: scrubber.body.querySelector('.tl-scrubber-track'),
      scrubWindow: scrubber.body.querySelector('.tl-scrubber-window'),
      scrubHandleL: scrubber.body.querySelector('.tl-scrubber-handle-l'),
      scrubHandleR: scrubber.body.querySelector('.tl-scrubber-handle-r'),
      // Pivot refs
      pvRows: pivotSec.body.querySelector('[data-field="pv-rows"]'),
      pvCols: pivotSec.body.querySelector('[data-field="pv-cols"]'),
      pvAgg: pivotSec.body.querySelector('[data-field="pv-agg"]'),
      pvAggCol: pivotSec.body.querySelector('[data-field="pv-agg-col"]'),
      pvAggColWrap: pivotSec.body.querySelector('[data-v="pv-agg-col-wrap"]'),
      pvBuild: pivotSec.body.querySelector('[data-act="pv-build"]'),
      pvReset: pivotSec.body.querySelector('[data-act="pv-reset"]'),
      pvResultBody: pivotSec.body.querySelector('.tl-pivot-body'),
    };
    this._populateToolbarSelects();
    this._populatePivotSelects();
  }

  // Factory for a collapsible, optionally-exportable section wrapper.
  _buildSection(id, title, bodyFactory, opts) {
    opts = opts || {};
    const wrap = document.createElement('section');
    wrap.className = 'tl-section tl-section-' + id + (opts.extraClass ? ' ' + opts.extraClass : '');
    wrap.dataset.secId = id;
    const collapsed = id in this._sections
      ? !!this._sections[id]
      : !!opts.startCollapsed;
    if (collapsed) wrap.classList.add('collapsed');

    let head = null;
    if (title != null) {
      head = document.createElement('header');
      head.className = 'tl-section-head';
      head.innerHTML = `
        <button class="tl-section-chev" type="button" aria-label="Toggle section"><span>▾</span></button>
        <span class="tl-section-title">${_tlEsc(title)}</span>
        <span class="tl-section-actions"></span>
      `;
      const actions = head.querySelector('.tl-section-actions');
      if (opts.actions) {
        for (const a of opts.actions) {
          const b = document.createElement('button');
          b.type = 'button';
          b.className = 'tl-tb-btn tl-section-action';
          b.textContent = a.label;
          if (a.title) b.title = a.title;
          b.dataset.act = a.act;
          actions.appendChild(b);
        }
      }
      wrap.appendChild(head);
      head.querySelector('.tl-section-chev').addEventListener('click', () => this._toggleSection(id));
      // Click title also toggles.
      head.querySelector('.tl-section-title').addEventListener('click', () => this._toggleSection(id));
    }
    const body = bodyFactory();
    body.classList.add('tl-section-body');
    wrap.appendChild(body);
    return { wrapper: wrap, head, body };
  }

  _toggleSection(id) {
    const wrap = this._root.querySelector(`.tl-section-${id}`);
    if (!wrap) return;
    wrap.classList.toggle('collapsed');
    const collapsed = wrap.classList.contains('collapsed');
    this._sections[id] = collapsed;
    TimelineView._saveSections(this._sections);
    // Chart + grid canvases/virtuals may need a repaint on expand.
    // When the columns (Top Values) section is expanded, schedule a
    // 'columns' render so deferred _colStats are computed on demand.
    const tasks = ['chart', 'grid'];
    if (id === 'columns' && !collapsed) tasks.push('columns');
    this._scheduleRender(tasks);
  }


  _populateToolbarSelects() {
    const { timeColSelect, stackColSelect, bucketSelect } = this._els;
    const cols = this.columns;

    const rebuild = (sel, includeNone, current, noneLabel) => {
      sel.innerHTML = '';
      if (includeNone) {
        const opt = document.createElement('option');
        opt.value = '-1'; opt.textContent = noneLabel;
        sel.appendChild(opt);
      }
      for (let i = 0; i < cols.length; i++) {
        const opt = document.createElement('option');
        opt.value = String(i);
        opt.textContent = cols[i] || `(col ${i + 1})`;
        if (i >= this._baseColumns.length) opt.textContent = '⨯ ' + opt.textContent;
        sel.appendChild(opt);
      }
      sel.value = current == null ? '-1' : String(current);
    };
    rebuild(timeColSelect, true, this._timeCol, '— none —');
    rebuild(stackColSelect, true, this._stackCol, '— none —');

    bucketSelect.innerHTML = '';
    for (const o of TIMELINE_BUCKET_OPTIONS) {
      const opt = document.createElement('option');
      opt.value = o.id; opt.textContent = o.label;
      bucketSelect.appendChild(opt);
    }
    bucketSelect.value = this._bucketId;
  }

  _populatePivotSelects() {
    const { pvRows, pvCols, pvAgg, pvAggCol, pvAggColWrap } = this._els;
    const cols = this.columns;
    const fill = (sel) => {
      sel.innerHTML = '';
      const none = document.createElement('option');
      none.value = '-1'; none.textContent = '— choose —';
      sel.appendChild(none);
      for (let i = 0; i < cols.length; i++) {
        const o = document.createElement('option');
        o.value = String(i); o.textContent = cols[i] || `(col ${i + 1})`;
        sel.appendChild(o);
      }
    };
    fill(pvRows);
    fill(pvCols);
    fill(pvAggCol);

    pvAgg.innerHTML = '';
    for (const a of [
      { v: 'count', t: 'Count rows' },
      { v: 'distinct', t: 'Count distinct …' },
      { v: 'sum', t: 'Sum numeric …' },
    ]) {
      const o = document.createElement('option'); o.value = a.v; o.textContent = a.t;
      pvAgg.appendChild(o);
    }

    // Restore saved spec.
    if (this._pivotSpec) {
      if (this._pivotSpec.rows != null) pvRows.value = String(this._pivotSpec.rows);
      if (this._pivotSpec.cols != null) pvCols.value = String(this._pivotSpec.cols);
      if (this._pivotSpec.aggOp) pvAgg.value = this._pivotSpec.aggOp;
      if (this._pivotSpec.aggCol != null) pvAggCol.value = String(this._pivotSpec.aggCol);
    }
    pvAggColWrap.style.display = (pvAgg.value === 'count') ? 'none' : '';
  }

  // ── Event wiring ─────────────────────────────────────────────────────────
  _wireEvents() {
    const els = this._els;

    els.timeColSelect.addEventListener('change', () => {
      const v = parseInt(els.timeColSelect.value, 10);
      this._timeCol = v >= 0 ? v : null;
      this._parseAllTimestamps();
      this._dataRange = this._computeDataRange();
      this._window = null;
      this._recomputeFilter();
      this._scheduleRender(['chart', 'scrubber', 'grid', 'columns', 'chips']);
    });
    els.stackColSelect.addEventListener('change', () => {
      const v = parseInt(els.stackColSelect.value, 10);
      this._stackCol = v >= 0 ? v : null;
      this._buildStableStackColorMap();
      this._scheduleRender(['chart', 'grid', 'columns']);
    });
    els.bucketSelect.addEventListener('change', () => {
      this._bucketId = els.bucketSelect.value;
      TimelineView._saveBucketPref(this._bucketId);
      this._scheduleRender(['chart']);
    });
    els.resetBtn.addEventListener('click', () => this._reset());
    els.extractBtn.addEventListener('click', () => this._openExtractionDialog(null));

    // Summarize button — EVTX-only. Hidden in _buildDOM via the `hidden`
    // attribute; we only un-hide and wire the click when this view actually
    // has EVTX findings attached. CSV/TSV/SQLite timelines never see it.
    if (els.summarizeBtn) {
      if (this._evtxFindings) {
        els.summarizeBtn.hidden = false;
        els.summarizeBtn.addEventListener('click', () => this._summarizeAndCopy());
      }
    }

    // Range-banner Clear button — matches the old range-chip ⊗ semantics:
    // window-only change, no filter re-run, fast path via
    // `_applyWindowOnly()`. Piggybacks chips/banner render on the same
    // scheduleRender call.
    if (els.rangeBannerClear) {
      els.rangeBannerClear.addEventListener('click', () => {
        this._window = null;
        this._applyWindowOnly();
        this._scheduleRender(['scrubber', 'chart', 'chips', 'grid', 'columns']);
      });
    }

    // Construct the query editor now that columns / stats are available
    // (suggestion lookups consult `this.columns` + `_distinctValuesFor`).
    // The editor's DOM `.root` is appended into the `.tl-query-mount`
    // container prepared by `_buildDOM`. onChange → live re-parse + filter;
    // onCommit → persist the string under `loupe_timeline_query` and push
    // onto the history ring.
    this._queryEditor = new TimelineQueryEditor({
      view: this,
      initialValue: this._queryStr || '',
      onChange: (q) => this._applyQueryString(q),
      onCommit: (q) => TimelineView._saveQueryFor(this._fileKey, q),
    });
    els.queryBar.appendChild(this._queryEditor.root);
    if (this._queryStr) {
      // Kick off an initial parse so the editor reflects the restored
      // value (pill highlighting + status line) without waiting for the
      // first keystroke.
      this._applyQueryString(this._queryStr);
    }


    // Chart interaction — pointer-based: short click = drill into bucket,
    // drag = rubber-band a time-window selection. See `_installChartDrag`.
    this._installChartDrag(els.chartCanvas, els.chart, els.chartTooltip, () => this._lastChartData);

    // Scrubber / splitter / chart resize
    this._installScrubberDrag();
    this._installSplitterDrag();
    this._installChartResizeDrag();

    // Section action buttons (export).
    this._root.addEventListener('click', (e) => {
      const btn = e.target.closest('.tl-section-action');
      if (btn) { e.stopPropagation(); this._onSectionAction(btn.dataset.act); return; }
    });

    // Pivot controls
    els.pvAgg.addEventListener('change', () => {
      els.pvAggColWrap.style.display = (els.pvAgg.value === 'count') ? 'none' : '';
    });
    els.pvBuild.addEventListener('click', () => this._buildPivot());
    els.pvReset.addEventListener('click', () => {
      els.pvRows.value = '-1'; els.pvCols.value = '-1'; els.pvAgg.value = 'count';
      els.pvAggCol.value = '-1'; els.pvAggColWrap.style.display = 'none';
      this._pivotSpec = null;
      TimelineView._savePivotSpec({});
      this._els.pvResultBody.innerHTML = '<div class="tl-pivot-empty">Pick Rows + Columns + Aggregate → Build.</div>';
    });

    // ResizeObserver — scrubber/chart layout + grid height recomputes.
    this._resizeObs = new ResizeObserver(() => {
      this._scheduleRender(['chart']);
    });
    this._resizeObs.observe(els.chart);

    // Close any popover on ESC or outside click. Header cells are exempt
    // so the click handler (which fires after mousedown) can apply toggle
    // logic — close if the same column's menu is already open, otherwise
    // close-then-reopen for a different column.
    this._onDocClick = (e) => {
      if (!this._openPopover) return;
      if (this._openPopover.contains(e.target)) return;
      if (e.target.closest && e.target.closest('.grid-header-cell')) return;
      this._closePopover();
    };
    // Double-tap Esc anywhere on the Timeline page clears the current
    // query. Single Esc keeps the existing precedence: dialog → popover →
    // event cursor. Each consumed press resets the double-tap window so
    // an Esc that closes a popover never counts as the first half of a
    // clear-query gesture. Window matches the OS double-click feel.
    this._lastEscAt = 0;
    this._DBL_ESC_MS = 500;
    this._onDocKey = (e) => {
      if (e.key !== 'Escape') return;
      if (this._openDialog) { this._closeDialog(); e.stopPropagation(); this._lastEscAt = 0; return; }
      if (this._openPopover) { this._closePopover(); e.stopPropagation(); this._lastEscAt = 0; return; }
      // Nothing open → clear the "you are here" cursor if it's active.
      if (this._cursorDataIdx != null) { this._setCursorDataIdx(null); e.stopPropagation(); this._lastEscAt = 0; return; }
      // Nothing else consumed Esc — double-tap clears the query. The
      // single-Esc-clears-when-textarea-focused behaviour lives in
      // TimelineQueryEditor and is unaffected by this branch (its
      // keydown handler runs on the textarea, not capture-phase doc).
      const now = Date.now();
      const within = this._lastEscAt && (now - this._lastEscAt) <= this._DBL_ESC_MS;
      if (within && this._queryStr) {
        e.preventDefault();
        e.stopPropagation();
        if (this._queryEditor) this._queryEditor.setValue('');
        this._applyQueryString('');
        if (this._app && typeof this._app._toast === 'function') {
          this._app._toast('Filter cleared', 'info');
        }
        this._lastEscAt = 0;
        return;
      }
      // First Esc with nothing else to do — arm the double-tap window
      // and (if there's actually a query to clear) toast a hint so the
      // gesture is discoverable.
      this._lastEscAt = now;
      if (this._queryStr && this._app && typeof this._app._toast === 'function') {
        this._app._toast('Press Esc again to clear filter', 'info');
      }
    };
    // Scrolling the main page (viewer, window, or any nested scroller)
    // while a row / column popover is open would leave it floating over
    // moved content, since every menu is `position: fixed` and anchored to
    // the click coordinates. Dismiss on any scroll, capture-phase so we
    // also catch scrolls inside the timeline's own sub-scrollers. The
    // grid-viewer drawer's JSON-tree menu already does the same.
    this._onDocScroll = (e) => {
      if (!this._openPopover) return;
      // Don't dismiss when the scroll originates inside the popover
      // itself — Top-Values / header-menu lists are internally
      // scrollable, and bubbling their scroll up to this capture-phase
      // listener would close the popover on the first wheel tick.
      const t = e.target;
      const node = t && t.nodeType === 1 ? t : (t && t.parentNode) || null;
      if (node && this._openPopover.contains(node)) return;
      this._closePopover();
    };
    document.addEventListener('mousedown', this._onDocClick, true);
    document.addEventListener('keydown', this._onDocKey, true);
    window.addEventListener('scroll', this._onDocScroll, true);

    // Ctrl/Meta keyup — commit any pending multi-select IN filter.
    this._onDocKeyUp = (e) => {
      if (e.key === 'Control' || e.key === 'Meta') this._commitCtrlSelect();
    };
    document.addEventListener('keyup', this._onDocKeyUp, true);
  }

  // Canonical "put me back to neutral" button. Wipes every piece of
  // analyst-authored filter / view state on this view: time window,
  // hidden columns, typed query, 🚩 Suspicious marks, stack column,
  // pivot spec, and every extracted (ƒx / regex / JSON-leaf) column.
  // Also wipes every Timeline-related `loupe_*` persisted key and

  // resets the in-memory layout prefs (`_gridH`, `_chartH`,
  // `_sections`, `_bucketId`, `_cardWidths`, `_cardOrder`), plus the
  // embedded GridViewer's saved column widths and drawer width, plus
  // the global TimelineQueryEditor history ring. Reset is the single
  // "scrub this workstation clean of Timeline state" button.
  //
  // ── Auto-extract nudge strip ────────────────────────────────────────
  // Inserted above `.tl-query-mount` once the lazy load completes. It
  // only renders if the auto-scanner finds ≥ 1 proposal and the user
  // hasn't opted out ("Don't show again" → `loupe_timeline_autoextract_nudged_hard`).
  // The strip surfaces up to 4 preview rows with a per-row "Add" button
  // plus a "See all N →" escape hatch that opens the full Extract dialog.
  _renderAutoExtractNudge() {
    if (this._destroyed) return;
    if (this._autoExtractNudgeDismissed) return;
    if (safeStorage.get(TIMELINE_KEYS.AUTOEXTRACT_NUDGED_HARD) === '1') return;
    if (!this._els || !this._els.host || !this._els.queryBar) return;

    // Don't pile a second strip on top of an existing one.
    if (this._els.host.querySelector('.tl-autoextract-nudge')) return;

    let proposals = [];
    try { proposals = this._autoExtractScan() || []; } catch (_) { return; }
    if (!proposals.length) return;

    // Rank by match %, then by URL/host kind over generic JSON leaves.
    const kindRank = { 'url-part': 0, 'text-url': 0, 'text-host': 0, 'json-url': 1, 'json-host': 1, 'kv-field': 2, 'json-leaf': 3 };
    const ranked = proposals.slice().sort((a, b) => {
      const ka = kindRank[a.kind] == null ? 9 : kindRank[a.kind];
      const kb = kindRank[b.kind] == null ? 9 : kindRank[b.kind];
      if (ka !== kb) return ka - kb;
      return (b.matchPct || 0) - (a.matchPct || 0);
    });
    const previewCount = Math.min(4, ranked.length);

    const strip = document.createElement('div');
    strip.className = 'tl-autoextract-nudge';
    strip.setAttribute('role', 'region');
    strip.setAttribute('aria-label', 'Auto-extractable fields');

    const header = document.createElement('div');
    header.className = 'tl-autoextract-nudge__header';
    header.innerHTML = `
      <span class="tl-autoextract-nudge__spark" aria-hidden="true">✨</span>
      <span class="tl-autoextract-nudge__title">${ranked.length} auto-extractable field${ranked.length === 1 ? '' : 's'} detected</span>
    `;
    const actions = document.createElement('div');
    actions.className = 'tl-autoextract-nudge__actions';
    actions.innerHTML = `
      <button type="button" class="tl-autoextract-nudge__seeall">See all ${ranked.length} →</button>
      <button type="button" class="tl-autoextract-nudge__dismiss" title="Hide for this session">Dismiss</button>
      <button type="button" class="tl-autoextract-nudge__never" title="Never show this nudge again on any file">Don't show again</button>
    `;
    header.appendChild(actions);
    strip.appendChild(header);

    const list = document.createElement('div');
    list.className = 'tl-autoextract-nudge__list';

    // Header row — shares the same `__row` grid template so every label
    // sits directly above its matching data cell. The trailing empty
    // <span> preserves the 6-track grid (kind | col | path | rate |
    // sample | add) so the "Add" buttons in data rows stay aligned.
    const head = document.createElement('div');
    head.className = 'tl-autoextract-nudge__row tl-autoextract-nudge__row--head';
    head.setAttribute('role', 'row');
    head.innerHTML = `
      <span class="tl-autoextract-nudge__kind tl-autoextract-nudge__kind--head">Type</span>
      <span class="tl-autoextract-nudge__col">Column</span>
      <span class="tl-autoextract-nudge__path">Path</span>
      <span class="tl-autoextract-nudge__rate" title="Match rate in sample">Match</span>
      <span class="tl-autoextract-nudge__sample">Sample</span>
      <span aria-hidden="true"></span>
    `;
    list.appendChild(head);

    const applyOne = (p) => {
      const before = this._extractedCols.length;
      if (p.kind === 'json-url' || p.kind === 'json-host' || p.kind === 'json-leaf') {
        this._addJsonExtractedColNoRender(p.sourceCol, p.path, p.proposedName, { autoKind: p.kind });
      } else if (p.kind === 'text-url' || p.kind === 'text-host') {
        this._addRegexExtractNoRender({
          name: p.proposedName,
          col: p.sourceCol,
          pattern: (p.kind === 'text-url' ? TL_URL_RE.source : TL_HOSTNAME_INLINE_RE.source),
          flags: 'i',
          group: (p.kind === 'text-host') ? 1 : 0,
          kind: 'auto',
        });
      } else if (p.kind === 'kv-field') {
        const esc = String(p.fieldName || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const pattern = `(?:^| \\| )${esc}=([\\s\\S]*?)(?= \\| [A-Za-z_][\\w.-]*=|$)`;
        this._addRegexExtractNoRender({
          name: p.proposedName,
          col: p.sourceCol,
          pattern,
          flags: '',
          group: 1,
          kind: 'auto',
          trim: true,
        });
      } else if (p.kind === 'url-part') {
        this._addRegexExtractNoRender({
          name: p.proposedName,
          col: p.sourceCol,
          pattern: p.pattern,
          flags: '',
          group: p.group,
          kind: 'auto',
        });
      }
      const added = this._extractedCols.length - before;
      if (added) {
        this._rebuildExtractedStateAndRender();

        if (this._app && this._app._toast) {
          this._app._toast(`Added "${p.proposedName}"`, 'info');
        }
      } else if (this._app && this._app._toast) {
        this._app._toast('Already extracted', 'info');
      }
    };

    for (let i = 0; i < previewCount; i++) {
      const p = ranked[i];
      const row = document.createElement('div');
      row.className = 'tl-autoextract-nudge__row';
      const colName = this.columns[p.sourceCol] || `(col ${p.sourceCol + 1})`;
      const pathLabel = p.path
        ? _tlJsonPathLabel(p.path)
        : (p.kind === 'kv-field' ? p.fieldName : '(whole cell)');
      row.innerHTML = `
        <span class="tl-autoextract-nudge__kind" data-kind="${_tlEsc(p.kind)}">${_tlEsc(p.kindLabel)}</span>
        <span class="tl-autoextract-nudge__col" title="${_tlEsc(colName)}">${_tlEsc(colName)}</span>
        <span class="tl-autoextract-nudge__path" title="${_tlEsc(String(pathLabel))}">${_tlEsc(String(pathLabel))}</span>
        <span class="tl-autoextract-nudge__rate" title="match rate in sample">${(p.matchPct || 0).toFixed(0)}%</span>
        <span class="tl-autoextract-nudge__sample" title="${_tlEsc(p.sample || '')}">${_tlEsc(this._ellipsis(p.sample || '', 80))}</span>
        <button type="button" class="tl-autoextract-nudge__add">Add</button>
      `;
      row.querySelector('.tl-autoextract-nudge__add').addEventListener('click', () => {
        applyOne(p);
        row.classList.add('tl-autoextract-nudge__row--added');
        const btn = row.querySelector('.tl-autoextract-nudge__add');
        if (btn) { btn.textContent = '✓ Added'; btn.disabled = true; }
      });
      list.appendChild(row);
    }
    strip.appendChild(list);

    const removeStrip = () => { if (strip.parentNode) strip.parentNode.removeChild(strip); };
    actions.querySelector('.tl-autoextract-nudge__seeall').addEventListener('click', () => {
      removeStrip();
      this._openExtractionDialog(null);
    });
    actions.querySelector('.tl-autoextract-nudge__dismiss').addEventListener('click', () => {
      this._autoExtractNudgeDismissed = true;
      removeStrip();
    });
    actions.querySelector('.tl-autoextract-nudge__never').addEventListener('click', () => {
      safeStorage.set(TIMELINE_KEYS.AUTOEXTRACT_NUDGED_HARD, '1');
      this._autoExtractNudgeDismissed = true;
      removeStrip();
      if (this._app && this._app._toast) this._app._toast('Auto-extract nudge disabled', 'info');
    });


    // Insert directly before the query mount so the nudge sits in the
    // normal scroll flow above the query bar.
    this._els.host.insertBefore(strip, this._els.queryBar);
  }

  // Extracted columns are cleared inline (not via `_clearAllExtractedCols`)
  // because that helper pops a window.confirm dialog and emits a toast —
  // both inappropriate for an explicit one-click Reset.
  _reset() {
    const baseLen = this._baseColumns.length;

    // ── Wipe every Timeline-related persisted key ────────────────────
    // This covers:
    //   - every `loupe_timeline_*` key (per-file + global)
    //   - the embedded GridViewer's saved column widths
    //     (`loupe_grid_colW_tl-grid-inner_csv-view`)
    //   - the shared drawer width (`loupe_grid_drawer_w`)
    safeStorage.removeMatching(k =>
      k.startsWith('loupe_timeline_')
      || k === 'loupe_grid_drawer_w'
      || k.startsWith('loupe_grid_colW_tl-grid-inner'));


    // ── Reset in-memory layout / workstation prefs ────────────────────
    // Must happen before the grid is destroyed below so the CSS custom
    // properties snap back on the still-mounted root.
    this._gridH = TIMELINE_GRID_DEFAULT_H;
    this._chartH = TIMELINE_CHART_DEFAULT_H;
    this._bucketId = 'auto';
    this._sections = {};
    this._cardWidths = {};
    this._cardOrder = null;
    this._pinnedCols = [];
    this._pendingCtrlSelect = null;
    if (this._root && this._root.style) {
      this._root.style.setProperty('--tl-grid-h', TIMELINE_GRID_DEFAULT_H + 'px');
      this._root.style.setProperty('--tl-chart-h', TIMELINE_CHART_DEFAULT_H + 'px');
    }
    if (this._els && this._els.bucketSelect) this._els.bucketSelect.value = 'auto';

    // Query history ring (cross-file workstation setting) — clear both
    // the persisted copy (already removed above) and the live editor's
    // in-memory array so the dropdown is empty immediately.
    if (this._queryEditor) {
      this._queryEditor._history = [];
    }

    // Embedded GridViewer — flush saved column widths + drawer width
    // that live on the instance (the persisted copies were removed
    // above; this stops the destroy-path from re-persisting them).

    if (this._grid) {
      try {
        if (this._grid._userColWidths && typeof this._grid._userColWidths.clear === 'function') {
          this._grid._userColWidths.clear();
        }
        if (this._grid.state && this._grid.state.drawer) {
          this._grid.state.drawer.width = null;
        }
      } catch (_) { /* noop */ }
    }


    // Query must be torn down BEFORE extracted columns, so the AST
    // serializer can still resolve extracted colIdx → name while the
    // query string is edited / cleared. After this, `_queryStr`,
    // `_queryAst`, `_queryPred` are all null and persistence is blanked.
    if (this._queryStr || this._queryEditor) {
      if (this._queryEditor) this._queryEditor.setValue('');
      this._applyQueryString('');
    }

    // Time-range window + grid cursor.
    this._window = null;
    this._cursorDataIdx = null;

    // 🚩 Suspicious marks — wipe in-memory array + persisted entry.
    if (this._susMarks && this._susMarks.length) {
      this._susMarks = [];
      TimelineView._saveSusMarksFor(this._fileKey, []);
      this._rebuildSusBitmap();
    }

    // Stack column — blank both state + select widget.
    if (this._stackCol != null) {
      this._stackCol = null;
      if (this._els && this._els.stackColSelect) this._els.stackColSelect.value = '-1';
    }

    // Pivot spec — clear persisted + cached results, and blank the
    // result body back to its placeholder so a stale table isn't left
    // visible until the next Build.
    if (this._pivotSpec) {
      this._pivotSpec = null;
      TimelineView._savePivotSpec({});
    }
    this._lastPivot = null;
    if (this._els) {
      if (this._els.pvRows) this._els.pvRows.value = '-1';
      if (this._els.pvCols) this._els.pvCols.value = '-1';
      if (this._els.pvAgg) this._els.pvAgg.value = 'count';
      if (this._els.pvAggCol) this._els.pvAggCol.value = '-1';
      if (this._els.pvAggColWrap) this._els.pvAggColWrap.style.display = 'none';
      if (this._els.pvResultBody) {
        this._els.pvResultBody.innerHTML = '<div class="tl-pivot-empty">Pick Rows + Columns + Aggregate → Build.</div>';
      }
    }

    // Extracted columns — strip every ƒx / regex / JSON-leaf column.
    // Query clauses targeting extracted cols were already dropped above
    // by the `_applyQueryString('')` pass, so we can splice the list
    // directly. Snap timestamp back to auto-detect if it pointed into
    // extracted space.
    if (this._extractedCols && this._extractedCols.length) {
      if (this._timeCol != null && this._timeCol >= baseLen) {
        this._timeCol = _tlAutoDetectTimestampCol(this._baseColumns, this.rows);
        if (this._els && this._els.timeColSelect) {
          this._els.timeColSelect.value = this._timeCol == null ? '-1' : String(this._timeCol);
        }
        this._parseAllTimestamps();
        this._dataRange = this._computeDataRange();
      }
      this._extractedCols = [];
      this._jsonCache.clear();
      this._persistRegexExtracts();   // writes an empty list for this file
    }

    // Unhide any columns the analyst hid via Ctrl+Click / column menu /
    // tl-col-card Ctrl+Click — Reset is the canonical "put me back to
    // neutral" button, so every grid-side UI toggle belongs here too.
    if (this._grid && typeof this._grid._unhideAllColumns === 'function') {
      try { this._grid._unhideAllColumns(); } catch (_) { /* noop */ }
    }

    // Invalidate every derived / cached render product so the next
    // scheduleRender starts from scratch.
    this._colStats = null;
    this._colStatsGen++;
    this._lastChartData = null;
    // Column count may have changed (extracted columns dropped) — kill
    // the grid so it rebuilds with the correct column set. Mirrors
    // `_rebuildExtractedStateAndRender`.
    if (this._grid) {
      try { this._grid.destroy(); } catch (_) { /* noop */ }
      this._grid = null;
    }

    // Re-populate toolbar + pivot dropdowns so extracted-column options
    // disappear from them. `_populateToolbarSelects` also re-applies the
    // (now-cleared) `_timeCol` / `_stackCol` / `_bucketId` values.
    this._populateToolbarSelects();
    this._populatePivotSelects();

    this._recomputeFilter();
    this._scheduleRender(['chart', 'scrubber', 'chips', 'grid', 'columns', 'detections', 'entities', 'pivot']);
  }




  // ── Render scheduler ─────────────────────────────────────────────────────
  _scheduleRender(tasks) {
    for (const t of tasks) this._pendingTasks.add(t);
    if (this._rafPending) return;
    this._rafPending = true;
    requestAnimationFrame(() => {
      this._rafPending = false;
      if (this._destroyed) return;
      const set = new Set(this._pendingTasks);
      this._pendingTasks.clear();
      // Chart, grid, scrubber, chips render first — these are the primary
      // visual feedback surfaces and must update in the same frame as the
      // user's keystroke / click so the UI feels responsive.
      if (set.has('scrubber')) this._renderScrubber();
      if (set.has('chart')) this._renderChart();
      if (set.has('chips')) this._renderRangeBanner();
      if (set.has('chips')) this._renderChips();
      if (set.has('grid')) this._renderGrid();
      if (set.has('detections')) this._renderDetections();
      if (set.has('entities')) this._renderEntities();
      if (set.has('pivot')) {/* lazy; built on demand via Build button */ }
      this._refreshRowStat();

      // Column stats are O(rows × cols) — the single most expensive
      // synchronous computation in the render pipeline. Defer them to a
      // follow-up animation frame so the chart + grid paint first and the
      // user sees immediate visual feedback. The column cards update one
      // frame later (≈16 ms), which is imperceptible but unblocks the
      // critical path that was causing stutter on clear / type-ahead.
      //
      // When the Top Values section is collapsed, skip the computation
      // entirely — `_colStats` remains null (the "dirty" flag). The
      // computation will run when the section is expanded, which already
      // schedules a 'columns' render via _toggleSection. This saves
      // 1-3 seconds on filter clear / type-ahead for 1M-row datasets.
      if (set.has('columns')) {
        const colsCollapsed = !!this._sections.columns;
        cancelAnimationFrame(this._colStatsRaf);
        if (colsCollapsed) {
          this._colStatsRaf = 0;
        } else {
          this._colStatsRaf = requestAnimationFrame(() => {
            this._colStatsRaf = 0;
            if (this._destroyed) return;
            if (!this._colStats) {
              const idx = this._filteredIdx || new Uint32Array(0);
              // Small datasets: synchronous (no perceptible delay).
              // Large datasets: cooperative-yielding so the main thread
              // stays responsive during the O(rows × cols) pass.
              if (idx.length < 50000) {
                this._colStats = this._computeColumnStatsSync(idx);
                this._renderColumns();
              } else {
                const gen = ++this._colStatsGen;
                this._computeColumnStatsAsync(idx, gen).then(result => {
                  if (this._destroyed) return;
                  if (result === null) return; // superseded
                  this._colStats = result;
                  this._renderColumns();
                });
              }
              return; // large-dataset path renders after the promise resolves
            }
            this._renderColumns();
          });
        }
      }
    });
  }

  _refreshRowStat() {
    const total = this.rows.length;
    const visible = this._filteredIdx ? this._filteredIdx.length : total;
    let txt = visible === total
      ? `${total.toLocaleString()} rows`
      : `${visible.toLocaleString()} / ${total.toLocaleString()} rows`;
    if (this._susAny) {
      const susCount = this._susFilteredIdx ? this._susFilteredIdx.length : 0;
      txt += ` · ${susCount.toLocaleString()} 🚩`;
    }
    this._els.rowStat.textContent = txt;
  }

  // ── Scrubber ─────────────────────────────────────────────────────────────
  _renderScrubber() {
    const els = this._els;
    const dr = this._dataRange;
    if (!dr) {
      els.scrubLabelL.textContent = '—';
      els.scrubLabelR.textContent = '—';
      els.scrubWindow.style.left = '0%';
      els.scrubWindow.style.width = '100%';
      els.scrubHandleL.style.left = '0%';
      els.scrubHandleR.style.left = '100%';
      return;
    }
    els.scrubLabelL.textContent = _tlFormatFullUtc(dr.min, this._timeIsNumeric);
    els.scrubLabelR.textContent = _tlFormatFullUtc(dr.max, this._timeIsNumeric);
    const span = dr.max - dr.min;
    const win = this._window;
    const lo = win ? (win.min - dr.min) / span : 0;
    const hi = win ? (win.max - dr.min) / span : 1;
    const loPct = Math.max(0, Math.min(1, lo)) * 100;
    const hiPct = Math.max(0, Math.min(1, hi)) * 100;
    els.scrubWindow.style.left = loPct + '%';
    els.scrubWindow.style.width = Math.max(0.5, hiPct - loPct) + '%';
    els.scrubHandleL.style.left = loPct + '%';
    els.scrubHandleR.style.left = hiPct + '%';
  }

  _installScrubberDrag() {
    const track = this._els.scrubTrack;
    const handleL = this._els.scrubHandleL;
    const handleR = this._els.scrubHandleR;
    const winEl = this._els.scrubWindow;

    const pctAt = (x) => {
      const rect = track.getBoundingClientRect();
      return Math.max(0, Math.min(1, (x - rect.left) / rect.width));
    };
    const msAt = (pct) => {
      const dr = this._dataRange; if (!dr) return NaN;
      return dr.min + pct * (dr.max - dr.min);
    };
    const beginDrag = (mode, startX) => {
      if (!this._dataRange) return;
      let dragging = true;
      const startWindow = this._window ? { ...this._window } : { min: this._dataRange.min, max: this._dataRange.max };
      const startPct = pctAt(startX);
      // Enter live-drag mode: renders skip grid/columns/sus for the duration
      // of the drag. Chip predicates are NOT re-run — only the cached
      // `_chipFilteredIdx` is re-clipped by the new window via
      // `_applyWindowOnly()`.
      this._windowDragging = true;
      const onMove = (e) => {
        if (!dragging) return;
        const pct = pctAt(e.clientX);
        const nowMs = msAt(pct);
        let lo, hi;
        if (mode === 'create') {
          const a = Math.min(startPct, pct), b = Math.max(startPct, pct);
          lo = msAt(a); hi = msAt(b);
        } else if (mode === 'left') {
          lo = Math.min(startWindow.max - 1, nowMs); hi = startWindow.max;
        } else if (mode === 'right') {
          lo = startWindow.min; hi = Math.max(startWindow.min + 1, nowMs);
        } else if (mode === 'move') {
          const deltaPct = pct - startPct;
          const deltaMs = deltaPct * (this._dataRange.max - this._dataRange.min);
          lo = startWindow.min + deltaMs; hi = startWindow.max + deltaMs;
          const span = hi - lo;
          if (lo < this._dataRange.min) { lo = this._dataRange.min; hi = lo + span; }
          if (hi > this._dataRange.max) { hi = this._dataRange.max; lo = hi - span; }
        }
        if (Number.isFinite(lo) && Number.isFinite(hi) && hi > lo) {
          this._window = {
            min: Math.max(this._dataRange.min, lo),
            max: Math.min(this._dataRange.max, hi),
          };
          this._applyWindowOnly();
          // Lightweight: only scrubber + chart visibly update during drag.
          // Row-stat reflects the new count but grid/columns/sus wait for
          // pointerup. This keeps drag rAF under a few ms even at 100k+ rows.
          this._scheduleRender(['scrubber', 'chart']);
          // Live-update the range banner so the analyst can read the
          // pending [from → to · duration] while dragging. O(1) text
          // update — cheaper than a full 'chips' task (which would also
          // repaint the sus chips strip unnecessarily).
          this._renderRangeBanner({ min: this._window.min, max: this._window.max, preview: true });
        }
      };
      const onUp = () => {
        dragging = false;
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
        this._windowDragging = false;
        // Commit: run the full render pass once, including grid/columns/sus.
        // The 'chips' task clears the --preview modifier off the banner.
        this._scheduleRender(['scrubber', 'chart', 'chips', 'grid', 'columns']);
      };

      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
    };

    track.addEventListener('pointerdown', (e) => {
      if (e.target === handleL) { beginDrag('left', e.clientX); return; }
      if (e.target === handleR) { beginDrag('right', e.clientX); return; }
      if (e.target === winEl) { beginDrag('move', e.clientX); return; }
      beginDrag('create', e.clientX);
    });
  }

  // ── Chart ────────────────────────────────────────────────────────────────
  _renderChart() {
    this._lastChartData = this._renderChartInto(
      this._els.chartCanvas, this._els.chartLegend, this._els.chartEmpty,
      this._filteredIdx, 'main',
    );

  }

  // ── Stable stack-color assignment ────────────────────────────────────────
  // Builds value → palette-index mapping from the FULL (unfiltered)
  // dataset so that legend colors stay pinned to the same values
  // regardless of what subset is currently visible after filtering.
  // Called once when the stack column is chosen or changed — NOT on
  // every filter / chart render.

  _buildStableStackColorMap() {
    const col = this._stackCol;
    if (col == null) { this._stackColorMap = null; return; }
    const counts = new Map();
    for (let i = 0; i < this.rows.length; i++) {
      const v = this._cellAt(i, col);
      counts.set(v, (counts.get(v) || 0) + 1);
    }
    // Sort by descending frequency so the most common values claim the
    // first (most visually distinctive) palette slots.  Every unique
    // value gets its own colour — no "Other" bucket.
    const sorted = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
    const m = new Map();
    for (let i = 0; i < sorted.length; i++) m.set(sorted[i][0], i);
    this._stackColorMap = m;
  }

  _renderChartInto(canvas, legendEl, emptyEl, idx, role) {
    if (!canvas) return null;
    const data = this._computeChartData(idx);
    if (!data || !idx || idx.length === 0) {
      emptyEl.classList.remove('hidden');
      const dprE = window.devicePixelRatio || 1;
      const bwE = Math.round(canvas.clientWidth * dprE);
      const bhE = Math.round(canvas.clientHeight * dprE);
      if (canvas.width !== bwE || canvas.height !== bhE) { canvas.width = bwE; canvas.height = bhE; }
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      legendEl.innerHTML = '';
      return null;
    }
    emptyEl.classList.add('hidden');
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    // Re-size the backing store whenever EITHER dimension changes. The
    // previous width-only guard missed vertical-only resizes (dragging
    // `.tl-chart-resize`), leaving a stale backing store that the browser
    // then stretched up to fill `clientHeight`.
    const bw = Math.round(w * dpr), bh = Math.round(h * dpr);
    if (canvas.width !== bw || canvas.height !== bh) { canvas.width = bw; canvas.height = bh; }
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const { buckets, bucketCount, maxTotal, stackKeys, rangeMs, viewLo, bucketMs } = data;
    const padL = 48, padR = 14, padT = 14, padB = 24;
    const plotW = Math.max(1, w - padL - padR);
    const plotH = Math.max(1, h - padT - padB);
    const barW = plotW / bucketCount;
    const k = stackKeys ? stackKeys.length : 1;

    // Grid lines
    ctx.strokeStyle = 'rgba(128,128,128,0.15)';
    ctx.lineWidth = 1;
    for (let g = 1; g <= 4; g++) {
      const y = padT + (plotH * g) / 5;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(padL + plotW, y); ctx.stroke();
    }

    ctx.fillStyle = 'rgba(128,128,128,0.8)';
    ctx.font = '10px system-ui, -apple-system, Segoe UI, sans-serif';
    ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
    ctx.fillText(String(maxTotal), padL - 4, padT);
    ctx.fillText('0', padL - 4, padT + plotH);

    ctx.textAlign = 'center'; ctx.textBaseline = 'top';
    const ticks = 5;
    for (let i = 0; i <= ticks; i++) {
      const t = viewLo + (rangeMs * i) / ticks;
      const x = padL + (plotW * i) / ticks;
      ctx.fillText(_tlFormatTick(t, rangeMs, this._timeIsNumeric), x, padT + plotH + 4);
    }

    // Resolve per-stack-key palette indices: prefer the stable color map
    // (pinned to unfiltered frequencies) so colours don't shift on filter.
    // Falls back to positional indexing when no stable map exists.
    const stableMap = this._stackColorMap;
    const paletteFor = (j) => {
      if (stableMap && stackKeys) {
        const ci = stableMap.get(stackKeys[j]);
        if (ci !== undefined) return TIMELINE_STACK_PALETTE[ci % TIMELINE_STACK_PALETTE.length];
      }
      return TIMELINE_STACK_PALETTE[j % TIMELINE_STACK_PALETTE.length];
    };

    const scale = maxTotal > 0 ? plotH / maxTotal : 0;
    for (let b = 0; b < bucketCount; b++) {
      let yAcc = padT + plotH;
      const x = padL + b * barW;
      for (let j = 0; j < k; j++) {
        const c = buckets[b * k + j];
        if (!c) continue;
        const barH = c * scale;
        ctx.fillStyle = paletteFor(j);
        const bw = Math.max(1, barW - 1);
        ctx.fillRect(x, yAcc - barH, bw, barH);
        yAcc -= barH;
      }
    }

    // Red-tinted sus overlay — drawn only on the main histogram (the sus
    // mini-chart is already all-sus). The tint sits on TOP of the stacked
    // bars, proportional to the sus-share within each bucket, so the user
    // can read how much of each bar is 🚩-flagged without losing the
    // stack colours beneath. `--risk-high` is #dc2626 = rgb(220,38,38);
    // canvas can't resolve CSS custom properties so we hardcode it.
    const susBuckets = data.susBuckets;
    if (susBuckets && role === 'main') {
      ctx.fillStyle = 'rgba(220,38,38,0.55)';
      for (let b = 0; b < bucketCount; b++) {
        const sc = susBuckets[b];
        if (!sc) continue;
        // Total bucket height (sum of stacks) = baseline for positioning
        // the tint. Clamp to total so overlays never exceed the bar.
        let total = 0;
        for (let j = 0; j < k; j++) total += buckets[b * k + j];
        if (!total) continue;
        const totalH = total * scale;
        const susH = Math.min(totalH, sc * scale);
        const x = padL + b * barW;
        const bw = Math.max(1, barW - 1);
        const y = padT + plotH - totalH;
        ctx.fillRect(x, y, bw, susH);
      }
    }

    ctx.strokeStyle = 'rgba(128,128,128,0.35)';
    ctx.strokeRect(padL, padT, plotW, plotH);

    // Sus-bucket indicator strip — high-contrast red tick along the top
    // edge of the plot area for every bucket that contains ≥ 1 🚩
    // suspicious event. Complements the proportional in-bar red wash
    // above: the wash reads "how MUCH of this bar is sus" (can be small
    // / invisible on a bar dominated by benign rows), whereas this strip
    // is a binary "HERE be dragons" signal that stays loud even when
    // the sus share is tiny. Drawn AFTER the plot border so the ticks
    // sit on top of `strokeRect` rather than being clipped by it.
    // Skipped on the sus mini-chart (every bar is already all-sus there).
    if (susBuckets && role === 'main') {
      ctx.fillStyle = 'rgb(220,38,38)';
      for (let b = 0; b < bucketCount; b++) {
        if (!susBuckets[b]) continue;
        const x = padL + b * barW;
        const bw = Math.max(2, barW - 1);
        // 3 px strip pinned just inside the top of the plot — sits
        // clear of both the y-axis tick labels and the cursor's top
        // triangle (the `.tl-chart-cursor::before` at top: -4px).
        ctx.fillRect(x, padT, bw, 3);
      }
    }


    // Legend
    legendEl.innerHTML = '';
    if (stackKeys && stackKeys.length) {
      const stackColName = this._stackCol != null ? (this.columns[this._stackCol] || '') : '';
      if (stackColName) {
        const hdr = document.createElement('span');
        hdr.className = 'tl-legend-hdr';
        hdr.textContent = `stacked by ${stackColName}:`;
        legendEl.appendChild(hdr);
      }
      for (let i = 0; i < stackKeys.length; i++) {
        const k2 = stackKeys[i];
        const chip = document.createElement('span');
        chip.className = 'tl-legend-chip';
        chip.dataset.key = k2;
        chip.dataset.role = role;
        chip.innerHTML = `<span class="tl-legend-swatch" style="background:${paletteFor(i)}"></span>${_tlEsc(k2)}`;
        chip.title = 'Click = filter · Dbl-click = only this · Shift-click = exclude · Right-click = more';
        legendEl.appendChild(chip);
      }
      // Wire legend interactions once per legend render.
      legendEl.addEventListener('click', this._onLegendClick || (this._onLegendClick = (e) => this._handleLegendClick(e)));
      legendEl.addEventListener('dblclick', this._onLegendDbl || (this._onLegendDbl = (e) => this._handleLegendDbl(e)));
      legendEl.addEventListener('contextmenu', this._onLegendCtx || (this._onLegendCtx = (e) => this._handleLegendContext(e)));
    }

    // Paint the red-line cursor (if any) after the bars. Implemented as a
    // cheap absolutely-positioned <div> overlay inside `.tl-chart` so grid-
    // row clicks don't have to redraw the whole canvas. We position it
    // here off the fresh layout to stay in sync with zoom / bucket changes.
    this._paintChartCursorFor(canvas, { padL, padT, plotW, plotH, viewLo, rangeMs });

    return { ...data, layout: { padL, padR, padT, padB, plotW, plotH, barW, bucketMs } };
  }

  // ── Red-line "you are here" cursor ───────────────────────────────────────
  // Paints a thin vertical red line on the given chart canvas at the
  // x-position matching `this._cursorDataIdx`. Called from `_renderChartInto`
  // so the cursor stays glued to the correct time even when bucket / zoom /
  // stack settings change. The cursor is a lazily-created absolutely-
  // positioned <div.tl-chart-cursor> inside the chart wrapper — much cheaper
  // than re-drawing the whole canvas whenever the focused row changes.
  _paintChartCursorFor(canvas, layout) {
    const wrap = canvas && canvas.parentElement; if (!wrap) return;
    let cur = wrap.querySelector('.tl-chart-cursor');
    const di = this._cursorDataIdx;
    if (di == null || !this._timeMs) {
      if (cur) cur.hidden = true;
      return;
    }
    const t = this._timeMs[di];
    if (!Number.isFinite(t)) { if (cur) cur.hidden = true; return; }
    const { padL, padT, plotW, plotH, viewLo, rangeMs } = layout;
    const rel = (t - viewLo) / rangeMs;
    if (!Number.isFinite(rel) || rel < 0 || rel > 1) {
      if (cur) cur.hidden = true;
      return;
    }
    if (!cur) {
      cur = document.createElement('div');
      cur.className = 'tl-chart-cursor';
      // Top handle — a real DOM element (not ::before) so it can receive
      // pointer events for click+drag scrubbing through the events grid.
      const handle = document.createElement('div');
      handle.className = 'tl-chart-cursor-handle';
      cur.appendChild(handle);
      wrap.appendChild(cur);
      this._installCursorDrag(handle, cur, canvas);
    }
    // Offset by the canvas's position within `.tl-chart` so the cursor
    // lines up with the plot area. `.tl-chart` has padding (see
    // viewers.css) and absolute children are positioned against its
    // padding-box — without `canvas.offsetLeft/Top` the cursor lands to
    // the left of the canvas (visible on the very first event, where
    // `rel ≈ 0`, because `padL` alone is in canvas-local pixels).
    cur.hidden = false;
    cur.style.left = (canvas.offsetLeft + padL + rel * plotW) + 'px';
    cur.style.top = (canvas.offsetTop + padT) + 'px';
    cur.style.height = plotH + 'px';
  }


  // Paint (or clear) the matching cursor on the scrubber track — so the
  // cursor reads sensibly even when the histogram is zoomed past it.
  _paintScrubberCursor() {
    const track = this._els && this._els.scrubTrack; if (!track) return;
    let cur = track.querySelector('.tl-scrubber-cursor');
    const di = this._cursorDataIdx;
    const dr = this._dataRange;
    if (di == null || !dr || !this._timeMs) { if (cur) cur.hidden = true; return; }
    const t = this._timeMs[di];
    if (!Number.isFinite(t)) { if (cur) cur.hidden = true; return; }
    const pct = (t - dr.min) / Math.max(1, dr.max - dr.min);
    if (!Number.isFinite(pct) || pct < 0 || pct > 1) { if (cur) cur.hidden = true; return; }
    if (!cur) {
      cur = document.createElement('div');
      cur.className = 'tl-scrubber-cursor';
      track.appendChild(cur);
    }
    cur.hidden = false;
    cur.style.left = (pct * 100) + '%';
  }

  // ── Cursor drag (click+drag the red-line handle to scrub) ──────────────
  // Given a target timestamp, find the row in `_filteredIdx` whose time
  // is closest. The filtered index is in original-row order (which is
  // the file's native row order — usually chronological for CSV/EVTX),
  // so a linear scan is acceptable at interactive rates (rAF-throttled).
  // Returns a dataIdx suitable for `_setCursorDataIdx`, or null.
  _findNearestDataIdxForTime(targetMs) {
    const idx = this._filteredIdx;
    const times = this._timeMs;
    if (!idx || !idx.length || !times) return null;
    let bestDi = null;
    let bestDist = Infinity;
    for (let i = 0; i < idx.length; i++) {
      const di = idx[i];
      const t = times[di];
      if (!Number.isFinite(t)) continue;
      const d = Math.abs(t - targetMs);
      if (d < bestDist) { bestDist = d; bestDi = di; }
    }
    return bestDi;
  }

  // Scroll the main grid so the row for `dataIdx` is roughly centred in
  // the viewport. Uses instant (non-smooth) scrolling so the grid tracks
  // the cursor position during a drag without animation lag. Skips the
  // GridViewer `_scrollToRow` path which opens the drawer and does
  // highlight flash — here we just want a lightweight viewport reposition.
  _scrollGridToCursorIdx(dataIdx) {
    const viewer = this._grid;
    if (!viewer || !viewer._scr) return;
    // Map original dataIdx → virtual row index in the grid. The grid's
    // rows are in `_filteredIdx` order, so we need the position of
    // `dataIdx` within `_filteredIdx`.
    const fi = this._filteredIdx;
    if (!fi) return;
    let vIdx = -1;
    for (let i = 0; i < fi.length; i++) {
      if (fi[i] === dataIdx) { vIdx = i; break; }
    }
    if (vIdx < 0) return;
    const rowH = viewer.ROW_HEIGHT || 28;
    const viewportH = viewer._scr.clientHeight || 400;
    const target = Math.max(0, vIdx * rowH - (viewportH - rowH) / 2);
    viewer._scr.scrollTop = target;
  }

  // Wire pointer events on the cursor handle so the analyst can click+drag
  // the red line to scrub through the events grid. Captures the pointer on
  // the handle element, converts each pointermove into a timestamp via the
  // cached chart layout, finds the nearest filtered row, moves the cursor,
  // and scrolls the grid. Stops propagation so the chart's own rubber-band
  // / bucket-drill handler does not fire.
  _installCursorDrag(handle, cursorEl, canvas) {
    let dragging = false;
    let scrollRaf = 0;

    handle.addEventListener('pointerdown', (e) => {
      if (e.button !== 0) return;
      e.stopPropagation();  // don't trigger chart rubber-band / drill
      e.preventDefault();
      const data = this._lastChartData;
      if (!data || !data.layout) return;

      // Acquire pointer capture *before* mutating drag state. If
      // setPointerCapture throws (rare — torn-down handle, browser quirk),
      // pointermove events outside the 8-px handle never fire and the
      // drag silently stalls. Bail early in that case so `dragging` /
      // `_cursorDragging` don't get stuck on, which would otherwise
      // disable the grid-scroll cursor anchor until the next click.
      try {
        handle.setPointerCapture(e.pointerId);
      } catch (_) {
        return;
      }

      dragging = true;
      this._cursorDragging = true;
      cursorEl.classList.add('dragging');
      // Also kill the scrubber cursor transition so both stay in sync.
      const scrubCur = this._els && this._els.scrubTrack
        ? this._els.scrubTrack.querySelector('.tl-scrubber-cursor') : null;
      if (scrubCur) scrubCur.classList.add('dragging');

      const onMove = (ev) => {
        if (!dragging) return;
        const cd = this._lastChartData;
        if (!cd || !cd.layout) return;
        const rect = canvas.getBoundingClientRect();
        const x = ev.clientX - rect.left;
        const { padL, plotW } = cd.layout;
        const clamped = Math.max(padL, Math.min(padL + plotW, x));
        const rel = (clamped - padL) / plotW;
        const targetMs = cd.viewLo + rel * cd.rangeMs;
        const di = this._findNearestDataIdxForTime(targetMs);
        if (di != null) {
          this._setCursorDataIdx(di);
          // Throttle grid scrolling to rAF so we don't overwhelm
          // the virtual-scroll grid with synchronous reflows.
          if (!scrollRaf) {
            const scrollDi = di;
            scrollRaf = requestAnimationFrame(() => {
              scrollRaf = 0;
              this._scrollGridToCursorIdx(scrollDi);
            });
          }
        }
      };

      const onUp = () => {
        dragging = false;
        this._cursorDragging = false;
        cursorEl.classList.remove('dragging');
        if (scrubCur) scrubCur.classList.remove('dragging');
        handle.removeEventListener('pointermove', onMove);
        handle.removeEventListener('pointerup', onUp);
        handle.removeEventListener('pointercancel', onUp);
        try { handle.releasePointerCapture(e.pointerId); } catch (_) { /* noop */ }
        if (scrollRaf) { cancelAnimationFrame(scrollRaf); scrollRaf = 0; }
      };

      handle.addEventListener('pointermove', onMove);
      handle.addEventListener('pointerup', onUp);
      handle.addEventListener('pointercancel', onUp);
    });
  }

  // Anchor the "you are here" cursor to the row currently nearest the
  // vertical middle of a grid's viewport (or the row opened in the
  // drawer, if any — that wins because it's a stable fixed reference).
  // Called rAF-throttled from each grid's scroll handler; the CSS
  // `transition: left 140ms ease-out` on `.tl-chart-cursor` provides the
  // visual glide, so this just needs to set the right dataIdx. The
  // ±8-row bidirectional scan tolerates rows with missing / unparseable
  // timestamps without hiding or snapping the cursor — mirrors the
  // anchor logic in `grid-viewer.js` `_updateTimelineCursor`.
  _updateCursorFromGridScroll(viewer) {
    if (!viewer || !viewer._scr || !this._timeMs) return;
    // During a cursor drag the analyst is driving the cursor position
    // via the chart — the grid scrolls to follow.  If we let the
    // scroll-driven anchor run it would fight the drag and teleport
    // the cursor back to the viewport midpoint.
    if (this._cursorDragging) return;

    // Scroll-anchored: row nearest the vertical middle of the
    //    viewport. Middle (not top-edge) to avoid twitch on fine
    //    trackpad scroll.
    const visible = viewer._visibleCount ? viewer._visibleCount() : 0;
    if (!visible) return;
    const rowH = viewer.ROW_HEIGHT || 28;
    const midPx = (viewer._scr.scrollTop || 0) + ((viewer._scr.clientHeight || 0) / 2);
    const midV = Math.max(0, Math.min(visible - 1, Math.floor(midPx / rowH)));

    // ±8-row scan to tolerate rows with no parseable time — prevents
    //    the cursor from hiding / snapping when the user scrolls through
    //    a stretch of blank-timestamp rows.
    const WIN = 8;
    const lo = Math.max(0, midV - WIN);
    const hi = Math.min(visible - 1, midV + WIN);
    let bestDist = Infinity;
    let bestDataIdx = null;
    for (let v = lo; v <= hi; v++) {
      const di = viewer._dataIdxOf ? viewer._dataIdxOf(v) : null;
      if (di == null) continue;
      // `di` here is an index into the grid's `rowsConcat` — which is the
      // same as the original dataIdx because we pass rows in the exact
      // order of `this._filteredIdx` / `this._susFilteredIdx` (see
      // `_renderGridInto`). Map grid-virtual → original data row.
      const role = viewer._tlRole;
      const srcArr = (role === 'main') ? this._filteredIdx : this._susFilteredIdx;
      const orig = srcArr ? srcArr[di] : di;
      const t = this._timeMs[orig];
      if (!Number.isFinite(t)) continue;
      const dist = Math.abs(v - midV);
      if (dist < bestDist) { bestDist = dist; bestDataIdx = orig; }
    }
    if (bestDataIdx != null) this._setCursorDataIdx(bestDataIdx);
  }

  // Public-ish setter — called from grid-row click. Clears the cursor when
  // passed `null`. Triggers a cheap cursor-only repaint; the chart bars
  // themselves do not need to redraw.
  _setCursorDataIdx(dataIdx) {

    this._cursorDataIdx = (dataIdx == null) ? null : (dataIdx | 0);
    // Main chart
    if (this._els && this._els.chartCanvas && this._lastChartData && this._lastChartData.layout) {
      this._paintChartCursorFor(this._els.chartCanvas, {
        ...this._lastChartData.layout,
        viewLo: this._lastChartData.viewLo,
        rangeMs: this._lastChartData.rangeMs,
      });
    }
    this._paintScrubberCursor();
  }

  // Single-bucket drill — invoked by `_installChartDrag` when the user
  // pointer-clicks without dragging. Uses the fast window-only path because
  // chip predicates don't change.
  _onChartClick(canvas, data, clientX) {
    if (!data) return;
    const rect = canvas.getBoundingClientRect();
    const x = clientX - rect.left;
    const { padL, plotW, barW, bucketMs } = data.layout;
    if (x < padL || x > padL + plotW) return;
    const b = Math.min(data.bucketCount - 1, Math.max(0, Math.floor((x - padL) / barW)));
    const bucketLo = data.viewLo + b * bucketMs;
    const bucketHi = bucketLo + bucketMs;
    this._window = { min: bucketLo, max: bucketHi };
    this._applyWindowOnly();
    this._scheduleRender(['scrubber', 'chart', 'chips', 'grid', 'columns']);
  }

  // ── Chart rubber-band selection ──────────────────────────────────────────
  // Layered over each chart canvas. Three interactions from one pointer stream:
  //   - tap (no drag, move < 4 px) → existing single-bucket drill
  //   - drag within plot area      → set the time window to [startX, endX],
  //                                  snapped to bucket boundaries on pointer-up
  //   - Shift-drag                 → union the selection with the current window
  //   - double-click               → reset window to data range (like Reset chip)
  //
  // During the drag itself we stay in the cheap path: `_applyWindowOnly()` +
  // `_scheduleRender(['scrubber','chart'])`. Grid / columns / sus are deferred
  // until pointer-up so 100k-row datasets stay interactive. The visible
  // selection overlay is a cheap absolutely-positioned <div> inside `.tl-chart`.
  _installChartDrag(canvas, chartWrap, tooltip, getData) {
    // Hover tooltip stays wired — `_onChartHover` reads `.layout` off the
    // currently-cached chart data to highlight the nearest bucket.
    canvas.addEventListener('mousemove', (e) => this._onChartHover(e, getData(), tooltip));
    canvas.addEventListener('mouseleave', () => { tooltip.hidden = true; });

    // Double-click anywhere on the plot clears the window.
    canvas.addEventListener('dblclick', (e) => {
      const data = getData();
      if (!data) return;
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const { padL, plotW } = data.layout;
      if (x < padL || x > padL + plotW) return;
      if (this._window) {
        this._window = null;
        this._applyWindowOnly();
        this._scheduleRender(['scrubber', 'chart', 'chips', 'grid', 'columns']);
      }
    });

    const DRAG_THRESHOLD_PX = 4;

    canvas.addEventListener('pointerdown', (e) => {
      if (e.button !== 0) return;   // left button only — right-click reserved
      const data = getData();
      if (!data) return;
      const rect = canvas.getBoundingClientRect();
      const x0 = e.clientX - rect.left;
      const { padL, plotW, padT, plotH } = data.layout;
      if (x0 < padL || x0 > padL + plotW) return;   // clicked in axis margin — ignore
      // Snapshot the window state at drag-start so Shift-union works against
      // the stable starting window rather than the in-flight one.
      const startWindow = this._window
        ? { min: this._window.min, max: this._window.max }
        : null;
      // Convert a plot-space x (pixels) to a time (ms) in the chart's domain.
      const xToMs = (px) => {
        const clamped = Math.max(padL, Math.min(padL + plotW, px));
        const rel = (clamped - padL) / plotW;
        return data.viewLo + rel * data.rangeMs;
      };
      // Snap a time to bucket boundaries so the selection lands on whole bars.
      const snap = (ms, floor) => {
        const off = ms - data.viewLo;
        const idx = floor ? Math.floor(off / data.bucketMs) : Math.ceil(off / data.bucketMs);
        return data.viewLo + idx * data.bucketMs;
      };

      // Build the selection overlay lazily — reused across drags on the same
      // chart. Lives inside `.tl-chart` so it's relative to the plot.
      let overlay = chartWrap.querySelector('.tl-chart-selection');
      if (!overlay) {
        overlay = document.createElement('div');
        overlay.className = 'tl-chart-selection';
        overlay.hidden = true;
        chartWrap.appendChild(overlay);
      }

      let dragged = false;
      try { canvas.setPointerCapture(e.pointerId); } catch (_) { /* noop */ }
      this._windowDragging = true;

      // `.tl-chart` has padding (see viewers.css), and the overlay is
      // positioned relative to `.tl-chart` (its padding-box), while
      // `padL` is in canvas-local coordinates. Offset by the canvas's
      // position within its parent so the overlay lines up 1:1 with
      // the plot area.
      const canvasOffX = canvas.offsetLeft;
      const canvasOffY = canvas.offsetTop;
      const onMove = (ev) => {
        const xNow = ev.clientX - rect.left;
        const dx = Math.abs(xNow - x0);
        if (!dragged && dx < DRAG_THRESHOLD_PX) return;
        dragged = true;
        tooltip.hidden = true;

        const a = Math.min(x0, xNow);
        const b = Math.max(x0, xNow);
        const aClamped = Math.max(padL, Math.min(padL + plotW, a));
        const bClamped = Math.max(padL, Math.min(padL + plotW, b));
        overlay.hidden = false;
        overlay.style.left = (canvasOffX + aClamped) + 'px';
        overlay.style.top = (canvasOffY + padT) + 'px';
        overlay.style.width = Math.max(1, bClamped - aClamped) + 'px';
        overlay.style.height = plotH + 'px';
        // NOTE: the selection is purely visual during the drag — we
        // do NOT touch `this._window` / `_applyWindowOnly` / render
        // here. The histogram, scrubber, grid, columns and sus panes
        // all stay in their pre-drag state until pointer-up, which
        // keeps even 100k-row datasets buttery while the user picks
        // a range.
        //
        // One exception: we DO live-update the range banner so the
        // analyst can read the pending [from → to · duration] while
        // still dragging. This is a pure text update (O(1)) — no
        // render pass — so it stays in the same budget as the
        // overlay rect it mirrors.
        const previewLo = xToMs(aClamped);
        const previewHi = xToMs(bClamped);
        if (Number.isFinite(previewLo) && Number.isFinite(previewHi) && previewHi > previewLo) {
          this._renderRangeBanner({ min: previewLo, max: previewHi, preview: true });
        }
      };

      const onUp = (ev) => {
        canvas.removeEventListener('pointermove', onMove);
        canvas.removeEventListener('pointerup', onUp);
        canvas.removeEventListener('pointercancel', onUp);
        try { canvas.releasePointerCapture(e.pointerId); } catch (_) { /* noop */ }
        this._windowDragging = false;

        if (!dragged) {
          // Click, not drag → treat as bucket drill.
          overlay.hidden = true;
          this._onChartClick(canvas, data, ev.clientX);
          return;
        }

        // Snap to bucket boundaries.
        const xEnd = ev.clientX - rect.left;
        const a = Math.min(x0, xEnd);
        const b = Math.max(x0, xEnd);
        let lo = snap(xToMs(Math.max(padL, Math.min(padL + plotW, a))), true);
        let hi = snap(xToMs(Math.max(padL, Math.min(padL + plotW, b))), false);
        if (ev.shiftKey && startWindow) {
          lo = Math.min(lo, startWindow.min);
          hi = Math.max(hi, startWindow.max);
        }
        if (this._dataRange) {
          lo = Math.max(this._dataRange.min, lo);
          hi = Math.min(this._dataRange.max, hi);
        }
        if (!(Number.isFinite(lo) && Number.isFinite(hi) && hi > lo)) {
          overlay.hidden = true;
          return;
        }
        overlay.hidden = true;
        this._window = { min: lo, max: hi };
        this._applyWindowOnly();
        // Commit: full render pass now that the selection is final.
        this._scheduleRender(['scrubber', 'chart', 'chips', 'grid', 'columns']);
      };
      canvas.addEventListener('pointermove', onMove);
      canvas.addEventListener('pointerup', onUp);
      canvas.addEventListener('pointercancel', onUp);
    });
  }

  _onChartHover(e, data, tooltip) {
    if (!data) { tooltip.hidden = true; return; }
    const canvas = e.currentTarget;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const { padL, plotW, padT, plotH, barW, bucketMs } = data.layout;
    if (x < padL || x > padL + plotW || y < padT || y > padT + plotH) { tooltip.hidden = true; return; }
    const b = Math.min(data.bucketCount - 1, Math.max(0, Math.floor((x - padL) / barW)));
    const lo = data.viewLo + b * bucketMs;
    const hi = lo + bucketMs;
    const k = data.stackKeys ? data.stackKeys.length : 1;
    let total = 0;
    const parts = [];
    for (let j = 0; j < k; j++) {
      const c = data.buckets[b * k + j];
      if (c) {
        total += c;
        const label = data.stackKeys ? data.stackKeys[j] : 'Count';
        const sm = this._stackColorMap;
        let dotColor = TIMELINE_STACK_PALETTE[j % TIMELINE_STACK_PALETTE.length];
        if (sm && data.stackKeys) {
          const ci = sm.get(data.stackKeys[j]);
          if (ci !== undefined) dotColor = TIMELINE_STACK_PALETTE[ci % TIMELINE_STACK_PALETTE.length];
        }
        parts.push(`<span class="tl-chart-tooltip-dot" style="background:${dotColor}"></span>${_tlEsc(label)}: <b>${c.toLocaleString()}</b>`);
      }
    }
    // 🚩 Suspicious row — only present on the main chart (see the
    // `role === 'main'` gate in `_computeChartData` for `susBuckets`).
    let susLine = '';
    if (data.susBuckets && data.susBuckets[b]) {
      susLine = `<div class="tl-chart-tooltip-sus">🚩 Suspicious: <b>${data.susBuckets[b].toLocaleString()}</b></div>`;
    }
    tooltip.innerHTML = `<div class="tl-chart-tooltip-h">${_tlEsc(_tlFormatFullUtc(lo, this._timeIsNumeric))} → ${_tlEsc(_tlFormatFullUtc(hi, this._timeIsNumeric))}</div>
      <div class="tl-chart-tooltip-total">${total.toLocaleString()} events</div>
      ${parts.length ? '<div class="tl-chart-tooltip-rows">' + parts.join('<br>') + '</div>' : ''}
      ${susLine}`;
    tooltip.hidden = false;
    const tW = tooltip.offsetWidth || 160;
    const tH = tooltip.offsetHeight || 40;
    let left = x + 12, top = y + 12;
    if (left + tW > canvas.clientWidth) left = x - tW - 12;
    if (top + tH > canvas.clientHeight) top = y - tH - 12;
    tooltip.style.left = left + 'px';
    tooltip.style.top = top + 'px';
  }

  _handleLegendClick(e) {
    const chip = e.target.closest('.tl-legend-chip');
    if (!chip || this._stackCol == null) return;
    const key = chip.dataset.key;
    const op = e.shiftKey ? 'ne' : 'eq';
    this._addOrToggleChip(this._stackCol, key, { op });
  }
  _handleLegendDbl(e) {
    const chip = e.target.closest('.tl-legend-chip');
    if (!chip || this._stackCol == null) return;
    const key = chip.dataset.key;
    // "Only this" → replace all chips on this column with a single eq.
    this._addOrToggleChip(this._stackCol, key, { op: 'eq', replace: true });
  }
  _handleLegendContext(e) {
    const chip = e.target.closest('.tl-legend-chip');
    if (!chip || this._stackCol == null) return;
    e.preventDefault();
    const key = chip.dataset.key;
    this._openRowContextMenu(e, this._stackCol, key);
  }

  // ── Range banner ────────────────────────────────────────────────────────
  // Shown above the query bar whenever a time window is active. Hidden
  // (`.hidden`) when `_window == null` so the analyst gets an empty,
  // unobstructed view in the neutral state. Piggybacks on the 'chips'
  // task in `_scheduleRender` since every site that mutates `_window`
  // already schedules 'chips'.
  _renderRangeBanner(overrides) {
    const el = this._els && this._els.rangeBanner;
    if (!el) return;
    // During a live drag-preview the banner is fed a transient
    // `{min,max,preview:true}` span so the analyst can see the range
    // they're about to commit. `preview` adds a `--preview` modifier
    // so the banner visually reads "not committed yet".
    const win = overrides || this._window;
    if (!win) {
      el.classList.add('hidden');
      el.classList.remove('tl-range-banner--preview');
      return;
    }
    el.classList.remove('hidden');
    el.classList.toggle('tl-range-banner--preview', !!(overrides && overrides.preview));
    const lo = _tlFormatFullUtc(win.min, this._timeIsNumeric);
    const hi = _tlFormatFullUtc(win.max, this._timeIsNumeric);
    if (this._els.rangeBannerText) {
      // Append a human-friendly duration ("30m", "2h 15m", …) to the
      // end of the readout. Skipped in numeric-axis mode — `_tlFormatDuration`
      // treats its argument as milliseconds, so a duration of "year 2024"
      // on a numeric axis has no sensible spelling.
      let suffix = '';
      if (!this._timeIsNumeric) {
        const dur = _tlFormatDuration(win.max - win.min);
        if (dur) suffix = ' · ' + dur;
      } else {
        const span = win.max - win.min;
        if (Number.isFinite(span)) suffix = ' · Δ ' + _tlFormatNumericTick(span, span);
      }
      this._els.rangeBannerText.textContent = `${lo} → ${hi}${suffix}`;
    }
  }


  // ── Chips ────────────────────────────────────────────────────────────────
  // The chips strip hosts the "＋ Add Suspicious Indicator" button —
  // anchored on the left via flex-shrink:0 so it never moves — and zero-
  // or-more 🚩 sus chips that flow to its right from `_susMarks`
  // (persisted by column name, tint-only — never filter rows). The
  // active time window got promoted to the banner above; row-filter
  // chips live in the query bar. So this strip is pure sus state.
  _renderChips() {
    const el = this._els.chips;
    el.innerHTML = '';

    // "＋ Add Sus" button — always rendered FIRST so sus chips flow to
    // its right and the button's left position stays stable as chips
    // are added / removed.
    const addBtn = document.createElement('button');
    addBtn.type = 'button';
    addBtn.className = 'tl-chip tl-chip-add';
    addBtn.innerHTML = `<span class="tl-chip-plus">＋</span><span class="tl-chip-val">Add Suspicious Indicator</span>`;
    addBtn.title = 'Flag a value as 🚩 suspicious (tint-only, does not filter rows)';
    addBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this._openAddSusPopover(addBtn);
    });
    el.appendChild(addBtn);

    // Render sus marks from `_susMarks` (resolved to live colIdx). Note
    // that we iterate `_susMarks` directly (not the resolved list) so
    // the ⊗ handler can splice the PERSISTED index and keep the
    // by-name persistence stable. Marks whose column is currently
    // missing (extracted col removed etc.) stay persisted but don't
    // render — `_susMarksResolved()` drops them.
    for (let i = 0; i < this._susMarks.length; i++) {

      const m = this._susMarks[i];
      // "Any column" marks render with a synthetic "Any" column label and
      // always bind to the persisted index (they don't resolve to a live
      // colIdx). Column-scoped marks whose column has disappeared (e.g.
      // extracted col removed) stay persisted but don't render — mirrors
      // `_susMarksResolved()`.
      const isAny = m.any === true;
      if (!isAny) {
        const colIdx = this.columns.indexOf(m.colName);
        if (colIdx < 0) continue;
      }
      const chip = document.createElement('span');
      chip.className = 'tl-chip tl-chip-sus' + (isAny ? ' tl-chip-sus-any' : '');
      const label = isAny ? '＊ Any' : m.colName;
      chip.innerHTML = `<span class="tl-chip-col">${_tlEsc(label)}</span><span class="tl-chip-op">🚩</span><span class="tl-chip-val">${_tlEsc(m.val)}</span><button class="tl-chip-x" title="Remove">⊗</button>`;
      // Capture the mark *object* (not its index) so rapid double-removal
      // can't splice the wrong entry after an earlier splice shifted indices.
      const markRef = m;
      chip.querySelector('.tl-chip-x').addEventListener('click', () => {
        const idx = this._susMarks.indexOf(markRef);
        if (idx < 0) return;
        this._susMarks.splice(idx, 1);
        TimelineView._saveSusMarksFor(this._fileKey, this._susMarks);
        this._rebuildSusBitmap();
        this._recomputeFilter();
        this._scheduleRender(['chart', 'chips', 'grid', 'columns']);
      });
      el.appendChild(chip);
    }

    // Clear-all button — only when there's at least one sus mark. Mirrors
    // the per-chip ⊗ teardown (wipe _susMarks, persist, rebuild bitmap,
    // recompute filter, re-render). margin-left:auto pushes it to the
    // far right of the chips strip.
    if (this._susMarks.length > 0) {
      const clearBtn = document.createElement('button');
      clearBtn.type = 'button';
      clearBtn.className = 'tl-chips-clear';
      clearBtn.innerHTML = '✕ Clear';
      clearBtn.title = 'Remove all suspicious indicators';
      clearBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this._susMarks = [];
        TimelineView._saveSusMarksFor(this._fileKey, []);
        this._rebuildSusBitmap();
        this._recomputeFilter();
        this._scheduleRender(['chart', 'chips', 'grid', 'columns']);
      });
      el.appendChild(clearBtn);
    }
  }


  // ── "＋ Add Sus" popover ─────────────────────────────────────────────────

  // Compact form anchored on the Add-Sus button. Pick a column + value
  // and push onto `_susMarks` (persisted by column name). Sus marks
  // tint rows but do NOT filter — use the query bar for row filtering.
  _openAddSusPopover(anchor) {
    this._closePopover();
    const menu = document.createElement('div');
    menu.className = 'tl-popover tl-add-sus';

    // Build column <select>. An "Any column" sentinel (value -1) is
    // offered first and selected by default — this is the most common
    // sus pattern ("flag this value wherever it appears") and having it
    // sit at the top avoids the footgun where a user flags "admin" under
    // the first real column and then can't see why a later row with
    // admin in a different column is tinted.
    const cols = this.columns;
    let colOptions = '<option value="-1" selected>＊ Any column</option>';
    for (let i = 0; i < cols.length; i++) {
      const name = cols[i] || `(col ${i + 1})`;
      const prefix = (i >= this._baseColumns.length) ? '⨯ ' : '';
      colOptions += `<option value="${i}">${_tlEsc(prefix + name)}</option>`;
    }

    menu.innerHTML = `
      <div class="tl-add-filter-form">
        <label class="tl-field">
          <span class="tl-field-label">Column</span>
          <select class="tl-field-select" data-f="col">${colOptions}</select>
        </label>
        <label class="tl-field tl-field-wide">
          <span class="tl-field-label">Value</span>
           <input type="text" class="tl-field-select" data-f="val" spellcheck="false" placeholder="text to flag (substring, case-insensitive)">
        </label>
        <div class="tl-add-filter-hint">🚩 Sus marks tint rows red. Use <code>is:sus</code> in the query bar to filter to only sus rows.</div>
        <div class="tl-add-filter-actions">
          <button class="tl-tb-btn" type="button" data-act="cancel">Cancel</button>
          <button class="tl-tb-btn tl-tb-btn-primary" type="button" data-act="add">Mark suspicious</button>
        </div>
      </div>
    `;

    const colSel = menu.querySelector('[data-f="col"]');
    const valEl = menu.querySelector('[data-f="val"]');

    const submit = () => {
      const colIdx = parseInt(colSel.value, 10);
      const val = valEl.value;
      if (val === '') { valEl.focus(); return; }
      // colIdx === -1 is the "Any column" sentinel. Everything else must
      // resolve to a live column index.
      if (colIdx === -1) {
        // Toggle an "Any column" mark. Keyed on { any:true, val } so
        // repeated adds of the same value de-dupe as a removal.
        // Values are lower-cased for case-insensitive substring matching.
        const valStr = String(val).toLowerCase();
        const ix = this._susMarks.findIndex(m => m.any === true && m.val.toLowerCase() === valStr);
        if (ix >= 0) this._susMarks.splice(ix, 1);
        else this._susMarks.push({ any: true, colName: null, val: valStr });
        TimelineView._saveSusMarksFor(this._fileKey, this._susMarks);
        this._rebuildSusBitmap();
        this._recomputeFilter();
        this._scheduleRender(['chart', 'chips', 'grid', 'columns']);
        this._closePopover();
        return;
      }
      if (!Number.isFinite(colIdx) || colIdx < 0 || colIdx >= cols.length) return;
      this._addOrToggleChip(colIdx, val, { op: 'sus' });
      this._closePopover();
    };
    menu.querySelector('[data-act="add"]').addEventListener('click', submit);
    menu.querySelector('[data-act="cancel"]').addEventListener('click', () => this._closePopover());
    valEl.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); submit(); }
      else if (e.key === 'Escape') { e.preventDefault(); this._closePopover(); }
    });

    // Anchor below the button.
    const rect = anchor.getBoundingClientRect();
    this._positionFloating(menu, rect.left, rect.bottom + 4);
    document.body.appendChild(menu);
    this._openPopover = menu;
    setTimeout(() => valEl.focus(), 0);
  }


  // ── Grid ─────────────────────────────────────────────────────────────────
  _renderGrid() {
    this._renderGridInto(this._els.gridWrap, this._filteredIdx || new Uint32Array(0), 'main');
  }

  /** Invalidate the cached sorted-index and rowsConcat arrays. Called
   *  whenever `_timeMs` content changes (via `_parseAllTimestamps`) so
   *  the next `_renderGridInto` re-sorts from scratch. */
  _invalidateGridCache() {
    this._sortedFullIdx = null;
    this._cachedRowsConcat = null;
    this._cachedRowsConcatExtLen = -1;
  }

  _renderGridInto(wrap, idx, role) {
    // ── Pre-sort idx by timestamp ──────────────────────────────────────
    // Sort the filtered index array by the pre-parsed _timeMs values so
    // rowsConcat is handed to GridViewer in chronological order. This
    // avoids GridViewer's _sortByColumn temporal path which would re-parse
    // every cell via Date.parse() inside the sort comparator — O(n log n)
    // Date.parse calls that cost 2-4s for 1M rows. The numerical sort
    // below is O(n log n) float comparisons on an already-parsed
    // Float64Array, which completes in ~200ms for 1M rows.
    //
    // When the index covers the full dataset (no query active) and the
    // time column hasn't changed, reuse the previously sorted index and
    // the pre-built rowsConcat array. This turns filter-clear from
    // O(n log n) re-sort + O(n) array build into O(1) cache hits.
    const timeCol = this._timeCol;
    const timeMs = this._timeMs;
    const isFullDataset = idx.length === this.rows.length;
    if (timeCol != null && timeMs && idx.length > 1) {
      if (isFullDataset && this._sortedFullIdx &&
        this._sortedFullIdx.length === idx.length) {
        // Cache hit — reuse the previously sorted full-dataset index.
        idx = this._sortedFullIdx;
      } else {
        // Work on a mutable copy so we don't disturb _chipFilteredIdx.
        const sorted = new Uint32Array(idx);
        sorted.sort((a, b) => {
          const ta = timeMs[a], tb = timeMs[b];
          const af = Number.isFinite(ta), bf = Number.isFinite(tb);
          if (!af && !bf) return a - b;
          if (!af) return 1;
          if (!bf) return -1;
          return (ta - tb) || (a - b);
        });
        idx = sorted;
        // Cache the sorted order for the full (unfiltered) dataset so
        // subsequent filter-clears skip the O(n log n) re-sort.
        if (isFullDataset) this._sortedFullIdx = sorted;
      }
      // Update _filteredIdx so click-handlers, scroll-cursor and
      // right-click menus resolve virtual → original-row correctly.
      if (role === 'main') this._filteredIdx = idx;
    }

    // When no extracted columns exist, reference the base row arrays
    // directly instead of calling _buildRowConcat per row. For 500K rows
    // this eliminates 500K function calls + the per-row length check.
    //
    // For the full-dataset case, cache the result so filter-clears skip
    // the O(n) rebuild. Invalidated when extracted columns change (the
    // grid is destroyed and recreated in that case anyway) or when
    // _invalidateGridCache() is called.
    const hasExtracted = this._extractedCols.length > 0;
    const extLen = this._extractedCols.length;
    const cacheHit = isFullDataset && this._cachedRowsConcat &&
      this._cachedRowsConcat.length === idx.length &&
      this._cachedRowsConcatExtLen === extLen;
    let rowsConcat;
    if (cacheHit) {
      rowsConcat = this._cachedRowsConcat;
    } else {
      rowsConcat = new Array(idx.length);
      if (hasExtracted) {
        for (let i = 0; i < idx.length; i++) rowsConcat[i] = this._buildRowConcat(idx[i]);
      } else {
        const rows = this.rows;
        for (let i = 0; i < idx.length; i++) rowsConcat[i] = rows[idx[i]] || [];
      }
      if (isFullDataset) {
        this._cachedRowsConcat = rowsConcat;
        this._cachedRowsConcatExtLen = extLen;
      }
    }
    const sus = this._susBitmap;
    const origIdx = idx;

    // Capture stack-color state for the rowClass closure.  `colorMap`
    // maps a cell value → palette index (0–8); when present, every grid
    // row receives a `tl-stack-N` class that tints its background with
    // the matching legend color.
    const stackCol = this._stackCol;
    const colorMap = this._stackColorMap;   // Map<value, paletteIdx> | null
    const self = this;

    const rowClass = (rowIdx) => {
      const orig = origIdx[rowIdx];
      let cls = (sus && sus[orig]) ? 'tl-row-sus' : '';
      if (colorMap && stackCol != null) {
        const val = self._cellAt(orig, stackCol);
        const ci = colorMap.get(val);
        if (ci !== undefined) cls += (cls ? ' ' : '') + 'tl-stack-' + (ci % TIMELINE_STACK_PALETTE.length);
      }
      return cls;
    };

    // Color the text in the stack column's cells to match the legend.
    const cellClass = (dataIdx, colIdx) => {
      if (colorMap && colIdx === stackCol) {
        const orig = origIdx[dataIdx];
        const val = self._cellAt(orig, stackCol);
        const ci = colorMap.get(val);
        if (ci !== undefined) return 'tl-stack-text-' + (ci % TIMELINE_STACK_PALETTE.length);
      }
      return null;
    };

    // Drawer highlight: tint the specific key/val pairs that triggered a
    // suspicious mark strongly, and dim-tint the rest of a sus row's
    // fields so the viewer can locate the offending value at a glance.
    // Resolved marks are captured at construction and rebuilt when sus
    // state changes (grid is torn down + recreated).
    const susResolved = this._susMarksResolved();
    const susAny = susResolved.length > 0;
    const detailCellClass = !susAny ? null : (dataIdx, colIdx, _val) => {
      const orig = origIdx[dataIdx];
      if (!sus || !sus[orig]) return null;
      const cellLc = self._cellAt(orig, colIdx).toLowerCase();
      for (let s = 0; s < susResolved.length; s++) {
        const spec = susResolved[s];
        if (spec.any) {
          if (cellLc.includes(spec.val)) return 'tl-sus-cell';
        } else if (spec.colIdx === colIdx) {
          if (cellLc.includes(spec.val)) return 'tl-sus-cell';
        }
      }
      return 'tl-sus-row-cell';
    };


    // role is always 'main' now (the 🚩 Suspicious section is gone); the
    // parameter is kept on the method signature because `_tlRole` is still
    // stamped on the GridViewer instance further down — other callers
    // (scroll → cursor resolver) read it.
    // EVTX Event-ID annotation hooks — only wired when the Timeline is
    // hosting an EVTX file (identified by the `_evtxFindings` side-
    // channel). Looks up `<channel>:<eid>` (then bare `<eid>`) in the
    // EvtxEventIds registry and renders:
    //   - a multi-line `td.title` tooltip on every Event-ID body cell
    //     (Row grid view)
    //   - a summary pill + MITRE-technique pill next to the Event-ID
    //     value in the drawer pane
    // Disabled on non-EVTX timeline files (CSV / TSV / JSON) — returning
    // null from the hooks short-circuits the augment path.
    const Reg = (typeof window !== 'undefined' && window.EvtxEventIds) || null;
    const evtxEidCol = (this._evtxFindings && Reg)
      ? this._baseColumns.indexOf(EVTX_COLUMNS.EVENT_ID)
      : -1;
    const evtxChannelCol = (evtxEidCol >= 0)
      ? this._baseColumns.indexOf(EVTX_COLUMNS.CHANNEL)
      : -1;
    const evtxLookupRec = (dataIdx) => {
      if (evtxEidCol < 0) return null;
      // dataIdx here is an index into `rowsConcat`, which is the
      // GridViewer's source. `origIdx` maps back to the un-sorted
      // original row offset where applicable, but `rowsConcat` rows
      // are self-contained — the cell at colIdx is already the value
      // the user sees. Read directly.
      const row = rowsConcat[dataIdx];
      if (!row) return null;
      const eid = row[evtxEidCol];
      if (!eid) return null;
      const ch = evtxChannelCol >= 0 ? row[evtxChannelCol] : '';
      try { return Reg.lookup(eid, ch); } catch (_) { return null; }
    };
    const cellTitle = (evtxEidCol >= 0) ? (dataIdx, colIdx /*, raw */) => {
      if (colIdx !== evtxEidCol) return null;
      const rec = evtxLookupRec(dataIdx);
      if (!rec) return null;
      try { return Reg.formatTooltip(rec); } catch (_) { return null; }
    } : null;
    const detailAugment = (evtxEidCol >= 0) ? (dataIdx, colIdx, value, ctx) => {
      if (colIdx !== evtxEidCol) return;
      const valEl = ctx && ctx.valEl;
      if (!valEl) return;
      // Resolve the row's eid + channel and emit pills via the shared
      // helper so the drawer / Top-values card / Detections table all
      // render identical chips. Drawer additionally promotes the
      // tooltip onto `valEl` itself.
      const row = rowsConcat[dataIdx];
      if (!row) return;
      const eid = row[evtxEidCol];
      if (!eid) return;
      const ch = evtxChannelCol >= 0 ? row[evtxChannelCol] : '';
      try {
        const rec = Reg.lookup(eid, ch);
        if (rec) valEl.title = Reg.formatTooltip(rec);
      } catch (_) { /* ignore */ }
      const frag = this._evtxEidPillsFor(eid, ch);
      if (frag.childNodes.length) valEl.appendChild(frag);
    } : null;
    // Visible-cell variant — fires per visible row in the EVTX grid
    // body and appends the same Microsoft summary + ATT&CK pills next
    // to the bare Event-ID number, so the analyst gets the at-a-glance
    // context without having to hover for the tooltip or open the
    // drawer. Mirrors the Detections-table EID column. Uses the
    // GridViewer `cellAugment` hook (sibling to `detailAugment`); the
    // `.tl-evtx-eid-pill` single-line / max-width / ellipsis CSS keeps
    // the cell on a single 28 px row regardless of summary length.
    const cellAugment = (evtxEidCol >= 0) ? (dataIdx, colIdx, _raw, td) => {
      if (colIdx !== evtxEidCol) return;
      const row = rowsConcat[dataIdx];
      if (!row) return;
      const eid = row[evtxEidCol];
      if (eid === '' || eid == null) return;
      const ch = evtxChannelCol >= 0 ? row[evtxChannelCol] : '';
      const frag = this._evtxEidPillsFor(eid, ch);
      // Wrap the bare EID number in a fixed-width, tabular-numeric span
      // so the trailing `.tl-evtx-eid-pill` summary chip starts at the
      // same X coordinate on every row regardless of digit count
      // (3-digit `624` next to 5-digit `12345` would otherwise make
      // the pill column visually jagged and hard to scan). The wrapper
      // is also what `.grid-cell:has(.tl-evtx-eid-num)` keys off to
      // override GridViewer's numeric-column right-alignment, so it
      // must be applied *unconditionally* — including rows whose EID
      // has no descriptive pill in `_evtxEidPillsFor` — otherwise those
      // cells would still right-align and the column would look ragged.
      const num = document.createElement('span');
      num.className = 'tl-evtx-eid-num';
      num.textContent = td.textContent;
      td.textContent = '';
      td.appendChild(num);
      if (frag.childNodes.length) td.appendChild(frag);
    } : null;


    const existing = (role === 'main' ? this._grid : null);
    if (!existing) {
      const viewer = new GridViewer({
        columns: this.columns,
        rows: rowsConcat,
        className: 'tl-grid-inner csv-view',
        hideFilterBar: true,
        infoText: '',
        timeColumn: -1,
        rowClass,
        cellClass,
        cellTitle,
        cellAugment,
        detailAugment,
        detailCellClass,

        // In Timeline Mode the embedded grid's built-in "Use as timeline"
        // and "Stack timeline by this column" column-header actions must
        // drive the outer Timeline histogram + stack selects instead of
        // promoting GridViewer's internal `.grid-timeline` strip.
        onUseAsTimeline: role === 'main' ? (colIdx) => this._setTimeColFromGrid(colIdx) : null,
        onStackTimelineBy: role === 'main' ? (colIdx) => this._setStackColFromGrid(colIdx) : null,
        // Left-click on a grid header → open the Excel-style filter
        // popover (same as the Top-Lists ▾ button). Right-click is
        // wired separately via `contextmenu` to open the sort/hide menu.
        onHeaderClick: role === 'main' ? (colIdx, anchor) => this._openColumnMenu(colIdx, anchor) : null,
        // Drawer → key right-click menu → promote the JSON leaf to a
        // virtual (extracted) column and optionally chain a filter chip.
        // `colIdx` is the column index in the GridViewer's column array,
        // which matches `_baseColumns` + `_extractedCols` — we only allow
        // picks rooted at base columns (the JSON source cell).
        //
        // `action` ∈ 'extract' | 'include' | 'exclude' (leaves only — the
        // JsonTree context menu is not wired on composite keys).
        //   - extract        — just add the extracted column
        //   - include/exclude — add the column AND push an eq/ne chip
        //     against the leaf's current value
        onCellPick: (dataIdx, colIdx, path, leafValue, action) => {
          void dataIdx;
          try {
            // Empty-path sentinel — grid-drawer plain-text field right-click
            // ("Include value" / "Exclude value" on an ordinary non-JSON
            // cell). Do NOT synthesise a virtual extracted column; push
            // the chip directly against the source column. Extract is
            // intentionally not supported here — the source column
            // already exists so extraction would produce a duplicate.
            if (!path || path.length === 0) {
              if (colIdx < 0 || colIdx >= this.columns.length) return;
              const act = action || 'include';
              if (act !== 'include' && act !== 'exclude') return;
              const chipOp = act === 'exclude' ? 'ne' : 'eq';
              const chipVal = (leafValue == null) ? ''
                : (typeof leafValue === 'object' ? JSON.stringify(leafValue) : String(leafValue));
              this._addOrToggleChip(colIdx, chipVal, { op: chipOp });
              if (this._app && typeof this._app._toast === 'function') {
                const verb = act === 'include' ? 'Include' : 'Exclude';
                const colName = this.columns[colIdx] || `col${colIdx}`;
                this._app._toast(`${verb} filter added: ${colName}`, 'info');
              }
              return;
            }

            // Non-empty path — JSON-leaf pick. Extract a virtual column
            // (and chain a chip for include/exclude). Only allowed on
            // base columns — picks against an already-extracted column
            // are intentionally ignored to avoid recursion.
            if (colIdx >= this._baseColumns.length) return;
            const label = _tlJsonPathLabel(path);
            const fullLabel = `${this._baseColumns[colIdx] || 'col' + colIdx}.${label}`;
            const newColIdx = this._addJsonExtractedCol(colIdx, path, fullLabel);
            const act = action || 'extract';
            if (newColIdx >= 0 && act !== 'extract') {
              let chipVal = '';
              let chipOp = 'eq';
              if (act === 'include') {
                chipOp = 'eq';
                chipVal = (leafValue == null) ? ''
                  : (typeof leafValue === 'object' ? JSON.stringify(leafValue) : String(leafValue));
              } else if (act === 'exclude') {
                chipOp = 'ne';
                chipVal = (leafValue == null) ? ''
                  : (typeof leafValue === 'object' ? JSON.stringify(leafValue) : String(leafValue));
              }
              this._addOrToggleChip(newColIdx, chipVal, { op: chipOp });
            }
            if (this._app && typeof this._app._toast === 'function') {
              const verb = act === 'extract' ? 'Added column'
                : act === 'include' ? 'Added column + include filter'
                  : act === 'exclude' ? 'Added column + exclude filter'
                    : 'Added column';
              this._app._toast(`${verb}: ${fullLabel}`, 'info');
            }
          } catch (err) { console.error('onCellPick failed', err); }
        },

      });

      // Stamp the role on the viewer so the scroll handler below (and any
      // future per-role logic) can look up the live filtered-index array
      // on `this` rather than relying on a stale closure — `origIdx` here
      // is the snapshot that was passed in for the first render; later
      // re-renders call `existing.setRows()` with a fresh filtered set, so
      // any virtual-row → original-row mapping has to be re-read each time
      // from `this._filteredIdx` / `this._susFilteredIdx`.
      viewer._tlRole = role;
      wrap.innerHTML = '';
      wrap.appendChild(viewer.root());

      // Left-click a row → move the red-line cursor on the histogram to
      // this row's timestamp. Uses the virtual row index from data-idx
      // (populated by GridViewer) to look up the original dataIdx.
      viewer.root().addEventListener('click', (e) => {
        const rowEl = e.target.closest('.grid-row');
        if (!rowEl) return;
        // Don't eat clicks on interactive children (links, buttons, etc.).
        if (e.target.closest('button, a, input, select, textarea')) return;
        const virtualIdx = parseInt(rowEl.dataset.idx || '-1', 10);
        if (!Number.isFinite(virtualIdx) || virtualIdx < 0) return;
        const curIdx = (viewer._tlRole === 'main') ? this._filteredIdx : this._susFilteredIdx;
        const origRow = curIdx ? curIdx[virtualIdx] : origIdx[virtualIdx];
        this._setCursorDataIdx(origRow);
      });

      // Scroll → move the red-line cursor on the histogram so it tracks
      // where the analyst is reading, not just the last row they clicked.
      // rAF-throttled to stay cheap; the CSS `transition: left 140ms
      // ease-out` on `.tl-chart-cursor` provides the same visual
      // smoothening as `.grid-timeline-cursor` in non-timeline mode.
      let scrollRaf = 0;
      viewer._scr.addEventListener('scroll', () => {
        if (scrollRaf) return;
        scrollRaf = requestAnimationFrame(() => {
          scrollRaf = 0;
          this._updateCursorFromGridScroll(viewer);
        });
      }, { passive: true });


      // Wire right-click on rows.
      viewer.root().addEventListener('contextmenu', (e) => {
        // Right-click on a header cell → open GridViewer's sort / hide /
        // copy menu (the same surface that left-click used to open before
        // the gesture swap). Left-click now opens the Excel-style filter
        // popover via the `onHeaderClick` callback above. Close any
        // Timeline popover first so two menus can't overlap.
        const headCell = e.target.closest('.grid-header-cell.grid-header-clickable');
        if (headCell) {
          const colAttr = parseInt(headCell.dataset.col || '-1', 10);
          if (Number.isFinite(colAttr) && colAttr >= 0) {
            e.preventDefault();
            this._closePopover();
            viewer._openHeaderMenu(colAttr, headCell);
          }
          return;
        }
        const cell = e.target.closest('.grid-cell');
        if (!cell) return;
        const rowEl = cell.closest('.grid-row');
        if (!rowEl) return;
        const virtualIdx = parseInt(rowEl.dataset.idx || '-1', 10);
        if (!Number.isFinite(virtualIdx) || virtualIdx < 0) return;
        // grid-viewer uses data-idx = dataIdx within the viewer's rows array;
        // that's the position in `rowsConcat`, NOT the original index.
        // IMPORTANT: resolve the virtual → original-row mapping against the
        // LIVE filtered-index on `this`, not the `origIdx` captured in this
        // listener's closure at first-render time. The contextmenu listener
        // is wired once, but `_renderGridInto` re-uses the same GridViewer
        // and swaps rows via `existing.setRows(rowsConcat)` whenever a
        // filter is applied — `origIdx` becomes stale the moment the query
        // bar narrows the grid, which previously made the right-click
        // menu's `Include / Exclude "<value>"` labels (and the resulting
        // chips) point at the wrong cell. Mirrors the same pattern the
        // left-click handler above already uses.
        const curIdx = (viewer._tlRole === 'main') ? this._filteredIdx : this._susFilteredIdx;
        const origRow = curIdx ? curIdx[virtualIdx] : origIdx[virtualIdx];
        // Determine which column was clicked. GridViewer stamps `data-col`
        // on every body cell with the REAL column index (survives hidden /
        // pinned / reordered columns). Prefer that; fall back to positional
        // math only if the attribute is missing on some legacy path.
        //
        // Positional math (`cells.indexOf(cell) - 1`) is fundamentally wrong
        // whenever any column is hidden — GridViewer skips hidden columns in
        // the DOM, so sibling position no longer maps to column index and
        // the right-click menu ends up operating on the wrong column.
        let colIdx = -1;
        const colAttr = cell.dataset ? cell.dataset.col : null;
        if (colAttr != null && colAttr !== '') {
          const n = parseInt(colAttr, 10);
          if (Number.isFinite(n)) colIdx = n;
        }
        if (colIdx < 0) {
          // Defensive fallback — only hit if a non-GridViewer row somehow
          // landed inside the timeline grid.
          const cells = Array.from(rowEl.querySelectorAll('.grid-cell'));
          const cellIdx = cells.indexOf(cell);
          if (cellIdx <= 0) return;
          colIdx = cellIdx - 1;   // row-num is 0
        }
        if (colIdx < 0 || colIdx >= this.columns.length) return;
        const val = this._cellAt(origRow, colIdx);
        e.preventDefault();
        this._openRowContextMenu(e, colIdx, val, { origRow });
      });
      if (role === 'main') {
        this._grid = viewer;
        // Rows are already pre-sorted by _timeMs above — stamp the sort
        // spec + identity order directly instead of calling _sortByColumn
        // which would re-parse every cell via Date.parse(). This saves
        // 2-4s for 1M rows.
        if (this._timeCol != null) {
          const n = rowsConcat.length;
          const idxs = new Array(n);
          for (let i = 0; i < n; i++) idxs[i] = i;
          viewer._sortSpec = { colIdx: this._timeCol, dir: 'asc' };
          viewer._sortOrder = idxs;
          viewer._buildHeaderCells();
          viewer._forceFullRender();
        }
      }
    } else {
      // Preserve columns in case new extracted columns were added.
      existing.columns = this.columns;
      existing._rowClassFn = rowClass;
      existing._cellClassFn = cellClass;
      // Re-bind the EVTX EID `cellAugment` closure too — it captures the
      // current `rowsConcat` reference, so without re-assignment the hook
      // would keep appending pills based on a stale row array after a
      // filter / sort re-render.
      existing._cellAugmentFn = cellAugment;
      // Rows are pre-sorted by _timeMs — skip the expensive re-sort in
      // setRows that would call _sortByColumn → Date.parse per comparison.
      existing.setRows(rowsConcat, null, null, { preSorted: true });
    }
  }

  // Build a concatenated row (base + extracted cell values) for GridViewer.
  _buildRowConcat(dataIdx) {
    const base = this.rows[dataIdx] || [];
    if (!this._extractedCols.length) return base;
    const out = new Array(this._baseColumns.length + this._extractedCols.length);
    for (let c = 0; c < this._baseColumns.length; c++) out[c] = base[c] == null ? '' : base[c];
    for (let e = 0; e < this._extractedCols.length; e++) {
      out[this._baseColumns.length + e] = this._extractedCols[e].values[dataIdx] || '';
    }
    return out;
  }

  // ── Column top-values cards ──────────────────────────────────────────────
  _renderColumns() {
    this._paintColumnCards(this._els.cols, this._colStats, 'main');
  }

  // ── Detections (EVTX-only) ───────────────────────────────────────────────
  // Renders Sigma-style rule hits pulled from `this._evtxFindings.externalRefs`
  // (where `type === IOC.PATTERN`). Each row is: severity dot / description /
  // count / target Event ID. Clicking a row pushes an `eq` chip on the Event
  // ID column (colIdx 1 for the default EVTX schema) so the analyst can pivot
  // to just the rows that triggered the detection.
  // ── Detections + Entities (EVTX-only) ────────────────────────────────────
  // Methods `_renderDetections`, `_renderEntities`, `_collectEntities`,
  // `_pivotOnEntity`, `_pivotAnyContainsToggle` are attached to
  // TimelineView.prototype by `timeline-detections.js`.


  _paintColumnCards(host, stats, role) {

    host.innerHTML = '';
    let rowHeight = 22;
    const cols = this.columns;
    // EVTX-only: identify the Event-ID column index so the renderer
    // below can append a `.tl-evtx-eid-pill` (Microsoft summary) +
    // optional `.tl-evtx-mitre-pill` (ATT&CK) to each top-values row.
    // Resolves to -1 on CSV / TSV / SQLite — pill rendering is skipped.
    const tlEvtxEidCol = (this._evtxFindings && this._baseColumns)
      ? this._baseColumns.indexOf(EVTX_COLUMNS.EVENT_ID)
      : -1;


    // Build column-index iteration order: if a saved drag-order exists,
    // honour it; columns absent from the saved array (new columns added
    // after the order was persisted) are appended at the end so they
    // surface automatically.
    const _indices = [];
    const _savedOrder = this._cardOrder;
    if (_savedOrder && _savedOrder.length) {
      const _nameToIdx = new Map();
      for (let i = 0; i < cols.length; i++) {
        if (i === this._timeCol) continue;
        _nameToIdx.set(cols[i] || `(col ${i + 1})`, i);
      }
      const _used = new Set();
      for (const nm of _savedOrder) {
        if (_nameToIdx.has(nm) && !_used.has(nm)) {
          _indices.push(_nameToIdx.get(nm));
          _used.add(nm);
        }
      }
      for (let i = 0; i < cols.length; i++) {
        if (i === this._timeCol) continue;
        const n = cols[i] || `(col ${i + 1})`;
        if (!_used.has(n)) _indices.push(i);
      }
    } else {
      for (let i = 0; i < cols.length; i++) {
        if (i === this._timeCol) continue;
        _indices.push(i);
      }
    }

    // Pin sorting — move pinned columns to the front of _indices while
    // preserving relative order among pinned and unpinned groups.
    if (this._pinnedCols && this._pinnedCols.length) {
      const pinnedSet = new Set();
      const nameOf = (ci) => cols[ci] || `(col ${ci + 1})`;
      for (const pn of this._pinnedCols) pinnedSet.add(pn);
      const pinned = _indices.filter(ci => pinnedSet.has(nameOf(ci)));
      const unpinned = _indices.filter(ci => !pinnedSet.has(nameOf(ci)));
      _indices.length = 0;
      for (const ci of pinned) _indices.push(ci);
      for (const ci of unpinned) _indices.push(ci);
    }

    for (let _ci = 0; _ci < _indices.length; _ci++) {
      const c = _indices[_ci];
      const s = (stats && stats[c]) || { total: 0, distinct: 0, values: [] };

      const card = document.createElement('div');
      card.className = 'tl-col-card';
      if (this._isExtractedCol(c)) {
        card.classList.add('tl-col-card-extracted');
        const e = this._extractedColFor(c);
        if (e && e.kind) card.classList.add('tl-col-card-kind-' + e.kind);
      }
      card.dataset.colIdx = String(c);
      card.dataset.role = role;

      const colName = cols[c] || `(col ${c + 1})`;
      const savedSpan = this._cardSpanFor(colName);
      if (savedSpan > 1) card.style.gridColumn = `span ${savedSpan}`;

      const isPinned = this._pinnedCols && this._pinnedCols.includes(colName);
      if (isPinned) card.classList.add('tl-col-card-pinned');

      const head = document.createElement('div');
      head.className = 'tl-col-head';
      const extractedMark = this._isExtractedCol(c) ? '<span class="tl-col-badge" title="Extracted column">ƒx</span>' : '';
      // Per-card sort mode — cycles count-desc → count-asc → a-z → z-a on
      // each click of the hidden `.tl-col-sort` button. Alt-click resets
      // to the default (count-desc). Stored on the DOM node so it survives
      // re-paints within the same card — but every card starts fresh on
      // rebuild (stats refresh), which matches user expectations for a
      // transient view-state toggle.
      const sortLabels = { 'count-desc': '# ↓', 'count-asc': '# ↑', 'az': 'A→Z', 'za': 'Z→A' };
      // Header layout:
      //   • Always-visible centred name + muted distinct-count "subscript".
      //   • Hover-only button cluster (pin / copy-visible-values / sort)
      //     anchored to the top-right corner — absolutely positioned so
      //     the centred name never shifts when hover reveals them.
      //   • Always-visible column-menu button (⋮) top-left so it's always
      //     reachable without hover.
      head.innerHTML = `
        <button class="tl-col-menu" type="button" title="Column menu">⋮</button>
        <div class="tl-col-head-actions">
          <button class="tl-col-pin${isPinned ? ' tl-col-pin-active' : ''}" type="button" title="${isPinned ? 'Unpin card' : 'Pin card to top-left'}">📌</button>
          <button class="tl-col-copy" type="button" title="Copy visible values to clipboard">📋</button>
          <button class="tl-col-sort" type="button" title="Cycle sort (count ↓ → count ↑ → A→Z → Z→A · Alt-click to reset)" data-mode="count-desc">${sortLabels['count-desc']}</button>
        </div>
        <div class="tl-col-head-title">
          ${extractedMark}
          <span class="tl-col-name" title="${_tlEsc(colName)}">${_tlEsc(colName)}</span>
          <span class="tl-col-sub" title="distinct values">${s.distinct.toLocaleString()} unique</span>
        </div>
      `;
      card.appendChild(head);

      // Per-card search row — filters the distinct values displayed in
      // this card without touching any global chips / query. Empty by
      // default; hiding behind ". tl-col-card:hover" in CSS would make
      // it invisible to keyboard-only users so we leave it always visible
      // but kept visually subtle.
      const searchRow = document.createElement('div');
      searchRow.className = 'tl-col-search-wrap';
      searchRow.innerHTML = `<input type="text" class="tl-col-search" placeholder="filter values…" spellcheck="false" autocomplete="off">`;
      card.appendChild(searchRow);
      const searchInput = searchRow.querySelector('.tl-col-search');

      const viewport = document.createElement('div');
      viewport.className = 'tl-col-viewport';
      const sizer = document.createElement('div');
      sizer.className = 'tl-col-sizer';
      viewport.appendChild(sizer);
      card.appendChild(viewport);

      // Local filtered + sorted list (computed from `s.values` — which is
      // already sorted count-desc by `_computeColumnStats`).
      let displayValues = s.values;
      const applySortAndFilter = () => {
        const mode = card._sortMode || 'count-desc';
        const q = (card._searchText || '').toLowerCase();
        let arr = s.values;
        if (q) arr = arr.filter(([val]) => String(val).toLowerCase().includes(q));
        if (mode !== 'count-desc') {
          arr = arr.slice();
          if (mode === 'count-asc') arr.sort((a, b) => a[1] - b[1]);
          else if (mode === 'az') arr.sort((a, b) => String(a[0]).localeCompare(String(b[0])));
          else if (mode === 'za') arr.sort((a, b) => String(b[0]).localeCompare(String(a[0])));
        }
        displayValues = arr;
        sizer.style.height = (displayValues.length * rowHeight) + 'px';
        // Reset scroll if the visible set shrank below the current offset.
        if (viewport.scrollTop > Math.max(0, sizer.offsetHeight - viewport.clientHeight)) {
          viewport.scrollTop = 0;
        }
      };
      applySortAndFilter();

      const renderRows = () => {
        const scroll = viewport.scrollTop;
        const vpH = viewport.clientHeight || 300;
        const buffer = 4;
        const start = Math.max(0, Math.floor(scroll / rowHeight) - buffer);
        const end = Math.min(displayValues.length, Math.ceil((scroll + vpH) / rowHeight) + buffer);
        while (sizer.firstChild) sizer.removeChild(sizer.firstChild);
        // Top value is always derived from `s.values[0]` (the global
        // unfiltered max) so the bar widths stay comparable across cards
        // rather than rescaling on every keystroke.
        const topVal = s.values.length ? s.values[0][1] : 1;
        const susVals = this._susValsForCol(c);
        if (!displayValues.length) {
          const empty = document.createElement('div');
          empty.className = 'tl-col-empty';
          empty.textContent = card._searchText ? 'No matches' : '—';
          sizer.appendChild(empty);
          return;
        }
        // Stack-color state: when this card is the stack column, tint each
        // value's bar and prepend a legend-colored swatch dot.
        const isStackCard = (c === this._stackCol && this._stackColorMap);

        for (let i = start; i < end; i++) {
          const [val, count] = displayValues[i];
          const row = document.createElement('div');
          row.className = 'tl-col-row';
          if (susVals && susVals.has(val)) row.classList.add('tl-col-row-sus');
          if (this._pendingCtrlSelect && this._pendingCtrlSelect.colIdx === c && this._pendingCtrlSelect.values.has(val)) row.classList.add('tl-col-row-selected');
          row.style.top = (i * rowHeight) + 'px';
          row.dataset.value = val;
          const pct = topVal > 0 ? Math.max(2, Math.round((count / topVal) * 100)) : 0;

          // Resolve stack-palette color for this value (if applicable).
          let barStyle = `width:${pct}%`;
          let swatchHtml = '';
          if (isStackCard) {
            const ci = this._stackColorMap.get(val);
            if (ci !== undefined) {
              const hex = TIMELINE_STACK_PALETTE[ci % TIMELINE_STACK_PALETTE.length];
              barStyle += `;background:${hex}20`;
              swatchHtml = `<span class="tl-col-swatch" style="background:${hex}"></span>`;
            }
          }

          row.innerHTML = `
            <span class="tl-col-bar" style="${barStyle}"></span>
            ${swatchHtml}<span class="tl-col-val" title="${_tlEsc(val)}">${_tlEsc(val === '' ? '(empty)' : val)}</span>
            <span class="tl-col-count">${count.toLocaleString()}</span>`;
          // EVTX-only: insert Microsoft summary + ATT&CK pills BETWEEN the
          // value and the count so each row reads as
          // `4624 (Successful logon) … 77` instead of putting the count
          // between the EID and its description. `tlEvtxEidCol` is -1
          // for non-EVTX schemas, suppressing the lookup.
          if (c === tlEvtxEidCol && val !== '' && this._evtxEidPillsFor) {
            const pillFrag = this._evtxEidPillsFor(val, '');
            if (pillFrag && pillFrag.childNodes.length) {
              const countEl = row.querySelector('.tl-col-count');
              if (countEl) row.insertBefore(pillFrag, countEl);
              else row.appendChild(pillFrag);
            }
          }
          sizer.appendChild(row);
        }
      };
      renderRows();

      // Measure actual row height after DOM insertion — the CSS `height: 22px`
      // can render at a fractional pixel size depending on zoom / DPI / browser
      // rounding, which accumulates into a visible spacer gap at the bottom of
      // the list (the same bug fixed in csv-renderer.js commit 11b56aa).
      requestAnimationFrame(() => {
        const sample = sizer.querySelector('.tl-col-row');
        if (sample && sample.offsetHeight > 0 && sample.offsetHeight !== rowHeight) {
          rowHeight = sample.offsetHeight;
          applySortAndFilter();
        }
        renderRows();
      });

      // Wire per-card search — debounced input → re-sort + re-render.
      let searchTimer = 0;
      searchInput.addEventListener('input', () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => {
          card._searchText = searchInput.value;
          applySortAndFilter();
          renderRows();
        }, 80);
      });
      searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && searchInput.value) {
          e.preventDefault();
          searchInput.value = '';
          card._searchText = '';
          applySortAndFilter();
          renderRows();
        }
      });

      // Wire the sort-cycle button — single click cycles forward, Alt-click
      // resets. Updates both the button label and the per-card state.
      const sortBtn = head.querySelector('.tl-col-sort');
      sortBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const order = ['count-desc', 'count-asc', 'az', 'za'];
        if (e.altKey) {
          card._sortMode = 'count-desc';
        } else {
          const cur = card._sortMode || 'count-desc';
          const ix = order.indexOf(cur);
          card._sortMode = order[(ix + 1) % order.length];
        }
        sortBtn.dataset.mode = card._sortMode;
        sortBtn.textContent = sortLabels[card._sortMode];
        applySortAndFilter();
        renderRows();
      });


      viewport.addEventListener('scroll', () => {
        if (card._rowsRaf) return;
        card._rowsRaf = requestAnimationFrame(() => { card._rowsRaf = null; renderRows(); });
      });

      // Click = add eq chip; shift-click = ne chip; ctrl/meta = accumulate multi-select
      sizer.addEventListener('click', (e) => {
        const row = e.target.closest('.tl-col-row');
        if (!row) return;
        const val = row.dataset.value;
        if (e.ctrlKey || e.metaKey) {
          this._accumulateCtrlSelect(c, val, row);
          return;
        }
        this._clearCtrlSelect();
        this._addOrToggleChip(c, val, { op: e.shiftKey ? 'ne' : 'eq' });
      });
      // Right-click = context menu
      sizer.addEventListener('contextmenu', (e) => {
        const row = e.target.closest('.tl-col-row');
        if (!row) return;
        e.preventDefault();
        this._openRowContextMenu(e, c, row.dataset.value);
      });

      // Column-menu button
      head.querySelector('.tl-col-menu').addEventListener('click', (e) => {
        e.stopPropagation();
        this._openColumnMenu(c, head);
      });

      // Pin button
      head.querySelector('.tl-col-pin').addEventListener('click', (e) => {
        e.stopPropagation();
        this._togglePinCol(colName);
      });

      // Copy-visible-values button — copies the currently displayed values
      // (respecting per-card search filter + active sort order) as
      // newline-separated text. Stops propagation so the drag-to-reorder
      // on the head doesn't trigger.
      head.querySelector('.tl-col-copy').addEventListener('click', (e) => {
        e.stopPropagation();
        const txt = displayValues.map(([val]) => String(val == null ? '' : val)).join('\n');
        this._copyToClipboard(txt);
        if (this._app && typeof this._app._toast === 'function') {
          this._app._toast(`Copied ${displayValues.length.toLocaleString()} value${displayValues.length === 1 ? '' : 's'} from "${colName}"`, 'info');
        }
      });

      // Ctrl/Meta-click anywhere on the card head (but not the ▾ menu
      // button) = hide this column on the underlying grids. Mirrors the
      // Ctrl+Click hide on GridViewer column headers so the user has a
      // consistent "quickly hide this column" gesture regardless of which
      // surface they're looking at. Re-hide on the OTHER grid too so the
      // Suspicious sub-grid stays in sync with the main grid.
      head.addEventListener('click', (e) => {
        if (!(e.ctrlKey || e.metaKey)) return;
        if (e.target.closest('.tl-col-menu')) return;
        if (e.target.closest('.tl-col-pin')) return;
        e.preventDefault();
        e.stopPropagation();
        if (this._grid && typeof this._grid._toggleHideColumn === 'function') {
          try { this._grid._toggleHideColumn(c); } catch (_) { /* noop */ }
        }
        if (this._app && typeof this._app._toast === 'function') {
          this._app._toast(`Hid column "${colName}" (use the chip in the grid's filter bar to unhide)`, 'info');
        }
      });
      // Add the hint into the column-name tooltip so users can discover the gesture.
      const nameEl = head.querySelector('.tl-col-name');
      if (nameEl) nameEl.title = `${colName} · Ctrl+Click card header to hide this column in the grid · Drag header to reorder`;

      // --- Drag-to-reorder card headers ---
      head.draggable = true;
      head.addEventListener('dragstart', (e) => {
        if (e.target.closest('button')) { e.preventDefault(); return; }
        card.classList.add('tl-col-drag-source');
        document.body.classList.add('tl-col-dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', colName);
      });
      head.addEventListener('dragend', () => {
        card.classList.remove('tl-col-drag-source');
        document.body.classList.remove('tl-col-dragging');
        host.querySelectorAll('.tl-col-drag-over-before,.tl-col-drag-over-after').forEach(
          el => el.classList.remove('tl-col-drag-over-before', 'tl-col-drag-over-after')
        );
      });
      card.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        const rect = card.getBoundingClientRect();
        const midX = rect.left + rect.width / 2;
        card.classList.toggle('tl-col-drag-over-before', e.clientX < midX);
        card.classList.toggle('tl-col-drag-over-after', e.clientX >= midX);
      });
      card.addEventListener('dragleave', () => {
        card.classList.remove('tl-col-drag-over-before', 'tl-col-drag-over-after');
      });
      card.addEventListener('drop', (e) => {
        e.preventDefault();
        card.classList.remove('tl-col-drag-over-before', 'tl-col-drag-over-after');
        const srcName = e.dataTransfer.getData('text/plain');
        if (!srcName || srcName === colName) return;
        const srcCard = [...host.children].find(el => {
          const idx = el.dataset.colIdx;
          return idx != null && (this.columns[+idx] || `(col ${+idx + 1})`) === srcName;
        });
        if (!srcCard) return;
        const rect = card.getBoundingClientRect();
        const midX = rect.left + rect.width / 2;
        if (e.clientX < midX) host.insertBefore(srcCard, card);
        else host.insertBefore(srcCard, card.nextSibling);
        this._commitCardOrder(host);
      });

      // Resize handles — left and right edges
      const resizerR = document.createElement('div');
      resizerR.className = 'tl-col-resize';
      card.appendChild(resizerR);
      resizerR.addEventListener('pointerdown', (e) => this._installCardResize(e, card, colName, 'right'));

      const resizerL = document.createElement('div');
      resizerL.className = 'tl-col-resize-left';
      card.appendChild(resizerL);
      resizerL.addEventListener('pointerdown', (e) => this._installCardResize(e, card, colName, 'left'));

      host.appendChild(card);
    }
  }

  // Read the current DOM order of cards in the host container and persist
  // it so the next render honours the user's chosen arrangement.
  _commitCardOrder(host) {
    const order = [];
    for (const el of host.children) {
      const idx = el.dataset.colIdx;
      if (idx == null) continue;
      const name = this.columns[+idx] || `(col ${+idx + 1})`;
      order.push(name);
    }
    this._cardOrder = order;
    TimelineView._saveCardOrderFor(this._fileKey, order);
  }

  // Sus values keyed by column — for highlighting top-values cards.
  // Sourced from `_susMarks` (resolved to live colIdx): sus is a tint-
  // only parallel data model, not a query-bar clause.
  _susValsForCol(colIdx) {
    if (!this._susAny) return null;
    const m = new Set();
    const resolved = this._susMarksResolved();
    for (const r of resolved) {
      // `any`-type marks apply to every column; column-scoped marks
      // match only their own colIdx.
      if (r.any === true || r.colIdx === colIdx) m.add(String(r.val));
    }
    return m;
  }

  // Per-column card width is expressed as a `grid-column: span N` override so
  // it cooperates with the `.tl-columns` auto-fill grid (plain `width: Npx`
  // silently fights the grid's implicit track width). We compute the current
  // track width from the host's box + the `--tl-card-min-w` preset, then
  // snap the drag to integer column spans.
  _cardSpanFor(colName) {
    const v = this._cardWidths[colName];
    if (v == null) return 1;
    if (typeof v === 'number') {
      // Legacy px value saved by an earlier build — translate to a span
      // based on the current card-size preset.
      const trackW = TIMELINE_CARD_SIZES[this._cardSize] || TIMELINE_CARD_SIZES.M;
      return Math.max(1, Math.min(4, Math.round(v / trackW)));
    }
    if (typeof v === 'object' && Number.isFinite(v.span)) {
      return Math.max(1, Math.min(6, v.span | 0));
    }
    return 1;
  }

  // Persist a card's column-span override. Deletes the key when span
  // falls back to the default (1) so the persistence layer stays tidy.

  _cardSizeSave(colName, span) {
    if (span <= 1) delete this._cardWidths[colName];
    else this._cardWidths[colName] = { span };
    TimelineView._saveCardWidthsFor(this._fileKey, this._cardWidths);
  }

  // Horizontal resize — `dir` is `'left'` or `'right'`. Both directions
  // snap to the same integer grid-column span; the difference is only
  // how the mouse delta maps to width growth.
  _installCardResize(e, card, colName, dir) {
    e.preventDefault();
    document.body.classList.add('tl-col-resizing');
    const host = card.parentElement;   // .tl-columns or .tl-entities-wrap
    const startX = e.clientX;
    const startSpan = this._cardSpanFor(colName);
    const entityMinW = colName.startsWith('entity:') ? 260 : undefined;
    const { trackW, cols, gap } = this._columnsGridGeometry(host, entityMinW);
    const startW = startSpan * trackW + (startSpan - 1) * gap;
    const sign = dir === 'left' ? -1 : 1;
    const apply = (span) => {
      const clamped = Math.max(1, Math.min(cols, span));
      if (clamped <= 1) card.style.gridColumn = '';
      else card.style.gridColumn = `span ${clamped}`;
      card.dataset.span = String(clamped);
    };
    const onMove = (ev) => {
      const w = Math.max(trackW, Math.round(startW + sign * (ev.clientX - startX)));
      const span = Math.round(w / (trackW + gap));
      apply(span);
    };
    const onUp = () => {
      document.body.classList.remove('tl-col-resizing');
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      const span = parseInt(card.dataset.span || String(startSpan), 10);
      this._cardSizeSave(colName, span);
    };
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
  }

  // Resolve the `.tl-columns` grid geometry — how many tracks fit and each
  // track's effective pixel width. Mirrors the CSS
  //   grid-template-columns: repeat(auto-fill, minmax(var(--tl-card-min-w), 1fr));
  // `minWOverride` lets entity cards pass their own fixed min-width (260)
  // instead of the S/M/L preset.
  _columnsGridGeometry(host, minWOverride) {
    const style = getComputedStyle(host);
    const pad = (parseFloat(style.paddingLeft) || 0) + (parseFloat(style.paddingRight) || 0);
    const gap = parseFloat(style.columnGap || style.gap) || 10;
    const hostW = host.getBoundingClientRect().width - pad;
    const minW = minWOverride || TIMELINE_CARD_SIZES[this._cardSize] || TIMELINE_CARD_SIZES.M;
    const cols = Math.max(1, Math.floor((hostW + gap) / (minW + gap)));
    const trackW = (hostW - gap * (cols - 1)) / cols;
    return { trackW, cols, gap };
  }

  // ── AST edit helpers ─────────────────────────────────────────────────────
  // The query bar is the single source of truth for row filtering, so every
  // click-pivot (right-click Include / Exclude / Only, column-card click,
  // column-menu Apply, pivot drill-down, detection drill, legend click)
  // must MUTATE THE QUERY STRING rather than push onto a parallel chip
  // list. These helpers do the plumbing: parse `_queryStr` into an AST,
  // manipulate the top-level AND clauses, serialize back with live column
  // names (`_tlFormatQuery` uses `this.columns` so extracted columns
  // round-trip) and push into the editor + `_applyQueryString`. Every
  // helper funnels through `_queryCommitClauses` so exactly one parse /
  // render cycle happens per user action.
  _queryCurrentAst() {
    const s = (this._queryStr || '').trim();
    if (!s) return { k: 'empty' };
    try {
      return _tlParseQuery(_tlTokenize(s), () => this.columns);
    } catch (_) {
      // Mid-edit parse error — treat as empty so callers can still add
      // clauses (serializer will produce a valid string overwriting the
      // broken one).
      return { k: 'empty' };
    }
  }
  _queryTopLevelClauses(ast) {
    if (!ast || ast.k === 'empty') return [];
    if (ast.k === 'and') return ast.children.slice();
    return [ast];
  }
  _queryClausesToAst(clauses) {
    if (!clauses.length) return { k: 'empty' };
    if (clauses.length === 1) return clauses[0];
    return { k: 'and', children: clauses };
  }
  _queryCommitClauses(clauses) {
    const ast = this._queryClausesToAst(clauses);
    const s = _tlFormatQuery(ast, this.columns);
    if (this._queryEditor) this._queryEditor.setValue(s);
    this._applyQueryString(s);
  }
  // Does a single top-level clause reference `colIdx`?
  _clauseTargetsCol(c, colIdx) {
    if (!c) return false;
    if (c.k === 'pred' || c.k === 'in') return c.colIdx === colIdx;
    return false;
  }

  // Append a clause to the top-level AND. `opts.dedupe` skips duplicates.
  _queryAddClause(node, opts) {
    opts = opts || {};
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst());
    if (opts.dedupe) {
      const key = JSON.stringify(node);
      for (const c of clauses) if (JSON.stringify(c) === key) return;
    }
    clauses.push(node);
    this._queryCommitClauses(clauses);
  }

  // Strip any top-level clause that would directly contradict an incoming
  // `col <op> val` assertion from the click-pivot path (right-click
  // Include / Exclude, column-card click, etc.) so the resulting query
  // never ends up with something like `col = v AND col != v` (0 rows,
  // useless to the analyst). Only `eq` / `ne` / `in` clauses on the same
  // column are considered — everything else is left alone. `in` lists
  // have just the contradicting value stripped and collapse to a bare
  // `pred` when a single value remains, matching the collapse rules used
  // by `_queryToggleEqClause`.
  //
  // `forOp` is the op the CALLER is about to append:
  //   'eq' → strip clauses that forbid `valStr` (ne + positive-sense
  //           absence inside a NOT-IN list)
  //   'ne' → strip clauses that require `valStr` (eq + presence inside
  //           an IN list)
  _queryDropContradictions(clauses, colIdx, valStr, forOp) {
    const stripOp = forOp === 'eq' ? 'ne' : 'eq';
    const stripNeg = forOp === 'eq';   // eq → strip NOT-IN; ne → strip IN
    for (let i = clauses.length - 1; i >= 0; i--) {
      const c = clauses[i];
      if (!c || c.colIdx !== colIdx) continue;
      if (c.k === 'pred' && c.op === stripOp && String(c.val) === valStr) {
        clauses.splice(i, 1);
        continue;
      }
      if (c.k === 'in' && !!c.neg === stripNeg) {
        const ix = c.vals.indexOf(valStr);
        if (ix < 0) continue;
        const newVals = c.vals.slice(); newVals.splice(ix, 1);
        if (newVals.length === 0) {
          clauses.splice(i, 1);
        } else if (newVals.length === 1) {
          clauses[i] = { k: 'pred', colIdx, op: c.neg ? 'ne' : 'eq', val: newVals[0] };
        } else {
          clauses[i] = { k: 'in', colIdx, vals: newVals, neg: !!c.neg };
        }
      }
    }
  }

  // Toggle an eq match against `col = val`. Handles both `pred(eq)` and
  // positive `in` nodes: if the value is found inside an `in` list, it's
  // removed (collapsing to a bare eq if one value remains, dropping the
  // clause entirely if empty). If not present, folds away any opposing
  // `ne` / `NOT IN` on the same `(col, val)` pair (so Include-after-
  // Exclude clears the exclude rather than producing an unsatisfiable
  // `col = v AND col != v`) and appends a bare eq clause.
  _queryToggleEqClause(colIdx, val) {
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst());
    const valStr = String(val);
    for (let i = 0; i < clauses.length; i++) {
      const c = clauses[i];
      if (c.k === 'pred' && c.op === 'eq' && c.colIdx === colIdx && String(c.val) === valStr) {
        clauses.splice(i, 1);
        this._queryCommitClauses(clauses);
        return;
      }
      if (c.k === 'in' && !c.neg && c.colIdx === colIdx) {
        const ix = c.vals.indexOf(valStr);
        if (ix >= 0) {
          const newVals = c.vals.slice(); newVals.splice(ix, 1);
          if (newVals.length === 0) clauses.splice(i, 1);
          else if (newVals.length === 1) clauses[i] = { k: 'pred', colIdx, op: 'eq', val: newVals[0] };
          else clauses[i] = { k: 'in', colIdx, vals: newVals, neg: false };
          this._queryCommitClauses(clauses);
          return;
        }
      }
    }
    this._queryDropContradictions(clauses, colIdx, valStr, 'eq');
    clauses.push({ k: 'pred', colIdx, op: 'eq', val: valStr });
    this._queryCommitClauses(clauses);
  }

  // Toggle a ne match against `col != val`. Symmetric with the eq path
  // above but never folds into an `in` list (DSL has no `NOT IN` toggle).
  // Folds away any opposing `eq` / `IN` on the same `(col, val)` pair so
  // Exclude-after-Include clears the include rather than producing an
  // unsatisfiable `col = v AND col != v`.
  _queryToggleNeClause(colIdx, val) {
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst());
    const valStr = String(val);
    for (let i = 0; i < clauses.length; i++) {
      const c = clauses[i];
      if (c.k === 'pred' && c.op === 'ne' && c.colIdx === colIdx && String(c.val) === valStr) {
        clauses.splice(i, 1);
        this._queryCommitClauses(clauses);
        return;
      }
    }
    this._queryDropContradictions(clauses, colIdx, valStr, 'ne');
    clauses.push({ k: 'pred', colIdx, op: 'ne', val: valStr });
    this._queryCommitClauses(clauses);
  }

  // Strip existing `col : text` contains clauses, then optionally append a
  // new one. Contains is "replace on column" by convention (legacy
  // `_addContainsChipsReplace` semantics).
  _queryReplaceContainsForCol(colIdx, text) {
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst())
      .filter(c => !(c.k === 'pred' && c.op === 'contains' && c.colIdx === colIdx));
    if (text) clauses.push({ k: 'pred', colIdx, op: 'contains', val: String(text) });
    this._queryCommitClauses(clauses);
  }

  // Strip every eq / in / ne clause on this column, then install a fresh
  // set. 0 values → clears; 1 value → `col = v`; ≥ 2 values → `col IN (…)`.
  _queryReplaceEqForCol(colIdx, values) {
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst())
      .filter(c => !(
        (c.k === 'pred' && (c.op === 'eq' || c.op === 'ne') && c.colIdx === colIdx) ||
        (c.k === 'in' && c.colIdx === colIdx)
      ));
    const vals = (values || []).map(v => String(v));
    const seen = new Set();
    const dedup = [];
    for (const v of vals) if (!seen.has(v)) { seen.add(v); dedup.push(v); }
    if (dedup.length === 1) {
      clauses.push({ k: 'pred', colIdx, op: 'eq', val: dedup[0] });
    } else if (dedup.length >= 2) {
      clauses.push({ k: 'in', colIdx, vals: dedup, neg: false });
    }
    this._queryCommitClauses(clauses);
  }

  // Column-menu companion: install a NEGATIVE set (`col != v` / `col NOT IN
  // (…)`). 0 values → clears; 1 value → `col != v`; ≥ 2 → `col NOT IN (…)`.
  // Strips the same family of eq/in/ne clauses as `_queryReplaceEqForCol`
  // so the two helpers are interchangeable end-state producers and the
  // Apply handler can pick whichever representation is shorter.
  _queryReplaceNotInForCol(colIdx, values) {
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst())
      .filter(c => !(
        (c.k === 'pred' && (c.op === 'eq' || c.op === 'ne') && c.colIdx === colIdx) ||
        (c.k === 'in' && c.colIdx === colIdx)
      ));
    const vals = (values || []).map(v => String(v));
    const seen = new Set();
    const dedup = [];
    for (const v of vals) if (!seen.has(v)) { seen.add(v); dedup.push(v); }
    if (dedup.length === 1) {
      clauses.push({ k: 'pred', colIdx, op: 'ne', val: dedup[0] });
    } else if (dedup.length >= 2) {
      clauses.push({ k: 'in', colIdx, vals: dedup, neg: true });
    }
    this._queryCommitClauses(clauses);
  }

  // Strip every top-level clause referencing this column. Used by the
  // column menu's Reset button and by extracted-column removal.
  _queryReplaceAllForCol(colIdx) {
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst())
      .filter(c => !this._clauseTargetsCol(c, colIdx));
    this._queryCommitClauses(clauses);
  }

  // Bulk variant — drop clauses targeting any of `colIndices`.
  _queryRemoveClausesForCols(colIndices) {
    const set = new Set(colIndices);
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst())
      .filter(c => {
        if (c.k === 'pred' || c.k === 'in') return !set.has(c.colIdx);
        return true;
      });
    this._queryCommitClauses(clauses);
  }

  // ── Chip operations ──────────────────────────────────────────────────────
  // Thin dispatch wrappers. `op: 'sus'` writes to `_susMarks` (parallel
  // tint-only data model, persisted by column name). Everything else
  // mutates the query string via the AST-edit helpers above so the query
  // bar stays authoritative for row filtering.
  _addOrToggleChip(colIdx, val, opts) {
    const op = (opts && opts.op) || 'eq';
    const replace = !!(opts && opts.replace);
    if (op === 'sus') {
      const colName = this.columns[colIdx];
      if (colName == null) return;
      const valStr = String(val).toLowerCase();
      const ix = this._susMarks.findIndex(m => m.colName === colName && m.val.toLowerCase() === valStr);
      if (ix >= 0) this._susMarks.splice(ix, 1);
      else this._susMarks.push({ colName, val: valStr });
      TimelineView._saveSusMarksFor(this._fileKey, this._susMarks);
      this._rebuildSusBitmap();
      this._recomputeFilter();
      this._scheduleRender(['chart', 'chips', 'grid', 'columns']);
      return;
    }
    if (op === 'eq') {
      if (replace) this._queryReplaceEqForCol(colIdx, [val]);
      else this._queryToggleEqClause(colIdx, val);
      return;
    }
    if (op === 'ne') {
      this._queryToggleNeClause(colIdx, val);
      return;
    }
    if (op === 'contains') {
      // Contains on an "any" column (colIdx === -1) can't go through the
      // replace-for-col helper (it keys on colIdx). Fall through to the
      // generic add-clause path for the -1 case.
      if (colIdx === -1) {
        this._queryAddClause({ k: 'any', needle: String(val) }, { dedupe: true });
      } else {
        this._queryReplaceContainsForCol(colIdx, val);
      }
      return;
    }
  }

  _addContainsChipsReplace(colIdx, text) {
    this._queryReplaceContainsForCol(colIdx, text);
  }

  _replaceEqChipsForCol(colIdx, values) {
    this._queryReplaceEqForCol(colIdx, values);
  }

  // ── Ctrl+Click multi-select helpers ──────────────────────────────────────
  _accumulateCtrlSelect(colIdx, val, rowEl) {
    if (!this._pendingCtrlSelect || this._pendingCtrlSelect.colIdx !== colIdx) {
      this._clearCtrlSelect();
      this._pendingCtrlSelect = { colIdx, values: new Set(), rows: [] };
    }
    const p = this._pendingCtrlSelect;
    if (p.values.has(val)) {
      p.values.delete(val);
      rowEl.classList.remove('tl-col-row-selected');
    } else {
      p.values.add(val);
      rowEl.classList.add('tl-col-row-selected');
    }
    if (!p.values.size) this._pendingCtrlSelect = null;
  }

  _commitCtrlSelect() {
    if (!this._pendingCtrlSelect || !this._pendingCtrlSelect.values.size) return;
    const { colIdx, values } = this._pendingCtrlSelect;
    this._pendingCtrlSelect = null;
    this._queryReplaceEqForCol(colIdx, Array.from(values));
  }

  _clearCtrlSelect() {
    if (!this._pendingCtrlSelect) return;
    for (const r of this._pendingCtrlSelect.rows) r.classList.remove('tl-col-row-selected');
    const host = this._els && this._els.cols;
    if (host) host.querySelectorAll('.tl-col-row-selected').forEach(el => el.classList.remove('tl-col-row-selected'));
    this._pendingCtrlSelect = null;
  }

  _togglePinCol(colName) {
    const idx = this._pinnedCols.indexOf(colName);
    if (idx >= 0) this._pinnedCols.splice(idx, 1);
    else this._pinnedCols.push(colName);
    TimelineView._savePinnedColsFor(this._fileKey, this._pinnedCols);
    this._scheduleRender(['columns']);
  }


  // ── Chart height drag ────────────────────────────────────────────────────
  // Mirrors the main splitter but targets the `.tl-chart-resize` grab-bar
  // rendered at the bottom edge of the histogram body. Persists the new
  // height to `loupe_timeline_chart_h` on pointer-up.
  _installChartResizeDrag() {
    const root = this._root;
    const handle = this._els.chart.querySelector('.tl-chart-resize');
    if (!handle) return;
    handle.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      document.body.classList.add('tl-chart-resizing');
      const startY = e.clientY;
      const startH = this._chartH;
      const onMove = (ev) => {
        const dy = ev.clientY - startY;
        const h = Math.max(TIMELINE_CHART_MIN_H, Math.min(TIMELINE_CHART_MAX_H, startH + dy));
        this._chartH = h;
        root.style.setProperty('--tl-chart-h', h + 'px');
      };
      const onUp = () => {
        document.body.classList.remove('tl-chart-resizing');
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
        TimelineView._saveChartH(this._chartH);
        // Canvas size changed → redraw.
        this._scheduleRender(['chart']);
      };
      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
    });
  }

  // ── Splitter ─────────────────────────────────────────────────────────────
  _installSplitterDrag() {
    const root = this._root;
    const splitter = this._els.splitter;
    splitter.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      document.body.classList.add('tl-splitter-dragging');
      const startY = e.clientY;
      const startH = this._gridH;
      const onMove = (ev) => {
        const dy = ev.clientY - startY;
        let h = Math.max(TIMELINE_GRID_MIN_H, Math.min(900, startH + dy));
        this._gridH = h;
        root.style.setProperty('--tl-grid-h', h + 'px');
      };
      const onUp = () => {
        document.body.classList.remove('tl-splitter-dragging');
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
        TimelineView._saveGridH(this._gridH);
      };
      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
    });
  }

  // ── GridViewer → outer Timeline select bridges ──────────────────────────
  // Passed as `onUseAsTimeline` / `onStackTimelineBy` into the main-role
  // embedded GridViewer. Returning truthy tells the grid that we handled
  // the action, which suppresses its built-in internal `.grid-timeline`
  // strip promotion. Behaviour mirrors the column-menu Apply handlers in
  // `_openColumnMenu` — keep those two in lockstep.
  _setTimeColFromGrid(colIdx) {
    if (!Number.isInteger(colIdx) || colIdx < 0 || colIdx >= this.columns.length) return true;
    this._timeCol = colIdx;
    if (this._els.timeColSelect) this._els.timeColSelect.value = String(colIdx);
    this._parseAllTimestamps();
    this._dataRange = this._computeDataRange();
    this._window = null;
    this._recomputeFilter();
    this._scheduleRender(['chart', 'scrubber', 'grid', 'columns', 'chips']);
    return true;
  }
  _setStackColFromGrid(colIdx) {
    if (!Number.isInteger(colIdx) || colIdx < 0 || colIdx >= this.columns.length) return true;
    this._stackCol = colIdx;
    this._buildStableStackColorMap();
    if (this._els.stackColSelect) this._els.stackColSelect.value = String(colIdx);
    this._scheduleRender(['chart', 'grid', 'columns']);
    return true;
  }

  // ── Right-click row context menu ─────────────────────────────────────────
  _openRowContextMenu(e, colIdx, val, opts) {
    opts = opts || {};
    this._closePopover();
    const menu = document.createElement('div');
    menu.className = 'tl-popover tl-rowmenu';
    const items = [];
    items.push({ label: `✓ Include "${this._ellipsis(val, 60)}"`, act: () => this._addOrToggleChip(colIdx, val, { op: 'eq' }) });
    items.push({ label: `✕ Exclude "${this._ellipsis(val, 60)}"`, act: () => this._addOrToggleChip(colIdx, val, { op: 'ne' }) });
    // "Only …" is a shortcut for "clear this column's filters, then include X".
    // Hide it when the column has no existing non-sus chips, because in that
    // state it is functionally identical to the ✓ Include item above (the
    // `replace: true` wipe step has nothing to remove). `sus` chips are
    // preserved by `_addOrToggleChip` either way, so they don't count here.
    // Query-bar is the single source of truth for column filters; walk the
    // current AST's top-level clauses and ask if any of them target `colIdx`.
    // Sus marks live in `_susMarks` (not the query) so they can never show up
    // here, which matches the old `c.op !== 'sus'` carve-out.
    const _hasOtherChipsOnCol = this._queryTopLevelClauses(this._queryCurrentAst())
      .some(c => this._clauseTargetsCol(c, colIdx));
    if (_hasOtherChipsOnCol) {
      items.push({
        label: `↺ Only "${this._ellipsis(val, 60)}" on this column`,
        act: () => this._addOrToggleChip(colIdx, val, { op: 'eq', replace: true }),
      });
    }
    items.push({ sep: true });
    items.push({ label: `🚩 Mark suspicious`, act: () => this._addOrToggleChip(colIdx, val, { op: 'sus' }) });
    // Focus-around-this-event pills — only when the row has a parseable
    // timestamp. Shown on EVERY column (not just the time column) so the
    // analyst can pivot without having to first click the time cell.
    const origRow = opts.origRow;
    const rowTime = (origRow != null && this._timeMs) ? this._timeMs[origRow] : null;
    if (origRow != null && Number.isFinite(rowTime) && this._dataRange) {
      items.push({ sep: true });
      items.push({ label: `🕒 Focus around this event`, labelOnly: true });
      items.push({
        pills: [
          { label: '±10s', ms: 10_000 },
          { label: '±1m', ms: 60_000 },
          { label: '±5m', ms: 300_000 },
          { label: '±10m', ms: 600_000 },
          { label: '±30m', ms: 1_800_000 },
        ], origRow
      });
    }
    items.push({ sep: true });
    items.push({ label: `ƒx Extract values`, act: () => this._openExtractionDialog(colIdx, 'manual') });

    items.push({ sep: true });
    // Auto-pivot — pick a sensible Rows × Cols × Count triple based on the
    // clicked column + the current stack column (if any) and expand the
    // pivot section. See `_autoPivotFromColumn` for the heuristic (which
    // already prefers the current stack column as Cols when one is set, so
    // a single entry is sufficient here).
    items.push({ label: `🧮 Auto pivot on this column`, act: () => this._autoPivotFromColumn(colIdx) });
    items.push({ sep: true });
    items.push({ label: `Copy value`, act: () => this._copyToClipboard(val) });


    for (const it of items) {
      if (it.sep) {
        const sep = document.createElement('div');
        sep.className = 'tl-popover-sep';
        menu.appendChild(sep);
      } else if (it.labelOnly) {
        const lbl = document.createElement('div');
        lbl.className = 'tl-popover-label';
        lbl.textContent = it.label;
        menu.appendChild(lbl);
      } else if (it.pills) {
        const row = document.createElement('div');
        row.className = 'tl-popover-pills';
        for (const p of it.pills) {
          const pb = document.createElement('button');
          pb.type = 'button';
          pb.className = 'tl-popover-pill';
          pb.textContent = p.label;
          const ms = p.ms;
          const oRow = it.origRow;
          pb.addEventListener('click', () => {
            try {
              const t = this._timeMs[oRow];
              if (!Number.isFinite(t) || !this._dataRange) return;
              const lo = Math.max(this._dataRange.min, t - ms);
              const hi = Math.min(this._dataRange.max, t + ms);
              this._window = { min: lo, max: hi };
              this._applyWindowOnly();
              this._scheduleRender(['scrubber', 'chart', 'chips', 'grid', 'columns']);
            } finally { this._closePopover(); }
          });
          row.appendChild(pb);
        }
        menu.appendChild(row);
      } else {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'tl-popover-item';
        b.textContent = it.label;
        b.addEventListener('click', () => { try { it.act(); } finally { this._closePopover(); } });
        menu.appendChild(b);
      }
    }
    this._positionFloating(menu, e.clientX, e.clientY);
    document.body.appendChild(menu);
    this._openPopover = menu;
  }

  _ellipsis(s, max) {
    const str = String(s == null ? '' : s);
    return str.length > max ? str.slice(0, max) + '…' : str;
  }

  _copyToClipboard(text) {
    try { navigator.clipboard.writeText(String(text)); } catch (_) { /* noop */ }
  }

  _positionFloating(el, x, y) {
    el.style.position = 'fixed';
    el.style.left = x + 'px';
    el.style.top = y + 'px';
    el.style.zIndex = '9999';
    // After append we might nudge back into the viewport.
    requestAnimationFrame(() => {
      const w = el.offsetWidth, h = el.offsetHeight;
      const vw = window.innerWidth, vh = window.innerHeight;
      if (x + w > vw) el.style.left = Math.max(8, vw - w - 8) + 'px';
      if (y + h > vh) el.style.top = Math.max(8, vh - h - 8) + 'px';
    });
  }

  _closePopover() {
    if (this._openPopover && this._openPopover.parentNode) {
      this._openPopover.parentNode.removeChild(this._openPopover);
    }
    this._openPopover = null;
  }

  // ── Column menu (Excel-style) ────────────────────────────────────────────
  _openColumnMenu(colIdx, anchor) {
    // Toggle: if the menu is already open for this exact column, close it.
    if (this._openPopover && this._openPopover.dataset.colIdx === String(colIdx)) {
      this._closePopover();
      return;
    }
    this._closePopover();
    const menu = document.createElement('div');
    menu.dataset.colIdx = colIdx;
    menu.className = 'tl-popover tl-colmenu';
    const name = this.columns[colIdx] || `(col ${colIdx + 1})`;
    // Pre-fill the Contains input + Values checkboxes from the current
    // query AST rather than a separate chip list — the query bar is now
    // the single source of truth. For `existingContains`, match the
    // first top-level `contains` predicate on this column. For
    // `existingEqs`, collect the union of (positive) `eq` predicate
    // values AND the values inside any positive `IN (…)` clause on
    // this column — the Apply handler below emits either an eq or an
    // `IN` list depending on cardinality, so both round-trip cleanly.
    const _astClauses = this._queryTopLevelClauses(this._queryCurrentAst());
    const _containsClause = _astClauses.find(c => c.k === 'pred' && c.op === 'contains' && c.colIdx === colIdx);
    const existingContains = _containsClause ? { val: _containsClause.val } : null;
    // Positive membership: `col = v` or `col IN (…)` — these narrow to an
    // explicit whitelist, so checkboxes are painted *unchecked* except for
    // members of `eqSet`.
    const existingEqs = [];
    // Negative membership: `col != v` or `col NOT IN (…)` — these narrow by
    // exclusion, so the menu starts *all-checked* with members of `neSet`
    // unchecked. This is the round-trip of the "shorter list wins" Apply
    // handler below.
    const existingNes = [];
    for (const c of _astClauses) {
      if (c.k === 'pred' && c.op === 'eq' && c.colIdx === colIdx) existingEqs.push(String(c.val));
      else if (c.k === 'pred' && c.op === 'ne' && c.colIdx === colIdx) existingNes.push(String(c.val));
      else if (c.k === 'in' && !c.neg && c.colIdx === colIdx) {
        for (const v of c.vals) existingEqs.push(String(v));
      } else if (c.k === 'in' && c.neg && c.colIdx === colIdx) {
        for (const v of c.vals) existingNes.push(String(v));
      }
    }
    const eqSet = new Set(existingEqs);
    const neSet = new Set(existingNes);

    // Only offer "Use as Timestamp" when the column's values actually parse
    // as timestamps (or bare numbers suitable for a numeric axis). Reuses the
    // scorers already used by `_tlAutoDetectTimestampCol`. Extracted columns
    // are sampled via `_cellAt` since their values live in `_extractedCols`.
    // The button is also hidden for the column that's already the current
    // timestamp — setting it a second time is a no-op.
    const showTimeBtn = this._columnLooksLikeTimestamp(colIdx)
      && colIdx !== this._timeCol;

    menu.innerHTML = `
      <div class="tl-colmenu-head">
        <strong>${_tlEsc(name)}</strong>
      </div>
      <div class="tl-colmenu-section">
        <label class="tl-colmenu-label">Contains</label>
        <input type="text" class="tl-colmenu-input" data-f="contains" placeholder="substring…" spellcheck="false" value="${_tlEsc((existingContains && existingContains.val) || '')}">
      </div>
      <div class="tl-colmenu-section">
        <div class="tl-colmenu-row">
          <label class="tl-colmenu-label">Values (top 200)</label>
          <input type="text" class="tl-colmenu-input tl-colmenu-input-sm" data-f="valsearch" placeholder="search values…" spellcheck="false">
          <button class="tl-colmenu-copy" type="button" data-act="copyvals" title="Copy visible values to clipboard">📋</button>
        </div>
        <div class="tl-colmenu-values"></div>
        <div class="tl-colmenu-valactions">
          <button class="tl-tb-btn" data-act="selall">All</button>
          <button class="tl-tb-btn" data-act="selnone">None</button>
        </div>
      </div>
      <div class="tl-colmenu-section">
        ${showTimeBtn ? '<button class="tl-tb-btn" data-act="timecol">Use as Timestamp</button>' : ''}
        <button class="tl-tb-btn" data-act="stackcol">Stack chart by this</button>
      </div>
      ${this._isExtractedCol(colIdx) ? '<div class="tl-colmenu-section"><button class="tl-tb-btn tl-tb-btn-danger" data-act="removeExtract">✕ Remove extracted column</button></div>' : ''}
      <div class="tl-colmenu-section">
        <button class="tl-tb-btn" data-act="extract">ƒx Extract values</button>
        <button class="tl-tb-btn" data-act="autopivot">🧮 Auto pivot on this column</button>
      </div>
      <div class="tl-colmenu-foot">
        <button class="tl-tb-btn" data-act="reset">Reset filters</button>
        <button class="tl-tb-btn tl-tb-btn-primary" data-act="apply">Apply</button>
      </div>
    `;

    const valsWrap = menu.querySelector('.tl-colmenu-values');
    // Populate distinct values using the "all-but-this-column" filter so
    // the user can broaden a narrowed selection without hitting Reset
    // first. Excel-parity — see `_indexIgnoringColumn` for semantics.
    const items = this._distinctValuesFor(colIdx, this._indexIgnoringColumn(colIdx), 200);
    // Three round-trip modes:
    //   (a) positive-eq present → start with only `eqSet` checked;
    //   (b) negative-ne present (and no eq) → start all-checked, `neSet` off;
    //   (c) nothing on this column → start all-checked.
    const initialAll = existingEqs.length === 0 && existingNes.length === 0;
    const initialAllMinusNe = existingEqs.length === 0 && existingNes.length > 0;

    // Live checkbox state — survives paint() re-renders when the user
    // types in Search Values. Keyed by value string → boolean (checked).
    // Seeded from the initial round-trip mode so the first paint is
    // correct, then updated by individual checkbox toggles and All/None.
    const liveState = new Map();
    for (const [val] of items) {
      const checked = initialAll ? true
        : initialAllMinusNe ? !neSet.has(val)
          : eqSet.has(val);
      liveState.set(val, checked);
    }

    const paint = (filterText) => {
      valsWrap.innerHTML = '';
      const lo = (filterText || '').toLowerCase();
      for (const [val, count] of items) {
        if (lo && !val.toLowerCase().includes(lo)) continue;
        const line = document.createElement('label');
        line.className = 'tl-colmenu-value';
        const checked = liveState.get(val) !== false;
        line.innerHTML = `<input type="checkbox" ${checked ? 'checked' : ''} data-val="${_tlEsc(val)}"> <span class="tl-colmenu-value-label" title="${_tlEsc(val)}">${_tlEsc(val === '' ? '(empty)' : val)}</span> <span class="tl-colmenu-value-count">${count.toLocaleString()}</span>`;
        valsWrap.appendChild(line);
      }
      if (!valsWrap.firstChild) {
        const hint = document.createElement('div');
        hint.className = 'tl-colmenu-empty';
        hint.textContent = 'No matches.';
        valsWrap.appendChild(hint);
      }
    };
    paint('');

    menu.querySelector('[data-f="valsearch"]').addEventListener('input', (e) => paint(e.target.value));

    // Copy visible values — iterates the currently-rendered checkbox
    // rows (post search filter) and copies their values as newline-
    // separated text. Not every checkbox state is preserved across
    // searches; we copy whatever is visible regardless of checked
    // state since the analyst can see it.

    menu.querySelector('[data-act="copyvals"]').addEventListener('click', (e) => {
      e.stopPropagation();
      const rows = valsWrap.querySelectorAll('.tl-colmenu-value input[type=checkbox]');
      const vals = [];
      rows.forEach(cb => { if (cb.dataset.val != null) vals.push(cb.dataset.val); });
      if (!vals.length) return;
      this._copyToClipboard(vals.join('\n'));
      if (this._app && typeof this._app._toast === 'function') {
        this._app._toast(`Copied ${vals.length.toLocaleString()} value${vals.length === 1 ? '' : 's'} from "${name}"`, 'info');
      }
    });

    // Keep liveState in sync when the user toggles individual checkboxes.
    // Delegated on the wrapper so dynamically-created checkboxes after
    // paint() re-renders are covered without per-element listeners.
    valsWrap.addEventListener('change', (e) => {
      const cb = e.target;
      if (cb.type === 'checkbox' && cb.dataset.val != null) {
        liveState.set(cb.dataset.val, cb.checked);
      }
    });

    // Enter in either text input → Apply and close (mirrors the pattern
    // in _openAddSusPopover). Gives keyboard-driven analysts the
    // expected submit-on-Enter UX without reaching for the button.
    const applyBtn = menu.querySelector('[data-act="apply"]');
    menu.querySelector('[data-f="contains"]').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); applyBtn.click(); }
    });
    menu.querySelector('[data-f="valsearch"]').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); applyBtn.click(); }
    });

    // All / None affect only the currently visible (search-filtered)
    // checkboxes — so the user can search for "bob", click None to
    // deselect just the bob values, then search for something else and
    // those deselections persist in liveState across paint() calls.
    menu.querySelector('[data-act="selall"]').addEventListener('click', () => {
      valsWrap.querySelectorAll('input[type=checkbox]').forEach(cb => {
        cb.checked = true;
        liveState.set(cb.dataset.val, true);
      });
    });
    menu.querySelector('[data-act="selnone"]').addEventListener('click', () => {
      valsWrap.querySelectorAll('input[type=checkbox]').forEach(cb => {
        cb.checked = false;
        liveState.set(cb.dataset.val, false);
      });
    });
    // The `Use as Timestamp` button is now conditional (see `showTimeBtn`
    // above — hidden when the column doesn't parse as timestamps / numbers,
    // and on the already-selected timestamp column). Null-guard the wire
    // up; without this, if the button isn't rendered the following
    // `querySelector(...).addEventListener` throws mid-handler and kills
    // every subsequent listener wire-up in this menu — including the
    // value-search <input>, which is how the user most often discovers it.
    const timeColBtn = menu.querySelector('[data-act="timecol"]');
    if (timeColBtn) timeColBtn.addEventListener('click', () => {
      this._timeCol = colIdx;
      this._els.timeColSelect.value = String(colIdx);
      this._parseAllTimestamps();
      this._dataRange = this._computeDataRange();
      this._window = null;
      this._recomputeFilter();
      this._scheduleRender(['chart', 'scrubber', 'grid', 'columns', 'chips']);
      this._closePopover();
    });
    menu.querySelector('[data-act="stackcol"]').addEventListener('click', () => {
      this._stackCol = colIdx;
      this._buildStableStackColorMap();
      this._els.stackColSelect.value = String(colIdx);
      this._scheduleRender(['chart', 'grid', 'columns']);
      this._closePopover();
    });
    menu.querySelector('[data-act="extract"]').addEventListener('click', () => {
      this._closePopover();
      this._openExtractionDialog(colIdx, 'manual');
    });
    menu.querySelector('[data-act="autopivot"]').addEventListener('click', () => {
      this._closePopover();
      this._autoPivotFromColumn(colIdx);
    });
    const removeExtractBtn = menu.querySelector('[data-act="removeExtract"]');
    if (removeExtractBtn) removeExtractBtn.addEventListener('click', () => {
      this._removeExtractedCol(colIdx);
      this._closePopover();
    });
    menu.querySelector('[data-act="reset"]').addEventListener('click', () => {
      // Strip every top-level clause targeting this column from the
      // query AST. Sus marks aren't query-bar clauses, so they're
      // unaffected — matches the old `c.op !== 'sus'` carve-out.
      this._queryReplaceAllForCol(colIdx);
      this._closePopover();
    });
    menu.querySelector('[data-act="apply"]').addEventListener('click', () => {
      // Contains
      const containsText = menu.querySelector('[data-f="contains"]').value.trim();
      this._addContainsChipsReplace(colIdx, containsText);
      // Eq set — read from `liveState` (all items, not just the
      // currently visible DOM) so values hidden by Search Values
      // aren't silently dropped. Pick the shorter representation
      // (`col IN (…)` vs `col NOT IN (…)`) so unchecking one value
      // out of 200 doesn't emit a 199-value IN list. NOT IN is
      // safe when the distinct set is complete, or when the user
      // started from an all-pass / NOT IN baseline (unchecking
      // means "exclude these" and hidden values should pass). NOT
      // IN is blocked only when a positive IN whitelist was active
      // — the user explicitly chose a subset and values beyond the
      // cap were never included.
      const entries = Array.from(liveState.entries());
      const allChecked = entries.length > 0 && entries.every(([, v]) => v);
      const noneChecked = entries.length > 0 && entries.every(([, v]) => !v);
      if (allChecked) {
        // "All selected" → no eq chip narrowing needed.
        this._replaceEqChipsForCol(colIdx, []);
      } else if (noneChecked) {
        // "None" → rarely useful, but treat as excluding all — user probably
        // means clear + contains only.
        this._replaceEqChipsForCol(colIdx, []);
      } else {
        const checked = entries.filter(([, v]) => v).map(([k]) => k);
        const unchecked = entries.filter(([, v]) => !v).map(([k]) => k);
        // NOT IN is always safe when the full distinct set is known.
        // When the set was truncated (cap exceeded), NOT IN is still
        // correct if the user started from an all-pass or NOT IN
        // baseline — unchecked items are exclusions and hidden values
        // beyond the cap should continue to pass through, matching the
        // prior "no filter" / "NOT IN" semantic.  Only when the
        // baseline was a positive IN whitelist do we stick with IN,
        // because the user explicitly selected a subset and values
        // beyond the cap were never included.
        const canNegate = !items.truncated || initialAll || initialAllMinusNe;
        if (canNegate && unchecked.length < checked.length) {
          this._queryReplaceNotInForCol(colIdx, unchecked);
        } else {
          this._replaceEqChipsForCol(colIdx, checked);
        }
      }
      this._closePopover();
    });

    // Anchor below the column head
    const rect = anchor.getBoundingClientRect();
    this._positionFloating(menu, rect.left, rect.bottom + 2);
    document.body.appendChild(menu);
    this._openPopover = menu;
    menu.querySelector('[data-f="contains"]').focus();
  }

  _closeDialog() {
    if (this._openDialog && this._openDialog.parentNode) {
      this._openDialog.parentNode.removeChild(this._openDialog);
    }
    this._openDialog = null;
  }

  // ── Extraction dialog (Smart scan + Regex + Clicker tabs) ────────────────
  _openExtractionDialog(preselectCol, defaultTab) {
    this._closePopover();
    this._closeDialog();
    const dlg = this._openDialog = document.createElement('div');
    dlg.className = 'tl-dialog';
    dlg.innerHTML = `
      <div class="tl-dialog-card tl-dialog-extract">
        <header class="tl-dialog-head">
          <strong>ƒx Extract values</strong>
          <span class="tl-dialog-spacer"></span>
          ${this._extractedCols.length
        ? `<button class="tl-tb-btn tl-tb-btn-danger" data-act="clear-all" title="Remove all extracted columns">✕ Clear all extracted (${this._extractedCols.length})</button>`
        : ''}
          <button class="tl-dialog-close" type="button" aria-label="Close">✕</button>
        </header>
        <div class="tl-dialog-tabs">
          <button class="tl-dialog-tab tl-dialog-tab-active" data-tab="auto">Auto</button>
          <button class="tl-dialog-tab" data-tab="manual">Manual</button>
        </div>
        <div class="tl-dialog-body">
          <section class="tl-dialog-pane tl-dialog-pane-auto">
            <div class="tl-auto-toolbar">
              <div class="tl-auto-bulk">
                <button type="button" class="tl-tb-btn" data-act="sel-all" title="Select all visible">✓ All</button>
                <button type="button" class="tl-tb-btn" data-act="sel-none" title="Deselect all visible">☐ None</button>
                <button type="button" class="tl-tb-btn" data-act="sel-invert" title="Invert selection (visible)">↔ Invert</button>
              </div>
              <span class="tl-auto-count" aria-live="polite">0 of 0 selected</span>
              <div class="tl-auto-facet" role="tablist">
                <button type="button" class="tl-auto-facet-btn tl-auto-facet-active" data-facet="all">All</button>
                <button type="button" class="tl-auto-facet-btn" data-facet="url" title="URL-shaped values">🌐 URL</button>
                <button type="button" class="tl-auto-facet-btn" data-facet="host" title="Hostnames">🖥 Host</button>
                <button type="button" class="tl-auto-facet-btn" data-facet="kv" title="Pipe-delimited Key=Value fields">🪵 Key=Value</button>
                <button type="button" class="tl-auto-facet-btn" data-facet="json" title="Generic JSON leaves">📝 JSON</button>
              </div>
              <input type="text" class="tl-auto-filter" placeholder="Search proposals…  ( / )" aria-label="Search proposals" spellcheck="false" autocomplete="off">
              <select class="tl-auto-sort" title="Sort proposals">
                <option value="match-desc">Match % ↓</option>
                <option value="match-asc">Match % ↑</option>
                <option value="column">Column</option>
                <option value="kind">Kind</option>
                <option value="name">Name</option>
              </select>
            </div>
            <p class="tl-dialog-muted">Scans the first 200 rows of every non-empty column for JSON leaves, pipe-delimited <code>Key=Value</code> fields (EVTX Event Data), and URL/hostname values. On browser-history SQLite the <code>url</code> column also yields host / path / query parts. Tick a row to turn it into a new column.</p>
            <div class="tl-auto-body">
              <div class="tl-auto-empty">Running auto-scan…</div>
            </div>
            <footer class="tl-dialog-foot">
              <button class="tl-tb-btn" data-act="auto-rescan">Rescan</button>
              <span class="tl-dialog-spacer"></span>
              <button class="tl-tb-btn tl-tb-btn-primary" data-act="auto-extract" disabled>Extract selected</button>
            </footer>
          </section>

          <section class="tl-dialog-pane tl-dialog-pane-manual" style="display:none">
            <div class="tl-regex-grid">
              <label class="tl-field">
                <span class="tl-field-label">Column</span>
                <select class="tl-field-select" data-field="col"></select>
              </label>
              <label class="tl-field">
                <span class="tl-field-label">Preset</span>
                <select class="tl-field-select" data-field="preset">
                  <option value="-1">— custom —</option>
                </select>
              </label>
              <label class="tl-field tl-field-wide">
                <span class="tl-field-label">Name</span>
                <input type="text" class="tl-field-select" data-field="name" placeholder="auto">
              </label>
            </div>
            <p class="tl-dialog-muted">Click a token or drag-select a substring in any sample row below — Loupe infers a regex that captures the same slot on every row and fills the Pattern field automatically. Or write a Pattern directly. The picked value is classified (digits, hex, IP, UUID, hostname, path, quoted, …) and surrounding characters become anchors.</p>
            <div class="tl-clicker-samples" aria-label="Sample rows — click a token to pick"></div>
            <div class="tl-regex-grid">
              <label class="tl-field tl-field-wide">
                <span class="tl-field-label">Pattern</span>
                <input type="text" class="tl-field-select" data-field="pattern" spellcheck="false" placeholder="e.g. \\b\\d+\\b">
              </label>
              <label class="tl-field">
                <span class="tl-field-label">Flags</span>
                <input type="text" class="tl-field-select" data-field="flags" value="i" maxlength="8" spellcheck="false">
              </label>
              <label class="tl-field">
                <span class="tl-field-label">Group</span>
                <input type="number" class="tl-field-select" data-field="group" value="0" min="0" max="9">
              </label>
            </div>
            <details class="tl-regex-cheatsheet">
              <summary>Regex cheatsheet</summary>
              <div class="tl-regex-hint">
                <code>\\b</code> word boundary · <code>\\d+</code> digits · <code>[a-z]+</code> letters ·
                <code>(...)</code> capture group · <code>\\.</code> literal dot · flags: <code>i</code> case-insensitive.
                Capture group <code>0</code> is the full match; <code>1</code> is the first <code>(...)</code>.
                <br>⚠ <code>|</code> is alternation — to match a literal pipe, escape it as <code>\\|</code>
                (e.g. in an EVTX Event Data cell, write <code>DestAddress=(.+?) \\|</code>, not <code>DestAddress=(.+?) |</code>).
              </div>
            </details>
            <div class="tl-regex-preview">
              <div class="tl-regex-status">Pick a value above or enter a pattern to preview.</div>
              <div class="tl-regex-samples"></div>
            </div>
            <footer class="tl-dialog-foot">
              <button class="tl-tb-btn" data-act="regex-test">Test</button>
              <span class="tl-dialog-spacer"></span>
              <button class="tl-tb-btn tl-tb-btn-primary" data-act="regex-extract">Extract</button>
            </footer>
          </section>
        </div>
      </div>
    `;
    document.body.appendChild(dlg);

    // Tabs — two panes: Auto / Manual. The Manual tab is a single unified
    // pane that combines Clicker (sample rows) + Regex (Pattern/Flags/Group)
    // wiring, sharing one Column dropdown, one Name field, and one preview.
    const tabs = dlg.querySelectorAll('.tl-dialog-tab');
    const panes = {
      auto: [dlg.querySelector('.tl-dialog-pane-auto')],
      manual: [dlg.querySelector('.tl-dialog-pane-manual')],
    };
    const _showTab = (which) => {
      tabs.forEach(x => x.classList.remove('tl-dialog-tab-active'));
      const btn = dlg.querySelector(`.tl-dialog-tab[data-tab="${which}"]`);
      if (btn) btn.classList.add('tl-dialog-tab-active');
      for (const [k, els] of Object.entries(panes)) {
        const vis = (k === which);
        for (const el of els) { if (el) el.style.display = vis ? '' : 'none'; }
      }
    };
    tabs.forEach(t => t.addEventListener('click', () => _showTab(t.dataset.tab)));
    // Activate requested tab (default = auto)
    _showTab(defaultTab && panes[defaultTab] ? defaultTab : 'auto');

    // Close
    const close = () => this._closeDialog();
    dlg.querySelector('.tl-dialog-close').addEventListener('click', close);
    dlg.addEventListener('click', (e) => { if (e.target === dlg) close(); });

    // Keyboard shortcuts:
    //   /      → focus the Smart-scan filter input (only when that tab
    //            is active; inside the filter itself it's a literal char).
    //   Space  → toggle the checkbox on the row currently hovered under
    //            the pointer (label-wide hit target).
    //   Enter  → trigger the active tab's primary action (Extract).
    // Esc is handled by the global `_onDocKey` listener (closes popover
    // or dialog).
    dlg.addEventListener('keydown', (e) => {
      if (e.key === '/') {
        const autoTab = dlg.querySelector('.tl-dialog-pane-auto');
        const inFilter = e.target && e.target.classList
          && e.target.classList.contains('tl-auto-filter');
        if (autoTab && autoTab.style.display !== 'none' && !inFilter
          && !(e.target && /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName))) {
          const f = dlg.querySelector('.tl-auto-filter');
          if (f) { e.preventDefault(); f.focus(); f.select(); }
          return;
        }
      }
      if (e.key === 'Enter') {
        // Don't steal Enter from text inputs (Regex-tab fields submit
        // via their own wiring, and multi-line textareas would be
        // sabotaged). Only act when focus is on a button / select or
        // the dialog chrome itself.
        const tag = e.target && e.target.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA') return;
        const activeTab = dlg.querySelector('.tl-dialog-tab.tl-dialog-tab-active');
        const which = activeTab ? activeTab.dataset.tab : 'auto';
        if (which === 'auto') {
          const btn = dlg.querySelector('[data-act="auto-extract"]');
          if (btn && !btn.disabled) { e.preventDefault(); btn.click(); }
        } else if (which === 'manual') {
          // Unified Manual tab — single Extract button covers both
          // clicker-inferred and hand-written patterns.
          const rBtn = dlg.querySelector('[data-act="regex-extract"]');
          if (rBtn) { e.preventDefault(); rBtn.click(); }
        }
      }
    });

    // Clear-all (only rendered when _extractedCols.length > 0)
    const clearAllBtn = dlg.querySelector('[data-act="clear-all"]');
    if (clearAllBtn) {
      clearAllBtn.addEventListener('click', () => {
        if (this._clearAllExtractedCols()) close();
      });
    }

    // ── Auto tab wiring
    const autoPane = dlg.querySelector('.tl-dialog-pane-auto');
    const autoBody = dlg.querySelector('.tl-auto-body');
    const autoExtractBtn = dlg.querySelector('[data-act="auto-extract"]');
    const autoCount = dlg.querySelector('.tl-auto-count');
    const autoFilter = dlg.querySelector('.tl-auto-filter');
    const autoSort = dlg.querySelector('.tl-auto-sort');
    const autoFacetBtns = dlg.querySelectorAll('.tl-auto-facet-btn');
    const autoToolbar = dlg.querySelector('.tl-auto-toolbar');

    // "Will create:" preview strip — injected between body and footer.
    const previewStrip = document.createElement('div');
    previewStrip.className = 'tl-dialog-preview';
    previewStrip.innerHTML = `<span class="tl-dialog-preview-label">Will create:</span><span class="tl-dialog-preview-list">(none selected)</span>`;
    autoBody.parentNode.insertBefore(previewStrip, autoBody.nextSibling);
    const previewListEl = previewStrip.querySelector('.tl-dialog-preview-list');

    // Facet → set of proposal kinds
    const FACET_KINDS = {
      all: null,
      url: new Set(['text-url', 'json-url', 'url-part']),
      host: new Set(['text-host', 'json-host']),
      kv: new Set(['kv-field']),
      json: new Set(['json-leaf']),
    };
    let currentFacet = 'all';

    // State used by the toolbar filters + renderer.
    //   _allProposals — every proposal from the last `_autoExtractScan()` pass.
    //   _visibleIndices — indices into `_allProposals` that pass the current
    //                     facet + search filter (the rows the list renders).
    //   _selection — stable Set<origIdx> of CHECKED proposals. Survives
    //                facet / search / sort changes, so a tick the analyst
    //                made before typing into the search box stays ticked
    //                once the row is re-revealed. Counts + preview +
    //                Extract all read from this Set, never from DOM
    //                checkboxes, so hidden-but-selected rows are honoured.
    let _allProposals = [];
    let _visibleIndices = [];
    const _selection = new Set();

    const countMatches = (kind) => {
      if (!_allProposals.length) return 0;
      const set = FACET_KINDS[kind];
      if (!set) return _allProposals.length;
      let n = 0;
      for (const p of _allProposals) if (set.has(p.kind)) n++;
      return n;
    };

    const updateFacetCounts = () => {
      autoFacetBtns.forEach(b => {
        const f = b.dataset.facet;
        const base = b.dataset.baseLabel || b.textContent;
        if (!b.dataset.baseLabel) b.dataset.baseLabel = base;
        const n = countMatches(f);
        b.textContent = (b.dataset.baseLabel) + ' (' + n + ')';
      });
    };

    const sortProposals = (arr, mode) => {
      const kindOrder = { 'text-url': 0, 'url-part': 1, 'json-url': 2, 'text-host': 3, 'json-host': 4, 'kv-field': 5, 'json-leaf': 6 };
      const nameOf = (p) => p.proposedName || '';
      const colOf = (p) => this.columns[p.sourceCol] || '';
      const cmp = {
        'match-desc': (a, b) => (b.matchPct || 0) - (a.matchPct || 0),
        'match-asc': (a, b) => (a.matchPct || 0) - (b.matchPct || 0),
        'column': (a, b) => colOf(a).localeCompare(colOf(b)) || (b.matchPct - a.matchPct),
        'kind': (a, b) => (kindOrder[a.kind] || 9) - (kindOrder[b.kind] || 9) || (b.matchPct - a.matchPct),
        'name': (a, b) => nameOf(a).localeCompare(nameOf(b)),
      }[mode] || ((a, b) => (b.matchPct || 0) - (a.matchPct || 0));
      return arr.slice().sort(cmp);
    };

    const updatePreview = () => {
      // Read from the stable _selection Set so hidden-but-ticked proposals
      // (e.g. after the user narrows the search box) still appear in the
      // "Will create:" strip and get extracted on submit.
      const picked = [];
      for (const i of _selection) {
        if (_allProposals[i]) picked.push(_allProposals[i].proposedName);
      }
      if (!picked.length) {
        previewListEl.textContent = '(none selected)';
        previewListEl.classList.add('tl-dialog-preview-empty');
      } else {
        previewListEl.classList.remove('tl-dialog-preview-empty');
        const maxShow = 8;
        const head = picked.slice(0, maxShow).map(n => `<span class="tl-dialog-preview-pill">${_tlEsc(n)}</span>`).join('');
        const more = picked.length > maxShow ? ` <span class="tl-dialog-preview-more">+${picked.length - maxShow} more</span>` : '';
        previewListEl.innerHTML = head + more;
      }
    };

    const updateCount = () => {
      // "N of V selected" where V is the number of currently-visible rows
      // (so search narrows the denominator) and N is the total stable
      // selection size (so ticks survive searching / faceting).
      const visN = _visibleIndices.length;
      const selN = _selection.size;
      autoCount.textContent = `${selN} of ${visN} selected`;
      autoExtractBtn.disabled = selN === 0;
    };


    const renderList = () => {
      if (!_allProposals.length) {
        autoBody.innerHTML = '<div class="tl-auto-empty">No extractable values found in the first 200 rows.</div>';
        _visibleIndices = [];
        autoExtractBtn.disabled = true;
        updateCount();
        updatePreview();
        return;
      }
      const facetSet = FACET_KINDS[currentFacet];
      const filterTxt = (autoFilter.value || '').toLowerCase();
      // Build visible list, preserving original indices for checkbox mapping.
      const sorted = sortProposals(_allProposals, autoSort.value);
      const origIndexOf = new Map(_allProposals.map((p, i) => [p, i]));
      _visibleIndices = [];
      const list = document.createElement('div');
      list.className = 'tl-auto-list';
      for (const p of sorted) {
        if (facetSet && !facetSet.has(p.kind)) continue;
        if (filterTxt) {
          const hay = (p.proposedName + ' ' + (this.columns[p.sourceCol] || '') + ' ' + (p.sample || '')).toLowerCase();
          if (hay.indexOf(filterTxt) === -1) continue;
        }
        const origI = origIndexOf.get(p);
        _visibleIndices.push(origI);
        const row = document.createElement('label');
        row.className = 'tl-auto-row';
        row.dataset.i = String(origI);
        const colName = this.columns[p.sourceCol] || `(col ${p.sourceCol + 1})`;
        // Checked state is driven by the stable _selection Set, NOT the
        // proposal's preselect hint — the hint only seeds _selection in
        // runAuto(). After seeding, survivorship across search / facet /
        // sort is absolute: a row's tick state is _selection.has(origI).
        const isChecked = _selection.has(origI);
        const samplePreview = p.sample || '';
        row.innerHTML = `
          <input type="checkbox" data-i="${origI}" ${isChecked ? 'checked' : ''}>

          <span class="tl-auto-kind" data-kind="${_tlEsc(p.kind)}">${_tlEsc(p.kindLabel)}</span>
          <span class="tl-auto-sample" title="${_tlEsc(samplePreview)}">${_tlEsc(this._ellipsis(samplePreview, 90))}</span>
          <span class="tl-auto-col" title="${_tlEsc(colName)}">${_tlEsc(colName)}</span>
          <span class="tl-auto-rate" title="match rate in sample">${(p.matchPct || 0).toFixed(0)}%</span>
        `;
        list.appendChild(row);
      }
      if (!_visibleIndices.length) {
        autoBody.innerHTML = '<div class="tl-auto-empty">No proposals match the current filter.</div>';
      } else {
        autoBody.innerHTML = '';
        autoBody.appendChild(list);
      }
      autoExtractBtn.disabled = _visibleIndices.length === 0;
      updateCount();
      updatePreview();
    };

    // Bulk select buttons — operate on the *visible* rows only, but mutate
    // the stable `_selection` Set so ticks persist if the user subsequently
    // narrows the search box / switches facet. We re-render so the DOM
    // checkboxes pick up the new ticked state from `_selection.has()`.
    autoToolbar.querySelector('[data-act="sel-all"]').addEventListener('click', () => {
      for (const i of _visibleIndices) _selection.add(i);
      renderList();
    });
    autoToolbar.querySelector('[data-act="sel-none"]').addEventListener('click', () => {
      for (const i of _visibleIndices) _selection.delete(i);
      renderList();
    });
    autoToolbar.querySelector('[data-act="sel-invert"]').addEventListener('click', () => {
      for (const i of _visibleIndices) {
        if (_selection.has(i)) _selection.delete(i);
        else _selection.add(i);
      }
      renderList();
    });
    autoFacetBtns.forEach(b => b.addEventListener('click', () => {
      autoFacetBtns.forEach(x => x.classList.remove('tl-auto-facet-active'));
      b.classList.add('tl-auto-facet-active');
      currentFacet = b.dataset.facet;
      renderList();
    }));
    let filterTimer = 0;
    autoFilter.addEventListener('input', () => {
      clearTimeout(filterTimer);
      filterTimer = setTimeout(renderList, 80);
    });
    autoSort.addEventListener('change', renderList);
    autoBody.addEventListener('change', (e) => {
      if (e.target && e.target.type === 'checkbox') {
        const origI = +e.target.dataset.i;
        if (Number.isFinite(origI)) {
          if (e.target.checked) _selection.add(origI);
          else _selection.delete(origI);
        }
        updateCount();
        updatePreview();
      }
    });

    const runAuto = () => {
      autoBody.innerHTML = '<div class="tl-auto-empty">Running auto-scan…</div>';
      autoExtractBtn.disabled = true;
      setTimeout(() => {
        _allProposals = this._autoExtractScan() || [];
        autoExtractBtn._proposals = _allProposals;
        // Seed the stable selection from each proposal's preselect hint.
        // Subsequent ticks/unticks mutate this Set directly; facet/search/
        // sort changes only affect `_visibleIndices`, never `_selection`.
        _selection.clear();
        for (let i = 0; i < _allProposals.length; i++) {
          if (_allProposals[i].preselect !== false) _selection.add(i);
        }
        updateFacetCounts();
        renderList();
      }, 10);
    };
    dlg.querySelector('[data-act="auto-rescan"]').addEventListener('click', runAuto);

    autoExtractBtn.addEventListener('click', () => {
      const props = autoExtractBtn._proposals || [];
      // Extract every ticked proposal from the stable `_selection` Set —
      // NOT from the DOM, so rows currently hidden by search/facet are
      // still honoured.
      const pick = [];
      for (const i of _selection) {
        const p = props[i];
        if (p) pick.push(p);
      }
      if (!pick.length) return;
      const before = this._extractedCols.length;
      for (const p of pick) {
        if (p.kind === 'json-url' || p.kind === 'json-host' || p.kind === 'json-leaf') {
          this._addJsonExtractedColNoRender(p.sourceCol, p.path, p.proposedName, { autoKind: p.kind });
        } else if (p.kind === 'text-url' || p.kind === 'text-host') {

          this._addRegexExtractNoRender({
            name: p.proposedName,
            col: p.sourceCol,
            pattern: (p.kind === 'text-url' ? TL_URL_RE.source : TL_HOSTNAME_INLINE_RE.source),
            flags: 'i',
            group: (p.kind === 'text-host') ? 1 : 0,
            kind: 'auto',
          });
        } else if (p.kind === 'kv-field') {
          // Pipe-delimited Key=Value cells (e.g. EVTX Event Data rendered as
          // "Key1=val | Key2=val | …"). The value can span newlines (e.g.
          // `UserAccountControl=\n%%2080\n%%2082`) or contain XML payloads,
          // so we use `[\s\S]*?` and a lookahead that stops at the next
          // real " | SomeKey=" boundary or end-of-string.
          //
          // The boundary uses LITERAL ` | ` (single-space / pipe / single-
          // space), matching exactly what `EvtxRenderer` emits via
          // `parts.join(' | ')`. Historically this was `\s\|\s`, which is
          // looser and risks false boundaries on multi-line values that
          // contain a stray `\n|\n` sequence. `trim: true` asks the eval
          // path to strip leading/trailing whitespace and per-line tab
          // indentation so multi-line values (`PrivilegeList`,
          // `UserAccountControl`) don't render as `\n\t\t\tSeTcbPrivilege…`
          // in the grid / topvals / pivot.
          const esc = String(p.fieldName || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const pattern = `(?:^| \\| )${esc}=([\\s\\S]*?)(?= \\| [A-Za-z_][\\w.-]*=|$)`;
          this._addRegexExtractNoRender({
            name: p.proposedName,
            col: p.sourceCol,
            pattern,
            flags: '',
            group: 1,
            kind: 'auto',
            trim: true,
          });
        } else if (p.kind === 'url-part') {
          // Browser-history SQLite `url` column: extract scheme://host,
          // path, or ?query using pre-baked regex patterns from the
          // scanner. `p.pattern` / `p.group` come straight from the
          // proposal so we don't need to re-derive them here.
          this._addRegexExtractNoRender({
            name: p.proposedName,
            col: p.sourceCol,
            pattern: p.pattern,
            flags: p.flags || '',
            group: p.group != null ? p.group : 1,
            kind: 'auto',
          });
        }
      }
      const added = this._extractedCols.length - before;
      const skipped = pick.length - added;
      if (this._app && this._app._toast) {
        if (added && skipped) this._app._toast(`Added ${added} column${added === 1 ? '' : 's'}; skipped ${skipped} duplicate${skipped === 1 ? '' : 's'}`, 'info');
        else if (added) this._app._toast(`Added ${added} column${added === 1 ? '' : 's'}`, 'info');
        else if (skipped) this._app._toast(`Skipped ${skipped} duplicate${skipped === 1 ? '' : 's'} — already extracted`, 'info');
      }
      this._rebuildExtractedStateAndRender();
      close();
    });
    runAuto();

    // ── Manual tab wiring (unified Clicker + Regex)
    // The Manual tab is a single pane that shares one Column dropdown,
    // one Name field, and one preview between the click-to-pick sample
    // rows and the hand-authored Pattern/Flags/Group fields. Picking a
    // token / drag-selecting in a sample row infers a regex which is
    // written directly into the Pattern field — there is no separate
    // "Edit in Regex tab" step. The single Extract button at the foot
    // saves whatever pattern is currently in the form.
    const clickerSamples = dlg.querySelector('.tl-clicker-samples');

    // Token classifier — inspects a picked substring and returns a regex

    // fragment that matches the same shape. Ordered from most specific
    // to most general so a UUID doesn't degenerate to `[0-9a-f]+`.
    const _classifyPick = (s) => {
      if (!s) return { pattern: '\\S+', label: 'text' };
      if (/^\d+$/.test(s)) return { pattern: '\\d+', label: 'digits' };
      if (/^[+-]?\d+\.\d+$/.test(s)) return { pattern: '[+-]?\\d+\\.\\d+', label: 'decimal' };
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) {
        return { pattern: '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', label: 'UUID' };
      }
      if (/^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(s)) {
        return { pattern: '(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}', label: 'IPv4' };
      }
      if (/^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(s)) {
        return { pattern: '(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}', label: 'MAC' };
      }
      if (/^[0-9a-f]{32}$/i.test(s)) return { pattern: '[0-9a-f]{32}', label: 'MD5' };
      if (/^[0-9a-f]{40}$/i.test(s)) return { pattern: '[0-9a-f]{40}', label: 'SHA1' };
      if (/^[0-9a-f]{64}$/i.test(s)) return { pattern: '[0-9a-f]{64}', label: 'SHA256' };
      if (/^[0-9a-f]+$/i.test(s) && s.length >= 4) return { pattern: '[0-9a-f]+', label: 'hex' };
      if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/.test(s)) {
        return { pattern: '\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?', label: 'ISO timestamp' };
      }
      if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return { pattern: '\\d{4}-\\d{2}-\\d{2}', label: 'date' };
      if (/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(s)) {
        return { pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}', label: 'email' };
      }
      if (/^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(s)) {
        return { pattern: '[a-z][a-z0-9+.\\-]*:\\/\\/\\S+', label: 'URL' };
      }
      if (/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(s)) {
        return { pattern: '(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}', label: 'hostname' };
      }
      if (/^[A-Za-z]:\\/.test(s)) return { pattern: '[A-Za-z]:\\\\[^\\s"<>|?*]+', label: 'Windows path' };
      if (/^\/[^\s]+$/.test(s)) return { pattern: '\\/[^\\s]+', label: 'POSIX path' };
      if (/^[A-Za-z_][\w-]*$/.test(s)) return { pattern: '[A-Za-z_][\\w-]*', label: 'identifier' };
      if (/^\S+$/.test(s)) return { pattern: '\\S+', label: 'token' };
      return { pattern: '.+?', label: 'text' };
    };

    // Regex-escape a literal anchor. Newlines collapse to \n (so
    // multi-line cells don't paste a raw CR/LF into the pattern).
    const _escLiteral = (s) => String(s)
      .replace(/\\/g, '\\\\')
      .replace(/[.*+?^${}()|[\]]/g, '\\$&')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');

    // Collect up to 30 non-empty samples for the pick pane + anchor check.
    const _collectClickerSamples = (colIdx) => {
      const out = [];
      const cap = Math.min(this.rows.length, 400);
      for (let i = 0; i < cap && out.length < 30; i++) {
        const v = this._cellAt(i, colIdx);
        if (v) out.push(v);
      }
      return out;
    };

    // Generalise a left anchor: keep trimming from the LEFT (so the
    // anchor stays adjacent to the pick) until ≥ 70 % of samples match
    // `escAnchor + tokenPattern` somewhere. Empty anchor = use `\b`.
    const _generaliseAnchor = (rawAnchor, tokenPattern, samples, side) => {
      if (!rawAnchor) return side === 'left' ? '\\b' : '\\b';
      // Start from the full raw anchor and shrink.
      let anchor = rawAnchor;
      const threshold = Math.max(1, Math.ceil(samples.length * 0.7));
      // Try full → progressively shorter. For left side, drop chars from
      // the start; for right, drop from the end.
      while (anchor.length > 0) {
        const escAnchor = _escLiteral(anchor);
        let re;
        try {
          /* safeRegex: builtin */
          re = side === 'left'
            ? new RegExp(escAnchor + '(' + tokenPattern + ')', 'i')
            : new RegExp('(' + tokenPattern + ')' + escAnchor, 'i');
        } catch (_) { break; }
        let hits = 0;
        for (const s of samples) if (re.test(s)) hits++;
        if (hits >= threshold) return escAnchor;
        anchor = side === 'left' ? anchor.slice(1) : anchor.slice(0, -1);
      }
      return '\\b';
    };

    // ── Regex / pattern wiring (shared by the unified Manual pane)
    const colSel = dlg.querySelector('[data-field="col"]');
    colSel.innerHTML = '';
    for (let i = 0; i < this._baseColumns.length; i++) {
      const o = document.createElement('option');
      o.value = String(i); o.textContent = this._baseColumns[i] || `(col ${i + 1})`;
      colSel.appendChild(o);
    }
    for (let i = 0; i < this._extractedCols.length; i++) {
      const o = document.createElement('option');
      o.value = String(this._baseColumns.length + i);
      o.textContent = this._extractedCols[i].name + ' ⚡';
      colSel.appendChild(o);
    }
    if (preselectCol != null && preselectCol < this.columns.length) colSel.value = String(preselectCol);

    const presetSel = dlg.querySelector('[data-field="preset"]');
    for (const p of TL_REGEX_PRESETS) {
      const o = document.createElement('option');
      o.value = p.label; o.textContent = p.label; presetSel.appendChild(o);
    }
    const patternEl = dlg.querySelector('[data-field="pattern"]');
    const flagsEl = dlg.querySelector('[data-field="flags"]');
    const groupEl = dlg.querySelector('[data-field="group"]');
    const nameEl = dlg.querySelector('[data-field="name"]');
    const statusEl = dlg.querySelector('.tl-regex-status');
    const samplesEl = dlg.querySelector('.tl-regex-samples');

    // Render the clicker sample rows for the currently-selected column.
    // Each row carries its untruncated text on `_fullText` so `handlePick`
    // can compute pick offsets without re-reading the table.
    const renderClickerSamples = () => {
      const col = parseInt(colSel.value, 10);
      if (!Number.isFinite(col) || col < 0) { clickerSamples.innerHTML = ''; return; }
      const samples = _collectClickerSamples(col);
      clickerSamples.innerHTML = '';
      if (!samples.length) {
        const empty = document.createElement('div');
        empty.className = 'tl-clicker-empty';
        empty.textContent = '(no non-empty values in this column)';
        clickerSamples.appendChild(empty);
        return;
      }
      for (const s of samples) {
        const row = document.createElement('div');
        row.className = 'tl-clicker-row';
        row.textContent = s;
        row._fullText = s;
        clickerSamples.appendChild(row);
      }
    };

    // Pick handler — fires on mouseup inside a `.tl-clicker-row`. Builds a
    // regex from the picked / drag-selected substring + sniffed anchors,
    // writes it directly into the unified Pattern / Flags / Group fields,
    // resets the Preset dropdown to "— custom —", optionally seeds the
    // Name placeholder, then calls `runTest()` so the unified preview
    // updates. The user can fine-tune the pattern by hand and click
    // Extract — there is no separate "Edit in Regex tab" step.
    const handlePick = (rowEl) => {
      if (!rowEl) return;
      const full = rowEl._fullText || rowEl.textContent || '';
      if (!full) return;
      const sel = window.getSelection();
      let picked = '';
      let start = -1;
      if (sel && sel.rangeCount && !sel.isCollapsed) {
        const range = sel.getRangeAt(0);
        if (rowEl.contains(range.startContainer) && rowEl.contains(range.endContainer)) {
          picked = sel.toString();
          start = full.indexOf(picked);
        }
      }
      if (!picked) {
        // Click-only fallback: pick the first whitespace-delimited token.
        const visible = rowEl.textContent || '';
        const m = /\S+/.exec(visible);
        if (m) {
          picked = m[0];
          start = full.indexOf(picked);
        }
      }
      if (!picked) return;
      if (start < 0) start = 0;
      const end = start + picked.length;

      const ANCHOR_MAX = 24;
      let left = full.slice(Math.max(0, start - ANCHOR_MAX), start);
      let right = full.slice(end, end + ANCHOR_MAX);
      const leftWs = left.search(/\s\S*$/);
      if (leftWs >= 0) left = left.slice(leftWs);
      const rightWsEnd = right.search(/\s/);
      if (rightWsEnd > 0) right = right.slice(0, rightWsEnd);
      left = left.replace(/^\s+/, '');
      right = right.replace(/\s+$/, '');

      const cls = _classifyPick(picked);
      const col = parseInt(colSel.value, 10);
      const samples = Number.isFinite(col) ? _collectClickerSamples(col) : [];
      const leftEsc = _generaliseAnchor(left, cls.pattern, samples, 'left');
      const rightEsc = _generaliseAnchor(right, cls.pattern, samples, 'right');
      const inferred = leftEsc + '(' + cls.pattern + ')' + rightEsc;

      patternEl.value = inferred;
      flagsEl.value = 'i';
      groupEl.value = '1';
      if (presetSel) presetSel.value = '-1';

      // Default Name placeholder: "<colName>.<label>" — only set if the
      // user hasn't typed their own name. Keeps the value field empty so
      // the extract handler's `(nameEl.value || '').trim()` fallback to
      // `${colName} (regex)` still applies if the placeholder is rejected.
      const colName = this._baseColumns[col] || `col${col + 1}`;
      if (!nameEl.value.trim()) {
        nameEl.placeholder = `${colName}.${cls.label.replace(/\s+/g, '_')}`;
      }

      runTest();
    };

    clickerSamples.addEventListener('mouseup', (e) => {
      const row = e.target.closest('.tl-clicker-row');
      if (!row) return;
      // Give the browser a tick to finalise the selection before reading it.
      setTimeout(() => handlePick(row), 0);
    });

    presetSel.addEventListener('change', () => {

      const p = TL_REGEX_PRESETS.find(x => x.label === presetSel.value);
      if (p) {
        patternEl.value = p.pattern;
        flagsEl.value = p.flags || '';
        groupEl.value = String(p.group == null ? 0 : p.group);
        nameEl.value = p.label;
      }
    });

    // Detect an UNESCAPED top-level `|` in the pattern — that's alternation,
    // not a literal pipe. The classic footgun: `DestAddress=(.+?) |` reads as
    // the alternation `"DestAddress=(.+?) " OR ""`, so every row matches at
    // offset 0 with group 1 = undefined → the preview's old "matched" count
    // rings 100% while every saved value is empty. We strip out escaped `\|`
    // and character classes `[...]` before scanning so we only warn on the
    // genuine gotcha.
    const _hasTopLevelPipe = (src) => {
      if (!src) return false;
      // Remove escaped metacharacters (notably `\|`).
      let stripped = src.replace(/\\./g, '');
      // Remove character classes `[…]` — `|` inside a class is literal.
      stripped = stripped.replace(/\[[^\]]*\]/g, '');
      return stripped.indexOf('|') !== -1;
    };

    const runTest = () => {
      const pattern = patternEl.value;
      const flags = flagsEl.value;
      if (!pattern) { statusEl.textContent = 'Enter a pattern to preview.'; samplesEl.innerHTML = ''; return; }
      // Cap pattern length to prevent pathologically long inputs from
      // even reaching the engine. 1 KB is plenty for any realistic
      // extractor; anything longer is almost certainly a paste accident.
      if (pattern.length > 1024) {
        statusEl.textContent = 'Pattern too long (>1024 chars). Try anchoring or trimming it.';
        samplesEl.innerHTML = '';
        return;
      }
      const safe = safeRegex(pattern, flags);
      if (!safe.ok) {
        statusEl.textContent = 'Invalid or unsafe regex: ' + safe.error;
        samplesEl.innerHTML = '';
        return;
      }
      const re = safe.regex;
      if (safe.warning) {
        statusEl.textContent = '⚠ Pattern may be slow (' + safe.warning + ') — preview limited to 200 rows.';
      }
      const col = parseInt(colSel.value, 10);
      const gp = Math.max(0, Math.min(9, parseInt(groupEl.value, 10) || 0));
      const sampleMax = 200;
      const N = Math.min(this.rows.length, sampleMax);
      // `matched`  — rows where `re.exec()` returned any match at all.
      // `captured` — rows where the selected group `gp` captured a
      //              NON-EMPTY string. This is the count the user actually
      //              cares about: it's what the saved extractor will emit.
      //              Historical bug: the preview reported `matched` alone
      //              as "N/M matched (100%)" and then saved an all-empty
      //              column, because `DestAddress=(.+?) |` matches the
      //              empty alternative at offset 0 for every row and
      //              leaves group 1 undefined.
      let seen = 0, matched = 0, captured = 0, emptyCap = 0;
      const hits = [];
      // Per-preview wall-clock budget. A single `re.exec(v)` call is not
      // preemptible, but bounding the loop and the per-cell input length
      // keeps adversarial patterns from chewing through 200 rows.
      const _previewStart = Date.now();
      const _PREVIEW_BUDGET_MS = 250;
      let _bailedTimeout = false;
      for (let i = 0; i < N; i++) {
        const v = this._cellAt(i, col);
        if (!v) continue;
        seen++;
        // Cap per-cell input length to prevent a single long row from
        // dominating the preview budget.
        const _vCap = v.length > 8192 ? v.slice(0, 8192) : v;
        const m = re.exec(_vCap);
        if ((seen & 0x1F) === 0 && Date.now() - _previewStart > _PREVIEW_BUDGET_MS) {
          _bailedTimeout = true;
          break;
        }
        if (!m) continue;
        matched++;
        const cap = (gp < m.length) ? (m[gp] == null ? '' : m[gp]) : m[0];
        if (cap !== '') {
          captured++;
          if (hits.length < 20) hits.push({ src: v, cap });
        } else {
          emptyCap++;
        }
      }
      const capPct = seen ? (captured * 100 / seen) : 0;
      let status;
      if (matched === captured) {
        status = `${captured}/${seen} sampled rows captured (${capPct.toFixed(0)}%).`;
      } else {
        // The preview that will actually be saved is the non-empty column.
        // Surface both numbers so the user can see the honest gap.
        status = `${captured}/${seen} captured (${capPct.toFixed(0)}%) · ${matched} matched but ${emptyCap} produced empty values (group ${gp} was undefined / empty).`;
      }
      // Pipe-alternation footgun — strong hint that the user meant a
      // literal pipe. Only warn when there's a real discrepancy, to
      // avoid alarming users who intentionally wrote alternations.
      if (_hasTopLevelPipe(pattern) && matched > captured) {
        status += `  ⚠ Your pattern contains "|" (regex alternation). To match a literal pipe character use "\\|".`;
      }
      if (_bailedTimeout) {
        status = `Pattern timed out after ${seen} of ${N} sample rows — try anchoring or bounding it.`;
        statusEl.textContent = status;
        samplesEl.innerHTML = '';
        return;
      }
      statusEl.textContent = status;
      samplesEl.innerHTML = '';
      for (const h of hits) {
        const d = document.createElement('div');
        d.className = 'tl-regex-sample';
        d.innerHTML = `<span class="tl-regex-sample-cap">${_tlEsc(h.cap)}</span><span class="tl-regex-sample-src" title="${_tlEsc(h.src)}">${_tlEsc(this._ellipsis(h.src, 90))}</span>`;
        samplesEl.appendChild(d);
      }
    };
    // Debounce the keystroke-driven preview. Each keystroke previously fired
    // a fresh `runTest` synchronously over up to 200 rows; for adversarial
    // patterns this could stall the dialog. 100 ms is short enough to feel
    // responsive but coalesces typing bursts.
    let _runTestTimer = null;
    const runTestDebounced = () => {
      if (_runTestTimer != null) clearTimeout(_runTestTimer);
      _runTestTimer = setTimeout(() => { _runTestTimer = null; runTest(); }, 100);
    };
    patternEl.addEventListener('input', runTestDebounced);
    flagsEl.addEventListener('input', runTestDebounced);
    groupEl.addEventListener('input', runTestDebounced);
    // Column change repaints the click-to-pick samples (so users see rows
    // from the newly-selected column) and re-runs the regex preview.
    colSel.addEventListener('change', () => { renderClickerSamples(); runTest(); });
    dlg.querySelector('[data-act="regex-test"]').addEventListener('click', runTest);

    dlg.querySelector('[data-act="regex-extract"]').addEventListener('click', () => {
      const pattern = patternEl.value;
      if (!pattern) { if (this._app) this._app._toast('Enter a regex pattern', 'error'); return; }
      if (pattern.length > 1024) {
        if (this._app) this._app._toast('Pattern too long (>1024 chars)', 'error');
        return;
      }
      const safe = safeRegex(pattern, flagsEl.value);
      if (!safe.ok) { if (this._app) this._app._toast('Invalid or unsafe regex: ' + safe.error, 'error'); return; }
      const re = safe.regex;
      // Sample-budget gate: dry-run the compiled regex against up to 1k rows
      // with a 250 ms budget. If it can't keep up on the sample, the full
      // commit (which scans every row in the timeline) certainly can't.
      const sampleN = Math.min(this.rows.length, 1000);
      const col = parseInt(colSel.value, 10);
      const sampleStart = Date.now();
      let sampleBail = false;
      for (let i = 0; i < sampleN; i++) {
        const v = this._cellAt(i, col);
        if (!v) continue;
        const _vCap = v.length > 8192 ? v.slice(0, 8192) : v;
        try { re.exec(_vCap); } catch (_e) { /* ignore */ }
        if ((i & 0x3F) === 0 && Date.now() - sampleStart > 250) {
          sampleBail = true;
          break;
        }
      }
      if (sampleBail) {
        if (this._app) this._app._toast('Pattern too slow on sample — refusing to apply across full table', 'error');
        return;
      }
      const gp = Math.max(0, Math.min(9, parseInt(groupEl.value, 10) || 0));
      const colName = this._baseColumns[col] || `(col ${col + 1})`;
      const name = (nameEl.value || '').trim() || `${colName} (regex)`;
      const before = this._extractedCols.length;
      this._addRegexExtractNoRender({
        name, col, pattern, flags: flagsEl.value, group: gp, kind: 'regex',
      });
      if (this._extractedCols.length === before) {
        if (this._app && this._app._toast) this._app._toast('That column is already extracted', 'info');
        return;
      }
      this._rebuildExtractedStateAndRender();
      close();
      void re;  // re already constructed
    });

    // Initial paint of the click-to-pick samples for the preselected
    // column so the unified Manual pane shows rows the moment the dialog
    // opens — without this, samples only appeared after the user changed
    // the Column dropdown.
    renderClickerSamples();
  }

  // ── Auto-extract scanner ─────────────────────────────────────────────────

  _autoExtractScan() {
    const proposals = [];
    const sampleCap = Math.min(this.rows.length, 200);
    const cols = this._baseColumns.length;

    // EVTX detection: format label is "EVTX", or the base columns include
    // the synthesised "Event Data" column emitted by `fromEvtx`. When EVTX
    // is detected, the KV-field heuristic uses looser thresholds so sparse
    // but forensically-important fields (LogonType, UserAccountControl…)
    // surface in the dialog instead of being filtered out as noise.
    const isEvtx = this.formatLabel === 'EVTX'
      || (this._baseColumns && this._baseColumns.indexOf(EVTX_COLUMNS.EVENT_DATA) !== -1);

    // Forensics-grade EVTX fields: pre-selected by default (others stay
    // visible but unchecked) so analysts can Extract-selected and get a
    // tight investigatable column set without triaging 40 checkboxes.
    const FORENSIC_EVTX_FIELDS = new Set([
      'CommandLine', 'ParentCommandLine', 'TargetUserName', 'SubjectUserName',
      'ProcessName', 'NewProcessName', 'IpAddress', 'LogonType',
    ]);

    // Browser-history SQLite — the `url` column gets three additional
    // `url-part` proposals (host / path / query) so analysts can split a
    // visited URL into its components with one click.
    const isBrowserHistory = typeof this.formatLabel === 'string'
      && this.formatLabel.indexOf('SQLite') === 0
      && this.formatLabel.indexOf('History') !== -1;

    for (let c = 0; c < cols; c++) {
      // Browser-history: emit url-part proposals for the `url` column
      // before the generic branches, so they appear at the top of the
      // list sorted by match %.
      if (isBrowserHistory && (this._baseColumns[c] || '').toLowerCase() === 'url') {
        const colName = this._baseColumns[c] || 'url';
        // Sample a value for the preview column.
        let sampleVal = '';
        for (let i = 0; i < Math.min(this.rows.length, 50); i++) {
          const v = this._cellAt(i, c);
          if (v) { sampleVal = v; break; }
        }
        const parts = [
          { sub: 'host', label: 'URL host', pattern: '^[a-z][a-z0-9+.\\-]*:\\/\\/([^\\/?#]+)', group: 1 },
          { sub: 'path', label: 'URL path', pattern: '^[a-z][a-z0-9+.\\-]*:\\/\\/[^\\/?#]+([^?#]*)', group: 1 },
          { sub: 'query', label: 'URL query', pattern: '\\?([^#]*)', group: 1 },
        ];
        for (const p of parts) {
          proposals.push({
            kind: 'url-part', kindLabel: p.label, sourceCol: c, path: null,
            subKind: p.sub, pattern: p.pattern, group: p.group,
            matchPct: 95,
            proposedName: `${colName}.${p.sub}`,
            sample: sampleVal,
            preselect: true,
          });
        }
      }

      // Sample cells.
      const samples = [];
      for (let i = 0; i < sampleCap; i++) {
        const v = this._cellAt(i, c);
        if (v !== '') samples.push({ i, v });
      }
      if (!samples.length) continue;

      // Determine: JSON-dominant column?
      let jsonOk = 0;
      const parsedList = new Array(samples.length);
      for (let i = 0; i < samples.length; i++) {
        const v = samples[i].v;
        if (_tlMaybeJson(v)) {
          try { parsedList[i] = JSON.parse(v); if (parsedList[i] != null && typeof parsedList[i] === 'object') jsonOk++; }
          catch (_) { parsedList[i] = null; }
        } else {
          parsedList[i] = null;
        }
      }
      if (jsonOk >= samples.length * 0.5 && jsonOk >= 3) {
        // Score path leaves.
        const pathStats = new Map();
        for (let i = 0; i < samples.length; i++) {
          const parsed = parsedList[i];
          if (parsed == null || typeof parsed !== 'object') continue;
          this._jsonCollectLeafPaths(parsed, [], (pathKey, path, v) => {
            let rec = pathStats.get(pathKey);
            if (!rec) { rec = { path: path.slice(), total: 0, url: 0, host: 0, sample: '' }; pathStats.set(pathKey, rec); }
            rec.total++;
            const vs = String(v);
            if (!rec.sample) rec.sample = vs;
            if (TL_URL_RE.test(vs)) rec.url++;
            else if (TL_HOSTNAME_RE.test(vs.trim())) rec.host++;
          }, 4);   // max depth
        }
        // Bounded enumeration of leaf paths → one proposal per distinct
        // leaf path, so the analyst can flatten an entire JSON column into
        // a set of CSV-like columns ("JSON → CSV"). URL / hostname paths
        // are already emitted above with their richer kind labels; all
        // other leaves fall through to the generic `json-leaf` proposal
        // here. Cap per-column to keep the Extract dialog readable on
        // pathological payloads.
        const JSON_LEAF_CAP = 60;
        let emittedLeaves = 0;
        for (const [, rec] of pathStats) {
          if (rec.total < Math.max(3, samples.length * 0.3)) continue;
          const isUrl = rec.url >= rec.total * 0.4;
          const isHost = !isUrl && rec.host >= rec.total * 0.4;
          if (isUrl) {
            proposals.push({
              kind: 'json-url', kindLabel: 'URL', sourceCol: c, path: rec.path,
              matchPct: rec.url * 100 / rec.total,
              proposedName: `${this._baseColumns[c] || 'col' + c}.${_tlJsonPathLabel(rec.path)}`,
              sample: rec.sample,
            });
          } else if (isHost) {
            proposals.push({
              kind: 'json-host', kindLabel: 'Hostname', sourceCol: c, path: rec.path,
              matchPct: rec.host * 100 / rec.total,
              proposedName: `${this._baseColumns[c] || 'col' + c}.${_tlJsonPathLabel(rec.path)}`,
              sample: rec.sample,
            });
          } else if (emittedLeaves < JSON_LEAF_CAP) {
            // Generic JSON leaf — lets the user flatten arbitrary nested
            // keys (`Events[*].EventID`, `response.status`, …) into
            // extracted columns via the Auto tab.
            proposals.push({
              kind: 'json-leaf', kindLabel: 'JSON leaf', sourceCol: c, path: rec.path,
              matchPct: rec.total * 100 / samples.length,
              proposedName: `${this._baseColumns[c] || 'col' + c}.${_tlJsonPathLabel(rec.path)}`,
              sample: rec.sample,
            });
            emittedLeaves++;
          }
        }

      } else {
        // Pipe-delimited Key=Value detection — catches EVTX Event Data
        // (`TargetUserName=foo | SubjectUserName=bar | …`), Sysmon-style
        // key=value strings, and any other column whose cells encode an
        // ad-hoc mini-schema the analyst would otherwise have to rip
        // apart with hand-rolled regex. Runs BEFORE the URL/host branch
        // so KV-dominant columns don't also try to match whole-cell URLs
        // (noisy on EVTX) — if we detect enough KV rows we emit per-field
        // proposals and skip straight to the next column.
        //
        // Heuristic: split each cell on ` | ` (the exact separator emitted
        // by EvtxRenderer) and count parts starting with an identifier +
        // `=`. If ≥ 50 % of sampled rows have ≥ 2 such pairs, tally field
        // names across the whole sample and emit one `kv-field` proposal
        // per field that appears in ≥ 30 % of rows (min 3 occurrences).
        const KV_KEY_RE = /^([A-Za-z_][\w.-]{0,63})=/;
        const fieldStats = new Map();
        let kvRows = 0;
        for (const s of samples) {
          const parts = s.v.split(' | ');
          let pairs = 0;
          for (const part of parts) {
            const m = KV_KEY_RE.exec(part);
            if (!m) continue;
            pairs++;
            const name = m[1];
            let rec = fieldStats.get(name);
            if (!rec) {
              rec = { count: 0, sample: '' };
              fieldStats.set(name, rec);
            }
            rec.count++;
            if (!rec.sample) {
              const val = part.slice(m[0].length);
              // Keep the sample on a single line — multi-line values
              // (`UserAccountControl=\n%%2080\n…`) render fine as a
              // preview once collapsed.
              rec.sample = val.replace(/\s+/g, ' ').trim() || '(empty)';
            }
          }
          if (pairs >= 2) kvRows++;
        }
        // EVTX: lower the KV-dominance and per-field thresholds so sparse
        // but forensically important fields surface. On generic logs the
        // stricter 50 %/2 % defaults still apply — so a column that is only
        // occasionally `key=value` won't spuriously trigger.
        const kvDomFrac = isEvtx ? 0.1 : 0.5;
        const kvDominant = kvRows >= Math.max(3, samples.length * kvDomFrac);
        if (kvDominant && fieldStats.size) {
          const KV_FIELD_CAP = 80;
          const minCount = isEvtx
            ? Math.max(2, Math.floor(samples.length * 0.01))
            : Math.max(3, Math.floor(samples.length * 0.02));
          const ranked = Array.from(fieldStats.entries())
            .filter(([, rec]) => rec.count >= minCount)
            .sort((a, b) => b[1].count - a[1].count)
            .slice(0, KV_FIELD_CAP);
          for (const [name, rec] of ranked) {
            proposals.push({
              kind: 'kv-field', kindLabel: 'Field', sourceCol: c, path: null,
              fieldName: name,
              matchPct: rec.count * 100 / samples.length,
              proposedName: `${this._baseColumns[c] || 'col' + c}.${name}`,
              sample: rec.sample,
              // On EVTX, pre-check only forensic-grade fields so Extract-all
              // lands a tight investigatable set. Non-EVTX columns default
              // to checked so the classic "extract everything" flow still works.
              preselect: isEvtx ? FORENSIC_EVTX_FIELDS.has(name) : true,
            });
          }
          continue;   // skip URL / host probing on KV-dominant columns
        }

        // Plain-text column: test URL + hostname patterns directly.
        let urlHits = 0, hostHits = 0;
        let urlSample = '', hostSample = '';
        for (const s of samples) {
          if (TL_URL_RE.test(s.v)) { urlHits++; if (!urlSample) urlSample = s.v; }
          else {
            const m = TL_HOSTNAME_INLINE_RE.exec(s.v);
            if (m && m[1] && m[1].indexOf('.') > 0) { hostHits++; if (!hostSample) hostSample = m[1]; }
          }
        }
        const total = samples.length;
        if (urlHits >= Math.max(3, total * 0.3)) {
          proposals.push({
            kind: 'text-url', kindLabel: 'URL', sourceCol: c, path: null,
            matchPct: urlHits * 100 / total,
            proposedName: `${this._baseColumns[c] || 'col' + c} (URL)`,
            sample: urlSample,
          });
        }
        if (hostHits >= Math.max(3, total * 0.3) && !urlHits) {
          proposals.push({
            kind: 'text-host', kindLabel: 'Hostname', sourceCol: c, path: null,
            matchPct: hostHits * 100 / total,
            proposedName: `${this._baseColumns[c] || 'col' + c} (host)`,
            sample: hostSample,
          });
        }
      }
    }
    proposals.sort((a, b) => b.matchPct - a.matchPct);
    return proposals;
  }


  // ── JSON drawer + extracted-column helpers ───────────────────────────────
  // Methods `_jsonCollectLeafPaths`, `_jsonPathGetWithStar`,
  // `_addJsonExtractedCol[NoRender]`, `_addRegexExtractNoRender`,
  // `_findDuplicateExtractedCol`, `_clearAllExtractedCols`,
  // `_uniqueColName`, `_removeExtractedCol`,
  // `_rebuildExtractedStateAndRender`, `_persistRegexExtracts` are
  // attached to TimelineView.prototype by `timeline-drawer.js`
  //.

  // ── Pivot ────────────────────────────────────────────────────────────────
  // Auto-pivot heuristic — pick sensible Rows / Cols / Aggregate selections
  // from a user-clicked column and (optionally) the current stack column,
  // expand the pivot section (it starts collapsed), write the choices into
  // the select widgets, and call `_buildPivot()`. Scrolls the result into
  // view with a brief flash so the user can see where it went.
  //
  // Heuristic (simple on purpose — pivot is ultimately interactive):
  //   - Rows     = clicked column (always).
  //   - Cols     = opts.colsCol if provided; else the current stack column
  //                if it differs from Rows and has 2..60 distinct values;
  //                else the first OTHER column with 2..60 distinct values,
  //                skipping the timestamp column and Rows.
  //   - Agg      = 'count' (the only aggregate that always makes sense for
  //                categorical x categorical).
  _autoPivotFromColumn(rowsCol, opts) {
    opts = opts || {};
    if (!Number.isInteger(rowsCol) || rowsCol < 0 || rowsCol >= this.columns.length) return;

    // Ensure column stats are fresh so the heuristic can read distinct counts.
    if (!this._colStats) {
      this._colStats = this._computeColumnStats(this._filteredIdx || new Uint32Array(0));
    }
    const stats = this._colStats;

    const MIN = 2, MAX = 60;
    const good = (ci) => {
      if (ci === rowsCol) return false;
      if (ci === this._timeCol) return false;
      const s = stats[ci]; if (!s) return false;
      return s.distinct >= MIN && s.distinct <= MAX;
    };

    let colsCol = Number.isInteger(opts.colsCol) ? opts.colsCol : null;
    if (colsCol == null && this._stackCol != null && good(this._stackCol)) {
      colsCol = this._stackCol;
    }
    if (colsCol == null) {
      // Pick the column with the most "interesting" cardinality — prefer
      // mid-range distinct counts (10..30 is ideal for a readable pivot).
      let bestCol = -1, bestScore = -Infinity;
      for (let c = 0; c < this.columns.length; c++) {
        if (!good(c)) continue;
        const d = stats[c].distinct;
        // Score = closeness to 15 (peak), capped. Prefer 5..30.
        const score = -Math.abs(d - 15);
        if (score > bestScore) { bestScore = score; bestCol = c; }
      }
      if (bestCol >= 0) colsCol = bestCol;
    }

    if (colsCol == null) {
      if (this._app) this._app._toast('No suitable pivot column found (need a column with 2–60 distinct values).', 'error');
      return;
    }

    // Wire up the pivot UI.
    const els = this._els;
    els.pvRows.value = String(rowsCol);
    els.pvCols.value = String(colsCol);
    els.pvAgg.value = 'count';
    els.pvAggCol.value = '-1';
    els.pvAggColWrap.style.display = 'none';

    // Uncollapse the pivot section (it defaults to collapsed).
    const pivotSec = this._root.querySelector('.tl-section-pivot');
    if (pivotSec && pivotSec.classList.contains('collapsed')) {
      pivotSec.classList.remove('collapsed');
      this._sections.pivot = false;
      TimelineView._saveSections(this._sections);
    }

    this._buildPivot();

    // Scroll into view + brief flash highlight.
    if (pivotSec && pivotSec.scrollIntoView) {
      pivotSec.scrollIntoView({ behavior: 'smooth', block: 'start' });
      pivotSec.classList.add('tl-section-flash');
      setTimeout(() => pivotSec.classList.remove('tl-section-flash'), 1200);
    }
  }

  _buildPivot() {
    const rowsCol = parseInt(this._els.pvRows.value, 10);
    const colsCol = parseInt(this._els.pvCols.value, 10);
    const aggOp = this._els.pvAgg.value;
    const aggCol = parseInt(this._els.pvAggCol.value, 10);
    if (rowsCol < 0 || colsCol < 0) {
      this._els.pvResultBody.innerHTML = '<div class="tl-pivot-empty">Pick Rows and Columns to build a pivot.</div>';
      return;
    }
    this._pivotSpec = { rows: rowsCol, cols: colsCol, aggOp, aggCol };
    TimelineView._savePivotSpec(this._pivotSpec);

    const idx = this._filteredIdx;
    const rowKeys = new Map(); // rowVal → index
    const colKeys = new Map(); // colVal → index
    const rowList = [];
    const colList = [];
    const rowKeyOf = new Array(idx.length);
    const colKeyOf = new Array(idx.length);

    for (let i = 0; i < idx.length; i++) {
      const rv = this._cellAt(idx[i], rowsCol);
      const cv = this._cellAt(idx[i], colsCol);
      if (!rowKeys.has(rv)) { rowKeys.set(rv, rowList.length); rowList.push(rv); }
      if (!colKeys.has(cv)) { colKeys.set(cv, colList.length); colList.push(cv); }
      rowKeyOf[i] = rowKeys.get(rv);
      colKeyOf[i] = colKeys.get(cv);
    }
    // Sort col keys by total, row keys by total, then cap to 50×50.
    const rowTotals = new Int32Array(rowList.length);
    const colTotals = new Int32Array(colList.length);
    for (let i = 0; i < idx.length; i++) {
      rowTotals[rowKeyOf[i]]++;
      colTotals[colKeyOf[i]]++;
    }
    const rowOrder = Array.from(rowList.keys()).sort((a, b) => rowTotals[b] - rowTotals[a]);
    const colOrder = Array.from(colList.keys()).sort((a, b) => colTotals[b] - colTotals[a]);
    const MAX = 50;
    const visibleRows = rowOrder.slice(0, MAX);
    const visibleCols = colOrder.slice(0, MAX);
    const rowMap = new Map(visibleRows.map((v, i) => [v, i]));
    const colMap = new Map(visibleCols.map((v, i) => [v, i]));

    // Build the aggregate matrix.
    const nR = visibleRows.length, nC = visibleCols.length;
    // For 'count' and 'sum' → Float64Array.
    // For 'distinct' → Array of Set<string> per cell.
    let mat;
    if (aggOp === 'distinct') {
      mat = new Array(nR * nC);
      for (let k = 0; k < mat.length; k++) mat[k] = null;
    } else {
      mat = new Float64Array(nR * nC);
    }

    // `rowMap` / `colMap` are keyed by INDEX into rowList/colList (not by the
    // raw cell value) — `rowKeyOf[i]` / `colKeyOf[i]` are already those
    // indices, so pass them straight through. Passing the resolved value
    // here silently missed on every row (empty pivot table, integer
    // headers) — see CONTRIBUTING for the history of this fix.
    for (let i = 0; i < idx.length; i++) {
      const rk = rowMap.get(rowKeyOf[i]);
      const ck = colMap.get(colKeyOf[i]);
      if (rk == null || ck == null) continue;  // in 'Other' bucket — skip for v1
      const cellIdx = rk * nC + ck;
      if (aggOp === 'count') mat[cellIdx]++;
      else if (aggOp === 'distinct' && aggCol >= 0) {
        let s = mat[cellIdx]; if (!s) { s = new Set(); mat[cellIdx] = s; }
        s.add(this._cellAt(idx[i], aggCol));
      } else if (aggOp === 'sum' && aggCol >= 0) {
        const n = parseFloat(this._cellAt(idx[i], aggCol));
        if (Number.isFinite(n)) mat[cellIdx] += n;
      }
    }

    // Render table.
    const cellVal = (rk, ck) => {
      const x = mat[rk * nC + ck];
      if (aggOp === 'distinct') return x ? x.size : 0;
      return x || 0;
    };
    let maxV = 0;
    for (let r = 0; r < nR; r++) for (let c = 0; c < nC; c++) {
      const v = cellVal(r, c); if (v > maxV) maxV = v;
    }
    const heat = (v) => {
      if (!maxV || v <= 0) return '';
      const pct = Math.min(1, v / maxV);
      return `background: rgb(var(--accent-rgb) / ${(0.05 + pct * 0.45).toFixed(3)});`;
    };

    // Resolve the visible-*-index arrays to their actual cell values for
    // display / drill-down / export. `visibleRows` / `visibleCols` are
    // arrays of indices into `rowList` / `colList`, NOT values.
    const visibleRowVals = visibleRows.map(i => rowList[i]);
    const visibleColVals = visibleCols.map(i => colList[i]);

    const tbl = document.createElement('table');
    tbl.className = 'tl-pivot-table';
    let html = '<thead><tr><th class="tl-pivot-corner"></th>';
    for (const cv of visibleColVals) html += `<th title="${_tlEsc(cv)}">${_tlEsc(cv === '' ? '(empty)' : this._ellipsis(cv, 30))}</th>`;
    if (colOrder.length > MAX) html += `<th class="tl-pivot-other" title="${colOrder.length - MAX} more columns not shown">…+${colOrder.length - MAX}</th>`;
    html += '</tr></thead><tbody>';
    for (let r = 0; r < nR; r++) {
      const rv = visibleRowVals[r];
      html += `<tr><th title="${_tlEsc(rv)}">${_tlEsc(rv === '' ? '(empty)' : this._ellipsis(rv, 30))}</th>`;
      for (let c = 0; c < nC; c++) {
        const v = cellVal(r, c);
        html += `<td data-r="${r}" data-c="${c}" style="${heat(v)}">${v ? v.toLocaleString() : ''}</td>`;
      }
      if (colOrder.length > MAX) html += '<td class="tl-pivot-other"></td>';
      html += '</tr>';
    }
    if (rowOrder.length > MAX) html += `<tr><th class="tl-pivot-other">…+${rowOrder.length - MAX} more rows</th><td colspan="${nC + (colOrder.length > MAX ? 1 : 0)}"></td></tr>`;
    html += '</tbody>';
    tbl.innerHTML = html;

    // Double-click a cell = filter-drill-down. Each add-clause commit
    // triggers a full re-parse + render cycle, but that's fine for a
    // user-initiated drill-down — we get the same render either way.
    tbl.addEventListener('dblclick', (e) => {
      const td = e.target.closest('td[data-r]');
      if (!td) return;
      const r = +td.dataset.r, c = +td.dataset.c;
      const rv = visibleRowVals[r]; const cv = visibleColVals[c];
      this._queryAddClause({ k: 'pred', colIdx: rowsCol, op: 'eq', val: String(rv) }, { dedupe: true });
      this._queryAddClause({ k: 'pred', colIdx: colsCol, op: 'eq', val: String(cv) }, { dedupe: true });
    });

    const summary = document.createElement('div');
    summary.className = 'tl-pivot-summary';
    summary.textContent = `${rowOrder.length.toLocaleString()} × ${colOrder.length.toLocaleString()} → showing ${nR} × ${nC}. Double-click a cell to drill down.`;

    this._els.pvResultBody.innerHTML = '';
    this._els.pvResultBody.appendChild(summary);
    const scroll = document.createElement('div');
    scroll.className = 'tl-pivot-scroll';
    scroll.appendChild(tbl);
    this._els.pvResultBody.appendChild(scroll);

    // Stash for CSV export. Expose the RESOLVED values (not the opaque
    // into-rowList indices) so `_exportPivotCsv` produces a human-readable
    // sheet.
    this._lastPivot = { rowsCol, colsCol, aggOp, aggCol, visibleRowVals, visibleColVals, nR, nC, cellVal };
  }

  // ── Exports / section actions ────────────────────────────────────────────
  _onSectionAction(act) {
    switch (act) {
      case 'chart-png': this._exportChartPng(this._els.chartCanvas, this._forensicFilename('chart', 'png')); break;
      case 'chart-csv': this._exportChartCsv(this._lastChartData, this._forensicFilename('buckets', 'csv')); break;
      case 'grid-csv': this._exportGridCsv(this._filteredIdx, this._forensicFilename('rows', 'csv')); break;
      case 'columns-csv': this._exportColumnsCsv(this._colStats, this._forensicFilename('top-values', 'csv')); break;
      case 'pivot-csv': this._exportPivotCsv(this._forensicFilename('pivot', 'csv')); break;
    }
  }

  // Build a forensic-flavoured filename for a timeline export. Shape:
  //
  //   {sourceStem}__{section}__{fromCompact}_to_{toCompact}.{ext}
  //
  // Where `fromCompact` / `toCompact` are compact UTC timestamps
  // (`YYYYMMDDTHHMMZ` — no seconds, no punctuation, trailing Z) covering
  // the data actually in the export: the current `_window` if the analyst
  // has narrowed the scrubber, else the full `_dataRange`. For numeric-axis
  // columns (ids / periods / years) the compact range falls back to
  // `num_{lo}_to_num_{hi}` with locale-free integer strings, so a file of
  // year-numbered rows doesn't emit misleading 1970 dates.
  //
  // If no timestamp column is chosen, or zero rows parsed, the range
  // segment is omitted — `{sourceStem}__{section}.{ext}`.
  //
  // The source stem is sanitised: non-filename-safe characters become `_`,
  // length capped at 80 chars so the full name stays well under the ~255-
  // byte OS limit.
  _forensicFilename(section, ext) {
    const stem = this._forensicSourceStem();
    const range = this._forensicRangeSegment();
    const parts = [stem, section];
    if (range) parts.push(range);
    return parts.join('__') + '.' + ext;
  }

  _forensicSourceStem() {
    const raw = (this.file && this.file.name) ? String(this.file.name) : '';
    let stem = raw;
    const dot = stem.lastIndexOf('.');
    if (dot > 0) stem = stem.slice(0, dot);
    // Replace filename-unsafe characters (Windows + POSIX reserved) + controls.
    stem = stem.replace(/[\\/:*?"<>|\x00-\x1f]+/g, '_').trim();
    if (!stem) stem = 'timeline';
    if (stem.length > 80) stem = stem.slice(0, 80);
    return stem;
  }

  // Compact UTC formatter — `YYYYMMDDTHHMMZ`. Minute-level precision
  // deliberately (seconds are rarely meaningful on a range spanning
  // hours / days and make filenames noisier to skim).
  _forensicCompactUtc(ms) {
    if (!Number.isFinite(ms)) return '';
    const d = new Date(ms);
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}`
      + `T${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}Z`;
  }

  // Compact numeric formatter — strips punctuation so filenames stay
  // shell-safe across platforms. Large magnitudes pass through as plain
  // integers (no thousand-separators), fractional values round to 4 dp.
  _forensicCompactNum(v) {
    if (!Number.isFinite(v)) return '';
    if (Number.isInteger(v)) return String(v);
    return String(Math.round(v * 10000) / 10000);
  }

  _forensicRangeSegment() {
    const dr = this._dataRange; if (!dr) return '';
    const lo = this._window ? this._window.min : dr.min;
    const hi = this._window ? this._window.max : dr.max;
    if (!Number.isFinite(lo) || !Number.isFinite(hi)) return '';
    if (this._timeIsNumeric) {
      const a = this._forensicCompactNum(lo);
      const b = this._forensicCompactNum(hi);
      if (!a || !b) return '';
      return `num_${a}_to_num_${b}`;
    }
    const a = this._forensicCompactUtc(lo);
    const b = this._forensicCompactUtc(hi);
    if (!a || !b) return '';
    return `${a}_to_${b}`;
  }


  _exportChartPng(canvas, filename) {
    if (!canvas) return;
    canvas.toBlob((blob) => {
      if (!blob) return;
      if (window.FileDownload && typeof window.FileDownload.downloadBlob === 'function') {
        window.FileDownload.downloadBlob(blob, filename, 'image/png');
      }
    }, 'image/png');
  }

  _exportChartCsv(data, filename) {
    if (!data) return;
    const { buckets, bucketCount, stackKeys, viewLo, bucketMs } = data;
    const k = stackKeys ? stackKeys.length : 1;
    const header = ['Bucket start (UTC)', 'Bucket end (UTC)'];
    if (stackKeys && stackKeys.length) for (const s of stackKeys) header.push(s);
    else header.push('Count');
    const lines = [_tlCsvRow(header)];
    for (let b = 0; b < bucketCount; b++) {
      const lo = viewLo + b * bucketMs;
      const hi = lo + bucketMs;
      const row = [_tlFormatFullUtc(lo, this._timeIsNumeric), _tlFormatFullUtc(hi, this._timeIsNumeric)];
      for (let j = 0; j < k; j++) row.push(String(buckets[b * k + j]));
      lines.push(_tlCsvRow(row));
    }
    if (window.FileDownload) window.FileDownload.downloadText(lines.join('\r\n'), filename, 'text/csv');
  }

  _exportGridCsv(idx, filename) {
    if (!idx || !idx.length) return;
    const cols = this.columns;
    const lines = [_tlCsvRow(cols)];
    for (let i = 0; i < idx.length; i++) {
      const di = idx[i];
      const row = new Array(cols.length);
      for (let c = 0; c < cols.length; c++) row[c] = this._cellAt(di, c);
      lines.push(_tlCsvRow(row));
    }
    if (window.FileDownload) window.FileDownload.downloadText(lines.join('\r\n'), filename, 'text/csv');
  }

  _exportColumnsCsv(stats, filename) {
    if (!stats) return;
    const lines = [_tlCsvRow(['Column', 'Value', 'Count'])];
    for (let c = 0; c < this.columns.length; c++) {
      const s = stats[c]; if (!s) continue;
      for (const [val, cnt] of s.values) {
        lines.push(_tlCsvRow([this.columns[c] || '', val, String(cnt)]));
      }
    }
    if (window.FileDownload) window.FileDownload.downloadText(lines.join('\r\n'), filename, 'text/csv');
  }

  _exportPivotCsv(filename) {
    const p = this._lastPivot; if (!p) return;
    const header = [''];
    for (const cv of p.visibleColVals) header.push(cv);
    const lines = [_tlCsvRow(header)];
    for (let r = 0; r < p.nR; r++) {
      const row = [p.visibleRowVals[r]];
      for (let c = 0; c < p.nC; c++) row.push(String(p.cellVal(r, c)));
      lines.push(_tlCsvRow(row));
    }
    if (window.FileDownload) window.FileDownload.downloadText(lines.join('\r\n'), filename, 'text/csv');
  }
}


