'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view.js — TimelineView class core.
//
// Split out of the legacy app-timeline.js monolith. Owns all
// DOM + state for a single loaded file: virtual scroll grid, scrubber,
// stacked-bar histogram, top-values cards, query chips, pivot table,
// extraction dialog, exports.
//
// The static factories `fromCsvAsync` / `fromEvtx` / `fromSqlite`
// have been hoisted into a sibling mixin (timeline-view-factories.js,
// B2a) so this file can stay focused on instance state + lifecycle.
// They still construct via `new TimelineView({...})` and reach into
// the same column-/row-shape contract.
//
// Prototype mixins extend this class AFTER its declaration:
//   - timeline-view-factories.js → static factories (B2a).
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

  // ── Construction ─────────────────────────────────────────────────────────
  constructor(opts) {
    this.file = opts.file;
    this._baseColumns = opts.columns || [];
    // Phase 3+4 row container — TimelineView reads cells exclusively
    // via `this.store.getCell(rowIdx, colIdx)` (see `src/row-store.js`).
    // The legacy `string[][]` layout is gone from this class entirely;
    // GridViewer reads through a per-render `TimelineRowView` adapter
    // (see `src/app/timeline/timeline-row-view.js`) so no full row
    // matrix is ever materialised.
    //
    // Phase 8: `opts.store` is REQUIRED. Every caller (the worker
    // path's `_buildTimelineViewFromWorker` and the three sync
    // factories `fromCsvAsync` / `fromEvtx` / `fromSqlite`) builds a
    // `RowStore` via `RowStoreBuilder` or `RowStore.fromStringMatrix`
    // before invoking the constructor. Throwing here on a missing
    // store points at the call site immediately rather than producing
    // a zero-row view that silently turns into a "file failed to
    // parse" toast far downstream. Wrap legacy `string[][]` callers
    // via `RowStore.fromStringMatrix(columns, rows)` (matches the
    // analogous shape error in `GridViewer.setRows`).
    if (!opts.store || typeof opts.store.getCell !== 'function') {
      throw new TypeError(
        'TimelineView: opts.store is required (RowStore-shaped). ' +
        'Wrap legacy `string[][]` callers via ' +
        '`RowStore.fromStringMatrix(columns, rows)`.',
      );
    }
    this.store = opts.store;
    this.formatLabel = opts.formatLabel || '';
    this.truncated = !!opts.truncated;
    this.originalRowCount = opts.originalRowCount || this.store.rowCount;
    this._fileKey = _tlFileKey(this.file);

    // EVTX-only side-channel — the parsed event array (same indices as
    // `this.store.getRow(i)`) and the Sigma-style `analyzeForSecurity`
    // findings object. Used by the Detections + Entities sections below
    // to render Sigma-rule hits, click-to-filter on Event ID, and entity
    // pivots without re-parsing the file. Both are `null` for CSV / TSV.
    //
    // INVARIANT: `_evtxEvents.length === store.rowCount`. Consumers in
    // `timeline-summary.js` and `timeline-detections.js` walk
    // `_evtxEvents[i]` in parallel with `_timeMs[i]` and
    // `store.getRow(i)`. A length mismatch here means the sync EVTX
    // factory (or any future caller) forgot to slice `events` to the
    // truncated `list.length` — we'd rather throw at construction than
    // produce per-row `undefined` reads downstream. See
    // `fromEvtx` above and `timeline.worker.js::_parseEvtx`'s
    // `trimmedEvents`.
    this._evtxEvents = Array.isArray(opts.evtxEvents) ? opts.evtxEvents : null;
    if (this._evtxEvents && this._evtxEvents.length !== this.store.rowCount) {
      throw new Error(
        'TimelineView: evtxEvents.length (' + this._evtxEvents.length +
        ') must equal store.rowCount (' + this.store.rowCount + '); ' +
        'caller forgot to slice events to the truncated list.length.',
      );
    }
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
      : _tlAutoDetectTimestampCol(this._baseColumns, this.store);
    this._stackCol = Number.isInteger(opts.defaultStackColIdx)
      ? opts.defaultStackColIdx
      : _tlAutoDetectStackCol(this._baseColumns, this.store, this._timeCol);
    this._stackColorMap = null;
    this._buildStableStackColorMap();
    this._bucketId = TimelineView._loadBucketPref();
    this._timeMs = new Float64Array(this.store.rowCount);
    // `_timeIsNumeric` — switches the axis / bucket / tick formatters from
    // wall-clock ms into a plain numeric domain. Set by `_parseAllTimestamps`
    // based on the column's parse-ability. When true, `_timeMs[i]` holds the
    // raw numeric value (NOT milliseconds since epoch).
    this._timeIsNumeric = false;
    // ── TimelineDataset wrapper ─────────────────────────────────────────────
    // Shares references to `store` / `_timeMs` / `_evtxEvents` /
    // `_extractedCols` and re-asserts the `length === rowCount`
    // cardinality invariant on every mutation. Read-side consumers
    // (timeline-summary, timeline-detections, the grid-render path)
    // are migrating to `_dataset.cellAt` / `timeAt` / `evtxAt` /
    // `extractedAt` (B1b/B1c) so that any future fifth parallel-array
    // slot has exactly one place to land. Until that migration is
    // complete, the slots above (`this._timeMs` / `this._evtxEvents` /
    // `this._extractedCols`) and the dataset's internal references
    // point at the SAME arrays — `_parseAllTimestamps` mutates the
    // typed array in place and `_extractedCols.push(...)` is observed
    // by the dataset. See `src/app/timeline/timeline-dataset.js` for
    // the contract.
    this._dataset = new TimelineDataset({
      store: this.store,
      timeMs: this._timeMs,
      evtxEvents: this._evtxEvents,
      extractedCols: this._extractedCols,
    });
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

    // Grid sort cache — invalidated by _invalidateGridCache() whenever
    // _timeMs content changes. Avoids the O(n log n) re-sort on
    // filter-clear for 1M-row datasets. Phase 4 dropped the matching
    // `_cachedRowsConcat` materialisation cache: GridViewer now reads
    // cells through a `TimelineRowView` adapter on the underlying
    // RowStore, so re-renders cost no allocations beyond the small
    // adapter object itself.
    this._sortedFullIdx = null;

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
    // Per-file grid column display-order (drag-reorder persistence).
    // Array of column NAMES in display order, or `null` for identity.
    // Resolved to real indices and applied via
    // `GridViewer._setColumnOrder` on grid mount + after every
    // `_updateColumns` call so it survives auto-extract.
    this._gridColOrder = TimelineView._loadGridColOrderFor(this._fileKey);
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
    // Auto-extract idle scheduler bookkeeping — populated by
    // `_autoExtractBestEffort` when it schedules the scan + per-proposal
    // apply ticks. Stored as `{ handle, cancel }` so `destroy()` can
    // pair the cancel API with whichever scheduler the runtime picked
    // (`requestIdleCallback` vs the `setTimeout` fallback for Safari).
    this._autoExtractIdleHandle = null;
    this._pendingTasks = new Set();
    this._openPopover = null;
    this._openDialog = null;

    this._buildDOM();
    this._wireEvents();
    this._rebuildSusBitmap();
    this._rebuildDetectionBitmap();
    this._recomputeFilter();
    this._scheduleRender(['chart', 'scrubber', 'chips', 'grid', 'columns', 'detections', 'entities', 'pivot', 'sections']);
    // Best-effort auto-extract — run one tick later so the initial render
    // has painted (the analyst sees the grid first, then any high-coverage
    // extracted columns slide in next to it). Single-shot per file: the
    // `loupe_timeline_autoextract_done` marker is checked + set inside
    // `_autoExtractBestEffort` so deleted columns never come back on
    // reopen. The full Extract Values dialog still exists for analysts
    // who want to opt into lower-coverage proposals manually.
    setTimeout(() => this._autoExtractBestEffort(), 60);
    // GeoIP enrichment runs on the same post-mount tick as auto-extract,
    // but slightly later so its idempotence-marker check sees any
    // analyst-deleted columns from auto-extract first. The mixin
    // (`timeline-view-geoip.js`) reads `this._app.geoip` for the active
    // provider and is a no-op when `_app` isn't wired yet (which happens
    // briefly on the synchronous factory path — `_app` is assigned by
    // the router after `view.root()` is mounted). The router calls
    // `_runGeoipEnrichment()` again after stamping `_app` for that case.
    setTimeout(() => {
      if (typeof this._runGeoipEnrichment === 'function') {
        try { this._runGeoipEnrichment(); } catch (_) { /* enrichment is additive */ }
      }
    }, 100);
  }


  root() { return this._root; }

  destroy() {
    if (this._destroyed) return;
    this._destroyed = true;
    cancelAnimationFrame(this._colStatsRaf);
    this._colStatsRaf = 0;
    // Cancel any in-flight auto-extract idle/timeout tick. The handle
    // record carries its own cancel fn so we don't have to remember
    // which scheduler we picked (rIC vs setTimeout fallback). Without
    // this, a fast tab-close mid-run would leave the callback to fire
    // against a destroyed view → `_addRegexExtractNoRender` against a
    // null grid host.
    if (this._autoExtractIdleHandle) {
      try { this._autoExtractIdleHandle.cancel(); } catch (_) { /* noop */ }
      this._autoExtractIdleHandle = null;
    }
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
    this.store = null;
    this._baseColumns = null;
    this._extractedCols = null;
    // The dataset wrapper holds references to `store` / `_timeMs` /
    // `_evtxEvents` / `_extractedCols` — null it explicitly so the
    // GC doesn't keep the parsed data alive via the dataset alone.
    this._dataset = null;
    this._colStats = null;
    this._sortedFullIdx = null;
    this._filteredIdx = null;
    this._susBitmap = null;
    this._detectionBitmap = null;
    this.file = null;
    this._evtxEvents = null;
    this._evtxFindings = null;
    this._app = null;
  }

  // ── Columns accessor (base + extracted) ─────────────────────────────────
  // Delegated to `TimelineDataset.allColumnNames()` — the dataset
  // owns the base+extracted concatenation, and going through it
  // means the base/extracted split has exactly one source of truth.
  // Falls back to the legacy slot path if `_dataset` is null (the
  // dispose state — every consumer should already be inert at that
  // point, but `columns` is read defensively from a few error paths).
  get columns() {
    if (this._dataset) return this._dataset.allColumnNames();
    if (!this._extractedCols || !this._extractedCols.length) return this._baseColumns;
    const out = this._baseColumns.slice();
    for (const e of this._extractedCols) out.push(e.name);
    return out;
  }

  // `_isExtractedCol` / `_extractedColFor` use the dataset's
  // `baseColCount` (which equals `this.store.colCount` — same number
  // as the legacy `this._baseColumns.length`, just sourced from the
  // canonical RowStore).
  _isExtractedCol(colIdx) {
    const baseLen = this._dataset ? this._dataset.baseColCount : this._baseColumns.length;
    return colIdx >= baseLen;
  }
  _extractedColFor(colIdx) {
    const baseLen = this._dataset ? this._dataset.baseColCount : this._baseColumns.length;
    const cols = this._dataset ? this._dataset.extractedCols : this._extractedCols;
    return cols[colIdx - baseLen] || null;
  }

  // Cell access — unified base + extracted lookup. Returns a string or ''.
  // Delegates to the dataset's `cellAt` so the base/extracted dispatch
  // has one implementation. Falls back to the inline lookup only when
  // the dataset is null (post-dispose) — every live read goes through
  // the dataset.
  _cellAt(dataIdx, colIdx) {
    if (this._dataset) return this._dataset.cellAt(dataIdx, colIdx);
    if (colIdx < this._baseColumns.length) {
      return this.store.getCell(dataIdx, colIdx);
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
    if (!this.store || !this.store.rowCount) return false;
    const N = Math.min(this.store.rowCount, 200);
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
  //
  // The ~30 `_loadXxx` / `_saveXxx` static helpers live in the
  // sibling mixin `timeline-view-persist.js` (B2b). Callers reach
  // them via `TimelineView._loadBucketPref()` etc. unchanged.

  // ── Filter + chart-data pipeline ────────────────────────────────────
  //
  // The timestamp parser, query AST application, full-recompute
  // filter loop, sus + detection bitmap rebuilds, window-only fast
  // path, column-stats (sync + async), distinct-values lookup,
  // ignore-one-column index helper, bucket-size resolver, and
  // `_computeChartData` (the histogram bucketer) live in the sibling
  // mixin `timeline-view-filter.js` (B2c). Methods attach to the
  // prototype via `Object.assign(TimelineView.prototype, {...})`.

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

    // Query bar — mount point for TimelineQueryEditor. The editor itself
    // is constructed in `_wireEvents` (after columns are known) and its
    // `.root` is appended into this container. Kept as a thin shell here
    // so the layout ordering (scrubber → chart → query → chips → grid)
    // is visible from `_buildDOM`.
    //
    // The active time window readout (formerly a separate
    // `tl-range-banner` strip above this mount point) now lives INSIDE
    // the query bar as a compact two-line button — see
    // `TimelineQueryEditor`'s `setWindow` API. Scrubber / chart-drag
    // call sites push window updates through that API; the editor's
    // popover commits user input back via `onWindowChange`.
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

    // Construct the query editor now that columns / stats are available
    // (suggestion lookups consult `this.columns` + `_distinctValuesFor`).
    // The editor's DOM `.root` is appended into the `.tl-query-mount`
    // container prepared by `_buildDOM`.
    //
    //   onChange         → live re-parse + filter (debounced).
    //   onCommit         → persist string under `loupe_timeline_query` +
    //                      push onto history ring.
    //   onWindowChange   → datetime-range widget commits a new {min,max}
    //                      (or null = "Any time"). Replaces the legacy
    //                      `tl-range-banner` Clear-button wiring; same
    //                      semantics — window-only change, fast path via
    //                      `_applyWindowOnly()`.
    //   formatters       → pure helpers the widget uses to render the
    //                      compact button + popover. We pass live
    //                      lambdas for `isNumeric` / `dataRange` because
    //                      both flip when the analyst picks a new time
    //                      column from the toolbar.
    this._queryEditor = new TimelineQueryEditor({
      view: this,
      initialValue: this._queryStr || '',
      initialWindow: this._window,
      onChange: (q) => this._applyQueryString(q),
      onCommit: (q) => TimelineView._saveQueryFor(this._fileKey, q),
      onWindowChange: (win) => {
        this._window = win;
        this._applyWindowOnly();
        this._scheduleRender(['scrubber', 'chart', 'chips', 'grid', 'columns']);
      },
      formatters: {
        formatTimestamp: _tlFormatFullUtc,
        formatDuration: _tlFormatDuration,
        formatNumeric: _tlFormatNumericTick,
        parseRelative: _tlParseRelative,
        isNumeric: () => !!this._timeIsNumeric,
        dataRange: () => this._dataRange,
      },
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

  // ── Auto-extract (best-effort + scanner) ────────────────────────────────
  //
  // The silent first-open auto-extract pass and the heuristic scanner that
  // proposes JSON-leaf / URL / URL-part / text-host extractions are
  // hoisted into `timeline-view-autoextract.js` (a sibling prototype
  // mixin loaded by `scripts/build.py` AFTER `timeline-drawer.js` because
  // it calls `_addJsonExtractedColNoRender` / `_addRegexExtractNoRender`
  // / `_rebuildExtractedStateAndRender`). The methods
  //
  //   _autoExtractBestEffort, _applyAutoProposal, _autoExtractScan
  //
  // are still resolved on the `TimelineView` prototype via `Object.assign`
  // and remain reachable as `this._autoExtractBestEffort()` etc. from
  // every other method here. The Auto tab inside the Extraction dialog
  // (in `timeline-view-popovers.js`) consumes `_autoExtractScan` directly.


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
    this._gridColOrder = null;
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
        this._timeCol = _tlAutoDetectTimestampCol(this._baseColumns, this.store);
        if (this._els && this._els.timeColSelect) {
          this._els.timeColSelect.value = this._timeCol == null ? '-1' : String(this._timeCol);
        }
        this._parseAllTimestamps();
        this._dataRange = this._computeDataRange();
      }
      // Route through the dataset's mutation API — `clearExtractedCols`
      // zero-lengths the SHARED array in place. A naive
      // `this._extractedCols = []` would replace the reference and
      // silently desync the dataset (the exact failure class B1d
      // closes off).
      this._dataset.clearExtractedCols();
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
      // Window readout lives inside the query bar now (compact button
      // on the editor's left edge). Pushing the current `_window` here
      // keeps the button in sync with scrubber/chart drags, the Reset
      // button, and chip-driven re-clips. The editor itself commits
      // user input back via `onWindowChange` (wired in `_wireEvents`).
      if (set.has('chips') && this._queryEditor) this._queryEditor.setWindow(this._window);
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
    const total = this.store.rowCount;
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

  // ── Chart paint stack (scrubber + chart + cursor + rubber-band + legend) ─
  //
  // The 19 chart-related methods (`_renderScrubber`,
  // `_installScrubberDrag`, `_paintScrubberCursor`, `_renderChart`,
  // `_buildStableStackColorMap`, `_renderChartInto`,
  // `_paintChartCursorFor`, `_findNearestDataIdxForTime`,
  // `_scrollGridToCursorIdx`, `_installCursorDrag`,
  // `_updateCursorFromGridScroll`, `_setCursorDataIdx`,
  // `_onChartClick`, `_installChartDrag`, `_onChartHover`,
  // `_handleLegendClick`, `_handleLegendDbl`, `_handleLegendContext`,
  // `_installChartResizeDrag`) are hoisted into
  // `timeline-view-render-chart.js` (a sibling prototype mixin loaded
  // by `scripts/build.py` after this file). They remain reachable as
  // `this._renderChart()` etc. via prototype dispatch.
  //
  // Stays here:
  //   • `_scheduleRender` (rAF-coalesced per-section dispatcher) and
  //     `_installSplitterDrag` (chart-vs-grid divider) — both cross
  //     the chart and grid surfaces, so neither belongs in a single
  //     render mixin.

  // ── Query AST + chips strip ─────────────────────────────────────────────
  //
  // The chips renderer + every query-AST mutator (the click-pivot
  // surface that builds the query string from grid / chart / column
  // clicks), plus chip-operation wrappers, plus Ctrl+Click
  // multi-select helpers, are hoisted into
  // `timeline-view-query-chips.js` (a sibling prototype mixin loaded
  // by `scripts/build.py` after this file). The 21 methods
  //
  //   _renderChips, _queryCurrentAst, _queryTopLevelClauses,
  //   _queryClausesToAst, _queryCommitClauses, _clauseTargetsCol,
  //   _queryAddClause, _queryDropContradictions,
  //   _queryToggleEqClause, _queryToggleNeClause,
  //   _queryReplaceContainsForCol, _queryReplaceEqForCol,
  //   _queryReplaceNotInForCol, _queryReplaceAllForCol,
  //   _queryRemoveClausesForCols, _addOrToggleChip,
  //   _addContainsChipsReplace, _replaceEqChipsForCol,
  //   _accumulateCtrlSelect, _commitCtrlSelect, _clearCtrlSelect,
  //   _togglePinCol
  //
  // remain reachable as `this._addOrToggleChip(...)` etc. via
  // prototype dispatch.

  // ── Popovers / menus / dialogs ───────────────────────────────────────────
  //
  // The Add-Sus popover, right-click row context menu, column header menu,
  // and the multi-tab Extraction dialog are hoisted into
  // `timeline-view-popovers.js` (a sibling prototype mixin loaded by
  // `scripts/build.py` immediately after this file). The methods
  //
  //   _openAddSusPopover, _openRowContextMenu, _closePopover,
  //   _openColumnMenu, _closeDialog, _openExtractionDialog
  //
  // are still resolved on the `TimelineView` prototype via `Object.assign`
  // and are therefore reachable as `this._openColumnMenu(...)` etc. from
  // every other method on this class.
  //
  // The tiny utilities `_ellipsis`, `_copyToClipboard`, `_positionFloating`
  // remain on this class — they're shared with the chart and grid render
  // paths and centralising them in the popovers mixin would invert the
  // dependency direction.


  // ── Grid + column top-values cards ──────────────────────────────────────
  //
  // The grid table mount + the column-cards strip are hoisted into
  // `timeline-view-render-grid.js` (a sibling prototype mixin loaded by
  // `scripts/build.py` after this file). The 11 methods
  //
  //   _renderGrid, _invalidateGridCache, _renderGridInto,
  //   _renderColumns, _paintColumnCards, _commitCardOrder,
  //   _susValsForCol, _cardSpanFor, _cardSizeSave,
  //   _installCardResize, _columnsGridGeometry
  //
  // remain reachable as `this._renderGrid()` etc. via prototype dispatch.
  //
  // Detection rendering (`_renderDetections`, `_renderEntities`,
  // `_collectEntities`, `_pivotOnEntity`, `_pivotAnyContainsToggle`)
  // continues to live in the pre-existing `timeline-detections.js`
  // sibling mixin — unchanged by B2f2.

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




  // ── JSON drawer + extracted-column helpers ───────────────────────────────
  // Methods `_jsonCollectLeafPaths`, `_jsonPathGetWithStar`,
  // `_addJsonExtractedCol[NoRender]`, `_addRegexExtractNoRender`,
  // `_findDuplicateExtractedCol`, `_clearAllExtractedCols`,
  // `_uniqueColName`, `_removeExtractedCol`,
  // `_rebuildExtractedStateAndRender`, `_persistRegexExtracts` are
  // attached to TimelineView.prototype by `timeline-drawer.js`
  //.

  // ── Pivot + exports ─────────────────────────────────────────────────────
  //
  // The pivot-table auto-pick + builder, the per-section "⋯" /
  // export menu dispatcher (`_onSectionAction`), the
  // `_forensic*` filename helpers, and every CSV / PNG exporter
  // (`_exportChartPng`, `_exportChartCsv`, `_exportGridCsv`,
  // `_exportColumnsCsv`, `_exportPivotCsv`) are hoisted into
  // `timeline-view-export.js` (a sibling prototype mixin loaded by
  // `scripts/build.py` after this file). The 13 methods
  //
  //   _autoPivotFromColumn, _buildPivot, _onSectionAction,
  //   _forensicFilename, _forensicSourceStem,
  //   _forensicCompactUtc, _forensicCompactNum,
  //   _forensicRangeSegment, _exportChartPng, _exportChartCsv,
  //   _exportGridCsv, _exportColumnsCsv, _exportPivotCsv
  //
  // remain reachable as `this._buildPivot()` etc. via prototype
  // dispatch.
}


