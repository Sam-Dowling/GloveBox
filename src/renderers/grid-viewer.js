'use strict';
// ════════════════════════════════════════════════════════════════════════════
// grid-viewer.js — shared virtual-scroll grid
//
// Single primitive consumed by CSV, EVTX, XLSX, SQLite, and JSON-array
// renderers.
//
// Design invariants:
//
//   1. FIXED ROW HEIGHT. Every body row is exactly `ROW_HEIGHT` px. Total
//      scrollable height = `rowCount * ROW_HEIGHT` — O(1). No dynamic
//      detail-height math, no spacer arithmetic, no rAF-driven height
//      remeasure re-render. The whole "spacing glitch on fast scroll" and
//      "flash disappears after height remeasure" bug class cannot happen.
//
//   2. ABSOLUTE-POSITIONED ROWS inside a `position:relative; height: rowCount
//      * ROW_HEIGHT` sizer. Each row lives at `top: dataIdx * ROW_HEIGHT`.
//      Scroll math is trivial division; visible-range math is trivial
//      addition. No accumulator loop over `state.expandedRows`.
//
//   3. ROW DETAIL LIVES IN A RIGHT-HAND DRAWER, never inline. Opening /
//      closing / switching the drawer row does not change any grid row's
//      height, never invalidates the sizer, never fires a re-render of any
//      other row. The drawer width is independently resizable and persisted.
//
//   4. ONE HIGHLIGHT STATE, ONE TIMER. `state.highlight` is a single object
//      `{ mode: 'flash'|'ioc'|'yara', dataIdx, payload, clearAt, timer,
//      onExpire }`. Every render reads state and decorates fresh DOM.
//      Setting a new highlight cancels the previous one atomically; there
//      is no way for two conflicting highlight groups to coexist and race.
//
//   5. SCROLL IS rAF-DRIVEN, NEVER scrollend-BASED. scrollToRow computes
//      the target, picks smooth or instant based on distance, then resolves
//      on `requestAnimationFrame(requestAnimationFrame(…))`. No 1 s
//      safety-timeout stall, no polyfill race with scroll events.
//
//   6. ONE-SHOT ROW HAND-OFF. The caller passes a finished
//      `RowStore`-shaped container via `opts.store` (constructor) or
//      `setRows(store, ...)`. Streaming CSV / TSV parses build the
//      store via `RowStoreBuilder` and call `setRows` exactly once on
//      EOF. The grid re-renders only the visible window, so even a
//      1 M-row hand-off paints in <50 ms.
//
//   7. destroy() IS MANDATORY AND COMPLETE. Cancels all timers, rAFs,
//      disconnects the ResizeObserver, empties caches, removes listeners.
//      `App` calls it whenever a new file replaces the current view so
//      large-file-after-large-file workflows don't leak handlers.
//
// Back-compatible API (the sidebar click-to-focus engine uses these names
// verbatim — see src/app/app-sidebar-focus.js). The root DOM element
// exposes `_csvFilters = { ... }` and `_rawText`.
//
// ════════════════════════════════════════════════════════════════════════════
class GridViewer {
  /**
   * @param {{
   *   columns: string[],                 // header row
   *   rows:    string[][],               // body rows (cells per row)
   *   rowSearchText?: string[],          // parallel array of `rows[i].join(' ').toLowerCase()` for fast filter/IOC search
   *   rowOffsets?: {start:number,end:number}[],  // byte offsets into rawText — enables YARA offset→row mapping
   *   rawText?: string,                  // full source text; used by sidebar IOC extraction & YARA mapping
   *   className?: string,                // extra class on root (default 'csv-view' for sidebar compatibility)
   *   infoText?: string,                 // header info bar ("N rows × M cols · delimiter: Comma")
   *   truncationNote?: string,           // "⚠ Showing first N of M rows" banner below the grid
   *   emptyMessage?: string              // rendered when rows.length === 0
   * }} opts
   */
  constructor(opts) {
    this.columns = opts.columns || [];
    // Row container — every caller (timeline, csv, sqlite, evtx, xlsx,
    // json) hands GridViewer a RowStore-shaped object exposing
    // `rowCount`, `getCell(r, c)`, `getRow(r)`. The legacy `string[][]`
    // path was retired in Phase 4c. Internally cells are read through
    // `_rowCount()` / `_rowAt(r)` / `_cellAt(r, c)` (see the accessor
    // block immediately below the constructor) so a future container
    // swap only touches three lines.
    if (!opts.store || typeof opts.store.getCell !== 'function') {
      throw new TypeError(
        'GridViewer: `opts.store` is required and must expose `rowCount` / `getCell` / `getRow` ' +
        '(use `RowStore.fromStringMatrix(columns, rows)` for sync builders or `RowStore.empty(columns)` ' +
        'for streaming construction).',
      );
    }
    this.store = opts.store;
    // `rowSearchText` is the per-row pre-joined lowercase text cache used
    // by the filter-bar substring match. The cache earns its ~3× memory
    // cost only when the grid filter bar is the primary entry point —
    // which is true for CSV / EVTX / SQLite / XLSX / JSON renderers
    // but NOT for the timeline (its query DSL bypasses the filter
    // bar). Boolean `searchTextCache` — `true` opts into the eager
    // pre-build + lazy fill via `_scheduleIdleSearchTextBuild`, `false`
    // (default) resolves on the fly inside `_rowMatchesQuery`. Phase
    // 4c collapsed the previous `'auto'|'always'|'never'` tri-state
    // since post-single-mode there were only two distinct behaviours.
    this._searchTextCache = !!opts.searchTextCache;
    this.rowSearchText = this._searchTextCache
      ? (opts.rowSearchText || null)
      : null;
    this.rowOffsets = opts.rowOffsets || null;
    this.rawText = opts.rawText || '';
    this._rootClass = opts.className || 'csv-view';
    this._infoText = opts.infoText || '';
    this._truncNote = opts.truncationNote || '';
    this._emptyMessage = opts.emptyMessage || 'Empty file.';
    // Optional hooks — let format-specific renderers (EVTX, XLSX, SQLite,
    // JSON) reuse the virtual-scroll + drawer + highlight core while still
    // owning their own toolbar and drawer-body layout:
    //   detailBuilder : (dataIdx, row, cols) => HTMLElement   // drawer body
    //   hideFilterBar : bool   // suppress the built-in search input
    //   extraToolbarEls : HTMLElement[]   // prepended above the filter bar
    //   rowTitle      : (dataIdx) => string   // drawer heading override
    //   cellText      : (dataIdx, colIdx, rawCell) => string  // display formatter
    //   cellClass     : (dataIdx, colIdx, rawCell) => string|null  // extra class
    this._detailBuilder = typeof opts.detailBuilder === 'function' ? opts.detailBuilder : null;
    this._hideFilterBar = !!opts.hideFilterBar;
    this._extraToolbarEls = Array.isArray(opts.extraToolbarEls) ? opts.extraToolbarEls : [];
    this._rowTitleFn = typeof opts.rowTitle === 'function' ? opts.rowTitle : null;
    this._cellTextFn = typeof opts.cellText === 'function' ? opts.cellText : null;
    this._cellClassFn = typeof opts.cellClass === 'function' ? opts.cellClass : null;
    // Optional per-cell title-attribute callback. When it returns a non-null
    // string, the value replaces the default tooltip on the `<td>` (which
    // normally only kicks in for cells whose text is longer than 40 chars).
    // Timeline Mode uses this to attach a multi-line Event-ID → human name +
    // MITRE ATT&CK tooltip to the EVTX "Event ID" column.
    this._cellTitleFn = typeof opts.cellTitle === 'function' ? opts.cellTitle : null;
    // Optional per-cell augment hook. Runs AFTER `textContent` / class /
    // title setup with the live `<td>` element so callers can append
    // decorative children (e.g. an Event-ID summary + MITRE pill in the
    // EVTX grid). Signature:
    //   cellAugment(dataIdx, colIdx, rawCell, td) → void
    // Like `detailAugment` it must be cheap — it fires per visible row on
    // every scroll. Exceptions are swallowed (decorative only).
    this._cellAugmentFn = typeof opts.cellAugment === 'function' ? opts.cellAugment : null;
    // Optional per-drawer-row augment hook. Called AFTER the default drawer
    // key/value row has been populated, with the key + value DOM elements so
    // callers can append decorative pills (e.g. an Event-ID summary + MITRE
    // pill) and/or stamp a tooltip. Receives
    //   detailAugment(dataIdx, colIdx, value, { keyEl, valEl, colName })
    // Never called when a custom `detailBuilder` is supplied.
    this._detailAugmentFn = typeof opts.detailAugment === 'function' ? opts.detailAugment : null;
    // Optional per-drawer-cell class callback. Invoked while building the

    // default key/value drawer pane — returns a space-separated class string
    // (or empty/null) that is added to BOTH the `.csv-detail-key` and
    // `.csv-detail-val` elements for that column. Used by Timeline mode to
    // tint drawer rows that correspond to a 🚩 Sus mark. Does not apply when
    // a custom `detailBuilder` is supplied.
    this._detailCellClassFn = typeof opts.detailCellClass === 'function' ? opts.detailCellClass : null;

    // Optional per-row class callback. Returns a space-separated class string
    // (or empty/null) that is added to the row's `.grid-row` div at build
    // time. Used by Timeline mode to tint "suspicious" rows without
    // re-rendering the whole grid. Pure decoration — does not affect
    // filtering or layout.
    this._rowClassFn = typeof opts.rowClass === 'function' ? opts.rowClass : null;

    // Timeline layout. Opt-in per-caller:
    //   timeColumn       : number|null     — index of the timestamp column.
    //                                          null / omitted → auto-sniff:
    //                                          first column whose sampled
    //                                          cells parse as Date.parse().
    //   timeParser       : (cell,i) => ms  — optional custom parser (EVTX can
    //                                          still use Date.parse(); XLSX
    //                                          might want Excel-serial math).
    //   timelineBuckets  : number          — histogram bucket count. Clamped
    //                                          to [20,400]; default 100.
    //   onFilterRecompute: () => void      — external-filter renderers (EVTX)
    //                                          pass their own filter runner
    //                                          so setTimeWindow() can trigger
    //                                          a full re-filter. Without a
    //                                          callback the default path
    //                                          calls this._applyFilter().
    this._timeColumn = Number.isInteger(opts.timeColumn) ? opts.timeColumn : null;
    this._timeColumnIsAuto = !Number.isInteger(opts.timeColumn);
    this._timeParser = typeof opts.timeParser === 'function' ? opts.timeParser : null;
    this._timeBucketCount = Math.max(20, Math.min(400, opts.timelineBuckets || 100));
    this._onFilterRecompute = typeof opts.onFilterRecompute === 'function' ? opts.onFilterRecompute : null;

    // Timeline Mode hand-off — when the grid is embedded inside Timeline
    // Mode (src/app/app-timeline.js), the outer view owns its own histogram
    // and stack-column <select>s. These opt-in callbacks let the column-
    // header menu items "Use as timeline" / "Stack timeline by this column"
    // update the *outer* Timeline view instead of promoting the grid's
    // own internal `.grid-timeline` strip. Returning a truthy value (or
    // just being present) is treated as "handled": the grid does not run
    // its own built-in timeline promotion path for that click.
    this._onUseAsTimeline = typeof opts.onUseAsTimeline === 'function' ? opts.onUseAsTimeline : null;
    this._onStackTimelineBy = typeof opts.onStackTimelineBy === 'function' ? opts.onStackTimelineBy : null;

    // Drawer-body JSON-tree picker hook — when a cell in the drawer
    // renders as a collapsible JSON tree, right-clicking a scalar leaf
    // key opens a small menu (Extract column / Include value / Exclude
    // value) that invokes this callback:
    //
    //   onCellPick(dataIdx, colIdx, pathArray, nodeValue, action)
    //
    // `action` ∈ 'extract' | 'include' | 'exclude'. Composite (object /
    // array) keys intentionally have no context menu. Timeline Mode
    // passes this so picking an item creates a virtual column extracting
    // that path from every row (and, for include/exclude, adds a
    // matching filter chip). When omitted the tree still renders; the
    // key-context menu is simply absent.
    this._onCellPick = typeof opts.onCellPick === 'function' ? opts.onCellPick : null;

    // Header-cell left-click override — when provided, left-clicking a
    // column header calls this callback instead of opening GridViewer's
    // own sort/hide/copy menu. Timeline Mode passes this so left-click
    // opens the Excel-style filter popover (same as the Top-Lists ▾
    // button) while right-click opens the sort/hide menu.
    //   onHeaderClick(colIdx, anchorEl)
    this._onHeaderClick = typeof opts.onHeaderClick === 'function' ? opts.onHeaderClick : null;

    // Column-reorder hook — fired AFTER `_colOrder` has been mutated and
    // the grid has re-rendered. Receives the new display-order array of
    // REAL column indices. Hosts (Timeline Mode) use this to persist the
    // user's preferred order under `loupe_timeline_grid_col_order_<file>`
    // so it survives reload. The grid itself stores nothing — `_colOrder`
    // is rehydrated by the host via `_setColumnOrder(...)` on mount.
    //   onColumnReorder(realIndicesInDisplayOrder)
    this._onColumnReorder = typeof opts.onColumnReorder === 'function' ? opts.onColumnReorder : null;

    // ── Column display-order layer ────────────────────────────────────────
    //
    // GridViewer's data model and the column-kind / width / sort engines
    // all key off REAL column indices (the position in `this.columns`
    // and in the row arrays returned by `store.getRow`). For reorder
    // support we add a thin presentation layer on top: `_colOrder` holds
    // the real indices in DISPLAY order. `null` is the identity case
    // (no user reorder yet) and is the default — every render path
    // resolves the order on the fly via `_resolveColOrder()`, which
    // returns the identity `[0, 1, …, columns.length-1]` when
    // `_colOrder` is null. This keeps the in-memory shape of every
    // grid that doesn't use reorder identical to the pre-feature path.
    //
    // The row-number column has no slot in `_colOrder` — it's stamped
    // unconditionally as the first element of the CSS template and the
    // first child of every header / data row by `_buildHeaderCells`
    // and `_buildRow`. Hidden columns (`_hiddenCols`) continue to skip
    // out of every iteration regardless of order; hiding does NOT
    // reorder the surviving columns (a hidden column's slot in
    // `_colOrder` is preserved so unhide restores it where it was).
    //
    // `_updateColumns` (used by Timeline auto-extract) extends
    // `_colOrder` with the newly-appended real indices in append order,
    // and prunes trailing entries on shrink — matching its existing
    // "append/tail-truncate only" contract. Timeline's geo-enrichment
    // path then optionally calls `_setColumnOrder([...with the new col
    // moved next to its source])` to land the geo column adjacent to
    // its IPv4 source instead of at the end.
    this._colOrder = null;

    // Optional stacking: histogram bars are split by category when a stack
    // column is set. Default: single-density bars.
    //   timelineStackColumn : number   — index of the grouping column.
    // Also toggle-able at runtime via the column-header menu item
    // "Stack timeline by this column". Top STACK_MAX_KEYS groups get their
    // own colour; the rest collapse into an "Other" bucket.
    this._timeStackColumn = Number.isInteger(opts.timelineStackColumn) ? opts.timelineStackColumn : null;
    this._timeStackKeys = null;  // Array<string> — legend order, index = palette slot
    this._timeStackOtherIdx = -1;   // index in _timeStackKeys reserved for "Other" (-1 = not used)
    // Stacked-bucket aggregate: Array(B) of Int32Array(keyCount). Swaps in
    // for _timeBuckets when stacking is active.
    this._timeStackBuckets = null;
    this.STACK_MAX_KEYS = 8;    // top-N + "Other"; keep palette readable
    this.STACK_MAX_DISTINCT = 500;  // refuse to stack if distinct-value count blows past this


    // Timeline runtime state — populated by _rebuildTimeline().
    //   _timeMs[dataIdx] = parsed ms-since-epoch (NaN if unparseable / empty).
    //   _timeDataRange   = { min, max } across all parseable cells — the
    //                      *absolute* span of the dataset, never changes
    //                      while the row set is stable.
    //   _timeRange       = { min, max } currently-rendered view span. Equals
    //                      _timeDataRange when no window is active; equals
    //                      _timeWindow when the user has drag-selected a
    //                      sub-range (so the histogram zooms to fill the
    //                      strip with just that range).
    //   _timeBuckets     = Int32Array(bucketCount) — count per bucket,
    //                      computed against _timeRange (i.e. the visible
    //                      view). Rebuilt by _rebuildBucketsForView().
    //   _timeWindow      = null | { min, max }   — active user selection.
    this._timeMs = null;
    this._timeDataRange = null;
    this._timeRange = null;
    this._timeBuckets = null;
    this._timeWindow = null;


    // Tunables (intentionally internal — callers don't twiddle these).
    this.ROW_HEIGHT = 28;
    this.HEADER_H = 32;
    this.BUFFER_ROWS = 12;
    this.MIN_COL_W = 60;
    this.MAX_COL_W = 320;     // default soft-cap for 'text' kind
    this.SHORT_COL_MAX = 240;    // 'short' kind soft-cap
    this.BLOB_BASE_MAX = 420;    // 'blob' kind base clamp (grows beyond via slack)
    this.CELL_PAD_PX = 22;      // body cell horizontal padding+border
    this.HEADER_EXTRA_PX = 24;   // extra px needed in header for chevron + sort indicator
    this.ROWNUM_COL_W = 64;
    this.DRAWER_MIN_W = 280;
    // Upper bound for the drawer width. Computed dynamically from the
    // current viewport so the analyst can swell the drawer out to
    // essentially the whole window on wide screens, while always leaving
    // at least `DRAWER_MIN_GRID_W` px for the grid body itself so the
    // grid can never become un-closable / un-usable. Recomputed on
    // every drag tick + on load-from-storage so a resized window picks
    // up the new cap automatically.
    this.DRAWER_MIN_GRID_W = 320;


    // Column-kind + manual-resize wiring (see _recomputeColumnWidths /
    // _classifyColumns). Callers that know their schema up-front (EVTX,
    // SQLite with PRAGMA hints) can pass `columnKinds: [...]` to skip the
    // sniffer; anything else auto-detects on the first populated recompute.
    //   Kinds: 'timestamp' | 'number' | 'id' | 'enum' | 'hash' |
    //          'short'     | 'text'   | 'blob'
    // Fixed-shape kinds (timestamp/number/id/enum/hash) are sized to their
    // p100 content and do NOT grow into viewport slack. 'blob' is greedy
    // and absorbs 100% of leftover slack so JSON/Message-style columns can
    // fill the viewport instead of being pinned at the old 480 px cap.
    this._columnKindsHint = Array.isArray(opts.columnKinds) ? opts.columnKinds.slice() : null;
    this._columnKinds = [];
    this._columnWidthMeta = [];
    this._chW = 7.2;   // px-per-char fallback; replaced on mount
    this._chWMeasured = false;

    // Per-renderer-kind storage namespace for user-resized column widths.
    // Caller may pass `gridKey` explicitly; otherwise fall back to className
    // (e.g. 'evtx-view', 'csv-view') so EVTX-resized widths survive
    // re-opens but don't pollute other renderers.
    this._gridKey = String(opts.gridKey || opts.className || 'grid')
      .replace(/[^a-zA-Z0-9_-]/g, '_');
    this._userColWidths = this._loadUserColumnWidths();   // Map<colIdx, px>

    // Mutable state — all reads go through here; all writes schedule a render.
    this.state = {
      filteredIndices: null,              // null = no filter + no sort; else Array of dataIdx
      visibleCount: this._rowCount(),
      renderedRange: { start: -1, end: -1 },
      drawer: {
        open: false,
        dataIdx: -1,
        width: this._loadDrawerWidth()
      },
      // Single highlight group — one timer, one state, one renderer path.
      //   mode === 'flash' → { mode, dataIdx, clearAt, timer, onExpire }
      //   mode === 'ioc'   → { mode, dataIdx, term, clearAt, timer, onExpire }
      //   mode === 'yara'  → { mode, focusDataIdx, focusMatchIdx, matchesByDataIdx, sourceText, clearAt, timer, onExpire }
      highlight: null,
      isProgrammaticScroll: false,
      parseComplete: true,                // flip to false + updateProgress() during chunked parse
      parseProgress: { rows: 0, total: 0 }
    };

    // Column-level features, defang, malformed ribbon.
    this._sortOrder = null;   // null | Int32Array — permutation of dataIdx under current sort
    this._sortSpec = null;   // null | { colIdx, dir: 'asc'|'desc' }
    this._hiddenCols = new Set();
    this._malformedRows = null;   // null | Set<dataIdx>   (CSV short-row / bad-quote rows)
    this._malformedCursor = -1;

    this._renderRAF = null;
    this._resizeObs = null;
    this._destroyed = false;
    this._boundHandlers = {};
    this._columnWidths = [];
    this._openPopover = null;     // active header menu / top-values popover DOM node


    this._buildDOM();
    this._recomputeColumnWidths();
    this._applyColumnTemplate();
    this._wireEvents();
    this._updateInfoBar();
    this._installBackCompatApi();
    this._scheduleRender();
    // If rows were provided up-front (non-streaming case), materialise the
    // timeline now. Streaming callers rebuild it in endParseProgress() /
    // setRows() — by which time the time column is populated.
    if (this._rowCount()) this._rebuildTimeline();
  }


  // ═══════════════════════════════════════════════════════════════════════════
  //  ROW ACCESSORS — single source of truth for cell access. Hot loops should
  //  call these once and cache the result locally to dodge the per-iteration
  //  property load. The legacy `string[][]` branch was retired in Phase 4c;
  //  every caller now hands a RowStore-shaped object via `opts.store` /
  //  `setRows(store, …)`.
  // ═══════════════════════════════════════════════════════════════════════════
  _rowCount() {
    return this.store.rowCount;
  }

  _rowAt(dataIdx) {
    return this.store.getRow(dataIdx);
  }

  _cellAt(dataIdx, colIdx) {
    return this.store.getCell(dataIdx, colIdx);
  }


  // ═══════════════════════════════════════════════════════════════════════════
  //  COLUMN DISPLAY ORDER
  //
  //  Thin presentation layer that lets headers + cells be reordered
  //  without touching the underlying column / row indices used by the
  //  classifier, width algorithm, sort engine, or persistence layer.
  //  See the `_colOrder` field comment in the constructor for the full
  //  contract.
  // ═══════════════════════════════════════════════════════════════════════════

  /** Resolve the current display order to a concrete real-index array
   *  with `columns.length` entries. The returned array is fresh — safe
   *  to mutate without affecting `_colOrder`. */
  _resolveColOrder() {
    const n = this.columns.length;
    if (!Array.isArray(this._colOrder)) {
      const out = new Array(n);
      for (let i = 0; i < n; i++) out[i] = i;
      return out;
    }
    // Defensive sanitiser: drop out-of-range, drop dupes, append any
    // real index that's missing (so a stale `_colOrder` from a previous
    // schema is healed gracefully — Timeline reorder + auto-extract
    // race could otherwise leave a freshly-extracted column dangling).
    const seen = new Set();
    const out = [];
    for (let i = 0; i < this._colOrder.length; i++) {
      const v = this._colOrder[i];
      if (!Number.isInteger(v) || v < 0 || v >= n) continue;
      if (seen.has(v)) continue;
      seen.add(v);
      out.push(v);
    }
    for (let i = 0; i < n; i++) {
      if (!seen.has(i)) out.push(i);
    }
    return out;
  }

  /** Return the current display order as a fresh real-index array.
   *  Always exactly `columns.length` entries. */
  _getColumnOrder() {
    return this._resolveColOrder();
  }

  /** Replace the display order. `realIndices` must be a permutation of
   *  `[0..columns.length)` — extra / missing / duplicate entries are
   *  healed by `_resolveColOrder()`. Triggers a re-render of headers,
   *  CSS template and rows; does NOT fire `onColumnReorder` (callers
   *  that want host persistence call this from the reorder pipeline
   *  AFTER computing the new order, then invoke the host callback
   *  themselves — see `_commitColumnReorder` below). */
  _setColumnOrder(realIndices) {
    if (!Array.isArray(realIndices)) {
      this._colOrder = null;
    } else {
      this._colOrder = realIndices.slice();
    }
    this._buildHeaderCells();
    this._applyColumnTemplate();
    this._forceFullRender();
  }

  /** Apply a new display order AND notify the host via `onColumnReorder`.
   *  This is the path the drag-drop handler uses — separating the two
   *  call sites lets host code (Timeline restore-from-storage) call
   *  `_setColumnOrder` without re-firing the persistence callback. */
  _commitColumnReorder(realIndices) {
    this._setColumnOrder(realIndices);
    if (this._onColumnReorder) {
      try { this._onColumnReorder(this._resolveColOrder()); }
      catch (_) { /* host bug; don't kill the grid */ }
    }
  }


  // ═══════════════════════════════════════════════════════════════════════════
  //  DOM CONSTRUCTION
  // ═══════════════════════════════════════════════════════════════════════════
  _buildDOM() {
    const root = document.createElement('div');
    root.className = this._rootClass + ' grid-view';
    root._rawText = lfNormalize(this.rawText);

    // ── Info bar ────────────────────────────────────────────────────────────
    const info = document.createElement('div');
    info.className = 'csv-info grid-info';
    root.appendChild(info);

    // ── Parse progress (only visible during chunked parse) ──────────────────
    const progress = document.createElement('div');
    progress.className = 'grid-progress hidden';
    progress.innerHTML = '<div class="grid-progress-bar"></div><span class="grid-progress-label">Parsing…</span>';
    root.appendChild(progress);

    // ── Extra toolbar rows (injected by format-specific renderers like
    //    EVTX, XLSX, SQLite — stats, export buttons, custom filter rows). ──
    for (const el of this._extraToolbarEls) {
      if (el) root.appendChild(el);
    }

    // ── Timeline strip — hidden by default; populated after the
    //    row set is finalised (a) at construction time if rows were passed
    //    in, or (b) on setRows() / endParseProgress() for streaming parsers.
    //    Contains: a bucket area for the density histogram + drag-select,
    //    min/max labels, a clear-window chip, and a floating tooltip. ──────
    const timeline = document.createElement('div');
    timeline.className = 'grid-timeline hidden';
    timeline.innerHTML =
      '<span class="grid-timeline-label grid-timeline-label-left"></span>' +
      '<div class="grid-timeline-track">' +
      '<div class="grid-timeline-buckets"></div>' +
      '<div class="grid-timeline-window hidden"></div>' +
      '<div class="grid-timeline-cursor hidden"></div>' +
      '<div class="grid-timeline-tooltip hidden"></div>' +
      '</div>' +
      '<span class="grid-timeline-label grid-timeline-label-right"></span>' +
      '<span class="grid-timeline-window-label hidden" aria-live="polite"></span>' +
      '<button class="tb-btn grid-timeline-clear hidden" title="Clear time window ([Esc])" aria-label="Clear time window">✕</button>';
    root.appendChild(timeline);

    // ── Filter bar ──────────────────────────────────────────────────────────
    const filterBar = document.createElement('div');
    filterBar.className = 'csv-filter-bar grid-filter-bar';
    const filterInput = document.createElement('input');
    filterInput.type = 'text';
    filterInput.placeholder = 'Filter rows…';
    filterInput.className = 'csv-filter-input grid-filter-input';
    filterInput.spellcheck = false;
    const clearBtn = document.createElement('button');
    clearBtn.className = 'tb-btn csv-clear-btn grid-clear-btn';
    clearBtn.textContent = '✕ Clear';
    clearBtn.title = 'Clear filter';
    clearBtn.style.display = 'none';
    const filterStatus = document.createElement('span');
    filterStatus.className = 'csv-filter-status grid-filter-status';
    filterBar.appendChild(filterInput);
    filterBar.appendChild(clearBtn);
    filterBar.appendChild(filterStatus);

    // Malformed-row ribbon — only visible when _malformedRows is non-empty.
    // Clicking "Next" cycles through the malformed rows; "Filter" toggles
    // filter-to-malformed-only.
    const malformedChip = document.createElement('span');
    malformedChip.className = 'grid-malformed-chip';
    malformedChip.style.display = 'none';
    malformedChip.innerHTML =
      '<span class="grid-malformed-label">⚠ <span class="grid-malformed-count">0</span> malformed</span>' +
      '<button class="tb-btn grid-malformed-next" title="Jump to next malformed row">Next</button>' +
      '<button class="tb-btn grid-malformed-filter" title="Show only malformed rows">Filter</button>';
    filterBar.appendChild(malformedChip);

    // Hidden-columns chip — only visible when _hiddenCols is non-empty.
    // Click the chip itself to open a popover listing every hidden column
    // (click a row to unhide just that one); click the "Show all" button
    // to unhide every hidden column at once. Mirrors the malformed-row
    // ribbon visually so the two status chips compose naturally.
    const hiddenChip = document.createElement('span');
    hiddenChip.className = 'grid-hidden-chip';
    hiddenChip.style.display = 'none';
    hiddenChip.innerHTML =
      '<button class="tb-btn grid-hidden-label" title="Show hidden columns…">' +
      '👁 <span class="grid-hidden-count">0</span> hidden' +
      '</button>' +
      '<button class="tb-btn grid-hidden-show" title="Unhide every hidden column">Show all</button>';
    filterBar.appendChild(hiddenChip);

    if (this._hideFilterBar) filterBar.style.display = 'none';
    root.appendChild(filterBar);



    // ── Main flex row: scroll container + drawer ───────────────────────────
    const main = document.createElement('div');
    main.className = 'grid-main';
    root.appendChild(main);

    // Scroll container
    const scr = document.createElement('div');
    scr.className = 'grid-scroll csv-scroll';
    scr.tabIndex = 0;
    main.appendChild(scr);

    // Header (sticky inside scroll container)
    const header = document.createElement('div');
    header.className = 'grid-header';
    header.setAttribute('role', 'row');
    scr.appendChild(header);

    // Body sizer (establishes total scrollable height)
    const sizer = document.createElement('div');
    sizer.className = 'grid-body-sizer';
    scr.appendChild(sizer);

    // Drawer resize handle (left edge of drawer)
    const handle = document.createElement('div');
    handle.className = 'grid-drawer-handle';
    handle.title = 'Drag to resize detail pane';
    handle.style.display = 'none';
    main.appendChild(handle);

    // Drawer container (hidden by default)
    const drawer = document.createElement('aside');
    drawer.className = 'grid-drawer';
    drawer.style.display = 'none';
    drawer.style.flexBasis = this.state.drawer.width + 'px';
    drawer.innerHTML = `
      <div class="grid-drawer-topbar">
        <span class="grid-drawer-title">Row details</span>
        <div class="grid-drawer-search-wrap">
          <input type="search" class="grid-drawer-search" placeholder="Search in row…" aria-label="Search detail pane" spellcheck="false" autocomplete="off" />
          <span class="grid-drawer-search-count" aria-live="polite"></span>
          <button class="grid-drawer-search-prev" title="Previous match (Shift+Enter)" aria-label="Previous match" tabindex="-1">▲</button>
          <button class="grid-drawer-search-next" title="Next match (Enter)" aria-label="Next match" tabindex="-1">▼</button>
        </div>
        <button class="grid-drawer-close" title="Close (Esc)" aria-label="Close detail pane">✕</button>
      </div>
      <div class="grid-drawer-body"></div>
    `;
    main.appendChild(drawer);

    // ── Truncation notice below main ───────────────────────────────────────
    if (this._truncNote) {
      const trunc = document.createElement('div');
      trunc.className = 'csv-info grid-trunc';
      trunc.textContent = this._truncNote;
      root.appendChild(trunc);
    }

    // Stash DOM refs
    this._root = root;
    this._info = info;
    this._progress = progress;
    this._progressBar = progress.querySelector('.grid-progress-bar');
    this._progressLbl = progress.querySelector('.grid-progress-label');
    this._filterInput = filterInput;
    this._clearBtn = clearBtn;
    this._filterStatus = filterStatus;
    this._malformedChip = malformedChip;
    this._malformedLabel = malformedChip.querySelector('.grid-malformed-count');
    this._malformedNextBtn = malformedChip.querySelector('.grid-malformed-next');
    this._malformedFilterBtn = malformedChip.querySelector('.grid-malformed-filter');
    this._hiddenChip = hiddenChip;
    this._hiddenCountLabel = hiddenChip.querySelector('.grid-hidden-count');
    this._hiddenChipLabelBtn = hiddenChip.querySelector('.grid-hidden-label');
    this._hiddenShowAllBtn = hiddenChip.querySelector('.grid-hidden-show');
    this._main = main;
    this._emptyEl = null;

    // Timeline strip refs
    this._timelineEl = timeline;
    this._timelineTrackEl = timeline.querySelector('.grid-timeline-track');
    this._timelineBucketsEl = timeline.querySelector('.grid-timeline-buckets');
    this._timelineWindowEl = timeline.querySelector('.grid-timeline-window');
    this._timelineTooltipEl = timeline.querySelector('.grid-timeline-tooltip');
    this._timelineLabelLeft = timeline.querySelector('.grid-timeline-label-left');
    this._timelineLabelRight = timeline.querySelector('.grid-timeline-label-right');
    this._timelineWindowLbl = timeline.querySelector('.grid-timeline-window-label');
    this._timelineClearBtn = timeline.querySelector('.grid-timeline-clear');
    this._timelineCursorEl = timeline.querySelector('.grid-timeline-cursor');

    this._scr = scr;
    this._header = header;
    this._sizer = sizer;
    this._drawerHandle = handle;
    this._drawer = drawer;
    this._drawerBody = drawer.querySelector('.grid-drawer-body');
    this._drawerClose = drawer.querySelector('.grid-drawer-close');
    this._drawerTitle = drawer.querySelector('.grid-drawer-title');

    // Build header cells
    this._buildHeaderCells();

    if (!this._rowCount()) {
      const empty = document.createElement('div');
      empty.className = 'grid-empty';
      empty.textContent = this._emptyMessage;
      main.appendChild(empty);
      this._emptyEl = empty;
    }
  }

  _buildHeaderCells() {
    this._header.replaceChildren();
    // Row-number cell — click to clear sort.
    const numCell = document.createElement('div');
    numCell.className = 'grid-header-cell grid-row-num';
    numCell.textContent = '#';
    numCell.title = this._sortSpec ? 'Click to clear sort' : '#';
    numCell.addEventListener('click', () => {
      if (this._sortSpec) this._clearSort();
    });
    this._header.appendChild(numCell);
    // Data cells — each is a button-ish clickable region that opens the
    // header dropdown menu (Sort asc/desc/clear · Copy column · Hide · Top values).
    //
    // Iteration is in DISPLAY order (post-reorder), but `data-col` and
    // every closure capture remain the REAL column index — that way
    // sort/hide/resize/right-click handlers and external consumers
    // (Timeline's right-click menu, drawer, top-values popover) keep
    // working identically whether the user has reordered columns or not.
    const order = this._resolveColOrder();
    for (let oi = 0; oi < order.length; oi++) {
      const i = order[oi];
      if (this._hiddenCols.has(i)) continue;
      const cell = document.createElement('div');
      cell.className = 'grid-header-cell grid-header-clickable';
      cell.dataset.col = i;
      const name = this.columns[i] || `Column ${i + 1}`;

      const label = document.createElement('span');
      label.className = 'grid-header-label';
      label.textContent = name;
      cell.appendChild(label);

      // Sort indicator — lights up when this column is the active sort.
      const sortInd = document.createElement('span');
      sortInd.className = 'grid-header-sort';
      if (this._sortSpec && this._sortSpec.colIdx === i) {
        sortInd.textContent = this._sortSpec.dir === 'asc' ? ' ▲' : ' ▼';
        cell.classList.add('grid-header-sorted');
      }
      cell.appendChild(sortInd);

      // Dropdown chevron.
      const chev = document.createElement('span');
      chev.className = 'grid-header-chev';
      chev.textContent = '▾';
      chev.setAttribute('aria-hidden', 'true');
      cell.appendChild(chev);

      cell.title = this._onHeaderClick
        ? name + ' — click for filter · right-click for sort/hide · Ctrl+Click to hide'
        : name + ' — click for column menu · Ctrl+Click to hide';
      cell.addEventListener('click', (e) => {
        e.stopPropagation();
        // Ctrl/Cmd+Click on a header → quick-hide. Same as picking
        // "Hide column" from the ▾ menu, but without opening the menu.
        // Mirrored on the Timeline `tl-col-card` header so the shortcut
        // is consistent across the two places columns live.
        if (e.ctrlKey || e.metaKey) {
          this._toggleHideColumn(i);
          return;
        }
        if (this._onHeaderClick) {
          // Close GridViewer's own popover (e.g. a sort/hide menu from
          // a prior right-click) before handing off to the external
          // handler, so two popovers can't overlap.
          this._closePopover();
          this._onHeaderClick(i, cell);
        } else {
          this._openHeaderMenu(i, cell);
        }
      });
      // Drag-to-resize handle on the right edge of the cell. Double-click
      // the handle to reset this column to its auto-calculated width.
      // Swallows click/mousedown so it can't reopen the header menu.
      this._wireColumnResize(cell, i);
      // Drag-to-reorder — uses the HTML5 native DnD API so it cooperates
      // with the existing click / right-click / resize handlers (only one
      // is "winning" any given mousedown gesture). The cell starts
      // un-draggable and only flips `draggable=true` when a mousedown
      // lands on the body of the cell (NOT the resize handle, NOT the
      // chevron). This is the same trick the Timeline `tl-col-card`
      // uses to keep drag and click on the same element.
      this._wireColumnDrag(cell, i);
      this._header.appendChild(cell);
    }
  }


  // ══════════════════════════════════════════════════════════════════════════
  //  COLUMN WIDTH ALGORITHM (kind-aware)
  //
  //  Old algorithm gave every column a clamp(p85*charW, 60, 320) base then
  //  split viewport slack *proportional to base width*. That inflated
  //  fixed-shape columns (Timestamp / Event ID / Level) at the expense of
  //  the one column that actually holds long-form content (e.g. Event Data
  //  JSON), which got pinned at the 480 px fill-cap.
  //
  //  The new algorithm classifies every column up-front into a "kind",
  //  then sizes each kind against its own rules:
  //
  //    timestamp / number / id / hash / enum → tight-fit to max content
  //      length (no viewport growth)
  //    short                                 → p95 base, modest soft cap
  //    text                                  → p85 base, old 320 cap
  //    blob                                  → p85 base, but tagged
  //      *greedy* and takes 100% of leftover slack after every other
  //      column is satisfied
  //
  //  Callers that know their schema (EVTX) skip the sniffer by passing
  //  `columnKinds: [...]` at construction time. Everyone else gets
  //  auto-detection on first populated width recompute.
  // ══════════════════════════════════════════════════════════════════════════

  /** Measure the grid body's actual cell font once, so width math doesn't
   *  rely on a `7.2 px/char` guess that silently breaks when a theme swaps
   *  the monospace font. Cached on `this._chW`. Safe to call before the
   *  grid is attached to the document (falls back to the default guess). */
  _measureCharWidth() {
    if (this._chWMeasured) return this._chW;
    // We need a cell-shaped element *inside the grid* so the probe inherits
    // font-family/size/weight from the viewer-specific CSS (core.css + any
    // theme overlay). Fall back to a plain off-screen span if the root
    // hasn't mounted yet.
    const probe = document.createElement('div');
    probe.className = 'grid-cell';
    probe.style.position = 'absolute';
    probe.style.visibility = 'hidden';
    probe.style.whiteSpace = 'pre';
    probe.style.padding = '0';
    probe.style.border = '0';
    probe.textContent = '0'.repeat(80);   // 80 zeros → stable sample
    const host = (this._sizer && this._sizer.isConnected) ? this._sizer
      : (this._root && this._root.isConnected) ? this._root
        : document.body;
    host.appendChild(probe);
    const w = probe.getBoundingClientRect().width / 80;
    probe.remove();
    if (Number.isFinite(w) && w > 0) {
      this._chW = w;
      this._chWMeasured = true;
    }
    return this._chW;
  }

  /** Classify each column into one of:
   *    'timestamp' | 'number' | 'id' | 'hash' | 'enum' | 'short' | 'text' | 'blob'
   *
   *  Stratified sampling (head + middle + tail) so EVTX's boot-chatter-
   *  heavy prefix doesn't mis-type Event Data as 'short' just because the
   *  first 100 records happen to have tiny payloads.
   *
   *  Caller-supplied `columnKinds` wins per-cell: any index whose entry is
   *  a known kind string is accepted verbatim and the sniffer skipped. */
  _classifyColumns() {
    const hint = this._columnKindsHint;
    const cols = this.columns.length;
    const kinds = new Array(cols);
    const lens = new Array(cols);       // Array<sorted number[]>
    const distinct = new Array(cols);   // Array<Set<string>> — up to 50 each
    for (let c = 0; c < cols; c++) {
      lens[c] = [];
      distinct[c] = new Set();
    }

    // Stratified sample: head + middle + tail, up to ~300 rows total.
    const n = this._rowCount();
    const sampleIdxs = [];
    if (n > 0) {
      const HEAD = Math.min(100, n);
      for (let i = 0; i < HEAD; i++) sampleIdxs.push(i);
      if (n > 200) {
        const midStart = Math.floor(n / 2) - 50;
        for (let i = 0; i < 100 && (midStart + i) < n; i++) {
          sampleIdxs.push(midStart + i);
        }
        for (let i = Math.max(0, n - 100); i < n; i++) sampleIdxs.push(i);
      }
    }

    // Per-column tallies: numeric count, pure-hex32/40/64 count, timestamp
    // count, max length, non-empty count. Regex kept narrow on purpose —
    // auto-detection is only meant to catch the obvious cases.
    const stats = new Array(cols);
    for (let c = 0; c < cols; c++) {
      stats[c] = { nonEmpty: 0, numeric: 0, ts: 0, hex32: 0, hex40: 0, hex64: 0, maxLen: 0, startsJsonish: 0 };
    }
    const TS_RE = /^(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)$/;
    const NUM_RE = /^-?\d+(?:\.\d+)?$/;
    const HEX_RE = /^[0-9a-fA-F]+$/;

    for (const r of sampleIdxs) {
      const row = this._rowAt(r);
      if (!row) continue;
      for (let c = 0; c < cols; c++) {
        let cell = row[c];
        if (cell == null) cell = '';
        const s = String(cell);
        const trimmed = s.trim();
        const L = s.length;
        if (L > stats[c].maxLen) stats[c].maxLen = L;
        lens[c].push(L);
        if (!trimmed) continue;
        stats[c].nonEmpty++;
        if (distinct[c].size < 50) distinct[c].add(trimmed);
        if (NUM_RE.test(trimmed)) stats[c].numeric++;
        if (TS_RE.test(trimmed)) stats[c].ts++;
        if (HEX_RE.test(trimmed)) {
          const hl = trimmed.length;
          if (hl === 32) stats[c].hex32++;
          else if (hl === 40) stats[c].hex40++;
          else if (hl === 64) stats[c].hex64++;
        }
        if (trimmed[0] === '{' || trimmed[0] === '[') stats[c].startsJsonish++;
      }
    }

    for (let c = 0; c < cols; c++) {
      // Caller-supplied hint wins.
      if (hint && typeof hint[c] === 'string') {
        kinds[c] = hint[c];
        continue;
      }
      const st = stats[c];
      if (st.nonEmpty === 0) { kinds[c] = 'short'; continue; }

      // Hash — ≥90% fixed-length hex at a known length → column is hashes.
      if (st.hex32 / st.nonEmpty >= 0.9 || st.hex40 / st.nonEmpty >= 0.9 || st.hex64 / st.nonEmpty >= 0.9) {
        kinds[c] = 'hash';
        continue;
      }
      // Timestamp — most non-empty cells parse as an ISO-ish date.
      if (st.ts / st.nonEmpty >= 0.85) { kinds[c] = 'timestamp'; continue; }
      // Numeric / ID — mostly bare numbers, short columns.
      if (st.numeric / st.nonEmpty >= 0.9 && st.maxLen <= 12) {
        kinds[c] = 'id';
        continue;
      }
      if (st.numeric / st.nonEmpty >= 0.9) { kinds[c] = 'number'; continue; }

      // Blob — JSON-ish opener OR very wide cells.
      if (st.startsJsonish / st.nonEmpty >= 0.5 || st.maxLen > 160) {
        kinds[c] = 'blob';
        continue;
      }
      // Enum — few distinct values, all reasonably short.
      if (distinct[c].size > 0 && distinct[c].size <= 12 && st.maxLen <= 24) {
        kinds[c] = 'enum';
        continue;
      }
      // Short-text (hostname, username, short path).
      if (st.maxLen <= 48) { kinds[c] = 'short'; continue; }

      kinds[c] = 'text';
    }

    this._columnKinds = kinds;
    this._columnLengths = lens;
  }

  /** Compute each column's "base" width — the width it would get in
   *  isolation, with no viewport-fill growth. Honours per-kind sizing
   *  rules and always guarantees enough space for the header label so
   *  nothing gets truncated out of the gate. User-resized widths (from
   *  the drag-resize handle) override the algorithm for that column. */
  _recomputeColumnWidths() {
    if (!this.columns.length) {
      this._columnWidths = [];
      this._columnWidthMeta = [];
      return;
    }
    this._classifyColumns();
    const chW = this._measureCharWidth();
    const kinds = this._columnKinds;
    const lens = this._columnLengths;
    const cols = this.columns.length;
    const widths = new Array(cols);
    const meta = new Array(cols);

    for (let c = 0; c < cols; c++) {
      const kind = kinds[c] || 'text';
      // Header floor — nothing in the body should force the header label
      // to truncate. chevron + sort indicator eat ~24 px of header width.
      const hdrLen = (this.columns[c] || '').length;
      const headerPx = Math.ceil(hdrLen * chW) + this.HEADER_EXTRA_PX + this.CELL_PAD_PX;

      const arr = lens[c] ? lens[c].slice().sort((a, b) => a - b) : [0];
      const p = (pct) => {
        if (!arr.length) return 0;
        const i = Math.min(arr.length - 1, Math.max(0, Math.floor(arr.length * pct)));
        return arr[i];
      };
      const p85 = p(0.85);
      const p95 = p(0.95);
      const p100 = arr[arr.length - 1] || 0;

      let base;
      let greedy = false;
      // Small amount of extra breathing room for fixed-shape columns so
      // the last char doesn't sit flush against the next cell's border.
      const TIGHT_PAD = 8;

      switch (kind) {
        case 'timestamp':
          base = Math.ceil(p100 * chW) + this.CELL_PAD_PX + TIGHT_PAD;
          break;
        case 'number':
        case 'id':
          base = Math.ceil(p100 * chW) + this.CELL_PAD_PX + TIGHT_PAD;
          break;
        case 'hash':
          base = Math.ceil(p100 * chW) + this.CELL_PAD_PX + TIGHT_PAD;
          break;
        case 'enum':
          base = Math.ceil(p100 * chW) + this.CELL_PAD_PX + TIGHT_PAD;
          break;
        case 'short':
          base = Math.min(this.SHORT_COL_MAX, Math.ceil(p95 * chW) + this.CELL_PAD_PX);
          break;
        case 'blob':
          base = Math.min(this.BLOB_BASE_MAX, Math.ceil(p85 * chW) + this.CELL_PAD_PX);
          greedy = true;
          break;
        case 'text':
        default:
          base = Math.min(this.MAX_COL_W, Math.ceil(p85 * chW) + this.CELL_PAD_PX);
          break;
      }
      // Clamp & floor.
      base = Math.max(this.MIN_COL_W, base);
      base = Math.max(base, headerPx);          // header never truncates

      // User-resized column? Respect it regardless of kind, but record the
      // algorithm's opinion in meta so a future "Reset" action can restore.
      const user = this._userColWidths.get(c);
      widths[c] = (user && Number.isFinite(user)) ? user : base;

      meta[c] = {
        kind,
        greedy,
        headerPx,
        base,
        userOverride: !!(user && Number.isFinite(user))
      };
    }

    this._columnWidths = widths;
    this._columnWidthMeta = meta;
  }

  _applyColumnTemplate() {
    // Build the list of visible (non-hidden) columns with their kind,
    // base width, and greedy flag — IN DISPLAY ORDER, so the resulting
    // CSS `grid-template-columns` track sizes line up with the order
    // `_buildHeaderCells` / `_buildRow` lay out their children. Width
    // and meta are still keyed by REAL column index in
    // `_columnWidths` / `_columnWidthMeta`, so widths persist across
    // reorder without re-sampling.
    const visIdx = [];
    const baseWs = [];
    const meta = [];
    const order = this._resolveColOrder();
    for (let oi = 0; oi < order.length; oi++) {
      const i = order[oi];
      if (i >= this._columnWidths.length) continue;
      if (this._hiddenCols.has(i)) continue;
      visIdx.push(i);
      baseWs.push(this._columnWidths[i]);
      meta.push(this._columnWidthMeta[i] || { kind: 'text', greedy: false });
    }

    const scrW = (this._scr && this._scr.clientWidth) || 0;
    const outWs = baseWs.slice();

    // Two-pass slack allocation:
    //   Pass 1 — leave fixed-shape columns (timestamp/number/id/enum/
    //            hash/short/user-overridden) alone. Greedy blobs absorb
    //            ALL leftover slack, split equally between them when
    //            multiple blobs exist.
    //   Pass 2 — if no greedy column exists (typical CSV with short
    //            text only), fall back to proportional-fill so small
    //            tables still fill the viewport instead of leaving a
    //            right-edge gutter.
    if (scrW > 0 && visIdx.length) {
      // Reserve the row-number gutter + a 2 px safety margin so the last
      // column never provokes a horizontal scrollbar after rounding.
      const avail = scrW - this.ROWNUM_COL_W - 2;
      const baseSum = outWs.reduce((a, b) => a + b, 0);
      let slack = avail - baseSum;

      // Identify greedy columns (blob kind, not user-overridden).
      const greedyIdxs = [];
      for (let i = 0; i < meta.length; i++) {
        if (meta[i].greedy && !meta[i].userOverride) greedyIdxs.push(i);
      }

      if (slack > 0) {
        if (greedyIdxs.length > 0) {
          // PHASE 1 — dump everything into greedy columns, split equally.
          const share = slack / greedyIdxs.length;
          for (const i of greedyIdxs) outWs[i] += share;
        } else {
          // PHASE 2 — no blobs. Grow non-fixed kinds proportionally, with
          // a per-column 2× soft cap (twice its own base) to stop a
          // single long-text column from swelling into a non-interactive
          // wall of whitespace.
          const growable = [];
          for (let i = 0; i < meta.length; i++) {
            const k = meta[i].kind;
            // Fixed-shape kinds + user overrides never grow.
            if (meta[i].userOverride) continue;
            if (k === 'timestamp' || k === 'number' || k === 'id' ||
              k === 'hash' || k === 'enum') continue;
            growable.push(i);
          }
          if (growable.length === 0) {
            // Everything is fixed — leave the trailing slack as empty track.
          } else {
            let growBase = 0;
            for (const i of growable) growBase += outWs[i];
            const caps = growable.map(i => outWs[i] * 2);
            for (let pass = 0; pass < 3 && slack > 1; pass++) {
              let spent = 0;
              for (let gi = 0; gi < growable.length; gi++) {
                const i = growable[gi];
                if (outWs[i] >= caps[gi]) continue;
                const share = outWs[i] / growBase;
                const want = slack * share;
                const capped = Math.min(want, caps[gi] - outWs[i]);
                outWs[i] += capped;
                spent += capped;
              }
              slack -= spent;
              // Recompute growBase over still-growable columns.
              growBase = 0;
              for (let gi = 0; gi < growable.length; gi++) {
                const i = growable[gi];
                if (outWs[i] < caps[gi]) growBase += outWs[i];
              }
              if (growBase <= 0) break;
            }
          }
        }
      } else if (slack < 0) {
        // Viewport is narrower than the sum of base widths. Shrink greedy
        // columns first (they're discretionary); if none, proportionally
        // shrink non-fixed columns down to MIN_COL_W.
        let deficit = -slack;
        if (greedyIdxs.length > 0) {
          // Shrink greedy columns evenly, but not below MIN_COL_W.
          const per = deficit / greedyIdxs.length;
          for (const i of greedyIdxs) {
            const nw = Math.max(this.MIN_COL_W, outWs[i] - per);
            deficit -= (outWs[i] - nw);
            outWs[i] = nw;
          }
        }
        // Further deficit handled silently — browser shows a horizontal
        // scrollbar, which is the right UX when the viewport really is
        // too narrow.
      }
    }

    const parts = [this.ROWNUM_COL_W + 'px'];
    let totalW = this.ROWNUM_COL_W;
    for (let i = 0; i < outWs.length; i++) {
      const w = Math.round(outWs[i]);
      parts.push(w + 'px');
      totalW += w;
    }
    this._root.style.setProperty('--grid-template', parts.join(' '));
    this._root.style.setProperty('--grid-min-width', totalW + 'px');

    // Record the rendered widths so manual-resize drag handles can read
    // their starting pixel value cheaply without re-reading the CSS var.
    this._visibleColIdxs = visIdx;
    this._renderedColWidths = outWs.slice();
  }

  // ══════════════════════════════════════════════════════════════════════════
  //  MANUAL COLUMN RESIZE — persisted per-grid-kind under `loupe_`
  //  prefix (see .clinerules — user-persisted preferences are required
  //  to use this namespace).
  // ══════════════════════════════════════════════════════════════════════════

  _colWidthStorageKey() {
    return `loupe_grid_colW_${this._gridKey}`;
  }

  _loadUserColumnWidths() {
    const m = new Map();
    const obj = safeStorage.getJSON(this._colWidthStorageKey(), null);
    if (obj && typeof obj === 'object') {
      for (const k of Object.keys(obj)) {
        const i = parseInt(k, 10);
        const v = parseInt(obj[k], 10);
        if (Number.isFinite(i) && Number.isFinite(v)) {
          m.set(i, Math.max(this.MIN_COL_W, Math.min(1600, v)));
        }
      }
    }
    return m;
  }

  _saveUserColumnWidth(colIdx, widthPx) {
    const obj = {};
    for (const [k, v] of this._userColWidths) obj[k] = v;
    if (widthPx == null) delete obj[colIdx];
    else obj[colIdx] = widthPx;
    safeStorage.setJSON(this._colWidthStorageKey(), obj);
  }

  /** Reset one column back to its auto-calculated width. Called from the
   *  column-header menu. */
  _resetColumnWidth(colIdx) {
    this._userColWidths.delete(colIdx);
    this._saveUserColumnWidth(colIdx, null);
    this._recomputeColumnWidths();
    this._applyColumnTemplate();
  }

  /** Wire a drag handle onto one header cell. Called from
   *  `_buildHeaderCells()` for every visible column. Live-drag updates
   *  the CSS var directly for smooth feedback; commits on mouseup. */
  _wireColumnResize(cell, colIdx) {
    const handle = document.createElement('div');
    handle.className = 'grid-col-resize-handle';
    handle.title = 'Drag to resize · double-click to auto-fit';
    handle.addEventListener('click', (e) => { e.stopPropagation(); });
    handle.addEventListener('dblclick', (e) => {
      e.stopPropagation();
      this._resetColumnWidth(colIdx);
    });
    handle.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      e.stopPropagation();
      const startX = e.clientX;
      const startW = cell.getBoundingClientRect().width || this.MIN_COL_W;
      let curW = startW;
      document.body.classList.add('grid-resizing');
      const onMove = (ev) => {
        const dx = ev.clientX - startX;
        curW = Math.max(this.MIN_COL_W, Math.min(1600, Math.round(startW + dx)));
        this._userColWidths.set(colIdx, curW);
        this._columnWidths[colIdx] = curW;
        if (this._columnWidthMeta[colIdx]) {
          this._columnWidthMeta[colIdx].userOverride = true;
        }
        this._applyColumnTemplate();
      };
      const onUp = () => {
        document.body.classList.remove('grid-resizing');
        window.removeEventListener('mousemove', onMove);
        window.removeEventListener('mouseup', onUp);
        this._saveUserColumnWidth(colIdx, curW);
      };
      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onUp);
    });
    cell.appendChild(handle);
  }


  // ══════════════════════════════════════════════════════════════════════════
  //  COLUMN DRAG-TO-REORDER
  //
  //  Native HTML5 DnD on every header cell. The cell becomes draggable
  //  only when the user mouses down on the cell body (not on the resize
  //  handle, not on the chevron) — flipping `draggable` on the fly is
  //  what stops drag from hijacking left-click / right-click. Drop
  //  resolution is midpoint-based: drop position is "before target"
  //  if the pointer is in the left half of the target cell, "after"
  //  otherwise. Mirrors the proven `tl-col-card` reorder UX.
  //
  //  Hidden columns are skipped during render (no draggable cell, so
  //  they can't be dragged), but their slot in `_colOrder` is preserved
  //  — unhide restores the column at its original display position.
  //
  //  Calls `_commitColumnReorder` on drop so the host's persistence
  //  callback (`onColumnReorder`) fires exactly once per user gesture.
  // ══════════════════════════════════════════════════════════════════════════

  _wireColumnDrag(cell, realIdx) {
    // Only flip `draggable` ON when the press lands on the cell body
    // (not the resize handle, not the chevron, not a button child).
    cell.addEventListener('mousedown', (e) => {
      const t = e.target;
      if (!t) return;
      if (t.classList && (
        t.classList.contains('grid-col-resize-handle') ||
        t.classList.contains('grid-header-chev')
      )) {
        cell.draggable = false;
        return;
      }
      // Right-click / middle-click never starts a drag.
      if (e.button !== 0) {
        cell.draggable = false;
        return;
      }
      cell.draggable = true;
    });
    cell.addEventListener('mouseup', () => { cell.draggable = false; });
    cell.addEventListener('dragstart', (e) => {
      // Stamp the source's REAL index on the dataTransfer so a drop
      // resolves regardless of where the cell is in the live DOM.
      try {
        e.dataTransfer.setData('text/x-loupe-col', String(realIdx));
        e.dataTransfer.effectAllowed = 'move';
      } catch (_) { /* some browsers throw on setData inside non-user gesture */ }
      cell.classList.add('grid-header-drag-source');
      // Body-level flag lets CSS disable the resize handle for the
      // duration of the drag so dragover always lands on the cell body
      // and not the 6-px-wide handle on its right edge.
      try { document.body.classList.add('grid-col-dragging'); } catch (_) { /* noop */ }
    });
    cell.addEventListener('dragend', () => {
      cell.classList.remove('grid-header-drag-source');
      cell.draggable = false;
      try { document.body.classList.remove('grid-col-dragging'); } catch (_) { /* noop */ }
      // Clear any lingering drop indicators across the row (drop fired
      // somewhere else, or the user pressed Escape).
      const all = this._header ? this._header.querySelectorAll(
        '.grid-header-drag-over-before, .grid-header-drag-over-after'
      ) : [];
      for (const n of all) {
        n.classList.remove('grid-header-drag-over-before', 'grid-header-drag-over-after');
      }
    });
    cell.addEventListener('dragover', (e) => {
      // Only accept loupe column drags. Without this guard a file drop
      // on the header would be eligible.
      const types = e.dataTransfer && e.dataTransfer.types;
      if (!types || !Array.prototype.includes.call(types, 'text/x-loupe-col')) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      const rect = cell.getBoundingClientRect();
      const before = (e.clientX - rect.left) < (rect.width / 2);
      cell.classList.toggle('grid-header-drag-over-before', before);
      cell.classList.toggle('grid-header-drag-over-after', !before);
    });
    cell.addEventListener('dragleave', () => {
      cell.classList.remove('grid-header-drag-over-before', 'grid-header-drag-over-after');
    });
    cell.addEventListener('drop', (e) => {
      const raw = e.dataTransfer && e.dataTransfer.getData('text/x-loupe-col');
      cell.classList.remove('grid-header-drag-over-before', 'grid-header-drag-over-after');
      if (raw == null || raw === '') return;
      const fromReal = parseInt(raw, 10);
      const toReal = realIdx;
      if (!Number.isInteger(fromReal) || fromReal === toReal) return;
      e.preventDefault();
      const rect = cell.getBoundingClientRect();
      const before = (e.clientX - rect.left) < (rect.width / 2);
      // Compute the new order. Work in DISPLAY space: pull `fromReal`
      // out of its current display slot, then insert it before/after
      // `toReal`'s current display slot.
      const order = this._resolveColOrder();
      const fromPos = order.indexOf(fromReal);
      if (fromPos < 0) return;
      order.splice(fromPos, 1);
      // Recompute target's position AFTER splice (it may have shifted).
      let toPos = order.indexOf(toReal);
      if (toPos < 0) {
        // Target column got hidden mid-drag; bail without reordering.
        return;
      }
      if (!before) toPos += 1;
      order.splice(toPos, 0, fromReal);
      this._commitColumnReorder(order);
    });
  }


  _updateInfoBar() {
    if (this._infoText) {
      this._info.textContent = this._infoText;
    } else {
      const rc = this._rowCount();
      const cc = this.columns.length;
      this._info.textContent = `${rc.toLocaleString()} rows × ${cc} columns`;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  EVENT WIRING
  // ═══════════════════════════════════════════════════════════════════════════
  _wireEvents() {
    // Scroll — rAF-throttled.
    this._boundHandlers.onScroll = () => {
      // The red scrub cursor tracks the first visible row as the user
      // scrolls. It's cheap (div + ms lookup) so we update it on every
      // scroll tick, not just the rAF-throttled render tick — that way
      // it tracks fluid finger/trackpad motion even when renderedRange
      // hasn't changed enough to trigger a repaint.
      this._updateTimelineCursor();
      if (this._renderRAF || this.state.isProgrammaticScroll) return;
      this._renderRAF = requestAnimationFrame(() => {
        this._renderRAF = null;
        this._render();
      });
    };
    this._scr.addEventListener('scroll', this._boundHandlers.onScroll, { passive: true });

    // Filter input
    // Debounce keystroke-driven filtering: every keystroke previously fired
    // a synchronous O(N) scan over every row, which on million-row CSV /
    // EVTX / SQLite tables is the dominant typing-lag source. 150 ms is
    // short enough to feel responsive but coalesces typing bursts.
    // Small tables (<5k rows) skip the debounce so muscle-memory users
    // still see instant updates.
    this._filterDebounceMs = 150;
    this._filterDebounceMin = 5000;
    this._filterTimer = null;
    const _runFilter = () => {
      this._filterTimer = null;
      this._applyFilter();
    };
    this._boundHandlers.onFilter = () => {
      const big = this._rowCount() >= this._filterDebounceMin;
      if (this._filterTimer != null) clearTimeout(this._filterTimer);
      if (big) {
        this._filterTimer = setTimeout(_runFilter, this._filterDebounceMs);
      } else {
        this._applyFilter();
      }
    };
    this._filterInput.addEventListener('input', this._boundHandlers.onFilter);
    this._filterInput.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { this._filterInput.blur(); }
      // Enter forces an immediate filter (skips debounce).
      if (e.key === 'Enter') {
        if (this._filterTimer != null) { clearTimeout(this._filterTimer); this._filterTimer = null; }
        this._applyFilter();
      }
    });
    this._clearBtn.addEventListener('click', () => {
      if (this._filterTimer != null) { clearTimeout(this._filterTimer); this._filterTimer = null; }
      this._filterInput.value = '';
      this._applyFilter();
    });

    // Kick off background pre-build of the row-search-text cache so the
    // first filter keystroke on a million-row table doesn't pay the
    // materialisation cost. Idempotent — re-running it skips already-built
    // rows. EVTX / Timeline already supply this array in `setRows` and
    // skip the work.
    this._scheduleIdleSearchTextBuild();

    // Row click → drawer toggle
    this._boundHandlers.onSizerClick = (e) => {
      const row = e.target.closest('.grid-row');
      if (!row || !row.dataset.idx) return;
      const dataIdx = +row.dataset.idx;
      if (this.state.drawer.open && this.state.drawer.dataIdx === dataIdx) {
        this._closeDrawer();
      } else {
        this._openDrawer(dataIdx);
      }
    };
    this._sizer.addEventListener('click', this._boundHandlers.onSizerClick);

    // Drawer close
    this._drawerClose.addEventListener('click', () => this._closeDrawer());

    // Keyboard: Esc closes drawer when scroll container or drawer is focused.
    // [ / ] pan the active time window; Esc (when no drawer) clears it.
    this._boundHandlers.onKey = (e) => {
      if (e.key === 'Escape') {
        if (this.state.drawer.open) {
          this._closeDrawer();
          e.stopPropagation();
          return;
        }
        if (this._timeWindow) {
          this._clearTimeWindow();
          e.stopPropagation();
          return;
        }
      }
      if ((e.key === '[' || e.key === ']') && this._timeWindow) {
        this._stepTimeWindow(e.key === ']' ? +1 : -1);
        e.stopPropagation();
        e.preventDefault();
      }
      // Arrow up / down — step the drawer through consecutive visible
      // rows. Respects the active sort + filter by walking via
      // virtual-row index (`_virtualIdxOf` / `_dataIdxOf`), so a sorted
      // EVTX view or a DSL-filtered Timeline grid both advance through
      // whatever the user is actually looking at. If no row is open,
      // the first key-press opens the drawer on the first visible row
      // (Down) or last visible row (Up). Scrolls the target into view
      // via `_scrollToRow` so the drawer follows without the analyst
      // losing their place.
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        // Don't steal arrow keys from interactive controls embedded
        // in the drawer (e.g. the query-editor textarea, select
        // elements, JSON-tree toggles).
        const tag = e.target && e.target.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
        if (e.target && e.target.isContentEditable) return;
        const visible = this._visibleCount();
        if (!visible) return;
        let vIdx;
        if (this.state.drawer.open && this.state.drawer.dataIdx >= 0) {
          const curV = this._virtualIdxOf(this.state.drawer.dataIdx);
          if (curV < 0) {
            // Drawer-open row is no longer visible under the current
            // filter — fall back to the first visible row on Down,
            // last on Up, so the user can still drive from here.
            vIdx = e.key === 'ArrowDown' ? 0 : visible - 1;
          } else {
            vIdx = e.key === 'ArrowDown' ? curV + 1 : curV - 1;
          }
        } else {
          vIdx = e.key === 'ArrowDown' ? 0 : visible - 1;
        }
        if (vIdx < 0 || vIdx >= visible) {
          // Off either end — swallow the key but don't move (prevents
          // the browser from scrolling the outer page instead).
          e.preventDefault();
          e.stopPropagation();
          return;
        }
        const dataIdx = this._dataIdxOf(vIdx);
        if (dataIdx == null) return;
        e.preventDefault();
        e.stopPropagation();
        this._scrollToRow(dataIdx, /* highlightFlash */ false);
      }
    };
    this._scr.addEventListener('keydown', this._boundHandlers.onKey);
    this._drawer.addEventListener('keydown', this._boundHandlers.onKey);

    // Timeline drag-select + click-bucket + hover-tooltip.
    this._wireTimelineEvents();
    this._timelineClearBtn.addEventListener('click', () => this._clearTimeWindow());


    // Drawer handle drag to resize
    this._wireDrawerResize();

    // Drawer in-pane search (smooth-scrolls + highlights).
    this._wireDrawerSearch();

    // Malformed-row ribbon — Next and Filter buttons.
    this._malformedNextBtn.addEventListener('click', () => this._jumpToNextMalformed());
    this._malformedFilterBtn.addEventListener('click', () => this._toggleMalformedFilter());

    // Hidden-columns chip — the left label opens a popover listing every
    // hidden column; the right "Show all" button unhides them in one shot.
    this._hiddenChipLabelBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this._openHiddenColsPopover(this._hiddenChipLabelBtn);
    });
    this._hiddenShowAllBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      this._unhideAllColumns();
    });

    // Global click to dismiss any open header / top-values popover.
    // Header cells are exempt from mousedown-dismiss so the click handler
    // (which fires after mousedown) can apply its own toggle logic: close
    // if the same column is already open, close-then-reopen for a
    // different column. Without this exemption, mousedown would always
    // pre-close the popover, defeating the toggle check.
    this._boundHandlers.onDocClick = (e) => {
      if (!this._openPopover) return;
      if (this._openPopover.contains(e.target)) return;
      if (e.target.closest && e.target.closest('.grid-header-cell')) return;
      this._closePopover();
    };
    document.addEventListener('mousedown', this._boundHandlers.onDocClick, true);

    // Dismiss the popover on any scroll — capture-phase so scrolls inside
    // our own `.grid-scroll` container (and any ancestor scroller) trigger
    // it too. Matches the behaviour of Timeline Mode's popovers and the
    // json-tree key menu, so header / top-values menus never dangle over
    // content that has moved underneath them.
    this._boundHandlers.onDocScroll = () => {
      if (this._openPopover) this._closePopover();
    };
    window.addEventListener('scroll', this._boundHandlers.onDocScroll, true);

    // ResizeObserver on scroll container. Re-runs the viewport-fill pass
    // in _applyColumnTemplate() so columns re-stretch when the window /
    // drawer / sidebar resizes, then schedules a render. The initial
    // constructor pass runs with clientWidth === 0 (not yet in the DOM),
    // so the *first* ResizeObserver tick after mount is actually what
    // makes the grid fill its host — which is exactly what we want.
    this._resizeObs = new ResizeObserver(() => {
      this._applyColumnTemplate();
      this._scheduleRender();
    });
    this._resizeObs.observe(this._scr);
  }


  _drawerMaxW() {
    // Upper bound recomputed per-call so a viewport resize takes effect on
    // the very next drag tick. `window.innerWidth` is the cheapest proxy —
    // the grid host may be narrower (e.g. inside Timeline Mode's layout)
    // but the flex container caps the rendered width anyway, and erring
    // on the permissive side lets the user drag the drawer as wide as
    // they want while still leaving `DRAWER_MIN_GRID_W` px for the grid.
    const vw = (window && window.innerWidth) || 1200;
    return Math.max(900, vw - this.DRAWER_MIN_GRID_W);
  }

  _wireDrawerResize() {
    let startX = 0, startW = 0, dragging = false;
    const onMove = (e) => {
      if (!dragging) return;
      const dx = startX - e.clientX;
      const newW = Math.max(this.DRAWER_MIN_W, Math.min(this._drawerMaxW(), startW + dx));
      this.state.drawer.width = newW;
      this._drawer.style.flexBasis = newW + 'px';
    };
    const onUp = () => {
      if (!dragging) return;
      dragging = false;
      document.body.classList.remove('grid-resizing');
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      this._saveDrawerWidth(this.state.drawer.width);
    };
    this._drawerHandle.addEventListener('mousedown', (e) => {
      dragging = true;
      startX = e.clientX;
      startW = this.state.drawer.width;
      document.body.classList.add('grid-resizing');
      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onUp);
      e.preventDefault();
    });
    this._drawerHandle.addEventListener('dblclick', () => {
      const defaultW = 700;
      this.state.drawer.width = defaultW;
      this._drawer.style.flexBasis = defaultW + 'px';
      this._saveDrawerWidth(defaultW);
    });
  }

  _loadDrawerWidth() {
    const v = parseInt(safeStorage.get('loupe_grid_drawer_w'), 10);
    if (Number.isFinite(v)) return Math.max(this.DRAWER_MIN_W, Math.min(this._drawerMaxW(), v));
    return 420;
  }
  _saveDrawerWidth(w) {
    safeStorage.set('loupe_grid_drawer_w', String(w));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  DRAWER IN-PANE SEARCH
  //
  //  Lightweight local find for the detail drawer — the full row can be
  //  huge (EVTX rendered-message, JSON trees hundreds of lines deep) and
  //  the grid's row filter is no help once you're *inside* one row's
  //  detail. The search walks the drawer-body's text nodes, wraps every
  //  hit in a `<mark class="grid-drawer-hit">` span, and smooth-scrolls
  //  the current hit into view. Enter / Shift+Enter step through hits;
  //  Esc clears the term; Ctrl/Cmd+F focuses the input when any element
  //  inside the drawer has focus.
  // ═══════════════════════════════════════════════════════════════════════════
  _wireDrawerSearch() {
    const input = this._drawer.querySelector('.grid-drawer-search');
    if (!input) return;
    this._drawerSearchInput = input;
    this._drawerSearchCount = this._drawer.querySelector('.grid-drawer-search-count');
    const nextBtn = this._drawer.querySelector('.grid-drawer-search-next');
    const prevBtn = this._drawer.querySelector('.grid-drawer-search-prev');
    this._drawerSearchTerm = '';
    this._drawerSearchHits = [];
    this._drawerSearchIdx = -1;

    let debounceT = null;
    const scheduleApply = () => {
      if (debounceT) clearTimeout(debounceT);
      debounceT = setTimeout(() => {
        debounceT = null;
        this._applyDrawerSearch(input.value);
      }, 80);
    };

    input.addEventListener('input', scheduleApply);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        if (debounceT) { clearTimeout(debounceT); debounceT = null; this._applyDrawerSearch(input.value); }
        this._stepDrawerSearch(e.shiftKey ? -1 : +1);
      } else if (e.key === 'Escape') {
        if (input.value) {
          input.value = '';
          this._applyDrawerSearch('');
          e.preventDefault();
          e.stopPropagation();
        }
      }
    });
    if (nextBtn) nextBtn.addEventListener('click', (e) => { e.preventDefault(); this._stepDrawerSearch(+1); });
    if (prevBtn) prevBtn.addEventListener('click', (e) => { e.preventDefault(); this._stepDrawerSearch(-1); });

    // Ctrl/Cmd+F while focus is anywhere inside the drawer → focus the
    // search input. Capture phase so it beats the browser's own find
    // dialog when the drawer has focus.
    this._drawer.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'f' || e.key === 'F')) {
        e.preventDefault();
        e.stopPropagation();
        input.focus();
        input.select();
      }
    });
  }

  /** Apply the current search term to the drawer body. Clears any
   *  previous hit spans, then walks text nodes under `.grid-drawer-body`
   *  and wraps each case-insensitive substring match. Collapses hits
   *  longer than 400 per call as a sanity cap so a 1-char term in a
   *  30 KB rendered-message field doesn't DOM-bomb the tab. */
  _applyDrawerSearch(rawTerm) {
    const term = (rawTerm || '').trim();
    this._drawerSearchTerm = term;
    this._clearDrawerSearchHits();
    if (!term) {
      this._drawerSearchHits = [];
      this._drawerSearchIdx = -1;
      this._updateDrawerSearchCount();
      return;
    }
    const hits = [];
    const MAX_HITS = 400;
    const needle = term.toLowerCase();
    const nLen = needle.length;
    const body = this._drawerBody;
    if (!body) return;
    const walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT, {
      acceptNode: (n) => {
        // Skip text inside our own hit spans (would double-wrap on
        // repeat apply) and inside hidden subtrees.
        if (!n.nodeValue || !n.nodeValue.length) return NodeFilter.FILTER_REJECT;
        const p = n.parentNode;
        if (p && p.classList && p.classList.contains('grid-drawer-hit')) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    const pending = [];
    let node;
    while ((node = walker.nextNode())) pending.push(node);

    for (const textNode of pending) {
      if (hits.length >= MAX_HITS) break;
      const text = textNode.nodeValue;
      const lc = text.toLowerCase();
      let i = lc.indexOf(needle);
      if (i === -1) continue;
      const frag = document.createDocumentFragment();
      let pos = 0;
      while (i !== -1 && hits.length < MAX_HITS) {
        if (i > pos) frag.appendChild(document.createTextNode(text.slice(pos, i)));
        const mk = document.createElement('span');
        mk.className = 'grid-drawer-hit';
        mk.textContent = text.slice(i, i + nLen);
        frag.appendChild(mk);
        hits.push(mk);
        pos = i + nLen;
        i = lc.indexOf(needle, pos);
      }
      if (pos < text.length) frag.appendChild(document.createTextNode(text.slice(pos)));
      textNode.parentNode.replaceChild(frag, textNode);
    }

    this._drawerSearchHits = hits;
    this._drawerSearchIdx = hits.length ? 0 : -1;
    this._focusDrawerSearchHit(false);
    this._updateDrawerSearchCount();
  }

  _stepDrawerSearch(dir) {
    const hits = this._drawerSearchHits;
    if (!hits || !hits.length) return;
    let idx = this._drawerSearchIdx + dir;
    if (idx < 0) idx = hits.length - 1;
    if (idx >= hits.length) idx = 0;
    this._drawerSearchIdx = idx;
    this._focusDrawerSearchHit(true);
    this._updateDrawerSearchCount();
  }

  _focusDrawerSearchHit(smooth) {
    const hits = this._drawerSearchHits;
    if (!hits || !hits.length) return;
    for (const h of hits) h.classList.remove('grid-drawer-hit-current');
    const cur = hits[this._drawerSearchIdx];
    if (!cur) return;
    cur.classList.add('grid-drawer-hit-current');
    try {
      cur.scrollIntoView({ behavior: smooth ? 'smooth' : 'auto', block: 'center', inline: 'nearest' });
    } catch (_) {
      cur.scrollIntoView();
    }
  }

  _clearDrawerSearchHits() {
    const body = this._drawerBody;
    if (!body) return;
    const marks = body.querySelectorAll('.grid-drawer-hit');
    for (const m of marks) {
      const parent = m.parentNode;
      if (!parent) continue;
      parent.replaceChild(document.createTextNode(m.textContent), m);
      parent.normalize();
    }
  }

  _updateDrawerSearchCount() {
    const el = this._drawerSearchCount;
    if (!el) return;
    const n = this._drawerSearchHits ? this._drawerSearchHits.length : 0;
    if (!this._drawerSearchTerm) { el.textContent = ''; return; }
    if (!n) { el.textContent = 'No matches'; return; }
    el.textContent = `${this._drawerSearchIdx + 1} / ${n.toLocaleString()}`;
  }

  /** Re-apply the current drawer-search term after the drawer body has
   *  been rebuilt (row change, filter rerun, highlight refresh). Called
   *  from `_renderDrawerBody` so a user search survives navigating
   *  between rows with Arrow Up/Down. */
  _reapplyDrawerSearch() {
    if (this._drawerSearchTerm) {
      // Deferred by a microtask so any highlight wrapping installed by
      // `_wrapIocInPane` / `_wrapYaraInPane` is already in place.
      Promise.resolve().then(() => this._applyDrawerSearch(this._drawerSearchTerm));
    } else {
      this._drawerSearchHits = [];
      this._drawerSearchIdx = -1;
      this._updateDrawerSearchCount();
    }
  }


  // ═══════════════════════════════════════════════════════════════════════════
  //  RENDER CORE (the whole point of the rewrite)
  // ═══════════════════════════════════════════════════════════════════════════
  _scheduleRender() {
    if (this._renderRAF) return;
    this._renderRAF = requestAnimationFrame(() => {
      this._renderRAF = null;
      this._render();
    });
  }

  _forceFullRender() {
    this.state.renderedRange = { start: -1, end: -1 };
    this._scheduleRender();
  }

  _visibleCount() {
    return this.state.filteredIndices ? this.state.filteredIndices.length : this._rowCount();
  }

  _dataIdxOf(virtualIdx) {
    return this.state.filteredIndices ? this.state.filteredIndices[virtualIdx] : virtualIdx;
  }

  _virtualIdxOf(dataIdx) {
    if (!this.state.filteredIndices) return dataIdx;
    // Linear scan — acceptable because callers only use this for rare ops
    // (scrollToRow after an IOC click). The filter predicate is already the
    // bottleneck in those flows.
    const arr = this.state.filteredIndices;
    for (let i = 0; i < arr.length; i++) if (arr[i] === dataIdx) return i;
    return -1;
  }

  _render() {
    if (this._destroyed) return;
    const visible = this._visibleCount();

    // Update sizer height (O(1) — no dynamic row math).
    const totalH = visible * this.ROW_HEIGHT;
    this._sizer.style.height = totalH + 'px';

    if (visible === 0) {
      this._sizer.replaceChildren();
      this.state.renderedRange = { start: 0, end: 0 };
      return;
    }

    const scrollTop = this._scr.scrollTop;
    const viewportH = this._scr.clientHeight || 400;

    // Virtual range — trivial arithmetic because row height is constant.
    const firstIdx = Math.max(0, Math.floor(scrollTop / this.ROW_HEIGHT) - this.BUFFER_ROWS);
    const lastIdx = Math.min(
      visible,
      Math.ceil((scrollTop + viewportH) / this.ROW_HEIGHT) + this.BUFFER_ROWS
    );

    // Fast path: identical range.
    if (firstIdx === this.state.renderedRange.start && lastIdx === this.state.renderedRange.end) {
      // Still refresh highlight decorations in case state.highlight changed.
      this._refreshHighlightDecorations();
      return;
    }

    // Atomic replacement — DocumentFragment prevents intermediate empty state.
    const frag = document.createDocumentFragment();
    for (let v = firstIdx; v < lastIdx; v++) {
      const dataIdx = this._dataIdxOf(v);
      if (dataIdx == null || dataIdx >= this._rowCount()) continue;
      frag.appendChild(this._buildRow(dataIdx, v));
    }
    this._sizer.replaceChildren(frag);
    this.state.renderedRange = { start: firstIdx, end: lastIdx };
  }

  _buildRow(dataIdx, virtualIdx) {
    const row = this._rowAt(dataIdx);
    const tr = document.createElement('div');
    // Zebra striping is stamped from `dataIdx` parity (stable per source
    // row) rather than via CSS `:nth-child`, which would re-shuffle on
    // every scroll tick because only the visible window of rows is
    // materialised in the virtualised DOM — the same data row would
    // flip between even/odd as it moved through the buffer. Keying on
    // dataIdx pins each row to a single banded colour for the lifetime
    // of the dataset regardless of scroll position.
    tr.className = 'grid-row ' + ((dataIdx & 1) ? 'grid-row-odd' : 'grid-row-even');
    tr.dataset.idx = dataIdx;
    tr.dataset.vidx = virtualIdx;
    tr.style.top = (virtualIdx * this.ROW_HEIGHT) + 'px';

    // Row-number cell — shows the display position (1-indexed) so that
    // when sorted (e.g. ascending by timestamp) the # column counts up
    // sequentially from 1 regardless of the original file order.
    const numCell = document.createElement('div');
    numCell.className = 'grid-cell grid-row-num';
    numCell.textContent = String(virtualIdx + 1);
    tr.appendChild(numCell);

    // Data cells — iterate in DISPLAY order so cell DOM matches the
    // header's CSS-grid template column-by-column. `c` remains the REAL
    // column index throughout the loop body, so every reference into
    // the row array, kind table, augment hooks, and `data-col` stamp
    // continues to use the original index space.
    const order = this._resolveColOrder();
    for (let oi = 0; oi < order.length; oi++) {
      const c = order[oi];
      if (this._hiddenCols.has(c)) continue;
      const td = document.createElement('div');
      td.className = 'grid-cell';
      // Stamp the real column index on the cell so consumers (e.g. the
      // Timeline's right-click handler) can resolve clicked column →
      // original column index without positional math. Doing the math
      // against `cell.parentNode.children` breaks the moment any column
      // is hidden, because `_hiddenCols` entries are skipped above —
      // and the same is true once display reordering enters the picture.
      td.dataset.col = c;
      const rawCell = row ? (row[c] != null ? row[c] : '') : '';
      const displayCell = this._cellTextFn
        ? this._cellTextFn(dataIdx, c, rawCell)
        : rawCell;
      const asStr = String(displayCell == null ? '' : displayCell);
      // Hard DOM-safety cap — even a resizable column can't render a 100 KB
      // JSON blob as a single text node without wrecking layout. Cap at
      // 4000 chars; CSS `text-overflow: ellipsis` on `.grid-cell` still
      // handles the visible clipping at the column edge. Raising this
      // from the legacy 160 was the fix for the "Events column ellipses
      // long before the cell edge" bug — 160 fired well before CSS
      // ever got a chance to truncate at the real viewport width.
      const truncated = asStr.length > 4000 ? asStr.substring(0, 4000) + '…' : asStr;
      td.textContent = truncated;
      if (asStr.length > 40) td.title = asStr.length > 4000 ? asStr.substring(0, 4000) + '…' : asStr;
      // Optional format-specific tooltip override. Timeline Mode's EVTX
      // view uses this to stamp the "Event ID → human summary + MITRE
      // ATT&CK" multi-line tooltip onto the Event ID column.
      if (this._cellTitleFn) {
        try {
          const t = this._cellTitleFn(dataIdx, c, rawCell);
          if (t != null) td.title = String(t);
        } catch (_) { /* decorative only */ }
      }
      // Use the column-level classification (number/id) to decide numeric
      // styling instead of per-cell sniffing.  This prevents mixed-content
      // columns (e.g. browser-history Title "47643_babana_02.jpg …") from
      // flipping individual cells to green / right-aligned just because the
      // string happens to start with a digit.  Callers that force numeric
      // styling via cellClass callbacks (SQLite Visit Count, etc.) are
      // unaffected — that path runs separately below.
      const colKind = this._columnKinds && this._columnKinds[c];
      if (colKind === 'number' || colKind === 'id') {
        td.classList.add('grid-cell-num');
      } else if (!colKind && asStr && !isNaN(parseFloat(asStr)) && /^-?\d/.test(asStr.trim())) {
        // Defensive fallback: column classification hasn't run yet.
        td.classList.add('grid-cell-num');
      }
      if (this._cellClassFn) {
        const extra = this._cellClassFn(dataIdx, c, rawCell);
        if (extra) td.classList.add(...String(extra).split(/\s+/).filter(Boolean));
      }
      // Optional per-cell augment hook — runs AFTER textContent / class /
      // title setup so callers can append decorative children (e.g. an
      // EVTX Event-ID summary + ATT&CK pill in the visible grid cell).
      // Mirrors the drawer-side `detailAugment` hook.
      if (this._cellAugmentFn) {
        try { this._cellAugmentFn(dataIdx, c, rawCell, td); }
        catch (_) { /* decorative only */ }
      }
      tr.appendChild(td);
    }


    // Selected / highlighted / malformed state
    if (this.state.drawer.open && this.state.drawer.dataIdx === dataIdx) {
      tr.classList.add('csv-row-selected', 'grid-row-selected');
    }
    if (this._malformedRows && this._malformedRows.has(dataIdx)) {
      tr.classList.add('grid-row-malformed');
    }
    if (this._rowClassFn) {
      try {
        const extra = this._rowClassFn(dataIdx);
        if (extra) tr.classList.add(...String(extra).split(/\s+/).filter(Boolean));
      } catch { /* decorative only */ }
    }


    const h = this.state.highlight;
    if (h && !this._highlightExpired(h)) {
      if (h.mode === 'flash' && h.dataIdx === dataIdx) {
        tr.classList.add('csv-row-highlight');
      } else if (h.mode === 'ioc' && h.dataIdx === dataIdx) {
        tr.classList.add('csv-ioc-row-highlight');
      } else if (h.mode === 'yara' && h.matchesByDataIdx && h.matchesByDataIdx.has(dataIdx)) {
        tr.classList.add('csv-yara-row-highlight');
      }
    }
    return tr;
  }

  _refreshHighlightDecorations() {
    // Re-sync row-level classes without rebuilding the row DOM.
    const h = this.state.highlight;
    const rows = this._sizer.querySelectorAll('.grid-row');
    for (const tr of rows) {
      const dataIdx = +tr.dataset.idx;
      tr.classList.remove('csv-row-highlight', 'csv-ioc-row-highlight', 'csv-yara-row-highlight');
      if (h && !this._highlightExpired(h)) {
        if (h.mode === 'flash' && h.dataIdx === dataIdx) tr.classList.add('csv-row-highlight');
        else if (h.mode === 'ioc' && h.dataIdx === dataIdx) tr.classList.add('csv-ioc-row-highlight');
        else if (h.mode === 'yara' && h.matchesByDataIdx && h.matchesByDataIdx.has(dataIdx))
          tr.classList.add('csv-yara-row-highlight');
      }
      // Re-apply selected state
      tr.classList.toggle('csv-row-selected', this.state.drawer.open && this.state.drawer.dataIdx === dataIdx);
      tr.classList.toggle('grid-row-selected', this.state.drawer.open && this.state.drawer.dataIdx === dataIdx);
    }
  }

  _highlightExpired(h) {
    return !h || performance.now() >= h.clearAt;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  DRAWER
  // ═══════════════════════════════════════════════════════════════════════════
  _openDrawer(dataIdx) {
    this.state.drawer.open = true;
    this.state.drawer.dataIdx = dataIdx;
    this._drawer.style.display = '';
    this._drawerHandle.style.display = '';
    this._drawer.style.flexBasis = this.state.drawer.width + 'px';
    this._renderDrawerBody(dataIdx);
    this._refreshHighlightDecorations();
    // Re-anchor the timeline scrub cursor onto the opened event so it
    // tracks the user's focused row instead of continuing to drift with
    // scroll position.
    this._updateTimelineCursor();
  }

  _closeDrawer() {
    this.state.drawer.open = false;
    this.state.drawer.dataIdx = -1;
    this._drawer.style.display = 'none';
    this._drawerHandle.style.display = 'none';
    this._drawerBody.replaceChildren();
    this._refreshHighlightDecorations();
    // Drawer-anchor gone — fall back to the scroll-position anchor for
    // the timeline cursor.
    this._updateTimelineCursor();
  }

  _renderDrawerBody(dataIdx) {
    const row = this._rowAt(dataIdx);
    if (!row) { this._drawerBody.replaceChildren(); return; }
    // Title — overridable by format-specific renderers (EVTX wants
    //   "Event 4624 — Record 12345", not "Row 42").
    if (this._rowTitleFn) {
      try {
        const t = this._rowTitleFn(dataIdx, row, this.columns);
        this._drawerTitle.textContent = t != null ? String(t) : `Row ${(dataIdx + 1).toLocaleString()}`;
      } catch (_) {
        this._drawerTitle.textContent = `Row ${(dataIdx + 1).toLocaleString()}`;
      }
    } else {
      this._drawerTitle.textContent = `Row ${(dataIdx + 1).toLocaleString()}`;
    }

    // Drawer body — format-specific override wins; fall back to the default
    // two-column key/value grid used by CSV / JSON / generic tabular views.
    let pane = null;
    if (this._detailBuilder) {
      try {
        pane = this._detailBuilder(dataIdx, row, this.columns);
      } catch (e) {
        pane = null;
        // Log but don't kill the viewer — fall back to default pane.
        try { console.error('grid-viewer detailBuilder threw', e); } catch (_) { /* ignore */ }
      }
    }
    if (!pane) pane = this._buildDetailPaneElement(this.columns, row, dataIdx);

    // Apply any live highlight decorations (IOC / YARA) to the fresh pane.
    const h = this.state.highlight;
    if (h && !this._highlightExpired(h)) {
      if (h.mode === 'ioc' && h.dataIdx === dataIdx && h.term) {
        this._wrapIocInPane(pane, h.term);
      } else if (h.mode === 'yara' && h.matchesByDataIdx && h.matchesByDataIdx.has(dataIdx)) {
        this._wrapYaraInPane(pane, h.matchesByDataIdx.get(dataIdx), h.sourceText);
      }
    }
    this._drawerBody.replaceChildren(pane);
    this._reapplyDrawerSearch();
  }

  _buildDetailPaneElement(cols, row, dataIdx) {
    const pane = document.createElement('div');
    pane.className = 'csv-detail-pane grid-detail-pane';
    const grid = document.createElement('div');
    grid.className = 'csv-detail-grid';
    let hasContent = false;
    // Shared JSON tree renderer — present at runtime because `src/json-tree.js`
    // loads before `grid-viewer.js` in the build order. Guard the access so a
    // future accidental reorder doesn't explode the drawer.
    const TreeHelper = (typeof window !== 'undefined' && window.JsonTree) || null;
    for (let i = 0; i < cols.length; i++) {
      if (this._hiddenCols.has(i)) continue;
      const key = cols[i] || `Column ${i + 1}`;
      const val = row[i] || '';
      if (!val || !String(val).trim()) continue;
      hasContent = true;
      const kEl = document.createElement('div');
      kEl.className = 'csv-detail-key';
      kEl.textContent = key;
      kEl.title = key;
      grid.appendChild(kEl);
      const vEl = document.createElement('div');
      vEl.className = 'csv-detail-val';
      // Optional per-cell decoration (e.g. Timeline Mode's 🚩 Sus mark
      // tint). Applied to BOTH the key and value elements so the whole
      // drawer row reads as flagged.
      if (this._detailCellClassFn) {
        try {
          const extra = this._detailCellClassFn(dataIdx, i, val);
          if (extra) {
            const parts = String(extra).split(/\s+/).filter(Boolean);
            if (parts.length) {
              kEl.classList.add(...parts);
              vEl.classList.add(...parts);
            }
          }
        } catch { /* decorative only */ }
      }


      // JSON-aware drawer body — when a cell parses as a JSON object or
      // array, render it as a collapsible tree instead of plain text.
      // Right-clicking a scalar leaf key in the tree opens a menu
      // (Extract column / Include value / Exclude value) that fires
      // `onCellPick(dataIdx, colIdx, path, nodeValue, action)`. Composite
      // (object / array) keys have no context menu. Timeline Mode uses
      // this to extract the path as a new virtual column — and, for
      // include/exclude, to add a matching filter chip on the newly
      // created column. When the parent view didn't supply a pick
      // callback the tree still renders (expand/collapse still works);
      // the key-context menu is simply absent.
      let parsed;
      try { parsed = TreeHelper ? TreeHelper.tryParse(val) : undefined; }
      catch (_) { parsed = undefined; }
      if (parsed !== undefined && TreeHelper) {
        vEl.classList.add('csv-detail-val-json');
        const onPick = this._onCellPick
          ? (path, nodeValue, action) => {
            try { this._onCellPick(dataIdx, i, path, nodeValue, action); }
            catch (e) { try { console.error('onCellPick threw', e); } catch (_) { /* ignore */ } }
          }
          : null;
        const tree = TreeHelper.render(parsed, {
          onPick,
          // Expand every nested object/array by default — the drawer is a
          // detail view, so the user has already opted into seeing the
          // whole row. Hard caps (MAX_DEPTH=16, maxChildren=200) inside
          // JsonTree still bound the work.
          autoOpenDepth: Infinity,
          maxChildren: 200
        });
        vEl.appendChild(tree);
      } else {
        vEl.textContent = val;
        // Plain-text drawer field — right-click the key OR value to
        // Include / Exclude that value on the source column. Mirrors the
        // JSON-leaf context menu above (Extract is omitted — the source
        // column already exists). Sends an *empty* path array to
        // `onCellPick` as the "this is a direct column filter, not a
        // JSON-extract" sentinel; Timeline Mode's `onCellPick` handler
        // dispatches on `path.length === 0` and pushes a chip directly
        // against `colIdx` without creating a virtual extracted column.
        if (this._onCellPick) {
          const colIdx = i;
          const leafValue = val;
          const openMenu = (ev) => {
            ev.preventDefault();
            ev.stopPropagation();
            this._openDrawerCellMenu(ev, dataIdx, colIdx, leafValue);
          };
          kEl.classList.add('grid-detail-key-pickable');
          kEl.title = key + ' — right-click to filter';
          kEl.addEventListener('contextmenu', openMenu);
          vEl.addEventListener('contextmenu', openMenu);
        }
      }
      grid.appendChild(vEl);
      // Optional format-specific drawer-row augment. Runs AFTER the
      // default key/value row is populated, so callers can append pill
      // badges or tweak tooltips without re-implementing the whole pane.
      if (this._detailAugmentFn) {
        try {
          this._detailAugmentFn(dataIdx, i, val, { keyEl: kEl, valEl: vEl, colName: key });
        } catch (_) { /* decorative only */ }
      }
    }

    if (!hasContent) {
      const empty = document.createElement('p');
      empty.className = 'grid-detail-empty';
      empty.textContent = 'All columns are empty for this row.';
      grid.appendChild(empty);
    }
    pane.appendChild(grid);
    return pane;
  }

  _wrapIocInPane(pane, term) {
    if (!term) return;
    const needle = term.toLowerCase();
    const valEls = pane.querySelectorAll('.csv-detail-val');
    for (const el of valEls) {
      const text = el.textContent;
      if (!text) continue;
      const idx = text.toLowerCase().indexOf(needle);
      if (idx === -1) continue;
      const before = _esc(text.slice(0, idx));
      const matched = _esc(text.slice(idx, idx + term.length));
      const after = _esc(text.slice(idx + term.length));
      el.innerHTML = `${before}<mark class="csv-ioc-highlight csv-ioc-highlight-flash">${matched}</mark>${after}`;
    }
  }

  _wrapYaraInPane(pane, rowMatches, sourceText) {
    if (!rowMatches || !rowMatches.length || !sourceText) return;
    const valEls = pane.querySelectorAll('.csv-detail-val');
    for (const el of valEls) {
      const text = el.textContent;
      if (!text) continue;
      const hits = [];
      for (const rm of rowMatches) {
        const matchStr = sourceText.substring(rm.offset, rm.offset + rm.length);
        if (!matchStr) continue;
        let idx = text.indexOf(matchStr);
        if (idx === -1) idx = text.toLowerCase().indexOf(matchStr.toLowerCase());
        if (idx !== -1) hits.push({ start: idx, end: idx + matchStr.length, matchIdx: rm._matchIdx });
      }
      if (!hits.length) continue;
      hits.sort((a, b) => a.start - b.start);
      // Resolve overlaps: earliest-start-wins.
      const keep = [];
      let cur = -1;
      for (const h of hits) { if (h.start >= cur) { keep.push(h); cur = h.end; } }
      let out = '';
      let pos = 0;
      for (const h of keep) {
        if (h.start > pos) out += _esc(text.substring(pos, h.start));
        out += `<mark class="csv-yara-highlight csv-yara-highlight-flash" data-yara-match="${h.matchIdx}">${_esc(text.substring(h.start, h.end))}</mark>`;
        pos = h.end;
      }
      if (pos < text.length) out += _esc(text.substring(pos));
      el.innerHTML = out;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  FILTER
  // ═══════════════════════════════════════════════════════════════════════════
  _applyFilter() {
    const query = this._filterInput.value.toLowerCase().trim();
    this._closeDrawer();
    this._clearHighlight(/* silent */ true);

    const total = this._rowCount();
    const tw = this._timeWindow;
    if (!query && !tw) {
      this.state.filteredIndices = null;
      this._clearBtn.style.display = 'none';
      this._filterStatus.textContent = '';
    } else {
      // Surface a busy hint on tables large enough for the loop to be
      // visible. The status flips back to the row-count below; if the
      // browser yields between sets, the user sees "Filtering…" briefly.
      if (total >= 50000) this._filterStatus.textContent = 'Filtering…';
      const _filterStart = (total >= 50000) ? Date.now() : 0;
      const out = [];
      for (let i = 0; i < total; i++) {
        if (query && !this._rowMatchesQuery(i, query)) continue;
        if (tw && !this._dataIdxInTimeWindow(i)) continue;
        out.push(i);
      }
      this.state.filteredIndices = out;
      this._clearBtn.style.display = query ? '' : 'none';
      const suffix = tw ? ' · timeline window' : '';
      const elapsed = _filterStart ? (Date.now() - _filterStart) : 0;
      const slow = elapsed > 250 ? ` · ${elapsed} ms` : '';
      this._filterStatus.textContent = query || tw
        ? `${out.length.toLocaleString()} of ${total.toLocaleString()} rows${suffix}${slow}`
        : '';
    }
    this._scr.scrollTop = 0;
    this._forceFullRender();
    // Filter changed — histogram counts per bucket change too.
    // Rebuild + repaint so the timeline shrinks in step with the grid body.
    this._refreshTimelineBuckets();
  }


  _dataIdxInTimeWindow(dataIdx) {
    if (!this._timeWindow || !this._timeMs) return true;
    const t = this._timeMs[dataIdx];
    if (!Number.isFinite(t)) return false;
    return t >= this._timeWindow.min && t <= this._timeWindow.max;
  }


  _rowMatchesQuery(dataIdx, needle) {
    // `!= null` — `''` (a row of all-empty cells with zero columns)
    // is a legitimate cached value that must short-circuit the rebuild.
    // Truthy-check would treat it as "not yet built" and re-allocate
    // forever on each filter pass; in tree this case is unreachable
    // (every grid has ≥ 1 column) but the precise check is a free
    // correctness fix.
    if (this.rowSearchText && this.rowSearchText[dataIdx] != null) {
      return this.rowSearchText[dataIdx].includes(needle);
    }
    // Cache disabled — resolve match on the fly without caching. The
    // timeline path takes this branch: its query DSL is primary, the
    // filter bar is rare, and a 160 MB cache for a feature the user
    // doesn't reach for is the wrong trade.
    if (!this._searchTextCache) {
      const row = this.store.getRow(dataIdx);
      return row.join(' ').toLowerCase().includes(needle);
    }
    // Cache enabled — build on demand and cache for re-use, mirroring the
    // eager idle pre-build's policy so subsequent matches on the same
    // row are O(1).
    const row = this.store.getRow(dataIdx);
    const joined = row.join(' ').toLowerCase();
    if (!this.rowSearchText) this.rowSearchText = new Array(this._rowCount());
    this.rowSearchText[dataIdx] = joined;
    return joined.includes(needle);
  }

  // ── Idle pre-build of `rowSearchText` ────────────────────────────────────
  // Walks the store in 5 K-row batches via `requestIdleCallback` (with a
  // `setTimeout(_, 0)` fallback) and populates `this.rowSearchText[i]` so the
  // first filter keystroke on a million-row table doesn't pay an O(N · avg
  // row width) string-materialisation cost. Cancelled and re-scheduled on
  // every `setRows`. Skipped on tables <5 K rows (the lazy fallback in
  // `_rowMatchesQuery` is fast enough at that size) and when
  // `searchTextCache` is false.
  //
  // The per-cell `if (this.rowSearchText[i] != null) continue` check is
  // what makes this safe to re-schedule mid-build, but it ALSO means
  // stale entries from a previous `setRows` are silently retained —
  // `setRows` MUST drop the cache (`this.rowSearchText = null`) when
  // the caller doesn't supply a fresh array, otherwise filtering reads
  // stale text from the prior dataset and silently filters the wrong
  // rows.
  _scheduleIdleSearchTextBuild() {
    // Pair the schedule and cancel API choices so a handle scheduled via
    // `requestIdleCallback` is always cancelled via `cancelIdleCallback`
    // (and the `setTimeout` / `clearTimeout` fallback likewise). Selecting
    // each independently risks calling the wrong canceller on a handle in
    // the (vanishingly rare) browser that ships one without the other.
    const useIdle  = (typeof requestIdleCallback === 'function');
    const schedule = useIdle
      ? (fn) => requestIdleCallback(fn, { timeout: 250 })
      : (fn) => setTimeout(fn, 0);
    const cancel   = useIdle ? cancelIdleCallback : clearTimeout;

    if (this._idleBuildHandle != null) {
      try { cancel(this._idleBuildHandle); } catch (_e) { /* ignore */ }
      this._idleBuildHandle = null;
    }
    // Cache policy gate — only build when the renderer explicitly opts in
    // via `searchTextCache: true`. The default skips the eager build;
    // the lazy fallback in `_rowMatchesQuery` would refuse to cache
    // anyway.
    if (!this._searchTextCache) return;
    const total = this._rowCount();
    if (total < 5000) return;
    if (!this.rowSearchText) this.rowSearchText = new Array(total);
    let i = 0;
    const BATCH = 5000;
    const step = () => {
      this._idleBuildHandle = null;
      const end = Math.min(i + BATCH, total);
      for (; i < end; i++) {
        // Skip rows the lazy path already populated. `!= null` (not
        // truthy) so a legitimately-empty cached entry isn't rebuilt.
        if (this.rowSearchText[i] != null) continue;
        const row = this.store.getRow(i);
        this.rowSearchText[i] = row.join(' ').toLowerCase();
      }
      if (i < total) {
        this._idleBuildHandle = schedule(step);
      }
    };
    this._idleBuildHandle = schedule(step);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  SCROLL-TO-ROW
  // ═══════════════════════════════════════════════════════════════════════════
  _scrollToRow(dataIdx, highlightFlash = true) {
    return new Promise((resolve) => {
      if (this._destroyed) { resolve(); return; }

      // If the row is filtered out, clear the filter.
      let vIdx = this._virtualIdxOf(dataIdx);
      if (vIdx === -1 && this.state.filteredIndices) {
        this._filterInput.value = '';
        this.state.filteredIndices = null;
        this._clearBtn.style.display = 'none';
        this._filterStatus.textContent = '';
        vIdx = dataIdx;
      }
      if (vIdx < 0) { resolve(); return; }

      // Open drawer for the target row so its details are visible.
      if (!this.state.drawer.open || this.state.drawer.dataIdx !== dataIdx) {
        this._openDrawer(dataIdx);
      } else {
        // Drawer already open on this row — refresh its body so current
        // highlight state is reflected.
        this._renderDrawerBody(dataIdx);
      }

      // Install flash highlight BEFORE rendering so _buildRow paints it.
      if (highlightFlash) this._setHighlight({ mode: 'flash', dataIdx, clearMs: 2000 });

      // Compute target scrollTop (center the row in the viewport).
      const viewportH = this._scr.clientHeight || 400;
      const rowTop = vIdx * this.ROW_HEIGHT;
      const target = Math.max(0, rowTop - (viewportH - this.ROW_HEIGHT) / 2);
      const current = this._scr.scrollTop;
      const distance = Math.abs(target - current);

      // Already there (or effectively): just rerender and resolve next frame.
      if (distance < 4) {
        this._forceFullRender();
        requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
        return;
      }

      // Long jumps → instant. Short jumps → smooth. Smooth on a long jump
      // used to trigger the scrollend-polyfill race; we sidestep it entirely.
      const behavior = distance > viewportH * 1.5 ? 'instant' : 'smooth';
      this.state.isProgrammaticScroll = true;
      this._scr.scrollTo({ top: target, left: 0, behavior });

      // Resolve after a rAF tick — not via scrollend. Smooth animations
      // finish under 300 ms in practice and the renderer catches up on
      // subsequent scroll events. If the user scrolls during the animation
      // we just bail to wherever they land.
      const settle = () => {
        this.state.isProgrammaticScroll = false;
        this._forceFullRender();
        requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
      };
      if (behavior === 'instant') {
        // Scroll has already happened synchronously; next frame renders.
        requestAnimationFrame(settle);
      } else {
        // Smooth — give the browser ~350 ms to animate, then reassert render.
        setTimeout(settle, 360);
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  HIGHLIGHT STATE MACHINE
  // ═══════════════════════════════════════════════════════════════════════════
  _setHighlight(spec) {
    // Cancel any previous highlight atomically. No supersession races.
    this._cancelHighlightTimer();
    const clearMs = spec.clearMs || 5000;
    const clearAt = performance.now() + clearMs;
    const base = { clearAt, onExpire: spec.onExpire || null };
    const h = { ...spec, ...base };
    this.state.highlight = h;
    h.timer = setTimeout(() => {
      if (this._destroyed) return;
      // Only clear if this is still the active highlight (later sets
      // override timer reference via cancelHighlightTimer).
      if (this.state.highlight === h) {
        this._clearHighlight(false);
        if (typeof h.onExpire === 'function') {
          try { h.onExpire(); } catch (_) { /* never break cleanup */ }
        }
      }
    }, clearMs);

    // Paint immediately on current rows + drawer.
    this._refreshHighlightDecorations();
    if (this.state.drawer.open) this._renderDrawerBody(this.state.drawer.dataIdx);
  }

  _cancelHighlightTimer() {
    if (this.state.highlight && this.state.highlight.timer) {
      clearTimeout(this.state.highlight.timer);
      this.state.highlight.timer = null;
    }
  }

  _clearHighlight(silent) {
    this._cancelHighlightTimer();
    this.state.highlight = null;
    if (!silent) {
      this._refreshHighlightDecorations();
      if (this.state.drawer.open) this._renderDrawerBody(this.state.drawer.dataIdx);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  CHUNKED-PARSE INGEST HOOKS (used by CsvRenderer during large-file parse)
  // ═══════════════════════════════════════════════════════════════════════════
  beginParseProgress(total) {
    this.state.parseComplete = false;
    this.state.parseProgress = { rows: this._rowCount(), total };
    this._progress.classList.remove('hidden');
    this._progressBar.style.width = '0%';
    this._progressLbl.textContent = 'Parsing…';
  }
  updateParseProgress(rowsDone, totalHint) {
    const total = totalHint || this.state.parseProgress.total || 1;
    const pct = Math.min(100, Math.floor((rowsDone / total) * 100));
    this._progressBar.style.width = pct + '%';
    this._progressLbl.textContent = `Parsing… ${rowsDone.toLocaleString()} rows`;
  }
  endParseProgress() {
    this.state.parseComplete = true;
    this._progress.classList.add('hidden');
    this._updateInfoBar();
    // Row set is finalised now — re-run the column-kind sniffer on the
    // real data (the constructor's initial call saw an empty row set for
    // streaming parsers and produced default 'short' widths).
    this._recomputeColumnWidths();
    this._applyColumnTemplate();
    this._rebuildTimeline();
  }

  /**
   * Replace the grid's row data. When `opts.preSorted` is truthy, the
   * caller guarantees rows are already in the correct sort order — the
   * expensive `_sortByColumn` pass (O(n log n) with `Date.parse` for
   * temporal columns) is skipped entirely, saving seconds on 1M-row
   * datasets. The previous `_sortSpec` is preserved so column-header
   * sort indicators still render and subsequent user-initiated sorts
   * work as before. Timeline Mode uses this path because it pre-sorts
   * the `idx` permutation handed to `TimelineRowView` via the
   * already-parsed `_timeMs` Float64Array.
   */
  setRows(store, rowSearchText, rowOffsets, opts) {
    // The store argument MUST be RowStore-shaped — every caller in tree
    // hands either a `RowStore` or a thin adapter (TimelineRowView).
    // The legacy `string[][]` shape was retired in Phase 4c; reject it
    // here so a regression points at the call site immediately rather
    // than producing silently-mangled cells on first read.
    if (!store || typeof store.getCell !== 'function') {
      throw new TypeError(
        'GridViewer.setRows: argument must be RowStore-shaped (rowCount / getCell / getRow). ' +
        'Wrap legacy `string[][]` callers via `RowStore.fromStringMatrix(columns, rows)`.',
      );
    }
    this.store = store;
    // Drop the cache by default; renderers that want it (csv / sqlite /
    // evtx / xlsx / json with `searchTextCache: true`) repopulate via
    // the idle build below or lazily via `_rowMatchesQuery`. Without
    // this reset the idle-rebuild's `if (rowSearchText[i] != null)
    // continue` check would silently retain stale text from the prior
    // dataset and filter the wrong rows. See review notes #3 from the
    // 2026-04-27 audit.
    this.rowSearchText = this._searchTextCache
      ? (rowSearchText || null)
      : null;
    this.rowOffsets = rowOffsets || this.rowOffsets;
    // Schedule a background pre-build of `rowSearchText` so the first
    // filter keystroke doesn't pay the materialisation cost row-by-row.
    // Skipped when the caller already supplied a populated array (EVTX,
    // Timeline), in store mode (no cache needed), or when the dataset
    // is small enough that lazy caching is fast anyway.
    this._scheduleIdleSearchTextBuild();
    this._maybeRemoveEmptyPlaceholder();
    // Re-run column-kind sniffer now that we have real rows to sample.
    this._recomputeColumnWidths();
    this._applyColumnTemplate();

    // The previous rows array is gone — any cached permutation
    // (`_sortOrder`) or derived filter index (`state.filteredIndices`)
    // references the OLD dataset and would index past the new rows
    // length. Without this invalidation the Timeline's column-chip
    // filter path (which calls setRows with a smaller filtered slice)
    // would leave a stale `_sortOrder` pointing at higher indices than
    // the new rows array, and the grid would render empty even though
    // rows matched. Save any active sort spec so we can re-apply it on
    // the fresh rows instead of dropping it.
    const prevSort = this._sortSpec;
    this.state.filteredIndices = null;
    this._sortSpec = null;
    this._sortOrder = null;

    if (opts && opts.preSorted && prevSort) {
      // Caller pre-sorted — stamp an identity sort order and restore the
      // spec so header arrows render correctly. No re-parse needed.
      const n = this._rowCount();
      const idxs = new Array(n);
      for (let i = 0; i < n; i++) idxs[i] = i;
      this._sortSpec = prevSort;
      this._sortOrder = idxs;
      if (this._filterInput.value && this._filterInput.value.trim()) {
        this._applyFilter();
      } else {
        this._forceFullRender();
      }
    } else if (prevSort) {
      // Re-sort on the fresh rows — _sortByColumn also re-applies the
      // live filter-input query when it intersects with filteredIndices,
      // so this single call correctly handles sort+filter combos.
      this._sortByColumn(prevSort.colIdx, prevSort.dir);
      if (this._filterInput.value && this._filterInput.value.trim()) {
        // _sortByColumn intersects with the *existing* filteredIndices
        // (which we just nulled), so re-run _applyFilter and then the
        // sort permutation gets re-intersected in the same pass via
        // _applyFilter → _forceFullRender path. Simpler: call
        // _applyFilter which rebuilds filteredIndices from the query,
        // then re-sort on top.
        this._applyFilter();
        this._sortByColumn(prevSort.colIdx, prevSort.dir);
      }
    } else if (this._filterInput.value && this._filterInput.value.trim()) {
      this._applyFilter();
    } else {
      this._forceFullRender();
    }
    this._updateInfoBar();
    this._rebuildTimeline();
  }


  /**
   * Replace the column set on a live grid without tearing down the DOM.
   *
   * Used by Timeline Mode to apply auto-extracted / manually-extracted
   * columns in place, so the analyst sees columns appear next to the
   * already-mounted grid instead of the entire `<table>` blinking out
   * during a destroy + reconstruct cycle (the "auto-extract flash" that
   * `_rebuildExtractedStateAndRender` historically caused).
   *
   * Contract:
   *   • `newColumns` is the full new column array (base + extracted).
   *     The base prefix MUST match the existing prefix — this method
   *     only supports append / tail-truncate, never insert / reorder.
   *     That covers every in-tree caller (auto-extract, Extract dialog
   *     add, drawer right-click extract, and `removeExtractedCol`).
   *   • Per-column user state keyed by index (`_userColWidths`,
   *     `_hiddenCols`, `_sortSpec.colIdx`) is preserved across grow.
   *     On shrink, indices that fall off the tail are pruned (hidden
   *     set / user-width map) or cleared (sort spec).
   *   • The follow-up `_recomputeColumnWidths` resamples the new tail
   *     columns against real row data, so kind / width are correct
   *     immediately. No extra `setRows` call is required.
   *
   * Callers that want to swap rows AND columns in one go should call
   * `_updateColumns` first, then `setRows` — the row swap path also
   * runs `_recomputeColumnWidths` so the second pass is idempotent.
   */
  _updateColumns(newColumns) {
    if (!Array.isArray(newColumns)) return;
    const oldLen = this.columns.length;
    const newLen = newColumns.length;
    this.columns = newColumns.slice();

    // Prune per-index state on shrink. Auto-extract only ever appends,
    // but `removeExtractedCol` deletes from the tail of the extracted
    // segment, so the shrink path is exercised on manual delete.
    if (newLen < oldLen) {
      // Hidden columns at indices that no longer exist.
      if (this._hiddenCols && this._hiddenCols.size) {
        for (const i of Array.from(this._hiddenCols)) {
          if (i >= newLen) this._hiddenCols.delete(i);
        }
      }
      // User-resized widths beyond the new tail.
      if (this._userColWidths && this._userColWidths.size) {
        for (const i of Array.from(this._userColWidths.keys())) {
          if (i >= newLen) this._userColWidths.delete(i);
        }
      }
      // Active sort on a now-deleted column → drop it.
      if (this._sortSpec && this._sortSpec.colIdx >= newLen) {
        this._sortSpec = null;
        this._sortOrder = null;
      }
      // Display order: drop entries that fell off the tail. We don't
      // need to do anything when `_colOrder` is null (identity); the
      // resolver reads `columns.length` directly.
      if (Array.isArray(this._colOrder)) {
        this._colOrder = this._colOrder.filter(i => Number.isInteger(i) && i < newLen);
      }
    }
    // Grow: append new real-indices to `_colOrder` so newly-added
    // columns land at the END of the display order — matching the
    // legacy behaviour for callers that don't know about reorder.
    // Timeline's geo-enrichment path overrides this immediately
    // afterwards via `_setColumnOrder` to insert next to source.
    if (newLen > oldLen && Array.isArray(this._colOrder)) {
      const seen = new Set(this._colOrder);
      for (let i = oldLen; i < newLen; i++) {
        if (!seen.has(i)) this._colOrder.push(i);
      }
    }

    // Re-sample column kinds / widths against real rows so the new tail
    // columns get correct alignment + greedy treatment immediately.
    this._recomputeColumnWidths();
    this._buildHeaderCells();
    this._applyColumnTemplate();
    this._forceFullRender();
    // Drawer (if open) shows every column as a key/value row — refresh
    // it so newly added columns appear and removed ones disappear.
    if (this.state && this.state.drawer && this.state.drawer.open
      && typeof this._renderDrawerBody === 'function') {
      try { this._renderDrawerBody(this.state.drawer.dataIdx); } catch (_) { /* noop */ }
    }
    this._updateInfoBar();
  }


  /**
   * Drop the "Empty file." placeholder added in _buildDOM when the grid
   * was constructed with zero rows. Called whenever a setRows() call
   * swaps in a non-empty store (CSV streaming path constructs the grid
   * with `RowStore.empty(columns)` and finalises the real store on EOF).
   */
  _maybeRemoveEmptyPlaceholder() {
    if (this._emptyEl && this._rowCount()) {
      try { this._emptyEl.remove(); } catch (_) { /* ignore */ }
      this._emptyEl = null;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  BACK-COMPAT API (mounted on root as `_csvFilters` — keeps the existing
  //  sidebar click-to-focus engine in src/app/app-sidebar-focus.js working
  //  without any change on its side).
  // ═══════════════════════════════════════════════════════════════════════════
  _installBackCompatApi() {
    const self = this;

    // dataRows — lazy, linear-iteration-friendly. Sidebar scans for
    //   `for (const r of filters.dataRows) { if (r.searchText.includes(term)) ... }`
    // We materialise on demand; each element carries searchText + offsets.
    const dataRowsProxy = {
      get length() { return self._rowCount(); },
      [Symbol.iterator]: function* () {
        const n = self._rowCount();
        for (let i = 0; i < n; i++) yield self._dataRowShape(i);
      }
    };

    this._root._csvFilters = {
      // Core
      filterInput: this._filterInput,
      applyFilter: () => this._applyFilter(),
      clearFilter: () => { this._filterInput.value = ''; this._applyFilter(); },
      scrollContainer: this._scr,
      dataRows: dataRowsProxy,
      headerRow: this.columns,
      expandRow: (rowObj) => {
        const idx = rowObj && rowObj.dataIndex !== undefined ? rowObj.dataIndex : rowObj;
        this._openDrawer(+idx);
      },
      scrollToRow: (idx, flash = true) => this._scrollToRow(+idx, flash),
      scrollToFirstMatch: () => {
        if (this._visibleCount() > 0) this._scrollToRow(this._dataIdxOf(0));
      },
      forceRender: () => this._forceFullRender(),
      buildDetailPane: (td, row, dataIdx) => {
        const pane = this._buildDetailPaneElement(this.columns, row, dataIdx);
        td.appendChild(pane);
      },
      state: this.state,
      getVisibleRowCount: () => this._visibleCount(),
      getDataIndex: (v) => this._dataIdxOf(v),
      getVirtualIndex: (d) => this._virtualIdxOf(d),

      // IOC navigation — sets ioc highlight state + opens drawer + scrolls.
      scrollToRowWithIocHighlight: (dataIdx, term, clearMs = 5000, onExpire = null) => {
        self._setHighlight({ mode: 'ioc', dataIdx: +dataIdx, term, clearMs, onExpire });
        return self._scrollToRow(+dataIdx, false);
      },
      clearIocHighlight: () => self._clearHighlight(false),

      // YARA navigation — caller supplies full per-row match map up front.
      setYaraHighlight: (matchesByDataIdx, focusDataIdx, focusMatchIdx, sourceText, clearMs = 5000, onExpire = null) => {
        self._setHighlight({
          mode: 'yara',
          matchesByDataIdx, focusDataIdx: +focusDataIdx, focusMatchIdx,
          sourceText,
          dataIdx: +focusDataIdx,
          clearMs, onExpire
        });
      },
      clearYaraHighlight: () => self._clearHighlight(false),
      scrollToYaraFocus: () => {
        const h = self.state.highlight;
        if (!h || h.mode !== 'yara') return;
        // The focus mark lives in the drawer body (detail pane).
        const mk = self._drawerBody.querySelector(
          `mark.csv-yara-highlight[data-yara-match="${h.focusMatchIdx}"]`);
        if (mk) mk.scrollIntoView({ behavior: 'smooth', block: 'center' });
      },

      // Grid-specific hooks (used by the CsvRenderer wrapper for chunked parse).
      setMalformedRows: (set) => self.setMalformedRows(set),
      _viewer: self,
    };
  }

  _dataRowShape(dataIdx) {
    const row = this._rowAt(dataIdx) || [];
    let searchText;
    if (this.rowSearchText && this.rowSearchText[dataIdx] != null) {
      searchText = this.rowSearchText[dataIdx];
    } else {
      searchText = row.join(' ').toLowerCase();
      if (!this.rowSearchText) this.rowSearchText = new Array(this._rowCount());
      this.rowSearchText[dataIdx] = searchText;
    }
    const off = this.rowOffsets ? this.rowOffsets[dataIdx] : null;
    return {
      rowData: row,
      searchText,
      offsetStart: off ? off.start : 0,
      offsetEnd: off ? off.end : 0,
      dataIndex: dataIdx,
      tr: null, detailTr: null, detailTd: null, visible: true
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  WAVE-C — COLUMN MENU / SORT / HIDE / COPY / TOP-VALUES POPOVER
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Open the per-column header dropdown. Anchored below the header cell.
   * Items: Sort asc, Sort desc, Clear sort (if sorted), Copy column,
   * Hide column, Top values….
   */
  _openHeaderMenu(colIdx, anchorEl) {
    // Toggle: if the menu is already open for this exact column, close it.
    if (this._openPopover && this._openPopover.dataset.colIdx === String(colIdx)) {
      this._closePopover();
      return;
    }
    this._closePopover();
    const pop = document.createElement('div');
    pop.className = 'grid-popover grid-header-menu';
    pop.dataset.colIdx = colIdx;

    const mkItem = (label, onClick, opts) => {
      const item = document.createElement('button');
      item.type = 'button';
      item.className = 'grid-popover-item';
      item.textContent = label;
      if (opts && opts.danger) item.classList.add('grid-popover-danger');
      item.addEventListener('click', (e) => {
        e.stopPropagation();
        try { onClick(); } finally { this._closePopover(); }
      });
      return item;
    };

    const sorted = this._sortSpec && this._sortSpec.colIdx === colIdx;
    pop.appendChild(mkItem(sorted && this._sortSpec.dir === 'asc' ? '✓ Sort ascending' : 'Sort ascending',
      () => this._sortByColumn(colIdx, 'asc')));
    pop.appendChild(mkItem(sorted && this._sortSpec.dir === 'desc' ? '✓ Sort descending' : 'Sort descending',
      () => this._sortByColumn(colIdx, 'desc')));
    if (this._sortSpec) {
      pop.appendChild(mkItem('Clear sort', () => this._clearSort()));
    }
    pop.appendChild(this._popoverSeparator());
    // Opt-in promotion of any column to the timeline source.
    // Hidden for columns that look like bare numeric IDs so it doesn't
    // clutter menus on non-temporal data; still shown whenever at least
    // ~50% of sampled cells parse as a real timestamp.
    // In Timeline Mode the outer view's left-click column menu already
    // provides "Use as Timestamp" and "Stack chart by this" — suppress
    // the duplicates here so the right-click menu stays focused on
    // sort / hide / copy.
    if (!this._onUseAsTimeline && this._columnLooksTemporal(colIdx)) {
      const active = this._timeColumn === colIdx && this._timeMs;
      pop.appendChild(mkItem(
        active ? '✓ Use as timeline' : 'Use as timeline',
        () => this._useColumnAsTimeline(colIdx)
      ));
    }
    // Stack the timeline histogram by this column. Shown whenever
    // the timeline is active and the column has a reasonable number of
    // distinct values on the visible row set (≥2, ≤ STACK_MAX_GROUPS).
    if (!this._onStackTimelineBy && this._timeMs && this._columnLooksStackable(colIdx)) {
      const active = this._timeStackColumn === colIdx;
      pop.appendChild(mkItem(
        active ? '✓ Stack timeline by this column' : 'Stack timeline by this column',
        () => this._useColumnAsTimelineStack(colIdx)
      ));
    }
    pop.appendChild(mkItem('Copy column', () => this._copyColumn(colIdx)));
    pop.appendChild(this._popoverSeparator());
    pop.appendChild(mkItem('Hide column', () => this._toggleHideColumn(colIdx), { danger: true }));
    // Escape hatch — if any column is currently hidden, surface the same
    // popover that the "👁 N hidden" chip opens. Duplicates the chip's
    // entry-point so users who hide several columns in a row via the
    // header menu don't have to chase the chip to get them back.
    if (this._hiddenCols.size > 0) {
      // Built manually instead of via mkItem because mkItem's
      // `finally { _closePopover() }` would immediately destroy
      // the hidden-columns popover that _openHiddenColsPopover
      // just opened.
      const showHiddenBtn = document.createElement('button');
      showHiddenBtn.type = 'button';
      showHiddenBtn.className = 'grid-popover-item';
      showHiddenBtn.textContent = `Show hidden columns… (${this._hiddenCols.size})`;
      showHiddenBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this._openHiddenColsPopover(anchorEl);
      });
      pop.appendChild(showHiddenBtn);
    }


    this._positionPopover(pop, anchorEl);
    this._openPopover = pop;
  }

  _popoverSeparator() {
    const sep = document.createElement('div');
    sep.className = 'grid-popover-sep';
    return sep;
  }

  /**
   * Position `pop` below `anchorEl`, clamped to the viewport. Appended to
   * document.body so it escapes any overflow:hidden ancestor.
   */
  _positionPopover(pop, anchorEl) {
    document.body.appendChild(pop);
    const rect = anchorEl.getBoundingClientRect();
    // Render off-screen first to measure.
    pop.style.visibility = 'hidden';
    pop.style.left = '0px';
    pop.style.top = '0px';
    const popW = pop.offsetWidth || 220;
    const popH = pop.offsetHeight || 200;
    const vw = window.innerWidth || document.documentElement.clientWidth;
    const vh = window.innerHeight || document.documentElement.clientHeight;
    let left = rect.left;
    let top = rect.bottom + 2;
    if (left + popW > vw - 8) left = Math.max(8, vw - popW - 8);
    if (top + popH > vh - 8) top = Math.max(8, rect.top - popH - 2);
    pop.style.left = left + 'px';
    pop.style.top = top + 'px';
    pop.style.visibility = '';
  }

  _closePopover() {
    if (!this._openPopover) return;
    try { this._openPopover.remove(); } catch (_) { /* ignore */ }
    this._openPopover = null;
  }

  /**
   * Right-click context menu for plain-text drawer fields. Mirrors the
   * JSON-leaf menu that `src/json-tree.js` opens for tree keys — except
   * "Extract column" is omitted (the source column already exists) and
   * the `onCellPick` callback is invoked with an empty `path` array as
   * a sentinel meaning "this is a direct column filter, not a
   * JSON-extract request". Positioned at the cursor and dismissed on
   * outside click / Esc / scroll / resize.
   */
  _openDrawerCellMenu(ev, dataIdx, colIdx, leafValue) {
    this._closePopover();
    if (!this._onCellPick) return;

    const pop = document.createElement('div');
    pop.className = 'grid-popover grid-header-menu';
    pop.setAttribute('role', 'menu');
    pop.style.position = 'fixed';

    const mkItem = (label, action) => {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'grid-popover-item';
      b.textContent = label;
      b.addEventListener('click', (e) => {
        e.stopPropagation();
        this._closePopover();
        try { this._onCellPick(dataIdx, colIdx, [], leafValue, action); }
        catch (err) { try { console.error('onCellPick threw', err); } catch (_) { /* ignore */ } }
      });
      pop.appendChild(b);
    };
    mkItem('✓ Include value', 'include');
    mkItem('✕ Exclude value', 'exclude');

    // Position at the cursor, then nudge into the viewport after measuring
    // — same contract as `JsonTree._openKeyMenu`.
    document.body.appendChild(pop);
    pop.style.left = (ev.clientX || 0) + 'px';
    pop.style.top = (ev.clientY || 0) + 'px';
    const rect = pop.getBoundingClientRect();
    const vw = window.innerWidth || document.documentElement.clientWidth;
    const vh = window.innerHeight || document.documentElement.clientHeight;
    if (rect.right > vw) pop.style.left = Math.max(0, vw - rect.width - 4) + 'px';
    if (rect.bottom > vh) pop.style.top = Math.max(0, vh - rect.height - 4) + 'px';

    this._openPopover = pop;
  }


  /**
   * Top-values popover — tallies frequency of each value in `colIdx`
   * across the current filtered/sorted set, shows top 50 as a mini bar
   * chart. Clicking a row sets the filter input to that value.
   */
  _openTopValuesPopover(colIdx, anchorEl) {
    this._closePopover();
    const pop = document.createElement('div');
    pop.className = 'grid-popover grid-top-values';

    const header = document.createElement('div');
    header.className = 'grid-top-values-header';
    const colName = this.columns[colIdx] || `Column ${colIdx + 1}`;
    header.textContent = `Top values · ${colName}`;
    pop.appendChild(header);

    // Tally from the currently-visible row set so top-values respects filter+sort.
    const counts = new Map();
    const total = this._visibleCount();
    const scanCap = Math.min(total, 200000); // absurd upper bound for a single column scan
    for (let v = 0; v < scanCap; v++) {
      const dIdx = this._dataIdxOf(v);
      if (dIdx == null) continue;
      const row = this._rowAt(dIdx);
      if (!row) continue;
      let val = row[colIdx];
      if (val == null) val = '';
      const key = String(val);
      counts.set(key, (counts.get(key) || 0) + 1);
    }

    const entries = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const TOP_N = 50;
    const shown = entries.slice(0, TOP_N);

    if (!shown.length) {
      const empty = document.createElement('div');
      empty.className = 'grid-top-values-empty';
      empty.textContent = 'No values to tally.';
      pop.appendChild(empty);
    } else {
      const max = shown[0][1] || 1;
      const list = document.createElement('div');
      list.className = 'grid-top-values-list';
      for (const [key, count] of shown) {
        const row = document.createElement('button');
        row.type = 'button';
        row.className = 'grid-top-values-row';
        row.title = key ? `Filter to "${key}"` : 'Filter to empty cells';
        const pct = Math.max(2, Math.round((count / max) * 100));

        const bar = document.createElement('span');
        bar.className = 'grid-top-values-bar';
        bar.style.width = pct + '%';
        row.appendChild(bar);

        const label = document.createElement('span');
        label.className = 'grid-top-values-label';
        label.textContent = key === '' ? '(empty)' : (key.length > 120 ? key.substring(0, 120) + '…' : key);
        row.appendChild(label);

        const cnt = document.createElement('span');
        cnt.className = 'grid-top-values-count';
        cnt.textContent = count.toLocaleString();
        row.appendChild(cnt);

        row.addEventListener('click', (e) => {
          e.stopPropagation();
          if (key !== '') {
            this._filterInput.value = key;
            this._applyFilter();
          }
          this._closePopover();
        });
        list.appendChild(row);
      }
      pop.appendChild(list);
    }

    if (entries.length > TOP_N) {
      const more = document.createElement('div');
      more.className = 'grid-top-values-footer';
      more.textContent = `… and ${(entries.length - TOP_N).toLocaleString()} more distinct values`;
      pop.appendChild(more);
    } else {
      const foot = document.createElement('div');
      foot.className = 'grid-top-values-footer';
      foot.textContent = `${entries.length.toLocaleString()} distinct value${entries.length === 1 ? '' : 's'}`;
      pop.appendChild(foot);
    }

    this._positionPopover(pop, anchorEl);
    this._openPopover = pop;
  }

  /**
   * Sort by `colIdx`. Builds a permutation over the full dataset, then
   * intersects with the active filter. Stable.
   */
  _sortByColumn(colIdx, dir) {
    const n = this._rowCount();
    const idxs = new Array(n);
    for (let i = 0; i < n; i++) idxs[i] = i;

    const mul = dir === 'desc' ? -1 : 1;

    const getCell = (i) => {
      const r = this._rowAt(i);
      return r ? (r[colIdx] == null ? '' : r[colIdx]) : '';
    };

    // ── Decorate-sort-undecorate ──────────────────────────────────────
    // Pre-extract sort keys once O(n), then compare pre-computed keys in
    // the sort comparator. This eliminates repeated per-comparison parsing
    // (Date.parse / parseFloat / toLowerCase are each called O(n log n)
    // times in the naïve approach — for 1M rows that's ~20M calls).
    // With pre-extraction each value is parsed exactly once: O(n).

    // Temporal probe FIRST — if the column parses as timestamps, sort by
    // ms-since-epoch. Without this branch the subsequent numeric-sniff
    // matches ISO strings like "2024-05-20T08:10:01Z" (parseFloat → 2024),
    // collapses every row to the same value, and leaves the apparent order
    // unchanged. Reuses the timeline parser so custom _timeParser callers
    // (EVTX's Excel-serial math, XLSX) sort identically to the timeline strip.
    const temporal = this._columnLooksTemporal(colIdx);
    if (temporal) {
      // Pre-compute all timestamp keys in one O(n) pass.
      const keys = new Float64Array(n);
      for (let i = 0; i < n; i++) keys[i] = this._parseTimeCell(getCell(i), i);
      idxs.sort((a, b) => {
        const av = keys[a], bv = keys[b];
        const aFin = Number.isFinite(av);
        const bFin = Number.isFinite(bv);
        if (!aFin && !bFin) return a - b;
        if (!aFin) return 1;          // unparseable sorts last
        if (!bFin) return -1;
        return (av - bv) * mul || (a - b);
      });
    }

    // Detect numeric column by sampling — if ≥90% of non-empty cells parse
    // as finite numbers, sort numerically; else lexical (case-insensitive).
    let numCount = 0, nonEmpty = 0;
    const sampleN = Math.min(n, 200);
    for (let i = 0; i < sampleN; i++) {
      const v = this._cellAt(i, colIdx);
      if (v === '') continue;
      nonEmpty++;
      const f = parseFloat(v);
      if (Number.isFinite(f) && /^-?\s*\d/.test(v.trim())) numCount++;
    }
    const numeric = !temporal && nonEmpty > 0 && numCount / nonEmpty >= 0.9;

    if (temporal) {
      // already sorted above
    } else if (numeric) {
      // Pre-compute numeric keys in one O(n) pass.
      const keys = new Float64Array(n);
      for (let i = 0; i < n; i++) {
        const v = getCell(i);
        const f = parseFloat(v);
        keys[i] = (Number.isFinite(f) && (v !== '' || false)) ? f : NaN;
      }
      idxs.sort((a, b) => {
        const av = keys[a], bv = keys[b];
        const aFin = Number.isFinite(av);
        const bFin = Number.isFinite(bv);
        if (!aFin && !bFin) return (a - b); // stable
        if (!aFin) return 1;
        if (!bFin) return -1;
        return (av - bv) * mul || (a - b);
      });
    } else {
      // Pre-compute lowercased string keys in one O(n) pass.
      const keys = new Array(n);
      for (let i = 0; i < n; i++) keys[i] = String(getCell(i)).toLowerCase();
      idxs.sort((a, b) => {
        const av = keys[a], bv = keys[b];
        if (av < bv) return -1 * mul;
        if (av > bv) return 1 * mul;
        return a - b;
      });
    }

    // Intersect with active filter, preserving sort order.
    const prevFilter = this.state.filteredIndices;
    if (prevFilter) {
      const allowed = new Set(prevFilter);
      const out = [];
      for (let i = 0; i < idxs.length; i++) if (allowed.has(idxs[i])) out.push(idxs[i]);
      this.state.filteredIndices = out;
    } else {
      this.state.filteredIndices = idxs;
    }

    this._sortSpec = { colIdx, dir };
    this._sortOrder = idxs;
    this._buildHeaderCells();
    this._scr.scrollTop = 0;
    this._forceFullRender();
  }

  _clearSort() {
    if (!this._sortSpec) return;
    this._sortSpec = null;
    this._sortOrder = null;
    // Re-apply filter to restore natural order (no-op if no filter).
    const q = this._filterInput.value;
    if (q && q.trim()) {
      this._applyFilter();
    } else {
      this.state.filteredIndices = null;
    }
    this._buildHeaderCells();
    this._forceFullRender();
  }

  _toggleHideColumn(colIdx) {
    if (this._hiddenCols.has(colIdx)) this._hiddenCols.delete(colIdx);
    else this._hiddenCols.add(colIdx);
    // If every column is hidden, un-hide the one the user just hid so they
    // don't end up with an empty grid they can't recover from.
    if (this._hiddenCols.size >= this.columns.length) {
      this._hiddenCols.delete(colIdx);
      return;
    }
    this._buildHeaderCells();
    this._applyColumnTemplate();
    this._forceFullRender();
    this._updateHiddenChipUI();
    // If the drawer is open the pane shows every column as a key/value
    // row — refresh it so hidden columns disappear from the drawer too.
    if (this.state.drawer.open) this._renderDrawerBody(this.state.drawer.dataIdx);
  }

  /** Unhide a single previously-hidden column. No-op if it wasn't hidden. */
  _unhideColumn(colIdx) {
    if (!this._hiddenCols.has(colIdx)) return;
    this._hiddenCols.delete(colIdx);
    this._buildHeaderCells();
    this._applyColumnTemplate();
    this._forceFullRender();
    this._updateHiddenChipUI();
    if (this.state.drawer.open) this._renderDrawerBody(this.state.drawer.dataIdx);
  }

  /** Unhide every hidden column — wired to the "Show all" chip button
   *  and also called from Timeline Mode's Reset so users can recover
   *  from a column-hiding spree without reloading the file. */
  _unhideAllColumns() {
    if (!this._hiddenCols.size) return;
    this._hiddenCols.clear();
    this._buildHeaderCells();
    this._applyColumnTemplate();
    this._forceFullRender();
    this._updateHiddenChipUI();
    if (this.state.drawer.open) this._renderDrawerBody(this.state.drawer.dataIdx);
  }

  /** Sync the "👁 N hidden" chip with `_hiddenCols.size`. Safe to call
   *  before the chip DOM has been mounted (no-op). */
  _updateHiddenChipUI() {
    if (!this._hiddenChip) return;
    const n = this._hiddenCols.size;
    if (!n) {
      this._hiddenChip.style.display = 'none';
      return;
    }
    this._hiddenChip.style.display = '';
    if (this._hiddenCountLabel) this._hiddenCountLabel.textContent = n.toLocaleString();
  }

  /** Popover listing every hidden column, one button per column. Clicking
   *  a row unhides just that column. Positioned by the shared popover
   *  helper so it auto-flips when it'd overflow the viewport. */
  _openHiddenColsPopover(anchorEl) {
    this._closePopover();
    const pop = document.createElement('div');
    pop.className = 'grid-popover grid-hidden-popover';

    const header = document.createElement('div');
    header.className = 'grid-hidden-popover-header';
    header.textContent = `Hidden columns · ${this._hiddenCols.size}`;
    pop.appendChild(header);

    const list = document.createElement('div');
    list.className = 'grid-hidden-popover-list';
    const sorted = [...this._hiddenCols].sort((a, b) => a - b);
    for (const ci of sorted) {
      const name = this.columns[ci] || `Column ${ci + 1}`;
      const item = document.createElement('button');
      item.type = 'button';
      item.className = 'grid-popover-item grid-hidden-popover-item';
      item.title = 'Click to unhide this column';
      item.textContent = '👁 ' + name;
      item.addEventListener('click', (e) => {
        e.stopPropagation();
        this._unhideColumn(ci);
        this._closePopover();
        // Re-open so users can unhide several in a row without chasing
        // the chip again; close if they've now unhidden everything.
        if (this._hiddenCols.size) {
          this._openHiddenColsPopover(this._hiddenChipLabelBtn);
        }
      });
      list.appendChild(item);
    }
    pop.appendChild(list);

    if (this._hiddenCols.size > 1) {
      pop.appendChild(this._popoverSeparator());
      const allBtn = document.createElement('button');
      allBtn.type = 'button';
      allBtn.className = 'grid-popover-item grid-hidden-popover-all';
      allBtn.textContent = 'Show all columns';
      allBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this._unhideAllColumns();
        this._closePopover();
      });
      pop.appendChild(allBtn);
    }

    this._positionPopover(pop, anchorEl);
    this._openPopover = pop;
  }

  _copyColumn(colIdx) {
    const n = this._visibleCount();
    const parts = new Array(n);
    for (let v = 0; v < n; v++) {
      const d = this._dataIdxOf(v);
      parts[v] = this._cellAt(d, colIdx);
    }
    const text = parts.join('\n');
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(() => this._fallbackCopy(text));
      } else {
        this._fallbackCopy(text);
      }
    } catch (_) {
      this._fallbackCopy(text);
    }
  }

  _fallbackCopy(text) {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    } catch (_) { /* ignore */ }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  WAVE-C — MALFORMED-ROW RIBBON
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Public API for parsers (CSV, NDJSON) to flag rows with structural
   * problems — wrong cell count, unbalanced quotes, failed inner parse.
   * Accepts any iterable of dataIdx numbers.
   */
  setMalformedRows(set) {
    if (!set) {
      this._malformedRows = null;
    } else if (set instanceof Set) {
      this._malformedRows = set;
    } else {
      this._malformedRows = new Set(set);
    }
    this._malformedCursor = -1;
    this._updateMalformedUI();
    this._forceFullRender();
  }

  _updateMalformedUI() {
    if (!this._malformedChip) return;
    const n = this._malformedRows ? this._malformedRows.size : 0;
    if (!n) {
      this._malformedChip.style.display = 'none';
      return;
    }
    this._malformedChip.style.display = '';
    if (this._malformedLabel) this._malformedLabel.textContent = n.toLocaleString();
  }

  _jumpToNextMalformed() {
    if (!this._malformedRows || !this._malformedRows.size) return;
    const sorted = [...this._malformedRows].sort((a, b) => a - b);
    let next = sorted.find(i => i > this._malformedCursor);
    if (next === undefined) next = sorted[0];
    this._malformedCursor = next;
    this._scrollToRow(next, true);
  }

  _toggleMalformedFilter() {
    if (!this._malformedRows || !this._malformedRows.size) return;
    const active = this._malformedFilterBtn.classList.toggle('active');
    if (active) {
      // Show only malformed rows.
      const arr = [...this._malformedRows].sort((a, b) => a - b);
      this.state.filteredIndices = arr;
      this._clearBtn.style.display = '';
      this._filterStatus.textContent =
        `${arr.length.toLocaleString()} malformed of ${this._rowCount().toLocaleString()} rows`;
    } else {
      // Restore current filter-input state.
      this._applyFilter();
    }
    this._scr.scrollTop = 0;
    this._forceFullRender();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  WAVE-E — TIMELINE PRIMITIVE (density histogram + drag-select window)
  //
  //  Design:
  //    • Parse the time column once into this._timeMs — an Array of
  //      ms-since-epoch, NaN for unparseable cells. The per-dataIdx layout
  //      means window-filter lookups are O(1) with no per-row allocation.
  //    • Aggregate into a fixed-count bucket histogram for paint (cheap —
  //      one Int32Array, no DOM per row).
  //    • Drag-select on the track picks [min,max]; click-a-bucket picks
  //      that bucket's ms range; Esc / ✕ clears.
  //    • _applyFilter() already intersects text filter + _timeWindow, so
  //      downstream callers (text input, header filter UI) get composition
  //      for free. External-filter renderers (EVTX) can pass a custom
  //      onFilterRecompute callback so their own search/EID/Level filters
  //      compose with the timeline.
  // ═══════════════════════════════════════════════════════════════════════════

  /** Parse one cell into ms-since-epoch. Uses the caller-supplied parser
   *  if any; otherwise Date.parse() (which handles ISO 8601, RFC 2822,
   *  and most sensible string forms). Returns NaN for empty / unparseable. */
  _parseTimeCell(cell, dataIdx) {
    if (cell == null || cell === '') return NaN;
    if (this._timeParser) {
      try {
        const v = this._timeParser(cell, dataIdx);
        return (typeof v === 'number' && Number.isFinite(v)) ? v : NaN;
      } catch (_) { return NaN; }
    }
    // Fast default — strip a trailing ' UTC' / 'Z' variance, try Date.parse.
    const s = String(cell).trim();
    if (!s) return NaN;
    const t = Date.parse(s);
    return Number.isFinite(t) ? t : NaN;
  }

  /** Sample a column to decide whether the "Use as timeline" menu item
   *  should appear. Requires ≥50% of non-empty sampled cells to parse as
   *  timestamps with at least 2 distinct values, and rejects bare numeric
   *  IDs (integers without any date separators). */
  _columnLooksTemporal(colIdx) {
    const n = this._rowCount();
    if (!n) return false;
    const SAMPLE = Math.min(n, 40);
    const step = Math.max(1, Math.floor(n / SAMPLE));
    let nonEmpty = 0, parsed = 0, idLike = 0;
    const seen = new Set();
    for (let i = 0; i < n && seen.size < 20; i += step) {
      const r = this._rowAt(i);
      if (!r) continue;
      const cell = r[colIdx];
      if (cell == null || cell === '') continue;
      nonEmpty++;
      const s = String(cell).trim();
      if (/^-?\d+$/.test(s) && s.length < 10) idLike++;
      const t = this._parseTimeCell(cell, i);
      if (Number.isFinite(t)) { parsed++; seen.add(t); }
    }
    if (nonEmpty < 3) return false;
    if (idLike / nonEmpty > 0.8) return false;
    return (parsed / nonEmpty) >= 0.5 && seen.size >= 2;
  }

  /** Pick a timeline column: user-forced wins; otherwise scan for the
   *  first column that passes _columnLooksTemporal. */
  _sniffTimeColumn() {
    if (!this._timeColumnIsAuto) return this._timeColumn;
    for (let c = 0; c < this.columns.length; c++) {
      if (this._columnLooksTemporal(c)) return c;
    }
    return null;
  }

  /** Parse every row's time cell into _timeMs, compute _timeRange, and
   *  aggregate into _timeBuckets. Called from endParseProgress() / setRows()
   *  / the initial constructor path. */
  _rebuildTimeline() {
    if (!this._timelineEl) return;
    const col = this._timeColumnIsAuto ? this._sniffTimeColumn() : this._timeColumn;
    if (col == null || col < 0 || col >= this.columns.length) {
      this._hideTimeline();
      return;
    }
    this._timeColumn = col;

    const n = this._rowCount();
    if (!n) { this._hideTimeline(); return; }

    const ms = new Array(n);
    let min = Infinity, max = -Infinity, parsed = 0;
    for (let i = 0; i < n; i++) {
      const r = this._rowAt(i);
      const t = r ? this._parseTimeCell(r[col], i) : NaN;
      ms[i] = t;
      if (Number.isFinite(t)) {
        parsed++;
        if (t < min) min = t;
        if (t > max) max = t;
      }
    }
    // Bail if ≤1 parseable cell or zero span — a histogram with one bar
    // is pure UI noise.
    if (parsed < 2 || !Number.isFinite(min) || !Number.isFinite(max) || max <= min) {
      this._hideTimeline();
      this._timeMs = ms;
      return;
    }

    this._timeMs = ms;
    this._timeDataRange = { min, max };
    // Preserve an existing zoom if the user has a window active and it
    // still lies inside the new data range; otherwise fall back to the
    // full data range.
    if (this._timeWindow &&
      this._timeWindow.min >= min && this._timeWindow.max <= max) {
      this._timeRange = { min: this._timeWindow.min, max: this._timeWindow.max };
    } else {
      this._timeRange = { min, max };
    }

    this._rebuildBucketsForView();

    this._paintTimeline();
    this._timelineEl.classList.remove('hidden');

    // If a window is active but out of range (e.g. after setRows), clear it.
    if (this._timeWindow &&
      (this._timeWindow.max < min || this._timeWindow.min > max)) {
      this._timeWindow = null;
      this._timeRange = { min, max };
      this._rebuildBucketsForView();
      this._paintTimeline();
      this._timelineWindowEl.classList.add('hidden');
      this._timelineClearBtn.classList.add('hidden');
    }
    this._paintTimelineWindow();
    this._updateTimelineCursor();
  }

  /** Bucket construction against the current `_timeRange` (i.e. the zoomed
   *  view, which equals `_timeDataRange` when no window is active). Splits
   *  out so `_setTimeWindow` / `_clearTimeWindow` can rebuild without
   *  having to reparse every time cell.
   *
   *  Honours two state modes:
   *    1. `state.filteredIndices` (text filter / EID / Level) — if non-null,
   *       buckets only count rows that pass the filter. Exception: rows
   *       excluded *solely* by the active `_timeWindow` are included too,
   *       otherwise the window itself would trivially zero out every bar
   *       outside the selection and obscure dataset density.
   *    2. `_timeStackColumn` — when set, each bucket is an Int32Array of
   *       per-group counts (indexed by the position in `_timeStackKeys`);
   *       otherwise the legacy flat Int32Array is used. Paint dispatches
   *       on `_timeStackBuckets ? stacked-path : flat-path`. */
  // Invariant: this method does NOT re-walk `state.filteredIndices` — it
  // reads the same array `_applyFilter` produced and walks each index
  // once. The filter cost is therefore paid once per filter change; bucket
  // rebuilds on zoom / window adjust are O(rows-in-view) only.
  _rebuildBucketsForView() {
    if (!this._timeMs || !this._timeRange) {
      this._timeBuckets = null;
      this._timeStackBuckets = null;
      return;
    }
    const { min, max } = this._timeRange;
    const span = max - min;
    const B = this._timeBucketCount;
    if (span <= 0) {
      this._timeBuckets = new Int32Array(B);
      this._timeStackBuckets = null;
      return;
    }

    // Decide whether stacking is active. If the configured stack column is
    // out of range or produced no keys, fall back to flat counts.
    const stackCol = this._timeStackColumn;
    const stacking = Number.isInteger(stackCol) && stackCol >= 0 && stackCol < this.columns.length;
    if (stacking) this._ensureStackKeys();
    const keys = stacking ? this._timeStackKeys : null;
    const K = keys ? keys.length : 0;
    const doStack = stacking && K > 0;

    // Pick the iteration source — filtered rows (subject to the timeline-
    // window exception above) when a filter is active, otherwise everyone.
    const ms = this._timeMs;
    const tw = this._timeWindow;
    const filtered = this.state.filteredIndices;
    const rowIterator = this._makeBucketRowIterator(filtered, tw);

    const flat = doStack ? null : new Int32Array(B);
    const stack = doStack ? new Array(B) : null;
    if (doStack) {
      for (let i = 0; i < B; i++) stack[i] = new Int32Array(K);
    }

    let dataIdx;
    while ((dataIdx = rowIterator()) !== -1) {
      const t = ms[dataIdx];
      if (!Number.isFinite(t)) continue;
      if (t < min || t > max) continue;
      let b = Math.floor(((t - min) / span) * B);
      if (b >= B) b = B - 1;
      if (b < 0) b = 0;
      if (doStack) {
        const row = this._rowAt(dataIdx);
        const rawVal = row ? row[stackCol] : '';
        const k = this._stackKeyForValue(rawVal);
        stack[b][k]++;
      } else {
        flat[b]++;
      }
    }
    if (doStack) {
      this._timeStackBuckets = stack;
      // Mirror total counts into the flat array so hover-tooltip /
      // cursor logic that reads `_timeBuckets` still works without a
      // branching code path.
      const totals = new Int32Array(B);
      for (let i = 0; i < B; i++) {
        const s = stack[i];
        let sum = 0;
        for (let k = 0; k < K; k++) sum += s[k];
        totals[i] = sum;
      }
      this._timeBuckets = totals;
    } else {
      this._timeBuckets = flat;
      this._timeStackBuckets = null;
    }
  }

  /** Iterator factory — returns a closure that yields successive dataIdx
   *  values according to the rules in `_rebuildBucketsForView`. Folding
   *  the two branches (filtered-only vs. filtered-plus-timeline-window-
   *  excluded) into a single closure keeps the hot bucket loop tight. */
  _makeBucketRowIterator(filteredIndices, tw) {
    if (!filteredIndices) {
      let i = 0;
      const n = this._rowCount();
      return () => (i < n ? i++ : -1);
    }
    if (!tw) {
      let v = 0;
      const arr = filteredIndices;
      return () => (v < arr.length ? arr[v++] : -1);
    }
    // Filtered + a timeline window is active. The filter itself already
    // dropped rows outside the window; re-include them here so the bars
    // outside the window still show the *pre-window* density silhouette.
    // We walk the union: filteredIndices ∪ rows that pass all non-timeline
    // filters. Since we can't cheaply recover the latter here, approximate
    // by walking the full row set but only counting rows that either (a)
    // are in the filtered-indices Set, or (b) are outside the window.
    const set = new Set(filteredIndices);
    const ms = this._timeMs;
    let i = 0;
    const n = this._rowCount();
    return () => {
      while (i < n) {
        const d = i++;
        if (set.has(d)) return d;
        const t = ms[d];
        if (!Number.isFinite(t)) continue;
        if (t < tw.min || t > tw.max) return d;
      }
      return -1;
    };
  }

  /** Rebuild + repaint the histogram without touching the parsed times.
   *  Cheap — avoids the full reparse that `_rebuildTimeline` does. Called
   *  whenever a filter change might have changed the per-bucket counts. */
  _refreshTimelineBuckets() {
    if (!this._timeMs || !this._timeRange) return;
    // Rebuild the stack legend against the *visible* row set so the top-N
    // groups track whatever the user's current filter has narrowed to.
    if (Number.isInteger(this._timeStackColumn)) {
      this._timeStackKeys = null;  // force regenerate
    }
    this._rebuildBucketsForView();
    this._paintTimeline();
  }

  /** Distinct-value test for the "Stack timeline by this column" menu
   *  item. Returns true when the column has ≥2 distinct non-empty values
   *  on the visible row set and ≤ STACK_MAX_DISTINCT overall — i.e. a
   *  manageable categorical dimension. */
  _columnLooksStackable(colIdx) {
    if (!Number.isInteger(colIdx) || colIdx < 0 || colIdx >= this.columns.length) return false;
    const SAMPLE = 1000;
    const total = this._visibleCount();
    if (!total) return false;
    const n = Math.min(total, SAMPLE);
    const seen = new Set();
    for (let v = 0; v < n; v++) {
      const d = this._dataIdxOf(v);
      if (d == null) continue;
      const row = this._rowAt(d);
      if (!row) continue;
      const val = row[colIdx];
      if (val == null || val === '') continue;
      seen.add(String(val));
      if (seen.size > this.STACK_MAX_DISTINCT) return false;
    }
    return seen.size >= 2;
  }

  /** Build `_timeStackKeys` — the legend-ordered list of category values
   *  for the current stack column. Top (STACK_MAX_KEYS - 1) distinct
   *  values by visible-row-set frequency get their own palette slot; the
   *  tail collapses into a single "Other" slot. Recomputed on every
   *  filter change so the legend tracks what the user is looking at. */
  _ensureStackKeys() {
    if (this._timeStackKeys) return;
    const col = this._timeStackColumn;
    if (!Number.isInteger(col) || col < 0 || col >= this.columns.length) {
      this._timeStackKeys = [];
      this._timeStackOtherIdx = -1;
      return;
    }
    const counts = new Map();
    const filtered = this.state.filteredIndices;
    const tw = this._timeWindow;
    const iter = this._makeBucketRowIterator(filtered, tw);
    let d;
    while ((d = iter()) !== -1) {
      const row = this._rowAt(d);
      if (!row) continue;
      let v = row[col];
      if (v == null) v = '';
      const key = String(v);
      counts.set(key, (counts.get(key) || 0) + 1);
    }
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const maxPrimary = this.STACK_MAX_KEYS - 1;  // reserve one slot for "Other"
    const primary = sorted.slice(0, maxPrimary).map(([k]) => k);
    if (sorted.length > maxPrimary) {
      primary.push('Other');
      this._timeStackOtherIdx = primary.length - 1;
    } else {
      this._timeStackOtherIdx = -1;
    }
    this._timeStackKeys = primary;
    // Index for O(1) lookup in the hot bucket loop.
    this._timeStackKeyIdx = new Map();
    for (let i = 0; i < primary.length; i++) {
      if (i === this._timeStackOtherIdx) continue;
      this._timeStackKeyIdx.set(primary[i], i);
    }
  }

  /** Map a raw cell value to its palette-slot index. Falls back to the
   *  "Other" slot when the value didn't make the top-N legend. Safe to
   *  call when legend generation yielded zero keys (returns 0 — paint
   *  code checks key-count before rendering anyway). */
  _stackKeyForValue(rawVal) {
    if (!this._timeStackKeyIdx) return 0;
    const key = rawVal == null ? '' : String(rawVal);
    const idx = this._timeStackKeyIdx.get(key);
    if (idx !== undefined) return idx;
    return this._timeStackOtherIdx >= 0 ? this._timeStackOtherIdx : 0;
  }


  _hideTimeline() {
    this._timeMs = null;
    this._timeDataRange = null;
    this._timeRange = null;
    this._timeBuckets = null;
    this._timeStackBuckets = null;
    this._timeStackKeys = null;
    if (this._timelineCursorEl) this._timelineCursorEl.classList.add('hidden');
    if (this._timelineEl) this._timelineEl.classList.add('hidden');
  }

  /** Render the bucket bars + min/max date labels. When stacking is
   *  active (`_timeStackBuckets` populated), each bucket paints multiple
   *  coloured segments stacked bottom-up in palette-slot order — what
   *  the user asked for: a Windows-EID-style breakdown of "how many
   *  4624 vs 4688 vs 4672 occurred in each time slice". Segment colours
   *  come from `--grid-stack-color-<N>` CSS custom properties so theme
   *  overlays can re-skin the palette without touching JS. */
  _paintTimeline() {
    if (!this._timeBuckets || !this._timeRange) return;
    const totals = this._timeBuckets;
    let peak = 1;
    for (let i = 0; i < totals.length; i++) if (totals[i] > peak) peak = totals[i];
    const B = totals.length;
    const stack = this._timeStackBuckets;
    const keys = this._timeStackKeys;
    const frag = document.createDocumentFragment();

    if (stack && keys && keys.length) {
      // Stacked path — one <span> per non-zero (bucket × group).
      const K = keys.length;
      for (let i = 0; i < B; i++) {
        const total = totals[i];
        if (total === 0) continue;
        const barPct = Math.max(4, Math.round((total / peak) * 100));
        const left = (i / B) * 100;
        const width = (1 / B) * 100;
        let runningBottom = 0;
        const segBuckets = stack[i];
        for (let k = 0; k < K; k++) {
          const cnt = segBuckets[k];
          if (cnt === 0) continue;
          // Share of this segment within its bucket, scaled to the
          // bucket's bar height so a 100-row bucket and a 1-row bucket
          // don't paint equally-tall segments.
          const segFrac = cnt / total;
          const segH = segFrac * barPct;
          const seg = document.createElement('span');
          seg.className = 'grid-timeline-bar grid-timeline-bar-stack';
          seg.style.left = left + '%';
          seg.style.width = width + '%';
          seg.style.height = segH + '%';
          seg.style.bottom = runningBottom + '%';
          // Use a direct background so the palette works even on themes
          // that don't pre-declare `--grid-stack-color-N`; the CSS rule
          // layers a custom-property lookup on top for re-skinning.
          seg.style.setProperty('--grid-stack-slot', String(k));
          seg.dataset.bucket = i;
          seg.dataset.stackKey = k;
          seg.dataset.count = cnt;
          frag.appendChild(seg);
          runningBottom += segH;
        }
      }
    } else {
      // Flat path — legacy one-bar-per-bucket density.
      for (let i = 0; i < B; i++) {
        const bar = document.createElement('span');
        bar.className = 'grid-timeline-bar';
        const pct = totals[i] === 0 ? 0 : Math.max(4, Math.round((totals[i] / peak) * 100));
        bar.style.left = (i / B * 100) + '%';
        bar.style.width = (1 / B * 100) + '%';
        bar.style.height = pct + '%';
        bar.dataset.bucket = i;
        bar.dataset.count = totals[i];
        frag.appendChild(bar);
      }
    }
    this._timelineBucketsEl.replaceChildren(frag);

    this._timelineLabelLeft.replaceChildren(this._fmtEdgeLabel(this._timeRange.min));
    this._timelineLabelRight.replaceChildren(this._fmtEdgeLabel(this._timeRange.max));
    // Full-precision tooltip so analysts can hover for sub-second context
    // even though the visible label stops at whole seconds.
    const minIso = new Date(this._timeRange.min).toISOString().replace('T', ' ').slice(0, 19);
    const maxIso = new Date(this._timeRange.max).toISOString().replace('T', ' ').slice(0, 19);
    this._timelineLabelLeft.title = minIso + ' UTC';
    this._timelineLabelRight.title = maxIso + ' UTC';
  }


  /** Edge-label format — ALWAYS shows both date and time (YYYY-MM-DD over
   *  HH:MM:SS) regardless of span, so multi-day / multi-year timelines
   *  can never hide the date on the edge ticks and intraday timelines
   *  can never hide the date either. Returns a DocumentFragment with
   *  two child spans so CSS can stack them. Kept separate from
   *  _fmtTimeLabel so the hover tooltip + selected-window chip keep
   *  their compact span-adaptive form where strip real estate matters. */
  _fmtEdgeLabel(ms) {
    const frag = document.createDocumentFragment();
    if (!Number.isFinite(ms)) return frag;
    const iso = new Date(ms).toISOString();           // YYYY-MM-DDTHH:MM:SS.sssZ
    const d = document.createElement('span');
    d.className = 'grid-timeline-edge-date';
    d.textContent = iso.slice(0, 10);                 // YYYY-MM-DD
    const t = document.createElement('span');
    t.className = 'grid-timeline-edge-time';
    t.textContent = iso.slice(11, 19);                // HH:MM:SS
    frag.appendChild(d);
    frag.appendChild(t);
    return frag;
  }

  /** Compact date format — drops the year when the full range fits in
   *  the same year, drops seconds when the span is longer than ~2 hours.
   *  Used by the hover tooltip and the selected-window chip, where the
   *  two halves of a range share one narrow strip and stacking isn't
   *  an option. */
  _fmtTimeLabel(ms) {

    if (!Number.isFinite(ms)) return '';
    const d = new Date(ms);
    if (!this._timeRange) return d.toISOString().replace('T', ' ').slice(0, 19);
    const span = this._timeRange.max - this._timeRange.min;
    const DAY = 86400 * 1000;
    if (span <= 2 * DAY) {
      // Intraday → HH:MM:SS
      return d.toISOString().slice(11, 19);
    } else if (span <= 365 * DAY) {
      return (d.toISOString().slice(5, 10) + ' ' + d.toISOString().slice(11, 16));
    }
    return d.toISOString().slice(0, 10);
  }

  _fmtTimeDuration(ms) {
    if (!Number.isFinite(ms) || ms <= 0) return '';
    const s = Math.round(ms / 1000);
    if (s < 60) return `${s}s`;
    const m = Math.round(s / 60);
    if (m < 60) return `${m}m`;
    const h = Math.floor(m / 60);
    const mr = m % 60;
    if (h < 24) return mr ? `${h}h ${mr}m` : `${h}h`;
    const d = Math.floor(h / 24);
    const hr = h % 24;
    return hr ? `${d}d ${hr}h` : `${d}d`;
  }

  _paintTimelineWindow(opts) {
    const preview = !!(opts && opts.preview);
    if (!this._timelineWindowEl || !this._timeRange) return;
    if (!this._timeWindow) {
      this._timelineWindowEl.classList.add('hidden');
      this._timelineClearBtn.classList.add('hidden');
      if (this._timelineWindowLbl) {
        this._timelineWindowLbl.classList.add('hidden');
        this._timelineWindowLbl.classList.remove('grid-timeline-window-label--preview');
        this._timelineWindowLbl.textContent = '';
      }
      return;
    }
    const { min, max } = this._timeRange;
    const span = max - min || 1;
    const l = Math.max(0, (this._timeWindow.min - min) / span) * 100;
    const r = Math.min(1, (this._timeWindow.max - min) / span) * 100;
    this._timelineWindowEl.style.left = l + '%';
    this._timelineWindowEl.style.width = Math.max(0.5, r - l) + '%';
    this._timelineWindowEl.classList.remove('hidden');
    this._timelineClearBtn.classList.remove('hidden');
    const dur = this._fmtTimeDuration(this._timeWindow.max - this._timeWindow.min);
    const rangeStr =
      `${this._fmtTimeLabel(this._timeWindow.min)} → ${this._fmtTimeLabel(this._timeWindow.max)}`;
    const labelStr = dur ? `${rangeStr} · ${dur}` : rangeStr;
    this._timelineClearBtn.title = `${rangeStr} ([ ] to step, Esc to clear)`;
    if (this._timelineWindowLbl) {
      this._timelineWindowLbl.textContent = labelStr;
      this._timelineWindowLbl.title = preview
        ? `Previewing window · ${labelStr} · release to apply`
        : `Selected window · ${labelStr} · [ ] to step`;
      this._timelineWindowLbl.classList.remove('hidden');
      this._timelineWindowLbl.classList.toggle('grid-timeline-window-label--preview', preview);
    }
  }

  /** Wire mousedown on the bucket track for drag-select + click-bucket,
   *  plus mousemove for the floating tooltip. */
  _wireTimelineEvents() {
    const track = this._timelineTrackEl;
    const tip = this._timelineTooltipEl;
    if (!track) return;

    const pctFromX = (clientX) => {
      const rect = track.getBoundingClientRect();
      if (!rect.width) return 0;
      return Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
    };
    const msFromPct = (p) => {
      if (!this._timeRange) return NaN;
      return this._timeRange.min + p * (this._timeRange.max - this._timeRange.min);
    };

    track.addEventListener('mousemove', (e) => {
      if (!this._timeBuckets || !this._timeRange) return;
      const p = pctFromX(e.clientX);
      const b = Math.min(this._timeBuckets.length - 1, Math.floor(p * this._timeBuckets.length));
      const count = this._timeBuckets[b];
      const bStart = this._timeRange.min + (b / this._timeBuckets.length) * (this._timeRange.max - this._timeRange.min);
      const bEnd = this._timeRange.min + ((b + 1) / this._timeBuckets.length) * (this._timeRange.max - this._timeRange.min);
      tip.textContent = `${count.toLocaleString()} row${count === 1 ? '' : 's'} · ${this._fmtTimeLabel(bStart)} → ${this._fmtTimeLabel(bEnd)}`;
      const rect = track.getBoundingClientRect();
      const x = e.clientX - rect.left;
      // Flip the tooltip to the left of the cursor when it'd overflow the
      // track on the right.
      const tipW = tip.offsetWidth || 180;
      const leftPx = x + tipW + 12 > rect.width ? Math.max(4, x - tipW - 8) : x + 8;
      tip.style.left = leftPx + 'px';
      tip.classList.remove('hidden');
    });
    track.addEventListener('mouseleave', () => tip.classList.add('hidden'));

    // Drag-select + click. mousedown on the track starts a drag; a drag
    // of <3px is treated as a click-bucket selection.
    track.addEventListener('mousedown', (e) => {
      if (!this._timeBuckets || !this._timeRange || e.button !== 0) return;
      const startP = pctFromX(e.clientX);
      let lastP = startP;
      let didDrag = false;
      document.body.classList.add('grid-timeline-dragging');

      const onMove = (ev) => {
        lastP = pctFromX(ev.clientX);
        if (Math.abs(lastP - startP) * (track.getBoundingClientRect().width || 1) >= 3) {
          didDrag = true;
          const lo = Math.min(startP, lastP);
          const hi = Math.max(startP, lastP);
          // Preview the window as we drag.
          this._timeWindow = { min: msFromPct(lo), max: msFromPct(hi) };
          this._paintTimelineWindow({ preview: true });
        }
      };
      const onUp = () => {
        window.removeEventListener('mousemove', onMove);
        window.removeEventListener('mouseup', onUp);
        document.body.classList.remove('grid-timeline-dragging');
        if (!didDrag) {
          // Click-bucket → snap to that bucket's range.
          const B = this._timeBuckets.length;
          const span = this._timeRange.max - this._timeRange.min;
          const b = Math.min(B - 1, Math.floor(startP * B));
          const bStart = this._timeRange.min + (b / B) * span;
          const bEnd = this._timeRange.min + ((b + 1) / B) * span;
          this._setTimeWindow(bStart, bEnd);
        } else {
          // Commit the drag-selected window through _setTimeWindow so the
          // histogram zooms to the selection (and the temporary selection
          // rectangle painted by the preview is replaced by the zoomed
          // view where the strip *is* the window).
          const w = this._timeWindow;
          if (w) this._setTimeWindow(w.min, w.max);
          else this._applyTimelineFilter();
        }
      };
      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onUp);
      e.preventDefault();
    });
  }

  /** Commit a time window. Zooms the histogram strip to exactly the
   *  selected [min,max] so bucket resolution scales with the selection
   *  (what used to be one bar is now many), and the selection rectangle
   *  is hidden — when the view *is* the window the rectangle would span
   *  the full strip and add noise. Re-buckets against the new view
   *  range, repaints bars + edge labels, then triggers the filter
   *  recompute so the grid body narrows to the same range. */
  _setTimeWindow(min, max) {
    if (!Number.isFinite(min) || !Number.isFinite(max)) return;
    if (min > max) { const t = min; min = max; max = t; }
    // Clamp to the absolute data range so a zoomed-in step can't drift
    // into empty space outside the dataset.
    if (this._timeDataRange) {
      if (min < this._timeDataRange.min) min = this._timeDataRange.min;
      if (max > this._timeDataRange.max) max = this._timeDataRange.max;
    }
    this._timeWindow = { min, max };
    this._timeRange = { min, max };
    this._rebuildBucketsForView();
    this._paintTimeline();
    this._paintTimelineWindow();
    this._applyTimelineFilter();
    this._updateTimelineCursor();
  }

  /** ✕ Window / Esc — clear the selection AND restore the histogram to
   *  the full dataset range, so the user is back at the same view they
   *  started from. */
  _clearTimeWindow() {
    if (!this._timeWindow && (!this._timeDataRange ||
      (this._timeRange && this._timeRange.min === this._timeDataRange.min &&
        this._timeRange.max === this._timeDataRange.max))) {
      return;
    }
    this._timeWindow = null;
    if (this._timeDataRange) {
      this._timeRange = { min: this._timeDataRange.min, max: this._timeDataRange.max };
      this._rebuildBucketsForView();
      this._paintTimeline();
    }
    this._paintTimelineWindow();
    this._applyTimelineFilter();
    this._updateTimelineCursor();
  }

  /** [ / ] step the window by its own width earlier / later. Clamps
   *  against `_timeDataRange` (not `_timeRange`) because when the view
   *  is zoomed those two are equal — stepping against `_timeRange` would
   *  pin the window to its current position. */
  _stepTimeWindow(dir) {
    if (!this._timeWindow) return;
    const bounds = this._timeDataRange || this._timeRange;
    if (!bounds) return;
    const w = this._timeWindow.max - this._timeWindow.min;
    if (w <= 0) return;
    let nmin = this._timeWindow.min + dir * w;
    let nmax = this._timeWindow.max + dir * w;
    // Clamp to the absolute data range.
    if (nmin < bounds.min) {
      const shift = bounds.min - nmin;
      nmin += shift; nmax += shift;
    }
    if (nmax > bounds.max) {
      const shift = nmax - bounds.max;
      nmin -= shift; nmax -= shift;
    }
    this._setTimeWindow(nmin, nmax);
  }

  /** Red scrub indicator — paints a thin vertical line on the timeline
   *  strip at the time of the row the analyst is currently focused on,
   *  so they can see *where* in the timeline they're sitting without
   *  reading a date column.
   *
   *  Anchor priority (highest first):
   *    1. The row currently opened in the detail drawer — this is the
   *       "currently opened event" and is a stable fixed reference,
   *       so the cursor does not wander as the user scrolls around it.
   *    2. The row nearest the vertical middle of the viewport — far
   *       less twitchy than anchoring to the top edge (which flips
   *       every ~28 px of scroll and when the top row happens to have
   *       an out-of-order timestamp relative to its neighbours the
   *       cursor visibly teleports).
   *    3. If the middle row has no parseable / in-range time, scan a
   *       small +/- window around it to find one, rather than hiding
   *       the cursor (prevents flicker through empty-time gaps).
   *
   *  Cheap — one scroll-top read + a handful of array lookups. Safe
   *  to call from the scroll handler; CSS supplies the smoothing. */
  _updateTimelineCursor() {
    const el = this._timelineCursorEl;
    if (!el) return;
    if (!this._timeMs || !this._timeRange || !this._scr) {
      el.classList.add('hidden');
      return;
    }
    const visible = this._visibleCount();
    if (!visible) { el.classList.add('hidden'); return; }

    const { min, max } = this._timeRange;
    const ms = this._timeMs;

    // 1. Drawer-anchored: if a row is open, pin the cursor to its time.
    if (this.state.drawer.open && this.state.drawer.dataIdx >= 0) {
      const t = ms[this.state.drawer.dataIdx];
      if (Number.isFinite(t) && t >= min && t <= max) {
        const span = max - min;
        const pct = span > 0 ? ((t - min) / span) * 100 : 0;
        el.style.left = pct + '%';
        el.classList.remove('hidden');
        return;
      }
      // Drawer row has no valid time → fall through to scroll anchor.
    }

    // 2. Scroll-anchored: middle of the viewport, not the top edge.
    const scrollTop = this._scr.scrollTop || 0;
    const viewportH = this._scr.clientHeight || 0;
    const midPx = scrollTop + (viewportH / 2);
    const midV = Math.max(0, Math.min(visible - 1,
      Math.floor(midPx / this.ROW_HEIGHT)));

    // 3. Short bidirectional scan to tolerate rows with missing or
    //    out-of-range timestamps — scrolling through a few such rows
    //    should not hide the cursor or snap it to zero.
    const WINDOW = 8;
    const lo = Math.max(0, midV - WINDOW);
    const hi = Math.min(visible - 1, midV + WINDOW);
    let bestT = NaN;
    let bestD = Infinity;
    for (let v = lo; v <= hi; v++) {
      const dIdx = this._dataIdxOf(v);
      if (dIdx == null) continue;
      const t = ms[dIdx];
      if (!Number.isFinite(t) || t < min || t > max) continue;
      const d = Math.abs(v - midV);
      if (d < bestD) { bestD = d; bestT = t; }
    }
    if (!Number.isFinite(bestT)) { el.classList.add('hidden'); return; }

    const span = max - min;
    const pct = span > 0 ? ((bestT - min) / span) * 100 : 0;
    el.style.left = pct + '%';
    el.classList.remove('hidden');
  }

  /** Promotion from the column-header menu — opt the user into stacking
   *  the timeline histogram by `colIdx`. Toggle semantics: selecting the
   *  currently-active stack column disables stacking and returns the
   *  histogram to flat density.
   *
   *  When hosted inside Timeline Mode (outer view owns its own histogram
   *  + stack <select>), the `onStackTimelineBy` callback wins and we do
   *  NOT run the built-in internal-strip promotion path — a truthy return
   *  is treated as "handled". */
  _useColumnAsTimelineStack(colIdx) {
    if (this._onStackTimelineBy) {
      try {
        const handled = this._onStackTimelineBy(colIdx, this.columns[colIdx]);
        if (handled !== false) return;
      } catch (e) {
        try { console.error('grid-viewer onStackTimelineBy threw', e); } catch (_) { /* ignore */ }
      }
    }
    if (this._timeStackColumn === colIdx) {
      this._timeStackColumn = null;
      this._timeStackKeys = null;
      this._timeStackBuckets = null;
    } else {
      this._timeStackColumn = colIdx;
      this._timeStackKeys = null;      // force regenerate against visible rows
      this._timeStackBuckets = null;
    }
    this._rebuildBucketsForView();
    this._paintTimeline();
  }

  /** Promotion from the column-header menu — opt the user into a different
   *  column as the timeline source (or disable it if already active).
   *
   *  When hosted inside Timeline Mode (outer view owns its own histogram
   *  strip and time-column `<select>`), the `onUseAsTimeline` callback
   *  wins: a truthy return is treated as "handled" and the grid does
   *  NOT promote its own internal `.grid-timeline` strip — otherwise the
   *  column would light up both the outer Timeline histogram AND a
   *  duplicate in-grid strip. */
  _useColumnAsTimeline(colIdx) {
    if (this._onUseAsTimeline) {
      try {
        const handled = this._onUseAsTimeline(colIdx, this.columns[colIdx]);
        if (handled !== false) return;
      } catch (e) {
        try { console.error('grid-viewer onUseAsTimeline threw', e); } catch (_) { /* ignore */ }
      }
    }

    if (this._timeColumn === colIdx && this._timeMs) {
      // Toggle off.
      this._timeColumnIsAuto = true;
      this._timeColumn = null;
      this._timeWindow = null;
      this._hideTimeline();
      this._applyTimelineFilter();
      return;
    }
    this._timeColumnIsAuto = false;
    this._timeColumn = colIdx;
    this._timeWindow = null;
    this._rebuildTimeline();
    this._applyTimelineFilter();
  }

  /** Single entry point for "a time-window change may have changed the
   *  visible row set". If an external renderer (EVTX) supplied its own
   *  filter runner it wins — that path already intersects the viewer's
   *  _timeWindow via _dataIdxInTimeWindow because its filter loop calls
   *  into the viewer's filteredIndices. Otherwise we fall through to the
   *  built-in text-filter recompute. */
  _applyTimelineFilter() {
    if (this._onFilterRecompute) {
      try { this._onFilterRecompute(); }
      catch (e) { try { console.error('grid-viewer onFilterRecompute threw', e); } catch (_) { /* ignore */ } }
    } else {
      this._applyFilter();
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  //  LIFECYCLE
  // ═══════════════════════════════════════════════════════════════════════════
  root() { return this._root; }


  destroy() {
    if (this._destroyed) return;
    this._destroyed = true;
    if (this._renderRAF) cancelAnimationFrame(this._renderRAF);
    this._cancelHighlightTimer();
    this._closePopover();
    if (this._resizeObs) { try { this._resizeObs.disconnect(); } catch (_) { /* ignore */ } }
    if (this._boundHandlers.onDocClick) {
      try { document.removeEventListener('mousedown', this._boundHandlers.onDocClick, true); } catch (_) { /* ignore */ }
    }
    if (this._boundHandlers.onDocScroll) {
      try { window.removeEventListener('scroll', this._boundHandlers.onDocScroll, true); } catch (_) { /* ignore */ }
    }
    this._sizer.replaceChildren();
    this._drawerBody.replaceChildren();
    this._searchTextCache = null;

    // ── Release heavy data arrays ────────────────────────────────────────
    // Without explicit nulling, any transient reference (pending RAF,
    // highlight timer closure, back-reference from a parent view) keeps
    // the entire row dataset alive. For large files this is hundreds of
    // MB — repeated load/clear cycles OOM the browser tab.
    this.store = null;
    this.rawText = null;
    this.rowSearchText = null;
    this.rowOffsets = null;
    this._timeMs = null;
    this._timeBuckets = null;
    this._timeStackBuckets = null;
    this._columnLengths = null;
  }
}

// Local HTML-escape alias — delegates to the canonical escHtml() from constants.js.
const _esc = escHtml;
