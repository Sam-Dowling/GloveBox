'use strict';
// ════════════════════════════════════════════════════════════════════════════
// grid-viewer.js — bulletproof shared virtual-scroll grid
//
// Wave-A architectural rewrite of the former csv-renderer.js / evtx-renderer.js
// virtual-scroll plumbing. Single primitive consumed by CSV (now), and EVTX /
// XLSX / SQLite / JSON-array (in later waves).
//
// Design invariants (what kills the race-condition class):
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
//   6. CHUNKED COOPERATIVE PARSE. The caller's row source can be fed in
//      chunks via `setRows()` / `appendRows()`. The grid re-renders only
//      the visible window, so a 50 MB CSV can paint its first 1 k rows in
//      ~200 ms while the rest streams in without blocking the main thread.
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
    this.columns        = opts.columns || [];
    this.rows           = opts.rows || [];
    this.rowSearchText  = opts.rowSearchText || null;
    this.rowOffsets     = opts.rowOffsets || null;
    this.rawText        = opts.rawText || '';
    this._rootClass     = opts.className || 'csv-view';
    this._infoText      = opts.infoText || '';
    this._truncNote     = opts.truncationNote || '';
    this._emptyMessage  = opts.emptyMessage || 'Empty file.';
    // Wave-B hooks (optional) — let format-specific renderers (EVTX, XLSX,
    // SQLite, JSON) reuse the virtual-scroll + drawer + highlight core
    // without having to re-implement it, while still owning their own
    // toolbar and drawer-body layout:
    //   detailBuilder : (dataIdx, row, cols) => HTMLElement   // drawer body
    //   hideFilterBar : bool   // suppress the built-in search input
    //   extraToolbarEls : HTMLElement[]   // prepended above the filter bar
    //   rowTitle      : (dataIdx) => string   // drawer heading override
    //   cellText      : (dataIdx, colIdx, rawCell) => string  // display formatter
    //   cellClass     : (dataIdx, colIdx, rawCell) => string|null  // extra class
    this._detailBuilder   = typeof opts.detailBuilder === 'function' ? opts.detailBuilder : null;
    this._hideFilterBar   = !!opts.hideFilterBar;
    this._extraToolbarEls = Array.isArray(opts.extraToolbarEls) ? opts.extraToolbarEls : [];
    this._rowTitleFn      = typeof opts.rowTitle === 'function' ? opts.rowTitle : null;
    this._cellTextFn      = typeof opts.cellText === 'function' ? opts.cellText : null;
    this._cellClassFn     = typeof opts.cellClass === 'function' ? opts.cellClass : null;
    // Wave-E — Timeline layout (final). Opt-in per-caller:
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
    this._timeColumn       = Number.isInteger(opts.timeColumn) ? opts.timeColumn : null;
    this._timeColumnIsAuto = !Number.isInteger(opts.timeColumn);
    this._timeParser       = typeof opts.timeParser === 'function' ? opts.timeParser : null;
    this._timeBucketCount  = Math.max(20, Math.min(400, opts.timelineBuckets || 100));
    this._onFilterRecompute = typeof opts.onFilterRecompute === 'function' ? opts.onFilterRecompute : null;

    // Timeline runtime state — populated by _buildTimelineBuckets().
    //   _timeMs[dataIdx] = parsed ms-since-epoch (NaN if unparseable / empty).
    //   _timeRange       = { min, max } across all parseable cells.
    //   _timeBuckets     = Int32Array(bucketCount) — count per bucket.
    //   _timeWindow      = null | { min, max }   — active user selection.
    this._timeMs      = null;
    this._timeRange   = null;
    this._timeBuckets = null;
    this._timeWindow  = null;


    // Tunables (intentionally internal — callers don't twiddle these).
    this.ROW_HEIGHT   = 28;
    this.HEADER_H     = 32;
    this.BUFFER_ROWS  = 12;
    this.MIN_COL_W    = 60;
    this.MAX_COL_W    = 320;
    this.ROWNUM_COL_W = 64;
    this.DRAWER_MIN_W = 280;
    this.DRAWER_MAX_W = 900;

    // Mutable state — all reads go through here; all writes schedule a render.
    this.state = {
      filteredIndices: null,              // null = no filter + no sort; else Array of dataIdx
      visibleCount:    this.rows.length,
      renderedRange:   { start: -1, end: -1 },
      drawer: {
        open:    false,
        dataIdx: -1,
        width:   this._loadDrawerWidth()
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

    // Wave-C state — column-level features, defang, malformed ribbon.
    this._sortOrder       = null;   // null | Int32Array — permutation of dataIdx under current sort
    this._sortSpec        = null;   // null | { colIdx, dir: 'asc'|'desc' }
    this._hiddenCols      = new Set();
    this._malformedRows   = null;   // null | Set<dataIdx>   (CSV short-row / bad-quote rows)
    this._malformedCursor = -1;

    this._renderRAF     = null;
    this._resizeObs     = null;
    this._destroyed     = false;
    this._boundHandlers = {};
    this._columnWidths  = [];
    this._openPopover   = null;     // active header menu / top-values popover DOM node


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
    if (this.rows.length) this._rebuildTimeline();
  }


  // ═══════════════════════════════════════════════════════════════════════════
  //  DOM CONSTRUCTION
  // ═══════════════════════════════════════════════════════════════════════════
  _buildDOM() {
    const root = document.createElement('div');
    root.className = this._rootClass + ' grid-view';
    root._rawText = this.rawText;

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

    // ── Timeline strip (Wave-E) — hidden by default; populated after the
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
      '<div class="grid-timeline-tooltip hidden"></div>' +
      '</div>' +
      '<span class="grid-timeline-label grid-timeline-label-right"></span>' +
      '<button class="tb-btn grid-timeline-clear hidden" title="Clear time window ([Esc])">✕ Window</button>';
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
    this._root         = root;
    this._info         = info;
    this._progress     = progress;
    this._progressBar  = progress.querySelector('.grid-progress-bar');
    this._progressLbl  = progress.querySelector('.grid-progress-label');
    this._filterInput  = filterInput;
    this._clearBtn     = clearBtn;
    this._filterStatus = filterStatus;
    this._malformedChip   = malformedChip;
    this._malformedLabel  = malformedChip.querySelector('.grid-malformed-count');
    this._malformedNextBtn   = malformedChip.querySelector('.grid-malformed-next');
    this._malformedFilterBtn = malformedChip.querySelector('.grid-malformed-filter');
    this._main         = main;
    this._emptyEl      = null;

    // Timeline strip refs
    this._timelineEl        = timeline;
    this._timelineTrackEl   = timeline.querySelector('.grid-timeline-track');
    this._timelineBucketsEl = timeline.querySelector('.grid-timeline-buckets');
    this._timelineWindowEl  = timeline.querySelector('.grid-timeline-window');
    this._timelineTooltipEl = timeline.querySelector('.grid-timeline-tooltip');
    this._timelineLabelLeft = timeline.querySelector('.grid-timeline-label-left');
    this._timelineLabelRight= timeline.querySelector('.grid-timeline-label-right');
    this._timelineClearBtn  = timeline.querySelector('.grid-timeline-clear');

    this._scr          = scr;
    this._header       = header;
    this._sizer        = sizer;
    this._drawerHandle = handle;
    this._drawer       = drawer;
    this._drawerBody   = drawer.querySelector('.grid-drawer-body');
    this._drawerClose  = drawer.querySelector('.grid-drawer-close');
    this._drawerTitle  = drawer.querySelector('.grid-drawer-title');

    // Build header cells
    this._buildHeaderCells();

    if (!this.rows.length) {
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
    for (let i = 0; i < this.columns.length; i++) {
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

      cell.title = name + ' — click for column menu';
      cell.addEventListener('click', (e) => {
        e.stopPropagation();
        this._openHeaderMenu(i, cell);
      });
      this._header.appendChild(cell);
    }
  }


  _recomputeColumnWidths() {
    if (!this.columns.length) { this._columnWidths = []; return; }
    const sample = this.rows.slice(0, 100);
    const widths = [];
    for (let col = 0; col < this.columns.length; col++) {
      const lens = [];
      lens.push((this.columns[col] || '').length);
      for (let r = 0; r < sample.length; r++) {
        const cell = sample[r][col] || '';
        lens.push(cell.length);
      }
      lens.sort((a, b) => a - b);
      const p85 = lens[Math.floor(lens.length * 0.85)] || lens[lens.length - 1] || 10;
      const w = Math.min(this.MAX_COL_W, Math.max(this.MIN_COL_W, Math.ceil(p85 * 7.2)));
      widths.push(w);
    }
    this._columnWidths = widths;
  }

  _applyColumnTemplate() {
    const parts = [this.ROWNUM_COL_W + 'px'];
    let totalW = this.ROWNUM_COL_W;
    for (let i = 0; i < this._columnWidths.length; i++) {
      if (this._hiddenCols.has(i)) continue;
      parts.push(this._columnWidths[i] + 'px');
      totalW += this._columnWidths[i];
    }
    this._root.style.setProperty('--grid-template', parts.join(' '));
    this._root.style.setProperty('--grid-min-width', totalW + 'px');
  }


  _updateInfoBar() {
    if (this._infoText) {
      this._info.textContent = this._infoText;
    } else {
      const rc = this.rows.length;
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
      if (this._renderRAF || this.state.isProgrammaticScroll) return;
      this._renderRAF = requestAnimationFrame(() => {
        this._renderRAF = null;
        this._render();
      });
    };
    this._scr.addEventListener('scroll', this._boundHandlers.onScroll, { passive: true });

    // Filter input
    this._boundHandlers.onFilter = () => this._applyFilter();
    this._filterInput.addEventListener('input', this._boundHandlers.onFilter);
    this._filterInput.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { this._filterInput.blur(); }
    });
    this._clearBtn.addEventListener('click', () => {
      this._filterInput.value = '';
      this._applyFilter();
    });

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
    };
    this._scr.addEventListener('keydown', this._boundHandlers.onKey);
    this._drawer.addEventListener('keydown', this._boundHandlers.onKey);

    // Timeline drag-select + click-bucket + hover-tooltip.
    this._wireTimelineEvents();
    this._timelineClearBtn.addEventListener('click', () => this._clearTimeWindow());


    // Drawer handle drag to resize
    this._wireDrawerResize();

    // Malformed-row ribbon — Next and Filter buttons.
    this._malformedNextBtn.addEventListener('click', () => this._jumpToNextMalformed());
    this._malformedFilterBtn.addEventListener('click', () => this._toggleMalformedFilter());

    // Global click to dismiss any open header / top-values popover.
    this._boundHandlers.onDocClick = (e) => {
      if (!this._openPopover) return;
      if (this._openPopover.contains(e.target)) return;
      if (e.target.closest && e.target.closest('.grid-header-cell')) return;
      this._closePopover();
    };
    document.addEventListener('mousedown', this._boundHandlers.onDocClick, true);

    // ResizeObserver on scroll container
    this._resizeObs = new ResizeObserver(() => this._scheduleRender());
    this._resizeObs.observe(this._scr);
  }


  _wireDrawerResize() {
    let startX = 0, startW = 0, dragging = false;
    const onMove = (e) => {
      if (!dragging) return;
      const dx = startX - e.clientX;
      const newW = Math.max(this.DRAWER_MIN_W, Math.min(this.DRAWER_MAX_W, startW + dx));
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
  }

  _loadDrawerWidth() {
    try {
      const v = parseInt(localStorage.getItem('loupe_grid_drawer_w'), 10);
      if (Number.isFinite(v)) return Math.max(280, Math.min(900, v));
    } catch (_) { /* ignore */ }
    return 420;
  }
  _saveDrawerWidth(w) {
    try { localStorage.setItem('loupe_grid_drawer_w', String(w)); } catch (_) { /* ignore */ }
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
    return this.state.filteredIndices ? this.state.filteredIndices.length : this.rows.length;
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

    const scrollTop    = this._scr.scrollTop;
    const viewportH    = this._scr.clientHeight || 400;

    // Virtual range — trivial arithmetic because row height is constant.
    const firstIdx = Math.max(0, Math.floor(scrollTop / this.ROW_HEIGHT) - this.BUFFER_ROWS);
    const lastIdx  = Math.min(
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
      if (dataIdx == null || dataIdx >= this.rows.length) continue;
      frag.appendChild(this._buildRow(dataIdx, v));
    }
    this._sizer.replaceChildren(frag);
    this.state.renderedRange = { start: firstIdx, end: lastIdx };
  }

  _buildRow(dataIdx, virtualIdx) {
    const row = this.rows[dataIdx];
    const tr = document.createElement('div');
    tr.className = 'grid-row';
    tr.dataset.idx = dataIdx;
    tr.dataset.vidx = virtualIdx;
    tr.style.top = (virtualIdx * this.ROW_HEIGHT) + 'px';

    // Row-number cell
    const numCell = document.createElement('div');
    numCell.className = 'grid-cell grid-row-num';
    numCell.textContent = String(dataIdx + 1);
    tr.appendChild(numCell);

    // Data cells
    const cols = this.columns.length;
    for (let c = 0; c < cols; c++) {
      if (this._hiddenCols.has(c)) continue;
      const td = document.createElement('div');
      td.className = 'grid-cell';
      const rawCell = row ? (row[c] != null ? row[c] : '') : '';
      const displayCell = this._cellTextFn
        ? this._cellTextFn(dataIdx, c, rawCell)
        : rawCell;
      const asStr = String(displayCell == null ? '' : displayCell);
      // Truncate for display; full value shown in drawer.
      const truncated = asStr.length > 160 ? asStr.substring(0, 160) + '…' : asStr;
      td.textContent = truncated;
      if (asStr.length > 40) td.title = asStr;
      if (asStr && !isNaN(parseFloat(asStr)) && /^-?\d/.test(asStr.trim())) {
        td.classList.add('grid-cell-num');
      }
      if (this._cellClassFn) {
        const extra = this._cellClassFn(dataIdx, c, rawCell);
        if (extra) td.classList.add(...String(extra).split(/\s+/).filter(Boolean));
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
  }

  _closeDrawer() {
    this.state.drawer.open = false;
    this.state.drawer.dataIdx = -1;
    this._drawer.style.display = 'none';
    this._drawerHandle.style.display = 'none';
    this._drawerBody.replaceChildren();
    this._refreshHighlightDecorations();
  }

  _renderDrawerBody(dataIdx) {
    const row = this.rows[dataIdx];
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
    if (!pane) pane = this._buildDetailPaneElement(this.columns, row);

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
  }

  _buildDetailPaneElement(cols, row) {
    const pane = document.createElement('div');
    pane.className = 'csv-detail-pane grid-detail-pane';
    const grid = document.createElement('div');
    grid.className = 'csv-detail-grid';
    let hasContent = false;
    for (let i = 0; i < cols.length; i++) {
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
      vEl.textContent = val;
      grid.appendChild(vEl);
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
      const before  = _esc(text.slice(0, idx));
      const matched = _esc(text.slice(idx, idx + term.length));
      const after   = _esc(text.slice(idx + term.length));
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

    const total = this.rows.length;
    const tw = this._timeWindow;
    if (!query && !tw) {
      this.state.filteredIndices = null;
      this._clearBtn.style.display = 'none';
      this._filterStatus.textContent = '';
    } else {
      const out = [];
      for (let i = 0; i < total; i++) {
        if (query && !this._rowMatchesQuery(i, query)) continue;
        if (tw && !this._dataIdxInTimeWindow(i)) continue;
        out.push(i);
      }
      this.state.filteredIndices = out;
      this._clearBtn.style.display = query ? '' : 'none';
      const suffix = tw ? ' · timeline window' : '';
      this._filterStatus.textContent = query || tw
        ? `${out.length.toLocaleString()} of ${total.toLocaleString()} rows${suffix}`
        : '';
    }
    this._scr.scrollTop = 0;
    this._forceFullRender();
  }

  _dataIdxInTimeWindow(dataIdx) {
    if (!this._timeWindow || !this._timeMs) return true;
    const t = this._timeMs[dataIdx];
    if (!Number.isFinite(t)) return false;
    return t >= this._timeWindow.min && t <= this._timeWindow.max;
  }


  _rowMatchesQuery(dataIdx, needle) {
    if (this.rowSearchText && this.rowSearchText[dataIdx]) {
      return this.rowSearchText[dataIdx].includes(needle);
    }
    // Fallback — build on demand, cache for re-use.
    const row = this.rows[dataIdx];
    if (!row) return false;
    const joined = row.join(' ').toLowerCase();
    if (!this.rowSearchText) this.rowSearchText = new Array(this.rows.length);
    this.rowSearchText[dataIdx] = joined;
    return joined.includes(needle);
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
    this.state.parseProgress = { rows: this.rows.length, total };
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
    this._rebuildTimeline();
  }

  setRows(rows, rowSearchText, rowOffsets) {
    this.rows = rows;
    this.rowSearchText = rowSearchText || this.rowSearchText;
    this.rowOffsets = rowOffsets || this.rowOffsets;
    this._maybeRemoveEmptyPlaceholder();
    // If our filter is active it may now include new rows — recompute.
    if (this.state.filteredIndices != null && this._filterInput.value) {
      this._applyFilter();
    } else {
      this._forceFullRender();
    }
    this._updateInfoBar();
    this._rebuildTimeline();
  }


  /**
   * Drop the "Empty file." placeholder added in _buildDOM when the grid
   * was constructed with zero rows. Called whenever a chunked parser
   * pushes its first rows in via setRows() / appendRows() — without this
   * the placeholder lingers on top of the now-populated grid (CSV
   * streaming path).
   */
  _maybeRemoveEmptyPlaceholder() {
    if (this._emptyEl && this.rows.length) {
      try { this._emptyEl.remove(); } catch (_) { /* ignore */ }
      this._emptyEl = null;
    }
  }

  appendRows(newRows, newRowSearch, newRowOffsets) {
    // Cheap incremental push — used by the chunked CSV parser.
    const wasEmpty = this.rows.length === 0;
    for (const r of newRows) this.rows.push(r);
    if (wasEmpty && this.rows.length) this._maybeRemoveEmptyPlaceholder();
    if (newRowSearch) {
      if (!this.rowSearchText) this.rowSearchText = [];
      for (const s of newRowSearch) this.rowSearchText.push(s);
    }
    if (newRowOffsets) {
      if (!this.rowOffsets) this.rowOffsets = [];
      for (const o of newRowOffsets) this.rowOffsets.push(o);
    }
    // If filter is active, re-evaluate just the newly-appended rows.
    if (this.state.filteredIndices != null && this._filterInput.value) {
      const q = this._filterInput.value.toLowerCase().trim();
      const startIdx = this.rows.length - newRows.length;
      for (let i = 0; i < newRows.length; i++) {
        const dIdx = startIdx + i;
        if (this._rowMatchesQuery(dIdx, q)) this.state.filteredIndices.push(dIdx);
      }
      this._filterStatus.textContent =
        `${this.state.filteredIndices.length.toLocaleString()} of ${this.rows.length.toLocaleString()} rows`;
    }
    this._scheduleRender();
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
      get length() { return self.rows.length; },
      [Symbol.iterator]: function* () {
        for (let i = 0; i < self.rows.length; i++) yield self._dataRowShape(i);
      }
    };

    this._root._csvFilters = {
      // Core
      filterInput:      this._filterInput,
      applyFilter:      () => this._applyFilter(),
      clearFilter:      () => { this._filterInput.value = ''; this._applyFilter(); },
      scrollContainer:  this._scr,
      dataRows:         dataRowsProxy,
      headerRow:        this.columns,
      expandRow:        (rowObj) => {
        const idx = rowObj && rowObj.dataIndex !== undefined ? rowObj.dataIndex : rowObj;
        this._openDrawer(+idx);
      },
      scrollToRow:      (idx, flash = true) => this._scrollToRow(+idx, flash),
      scrollToFirstMatch: () => {
        if (this._visibleCount() > 0) this._scrollToRow(this._dataIdxOf(0));
      },
      forceRender:      () => this._forceFullRender(),
      buildDetailPane:  (td, row) => {
        const pane = this._buildDetailPaneElement(this.columns, row);
        td.appendChild(pane);
      },
      state:            this.state,
      getVisibleRowCount: () => this._visibleCount(),
      getDataIndex:     (v) => this._dataIdxOf(v),
      getVirtualIndex:  (d) => this._virtualIdxOf(d),

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
    const row = this.rows[dataIdx] || [];
    let searchText;
    if (this.rowSearchText && this.rowSearchText[dataIdx] != null) {
      searchText = this.rowSearchText[dataIdx];
    } else {
      searchText = row.join(' ').toLowerCase();
      if (!this.rowSearchText) this.rowSearchText = new Array(this.rows.length);
      this.rowSearchText[dataIdx] = searchText;
    }
    const off = this.rowOffsets ? this.rowOffsets[dataIdx] : null;
    return {
      rowData: row,
      searchText,
      offsetStart: off ? off.start : 0,
      offsetEnd:   off ? off.end   : 0,
      dataIndex:   dataIdx,
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
    this._closePopover();
    const pop = document.createElement('div');
    pop.className = 'grid-popover grid-header-menu';

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
    pop.appendChild(mkItem('Top values…', () => this._openTopValuesPopover(colIdx, anchorEl)));
    // Wave-E — opt-in promotion of any column to the timeline source.
    // Hidden for columns that look like bare numeric IDs so it doesn't
    // clutter menus on non-temporal data; still shown whenever at least
    // ~50% of sampled cells parse as a real timestamp.
    if (this._columnLooksTemporal(colIdx)) {
      const active = this._timeColumn === colIdx && this._timeMs;
      pop.appendChild(mkItem(
        active ? '✓ Use as timeline' : 'Use as timeline',
        () => this._useColumnAsTimeline(colIdx)
      ));
    }
    pop.appendChild(mkItem('Copy column', () => this._copyColumn(colIdx)));
    pop.appendChild(this._popoverSeparator());
    pop.appendChild(mkItem('Hide column', () => this._toggleHideColumn(colIdx), { danger: true }));


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
    let top  = rect.bottom + 2;
    if (left + popW > vw - 8) left = Math.max(8, vw - popW - 8);
    if (top + popH > vh - 8) top = Math.max(8, rect.top - popH - 2);
    pop.style.left = left + 'px';
    pop.style.top  = top + 'px';
    pop.style.visibility = '';
  }

  _closePopover() {
    if (!this._openPopover) return;
    try { this._openPopover.remove(); } catch (_) { /* ignore */ }
    this._openPopover = null;
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
      const row = this.rows[dIdx];
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
    const n = this.rows.length;
    const idxs = new Array(n);
    for (let i = 0; i < n; i++) idxs[i] = i;

    const mul = dir === 'desc' ? -1 : 1;
    // Detect numeric column by sampling — if ≥90% of non-empty cells parse
    // as finite numbers, sort numerically; else lexical (case-insensitive).
    let numCount = 0, nonEmpty = 0;
    const sampleN = Math.min(n, 200);
    for (let i = 0; i < sampleN; i++) {
      const v = this.rows[i] && this.rows[i][colIdx];
      if (v == null || v === '') continue;
      nonEmpty++;
      const f = parseFloat(v);
      if (Number.isFinite(f) && /^-?\s*\d/.test(String(v).trim())) numCount++;
    }
    const numeric = nonEmpty > 0 && numCount / nonEmpty >= 0.9;

    const getCell = (i) => {
      const r = this.rows[i];
      return r ? (r[colIdx] == null ? '' : r[colIdx]) : '';
    };

    if (numeric) {
      idxs.sort((a, b) => {
        const av = parseFloat(getCell(a));
        const bv = parseFloat(getCell(b));
        const aFin = Number.isFinite(av);
        const bFin = Number.isFinite(bv);
        if (!aFin && !bFin) return (a - b); // stable
        if (!aFin) return 1;
        if (!bFin) return -1;
        return (av - bv) * mul || (a - b);
      });
    } else {
      idxs.sort((a, b) => {
        const av = String(getCell(a)).toLowerCase();
        const bv = String(getCell(b)).toLowerCase();
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
  }

  _copyColumn(colIdx) {
    const n = this._visibleCount();
    const parts = new Array(n);
    for (let v = 0; v < n; v++) {
      const d = this._dataIdxOf(v);
      const r = this.rows[d];
      parts[v] = (r && r[colIdx] != null) ? String(r[colIdx]) : '';
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
        `${arr.length.toLocaleString()} malformed of ${this.rows.length.toLocaleString()} rows`;
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
    const n = this.rows.length;
    if (!n) return false;
    const SAMPLE = Math.min(n, 40);
    const step = Math.max(1, Math.floor(n / SAMPLE));
    let nonEmpty = 0, parsed = 0, idLike = 0;
    const seen = new Set();
    for (let i = 0; i < n && seen.size < 20; i += step) {
      const r = this.rows[i];
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

    const n = this.rows.length;
    if (!n) { this._hideTimeline(); return; }

    const ms = new Array(n);
    let min = Infinity, max = -Infinity, parsed = 0;
    for (let i = 0; i < n; i++) {
      const r = this.rows[i];
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

    this._timeMs    = ms;
    this._timeRange = { min, max };

    const B = this._timeBucketCount;
    const buckets = new Int32Array(B);
    const span = max - min;
    for (let i = 0; i < n; i++) {
      const t = ms[i];
      if (!Number.isFinite(t)) continue;
      let b = Math.floor(((t - min) / span) * B);
      if (b >= B) b = B - 1;
      if (b < 0) b = 0;
      buckets[b]++;
    }
    this._timeBuckets = buckets;

    this._paintTimeline();
    this._timelineEl.classList.remove('hidden');

    // If a window is active but out of range (e.g. after setRows), clear it.
    if (this._timeWindow &&
        (this._timeWindow.max < min || this._timeWindow.min > max)) {
      this._timeWindow = null;
      this._timelineWindowEl.classList.add('hidden');
      this._timelineClearBtn.classList.add('hidden');
    }
    this._paintTimelineWindow();
  }

  _hideTimeline() {
    this._timeMs = null;
    this._timeRange = null;
    this._timeBuckets = null;
    if (this._timelineEl) this._timelineEl.classList.add('hidden');
  }

  /** Render the bucket bars + min/max date labels. */
  _paintTimeline() {
    if (!this._timeBuckets || !this._timeRange) return;
    const buckets = this._timeBuckets;
    let peak = 1;
    for (let i = 0; i < buckets.length; i++) if (buckets[i] > peak) peak = buckets[i];
    const B = buckets.length;
    const frag = document.createDocumentFragment();
    for (let i = 0; i < B; i++) {
      const bar = document.createElement('span');
      bar.className = 'grid-timeline-bar';
      const pct = buckets[i] === 0 ? 0 : Math.max(4, Math.round((buckets[i] / peak) * 100));
      bar.style.left = (i / B * 100) + '%';
      bar.style.width = (1 / B * 100) + '%';
      bar.style.height = pct + '%';
      bar.dataset.bucket = i;
      bar.dataset.count = buckets[i];
      frag.appendChild(bar);
    }
    this._timelineBucketsEl.replaceChildren(frag);

    this._timelineLabelLeft.textContent  = this._fmtTimeLabel(this._timeRange.min);
    this._timelineLabelRight.textContent = this._fmtTimeLabel(this._timeRange.max);
  }

  /** Compact date format — drops the year when the full range fits in
   *  the same year, drops seconds when the span is longer than ~2 hours. */
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

  _paintTimelineWindow() {
    if (!this._timelineWindowEl || !this._timeRange) return;
    if (!this._timeWindow) {
      this._timelineWindowEl.classList.add('hidden');
      this._timelineClearBtn.classList.add('hidden');
      return;
    }
    const { min, max } = this._timeRange;
    const span = max - min || 1;
    const l = Math.max(0, (this._timeWindow.min - min) / span) * 100;
    const r = Math.min(1, (this._timeWindow.max - min) / span) * 100;
    this._timelineWindowEl.style.left  = l + '%';
    this._timelineWindowEl.style.width = Math.max(0.5, r - l) + '%';
    this._timelineWindowEl.classList.remove('hidden');
    this._timelineClearBtn.classList.remove('hidden');
    this._timelineClearBtn.title =
      `${this._fmtTimeLabel(this._timeWindow.min)} → ${this._fmtTimeLabel(this._timeWindow.max)} ([ ] to step, Esc to clear)`;
  }

  /** Wire mousedown on the bucket track for drag-select + click-bucket,
   *  plus mousemove for the floating tooltip. */
  _wireTimelineEvents() {
    const track = this._timelineTrackEl;
    const tip   = this._timelineTooltipEl;
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
      const bEnd   = this._timeRange.min + ((b + 1) / this._timeBuckets.length) * (this._timeRange.max - this._timeRange.min);
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
          this._paintTimelineWindow();
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
          const bEnd   = this._timeRange.min + ((b + 1) / B) * span;
          this._setTimeWindow(bStart, bEnd);
        } else {
          // Commit the drag-selected window.
          this._applyTimelineFilter();
        }
      };
      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onUp);
      e.preventDefault();
    });
  }

  _setTimeWindow(min, max) {
    if (!Number.isFinite(min) || !Number.isFinite(max)) return;
    if (min > max) { const t = min; min = max; max = t; }
    this._timeWindow = { min, max };
    this._paintTimelineWindow();
    this._applyTimelineFilter();
  }

  _clearTimeWindow() {
    if (!this._timeWindow) return;
    this._timeWindow = null;
    this._paintTimelineWindow();
    this._applyTimelineFilter();
  }

  /** [ / ] step the window by its own width earlier / later. */
  _stepTimeWindow(dir) {
    if (!this._timeWindow || !this._timeRange) return;
    const w = this._timeWindow.max - this._timeWindow.min;
    if (w <= 0) return;
    let nmin = this._timeWindow.min + dir * w;
    let nmax = this._timeWindow.max + dir * w;
    // Clamp to range.
    if (nmin < this._timeRange.min) {
      const shift = this._timeRange.min - nmin;
      nmin += shift; nmax += shift;
    }
    if (nmax > this._timeRange.max) {
      const shift = nmax - this._timeRange.max;
      nmin -= shift; nmax -= shift;
    }
    this._setTimeWindow(nmin, nmax);
  }

  /** Promotion from the column-header menu — opt the user into a different
   *  column as the timeline source (or disable it if already active). */
  _useColumnAsTimeline(colIdx) {
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
    this._sizer.replaceChildren();
    this._drawerBody.replaceChildren();
    this._searchTextCache = null;
  }
}

// Local HTML-escape helper — kept free of the class so class-internal `this`
// references can't accidentally reach it. Same contract as the old inline
// `_esc` in csv-renderer.js.
function _esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
