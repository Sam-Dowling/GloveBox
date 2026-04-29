'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-render-grid.js — TimelineView prototype mixin (B2f2).
//
// Hosts the grid + column-top-values-cards paint stack. Twin to
// `timeline-view-render-chart.js` (B2f1), but for the lower
// (table) half of the timeline UI.
//
// Methods (~11 instance, ~975 lines):
//
//   Grid table:
//     _renderGrid (thin dispatcher),
//     _invalidateGridCache,
//     _renderGridInto — the workhorse that mounts a `GridViewer`
//       child against `_filteredIdx`, wires per-row click handlers
//       to the cursor / chip / popover surfaces, and threads the
//       `_rawText` payload back through for sidebar focus.
//
//   Column top-values cards (the "card-strip" above the grid):
//     _renderColumns (thin dispatcher),
//     _paintColumnCards — paints one card per column with a
//       sparkline + top-N values, drag-to-reorder, click-to-
//       Include/Exclude/Sus, and per-column resize handles.
//     _commitCardOrder, _susValsForCol, _cardSpanFor,
//     _cardSizeSave, _installCardResize,
//     _columnsGridGeometry — CSS-Grid track-size resolver for the
//       column-cards container (responds to viewport width + the
//       persisted `_cardSize` setting S/M/L).
//
// Methods kept in core `timeline-view.js` (NOT moved):
//   • `_scheduleRender` — cross-surface dispatcher (chart + grid).
//   • `_installSplitterDrag` — chart-vs-grid divider.
//
// Detection-renderer redirect comments around lines 1900–1910 in
// the pre-B2f2 file are MOVED with this mixin — the actual methods
// (`_renderDetections`, `_renderEntities`, `_collectEntities`,
// `_pivotOnEntity`, `_pivotAnyContainsToggle`) already live in
// `timeline-detections.js` (a pre-existing sibling mixin, NOT
// touched by this commit).
//
// Bodies are moved byte-identically. The grid mount path and
// column-card paint inner loop are perf-critical — pinned by
// parity test below.
//
// Loads AFTER timeline-view.js (which declares `class TimelineView`).
// ════════════════════════════════════════════════════════════════════════════

Object.assign(TimelineView.prototype, {

  // ── Grid ─────────────────────────────────────────────────────────────────
  _renderGrid() {
    this._renderGridInto(this._els.gridWrap, this._filteredIdx || new Uint32Array(0), 'main');
  },

  /** Invalidate the cached sorted-index. Called whenever `_timeMs`
   *  content changes (via `_parseAllTimestamps`) so the next
   *  `_renderGridInto` re-sorts from scratch. The Phase 4 RowView
   *  adapter has no per-render cache of its own — re-renders allocate
   *  only the small adapter object — so there's nothing else to clear. */
  _invalidateGridCache() {
    this._sortedFullIdx = null;
  },

  _renderGridInto(wrap, idx, role) {
    // ── Pre-sort idx by timestamp ──────────────────────────────────────
    // Sort the filtered index array by the pre-parsed _timeMs values so
    // rows are handed to GridViewer in chronological order. This avoids
    // GridViewer's _sortByColumn temporal path which would re-parse
    // every cell via Date.parse() inside the sort comparator — O(n log n)
    // Date.parse calls that cost 2-4s for 1M rows. The numerical sort
    // below is O(n log n) float comparisons on an already-parsed
    // Float64Array, which completes in ~200ms for 1M rows.
    //
    // When the index covers the full dataset (no query active) and the
    // time column hasn't changed, reuse the previously sorted index.
    // This turns filter-clear from an O(n log n) re-sort into an O(1)
    // cache hit; the per-row materialisation cost vanished entirely
    // with the Phase 4 `TimelineRowView` adapter.
    const timeCol = this._timeCol;
    const timeMs = this._timeMs;
    const isFullDataset = idx.length === this.store.rowCount;
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

    // Build a RowStore-shaped adapter that GridViewer can read cells
    // through directly — no `string[][]` materialisation, no per-render
    // ~3× input allocation. The adapter is cheap to recreate (a few
    // field assignments) so we don't bother caching it across re-renders;
    // invalidation is implicit when the caller passes a different `idx`.
    //
    // Source the three slot-shaped fields from `this._dataset` (rather
    // than the legacy `this.store` / `this._extractedCols` /
    // `this._baseColumns.length` aliases). The dataset's
    // `extractedCols` getter returns the SAME array reference the view
    // mutates, so the adapter sees newly-pushed extracted columns
    // without needing a re-build.
    const ds = this._dataset;
    const rowView = new TimelineRowView({
      baseStore: ds ? ds.store : this.store,
      extractedCols: ds ? ds.extractedCols : this._extractedCols,
      baseLen: ds ? ds.baseColCount : this._baseColumns.length,
      idx,
    });
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
      // `dataIdx` is the grid's visIdx — the position within
      // `rowView` (which already has the chrono sort + chip filter
      // applied). Read the EID and Channel cells out of the rowView
      // directly; it dispatches to `baseStore.getCell` internally so
      // no allocation happens per pill rebuild.
      const eid = rowView.getCell(dataIdx, evtxEidCol);
      if (!eid) return null;
      const ch = evtxChannelCol >= 0 ? rowView.getCell(dataIdx, evtxChannelCol) : '';
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
      const eid = rowView.getCell(dataIdx, evtxEidCol);
      if (!eid) return;
      const ch = evtxChannelCol >= 0 ? rowView.getCell(dataIdx, evtxChannelCol) : '';
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
      const eid = rowView.getCell(dataIdx, evtxEidCol);
      if (eid === '') return;
      const ch = evtxChannelCol >= 0 ? rowView.getCell(dataIdx, evtxChannelCol) : '';
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
        store: rowView,
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
        // Column drag-reorder persistence — only on the main grid
        // (the suspicious-rows mini-grid is read-only). Receives the
        // post-reorder real-index array from GridViewer; we translate
        // it to column NAMES (stable across schema mutations) and save
        // it to the per-file `loupe_timeline_grid_col_order` map. On
        // next mount, `_applyGridColOrder` converts the saved names
        // back to live real indices and re-applies via
        // `viewer._setColumnOrder`. Without this hook, drags work for
        // the session but are lost on reload.
        onColumnReorder: role === 'main' ? (realIdxs) => {
          const names = [];
          for (const i of realIdxs) {
            if (Number.isInteger(i) && i >= 0 && i < this.columns.length) {
              names.push(this.columns[i] || `col${i}`);
            }
          }
          this._gridColOrder = names;
          TimelineView._saveGridColOrderFor(this._fileKey, names);
        } : null,
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
        // grid-viewer uses data-idx = dataIdx within the viewer's rows view;
        // that's the position inside the `TimelineRowView` adapter (i.e.
        // an index into the filtered/sorted `idx`), NOT the original row.
        // IMPORTANT: resolve the virtual → original-row mapping against the
        // LIVE filtered-index on `this`, not the `origIdx` captured in this
        // listener's closure at first-render time. The contextmenu listener
        // is wired once, but `_renderGridInto` re-uses the same GridViewer
        // and swaps the row source via `existing.setRows(rowView, …)`
        // whenever a filter is applied — `origIdx` becomes stale the moment
        // the query bar narrows the grid, which previously made the right-click
        // menu's `Include / Exclude "<value>"` labels (and the resulting
        // chips) point at the wrong cell. Mirrors the same pattern the
        // left-click handler above already uses.
        const curIdx = (viewer._tlRole === 'main') ? this._filteredIdx : this._susFilteredIdx;
        const origRow = curIdx ? curIdx[virtualIdx] : origIdx[virtualIdx];
        // Determine which column was clicked. GridViewer stamps `data-col`
        // on every body cell with the REAL column index (survives hidden /
        // pinned / reordered columns). Single-mode GridViewer (Phase 4c)
        // unconditionally stamps the attribute, so the legacy positional-
        // math fallback that previously lived here is unreachable from any
        // in-tree caller and has been removed.
        const colAttr = cell.dataset ? cell.dataset.col : null;
        if (colAttr == null || colAttr === '') return;
        const colIdx = parseInt(colAttr, 10);
        if (!Number.isFinite(colIdx) || colIdx < 0 || colIdx >= this.columns.length) return;
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
          const n = rowView.rowCount;
          const idxs = new Array(n);
          for (let i = 0; i < n; i++) idxs[i] = i;
          viewer._sortSpec = { colIdx: this._timeCol, dir: 'asc' };
          viewer._sortOrder = idxs;
          viewer._buildHeaderCells();
          viewer._forceFullRender();
        }
        // Re-apply persisted drag-reorder, if any. Done AFTER the
        // sort-spec stamp so the rebuilt header rows reflect both the
        // sort indicator AND the saved order. `_applyGridColOrder` is a
        // no-op when `_gridColOrder` is null or empty.
        this._applyGridColOrder();
      }
    } else {
      // Preserve columns in case new extracted columns were added.
      existing.columns = this.columns;
      existing._rowClassFn = rowClass;
      existing._cellClassFn = cellClass;
      // Re-bind the EVTX EID `cellAugment` closure too — it captures the
      // current `rowView` reference, so without re-assignment the hook
      // would keep appending pills based on a stale view after a filter
      // / sort re-render.
      existing._cellAugmentFn = cellAugment;
      // Hand the new rowView to GridViewer's setRows. `setRows` detects
      // the RowStore-shape and switches the grid into store mode; the
      // identity sort order is stamped via `preSorted` so the chrono
      // permutation already encoded in `idx` is preserved without an
      // expensive Date.parse-per-comparison re-sort.
      existing.setRows(rowView, null, null, { preSorted: true });
    }
  },

  // ── Column top-values cards ──────────────────────────────────────────────
  _renderColumns() {
    this._paintColumnCards(this._els.cols, this._colStats, 'main');
  },

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
  },

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
  },

  // Resolve `_gridColOrder` (column NAMES) → live real indices and
  // hand them to GridViewer. Called from three sites:
  //   1. After first mount of `this._grid` in `_renderGridInto` so a
  //      saved order is honoured on every page reload.
  //   2. After `_grid._updateColumns(this.columns)` in the fast path
  //      of `_rebuildExtractedStateAndRender`, because `_updateColumns`
  //      appends newly-added real-indices to `_colOrder`'s tail —
  //      `_applyGridColOrder` then re-asserts the user's preferred
  //      arrangement (extracted column may belong somewhere in the
  //      middle, not at the end).
  //   3. From `_enrichSingleIpCol` after geo-extracting, to land the
  //      new geo column adjacent to its IPv4 source. (Uses the same
  //      pipeline: it computes the new name order, stores it on
  //      `this._gridColOrder`, and calls `_applyGridColOrder`.)
  //
  // No-op when there's no grid mounted, no saved order, or the saved
  // order resolves to the identity permutation (saves a re-render).
  _applyGridColOrder() {
    if (!this._grid || typeof this._grid._setColumnOrder !== 'function') return;
    const names = this._gridColOrder;
    if (!Array.isArray(names) || !names.length) return;
    const n = this.columns.length;
    if (!n) return;
    // Resolve names → real indices. Any name that no longer exists
    // (column deleted, schema changed) is silently skipped; the
    // GridViewer-side resolver heals the residue by appending any
    // missing real index.
    const seen = new Set();
    const realIdxs = [];
    for (const name of names) {
      const i = this.columns.indexOf(name);
      if (i < 0) continue;
      if (seen.has(i)) continue;
      seen.add(i);
      realIdxs.push(i);
    }
    // If the resolved order matches identity, skip the costly re-render.
    let identity = realIdxs.length === n;
    if (identity) {
      for (let i = 0; i < n; i++) {
        if (realIdxs[i] !== i) { identity = false; break; }
      }
    }
    if (identity) return;
    this._grid._setColumnOrder(realIdxs);
  },

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
  },

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
  },

  // Persist a card's column-span override. Deletes the key when span
  // falls back to the default (1) so the persistence layer stays tidy.

  _cardSizeSave(colName, span) {
    if (span <= 1) delete this._cardWidths[colName];
    else this._cardWidths[colName] = { span };
    TimelineView._saveCardWidthsFor(this._fileKey, this._cardWidths);
  },

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
  },

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
  },

});
