'use strict';
// ════════════════════════════════════════════════════════════════════════════
// csv-renderer.js — Renders .csv and .tsv files as styled tables
// Features: virtual scrolling (50k rows), click-to-expand detail panes,
//           dynamic row heights, auto-detect column widths, IOC navigation
// No external dependencies beyond the browser DOM.
// ════════════════════════════════════════════════════════════════════════════
class CsvRenderer {
  render(text, fileName) {
    // ═══════════════════════════════════════════════════════════════════════
    // CONFIGURATION
    // ═══════════════════════════════════════════════════════════════════════
    let rowHeight = 32;                  // Base row height in pixels (measured dynamically after DOM insertion)
    const DEFAULT_DETAIL_HEIGHT = 200;   // Fallback detail pane height before measurement
    const BUFFER_ROWS = 20;              // Extra rows to render above/below viewport
    const MAX_ROWS = 150000;             // Maximum rows to process

    const wrap = document.createElement('div');
    wrap.className = 'csv-view';
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const delim = ext === 'tsv' ? '\t' : this._delim(text);
    const { rows, rowOffsets } = this._parse(text, delim);
    if (!rows.length) { wrap.textContent = 'Empty file.'; return wrap; }

    // Header row (first row)
    const headerRow = rows[0] || [];
    const dataRowsRaw = rows.slice(1);
    // Data row offsets (skip header row offset)
    const dataRowOffsets = rowOffsets.slice(1);

    // Limit data rows
    const totalDataRows = dataRowsRaw.length;
    const limitedDataRows = dataRowsRaw.slice(0, MAX_ROWS);
    const limitedOffsets = dataRowOffsets.slice(0, MAX_ROWS);

    // Calculate reasonable column widths based on content
    const colWidths = this._calcColumnWidths([headerRow, ...limitedDataRows.slice(0, 100)]);

    // ═══════════════════════════════════════════════════════════════════════
    // VIRTUAL SCROLL STATE
    // ═══════════════════════════════════════════════════════════════════════
    const state = {
      expandedRows: new Set(),           // Set of expanded row data indices (0 or 1 items)
      detailPaneCache: new Map(),        // dataIdx -> detail pane DOM element
      detailHeightCache: new Map(),      // dataIdx -> measured height in pixels
      filteredIndices: null,             // null = no filter, array = indices of matching rows
      renderedRange: { start: -1, end: -1 },
      // Three mutually-exclusive highlight groups. Each holds its own timer
      // so cleanup is atomic. createRowElements reads these to reapply the
      // relevant CSS classes and <mark> wrappings on every re-render — that
      // is what makes highlights survive the RAF-driven height-remeasure
      // re-render, resize events, scroll events, and filter changes.
      flashHighlight: null,   // { dataIdx, clearAt, timer } — cyan scroll flash
      iocHighlight: null,     // { dataIdx, term, clearAt, timer } — yellow IOC nav
      yaraHighlight: null     // { matchesByDataIdx, focusDataIdx, focusMatchIdx,
      //   sourceText, clearAt, timer } — YARA match nav
    };

    // ═══════════════════════════════════════════════════════════════════════
    // HIGHLIGHT HELPERS (used by createRowElements to decorate freshly-built
    // detail panes with <mark> wrapping that survives re-renders)
    // ═══════════════════════════════════════════════════════════════════════
    const _esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    // IOC highlight: single search term, case-insensitive, first match per
    // .csv-detail-val cell. Wraps in <mark class="csv-ioc-highlight …">.
    const _wrapIocMarkInPane = (pane, term) => {
      if (!term) return;
      const termLower = term.toLowerCase();
      const valEls = pane.querySelectorAll('.csv-detail-val');
      for (const valEl of valEls) {
        const text = valEl.textContent;
        if (!text) continue;
        const idx = text.toLowerCase().indexOf(termLower);
        if (idx === -1) continue;
        const before = _esc(text.slice(0, idx));
        const matched = _esc(text.slice(idx, idx + term.length));
        const after = _esc(text.slice(idx + term.length));
        valEl.innerHTML = `${before}<mark class="csv-ioc-highlight csv-ioc-highlight-flash">${matched}</mark>${after}`;
      }
    };

    // YARA highlight: multiple matches per cell, each tagged with its global
    // matchIdx for focus-mark lookup. Overlapping hits resolved by
    // earliest-start-wins.
    const _wrapYaraMarksInPane = (pane, rowMatches, sourceText) => {
      if (!rowMatches || !rowMatches.length || !sourceText) return;
      const valEls = pane.querySelectorAll('.csv-detail-val');
      for (const valEl of valEls) {
        const cellText = valEl.textContent;
        if (!cellText) continue;
        const hits = [];
        for (const rm of rowMatches) {
          const matchStr = sourceText.substring(rm.offset, rm.offset + rm.length);
          if (!matchStr) continue;
          let idx = cellText.indexOf(matchStr);
          if (idx === -1) idx = cellText.toLowerCase().indexOf(matchStr.toLowerCase());
          if (idx !== -1) hits.push({ start: idx, end: idx + matchStr.length, matchIdx: rm._matchIdx });
        }
        if (!hits.length) continue;
        hits.sort((a, b) => a.start - b.start);
        const keep = [];
        let cursor = -1;
        for (const h of hits) { if (h.start >= cursor) { keep.push(h); cursor = h.end; } }
        let out = '';
        let pos = 0;
        for (const h of keep) {
          if (h.start > pos) out += _esc(cellText.substring(pos, h.start));
          out += `<mark class="csv-yara-highlight csv-yara-highlight-flash" data-yara-match="${h.matchIdx}">${_esc(cellText.substring(h.start, h.end))}</mark>`;
          pos = h.end;
        }
        if (pos < cellText.length) out += _esc(cellText.substring(pos));
        valEl.innerHTML = out;
      }
    };

    // Internal clear helpers — cancel timer and null out the group.
    const _clearFlashInternal = () => {
      if (state.flashHighlight) { clearTimeout(state.flashHighlight.timer); state.flashHighlight = null; }
    };
    const _clearIocInternal = () => {
      if (state.iocHighlight) { clearTimeout(state.iocHighlight.timer); state.iocHighlight = null; }
    };
    const _clearYaraInternal = () => {
      if (state.yaraHighlight) { clearTimeout(state.yaraHighlight.timer); state.yaraHighlight = null; }
    };

    // Pre-compute search text for all rows (for filtering)
    const rowSearchText = limitedDataRows.map(row => row.join(' ').toLowerCase());

    // ── Info bar ─────────────────────────────────────────────────────────
    const info = document.createElement('div'); info.className = 'csv-info';
    const dn = delim === '\t' ? 'Tab' : delim === ',' ? 'Comma' : delim === ';' ? 'Semicolon' : 'Pipe';
    info.textContent = `${rows.length.toLocaleString()} rows × ${headerRow.length} columns · delimiter: ${dn}`;
    wrap.appendChild(info);

    // ── Filter bar ───────────────────────────────────────────────────────
    const filterBar = document.createElement('div');
    filterBar.className = 'csv-filter-bar';

    const filterInput = document.createElement('input');
    filterInput.type = 'text';
    filterInput.placeholder = 'Filter rows…';
    filterInput.className = 'csv-filter-input';

    const clearBtn = document.createElement('button');
    clearBtn.className = 'tb-btn csv-clear-btn';
    clearBtn.textContent = '✕ Clear';
    clearBtn.title = 'Clear filter and show all rows';
    clearBtn.style.display = 'none';

    const filterStatus = document.createElement('span');
    filterStatus.className = 'csv-filter-status';

    filterBar.appendChild(filterInput);
    filterBar.appendChild(clearBtn);
    filterBar.appendChild(filterStatus);
    wrap.appendChild(filterBar);

    // ═══════════════════════════════════════════════════════════════════════
    // SCROLL CONTAINER & TABLE (simple structure for virtual scrolling)
    // ═══════════════════════════════════════════════════════════════════════
    const scr = document.createElement('div');
    scr.className = 'csv-scroll';
    scr.style.cssText = 'overflow:auto;';

    const tbl = document.createElement('table');
    tbl.className = 'xlsx-table csv-table';
    tbl.style.cssText = 'width:100%;table-layout:auto;';

    // ── Header row ───────────────────────────────────────────────────────
    const thead = document.createElement('thead');
    const headerTr = document.createElement('tr');

    // Row number header
    const thNum = document.createElement('th');
    thNum.className = 'xlsx-row-header';
    thNum.textContent = '#';
    headerTr.appendChild(thNum);

    // Column headers with calculated widths
    headerRow.forEach((cell, ci) => {
      const th = document.createElement('th');
      th.className = 'xlsx-col-header csv-header';
      th.textContent = cell;
      th.title = cell;
      if (colWidths[ci]) {
        th.style.maxWidth = colWidths[ci] + 'px';
        th.style.overflow = 'hidden';
        th.style.textOverflow = 'ellipsis';
        th.style.whiteSpace = 'nowrap';
      }
      headerTr.appendChild(th);
    });
    thead.appendChild(headerTr);
    tbl.appendChild(thead);

    // ── Table body (virtual rows will be rendered here) ──────────────────
    const tbody = document.createElement('tbody');
    tbl.appendChild(tbody);

    scr.appendChild(tbl);
    wrap.appendChild(scr);

    // Truncation warning (if needed)
    if (totalDataRows > MAX_ROWS) {
      const note = document.createElement('div');
      note.className = 'csv-info';
      note.textContent = `⚠ Showing first ${MAX_ROWS.toLocaleString()} of ${totalDataRows.toLocaleString()} rows`;
      wrap.appendChild(note);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // HELPER: Get visible row count
    // ═══════════════════════════════════════════════════════════════════════
    const getVisibleRowCount = () => {
      return state.filteredIndices ? state.filteredIndices.length : limitedDataRows.length;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // HELPER: Get data index for virtual index
    // ═══════════════════════════════════════════════════════════════════════
    const getDataIndex = (virtualIdx) => {
      return state.filteredIndices ? state.filteredIndices[virtualIdx] : virtualIdx;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // HELPER: Get virtual index for data index
    // ═══════════════════════════════════════════════════════════════════════
    const getVirtualIndex = (dataIdx) => {
      if (!state.filteredIndices) return dataIdx;
      return state.filteredIndices.indexOf(dataIdx);
    };

    // ═══════════════════════════════════════════════════════════════════════
    // DYNAMIC HEIGHT HELPERS
    // ═══════════════════════════════════════════════════════════════════════

    // Get measured or estimated detail height for an expanded row
    const getDetailHeight = (dataIdx) => {
      return state.detailHeightCache.has(dataIdx)
        ? state.detailHeightCache.get(dataIdx)
        : DEFAULT_DETAIL_HEIGHT;
    };

    // Get total height for a row (base + detail if expanded)
    const getRowHeight = (dataIdx) => {
      return state.expandedRows.has(dataIdx)
        ? rowHeight + getDetailHeight(dataIdx)
        : rowHeight;
    };

    // Calculate cumulative height up to (not including) virtualIdx
    const calculateHeightUpTo = (virtualIdx) => {
      let height = virtualIdx * rowHeight;

      for (const expandedDataIdx of state.expandedRows) {
        const expandedVirtualIdx = getVirtualIndex(expandedDataIdx);
        if (expandedVirtualIdx >= 0 && expandedVirtualIdx < virtualIdx) {
          height += getDetailHeight(expandedDataIdx);
        }
      }

      return height;
    };

    // Get total scrollable height
    const getTotalHeight = () => {
      const rowCount = getVisibleRowCount();
      let height = rowCount * rowHeight;

      for (const expandedDataIdx of state.expandedRows) {
        const expandedVirtualIdx = getVirtualIndex(expandedDataIdx);
        if (expandedVirtualIdx >= 0 && expandedVirtualIdx < rowCount) {
          height += getDetailHeight(expandedDataIdx);
        }
      }

      return height;
    };

    // Find virtual row index at a given scroll position
    const findRowAtScrollPosition = (scrollTop) => {
      let accumulatedHeight = 0;
      const rowCount = getVisibleRowCount();

      for (let virtualIdx = 0; virtualIdx < rowCount; virtualIdx++) {
        const dataIdx = getDataIndex(virtualIdx);
        const rh = getRowHeight(dataIdx);

        if (accumulatedHeight + rh > scrollTop) {
          return virtualIdx;
        }
        accumulatedHeight += rh;
      }

      return Math.max(0, rowCount - 1);
    };

    // ═══════════════════════════════════════════════════════════════════════
    // CREATE ROW ELEMENTS
    // ═══════════════════════════════════════════════════════════════════════
    const createRowElements = (dataIdx, virtualIdx) => {
      const row = limitedDataRows[dataIdx];
      const tr = document.createElement('tr');
      tr.dataset.idx = dataIdx;
      tr.dataset.vidx = virtualIdx;

      const isExpanded = state.expandedRows.has(dataIdx);

      // Row number with expand icon
      const tdNum = document.createElement('td');
      tdNum.className = 'xlsx-row-header';
      tdNum.innerHTML = `<span class="csv-expand-icon">${isExpanded ? '▼' : '▶'}</span> ${dataIdx + 1}`;
      tr.appendChild(tdNum);

      // Data cells with truncation
      row.forEach((cell, ci) => {
        const td = document.createElement('td');
        td.className = 'xlsx-cell csv-cell-truncate';

        if (colWidths[ci]) {
          td.style.setProperty('--csv-col-width', colWidths[ci] + 'px');
        }

        const displayText = cell.length > 80 ? cell.substring(0, 80) + '…' : cell;
        td.textContent = displayText;
        td.title = cell.length > 80 ? 'Click row to see full content' : cell;

        if (cell.trim() && !isNaN(parseFloat(cell))) {
          td.style.textAlign = 'right';
        }

        tr.appendChild(td);
      });

      // Mark as selected if expanded
      if (isExpanded) {
        tr.classList.add('csv-row-selected');
      }

      // Re-apply any active highlight classes on this fresh <tr>. Without
      // this the highlight would be wiped the moment any re-render occurred
      // after scrollToRow() set it on a <tr> — that was the original "flash
      // disappears immediately" bug. Three mutually-exclusive groups:
      const now = performance.now();
      if (state.flashHighlight && state.flashHighlight.dataIdx === dataIdx &&
          now < state.flashHighlight.clearAt) {
        tr.classList.add('csv-row-highlight');
      }
      if (state.iocHighlight && state.iocHighlight.dataIdx === dataIdx &&
          now < state.iocHighlight.clearAt) {
        tr.classList.add('csv-ioc-row-highlight');
      }
      if (state.yaraHighlight && state.yaraHighlight.matchesByDataIdx.has(dataIdx) &&
          now < state.yaraHighlight.clearAt) {
        tr.classList.add('csv-yara-row-highlight');
      }

      // Detail row
      const detailTr = document.createElement('tr');
      detailTr.className = 'csv-detail-row';
      detailTr.dataset.idx = dataIdx;  // For height measurement
      detailTr.style.display = isExpanded ? '' : 'none';
      const detailTd = document.createElement('td');
      detailTd.colSpan = headerRow.length + 1;

      // Sticky wrapper: keeps the detail pane pinned to the left edge of the
      // scroll viewport and sized to the visible width (not the table's full
      // max-content width), so long values word-wrap to the user's viewport
      // rather than forcing horizontal scroll. Width is applied inline from
      // scr.clientWidth so it's authoritative (CSS-variable fallbacks would
      // silently resolve against the td's content-box width, i.e. the full
      // table width, for wide CSVs — that's why wrapping previously failed).
      const detailSticky = document.createElement('div');
      detailSticky.className = 'csv-detail-sticky';
      const stickyW = scr.clientWidth;
      if (stickyW > 0) {
        detailSticky.style.width = stickyW + 'px';
        detailSticky.style.maxWidth = stickyW + 'px';
      }

      // Use cached detail pane or build new one if expanded
      if (isExpanded) {
        if (!state.detailPaneCache.has(dataIdx)) {
          const pane = this._buildDetailPaneElement(headerRow, row);
          state.detailPaneCache.set(dataIdx, pane);
        }
        const clone = state.detailPaneCache.get(dataIdx).cloneNode(true);
        // Apply navigation marks to the clone before inserting. IOC and
        // YARA are mutually exclusive in practice (sidebar clears one
        // before setting the other); if both are somehow active we prefer
        // IOC — wrapping is destructive to textContent.
        if (state.iocHighlight && state.iocHighlight.dataIdx === dataIdx &&
            now < state.iocHighlight.clearAt) {
          _wrapIocMarkInPane(clone, state.iocHighlight.term);
        } else if (state.yaraHighlight && state.yaraHighlight.matchesByDataIdx.has(dataIdx) &&
            now < state.yaraHighlight.clearAt) {
          _wrapYaraMarksInPane(clone,
            state.yaraHighlight.matchesByDataIdx.get(dataIdx),
            state.yaraHighlight.sourceText);
        }
        detailSticky.appendChild(clone);
      }
      detailTd.appendChild(detailSticky);
      detailTr.appendChild(detailTd);

      // Click handler
      tr.addEventListener('click', () => {
        if (state.expandedRows.has(dataIdx)) {
          // Collapse this row
          state.expandedRows.delete(dataIdx);
          tr.classList.remove('csv-row-selected');
          const icon = tr.querySelector('.csv-expand-icon');
          if (icon) icon.textContent = '▶';
          detailTr.style.display = 'none';

          // Force re-render to update spacer heights
          state.renderedRange = { start: -1, end: -1 };
          renderVisibleRows();
        } else {
          // Collapse any other expanded row first (only one expanded at a time)
          state.expandedRows.clear();

          // Expand this row
          state.expandedRows.add(dataIdx);
          tr.classList.add('csv-row-selected');
          const icon = tr.querySelector('.csv-expand-icon');
          if (icon) icon.textContent = '▼';

          // Build detail pane if not cached
          if (!state.detailPaneCache.has(dataIdx)) {
            const pane = this._buildDetailPaneElement(headerRow, row);
            state.detailPaneCache.set(dataIdx, pane);
          }
          // Rebuild sticky wrapper + pane (detailTd was originally populated
          // with an empty sticky div; replace its contents wholesale).
          detailTd.innerHTML = '';
          const sticky = document.createElement('div');
          sticky.className = 'csv-detail-sticky';
          const sW = scr.clientWidth;
          if (sW > 0) {
            sticky.style.width = sW + 'px';
            sticky.style.maxWidth = sW + 'px';
          }
          const clickClone = state.detailPaneCache.get(dataIdx).cloneNode(true);
          // Same mark re-application contract as the initial render branch.
          const nowClick = performance.now();
          if (state.iocHighlight && state.iocHighlight.dataIdx === dataIdx &&
              nowClick < state.iocHighlight.clearAt) {
            _wrapIocMarkInPane(clickClone, state.iocHighlight.term);
          } else if (state.yaraHighlight && state.yaraHighlight.matchesByDataIdx.has(dataIdx) &&
              nowClick < state.yaraHighlight.clearAt) {
            _wrapYaraMarksInPane(clickClone,
              state.yaraHighlight.matchesByDataIdx.get(dataIdx),
              state.yaraHighlight.sourceText);
          }
          sticky.appendChild(clickClone);
          detailTd.appendChild(sticky);
          detailTr.style.display = '';

          // Scroll to the left to show the detail pane
          scr.scrollLeft = 0;

          // Force re-render to update DOM structure
          state.renderedRange = { start: -1, end: -1 };
          renderVisibleRows();
        }
      });

      return { tr, detailTr, detailTd, dataIdx };
    };

    // ═══════════════════════════════════════════════════════════════════════
    // CREATE SPACER ROW (for virtual scrolling)
    // ═══════════════════════════════════════════════════════════════════════
    const createSpacerRow = (height) => {
      const tr = document.createElement('tr');
      tr.className = 'csv-spacer-row';
      tr.setAttribute('aria-hidden', 'true');
      const td = document.createElement('td');
      td.colSpan = headerRow.length + 1;
      td.style.cssText = `height:${height}px;padding:0;border:none;background:transparent;`;
      tr.appendChild(td);
      return tr;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // RENDER VISIBLE ROWS (Virtual Scrolling Core)
    // ═══════════════════════════════════════════════════════════════════════
    const renderVisibleRows = () => {
      const scrollTop = scr.scrollTop;
      const viewportHeight = scr.clientHeight || 600;

      // Keep the CSS custom property in sync for any legacy consumers, but
      // each newly-created sticky wrapper also gets an authoritative inline
      // width from scr.clientWidth — that's the real source of truth.
      const viewportWidth = scr.clientWidth;
      if (viewportWidth > 0) {
        wrap.style.setProperty('--csv-detail-width', viewportWidth + 'px');
      }

      const rowCount = getVisibleRowCount();
      if (rowCount === 0) {
        tbody.replaceChildren();
        state.renderedRange = { start: 0, end: 0 };
        return;
      }

      // Find visible range using dynamic height calculations
      const firstVisibleRow = findRowAtScrollPosition(scrollTop);
      const startIdx = Math.max(0, firstVisibleRow - BUFFER_ROWS);

      const lastVisibleRow = findRowAtScrollPosition(scrollTop + viewportHeight);
      const endIdx = Math.min(rowCount, lastVisibleRow + BUFFER_ROWS + 1);

      // Fast path: if range hasn't changed, nothing to do
      if (startIdx === state.renderedRange.start && endIdx === state.renderedRange.end) {
        return;
      }

      // Auto-collapse rows that are FAR outside the visible range (use 2x buffer)
      // This prevents premature collapse when scrolling small amounts
      const collapseBuffer = BUFFER_ROWS * 2;
      for (const expandedDataIdx of state.expandedRows) {
        const expandedVirtualIdx = getVirtualIndex(expandedDataIdx);
        if (expandedVirtualIdx < startIdx - collapseBuffer ||
          expandedVirtualIdx >= endIdx + collapseBuffer) {
          state.expandedRows.delete(expandedDataIdx);
        }
      }

      // Build new content in fragment
      const fragment = document.createDocumentFragment();

      // Top spacer with dynamic height
      const topSpacerHeight = calculateHeightUpTo(startIdx);
      if (topSpacerHeight > 0) {
        fragment.appendChild(createSpacerRow(topSpacerHeight));
      }

      // Render visible rows
      for (let virtualIdx = startIdx; virtualIdx < endIdx; virtualIdx++) {
        const dataIdx = getDataIndex(virtualIdx);
        if (dataIdx === undefined || dataIdx >= limitedDataRows.length) continue;

        const { tr, detailTr } = createRowElements(dataIdx, virtualIdx);
        fragment.appendChild(tr);
        fragment.appendChild(detailTr);
      }

      // Bottom spacer with dynamic height
      const totalHeight = getTotalHeight();
      const heightUpToEnd = calculateHeightUpTo(endIdx);
      const bottomSpacerHeight = Math.max(0, totalHeight - heightUpToEnd);
      if (bottomSpacerHeight > 0) {
        fragment.appendChild(createSpacerRow(bottomSpacerHeight));
      }

      // Atomic replacement - no intermediate empty state
      tbody.replaceChildren(fragment);
      state.renderedRange = { start: startIdx, end: endIdx };

      // Measure heights of expanded rows after render
      requestAnimationFrame(() => {
        let heightChanged = false;
        for (const expandedDataIdx of state.expandedRows) {
          if (!state.detailHeightCache.has(expandedDataIdx)) {
            const detailTr = tbody.querySelector(`tr.csv-detail-row[data-idx="${expandedDataIdx}"]`);
            if (detailTr && detailTr.offsetHeight > 0) {
              state.detailHeightCache.set(expandedDataIdx, detailTr.offsetHeight);
              heightChanged = true;
            }
          }
        }
        // Re-render if heights changed to fix spacers
        if (heightChanged) {
          state.renderedRange = { start: -1, end: -1 };
          renderVisibleRows();
        }
      });
    };

    // ═══════════════════════════════════════════════════════════════════════
    // SCROLL HANDLER (throttled with requestAnimationFrame)
    // ═══════════════════════════════════════════════════════════════════════
    let scrollRAF = null;
    let isProgrammaticScroll = false;  // Flag to disable scroll handler during programmatic scroll

    scr.addEventListener('scroll', () => {
      if (scrollRAF || isProgrammaticScroll) return;
      scrollRAF = requestAnimationFrame(() => {
        renderVisibleRows();
        scrollRAF = null;
      });
    });

    // ═══════════════════════════════════════════════════════════════════════
    // FILTER LOGIC
    // ═══════════════════════════════════════════════════════════════════════
    const applyFilter = () => {
      const query = filterInput.value.toLowerCase().trim();

      // Auto-collapse all expanded rows when filter changes
      state.expandedRows.clear();

      if (!query) {
        state.filteredIndices = null;
        clearBtn.style.display = 'none';
        filterStatus.textContent = '';
      } else {
        state.filteredIndices = [];
        for (let i = 0; i < limitedDataRows.length; i++) {
          if (rowSearchText[i].includes(query)) {
            state.filteredIndices.push(i);
          }
        }
        clearBtn.style.display = '';
        filterStatus.textContent = `${state.filteredIndices.length.toLocaleString()} of ${limitedDataRows.length.toLocaleString()} rows`;
      }

      // Reset scroll position and re-render
      scr.scrollTop = 0;
      state.renderedRange = { start: -1, end: -1 };
      renderVisibleRows();
    };

    const clearFilter = () => {
      filterInput.value = '';
      applyFilter();
    };

    // ═══════════════════════════════════════════════════════════════════════
    // SCROLL TO ROW (for IOC navigation)
    // ═══════════════════════════════════════════════════════════════════════
    // Wait for a programmatic smooth-scroll to actually finish. The previous
    // implementation used a hard-coded setTimeout(400) which raced with
    // long-distance smooth scrolls (scrollTop still changing) — the scroll
    // handler would re-enable mid-flight, scroll events would fire, the
    // tbody would rebuild, and the flash would vanish.
    //
    // Primary path: the native `scrollend` event (Chrome 114+, Firefox 109+,
    // Safari 17+). Fallback: poll scrollTop via rAF and resolve once it's
    // been stable for 2 consecutive frames. Safety cap: 1000 ms.
    const waitForScrollEnd = () => new Promise(resolve => {
      let settled = false;
      const done = () => { if (!settled) { settled = true; resolve(); } };

      if ('onscrollend' in scr) {
        scr.addEventListener('scrollend', done, { once: true });
        setTimeout(done, 1000);
        return;
      }

      // Polyfill for Safari <17 / older browsers.
      let last = scr.scrollTop;
      let stable = 0;
      const tick = () => {
        if (settled) return;
        if (scr.scrollTop === last) {
          if (++stable >= 2) return done();
        } else {
          stable = 0;
          last = scr.scrollTop;
        }
        requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
      setTimeout(done, 1000);
    });

    // Returns a Promise that resolves after the smooth scroll has ended AND
    // the subsequent re-render + RAF-driven height-remeasure re-render have
    // both completed. Callers that need to do post-scroll DOM work (e.g.
    // scroll a focus <mark> into view) should chain off the returned promise
    // rather than racing on a timer.
    const scrollToRow = (dataIdx, highlight = true) => new Promise(resolve => {
      // Check if row is filtered out
      let virtualIdx = getVirtualIndex(dataIdx);

      if (virtualIdx === -1 && state.filteredIndices) {
        // Row is filtered out - clear filter first
        filterInput.value = '';
        state.filteredIndices = null;
        clearBtn.style.display = 'none';
        filterStatus.textContent = '';
        virtualIdx = dataIdx;
      }

      // Collapse all rows first, then expand only the target row
      state.expandedRows.clear();
      state.expandedRows.add(dataIdx);

      // Calculate scroll position to center the row (using dynamic heights)
      const viewportHeight = scr.clientHeight || 600;
      const targetTop = calculateHeightUpTo(virtualIdx);
      const scrollTarget = Math.max(0, targetTop - viewportHeight / 2);

      // Disable scroll handler during programmatic scroll to prevent glitchy re-renders
      isProgrammaticScroll = true;

      // If the user asked for a cyan flash, install it in state BEFORE we
      // re-render so createRowElements picks it up on the fresh <tr>. Using
      // the flashHighlight group (rather than a raw class add post-render)
      // is what makes the flash survive the RAF-driven height-remeasure
      // re-render that occurs after the initial render. Cleanup timer is
      // owned by the group; subsequent scrollToRow calls supersede.
      if (highlight) {
        _clearFlashInternal();
        state.flashHighlight = {
          dataIdx,
          clearAt: performance.now() + 2000,
          timer: setTimeout(() => {
            // Clear iff still ours — a later scrollToRow may have taken over.
            if (state.flashHighlight && state.flashHighlight.dataIdx === dataIdx) {
              _clearFlashInternal();
              state.renderedRange = { start: -1, end: -1 };
              renderVisibleRows();
            }
          }, 2000)
        };
      }

      // Fast path: when the target is (effectively) already the current
      // scroll position, `scr.scrollTo({ behavior: 'smooth' })` does NOT
      // fire a `scrollend` event in Chrome or Firefox — the polyfill
      // then waits the full 1000 ms safety cap before resolving, which
      // manifests as a 1 s UI stall when clicking an IOC pointing at
      // the currently-visible row. Detect that case and skip the whole
      // scroll/wait dance. `isProgrammaticScroll` is still toggled around
      // the re-render as a safety belt in case renderVisibleRows' DOM
      // mutations incidentally fire scroll events.
      const startTop = scr.scrollTop;
      if (Math.abs(scrollTarget - startTop) < 1) {
        state.renderedRange = { start: -1, end: -1 };
        renderVisibleRows();
        requestAnimationFrame(() => requestAnimationFrame(() => {
          isProgrammaticScroll = false;
          resolve();
        }));
        return;
      }

      // Scroll with smooth animation
      scr.scrollTo({
        top: scrollTarget,
        left: 0,  // Scroll to the left to show detail pane
        behavior: 'smooth'
      });

      waitForScrollEnd().then(() => {
        isProgrammaticScroll = false;
        // Force full re-render at final position
        state.renderedRange = { start: -1, end: -1 };
        renderVisibleRows();
        // renderVisibleRows schedules an internal rAF to remeasure detail
        // heights; wait 2 rAFs so that remeasure + any resulting re-render
        // have definitely settled before we resolve. Callers that chain
        // post-scroll work (YARA scrollToYaraFocus) depend on this.
        requestAnimationFrame(() => requestAnimationFrame(resolve));
      });
    });

    // ═══════════════════════════════════════════════════════════════════════
    // EXPAND A SPECIFIC ROW (for external API)
    // ═══════════════════════════════════════════════════════════════════════
    const expandRow = (rowObj) => {
      const dataIdx = rowObj.dataIndex !== undefined ? rowObj.dataIndex : rowObj;
      // Collapse any other expanded row first
      state.expandedRows.clear();
      state.expandedRows.add(dataIdx);
      state.renderedRange = { start: -1, end: -1 };
      renderVisibleRows();
      // Scroll left to show detail pane
      scr.scrollLeft = 0;
    };

    // ═══════════════════════════════════════════════════════════════════════
    // EVENT LISTENERS
    // ═══════════════════════════════════════════════════════════════════════
    filterInput.addEventListener('input', applyFilter);
    filterInput.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        filterInput.blur();
      }
    });
    clearBtn.addEventListener('click', clearFilter);

    // ═══════════════════════════════════════════════════════════════════════
    // EXPOSE API FOR EXTERNAL ACCESS (IOC navigation, YARA highlighting)
    // ═══════════════════════════════════════════════════════════════════════
    // Build dataRows array for compatibility with existing IOC navigation code
    const dataRowsCompat = limitedDataRows.map((row, i) => ({
      rowData: row,
      searchText: rowSearchText[i],
      offsetStart: limitedOffsets[i] ? limitedOffsets[i].start : 0,
      offsetEnd: limitedOffsets[i] ? limitedOffsets[i].end : 0,
      dataIndex: i,
      // Legacy compatibility - these are now virtual, not real DOM refs
      tr: null,
      detailTr: null,
      detailTd: null,
      visible: true
    }));

    wrap._csvFilters = {
      filterInput,
      applyFilter,
      clearFilter,
      scrollToFirstMatch: () => {
        const rowCount = getVisibleRowCount();
        if (rowCount > 0) {
          const dataIdx = getDataIndex(0);
          scrollToRow(dataIdx);
        }
      },
      scrollContainer: scr,
      dataRows: dataRowsCompat,
      expandRow,
      scrollToRow,
      headerRow,
      buildDetailPane: (td, row) => {
        const pane = this._buildDetailPaneElement(headerRow, row);
        td.appendChild(pane);
      },
      // Expose state for advanced use cases
      state,
      getVisibleRowCount,
      getDataIndex,
      getVirtualIndex,
      forceRender: () => {
        state.renderedRange = { start: -1, end: -1 };
        renderVisibleRows();
      },

      // ── IOC click navigation ───────────────────────────────────────────
      // Renderer-owned IOC highlight: set state, scroll, let
      // createRowElements paint .csv-ioc-row-highlight + <mark> wrappings
      // on every subsequent re-render until clearMs elapses. Returns the
      // Promise from scrollToRow so callers can chain post-scroll work.
      //
      // `onExpire` (optional) is invoked synchronously when the internal
      // timer fires naturally AND this state group is still the active
      // one — it is NOT invoked on programmatic clears (clearIocHighlight)
      // or when a later setYaraHighlight / scrollToRowWithIocHighlight
      // supersedes this group. Callers use it to reset their own state
      // (e.g. sidebar's `ref._currentMatchIndex`) without needing a
      // parallel timer that could desync.
      scrollToRowWithIocHighlight: (dataIdx, term, clearMs = 5000, onExpire = null) => {
        _clearIocInternal();
        _clearYaraInternal();
        state.iocHighlight = {
          dataIdx, term,
          clearAt: performance.now() + clearMs,
          timer: setTimeout(() => {
            if (state.iocHighlight && state.iocHighlight.dataIdx === dataIdx) {
              _clearIocInternal();
              state.renderedRange = { start: -1, end: -1 };
              renderVisibleRows();
              if (typeof onExpire === 'function') {
                try { onExpire(); } catch (_) { /* callback errors must not break cleanup */ }
              }
            }
          }, clearMs)
        };
        return scrollToRow(dataIdx, false);
      },
      clearIocHighlight: () => {
        _clearIocInternal();
        state.renderedRange = { start: -1, end: -1 };
        renderVisibleRows();
      },

      // ── YARA match navigation ──────────────────────────────────────────
      // Renderer-owned YARA highlight. Caller (sidebar) supplies the full
      // per-row match map up front so every currently-rendered row gets
      // its marks. Note that this does NOT scroll — caller should follow
      // with scrollToRow(focusDataIdx).then(scrollToYaraFocus-if-needed).
      //
      // `onExpire` — see scrollToRowWithIocHighlight for semantics. Not
      // fired on clearYaraHighlight or supersession.
      setYaraHighlight: (matchesByDataIdx, focusDataIdx, focusMatchIdx, sourceText, clearMs = 5000, onExpire = null) => {
        _clearIocInternal();
        _clearYaraInternal();
        state.yaraHighlight = {
          matchesByDataIdx, focusDataIdx, focusMatchIdx, sourceText,
          clearAt: performance.now() + clearMs,
          timer: setTimeout(() => {
            if (state.yaraHighlight && state.yaraHighlight.focusDataIdx === focusDataIdx) {
              _clearYaraInternal();
              state.renderedRange = { start: -1, end: -1 };
              renderVisibleRows();
              if (typeof onExpire === 'function') {
                try { onExpire(); } catch (_) { /* callback errors must not break cleanup */ }
              }
            }
          }, clearMs)
        };
      },
      clearYaraHighlight: () => {
        _clearYaraInternal();
        state.renderedRange = { start: -1, end: -1 };
        renderVisibleRows();
      },
      // Scroll the focus <mark> into view. Intended to be called after
      // scrollToRow's Promise resolves (i.e. after the row's detail pane
      // has been rendered with the focus mark). Guarded with
      // isProgrammaticScroll so the subsequent smooth scroll doesn't fire
      // scroll-driven re-renders that would wipe the mark.
      scrollToYaraFocus: () => {
        const y = state.yaraHighlight;
        if (!y) return;
        const focusMark = tbody.querySelector(
          `mark.csv-yara-highlight[data-yara-match="${y.focusMatchIdx}"]`);
        if (!focusMark) return;
        isProgrammaticScroll = true;
        focusMark.scrollIntoView({ behavior: 'smooth', block: 'center' });
        waitForScrollEnd().then(() => { isProgrammaticScroll = false; });
      }
    };

    // Store raw CSV text for proper IOC extraction
    wrap._rawText = text;

    // ═══════════════════════════════════════════════════════════════════════
    // DETAIL PANE WIDTH SYNC
    // Detail pane sits inside a sticky wrapper pinned to the scroll
    // container's left edge. Its width is driven by --csv-detail-width so
    // long values word-wrap to the viewport rather than the (potentially
    // much wider) table's max-content width.
    // ═══════════════════════════════════════════════════════════════════════
    const updateDetailStickyWidth = () => {
      const w = scr.clientWidth;
      if (w > 0) {
        wrap.style.setProperty('--csv-detail-width', w + 'px');
      }
    };
    updateDetailStickyWidth();

    // ═══════════════════════════════════════════════════════════════════════
    // INITIAL RENDER
    // ═══════════════════════════════════════════════════════════════════════
    renderVisibleRows();

    // Re-render when scroll container gets its actual dimensions after DOM
    // insertion, on window resize, and on sidebar show/hide/resize (the
    // sidebar is a flex sibling of #viewer, so any sidebar width change
    // reflows #viewer and fires this observer on .csv-scroll).
    const resizeObs = new ResizeObserver(() => {
      // Measure actual row height from a rendered data row
      const sampleRow = tbody.querySelector('tr[data-idx]');
      if (sampleRow && sampleRow.offsetHeight > 0) {
        rowHeight = sampleRow.offsetHeight;
      }
      // Keep the sticky detail pane matched to the new viewport width, and
      // invalidate cached detail heights because wrap-width changes may
      // change the rendered height of word-wrapped content.
      const prevWidth = parseFloat(wrap.style.getPropertyValue('--csv-detail-width')) || 0;
      updateDetailStickyWidth();
      const newWidth = parseFloat(wrap.style.getPropertyValue('--csv-detail-width')) || 0;
      if (Math.abs(newWidth - prevWidth) > 1) {
        state.detailHeightCache.clear();
      }
      state.renderedRange = { start: -1, end: -1 };
      renderVisibleRows();
    });
    resizeObs.observe(scr);

    return wrap;
  }

  // ════════════════════════════════════════════════════════════════════════
  // Calculate reasonable column widths based on content
  // ════════════════════════════════════════════════════════════════════════
  _calcColumnWidths(rows, maxSampleRows = 100) {
    if (!rows.length) return [];
    const colCount = rows[0].length;
    const widths = [];

    for (let col = 0; col < colCount; col++) {
      const samples = [];

      // Sample header + up to maxSampleRows data rows
      for (let row = 0; row < Math.min(rows.length, maxSampleRows + 1); row++) {
        const cell = rows[row]?.[col] || '';
        samples.push(cell.length);
      }

      // Sort and use 85th percentile length (avoids outlier-driven widths)
      samples.sort((a, b) => a - b);
      const p85Idx = Math.floor(samples.length * 0.85);
      const typicalLen = samples[p85Idx] || samples[samples.length - 1] || 10;

      // Convert to pixels: ~7.5px per char in monospace
      // Min 60px (very short columns), max 300px (prevents super-wide columns)
      const width = Math.min(300, Math.max(60, Math.ceil(typicalLen * 7.5)));
      widths.push(width);
    }

    return widths;
  }

  // ════════════════════════════════════════════════════════════════════════
  // Build detail pane element (only shows non-empty columns)
  // ════════════════════════════════════════════════════════════════════════
  _buildDetailPaneElement(headerRow, rowData) {
    const pane = document.createElement('div');
    pane.className = 'csv-detail-pane';

    const heading = document.createElement('h4');
    heading.textContent = 'Row Details';
    pane.appendChild(heading);

    const grid = document.createElement('div');
    grid.className = 'csv-detail-grid';

    let hasContent = false;

    // Display each column as key-value pair (only if value is non-empty)
    for (let i = 0; i < headerRow.length; i++) {
      const key = headerRow[i] || `Column ${i + 1}`;
      const val = rowData[i] || '';

      // Skip columns with empty values
      if (!val.trim()) continue;

      hasContent = true;

      const keyEl = document.createElement('div');
      keyEl.className = 'csv-detail-key';
      keyEl.textContent = key;
      keyEl.title = key;
      grid.appendChild(keyEl);

      const valEl = document.createElement('div');
      valEl.className = 'csv-detail-val';
      valEl.textContent = val;
      grid.appendChild(valEl);
    }

    // Show message if all columns are empty
    if (!hasContent) {
      const empty = document.createElement('p');
      empty.style.cssText = 'color:#888;font-style:italic;margin:0;';
      empty.textContent = 'All columns are empty for this row.';
      grid.appendChild(empty);
    }

    pane.appendChild(grid);
    return pane;
  }

  // Legacy method for compatibility
  _buildDetailPane(container, headerRow, rowData) {
    const pane = this._buildDetailPaneElement(headerRow, rowData);
    container.appendChild(pane);
  }

  // ════════════════════════════════════════════════════════════════════════
  // Auto-detect delimiter by counting occurrences in the first line
  // ════════════════════════════════════════════════════════════════════════
  _delim(text) {
    // Slice first line via indexOf to avoid splitting the whole buffer.
    let nl = text.indexOf('\n');
    if (nl === -1) nl = text.length;
    const line = text.substring(0, nl);
    const c = { ',': 0, ';': 0, '\t': 0, '|': 0 };
    let inQ = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        inQ = !inQ;
      } else if (!inQ && c[ch] !== undefined) {
        c[ch]++;
      }
    }
    return Object.entries(c).sort((a, b) => b[1] - a[1])[0][0];
  }

  // ════════════════════════════════════════════════════════════════════════
  // Parse CSV text into rows with offset tracking
  //
  // Fast path: lines without any '"' use native String.prototype.split,
  // which is dramatically faster than the per-character state machine.
  // Lines that contain '"' fall through to _splitQuoted for correctness.
  // ════════════════════════════════════════════════════════════════════════
  _parse(text, delim) {
    const rows = [];
    const rowOffsets = [];
    const len = text.length;
    let offset = 0;

    while (offset < len) {
      // Locate next LF with native indexOf (native C++ in V8).
      let lineEnd = text.indexOf('\n', offset);
      if (lineEnd === -1) lineEnd = len;

      // Handle CRLF by trimming a trailing \r from the content range.
      let contentEnd = lineEnd;
      if (contentEnd > offset && text.charCodeAt(contentEnd - 1) === 13) {
        contentEnd--;
      }

      if (contentEnd > offset) {
        const line = text.substring(offset, contentEnd);
        // Fast path: no quotes anywhere in the line → native split.
        const cells = line.indexOf('"') === -1
          ? line.split(delim)
          : this._splitQuoted(line, delim);
        rows.push(cells);
        rowOffsets.push({ start: offset, end: contentEnd });
      }

      offset = lineEnd + 1;
    }

    return { rows, rowOffsets };
  }

  // ════════════════════════════════════════════════════════════════════════
  // Split a CSV line into cells (RFC 4180 quoted handling).
  // Only used for lines that actually contain '"' — the common
  // quote-free case is handled in _parse via native String.split.
  // ════════════════════════════════════════════════════════════════════════
  _splitQuoted(line, delim) {
    const cells = [];
    let cur = '';
    let inQ = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQ && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQ = !inQ;
        }
      } else if (ch === delim && !inQ) {
        cells.push(cur);
        cur = '';
      } else {
        cur += ch;
      }
    }
    cells.push(cur);
    return cells;
  }

  // ════════════════════════════════════════════════════════════════════════
  // Security analysis — formula-injection (CWE-1236) detection.
  // A bare leading =/+/-/@ is the baseline indicator (medium). When the
  // formula also references a known dangerous function — DDE (`cmd|/C`,
  // `powershell`), MSEXCEL/MSExcel DDE channels, or an external
  // HYPERLINK/WEBSERVICE pointing outside the workbook — we escalate to
  // critical, because the cell is actively weaponised, not just suspicious.
  // ════════════════════════════════════════════════════════════════════════
  analyzeForSecurity(text) {
    const f = { risk: 'low', hasMacros: false, macroSize: 0, macroHash: '', autoExec: [], modules: [], externalRefs: [], metadata: {} };
    const lines = text.split('\n').slice(0, 5000);
    let anyFormula = false;
    let dangerHit = null;  // { line, snippet, kind }
    const DANGER_RE = /(cmd(?:\.exe)?\s*[|/]|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|\bDDE(?:AUTO)?\b|MSEXCEL\|['"]|MSExcel\|['"]|=\s*HYPERLINK\s*\(|=\s*WEBSERVICE\s*\(|=\s*IMPORTXML\s*\(|=\s*IMPORTDATA\s*\(|=\s*IMPORTHTML\s*\()/i;

    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      const t = l.trim();
      if (!t) continue;
      // Match leading =/+/-/@ in any cell (first-cell heuristic is close enough
      // at this tier — the column splitter lives in _split).
      if (/^["']?[=+\-@]/.test(t) || /[,;\t|]["']?[=+\-@]/.test(l)) {
        anyFormula = true;
        if (!dangerHit) {
          const m = l.match(DANGER_RE);
          if (m) {
            const idx = m.index || 0;
            dangerHit = {
              line: i + 1,
              snippet: l.substring(Math.max(0, idx - 8), Math.min(l.length, idx + 80)).trim(),
            };
          }
        }
      }
    }

    if (dangerHit) {
      f.risk = 'critical';
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `Weaponised formula-injection payload (CWE-1236) on line ${dangerHit.line} — references command execution, DDE, or external data function: "${dangerHit.snippet}"`,
        severity: 'critical',
      });
    } else if (anyFormula) {
      f.risk = 'medium';
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'Formula injection risk (CWE-1236) — cells beginning with =, +, -, or @ detected. Opened in a spreadsheet these may execute if the user accepts the formula prompt.',
        severity: 'medium',
      });
    }
    return f;
  }
}

