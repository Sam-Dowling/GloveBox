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
      renderedRange: { start: -1, end: -1 }
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

      // Detail row
      const detailTr = document.createElement('tr');
      detailTr.className = 'csv-detail-row';
      detailTr.dataset.idx = dataIdx;  // For height measurement
      detailTr.style.display = isExpanded ? '' : 'none';
      const detailTd = document.createElement('td');
      detailTd.colSpan = headerRow.length + 1;

      // Use cached detail pane or build new one if expanded
      if (isExpanded) {
        if (!state.detailPaneCache.has(dataIdx)) {
          const pane = this._buildDetailPaneElement(headerRow, row);
          state.detailPaneCache.set(dataIdx, pane);
        }
        detailTd.appendChild(state.detailPaneCache.get(dataIdx).cloneNode(true));
      }
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
          detailTd.innerHTML = '';
          detailTd.appendChild(state.detailPaneCache.get(dataIdx).cloneNode(true));
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
    const scrollToRow = (dataIdx, highlight = true) => {
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

      // Scroll with smooth animation
      scr.scrollTo({
        top: scrollTarget,
        left: 0,  // Scroll to the left to show detail pane
        behavior: 'smooth'
      });

      // Wait for scroll animation to complete, then re-render and highlight
      setTimeout(() => {
        // Re-enable scroll handler
        isProgrammaticScroll = false;

        // Force full re-render at final position
        state.renderedRange = { start: -1, end: -1 };
        renderVisibleRows();

        // Find and highlight the row
        if (highlight) {
          const tr = tbody.querySelector(`tr[data-idx="${dataIdx}"]`);
          if (tr) {
            tr.classList.add('csv-row-highlight');
            // Also apply highlight to cells for better visibility
            const cells = tr.querySelectorAll('td');
            cells.forEach(cell => {
              cell.style.transition = 'background 0.3s ease-out';
              cell.style.background = 'rgba(34, 211, 238, 0.4)';
            });
            setTimeout(() => {
              tr.classList.remove('csv-row-highlight');
              cells.forEach(cell => {
                cell.style.background = '';
              });
            }, 2000);
            setTimeout(() => {
              cells.forEach(cell => {
                cell.style.transition = '';
              });
            }, 2500);
          }
        }
      }, 400);  // Slightly longer timeout to ensure smooth scroll completes
    };

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
      }
    };

    // Store raw CSV text for proper IOC extraction
    wrap._rawText = text;

    // ═══════════════════════════════════════════════════════════════════════
    // INITIAL RENDER
    // ═══════════════════════════════════════════════════════════════════════
    renderVisibleRows();

    // Re-render when scroll container gets its actual dimensions after DOM insertion
    const resizeObs = new ResizeObserver(() => {
      // Measure actual row height from a rendered data row
      const sampleRow = tbody.querySelector('tr[data-idx]');
      if (sampleRow && sampleRow.offsetHeight > 0) {
        rowHeight = sampleRow.offsetHeight;
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
    const line = (text.split('\n')[0] || '');
    const c = { ',': 0, ';': 0, '\t': 0, '|': 0 };
    let inQ = false;
    for (const ch of line) {
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
  // ════════════════════════════════════════════════════════════════════════
  _parse(text, delim) {
    const rows = [];
    const rowOffsets = [];
    let offset = 0;
    let lineStart = 0;

    while (offset <= text.length) {
      let lineEnd = offset;
      while (lineEnd < text.length && text[lineEnd] !== '\r' && text[lineEnd] !== '\n') {
        lineEnd++;
      }

      const line = text.substring(lineStart, lineEnd);

      if (line.trim()) {
        rows.push(this._split(line, delim));
        rowOffsets.push({ start: lineStart, end: lineEnd });
      }

      if (lineEnd < text.length) {
        if (text[lineEnd] === '\r' && text[lineEnd + 1] === '\n') {
          offset = lineEnd + 2;
        } else {
          offset = lineEnd + 1;
        }
        lineStart = offset;
      } else {
        break;
      }
    }

    return { rows, rowOffsets };
  }

  // ════════════════════════════════════════════════════════════════════════
  // Split a CSV line into cells
  // ════════════════════════════════════════════════════════════════════════
  _split(line, delim) {
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

