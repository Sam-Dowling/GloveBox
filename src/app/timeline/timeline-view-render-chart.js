'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-render-chart.js — TimelineView prototype mixin (B2f1).
//
// Hosts the entire chart paint stack — every method that draws on
// the histogram canvas, paints the scrubber, manages the red-line
// "you are here" cursor, runs the rubber-band drag selection, or
// services the stack legend.
//
// Methods (19 instance, hot paths):
//
//   Scrubber (top-of-chart "minimap"):
//     _renderScrubber, _installScrubberDrag, _paintScrubberCursor
//
//   Chart paint:
//     _renderChart, _buildStableStackColorMap, _renderChartInto
//
//   Red-line cursor (current row indicator):
//     _paintChartCursorFor,
//     _findNearestDataIdxForTime,
//     _scrollGridToCursorIdx,
//     _installCursorDrag,
//     _updateCursorFromGridScroll,
//     _setCursorDataIdx
//
//   Chart pointer / wheel handlers:
//     _onChartClick, _installChartDrag (rubber-band selection),
//     _onChartHover (tooltip)
//
//   Legend:
//     _handleLegendClick, _handleLegendDbl, _handleLegendContext
//
//   Resize:
//     _installChartResizeDrag — chart-only height grab-bar; mirrors
//     `_installSplitterDrag` (the global chart/grid splitter, which
//     STAYS in core because it crosses chart and grid).
//
// Bodies are moved byte-identically. The chart paint hot loops
// (`_renderChartInto`'s per-bucket `ctx.fillRect` walk, the
// `requestAnimationFrame`-driven scrubber repaint, the
// pointer-capture rubber-band) are perf-critical — pinned by parity
// test below.
//
// Methods kept in core `timeline-view.js` (NOT moved):
//   • The "Chart" section header at line ~1434 was a 9-line stub
//     (`_renderChart` lives in the section labelled "Stable
//     stack-color assignment" because it dispatches into
//     `_renderChartInto`). The whole sequence Scrubber → Chart →
//     stack-color → cursor → drag → rubber-band moves as one
//     contiguous block.
//   • `_renderScheduler` (rAF-coalesced per-section dispatch) —
//     stays in core, calls into BOTH chart and grid mixins.
//   • `_installSplitterDrag` (chart vs. grid divider) — stays in
//     core for the same reason.
//
// Loads AFTER timeline-view.js (which declares `class TimelineView`).
// ════════════════════════════════════════════════════════════════════════════

Object.assign(TimelineView.prototype, {

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
  },

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
          // Live-update the inline datetime widget so the analyst can
          // read the pending [from → to · duration] while dragging.
          // O(1) text update — cheaper than a full 'chips' task (which
          // would also repaint the sus chips strip unnecessarily). The
          // `preview:true` flag adds a `--preview` modifier so the
          // button visually reads "not committed yet".
          if (this._queryEditor) {
            this._queryEditor.setWindow({ min: this._window.min, max: this._window.max, preview: true });
          }
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
  },

  // ── Chart ────────────────────────────────────────────────────────────────
  _renderChart() {
    this._lastChartData = this._renderChartInto(
      this._els.chartCanvas, this._els.chartLegend, this._els.chartEmpty,
      this._filteredIdx, 'main',
    );

  },

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
    for (let i = 0; i < this.store.rowCount; i++) {
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
  },

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
  },

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
  },


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
  },

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
  },

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
  },

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
  },

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
      // `di` here is the grid's `dataIdx` — i.e. the index passed to
      // `TimelineRowView.getCell(dataIdx, …)`. Because we feed the
      // adapter `idx === this._filteredIdx` (or `_susFilteredIdx` for
      // the suspicious sub-grid), `dataIdx` is _not_ the original row
      // — it's the position inside that filtered/sorted index. Map it
      // back via the same array to recover the original data row.
      const role = viewer._tlRole;
      const srcArr = (role === 'main') ? this._filteredIdx : this._susFilteredIdx;
      const orig = srcArr ? srcArr[di] : di;
      const t = this._timeMs[orig];
      if (!Number.isFinite(t)) continue;
      const dist = Math.abs(v - midV);
      if (dist < bestDist) { bestDist = dist; bestDataIdx = orig; }
    }
    if (bestDataIdx != null) this._setCursorDataIdx(bestDataIdx);
  },

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
  },

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
  },

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
        // One exception: we DO live-update the inline datetime widget
        // (in the query bar) so the analyst can read the pending
        // [from → to · duration] while still dragging. This is a pure
        // text update (O(1)) — no render pass — so it stays in the
        // same budget as the overlay rect it mirrors.
        const previewLo = xToMs(aClamped);
        const previewHi = xToMs(bClamped);
        if (Number.isFinite(previewLo) && Number.isFinite(previewHi) && previewHi > previewLo
            && this._queryEditor) {
          this._queryEditor.setWindow({ min: previewLo, max: previewHi, preview: true });
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
  },

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
  },

  _handleLegendClick(e) {
    const chip = e.target.closest('.tl-legend-chip');
    if (!chip || this._stackCol == null) return;
    const key = chip.dataset.key;
    const op = e.shiftKey ? 'ne' : 'eq';
    this._addOrToggleChip(this._stackCol, key, { op });
  },
  _handleLegendDbl(e) {
    const chip = e.target.closest('.tl-legend-chip');
    if (!chip || this._stackCol == null) return;
    const key = chip.dataset.key;
    // "Only this" → replace all chips on this column with a single eq.
    this._addOrToggleChip(this._stackCol, key, { op: 'eq', replace: true });
  },
  _handleLegendContext(e) {
    const chip = e.target.closest('.tl-legend-chip');
    if (!chip || this._stackCol == null) return;
    e.preventDefault();
    const key = chip.dataset.key;
    this._openRowContextMenu(e, this._stackCol, key);
  },
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
  },

});
