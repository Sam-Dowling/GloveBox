'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-filter.js — TimelineView prototype mixin (B2c).
//
// Hosts the filter + chart-data pipeline: timestamp parsing, query
// AST application, the full-recompute filter loop, sus / detection
// bitmap rebuilds, the window-only fast path, the column-stats
// (sync + cooperative-async) loops, distinct-values lookup, the
// "ignore one column" index helper used by the column-menu IN/NOT IN
// picker, the bucket-size resolver, and `_computeChartData` (the
// histogram bucketer that drives every chart paint).
//
// Methods (14 instance, ms-budget hot paths):
//   _parseAllTimestamps, _computeDataRange,
//   _applyQueryString, _recomputeFilter, _susMarksResolved,
//   _rebuildSusBitmap, _rebuildDetectionBitmap, _applyWindowOnly,
//   _computeColumnStatsSync, _computeColumnStatsAsync,
//   _distinctValuesFor, _indexIgnoringColumn,
//   _bucketMs, _computeChartData
//
// Bodies are moved byte-identically from `timeline-view.js`. The hot
// loops (`for (let i = 0; i < t.length; i++)` in `_computeChartData`,
// the per-row `_cellAt` walks in `_computeColumnStatsSync`/`Async`)
// are perf-critical — any reformat here would silently regress chart
// paint or filter latency.
//
// Loads AFTER timeline-view.js (which declares `class TimelineView`).
// ════════════════════════════════════════════════════════════════════════════

Object.assign(TimelineView.prototype, {

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
    const store = this.store;
    const out = this._timeMs;
    if (col == null) {
      out.fill(NaN);
      this._timeIsNumeric = false;
      return;
    }
    const total = store ? store.rowCount : 0;
    // Decide numeric vs. timestamp for THIS column. Extracted columns are
    // skipped for the numeric path — base-only sampling — so they always
    // go through `_tlParseTimestamp`.
    const numeric = (col < this._baseColumns.length)
      && _tlColumnIsNumericAxis(store, col);
    this._timeIsNumeric = numeric;
    if (numeric) {
      for (let i = 0; i < total; i++) {
        const c = store.getCell(i, col);
        if (c === '') { out[i] = NaN; continue; }
        const n = Number(c.trim());
        out[i] = Number.isFinite(n) ? n : NaN;
      }
    } else {
      // Detect the dominant timestamp format from a small sample and use
      // the specialised fast-path parser that skips the full regex
      // waterfall. Falls back to `_tlParseTimestamp` for outlier cells.
      // Extracted (virtual) columns resolve via `_cellAt` since their
      // values live in `_extractedCols`, not the RowStore.
      const isExtracted = col >= this._baseColumns.length;
      const fmt = isExtracted ? 'generic' : _tlDetectTimestampFormat(store, col, 30);
      if (fmt === 'generic') {
        for (let i = 0; i < total; i++) {
          const v = isExtracted ? this._cellAt(i, col) : store.getCell(i, col);
          out[i] = (v === '' || v == null) ? NaN : _tlParseTimestamp(v);
        }
      } else {
        for (let i = 0; i < total; i++) {
          const v = store.getCell(i, col);
          out[i] = v === '' ? NaN : _tlParseTimestampFast(v, fmt);
        }
      }
    }
  },

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
  },

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
        const tot = this.store.rowCount;
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
  },

  _recomputeFilter() {
    // Query bar is now the single source of truth for row filtering —
    // every click-pivot (right-click Include / Exclude / Only, column
    // card click, column-menu Apply, pivot drill-down, detection drill,
    // legend click) mutates `this._queryStr` via the AST-edit helpers
    // below rather than pushing onto a separate chip list. Sus marks
    // (`this._susMarks`, persisted by colName) are orthogonal — they
    // tint matching rows red but never filter them out.
    const n = this.store.rowCount;
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
  },

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
  },

  // (Re)build the `_susBitmap` eagerly from the current `_susMarks`.
  // Called once at construction, and again whenever sus marks are
  // added / removed / cleared. The bitmap must exist BEFORE the query
  // compiler runs so that `is:sus` can reference it.
  _rebuildSusBitmap() {
    const n = this.store.rowCount;
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
  },

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
    const n = this.store.rowCount;
    const bm = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      if (eids.has(this._cellAt(i, eventIdCol))) bm[i] = 1;
    }
    this._detectionBitmap = bm;
  },

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
  },

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
  },

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
          // In-loop staleness check. The post-yield check below catches
          // stale generations between 50k-row chunks, but a single chunk
          // on a wide grid (30 cols × 50k rows = 1.5M _cellAt calls) is
          // already a multi-hundred-millisecond slab of work that we
          // throw away. Sampling the generation every 4096 rows lets a
          // newer scheduled computation supersede this one mid-chunk —
          // critical during the auto-extract apply pump where columns
          // are appended in rapid succession.
          if ((i & 4095) === 0
              && (self._colStatsGen !== generation || self._destroyed)) {
            return null;
          }
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
  },

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
  },

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
    const n = this.store.rowCount;
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
  },

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
  },

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
  },

});
