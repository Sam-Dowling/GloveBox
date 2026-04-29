'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-drawer.js — TimelineView prototype mixin.
//
// Split out of the legacy app-timeline.js monolith. JSON
// drawer leaf-path collector + extracted-column helpers (JSON-leaf
// flatten, regex extract dedup + persistence, column add/remove).
//
// Loads AFTER timeline-view.js (which declares `class TimelineView`).
// Analysis-bypass guard applies — these helpers operate purely on
// already-parsed row data and emit no IOCs.
// ════════════════════════════════════════════════════════════════════════════

Object.assign(TimelineView.prototype, {

  _jsonCollectLeafPaths(value, path, cb, maxDepth) {
    if (path.length >= maxDepth) return;
    if (value == null) return;
    if (typeof value === 'object') {
      if (Array.isArray(value)) {
        // Treat all array entries as the same path (use [*]).
        for (let i = 0; i < Math.min(value.length, 5); i++) {
          this._jsonCollectLeafPaths(value[i], path.concat('[*]'), cb, maxDepth);
        }
      } else {
        for (const k of Object.keys(value)) {
          this._jsonCollectLeafPaths(value[k], path.concat(k), cb, maxDepth);
        }
      }
    } else {
      if (path.length === 0) return;
      const key = path.join('·');
      cb(key, path, value);
    }
  },

  // Walk a value with a path that may contain [*] — returns the first found
  // leaf string (deterministic first-match semantics).
  _jsonPathGetWithStar(value, path) {
    let cur = [value];
    for (const seg of path) {
      const next = [];
      for (const v of cur) {
        if (v == null) continue;
        if (seg === '[*]' && Array.isArray(v)) {
          for (const el of v) next.push(el);
        } else if (/^\[\d+\]$/.test(seg) && Array.isArray(v)) {
          next.push(v[Number(seg.slice(1, -1))]);
        } else if (typeof v === 'object') {
          next.push(v[seg]);
        }
      }
      cur = next;
      if (!cur.length) return undefined;
    }
    for (const v of cur) {
      if (v != null && typeof v !== 'object') return v;
    }
    return undefined;
  },

  // ── Add / remove extracted columns ──────────────────────────────────────
  // Returns the new column's index in `this.columns` (base + extracted),
  // so callers can chain a filter chip against it (see `onCellPick`).
  _addJsonExtractedCol(colIdx, path, label) {
    const before = this._extractedCols.length;
    this._addJsonExtractedColNoRender(colIdx, path, label);
    // Duplicate rejected — nothing to rebuild, and the caller needs a
    // sentinel so downstream chip-chaining can fall back gracefully.
    if (this._extractedCols.length === before) return -1;
    const newColIdx = this._baseColumns.length + this._extractedCols.length - 1;
    this._rebuildExtractedStateAndRender();
    return newColIdx;
  },
  _addJsonExtractedColNoRender(colIdx, path, label, opts) {
    // Dedup: same source column + same JSON path == same extractor. Reject
    // silently so repeated clicks on the same JSON leaf don't pile up
    // duplicate columns.
    if (this._findDuplicateExtractedCol({ kind: 'json', sourceCol: colIdx, path }) >= 0) return;
    const name = this._uniqueColName(label || _tlJsonPathLabel(path));
    const values = new Array(this.store.rowCount);
    // Optional pre-decoded source-column cache. The auto-extract apply
    // pump groups proposals by `sourceCol` and decodes the column once,
    // then passes the resulting `string[]` through `opts.srcValues` so
    // every proposal in the group shares the same materialised view of
    // the column instead of hammering `_cellAt` (which delegates into
    // `RowStore._decodeAsciiSlice` — the dominant cost on 100k-row
    // CSVs). The fallback path (no `srcValues`) is the legacy behaviour
    // used by every non-pump caller (Extract dialog click, JSON-tree
    // pick, regex tab, persisted-regex replay).
    const srcValues = (opts && Array.isArray(opts.srcValues)
      && opts.srcValues.length === this.store.rowCount) ? opts.srcValues : null;

    for (let i = 0; i < this.store.rowCount; i++) {
      const raw = srcValues ? srcValues[i] : this._cellAt(i, colIdx);
      if (!raw) { values[i] = ''; continue; }
      let parsed = this._jsonCache.get(i);
      if (parsed === undefined) {
        try { parsed = JSON.parse(raw); } catch (_) { parsed = null; }
        this._jsonCache.set(i, parsed);
      }
      if (parsed == null || typeof parsed !== 'object') { values[i] = ''; continue; }
      const v = this._jsonPathGetWithStar(parsed, path);
      values[i] = v == null ? '' : (typeof v === 'object' ? JSON.stringify(v) : String(v));
    }
    // Route the append through the dataset so the per-mutation
    // invariant (`values.length === store.rowCount`) is asserted at
    // the call site rather than only on the next read. The dataset's
    // internal `_extractedCols` is the SAME array reference as
    // `this._extractedCols`, so this push mutates BOTH views.
    this._dataset.addExtractedCol({
      name, kind: (opts && opts.autoKind) ? 'auto' : 'json',
      sourceCol: colIdx, path, values,
    });
  },

  _addRegexExtractNoRender(spec) {
    // Route through `safeRegex` so persisted-regex replay (loaded from
    // localStorage) cannot crash the timeline if a pattern that previously
    // compiled is now flagged as ReDoS-prone, and so adversarial patterns
    // never reach `new RegExp`.
    const _src = spec.pattern || '';
    if (_src.length > 1024) return;
    const safe = safeRegex(_src, spec.flags || '');
    if (!safe.ok) return;
    const re = safe.regex;
    const col = spec.col;
    const gp = Math.max(0, Math.min(9, spec.group || 0));
    // Dedup: same source column + same (pattern, flags, group) == same
    // extractor. Reject silently; the Regex-tab extract button detects
    // the no-op by list-length diff and toasts a user-facing "already
    // extracted" notice. Persisted-regex replay on construction hits
    // this path too — legacy storage that stacked duplicates is
    // collapsed on the next load.
    if (this._findDuplicateExtractedCol({
      kind: spec.kind || 'regex',
      sourceCol: col,
      pattern: spec.pattern,
      flags: spec.flags || '',
      group: gp,
    }) >= 0) return;
    // `trim` post-processes the captured string: strip leading/trailing
    // whitespace + drop per-line tab-indentation. Multi-line EVTX values
    // (`PrivilegeList=A\n\t\t\tB\n\t\t\tC`, `UserAccountControl=\n\t\t%%2080
    // \n\t\t%%2082`) then render cleanly in the grid / topvals / pivot
    // instead of being decorated with EvtxRenderer's tab continuation.
    // Only enabled for the Auto-tab KV branch via `spec.trim`; manually
    // authored Regex-tab extractors keep their raw capture bytes.
    const doTrim = !!spec.trim;
    const values = new Array(this.store.rowCount);
    // Optional pre-decoded source-column cache (mirrors
    // `_addJsonExtractedColNoRender`). Populated by the auto-extract
    // apply pump for proposals that share a `sourceCol`, sidestepping
    // ~rowCount calls to `_cellAt` per proposal. Manual regex extracts,
    // persisted-regex replay, and dialog interactions never set this
    // and stay on the legacy `_cellAt` path.
    const srcValues = (Array.isArray(spec.srcValues)
      && spec.srcValues.length === this.store.rowCount) ? spec.srcValues : null;
    for (let i = 0; i < this.store.rowCount; i++) {
      const v = srcValues ? srcValues[i] : this._cellAt(i, col);
      if (!v) { values[i] = ''; continue; }
      // Reset lastIndex if global flag used
      if (re.global) re.lastIndex = 0;
      const m = re.exec(v);
      if (!m) { values[i] = ''; continue; }
      const captured = (gp < m.length) ? (m[gp] == null ? '' : m[gp]) : m[0];
      let out = String(captured);
      if (doTrim && out) {
        out = out.replace(/^\s+|\s+$/g, '').replace(/[ \t]*\n[ \t]*/g, '\n');
      }
      values[i] = out;
    }
    // Route through the dataset's `addExtractedCol` so the per-push
    // invariant fires (catches a future caller that builds a
    // wrong-length `values` array — the regex extract path
    // pre-allocates `new Array(this.store.rowCount)`, but this
    // assertion guards against an off-by-one in any future
    // refactor of the loop above).
    this._dataset.addExtractedCol({
      name: this._uniqueColName(spec.name || 'regex'),
      kind: spec.kind || 'regex',
      sourceCol: col, pattern: spec.pattern, flags: spec.flags || '', group: gp,
      trim: doTrim,
      values,
    });
    // Persist regex extractors.
    this._persistRegexExtracts();
  },

  // Returns the index of an existing extractor equivalent to `spec`, or -1
  // if none. `spec` is one of:
  //   { kind: 'json'|'auto', sourceCol, path }      — JSON-leaf extractor
  //   { kind: 'regex'|'auto', sourceCol, pattern, flags, group }  — regex
  // The `auto` kind is normalised by presence/absence of `path` so that an
  // Auto-tab json-leaf and a manually-picked JSON leaf on the same path
  // collapse into a single column. Paths compared by JSON.stringify — cheap
  // and stable for the small arrays these paths use.
  _findDuplicateExtractedCol(spec) {
    if (!spec) return -1;
    const sHasPath = Array.isArray(spec.path);
    const sKind = sHasPath ? 'json' : 'regex';
    const sPathKey = sHasPath ? JSON.stringify(spec.path) : null;
    const sFlags = spec.flags || '';
    const sGroup = spec.group || 0;
    for (let i = 0; i < this._extractedCols.length; i++) {
      const e = this._extractedCols[i];
      if (e.sourceCol !== spec.sourceCol) continue;
      const eHasPath = Array.isArray(e.path);
      const eKind = eHasPath ? 'json' : 'regex';
      if (eKind !== sKind) continue;
      if (sKind === 'json') {
        if (JSON.stringify(e.path || []) === sPathKey) return i;
      } else {
        if (e.pattern === spec.pattern
          && (e.flags || '') === sFlags
          && (e.group || 0) === sGroup) return i;
      }
    }
    return -1;
  },

  // Wipe every extractor on this view. Called from the "✕ Clear all
  // extracted" button in the Extract dialog header. Drops chips that
  // reference extracted cols, resets time/stack/pivot if they point into
  // extracted space, then calls `_rebuildExtractedStateAndRender()` to
  // recreate both grids with the trimmed column set and persist an empty
  // regex-extracts list for this file.
  _clearAllExtractedCols() {
    if (!this._extractedCols.length) return false;
    const n = this._extractedCols.length;

    if (!window.confirm(`Remove ${n} extracted column${n === 1 ? '' : 's'}? This cannot be undone.`)) return false;
    const baseLen = this._baseColumns.length;

    // Strip query clauses targeting any extracted column (colIdx >= baseLen)
    // BEFORE wiping `_extractedCols`, so the serializer can still resolve
    // those column indices to names while editing the query string.
    if (this.columns.length > baseLen) {
      const extractedIndices = [];
      for (let i = baseLen; i < this.columns.length; i++) extractedIndices.push(i);
      this._queryRemoveClausesForCols(extractedIndices);
    }
    // Time/stack/pivot sometimes reference an extracted col — snap back.
    if (this._timeCol != null && this._timeCol >= baseLen) {
      this._timeCol = _tlAutoDetectTimestampCol(this._baseColumns, this.store);
      this._parseAllTimestamps();
      this._dataRange = this._computeDataRange();
      this._window = null;
    }
    if (this._stackCol != null && this._stackCol >= baseLen) this._stackCol = null;
    if (this._pivotSpec) {
      const refs = [this._pivotSpec.rows, this._pivotSpec.cols, this._pivotSpec.aggCol];
      if (refs.some(v => typeof v === 'number' && v >= baseLen)) {
        this._pivotSpec = null;
        TimelineView._savePivotSpec({});
      }
    }

    // CRITICAL: must NOT do `this._extractedCols = []` — that would
    // replace the array reference, leaving the dataset's
    // `_extractedCols` pointing at the old populated array (the
    // exact desync class TimelineDataset's invariant exists to
    // prevent). `clearExtractedCols` zero-lengths the SHARED array
    // in place so both `this._extractedCols` and the dataset's
    // internal slot end up empty.
    this._dataset.clearExtractedCols();
    this._persistRegexExtracts();          // writes empty list for this file
    this._rebuildExtractedStateAndRender();
    if (this._app && typeof this._app._toast === 'function') {
      this._app._toast(`Removed ${n} extracted column${n === 1 ? '' : 's'}`, 'info');
    }
    return true;
  },


  _uniqueColName(want) {
    let base = String(want || 'extract').trim() || 'extract';
    const existing = new Set(this.columns);
    if (!existing.has(base)) return base;
    for (let i = 2; i < 999; i++) {
      const name = base + ' ' + i;
      if (!existing.has(name)) return name;
    }
    return base + ' ' + Date.now();
  },

  _removeExtractedCol(colIdx) {
    if (!this._isExtractedCol(colIdx)) return;
    // Strip query clauses targeting this column BEFORE splicing it out of
    // `_extractedCols` — the serializer uses `this.columns` to resolve
    // colIdx → name, so the column must still exist while we edit the
    // query string. After splice, columns above `colIdx` shift down by
    // one; the query serialises by NAME not index, so round-trip picks
    // the correct column automatically.
    this._queryRemoveClausesForCols([colIdx]);
    // Route the splice through the dataset so the operation acts
    // on the canonically-owned array. `removeExtractedCol` uses
    // `splice(extIdx, 1)` on the shared reference internally —
    // identical semantics to the previous direct splice, but the
    // call surface is the dataset's mutation API.
    this._dataset.removeExtractedCol(colIdx - this._dataset.baseColCount);
    this._persistRegexExtracts();
    this._rebuildExtractedStateAndRender();
  },

  _rebuildExtractedStateAndRender() {
    // Any time the column set changes: recompute filter (chips may ref
    // extracted cols), re-populate toolbar & pivot dropdowns, and
    // refresh the grid + chart + chips + column-cards surfaces.
    //
    // In-place vs destroy/rebuild — historically this method always
    // destroyed `this._grid` and let `_renderGrid` reconstruct a fresh
    // GridViewer with the new column set. On big files (and especially
    // immediately after the post-load auto-extract pass) the user saw
    // the just-painted grid blink out for a frame and then come back
    // with the extra columns — visible "jank". When a grid is already
    // mounted, we now hand the new column array to
    // `_grid._updateColumns(...)` instead, which patches headers /
    // widths / template / drawer pane in place. The grid DOM stays
    // mounted; users see new columns appear next to the existing rows
    // rather than the whole table flicker.
    //
    // Auto-extract calls this once per applied proposal (one column
    // at a time, one per idle tick), so the visible result is a
    // smooth column-by-column reveal over ~200 ms.
    this._recomputeFilter();
    this._populateToolbarSelects();
    this._populatePivotSelects();
    if (this._grid && typeof this._grid._updateColumns === 'function') {
      // Fast path — keep the GridViewer alive, swap its column array.
      // `_updateColumns` runs `_recomputeColumnWidths` + `_buildHeaderCells`
      // + `_applyColumnTemplate` + `_forceFullRender` so the grid is
      // already painted with the new shape by the time we return.
      // We still schedule a render of the OTHER surfaces (chart legend
      // can reference extracted cols, chips render their value chips,
      // and the column-cards strip needs to gain/lose a card) but skip
      // 'grid' because the in-place path just handled it.
      try { this._grid._updateColumns(this.columns); } catch (_) {
        // If the in-place patch threw for any reason, fall back to the
        // legacy destroy/rebuild path so we don't leave the grid in a
        // half-updated state. Same `'columns'` suppression as the
        // success path — the apply-pump terminus schedules it once.
        try { this._grid.destroy(); } catch (__) { /* noop */ }
        this._grid = null;
        // D1: during the apply pump, also suppress 'chart' / 'scrubber' /
        // 'chips' — the chart re-renders identical data on every
        // proposal (filter / window / stack-col are all unchanged), so
        // N back-to-back chart redraws are pure waste. Scrubber and
        // chips are negligible CPU but suppressed for visual coherence
        // (no flicker mid-pump). The terminus in
        // `timeline-view-autoextract.js#applyStep` schedules the full
        // task list `['columns', 'chart', 'scrubber', 'chips']` once
        // after the last proposal lands.
        const fallbackTasks = this._autoExtractApplying
          ? ['grid']
          : ['chart', 'scrubber', 'chips', 'grid', 'columns'];
        this._scheduleRender(fallbackTasks);
        return;
      }
      // CRITICAL: The GridViewer's `store` is a `TimelineRowView`, which
      // SNAPSHOTS `_extLen` / `_totalCols` in its constructor — even
      // though it shares the live `_extractedCols` array reference, the
      // length snapshot is stuck at whatever it was when the rowView was
      // built. `_rowAt(r)` (used by `_buildRow` and `_classifyColumns`)
      // truncates output to `_totalCols`, so cells for newly-added
      // extracted columns render as `''` — the bug the GeoIP feature
      // surfaced. Rebuild the rowView and hand it to GridViewer's
      // `setRows` so the row materialiser sees the new column. Cheap:
      // a few field assignments. `idx` is the same one the cold path
      // would use (`_filteredIdx`); `preSorted: true` skips a Date.parse
      // re-sort because the existing idx is already chrono-sorted.
      try {
        const ds = this._dataset;
        const rowView = new TimelineRowView({
          baseStore: ds ? ds.store : this.store,
          extractedCols: ds ? ds.extractedCols : this._extractedCols,
          baseLen: ds ? ds.baseColCount : this._baseColumns.length,
          idx: this._filteredIdx || null,
        });
        this._grid.setRows(rowView, null, null, { preSorted: true });
      } catch (_) { /* fall through to scheduled render */ }
      // Re-apply persisted drag-reorder so a freshly-extracted column
      // doesn't get stuck at the end after the user has previously
      // dragged columns into a custom arrangement. _updateColumns just
      // appended the new real-indices to `_colOrder`'s tail; this call
      // overrides that with the user's saved name-keyed order.
      this._applyGridColOrder();
      // Suppress per-proposal heavy tasks while the auto-extract apply
      // pump is running. The grid is already updated in-place above; we
      // skip 'chart' / 'scrubber' / 'chips' / 'columns' because:
      //   - 'columns' triggers `_computeColumnStatsAsync` (O(rows×cols))
      //     and N back-to-back sweeps would supersede each other.
      //   - 'chart' calls `_renderChart` which re-rasters the histogram
      //     using `_filteredIdx` / `_window` / `_stackCol` — none of
      //     which change during the pump, so every redraw is identical
      //     pixels (D1, ~1.28 s saved on a 100k-row CSV).
      //   - 'scrubber' / 'chips' are cheap but suppressed for visual
      //     coherence (no flicker as columns slide in).
      // The pump's terminating branch (`applyStep` in
      // timeline-view-autoextract.js) schedules
      // `['columns', 'chart', 'scrubber', 'chips']` exactly once after
      // the last proposal lands, so all suppressed surfaces refresh.
      const fastTasks = this._autoExtractApplying
        ? []
        : ['chart', 'scrubber', 'chips', 'columns'];
      if (fastTasks.length) this._scheduleRender(fastTasks);
      return;
    }
    // Cold path — first mount, or a grid implementation without the
    // `_updateColumns` helper. Reconstruct via `_renderGrid` on the
    // next RAF. Same suppression strategy as the fast path: during the
    // apply pump we render only the grid; chart / scrubber / chips /
    // columns are deferred to the terminus.
    if (this._grid) { try { this._grid.destroy(); } catch (_) { } this._grid = null; }
    const coldTasks = this._autoExtractApplying
      ? ['grid']
      : ['chart', 'scrubber', 'chips', 'grid', 'columns'];
    this._scheduleRender(coldTasks);
  },

  _persistRegexExtracts() {
    // ONLY persist `kind: 'regex'` — the manual Regex-tab extracts the
    // analyst typed in by hand. `kind: 'auto'` (silent scanner +
    // Auto/Edit dialog) and `kind: 'json'` (JSON-tree click) are
    // EPHEMERAL by design: the auto-extract pass re-derives them
    // deterministically on every file open, so persisting them would
    // (a) duplicate work for no benefit, and (b) re-introduce the
    // silent column-loss bug — the JSON branch produces `kind: 'json'`
    // entries with no `pattern`, which would be filtered out by the
    // `.filter(e => e.pattern)` below, leaving only the regex-shaped
    // half of the auto-extract output behind. See the long comment in
    // `_autoExtractBestEffort` (timeline-view-autoextract.js) for the
    // full design rationale.
    const list = this._extractedCols
      .filter(e => e.kind === 'regex')
      .map(e => ({
        name: e.name, col: e.sourceCol, pattern: e.pattern, flags: e.flags,
        group: e.group, kind: e.kind,
        // `trim` is only meaningful for Auto-tab KV extractors — persist it
        // when set so multi-line EVTX values stay normalised across reloads.
        ...(e.trim ? { trim: true } : {}),
      }))
      .filter(e => e.pattern);
    TimelineView._saveRegexExtractsFor(this._fileKey, list);
  },

});
