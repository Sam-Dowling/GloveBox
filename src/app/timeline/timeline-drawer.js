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
    const values = new Array(this.rows.length);

    for (let i = 0; i < this.rows.length; i++) {
      const raw = this._cellAt(i, colIdx);
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
    this._extractedCols.push({
      name, kind: (opts && opts.autoKind) ? 'auto' : 'json',
      sourceCol: colIdx, path, values,
    });
  },

  _addRegexExtractNoRender(spec) {
    let re;
    try { re = new RegExp(spec.pattern, spec.flags || ''); } catch (_) { return; }
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
    const values = new Array(this.rows.length);
    for (let i = 0; i < this.rows.length; i++) {
      const v = this._cellAt(i, col);
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
    this._extractedCols.push({
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
      this._timeCol = _tlAutoDetectTimestampCol(this._baseColumns, this.rows);
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

    this._extractedCols = [];
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
    this._extractedCols.splice(colIdx - this._baseColumns.length, 1);
    this._persistRegexExtracts();
    this._rebuildExtractedStateAndRender();
  },

  _rebuildExtractedStateAndRender() {
    // Any time the column set changes: recompute filter (chips may ref extracted cols),
    // re-populate toolbar & pivot dropdowns, invalidate stats, kill the grid so it
    // rebuilds with the new columns.
    this._recomputeFilter();
    this._populateToolbarSelects();
    this._populatePivotSelects();
    // Destroy existing grid — column count changed.
    if (this._grid) { try { this._grid.destroy(); } catch (_) { } this._grid = null; }
    this._scheduleRender(['chart', 'scrubber', 'chips', 'grid', 'columns']);
  },

  _persistRegexExtracts() {
    const list = this._extractedCols
      .filter(e => e.kind === 'regex' || e.kind === 'auto')
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
