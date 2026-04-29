'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-persist.js — TimelineView static-method mixin (B2b).
//
// Hosts the ~30 `_loadXxx` / `_saveXxx` localStorage helpers that
// power Timeline's persistence: bucket pref, grid + chart heights,
// section open/closed state, per-file card widths / order / pinned
// columns, entities-section pinned + ordered types, the "group
// Detections by ATT&CK tactic" boolean, per-file regex extracts,
// per-file auto-extract-done marker, the global pivot spec, the
// per-file last-typed query, and the per-file 🚩 suspicious marks.
//
// All keys live in `TIMELINE_KEYS` (see `src/app/timeline/timeline-
// helpers.js`), which round-trips them through `safeStorage` (the
// quota-aware `localStorage` wrapper). Keys are documented in the
// **Persistence Keys** table in `CONTRIBUTING.md` — any change to a
// key string is a storage-format break.
//
// These helpers are pure static `localStorage` JSON wrappers: zero
// instance state, zero DOM. The B2 split moves them out of
// `timeline-view.js` (where they made the class file 6,954 lines)
// without changing any byte of the wrapped key strings or the parse/
// stringify shape.
//
// Loads AFTER timeline-view.js so the class identifier exists when
// `Object.assign(TimelineView, {...})` runs.
// ════════════════════════════════════════════════════════════════════════════

Object.assign(TimelineView, {

  _loadBucketPref() {
    const v = safeStorage.get(TIMELINE_KEYS.BUCKET);
    if (v && TIMELINE_BUCKET_OPTIONS.some(o => o.id === v)) return v;
    return 'auto';
  },
  _saveBucketPref(id) {
    safeStorage.set(TIMELINE_KEYS.BUCKET, id);
  },
  _loadGridH() {
    const v = parseInt(safeStorage.get(TIMELINE_KEYS.GRID_H), 10);
    if (Number.isFinite(v) && v >= TIMELINE_GRID_MIN_H) return v;
    return TIMELINE_GRID_DEFAULT_H;
  },
  _saveGridH(h) {
    safeStorage.set(TIMELINE_KEYS.GRID_H, String(h));
  },
  _loadChartH() {
    const v = parseInt(safeStorage.get(TIMELINE_KEYS.CHART_H), 10);
    if (Number.isFinite(v) && v >= TIMELINE_CHART_MIN_H && v <= TIMELINE_CHART_MAX_H) return v;
    return TIMELINE_CHART_DEFAULT_H;
  },
  _saveChartH(h) {
    safeStorage.set(TIMELINE_KEYS.CHART_H, String(h));
  },
  _loadSections() {
    const obj = safeStorage.getJSON(TIMELINE_KEYS.SECTIONS, {});
    return obj && typeof obj === 'object' ? obj : {};
  },
  _saveSections(obj) {
    safeStorage.setJSON(TIMELINE_KEYS.SECTIONS, obj);
  },
  _loadCardWidthsFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.CARD_WIDTHS, null);
    return (all && all[fileKey]) || {};
  },
  _saveCardWidthsFor(fileKey, widths) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.CARD_WIDTHS, {}) || {};
    all[fileKey] = widths;
    safeStorage.setJSON(TIMELINE_KEYS.CARD_WIDTHS, all);
  },
  _loadCardOrderFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.CARD_ORDER, null);
    const arr = all && all[fileKey];
    return Array.isArray(arr) ? arr : null;
  },
  _saveCardOrderFor(fileKey, order) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.CARD_ORDER, {}) || {};
    if (order && order.length) all[fileKey] = order;
    else delete all[fileKey];
    safeStorage.setJSON(TIMELINE_KEYS.CARD_ORDER, all);
  },
  // Grid column display-order — same shape as CARD_ORDER (per-file
  // map of column-name arrays). Returned `null` ⇒ no saved order ⇒
  // GridViewer falls back to identity ordering (real-index = display-
  // index). See `TIMELINE_KEYS.GRID_COL_ORDER` for why we persist names
  // instead of real indices.
  _loadGridColOrderFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.GRID_COL_ORDER, null);
    const arr = all && all[fileKey];
    return Array.isArray(arr) ? arr : null;
  },
  _saveGridColOrderFor(fileKey, names) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.GRID_COL_ORDER, {}) || {};
    if (names && names.length) all[fileKey] = names;
    else delete all[fileKey];
    safeStorage.setJSON(TIMELINE_KEYS.GRID_COL_ORDER, all);
  },
  _loadPinnedColsFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.PINNED_COLS, null);
    const arr = all && all[fileKey];
    return Array.isArray(arr) ? arr : [];
  },
  _savePinnedColsFor(fileKey, cols) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.PINNED_COLS, {}) || {};
    if (cols && cols.length) all[fileKey] = cols;
    else delete all[fileKey];
    safeStorage.setJSON(TIMELINE_KEYS.PINNED_COLS, all);
  },
  // Entities-section state — mirrors the `_loadPinnedColsFor` /
  // `_loadCardOrderFor` shapes but keys on the IOC-type identifier instead
  // of a column name. Stored under the dedicated ENT_PINNED / ENT_ORDER
  // namespaces so the Top-values column state stays uncoupled.
  _loadEntPinnedFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.ENT_PINNED, null);
    const arr = all && all[fileKey];
    return Array.isArray(arr) ? arr : [];
  },
  _saveEntPinnedFor(fileKey, types) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.ENT_PINNED, {}) || {};
    if (types && types.length) all[fileKey] = types;
    else delete all[fileKey];
    safeStorage.setJSON(TIMELINE_KEYS.ENT_PINNED, all);
  },
  _loadEntOrderFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.ENT_ORDER, null);
    const arr = all && all[fileKey];
    return Array.isArray(arr) ? arr : null;
  },
  _saveEntOrderFor(fileKey, order) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.ENT_ORDER, {}) || {};
    if (order && order.length) all[fileKey] = order;
    else delete all[fileKey];
    safeStorage.setJSON(TIMELINE_KEYS.ENT_ORDER, all);
  },
  // Global "group Detections by ATT&CK tactic" toggle. Cross-file because
  // analysts who turn it on once tend to want it on for every EVTX they
  // open. Boolean stored as 0/1.
  _loadDetectionsGroup() {
    const raw = safeStorage.get(TIMELINE_KEYS.DETECTIONS_GROUP);
    return raw === '1';
  },
  _saveDetectionsGroup(on) {
    safeStorage.set(TIMELINE_KEYS.DETECTIONS_GROUP, on ? '1' : '0');
  },
  _loadRegexExtractsFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.REGEX_EXTRACTS, null);
    const list = (all && all[fileKey]) || [];
    return Array.isArray(list) ? list : [];
  },
  _saveRegexExtractsFor(fileKey, list) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.REGEX_EXTRACTS, {}) || {};
    all[fileKey] = list;
    safeStorage.setJSON(TIMELINE_KEYS.REGEX_EXTRACTS, all);
  },
  // Per-file marker — set the first time the best-effort auto-extract pass
  // runs against a file so we never re-add columns the analyst has since
  // deleted. Read on construction (`_autoExtractBestEffort` short-circuits
  // when truthy), written once after that pass runs (whether or not it
  // added any columns — a zero-result file shouldn't get re-scanned on
  // every reopen). Cleared by `_reset()` via the `loupe_timeline_*` prefix
  // wipe so a hard reset always re-runs auto-extract.
  _loadAutoExtractDoneFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.AUTOEXTRACT_DONE, null);
    return !!(all && all[fileKey]);
  },
  _saveAutoExtractDoneFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.AUTOEXTRACT_DONE, {}) || {};
    all[fileKey] = true;
    safeStorage.setJSON(TIMELINE_KEYS.AUTOEXTRACT_DONE, all);
  },
  _loadPivotSpec() {
    const obj = safeStorage.getJSON(TIMELINE_KEYS.PIVOT, null);
    return obj && typeof obj === 'object' ? obj : null;
  },
  _savePivotSpec(obj) {
    safeStorage.setJSON(TIMELINE_KEYS.PIVOT, obj);
  },


  // Per-file last-typed query — keyed by `_fileKey` so a large CSV the
  // analyst revisits tomorrow still has their last filter stuck in the
  // editor when they re-open it. Read on construction (see `_queryStr`
  // init), written every time the query is committed (Enter key).
  _loadQueryFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.QUERY, null);
    return (all && typeof all[fileKey] === 'string') ? all[fileKey] : '';
  },
  _saveQueryFor(fileKey, q) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.QUERY, {}) || {};
    if (q) all[fileKey] = q;
    else delete all[fileKey];
    safeStorage.setJSON(TIMELINE_KEYS.QUERY, all);
  },


  // Per-file suspicious marks — `[{ colName, val }]`. Persisted by column
  // NAME (not index) so an extracted column that rebuilds under a different
  // index on reload still re-hydrates its 🚩 marks. The view resolves the
  // name back to a live colIdx at filter-time (`_susMarksResolved`).
  _loadSusMarksFor(fileKey) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.SUS_MARKS, null);
    const arr = all && Array.isArray(all[fileKey]) ? all[fileKey] : [];
    // Two shapes are persisted: column-scoped marks carry `colName`, and
    // "Any column" marks carry `any: true` with `colName: null`. Filter
    // on the presence of a usable discriminator + value.
    return arr
      .filter(m => m && m.val != null && (m.any === true || typeof m.colName === 'string'))
      .map(m => (m.any === true
        ? { any: true, colName: null, val: String(m.val) }
        : { colName: String(m.colName), val: String(m.val) }));
  },
  _saveSusMarksFor(fileKey, marks) {
    const all = safeStorage.getJSON(TIMELINE_KEYS.SUS_MARKS, {}) || {};
    if (marks && marks.length) {
      all[fileKey] = marks.map(m => (m.any === true
        ? { any: true, colName: null, val: String(m.val) }
        : { colName: String(m.colName), val: String(m.val) }));
    } else {
      delete all[fileKey];
    }
    safeStorage.setJSON(TIMELINE_KEYS.SUS_MARKS, all);
  },

});
