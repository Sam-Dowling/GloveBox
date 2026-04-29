'use strict';
// ════════════════════════════════════════════════════════════════════════════
// grid-viewer-col-order.test.js — pin the column display-order layer.
//
// GridViewer has two distinct index spaces:
//   • REAL index — position in `this.columns` and in row arrays. The
//     classifier, width algorithm, sort engine, hidden-cols set, user
//     widths map, drawer body, and every external consumer (Timeline
//     right-click handler, drawer JSON-tree picker) all key off the
//     real index. NEVER changes under reorder.
//   • DISPLAY index — visible position in the header row / data row.
//     Computed from `_colOrder` (or identity when null) on every render.
//
// The contract these tests pin:
//   1. `_colOrder` defaults to null (no reorder, identity-shaped output).
//   2. `_resolveColOrder()` heals stale entries (out-of-range, dupes,
//      missing reals) without throwing.
//   3. `_buildHeaderCells`, `_buildRow`, `_applyColumnTemplate` all
//      iterate via `_resolveColOrder` so the three surfaces stay aligned.
//   4. `data-col` continues to stamp the REAL index (Timeline / drawer
//      consumers depend on this regardless of display order).
//   5. `_updateColumns` extends `_colOrder` on grow (append new tail
//      indices) and prunes on shrink (drop indices ≥ newLen). Without
//      this, an auto-extract pass after a user drag would leave the
//      new column dangling outside the display order.
//   6. The host opt-in `onColumnReorder` callback is wired and fires
//      from `_commitColumnReorder` (the drag-drop drop handler path).
//   7. Drag-drop is wired on header cells via HTML5 native DnD, with
//      a `text/x-loupe-col` MIME type and midpoint-based drop logic.
//
// Tests are structural pins (regex against source) — same style as
// `grid-viewer-update-columns.test.js`. A behavioural test would need
// a JSDOM-style harness that does not exist yet for this file; the
// behavioural coverage lives in tests/e2e-fixtures/timeline-grid-
// reorder.spec.ts (drag → reload → order survives).
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const GV = fs.readFileSync(
  path.join(REPO_ROOT, 'src/renderers/grid-viewer.js'),
  'utf8',
);
const RENDER_GRID = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-render-grid.js'),
  'utf8',
);
const PERSIST = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-persist.js'),
  'utf8',
);
const HELPERS = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-helpers.js'),
  'utf8',
);
const VIEW = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view.js'),
  'utf8',
);
const VIEWERS_CSS = fs.readFileSync(
  path.join(REPO_ROOT, 'src/styles/viewers.css'),
  'utf8',
);

// ── GridViewer field + helpers ────────────────────────────────────────────

test('GridViewer constructor initialises this._colOrder = null', () => {
  // null is the identity case: no allocation, no extra work, the same
  // shape every grid had before the feature was added.
  assert.match(
    GV,
    /this\._colOrder\s*=\s*null\s*;/,
    'this._colOrder = null must be set in the constructor',
  );
});

test('GridViewer accepts opts.onColumnReorder', () => {
  assert.match(
    GV,
    /this\._onColumnReorder\s*=\s*typeof\s+opts\.onColumnReorder\s*===\s*['"]function['"]/,
    'opts.onColumnReorder must be wired onto this._onColumnReorder',
  );
});

test('GridViewer defines _resolveColOrder / _setColumnOrder / _getColumnOrder / _commitColumnReorder', () => {
  for (const name of [
    '_resolveColOrder',
    '_setColumnOrder',
    '_getColumnOrder',
    '_commitColumnReorder',
  ]) {
    const re = new RegExp(`^ {2}${name}\\s*\\(`, 'm');
    assert.match(GV, re, `${name} must be defined on GridViewer`);
  }
});

test('_commitColumnReorder fires onColumnReorder host callback', () => {
  const m = GV.match(/^ {2}_commitColumnReorder\s*\([^)]*\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_commitColumnReorder body not found');
  const body = m[1];
  assert.match(
    body,
    /this\._onColumnReorder\s*\(/,
    '_commitColumnReorder must invoke this._onColumnReorder so the host can persist',
  );
  assert.match(
    body,
    /this\._setColumnOrder\s*\(/,
    '_commitColumnReorder must apply the new order via _setColumnOrder',
  );
});

// ── Render path uses display order ─────────────────────────────────────────

test('_buildHeaderCells iterates display order and stamps real-index data-col', () => {
  const m = GV.match(/^ {2}_buildHeaderCells\s*\(\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_buildHeaderCells body not found');
  const body = m[1];
  assert.match(
    body,
    /this\._resolveColOrder\s*\(/,
    '_buildHeaderCells must resolve display order via this._resolveColOrder()',
  );
  assert.match(
    body,
    /cell\.dataset\.col\s*=\s*i\s*;/,
    '_buildHeaderCells must stamp the REAL index on cell.dataset.col (loop variable, NOT display position)',
  );
});

test('_buildRow iterates display order and stamps real-index data-col', () => {
  const m = GV.match(/^ {2}_buildRow\s*\([^)]*\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_buildRow body not found');
  const body = m[1];
  assert.match(
    body,
    /this\._resolveColOrder\s*\(/,
    '_buildRow must resolve display order via this._resolveColOrder()',
  );
  assert.match(
    body,
    /td\.dataset\.col\s*=\s*c\s*;/,
    '_buildRow must stamp the REAL column index on td.dataset.col (the resolved real-index, NOT the display position)',
  );
});

test('_applyColumnTemplate iterates display order so CSS template matches header / row layout', () => {
  const m = GV.match(/^ {2}_applyColumnTemplate\s*\(\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_applyColumnTemplate body not found');
  const body = m[1];
  assert.match(
    body,
    /this\._resolveColOrder\s*\(/,
    '_applyColumnTemplate must resolve display order via this._resolveColOrder() so the grid-template tracks line up with cell DOM',
  );
});

// ── _updateColumns grow + shrink paths ─────────────────────────────────────

test('_updateColumns appends new real-indices to _colOrder on grow', () => {
  const m = GV.match(/^ {2}_updateColumns\s*\([^)]*\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_updateColumns body not found');
  const body = m[1];
  assert.match(
    body,
    /Array\.isArray\(\s*this\._colOrder\s*\)/,
    '_updateColumns must guard `_colOrder` mutation with Array.isArray (null = identity, no allocation needed)',
  );
  assert.match(
    body,
    /this\._colOrder\.push\s*\(/,
    '_updateColumns must append new tail real-indices onto _colOrder so they render after the existing display order',
  );
});

test('_updateColumns prunes _colOrder entries on shrink', () => {
  const m = GV.match(/^ {2}_updateColumns\s*\([^)]*\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_updateColumns body not found');
  const body = m[1];
  assert.match(
    body,
    /this\._colOrder\s*=\s*this\._colOrder\.filter\s*\(/,
    '_updateColumns must prune `_colOrder` entries that fall off the tail on shrink',
  );
});

// ── Drag-and-drop wiring ───────────────────────────────────────────────────

test('GridViewer defines _wireColumnDrag and calls it from _buildHeaderCells', () => {
  assert.match(
    GV,
    /^ {2}_wireColumnDrag\s*\(/m,
    '_wireColumnDrag must be defined on GridViewer',
  );
  // Must be invoked per-cell from inside _buildHeaderCells so every
  // visible header is draggable (a hidden column has no header cell).
  const m = GV.match(/^ {2}_buildHeaderCells\s*\(\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_buildHeaderCells body not found');
  assert.match(
    m[1],
    /this\._wireColumnDrag\s*\(\s*cell\s*,\s*i\s*\)/,
    '_buildHeaderCells must call this._wireColumnDrag(cell, i) per visible column',
  );
});

test('_wireColumnDrag uses HTML5 native DnD with a custom MIME type', () => {
  const m = GV.match(/^ {2}_wireColumnDrag\s*\([^)]*\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_wireColumnDrag body not found');
  const body = m[1];
  // The full DnD lifecycle: dragstart sets dataTransfer, dragover
  // toggles the drop indicator, drop reads the source index.
  for (const evt of ['dragstart', 'dragover', 'drop', 'dragend']) {
    assert.match(
      body,
      new RegExp(`addEventListener\\(\\s*['"]${evt}['"]`),
      `_wireColumnDrag must register a '${evt}' handler`,
    );
  }
  // Custom MIME stops file drops from being eligible for column reorder.
  assert.match(
    body,
    /text\/x-loupe-col/g,
    '_wireColumnDrag must stamp the source column index under a custom MIME type (text/x-loupe-col) so file drops do not reorder',
  );
  // Midpoint-based drop resolution mirrors the proven `tl-col-card`
  // reorder UX.
  assert.match(
    body,
    /rect\.width\s*\/\s*2/,
    '_wireColumnDrag must use a midpoint check (rect.width / 2) to decide before/after on drop',
  );
});

test('_wireColumnDrag commits the new order via _commitColumnReorder', () => {
  const m = GV.match(/^ {2}_wireColumnDrag\s*\([^)]*\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_wireColumnDrag body not found');
  assert.match(
    m[1],
    /this\._commitColumnReorder\s*\(/,
    '_wireColumnDrag drop handler must call _commitColumnReorder so the host onColumnReorder callback fires',
  );
});

// ── CSS visuals ────────────────────────────────────────────────────────────

test('viewers.css defines drag-source + drop-indicator visuals', () => {
  // Source cell dims while being dragged; target cell shows a 2 px
  // accent-coloured edge on the appropriate side.
  for (const cls of [
    '.grid-header-drag-source',
    '.grid-header-drag-over-before',
    '.grid-header-drag-over-after',
  ]) {
    assert.ok(
      VIEWERS_CSS.includes(cls),
      `viewers.css must define a rule for ${cls}`,
    );
  }
});

// ── Timeline persistence wiring ────────────────────────────────────────────

test('TIMELINE_KEYS includes GRID_COL_ORDER under the loupe_ prefix', () => {
  assert.match(
    HELPERS,
    /GRID_COL_ORDER:\s*['"]loupe_timeline_grid_col_order['"]/,
    'TIMELINE_KEYS.GRID_COL_ORDER must equal "loupe_timeline_grid_col_order"',
  );
});

test('persist mixin defines _loadGridColOrderFor / _saveGridColOrderFor', () => {
  for (const name of ['_loadGridColOrderFor', '_saveGridColOrderFor']) {
    const re = new RegExp(`^\\s{2}${name}\\s*\\(`, 'm');
    assert.match(PERSIST, re, `${name} must be defined in timeline-view-persist.js`);
  }
});

test('TimelineView constructor hydrates this._gridColOrder from storage', () => {
  assert.match(
    VIEW,
    /this\._gridColOrder\s*=\s*TimelineView\._loadGridColOrderFor\s*\(\s*this\._fileKey\s*\)/,
    'TimelineView constructor must load _gridColOrder from per-file storage',
  );
});

test('Timeline grid wires onColumnReorder → _saveGridColOrderFor for the main role only', () => {
  // The suspicious-rows mini-grid is read-only; only the main grid
  // should round-trip to storage.
  assert.match(
    RENDER_GRID,
    /onColumnReorder:\s*role\s*===\s*['"]main['"]/,
    'onColumnReorder must be conditional on role === "main"',
  );
  assert.match(
    RENDER_GRID,
    /TimelineView\._saveGridColOrderFor\s*\(\s*this\._fileKey/,
    'onColumnReorder handler must persist via TimelineView._saveGridColOrderFor(this._fileKey, …)',
  );
});

test('TimelineView defines _applyGridColOrder and calls it after grid mount', () => {
  // Method presence.
  assert.match(
    RENDER_GRID,
    /^ {2}_applyGridColOrder\s*\(\)\s*\{/m,
    '_applyGridColOrder must be defined as a TimelineView method (object-literal shorthand)',
  );
  // It must be invoked on first-mount path so a saved order is honoured
  // immediately on reload.
  assert.match(
    RENDER_GRID,
    /this\._grid\s*=\s*viewer\s*;[\s\S]*?this\._applyGridColOrder\s*\(\s*\)/,
    '_applyGridColOrder must be called inside _renderGridInto after `this._grid = viewer` so a saved order is restored on first mount',
  );
});

test('_rebuildExtractedStateAndRender fast path calls _applyGridColOrder after setRows', () => {
  const DRAWER = fs.readFileSync(
    path.join(REPO_ROOT, 'src/app/timeline/timeline-drawer.js'),
    'utf8',
  );
  // Order pin: setRows → applyGridColOrder. The opposite order would
  // re-apply against a stale rowView and the geo column would still
  // render empty.
  const setRowsIdx = DRAWER.indexOf('this._grid.setRows');
  const applyIdx = DRAWER.indexOf('this._applyGridColOrder');
  assert.ok(
    setRowsIdx >= 0 && applyIdx >= 0 && applyIdx > setRowsIdx,
    '_applyGridColOrder must be called AFTER this._grid.setRows(…) in _rebuildExtractedStateAndRender (otherwise a stale rowView paints first)',
  );
});

test('_applyGridColOrder resolves names → real indices and skips identity orders', () => {
  const m = RENDER_GRID.match(/^ {2}_applyGridColOrder\s*\(\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_applyGridColOrder body not found');
  const body = m[1];
  assert.match(
    body,
    /this\.columns\.indexOf\s*\(/,
    '_applyGridColOrder must look up names → real indices via this.columns.indexOf',
  );
  assert.match(
    body,
    /this\._grid\._setColumnOrder\s*\(/,
    '_applyGridColOrder must hand the resolved order to GridViewer via _setColumnOrder',
  );
});
