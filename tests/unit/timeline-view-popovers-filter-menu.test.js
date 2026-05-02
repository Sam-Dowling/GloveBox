'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-popovers-filter-menu.test.js
//
// Pin `_openColumnFilterMenu` — the Excel-style column filter dropdown
// the **Events grid** opens on column-header click. Restored after the
// regression in commit f0dd560 ("feat(timeline): slim column menu, …"),
// which collapsed both the slim Top-Values-card `⋮` menu AND the grid's
// filter dropdown into a single button-list and broke the latter.
//
// These tests pin the SHAPE of the function at static-text level so a
// future refactor that drops a primitive (Contains input, value
// checklist, All/None, copy-values, Reset/Apply) gets caught even if
// the test runner can't load the full TimelineView prototype mixin
// chain. Behavioural pins (round-trip from query AST, IN/NOT-IN
// "shorter list wins" Apply) are covered by existing
// `timeline-view-filter-*.test.js` files via the underlying helpers.
//
// Static-text pins on the source file. No view bootstrap.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const POPOVERS = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-popovers.js'),
  'utf8',
);
const RENDER_GRID = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-render-grid.js'),
  'utf8',
);

// ── Function exists + the slim sibling is preserved ───────────────────────

test('_openColumnFilterMenu(colIdx, anchor) exists in the popovers mixin', () => {
  assert.match(
    POPOVERS,
    /^\s{2}_openColumnFilterMenu\s*\(\s*colIdx\s*,\s*anchor\s*\)\s*\{/m,
    '`_openColumnFilterMenu(colIdx, anchor)` must be defined in timeline-view-popovers.js',
  );
});

test('_openColumnMenu (slim Top-Values-card menu) is preserved alongside it', () => {
  // The two surfaces deliberately diverge: Top-Values cards have their
  // own per-card search input (so the slim button-list suffices),
  // while the Events grid does not (so the Excel-style filter is
  // restored). A future refactor that re-merges them must not silently
  // delete `_openColumnMenu`.
  assert.match(
    POPOVERS,
    /^\s{2}_openColumnMenu\s*\(\s*colIdx\s*,\s*anchor\s*\)\s*\{/m,
    '`_openColumnMenu(colIdx, anchor)` (slim Top-Values-card actions) must remain defined',
  );
});

// ── Filter-menu primitive markup ──────────────────────────────────────────

// Slice the function body once and run all primitive-presence asserts
// against that slice — keeps every assertion robust against identical
// strings happening to appear elsewhere in the module.
function sliceFilterMenuBody() {
  const m = POPOVERS.match(/_openColumnFilterMenu\s*\(\s*colIdx\s*,\s*anchor\s*\)\s*\{[\s\S]*?\n  \},\n/);
  assert.ok(m, 'failed to slice the body of `_openColumnFilterMenu`');
  return m[0];
}

test('filter menu renders the Contains input', () => {
  const body = sliceFilterMenuBody();
  assert.match(
    body,
    /data-f="contains"/,
    'expected `data-f="contains"` substring-filter input',
  );
});

test('filter menu renders the values search input', () => {
  const body = sliceFilterMenuBody();
  assert.match(
    body,
    /data-f="valsearch"/,
    'expected `data-f="valsearch"` value-search input',
  );
});

test('filter menu renders Reset + Apply footer buttons', () => {
  const body = sliceFilterMenuBody();
  assert.match(body, /data-act="reset"/, 'expected Reset button (`data-act="reset"`)');
  assert.match(body, /data-act="apply"/, 'expected Apply button (`data-act="apply"`)');
});

test('filter menu renders All / None batch toggles + 📋 Copy', () => {
  const body = sliceFilterMenuBody();
  assert.match(body, /data-act="selall"/, 'expected All button (`data-act="selall"`)');
  assert.match(body, /data-act="selnone"/, 'expected None button (`data-act="selnone"`)');
  assert.match(body, /data-act="copyvals"/, 'expected Copy-values button (`data-act="copyvals"`)');
});

test('filter menu renders the column-action buttons (stack / extract / autopivot)', () => {
  const body = sliceFilterMenuBody();
  assert.match(body, /data-act="stackcol"/, 'expected Stack chart button');
  assert.match(body, /data-act="extract"/, 'expected ƒx Extract values button');
  assert.match(body, /data-act="autopivot"/, 'expected Auto-pivot button');
});

test('filter menu uses the .tl-colmenu CSS class (Excel-style styling)', () => {
  const body = sliceFilterMenuBody();
  assert.match(
    body,
    /menu\.className\s*=\s*['"]tl-popover\s+tl-colmenu['"]/,
    'expected `tl-popover tl-colmenu` className so .tl-colmenu* CSS rules attach',
  );
});

test('filter menu round-trips from the query AST (existingContains/Eqs/Nes)', () => {
  // The Excel-style menu pre-fills its Contains input + value checkboxes
  // from the current query AST so re-opening reflects active chips.
  // Pin the three round-trip locals.
  const body = sliceFilterMenuBody();
  assert.match(body, /existingContains/, 'expected existingContains round-trip');
  assert.match(body, /existingEqs/, 'expected existingEqs round-trip');
  assert.match(body, /existingNes/, 'expected existingNes round-trip');
});

test('filter menu retains the IN-vs-NOT-IN "shorter list wins" Apply path', () => {
  const body = sliceFilterMenuBody();
  // The Apply handler must still call _queryReplaceNotInForCol when
  // the unchecked set is shorter than checked (subject to the
  // truncated-IN-baseline guard). This is the user-facing chip-bar
  // tidiness contract.
  assert.match(
    body,
    /_queryReplaceNotInForCol\s*\(\s*colIdx\s*,\s*unchecked\s*\)/,
    'expected `_queryReplaceNotInForCol(colIdx, unchecked)` Apply path',
  );
  assert.match(
    body,
    /_replaceEqChipsForCol\s*\(\s*colIdx\s*,\s*checked\s*\)/,
    'expected `_replaceEqChipsForCol(colIdx, checked)` fallback Apply path',
  );
});

test('filter menu keeps the 200-distinct-value cap via _distinctValuesFor', () => {
  const body = sliceFilterMenuBody();
  // The 200-cap is intentional even after Top-Lists were uncapped —
  // a checkbox grid with thousands of rows is unusable. Top-Lists use
  // their own virtualised path; the filter menu does not virtualise.
  assert.match(
    body,
    /this\._distinctValuesFor\s*\(\s*colIdx\s*,\s*this\._indexIgnoringColumn\s*\(\s*colIdx\s*\)\s*,\s*200\s*\)/,
    'expected `_distinctValuesFor(colIdx, _indexIgnoringColumn(colIdx), 200)`',
  );
});

// ── Grid wires onHeaderClick to the filter menu (NOT the slim menu) ──────

test('Events-grid onHeaderClick routes to _openColumnFilterMenu', () => {
  // Regression guard for f0dd560: the grid's header-click MUST NOT call
  // the slim `_openColumnMenu` (which is for the Top-Values card `⋮`
  // button). It must call `_openColumnFilterMenu`.
  assert.match(
    RENDER_GRID,
    /onHeaderClick\s*:\s*role\s*===\s*['"]main['"]\s*\?\s*\(\s*colIdx\s*,\s*anchor\s*\)\s*=>\s*this\._openColumnFilterMenu\s*\(\s*colIdx\s*,\s*anchor\s*\)/,
    'Events-grid `onHeaderClick` must call `_openColumnFilterMenu` — NOT the slim `_openColumnMenu`',
  );
});

test('Top-Values card ⋮ button still routes to the slim _openColumnMenu', () => {
  // Symmetric pin — the slim button-list belongs on the Top-Values
  // card `⋮` only. A future "let's unify them again" refactor that
  // re-routes this site through `_openColumnFilterMenu` would
  // re-introduce the f0dd560 regression in the opposite direction
  // (cards getting an Excel filter dropdown they don't need).
  assert.match(
    RENDER_GRID,
    /head\.querySelector\(['"]\.tl-col-menu['"]\)[\s\S]{0,200}?this\._openColumnMenu\s*\(\s*c\s*,\s*head\s*\)/,
    'Top-Values card `⋮` button must still call the slim `_openColumnMenu`',
  );
});
