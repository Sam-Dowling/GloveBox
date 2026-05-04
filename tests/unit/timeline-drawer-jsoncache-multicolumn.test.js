'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-drawer-jsoncache-multicolumn.test.js
//
// Regression test for the _jsonCache compound-key fix.
//
// Background: `_addJsonExtractedColNoRender` populates `_jsonCache` to avoid
// re-parsing the same JSON string multiple times when several proposals
// target the same source column. Before this fix the cache was keyed purely
// by row index `i`, which meant that when two DIFFERENT source columns
// both contained JSON, the parse result for row `i` of column A would be
// returned for row `i` of column B — producing silently wrong extracted
// values.
//
// The fix: key by `(colIdx * 0x100000) + rowIdx` so entries from different
// columns never collide. This test drives `_addJsonExtractedColNoRender`
// directly against a two-column grid where each JSON column has a distinct
// schema, then asserts that extracted values come from the correct column.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

// ── vm harness ────────────────────────────────────────────────────────────
//
// Load the drawer mixin into a minimal stub TimelineView so we can call
// `_addJsonExtractedColNoRender` directly. We replicate the same sandbox
// pattern used by `timeline-view-autoextract-real-fixture.test.js`.

function loadDrawerSandbox() {
  const sandbox = {
    console,
    Map, Set, Date, Math, JSON, RegExp, Error, TypeError,
    Object, Array, Number, String, Boolean,
    Uint8Array, Uint16Array, Uint32Array, Float64Array,
    parseInt, parseFloat, isFinite, isNaN, Symbol, Promise,
    setTimeout, clearTimeout,
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);

  const constantsSrc = fs.readFileSync(
    path.join(REPO_ROOT, 'src/constants.js'), 'utf8');
  const helpersSrc = fs.readFileSync(
    path.join(REPO_ROOT, 'src/app/timeline/timeline-helpers.js'), 'utf8');
  const drawerSrc = fs.readFileSync(
    path.join(REPO_ROOT, 'src/app/timeline/timeline-drawer.js'), 'utf8');

  // Minimal stub class — the mixin attaches to its prototype.
  const stubClass = 'class TimelineView { constructor() {} }\n';
  const expose = '\nglobalThis.TimelineView = TimelineView;\n';

  const combined =
    constantsSrc + '\n' +
    stubClass +
    helpersSrc + '\n' +
    drawerSrc + '\n' +
    expose;

  vm.runInContext(combined, sandbox, {
    filename: 'timeline-drawer-jsoncache-multicolumn:concat',
    displayErrors: true,
  });
  return sandbox;
}

// ── Build a minimal view instance ─────────────────────────────────────────
//
// `_addJsonExtractedColNoRender` reads:
//   this.store.rowCount
//   this._jsonCache           (Map)
//   this._cellAt(row, col)    (string accessor)
//   this._findDuplicateExtractedCol(desc)  → -1 means "not found"
//   this._uniqueColName(name) → return name unchanged for test simplicity
//   this._dataset.addExtractedCol(desc)    → push to our results array

function buildView(sandbox, colA, colB) {
  const TimelineView = sandbox.TimelineView;
  const view = new TimelineView();
  const rowCount = colA.length;
  assert.equal(colB.length, rowCount, 'test setup: both columns must have same row count');

  view._jsonCache = new sandbox.Map();
  view.store = { rowCount };
  // Two columns: index 0 = colA, index 1 = colB.
  view._cellAt = function (row, col) {
    if (col === 0) return colA[row] || '';
    if (col === 1) return colB[row] || '';
    return '';
  };

  // Collect extracted columns in a plain array.
  const extracted = [];
  view._findDuplicateExtractedCol = () => -1;   // never deduplicate
  view._uniqueColName = (name) => name;
  view._dataset = {
    addExtractedCol(desc) { extracted.push(desc); },
  };
  view._extractedResults = extracted;

  return view;
}

// ── Tests ──────────────────────────────────────────────────────────────────

test('_jsonCache compound key: two JSON columns produce correct independent extractions', () => {
  // colA has objects with { "kind": "A", "value": N }.
  // colB has objects with { "kind": "B", "label": "X" }.
  // Without the compound key, extracting col 0 first populates the cache
  // for row indices 0..N-1. A subsequent extraction of col 1 would then
  // read the wrong (col 0) JSON for each row and return '' for every leaf
  // that doesn't exist in col 0's schema.
  const rowCount = 5;
  const colA = Array.from({ length: rowCount }, (_, i) =>
    JSON.stringify({ kind: 'A', value: i * 10 }));
  const colB = Array.from({ length: rowCount }, (_, i) =>
    JSON.stringify({ kind: 'B', label: `item-${i}` }));

  const sandbox = loadDrawerSandbox();
  const view = buildView(sandbox, colA, colB);

  // Extract from col 0: path ['value']
  sandbox.TimelineView.prototype._addJsonExtractedColNoRender.call(
    view, 0, ['value'], 'col0-value', {});

  // Extract from col 1: path ['label']
  sandbox.TimelineView.prototype._addJsonExtractedColNoRender.call(
    view, 1, ['label'], 'col1-label', {});

  assert.equal(view._extractedResults.length, 2,
    'expected 2 extracted columns');

  const col0Result = view._extractedResults[0];
  const col1Result = view._extractedResults[1];

  // col 0 extracted values must come from colA's "value" field.
  for (let i = 0; i < rowCount; i++) {
    assert.equal(String(col0Result.values[i]), String(i * 10),
      `col0 row ${i}: expected value=${i * 10}, got ${col0Result.values[i]}`);
  }

  // col 1 extracted values must come from colB's "label" field.
  for (let i = 0; i < rowCount; i++) {
    assert.equal(col1Result.values[i], `item-${i}`,
      `col1 row ${i}: expected label=item-${i}, got ${col1Result.values[i]}`);
  }
});

test('_jsonCache compound key: same source column shares cache entries across proposals', () => {
  // When two proposals target the same column (the common JSON-leaf cascade),
  // the compound key must still allow cache reuse — row `i` from the SAME
  // column must not be re-parsed on the second proposal.
  const rowCount = 4;
  const colA = Array.from({ length: rowCount }, (_, i) =>
    JSON.stringify({ x: i, y: i * 2 }));
  // colB unused in this test — supply a same-length array to satisfy buildView.
  const colB = Array.from({ length: rowCount }, () => '');

  const sandbox = loadDrawerSandbox();
  const view = buildView(sandbox, colA, colB);

  // Track JSON.parse call count by patching via the sandbox.
  let parseCalls = 0;
  const origParse = sandbox.JSON.parse.bind(sandbox.JSON);
  sandbox.JSON.parse = function (s) { parseCalls++; return origParse(s); };

  // Two proposals, both on col 0.
  sandbox.TimelineView.prototype._addJsonExtractedColNoRender.call(
    view, 0, ['x'], 'col0-x', {});
  sandbox.TimelineView.prototype._addJsonExtractedColNoRender.call(
    view, 0, ['y'], 'col0-y', {});

  // Each row was parsed at most twice (once per proposal if cache misses),
  // but the cache should have been populated on the first proposal so the
  // second hits it: total parses = rowCount (not 2 × rowCount).
  assert.equal(parseCalls, rowCount,
    `expected exactly ${rowCount} JSON.parse calls (cache reuse across proposals on same column); got ${parseCalls}`);

  // Correctness: both extractions must be right.
  const xResult = view._extractedResults[0];
  const yResult = view._extractedResults[1];
  for (let i = 0; i < rowCount; i++) {
    assert.equal(String(xResult.values[i]), String(i),
      `x col row ${i}: expected ${i}, got ${xResult.values[i]}`);
    assert.equal(String(yResult.values[i]), String(i * 2),
      `y col row ${i}: expected ${i * 2}, got ${yResult.values[i]}`);
  }
});

test('_jsonCache compound key: cache key is (colIdx * 0x100000) + rowIdx', () => {
  // Static text pin: the compound key formula must be present in the source.
  // If someone simplifies the loop and removes the compound key, this test
  // catches it before the correctness tests (which load the live code) even
  // run.
  const drawerSrc = fs.readFileSync(
    path.join(REPO_ROOT, 'src/app/timeline/timeline-drawer.js'), 'utf8');
  assert.match(drawerSrc, /colIdx \* 0x100000/,
    'expected compound cache key `colIdx * 0x100000` in timeline-drawer.js');
  assert.match(drawerSrc, /const cacheKey = cacheBase \+ i;/,
    'expected `const cacheKey = cacheBase + i;` in the hot loop');
  assert.match(drawerSrc, /this\._jsonCache\.get\(cacheKey\)/,
    'expected `_jsonCache.get(cacheKey)` (not plain `i`) in the hot loop');
  assert.match(drawerSrc, /this\._jsonCache\.set\(cacheKey, parsed\)/,
    'expected `_jsonCache.set(cacheKey, parsed)` (not plain `i`) in the hot loop');
});
