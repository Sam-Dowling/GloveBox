'use strict';
// ════════════════════════════════════════════════════════════════════════════
// grid-viewer-header-class.test.js — pin the `headerClass` hook wired
// through GridViewer.
//
// GridViewer already carries two decorative hooks (`cellClass`,
// `rowClass`) with near-identical shapes.  The merged-Timeline
// canonical-column differentiator needs a third: a per-header-cell
// class callback that fires inside `_buildHeaderCells` so the
// caller can tag `__source` with `grid-header-canonical` (and any
// future renderer can tag its own columns uniformly).
//
// This file pins four invariants:
//
//   1. The constructor captures `opts.headerClass` as
//      `this._headerClassFn` — mirrors the existing `cellClass` /
//      `rowClass` stashing so future refactors that rename the
//      internal field have a locator.
//
//   2. `_buildHeaderCells` invokes `this._headerClassFn(i, name)`
//      when the hook is present, where `i` is the REAL column index
//      (matching the `data-col` stamping contract — see
//      `grid-viewer-col-order.test.js`) and `name` is the resolved
//      column label.
//
//   3. The returned string is applied to the header cell's classList
//      via `classList.add` (composes with the base
//      `grid-header-clickable` class).
//
//   4. The hook is wrapped in a try/catch so a throwing callback
//      never breaks header rendering — decorative failures should
//      not take down the grid.
//
// These are SOURCE-REGEX pins, not DOM exercises, because the
// hook's surface is tiny and end-to-end behaviour is covered by
// `tests/e2e-fixtures/timeline-merge.spec.ts`.
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

test('constructor captures opts.headerClass as _headerClassFn', () => {
  // Mirrors the idiom used for `_cellClassFn` / `_rowClassFn` — if
  // this field is ever renamed the timeline-side wiring plus the
  // _buildHeaderCells invocation below will drift silently without
  // this pin.
  assert.match(
    GV,
    /this\._headerClassFn\s*=\s*typeof\s+opts\.headerClass\s*===\s*['"]function['"]\s*\?\s*opts\.headerClass\s*:\s*null\s*;/,
    '_headerClassFn must be captured from opts.headerClass in the constructor',
  );
});

test('_buildHeaderCells invokes _headerClassFn(i, name) when present', () => {
  const m = GV.match(/^ {2}_buildHeaderCells\s*\(\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_buildHeaderCells body not found');
  const body = m[1];
  // Must call the hook with (realIdx, resolvedName).
  assert.match(
    body,
    /this\._headerClassFn\s*\(\s*i\s*,\s*name\s*\)/,
    '_buildHeaderCells must call `this._headerClassFn(i, name)` — real index + resolved name',
  );
});

test('_buildHeaderCells adds returned classes via classList.add', () => {
  const m = GV.match(/^ {2}_buildHeaderCells\s*\(\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_buildHeaderCells body not found');
  const body = m[1];
  // Must split on whitespace and call classList.add per token — the
  // convention mirrors cellClass / rowClass (which accept a
  // space-separated string).
  assert.match(
    body,
    /cell\.classList\.add\s*\(\s*parts\[pi\]\s*\)/,
    '_buildHeaderCells must apply returned classes via cell.classList.add',
  );
  assert.match(
    body,
    /String\(extra\)\.trim\(\)\.split\(\s*\/\\s\+\/\s*\)/,
    '_buildHeaderCells must tolerate space-separated multi-class returns',
  );
});

test('_buildHeaderCells wraps the hook in try/catch', () => {
  // Decorative only — must not break header render if the callback
  // throws.  Matches the try/catch pattern used by `cellAugment` /
  // `detailAugment`.
  const m = GV.match(/^ {2}_buildHeaderCells\s*\(\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_buildHeaderCells body not found');
  const body = m[1];
  // Look for a try{...}catch pattern specifically around the
  // _headerClassFn call.
  const hookRegion = body.match(
    /this\._headerClassFn[\s\S]{0,400}?catch\s*\(/,
  );
  assert.ok(hookRegion,
    '_buildHeaderCells must wrap the _headerClassFn invocation in try/catch');
});
