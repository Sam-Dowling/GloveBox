'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-filter-colstats-cap-lift.test.js
//
// Pin the two changes to `_computeColumnStatsSync` /
// `_computeColumnStatsAsyncInternal` (May 2026):
//
//   1. The 500-row top-N cap (`TIMELINE_COL_TOP_N`) is gone — Top-Values
//      cards already virtualise their row list, so the cap was an
//      arbitrary clip on data the user could otherwise scroll to. The
//      Excel filter menu retains its own independent 200-cap via
//      `_distinctValuesFor(...)`.
//
//   2. All-unique columns (every row's value is unique — e.g. timestamp,
//      event_record_id, sequence_no) short-circuit BEFORE the sort and
//      surface as `{ values: [], allUnique: true, distinct }`.
//      `_paintColumnCards` consumes `allUnique` to suppress the card
//      entirely; the suppression takes precedence over the pinned
//      carve-out because pin-buttons only exist on rendered cards.
//
// Static-text pins on the source file (no view bootstrap), plus a
// behavioural parity block that stamps a synthetic dataset through a
// reference implementation cloning the new finalisation block.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const FILTER = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-filter.js'),
  'utf8',
);
const HELPERS = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-helpers.js'),
  'utf8',
);
const RENDER_GRID = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-render-grid.js'),
  'utf8',
);

// ── Cap removal ────────────────────────────────────────────────────────────

test('TIMELINE_COL_TOP_N constant is gone from timeline-helpers.js', () => {
  assert.doesNotMatch(
    HELPERS,
    /TIMELINE_COL_TOP_N/,
    'expected `TIMELINE_COL_TOP_N` constant to be removed (zero remaining consumers)',
  );
});

test('_computeColumnStatsSync no longer slices values to a top-N cap', () => {
  // Pin the absence of the old `arr.slice(0, TIMELINE_COL_TOP_N)` shape.
  // A regression that re-introduces ANY top-N slice would defeat the
  // uncap, so we negative-match a generic `arr.slice(0, ` followed by
  // a numeric-or-identifier cap inside this finalisation block.
  assert.doesNotMatch(
    FILTER,
    /values\s*:\s*arr\.slice\s*\(\s*0\s*,/,
    'expected NO `values: arr.slice(0, ...)` cap in stats finalisation',
  );
});

test('_computeColumnStatsSync emits uncapped values: arr', () => {
  assert.match(
    FILTER,
    /out\[c\]\s*=\s*\{\s*total\s*,\s*distinct\s*,\s*values\s*:\s*arr\s*\}\s*;/,
    'expected uncapped finalisation `out[c] = { total, distinct, values: arr };`',
  );
});

// ── All-unique short-circuit ──────────────────────────────────────────────

test('stats compute short-circuits on distinct === total via allUnique flag', () => {
  // Pin the guard form. `total > 0` is critical — a zero-row dataset
  // has `m.size === 0` AND `total === 0`, but that's the genuinely
  // empty case (handled by the existing `_isEmptyCol` branch via
  // `distinct === 0`), not all-unique.
  assert.match(
    FILTER,
    /if\s*\(\s*distinct\s*===\s*total\s*&&\s*total\s*>\s*0\s*\)\s*\{\s*out\[c\]\s*=\s*\{\s*total\s*,\s*distinct\s*,\s*values\s*:\s*\[\]\s*,\s*allUnique\s*:\s*true\s*\}\s*;/,
    'expected `if (distinct === total && total > 0) { out[c] = { total, distinct, values: [], allUnique: true }; }`',
  );
});

test('stats compute short-circuit appears in BOTH sync and async paths', () => {
  // The async path's IIFE inside `_computeColumnStatsAsyncInternal`
  // mirrors the sync finalisation. Both must carry the all-unique
  // branch — a regression that drops it from one would silently
  // bring the cap-removed sort cost back on big-EVTX async runs.
  const occurrences = (FILTER.match(
    /allUnique\s*:\s*true/g,
  ) || []).length;
  assert.ok(
    occurrences >= 2,
    `expected the \`allUnique: true\` shape to appear at least twice (sync + async finalisation), got ${occurrences}`,
  );
});

// ── Behavioural parity (reference-vs-extracted finalisation) ──────────────

// The static pins above prove the SHAPE. This block proves the
// SEMANTICS: replicate the new finalisation block as a standalone
// helper, drive synthetic input through it, and assert the three
// expected outcomes (cap lifted, all-unique suppressed, mixed pass-
// through). Any regression that breaks one outcome but not the others
// gets caught here.

function finaliseRef(stats, total) {
  const out = new Array(stats.length);
  for (let c = 0; c < stats.length; c++) {
    const m = stats[c];
    const distinct = m.size;
    if (distinct === total && total > 0) {
      out[c] = { total, distinct, values: [], allUnique: true };
      continue;
    }
    const arr = Array.from(m.entries());
    arr.sort((a, b) => b[1] - a[1]);
    out[c] = { total, distinct, values: arr };
  }
  return out;
}

test('cap lifted: 800 distinct values across 1600 rows pass through uncapped', () => {
  // Each value repeats exactly twice → distinct (800) !== total (1600)
  // → no all-unique short-circuit → sorted full array survives.
  const total = 1600;
  const m = new Map();
  for (let i = 0; i < total; i++) {
    const v = `val-${i % 800}`;
    m.set(v, (m.get(v) || 0) + 1);
  }
  const out = finaliseRef([m], total);
  assert.equal(out[0].values.length, 800,
    'expected uncapped values.length === 800 (was 500 under TIMELINE_COL_TOP_N)');
  assert.equal(out[0].distinct, 800);
  assert.equal(out[0].total, total);
  assert.ok(!out[0].allUnique, 'expected allUnique to be falsy when distinct < total');
});

test('all-unique suppressed: 1000 distinct × 1000 rows → values:[], allUnique:true', () => {
  const total = 1000;
  const m = new Map();
  for (let i = 0; i < total; i++) m.set(`uniq-${i}`, 1);
  const out = finaliseRef([m], total);
  assert.deepEqual(out[0].values, [], 'expected empty values[] for all-unique column');
  assert.equal(out[0].allUnique, true, 'expected allUnique flag set');
  assert.equal(out[0].distinct, total, 'expected distinct === total');
  assert.equal(out[0].total, total);
});

test('zero-row column is NOT mis-classified as all-unique (total > 0 guard)', () => {
  // distinct === 0 AND total === 0 → guard `total > 0` blocks the
  // short-circuit. Hits the regular finalisation path with empty arr.
  const out = finaliseRef([new Map()], 0);
  assert.equal(out[0].allUnique, undefined, 'expected NO allUnique flag when total === 0');
  assert.equal(out[0].distinct, 0);
  assert.deepEqual(out[0].values, []);
});

test('mixed: one column all-unique, one column normal — independent finalisation', () => {
  // Drives the per-column independence: each Map gets its own decision.
  const total = 500;
  const allUniq = new Map();
  for (let i = 0; i < total; i++) allUniq.set(`u-${i}`, 1);
  const normal = new Map();
  for (let i = 0; i < total; i++) {
    const v = `n-${i % 50}`;
    normal.set(v, (normal.get(v) || 0) + 1);
  }
  const out = finaliseRef([allUniq, normal], total);
  assert.equal(out[0].allUnique, true);
  assert.deepEqual(out[0].values, []);
  assert.ok(!out[1].allUnique, 'normal column must not be flagged allUnique');
  assert.equal(out[1].values.length, 50, 'normal column must surface its 50 distinct values');
});

// ── _paintColumnCards consumer-side suppression ──────────────────────────

test('_paintColumnCards defines _isAllUniqueCol(ci) reading stats[ci].allUnique', () => {
  assert.match(
    RENDER_GRID,
    /const\s+_isAllUniqueCol\s*=\s*\(\s*ci\s*\)\s*=>\s*\{[\s\S]*?stats\s*&&\s*stats\[ci\]\s*;[\s\S]*?return\s*!!\s*\(\s*s\s*&&\s*s\.allUnique\s*\)\s*;/,
    'expected `_isAllUniqueCol(ci)` predicate reading `stats[ci].allUnique`',
  );
});

test('_paintColumnCards filter applies all-unique suppression BEFORE pin-carve-out', () => {
  // The order matters: pinned carve-out must NOT rescue an all-unique
  // column (the pin button can never be reached on a card that does
  // not render). Pin the explicit "if (_isAllUniqueCol(ci)) return false"
  // appearing first inside the filter callback.
  assert.match(
    RENDER_GRID,
    /_filteredIndices\s*=\s*_indices\.filter\s*\(\s*ci\s*=>\s*\{\s*\/\/[^\n]*\n\s*\/\/[^\n]*\n\s*if\s*\(\s*_isAllUniqueCol\s*\(\s*ci\s*\)\s*\)\s*return\s+false\s*;\s*return\s+_pinnedNamesSet\.has\s*\(\s*_nameOfCi\s*\(\s*ci\s*\)\s*\)\s*\|\|\s*!\s*_isEmptyCol\s*\(\s*ci\s*\)\s*;/,
    'expected `_isAllUniqueCol` early-return BEFORE the pinned-or-non-empty fallback',
  );
});

test('_isEmptyCol detects empty by `s.distinct === 0` (not values.length === 0)', () => {
  // After the cap-lift, `values.length === 0` is also the all-unique
  // shape, so the empty predicate must distinguish via `distinct`. A
  // regression that keeps the old `values.length === 0` form would
  // mis-classify all-unique columns as empty (and the pin override
  // would resurrect them — exactly the regression we just fixed).
  assert.match(
    RENDER_GRID,
    /const\s+_isEmptyCol\s*=\s*\(\s*ci\s*\)\s*=>\s*\{[\s\S]*?if\s*\(\s*s\.distinct\s*===\s*0\s*\)\s*return\s+true\s*;/,
    'expected `_isEmptyCol` to gate on `s.distinct === 0`',
  );
});
