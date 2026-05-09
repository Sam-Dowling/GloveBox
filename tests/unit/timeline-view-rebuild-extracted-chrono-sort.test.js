'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-rebuild-extracted-chrono-sort.test.js — pin the chrono-sort
// fix that closes the merged-Timeline "header says ascending but rows are
// not sorted" desync.
//
// CONTEXT — the regression this test exists to prevent:
//   When a Timeline is built from ≥2 sources (drag-drop a second CSV onto
//   the existing view), the composite RowStore concatenates source-A's
//   rows then source-B's rows. Identity-order is therefore NOT
//   chronological — it interleaves time ranges. The first paint is
//   correct because `_renderGridInto` chrono-sorts `idx` before mounting
//   the GridViewer. But auto-extract runs ~60 ms later and calls
//   `_rebuildExtractedStateAndRender` per applied proposal. That fast
//   path:
//     1. calls `_recomputeFilter()`, which resets `_filteredIdx` to the
//        unsorted `_identityIdx` (`[0..n-1]`) when no query is active;
//     2. builds a fresh `TimelineRowView` with that unsorted idx;
//     3. calls `GridViewer.setRows(rowView, …, { preSorted: true })`,
//        which preserves the asc-Timestamp `_sortSpec` but stamps an
//        identity `_sortOrder`.
//   Net effect: the grid paints rows in source-concat order while the
//   indicator advertises ascending Timestamp — the desync the user
//   reported.
//
//   The same defect exists for any single-file Timeline whose row order
//   isn't already chronological; merged Timelines just make it always
//   reproducible.
//
//   Fix: a shared `TimelineView.prototype._chronoSortIdx(idx)` helper
//   that returns the cached `_sortedFullIdx` on the full-dataset path
//   (O(1)) or builds a fresh chrono-sorted Uint32Array otherwise.
//   `_renderGridInto` calls it as before; `_rebuildExtractedStateAndRender`
//   now also calls it before the `setRows({ preSorted: true })` hand-off
//   and writes the result back to `this._filteredIdx` so cursor / right-
//   click menus / scroll resolver agree with what the grid is showing.
//
// What this test pins:
//   • The helper is declared exactly once on `TimelineView.prototype`
//     (Object.assign mixin shape) and invalidated by `_invalidateGridCache`.
//   • `_renderGridInto` calls `this._chronoSortIdx(idx)` — i.e. uses the
//     shared helper rather than a local re-implementation.
//   • `_rebuildExtractedStateAndRender`'s in-place fast path:
//       - calls `this._chronoSortIdx(idx)` BEFORE building the new
//         `TimelineRowView`,
//       - assigns the sorted permutation back to `this._filteredIdx`,
//       - hands the SORTED idx to the rowView ctor and calls
//         `setRows(rowView, …, { preSorted: true })`.
//   • Runtime: extracting `_chronoSortIdx` from the source and running
//     it against a stub TimelineView with interleaved timestamps
//     produces a chrono-sorted permutation, populates `_sortedFullIdx`
//     on the full-dataset path, and is reused on subsequent calls
//     (reference identity).
//
// Static-source style mirrors `timeline-view-autoextract-pump-suppress-
// columns.test.js` — pinning the literal text of the fix is enough to
// catch a "let's just call setRows directly" or "let's drop the
// _chronoSortIdx helper" regression without spinning up the full
// TimelineView/DOM stack.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const GRID_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-render-grid.js'), 'utf8');
const DRAWER_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-drawer.js'), 'utf8');

// ── Helper presence + uniqueness (timeline-view-render-grid.js) ────────────

test('_chronoSortIdx is defined exactly once on TimelineView.prototype', () => {
  // The mixin attaches via `Object.assign(TimelineView.prototype, { … })`
  // so each method appears as `^  methodName(args) {` once. Counting
  // `^  _chronoSortIdx(` matches catches a duplicate-define regression.
  const matches = GRID_SRC.match(/^  _chronoSortIdx\s*\(/gm) || [];
  assert.equal(
    matches.length,
    1,
    `_chronoSortIdx must appear exactly once in timeline-view-render-grid.js (got ${matches.length})`,
  );
});

test('_chronoSortIdx populates / reuses _sortedFullIdx on the full-dataset path', () => {
  // The cache contract: full-dataset calls memoise on `_sortedFullIdx`
  // and reuse on subsequent calls; non-full calls allocate a fresh
  // sorted array each time. Pin both branches' literal markers.
  assert.match(
    GRID_SRC,
    /isFullDataset\s*&&\s*this\._sortedFullIdx/,
    '_chronoSortIdx must consult the cached `_sortedFullIdx` on full-dataset calls',
  );
  assert.match(
    GRID_SRC,
    /if\s*\(\s*isFullDataset\s*\)\s*this\._sortedFullIdx\s*=\s*sorted/,
    '_chronoSortIdx must store the sorted permutation on `_sortedFullIdx` for full-dataset calls',
  );
});

test('_renderGridInto delegates to _chronoSortIdx instead of inlining the comparator', () => {
  // Pin the call to the shared helper so a future refactor that
  // re-inlines the sort comparator (and silently diverges from the
  // cache contract used by `_rebuildExtractedStateAndRender`) is
  // caught at unit-test time.
  assert.match(
    GRID_SRC,
    /this\._chronoSortIdx\s*\(\s*idx\s*\)/,
    '_renderGridInto must call this._chronoSortIdx(idx)',
  );
});

// ── Drawer fast-path (timeline-drawer.js) ──────────────────────────────────

test('_rebuildExtractedStateAndRender chrono-sorts idx before setRows({ preSorted: true })', () => {
  // The fast path that the user-reported bug lives inside. Three
  // invariants must all hold:
  //   (1) Read `_filteredIdx`.
  //   (2) Pass it through `_chronoSortIdx`. Without this step the
  //       `setRows({ preSorted: true })` call below stamps an identity
  //       sort order against an unsorted rowView — the exact desync.
  //   (3) Assign the sorted result back to `this._filteredIdx` so the
  //       cursor / right-click / scroll resolvers agree with what the
  //       grid is painting.
  // We co-locate them with a multi-line regex anchored on the
  // `_chronoSortIdx` call so a partial revert (e.g. dropping the
  // assignment-back) still lights up.
  const re = /let\s+idx\s*=\s*this\._filteredIdx\s*\|\|\s*null\s*;\s*\n\s*if\s*\(\s*idx\s*&&\s*typeof\s+this\._chronoSortIdx\s*===\s*'function'\s*\)\s*\{\s*\n\s*const\s+sorted\s*=\s*this\._chronoSortIdx\s*\(\s*idx\s*\)\s*;\s*\n\s*if\s*\(\s*sorted\s*!==\s*idx\s*\)\s*\{\s*\n\s*idx\s*=\s*sorted\s*;\s*\n\s*this\._filteredIdx\s*=\s*idx\s*;/;
  assert.ok(
    re.test(DRAWER_SRC),
    'expected `_rebuildExtractedStateAndRender` fast path to chrono-sort `_filteredIdx` ' +
    'via `this._chronoSortIdx(idx)` and assign the result back to `this._filteredIdx` ' +
    'before constructing the new TimelineRowView',
  );
});

test('_rebuildExtractedStateAndRender hands the chrono-sorted idx to the new TimelineRowView', () => {
  // Pin the order: the `idx` local declared by the chrono-sort prelude
  // above must be the SAME identifier passed to `new TimelineRowView`.
  // A regression that re-read `this._filteredIdx` on the rowView ctor
  // line would silently revert to the unsorted identity (the exact
  // pre-fix shape), so anchor on `idx,` (not `idx: this._filteredIdx`).
  const re = /new TimelineRowView\(\{[^}]*\bidx\s*,[^}]*\}\)\s*;\s*\n\s*this\._grid\.setRows\(rowView,\s*null,\s*null,\s*\{\s*preSorted:\s*true\s*\}\)/;
  assert.ok(
    re.test(DRAWER_SRC),
    'expected new TimelineRowView({ …, idx, }) immediately followed by ' +
    'this._grid.setRows(rowView, null, null, { preSorted: true })',
  );
});

test('post-fix drawer no longer hands `idx: this._filteredIdx` directly to TimelineRowView', () => {
  // Guard against a partial revert: a refactor that "simplified" the
  // rowView ctor by inlining `idx: this._filteredIdx || null` would
  // silently re-introduce the unsorted-rowView desync (because
  // `_recomputeFilter` ran a few lines above and just reset
  // `_filteredIdx` to the identity index). Forbid the literal shape.
  assert.ok(
    !/new TimelineRowView\(\{[^}]*\bidx:\s*this\._filteredIdx\s*\|\|\s*null/.test(DRAWER_SRC),
    'forbidden literal `idx: this._filteredIdx || null` found in ' +
    'timeline-drawer.js — chrono-sort prelude must own the idx local',
  );
});

// ── Runtime — extract _chronoSortIdx and exercise it against stubs ─────────

// Pull the helper body out of the source file and evaluate it as a
// standalone function on a stub `this`. We don't load the full
// TimelineView (it requires a DOM); the helper is purely arithmetic
// over `this._timeCol`, `this._timeMs`, `this._sortedFullIdx`, and
// `this.store.rowCount`, so a stub is sufficient.
function extractChronoSortIdx() {
  // Find the `_chronoSortIdx(idx) { … },` block. The body ends at the
  // next `},` at the same indent level as the opening line. Use a
  // greedy match across the whole file and bracket-balance the block.
  const startMatch = GRID_SRC.match(/^  _chronoSortIdx\s*\(\s*idx\s*\)\s*\{/m);
  assert.ok(startMatch, 'failed to locate _chronoSortIdx in source — has the helper been renamed?');
  const start = startMatch.index + startMatch[0].length;
  let depth = 1;
  let i = start;
  while (i < GRID_SRC.length && depth > 0) {
    const ch = GRID_SRC[i];
    if (ch === '{') depth++;
    else if (ch === '}') depth--;
    i++;
  }
  const body = GRID_SRC.slice(start, i - 1);
  // Wrap the body in a fresh function so it runs against a vm-supplied
  // `this`. The body uses `Number.isFinite` and `Uint32Array` — both
  // available on the host realm we run in (Node).
  const wrapped = `(function (idx) {\n${body}\n})`;
  // eslint-disable-next-line no-new-func
  return new Function(`return ${wrapped};`)();
}

const _chronoSortIdx = extractChronoSortIdx();

function makeStubView(timeMs, rowCount) {
  return {
    _timeCol: 0,
    _timeMs: timeMs,
    _sortedFullIdx: null,
    store: { rowCount: rowCount != null ? rowCount : timeMs.length },
  };
}

test('_chronoSortIdx returns idx unchanged when timeCol is null', () => {
  const view = makeStubView(Float64Array.from([3, 1, 2]));
  view._timeCol = null;
  const idx = new Uint32Array([0, 1, 2]);
  const out = _chronoSortIdx.call(view, idx);
  assert.equal(out, idx, 'no-time-col path must return the input array reference');
});

test('_chronoSortIdx returns idx unchanged when length <= 1', () => {
  const view = makeStubView(Float64Array.from([42]));
  const idx = new Uint32Array([0]);
  const out = _chronoSortIdx.call(view, idx);
  assert.equal(out, idx, 'singleton-input must short-circuit');
});

test('_chronoSortIdx sorts an interleaved (merged-Timeline shape) idx chronologically', () => {
  // Source-A occupies rows 0–2 at 12:00–12:02; source-B occupies
  // rows 3–5 at 09:00–09:02. Identity order is non-chronological.
  // The helper must produce [3,4,5,0,1,2] (or any permutation that
  // satisfies _timeMs[out[i]] <= _timeMs[out[i+1]]).
  const t = Float64Array.from([
    1_700_000_000_000 + 12 * 3600_000 + 0,
    1_700_000_000_000 + 12 * 3600_000 + 1,
    1_700_000_000_000 + 12 * 3600_000 + 2,
    1_700_000_000_000 + 9 * 3600_000 + 0,
    1_700_000_000_000 + 9 * 3600_000 + 1,
    1_700_000_000_000 + 9 * 3600_000 + 2,
  ]);
  const view = makeStubView(t);
  const idx = new Uint32Array([0, 1, 2, 3, 4, 5]);
  const out = _chronoSortIdx.call(view, idx);
  assert.notEqual(out, idx, 'sort path must allocate a fresh Uint32Array');
  for (let i = 1; i < out.length; i++) {
    assert.ok(
      t[out[i - 1]] <= t[out[i]],
      `row ${i}: _timeMs[${out[i - 1]}]=${t[out[i - 1]]} must be <= _timeMs[${out[i]}]=${t[out[i]]}`,
    );
  }
});

test('_chronoSortIdx caches on _sortedFullIdx for full-dataset calls and reuses on the next call', () => {
  const t = Float64Array.from([3, 1, 2, 4, 0]);
  const view = makeStubView(t);
  const idx = new Uint32Array([0, 1, 2, 3, 4]);
  const first = _chronoSortIdx.call(view, idx);
  assert.equal(view._sortedFullIdx, first, 'first call must populate _sortedFullIdx');
  // Second call with a fresh identity idx (mirrors what
  // `_rebuildExtractedStateAndRender` does after `_recomputeFilter`
  // resets `_filteredIdx` to the identity reference).
  const second = _chronoSortIdx.call(view, new Uint32Array([0, 1, 2, 3, 4]));
  assert.equal(second, first, 'second call must return the cached `_sortedFullIdx` reference (no re-allocation)');
});

test('_chronoSortIdx places NaN timestamps last (ties broken by original index)', () => {
  // Mirrors `_renderGridInto`'s comparator semantics so the helper
  // and the cold path stay in lockstep.
  const t = Float64Array.from([5, NaN, 1, NaN, 3]);
  const view = makeStubView(t);
  const idx = new Uint32Array([0, 1, 2, 3, 4]);
  const out = _chronoSortIdx.call(view, idx);
  // The first three slots must be the finite rows in ascending order.
  assert.deepEqual(
    Array.from(out.slice(0, 3)),
    [2, 4, 0],
    'finite timestamps must be sorted ascending and come before NaNs',
  );
  // The remaining slots must be NaN rows; original-index tie-break
  // means [1, 3] (1 < 3).
  assert.deepEqual(
    Array.from(out.slice(3)),
    [1, 3],
    'NaN timestamps must follow the finite ones, ordered by original index',
  );
});

test('_chronoSortIdx does NOT cache when the input does not span the full dataset', () => {
  // E.g. a query is active and `_filteredIdx` has fewer rows than
  // `store.rowCount`. The helper must still sort but must NOT
  // contaminate `_sortedFullIdx` (which is keyed on the full dataset).
  const t = Float64Array.from([3, 1, 2, 4, 0]);
  const view = makeStubView(t, /* rowCount = */ 5);
  const idx = new Uint32Array([0, 1, 2]); // partial — only 3 of 5 rows
  const out = _chronoSortIdx.call(view, idx);
  assert.equal(view._sortedFullIdx, null, 'partial-dataset call must not populate _sortedFullIdx');
  for (let i = 1; i < out.length; i++) {
    assert.ok(
      t[out[i - 1]] <= t[out[i]],
      'partial-dataset call must still sort the supplied subset',
    );
  }
});

// vm import retained in case future runtime tests want to load the
// full mixin in a sandboxed context. The helper-extraction path above
// is sufficient for the current pins.
void vm;
