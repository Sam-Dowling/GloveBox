'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-dataset.test.js — TimelineDataset cardinality invariant +
// read API + mutation API.
//
// TimelineDataset is the wrapper that owns the four parallel-array
// slots (`store` / `_timeMs` / `_evtxEvents` / `_extractedCols`)
// previously inlined on TimelineView. The previous arrangement let
// any new caller introduce a fresh parallel-array desync — which is
// exactly what the §2.1 sync-EVTX bug did. Centralising the
// `length === store.rowCount` invariant means future fifth slots
// land in one place.
//
// Coverage:
//   • Constructor invariant on every parallel-array slot.
//   • Type checks on opts (timeMs must be Float64Array; evtxEvents
//     must be Array or null; extractedCols entries must have a
//     `values: string[]`).
//   • Read API — cellAt / timeAt / evtxAt / extractedAt OOB
//     behaviour and hit cases against a real RowStore.
//   • Mutation API — setTimeMs / addExtractedCol /
//     removeExtractedCol / clearExtractedCols re-validate the
//     invariant and operate in place where promised.
//   • Reference-sharing contract — extractedCols is held BY
//     REFERENCE (not sliced). This is intentional, documented, and
//     load-bearing for the migration window where TimelineView still
//     does in-place `_extractedCols.push(...)`. A regression that
//     reverted to a defensive `.slice()` would silently desync the
//     view and the dataset; this test pins it.
//   • Bundle membership — a static-source assert that
//     `timeline-dataset.js` is in `APP_JS_FILES` (the build prepends
//     it before `timeline-view.js`).
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle.js');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

// TimelineDataset depends on the RowStore *shape* (rowCount, getCell,
// columns, colCount). We load both files so we can build a real
// store and feed it in — no fakes, no shape drift.
const ctx = loadModules(
  ['src/row-store.js', 'src/app/timeline/timeline-dataset.js'],
  { expose: ['RowStore', 'RowStoreBuilder', 'TimelineDataset'] },
);
const { RowStore, TimelineDataset } = ctx;

// Helper — build a small RowStore with deterministic content so the
// read-API tests have something to verify against.
function makeStore(cols, rows) {
  return RowStore.fromStringMatrix(cols, rows);
}

// ── Smoke ──────────────────────────────────────────────────────────────────

test('TimelineDataset is a constructor', () => {
  assert.equal(typeof TimelineDataset, 'function');
});

// ── Constructor — type checks ──────────────────────────────────────────────

test('constructor rejects missing or non-RowStore opts.store', () => {
  assert.throws(
    () => new TimelineDataset({}),
    /opts\.store must be a RowStore-shaped object/,
  );
  assert.throws(
    () => new TimelineDataset({ store: { rowCount: 0 } }),
    /opts\.store must be a RowStore-shaped object/,
  );
});

test('constructor rejects non-Float64Array timeMs', () => {
  const store = makeStore(['a'], [['x']]);
  assert.throws(
    () => new TimelineDataset({ store, timeMs: [0] }),
    /opts\.timeMs must be a Float64Array/,
  );
  assert.throws(
    () => new TimelineDataset({ store, timeMs: new Uint32Array(1) }),
    /opts\.timeMs must be a Float64Array/,
  );
});

test('constructor rejects non-array evtxEvents', () => {
  const store = makeStore(['a'], [['x']]);
  assert.throws(
    () => new TimelineDataset({ store, evtxEvents: 'oops' }),
    /opts\.evtxEvents must be an Array or null/,
  );
});

test('constructor allocates a zero-filled Float64Array when timeMs is omitted', () => {
  const store = makeStore(['a'], [['x'], ['y'], ['z']]);
  const ds = new TimelineDataset({ store });
  assert.ok(ds.timeMs instanceof Float64Array);
  assert.equal(ds.timeMs.length, 3);
  assert.equal(ds.timeAt(0), 0);
  assert.equal(ds.timeAt(2), 0);
});

// ── Constructor — cardinality invariant ────────────────────────────────────

test('constructor throws when timeMs.length !== store.rowCount', () => {
  const store = makeStore(['a'], [['x'], ['y']]); // rowCount = 2
  assert.throws(
    () => new TimelineDataset({ store, timeMs: new Float64Array(1) }),
    /timeMs\.length \(1\) must equal store\.rowCount \(2\)/,
  );
  assert.throws(
    () => new TimelineDataset({ store, timeMs: new Float64Array(3) }),
    /timeMs\.length \(3\) must equal store\.rowCount \(2\)/,
  );
});

test('constructor throws when evtxEvents.length !== store.rowCount', () => {
  const store = makeStore(['a'], [['x'], ['y'], ['z']]); // rowCount = 3
  // Mirrors the §2.1 sync EVTX regression: caller passed a 5-event
  // array against a 3-row store.
  assert.throws(
    () => new TimelineDataset({
      store,
      evtxEvents: [{}, {}, {}, {}, {}],
    }),
    /evtxEvents\.length \(5\) must equal store\.rowCount \(3\)/,
  );
});

test('constructor throws when extractedCols entries are missing values', () => {
  const store = makeStore(['a'], [['x']]);
  assert.throws(
    () => new TimelineDataset({
      store,
      extractedCols: [{ name: 'bad' }],
    }),
    /extractedCols\[0\] must have a values:string\[\] array/,
  );
});

test('constructor throws when extractedCols[i].values.length !== rowCount', () => {
  const store = makeStore(['a'], [['x'], ['y']]); // rowCount = 2
  assert.throws(
    () => new TimelineDataset({
      store,
      extractedCols: [
        { name: 'first',  values: ['p', 'q'] },
        { name: 'second', values: ['only-one'] },
      ],
    }),
    /extractedCols\[1\]\.values\.length \(1\) must equal store\.rowCount \(2\)/,
  );
});

test('constructor accepts a fully-valid bundle', () => {
  const store = makeStore(['col'], [['a'], ['b'], ['c']]);
  const ds = new TimelineDataset({
    store,
    timeMs:      new Float64Array([10, 20, 30]),
    evtxEvents:  [{ id: 1 }, { id: 2 }, { id: 3 }],
    extractedCols: [{ name: 'extra', values: ['p', 'q', 'r'] }],
  });
  assert.equal(ds.rowCount, 3);
  assert.equal(ds.baseColCount, 1);
  assert.equal(ds.totalColCount, 2);
  assert.equal(ds.extractedCount, 1);
});

// ── Read API ───────────────────────────────────────────────────────────────

test('cellAt returns base cells for col < baseColCount', () => {
  const store = makeStore(['a', 'b'], [['1', '2'], ['3', '4']]);
  const ds = new TimelineDataset({ store });
  assert.equal(ds.cellAt(0, 0), '1');
  assert.equal(ds.cellAt(0, 1), '2');
  assert.equal(ds.cellAt(1, 0), '3');
  assert.equal(ds.cellAt(1, 1), '4');
});

test('cellAt returns extracted-col values for col >= baseColCount', () => {
  const store = makeStore(['a'], [['x'], ['y'], ['z']]);
  const ds = new TimelineDataset({
    store,
    extractedCols: [
      { name: 'ext1', values: ['P', 'Q', 'R'] },
      { name: 'ext2', values: ['ι', 'κ', 'λ'] },
    ],
  });
  assert.equal(ds.cellAt(0, 1), 'P'); // first extracted, row 0
  assert.equal(ds.cellAt(2, 2), 'λ'); // second extracted, row 2
});

test('cellAt returns "" for OOB indices in either axis', () => {
  const store = makeStore(['a'], [['x']]);
  const ds = new TimelineDataset({
    store,
    extractedCols: [{ name: 'ext', values: ['P'] }],
  });
  assert.equal(ds.cellAt(-1, 0), '');
  assert.equal(ds.cellAt(99, 0), '');
  assert.equal(ds.cellAt(0, -1), '');
  assert.equal(ds.cellAt(0, 99), '');
  // Extracted col, OOB row.
  assert.equal(ds.cellAt(99, 1), '');
});

test('cellAt coerces null/undefined extracted values to ""', () => {
  const store = makeStore(['a'], [['x'], ['y']]);
  const ds = new TimelineDataset({
    store,
    extractedCols: [{ name: 'ext', values: [null, undefined] }],
  });
  assert.equal(ds.cellAt(0, 1), '');
  assert.equal(ds.cellAt(1, 1), '');
});

test('timeAt returns the parsed timestamp / NaN for OOB', () => {
  const store = makeStore(['t'], [['1'], ['2'], ['3']]);
  const tm = new Float64Array([100, NaN, 300]);
  const ds = new TimelineDataset({ store, timeMs: tm });
  assert.equal(ds.timeAt(0), 100);
  assert.ok(Number.isNaN(ds.timeAt(1)));
  assert.equal(ds.timeAt(2), 300);
  assert.ok(Number.isNaN(ds.timeAt(-1)));
  assert.ok(Number.isNaN(ds.timeAt(3)));
});

test('evtxAt returns null when evtxEvents is null (non-EVTX dataset)', () => {
  const store = makeStore(['a'], [['x'], ['y']]);
  const ds = new TimelineDataset({ store });
  assert.equal(ds.evtxAt(0), null);
  assert.equal(ds.evtxAt(1), null);
});

test('evtxAt returns the per-row EVTX object', () => {
  const store = makeStore(['a'], [['x'], ['y']]);
  const ev0 = { id: 4624 };
  const ev1 = { id: 4625 };
  const ds = new TimelineDataset({ store, evtxEvents: [ev0, ev1] });
  assert.strictEqual(ds.evtxAt(0), ev0);
  assert.strictEqual(ds.evtxAt(1), ev1);
  assert.equal(ds.evtxAt(-1), null);
  assert.equal(ds.evtxAt(2), null);
});

test('extractedAt addresses by extracted-col index, not total-col index', () => {
  const store = makeStore(['a', 'b'], [['1', '2'], ['3', '4']]);
  const ds = new TimelineDataset({
    store,
    extractedCols: [
      { name: 'first',  values: ['P', 'Q'] },
      { name: 'second', values: ['X', 'Y'] },
    ],
  });
  // extractedAt is 0-indexed against the extracted list, NOT offset
  // by baseColCount. The migration plan keeps this asymmetric on
  // purpose — callers that already know they want an extracted col
  // shouldn't have to thread baseColCount.
  assert.equal(ds.extractedAt(0, 0), 'P');
  assert.equal(ds.extractedAt(1, 0), 'Q');
  assert.equal(ds.extractedAt(0, 1), 'X');
  assert.equal(ds.extractedAt(1, 1), 'Y');
  // OOB → ''
  assert.equal(ds.extractedAt(0, 99), '');
  assert.equal(ds.extractedAt(99, 0), '');
});

test('allColumnNames concatenates base + extracted names in order', () => {
  const store = makeStore(['t', 'msg'], [['1', 'a']]);
  const ds = new TimelineDataset({
    store,
    extractedCols: [
      { name: 'src',  values: ['x'] },
      { name: 'dest', values: ['y'] },
    ],
  });
  assert.deepEqual(ds.allColumnNames(), ['t', 'msg', 'src', 'dest']);
});

test('extractedColumns() returns a defensive copy', () => {
  const store = makeStore(['a'], [['x']]);
  const ds = new TimelineDataset({
    store,
    extractedCols: [{ name: 'ext', values: ['P'] }],
  });
  const snap = ds.extractedColumns();
  snap.push({ name: 'sneak', values: ['Z'] });
  // Mutating the snapshot must not change the dataset's view.
  assert.equal(ds.extractedCount, 1);
  assert.equal(ds.cellAt(0, 1), 'P');
});

// ── Reference-sharing contract (load-bearing during migration) ─────────────

test('extractedCols is shared BY REFERENCE (not sliced) — load-bearing', () => {
  // During the B1b/B1c migration window, TimelineView still does
  // in-place `this._extractedCols.push({...})` from a dozen entry
  // points. The dataset MUST observe those mutations through the
  // shared array reference, otherwise reads via `cellAt` would
  // silently miss every newly-added column. This is the precise
  // failure mode the comment in `timeline-dataset.js` warns about.
  const store = makeStore(['a'], [['x'], ['y']]);
  const owned = [];
  const ds = new TimelineDataset({ store, extractedCols: owned });
  // Mutate the caller-owned array IN PLACE.
  owned.push({ name: 'new-ext', values: ['P', 'Q'] });
  // Dataset reads see the new column without any setter call.
  assert.equal(ds.extractedCount, 1);
  assert.equal(ds.cellAt(0, 1), 'P');
  assert.equal(ds.cellAt(1, 1), 'Q');
  assert.equal(ds.totalColCount, 2);
});

// ── Mutation API ───────────────────────────────────────────────────────────

test('setTimeMs replaces the typed array and re-validates length', () => {
  const store = makeStore(['a'], [['x'], ['y']]);
  const ds = new TimelineDataset({ store });
  const next = new Float64Array([10, 20]);
  ds.setTimeMs(next);
  assert.equal(ds.timeAt(0), 10);
  assert.equal(ds.timeAt(1), 20);
  // Bad length → throw.
  assert.throws(
    () => ds.setTimeMs(new Float64Array(1)),
    /arr\.length \(1\) must equal rowCount \(2\)/,
  );
  // Bad type → throw.
  assert.throws(
    () => ds.setTimeMs([1, 2]),
    /arr must be a Float64Array/,
  );
});

test('addExtractedCol appends and validates length', () => {
  const store = makeStore(['a'], [['x'], ['y']]);
  const ds = new TimelineDataset({ store });
  const n = ds.addExtractedCol({ name: 'first', values: ['P', 'Q'] });
  assert.equal(n, 1);
  assert.equal(ds.cellAt(0, 1), 'P');
  // Wrong length → throw, list unchanged.
  assert.throws(
    () => ds.addExtractedCol({ name: 'bad', values: ['only-one'] }),
    /values\.length \(1\) must equal rowCount \(2\)/,
  );
  assert.equal(ds.extractedCount, 1);
  // Missing values array → type error.
  assert.throws(
    () => ds.addExtractedCol({ name: 'no-values' }),
    /must have a values:string\[\] array/,
  );
});

test('removeExtractedCol drops the entry at extIdx (no-op for OOB)', () => {
  const store = makeStore(['a'], [['x']]);
  const ds = new TimelineDataset({
    store,
    extractedCols: [
      { name: 'first',  values: ['P'] },
      { name: 'second', values: ['Q'] },
    ],
  });
  ds.removeExtractedCol(0);
  assert.equal(ds.extractedCount, 1);
  assert.equal(ds.cellAt(0, 1), 'Q');
  // OOB → no-op.
  ds.removeExtractedCol(99);
  ds.removeExtractedCol(-1);
  assert.equal(ds.extractedCount, 1);
});

test('clearExtractedCols mutates the array IN PLACE', () => {
  // Critical for migration: TimelineView.reset() calls
  // `this._extractedCols.length = 0` and the dataset must see it via
  // the shared reference. Symmetrically, `clearExtractedCols()`
  // must zero-length the SAME array (not assign a fresh `[]`),
  // otherwise the view's `this._extractedCols` would still point at
  // the old populated array.
  const store = makeStore(['a'], [['x']]);
  const owned = [
    { name: 'first',  values: ['P'] },
    { name: 'second', values: ['Q'] },
  ];
  const ds = new TimelineDataset({ store, extractedCols: owned });
  ds.clearExtractedCols();
  assert.equal(ds.extractedCount, 0);
  // The original caller-owned array reference must now be empty too —
  // proves we cleared in place rather than swapped.
  assert.equal(owned.length, 0);
});

// ── Bundle membership ──────────────────────────────────────────────────────

test('timeline-dataset.js is registered in build APP_JS_FILES', () => {
  // `scripts/build.py` concatenates JS files in a load-bearing
  // order; `timeline-dataset.js` must appear before
  // `timeline-view.js` (the view constructs a dataset). A future
  // hand-edit that drops the file from `APP_JS_FILES` would make
  // the bundle reference an undefined `TimelineDataset` symbol.
  const buildPy = fs.readFileSync(
    path.join(REPO_ROOT, 'scripts/build.py'),
    'utf8',
  );
  const dsIdx = buildPy.indexOf("'src/app/timeline/timeline-dataset.js'");
  const viewIdx = buildPy.indexOf("'src/app/timeline/timeline-view.js'");
  assert.notEqual(dsIdx, -1, 'timeline-dataset.js must be listed in APP_JS_FILES');
  assert.notEqual(viewIdx, -1, 'timeline-view.js must be listed in APP_JS_FILES');
  assert.ok(
    dsIdx < viewIdx,
    'timeline-dataset.js must precede timeline-view.js in APP_JS_FILES',
  );
});
