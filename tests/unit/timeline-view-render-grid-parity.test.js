'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-render-grid-parity.test.js — pin the B2f2 split.
//
// B2f2 hoists the grid mount + column top-values cards out of
// `timeline-view.js` into `timeline-view-render-grid.js`. The
// mixin attaches via `Object.assign(TimelineView.prototype,
// {...})`.
//
// Pins:
//   • each method's `methodName(args) {` definition is GONE from
//     `timeline-view.js`
//   • each method appears EXACTLY once in
//     `timeline-view-render-grid.js`
//   • `_scheduleRender` and `_installSplitterDrag` STAY in core
//     (cross-surface dispatchers)
//   • build order: grid mixin loads after `timeline-view.js`
//   • hot-path body anchors survive byte-identical
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const VIEW = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view.js'),
  'utf8',
);
const MIXIN = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-render-grid.js'),
  'utf8',
);
const BUILD = fs.readFileSync(
  path.join(REPO_ROOT, 'scripts/build.py'),
  'utf8',
);

const MOVED_METHODS = [
  // Grid table
  '_renderGrid',
  '_invalidateGridCache',
  '_renderGridInto',
  // Column top-values cards
  '_renderColumns',
  '_paintColumnCards',
  '_commitCardOrder',
  '_susValsForCol',
  '_cardSpanFor',
  '_cardSizeSave',
  '_installCardResize',
  '_columnsGridGeometry',
];

const KEPT_IN_CORE = ['_scheduleRender', '_installSplitterDrag'];

// ── Removal asserts ────────────────────────────────────────────────────────

test('timeline-view.js no longer defines any grid-paint method', () => {
  for (const name of MOVED_METHODS) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.doesNotMatch(
      VIEW,
      re,
      `${name} must be moved to timeline-view-render-grid.js`,
    );
  }
});

test('timeline-view.js KEEPS the cross-surface render methods', () => {
  for (const name of KEPT_IN_CORE) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.match(
      VIEW,
      re,
      `${name} must remain in timeline-view.js — it crosses chart and grid surfaces`,
    );
  }
});

// ── Presence asserts ───────────────────────────────────────────────────────

test('timeline-view-render-grid.js attaches via Object.assign(TimelineView.prototype, ...)', () => {
  assert.match(
    MIXIN,
    /Object\.assign\(\s*TimelineView\.prototype\s*,\s*\{/,
  );
});

test('timeline-view-render-grid.js defines every grid-paint method exactly once', () => {
  for (const name of MOVED_METHODS) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'gm');
    const matches = MIXIN.match(re) || [];
    assert.equal(
      matches.length,
      1,
      `${name} must appear exactly once in timeline-view-render-grid.js (got ${matches.length})`,
    );
  }
});

test('timeline-view-render-grid.js does NOT redefine the cross-surface render methods', () => {
  for (const name of KEPT_IN_CORE) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.doesNotMatch(
      MIXIN,
      re,
      `${name} must NOT be moved to grid mixin — it stays in core`,
    );
  }
});

// ── Body anchors — perf-critical hot paths survive byte-identical ─────────

test('_renderGridInto mounts a GridViewer against _filteredIdx', () => {
  // The `GridViewer` constructor is the entry into the table-paint
  // path; pin the reference + the `_filteredIdx` source-of-truth so a
  // refactor that swapped the index source (or the renderer class)
  // would light up here.
  assert.match(
    MIXIN,
    /new GridViewer\b/,
    '_renderGridInto must mount a GridViewer instance',
  );
});

test('_renderGridInto threads _rawText for sidebar focus', () => {
  // Sidebar click-to-focus reads the grid container's `_rawText`
  // (newline-normalised) — pin so a refactor doesn't silently drop
  // the threading and break in-grid highlight scrolling.
  assert.match(
    MIXIN,
    /_rawText/,
    '_renderGridInto must thread _rawText into the grid container',
  );
});

test('_paintColumnCards consumes the per-column stats produced by the filter mixin', () => {
  // The cards strip reads `this._colStats` (built by
  // `_computeColumnStatsSync`/`Async` in the filter mixin). Pin the
  // contract — if a refactor renamed it, every card would render
  // empty.
  assert.match(
    MIXIN,
    /\bstats\b/,
    '_paintColumnCards must accept a stats parameter',
  );
});

test('_invalidateGridCache clears the sorted-index cache', () => {
  // The cache is invalidated whenever `_timeMs` changes (time-column
  // change, reset, etc.). Pin the symbolic reset so a future
  // refactor that introduced a stale-cache regression lights up.
  assert.match(
    MIXIN,
    /_sortedFullIdx\s*=\s*null/,
    '_invalidateGridCache must null the sorted-index cache',
  );
});

test('_columnsGridGeometry honours the persisted card-size preference', () => {
  // The S/M/L card-size setting drives the CSS-Grid track width;
  // pin `TIMELINE_CARD_SIZES` reference so a refactor that lost the
  // persisted-size lookup is caught.
  assert.match(
    MIXIN,
    /TIMELINE_CARD_SIZES/,
    '_columnsGridGeometry must consult TIMELINE_CARD_SIZES',
  );
});

// ── Build order ────────────────────────────────────────────────────────────

test('scripts/build.py registers timeline-view-render-grid.js after timeline-view.js', () => {
  const viewIdx = BUILD.indexOf("'src/app/timeline/timeline-view.js'");
  const gridIdx = BUILD.indexOf("'src/app/timeline/timeline-view-render-grid.js'");
  assert.notEqual(viewIdx, -1);
  assert.notEqual(gridIdx, -1);
  assert.ok(gridIdx > viewIdx, 'grid mixin must load AFTER timeline-view.js');
});

// ── TimelineDataset invariant ──────────────────────────────────────────────

test('moved grid bodies do not introduce a bare this._evtxEvents reference', () => {
  const stripped = MIXIN
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"])\/\/[^\n]*/g, '$1')
    .replace(/`[\s\S]*?`/g, '``')
    .replace(/"[^"\n]*"/g, '""')
    .replace(/'[^'\n]*'/g, "''");
  assert.doesNotMatch(
    stripped,
    /this\._evtxEvents\b/,
    'timeline-view-render-grid.js must not read this._evtxEvents — use the dataset / store',
  );
});
