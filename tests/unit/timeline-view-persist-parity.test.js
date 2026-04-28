'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-persist-parity.test.js — pin the B2b split.
//
// B2b hoists the ~30 `_loadXxx` / `_saveXxx` localStorage helpers out
// of `timeline-view.js` into `timeline-view-persist.js`. The mixin
// attaches them via `Object.assign(TimelineView, {...})` so callers
// reach them as `TimelineView._loadBucketPref()` etc. unchanged.
//
// Pins:
//   • each `_loadXxx` / `_saveXxx` definition is GONE from
//     `timeline-view.js`
//   • each definition appears EXACTLY once in
//     `timeline-view-persist.js`
//   • the TIMELINE_KEYS reference inventory matches between the
//     pre-B2b state (read from the persist file post-move) and the
//     callers in `timeline-view.js` (read access for construction-
//     time hydration is unchanged)
//   • `loupe_*` storage keys never appear bare in either file
//     (everything routes through `TIMELINE_KEYS.*`)
//   • build order: persist mixin loads after timeline-view.js
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
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-persist.js'),
  'utf8',
);
const BUILD = fs.readFileSync(
  path.join(REPO_ROOT, 'scripts/build.py'),
  'utf8',
);

// Canonical list of methods that must move (15 load/save pairs = 30
// methods). If a future commit adds a 31st helper, update this list.
const PERSIST_METHODS = [
  '_loadBucketPref',         '_saveBucketPref',
  '_loadGridH',              '_saveGridH',
  '_loadChartH',             '_saveChartH',
  '_loadSections',           '_saveSections',
  '_loadCardWidthsFor',      '_saveCardWidthsFor',
  '_loadCardOrderFor',       '_saveCardOrderFor',
  '_loadPinnedColsFor',      '_savePinnedColsFor',
  '_loadEntPinnedFor',       '_saveEntPinnedFor',
  '_loadEntOrderFor',        '_saveEntOrderFor',
  '_loadDetectionsGroup',    '_saveDetectionsGroup',
  '_loadRegexExtractsFor',   '_saveRegexExtractsFor',
  '_loadAutoExtractDoneFor', '_saveAutoExtractDoneFor',
  '_loadPivotSpec',          '_savePivotSpec',
  '_loadQueryFor',           '_saveQueryFor',
  '_loadSusMarksFor',        '_saveSusMarksFor',
];

// ── Removal asserts ────────────────────────────────────────────────────────

test('timeline-view.js no longer defines any _load/_save persist helper', () => {
  for (const name of PERSIST_METHODS) {
    // Match `static methodName(`  (the original definition shape).
    const re = new RegExp(`^\\s*static\\s+${name}\\s*\\(`, 'm');
    assert.doesNotMatch(
      VIEW,
      re,
      `${name} must be moved to timeline-view-persist.js`,
    );
  }
});

// ── Presence asserts ───────────────────────────────────────────────────────

test('timeline-view-persist.js attaches via Object.assign(TimelineView, ...)', () => {
  assert.match(
    MIXIN,
    /Object\.assign\(\s*TimelineView\s*,\s*\{/,
    'mixin must use `Object.assign(TimelineView, {...})` to attach static methods',
  );
});

test('timeline-view-persist.js defines every _load/_save helper exactly once', () => {
  for (const name of PERSIST_METHODS) {
    // Object-literal shorthand: `methodName(args) {` at start-of-line
    // indented 2 spaces (matching the file's formatting).
    const re = new RegExp(`^\\s+${name}\\s*\\(`, 'gm');
    const matches = MIXIN.match(re) || [];
    assert.equal(
      matches.length,
      1,
      `${name} must appear exactly once in timeline-view-persist.js (got ${matches.length})`,
    );
  }
});

// ── Storage-key inventory ──────────────────────────────────────────────────

test('TIMELINE_KEYS inventory in timeline-view-persist.js is the canonical 15-key set', () => {
  // The 15 keys these helpers are responsible for. Any change here
  // would be a localStorage format break — bump CONTRIBUTING.md's
  // Persistence Keys table in the same commit if you have a real
  // reason to do so.
  const EXPECTED_KEYS = [
    'AUTOEXTRACT_DONE', 'BUCKET', 'CARD_ORDER', 'CARD_WIDTHS',
    'CHART_H', 'DETECTIONS_GROUP', 'ENT_ORDER', 'ENT_PINNED',
    'GRID_H', 'PINNED_COLS', 'PIVOT', 'QUERY', 'REGEX_EXTRACTS',
    'SECTIONS', 'SUS_MARKS',
  ];
  const found = new Set();
  const re = /TIMELINE_KEYS\.([A-Z_]+)/g;
  let m;
  while ((m = re.exec(MIXIN)) !== null) found.add(m[1]);
  for (const key of EXPECTED_KEYS) {
    assert.ok(
      found.has(key),
      `TIMELINE_KEYS.${key} must appear in timeline-view-persist.js`,
    );
  }
  // Reverse direction — no rogue keys snuck in.
  for (const key of found) {
    assert.ok(
      EXPECTED_KEYS.includes(key),
      `Unexpected TIMELINE_KEYS.${key} in timeline-view-persist.js — update test or revert`,
    );
  }
});

test('no bare `loupe_` storage keys in timeline-view-persist.js (all route through TIMELINE_KEYS)', () => {
  // The `safeStorage` wrapper always receives `TIMELINE_KEYS.X`, never
  // a hand-typed `'loupe_timeline_xxx'`. A bare key would silently
  // bypass the namespace constants and could collide with a renamed
  // entry in `TIMELINE_KEYS`.
  // Strip comments + string literals first so explanatory comments
  // don't trip the test.
  const stripped = MIXIN
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"])\/\/[^\n]*/g, '$1')
    .replace(/`[\s\S]*?`/g, '``')
    .replace(/"[^"\n]*"/g, '""')
    .replace(/'[^'\n]*'/g, "''");
  assert.doesNotMatch(
    stripped,
    /\bloupe_[a-z_]+/,
    'bare `loupe_*` key found — route through TIMELINE_KEYS instead',
  );
});

// ── Build order ────────────────────────────────────────────────────────────

test('scripts/build.py registers timeline-view-persist.js after timeline-view.js', () => {
  const viewIdx = BUILD.indexOf("'src/app/timeline/timeline-view.js'");
  const persistIdx = BUILD.indexOf("'src/app/timeline/timeline-view-persist.js'");
  assert.notEqual(viewIdx, -1);
  assert.notEqual(persistIdx, -1);
  assert.ok(persistIdx > viewIdx, 'persist mixin must load AFTER timeline-view.js');
});

// ── Caller surface ─────────────────────────────────────────────────────────

test('callers still reach the persist helpers via TimelineView.<methodName>', () => {
  // Construction-time hydration in `timeline-view.js` and other
  // sibling mixins reads several persist helpers via
  // `TimelineView._loadXxx(...)`. Pin the most load-bearing ones —
  // if any of these stops resolving, the view defaults its entire
  // persisted state to nothing on every reload.
  //
  // We scan both `timeline-view.js` AND the sibling mixins because
  // call sites have migrated as the B2 split progressed (e.g.
  // `_loadAutoExtractDoneFor` callers moved into
  // `timeline-view-autoextract.js` during B2e).
  const SIBLING_FILES = [
    'src/app/timeline/timeline-view.js',
    'src/app/timeline/timeline-view-factories.js',
    'src/app/timeline/timeline-view-filter.js',
    'src/app/timeline/timeline-view-popovers.js',
    'src/app/timeline/timeline-view-autoextract.js',
  ];
  const COMBINED = SIBLING_FILES
    .map(p => {
      try { return fs.readFileSync(path.join(REPO_ROOT, p), 'utf8'); }
      catch (_) { return ''; }
    })
    .join('\n');
  const SENTINELS = [
    'TimelineView._loadBucketPref',
    'TimelineView._loadSusMarksFor',
    'TimelineView._loadQueryFor',
    'TimelineView._loadAutoExtractDoneFor',
  ];
  for (const s of SENTINELS) {
    assert.ok(
      COMBINED.includes(s),
      `${s} caller still expected somewhere in the timeline-view family after B2`,
    );
  }
});
