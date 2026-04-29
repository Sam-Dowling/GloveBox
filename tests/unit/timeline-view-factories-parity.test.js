'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-factories-parity.test.js — pin the B2a split.
//
// B2a hoists the three TimelineView static factories out of
// `timeline-view.js` into a sibling mixin `timeline-view-factories.js`.
// The mixin attaches the methods via
// `Object.assign(TimelineView, {...})` so callers' surface
// (`TimelineView.fromCsvAsync(...)`, `TimelineView.fromEvtx(...)`,
// `TimelineView.fromSqlite(...)`) is unchanged.
//
// This test pins the migration:
//   • each `static <fn>` definition is GONE from timeline-view.js
//   • each method's body re-appears in timeline-view-factories.js
//     (signature + a representative body anchor)
//   • build order: `timeline-view-factories.js` is in `APP_JS_FILES`
//     immediately after `timeline-view.js`
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
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-factories.js'),
  'utf8',
);
const BUILD = fs.readFileSync(
  path.join(REPO_ROOT, 'scripts/build.py'),
  'utf8',
);

// ── Removal asserts ────────────────────────────────────────────────────────

test('timeline-view.js no longer defines `static async fromCsvAsync`', () => {
  assert.doesNotMatch(
    VIEW,
    /^\s*static\s+async\s+fromCsvAsync\s*\(/m,
    'fromCsvAsync must be moved to timeline-view-factories.js',
  );
});

test('timeline-view.js no longer defines `static async fromEvtx`', () => {
  assert.doesNotMatch(
    VIEW,
    /^\s*static\s+async\s+fromEvtx\s*\(/m,
    'fromEvtx must be moved to timeline-view-factories.js',
  );
});

test('timeline-view.js no longer defines `static fromSqlite`', () => {
  assert.doesNotMatch(
    VIEW,
    /^\s*static\s+fromSqlite\s*\(/m,
    'fromSqlite must be moved to timeline-view-factories.js',
  );
});

// ── Presence asserts ───────────────────────────────────────────────────────

test('timeline-view-factories.js attaches via Object.assign(TimelineView, ...)', () => {
  assert.match(
    MIXIN,
    /Object\.assign\(\s*TimelineView\s*,\s*\{/,
    'mixin must use `Object.assign(TimelineView, {...})` to attach static methods',
  );
});

test('timeline-view-factories.js defines fromCsvAsync with the chunked-decode body', () => {
  assert.match(MIXIN, /\basync\s+fromCsvAsync\s*\(\s*file\s*,\s*buffer\s*,\s*explicitDelim\s*,\s*kindHint\s*\)/);
  // Body anchor: the DECODE_CHUNK constant + the chunked yield helper
  // are both load-bearing and would be tedious to re-derive.
  assert.match(MIXIN, /RENDER_LIMITS\.DECODE_CHUNK_BYTES/);
  assert.match(MIXIN, /MessageChannel/);
  assert.match(MIXIN, /TIMELINE_MAX_ROWS/);
});

test('timeline-view-factories.js defines fromEvtx with analyzeForSecurity threading', () => {
  assert.match(MIXIN, /\basync\s+fromEvtx\s*\(\s*file\s*,\s*buffer\s*\)/);
  // Body anchor: the EVTX factory threads `securityFindings` through to
  // the constructor — this is what feeds the in-view Detections section.
  assert.match(MIXIN, /securityFindings\s*=\s*r\.analyzeForSecurity\(/);
  assert.match(MIXIN, /evtxFindings:\s*securityFindings/);
});

test('timeline-view-factories.js defines fromSqlite with browser-history projection', () => {
  assert.match(MIXIN, /\bfromSqlite\s*\(\s*file\s*,\s*buffer\s*\)/);
  // Body anchors: per-event vs URL-aggregated branches + the browser
  // label string concatenation.
  assert.match(MIXIN, /db\.historyEventRows/);
  assert.match(MIXIN, /db\.browserType\s*===\s*'firefox'/);
});

// ── Build order ────────────────────────────────────────────────────────────

test('scripts/build.py registers timeline-view-factories.js after timeline-view.js', () => {
  const viewIdx = BUILD.indexOf("'src/app/timeline/timeline-view.js'");
  const factIdx = BUILD.indexOf("'src/app/timeline/timeline-view-factories.js'");
  assert.notEqual(viewIdx, -1, 'timeline-view.js must be in APP_JS_FILES');
  assert.notEqual(factIdx, -1, 'timeline-view-factories.js must be in APP_JS_FILES');
  assert.ok(
    factIdx > viewIdx,
    'timeline-view-factories.js must load AFTER timeline-view.js',
  );
});

// ── Sanity — callers' surface is unchanged ─────────────────────────────────

test('callers still reference TimelineView.fromCsvAsync / fromEvtx / fromSqlite', () => {
  // The router is the canonical caller. If B2a accidentally renamed a
  // method, the router would now call something undefined.
  const router = fs.readFileSync(
    path.join(REPO_ROOT, 'src/app/timeline/timeline-router.js'),
    'utf8',
  );
  assert.match(router, /TimelineView\.fromCsvAsync\b/);
  assert.match(router, /TimelineView\.fromEvtx\b/);
  assert.match(router, /TimelineView\.fromSqlite\b/);
});
