'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-autoextract-parity.test.js — pin the B2e split.
//
// B2e hoists the silent first-open auto-extract pass and the
// heuristic scanner out of `timeline-view.js` into
// `timeline-view-autoextract.js`. The mixin attaches via
// `Object.assign(TimelineView.prototype, {...})`.
//
// Pins:
//   • each method's `methodName(args) {` definition is GONE from
//     `timeline-view.js`
//   • each method appears EXACTLY once in
//     `timeline-view-autoextract.js`
//   • build order: autoextract mixin loads AFTER `timeline-drawer.js`
//     (that's where `_addJsonExtractedColNoRender` /
//     `_addRegexExtractNoRender` / `_rebuildExtractedStateAndRender`
//     live)
//   • the `requestIdleCallback` / `setTimeout(0)` Safari fallback
//     scheduling pattern survives byte-identical (perf-load-bearing)
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
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-autoextract.js'),
  'utf8',
);
const BUILD = fs.readFileSync(
  path.join(REPO_ROOT, 'scripts/build.py'),
  'utf8',
);

const MOVED_METHODS = [
  '_autoExtractBestEffort',
  '_applyAutoProposal',
  '_autoExtractScan',
];

// ── Removal asserts ────────────────────────────────────────────────────────

test('timeline-view.js no longer defines any auto-extract method', () => {
  for (const name of MOVED_METHODS) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.doesNotMatch(
      VIEW,
      re,
      `${name} must be moved to timeline-view-autoextract.js`,
    );
  }
});

// ── Presence asserts ───────────────────────────────────────────────────────

test('timeline-view-autoextract.js attaches via Object.assign(TimelineView.prototype, ...)', () => {
  assert.match(
    MIXIN,
    /Object\.assign\(\s*TimelineView\.prototype\s*,\s*\{/,
  );
});

test('timeline-view-autoextract.js defines every auto-extract method exactly once', () => {
  for (const name of MOVED_METHODS) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'gm');
    const matches = MIXIN.match(re) || [];
    assert.equal(
      matches.length,
      1,
      `${name} must appear exactly once in timeline-view-autoextract.js (got ${matches.length})`,
    );
  }
});

// ── Body anchors — perf / correctness invariants survive ───────────────────

test('_autoExtractBestEffort idle-tick scheduling survives', () => {
  // The `requestIdleCallback` with `setTimeout(0)` Safari fallback is the
  // load-bearing scheduler that turned the post-mount LongTask cluster
  // into a series of paint-friendly idle ticks. Pin so a refactor that
  // collapsed it back to a synchronous loop lights up here.
  assert.match(
    MIXIN,
    /requestIdleCallback/,
    '_autoExtractBestEffort lost its requestIdleCallback path',
  );
  assert.match(
    MIXIN,
    /setTimeout\([^,]+,\s*0\)/,
    '_autoExtractBestEffort lost its setTimeout(0) Safari fallback',
  );
});

test('_autoExtractBestEffort writes the done-marker via persist mixin', () => {
  // Idempotence: the per-file marker
  // (`loupe_timeline_autoextract_done_<fileKey>`) prevents re-adding
  // user-deleted columns on reopen. Pin the call into the B2b persist
  // mixin so a regression that drops the marker write is caught.
  assert.match(
    MIXIN,
    /TimelineView\._saveAutoExtractDoneFor\(/,
    '_autoExtractBestEffort must persist the done-marker via the persist mixin',
  );
});

test('_applyAutoProposal dispatches all 6 known kinds', () => {
  // The proposal kinds drive which extractor runs; pin each so a
  // refactor that collapses kinds (or renames one) breaks visibly.
  for (const kind of [
    'json-url', 'json-host', 'json-leaf',
    'text-url', 'text-host', 'url-part',
  ]) {
    assert.match(
      MIXIN,
      new RegExp(`['"\`]${kind}['"\`]`),
      `_applyAutoProposal lost its '${kind}' branch`,
    );
  }
});

test('_autoExtractScan caps at 200 sample rows', () => {
  // The 200-row sample cap is the perf budget — pin it so a future
  // "let's just scan everything" regression is caught here. The
  // scanner runs synchronously, so removing the cap would block the
  // first-paint path on million-row CSVs.
  assert.match(
    MIXIN,
    /Math\.min\(this\.store\.rowCount,\s*200\)/,
    '_autoExtractScan lost its 200-row sample cap',
  );
});

test('_autoExtractBestEffort refreshes per proposal (no batched rebuild)', () => {
  // Anti-flash invariant: the apply loop calls
  // `_rebuildExtractedStateAndRender` from inside the per-proposal idle
  // tick (so each new column slides into the live GridViewer via
  // `_updateColumns` one tick at a time) rather than coalescing a
  // single rebuild at the end of the batch (which manifested visually
  // as a "blink" of the freshly-mounted grid). Pin the call site
  // inside the apply step so a refactor that re-batches the rebuild
  // is caught here. The check is structural — we look for the call
  // appearing inside the body that also references `_applyAutoProposal`.
  const applyBlock = MIXIN.match(/_applyAutoProposal[\s\S]*?_autoExtractIdleHandle\s*=\s*schedule\(applyStep\)/);
  assert.ok(
    applyBlock,
    '_autoExtractBestEffort apply loop missing — refactor changed the scheduler shape',
  );
  assert.match(
    applyBlock[0],
    /_rebuildExtractedStateAndRender\s*\(/,
    '_autoExtractBestEffort must call _rebuildExtractedStateAndRender inside the per-proposal apply step (not after the batch)',
  );
});

// ── Build order ────────────────────────────────────────────────────────────

test('scripts/build.py registers timeline-view-autoextract.js after timeline-drawer.js', () => {
  // Critical dep: this mixin calls `_addJsonExtractedColNoRender` /
  // `_addRegexExtractNoRender` / `_rebuildExtractedStateAndRender`,
  // all defined in `timeline-drawer.js`. Loading earlier would
  // attach the auto-extract methods, but they'd reference helpers
  // that aren't yet on the prototype — silent ReferenceError at
  // first-open auto-extract time.
  const drawerIdx = BUILD.indexOf("'src/app/timeline/timeline-drawer.js'");
  const autoIdx = BUILD.indexOf("'src/app/timeline/timeline-view-autoextract.js'");
  assert.notEqual(drawerIdx, -1);
  assert.notEqual(autoIdx, -1);
  assert.ok(
    autoIdx > drawerIdx,
    'autoextract mixin must load AFTER timeline-drawer.js',
  );
});

// ── TimelineDataset invariant ──────────────────────────────────────────────

test('moved auto-extract bodies do not introduce a bare this._evtxEvents reference', () => {
  // B1 invariant: typed-array slots and `this.store` are the
  // canonical paths.
  const stripped = MIXIN
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"])\/\/[^\n]*/g, '$1')
    .replace(/`[\s\S]*?`/g, '``')
    .replace(/"[^"\n]*"/g, '""')
    .replace(/'[^'\n]*'/g, "''");
  assert.doesNotMatch(
    stripped,
    /this\._evtxEvents\b/,
    'timeline-view-autoextract.js must not read this._evtxEvents — use the dataset / store',
  );
});
