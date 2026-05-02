'use strict';
// ════════════════════════════════════════════════════════════════════════════
// app-load-set-render-result.test.js — pin the contract of
// `App.prototype._setRenderResult` (the *only* `_renderEpoch++` site
// in the codebase).
//
// Why this test matters
// ---------------------
// `_setRenderResult` is the single chokepoint that bumps the render-
// epoch counter and swaps in a fresh `currentResult`. Every other write
// to `app.currentResult` / `app._renderEpoch` is either
//
//   • a `_renderEpoch += 1` in `_setRenderResult` itself (this method), or
//   • a fresh-skeleton swap inside `RenderRoute._orphanInFlight` that
//     deliberately does *not* bump the epoch (see render-route.js header
//     and `06cbb04` — bumping there blanks the page on every fallback).
//
// Two regressions have shipped against this pair before:
//
//   • `06cbb04` — `_orphanInFlight` accidentally bumped the epoch and
//     blanked the page on every fallback (Phase-1/C3 ship-stopper).
//   • `58b6778` — caller-owned epoch + worker-channel cancellation
//     cleanup; workers must capture the epoch at dispatch time.
//
// The unit-test contract guards five invariants of the pure logic
// (constructed App + direct method invocation; no DOM, no real load):
//
//   1. The method increments `_renderEpoch` by exactly +1 per call.
//   2. The method returns the *new* epoch (callers thread the captured
//      value into `RenderRoute.run(..., epoch)` for cross-load fencing).
//   3. The method swaps `currentResult` with the supplied value.
//   4. The method clears `_yaraHighlightActiveView` and
//      `_iocCsvHighlightActiveView` so a stale GridViewer pointer can
//      never reach `_clearYaraHighlight` / `_clearIocCsvHighlight` on
//      the next view-transition.
//   5. The first call from a freshly-constructed App lands at epoch 1
//      (the constructor seeds `_renderEpoch = 0`).
//
// We deliberately do *not* exercise `_loadFile` — it requires a real DOM,
// the renderer registry, the watchdog, the hashing pipeline, and a dozen
// mixins. The full pipeline is covered by the e2e fixture matrix; this
// unit test is just the surgical guard around the single most-broken
// invariant in the codebase.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// Load order matches `scripts/build.py::JS_FILES`: constants → archive-budget
// → app-core (defines `App` + `extendApp`) → app-load (extendApp({...})).
// app-load only mixes methods onto `App.prototype`; nothing in its
// top-level executes any I/O, so loading the file is side-effect-free
// once `extendApp` exists.
const ctx = loadModules(
  [
    'src/constants.js',
    'src/archive-budget.js',
    'src/app/app-core.js',
    'src/app/app-load.js',
  ],
  { expose: ['App', 'extendApp'] },
);
const { App } = ctx;

test('_setRenderResult exists on App.prototype', () => {
  assert.equal(typeof App.prototype._setRenderResult, 'function',
    '_setRenderResult must be defined on App.prototype after app-load.js loads');
});

test('_setRenderResult increments _renderEpoch by exactly +1 per call', () => {
  const app = new App();
  // Constructor seeds `_renderEpoch = 0`.
  assert.equal(app._renderEpoch, 0, 'fresh App must start at epoch 0');
  const e1 = app._setRenderResult({ marker: 'first' });
  assert.equal(e1, 1);
  assert.equal(app._renderEpoch, 1);
  const e2 = app._setRenderResult({ marker: 'second' });
  assert.equal(e2, 2);
  assert.equal(app._renderEpoch, 2);
  const e3 = app._setRenderResult({ marker: 'third' });
  assert.equal(e3, 3);
  assert.equal(app._renderEpoch, 3);
});

test('_setRenderResult returns the new epoch (caller threads it into RenderRoute.run)', () => {
  // Callers capture the return value as `epoch` and pass it into
  // `RenderRoute.run(file, buf, app, rctx, epoch)`. The end-of-run guard
  // compares `epoch !== app._renderEpoch` for cross-load supersession;
  // a wrong return value here would either trip the guard on every
  // first-paint (returning the *pre*-bump value) or never trip it
  // (returning a stale captured value).
  const app = new App();
  const returned = app._setRenderResult({ marker: 'x' });
  assert.equal(returned, app._renderEpoch,
    'returned value must equal the post-bump epoch');
});

test('_setRenderResult swaps currentResult to the supplied value', () => {
  const app = new App();
  const a = { marker: 'A' };
  const b = { marker: 'B' };
  app._setRenderResult(a);
  assert.equal(app.currentResult, a, 'currentResult must point at the new result');
  app._setRenderResult(b);
  assert.equal(app.currentResult, b, 'second call must swap in the second result');
  // The previous slot is now unreferenced from `app.currentResult` —
  // the renderer that wrote into it (still running async) keeps its
  // captured reference but its writes can no longer reach the live UI.
  assert.notEqual(app.currentResult, a);
});

test('_setRenderResult clears the highlight-active-view back-references', () => {
  // Both fields hold a back-reference to the GridViewer that owns the
  // live YARA / IOC highlight. Every view transition (file-clear,
  // drill-down via openInnerFile, Timeline ↔ renderer pivot) routes
  // through `_setRenderResult`, so clearing them here prevents a
  // dangling pointer reaching `_clearYaraHighlight` /
  // `_clearIocCsvHighlight` after the previous grid is torn down.
  const app = new App();
  // Simulate the previous file's render leaving these stamped:
  app._yaraHighlightActiveView = { _stale: 'yara' };
  app._iocCsvHighlightActiveView = { _stale: 'csv' };
  app._setRenderResult({ marker: 'next' });
  assert.equal(app._yaraHighlightActiveView, null,
    '_yaraHighlightActiveView must be cleared on render-result swap');
  assert.equal(app._iocCsvHighlightActiveView, null,
    '_iocCsvHighlightActiveView must be cleared on render-result swap');
});

test('_setRenderResult is the SOLE epoch-bump site in app-load.js', () => {
  // Static-source guard — paired with the runtime test above. The
  // render-route header documents the invariant: "The only legitimate
  // epoch bump is the caller's `_setRenderResult` call." If a future
  // edit adds a `this._renderEpoch++` / `this._renderEpoch = N`
  // outside the helper, the regression is caught here.
  const fs = require('node:fs');
  const path = require('node:path');
  const SRC = fs.readFileSync(
    path.join(__dirname, '..', '..', 'src', 'app', 'app-load.js'),
    'utf8',
  );
  // Locate the `_setRenderResult` body so we can exclude it from the
  // file-wide search for assignments to `_renderEpoch`.
  const helperStart = SRC.indexOf('_setRenderResult(result)');
  assert.notEqual(helperStart, -1, 'expected to find _setRenderResult method');
  // Walk braces to find the body span.
  const open = SRC.indexOf('{', helperStart);
  let depth = 1, i = open + 1;
  while (i < SRC.length && depth > 0) {
    const c = SRC[i++];
    if (c === '{') depth++;
    else if (c === '}') depth--;
  }
  const sansHelper = SRC.slice(0, open) + SRC.slice(i);
  // Match `this._renderEpoch =` and `this._renderEpoch +=` and
  // `this._renderEpoch++` outside the helper body.
  const writes = sansHelper.match(/this\._renderEpoch\s*(?:=(?!=)|\+=|\+\+)/g);
  assert.equal(writes, null,
    `_renderEpoch must only be written inside _setRenderResult; ` +
    `found writes outside the helper: ${writes && writes.join(', ')}`);
});

test('_setRenderResult on a fresh App with no prior state lands at epoch 1', () => {
  // Defends the `(this._renderEpoch || 0) + 1` pattern: even if a
  // future refactor accidentally drops the constructor's `= 0` seed,
  // the `|| 0` keeps the first call landing at epoch 1 instead of
  // `NaN + 1 → NaN`.
  const app = new App();
  app._renderEpoch = undefined;            // simulate the missing-seed case
  const e = app._setRenderResult({ marker: 'first' });
  assert.equal(e, 1, 'first call must land at epoch 1 even with missing seed');
  assert.equal(app._renderEpoch, 1);
});
