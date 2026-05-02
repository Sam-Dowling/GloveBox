'use strict';
// ════════════════════════════════════════════════════════════════════════════
// render-route.test.js — pin the contract of `RenderRoute`, the central
// renderer-dispatch wrapper.
//
// `RenderRoute.run(file, buffer, app, rctx?, epoch?)` owns six concerns
// (full list in `src/render-route.js` header). The most subtle of those
// is the **render-epoch fence** — a regression here ships a blank-page
// bug on every fallback (see `06cbb04`, the Phase-1/C3 ship-stopper).
//
// What this test pins
// -------------------
//   1. `_emptyResult(buffer)` — shape of the canonical RenderResult
//      skeleton (every renderer-side stamp lands on a pre-allocated
//      slot of this shape).
//   2. `_emptyFindings()` — shape mirrors the constructor state expected
//      by `_renderSidebar` and `pushIOC()`.
//   3. `_orphanInFlight(app, buffer)` — freezes the previous findings,
//      swaps in fresh skeletons, and (critically) does **NOT** bump
//      the render-epoch.
//   4. `run()` — end-of-run supersession guard returns
//      `{ _superseded: true }` when the live `app._renderEpoch` has
//      moved past the captured value mid-flight.
//   5. `run()` — graceful plaintext fallback on a renderer exception
//      pushes a single `IOC.INFO` row, calls `_orphanInFlight`, and
//      keeps the render-epoch unchanged.
//   6. `run()` — graceful plaintext fallback on a per-dispatch size-cap
//      breach behaves the same as the exception-fallback path.
//   7. `run()` — happy path normalises a bare `HTMLElement` return into
//      the canonical `{ docEl, rawText, ... }` shape and runs
//      `lfNormalize` on the rawText source.
//
// Mocking strategy
// ----------------
// `RenderRoute.run` calls `RendererRegistry.makeContext` /
// `RendererRegistry.detect` and `ParserWatchdog.run`. Both are too heavy
// to stand up here (the registry's `_bootstrap()` walks every renderer
// class). Instead the sandbox is pre-seeded with minimal stubs and only
// `constants.js` + `render-route.js` are evaluated against them. This
// keeps the test a true unit (no renderer-class dependencies leak in)
// and matches the pattern used by other targeted test files.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// Build a fresh sandbox per test so no state leaks across cases. Each
// invocation re-evaluates the bundle, but that's microseconds.
function makeCtx(opts) {
  const o = opts || {};
  // Shims: stub RendererRegistry / ParserWatchdog before render-route.js
  // evaluates. Each test substitutes its own stubs by mutating these
  // globals after load, but a default no-op pair lets the file evaluate
  // cleanly.
  const shims = {
    document: { createElement: (tag) => ({ tagName: tag.toUpperCase(), nodeType: 1, textContent: '', _rawText: null, appendChild: () => {} }) },
    HTMLElement: function () {},
    RendererRegistry: o.RendererRegistry || {
      makeContext: () => ({}),
      detect: () => ({ id: 'plaintext' }),
    },
    ParserWatchdog: o.ParserWatchdog || {
      _activeSignal: null,
      run: async (fn /* , opts */) => {
        // Default "good" watchdog: invoke fn synchronously and return.
        return await fn({ signal: null });
      },
    },
  };
  return loadModules(
    [
      'src/constants.js',
      'src/render-route.js',
    ],
    { expose: ['RenderRoute', 'IOC', 'PARSER_LIMITS', 'pushIOC'], shims },
  );
}

// ── 1. _emptyResult / _emptyFindings shape pins ──────────────────────────

test('RenderRoute._emptyResult returns the canonical RenderResult skeleton', () => {
  const { RenderRoute } = makeCtx();
  const buf = new ArrayBuffer(8);
  const r = RenderRoute._emptyResult(buf);
  // Pin every documented slot — a missing slot would silently NPE on a
  // renderer's per-dispatch stamp (e.g. `currentResult.binary = …`).
  assert.equal(r.docEl, null);
  assert.equal(r.findings, null);          // filled post-render from app.findings
  assert.equal(r.rawText, '');
  assert.equal(r.buffer, buf);             // canonical handle for downstream
  assert.equal(r.binary, null);            // PE/ELF/Mach-O write target
  assert.equal(r.yaraBuffer, null);        // SVG/HTML/Plist augmented buffer
  assert.equal(r.navTitle, '');
  assert.equal(r.analyzer, null);          // DOCX SecurityAnalyzer hand-back
  assert.equal(r.dispatchId, null);
  assert.equal(r.formatTag, null);
});

test('RenderRoute._emptyResult tolerates missing buffer (legacy callers)', () => {
  const { RenderRoute } = makeCtx();
  const r = RenderRoute._emptyResult();
  assert.equal(r.buffer, null,
    'missing buffer arg must coerce to null, not undefined');
});

test('RenderRoute._emptyFindings matches the constructor-state shape pushIOC writes into', () => {
  const { RenderRoute } = makeCtx();
  const f = RenderRoute._emptyFindings();
  assert.equal(f.risk, 'low');
  // Shape-only checks (cross-realm: arrays/objects originate inside the
  // vm sandbox and are NOT reference-prototype-equal to host literals).
  assert.equal(Array.isArray(f.externalRefs) || f.externalRefs.length === 0, true);
  assert.equal(f.externalRefs.length, 0);
  assert.equal(f.interestingStrings.length, 0);
  assert.equal(Object.keys(f.metadata).length, 0);
});

// ── 2. _orphanInFlight: freeze + swap + epoch unchanged ────────────────

test('_orphanInFlight freezes the previous findings so late writes throw', () => {
  const { RenderRoute } = makeCtx();
  const prevFindings = { risk: 'low', externalRefs: [], interestingStrings: [{ url: 'x' }], metadata: {} };
  const app = {
    _renderEpoch: 7,
    findings: prevFindings,
    currentResult: { docEl: 'old' },
  };
  RenderRoute._orphanInFlight(app, new ArrayBuffer(0));
  assert.ok(Object.isFrozen(prevFindings),
    'previous findings must be frozen so renderer-late `findings.X.push(…)` throws');
});

test('_orphanInFlight swaps findings + currentResult with fresh skeletons', () => {
  const { RenderRoute } = makeCtx();
  const oldFindings = { risk: 'low', externalRefs: [], interestingStrings: [], metadata: {} };
  const oldResult = { docEl: 'old' };
  const app = { _renderEpoch: 7, findings: oldFindings, currentResult: oldResult };
  const buf = new ArrayBuffer(64);
  RenderRoute._orphanInFlight(app, buf);
  assert.notEqual(app.findings, oldFindings,
    'app.findings must be replaced with a fresh empty findings object');
  assert.notEqual(app.currentResult, oldResult,
    'app.currentResult must be replaced with a fresh empty skeleton');
  assert.equal(app.findings.externalRefs.length, 0);
  assert.equal(app.currentResult.buffer, buf,
    'fresh skeleton must carry the supplied buffer');
});

test('_orphanInFlight does NOT bump _renderEpoch (06cbb04 ship-stopper guard)', () => {
  // The single most-broken invariant in the repo: bumping the epoch
  // here trips the end-of-run supersession guard on every fallback
  // path, returns `{ _superseded: true }`, and `_loadFile` early-
  // returns on the sentinel — leaving the page blank instead of
  // painting the plaintext view.
  const { RenderRoute } = makeCtx();
  const app = {
    _renderEpoch: 42,
    findings: { risk: 'low', externalRefs: [], interestingStrings: [], metadata: {} },
    currentResult: {},
  };
  const before = app._renderEpoch;
  RenderRoute._orphanInFlight(app, new ArrayBuffer(0));
  assert.equal(app._renderEpoch, before,
    '_orphanInFlight must NOT bump _renderEpoch — see render-route.js header (06cbb04)');
});

test('_orphanInFlight returns the (unchanged) current epoch', () => {
  const { RenderRoute } = makeCtx();
  const app = {
    _renderEpoch: 42,
    findings: { risk: 'low', externalRefs: [], interestingStrings: [], metadata: {} },
    currentResult: {},
  };
  const ret = RenderRoute._orphanInFlight(app, new ArrayBuffer(0));
  assert.equal(ret, 42, 'helper must return the unchanged epoch for callers that want it');
});

test('_orphanInFlight is idempotent against null findings (defensive entry)', () => {
  const { RenderRoute } = makeCtx();
  const app = { _renderEpoch: 1, findings: null, currentResult: null };
  // Must not throw on the freeze step when findings is null.
  RenderRoute._orphanInFlight(app, new ArrayBuffer(0));
  assert.notEqual(app.findings, null);
  assert.notEqual(app.currentResult, null);
  assert.equal(app._renderEpoch, 1);
});

// ── 3. run() supersession guard ────────────────────────────────────────

test('run() returns {_superseded:true} when caller-supplied epoch has been overtaken', async () => {
  // Simulate a quick back-to-back load: the first dispatch captured
  // epoch=1 at entry, but a second `_setRenderResult` bumped the live
  // counter to 2 mid-flight. The end-of-run guard must detect this and
  // bail with the sentinel instead of clobbering the new state.
  let detectedDispatch = 'plaintext';
  const ctx = makeCtx({
    RendererRegistry: {
      makeContext: () => ({ ext: 'txt' }),
      detect: () => ({ id: detectedDispatch }),
    },
  });
  const { RenderRoute } = ctx;
  const docEl = { nodeType: 1, textContent: 'hi', _rawText: 'hi' };
  const handler = function () { return docEl; };
  const app = {
    _renderEpoch: 2,                       // live counter has moved past
    findings: ctx.RenderRoute._emptyFindings(),
    currentResult: ctx.RenderRoute._emptyResult(null),
    _rendererDispatch: { plaintext: handler },
  };
  const file = { name: 'x.txt' };
  const buf = new ArrayBuffer(4);
  const result = await RenderRoute.run(file, buf, app, null, /* epoch= */ 1);
  assert.equal(result._superseded, true,
    'run() must return _superseded:true when captured epoch !== live epoch');
  // The new state's docEl must NOT be set (we did not paint).
  assert.equal(result.docEl, null);
});

test('run() does NOT bump _renderEpoch on the happy path (caller owns the bump)', async () => {
  const ctx = makeCtx({
    RendererRegistry: {
      makeContext: () => ({}),
      detect: () => ({ id: 'plaintext' }),
    },
  });
  const { RenderRoute } = ctx;
  const docEl = { nodeType: 1, textContent: 'hello', _rawText: 'hello' };
  const app = {
    _renderEpoch: 5,
    findings: RenderRoute._emptyFindings(),
    currentResult: RenderRoute._emptyResult(null),
    _rendererDispatch: { plaintext: () => docEl },
  };
  await RenderRoute.run({ name: 'a.txt' }, new ArrayBuffer(4), app, null, 5);
  assert.equal(app._renderEpoch, 5, 'happy path must leave _renderEpoch unchanged');
});

// ── 4. run() fallback on renderer exception ────────────────────────────

test('run() falls back to plaintext on a thrown renderer error and pushes IOC.INFO', async () => {
  const ctx = makeCtx({
    RendererRegistry: {
      makeContext: () => ({}),
      detect: () => ({ id: 'pe' }),       // a non-plaintext id triggers fallback wiring
    },
  });
  const { RenderRoute, IOC } = ctx;
  const plaintextDocEl = { nodeType: 1, textContent: 'fallback', _rawText: 'fallback' };
  const app = {
    _renderEpoch: 3,
    findings: RenderRoute._emptyFindings(),
    currentResult: RenderRoute._emptyResult(null),
    _rendererDispatch: {
      pe: function () { throw new Error('truncated PE header'); },
      plaintext: function () { return plaintextDocEl; },
    },
  };
  const result = await RenderRoute.run({ name: 'x.exe' }, new ArrayBuffer(8), app, null, 3);
  // Epoch must be unchanged across the fallback (the critical
  // invariant — bumping it would `_supersede` the fallback paint).
  assert.equal(app._renderEpoch, 3,
    '_renderEpoch must not be bumped on the fallback path (06cbb04)');
  // Result is the plaintext view, not a `_superseded` sentinel.
  assert.notEqual(result._superseded, true);
  assert.equal(result.dispatchId, 'plaintext',
    'dispatchId must be rewritten to plaintext after fallback');
  // A visible IOC.INFO row must have been pushed.
  const infoRows = app.findings.interestingStrings.filter(r => r.type === IOC.INFO);
  assert.equal(infoRows.length, 1, 'exactly one IOC.INFO row should be pushed on fallback');
  assert.match(infoRows[0].url || infoRows[0].value || '', /pe/i,
    'fallback IOC.INFO must mention the failed dispatch id');
  assert.match(infoRows[0].url || infoRows[0].value || '', /plain-text/i,
    'fallback IOC.INFO must explain the fallback to plain-text');
});

test('run() re-raises when plaintext itself throws (degenerate case)', async () => {
  const ctx = makeCtx({
    RendererRegistry: {
      makeContext: () => ({}),
      detect: () => ({ id: 'plaintext' }),
    },
  });
  const { RenderRoute } = ctx;
  const app = {
    _renderEpoch: 1,
    findings: RenderRoute._emptyFindings(),
    currentResult: RenderRoute._emptyResult(null),
    _rendererDispatch: {
      plaintext: function () { throw new Error('plaintext blew up'); },
    },
  };
  let rejected = null;
  try {
    await RenderRoute.run({ name: 'x.txt' }, new ArrayBuffer(4), app, null, 1);
  } catch (e) { rejected = e; }
  assert.ok(rejected, 'plaintext-itself failure must surface as a rejection');
  assert.match(rejected.message, /plaintext blew up/);
});

// ── 5. run() per-dispatch size-cap fallback ────────────────────────────

test('run() falls back to plaintext when the file exceeds MAX_FILE_BYTES_BY_DISPATCH', async () => {
  const ctx = makeCtx({
    RendererRegistry: {
      makeContext: () => ({}),
      detect: () => ({ id: 'pdf' }),
    },
  });
  const { RenderRoute, IOC, PARSER_LIMITS } = ctx;
  // Pick a buffer size guaranteed to exceed the pdf cap (256 MiB).
  const cap = PARSER_LIMITS.MAX_FILE_BYTES_BY_DISPATCH.pdf
    || PARSER_LIMITS.MAX_FILE_BYTES_BY_DISPATCH._DEFAULT;
  // Don't actually allocate cap+1 bytes; mock byteLength via a fake
  // buffer object that reports an over-cap size.
  const fakeBuf = Object.create(ArrayBuffer.prototype);
  Object.defineProperty(fakeBuf, 'byteLength', { value: cap + 1 });
  let pdfHandlerCalled = false;
  const app = {
    _renderEpoch: 1,
    findings: RenderRoute._emptyFindings(),
    currentResult: RenderRoute._emptyResult(fakeBuf),
    _rendererDispatch: {
      pdf: function () { pdfHandlerCalled = true; return null; },
      plaintext: function () { return { nodeType: 1, textContent: '', _rawText: '' }; },
    },
  };
  const result = await RenderRoute.run({ name: 'huge.pdf' }, fakeBuf, app, null, 1);
  assert.equal(pdfHandlerCalled, false,
    'over-cap files must bypass the structured renderer');
  assert.equal(result.dispatchId, 'plaintext');
  assert.equal(app._renderEpoch, 1, 'size-cap fallback must not bump epoch');
  const infoRows = app.findings.interestingStrings.filter(r => r.type === IOC.INFO);
  assert.equal(infoRows.length, 1);
  assert.match(infoRows[0].url || infoRows[0].value || '', /cap|MiB/i,
    'size-cap IOC.INFO must mention the cap or MiB unit');
});

// ── 6. run() happy-path normalisation ──────────────────────────────────

test('run() normalises bare-HTMLElement return into RenderResult shape', async () => {
  const ctx = makeCtx({
    RendererRegistry: {
      makeContext: () => ({}),
      detect: () => ({ id: 'plaintext' }),
    },
  });
  const { RenderRoute } = ctx;
  // Renderer returns a bare element (legacy contract).
  const docEl = { nodeType: 1, textContent: 'hello', _rawText: 'line1\r\nline2\nline3' };
  const app = {
    _renderEpoch: 1,
    findings: RenderRoute._emptyFindings(),
    currentResult: RenderRoute._emptyResult(null),
    _rendererDispatch: { plaintext: () => docEl },
  };
  const result = await RenderRoute.run({ name: 'x.txt' }, new ArrayBuffer(4), app, null, 1);
  assert.equal(result.docEl, docEl);
  // lfNormalize must collapse CRLF → LF in rawText.
  assert.equal(result.rawText, 'line1\nline2\nline3',
    'rawText must be lfNormalize()-d (CRLF → LF)');
  assert.equal(result.dispatchId, 'plaintext');
  assert.equal(result.navTitle, 'x.txt');
  assert.equal(result.findings, app.findings,
    'result.findings is a read-through reference to app.findings');
});

test('run() normalises {docEl, analyzer} return shape and forwards analyzer', async () => {
  const ctx = makeCtx({
    RendererRegistry: {
      makeContext: () => ({}),
      detect: () => ({ id: 'plaintext' }),
    },
  });
  const { RenderRoute } = ctx;
  const docEl = { nodeType: 1, textContent: 'x', _rawText: 'x' };
  const analyzer = { _markerForTest: 'docx-analyzer' };
  const app = {
    _renderEpoch: 1,
    findings: RenderRoute._emptyFindings(),
    currentResult: RenderRoute._emptyResult(null),
    _rendererDispatch: { plaintext: () => ({ docEl, analyzer }) },
  };
  const result = await RenderRoute.run({ name: 'x.txt' }, new ArrayBuffer(4), app, null, 1);
  assert.equal(result.docEl, docEl);
  assert.equal(result.analyzer, analyzer,
    '{ docEl, analyzer } shape must surface the analyzer on the RenderResult');
});
