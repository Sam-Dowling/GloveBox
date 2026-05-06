'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-autoextract-geoip-handoff.test.js — pin the integration
// between auto-extract's terminal branch and the GeoIP retry path.
//
// What this test pins (vm-sandboxed end-to-end, NOT just static text):
//
//   • When the natural-detect GeoIP pass found NO IP-shaped base
//     columns AND auto-extract added one or more extracted columns
//     containing IPv4 values, the terminal branch fires
//     `_runGeoipEnrichment({ retryExtractedCols: true })` exactly once.
//
//   • When the natural-detect pass already found IP cols (cache is
//     a non-empty array), the terminal branch does NOT fire the
//     retry — the work would be duplicate.
//
//   • When auto-extract added zero columns (e.g. all proposals
//     deduped against pre-seeded regex extracts), the terminal
//     branch does NOT fire the retry — there's nothing new to scan.
//
//   • The `_geoipBaseDetectResult` cache is cleared (set to null)
//     after the retry so subsequent triggers re-scan rather than
//     reusing the snapshot.
//
// Sandbox shape mirrors `timeline-view-autoextract-reopen-path.test.js`
// (the existing reopen-flow harness). The geoip mixin is NOT loaded —
// instead `_runGeoipEnrichment` is stubbed with a call recorder so the
// test pins HOW the autoextract side calls it, not the geoip side's
// behaviour. Behavioural coverage of the geoip side lives in
// `timeline-view-geoip.test.js` and the e2e spec.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

// ── Sandbox builder ────────────────────────────────────────────────────────

function buildSandbox() {
  const store = new Map();
  const localStorage = {
    getItem: (k) => store.has(k) ? store.get(k) : null,
    setItem: (k, v) => { store.set(k, String(v)); },
    removeItem: (k) => { store.delete(k); },
    clear: () => { store.clear(); },
    get length() { return store.size; },
    key: (i) => Array.from(store.keys())[i] || null,
    _dump: () => Object.fromEntries(store),
  };

  const sandbox = {
    console: { log: () => {}, warn: () => {}, error: () => {} },
    Map, Set, Date, Math, JSON, RegExp, Error, TypeError,
    Object, Array, Number, String, Boolean,
    Uint8Array, Uint16Array, Uint32Array, Float64Array,
    parseInt, parseFloat, isFinite, isNaN, Symbol, Promise,
    setTimeout, clearTimeout,
    localStorage,
    requestIdleCallback: (fn) => {
      fn({ timeRemaining: () => 50, didTimeout: false });
      return 1;
    },
    cancelIdleCallback: () => {},
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);

  const files = [
    'src/constants.js',
    'src/storage.js',
    'src/app/timeline/timeline-parser-helpers.js',
  'src/app/timeline/timeline-helpers.js',
  ];

  const stubClass = 'class TimelineView { constructor() {} }\n';

  const tail = [
    'src/app/timeline/timeline-drawer.js',
    'src/app/timeline/timeline-view-persist.js',
    'src/app/timeline/timeline-view-autoextract.js',
  ];

  let combined = '';
  for (const f of files) combined += fs.readFileSync(path.join(REPO_ROOT, f), 'utf8') + '\n';
  combined += stubClass;
  for (const f of tail) combined += fs.readFileSync(path.join(REPO_ROOT, f), 'utf8') + '\n';

  combined +=
    '\nglobalThis.TimelineView = TimelineView;\n' +
    'globalThis.TIMELINE_KEYS = TIMELINE_KEYS;\n' +
    'globalThis.safeStorage = safeStorage;\n';

  vm.runInContext(combined, sandbox, {
    filename: 'timeline-view-autoextract-geoip-handoff:concat',
    displayErrors: true,
  });
  return sandbox;
}

// ── View builder ───────────────────────────────────────────────────────────
//
// Mirrors the reopen-path test's view builder, with two extras:
//   • a `geoipCalls` array that records every `_runGeoipEnrichment(...)`
//     invocation (the autoextract code calls it via `this.fn(...)` so
//     stubbing on the instance is sufficient).
//   • a stable `_geoipBaseDetectResult` field that the test seeds to
//     simulate "natural-detect already ran; here's what it found."

function buildView(sandbox, opts = {}) {
  const TimelineView = sandbox.TimelineView;
  const view = new TimelineView();
  // 8-col file. Col 7 holds JSON with an IPv4 inside — the kind of
  // thing that base-detect can't see but extracted-detect can.
  const baseColumns = ['Timestamp', 'EventType', 'UserId', 'Department',
                       'Severity', 'Status', 'DurationMs', 'Raw Data'];
  view._baseColumns = baseColumns;
  view.formatLabel = 'CSV';
  view._jsonCache = new sandbox.Map();
  view._fileKey = opts.fileKey || ('test|0|' + Math.random().toString(36).slice(2));

  const toasts = [];
  view._app = {
    debug: false,
    _toast: (msg, kind) => { toasts.push({ msg, kind }); },
  };
  view.toasts = toasts;
  view._els = { host: {} };

  // Pre-seed the GeoIP base-detect result-cache as the test wants.
  // Three states the autoextract terminal branch can encounter:
  //   • opts.geoipBaseDetectResult === undefined → pretend natural-
  //     detect never ran (the constructor null-init). The hook
  //     should NOT fire (the gate requires `Array.isArray(...)`).
  //   • opts.geoipBaseDetectResult === [] → natural-detect ran AND
  //     found nothing. The hook SHOULD fire.
  //   • opts.geoipBaseDetectResult === [colIdx, …] → natural-detect
  //     ran AND found IP cols. The hook should NOT fire.
  view._geoipBaseDetectResult = opts.geoipBaseDetectResult === undefined
    ? null
    : opts.geoipBaseDetectResult.slice();

  // Stub _runGeoipEnrichment as a recorder.
  const geoipCalls = [];
  view._runGeoipEnrichment = function (callOpts) {
    geoipCalls.push(callOpts || {});
  };
  view.geoipCalls = geoipCalls;

  // Dataset + extracted-cols infrastructure.
  const extractedCols = [];
  view._extractedCols = extractedCols;
  view._dataset = {
    baseColCount: baseColumns.length,
    addExtractedCol: (entry) => {
      if (!entry || !sandbox.Array.isArray(entry.values)) {
        throw new sandbox.TypeError(
          'addExtractedCol: entry.values must be an array');
      }
      if (entry.values.length !== view.store.rowCount) {
        throw new sandbox.Error(
          'addExtractedCol: values.length must equal rowCount');
      }
      extractedCols.push(entry);
      return extractedCols.length;
    },
    removeExtractedCol: (extIdx) => {
      if (extIdx < 0 || extIdx >= extractedCols.length) return;
      extractedCols.splice(extIdx, 1);
    },
    clearExtractedCols: () => { extractedCols.length = 0; },
  };

  // Drive the JSON-leaf branch with a row count > 8 (so the json-
  // dominant gate fires). 30 rows is plenty for the 80% gate.
  const rowCount = opts.rowCount || 30;
  // The JSON blob has a stable shape with three keys: {RemoteAddr, User, Path}.
  // RemoteAddr is the IPv4 we want extracted-detect to spot.
  const ipFor = (r) => `10.0.${r % 256}.${(r * 7) % 256}`;
  const columnValues = [];
  for (let r = 0; r < rowCount; r++) {
    columnValues.push(JSON.stringify({
      RemoteAddr: ipFor(r),
      User: 'user' + r,
      Path: '/api/v1/' + r,
    }));
  }

  view.store = {
    rowCount: rowCount,
    colCount: baseColumns.length,
    columns: baseColumns.slice(),
    getCell: (row, col) => {
      if (col === 7) return columnValues[row] || '';
      return '';
    },
  };

  Object.defineProperty(view, 'columns', {
    get() {
      const out = baseColumns.slice();
      for (const e of extractedCols) out.push(e.name);
      return out;
    },
    configurable: true,
  });

  view._cellAt = function (row, col) {
    if (col === 7) return columnValues[row] || '';
    if (col === 0) return `2025-01-01T00:00:${String(row % 60).padStart(2, '0')}Z`;
    return '';
  };

  view._rebuildExtractedStateAndRender = () => {};
  // Stub the render scheduler so the apply-pump terminus branch (which
  // schedules a one-shot `['columns']` to populate the Top Values strip
  // after the pump finishes) can call it without blowing up. Records
  // the calls for tests that want to assert the terminus fires the
  // deferred sweep.
  const renderCalls = [];
  view._scheduleRender = (tasks) => { renderCalls.push(tasks); };
  view.renderCalls = renderCalls;

  return view;
}

// ── Tests ──────────────────────────────────────────────────────────────────

test('terminal branch fires retry when base-detect was empty + extracted cols added', () => {
  const sandbox = buildSandbox();
  const view = buildView(sandbox, {
    fileKey: 'handoff|empty-base|TEST',
    // Simulate: natural-detect already ran, found NO IP-shaped base cols.
    geoipBaseDetectResult: [],
  });

  view._autoExtractBestEffort();

  // Auto-extract should have added at least one column (the JSON
  // fixture has multiple leaves).
  assert.ok(view._extractedCols.length > 0,
    `auto-extract should add extracted cols from the JSON fixture; ` +
    `got ${view._extractedCols.length}`);

  // Exactly one retry call.
  assert.equal(view.geoipCalls.length, 1,
    `_runGeoipEnrichment should have been called exactly once with ` +
    `the retry opt; got ${view.geoipCalls.length} calls: ` +
    `${JSON.stringify(view.geoipCalls)}`);

  assert.equal(view.geoipCalls[0].retryExtractedCols, true,
    `retry call must pass retryExtractedCols: true; got opts: ` +
    `${JSON.stringify(view.geoipCalls[0])}`);
});

test('terminal branch does NOT fire retry when base-detect found IP cols', () => {
  const sandbox = buildSandbox();
  const view = buildView(sandbox, {
    fileKey: 'handoff|found-base|TEST',
    // Simulate: natural-detect already ran, found IP-shaped col at idx 3.
    geoipBaseDetectResult: [3],
  });

  view._autoExtractBestEffort();

  // Auto-extract should still add columns (uncapped — the gate is
  // independent from the retry decision).
  assert.ok(view._extractedCols.length > 0,
    `auto-extract should still add extracted cols`);

  // No retry call — natural-detect already found IP cols, so the
  // retry would be wasted work.
  assert.equal(view.geoipCalls.length, 0,
    `_runGeoipEnrichment must NOT be called when ` +
    `_geoipBaseDetectResult is non-empty (natural-detect already ` +
    `found IP cols); got ${view.geoipCalls.length} calls: ` +
    `${JSON.stringify(view.geoipCalls)}`);
});

test('terminal branch does NOT fire retry when base-detect cache is null', () => {
  const sandbox = buildSandbox();
  const view = buildView(sandbox, {
    fileKey: 'handoff|null-cache|TEST',
    // Don't pass geoipBaseDetectResult — defaults to null (the
    // constructor init state). The hook's `Array.isArray` guard
    // should reject this.
  });

  // Verify the cache really is null going in (not undefined).
  assert.equal(view._geoipBaseDetectResult, null,
    `pre-condition: _geoipBaseDetectResult must be null`);

  view._autoExtractBestEffort();

  // No retry call — natural-detect hasn't run yet, so we don't
  // know whether the retry would be productive. Letting the
  // natural-detect (router-scheduled) run first is the right
  // ordering; the autoextract hook is opportunistic, not load-bearing.
  assert.equal(view.geoipCalls.length, 0,
    `_runGeoipEnrichment must NOT be called when ` +
    `_geoipBaseDetectResult is null (natural-detect hasn't run); ` +
    `got ${view.geoipCalls.length} calls: ` +
    `${JSON.stringify(view.geoipCalls)}`);
});

test('terminal branch clears _geoipBaseDetectResult after firing retry', () => {
  const sandbox = buildSandbox();
  const view = buildView(sandbox, {
    fileKey: 'handoff|clear-after|TEST',
    geoipBaseDetectResult: [],
  });

  view._autoExtractBestEffort();

  // Sanity: retry fired.
  assert.equal(view.geoipCalls.length, 1,
    `pre-condition: retry should have fired exactly once`);

  // Cache cleared. This matters for subsequent GeoIP triggers
  // (MMDB hydrate, user upload, right-click) — they need to
  // re-evaluate against the current column set, not this stale
  // snapshot.
  assert.equal(view._geoipBaseDetectResult, null,
    `after firing retry, _geoipBaseDetectResult must be set back ` +
    `to null so subsequent GeoIP triggers re-scan; ` +
    `got: ${JSON.stringify(view._geoipBaseDetectResult)}`);
});

test('terminal branch does NOT fire retry when zero extracted cols added', () => {
  const sandbox = buildSandbox();
  const view = buildView(sandbox, {
    fileKey: 'handoff|empty-extract|TEST',
    geoipBaseDetectResult: [],
  });

  // Override _cellAt so col 7 returns no JSON — scanner finds nothing.
  view._cellAt = function (_row, _col) { return ''; };
  view.store.getCell = (_r, _c) => '';

  view._autoExtractBestEffort();

  // Auto-extract added zero cols.
  assert.equal(view._extractedCols.length, 0,
    `pre-condition: scanner should have found nothing; got ` +
    `${view._extractedCols.length} cols`);

  // No retry call — nothing new to scan.
  assert.equal(view.geoipCalls.length, 0,
    `_runGeoipEnrichment must NOT be called when zero extracted ` +
    `cols were added (no new content for retry to scan); got ` +
    `${view.geoipCalls.length} calls`);
});
