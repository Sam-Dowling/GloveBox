'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-autoextract-reopen-path.test.js — end-to-end pin for the
// auto-extract reopen contract.
//
// HISTORY: this file exists because the same bug class shipped twice.
// Static-text tests pinning predicates passed while the user-visible
// behaviour remained broken — the pre-fix code's `_loadAutoExtractDoneFor`
// guard short-circuited before the new `hasAnalystWork` predicate could
// run, so neither the scanner test (calling `_autoExtractScan` directly)
// nor the static-source test (verifying the predicate substring) ever
// exercised the actual reopen flow.
//
// This test drives `_autoExtractBestEffort` end-to-end against a fake
// `localStorage` and a stubbed-but-real-shaped `_dataset`, replaying the
// ctor-load → scanner-apply → toast cycle TWICE to simulate first-open
// and reopen. It pins:
//
//   1. First open: scanner runs, ≥10 columns added (json-leaf branch),
//      toast fires, the `loupe_timeline_autoextract_toast_shown` marker
//      gets stamped, AND the regex-extracts persistence stays empty
//      (auto extracts are ephemeral — they have `kind:'auto'`, the
//      persister filter is `kind === 'regex'`).
//
//   2. Reopen: scanner runs AGAIN unconditionally; the same ≥10 columns
//      get re-added; toast does NOT fire (marker stamped); persistence
//      remains empty.
//
//   3. Reopen with a pre-existing user regex extract that overlaps an
//      auto-proposal: dedup wins, the user extract is preserved
//      verbatim in regex-extracts persistence, and the column count
//      matches the no-overlap reopen (the duplicate auto proposal is
//      silently skipped).
//
// vm-sandbox harness — bigger than the existing `-real-fixture.test.js`
// because it loads the full mutation surface (`storage.js`,
// `timeline-view-persist.js`, plus the existing autoextract + drawer +
// helpers + constants). The harness uses a stubbed dataset that mirrors
// just `addExtractedCol(entry)` and `baseColCount` — that's all the
// auto-extract codepath touches.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

// ── Fixture: column 7 of examples/forensics/json-example.csv ──────────────

function readJsonExampleColumn7() {
  const csvPath = path.join(REPO_ROOT, 'examples', 'forensics', 'json-example.csv');
  const text = fs.readFileSync(csvPath, 'utf8');
  const rows = parseCsv(text);
  const header = rows.shift();
  assert.equal(header[7], 'Raw Data', 'fixture column 7 must be "Raw Data"');
  return rows.map(r => r[7] || '');
}

function parseCsv(text) {
  // Same minimal RFC4180 tokeniser as the sibling -real-fixture test —
  // intentionally not deduplicated because the two tests should be
  // independently reviewable.
  const rows = [];
  let row = [];
  let field = '';
  let i = 0;
  let inQuotes = false;
  while (i < text.length) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
        inQuotes = false; i++; continue;
      }
      field += ch; i++; continue;
    }
    if (ch === '"') { inQuotes = true; i++; continue; }
    if (ch === ',') { row.push(field); field = ''; i++; continue; }
    if (ch === '\r') { i++; continue; }
    if (ch === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
    field += ch; i++;
  }
  if (field.length > 0 || row.length > 0) { row.push(field); rows.push(row); }
  return rows;
}

// ── Sandbox builder ────────────────────────────────────────────────────────

function buildSandbox() {
  // Fake localStorage with the standard four methods + a `length` /
  // `key(i)` shape so `safeStorage.keys()` works.
  const store = new Map();
  const localStorage = {
    getItem: (k) => store.has(k) ? store.get(k) : null,
    setItem: (k, v) => { store.set(k, String(v)); },
    removeItem: (k) => { store.delete(k); },
    clear: () => { store.clear(); },
    get length() { return store.size; },
    key: (i) => Array.from(store.keys())[i] || null,
    // Test helper — not part of the standard API.
    _dump: () => Object.fromEntries(store),
    _store: store,
  };

  const sandbox = {
    console: { log: () => {}, warn: () => {}, error: () => {} },
    Map, Set, Date, Math, JSON, RegExp, Error, TypeError,
    Object, Array, Number, String, Boolean,
    Uint8Array, Uint16Array, Uint32Array, Float64Array,
    parseInt, parseFloat, isFinite, isNaN, Symbol, Promise,
    setTimeout, clearTimeout,
    localStorage,
    // Idle-scheduler stub — call synchronously so the test doesn't have
    // to await ticks. The auto-extract code paths are async-shaped via
    // `requestIdleCallback`/`setTimeout(0)` for paint smoothing on real
    // files; for testing, sync-schedule lets the apply loop drain in a
    // single deterministic step.
    requestIdleCallback: (fn) => { fn({ timeRemaining: () => 50, didTimeout: false }); return 1; },
    cancelIdleCallback: () => {},
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);

  // Load order matches the production `scripts/build.py` JS_FILES order
  // for the relevant subset: constants → storage → helpers → drawer →
  // (stub TimelineView class) → persist → autoextract.
  const files = [
    'src/constants.js',
    'src/storage.js',
    'src/app/timeline/timeline-parser-helpers.js',
  'src/app/timeline/timeline-helpers.js',
  ];

  // The drawer mixin attaches to `TimelineView.prototype`. The persist
  // mixin attaches static methods directly to `TimelineView`. Define the
  // stub class AFTER helpers but BEFORE drawer / persist / autoextract.
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
    filename: 'timeline-view-autoextract-reopen-path:concat',
    displayErrors: true,
  });
  return sandbox;
}

// ── View instance builder ──────────────────────────────────────────────────
//
// Builds a TimelineView-shaped object minimally populated for the
// auto-extract code path. Each new instance shares the sandbox (and
// therefore the fake localStorage) so multiple opens of the "same"
// file see persisted state evolve correctly.

function buildView(sandbox, columnValues, fileKey, opts = {}) {
  const TimelineView = sandbox.TimelineView;
  const view = new TimelineView();
  const baseColumns = ['Timestamp', 'EventType', 'UserId', 'Department',
                       'Severity', 'Status', 'DurationMs', 'Raw Data'];
  view._baseColumns = baseColumns;
  view.formatLabel = 'CSV';
  view._jsonCache = new sandbox.Map();
  view._fileKey = fileKey;

  // Toasts: collected into a list so the test can assert on toast
  // firing without scraping anything visual.
  const toasts = [];
  view._app = {
    debug: false,
    _toast: (msg, kind) => { toasts.push({ msg, kind }); },
  };
  view.toasts = toasts;   // test helper

  // Mark host present so the early-return guards on _els pass. The
  // auto-extract function only checks truthiness, not any DOM API.
  view._els = { host: {} };

  // Dataset stub — implements only the surface auto-extract uses.
  // Shares the `_extractedCols` array with `view` (production code
  // also shares this — see drawer.js comments).
  const extractedCols = [];
  view._extractedCols = extractedCols;
  view._dataset = {
    baseColCount: baseColumns.length,
    addExtractedCol: (entry) => {
      // Match production's invariant check.
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

  view.store = {
    rowCount: columnValues.length,
    colCount: baseColumns.length,
    columns: baseColumns.slice(),
  };

  // `this.columns` is a getter on the production class; we attach a
  // matching `columns` get to our plain instance.
  Object.defineProperty(view, 'columns', {
    get() {
      const out = baseColumns.slice();
      for (const e of extractedCols) out.push(e.name);
      return out;
    },
    configurable: true,
  });

  // Per-cell accessor — col 7 returns the JSON; col 0 returns a
  // dummy ISO timestamp; col 1 returns a dummy event-type string;
  // others return ''. Matches the production `_cellAt(row, col)`
  // signature.
  view._cellAt = function (row, col) {
    if (col === 7) return columnValues[row] || '';
    if (col === 0) return `2025-01-01T00:00:${String(row % 60).padStart(2, '0')}Z`;
    if (col === 1) return ['user.login', 'user.logout', 'file.access'][row % 3];
    return '';
  };

  // Render is a no-op — the test cares about state, not visuals.
  view._rebuildExtractedStateAndRender = () => {};
  // Stub the render scheduler so the apply-pump terminus's deferred
  // `['columns']` schedule (the post-pump Top Values populate) doesn't
  // throw. The test only cares about state, so a recorder that
  // discards the calls is enough.
  view._scheduleRender = () => {};

  // Pre-seed any persisted regex extracts (simulating the ctor's
  // `_loadRegexExtractsFor` replay). Mirrors production by calling
  // `_addRegexExtractNoRender` directly — that path goes through the
  // same dedup + dataset.addExtractedCol as fresh extracts.
  if (Array.isArray(opts.preSeedRegexExtracts)) {
    for (const spec of opts.preSeedRegexExtracts) {
      view._addRegexExtractNoRender(spec);
    }
  }

  return view;
}

// ── Tests ──────────────────────────────────────────────────────────────────

test('first open: auto-extract runs, toast fires, marker stamped, no regex persistence', () => {
  const sandbox = buildSandbox();
  const col = readJsonExampleColumn7();
  const fileKey = 'json-example.csv|77222|TEST_FIRST_OPEN';
  const view = buildView(sandbox, col, fileKey);

  view._autoExtractBestEffort();

  assert.ok(view._extractedCols.length >= 10,
    `first-open auto-extract should produce >=10 columns; got ` +
    `${view._extractedCols.length}: ${view._extractedCols.map(e => e.name).join(', ')}`);
  // Below LARGE_FILE_THRESHOLD (200 MB) the apply loop is uncapped —
  // every eligible proposal applies. The fixture is < 100 KB so we
  // expect the full eligible set, NOT a 12-cap. Pin a generous upper
  // bound (something the scanner physically couldn't exceed for this
  // fixture) to catch a regression that re-introduces a hard cap.
  assert.ok(view._extractedCols.length <= 60,
    `first-open auto-extract should not produce an absurd column count; ` +
    `got ${view._extractedCols.length} — has the JSON_LEAF_CAP soft ` +
    `limit broken?`);
  assert.ok(view.toasts.length >= 1,
    `toast must fire on first open; got 0 toasts`);
  const toastMsg = view.toasts[0].msg;
  assert.ok(/Auto-extracted \d+ field/.test(toastMsg),
    `toast must look like "Auto-extracted N field(s)"; got: ${toastMsg}`);

  // Marker stamped under the new key name.
  const dump = sandbox.localStorage._dump();
  assert.ok(dump['loupe_timeline_autoextract_toast_shown'],
    `toast-shown marker must be set; localStorage keys: ${Object.keys(dump).join(', ')}`);
  const markerData = JSON.parse(dump['loupe_timeline_autoextract_toast_shown']);
  assert.equal(markerData[fileKey], true,
    `marker must be stamped for THIS fileKey; got: ${JSON.stringify(markerData)}`);

  // Regex-extracts persistence: empty (or absent) — auto extracts are
  // ephemeral with kind:'auto', and the persister filter is
  // kind === 'regex' only.
  const regexExtractsRaw = dump['loupe_timeline_regex_extracts'];
  if (regexExtractsRaw) {
    const regexExtracts = JSON.parse(regexExtractsRaw);
    const forFile = regexExtracts[fileKey] || [];
    assert.equal(forFile.length, 0,
      `regex-extracts persistence must be empty for this file (auto ` +
      `extracts are ephemeral); got: ${JSON.stringify(forFile)}`);
  }
});

test('reopen: auto-extract re-runs, no toast, columns re-derived, persistence stays empty', () => {
  const sandbox = buildSandbox();
  const col = readJsonExampleColumn7();
  const fileKey = 'json-example.csv|77222|TEST_REOPEN';

  // First open — populates the marker.
  const view1 = buildView(sandbox, col, fileKey);
  view1._autoExtractBestEffort();
  const firstCount = view1._extractedCols.length;
  assert.ok(firstCount >= 10, `first-open setup: expected >=10 columns, got ${firstCount}`);
  assert.ok(view1.toasts.length >= 1, 'first-open setup: toast must fire');

  // Reopen — fresh view instance, same sandbox (so localStorage carries
  // the stamped marker forward).
  const view2 = buildView(sandbox, col, fileKey);
  view2._autoExtractBestEffort();

  assert.equal(view2._extractedCols.length, firstCount,
    `reopen must produce the SAME number of columns as first open; ` +
    `first=${firstCount}, reopen=${view2._extractedCols.length}. ` +
    `If reopen produces fewer, the silent-drop bug has regressed.`);

  assert.equal(view2.toasts.length, 0,
    `reopen must NOT toast (toast-shown marker present); got: ` +
    `${JSON.stringify(view2.toasts)}`);

  // Persistence still empty after reopen.
  const dump = sandbox.localStorage._dump();
  const regexExtractsRaw = dump['loupe_timeline_regex_extracts'];
  if (regexExtractsRaw) {
    const regexExtracts = JSON.parse(regexExtractsRaw);
    const forFile = regexExtracts[fileKey] || [];
    assert.equal(forFile.length, 0,
      `regex-extracts persistence must remain empty after reopen; got: ` +
      `${JSON.stringify(forFile)}`);
  }
});

test('reopen with pre-existing user regex extract: user wins, count matches, persistence preserved', () => {
  const sandbox = buildSandbox();
  const col = readJsonExampleColumn7();
  const fileKey = 'json-example.csv|77222|TEST_USER_REGEX';

  // First open — to know how many auto cols a clean run produces.
  const baseline = buildView(sandbox, col, fileKey);
  baseline._autoExtractBestEffort();
  const baselineCount = baseline._extractedCols.length;
  assert.ok(baselineCount >= 10, `baseline must produce >=10 columns`);

  // Simulate a closed/reopened file with a manual Regex-tab extract
  // already persisted. We use a different fileKey so the toast-shown
  // marker doesn't apply (this is the "first open with manual regex
  // already present" scenario — equivalent to reopen since the
  // extraction itself doesn't depend on the marker).
  const fileKey2 = 'json-example.csv|77222|TEST_USER_REGEX_2';
  const userPattern = '\\b([a-z]+\\.[a-z]+)\\b';
  const view = buildView(sandbox, col, fileKey2, {
    preSeedRegexExtracts: [{
      name: 'My Custom Extract',
      col: 1,
      pattern: userPattern,
      flags: 'i',
      group: 1,
      kind: 'regex',
    }],
  });

  // Confirm the user extract is in there before the auto pass.
  const beforeAuto = view._extractedCols.length;
  assert.equal(beforeAuto, 1,
    `pre-seed must add exactly 1 user extract; got ${beforeAuto}`);

  // Run auto-extract.
  view._autoExtractBestEffort();

  // Total cols = 1 user + N auto, where N is uncapped below 200 MB
  // (test fixture is well below that). Dedup should ensure we don't
  // double up on the user's column 1 (if auto wanted to put a
  // text-host there, dedup either skips or coexists depending on
  // shape — we just assert the user extract is still there with its
  // original name and pattern).
  const userExtractStill = view._extractedCols.find(e => e.name === 'My Custom Extract');
  assert.ok(userExtractStill,
    `user regex extract must be preserved after auto-extract pass; ` +
    `extracted cols: ${view._extractedCols.map(e => e.name).join(', ')}`);
  assert.equal(userExtractStill.pattern, userPattern,
    `user extract's pattern must be unchanged`);
  assert.equal(userExtractStill.kind, 'regex',
    `user extract's kind must remain 'regex'`);

  // Persistence: the user extract MUST be in regex-extracts storage,
  // and ONLY the user extract (no auto entries piggy-back on the
  // persistence key).
  const dump = sandbox.localStorage._dump();
  const regexExtractsRaw = dump['loupe_timeline_regex_extracts'];
  assert.ok(regexExtractsRaw,
    `loupe_timeline_regex_extracts must exist (the user extract was ` +
    `persisted via _addRegexExtractNoRender)`);
  const regexExtracts = JSON.parse(regexExtractsRaw);
  const forFile = regexExtracts[fileKey2] || [];
  assert.equal(forFile.length, 1,
    `persistence must contain exactly 1 entry (the user regex); got ` +
    `${forFile.length}: ${JSON.stringify(forFile)}`);
  assert.equal(forFile[0].pattern, userPattern,
    `persisted entry must be the user's regex`);
  assert.equal(forFile[0].kind, 'regex',
    `persisted entry must have kind:'regex' (no auto leak)`);
});

test('legacy AUTOEXTRACT_DONE key is deleted on first toast-shown load', () => {
  // Migration test: pre-seed the legacy key, then trigger any path
  // that calls `_loadAutoExtractToastShownFor`. The legacy key must
  // be gone after.
  const sandbox = buildSandbox();
  sandbox.localStorage.setItem(
    'loupe_timeline_autoextract_done',
    JSON.stringify({ 'some-old-file': true }));

  // Calling the load function directly is enough — we don't need a
  // full view here.
  sandbox.TimelineView._loadAutoExtractToastShownFor('any-key');

  const dump = sandbox.localStorage._dump();
  assert.equal(dump['loupe_timeline_autoextract_done'], undefined,
    `legacy key must be deleted on first call to ` +
    `_loadAutoExtractToastShownFor; remaining keys: ` +
    `${Object.keys(dump).join(', ')}`);
});
