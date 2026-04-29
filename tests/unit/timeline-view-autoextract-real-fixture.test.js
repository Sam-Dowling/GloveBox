'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-autoextract-real-fixture.test.js — pin the auto-extract
// scanner against the real `examples/forensics/json-example.csv` fixture.
//
// HISTORY: a regression in `timeline-view-geoip.js` stamped the shared
// `loupe_timeline_autoextract_done` marker on the no-IP-columns path,
// poisoning the auto-extract idempotence guard so JSON / URL / host
// extraction silently never ran on files like this one. After the marker
// split, that bug can't recur — but the SCANNER itself could still
// regress (a depth-limit tweak, a sample-skip threshold change, a
// `Math.min` clamp that masks zero-result bugs, …) and it would only
// surface on real JSON-shaped CSVs. Pin the scanner's contract here.
//
// What this test verifies:
//   • Real CSV column 7 ("Raw Data") of `examples/forensics/json-example.csv`
//     parses as JSON in ≥ 50 % of sampled rows (the JSON-dominant gate).
//   • `_autoExtractScan` returns ≥ 1 proposal of kind `'json-leaf'` for
//     that column (the actual user-visible regression: "no extracted
//     columns appear after auto-extract runs").
//   • Every emitted proposal has `matchPct <= 100` (the array-leaf
//     overcount fix).
//   • The proposal cap (`MAX = 12` in `_autoExtractBestEffort`) is not
//     enforced INSIDE `_autoExtractScan` — the scanner emits the full set
//     and the apply loop trims (so a future "let's also cap in the
//     scanner" change would surface here).
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

// ── Fixture extraction ─────────────────────────────────────────────────────
//
// Read column 7 of the real CSV via a hand-rolled RFC4180 tokeniser. We
// deliberately don't reuse the production CSV worker — we want to assert
// the scanner's contract against the fixture content, not against a
// chain of parsers that could mask each other's regressions.
//
// The header row's column 7 is "Raw Data"; every data row has a JSON
// object in that column, with quoted internal quotes (`""key""`).

function readColumn7() {
  const csvPath = path.join(REPO_ROOT, 'examples', 'forensics', 'json-example.csv');
  const text = fs.readFileSync(csvPath, 'utf8');
  const rows = parseCsv(text);
  // Drop header.
  const header = rows.shift();
  assert.equal(header[7], 'Raw Data', 'fixture column 7 must be "Raw Data"');
  return rows.map(r => r[7] || '');
}

function parseCsv(text) {
  // Minimal RFC4180 parser — handles doubled-quote escaping, embedded
  // newlines inside quoted fields, no comments. Sufficient for our
  // fixture (which has neither leading BOM nor exotic line endings).
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

// ── vm harness — load helpers + drawer + autoextract under a stub class ──
//
// The autoextract mixin attaches to `TimelineView.prototype`. The real
// `TimelineView` is defined in `timeline-view.js` (~1500 lines, depends
// on the rest of the timeline subgraph). We declare a minimal stub class
// in the prelude so the mixin's `Object.assign(TimelineView.prototype,
// …)` succeeds, then call the methods on a plain instance whose fields
// we hand-populate from the fixture.

function loadScannerSandbox() {
  const sandbox = {
    console,
    Map, Set, Date, Math, JSON, RegExp, Error, TypeError,
    Object, Array, Number, String, Boolean,
    Uint8Array, Uint16Array, Uint32Array, Float64Array,
    parseInt, parseFloat, isFinite, isNaN, Symbol, Promise,
    setTimeout, clearTimeout,
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);

  const constantsSrc = fs.readFileSync(
    path.join(REPO_ROOT, 'src/constants.js'), 'utf8');
  const helpersSrc = fs.readFileSync(
    path.join(REPO_ROOT, 'src/app/timeline/timeline-helpers.js'), 'utf8');
  const drawerSrc = fs.readFileSync(
    path.join(REPO_ROOT, 'src/app/timeline/timeline-drawer.js'), 'utf8');
  const autoextractSrc = fs.readFileSync(
    path.join(REPO_ROOT, 'src/app/timeline/timeline-view-autoextract.js'), 'utf8');

  const stubClass =
    'class TimelineView { constructor() {} }\n';
  const expose =
    `\nglobalThis.TimelineView = TimelineView;\n` +
    `globalThis._tlMaybeJson = (typeof _tlMaybeJson !== 'undefined') ? _tlMaybeJson : undefined;\n` +
    `globalThis._tlJsonPathLabel = (typeof _tlJsonPathLabel !== 'undefined') ? _tlJsonPathLabel : undefined;\n` +
    `globalThis.TL_URL_RE = (typeof TL_URL_RE !== 'undefined') ? TL_URL_RE : undefined;\n` +
    `globalThis.TL_HOSTNAME_RE = (typeof TL_HOSTNAME_RE !== 'undefined') ? TL_HOSTNAME_RE : undefined;\n` +
    `globalThis.EVTX_COLUMNS = (typeof EVTX_COLUMNS !== 'undefined') ? EVTX_COLUMNS : undefined;\n` +
    `globalThis.TIMELINE_FORENSIC_EVTX_FIELDS_SET = (typeof TIMELINE_FORENSIC_EVTX_FIELDS_SET !== 'undefined') ? TIMELINE_FORENSIC_EVTX_FIELDS_SET : undefined;\n`;

  const combined =
    constantsSrc + '\n' +
    stubClass +
    helpersSrc + '\n' +
    drawerSrc + '\n' +
    autoextractSrc + '\n' +
    expose;

  vm.runInContext(combined, sandbox, {
    filename: 'timeline-view-autoextract-real-fixture:concat',
    displayErrors: true,
  });
  return sandbox;
}

// ── Build a scanner-shaped stub instance ───────────────────────────────────
//
// `_autoExtractScan` reads:
//   this.store.rowCount
//   this._baseColumns          (array of names)
//   this.formatLabel           (string — for EVTX detection)
//   this._cellAt(row, col)     (string accessor)
//   this._jsonCache            (Map; the function calls .get / .set on it)
//
// Plus it calls `this._jsonCollectLeafPaths(...)` from the drawer mixin,
// which the vm context already attached to the stub class's prototype.

function buildScannerInstance(sandbox, columnValues) {
  const TimelineView = sandbox.TimelineView;
  const view = new TimelineView();
  const baseColumns = ['Timestamp', 'EventType', 'UserId', 'Department',
                       'Severity', 'Status', 'DurationMs', 'Raw Data'];
  view._baseColumns = baseColumns;
  view.formatLabel = 'CSV';
  view._jsonCache = new sandbox.Map();
  view.store = {
    rowCount: columnValues.length,
    colCount: baseColumns.length,
    columns: baseColumns.slice(),
  };
  view._cellAt = function (row, col) {
    if (col === 7) return columnValues[row] || '';
    if (col === 0) return '2025-01-01T00:00:00Z';   // dummy timestamp
    return '';
  };
  return view;
}

// ── Tests ──────────────────────────────────────────────────────────────────

test('fixture sanity — column 7 of json-example.csv has 100 JSON rows', () => {
  const col = readColumn7();
  assert.equal(col.length, 100, 'fixture must have exactly 100 data rows');
  // Spot-check shape: every row should start with `{`.
  let jsonish = 0;
  for (const v of col) if (v && v.trimStart().startsWith('{')) jsonish++;
  assert.ok(jsonish >= 95,
    `expected >=95 JSON-shaped rows, got ${jsonish}`);
});

test('_autoExtractScan emits >=1 json-leaf proposal for the fixture', () => {
  // The actual user-visible regression we just diagnosed: this file
  // produced ZERO extracted columns because the GeoIP no-op path
  // poisoned the marker. Even with the marker fix, if the scanner
  // itself stops producing proposals (because someone tightens the
  // 30 %-of-rows gate, or shrinks `maxDepth` from 4 to 2, or breaks
  // `_jsonCollectLeafPaths`'s `[*]` recursion) the user will again
  // see no extracted columns. Pin the contract.
  const sandbox = loadScannerSandbox();
  const col = readColumn7();
  const view = buildScannerInstance(sandbox, col);
  const proposals = sandbox.TimelineView.prototype._autoExtractScan.call(view);
  assert.ok(Array.isArray(proposals),
    '_autoExtractScan must return an array');
  const jsonLeaf = proposals.filter(p => p && p.kind === 'json-leaf'
                                          && p.sourceCol === 7);
  assert.ok(jsonLeaf.length >= 1,
    `expected >=1 json-leaf proposal for column 7 (Raw Data), ` +
    `got ${jsonLeaf.length}. Total proposals: ${proposals.length}. ` +
    `Kinds: ${[...new Set(proposals.map(p => p.kind))].join(',')}`);
});

test('_autoExtractScan never emits matchPct > 100', () => {
  // Pre-fix, `[*]`-recursed array leaves could exceed 100 % because
  // `_jsonCollectLeafPaths` emits one entry per array element while the
  // denominator is `samples.length` (rows). Clamp pinned here so a
  // future "remove the Math.min, who needs it" PR breaks visibly.
  const sandbox = loadScannerSandbox();
  const col = readColumn7();
  const view = buildScannerInstance(sandbox, col);
  const proposals = sandbox.TimelineView.prototype._autoExtractScan.call(view);
  for (const p of proposals) {
    assert.ok(typeof p.matchPct === 'number' && Number.isFinite(p.matchPct),
      `proposal matchPct must be finite, got ${p.matchPct} for ${JSON.stringify(p)}`);
    assert.ok(p.matchPct <= 100,
      `proposal matchPct must be <= 100, got ${p.matchPct} for ` +
      `kind=${p.kind} path=${JSON.stringify(p.path)}`);
    assert.ok(p.matchPct >= 0,
      `proposal matchPct must be >= 0, got ${p.matchPct}`);
  }
});

test('_autoExtractScan does NOT enforce the MAX=12 cap (apply loop trims)', () => {
  // The 12-column cap lives in `_autoExtractBestEffort` (the apply
  // scheduler), not in `_autoExtractScan`. The scanner emits the full
  // set so the dialog UX has access to all candidates — only the silent
  // first-open pass clips to 12. Pin the separation so a refactor that
  // collapses the cap into the scanner doesn't silently shrink the
  // Extract Values dialog's catalog.
  const sandbox = loadScannerSandbox();
  const col = readColumn7();
  const view = buildScannerInstance(sandbox, col);
  const proposals = sandbox.TimelineView.prototype._autoExtractScan.call(view);
  // The fixture has more than 12 distinct leaves at depth <= 4
  // (verified empirically); if the scanner enforced the cap we'd see
  // exactly 12 here.
  assert.ok(proposals.length > 12,
    `scanner should emit > 12 proposals before the apply-loop cap; ` +
    `got ${proposals.length} — has the MAX cap leaked into the scanner?`);
});

// ── Issue 2 regression pins (text-host detection) ──────────────────────────
//
// These tests build a richer multi-column stub (one column per call to
// `_cellAt`) so we can drive the text-host detection branch directly.
// The default `buildScannerInstance` only varies col 7; for these we
// override `_cellAt` with a per-column lookup table.

function buildMultiColView(sandbox, columnsByIndex, baseColumns) {
  const TimelineView = sandbox.TimelineView;
  const view = new TimelineView();
  view._baseColumns = baseColumns;
  view.formatLabel = 'CSV';
  view._jsonCache = new sandbox.Map();
  const rowCount = Math.max(...Object.values(columnsByIndex).map(a => a.length));
  view.store = {
    rowCount,
    colCount: baseColumns.length,
    columns: baseColumns.slice(),
  };
  view._cellAt = function (row, col) {
    const arr = columnsByIndex[col];
    if (!arr) return '';
    return arr[row] || '';
  };
  return view;
}

test('_autoExtractScan does NOT emit text-host proposal for ISO-8601 Timestamp column', () => {
  // The unanchored `TL_HOSTNAME_INLINE_RE` matched the millisecond
  // fragment `21.271Z` inside ISO-8601 timestamps and flagged Timestamp
  // as a hostname column. After switching detection to `TL_HOSTNAME_RE`
  // (anchored, full-cell), this junk proposal disappears. Pin it.
  const sandbox = loadScannerSandbox();
  const timestamps = [];
  for (let i = 0; i < 50; i++) {
    const ms = String(100 + i).padStart(3, '0');
    timestamps.push(`2025-11-03T08:25:${String(20 + (i % 30)).padStart(2, '0')}.${ms}Z`);
  }
  const view = buildMultiColView(sandbox, { 0: timestamps }, ['Timestamp']);
  const proposals = sandbox.TimelineView.prototype._autoExtractScan.call(view);
  const textHostHits = proposals.filter(
    p => p && p.kind === 'text-host' && p.sourceCol === 0);
  assert.equal(textHostHits.length, 0,
    `Timestamp column must not produce a text-host proposal; got ` +
    `${textHostHits.length}: ${JSON.stringify(textHostHits)}`);
});

test('_autoExtractScan DOES emit text-host proposal for genuinely hostname-shaped column', () => {
  // Sanity check on the anchored fix: legitimate hostname columns
  // (whole-cell hostnames) must still be detected, otherwise we've
  // over-corrected. Stays a behavioural pin in case someone later
  // tightens the regex further (e.g. requires letter-only TLD) and
  // breaks the common case.
  const sandbox = loadScannerSandbox();
  const hosts = [];
  const samples = ['example.com', 'api.example.com', 'mail.google.com',
    'cdn.cloudflare.com', 'status.github.com', 'login.microsoft.com',
    'auth.okta.com', 'sso.example.org', 'web.example.net', 'srv.example.io'];
  for (let i = 0; i < 50; i++) hosts.push(samples[i % samples.length]);
  const view = buildMultiColView(sandbox, { 0: hosts }, ['Server']);
  const proposals = sandbox.TimelineView.prototype._autoExtractScan.call(view);
  const textHostHits = proposals.filter(
    p => p && p.kind === 'text-host' && p.sourceCol === 0);
  assert.ok(textHostHits.length >= 1,
    `legitimate hostname column should produce >=1 text-host proposal; ` +
    `got ${textHostHits.length}. All proposals: ` +
    `${JSON.stringify(proposals.map(p => ({k: p.kind, c: p.sourceCol})))}`);
});

test('_autoExtractScan json-leaf proposals only come from JSON-shaped column 7 of fixture', () => {
  // Defence-in-depth: confirm no JSON-leaf proposals leak from columns
  // 0-6 of the real fixture (Timestamp, EventType, UserId, Department,
  // Severity, Status, DurationMs). If any did, that would indicate
  // either a regression in `_tlMaybeJson`'s gating or a bug where the
  // JSON branch sees data from the wrong column.
  const sandbox = loadScannerSandbox();
  const col7 = readColumn7();
  // Default buildScannerInstance returns dummy strings for cols 0-6,
  // which suits us — they're not JSON-shaped, so they must not produce
  // json-* proposals.
  const view = buildScannerInstance(sandbox, col7);
  const proposals = sandbox.TimelineView.prototype._autoExtractScan.call(view);
  const jsonProposalsFromOtherCols = proposals.filter(
    p => p && (p.kind === 'json-leaf' || p.kind === 'json-host' ||
               p.kind === 'json-url') && p.sourceCol !== 7);
  assert.equal(jsonProposalsFromOtherCols.length, 0,
    `JSON-shaped proposals must only come from col 7 (Raw Data); got ` +
    `${jsonProposalsFromOtherCols.length} from other cols: ` +
    `${JSON.stringify(jsonProposalsFromOtherCols.map(p => ({k:p.kind, c:p.sourceCol})))}`);
});
