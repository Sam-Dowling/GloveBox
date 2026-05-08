'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-autoextract-canonical-skip.test.js — regression guard for
// merged-Timeline canonical columns.
//
// `TIMELINE_CANONICAL_COLS` prefixes every merged Timeline with two
// bookkeeping columns (`__source`, `__format`) that carry the source
// filename and format label. When those filenames look hostname-shaped
// (common case: `events.csv` / `test1-1k.csv` / `m365-audit-a.csv` — a
// short alphabetic "TLD" token plus a dot) the unanchored
// `TL_HOSTNAME_INLINE_RE` matches them and `_autoExtractScan` emits a
// `text-host` proposal. The auto-apply pump then creates a spurious
// `__source (host)` regex-extracted column — a literal copy of
// `__source` with a different name, pure grid clutter.
//
// The fix lives in `_autoExtractScan`: skip any base column whose name
// starts with `__` (the canonical prefix). This test pins that guard
// so nobody silently removes it during a future refactor.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

// Inlined sandbox loader (copied from the sibling fixture test — the
// helper isn't exported and inlining keeps the test's dependencies
// auditable without adding a tests/helpers/ file).
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
    filename: 'timeline-view-autoextract-canonical-skip:concat',
    displayErrors: true,
  });
  return sandbox;
}

function buildView(sandbox, columnsByIndex, baseColumns) {
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

test('_autoExtractScan skips hostname-shaped __source column (no spurious (host) extract)', () => {
  // Real-world trigger: a merged Timeline stamps every row with the
  // originating source's filename in the canonical `__source` column.
  // Filenames like `test1-1k.csv` are hostname-shaped to the
  // unanchored inline regex, which would produce a `text-host`
  // proposal and, via the auto-apply pump, a `__source (host)`
  // regex-extracted column that's a pointless copy of `__source`.
  const sandbox = loadScannerSandbox();
  const sources = [];
  // 50 rows alternating between two hostname-shaped filenames —
  // well above the `matchPct >= 80` threshold.
  for (let i = 0; i < 50; i++) {
    sources.push(i % 2 === 0 ? 'test1-1k.csv' : 'test2-1k.csv');
  }
  const view = buildView(sandbox, { 0: sources }, ['__source']);
  const proposals = sandbox.TimelineView.prototype._autoExtractScan.call(view);
  // No proposals at all for col 0 — the entire column is skipped.
  const anyForCanonical = proposals.filter(p => p && p.sourceCol === 0);
  assert.equal(anyForCanonical.length, 0,
    'canonical __source column must produce ZERO proposals; got ' +
    anyForCanonical.length + ': ' +
    JSON.stringify(anyForCanonical.map(p => ({k: p.kind, n: p.proposedName}))));
});

test('_autoExtractScan also skips __format canonical column', () => {
  // Same guard covers `__format` (format label, e.g. "CSV" / "EVTX").
  // Less likely to false-hit the hostname regex but still not data
  // the analyst should ever need to extract from.
  const sandbox = loadScannerSandbox();
  const fmts = [];
  for (let i = 0; i < 50; i++) fmts.push('CSV');
  const view = buildView(sandbox, { 0: fmts }, ['__format']);
  const proposals = sandbox.TimelineView.prototype._autoExtractScan.call(view);
  const anyForCanonical = proposals.filter(p => p && p.sourceCol === 0);
  assert.equal(anyForCanonical.length, 0,
    'canonical __format column must produce ZERO proposals');
});

test('_autoExtractScan still emits proposals for non-canonical columns in same scan', () => {
  // Defence-in-depth: make sure the skip is scoped to the canonical
  // column, not a blanket skip. Setup: col 0 = __source (filenames),
  // col 1 = Server (legitimate hostnames). After the fix, col 1 must
  // still produce a text-host proposal; only col 0 is silenced.
  const sandbox = loadScannerSandbox();
  const sources = [];
  const hosts = [];
  const hostSamples = ['example.com', 'api.example.com', 'mail.google.com',
    'cdn.cloudflare.com', 'status.github.com'];
  for (let i = 0; i < 50; i++) {
    sources.push('test1-1k.csv');
    hosts.push(hostSamples[i % hostSamples.length]);
  }
  const view = buildView(sandbox,
    { 0: sources, 1: hosts },
    ['__source', 'Server']);
  const proposals = sandbox.TimelineView.prototype._autoExtractScan.call(view);
  // Col 0 (__source) — silent.
  assert.equal(
    proposals.filter(p => p && p.sourceCol === 0).length, 0,
    '__source column must be skipped');
  // Col 1 (Server) — still detected.
  const textHostHits = proposals.filter(
    p => p && p.kind === 'text-host' && p.sourceCol === 1);
  assert.ok(textHostHits.length >= 1,
    'Server column must still produce text-host proposal; got ' +
    textHostHits.length);
});

test('_autoExtractScan does NOT skip a legitimate column with a leading underscore', () => {
  // Safety-net: the skip is strictly for columns starting with TWO
  // underscores (the canonical prefix). A user-defined column named
  // `_internal` or `_id` must still be scanned normally — that's
  // legitimate schema choice, not canonical bookkeeping.
  const sandbox = loadScannerSandbox();
  const hosts = [];
  const hostSamples = ['example.com', 'api.example.com', 'mail.google.com',
    'cdn.cloudflare.com', 'status.github.com'];
  for (let i = 0; i < 50; i++) hosts.push(hostSamples[i % hostSamples.length]);
  const view = buildView(sandbox, { 0: hosts }, ['_internal']);
  const proposals = sandbox.TimelineView.prototype._autoExtractScan.call(view);
  const textHostHits = proposals.filter(
    p => p && p.kind === 'text-host' && p.sourceCol === 0);
  assert.ok(textHostHits.length >= 1,
    'single-underscore column must still be scanned; got ' +
    textHostHits.length + ' text-host proposals');
});
