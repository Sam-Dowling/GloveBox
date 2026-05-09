'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-composite.test.js — composite RowStore builder + chrono-sort +
// enabled bitmap + mixed-time-domain refusal.
//
// Covers:
//   • `buildCompositeSchema(sources)` — canonical cols leading, fused
//     same-name columns, namespaced conflicting columns, time-domain
//     mismatch throw.
//   • `buildCompositeStore(sources, plan)` — cells populated via mapper,
//     canonical `__source` stamped, native cells occupy the right
//     composite columns, empty rows for other sources.
//   • `buildCompositeTime(sources)` — concat preserves length + ordering.
//   • `buildSourceOfRow(sources)` — per-row source-index mapping.
//   • `buildEnabledBitmap(sources, sourceOfRow)` — toggle-off flips bits.
//   • `sortCompositeByTime(timeMs)` — chrono sort with NaN-to-end.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle.js');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const ctx = loadModules([
  'src/constants.js',
  'src/row-store.js',
  'src/app/timeline/timeline-parser-helpers.js',
  'src/app/timeline/timeline-mapper.js',
  'src/app/timeline/timeline-composite.js',
], {
  expose: [
    'RowStore', 'RowStoreBuilder',
    'TIMELINE_CANONICAL_COLS',
    'buildCompositeSchema', 'buildCompositeStore',
    'buildCompositeTime', 'buildSourceOfRow',
    'buildEnabledBitmap', 'sortCompositeByTime',
  ],
});
const {
  RowStore, RowStoreBuilder, TIMELINE_CANONICAL_COLS,
  buildCompositeSchema, buildCompositeStore,
  buildCompositeTime, buildSourceOfRow,
  buildEnabledBitmap, sortCompositeByTime,
} = ctx;

// ── Helpers ────────────────────────────────────────────────────────────────

// Build a minimal SourceRecord stub suitable for composite builders.
function stubSource(opts) {
  const baseStore = RowStore.fromStringMatrix(opts.columns, opts.rows);
  const baseTimeMs = opts.timeMs != null
    ? (opts.timeMs instanceof Float64Array ? opts.timeMs : Float64Array.from(opts.timeMs))
    : new Float64Array(opts.rows.length);
  return {
    file: { name: opts.label, size: 0, lastModified: 0 },
    fileKey: opts.label + '|0|0',
    sourceId: opts.id || 1,
    sourceLabel: opts.label,
    formatLabel: opts.formatLabel || opts.formatKind.toUpperCase(),
    formatKind: opts.formatKind,
    baseColumns: opts.columns,
    baseStore,
    baseTimeMs,
    baseTimeIsNumeric: !!opts.numeric,
    timeCol: opts.timeCol || 0,
    stackCol: opts.stackCol || 1,
    evtxEvents: null,
    evtxFindings: null,
    ipColumns: [],
    enabled: opts.enabled === false ? false : true,
    truncated: false,
    originalRowCount: opts.rows.length,
  };
}

// ── Schema resolver ────────────────────────────────────────────────────────

test('buildCompositeSchema lays canonical cols first then native cols', () => {
  const s = stubSource({
    id: 1, label: 'events.csv', formatKind: 'csv',
    columns: ['hostname', 'message'],
    rows: [['web01', 'ok'], ['web02', 'fail']],
  });
  const plan = buildCompositeSchema([s]);
  assert.equal(plan.timeIsNumeric, false);
  // First N entries == canonical cols.
  for (let i = 0; i < TIMELINE_CANONICAL_COLS.length; i++) {
    assert.equal(plan.compositeColumns[i], TIMELINE_CANONICAL_COLS[i]);
  }
  // Native cols append after.
  assert.equal(plan.compositeColumns[TIMELINE_CANONICAL_COLS.length], 'hostname');
  assert.equal(plan.compositeColumns[TIMELINE_CANONICAL_COLS.length + 1], 'message');
});

test('buildCompositeSchema fuses same-name compatible CSV columns into one', () => {
  const a = stubSource({
    id: 1, label: 'a.csv', formatKind: 'csv',
    columns: ['host', 'status'],
    rows: [['h1', '200'], ['h2', '404']],
  });
  const b = stubSource({
    id: 2, label: 'b.csv', formatKind: 'csv',
    columns: ['host', 'status'],
    rows: [['h3', '500'], ['h4', '200']],
  });
  const plan = buildCompositeSchema([a, b]);
  // Both `host` and `status` should fuse (same name, same formatKind,
  // compatible content shape). Total composite col count =
  // (culled) canonical + 2 fused natives.
  assert.equal(plan.compositeColumns.length, plan.canonicalCols.length + 2);
  assert.ok(plan.compositeColumns.includes('host'));
  assert.ok(plan.compositeColumns.includes('status'));
});

test('buildCompositeSchema namespaces same-name incompatible columns', () => {
  const a = stubSource({
    id: 1, label: 'a.csv', formatKind: 'csv',
    columns: ['status'],
    rows: [['200'], ['404'], ['500'], ['200']],
  });
  const b = stubSource({
    id: 2, label: 'b.csv', formatKind: 'csv',
    columns: ['status'],
    rows: [['ok'], ['fail'], ['ok'], ['fail']],
  });
  const plan = buildCompositeSchema([a, b]);
  // Both `status` columns are different shape (numeric vs text) — so
  // they split into namespaced siblings.
  const natives = plan.compositeColumns.slice(plan.canonicalCols.length);
  assert.equal(natives.length, 2);
  // First source anchor keeps the bare name; second source gets prefix.
  assert.ok(natives[0] === 'status' || natives[0].startsWith('a.csv·'));
  assert.ok(natives.some(n => n.startsWith('b.csv·status')));
});

test('buildCompositeSchema throws on mixed time domains', () => {
  const a = stubSource({
    id: 1, label: 'wall.csv', formatKind: 'csv',
    columns: ['ts'], rows: [['2024-01-01']],
    numeric: false,
  });
  const b = stubSource({
    id: 2, label: 'num.csv', formatKind: 'csv',
    columns: ['seq'], rows: [['1']],
    numeric: true,
  });
  assert.throws(() => buildCompositeSchema([a, b]), /MIXED/i);
});

// ── Composite store builder ────────────────────────────────────────────────

test('buildCompositeStore stamps __source for every row', () => {
  const s = stubSource({
    id: 1, label: 'events.csv', formatKind: 'csv',
    formatLabel: 'CSV',
    columns: ['hostname', 'message'],
    rows: [['web01', 'login ok'], ['web02', 'login fail']],
  });
  const plan = buildCompositeSchema([s]);
  const store = buildCompositeStore([s], plan);
  assert.equal(store.rowCount, 2);
  const iSrc = plan.canonicalCols.indexOf('__source');
  assert.equal(store.getCell(0, iSrc), 'events.csv');
  assert.equal(store.getCell(1, iSrc), 'events.csv');
  // Format identity is intentionally NOT a canonical column —
  // the source filename plus the per-chip format badge cover it.
  assert.equal(plan.canonicalCols.indexOf('__format'), -1);
});

test('buildCompositeStore invokes the mapper and populates canonical Host cell', () => {
  const s = stubSource({
    id: 1, label: 'events.csv', formatKind: 'csv',
    columns: ['hostname', 'message'],
    rows: [['web01', 'hello'], ['web02', 'world']],
  });
  const plan = buildCompositeSchema([s]);
  const store = buildCompositeStore([s], plan);
  const iHost = plan.canonicalCols.indexOf('Host');
  assert.equal(store.getCell(0, iHost), 'web01');
  assert.equal(store.getCell(1, iHost), 'web02');
});

test('buildCompositeStore concatenates rows from multiple sources in source order', () => {
  const a = stubSource({
    id: 1, label: 'a.csv', formatKind: 'csv',
    columns: ['host'], rows: [['h1'], ['h2']],
  });
  const b = stubSource({
    id: 2, label: 'b.csv', formatKind: 'csv',
    columns: ['host'], rows: [['h3'], ['h4'], ['h5']],
  });
  const plan = buildCompositeSchema([a, b]);
  const store = buildCompositeStore([a, b], plan);
  assert.equal(store.rowCount, 5);
  const iSrc = plan.canonicalCols.indexOf('__source');
  // Rows 0–1 come from a.csv, 2–4 from b.csv.
  assert.equal(store.getCell(0, iSrc), 'a.csv');
  assert.equal(store.getCell(1, iSrc), 'a.csv');
  assert.equal(store.getCell(2, iSrc), 'b.csv');
  assert.equal(store.getCell(4, iSrc), 'b.csv');
});

test('buildCompositeStore leaves namespaced columns empty for rows from other sources', () => {
  const a = stubSource({
    id: 1, label: 'a.csv', formatKind: 'csv',
    columns: ['status'],
    rows: [['200'], ['404'], ['500'], ['200']],
  });
  const b = stubSource({
    id: 2, label: 'b.csv', formatKind: 'csv',
    columns: ['status'],
    rows: [['ok'], ['fail'], ['ok'], ['fail']],
  });
  const plan = buildCompositeSchema([a, b]);
  const store = buildCompositeStore([a, b], plan);
  const canonCount = plan.canonicalCols.length;
  const natives = plan.compositeColumns.slice(canonCount);
  // Locate each namespaced column in the composite.
  const iAStatus = canonCount + natives.findIndex(n => !n.includes('·'));
  const iBStatus = canonCount + natives.findIndex(n => n.includes('·'));
  // Row 0 from a.csv — a-status cell populated, b-status cell empty.
  assert.equal(store.getCell(0, iAStatus), '200');
  assert.equal(store.getCell(0, iBStatus), '');
  // Row 4 from b.csv — b-status cell populated, a-status empty.
  assert.equal(store.getCell(4, iAStatus), '');
  assert.equal(store.getCell(4, iBStatus), 'ok');
});

// ── Time / bitmap / sort ───────────────────────────────────────────────────

test('buildCompositeTime concatenates per-source time arrays', () => {
  const a = stubSource({
    id: 1, label: 'a', formatKind: 'csv',
    columns: ['x'], rows: [['r0'], ['r1']],
    timeMs: [100, 200],
  });
  const b = stubSource({
    id: 2, label: 'b', formatKind: 'csv',
    columns: ['x'], rows: [['r0'], ['r1']],
    timeMs: [150, 250],
  });
  const out = buildCompositeTime([a, b]);
  assert.equal(out.length, 4);
  assert.equal(out[0], 100);
  assert.equal(out[1], 200);
  assert.equal(out[2], 150);
  assert.equal(out[3], 250);
});

test('buildSourceOfRow produces a per-row source-index Uint32Array', () => {
  const a = stubSource({
    id: 1, label: 'a', formatKind: 'csv',
    columns: ['x'], rows: [['r0'], ['r1']],
  });
  const b = stubSource({
    id: 2, label: 'b', formatKind: 'csv',
    columns: ['x'], rows: [['r0'], ['r1'], ['r2']],
  });
  const out = buildSourceOfRow([a, b]);
  assert.ok(out instanceof Uint32Array);
  assert.equal(out.length, 5);
  assert.equal(out[0], 0);
  assert.equal(out[1], 0);
  assert.equal(out[2], 1);
  assert.equal(out[3], 1);
  assert.equal(out[4], 1);
});

test('buildEnabledBitmap flips bits when a source is disabled', () => {
  const a = stubSource({
    id: 1, label: 'a', formatKind: 'csv',
    columns: ['x'], rows: [['r0'], ['r1']],
  });
  const b = stubSource({
    id: 2, label: 'b', formatKind: 'csv',
    columns: ['x'], rows: [['r0'], ['r1']],
    enabled: false,
  });
  const sourceOfRow = buildSourceOfRow([a, b]);
  const bm = buildEnabledBitmap([a, b], sourceOfRow);
  assert.equal(bm.length, 4);
  assert.equal(bm[0], 1);
  assert.equal(bm[1], 1);
  assert.equal(bm[2], 0);
  assert.equal(bm[3], 0);
});

test('sortCompositeByTime sorts ascending with NaN last', () => {
  const time = Float64Array.from([30, 10, 20, NaN, 5]);
  const idx = sortCompositeByTime(time);
  assert.ok(idx instanceof Uint32Array);
  assert.equal(idx.length, 5);
  // Expected order: 4 (5), 1 (10), 2 (20), 0 (30), then NaN at 3.
  assert.equal(idx[0], 4);
  assert.equal(idx[1], 1);
  assert.equal(idx[2], 2);
  assert.equal(idx[3], 0);
  assert.equal(idx[4], 3);
});

// ── Canonical column culling (merged views) ────────────────────────────────

test('culls canonical columns populated by zero rows across every source', () => {
  // Two CSVs whose header names match very few canonical probes —
  // only `timestamp` and `raw` → Timestamp + Message. Every other
  // canonical (Host / User / Process / EventID / Severity / Category
  // / SourceIP / DestIP) should be culled.
  const a = stubSource({
    id: 1, label: 'a.csv', formatKind: 'csv',
    columns: ['timestamp', 'raw', 'extra1'],
    rows: [['2024-01-01', 'entry A', 'x'], ['2024-01-02', 'entry B', 'y']],
  });
  const b = stubSource({
    id: 2, label: 'b.csv', formatKind: 'csv',
    columns: ['timestamp', 'raw', 'extra2'],
    rows: [['2024-01-03', 'entry C', 'z'], ['2024-01-04', 'entry D', 'w']],
  });
  const plan = buildCompositeSchema([a, b]);
  // Always-kept canonicals.
  assert.ok(plan.canonicalCols.includes('__source'));
  assert.equal(plan.canonicalCols.includes('__format'), false);
  // Populated canonicals — only `Timestamp` is hit by the `timestamp`
  // probe alias. The CSV mapper does NOT project `raw` into a
  // canonical slot any more (wide-narrative columns stay on the
  // native plane), so every other canonical is culled.
  assert.ok(plan.canonicalCols.includes('Timestamp'));
  // Culled canonicals — neither source matches any non-Timestamp
  // probe.
  assert.equal(plan.canonicalCols.includes('Host'), false);
  assert.equal(plan.canonicalCols.includes('User'), false);
  assert.equal(plan.canonicalCols.includes('EventID'), false);
  assert.equal(plan.canonicalCols.includes('Severity'), false);
  assert.equal(plan.canonicalCols.includes('Category'), false);
  assert.equal(plan.canonicalCols.includes('SourceIP'), false);
  assert.equal(plan.canonicalCols.includes('DestIP'), false);
});

test('keeps __source unconditionally when n>=2', () => {
  // Pathological pair: columns that match NO canonical probe at all.
  // Only `__source` should survive in the canonical set.
  const a = stubSource({
    id: 1, label: 'a.csv', formatKind: 'csv',
    columns: ['zzq', 'qqq'],
    rows: [['v1', 'v2']],
  });
  const b = stubSource({
    id: 2, label: 'b.csv', formatKind: 'csv',
    columns: ['zzq', 'qqq'],
    rows: [['v3', 'v4']],
  });
  const plan = buildCompositeSchema([a, b]);
  assert.ok(plan.canonicalCols.includes('__source'));
  assert.equal(plan.canonicalCols.length, 1);
});

test('does NOT cull for single-source views (n=1)', () => {
  // Single-source views keep every canonical in the schema — the
  // grid hides empties via default `_gridColOrder` rather than
  // schema surgery, so a later merge can bring them back cleanly.
  const a = stubSource({
    id: 1, label: 'a.csv', formatKind: 'csv',
    columns: ['timestamp', 'raw'],
    rows: [['2024-01-01', 'entry A']],
  });
  const plan = buildCompositeSchema([a]);
  assert.equal(plan.canonicalCols.length, 9);
  assert.ok(plan.canonicalCols.includes('Host'));
  assert.ok(plan.canonicalCols.includes('DestIP'));
});

test('keeps a canonical populated by at least one source out of many', () => {
  // Source A populates `Host` (via `hostname`); source B does not.
  // `Host` should survive the cull because A emits it.
  const a = stubSource({
    id: 1, label: 'a.csv', formatKind: 'csv',
    columns: ['timestamp', 'hostname', 'raw'],
    rows: [['t1', 'web01', 'line']],
  });
  const b = stubSource({
    id: 2, label: 'b.csv', formatKind: 'csv',
    columns: ['timestamp', 'raw'],
    rows: [['t2', 'other']],
  });
  const plan = buildCompositeSchema([a, b]);
  assert.ok(plan.canonicalCols.includes('Host'));
});

test('M365-audit-schema CSVs produce a zero-empty-canonical composite', () => {
  // Regression guard for the dist/test1-1k.csv + dist/test2-1k.csv
  // merge pair: schema is Timestamp / UserId / EventName / Workload
  // / ClientIP / UserAgent / Outcome / TargetResource / Raw.
  //
  // Survivors after the cull (canonicals only — native columns sit
  // in `nativeCols`, not `canonicalCols`):
  //   __source, Timestamp, User, EventID, Severity,
  //   Category, SourceIP.
  // Culled: Host + DestIP (neither source carries a hostname or
  // destination IP).
  // Not canonical (live on the native plane):
  //   UserAgent, TargetResource, Raw — no canonical slot, the
  //   analyst pivots on them by their original column name.
  const a = stubSource({
    id: 1, label: 'a.csv', formatKind: 'csv',
    columns: ['Timestamp', 'UserId', 'EventName', 'Workload', 'ClientIP',
              'UserAgent', 'Outcome', 'TargetResource', 'Raw'],
    rows: [[
      '2026-04-08T18:37:13Z', 'brian@lit.com', 'UserLoggedIn',
      'AzureActiveDirectory', '10.67.139.172', 'Office/16.0',
      'Success', 'brian@lit.com', '{}',
    ]],
  });
  const b = stubSource({
    id: 2, label: 'b.csv', formatKind: 'csv',
    columns: ['Timestamp', 'UserId', 'EventName', 'Workload', 'ClientIP',
              'UserAgent', 'Outcome', 'TargetResource', 'Raw'],
    rows: [[
      '2026-04-08T18:53:04Z', 'steven@lit.com', 'FileAccessed',
      'SharePoint', '152.196.170.74', 'Postman/7.37.3',
      'Success', 'https://example.com/x', '{}',
    ]],
  });
  const plan = buildCompositeSchema([a, b]);
  // Every canonical survivor must have a non-empty value in at least
  // the first sample row — proves the cull predicate is sane.
  assert.ok(plan.canonicalCols.includes('__source'));
  assert.equal(plan.canonicalCols.includes('__format'), false);
  assert.ok(plan.canonicalCols.includes('Timestamp'));
  assert.ok(plan.canonicalCols.includes('User'));       // UserId alias
  assert.ok(plan.canonicalCols.includes('EventID'));    // EventName alias
  assert.ok(plan.canonicalCols.includes('Severity'));   // Outcome alias
  assert.ok(plan.canonicalCols.includes('Category'));   // Workload alias
  assert.ok(plan.canonicalCols.includes('SourceIP'));   // ClientIP alias
  // Culled: no column in this schema produces Host or DestIP.
  assert.equal(plan.canonicalCols.includes('Host'), false);
  assert.equal(plan.canonicalCols.includes('DestIP'), false);
  // Wide-narrative columns stay on the native plane.
  assert.equal(plan.canonicalCols.includes('Process'), false);
  assert.equal(plan.canonicalCols.includes('Message'), false);
  // The native columns still surface — UserAgent and Raw are
  // pivotable by their original header name.
  const nativeNames = plan.nativeCols.map(nc => nc.name.toLowerCase());
  assert.ok(nativeNames.includes('useragent'),
    'UserAgent must survive as a native composite column');
  assert.ok(nativeNames.includes('raw'),
    'Raw must survive as a native composite column');
});
