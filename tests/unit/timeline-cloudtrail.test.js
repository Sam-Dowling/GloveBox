'use strict';
// timeline-cloudtrail.test.js — AWS CloudTrail tokeniser (JSONL with
// canonical column projection).
//
// CloudTrail is the de-facto AWS audit log: every API call against
// every AWS service writes a record with `eventTime`, `eventName`,
// `eventSource`, `awsRegion`, `sourceIPAddress`, `userIdentity`, …
// Records are emitted in two on-disk shapes:
//   • Wrapped: `{"Records":[{event}, …]}` (single JSON document).
//     The router decodes + unwraps to JSONL bytes BEFORE this
//     tokeniser sees the input.
//   • JSONL:   one event per line (no wrapper). Sniffed via the
//     CloudTrail-key probe in `_sniffTimelineContent`.
// Both routes converge on the tokeniser exercised below.
//
// The CloudTrail tokeniser is a thin wrapper over JSONL with three
// behavioural overrides:
//   1. Schema is PRE-SEEDED with canonical CloudTrail columns, so
//      the columns appear in headline order regardless of what keys
//      the first real record happens to carry.
//   2. `getDefaultStackColIdx()` always returns the canonical
//      index of `eventName` (rather than walking the JSONL stack-
//      candidate priority list).
//   3. `getFormatLabel()` returns `'AWS CloudTrail'`.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-parser-helpers.js',
  'src/app/timeline/timeline-helpers.js',
], {
  expose: [
    '_tlMakeCloudTrailTokenizer',
    '_TL_CLOUDTRAIL_CANONICAL_COLS',
  ],
});
const {
  _tlMakeCloudTrailTokenizer,
  _TL_CLOUDTRAIL_CANONICAL_COLS,
} = ctx;

// A representative CloudTrail record. Keys are intentionally in a
// different order than the canonical column list to prove the
// tokeniser projects onto the canonical schema (columns left-aligned,
// not record-order).
const SAMPLE_RECORD = {
  eventVersion: '1.08',
  userIdentity: {
    type: 'IAMUser',
    principalId: 'AIDAEXAMPLE12345',
    arn: 'arn:aws:iam::123456789012:user/alice',
    accountId: '123456789012',
    userName: 'alice',
  },
  eventTime: '2024-10-15T22:14:15Z',
  eventSource: 's3.amazonaws.com',
  eventName: 'PutObject',
  awsRegion: 'us-east-1',
  sourceIPAddress: '203.0.113.42',
  userAgent: 'aws-cli/2.13.0',
  requestParameters: { bucketName: 'logs-prod', key: 'app/2024-10-15.log' },
  responseElements: null,
  eventID: 'a1b2c3d4-5678-90ab-cdef-1234567890ab',
  readOnly: false,
  eventType: 'AwsApiCall',
  managementEvent: true,
  recipientAccountId: '123456789012',
  requestID: 'XYZ123ABC',
};

// ── Construction ──────────────────────────────────────────────────────
test('factory: returns the expected closure shape', () => {
  const tk = _tlMakeCloudTrailTokenizer();
  assert.strictEqual(typeof tk.tokenize, 'function');
  assert.strictEqual(typeof tk.getColumns, 'function');
  assert.strictEqual(typeof tk.getDefaultStackColIdx, 'function');
  assert.strictEqual(typeof tk.getFormatLabel, 'function');
  assert.strictEqual(tk.getFormatLabel(), 'AWS CloudTrail');
});

test('factory: each instance is independent (no shared mutable state)', () => {
  const a = _tlMakeCloudTrailTokenizer();
  const b = _tlMakeCloudTrailTokenizer();
  // The schemas should already be pre-seeded identically. Drive A
  // with one record carrying an unknown key — that key will spill
  // to A's `_extra` but must NOT leak into B's schema.
  a.tokenize(JSON.stringify({ ...SAMPLE_RECORD, customApp: 'foo' }), 0);
  const colsA = a.getColumns(0);
  const colsB = b.getColumns(0);
  assert.deepStrictEqual(colsA, colsB,
    'instances must share the same canonical schema, untouched by data');
});

// ── Pre-seeded canonical schema ──────────────────────────────────────
test('schema is pre-seeded with the canonical column list (in canonical order)', () => {
  const tk = _tlMakeCloudTrailTokenizer();
  // Don't tokenize anything yet — the schema should already be set.
  const cols = tk.getColumns(0);
  // Every canonical column should appear, in canonical order.
  for (let i = 0; i < _TL_CLOUDTRAIL_CANONICAL_COLS.length; i++) {
    assert.strictEqual(cols[i], _TL_CLOUDTRAIL_CANONICAL_COLS[i],
      `column ${i} must be ${_TL_CLOUDTRAIL_CANONICAL_COLS[i]}, got ${cols[i]}`);
  }
  // `_extra` is always the last column.
  assert.strictEqual(cols[cols.length - 1], '_extra');
  // Width = canonical + _extra.
  assert.strictEqual(cols.length, _TL_CLOUDTRAIL_CANONICAL_COLS.length + 1);
});

test('canonical schema includes the most useful CloudTrail keys', () => {
  // Sanity-check the canonical list. These keys MUST be present —
  // they're what an analyst expects to see at-a-glance.
  const expected = [
    'eventTime', 'eventName', 'eventSource', 'awsRegion',
    'sourceIPAddress', 'userIdentity.type', 'userIdentity.userName',
  ];
  for (const k of expected) {
    assert.strictEqual(_TL_CLOUDTRAIL_CANONICAL_COLS.includes(k), true,
      `canonical schema missing required column: ${k}`);
  }
});

test('eventTime is column 0 (analysts read time-first)', () => {
  assert.strictEqual(_TL_CLOUDTRAIL_CANONICAL_COLS[0], 'eventTime');
});

test('eventName is column 1 (the headline action)', () => {
  assert.strictEqual(_TL_CLOUDTRAIL_CANONICAL_COLS[1], 'eventName');
});

// ── Record projection ────────────────────────────────────────────────
test('record projects onto canonical schema in canonical order', () => {
  const tk = _tlMakeCloudTrailTokenizer();
  const cells = tk.tokenize(JSON.stringify(SAMPLE_RECORD), 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cells.length, cols.length);

  // Spot-check the canonical columns map to the right cell values.
  const idx = (k) => cols.indexOf(k);
  assert.strictEqual(cells[idx('eventTime')], '2024-10-15T22:14:15Z');
  assert.strictEqual(cells[idx('eventName')], 'PutObject');
  assert.strictEqual(cells[idx('eventSource')], 's3.amazonaws.com');
  assert.strictEqual(cells[idx('awsRegion')], 'us-east-1');
  assert.strictEqual(cells[idx('sourceIPAddress')], '203.0.113.42');
  assert.strictEqual(cells[idx('userIdentity.type')], 'IAMUser');
  assert.strictEqual(cells[idx('userIdentity.userName')], 'alice');
  assert.strictEqual(cells[idx('userIdentity.arn')],
    'arn:aws:iam::123456789012:user/alice');
  assert.strictEqual(cells[idx('userIdentity.accountId')], '123456789012');
  assert.strictEqual(cells[idx('userAgent')], 'aws-cli/2.13.0');
  assert.strictEqual(cells[idx('eventID')],
    'a1b2c3d4-5678-90ab-cdef-1234567890ab');
  assert.strictEqual(cells[idx('readOnly')], 'false');
  assert.strictEqual(cells[idx('eventType')], 'AwsApiCall');
  assert.strictEqual(cells[idx('managementEvent')], 'true');
});

test('records missing canonical keys leave those cells empty (no width drift)', () => {
  const tk = _tlMakeCloudTrailTokenizer();
  // Minimal record — no userIdentity, no userAgent, no error fields.
  const minimal = {
    eventTime: '2024-10-15T22:00:00Z',
    eventName: 'AssumeRole',
    eventSource: 'sts.amazonaws.com',
  };
  const cells = tk.tokenize(JSON.stringify(minimal), 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cells.length, cols.length);
  // Present:
  const idx = (k) => cols.indexOf(k);
  assert.strictEqual(cells[idx('eventTime')], '2024-10-15T22:00:00Z');
  assert.strictEqual(cells[idx('eventName')], 'AssumeRole');
  assert.strictEqual(cells[idx('eventSource')], 'sts.amazonaws.com');
  // Missing canonical keys → empty cells.
  assert.strictEqual(cells[idx('awsRegion')], '');
  assert.strictEqual(cells[idx('sourceIPAddress')], '');
  assert.strictEqual(cells[idx('userIdentity.type')], '');
  assert.strictEqual(cells[idx('userIdentity.userName')], '');
  assert.strictEqual(cells[idx('userAgent')], '');
});

test('non-canonical keys spill into _extra as JSON', () => {
  const tk = _tlMakeCloudTrailTokenizer();
  // Add a key NOT in the canonical list. CloudTrail records
  // routinely carry `requestParameters` / `responseElements` —
  // service-specific blobs that don't belong in the headline grid.
  const cells = tk.tokenize(JSON.stringify(SAMPLE_RECORD), 0);
  const cols = tk.getColumns(0);
  const extraIdx = cols.indexOf('_extra');
  assert.strictEqual(extraIdx, cols.length - 1);
  const extra = JSON.parse(cells[extraIdx]);
  // `requestParameters` was on the input record but not in the
  // canonical schema → must appear in _extra.
  assert.strictEqual(typeof extra['requestParameters.bucketName'], 'string');
  assert.strictEqual(extra['requestParameters.bucketName'], 'logs-prod');
  assert.strictEqual(extra['requestParameters.key'], 'app/2024-10-15.log');
  // `eventVersion` was on the input but isn't in the canonical
  // schema either.
  assert.strictEqual(extra['eventVersion'], '1.08');
});

// ── Default stack column ─────────────────────────────────────────────
test('default stack column always points at eventName', () => {
  const tk = _tlMakeCloudTrailTokenizer();
  // Even without driving any records, the canonical schema is
  // already seeded so the lookup must succeed.
  const idx = tk.getDefaultStackColIdx();
  assert.strictEqual(idx, _TL_CLOUDTRAIL_CANONICAL_COLS.indexOf('eventName'));
  // Sanity: that index resolves to `eventName` in the rendered
  // column list.
  const cols = tk.getColumns(0);
  assert.strictEqual(cols[idx], 'eventName');
});

test('default stack column is stable across records', () => {
  const tk = _tlMakeCloudTrailTokenizer();
  const before = tk.getDefaultStackColIdx();
  tk.tokenize(JSON.stringify(SAMPLE_RECORD), 0);
  tk.tokenize(JSON.stringify({ eventTime: 't2', eventName: 'GetObject' }), 0);
  const after = tk.getDefaultStackColIdx();
  assert.strictEqual(before, after,
    'default stack column must not drift as records are tokenised');
});

// ── Robustness ────────────────────────────────────────────────────────
test('skips invalid JSON lines without poisoning the schema', () => {
  const tk = _tlMakeCloudTrailTokenizer();
  // Garbage line.
  assert.strictEqual(tk.tokenize('not-json', 0), null);
  // Empty.
  assert.strictEqual(tk.tokenize('', 0), null);
  // Top-level array (CloudTrail records are objects).
  assert.strictEqual(tk.tokenize('[1,2,3]', 0), null);
  // Top-level scalar.
  assert.strictEqual(tk.tokenize('42', 0), null);
  // Schema must still be intact — feed a real record after the
  // garbage and confirm the canonical projection works.
  const cells = tk.tokenize(JSON.stringify(SAMPLE_RECORD), 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cells.length, cols.length);
  assert.strictEqual(cells[cols.indexOf('eventName')], 'PutObject');
});

test('tolerates a leading UTF-8 BOM on the first record', () => {
  const tk = _tlMakeCloudTrailTokenizer();
  const cells = tk.tokenize('\uFEFF' + JSON.stringify(SAMPLE_RECORD), 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cells[cols.indexOf('eventName')], 'PutObject');
});

// ── Cross-realm parity ───────────────────────────────────────────────
test('worker-shim copy of _tlMakeCloudTrailTokenizer matches main-bundle copy', () => {
  const shimCtx = loadModules(['src/app/timeline/timeline-parser-helpers.js', 'src/workers/timeline-worker-shim.js'], {
    expose: ['_tlMakeCloudTrailTokenizer'],
  });
  const shimMake = shimCtx._tlMakeCloudTrailTokenizer;
  assert.strictEqual(typeof shimMake, 'function',
    'shim must export _tlMakeCloudTrailTokenizer');
  const drive = (factory) => {
    const tk = factory();
    const lines = [
      JSON.stringify(SAMPLE_RECORD),
      JSON.stringify({
        eventTime: '2024-10-15T22:14:30Z',
        eventName: 'GetObject',
        eventSource: 's3.amazonaws.com',
        awsRegion: 'us-east-1',
        sourceIPAddress: '198.51.100.7',
        userIdentity: {
          type: 'AssumedRole',
          arn: 'arn:aws:sts::123456789012:assumed-role/Reader/session',
        },
      }),
      'not-json',
      '',
      JSON.stringify({
        eventTime: '2024-10-15T22:14:45Z',
        eventName: 'ConsoleLogin',
        eventSource: 'signin.amazonaws.com',
        unexpectedField: 'spillover-to-extra',
        responseElements: { ConsoleLogin: 'Success' },
      }),
    ];
    return {
      out: lines.map(l => tk.tokenize(l, 0)),
      cols: tk.getColumns(0),
      label: tk.getFormatLabel(),
      stackIdx: tk.getDefaultStackColIdx(),
    };
  };
  const a = drive(_tlMakeCloudTrailTokenizer);
  const b = drive(shimMake);
  assert.strictEqual(a.out.length, b.out.length);
  for (let i = 0; i < a.out.length; i++) {
    const ai = a.out[i], bi = b.out[i];
    if (ai === null || bi === null) {
      assert.strictEqual(ai, bi, `line ${i} null parity`);
      continue;
    }
    assert.strictEqual(ai.length, bi.length, `line ${i} width`);
    for (let j = 0; j < ai.length; j++) {
      assert.strictEqual(ai[j], bi[j], `line ${i} cell ${j}`);
    }
  }
  assert.strictEqual(a.cols.length, b.cols.length);
  for (let i = 0; i < a.cols.length; i++) {
    assert.strictEqual(a.cols[i], b.cols[i], 'col ' + i);
  }
  assert.strictEqual(a.label, b.label);
  assert.strictEqual(a.stackIdx, b.stackIdx);
});
