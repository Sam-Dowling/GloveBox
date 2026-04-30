'use strict';
// timeline-logfmt.test.js — logfmt tokeniser.
//
// logfmt is a flat `key=value key="quoted value" key=` line
// format with no header — used by Heroku, Logrus, Hashicorp
// tools (Consul/Vault/Nomad), and many Go services. Spec:
// https://brandur.org/logfmt.
//
// Grammar:
//   pair    := key '=' value | key
//   key     := [A-Za-z_][\w.\-/]*
//   value   := '"' (\" | \\ | \n | \r | \t | non-quote)* '"'
//            | non-whitespace*
//
// What we verify:
//   • Schema lock-in from first record; later records project +
//     spill unknown keys into `_extra`.
//   • Quoted values with `\"`, `\\`, `\n` escapes round-trip.
//   • Bare values run to whitespace; embedded `=` after the first
//     does not break the value.
//   • Missing-value (bare-key) form yields the empty string.
//   • Default stack column probes `[level, severity, lvl, msg,
//     status, method]` against the locked schema (returns null
//     when no candidate matches).
//   • Non-logfmt input (free text, no `=`) returns null.
//   • Format label = `'logfmt'`.
//   • Cross-realm parity with the worker-shim copy.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-helpers.js',
], {
  expose: ['_tlMakeLogfmtTokenizer'],
});
const { _tlMakeLogfmtTokenizer } = ctx;

// ── Construction ──────────────────────────────────────────────────────
test('factory: returns the expected closure shape', () => {
  const tk = _tlMakeLogfmtTokenizer();
  assert.strictEqual(typeof tk.tokenize, 'function');
  assert.strictEqual(typeof tk.getColumns, 'function');
  assert.strictEqual(typeof tk.getDefaultStackColIdx, 'function');
  assert.strictEqual(typeof tk.getFormatLabel, 'function');
  assert.strictEqual(tk.getFormatLabel(), 'logfmt');
});

// ── Schema lock + projection ─────────────────────────────────────────
test('first record locks the schema; later records project + spill', () => {
  const tk = _tlMakeLogfmtTokenizer();
  const a = tk.tokenize('level=info msg="hello world" service=api', 0);
  assert.ok(Array.isArray(a));
  const cols = tk.getColumns();
  assert.deepStrictEqual(cols, ['level', 'msg', 'service', '_extra']);
  assert.strictEqual(a[cols.indexOf('level')], 'info');
  assert.strictEqual(a[cols.indexOf('msg')], 'hello world');
  assert.strictEqual(a[cols.indexOf('service')], 'api');
  assert.strictEqual(a[cols.indexOf('_extra')], '');

  // Reordered + missing one + adding one.
  const b = tk.tokenize('service=worker level=warn dur=42ms', 0);
  assert.strictEqual(b[cols.indexOf('level')], 'warn');
  assert.strictEqual(b[cols.indexOf('msg')], '');
  assert.strictEqual(b[cols.indexOf('service')], 'worker');
  const extras = JSON.parse(b[cols.indexOf('_extra')]);
  assert.strictEqual(extras.dur, '42ms');
});

// ── Quoted-value escapes ─────────────────────────────────────────────
test('quoted values: spaces, \\", \\\\, \\n round-trip', () => {
  const tk = _tlMakeLogfmtTokenizer();
  const a = tk.tokenize(
    'msg="hello \\"world\\"" path="C:\\\\Users\\\\bob" body="line1\\nline2"', 0);
  const cols = tk.getColumns();
  assert.strictEqual(a[cols.indexOf('msg')], 'hello "world"');
  assert.strictEqual(a[cols.indexOf('path')], 'C:\\Users\\bob');
  assert.strictEqual(a[cols.indexOf('body')], 'line1\nline2');
});

test('quoted values: unterminated quoted string consumes to EOL', () => {
  const tk = _tlMakeLogfmtTokenizer();
  const a = tk.tokenize('level=info msg="oops no close', 0);
  const cols = tk.getColumns();
  assert.strictEqual(a[cols.indexOf('level')], 'info');
  assert.strictEqual(a[cols.indexOf('msg')], 'oops no close');
});

// ── Bare values ─────────────────────────────────────────────────────
test('bare values: run to whitespace; preserve embedded `=` after first', () => {
  const tk = _tlMakeLogfmtTokenizer();
  const a = tk.tokenize('url=http://x.example/?q=v&a=b method=GET', 0);
  const cols = tk.getColumns();
  assert.strictEqual(a[cols.indexOf('url')], 'http://x.example/?q=v&a=b');
  assert.strictEqual(a[cols.indexOf('method')], 'GET');
});

// ── Missing-value form ──────────────────────────────────────────────
test('bare keys (no `=`) yield empty string but lock the column', () => {
  const tk = _tlMakeLogfmtTokenizer();
  const a = tk.tokenize('marker level=info', 0);
  const cols = tk.getColumns();
  assert.deepStrictEqual(cols, ['marker', 'level', '_extra']);
  assert.strictEqual(a[cols.indexOf('marker')], '');
  assert.strictEqual(a[cols.indexOf('level')], 'info');
});

// ── Default stack column ────────────────────────────────────────────
test('default stack column: level (first candidate)', () => {
  const tk = _tlMakeLogfmtTokenizer();
  tk.tokenize('time=2025-01-01 level=info status=200 method=GET', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cols[tk.getDefaultStackColIdx()], 'level');
});

test('default stack column: falls back to severity, then lvl', () => {
  const a = _tlMakeLogfmtTokenizer();
  a.tokenize('time=t severity=error code=500', 0);
  const colsA = a.getColumns();
  assert.strictEqual(colsA[a.getDefaultStackColIdx()], 'severity');

  const b = _tlMakeLogfmtTokenizer();
  b.tokenize('time=t lvl=warn code=400', 0);
  const colsB = b.getColumns();
  assert.strictEqual(colsB[b.getDefaultStackColIdx()], 'lvl');
});

test('default stack column: returns null when no candidate matches', () => {
  const tk = _tlMakeLogfmtTokenizer();
  tk.tokenize('time=t request_id=abc tenant=acme', 0);
  assert.strictEqual(tk.getDefaultStackColIdx(), null);
});

// ── Robustness ──────────────────────────────────────────────────────
test('returns null for non-logfmt input', () => {
  const tk = _tlMakeLogfmtTokenizer();
  assert.strictEqual(tk.tokenize('', 0), null);
  assert.strictEqual(tk.tokenize('   ', 0), null);
  // Free text without any `key=value` pair.
  assert.strictEqual(tk.tokenize('just a freeform log line', 0), null);
});

test('tolerates a leading UTF-8 BOM on the first line', () => {
  const tk = _tlMakeLogfmtTokenizer();
  const a = tk.tokenize('\uFEFFlevel=info msg=hi', 0);
  assert.ok(Array.isArray(a));
  const cols = tk.getColumns();
  assert.strictEqual(a[cols.indexOf('level')], 'info');
});

test('keys may include `.` `-` `/` (e.g. log.level, request-id, x/y)', () => {
  const tk = _tlMakeLogfmtTokenizer();
  const a = tk.tokenize('log.level=warn request-id=abc x/y=z', 0);
  const cols = tk.getColumns();
  assert.deepStrictEqual(cols, ['log.level', 'request-id', 'x/y', '_extra']);
  assert.strictEqual(a[cols.indexOf('log.level')], 'warn');
  assert.strictEqual(a[cols.indexOf('request-id')], 'abc');
  assert.strictEqual(a[cols.indexOf('x/y')], 'z');
});

// ── Cross-realm parity ──────────────────────────────────────────────
test('worker-shim copy of _tlMakeLogfmtTokenizer matches main-bundle copy', () => {
  const shimCtx = loadModules(['src/workers/timeline-worker-shim.js'], {
    expose: ['_tlMakeLogfmtTokenizer'],
  });
  const shimMake = shimCtx._tlMakeLogfmtTokenizer;
  assert.strictEqual(typeof shimMake, 'function',
    'shim must export _tlMakeLogfmtTokenizer');
  const drive = (factory) => {
    const tk = factory();
    const lines = [
      'level=info msg="hello world" service=api',
      'level=warn msg="auth failed" service=api user=alice attempts=3',
      'level=debug body="a\\nb\\nc" path="C:\\\\tmp" code=200',
      'level=error msg="oops no close',
      'free text no kv pair',
      '',
      'request_id=xyz tenant=acme',
    ];
    return {
      out: lines.map(l => tk.tokenize(l, 0)),
      cols: tk.getColumns(),
      label: tk.getFormatLabel(),
      stackIdx: tk.getDefaultStackColIdx(),
    };
  };
  const a = drive(_tlMakeLogfmtTokenizer);
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
  assert.deepStrictEqual(a.cols, b.cols);
  assert.strictEqual(a.label, b.label);
  assert.strictEqual(a.stackIdx, b.stackIdx);
});
