'use strict';
// timeline-apache-error.test.js — Apache HTTP Server error_log
// tokeniser.
//
// Apache error logs (the `ErrorLog` directive output, distinct
// from access logs which we cover via CLF) start with a
// bracketed timestamp + day-name token and continue with
// bracketed metadata + a free-text message:
//
//   [Tue Apr 30 14:23:11.123456 2024] [core:error] [pid 12345]
//   [client 10.0.0.5:51234] AH00037: Symbolic link not allowed
//
// Schema (fixed 8 cols): Timestamp · Module · Severity · PID ·
// TID · Client · ErrorCode · Message.
//
// What we verify:
//   • Timestamp parsing with and without microsecond precision.
//   • Module + Severity split from the `[module:level]` bracket.
//   • Optional `[pid N]` and `[pid N:tid M]` extraction.
//   • Optional `[client IP]` and `[client IP:PORT]` extraction.
//   • Optional `AH<5digits>:` error-code token at message start.
//   • Free-text message preservation including embedded
//     parens, brackets, and status text.
//   • Default histogram stack column = Severity (col 2).
//   • Format label = `'Apache error_log'`.
//   • Rejection of non-Apache lines (returns null).
//   • Cross-realm parity with the worker-shim copy.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-parser-helpers.js',
  'src/app/timeline/timeline-helpers.js',
], {
  expose: ['_tlMakeApacheErrorTokenizer', '_TL_APACHE_ERROR_COLS'],
});
const { _tlMakeApacheErrorTokenizer, _TL_APACHE_ERROR_COLS } = ctx;

// ── Construction ──────────────────────────────────────────────────────
test('factory: returns the expected closure shape', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  assert.strictEqual(typeof tk.tokenize, 'function');
  assert.strictEqual(typeof tk.getColumns, 'function');
  assert.strictEqual(typeof tk.getDefaultStackColIdx, 'function');
  assert.strictEqual(typeof tk.getFormatLabel, 'function');
  assert.strictEqual(tk.getFormatLabel(), 'Apache error_log');
});

test('schema: fixed 8-column layout', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cols = tk.getColumns();
  const expected = [
    'Timestamp', 'Module', 'Severity', 'PID', 'TID', 'Client',
    'ErrorCode', 'Message',
  ];
  // Element-wise compare: cross-realm `deepStrictEqual` on
  // arrays returned from the loaded bundle reports
  // "same structure but not reference-equal" since the array
  // prototype differs between realms.
  assert.strictEqual(cols.length, expected.length);
  for (let i = 0; i < expected.length; i++) {
    assert.strictEqual(cols[i], expected[i], 'col ' + i);
  }
});

// ── Timestamp parsing ──────────────────────────────────────────────
test('timestamp: parses standard `[Day Mon DD HH:MM:SS YYYY]` form', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Tue Apr 30 14:23:11 2024] [core:error] [pid 12345] AH00037: failed', 0);
  assert.ok(Array.isArray(cells));
  assert.strictEqual(cells[0], '2024-04-30T14:23:11');
});

test('timestamp: parses microsecond-precision form `[…HH:MM:SS.usec YYYY]`', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Tue Apr 30 14:23:11.123456 2024] [core:error] [pid 12345] AH00037: failed', 0);
  assert.strictEqual(cells[0], '2024-04-30T14:23:11.123456');
});

test('timestamp: pads single-digit day-of-month with leading zero', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Mon Apr  7 09:05:01 2024] [mpm_event:notice] [pid 100] hello', 0);
  assert.strictEqual(cells[0], '2024-04-07T09:05:01');
});

// ── Module + Severity split ────────────────────────────────────────
test('module + severity split from `[module:level]`', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Tue Apr 30 14:23:11 2024] [proxy_fcgi:error] [pid 12345] (70007)Timeout', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells[cols.indexOf('Module')], 'proxy_fcgi');
  assert.strictEqual(cells[cols.indexOf('Severity')], 'error');
});

test('module + severity: trace1..trace8 are recognised', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Tue Apr 30 14:23:11 2024] [http2:trace3] [pid 12345] very verbose stuff', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells[cols.indexOf('Severity')], 'trace3');
});

// ── PID / TID extraction ───────────────────────────────────────────
test('pid: bare `[pid N]` form populates PID, leaves TID blank', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Tue Apr 30 14:23:11 2024] [core:error] [pid 12345] AH00037: x', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells[cols.indexOf('PID')], '12345');
  assert.strictEqual(cells[cols.indexOf('TID')], '');
});

test('pid+tid: `[pid N:tid M]` form populates both', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Tue Apr 30 14:23:11 2024] [core:error] [pid 12345:tid 140737] AH00037: x', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells[cols.indexOf('PID')], '12345');
  assert.strictEqual(cells[cols.indexOf('TID')], '140737');
});

test('pid: missing entirely leaves both PID and TID blank', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Tue Apr 30 14:23:11 2024] [core:warn] some bare warning', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells[cols.indexOf('PID')], '');
  assert.strictEqual(cells[cols.indexOf('TID')], '');
});

// ── Client extraction ──────────────────────────────────────────────
test('client: `[client IP:PORT]` form populates the Client cell', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Tue Apr 30 14:23:11 2024] [core:error] [pid 12345] [client 10.0.0.5:51234] AH00037: x', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells[cols.indexOf('Client')], '10.0.0.5:51234');
});

test('client: `[client IP]` (older Apache, no port) populates Client', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Tue Apr 30 14:23:11 2024] [core:error] [pid 12345] [client 10.0.0.5] AH00037: x', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells[cols.indexOf('Client')], '10.0.0.5');
});

test('client: missing leaves Client blank', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Tue Apr 30 14:23:11 2024] [mpm_event:notice] [pid 12345] AH00489: configured', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells[cols.indexOf('Client')], '');
});

// ── AHnnnnn: error-code extraction ─────────────────────────────────
test('error-code: `AH<5digits>:` token at message start populates ErrorCode', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Tue Apr 30 14:23:11 2024] [core:error] [pid 12345] [client 10.0.0.5:51234] AH00037: Symbolic link not allowed', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells[cols.indexOf('ErrorCode')], 'AH00037');
  assert.strictEqual(cells[cols.indexOf('Message')], 'Symbolic link not allowed');
});

test('error-code: missing leaves ErrorCode blank, full text in Message', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Tue Apr 30 14:23:11 2024] [core:warn] [pid 12345] some bare warning', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells[cols.indexOf('ErrorCode')], '');
  assert.strictEqual(cells[cols.indexOf('Message')], 'some bare warning');
});

// ── Free-text message preservation ─────────────────────────────────
test('message preserves embedded parens / status text after AH code', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '[Tue Apr 30 14:23:11 2024] [proxy_fcgi:error] [pid 12345] (70007)The timeout specified has expired: AH01075: Error dispatching request to :', 0);
  const cols = tk.getColumns();
  // No AH token at the very start (it's after the parenthetical),
  // so ErrorCode stays blank and the entire tail goes into
  // Message.
  assert.strictEqual(cells[cols.indexOf('ErrorCode')], '');
  assert.match(cells[cols.indexOf('Message')], /^\(70007\)The timeout/);
  assert.match(cells[cols.indexOf('Message')], /AH01075: Error dispatching/);
});

// ── Default stack column ───────────────────────────────────────────
test('default stack column: Severity (col 2)', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  assert.strictEqual(tk.getDefaultStackColIdx(), 2);
  const cols = tk.getColumns();
  assert.strictEqual(cols[2], 'Severity');
});

// ── Robustness ─────────────────────────────────────────────────────
test('returns null for non-Apache lines', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  assert.strictEqual(tk.tokenize('', 0), null);
  assert.strictEqual(tk.tokenize('not an apache line', 0), null);
  assert.strictEqual(
    tk.tokenize('[2024-04-30 14:23:11] not the right shape', 0),
    null);
  // Looks bracketed but doesn't have a day-name + month-name combo.
  assert.strictEqual(
    tk.tokenize('[Apr 30 14:23:11 2024] [core:error] missing day name', 0),
    null);
});

test('tolerates a leading UTF-8 BOM', () => {
  const tk = _tlMakeApacheErrorTokenizer();
  const cells = tk.tokenize(
    '\uFEFF[Tue Apr 30 14:23:11 2024] [core:error] [pid 12345] AH00037: failed', 0);
  assert.ok(Array.isArray(cells));
  assert.strictEqual(cells[0], '2024-04-30T14:23:11');
});

// ── Cross-realm parity ────────────────────────────────────────────
test('worker-shim copy of _tlMakeApacheErrorTokenizer matches main-bundle copy', () => {
  const shimCtx = loadModules(['src/app/timeline/timeline-parser-helpers.js', 'src/workers/timeline-worker-shim.js'], {
    expose: ['_tlMakeApacheErrorTokenizer'],
  });
  const shimMake = shimCtx._tlMakeApacheErrorTokenizer;
  assert.strictEqual(typeof shimMake, 'function',
    'shim must export _tlMakeApacheErrorTokenizer');
  const drive = (factory) => {
    const tk = factory();
    const lines = [
      '[Tue Apr 30 14:23:11 2024] [core:error] [pid 12345] [client 10.0.0.5:51234] AH00037: Symbolic link not allowed',
      '[Tue Apr 30 14:23:12 2024] [mpm_event:notice] [pid 12345:tid 140] AH00489: Apache/2.4.58 (Unix) configured -- resuming normal operations',
      '[Tue Apr 30 14:23:13 2024] [proxy_fcgi:error] [pid 12346] (70007)The timeout specified has expired: AH01075: Error dispatching request',
      '[Mon Apr  7 09:05:01 2024] [http2:trace3] [pid 100] very verbose',
      'not an apache line',
      '',
      '[Tue Apr 30 14:23:14.123456 2024] [core:warn] some bare warning',
    ];
    return {
      out: lines.map(l => tk.tokenize(l, 0)),
      cols: tk.getColumns(),
      label: tk.getFormatLabel(),
      stackIdx: tk.getDefaultStackColIdx(),
    };
  };
  const a = drive(_tlMakeApacheErrorTokenizer);
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
