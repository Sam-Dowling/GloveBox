'use strict';
// timeline-access-log.test.js — generic space-delimited access log
// tokeniser (covers Pulse Secure / Ivanti Connect Secure exports,
// custom proxy / audit logs, any hand-rolled access log whose col 1
// is a recognisable timestamp).
//
// Format shape (from real Pulse Secure access log):
//
//   2025-05-15--17-43-27 64.62.197.102 TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 \
//     "GET /mifs/…" 277 "-" "Mozilla/5.0 (…)"
//
// What we verify:
//   • TLS-access-log fingerprint → 8-col canonical schema
//     (time · ip · tls_version · tls_cipher · request · bytes ·
//     referer · user_agent).
//   • Generic fallback for other timestamps / shapes →
//     (time · field_2 · …) naming.
//   • Timestamp column accepts ISO, Ivanti double-dash, and epoch
//     (s / ms) forms; rejects lines whose col 1 is not a valid
//     timestamp (e.g. an IP in col 1).
//   • Quoted-field decoding mirrors CLF: `\"` → `"`, `\\` → `\`.
//   • Rejection of lines not starting with a timestamp.
//   • Default histogram stack column: TLS version (col 2) for TLS
//     fingerprint; null for generic.
//   • Format labels: 'TLS Access Log' vs 'Access Log'.
//   • Cross-realm parity with the worker-shim copy.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-helpers.js',
], {
  expose: ['_tlMakeAccessLogTokenizer', '_tlParseTimestamp'],
});
const { _tlMakeAccessLogTokenizer, _tlParseTimestamp } = ctx;

// ── Construction ───────────────────────────────────────────────────
test('factory: returns the expected closure shape', () => {
  const tk = _tlMakeAccessLogTokenizer();
  assert.strictEqual(typeof tk.tokenize, 'function');
  assert.strictEqual(typeof tk.getColumns, 'function');
  assert.strictEqual(typeof tk.getDefaultStackColIdx, 'function');
  assert.strictEqual(typeof tk.getFormatLabel, 'function');
  // Label / stack-idx are unresolved until the first line locks
  // a fingerprint — the factory closes over mutable state.
  assert.strictEqual(tk.getFormatLabel(), 'Access Log');
});

// ── TLS-fingerprint canonical schema ───────────────────────────────
test('tls fingerprint: 8-col canonical schema (ip, tls_version, cipher, …)', () => {
  const tk = _tlMakeAccessLogTokenizer();
  const cells = tk.tokenize(
    '2025-05-15--17-43-27 64.62.197.102 TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 '
    + '"GET /mifs/rs/api/v2/featureusage_history?format=shadowserver HTTP/1.1" '
    + '277 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"', 0);
  assert.ok(Array.isArray(cells), 'tokenise should succeed');
  assert.strictEqual(cells.length, 8);
  const expected = [
    'time', 'ip', 'tls_version', 'tls_cipher', 'request',
    'bytes', 'referer', 'user_agent',
  ];
  const cols = tk.getColumns();
  assert.strictEqual(cols.length, expected.length);
  for (let i = 0; i < expected.length; i++) {
    assert.strictEqual(cols[i], expected[i], 'col ' + i);
  }
  assert.strictEqual(cells[0], '2025-05-15--17-43-27');
  assert.strictEqual(cells[1], '64.62.197.102');
  assert.strictEqual(cells[2], 'TLSv1.2');
  assert.strictEqual(cells[3], 'ECDHE-RSA-AES128-GCM-SHA256');
  assert.match(cells[4], /^GET \/mifs\//);
  assert.strictEqual(cells[5], '277');
  assert.strictEqual(cells[6], '-');
  assert.match(cells[7], /Macintosh/);
  assert.strictEqual(tk.getFormatLabel(), 'TLS Access Log');
  assert.strictEqual(tk.getDefaultStackColIdx(), 2);
});

test('tls fingerprint: column-1 timestamp parses to a finite Date', () => {
  const tk = _tlMakeAccessLogTokenizer();
  const cells = tk.tokenize(
    '2025-05-15--17-43-27 10.0.0.1 TLSv1.3 TLS_AES_256_GCM_SHA384 '
    + '"GET / HTTP/1.1" 100 "-" "curl/8.0"', 0);
  const ms = _tlParseTimestamp(cells[0]);
  assert.ok(Number.isFinite(ms));
  // 2025-05-15 17:43:27 UTC = 1747330407000 ms
  assert.strictEqual(ms, Date.UTC(2025, 4, 15, 17, 43, 27));
});

// ── Generic fallback ───────────────────────────────────────────────
test('generic fallback: non-TLS schema produces field_2..field_N names', () => {
  const tk = _tlMakeAccessLogTokenizer();
  const cells = tk.tokenize(
    '2025-05-15T10:20:30 alice login ok 203.0.113.4', 0);
  assert.ok(Array.isArray(cells));
  assert.strictEqual(cells.length, 5);
  const cols = tk.getColumns();
  assert.strictEqual(cols[0], 'time');
  assert.strictEqual(cols[1], 'field_2');
  assert.strictEqual(cols[2], 'field_3');
  assert.strictEqual(cols[3], 'field_4');
  assert.strictEqual(cols[4], 'field_5');
  assert.strictEqual(tk.getFormatLabel(), 'Access Log');
  assert.strictEqual(tk.getDefaultStackColIdx(), null);
});

test('generic fallback: pins col count from the FIRST valid row', () => {
  const tk = _tlMakeAccessLogTokenizer();
  tk.tokenize('2025-05-15T10:00:00 a b c', 0);
  // Second line has 5 cells; schema locked at 4 from first.
  const cells2 = tk.tokenize('2025-05-15T10:01:00 a b c d e', 0);
  assert.ok(Array.isArray(cells2));
  // Tokeniser returns the natural cell count; padding / trimming
  // to the locked schema width is the caller's (worker's) job.
  // Verify column list stays at the locked width.
  assert.strictEqual(tk.getColumns().length, 4);
});

// ── Timestamp forms ────────────────────────────────────────────────
test('timestamp: epoch-seconds (10 digits) in col 1 is accepted', () => {
  const tk = _tlMakeAccessLogTokenizer();
  const cells = tk.tokenize('1716824607 hostA login ok', 0);
  assert.ok(Array.isArray(cells));
  assert.strictEqual(cells[0], '1716824607');
});

test('timestamp: epoch-millis (13 digits) in col 1 is accepted', () => {
  const tk = _tlMakeAccessLogTokenizer();
  const cells = tk.tokenize('1716824607000 hostA login ok', 0);
  assert.ok(Array.isArray(cells));
  assert.strictEqual(cells[0], '1716824607000');
});

test('timestamp: ISO-8601 with Z suffix in col 1 is accepted', () => {
  const tk = _tlMakeAccessLogTokenizer();
  const cells = tk.tokenize('2025-05-15T10:20:30Z alice login', 0);
  assert.ok(Array.isArray(cells));
  assert.strictEqual(cells[0], '2025-05-15T10:20:30Z');
});

// ── Quoted-field decoding ──────────────────────────────────────────
test('quoted fields: decode backslash-escaped quotes and backslashes', () => {
  const tk = _tlMakeAccessLogTokenizer();
  const cells = tk.tokenize(
    '2025-05-15T10:20:30 10.0.0.1 "he said \\"hi\\"" 200', 0);
  assert.ok(Array.isArray(cells));
  assert.strictEqual(cells[2], 'he said "hi"');
});

test('quoted fields: preserve embedded spaces', () => {
  const tk = _tlMakeAccessLogTokenizer();
  const cells = tk.tokenize(
    '2025-05-15T10:20:30 10.0.0.1 "a b c d e"', 0);
  assert.strictEqual(cells.length, 3);
  assert.strictEqual(cells[2], 'a b c d e');
});

// ── Rejection paths ────────────────────────────────────────────────
test('rejects: empty and null input', () => {
  const tk = _tlMakeAccessLogTokenizer();
  assert.strictEqual(tk.tokenize('', 0), null);
  assert.strictEqual(tk.tokenize(null, 0), null);
});

test('rejects: lines that do not start with a timestamp', () => {
  const tk = _tlMakeAccessLogTokenizer();
  // Starts with an IP — no timestamp shape at col 1.
  assert.strictEqual(tk.tokenize('10.0.0.5 foo bar baz', 0), null);
  // Looks structured but is a CLF line (bracketed timestamp at col 4).
  assert.strictEqual(
    tk.tokenize('127.0.0.1 - - [20/Jun/2012:19:05:12 +0200] "GET /" 200 0', 0),
    null);
  // Plain English.
  assert.strictEqual(tk.tokenize('not a log line', 0), null);
});

test('rejects: invalid calendar date in Ivanti form', () => {
  const tk = _tlMakeAccessLogTokenizer();
  // Month 13, day 32, hour 25 — lexically matches but not valid.
  assert.strictEqual(
    tk.tokenize('2025-13-32--25-99-99 10.0.0.1 foo', 0), null);
});

test('rejects: timestamp-only line (no fields)', () => {
  const tk = _tlMakeAccessLogTokenizer();
  assert.strictEqual(tk.tokenize('2025-05-15T10:20:30', 0), null);
});

// ── BOM tolerance ──────────────────────────────────────────────────
test('tolerates a leading UTF-8 BOM', () => {
  const tk = _tlMakeAccessLogTokenizer();
  const cells = tk.tokenize(
    '\uFEFF2025-05-15--17-43-27 10.0.0.1 TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 '
    + '"GET / HTTP/1.1" 100 "-" "curl/8.0"', 0);
  assert.ok(Array.isArray(cells));
  assert.strictEqual(cells[0], '2025-05-15--17-43-27');
});

// ── Ivanti-dashed timestamp recognised by _tlParseTimestamp ────────
test('_tlParseTimestamp: recognises YYYY-MM-DD--HH-MM-SS', () => {
  const ms = _tlParseTimestamp('2025-05-15--17-43-27');
  assert.ok(Number.isFinite(ms));
  assert.strictEqual(ms, Date.UTC(2025, 4, 15, 17, 43, 27));
});

test('_tlParseTimestamp: rejects invalid Ivanti-dashed values', () => {
  assert.ok(!Number.isFinite(_tlParseTimestamp('2025-13-01--00-00-00')));
  assert.ok(!Number.isFinite(_tlParseTimestamp('2025-01-32--00-00-00')));
  assert.ok(!Number.isFinite(_tlParseTimestamp('2025-01-01--25-00-00')));
});

// ── Cross-realm parity ─────────────────────────────────────────────
test('worker-shim copy of _tlMakeAccessLogTokenizer matches main-bundle copy', () => {
  const shimCtx = loadModules(['src/workers/timeline-worker-shim.js'], {
    expose: ['_tlMakeAccessLogTokenizer'],
  });
  const shimMake = shimCtx._tlMakeAccessLogTokenizer;
  assert.strictEqual(typeof shimMake, 'function',
    'shim must export _tlMakeAccessLogTokenizer');
  const drive = (factory) => {
    const tk = factory();
    const lines = [
      // TLS fingerprint locks on the first line.
      '2025-05-15--17-43-27 64.62.197.102 TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 '
        + '"GET /mifs/rs/api/v2/featureusage_history?format=shadowserver HTTP/1.1" '
        + '277 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
      '2025-05-15--17-43-39 10.43.168.110 TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 '
        + '"GET / HTTP/1.1" 288 "-" "curl/7.29.0"',
      '2025-05-15--17-43-41 10.43.168.110 TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 '
        + '"GET / HTTP/1.1" 288 "-" "curl/7.29.0"',
      // Rejected rows.
      '',
      'not a log line',
      '10.0.0.5 - - [20/Jun/2012:19:05:12 +0200] "GET /" 200 0',
    ];
    return {
      out: lines.map(l => tk.tokenize(l, 0)),
      cols: tk.getColumns(),
      label: tk.getFormatLabel(),
      stackIdx: tk.getDefaultStackColIdx(),
    };
  };
  const a = drive(_tlMakeAccessLogTokenizer);
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
