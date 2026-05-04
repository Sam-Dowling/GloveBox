'use strict';
// ════════════════════════════════════════════════════════════════════════════
// evtx-renderer-readutf16.test.js
//
// Regression coverage for the dual-path _readUtf16 helper in
// `src/renderers/evtx-renderer.js`.
//
// Paths under test:
//   • short strings (≤32 code units)  → hand-rolled concat loop
//   • long strings  (>32 code units) → shared TextDecoder('utf-16le')
//
// Invariants:
//   1. NUL-termination stops decoding at first U+0000 regardless of path.
//   2. Out-of-range `charCount` is clamped to the buffer (no OOB read).
//   3. Well-formed BMP and supplementary strings round-trip bit-exactly.
//   4. Large inputs (100 k+ chars) decode without crashing — the old
//      `String.fromCharCode(...chars)` path threw
//      `Maximum call stack size exceeded` above ~200 k arguments on V8.
//   5. Malformed UTF-16 (lone surrogates) renders as U+FFFD, matching
//      the documented Option-A semantic change.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

function buildRenderer() {
  const sandbox = loadModules([
    'src/constants.js',
    'src/hashes.js',
    'src/evtx-event-ids.js',
    'src/renderers/evtx-renderer.js',
  ], { expose: ['EvtxRenderer'] });
  return new sandbox.EvtxRenderer();
}

// Build UTF-16LE bytes for a given JS string. Does NOT emit a NUL
// terminator unless the caller explicitly appends one.
function encodeUtf16LE(s) {
  const bytes = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    const cu = s.charCodeAt(i);
    bytes[i * 2] = cu & 0xFF;
    bytes[i * 2 + 1] = (cu >>> 8) & 0xFF;
  }
  return bytes;
}

// ── Short-string path (≤32 chars) ─────────────────────────────────────────

test('readUtf16 short path: ASCII round-trips exactly', () => {
  const r = buildRenderer();
  for (const s of ['', 'a', 'hello', 'System', 'EventID', 'Data', 'A'.repeat(32)]) {
    const bytes = encodeUtf16LE(s);
    assert.equal(r._readUtf16(bytes, 0, s.length), s, `mismatch on "${s}"`);
  }
});

test('readUtf16 short path: BMP non-ASCII (Cyrillic, CJK, Latin supplement) round-trips exactly', () => {
  const r = buildRenderer();
  for (const s of ['café', 'jalapeño', 'привет', '日本語', '中文字符', 'ä'.repeat(16)]) {
    const bytes = encodeUtf16LE(s);
    assert.equal(r._readUtf16(bytes, 0, s.length), s, `mismatch on "${s}"`);
  }
});

test('readUtf16 short path: NUL-terminates at first U+0000', () => {
  const r = buildRenderer();
  const bytes = new Uint8Array([
    0x48, 0x00, // H
    0x69, 0x00, // i
    0x00, 0x00, // NUL
    0x58, 0x00, // X (must NOT appear in output)
    0x59, 0x00, // Y
  ]);
  assert.equal(r._readUtf16(bytes, 0, 5), 'Hi');
});

// ── Long-string path (>32 chars) ──────────────────────────────────────────

test('readUtf16 long path: 128-char ASCII round-trips exactly', () => {
  const r = buildRenderer();
  const s = 'A'.repeat(128);
  const bytes = encodeUtf16LE(s);
  assert.equal(r._readUtf16(bytes, 0, s.length), s);
});

test('readUtf16 long path: mixed-script 1 K-char round-trips exactly', () => {
  const r = buildRenderer();
  const s = ('café-日本語-привет-abcdef-12345-').repeat(40); // ~1 080 chars
  const bytes = encodeUtf16LE(s);
  assert.equal(r._readUtf16(bytes, 0, s.length), s);
});

test('readUtf16 long path: supplementary plane (🔥, 𝕏) round-trips via surrogate pairs', () => {
  const r = buildRenderer();
  // 🔥 = U+1F525 → surrogate pair D83D DD25
  // 𝕏 = U+1D54F → surrogate pair D835 DD4F
  const s = 'fire🔥 math𝕏 end'.repeat(10); // >32 chars to force long path
  const bytes = encodeUtf16LE(s);
  assert.equal(r._readUtf16(bytes, 0, s.length), s);
});

test('readUtf16 long path: lone low-surrogate replaces with U+FFFD (Option A)', () => {
  const r = buildRenderer();
  // Build a 40-char buffer (forces long path): 39 valid chars + one lone
  // low-surrogate 0xDC00 with no preceding high surrogate. The
  // TextDecoder substitutes U+FFFD.
  const prefix = 'A'.repeat(39);
  const bytes = new Uint8Array(40 * 2);
  for (let i = 0; i < 39; i++) {
    bytes[i * 2] = 0x41; // 'A'
    bytes[i * 2 + 1] = 0x00;
  }
  // Lone low-surrogate U+DC00
  bytes[78] = 0x00;
  bytes[79] = 0xDC;

  const got = r._readUtf16(bytes, 0, 40);
  assert.equal(got.length, 40, 'output length should equal input code units');
  assert.equal(got.slice(0, 39), prefix);
  assert.equal(got.charCodeAt(39), 0xFFFD,
    'lone low-surrogate should render as U+FFFD under fatal:false decoder');
});

// ── Bounds / pathological inputs ──────────────────────────────────────────

test('readUtf16: empty input returns empty string', () => {
  const r = buildRenderer();
  assert.equal(r._readUtf16(new Uint8Array(0), 0, 0), '');
  assert.equal(r._readUtf16(new Uint8Array(10), 0, 0), '');
});

test('readUtf16: charCount beyond buffer end is clamped (no OOB)', () => {
  const r = buildRenderer();
  const bytes = encodeUtf16LE('Hi'); // 4 bytes
  // Ask for 50 chars — only 2 are available.
  assert.equal(r._readUtf16(bytes, 0, 50), 'Hi');
});

test('readUtf16: off=bytes.length returns empty', () => {
  const r = buildRenderer();
  const bytes = new Uint8Array(10);
  assert.equal(r._readUtf16(bytes, 10, 5), '');
});

// ── Stack-overflow regression ─────────────────────────────────────────────
//
// The old implementation did `String.fromCharCode(...chars)` — argument
// spread. V8 rejects argument lists above ~125 k-200 k depending on the
// build, with "Maximum call stack size exceeded". The new impl routes
// such inputs through TextDecoder which has no argument-stack limit.

test('readUtf16: 200 k-char input does not crash (regression for #stackoverflow)', () => {
  const r = buildRenderer();
  const n = 200_000;
  const bytes = new Uint8Array(n * 2);
  for (let i = 0; i < n; i++) bytes[i * 2] = 0x41; // 'A' (LE: 0x41 0x00)
  const got = r._readUtf16(bytes, 0, n);
  assert.equal(got.length, n);
  // First and last chars match — cheap sanity without comparing 200 k chars.
  assert.equal(got.charCodeAt(0), 0x41);
  assert.equal(got.charCodeAt(n - 1), 0x41);
});

test('readUtf16: 500 k-char input does not crash', () => {
  const r = buildRenderer();
  const n = 500_000;
  const bytes = new Uint8Array(n * 2);
  for (let i = 0; i < n; i++) bytes[i * 2] = 0x42; // 'B'
  const got = r._readUtf16(bytes, 0, n);
  assert.equal(got.length, n);
  assert.equal(got.charCodeAt(0), 0x42);
  assert.equal(got.charCodeAt(n - 1), 0x42);
});

// ── _u16Decoder lazy-init pin ─────────────────────────────────────────────

test('readUtf16: _u16Decoder is lazy-initialised (not constructed for short-only workloads)', () => {
  const r = buildRenderer();
  // Drive only short-path calls. The decoder field must stay undefined.
  r._readUtf16(encodeUtf16LE('System'), 0, 6);
  r._readUtf16(encodeUtf16LE('Data'), 0, 4);
  r._readUtf16(encodeUtf16LE('EventID'), 0, 7);
  assert.equal(r._u16Decoder, undefined,
    '_u16Decoder should not be constructed for short-only workloads');

  // One long-path call triggers lazy init.
  r._readUtf16(encodeUtf16LE('A'.repeat(64)), 0, 64);
  assert.ok(r._u16Decoder, '_u16Decoder should be created on first long-path call');

  // Subsequent calls reuse the same decoder — no new allocation.
  const ref = r._u16Decoder;
  r._readUtf16(encodeUtf16LE('B'.repeat(64)), 0, 64);
  assert.strictEqual(r._u16Decoder, ref, 'decoder instance must be reused, not re-constructed');
});

// ── EVTX fixture end-to-end sanity ────────────────────────────────────────
//
// Parse the real fixture end-to-end — if the rewrite is wrong the byte
// offsets in downstream tokens go haywire and events either vanish or
// parse garbage.

test('EVTX fixture parses end-to-end after _readUtf16 rewrite', () => {
  const fs = require('node:fs');
  const r = buildRenderer();
  const fx = fs.readFileSync(path.join(REPO_ROOT, 'examples/forensics/example-security.evtx'));
  const events = r._parse(new Uint8Array(fx.buffer, fx.byteOffset, fx.byteLength));
  assert.ok(events.length > 0, 'fixture should yield at least one event');
  // Spot-check: at least one event has a known Security-log channel string.
  const channelsSeen = new Set(events.map(e => e.channel));
  assert.ok(channelsSeen.size > 0, 'at least one distinct channel should be extracted');
  // System event IDs are small integers; they must not contain binary
  // garbage from a botched decode.
  for (const e of events.slice(0, 20)) {
    if (e.eventId) {
      assert.match(e.eventId, /^\d+$/, `eventId should be numeric, got "${e.eventId}"`);
    }
  }
});
