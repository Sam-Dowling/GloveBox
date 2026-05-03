'use strict';
// php-obfuscation-technique-shape.test.js — regression pin for the exact
// `technique` string shape emitted by the PHP1 eval-chain branch of
// `src/decoders/php-obfuscation.js`. This string ships to end users via
// the sidebar, Summary, STIX, and MISP exports; a malformed shape (see
// historical bug below) silently survived the existing regex-based
// assertions in `php-obfuscation.test.js` because each test only
// asserted that the technique *contained* a substring (e.g. `/gzinflate/`)
// — a malformed `"PHP eval(gzinflatebase64_decode(...))"` passes that
// test just fine.
//
// Historical bug (fix landed alongside this test):
//   Before:  'PHP eval(gzinflatebase64_decode(...))'      ← missing `(`, wrong )count
//   Before:  'PHP eval(gzinflate(str_rot13base64_decode(...))))'
//   After:   'PHP eval(gzinflate(base64_decode(...)))'
//   After:   'PHP eval(gzinflate(str_rot13(base64_decode(...))))'
//
// Each assertion here pins the EXACT string, including every paren.

const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/php-obfuscation.js',
]);

ctx.Decompressor = {
  inflateSync(bytes, format) {
    try {
      const buf = Buffer.from(bytes.buffer || bytes, bytes.byteOffset || 0, bytes.byteLength || bytes.length);
      if (format === 'gzip') return new Uint8Array(zlib.gunzipSync(buf));
      if (format === 'deflate-raw') return new Uint8Array(zlib.inflateRawSync(buf));
      return new Uint8Array(zlib.inflateSync(buf));
    } catch (_) { return null; }
  },
};

const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

function techFor(text) {
  const cands = host(d._findPhpObfuscationCandidates(text, {}));
  // PHP1 eval-chain is the only branch that emits a dynamically-built
  // `'PHP eval(...)'` label; filter to it.
  const php1 = cands.filter(c => typeof c.technique === 'string'
                                && c.technique.startsWith('PHP eval('));
  assert.ok(php1.length >= 1,
    `no PHP eval(…) candidate emitted; all techniques: ${JSON.stringify(cands.map(c => c.technique))}`);
  return php1[0].technique;
}

// ── Bare base64_decode — no wrapper chain ──────────────────────────────────
test('php-technique-shape: bare eval(base64_decode(…))', () => {
  const payload = 'system($_GET[0]);';
  const b64 = Buffer.from(payload).toString('base64');
  const text = `<?php eval(base64_decode('${b64}'));`;
  assert.equal(techFor(text), 'PHP eval(base64_decode(...))');
});

// ── Single wrapper — gzinflate ─────────────────────────────────────────────
test('php-technique-shape: eval(gzinflate(base64_decode(…))) — single wrapper', () => {
  const inner = '<?php echo "pwned"; ?>';
  const compressed = zlib.deflateRawSync(Buffer.from(inner));
  const b64 = compressed.toString('base64');
  const text = `eval(gzinflate(base64_decode("${b64}")));`;
  assert.equal(techFor(text), 'PHP eval(gzinflate(base64_decode(...)))');
});

// ── Single wrapper — str_rot13 ─────────────────────────────────────────────
test('php-technique-shape: eval(str_rot13(base64_decode(…))) — single wrapper', () => {
  const inner = 'system("id");'; // any cleartext works; str_rot13 doesn't need Decompressor
  const rot = inner.replace(/[A-Za-z]/g, ch => {
    const c = ch.charCodeAt(0);
    const base = c < 97 ? 65 : 97;
    return String.fromCharCode(((c - base + 13) % 26) + base);
  });
  const b64 = Buffer.from(rot).toString('base64');
  const text = `eval(str_rot13(base64_decode('${b64}')));`;
  assert.equal(techFor(text), 'PHP eval(str_rot13(base64_decode(...)))');
});

// ── Single wrapper — gzuncompress ──────────────────────────────────────────
test('php-technique-shape: eval(gzuncompress(base64_decode(…))) — single wrapper', () => {
  const inner = 'phpinfo();';
  const compressed = zlib.deflateSync(Buffer.from(inner));
  const b64 = compressed.toString('base64');
  const text = `eval(gzuncompress(base64_decode('${b64}')));`;
  assert.equal(techFor(text), 'PHP eval(gzuncompress(base64_decode(...)))');
});

// ── Double wrapper — str_rot13(gzinflate(base64_decode(…))) ───────────────
//
// PHP runtime call order is INNERMOST-FIRST: base64_decode first, then
// gzinflate, then str_rot13. The source `eval(str_rot13(gzinflate(...)))`
// emits a technique string that mirrors the source shape left-to-right.
test('php-technique-shape: eval(str_rot13(gzinflate(base64_decode(…)))) — double wrapper', () => {
  const inner = '<?php echo shell_exec($_POST["c"]); ?>';
  const rot = inner.replace(/[A-Za-z]/g, ch => {
    const c = ch.charCodeAt(0);
    const base = c < 97 ? 65 : 97;
    return String.fromCharCode(((c - base + 13) % 26) + base);
  });
  const compressed = zlib.deflateRawSync(Buffer.from(rot));
  const b64 = compressed.toString('base64');
  const text = `eval(str_rot13(gzinflate(base64_decode("${b64}"))));`;
  assert.equal(
    techFor(text),
    'PHP eval(str_rot13(gzinflate(base64_decode(...))))',
  );
});

// ── Double wrapper — gzinflate(str_rot13(base64_decode(…))) ────────────────
//
// Reversed wrapper order vs the previous test. The source shape dictates
// the technique-label shape; runtime order is now str_rot13 → gzinflate.
// Pick a payload whose rot13-then-deflate is decodable.
test('php-technique-shape: eval(gzinflate(str_rot13(base64_decode(…)))) — reversed double', () => {
  // str_rot13 works on latin-1 text. Start with the cleartext the runtime
  // would produce LAST — i.e. after gzinflate. To walk back through the
  // wrappers: final_after_rot13 = rot13(cleartext); pre_deflate =
  // final_after_rot13; base64 = base64(deflate_raw(pre_deflate)). But the
  // decoder won't use the cleartext for string-shape comparison, only for
  // the preview. We just need ANY string such that Decompressor.inflateSync
  // then str_rot13 yields a ≥2-char preview.
  const raw = 'system("whoami");';
  const compressed = zlib.deflateRawSync(Buffer.from(raw));
  // The runtime order is INNERMOST-FIRST: base64_decode -> str_rot13 -> gzinflate.
  // So we need b64 to decode into bytes whose rot13 is valid deflate_raw of the
  // cleartext. That's fiddly to construct; and for this test we only need the
  // decoder to RECOGNISE the shape and emit the correct label — the preview
  // can fall back via the `final = b64Bytes` path when the chain fails.
  const b64 = compressed.toString('base64');
  const text = `eval(gzinflate(str_rot13(base64_decode("${b64}"))));`;
  assert.equal(
    techFor(text),
    'PHP eval(gzinflate(str_rot13(base64_decode(...))))',
  );
});

// ── Triple wrapper ─────────────────────────────────────────────────────────
//
// The decoder captures up to 3 wrappers; this test pins the label shape
// at the cap. Any inner-payload validity is irrelevant — the label
// construction path runs before preview generation and doesn't depend
// on inflate success.
test('php-technique-shape: eval(gzuncompress(str_rot13(gzinflate(base64_decode(…))))) — triple wrapper', () => {
  // A structurally-valid b64 body (≥8 chars) is enough to enter the
  // label-construction branch; preview falls back to raw bytes if the
  // chain fails — we're only asserting the technique shape.
  const b64 = Buffer.from('somewhere-over-the-rainbow').toString('base64');
  const text = `eval(gzuncompress(str_rot13(gzinflate(base64_decode("${b64}")))));`;
  assert.equal(
    techFor(text),
    'PHP eval(gzuncompress(str_rot13(gzinflate(base64_decode(...)))))',
  );
});

// ── Balanced paren integrity ──────────────────────────────────────────────
//
// A self-consistent structural invariant: whatever the wrapper chain,
// the number of `(` in the emitted technique string MUST equal the
// number of `)`. A single missing paren would have caught the historical
// bug immediately.
test('php-technique-shape: every emitted PHP1 technique has balanced parens', () => {
  const sources = [
    `<?php eval(base64_decode('${Buffer.from('system();').toString('base64')}'));`,
    `eval(gzinflate(base64_decode("${zlib.deflateRawSync(Buffer.from('xxxxxxxx')).toString('base64')}")));`,
    `eval(str_rot13(gzinflate(base64_decode("${zlib.deflateRawSync(Buffer.from('yyyyyyyy')).toString('base64')}"))));`,
    `eval(gzuncompress(str_rot13(gzinflate(base64_decode("${Buffer.from('helloworldhello').toString('base64')}")))));`,
  ];
  for (const text of sources) {
    const tech = techFor(text);
    const opens = (tech.match(/\(/g) || []).length;
    const closes = (tech.match(/\)/g) || []).length;
    assert.equal(opens, closes,
      `unbalanced parens in technique ${JSON.stringify(tech)}: ${opens} open vs ${closes} close`);
  }
});
