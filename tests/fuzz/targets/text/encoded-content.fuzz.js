'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/text/encoded-content.fuzz.js
//
// Fuzz the EncodedContentDetector primary finders + decoders. The full
// `EncodedContentDetector.scan()` pipeline depends on vendored libs
// (pako, JSZip) and is async — too heavy and too vendor-coupled for the
// vm-sandbox harness. Instead we target the regex-only primary finders
// and the byte decoders, which is where the historical ReDoS / decode
// bugs lived:
//   • _findBase64Candidates   (regex finder, no vendor dep)
//   • _findHexCandidates      (regex finder, no vendor dep)
//   • _findBase32Candidates   (regex finder, no vendor dep)
//   • _decodeBase64           (atob round-trip)
//   • _decodeHex              (pure JS)
//   • _decodeBase32           (pure JS)
//
// History:
//   • 0f71338 — per-finder budget + tightened backtick/rot13 patterns
//   • 1388c1c — three rules rewritten for bounded quantifiers
//   • 6a83848 — recursively stamp chain prefix on innerFindings subtree
//   • 716d532 — bound `invisRe` to {2,64}; route IOC matchAll through safeMatchAll
//
// Invariants:
//   1. Each finder returns within the per-iteration budget.
//   2. Each candidate has a numeric .start ≥ 0 and a string .text.
//   3. Each decoder returns either null (graceful reject) or a Uint8Array.
//   4. `_decodeBase64('Hello' → corrupted)` must not throw — the production
//      path expects null on parse failure, never an exception.
// ════════════════════════════════════════════════════════════════════════════

const path = require('node:path');
const fs = require('node:fs');
const { defineFuzzTarget } = require('../../helpers/harness.js');
const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');

const td = new TextDecoder('utf-8', { fatal: false });

const fuzz = defineFuzzTarget({
  modules: [
    'src/constants.js',
    'src/encoded-content-detector.js',
    // whitelist.js mounts `_isDataURI`, `_isPEM`, `_isHashLength`,
    // `_isGUID`, `_isPowerShellEncodedCommand`, `_hasBase32Context`
    // onto EncodedContentDetector.prototype. The Base64/Hex/Base32
    // candidate finders all consult these gates, so loading
    // `base64-hex.js` without `whitelist.js` produces a TypeError on
    // first iteration. (Mirrors `_DETECTOR_FILES` order in
    // `scripts/build.py`: whitelist BEFORE base64-hex.)
    'src/decoders/whitelist.js',
    'src/decoders/entropy.js',
    'src/decoders/base64-hex.js',
  ],
  // The regex finders historically melted on multi-megabyte adversarial
  // inputs — keep the cap tight so iterations stay sub-second on the
  // happy path and budget violations surface quickly on regressions.
  maxBytes: 256 * 1024,
  perIterBudgetMs: 2_500,

  onIteration(ctx, data) {
    const { EncodedContentDetector } = ctx;
    if (!EncodedContentDetector) {
      throw new Error('harness: EncodedContentDetector not exposed');
    }
    const det = new EncodedContentDetector();
    const text = td.decode(data);
    if (text.length === 0) return;

    // ── Finders. context = {} matches the production initial scan call. ──
    // Each candidate has shape { type, raw, offset, length, entropy?, … }.
    // See src/decoders/base64-hex.js → candidates.push({…}) sites.
    const tryFinder = (name) => {
      if (typeof det[name] !== 'function') return [];  // optional method
      const out = det[name](text, {});
      if (!Array.isArray(out)) {
        throw new Error(`invariant: ${name} returned ${typeof out}, expected array`);
      }
      for (const cand of out) {
        if (!cand || typeof cand !== 'object') {
          throw new Error(`invariant: ${name} candidate not object`);
        }
        if (typeof cand.offset !== 'number' || cand.offset < 0 || cand.offset > text.length) {
          throw new Error(`invariant: ${name} candidate.offset ${cand.offset} out of range`);
        }
        if (typeof cand.raw !== 'string') {
          throw new Error(`invariant: ${name} candidate.raw not string`);
        }
        // `length` is the span consumed in `text` (for offset bookkeeping)
        // not necessarily `raw.length`. The `Hex (escaped)` finder strips
        // `\x` prefixes from `raw` but keeps `length` as the original
        // span — see src/decoders/base64-hex.js:285. We assert only that
        // length is non-negative and fits in `text`.
        if (typeof cand.length !== 'number' || cand.length < 0
            || cand.offset + cand.length > text.length) {
          throw new Error(`invariant: ${name} candidate span out of bounds — `
            + `offset=${cand.offset} length=${cand.length} text.length=${text.length}`);
        }
      }
      return out;
    };

    const b64 = tryFinder('_findBase64Candidates');
    const hex = tryFinder('_findHexCandidates');
    const b32 = tryFinder('_findBase32Candidates');

    // ── Decoders. Drive each candidate through its decoder and
    //    assert null-or-Uint8Array. The production code paths feed the
    //    same shape, so divergence here is a real bug.
    for (const cand of b64) {
      const decoded = det._decodeBase64(cand.raw);
      if (decoded !== null && !(decoded instanceof Uint8Array)) {
        throw new Error(`invariant: _decodeBase64 returned ${typeof decoded}, expected null|Uint8Array`);
      }
    }
    for (const cand of hex) {
      const decoded = det._decodeHex(cand.raw);
      if (decoded !== null && !(decoded instanceof Uint8Array)) {
        throw new Error(`invariant: _decodeHex returned ${typeof decoded}, expected null|Uint8Array`);
      }
    }
    for (const cand of b32) {
      if (typeof det._decodeBase32 !== 'function') break;
      const decoded = det._decodeBase32(cand.raw);
      if (decoded !== null && !(decoded instanceof Uint8Array)) {
        throw new Error(`invariant: _decodeBase32 returned ${typeof decoded}, expected null|Uint8Array`);
      }
    }
  },
});

function loadEncodedSeeds() {
  const seeds = [];
  const dir = path.join(REPO_ROOT, 'examples', 'encoded-payloads');
  if (fs.existsSync(dir)) {
    for (const name of fs.readdirSync(dir).sort()) {
      const p = path.join(dir, name);
      let buf;
      try { buf = fs.readFileSync(p); } catch (_) { continue; }
      if (!buf.length) continue;
      if (buf.length > 64 * 1024) buf = buf.subarray(0, 64 * 1024);
      seeds.push(buf);
      if (seeds.length >= 20) break;
    }
  }
  // Hand-rolled adversarial shapes — one per historical bug class.
  const handRolled = [
    // Base64 edge cases
    'A'.repeat(10_000),                                           // long all-A (used to trigger backtracking)
    'AAAAAAAA'.repeat(1024) + '====',
    'SGVsbG8sIFdvcmxkIQ==',                                       // canonical "Hello, World!"
    'YWJjZGVmZw',                                                 // un-padded
    // Hex edge cases
    'deadbeef'.repeat(2048),
    '0x' + 'ff'.repeat(1024),
    // Base32 edge cases
    'JBSWY3DPEHPK3PXP'.repeat(256),
    // Mixed garbage
    '\\x00\\x01\\x02\\x03',
    Buffer.from(new Uint8Array(4096).map((_, i) => i & 0xFF)).toString('base64'),
  ];
  for (const s of handRolled) seeds.push(Buffer.from(s, 'utf8'));
  return seeds;
}

const seeds = [...loadEncodedSeeds(), ...syntheticTextSeeds(8)];

module.exports = { fuzz, seeds, name: 'encoded-content' };
