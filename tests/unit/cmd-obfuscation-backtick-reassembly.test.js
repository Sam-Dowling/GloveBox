'use strict';
// ════════════════════════════════════════════════════════════════════════════
// cmd-obfuscation-backtick-reassembly.test.js — end-to-end regression
// pin for the user-reported "Load for analysis" + "Load stitched script"
// bug on PowerShell backtick-escape .NET namespace chains.
//
// The bug: the backtick decoder's token regex was `[a-zA-Z0-9`]`, which
// could not span dotted identifiers like `Sy`st`em.Ne`t.We`b`Cl`ie`nt`.
// For the script:
//
//     Write-Host "[TEST] Backtick obfuscation:"
//     $example = "In`v`o`k`e-Ex`pr`es`si`on"
//     $example2 = "Ne`w`-O`b`je`ct Sy`st`em.Ne`t.We`b`Cl`ie`nt"
//     Write-Host "Built: $example"
//     Write-Host "Built: $example2"
//
// the decoder emitted ONE candidate per line-3 token (New-Object) and
// the namespace chain was unreachable. The reassembler spliced the
// 10-char `New-Object` into the 16-char raw-backticked source range,
// leaving the obfuscated tail `" Sy`st`em.Ne`t.We`b`Cl`ie`nt"` in the
// stitched output. Both "Load for analysis" on the per-finding card
// and "Load stitched script" surfaced the duplicated / still-obfuscated
// text.
//
// The fix widens the regex char class to include `.` AND extends the
// shared whitelist with curated .NET weaponisation namespaces, so each
// token emits its own candidate with honest offset/length/bytes/text
// alignment.
//
// This file pins the behavioural contract end-to-end: run the full
// EncodedContentDetector.scan() pipeline + EncodedReassembler.build()
// on the exact user fixture and assert the stitched body no longer
// carries the obfuscated tail, and is not corrupted by duplication.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// Load the detector AND the reassembler in the same realm. The detector
// needs the full decoder set so cmd-obfuscation findings are emitted
// with decodedBytes + _deobfuscatedText populated the way production
// does. The reassembler is a pure offset-splicer — it just needs the
// findings + source.
const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/safelinks.js',
  'src/decoders/whitelist.js',
  'src/decoders/entropy.js',
  'src/decoders/ioc-extract.js',
  'src/decoders/base64-hex.js',
  'src/decoders/encoding-decoders.js',
  'src/decoders/encoding-finders.js',
  'src/decoders/interleaved-separator.js',
  'src/decoders/xor-bruteforce.js',
  'src/decoders/zlib.js',
  'src/decoders/js-assembly.js',
  'src/decoders/cmd-obfuscation.js',
  'src/decoders/ps-mini-evaluator.js',
  'src/decoders/bash-obfuscation.js',
  'src/decoders/python-obfuscation.js',
  'src/decoders/php-obfuscation.js',
  'src/encoded-reassembler.js',
], { expose: ['EncodedContentDetector', 'EncodedReassembler'] });

const { EncodedContentDetector, EncodedReassembler } = ctx;

const USER_FIXTURE = [
  'Write-Host "[TEST] Backtick obfuscation:"',
  '$example = "In`v`o`k`e-Ex`pr`es`si`on"',
  '$example2 = "Ne`w`-O`b`je`ct Sy`st`em.Ne`t.We`b`Cl`ie`nt"',
  'Write-Host "Built: $example"',
  'Write-Host "Built: $example2"',
].join('\n');

// Helper: run the full detector scan and return the top-level
// `encoded-content` findings the reassembler consumes.
async function scan(source) {
  const d = new EncodedContentDetector();
  const bytes = new TextEncoder().encode(source);
  return await d.scan(source, bytes, {});
}

test('user-fixture: backtick decoder emits three independent candidates on line 2+3', async () => {
  // Sanity anchor: the upstream detector produces one finding per
  // backticked token (In`v`o`k`e-Ex`pr`es`si`on, Ne`w`-O`b`je`ct,
  // Sy`st`em.Ne`t.We`b`Cl`ie`nt). Before the fix, only two emitted
  // (the namespace chain was dropped by the regex char class).
  const findings = await scan(USER_FIXTURE);
  const btk = findings.filter(f => f.encoding === 'PowerShell Backtick Escape');
  // At least three — the detector may collapse adjacent candidates via
  // later-stage merging but never below the raw emission count.
  assert.ok(btk.length >= 3,
    `expected ≥3 backtick findings; got ${btk.length}: ${JSON.stringify(btk.map(f => ({enc: f.encoding, txt: f._deobfuscatedText, off: f.offset})))}`);
  const decoded = btk.map(f => String(f._deobfuscatedText || '').toLowerCase()).sort();
  assert.ok(decoded.includes('invoke-expression'),
    `expected Invoke-Expression in decoded set; got ${JSON.stringify(decoded)}`);
  assert.ok(decoded.includes('new-object'),
    `expected New-Object in decoded set; got ${JSON.stringify(decoded)}`);
  assert.ok(decoded.includes('system.net.webclient'),
    `expected System.Net.WebClient in decoded set; got ${JSON.stringify(decoded)}`);
});

test('user-fixture: reassembled stitched body has no leftover backticks on line 3', async () => {
  // The user's Bug 2: stitched script showed
  //   $example2 = "New-Object System.Net.WebClient Sy`st`em.Ne`t.We`b`Cl`ie`nt"
  // because the reassembler spliced the expanded expansion-text into
  // the narrower raw-token span. Honest offset/length alignment post-
  // fix means each backtick-obfuscated token is cleanly replaced by
  // its decoded form with no leftover raw tail.
  const findings = await scan(USER_FIXTURE);
  const recon = EncodedReassembler.build(USER_FIXTURE, findings, { mode: 'auto' });
  assert.ok(recon && !recon.skipReason,
    `expected reassembly; got skipReason=${recon && recon.skipReason}`);
  const stripped = EncodedReassembler.stripSentinels(recon.text);

  // No leftover obfuscated fragments from the input.
  assert.doesNotMatch(stripped, /Sy`st`em/, 'stitched body must not contain `Sy\`st\`em`');
  assert.doesNotMatch(stripped, /Ne`t/,     'stitched body must not contain `Ne\`t`');
  assert.doesNotMatch(stripped, /We`b/,     'stitched body must not contain `We\`b`');
  assert.doesNotMatch(stripped, /Cl`ie/,    'stitched body must not contain `Cl\`ie`');
  assert.doesNotMatch(stripped, /In`v/,     'stitched body must not contain `In\`v`');
  assert.doesNotMatch(stripped, /Ne`w/,     'stitched body must not contain `Ne\`w`');

  // Fully cleaned forms must appear at the right logical positions.
  // We check for presence, not exact byte equality, because the
  // reassembler wraps spliced regions in invisible sentinels that
  // `stripSentinels` removes but adjacent whitespace handling may
  // differ marginally depending on span ordering.
  assert.match(stripped, /\$example\s*=\s*"Invoke-Expression"/);
  assert.match(stripped, /\$example2\s*=\s*"New-Object\s+System\.Net\.WebClient"/);
});

test('user-fixture: "Load stitched script" byte-payload equals the previewed stitched body', async () => {
  // The user's diagnosis pairs "preview shows X" with "loader loads Y".
  // The stitched-script load button encodes `stripSentinels(recon.text)`
  // as UTF-8 and hands that buffer to `openInnerFile`. This test pins
  // that the loader-bound bytes round-trip to the same string the
  // preview renders — the two paths must be byte-identical.
  const findings = await scan(USER_FIXTURE);
  const recon = EncodedReassembler.build(USER_FIXTURE, findings, { mode: 'auto' });
  assert.ok(recon);
  const previewText = EncodedReassembler.stripSentinels(recon.text);
  const loaderBytes = new TextEncoder().encode(previewText);
  const roundTrip = new TextDecoder('utf-8').decode(loaderBytes);
  assert.equal(roundTrip, previewText,
    '"Load stitched script" bytes must decode to the exact preview string');
  // And the round-trip is the expanded form (no backticks on line 3).
  assert.doesNotMatch(roundTrip, /Sy`st`em/);
  assert.match(roundTrip, /System\.Net\.WebClient/);
});

test('user-fixture: per-finding decodedBytes == _deobfuscatedText (Load-for-analysis consistency)', async () => {
  // The user's Bug 1: card preview showed "New-Object System.Net.WebClient"
  // (via my earlier _deobfuscatedText override) but clicking "Load for
  // analysis" loaded only `New-Object` bytes. Post-fix each candidate
  // is emitted honestly and the two fields must stay in lockstep.
  const findings = await scan(USER_FIXTURE);
  const btk = findings.filter(f => f.encoding === 'PowerShell Backtick Escape');
  for (const f of btk) {
    assert.ok(f.decodedBytes, `finding at offset=${f.offset} missing decodedBytes`);
    const decoded = new TextDecoder('utf-8').decode(f.decodedBytes);
    assert.equal(decoded, f._deobfuscatedText,
      `decodedBytes must decode to _deobfuscatedText; offset=${f.offset} got decoded=${JSON.stringify(decoded)} vs text=${JSON.stringify(f._deobfuscatedText)}`);
  }
});
