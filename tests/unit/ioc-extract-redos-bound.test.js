'use strict';
// ioc-extract-redos-bound.test.js — Wall-clock regression for `invisRe` ReDoS.
//
// Before the bound was added, `extractInterestingStringsCore` ran the
// invisible-character identifier regex
//   /\w{2,}[\u200B\u200C\u200D\u2060\uFEFF]\w{2,}/g
// against the scan surface. On a long single-line `\w` input (e.g. a 165 KB
// base64 PowerShell payload with no newlines and no INVIS chars) the
// engine's greedy match-then-backtrack walk produced O(n²) backtracking,
// which froze the main thread for ~7 seconds in SpiderMonkey on the
// `examples/windows-scripts/recursive-powershell.ps1` fixture (FF profile
// dump 2026-05-03).
//
// Fix: bound `\w{2,}` → `\w{2,64}` (real identifiers don't legitimately
// exceed that). Defence-in-depth: every `matchAll` site in the IOC core
// now routes through `safeMatchAll(re, str, 500, 10000)` so a future
// regex-shape mistake can no longer monopolise the thread.
//
// This test plants both signals with a generous 1 s wall-clock budget on
// node's `process.hrtime.bigint()`, which is well above the post-fix
// timing (<50 ms on commodity hardware) and well below the pre-fix
// 7 000 ms.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/constants.js', 'src/ioc-extract.js']);
const { extractInterestingStringsCore, IOC } = ctx;

function elapsedMs(fn) {
  const t0 = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

test('redos-bound: 200 KB single-line `\\w` blob completes under 1 s', () => {
  // Shape that would have triggered the catastrophic O(n²) backtrack:
  // a single long line of pure `\w` characters with no INVIS char to
  // anchor the right-hand `\w{2,…}` against.
  const text = 'a'.repeat(200_000);
  let result;
  const ms = elapsedMs(() => { result = extractInterestingStringsCore(text); });
  assert.ok(ms < 1000,
    `extractInterestingStringsCore must finish < 1 s on a 200 KB single-line ` +
    `\\w blob (saw ${ms.toFixed(1)} ms — ReDoS regression in invisRe).`);
  // Sanity: the input has no INVIS chars / URL-shaped substrings — every
  // legitimate finding must be an empty / Trojan-Source-class miss.
  const invisHits = host(result.findings.filter(e =>
    e.type === IOC.PATTERN && e.url.includes('Invisible character')));
  assert.equal(invisHits.length, 0,
    `200 KB of pure `+'`'+`a`+'`'+` chars must not produce any invisible-character findings.`);
});

test('redos-bound: 200 KB blob with one legitimate ZWSP-split identifier still flagged', () => {
  // Belt-and-braces: the bounded regex must still catch a real attack
  // shape (`pas\u200Bsword`) when buried in a pathological surrounding
  // input. Preserving detection is just as important as preserving wall-
  // clock speed.
  const noise = 'a'.repeat(100_000);
  const tainted = noise + ' pas\u200Bsword ' + noise;
  let result;
  const ms = elapsedMs(() => { result = extractInterestingStringsCore(tainted); });
  assert.ok(ms < 1000,
    `tainted 200 KB blob must finish < 1 s (saw ${ms.toFixed(1)} ms).`);
  const invisHits = host(result.findings.filter(e =>
    e.type === IOC.PATTERN && e.url.includes('Invisible character')));
  assert.ok(invisHits.length >= 1,
    `expected the bounded invisRe to still catch the legitimate ZWSP split, ` +
    `got: ${JSON.stringify(invisHits)}`);
});

test('redos-bound: safeMatchAll caps each regex at 10 000 matches', () => {
  // The `_matchAll` shim in `extractInterestingStringsCore` passes
  // `maxMatches=10000`. Build an input with > 10 000 trivial email-shape
  // hits and assert that the per-type cap (`PER_TYPE_CAP = 400`) still
  // applies — the safeMatchAll cap is invisible to the public API
  // because the per-type cap kicks in long before. This guards against
  // a future tweak that would relax the per-type cap.
  const emails = Array.from({ length: 12_000 },
    (_, i) => `u${i}@example.com`).join(' ');
  let result;
  const ms = elapsedMs(() => { result = extractInterestingStringsCore(emails); });
  // Generous: 12 000 emails under both caps must still finish quickly.
  assert.ok(ms < 2000,
    `12 000-email input must finish < 2 s (saw ${ms.toFixed(1)} ms).`);
  const acceptedEmails = host(result.findings.filter(e => e.type === IOC.EMAIL));
  // Per-type cap is 400; safeMatchAll cap is 10 000 — accepted is
  // bounded by the per-type cap, not safeMatchAll.
  assert.equal(acceptedEmails.length, 400,
    `per-type cap must hold (expected 400, got ${acceptedEmails.length}).`);
});
