'use strict';
// base64-hex-perf.test.js — Perf-budget regression guard for the
// wrapped-block pre-pass in `src/decoders/base64-hex.js`.
//
// The `_scanWrappedBlocks` helper originally shipped with a regex of the
// shape
//
//   (?:[A-Za-z0-9+/\-_]{N,}[ \t]*\r?\n[ \t]*){1,}[A-Za-z0-9+/\-_]{4,}={0,2}
//
// which exhibited catastrophic backtracking on files with LONG contiguous
// Base64 runs and NO delimiters — e.g. `recursive-powershell.ps1`, a 165 KB
// single-line `Invoke-Command -ScriptBlock ([scriptblock]::Create(…
// FromBase64String('<165 KB of base64>')))`. The unbounded inner `{N,}`
// inside an unbounded outer `{1,}` forced the engine into O(N²) behaviour
// (~35 s wall-clock), exceeding the 30 s render-watchdog and silently
// falling the whole file back to plaintext — no Deobfuscation findings.
//
// The fix replaced the regex with a delimiter-first two-pass manual scan
// (`indexOf('\n')` → backward/forward char-class walks). On the same
// fixture the scan now completes in ~30 ms.
//
// This test locks the perf envelope in place. A future change that
// reintroduces a backtracking shape will fail this gate long before it
// reaches production. The 500 ms budget is intentionally generous —
// production runs in the 30 ms range, but CI runners vary by 5-10×.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/whitelist.js',
  'src/decoders/entropy.js',
  'src/decoders/base64-hex.js',
]);
const { EncodedContentDetector } = ctx;

// 500 ms wall-clock budget per finder per fixture. Production is in the
// 10-30 ms range; the wide margin absorbs CI-runner jitter and
// first-compile cost. If this ever tightens, update the ratio in sync —
// a 10× headroom was the design intent.
const BUDGET_MS = 500;

// Fixtures known to exercise the wrapped-block pre-pass against large
// contiguous Base64 / Hex payloads with NO interior whitespace. These
// are the exact shapes that previously hit the O(N²) ReDoS — a
// regression that reintroduces the backtracking shape will time out
// here before landing.
const FIXTURES = [
  // The primary regression reproducer — 165 KB single-line PS payload.
  'examples/windows-scripts/recursive-powershell.ps1',
  // Compressed-B64 PS stager with moderate contiguous body.
  'examples/encoded-payloads/compressed-base64-powershell.txt',
  // B64-wrapped PE MZ header; tiny, but verifies the pre-pass doesn't
  // regress on the happy-path wrap-style input either.
  'examples/encoded-payloads/encoded-base64-pe.txt',
  // Nested hex + B64 + PS payload — exercises _findHexCandidates too.
  'examples/encoded-payloads/encoded-hex-base64-powershell.txt',
  // Zlib-compressed payload inside B64; short but representative.
  'examples/encoded-payloads/encoded-zlib-base64.txt',
];

/**
 * Run a finder and return its wall-clock cost in ms. We run ONCE — no
 * JIT warmup — so the budget includes first-compile. That's the
 * user-visible cost we care about (the detector is constructed fresh
 * for every file load).
 */
function timeFinder(detector, fn, text) {
  const t0 = (typeof performance !== 'undefined' && performance.now)
    ? performance.now() : Date.now();
  const result = fn.call(detector, text, {});
  const t1 = (typeof performance !== 'undefined' && performance.now)
    ? performance.now() : Date.now();
  return { ms: t1 - t0, count: Array.isArray(result) ? result.length : 0 };
}

const REPO_ROOT = path.resolve(__dirname, '..', '..');

for (const rel of FIXTURES) {
  const full = path.join(REPO_ROOT, rel);
  if (!fs.existsSync(full)) continue;  // fixture drift shouldn't break the suite
  const text = fs.readFileSync(full, 'utf8');

  test(`base64-hex-perf: _findBase64Candidates on ${rel} completes within ${BUDGET_MS}ms`, () => {
    const det = new EncodedContentDetector();
    const r = timeFinder(det, det._findBase64Candidates, text);
    assert.ok(r.ms < BUDGET_MS,
      `_findBase64Candidates took ${r.ms.toFixed(1)}ms on ${rel} (${text.length} bytes), ` +
      `budget ${BUDGET_MS}ms. If this file has been shrunk to be in-scope, adjust the ` +
      `budget; otherwise a wrapped-block regex has drifted to a backtracking shape — ` +
      `see git-blame on src/decoders/base64-hex.js::_scanWrappedBlocks.`);
  });

  test(`base64-hex-perf: _findHexCandidates on ${rel} completes within ${BUDGET_MS}ms`, () => {
    const det = new EncodedContentDetector();
    const r = timeFinder(det, det._findHexCandidates, text);
    assert.ok(r.ms < BUDGET_MS,
      `_findHexCandidates took ${r.ms.toFixed(1)}ms on ${rel} (${text.length} bytes), ` +
      `budget ${BUDGET_MS}ms. See _scanWrappedBlocks notes.`);
  });

  test(`base64-hex-perf: _findBase32Candidates on ${rel} completes within ${BUDGET_MS}ms`, () => {
    const det = new EncodedContentDetector();
    const r = timeFinder(det, det._findBase32Candidates, text);
    assert.ok(r.ms < BUDGET_MS,
      `_findBase32Candidates took ${r.ms.toFixed(1)}ms on ${rel} (${text.length} bytes), ` +
      `budget ${BUDGET_MS}ms. See _scanWrappedBlocks notes.`);
  });
}

// Synthetic pathological input: a 200 KB contiguous Base64 run with NO
// whitespace. Even if none of the fixture files are large enough to
// trigger the old backtracking shape, this test will.
test('base64-hex-perf: synthetic 200KB contiguous Base64 completes within budget', () => {
  const chunk = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAA';  // 37 chars
  const text = chunk.repeat(Math.ceil((200 * 1024) / chunk.length));
  assert.ok(text.length >= 200 * 1024);
  const det = new EncodedContentDetector();
  const r = timeFinder(det, det._findBase64Candidates, text);
  assert.ok(r.ms < BUDGET_MS,
    `_findBase64Candidates on 200KB synthetic contiguous Base64 took ${r.ms.toFixed(1)}ms; ` +
    `budget ${BUDGET_MS}ms. Wrapped-block regex has regressed to O(N²).`);
});

// Synthetic wrapped input: 200 KB Base64 wrapped at 60 cols CRLF. Must
// ALSO complete within budget — the fix mustn't have regressed the
// happy-path (wrapped-detection) cost.
test('base64-hex-perf: synthetic 200KB CRLF-wrapped Base64 completes within budget', () => {
  const chunk = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAA';
  const raw = chunk.repeat(Math.ceil((200 * 1024) / chunk.length));
  const wrapped = (raw.match(/.{1,60}/g) || []).join('\r\n');
  const det = new EncodedContentDetector();
  const r = timeFinder(det, det._findBase64Candidates, wrapped);
  assert.ok(r.ms < BUDGET_MS,
    `_findBase64Candidates on 200KB wrapped Base64 took ${r.ms.toFixed(1)}ms; ` +
    `budget ${BUDGET_MS}ms.`);
  assert.ok(r.count >= 1,
    `wrapped input must still produce at least one candidate; got ${r.count}`);
});
