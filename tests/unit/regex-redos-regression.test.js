'use strict';
// ════════════════════════════════════════════════════════════════════════════
// regex-redos-regression.test.js — adversarial-input timing tests for the
// path / UNC / defanged-domain regexes hardened against catastrophic
// backtracking.
//
// Background
// ----------
// Before the hardening, three regex shapes appeared across `src/`:
//
//   • Windows path:    /[A-Za-z]:\\(?:[\w\-. ]+\\)+[\w\-. ]{2,}/g
//   • UNC path:        /\\\\[\w.\-]{2,}(?:\\[\w.\-]+)+/g
//   • Defanged domain: /\b[\w\-]+(?:\[\.\][\w\-]+)+(?:\/[^\s"'<>]*)?\b/g
//
// The unbounded inner `+` inside the unbounded outer `+` (or `{1,}`) is
// the classic catastrophic-backtracking shape. A long unterminated input
// — e.g. `C:\` followed by 5,000 chars of allowed-but-non-terminal data
// — could pin a single thread for tens of seconds while the regex engine
// explored every possible split.
//
// The fix
// -------
// Each pattern now uses bounded quantifiers:
//   • Path component ≤255 (NTFS / Windows MAX_PATH per-component limit).
//   • Path depth ≤32 (well above any real-world path).
//   • Domain label ≤63 (RFC 1035), ≤8 labels (real FQDNs rarely exceed 5).
// Real-world inputs still match identically; pathological inputs run in
// linear time.
//
// What this test asserts
// ----------------------
// For each of the four hardened patterns:
//   1. An adversarial input that would have hung the original pattern
//      now returns from `String.matchAll(...)` in <100 ms.
//   2. A canonical positive input still matches (no behavioural regression
//      on real-world strings).
//
// We measure with `process.hrtime.bigint()` rather than `performance.now()`
// for nanosecond precision, and budget 100 ms per pattern — generous
// enough to absorb a slow CI runner, tight enough to catch a regression.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');

const BUDGET_NS = 100n * 1_000_000n; // 100 ms in nanoseconds

function timeMatchAll(regex, input) {
  const start = process.hrtime.bigint();
  // Drain the iterator so `matchAll` actually runs the engine to
  // completion — `matchAll(...)` returns a lazy iterator and the actual
  // backtracking happens during `.next()` / `Array.from(...)`.
  const matches = Array.from(input.matchAll(regex));
  const elapsed = process.hrtime.bigint() - start;
  return { matches, elapsedNs: elapsed };
}

function assertWithinBudget(label, elapsedNs) {
  assert.ok(
    elapsedNs < BUDGET_NS,
    `${label}: regex took ${Number(elapsedNs) / 1e6}ms ` +
    `(budget ${Number(BUDGET_NS) / 1e6}ms) — possible ReDoS regression`,
  );
}

// ── Windows file path ──────────────────────────────────────────────────────
const WIN_PATH_RE = /[A-Za-z]:\\(?:[\w\-. ]{1,255}\\){1,32}[\w\-. ]{2,255}/g;

test('redos: Windows file path regex — adversarial input completes in <100ms', () => {
  // The classic catastrophic input: a long unterminated path-segment
  // that the engine must try to split every which way before failing.
  // 50,000 chars of allowed inner-segment material with no terminating
  // backslash + final segment.
  const evil = 'C:\\' + 'a'.repeat(50000) + '\0';
  const { elapsedNs } = timeMatchAll(WIN_PATH_RE, evil);
  assertWithinBudget('Windows path adversarial', elapsedNs);
});

test('redos: Windows file path regex — positive cases still match', () => {
  const cases = [
    'C:\\Windows\\System32\\cmd.exe',
    'D:\\Program Files\\App\\bin\\app.exe',
    'C:\\Users\\victim\\AppData\\Roaming\\malware.dll',
  ];
  for (const c of cases) {
    const matches = Array.from(c.matchAll(WIN_PATH_RE));
    assert.ok(matches.length >= 1, `${c} must still match`);
    assert.equal(matches[0][0], c, `${c} must match in full`);
  }
});

// ── UNC path (renderer-side shape) ─────────────────────────────────────────
const UNC_RE = /\\\\[\w.\-]{2,255}(?:\\[\w.\-]{1,255}){1,32}/g;

test('redos: UNC path regex — adversarial input completes in <100ms', () => {
  // 50,000 chars of allowed material after a `\\` prefix, no second
  // segment terminator. Old unbounded pattern would explore every
  // (server, segment) split.
  const evil = '\\\\' + 'a'.repeat(50000) + '\0';
  const { elapsedNs } = timeMatchAll(UNC_RE, evil);
  assertWithinBudget('UNC adversarial', elapsedNs);
});

test('redos: UNC path regex — positive cases still match', () => {
  const cases = [
    '\\\\server\\share\\file.txt',
    '\\\\fileserver01\\public\\reports\\Q4\\summary.docx',
    '\\\\10.0.0.1\\backup\\db.bak',
  ];
  for (const c of cases) {
    const matches = Array.from(c.matchAll(UNC_RE));
    assert.ok(matches.length >= 1, `${c} must still match`);
    assert.equal(matches[0][0], c, `${c} must match in full`);
  }
});

// ── UNC path (constants.js shape) ──────────────────────────────────────────
// Slightly different character class — covers the `_UNC_RE` helper used
// by `extractUncPaths()` (PE/ELF/Mach-O joined-strings extraction path).
const UNC_CONSTANTS_RE = /\\\\[A-Za-z0-9._\-$]{1,255}(?:\\[A-Za-z0-9._\-$%]{1,255}){1,32}/g;

test('redos: constants.js _UNC_RE — adversarial input completes in <100ms', () => {
  const evil = '\\\\' + 'a'.repeat(50000) + '\0';
  const { elapsedNs } = timeMatchAll(UNC_CONSTANTS_RE, evil);
  assertWithinBudget('constants UNC adversarial', elapsedNs);
});

test('redos: constants.js _UNC_RE — positive cases still match', () => {
  const cases = [
    '\\\\server\\share$\\admin',
    '\\\\srv01\\public\\file%20with%20space',
  ];
  for (const c of cases) {
    const matches = Array.from(c.matchAll(UNC_CONSTANTS_RE));
    assert.ok(matches.length >= 1, `${c} must still match`);
  }
});

// ── Defanged domain ────────────────────────────────────────────────────────
const DEFANGED_DOMAIN_RE = /\b[\w\-]{1,63}(?:\[\.\][\w\-]{1,63}){1,8}(?:\/[^\s"'<>]{0,2048})?\b/g;

test('redos: defanged domain regex — adversarial input completes in <100ms', () => {
  // A nasty input: many `[.]` separators chained together. The original
  // unbounded `(?:\[\.\][\w\-]+)+` could backtrack on the trailing path
  // suffix.
  const evil = 'a' + '[.]a'.repeat(1000) + '/' + 'x'.repeat(50000);
  const { elapsedNs } = timeMatchAll(DEFANGED_DOMAIN_RE, evil);
  assertWithinBudget('defanged domain adversarial', elapsedNs);
});

test('redos: defanged domain regex — positive cases still match', () => {
  const cases = [
    'evil[.]example[.]com',
    'malicious[.]subdomain[.]bad-site[.]net',
    'phish[.]example[.]com/login.php',
  ];
  for (const c of cases) {
    const matches = Array.from(c.matchAll(DEFANGED_DOMAIN_RE));
    assert.ok(matches.length >= 1, `${c} must still match (got ${matches.length} matches)`);
  }
});

// ── Sanity: bounds chosen don't reject pathological-but-legitimate inputs ──
test('redos: bounds preserve real-world boundary cases', () => {
  // 32-segment Windows path — at the new depth cap. Should still match
  // (greedy quantifiers hit the cap, not exceed it).
  const deep32 = 'C:\\' + Array(31).fill('seg').join('\\') + '\\file.txt';
  const m = Array.from(deep32.matchAll(WIN_PATH_RE));
  assert.ok(m.length >= 1, '32-segment path must match (boundary case)');

  // 8-label defanged domain — at the new label cap.
  const deepDomain = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'].join('[.]');
  const md = Array.from(deepDomain.matchAll(DEFANGED_DOMAIN_RE));
  assert.ok(md.length >= 1, '9-label defanged domain must match');
});
