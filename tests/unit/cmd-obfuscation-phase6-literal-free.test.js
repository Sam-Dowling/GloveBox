'use strict';
// cmd-obfuscation-phase6-literal-free.test.js — Phase-6 additions under
// `src/decoders/cmd-obfuscation.js` and `src/decoders/ps-mini-evaluator.js`.
// Covers the four literal-free PowerShell identifier-reconstruction
// branches:
//
//   1. PowerShell Get-Command Wildcard   — &(gcm i*x), &(Get-Command i*rest*)
//   2. PowerShell Comment Injection      — I<##>nv<##>oke-Expression
//   3. PowerShell [bool] typecast gate   — if ([bool]1254) { … }    (ps-mini)
//   4. PowerShell Quote Interruption     — i''e''x, p""o""w""e""r""s""h""e""l""l
//
// Each branch asserts BOTH shape (candidate technique label matches) AND
// semantic (deobfuscated text contains the resolved token). Amp-budget
// and suppression gates are exercised too so a future widening of the
// patterns would surface here.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/safelinks.js',
  'src/decoders/whitelist.js',
  'src/decoders/entropy.js',
  'src/decoders/ioc-extract.js',
  'src/decoders/base64-hex.js',
  'src/decoders/cmd-obfuscation.js',
  'src/decoders/ps-mini-evaluator.js',
]);
const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

function pick(cands, pred) { return host(cands.filter(pred)); }

// ── 1. Get-Command wildcard ───────────────────────────────────────────────

test('ps Get-Command wildcard: resolves &(gcm i*x) to iex/invoke-expression', () => {
  const text = "&(gcm i*x) 'whoami'";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Get-Command Wildcard');
  assert.ok(hits.length >= 1, `expected wildcard hit; got: ${JSON.stringify(host(cands))}`);
  // glob `i*x` matches both `iex` and `invoke-expression` — both critical
  // so the resolver emits them joined with `|`.
  assert.match(hits[0].deobfuscated, /iex/);
  // _patternIocs must carry a critical-severity LOLBin pivot for risk.
  assert.ok(Array.isArray(hits[0]._patternIocs) && hits[0]._patternIocs.length === 1);
  assert.equal(hits[0]._patternIocs[0].severity, 'critical');
});

test('ps Get-Command wildcard: resolves Get-Command i????e-rest* to invoke-restmethod', () => {
  const text = "&(Get-Command i????e-rest*) -uri 'http://e/p'";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Get-Command Wildcard');
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /invoke-restmethod/i);
  assert.equal(hits[0]._patternIocs[0].severity, 'high');
});

test('ps Get-Command wildcard: permissive glob (letters < 3) drops silently', () => {
  const text = "&(gcm i*) 'arg'";       // only 1 literal letter after wildcards
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Get-Command Wildcard');
  assert.equal(hits.length, 0, `expected no hit; got: ${JSON.stringify(hits)}`);
});

test('ps Get-Command wildcard: mixed-severity glob drops', () => {
  // `i*-*` would match both critical (iex/invoke-expression) and high
  // (invoke-webrequest/invoke-restmethod/invoke-item) cmdlets. The
  // resolver requires all matches share the severity class, so it
  // drops. This is intentional — tier-inflation on benign would
  // otherwise surface false criticals.
  const text = "&(gcm i*-*) 'arg'";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Get-Command Wildcard');
  assert.equal(hits.length, 0);
});

test('ps Get-Command wildcard: dot-sourced form `.(Get-Command …)` also fires', () => {
  const text = ".(Get-Command n*-o*) Net.WebClient";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Get-Command Wildcard');
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /new-object/i);
  // Leading dot is preserved in the output so the exec-shape
  // downstream scorer sees it.
  assert.ok(hits[0].deobfuscated.startsWith('.'));
});

// ── 2. Comment injection ──────────────────────────────────────────────────

test('ps comment injection: I<#x#>nv<#y#>oke-Expression strips to Invoke-Expression', () => {
  const text = "I<#x#>nv<#y#>oke-Expression 'payload'";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Comment Injection');
  assert.ok(hits.length >= 1, `got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/i);
});

test('ps comment injection: long comment bodies survive the 256-char bound', () => {
  const noise = 'x'.repeat(200);
  const text = `New<# ${noise} #>-Object Net.WebClient`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Comment Injection');
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /New-Object/i);
});

test('ps comment injection: benign adjacent comment does NOT fire', () => {
  // A block comment next to a word that does NOT form a sensitive
  // keyword after stripping must drop.
  const text = "Foo<# harmless #>Bar";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Comment Injection');
  assert.equal(hits.length, 0);
});

test('ps comment injection: powershell<#x#>shell resolves to powershell', () => {
  const text = "power<# 42 #>shell -nop -c whoami";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Comment Injection');
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /powershell/);
});

// ── 3. [bool] typecast gate (via ps-mini) ─────────────────────────────────

test('ps [bool] gate: $g = [bool]1254; if ($g) { body } flattens body', () => {
  const text = "$g = [bool]1254\nif ($g) { $c = 'Invoke-Expression'; & $c 'whoami' }";
  const cands = d._findPsVariableResolutionCandidates(text, {});
  assert.ok(cands.length >= 1, `expected a ps-mini candidate; got ${cands.length}`);
  assert.match(cands[0].deobfuscated, /Invoke-Expression/);
});

test('ps [bool] gate: false guard drops body (no variable resolution emitted)', () => {
  const text = "$g = [bool]0\nif ($g) { $c = 'Invoke-Expression'; & $c 'whoami' }";
  const cands = d._findPsVariableResolutionCandidates(text, {});
  // The inner `& $c` never becomes top-level because the guard is falsy.
  assert.equal(cands.length, 0);
});

test('ps [bool] gate: !$null evaluates truthy', () => {
  const text = "$g = ![bool]$null\nif ($g) { $c = 'IEX'; & $c }";
  const cands = d._findPsVariableResolutionCandidates(text, {});
  assert.ok(cands.length >= 1);
  assert.match(cands[0].deobfuscated, /IEX/);
});

test('ps [bool] gate: (N -eq N) comparison evaluates truthy', () => {
  const text = "$g = (9999 -eq 9999)\nif ($g) { $c = 'Invoke-Expression'; & $c }";
  const cands = d._findPsVariableResolutionCandidates(text, {});
  assert.ok(cands.length >= 1);
  assert.match(cands[0].deobfuscated, /Invoke-Expression/);
});

test('ps [bool] gate: (N -ne N) comparison evaluates falsy', () => {
  const text = "$g = (1 -ne 1)\nif ($g) { $c = 'Invoke-Expression'; & $c }";
  const cands = d._findPsVariableResolutionCandidates(text, {});
  assert.equal(cands.length, 0);
});

test('ps [bool] gate: bounded negation chain does not loop', () => {
  // 64 negations is exactly the cap; any more and the evaluator
  // bails. 32 is well inside the bound — result is simply true.
  const text = `$g = ${'!'.repeat(32)}[bool]1\nif ($g) { $c = 'IEX'; & $c }`;
  const cands = d._findPsVariableResolutionCandidates(text, {});
  assert.ok(cands.length >= 1);
});

// ── 4. Quote interruption (single-token) ──────────────────────────────────

test('ps quote interruption: i\'\'e\'\'x strips to iex', () => {
  const text = "i''e''x 'arg'";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Quote Interruption (single-token)');
  assert.ok(hits.length >= 1, `got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /iex/);
});

test('ps quote interruption: double-quoted form i""e""x also works', () => {
  const text = 'i""e""x 2>&1';
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Quote Interruption (single-token)');
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /iex/);
});

test('ps quote interruption: p""o""w""e""r""s""h""e""l""l strips to powershell', () => {
  const text = 'p""o""w""e""r""s""h""e""l""l -nop';
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Quote Interruption (single-token)');
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /powershell/i);
});

test('ps quote interruption: non-sensitive post-strip token is suppressed', () => {
  // `'a''b''c''d''e''f'` strips to `abcdef` which is NOT in the
  // sensitive keyword list — must drop.
  const text = "a''b''c''d''e''f";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Quote Interruption (single-token)');
  assert.equal(hits.length, 0);
});

test('ps quote interruption: amp budget respected', () => {
  // A run of empty-quote-pairs cannot blow deobfuscated beyond raw
  // (strip only removes chars). Sanity-assert anyway because future
  // edits could drift.
  const text = "c''e''r''t''u''t''i''l -decode a b";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PowerShell Quote Interruption (single-token)');
  assert.ok(hits.length >= 1);
  for (const h of hits) {
    const cap = Math.min(8 * 1024, 32 * Math.max(1, h.raw.length));
    assert.ok(h.deobfuscated.length <= cap);
  }
});

// ── Cross-branch: amp budget on all four phase-6 techniques ───────────────

test('phase-6: amp-budget contract holds across all four new branches', () => {
  const corpus = [
    "&(gcm i*x) 'arg'",
    "I<# pad #>nvoke<##>-Expression 'arg'",
    "$g = [bool]1\nif ($g) { $c = 'IEX'; & $c }",
    "c''e''r''t''u''t''i''l -decode",
  ].join('\n');
  const cands = d._findCommandObfuscationCandidates(corpus, {});
  for (const c of cands) {
    if (typeof c.deobfuscated === 'string' && typeof c.raw === 'string') {
      const cap = Math.min(8 * 1024, 32 * Math.max(1, c.raw.length));
      assert.ok(
        c.deobfuscated.length <= cap,
        `amp-budget violation: technique=${c.technique} raw=${c.raw.length} deobf=${c.deobfuscated.length} cap=${cap}`
      );
    }
  }
});
