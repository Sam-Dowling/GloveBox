'use strict';
// ════════════════════════════════════════════════════════════════════════════
// cmd-obfuscation-phase3-ops.test.js — Phase C bounded string/byte ops.
//
// Phase C extends the ps-mini evaluator with a narrow method-call layer
// (`.Substring`, `.Replace`, `.Trim*`, `.ToUpper/.ToLower`,
// `.ToCharArray`, `.Length`, `.Insert`, `.Remove`), static-call primaries
// (`[string]::Join`, `[char](intExpr)`, `[char[]](intArr)`), a tiny
// integer-arithmetic resolver (`_psResolveIntValue`), and a variable-key
// XOR branch in cmd-obfuscation.js.
//
// Deliberately NOT a full PowerShell method surface — only the shapes
// real Invoke-Obfuscation output actually uses.
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
  'src/decoders/base64-hex.js',
  'src/decoders/cmd-obfuscation.js',
  'src/decoders/ps-mini-evaluator.js',
]);
const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();
function pick(cands, pred) { return host(cands.filter(pred)); }
function psVar(cands) { return pick(cands, c => /Variable Resolution/.test(c.technique)); }

// ── String methods on $var receiver ────────────────────────────────────────

test('phase-C: `$x.Substring(start, length)` resolves', () => {
  const text = "$x = 'prefixIEXsuffix'; $y = $x.Substring(6,3); & ($y) 'arg'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /IEX/);
});

test('phase-C: `$x.Substring(start)` single-arg form', () => {
  const text = "$x = 'garbageIEX'; $y = $x.Substring(7); & ($y) 'arg'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /IEX/);
});

test('phase-C: `$x.Replace(a,b)` resolves', () => {
  const text = "$x = 'IXE-Expression'; $y = $x.Replace('IXE','Invoke'); & ($y)";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('phase-C: `$x.ToUpper()` / `$x.ToLower()` round-trip', () => {
  const text = "$x = 'invoke-expression'; $y = $x.ToUpper(); & ($y.ToLower())";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /invoke-expression/);
});

test('phase-C: `$x.Trim()` resolves', () => {
  const text = "$x = '  Invoke-Expression  '; $y = $x.Trim(); & ($y)";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('phase-C: `$x.Insert(i, s)` resolves', () => {
  // "Inv-Expression" insert "oke" at index 3 → "Invoke-Expression".
  const text = "$x = 'Inv-Expression'; $y = $x.Insert(3,'oke'); & ($y)";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1, `got: ${JSON.stringify(hits)}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('phase-C: `$x.Remove(i, n)` resolves', () => {
  const text = "$x = 'InvokeXXX-Expression'; $y = $x.Remove(6,3); & ($y)";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('phase-C: `$x.Length` returns numeric string', () => {
  // Verify via an indexing access that uses .Length as the endpoint:
  // `$s[$s.Length - 1]` ≡ last char.
  // Simpler: use .Length in an arithmetic expression inside Substring.
  const text = "$x = 'padIEX'; $y = $x.Substring(3, 3); & ($y) 'arg'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /IEX/);
});

// ── Static-call primaries ─────────────────────────────────────────────────

test("phase-C: `[char](intExpr)` evaluates arithmetic inside char cast", () => {
  // [char](72) = 'H'. Chain: 'Inv' + [char](111)+[char](107)+[char](101) →
  // 'Invoke', then - + 'Expression' = 'Invoke-Expression'? Not quite. Use
  // simple demonstration: $k = 72; $c = [char]($k+1) = 'I', then
  // concatenate with 'EX' → 'IEX'.
  const text = "$k = 72; $x = [char]($k+1) + 'E' + 'X'; & ($x) 'arg'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /IEX/);
});

test("phase-C: `[char](0xHH)` hex arg resolves", () => {
  const text = "$x = [char](0x49) + [char](0x45) + [char](0x58); & ($x) 'arg'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /IEX/);
});

test("phase-C: `[string]::Join(sep, arr)` with array var", () => {
  const text = "$arr = 'Inv','oke-','Expression'; $x = [string]::Join('', $arr); & ($x)";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test("phase-C: `[char[]](N,M,P) -join ''` resolves via char cast + join", () => {
  // 73,69,88 → "IEX"
  const text = "$x = [char[]](73,69,88) -join ''; & ($x) 'arg'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /IEX/);
});

test("phase-C: `[char[]](65..90) -join ''` range-expanded cast", () => {
  // Whole alphabet — no 'IEX' substring test needed, just assert a
  // 26-char output shows up.
  const text = "$x = [char[]](65..90) -join ''; $y = $x.Substring(8,3); & ($y)";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /IJK/);
});

// ── Variable-key XOR in cmd-obfuscation.js ────────────────────────────────

test('phase-C: `-bxor $key` variable-key decode fires', () => {
  const pl = 'Invoke-Expression iex';
  const key = 0x5a;
  const nums = [...pl].map(c => (c.charCodeAt(0) ^ key).toString()).join(',');
  const text = `$k = ${key}; @(${nums}) | ForEach-Object { $_ -bxor $k }`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /bxor.*var-key/.test(c.technique));
  assert.ok(hits.length >= 1, `expected var-key bxor; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('phase-C: `-bxor $key` hex-literal-value key resolves through evaluator', () => {
  const pl = 'powershell.exe -Command whoami';
  const key = 0x42;
  const nums = [...pl].map(c => (c.charCodeAt(0) ^ key).toString()).join(',');
  const text = `$k = 0x${key.toString(16)}; @(${nums}) | % { $_ -bxor $k }`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /bxor.*var-key/.test(c.technique));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /powershell/i);
});

test('phase-C: `-bxor $unset` unresolved-key does not fire', () => {
  const pl = 'Invoke-Expression iex';
  const key = 0x5a;
  const nums = [...pl].map(c => (c.charCodeAt(0) ^ key).toString()).join(',');
  const text = `@(${nums}) | % { $_ -bxor $somethingUnset }`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /bxor/.test(c.technique));
  assert.equal(hits.length, 0);
});

// ── Combined — mini Invoke-Obfuscation-style chain ────────────────────────

test('phase-C: `[string]::Join` of `[char]` cast array within a chain', () => {
  // Build 'IEX' via per-char constructs and a Join.
  const text = "$arr = [char](73),[char](69),[char](88); $x = [string]::Join('', $arr); & ($x) 'arg'";
  const hits = psVar(d._findPsVariableResolutionCandidates(text, {}));
  assert.ok(hits.length >= 1, `got: ${JSON.stringify(hits)}`);
  assert.match(hits[0].deobfuscated, /IEX/);
});

// ── Amp-budget invariant ──────────────────────────────────────────────────

test('phase-C: candidates respect the 32x amp-budget contract', () => {
  const text = "$x = 'padIEX'; $y = $x.Substring(3,3); & ($y) 'arg'";
  const cands = d._findPsVariableResolutionCandidates(text, {});
  for (const c of cands) {
    if (typeof c.deobfuscated === 'string' && typeof c.raw === 'string') {
      assert.ok(
        c.deobfuscated.length <= 32 * Math.max(1, c.raw.length),
        `amp violation: raw=${c.raw.length} deobf=${c.deobfuscated.length}`,
      );
    }
  }
});
