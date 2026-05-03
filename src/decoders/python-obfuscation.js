// ════════════════════════════════════════════════════════════════════════════
// python-obfuscation.js — Python obfuscation detection & deobfuscation.
// Mirrors the candidate-emission contract of cmd-obfuscation.js so each
// candidate flows through the shared `_processCommandObfuscation`
// post-processor (severity tier from dangerousPatterns + IOCs +
// _executeOutput escalation).
//
// Six finder branches:
//   P1  exec(zlib.decompress(base64.b64decode(b'…')))
//         The canonical "compressed marshalled payload" dropper carrier.
//         Also handles eval/compile wrappers and the
//         __import__('zlib').decompress chain. Decodes both layers
//         (base64 → zlib) using Decompressor.inflateSync.
//   P2  exec(marshal.loads(base64.b64decode('…')))
//         Marshalled bytecode. We surface the base64-decoded bytes (a
//         marshal stream is unreadable but its presence is the signal —
//         the post-processor's _executeOutput tier escalates severity).
//   P3  codecs.decode(s, 'rot_13' | 'hex' | 'base64' | 'zlib')
//         Encoding-specifying decode call with a literal-quoted source.
//   P4  ''.join(chr(N) for …) / bytes([N,N,…]).decode() / chr(N)+chr(N)+…
//         Char-array reassembly. Bounded counts so adversarial inputs
//         can't drive catastrophic backtracking.
//   P5  __import__('os').system(…) / getattr(__builtins__, 'e'+'val')
//         Concatenated builtin lookup. We resolve the name and emit an
//         _executeOutput candidate — the actual sink (`eval` / `exec` /
//         `system`) is what makes it dangerous.
//   P6  subprocess.{run,Popen,check_output,call,getoutput}(…) /
//         os.{system,popen,execv,execl,…}(…)
//         Command-execution sinks. Detection-only when the argument is
//         non-literal; literal-arg variants surface the cleartext.
//
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
// `scripts/build.py` _DETECTOR_FILES loads this AFTER cmd-obfuscation.js
// (it consumes _processCommandObfuscation at scan time, not at load
// time, so this file has no hard dependency on bash-obfuscation.js).
// ════════════════════════════════════════════════════════════════════════════

// Sensitive-token regex used as the post-decode plausibility gate for
// the char-array / chr-concat / decoded-payload branches. Mirrors the
// SENSITIVE_BASH_KEYWORDS / SENSITIVE_CMD_KEYWORDS patterns. A decoded
// Python string must look command-shaped (`exec`, `import`, `subprocess`,
// `socket`, `os.system`, …) to qualify — otherwise every legitimate
// `''.join(chr(c) for c in …)` ascii-art trick would emit findings.
const SENSITIVE_PY_KEYWORDS = /\b(?:exec|eval|compile|__import__|importlib|subprocess|os\.(?:system|popen|exec[vl]?[pe]?|spawn[vl]?[pe]?|fork|kill)|popen\d?|socket|connect|recv|sendall|urllib|urlopen|requests\.(?:get|post|put)|httplib|paramiko|ssl\.wrap_socket|base64\.b(?:32|64)decode|codecs\.decode|marshal\.loads|zlib\.decompress|pty\.spawn|select|ctypes|VirtualAlloc|kernel32|crypto|Fernet|AES\.new|cmd\.exe|powershell|\/bin\/sh|\/bin\/bash|nc\b|ncat|netcat|reverse_shell|\/etc\/passwd|\/etc\/shadow|chmod\s+\+x|os\.environ|sys\.argv|getpass\.getpass)\b/i;

// Helper: dequote a Python string literal (single, double, triple-quoted,
// raw-prefixed, byte-prefixed). Returns null if the input doesn't look
// like a single literal. We model the most common forms; f-strings are
// returned with their leading `f` stripped (and the body verbatim) — we
// don't evaluate `{…}` placeholders, just reveal the surrounding template.
function _dequotePyLiteral(s) {
  if (typeof s !== 'string' || s.length < 2) return null;
  // Strip prefix(es): rb / br / Rb / fR / fb / etc. up to two chars.
  let i = 0;
  let isBytes = false;
  let isRaw = false;
  while (i < 2 && i < s.length) {
    const ch = s[i].toLowerCase();
    if (ch === 'r') { isRaw = true; i++; continue; }
    if (ch === 'b') { isBytes = true; i++; continue; }
    if (ch === 'u' || ch === 'f') { i++; continue; }
    break;
  }
  let body = s.slice(i);
  if (body.length < 2) return null;
  // Triple-quoted
  if (body.startsWith("'''") || body.startsWith('"""')) {
    const q = body.slice(0, 3);
    if (!body.endsWith(q) || body.length < 6) return null;
    body = body.slice(3, -3);
  } else if (body[0] === "'" || body[0] === '"') {
    const q = body[0];
    if (body[body.length - 1] !== q || body.length < 2) return null;
    body = body.slice(1, -1);
  } else {
    return null;
  }
  if (isRaw) return body;
  // Decode standard Python string escapes — same set as ANSI-C plus
  // Python-specific \N{}, \xNN, \uHHHH, \UHHHHHHHH.
  return _decodePyEscapes(body, isBytes);
}

// Decode Python-style string escapes inside a quoted literal body.
// Bounded — every alternative consumes ≥1 char.
function _decodePyEscapes(body, /* isBytes */ _isB) {
  let out = '';
  let i = 0;
  while (i < body.length) {
    const c = body[i];
    if (c !== '\\') { out += c; i++; continue; }
    if (i + 1 >= body.length) { out += '\\'; i++; continue; }
    const n = body[i + 1];
    const simple = { 'a': 7, 'b': 8, 'f': 12, 'n': 10, 'r': 13, 't': 9,
                     'v': 11, '\\': 92, "'": 39, '"': 34, '0': 0 };
    if (simple[n] !== undefined && !(n >= '1' && n <= '7')) {
      out += String.fromCharCode(simple[n]); i += 2; continue;
    }
    if (n === 'x') {
      const m = /^[0-9a-fA-F]{1,2}/.exec(body.slice(i + 2)); /* safeRegex: builtin */
      if (m) { out += String.fromCharCode(parseInt(m[0], 16)); i += 2 + m[0].length; continue; }
      out += body[i]; i++; continue;
    }
    if (n === 'u') {
      const m = /^[0-9a-fA-F]{1,4}/.exec(body.slice(i + 2)); /* safeRegex: builtin */
      if (m) {
        try { out += String.fromCodePoint(parseInt(m[0], 16)); }
        catch (_) { out += '?'; }
        i += 2 + m[0].length; continue;
      }
      out += body[i]; i++; continue;
    }
    if (n === 'U') {
      const m = /^[0-9a-fA-F]{1,8}/.exec(body.slice(i + 2)); /* safeRegex: builtin */
      if (m) {
        try {
          const cp = parseInt(m[0], 16);
          if (cp <= 0x10FFFF) out += String.fromCodePoint(cp);
          else out += '?';
        } catch (_) { out += '?'; }
        i += 2 + m[0].length; continue;
      }
      out += body[i]; i++; continue;
    }
    // Octal \NNN (1-3 digits, max value 0o777 = 511; clamp to byte)
    if (n >= '0' && n <= '7') {
      const m = /^[0-7]{1,3}/.exec(body.slice(i + 1)); /* safeRegex: builtin */
      if (m) { out += String.fromCharCode(parseInt(m[0], 8) & 0xFF); i += 1 + m[0].length; continue; }
      out += body[i]; i++; continue;
    }
    // \N{NAME} — too rare to model; surface verbatim
    if (n === 'N' && body[i + 2] === '{') {
      const end = body.indexOf('}', i + 3);
      if (end > 0 && end - i - 3 < 80) {
        out += `\\N{${body.slice(i + 3, end)}}`;
        i = end + 1; continue;
      }
      out += body[i + 1]; i += 2; continue;
    }
    // Unknown escape — Python preserves both chars verbatim
    out += body[i] + body[i + 1]; i += 2;
  }
  return out;
}

// Helper: base64-decode a UTF-8 string into a Uint8Array. Returns null
// on decode failure. Uses `atob` in browsers, Buffer in Node tests.
function _b64ToBytes(s) {
  if (typeof s !== 'string') return null;
  const clean = s.replace(/\s+/g, '');
  try {
    if (typeof atob === 'function') {
      const bin = atob(clean);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    /* eslint-disable-next-line no-undef */
    return new Uint8Array(Buffer.from(clean, 'base64'));
  } catch (_) { return null; }
}

// Helper: Uint8Array → printable preview string. Decodes as UTF-8 with
// `replacement` errors (the default TextDecoder behaviour); if the
// result is mostly non-printable, the post-processor still gets bytes
// to count via decodedBytes, but the deobfuscated preview falls back
// to a hex synopsis of the leading 32 bytes.
function _bytesToPreview(bytes) {
  if (!bytes || !bytes.length) return null;
  let s = '';
  try { s = new TextDecoder('utf-8', { fatal: false }).decode(bytes); }
  catch (_) {
    let hex = '';
    for (let i = 0; i < Math.min(bytes.length, 32); i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return `<binary ${bytes.length}B: ${hex}\u2026>`;
  }
  // A printable ratio < 0.7 means the decoded bytes are likely
  // marshalled bytecode / pickle — surface the byte length plus a
  // hex synopsis so the analyst sees the breadcrumb instead of mojibake.
  let printable = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127)) printable++;
  }
  if (s.length > 0 && printable / s.length < 0.7) {
    let hex = '';
    for (let i = 0; i < Math.min(bytes.length, 32); i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return `<binary ${bytes.length}B (likely marshal/pickle): ${hex}\u2026>`;
  }
  return s;
}

// ════════════════════════════════════════════════════════════════════════════


Object.assign(EncodedContentDetector.prototype, {

  /**
   * Find Python obfuscation patterns. Each candidate has the
   * candidate-emission contract:
   *   { type:'cmd-obfuscation', technique, raw, offset, length, deobfuscated }
   * and is consumed by the shared `_processCommandObfuscation`
   * post-processor.
   */
  _findPythonObfuscationCandidates(text, _context) {
    if (!text || text.length < 8) return [];
    const candidates = [];

    // ── P1: exec(zlib.decompress(base64.b64decode(b'…'))) ──
    //
    // Variants:
    //   exec(zlib.decompress(base64.b64decode(b'…')))
    //   exec(__import__('zlib').decompress(__import__('base64').b64decode('…')))
    //   eval(compile(zlib.decompress(base64.b64decode(b'…')), …))
    //   exec(__import__('zlib').decompress(__import__('base64').b16decode('…')))
    //
    // The base64 / b16 / b32 alphabet captures up to 64KB of payload
    // (worker-bundle decode budget). Decompressor.inflateSync handles
    // both zlib (78 9C) and gzip (1F 8B) headers; success → we recurse
    // the cleartext through `_processCandidate` via the post-processor.
    const p1Re = /\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?(?:zlib|__import__\s*\(\s*['"]zlib['"]\s*\))\s*\.\s*decompress\s*\(\s*(?:base64|__import__\s*\(\s*['"]base64['"]\s*\))\s*\.\s*(b(?:64|32|16)decode)\s*\(\s*(b?['"][A-Za-z0-9+/=\s]{4,65536}['"])\s*\)/g;
    let m;
    while ((m = p1Re.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const fn = m[1];                  // b16decode / b32decode / b64decode
      const litRaw = m[2];
      const lit = _dequotePyLiteral(litRaw);
      if (lit === null) continue;
      let bytes = null;
      if (fn === 'b64decode') bytes = _b64ToBytes(lit);
      else if (fn === 'b16decode') {
        // base16 / hex
        const hex = lit.replace(/\s+/g, '');
        if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) continue;
        bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
          bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
        }
      } else if (fn === 'b32decode') {
        // base32 — uncommon in droppers; skip statically (analyst can
        // run a one-off decoder). Falling through is intentional.
        continue;
      }
      if (!bytes || bytes.length === 0) continue;
      // Inflate via Decompressor.inflateSync (sync zlib/deflate path).
      let inflated = null;
      try {
        if (typeof Decompressor !== 'undefined'
            && typeof Decompressor.inflateSync === 'function') {
          // The compressed bytes can be raw deflate, zlib (78 9C), or
          // gzip (1F 8B); try deflate first (most common in droppers
          // because the Python `zlib` module wraps with zlib header).
          inflated = Decompressor.inflateSync(bytes, 'zlib')
                   || Decompressor.inflateSync(bytes, 'gzip')
                   || Decompressor.inflateSync(bytes, 'deflate-raw');
        }
      } catch (_) { /* fall through */ }
      const preview = inflated
        ? (_bytesToPreview(inflated) || _bytesToPreview(bytes))
        : _bytesToPreview(bytes);
      if (!preview) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Python exec(zlib.decompress(b64))',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: preview,
        _executeOutput: true,
      });
    }

    // ── P2: exec(marshal.loads(base64.b64decode('…'))) ──
    //
    // Marshal serialises Python bytecode (code objects, ints, tuples,
    // strs, …). The bytestream is unreadable to a human but its mere
    // presence inside `exec(marshal.loads(...))` is a textbook dropper
    // primitive (PEP-3127, used since pyobfuscate.py in 2010).
    const p2Re = /\b(?:exec|eval)\s*\(\s*marshal\s*\.\s*loads\s*\(\s*(?:base64\s*\.\s*b64decode\s*\(\s*)?(b?['"][A-Za-z0-9+/=\s]{8,65536}['"])/g;
    while ((m = p2Re.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const lit = _dequotePyLiteral(m[1]);
      if (lit === null) continue;
      const bytes = _b64ToBytes(lit);
      if (!bytes || bytes.length < 4) continue;
      const preview = _bytesToPreview(bytes) || `<marshal payload ${bytes.length}B>`;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Python exec(marshal.loads(b64))',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: preview,
        _executeOutput: true,
      });
    }

    // ── P3: codecs.decode(s, 'rot_13' | 'hex' | 'base64' | 'zlib') ──
    //
    //   codecs.decode('uryyb', 'rot_13')     → 'hello'
    //   codecs.decode('68656c6c6f', 'hex')   → 'hello'
    //   codecs.decode(b'…', 'base64')        → bytes
    //   codecs.decode(b'…', 'zlib')          → bytes (after inflate)
    //
    // Decode encoding-by-name and emit the cleartext for sensitivity
    // gating. We model rot_13/rot13, hex/hex_codec, base64/base64_codec,
    // zlib/zlib_codec — the common encoder-name variants.
    const p3Re = /\bcodecs\s*\.\s*decode\s*\(\s*(b?['"][^'"\r\n]{4,8192}['"])\s*,\s*['"]([a-z0-9_]{2,32})['"]\s*\)/gi;
    while ((m = p3Re.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const lit = _dequotePyLiteral(m[1]);
      if (lit === null) continue;
      const enc = m[2].toLowerCase().replace(/[-_]?codec$/, '');
      let preview = null;
      if (enc === 'rot13' || enc === 'rot_13') {
        preview = lit.replace(/[A-Za-z]/g, ch => {
          const c = ch.charCodeAt(0);
          const base = c < 97 ? 65 : 97;
          return String.fromCharCode(((c - base + 13) % 26) + base);
        });
      } else if (enc === 'hex' || enc === 'hex_codec') {
        const hex = lit.replace(/\s+/g, '');
        if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) continue;
        let s = '';
        for (let i = 0; i < hex.length; i += 2) {
          s += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
        }
        preview = s;
      } else if (enc === 'base64' || enc === 'base64_codec' || enc === 'b64') {
        const bytes = _b64ToBytes(lit);
        if (!bytes) continue;
        preview = _bytesToPreview(bytes);
      } else if (enc === 'zlib' || enc === 'zlib_codec') {
        const bytes = _b64ToBytes(lit);
        if (!bytes) continue;
        let inflated = null;
        try {
          if (typeof Decompressor !== 'undefined'
              && typeof Decompressor.inflateSync === 'function') {
            inflated = Decompressor.inflateSync(bytes, 'zlib')
                     || Decompressor.inflateSync(bytes, 'deflate-raw');
          }
        } catch (_) { /* fall through */ }
        if (!inflated) continue;
        preview = _bytesToPreview(inflated);
      } else {
        continue;
      }
      if (!preview || preview.length < 2) continue;
      // Sensitivity gate: only emit when decoded looks command-shaped
      // (the codecs.decode entry point is also used in legitimate
      // text-processing code). Bruteforce mode bypasses.
      if (!SENSITIVE_PY_KEYWORDS.test(preview) && !this._bruteforce) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: `Python codecs.decode('${enc}')`,
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: preview,
      });
    }

    // ── P4: char-array reassembly ──
    //
    //   ''.join(chr(N) for N in [78, 79, …])
    //   bytes([78, 79, …]).decode()
    //   chr(72)+chr(101)+chr(108)+chr(108)+chr(111)
    //   ''.join([chr(72), chr(101), …])
    //
    // We bound the array to ≤512 ints to cap regex cost; a longer
    // payload should not be carried this way (printable-string drop
    // would be more efficient — droppers use zlib/marshal instead).
    const p4ChrJoinRe = /(?:''|""|b'')\.join\s*\(\s*(?:\[\s*)?chr\s*\(\s*(?:\d{1,4})\s*\)(?:\s*,\s*chr\s*\(\s*\d{1,4}\s*\)){2,511}\s*(?:\]\s*)?\)/g;
    while ((m = p4ChrJoinRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      const nums = [...raw.matchAll(/chr\s*\(\s*(\d{1,4})\s*\)/g)].map(x => parseInt(x[1], 10));
      if (nums.length < 3) continue;
      let s = '';
      for (const n of nums) {
        if (n > 0x10FFFF) { s = ''; break; }
        try { s += String.fromCodePoint(n); } catch (_) { s = ''; break; }
      }
      if (!s || s.length < 3) continue;
      if (!SENSITIVE_PY_KEYWORDS.test(s) && !this._bruteforce) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Python chr-join Reassembly',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: s,
      });
    }

    // Comprehension/generator form: chr(X) for X in [N,N,…] / [chr(X) for X in [N,N,…]]
    //
    //   ''.join(chr(x) for x in [78, 79, …])
    //   ''.join([chr(i) for i in [78, 79, …]])
    //   ''.join(chr(c) for c in (78, 79, …))
    //
    // The literal-tuple form is the one that matters — the decoder
    // can resolve the codepoint list statically. A generator iterating
    // a variable is undecodable without interpreting.
    const p4ChrCompRe = /(?:''|""|b'')\.join\s*\(\s*\[?\s*chr\s*\(\s*\w+\s*\)\s+for\s+\w+\s+in\s+[\[\(]\s*(\d{1,4}(?:\s*,\s*\d{1,4}){2,511})\s*[\]\)]\s*\]?\s*\)/g;
    while ((m = p4ChrCompRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      const nums = m[1].split(',').map(x => parseInt(x.trim(), 10));
      if (nums.length < 3) continue;
      let s = '';
      for (const n of nums) {
        if (!Number.isFinite(n) || n < 0 || n > 0x10FFFF) { s = ''; break; }
        try { s += String.fromCodePoint(n); } catch (_) { s = ''; break; }
      }
      if (!s || s.length < 3) continue;
      if (!SENSITIVE_PY_KEYWORDS.test(s) && !this._bruteforce) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Python chr-join Reassembly',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: s,
      });
    }

    // bytes([N,N,…]).decode() / bytes([…]).decode('utf-8')
    const p4BytesArrRe = /bytes\s*\(\s*\[\s*(\d{1,3}(?:\s*,\s*\d{1,3}){2,511})\s*\]\s*\)\s*\.\s*decode\s*\([^)]{0,40}\)/g;
    while ((m = p4BytesArrRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const nums = m[1].split(',').map(x => parseInt(x.trim(), 10));
      if (nums.some(n => isNaN(n) || n > 255 || n < 0)) continue;
      const arr = new Uint8Array(nums);
      const preview = _bytesToPreview(arr);
      if (!preview || preview.length < 3) continue;
      if (!SENSITIVE_PY_KEYWORDS.test(preview) && !this._bruteforce) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Python bytes-list Reassembly',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: preview,
      });
    }

    // chr(N)+chr(N)+chr(N)…  — concatenation form
    const p4ChrConcatRe = /chr\s*\(\s*\d{1,4}\s*\)(?:\s*\+\s*chr\s*\(\s*\d{1,4}\s*\)){2,511}/g;
    while ((m = p4ChrConcatRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      const nums = [...raw.matchAll(/chr\s*\(\s*(\d{1,4})\s*\)/g)].map(x => parseInt(x[1], 10));
      if (nums.length < 3) continue;
      let s = '';
      for (const n of nums) {
        if (n > 0x10FFFF) { s = ''; break; }
        try { s += String.fromCodePoint(n); } catch (_) { s = ''; break; }
      }
      if (!s || s.length < 3) continue;
      if (!SENSITIVE_PY_KEYWORDS.test(s) && !this._bruteforce) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Python chr-concat Reassembly',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: s,
      });
    }

    // ── P5: builtin-name string-concat lookup ──
    //
    //   getattr(__builtins__, 'e' + 'val')(payload)
    //   __builtins__.__dict__['e'+'xec']
    //   globals()['__b'+'uiltins__']['eval']
    //
    // The point is to bypass YARA / hand-rolled scanners that look for
    // a literal `eval`/`exec`/`compile` token. We resolve the
    // concatenation and emit when the joined name lands in the
    // dangerous-builtin set.
    const DANGEROUS_BUILTINS = new Set([
      'eval', 'exec', 'compile', '__import__', 'getattr', 'globals',
      'locals', 'open', 'input', 'breakpoint',
    ]);
    const p5ConcatRe = /(?:getattr\s*\(\s*[^,)]{1,80}\s*,\s*|\[\s*)\s*(['"])((?:[A-Za-z_]\w*)?)\1(\s*\+\s*(['"])([A-Za-z_]\w{0,40})\4){1,8}/g;
    while ((m = p5ConcatRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      // Sum the quoted fragments
      const frags = [...raw.matchAll(/(['"])([A-Za-z_]\w{0,40})\1/g)].map(x => x[2]);
      const joined = frags.join('');
      if (joined.length < 3 || joined.length > 60) continue;
      if (!DANGEROUS_BUILTINS.has(joined) && !this._bruteforce) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Python Builtin String-Concat',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: `getattr(\u2026, '${joined}')`,
        _executeOutput: true,
      });
    }

    // ── P6: command-execution sinks ──
    //
    //   subprocess.{run,Popen,check_output,check_call,call,getoutput}(['sh','-c','…'])
    //   subprocess.{...}('cmd …', shell=True)
    //   os.system('…')
    //   os.popen('…').read()
    //   os.{execv,execvp,execl,execlp,spawnv,spawnvp,…}('/bin/sh', …)
    //   pty.spawn('/bin/sh')  — interactive-shell upgrade primitive
    //
    // Detection-only when the command is non-literal. Literal-arg
    // variants surface the cleartext (sensitivity gate via
    // dangerousPatterns in the post-processor).
    const p6SubRe = /\bsubprocess\s*\.\s*(?:run|Popen|check_output|check_call|call|getoutput)\s*\(\s*(?:\[\s*)?(b?['"][^'"\r\n]{2,400}['"])(?:\s*,\s*(?:b?['"][^'"\r\n]{0,400}['"](?:\s*,\s*)?){0,8})?(?:\s*\])?(?:\s*,\s*shell\s*=\s*True)?/g;
    while ((m = p6SubRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const lit = _dequotePyLiteral(m[1]);
      if (lit === null) continue;
      // Strip the "['/bin/sh', '-c', …]" wrapper to reveal the actual
      // command. The full match captures any subsequent quoted args;
      // re-collect them all and pick the longest (typically the -c arg).
      const allLits = [...m[0].matchAll(/(b?)(['"])([^'"\r\n]{0,400})\2/g)].map(x => x[3]);
      const longest = allLits.length ? allLits.reduce((a, b) => a.length >= b.length ? a : b) : lit;
      if (longest.length < 3) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Python subprocess Sink',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: longest,
        _executeOutput: true,
      });
    }

    const p6OsRe = /\bos\s*\.\s*(?:system|popen|exec[vl][pe]?|spawn[vl][pe]?)\s*\(\s*(b?['"][^'"\r\n]{2,400}['"])/g;
    while ((m = p6OsRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const lit = _dequotePyLiteral(m[1]);
      if (lit === null) continue;
      if (lit.length < 3) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Python os.system Sink',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: lit,
        _executeOutput: true,
      });
    }

    // pty.spawn('/bin/sh') — the canonical interactive-shell upgrade
    // primitive after a reverse-shell catch.
    const p6PtyRe = /\bpty\s*\.\s*spawn\s*\(\s*(b?['"][^'"\r\n]{2,200}['"])/g;
    while ((m = p6PtyRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const lit = _dequotePyLiteral(m[1]);
      if (lit === null) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Python pty.spawn Shell-Upgrade',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: `pty.spawn(${JSON.stringify(lit)})`,
        _executeOutput: true,
      });
    }

    // socket reverse-shell shape: socket.socket() + connect((HOST,PORT))
    // + os.dup2(s.fileno(),N) + pty.spawn / subprocess.call. We model
    // a more compact heuristic: socket.connect((<ip-or-host>, <port>))
    // within ~1 KB of an os.dup2 call. Detection-only; no decode.
    const p6RevShellRe = /socket\s*\.\s*socket\s*\([^\r\n)]{0,200}\)[\s\S]{0,1000}?\.\s*connect\s*\(\s*\(\s*(['"]?)([\w.\-]{3,80})\1\s*,\s*(\d{1,5})\s*\)[\s\S]{0,1000}?(?:os\s*\.\s*dup2|pty\s*\.\s*spawn|subprocess\s*\.\s*(?:call|Popen|run))/g;
    while ((m = p6RevShellRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const host = m[2];
      const port = m[3];
      const raw = m[0];
      if (raw.length > 2000) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Python Socket Reverse-Shell',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: `socket connect ${host}:${port} \u2192 dup2/pty.spawn`,
        _executeOutput: true,
      });
    }

    return candidates;
  },
});
