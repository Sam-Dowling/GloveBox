// ════════════════════════════════════════════════════════════════════════════
// js-assembly.js — JavaScript string-array obfuscation resolver
//
// Defangs the most common JS obfuscator-tool layout (obfuscator.io,
// javascript-obfuscator npm package, and any hand-written variant of the
// same shape):
//
//   var _0xabc1 = ['log', 'Hello, World', 'http://attacker.example/c2'];
//   function _0xdef2 (i, k) { return _0xabc1[i - 0]; }
//   eval(_0xdef2(0x0) + _0xdef2(0x1));
//   console[_0xdef2(0)](_0xdef2(0x1) + ' ' + _0xdef2(0x2));
//
// The script is a string-array literal at the top, an indexer function that
// returns `arr[i ± K]`, and one or more sink calls (`eval`, `Function`,
// `setTimeout`, `atob`) whose arguments are concatenated indexer calls. The
// sink-call argument is the only thing the original program is ever going to
// actually evaluate, and recovering it surfaces every URL / domain / shell
// invocation the obfuscator was hiding.
//
// Supported shapes
// ----------------
//   * One string-array assignment per source span: `var/let/const NAME = [
//     'lit1', 'lit2', … ];` — comma-separated string literals, ≥10 entries
//     OR ≥5 base64-looking entries (the trigger gate, see
//     `_jsLooksLikeStringArrayObfuscation`).
//   * One indexer function: `function NAME(i, …) { return ARR[i]; }` or
//     `return ARR[i - N];` / `return ARR[i + N];` (simple offset only).
//   * Sink calls anywhere downstream:
//       - eval(<expr>)
//       - Function(<expr>)               (also new Function(<expr>))
//       - setTimeout(<expr>, …)
//       - setInterval(<expr>, …)
//       - atob(<expr>)
//     `<expr>` is a concatenation of `INDEXER(<numeric>)` calls and
//     string literals joined by `+`. Anything we can't resolve drops
//     the whole sink (no half-resolved emission).
//
// Out of scope (deliberate)
// -------------------------
//   * Multiple arrays (rare in practice; first-array-wins keeps cost flat).
//   * Array shuffles / runtime mutations (`arr.push(arr.shift())` cycles —
//     a richer evaluator would need real control-flow tracking).
//   * `Function.prototype.constructor` access shapes.
//   * Bracket-property access on objects keyed by indexer call
//     (`window[INDEXER(0)] = …`) — currently the resolved string is
//     reported but no sink-style finding is emitted.
//   * Bracket-property access on the indexer return value.
//
// Why a finder + evaluator in one file?
// -------------------------------------
// `ps-mini-evaluator.js` set the precedent: keep the parser, symbol-table
// builder, expression resolver, and the `_findFooCandidates` entrypoint
// together so the file is one self-contained deobfuscation strategy. The
// evaluator state is short-lived (one `_jsResolveArrayObfuscation` call per
// scan), so there's no reason to split its types out into a sibling module.
//
// CSP & safety
// ------------
// Pure tokeniser. No `eval`, no `new Function`, no `Function.prototype.bind`
// trickery. All resolution is string-literal lookups + concatenation in
// JS-land. The decoder cannot itself execute the resolved payload; the
// caller (`_processCommandObfuscation`) decides whether to forward it for
// further analysis.
//
// Wall-clock budget
// -----------------
// The scan has three caps that match the `ps-mini-evaluator` budget so a
// pathological input degrades coverage rather than hanging the worker:
//   * Source length: ignored above 256 KB (`MAX_SOURCE_BYTES`).
//   * Array entries: capped at 4096 (`MAX_ARRAY_ENTRIES`).
//   * Sink calls per file: `this.maxCandidatesPerType` (host-set).
// Any internal exception returns `[]`.
//
// PLAN.md → D6. Mounted via `Object.assign(EncodedContentDetector.prototype,
// …)` so candidates flow through `_processCommandObfuscation` (severity,
// IOC extraction, sidebar wiring already handled there).
// ════════════════════════════════════════════════════════════════════════════

(function () {

  // ── Tunables ────────────────────────────────────────────────────────────
  // Source spans larger than this almost always belong to bundled libs
  // (jQuery, lodash, webpack runtime), where the false-positive cost of
  // parsing string-array literals dwarfs the analytic value. The
  // string-array obfuscator's typical output is well under this cap.
  const MAX_SOURCE_BYTES = 256 * 1024;

  // Hard upper bound on the recovered string-array. obfuscator.io output
  // commonly has 50–500 entries; anything past 4096 is pathological and
  // unlikely to belong to the simple shape we resolve.
  const MAX_ARRAY_ENTRIES = 4096;

  // The trigger gate. The finder needs to be confident enough that the
  // span IS a string-array obfuscation before paying the parse cost; an
  // ordinary `const COLOURS = ['red', 'green', 'blue']` should NOT trip
  // it. Two paths qualify a literal as obfuscation-shaped:
  //   * ≥ MIN_ENTRIES distinct elements, OR
  //   * ≥ MIN_BASE64_LOOKING base64-shaped strings (length ≥ 8, alphabet
  //     conforms). The base64-looking check is what catches obfuscators
  //     that emit short arrays of long encoded blobs.
  const MIN_ENTRIES = 10;
  const MIN_BASE64_LOOKING = 5;

  // Per-string sanity caps — defend against pathological inputs without
  // restricting realistic obfuscator output.
  const MAX_STRING_LITERAL_LEN = 4096;
  const MAX_SINK_ARG_LEN       = 4096;
  const MAX_RESOLVED_LEN       = 16 * 1024;

  // Sink table — call expressions whose first argument is the program's
  // actual payload. Order matters only for the regex alternation below
  // (longer names first to prevent partial matches). The patterns are
  // anchored by a word-boundary so `myEval(` doesn't match `eval(`.
  const SINK_NAMES = ['Function', 'setTimeout', 'setInterval', 'eval', 'atob'];
  // Alternation built from the closed SINK_NAMES literal list, no user input.
  /* safeRegex: builtin */
  const SINK_RE = new RegExp(
    '(?:^|[^\\w$])(?:new\\s+)?(' + SINK_NAMES.join('|') + ')\\s*\\(',
    'g',
  );

  // Indexer-function shape. Captures the indexer name in group 1 and the
  // array name in group 2. Two return forms accepted:
  //   * `return ARR[i];`
  //   * `return ARR[i - N];` / `return ARR[i + N];`
  // The offset is computed by the caller (negated for `-`, kept for `+`)
  // because the indexer's `i` is the OBFUSCATOR'S synthetic index, and
  // the real array index is `i - offset`. Many obfuscators use a non-zero
  // offset purely to make hand-deobfuscation harder.
  const INDEXER_RE = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{[\s\S]{0,512}?return\s+([A-Za-z_$][\w$]*)\s*\[\s*([^[\]]{0,64})\s*\]\s*;?\s*\}/g;

  // String-array assignment. Group 1 = name, group 2 = body. The body
  // is bounded ([\s\S]{0,...}) so a missing `]` doesn't backtrack
  // catastrophically.
  const ARRAY_ASSIGN_RE = /\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*\[([\s\S]{0,131072}?)\]\s*;?/g;

  // ── Helpers ──────────────────────────────────────────────────────────

  /** True when `s` is plausibly Base64 — at least 8 chars, alphabet conforms.
   *  We accept the URL-safe variant too. Padding is optional. */
  function _looksLikeBase64(s) {
    if (typeof s !== 'string' || s.length < 8) return false;
    return /^[A-Za-z0-9+/_-]+={0,2}$/.test(s);
  }

  /** Parse a JavaScript string literal starting at `src[i]` (which must be
   *  a `'` or `"`). Returns `{ value, end }` where `end` is the index
   *  *past* the closing quote, or `null` if the literal is malformed.
   *  Honours the standard escapes and rejects newlines (template literals
   *  use backticks, which are a separate shape we don't claim to support).
   */
  function _readStringLiteral(src, i) {
    if (i >= src.length) return null;
    const quote = src[i];
    if (quote !== "'" && quote !== '"') return null;
    let out = '';
    let j = i + 1;
    while (j < src.length) {
      const c = src[j];
      if (c === quote) return { value: out, end: j + 1 };
      if (c === '\n' || c === '\r') return null;
      if (c === '\\' && j + 1 < src.length) {
        const e = src[j + 1];
        switch (e) {
          case 'n':  out += '\n'; j += 2; break;
          case 'r':  out += '\r'; j += 2; break;
          case 't':  out += '\t'; j += 2; break;
          case 'b':  out += '\b'; j += 2; break;
          case 'f':  out += '\f'; j += 2; break;
          case 'v':  out += '\v'; j += 2; break;
          case '0':  out += '\0'; j += 2; break;
          case "'":  out += "'";  j += 2; break;
          case '"':  out += '"';  j += 2; break;
          case '\\': out += '\\'; j += 2; break;
          case '/':  out += '/';  j += 2; break;
          case '\n': /* line continuation */ j += 2; break;
          case 'x': {
            // \xHH
            const hex = src.substring(j + 2, j + 4);
            if (/^[0-9a-fA-F]{2}$/.test(hex)) {
              out += String.fromCharCode(parseInt(hex, 16));
              j += 4;
            } else {
              return null;
            }
            break;
          }
          case 'u': {
            // \uHHHH — refuse `\u{…}` form (extra parsing cost, rare in
            // obfuscator output).
            const hex = src.substring(j + 2, j + 6);
            if (/^[0-9a-fA-F]{4}$/.test(hex)) {
              out += String.fromCharCode(parseInt(hex, 16));
              j += 6;
            } else {
              return null;
            }
            break;
          }
          default:
            // Unknown escape — preserve the literal char (matches V8 behaviour
            // for non-special escapes).
            out += e;
            j += 2;
        }
        if (out.length > MAX_STRING_LITERAL_LEN) return null;
        continue;
      }
      out += c;
      j++;
      if (out.length > MAX_STRING_LITERAL_LEN) return null;
    }
    return null; // EOF without closing quote
  }

  /** Parse a comma-separated list of string literals (the body of a
   *  string-array literal). Whitespace is permitted between elements;
   *  trailing comma is allowed. Returns an array of strings, or `null` on
   *  any deviation from the accepted shape (a non-string element drops
   *  the whole array — the trigger gate would lose its precision if we
   *  papered over expressions like `[…, fn(), …]`). */
  function _parseStringArrayBody(body) {
    if (body.length > 1024 * 1024) return null;
    const out = [];
    let i = 0;
    while (i < body.length) {
      // Skip whitespace + comments. Comments inside obfuscator output
      // are uncommon but we tolerate single-line `//` for forward
      // compatibility (block comments are stripped at the lexer level
      // by V8 before we ever see them in real code, but our input is
      // raw source so we honour them).
      while (i < body.length && /\s/.test(body[i])) i++;
      if (i < body.length && body[i] === '/' && body[i + 1] === '/') {
        while (i < body.length && body[i] !== '\n') i++;
        continue;
      }
      if (i < body.length && body[i] === '/' && body[i + 1] === '*') {
        const close = body.indexOf('*/', i + 2);
        if (close < 0) return null;
        i = close + 2;
        continue;
      }
      if (i >= body.length) break;
      const lit = _readStringLiteral(body, i);
      if (!lit) return null;
      out.push(lit.value);
      if (out.length > MAX_ARRAY_ENTRIES) return null;
      i = lit.end;
      while (i < body.length && /\s/.test(body[i])) i++;
      if (i < body.length && body[i] === ',') i++;
      else if (i < body.length) {
        // A non-comma, non-whitespace, non-comment token after a literal
        // means the array contains something other than string literals
        // — fail the whole parse so the trigger gate doesn't fire on a
        // mixed array we can't faithfully resolve.
        return null;
      }
    }
    return out;
  }

  /** Parse the body of an indexer's index expression (the `…` between the
   *  brackets in `arr[…]`). Returns `{ varName, offset }` where `offset`
   *  is the constant to be SUBTRACTED from the call argument before the
   *  array lookup (matches `arr[i - N]` semantics — for `+ N`, the
   *  offset is `-N`). Returns `null` on any unsupported shape (e.g.
   *  hex-string subtraction, function calls, multiple ops). */
  function _parseIndexerExpr(expr) {
    const trimmed = expr.trim();
    // Plain `i` — just use the call argument as the index.
    const plain = /^([A-Za-z_$][\w$]*)$/.exec(trimmed);
    if (plain) return { varName: plain[1], offset: 0 };
    // `i - N` or `i + N` — N is decimal or hex.
    const op = /^([A-Za-z_$][\w$]*)\s*([-+])\s*(0x[0-9a-fA-F]+|\d+)$/.exec(trimmed);
    if (op) {
      const n = op[3].startsWith('0x') ? parseInt(op[3], 16) : parseInt(op[3], 10);
      if (!Number.isFinite(n)) return null;
      return { varName: op[1], offset: op[2] === '-' ? n : -n };
    }
    return null;
  }

  /** Top-level split on `+`. Quoted literals, parens, brackets, and
   *  template literals are honoured (template literals are skipped opaquely
   *  — we don't resolve them either way). Returns the operand spans. */
  function _splitConcat(src) {
    const out = [];
    let inSingle = false, inDouble = false, inBack = false;
    let depth = 0, start = 0;
    for (let i = 0; i < src.length; i++) {
      const c = src[i];
      if (inSingle) { if (c === '\\' && i + 1 < src.length) i++; else if (c === "'") inSingle = false; continue; }
      if (inDouble) { if (c === '\\' && i + 1 < src.length) i++; else if (c === '"') inDouble = false; continue; }
      if (inBack)   { if (c === '\\' && i + 1 < src.length) i++; else if (c === '`') inBack = false; continue; }
      if (c === "'")  { inSingle = true; continue; }
      if (c === '"')  { inDouble = true; continue; }
      if (c === '`')  { inBack = true;   continue; }
      if (c === '(' || c === '{' || c === '[') { depth++; continue; }
      if (c === ')' || c === '}' || c === ']') { depth = Math.max(0, depth - 1); continue; }
      if (depth === 0 && c === '+' &&
          // not `++` and not the unary form (preceded by another operator).
          src[i + 1] !== '+' && src[i - 1] !== '+') {
        out.push(src.substring(start, i));
        start = i + 1;
      }
    }
    out.push(src.substring(start));
    return out;
  }

  /** Resolve a concatenation span (`A + B + C + …`) to a single string,
   *  given the indexer name and the resolved string-array. Returns the
   *  concatenated string, or `null` if any operand is not resolvable
   *  (a string literal or an `INDEXER(<numeric>)` call). The all-or-nothing
   *  policy keeps the analyst from chasing a half-resolved sink call. */
  function _resolveConcat(span, indexerName, indexerOffset, arr) {
    const parts = _splitConcat(span);
    let out = '';
    for (const raw of parts) {
      const p = raw.trim();
      if (!p) return null;
      // String literal operand?
      if (p[0] === '"' || p[0] === "'") {
        const lit = _readStringLiteral(p, 0);
        if (!lit || lit.end !== p.length) return null;
        out += lit.value;
        if (out.length > MAX_RESOLVED_LEN) return null;
        continue;
      }
      // INDEXER(<numeric>) call? `indexerName` is a JS identifier captured
      // from `INDEXER_RE` and regex-metachar-escaped before interpolation.
      /* safeRegex: builtin */
      const callRe = new RegExp(
        '^' + indexerName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
            + '\\s*\\(\\s*(0x[0-9a-fA-F]+|\\d+)\\s*\\)$',
      );
      const m = callRe.exec(p);
      if (!m) return null;
      const rawIdx = m[1].startsWith('0x') ? parseInt(m[1], 16) : parseInt(m[1], 10);
      if (!Number.isFinite(rawIdx)) return null;
      const realIdx = rawIdx - indexerOffset;
      if (realIdx < 0 || realIdx >= arr.length) return null;
      out += arr[realIdx];
      if (out.length > MAX_RESOLVED_LEN) return null;
    }
    return out;
  }

  /** Walk forward from an open paren and return the index of the matching
   *  close paren (or -1 on unbalanced / pathological-length input). The
   *  cap prevents quadratic-cost fallback on deliberately malformed
   *  source. */
  function _findMatchingParen(src, openIdx) {
    let depth = 1;
    let inSingle = false, inDouble = false, inBack = false;
    const cap = Math.min(src.length, openIdx + MAX_SINK_ARG_LEN);
    for (let i = openIdx + 1; i < cap; i++) {
      const c = src[i];
      if (inSingle) { if (c === '\\' && i + 1 < src.length) i++; else if (c === "'") inSingle = false; continue; }
      if (inDouble) { if (c === '\\' && i + 1 < src.length) i++; else if (c === '"') inDouble = false; continue; }
      if (inBack)   { if (c === '\\' && i + 1 < src.length) i++; else if (c === '`') inBack = false; continue; }
      if (c === "'")  { inSingle = true; continue; }
      if (c === '"')  { inDouble = true; continue; }
      if (c === '`')  { inBack = true;   continue; }
      if (c === '(') depth++;
      else if (c === ')') {
        depth--;
        if (depth === 0) return i;
      }
    }
    return -1;
  }

  /** Trigger gate. Returns true when the source span is plausibly the
   *  string-array obfuscator shape — used by the finder to bail before
   *  paying full parse cost on JS that doesn't match. False positives
   *  here are cheap (an extra parse), false negatives are expensive (we
   *  miss the deobfuscation), so the gate errs on inclusion. */
  function _looksLikeStringArrayObfuscation(text) {
    if (!text || text.length < 50) return false;
    // Must contain at least one array-assign + one indexer-shaped function.
    if (!/\b(?:var|let|const)\s+[A-Za-z_$][\w$]*\s*=\s*\[/.test(text)) return false;
    if (!/\bfunction\s+[A-Za-z_$][\w$]*\s*\([^)]*\)\s*\{[\s\S]{0,512}?return\s+[A-Za-z_$][\w$]*\s*\[/.test(text)) return false;
    // Must contain at least one sink call.
    SINK_RE.lastIndex = 0;
    if (!SINK_RE.test(text)) return false;
    return true;
  }

  Object.assign(EncodedContentDetector.prototype, {

    /**
     * Find JS string-array obfuscation candidates whose sink-call payload
     * resolves via a one-pass evaluator. Emits `cmd-obfuscation` candidates
     * that `_processCommandObfuscation` promotes to findings (so severity,
     * IOC extraction, and the deobfuscated-command sidebar shape are all
     * inherited from the existing pipeline — see the candidate shape used
     * by `_findCommandObfuscationCandidates` and friends).
     */
    _findJsStringArrayCandidates(text, _context) {
      if (!text || text.length > MAX_SOURCE_BYTES) return [];
      if (!_looksLikeStringArrayObfuscation(text)) return [];

      const candidates = [];
      let arrayName = null;
      let arrayBody = null;
      let arrayBodyStart = -1;
      let arrayBodyEnd   = -1;

      // ── Pass 1: locate the string-array literal. First-array-wins.
      // A second array assignment with a different name elsewhere in the
      // file is left unresolved; supporting multi-array shapes requires
      // proper scope tracking which is well beyond this pure tokeniser.
      ARRAY_ASSIGN_RE.lastIndex = 0;
      let am;
      while ((am = ARRAY_ASSIGN_RE.exec(text)) !== null) {
        throwIfAborted();
        const name = am[1];
        const body = am[2];
        const arr = _parseStringArrayBody(body);
        if (!arr) continue;
        // Apply the trigger gate to the resolved array, not the raw body
        // — otherwise a 2-element array of base64 blobs would slip past
        // the `≥10 entries` check on raw byte count alone.
        const distinct = new Set(arr).size;
        const b64Count = arr.filter(_looksLikeBase64).length;
        if (distinct < MIN_ENTRIES && b64Count < MIN_BASE64_LOOKING) continue;
        arrayName = name;
        arrayBody = arr;
        arrayBodyStart = am.index;
        arrayBodyEnd   = am.index + am[0].length;
        break;
      }
      if (!arrayName) return [];

      // ── Pass 2: locate the indexer function that returns `arr[…]`.
      INDEXER_RE.lastIndex = 0;
      let indexerName = null;
      let indexerOffset = 0;
      let im;
      while ((im = INDEXER_RE.exec(text)) !== null) {
        throwIfAborted();
        const fnName = im[1];
        const refArr = im[2];
        const expr   = im[3];
        if (refArr !== arrayName) continue;
        const parsed = _parseIndexerExpr(expr);
        if (!parsed) continue;
        if (parsed.varName === arrayName) continue; // would be `arr[arr]`, opaque
        indexerName = fnName;
        indexerOffset = parsed.offset;
        break;
      }
      if (!indexerName) return [];

      // ── Pass 3: scan for sink calls whose first argument resolves.
      SINK_RE.lastIndex = 0;
      let sm;
      while ((sm = SINK_RE.exec(text)) !== null) {
        throwIfAborted();
        if (candidates.length >= this.maxCandidatesPerType) break;

        const sinkName = sm[1];
        // The match consumed the open paren; sm.index points at the
        // start of the (possibly preceding) non-word char or string
        // start. The actual `(` is the last char of the match.
        const openParen = sm.index + sm[0].length - 1;
        const closeParen = _findMatchingParen(text, openParen);
        if (closeParen < 0) continue;

        // Skip sinks that fall inside the array literal body (which
        // would be a literal `eval` string, not a real call). The
        // outer-most parens position is what counts.
        if (openParen >= arrayBodyStart && openParen < arrayBodyEnd) continue;

        const argSpan = text.substring(openParen + 1, closeParen);
        // setTimeout / setInterval take a second arg (the delay). Only
        // the first arg matters for resolution; split on top-level `,`.
        const firstArg = (sinkName === 'setTimeout' || sinkName === 'setInterval')
          ? _splitTopLevelComma(argSpan)
          : argSpan;
        if (!firstArg || !firstArg.trim()) continue;

        let resolved;
        try {
          resolved = _resolveConcat(firstArg, indexerName, indexerOffset, arrayBody);
        } catch (_) { resolved = null; }
        if (!resolved || resolved.length < 3) continue;

        // Emit the cmd-obfuscation candidate. The technique label drives
        // the chain pill in the sidebar; the deobfuscated string drives
        // severity scoring inside `_processCommandObfuscation`.
        const rawStart = sm.index + (sm[0].startsWith(sinkName) ? 0 : sm[0].indexOf(sinkName));
        const rawEnd   = closeParen + 1;
        candidates.push({
          type:        'cmd-obfuscation',
          technique:   'JS String-Array Resolution',
          raw:         text.substring(rawStart, rawEnd),
          offset:      rawStart,
          length:      rawEnd - rawStart,
          deobfuscated: sinkName + '(' + JSON.stringify(resolved) + ')',
        });
      }

      return candidates;
    },

    // ── Three additional JS-obfuscation resolvers ──
    //
    // These three methods extend js-assembly.js with the most common JS
    // obfuscator shapes that don't fit the string-array layout above:
    //
    //   1. Dean Edwards p.a.c.k.e.r (`packer.js`) — the `eval(function(p,a,c,k,e,d)…)`
    //      idiom that's been around since 2004 and is still the dominant
    //      delivery shape for jQuery / WordPress-pwn JS droppers.
    //   2. aaencode / jjencode — Yosuke Hasegawa's pure-symbol JS encoders.
    //      Detection-only (we surface the carrier; full decode requires
    //      executing the script in a sandbox, which we won't do).
    //   3. Function('...')() / new Function(atob('…'))() — the canonical
    //      "code in a string" carrier. We surface the inner code source
    //      when it's a static string literal or `atob(literal)` call.
    //
    // Each emits the same `cmd-obfuscation` candidate shape consumed by
    // `_processCommandObfuscation` in cmd-obfuscation.js — same severity
    // scoring, IOC mirroring, and `_executeOutput` escalation used by the
    // sister bash / python / php finders.

    /**
     * Find Dean Edwards p.a.c.k.e.r-style payloads. The carrier shape is
     * fixed:
     *
     *   eval(function(p,a,c,k,e,d){…return p}('<PAYLOAD>',<A>,<C>,'<K>'.split('|'),0,{}))
     *
     * `<A>` is the radix used to map dictionary indices in the payload
     * (commonly 36 or 62), `<C>` is the dictionary length, and `<K>` is
     * a `|`-separated list of identifiers that replace `\bN\b` tokens
     * in the payload (where `N` is rendered in base-`<A>`). For a full
     * spec see <https://dean.edwards.name/packer/> — we re-implement the
     * decoder here statically (no eval).
     */
    _findJsPackerCandidates(text, _context) {
      if (!text || text.length < 60 || text.length > MAX_SOURCE_BYTES) return [];
      // Quick reject: every packer carrier contains the exact opening
      // `eval(function(p,a,c,k,e,d)` (whitespace-tolerant).
      if (!/eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/.test(text)) {
        return [];
      }
      const candidates = [];
      // Capture the four trailing arguments: '<PAYLOAD>',<A>,<C>,'<K>'.split('|'),0,{}
      // The full body inside `function(p,a,c,k,e,d){…}` is opaque and
      // varies between packer revisions; we only need the call-site args.
      // Quote-tolerant body classes: a `'`-quoted string can contain
      // unescaped `"` (and vice versa), so we capture the chosen quote
      // in a back-reference and exclude only it. Escaped chars (`\.`)
      // are also accepted so real dropper output with `\x27` / `\\` /
      // `\'` survives. The two args we want are PAYLOAD (m[2]) and
      // DICT (m[6]); they may use different quote styles.
      const callRe = /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)\s*\{[\s\S]{0,4096}?\}\s*\(\s*(['"])((?:(?!\1)[^\\]|\\.){2,1048576}?)\1\s*,\s*(\d{1,3})\s*,\s*(\d{1,5})\s*,\s*(['"])((?:(?!\5)[^\\\r\n]|\\.){0,524288})\5\s*\.\s*split\s*\(\s*(['"])\|\7\s*\)/g;
      let m;
      while ((m = callRe.exec(text)) !== null) {
        throwIfAborted();
        if (candidates.length >= this.maxCandidatesPerType) break;
        const payload = m[2];
        const radix = parseInt(m[3], 10);
        const dictLen = parseInt(m[4], 10);
        const dict = m[6].split('|');
        if (radix < 2 || radix > 62 || dict.length !== dictLen) continue;
        const decoded = _packerDecode(payload, radix, dict);
        if (!decoded || decoded.length < 4) continue;
        candidates.push({
          type: 'cmd-obfuscation',
          technique: 'JS p.a.c.k.e.r (Dean Edwards)',
          raw: m[0],
          offset: m.index,
          length: m[0].length,
          deobfuscated: decoded,
          _executeOutput: true,
        });
      }
      return candidates;
    },

    /**
     * Find aaencode / jjencode payloads. Both encode arbitrary JS into
     * pure-symbol strings (aaencode uses Japanese kaomoji, jjencode uses
     * a small alphabet of `[]{}()+!_`). We can't statically execute these
     * (they recover the source via JS-engine semantics), so this branch
     * is detection-only — we emit a candidate naming the carrier so the
     * post-processor can flag it `_executeOutput: true` (the construct
     * itself is the IOC).
     */
    _findJsAaJjEncodeCandidates(text, _context) {
      if (!text || text.length < 60 || text.length > MAX_SOURCE_BYTES) return [];
      const candidates = [];
      // aaencode signature: opens with `ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻` (or similar
      // kaomoji burst). The exact opening varies but every aaencode
      // dump contains a long run of dense Hangul/Greek/Cyrillic/halfwidth
      // chars followed by `(ﾟДﾟ)[ﾟεﾟ]+` style signature tokens. The
      // canonical aaencode token alphabet uses U+0370-U+03FF (Greek),
      // U+0400-U+04FF (Cyrillic), and U+30A0-U+30FF / U+FF00-U+FFEF
      // (katakana / halfwidth-fullwidth). We accept all four ranges so
      // a `(ﾟДﾟ)` token (where `Д` is Cyrillic and `ﾟ` is halfwidth)
      // matches.
      // The prefix-to-token gap may span newlines (real aaencode dumps
      // are typically a single very long line, but synthetic / pretty-
      // printed samples can split). Use `[\s\S]*?` instead of `.*?` so
      // the connector spans line breaks.
      const aaCharClass = '[\\u0370-\\u03FF\\u0400-\\u04FF\\u30A0-\\u30FF\\uFF00-\\uFFEF]';
      const aaSig = new RegExp(`${aaCharClass}{4,}[\\s\\S]{0,2048}?\\(\\s*${aaCharClass}+\\s*\\)`); /* safeRegex: builtin */
      if (aaSig.test(text)) {
        const m = aaSig.exec(text);
        if (m) {
          const start = Math.max(0, m.index - 20);
          const end = Math.min(text.length, m.index + 200);
          candidates.push({
            type: 'cmd-obfuscation',
            technique: 'JS aaencode (Hasegawa kaomoji obfuscation)',
            raw: text.slice(start, end),
            offset: start,
            length: end - start,
            deobfuscated: 'aaencode payload \u2014 statically opaque; sandbox required to recover JS',
            _executeOutput: true,
          });
        }
      }
      // jjencode signature: a single long line where >=80% of chars are
      // in the small jjencode alphabet (`[]{}()+!_/$.\\`) and the line
      // is ≥200 chars long. We also require the canonical opening
      // `<NAME>=~[]; <NAME>={…}` shape so a legitimate minified file
      // doesn't fire.
      const jjSig = /([A-Za-z_$][A-Za-z0-9_$]{0,40})\s*=\s*~\s*\[\s*\]\s*;\s*\1\s*=\s*\{/;
      const jm = jjSig.exec(text);
      if (jm) {
        // Confirm the dense-symbol ratio of the next ~500 chars to cut
        // FPs against minifier output that happens to start `x=~[];`.
        const window2 = text.slice(jm.index, Math.min(text.length, jm.index + 500));
        let symbol = 0;
        for (let i = 0; i < window2.length; i++) {
          const c = window2[i];
          if ('[]{}()+!_/$.\\'.indexOf(c) >= 0) symbol++;
        }
        if (symbol / window2.length > 0.4) {
          candidates.push({
            type: 'cmd-obfuscation',
            technique: 'JS jjencode (Hasegawa symbol-only obfuscation)',
            raw: window2.slice(0, 200),
            offset: jm.index,
            length: Math.min(200, window2.length),
            deobfuscated: 'jjencode payload \u2014 statically opaque; sandbox required to recover JS',
            _executeOutput: true,
          });
        }
      }
      return candidates;
    },

    /**
     * Find Function-wrapper carriers:
     *
     *   Function('return ' + atob('<B64>'))()
     *   (new Function(atob('<B64>')))()
     *   Function(unescape('%XX%XX…'))()
     *   Function.constructor('payload')()
     *
     * The inner code is what makes the construct dangerous — we surface
     * the cleartext when the wrapped expression is a static literal /
     * atob(literal) / unescape(literal) call. Anything more dynamic
     * (string-concat with a variable, indirect lookup) is flagged as
     * structural-only.
     */
    _findJsFunctionWrapperCandidates(text, _context) {
      if (!text || text.length < 16 || text.length > MAX_SOURCE_BYTES) return [];
      const candidates = [];
      // Function(atob('B64'))() / new Function(atob('B64'))()
      const fnAtobRe = /(?:new\s+)?Function\s*\(\s*(?:['"]return\s+['"]\s*\+\s*)?atob\s*\(\s*(['"])([A-Za-z0-9+/=\s]{8,524288})\1\s*\)\s*(?:\+\s*['"][^'"\r\n]{0,40}['"])?\s*\)\s*\(\s*\)/g;
      let m;
      while ((m = fnAtobRe.exec(text)) !== null) {
        throwIfAborted();
        if (candidates.length >= this.maxCandidatesPerType) break;
        const b64 = m[2].replace(/\s+/g, '');
        let decoded = '';
        try {
          if (typeof atob === 'function') decoded = atob(b64);
          /* eslint-disable-next-line no-undef */
          else decoded = Buffer.from(b64, 'base64').toString('binary');
        } catch (_) { continue; }
        if (decoded.length < 4) continue;
        candidates.push({
          type: 'cmd-obfuscation',
          technique: 'JS Function(atob(...))()',
          raw: m[0],
          offset: m.index,
          length: m[0].length,
          deobfuscated: decoded,
          _executeOutput: true,
        });
      }
      // Function(unescape('%XX%XX…'))()
      const fnUnescapeRe = /(?:new\s+)?Function\s*\(\s*unescape\s*\(\s*(['"])((?:%[0-9a-fA-F]{2}|[\w\-.~!*'();:@&=+$,/?#[\]]){8,8192})\1\s*\)\s*\)\s*\(\s*\)/g;
      while ((m = fnUnescapeRe.exec(text)) !== null) {
        throwIfAborted();
        if (candidates.length >= this.maxCandidatesPerType) break;
        let decoded = '';
        try { decoded = decodeURIComponent(m[2]); }
        catch (_) {
          // legacy unescape() falls back to %uXXXX → BMP codepoint
          decoded = m[2].replace(/%([0-9a-fA-F]{2})/g, (_full, h) => String.fromCharCode(parseInt(h, 16)));
        }
        if (decoded.length < 4) continue;
        candidates.push({
          type: 'cmd-obfuscation',
          technique: 'JS Function(unescape(...))()',
          raw: m[0],
          offset: m.index,
          length: m[0].length,
          deobfuscated: decoded,
          _executeOutput: true,
        });
      }
      // Function.constructor('payload')() / Function.prototype.constructor.call(...)
      const fnConstructorRe = /\b(?:Function|[A-Za-z_$]\w{0,40})\s*(?:\.\s*(?:prototype\s*\.\s*)?constructor)\s*\(\s*(['"])([^'"\r\n]{4,4096})\1\s*\)\s*(?:\.\s*call\s*\([^)]{0,80}\)|\(\s*\))/g;
      while ((m = fnConstructorRe.exec(text)) !== null) {
        throwIfAborted();
        if (candidates.length >= this.maxCandidatesPerType) break;
        const payload = m[2];
        if (payload.length < 4) continue;
        candidates.push({
          type: 'cmd-obfuscation',
          technique: 'JS Function.constructor RCE',
          raw: m[0],
          offset: m.index,
          length: m[0].length,
          deobfuscated: payload,
          _executeOutput: true,
        });
      }
      return candidates;
    },
  });

  // ── packer.js static decoder ─────────────────────────────────────────────
  //
  // Re-implements Dean Edwards' p.a.c.k.e.r unpacker statically: every
  // dictionary index `i` (0 ≤ i < dict.length) is rendered into base-`radix`
  // and any whole-word match in the payload is substituted with `dict[i]`
  // (when `dict[i]` is non-empty; otherwise the token is preserved). Mirrors
  // the original packer.js v3 unpacker:
  //   while (c--) if (k[c]) p = p.replace(new RegExp('\\b'+e(c)+'\\b','g'), k[c]);
  //
  // We use an O(n) reverse-scan of the payload instead of `replace` per
  // index because the worst-case dict size is ~10000 and the regex-per-
  // index loop would become O(n*k). The walk classifies each char as
  // identifier-vs-non-identifier and substitutes whole tokens when the
  // token's base-radix interpretation is < dict.length AND dict[idx] is
  // non-empty.
  function _packerDecode(payload, radix, dict) {
    const isIdent = c => (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c === '_' || c === '$';
    let out = '';
    let i = 0;
    while (i < payload.length) {
      const c = payload[i];
      if (!isIdent(c)) { out += c; i++; continue; }
      // Read the whole identifier token
      let j = i;
      while (j < payload.length && isIdent(payload[j])) j++;
      const tok = payload.slice(i, j);
      // Try interpreting tok as base-`radix` integer. If invalid (any
      // char outside the radix's digit set), preserve verbatim.
      const idx = _parseRadixInt(tok, radix);
      if (idx >= 0 && idx < dict.length && dict[idx] && dict[idx].length > 0) {
        out += dict[idx];
      } else {
        out += tok;
      }
      i = j;
    }
    return out;
  }

  // Parse `s` as a base-`radix` integer (0 ≤ radix ≤ 62). Lowercase
  // letters represent digits 10..35 and uppercase letters represent
  // 36..61 — packer.js's `e()` function uses the same convention. Returns
  // -1 if any character is out of range.
  function _parseRadixInt(s, radix) {
    if (!s) return -1;
    let n = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      let d = -1;
      if (c >= 48 && c <= 57) d = c - 48;          // '0'..'9'
      else if (c >= 97 && c <= 122) d = c - 87;    // 'a'..'z' → 10..35
      else if (c >= 65 && c <= 90) d = c - 29;     // 'A'..'Z' → 36..61
      if (d < 0 || d >= radix) return -1;
      n = n * radix + d;
      if (n > Number.MAX_SAFE_INTEGER) return -1;
    }
    return n;
  }

  // Top-level `,` splitter — matches the `setTimeout(<expr>, <ms>)` shape.
  // Hoisted out of the closure for unit-test reachability via the
  // detector's `_findJsStringArrayCandidates` path. (Not exposed on the
  // prototype because there's no good reason for the rest of the codebase
  // to call it.)
  function _splitTopLevelComma(src) {
    let inSingle = false, inDouble = false, inBack = false;
    let depth = 0;
    for (let i = 0; i < src.length; i++) {
      const c = src[i];
      if (inSingle) { if (c === '\\' && i + 1 < src.length) i++; else if (c === "'") inSingle = false; continue; }
      if (inDouble) { if (c === '\\' && i + 1 < src.length) i++; else if (c === '"') inDouble = false; continue; }
      if (inBack)   { if (c === '\\' && i + 1 < src.length) i++; else if (c === '`') inBack = false; continue; }
      if (c === "'")  { inSingle = true; continue; }
      if (c === '"')  { inDouble = true; continue; }
      if (c === '`')  { inBack = true;   continue; }
      if (c === '(' || c === '{' || c === '[') { depth++; continue; }
      if (c === ')' || c === '}' || c === ']') { depth = Math.max(0, depth - 1); continue; }
      if (depth === 0 && c === ',') return src.substring(0, i);
    }
    return src;
  }

})();
