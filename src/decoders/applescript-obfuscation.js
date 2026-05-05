// ════════════════════════════════════════════════════════════════════════════
// applescript-obfuscation.js — AppleScript / JXA char-code reassembly
// decoder with cross-reference resolution. Mirrors the candidate-
// emission contract of cmd-obfuscation.js / bash-obfuscation.js /
// python-obfuscation.js so every candidate flows through the shared
// `_processCommandObfuscation` post-processor (severity tier + IOC
// extraction + _executeOutput escalation).
//
// Real-world AppleScript droppers build their `do shell script`
// argument out of fragments distributed across dozens of
// `property _randomName : <chain>` / `set _randomName to <chain>`
// bindings. Each chain in isolation resolves to an innocuous-looking
// fragment (a hex token, a URL path element, a User-Agent substring);
// only when the `do shell script` call-site concatenates the named
// properties together does the final malicious command appear. A
// per-chain keyword gate that demands `curl` / `bash` / `do shell
// script` in every reassembled value would therefore reject every
// fragment and never surface the attack.
//
// This module runs a TWO-PASS decoder:
//
//   Pass 1 — Binding collection
//     Scan the file for `property <name> : <rhs>` / `set <name> to
//     <rhs>` / `global <name> : <rhs>` / `local <name> : <rhs>`
//     declarations. For each, parse <rhs> as an AppleScript
//     expression whose operands are any combination of:
//       - char-code primitives (ASCII character N / character id N /
//         string id {N, N, …})
//       - double-quoted string literals
//       - identifier references to other declared names
//     Record bindings in a `Map<name, record>` with resolved-value,
//     kind, offset, and outgoing-reference set.
//
//   Pass 2 — Fixed-point resolution
//     Iterate over the binding map (max 8 rounds). Each round, for
//     every partially-resolved binding, substitute any referenced
//     name whose value is already fully resolved. Break when no
//     substitution happened in a round (converged) or when the round
//     cap is hit (circular / too-deep references). Bindings that
//     remain unresolved surface with `⟨_NAME⟩` placeholders so the
//     analyst can see the structure.
//
// Then scan the file for `do shell script <expr>` sinks and resolve
// <expr> using the binding map — the reassembled command is what
// the existing vocabulary-based YARA rules in
// `src/rules/osascript-threats.yar` key on.
//
// Three candidate shapes emit:
//   - `AppleScript Binding Reassembly`     one per resolved
//                                           property/set/local/global
//   - `AppleScript Reassembled Shell Command`  one per `do shell script`
//                                               sink, full cleartext
//   - `AppleScript Codepoint Array` / `AppleScript Char-Code Reassembly`
//                                           anon (unbound) chains and
//                                           standalone `string id {…}`
//                                           literals — legacy AS1/AS2
//                                           branches, preserved for
//                                           files that use char-code
//                                           obfuscation without binding
//                                           declarations.
//
// Amp budget: per-binding resolved value ≤ 64 KiB; aggregate resolved
// text across all bindings ≤ 1 MiB; per-candidate deobfuscated output
// clipped via the shared `_clipDeobfToAmpBudget` (8 KiB / 32× raw
// length). These bounds are load-bearing — adversarial input can in
// principle build an arbitrarily long string from cross-referenced
// bindings, and without these caps the resolution pass would burn CPU
// or heap memory on obvious DoS shapes.
//
// File-level plausibility gate (Scope A): the finder is a no-op unless
// the file looks like AppleScript / JXA with real signals. We require
// one of: an actual `do shell script` call-site, ≥ 2 randomised
// `property _XXXXXX :` bindings, ≥ 3 char-code primitive operators,
// or classic AppleScript surface (`tell application`, `on run`,
// `quoted form of`, `administrator privileges`). Benign
// internationalised AppleScript that uses `(character id 233)` for a
// single `é` will hit none of these and return zero candidates.
//
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
// `scripts/build.py` _DETECTOR_FILES loads this AFTER cmd-obfuscation.js
// (consumes `_processCommandObfuscation` at scan time, not at load
// time, so load order relative to the bash/python/php decoders is free).
// ════════════════════════════════════════════════════════════════════════════

// Per-chain hard caps. Pathological AppleScript can build an
// arbitrary-length string via thousands of `&`-concatenated nodes; we
// bound the regex alternation count plus the resolved string length
// so the finder can't burn CPU or memory on adversarial input.
//   MAX_CHAIN_NODES  — number of operands (codepoints / string-id / literal
//                      / identifier-ref) allowed in one chain.
//   MAX_STRID_CODES  — maximum codepoints inside a single `string id {…}`
//                      literal.
//   MAX_RESOLVED_LEN — maximum post-decode string length BEFORE the amp
//                      budget clip. Hard ceiling so even a pathological
//                      chain of 2048 `string id {4096 codes}` entries
//                      can't materialize an 8 MB string in one pass.
//   MAX_BINDINGS     — maximum number of distinct name bindings per
//                      file. Beyond this we stop recording; remaining
//                      chains still surface as anonymous AS1/AS2 hits.
//   MAX_AGGREGATE_RESOLVED — total bytes of resolved binding text
//                      allowed per file. Guard against reference-
//                      explosion bombs where 512 bindings each hold
//                      all-others concatenated.
//   MAX_RESOLUTION_ROUNDS — fixed-point iteration cap. 8 rounds
//                      comfortably resolves 6-level reference chains
//                      (seen in the wild) while bounding CPU.
//   MAX_SHELL_SINKS  — per-file cap on `do shell script` reassemblies.
const _AS_MAX_CHAIN_NODES = 2048;
const _AS_MAX_STRID_CODES = 4096;
const _AS_MAX_RESOLVED_LEN = 64 * 1024;
const _AS_MAX_BINDINGS = 512;
const _AS_MAX_AGGREGATE_RESOLVED = 1024 * 1024;
const _AS_MAX_RESOLUTION_ROUNDS = 8;
const _AS_MAX_SHELL_SINKS = 64;

// Tier A / loop-expansion caps. `_lhfMIBr93U : {chain1, chain2, chain3}`
// style list bindings are enumerated for `repeat with x in <list>` loop
// iterators. Cap the number of list elements we'll accept AND the
// cross-product of loop variants we emit per sink so adversarial input
// can't balloon our candidate output.
const _AS_MAX_LIST_ELEMENTS = 16;
const _AS_MAX_LOOP_VARIANTS = 8;

// AppleScript runtime-accessor keywords. If any of these appear on the
// RHS of a handler-local `set X to <rhs>`, we refuse to collect X as
// a resolvable binding — the value is genuinely dynamic and collecting
// it would emit `⟨unresolved⟩`-riddled partial reassemblies that
// mislead the analyst about completeness. Top-level `set`s still
// collect unconditionally because they don't reference loop iterators
// or handler-arg state. The list is deliberately conservative — we'd
// rather miss a binding than poison the map.
//
// Covered: `contents of X`, `count of L`, `item N of L`, `first…of`,
// `last…of`, `every…of`, `value of`, `result`, `return value of`,
// `do shell script` on RHS, `call method`, `current application`,
// `system info`, `POSIX file`, plus the `<expr> of <expr>` / `<expr>'s`
// possessive accessors which are idiomatic AS property traversal.
/* safeRegex: builtin */
const _AS_RUNTIME_ACCESSOR_RE =
  /\b(?:contents\s+of|count\s+of|item\s+\d+\s+of|first\s+\w+\s+of|last\s+\w+\s+of|every\s+\w+\s+of|value\s+of|result|return\s+value\s+of|call\s+method|current\s+application|system\s+info|POSIX\s+file|do\s+shell\s+script)\b/i;

// File-level plausibility gate. Returns true if the input text looks
// like AppleScript / JXA with enough structural signals that surfacing
// char-code reassembly is worth the analyst's attention. Without this
// gate, any file containing two `(character id N)` tokens for locale
// diacritics would light up the sidebar with Deobfuscated Layers rows.
function _isAppleScriptPlausibleContext(text) {
  if (typeof text !== 'string' || text.length < 16) return false;
  // Strong signal: any `do shell script` call-site.
  if (/\bdo\s+shell\s+script\b/i.test(text)) return true;
  // Strong signal: ≥ 2 randomised-looking property declarations.
  let propCount = 0;
  /* safeRegex: builtin */
  const propRe = /\bproperty\s+_[A-Za-z0-9]{5,}\s*:/gi;
  let m;
  while ((m = propRe.exec(text)) !== null) {
    if (++propCount >= 2) return true;
    if (propCount > 64) break; // pathological guard
  }
  // Strong signal: ≥ 3 distinct char-code primitive operators. Counted
  // across the three primitive shapes together.
  let primCount = 0;
  /* safeRegex: builtin */
  const primRe = /\(\s*(?:ASCII\s+character|character\s+id)\s+\d{1,6}\s*\)|\bstring\s+id\s*\{\s*\d/gi;
  while ((m = primRe.exec(text)) !== null) {
    if (++primCount >= 3) return true;
    if (primCount > 256) break;
  }
  // Classic AppleScript surface.
  if (/\btell\s+application\b/i.test(text)) return true;
  if (/\bon\s+run\b/i.test(text)) return true;
  if (/\bquoted\s+form\s+of\b/i.test(text)) return true;
  if (/\badministrator\s+privileges\b/i.test(text)) return true;
  return false;
}

// Codepoint-sanity check shared by `ASCII character N`, `character id N`,
// and `string id {…}` members. AppleScript's `ASCII character N` is
// defined for 0..255 but we accept the full Unicode range because
// `character id` is explicitly a Unicode codepoint and many compilers
// silently fold `ASCII character 200` to its MacRoman equivalent
// rather than failing.
function _asSafeCodepoint(n) {
  return Number.isFinite(n) && n >= 0 && n <= 0x10FFFF;
}

// Decode a whitespace-tolerant comma-separated integer list into an
// array of sanitised codepoints. Returns null on any malformed entry.
function _asParseCodepointList(body) {
  if (typeof body !== 'string' || body.length === 0) return null;
  const parts = body.split(',');
  if (parts.length < 1 || parts.length > _AS_MAX_STRID_CODES) return null;
  const out = [];
  for (const p of parts) {
    const t = p.trim();
    if (!/^\d{1,6}$/.test(t)) return null;
    const n = parseInt(t, 10);
    if (!_asSafeCodepoint(n)) return null;
    out.push(n);
  }
  return out;
}

// Split an AppleScript list-literal body on top-level commas, honouring
// nested parens / braces / string literals. Input is the body BETWEEN
// the outer `{` and `}` (already stripped by caller). Returns an array
// of raw substrings — one per element — preserving element ordering.
// Returns null on malformed input (unbalanced parens / unterminated
// strings). Caller is responsible for calling `_asTokeniseExpression`
// on each element.
function _asSplitListElements(body) {
  if (typeof body !== 'string' || body.length === 0) return null;
  const out = [];
  let depthParen = 0;
  let depthBrace = 0;
  let start = 0;
  let i = 0;
  const len = body.length;
  while (i < len) {
    const c = body[i];
    if (c === '"') {
      // Skip over string literal honouring `\"` / `\\` escapes.
      i++;
      while (i < len) {
        if (body[i] === '\\' && i + 1 < len) { i += 2; continue; }
        if (body[i] === '"') { i++; break; }
        i++;
      }
      continue;
    }
    if (c === '(') { depthParen++; i++; continue; }
    if (c === ')') { depthParen--; if (depthParen < 0) return null; i++; continue; }
    if (c === '{') { depthBrace++; i++; continue; }
    if (c === '}') { depthBrace--; if (depthBrace < 0) return null; i++; continue; }
    if (c === ',' && depthParen === 0 && depthBrace === 0) {
      out.push(body.slice(start, i));
      i++;
      start = i;
      if (out.length > _AS_MAX_LIST_ELEMENTS) return null;
      continue;
    }
    i++;
  }
  if (depthParen !== 0 || depthBrace !== 0) return null;
  out.push(body.slice(start, i));
  return out;
}

// Dequote an AppleScript double-quoted string literal. AppleScript
// uses `\"` / `\\` inside strings plus `\n`, `\r`, `\t`; other `\X`
// escapes pass through as X (matches Script Editor behaviour).
function _asDequoteStringLiteral(s) {
  if (typeof s !== 'string' || s.length < 2) return null;
  if (s[0] !== '"' || s[s.length - 1] !== '"') return null;
  const body = s.slice(1, -1);
  let out = '';
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch !== '\\') { out += ch; continue; }
    if (i + 1 >= body.length) { out += '\\'; break; }
    const nx = body[i + 1];
    if (nx === 'n') { out += '\n'; i++; continue; }
    if (nx === 'r') { out += '\r'; i++; continue; }
    if (nx === 't') { out += '\t'; i++; continue; }
    out += nx;
    i++;
  }
  return out;
}

// Tokenise an AppleScript expression into a flat operand list. Each
// operand is one of:
//   { kind: 'primitive', raw, value }       — resolved codepoint string
//   { kind: 'literal',   raw, value }       — resolved dequoted string
//   { kind: 'ref',       raw, name }        — identifier reference
//   { kind: 'unknown',   raw }               — unparseable token
//
// The walker splits on top-level `&` respecting:
//   - `"…"` double-quoted strings (with `\"` / `\\` escapes)
//   - `(…)` parenthesised groups (tracked as depth 1)
//   - `{…}` braced codepoint arrays (tracked as nested depth)
//
// Returns `null` if the input is structurally malformed (unbalanced
// parens / quotes) or exceeds MAX_CHAIN_NODES. Returns `[]` on empty
// expression.
//
// Used by BOTH Pass 1 (binding RHS parse) and Pass 2 (shell-sink
// argument parse), so identifier references are the central abstraction
// that lets cross-reference resolution work.
function _asTokeniseExpression(raw) {
  if (typeof raw !== 'string') return null;
  const operands = [];
  let i = 0;
  const len = raw.length;

  while (i < len) {
    // Skip whitespace and `&` separators. Also tolerate leading `(`
    // wrapper at top level — the walker strips any redundant outer
    // parens per operand below.
    while (i < len && (raw[i] === ' ' || raw[i] === '\t' || raw[i] === '\r' || raw[i] === '\n' || raw[i] === '&')) i++;
    if (i >= len) break;
    if (operands.length >= _AS_MAX_CHAIN_NODES) return null;

    const start = i;

    if (raw[i] === '"') {
      // String literal. Consume up to matching close-quote, honouring
      // `\"` / `\\` escapes.
      i++;
      while (i < len) {
        if (raw[i] === '\\' && i + 1 < len) { i += 2; continue; }
        if (raw[i] === '"') { i++; break; }
        i++;
      }
      const tok = raw.slice(start, i);
      const val = _asDequoteStringLiteral(tok);
      if (val === null) return null;
      operands.push({ kind: 'literal', raw: tok, value: val });
      continue;
    }

    if (raw[i] === '(' || raw[i] === '{') {
      // Parenthesised / braced group. Track nesting to find matching
      // close. Then re-parse inner content as a primitive or — if
      // recursive parentheses — fall back to scanning for primitive.
      //
      // Must be STRING-AWARE: `"(M"` inside a group would otherwise
      // corrupt the depth stack because the `(` lives inside a string
      // literal. Walk the group body with inline quote-tracking.
      const openers = { '(': ')', '{': '}' };
      const stack = [openers[raw[i]]];
      i++;
      while (i < len && stack.length > 0) {
        const c = raw[i];
        if (c === '"') {
          // Skip over string literal honouring `\"` / `\\` escapes.
          i++;
          while (i < len) {
            if (raw[i] === '\\' && i + 1 < len) { i += 2; continue; }
            if (raw[i] === '"') { i++; break; }
            i++;
          }
          continue;
        }
        if (c === '(' || c === '{') stack.push(openers[c]);
        else if (c === stack[stack.length - 1]) stack.pop();
        i++;
      }
      if (stack.length !== 0) return null; // unbalanced
      const tok = raw.slice(start, i);
      const inner = _asClassifyPrimitiveBody(tok);
      if (inner && inner.kind === 'primitive') {
        operands.push({ kind: 'primitive', raw: tok, value: inner.value });
      } else if (inner && inner.kind === 'list_literal') {
        // AppleScript list literal `{e1, e2, e3}` — pre-parsed into
        // per-element operand arrays by the classifier. Used by Tier
        // A loop-iterator expansion so `repeat with x in <listRef>`
        // can enumerate concrete values.
        operands.push({ kind: 'list_literal', raw: tok, elements: inner.elements });
      } else if (inner && inner.kind === 'expression') {
        // Nested `& …`: recurse into the inner expression (strip one
        // level of outer parens) and flatten the results into the
        // current operand list.
        const nested = _asTokeniseExpression(tok.slice(1, -1));
        if (nested === null) return null;
        for (const op of nested) {
          if (operands.length >= _AS_MAX_CHAIN_NODES) return null;
          operands.push(op);
        }
      } else {
        operands.push({ kind: 'unknown', raw: tok });
      }
      continue;
    }

    // Bare identifier, keyword, or unknown. Consume to next top-level
    // separator (`&` / whitespace terminating on a `&` or EOL).
    if (/[A-Za-z_]/.test(raw[i])) {
      // Multi-token unary operator: `quoted form of <primary-expr>`.
      // AppleScript's `quoted form of X` POSIX-quotes X for shell use.
      // Treating `quoted`, `form`, `of` as three separate identifiers
      // would emit three unresolved-ref placeholders and obscure the
      // shell-arg wrapper. Instead we consume the three keywords + the
      // next primary expression and emit a single `quoted_form_of`
      // operand whose resolver applies POSIX quoting.
      const qfm = /^quoted\s+form\s+of\s+/i.exec(raw.slice(i));
      if (qfm) {
        const afterKw = i + qfm[0].length;
        // Parse the next primary expression: `(…)`, `{…}`, `"…"`, or
        // a bare identifier. We do NOT recursively parse `&`-chains
        // here — `quoted form of` binds tighter than `&`.
        let j = afterKw;
        let operand = null;
        if (j < len && (raw[j] === '(' || raw[j] === '{')) {
          const openers = { '(': ')', '{': '}' };
          const stack2 = [openers[raw[j]]];
          const opStart = j;
          j++;
          while (j < len && stack2.length > 0) {
            const c = raw[j];
            if (c === '"') {
              j++;
              while (j < len) {
                if (raw[j] === '\\' && j + 1 < len) { j += 2; continue; }
                if (raw[j] === '"') { j++; break; }
                j++;
              }
              continue;
            }
            if (c === '(' || c === '{') stack2.push(openers[c]);
            else if (c === stack2[stack2.length - 1]) stack2.pop();
            j++;
          }
          if (stack2.length !== 0) return null;
          const tok = raw.slice(opStart, j);
          const inner = _asClassifyPrimitiveBody(tok);
          if (inner && inner.kind === 'primitive') {
            operand = { kind: 'primitive', raw: tok, value: inner.value };
          } else if (inner && inner.kind === 'expression') {
            // Nested expression — tokenise its body and wrap as a
            // single synthetic operand whose resolver concatenates
            // its sub-operands. We model this as nested resolution by
            // stashing the operand list and a sentinel kind.
            const nested = _asTokeniseExpression(tok.slice(1, -1));
            if (nested === null) return null;
            operand = { kind: 'group', raw: tok, operands: nested };
          } else {
            operand = { kind: 'unknown', raw: tok };
          }
        } else if (j < len && raw[j] === '"') {
          const strStart = j;
          j++;
          while (j < len) {
            if (raw[j] === '\\' && j + 1 < len) { j += 2; continue; }
            if (raw[j] === '"') { j++; break; }
            j++;
          }
          const tok = raw.slice(strStart, j);
          const val = _asDequoteStringLiteral(tok);
          if (val === null) return null;
          operand = { kind: 'literal', raw: tok, value: val };
        } else if (j < len && /[A-Za-z_]/.test(raw[j])) {
          const idMatch = /^[_A-Za-z][A-Za-z0-9_]{0,63}/.exec(raw.slice(j));
          if (idMatch) {
            operand = { kind: 'ref', raw: idMatch[0], name: idMatch[0] };
            j += idMatch[0].length;
          }
        }
        if (operand) {
          operands.push({ kind: 'quoted_form_of', raw: raw.slice(i, j), operand });
          i = j;
          continue;
        }
        // Fall through to ordinary identifier parse if we couldn't
        // find a valid operand (shouldn't happen in well-formed input).
      }

      // Try three keyword-prefixed shapes without outer parens:
      //   `string id {…}` — AS2-style bare literal
      //   `ASCII character N` — bare primitive
      //   `character id N` — bare primitive
      const slice = raw.slice(i);
      let mm;
      if ((mm = /^string\s+id\s*\{[^}]{1,32768}\}/i.exec(slice))) {
        const body = /\{([^}]{1,32768})\}/.exec(mm[0])[1];
        const codes = _asParseCodepointList(body);
        if (!codes) return null;
        try {
          operands.push({ kind: 'primitive', raw: mm[0], value: String.fromCodePoint(...codes) });
        } catch (_) { return null; }
        i += mm[0].length;
        continue;
      }
      if ((mm = /^ASCII\s+character\s+\d{1,6}/i.exec(slice))) {
        const n = parseInt(/\d{1,6}/.exec(mm[0])[0], 10);
        if (!_asSafeCodepoint(n)) return null;
        try {
          operands.push({ kind: 'primitive', raw: mm[0], value: String.fromCodePoint(n) });
        } catch (_) { return null; }
        i += mm[0].length;
        continue;
      }
      if ((mm = /^character\s+id\s+\d{1,6}/i.exec(slice))) {
        const n = parseInt(/\d{1,6}/.exec(mm[0])[0], 10);
        if (!_asSafeCodepoint(n)) return null;
        try {
          operands.push({ kind: 'primitive', raw: mm[0], value: String.fromCodePoint(n) });
        } catch (_) { return null; }
        i += mm[0].length;
        continue;
      }
      // Identifier reference. Allow leading `_` and up to 63 chars.
      const idMatch = /^[_A-Za-z][A-Za-z0-9_]{0,63}/.exec(slice);
      if (idMatch) {
        const name = idMatch[0];
        // Reject AppleScript keywords that shouldn't be treated as refs.
        // We still allow them through as 'unknown' so the expression
        // parse succeeds, but the binding lookup will miss them.
        const keywordBlocklist = /^(?:of|to|in|with|without|the|a|an|and|or|not|as|if|then|else|return|set|get|tell|end|on|property|global|local|true|false|it|me|my|where|whose|from|into|it|ref|through|thru|considering|ignoring|until|while|repeat)$/i;
        if (keywordBlocklist.test(name)) {
          operands.push({ kind: 'unknown', raw: name });
        } else {
          operands.push({ kind: 'ref', raw: name, name });
        }
        i += name.length;
        continue;
      }
      // Unknown alphabetic token — eat until next separator to avoid
      // an infinite loop, record as unknown.
      let j = i;
      while (j < len && raw[j] !== '&' && raw[j] !== ' ' && raw[j] !== '\t' && raw[j] !== '\r' && raw[j] !== '\n' && raw[j] !== '(' && raw[j] !== '{' && raw[j] !== '"') j++;
      operands.push({ kind: 'unknown', raw: raw.slice(i, j) });
      i = j;
      continue;
    }

    // Any other char at top level — bail.
    return null;
  }

  return operands;
}

// Classify a parenthesised/braced body as either a primitive operand
// (returns `{kind:'primitive', value}`) or a nested expression that
// needs re-tokenisation (returns `{kind:'expression'}`). `raw` is the
// full `(…)` or `{…}` slice INCLUDING the outer delimiters.
function _asClassifyPrimitiveBody(raw) {
  if (typeof raw !== 'string' || raw.length < 2) return null;
  const outerOpen = raw[0];
  const outerClose = raw[raw.length - 1];
  if (outerOpen === '{' && outerClose === '}') {
    // `{N, N, N, …}` standalone codepoint array. Allow as AS3 primitive.
    const body = raw.slice(1, -1);
    const codes = _asParseCodepointList(body);
    if (codes) {
      try {
        return { kind: 'primitive', value: String.fromCodePoint(...codes) };
      } catch (_) { return null; }
    }
    // Not a codepoint array — try to parse as an AppleScript list
    // literal: `{expr1, expr2, …}` where each element is a chain
    // expression. Used by Tier A loop-iterator expansion so that
    // `property _L : {chain1, chain2, chain3}` produces a list-valued
    // binding whose elements can be enumerated by `repeat with x in
    // _L` loops.
    const elements = _asSplitListElements(body);
    if (elements && elements.length > 0 && elements.length <= _AS_MAX_LIST_ELEMENTS) {
      const parsed = [];
      for (const elem of elements) {
        const trimmed = elem.trim();
        if (!trimmed) return null;
        const ops = _asTokeniseExpression(trimmed);
        if (ops === null) return null;
        parsed.push(ops);
      }
      return { kind: 'list_literal', elements: parsed };
    }
    return null;
  }
  if (outerOpen !== '(' || outerClose !== ')') return null;
  const inner = raw.slice(1, -1).trim();
  // Primitive shapes.
  let mm;
  if ((mm = /^ASCII\s+character\s+(\d{1,6})$/i.exec(inner))) {
    const n = parseInt(mm[1], 10);
    if (!_asSafeCodepoint(n)) return null;
    try { return { kind: 'primitive', value: String.fromCodePoint(n) }; }
    catch (_) { return null; }
  }
  if ((mm = /^character\s+id\s+(\d{1,6})$/i.exec(inner))) {
    const n = parseInt(mm[1], 10);
    if (!_asSafeCodepoint(n)) return null;
    try { return { kind: 'primitive', value: String.fromCodePoint(n) }; }
    catch (_) { return null; }
  }
  if ((mm = /^string\s+id\s*\{([^}]{1,32768})\}$/i.exec(inner))) {
    const codes = _asParseCodepointList(mm[1]);
    if (!codes) return null;
    try { return { kind: 'primitive', value: String.fromCodePoint(...codes) }; }
    catch (_) { return null; }
  }
  // Not a primitive — this is a nested parenthesised expression that
  // needs to be re-tokenised at a higher level.
  return { kind: 'expression' };
}

// Resolve an operand list to a cleartext string, using the supplied
// binding map to substitute `ref` operands. Returns
//   { value: string, fullyResolved: bool, unresolvedRefs: Set<string> }
// Or `null` if the resolution exceeded _AS_MAX_RESOLVED_LEN (adversarial).
//
// Partial resolution: `ref` operands whose name is not yet in `bindings`
// or whose target is still `partiallyResolved` are rendered as
// `⟨_NAME⟩` (U+27E8 / U+27E9 — mathematical angle brackets — chosen
// because they don't collide with AppleScript syntax, shell `${VAR}`,
// or typical file-content substrings).
//
// `stack` is the active-resolution stack used to break circular refs.
function _asResolveOperands(operands, bindings, stack) {
  if (!Array.isArray(operands)) return null;
  let value = '';
  let fullyResolved = true;
  const unresolvedRefs = new Set();
  for (const op of operands) {
    let piece;
    if (op.kind === 'literal' || op.kind === 'primitive') {
      piece = op.value;
    } else if (op.kind === 'ref') {
      if (stack.indexOf(op.name) !== -1) {
        // Circular reference — render as placeholder and keep going.
        piece = '\u27E8circular:' + op.name + '\u27E9';
        fullyResolved = false;
        unresolvedRefs.add(op.name);
      } else {
        const target = bindings.get(op.name);
        if (target && typeof target.value === 'string') {
          // Use the binding's value even if it's only partially
          // resolved — a partial value like
          // `"https://⟨unresolved:_Runtime⟩/"` carries genuine
          // information (the static prefix / suffix) that we'd lose
          // by emitting `⟨unresolved:NAME⟩` wholesale. The caller
          // propagates `fullyResolved=false` upward so downstream
          // consumers (severity uplift, patternIocs gating) still
          // see the partial-resolution signal.
          piece = target.value;
          if (!target.fullyResolved) {
            fullyResolved = false;
            // Add this ref's name plus any nested unresolvedRefs
            // so the outer resolver can accurately report the
            // dependency closure.
            unresolvedRefs.add(op.name);
            if (target.unresolvedRefs) {
              for (const n of target.unresolvedRefs) unresolvedRefs.add(n);
            }
          }
        } else {
          piece = '\u27E8unresolved:' + op.name + '\u27E9';
          fullyResolved = false;
          unresolvedRefs.add(op.name);
        }
      }
    } else if (op.kind === 'quoted_form_of') {
      // `quoted form of <operand>` — resolve operand, POSIX-quote it.
      const inner = _asResolveOperands([op.operand], bindings, stack);
      if (inner === null) return null;
      if (inner.fullyResolved) {
        piece = _asPosixQuote(inner.value);
      } else {
        piece = 'quoted form of ' + inner.value;
        fullyResolved = false;
        for (const n of inner.unresolvedRefs) unresolvedRefs.add(n);
      }
    } else if (op.kind === 'group') {
      // Parenthesised sub-expression — recurse into its operand list.
      const inner = _asResolveOperands(op.operands, bindings, stack);
      if (inner === null) return null;
      piece = inner.value;
      if (!inner.fullyResolved) {
        fullyResolved = false;
        for (const n of inner.unresolvedRefs) unresolvedRefs.add(n);
      }
    } else if (op.kind === 'list_literal') {
      // AppleScript list `{e1, e2, …}`. Resolve each element; produce
      // a stringified representation `{"v1", "v2", "v3"}` for the
      // value channel and expose structured `listValues` via the
      // outer return so Tier A loop-iterator enumeration can consume
      // them. Elements that fail to resolve leave a ⟨unresolved:…⟩
      // tail in the stringified form AND mark fullyResolved=false so
      // the binding can't be incorrectly treated as a resolvable
      // literal.
      const vals = [];
      const parts = [];
      let listFully = true;
      for (const elemOps of op.elements) {
        const inner = _asResolveOperands(elemOps, bindings, stack);
        if (inner === null) return null;
        vals.push(inner.value);
        parts.push(_asAppleScriptQuote(inner.value));
        if (!inner.fullyResolved) {
          listFully = false;
          for (const n of inner.unresolvedRefs) unresolvedRefs.add(n);
        }
      }
      piece = '{' + parts.join(', ') + '}';
      if (!listFully) fullyResolved = false;
      // Stash the resolved element array on the operand itself so
      // `_collectLoopIteratorBindings` can consume it. Single-pass
      // side-effect — operand is not shared across different resolution
      // contexts (the parse tree is per-binding).
      op._resolvedListValues = vals;
      op._resolvedListFully = listFully;
    } else {
      // unknown — render as placeholder with the raw text.
      piece = '\u27E8unknown:' + op.raw + '\u27E9';
      fullyResolved = false;
    }
    value += piece;
    if (value.length > _AS_MAX_RESOLVED_LEN) return null;
  }
  return { value, fullyResolved, unresolvedRefs };
}

// POSIX single-quote an already-resolved string for shell embedding.
// `a'b` → `'a'\''b'`. Used by `quoted form of` operator evaluation.
function _asPosixQuote(s) {
  if (typeof s !== 'string' || s.length === 0) return "''";
  return "'" + s.replace(/'/g, "'\\''") + "'";
}

// AppleScript-requote a resolved string for emission as a string
// literal inside reconstructed source. Preserves AS validity when the
// candidate's `deobfuscated` is spliced back into the original script.
function _asAppleScriptQuote(s) {
  if (typeof s !== 'string') return '""';
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

Object.assign(EncodedContentDetector.prototype, {
  /**
   * Entry point for the AppleScript obfuscation finder. Returns an
   * array of `cmd-obfuscation`-shaped candidates covering every
   * binding reassembly, shell-sink reassembly, and standalone AS1/AS2
   * char-code chain in the file.
   *
   * Two-pass flow:
   *   1. Collect bindings (property/set/global/local).
   *   2. Fixed-point resolve cross-references.
   *   3. Walk `do shell script <expr>` sinks and substitute bindings.
   *   4. Walk standalone `&`-chains NOT already covered by a binding
   *      or sink (the legacy AS1/AS2 branches).
   *
   * See the file header for the design rationale and caps.
   */
  _findAppleScriptObfuscationCandidates(text, _context) {
    if (!text || text.length < 12) return [];
    // Cheap primitive-presence gate to avoid running expensive regex on
    // the hundreds of MB of non-AppleScript text the detector scans in
    // aggregate.
    if (!/\b(?:ASCII\s+character|character\s+id|string\s+id\s*\{|\bproperty\s+_|\bdo\s+shell\s+script)/i.test(text)) {
      return [];
    }
    // File-level plausibility gate. Benign internationalised AppleScript
    // (single `(character id 233)` for locale diacritics) fails this
    // gate and returns empty.
    if (!this._bruteforce && !_isAppleScriptPlausibleContext(text)) {
      return [];
    }

    const candidates = [];

    // ── Pass 1: collect bindings ────────────────────────────────────
    const bindings = this._collectAppleScriptBindings(text);

    // ── Pass 1.5 (Tier C): surface `set X to do shell script "…"`
    //     runtime-URL-fetch bindings as separate candidates. These RHSs
    //     are rejected by the runtime-accessor gate in `record()`
    //     (their value is genuinely not statically knowable — depends
    //     on the command's runtime output) but the COMMAND STRING
    //     itself contains extractable URLs / hosts that are high-
    //     value IOCs. Emit an annotation-only candidate per detected
    //     runtime-fetch assignment so the analyst sees the source.
    this._emitAppleScriptRuntimeUrlFetchCandidates(text, candidates);

    // ── Pass 2: fixed-point resolve cross-references ────────────────
    this._resolveAppleScriptBindings(bindings);

    // ── Pass 2.5a: Tier B — handler post-condition propagation ───────
    // When a file-scope `property _X : ""` is reassigned inside a
    // handler by a self-contained `set _X to <rhs>`, AND no other
    // conflicting reassignment exists, promote the handler's value
    // to file-scope. This models the common malware pattern where a
    // property is declared empty at file top and populated inside a
    // helper handler whose caller is guaranteed to run before the
    // top-level sink.
    this._propagateHandlerPostConditions(text, bindings);

    // ── Pass 2.5b: Tier A — loop-iterator enumeration ────────────────
    // Detect `repeat with <iter> in <listRef>` inside handler bodies
    // where <listRef> resolves to a list-typed binding. Handler-local
    // `set <X> to (contents of <iter>)` / `set <X> to <iter>` become
    // multi-valued: <X> takes each list element per iteration. These
    // multi-valued bindings are stored OUTSIDE the normal `bindings`
    // map so they don't pollute file-scope resolution.
    const loopIteratorBindings = this._collectLoopIteratorBindings(text, bindings);

    // ── Emit one candidate per binding that has a meaningful value ──
    let aggregateResolved = 0;
    for (const rec of bindings.values()) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      if (typeof rec.value !== 'string') continue;
      if (rec.value.length < 3) continue;
      // Binding with no primitive operand and no refs: skip — that's a
      // plain string literal binding, not obfuscation.
      if (!rec.hasPrimitive && rec.refs.size === 0) continue;
      // Budget the aggregate resolved text so adversarial input can't
      // blow the candidate emission.
      aggregateResolved += rec.value.length;
      if (aggregateResolved > _AS_MAX_AGGREGATE_RESOLVED) break;
      // Emit the binding in VALID APPLESCRIPT syntax:
      //   property _X : "<resolved>"
      //   set _X to "<resolved>"
      // `deobfuscated` is the full reconstructed binding statement,
      // so splicing it back into the source at `rec.offset` produces
      // copy-paste-runnable AppleScript instead of a bare string
      // fragment with a lost label. Resolved value is AppleScript-
      // quoted to preserve string-literal semantics.
      const quotedValue = _asAppleScriptQuote(rec.value);
      const separator = rec.kind === 'set' ? ' to ' : ' : ';
      const keyword = rec.kind === 'set' ? 'set ' : rec.kind + ' ';
      const reconstructed = keyword + rec.name + separator + quotedValue;
      const clipped = _clipDeobfToAmpBudget(reconstructed, rec.raw);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: rec.fullyResolved
          ? 'AppleScript Binding Reassembly'
          : 'AppleScript Partial Binding Reassembly',
        raw: rec.raw,
        offset: rec.offset,
        length: rec.length,
        deobfuscated: clipped,
        _assignedTo: rec.name,
        _bindingKind: rec.kind,
        // Raw resolved value (without the binding envelope) for
        // callers that want to inspect the reassembled payload
        // directly — tests, IOC extraction, sibling candidates, etc.
        _resolvedValue: rec.value,
        // Forward the handler-scope flag so downstream consumers
        // (tests, signatureMatches mirroring) can discriminate.
        _handlerScoped: !!rec._handlerScoped,
      });
    }

    // ── Pass 3: walk `do shell script <expr>` sinks ─────────────────
    const sinks = this._findAppleScriptShellSinks(text, bindings, loopIteratorBindings);
    for (const s of sinks) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      candidates.push(s);
    }

    // ── Pass 4: legacy standalone AS1/AS2 for chains NOT covered by
    //           any binding or sink. This lets files that use char-
    //           code obfuscation WITHOUT assignment declarations
    //           still surface (e.g. an inline `display dialog ((…))`).
    this._findAppleScriptAnonymousChains(text, bindings, sinks, candidates);

    return candidates;
  },

  /**
   * Pass 1 — collect every AppleScript binding declaration in the
   * file. Populates a Map<name, record> where record is
   *
   *   {
   *     name: string,                 // identifier name
   *     kind: 'property'|'set'|'global'|'local',
   *     offset: number,               // file offset of the decl start
   *     length: number,               // decl length (keyword → EOL)
   *     raw: string,                  // full decl text
   *     rhs: string,                  // RHS expression text
   *     operands: Operand[] | null,   // tokenised RHS (null on parse err)
   *     value: string | null,         // resolved value (null until resolved)
   *     fullyResolved: bool,
   *     refs: Set<string>,            // outgoing refs from the RHS
   *     hasPrimitive: bool,           // RHS contains ≥ 1 primitive operand
   *     partiallyResolved: bool,      // any ref unresolved
   *   }
   *
   * Hard cap: _AS_MAX_BINDINGS distinct bindings per file. Beyond
   * this, remaining bindings are silently dropped (the anon-chain
   * pass still covers them).
   */
  _collectAppleScriptBindings(text) {
    const bindings = new Map();
    // Normalise AppleScript line continuation (`¬` U+00AC or trailing
    // `\`) so multi-line RHS expressions are captured as one string.
    // We don't mutate positions — only collapse the continuation char
    // + following newline(s) into a single space in a scratch copy.
    const norm = text.replace(/[\u00AC\\][ \t]*\r?\n[ \t]*/g, ' ');

    // Compute handler-body byte ranges. Bindings inside a handler
    // (`on NAME() … end NAME` / `on NAME of X … end NAME`) are
    // GENUINE handler-local runtime assignments — the same `set _X
    // to …` statement may run many times with different values, so
    // inline-substituting their first-seen value at use-sites in the
    // top-level script is unsound.
    //
    // Bindings inside top-level control-flow blocks (`if … then …
    // end if`, `try … end try`, `repeat … end repeat`, `tell … end
    // tell`) ARE collected — they execute once in the same scope as
    // the top-level script and their values are visible to every
    // subsequent reference. The user-report sample has `set
    // _UCg1iH9a to …` inside a top-level `if …() then … end if`
    // block; failing to collect that binding leaves the final
    // `do shell script _UCg1iH9a` sink unresolved.
    //
    // Handler-range detection: we anchor on `^\s*on NAME(\s*\(…\))?
    // \s*$` / `^\s*on NAME\b` and find the matching `^\s*end NAME\b`
    // (or `^\s*end\b` at the same indent level if no name given).
    // Simple name-matched stack so nested handlers within the same
    // file (rare but legal) don't confuse the walker.
    const handlerRanges = [];
    {
      /* safeRegex: builtin */
      const onRe = /^[ \t]*on\s+([A-Za-z_][A-Za-z0-9_]{0,63})\b[^\r\n]*$/gim;
      let om;
      while ((om = onRe.exec(norm)) !== null) {
        const name = om[1];
        // Skip trigger handlers that aren't user-defined scoping
        // blocks: `on error` is a try-block clause, not a handler
        // definition. `on open`, `on run`, `on idle`, `on quit`,
        // etc. ARE handlers, but also execute once per event in
        // top-level scope from the analyst's perspective, so we
        // INCLUDE them (their internal `set` collections resolve
        // against the global binding map).
        if (name.toLowerCase() === 'error') continue;
        const startOff = om.index + om[0].length;
        // Find matching `end NAME` or `end <name>` with same name.
        /* safeRegex: builtin */
        const endRe = new RegExp(
          '^[ \\t]*end\\s+' + name.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&') + '\\b[^\\r\\n]*$',
          'im'
        );
        endRe.lastIndex = startOff;
        const endM = endRe.exec(norm.slice(startOff));
        if (endM) {
          const endOff = startOff + endM.index + endM[0].length;
          handlerRanges.push([om.index, endOff]);
          // Advance the `on` matcher past the handler body so we
          // don't treat nested handlers as new top-level handlers
          // inside already-skipped ranges.
          onRe.lastIndex = endOff;
        }
      }
    }
    const isInsideHandler = (offset) => {
      for (const [a, b] of handlerRanges) {
        if (offset >= a && offset < b) return true;
      }
      return false;
    };

    // Four binding shapes. We anchor on start-of-line (permissive —
    // allow leading whitespace) so in-string keyword occurrences
    // don't spuriously match.
    //   property _X : <rhs>
    //   global   _X : <rhs>   (rare — `global` usually has no `:`)
    //   local    _X : <rhs>
    //   set      _X to <rhs>
    //
    // RHS captured lazily up to end-of-line. Line continuation already
    // collapsed above.
    /* safeRegex: builtin */
    const propRe = /^[ \t]*(property|global|local)\s+([_A-Za-z][A-Za-z0-9_]{0,63})\s*:\s*(.{1,8192})$/gim;
    /* safeRegex: builtin */
    const setRe = /^[ \t]*set\s+([_A-Za-z][A-Za-z0-9_]{0,63})\s+to\s+(.{1,8192})$/gim;

    const record = (name, kind, offset, length, raw, rhs) => {
      if (bindings.size >= _AS_MAX_BINDINGS) return;
      // Handler-local bindings: in AppleScript, `property` declarations
      // are always file-scope (the compiler rejects nested property
      // declarations) — so `property` / `global` / `local` always
      // reach this point. `set X to <rhs>` CAN appear inside
      // `on NAME() … end NAME` handler bodies, where the value is
      // genuinely runtime-scoped (depends on handler arguments, loop
      // iterators, call results). But real-world obfuscated droppers
      // also use handler-local `set` for self-contained composition —
      // char-code chains + refs to file-scope bindings — producing a
      // statically-resolvable shell command fragment inside the
      // handler body. Collect those: tag with `_handlerScoped: true`
      // so downstream (sinks / tests) can discriminate, and gate
      // admission on the self-contained classifier below to exclude
      // runtime-valued sets (`set X to (contents of y)`,
      // `set X to do shell script …`, `set X to result of …` etc).
      const handlerScoped = isInsideHandler(offset);
      if (/^\s*do\s+shell\s+script\b/i.test(rhs)) return;
      // Reject handler-local `set`s whose RHS contains AppleScript
      // runtime accessors. The decoder cannot know the value of
      // `contents of X` / `item 1 of L` / `result of foo()` etc.
      // statically — collecting them would emit `⟨unresolved⟩`-riddled
      // candidates that mislead the analyst about reassembly
      // completeness. File-scope bindings are less strict (they can't
      // reference loop iterators).
      if (handlerScoped && _AS_RUNTIME_ACCESSOR_RE.test(rhs)) return;
      // Pre-tokenise the RHS so we can decide whether this binding
      // carries meaningful obfuscation content before committing it
      // to the map.
      const operands = _asTokeniseExpression(rhs.trim());
      if (operands === null) return;
      const refs = new Set();
      let hasPrimitive = false;
      let isPureEmpty = false;
      for (const op of operands) {
        if (op.kind === 'ref') refs.add(op.name);
        else if (op.kind === 'primitive') hasPrimitive = true;
        else if (op.kind === 'quoted_form_of') hasPrimitive = true;
        else if (op.kind === 'group') hasPrimitive = true;
        else if (op.kind === 'list_literal') {
          // List-literal bindings participate as their own obfuscation
          // shape (Tier A loop-iterator source). Treat as "primitive"
          // for emit-gating so they're not dropped as pure-literal
          // bindings. Element refs are walked so they contribute to
          // the binding's `refs` set for fixed-point resolution.
          hasPrimitive = true;
          for (const elemOps of op.elements) {
            for (const innerOp of elemOps) {
              if (innerOp.kind === 'ref') refs.add(innerOp.name);
            }
          }
        }
      }
      if (operands.length === 1 && operands[0].kind === 'literal' && operands[0].value === '') {
        isPureEmpty = true;
      }
      // First-seen-wins with one exception: an empty-string
      // placeholder property (`property X : ""`) shouldn't block a
      // later FILE-SCOPE `set X to ((chain…))` from recording the
      // real payload. Common malware shape: declare as empty at file
      // top, then assign the UA / URL / command string later via a
      // char-code chain.
      //
      // Handler-local bindings never override — the file-scope value
      // is what's in effect at file-scope resolution time. A handler
      // reassigning X does NOT change the file-scope definition from
      // the decoder's static-analysis perspective.
      if (bindings.has(name)) {
        const existing = bindings.get(name);
        const existingIsPureEmpty =
          existing.operands &&
          existing.operands.length === 1 &&
          existing.operands[0].kind === 'literal' &&
          existing.operands[0].value === '';
        if (!existingIsPureEmpty) return;
        if (isPureEmpty) return;
        if (handlerScoped) return;
        // Fall through — replace the empty-string placeholder with
        // this richer file-scope binding.
      }
      bindings.set(name, {
        name,
        kind,
        offset,
        length,
        raw,
        rhs,
        operands,
        value: null,
        fullyResolved: false,
        partiallyResolved: true,
        refs,
        hasPrimitive,
        _handlerScoped: handlerScoped,
      });
    };

    let m;
    while ((m = propRe.exec(norm)) !== null) {
      record(m[2], m[1].toLowerCase(), m.index, m[0].length, m[0], m[3]);
      if (bindings.size >= _AS_MAX_BINDINGS) break;
    }
    while ((m = setRe.exec(norm)) !== null) {
      record(m[1], 'set', m.index, m[0].length, m[0], m[2]);
      if (bindings.size >= _AS_MAX_BINDINGS) break;
    }
    return bindings;
  },

  /**
   * Pass 2 — fixed-point resolve cross-references. Iterates over the
   * binding map up to _AS_MAX_RESOLUTION_ROUNDS times. Each round, for
   * every unresolved binding, attempts to substitute refs whose
   * targets are already fully resolved. Stops when a round produces
   * no changes (converged) or when the round cap is hit.
   *
   * Circular references are detected via the resolution stack passed
   * into `_asResolveOperands` and emit the `⟨_NAME⟩` placeholder
   * instead of looping.
   *
   * Mutates each record's `value` / `fullyResolved` / `partiallyResolved`
   * fields in place.
   */
  _resolveAppleScriptBindings(bindings) {
    const extractListValues = (rec) => {
      // If this binding's operand list is a single `list_literal`,
      // lift its resolved-element array onto the record so Tier A
      // loop-iterator expansion can consume it without re-walking.
      if (!rec.operands || rec.operands.length !== 1) return;
      const op = rec.operands[0];
      if (op.kind !== 'list_literal') return;
      if (!Array.isArray(op._resolvedListValues)) return;
      if (!op._resolvedListFully) return;
      rec.listValues = op._resolvedListValues.slice();
    };
    // First round: resolve bindings whose operands are literal/primitive
    // only (no refs) — these bootstrap the fixed-point.
    for (const rec of bindings.values()) {
      if (!rec.operands) continue;
      if (rec.refs.size !== 0) continue;
      const r = _asResolveOperands(rec.operands, bindings, [rec.name]);
      if (r === null) continue;
      rec.value = r.value;
      rec.fullyResolved = r.fullyResolved;
      rec.partiallyResolved = !r.fullyResolved;
      rec.unresolvedRefs = r.unresolvedRefs;
      extractListValues(rec);
    }
    // Subsequent rounds: resolve bindings whose refs have become
    // resolved. Stop on convergence or round cap.
    for (let round = 0; round < _AS_MAX_RESOLUTION_ROUNDS; round++) {
      let changed = false;
      for (const rec of bindings.values()) {
        if (!rec.operands) continue;
        if (rec.fullyResolved) continue;
        const r = _asResolveOperands(rec.operands, bindings, [rec.name]);
        if (r === null) continue;
        // Record partial progress even on rounds where we don't reach
        // full resolution — the last-round partial value surfaces in
        // the candidate. Dependency closure is also updated each
        // round so cross-ref propagation works correctly when a ref's
        // target moves from fully-empty to partially-resolved.
        const prevValue = rec.value;
        rec.value = r.value;
        rec.fullyResolved = r.fullyResolved;
        rec.partiallyResolved = !r.fullyResolved;
        rec.unresolvedRefs = r.unresolvedRefs;
        extractListValues(rec);
        if (prevValue !== r.value) changed = true;
      }
      if (!changed) break;
    }
  },

  /**
   * Pass 2.5a (Tier B) — handler post-condition propagation.
   *
   * When a file-scope binding is `property X : ""` (empty-string
   * literal) AND a handler body contains exactly ONE self-contained
   * `set X to <rhs>` reassignment, promote the handler's RHS to the
   * file-scope binding's operands and re-resolve.
   *
   * Conservative: bail on
   *   - multiple `set X to …` in any one handler
   *   - assignments inside nested control-flow (`if/try/repeat` where
   *     the execution path isn't guaranteed)
   *   - handler RHS that contains `_AS_RUNTIME_ACCESSOR_RE` keywords
   *   - existing file-scope binding is not pure-empty
   *
   * After promotion we re-resolve the whole binding map once so
   * downstream refs pick up the new value.
   */
  _propagateHandlerPostConditions(text, bindings) {
    if (bindings.size === 0) return;
    // Find file-scope pure-empty properties that are candidates.
    const candidates = [];
    for (const rec of bindings.values()) {
      if (rec._handlerScoped) continue;
      if (rec.kind !== 'property') continue;
      if (rec.value !== '') continue;
      candidates.push(rec);
    }
    if (candidates.length === 0) return;

    // Find handler ranges so we know where each handler body starts /
    // ends. Mirror of the range detector in `_collectAppleScriptBindings`.
    const norm = text.replace(/[\u00AC\\][ \t]*\r?\n[ \t]*/g, ' ');
    const handlerRanges = [];
    /* safeRegex: builtin */
    const onRe = /^[ \t]*on\s+([A-Za-z_][A-Za-z0-9_]{0,63})\b[^\r\n]*$/gim;
    let om;
    while ((om = onRe.exec(norm)) !== null) {
      const hName = om[1];
      if (hName.toLowerCase() === 'error') continue;
      const startOff = om.index + om[0].length;
      /* safeRegex: builtin */
      const endRe = new RegExp(
        '^[ \\t]*end\\s+' + hName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b[^\\r\\n]*$',
        'im'
      );
      const endM = endRe.exec(norm.slice(startOff));
      if (endM) {
        handlerRanges.push([startOff, startOff + endM.index]);
        onRe.lastIndex = startOff + endM.index + endM[0].length;
      }
    }
    if (handlerRanges.length === 0) return;

    let changed = false;
    for (const rec of candidates) {
      // Scan every handler body for `set <name> to <rhs>`. Conservative:
      // only promote when exactly one match across all handlers.
      const escaped = rec.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      /* safeRegex: builtin */
      const setRe = new RegExp(
        '^[ \\t]*set\\s+' + escaped + '\\s+to\\s+(.{1,8192})$',
        'gim'
      );
      const hits = [];
      for (const [start, end] of handlerRanges) {
        const body = norm.slice(start, end);
        let m;
        setRe.lastIndex = 0;
        while ((m = setRe.exec(body)) !== null) {
          const absIndex = start + m.index;
          hits.push({ rhs: m[1], offset: absIndex });
          if (hits.length > 1) break;
        }
        if (hits.length > 1) break;
      }
      if (hits.length !== 1) continue;
      const { rhs } = hits[0];
      // Reject runtime-accessor RHS.
      if (_AS_RUNTIME_ACCESSOR_RE.test(rhs)) continue;
      const ops = _asTokeniseExpression(rhs.trim());
      if (!ops) continue;
      // Heuristic: require the RHS to carry obfuscation content (a
      // primitive / group / chain). A plain ref assignment like
      // `set _X to _Y` is promoted only if _Y's resolution would
      // produce a non-empty value.
      rec.operands = ops;
      rec.refs = new Set();
      rec.hasPrimitive = false;
      for (const op of ops) {
        if (op.kind === 'ref') rec.refs.add(op.name);
        else if (op.kind === 'primitive') rec.hasPrimitive = true;
        else if (op.kind === 'quoted_form_of') rec.hasPrimitive = true;
        else if (op.kind === 'group') rec.hasPrimitive = true;
        else if (op.kind === 'list_literal') rec.hasPrimitive = true;
      }
      rec.value = null;
      rec.fullyResolved = false;
      rec.partiallyResolved = true;
      rec.unresolvedRefs = null;
      rec._postConditionPromoted = true;
      changed = true;
    }
    if (changed) {
      // Re-run fixed-point resolution to propagate the promoted values.
      this._resolveAppleScriptBindings(bindings);
    }
  },

  /**
   * Pass 2.5b (Tier A) — loop-iterator binding enumeration.
   *
   * Detects `repeat with <iter> in <listRef>` loops inside handler
   * bodies. When <listRef> resolves to a list-typed binding, enumerate
   * handler-local `set <X> to (contents of <iter>)` / `set <X> to
   * <iter>` inside the loop body as multi-valued bindings.
   *
   * Returns a `Map<name, { values: string[], offset, length, rhs }>`.
   * Sink walking (Pass 3) consults this map to emit N variants for
   * sinks whose operand chain refs a multi-valued binding.
   */
  _collectLoopIteratorBindings(text, bindings) {
    const out = new Map();
    // Cheap pre-gate: skip files without the surface syntax.
    if (!/\brepeat\s+with\s+/i.test(text)) return out;
    const norm = text.replace(/[\u00AC\\][ \t]*\r?\n[ \t]*/g, ' ');
    /* safeRegex: builtin */
    const loopRe =
      /\brepeat\s+with\s+([_A-Za-z][A-Za-z0-9_]{0,63})\s+in\s+([_A-Za-z][A-Za-z0-9_]{0,63})\b([\s\S]{1,32768}?)^\s*end\s+repeat\b/gim;
    let m;
    while ((m = loopRe.exec(norm)) !== null) {
      const iterName = m[1];
      const listName = m[2];
      const bodyStart = m.index + m[0].indexOf(m[3]);
      const bodyText = m[3];
      // Is the source list a known file-scope list-typed binding?
      const listRec = bindings.get(listName);
      if (!listRec) continue;
      if (!Array.isArray(listRec.listValues)) continue;
      const listValues = listRec.listValues;
      if (listValues.length === 0 || listValues.length > _AS_MAX_LIST_ELEMENTS) continue;
      // Inside the body, find `set <X> to (contents of <iter>)` or
      // `set <X> to <iter>` — these are the multi-valued sinks of
      // the loop iterator.
      const escIter = iterName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      /* safeRegex: builtin */
      const setRe = new RegExp(
        '^[ \\t]*set\\s+([_A-Za-z][A-Za-z0-9_]{0,63})\\s+to\\s+' +
          '(?:\\(\\s*contents\\s+of\\s+' + escIter + '\\s*\\)|' +
          escIter + ')\\s*$',
        'gim'
      );
      let sm;
      while ((sm = setRe.exec(bodyText)) !== null) {
        const name = sm[1];
        // First-seen wins within loop-iterator map to avoid conflicts.
        if (out.has(name)) continue;
        out.set(name, {
          values: listValues.slice(),
          offset: bodyStart + sm.index,
          length: sm[0].length,
          iterName,
          listName,
        });
      }
    }
    return out;
  },

  /**
   * Pass 1.5 (Tier C) — emit `AppleScript Runtime URL Fetch`
   * annotation candidates for `set X to do shell script "…"` patterns.
   *
   * These bindings are rejected by `record()`'s runtime-accessor gate
   * (the command's output is genuinely unknown at static-analysis
   * time) but the command-string literal itself usually contains
   * URLs or hosts that are high-value IOCs — commonly this pattern is
   * used to fetch a C2 address from a dead-drop channel (Pastebin,
   * Telegram, GitHub Gist, dynamic DNS, etc.).
   *
   * Emits a candidate per match with:
   *   technique: 'AppleScript Runtime URL Fetch'
   *   deobfuscated: a human-readable annotation naming the var + source
   *   _patternIocs: [{ url: <label string>, severity: 'high' }, …]
   */
  _emitAppleScriptRuntimeUrlFetchCandidates(text, candidates) {
    if (!/\bdo\s+shell\s+script\b/i.test(text)) return;
    /* safeRegex: builtin */
    const re = /^[ \t]*set\s+([_A-Za-z][A-Za-z0-9_]{0,63})\s+to\s+do\s+shell\s+script\s+"((?:[^"\\\r\n]|\\.){1,4096})"/gim;
    let m;
    let emitted = 0;
    while ((m = re.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      if (emitted >= 32) break;
      throwIfAborted();
      const varName = m[1];
      const cmdLiteral = m[2];
      // Unescape the AS string-literal body so URL-extraction sees the
      // actual runtime-command bytes.
      const cmd = cmdLiteral
        .replace(/\\"/g, '"')
        .replace(/\\\\/g, '\\')
        .replace(/\\n/g, '\n')
        .replace(/\\t/g, '\t');
      // Extract http(s) URLs from the command. Conservative regex —
      // real URLs only; skip things that merely look like a URL inside
      // a sed pattern.
      /* safeRegex: builtin */
      const urlRe = /\bhttps?:\/\/[^\s'"`<>\\()]{3,1024}/gi;
      const urls = [];
      let um;
      while ((um = urlRe.exec(cmd)) !== null) {
        urls.push(um[0]);
        if (urls.length >= 8) break;
      }
      if (urls.length === 0) continue;
      const rawSpan = m[0];
      // Plain-English annotation body. The `⟨ … ⟩` wrapper matches the
      // `⟨unresolved:…⟩` sentinel convention used elsewhere in this
      // decoder (see comments around `expandTransitive` in
      // `_findAppleScriptShellSinks`), signalling to the reader that
      // this is an analysis placeholder, not AppleScript source. Using
      // U+27E8 / U+27E9 keeps the string syntactically distinct from
      // any real AS literal so it can never accidentally round-trip
      // back into the parser. Singular/plural branch is polish for the
      // overwhelmingly common 1-URL case.
      const annotation = urls.length === 1
        ? 'set ' + varName + ' to \u27e8runtime fetch from ' + urls[0] + '\u27e9'
        : 'set ' + varName + ' to \u27e8runtime fetch from: ' + urls.join(', ') + '\u27e9';
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'AppleScript Runtime URL Fetch',
        raw: rawSpan,
        offset: m.index,
        length: rawSpan.length,
        deobfuscated: annotation,
        _assignedTo: varName,
        _bindingKind: 'set',
        _resolvedValue: '',
        _dynamicSource: { type: 'do-shell-script', urls, command: cmd },
        _patternIocs: urls.map(u => ({
          // `_patternIocs` entries are emitted as IOC.PATTERN rows
          // with the `url:` field carrying the row label. Runtime-
          // fetch URLs surface as `IOC.PATTERN` (labelled with the
          // URL + provenance note) rather than `IOC.URL` because
          // `_processCommandObfuscation`'s consumer unconditionally
          // stamps `IOC.PATTERN` for `_patternIocs` entries.
          url: 'Dynamic C2 discovery via `do shell script` \u2014 ' + u,
          severity: 'high',
        })),
      });
      emitted++;
    }
  },

  /**
   * Pass 3 — walk every `do shell script <expr>` occurrence and
   * resolve the expression against the binding map. Emits a candidate
   * per sink, severity escalated when `with administrator privileges`
   * modifier is present on the same line.
   *
   * Returns an array of cmd-obfuscation-shaped candidates.
   */
  _findAppleScriptShellSinks(text, bindings, loopIteratorBindings) {
    const results = [];
    const loopMap = loopIteratorBindings || new Map();
    // Walk a tokenised operand tree to collect every `ref` name used.
    const collectRefs = (ops, out) => {
      if (!Array.isArray(ops)) return;
      for (const op of ops) {
        if (op.kind === 'ref') out.add(op.name);
        else if (op.kind === 'quoted_form_of') collectRefs([op.operand], out);
        else if (op.kind === 'group') collectRefs(op.operands, out);
        else if (op.kind === 'list_literal') {
          for (const el of op.elements) collectRefs(el, out);
        }
      }
    };
    // Compute the TRANSITIVE ref closure of a set of names through
    // the binding map. If `_X` references `_Y` which is partially
    // resolved via `⟨unresolved:__cViNLHc⟩`, and `__cViNLHc` is a
    // loop-iterator binding, we need to know that `_X` is affected.
    // This walks each binding's operand tree + its `unresolvedRefs`
    // closure.
    const expandTransitive = (nameSet) => {
      const out = new Set(nameSet);
      const queue = [...nameSet];
      while (queue.length > 0) {
        const name = queue.shift();
        const rec = bindings.get(name);
        if (!rec) continue;
        const inner = new Set();
        if (rec.operands) collectRefs(rec.operands, inner);
        if (rec.unresolvedRefs) {
          for (const n of rec.unresolvedRefs) inner.add(n);
        }
        for (const n of inner) {
          if (!out.has(n)) {
            out.add(n);
            queue.push(n);
          }
        }
      }
      return out;
    };
    // Match `do shell script <expr>` up to the modifier keyword or
    // end-of-statement. Capture is non-greedy; the lookahead permits
    // ending at whitespace+modifier or line-boundary. We accept capture
    // lengths from 1 char (a bare `_X` identifier ref) up to 4096.
    /* safeRegex: builtin */
    const sinkRe = /\bdo\s+shell\s+script\s+(.{1,4096}?)(?:\s+(?=with\s+administrator\s+privileges\b|password\b|as\s+\w+|without\b|returning\b)|(?=[\r\n])|$)/gi;
    let m;
    while ((m = sinkRe.exec(text)) !== null) {
      if (results.length >= _AS_MAX_SHELL_SINKS) break;
      throwIfAborted();
      const exprRaw = m[1].trim();
      // Strip matched outer parens — AppleScript writes
      // `do shell script (_A & _B)`. Our tokeniser handles both shapes
      // but leaves an extra layer of unknown-ness in the arg if we
      // include the outer parens.
      let expr = exprRaw;
      if (expr.length >= 2 && expr[0] === '(' && expr[expr.length - 1] === ')') {
        expr = expr.slice(1, -1).trim();
      }
      const operands = _asTokeniseExpression(expr);
      if (!operands || operands.length === 0) continue;
      // Require that resolution actually does work. A plain
      // `do shell script "ls"` with no refs / no primitives is not
      // obfuscation — let the vocabulary-based YARA rules cover those
      // directly.
      const hasPrimitive = operands.some(op => op.kind === 'primitive');
      const hasRef = operands.some(op => op.kind === 'ref');
      const hasQuotedForm = operands.some(op => op.kind === 'quoted_form_of');
      const hasGroup = operands.some(op => op.kind === 'group');
      if (!hasPrimitive && !hasRef && !hasQuotedForm && !hasGroup) continue;
      // Detect `with administrator privileges` modifier in the same
      // statement. Look ahead up to 120 chars from end of match.
      const tailStart = m.index + m[0].length;
      const tail = text.substring(tailStart, tailStart + 120);
      const isAdmin = /^\s*with\s+administrator\s+privileges\b/i.test(tail);
      const rawSpan = text.substring(m.index, tailStart + (isAdmin ? 30 : 0));

      // Detect the enclosing `set <var> to do shell script …` context.
      // If this sink is an assignment target, we'll record the
      // variable name + extract URLs from the resolved command so
      // Tier C surfaces runtime-fetch sources as IOCs even when the
      // command itself is built from a char-code chain (not a literal
      // string). Look back up to 200 chars for a `set X to` preamble
      // on the same line.
      let assignedToVar = null;
      {
        const lineStart = text.lastIndexOf('\n', m.index - 1) + 1;
        const preamble = text.substring(lineStart, m.index);
        const preambleMatch = /^\s*set\s+([_A-Za-z][A-Za-z0-9_]{0,63})\s+to\s+$/i.exec(preamble);
        if (preambleMatch) assignedToVar = preambleMatch[1];
      }

      // Tier A: when the sink's operand chain references a multi-
      // valued loop-iterator binding (directly OR transitively via
      // another binding whose resolved value carries
      // `⟨unresolved:__loopvar⟩`), emit N variants — one per list
      // value. Cross-product with multiple loop-iterator refs is
      // capped by `_AS_MAX_LOOP_VARIANTS` to avoid combinatorial
      // blowup.
      const sinkDirectRefs = new Set();
      collectRefs(operands, sinkDirectRefs);
      const transitiveRefs = expandTransitive(sinkDirectRefs);
      const loopRefs = [];
      for (const name of transitiveRefs) {
        if (loopMap.has(name)) loopRefs.push({ name, values: loopMap.get(name).values });
      }

      // Helper: build the cross-product of loop-ref value assignments.
      // Each element of `variants` is a Map<name, value> representing
      // one concrete assignment to use when resolving this sink.
      const buildVariants = () => {
        if (loopRefs.length === 0) return [null];
        let variants = [new Map()];
        for (const { name, values } of loopRefs) {
          const next = [];
          for (const v of variants) {
            for (const val of values) {
              if (next.length >= _AS_MAX_LOOP_VARIANTS) break;
              const m2 = new Map(v);
              m2.set(name, val);
              next.push(m2);
            }
            if (next.length >= _AS_MAX_LOOP_VARIANTS) break;
          }
          variants = next;
        }
        return variants;
      };

      const variantAssignments = buildVariants();
      const emitForVariant = (assignment) => {
        // Build a shadow bindings map that overrides the loop-ref names
        // with their concrete values for this variant. Doesn't mutate
        // the original `bindings` map. We also re-resolve every
        // binding in the transitive-ref closure against the shadow
        // map so partially-resolved bindings (e.g. `__WACaHqJOA0 =
        // "https://⟨unresolved:__cViNLHc⟩/"`) pick up the concrete
        // loop-var value instead of carrying the placeholder through.
        let resolveBindings = bindings;
        if (assignment && assignment.size > 0) {
          resolveBindings = new Map(bindings);
          for (const [name, val] of assignment) {
            resolveBindings.set(name, {
              name,
              kind: 'set',
              value: val,
              fullyResolved: true,
              partiallyResolved: false,
              unresolvedRefs: new Set(),
              operands: [{ kind: 'literal', raw: '"' + val + '"', value: val }],
              refs: new Set(),
              hasPrimitive: true,
              _loopVariant: true,
            });
          }
          // Re-resolve every binding in `transitiveRefs` (except the
          // already-overridden loop vars) so dependent values like
          // `__WACaHqJOA0` pick up the concrete loop-var assignment.
          // Bounded iteration (at most _AS_MAX_RESOLUTION_ROUNDS per
          // variant) to handle transitive chains.
          for (let round = 0; round < _AS_MAX_RESOLUTION_ROUNDS; round++) {
            let changed = false;
            for (const depName of transitiveRefs) {
              if (assignment.has(depName)) continue;
              const origRec = bindings.get(depName);
              if (!origRec || !origRec.operands) continue;
              const r = _asResolveOperands(origRec.operands, resolveBindings, [depName]);
              if (r === null) continue;
              const shadowed = resolveBindings.get(depName);
              if (shadowed && shadowed.value === r.value && shadowed.fullyResolved === r.fullyResolved) continue;
              resolveBindings.set(depName, {
                name: depName,
                kind: origRec.kind,
                value: r.value,
                fullyResolved: r.fullyResolved,
                partiallyResolved: !r.fullyResolved,
                unresolvedRefs: r.unresolvedRefs,
                operands: origRec.operands,
                refs: origRec.refs,
                hasPrimitive: origRec.hasPrimitive,
                _handlerScoped: origRec._handlerScoped,
              });
              changed = true;
            }
            if (!changed) break;
          }
        }
        const resolved = _asResolveOperands(operands, resolveBindings, ['__sink']);
        if (!resolved) return;
        if (resolved.value.length < 3) return;
        const quotedCmd = _asAppleScriptQuote(resolved.value);
        const deobf = isAdmin
          ? 'do shell script ' + quotedCmd + ' with administrator privileges'
          : 'do shell script ' + quotedCmd;
        const clipped = _clipDeobfToAmpBudget(deobf, rawSpan);
        const variantMeta = assignment && assignment.size > 0
          ? { iteration: Object.fromEntries(assignment) }
          : null;
        // Tier C: if this sink is `set <var> to do shell script …`
        // (runtime-URL-fetch binding) AND the resolved command
        // contains URLs, surface those as pattern IOCs so the analyst
        // sees WHERE the variable's runtime value comes from. Applies
        // regardless of whether the sink's command was a literal
        // string or a char-code chain — the resolved value is what
        // matters.
        const dynamicFetchUrls = [];
        if (assignedToVar) {
          /* safeRegex: builtin */
          const urlRe = /\bhttps?:\/\/[^\s'"`<>\\()]{3,1024}/gi;
          let um;
          while ((um = urlRe.exec(resolved.value)) !== null) {
            dynamicFetchUrls.push(um[0]);
            if (dynamicFetchUrls.length >= 8) break;
          }
        }
        const patternIocs = resolved.fullyResolved
          ? [{
              // The `_patternIocs` shape consumed by
              // `_processCommandObfuscation` uses `url:` (a label
              // string for the PATTERN row — name is historical,
              // it's not restricted to URLs) not `value:`. Other
              // decoder families (bash, cmd) agree. Using the wrong
              // key surfaces `IOC Pattern: undefined` in the sidebar.
              url: isAdmin
                ? 'AppleScript Reassembled Admin Shell Command'
                : 'AppleScript Reassembled Shell Command',
              severity: isAdmin ? 'critical' : 'high',
            }]
          : [];
        for (const u of dynamicFetchUrls) {
          patternIocs.push({
            // IOC.PATTERN shape; see comment on other _patternIocs
            // entries in this file for why the `url:` key is the
            // label channel (not `value:`).
            url: 'Dynamic C2 discovery via `do shell script` (assigned to '
              + assignedToVar + ') \u2014 ' + u,
            severity: 'high',
          });
        }
        results.push({
          type: 'cmd-obfuscation',
          technique: resolved.fullyResolved
            ? (isAdmin ? 'AppleScript Reassembled Admin Shell Command'
                       : 'AppleScript Reassembled Shell Command')
            : 'AppleScript Partially-Reassembled Shell Command',
          raw: rawSpan,
          offset: m.index,
          length: rawSpan.length,
          deobfuscated: clipped,
          // Raw resolved command (without the `do shell script` envelope)
          // for IOC extraction and tests.
          _resolvedValue: resolved.value,
          _patternIocs: patternIocs,
          _loopVariant: variantMeta,
          _assignedTo: assignedToVar || undefined,
          _dynamicFetchUrls: dynamicFetchUrls.length > 0 ? dynamicFetchUrls : undefined,
        });
      };
      for (const assignment of variantAssignments) {
        if (results.length >= _AS_MAX_SHELL_SINKS) break;
        emitForVariant(assignment);
      }
    }
    return results;
  },

  /**
   * Pass 4 — legacy AS1/AS2 anonymous-chain finder. Catches char-code
   * chains NOT already covered by a binding declaration (Pass 1) or a
   * `do shell script` sink (Pass 3). Useful for files that inline
   * char-code chains into `display dialog (…)`, `set the clipboard to
   * (…)`, logging expressions, etc.
   *
   * Appends candidates to the supplied `candidates` array in place.
   * Skips chains whose offset falls inside any already-captured
   * binding or sink (dedup).
   */
  _findAppleScriptAnonymousChains(text, bindings, sinks, candidates) {
    // Build a covered-span list from bindings + sinks. Small enough
    // that linear overlap test is fine.
    const covered = [];
    for (const rec of bindings.values()) {
      covered.push([rec.offset, rec.offset + rec.length]);
    }
    for (const s of sinks) {
      covered.push([s.offset, s.offset + s.length]);
    }
    const isCovered = (off, len) => {
      for (const [a, b] of covered) {
        if (off >= a && off + len <= b) return true;
      }
      return false;
    };

    // AS1: `&`-concatenation chain.
    /* safeRegex: builtin */
    const chainRe = new RegExp(
      '(?:'
        + '\\(\\s*ASCII\\s+character\\s+\\d{1,6}\\s*\\)'
      + '|'
        + '\\(\\s*character\\s+id\\s+\\d{1,6}\\s*\\)'
      + '|'
        + '\\(?\\s*string\\s+id\\s*\\{[^}]{1,32768}\\}\\s*\\)?'
      + '|'
        + '"(?:[^"\\\\\\r\\n]|\\\\.){0,512}"'
      + ')'
      + '(?:\\s*&\\s*'
      + '(?:'
        + '\\(\\s*ASCII\\s+character\\s+\\d{1,6}\\s*\\)'
      + '|'
        + '\\(\\s*character\\s+id\\s+\\d{1,6}\\s*\\)'
      + '|'
        + '\\(?\\s*string\\s+id\\s*\\{[^}]{1,32768}\\}\\s*\\)?'
      + '|'
        + '"(?:[^"\\\\\\r\\n]|\\\\.){0,512}"'
      + ')'
      + '){1,' + _AS_MAX_CHAIN_NODES + '}',
      'gi'
    );
    let m;
    while ((m = chainRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (isCovered(m.index, raw.length)) continue;
      if (!/\b(?:ASCII\s+character|character\s+id|string\s+id)\b/i.test(raw)) continue;
      const operands = _asTokeniseExpression(raw);
      if (!operands) continue;
      const r = _asResolveOperands(operands, bindings, []);
      if (!r) continue;
      if (r.value.length < 3) continue;
      // Wrap resolved value as an AppleScript string literal so
      // splicing at the chain's offset produces a valid AS
      // sub-expression. The raw chain is typically embedded in an
      // `&`-concatenation, e.g. `property X : (chain) & _Y`; pasting a
      // bare unquoted value there would produce `X : https:// & _Y`,
      // which is a parse error. Quoted (`"https://"`) is always valid.
      // Raw resolved bytes preserved on `_resolvedValue` for IOC
      // extraction, tests, and sibling candidates.
      const quoted = _asAppleScriptQuote(r.value);
      const clipped = _clipDeobfToAmpBudget(quoted, raw);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'AppleScript Char-Code Reassembly',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: clipped,
        _resolvedValue: r.value,
      });
    }

    // AS2: standalone `string id {…}` literal-array.
    /* safeRegex: builtin */
    const stridRe = /\bstring\s+id\s*\{([^}]{1,32768})\}/gi;
    while ((m = stridRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (isCovered(m.index, raw.length)) continue;
      const codes = _asParseCodepointList(m[1]);
      if (!codes || codes.length < 3) continue;
      let resolved;
      try { resolved = String.fromCodePoint(...codes); } catch (_) { continue; }
      if (!resolved || resolved.length > _AS_MAX_RESOLVED_LEN) continue;
      // De-dup against an AS1 hit that already contained this literal.
      let coveredByChain = false;
      for (const c of candidates) {
        if (c.offset <= m.index && m.index + raw.length <= c.offset + c.length) {
          coveredByChain = true;
          break;
        }
      }
      if (coveredByChain) continue;
      // Same quoting rationale as AS1 above — splice as AS string
      // literal so the reassembled source remains valid AppleScript.
      const quoted = _asAppleScriptQuote(resolved);
      const clipped = _clipDeobfToAmpBudget(quoted, raw);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'AppleScript Codepoint Array',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: clipped,
        _resolvedValue: resolved,
      });
    }

    // AS3: lone parenthesised primitive NOT caught by AS1 (which
    // requires ≥1 `&` operator). Real-world obfuscated droppers often
    // mix a single trailing `(ASCII character 47)` onto the end of a
    // chain expression — e.g. `(chain) & _X & (ASCII character 47)` —
    // where the trailing primitive sits outside the AS1 match. Also
    // covers standalone `(ASCII character 10)` / `(character id 47)`
    // inside function-argument expressions like `display dialog foo &
    // (ASCII character 10)`.
    //
    // Expression-context gate: only emit if the primitive lives in an
    // expression (nearby `&`, `"`, `(`, `,`, identifier). Skip bare
    // primitives that might be benign (e.g. inside a comment-like
    // context or as a standalone statement). The gate inspects 12
    // chars before and after the match; presence of `&` in either
    // direction is the strongest signal of concatenation context.
    /* safeRegex: builtin */
    const lonePrimRe = /\(\s*ASCII\s+character\s+(\d{1,6})\s*\)|\(\s*character\s+id\s+(\d{1,6})\s*\)/gi;
    while ((m = lonePrimRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (isCovered(m.index, raw.length)) continue;
      // Already claimed by AS1 / AS2 / binding / sink?
      let claimed = false;
      for (const c of candidates) {
        if (c.offset <= m.index && m.index + raw.length <= c.offset + c.length) {
          claimed = true;
          break;
        }
      }
      if (claimed) continue;
      // Expression-context gate: the primitive must be immediately
      // adjacent to an AppleScript concatenation operator `&` (the
      // only syntactic position where a `(ASCII character N)` or
      // `(character id N)` primitive legitimately appears in an
      // obfuscated expression). Look 8 chars before and after — just
      // enough to span `" ) & ` / ` & ` / `, & ` patterns from a
      // preceding/following operand. Rejects standalone primitives
      // that might be benign (comment / documentation / trailing
      // diagnostic `(ASCII character 10)` on its own line).
      const before = text.substring(Math.max(0, m.index - 8), m.index);
      const after = text.substring(m.index + raw.length, m.index + raw.length + 8);
      if (!/&/.test(before) && !/&/.test(after)) continue;
      const n = parseInt(m[1] || m[2], 10);
      if (!Number.isFinite(n) || n < 0 || n > 0x10FFFF) continue;
      let resolved;
      try { resolved = String.fromCodePoint(n); } catch (_) { continue; }
      const quoted = _asAppleScriptQuote(resolved);
      const clipped = _clipDeobfToAmpBudget(quoted, raw);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'AppleScript Lone Primitive',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: clipped,
        _resolvedValue: resolved,
      });
    }
  },
});
