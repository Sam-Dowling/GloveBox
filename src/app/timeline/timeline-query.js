'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-query.js — Timeline DSL query language: tokeniser, parser,
// compiler, serialiser, suggest-context resolver, syntax highlighter.
//
// Split out of the legacy app-timeline.js monolith. Pure
// module — no DOM, no class state. Reads the column resolver as a
// callback so the parser doesn't need a TimelineView reference. The
// output of `_tlCompileAst` is a predicate `(rowIdx) => boolean` plus
// the column index set the predicate touches.
//
// Loads AFTER timeline-helpers.js (uses `_tlEsc`, `_tlMaybeJson`, etc.)
// and BEFORE timeline-query-editor.js (consumed by the editor's
// suggest popover and undo-snapshot logic).
// ════════════════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════════════
// Query language — tokeniser + recursive-descent parser + AST compiler
// ────────────────────────────────────────────────────────────────────────────
// Grammar (single-line, case-insensitive keywords):
//
//   expr    := or
//   or      := and ('OR' and)*
//   and     := not (('AND' | implicit) not)*        // implicit AND = whitespace
//   not     := 'NOT' not | '-' primary | primary
//   primary := '(' expr ')'
//            | predicate
//            | bareWord                              // any-column contains
//   predicate := field op value
//   field      := IDENT | '"…"' | '[…]'
//   op         := ':' | '=' | ':=' | '!=' | ':!' | '~' | '<' | '<=' | '>' | '>='
//   value      := IDENT | NUMBER | STRING | REGEX | '-' value-like
//
// Tokens produced by `_tlTokenize`:
//   { kind: 'WORD'|'STRING'|'REGEX'|'NUMBER'|'OP'|'LP'|'RP'|'KW'|'WS'|'ERR',
//     text: raw, value?: parsed, start: number, end: number }
//
// AST nodes (consumed by `_tlCompileAst`):
//   { k: 'and'|'or', children: [...] }
//   { k: 'not', child }
//   { k: 'pred', colIdx, op, val, re?, num? }
//   { k: 'any', needle }              // bareword / any-column contains
//   { k: 'empty' }                    // the empty query — matches everything
//
// Everything is CSP-safe — `RegExp` is used with user-authored source
// strings + whitelisted flags, no `eval`, no `new Function`.
// ════════════════════════════════════════════════════════════════════════════

// Reserved keywords (case-insensitive).
const _TL_QUERY_KEYWORDS = new Set(['AND', 'OR', 'NOT', 'IN']);

// Operator lookup — ordered so longest prefixes match first in the tokenizer.
// `,` is here so the bareword scanner breaks on it — used only as a list
// separator inside `field IN (a, b, c)`. Everywhere else a stray comma is a
// parse error (parser treats it as an unexpected token).
const _TL_QUERY_OPS = [
  '>=', '<=', '!=', ':=', ':!', ':', '=', '~', '<', '>', ',',
];

function _tlTokenize(src) {
  const tokens = [];
  const s = String(src == null ? '' : src);
  const n = s.length;
  let i = 0;
  while (i < n) {
    const c = s.charAt(i);
    // Whitespace — collapsed into one WS token so caret-context lookup can
    // distinguish "just typed a space" from "inside a token".
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') {
      const start = i;
      while (i < n) {
        const cc = s.charAt(i);
        if (cc !== ' ' && cc !== '\t' && cc !== '\r' && cc !== '\n') break;
        i++;
      }
      tokens.push({ kind: 'WS', text: s.slice(start, i), start, end: i });
      continue;
    }
    if (c === '(') { tokens.push({ kind: 'LP', text: '(', start: i, end: i + 1 }); i++; continue; }
    if (c === ')') { tokens.push({ kind: 'RP', text: ')', start: i, end: i + 1 }); i++; continue; }
    // Double-quoted string. Backslash escapes supported for `\"` and `\\`.
    if (c === '"') {
      const start = i; i++;
      let buf = '';
      let closed = false;
      while (i < n) {
        const ch = s.charAt(i);
        if (ch === '\\' && i + 1 < n) { buf += s.charAt(i + 1); i += 2; continue; }
        if (ch === '"') { i++; closed = true; break; }
        buf += ch; i++;
      }
      tokens.push({
        kind: closed ? 'STRING' : 'ERR',
        text: s.slice(start, i), value: buf, start, end: i,
        err: closed ? null : 'unterminated string',
      });
      continue;
    }
    // Bracket-quoted field name — `[Event ID]`.
    if (c === '[') {
      const start = i; i++;
      let buf = '';
      let closed = false;
      while (i < n) {
        const ch = s.charAt(i);
        if (ch === ']') { i++; closed = true; break; }
        buf += ch; i++;
      }
      tokens.push({
        kind: closed ? 'STRING' : 'ERR',
        text: s.slice(start, i), value: buf, start, end: i,
        bracketed: true,
        err: closed ? null : 'unterminated field name',
      });
      continue;
    }
    // Regex literal — `/pattern/flags`. Only recognised when a regex makes
    // sense here (after an op like `~`); otherwise a leading `/` is just a
    // word character. The parser checks this after the fact; for the
    // tokenizer we only emit REGEX when the preceding non-WS token is an
    // OP of kind `~` (or a colon-equivalent).
    if (c === '/') {
      // Look back through WS for the last non-WS token.
      let prev = null;
      for (let k = tokens.length - 1; k >= 0; k--) {
        if (tokens[k].kind !== 'WS') { prev = tokens[k]; break; }
      }
      const regexOk = prev && prev.kind === 'OP' && prev.text === '~';
      if (regexOk) {
        const start = i; i++;
        let pat = '';
        let closed = false;
        while (i < n) {
          const ch = s.charAt(i);
          if (ch === '\\' && i + 1 < n) { pat += ch + s.charAt(i + 1); i += 2; continue; }
          if (ch === '/') { i++; closed = true; break; }
          pat += ch; i++;
        }
        let flags = '';
        while (i < n && /[imsuy]/.test(s.charAt(i))) { flags += s.charAt(i); i++; }
        tokens.push({
          kind: closed ? 'REGEX' : 'ERR',
          text: s.slice(start, i), value: { pattern: pat, flags }, start, end: i,
          err: closed ? null : 'unterminated regex',
        });
        continue;
      }
    }
    // Operators.
    let opMatched = null;
    for (const op of _TL_QUERY_OPS) {
      if (s.startsWith(op, i)) { opMatched = op; break; }
    }
    if (opMatched) {
      tokens.push({ kind: 'OP', text: opMatched, start: i, end: i + opMatched.length });
      i += opMatched.length;
      continue;
    }
    // Bare word / number. Stop at whitespace, parens, quotes, or an op char.
    const start = i;
    let buf = '';
    while (i < n) {
      const ch = s.charAt(i);
      if (ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n') break;
      if (ch === '(' || ch === ')' || ch === '"' || ch === '[' || ch === ']') break;
      // Break on an op — but only if we already have some buffered text.
      // This lets `col:foo` tokenize as WORD(col) OP(:) WORD(foo).
      if (buf.length) {
        let atOp = false;
        for (const op of _TL_QUERY_OPS) {
          if (s.startsWith(op, i)) { atOp = true; break; }
        }
        if (atOp) break;
      }
      buf += ch; i++;
    }
    if (!buf.length) {
      // Shouldn't happen, but avoid infinite loop.
      tokens.push({ kind: 'ERR', text: s.charAt(i), start: i, end: i + 1, err: 'unexpected character' });
      i++;
      continue;
    }
    const upper = buf.toUpperCase();
    if (_TL_QUERY_KEYWORDS.has(upper)) {
      tokens.push({ kind: 'KW', text: buf, value: upper, start, end: i });
    } else if (/^-?\d+(?:\.\d+)?$/.test(buf)) {
      tokens.push({ kind: 'NUMBER', text: buf, value: Number(buf), start, end: i });
    } else {
      tokens.push({ kind: 'WORD', text: buf, value: buf, start, end: i });
    }
  }
  return tokens;
}

// Parse a tokens array into an AST. Throws a `{msg, col}` shaped error
// object on syntax errors. Whitespace tokens are dropped before parsing.
function _tlParseQuery(tokens, columnsResolver) {
  const toks = tokens.filter(t => t.kind !== 'WS');
  let pos = 0;

  const peek = () => toks[pos];
  const eat = () => toks[pos++];
  const atEnd = () => pos >= toks.length;

  const err = (msg, tok) => {
    const col = tok ? tok.start : (toks.length ? toks[toks.length - 1].end : 0);
    const e = new Error(msg); e.col = col; e.userMsg = msg; throw e;
  };

  // Normalise op text → canonical predicate op.
  //   ':'  / (default)  → contains
  //   '='  / ':='       → eq
  //   '!=' / ':!'       → ne
  //   '~'               → regex
  //   '<' '<=' '>' '>=' → lt / le / gt / ge
  const canonOp = (t) => {
    switch (t) {
      case ':': return 'contains';
      case '=': case ':=': return 'eq';
      case '!=': case ':!': return 'ne';
      case '~': return 'regex';
      case '<': return 'lt';
      case '<=': return 'le';
      case '>': return 'gt';
      case '>=': return 'ge';
      default: return null;
    }
  };

  // Resolve a field name to a column index, or -1 for "any column" sentinel.
  // Matching is case-insensitive; exact match wins over prefix match.
  const resolveField = (name, tok) => {
    const raw = String(name || '').trim();
    if (!raw) err('missing field name', tok);
    if (raw === '*' || raw.toLowerCase() === 'any') return -1;
    if (!columnsResolver) err('no columns available', tok);
    const cols = columnsResolver();
    const lc = raw.toLowerCase();
    // Exact match first.
    for (let i = 0; i < cols.length; i++) {
      if (String(cols[i] || '').toLowerCase() === lc) return i;
    }
    // Trailing-colon tolerance — some user types in a way that includes
    // punctuation from the column name (e.g. EVTX "Event ID" vs. typed
    // "event_id"). We don't try to be clever — just flag the error.
    err(`unknown column: ${raw}`, tok);
    return -1; // unreachable
  };

  // Parse a "value" — a single token that yields a scalar comparison value.
  const parseValue = () => {
    if (atEnd()) err('expected value', toks[toks.length - 1]);
    const t = eat();
    if (t.kind === 'STRING' || t.kind === 'WORD') return { text: t.value, num: Number(t.value), tok: t };
    if (t.kind === 'NUMBER') return { text: String(t.text), num: Number(t.value), tok: t };
    if (t.kind === 'REGEX') return { text: t.text, re: t.value, tok: t };
    if (t.kind === 'ERR') err(t.err || 'invalid token', t);
    err('expected value', t);
    return null; // unreachable
  };

  // Parse a `IN (v1, v2, …)` tail — caller has already consumed the field
  // token (`fieldTok`) and the `IN` keyword (plus the leading `NOT` when
  // `negated === true`). Produces an `{k:'in', colIdx, vals:[strings], neg}`
  // node. `vals` is deduplicated (case-sensitive) but preserves first-seen
  // order so the serializer round-trips the user's ordering.
  const parseInList = (fieldTok, negated) => {
    const fieldName = fieldTok.value != null ? fieldTok.value : fieldTok.text;
    const colIdx = resolveField(fieldName, fieldTok);
    if (colIdx === -1) err('IN requires a specific column (not *)', fieldTok);
    if (atEnd() || peek().kind !== 'LP') err('expected "(" after IN', peek() || fieldTok);
    eat(); // (
    const vals = [];
    const seen = new Set();
    // Empty list is not allowed.
    if (!atEnd() && peek().kind === 'RP') err('IN list cannot be empty', peek());
    while (!atEnd()) {
      const v = parseValue();
      const s = String(v.text == null ? '' : v.text);
      if (!seen.has(s)) { seen.add(s); vals.push(s); }
      if (atEnd()) err('expected ")" to close IN list', toks[toks.length - 1]);
      const t = peek();
      if (t.kind === 'RP') { eat(); break; }
      if (t.kind === 'OP' && t.text === ',') { eat(); continue; }
      err('expected "," or ")" in IN list', t);
    }
    if (!vals.length) err('IN list cannot be empty', fieldTok);
    return { k: 'in', colIdx, vals, neg: !!negated };
  };

  // Parse a primary expression.
  const parsePrimary = () => {

    if (atEnd()) err('expected expression', toks[toks.length - 1] || { start: 0 });
    const t = peek();
    if (t.kind === 'LP') {
      eat();
      const inner = parseExpr();
      if (atEnd() || peek().kind !== 'RP') err('expected ")"', peek() || t);
      eat();
      return inner;
    }
    // `-word` / `-"phrase"` sugar for NOT.
    if (t.kind === 'OP' && t.text === '<') {
      // Not a supported prefix operator — likely a typo. Fall through as
      // a bareword if the parser got here by accident.
    }
    if (t.kind === 'WORD' || t.kind === 'STRING' || t.kind === 'NUMBER' || t.kind === 'REGEX') {
      // Three shapes:
      //   (a) field OP value              — a predicate
      //   (b) field IN (v1, v2, …)        — set-membership  (NEW)
      //   (c) field NOT IN (v1, v2, …)    — negated set-membership
      //   (d) bareword                    — any-column contains needle
      // Look-ahead up to three non-WS tokens.
      const next = toks[pos + 1];
      const next2 = toks[pos + 2];
      // `field IN (...)`
      if (next && next.kind === 'KW' && next.value === 'IN') {
        const fieldTok = eat();
        eat(); // IN
        return parseInList(fieldTok, false);
      }
      // `field NOT IN (...)` — sugar for NOT (field IN (…)) but folded
      // into the `in` node so the serializer emits it back as a single
      // `NOT IN` clause (nicer in the query bar).
      if (next && next.kind === 'KW' && next.value === 'NOT'
        && next2 && next2.kind === 'KW' && next2.value === 'IN') {
        const fieldTok = eat();
        eat(); // NOT
        eat(); // IN
        return parseInList(fieldTok, true);
      }
      // `is:sus`, `is:detection`, `is=sus`, `is=detection` — virtual meta-field.
      // Intercept before `resolveField()` which would reject "is" as unknown.
      if (next && next.kind === 'OP' && (next.text === ':' || next.text === '=')
        && t.kind === 'WORD' && (t.value || t.text || '').toLowerCase() === 'is') {
        eat(); // consume 'is' field token
        eat(); // consume : or =
        const val = parseValue();
        const name = String(val.text || '').toLowerCase();
        if (name !== 'sus' && name !== 'detection') {
          err('is: accepts "sus" or "detection", got "' + (val.text || '') + '"', val.tok);
        }
        return { k: 'is', name };
      }
      if (next && next.kind === 'OP') {

        const op = canonOp(next.text);
        if (op) {
          const fieldTok = eat();
          eat(); // consume OP
          const fieldName = fieldTok.value != null ? fieldTok.value : fieldTok.text;
          const colIdx = resolveField(fieldName, fieldTok);
          const val = parseValue();
          if (op === 'regex') {
            if (val.re == null) {
              // Allow `col ~ "pattern"` as an alternative to `/pattern/`.
              const _src = val.text || '';
              if (_src.length > 1024) err('regex too long (>1024 chars)', val.tok);
              const safe = safeRegex(_src, 'i');
              if (!safe.ok) err('invalid or unsafe regex: ' + safe.error, val.tok);
              return { k: 'pred', colIdx, op, val: _src, re: safe.regex };
            }
            const _src = val.re.pattern || '';
            if (_src.length > 1024) err('regex too long (>1024 chars)', val.tok);
            const safe = safeRegex(_src, val.re.flags || '');
            if (!safe.ok) err('invalid or unsafe regex: ' + safe.error, val.tok);
            return { k: 'pred', colIdx, op, val: val.text, re: safe.regex };
          }
          if (op === 'lt' || op === 'le' || op === 'gt' || op === 'ge') {
            return { k: 'pred', colIdx, op, val: val.text, num: val.num };
          }
          // contains / eq / ne — ignore colIdx === -1 for eq/ne (any-column
          // equality is meaningless); fall through to contains semantics.
          if ((op === 'eq' || op === 'ne') && colIdx === -1) {
            return { k: 'any', needle: String(val.text || '') };
          }
          return { k: 'pred', colIdx, op, val: String(val.text == null ? '' : val.text) };
        }
      }
      // Bareword → any-column contains. Numbers get stringified.
      eat();
      const s = t.kind === 'NUMBER' ? String(t.text) : (t.value != null ? t.value : t.text);
      return { k: 'any', needle: String(s) };
    }
    if (t.kind === 'ERR') err(t.err || 'invalid token', t);
    err('unexpected token "' + t.text + '"', t);
    return null;
  };

  const parseNot = () => {
    const t = peek();
    if (!t) err('expected expression', toks[toks.length - 1] || { start: 0 });
    if (t.kind === 'KW' && t.value === 'NOT') { eat(); return { k: 'not', child: parseNot() }; }
    // Prefix `-` sugar: `-word` ≡ `NOT word`. Only when immediately followed
    // by a word / string / number with no space between (which the tokenizer
    // naturally produces since `-` inside a bareword is part of the word).
    // Here we only see `-` as its own token when it appears before a
    // quoted string or paren. Support that.
    if (t.kind === 'OP' && t.text === '-') {
      eat();
      return { k: 'not', child: parseNot() };
    }
    return parsePrimary();
  };

  const parseAnd = () => {
    let left = parseNot();
    while (!atEnd()) {
      const t = peek();
      if (t.kind === 'KW' && t.value === 'AND') {
        eat();
        const right = parseNot();
        if (left.k === 'and') left.children.push(right);
        else left = { k: 'and', children: [left, right] };
        continue;
      }
      // Implicit AND — any start-of-primary token glues.
      if (t.kind === 'WORD' || t.kind === 'STRING' || t.kind === 'NUMBER'
        || t.kind === 'REGEX' || t.kind === 'LP'
        || (t.kind === 'KW' && t.value === 'NOT')
        || (t.kind === 'OP' && t.text === '-')) {
        const right = parseNot();
        if (left.k === 'and') left.children.push(right);
        else left = { k: 'and', children: [left, right] };
        continue;
      }
      break;
    }
    return left;
  };

  const parseExpr = () => {
    let left = parseAnd();
    while (!atEnd()) {
      const t = peek();
      if (t.kind === 'KW' && t.value === 'OR') {
        eat();
        const right = parseAnd();
        if (left.k === 'or') left.children.push(right);
        else left = { k: 'or', children: [left, right] };
        continue;
      }
      break;
    }
    return left;
  };

  if (!toks.length) return { k: 'empty' };
  const ast = parseExpr();
  if (pos < toks.length) {
    const t = toks[pos];
    err('unexpected "' + t.text + '"', t);
  }
  return ast;
}

// Compile an AST into a predicate `(rowIdx) => boolean`, captured against
// `view` (a TimelineView). Returns `null` for `k: 'empty'` so callers can
// short-circuit.
function _tlCompileAst(ast, view) {
  if (!ast || ast.k === 'empty') return null;
  const cellAt = (di, ci) => view._cellAt(di, ci);
  const allColsJoin = (di) => {
    const total = view.columns.length;
    const parts = new Array(total);
    for (let c = 0; c < total; c++) parts[c] = cellAt(di, c);
    return parts.join('\n').toLowerCase();
  };
  const compile = (node) => {
    switch (node.k) {
      case 'and': {
        const kids = node.children.map(compile);
        return (di) => {
          for (let i = 0; i < kids.length; i++) if (!kids[i](di)) return false;
          return true;
        };
      }
      case 'or': {
        const kids = node.children.map(compile);
        return (di) => {
          for (let i = 0; i < kids.length; i++) if (kids[i](di)) return true;
          return false;
        };
      }
      case 'not': {
        const inner = compile(node.child);
        return (di) => !inner(di);
      }
      case 'any': {
        const needle = String(node.needle || '').toLowerCase();
        if (!needle) return () => true;
        return (di) => allColsJoin(di).indexOf(needle) !== -1;
      }
      case 'is': {
        const name = node.name;
        if (name === 'sus') {
          return (di) => { const bm = view._susBitmap; return bm ? bm[di] === 1 : false; };
        }
        if (name === 'detection') {
          return (di) => { const bm = view._detectionBitmap; return bm ? bm[di] === 1 : false; };
        }
        return () => false;
      }
      case 'in': {
        const ci = node.colIdx;
        const vals = Array.isArray(node.vals) ? node.vals : [];
        const set = new Set(vals.map(v => String(v == null ? '' : v)));
        const neg = !!node.neg;
        return (di) => {
          const hit = set.has(cellAt(di, ci));
          return neg ? !hit : hit;
        };
      }
      case 'pred': {
        const ci = node.colIdx;
        const v = String(node.val == null ? '' : node.val);
        const lcNeedle = v.toLowerCase();

        switch (node.op) {
          case 'contains':
            if (ci === -1) return (di) => allColsJoin(di).indexOf(lcNeedle) !== -1;
            return (di) => cellAt(di, ci).toLowerCase().indexOf(lcNeedle) !== -1;
          case 'eq':
            return (di) => cellAt(di, ci) === v;
          case 'ne':
            return (di) => cellAt(di, ci) !== v;
          case 'regex': {
            const re = node.re;
            return (di) => { re.lastIndex = 0; return re.test(cellAt(di, ci)); };
          }
          case 'lt': case 'le': case 'gt': case 'ge': {
            const target = Number(node.num);
            if (!Number.isFinite(target)) return () => false;
            const cmp = node.op;
            return (di) => {
              const raw = cellAt(di, ci);
              if (raw === '') return false;
              // Prefer numeric interpretation; if NaN, fall back to timestamp.
              let x = Number(raw);
              if (!Number.isFinite(x)) x = _tlParseTimestamp(raw);
              if (!Number.isFinite(x)) return false;
              switch (cmp) {
                case 'lt': return x < target;
                case 'le': return x <= target;
                case 'gt': return x > target;
                case 'ge': return x >= target;
              }
              return false;
            };
          }
          default: return () => true;
        }
      }
      default: return () => true;
    }
  };
  return compile(ast);
}

// Walk the AST and return the set of column indices referenced by its
// predicates. Used by the column-menu "Values" path to strip the query's
// constraints on the target column when computing pivot-counts (mirrors
// the chip-exclusion logic in `_indexIgnoringColumn`).
function _tlQueryCollectCols(ast, set) {
  if (!ast || ast.k === 'empty') return set || new Set();
  const out = set || new Set();
  const walk = (n) => {
    if (!n) return;
    if (n.k === 'pred' && n.colIdx >= 0) out.add(n.colIdx);
    if (n.k === 'in' && n.colIdx >= 0) out.add(n.colIdx);
    if (n.children) for (const c of n.children) walk(c);
    if (n.child) walk(n.child);
  };

  walk(ast);
  return out;
}

// Compile an AST into a predicate while EXCLUDING any predicate that
// targets `excludeColIdx`. Used by `_indexIgnoringColumn` so the column
// menu's "Values" counts reflect only the OTHER constraints in the query.
// Returns `null` if the stripped AST is empty (everything matches).
function _tlCompileAstExcluding(ast, view, excludeColIdx) {
  if (!ast || ast.k === 'empty') return null;
  const strip = (n) => {
    if (!n) return null;
    if (n.k === 'pred') return n.colIdx === excludeColIdx ? null : n;
    if (n.k === 'in') return n.colIdx === excludeColIdx ? null : n;
    if (n.k === 'and' || n.k === 'or') {
      const kids = n.children.map(strip).filter(Boolean);
      if (!kids.length) return null;
      if (kids.length === 1) return kids[0];
      return { k: n.k, children: kids };
    }
    if (n.k === 'not') {
      const c = strip(n.child);
      return c ? { k: 'not', child: c } : null;
    }
    return n;
  };
  const stripped = strip(ast);
  return _tlCompileAst(stripped, view);
}

// Characters that force a field name / value to be quoted / bracketed when
// the query is serialized back to a string. Whitespace, DSL operators,
// the parenthesis + comma IN-list punctuation, and the quote / bracket
// characters themselves all fall in. Kept as a single shared regex so
// `_tlEscapeField` and `_tlEscapeValue` stay in lockstep with the
// tokenizer's break-characters.
const _TL_FIELD_NEEDS_BRACKETS = /[\s=!:~<>(),"[\]]/;
const _TL_VALUE_NEEDS_QUOTES = /[\s=!:~<>(),"[\]]/;
// Column names that clash with a reserved keyword (case-insensitive) also
// need bracketing so they're not mis-lexed as `AND` / `OR` / `NOT` / `IN`.

function _tlEscapeField(name) {
  const s = String(name == null ? '' : name);
  if (!s) return '""';
  const upper = s.toUpperCase();
  if (_TL_FIELD_NEEDS_BRACKETS.test(s) || _TL_QUERY_KEYWORDS.has(upper)) {
    return '[' + s + ']';
  }
  return s;
}

function _tlEscapeValue(v) {
  const s = String(v == null ? '' : v);
  if (s === '') return '""';
  const upper = s.toUpperCase();
  if (_TL_VALUE_NEEDS_QUOTES.test(s) || _TL_QUERY_KEYWORDS.has(upper)) {
    return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }
  return s;
}

// Serialize an AST back to a string suitable for the query editor. Column
// indices are resolved against the caller-supplied `columns` array (the
// view's live columns, so extracted virtual columns round-trip too).
//
// The `prec` parameter controls when to wrap a sub-expression in parens:
//   0 = top-level (no wrap)
//   1 = under OR  (wrap ANDs? no — AND binds tighter than OR → no wrap)
//   2 = under AND (wrap ORs so `a OR b AND c` doesn't silently re-associate)
//   3 = under NOT (wrap anything non-atomic)
// `and` returns paren-wrapped when prec > 2 (i.e. underneath a NOT);
// `or` returns paren-wrapped when prec > 1 (i.e. under AND or NOT).
function _tlFormatQuery(ast, columns) {
  if (!ast || ast.k === 'empty') return '';
  return _tlSerialize(ast, columns || [], 0);
}

function _tlSerialize(node, cols, prec) {
  if (!node) return '';
  switch (node.k) {
    case 'empty': return '';
    case 'any': return _tlEscapeValue(node.needle);
    case 'pred': {
      const colName = node.colIdx === -1 ? 'any' : (cols[node.colIdx] || `col${node.colIdx + 1}`);
      const field = _tlEscapeField(colName);
      const opStr = {
        contains: ':', eq: '=', ne: '!=', regex: '~',
        lt: '<', le: '<=', gt: '>', ge: '>=',
      }[node.op] || ':';
      // Regex values serialize with `/pat/flags`; everything else goes
      // through `_tlEscapeValue`.
      let valStr;
      if (node.op === 'regex') {
        const re = node.re;
        if (re && re.source != null) {
          valStr = '/' + re.source + '/' + (re.flags || '');
        } else {
          valStr = _tlEscapeValue(node.val);
        }
      } else {
        valStr = _tlEscapeValue(node.val);
      }
      return `${field}${opStr}${valStr}`;
    }
    case 'in': {
      const colName = cols[node.colIdx] || `col${node.colIdx + 1}`;
      const field = _tlEscapeField(colName);
      const kw = node.neg ? 'NOT IN' : 'IN';
      const list = (node.vals || []).map(_tlEscapeValue).join(', ');
      return `${field} ${kw} (${list})`;
    }
    case 'is':
      return `is:${node.name}`;
    case 'not': {
      // Atomic children don't need wrapping; composite children do. Bump
      // precedence to 3 so ANDs/ORs inside the NOT get parens.
      const inner = _tlSerialize(node.child, cols, 3);
      const kid = node.child;
      const atomic = kid && (kid.k === 'pred' || kid.k === 'in' || kid.k === 'any' || kid.k === 'is' || kid.k === 'not');
      return 'NOT ' + (atomic ? inner : `(${inner})`);
    }
    case 'and': {
      const parts = node.children.map(c => _tlSerialize(c, cols, 2));
      const s = parts.join(' AND ');
      return prec > 2 ? `(${s})` : s;
    }
    case 'or': {
      const parts = node.children.map(c => _tlSerialize(c, cols, 1));
      const s = parts.join(' OR ');
      return prec > 1 ? `(${s})` : s;
    }
    default: return '';
  }
}


// Render a token array as syntax-highlighted HTML for the `<pre>` overlay.

// Pills wrap contiguous predicate tokens (`field op value`). Whitespace
// tokens are preserved verbatim so the overlay stays pixel-aligned with
// the underlying `<textarea>`.
function _tlFormatHighlightHtml(tokens) {
  const esc = _tlEsc;
  const n = tokens.length;
  const out = [];
  let i = 0;
  while (i < n) {
    const t = tokens[i];
    // Predicate detection — field (WORD|STRING) + non-WS OP + value.
    if (t.kind === 'WORD' || t.kind === 'STRING') {
      let j = i + 1;
      while (j < n && tokens[j].kind === 'WS') j++;
      const opTok = tokens[j];
      if (opTok && opTok.kind === 'OP' && _TL_QUERY_OPS.indexOf(opTok.text) !== -1) {
        let k = j + 1;
        while (k < n && tokens[k].kind === 'WS') k++;
        const valTok = tokens[k];
        if (valTok && (valTok.kind === 'WORD' || valTok.kind === 'STRING'
          || valTok.kind === 'NUMBER' || valTok.kind === 'REGEX')) {
          // Emit a pill enclosing field+op+value (with any interior WS inline).
          out.push('<span class="tl-pill">');
          for (let q = i; q <= k; q++) out.push(_tlFormatHighlightOne(tokens[q], esc));
          out.push('</span>');
          i = k + 1;
          continue;
        }
      }
    }
    out.push(_tlFormatHighlightOne(t, esc));
    i++;
  }
  return out.join('') || '&nbsp;';
}

function _tlFormatHighlightOne(t, esc) {
  if (t.kind === 'WS') return esc(t.text).replace(/ /g, '&nbsp;');
  const cls = {
    WORD: 'tl-tok-word',
    STRING: 'tl-tok-string',
    REGEX: 'tl-tok-regex',
    NUMBER: 'tl-tok-number',
    OP: 'tl-tok-op',
    LP: 'tl-tok-paren',
    RP: 'tl-tok-paren',
    KW: 'tl-tok-kw',
    ERR: 'tl-tok-err',
  }[t.kind] || 'tl-tok-word';
  return `<span class="tl-tok ${cls}" data-s="${t.start}" data-e="${t.end}">${esc(t.text)}</span>`;
}

// Compute a suggestion context for the caret position within `text`.
// Returns { kind: 'field'|'value'|'keyword'|'none', fieldName?, prefix, replaceStart, replaceEnd, tokenStart }.
//
// This is a pure function — it just describes what kind of completion
// would make sense at the caret. The editor decides WHEN to actually
// open the popover based on the user's last input (see
// `TimelineQueryEditor._shouldOpenFromInput`). Keeping the "what" and
// "when" separated is the single biggest simplification over the
// previous implementation, which tried to bake dismissal state into
// the context itself.
function _tlSuggestContext(text, caret) {
  // Caret-inside-quoted-literal → no completion makes sense.
  let inQuote = false;
  for (let i = 0; i < caret; i++) {
    const ch = text.charAt(i);
    if (ch === '\\' && inQuote) { i++; continue; }
    if (ch === '"') inQuote = !inQuote;
  }
  if (inQuote) {
    return { kind: 'none', prefix: '', replaceStart: caret, replaceEnd: caret, tokenStart: caret };
  }

  // Walk back/forward over the current bareword. The forward walk also
  // breaks on DSL operator characters so a caret at the *start* of a
  // `field:value` token doesn't get a token range that swallows the
  // colon — otherwise the editor's `_applySuggest` would replace
  // `field:` with the chosen field name and clobber the operator. The
  // back-walk intentionally does NOT break on operator chars: when the
  // caret sits *after* `field:`, the prefix-side operator detection
  // (the loop further down) reclassifies the context as `value`.
  let start = caret;
  while (start > 0) {
    const ch = text.charAt(start - 1);
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '(' || ch === ')' || ch === '"') break;
    start--;
  }
  let end = caret;
  while (end < text.length) {
    const ch = text.charAt(end);
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '(' || ch === ')' || ch === '"') break;
    if (ch === ':' || ch === '=' || ch === '!' || ch === '~' || ch === '<' || ch === '>' || ch === ',') break;
    end++;
  }
  const prefix = text.slice(start, caret);

  // Operator inside the current word — `col:` / `col=foo` → value context.
  for (const op of _TL_QUERY_OPS) {
    const idx = prefix.lastIndexOf(op);
    if (idx !== -1 && idx + op.length === prefix.length) {
      const fieldRaw = prefix.slice(0, idx).trim();
      return {
        kind: 'value', fieldName: fieldRaw.replace(/^["[]|["\]]$/g, ''),
        prefix: '', replaceStart: caret, replaceEnd: caret, tokenStart: start,
      };
    }
    const idx2 = prefix.indexOf(op);
    if (idx2 !== -1 && /^[^\s()]/.test(prefix.charAt(idx2 + op.length) || '')) {
      const fieldRaw = prefix.slice(0, idx2).trim();
      const valRaw = prefix.slice(idx2 + op.length);
      return {
        kind: 'value', fieldName: fieldRaw.replace(/^["[]|["\]]$/g, ''),
        prefix: valRaw, replaceStart: start + idx2 + op.length, replaceEnd: end,
        tokenStart: start,
      };
    }
  }

  // No operator — decide field vs keyword by what sits to the left.
  const before = text.slice(0, start).trimEnd();
  const lastChar = before.charAt(before.length - 1);
  const afterKeyword = /(?:^|\s)(AND|OR|NOT)$/i.test(before);
  if (before === '' || lastChar === '(' || afterKeyword) {
    return { kind: 'field', prefix, replaceStart: start, replaceEnd: end, tokenStart: start };
  }
  return { kind: 'keyword', prefix, replaceStart: start, replaceEnd: end, tokenStart: start };
}

