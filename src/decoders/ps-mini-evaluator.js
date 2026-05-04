// ════════════════════════════════════════════════════════════════════════════
// ps-mini-evaluator.js — PowerShell variable / hashtable / env-var resolution
//
// A deliberately tiny PowerShell *interpreter* that walks a script statement
// by statement, maintains a symbol table of literal assignments, and resolves
// the simplest expression shapes that show up in real-world obfuscated
// samples. Anything outside the supported shapes is treated as opaque and
// drops the symbol from the table — fixed-point iteration is intentionally
// avoided to keep the wall-clock cost bounded.
//
// Supported constructs (everything else is opaque):
//
//   $x = 'literal' / "literal"        (string literal; "$y" interpolation only)
//   $x = 1,2,3                        (integer array)
//   $x = @{ k='v'; k2='v2' }           (flat hashtable, literal keys only)
//   $env:Y = 'literal'                (env namespace assignment)
//   $x[i]                             (integer-indexed array access)
//   $x.k                              (hashtable property access)
//   $env:Y                            (env namespace lookup)
//   $x + $y / $x + 'lit'              (string concatenation)
//   $x -split 'sep' / $x -join 'sep'  (array <-> string)
//   &(<expr>) <args>                  (invocation form — emits cmd-obfuscation
//                                      candidate with technique
//                                      'PowerShell Variable Resolution')
//
// Wall-clock budget: cap statements at 200, RHS length at 400 chars, candidate
// count at `maxCandidatesPerType`. Any internal exception returns [] so a
// pathological input degrades coverage rather than hanging the worker.
//
// PLAN.md → D3 / mounted via `Object.assign(EncodedContentDetector.prototype,
// …)` so the candidates flow through `_processCommandObfuscation` (which
// already handles severity, IOC extraction, and dangerous-keyword scoring).
// ════════════════════════════════════════════════════════════════════════════

// Default values of well-known PowerShell *automatic* variables — the
// engine-managed `$Foo` symbols that exist before any user assignment.
// Attackers obfuscate cmdlets by indexing into the well-known string
// values of these variables (e.g.
// `$VerbosePreference.toString()[1,3]+'x' -join ''`
// → `['i','e']+'x'` → `'iex'` — characters 1 and 3 of `SilentlyContinue`).
//
// Casing in the keys is irrelevant (PowerShell auto-vars are
// case-insensitive); we lower-case the lookup key. The values are the
// stable defaults reported by `Get-Variable -Name <auto>` on a stock
// Windows PowerShell 5.1 / pwsh install — the values an attacker is
// counting on when they hard-code `[i,j,k]` index sequences.
const KNOWN_PS_AUTO_VARS = Object.freeze({
  verbosepreference:     'SilentlyContinue',
  debugpreference:       'SilentlyContinue',
  warningpreference:     'Continue',
  progresspreference:    'Continue',
  informationpreference: 'SilentlyContinue',
  erroractionpreference: 'Continue',
  confirmpreference:     'High',
  pshome:                'C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
  shellid:               'Microsoft.PowerShell',
  psedition:             'Desktop',
  psversiontable:        '',  // hashtable in real PS, treated as opaque
});

Object.assign(EncodedContentDetector.prototype, {

  /**
   * Find PowerShell `&(<expr>) <args>` invocations whose `<expr>` resolves
   * via a one-pass symbol table. Emits `cmd-obfuscation` candidates that
   * `_processCommandObfuscation` promotes to findings.
   */
  _findPsVariableResolutionCandidates(text, context) {
    if (!text || text.length < 20) return [];
    // Fast bail — `&(` invocation form is the only shape we care about; no
    // point statement-tokenising scripts that don't contain it.
    if (text.indexOf('&(') === -1 && text.indexOf('& (') === -1) return [];

    const candidates = [];
    let stmts;
    try {
      stmts = this._psSplitStatements(text);
    } catch (_) {
      return [];
    }
    if (!stmts || stmts.length === 0) return [];

    // ── Pass 1: build a symbol table from the simplest assignment forms.
    // Two namespaces:
    //   vars      — keyed on the variable name without the `$` prefix
    //   envVars   — keyed on the env var name (right of `$env:`)
    // Each entry is `{ kind: 'string'|'array'|'hash', value: … }`.
    const vars = new Map();
    const envVars = new Map();

    const stmtCap = 200;
    const rhsCap  = 400;

    for (let si = 0; si < stmts.length && si < stmtCap; si++) {
      const stmt = stmts[si].trim();
      if (!stmt) continue;

      // ── env-var assignment: $env:Y = '…' ──
      const envM = /^\$env:([A-Za-z_][\w]*)\s*=\s*(.+)$/i.exec(stmt);
      if (envM) {
        const name = envM[1];
        const rhs  = envM[2].slice(0, rhsCap);
        const lit  = this._psParseStringLiteral(rhs, vars, envVars);
        if (lit !== null) envVars.set(name, { kind: 'string', value: lit });
        else envVars.delete(name);
        continue;
      }

      // ── plain assignment: $x = … ──
      const asnM = /^\$([A-Za-z_][\w]*)\s*=\s*(.+)$/.exec(stmt);
      if (!asnM) continue;
      const name = asnM[1];
      const rhs  = asnM[2].slice(0, rhsCap);

      // Try, in order: hashtable → array → string.
      const hash = this._psParseHashtableLiteral(rhs);
      if (hash) { vars.set(name, { kind: 'hash', value: hash }); continue; }

      const arr = this._psParseArrayLiteral(rhs, vars, envVars);
      if (arr) { vars.set(name, { kind: 'array', value: arr }); continue; }

      const str = this._psParseStringLiteral(rhs, vars, envVars);
      if (str !== null) { vars.set(name, { kind: 'string', value: str }); continue; }

      // RHS we can't resolve — drop any prior binding so a later
      // `$x.subkey` access can't pick up a stale value.
      vars.delete(name);
    }

    // ── Pass 2: scan for `&(<expr>) <args>` invocations. ──
    // The `<expr>` runs to a balanced close-paren; `<args>` is the rest of
    // the current statement, evaluated piecewise.
    const invokeRe = /&\s*\(/g;
    let im;
    while ((im = invokeRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;

      const openParen = im.index + im[0].length - 1; // position of `(`
      const closeParen = this._psFindMatchingParen(text, openParen);
      if (closeParen < 0 || closeParen - openParen > rhsCap) continue;

      const exprSrc = text.substring(openParen + 1, closeParen).trim();
      if (!exprSrc) continue;

      // Find the end of the statement so we can grab the argument tail.
      const stmtEnd = this._psFindStatementEnd(text, closeParen + 1);
      const argTail = text.substring(closeParen + 1, stmtEnd).trim();

      let resolvedCmd;
      try {
        resolvedCmd = this._psResolveExpression(exprSrc, vars, envVars);
      } catch (_) { resolvedCmd = null; }
      if (resolvedCmd === null || typeof resolvedCmd !== 'string' || resolvedCmd.length < 3) continue;

      let resolvedArgs = '';
      if (argTail) {
        try {
          resolvedArgs = this._psResolveArgList(argTail, vars, envVars);
        } catch (_) { resolvedArgs = ''; }
      }

      const deobf = (resolvedArgs ? (resolvedCmd + ' ' + resolvedArgs) : resolvedCmd).trim();
      if (deobf.length < 3) continue;
      // Don't emit if nothing actually resolved (the literal `&($x+$y)`
      // would deobf to an empty string when the table is empty).
      if (deobf === exprSrc) continue;

      const rawStart = im.index;
      const rawEnd   = stmtEnd;
      const raw      = text.substring(rawStart, rawEnd).trim();

      // Clip resolved output to the shared amp budget. The resolver
      // expands every `$var` / array / hash reference in the argument
      // tail; an input like `$a='…(long)…'; &(...) $a $a $a $a …` can
      // grow `deobf` to 30× the short `raw` statement span, violating
      // the peer-branch `32× raw / 8 KiB` contract (defined in
      // cmd-obfuscation.js). Clipping preserves the leading detection
      // signal (SENSITIVE_CMD_KEYWORDS survive — they live at the head
      // of resolvedCmd) while bounding sidebar payload size.
      const clippedDeobf = _clipDeobfToAmpBudget(deobf, raw);

      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell Variable Resolution',
        raw,
        offset: rawStart,
        length: rawEnd - rawStart,
        deobfuscated: clippedDeobf,
      });
    }

    return candidates;
  },

  /**
   * Tokenise a script into top-level statements on `;` and newline. Quoted
   * literals (single, double) and `@{ … }` / `@( … )` blocks are treated as
   * opaque so an embedded `;` inside a string or hashtable doesn't break a
   * statement in two.
   */
  _psSplitStatements(text) {
    const out = [];
    let depth = 0;            // (/) and {/} nesting
    let inSingle = false;     // ' … '
    let inDouble = false;     // " … "
    let start = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (inSingle) {
        if (c === "'") inSingle = false;
        continue;
      }
      if (inDouble) {
        if (c === '"') inDouble = false;
        else if (c === '`' && i + 1 < text.length) i++; // PS escape
        continue;
      }
      if (c === "'") { inSingle = true; continue; }
      if (c === '"') { inDouble = true; continue; }
      if (c === '(' || c === '{' || c === '[') { depth++; continue; }
      if (c === ')' || c === '}' || c === ']') { depth = Math.max(0, depth - 1); continue; }
      if (depth === 0 && (c === ';' || c === '\n')) {
        out.push(text.substring(start, i));
        start = i + 1;
        if (out.length > 1000) break; // hard guard
      }
    }
    if (start < text.length) out.push(text.substring(start));
    return out;
  },

  /**
   * Walk forward from an open paren and return the index of the matching
   * close paren (or -1 if unbalanced before EOF / hitting the 1024-char
   * pathological-length cap).
   */
  _psFindMatchingParen(text, openIdx) {
    let depth = 1;
    let inSingle = false, inDouble = false;
    const cap = Math.min(text.length, openIdx + 1024);
    for (let i = openIdx + 1; i < cap; i++) {
      const c = text[i];
      if (inSingle) { if (c === "'") inSingle = false; continue; }
      if (inDouble) {
        if (c === '"') inDouble = false;
        else if (c === '`' && i + 1 < text.length) i++;
        continue;
      }
      if (c === "'") { inSingle = true; continue; }
      if (c === '"') { inDouble = true; continue; }
      if (c === '(') depth++;
      else if (c === ')') {
        depth--;
        if (depth === 0) return i;
      }
    }
    return -1;
  },

  /**
   * Find the end of a statement starting at `from` — first top-level `;`,
   * `\n`, or EOF. Quoted literals are honoured.
   */
  _psFindStatementEnd(text, from) {
    let inSingle = false, inDouble = false;
    let depth = 0;
    const cap = Math.min(text.length, from + 1024);
    for (let i = from; i < cap; i++) {
      const c = text[i];
      if (inSingle) { if (c === "'") inSingle = false; continue; }
      if (inDouble) {
        if (c === '"') inDouble = false;
        else if (c === '`' && i + 1 < text.length) i++;
        continue;
      }
      if (c === "'") { inSingle = true; continue; }
      if (c === '"') { inDouble = true; continue; }
      if (c === '(' || c === '{' || c === '[') { depth++; continue; }
      if (c === ')' || c === '}' || c === ']') { depth = Math.max(0, depth - 1); continue; }
      if (depth === 0 && (c === ';' || c === '\n')) return i;
    }
    return cap;
  },

  /**
   * Parse the simplest `@{ k='v'; k2="v2"; … }` hashtable. Literal string
   * values only (no nested expressions). Returns a `Map` keyed by string,
   * or `null` on any deviation from the accepted shape.
   */
  _psParseHashtableLiteral(rhs) {
    const m = /^@\{\s*([\s\S]*?)\s*\}\s*$/.exec(rhs);
    if (!m) return null;
    const body = m[1];
    if (body.length > 400) return null;
    const out = new Map();
    // Split on `;` or newline at top level. The body is small, so a quick
    // string-aware splitter suffices.
    const pairs = [];
    let inSingle = false, inDouble = false, depth = 0, start = 0;
    for (let i = 0; i < body.length; i++) {
      const c = body[i];
      if (inSingle) { if (c === "'") inSingle = false; continue; }
      if (inDouble) {
        if (c === '"') inDouble = false;
        else if (c === '`' && i + 1 < body.length) i++;
        continue;
      }
      if (c === "'") { inSingle = true; continue; }
      if (c === '"') { inDouble = true; continue; }
      if (c === '{' || c === '(' || c === '[') { depth++; continue; }
      if (c === '}' || c === ')' || c === ']') { depth = Math.max(0, depth - 1); continue; }
      if (depth === 0 && (c === ';' || c === '\n')) {
        pairs.push(body.substring(start, i));
        start = i + 1;
      }
    }
    if (start < body.length) pairs.push(body.substring(start));
    for (const p of pairs) {
      const trimmed = p.trim();
      if (!trimmed) continue;
      const pm = /^([A-Za-z_][\w]*|"[^"]+"|'[^']+')\s*=\s*(.+)$/.exec(trimmed);
      if (!pm) return null;
      let key = pm[1];
      if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) {
        key = key.slice(1, -1);
      }
      const valSrc = pm[2].trim();
      // Only literal string values supported.
      const lit = this._psParseStringLiteral(valSrc, null, null);
      if (lit === null) return null;
      out.set(key, lit);
    }
    return out;
  },

  /**
   * Parse an array literal in either `1,2,3` (comma-separated) or
   * `@(1,2,3)` form. Element values may themselves be string literals,
   * integers, or `$var` references that resolve against the symbol table.
   * Returns a JS array of strings (integers are stringified at lookup
   * time), or `null` if any element fails to resolve.
   */
  _psParseArrayLiteral(rhs, vars, envVars) {
    let body;
    const wrapped = /^@\(\s*([\s\S]*?)\s*\)\s*$/.exec(rhs);
    if (wrapped) body = wrapped[1];
    else if (rhs.indexOf(',') !== -1) body = rhs;
    else return null;
    if (body.length > 400) return null;

    // Split on top-level commas only.
    const parts = [];
    let inSingle = false, inDouble = false, depth = 0, start = 0;
    for (let i = 0; i < body.length; i++) {
      const c = body[i];
      if (inSingle) { if (c === "'") inSingle = false; continue; }
      if (inDouble) {
        if (c === '"') inDouble = false;
        else if (c === '`' && i + 1 < body.length) i++;
        continue;
      }
      if (c === "'") { inSingle = true; continue; }
      if (c === '"') { inDouble = true; continue; }
      if (c === '(' || c === '{' || c === '[') { depth++; continue; }
      if (c === ')' || c === '}' || c === ']') { depth = Math.max(0, depth - 1); continue; }
      if (depth === 0 && c === ',') {
        parts.push(body.substring(start, i));
        start = i + 1;
      }
    }
    parts.push(body.substring(start));
    if (parts.length < 2) return null; // single-value RHS isn't an array

    const out = [];
    for (const p of parts) {
      const t = p.trim();
      if (!t) return null;
      // Integer literal.
      if (/^-?\d+$/.test(t)) { out.push(t); continue; }
      // String literal or $var reference.
      const lit = this._psParseStringLiteral(t, vars, envVars);
      if (lit === null) return null;
      out.push(lit);
    }
    return out;
  },

  /**
   * Resolve a single PowerShell *string-shaped* expression. Supports:
   *   'literal'   "literal" (with `$var` interpolation)
   *   $var, $env:Y, $var.k, $var[i]
   *   <expr> + <expr>          (string concat)
   *   <expr> -split 'sep'      (returns array; caller can index)
   *   <expr> -join 'sep'       (array → string)
   *
   * Returns the resolved string, or `null` if any sub-expression can't be
   * resolved against the supplied symbol tables.
   */
  _psParseStringLiteral(src, vars, envVars) {
    if (typeof src !== 'string') return null;
    const v = this._psResolveExpression(src, vars || new Map(), envVars || new Map());
    if (v === null || v === undefined) return null;
    if (Array.isArray(v)) return null; // caller wanted a string
    return String(v);
  },

  /**
   * Recursive expression resolver — returns `string | string[]` or `null`.
   * Handles `+` concat (left-associative), `-split` / `-join` operators
   * (split before join when both appear left-to-right, mirroring PS), and
   * primary terms (literal, `$var`, `$env:Y`, `$var[i]`, `$var.k`).
   *
   * The implementation is a tiny recursive-descent walker — operator
   * precedence is fixed at: primary → split → join → concat. PowerShell's
   * actual precedence is more elaborate, but the obfuscation patterns we
   * target only ever use these in left-to-right combinations.
   */
  _psResolveExpression(src, vars, envVars) {
    src = src.trim();
    if (!src) return null;
    if (src.length > 400) return null;

    // ── concat: split top-level `+` runs. ──
    const concatParts = this._psSplitTopLevel(src, '+');
    if (concatParts.length > 1) {
      const out = [];
      for (const p of concatParts) {
        const v = this._psResolveExpression(p.trim(), vars, envVars);
        if (v === null) return null;
        if (Array.isArray(v)) out.push(v.join(''));
        else out.push(String(v));
      }
      return out.join('');
    }

    // ── -join 'sep' ──
    const joinM = /^([\s\S]+?)\s+-join\s+(.+)$/i.exec(src);
    if (joinM) {
      const left = this._psResolveExpression(joinM[1].trim(), vars, envVars);
      const sep  = this._psResolveExpression(joinM[2].trim(), vars, envVars);
      if (left === null || sep === null) return null;
      const arr = Array.isArray(left) ? left : [String(left)];
      return arr.join(typeof sep === 'string' ? sep : '');
    }

    // ── -split 'sep' ──
    const splitM = /^([\s\S]+?)\s+-split\s+(.+)$/i.exec(src);
    if (splitM) {
      const left = this._psResolveExpression(splitM[1].trim(), vars, envVars);
      const sep  = this._psResolveExpression(splitM[2].trim(), vars, envVars);
      if (left === null || sep === null) return null;
      const s = Array.isArray(left) ? left.join('') : String(left);
      // PowerShell's `-split` interprets the RHS as a regex by default.
      // We honour that for the simple meta-character set the obfuscation
      // patterns use; on regex compilation failure we fall back to a
      // literal split.
      let parts;
      try {
        /* safeRegex: builtin */
        parts = s.split(new RegExp(typeof sep === 'string' ? sep : ''));
      } catch (_) {
        parts = s.split(typeof sep === 'string' ? sep : '');
      }
      return parts;
    }

    // ── primary terms ──
    return this._psResolvePrimary(src, vars, envVars);
  },

  /**
   * Resolve a primary term: literal, parenthesised sub-expression, or
   * variable reference (with optional `[i]` / `.k` accessor).
   */
  _psResolvePrimary(src, vars, envVars) {
    src = src.trim();
    if (!src) return null;

    // Parenthesised sub-expression.
    if (src.startsWith('(') && src.endsWith(')')) {
      const close = this._psFindMatchingParen(src, 0);
      if (close === src.length - 1) {
        return this._psResolveExpression(src.slice(1, -1), vars, envVars);
      }
    }

    // Single-quoted literal — verbatim, no interpolation.
    if (src.startsWith("'") && src.endsWith("'") && src.length >= 2) {
      // Reject if an unescaped `'` lives inside (would mean two adjacent
      // literals, which we don't handle).
      const inner = src.slice(1, -1);
      if (inner.indexOf("'") !== -1) return null;
      return inner;
    }

    // Double-quoted literal — handle `$var` / `$env:Y` interpolation,
    // ignore subexpressions / casts.
    if (src.startsWith('"') && src.endsWith('"') && src.length >= 2) {
      const inner = src.slice(1, -1);
      if (/\$\(/.test(inner)) return null; // subexpressions unsupported
      // Replace `$env:Y` first (longer form), then `$var`. PowerShell
      // variable names are letters/digits/underscore.
      let out = inner.replace(/\$env:([A-Za-z_][\w]*)/gi, (_full, name) => {
        const v = envVars.get(name);
        return v ? String(v.value) : '';
      });
      out = out.replace(/\$([A-Za-z_][\w]*)/g, (_full, name) => {
        const v = vars.get(name);
        if (!v) return '';
        if (v.kind === 'string') return String(v.value);
        if (v.kind === 'array')  return v.value.join(' ');
        return '';
      });
      // Strip PS backtick escapes (`n → newline, `t → tab, … — for the
      // obfuscation use case we just drop the backtick).
      out = out.replace(/`([\s\S])/g, '$1');
      return out;
    }

    // Integer literal.
    if (/^-?\d+$/.test(src)) return src;

    // $env:Y reference — possibly with [i] / .k accessor (rare for env).
    const envM = /^\$env:([A-Za-z_][\w]*)\s*(.*)$/i.exec(src);
    if (envM) {
      const name = envM[1];
      const tail = envM[2];
      const v = envVars.get(name);
      if (!v) return null;
      return this._psApplyAccessors(v, tail, vars, envVars);
    }

    // $var reference — possibly with [i] / .k accessor.
    const varM = /^\$([A-Za-z_][\w]*)\s*(.*)$/.exec(src);
    if (varM) {
      const name = varM[1];
      const tail = varM[2];
      let v = vars.get(name);
      if (!v) {
        // Fall back to PowerShell's well-known automatic variables. The
        // value is exposed as a string-kind entry so `[i]`, `[i,j,k]`,
        // and `.toString()` chains all work uniformly.
        const auto = KNOWN_PS_AUTO_VARS[name.toLowerCase()];
        if (typeof auto === 'string' && auto.length > 0) {
          v = { kind: 'string', value: auto };
        } else {
          return null;
        }
      }
      return this._psApplyAccessors(v, tail, vars, envVars);
    }

    return null;
  },


  /**
   * Apply a chain of `[i]` / `[i,j,k]` / `.k` / `.toString()` accessors
   * against a symbol-table entry. Returns `string | string[]` or `null`
   * on any failure.
   *
   * String-kind entries support character indexing — `'abc'[1]` → `'b'`,
   * `'abc'[0,2]` → `['a','c']` — because real-world obfuscation uses
   * exactly that form on the well-known `$VerbosePreference`,
   * `$PSHOME`, etc. automatic-variable string values to fish out
   * cmdlet-name characters.
   */
  _psApplyAccessors(entry, tail, vars, envVars) {
    let cur = entry; // { kind, value }
    let rest = tail.trim();
    while (rest) {
      // [i] / [i,j,k] — integer indexing. For an *array* this picks
      // elements; for a *string* it picks characters. `[i,j,k]` returns
      // a fresh array kind that downstream `-join` can collapse.
      const idxM = /^\[\s*([^\]]+?)\s*\](.*)$/.exec(rest);
      if (idxM) {
        const idxSrc = idxM[1].trim();
        rest = idxM[2].trim();
        if (!cur) return null;
        // Treat the index list as comma-separated; honour quoted /
        // bracket nesting via _psSplitTopLevel.
        const idxParts = this._psSplitTopLevel(idxSrc, ',').map(p => p.trim()).filter(Boolean);
        const indices = [];
        for (const ip of idxParts) {
          let i;
          if (/^-?\d+$/.test(ip)) i = parseInt(ip, 10);
          else {
            const v = this._psResolveExpression(ip, vars, envVars);
            if (typeof v !== 'string' || !/^-?\d+$/.test(v)) return null;
            i = parseInt(v, 10);
          }
          indices.push(i);
        }
        if (indices.length === 0) return null;

        // Source we can index into — array elements, or the codepoints
        // of a string. Hashtables aren't indexable; bail.
        let srcArr;
        if (cur.kind === 'array') srcArr = cur.value.slice();
        else if (cur.kind === 'string') srcArr = String(cur.value).split('');
        else return null;

        const picked = [];
        for (let i of indices) {
          if (i < 0) i += srcArr.length;
          if (i < 0 || i >= srcArr.length) return null;
          picked.push(srcArr[i]);
        }
        cur = (picked.length === 1)
          ? { kind: 'string', value: picked[0] }
          : { kind: 'array', value: picked };
        continue;
      }
      // .toString() — no-op for string-kind entries; collapse an array
      // into a space-joined string (`[object[]].ToString()` actually
      // returns "System.Object[]" in real PowerShell, but the
      // obfuscation form `$X.toString()[i,j]` is only ever applied to
      // already-string-shaped automatic variables — treating it as
      // identity is the right thing for the analyst's view).
      const tsM = /^\.\s*toString\s*\(\s*\)(.*)$/i.exec(rest);
      if (tsM) {
        rest = tsM[1].trim();
        if (!cur) return null;
        if (cur.kind === 'array') {
          cur = { kind: 'string', value: cur.value.join('') };
        }
        // string-kind passes through unchanged.
        continue;
      }
      // .k — hashtable property lookup.
      const propM = /^\.\s*([A-Za-z_][\w]*)(.*)$/.exec(rest);
      if (propM) {
        const key = propM[1];
        rest = propM[2].trim();
        if (!cur || cur.kind !== 'hash') return null;
        if (!cur.value.has(key)) return null;
        cur = { kind: 'string', value: cur.value.get(key) };
        continue;
      }
      // Any other suffix is opaque.
      return null;
    }
    if (!cur) return null;
    if (cur.kind === 'array') return cur.value.slice();
    return String(cur.value);
  },


  /**
   * Resolve an argument list — everything from the close-paren of `&(…)`
   * up to end-of-statement. Comma-separated arguments are joined with a
   * single space (the same shape `_processCommandObfuscation` already
   * scores).
   */
  _psResolveArgList(src, vars, envVars) {
    // Treat the tail as a sequence of whitespace- or comma-separated
    // expression atoms. We deliberately do NOT try to be PowerShell's
    // own argument tokeniser — the analyst-relevant shape is "one or
    // more quoted/var atoms".
    const atoms = this._psSplitArgAtoms(src);
    const out = [];
    for (const a of atoms) {
      const v = this._psResolveExpression(a, vars, envVars);
      if (v === null) return src.trim();
      out.push(Array.isArray(v) ? v.join(' ') : String(v));
    }
    return out.join(' ');
  },

  /**
   * Tokenise an argument tail on whitespace at top level (quotes /
   * brackets balanced).
   */
  _psSplitArgAtoms(src) {
    const out = [];
    let inSingle = false, inDouble = false, depth = 0, start = -1;
    for (let i = 0; i < src.length; i++) {
      const c = src[i];
      const ws = (c === ' ' || c === '\t');
      if (inSingle) {
        if (c === "'") inSingle = false;
        continue;
      }
      if (inDouble) {
        if (c === '"') inDouble = false;
        else if (c === '`' && i + 1 < src.length) i++;
        continue;
      }
      if (c === "'") { if (start < 0) start = i; inSingle = true; continue; }
      if (c === '"') { if (start < 0) start = i; inDouble = true; continue; }
      if (c === '(' || c === '{' || c === '[') {
        if (start < 0) start = i;
        depth++;
        continue;
      }
      if (c === ')' || c === '}' || c === ']') {
        depth = Math.max(0, depth - 1);
        continue;
      }
      if (depth === 0 && ws) {
        if (start >= 0) {
          out.push(src.substring(start, i));
          start = -1;
        }
      } else if (start < 0) {
        start = i;
      }
    }
    if (start >= 0) out.push(src.substring(start));
    return out;
  },

  /**
   * Split `src` on the supplied top-level operator (`+`). Quoted literals,
   * brackets, and parens are honoured. Skips operators that are
   * immediately preceded by another operator (so `--` / `++` cannot
   * accidentally split — neither shape is meaningful here, but the guard
   * costs nothing).
   */
  _psSplitTopLevel(src, op) {
    const out = [];
    let inSingle = false, inDouble = false, depth = 0, start = 0;
    for (let i = 0; i < src.length; i++) {
      const c = src[i];
      if (inSingle) { if (c === "'") inSingle = false; continue; }
      if (inDouble) {
        if (c === '"') inDouble = false;
        else if (c === '`' && i + 1 < src.length) i++;
        continue;
      }
      if (c === "'") { inSingle = true; continue; }
      if (c === '"') { inDouble = true; continue; }
      if (c === '(' || c === '{' || c === '[') { depth++; continue; }
      if (c === ')' || c === '}' || c === ']') { depth = Math.max(0, depth - 1); continue; }
      if (depth === 0 && c === op) {
        out.push(src.substring(start, i));
        start = i + 1;
      }
    }
    out.push(src.substring(start));
    return out;
  },
});
