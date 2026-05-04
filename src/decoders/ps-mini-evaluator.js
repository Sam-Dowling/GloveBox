// ════════════════════════════════════════════════════════════════════════════
// ps-mini-evaluator.js — PowerShell variable / hashtable / env-var resolution
//
// A deliberately tiny PowerShell *interpreter* that walks a script statement
// by statement, maintains a symbol table of literal assignments, and resolves
// the simplest expression shapes that show up in real-world obfuscated
// samples. Anything outside the supported shapes is treated as opaque and
// drops the symbol from the table.
//
// Fixed-point iteration: bounded (max 3 passes) — just enough to resolve
// multi-hop chains like `$a='I'; $b='EX'; $c=$a+$b; &($c)` without
// degenerating into a full interpreter. Each pass only re-runs on RHS
// values that couldn't resolve in the previous pass, and we early-exit on
// zero-delta.
//
// Supported constructs (everything else is opaque):
//
//   $x = 'literal' / "literal"        (string literal; "$y" / "${y}" interp)
//   $x = 1,2,3                        (integer array)
//   $x = @{ k='v'; k2='v2' }           (flat hashtable, literal keys only)
//   $x = @"…"@ / @'…'@                 (here-string literal; verbatim for @')
//   $env:Y = 'literal'                (env namespace assignment)
//   sal/Set-Alias/New-Alias name 'lit'(literal-target alias assignment)
//   $x[i] / ${x}                      (integer-indexed array access; braces)
//   $x.k                              (hashtable property access)
//   $env:Y / ${env:Y}                 (env namespace lookup; braces)
//   $x + $y / $x + 'lit'              (string concatenation)
//   'a'+''+'b' / "a"+""+"b"           (quote-pair collapse)
//   $x -split 'sep' / $x -join 'sep'  (array <-> string)
//   N..M                              (range operator, bounded to 1024 elts)
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

// Bounded fixed-point iteration cap. 3 passes is enough to resolve the
// common multi-hop chains (`$a='I'; $b='EX'; $c=$a+$b; $d='-Expression';
// $e=$c+$d; &($e)`) without degenerating. Each pass re-tries only the
// previously-unresolved RHS values — convergence is O(deps × passes)
// in the worst case, but the stmtCap + rhsCap guards dominate.
const _PS_MAX_FIXED_POINT_PASSES = 3;

// Range operator `N..M` output cap. Stops `0..65535 -join ''` from
// producing a 60 KB string; most real obfuscators use `65..90` / `32..126`
// / `-1..-$s.Length` which are comfortably under the cap.
const _PS_RANGE_MAX_ELEMENTS = 1024;

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
   * Build (or reuse from a single-entry cache) the PowerShell symbol
   * table for `text`. Returns `{ vars, envVars, aliases }` Maps. Invoked
   * lazily by `_findPsVariableResolutionCandidates` AND by cmd-obfuscation
   * sink branches that need to resolve variable-backed arguments (Phase B
   * — `-EncodedCommand $b64`, `[Convert]::FromBase64String($x)`,
   * `[scriptblock]::Create($s)`).
   *
   * Cache key is the text pointer itself (JS strings are value-compared
   * for the ===; the identity heuristic is safe because both callers pass
   * the same `text` argument from the same scan). The cache holds only
   * the latest scan's table; concurrent scans on different EncodedContent
   * Detector instances don't share cache state (the cache lives on
   * `this`).
   */
  _buildPsSymbolTable(text) {
    if (this._psSymbolTableCache
        && this._psSymbolTableCache.text === text) {
      return this._psSymbolTableCache.table;
    }
    const vars = new Map();
    const envVars = new Map();
    const aliases = new Map();
    if (!text || typeof text !== 'string' || text.length === 0) {
      const empty = { vars, envVars, aliases };
      this._psSymbolTableCache = { text, table: empty };
      return empty;
    }

    let stmts;
    try {
      stmts = this._psSplitStatements(text);
    } catch (_) {
      const empty = { vars, envVars, aliases };
      this._psSymbolTableCache = { text, table: empty };
      return empty;
    }
    if (!stmts || stmts.length === 0) {
      const empty = { vars, envVars, aliases };
      this._psSymbolTableCache = { text, table: empty };
      return empty;
    }

    const stmtCap = 200;
    const rhsCap  = 400;
    let pending = [];
    const lastResolvedIdx = new Map();
    const _mark = (ns, name, idx) => lastResolvedIdx.set(ns + ':' + name, idx);
    const _lastIdx = (ns, name) => {
      const v = lastResolvedIdx.get(ns + ':' + name);
      return (typeof v === 'number') ? v : -1;
    };

    for (let si = 0; si < stmts.length && si < stmtCap; si++) {
      const stmt = stmts[si].trim();
      if (!stmt) continue;

      const aliasM = /^(?:sal|Set-Alias|New-Alias)\s+(?:-Name\s+)?['"]?([A-Za-z_][\w]*)['"]?\s+(?:-Value\s+)?([\s\S]+)$/i.exec(stmt);
      if (aliasM) {
        pending.push({ kind: 'alias', name: aliasM[1], rhs: aliasM[2].slice(0, rhsCap), idx: si });
        continue;
      }
      const envM = /^\$(?:env:|\{env:)([A-Za-z_][\w]*)\}?\s*=\s*([\s\S]+)$/i.exec(stmt);
      if (envM) {
        pending.push({ kind: 'env', name: envM[1], rhs: envM[2].slice(0, rhsCap), idx: si });
        continue;
      }
      const asnM = /^\$\{?([A-Za-z_][\w]*)\}?\s*=\s*([\s\S]+)$/.exec(stmt);
      if (asnM) {
        pending.push({ kind: 'var', name: asnM[1], rhs: asnM[2].slice(0, rhsCap), idx: si });
      }
    }

    // _psAliasScratch must be set BEFORE _psParseStringLiteral fires
    // because the resolver consults it via _psResolveVarName / _psInterpolate.
    this._psAliasScratch = aliases;

    for (let pass = 0; pass < _PS_MAX_FIXED_POINT_PASSES; pass++) {
      const nextPending = [];
      let resolvedThisPass = 0;
      for (const p of pending) {
        if (p.kind === 'var') {
          const hash = this._psParseHashtableLiteral(p.rhs);
          if (hash) { vars.set(p.name, { kind: 'hash', value: hash }); _mark('v', p.name, p.idx); resolvedThisPass++; continue; }
          const arr = this._psParseArrayLiteral(p.rhs, vars, envVars);
          if (arr) { vars.set(p.name, { kind: 'array', value: arr }); _mark('v', p.name, p.idx); resolvedThisPass++; continue; }
          const str = this._psParseStringLiteral(p.rhs, vars, envVars);
          if (str !== null) { vars.set(p.name, { kind: 'string', value: str }); _mark('v', p.name, p.idx); resolvedThisPass++; continue; }
          if (pass < _PS_MAX_FIXED_POINT_PASSES - 1) nextPending.push(p);
          else if (_lastIdx('v', p.name) < p.idx) vars.delete(p.name);
        } else if (p.kind === 'env') {
          const lit = this._psParseStringLiteral(p.rhs, vars, envVars);
          if (lit !== null) {
            envVars.set(p.name, { kind: 'string', value: lit });
            _mark('e', p.name, p.idx);
            resolvedThisPass++;
          } else if (pass < _PS_MAX_FIXED_POINT_PASSES - 1) {
            nextPending.push(p);
          } else if (_lastIdx('e', p.name) < p.idx) {
            envVars.delete(p.name);
          }
        } else if (p.kind === 'alias') {
          const lit = this._psParseStringLiteral(p.rhs, vars, envVars);
          if (typeof lit === 'string' && lit.length > 0 && lit.length < 120) {
            aliases.set(p.name.toLowerCase(), { kind: 'string', value: lit });
            _mark('a', p.name.toLowerCase(), p.idx);
            resolvedThisPass++;
          } else if (pass < _PS_MAX_FIXED_POINT_PASSES - 1) {
            nextPending.push(p);
          }
        }
      }
      pending = nextPending;
      if (resolvedThisPass === 0) break;
      if (pending.length === 0) break;
    }

    const table = { vars, envVars, aliases };
    this._psSymbolTableCache = { text, table };
    return table;
  },

  /**
   * Resolve a single argument token (`$name`, `${name}`, `$env:NAME`,
   * `${env:NAME}`, `'literal'`, `"literal"`) against a symbol table
   * returned by `_buildPsSymbolTable`. Used by cmd-obfuscation's variable-
   * backed sink branches (Phase B) to recover a base64 / script body
   * argument that is stored in a $var rather than inlined.
   *
   * Returns a string (possibly empty) on success, or `null` when the
   * token is a bare `$x` that isn't in the table, or when the token
   * shape isn't something we statically recognise.
   */
  _psResolveArgToken(token, table) {
    if (typeof token !== 'string') return null;
    const t = token.trim();
    if (!t) return null;
    if (!table) return null;
    const vars = table.vars || new Map();
    const envVars = table.envVars || new Map();
    this._psAliasScratch = table.aliases;
    // Literal: delegate to the full resolver so quote-pair chains /
    // interpolation / concat work uniformly.
    if (t[0] === "'" || t[0] === '"' || t[0] === '(' || t[0] === '@') {
      const v = this._psResolveExpression(t, vars, envVars);
      if (typeof v === 'string') return v;
      if (Array.isArray(v)) return v.join('');
      return null;
    }
    // $name / ${name} / $env:NAME / ${env:NAME}, possibly with accessors.
    if (t[0] === '$') {
      const v = this._psResolvePrimary(t, vars, envVars);
      if (typeof v === 'string') return v;
      if (Array.isArray(v)) return v.join('');
      return null;
    }
    return null;
  },

  /**
   * Find PowerShell `&(<expr>) <args>` invocations whose `<expr>` resolves
   * via a one-pass symbol table. Emits `cmd-obfuscation` candidates that
   * `_processCommandObfuscation` promotes to findings.
   */
  _findPsVariableResolutionCandidates(text, context) {
    if (!text || text.length < 20) return [];
    // Fast bail: both the `&(…)` paren form and the paren-less
    // `& $x` / `iex $x` / `. $x` / `Invoke-Expression $x` / `Invoke-Command
    // -ScriptBlock $sb` forms must appear for this finder to do useful
    // work. Any occurrence of one of those markers is a cheap pre-filter.
    const hasParenForm = text.indexOf('&(') !== -1 || text.indexOf('& (') !== -1;
    // The paren-less filter matches the invocation keyword anywhere that
    // is followed (possibly after a `-ScriptBlock`-style named flag) by a
    // `$` within 40 chars. Cheap but permissive enough that Phase B
    // variations (`Invoke-Command -ScriptBlock $sb`) don't short-circuit.
    //
    // Word-boundary caveat: `\.` / `&` are non-word chars, so `\b` after
    // them fails when the next char is whitespace. Use a non-capturing
    // `(?=\s)` lookahead for the symbol verbs and `\b` only for the
    // alphabetic verbs that actually need it (`iex`, `Invoke-*`).
    const hasParenlessForm = /(?:^|[\s;&|(])(?:\.(?=\s)|&(?=\s)|iex\b|Invoke-Expression\b|Invoke-Command\b)[^\r\n;|&]{0,40}\$/i.test(text);
    if (!hasParenForm && !hasParenlessForm) return [];

    const candidates = [];
    const table = this._buildPsSymbolTable(text);
    const { vars, envVars, aliases } = table;
    if (!vars) return [];
    // Make the alias scratch visible to _psResolvePrimary / _psInterpolate
    // for this scan.
    this._psAliasScratch = aliases;

    // ── Paren form: scan for `&(<expr>) <args>` invocations. ──
    // The `<expr>` runs to a balanced close-paren; `<args>` is the rest of
    // the current statement, evaluated piecewise.
    const _RHS_CAP = 400;
    const invokeRe = /&\s*\(/g;
    let im;
    while ((im = invokeRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;

      const openParen = im.index + im[0].length - 1; // position of `(`
      const closeParen = this._psFindMatchingParen(text, openParen);
      if (closeParen < 0 || closeParen - openParen > _RHS_CAP) continue;

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

    // ── Paren-less form: `& $x` / `. $x` / `iex $x` / `Invoke-Expression $x`
    //                   / `Invoke-Command -ScriptBlock $sb` ──
    //
    // These are the most common variable-backed sink shapes today. The
    // paren-form above only fires on `&($x)`; paren-less variants go
    // through an independent regex locator that captures the invocation
    // sink keyword + the first `$name` / `${name}` / `$env:NAME` argument.
    //
    // Gate: the resolved target must hit SENSITIVE_CMD_KEYWORDS OR
    // _EXEC_INTENT_RE, to avoid firing on benign `& $build -v` style
    // invocations. (Bruteforce mode drops the gate.)
    const parenlessRe = /(?:^|[\s;&|(])(\.|&|iex|Invoke-Expression|Invoke-Command(?:\s+-ScriptBlock)?)\s+(\$\{?[A-Za-z_][\w]*\}?|\$env:[A-Za-z_][\w]*|\$\{env:[A-Za-z_][\w]*\})(\s+[^\r\n;|&]{0,200})?/gi;
    let pm;
    while ((pm = parenlessRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const verb = (pm[1] || '').trim();
      const varToken = pm[2];
      const argTail = (pm[3] || '').trim();

      let resolvedCmd;
      try {
        resolvedCmd = this._psResolveArgToken(varToken, table);
      } catch (_) { resolvedCmd = null; }
      if (!resolvedCmd || resolvedCmd.length < 3) continue;

      // Plausibility gate: the resolved target must look like an
      // exec-intent keyword / LOLBin. Without this gate a `& $buildTool`
      // in a benign MSBuild script fires.
      if (!this._bruteforce
          && !_EXEC_INTENT_RE.test(resolvedCmd)) {
        continue;
      }

      let resolvedArgs = '';
      if (argTail) {
        try {
          resolvedArgs = this._psResolveArgList(argTail, vars, envVars);
        } catch (_) { resolvedArgs = argTail; }
      }

      // `verb` is the textual invocation keyword; we keep it in the
      // deobfuscated output so the analyst sees exactly how the
      // resolved target was dispatched (`& iex` vs `. iex` vs
      // `Invoke-Expression iex`).
      const deobf = (resolvedArgs
        ? (verb + ' ' + resolvedCmd + ' ' + resolvedArgs)
        : (verb + ' ' + resolvedCmd)).trim();
      if (deobf.length < 3) continue;

      // Raw span: from the verb start to the end of statement.
      const verbStart = pm.index + pm[0].indexOf(verb);
      const stmtEnd = this._psFindStatementEnd(text, verbStart);
      const raw = text.substring(verbStart, stmtEnd).trim();
      const clippedDeobf = _clipDeobfToAmpBudget(deobf, raw);

      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell Variable Resolution (call-operator)',
        raw,
        offset: verbStart,
        length: stmtEnd - verbStart,
        deobfuscated: clippedDeobf,
        _patternIocs: [{
          url: 'PowerShell invocation of variable-held command name \u2014 T1059.001 (call-operator / iex / Invoke-Expression indirection)',
          severity: 'high',
        }],
      });
    }

    return candidates;
  },

  /**
   * Tokenise a script into top-level statements on `;` and newline. Quoted
   * literals (single, double), here-strings (`@"…\n"@` / `@'…\n'@`), and
   * `@{ … }` / `@( … )` blocks are treated as opaque so an embedded `;`
   * inside a string or hashtable doesn't break a statement in two.
   *
   * Here-string recognition: `@"` or `@'` followed immediately by `\n`
   * opens a here-string that runs until a line starting with `"@` / `'@`.
   * Terminators MUST appear at the beginning of a line (optionally
   * preceded by whitespace — PowerShell 5+ relaxed this, though strict
   * 2.0 required no leading whitespace). The lexer skips the entire
   * body so embedded `;` / newlines don't split statements.
   */
  _psSplitStatements(text) {
    const out = [];
    let depth = 0;            // (/) and {/} nesting
    let inSingle = false;     // ' … '
    let inDouble = false;     // " … "
    let hereKind = null;      // null | '"' | "'"
    let start = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      // Here-string: runs until `\n"@` or `\n'@` at the start of a line.
      if (hereKind !== null) {
        if (c === '\n') {
          // Scan the next line's leading whitespace to see if it closes.
          let j = i + 1;
          while (j < text.length && (text[j] === ' ' || text[j] === '\t')) j++;
          if (j + 1 < text.length && text[j] === hereKind && text[j + 1] === '@') {
            // Consume up through the closing marker.
            i = j + 1;
            hereKind = null;
          }
        }
        continue;
      }
      if (inSingle) {
        if (c === "'") inSingle = false;
        continue;
      }
      if (inDouble) {
        if (c === '"') inDouble = false;
        else if (c === '`' && i + 1 < text.length) i++; // PS escape
        continue;
      }
      // Here-string opener: `@"` / `@'` immediately followed by newline.
      if (c === '@' && i + 2 < text.length
          && (text[i + 1] === '"' || text[i + 1] === "'")
          && (text[i + 2] === '\n' || text[i + 2] === '\r')) {
        hereKind = text[i + 1];
        i += 2;
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
   * pathological-length cap). Honours here-string openers so a `;` / `)`
   * inside a here-string body can't unbalance the counter.
   */
  _psFindMatchingParen(text, openIdx) {
    let depth = 1;
    let inSingle = false, inDouble = false;
    let hereKind = null;
    const cap = Math.min(text.length, openIdx + 1024);
    for (let i = openIdx + 1; i < cap; i++) {
      const c = text[i];
      if (hereKind !== null) {
        if (c === '\n') {
          let j = i + 1;
          while (j < text.length && (text[j] === ' ' || text[j] === '\t')) j++;
          if (j + 1 < text.length && text[j] === hereKind && text[j + 1] === '@') {
            i = j + 1;
            hereKind = null;
          }
        }
        continue;
      }
      if (inSingle) { if (c === "'") inSingle = false; continue; }
      if (inDouble) {
        if (c === '"') inDouble = false;
        else if (c === '`' && i + 1 < text.length) i++;
        continue;
      }
      if (c === '@' && i + 2 < text.length
          && (text[i + 1] === '"' || text[i + 1] === "'")
          && (text[i + 2] === '\n' || text[i + 2] === '\r')) {
        hereKind = text[i + 1];
        i += 2;
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
   * `\n`, or EOF. Quoted literals and here-strings are honoured.
   */
  _psFindStatementEnd(text, from) {
    let inSingle = false, inDouble = false;
    let hereKind = null;
    let depth = 0;
    const cap = Math.min(text.length, from + 1024);
    for (let i = from; i < cap; i++) {
      const c = text[i];
      if (hereKind !== null) {
        if (c === '\n') {
          let j = i + 1;
          while (j < text.length && (text[j] === ' ' || text[j] === '\t')) j++;
          if (j + 1 < text.length && text[j] === hereKind && text[j + 1] === '@') {
            i = j + 1;
            hereKind = null;
          }
        }
        continue;
      }
      if (inSingle) { if (c === "'") inSingle = false; continue; }
      if (inDouble) {
        if (c === '"') inDouble = false;
        else if (c === '`' && i + 1 < text.length) i++;
        continue;
      }
      if (c === '@' && i + 2 < text.length
          && (text[i + 1] === '"' || text[i + 1] === "'")
          && (text[i + 2] === '\n' || text[i + 2] === '\r')) {
        hereKind = text[i + 1];
        i += 2;
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
   *   @"…"@       @'…'@     (here-strings — verbatim for @', interp for @")
   *   $var, $env:Y, $var.k, $var[i]
   *   ${var}, ${env:Y}                (braced form)
   *   <expr> + <expr>          (string concat; '' and "" operands collapsed)
   *   <expr> -split 'sep'      (returns array; caller can index)
   *   <expr> -join 'sep'       (array → string)
   *   N..M                     (range operator; bounded to 1024 elements)
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
   * (split before join when both appear left-to-right, mirroring PS),
   * range operator `N..M`, and primary terms (literal, `$var`, `$env:Y`,
   * `${var}`, here-strings, `$var[i]`, `$var.k`).
   *
   * The implementation is a tiny recursive-descent walker — operator
   * precedence is fixed at: primary → split → join → range → concat.
   * PowerShell's actual precedence is more elaborate, but the obfuscation
   * patterns we target only ever use these in left-to-right combinations.
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
        const trimmed = p.trim();
        // Empty-operand short-circuit: `'a' + '' + 'b'` would otherwise
        // recurse on a 0-char literal and return null. Treat empty
        // literals as empty strings explicitly.
        if (trimmed === "''" || trimmed === '""') { out.push(''); continue; }
        const v = this._psResolveExpression(trimmed, vars, envVars);
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

    // ── range: N..M  /  $var..$var  (integer endpoints only) ──
    //
    // Emits a numeric string-array so downstream `-join ''` / `[char[]]`
    // / `[i,j,k]` accessors pick it up uniformly. Capped at
    // _PS_RANGE_MAX_ELEMENTS elements to stop `0..65535 -join ''`-style
    // amp blowups. Negative ranges decrement (`-1..-5` = -1,-2,-3,-4,-5).
    const rangeM = /^([\s\S]+?)\s*\.\.\s*([\s\S]+)$/.exec(src);
    if (rangeM) {
      const lo = this._psResolveExpression(rangeM[1].trim(), vars, envVars);
      const hi = this._psResolveExpression(rangeM[2].trim(), vars, envVars);
      if (lo !== null && hi !== null
          && !Array.isArray(lo) && !Array.isArray(hi)) {
        const ls = String(lo);
        const hs = String(hi);
        if (/^-?\d+$/.test(ls) && /^-?\d+$/.test(hs)) {
          const n = parseInt(ls, 10);
          const m = parseInt(hs, 10);
          const span = Math.abs(m - n) + 1;
          if (span <= _PS_RANGE_MAX_ELEMENTS) {
            const arr = [];
            if (n <= m) for (let k = n; k <= m; k++) arr.push(String(k));
            else        for (let k = n; k >= m; k--) arr.push(String(k));
            return arr;
          }
          return null; // range too wide — refuse rather than blow budget
        }
      }
    }

    // ── primary terms ──
    return this._psResolvePrimary(src, vars, envVars);
  },

  /**
   * Resolve a primary term: literal, here-string, parenthesised
   * sub-expression, or variable reference (with optional `[i]` / `.k`
   * accessor). Supports both plain (`$var`, `$env:Y`) and braced
   * (`${var}`, `${env:Y}`) variable syntax.
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

    // Verbatim here-string: @'…\n…\n'@ — no interpolation, preserves
    // everything between the opener and the line-anchored closer. The
    // opener is `@'` followed by a newline; body runs until a line whose
    // leading non-whitespace is `'@`.
    if (src.startsWith("@'") && (src[2] === '\n' || src[2] === '\r')) {
      const end = src.indexOf("\n'@");
      if (end > 0) {
        // Body starts after `@'\n` (skip leading \r if CRLF).
        let bodyStart = 3;
        if (src[2] === '\r' && src[3] === '\n') bodyStart = 4;
        // Everything between bodyStart and the newline before `'@`.
        return src.substring(bodyStart, end);
      }
    }

    // Expandable here-string: @"…\n…\n"@ — $var and ${var} interp only.
    if (src.startsWith('@"') && (src[2] === '\n' || src[2] === '\r')) {
      const end = src.indexOf('\n"@');
      if (end > 0) {
        let bodyStart = 3;
        if (src[2] === '\r' && src[3] === '\n') bodyStart = 4;
        const inner = src.substring(bodyStart, end);
        return this._psInterpolate(inner, vars, envVars);
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

    // Double-quoted literal — handle `$var` / `${var}` / `$env:Y` /
    // `${env:Y}` interpolation, ignore subexpressions / casts.
    if (src.startsWith('"') && src.endsWith('"') && src.length >= 2) {
      const inner = src.slice(1, -1);
      if (/\$\(/.test(inner)) return null; // subexpressions unsupported
      return this._psInterpolate(inner, vars, envVars);
    }

    // Integer literal.
    if (/^-?\d+$/.test(src)) return src;

    // ${env:Y} — braced env-var form. Must come before ${var} so the
    // `env:` prefix isn't mistaken for a regular variable name.
    const envBraceM = /^\$\{env:([A-Za-z_][\w]*)\}\s*(.*)$/i.exec(src);
    if (envBraceM) {
      const name = envBraceM[1];
      const tail = envBraceM[2];
      const v = envVars.get(name);
      if (!v) return null;
      return this._psApplyAccessors(v, tail, vars, envVars);
    }

    // ${var} — braced var form.
    const varBraceM = /^\$\{([A-Za-z_][\w]*)\}\s*(.*)$/.exec(src);
    if (varBraceM) {
      const name = varBraceM[1];
      const tail = varBraceM[2];
      return this._psResolveVarName(name, tail, vars, envVars);
    }

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
      return this._psResolveVarName(varM[1], varM[2], vars, envVars);
    }

    // Bare alias reference (no `$`) — if a literal-target alias with
    // this name was registered by `sal`/`Set-Alias`/`New-Alias`, return
    // its string value. This is deliberately narrow: only matches a
    // standalone identifier with no accessor tail, so a random word
    // in a log line can't accidentally resolve.
    const aliasBareM = /^([A-Za-z_][\w]*)$/.exec(src);
    if (aliasBareM && this._psAliasScratch) {
      const hit = this._psAliasScratch.get(aliasBareM[1].toLowerCase());
      if (hit) return String(hit.value);
    }

    return null;
  },

  /**
   * Resolve a bare variable name (`$x` / `${x}`), falling back through
   * the vars table → automatic-variable defaults → registered alias
   * table → null. Applies any accessor tail uniformly.
   */
  _psResolveVarName(name, tail, vars, envVars) {
    let v = vars.get(name);
    if (!v) {
      // Fall back to PowerShell's well-known automatic variables.
      const auto = KNOWN_PS_AUTO_VARS[name.toLowerCase()];
      if (typeof auto === 'string' && auto.length > 0) {
        v = { kind: 'string', value: auto };
      } else if (this._psAliasScratch) {
        // Finally, alias lookup — `sal x iex; &($x)` resolves through
        // the alias table. Aliases are always string-kind.
        const hit = this._psAliasScratch.get(name.toLowerCase());
        if (hit) v = { kind: 'string', value: hit.value };
      }
      if (!v) return null;
    }
    return this._psApplyAccessors(v, tail, vars, envVars);
  },

  /**
   * Interpolate `$var`, `${var}`, `$env:Y`, `${env:Y}` inside a
   * double-quoted string body. Also strips PS backtick escapes.
   * Returns a plain string (possibly empty).
   */
  _psInterpolate(inner, vars, envVars) {
    // Handle the four variable shapes in priority order so `${env:X}`
    // isn't mistakenly consumed by the `${…}` or `$env:…` handlers.
    let out = inner.replace(/\$\{env:([A-Za-z_][\w]*)\}/gi, (_full, name) => {
      const v = envVars.get(name);
      return v ? String(v.value) : '';
    });
    out = out.replace(/\$env:([A-Za-z_][\w]*)/gi, (_full, name) => {
      const v = envVars.get(name);
      return v ? String(v.value) : '';
    });
    const lookupVar = (name) => {
      const v = vars.get(name);
      if (v) {
        if (v.kind === 'string') return String(v.value);
        if (v.kind === 'array')  return v.value.join(' ');
        return '';
      }
      const auto = KNOWN_PS_AUTO_VARS[name.toLowerCase()];
      if (typeof auto === 'string') return auto;
      if (this._psAliasScratch) {
        const hit = this._psAliasScratch.get(name.toLowerCase());
        if (hit) return String(hit.value);
      }
      return '';
    };
    out = out.replace(/\$\{([A-Za-z_][\w]*)\}/g, (_full, name) => lookupVar(name));
    out = out.replace(/\$([A-Za-z_][\w]*)/g, (_full, name) => lookupVar(name));
    // Strip PS backtick escapes (`n → newline, `t → tab, … — for the
    // obfuscation use case we just drop the backtick).
    out = out.replace(/`([\s\S])/g, '$1');
    return out;
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
