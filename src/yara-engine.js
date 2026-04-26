'use strict';
// ════════════════════════════════════════════════════════════════════════════
// yara-engine.js — Lightweight in-browser YARA rule parser and matcher
// Supports: text strings, hex strings, regex strings, nocase/wide/ascii,
//           conditions: any/all of them/set, $var at N, $var in (lo..hi),
//           N of ($prefix*), uint8/16/32, int8/16/32, filesize, #var, and/or/not
// ════════════════════════════════════════════════════════════════════════════

class YaraEngine {

  /**
   * Parse YARA rule source text into an array of rule objects.
   * @param {string} source  YARA rule text
   * @returns {{ rules: object[], errors: string[] }}
   */
  static parseRules(source) {
    const rules = [];
    const errors = [];
    // Strip comments while preserving string literals and regex literals.
    // Order matters: match strings first, then YARA regex literals of the form
    // `= /…/` (so a trailing `\/ /` inside a regex is not treated as a line
    // comment), then block and line comments.
    const cleaned = source.replace(
      /"(?:[^"\\]|\\.)*"|=\s*\/(?:[^/\\\n]|\\.)*\/[gismxuy]*|\/\*[\s\S]*?\*\/|\/\/[^\n]*/g,
      (m) => {
        const c = m[0];
        if (c === '"' || c === '=') return m;  // keep strings and regex literals
        return '';                              // strip comments
      }
    );

    // Match rule blocks:  rule <name> [: <tags>] { ... }
    const ruleRx = /\brule\s+(\w+)\s*(?::\s*([\w\s]+?))?\s*\{([\s\S]*?)\n\}/g;
    let m;
    while ((m = ruleRx.exec(cleaned)) !== null) {
      try {
        const rule = YaraEngine._parseRuleBody(m[1], (m[2] || '').trim(), m[3]);
        rules.push(rule);
      } catch (e) {
        errors.push(`Rule "${m[1]}": ${e.message}`);
      }
    }

    if (!rules.length && !errors.length && source.trim().length > 0) {
      errors.push('No valid YARA rules found. Check syntax: rule name { strings: ... condition: ... }');
    }
    return { rules, errors };
  }

  /**
   * Validate YARA source with structural and semantic checks.
   * @param {string} source
   * @returns {{ valid: boolean, errors: string[], warnings: string[], ruleCount: number }}
   */
  static validate(source) {
    const { rules, errors } = YaraEngine.parseRules(source);
    const warnings = [];

    // Re-parse rule blocks for structural validation on raw body text
    // Use original source (not comment-stripped) to avoid corrupting URL strings containing //
    const ruleRx2 = /\brule\s+(\w+)\s*(?::\s*([\w\s]+?))?\s*\{([\s\S]*?)\n\}/g;
    let m;
    while ((m = ruleRx2.exec(source)) !== null) {
      const sv = YaraEngine._validateRuleStructure(m[1], m[3]);
      for (const e of sv.errors)   errors.push(e);
      for (const w of sv.warnings) warnings.push(w);
    }

    // Validate each successfully parsed rule object
    for (const rule of rules) {
      const rv = YaraEngine._validateParsedRule(rule);
      for (const e of rv.errors)   errors.push(e);
      for (const w of rv.warnings) warnings.push(w);
    }

    // Duplicate rule names
    const seen = new Set();
    for (const rule of rules) {
      if (seen.has(rule.name)) errors.push('Duplicate rule name "' + rule.name + '"');
      seen.add(rule.name);
    }

    return { valid: errors.length === 0 && rules.length > 0, errors, warnings, ruleCount: rules.length };
  }

  // ── Internal: Structural validation of raw rule body text ─────────────────

  /**
   * Validate the raw body text of a rule for structural issues.
   * @param {string} name  Rule name
   * @param {string} body  Raw text between rule { and closing }
   * @returns {{ errors: string[], warnings: string[] }}
   */
  static _validateRuleStructure(name, body) {
    const errors = [];
    const warnings = [];
    const p = 'Rule "' + name + '": ';

    // Rule name cannot start with a digit
    if (/^\d/.test(name)) {
      errors.push(p + 'name cannot start with a digit');
    }

    // ── Missing colons after section keywords ────────────────────────────
    const hasMetaColon    = /\bmeta\s*:/i.test(body);
    const hasStringsColon = /\bstrings\s*:/i.test(body);
    const hasCondColon    = /\bcondition\s*:/i.test(body);

    if (!hasMetaColon && /^\s*meta\s*$/im.test(body)) {
      errors.push(p + 'missing colon after "meta" \u2014 should be "meta:"');
    }
    if (!hasStringsColon && /^\s*strings\s*$/im.test(body)) {
      errors.push(p + 'missing colon after "strings" \u2014 should be "strings:"');
    }
    if (!hasCondColon) {
      if (/^\s*condition\s*$/im.test(body)) {
        errors.push(p + 'missing colon after "condition" \u2014 should be "condition:"');
      } else {
        errors.push(p + 'missing required "condition:" section');
      }
    }

    // ── Empty condition body ─────────────────────────────────────────────
    if (hasCondColon) {
      const cm = body.match(/\bcondition\s*:([\s\S]*?)$/i);
      if (cm && !cm[1].trim()) {
        errors.push(p + 'empty condition body');
      }
    }

    // ── Unclosed string literals (per-line assignment = "..." check) ─────
    const lines = body.split('\n');
    const assignQt = /(?:\$\w+|\w+)\s*=\s*"/g;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].trim().startsWith('//')) continue; // skip comment lines
      assignQt.lastIndex = 0;
      let qm;
      while ((qm = assignQt.exec(lines[i])) !== null) {
        let closed = false;
        for (let j = qm.index + qm[0].length; j < lines[i].length; j++) {
          if (lines[i][j] === '\\') { j++; continue; }
          if (lines[i][j] === '"') { closed = true; assignQt.lastIndex = j + 1; break; }
        }
        if (!closed) {
          const snip = lines[i].trim();
          errors.push(p + 'unclosed string literal: ' +
            (snip.length > 60 ? snip.slice(0, 60) + '\u2026' : snip));
          break; // one error per line
        }
      }
    }

    // ── Unclosed hex patterns (= { without matching }) ───────────────────
    const hexOpenRx = /=\s*\{/g;
    let hm;
    while ((hm = hexOpenRx.exec(body)) !== null) {
      const rest = body.substring(hm.index + hm[0].length);
      if (rest.indexOf('}') === -1) {
        errors.push(p + 'unclosed hex pattern \u2014 missing closing "}"');
        break; // remaining opens are subsumed by this
      }
    }

    return { errors, warnings };
  }

  // ── Internal: Validation of a parsed rule object ──────────────────────────

  /**
   * Validate a successfully parsed rule for semantic issues.
   * @param {object} rule  Parsed rule from _parseRuleBody
   * @returns {{ errors: string[], warnings: string[] }}
   */
  static _validateParsedRule(rule) {
    const errors = [];
    const warnings = [];
    const p = 'Rule "' + rule.name + '": ';

    // ── Duplicate string identifiers ─────────────────────────────────────
    const ids = new Set();
    for (const s of rule.strings) {
      if (ids.has(s.id)) errors.push(p + 'duplicate string identifier "' + s.id + '"');
      ids.add(s.id);
    }

    // ── Condition references to undefined strings ($var, #var, @var) ─────
    const defined = new Set(rule.strings.map(s => s.id.toLowerCase()));
    const cond = rule.condition || '';
    const refRx = /(\$\w+\*?|#\w+|@\w+)/g;
    let cv;
    const checked = new Set();
    while ((cv = refRx.exec(cond)) !== null) {
      const ref = cv[1];
      if (ref.endsWith('*')) continue; // wildcard prefix \u2014 skip
      const vid = (ref[0] === '$' ? ref : '$' + ref.substring(1)).toLowerCase();
      if (checked.has(vid)) continue;
      checked.add(vid);
      if (!defined.has(vid)) {
        errors.push(p + 'condition references undefined string "' + ref + '"');
      }
    }

    // ── Invalid severity value ───────────────────────────────────────────
    if (rule.meta && rule.meta.severity) {
      const sev = rule.meta.severity.toLowerCase();
      if (!['critical', 'high', 'medium', 'low', 'info'].includes(sev)) {
        warnings.push(p + 'unknown severity "' + rule.meta.severity +
          '" \u2014 expected: critical, high, medium, low, info');
      }
    }

    // ── Hex pattern token validation ─────────────────────────────────────
    for (const s of rule.strings) {
      if (s.type === 'hex') {
        const inner = s.pattern.replace(/[{}]/g, '').trim();
        if (!inner) { errors.push(p + 'empty hex pattern in ' + s.id); continue; }
        const tokens = inner.split(/\s+/);
        for (const tok of tokens) {
          if (!tok) continue;
          if (tok === '??' || tok === '?') continue;                            // wildcard
          if (/^[0-9a-fA-F]{2}$/.test(tok)) continue;                          // valid byte
          if (/^\[[\d\-]+\]$/.test(tok)) continue;                             // jump range
          if (/^[()]$/.test(tok) || tok === '|' || tok === '~') continue;       // alternation
          if (/^[0-9a-fA-F]\?$/.test(tok) || /^\?[0-9a-fA-F]$/.test(tok)) continue; // nibble
          errors.push(p + 'invalid hex token "' + tok + '" in ' + s.id);
        }
      }
    }

    // ── Regex compilation check ──────────────────────────────────────────
    for (const s of rule.strings) {
      if (s.type === 'regex') {
        try { new RegExp(s.pattern, (s.flags || '').replace(/[^gimsuy]/g, '')); }
        catch (e) { errors.push(p + 'invalid regex ' + s.id + ': ' + e.message); }
      }
    }

    return { errors, warnings };
  }

  /**
   * Scan a buffer against parsed YARA rules.
   *
   * The optional fourth `opts` arg is a diagnostics sink — when present, any
   * per-string failure (invalid regex, iteration cap, wall-clock cap) is
   * appended to `opts.errors` as
   * `{ ruleName, stringId, reason: 'invalid-regex'|'iter-cap'|'time-cap', message }`.
   * Callers that pass three args (the legacy shape) get the historical
   * silent-skip behaviour, since `_findString` no-ops on a missing sink.
   *
   * @param {ArrayBuffer|Uint8Array} buffer  File content
   * @param {object[]} rules  Parsed rule objects from parseRules()
   * @param {object?}  opts   Optional `{ errors: [] }` diagnostics sink.
   * @returns {{ ruleName: string, tags: string, meta: object, condition: string, matches: { id: string, value: string, matches: {offset: number, length: number}[] }[] }[]}
   */
  static scan(buffer, rules, opts) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    // Decode as latin-1 for string matching
    const textChunks = [];
    const CHUNK = 32 * 1024;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      textChunks.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK)));
    }
    const text = textChunks.join('');

    const errorSink = (opts && Array.isArray(opts.errors)) ? opts.errors : null;

    const results = [];
    for (const rule of rules) {
      const stringMatches = {};
      // Evaluate each string definition
      for (const strDef of rule.strings) {
        const matchList = YaraEngine._findString(text, bytes, strDef, errorSink, rule.name);
        stringMatches[strDef.id] = matchList;

      }

      // Evaluate condition
      const condResult = YaraEngine._evalCondition(rule.condition, stringMatches, rule.strings, bytes);
      if (condResult) {
        const matchDetails = [];
        for (const strDef of rule.strings) {
          if (stringMatches[strDef.id] && stringMatches[strDef.id].length > 0) {
            matchDetails.push({
              id: strDef.id,
              value: strDef.display || strDef.pattern,
              matches: stringMatches[strDef.id].slice(0, 20) // Cap at 20 matches for display
            });
          }
        }
        results.push({
          ruleName: rule.name,
          tags: rule.tags,
          meta: rule.meta,
          condition: rule.condition,
          matches: matchDetails
        });
      }
    }
    return results;
  }

  // ── Internal: Parse a single rule body ────────────────────────────────────

  static _parseRuleBody(name, tags, body) {
    const rule = { name, tags, strings: [], condition: 'any of them', meta: {} };

    // Extract meta section
    const metaMatch = body.match(/meta\s*:([\s\S]*?)(?=strings\s*:|condition\s*:|$)/i);
    if (metaMatch) {
      const metaBlock = metaMatch[1];
      const metaRx = /(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"/g;
      let mm;
      while ((mm = metaRx.exec(metaBlock)) !== null) {
        rule.meta[mm[1]] = mm[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
      }
    }

    // Extract strings section
    const stringsMatch = body.match(/strings\s*:([\s\S]*?)(?=condition\s*:|$)/i);
    if (stringsMatch) {
      const stringsBlock = stringsMatch[1];
      // Match each string definition: $id = "text" or $id = { hex } or $id = /regex/
      const strRx = /(\$\w+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"\s*(nocase|wide|ascii|fullword|\s)*|(\{[\s\S]*?\})\s*(nocase|wide|ascii|\s)*|\/((?:[^/\\]|\\.)*)\/\s*([is]*)\s*(nocase|wide|ascii|\s)*)/g;
      let sm;
      while ((sm = strRx.exec(stringsBlock)) !== null) {
        if (sm[2] !== undefined) {
          // Text string
          const modifiers = (sm[3] || '').trim().toLowerCase();
          rule.strings.push({
            id: sm[1],
            type: 'text',
            pattern: sm[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\'),
            display: `"${sm[2]}"`,
            nocase: modifiers.includes('nocase'),
            wide: modifiers.includes('wide'),
            fullword: modifiers.includes('fullword')
          });
        } else if (sm[4]) {
          // Hex string
          rule.strings.push({
            id: sm[1],
            type: 'hex',
            pattern: sm[4],
            display: sm[4],
            nocase: false, wide: false, fullword: false
          });
        } else if (sm[6] !== undefined) {
          // Regex string
          const flags = sm[7] || '';
          const modifiers = (sm[8] || '').trim().toLowerCase();
          rule.strings.push({
            id: sm[1],
            type: 'regex',
            pattern: sm[6],
            flags: flags + (modifiers.includes('nocase') ? 'i' : ''),
            display: `/${sm[6]}/${flags}`,
            nocase: flags.includes('i') || modifiers.includes('nocase'),
            wide: modifiers.includes('wide'),
            fullword: false
          });
        }
      }
    }

    // Extract condition
    const condMatch = body.match(/condition\s*:([\s\S]*?)$/i);
    if (condMatch) {
      rule.condition = condMatch[1].trim();
    }

    return rule;
  }

  // ── Internal: Find all matches of a string in the buffer ───────────────────
  // Returns array of { offset, length } objects for precise highlighting.
  //
  // Regex strings are bounded by three independent budgets — all three were
  // historically absent, so a single pathological pattern (e.g. nested
  // quantifiers over a 200 KB head) could stall the entire scan:
  //   • `MAX` (1000)        — match objects retained per string (display cap)
  //   • `MAX_REGEX_ITERS`   — total `rx.exec` iterations before giving up
  //   • `TIME_BUDGET_MS`    — wall-clock cap per string for regex matching
  // Compile failures, hits on either runtime budget, and exec exceptions
  // are appended to `errorSink` (when non-null) as a structured record so
  // `app-yara.js` can surface them to the user instead of silently
  // dropping the rule.
  //
  // Compiled `RegExp` instances are memoised on the strDef itself
  // (`_compiledRx`) — `parseRules()` is called once per scan but the same
  // parsed-rule objects survive across the auto-scan, manual scan, and
  // filter passes, so the cache is a real win.
  static _findString(text, bytes, strDef, errorSink, ruleName) {
    const matches = [];
    const MAX = 1000; // cap matches per string
    const MAX_REGEX_ITERS = 10000;
    const TIME_BUDGET_MS = 250;

    const recordError = (reason, message) => {
      if (!errorSink) return;
      errorSink.push({
        ruleName: ruleName || '',
        stringId: strDef.id,
        reason,
        message,
      });
    };


    if (strDef.type === 'text') {
      const pattern = strDef.pattern;
      if (strDef.wide) {
        // Wide strings: each char followed by 0x00
        const widePat = [];
        for (let i = 0; i < pattern.length; i++) {
          widePat.push(pattern.charCodeAt(i));
          widePat.push(0);
        }
        const matchLen = widePat.length;
        for (let i = 0; i <= bytes.length - matchLen && matches.length < MAX; i++) {
          let match = true;
          for (let j = 0; j < matchLen; j++) {
            let b = bytes[i + j];
            let p = widePat[j];
            if (strDef.nocase && j % 2 === 0) {
              b = b >= 0x41 && b <= 0x5A ? b + 0x20 : b;
              p = p >= 0x41 && p <= 0x5A ? p + 0x20 : p;
            }
            if (b !== p) { match = false; break; }
          }
          if (match) matches.push({ offset: i, length: matchLen });
        }
      } else {
        // ASCII text search
        const searchIn = strDef.nocase ? text.toLowerCase() : text;
        const searchFor = strDef.nocase ? pattern.toLowerCase() : pattern;
        const matchLen = pattern.length;
        let pos = 0;
        while (pos < searchIn.length && matches.length < MAX) {
          const idx = searchIn.indexOf(searchFor, pos);
          if (idx === -1) break;
          if (strDef.fullword) {
            const before = idx > 0 ? searchIn[idx - 1] : ' ';
            const after = idx + matchLen < searchIn.length ? searchIn[idx + matchLen] : ' ';
            if (/\w/.test(before) || /\w/.test(after)) { pos = idx + 1; continue; }
          }
          matches.push({ offset: idx, length: matchLen });
          pos = idx + 1;
        }
      }
    } else if (strDef.type === 'hex') {
      // Parse hex pattern: { AA BB CC ?? DD [2-4] EE }
      const hexBytes = YaraEngine._parseHexPattern(strDef.pattern);
      if (hexBytes) {
        const matchLen = hexBytes.length;
        for (let i = 0; i <= bytes.length - matchLen && matches.length < MAX; i++) {
          let match = true;
          for (let j = 0; j < matchLen; j++) {
            if (hexBytes[j] === -1) continue; // wildcard ??
            if (bytes[i + j] !== hexBytes[j]) { match = false; break; }
          }
          if (match) matches.push({ offset: i, length: matchLen });
        }
      }
    } else if (strDef.type === 'regex') {
      // Compile-once cache. The same parsed-rule objects are reused across
      // the auto-scan, manual scan, and post-match filter passes; recompiling
      // each time is pure waste. `_compiledRx` is `null` after a failed
      // compile so we don't retry every scan.
      let rx = strDef._compiledRx;
      if (rx === undefined) {
        try {
          rx = new RegExp(strDef.pattern, 'g' + (strDef.nocase ? 'i' : ''));
        } catch (e) {
          rx = null;
          recordError('invalid-regex', (e && e.message) ? e.message : String(e));
        }
        strDef._compiledRx = rx;
      }
      if (rx) {
        // Reset the global flag's lastIndex — the cached `rx` is shared
        // across scans so a previous run could leave it past the end of
        // the new buffer's text.
        rx.lastIndex = 0;
        const t0 = Date.now();
        let iters = 0;
        let stopped = null;
        try {
          let rm;
          while ((rm = rx.exec(text)) !== null && matches.length < MAX) {
            iters++;
            if (iters >= MAX_REGEX_ITERS) { stopped = 'iter-cap'; break; }
            // Cheap clock check: only sample once every 256 iters.
            if ((iters & 0xff) === 0 && (Date.now() - t0) > TIME_BUDGET_MS) {
              stopped = 'time-cap';
              break;
            }
            matches.push({ offset: rm.index, length: rm[0].length });
            if (rm.index === rx.lastIndex) rx.lastIndex++; // avoid infinite loop on zero-width
          }
        } catch (e) {
          recordError('exec-error', (e && e.message) ? e.message : String(e));
        }
        if (stopped === 'iter-cap') {
          recordError('iter-cap',
            'regex iteration cap reached (' + MAX_REGEX_ITERS + ') — pattern truncated');
        } else if (stopped === 'time-cap') {
          recordError('time-cap',
            'regex time budget exceeded (' + TIME_BUDGET_MS + 'ms) — pattern truncated');
        }
      }
    }


    return matches;
  }

  // ── Internal: Parse hex pattern string ────────────────────────────────────

  static _parseHexPattern(pat) {
    // Strip braces and whitespace
    const inner = pat.replace(/[{}]/g, '').trim();
    const tokens = inner.split(/\s+/);
    const result = [];
    for (const tok of tokens) {
      if (tok === '??' || tok === '?') {
        result.push(-1); // wildcard
      } else if (/^[0-9A-Fa-f]{2}$/.test(tok)) {
        result.push(parseInt(tok, 16));
      } else if (/^\[[\d-]+\]$/.test(tok)) {
        // Jump — simplified: treat as wildcards for the minimum count
        const jm = tok.match(/\[(\d+)/);
        if (jm) for (let i = 0; i < parseInt(jm[1]); i++) result.push(-1);
      }
      // Skip other tokens we can't handle
    }
    return result.length > 0 ? result : null;
  }

  // ── Internal: Evaluate condition expression ───────────────────────────────

  static _evalCondition(condition, stringMatches, stringDefs, bytes) {
    const cond = condition.trim().toLowerCase();

    // Fast-path: "any of them"
    if (cond === 'any of them') {
      return Object.values(stringMatches).some(o => o.length > 0);
    }
    // Fast-path: "all of them"
    if (cond === 'all of them') {
      return stringDefs.length > 0 && stringDefs.every(s => stringMatches[s.id] && stringMatches[s.id].length > 0);
    }
    // Fast-path: "N of them"
    const nOf = cond.match(/^(\d+)\s+of\s+them$/);
    if (nOf) {
      const needed = parseInt(nOf[1]);
      const matched = Object.values(stringMatches).filter(o => o.length > 0).length;
      return matched >= needed;
    }
    // Fast-path: "#var > N" (whole-condition shorthand)
    const countCond = cond.match(/^#(\$?\w+)\s*(>=?|<=?|==|!=)\s*(\d+)$/);
    if (countCond) {
      const varId = countCond[1].startsWith('$') ? countCond[1] : '$' + countCond[1];
      const count = (stringMatches[varId] || []).length;
      const val = parseInt(countCond[3]);
      switch (countCond[2]) {
        case '>': return count > val;
        case '>=': return count >= val;
        case '<': return count < val;
        case '<=': return count <= val;
        case '==': return count === val;
        case '!=': return count !== val;
      }
    }

    // Complex boolean: full expression parser
    return YaraEngine._evalBoolCondition(condition, stringMatches, stringDefs, bytes);
  }

  // ── Internal: Full YARA condition expression evaluator ─────────────────────
  // Recursive-descent parser supporting:
  //   $var, $var at N, $var in (lo..hi), #var (count), N of (set),
  //   any/all of (set), uint8/16/32(N), int8/16/32(N), filesize,
  //   boolean and/or/not, comparison operators ==  !=  >  <  >=  <=

  static _evalBoolCondition(condition, stringMatches, stringDefs, bytes) {
    // Normalise string-match keys to lowercase for consistent lookup
    const sm = {};
    for (const key of Object.keys(stringMatches)) sm[key.toLowerCase()] = stringMatches[key];
    const allIds = stringDefs.map(s => s.id.toLowerCase());

    // ── Tokenise ────────────────────────────────────────────────────────────
    const tokens = [];
    const rx = /(\$[\w*]+|#\w+|uint(?:8|16|32)|int(?:8|16|32)|0x[0-9a-fA-F]+|\d+|!=|==|>=|<=|>|<|\.\.|and|or|not|at|of|in|them|any|all|filesize|true|false|[(),])/gi;
    let tm;
    while ((tm = rx.exec(condition)) !== null) tokens.push(tm[1]);

    let pos = 0;
    const peek = () => pos < tokens.length ? tokens[pos] : null;
    const next = () => pos < tokens.length ? tokens[pos++] : null;
    const lc   = (t) => t ? t.toLowerCase() : null;

    // ── Grammar ─────────────────────────────────────────────────────────────
    //  expr        → or_expr
    //  or_expr     → and_expr ('or' and_expr)*
    //  and_expr    → not_expr ('and' not_expr)*
    //  not_expr    → 'not' not_expr | comparison
    //  comparison  → value (comp_op value)?
    //  value       → '(' expr ')' | '$var' ['at' N | 'in' '(' N '..' N ')']
    //              | '#var' | number ['of' set] | 'any'|'all' 'of' set
    //              | uint/int func | 'filesize' | 'true' | 'false'

    const parseOr = () => {
      let left = parseAnd();
      while (lc(peek()) === 'or') {
        next();
        const right = parseAnd();   // always evaluate — never short-circuit token consumption
        left = left || right;
      }
      return left;
    };

    const parseAnd = () => {
      let left = parseNot();
      while (lc(peek()) === 'and') {
        next();
        const right = parseNot();   // always evaluate — never short-circuit token consumption
        left = left && right;
      }
      return left;
    };

    const parseNot = () => {
      if (lc(peek()) === 'not') { next(); return !parseNot(); }
      return parseComparison();
    };

    const parseComparison = () => {
      const left = parseValue();
      const op = peek();
      if (op && /^(!=|==|>=|<=|>|<)$/.test(op)) {
        next();
        const right = parseValue();
        switch (op) {
          case '==': return left == right;
          case '!=': return left != right;
          case '>=': return left >= right;
          case '<=': return left <= right;
          case '>':  return left > right;
          case '<':  return left < right;
        }
      }
      return left;
    };

    const parseValue = () => {
      const t = peek();
      if (t === null) return false;
      const tl = lc(t);

      // ── Grouping: ( expr ) ──────────────────────────────────────────────
      if (t === '(') {
        next();
        const val = parseOr();
        if (peek() === ')') next();
        return val;
      }

      // ── Boolean literals ────────────────────────────────────────────────
      if (tl === 'true')  { next(); return true; }
      if (tl === 'false') { next(); return false; }

      // ── String variable: $var [at N | in (lo..hi)] ──────────────────────
      if (t.startsWith('$') && !t.includes('*')) {
        next();
        const varId = tl;
        const matches = sm[varId] || [];

        // $var at <offset>
        if (lc(peek()) === 'at') {
          next();
          const offset = parseValue();
          return matches.some(m => m.offset === offset);
        }
        // $var in (<lo>..<hi>)
        if (lc(peek()) === 'in') {
          next();
          if (peek() === '(') next();
          const lo = parseValue();
          if (lc(peek()) === '..') next();
          const hi = parseValue();
          if (peek() === ')') next();
          return matches.some(m => m.offset >= lo && m.offset <= hi);
        }
        // bare $var — true if at least one match
        return matches.length > 0;
      }

      // ── Count reference: #var ───────────────────────────────────────────
      if (t.startsWith('#')) {
        next();
        const varId = '$' + tl.substring(1);
        return (sm[varId] || []).length;
      }

      // ── any of … | all of … ────────────────────────────────────────────
      if (tl === 'any' || tl === 'all') {
        next();
        if (lc(peek()) === 'of') {
          next();
          const set = parseOfSet();
          if (tl === 'any') return set.some(id => (sm[id] || []).length > 0);
          return set.length > 0 && set.every(id => (sm[id] || []).length > 0);
        }
        return false;
      }

      // ── Numeric literal (may begin "N of …") ───────────────────────────
      if (/^(0x[0-9a-f]+|\d+)$/i.test(t)) {
        next();
        const num = tl.startsWith('0x') ? parseInt(t, 16) : parseInt(t, 10);
        if (lc(peek()) === 'of') {
          next();
          const set = parseOfSet();
          const count = set.filter(id => (sm[id] || []).length > 0).length;
          return count >= num;
        }
        return num;
      }

      // ── Integer functions: uint8/16/32(N), int8/16/32(N) ────────────────
      if (/^u?int(?:8|16|32)$/i.test(tl)) {
        next();
        if (peek() === '(') next();
        const offset = parseValue();
        if (peek() === ')') next();
        return YaraEngine._readInt(bytes, tl, offset);
      }

      // ── filesize ────────────────────────────────────────────────────────
      if (tl === 'filesize') {
        next();
        return bytes ? bytes.length : 0;
      }

      // Unknown token — skip
      next();
      return false;
    };

    // Parse set specifier after "of":  them | ($a, $b, …) | ($prefix*)
    const parseOfSet = () => {
      if (lc(peek()) === 'them') { next(); return allIds; }
      if (peek() === '(') {
        next();
        const ids = [];
        while (peek() && peek() !== ')') {
          const tok = next();
          if (tok === ',') continue;
          if (tok && tok.startsWith('$')) {
            const tokLower = tok.toLowerCase();
            if (tok.includes('*')) {
              const prefix = tokLower.replace(/\*+$/, '');
              for (const id of allIds) { if (id.startsWith(prefix)) ids.push(id); }
            } else {
              ids.push(tokLower);
            }
          }
        }
        if (peek() === ')') next();
        return ids;
      }
      return allIds; // fallback: treat bare "of" without set as "of them"
    };

    try {
      return tokens.length > 0 ? !!parseOr() : true;
    } catch (_) {
      return false;
    }
  }

  // ── Internal: Read integer from buffer (little-endian, matching YARA) ─────

  static _readInt(bytes, func, offset) {
    if (!bytes || offset < 0 || offset + 1 > bytes.length) return 0;
    const f = func.toLowerCase();
    const signed = f.startsWith('int') && !f.startsWith('uint');
    const bits = parseInt(f.replace(/^u?int/, ''));
    try {
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      switch (bits) {
        case 8:  return signed ? dv.getInt8(offset) : dv.getUint8(offset);
        case 16: return signed ? dv.getInt16(offset, true) : dv.getUint16(offset, true);
        case 32: return signed ? dv.getInt32(offset, true) : dv.getUint32(offset, true);
      }
    } catch (_) { /* offset out of bounds */ }
    return 0;
  }

  /**
   * Default example YARA rules for the editor template.
   * At build time, DEFAULT_YARA_RULES is injected from src/default-rules.yar
   */
  static get EXAMPLE_RULES() {
    return (typeof DEFAULT_YARA_RULES !== 'undefined') ? DEFAULT_YARA_RULES : '';
  }
}
