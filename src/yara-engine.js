'use strict';
// ════════════════════════════════════════════════════════════════════════════
// yara-engine.js — Lightweight in-browser YARA rule parser and matcher
// Supports: text strings, hex strings, regex strings, nocase/wide/ascii,
//           conditions: any/all of them, $var, and/or/not, N of them, #var > N
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
    // Strip C-style comments
    const cleaned = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*/g, '');

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
   * Validate YARA source without scanning.
   * @param {string} source
   * @returns {{ valid: boolean, errors: string[], ruleCount: number }}
   */
  static validate(source) {
    const { rules, errors } = YaraEngine.parseRules(source);
    return { valid: errors.length === 0 && rules.length > 0, errors, ruleCount: rules.length };
  }

  /**
   * Scan a buffer against parsed YARA rules.
   * @param {ArrayBuffer|Uint8Array} buffer  File content
   * @param {object[]} rules  Parsed rule objects from parseRules()
   * @returns {{ ruleName: string, tags: string, matches: { id: string, offsets: number[] }[] }[]}
   */
  static scan(buffer, rules) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    // Decode as latin-1 for string matching
    const textChunks = [];
    const CHUNK = 512 * 1024;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      textChunks.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK)));
    }
    const text = textChunks.join('');

    const results = [];
    for (const rule of rules) {
      const stringMatches = {};
      let anyMatch = false;

      // Evaluate each string definition
      for (const strDef of rule.strings) {
        const offsets = YaraEngine._findString(text, bytes, strDef);
        stringMatches[strDef.id] = offsets;
        if (offsets.length > 0) anyMatch = true;
      }

      // Evaluate condition
      const condResult = YaraEngine._evalCondition(rule.condition, stringMatches, rule.strings);
      if (condResult) {
        const matchDetails = [];
        for (const strDef of rule.strings) {
          if (stringMatches[strDef.id] && stringMatches[strDef.id].length > 0) {
            matchDetails.push({
              id: strDef.id,
              value: strDef.display || strDef.pattern,
              offsets: stringMatches[strDef.id].slice(0, 20) // Cap at 20 offsets for display
            });
          }
        }
        results.push({
          ruleName: rule.name,
          tags: rule.tags,
          meta: rule.meta,
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

  // ── Internal: Find all offsets of a string in the buffer ──────────────────

  static _findString(text, bytes, strDef) {
    const offsets = [];
    const MAX = 1000; // cap matches per string

    if (strDef.type === 'text') {
      const pattern = strDef.pattern;
      if (strDef.wide) {
        // Wide strings: each char followed by 0x00
        const widePat = [];
        for (let i = 0; i < pattern.length; i++) {
          widePat.push(pattern.charCodeAt(i));
          widePat.push(0);
        }
        for (let i = 0; i <= bytes.length - widePat.length && offsets.length < MAX; i++) {
          let match = true;
          for (let j = 0; j < widePat.length; j++) {
            let b = bytes[i + j];
            let p = widePat[j];
            if (strDef.nocase && j % 2 === 0) {
              b = b >= 0x41 && b <= 0x5A ? b + 0x20 : b;
              p = p >= 0x41 && p <= 0x5A ? p + 0x20 : p;
            }
            if (b !== p) { match = false; break; }
          }
          if (match) offsets.push(i);
        }
      } else {
        // ASCII text search
        const searchIn = strDef.nocase ? text.toLowerCase() : text;
        const searchFor = strDef.nocase ? pattern.toLowerCase() : pattern;
        let pos = 0;
        while (pos < searchIn.length && offsets.length < MAX) {
          const idx = searchIn.indexOf(searchFor, pos);
          if (idx === -1) break;
          if (strDef.fullword) {
            const before = idx > 0 ? searchIn[idx - 1] : ' ';
            const after = idx + searchFor.length < searchIn.length ? searchIn[idx + searchFor.length] : ' ';
            if (/\w/.test(before) || /\w/.test(after)) { pos = idx + 1; continue; }
          }
          offsets.push(idx);
          pos = idx + 1;
        }
      }
    } else if (strDef.type === 'hex') {
      // Parse hex pattern: { AA BB CC ?? DD [2-4] EE }
      const hexBytes = YaraEngine._parseHexPattern(strDef.pattern);
      if (hexBytes) {
        for (let i = 0; i <= bytes.length - hexBytes.length && offsets.length < MAX; i++) {
          let match = true;
          for (let j = 0; j < hexBytes.length; j++) {
            if (hexBytes[j] === -1) continue; // wildcard ??
            if (bytes[i + j] !== hexBytes[j]) { match = false; break; }
          }
          if (match) offsets.push(i);
        }
      }
    } else if (strDef.type === 'regex') {
      try {
        const rx = new RegExp(strDef.pattern, 'g' + (strDef.nocase ? 'i' : ''));
        let rm;
        while ((rm = rx.exec(text)) !== null && offsets.length < MAX) {
          offsets.push(rm.index);
          if (rm.index === rx.lastIndex) rx.lastIndex++; // avoid infinite loop on zero-width
        }
      } catch (_) { /* invalid regex — skip */ }
    }

    return offsets;
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

  static _evalCondition(condition, stringMatches, stringDefs) {
    const cond = condition.trim().toLowerCase();

    // "any of them"
    if (cond === 'any of them') {
      return Object.values(stringMatches).some(o => o.length > 0);
    }
    // "all of them"
    if (cond === 'all of them') {
      return stringDefs.length > 0 && stringDefs.every(s => stringMatches[s.id] && stringMatches[s.id].length > 0);
    }
    // "N of them"
    const nOf = cond.match(/^(\d+)\s+of\s+them$/);
    if (nOf) {
      const needed = parseInt(nOf[1]);
      const matched = Object.values(stringMatches).filter(o => o.length > 0).length;
      return matched >= needed;
    }
    // "#var > N" or "#var >= N"
    const countCond = cond.match(/^#(\$?\w+)\s*(>=?|<=?|==|!=)\s*(\d+)$/);
    if (countCond) {
      const varId = countCond[1].startsWith('$') ? countCond[1] : '$' + countCond[1];
      const count = (stringMatches[varId] || []).length;
      const val = parseInt(countCond[3]);
      switch (countCond[2]) {
        case '>':  return count > val;
        case '>=': return count >= val;
        case '<':  return count < val;
        case '<=': return count <= val;
        case '==': return count === val;
        case '!=': return count !== val;
      }
    }

    // Complex boolean: tokenize and evaluate
    return YaraEngine._evalBoolCondition(condition, stringMatches);
  }

  static _evalBoolCondition(condition, stringMatches) {
    // Simple recursive descent for: $a and $b, $a or $b, not $a, ($a), true, false
    const tokens = [];
    const rx = /(\$\w+|and|or|not|true|false|\(|\))/gi;
    let tm;
    while ((tm = rx.exec(condition)) !== null) {
      tokens.push(tm[1].toLowerCase());
    }

    let pos = 0;
    const peek = () => tokens[pos] || null;
    const next = () => tokens[pos++] || null;

    const parseOr = () => {
      let left = parseAnd();
      while (peek() === 'or') { next(); left = left || parseAnd(); }
      return left;
    };
    const parseAnd = () => {
      let left = parseNot();
      while (peek() === 'and') { next(); left = left && parseNot(); }
      return left;
    };
    const parseNot = () => {
      if (peek() === 'not') { next(); return !parseAtom(); }
      return parseAtom();
    };
    const parseAtom = () => {
      const t = next();
      if (t === '(') {
        const val = parseOr();
        if (peek() === ')') next();
        return val;
      }
      if (t === 'true') return true;
      if (t === 'false') return false;
      if (t && t.startsWith('$')) {
        return (stringMatches[t] || []).length > 0;
      }
      return false;
    };

    try {
      return tokens.length > 0 ? parseOr() : true;
    } catch (_) {
      return false;
    }
  }

  /**
   * Default example YARA rules for the editor template.
   * At build time, DEFAULT_YARA_RULES is injected from src/default-rules.yar
   */
  static get EXAMPLE_RULES() {
    return (typeof DEFAULT_YARA_RULES !== 'undefined') ? DEFAULT_YARA_RULES : '';
  }
}
