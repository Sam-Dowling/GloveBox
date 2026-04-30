'use strict';
// ════════════════════════════════════════════════════════════════════════════
// yara-engine.js — Lightweight in-browser YARA rule parser and matcher
// Supports: text strings, hex strings, regex strings, nocase/wide/ascii,
//           conditions: any/all of them/set, $var at N, $var in (lo..hi),
//           N of ($prefix*), uint8/16/32, int8/16/32, filesize, #var, and/or/not
//
// Format-aware predicates (Loupe extension)
// -----------------------------------------
// The host (`src/render-route.js`) passes a `formatTag` string into
// `YaraEngine.scan(buffer, rules, { context: { formatTag } })`. The tag is
// usually the same as `RendererRegistry.detect()`'s `dispatchId` ("pe", "lnk",
// "rtf", "svg", "plist", etc.) but for files Loupe routes to `plaintext` it
// can be a script-language hint produced by `RendererRegistry._sniffScriptKind`
// ("ps1", "bash", "bat", "vbs", "js", "py", "perl"). Rules consume it two ways:
//
//   1. `is_*` boolean keywords inside `condition:`. The full keyword set is
//      `YaraEngine.FORMAT_PREDICATES` below; each maps to a list of allowed
//      `formatTag` values. `is_office`, `is_zip_container`, `is_script` etc.
//      are group aliases. The expression evaluator treats `is_*` as a value-
//      producing terminal so `not is_pe`, `is_pe and 2 of them`, and any
//      boolean composition just work.
//
//   2. `meta: applies_to = "..."` (comma- or whitespace-separated). When
//      present the entire rule is short-circuited unless the current
//      `formatTag` matches one of the listed tags or group aliases. The
//      string-match phase is also skipped, so unrelated rules cost ~zero on
//      mismatched files. Absent `applies_to` ⇒ legacy behaviour (rule always
//      runs).
//
// Backward compatibility: callers that pass no `context` (or `formatTag` is
// undefined) get the historical behaviour — `is_*` evaluates to `false` and
// rules with `applies_to` are skipped (safe default; nothing in the legacy
// corpus uses either feature). The Loupe in-app pipeline always supplies
// `formatTag` from `app.currentResult.formatTag`.
// ════════════════════════════════════════════════════════════════════════════

class YaraEngine {

  /**
   * Format predicate map. Keys are `is_*` keywords usable in a rule's
   * `condition:`; values are the `formatTag` strings that satisfy them.
   * `meta: applies_to` accepts the same keys (treated as group aliases) **or**
   * any individual `formatTag` string from this table.
   *
   * The host computes `formatTag` from `RendererRegistry.detect()`'s
   * `dispatchId` (and, for plaintext, `_sniffScriptKind`). When extending
   * either side, keep them in lockstep — `_validateAppliesTo` warns on
   * unknown tokens so typos surface in the editor's validate pass.
   */
  static FORMAT_PREDICATES = Object.freeze({
    // ── Binaries ────────────────────────────────────────────────────────
    is_pe:              ['pe'],
    is_elf:             ['elf'],
    is_macho:           ['macho'],
    is_native_binary:   ['pe', 'elf', 'macho'],
    is_wasm:            ['wasm'],

    // ── Documents / Office ──────────────────────────────────────────────
    is_pdf:             ['pdf'],
    is_rtf:             ['rtf'],
    is_office_legacy:   ['doc', 'xls', 'ppt', 'msg', 'msi'],
    is_office_ooxml:    ['docx', 'xlsx', 'pptx'],
    is_office_odf:      ['odt', 'ods', 'odp'],
    is_office:          ['doc', 'xls', 'ppt', 'msg', 'msi',
                         'docx', 'xlsx', 'pptx', 'odt', 'ods', 'odp'],
    is_onenote:         ['onenote'],

    // ── Web / markup ────────────────────────────────────────────────────
    is_svg:             ['svg'],
    is_html:            ['html', 'hta'],
    is_hta:             ['hta'],
    is_xml_like:        ['svg', 'html', 'hta', 'plist', 'wsf', 'clickonce'],

    // ── Containers / archives ───────────────────────────────────────────
    is_zip_plain:       ['zip'],
    is_zip_container:   ['zip', 'docx', 'xlsx', 'pptx', 'msix', 'browserext',
                         'jar', 'odt', 'ods', 'odp', 'npm'],
    is_archive:         ['zip', 'rar', 'sevenz', 'cab', 'iso', 'dmg', 'pkg'],
    is_jar:             ['jar'],
    is_msi:             ['msi'],
    is_msix:            ['msix'],
    is_browserext:      ['browserext'],
    is_npm:             ['npm'],
    is_cab:             ['cab'],
    is_rar:             ['rar'],
    is_sevenz:          ['sevenz'],
    is_iso:             ['iso'],
    is_dmg:             ['dmg'],
    is_pkg:             ['pkg'],

    // ── Windows shell / shortcuts ───────────────────────────────────────
    is_lnk:             ['lnk'],
    is_url_shortcut:    ['url'],
    is_reg:             ['reg'],
    is_inf:             ['inf'],
    is_iqyslk:          ['iqyslk'],

    // ── macOS / Apple ───────────────────────────────────────────────────
    is_plist:           ['plist'],
    is_osascript:       ['scpt'],
    is_apple_format:    ['plist', 'scpt', 'macho', 'pkg', 'dmg'],

    // ── Scripts (sniffed plaintext subtypes + named-script formats) ─────
    is_powershell:      ['ps1'],
    is_bash:            ['bash'],
    is_bat:             ['bat'],
    is_vbs:             ['vbs'],
    is_javascript:      ['js'],
    is_python:          ['py'],
    is_perl:            ['perl'],
    is_wsf:             ['wsf'],
    is_clickonce:       ['clickonce'],
    is_script:          ['ps1', 'bash', 'bat', 'vbs', 'js', 'py', 'perl',
                         'scpt', 'wsf', 'hta', 'inf'],

    // ── Email / certs / DBs ─────────────────────────────────────────────
    is_eml:             ['eml'],
    is_msg:             ['msg'],
    is_email:           ['eml', 'msg'],
    is_pgp:             ['pgp'],
    is_x509:            ['x509'],
    is_sqlite:          ['sqlite'],
    is_evtx:            ['evtx'],
    is_image:           ['image'],
    is_pcap:            ['pcap'],

    // ── Plaintext / catch-alls ──────────────────────────────────────────
    is_plaintext:       ['plaintext'],

    // ── Decoded-payload tier (Loupe extension) ──────────────────────────
    // Synthetic format tag stamped by `decoded-yara-filter.js` when the
    // host re-scans decoded encoded-content payloads (post-Base64,
    // post-XOR, post-decompression, …). Rules tagged
    // `applies_to = "decoded-payload"` opt in to running against these
    // tiny synthetic buffers and serve as the "is this decode actually
    // interesting?" gate that boosts encoded-content retention. Rules
    // NOT tagged with `decoded-payload` (the default) skip the second
    // pass entirely, keeping the per-payload scan cost proportional to
    // the curated subset of script / shellcode / LOLBin rules that make
    // sense on a fragment of decoded bytes (see
    // `src/decoded-yara-filter.js` for the dispatch site).
    is_decoded_payload: ['decoded-payload'],

    // ── Universal alias ─────────────────────────────────────────────────
    // `applies_to = "any"` resolves to *every* known formatTag. This is
    // the escape hatch for rules that want to remain universal while
    // ALSO opting into the decoded-payload second pass — they declare
    // `applies_to = "any, decoded-payload"` and `_matchesAppliesTo`
    // returns true for any host-detected format AND for the synthetic
    // `decoded-payload` formatTag stamped by `decoded-yara-filter.js`.
    // Without this alias, adding `applies_to = "decoded-payload"` to a
    // previously-untagged universal rule would silently restrict it to
    // decoded payloads only — a behavioural regression. The token list
    // is computed lazily so new format tags introduced later are
    // automatically included; see `_resolveAppliesToToken`.
  });

  /**
   * All `formatTag` values that the host can produce, derived from the
   * union of FORMAT_PREDICATES values. Used for `applies_to` validation.
   */
  static get _KNOWN_FORMAT_TAGS() {
    if (this.__knownTags) return this.__knownTags;
    const set = new Set();
    for (const list of Object.values(this.FORMAT_PREDICATES)) {
      for (const tag of list) set.add(tag);
    }
    return (this.__knownTags = set);
  }

  /**
   * Resolve a single `applies_to` token to the list of tags it accepts.
   * Accepts both group aliases (the `is_*` key with the `is_` prefix
   * optional, e.g. "office" or "is_office") and individual tags ("pe").
   * Returns an empty array for unknown tokens (caller decides whether to
   * warn / skip).
   */
  static _resolveAppliesToToken(token) {
    if (!token) return [];
    const lower = String(token).trim().toLowerCase();
    if (!lower) return [];
    // `any` / `is_any` ⇒ every known tag. Used by rules that want to
    // remain universal while still opting into a synthetic format tag
    // like `decoded-payload`. We deliberately exclude the synthetic
    // `decoded-payload` tag from the `any` expansion: a rule that wants
    // both must spell both (`applies_to = "any, decoded-payload"`),
    // which keeps the in-source intent explicit and prevents every
    // `any`-tagged rule from accidentally running on decoded payloads.
    if (lower === 'any' || lower === 'is_any') {
      const tags = Array.from(this._KNOWN_FORMAT_TAGS);
      return tags.filter(t => t !== 'decoded-payload');
    }
    const withPrefix = lower.startsWith('is_') ? lower : 'is_' + lower;
    if (this.FORMAT_PREDICATES[withPrefix]) {
      return this.FORMAT_PREDICATES[withPrefix];
    }
    if (this._KNOWN_FORMAT_TAGS.has(lower)) return [lower];
    return [];
  }

  /**
   * `meta.applies_to` short-circuit gate. Returns true when the rule
   * should be evaluated against `formatTag`, false when the rule should
   * be skipped entirely. Tokens are split on commas / whitespace.
   *
   * Behaviour with a missing/empty `formatTag`: the rule is skipped (the
   * safe default — `applies_to` declares "I only apply when context says
   * so", and absence of context is not "so").
   */
  static _matchesAppliesTo(appliesTo, formatTag) {
    if (!appliesTo) return true;
    if (!formatTag) return false;
    const tags = String(appliesTo).split(/[,\s]+/).filter(Boolean);
    for (const tok of tags) {
      const allowed = YaraEngine._resolveAppliesToToken(tok);
      if (allowed.includes(formatTag)) return true;
    }
    return false;
  }

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
    // Bounded lazy classes: tag list capped at 128 chars (a YARA rule with
    // more than ~30 tags is already absurd) and rule body capped at 64 KB
    // (the largest bundled rule is well under 16 KB). The bounds prevent
    // quadratic backtracking on malformed rule files (missing `}`, etc.).
    const ruleRx = /\brule\s+(\w+)\s*(?::\s*([\w\s]{1,128}?))?\s*\{([\s\S]{0,65536}?)\n\}/g;
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
    const ruleRx2 = /\brule\s+(\w+)\s*(?::\s*([\w\s]{1,128}?))?\s*\{([\s\S]{0,65536}?)\n\}/g;
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

    // ── Format-predicate validation (Loupe extension) ────────────────────
    // Warn (not error) on:
    //   • `is_*` keywords in `condition:` that aren't in FORMAT_PREDICATES
    //   • `meta: applies_to` tokens that match neither a group alias nor a
    //     known formatTag.
    // Both are warnings rather than errors so a rule using a future
    // predicate name (added in a later Loupe release) still loads.
    if (cond) {
      const isRx = /\bis_\w+/gi;
      const seen = new Set();
      let im;
      while ((im = isRx.exec(cond)) !== null) {
        const key = im[0].toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        if (!YaraEngine.FORMAT_PREDICATES[key]) {
          warnings.push(p + 'unknown format predicate "' + im[0] +
            '" \u2014 see YaraEngine.FORMAT_PREDICATES');
        }
      }
    }
    if (rule.meta && rule.meta.applies_to) {
      const tokens = String(rule.meta.applies_to).split(/[,\s]+/).filter(Boolean);
      for (const tok of tokens) {
        if (!YaraEngine._resolveAppliesToToken(tok).length) {
          warnings.push(p + 'unknown applies_to value "' + tok +
            '" \u2014 see YaraEngine.FORMAT_PREDICATES');
        }
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
        // Hard cap regex pattern length at 2 KB at validation time. Combined
        // with the `safeRegex` length / shape guards used at scan time, this
        // refuses pathological patterns at the earliest entry point so they
        // can't propagate to the worker scan loop.
        if ((s.pattern || '').length > 2048) {
          errors.push(p + 'regex ' + s.id + ' too long (>2048 chars)');
          continue;
        }
        try { /* safeRegex: builtin */ new RegExp(s.pattern, (s.flags || '').replace(/[^gimsuy]/g, '')); }
        catch (e) { errors.push(p + 'invalid regex ' + s.id + ': ' + e.message); }
      }
    }

    return { errors, warnings };
  }

  /**
   * Scan a buffer against parsed YARA rules.
   *
   * The optional fourth `opts` arg supports two fields:
   *
   *   • `opts.errors` — diagnostics sink. Any per-string failure (invalid
   *     regex, iteration cap, wall-clock cap) is appended as
   *     `{ ruleName, stringId, reason: 'invalid-regex'|'iter-cap'|'time-cap', message }`.
   *     Callers that omit this get the historical silent-skip behaviour.
   *
   *   • `opts.context.formatTag` — Loupe's authoritative file-format
   *     identifier (see the FORMAT_PREDICATES doc block at the top of this
   *     file). Used to evaluate `is_*` predicates inside `condition:` and
   *     to short-circuit rules whose `meta: applies_to` doesn't include
   *     this tag. When omitted, `is_*` returns false and any rule with
   *     `applies_to` is skipped.
   *
   * @param {ArrayBuffer|Uint8Array} buffer  File content
   * @param {object[]} rules  Parsed rule objects from parseRules()
   * @param {object?}  opts   Optional `{ errors?: [], context?: { formatTag } }`.
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
    const ctx = (opts && opts.context) ? opts.context : null;
    const formatTag = (ctx && typeof ctx.formatTag === 'string') ? ctx.formatTag : null;

    const results = [];
    for (const rule of rules) {
      // Cooperative-cancel: abort the YARA scan early when a newer file
      // load supersedes this one. Per-rule granularity is the right
      // cadence — string-search time per rule is bounded by an internal
      // iter cap, so checking once per rule keeps latency under a few ms.
      throwIfAborted();
      // ── meta: applies_to short-circuit ──────────────────────────────
      // Rules tagged with an `applies_to` meta value are skipped entirely
      // (string-matching included) when the current `formatTag` isn't one
      // of the listed formats. Skipped rules don't contribute to results
      // and don't pay the latin-1 string-search cost.
      if (rule.meta && rule.meta.applies_to) {
        if (!YaraEngine._matchesAppliesTo(rule.meta.applies_to, formatTag)) continue;
      }

      const stringMatches = {};
      // Evaluate each string definition
      for (const strDef of rule.strings) {
        const matchList = YaraEngine._findString(text, bytes, strDef, errorSink, rule.name);
        stringMatches[strDef.id] = matchList;

      }

      // Evaluate condition
      const condResult = YaraEngine._evalCondition(rule.condition, stringMatches, rule.strings, bytes, ctx);
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
    // `meta` is `Object.create(null)` so that user-supplied keys captured by
    // `(\w+)` below cannot shadow `Object.prototype` members or hit the
    // `__proto__` setter — `\w` matches `__proto__`, `constructor`, and
    // `prototype`. Belt-and-braces, we also explicitly skip those three
    // reserved names. Closes CodeQL alert js/remote-property-injection.
    const rule = { name, tags, strings: [], condition: 'any of them', meta: Object.create(null) };

    // Extract meta section
    const metaMatch = body.match(/meta\s*:([\s\S]*?)(?=strings\s*:|condition\s*:|$)/i);
    if (metaMatch) {
      const metaBlock = metaMatch[1];
      // Key whitelist: lowercase identifier (`[a-z_][a-z0-9_]*`). Built-in
      // YARA rules under src/rules/*.yar use only `applies_to`, `category`,
      // `description`, `mitre`, `reference`, `severity`. The whitelist is a
      // superset of those, keeps the parser permissive for future rule
      // authors, and rules out `__proto__` / `prototype` / `constructor`
      // (uppercase first letter or contains `_` only after a letter, so
      // `constructor` would technically pass — Object.create(null) above
      // makes that benign anyway, but the whitelist also makes CodeQL's
      // js/remote-property-injection happy without a Map refactor).
      const metaRx = /(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"/g;
      const SAFE_KEY = /^[a-z][a-z0-9_]*$/;
      let mm;
      while ((mm = metaRx.exec(metaBlock)) !== null) {
        const key = mm[1];
        if (!SAFE_KEY.test(key)) continue;
        if (key === 'constructor') continue;
        rule.meta[key] = mm[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
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
          /* safeRegex: builtin */
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

  static _evalCondition(condition, stringMatches, stringDefs, bytes, ctx) {
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
    return YaraEngine._evalBoolCondition(condition, stringMatches, stringDefs, bytes, ctx);
  }

  // ── Internal: Full YARA condition expression evaluator ─────────────────────
  // Recursive-descent parser supporting:
  //   $var, $var at N, $var in (lo..hi), #var (count), N of (set),
  //   any/all of (set), uint8/16/32(N), int8/16/32(N), filesize,
  //   boolean and/or/not, comparison operators ==  !=  >  <  >=  <=

  static _evalBoolCondition(condition, stringMatches, stringDefs, bytes, ctx) {
    // Normalise string-match keys to lowercase for consistent lookup
    const sm = {};
    for (const key of Object.keys(stringMatches)) sm[key.toLowerCase()] = stringMatches[key];
    const allIds = stringDefs.map(s => s.id.toLowerCase());

    // Loupe extension — `is_*` format predicates resolve against the
    // host-supplied `ctx.formatTag`. Missing `formatTag` ⇒ all `is_*`
    // evaluate to false (no false positives without context).
    const formatTag = (ctx && typeof ctx.formatTag === 'string') ? ctx.formatTag : null;

    // ── Tokenise ────────────────────────────────────────────────────────────
    // The `is_\w+` alternative is checked AFTER the binary keywords so that
    // existing identifiers like `int8`/`uint16`/`filesize` still match their
    // dedicated branches (none of which start with `is_`).
    const tokens = [];
    const rx = /(\$[\w*]+|#\w+|uint(?:8|16|32)|int(?:8|16|32)|0x[0-9a-fA-F]+|\d+|!=|==|>=|<=|>|<|\.\.|and|or|not|at|of|in|them|any|all|filesize|true|false|is_\w+|[(),])/gi;
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

      // ── Format predicates: is_pe, is_zip_container, is_office, … ───────
      // Loupe extension. The keyword is matched against
      // `YaraEngine.FORMAT_PREDICATES`; unknown `is_*` keywords evaluate
      // to false (validation surfaces the typo as a warning).
      if (tl && tl.startsWith('is_')) {
        next();
        const allowed = YaraEngine.FORMAT_PREDICATES[tl];
        if (!allowed) return false;
        return formatTag ? allowed.includes(formatTag) : false;
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
