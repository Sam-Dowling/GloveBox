// ════════════════════════════════════════════════════════════════════════════
// cmd-obfuscation.js — CMD + PowerShell command-obfuscation detection &
// deobfuscation. Extracted as a single module because the
// CMD and PowerShell techniques share the candidate-emission contract and
// finding-shape (`{type:'cmd-obfuscation', technique, raw, deobfuscated, …}`)
// and frequently appear interleaved in the same script.
//
// Hosts:
//   * `_findCommandObfuscationCandidates(text, context)` — pattern scan for
//     CMD caret insertion (`p^o^w^e^r^s^h^e^l^l`), CMD `set var=…` + `%v1%%v2%`
//     concatenation, CMD env-var substring abuse (`%COMSPEC:~-7,1%`),
//     PowerShell string concatenation (`'a'+'b'+'c'`), PowerShell `-replace`
//     chains, PowerShell backtick escapes (`I`nv`o`ke-`E`xp`ression`),
//     PowerShell format operator (`'{0}{1}'-f 'a','b'`), PowerShell string
//     reversal (`'…'[-1..-100] -join ''`).
//   * `_processCommandObfuscation(candidate)` — promotes a candidate into a
//     finding, scores severity from dangerous-keyword hits, attaches IOCs
//     extracted from the deobfuscated text.
//
// CMD env-var substring resolution uses a small table of well-known
// Windows defaults (`KNOWN_ENV_VARS`) plus any `set VAR=…` assignments
// observed earlier in the same buffer. When every token in a line
// resolves we emit the fully-decoded payload; mixed lines emit a partial
// decode with `⟨VAR[a..b]⟩` placeholders for the unknown slots; all-
// unknown lines (e.g. abuse of user-controlled `%PATH%`) still emit a
// structural rendering rather than a useless apology string, so the
// analyst sees the operation count and ordering at a glance.
//
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
// ════════════════════════════════════════════════════════════════════════════

// Default values of well-known Windows environment variables, used when
// resolving `%VAR:~N,M%` tokens. These are the values cmd.exe reports on
// a stock English-locale Windows install; attackers lean on them
// (especially COMSPEC and PATHEXT) precisely because they are
// predictable, so a static table covers a large fraction of real-world
// CMD obfuscation. Casing is preserved exactly because substring
// indices into these strings are what the obfuscator is actually
// computing — `%COMSPEC:~14,1%` indexes into the literal byte sequence
// "C:\\Windows\\System32\\cmd.exe".
const KNOWN_ENV_VARS = Object.freeze({
  COMSPEC: 'C:\\Windows\\System32\\cmd.exe',
  PATHEXT: '.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC',
  SYSTEMROOT: 'C:\\Windows',
  WINDIR: 'C:\\Windows',
  PROGRAMFILES: 'C:\\Program Files',
  'PROGRAMFILES(X86)': 'C:\\Program Files (x86)',
  PROGRAMW6432: 'C:\\Program Files',
  PROGRAMDATA: 'C:\\ProgramData',
  ALLUSERSPROFILE: 'C:\\ProgramData',
  PUBLIC: 'C:\\Users\\Public',
  OS: 'Windows_NT',
  PROCESSOR_ARCHITECTURE: 'AMD64',
  HOMEDRIVE: 'C:',
  SYSTEMDRIVE: 'C:',
  NUMBER_OF_PROCESSORS: '8',
});

/**
 * Resolve a single CMD `%VAR:~start[,length]%` substring operation
 * against a known string value. Mirrors cmd.exe semantics:
 *   - start ≥ 0: index from the front, clamped to [0, len]
 *   - start < 0: index from the end (len + start), floored at 0
 *   - length missing: take everything from `start` to the end
 *   - length ≥ 0: take that many chars (clamped)
 *   - length < 0: stop |length| chars before the end (slice[start, len+length])
 *
 * Returns the resolved substring (possibly empty), or `null` if the
 * indices are pathological (e.g. start past end with positive length).
 */
function _resolveCmdSubstring(value, start, length) {
  if (typeof value !== 'string') return null;
  const len = value.length;
  let s = (start < 0) ? Math.max(0, len + start) : Math.min(start, len);
  let e;
  if (length === null || length === undefined) {
    e = len;
  } else if (length < 0) {
    e = Math.max(s, len + length);
  } else {
    e = Math.min(s + length, len);
  }
  if (e < s) return '';
  return value.slice(s, e);
}

/** Build a structural placeholder for an unresolved substring op. */
function _formatUnresolvedSub(varName, start, length) {
  const lenStr = (length === null || length === undefined) ? '' : `,${length}`;
  return `⟨${varName}:~${start}${lenStr}⟩`;
}
// ════════════════════════════════════════════════════════════════════════════


Object.assign(EncodedContentDetector.prototype, {
  /**
   * Find command obfuscation patterns (CMD and PowerShell).
   * Each candidate includes the obfuscated text and the technique detected.
   */
  _findCommandObfuscationCandidates(text, context) {
    if (!text || text.length < 10) return [];
    const candidates = [];

    // ── CMD caret insertion: p^o^w^e^r^s^h^e^l^l ──
    // Match words with 3+ carets interspersed
    const caretRe = /\b[a-zA-Z]\^[a-zA-Z](?:\^?[a-zA-Z]){3,}\b/g;
    let m;
    while ((m = caretRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const deobfuscated = m[0].replace(/\^/g, '');
      if (deobfuscated.length < 3) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'CMD Caret Insertion',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated,
      });
    }

    // ── CMD set variable concatenation ──
    // Pattern: multiple "set X=..." followed by %X%%Y%%Z% or !X!!Y!!Z!
    const setRe = /(?:^|\n)\s*set\s+["']?(\w+)["']?\s*=\s*([^\r\n]*)/gim;
    const vars = {};
    while ((m = setRe.exec(text)) !== null) {
      throwIfAborted();
      vars[m[1].toLowerCase()] = { value: m[2].trim(), offset: m.index };
    }
    // Lookup helper used by both the concat and substring branches:
    // user-defined `set VAR=…` first (script-local), then the
    // KNOWN_ENV_VARS fallback table for stock Windows defaults.
    const _lookupVar = (vname) => {
      const userVal = vars[vname.toLowerCase()];
      if (userVal && typeof userVal.value === 'string') return userVal.value;
      const known = KNOWN_ENV_VARS[vname.toUpperCase()];
      return (typeof known === 'string') ? known : null;
    };

    if (Object.keys(vars).length >= 2) {
      // Look for variable concatenation: %var1%%var2%, !var1!!var2!, or
      // %var1:~N[,M]%%var2:~N[,M]% (a popular CMD obfuscation that combines
      // user-defined `set` vars with substring slicing).
      const concatRe = /(?:%(?:\w+(?::~-?\d+(?:,-?\d+)?)?)%|!(?:\w+(?::~-?\d+(?:,-?\d+)?)?)!){2,}/g;
      while ((m = concatRe.exec(text)) !== null) {
        throwIfAborted();
        if (candidates.length >= this.maxCandidatesPerType) break;
        let resolved = m[0];
        let anyResolved = false;
        // Resolve %var:~N,M% (substring) before bare %var% so the bare
        // form doesn't greedily eat the inner colon-anchored variant.
        const subResolver = (full, vname, startStr, lenStr) => {
          const val = _lookupVar(vname);
          if (val === null) return full;
          const start = parseInt(startStr, 10);
          const len = (lenStr === undefined) ? null : parseInt(lenStr, 10);
          const sliced = _resolveCmdSubstring(val, start, len);
          if (sliced === null) return full;
          anyResolved = true;
          return sliced;
        };
        resolved = resolved.replace(/%(\w+):~(-?\d+)(?:,(-?\d+))?%/g, subResolver);
        resolved = resolved.replace(/!(\w+):~(-?\d+)(?:,(-?\d+))?!/g, subResolver);
        // Resolve bare %var% / !var! references against user-defined vars
        // only — substituting in KNOWN_ENV_VARS for plain %COMSPEC% etc.
        // would replace far too much (every legitimate `%PATH%` echo, …).
        resolved = resolved.replace(/%(\w+)%/g, (full, vname) => {
          const v = vars[vname.toLowerCase()];
          if (v) { anyResolved = true; return v.value; }
          return full;
        });
        resolved = resolved.replace(/!(\w+)!/g, (full, vname) => {
          const v = vars[vname.toLowerCase()];
          if (v) { anyResolved = true; return v.value; }
          return full;
        });
        if (anyResolved && resolved !== m[0] && resolved.length >= 3) {
          candidates.push({
            type: 'cmd-obfuscation',
            technique: 'CMD Variable Concatenation',
            raw: m[0],
            offset: m.index,
            length: m[0].length,
            deobfuscated: resolved,
            _vars: vars,
          });
        }
      }
    }

    // ── CMD environment variable substring abuse: %COMSPEC:~-7,1% ──
    //
    // Three confidence tiers:
    //   • Full   — every token resolves against KNOWN_ENV_VARS or a prior
    //              `set VAR=…` assignment; the deobfuscated string is the
    //              actual payload that would have run.
    //   • Partial — at least one token resolved; unknown ones are rendered
    //               as `⟨VAR:~start,length⟩` placeholders so the analyst
    //               can see exactly which slot is missing.
    //   • Structural — nothing resolved (e.g. abuse of user-controlled
    //                  `%PATH%`); we still emit the full structural
    //                  rendering with placeholders for every token, so the
    //                  analyst sees the operation count and ordering at a
    //                  glance instead of a useless apology line.
    //
    // The regex now also accepts negative `length` and missing `length`,
    // both of which are legal cmd.exe substring forms (`%VAR:~5%`,
    // `%VAR:~0,-2%`) that show up in real malware.
    const envSubReFull = /%(\w+):~(-?\d+)(?:,(-?\d+))?%/g;
    const envSubMatches = [];
    while ((m = envSubReFull.exec(text)) !== null) {
      throwIfAborted();
      envSubMatches.push({ match: m[0], offset: m.index });
    }
    if (envSubMatches.length >= 3) {
      // Find the line(s) containing these substring tokens, treat each
      // such line as one obfuscated command.
      const lineRe = /^.*%\w+:~-?\d+(?:,-?\d+)?%.*$/gm;
      while ((m = lineRe.exec(text)) !== null) {
        throwIfAborted();
        if (candidates.length >= this.maxCandidatesPerType) break;
        const line = m[0];
        const tokens = [...line.matchAll(/%(\w+):~(-?\d+)(?:,(-?\d+))?%/g)];
        if (tokens.length < 3) continue;

        let resolvedCount = 0;
        let unresolvedCount = 0;
        const decoded = line.replace(
          /%(\w+):~(-?\d+)(?:,(-?\d+))?%/g,
          (_full, vname, startStr, lenStr) => {
            const val = _lookupVar(vname);
            const start = parseInt(startStr, 10);
            const len = (lenStr === undefined) ? null : parseInt(lenStr, 10);
            if (val !== null) {
              const sliced = _resolveCmdSubstring(val, start, len);
              if (sliced !== null) {
                resolvedCount++;
                return sliced;
              }
            }
            unresolvedCount++;
            return _formatUnresolvedSub(vname, start, len);
          }
        );

        let technique;
        if (unresolvedCount === 0) {
          technique = 'CMD Env Var Substring';
        } else if (resolvedCount > 0) {
          technique = 'CMD Env Var Substring (partial)';
        } else {
          technique = 'CMD Env Var Substring (structural)';
        }

        // Sanity floor: the decoded line still has to be substantive
        // enough to be worth surfacing. We keep the original 3-token
        // gate above and don't over-filter here so structural decodes
        // of short payloads still surface.
        if (!decoded || decoded.length < 3) continue;

        candidates.push({
          type: 'cmd-obfuscation',
          technique,
          raw: line,
          offset: m.index,
          length: line.length,
          deobfuscated: decoded,
          _envSubResolvedCount: resolvedCount,
          _envSubUnresolvedCount: unresolvedCount,
        });
      }
    }


    // ── PowerShell string concatenation: ('Down'+'loadStr'+'ing') ──
    const psConcat = /\(\s*'[^']{1,40}'\s*(?:\+\s*'[^']{1,40}'\s*){2,}\)/g;
    while ((m = psConcat.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const parts = [...m[0].matchAll(/'([^']*)'/g)].map(p => p[1]);
      const joined = parts.join('');
      if (joined.length < 4) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell String Concatenation',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: joined,
      });
    }
    // Also match with double quotes
    const psConcatDQ = /\(\s*"[^"]{1,40}"\s*(?:\+\s*"[^"]{1,40}"\s*){2,}\)/g;
    while ((m = psConcatDQ.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const parts = [...m[0].matchAll(/"([^"]*)"/g)].map(p => p[1]);
      const joined = parts.join('');
      if (joined.length < 4) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell String Concatenation',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: joined,
      });
    }

    // ── PowerShell -replace chain: 'XYZ'.replace('X','a').replace('Y','b') ──
    const psReplace = /'[^']{2,80}'(?:\s*\.\s*replace\s*\(\s*'[^']*'\s*,\s*'[^']*'\s*\)){2,}/gi;
    while ((m = psReplace.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      let result = m[0].match(/^'([^']*)'/)[1];
      const replacements = [...m[0].matchAll(/\.replace\s*\(\s*'([^']*)'\s*,\s*'([^']*)'\s*\)/gi)];
      for (const rep of replacements) {
        result = result.split(rep[1]).join(rep[2]);
      }
      if (result.length < 3 || result === m[0]) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell -replace Chain',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: result,
      });
    }

    // ── PowerShell backtick escape: I`nv`o`ke-`E`xp`ression ──
    // Tightened pattern: require ≥2 literal backticks inside the token
    // itself (not just an open character class that matches every word
    // and then re-checks). Capped match length keeps backtracking
    // bounded on adversarial inputs (the previous open `{4,}` form
    // matched every word in the file and ran the suspicious-keyword
    // test on each one — quadratic on documents full of long words).
    const backtickRe = /\b[a-zA-Z]+(?:`[a-zA-Z]+){2,80}(?:-[a-zA-Z]+(?:`[a-zA-Z]+){0,80})?\b/g;
    while ((m = backtickRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (raw.length > 200) continue; // pathological-length guard
      if ((raw.match(/`/g) || []).length < 2) continue;

      const cleaned = raw.replace(/`/g, '');
      // Must resolve to a known suspicious keyword
      const suspiciousKeywords = /^(invoke-expression|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|start-process|new-object|set-executionpolicy|invoke-command|get-credential|convertto-securestring|frombase64string|encodedcommand|invoke-mimikatz|invoke-shellcode|powershell|cmd|wscript|cscript|mshta|certutil|bitsadmin|regsvr32|rundll32)$/i;
      if (!suspiciousKeywords.test(cleaned)) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell Backtick Escape',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: cleaned,
      });
    }

    // ── PowerShell format operator: '{0}{1}' -f 'Inv','oke-Expression' ──
    const fmtRe = /'(\{[0-9]\}[^']{0,60})'\s*-f\s*'([^']+)'(?:\s*,\s*'([^']+)')*(?:\s*,\s*'([^']+)')*/gi;
    while ((m = fmtRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      // Capture the full expression including all arguments
      const fullExpr = m[0];
      const template = m[1];
      const args = [...fullExpr.matchAll(/-f\s+((?:'[^']*'(?:\s*,\s*)?)+)/gi)];
      if (!args.length) continue;
      const argValues = [...args[0][1].matchAll(/'([^']*)'/g)].map(a => a[1]);
      let result = template;
      for (let i = 0; i < argValues.length; i++) {
        result = result.replace(new RegExp('\\{' + i + '\\}', 'g'), argValues[i]);
      }
      if (result.length < 3 || result === template) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell Format Operator (-f)',
        raw: fullExpr,
        offset: m.index,
        length: fullExpr.length,
        deobfuscated: result,
      });
    }

    // ── PowerShell reverse string: 'sserpxE-ekovnI'[-1..-100] -join '' ──
    const revRe = /'([^']{4,80})'\s*\[\s*-1\s*\.\.\s*-\d+\s*\]\s*-join\s*['"]['"]['"]/gi;
    while ((m = revRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const reversed = m[1].split('').reverse().join('');
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell String Reversal',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: reversed,
      });
    }

    return candidates;
  },

  /**
   * Process a command obfuscation candidate into a finding.
   */
  async _processCommandObfuscation(candidate) {
    const deobf = candidate.deobfuscated;
    if (!deobf || deobf.length < 3) return null;

    const deobfBytes = new TextEncoder().encode(deobf);
    const iocs = this._extractIOCsFromDecoded(deobfBytes);

    // Check for dangerous patterns in deobfuscated output
    const dangerousPatterns = [
      /powershell/i, /cmd\.exe/i, /wscript/i, /cscript/i, /mshta/i,
      /certutil/i, /bitsadmin/i, /regsvr32/i, /rundll32/i,
      /invoke-expression/i, /invoke-webrequest/i, /downloadstring/i,
      /downloadfile/i, /new-object/i, /start-process/i,
      /net\.webclient/i, /frombase64string/i, /encodedcommand/i,
      /shellexecute/i, /wscript\.shell/i, /MSXML2\.XMLHTTP/i,
      /http:\/\//i, /https:\/\//i, /\\\\/,
    ];
    const matchedPatterns = dangerousPatterns.filter(p => p.test(deobf));
    let severity = 'medium';
    if (matchedPatterns.length >= 2) severity = 'high';
    if (matchedPatterns.length >= 3) severity = 'critical';
    if (iocs.length > 0) severity = severity === 'critical' ? 'critical' : 'high';

    return {
      type: 'encoded-content',
      severity,
      encoding: candidate.technique,
      offset: candidate.offset,
      length: candidate.length,
      decodedSize: deobf.length,
      decodedBytes: deobfBytes,
      chain: [candidate.technique, 'Deobfuscated Command'],
      classification: { type: 'Deobfuscated Command', ext: '.txt' },
      entropy: this._shannonEntropyBytes(deobfBytes),
      hint: candidate.technique,
      iocs,
      innerFindings: [],
      autoDecoded: true,
      canLoad: true,
      ext: '.txt',
      snippet: candidate.raw.substring(0, 120),
      _deobfuscatedText: deobf,
      _obfuscatedText: candidate.raw,
    };
  },
});
