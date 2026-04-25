// ════════════════════════════════════════════════════════════════════════════
// cmd-obfuscation.js — CMD + PowerShell command-obfuscation detection &
// deobfuscation (PLAN Track E2). Extracted as a single module because the
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
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
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
      vars[m[1].toLowerCase()] = { value: m[2].trim(), offset: m.index };
    }
    if (Object.keys(vars).length >= 2) {
      // Look for variable concatenation: %var1%%var2% or !var1!!var2! or %var1:~N,M%
      const concatRe = /(?:%(\w+)%|!(\w+)!){2,}/g;
      while ((m = concatRe.exec(text)) !== null) {
        if (candidates.length >= this.maxCandidatesPerType) break;
        let resolved = m[0];
        let anyResolved = false;
        // Resolve %var% references
        resolved = resolved.replace(/%(\w+)%/gi, (full, vname) => {
          const v = vars[vname.toLowerCase()];
          if (v) { anyResolved = true; return v.value; }
          return full;
        });
        // Resolve !var! references (delayed expansion)
        resolved = resolved.replace(/!(\w+)!/gi, (full, vname) => {
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
    const envSubRe = /%\w+:~-?\d+(?:,\d+)?%/g;
    const envSubMatches = [];
    while ((m = envSubRe.exec(text)) !== null) {
      envSubMatches.push({ match: m[0], offset: m.index });
    }
    if (envSubMatches.length >= 3) {
      // Find the line(s) containing these, treat entire line as obfuscated command
      const lineRe = /^.*%\w+:~-?\d+(?:,\d+)?%.*$/gm;
      while ((m = lineRe.exec(text)) !== null) {
        if (candidates.length >= this.maxCandidatesPerType) break;
        const subCount = (m[0].match(/%\w+:~-?\d+(?:,\d+)?%/g) || []).length;
        if (subCount < 3) continue;
        candidates.push({
          type: 'cmd-obfuscation',
          technique: 'CMD Env Var Substring',
          raw: m[0],
          offset: m.index,
          length: m[0].length,
          deobfuscated: `[${subCount} env var substring operations — partial decode not reliable without runtime]`,
        });
      }
    }

    // ── PowerShell string concatenation: ('Down'+'loadStr'+'ing') ──
    const psConcat = /\(\s*'[^']{1,40}'\s*(?:\+\s*'[^']{1,40}'\s*){2,}\)/g;
    while ((m = psConcat.exec(text)) !== null) {
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
    // Match words with 2+ backticks that form known cmdlets/keywords
    const backtickRe = /[a-zA-Z`]{4,}(?:-[a-zA-Z`]{3,})?/g;
    while ((m = backtickRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
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
