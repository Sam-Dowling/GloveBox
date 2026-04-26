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

/**
 * Strip literal carets from a CMD token. cmd.exe treats `^` as the
 * line-continuation / generic escape character, so `Co^m^S^p^Ec` is
 * semantically identical to `ComSpEc` / `COMSPEC`. Used both to
 * normalise variable names captured from `%…%` / `!…!` and to clean up
 * `set` LHS / RHS values before they enter the symbol table.
 */
function _stripCarets(s) {
  return (typeof s === 'string') ? s.replace(/\^/g, '') : s;
}

/**
 * Sensitive-keyword regex used to gate the inline single-token
 * substring finder. We only surface a candidate from a single
 * `%VAR:~N,M%` in the middle of a word when the resolved word spells
 * something an attacker would obfuscate — otherwise every legitimate
 * `prefix%COMSPEC:~0,2%suffix` echo in a help banner would emit a
 * finding. Kept in sync with the dangerous-pattern list in
 * `_processCommandObfuscation`; both lists exist because this gate
 * applies pre-decode (decides whether to *emit*) and the other
 * applies post-decode (decides *severity*).
 */
const SENSITIVE_CMD_KEYWORDS = /(?:powershell|pwsh|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin|regsvr32|rundll32|schtasks|wmic|forfiles|reg(?:\.exe)?\s+add|net(?:\.exe)?\s+(?:user|localgroup)|netstat|tasklist|whoami|nltest|systeminfo|invoke-expression|invoke-webrequest|downloadstring|downloadfile|new-object|frombase64string|encodedcommand|iex|iwr|irm)/i;
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
    //
    // Capture every `set VAR=…` assignment in the buffer, including
    // forms attackers use to bypass naive `^/\n`-anchored finders:
    //
    //   * Statement separators other than newline:
    //       cmd /c "set com=netstat /ano&&call %com%"
    //                                ^^ same line, separated by &&
    //
    //   * Indirect-name syntax:
    //       set %CdjPuLtXi%=p
    //     The literal %…% wrapper is part of the LHS — the var being
    //     written to is named CdjPuLtXi, not "%CdjPuLtXi%".
    //
    //   * Carets inside the LHS (cmd.exe escape):
    //       set Co^m=…    ←→  set Com=…
    //
    // We accept any of `^`, `\n`, `&`, `&&`, `|`, `||`, `(`, `)` or a
    // statement-terminating `"` as the boundary before `set`.
    const setRe = /(?:^|[\r\n&|()"\s])set\s+["']?(?:%([\w^]+)%|!([\w^]+)!|([\w^]+))["']?\s*=\s*([^\r\n&|"]*)/gim;
    const vars = {};
    while ((m = setRe.exec(text)) !== null) {
      throwIfAborted();
      const rawName = m[1] || m[2] || m[3] || '';
      const name = _stripCarets(rawName).trim();
      if (!name) continue;
      const rawVal = (m[4] || '').trim();
      // Strip a trailing `"` if the LHS came from `set "VAR=val"`-style
      // quoting where our boundary character ate the opening quote.
      const value = _stripCarets(rawVal.replace(/"+\s*$/, '').trim());
      if (!value) continue;
      vars[name.toLowerCase()] = { value, offset: m.index };
    }
    // Lookup helper used by both the concat and substring branches:
    // user-defined `set VAR=…` first (script-local), then the
    // KNOWN_ENV_VARS fallback table for stock Windows defaults.
    // The `vname` we receive may have inline carets (`Co^m^S^p^Ec`) —
    // strip them first so `%Co^m^S^p^Ec%` resolves as `COMSPEC`.
    const _lookupVar = (rawVname) => {
      const vname = _stripCarets(rawVname);
      const userVal = vars[vname.toLowerCase()];
      if (userVal && typeof userVal.value === 'string') return userVal.value;
      const known = KNOWN_ENV_VARS[vname.toUpperCase()];
      return (typeof known === 'string') ? known : null;
    };

    if (Object.keys(vars).length >= 1) {

      // Look for variable concatenation: %var1%%var2%, !var1!!var2!, or
      // %var1:~N[,M]%%var2:~N[,M]% (a popular CMD obfuscation that combines
      // user-defined `set` vars with substring slicing). The `[\w^]` class
      // in each variable name accepts inline carets (`%Co^m^S^p^Ec%`)
      // because cmd.exe strips them at parse time.
      const concatRe = /(?:%(?:[\w^]+(?::~-?\d+(?:,-?\d+)?)?)%|!(?:[\w^]+(?::~-?\d+(?:,-?\d+)?)?)!){2,}/g;
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
        resolved = resolved.replace(/%([\w^]+):~(-?\d+)(?:,(-?\d+))?%/g, subResolver);
        resolved = resolved.replace(/!([\w^]+):~(-?\d+)(?:,(-?\d+))?!/g, subResolver);
        // Resolve bare %var% / !var! references against user-defined vars
        // only — substituting in KNOWN_ENV_VARS for plain %COMSPEC% etc.
        // would replace far too much (every legitimate `%PATH%` echo, …).
        resolved = resolved.replace(/%([\w^]+)%/g, (full, vname) => {
          const v = vars[_stripCarets(vname).toLowerCase()];
          if (v) { anyResolved = true; return v.value; }
          return full;
        });
        // Delayed-expansion indirection: `!%X%!` first resolves the inner
        // `%X%` to a value, then the outer `!…!` re-looks-up that value
        // as a variable name. We approximate this with a single round of
        // re-lookup against the now-expanded string.
        resolved = resolved.replace(/!([\w^]+)!/g, (full, vname) => {
          const cleaned = _stripCarets(vname);
          const v = vars[cleaned.toLowerCase()];
          if (v) { anyResolved = true; return v.value; }
          // If the bang-name itself is the result of a previous %X%
          // expansion (i.e. cleaned now contains characters %, !, ^,
          // we don't see them at this stage; but a bare token like
          // "binkOHOTJcSMBkQ" coming through after the %…% expansion
          // would already be the var name we want).
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

      // ── Delayed-expansion indirection: `!%X%!!%Y%!!%Z%!` ──
      //
      // A specific construct seen in the wild that the generic concat
      // resolver above can't unwind in one pass:
      //
      //   set %X%=p
      //   set %Y%=ow
      //   set %Z%=er
      //   !%X%!!%Y%!!%Z%!
      //
      // The outer `!…!` is delayed expansion; the inner `%X%` is
      // immediate. cmd.exe first expands `%X%` to the *literal var name*
      // ("X" in this trivial case but a randomised garbage string in
      // real obfuscators) and then `!X!` looks that up to yield "p".
      //
      // We model this by scanning for runs of 2+ `!%word%!` tokens,
      // performing the immediate-expansion step (which here is just
      // unwrapping the outer `%…%` to the inner literal name — there is
      // no separate var-table for the inner side; in practice the
      // attacker's `set %X%=…` already wrote to the symbol table under
      // `X`), then resolving against `vars[X]`. This catches the
      // pathological "every var name is random base64" case in the big
      // wmic blob without needing a full cmd.exe simulator.
      const indirectRe = /(?:!%([\w^]+)%!){2,}/g;
      while ((m = indirectRe.exec(text)) !== null) {
        throwIfAborted();
        if (candidates.length >= this.maxCandidatesPerType) break;
        let resolved = '';
        let anyResolved = false;
        const inner = /!%([\w^]+)%!/g;
        let im;
        while ((im = inner.exec(m[0])) !== null) {
          const cleaned = _stripCarets(im[1]);
          const v = vars[cleaned.toLowerCase()];
          if (v) { resolved += v.value; anyResolved = true; }
          else { resolved += `⟨!${cleaned}!⟩`; }
        }
        if (anyResolved && resolved.length >= 3) {
          candidates.push({
            type: 'cmd-obfuscation',
            technique: 'CMD Delayed-Expansion Indirection',
            raw: m[0],
            offset: m.index,
            length: m[0].length,
            deobfuscated: resolved,
          });
        }
      }
    }

    // ── Inline single-token env-var substring abuse: ──
    //   PoWe%ALLUSERSPROFILE:~4,1%Shell.exe → PoWerShell.exe (4="r")
    //
    // The 3+-token line finder below misses single tokens welded into
    // the middle of a word — but that's the modern variant. Gate
    // emission on the resolved word matching SENSITIVE_CMD_KEYWORDS so
    // benign banner echoes don't false-positive. We only fire when the
    // token sits between non-space characters (i.e. it's spliced *into*
    // a word, not flanked by whitespace), which is itself a strong
    // obfuscation signal.
    const inlineSubRe = /(?<![ \t\r\n])(%([\w^]+):~(-?\d+)(?:,(-?\d+))?%|!([\w^]+):~(-?\d+)(?:,(-?\d+))?!)(?![ \t\r\n])/g;
    while ((m = inlineSubRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const vname = _stripCarets(m[2] || m[5] || '');
      const startStr = m[3] || m[6];
      const lenStr = m[4] || m[7];
      const val = _lookupVar(vname);
      if (val === null) continue;
      const start = parseInt(startStr, 10);
      const len = (lenStr === undefined) ? null : parseInt(lenStr, 10);
      const sliced = _resolveCmdSubstring(val, start, len);
      if (sliced === null) continue;

      // Locate the surrounding "word" so we have a coherent raw/decoded
      // pair. Stop at whitespace, statement separators, or quote chars.
      const stopBefore = /[\s"&|()<>]/;
      let lo = m.index;
      while (lo > 0 && !stopBefore.test(text[lo - 1])) lo--;
      let hi = m.index + m[0].length;
      while (hi < text.length && !stopBefore.test(text[hi])) hi++;
      const wordRaw = text.substring(lo, hi);
      const wordResolved = wordRaw.substring(0, m.index - lo)
        + sliced
        + wordRaw.substring(m.index - lo + m[0].length);

      if (!SENSITIVE_CMD_KEYWORDS.test(wordResolved)) continue;

      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'CMD Env Var Substring (inline)',
        raw: wordRaw,
        offset: lo,
        length: hi - lo,
        deobfuscated: wordResolved,
      });
    }

    // ── Bare `%COMSPEC%` / `%SystemRoot%\System32\…` in argv[0] position ──
    //
    // The variable-concat branch deliberately refuses to resolve a bare
    // `%COMSPEC%` (resolving every `%PATH%` echo would be noisy). But
    // when `%COMSPEC%` is the *first* token of a command — i.e. it's
    // about to fork a shell — that's a different signal: an attacker is
    // trying to invoke `cmd.exe` without writing the literal string. We
    // accept the resolution only when the token is in argv[0] position,
    // which we approximate as "right after start-of-line, `&`, `&&`,
    // `|`, `||`, `(`, `)`, `cmd /c "`, or `start `". Caret-stripping
    // applies so `%Co^m^S^p^Ec%` works too.
    const argv0Re = /(?:^|[\r\n;&|()"]|\bstart\s+|\bcall\s+|\bcmd(?:\.exe)?\s+(?:\/[a-z]\s+)?["']?)(%([\w^]+)%)([^\r\n]*)/gim;
    while ((m = argv0Re.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const vname = _stripCarets(m[2] || '');
      // Only resolve well-known shell-launcher env vars in this
      // position. Anything else is too noisy.
      if (!/^(COMSPEC|SYSTEMROOT|WINDIR)$/i.test(vname)) continue;
      const val = _lookupVar(vname);
      if (val === null) continue;
      const tail = m[3] || '';
      const tokenStart = m.index + m[0].length - m[1].length - tail.length;
      const fullStart = tokenStart;
      const fullEnd = tokenStart + m[1].length + tail.length;
      const raw = text.substring(fullStart, fullEnd);
      const resolved = (val + tail).trim();
      if (resolved.length < 5) continue;
      // Require some additional command shape to fire — bare
      // "C:\Windows\System32\cmd.exe" with no args is a documentation
      // line, not an attack.
      if (!/\s+(?:\/[a-z]|-[a-z])/i.test(tail)) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'CMD Env Var (argv0)',
        raw,
        offset: fullStart,
        length: fullEnd - fullStart,
        deobfuscated: resolved,
      });
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
