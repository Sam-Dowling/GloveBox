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
 * Clip a `deobfuscated` payload to the shared per-candidate amp budget:
 * `min(8 KiB, 32 × raw.length)`. Matches the `_AMP_RATIO = 32` /
 * `_ABS_CAP = 8 * 1024` cap the four in-file CMD branches enforce at
 * their input-capture point, applied instead at the output-emit point
 * so peer decoders (bash, ps-mini-evaluator, ClickFix wrapper) that
 * don't collect their output from a bounded input window can still
 * honour the same contract.
 *
 * A `candidate.deobfuscated.length > 32 × candidate.raw.length`
 * invariant violation is what the obfuscation fuzz targets assert on
 * (under `tests/fuzz`). Clipping preserves the detection signal (all
 * truncation markers still match the SENSITIVE_CMD_KEYWORDS /
 * SENSITIVE_BASH_KEYWORDS gates because the keywords live near the
 * head of the decoded payload) while bounding sidebar payload size
 * and matching the peer-branch contract.
 *
 * The trailing marker is a single `…` + literal `[truncated]` so the
 * UI highlight remains stable (no mid-token marker) and analysts see
 * when the decoded output has been clipped.
 */
const _DEOBF_AMP_RATIO = 32;
const _DEOBF_ABS_CAP   = 8 * 1024;
const _DEOBF_TRUNC_MARK = '… [truncated]';
function _clipDeobfToAmpBudget(deobf, raw) {
  if (typeof deobf !== 'string' || deobf.length === 0) return deobf;
  const rawLen = (typeof raw === 'string') ? raw.length : 0;
  const cap = Math.min(_DEOBF_ABS_CAP, _DEOBF_AMP_RATIO * Math.max(1, rawLen));
  if (deobf.length <= cap) return deobf;
  // Reserve room for the truncation marker so the returned string
  // (body + marker) stays ≤ cap. If the cap itself is smaller than
  // the marker length (pathological `raw.length = 0` edge case
  // already handled by `Math.max(1, rawLen)`), fall back to a hard
  // truncate without marker.
  const bodyLen = Math.max(0, cap - _DEOBF_TRUNC_MARK.length);
  if (bodyLen === 0) return deobf.slice(0, cap);
  return deobf.slice(0, bodyLen) + _DEOBF_TRUNC_MARK;
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
// LOLBAS additions (finger, tftp, nltest, ssh, curl, winrs, installutil,
// msbuild, pip) — see lolbas-project.github.io. These are dual-use system
// binaries abused for AWL bypass / payload-fetch in modern ClickFix kits.
const SENSITIVE_CMD_KEYWORDS = /(?:powershell|pwsh|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin|regsvr32|rundll32|schtasks|wmic|forfiles|reg(?:\.exe)?\s+add|net(?:\.exe)?\s+(?:user|localgroup)|netstat|tasklist|whoami|nltest|systeminfo|invoke-expression|invoke-webrequest|downloadstring|downloadfile|new-object|frombase64string|encodedcommand|iex|iwr|irm|finger|tftp|ssh|curl|winrs|installutil|msbuild|pip)/i;

// English-language ClickFix / fake-captcha social-engineering cues. Lifted
// verbatim from the HTML-side detector at
// `src/renderers/html-renderer.js:242` so the cue list has a single
// source of truth across both call sites. The HTML detector fires when
// the buffer is the page itself; this module's command-string detector
// (see the ClickFix Wrapper branch below) fires when the buffer is the
// pasted Run-dialog payload, the next link in the same chain.
const CLICKFIX_CUES = /press\s+win\s*\+\s*r|win\+r|ctrl\s*\+\s*v|paste|verify\s+you\s+are\s+human|captcha|i\s*'?\s*m\s+not\s+a\s+robot|click\s+to\s+verify/i;
// ════════════════════════════════════════════════════════════════════════════



Object.assign(EncodedContentDetector.prototype, {
  /**
   * Find command obfuscation patterns (CMD and PowerShell).
   * Each candidate includes the obfuscated text and the technique detected.
   */
  _findCommandObfuscationCandidates(text, context) {
    // Short-circuit: the shortest meaningful obfuscation any branch
    // below can decode is a 9-char backtick-escaped `m`s`h`t`a
    // (→ `mshta`). Anything shorter cannot carry a LOLBin signal.
    if (!text || text.length < 9) return [];
    const candidates = [];

    // ── CMD caret insertion: p^o^w^e^r^s^h^e^l^l (single carets) and
    //    ^^fi^^ng^^er (double carets, the for /f nested-quote form) ──
    //
    // The regex deliberately accepts ≥1 caret between letters and any
    // number of leading carets. The double-caret form is the canonical
    // for /f indirection: cmd.exe parses the outer string once (`^^`
    // collapses to `^`), then the spawned subshell parses again (`^`
    // stripped). Both layers reduce to the same deobfuscated word, so
    // the maximally-stripped form via `_stripCarets`-equivalent
    // `replace(/\^/g, '')` is the right answer for analyst reporting.
    //
    // Because the regex is broader than before, the post-decode block
    // enforces a sensitivity gate: emit only when the cleaned word
    // matches `SENSITIVE_CMD_KEYWORDS`, OR the raw match contained ≥2
    // caret pairs (i.e. `^^` appeared at least twice — an explicit
    // "I'm hiding inside a for /f / nested cmd /c" signal that warrants
    // emission even on words we don't pre-classify as sensitive).
    // `[a-zA-Z]+` (not just `[a-zA-Z]`) is required so `^^fi^^ng^^er` —
    // multi-letter runs separated by caret-runs — is captured. The
    // single-letter form `p^o^w^e^r^s^h^e^l^l` is a degenerate case
    // (every letter-run has length 1) and is still matched. Trailing
    // carets (`^^^certutil^^^ args`) and alnum-anchored continuations
    // (`r^u^n^d^l^l^3^2`) are both accepted — the suffix `\^*\d*` lets
    // digits and a final caret run close the match. This keeps the
    // `echo ^^^p^o^w^e^r^s^h^e^l^l^^^ args` shape (echo-wrapped
    // cmd-line insertion) and the `r^u^n^d^l^l^3^2` numeric-suffix
    // LOLBin form both flowing through.
    const caretRe = /(?<![\w^])\^*[a-zA-Z]+(?:\^+[a-zA-Z0-9]+){2,}\^*(?!\w)/g;
    let m;
    while ((m = caretRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (raw.length > 200) continue; // pathological-length guard
      const deobfuscated = raw.replace(/\^/g, '');
      if (deobfuscated.length < 3) continue;
      // Count consecutive caret pairs (`^^` runs). Two or more such runs
      // is a strong nested-parse signal regardless of the decoded word.
      const doublePairs = (raw.match(/\^\^/g) || []).length;
      const isNested = doublePairs >= 1;
      // Tightened: the structural-only path now requires both ≥3 double-
      // pairs AND a non-trivial deobfuscated length (≥5 chars). The
      // previous `doublePairs >= 2` shortcut accepted short noise like
      // `^^a^^b` from log-format strings. Sensitive-cmd-keyword path is
      // unchanged — that's the high-confidence trigger.
      const passesGate = SENSITIVE_CMD_KEYWORDS.test(deobfuscated)
        || (doublePairs >= 3 && deobfuscated.length >= 5);
      if (!passesGate) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: isNested ? 'CMD Caret Insertion (nested)' : 'CMD Caret Insertion',
        raw,
        offset: m.index,
        length: raw.length,
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
          // Amplification guard. `%X%%Y%` with a user-defined `set X=…`
          // holding a multi-KB value would explode the candidate's
          // deobfuscated length far past anything meaningful for the
          // sidebar / IOC pass (and triggers the fuzz-harness
          // 64×-raw-length invariant). In practice CMD Variable
          // Concatenation on legitimately-obfuscated samples stays
          // under ~8× raw; 32× is a generous headroom.
          const _AMP_RATIO = 32;
          const _ABS_CAP = 8 * 1024;
          const _cap = Math.min(_ABS_CAP, _AMP_RATIO * Math.max(1, m[0].length));
          if (resolved.length > _cap) resolved = resolved.slice(0, _cap);
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
          // Same amplification guard as the CMD Variable Concatenation
          // branch above: cap resolved length at 32× raw or 8 KiB,
          // whichever is smaller, so a big user-defined `set X=…` value
          // can't explode the sidebar / trigger the fuzz 64×-invariant.
          const _AMP_RATIO = 32;
          const _ABS_CAP = 8 * 1024;
          const _cap = Math.min(_ABS_CAP, _AMP_RATIO * Math.max(1, m[0].length));
          if (resolved.length > _cap) resolved = resolved.slice(0, _cap);
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

      // ── Single-bang delayed-expansion resolution: `!x! args` ──
      //
      // A `setlocal enabledelayedexpansion`-prefixed script commonly
      // uses a single `!var!` to trigger a stored LOLBin name (the
      // more compact variant of the `!%X%!…` indirection above). The
      // concat branch above only matches 2+ consecutive refs — this
      // catches the solitary bang form when the resolved value is a
      // SENSITIVE_CMD_KEYWORD, matching the same confidence bar the
      // caret-insertion branch uses.
      //
      // Gate: require a nearby `setlocal` or `enabledelayedexpansion`
      // token in the input so `!x!` alone in a context where bangs
      // are literal text (e.g. a log line) doesn't false-positive.
      const hasDelayedExpansion = /\bsetlocal\b[\s\S]{0,200}?\benabledelayedexpansion\b|\benabledelayedexpansion\b/i.test(text);
      if (hasDelayedExpansion) {
        const singleBangRe = /(?<![\w!])!([\w^]+)!(?![\w!])/g;
        while ((m = singleBangRe.exec(text)) !== null) {
          throwIfAborted();
          if (candidates.length >= this.maxCandidatesPerType) break;
          const rawName = m[1];
          const cleaned = _stripCarets(rawName).toLowerCase();
          const v = vars[cleaned];
          if (!v || typeof v.value !== 'string') continue;
          let resolved = v.value;
          if (resolved.length < 3) continue;
          // Sensitivity gate — surface when the stored value is either
          // a known LOLBin / shell-launch token OR any executable-
          // looking filename (`*.exe`, `*.dll`, `*.bat`, `*.cmd`,
          // `*.vbs`, `*.ps1`, `*.hta`). Benign scripts use `!VAR!` all
          // the time; the obfuscation signal is delayed-expansion
          // hiding a program/script name across a `set` + `!…!` pair.
          const _EXE_SUFFIX = /\.(?:exe|dll|bat|cmd|vbs|ps1|hta|scr|pif|cpl)\b/i;
          if (!SENSITIVE_CMD_KEYWORDS.test(resolved) && !_EXE_SUFFIX.test(resolved)) continue;
          // Amplification guard — same 32×-raw / 8 KiB cap the
          // `!%X%!…!%Z%!` indirection branch above uses. A single
          // `!abc!` reference (raw=5) to a `set abc=<long payload>`
          // value can trivially exceed the fuzz-harness 64×-raw
          // invariant; Jazzer found a raw=5 → deobf=507 blowup in
          // the coverage-guided run that motivated this cap.
          const _AMP_RATIO = 32;
          const _ABS_CAP = 8 * 1024;
          const _cap = Math.min(_ABS_CAP, _AMP_RATIO * Math.max(1, m[0].length));
          if (resolved.length > _cap) resolved = resolved.slice(0, _cap);
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

      // Clip inline substring expansion to the shared amp budget.
      // `sliced` comes from an arbitrarily long env var value — a
      // short `wordRaw = "%X:~0%tail"` (13 chars) against a 500-char
      // `set X=…` assignment can produce a 52× amp violating the
      // peer-branch 32× raw / 8 KiB contract. The SENSITIVE_CMD_KEYWORDS
      // hit survives clipping because keywords live near the head of
      // `wordResolved` (the gate above already fired against the
      // pre-clip value).
      const clippedWordResolved = _clipDeobfToAmpBudget(wordResolved, wordRaw);

      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'CMD Env Var Substring (inline)',
        raw: wordRaw,
        offset: lo,
        length: hi - lo,
        deobfuscated: clippedWordResolved,
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


    // ── CMD `for /f` indirect execution ──
    //
    //   for /f "delims=" %A in ('LOLBIN args') do call %A
    //
    // The inner command between `(` and `)` is the actual payload;
    // everything outside is scaffolding. When the body is `do call %X`
    // (or `do %X`) and `%X` is the for-variable from the same construct,
    // the captured stdout becomes the next shell command — the
    // structural signature of ClickFix-via-LOLBin (finger / nltest /
    // wmic / certutil delivery). We extract the inner command, resolve
    // any `%VAR%` tokens through the shared `_lookupVar` helper, strip
    // carets, and emit a candidate with the same three-tier confidence
    // ladder the env-var-substring branch below uses.
    //
    // Bounded character classes (`[^()\r\n]*?`, `[^'"`)\r\n]+`) keep
    // backtracking linear on adversarial inputs; per-iteration
    // `maxCandidatesPerType` budget matches every other branch in this
    // file.
    const forFRe = /\bfor\s*\/f\b[^()\r\n]{0,200}?\(\s*(['"`])([^'"`)\r\n]{1,400})\1\s*\)\s*do\s+(call\s+)?(%~?[A-Za-z]|%%[A-Za-z])/gi;
    while ((m = forFRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const innerRaw = m[2] || '';
      const hasCall = !!m[3];
      // The for-variable token (e.g. `%A` or `%%A`); used only as a
      // marker that the do-clause is referencing the captured value.
      const forVar = m[4] || '';
      // Strip carets first (cmd.exe's parse semantics) so any %VAR%
      // names inside resolve cleanly afterwards.
      let inner = _stripCarets(innerRaw);
      let resolvedCount = 0;
      let unresolvedCount = 0;
      inner = inner.replace(/%([\w^]+)%/g, (full, vname) => {
        const val = _lookupVar(vname);
        if (val !== null) { resolvedCount++; return val; }
        // Variables that aren't %X% lookups (e.g. %A — the for-variable
        // being reused) shouldn't count against the structural tier.
        if (/^[A-Za-z]$/.test(vname)) return full;
        unresolvedCount++;
        return `\u27e8${vname}\u27e9`;
      });
      const cleaned = inner.trim();
      if (cleaned.length < 3) continue;

      // Amplification guard — same rationale as the CMD Variable
      // Concatenation branch: a user-defined `set VAR=<large payload>`
      // expanded inside the `for /f (…)` body can trivially exceed
      // the fuzz-harness 64×-raw invariant (raw is the outer `for /f`
      // scaffolding, deobf is the expanded inner command). Cap at
      // 32× raw or 8 KiB, whichever is smaller.
      const _AMP_RATIO = 32;
      const _ABS_CAP = 8 * 1024;
      const _cap = Math.min(_ABS_CAP, _AMP_RATIO * Math.max(1, m[0].length));
      const cleanedCapped = cleaned.length > _cap ? cleaned.slice(0, _cap) : cleaned;

      let technique;
      // Tightened: the structural-only tier (zero env-vars resolved) is
      // dropped — pure-placeholder renderings are noise without a single
      // KNOWN_ENV_VAR match to anchor confidence. Real ClickFix payloads
      // always resolve at least %COMSPEC% / %SystemRoot%, so the Partial
      // tier still catches the canonical case. Bruteforce mode keeps the
      // structural emission for analyst escape-hatch use.
      if (unresolvedCount === 0) {
        technique = 'CMD for /f Indirect Execution';
      } else if (resolvedCount > 0) {
        technique = 'CMD for /f Indirect Execution (partial)';
      } else if (this._bruteforce) {
        technique = 'CMD for /f Indirect Execution (structural)';
      } else {
        continue;
      }

      // `do call %A` / `do %A` where the body re-references the
      // for-variable means "execute the captured output". Marker is
      // consumed by `_processCommandObfuscation` to bump severity and
      // mirror an IOC.PATTERN into the externalRefs surface.
      const executeOutput = !!forVar; // any reference of a %X is enough

      // Attach the CMD-specific behavioural-tell mirror at the
      // candidate site (not at the post-processor) so unrelated
      // decoder families that also set `_executeOutput` (bash live
      // fetch, python/php/js eval sinks) don't get tagged with this
      // CMD-only IOC.PATTERN. `_executeOutput` retains its generic
      // role of bumping severity in `_processCommandObfuscation`.
      const _patternIocs = executeOutput
        ? [{
            url: 'for /f \u2026 do call %X \u2014 captured command output is executed as a shell command',
            severity: 'high',
          }]
        : undefined;

      candidates.push({
        type: 'cmd-obfuscation',
        technique,
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: cleanedCapped,
        _executeOutput: executeOutput,
        _forFCall: hasCall,
        ..._patternIocs ? { _patternIocs } : {},
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

    // ── Isolated single-token env-var substring against KNOWN_ENV_VARS ──
    //
    // The 3+-token line resolver below requires the whole text contain
    // at least 3 substring tokens to emit a candidate — real-world
    // obfuscators often do exactly that (line of 4-8 slices that
    // spell a command). But `%COMSPEC:~20,3% /c whoami` is a
    // standalone single-token abuse that the 3+-gate misses. We
    // tier-gate it more strictly than the multi-token case:
    //   • the variable MUST resolve against KNOWN_ENV_VARS (not
    //     user-defined `set` vars — those already get the concat
    //     branch above and wouldn't fire here unless they happen to
    //     shadow a known env var),
    //   • the sliced substring must be ≥2 chars (so trivial
    //     single-char slices don't inflate the IOC surface).
    // Technique label is the same `CMD Env Var Substring` string
    // the multi-token full branch uses — downstream processing is
    // identical.
    if (envSubMatches.length >= 1) {
      const standaloneRe = /%(\w+):~(-?\d+)(?:,(-?\d+))?%/g;
      while ((m = standaloneRe.exec(text)) !== null) {
        throwIfAborted();
        if (candidates.length >= this.maxCandidatesPerType) break;
        const vname = m[1];
        const known = KNOWN_ENV_VARS[vname.toUpperCase()];
        if (typeof known !== 'string') continue;
        const start = parseInt(m[2], 10);
        const len = (m[3] === undefined) ? null : parseInt(m[3], 10);
        const sliced = _resolveCmdSubstring(known, start, len);
        if (sliced === null || sliced.length < 2) continue;
        candidates.push({
          type: 'cmd-obfuscation',
          technique: 'CMD Env Var Substring',
          raw: m[0],
          offset: m.index,
          length: m[0].length,
          deobfuscated: sliced,
        });
      }
    }

    // ── Bare `%COMSPEC%` (no substring slice) used as a LOLBin stand-in ──
    //
    // Attackers frequently type `%COMSPEC% /c <payload>` instead of
    // `cmd.exe /c …` to evade PPL/signature heuristics keyed on the
    // literal string `cmd.exe`. Resolve the bare form against
    // KNOWN_ENV_VARS ONLY when the expanded payload matches a known
    // LOLBin string (so generic `echo %PATH%` doesn't fire). Only the
    // stock `%COMSPEC%` is surfaced — other known vars (`%SYSTEMROOT%`,
    // `%PROGRAMFILES%`) resolve to filesystem paths that aren't
    // themselves obfuscation signals.
    {
      const bareRe = /%(COMSPEC)%/gi;
      while ((m = bareRe.exec(text)) !== null) {
        throwIfAborted();
        if (candidates.length >= this.maxCandidatesPerType) break;
        const vname = m[1].toUpperCase();
        const known = KNOWN_ENV_VARS[vname];
        if (typeof known !== 'string') continue;
        candidates.push({
          type: 'cmd-obfuscation',
          technique: 'CMD Env Var Substring',
          raw: m[0],
          offset: m.index,
          length: m[0].length,
          deobfuscated: known,
        });
      }
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
        // Tightened: structural-only tier dropped (see for /f branch
        // above). A line with zero resolved env-var slots can't be
        // distinguished from random `%X:~Y,Z%`-shaped strings in non-CMD
        // contexts. Bruteforce keeps the structural emission.
        if (unresolvedCount === 0) {
          technique = 'CMD Env Var Substring';
        } else if (resolvedCount > 0) {
          technique = 'CMD Env Var Substring (partial)';
        } else if (this._bruteforce) {
          technique = 'CMD Env Var Substring (structural)';
        } else {
          continue;
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


    // ── ClickFix run-dialog wrapper detection ──
    //
    // Triggers when *all three* hold simultaneously in the input:
    //   (a) at least one already-emitted candidate's decoded text
    //       contains a known ClickFix delivery vector (for /f, COMSPEC
    //       /c, mshta, powershell, finger);
    //   (b) `CLICKFIX_CUES` matches anywhere in the input (English
    //       social-engineering tells — "Verify you are human", etc.);
    //   (c) the input contains a trailing `echo` whose closing quote is
    //       preceded by ≥3 whitespace chars — the off-screen-scroll
    //       trick ClickFix kits use to hide the malicious portion in
    //       Win+R.
    //
    // Closes the loop the HTML detector at
    // `src/renderers/html-renderer.js:238-258` opens but cannot reach
    // when the buffer is the pasted command itself rather than the page
    // that wrote it to the clipboard.
    {
      // (a) Delivery vector is present — check both already-emitted
      // decoded candidates AND the raw text itself, so a literally-
      // typed `powershell -NoP …` ClickFix payload still triggers
      // (historically we only consulted `candidates`, which missed
      // the plaintext paste-bait form).
      const _vectorRe = /\bfor\s*\/f\b|cmd(?:\.exe)?\s*\/c\b|\bmshta\b|\bpowershell(?:\.exe)?\b|\bfinger\b|\bcertutil\b|\bbitsadmin\b|\bcurl\s+http/i;
      const hasDeliveryVector = _vectorRe.test(text) || candidates.some(c =>
        typeof c.deobfuscated === 'string' && _vectorRe.test(c.deobfuscated)
      );
      const cueMatch = CLICKFIX_CUES.exec(text);
      // Trailing echo signature — the canonical "hide behind
      // off-screen scroll" trick is a quoted string containing a
      // ≥3-space run immediately before OR after the content. Either
      // position is the scroll-bait signal (leading-spaces for the
      // "Verification complete" cue; trailing-spaces for the
      // "Loading captcha …   " form).
      const trailingEchoRe = /\becho\s+['"](?:\s{3,}[^'"\r\n]*|[^'"\r\n]*?\s{3,})['"]/i;
      const trailMatch = trailingEchoRe.exec(text);
      if (hasDeliveryVector && cueMatch && trailMatch && candidates.length < this.maxCandidatesPerType) {
        // Pick the most-relevant inner payload: prefer a for /f inner
        // command (the actual shell command), then the COMSPEC argv0
        // tail, then the first sensitive caret/concat decode, then
        // fall back to the delivery-vector line from the raw text.
        const pickPayload = () => {
          const forF = candidates.find(c => /for \/f/i.test(c.technique || ''));
          if (forF) return forF.deobfuscated;
          const argv0 = candidates.find(c => c.technique === 'CMD Env Var (argv0)');
          if (argv0) return argv0.deobfuscated;
          const sens = candidates.find(c =>
            typeof c.deobfuscated === 'string' && SENSITIVE_CMD_KEYWORDS.test(c.deobfuscated)
          );
          if (sens) return sens.deobfuscated;
          // Raw-text fallback: grab the line containing the delivery
          // vector so the candidate's deobfuscated output is a useful
          // string the analyst can actually read.
          const lines = text.split(/\r?\n/);
          for (const line of lines) {
            if (_vectorRe.test(line)) return line.trim().slice(0, 400);
          }
          return null;
        };
        const payload = pickPayload();
        if (payload && payload.length >= 3) {
          // The raw span covers the whole input from the cue to the
          // trailing echo, capped to keep the snippet readable. Offset
          // anchors at the earliest of cue / trail.
          const start = Math.min(cueMatch.index, trailMatch.index);
          const end = Math.min(text.length, Math.max(
            cueMatch.index + cueMatch[0].length,
            trailMatch.index + trailMatch[0].length
          ));
          const rawSpan = text.substring(start, Math.min(end, start + 400));
          // Clip the pulled-in payload to the shared amp budget — the
          // ClickFix branch sources `payload` from a sibling candidate's
          // `deobfuscated`, which may legitimately be up to 8 KiB even
          // when our detection window (cueMatch..trailMatch) is tiny.
          // Without this clip a sibling with large output + a narrow
          // ClickFix window would emit a candidate whose
          // `deobfuscated.length / raw.length` ratio exceeds the 32×
          // peer-branch contract (fuzz target invariant violation —
          // the SAFETY invariant, not a detection regression).
          const clippedPayload = _clipDeobfToAmpBudget(payload, rawSpan);
          candidates.push({
            type: 'cmd-obfuscation',
            technique: 'CMD ClickFix Wrapper',
            raw: rawSpan,
            offset: start,
            length: rawSpan.length,
            deobfuscated: clippedPayload,
            _clickfix: true,
            _patternIocs: [{
              url: 'ClickFix run-dialog payload \u2014 instructs user to paste malicious command (T1204.001)',
              severity: 'critical',
            }],
          });
        }
      }
    }

    // ── PowerShell string concatenation: ('Down'+'loadStr'+'ing') ──
    // Tightened: the joined result must either match SENSITIVE_CMD_KEYWORDS
    // OR contain a typed-character mix (letters + non-alpha) so simple
    // literal-only joins like ('a'+'b'+'c') don't fire unless they form
    // a real command. Bruteforce mode keeps the looser any-length gate.
    const _psConcatPlausible = (joined) => {
      if (this._bruteforce) return joined.length >= 4;
      if (joined.length < 4) return false;
      if (SENSITIVE_CMD_KEYWORDS.test(joined)) return true;
      // Mixed alpha + non-alpha shape — common in path / URL / cmdline
      // assemblies; pure-alpha joined tokens (e.g. concatenated words
      // in localised strings) drop unless they hit the keyword list.
      return /[A-Za-z]/.test(joined) && /[^A-Za-z0-9]/.test(joined) && joined.length >= 6;
    };
    const psConcat = /\(\s*'[^']{1,40}'\s*(?:\+\s*'[^']{1,40}'\s*){2,}\)/g;
    while ((m = psConcat.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const parts = [...m[0].matchAll(/'([^']*)'/g)].map(p => p[1]);
      const joined = parts.join('');
      if (!_psConcatPlausible(joined)) continue;
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
      if (!_psConcatPlausible(joined)) continue;
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
    //
    // Two shapes:
    //   (a) ≥2 chained `.replace(...)` calls — classic deobfuscation
    //       pipeline (`.replace('X','i').replace('Y','e').replace('Z','x')`).
    //   (b) Single `.replace(SENTINEL,'')` that strips a repeated
    //       sentinel from a pre-literal string — the "zero-replacement"
    //       form (`'QWErpowershellQWEr'.replace('QWEr','')` → `powershell`).
    //       Shape (a) was previously the only emitter; shape (b) is
    //       cheap to recognise because the result length must shrink
    //       *and* still name a LOLBin.
    const psReplace = /'[^']{2,80}'(?:\s*\.\s*replace\s*\(\s*'[^']*'\s*,\s*'[^']*'\s*\)){2,}/gi;
    while ((m = psReplace.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      let result = m[0].match(/^'([^']*)'/)[1];
      const replacements = [...m[0].matchAll(/\.replace\s*\(\s*'([^']*)'\s*,\s*'([^']*)'\s*\)/gi)];
      for (const rep of replacements) {
        result = result.split(rep[1]).join(rep[2]);
      }
      // Tightened: the post-replace string must match `_EXEC_INTENT_RE`
      // — a generic 3+-char output of an unrelated `.replace()` chain
      // (e.g. an HTML sanitiser pipeline) is otherwise indistinguishable
      // from a real obfuscated payload. Bruteforce skips this gate.
      if (result.length < 3 || result === m[0]) continue;
      if (!this._bruteforce && !_EXEC_INTENT_RE.test(result)) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell -replace Chain',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: result,
      });
    }

    // Single `.replace(SENTINEL,'')` — the zero-replacement sentinel-
    // strip form. A single chained call doesn't fire the ≥2-chain
    // branch above, so handle it explicitly. We require an EMPTY
    // second argument (non-empty single replacements are ambiguous
    // with ordinary string processing and produced too many FPs in
    // early prototypes) and the post-strip result must still name a
    // known LOLBin — same gate the chain branch relies on.
    const psSingleReplace = /'([^']{3,200})'\s*\.\s*replace\s*\(\s*'([^']{1,40})'\s*,\s*''\s*\)/gi;
    while ((m = psSingleReplace.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const original = m[1];
      const sentinel = m[2];
      if (!sentinel) continue;
      const result = original.split(sentinel).join('');
      if (result.length < 3 || result === original) continue;
      // Post-strip: require a suspicious PowerShell LOLBin keyword.
      // Matches the keyword set used by the backtick branch above.
      const psKeywords = /^(invoke-expression|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|start-process|new-object|set-executionpolicy|invoke-command|get-credential|convertto-securestring|frombase64string|encodedcommand|invoke-mimikatz|invoke-shellcode|powershell|cmd|wscript|cscript|mshta|certutil|bitsadmin|regsvr32|rundll32|finger|tftp|ssh|curl|winrs|installutil|msbuild|pip|iex)$/i;
      if (!this._bruteforce && !psKeywords.test(result)) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell -replace Sentinel Strip',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: result,
      });
    }

    // ── PowerShell backtick escape: I`nv`o`ke-`E`xp`ression ──
    //
    // The backtick in PowerShell is a generic escape character: any
    // character preceded by a backtick passes through literally (with
    // a handful of named-escape exceptions like `` `n ``, `` `t `` that
    // do the obvious thing). Adversaries abuse it to break up LOLBin
    // names into single-char-plus-backtick fragments so simple
    // substring/keyword scanners miss them. The three canonical
    // shapes we see in the wild are:
    //
    //   (a) compact:   I`nv`o`ke-`E`xp`ression     (multi-char segs)
    //   (b) full-char: i`n`v`o`k`e`-`e`x`p`r`e`s`s`i`o`n  (every char)
    //   (c) digit-tail: r`u`n`d`l`l`3`2 / re`gs`vr`32     (rundll32)
    //
    // We unify all three by allowing: word-chars + optional escaped-or-
    // literal hyphen + word-chars, with backticks permitted between
    // ANY two characters. The tightening that keeps ReDoS bounded is
    // the outer `\b…\b` anchors, bounded repetition counts, and the
    // post-match sanity test `(raw.match(/`/g).length >= 2)` — the
    // real decision is still made by `suspiciousKeywords`, not the
    // shape of the token itself.
    const backtickRe = /\b[a-zA-Z][a-zA-Z0-9`]{2,200}(?:`?-`?[a-zA-Z0-9`]{1,200})?\b/g;
    while ((m = backtickRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (raw.length > 200) continue; // pathological-length guard
      if ((raw.match(/`/g) || []).length < 2) continue;

      const cleaned = raw.replace(/`/g, '');
      // Must resolve to a known suspicious keyword. LOLBAS additions
      // kept in sync with SENSITIVE_CMD_KEYWORDS above — tftp / curl /
      // ssh are also valid PowerShell aliases, so backtick-escape
      // variants like `t``ftp` show up in real droppers.
      const suspiciousKeywords = /^(invoke-expression|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|start-process|new-object|set-executionpolicy|invoke-command|get-credential|convertto-securestring|frombase64string|encodedcommand|invoke-mimikatz|invoke-shellcode|powershell|cmd|wscript|cscript|mshta|certutil|bitsadmin|regsvr32|rundll32|finger|tftp|ssh|curl|winrs|installutil|msbuild|pip)$/i;
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
    //
    // Single repeated capture for trailing args; the previous shape had
    // *two* adjacent identical (?:…)* groups, which let the engine
    // 2^n-split on near-miss inputs (classic ReDoS). The argument-
    // extraction loop at `args[0][1].matchAll(...)` below recovers
    // each value, so the two groups were redundant anyway.
    //
    // Arg bodies use `[^']*` (not `+`) so that empty-string arguments
    // like `'{0}iex{1}' -f '',''` are accepted. The empty-arg form is
    // a genuine obfuscator — e.g. a template whose sentinel positions
    // end up as no-ops, leaving a LOLBin name embedded between them.
    const fmtRe = /'(\{[0-9]\}[^']{0,60})'\s*-f\s*'([^']*)'(?:\s*,\s*'([^']*)')*/gi;
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
        /* safeRegex: builtin */
        result = result.replace(new RegExp('\\{' + i + '\\}', 'g'), argValues[i]);
      }
      // Tightened: post-format string must match `_EXEC_INTENT_RE` to
      // distinguish a real obfuscated cmdline from generic format-string
      // output (logging templates, error formatters, etc.). Bruteforce
      // skips this gate.
      if (result.length < 3 || result === template) continue;
      if (!this._bruteforce && !_EXEC_INTENT_RE.test(result)) continue;
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

    // ── PowerShell -EncodedCommand / -enc / -ec <UTF-16LE-base64> ──
    //
    // The canonical PowerShell stager:
    //   powershell.exe -NoProfile -Exec Bypass -EncodedCommand JABjAD0…
    //
    // The argument is a base64-encoded UTF-16LE byte sequence. This is
    // the most common PowerShell obfuscation technique in the wild —
    // every Cobalt Strike, Metasploit, Empire, and hand-rolled Win loader
    // uses it. We recognise all three argument spellings
    // (`-EncodedCommand`, `-enc`, `-ec`) and the typical PowerShell
    // abbreviation where only the prefix matters (`-encod`, `-encode`).
    //
    // The decode pipeline:
    //   1. base64-decode → raw bytes
    //   2. interpret as UTF-16LE → text
    //   3. if the result is printable ASCII-ish, emit as deobfuscated
    //
    // Gate: the decoded text must match `_EXEC_INTENT_RE` OR be ≥8
    // printable chars. The first is the strong-signal gate (ClickFix /
    // C2 stagers always contain `iex` / `Invoke-` / `DownloadString`);
    // the second covers legitimate admin scripts that also get pulled
    // into `-EncodedCommand` form by tools like `Start-Job -ScriptBlock`
    // — an analyst still wants to see them decoded.
    //
    // `safeRegex`-like bounds: min 8 b64 chars (6 bytes decoded, 3 UTF-16
    // chars) so we don't fire on random `-ec Ab` noise, cap at 32 KiB
    // of base64 (which is 16 KiB of decoded text — within the 32× raw
    // cap when the encoded arg is ≥512 bytes, which is the practical
    // floor anyway).
    // Only match the documented short-forms `-EncodedCommand` / `-enc`
    // / `-ec`. Dropped the bare `-e` alias to avoid colliding with the
    // dozens of legit PS params that start with `e`
    // (`-ExecutionPolicy`, `-ExpandProperty`, `-Exclude`, ...). The
    // left anchor is start-of-string / whitespace / `;` / `|` / `&` —
    // NOT `\b`, because `\b` fails between a space and `-` (both are
    // non-word chars; JS regex `\b` transitions on word-char boundary
    // only, which a preceding space → `-` transition is not).
    const encCmdRe = /(?:^|[\s;|&'"])(?:-|\u2013)(?:EncodedCommand|EncodedArgument|Enc|Ec)\s+([A-Za-z0-9+/=]{8,32768})(?=\s|$|[;\r\n'"])/gi;
    while ((m = encCmdRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const b64 = m[1].replace(/\s+/g, '');
      // Require minimum decoded-bytes length and valid base64 padding.
      if (b64.length < 8 || (b64.length % 4) !== 0) continue;
      let bytes;
      try {
        if (typeof atob === 'function') {
          const bin = atob(b64);
          bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff;
        } else {
          bytes = new Uint8Array(Buffer.from(b64, 'base64'));
        }
      } catch (_) { continue; }
      if (!bytes || bytes.length < 4) continue;
      // UTF-16LE decode. `_tryDecodeUTF16LE` enforces low-NUL-density
      // + printable-ratio, so garbage base64 that happens to look like
      // UTF-16LE to the naive decoder still returns null.
      let decoded = null;
      if (typeof this._tryDecodeUTF16LE === 'function') {
        decoded = this._tryDecodeUTF16LE(bytes);
      }
      // Fallback: try UTF-8 (some `-enc` payloads actually use UTF-8,
      // despite the documented UTF-16LE convention).
      if (!decoded && typeof this._tryDecodeUTF8 === 'function') {
        decoded = this._tryDecodeUTF8(bytes);
      }
      if (!decoded || decoded.length < 4) continue;
      // Printable-ratio gate — at least 80% printable ASCII + common
      // whitespace. Anything below is almost certainly noise.
      let printable = 0;
      for (let i = 0; i < Math.min(decoded.length, 256); i++) {
        const cc = decoded.charCodeAt(i);
        if ((cc >= 0x20 && cc < 0x7f) || cc === 0x09 || cc === 0x0a || cc === 0x0d) printable++;
      }
      const sampleLen = Math.min(decoded.length, 256);
      if (printable / Math.max(1, sampleLen) < 0.8) continue;
      // Gate: exec-intent keyword is required unless bruteforce mode.
      // Without the exec-intent gate, a legit `-ec` of a version-string
      // or build-identifier (seen in MS-signed installers) would fire.
      // PowerShell-`-EncodedCommand` payloads authored by adversaries
      // always contain at least `iex` / `Invoke-` / `DownloadString` /
      // `FromBase64String` — `_EXEC_INTENT_RE` covers all three.
      if (!this._bruteforce && !_EXEC_INTENT_RE.test(decoded)) continue;
      const clipped = _clipDeobfToAmpBudget(decoded, m[0]);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell -EncodedCommand (UTF-16LE base64)',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: clipped,
        _patternIocs: [{
          url: 'powershell.exe -EncodedCommand \u2014 UTF-16LE base64 argument (T1059.001 / T1027) canonical PowerShell stager',
          severity: 'high',
        }],
      });
    }

    // ── PowerShell -EncodedCommand / -enc / -ec with $variable argument ──
    //
    // Phase B: the literal-argument branch above covers `powershell -enc
    // <b64>` only; real droppers often store the base64 in a $var first
    // (`$b = 'ZgBvAG8='; powershell -enc $b`). We mirror the literal
    // branch but first consult the ps-mini symbol table (built once per
    // scan in `_buildPsSymbolTable`) to resolve the $var.
    const encCmdVarRe = /(?:^|[\s;|&'"])(?:-|\u2013)(?:EncodedCommand|EncodedArgument|Enc|Ec)\s+(\$\{?[A-Za-z_][\w]*\}?|\$env:[A-Za-z_][\w]*|\$\{env:[A-Za-z_][\w]*\})(?=\s|$|[;\r\n'"])/gi;
    let encVarM;
    while ((encVarM = encCmdVarRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const varToken = encVarM[1];
      let b64;
      if (typeof this._buildPsSymbolTable === 'function') {
        const table = this._buildPsSymbolTable(text);
        b64 = this._psResolveArgToken(varToken, table);
      }
      if (typeof b64 !== 'string') continue;
      b64 = b64.replace(/\s+/g, '');
      if (b64.length < 8 || (b64.length % 4) !== 0) continue;
      if (!/^[A-Za-z0-9+/=]+$/.test(b64)) continue;
      let bytes;
      try {
        if (typeof atob === 'function') {
          const bin = atob(b64);
          bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff;
        } else {
          bytes = new Uint8Array(Buffer.from(b64, 'base64'));
        }
      } catch (_) { continue; }
      if (!bytes || bytes.length < 4) continue;
      let decoded = null;
      if (typeof this._tryDecodeUTF16LE === 'function') {
        decoded = this._tryDecodeUTF16LE(bytes);
      }
      if (!decoded && typeof this._tryDecodeUTF8 === 'function') {
        decoded = this._tryDecodeUTF8(bytes);
      }
      if (!decoded || decoded.length < 4) continue;
      let printable = 0;
      for (let i = 0; i < Math.min(decoded.length, 256); i++) {
        const cc = decoded.charCodeAt(i);
        if ((cc >= 0x20 && cc < 0x7f) || cc === 0x09 || cc === 0x0a || cc === 0x0d) printable++;
      }
      const sampleLen = Math.min(decoded.length, 256);
      if (printable / Math.max(1, sampleLen) < 0.8) continue;
      if (!this._bruteforce && !_EXEC_INTENT_RE.test(decoded)) continue;
      const clipped = _clipDeobfToAmpBudget(decoded, encVarM[0]);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell -EncodedCommand (var)',
        raw: encVarM[0],
        offset: encVarM.index,
        length: encVarM[0].length,
        deobfuscated: clipped,
        _patternIocs: [{
          url: 'powershell.exe -EncodedCommand $var \u2014 base64 argument stored in variable (T1059.001 / T1027) variable-backed PowerShell stager',
          severity: 'high',
        }],
      });
    }

    // ── PowerShell [char]N + [char]N + [char]N char-array reassembly ──
    //
    // Empire / Nishang / PowerSploit stubs routinely break a keyword
    // into `[char]0x49 + [char]0x45 + [char]0x58` (→ "IEX") to dodge
    // string-match AV. Accepts both decimal (`[char]105`) and hex
    // (`[char]0x69`) forms, with optional `[System.Char]` / `[System.Convert]::ToChar`
    // variants. Min 3 chars joined so random `[char]65 + [char]66` noise
    // (e.g. a unit-test assertion string) doesn't fire without an
    // exec-intent gate.
    const charArrRe = /(?:\[(?:System\.)?[Cc]har\]\s*(?:0x[0-9a-fA-F]{1,4}|\d{1,5})\s*\+?\s*){3,60}/g;
    while ((m = charArrRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (raw.length > 2048) continue;
      // Extract every numeric operand.
      const nums = [...raw.matchAll(/\[(?:System\.)?[Cc]har\]\s*(0x[0-9a-fA-F]{1,4}|\d{1,5})/g)]
        .map(n => n[1].toLowerCase().startsWith('0x') ? parseInt(n[1], 16) : parseInt(n[1], 10));
      if (nums.length < 3) continue;
      let joined = '';
      let anyHigh = false;
      for (const n of nums) {
        if (!Number.isFinite(n) || n < 0 || n > 0x10ffff) { joined = ''; break; }
        if (n > 0x7f) anyHigh = true;
        joined += String.fromCodePoint(n);
      }
      if (joined.length < 3) continue;
      // Post-assemble gate: exec-intent OR a suspicious sensitive
      // keyword. Noise like `[char]65+[char]66+[char]67` (→ ABC) does
      // NOT fire unless bruteforce is on.
      if (!this._bruteforce) {
        if (!_EXEC_INTENT_RE.test(joined) && !SENSITIVE_CMD_KEYWORDS.test(joined)) continue;
      }
      // Suppress high-bit noise that passed the keyword gate only by
      // accident (garbled unicode with `iex` substring by pure chance).
      if (anyHigh && !/\b(iex|invoke|powershell|cmd|certutil|rundll32)\b/i.test(joined)) continue;
      const clipped = _clipDeobfToAmpBudget(joined, raw);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell [char]N+[char]N Reassembly',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: clipped,
      });
    }

    // ── PowerShell [Convert]::FromBase64String / UTF8.GetString full form ──
    //
    // The canonical AMSI-bypass / downloader stager:
    //   [System.Text.Encoding]::UTF8.GetString(
    //     [System.Convert]::FromBase64String('<b64>'))
    //   [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('<b64>'))
    //
    // Unlike the bare `FromBase64String('…')` form (already caught by
    // the b64 finder), the `Encoding.GetString` wrapper tells us the
    // byte interpretation (UTF-8 / UTF-16LE / ASCII) directly, so we
    // can decode without guessing. We emit a cmd-obfuscation candidate
    // which flows through the same promotion as -EncodedCommand.
    const convFromB64Re = /\[\s*(?:System\.)?(?:Text\.)?Encoding\s*\]\s*::\s*(UTF8|Unicode|ASCII|UTF7|BigEndianUnicode)\s*\.\s*GetString\s*\(\s*\[\s*(?:System\.)?Convert\s*\]\s*::\s*FromBase64String\s*\(\s*(['"])([A-Za-z0-9+/=\s]{8,32768})\2\s*\)\s*\)/gi;
    while ((m = convFromB64Re.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const enc = (m[1] || '').toLowerCase();
      const b64 = (m[3] || '').replace(/\s+/g, '');
      if (b64.length < 8 || (b64.length % 4) !== 0) continue;
      let bytes;
      try {
        if (typeof atob === 'function') {
          const bin = atob(b64);
          bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff;
        } else {
          bytes = new Uint8Array(Buffer.from(b64, 'base64'));
        }
      } catch (_) { continue; }
      if (!bytes || bytes.length < 2) continue;
      let decoded = null;
      try {
        if (enc === 'unicode' || enc === 'bigendianunicode') {
          // PowerShell's [Text.Encoding]::Unicode == UTF-16LE.
          // BigEndianUnicode is UTF-16BE; browsers' TextDecoder
          // supports both labels.
          const label = enc === 'bigendianunicode' ? 'utf-16be' : 'utf-16le';
          decoded = new TextDecoder(label, { fatal: false }).decode(bytes);
        } else if (enc === 'utf7') {
          // UTF-7 is not universally supported by TextDecoder; fall
          // back to UTF-8 which decodes ASCII subset cleanly. Real
          // UTF-7 payloads are exceedingly rare.
          decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        } else {
          decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        }
      } catch (_) { continue; }
      if (!decoded || decoded.length < 3) continue;
      // Printable-ratio gate (identical to -EncodedCommand branch).
      let printable = 0;
      const sampleLen = Math.min(decoded.length, 256);
      for (let i = 0; i < sampleLen; i++) {
        const cc = decoded.charCodeAt(i);
        if ((cc >= 0x20 && cc < 0x7f) || cc === 0x09 || cc === 0x0a || cc === 0x0d) printable++;
      }
      if (printable / Math.max(1, sampleLen) < 0.8) continue;
      if (!this._bruteforce && !_EXEC_INTENT_RE.test(decoded)) continue;
      const clipped = _clipDeobfToAmpBudget(decoded, m[0]);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: `PowerShell [Convert]::FromBase64String + ${enc.toUpperCase()}.GetString`,
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: clipped,
      });
    }

    // ── [Convert]::FromBase64String($var) + Encoding.GetString ──
    //
    // Phase B companion to the literal-string branch above. Real samples
    // store the base64 in a $var then thread it through the encoding
    // wrapper:
    //
    //   $b = 'AAAA…'
    //   [System.Text.Encoding]::UTF8.GetString(
    //     [System.Convert]::FromBase64String($b))
    //
    // Same shape as the literal regex with the quoted arg replaced by
    // a $-prefixed variable reference.
    const convFromB64VarRe = /\[\s*(?:System\.)?(?:Text\.)?Encoding\s*\]\s*::\s*(UTF8|Unicode|ASCII|UTF7|BigEndianUnicode)\s*\.\s*GetString\s*\(\s*\[\s*(?:System\.)?Convert\s*\]\s*::\s*FromBase64String\s*\(\s*(\$\{?[A-Za-z_][\w]*\}?|\$env:[A-Za-z_][\w]*|\$\{env:[A-Za-z_][\w]*\})\s*\)\s*\)/gi;
    let convVarM;
    while ((convVarM = convFromB64VarRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const enc = (convVarM[1] || '').toLowerCase();
      const varToken = convVarM[2];
      let b64;
      if (typeof this._buildPsSymbolTable === 'function') {
        const table = this._buildPsSymbolTable(text);
        b64 = this._psResolveArgToken(varToken, table);
      }
      if (typeof b64 !== 'string') continue;
      b64 = b64.replace(/\s+/g, '');
      if (b64.length < 8 || (b64.length % 4) !== 0) continue;
      if (!/^[A-Za-z0-9+/=]+$/.test(b64)) continue;
      let bytes;
      try {
        if (typeof atob === 'function') {
          const bin = atob(b64);
          bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff;
        } else {
          bytes = new Uint8Array(Buffer.from(b64, 'base64'));
        }
      } catch (_) { continue; }
      if (!bytes || bytes.length < 2) continue;
      let decoded = null;
      try {
        if (enc === 'unicode' || enc === 'bigendianunicode') {
          const label = enc === 'bigendianunicode' ? 'utf-16be' : 'utf-16le';
          decoded = new TextDecoder(label, { fatal: false }).decode(bytes);
        } else if (enc === 'utf7') {
          decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        } else {
          decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        }
      } catch (_) { continue; }
      if (!decoded || decoded.length < 3) continue;
      let printable = 0;
      const sampleLen = Math.min(decoded.length, 256);
      for (let i = 0; i < sampleLen; i++) {
        const cc = decoded.charCodeAt(i);
        if ((cc >= 0x20 && cc < 0x7f) || cc === 0x09 || cc === 0x0a || cc === 0x0d) printable++;
      }
      if (printable / Math.max(1, sampleLen) < 0.8) continue;
      if (!this._bruteforce && !_EXEC_INTENT_RE.test(decoded)) continue;
      const clipped = _clipDeobfToAmpBudget(decoded, convVarM[0]);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: `PowerShell [Convert]::FromBase64String + ${enc.toUpperCase()}.GetString (var)`,
        raw: convVarM[0],
        offset: convVarM.index,
        length: convVarM[0].length,
        deobfuscated: clipped,
        _patternIocs: [{
          url: '[Convert]::FromBase64String($var) + Encoding.GetString \u2014 variable-backed base64 decode (T1140 Deobfuscate/Decode)',
          severity: 'high',
        }],
      });
    }

    // ── PowerShell -bxor inline-key payload decode ──
    //
    // BloodHound / SharpHound / Cobalt Strike often embed shellcode or
    // a string-keyed payload as a numeric array XOR'd against an
    // inline single-byte or short repeating key:
    //
    //   $b = @(0x12,0x34,0x56,...); $b | % { $_ -bxor 0x5a }
    //   $key=0x42; $enc=@(...); $dec=($enc | ForEach-Object { $_ -bxor $key })
    //   -join($enc | ForEach-Object { [char]($_ -bxor 0x5a) })
    //
    // We recognise: inline byte array `@(N,N,...)` of length ≥8, an
    // inline single-byte key (decimal or 0xHH), and the `-bxor` token.
    // The decoded bytes are interpreted as ASCII and gated through the
    // same exec-intent check.
    // Split the match into two cheaper passes: (1) find the `@(N,N,...)`
    // literal with ≥8 elements, (2) within 200 chars, locate the
    // `-bxor <key>` token. This avoids the single-regex worst case
    // where a long byte array with no trailing `-bxor` backtracks
    // through every element.
    const bxorArrRe = /@\s*\(\s*((?:0x[0-9a-fA-F]{1,2}|\d{1,3})(?:\s*,\s*(?:0x[0-9a-fA-F]{1,2}|\d{1,3})){7,8191})\s*\)/g;
    const bxorKeyRe = /-b?xor\s*(0x[0-9a-fA-F]{1,2}|\d{1,3})/i;
    // Variable-key form (Phase C): the key is stored in a $var —
    // `$k = 0x42; @(…) | % { $_ -bxor $k }`. Pairs with ps-mini's
    // _psResolveIntValue to decode the key value.
    const bxorVarKeyRe = /-b?xor\s*(\$\{?[A-Za-z_][\w]*\}?|\$env:[A-Za-z_][\w]*|\$\{env:[A-Za-z_][\w]*\})/i;
    let bxorIterBudget = this.maxCandidatesPerType * 4; // ensure cheap scan bound even with early-continue
    while ((m = bxorArrRe.exec(text)) !== null && bxorIterBudget-- > 0) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const arrEnd = m.index + m[0].length;
      const tailWindow = text.substring(arrEnd, Math.min(text.length, arrEnd + 200));
      let keyM = bxorKeyRe.exec(tailWindow);
      let key = null;
      let isVarKey = false;
      if (keyM) {
        const keySrc = keyM[1];
        key = keySrc.toLowerCase().startsWith('0x')
          ? parseInt(keySrc, 16)
          : parseInt(keySrc, 10);
      } else {
        // Try the variable-key form; resolve through ps-mini's symbol
        // table. Most real samples assign the key before the pipeline
        // so the fixed-point resolve has already filled it in.
        const varKeyM = bxorVarKeyRe.exec(tailWindow);
        if (!varKeyM) continue;
        keyM = varKeyM;
        if (typeof this._buildPsSymbolTable === 'function'
            && typeof this._psResolveIntValue === 'function') {
          const table = this._buildPsSymbolTable(text);
          const vars = table.vars || new Map();
          const envVars = table.envVars || new Map();
          this._psAliasScratch = table.aliases;
          key = this._psResolveIntValue(varKeyM[1], vars, envVars);
        }
        isVarKey = true;
      }
      if (!Number.isFinite(key) || key < 0 || key > 255) continue;
      const arrSrc = m[1];
      const nums = arrSrc.split(/\s*,\s*/).map(t => {
        return t.toLowerCase().startsWith('0x') ? parseInt(t, 16) : parseInt(t, 10);
      });
      if (nums.length < 8 || nums.length > 8192) continue;
      let decoded = '';
      let allPrintable = true;
      for (const n of nums) {
        if (!Number.isFinite(n) || n < 0 || n > 255) { decoded = ''; break; }
        const c = (n ^ key) & 0xff;
        if (!((c >= 0x20 && c < 0x7f) || c === 0x09 || c === 0x0a || c === 0x0d)) allPrintable = false;
        decoded += String.fromCharCode(c);
      }
      if (decoded.length < 4) continue;
      // Gate: must be mostly printable + exec-intent OR a known
      // shellcode tell (e.g. 'kernel32', 'VirtualAlloc', 'wininet').
      if (!allPrintable) {
        // Non-printable decode — only emit if bruteforce on.
        if (!this._bruteforce) continue;
      } else if (!this._bruteforce && !_EXEC_INTENT_RE.test(decoded)
                 && !/kernel32|virtualalloc|wininet|wsock32|winexec|loadlibrary/i.test(decoded)) {
        continue;
      }
      const rawSpan = text.substring(m.index, arrEnd + keyM.index + keyM[0].length);
      const clipped = _clipDeobfToAmpBudget(decoded, rawSpan);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: isVarKey
          ? 'PowerShell -bxor Inline-Key Decode (var-key)'
          : 'PowerShell -bxor Inline-Key Decode',
        raw: rawSpan,
        offset: m.index,
        length: rawSpan.length,
        deobfuscated: clipped,
        _patternIocs: [{
          url: `PowerShell ${isVarKey ? 'variable-keyed' : 'inline'} XOR-decoded payload (key=0x${key.toString(16).padStart(2, '0')}, ${nums.length} bytes) \u2014 T1027.013 Encrypted/Encoded File`,
          severity: 'high',
        }],
      });
    }

    // ── PowerShell [scriptblock]::Create(…).Invoke() ──
    //
    // A canonical `iex` replacement used by post-2020 AMSI-bypass chains
    // (Invoke-Obfuscation's SB token, CS beacon stagers). Reveals the
    // script-block source by the `::Create('…')` argument and flags
    // `.Invoke()` as the execution sink.
    //
    //   [scriptblock]::Create('Invoke-Expression …').Invoke()
    //   ([ScriptBlock]::Create($s)).Invoke()
    //
    // We statically resolve only the literal-string form; the
    // `$var`-argument form falls through to `_findPsVariableResolutionCandidates`.
    const sbCreateRe = /\[\s*(?:System\.Management\.Automation\.)?[Ss]cript[Bb]lock\s*\]\s*::\s*Create\s*\(\s*(['"])((?:\\.|(?!\1).){3,2048})\1\s*\)\s*(?:\.\s*Invoke\s*\(\s*\))?/g;
    while ((m = sbCreateRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const body = (m[2] || '').replace(/\\'/g, "'").replace(/\\"/g, '"');
      if (body.length < 3) continue;
      if (!this._bruteforce && !_EXEC_INTENT_RE.test(body)) continue;
      const clipped = _clipDeobfToAmpBudget(body, m[0]);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell [scriptblock]::Create',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: clipped,
        _patternIocs: [{
          url: '[scriptblock]::Create(\u2026).Invoke() \u2014 canonical iex replacement for AMSI bypass (T1059.001)',
          severity: 'high',
        }],
      });
    }

    // ── [scriptblock]::Create($var) — variable-backed scriptblock body ──
    //
    // Phase B: the literal branch above explicitly defers `$var`-argument
    // resolution to ps-mini-evaluator. That defer only fires on `&(…)`
    // invocations though, so a ScriptBlock literal like
    //   [scriptblock]::Create($sb).Invoke()
    // was silently missed when $sb held the real body. Mirror the literal
    // regex with a $-prefixed argument and resolve through the shared
    // symbol table.
    const sbCreateVarRe = /\[\s*(?:System\.Management\.Automation\.)?[Ss]cript[Bb]lock\s*\]\s*::\s*Create\s*\(\s*(\$\{?[A-Za-z_][\w]*\}?|\$env:[A-Za-z_][\w]*|\$\{env:[A-Za-z_][\w]*\})\s*\)\s*(?:\.\s*Invoke\s*\(\s*\))?/g;
    let sbVarM;
    while ((sbVarM = sbCreateVarRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const varToken = sbVarM[1];
      let body;
      if (typeof this._buildPsSymbolTable === 'function') {
        const table = this._buildPsSymbolTable(text);
        body = this._psResolveArgToken(varToken, table);
      }
      if (typeof body !== 'string' || body.length < 3) continue;
      if (!this._bruteforce && !_EXEC_INTENT_RE.test(body)) continue;
      const clipped = _clipDeobfToAmpBudget(body, sbVarM[0]);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell [scriptblock]::Create (var)',
        raw: sbVarM[0],
        offset: sbVarM.index,
        length: sbVarM[0].length,
        deobfuscated: clipped,
        _patternIocs: [{
          url: '[scriptblock]::Create($var).Invoke() \u2014 variable-held script body invocation (T1059.001 / T1140) variable-backed iex replacement',
          severity: 'high',
        }],
      });
    }

    // ── PowerShell AMSI-bypass pattern (structural IOC, not a decode) ──
    //
    // The canonical AMSI-disable string:
    //   [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
    //     GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
    //
    // Adversaries concat/split/escape the `amsiInitFailed` token
    // aggressively. We catch the pattern via a bounded regex against
    // `AmsiUtils` + `amsiInitFailed` (with optional concat splits);
    // emit a `_patternIocs` entry at severity `critical`. The "raw"
    // value is the full matched span, "deobfuscated" is the recovered
    // canonical form.
    //
    // Structurally recognised shapes (concat-joined from the source):
    //   'amsi' + 'InitFailed'
    //   'amsi'+'Init'+'Failed'
    //   "amsi${null}InitFailed"  (`${null}`-insertion obfuscator trick)
    //
    // All flagged as a single technique; the FP rate is essentially
    // zero (a legitimate script never mentions `AmsiUtils`).
    const amsiRe = /AmsiUtils[\s\S]{0,400}?(?:amsi|['"]\s*amsi\s*['"]\s*\+\s*['"]|amsi\$\{null\})/gi;
    while ((m = amsiRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (raw.length > 400) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell AMSI Bypass',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: 'System.Management.Automation.AmsiUtils.amsiInitFailed \u2190 $true (AMSI disabled)',
        _patternIocs: [{
          url: 'AMSI bypass \u2014 AmsiUtils.amsiInitFailed SetValue($null,$true) (T1562.001 Disable or Modify Tools)',
          severity: 'critical',
        }],
      });
    }

    // ── CMD set /a arithmetic-to-character computation ──
    //
    //   set /a X=0x68 & set /a Y=0x69
    //   set /a K=%X%+1
    //   for /l %%i in (…) do call set "S=%S%!chr:~%%i,1!"
    //
    // Attackers use `set /a` to compute ASCII codepoints that later feed
    // a `!chr:~N,1!` string-slice or a `-join` on an array. We recognise
    // the simpler form: a block of ≥4 `set /a X=<num>` statements where
    // the assigned values are all valid printable ASCII. Decoded output
    // is the concatenation of `chr(X)` in assignment order — noisy on
    // pure-arithmetic loops but high-signal on malware where the vars
    // spell out `powershell.exe -enc …`.
    const setAReExtract = /\bset\s+\/a\s+(?:"[^"]+"|[^\r\n&|;]{1,120})/gi;
    {
      // Collect all `set /a` statements first; emit one combined
      // candidate if ≥4 of them assign printable-ASCII-valued literals
      // in sequence.
      const setAMatches = [...text.matchAll(setAReExtract)];
      if (setAMatches.length >= 4 && candidates.length < this.maxCandidatesPerType) {
        throwIfAborted();
        const assigns = [];
        const assignRe = /set\s+\/a\s+(?:"\s*([A-Za-z_]\w*)\s*=\s*([^"\r\n]+?)\s*"|([A-Za-z_]\w*)\s*=\s*([^\s&|;\r\n]+))/gi;
        let am;
        while ((am = assignRe.exec(text)) !== null) {
          const name = am[1] || am[3];
          const valSrc = (am[2] || am[4] || '').trim();
          // Only accept a single integer literal; ignore expressions
          // (`%X%+1`, `X<<2` etc.) to avoid a symbol-table rebuild.
          let val = null;
          if (/^0x[0-9a-fA-F]{1,4}$/.test(valSrc)) val = parseInt(valSrc, 16);
          else if (/^\d{1,5}$/.test(valSrc)) val = parseInt(valSrc, 10);
          if (val !== null && name) assigns.push({ name, val, idx: am.index });
          if (assigns.length >= 256) break;
        }
        if (assigns.length >= 4) {
          let joined = '';
          let allPrintable = true;
          for (const a of assigns) {
            if (a.val < 0x20 || a.val > 0x7e) { allPrintable = false; break; }
            joined += String.fromCharCode(a.val);
          }
          if (allPrintable && joined.length >= 4
              && (this._bruteforce || _EXEC_INTENT_RE.test(joined)
                  || SENSITIVE_CMD_KEYWORDS.test(joined))) {
            const first = assigns[0].idx;
            const last = assigns[assigns.length - 1].idx;
            const rawSpan = text.substring(first, Math.min(text.length, last + 40));
            const clipped = _clipDeobfToAmpBudget(joined, rawSpan);
            candidates.push({
              type: 'cmd-obfuscation',
              technique: 'CMD set /a Arithmetic-to-Character',
              raw: rawSpan,
              offset: first,
              length: rawSpan.length,
              deobfuscated: clipped,
            });
          }
        }
      }
    }

    // ── CMD call :label indirection with obfuscated labels ──
    //
    // `call :<labelname> <args>` followed later by `:<labelname>` +
    // body. Obfuscators use this to break a single command into
    // dozens of labelled sub-routines so linear string search misses
    // the payload. We detect: a `call :X` that resolves to a
    // `:X` label elsewhere in the file, where the NEXT non-empty
    // line (or the trailing text on the same line, whichever is
    // non-empty) names a LOLBin. The emitted `deobfuscated` is that
    // body text.
    {
      // Build a cheap label table keyed on lowercased label name.
      // `value` is the effective body — trailing text on the same
      // line if non-empty, otherwise the next non-empty line (capped
      // at 240 chars to bound memory on pathological `.bat`s).
      const labelLineRe = /^[ \t]*:(\w{1,64})\b([^\r\n]*)$/gmi;
      const labels = new Map();
      let lm;
      while ((lm = labelLineRe.exec(text)) !== null) {
        if (labels.size >= 128) break;
        const name = lm[1].toLowerCase();
        if (labels.has(name)) continue;
        let body = (lm[2] || '').trim();
        if (body.length === 0) {
          // Walk forward to the next non-empty line.
          const afterLabel = lm.index + lm[0].length;
          let nextStart = afterLabel;
          while (nextStart < text.length && (text[nextStart] === '\r' || text[nextStart] === '\n')) nextStart++;
          const lineEnd = text.indexOf('\n', nextStart);
          const cutoff = lineEnd < 0 ? text.length : lineEnd;
          body = text.substring(nextStart, Math.min(cutoff, nextStart + 240)).trim();
        }
        if (body.length > 0) labels.set(name, { body, offset: lm.index });
      }
      if (labels.size > 0) {
        const callLabelRe = /\bcall\s+:(\w{1,64})(?:\s+([^\r\n]{0,200}))?/gi;
        while ((m = callLabelRe.exec(text)) !== null) {
          throwIfAborted();
          if (candidates.length >= this.maxCandidatesPerType) break;
          const name = m[1].toLowerCase();
          const entry = labels.get(name);
          if (!entry) continue;
          const resolved = (entry.body + (m[2] ? ' ' + m[2] : '')).trim();
          if (resolved.length < 3) continue;
          // Only surface when the resolved body looks like a command
          // (exec-intent / SENSITIVE_CMD_KEYWORDS match). Otherwise
          // a legitimate `call :helper` would fire on every script
          // with an internal subroutine.
          if (!this._bruteforce
              && !_EXEC_INTENT_RE.test(resolved)
              && !SENSITIVE_CMD_KEYWORDS.test(resolved)) {
            continue;
          }
          const clipped = _clipDeobfToAmpBudget(resolved, m[0]);
          candidates.push({
            type: 'cmd-obfuscation',
            technique: 'CMD call :label Indirection',
            raw: m[0],
            offset: m.index,
            length: m[0].length,
            deobfuscated: clipped,
          });
        }
      }
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

    // Check for dangerous patterns in deobfuscated output. LOLBAS
    // additions (finger / tftp / nltest / ssh / curl / winrs /
    // installutil / msbuild / pip) align with SENSITIVE_CMD_KEYWORDS
    // above. The ≥2 / ≥3 escalation gate at the bottom keeps a single
    // benign `curl` from reaching `'high'` on its own.
    //
    // Cross-shell additions (bash / sh / zsh / dash / python / php /
    // ruby / perl) ensure that bash-obfuscation.js, python-obfuscation.js,
    // and php-obfuscation.js candidates that decode to non-Windows
    // payloads still get scored — without these, a bash decoder onion
    // landing on `system($_REQUEST['c'])` would only score 0 dangerous
    // patterns and stay at the default 'medium' tier.
    const dangerousPatterns = [
      // Windows / PowerShell vocabulary
      /powershell/i, /cmd\.exe/i, /wscript/i, /cscript/i, /mshta/i,
      /certutil/i, /bitsadmin/i, /regsvr32/i, /rundll32/i,
      /invoke-expression/i, /invoke-webrequest/i, /downloadstring/i,
      /downloadfile/i, /new-object/i, /start-process/i,
      /net\.webclient/i, /frombase64string/i, /encodedcommand/i,
      /shellexecute/i, /wscript\.shell/i, /MSXML2\.XMLHTTP/i,
      /http:\/\//i, /https:\/\//i, /\\\\/,
      /\bfinger\b/i, /\btftp\b/i, /\bnltest\b/i, /\bssh\b/i, /\bcurl\b/i,
      /\bwinrs\b/i, /\binstallutil\b/i, /\bmsbuild\b/i, /\bpip\b/i,
      // Bash / POSIX-shell vocabulary
      /\b(?:bash|sh|zsh|ksh|dash)\s/i, /\bwget\b/i, /\bnc(?:at)?\b/i,
      /\bnetcat\b/i, /\bsocat\b/i, /\/dev\/tcp\//i, /\/dev\/udp\//i,
      /\bbase64\s+-d\b/i, /\bxxd\s+-r\b/i, /\bgzip\s+-d\b/i,
      /\bchmod\s+\+x\b/i, /\bcrontab\b/i, /\bsudo\b/i, /\b\/etc\/passwd\b/i,
      /\b\/etc\/shadow\b/i, /\b\/etc\/cron/i,
      // Python vocabulary
      /\bos\.system\b/i, /\bos\.popen\b/i, /\bsubprocess\.(?:run|Popen|call|check_output|getoutput)\b/,
      /\b__import__\s*\(\s*['"](?:os|subprocess|socket|ctypes|marshal)/i,
      /\bmarshal\.loads\b/, /\bzlib\.decompress\b/, /\bcodecs\.decode\b/,
      /\bpty\.spawn\b/, /\bsocket\.socket\b/i,
      // PHP webshell vocabulary
      /\bbase64_decode\b/i, /\bgzinflate\b/i, /\bgzuncompress\b/i,
      /\bstr_rot13\b/i, /\bshell_exec\b/i, /\bpassthru\b/i,
      /\bproc_open\b/i, /\bpreg_replace\b/i, /\bcreate_function\b/i,
      /\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i,
      /\bdata:\/\/|php:\/\//i,
    ];
    const matchedPatterns = dangerousPatterns.filter(p => p.test(deobf));
    let severity = 'medium';
    if (matchedPatterns.length >= 2) severity = 'high';
    if (matchedPatterns.length >= 3) severity = 'critical';
    if (iocs.length > 0) severity = severity === 'critical' ? 'critical' : 'high';

    // Behavioural-tell escalation: `_executeOutput` is a generic
    // signal that the decoded payload is fed back into a shell
    // (CMD `for /f \u2026 do call %X`, bash `curl \u2026 | sh`, python
    // `eval(decoded)`, php `eval($decoded)`, JS `Function(\u2026)()` etc.).
    // Severity bumps for every family. The family-specific IOC.PATTERN
    // text \u2014 when emitted at all \u2014 is attached at the candidate site
    // via `_patternIocs`, never inferred from `_executeOutput` here
    // (otherwise non-CMD candidates would be mis-labelled with the
    // CMD `for /f` pattern).
    if (candidate._executeOutput) {
      if (severity !== 'critical') severity = 'high';
    }

    // Per-candidate behaviour-pattern mirrors. Each entry becomes an
    // IOC.PATTERN row in `externalRefs`. CMD-specific labels (the
    // `for /f \u2026 do call %X` and ClickFix mirrors) live at their
    // CMD candidate sites in this same file; other decoder families
    // currently emit no mirror and rely on `_executeOutput` + the
    // dangerousPatterns scoring above.
    if (Array.isArray(candidate._patternIocs)) {
      for (const p of candidate._patternIocs) {
        iocs.push({
          type: IOC.PATTERN,
          url: p.url,
          severity: p.severity || 'high',
        });
        if (p.severity === 'critical') severity = 'critical';
        else if (p.severity === 'high' && severity !== 'critical') severity = 'high';
      }
    }

    // finger.exe LOLBin target enrichment: the canonical ClickFix
    // delivery primitive is `finger user@host`, where the host is the
    // attacker's finger daemon and `user` selects the payload variant.
    // The user@host form would otherwise classify only as IOC.EMAIL,
    // losing the LOLBin-target nuance an analyst needs to pivot on.
    {
      const fingerMatch = /\bfinger\s+(?:([\w.+\-]+)@)?([\w.\-]+\.[a-z]{2,})/i.exec(deobf);
      if (fingerMatch) {
        const host = fingerMatch[2];
        const user = fingerMatch[1];
        iocs.push({
          type: IOC.PATTERN,
          url: `finger LOLBin target \u2014 ${user ? user + '@' : ''}${host} (LOLBAS Finger.exe AWL-bypass / payload-fetch on TCP/79)`,
          severity: 'high',
        });
        if (severity !== 'critical') severity = 'high';
      }
    }

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
