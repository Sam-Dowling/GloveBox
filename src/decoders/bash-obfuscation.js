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
const SENSITIVE_BASH_KEYWORDS = /\b(?:bash|sh|zsh|ksh|dash|eval|exec|source|\.\s+\/|curl|wget|nc|ncat|netcat|socat|openssl\s+s_client|fetch|python\d?|perl|php|ruby|telnet|ssh|scp|rsync|finger|nslookup|dig|drill|host|host\s+-t|tftp|base64\s+-d|xxd\s+-r|gzip\s+-d|gunzip|bzip2\s+-d|bunzip2|chmod\s+\+x|chmod\s+[0-7]{3,4}|crontab|systemctl|service|launchctl|sudo|su\b|setuid|usermod|chattr|setcap|sed\s+-i|tee\s+-a|>>?\s*\/etc\/|\/dev\/tcp\/|\/dev\/udp\/|>\s*\/dev\/null|2>&1|powershell|pwsh|wmic|certutil|mshta|rundll32|regsvr32)\b/i;

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
      const value = vars[name];
      if (value === undefined) continue;
      const resolved = _resolveParamExpansion(value, op);
      if (resolved === null || resolved === m[0] || resolved.length < 1) continue;
      // Only emit single-token expansions that resolve to something
      // recognisably command-shaped. The interesting case for a
      // standalone expansion is a full command name — the per-character
      // shred shape is handled by the line-level resolver below.
      if (!SENSITIVE_BASH_KEYWORDS.test(resolved) && !this._bruteforce) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash Variable Expansion (single)',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: resolved,
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
    const pipeShellRe = /\b(?:curl|wget|fetch|invoke-webrequest|iwr|irm)\b[^\r\n|]{0,400}\|\s*(?:base64\s+-(?:d|decode)\s*\|\s*)?(?:xxd\s+-r(?:\s+-p)?\s*\|\s*)?(?:rev\s*\|\s*)?(?:ba)?sh\b/gi;
    while ((m = pipeShellRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (raw.length > 600) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash Pipe-to-Shell (live fetch)',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: raw,
        _executeOutput: true,
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
    const evalCmdSubRe = /\b(?:eval|exec|source|\.)\s+(?:"\$\(|\$\(|`)\s*echo\s+["']([A-Za-z0-9+/=\s]{4,4096})["']\s*\|\s*base64\s+-(?:d|decode)\s*(?:\)|`)/g;
    while ((m = evalCmdSubRe.exec(text)) !== null) {
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
    // We require ≥3 single-char-or-short vars adjacent without
    // intervening whitespace; the joined value must hit
    // SENSITIVE_BASH_KEYWORDS to fire (otherwise legitimate
    // `$prefix$mid$suffix` path-building emits noise).
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
      if (resolved < 3) continue;
      if (joined.length < 3) continue;
      if (joined === raw) continue;
      if (!SENSITIVE_BASH_KEYWORDS.test(joined) && !this._bruteforce) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: unresolved === 0
          ? 'Bash Variable Concatenation'
          : 'Bash Variable Concatenation (partial)',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: joined,
      });
    }

    // ── /dev/tcp reverse shell — the canonical bash reverse-shell
    //    primitive. Detection-only (no decode); the post-processor
    //    bumps severity via _executeOutput + dangerousPatterns.
    const devTcpRe = /\b(?:bash|sh)\s+-i\b[^\r\n]{0,200}>\s*&?\s*\/dev\/tcp\/[\w.\-]+\/\d{1,5}|\b\/dev\/tcp\/[\w.\-]+\/\d{1,5}\b[^\r\n]{0,200}\b(?:0<&|>&)\d/gi;
    while ((m = devTcpRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (raw.length > 500) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'Bash /dev/tcp Reverse Shell',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: raw,
        _executeOutput: true,
      });
    }

    return candidates;
  },
});
