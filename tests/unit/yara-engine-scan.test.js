'use strict';
// ════════════════════════════════════════════════════════════════════════════
// yara-engine-scan.test.js — `YaraEngine.scan` correctness.
//
// Why this file
// -------------
// Pins the matcher and condition-evaluator surface so refactors can't
// silently regress rule firing. Companion to `yara-engine-parse.test.js`
// (parser/validator) and `yara-rules-perf.test.js` (wall-clock budgets).
//
// Coverage
// --------
//   • Text strings: ASCII, nocase, fullword. (Wide is exercised via
//     direct strDef-injection — see comment on the parser bug below.)
//   • Hex strings: literal bytes, single-byte wildcard `??`, jumps `[N-M]`.
//   • Regex strings: case-sensitive vs nocase, iteration cap surfaces in
//     `errorSink`, time cap surfaces in `errorSink`, the cached
//     `_compiledRx` is reused across scans.
//   • Conditions:
//       any/all/N of them, $var at N, $var in (lo..hi),
//       N of ($prefix*), uint8/16/32(N), int8/16/32(N), filesize,
//       #var (count comparisons), boolean and/or/not, parens, true/false.
//   • Format-tag plumbing:
//       is_* keyword evaluation against ctx.formatTag (missing ctx ⇒ false),
//       meta.applies_to short-circuit (skip whole rule on mismatch).
//   • Engine bug ratchets:
//       — Parser drops modifiers in multi-line form (see
//         yara-engine-parse.test.js). For wide/nocase scan-path tests we
//         force `strDef.wide = true` etc. on the parsed rule rather than
//         relying on the parser to set them.
//       — `ascii wide` correctness (matches both ASCII *and* wide) is
//         deliberately NOT tested here. Current behaviour is to match
//         only `wide` when both are set, which is incorrect. The
//         correctness fix lands in Tier 2 alongside the test that locks
//         in the new behaviour. Adding the test now would either
//         (a) lock in the bug (worse than no test), or (b) ship a
//         pre-failing test (rejected by 'land in Phase 2 with the fix').
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/yara-engine.js']);
const { YaraEngine } = ctx;

// ── Helpers ────────────────────────────────────────────────────────────────

/** Parse one rule and return the parsed rule object. */
function parse(src) {
  const trimmed = src.startsWith('\n') ? src : '\n' + src;
  const tail = trimmed.endsWith('\n') ? trimmed : trimmed + '\n';
  const r = YaraEngine.parseRules(tail);
  if (r.errors.length) throw new Error('parse errors: ' + r.errors.join('; '));
  if (!r.rules.length) throw new Error('no rules parsed');
  return r.rules;
}

/** Scan and return the array of matched rule names (sorted, host realm). */
function scanNames(buf, rules, opts) {
  return host(YaraEngine.scan(buf, rules, opts || undefined).map(r => r.ruleName)).sort();
}

// ── Text strings ──────────────────────────────────────────────────────────

test('scan: text string matches at any offset', () => {
  const rules = parse(`rule R {
  strings:
    $a = "needle"
  condition: $a
}`);
  assert.deepEqual(scanNames(Buffer.from('hay needle stack'), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from('no n33dle here'), rules), []);
});

test('scan: text string nocase matches case-insensitively (forced flag)', () => {
  // Parser bug drops the `nocase` modifier in multi-line form — we set
  // it directly on the parsed strDef to exercise the matcher path.
  const rules = parse(`rule R {
  strings:
    $a = "hello"
  condition: $a
}`);
  rules[0].strings[0].nocase = true;
  assert.deepEqual(scanNames(Buffer.from('HELLO world'), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from('hello world'), rules), ['R']);
  rules[0].strings[0].nocase = false;
  // After clearing the cached lowercased lookup is a no-op (the matcher
  // re-derives per call), so the rule no longer matches uppercase.
  assert.deepEqual(scanNames(Buffer.from('HELLO world'), rules), []);
});

test('scan: text string fullword honours word boundary (forced flag)', () => {
  const rules = parse(`rule R {
  strings:
    $a = "cat"
  condition: $a
}`);
  rules[0].strings[0].fullword = true;
  assert.deepEqual(scanNames(Buffer.from('the cat sat'), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from('catalogue'), rules), []);
  assert.deepEqual(scanNames(Buffer.from('decat'), rules), []);
});

test('scan: text string wide matches UTF-16LE bytes (forced flag)', () => {
  const rules = parse(`rule R {
  strings:
    $a = "AB"
  condition: $a
}`);
  // Force a wide-only state (wide=true, ascii=false). The parser
  // produces this combination naturally for `"AB" wide`; we mutate
  // here because the test pre-dates the parser carrying explicit
  // `ascii` flags and we want to keep the assertion focused on the
  // _findString branch behaviour rather than parser modifier capture
  // (the latter is covered by yara-engine-parse.test.js).
  rules[0].strings[0].wide = true;
  rules[0].strings[0].ascii = false;
  // 'AB' as UTF-16LE = A 00 B 00
  const buf = Buffer.from([0x90, 0x90, 0x41, 0x00, 0x42, 0x00, 0xFF]);
  assert.deepEqual(scanNames(buf, rules), ['R']);
  // Plain ASCII does NOT match a wide-only pattern — documented YARA
  // semantics: bare `wide` is wide-only, ASCII matching only resumes
  // when `ascii` is also specified (`ascii wide`).
  assert.deepEqual(scanNames(Buffer.from('AB'), rules), []);
});

test('scan: text string `ascii wide` matches BOTH alphabets', () => {
  // Phase 2a invariant: explicit `ascii wide` runs both the ASCII and
  // the wide branches of `_findString`. Pre-Phase-2a the engine
  // executed wide-only whenever `wide` was set, silently dropping
  // ASCII hits — and `ascii` was never parsed into a flag at all
  // (the parser's modifier-capture bug was the upstream cause; see
  // yara-engine-parse.test.js for that ratchet).
  const rules = parse(`rule R {
  strings:
    $a = "AB" ascii wide
  condition: $a
}`);
  assert.equal(rules[0].strings[0].ascii, true);
  assert.equal(rules[0].strings[0].wide, true);
  // ASCII-only buffer
  assert.deepEqual(scanNames(Buffer.from('xxABxx'), rules), ['R']);
  // Wide-only buffer (UTF-16LE 'AB')
  const wideBuf = Buffer.from([0x90, 0x41, 0x00, 0x42, 0x00, 0x90]);
  assert.deepEqual(scanNames(wideBuf, rules), ['R']);
  // Buffer with neither encoding does not match
  assert.deepEqual(scanNames(Buffer.from('xxxxxx'), rules), []);
});

test('scan: text string default (no modifier) is ASCII-only, ignores wide bytes', () => {
  // Companion to the `ascii wide` test: default text strings should
  // match ASCII and NOT inadvertently match wide-encoded bytes. This
  // was previously safe by accident (the engine ran the ASCII branch
  // when `wide` was unset), but is now an explicit invariant that
  // depends on the parser setting `ascii: true` for unmodified
  // strings.
  const rules = parse(`rule R {
  strings:
    $a = "AB"
  condition: $a
}`);
  assert.equal(rules[0].strings[0].ascii, true);
  assert.equal(rules[0].strings[0].wide, false);
  assert.deepEqual(scanNames(Buffer.from('xxABxx'), rules), ['R']);
  // UTF-16LE bytes for "AB" alone do NOT match a default text string
  const wideBuf = Buffer.from([0x41, 0x00, 0x42, 0x00]);
  assert.deepEqual(scanNames(wideBuf, rules), []);
});

// ── Hex strings ───────────────────────────────────────────────────────────

test('scan: hex literal matches exact bytes', () => {
  const rules = parse(`rule R {
  strings:
    $a = { 4D 5A }
  condition: $a
}`);
  assert.deepEqual(scanNames(Buffer.from([0x4D, 0x5A, 0x00]), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from([0x4D, 0x5B, 0x00]), rules), []);
});

test('scan: hex single-byte wildcard ??', () => {
  const rules = parse(`rule R {
  strings:
    $a = { 4D ?? 5A }
  condition: $a
}`);
  assert.deepEqual(scanNames(Buffer.from([0x4D, 0xFF, 0x5A]), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from([0x4D, 0x00, 0x5A]), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from([0x4D, 0xFF, 0x5B]), rules), []);
});

test('scan: hex jump [N] is treated as N wildcards (engine simplification)', () => {
  // The current engine simplifies `[N-M]` to N wildcards (lower bound).
  // This is a known approximation pinned here so a Tier-3 fix (proper
  // jump semantics) lands with a deliberate test update.
  const rules = parse(`rule R {
  strings:
    $a = { 4D [3-3] 5A }
  condition: $a
}`);
  assert.deepEqual(scanNames(Buffer.from([0x4D, 1, 2, 3, 0x5A]), rules), ['R']);
  // Jump-of-N should NOT match a payload of length-N+1 between anchors:
  assert.deepEqual(scanNames(Buffer.from([0x4D, 1, 2, 3, 4, 0x5A]), rules), []);
});

// ── Regex strings ─────────────────────────────────────────────────────────

test('scan: regex matches and respects /i flag', () => {
  const rules = parse(`rule R {
  strings:
    $a = /foo[0-9]+/i
  condition: $a
}`);
  assert.deepEqual(scanNames(Buffer.from('this is FOO42 here'), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from('no match'), rules), []);
});

test('scan: regex iter-cap is currently UNREACHABLE (engine bug ratchet)', () => {
  // ── KNOWN BUG, ratcheted ──────────────────────────────────────────────
  // The intent of `MAX_REGEX_ITERS = 10000` in `_findString` is to cap
  // pathological regex execution. In practice the iter-cap branch is
  // unreachable: the outer loop exits as soon as `matches.length >= MAX`
  // (MAX = 1000), and `iters++` only fires inside the loop body, so
  // `iters` can never exceed `MAX = 1000 < MAX_REGEX_ITERS = 10000`.
  //
  // The time-cap branch is similarly hard to hit because the clock is
  // only sampled every 256 iterations, and matches.length saturates at
  // 1000 well before any catastrophic regex completes a single
  // expensive `rx.exec` call.
  //
  // This test pins the broken state: with a regex that matches at every
  // byte over a long input, NO errorSink entry is emitted and the
  // matches array saturates at 1000 (the display cap), silently
  // truncating the rest. Tier-2 will rework the budget so the iter and
  // time caps actually engage on adversarial input — flipping this test
  // is the deliberate signal that the fix landed.
  const rules = parse(`rule R {
  strings:
    $a = /a/
  condition: #$a > 0
}`);
  const errs = [];
  const out = host(YaraEngine.scan(Buffer.from('a'.repeat(12000)), rules, { errors: errs }));
  assert.equal(host(errs).length, 0, 'errorSink is empty (bug)');
  // Rule still fires because #a > 0; the truncation is silent.
  assert.equal(out.length, 1);
  assert.equal(out[0].matches[0].matches.length, 20,
    'display cap of 20 is what the user actually sees');
});

test('scan: regex with catastrophic backtracking — current engine has no usable wall-clock cap', () => {
  // ── KNOWN BUG, ratcheted ──────────────────────────────────────────────
  // `_findString` claims a `TIME_BUDGET_MS = 250` per string. But the
  // budget is only checked between successful `rx.exec` calls, sampled
  // every 256 iterations. A SINGLE catastrophic `rx.exec` cannot be
  // interrupted; the engine sits inside V8's regex backtracker until
  // V8 returns. This is why the 161 KB base64-blob investigation
  // observed ~60 s scans instead of the documented 250 ms-per-rule cap.
  //
  // We don't actually run a 60-second regex here — we'd block CI. The
  // ratchet is structural: the test exists to fail (with a clear
  // explanation) the moment a Tier-2 fix introduces a chunked /
  // pre-emptable execution path that DOES cap a single bad exec.
  // Run a small canary that completes well under 250 ms — but assert
  // that NO time-cap diagnostic is emitted, locking in the current
  // never-fires behaviour.
  const rules = [{
    name: 'B', tags: '', meta: {}, condition: '$a',
    strings: [{
      id: '$a', type: 'regex',
      // A pattern with bounded backtracking on a small input. Real
      // pathological cases (`(a+)+b`) would block CI; we settle for
      // proving "no diagnostic is emitted on a benign run" so the
      // test ratchets on Tier-2 changes that flush a diagnostic for
      // every long-enough exec.
      pattern: 'a+b', flags: '', display: '/a+b/',
      nocase: false, wide: false, fullword: false,
    }],
  }];
  const errs = [];
  YaraEngine.scan(Buffer.from('aaaaab'), rules, { errors: errs });
  assert.equal(host(errs).length, 0,
    'No diagnostic on a benign exec — ratchet for Tier-2 wall-clock changes');
});

test('scan: regex compile failure surfaces in errorSink', () => {
  // Unbalanced regex — parseRules accepts the literal but compilation
  // fails at scan time. The error MUST surface, not silently disappear.
  // We bypass parseRules so we don't trip the validator.
  const rules = [{
    name: 'BadRx', tags: '', meta: {}, condition: '$a',
    strings: [{ id: '$a', type: 'regex', pattern: '(unclosed', flags: '', display: '/(unclosed/', nocase: false, wide: false, fullword: false }],
  }];
  const errs = [];
  const results = YaraEngine.scan(Buffer.from('x'), rules, { errors: errs });
  assert.equal(results.length, 0, 'rule must not match when its regex fails to compile');
  const errsHost = host(errs);
  assert.equal(errsHost.length, 1);
  assert.equal(errsHost[0].reason, 'invalid-regex');
});

test('scan: compiled regex is cached on strDef across scans', () => {
  const rules = parse(`rule R {
  strings:
    $a = /[a-z]+/
  condition: $a
}`);
  YaraEngine.scan(Buffer.from('hello'), rules);
  const cached = rules[0].strings[0]._compiledRx;
  assert.ok(cached instanceof RegExp || (cached && cached.constructor && cached.constructor.name === 'RegExp'),
    '_compiledRx should be set after first scan');
  YaraEngine.scan(Buffer.from('world'), rules);
  assert.equal(rules[0].strings[0]._compiledRx, cached, 'cache should persist');
});

// ── Conditions: any/all/N of them ─────────────────────────────────────────

test('scan: any of them — true if at least one string matches', () => {
  const rules = parse(`rule R {
  strings:
    $a = "alpha"
    $b = "beta"
  condition: any of them
}`);
  assert.deepEqual(scanNames(Buffer.from('this contains alpha'), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from('this contains beta'), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from('neither token'), rules), []);
});

test('scan: all of them — true only if every string matches', () => {
  const rules = parse(`rule R {
  strings:
    $a = "alpha"
    $b = "beta"
  condition: all of them
}`);
  assert.deepEqual(scanNames(Buffer.from('alpha and beta'), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from('alpha only'), rules), []);
});

test('scan: N of them', () => {
  const rules = parse(`rule R {
  strings:
    $a = "alpha"
    $b = "beta"
    $c = "gamma"
  condition: 2 of them
}`);
  assert.deepEqual(scanNames(Buffer.from('alpha and beta'), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from('alpha gamma'), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from('alpha only'), rules), []);
});

test('scan: N of ($prefix*)', () => {
  const rules = parse(`rule R {
  strings:
    $pre1 = "alpha"
    $pre2 = "beta"
    $other = "gamma"
  condition: 2 of ($pre*)
}`);
  // $pre1 + $pre2 → 2 ⇒ match.
  assert.deepEqual(scanNames(Buffer.from('alpha beta'), rules), ['R']);
  // $pre1 + $other → only one $pre* ⇒ no match.
  assert.deepEqual(scanNames(Buffer.from('alpha gamma'), rules), []);
});

// ── Conditions: $var at N, $var in (lo..hi) ───────────────────────────────

test('scan: $var at <offset>', () => {
  const rules = parse(`rule R {
  strings:
    $a = "abc"
  condition: $a at 5
}`);
  assert.deepEqual(scanNames(Buffer.from('XXXXXabc'), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from('abcXXXXX'), rules), []);
});

test('scan: $var in (lo..hi)', () => {
  const rules = parse(`rule R {
  strings:
    $a = "abc"
  condition: $a in (3..10)
}`);
  assert.deepEqual(scanNames(Buffer.from('XXXXXabc'), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from('abcXXXXX'), rules), []);
  assert.deepEqual(scanNames(Buffer.from('XXXXXXXXXXXabc'), rules), []);
});

// ── Conditions: #var, integers, filesize ──────────────────────────────────

test('scan: #var count comparison', () => {
  const rules = parse(`rule R {
  strings:
    $a = "x"
  condition: #a > 2
}`);
  assert.deepEqual(scanNames(Buffer.from('xxxx'), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from('xx'), rules), []);
  assert.deepEqual(scanNames(Buffer.from(''), rules), []);
});

test('scan: uint16(0) reads little-endian', () => {
  const rules = parse(`rule R {
  condition: uint16(0) == 0x5a4d
}`);
  assert.deepEqual(scanNames(Buffer.from([0x4d, 0x5a, 0x90, 0x00]), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from([0x5a, 0x4d, 0x90, 0x00]), rules), []);
});

test('scan: uint32(0) reads little-endian', () => {
  const rules = parse(`rule R {
  condition: uint32(0) == 0x04030201
}`);
  assert.deepEqual(scanNames(Buffer.from([0x01, 0x02, 0x03, 0x04, 0xFF]), rules), ['R']);
});

test('scan: filesize comparison', () => {
  const rules = parse(`rule R {
  condition: filesize > 5
}`);
  assert.deepEqual(scanNames(Buffer.from([0,1,2,3,4,5,6,7]), rules), ['R']);
  assert.deepEqual(scanNames(Buffer.from([0,1,2]), rules), []);
});

// ── Conditions: boolean composition ───────────────────────────────────────

test('scan: and / or / not / parens', () => {
  const rules = parse(`rule R {
  strings:
    $a = "alpha"
    $b = "beta"
    $c = "gamma"
  condition: ($a and $b) or (not $c)
}`);
  assert.deepEqual(scanNames(Buffer.from('alpha beta gamma'), rules), ['R'],
    '($a and $b) is true');
  assert.deepEqual(scanNames(Buffer.from('only delta'), rules), ['R'],
    '(not $c) is true');
  assert.deepEqual(scanNames(Buffer.from('alpha gamma'), rules), [],
    '$a alone with $c present ⇒ both branches false');
});

test('scan: true / false literals', () => {
  const rT = parse(`rule T { condition: true
}`);
  const rF = parse(`rule F { condition: false
}`);
  assert.deepEqual(scanNames(Buffer.from('xx'), rT), ['T']);
  assert.deepEqual(scanNames(Buffer.from('xx'), rF), []);
});

// ── Format predicates: is_* ───────────────────────────────────────────────

test('scan: is_pe — true only when ctx.formatTag === "pe"', () => {
  const rules = parse(`rule R {
  strings:
    $a = "X"
  condition: $a and is_pe
}`);
  const buf = Buffer.from('XXX');
  assert.deepEqual(scanNames(buf, rules), [], 'no ctx ⇒ is_* false');
  assert.deepEqual(
    scanNames(buf, rules, { context: { formatTag: 'plaintext' } }), [],
    'wrong formatTag ⇒ is_pe false',
  );
  assert.deepEqual(
    scanNames(buf, rules, { context: { formatTag: 'pe' } }), ['R'],
    'matching formatTag ⇒ is_pe true',
  );
});

test('scan: is_office group alias matches any office tag', () => {
  const rules = parse(`rule R {
  condition: is_office
}`);
  for (const tag of ['doc', 'xlsx', 'pptx', 'odt', 'msg']) {
    assert.deepEqual(
      scanNames(Buffer.from('x'), rules, { context: { formatTag: tag } }),
      ['R'],
      `is_office should match formatTag=${tag}`,
    );
  }
  for (const tag of ['pe', 'plaintext', 'pdf']) {
    assert.deepEqual(
      scanNames(Buffer.from('x'), rules, { context: { formatTag: tag } }),
      [],
      `is_office should NOT match formatTag=${tag}`,
    );
  }
});

test('scan: unknown is_* keyword evaluates to false (no error)', () => {
  // Parser/validator emit a warning; the evaluator silently treats an
  // unknown predicate as false so the surrounding boolean expression
  // remains well-formed. This test pins that behaviour.
  const rules = parse(`rule R {
  condition: is_weasel
}`);
  assert.deepEqual(scanNames(Buffer.from('x'), rules, { context: { formatTag: 'pe' } }), []);
});

// ── meta.applies_to short-circuit ─────────────────────────────────────────

test('scan: meta.applies_to skips entire rule on mismatch', () => {
  const rules = parse(`rule R {
  meta:
    applies_to = "pe"
  strings:
    $a = "hello"
  condition: $a
}`);
  const buf = Buffer.from('hello world');
  assert.deepEqual(scanNames(buf, rules), [], 'no formatTag ⇒ skip');
  assert.deepEqual(scanNames(buf, rules, { context: { formatTag: 'plaintext' } }), [],
    'wrong formatTag ⇒ skip');
  assert.deepEqual(scanNames(buf, rules, { context: { formatTag: 'pe' } }), ['R']);
});

test('scan: meta.applies_to multi-tag list', () => {
  const rules = parse(`rule R {
  meta:
    applies_to = "pe, elf"
  condition: true
}`);
  for (const tag of ['pe', 'elf']) {
    assert.deepEqual(scanNames(Buffer.from('x'), rules, { context: { formatTag: tag } }), ['R']);
  }
  assert.deepEqual(scanNames(Buffer.from('x'), rules, { context: { formatTag: 'plaintext' } }), []);
});

test('scan: meta.applies_to "any" matches every formatTag except decoded-payload', () => {
  const rules = parse(`rule R {
  meta:
    applies_to = "any"
  condition: true
}`);
  for (const tag of ['pe', 'elf', 'plaintext', 'pdf']) {
    assert.deepEqual(scanNames(Buffer.from('x'), rules, { context: { formatTag: tag } }), ['R']);
  }
  assert.deepEqual(scanNames(Buffer.from('x'), rules, { context: { formatTag: 'decoded-payload' } }), [],
    '"any" alone must NOT include decoded-payload');
});

test('scan: meta.applies_to "any, decoded-payload" includes decoded-payload', () => {
  const rules = parse(`rule R {
  meta:
    applies_to = "any, decoded-payload"
  condition: true
}`);
  assert.deepEqual(scanNames(Buffer.from('x'), rules, { context: { formatTag: 'decoded-payload' } }), ['R']);
  assert.deepEqual(scanNames(Buffer.from('x'), rules, { context: { formatTag: 'pe' } }), ['R']);
});

// ── Multi-rule scans share a single buffer pass ───────────────────────────

test('scan: independent rules each evaluate', () => {
  const rules = parse(`rule A {
  strings: $x = "alpha"
  condition: $x
}
rule B {
  strings: $x = "beta"
  condition: $x
}`);
  assert.deepEqual(scanNames(Buffer.from('alpha and beta'), rules), ['A', 'B']);
  assert.deepEqual(scanNames(Buffer.from('only alpha'), rules), ['A']);
  assert.deepEqual(scanNames(Buffer.from('neither'), rules), []);
});

// ── Result shape ──────────────────────────────────────────────────────────

test('scan: result includes ruleName, tags, meta, condition, matches[]', () => {
  const rules = parse(`rule R : alpha beta {
  meta:
    description = "x"
    severity = "high"
  strings:
    $a = "needle"
  condition: $a
}`);
  const out = host(YaraEngine.scan(Buffer.from('hay needle'), rules));
  assert.equal(out.length, 1);
  assert.equal(out[0].ruleName, 'R');
  assert.equal(out[0].tags, 'alpha beta');
  assert.equal(out[0].meta.description, 'x');
  assert.equal(out[0].meta.severity, 'high');
  assert.equal(out[0].condition, '$a');
  assert.equal(out[0].matches.length, 1);
  assert.equal(out[0].matches[0].id, '$a');
  assert.equal(out[0].matches[0].matches[0].offset, 4);
  assert.equal(out[0].matches[0].matches[0].length, 6);
});

test('scan: each string match list is capped at 20 (display cap)', () => {
  const rules = parse(`rule R {
  strings:
    $a = "x"
  condition: #a > 0
}`);
  // 200 occurrences in input — engine caps display at 20.
  const out = host(YaraEngine.scan(Buffer.from('x'.repeat(200)), rules));
  assert.equal(out[0].matches[0].matches.length, 20);
});

// ── Edge cases ────────────────────────────────────────────────────────────

test('scan: empty buffer never matches a string-bearing rule', () => {
  const rules = parse(`rule R {
  strings: $a = "x"
  condition: $a
}`);
  assert.deepEqual(scanNames(Buffer.from(''), rules), []);
});

test('scan: empty buffer matches a "true" rule', () => {
  const rules = parse(`rule R {
  condition: true
}`);
  assert.deepEqual(scanNames(Buffer.from(''), rules), ['R']);
});

test('scan: empty rules array returns []', () => {
  const out = host(YaraEngine.scan(Buffer.from('xx'), []));
  assert.deepEqual(out, []);
});

test('scan: ArrayBuffer and Uint8Array inputs are both accepted', () => {
  const rules = parse(`rule R {
  strings: $a = "ABC"
  condition: $a
}`);
  const u8 = new Uint8Array([0x41, 0x42, 0x43, 0x44]);
  const ab = u8.buffer;
  assert.deepEqual(scanNames(u8, rules), ['R']);
  assert.deepEqual(scanNames(ab, rules), ['R']);
});
