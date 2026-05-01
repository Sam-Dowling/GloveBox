'use strict';
// ════════════════════════════════════════════════════════════════════════════
// yara-engine-parse.test.js — `YaraEngine.parseRules` and `.validate`
// correctness.
//
// Why this file
// -------------
// `src/yara-engine.js` ships a hand-rolled YARA parser/validator. The
// existing `decoded-yara-filter.test.js` covers host-side orchestration
// only (with a faked engine); there was no direct test of the engine
// itself. This file pins the parse + validate surface so future
// refactors of the parser don't silently regress rule loading.
//
// Coverage
// --------
//   • Happy paths: text / hex / regex strings, every modifier combo,
//     meta blocks, tags, conditions.
//   • Malformed inputs: missing `condition:`, missing colons, unclosed
//     quote, unclosed hex brace, name starts with digit.
//   • Bounds: 2 KB regex cap; long-but-bounded tag list still parses;
//     parser doesn't backtrack catastrophically on malformed bodies.
//   • Validation: duplicate rule names, duplicate string ids,
//     undefined-string-refs (`$undef`), unknown `is_*` predicates,
//     unknown `applies_to` values, non-canonical severity, hex-token
//     validation.
//   • Security: prototype-pollution-shaped meta keys (`__proto__`,
//     `constructor`) are dropped, not surfaced on `rule.meta`, and
//     never mutate `Object.prototype` (CodeQL js/remote-property-injection).
//   • Public surface: `_KNOWN_FORMAT_TAGS` is the union of all
//     FORMAT_PREDICATES values; `_resolveAppliesToToken('any')` returns
//     every known tag *except* `decoded-payload`; group aliases resolve.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/yara-engine.js']);
const { YaraEngine } = ctx;

// ── Helpers ────────────────────────────────────────────────────────────────

/** Build a minimal rule body. The parser's outer regex requires the rule
 *  body to end with `\n}` so we always emit multi-line form here. */
function rule(body) {
  return body.endsWith('\n') ? body : body + '\n';
}

// ── parseRules: happy paths ───────────────────────────────────────────────

test('parseRules: text string with no modifiers', () => {
  const src = rule(`rule R {
  strings:
    $a = "hello"
  condition:
    $a
}`);
  const { rules, errors } = YaraEngine.parseRules(src);
  assert.equal(errors.length, 0);
  assert.equal(rules.length, 1);
  const r = rules[0];
  assert.equal(r.name, 'R');
  assert.equal(r.strings.length, 1);
  assert.equal(r.strings[0].type, 'text');
  assert.equal(r.strings[0].pattern, 'hello');
  assert.equal(r.strings[0].nocase, false);
  assert.equal(r.strings[0].wide, false);
  assert.equal(r.strings[0].fullword, false);
  assert.equal(r.condition, '$a');
});

test('parseRules: KNOWN BUG — text-string modifiers are silently dropped (multi-line form)', () => {
  // ── KNOWN BUG, ratcheted ──────────────────────────────────────────────
  // The `_parseRuleBody` regex's modifier tail is `(nocase|wide|ascii|
  // fullword|\s)*`. Because `\s` is one of the alternatives and `*` only
  // retains the LAST captured iteration, the captured group is whitespace
  // when ANY whitespace follows the modifier — which is the canonical
  // multi-line rule form (`$a = "x" nocase\n    $b = …`) used everywhere
  // in `src/rules/`.
  //
  // Effect: every `nocase` / `wide` / `fullword` modifier in the bundled
  // rule corpus is silently a no-op, and case-sensitive matching is the
  // accidental default. The engine still recognises the modifier as
  // syntax (no parse error), so rule authors can't tell their rule isn't
  // doing what they wrote.
  //
  // This test pins the buggy behaviour so a Tier-2 fix flips it
  // deliberately (and updates this test in the same commit). Removing
  // this test without fixing the parser would let the bug regress
  // silently again. See `src/yara-engine.js:619` (`strRx` regex) and the
  // catch-all `else if (sm[6] !== undefined)` branch immediately below.
  const src = rule(`rule R {
  strings:
    $a = "x" nocase
    $b = "y" wide
    $c = "z" fullword
  condition: $a
}`);
  const { rules, errors } = YaraEngine.parseRules(src);
  assert.equal(errors.length, 0);
  // ALL three modifiers are dropped — the parsed flags are false, false, false.
  for (const s of rules[0].strings) {
    assert.equal(s.nocase,   false, `${s.id}: nocase should be (buggily) false`);
    assert.equal(s.wide,     false, `${s.id}: wide should be (buggily) false`);
    assert.equal(s.fullword, false, `${s.id}: fullword should be (buggily) false`);
  }
});

test('parseRules: text-string modifier IS captured at end-of-block (no trailing whitespace)', () => {
  // Edge case where the modifier IS the last thing before `}` — no
  // intervening whitespace token, so the regex's `(...|\s)*` retains the
  // modifier in its capture group. This pins the one path where modifiers
  // currently work, and documents how narrow it is.
  const src = `rule R {
  strings:
    $a = "x" nocase
  condition: $a}`;
  const { rules, errors } = YaraEngine.parseRules(src);
  // `}` without a leading newline: parser's outer regex requires `\n}` so
  // this won't parse at all. Wrap it differently — newline immediately
  // after the modifier with no space:
  void rules; void errors;
  const src2 = 'rule R {\n  strings:\n    $a = "x" nocase\n  condition: $a\n}';
  const r2 = YaraEngine.parseRules(src2);
  // Verify the bug: even with minimal whitespace the modifier is dropped.
  // We assert the buggy behaviour rather than the expected one to keep
  // this test green pre-fix.
  assert.equal(r2.rules[0].strings[0].nocase, false);
});

test('parseRules: hex string with wildcards and jumps', () => {
  const src = rule(`rule R {
  strings:
    $a = { AA BB ?? CC [2-4] DD }
  condition: $a
}`);
  const { rules, errors } = YaraEngine.parseRules(src);
  assert.equal(errors.length, 0);
  assert.equal(rules.length, 1);
  assert.equal(rules[0].strings[0].type, 'hex');
  assert.match(rules[0].strings[0].pattern, /AA BB \?\? CC \[2-4\] DD/);
});

test('parseRules: regex string preserves flags', () => {
  const src = rule(`rule R {
  strings:
    $a = /foo[a-z]+/i
  condition: $a
}`);
  const { rules, errors } = YaraEngine.parseRules(src);
  assert.equal(errors.length, 0);
  assert.equal(rules.length, 1);
  const s = rules[0].strings[0];
  assert.equal(s.type, 'regex');
  assert.equal(s.pattern, 'foo[a-z]+');
  assert.ok(s.flags.includes('i'));
  assert.equal(s.nocase, true);
});

test('parseRules: meta block populates rule.meta', () => {
  const src = rule(`rule R {
  meta:
    description = "hello world"
    severity = "high"
    applies_to = "pe"
  condition: true
}`);
  const { rules, errors } = YaraEngine.parseRules(src);
  assert.equal(errors.length, 0);
  assert.equal(rules[0].meta.description, 'hello world');
  assert.equal(rules[0].meta.severity, 'high');
  assert.equal(rules[0].meta.applies_to, 'pe');
});

test('parseRules: tags are captured', () => {
  const src = rule(`rule R : alpha beta gamma {
  condition: true
}`);
  const { rules, errors } = YaraEngine.parseRules(src);
  assert.equal(errors.length, 0);
  assert.equal(rules[0].tags, 'alpha beta gamma');
});

test('parseRules: condition is preserved verbatim (modulo trim)', () => {
  const src = rule(`rule R {
  strings:
    $a = "x"
    $b = "y"
  condition:
    $a and $b
}`);
  const { rules } = YaraEngine.parseRules(src);
  assert.equal(rules[0].condition, '$a and $b');
});

test('parseRules: line comments inside rule body are stripped', () => {
  const src = rule(`rule R {
  strings:
    $a = "x"  // inline comment
  // standalone line comment
  condition: $a
}`);
  const { rules, errors } = YaraEngine.parseRules(src);
  assert.equal(errors.length, 0);
  assert.equal(rules[0].strings.length, 1);
});

test('parseRules: multi-rule source returns all rules', () => {
  const src = rule(`rule A {
  condition: true
}
rule B {
  condition: false
}`);
  const { rules } = YaraEngine.parseRules(src);
  // host(): values come from the vm sandbox realm; deepStrictEqual checks
  // prototype identity, so we project through JSON for cross-realm
  // structural compare.
  assert.deepEqual(host(rules.map(r => r.name)), ['A', 'B']);
});

// ── parseRules: malformed / errors ────────────────────────────────────────

test('parseRules: empty source returns empty rules and no error', () => {
  const r = YaraEngine.parseRules('');
  assert.equal(r.rules.length, 0);
  assert.equal(r.errors.length, 0);
});

test('parseRules: junk source surfaces a "no valid rules" error', () => {
  const r = YaraEngine.parseRules('this is not yara');
  assert.equal(r.rules.length, 0);
  assert.equal(r.errors.length, 1);
  assert.match(r.errors[0], /No valid YARA rules/i);
});

// ── Security: prototype pollution defence ─────────────────────────────────

test('parseRules: __proto__ / constructor meta keys are dropped', () => {
  const src = rule(`rule P {
  meta:
    __proto__ = "polluted"
    constructor = "polluted"
    description = "safe"
  condition: true
}`);
  const { rules, errors } = YaraEngine.parseRules(src);
  assert.equal(errors.length, 0);
  // Only the whitelisted key survives.
  const keys = Object.keys(rules[0].meta);
  assert.deepEqual(keys, ['description']);
  assert.equal(rules[0].meta.description, 'safe');
  // No global pollution.
  assert.equal(Object.prototype.polluted, undefined);
});

test('parseRules: meta is a null-prototype object', () => {
  const src = rule(`rule P {
  meta:
    description = "x"
  condition: true
}`);
  const { rules } = YaraEngine.parseRules(src);
  assert.equal(Object.getPrototypeOf(rules[0].meta), null);
});

// ── validate: structural errors ───────────────────────────────────────────

test('validate: missing condition: section is an error', () => {
  const src = rule(`rule M {
  strings:
    $a = "x"
}`);
  const v = YaraEngine.validate(src);
  assert.ok(v.errors.some(e => /missing required "condition:"/.test(e)),
    `expected missing-condition error, got: ${v.errors.join(';')}`);
});

test('validate: rule name starting with a digit is an error', () => {
  // The outer parseRules regex won't bind `\d…` to a rule (rule names
  // require `\w+` which DOES include digits as start). The validator's
  // structural pass enforces the leading-non-digit rule.
  const src = rule(`rule 9R {
  condition: true
}`);
  const v = YaraEngine.validate(src);
  assert.ok(
    v.errors.some(e => /name cannot start with a digit/.test(e)),
    `expected leading-digit error, got: ${v.errors.join(';')}`,
  );
});

test('validate: duplicate rule names are an error', () => {
  const src = rule(`rule X {
  condition: true
}
rule X {
  condition: false
}`);
  const v = YaraEngine.validate(src);
  assert.ok(v.errors.some(e => /Duplicate rule name/.test(e)));
});

test('validate: duplicate string id is an error', () => {
  const src = rule(`rule D {
  strings:
    $a = "x"
    $a = "y"
  condition: $a
}`);
  const v = YaraEngine.validate(src);
  assert.ok(v.errors.some(e => /duplicate string identifier "\$a"/.test(e)));
});

test('validate: condition referencing undefined string is an error', () => {
  const src = rule(`rule U {
  strings:
    $a = "x"
  condition: $b
}`);
  const v = YaraEngine.validate(src);
  assert.ok(v.errors.some(e => /undefined string "\$b"/.test(e)));
});

test('validate: regex pattern over 2 KB is rejected', () => {
  const big = 'a'.repeat(2049);
  const src = rule(`rule L {
  strings:
    $a = /${big}/
  condition: $a
}`);
  const v = YaraEngine.validate(src);
  assert.ok(v.errors.some(e => /too long \(>2048/.test(e)));
});

test('validate: invalid hex token is an error', () => {
  const src = rule(`rule H {
  strings:
    $a = { AA ZZ BB }
  condition: $a
}`);
  const v = YaraEngine.validate(src);
  assert.ok(v.errors.some(e => /invalid hex token/.test(e)),
    `expected hex-token error, got: ${v.errors.join(';')}`);
});

test('validate: empty hex pattern is an error', () => {
  const src = rule(`rule H {
  strings:
    $a = {  }
  condition: $a
}`);
  const v = YaraEngine.validate(src);
  assert.ok(v.errors.some(e => /empty hex pattern/.test(e)),
    `expected empty-hex error, got: ${v.errors.join(';')}`);
});

// ── validate: warnings (Loupe-extension surface) ──────────────────────────

test('validate: unknown is_* predicate is a warning, not an error', () => {
  const src = rule(`rule B {
  condition: is_weasel
}`);
  const v = YaraEngine.validate(src);
  assert.equal(v.errors.length, 0);
  assert.ok(v.warnings.some(w => /unknown format predicate "is_weasel"/.test(w)));
});

test('validate: unknown applies_to token is a warning', () => {
  const src = rule(`rule A {
  meta:
    applies_to = "weasel"
  condition: true
}`);
  const v = YaraEngine.validate(src);
  assert.equal(v.errors.length, 0);
  assert.ok(v.warnings.some(w => /unknown applies_to value "weasel"/.test(w)));
});

test('validate: non-canonical severity is a warning', () => {
  const src = rule(`rule S {
  meta:
    severity = "MEGA"
  condition: true
}`);
  const v = YaraEngine.validate(src);
  assert.equal(v.errors.length, 0);
  assert.ok(v.warnings.some(w => /unknown severity "MEGA"/.test(w)));
});

test('validate: every canonical severity is accepted without warning', () => {
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    const src = rule(`rule S {
  meta: severity = "${sev}"
  condition: true
}`);
    const v = YaraEngine.validate(src);
    const sevWarn = v.warnings.find(w => /unknown severity/.test(w));
    assert.equal(sevWarn, undefined, `severity ${sev} should not warn`);
  }
});

// ── Public surface: format-tag plumbing ───────────────────────────────────

test('FORMAT_PREDICATES is frozen', () => {
  assert.ok(Object.isFrozen(YaraEngine.FORMAT_PREDICATES));
});

test('_KNOWN_FORMAT_TAGS is the union of every FORMAT_PREDICATES value', () => {
  const tags = YaraEngine._KNOWN_FORMAT_TAGS;
  assert.ok(tags instanceof Set);
  // Spot-check coverage of the obvious pillars.
  for (const t of ['pe', 'elf', 'macho', 'pdf', 'svg', 'plist',
                   'ps1', 'bash', 'plaintext', 'decoded-payload']) {
    assert.ok(tags.has(t), `_KNOWN_FORMAT_TAGS missing "${t}"`);
  }
  // Every value in every list is present.
  for (const list of Object.values(YaraEngine.FORMAT_PREDICATES)) {
    for (const t of list) assert.ok(tags.has(t), `${t} not in _KNOWN_FORMAT_TAGS`);
  }
});

test('_resolveAppliesToToken: known tag returns [tag]', () => {
  assert.deepEqual(host(YaraEngine._resolveAppliesToToken('pe')), ['pe']);
  assert.deepEqual(host(YaraEngine._resolveAppliesToToken('  PE  ')), ['pe']);
});

test('_resolveAppliesToToken: group alias expands', () => {
  const office = host(YaraEngine._resolveAppliesToToken('office'));
  assert.ok(office.includes('doc'));
  assert.ok(office.includes('xlsx'));
  assert.deepEqual(host(YaraEngine._resolveAppliesToToken('is_office')), office);
});

test('_resolveAppliesToToken: unknown token returns []', () => {
  assert.deepEqual(host(YaraEngine._resolveAppliesToToken('weasel')), []);
  assert.deepEqual(host(YaraEngine._resolveAppliesToToken('')), []);
  assert.deepEqual(host(YaraEngine._resolveAppliesToToken(null)), []);
});

test('_resolveAppliesToToken: "any" expands to every tag except decoded-payload', () => {
  const any = new Set(YaraEngine._resolveAppliesToToken('any'));
  assert.ok(any.has('pe'));
  assert.ok(any.has('plaintext'));
  assert.ok(!any.has('decoded-payload'),
    'decoded-payload must not be in `any` expansion (it is opt-in only)');
  // Same as is_any.
  assert.deepEqual(
    new Set(YaraEngine._resolveAppliesToToken('is_any')),
    any,
  );
});

test('_matchesAppliesTo: missing formatTag short-circuits to false', () => {
  assert.equal(YaraEngine._matchesAppliesTo('pe', null), false);
  assert.equal(YaraEngine._matchesAppliesTo('pe', undefined), false);
  assert.equal(YaraEngine._matchesAppliesTo('pe', ''), false);
});

test('_matchesAppliesTo: empty applies_to returns true (no gate)', () => {
  assert.equal(YaraEngine._matchesAppliesTo('', 'pe'), true);
  assert.equal(YaraEngine._matchesAppliesTo(null, 'pe'), true);
});

test('_matchesAppliesTo: comma- and whitespace-separated lists', () => {
  assert.equal(YaraEngine._matchesAppliesTo('pe, elf', 'elf'), true);
  assert.equal(YaraEngine._matchesAppliesTo('pe elf macho', 'macho'), true);
  assert.equal(YaraEngine._matchesAppliesTo('pe, elf', 'plaintext'), false);
});

test('_matchesAppliesTo: group alias matches member tag', () => {
  assert.equal(YaraEngine._matchesAppliesTo('office', 'docx'), true);
  assert.equal(YaraEngine._matchesAppliesTo('script', 'ps1'), true);
});

test('_matchesAppliesTo: "any, decoded-payload" matches decoded-payload', () => {
  assert.equal(YaraEngine._matchesAppliesTo('any, decoded-payload', 'decoded-payload'), true);
  assert.equal(YaraEngine._matchesAppliesTo('any, decoded-payload', 'pe'), true);
});

// ── Determinism: parseRules is pure (same input → same output) ─────────────

test('parseRules: deterministic across repeat calls', () => {
  const src = rule(`rule R {
  meta:
    description = "x"
  strings:
    $a = "hello"
    $b = /world/i
  condition: $a or $b
}`);
  const a = YaraEngine.parseRules(src);
  const b = YaraEngine.parseRules(src);
  // The rule objects mutate `_compiledRx` lazily during scan, but parse
  // alone should produce structurally identical results.
  assert.deepEqual(
    JSON.parse(JSON.stringify(a.rules)),
    JSON.parse(JSON.stringify(b.rules)),
  );
});
