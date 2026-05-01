// Shape lint for YARA rule regex strings.
//
// This is *not* a full ReDoS analyser; it detects four specific patterns
// that have been observed in the bundled rule corpus to backtrack
// catastrophically on uniform `\w` input (hex / base64 / 'x' alphabets
// at the canonical 161 KB investigation size). Each shape was identified
// from real timing data captured by `tests/unit/yara-rules-perf.test.js`
// (May 2026).
//
// Failing this test means a *new* rule has introduced one of the known
// catastrophic shapes. Existing offenders are listed in `KNOWN_OFFENDERS`
// below and tracked for Tier-1 rewrites; entries are removed in the same
// commit that rewrites the rule. This is the deliberate ratchet.
//
// Detected shapes:
//
//   A. greedy-w-then-bracket  — `\w+` (or `\S+`) at the START of a
//      regex (no literal anchor before it) followed by optional `\s*`
//      then `[`, `(`, `.`, or `/*`. On uniform `\w` input, the engine
//      matches the whole run, fails to find the bracket, then back-
//      tracks one character at a time. O(n^2). Real example:
//      JS_Bracket_Hex_Property (`\w+\s*\[\s*['"]\\x…`) — 113 s on
//      161 KB of `'x'`. Patterns where `\w+` is preceded by a literal
//      non-`\w` character (e.g. `&\s*\$\w+\.\w+` in
//      `PS_Hashtable_Command_Construction`) are NOT flagged: the
//      literal acts as an O(n) anchor — input must contain `&`/`.` —
//      and measurement confirms <2 ms on the perf corpora.
//
//   B. wide-class-plus  — `[…letters & digits…]+` followed by a literal
//      anchor. The anchor never appears in uniform alphabet input, so
//      the `+` matches the entire blob then backtracks one char per
//      step. Real example: Punycode_IDN_Homograph
//      (`[a-zA-Z0-9\-\.]+xn--`) — 22.5 s on 161 KB hex.
//
//   C. greedy-dot-bridge  — `.*` (greedy, not lazy) bridging two literal
//      segments. On long input, `.*` matches everything, then has to
//      retreat to find the right anchor. No current offenders, but the
//      shape is REDoS-equivalent to (B) and we want it pinned.
//
//   D. nested-quantifier  — classic `(X+)+` / `(X+)*` exponential
//      explosion. No current offenders.
//
// Phase-0 status: shapes A & B have known offenders; C & D have zero.

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle.js');

const { YaraEngine } = loadModules(['src/yara-engine.js']);

const RULES_DIR = path.join(__dirname, '..', '..', 'src', 'rules');

// Allowlist of currently-known catastrophic shapes. Each entry is keyed
// by `${file}::${ruleName}/${stringId}` and records the shape category
// plus a short rationale. When a rule rewrite lands, delete the entry
// in the same commit.
//
// DO NOT add to this list to silence a warning on a new rule. The
// correct response to a new flagging is to rewrite the regex: bound
// the `\w+`/`\S+` with an explicit `{0,N}` upper limit, switch `.*`
// to `.{0,N}?` (lazy + bounded), or rearrange so a literal token
// anchors the search.
//
// Empty since the May 2026 Tier-1 rewrite — Punycode_IDN_Homograph,
// JS_Comment_Injection_Obfuscation, and JS_Bracket_Hex_Property_Execution
// were all rewritten with bounded quantifiers in the same commit that
// emptied this list.
const KNOWN_OFFENDERS = new Map([]);

/**
 * Classify a regex pattern as one or more known catastrophic shapes.
 * Returns an array of shape names (empty if the pattern is fine).
 */
function classifyPattern(pat) {
  const issues = [];

  // Shape A: `\w+` (or `\S+`) at the START of a regex (no literal
  // anchor before it), followed by optional `\s*`/`\s+` then `[`,
  // `(`, `.`, or `/*`. The trailing token is what the engine hunts
  // for *after* greedily consuming the run — and it's the failure
  // mode we measured. Patterns with a leading literal non-`\w`
  // character (e.g. `&\s*\$\w+\.\w+` in PS_Hashtable_Command_*) are
  // intentionally not flagged: the leading literal acts as an O(n)
  // anchor (input must contain it) and the per-rule perf test
  // confirms <5 ms on hex/x corpora.
  if (/^(?:\(\?:)?\\[wS]\+(?!\?|\{)\s*(?:\\s\*|\\s\+)?\s*(?:\\\[|\\\(|\\\.|\\\/\\\*)/.test(pat)) {
    issues.push('greedy-w-then-bracket');
  }

  // Shape B: `[…]+` over a character class containing both letters
  // and digits, immediately followed by a literal letter (the anchor).
  // The class+ matches uniform input wholesale, then backtracks for
  // the literal that never appears.
  if (/\[(?=[^\]]*[a-zA-Z])(?=[^\]]*[0-9])[^\]]+\]\+(?!\?|\{)[a-zA-Z]/.test(pat)) {
    issues.push('wide-class-plus');
  }

  // Shape C: greedy `.*` (not lazy, not bounded) bridging two
  // alphabetic anchors. Real failure mode is the same as (B).
  // We require alphabetic neighbours on both sides to avoid flagging
  // patterns where `.*` is bounded by character-class context.
  if (/[A-Za-z\\]\.\*(?!\?|\{)[A-Za-z]/.test(pat) &&
      // Exclude `.*?` (lazy) which is fine, and bounded `.*\b…` etc.
      !/\.\*\?/.test(pat)) {
    issues.push('greedy-dot-bridge');
  }

  // Shape D: `(X+)+` / `(X+)*`. Classic exponential.
  if (/\([^)]*\+[^)]*\)[+*](?!\?)/.test(pat)) {
    issues.push('nested-quantifier');
  }

  return issues;
}

/** Walk every regex string in every .yar file. */
function* eachRegexString() {
  const files = fs.readdirSync(RULES_DIR).filter(f => f.endsWith('.yar')).sort();
  for (const file of files) {
    const src = fs.readFileSync(path.join(RULES_DIR, file), 'utf8');
    const { rules } = YaraEngine.parseRules(src);
    for (const rule of rules) {
      for (const s of rule.strings) {
        if (s.type !== 'regex') continue;
        yield { file, ruleName: rule.name, stringId: s.id, pattern: s.pattern };
      }
    }
  }
}

test('shape-lint: classifier sanity (positive cases match)', () => {
  // Shape A — synthetic
  assert.deepEqual(classifyPattern('\\w+\\s*\\[\\s*[\'"]\\\\x'),
                   ['greedy-w-then-bracket']);
  assert.deepEqual(classifyPattern('\\w+\\s*\\/\\*[^*]*\\*\\/\\s*\\.'),
                   ['greedy-w-then-bracket']);
  assert.deepEqual(classifyPattern('\\S+\\s*\\('),
                   ['greedy-w-then-bracket']);

  // Shape B
  assert.deepEqual(classifyPattern('[a-zA-Z0-9\\-\\.]+xn--'),
                   ['wide-class-plus']);

  // Shape C
  assert.deepEqual(classifyPattern('powershell.*Enc'),
                   ['greedy-dot-bridge']);

  // Shape D
  assert.deepEqual(classifyPattern('(\\w+)+'),
                   ['nested-quantifier']);
});

test('shape-lint: classifier sanity (negative cases don\'t match)', () => {
  // Bounded quantifier — fine
  assert.deepEqual(classifyPattern('\\w{1,32}\\['), []);
  // Lazy `.*?` — fine
  assert.deepEqual(classifyPattern('powershell.*?Enc'), []);
  // `.*` between non-alphabetic — fine
  assert.deepEqual(classifyPattern('".*"'), []);
  // Bounded `.{0,N}` — fine
  assert.deepEqual(classifyPattern('a.{0,16}b'), []);
  // Plain `\w+` not followed by bracket-like char — fine
  assert.deepEqual(classifyPattern('\\bon\\w+\\s*='), []);
});

test('shape-lint: no new catastrophic shapes in src/rules/', () => {
  const offenders = [];
  const seen = new Set();

  for (const { file, ruleName, stringId, pattern } of eachRegexString()) {
    const issues = classifyPattern(pattern);
    if (!issues.length) continue;

    const key = `${file}::${ruleName}/${stringId}`;
    seen.add(key);

    if (!KNOWN_OFFENDERS.has(key)) {
      offenders.push({ key, issues, pattern });
    }
  }

  if (offenders.length) {
    const report = offenders
      .map(o => `  ${o.key}\n    shape:   ${o.issues.join(', ')}\n    pattern: ${o.pattern}`)
      .join('\n');
    assert.fail(
      `Found ${offenders.length} new catastrophic regex shape(s):\n${report}\n\n` +
      `If this is intentional (e.g. you've measured the rule against the perf\n` +
      `corpus and it stays under budget), add an entry to KNOWN_OFFENDERS in\n` +
      `tests/unit/yara-rules-shape-lint.test.js with a one-line rationale.\n` +
      `Otherwise, rewrite the regex to bound the offending quantifier.`,
    );
  }

  // Stale-allowlist check: every KNOWN_OFFENDERS entry should still match.
  // If a rule was rewritten and the entry forgotten, fail loudly.
  const stale = [];
  for (const key of KNOWN_OFFENDERS.keys()) {
    if (!seen.has(key)) stale.push(key);
  }
  if (stale.length) {
    assert.fail(
      `KNOWN_OFFENDERS contains ${stale.length} stale entry/entries (rule rewritten ` +
      `or renamed but the allowlist entry remains):\n  ${stale.join('\n  ')}\n\n` +
      `Remove these entries from tests/unit/yara-rules-shape-lint.test.js.`,
    );
  }
});

test('shape-lint: every allowlisted offender is currently flagged', () => {
  // Defends against the classifier silently weakening — if we relax
  // a regex in `classifyPattern`, the corresponding KNOWN_OFFENDERS
  // entry stops flagging and we'd lose the ratchet on the rule.
  const allOffenders = new Map();
  for (const { file, ruleName, stringId, pattern } of eachRegexString()) {
    const issues = classifyPattern(pattern);
    if (issues.length) {
      allOffenders.set(`${file}::${ruleName}/${stringId}`, issues);
    }
  }

  for (const [key, expectedShape] of KNOWN_OFFENDERS) {
    const actualShapes = allOffenders.get(key);
    assert.ok(actualShapes,
      `KNOWN_OFFENDERS entry "${key}" expected shape "${expectedShape}" but ` +
      `the classifier no longer flags this pattern. Either the rule was ` +
      `rewritten (remove the allowlist entry) or the classifier was weakened ` +
      `(restore the detection).`);
    assert.ok(actualShapes.includes(expectedShape),
      `KNOWN_OFFENDERS entry "${key}" expected shape "${expectedShape}" but ` +
      `classifier reports ${actualShapes.join(', ')}.`);
  }
});

test('shape-lint: every .yar file under src/rules/ is parseable', () => {
  // Quick sanity — if a rule file fails to parse, the whole shape lint
  // would silently skip it. Pin parseability here, separately from the
  // perf-test parseability check (defence in depth).
  const files = fs.readdirSync(RULES_DIR).filter(f => f.endsWith('.yar')).sort();
  assert.ok(files.length > 0, 'no .yar files found in src/rules/');
  for (const file of files) {
    const src = fs.readFileSync(path.join(RULES_DIR, file), 'utf8');
    const result = YaraEngine.parseRules(src);
    assert.ok(Array.isArray(result.rules),
      `${file}: parseRules did not return an array`);
    assert.ok(result.rules.length > 0,
      `${file}: parseRules returned 0 rules — file may have a syntax error`);
  }
});
