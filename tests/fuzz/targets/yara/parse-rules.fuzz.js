'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/yara/parse-rules.fuzz.js
//
// Fuzz `YaraEngine.parseRules(source)` — the YARA grammar parser. Walks
// rule blocks (`rule <name> [: tags] { meta: … strings: … condition: … }`),
// strips comments while preserving string and regex literals, parses
// each rule body into a structured object.
//
// The parser uses safeRegex throughout (verified by `make.py regex`) but
// fuzzing exercises:
//   • Adversarial comment-stripping (regex-literal vs line-comment
//     ambiguity around `=  /…/`).
//   • Bounded-quantifier behaviour at the rule-body length cap (64 KB)
//     and tag-list cap (128 chars).
//   • String-modifier capture (ascii / wide / nocase / fullword / xor /
//     base64 / base64wide / hex-literal / regex-literal).
//   • Condition expression tokenisation (numeric, identifier, paren,
//     boolean op, string-count `#`, byte-fetch `uint8/16/32(…)`,
//     `for X of Y : (…)` predicates).
//
// Invariants:
//   1. parseRules NEVER throws — it accumulates errors into the returned
//      `errors[]` array. Any escaping throw is a real bug.
//   2. Result has shape `{ rules: object[], errors: string[] }`.
//   3. Each rule has `{ name: string, tags: string[]|string, meta: object,
//      strings: object[], condition: string }`.
//
// History (fix-points):
//   • 94117e8 — ascii/wide string-modifier semantics + per-scan lowercase view
//   • 0437e1f — multi-line string-modifier capture in parser
//   • 1388c1c — three rules rewritten for bounded quantifiers (ReDoS)
//   • 2061b82 — preserve regex literals when stripping comments
//   • 3457a09 — YARA editor rule import routes through safeRegex
// ════════════════════════════════════════════════════════════════════════════

const fs = require('node:fs');
const path = require('node:path');
const { defineFuzzTarget } = require('../../helpers/harness.js');
const { walkSorted } = require('../../helpers/seed-corpus.js');

const fuzz = defineFuzzTarget({
  modules: ['src/constants.js', 'src/yara-engine.js'],
  expose: ['YaraEngine'],

  // YARA rule files are well-bounded — biggest bundled is ~80 KB, the
  // editor's per-rule cap is 64 KB. 256 KB gives the mutator headroom.
  maxBytes: 256 * 1024,
  perIterBudgetMs: 5_000,

  onIteration(ctx, data) {
    const { YaraEngine } = ctx;
    if (!YaraEngine) throw new Error('harness: YaraEngine not exposed');

    // parseRules consumes a string. Decode as latin-1 so every byte
    // round-trips losslessly — UTF-8 fatal=false would silently drop
    // continuation bytes the mutator deliberately injects.
    let source = '';
    for (let i = 0; i < data.length; i++) {
      source += String.fromCharCode(data[i]);
    }

    const result = YaraEngine.parseRules(source);

    // ── Invariant 1: shape ────────────────────────────────────────────
    if (!result || typeof result !== 'object') {
      throw new Error('invariant: parseRules returned non-object');
    }
    if (!Array.isArray(result.rules)) {
      throw new Error(`invariant: result.rules not array (${typeof result.rules})`);
    }
    if (!Array.isArray(result.errors)) {
      throw new Error(`invariant: result.errors not array (${typeof result.errors})`);
    }

    // ── Invariant 2: errors are strings ───────────────────────────────
    for (const e of result.errors) {
      if (typeof e !== 'string') {
        throw new Error(`invariant: error entry ${typeof e} (expected string)`);
      }
    }

    // ── Invariant 3: parsed rule shape ────────────────────────────────
    for (const r of result.rules) {
      if (!r || typeof r !== 'object') {
        throw new Error('invariant: rule entry not object');
      }
      if (typeof r.name !== 'string' || r.name.length === 0) {
        throw new Error(`invariant: rule.name ${JSON.stringify(r.name)} not non-empty string`);
      }
      if (r.meta !== undefined && (r.meta === null || typeof r.meta !== 'object')) {
        throw new Error(`invariant: rule.meta ${typeof r.meta} (expected object)`);
      }
      if (!Array.isArray(r.strings)) {
        throw new Error(`invariant: rule.strings not array (${typeof r.strings})`);
      }
      // condition may be missing (some rules accept implicit `any of them`),
      // but if present it must be a string.
      if (r.condition !== undefined && typeof r.condition !== 'string') {
        throw new Error(`invariant: rule.condition ${typeof r.condition} (expected string)`);
      }
      for (const s of r.strings) {
        if (!s || typeof s !== 'object') {
          throw new Error('invariant: rule.strings entry not object');
        }
        if (typeof s.id !== 'string') {
          throw new Error(`invariant: string.id ${typeof s.id} (expected string)`);
        }
      }
    }
  },
});

// Seed corpus: every bundled rule pack + the user-facing example/broken
// fixtures. Each seed is a complete .yar file — the mutator's
// byte-flip + slice-splice ops produce a rich variety of malformed
// shapes from this base.
function loadYaraSeeds() {
  const seeds = [];
  const ruleDir = path.resolve(__dirname, '..', '..', '..', '..', 'src', 'rules');
  const exampleDir = path.resolve(__dirname, '..', '..', '..', '..', 'examples', 'yara');
  const cap = 64 * 1024;
  let total = 0;

  for (const dir of [ruleDir, exampleDir]) {
    if (!fs.existsSync(dir)) continue;
    for (const file of walkSorted(dir)) {
      if (!/\.ya?ra?$/i.test(file)) continue;
      try {
        let buf = fs.readFileSync(file);
        if (buf.length > cap) buf = buf.subarray(0, cap);
        if (total + buf.length > 4 * 1024 * 1024) break;
        total += buf.length;
        seeds.push(buf);
      } catch (_) { /* skip */ }
    }
  }

  // Hand-rolled adversarial seeds covering historical bugs.
  const handRolled = [
    // Empty
    '',
    // Whitespace only
    '   \n\t\n',
    // Bare rule
    'rule R { condition: true }',
    // Tag list at the cap boundary
    'rule T : ' + 'tag '.repeat(30) + '{ condition: true }',
    // Regex literal that looks like a line comment
    'rule R { strings: $a = /foo\\/\\/bar/ condition: $a }',
    // String modifier combinations — captures the 0437e1f multi-line fix
    'rule R {\n strings:\n  $a = "hi" ascii wide nocase\n  $b = "there" fullword xor\n condition: any of them\n}',
    // Hex literal with jumps
    'rule R { strings: $a = { 41 ?? [2-4] 42 } condition: $a }',
    // base64 modifier
    'rule R { strings: $a = "secret" base64 condition: $a }',
    // Comment-in-string preservation (2061b82)
    'rule R { strings: $a = "http://x/y/z" condition: $a }',
    // Duplicate rule names
    'rule R { condition: true }\nrule R { condition: false }',
    // Missing closing brace (must not throw)
    'rule R { condition: true',
    // Unicode + control bytes
    '\x00\x01\x02 rule \xff { condition: true }',
  ];
  for (const s of handRolled) seeds.push(Buffer.from(s, 'utf8'));

  return seeds;
}

const seeds = loadYaraSeeds();

module.exports = { fuzz, seeds, name: 'parse-rules' };
