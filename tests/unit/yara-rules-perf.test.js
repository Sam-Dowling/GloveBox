'use strict';
// ════════════════════════════════════════════════════════════════════════════
// yara-rules-perf.test.js — wall-clock budgets for the bundled YARA
// rule corpus on adversarial inputs.
//
// Why this file
// -------------
// Investigation context (May 2026): a 161 KB base64 blob took ~60 s to
// finish YARA scanning in the browser. This file pins per-rule-file and
// per-rule wall-clock budgets so REDoS-shaped patterns can't silently
// re-creep into the corpus. Tests intentionally emit timings via
// `console.log` so a contributor running `python make.py test-unit`
// gets a per-file/per-rule breakdown of where the time goes — this is
// the "measurement-as-test" half of the YARA-perf workstream.
//
// Strategy
// --------
//   • Generous initial budgets (≈5× current measured time) so the suite
//     passes on the un-fixed corpus and the failures are obvious when a
//     PR introduces a worse regex than we already have.
//   • A SUSPECT_RULES list pins specific rules whose names/files are
//     known REDoS hot-spots; tightened budgets there fail loudly when
//     the responsible regex regresses (or, after the Tier-1 rewrite,
//     when the fixed pattern silently degrades again).
//   • Inputs are generated programmatically (no fixtures committed) and
//     deterministic per `Math.random`-free seed.
//
// What "fast" means here
// ----------------------
// Numbers below were measured locally. CI runners are typically
// 2-5× slower than a developer laptop; budgets account for that.
// If a budget firing in CI but not locally indicates a real CI runner
// regression, raise the budget once with a comment — don't suppress.
//
// Coverage matrix (all run twice: formatTag=plaintext, formatTag=
// decoded-payload):
//   • Per-rule-file scan budget on a 161 KB single-line input over
//     three alphabets: base64, hex, all-x. The hex alphabet is the
//     worst case for many of our regexes (it's a subset of base64 AND
//     overlaps the `0-9 a-f` ranges used by hex-shellcode patterns).
//   • Per-rule budget for known REDoS hot-spots.
//   • Aggregated full-corpus budget for the canonical 161 KB base64
//     case (the original investigation input shape).
//   • Empty-buffer baseline (parse-only path) — a tight budget that
//     flags a parser regression.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/yara-engine.js']);
const { YaraEngine } = ctx;

const RULES_DIR = path.resolve(__dirname, '..', '..', 'src', 'rules');

// ── Input generation ──────────────────────────────────────────────────────

const ALPHABETS = {
  base64: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
  hex:    '0123456789abcdef',
  x:      'x',
};

/** Generate a deterministic single-line buffer of `bytes` length over
 *  the given alphabet. No randomness — same alphabet + size gives the
 *  same bytes on every run, on every machine. */
function generate(alphabet, bytes) {
  const out = Buffer.alloc(bytes);
  for (let i = 0; i < bytes; i++) {
    out[i] = alphabet.charCodeAt((i * 7919) % alphabet.length);
  }
  return out;
}

const SIZE_BIG = 161 * 1024;  // canonical investigation size (base64)
// REDoS-shaped patterns scale at least quadratically. Two rules in
// `script-threats.yar` (JS_Comment_Injection_Obfuscation,
// JS_Bracket_Hex_Property_Execution) catastrophically backtrack on
// uniform `\w` input: 161 KB of 'x' takes ~180 s combined, 161 KB of
// hex takes ~7 s. We use 8 KB for both hex and 'x' alphabets so the
// same regression is surfaced (a few seconds of CPU instead of three
// minutes), keeping total CI time under control. Once Tier-1 rewrites
// these patterns into bounded forms, both inputs will run in <100 ms
// and the budget will tighten in the same commit.
const SIZE_HEX = 8 * 1024;
const SIZE_X   = 8 * 1024;

// Pre-generate inputs once — generation itself is non-trivial.
const INPUTS = {
  base64_161k: generate(ALPHABETS.base64, SIZE_BIG),
  hex_8k:      generate(ALPHABETS.hex,    SIZE_HEX),
  x_8k:        generate(ALPHABETS.x,      SIZE_X),
  empty:       Buffer.alloc(0),
};

// ── Rule corpus loading ───────────────────────────────────────────────────

/** All `*.yar` files under `src/rules/`, sorted (deterministic order). */
const RULE_FILES = fs.readdirSync(RULES_DIR)
  .filter(f => f.endsWith('.yar'))
  .sort();

/** Per-file parsed rule arrays. Parsed once at module load. */
const PER_FILE = {};
for (const f of RULE_FILES) {
  const src = fs.readFileSync(path.join(RULES_DIR, f), 'utf8');
  const { rules, errors } = YaraEngine.parseRules(src);
  PER_FILE[f] = { rules, errors };
}

/** Flat rule list (every parsed rule across every file). */
const ALL_RULES = [];
for (const f of RULE_FILES) {
  for (const r of PER_FILE[f].rules) ALL_RULES.push(r);
}

// ── Timing helpers ────────────────────────────────────────────────────────

/** Run `fn` once and return wall-clock milliseconds. */
function timeMs(fn) {
  const t0 = process.hrtime.bigint();
  fn();
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

/** Format a per-row table line for console.log output. */
function row(label, ms, budget) {
  const pad = label.padEnd(46);
  const t = ms.toFixed(0).padStart(8);
  const b = budget !== undefined ? `(budget ${budget}ms)` : '';
  return `  ${pad}${t} ms  ${b}`;
}

// ── Per-file scan budgets ─────────────────────────────────────────────────
//
// Slowest per-file measurements after the May 2026 Tier-1 rule
// rewrites (Punycode_IDN_Homograph, JS_Bracket_Hex_Property_Execution,
// JS_Comment_Injection_Obfuscation):
//   • macho-threats.yar on base64_161k   ≈ 165 ms
//   • windows-threats.yar on base64_161k ≈ 135 ms
//   • document-threats.yar on base64_161k ≈ 93 ms
//   • script-threats.yar on base64_161k  ≈ 60 ms (was 151 ms)
//   • script-threats.yar on hex_8k       ≈  4 ms (was 906 ms)
//   • script-threats.yar on x_8k         ≈  4 ms (was 593 ms)
// 1.5 s per-file budget gives ~9× headroom on the slowest entry,
// catches a future REDoS regression even on the smallest 8 KB inputs.
const PER_FILE_BUDGET_MS = 1_500;

for (const formatTag of ['plaintext', 'decoded-payload']) {
  for (const inputName of ['base64_161k', 'hex_8k', 'x_8k']) {
    test(`perf: per-file scan budget — formatTag=${formatTag}, input=${inputName}`, { timeout: 60_000 }, () => {
      const buf = INPUTS[inputName];
      const lines = [`\n  ── per-file scan: formatTag=${formatTag}, input=${inputName} (${buf.length} bytes)`];
      let worstFile = null;
      let worstMs = 0;
      for (const f of RULE_FILES) {
        const ms = timeMs(() => YaraEngine.scan(buf, PER_FILE[f].rules, {
          context: { formatTag },
        }));
        lines.push(row(f, ms, PER_FILE_BUDGET_MS));
        if (ms > worstMs) { worstMs = ms; worstFile = f; }
      }
      // eslint-disable-next-line no-console
      console.log(lines.join('\n'));
      assert.ok(worstMs < PER_FILE_BUDGET_MS,
        `slowest file ${worstFile} took ${worstMs.toFixed(0)} ms ` +
        `(budget ${PER_FILE_BUDGET_MS} ms) — REDoS regression?`);
    });
  }
}

// ── Per-rule budgets for known REDoS hot-spots ────────────────────────────
//
// Each entry pins a single rule whose regex shape is known to be
// REDoS-prone on at least one of the alphabets above. The budget is
// generous (10 s) so the test passes on the current corpus; a Tier-1
// rewrite of the named rule should drop the time well below 1 s, at
// which point this list either tightens its budget (commit-by-commit)
// or removes the entry once the regex is safe.
//
// `inputs` is the list of alphabets the entry is sensitive to;
// budgets are per-input.
const SUSPECT_RULES = [
  // Punycode_IDN_Homograph: rewritten in Tier-1 to anchor on `\bxn--`.
  // Pre-Tier-1: 22.5 s on 161 KB hex. Post-Tier-1: <15 ms across all
  // tested alphabets. Pinned so a regression to `[…wide…]+xn--` form
  // fails loudly.
  { file: 'network-indicators.yar',  name: 'Punycode_IDN_Homograph',
    inputs: ['hex_8k', 'base64_161k'], budget: 250 },
  // JS_Bracket_Hex_Property_Execution: rewritten in Tier-1 to use
  // `\b[A-Za-z_$][\w$]{0,63}\[…` — bounded identifier with word-
  // boundary anchor. Pre-Tier-1: 113 s on 161 KB 'x'. Post-Tier-1:
  // <20 ms on 8 KB hex/x and <20 ms on 161 KB base64.
  { file: 'script-threats.yar',      name: 'JS_Bracket_Hex_Property_Execution',
    inputs: ['hex_8k', 'x_8k', 'base64_161k'], budget: 250 },
  // JS_Comment_Injection_Obfuscation: same Tier-1 rewrite pattern
  // (bounded identifier, bounded comment body, `\b` anchor).
  // Pre-Tier-1: 70 s on 161 KB 'x'. Post-Tier-1: <20 ms on all
  // tested alphabets.
  { file: 'script-threats.yar',      name: 'JS_Comment_Injection_Obfuscation',
    inputs: ['hex_8k', 'x_8k', 'base64_161k'], budget: 250 },
  // PS_Split_Join_Reassembly — `\-split\s*['"][^'"]+['"].*iex` —
  // shape-lint flags this as `greedy-dot-bridge` but the literal
  // `-split` / `-join` prefix anchors input. Measured <5 ms; pin
  // so a rewrite removing the literal anchor regresses loudly.
  { file: 'script-threats.yar',      name: 'PS_Split_Join_Reassembly',
    inputs: ['base64_161k'], budget: 250 },
  // Encoding-threats catch-all rules — broad `.*` contexts but
  // anchored on rare PowerShell tokens. Measured <10 ms; pin
  // against future REDoS-introducing edits.
  { file: 'encoding-threats.yar',    name: 'Standalone_LOLBin_Indicators',
    inputs: ['base64_161k'], budget: 250 },
  { file: 'encoding-threats.yar',    name: 'Standalone_Script_Shell_Execution',
    inputs: ['base64_161k'], budget: 250 },
  { file: 'encoding-threats.yar',    name: 'Right_To_Left_Override',
    inputs: ['base64_161k'], budget: 250 },
];

for (const entry of SUSPECT_RULES) {
  test(`perf: suspect rule — ${entry.file}/${entry.name}`, { timeout: 120_000 }, () => {
    const file = PER_FILE[entry.file];
    if (!file) { assert.fail(`unknown rule file ${entry.file}`); return; }
    const rule = file.rules.find(r => r.name === entry.name);
    if (!rule) {
      // Rule may have been renamed — surface as a clear failure so the
      // test list stays in sync with the corpus.
      assert.fail(`rule "${entry.name}" not found in ${entry.file} ` +
        `(corpus changed without updating SUSPECT_RULES?)`);
      return;
    }
    const lines = [`\n  ── suspect rule: ${entry.file}/${entry.name}`];
    let worst = 0;
    let worstInput = null;
    for (const inp of entry.inputs) {
      const buf = INPUTS[inp];
      const ms = timeMs(() => YaraEngine.scan(buf, [rule], {
        context: { formatTag: 'plaintext' },
      }));
      lines.push(row(inp, ms, entry.budget));
      if (ms > worst) { worst = ms; worstInput = inp; }
    }
    // eslint-disable-next-line no-console
    console.log(lines.join('\n'));
    assert.ok(worst < entry.budget,
      `${entry.name} on ${worstInput} took ${worst.toFixed(0)} ms ` +
      `(budget ${entry.budget} ms)`);
  });
}

// ── Aggregated full-corpus scan budget ────────────────────────────────────
//
// The original investigation observation: 161 KB base64 blob ⇒ ~60 s
// in-browser. The numbers measured here (Node, no worker overhead) are
// much lower because the 60 s number includes the second decoded-payload
// phase plus per-payload overhead inside the worker. We pin a 90 s budget
// (≈5× 60 s × 2 phases) on the WORST-CASE input so a future change
// doesn't make the engine demonstrably worse on the canonical case.

test('perf: full corpus, 161 KB base64 blob, formatTag=plaintext', { timeout: 30_000 }, () => {
  const ms = timeMs(() => YaraEngine.scan(INPUTS.base64_161k, ALL_RULES, {
    context: { formatTag: 'plaintext' },
  }));
  // eslint-disable-next-line no-console
  console.log(`\n  full-corpus base64_161k plaintext        ${ms.toFixed(0).padStart(8)} ms`);
  // Headline measurement that triggered the May 2026 audit. Loupe's
  // user-reported symptom was ~60 s wall time on a 161 KB base64
  // blob (worker overhead + sequential-phase serialisation magnified
  // a ~300 ms in-process scan into the wall-clock figure). After
  // Tier-1 rule rewrites this scan runs in 250–600 ms in Node with
  // significant variance from JIT/GC. 2 s budget catches a >3×
  // regression while tolerating cold-start jitter.
  assert.ok(ms < 2_000, `full corpus on base64 took ${ms.toFixed(0)} ms (budget 2000 ms)`);
});

test('perf: full corpus, 161 KB base64 blob, formatTag=decoded-payload', { timeout: 30_000 }, () => {
  const ms = timeMs(() => YaraEngine.scan(INPUTS.base64_161k, ALL_RULES, {
    context: { formatTag: 'decoded-payload' },
  }));
  // eslint-disable-next-line no-console
  console.log(`\n  full-corpus base64_161k decoded-payload  ${ms.toFixed(0).padStart(8)} ms`);
  assert.ok(ms < 2_000, `decoded-payload full corpus took ${ms.toFixed(0)} ms (budget 2000 ms)`);
});

test('perf: full corpus, 8 KB hex blob, formatTag=plaintext', { timeout: 30_000 }, () => {
  const ms = timeMs(() => YaraEngine.scan(INPUTS.hex_8k, ALL_RULES, {
    context: { formatTag: 'plaintext' },
  }));
  // eslint-disable-next-line no-console
  console.log(`\n  full-corpus hex_8k      plaintext        ${ms.toFixed(0).padStart(8)} ms`);
  // Pre-Tier-1: ≈600 ms (Punycode + JS_Bracket_Hex REDoS).
  // Post-Tier-1: ≈30 ms. 500 ms budget catches a 15× regression.
  assert.ok(ms < 500, `full corpus on hex took ${ms.toFixed(0)} ms (budget 500 ms)`);
});

test('perf: full corpus, 8 KB x blob, formatTag=plaintext', { timeout: 30_000 }, () => {
  const ms = timeMs(() => YaraEngine.scan(INPUTS.x_8k, ALL_RULES, {
    context: { formatTag: 'plaintext' },
  }));
  // eslint-disable-next-line no-console
  console.log(`\n  full-corpus x_8k        plaintext        ${ms.toFixed(0).padStart(8)} ms`);
  // Pre-Tier-1: ≈500 ms (`\w+` anchored regexes).
  // Post-Tier-1: ≈30 ms. 500 ms budget catches a 15× regression.
  assert.ok(ms < 500, `full corpus on x took ${ms.toFixed(0)} ms (budget 500 ms)`);
});

// ── Empty-buffer baseline ────────────────────────────────────────────────
//
// Pure parse + condition-evaluation overhead with no string-search work.
// A regression here means parsing or applies_to gating has gotten slower
// — independent of any individual rule's regex.

test('perf: full corpus, empty buffer (parse-only baseline)', () => {
  const ms = timeMs(() => YaraEngine.scan(INPUTS.empty, ALL_RULES, {
    context: { formatTag: 'plaintext' },
  }));
  // eslint-disable-next-line no-console
  console.log(`\n  full-corpus empty       plaintext        ${ms.toFixed(0).padStart(8)} ms`);
  assert.ok(ms < 1_000, `empty-buffer baseline ${ms.toFixed(0)} ms (budget 1000 ms)`);
});

// ── Sanity: corpus parsed cleanly ────────────────────────────────────────
//
// If any rule file has parse errors, the perf tests above are meaningless
// (we'd be scanning the wrong rule list). This test fails fast with the
// errors surfaced.

test('perf: every rule file in src/rules/ parses without error', () => {
  for (const f of RULE_FILES) {
    const errs = PER_FILE[f].errors;
    assert.equal(errs.length, 0,
      `${f}: ${errs.length} parse error(s): ${errs.slice(0, 3).join('; ')}`);
    assert.ok(PER_FILE[f].rules.length > 0,
      `${f}: zero rules parsed (build expected ≥1)`);
  }
});
