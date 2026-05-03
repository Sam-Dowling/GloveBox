'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/yara/scan.fuzz.js
//
// Fuzz `YaraEngine.scan(buffer, rules, opts)` — the rule execution
// engine. Drives a representative fixed rule set through fuzzer-generated
// byte streams. This is the same surface that auto-YARA pushes against
// every loaded file in production.
//
// Why a fixed rule set? `scan` takes two inputs (buffer + rules); fuzzing
// both at once doubles the search space without proportional bug-find
// gain. The dual-target design (parse-rules.fuzz.js fuzzes the parser;
// scan.fuzz.js fuzzes the engine) keeps each target focused.
//
// The fixed rule set covers every YARA feature the engine implements:
//   • ASCII / wide / nocase / fullword string modifiers
//   • Base64 / xor modifiers
//   • Hex pattern with jumps (`{ 41 ?? [2-4] 42 }`)
//   • Regex literal (`$x = /pattern/i`)
//   • Boolean condition expressions (and / or / not, paren grouping)
//   • String-count `#identifier` predicates
//   • Byte-fetch `uint16(0) == 0x5A4D`
//   • `for any i in (0..N) : (…)` predicates (rule-engine path the
//     parser-only target can't exercise)
//   • `applies_to` short-circuit
//
// Invariants:
//   1. scan NEVER throws on any byte input. The opt-in errorSink
//      array catches per-string regex compile failures cleanly.
//   2. Each result record has shape `{ ruleName, tags, meta, condition,
//      matches: [{ id, value, matches: [{ offset, length }] }] }`.
//   3. Every `match.offset` is in [0, buffer.length] and
//      `match.offset + match.length` is in [0, buffer.length].
//   4. Per-iter wall-clock under 5 s — anything longer is a ReDoS in
//      the bundled patterns.
//
// History:
//   • 484d23d — byte offsets must map through the actual scanned buffer
//   • 716d532 — bound `invisRe` to `\w{2,64}` + route every IOC matchAll
//     through safeMatchAll (ReDoS class)
//   • 1388c1c — three rules rewritten for bounded quantifiers
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { loadSeeds, syntheticTextSeeds } = require('../../helpers/seed-corpus.js');

// Representative rule set — small, but exercises every engine feature.
// Pre-parsed once per fuzz run inside ensureRules() below.
const RULES_SOURCE = `
rule TestAscii {
  strings:
    $a = "hello"
    $b = "world" nocase
  condition:
    $a or $b
}

rule TestWide {
  strings:
    $a = "secret" wide
    $b = "PowerShell" wide ascii nocase
  condition:
    any of them
}

rule TestFullword {
  strings:
    $a = "exec" fullword
  condition:
    $a
}

rule TestHex {
  strings:
    $a = { 4D 5A ?? ?? [2-8] 50 45 00 00 }
  condition:
    $a
}

rule TestRegex {
  strings:
    $url = /https?:\\/\\/[a-z0-9.-]{3,64}/i
  condition:
    $url
}

rule TestBase64 {
  strings:
    $a = "VirtualAlloc" base64
  condition:
    $a
}

rule TestXor {
  strings:
    $a = "encrypted" xor(0x01-0xFF)
  condition:
    $a
}

rule TestCounting {
  strings:
    $a = "AAAA"
  condition:
    #a > 3
}

rule TestUint {
  condition:
    uint16(0) == 0x5A4D
}

rule TestForLoop {
  strings:
    $a = "needle"
  condition:
    for any i in (0..#a) : ( @a[i] < filesize )
}

rule TestAppliesTo {
  meta:
    applies_to = "pe"
    severity = "medium"
  strings:
    $a = "MZ"
  condition:
    $a at 0
}
`;

let _rules = null;
function ensureRules(YaraEngine) {
  if (_rules === null) {
    const { rules, errors } = YaraEngine.parseRules(RULES_SOURCE);
    if (errors.length) {
      throw new Error(`harness: rule set failed to parse: ${errors.join('; ')}`);
    }
    if (rules.length === 0) {
      throw new Error('harness: rule set produced zero rules');
    }
    _rules = rules;
  }
  return _rules;
}

const fuzz = defineFuzzTarget({
  modules: ['src/constants.js', 'src/yara-engine.js'],
  expose: ['YaraEngine'],

  // 1 MiB is well past the per-rule string-search budget; the scan
  // engine's `safeRegex` per-call cap (`PARSER_LIMITS.FINDER_BUDGET_MS`)
  // bounds tail-latency cleanly even on adversarial inputs.
  maxBytes: 1 * 1024 * 1024,
  perIterBudgetMs: 5_000,

  onIteration(ctx, data) {
    const { YaraEngine } = ctx;
    if (!YaraEngine) throw new Error('harness: YaraEngine not exposed');

    const rules = ensureRules(YaraEngine);
    const errorSink = [];
    const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);

    const results = YaraEngine.scan(buf, rules, {
      errors: errorSink,
      // Drive the applies_to short-circuit half the time. The byte count
      // is fuzzer-controlled, so this oscillates deterministically.
      context: { formatTag: (data.length & 1) ? 'pe' : 'elf' },
    });

    // ── Invariant 1: shape ────────────────────────────────────────────
    if (!Array.isArray(results)) {
      throw new Error(`invariant: scan returned ${typeof results} (expected array)`);
    }

    for (const r of results) {
      if (!r || typeof r !== 'object') {
        throw new Error('invariant: result entry not object');
      }
      if (typeof r.ruleName !== 'string' || r.ruleName.length === 0) {
        throw new Error(`invariant: result.ruleName ${JSON.stringify(r.ruleName)} not non-empty string`);
      }
      if (r.meta !== undefined && r.meta !== null && typeof r.meta !== 'object') {
        throw new Error(`invariant: result.meta ${typeof r.meta}`);
      }
      if (typeof r.condition !== 'string') {
        throw new Error(`invariant: result.condition ${typeof r.condition}`);
      }
      if (!Array.isArray(r.matches)) {
        throw new Error(`invariant: result.matches not array (${typeof r.matches})`);
      }

      for (const m of r.matches) {
        if (!m || typeof m !== 'object') {
          throw new Error('invariant: match entry not object');
        }
        if (typeof m.id !== 'string') {
          throw new Error(`invariant: match.id ${typeof m.id}`);
        }
        if (!Array.isArray(m.matches)) {
          throw new Error(`invariant: match.matches not array (${typeof m.matches})`);
        }

        for (const hit of m.matches) {
          if (!hit || typeof hit !== 'object') {
            throw new Error('invariant: hit entry not object');
          }
          if (typeof hit.offset !== 'number'
              || !Number.isInteger(hit.offset)
              || hit.offset < 0
              || hit.offset > data.length) {
            throw new Error(
              `invariant: hit.offset ${hit.offset} out of [0, ${data.length}]`,
            );
          }
          if (typeof hit.length !== 'number'
              || !Number.isInteger(hit.length)
              || hit.length < 0
              || hit.offset + hit.length > data.length) {
            throw new Error(
              `invariant: hit.length ${hit.length} (offset ${hit.offset}) overflows buffer (${data.length})`,
            );
          }
        }
      }
    }

    // ── Invariant: errorSink entries are strings ──────────────────────
    for (const e of errorSink) {
      if (typeof e !== 'string') {
        throw new Error(`invariant: errorSink entry ${typeof e}`);
      }
    }
  },
});

// Seed corpus mixes:
//   • Real fixture bytes from PE / ELF / Mach-O / archives — the same
//     formats production YARA scans against.
//   • Synthetic text seeds that hit the string-modifier paths.
const seeds = [];

const realSeeds = loadSeeds({
  dirs: ['pe', 'elf', 'macos-system'],
  perFileMaxBytes: 256 * 1024,
  totalMaxBytes: 4 * 1024 * 1024,
  maxSeeds: 24,
});
seeds.push(...realSeeds);

// Hand-rolled bytes targeting specific rules.
const handRolled = [
  // Hits TestUint (`uint16(0) == 0x5A4D`)
  Buffer.from('MZ\x00\x00PE\x00\x00', 'binary'),
  // Hits TestAscii via "hello" + "world"
  Buffer.from('hello there world!', 'utf8'),
  // Hits TestWide ("secret" UTF-16LE)
  (() => {
    const b = Buffer.alloc(14);
    const s = 'secret';
    for (let i = 0; i < s.length; i++) {
      b[i*2] = s.charCodeAt(i); b[i*2+1] = 0;
    }
    return b;
  })(),
  // Hits TestHex (MZ + 4 wildcards + PE)
  Buffer.from([0x4D, 0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00]),
  // Hits TestCounting (#a > 3)
  Buffer.from('AAAA' + 'AAAA' + 'AAAA' + 'AAAA', 'utf8'),
  // Hits TestRegex
  Buffer.from('see https://example.com/ for details', 'utf8'),
];
seeds.push(...handRolled);
seeds.push(...syntheticTextSeeds(8));

module.exports = { fuzz, seeds, name: 'scan' };
