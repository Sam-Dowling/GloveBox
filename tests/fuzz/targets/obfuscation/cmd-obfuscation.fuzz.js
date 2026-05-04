'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/obfuscation/cmd-obfuscation.fuzz.js
//
// Fuzz the CMD obfuscation finder in isolation:
// `EncodedContentDetector.prototype._findCommandObfuscationCandidates`.
// The same finder also emits the PowerShell branches — that's intentional
// in the decoder (the two families interleave in real droppers) — but we
// narrow this target's technique catalog to the CMD-specific strings so
// the per-technique aggregator can attribute hits cleanly. The PowerShell
// catalog is the `powershell-obfuscation` target's responsibility.
//
// Loaded modules mirror the subset of `_DETECTOR_FILES` that
// `cmd-obfuscation.js` depends on at load time:
//
//   constants.js          — throwIfAborted stub + IOC / PARSER_LIMITS
//   encoded-content-detector.js — class root + maxCandidatesPerType
//   safelinks.js / whitelist.js / entropy.js — prototype mixins relied on
//                           inside the finder loop for plausibility gates
//   ioc-extract.js        — _executeOutput IOC mirroring inside
//                           _processCommandObfuscation (if we invoke it)
//   base64-hex.js         — detector needs _isHexLength / _isGUID helpers
//                           from the whitelist module, already included
//   cmd-obfuscation.js    — module under test
//
// Invariants:
//   1. _findCommandObfuscationCandidates returns an Array.
//   2. Each candidate.technique lives in CMD_TECHNIQUE_CATALOG OR the
//      PowerShell catalog (the finder is shared — tolerate that).
//   3. candidate.deobfuscated.length ≤ 64 × candidate.raw.length
//      (decode-blowup guard).
//   4. Per-iteration wall-clock ≤ DEFAULT_PER_ITER_BUDGET_MS — enforced
//      by the harness.
//   5. (soft) seeds carrying `_expectedSubstring` must appear in at
//      least one candidate's deobfuscated output — counted as
//      `expectedMiss` on the per-technique JSONL when absent.
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');
const { generateCmdSeeds, CMD_TECHNIQUE_CATALOG } = require('../../helpers/grammars/cmd-grammar.js');
const { POWERSHELL_TECHNIQUE_CATALOG } = require('../../helpers/grammars/powershell-grammar.js');
const { makeTechniqueRecorder } = require('../../helpers/technique-tracker.js');

// Combined catalog: the finder emits both families. Attribution lives in
// the `cmd-obfuscation` recorder either way — the split is cosmetic in
// the summary.md per-target table but lets the per-target column stay
// honest ("this target exercised PS Backtick Escape 321 times").
const FULL_CATALOG = [...CMD_TECHNIQUE_CATALOG, ...POWERSHELL_TECHNIQUE_CATALOG];
const recorder = makeTechniqueRecorder('cmd-obfuscation', FULL_CATALOG);

const td = new TextDecoder('utf-8', { fatal: false });

const fuzz = defineFuzzTarget({
  modules: [
    'src/constants.js',
    'src/encoded-content-detector.js',
    'src/decoders/safelinks.js',
    'src/decoders/whitelist.js',
    'src/decoders/entropy.js',
    'src/decoders/ioc-extract.js',
    'src/decoders/base64-hex.js',
    'src/decoders/cmd-obfuscation.js',
  ],
  // 64 KiB — the finder's inner loops scale linearly in text length
  // with bounded regex quantifiers, so this cap keeps each iteration
  // sub-second on the happy path while still exercising the multi-
  // statement resolution branches.
  maxBytes: 64 * 1024,
  perIterBudgetMs: 2_500,

  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    return err.message.startsWith('parser-limit:')
        || err.message.startsWith('finder-budget:');
  },

  onIteration(ctx, data) {
    const { EncodedContentDetector } = ctx;
    if (!EncodedContentDetector) {
      throw new Error('harness: EncodedContentDetector not exposed');
    }
    const text = td.decode(data);
    if (text.length === 0) return;

    const det = new EncodedContentDetector();
    const candidates = det._findCommandObfuscationCandidates(text, {});
    if (!Array.isArray(candidates)) {
      throw new Error(`invariant: finder returned ${typeof candidates}, expected array`);
    }

    const expected = data._expectedSubstring;
    let roundtripSatisfied = (expected == null);

    for (const c of candidates) {
      if (!c || typeof c !== 'object') {
        throw new Error('invariant: candidate not object');
      }
      if (typeof c.technique !== 'string' || c.technique.length === 0) {
        throw new Error(`invariant: candidate.technique shape — got ${JSON.stringify(c.technique)}`);
      }
      if (typeof c.raw !== 'string' || c.raw.length === 0) {
        throw new Error('invariant: candidate.raw empty/missing');
      }
      // Decode-blowup guard. Tightened to 32× to match the explicit
      // `_AMP_RATIO = 32` / `_ABS_CAP = 8 * 1024` cap in
      // `src/decoders/cmd-obfuscation.js`'s four branches (variable-
      // concat, delayed-expansion, `for /f`, single-bang). Any candidate
      // that exceeds 32× raw is a branch missing its peer cap — which
      // is the exact bug class the fuzzer is designed to find
      // (see AGENTS.md: `25f2e66` + twin pain-point entries).
      if (typeof c.deobfuscated === 'string'
          && c.deobfuscated.length > 32 * Math.max(1, c.raw.length)) {
        throw new Error(
          `invariant: decode blowup — technique=${JSON.stringify(c.technique)} `
          + `raw=${c.raw.length} deobf=${c.deobfuscated.length}`,
        );
      }

      const hasSubstring = typeof expected === 'string'
        && typeof c.deobfuscated === 'string'
        && c.deobfuscated.includes(expected);
      if (hasSubstring) roundtripSatisfied = true;

      recorder.record(c.technique, {
        success: typeof c.deobfuscated === 'string' && c.deobfuscated.length > 0,
        miss: false,  // tallied once at iteration end against the whole candidate set
      });
    }

    // Expected-substring miss counter — only meaningful for grammar
    // seeds (expected != null). Attribution split by finder outcome:
    //   • candidates empty  → recordEmptyMiss() (grammar seed failed to
    //                         trigger ANY branch; the signal is about
    //                         the seed itself, not a technique).
    //   • candidates fired  → tally the miss against the first
    //                         technique (candidate set disagreed with
    //                         the expected substring — decoder signal).
    if (typeof expected === 'string' && !roundtripSatisfied) {
      if (candidates.length === 0) {
        recorder.recordEmptyMiss();
      } else {
        recorder.record(candidates[0].technique, { miss: true });
      }
    }
  },
});

const seeds = [
  ...generateCmdSeeds(),
  ...syntheticTextSeeds(4),
];

module.exports = { fuzz, seeds, name: 'cmd-obfuscation' };
