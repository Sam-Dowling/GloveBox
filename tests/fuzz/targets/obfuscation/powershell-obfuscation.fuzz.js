'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/obfuscation/powershell-obfuscation.fuzz.js
//
// Fuzz the PowerShell-specific obfuscation surface. PowerShell lives in
// two decoder modules:
//
//   • `cmd-obfuscation.js` — PS string-concat, `-replace` chain, backtick
//                            escape, `-f` format operator, string
//                            reversal. The module is CMD+PS shared,
//                            loaded because ps-mini-evaluator.js depends
//                            on `_processCommandObfuscation` being
//                            present on the prototype.
//   • `ps-mini-evaluator.js` — `&(<expr>) <args>` one-pass symbol-table
//                            resolution; emits
//                            `'PowerShell Variable Resolution'`.
//
// This target drives BOTH finders per iteration and attributes hits to
// the unified `powershell-obfuscation` technique bucket.
//
// Invariants: same as cmd-obfuscation (shape, technique in catalog,
// decode-blowup guard). See that file for rationale.
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');
const { generatePowerShellSeeds, POWERSHELL_TECHNIQUE_CATALOG } = require('../../helpers/grammars/powershell-grammar.js');
const { CMD_TECHNIQUE_CATALOG } = require('../../helpers/grammars/cmd-grammar.js');
const { makeTechniqueRecorder } = require('../../helpers/technique-tracker.js');

// Shared finder emits CMD entries too on mixed inputs; accept both.
const FULL_CATALOG = [...POWERSHELL_TECHNIQUE_CATALOG, ...CMD_TECHNIQUE_CATALOG];
const recorder = makeTechniqueRecorder('powershell-obfuscation', FULL_CATALOG);

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
    'src/decoders/cmd-obfuscation.js',   // load order: cmd before ps-mini (build.py)
    'src/decoders/ps-mini-evaluator.js',
  ],
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

    // Two finder paths. Concatenate for uniform post-processing.
    const candidates = [];
    const c1 = det._findCommandObfuscationCandidates(text, {}) || [];
    if (!Array.isArray(c1)) {
      throw new Error('invariant: _findCommandObfuscationCandidates returned non-array');
    }
    for (const c of c1) candidates.push(c);

    if (typeof det._findPsVariableResolutionCandidates === 'function') {
      const c2 = det._findPsVariableResolutionCandidates(text, {}) || [];
      if (!Array.isArray(c2)) {
        throw new Error('invariant: _findPsVariableResolutionCandidates returned non-array');
      }
      for (const c of c2) candidates.push(c);
    }

    const expected = data._expectedSubstring;
    let roundtripSatisfied = (expected == null);

    for (const c of candidates) {
      if (!c || typeof c !== 'object') {
        throw new Error('invariant: candidate not object');
      }
      if (typeof c.technique !== 'string') {
        throw new Error(`invariant: candidate.technique shape — got ${typeof c.technique}`);
      }
      if (typeof c.deobfuscated === 'string'
          && typeof c.raw === 'string'
          && c.deobfuscated.length > 64 * Math.max(1, c.raw.length)) {
        throw new Error(
          `invariant: decode blowup — technique=${JSON.stringify(c.technique)} `
          + `raw=${c.raw.length} deobf=${c.deobfuscated.length}`,
        );
      }
      if (typeof expected === 'string'
          && typeof c.deobfuscated === 'string'
          && c.deobfuscated.includes(expected)) {
        roundtripSatisfied = true;
      }
      recorder.record(c.technique, {
        success: typeof c.deobfuscated === 'string' && c.deobfuscated.length > 0,
        miss: false,
      });
    }

    if (typeof expected === 'string' && !roundtripSatisfied) {
      const key = candidates[0]?.technique || '__unknown__';
      recorder.record(key, { miss: true });
    }
  },
});

const seeds = [
  ...generatePowerShellSeeds(),
  ...syntheticTextSeeds(4),
];

module.exports = { fuzz, seeds, name: 'powershell-obfuscation' };
