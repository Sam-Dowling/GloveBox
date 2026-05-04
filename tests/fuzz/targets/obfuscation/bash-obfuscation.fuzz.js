'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/obfuscation/bash-obfuscation.fuzz.js
//
// Fuzz `EncodedContentDetector.prototype._findBashObfuscationCandidates`
// (src/decoders/bash-obfuscation.js). Covers 26 technique branches across
// B1 (variable expansion), B2 (ANSI-C quoting), B3 (printf chains),
// B4 (pipe-to-shell — live fetch + base64/xxd variants), B5 (eval
// $(…) command substitution), B6 (IFS / brace fragmentation), the
// /dev/tcp reverse-shell structural recognition, plus Phase-2 fills:
// B7 (echo -e hex/octal), B8 (${!pointer} indirect expansion), B9
// (awk/perl/python{,3}/ruby/node/php inline executors), and B10
// (tr rot13 here-string cipher).
//
// Loads cmd-obfuscation.js because bash-obfuscation.js consumes
// `_processCommandObfuscation` from that module (build.py load order).
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');
const { generateBashSeeds, BASH_TECHNIQUE_CATALOG } = require('../../helpers/grammars/bash-grammar.js');
const { makeTechniqueRecorder } = require('../../helpers/technique-tracker.js');

const recorder = makeTechniqueRecorder('bash-obfuscation', BASH_TECHNIQUE_CATALOG);
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
    'src/decoders/bash-obfuscation.js',
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
    const candidates = det._findBashObfuscationCandidates(text, {}) || [];
    if (!Array.isArray(candidates)) {
      throw new Error(`invariant: finder returned ${typeof candidates}, expected array`);
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
          && c.deobfuscated.length > 32 * Math.max(1, c.raw.length)) {
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
      if (candidates.length === 0) {
        recorder.recordEmptyMiss();
      } else {
        recorder.record(candidates[0].technique, { miss: true });
      }
    }
  },
});

const seeds = [
  ...generateBashSeeds(),
  ...syntheticTextSeeds(4),
];

module.exports = { fuzz, seeds, name: 'bash-obfuscation' };
