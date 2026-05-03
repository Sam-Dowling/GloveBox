'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/obfuscation/php-obfuscation.fuzz.js
//
// Fuzz `EncodedContentDetector.prototype._findPhpObfuscationCandidates`
// (src/decoders/php-obfuscation.js). Covers the 6 PHP branches:
//
//   PHP1 — eval(base64_decode(...)) + gzinflate/gzuncompress/gzdecode/
//          str_rot13 onion wrappers. Emits variable-length
//          `techPretty` strings reflecting the decoder chain; we
//          enumerate common shapes in the catalog and tolerate the
//          rest via `__unknown__`.
//   PHP2 — Variable-Variables ($$x and ${'…'}).
//   PHP3 — chr-concat / pack(H*) reassembly.
//   PHP4 — preg_replace /e modifier.
//   PHP5 — Superglobal Callable / eval-on-superglobal.
//   PHP6 — data:/php:// stream wrapper include.
//
// php-obfuscation.js calls Decompressor.inflateSync guarded by
// `typeof Decompressor`; absence degrades gracefully (see module
// header). We don't load decompressor.js for the same reason as
// python-obfuscation — fuzz surface is the finder, not the inflate.
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');
const { generatePhpSeeds, PHP_TECHNIQUE_CATALOG } = require('../../helpers/grammars/php-grammar.js');
const { makeTechniqueRecorder } = require('../../helpers/technique-tracker.js');

const recorder = makeTechniqueRecorder('php-obfuscation', PHP_TECHNIQUE_CATALOG);
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
    'src/decoders/php-obfuscation.js',
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
    const candidates = det._findPhpObfuscationCandidates(text, {}) || [];
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
      if (candidates.length === 0) {
        recorder.recordEmptyMiss();
      } else {
        recorder.record(candidates[0].technique, { miss: true });
      }
    }
  },
});

const seeds = [
  ...generatePhpSeeds(),
  ...syntheticTextSeeds(4),
];

module.exports = { fuzz, seeds, name: 'php-obfuscation' };
