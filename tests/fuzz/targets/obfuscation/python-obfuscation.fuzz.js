'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/obfuscation/python-obfuscation.fuzz.js
//
// Fuzz `EncodedContentDetector.prototype._findPythonObfuscationCandidates`
// (src/decoders/python-obfuscation.js). Covers the 15 technique branches:
// exec(zlib.decompress(…)), exec(marshal.loads(…)), codecs.decode with
// rot13/base64/hex/zlib, chr-join / bytes-list / chr-concat reassembly,
// getattr-based builtin string-concat, and subprocess / os.system /
// pty.spawn / socket reverse-shell sinks.
//
// python-obfuscation.js calls `Decompressor.inflateSync` inside the
// zlib-wrapped branch; the finder guards with `typeof Decompressor`
// checks so absence degrades gracefully. We don't load src/decompressor.js
// to keep the fuzz target narrow — the "did we inflate?" path is covered
// by unit tests, and the interesting fuzz surface is the pattern finder.
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');
const { generatePythonSeeds, PYTHON_TECHNIQUE_CATALOG } = require('../../helpers/grammars/python-grammar.js');
const { makeTechniqueRecorder } = require('../../helpers/technique-tracker.js');

const recorder = makeTechniqueRecorder('python-obfuscation', PYTHON_TECHNIQUE_CATALOG);
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
    'src/decoders/python-obfuscation.js',
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
    const candidates = det._findPythonObfuscationCandidates(text, {}) || [];
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
  ...generatePythonSeeds(),
  ...syntheticTextSeeds(4),
];

module.exports = { fuzz, seeds, name: 'python-obfuscation' };
