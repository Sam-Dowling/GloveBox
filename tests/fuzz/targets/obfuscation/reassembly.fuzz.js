'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/obfuscation/reassembly.fuzz.js
//
// Fuzz the whole-file reassembly pipeline — `EncodedReassembler.build()` +
// `EncodedReassembler.analyze()` over real `EncodedContentDetector.scan()`
// output on multi-technique / multi-line obfuscated scripts.
//
// Why a dedicated target:
//   The per-shell obfuscation targets drive one decoder branch per
//   iteration. They catch single-atom decode regressions but CANNOT catch
//   orchestration bugs in the reassembler — the module that stitches N
//   independent spans from different byte offsets into one composite
//   script. `src/encoded-reassembler.js` is loaded by zero targets today
//   so its per-file coverage table row reads "never fuzzed".
//
// Pipeline per iteration:
//   1. `text = utf-8-decode(data)`
//   2. `encodedFindings = await det.scan(text, data, {})`   — full mixin chain
//   3. For each mode in ['auto', 'bruteforce']:
//        recon = EncodedReassembler.build(text, encodedFindings, { mode })
//        If `recon.spans.length >= 2`:
//          - Validate structural invariants (sentinels, hash shape,
//            mapReconToSource round-trip, stripSentinels no-sentinel
//            postcondition).
//          - analysis = await EncodedReassembler.analyze(recon, {
//              extractInterestingStringsCore, existingIocs: {allValues:new Set()},
//              workerManager: null,       // → `skipped.yara = 'no-worker-manager'`
//              yaraSource: '',
//            })
//          - Validate `analysis` shape; every novelIoc carries
//            `_fromReassembly === true` + `_reconstructedHash === hash`
//            and a canonical `IOC.*` type.
//          - Win-condition: if the seed declared `_expectedIocs`, check
//            every atom appears in either `recon.text` OR the novel IOC
//            values. Missed atoms record `expected-ioc-missed` (miss:true)
//            via the technique recorder — soft signal, never a crash.
//        Else:
//          - Record the specific skipReason as a technique (e.g.
//            'reassembly: below-coverage skip').
//
// Win-condition discipline (per the user's planning answer):
//   A grammar seed declaring `_expectedIocs` is asking "did the
//   reassembler recover every atom I planted?" A miss on any atom is
//   recorded as a soft signal (`miss: true` on the `expected-ioc-missed`
//   technique row + `recordEmptyMiss()` when zero candidates fired at
//   all) — never a crash. This matches the per-shell obfuscation
//   targets' `_expectedSubstring` convention.
//
// YARA scope:
//   `analyze()` has two phases — IOC-extract (pure, synchronous) and
//   decoded-payload YARA (worker-dependent). This target passes
//   `workerManager: null` so analyze takes the documented
//   `skipped.yara = 'no-worker-manager'` branch. YARA-over-stitched is
//   exercised by Playwright fixture tests.
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');
const { makeTechniqueRecorder } = require('../../helpers/technique-tracker.js');
const {
  generateMultiTechniqueSeeds,
  generatePairConcatSeeds,
  REASSEMBLY_TECHNIQUE_CATALOG,
} = require('../../helpers/grammars/multi-technique-grammar.js');
const { generateCmdSeeds } = require('../../helpers/grammars/cmd-grammar.js');
const { generatePowerShellSeeds } = require('../../helpers/grammars/powershell-grammar.js');
const { generateBashSeeds } = require('../../helpers/grammars/bash-grammar.js');
const { generatePythonSeeds } = require('../../helpers/grammars/python-grammar.js');
const { generatePhpSeeds } = require('../../helpers/grammars/php-grammar.js');

const recorder = makeTechniqueRecorder('reassembly', REASSEMBLY_TECHNIQUE_CATALOG);

const td = new TextDecoder('utf-8', { fatal: false });

// ── Module list ────────────────────────────────────────────────────────────
// Full `_DETECTOR_FILES` mixin chain (mirrors `encoded-decoder-chain.fuzz.js`)
// + `src/ioc-extract.js` (for `extractInterestingStringsCore`, needed by
// `analyze()`'s re-extract phase) + `src/encoded-reassembler.js` (the
// module under test). Order is load-bearing — each mixin assumes its
// dependencies have already loaded their prototype chunks.
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

// ── IOC enum pin (canonical invariant, 1fadc6b) ────────────────────────────
let _IOC_VALUES = null;
function ensureIocValues(ctx) {
  if (_IOC_VALUES === null) {
    if (!ctx.IOC) throw new Error('harness: IOC enum not exposed');
    _IOC_VALUES = new Set(Object.values(ctx.IOC));
  }
  return _IOC_VALUES;
}

// ── Structural invariant walker for a reconstructed object ────────────────
function validateReconstruction(recon, source) {
  if (!recon || typeof recon !== 'object') {
    throw new Error(`invariant: build() returned ${typeof recon}`);
  }
  // Skip-reason branch — minimal shape check and return.
  if (recon.skipReason !== undefined) {
    if (typeof recon.skipReason !== 'string' || recon.skipReason.length === 0) {
      throw new Error(`invariant: skipReason shape — got ${JSON.stringify(recon.skipReason)}`);
    }
    return { reconstructed: false };
  }
  // Happy-path shape.
  if (typeof recon.text !== 'string' || recon.text.length === 0) {
    throw new Error('invariant: recon.text missing or empty on reconstructed result');
  }
  if (!Array.isArray(recon.spans)) {
    throw new Error('invariant: recon.spans not an array');
  }
  if (!Array.isArray(recon.sourceMap)) {
    throw new Error('invariant: recon.sourceMap not an array');
  }
  if (typeof recon.reconstructedHash !== 'string'
      || !/^[0-9a-f]{16}$/.test(recon.reconstructedHash)) {
    throw new Error(`invariant: reconstructedHash shape — got ${JSON.stringify(recon.reconstructedHash)}`);
  }
  if (!recon.coverage
      || typeof recon.coverage.ratio !== 'number'
      || recon.coverage.ratio < 0 || recon.coverage.ratio > 1) {
    throw new Error(`invariant: coverage.ratio out of range — got ${recon.coverage && recon.coverage.ratio}`);
  }
  if (recon.coverage.bytesReplaced > recon.coverage.sourceBytes) {
    throw new Error('invariant: coverage.bytesReplaced > sourceBytes');
  }
  if (recon.coverage.sourceBytes !== source.length) {
    throw new Error(`invariant: coverage.sourceBytes !== source.length (${recon.coverage.sourceBytes} vs ${source.length})`);
  }
  if (!Array.isArray(recon.techniques)) {
    throw new Error('invariant: recon.techniques not an array');
  }
  const SEV = new Set(['critical', 'high', 'medium', 'low', 'info']);
  if (!SEV.has(recon.severity)) {
    throw new Error(`invariant: recon.severity outside canonical tier set — got ${JSON.stringify(recon.severity)}`);
  }

  // sourceMap ordering — reconOffset monotonically non-decreasing; cumulative
  // coverage must equal recon.text.length exactly.
  let prevReconOffset = -1;
  for (const entry of recon.sourceMap) {
    if (typeof entry.reconOffset !== 'number' || entry.reconOffset < prevReconOffset) {
      throw new Error(`invariant: sourceMap reconOffset not monotonic — got ${entry.reconOffset} after ${prevReconOffset}`);
    }
    prevReconOffset = entry.reconOffset;
  }

  return { reconstructed: true };
}

function validateSpans(recon) {
  // Every spliced span must carry sentinel wrappers on both sides;
  // textStart..textEnd must equal deobfuscatedText byte-for-byte.
  for (const s of recon.spans) {
    if (typeof s.replaceStart !== 'number' || typeof s.replaceEnd !== 'number'
        || typeof s.textStart !== 'number' || typeof s.textEnd !== 'number') {
      throw new Error('invariant: span offsets missing');
    }
    if (s.replaceStart >= s.replaceEnd || s.textStart > s.textEnd) {
      throw new Error('invariant: span offsets inverted');
    }
    if (s.replaceEnd > recon.text.length) {
      throw new Error(`invariant: span replaceEnd (${s.replaceEnd}) > text.length (${recon.text.length})`);
    }
    const opened = recon.text.slice(s.replaceStart, s.replaceStart + recon.sentinelOpen.length);
    const closed = recon.text.slice(s.replaceEnd - recon.sentinelClose.length, s.replaceEnd);
    if (opened !== recon.sentinelOpen) {
      throw new Error('invariant: span missing opening sentinel');
    }
    if (closed !== recon.sentinelClose) {
      throw new Error('invariant: span missing closing sentinel');
    }
    if (typeof s.deobfuscatedText === 'string'
        && recon.text.slice(s.textStart, s.textEnd) !== s.deobfuscatedText) {
      throw new Error('invariant: span.textStart..textEnd != deobfuscatedText');
    }
  }
}

function validateStripSentinels(recon, stripSentinels) {
  const stripped = stripSentinels(recon.text);
  if (typeof stripped !== 'string') {
    throw new Error(`invariant: stripSentinels returned ${typeof stripped}`);
  }
  // Post-strip: ZERO U+2063 code points.
  if (stripped.indexOf('\u2063') !== -1) {
    throw new Error('invariant: stripSentinels left a U+2063 sentinel behind');
  }
  // Idempotence: strip(strip(x)) === strip(x).
  if (stripSentinels(stripped) !== stripped) {
    throw new Error('invariant: stripSentinels not idempotent');
  }
}

function validateMapReconToSource(recon, mapReconToSource) {
  // Every span's `replaceStart + SENTINEL_OPEN.length` (start of the
  // decoded body) must map back to the span's `sourceOffset`.
  for (const s of recon.spans) {
    const probe = s.replaceStart + recon.sentinelOpen.length;
    const mapped = mapReconToSource(recon, probe);
    if (mapped !== s.sourceOffset) {
      throw new Error(
        `invariant: mapReconToSource(${probe}) returned ${mapped}, expected ${s.sourceOffset}`,
      );
    }
  }
}

function validateAnalyzeShape(analysis, recon, iocEnum) {
  if (!analysis || typeof analysis !== 'object') {
    throw new Error(`invariant: analyze() returned ${typeof analysis}`);
  }
  if (!Array.isArray(analysis.novelIocs)) {
    throw new Error('invariant: analysis.novelIocs not an array');
  }
  if (!Array.isArray(analysis.yaraHits)) {
    throw new Error('invariant: analysis.yaraHits not an array');
  }
  if (typeof analysis.scannedBytes !== 'number') {
    throw new Error('invariant: analysis.scannedBytes not a number');
  }
  if (typeof analysis.extractMs !== 'number' || typeof analysis.yaraMs !== 'number') {
    throw new Error('invariant: analysis timing shape');
  }
  if (!analysis.skipped || typeof analysis.skipped !== 'object') {
    throw new Error('invariant: analysis.skipped shape');
  }
  // `workerManager: null` must take the 'no-worker-manager' YARA branch.
  if (analysis.skipped.yara !== 'no-worker-manager') {
    throw new Error(
      `invariant: expected skipped.yara='no-worker-manager', got ${JSON.stringify(analysis.skipped.yara)}`,
    );
  }
  for (const ioc of analysis.novelIocs) {
    if (!ioc || typeof ioc !== 'object') {
      throw new Error('invariant: novelIoc entry not object');
    }
    if (typeof ioc.type !== 'string' || !iocEnum.has(ioc.type)) {
      throw new Error(`invariant: novelIoc.type ${JSON.stringify(ioc.type)} not in IOC.* enum`);
    }
    if (ioc._fromReassembly !== true) {
      throw new Error('invariant: novelIoc missing _fromReassembly=true');
    }
    if (ioc._reconstructedHash !== recon.reconstructedHash) {
      throw new Error(
        `invariant: novelIoc._reconstructedHash mismatch — got ${JSON.stringify(ioc._reconstructedHash)}, expected ${recon.reconstructedHash}`,
      );
    }
  }
}

// ── Fuzz target ────────────────────────────────────────────────────────────

const fuzz = defineFuzzTarget({
  modules: ['src/constants.js', 'src/hashes.js', ...DETECTOR_FILES, 'src/ioc-extract.js', 'src/encoded-reassembler.js'],
  expose: [
    'IOC',
    'EncodedContentDetector',
    'EncodedReassembler',
    'extractInterestingStringsCore',
    'PARSER_LIMITS',
  ],
  // 128 KiB — larger than `encoded-decoder-chain` (64 KiB) because the
  // composite seeds are deliberately multi-atom and the reassembler's
  // work scales with candidate count. Still well below FINDER_MAX_INPUT_BYTES.
  maxBytes: 128 * 1024,
  // scan() + build() + analyze() on a 128 KiB composite takes longer than
  // finders alone. 7.5 s leaves generous headroom above FINDER_BUDGET_MS
  // (2.5 s) and RENDERER_TIMEOUT_MS isn't relevant here (no DOM).
  perIterBudgetMs: 7_500,

  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    return err.message.startsWith('parser-limit:')
        || err.message.startsWith('aggregate-budget:')
        || err.message.startsWith('finder-budget:');
  },

  async onIteration(ctx, data) {
    const {
      EncodedContentDetector,
      EncodedReassembler,
      extractInterestingStringsCore,
    } = ctx;
    if (!EncodedContentDetector) throw new Error('harness: EncodedContentDetector not exposed');
    if (!EncodedReassembler)     throw new Error('harness: EncodedReassembler not exposed');
    if (typeof extractInterestingStringsCore !== 'function') {
      throw new Error('harness: extractInterestingStringsCore not exposed');
    }
    const iocEnum = ensureIocValues(ctx);
    const { build, analyze, stripSentinels, mapReconToSource } = EncodedReassembler;

    const text = td.decode(data);
    if (text.length === 0) return;

    const det = new EncodedContentDetector();
    const encodedFindings = await det.scan(text, data, {});
    if (!Array.isArray(encodedFindings)) {
      throw new Error(`invariant: scan() returned ${typeof encodedFindings}`);
    }

    // Surface the seed's expected IOCs (grammar-seeded only) exactly once
    // so we can evaluate the win condition on BOTH modes without
    // re-reading the property each iteration.
    const expectedIocs = Array.isArray(data._expectedIocs) ? data._expectedIocs : null;
    const expectedSubstring = typeof data._expectedSubstring === 'string' ? data._expectedSubstring : null;

    for (const mode of ['auto', 'bruteforce']) {
      const recon = build(text, encodedFindings, { mode });
      if (recon === null) {
        // Legacy shape — build() never returns null today but the
        // contract accepts it as a "nothing to stitch" signal. Treat
        // as a too-few-findings skip.
        recorder.record('reassembly: too-few-findings skip', { success: false });
        if (expectedIocs && expectedIocs.length > 0) recorder.recordEmptyMiss();
        continue;
      }

      const { reconstructed } = validateReconstruction(recon, text);

      if (!reconstructed) {
        // skipReason branch — attribute to a specific catalog row so the
        // aggregator can tell "below-coverage" apart from
        // "too-few-findings" apart from "too-few-after-overlap".
        const skip = recon.skipReason;
        const tech = (skip === 'below-coverage')                      ? 'reassembly: below-coverage skip'
                   : (skip === 'too-few-findings')                    ? 'reassembly: too-few-findings skip'
                   : (skip === 'too-few-after-overlap-resolution')    ? 'reassembly: too-few-after-overlap-resolution skip'
                   : (skip === 'no-source' || skip === 'no-findings') ? 'reassembly: too-few-findings skip'
                   : '__unknown__';
        recorder.record(tech, { success: false });
        if (expectedIocs && expectedIocs.length > 0) {
          // The seed planted IOCs but the reassembly couldn't build.
          // This is an empty-miss (candidates fired but none reassembled).
          recorder.recordEmptyMiss();
        }
        continue;
      }

      // Reconstructed happy path. Validate deeper invariants before
      // passing to analyze.
      if (recon.spans.length < 2) {
        throw new Error(`invariant: reconstructed result with spans.length=${recon.spans.length}`);
      }
      validateSpans(recon);
      validateStripSentinels(recon, stripSentinels);
      validateMapReconToSource(recon, mapReconToSource);

      // Determinism — build() twice on the same inputs must yield the
      // same reconstructedHash. A drift here means a source of
      // nondeterminism leaked into the splicing pipeline.
      const recon2 = build(text, encodedFindings, { mode });
      if (recon2 && recon2.reconstructedHash !== recon.reconstructedHash) {
        throw new Error(
          `invariant: reconstructedHash nondeterministic — ${recon.reconstructedHash} vs ${recon2.reconstructedHash}`,
        );
      }

      // Primary structural outcome.
      recorder.record('reassembly: built ≥2 spans', { success: true });

      // Auxiliary outcomes — truncation, overlap collisions, technique mix.
      if (recon.truncated === true) {
        recorder.record('reassembly: truncated', { success: true });
      }
      if (Array.isArray(recon.collisions) && recon.collisions.length > 0) {
        recorder.record('reassembly: overlap-collision', { success: true });
      }
      if (Array.isArray(recon.techniques) && recon.techniques.length >= 2) {
        recorder.record('reassembly: techniques-mixed', { success: true });
      }

      // ── Phase 2 — IOC re-extract over stripped body ────────────────
      // Pass `workerManager: null` to take the documented
      // `skipped.yara = 'no-worker-manager'` branch — this target
      // covers IOC-extract only; YARA-on-stitched is exercised by
      // Playwright fixture tests (per the planning decision).
      const analysis = await analyze(recon, {
        extractInterestingStringsCore,
        existingIocs: { allValues: new Set() },
        workerManager: null,
        yaraSource: '',
      });

      validateAnalyzeShape(analysis, recon, iocEnum);

      for (const _ioc of analysis.novelIocs) {
        recorder.record('reassembly: novel-ioc-surfaced', { success: true });
      }

      // Win-condition evaluation. `stitched` is the sentinel-stripped
      // reconstruction concatenated with the novel-IOC values — the
      // union of "what the stitched body literally contains" and "what
      // the re-extract surfaced". An `_expectedIocs` atom present in
      // EITHER counts as surfaced (some atoms aren't IOC-regex-shaped
      // but do appear verbatim in the stitched body).
      if (expectedIocs && expectedIocs.length > 0) {
        const stripped = stripSentinels(recon.text);
        const novelValues = analysis.novelIocs
          .map(r => r && (r.url || r.value))
          .filter(v => typeof v === 'string' && v.length > 0);
        const combined = stripped + '\n' + novelValues.join('\n');
        let missedAny = false;
        for (const atom of expectedIocs) {
          if (typeof atom !== 'string' || atom.length === 0) continue;
          if (!combined.includes(atom)) {
            missedAny = true;
            break;
          }
        }
        if (missedAny) {
          recorder.record('reassembly: expected-ioc-missed', { miss: true });
        } else {
          recorder.record('reassembly: all-expected-iocs-surfaced', { success: true });
        }
      } else if (expectedSubstring) {
        // Pair-concat fallback — the seed only carries the per-shell
        // `_expectedSubstring`. Treat exactly the same as a single-
        // atom `_expectedIocs`.
        const stripped = stripSentinels(recon.text);
        const novelValues = analysis.novelIocs
          .map(r => r && (r.url || r.value))
          .filter(v => typeof v === 'string' && v.length > 0);
        const combined = stripped + '\n' + novelValues.join('\n');
        if (!combined.includes(expectedSubstring)) {
          recorder.record('reassembly: expected-ioc-missed', { miss: true });
        } else {
          recorder.record('reassembly: all-expected-iocs-surfaced', { success: true });
        }
      }
    }
  },
});

// ── Seed corpus ───────────────────────────────────────────────────────────
// Primary: curated multi-technique composites + hand-rolled classic
// droppers from the new grammar module. Secondary: pair-concatenated
// per-shell grammar seeds (less-coherent but cross-decoder coverage).
// Tertiary: synthetic fallback for regex-shape sanity.
const perShellSeeds = [
  ...generateCmdSeeds(),
  ...generatePowerShellSeeds(),
  ...generateBashSeeds(),
  ...generatePythonSeeds(),
  ...generatePhpSeeds(),
];

const seeds = [
  ...generateMultiTechniqueSeeds(),
  ...generatePairConcatSeeds(perShellSeeds, 24),
  ...syntheticTextSeeds(4),
];

module.exports = { fuzz, seeds, name: 'reassembly' };
