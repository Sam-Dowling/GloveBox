'use strict';
// ════════════════════════════════════════════════════════════════════════════
// technique-tracker.js — per-technique hit / decode-success / expected-miss
// counters for the obfuscation fuzz targets.
//
// The obfuscation decoders
// (`src/decoders/{cmd,bash,python,php}-obfuscation.js`,
// `src/decoders/ps-mini-evaluator.js`, `src/decoders/js-assembly.js`) each
// emit candidate objects with a stringly-typed `technique` field describing
// the specific branch that fired (e.g. `'CMD Caret Insertion'`,
// `'Bash Pipe-to-Shell (live fetch)'`). The per-shell fuzz targets install a
// recorder from this module; when the env var `LOUPE_FUZZ_TECHNIQUE_DIR` is
// set (or `LOUPE_FUZZ_COVERAGE_DIR` — the two co-locate so
// `scripts/fuzz_coverage_aggregate.py` finds manifest + technique JSON
// sidecars side-by-side), the recorder writes a summary JSON per process
// at exit so the aggregator can render a per-technique table in
// `dist/fuzz-coverage/summary.md`.
//
// Outside a coverage run both env vars are unset and the recorder is a
// no-op — zero overhead on the crash-hunting hot path.
//
// Design notes:
//   • One recorder per target module. The recorder name is the target id
//     (e.g. `'bash-obfuscation'`) so the aggregator can key by it.
//   • The catalog is the authoritative list of known technique strings.
//     A `technique` value outside the catalog is recorded under
//     `__unknown__` so divergence between the grammar / decoder surfaces
//     is visible in the summary.
//   • Counts are accumulated in-process, flushed once on `exit`. Multi-
//     process (Jazzer.js worker fan-out) writes distinct files — the
//     aggregator unions on `technique` key, summing counters.
//   • Writes are best-effort: a failure to dump counters MUST NOT break
//     the fuzz run.
// ════════════════════════════════════════════════════════════════════════════

const fs = require('node:fs');
const path = require('node:path');

const DUMP_DIR = process.env.LOUPE_FUZZ_TECHNIQUE_DIR
              || process.env.LOUPE_FUZZ_COVERAGE_DIR
              || '';

// Registered recorders, flushed together on `exit`. Multiple targets in the
// same process (unusual — replay mode keeps one target per invocation) each
// contribute their own entry.
const _registry = [];
let _exitHooked = false;

function _installExitHook() {
  if (_exitHooked) return;
  _exitHooked = true;
  // `exit` is synchronous — a long async flush would be skipped. Our
  // payload is tiny (one JSON object per target) so sync fs is fine.
  process.on('exit', () => {
    if (!DUMP_DIR) return;
    try { fs.mkdirSync(DUMP_DIR, { recursive: true }); }
    catch (_) { return; }
    for (const rec of _registry) {
      try {
        const stamp = `${process.pid}-${Date.now().toString(36)}`;
        const fp = path.join(DUMP_DIR, `techniques-${rec.targetId}-${stamp}.json`);
        const payload = rec._serialise();
        fs.writeFileSync(fp, JSON.stringify({
          targetId:       rec.targetId,
          catalog:        rec.catalog,
          counters:       payload.counters,
          unknownSamples: payload.unknownSamples,
          emptyMisses:    payload.emptyMisses,
        }));
      } catch (err) {
        // Diagnostic only — never raise.
        try {
          process.stderr.write(
            `technique-tracker: flush failed for ${rec.targetId}: ${err.message}\n`,
          );
        } catch (_) { /* stderr already closed */ }
      }
    }
  });
}

// Cap on distinct unknown-technique sample strings retained per recorder.
// Bounded to keep the JSON sidecar tiny (each sample is usually 30-80 bytes,
// so 32 samples ≈ ≤3 KB) while giving the aggregator enough material to
// make catalog drift visible at a glance.
const UNKNOWN_SAMPLE_CAP = 32;

/**
 * Build a recorder for a fuzz target.
 *
 * @param {string}   targetId  Short identifier (e.g. `'bash-obfuscation'`).
 * @param {string[]} catalog   Authoritative list of known technique names.
 * @returns {{
 *   record: (technique: string, info?: {success?: boolean, miss?: boolean}) => void,
 *   recordEmptyMiss: () => void,
 *   snapshot: () => object,
 *   targetId: string,
 *   catalog: string[],
 * }}
 */
function makeTechniqueRecorder(targetId, catalog) {
  if (typeof targetId !== 'string' || !targetId) {
    throw new TypeError('makeTechniqueRecorder: targetId required');
  }
  if (!Array.isArray(catalog)) {
    throw new TypeError('makeTechniqueRecorder: catalog must be an array');
  }

  // Pre-populate so the aggregator sees every catalog entry, including
  // those with zero hits (the interesting case for "under-fuzzed
  // techniques" triage).
  const counters = new Map();
  for (const t of catalog) {
    counters.set(t, { hits: 0, decodeSuccess: 0, decodeFail: 0, expectedMiss: 0 });
  }
  counters.set('__unknown__', { hits: 0, decodeSuccess: 0, decodeFail: 0, expectedMiss: 0 });

  // Distinct unknown-technique strings seen during the run. A non-empty
  // set signals catalog drift — the aggregator renders it as a footnote
  // under the per-module technique table.
  const unknownSamples = new Set();

  // Count of iterations whose grammar seed declared an `_expectedSubstring`
  // but where the finder returned ZERO candidates (so there was nothing
  // to attribute the miss to). Distinct from `__unknown__.expectedMiss`
  // which now fires only when the finder did produce candidate(s) but
  // none contained the expected substring under a KNOWN technique.
  let emptyMisses = 0;

  const rec = {
    targetId,
    catalog: catalog.slice(),
    record(technique, info) {
      const known = typeof technique === 'string' && counters.has(technique);
      const key = known ? technique : '__unknown__';
      if (!known && typeof technique === 'string' && technique.length > 0
          && unknownSamples.size < UNKNOWN_SAMPLE_CAP) {
        // Clip pathological values (shouldn't happen — technique strings
        // in the decoders are all short literals — but a future change
        // could introduce a dynamically-constructed string; bound it).
        unknownSamples.add(technique.length > 160 ? technique.slice(0, 160) + '…' : technique);
      }
      const c = counters.get(key);
      c.hits++;
      if (info && info.success === true) c.decodeSuccess++;
      else if (info && info.success === false) c.decodeFail++;
      if (info && info.miss === true) c.expectedMiss++;
    },
    recordEmptyMiss() {
      emptyMisses++;
    },
    snapshot() {
      const out = {};
      for (const [k, v] of counters) out[k] = Object.assign({}, v);
      return out;
    },
    _serialise() {
      return {
        counters: rec.snapshot(),
        unknownSamples: [...unknownSamples],
        emptyMisses,
      };
    },
  };

  if (DUMP_DIR) {
    _registry.push(rec);
    _installExitHook();
  }
  return rec;
}

module.exports = { makeTechniqueRecorder };
