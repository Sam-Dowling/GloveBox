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
        fs.writeFileSync(fp, JSON.stringify({
          targetId: rec.targetId,
          catalog:  rec.catalog,
          counters: rec._serialise(),
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

/**
 * Build a recorder for a fuzz target.
 *
 * @param {string}   targetId  Short identifier (e.g. `'bash-obfuscation'`).
 * @param {string[]} catalog   Authoritative list of known technique names.
 * @returns {{
 *   record: (technique: string, info?: {success?: boolean, miss?: boolean}) => void,
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

  const rec = {
    targetId,
    catalog: catalog.slice(),
    record(technique, info) {
      const key = typeof technique === 'string' && counters.has(technique)
        ? technique : '__unknown__';
      const c = counters.get(key);
      c.hits++;
      if (info && info.success === true) c.decodeSuccess++;
      else if (info && info.success === false) c.decodeFail++;
      if (info && info.miss === true) c.expectedMiss++;
    },
    snapshot() {
      const out = {};
      for (const [k, v] of counters) out[k] = Object.assign({}, v);
      return out;
    },
    _serialise() {
      return rec.snapshot();
    },
  };

  if (DUMP_DIR) {
    _registry.push(rec);
    _installExitHook();
  }
  return rec;
}

module.exports = { makeTechniqueRecorder };
