#!/usr/bin/env node
'use strict';
// ════════════════════════════════════════════════════════════════════════════
// jazzer-bootstrap.js — CLI driver for the Jazzer.js v4 fuzzer.
//
// Jazzer.js v4 expects to be invoked via its CLI (`@jazzer.js/core`'s
// `bin: jazzer` entry); the public JS API takes an `OptionsManager`
// instance which is internal-flavoured. Calling the CLI from inside this
// file (rather than directly from `scripts/run_fuzz.py`) lets us:
//
//   1. Stage the target's seed corpus into the libFuzzer corpus dir
//      before fuzzing starts (Python could do this too, but keeping the
//      seed logic in JS means the seeds and the target file share a
//      runtime — easier to evolve together).
//
//   2. Pre-flight require the target so a syntax error / missing module
//      surfaces with a clean stack BEFORE Jazzer.js spawns its workers
//      (Jazzer's own error path here is comparatively cryptic).
//
//   3. Wrap the spawned CLI process with a Node child_process so we can
//      enforce our own timeout + buffer the stderr stream for the
//      python orchestrator's summary table.
//
// ENV (all set by scripts/run_fuzz.py):
//   LOUPE_FUZZ_TARGET     absolute path to the *.fuzz.js file
//   LOUPE_FUZZ_TARGET_ID  display name (e.g. "text/ioc-extract")
//   LOUPE_FUZZ_CORPUS     dist/fuzz-corpus/<id>/  (libFuzzer corpus dir)
//   LOUPE_FUZZ_CRASHES    dist/fuzz-crashes/<id>/ (libFuzzer artefact dir)
//   LOUPE_FUZZ_TIME       wall-clock seconds budget (libFuzzer -max_total_time)
// ════════════════════════════════════════════════════════════════════════════

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const TARGET = process.env.LOUPE_FUZZ_TARGET;
const TARGET_ID = process.env.LOUPE_FUZZ_TARGET_ID || 'unknown';
const CORPUS = process.env.LOUPE_FUZZ_CORPUS;
const CRASHES = process.env.LOUPE_FUZZ_CRASHES;
const TIME_SECONDS = parseInt(process.env.LOUPE_FUZZ_TIME || '60', 10);

if (!TARGET || !CORPUS || !CRASHES) {
  console.error('jazzer-bootstrap: LOUPE_FUZZ_TARGET / LOUPE_FUZZ_CORPUS / LOUPE_FUZZ_CRASHES env vars required');
  process.exit(2);
}

// ── Pre-flight require ──────────────────────────────────────────────────────
// Surface a missing-module / syntax error from the target itself with a
// clean stack before handing off to Jazzer.js's CLI.
let mod;
try { mod = require(path.resolve(TARGET)); }
catch (err) {
  console.error(`jazzer-bootstrap: failed to require target ${TARGET}:`);
  console.error(err && err.stack || err);
  process.exit(2);
}
if (typeof mod.fuzz !== 'function') {
  console.error(`jazzer-bootstrap: target ${TARGET} must export module.exports.fuzz`);
  process.exit(2);
}
const seeds = Array.isArray(mod.seeds) ? mod.seeds : [];
if (seeds.length === 0) {
  console.error(`jazzer-bootstrap: target ${TARGET} declared no seeds — coverage-guided fuzzing without seeds wastes the first ~minute on magic-byte discovery. Add seeds.`);
  process.exit(2);
}

// ── Stage seeds ─────────────────────────────────────────────────────────────
fs.mkdirSync(CORPUS, { recursive: true });
fs.mkdirSync(CRASHES, { recursive: true });
let staged = 0;
for (const seed of seeds) {
  const sha = crypto.createHash('sha256').update(seed).digest('hex').slice(0, 16);
  const f = path.join(CORPUS, `seed-${sha}`);
  if (!fs.existsSync(f)) {
    fs.writeFileSync(f, seed);
    staged++;
  }
}

// ── Resolve Jazzer.js CLI ───────────────────────────────────────────────────
// `dist/test-deps/node_modules/.bin/jazzer` is the canonical path; fall
// back to walking up via require.resolve in case npm laid it out
// elsewhere.
const jazzerCli = path.resolve(
  __dirname, '..', '..', '..',
  'dist', 'test-deps', 'node_modules', '.bin',
  process.platform === 'win32' ? 'jazzer.cmd' : 'jazzer',
);
if (!fs.existsSync(jazzerCli)) {
  console.error(`jazzer-bootstrap: jazzer CLI not found at ${jazzerCli}. `
    + `Run scripts/run_fuzz.py to provision @jazzer.js/core into dist/test-deps/.`);
  process.exit(2);
}

console.log(`jazzer-bootstrap: target=${TARGET_ID} corpus=${CORPUS} `
  + `seeded=${staged}/${seeds.length} budget=${TIME_SECONDS}s`);

// ── Spawn the CLI ───────────────────────────────────────────────────────────
//
// Argv shape (per `jazzer --help`):
//   jazzer <fuzzTarget> <corpusDir> -- <libFuzzerOptions...>
//
// `<fuzzTarget>` is a module specifier — the CLI runs `require(spec)`
// in its own runtime, so we pass the absolute path.
//
// The `--` separator ends Jazzer.js options and starts libFuzzer flags:
//   -artifact_prefix=<crashes-dir>/  → where libFuzzer drops crash files
//   -max_total_time=<seconds>        → wall-clock cap
//   -timeout=<seconds>               → per-iteration cap (libFuzzer's;
//                                       harness.js also enforces a
//                                       2.5 s budget per iter for
//                                       ReDoS detection independent of
//                                       this)
//   -rss_limit_mb=2048               → fail-fast on memory blowup
//   -print_final_stats=1             → emit summary table on exit
const args = [
  path.resolve(TARGET),
  CORPUS,
  // Keep instrumentation focused on our own source — vendor/, tests/,
  // node_modules/ are not the bug surface.
  //
  // NB: `includes` / `excludes` are SUBSTRING matches against the
  // filepath (see `Instrumentor.doesMatchFilters` in
  // @jazzer.js/instrumentor). A blanket `--excludes dist/` would
  // silently exclude the fuzz bundle written by
  // `tests/helpers/load-bundle.js::loadModulesAsRequire` (emitted at
  // `dist/fuzz-bundles/src/bundle-<hash>.js` so the `src/` include
  // matches it). That would leave the bundle uninstrumented and the
  // fuzzer blind. `node_modules/` already covers the only dist subtree
  // we actually want excluded (`dist/test-deps/node_modules/`).
  '--includes', 'src/',
  '--excludes', 'vendor/',
  '--excludes', 'tests/',
  '--excludes', 'node_modules/',
  '--sync', 'false',
  // libFuzzer options below the `--`.
  '--',
  `-artifact_prefix=${CRASHES.endsWith(path.sep) ? CRASHES : CRASHES + path.sep}`,
  `-max_total_time=${TIME_SECONDS}`,
  '-timeout=10',
  '-rss_limit_mb=2048',
  '-print_final_stats=1',
];

const child = spawn(jazzerCli, args, {
  stdio: 'inherit',
  cwd: path.resolve(__dirname, '..', '..', '..'),  // repo root
  env: {
    ...process.env,
    // Signal to tests/fuzz/helpers/harness.js that we're about to run
    // under Jazzer so it should load src/ via `require()` instead of
    // `vm.runInContext`. The former triggers Jazzer's
    // `hookRequire`-based sancov instrumentation; the latter bypasses
    // it and reduces coverage-guided fuzzing to a blind random mutator.
    LOUPE_FUZZ_JAZZER: '1',
  },
});

child.on('exit', (code, signal) => {
  // libFuzzer exit codes:
  //   0    clean shutdown (max_total_time reached, no findings)
  //   77   bug detector / crash found (Jazzer.js convention)
  //   78   unexpected error
  //   other → propagate as-is
  if (signal) {
    console.error(`jazzer: target ${TARGET_ID} terminated by signal ${signal}`);
    process.exit(1);
  }
  process.exit(code === null ? 1 : code);
});

child.on('error', (err) => {
  console.error(`jazzer: spawn failed: ${err.message}`);
  process.exit(2);
});
