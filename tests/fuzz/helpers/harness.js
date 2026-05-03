'use strict';
// ════════════════════════════════════════════════════════════════════════════
// harness.js — shared fuzz-target scaffolding for Loupe.
//
// Loupe's unit tests already use `tests/helpers/load-bundle.js` to evaluate
// the minimal subset of `src/` files for a target inside a fresh
// `vm.Context`. The fuzz harness reuses that infrastructure verbatim — every
// fuzz target loads the same way a unit test would, gets the same vm sandbox,
// and the same throwIfAborted / TextEncoder / atob shims.
//
// Two modes:
//
//   1. Coverage-guided fuzzing under Jazzer.js (`@jazzer.js/core`). Targets
//      export a `fuzz(data: Buffer)` function; Jazzer.js drives mutation,
//      sancov-instruments the loaded source via require-time hooks, and
//      handles libFuzzer-format corpus / crash dirs on its own.
//
//   2. Standalone "replay" mode — the same `fuzz()` callback is invoked
//      against a deterministic seed corpus + a small bytewise mutator.
//      Used for unit-style regression tests and the `--reproduce <crash>`
//      CLI; runs without Jazzer.js installed so first-time invocation
//      doesn't require the npm provision step.
//
// Targets call `defineFuzzTarget({ modules, expose, onIteration })`. The
// harness owns the vm context and the crash-dedup pipeline so individual
// target files stay tiny — typically 30-80 lines each.
//
// IMPORTANT — `vm.Context` lifetime:
//   • One context PER target module load. We do NOT share contexts across
//     different targets in the same process — Jazzer.js spawns the worker
//     per-target anyway, and reusing contexts across targets would defeat
//     the renderer-isolation invariant.
//   • Within one target, the SAME context is reused across iterations.
//     This matches the production renderer model (renderers run on the
//     same window across many drops) and amortises the ~100 ms loadModules
//     cost across hundreds of thousands of fuzz iterations.
// ════════════════════════════════════════════════════════════════════════════

const path = require('node:path');
const { performance } = require('node:perf_hooks');

const HELPERS_DIR = __dirname;
const FUZZ_DIR = path.dirname(HELPERS_DIR);
const REPO_ROOT = path.resolve(FUZZ_DIR, '..', '..');

// We deliberately reuse the unit-test bundle loader. Any divergence
// between fuzzing semantics and unit-test semantics would be a footgun
// — a crash a fuzzer finds must reproduce as a unit test.
const { loadModules, loadModulesWithManifest, loadModulesAsRequire } = require(path.join(REPO_ROOT, 'tests', 'helpers', 'load-bundle.js'));
const { hashStack, normaliseError } = require('./crash-dedup.js');

const fs = require('node:fs');

// ── Under-Jazzer detection ──────────────────────────────────────────────────
// `tests/fuzz/helpers/jazzer-bootstrap.js` sets `LOUPE_FUZZ_JAZZER=1`
// before spawning Jazzer's CLI (Jazzer itself doesn't set a process env
// we can sniff). When that flag is live we must load the bundle via
// `loadModulesAsRequire` so Jazzer's `hookRequire`-based sancov
// instrumentation fires — `vm.runInContext` silently bypasses the hook,
// which is the footgun-of-record that kept coverage-guided fuzzing
// running as a blind random mutator (`corp: 1/1b`, `new_units_added: 0`)
// on every obfuscation / binary / text target until this fix landed.
const UNDER_JAZZER = process.env.LOUPE_FUZZ_JAZZER === '1';

// ── Coverage manifest sidecar ───────────────────────────────────────────────
// When `scripts/run_fuzz.py` runs targets under V8 source coverage, it
// sets `LOUPE_FUZZ_COVERAGE_DIR` to a per-target directory. The harness
// uses `loadModulesWithManifest` instead of `loadModules` and writes a
// `manifest.json` next to V8's per-process coverage dumps so the
// orchestrator can attribute coverage ranges back to individual
// `src/<file>.js` paths after the run completes. Outside coverage runs
// the variable is unset and the harness pays nothing for the feature.
const COVERAGE_DIR = process.env.LOUPE_FUZZ_COVERAGE_DIR || '';

function _coverageBundleFilename() {
  // Stable URL-shaped identifier so V8's coverage JSON `url` field
  // exactly matches the manifest's `filename`. The target id, when
  // available via env (`scripts/run_fuzz.py` sets `LOUPE_FUZZ_TARGET_ID`),
  // makes per-target manifests easy to tell apart in a multi-target
  // accumulated dump.
  const tid = process.env.LOUPE_FUZZ_TARGET_ID || 'unknown';
  return `loupe-fuzz-bundle://${tid}`;
}

// ── Per-iteration timing budget ─────────────────────────────────────────────
// Jazzer.js's libFuzzer integration kills slow units at a configurable
// threshold (default 10 s). For Loupe targets we want a tighter envelope
// so we surface ReDoS / catastrophic backtracking long before the kill
// threshold — anything over PARSER_LIMITS.FINDER_BUDGET_MS (2 500 ms) is
// almost certainly a budget-violation bug, not a slow but legitimate path.
//
// `safeRegex` already enforces ~250 ms per regex; `RENDERER_TIMEOUT_MS` is
// 30 s. Pick a middle value that catches per-call regressions without
// flagging every legitimately-large input.
const DEFAULT_PER_ITER_BUDGET_MS = 2_500;

// ── Per-iteration max input size ────────────────────────────────────────────
// Mirror PARSER_LIMITS.FINDER_MAX_INPUT_BYTES (4 MiB) for text targets.
// Binary parsers override this per-target via `maxBytes`.
const DEFAULT_MAX_BYTES = 4 * 1024 * 1024;

/**
 * Build a fuzz target from a declarative config.
 *
 * @param {object} cfg
 * @param {string[]} cfg.modules
 *   `src/`-relative paths to load into the vm.Context (same shape as
 *   `loadModules()` accepts).
 * @param {string[]} [cfg.expose]
 *   Override the default symbol expose list. Most targets can use the
 *   default — only specify if you need to surface a non-`window.*`
 *   binding the default expose list doesn't already cover.
 * @param {object}  [cfg.shims]
 *   Extra sandbox globals merged before evaluation (rare).
 * @param {(ctx: object, data: Buffer) => void | Promise<void>} cfg.onIteration
 *   The body of one fuzz iteration. Receives the vm sandbox (`ctx`) and
 *   the mutated input bytes. Should call into the target function and
 *   throw on any invariant violation. May be async.
 * @param {number} [cfg.perIterBudgetMs]
 *   Wall-clock cap per iteration. Defaults to 2 500 ms.
 * @param {number} [cfg.maxBytes]
 *   Truncate inputs longer than this. Defaults to 4 MiB.
 * @param {(err: Error) => boolean} [cfg.isExpectedError]
 *   Predicate to classify thrown errors as "expected aborts" rather than
 *   crashes. The watchdog timeout (`_watchdogTimeout=true`) is always
 *   considered expected. Use this to whitelist e.g.
 *   `err.message.startsWith('parser-limit:')`.
 * @returns {(data: Buffer) => Promise<void>}
 *   The Jazzer.js-compatible fuzz function.
 */
function defineFuzzTarget(cfg) {
  if (!cfg || typeof cfg !== 'object') {
    throw new TypeError('defineFuzzTarget: config object required');
  }
  if (!Array.isArray(cfg.modules) || cfg.modules.length === 0) {
    throw new TypeError('defineFuzzTarget: cfg.modules must be a non-empty array');
  }
  if (typeof cfg.onIteration !== 'function') {
    throw new TypeError('defineFuzzTarget: cfg.onIteration must be a function');
  }

  const perIterBudgetMs = (typeof cfg.perIterBudgetMs === 'number'
    && cfg.perIterBudgetMs > 0)
    ? cfg.perIterBudgetMs
    : DEFAULT_PER_ITER_BUDGET_MS;
  const maxBytes = (typeof cfg.maxBytes === 'number' && cfg.maxBytes > 0)
    ? cfg.maxBytes
    : DEFAULT_MAX_BYTES;
  const isExpectedError = typeof cfg.isExpectedError === 'function'
    ? cfg.isExpectedError
    : null;

  // Lazy context init — the first iteration pays the loadModules cost.
  // Jazzer.js's harness invokes the fuzz function immediately, but the
  // standalone replay path also does, so we pay once either way.
  let ctx = null;
  function ensureCtx() {
    if (ctx === null) {
      if (UNDER_JAZZER) {
        // Coverage-guided mode — go through require() so Jazzer's
        // `hookRequire` sancov-instrumentation fires on every src/
        // file. The emitted bundle lives under dist/fuzz-bundles/src/
        // (the `src/` segment is deliberate — Jazzer's `--includes
        // src/` filter is a plain substring match on the filepath).
        const { sandbox } = loadModulesAsRequire(cfg.modules, {
          expose: cfg.expose,
          shims: cfg.shims,
        });
        // Under Jazzer we don't write a coverage manifest — V8
        // source-coverage isn't the signal here; the sancov edges are.
        ctx = sandbox;
      } else if (COVERAGE_DIR) {
        // Coverage run — record the bundle's char-offset → src/<file>.js
        // map alongside the V8 coverage dumps. Done once per process;
        // re-writing on subsequent calls would be redundant since the
        // bundle layout is identical for the lifetime of the process.
        const filename = _coverageBundleFilename();
        const { sandbox, manifest } = loadModulesWithManifest(cfg.modules, {
          expose: cfg.expose,
          shims: cfg.shims,
          filename,
        });
        try {
          fs.mkdirSync(COVERAGE_DIR, { recursive: true });
          // Suffix with the parent process pid + a high-res timestamp so
          // multiple processes (e.g. Jazzer.js worker fan-out) each
          // contribute a manifest without races. The orchestrator
          // tolerates duplicates — they describe the same bundle layout.
          const stamp = `${process.pid}-${Date.now().toString(36)}`;
          const fp = path.join(COVERAGE_DIR, `manifest-${stamp}.json`);
          fs.writeFileSync(fp, JSON.stringify(manifest));
        } catch (err) {
          // Coverage is opportunistic; a write failure here MUST NOT
          // break the fuzz run. Surface to stderr only.
          process.stderr.write(
            `harness: failed to write coverage manifest: ${err.message}\n`,
          );
        }
        ctx = sandbox;
      } else {
        ctx = loadModules(cfg.modules, {
          expose: cfg.expose,
          shims: cfg.shims,
        });
      }
    }
    return ctx;
  }

  async function fuzz(data) {
    // Jazzer.js feeds us a `Buffer`; the standalone replay path can pass
    // either Buffer or Uint8Array. Normalise.
    if (!Buffer.isBuffer(data)) {
      if (data instanceof Uint8Array) data = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
      else data = Buffer.from(data);
    }
    if (data.length > maxBytes) {
      data = data.subarray(0, maxBytes);
    }

    const sandbox = ensureCtx();
    const t0 = performance.now();
    try {
      await cfg.onIteration(sandbox, data);
    } catch (err) {
      // Normalise + classify. Watchdog timeouts and explicitly-expected
      // errors are NOT reported as crashes — they're the documented abort
      // path of the renderer / parser under test.
      const norm = normaliseError(err);
      if (norm._watchdogTimeout) return;
      if (isExpectedError && isExpectedError(err)) return;
      // Re-throw unchanged so Jazzer.js's bug-detection hooks see the
      // original error shape (it inspects `err.code`, `err.message`).
      // We attach a pre-computed stack hash so downstream tooling
      // (`scripts/fuzz_promote.py`) can dedup without re-parsing.
      try {
        Object.defineProperty(err, '_loupeFuzzStackHash', {
          value: hashStack(err),
          enumerable: false,
          configurable: true,
        });
      } catch (_) { /* frozen err — non-fatal */ }
      throw err;
    } finally {
      const dt = performance.now() - t0;
      if (dt > perIterBudgetMs) {
        // Slow path — surface as a hard failure. A renderer that runs
        // 5× longer than the documented finder budget is a ReDoS bug
        // even if it eventually returns successfully.
        const slow = new Error(
          `fuzz: iteration exceeded budget — ${dt.toFixed(0)}ms > `
          + `${perIterBudgetMs}ms (input ${data.length} bytes)`,
        );
        slow.code = 'LOUPE_FUZZ_BUDGET_EXCEEDED';
        slow._loupeFuzzInputLen = data.length;
        slow._loupeFuzzWallMs = dt;
        throw slow;
      }
    }
  }

  // Expose the underlying loaded sandbox so the standalone replay tool
  // can introspect (e.g. dump IOC.* keys to verify expose worked).
  fuzz._loadContext = () => ensureCtx();
  fuzz._config = cfg;
  return fuzz;
}

// ── Tiny deterministic mutator (replay-mode only) ──────────────────────────
// When Jazzer.js isn't installed (first invocation, --reproduce, or
// regression tests), `runReplay()` walks a seed corpus and applies a
// handful of byte-level mutations per seed. This is intentionally NOT a
// real coverage-guided fuzzer — Jazzer.js is the production engine. The
// replay mutator exists to:
//   1. smoke the harness without npm-installing anything
//   2. drive `tests/unit/<target>-fuzz-regress-*.test.js` reproducers
//   3. quick local sanity check ("does my new target even compile?")
function makeReplayMutator(seed) {
  // Tiny xorshift32 PRNG — deterministic per seed; no Math.random.
  let s = (seed | 0) || 0xC0FFEE;
  return {
    next() { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return s >>> 0; },
    int(n) { return this.next() % n; },
  };
}

const REPLAY_OPS = [
  function bitFlip(buf, rng) {
    if (buf.length === 0) return buf;
    const i = rng.int(buf.length);
    const out = Buffer.from(buf);
    out[i] ^= 1 << rng.int(8);
    return out;
  },
  function byteFlip(buf, rng) {
    if (buf.length === 0) return buf;
    const i = rng.int(buf.length);
    const out = Buffer.from(buf);
    out[i] = rng.int(256);
    return out;
  },
  function insertByte(buf, rng) {
    const i = rng.int(buf.length + 1);
    const v = rng.int(256);
    return Buffer.concat([buf.subarray(0, i), Buffer.from([v]), buf.subarray(i)]);
  },
  function deleteByte(buf, rng) {
    if (buf.length <= 1) return buf;
    const i = rng.int(buf.length);
    return Buffer.concat([buf.subarray(0, i), buf.subarray(i + 1)]);
  },
  function duplicateRun(buf, rng) {
    if (buf.length === 0) return buf;
    const i = rng.int(buf.length);
    const len = 1 + rng.int(Math.min(64, buf.length - i));
    const run = buf.subarray(i, i + len);
    return Buffer.concat([buf.subarray(0, i), run, buf.subarray(i)]);
  },
  function zeroRun(buf, rng) {
    if (buf.length === 0) return buf;
    const i = rng.int(buf.length);
    const len = 1 + rng.int(Math.min(32, buf.length - i));
    const out = Buffer.from(buf);
    out.fill(0, i, i + len);
    return out;
  },
  function spliceCorpus(buf, rng, otherSeeds) {
    if (otherSeeds.length === 0) return buf;
    const o = otherSeeds[rng.int(otherSeeds.length)];
    if (o.length === 0) return buf;
    const cut = rng.int(buf.length + 1);
    const take = 1 + rng.int(Math.min(256, o.length));
    const start = rng.int(o.length - take + 1);
    return Buffer.concat([
      buf.subarray(0, cut),
      o.subarray(start, start + take),
      buf.subarray(cut),
    ]);
  },
];

/**
 * Replay-mode runner — drive the fuzz target across a seed corpus with
 * a deterministic mutator. Returns the count of iterations executed plus
 * any first-failure crash hash. Does NOT swallow errors — propagates the
 * first failure so callers can decide whether to dump artefacts or rethrow.
 *
 * @param {(data: Buffer) => Promise<void>} fuzz  the fuzz function
 * @param {Buffer[]} seeds  seed inputs (will be cloned, not retained)
 * @param {object}   [opts]
 * @param {number}   [opts.iterations=200]   per-seed mutation iterations
 * @param {number}   [opts.seed=42]          PRNG seed
 * @param {boolean}  [opts.continueOnError=false]  collect all failures
 *                                                 instead of stopping
 * @param {(progress) => void} [opts.onProgress]   per-N progress hook
 * @returns {Promise<{iterations:number, failures:Array}>}
 */
async function runReplay(fuzz, seeds, opts) {
  const o = opts || {};
  const iterations = (typeof o.iterations === 'number' && o.iterations > 0)
    ? o.iterations : 200;
  const rng = makeReplayMutator(typeof o.seed === 'number' ? o.seed : 42);
  const continueOnError = !!o.continueOnError;
  const onProgress = typeof o.onProgress === 'function' ? o.onProgress : null;
  const failures = [];
  let count = 0;

  // First pass: every seed unmodified. Any crash on a seed is a real bug.
  for (const seed of seeds) {
    count++;
    try { await fuzz(seed); }
    catch (err) {
      const f = { kind: 'seed', input: seed, err };
      failures.push(f);
      if (!continueOnError) return { iterations: count, failures };
    }
    if (onProgress && (count & 0x3F) === 0) onProgress({ count, failures: failures.length });
  }

  // Second pass: mutate.
  for (let i = 0; i < iterations; i++) {
    for (const seed of seeds) {
      count++;
      let buf = Buffer.from(seed);
      const opCount = 1 + rng.int(3);
      for (let j = 0; j < opCount; j++) {
        const op = REPLAY_OPS[rng.int(REPLAY_OPS.length)];
        buf = op(buf, rng, seeds);
      }
      try { await fuzz(buf); }
      catch (err) {
        const f = { kind: 'mutation', input: buf, err };
        failures.push(f);
        if (!continueOnError) return { iterations: count, failures };
      }
      if (onProgress && (count & 0x3F) === 0) onProgress({ count, failures: failures.length });
    }
  }

  return { iterations: count, failures };
}

module.exports = {
  defineFuzzTarget,
  runReplay,
  REPO_ROOT,
  FUZZ_DIR,
  DEFAULT_PER_ITER_BUDGET_MS,
  DEFAULT_MAX_BYTES,
};
