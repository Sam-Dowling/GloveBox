'use strict';
// ════════════════════════════════════════════════════════════════════════════
// worker-manager.test.js — pin the lifecycle / cancellation / timeout
// contract of `WorkerManager`.
//
// `WorkerManager` is the **only** sanctioned home for `new Worker(...)`
// outside `src/workers/*.worker.js` (build gate
// `_check_worker_spawn_allowlist`). Its contract is dense and the
// regressions are subtle — see the comment at the top of
// `src/worker-manager.js` plus the pain-points in `AGENTS.md` (`58b6778`
// stale-onmessage, `b00ada6` worker-shim parity, `97fffb2` row-store-in-
// both-bundles).
//
// What this file pins
// -------------------
//   1. `_probe()` runs once and caches its result; callers see
//      `Error('workers-unavailable')` permanently after a first failure.
//   2. `runYara` resolves on `{event:'done'}` and decodes the payload
//      shape documented in the wrapper jsdoc.
//   3. A second `runYara` call **supersedes** the first — the first
//      promise rejects with `Error('superseded')`, and the prior
//      worker is `terminate()`-d synchronously (so the captured payload
//      reference is released, not pinned for the full timeout window).
//   4. `cancelYara()` rejects any in-flight job with
//      `Error('superseded')` and is idempotent when nothing is in flight.
//   5. Stale `onmessage` / `onerror` from a terminated worker are
//      DROPPED — never resolved or rejected on the new caller's promise.
//      This is the canonical `58b6778` regression.
//   6. Timeout: a job that never posts `done` is `terminate()`-d and
//      rejected with a watchdog-shaped error carrying the sentinel
//      fields `_watchdogTimeout`, `_watchdogName`, `_watchdogTimeoutMs`
//      so `app-load.js` callers that already branch on
//      `err._watchdogTimeout` continue to work.
//   7. `runDecodedYara([])` short-circuits to a resolved empty result
//      WITHOUT spawning a worker (the empty-input optimisation).
//
// Mocking strategy
// ----------------
// `WorkerManager` is constructed at require-time with `new Worker(...)`,
// `URL.createObjectURL`, and `Blob`. We seed all three as sandbox shims
// before evaluating the module so the IIFE's `_probe()` can succeed on
// our terms. `FakeWorker` records every postMessage and exposes
// `_drive(msg)` / `_driveError(e)` for tests to fire onmessage / onerror
// at controlled points.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// Build a fresh sandbox with shimmed Worker/URL/Blob and the four worker
// bundle constants the module reads via `typeof __X !== 'undefined' ? X : ''`.
function makeManager(opts) {
  const o = opts || {};

  // Per-test registry of constructed FakeWorkers so tests can drive them.
  const constructed = [];
  // `o.workerCtor` lets a test inject a constructor that throws (probe
  // failure) or counts spawns differently.
  function FakeWorker(/* url */) {
    if (o.constructorThrows) throw new Error('Worker construction blocked');
    this._terminated = false;
    this._postMessages = [];
    this.onmessage = null;
    this.onerror = null;
    this.terminate = function () { this._terminated = true; };
    this.postMessage = function (msg, transfers) {
      this._postMessages.push({ msg, transfers });
    };
    constructed.push(this);
  }

  const shims = {
    // Module reads `typeof window` and assigns `window.WorkerManager = …`,
    // so the sandbox needs a fresh `window` object (load-bundle.js already
    // aliases sb.window = sb so global writes land on it).
    Worker: FakeWorker,
    Blob: function () {},
    URL: { createObjectURL: () => 'blob:fake', revokeObjectURL: () => {} },
    // Force the four worker-bundle constants to be defined as non-empty
    // strings — the module bails out of `_spawnFromBundle` with a
    // hard-coded error when `bundleSrc` is empty.
    __YARA_WORKER_BUNDLE_SRC: 'self.close();',
    __TIMELINE_WORKER_BUNDLE_SRC: 'self.close();',
    __ENCODED_WORKER_BUNDLE_SRC: 'self.close();',
    __IOC_EXTRACT_WORKER_BUNDLE_SRC: 'self.close();',
  };
  if (o.constructorThrows) {
    // Replace the Worker shim with one that throws on construction —
    // simulates a Firefox `file://` Worker(blob:) refusal.
    shims.Worker = function () { throw new Error('Worker construction blocked'); };
  }
  // Optional setTimeout override (used by the timeout test to fire the
  // 5-min watchdog under 5 ms).
  if (typeof o.setTimeout === 'function') shims.setTimeout = o.setTimeout;

  const ctx = loadModules(['src/constants.js', 'src/worker-manager.js'], {
    expose: ['WorkerManager', 'PARSER_LIMITS'],
    shims,
  });
  // Stash for tests to drive.
  ctx._constructedWorkers = constructed;
  return ctx;
}

// ── 1. Probe gating ────────────────────────────────────────────────────

test('_probe failure: every run* rejects with Error("workers-unavailable")', async () => {
  const ctx = makeManager({ constructorThrows: true });
  const buf = new ctx.ArrayBuffer(8);
  let rej = null;
  try { await ctx.WorkerManager.runYara(buf, 'rule x {condition: true}'); }
  catch (e) { rej = e; }
  assert.ok(rej, 'runYara must reject when probe fails');
  assert.equal(rej.message, 'workers-unavailable',
    'probe failure must surface as Error("workers-unavailable") — caller falls back to sync');
});

test('_probe is cached (one probe per session)', async () => {
  const ctx = makeManager({});
  // First call triggers probe + spawn; second triggers spawn only.
  // (The probe Worker is constructed first, then the real job Worker.)
  ctx.WorkerManager.runYara(new ctx.ArrayBuffer(8), 'rule x {condition: true}')
    .catch(() => {});
  const after1 = ctx._constructedWorkers.length;
  ctx.WorkerManager.runYara(new ctx.ArrayBuffer(8), 'rule y {condition: true}')
    .catch(() => {});
  const after2 = ctx._constructedWorkers.length;
  // Probe + 1 job worker = 2; second call is 1 more job worker (not 1 + probe).
  assert.equal(after1, 2, 'first call constructs probe + 1 job worker');
  // Second call may have superseded the first (one extra terminate) but
  // must NOT re-probe. Net: exactly 1 additional worker construction.
  assert.equal(after2, 3, 'second call must not re-probe — only 1 new worker');
  // Drain any in-flight workers so their 5-min watchdog timer is cleared
  // (otherwise the test process would stay alive for 5 min after this
  // test completes, even though all assertions have passed).
  ctx.WorkerManager.cancelYara();
});

// ── 2. Happy path: runYara resolves on {event:'done'} ──────────────────

test('runYara resolves with the decoded done payload', async () => {
  const ctx = makeManager({});
  const buf = new ctx.ArrayBuffer(16);
  const promise = ctx.WorkerManager.runYara(buf, 'rule x {condition: true}');
  // The job worker is the SECOND construction (probe is first).
  const jobWorker = ctx._constructedWorkers[1];
  assert.ok(jobWorker, 'a job worker must have been spawned');
  // Drive a `done` event.
  jobWorker.onmessage({ data: {
    event: 'done',
    results: [{ rule: 'x' }],
    scanErrors: [],
    parseMs: 1,
    scanMs: 2,
    ruleCount: 1,
  } });
  const result = await promise;
  assert.equal(result.results.length, 1);
  assert.equal(result.results[0].rule, 'x');
  assert.equal(result.parseMs, 1);
  assert.equal(result.scanMs, 2);
  assert.equal(result.ruleCount, 1);
  assert.equal(jobWorker._terminated, true,
    'worker must be terminate()-d on the resolved branch (no leak)');
});

// ── 3. Supersession via cancelYara() — production pattern ─────────────
//
// `_loadFile` ALWAYS calls `cancelYara()` before `runYara()` on a new
// load (`app-load.js:135`). Pinning that pattern is the high-value
// contract. (A back-to-back `runYara()` without an interleaved
// `cancelYara()` triggers a separate token-ordering quirk in
// `_runWorkerJob` that double-bumps the channel token; not exercised by
// any production caller and not pinned here.)

test('cancelYara() rejects in-flight runYara with Error("superseded")', async () => {
  const ctx = makeManager({});
  const buf = new ctx.ArrayBuffer(8);
  const p = ctx.WorkerManager.runYara(buf, 'rule x {condition: true}');
  const w = ctx._constructedWorkers[1];
  ctx.WorkerManager.cancelYara();
  let rej = null;
  try { await p; } catch (e) { rej = e; }
  assert.ok(rej, 'cancel must reject the in-flight promise');
  assert.equal(rej.message, 'superseded',
    'cancel must reject with Error("superseded") so callers bail silently');
  assert.equal(w._terminated, true,
    'cancel must terminate the worker (releases captured payload)');
});

test('after cancelYara(), the next runYara resolves cleanly (production pattern)', async () => {
  // This is the canonical _loadFile sequence: every new file load calls
  // `cancelYara()` then `runYara()`. The cancel-then-run path is the
  // ONLY supersession pattern that's exercised in production code, so
  // it's the only one we pin to a deterministic outcome.
  const ctx = makeManager({});
  const p1 = ctx.WorkerManager.runYara(new ctx.ArrayBuffer(8), 'rule a {condition: true}');
  const w1 = ctx._constructedWorkers[1];
  ctx.WorkerManager.cancelYara();
  let p1Rej = null;
  try { await p1; } catch (e) { p1Rej = e; }
  assert.equal(p1Rej.message, 'superseded');
  assert.equal(w1._terminated, true);

  // Now a fresh runYara — must spawn a new worker and resolve normally.
  const p2 = ctx.WorkerManager.runYara(new ctx.ArrayBuffer(8), 'rule b {condition: true}');
  const w2 = ctx._constructedWorkers[2];
  w2.onmessage({ data: {
    event: 'done', results: [{ rule: 'b' }],
    scanErrors: [], parseMs: 0, scanMs: 0, ruleCount: 1,
  } });
  const r = await p2;
  assert.equal(r.results[0].rule, 'b');
  assert.equal(w2._terminated, true);
});

// ── 4. cancelYara is idempotent ────────────────────────────────────────

test('cancelYara() is idempotent when nothing is in flight', () => {
  const ctx = makeManager({});
  // Must not throw on a virgin channel, before any run.
  ctx.WorkerManager.cancelYara();
  ctx.WorkerManager.cancelYara();
  ctx.WorkerManager.cancelYara();
});

// ── 4b. Back-to-back runYara without cancel (regression) ───────────────

test('back-to-back runYara() without cancelYara supersedes the first and resolves the second', async () => {
  // Regression for a token-ordering bug in `_runWorkerJob`: capturing
  // `myToken = ++ch.token` BEFORE the supersede block meant that
  // `prior.abort()` (which itself bumps `ch.token` to invalidate the
  // prior worker's racing onmessage) would race past the new job's
  // captured token. The new worker's own `onmessage` then saw
  // `myToken !== ch.token`, dropped its `done` payload, and the new
  // promise hung forever.
  //
  // Production code masked this by always doing `cancelYara()` →
  // `runYara()` (see `app-load.js:135`). Direct back-to-back
  // `runYara()` is the canary that exposes the bug; it must:
  //   (a) reject the first promise with `Error('superseded')`, AND
  //   (b) resolve the second promise normally when its worker fires
  //       `done`.
  const ctx = makeManager({});
  const p1 = ctx.WorkerManager.runYara(new ctx.ArrayBuffer(8), 'rule a {condition: true}');
  // Don't cancel — fire the second call directly. Index 1 is the first
  // job worker (index 0 is the probe worker).
  const p2 = ctx.WorkerManager.runYara(new ctx.ArrayBuffer(8), 'rule b {condition: true}');
  const w2 = ctx._constructedWorkers[2];

  // (a) The first promise is rejected as superseded.
  let p1Rej = null;
  try { await p1; } catch (e) { p1Rej = e; }
  assert.equal(p1Rej.message, 'superseded');

  // (b) Drive the second worker to done; the second promise must
  // resolve. Before the fix this hung indefinitely (test would
  // time out instead of completing in <1ms).
  w2.onmessage({ data: {
    event: 'done', results: [{ rule: 'b' }],
    scanErrors: [], parseMs: 0, scanMs: 0, ruleCount: 1,
  } });
  const r = await p2;
  assert.equal(r.results[0].rule, 'b');
  assert.equal(w2._terminated, true);
});

// ── 5. Stale onmessage from a cancelled worker is dropped (58b6778) ────

test('stale `done` from a cancelled worker does NOT bleed into a fresh runYara', async () => {
  const ctx = makeManager({});
  const p1 = ctx.WorkerManager.runYara(new ctx.ArrayBuffer(8), 'rule a {condition: true}');
  const w1 = ctx._constructedWorkers[1];
  ctx.WorkerManager.cancelYara();
  let p1Rej = null;
  try { await p1; } catch (e) { p1Rej = e; }
  assert.equal(p1Rej.message, 'superseded');

  // Start a fresh job AFTER the cancel.
  const p2 = ctx.WorkerManager.runYara(new ctx.ArrayBuffer(8), 'rule b {condition: true}');
  const w2 = ctx._constructedWorkers[2];

  // Now fire a stale `done` on w1 (terminated, but its onmessage closure
  // may still exist if held by a microtask). The stale-token guard must
  // drop it silently — never resolving p2.
  if (typeof w1.onmessage === 'function') {
    w1.onmessage({ data: {
      event: 'done',
      results: [{ rule: 'STALE' }],
      scanErrors: [], parseMs: 0, scanMs: 0, ruleCount: 0,
    } });
  }
  // Drive p2 with the legitimate fresh result.
  w2.onmessage({ data: {
    event: 'done',
    results: [{ rule: 'fresh' }],
    scanErrors: [], parseMs: 0, scanMs: 0, ruleCount: 1,
  } });
  const r = await p2;
  assert.equal(r.results.length, 1);
  assert.equal(r.results[0].rule, 'fresh',
    'stale onmessage from cancelled worker must NOT bleed into the fresh promise (58b6778)');
});

// ── 6. Worker-reported error rejects the promise ───────────────────────

test('runYara rejects with the worker-reported error message on {event:"error"}', async () => {
  const ctx = makeManager({});
  const p = ctx.WorkerManager.runYara(new ctx.ArrayBuffer(8), 'rule x {condition: true}');
  const w = ctx._constructedWorkers[1];
  w.onmessage({ data: { event: 'error', message: 'parse failed at line 42' } });
  let rej = null;
  try { await p; } catch (e) { rej = e; }
  assert.ok(rej);
  assert.equal(rej.message, 'parse failed at line 42');
  assert.equal(w._terminated, true,
    'worker must be terminated on the worker-reported-error branch');
});

// ── 7. Timeout: terminate + watchdog-shaped error ──────────────────────

test('worker timeout terminates the worker and rejects with watchdog sentinels', async () => {
  // The public wrapper doesn't expose `timeoutMs` and `PARSER_LIMITS`
  // is frozen, so we shim `setTimeout` to fire after 5 ms regardless of
  // the requested delay. The manager's timer callback path is still
  // exercised end-to-end (terminate + watchdog-shaped error).
  const ctx = makeManager({
    setTimeout: (fn /* , ms */) => globalThis.setTimeout(fn, 5),
  });
  const p = ctx.WorkerManager.runYara(new ctx.ArrayBuffer(8), 'rule x {condition: true}');
  const w = ctx._constructedWorkers[1];
  // Don't fire onmessage — let the timer fire instead.
  let rej = null;
  try { await p; } catch (e) { rej = e; }
  assert.ok(rej, 'timeout must reject');
  assert.equal(rej._watchdogTimeout, true,
    'timeout error must carry _watchdogTimeout=true (callers branch on this)');
  assert.equal(rej._watchdogName, 'yara');
  assert.equal(typeof rej._watchdogTimeoutMs, 'number');
  assert.match(rej.message, /timed out/i);
  assert.equal(w._terminated, true,
    'worker must be terminate()-d on timeout (real preemption)');
});

// ── 8. runDecodedYara empty-input short-circuit ────────────────────────

test('runDecodedYara([]) resolves to an empty result without spawning a worker', async () => {
  const ctx = makeManager({});
  const before = ctx._constructedWorkers.length;
  const r = await ctx.WorkerManager.runDecodedYara([], 'rule x {condition: true}');
  const after = ctx._constructedWorkers.length;
  assert.equal(after, before,
    'empty payloads must short-circuit BEFORE the probe — no worker spawned');
  assert.equal(r.hits.length, 0);
  assert.equal(r.payloadCount, 0);
  assert.equal(r.ruleCount, 0);
});
