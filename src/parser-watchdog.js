'use strict';
// ════════════════════════════════════════════════════════════════════════════
// parser-watchdog.js — Timeout guard for parser invocations
//
// Wraps a sync or async function with a configurable deadline. If the
// function hangs (e.g. on a maliciously crafted file), the returned
// promise rejects after the timeout so the UI can recover.
//
// Two callers today:
//   • `_loadFile` reads `file.arrayBuffer()` under the default
//     `PARSER_LIMITS.TIMEOUT_MS` (60 s) buffer-read cap.
//   • `RenderRoute.run` wraps the per-renderer dispatch handler under
//     `PARSER_LIMITS.RENDERER_TIMEOUT_MS` (30 s) with a graceful
//     `PlainTextRenderer` fallback when a renderer hangs on a hostile
//     file.
//
// On timeout, the rejected error carries three sentinel fields so callers
// can distinguish a watchdog kill from a genuine parser exception and
// react (e.g. swap to a fallback renderer) instead of bubbling to the
// generic "Failed to open file" error box:
//   err._watchdogTimeout    = true
//   err._watchdogName       = <name from opts, or null>
//   err._watchdogTimeoutMs  = <effective timeout in ms>
//
// AbortSignal plumbing
// --------------------
// The watchdog owns an `AbortController` per call. The signal is handed
// to `fn` as `fn({ signal })` so signal-aware renderers can poll
// `signal.aborted` between chunks/rows and bail early. On timeout the
// controller is `abort()`-ed *before* the watchdog rejects, so any
// downstream `fetch`-shaped consumer wired to the signal also short-circuits.
//
// Renderer-side polling uses `throwIfAborted()` from `constants.js`, which
// reads `ParserWatchdog._activeSignal` — a per-process slot that
// `RenderRoute.run` sets to the active signal for the duration of the
// per-renderer dispatch and restores in `.finally()`. Storing the signal on
// a shared slot means renderers don't have to thread `{ signal }` through
// every helper call to be cancellation-aware: a single one-line poll inside
// any chunk / row / section loop is enough. The slot is `null` outside of a
// dispatch (manual YARA tab, sidebar drill-downs, early bootstrap), so
// `throwIfAborted()` is a contractual no-op there.
// ════════════════════════════════════════════════════════════════════════════

const ParserWatchdog = {

  // The currently-active `AbortSignal`, if any. Set by `RenderRoute.run`
  // around the per-renderer dispatch and restored to its previous value
  // in `.finally()` (so nested invocations — though unused today — would
  // still unwind cleanly). Read by `throwIfAborted()` in `constants.js`.
  // `null` means no enforced deadline is in flight; renderer polls become
  // no-ops in that case.
  _activeSignal: null,


  /**
   * Run a function with a timeout guard.
   *
   * @param {Function} fn      — sync or async function. Invoked with one
   *                             argument: `{ signal }` where `signal` is
   *                             an `AbortSignal` aborted on timeout. Args-
   *                             ignoring `() => …` callbacks remain valid.
   * @param {Object}  [opts]
   * @param {number}  [opts.timeout]   timeout in ms; defaults to
   *                                   `PARSER_LIMITS.TIMEOUT_MS` (60 s)
   * @param {string}  [opts.name]      label echoed in the timeout error
   *                                   message and on `err._watchdogName`
   *                                   so callers can branch on which
   *                                   renderer / phase tripped.
   * @param {boolean} [opts.skipOuter] when true, this call is a no-op
   *                                   race and just `await`s `fn()`
   *                                   directly. Reserved plumbing for a
   *                                   future renderer-side opt-in to a
   *                                   self-managed deadline; not invoked
   *                                   today.
   * @returns {Promise<*>}     resolves with fn's return value or rejects
   *                           on timeout.
   */
  run(fn, opts) {
    const o = opts || {};
    const timeout = o.timeout || (typeof PARSER_LIMITS !== 'undefined' ? PARSER_LIMITS.TIMEOUT_MS : 60000);
    const name = o.name || null;

    // Per-call AbortController. Always created (even on the skipOuter
    // path) so the renderer-side contract is uniform: every invocation
    // sees a `{ signal }` arg, regardless of whether a deadline is
    // actually being enforced from this layer.
    const controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    const signal     = controller ? controller.signal : null;

    // skipOuter — caller has already arranged its own deadline; just run
    // fn and surface its result/exception verbatim.
    if (o.skipOuter) {
      return Promise.resolve().then(() => fn({ signal }));
    }

    return new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          // Abort *before* rejecting so any signal-aware renderer code
          // that races between the timer firing and the reject landing
          // sees `signal.aborted === true` and bails instead of writing.
          if (controller) {
            try { controller.abort(); } catch (_) { /* best-effort */ }
          }
          const where = name ? ` (${name})` : '';
          const err = new Error(`Parser timed out after ${(timeout / 1000).toFixed(0)}s${where} — file may be malicious or too complex.`);
          err._watchdogTimeout   = true;
          err._watchdogName      = name;
          err._watchdogTimeoutMs = timeout;
          reject(err);
        }
      }, timeout);

      try {
        const result = fn({ signal });
        if (result && typeof result.then === 'function') {
          // Async path
          result.then(
            v => { if (!settled) { settled = true; clearTimeout(timer); resolve(v); } },
            e => { if (!settled) { settled = true; clearTimeout(timer); reject(e); } }
          );
        } else {
          // Sync path
          if (!settled) { settled = true; clearTimeout(timer); resolve(result); }
        }
      } catch (e) {
        if (!settled) { settled = true; clearTimeout(timer); reject(e); }
      }
    });
  },
};
