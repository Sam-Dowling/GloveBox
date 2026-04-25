'use strict';
// ════════════════════════════════════════════════════════════════════════════
// parser-watchdog.js — Timeout guard for parser invocations
// Wraps sync or async parser calls with a configurable deadline.
// If a parser hangs (e.g. on a maliciously crafted file), the promise rejects
// after the timeout so the UI can recover.
//
// Two callers today:
//   • `_loadFile` reads `file.arrayBuffer()` under the default
//     `PARSER_LIMITS.TIMEOUT_MS` (60 s) buffer-read cap.
//   • `_loadFile` wraps the per-renderer dispatch handler under
//     `PARSER_LIMITS.RENDERER_TIMEOUT_MS` (30 s, PLAN B5) with a graceful
//     `PlainTextRenderer` fallback when a renderer hangs on a hostile file.
//
// On timeout, the rejected error carries three sentinel fields so callers can
// distinguish a watchdog kill from a genuine parser exception and react
// (e.g. swap to a fallback renderer) instead of bubbling to the generic
// "Failed to open file" error box:
//   err._watchdogTimeout    = true
//   err._watchdogName       = <name from opts, or null>
//   err._watchdogTimeoutMs  = <effective timeout in ms>
// ════════════════════════════════════════════════════════════════════════════

const ParserWatchdog = {

  /**
   * Run a function with a timeout guard.
   *
   * Back-compat: `msOrOpts` may be a bare number (legacy 1-arg / 2-arg form
   * `ParserWatchdog.run(fn)` / `ParserWatchdog.run(fn, 5000)`) or an options
   * object. Pre-PLAN-B5 call sites continue to work unchanged.
   *
   * @param {Function} fn        — sync or async function to execute
   * @param {number|Object} [msOrOpts]
   *        number — timeout in milliseconds
   *        object — { timeout?: number, name?: string, skipOuter?: boolean }
   *          • timeout   default `PARSER_LIMITS.TIMEOUT_MS` (60 s)
   *          • name      label echoed in the timeout error message and on
   *                      `err._watchdogName` so callers can branch on which
   *                      renderer / phase tripped
   *          • skipOuter forward-compat plumbing for renderers that opt in
   *                      to running their own watchdog: when true, this call
   *                      is a no-op race and just `await`s `fn()` directly.
   *                      Reserved for future use; not invoked today.
   * @returns {Promise<*>}       — resolves with fn's return value or rejects on timeout
   */
  run(fn, msOrOpts) {
    const opts = (msOrOpts !== null && typeof msOrOpts === 'object')
      ? msOrOpts
      : { timeout: msOrOpts };
    const timeout = opts.timeout || (typeof PARSER_LIMITS !== 'undefined' ? PARSER_LIMITS.TIMEOUT_MS : 60000);
    const name = opts.name || null;

    // skipOuter — caller has already arranged its own deadline; just run fn
    // and surface its result/exception verbatim. Reserved plumbing for the
    // renderer-side watchdog opt-in introduced by PLAN B5.
    if (opts.skipOuter) {
      return Promise.resolve().then(fn);
    }

    return new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          const where = name ? ` (${name})` : '';
          const err = new Error(`Parser timed out after ${(timeout / 1000).toFixed(0)}s${where} — file may be malicious or too complex.`);
          err._watchdogTimeout   = true;
          err._watchdogName      = name;
          err._watchdogTimeoutMs = timeout;
          reject(err);
        }
      }, timeout);

      try {
        const result = fn();
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
