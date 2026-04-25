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
// ════════════════════════════════════════════════════════════════════════════

const ParserWatchdog = {

  /**
   * Run a function with a timeout guard.
   *
   * @param {Function} fn      — sync or async function to execute
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

    // skipOuter — caller has already arranged its own deadline; just run
    // fn and surface its result/exception verbatim.
    if (o.skipOuter) {
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
