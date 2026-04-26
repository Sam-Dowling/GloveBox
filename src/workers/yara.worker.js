'use strict';
// ════════════════════════════════════════════════════════════════════════════
// yara.worker.js — YARA scan worker
//
// Pure WorkerGlobalScope module: no DOM, no `window`, no `app.*` references.
// The worker runs `YaraEngine.parseRules` + `YaraEngine.scan` off the main
// thread so a 100 MiB scan no longer freezes the UI.
//
// Build-time inlining
// -------------------
// `scripts/build.py` reads `src/yara-engine.js` and this file in order,
// concatenates them, and emits the result as a JS template-literal constant
// `__YARA_WORKER_BUNDLE_SRC` injected at the top of the application script
// block. `src/worker-manager.js` is the only sanctioned spawn site:
//
//   const blob = new Blob([__YARA_WORKER_BUNDLE_SRC], { type: 'text/javascript' });
//   const url  = URL.createObjectURL(blob);
//   const w    = new Worker(url);          // CSP allows `worker-src blob:`
//   URL.revokeObjectURL(url);              // safe: Worker keeps its own ref
//
// postMessage protocol
// --------------------
//   in:  { buffer: ArrayBuffer (transferred), source: string }
//   out: { event: 'done',  results: [...], parseMs: N, scanMs: N }
//        { event: 'error', message: string }
//
// The buffer is **transferred** (caller loses access). Callers that need
// the bytes again — every site does, since the load pipeline keeps
// reading `this.currentResult.buffer` after auto-YARA — pass a
// `buffer.slice(0)` copy so the original survives. See
// `src/worker-manager.js::runYara`.
//
// Failure surface
// ---------------
// Parse errors and scan exceptions both come back as `{event: 'error'}`.
// The host (`src/app/app-yara.js::_autoYaraScan`) routes both through
// `App._reportNonFatal('auto-yara', err)`, which emits a single sidebar
// `IOC.INFO` row plus a console breadcrumb. The worker never throws —
// every path posts exactly one terminal event then exits.
//
// CSP note
// --------
// Workers run in `WorkerGlobalScope` and inherit the host CSP, so
// `default-src 'none'` continues to deny network access from inside the
// worker. The host ↔ worker boundary is `postMessage` only.
// ════════════════════════════════════════════════════════════════════════════

self.onmessage = function (ev) {
  const msg = ev && ev.data ? ev.data : {};
  const buffer = msg.buffer;
  const source = msg.source || '';

  try {
    if (typeof YaraEngine === 'undefined') {
      self.postMessage({ event: 'error', message: 'YaraEngine missing from worker bundle' });
      return;
    }
    if (!buffer) {
      self.postMessage({ event: 'error', message: 'no buffer transferred to worker' });
      return;
    }

    const t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    const parsed = YaraEngine.parseRules(source);
    const rules  = (parsed && parsed.rules)  || [];
    const errs   = (parsed && parsed.errors) || [];
    const t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

    if (errs.length && !rules.length) {
      // Total parse failure — host treats this as a scan error.
      self.postMessage({ event: 'error', message: 'parse: ' + errs.join('; ') });
      return;
    }

    const scanErrors = [];
    const results = YaraEngine.scan(buffer, rules, { errors: scanErrors });
    const t2 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

    self.postMessage({
      event:   'done',
      results: results || [],
      scanErrors,
      parseMs: Math.max(0, t1 - t0),
      scanMs:  Math.max(0, t2 - t1),
      ruleCount: rules.length,
    });
  } catch (e) {
    const message = (e && e.message) ? e.message : String(e);
    self.postMessage({ event: 'error', message });
  }
};
