'use strict';
// ════════════════════════════════════════════════════════════════════════════
// strings.worker.js — Binary-string extractor worker (PLAN C4)
//
// Pure WorkerGlobalScope module: no DOM, no `window`, no `app.*` references.
// The worker runs `extractAsciiAndUtf16leStrings()` off the main thread so
// large binary samples (PE / ELF / Mach-O / DMG) no longer freeze the UI
// while their printable-string corpora are mined for IOCs and BinaryStrings
// classifications (mutex / pipe / PDB / registry / Rust panic).
//
// Build-time inlining
// -------------------
// `scripts/build.py` reads `src/workers/strings-worker-shim.js` (which
// carries a copy of `extractAsciiAndUtf16leStrings`) and this file in
// order, concatenates them, and emits the result as a JS template-literal
// constant `__STRINGS_WORKER_BUNDLE_SRC` injected at the top of the
// application script block. `src/worker-manager.js::runStrings` is the
// only sanctioned spawn site:
//
//   const blob = new Blob([__STRINGS_WORKER_BUNDLE_SRC], { type: 'text/javascript' });
//   const url  = URL.createObjectURL(blob);
//   const w    = new Worker(url);          // CSP allows `worker-src blob:`
//   URL.revokeObjectURL(url);              // safe: Worker keeps its own ref
//
// postMessage protocol
// --------------------
//   in:  { buffer: ArrayBuffer (transferred), opts?: {
//             start?, end?, asciiMin?, utf16Min?, cap?
//          } }
//   out: { event: 'done',  ascii: string[], utf16: string[],
//          asciiCount: N, utf16Count: N, parseMs: N }
//        { event: 'error', message: string }
//
// The buffer is **transferred** (caller loses access). Callers that need
// the bytes again — every site does today, since the load pipeline keeps
// reading `_fileBuffer` after string extraction — pass a `buffer.slice(0)`
// copy so the original survives. See `src/worker-manager.js::runStrings`.
//
// Failure surface
// ---------------
// Extraction exceptions come back as `{event: 'error'}`. The host
// (`BinaryStrings.extractStringsAsync` / `DmgRenderer._scanStringsAsync`)
// treats both worker-unavailable rejection and a worker error the same
// way: fall back to the synchronous `extractAsciiAndUtf16leStrings()`
// already inlined into the main bundle. The worker never throws — every
// path posts exactly one terminal event then exits.
//
// Caps + budget
// -------------
// We post the full `{ascii, utf16}` arrays back as a single terminal
// message. The default `cap: 10000` total strings keeps the cross-thread
// payload bounded (a 10K-string scan is ≤ ~1 MB after JSON serialisation
// — postMessage uses structured-clone which is faster but the upper bound
// is the same order of magnitude). DMG passes `cap: 20000` for thorough
// `.app` harvesting; the structured-clone cost is still well under one
// frame for a real DMG.
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
  const opts = msg.opts || {};

  try {
    if (typeof extractAsciiAndUtf16leStrings !== 'function') {
      self.postMessage({ event: 'error', message: 'extractAsciiAndUtf16leStrings missing from worker bundle' });
      return;
    }
    if (!buffer) {
      self.postMessage({ event: 'error', message: 'no buffer transferred to worker' });
      return;
    }

    const t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    const bytes = new Uint8Array(buffer);
    const out = extractAsciiAndUtf16leStrings(bytes, opts) || { ascii: [], utf16: [] };
    const t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

    const ascii = Array.isArray(out.ascii) ? out.ascii : [];
    const utf16 = Array.isArray(out.utf16) ? out.utf16 : [];

    self.postMessage({
      event:      'done',
      ascii,
      utf16,
      asciiCount: ascii.length,
      utf16Count: utf16.length,
      parseMs:    Math.max(0, t1 - t0),
    });
  } catch (e) {
    const message = (e && e.message) ? e.message : String(e);
    self.postMessage({ event: 'error', message });
  }
};
