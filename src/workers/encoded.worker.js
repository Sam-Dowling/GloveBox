'use strict';
// ════════════════════════════════════════════════════════════════════════════
// encoded.worker.js — EncodedContentDetector parse-only worker (PLAN C3)
//
// Pure WorkerGlobalScope module: no DOM, no `window`, no `app.*` references.
// Runs the 2,114-line `EncodedContentDetector.scan()` recursion off the main
// thread so multi-megabyte text payloads (huge PowerShell drops, big VBA
// Auto_Open() macros, fat HTML reports) no longer freeze the analyser for
// seconds while the detector chases nested base64 / hex / zlib / chararray
// chains.
//
// Scope = scan + lazyDecode only. **No analysis, no IOC merging.**
// ────────────────────────────────────────────────────────────────────────────
// The host `app-load.js` post-scan loop still owns:
//   • merging `finding.iocs` rows into `findings.interestingStrings`
//   • stamping `_sourceOffset`, `_highlightText`, `_decodedFrom`,
//     `_encodedFinding` back-references on each merged IOC (those touch
//     `analysisText` and the existing IOC list, which the worker doesn't see)
//   • re-attaching `_rawBytes` for compressed findings whose lazy-decode is
//     deferred until the user clicks the sidebar row (the worker stripped
//     `_rawBytes` before posting — see "Buffer ownership" below).
//   • `_updateRiskFromEncodedContent()` and the second-tier escalation loop.
//
// Build-time inlining
// -------------------
// `scripts/build.py` reads each layer of the bundle and concatenates them in
// strict order — every preceding layer's globals must be defined before the
// next layer's module body runs:
//   1. src/workers/encoded-worker-shim.js   (IOC table, PARSER_LIMITS subset,
//                                            _trimPathExtGarbage)
//   2. vendor/pako.min.js                   (Decompressor sync fallback when
//                                            DecompressionStream is missing)
//   3. vendor/jszip.min.js                  (embedded-ZIP validator used by
//                                            EncodedContentDetector to prune
//                                            false-positive zlib hits)
//   4. src/decompressor.js                  (gzip/zlib/deflate facade)
//   5. src/encoded-content-detector.js      (the actual scanner)
//   6. src/workers/encoded.worker.js        (this file — onmessage dispatcher)
//
// All six layers are concatenated, the result is wrapped in a JS template
// literal, and `src/worker-manager.js::runEncoded()` blob-URL spawns it.
// `__ENCODED_WORKER_BUNDLE_SRC` is the constant name. The worker file is
// NOT in `JS_FILES` for the same reason the C1/C2 workers aren't — it must
// not run on the main thread, and its presence in `JS_FILES` would let the
// risk-pre-stamp / bare-IOC / `_rawText` / worker-spawn build gates iterate
// worker-only code that isn't subject to those rules.
//
// postMessage protocol
// --------------------
// in:  { textContent: string,
//        rawBytes: ArrayBuffer (transferred),
//        options:   { fileType?, mimeAttachments?, maxRecursionDepth?,
//                     maxCandidatesPerType? } }
//
// out (success):
//   { event: 'done',
//     findings: [...],   // EncodedContentDetector findings, with `_rawBytes`
//                        //   stripped (host re-stamps) and lazyDecode already
//                        //   driven on every cheap finding.
//     parseMs: number }
//
// out (any error):
//   { event: 'error', message: string }
//
// The buffer is **transferred** (caller loses access). The host's `_loadFile`
// keeps `this._fileBuffer` alive for the rest of the analyser pipeline, so
// `runEncoded()` passes a `buffer.slice(0)` copy — one memcpy of the file
// bytes is cheap relative to the scan.
//
// Buffer ownership / `_rawBytes`
// ------------------------------
// `EncodedContentDetector.scan()` stamps `finding._rawBytes = rawBytes` on
// every compressed finding so a later `lazyDecode()` (driven from the
// sidebar when the user expands the row) can run without re-reading the
// file. Posting a Uint8Array view across the worker boundary detaches its
// ArrayBuffer back-store on the host, so we strip `_rawBytes` from each
// finding before `postMessage` and the host re-stamps with a fresh
// `new Uint8Array(buffer)` view of its own retained copy. This is the same
// pattern `timeline.worker.js` uses for evtx `rawRecord`.
//
// Failure surface
// ---------------
// Any thrown exception is caught and posted as `{event:'error'}`. The worker
// never throws — every terminal path posts exactly one of `{event:'done'}`
// or `{event:'error'}` then exits. Host falls back to the existing
// sync-on-main-thread scan path when this worker emits `error`, mirroring
// the C1 / C2 fallback contract.
//
// CSP note
// --------
// Workers inherit the host CSP, so `default-src 'none'` continues to deny
// network access from inside the worker. `worker-src blob:` is the only
// relaxation — see SECURITY.md → Full Content-Security-Policy. The host ↔
// worker boundary is `postMessage` only.
// ════════════════════════════════════════════════════════════════════════════

// ── Dispatcher ──────────────────────────────────────────────────────────────
self.onmessage = async function (ev) {
  const msg = ev && ev.data ? ev.data : {};
  const textContent = typeof msg.textContent === 'string' ? msg.textContent : '';
  const rawBuffer   = msg.rawBytes;
  const options     = (msg.options && typeof msg.options === 'object') ? msg.options : {};

  const t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
  try {
    if (!rawBuffer) {
      self.postMessage({ event: 'error', message: 'no rawBytes transferred to worker' });
      return;
    }
    if (typeof EncodedContentDetector === 'undefined') {
      self.postMessage({ event: 'error', message: 'EncodedContentDetector missing from worker bundle' });
      return;
    }

    const rawBytes = new Uint8Array(rawBuffer);
    const detector = new EncodedContentDetector({
      maxRecursionDepth:    options.maxRecursionDepth,
      maxCandidatesPerType: options.maxCandidatesPerType,
    });

    const findings = await detector.scan(textContent, rawBytes, {
      fileType:        options.fileType,
      mimeAttachments: options.mimeAttachments || null,
      // existingIOCs is intentionally omitted — the host merges decoded IOCs
      // against `findings.interestingStrings` post-scan, where the canonical
      // list lives. Letting the worker pre-dedupe would force us to ship
      // (and keep in sync) the entire current IOC list across the boundary
      // for what is essentially a cheap host-side `Set` check.
    });

    // Eagerly drive lazyDecode on every cheap finding so the sidebar can
    // render decoded previews without a second host→worker round-trip.
    // Mirrors the host-side Promise.all in app-load.js — same predicate.
    if (Array.isArray(findings) && findings.length) {
      await Promise.all(
        findings
          .filter(ef => ef && ef.rawCandidate && !ef.decodedBytes)
          .map(ef => detector.lazyDecode(ef).catch(() => ef))
      );
    }

    // Strip `_rawBytes` from every finding before postMessage. The view
    // points at the worker's `rawBytes`, which is about to be discarded
    // when the worker terminates; transferring it would also detach the
    // host's freshly-spawned buffer copy. The host re-stamps `_rawBytes`
    // on compressed findings using its own retained `_fileBuffer`.
    const out = new Array(findings ? findings.length : 0);
    for (let i = 0; i < out.length; i++) {
      const f = findings[i];
      if (!f) { out[i] = f; continue; }
      if (f._rawBytes !== undefined) {
        // shallow clone, drop _rawBytes
        const { _rawBytes, ...rest } = f;
        out[i] = rest;
      } else {
        out[i] = f;
      }
    }

    const t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    self.postMessage({
      event:    'done',
      findings: out,
      parseMs:  Math.max(0, t1 - t0),
    });
  } catch (e) {
    const message = (e && e.message) ? e.message : String(e);
    self.postMessage({ event: 'error', message });
  }
};
