'use strict';
// ════════════════════════════════════════════════════════════════════════════
// decoded-yara-filter.js — second-pass YARA gate for decoded encoded-content
// payloads.
//
// Loupe's `EncodedContentDetector` produces a tree of `findings` for every
// successful decode it can speculatively unwrap (Base64, hex, ROT-N, char
// arrays, XOR cleartext, decompressed gzip/zlib, …). A non-trivial number
// of these decodes are coincidence — random ASCII that happens to look
// Base64-shaped, or a hex-encoded GUID that decodes to garbage. The
// detector's existing post-scan `_pruneFindings` (regex-based; see
// `src/encoded-content-detector.js:411`) already drops the obvious
// trash, but it has no view into *what the decoded bytes actually
// resemble* beyond a small classification regex and an exec-intent
// keyword test.
//
// This module bolts a second-pass YARA scan onto every retained decoded
// payload. The pass uses the curated `applies_to = "decoded-payload"`
// subset of the rule corpus (see `src/rules/*.yar`) — a rule opts in by
// adding the meta tag, signalling "my strings make sense on a fragment
// of decoded bytes". The result is one of:
//
//   • YARA matched ⇒ stamp `finding._yaraHits = [{ ruleName, severity, … }]`
//                    so the sidebar can render an "evidence" row, AND
//                    boost retention (see Rule 7 in `_shouldRetainFinding`
//                    inside `encoded-content-detector.js`).
//   • YARA didn't match ⇒ leave the finding untouched. The existing
//                    `_pruneFindings` retention rules still apply; this
//                    pass only ever ADDS retention reasons, never removes.
//
// In `bruteforce` mode (kitchen-sink decode-selection) the pass is skipped
// entirely. Bruteforce is the analyst's "show me everything" escape hatch
// and a YARA gate would silently strip findings the analyst explicitly
// asked for.
//
// Why a host-side module (vs. inside the encoded worker)?
// -------------------------------------------------------
// The encoded worker bundle deliberately doesn't include `yara-engine.js`
// — adding it would inflate the bundle for every encoded-content scan
// regardless of whether the user even has YARA enabled. Routing the
// decoded payloads back through the existing yara-channel worker
// (via `WorkerManager.runDecodedYara`) keeps the encoded worker lean and
// reuses the same `Worker(blob:)` infrastructure already paying for the
// auto-YARA scan. Two transfers per file is cheap; the alternative
// (bundle YARA into the encoded worker) is a much bigger change.
//
// The single packed-buffer transfer + offset-table is documented in
// `WorkerManager.runDecodedYara` and `src/workers/yara.worker.js::_dispatchMulti`.
//
// Failure surface
// ---------------
// Any rejection from the worker (probe failed, supersession, watchdog
// timeout, parse error) demotes to a no-op — findings come through
// unchanged. The trash-suppression value of this pass is additive; if it
// fails the analyst still sees the existing prune-pass result, just
// without the YARA evidence rows.
// ════════════════════════════════════════════════════════════════════════════

(function () {

  // ── Tunables ────────────────────────────────────────────────────────────
  // Per-payload size gates. Tiny buffers can't carry a meaningful YARA
  // string match; huge buffers blow up the per-call latin-1 string-build
  // inside `YaraEngine.scan` (it's O(n) regardless of rule count). The
  // upper cap is generous — most decoded payloads are sub-KB.
  const MIN_PAYLOAD_BYTES = 16;
  const MAX_PAYLOAD_BYTES = 256 * 1024;

  // Hard cap on payloads per file. A pathological sample with thousands of
  // tiny base64 literals that all decoded successfully would otherwise
  // amplify the per-call setup cost. Bruteforce mode bypasses the entire
  // pass anyway, so this only bites the default / aggressive paths.
  const MAX_PAYLOADS_PER_FILE = 256;

  /** Walk a findings tree (depth-first, pre-order) and yield every
   *  `{ finding, parent }` entry that has decoded bytes worth scanning.
   *  Filters by size gates and the existing classification (we don't
   *  need to YARA-scan something already classified as PE/ELF/Mach-O
   *  — the binary renderer's own pipeline owns those, and the
   *  decoded-payload rule subset is intentionally script/shellcode-
   *  shaped, not PE-structural).
   */
  function _collectScanCandidates(findings) {
    const out = [];
    const skipClassRe = /pe executable|elf|mach-o|java class/i;
    const walk = (list) => {
      if (!Array.isArray(list)) return;
      for (const f of list) {
        if (!f || typeof f !== 'object') continue;
        const bytes = (f.decodedBytes instanceof Uint8Array) ? f.decodedBytes : null;
        const ctype = (f.classification && f.classification.type) || '';
        const skip  = ctype && skipClassRe.test(ctype);
        if (bytes && !skip
            && bytes.byteLength >= MIN_PAYLOAD_BYTES
            && bytes.byteLength <= MAX_PAYLOAD_BYTES) {
          out.push(f);
          if (out.length >= MAX_PAYLOADS_PER_FILE) return;
        }
        if (Array.isArray(f.innerFindings) && f.innerFindings.length) {
          walk(f.innerFindings);
          if (out.length >= MAX_PAYLOADS_PER_FILE) return;
        }
      }
    };
    walk(findings);
    return out;
  }

  /** Apply YARA-gated retention to a findings tree, in place.
   *
   *  Returns the (possibly-mutated) findings array. The function is
   *  idempotent — calling twice with the same input produces the same
   *  `_yaraHits` stamps and no double-counting.
   *
   *  @param {Array}   findings    encoded-content findings tree
   *  @param {object}  opts
   *  @param {string}  opts.source         YARA rule source (`_getAllYaraSource()` output)
   *  @param {boolean} [opts.bruteforce]   when true, the pass is skipped
   *  @param {object}  [opts.workerManager] usually `window.WorkerManager`;
   *                                       parameter exists for the unit
   *                                       tests' fake worker.
   */
  async function applyDecodedYaraGate(findings, opts) {
    if (!Array.isArray(findings) || findings.length === 0) return findings;
    if (opts && opts.bruteforce) return findings;

    const wm = (opts && opts.workerManager) || (typeof WorkerManager !== 'undefined' ? WorkerManager : null);
    if (!wm || typeof wm.runDecodedYara !== 'function') return findings;
    if (typeof wm.workersAvailable === 'function' && !wm.workersAvailable()) {
      // Workers unavailable — skip the pass entirely. Running on the main
      // thread would freeze the UI on hundreds of tiny payloads, which is
      // exactly the case we're trying to optimise.
      return findings;
    }

    const candidates = _collectScanCandidates(findings);
    if (!candidates.length) return findings;

    const source = (opts && opts.source) || '';
    if (!source) return findings;

    // Each candidate gets a numeric id matching its index in `candidates`
    // so the worker's `hits` postback can be re-keyed back onto the
    // finding object without a Map<finding, id>.
    const payloads = new Array(candidates.length);
    for (let i = 0; i < candidates.length; i++) {
      payloads[i] = { id: i, bytes: candidates[i].decodedBytes };
    }

    let out;
    try {
      out = await wm.runDecodedYara(payloads, source, { formatTag: 'decoded-payload' });
    } catch (err) {
      // Supersession / probe-failure / parse-error: no-op. The findings
      // tree is left as the worker returned it; the existing prune
      // already dropped the worst offenders.
      return findings;
    }

    if (!out || !Array.isArray(out.hits) || !out.hits.length) {
      return findings;
    }

    for (const h of out.hits) {
      const idx = h && h.id;
      if (typeof idx !== 'number' || idx < 0 || idx >= candidates.length) continue;
      const f = candidates[idx];
      if (!f) continue;
      // Stamp a compact evidence shape on the finding. Keep only the
      // fields the sidebar's evidence row consumes — full match tables
      // can balloon a structured-cloned findings tree on pathological
      // samples. Keep `severity` so the sidebar can colour the chip.
      const slim = [];
      for (const r of (h.results || [])) {
        slim.push({
          ruleName: r.ruleName,
          severity: (r.meta && r.meta.severity) || null,
          tags:     r.tags || '',
        });
      }
      // Idempotent: dedupe against any prior stamp from a previous call.
      const existing = Array.isArray(f._yaraHits) ? f._yaraHits : [];
      const seen = new Set(existing.map(e => e.ruleName));
      for (const r of slim) {
        if (!seen.has(r.ruleName)) {
          existing.push(r);
          seen.add(r.ruleName);
        }
      }
      f._yaraHits = existing;
      // Treat a YARA hit as a retention reason in case some future
      // prune pass walks the tree again (today's prune already ran in
      // the worker before this pass; keeping the flag explicit is
      // belt-and-braces and lets the unit test assert it).
      f._retainedByYara = true;
    }
    return findings;
  }

  // Export under the global namespace so the host bundle can reach it
  // without ES modules. Mirrors the module-pattern of every other shared
  // helper (`Decompressor`, `EncodedContentDetector`, …).
  window.DecodedYaraFilter = {
    applyDecodedYaraGate,
    // Exposed for unit tests that want to assert the candidate-collection
    // gate without spinning up a worker.
    _collectScanCandidates,
    MIN_PAYLOAD_BYTES,
    MAX_PAYLOAD_BYTES,
    MAX_PAYLOADS_PER_FILE,
  };

})();
