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
//   in (single):
//        { buffer: ArrayBuffer (transferred), source: string,
//          formatTag?: string }   // Loupe-detected file format
//   in (multi — decoded-payload pass, see src/decoded-yara-filter.js):
//        { mode: 'multi',
//          source:    string,             // YARA rule source
//          formatTag: string,             // forwarded to YaraEngine.scan()
//                                         // — typically 'decoded-payload'
//          packed:    ArrayBuffer,        // single concat of every payload
//                                         // (transferred)
//          offsets:   number[],           // byte offsets into `packed`,
//                                         // length = N + 1 (last entry is
//                                         // the total byte count)
//          ids:       (string|number)[]   // host-supplied keys; correspond
//                                         // 1:1 with the offsets table
//        }
//   out (single):
//        { event: 'done', results: [...], parseMs: N, scanMs: N }
//   out (multi):
//        { event: 'done', mode: 'multi',
//          hits:     [{ id, results: [...] }, ...],   // only payloads
//                                                     // with ≥1 match are
//                                                     // included; empty
//                                                     // matches are pruned
//                                                     // before postback
//          parseMs:  N,                               // one-shot rule parse
//          scanMs:   N,                               // total across every
//                                                     // payload
//          payloadCount: N }
//   out (any error):
//        { event: 'error', message: string }
//
// `formatTag` is the value `RendererRegistry.detect()` produced for the
// file (`pe`, `lnk`, `rtf`, `svg`, …) — see `src/render-route.js`. It is
// forwarded into `YaraEngine.scan(..., { context: { formatTag } })` so
// rule conditions can use `is_*` predicates and `meta: applies_to`. When
// absent (legacy callers) the engine treats `is_*` as false and skips
// any rule with `applies_to`.
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
  const mode = (msg && typeof msg.mode === 'string') ? msg.mode : 'single';

  try {
    if (typeof YaraEngine === 'undefined') {
      self.postMessage({ event: 'error', message: 'YaraEngine missing from worker bundle' });
      return;
    }

    if (mode === 'multi') {
      _dispatchMulti(msg);
      return;
    }

    // ── Single-buffer path (legacy / auto-YARA / manual rescan) ──────────
    const buffer = msg.buffer;
    const source = msg.source || '';
    const formatTag = (typeof msg.formatTag === 'string') ? msg.formatTag : null;

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
    const results = YaraEngine.scan(buffer, rules, {
      errors: scanErrors,
      context: { formatTag },
    });
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

// ── Multi-payload dispatch ────────────────────────────────────────────────
//
// Used by `src/decoded-yara-filter.js` to scan every decoded encoded-content
// payload against the curated `applies_to = "decoded-payload"` subset of
// the rule corpus. The host packs all payloads into one ArrayBuffer with
// an offset table to avoid per-payload structured-clone overhead. Rules
// are parsed once and reused across every payload. Empty match sets are
// pruned before postback so the payload returned to the host is small even
// when the input was hundreds of decoded payloads.
function _dispatchMulti(msg) {
  const source    = msg.source || '';
  const formatTag = (typeof msg.formatTag === 'string') ? msg.formatTag : null;
  const packed    = msg.packed;
  const offsets   = Array.isArray(msg.offsets) ? msg.offsets : null;
  const ids       = Array.isArray(msg.ids)     ? msg.ids     : null;

  if (!packed || !offsets || !ids) {
    self.postMessage({ event: 'error', message: 'multi: missing packed/offsets/ids' });
    return;
  }
  if (offsets.length !== ids.length + 1) {
    self.postMessage({
      event:   'error',
      message: 'multi: offsets table length must equal ids.length + 1',
    });
    return;
  }

  const t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
  const parsed = YaraEngine.parseRules(source);
  const rules  = (parsed && parsed.rules)  || [];
  const errs   = (parsed && parsed.errors) || [];
  const t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

  if (errs.length && !rules.length) {
    self.postMessage({ event: 'error', message: 'parse: ' + errs.join('; ') });
    return;
  }

  // Pre-filter rules to only those that opt in to the decoded-payload pass.
  // Without this, every rule's string-search runs against every tiny payload
  // even though `applies_to` would short-circuit them inside `scan()` —
  // doing the filter once up here saves the per-rule walk on every call.
  const opted = [];
  for (const rule of rules) {
    if (rule.meta && rule.meta.applies_to) {
      if (YaraEngine._matchesAppliesTo(rule.meta.applies_to, formatTag)) {
        opted.push(rule);
      }
    }
    // Rules with no `applies_to` are intentionally excluded from the
    // decoded-payload pass — without an opt-in there's no signal that
    // the rule's strings make sense on a fragment of decoded bytes.
  }

  const view = new Uint8Array(packed);
  const hits = [];
  for (let i = 0; i < ids.length; i++) {
    const start = offsets[i];
    const end   = offsets[i + 1];
    if (end <= start) continue;
    const slice = view.subarray(start, end);
    const results = YaraEngine.scan(slice, opted, {
      // No errorSink — per-string regex caps still apply but we don't
      // surface them to the host (the host's auto-YARA path is the
      // canonical place for that).
      context: { formatTag },
    });
    if (results && results.length) {
      hits.push({ id: ids[i], results });
    }
  }
  const t2 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();

  self.postMessage({
    event:        'done',
    mode:         'multi',
    hits,
    parseMs:      Math.max(0, t1 - t0),
    scanMs:       Math.max(0, t2 - t1),
    payloadCount: ids.length,
    ruleCount:    opted.length,
  });
}
