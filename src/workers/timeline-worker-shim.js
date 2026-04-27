'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-worker-shim.js — Worker-bundle prelude for the Timeline parser
//
// This is the first file `scripts/build.py` concatenates into the
// `__TIMELINE_WORKER_BUNDLE_SRC` template-literal that powers the Timeline
// parse-only worker. It declares the small subset of constants
// and analyzer stubs the renderer sources reach for at module load and
// must therefore be defined **before** them.
//
// Bundle order (set in `scripts/build.py`):
//   1. src/workers/timeline-worker-shim.js   ← this file
//   2. src/renderers/csv-renderer.js
//   3. src/renderers/sqlite-renderer.js
//   4. src/renderers/evtx-renderer.js
//   5. src/workers/timeline.worker.js        ← parse fns + onmessage
//
// All five files are concatenated, the result is wrapped in a JS template
// literal, and `src/worker-manager.js::runTimeline()` blob-URL spawns it.
// `src/workers/timeline.worker.js` carries the full design rationale
// (postMessage protocol, fallback contract, CSP note, etc.) — keep this
// shim deliberately tight.
//
// What lives here vs `src/constants.js`
// -------------------------------------
// Only the values the parse paths actually read at runtime. Inlining the
// whole `src/constants.js` would pull in `escalateRisk`, `pushIOC`,
// `mirrorMetadataIOCs`, the `IOC.*` enum, ICON.*, NICELIST helpers, and
// other analyzer-side concerns the worker doesn't need. If `constants.js`
// ever changes one of these values, update this block too — the build
// will not catch the drift.
// ════════════════════════════════════════════════════════════════════════════

// ── Inlined RENDER_LIMITS subset ────────────────────────────────────────────
const RENDER_LIMITS = Object.freeze({
  MAX_CSV_ROWS:        1_000_000,
  MAX_EVTX_EVENTS:     1_000_000,
  DECODE_CHUNK_BYTES:  16 * 1024 * 1024,  // 16 MB — chunked UTF-8 decode size
});

// Same column order the main-thread renderer / Timeline view use; the
// worker hands events back as `{ columns, rows }` so this must match.
const EVTX_COLUMN_ORDER = ['Timestamp', 'Event ID', 'Level', 'Provider', 'Channel', 'Computer', 'Event Data'];

// Mirrors `TIMELINE_MAX_ROWS = RENDER_LIMITS.MAX_TIMELINE_ROWS` and
// `MAX_TIMELINE_ROWS: 1_000_000` from the main-thread constants table.
const TIMELINE_MAX_ROWS = 1_000_000;

// ── Stub IOC.* / risk helpers ───────────────────────────────────────────────
//
// `EvtxRenderer.analyzeForSecurity` (and `CsvRenderer.analyzeForSecurity`)
// reach for these constants and helpers when they run. The worker never
// calls those analyzer methods, but the renderer source we concatenate
// references them at class-body load time inside method bodies (still
// fine — methods are not executed). These no-op stubs let the source
// parse and load without ReferenceErrors should anything ever try.
const IOC = new Proxy({}, { get: (_t, p) => String(p) });
function escalateRisk() { /* no-op in worker */ }
function pushIOC() { /* no-op in worker */ }
function lfNormalize(s) { return typeof s === 'string' ? s.replace(/\r\n?/g, '\n') : s; }
// `throwIfAborted` is the render-epoch / watchdog poll site added in
// `src/constants.js`. `EvtxRenderer._parse` and `_parseAsync` (and other
// renderer sources we may pull into the worker bundle) call it at the top
// of every outer parse loop. The worker has no main-thread
// `ParserWatchdog._activeSignal` slot to consult and never needs to bail
// for supersession (the host calls `WorkerManager.cancelTimeline()` to
// terminate us instead), so the contractual no-op here is correct. Must
// be defined or the very first chunk-loop iteration throws
// `ReferenceError`, which the worker swallows into a zero-row result —
// the host's zero-row escape hatch then drops the file into the regular
// analyser pipeline, defeating the "EVTX always opens in Timeline" rule.
function throwIfAborted() { /* no-op in worker */ }

// ── safeRegex helpers (mirror src/constants.js) ─────────────────────────────
// Inlined into the worker because workers don't share globals with the host
// bundle. Used by the Timeline DSL regex compile path. Keep in lockstep with
// `src/constants.js` and `src/workers/encoded-worker-shim.js`.
const SAFE_REGEX_MAX_PATTERN_LEN = 2048;
const _REDOS_NESTED_QUANT_RE =
  /\((?:\?[:=!]|\?<[=!])?[^()]*(?:[+*]|\{\d+,\}|\{,\d+\})[^()]*\)\s*(?:[+*]|\{\d+,\}|\{,\d+\})/;
const _REDOS_DUPLICATE_GROUP_RE =
  /(\([^()]{2,80}\)[+*])\s*\1/;
function looksRedosProne(src) {
  if (typeof src !== 'string') return { warn: false, reject: false };
  if (src.length > SAFE_REGEX_MAX_PATTERN_LEN) {
    return { warn: false, reject: true, reason: 'pattern too long' };
  }
  if (_REDOS_DUPLICATE_GROUP_RE.test(src)) {
    return { warn: false, reject: true, reason: 'duplicate adjacent quantified groups' };
  }
  if (_REDOS_NESTED_QUANT_RE.test(src)) {
    return { warn: true, reject: false, reason: 'nested unbounded quantifier' };
  }
  return { warn: false, reject: false };
}
function safeRegex(pattern, flags) {
  const src = String(pattern == null ? '' : pattern);
  const heur = looksRedosProne(src);
  if (heur.reject) {
    return { ok: false, regex: null, warning: null, error: heur.reason };
  }
  let regex;
  try {
    /* safeRegex: builtin */
    regex = new RegExp(src, flags || '');
  } catch (e) {
    return { ok: false, regex: null, warning: null, error: e && e.message || 'invalid regex' };
  }
  return { ok: true, regex, warning: heur.warn ? heur.reason : null, error: null };
}

// ── EVTX event-id table stub ────────────────────────────────────────────────
//
// `evtx-event-ids.js` defines `EVTX_EVENT_DESCRIPTIONS` — view-only data
// the renderer's `_getEventDescription` uses. Parse paths don't touch it,
// but the renderer references it at module load. An empty object here
// keeps the worker bundle small (the real ~3 KB table is dead code in
// the worker) while preventing ReferenceError.
const EVTX_EVENT_DESCRIPTIONS = {};
