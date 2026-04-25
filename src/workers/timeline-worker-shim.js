'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-worker-shim.js — Worker-bundle prelude for the Timeline parser
//
// This is the first file `scripts/build.py` concatenates into the
// `__TIMELINE_WORKER_BUNDLE_SRC` template-literal that powers the Timeline
// parse-only worker (PLAN C2). It declares the small subset of constants
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

// ── EVTX event-id table stub ────────────────────────────────────────────────
//
// `evtx-event-ids.js` defines `EVTX_EVENT_DESCRIPTIONS` — view-only data
// the renderer's `_getEventDescription` uses. Parse paths don't touch it,
// but the renderer references it at module load. An empty object here
// keeps the worker bundle small (the real ~3 KB table is dead code in
// the worker) while preventing ReferenceError.
const EVTX_EVENT_DESCRIPTIONS = {};
