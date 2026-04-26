// ════════════════════════════════════════════════════════════════════════════
// early-drop-bootstrap.js — pre-App drag-and-drop / paste capture.
//
// Why this exists
// ───────────────
// Loupe is a single-file HTML bundle. CSP forbids external scripts, so every
// `<script>` is inline + synchronous and the browser parser blocks on each
// in source order. On a cold reload the parser reaches:
//
//   • theme-bootstrap IIFE      ~0 ms
//   • JSZip / SheetJS / pdf.js  ~60 ms compile
//   • highlight.js / utif / …   ~5 ms each
//   • the App mega-`<script>`   ~50 ms compile (defines `class App`,
//                                attaches Object.assign mixins, runs)
//
// Drag-and-drop / paste handlers are registered inside the **App
// constructor** (`src/app/app-core.js::_setupDrop`). On a cold reload
// that is ~1.5 s after FCP — long enough that the user can drop a file
// onto the visible drop-zone and get nothing but the browser's default
// "navigate-to-file" behaviour, which exits Loupe entirely.
//
// This bootstrap is the smallest possible inline `<script>` that beats
// the parser to the punch. It is concatenated **first** in `JS_FILES`
// (see `scripts/build.py`) so it lives at the top of the App bundle,
// well before any of the heavy compile blocks. Total cost: ≈ 60 LOC of
// pure event-listener glue, < 1 ms compile, no work until the user
// actually drops something.
//
// Behaviour
// ─────────
//   1. Window-level capture-phase listeners for `dragenter`, `dragover`,
//      `drop`, and `paste`.
//   2. Only reacts to **OS file drags** — gated on `dataTransfer.types`
//      containing `'Files'` so internal DOM drags (Timeline column
//      reorder, etc.) pass through cleanly.
//   3. On `drop` / `paste`: snapshots the `FileList` into a plain array
//      (the live FileList becomes empty once the handler returns) onto
//      `window.__loupePendingDrop` (drag) or `window.__loupePendingPaste`
//      (clipboard).
//   4. Exposes `window.__loupeEarlyDropTeardown()` — the App's
//      `_setupDrop()` calls this **after** wiring its own listeners so
//      the bootstrap removes itself and the App owns drag/drop end-to-end.
//
// Constraints
// ───────────
//   • No `eval`, no `new Function`, no network — strict CSP applies.
//   • No DOM mutation — UI feedback (drop-zone hover ring, overlay) is
//     the App's job. Stays cosmetic-free so the bootstrap can run before
//     the body's children even exist on extremely slow reloads.
//   • No new `localStorage` keys, no new vendor deps.
//   • Capture-phase listeners (`useCapture = true`) so the bootstrap
//     beats the App's bubble-phase listeners during the brief overlap
//     between `_setupDrop()` registering them and the bootstrap
//     teardown firing on the next line.
// ════════════════════════════════════════════════════════════════════════════

(function () {
  'use strict';

  // OS file drags carry `'Files'` in `DataTransfer.types`. Internal DOM
  // drags (e.g. timeline `🏆 Top values` card reorder) do not, so this
  // gate keeps them passing through to their own handlers.
  const isFileDrag = (e) => {
    const t = e && e.dataTransfer && e.dataTransfer.types;
    if (!t) return false;
    // DOMStringList in some browsers, array-like in others.
    return Array.from(t).indexOf('Files') !== -1;
  };

  const onDragOver = (e) => {
    if (!isFileDrag(e)) return;
    // Without preventDefault on dragover the drop event never fires.
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
  };

  const onDragEnter = (e) => {
    if (!isFileDrag(e)) return;
    e.preventDefault();
  };

  const onDrop = (e) => {
    if (!isFileDrag(e)) return;
    // Without preventDefault the browser navigates away to the file URL.
    e.preventDefault();
    e.stopPropagation();
    const files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length) {
      // Snapshot into a plain array — the live FileList is invalidated
      // the moment the handler returns, so by the time the App
      // constructor reaches `_setupDrop()`'s drain step the FileList
      // would be empty.
      window.__loupePendingDrop = Array.from(files);
    }
  };

  const onPaste = (e) => {
    const dt = e.clipboardData;
    if (!dt) return;
    if (dt.files && dt.files.length) {
      window.__loupePendingPaste = Array.from(dt.files);
    }
  };

  // useCapture = true so we run before any document/body bubble-phase
  // listener. Once the App registers its own (bubble-phase) handlers in
  // `_setupDrop`, it calls `__loupeEarlyDropTeardown()` to remove these
  // and hand drag/drop ownership over.
  window.addEventListener('dragover',  onDragOver,  true);
  window.addEventListener('dragenter', onDragEnter, true);
  window.addEventListener('drop',      onDrop,      true);
  window.addEventListener('paste',     onPaste,     true);

  window.__loupeEarlyDropTeardown = function () {
    window.removeEventListener('dragover',  onDragOver,  true);
    window.removeEventListener('dragenter', onDragEnter, true);
    window.removeEventListener('drop',      onDrop,      true);
    window.removeEventListener('paste',     onPaste,     true);
    // Single-shot — drop the function so a stray second call is a no-op
    // and a profiler / dev-tools snapshot doesn't show a stale teardown.
    try { delete window.__loupeEarlyDropTeardown; } catch (_) {
      window.__loupeEarlyDropTeardown = function () {};
    }
  };
})();
