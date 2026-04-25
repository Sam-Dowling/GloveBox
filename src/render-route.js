'use strict';
// ════════════════════════════════════════════════════════════════════════════
// render-route.js — central renderer dispatch (PLAN D1 + D4)
// ════════════════════════════════════════════════════════════════════════════
//
// `RenderRoute.run(file, buffer, app, rctx?)` is the single entry point that
// connects `RendererRegistry.detect()` to the per-id handlers in
// `App.prototype._rendererDispatch` (defined in `src/app/app-load.js`). It
// owns four concerns that previously lived inline in `App._loadFile`:
//
//   1. **Parser-watchdog wrap (PLAN B5).** Every renderer is invoked under
//      `ParserWatchdog.run(..., { timeout: PARSER_LIMITS.RENDERER_TIMEOUT_MS,
//      name: dispatchId })`. On a watchdog timeout we reset the partial
//      state the hung renderer may have written (`app.findings`,
//      `app.currentResult.binary`, `app.currentResult.yaraBuffer`), hand
//      the buffer to the `plaintext` handler, and surface a single
//      `IOC.INFO` row explaining why the structured viewer didn't load.
//      Genuine parser exceptions (i.e. errors that are NOT a watchdog
//      timeout) bubble out to the caller's outer `catch` — the failure
//      surface is unchanged.
//
//   2. **`RenderResult` normalisation.** Renderer handlers today return
//      either a bare `HTMLElement` (legacy) or `{ docEl, analyzer? }`. The
//      RenderResult object surfaced to `_loadFile` is the canonical
//      typedef from `PLAN.md` Tracks D1 + D4:
//        ```
//        { docEl, findings, rawText, buffer, binary?, yaraBuffer?,
//          navTitle, analyzer?, dispatchId }
//        ```
//      • `docEl`     — the view container, ready to mount under
//                      `#page-container`.
//      • `findings`  — read-through to `app.findings` (renderers still
//                      mutate the App-level field).
//      • `rawText`   — `lfNormalize(docEl._rawText || docEl.textContent || '')`.
//                      Centralised LF-normalisation: the post-render
//                      consumers (IOC sweep, encoded-content scan,
//                      click-to-focus offsets) see one consistent
//                      line-ending convention even when a renderer's
//                      `textContent` fallback path leaks CRLF.
//      • `buffer`    — the original file `ArrayBuffer`. Replaces the
//                      legacy `app._fileBuffer` instance-property stash
//                      (PLAN D4). `Object.defineProperty` aliases on
//                      `App.prototype` keep the legacy name working with
//                      a deprecation warn for one release cycle.
//      • `binary`    — `{ format, parsed }` when the renderer stamped
//                      `app._binaryFormat` (PE / ELF / Mach-O); `null`
//                      otherwise. Also written to via the alias setter
//                      (PLAN D4).
//      • `yaraBuffer`— optional augmented buffer (SVG/HTML/Plist/Scpt
//                      `findings.augmentedBuffer` is hoisted here so
//                      `_autoYaraScan` reads a single canonical handle).
//                      Replaces the legacy `app._yaraBuffer` instance
//                      stash. `null` when not augmented.
//      • `navTitle`  — defaults to `file.name`.
//      • `analyzer`  — pass-through for the DOCX module-renderer path
//                      (`SecurityAnalyzer` is the only renderer-side
//                      object the sidebar still consults directly).
//      • `dispatchId`— the registry decision id (e.g. `'pdf'`, `'pe'`).
//
//   3. **`app.currentResult` skeleton allocation (PLAN D4).** A skeleton
//      is stamped on `app` *before* the renderer handler is invoked so
//      that the legacy-field aliases (`app._fileBuffer`, `_binaryFormat`,
//      `_binaryParsed`, `_yaraBuffer`) — defined in `src/app/app-core.js`
//      — have a write target during the render. Renderer dispatchers
//      that still write `this._binaryFormat = 'pe'` etc. land in
//      `currentResult.binary` via the setter alias; no renderer-side
//      change is needed.
//
//   4. **Watchdog reset.** On timeout the partial `currentResult.binary`
//      / `currentResult.yaraBuffer` / `app.findings` writes from the
//      hung renderer are reset to `null` / a fresh empty findings object
//      before re-dispatching to `plaintext`.
//
// What `RenderRoute.run` deliberately does NOT do:
//
//   • It does not run the post-render IOC sweep, encoded-content scan,
//     hash join, sidebar render, or auto-YARA. Those still live in
//     `App._loadFile` after the `RenderRoute.run(...)` call returns.
//   • It does not handle the Timeline branch — Timeline is an intentional
//     analysis-bypass route (`_loadFileInTimeline`) that never touches
//     the registry. RenderRoute is for the generic branch only.
//   • It does not own the `_rendererDispatch` table. The table stays in
//     `app-load.js`.
//
// Dependencies (load-order):
//   • `src/constants.js`        — `PARSER_LIMITS`, `lfNormalize`, `pushIOC`, `IOC`
//   • `src/parser-watchdog.js`  — `ParserWatchdog.run`
//   • `src/renderer-registry.js`— `RendererRegistry.makeContext` / `.detect`
//   • `App.prototype._rendererDispatch` (`src/app/app-load.js`)
//
// `scripts/build.py` lists this file in `JS_FILES` AFTER `renderer-registry.js`
// and BEFORE `app-core.js` so `App._loadFile` can call `RenderRoute.run(...)`
// without forward references.
// ════════════════════════════════════════════════════════════════════════════

const RenderRoute = {

  /** Build a fresh, empty `currentResult` skeleton. Used by `run()` and by
   *  `App._loadFile`'s pre-render path so the legacy-field aliases (PLAN D4)
   *  always have a write target. */
  _emptyResult(buffer) {
    return {
      docEl: null,
      findings: null,         // filled post-render from `app.findings`
      rawText: '',
      buffer: buffer || null,
      binary: null,           // { format, parsed } when stamped by a renderer
      yaraBuffer: null,       // optional augmented buffer (SVG/HTML/etc.)
      navTitle: '',
      analyzer: null,
      dispatchId: null,
    };
  },

  /**
   * Centralised dispatch entry point.
   *
   * @param {File}        file    — the file being loaded.
   * @param {ArrayBuffer} buffer  — full file bytes (already read).
   * @param {App}         app     — the App instance (gives us the
   *                                `_rendererDispatch` handler table and
   *                                the read/write target for the per-id
   *                                renderer-side stamps).
   * @param {object?}     rctx    — optional pre-built RendererRegistry
   *                                context.
   * @returns {Promise<RenderResult>}
   */
  async run(file, buffer, app, rctx = null) {
    rctx = rctx || RendererRegistry.makeContext(file, buffer);
    const decision = RendererRegistry.detect(rctx);
    let dispatchId = decision.id;
    let handler = app._rendererDispatch[dispatchId] || app._rendererDispatch.plaintext;

    // ── PLAN D4 — currentResult skeleton allocation ──────────────────
    // Allocate before invoking the handler so the legacy-field aliases
    // on `App.prototype` (`_fileBuffer`, `_binaryFormat`, `_binaryParsed`,
    // `_yaraBuffer`) have a write target the moment a renderer's body
    // begins executing. Without this, the first `this._binaryFormat =
    // 'pe'` inside `pe()` would throw or silently lose the write.
    app.currentResult = RenderRoute._emptyResult(buffer);

    // ── PLAN F1 — per-dispatch file-size cap ─────────────────────────
    // If the file exceeds the structured-renderer cap for this dispatch
    // id, bypass the heavy parser and fall back to PlainTextRenderer
    // (same shape the watchdog-timeout fallback below uses). This is a
    // CPU-cost guard, not a memory-pressure guard — `RENDER_LIMITS.
    // HUGE_FILE_WARN` covers memory pressure separately. The analyst
    // can still inspect the bytes via the plaintext view, and the
    // manual YARA tab still scans the unmodified buffer.
    let f1Skipped = false;
    let f1Cap = 0;
    if (dispatchId !== 'plaintext') {
      const caps = (PARSER_LIMITS && PARSER_LIMITS.MAX_FILE_BYTES_BY_DISPATCH) || null;
      const cap = caps
        ? (caps[dispatchId] != null ? caps[dispatchId] : caps._DEFAULT)
        : Number.POSITIVE_INFINITY;
      const size = (buffer && buffer.byteLength) || 0;
      if (Number.isFinite(cap) && size > cap) {
        f1Skipped = true;
        f1Cap = cap;
        // Reset any partial state (currentResult skeleton already minimal,
        // but be explicit so the post-fallback path mirrors the watchdog
        // reset shape).
        app.findings = { risk: 'low', externalRefs: [], interestingStrings: [], metadata: {} };
        app.currentResult.binary = null;
        app.currentResult.yaraBuffer = null;
        // Re-route to plaintext for the rest of run().
        const originalDispatchId = dispatchId;
        dispatchId = 'plaintext';
        handler = app._rendererDispatch.plaintext;
        const mibCap  = (cap   / (1024 * 1024)).toFixed(0);
        const mibSize = (size  / (1024 * 1024)).toFixed(1);
        console.warn(
          `[loupe] PLAN F1 — dispatch "${originalDispatchId}" size cap exceeded ` +
          `(${mibSize} MiB > ${mibCap} MiB) — falling back to plain-text view`
        );
        // Stash the original id so the IOC.INFO row below names the
        // structured renderer the analyst missed out on.
        rctx._f1OriginalDispatchId = originalDispatchId;
      }
    }

    let raw;
    let analyzer = null;
    try {

      raw = await ParserWatchdog.run(
        () => handler.call(app, file, buffer, rctx),
        { timeout: PARSER_LIMITS.RENDERER_TIMEOUT_MS, name: dispatchId }
      );
    } catch (renderErr) {
      // Watchdog timeout → graceful PlainTextRenderer fallback. Skip the
      // fallback if the dispatcher we just timed out on was already
      // `plaintext` (degenerate case — let the caller render the
      // "Failed to open file" box).
      if (renderErr && renderErr._watchdogTimeout && dispatchId !== 'plaintext') {
        const secs = (PARSER_LIMITS.RENDERER_TIMEOUT_MS / 1000) | 0;
        console.warn(
          `[loupe] Renderer "${dispatchId}" timed out after ${secs}s — falling back to plain-text view`
        );
        // Reset partial state from the hung renderer so it can't bleed
        // into the sidebar (findings.risk pre-stamps, half-built IOC
        // arrays, binary-triage globals from a half-parsed PE/ELF/Mach-O).
        app.findings = { risk: 'low', externalRefs: [], interestingStrings: [], metadata: {} };
        // The legacy-field setters (PLAN D4) route into
        // `currentResult.binary` / `currentResult.yaraBuffer`, which is
        // exactly what we want to clear.
        app.currentResult.binary = null;
        app.currentResult.yaraBuffer = null;
        raw = await app._rendererDispatch.plaintext.call(app, file, buffer, rctx);
        analyzer = null;
        // Surface the fallback to the analyst as a visible IOC.INFO row
        // (interim; PLAN F2 will unify reporting via App._reportNonFatal).
        pushIOC(app.findings, {
          type: IOC.INFO,
          value: `Parser "${dispatchId}" timed out after ${secs}s — falling back to plain-text view. Open the YARA tab for a manual deep scan.`,
          severity: 'medium',
        });
      } else {
        throw renderErr;
      }
    }

    // Normalise the renderer return into a RenderResult.
    let docEl;
    if (raw && raw.nodeType === 1) {
      // bare HTMLElement
      docEl = raw;
    } else if (raw && raw.docEl) {
      docEl = raw.docEl;
      if (raw.analyzer && !analyzer) analyzer = raw.analyzer;
    } else {
      docEl = null;
    }

    // Centralised LF-normalisation (PLAN H3 fix).
    const rawTextSource = (docEl && docEl._rawText)
      || (docEl && docEl.textContent)
      || '';
    const rawText = lfNormalize(rawTextSource);

    // Fill in the remaining fields of the in-flight currentResult. The
    // skeleton already holds `buffer` and any `binary` / `yaraBuffer`
    // writes the renderer made via the alias setters.
    const result = app.currentResult;
    result.docEl = docEl;
    result.findings = app.findings;
    result.rawText = rawText;
    result.navTitle = file.name;
    result.analyzer = analyzer;
    result.dispatchId = dispatchId;

    // ── PLAN F1 — surface the size-cap skip as a sidebar IOC.INFO ─────
    // Pushed AFTER the plaintext handler has run so the row lands in the
    // post-render `app.findings` and is preserved by the post-render IOC
    // sweep. Mirrors the watchdog-timeout path's note shape.
    if (f1Skipped) {
      const orig = (rctx && rctx._f1OriginalDispatchId) || 'structured';
      const mibCap  = (f1Cap                       / (1024 * 1024)).toFixed(0);
      const mibSize = ((buffer.byteLength || 0)    / (1024 * 1024)).toFixed(1);
      pushIOC(app.findings, {
        type: IOC.INFO,
        value: `${orig.toUpperCase()} file (${mibSize} MiB) exceeds the ${mibCap} MiB structured-parse cap — falling back to plain-text view. Open the YARA tab for a manual deep scan.`,
        severity: 'medium',
      });
    }

    return result;
  },
};


window.RenderRoute = RenderRoute;
