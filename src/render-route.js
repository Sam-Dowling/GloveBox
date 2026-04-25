'use strict';
// ════════════════════════════════════════════════════════════════════════════
// render-route.js — central renderer dispatch
// ════════════════════════════════════════════════════════════════════════════
//
// `RenderRoute.run(file, buffer, app, rctx?)` is the single entry point that
// connects `RendererRegistry.detect()` to the per-id handlers in
// `App.prototype._rendererDispatch` (defined in `src/app/app-load.js`). It
// owns five concerns that previously lived inline in `App._loadFile`:
//
//   1. **Parser-watchdog wrap.** Every renderer is invoked under
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
//   2. **Per-dispatch file-size cap.** `PARSER_LIMITS
//      .MAX_FILE_BYTES_BY_DISPATCH[id]` (with `_DEFAULT` fallback) is
//      enforced *before* the renderer runs. Above the cap the structured
//      handler is bypassed and the buffer is rerouted to `plaintext`.
//      The watchdog and size-cap fallbacks share a single helper
//      (`_fallbackToPlaintext`) so the two paths produce identical
//      sidebar state.
//
//   3. **`RenderResult` normalisation.** Renderer handlers today return
//      either a bare `HTMLElement` (legacy) or `{ docEl, analyzer? }`. The
//      RenderResult object surfaced to `_loadFile` has the shape:
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
//      • `buffer`    — the original file `ArrayBuffer`. Canonical handle
//                      replacing the legacy `app._fileBuffer` instance
//                      stash.
//      • `binary`    — `{ format, parsed }` when a binary renderer
//                      stamped it (PE / ELF / Mach-O); `null` otherwise.
//      • `yaraBuffer`— optional augmented buffer (SVG/HTML/Plist/Scpt
//                      `findings.augmentedBuffer` is hoisted here so
//                      `_autoYaraScan` reads a single canonical handle).
//                      `null` when not augmented.
//      • `navTitle`  — defaults to `file.name`.
//      • `analyzer`  — pass-through for the DOCX module-renderer path
//                      (`SecurityAnalyzer` is the only renderer-side
//                      object the sidebar still consults directly).
//      • `dispatchId`— the registry decision id (e.g. `'pdf'`, `'pe'`).
//
//   4. **`app.currentResult` skeleton allocation.** A skeleton is stamped
//      on `app` *before* the renderer handler is invoked so renderers
//      that write `this.currentResult.binary = { format, parsed }` (or
//      `currentResult.yaraBuffer = …`) have a live target the moment
//      execution enters their body.
//
//   5. **Post-fallback IOC.INFO row.** Whichever path triggers the
//      fallback (watchdog timeout or size-cap), a single visible
//      `IOC.INFO` row is pushed onto the now-`plaintext` findings
//      explaining what just happened so the analyst is never left
//      wondering why a structured viewer didn't load.
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
   *  `App._loadFile`'s pre-render path so the per-renderer stamps always
   *  have a live write target. */
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

  /** Reset partial render state (findings + binary/yaraBuffer stamps),
   *  hand the buffer to the plaintext renderer, and push a sidebar
   *  `IOC.INFO` row explaining the fallback. Shared by both fallback
   *  triggers (watchdog timeout + per-dispatch size cap) so they
   *  produce identical sidebar state. Returns the plaintext renderer's
   *  raw return value (HTMLElement or `{docEl, analyzer?}`). */
  async _fallbackToPlaintext(app, file, buffer, rctx, infoMessage) {
    // Reset partial state from the bypassed renderer so it can't bleed
    // into the sidebar (findings.risk pre-stamps, half-built IOC arrays,
    // binary-triage stamps from a half-parsed PE/ELF/Mach-O).
    app.findings = { risk: 'low', externalRefs: [], interestingStrings: [], metadata: {} };
    app.currentResult.binary = null;
    app.currentResult.yaraBuffer = null;

    const raw = await app._rendererDispatch.plaintext.call(app, file, buffer, rctx);

    // Surface the fallback as a visible IOC.INFO row. Pushed after the
    // plaintext handler runs so the row lands in the post-render
    // `app.findings` and is preserved by the post-render IOC sweep.
    if (infoMessage) {
      pushIOC(app.findings, {
        type: IOC.INFO,
        value: infoMessage,
        severity: 'medium',
      });
    }

    return raw;
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

    // Allocate the currentResult skeleton before invoking the handler
    // so per-renderer stamps (`this.currentResult.binary = …`,
    // `this.currentResult.yaraBuffer = …`) have a live write target.
    app.currentResult = RenderRoute._emptyResult(buffer);

    // ── Per-dispatch file-size cap ────────────────────────────────────
    // If the file exceeds the structured-renderer cap for this dispatch
    // id, bypass the heavy parser and fall back to PlainTextRenderer
    // (same shape the watchdog-timeout fallback below uses). This is a
    // CPU-cost guard, not a memory-pressure guard — `RENDER_LIMITS.
    // HUGE_FILE_WARN` covers memory pressure separately. The analyst
    // can still inspect the bytes via the plaintext view, and the
    // manual YARA tab still scans the unmodified buffer.
    let raw;
    let analyzer = null;

    if (dispatchId !== 'plaintext') {
      const caps = (PARSER_LIMITS && PARSER_LIMITS.MAX_FILE_BYTES_BY_DISPATCH) || null;
      const cap = caps
        ? (caps[dispatchId] != null ? caps[dispatchId] : caps._DEFAULT)
        : Number.POSITIVE_INFINITY;
      const size = (buffer && buffer.byteLength) || 0;
      if (Number.isFinite(cap) && size > cap) {
        const originalDispatchId = dispatchId;
        const mibCap  = (cap   / (1024 * 1024)).toFixed(0);
        const mibSize = (size  / (1024 * 1024)).toFixed(1);
        console.warn(
          `[loupe] dispatch "${originalDispatchId}" size cap exceeded ` +
          `(${mibSize} MiB > ${mibCap} MiB) — falling back to plain-text view`
        );
        if (typeof app._breadcrumb === 'function') {
          app._breadcrumb('size-cap', originalDispatchId, { size, cap });
        }
        const message =
          `${originalDispatchId.toUpperCase()} file (${mibSize} MiB) exceeds the ` +
          `${mibCap} MiB structured-parse cap — falling back to plain-text view. ` +
          `Open the YARA tab for a manual deep scan.`;
        dispatchId = 'plaintext';
        raw = await RenderRoute._fallbackToPlaintext(app, file, buffer, rctx, message);
      }
    }

    // ── Watchdog-wrapped dispatch ─────────────────────────────────────
    if (raw === undefined) {
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
          if (typeof app._breadcrumb === 'function') {
            app._breadcrumb('watchdog', dispatchId, { timeoutMs: PARSER_LIMITS.RENDERER_TIMEOUT_MS });
          }
          const message =
            `Parser "${dispatchId}" timed out after ${secs}s — falling back to ` +
            `plain-text view. Open the YARA tab for a manual deep scan.`;
          const timedOutId = dispatchId;
          dispatchId = 'plaintext';
          raw = await RenderRoute._fallbackToPlaintext(app, file, buffer, rctx, message);
          analyzer = null;
          // Surface the timed-out renderer name for downstream telemetry
          // (e.g. dev-mode breadcrumb display).
          rctx._timedOutDispatchId = timedOutId;
        } else {
          throw renderErr;
        }
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

    // Centralised LF-normalisation for the sidebar's click-to-focus engine.
    const rawTextSource = (docEl && docEl._rawText)
      || (docEl && docEl.textContent)
      || '';
    const rawText = lfNormalize(rawTextSource);

    // Fill in the remaining fields of the in-flight currentResult. The
    // skeleton already holds `buffer` and any `binary` / `yaraBuffer`
    // writes the renderer made.
    const result = app.currentResult;
    result.docEl = docEl;
    result.findings = app.findings;
    result.rawText = rawText;
    result.navTitle = file.name;
    result.analyzer = analyzer;
    result.dispatchId = dispatchId;

    return result;
  },
};


window.RenderRoute = RenderRoute;
