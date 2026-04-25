'use strict';
// ════════════════════════════════════════════════════════════════════════════
// render-route.js — central renderer dispatch (PLAN D1)
// ════════════════════════════════════════════════════════════════════════════
//
// `RenderRoute.run(file, buffer, app, rctx?)` is the single entry point that
// connects `RendererRegistry.detect()` to the per-id handlers in
// `App.prototype._rendererDispatch` (defined in `src/app/app-load.js`). It
// owns three concerns that previously lived inline in `App._loadFile`:
//
//   1. **Parser-watchdog wrap (PLAN B5).** Every renderer is invoked under
//      `ParserWatchdog.run(..., { timeout: PARSER_LIMITS.RENDERER_TIMEOUT_MS,
//      name: dispatchId })`. On a watchdog timeout we reset the partial
//      state the hung renderer may have written (`app.findings`,
//      `app._binaryParsed` / `_binaryFormat`, `app._yaraBuffer`), hand the
//      buffer to the `plaintext` handler, and surface a single `IOC.INFO`
//      row explaining why the structured viewer didn't load. Genuine parser
//      exceptions (i.e. errors that are NOT a watchdog timeout) bubble out
//      to the caller's outer `catch` — the failure surface is unchanged
//      from before D1.
//
//   2. **`RenderResult` normalisation.** Renderer handlers today return
//      either a bare `HTMLElement` (legacy) or `{ docEl, analyzer? }`. The
//      RenderResult object surfaced to `_loadFile` is the canonical
//      typedef from `PLAN.md` Track D1:
//        ```
//        { docEl, findings, rawText, binary?, navTitle, analyzer?, dispatchId }
//        ```
//      • `docEl`     — the view container, ready to mount under
//                      `#page-container`.
//      • `findings`  — read-through to `app.findings` (renderers still
//                      mutate the App-level field; D4 will move this to a
//                      return value).
//      • `rawText`   — `lfNormalize(docEl._rawText || docEl.textContent || '')`.
//                      This is the centralised LF-normalisation the
//                      `_loadFile` post-render passes (IOC sweep, encoded-
//                      content scan) read from. Even a renderer that
//                      forgot to LF-normalise `docEl.textContent` (the
//                      fallback path) won't misalign click-to-focus
//                      offsets after the first CR — the issue tracked as
//                      H3 in `PLAN.md`.
//      • `binary`    — `{ format, parsed }` when the renderer stamped
//                      `app._binaryFormat` (PE / ELF / Mach-O); absent
//                      for non-binary loads.
//      • `navTitle`  — defaults to `file.name`. Reserved for D3 / D4.
//      • `analyzer`  — pass-through for the DOCX module-renderer path
//                      (`SecurityAnalyzer` is the only renderer-side
//                      object the sidebar still consults directly).
//      • `dispatchId`— the registry decision id (e.g. `'pdf'`, `'pe'`).
//
//   3. **`app.currentResult` stamping.** The result is also assigned to
//      `app.currentResult` so future tracks can migrate read sites off the
//      scattered `app._fileBuffer` / `app._binaryParsed` / `app._latestIOCs`
//      globals. **D1 does not yet rewrite any consumer** — the sidebar,
//      copy-analysis, and YARA paths still read the legacy fields. D4
//      replaces them with `app.currentResult.*` and adds deprecation
//      aliases for one release cycle.
//
// What `RenderRoute.run` deliberately does NOT do:
//
//   • It does not read or write `app._fileBuffer` / `app._yaraBuffer` /
//     `app._binaryParsed` / `app._binaryFormat`. Those are still set
//     directly by the per-id handlers in `_rendererDispatch` (PE / ELF /
//     Mach-O / SVG / HTML / Plist / OsaScript). D4 cuts them over.
//   • It does not run the post-render IOC sweep, encoded-content scan,
//     hash join, sidebar render, or auto-YARA. Those still live in
//     `App._loadFile` after the `RenderRoute.run(...)` call returns.
//   • It does not handle the Timeline branch — Timeline is an intentional
//     analysis-bypass route (`_loadFileInTimeline`) that never touches
//     the registry. RenderRoute is for the generic branch only.
//   • It does not own the `_rendererDispatch` table. The table stays in
//     `app-load.js`; D4 moves it (or the equivalent) into a registry-
//     driven structure once the renderer return-shape migration is far
//     enough along that the table can be regenerated mechanically.
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
   *                                context. Callers that already
   *                                memoised one (none today, but D2/D3
   *                                may) can pass it in; otherwise we
   *                                build it from `(file, buffer)`.
   * @returns {Promise<RenderResult>}
   */
  async run(file, buffer, app, rctx = null) {
    rctx = rctx || RendererRegistry.makeContext(file, buffer);
    const decision = RendererRegistry.detect(rctx);
    const dispatchId = decision.id;
    const handler = app._rendererDispatch[dispatchId] || app._rendererDispatch.plaintext;

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
        app._binaryParsed = null;
        app._binaryFormat = null;
        app._yaraBuffer = null;
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
    //
    // Legacy renderers return a bare `HTMLElement`; the dispatch handlers
    // wrap that into `{ docEl, analyzer? }` before we get here. A few
    // older paths still hand back the raw element directly — accept both.
    let docEl;
    if (raw && raw.nodeType === 1) {
      // bare HTMLElement
      docEl = raw;
    } else if (raw && raw.docEl) {
      docEl = raw.docEl;
      if (raw.analyzer && !analyzer) analyzer = raw.analyzer;
    } else {
      // Defensive: handler returned nothing usable. Caller's outer catch
      // will render the "Failed to open file" box if docEl is undefined.
      docEl = null;
    }

    // Centralised LF-normalisation (PLAN H3 fix). `docEl._rawText` is
    // already required to be LF-normalised at every renderer write site
    // (B4 build gate), but `docEl.textContent` — the fallback when a
    // renderer didn't attach `_rawText` — has no such guarantee. Run the
    // result through `lfNormalize` once, here, so every downstream
    // consumer (IOC sweep, encoded-content scan, click-to-focus string
    // search) sees a single consistent line-ending convention.
    const rawTextSource = (docEl && docEl._rawText)
      || (docEl && docEl.textContent)
      || '';
    const rawText = lfNormalize(rawTextSource);

    const result = {
      docEl,
      findings: app.findings,
      rawText,
      navTitle: file.name,
      analyzer,
      dispatchId,
    };
    if (app._binaryFormat) {
      result.binary = { format: app._binaryFormat, parsed: app._binaryParsed || null };
    }

    // D2 / D3 / D4 will read from `app.currentResult` exclusively. D1
    // just stamps it as a read-only mirror so existing call sites
    // (sidebar, copy-analysis, auto-YARA) continue reading the legacy
    // `app._fileBuffer` / `app._binaryParsed` / `app._latestIOCs` fields
    // unchanged.
    app.currentResult = result;

    return result;
  },
};

window.RenderRoute = RenderRoute;
