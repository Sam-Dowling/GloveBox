'use strict';
// ════════════════════════════════════════════════════════════════════════════
// render-route.js — central renderer dispatch
// ════════════════════════════════════════════════════════════════════════════
//
// `RenderRoute.run(file, buffer, app, rctx?)` is the single entry point that
// connects `RendererRegistry.detect()` to the per-id handlers in
// `App.prototype._rendererDispatch` (defined in `src/app/app-load.js`). It
// owns six concerns that previously lived inline in `App._loadFile`:
//
//   1. **Parser-watchdog wrap.** Every renderer is invoked under
//      `ParserWatchdog.run(..., { timeout: PARSER_LIMITS.RENDERER_TIMEOUT_MS,
//      name: dispatchId })`. On a watchdog timeout we reset the partial
//      state the hung renderer may have written (`app.findings`,
//      `app.currentResult.binary`, `app.currentResult.yaraBuffer`), hand
//      the buffer to the `plaintext` handler, and surface a single
//      `IOC.INFO` row explaining why the structured viewer didn't load.
//      Genuine parser exceptions ALSO route through the same plaintext
//      fallback (PLAN.md C4) — the failure surface used to be a bare
//      "Failed to open file" toast, which is the wrong default for a
//      tool whose job is to survive corrupt input gracefully.
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
//                      consumed by `app-yara.js`, copy-analysis, and
//                      every downstream sweep that needs the raw bytes.
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
//      fallback (watchdog timeout, size-cap, or any thrown error), a
//      single visible `IOC.INFO` row is pushed onto the now-`plaintext`
//      findings explaining what just happened so the analyst is never
//      left wondering why a structured viewer didn't load.
//
//   6. **Render-epoch fence.** The caller (`App._loadFile`,
//      `App._restoreNavFrame`, `App._clearFile`) owns the epoch — it
//      bumps `app._renderEpoch` and installs the fresh `currentResult`
//      skeleton in a single step via `App._setRenderResult(result)` and
//      passes the captured epoch into `RenderRoute.run(file, buffer,
//      app, rctx, epoch)`. `run()` itself never bumps the counter; it
//      only reads it. On every fallback (watchdog timeout, size-cap,
//      thrown error) `_orphanInFlight` swaps in a fresh `currentResult`
//      skeleton + a fresh `findings` object so the previous renderer's
//      still-running async work keeps a stale reference to the *old*
//      skeleton and old findings — its late writes
//      (`this.currentResult.binary = …`, `this.findings.X.push(…)`)
//      land on orphan objects and never reach the live UI. The old
//      `findings` is `Object.freeze`-d before being orphaned so any
//      late `.push(...)` against it throws under strict mode and is
//      caught by the global error handler / breadcrumb stream — turning
//      a silent wrong-answer into either a no-op or a visible
//      diagnostic. The epoch is NOT bumped on fallback — doing so would
//      trip the end-of-run `epoch !== app._renderEpoch` supersession
//      guard on every fallback path and `_loadFile` would early-return
//      on the resulting `_superseded` sentinel, leaving the page blank
//      instead of painting the plaintext view. The only legitimate
//      epoch bump is the caller's `_setRenderResult` call.

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

  /** Build a fresh, empty `findings` object. Shape mirrors the constructor
   *  state expected by `_renderSidebar` and `pushIOC()`. */
  _emptyFindings() {
    return { risk: 'low', externalRefs: [], interestingStrings: [], metadata: {} };
  },

  /** Orphan the hung/failed renderer's write targets so its late writes
   *  can never reach the live UI. Called from `_fallbackToPlaintext`
   *  *within the same `run()` invocation* — the epoch was already
   *  bumped on entry to `run()` and must not be bumped again here, or
   *  the end-of-run `epoch !== app._renderEpoch` supersession guard
   *  would fire on every fallback path and `App._loadFile` would early-
   *  return on the resulting `_superseded` sentinel, leaving the page
   *  blank instead of painting the plaintext view.
   *
   *  Mechanics (PLAN.md C1 Phase 1):
   *    1. The previous `app.findings` is `Object.freeze`-d before being
   *       replaced so any continued `findings.X.push(...)` from the
   *       hung renderer throws under strict mode. The throw is caught
   *       by the global error handler and turned into a breadcrumb;
   *       the worst case is "no-op", never "silent corruption".
   *    2. `app.findings` and `app.currentResult` are replaced with
   *       fresh empty objects so continued `currentResult.binary = …` /
   *       `findings.X = …` writes from the hung renderer land on the
   *       orphaned references and never reach the live UI.
   *
   *  Returns the (unchanged) current epoch for callers that want it.
   */
  _orphanInFlight(app, buffer) {
    if (app.findings && typeof Object.freeze === 'function') {
      try { Object.freeze(app.findings); } catch (_) { /* best-effort */ }
    }
    app.findings = RenderRoute._emptyFindings();
    app.currentResult = RenderRoute._emptyResult(buffer);
    return app._renderEpoch;
  },


  /** Reset partial render state (findings + binary/yaraBuffer stamps),
   *  hand the buffer to the plaintext renderer, and push a sidebar
   *  `IOC.INFO` row explaining the fallback. Shared by all three
   *  fallback triggers (watchdog timeout, per-dispatch size cap, and
   *  generic renderer exception) so they produce identical sidebar
   *  state. Returns the plaintext renderer's raw return value
   *  (HTMLElement or `{docEl, analyzer?}`). */
  async _fallbackToPlaintext(app, file, buffer, rctx, infoMessage) {
    // Orphan the hung/failed renderer's write targets BEFORE invoking
    // the plaintext handler. This freezes the previous findings (so any
    // late `.push(...)` throws and is caught upstream rather than
    // silently corrupting the plaintext view's sidebar) and swaps in a
    // fresh skeleton for the plaintext renderer to write into. The
    // render epoch is *not* bumped here — it was already bumped on
    // entry to `run()` and bumping again would trip the end-of-run
    // supersession guard (`epoch !== app._renderEpoch`) on every
    // fallback path, returning `_superseded: true` and leaving the
    // page blank instead of painting the plaintext view.
    RenderRoute._orphanInFlight(app, buffer);


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
   * @param {number?}     epoch   — caller-supplied epoch token, captured
   *                                from `App._setRenderResult(...)`. The
   *                                end-of-run guard compares this against
   *                                the live `app._renderEpoch` and
   *                                returns a `{ _superseded: true }`
   *                                sentinel if a newer load has bumped
   *                                the counter mid-flight. When omitted,
   *                                the current value is captured (only
   *                                callers that aren't already routing
   *                                through `_setRenderResult` end up
   *                                here, and they don't get cross-load
   *                                fencing).
   * @returns {Promise<RenderResult>}
   */
  async run(file, buffer, app, rctx = null, epoch = null) {
    rctx = rctx || RendererRegistry.makeContext(file, buffer);
    const decision = RendererRegistry.detect(rctx);
    let dispatchId = decision.id;
    let handler = app._rendererDispatch[dispatchId] || app._rendererDispatch.plaintext;

    // The caller (`App._loadFile` / `_restoreNavFrame` / `_clearFile`)
    // owns the epoch — they bump `app._renderEpoch` and install the
    // fresh `currentResult` skeleton in a single step via
    // `App._setRenderResult(...)` and pass the captured value here.
    // `run()` only reads it. Callers that don't supply an epoch (defensive
    // / legacy paths that bypass `_setRenderResult`) silently capture the
    // current value — they get the in-flight orphan-on-fallback
    // protection but no cross-load supersession fencing.
    if (epoch == null) epoch = app._renderEpoch || 0;

    // The caller already installed a fresh `currentResult` skeleton via
    // `_setRenderResult`, so per-renderer stamps
    // (`this.currentResult.binary = …`, `this.currentResult.yaraBuffer
    // = …`) already have a live write target. Defensive top-up: if a
    // legacy caller routed through `run()` without going through
    // `_setRenderResult` first, install a skeleton now so the renderer
    // doesn't NPE on the first stamp.
    if (!app.currentResult) {
      app.currentResult = RenderRoute._emptyResult(buffer);
    }

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
          // The watchdog hands us `{ signal }` as the sole arg; ignored
          // by every renderer today (the contract is strictly additive).
          // Phase-2 will migrate the long-running loops in
          // PE/ELF/Mach-O/EVTX/encoded-content to honour `signal.aborted`.
          () => handler.call(app, file, buffer, rctx),
          { timeout: PARSER_LIMITS.RENDERER_TIMEOUT_MS, name: dispatchId }
        );
      } catch (renderErr) {
        // Two fallback shapes:
        //   • Watchdog timeout (`err._watchdogTimeout`) → user-facing
        //     "this took too long" message.
        //   • Anything else (RangeError from a bad header, OleCfbParser
        //     bounds exception, JSZip rejection, ...) → graceful
        //     plaintext fallback with the original error attached as a
        //     visible sidebar warning. PLAN.md C4: a security analyser
        //     whose job is to *survive* corrupt input must not paint
        //     "Failed to open file" on a truncated PE / EVTX / SQLite.
        //
        // Both paths route through the same `_fallbackToPlaintext`
        // helper so the sidebar state is identical regardless of the
        // trigger.
        if (dispatchId === 'plaintext') {
          // Degenerate case — plaintext itself failed. Let the caller
          // paint the "Failed to open file" box.
          throw renderErr;
        }

        const isTimeout = !!(renderErr && renderErr._watchdogTimeout);
        let message;
        if (isTimeout) {
          const secs = (PARSER_LIMITS.RENDERER_TIMEOUT_MS / 1000) | 0;
          console.warn(
            `[loupe] Renderer "${dispatchId}" timed out after ${secs}s — falling back to plain-text view`
          );
          if (typeof app._breadcrumb === 'function') {
            app._breadcrumb('watchdog', dispatchId, { timeoutMs: PARSER_LIMITS.RENDERER_TIMEOUT_MS });
          }
          message =
            `Parser "${dispatchId}" timed out after ${secs}s — falling back to ` +
            `plain-text view. Open the YARA tab for a manual deep scan.`;
        } else {
          const errMsg = (renderErr && renderErr.message) ? renderErr.message : String(renderErr);
          console.warn(
            `[loupe] Renderer "${dispatchId}" threw "${errMsg}" — falling back to plain-text view`
          );
          if (typeof app._breadcrumb === 'function') {
            app._breadcrumb('renderer-error', dispatchId, { message: errMsg });
          }
          message =
            `Parser "${dispatchId}" failed (${errMsg}) — falling back to plain-text view. ` +
            `The file may be truncated or malformed. Open the YARA tab for a manual deep scan.`;
        }

        const failedId = dispatchId;
        dispatchId = 'plaintext';
        raw = await RenderRoute._fallbackToPlaintext(app, file, buffer, rctx, message);
        analyzer = null;
        // Surface the failed renderer name for downstream telemetry
        // (e.g. dev-mode breadcrumb display).
        rctx._timedOutDispatchId = isTimeout ? failedId : null;
        rctx._failedDispatchId   = isTimeout ? null     : failedId;
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

    // Final stale-epoch guard. If `App._setRenderResult` was called
    // (fast file-swap, drill-down, Back navigation, file close) while
    // this dispatch was still running, `app._renderEpoch` will have
    // moved past the value the caller captured for us. The writes below
    // would clobber the new state's freshly-installed `currentResult` /
    // `findings` — bail with a `_superseded` sentinel and let the caller
    // (`App._loadFile`) early-return without painting stale results.
    if (epoch !== app._renderEpoch) {
      // Return a synthetic result; the caller will see a non-null
      // skeleton it can ignore. The current epoch's `currentResult`
      // is unaffected.
      return {
        docEl: null,
        findings: app.findings,
        rawText: '',
        buffer: buffer || null,
        binary: null,
        yaraBuffer: null,
        navTitle: file.name,
        analyzer: null,
        dispatchId: dispatchId,
        _superseded: true,
      };
    }

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
