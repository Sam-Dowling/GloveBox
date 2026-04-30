// ════════════════════════════════════════════════════════════════════════════
// _md5  — compact pure-JS MD5 (crypto.subtle doesn't support MD5)
// ════════════════════════════════════════════════════════════════════════════
function _md5(bytes) {
  function add(x, y) { const l = (x & 0xFFFF) + (y & 0xFFFF); return (((x >> 16) + (y >> 16) + (l >> 16)) << 16) | (l & 0xFFFF); }
  function rol(x, n) { return (x << n) | (x >>> (32 - n)); }
  const T = []; for (let i = 1; i <= 64; i++)T[i] = Math.floor(Math.abs(Math.sin(i)) * 0x100000000) >>> 0;
  const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const n = bytes.length, pad = new Uint8Array((n + 72) & ~63);
  pad.set(bytes); pad[n] = 0x80;
  const dv = new DataView(pad.buffer);
  dv.setUint32(pad.length - 8, n << 3, true); dv.setUint32(pad.length - 4, n >>> 29, true);
  let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
  for (let o = 0; o < pad.length; o += 64) {
    const W = []; for (let i = 0; i < 16; i++)W[i] = dv.getUint32(o + i * 4, true);
    let A = a, B = b, C = c, D = d;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = 7 * i % 16; }
      F = add(add(add(F, A), W[g]), T[i + 1]);
      A = D; D = C; C = B; B = add(B, rol(F, S[i]));
    }
    a = add(a, A); b = add(b, B); c = add(c, C); d = add(d, D);
  }
  return [a, b, c, d].map(v => [v & 255, v >> 8 & 255, v >> 16 & 255, v >> 24 & 255].map(x => x.toString(16).padStart(2, '0')).join('')).join('');
}

// ════════════════════════════════════════════════════════════════════════════
// Defanged URL/IP/email refanging — `_refangString` is defined in
// `src/ioc-extract.js` (worker-safe global) and shared between the host IOC
// shim, the IOC worker, and the EML / MSG renderers. Do NOT redeclare it
// here.
// ════════════════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════════════
// App — file loading, hashing, interesting-string extraction
// ════════════════════════════════════════════════════════════════════════════
extendApp({

  // ── Single chokepoint for `currentResult` writes + epoch bump ──────────
  //
  // Every code path that swaps the App's render result (a fresh load, a
  // back-navigation, a file close) must go through this helper so the
  // `_renderEpoch` counter advances atomically with the slot it fences.
  // The previous file's still-running renderer captured the *old* epoch
  // when its `RenderRoute.run` invocation started; the moment we bump the
  // counter here, the supersession guard at the end of `run()` flips its
  // "do my writes still belong to the live UI" check from yes to no, and
  // the old work returns a `_superseded` sentinel instead of clobbering
  // the freshly-installed `currentResult` / `findings`.
  //
  // The only other write site is `RenderRoute._orphanInFlight` — it
  // swaps in a fresh skeleton on a watchdog timeout / size-cap / thrown
  // error inside the *same* `run()` invocation and explicitly does NOT
  // bump the epoch (bumping mid-`run()` would trip the end-of-run guard
  // on every fallback path and blank the page; see render-route.js
  // header for the full reasoning).
  //
  // Returns the new epoch so callers can capture it for the eventual
  // `RenderRoute.run(..., epoch)` call.
  _setRenderResult(result) {
    this._renderEpoch = (this._renderEpoch || 0) + 1;
    this.currentResult = result;
    // ── Sidebar highlight active-view refs ─────────────────────────────
    // Every view transition (file clear, drill-down via openInnerFile,
    // Timeline ↔ renderer pivot) routes through here. The two
    // `*HighlightActiveView` fields hold a back-reference to the
    // GridViewer that owns the live YARA / IOC highlight. After a
    // transition the previous view is being torn down, so the ref must
    // be cleared here to prevent `_clearYaraHighlight` /
    // `_clearIocCsvHighlight` from poking a destroyed grid. `_clearFile`
    // already nulls these too, but routing through this single
    // chokepoint covers drill-down and Timeline-pivot paths that don't
    // pass through `_clearFile`.
    this._yaraHighlightActiveView = null;
    this._iocCsvHighlightActiveView = null;
    return this._renderEpoch;
  },

  async _loadFile(file, prefetchedBuffer /* optional – passed by Timeline fallback */) {
    // ── Stale-load token bump ───────────────────────────────
    // Monotonic per-`_loadFile` invocation. Async work queued by the
    // *previous* load (QR decoders running over a PDF page raster, the
    // crypto.subtle SHA-256 of a PE overlay, an OneNote
    // FileDataStoreObject decode that lost a race with a quick Back-
    // then-forward navigation) may resolve **after** this method
    // returns and try to call `App.updateFindings(patch, { token })`.
    // The mutator no-ops when the supplied token doesn't match the
    // current value, so a deferred mutation can never paint into the
    // *next* file's findings / sidebar. Defaults to 0 on first load;
    // `_clearFile` resets it to 0 on file close so a stranded post-
    // close mutation also no-ops.
    this._loadToken = (this._loadToken || 0) + 1;

    // ── Debug breadcrumb ────────────────────────────────────
    // Cheap O(1) push into a 50-entry circular buffer; renders only when
    // the dev-mode panel is mounted. Captures the headline parameters of
    // the load so a user reporting "format X failed" can include the
    // filename + size in their breadcrumb dump.
    if (typeof this._breadcrumb === 'function') {
      this._breadcrumb('load', file && file.name ? file.name : '<unnamed>', {
        size: file && typeof file.size === 'number' ? file.size : null,
        prefetched: !!prefetchedBuffer,
        token: this._loadToken,
      });
    }

    // ── Timeline intercept ────────────────────────────────────────────
    // Every CSV / TSV / EVTX file opens in the Timeline view
    // unconditionally. `_timelineTryHandle` returns truthy when it
    // recognises the extension and dispatches the load; the regular
    // analyser pipeline only runs when it returns falsy. Extensionless
    // files are picked up below after the buffer is read via a magic-
    // byte / text sniff (`_sniffTimelineContent`).
    //
    // The `_skipTimelineRoute` flag is an escape-hatch used by the
    // Timeline loader itself: if the factory yields zero usable rows
    // (EVTX with an unreadable header, empty CSV) it re-enters
    // `_loadFile` with the flag set so the file degrades into the
    // analyser's hex/strings view instead of dead-ending.
    if (!this._skipTimelineRoute
      && this._timelineTryHandle
      && this._timelineTryHandle(file)) return;

    // ── YARA worker cancellation ────────────────────────────
    // A YARA scan from the *previous* file may still be running in a
    // worker. Terminate it now so the upcoming auto-scan isn't racing
    // against a superseded result, and so a 100 MiB scan abandoned by
    // a quick Back-then-forward navigation doesn't keep a worker alive
    // for tens of seconds. Cheap no-op when nothing is in flight or
    // when the WorkerManager probe has already failed.
    if (window.WorkerManager && WorkerManager.cancelYara) {
      WorkerManager.cancelYara();
    }

    // ── Timeline worker cancellation ────────────────────────
    // Same rationale as the YARA cancellation above — a Timeline parse
    // (CSV / TSV / EVTX / SQLite browser-history) from the previous
    // file may still be inflating in a worker. Terminate it now so the
    // upcoming load isn't racing a superseded `done` postback. Cheap
    // no-op when nothing is in flight or when the WorkerManager probe
    // has already failed.
    if (window.WorkerManager && WorkerManager.cancelTimeline) {
      WorkerManager.cancelTimeline();
    }

    // ── Encoded-content worker cancellation ─────────────────
    // Same rationale as the YARA / Timeline cancellations above — the
    // EncodedContentDetector scan from the previous file may still be
    // chasing nested base64 / hex / zlib chains in a worker. Terminate
    // it now so the upcoming scan isn't racing a superseded `done`
    // postback. Cheap no-op when nothing is in flight or when the
    // WorkerManager probe has already failed.
    if (window.WorkerManager && WorkerManager.cancelEncoded) {
      WorkerManager.cancelEncoded();
    }

    // ── IOC-extract worker cancellation ─────────────────────
    // Same rationale as the YARA / Timeline / Encoded cancellations
    // above — an in-flight off-thread IOC mass-extract from a previous
    // file (kicked off by `_kickIocExtractWorker` for non-timeline files
    // larger than IOC_WORKER_THRESHOLD_BYTES) would otherwise patch its
    // results into the new file's findings via the resolve handler.
    // Terminate it now so the upcoming load owns `findings.interesting-
    // Strings` cleanly. Cheap no-op when nothing is in flight or when the
    // WorkerManager probe has already failed.
    if (window.WorkerManager && WorkerManager.cancelIocExtract) {
      WorkerManager.cancelIocExtract();
    }

    // ── Sidebar-paint sentinel ─────────────────────────────────────────
    // Cleared at the start of every load so async post-render patchers
    // (`_patchIocFindingsFromWorker`, the IOC-worker fallback shim) can
    // tell whether the natural sidebar paint near the end of `_loadFile`
    // has already happened. When the IOC worker resolves DURING one of the awaits
    // earlier in `_loadFile` (encoded-content / hashPromise) the page
    // DOM swap hasn't run yet and `_currentAnalyzer` may still hold the
    // previous file's value — patching `findings` and skipping the
    // re-render lets the natural paint snapshot the patched data and
    // avoids an early stale render. Set to `true` directly after the
    // natural `_renderSidebar(...)` call.
    this._sidebarPainted = false;

    // ── pdf.worker cancellation ───────────────────────────────────────
    // pdf.js owns its own dedicated worker (`vendor/pdf.worker.js`)
    // outside the C1–C4 `WorkerManager` channels, so the cancellations
    // above won't touch it. PdfRenderer.render() and analyzeForSecurity()
    // register every open `PDFDocumentProxy` on `PdfRenderer._activeDocs`;
    // calling `disposeWorker()` here destroys each one, which causes any
    // pending `getPage()` / `page.render()` / `getJSActions()` against
    // the previous file to reject. Both call sites recognise the
    // `Worker was destroyed` / `AbortException` rejection as a benign
    // supersession (the next file is already loading) and return a
    // partial wrap / partial findings instead of bubbling a "Failed to
    // open file" toast.
    if (typeof PdfRenderer !== 'undefined' && PdfRenderer.disposeWorker) {
      PdfRenderer.disposeWorker();
    }

    // ── Timeline → Non-Timeline teardown ──────────────────────────────
    // If a Timeline view is currently mounted but the new file isn't a
    // Timeline format (otherwise `_timelineTryHandle` above would have
    // short-circuited), the regular analyser pipeline would render into
    // #page-container while the Timeline surface still covers the
    // viewer (body.has-timeline). Clicking the toolbar's X would then
    // route through `_clearTimelineFile` — which also nulls
    // `_fileMeta`, making the filename disappear from the breadcrumb.
    //
    // Do a UI-only teardown here: destroy the old view, empty the
    // host, drop the body class. Leave `_fileMeta`, `findings`,
    // `_navStack`, scroll state alone — the rest of `_loadFile` is
    // about to repopulate them for the incoming file.
    //
    // Extensionless Timeline re-route (below) re-adds `has-timeline`
    // harmlessly if the sniff later routes this file back into the
    // Timeline view.
    if (this._timelineCurrent) {
      try { this._timelineCurrent.destroy(); } catch (_) { /* noop */ }
      this._timelineCurrent = null;
      const tlHost = document.getElementById('timeline-root');
      if (tlHost) tlHost.innerHTML = '';
      document.body.classList.remove('has-timeline');
    }

    // Warn (non-blocking) for very large files so the analyst knows to
    // expect a longer load. Only show when this is a fresh load (not a
    // Timeline zero-row fallback, which already toasted).
    if (!prefetchedBuffer
      && file.size >= RENDER_LIMITS.HUGE_FILE_WARN) {
      const mb = (file.size / (1024 * 1024)).toFixed(0);
      this._toast(
        `Large file (${mb} MB) — loading may take a moment.`, 'info');
    }

    this._setLoading(true);

    // Reset the viewer + sidebar scroll position when a *fresh* file is
    // loaded (drop, picker, paste) so the user always starts at the top
    // of a new analysis. Drill-down loads (archive member, decoded
    // payload, "All the way") push the current frame onto `_navStack`
    // BEFORE calling `_loadFile` — that frame already captured the
    // parent's scroll offsets, so we're safe to clear here. Return-
    // navigation via the breadcrumb trail bypasses `_loadFile` entirely
    // and routes through `_stickyRestoreScroll` instead, so this reset
    // cannot clobber a restored scroll position.
    const viewerEl = document.getElementById('viewer');
    if (viewerEl) { viewerEl.scrollTop = 0; viewerEl.scrollLeft = 0; }
    const sbBodyEl = document.getElementById('sb-body');
    if (sbBodyEl) { sbBodyEl.scrollTop = 0; sbBodyEl.scrollLeft = 0; }

    // Show the breadcrumb trail immediately so the user sees the filename
    // while the (potentially slow) parse runs. The full _fileMeta (entropy,
    // magic, size-with-page-count) is filled in once parsing completes.
    this._fileMeta = { name: file.name, size: file.size };
    this._renderBreadcrumbs();
    const ext = file.name.split('.').pop().toLowerCase();

    try {
      const buffer = prefetchedBuffer
        || await ParserWatchdog.run(() => file.arrayBuffer());
      // ── Extensionless Timeline re-route ──────────────────────────────
      // If the file's extension wasn't a Timeline one (and we didn't set
      // `_skipTimelineRoute` to escape the loop), sniff the buffer for
      // EVTX magic or a CSV/TSV-shaped text head. This catches renamed
      // / extensionless logs that the fast-path `_timelineTryHandle`
      // couldn't spot from the filename alone.
      if (!this._skipTimelineRoute
        && this._sniffTimelineContent
        && !this._isTimelineExt(file)) {
        const sniffed = this._sniffTimelineContent(buffer);
        if (sniffed) {
          this._setLoading(false);
          await this._loadFileInTimeline(file, buffer);
          return;
        }
      }
      // Install a fresh `currentResult` skeleton and bump the render
      // epoch in a single step. The bump is what gives us cross-load
      // supersession: any prior `_loadFile` invocation that's still
      // running (slow PE / EVTX / encoded-content scan after a quick
      // back-to-back file swap) sees `epoch !== app._renderEpoch` at
      // the end-of-`run()` guard and returns `{ _superseded: true }`,
      // which the post-dispatch check below early-returns on. The
      // captured `epoch` is threaded into `RenderRoute.run` so it
      // doesn't have to mint its own; the caller owns the counter.
      const epoch = this._setRenderResult(RenderRoute._emptyResult(buffer));

      // Reset YARA state from previous file to prevent stale results bleeding over
      this._yaraResults = null;
      let docEl, analyzer = null;

      // Store file metadata for sidebar display
      this._fileMeta = {
        name: file.name,
        size: file.size,
        mimeType: file.type || '',
        lastModified: file.lastModified ? new Date(file.lastModified).toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC') : '',
        magic: this._detectMagic(new Uint8Array(buffer)),
        entropy: this._computeEntropy(new Uint8Array(buffer)),
      };

      // Compute file hashes in parallel with parsing
      const hashPromise = this._hashFile(buffer);

      // ── Central renderer dispatch ──────────────────────────
      // `RenderRoute.run` (src/render-route.js) owns the three concerns
      // that previously lived inline here:
      //   1. Build a `RendererRegistry.makeContext()` and ask
      //      `RendererRegistry.detect()` which renderer wins.
      //   2. Invoke the per-id handler from `this._rendererDispatch`
      //      under the parser-watchdog
      //      (`PARSER_LIMITS.RENDERER_TIMEOUT_MS`, 30 s) with a graceful
      //      `PlainTextRenderer` fallback + visible `IOC.INFO` row on
      //      timeout. Genuine parser exceptions still bubble to the
      //      outer `catch (e)` that paints the "Failed to open file"
      //      box — the failure surface is unchanged from before D1.
      //   3. Normalise the handler's return shape into the canonical
      //      `RenderResult` typedef (`{ docEl, findings, rawText, buffer,
      //      binary?, yaraBuffer?, analyzer?, navTitle, dispatchId }`) —
      //      including the centralised `lfNormalize(docEl._rawText ||
      //      docEl.textContent)` that produces consistent click-to-focus
      //      offsets for renderers that emit text via `textContent`
      //      rather than an explicit `_rawText`.
      //   4. Stamp `this.currentResult` — the single canonical handle the
      //      sidebar, copy-analysis, YARA, and drill-down paths all read
      //      from. Renderer dispatchers write `currentResult.binary` /
      //      `currentResult.yaraBuffer` during their body via the
      //      pre-allocated skeleton stamped above.
      //
      // The Timeline branch above is an analysis-bypass route and never
      // reaches `RenderRoute.run`.
      const result = await RenderRoute.run(file, buffer, this, null, epoch);
      // Render-epoch supersession guard. `RenderRoute.run` returns a
      // synthetic `{ _superseded: true }` shape if a newer
      // `_setRenderResult` call (a quick back-to-back file swap, a Back
      // navigation, or `_clearFile`) bumped `app._renderEpoch` while
      // the dispatch was running. A superseded dispatch means a newer
      // load / state-change already owns the UI — bail out silently
      // rather than painting `null` into #page-container or clobbering
      // the new state's freshly-installed findings.
      if (result && result._superseded) {
        return;
      }
      docEl = result.docEl;
      analyzer = result.analyzer || null;
      // Stash the renderer-side analyzer (DOCX `SecurityAnalyzer` is the
      // only one today) so deferred sidebar refreshes triggered by
      // `App.updateFindings` can pass the same analyzer back into
      // `_renderSidebar` without forcing the caller to remember it.
      // `_clearFile` nulls this on file close.
      this._currentAnalyzer = analyzer || null;

      // Extract interesting strings from rendered text + VBA source.
      // `result.rawText` is `lfNormalize(docEl._rawText || docEl.textContent)`
      // — the centralised LF-normalisation introduced by D1, replacing
      // the previous direct `docEl._rawText || docEl.textContent` read
      // (which could leak CRLF past the first CR for renderers that
      // didn't attach `_rawText`).
      const analysisText = result.rawText;
      const rendererIOCs = this.findings.interestingStrings || [];
      // ── IOC mass-extract: sync vs worker dispatch (Batch A) ─────
      // Files <= IOC_WORKER_THRESHOLD_BYTES (256 KB), and any file when
      // workers are unavailable (Firefox `file://`), run the synchronous
      // shim — same byte-equivalent output as before. Above the
      // threshold the regex sweep (URL / email / IPv4 / Windows path /
      // UNC / Unix path / registry key / defanged variants) ships to
      // `WorkerManager.runIocExtract` and a visible "Scanning IOCs…"
      // placeholder row holds the slot in the sidebar until the worker
      // resolves. Timeline-routed files never reach this code
      // (`src/app/timeline/timeline-router.js:16-24`) so the analyser-
      // bypass invariant is preserved by construction. See
      // plans/2026-04-27-loupe-perf-redos-followup-finish-v1.md (Batch A).
      const IOC_WORKER_THRESHOLD_BYTES = 262144;
      const _iocWorkerEligible =
        analysisText.length > IOC_WORKER_THRESHOLD_BYTES
        && typeof WorkerManager !== 'undefined'
        && WorkerManager.workersAvailable && WorkerManager.workersAvailable()
        && typeof WorkerManager.runIocExtract === 'function';
      if (_iocWorkerEligible) {
        // Async path. Insert a placeholder INFO row so the sidebar shows
        // a "Scanning IOCs…" indicator while the worker is in flight.
        // The placeholder carries `_iocScanPlaceholder: true` so the
        // resolve handler can locate + remove it without touching real
        // findings. `_kickIocExtractWorker` schedules the dispatch + the
        // patch-and-rerender step, guarded by the render epoch so a
        // superseding load bails silently.
        const placeholder = {
          type: IOC.INFO,
          url: 'Scanning IOCs…',
          severity: 'info',
          note: 'Off-thread IOC scan in progress',
          _iocScanPlaceholder: true,
        };
        this.findings.interestingStrings = [...rendererIOCs, placeholder];
        // Capture snapshots needed by the resolve handler. The renderer
        // may have populated `findings.modules` (VBA sources) before this
        // point — flatten them now so the worker sees the same input as
        // the synchronous shim.
        const vbaModuleSources = (this.findings.modules || []).map(m => m.source || '');
        // `existingValues` is the host-side dedup seed: every URL the
        // renderer pushed to `externalRefs` / `interestingStrings`
        // (excluding the placeholder we just inserted, which has a
        // dummy "Scanning IOCs…" string that won't collide). Without
        // this, the worker's per-type drop counts and `totalSeenByType`
        // over-report on files whose body text repeats renderer-pushed
        // URLs — see review notes #5 from the 2026-04-27 audit.
        const existingValues = [
          ...((this.findings.externalRefs || []).map(r => r.url)),
          ...rendererIOCs.map(r => r.url),
        ];
        this._kickIocExtractWorker(analysisText, vbaModuleSources, existingValues, file.name, epoch);
      } else {
        const extracted = this._extractInterestingStrings(analysisText, this.findings);
        this.findings.interestingStrings = [...rendererIOCs, ...extracted];
        // Stash per-type truncation info (attached as side-channel props on
        // the returned array in _extractInterestingStrings — array spread
        // below copies only indexed elements, so these props are lost from
        // the flattened findings.interestingStrings list) so the sidebar
        // can render a "Showing N of M <type>" note when extraction was
        // capped. Only attach when something was actually dropped — keeps
        // the property absent (not an empty map) in the common case for
        // easy truthy checks.
        if (extracted._droppedByType && extracted._droppedByType.size > 0) {
          this.findings._iocTruncation = {
            droppedByType: extracted._droppedByType,
            totalSeenByType: extracted._totalSeenByType,
          };
        }
      }

      // ── Encoded content detection ───────────────────────────
      // Worker-first path: `WorkerManager.runEncoded` spawns a Web Worker
      // bundle (encoded-content-detector + decompressor + JSZip + pako)
      // that runs `scan()` and eagerly drives `lazyDecode()` off the main
      // thread. The buffer is transferred, so we ship a `slice(0)` copy —
      // every downstream step in `_loadFile` still needs `buffer`. When
      // the worker probe has failed, or the worker reports an error
      // (rejects with anything other than `'workers-unavailable'`), we
      // fall back to the synchronous main-thread scan that has lived
      // here since before C3. The fallback is the same code path the
      // earlier Track-C lands used — see C1 (yara) / C2 (timeline) for
      // the same pattern.
      try {
        let encodedFindings;
        // Aggressive mode is single-shot — clear it before the scan so
        // a later "regular" inner-file load (e.g. a renderer's
        // open-inner-file event) doesn't accidentally inherit the flag
        // from an earlier selection-decode click.
        const aggressive = !!this._pendingAggressiveDecode;
        this._pendingAggressiveDecode = false;
        const bruteforce = !!this._pendingBruteforceDecode;
        this._pendingBruteforceDecode = false;
        try {
          const out = await WorkerManager.runEncoded(
            buffer.slice(0),
            analysisText,
            {
              fileType: ext,
              mimeAttachments: this.findings._mimeAttachments || null,
              aggressive,
              bruteforce,
            }
          );
          encodedFindings = out.findings || [];
        } catch (workerErr) {
          // A newer file load has bumped the encoded-channel token and
          // aborted this scan. Re-throw so the outer catch can bail
          // without running the synchronous fallback (which would burn
          // CPU on a buffer the new load already replaced) and without
          // overwriting `this.findings.encodedContent` mid-flight.
          if (workerErr && workerErr.message === 'superseded') throw workerErr;
          if (workerErr && workerErr.message !== 'workers-unavailable') {
            // Worker path failed but the synchronous fallback below still
            // succeeds — silent:true keeps the IOC list clean while the
            // breadcrumb console.warn inside _reportNonFatal preserves the
            // diagnostic for devs.
            this._reportNonFatal('encoded-worker-fallback', workerErr, { silent: true });
          }
          const detector = new EncodedContentDetector({ aggressive, bruteforce });
          encodedFindings = await detector.scan(
            analysisText,
            new Uint8Array(buffer),
            {
              fileType: ext,
              existingIOCs: this.findings.interestingStrings,
              mimeAttachments: this.findings._mimeAttachments || null,
            }
          );
          // Speculatively decode lazy findings so sidebar can show decoded
          // previews immediately (base64/hex decode is lightweight; skip
          // compressed blobs). The worker path already drove this
          // eagerly inside the worker, so only run on the fallback path.
          await Promise.all(
            encodedFindings
              .filter(ef => ef.rawCandidate && !ef.decodedBytes)
              .map(ef => detector.lazyDecode(ef))
          );
        }
        // ── Phase 1 — YARA-gated retention (additive evidence pass) ──────
        // Stamp `_yaraHits` on every retained decoded payload that matches
        // the curated `applies_to = "decoded-payload"` rule subset. The
        // gate is purely additive: findings the worker already kept stay
        // kept, but each retained finding now carries the rule names that
        // confirm "this decode is actually interesting". Bruteforce mode
        // is skipped because the analyst has explicitly opted into noise.
        // Any rejection (probe failure, supersession, watchdog) is a
        // silent no-op — the existing `_pruneFindings` result still stands.
        try {
          if (window.DecodedYaraFilter
              && typeof DecodedYaraFilter.applyDecodedYaraGate === 'function'
              && typeof this._getAllYaraSource === 'function') {
            const yaraSource = this._getAllYaraSource();
            if (yaraSource) {
              await DecodedYaraFilter.applyDecodedYaraGate(encodedFindings, {
                source:     yaraSource,
                bruteforce,
                workerManager: window.WorkerManager,
              });
            }
          }
        } catch (yaraGateErr) {
          // The gate is best-effort. Log via the breadcrumb channel but
          // don't abort the post-encoded merge below — the existing
          // worker-prune already removed the worst trash.
          this._reportNonFatal('decoded-yara-gate', yaraGateErr, { silent: true });
        }

        this.findings.encodedContent = encodedFindings;
        // Store raw bytes reference on compressed findings for lazy decompression
        for (const ef of encodedFindings) {
          if (ef.needsDecompression) ef._rawBytes = new Uint8Array(buffer);
          // Merge IOCs from decoded content into main findings.
          // Attach source location metadata so clicking an IOC from a nested
          // decoded layer will smooth-scroll and highlight the *encoded blob*
          // in the original document from which this IOC was extracted.
          if (ef.iocs && ef.iocs.length) {
            const existingUrls = new Set((this.findings.interestingStrings || []).map(r => r.url));
            for (const ioc of ef.iocs) {
              if (!existingUrls.has(ioc.url)) {
                // Point back to the parent encoded blob's location in the source text
                if (ef.offset !== undefined && ef.length) {
                  ioc._sourceOffset = ef.offset;
                  ioc._sourceLength = ef.length;
                  ioc._highlightText = ef.snippet || (analysisText ? analysisText.substring(ef.offset, ef.offset + Math.min(ef.length, 200)) : '');
                }
                // Note which decode chain produced this IOC
                if (ef.chain && ef.chain.length) {
                  ioc._decodedFrom = ef.chain.join(' → ');
                }
                // Back-reference to parent encoded finding for cross-flash linking
                ioc._encodedFinding = ef;
                this.findings.interestingStrings.push(ioc);
                existingUrls.add(ioc.url);
              } else {
                // IOC already exists from plaintext extraction — set back-reference
                // on the existing entry so cross-flash linking from Encoded Content
                // "IOCs" badge scrolls to the correct Signatures & IOCs row
                const existing = this.findings.interestingStrings.find(r => r.url === ioc.url);
                if (existing && !existing._encodedFinding) {
                  existing._encodedFinding = ef;
                  if (ef.chain && ef.chain.length) {
                    existing._decodedFrom = ef.chain.join(' → ');
                  }
                }
              }
            }
          }
        }
      } catch (encErr) {
        // Supersession is not an error — a newer load is already in
        // flight and owns `this.findings.encodedContent`. Leaving the
        // field untouched lets the new load populate it without a
        // window where it briefly reads `[]`.
        if (encErr && encErr.message === 'superseded') {
          // intentional no-op
        } else {
          this._reportNonFatal('encoded-content', encErr);
          this.findings.encodedContent = [];
        }
      }

      // Bump overall risk if encoded content findings have high severity
      this._updateRiskFromEncodedContent();

      const pc = document.getElementById('page-container');
      pc.innerHTML = ''; pc.appendChild(docEl);

      const dz = document.getElementById('drop-zone');
      dz.className = 'has-document'; dz.innerHTML = '';

      const pages = pc.querySelectorAll('.page').length;
      // Stash the page count on the single-source-of-truth _fileMeta so the
      // breadcrumb can show it as meta text next to the current crumb.
      this._fileMeta.pages = pages;
      this._renderBreadcrumbs();
      document.getElementById('btn-close').classList.remove('hidden');
      document.getElementById('viewer-toolbar').classList.remove('hidden');


      // Enable grab-to-pan on non-plaintext views
      const viewer = document.getElementById('viewer');
      const isPlaintext = !!pc.querySelector('.plaintext-view, .hex-view');
      viewer.classList.toggle('pannable', !isPlaintext);

      // Await hashes and render sidebar
      this.fileHashes = await hashPromise;
      // Single canonical nicelist tagging — see src/nicelist-annotate.js
      // header for the rationale. Must run BEFORE `_renderSidebar` so the
      // sidebar IOC section sees `_nicelisted`/`_nicelistSource` already
      // set, AND before any export-pipeline consumer (`_collectIocs`,
      // STIX, MISP, CSV) reads from the findings. Idempotent — the
      // worker-fallback path that re-runs after the IOC worker resolves
      // calls this again before it re-paints.
      if (typeof annotateNicelist === 'function') annotateNicelist(this.findings);
      this._renderSidebar(file.name, analyzer);
      // Sentinel for async post-render patchers — see the early reset
      // above (`this._sidebarPainted = false;`) for the rationale. After
      // this point, `_patchIocFindingsFromWorker` and the IOC-worker
      // fallback shim are free to re-render directly.
      this._sidebarPainted = true;

      // If the renderer decoded non-UTF-8 content (e.g. UTF-16LE PowerShell),
      // re-encode as UTF-8 for YARA scanning so text-based rules can match.
      // Route through `currentResult.yaraBuffer` (not `currentResult.buffer`)
      // so Save / Copy raw keep the original on-disk bytes — renderers like
      // OsascriptRenderer expose a string-extraction view via `_rawText`
      // that is NOT the file's real content. Respect any yaraBuffer already
      // set by an earlier site (SVG / HTML / Plist / Scpt augmented buffer).
      if (docEl._rawText && !this.currentResult.yaraBuffer) {
        this.currentResult.yaraBuffer = new TextEncoder().encode(docEl._rawText).buffer;
      }

      // Auto-run YARA scan against loaded file
      this._autoYaraScan();

      // Breadcrumb was already rendered up front; re-render now so the
      // current layer shows its final page count / size suffix.
      this._renderBreadcrumbs();

    } catch (e) {
      console.error(e);
      this._toast(`Failed to open: ${e.message}`, 'error');
      // Clear stale binary-triage state so the sidebar doesn't render
      // PE/ELF/Mach-O sections from a previous successful load.
      if (this.currentResult) this.currentResult.binary = null;
      const pc = document.getElementById('page-container'); pc.innerHTML = '';
      const eb = document.createElement('div'); eb.className = 'error-box';
      const h3 = document.createElement('h3'); h3.textContent = 'Failed to open file'; eb.appendChild(h3);
      const p1 = document.createElement('p'); p1.textContent = e.message; eb.appendChild(p1);
      pc.appendChild(eb);
    } finally { this._setLoading(false); }
  },

  // ── App.updateFindings ────────────────────────────────────────
  //
  // Public mutator for late-arriving findings. Renderers must continue to
  // mutate `app.findings` synchronously during `render()` /
  // `analyzeForSecurity()` (the renderer contract has not changed —
  // `_renderSidebar` still snapshots a complete picture at the moment
  // `_loadFile` resolves). What this helper exists for is the *deferred*
  // case: an async pdf.worker page raster QR decode, an OneNote
  // FileDataStoreObject inflate, an `crypto.subtle.digest('SHA-256',
  // overlayBytes)` for a PE/ELF/Mach-O overlay, an Image-renderer's
  // post-paint TIFF IFD walk — anything that produces an IOC / metadata
  // field / risk escalation **after** `_renderSidebar` has already painted
  // from the snapshot. Before D2 those late writes silently never reached
  // the sidebar (issue H2).
  //
  // Contract:
  //   • `patch` is `{ externalRefs?, interestingStrings?, metadata?,
  //                  risk?, encodedContent? }`. Any subset.
  //   • `opts.token` is an optional stale-load guard. Callers that captured
  //     `app._loadToken` at the moment they queued the async work pass it
  //     in — if a Back-or-forward navigation has happened in the meantime,
  //     `app._loadToken` will have been bumped and the patch is silently
  //     dropped (so a stranded post-load digest can't paint into the next
  //     file's findings).
  //   • Dedup is opt-in via a stable `id` field on each pushed entry.
  //     Entries with the same `id` as something already in
  //     `findings.externalRefs` / `interestingStrings` /
  //     `findings.encodedContent` are skipped. Entries without `id` are
  //     appended unconditionally — preserving the pre-D2 behaviour for
  //     renderers that haven't migrated.
  //   • `risk` is fed through `escalateRisk(findings, tier)` so the B1
  //     ladder rules apply (no pre-stamping past the current tier).
  //   • The patch dispatches `findings:updated` on `document` with
  //     `{ detail: { sections: [...] } }` for any external listeners
  //     (copy-analysis cache, future inspector overlay, etc.) and
  //     schedules a microtask-coalesced sidebar re-render.
  updateFindings(patch, opts) {
    if (!this.findings || !patch) return;
    if (opts && opts.token !== undefined && opts.token !== this._loadToken) {
      // Stale load — patch was queued for a previous file. Drop.
      return;
    }
    const sections = new Set();

    if (Array.isArray(patch.externalRefs) && patch.externalRefs.length) {
      const dst = this.findings.externalRefs = this.findings.externalRefs || [];
      const seenIds = new Set(dst.filter(r => r && r.id).map(r => r.id));
      for (const ref of patch.externalRefs) {
        if (!ref) continue;
        if (ref.id && seenIds.has(ref.id)) continue;
        if (ref.id) seenIds.add(ref.id);
        dst.push(ref);
      }
      sections.add('detections'); sections.add('iocs');
    }
    if (Array.isArray(patch.interestingStrings) && patch.interestingStrings.length) {
      const dst = this.findings.interestingStrings = this.findings.interestingStrings || [];
      const seenIds = new Set(dst.filter(r => r && r.id).map(r => r.id));
      for (const s of patch.interestingStrings) {
        if (!s) continue;
        if (s.id && seenIds.has(s.id)) continue;
        if (s.id) seenIds.add(s.id);
        dst.push(s);
      }
      sections.add('detections'); sections.add('iocs');
    }
    if (patch.metadata && typeof patch.metadata === 'object') {
      this.findings.metadata = this.findings.metadata || {};
      Object.assign(this.findings.metadata, patch.metadata);
      sections.add('fileInfo');
    }
    if (patch.risk && typeof escalateRisk === 'function') {
      escalateRisk(this.findings, patch.risk);
      sections.add('risk');
    }
    if (Array.isArray(patch.encodedContent) && patch.encodedContent.length) {
      const dst = this.findings.encodedContent = this.findings.encodedContent || [];
      const seenIds = new Set(dst.filter(r => r && r.id).map(r => r.id));
      for (const ef of patch.encodedContent) {
        if (!ef) continue;
        if (ef.id && seenIds.has(ef.id)) continue;
        if (ef.id) seenIds.add(ef.id);
        dst.push(ef);
      }
      sections.add('deobfuscation');
    }

    this._scheduleSidebarRefresh(sections);
  },

  // Microtask-coalesced sidebar refresh. Multiple `updateFindings(...)`
  // calls in the same task collapse into one re-render — important when a
  // renderer's deferred path emits 20 IOCs in a tight loop. The set of
  // touched sections is preserved on `_pendingSbSections` for a future
  // surgical re-render impl; today V1 just calls the existing
  // `_renderSidebar` (which preserves section open/closed state via
  // `_resolveSectionOpen`, so a full re-render is visually stable).
  _scheduleSidebarRefresh(sections) {
    if (!sections) sections = new Set();
    this._pendingSbSections = this._pendingSbSections || new Set();
    sections.forEach(s => this._pendingSbSections.add(s));
    if (this._sbRefreshScheduled) return;
    this._sbRefreshScheduled = true;
    Promise.resolve().then(() => {
      const pending = this._pendingSbSections || new Set();
      this._pendingSbSections = null;
      this._sbRefreshScheduled = false;
      if (!this.findings) return;
      try {
        document.dispatchEvent(new CustomEvent('findings:updated', {
          detail: { sections: [...pending] },
        }));
      } catch (_) { /* event dispatch is best-effort */ }
      const fileName = (this._fileMeta && this._fileMeta.name) || '';
      try {
        this._renderSidebar(fileName, this._currentAnalyzer || null);
      } catch (err) {
        // silent:true is mandatory here — _reportNonFatal pushes an INFO IOC
        // and re-schedules a sidebar refresh, which would re-enter this same
        // failure site and recurse. Console-only is the safe path.
        this._reportNonFatal('sidebar-refresh', err, { silent: true });
      }
    });
  },

  // ── Hashing ─────────────────────────────────────────────────────────────
  async _hashFile(buffer) {
    const data = buffer instanceof ArrayBuffer ? buffer : buffer.buffer;
    try {
      const [s1, s256] = await Promise.all([
        crypto.subtle.digest('SHA-1', data),
        crypto.subtle.digest('SHA-256', data)
      ]);
      const hex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
      return { md5: _md5(new Uint8Array(data)), sha1: hex(s1), sha256: hex(s256) };
    } catch (e) { return { md5: '—', sha1: '—', sha256: '—' }; }
  },

  // ── File magic detection ────────────────────────────────────────────────
  _detectMagic(bytes) {
    if (bytes.length < 4) return { hex: '', label: 'Unknown' };
    const h = n => Array.from(bytes.subarray(0, n)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
    // Check common signatures
    if (bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04)
      return { hex: h(4), label: 'ZIP / OOXML (PK)' };
    if (bytes[0] === 0xD0 && bytes[1] === 0xCF && bytes[2] === 0x11 && bytes[3] === 0xE0)
      return { hex: h(4), label: 'OLE/CFB Compound File' };
    if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46)
      return { hex: h(4), label: 'PDF Document' };
    if (bytes[0] === 0x4D && bytes[1] === 0x5A)
      return { hex: h(2), label: 'PE Executable (MZ)' };
    if (bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46)
      return { hex: h(4), label: 'ELF Binary' };
    if (bytes[0] === 0xCF && bytes[1] === 0xFA && bytes[2] === 0xED && bytes[3] === 0xFE)
      return { hex: h(4), label: 'Mach-O Binary (64-bit)' };
    if (bytes[0] === 0xCE && bytes[1] === 0xFA && bytes[2] === 0xED && bytes[3] === 0xFE)
      return { hex: h(4), label: 'Mach-O Binary (32-bit)' };
    if (bytes[0] === 0xCA && bytes[1] === 0xFE && bytes[2] === 0xBA && bytes[3] === 0xBE) {
      if (typeof JarRenderer !== 'undefined' && JarRenderer.isJavaClass(bytes))
        return { hex: h(4), label: 'Java Class File' };
      return { hex: h(4), label: 'Mach-O Fat/Universal Binary' };
    }
    if (bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72)
      return { hex: h(3), label: 'RAR Archive' };
    if (bytes[0] === 0x37 && bytes[1] === 0x7A && bytes[2] === 0xBC && bytes[3] === 0xAF)
      return { hex: h(4), label: '7-Zip Archive' };
    if (bytes[0] === 0x4C && bytes[1] === 0x00 && bytes[2] === 0x00 && bytes[3] === 0x00)
      return { hex: h(4), label: 'Windows Shortcut (LNK)' };
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47)
      return { hex: h(4), label: 'PNG Image' };
    if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF)
      return { hex: h(3), label: 'JPEG Image' };
    if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46)
      return { hex: h(3), label: 'GIF Image' };
    // Text-based detection
    const head = String.fromCharCode(...bytes.subarray(0, Math.min(20, bytes.length)));
    if (head.startsWith('{\\rtf')) return { hex: h(5), label: 'Rich Text Format (RTF)' };
    if (head.startsWith('<!DOCTYPE') || head.startsWith('<html') || head.startsWith('<HTML'))
      return { hex: h(6), label: 'HTML Document' };
    if (head.startsWith('<HTA:') || head.includes('<HTA:'))
      return { hex: h(6), label: 'HTML Application (HTA)' };
    if (head.startsWith('<?xml') || head.startsWith('<xml'))
      return { hex: h(5), label: 'XML Document' };
    if (head.startsWith('[InternetShortcut]'))
      return { hex: h(8), label: 'Internet Shortcut (.url)' };
    // Registry files: REGEDIT4 or "Windows Registry Editor Version 5.00" (may have UTF-16LE BOM FF FE)
    if (head.startsWith('REGEDIT4') || head.startsWith('Windows Registry'))
      return { hex: h(8), label: 'Windows Registry File (.reg)' };
    if (bytes.length >= 4 && bytes[0] === 0xFF && bytes[1] === 0xFE) {
      const u16 = new TextDecoder('utf-16le', { fatal: false }).decode(bytes.subarray(0, Math.min(80, bytes.length)));
      if (u16.startsWith('Windows Registry'))
        return { hex: 'FF FE', label: 'Windows Registry File (.reg, UTF-16LE)' };
    }
    // INF: Setup Information files start with [Version] section
    if (head.startsWith('[Version]') || head.startsWith('[version]'))
      return { hex: h(9), label: 'Setup Information File (.inf)' };
    if (head.startsWith('From ') || head.startsWith('Received:') || head.startsWith('MIME-Version'))
      return { hex: h(6), label: 'Email Message (RFC 5322)' };
    // EVTX: "ElfFile\0"
    if (bytes[0] === 0x45 && bytes[1] === 0x6C && bytes[2] === 0x66 && bytes[3] === 0x46 &&
      bytes[4] === 0x69 && bytes[5] === 0x6C && bytes[6] === 0x65 && bytes[7] === 0x00)
      return { hex: h(8), label: 'Windows Event Log (EVTX)' };
    // SQLite: "SQLite format 3\000"
    if (bytes[0] === 0x53 && bytes[1] === 0x51 && bytes[2] === 0x4C && bytes[3] === 0x69 &&
      bytes[4] === 0x74 && bytes[5] === 0x65 && bytes[6] === 0x20)
      return { hex: h(6), label: 'SQLite Database' };
    if (bytes.length > 32768 + 5) {
      const iso = String.fromCharCode(bytes[32769], bytes[32770], bytes[32771], bytes[32772], bytes[32773]);
      if (iso === 'CD001') return { hex: 'CD001', label: 'ISO 9660 Disk Image' };
    }
    // OneNote magic
    if (bytes.length >= 16 && bytes[0] === 0xE4 && bytes[1] === 0x52 && bytes[2] === 0x5C && bytes[3] === 0x7B)
      return { hex: h(4), label: 'OneNote Document' };
    // Binary plist: "bplist"
    if (bytes.length >= 8 && bytes[0] === 0x62 && bytes[1] === 0x70 && bytes[2] === 0x6C &&
      bytes[3] === 0x69 && bytes[4] === 0x73 && bytes[5] === 0x74)
      return { hex: h(8), label: 'Binary Property List (bplist)' };
    // OpenPGP ASCII armor (text-based: -----BEGIN PGP ...)
    if (head.startsWith('-----BEGIN PGP'))
      return { hex: h(14), label: 'OpenPGP ASCII-Armored Data' };
    // PEM certificate (text-based: -----BEGIN ...)
    if (head.startsWith('-----BEGIN '))
      return { hex: h(11), label: 'PEM Encoded Data' };
    // OpenPGP binary packet stream: Public-Key (0x99 / 0xC6), Secret-Key (0x95 / 0xC5),
    // Public-Subkey (0xB9 / 0xCE), Secret-Subkey (0x9D / 0xC7) — followed by a version
    // byte in {3,4,5,6}. Check tight byte patterns to avoid false positives.
    if (bytes.length >= 3 &&
      [0x99, 0x95, 0xB9, 0x9D, 0xC6, 0xC5, 0xCE, 0xC7].includes(bytes[0])) {
      // For old-format packets (0x9X / 0xBX) the version byte is at offset 3 (after 2-byte length);
      // for new-format (0xCX) it follows the length byte(s). We accept either if we see a plausible version in the first 8 bytes.
      const scan = bytes.subarray(0, Math.min(8, bytes.length));
      if ([3, 4, 5, 6].some(v => Array.from(scan).includes(v))) {
        return { hex: h(4), label: 'OpenPGP Binary Key / Signature' };
      }
    }
    // DER certificate (ASN.1 SEQUENCE with long-form length)
    if (bytes[0] === 0x30 && bytes[1] === 0x82)
      return { hex: h(4), label: 'DER / ASN.1 Data' };
    return { hex: h(Math.min(4, bytes.length)), label: 'Unknown' };
  },

  // ── Heuristic: does this buffer look like OpenPGP data? ─────────────────
  // Used to disambiguate .key between X.509 private key (PEM) and PGP key.
  _looksLikePgp(bytes) {
    if (!bytes || bytes.length < 4) return false;
    // ASCII-armored
    const head = String.fromCharCode(...bytes.subarray(0, Math.min(64, bytes.length)));
    if (head.includes('-----BEGIN PGP ')) return true;
    // Binary OpenPGP packet headers (Public-Key, Secret-Key, their subkey variants,
    // both old-format and new-format)
    const first = bytes[0];
    if ([0x99, 0x95, 0xB9, 0x9D, 0xC6, 0xC5, 0xCE, 0xC7].includes(first)) return true;
    return false;
  },


  // ── Renderer dispatch table ───────────────────────────────────────────
  //
  // Single source of truth that maps a registry id (the value returned by
  // `RendererRegistry.detect()`) to the handler that owns the actual
  // instantiate → analyze → render sequence for that format. Every handler:
  //
  //   • is called with `(file, buffer, rctx)` bound to `App`
  //   • assigns `this.findings` from the renderer's `analyzeForSecurity()`
  //   • returns `{ docEl, analyzer? }` — analyzer is only set for the DOCX
  //     pipeline (which still needs to hand the analyzer instance into
  //     `_renderSidebar` for module rendering)
  //   • attaches the `open-inner-file` listener whose containers expose
  //     drill-down (msg / eml / pdf / zip / msix / browserext / jar / msi)
  //
  // Adding a new renderer means appending one entry here AND one entry in
  // `RendererRegistry.ENTRIES`. The catch-all `plaintext` handler is the
  // last-resort fallback that `_loadFile` selects when the registry can't
  // find any match.
  _rendererDispatch: {
    // ── DOCX pipeline (parser + analyzer + content renderer) ────────────
    async docx(file, buffer) {
      const parsed = await new DocxParser().parse(buffer);
      const analyzer = new SecurityAnalyzer();
      this.findings = analyzer.analyze(parsed);
      const docEl = new ContentRenderer(parsed).render();
      return { docEl, analyzer };
    },

    // ── OOXML / OLE workbooks + ODS — all route through XlsxRenderer ────
    async xlsx(file, buffer) {
      const r = new XlsxRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    async xls(file, buffer) { return this._rendererDispatch.xlsx.call(this, file, buffer); },
    async ods(file, buffer) { return this._rendererDispatch.xlsx.call(this, file, buffer); },

    async pptx(file, buffer) {
      const r = new PptxRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      return { docEl: await r.render(buffer) };
    },
    async odt(file, buffer) {
      const r = new OdtRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      return { docEl: await r.render(buffer) };
    },
    async odp(file, buffer) {
      const r = new OdpRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      return { docEl: await r.render(buffer) };
    },
    async ppt(file, buffer) {
      const r = new PptBinaryRenderer();
      this.findings = r.analyzeForSecurity(buffer);
      return { docEl: r.render(buffer) };
    },
    async doc(file, buffer) {
      const r = new DocBinaryRenderer();
      this.findings = r.analyzeForSecurity(buffer);
      return { docEl: r.render(buffer) };
    },

    // ── CSV / TSV ─────────────────────────────────────────────────────────
    // Decode from the ArrayBuffer we already have rather than calling
    // `file.text()` (which would read the file a second time and, for
    // files near V8's string-length limit, can silently return '').
    // For buffers > DECODE_CHUNK_BYTES (16 MB) the decode is chunked
    // so each intermediate string stays well under the ~512 M-char limit.
    async csv(file, buffer) {
      const text = CsvRenderer.decodeBuffer(buffer);
      const r = new CsvRenderer();
      this.findings = r.analyzeForSecurity(text);
      return { docEl: r.render(text, file.name) };
    },

    // ── JSON / NDJSON — tabular viewer via GridViewer ───────────────────
    //
    // Decoded via `File.text()` so UTF-8 / BOM handling matches CSV. The
    // registry's `json` entry only routes array-shaped JSON / NDJSON here
    // (`extDisambiguator` → `_sniffJsonArrayOrNdjson`); object-root and
    // scalar-root JSON fall through to PlainTextRenderer. The renderer's
    // own `_fallback()` also re-routes pathological inputs to the plain-
    // text view, so every JSON file remains viewable.
    async json(file) {
      const text = await file.text();
      const r = new JsonRenderer();
      this.findings = r.analyzeForSecurity(text);
      return { docEl: r.render(text, file.name) };
    },

    // ── Forensic / structured-binary formats ────────────────────────────
    async evtx(file, buffer) {
      const r = new EvtxRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    sqlite(file, buffer) {
      const r = new SqliteRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    lnk(file, buffer) {
      const r = new LnkRenderer();
      this.findings = r.analyzeForSecurity(buffer);
      return { docEl: r.render(buffer) };
    },
    iso(file, buffer) {
      const r = new IsoRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      const docEl = r.render(buffer, file.name);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },
    dmg(file, buffer) {
      const r = new DmgRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    async pkg(file, buffer) {
      const r = new PkgRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      const docEl = await r.render(buffer, file.name);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },

    async onenote(file, buffer) {
      const r = new OneNoteRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },

    // ── Email / message containers (drill-down via open-inner-file) ─────
    msg(file, buffer) {
      const r = new MsgRenderer();
      this.findings = r.analyzeForSecurity(buffer);
      const docEl = r.render(buffer);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },
    async eml(file, buffer) {
      const r = new EmlRenderer();
      this.findings = await r.analyzeForSecurity(buffer);
      const docEl = r.render(buffer);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },

    // ── Archives + package formats (all expose drill-down) ──────────────
    async zip(file, buffer) {
      const r = new ZipRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      const docEl = await r.render(buffer, file.name);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },
    async cab(file, buffer) {
      const r = new CabRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      const docEl = await r.render(buffer, file.name);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },
    async rar(file, buffer) {
      const r = new RarRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      const docEl = await r.render(buffer, file.name);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },
    async sevenz(file, buffer) {
      const r = new SevenZRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      const docEl = await r.render(buffer, file.name);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },
    async msix(file, buffer) {
      const r = new MsixRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      const docEl = await r.render(buffer, file.name);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },
    async browserext(file, buffer) {
      const r = new BrowserExtRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      const docEl = await r.render(buffer, file.name);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },
    async npm(file, buffer) {
      const r = new NpmRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      const docEl = await r.render(buffer, file.name);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },
    async jar(file, buffer) {
      // body.jar-active clamps the sidebar to 33vw (vs the default 50vw)
      // — JAR viewers have dense tables, file tree, and a tab strip that
      // need horizontal room. Set BEFORE `_renderSidebar` runs so the
      // width-lock captures the clamped value.
      document.body.classList.add('jar-active');
      const r = new JarRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      const docEl = await r.render(buffer, file.name);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },
    msi(file, buffer) {
      const r = new MsiRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      const docEl = r.render(buffer, file.name);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },

    // ── PDF (drill-down via embedded /Filespec attachments) ─────────────
    async pdf(file, buffer) {
      const r = new PdfRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      const docEl = await r.render(buffer, file.name, this.findings);
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },

    // ── Misc text / config formats ──────────────────────────────────────
    rtf(file, buffer) {
      const r = new RtfRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    hta(file, buffer) {
      const r = new HtaRenderer();
      this.findings = r.analyzeForSecurity(buffer);
      return { docEl: r.render(buffer) };
    },
    html(file, buffer) {
      const r = new HtmlRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      if (this.findings.augmentedBuffer) this.currentResult.yaraBuffer = this.findings.augmentedBuffer;
      return { docEl: r.render(buffer, file.name) };
    },
    url(file, buffer) {
      const r = new UrlShortcutRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    scf(file, buffer) {
      const r = new ScfRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    libraryms(file, buffer) {
      const r = new LibraryMsRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    mof(file, buffer) {
      const r = new MofRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    reg(file, buffer) {
      const r = new RegRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    inf(file, buffer) {
      const r = new InfSctRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    iqyslk(file, buffer) {
      const r = new IqySlkRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    wsf(file, buffer) {
      const r = new WsfRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    clickonce(file, buffer) {
      const r = new ClickOnceRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },

    // ── SVG / Plist / AppleScript — augmentedBuffer goes to YARA ────────
    async svg(file, buffer) {
      const r = new SvgRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      if (this.findings.augmentedBuffer) this.currentResult.yaraBuffer = this.findings.augmentedBuffer;
      return { docEl: r.render(buffer, file.name) };
    },
    plist(file, buffer) {
      const r = new PlistRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      if (this.findings.augmentedBuffer) this.currentResult.yaraBuffer = this.findings.augmentedBuffer;
      return { docEl: r.render(buffer, file.name) };
    },
    scpt(file, buffer) {
      const r = new OsascriptRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      if (this.findings.augmentedBuffer) this.currentResult.yaraBuffer = this.findings.augmentedBuffer;
      return { docEl: r.render(buffer, file.name) };
    },

    // ── Crypto material ─────────────────────────────────────────────────
    pgp(file, buffer) {
      const r = new PgpRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },
    x509(file, buffer) {
      const r = new X509Renderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },

    // ── Native binaries ─────────────────────────────────────────────────
    //
    // Each dispatcher stamps the format identity + parsed-header struct
    // onto `this.currentResult.binary` for the sidebar's Binary Triage
    // and MITRE ATT&CK sections to consume:
    //
    //   • `binary.parsed` — the renderer's parsed header struct
    //     (r._parsed), used for pivot fields the findings object doesn't
    //     carry verbatim (build IDs, signer tri-state, LC summaries, etc.)
    //   • `binary.format` — 'pe' | 'elf' | 'macho', so the sidebar knows
    //     which format-specific card schema to render without re-sniffing
    //     the bytes.
    //
    // The whole `binary` sub-object is cleared implicitly on the next
    // _loadFile() because `RenderRoute.run` allocates a fresh
    // `currentResult` skeleton with `binary: null`; a non-binary load
    // simply leaves it null.
    pe(file, buffer) {
      // .xll — Excel add-in; structurally a DLL. The PE renderer's
      // format-heuristics pass picks up xlAutoOpen / xlAutoClose so the
      // sidebar / Summary / YARA pass all flag the XLL class correctly.
      const r = new PeRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      this.currentResult.binary = { format: 'pe', parsed: r._parsed || null };
      const docEl = r.render(buffer, file.name);
      // Overlay card may emit `open-inner-file` when the user clicks the
      // "Analyse overlay" button — wire the listener so the synthetic File
      // round-trips through `_loadFile` and gets pushed onto the nav stack.
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },
    elf(file, buffer) {
      const r = new ElfRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      this.currentResult.binary = { format: 'elf', parsed: r._parsed || null };
      const docEl = r.render(buffer, file.name);
      // Overlay card drill-down — see pe() above.
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },
    macho(file, buffer) {
      const r = new MachoRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      this.currentResult.binary = { format: 'macho', parsed: r._parsed || null };
      const docEl = r.render(buffer, file.name);
      // Overlay / Fat-container-tail drill-down — see pe() above.
      this._wireInnerFileListener(docEl, file.name);
      return { docEl };
    },

    // ── Images ──────────────────────────────────────────────────────────
    async image(file, buffer) {
      const r = new ImageRenderer();
      this.findings = await r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name) };
    },

    // ── Catch-all — invoked by `_loadFile` when the registry can't find
    //    any match, OR when the chosen handler is unknown (defensive).
    plaintext(file, buffer) {
      const r = new PlainTextRenderer();
      this.findings = r.analyzeForSecurity(buffer, file.name);
      return { docEl: r.render(buffer, file.name, file.type) };
    },
  },

  // ── Unified inner-file drill-down ────────────────────────────
  //
  // Single entry point for every recursive load: archive entry, attachment,
  // binary overlay, decoded encoded-content blob, PE/ELF/Mach-O resource,
  // Back-button replay (`_reRender*`). Every drill-down funnels through
  // here so the nav-stack push, the optional `returnFocus` payload, and
  // the re-entry into `_loadFile` (which re-runs the full
  // `RendererRegistry.dispatch` chain — no inline reclassification) live
  // in one canonical helper.
  //
  // Replaces the historic `_wireInnerFileListener` (event listener) +
  // `_drillDownToSynthetic` (sidebar synthetic-File builder) +
  // four copy-pasted `addEventListener('open-inner-file', …)` blocks
  // inside `_reRenderZip` / `_reRenderMsi` / `_reRenderIso` / `_reRenderJar`.
  // Those callers now delegate here.
  //
  // @param {File} file              Real or synthetic File to load.
  // @param {ArrayBuffer?} parentBuf Optional prefetched bytes (skips a re-read).
  //                                 Honoured by `_loadFile`'s `prefetchedBuffer`
  //                                 parameter — see CONTRIBUTING.md →
  //                                 "Drill-down: the open-inner-file event
  //                                 protocol" for the public contract.
  // @param {Object?} ctx
  // @param {string?} ctx.parentName     Display name for the breadcrumb;
  //                                     defaults to current `_fileMeta.name`.
  // @param {Object?} ctx.returnFocus    e.g. { section:'deobfuscation',
  //                                     findingOffset:N } — replayed by
  //                                     `_renderSidebar` after the drill-down
  //                                     round-trip completes.
  openInnerFile(file, parentBuf, ctx) {
    if (!file) return;
    const opts = ctx || {};
    const crumb = opts.parentName
      || (this._fileMeta && this._fileMeta.name)
      || '';
    this._pushNavState(crumb);
    if (opts.returnFocus) {
      const top = this._navStack && this._navStack[this._navStack.length - 1];
      if (top) top.returnFocus = opts.returnFocus;
    }
    // Selection-driven decode (`app-selection-decode.js`) sets
    // `_aggressiveDecode: true` so the encoded-content scan stage in
    // `_loadFile` lowers finder thresholds. Stashed as a transient
    // single-shot flag — consumed and cleared by the encoded-content
    // block below to keep state out of every other code path.
    if (opts._aggressiveDecode) {
      this._pendingAggressiveDecode = true;
    }
    // Bruteforce ("kitchen sink") mode — implies aggressive. Set by
    // the "Decode selection" chip ONLY. Threads `bruteforce: true`
    // into `EncodedContentDetector`, which raises depth (4 → 6),
    // raises per-type cap (50 → 200), bypasses every whitelist
    // filter, drops exec-keyword plausibility gates, runs ROT-1…
    // ROT-25 on quoted literals, and flips on multi-byte XOR + crib
    // analysis. Same single-shot lifetime as the aggressive flag.
    if (opts._bruteforceDecode) {
      this._pendingBruteforceDecode = true;
      this._pendingAggressiveDecode = true;  // implies aggressive
    }
    this._loadFile(file, parentBuf || null);
  },

  // Wire `open-inner-file` events from a container renderer (msg / eml /
  // zip / pdf / msix / browserext / jar / msi / pe / elf / macho overlay)
  // to the unified drill-down helper. Honours the documented
  // `e.detail._prefetchedBuffer` escape hatch (CONTRIBUTING → drill-down
  // event protocol) so a parent that already has the bytes in memory can
  // skip the re-read.
  _wireInnerFileListener(docEl, parentName) {
    if (!docEl || typeof docEl.addEventListener !== 'function') return;
    docEl.addEventListener('open-inner-file', (e) => {
      const innerFile = e.detail;
      if (!innerFile) return;
      this.openInnerFile(
        innerFile,
        innerFile._prefetchedBuffer || null,
        { parentName }
      );
    });
  },

  // ── Shannon entropy ─────────────────────────────────────────────────────

  _computeEntropy(bytes) {
    if (bytes.length === 0) return 0;
    const freq = new Uint32Array(256);
    for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
    let entropy = 0;
    const len = bytes.length;
    for (let i = 0; i < 256; i++) {
      if (freq[i] === 0) continue;
      const p = freq[i] / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 1000) / 1000;
  },

  // ── Navigation stack (for going back from inner archive files) ──────────
  //
  // Strategy: instead of serialising the rendered DOM via innerHTML (which
  // destroys event listeners, tab state, tree expansion, scroll position,
  // and any JS-held references), we *detach* the live DOM node from the
  // page container and park it on the nav stack. When the user clicks Back,
  // we re-attach the exact same node tree — preserving everything.
  //
  // Safety net: if re-attachment fails (detached node missing, renderer
  // mismatch), we fall back to re-rendering from the stored buffer via the
  // per-format helpers below.
  _pushNavState(parentName) {
    // `_navStack` is always present — initialised in the App constructor
    // (`app-core.js`) and only reset via `_resetNavStack()`. The historic
    // lazy `if (!this._navStack) this._navStack = []` was removed in H6;
    // any path that lost the array now fails loudly here instead of
    // silently re-creating it (which would orphan in-flight frames).
    if (this._navStack.length >= PARSER_LIMITS.MAX_DEPTH) {
      console.warn(`Nesting depth limit reached (${PARSER_LIMITS.MAX_DEPTH}) — refusing to open inner file`);
      const toast = document.getElementById('toast');
      if (toast) { toast.textContent = `⚠ Nesting depth limit (${PARSER_LIMITS.MAX_DEPTH}) reached — cannot open further nested files.`; toast.className = ''; setTimeout(() => toast.className = 'hidden', 4000); }
      throw new Error('DEPTH_LIMIT');
    }
    const pc = document.getElementById('page-container');
    const docEl = pc && pc.firstElementChild;

    // CAPTURE ORDER MATTERS: we must read #viewer.scrollTop and walk the
    // live DOM for a scroll anchor *before* detaching the JAR view,
    // because removeChild() empties #page-container which instantly
    // clamps #viewer.scrollTop to 0 and detaches every element we would
    // want to anchor on (detached elements report zero-sized bounding
    // rects). If we read after the detach we save garbage (scroll=0,
    // anchor=null), leaving Back navigation unable to restore position.
    //
    // In addition to the numeric scrollTop we capture a DOM *anchor*: a
    // direct reference to the element that was sitting at the top of the
    // viewport, plus its offset from the pane top. When we restore, the
    // re-rendered sidebar can cause #viewer to change width by a few pixels,
    // which reflows the JAR view and makes the saved scrollTop point at a
    // slightly different visual row. Scrolling the anchor element into view
    // instead locks onto the same row regardless of reflow.
    const viewerEl = document.getElementById('viewer');
    const sbBodyEl = document.getElementById('sb-body');
    const viewerScroll = viewerEl ? { top: viewerEl.scrollTop, left: viewerEl.scrollLeft } : null;
    const sbBodyScroll = sbBodyEl ? { top: sbBodyEl.scrollTop, left: sbBodyEl.scrollLeft } : null;
    const viewerAnchor = this._captureScrollAnchor(viewerEl, docEl);
    const sbBodyAnchor = this._captureScrollAnchor(sbBodyEl, sbBodyEl);

    // Also snapshot scroll of every scrollable descendant of the JAR view
    // itself (inner tab panes, search results list, etc.) before detaching.
    let scrollSnapshot = null;
    if (docEl) scrollSnapshot = this._snapshotScroll(docEl);

    // NOW detach the live node (removes it from the DOM but keeps all
    // handlers, child state, and scroll intact). scrollTop/scrollLeft are
    // saved as a belt-and-braces measure for cases where the browser resets
    // them on re-attach (rare, but observed with some overflow containers).
    let pageNode = null;
    if (docEl) {
      try {
        pageNode = pc.removeChild(docEl);
      } catch (e) {
        console.warn('Failed to detach page node for nav state:', e);
        pageNode = null;
      }
    }

    this._navStack.push({
      findings: this.findings,
      fileHashes: this.fileHashes,
      fileMeta: this._fileMeta,
      currentResult: this.currentResult,
      yaraResults: this._yaraResults,
      pageNode,                 // detached live DOM node (preferred)
      scrollSnapshot,           // Map<element,{top,left}> for restoration
      viewerScroll,             // #viewer scroll position (outer pane)
      sbBodyScroll,             // #sb-body scroll position (sidebar pane)
      viewerAnchor,             // { el, offset } — anchor for reflow-robust restore
      sbBodyAnchor,             // { el, offset } — anchor for reflow-robust restore
      rawText: (docEl && docEl._rawText) || null,
      parentName,
      // Snapshot which top-level sidebar sections the user had open/closed
      // at the moment they drilled in. When `_restoreNavFrame` replays this
      // frame on Back, `_renderSidebar` consumes the snapshot via
      // `_pendingSectionOpenState` and re-renders each section with the
      // same open state — preserving manual collapses across the round-trip.
      sectionOpenState: this._snapshotSectionOpenState(),
    });
  },

  // ── Snapshot sidebar section open/closed state ──────────────────────────
  //
  // Walks the live `#sb-body details[data-sb-section]` elements and builds
  // a plain `{ key: boolean }` map capturing which top-level sections were
  // open at snapshot time. Consumed on restore via `_pendingSectionOpenState`
  // / `_resolveSectionOpen` in app-sidebar.js. Keys must stay in sync with
  // the `det.dataset.sbSection = ...` tags in the sidebar renderers:
  //   fileInfo / detections / iocs / macros / pdfJs / deobfuscation
  _snapshotSectionOpenState() {
    const out = {};
    const sbBody = document.getElementById('sb-body');
    if (!sbBody) return out;
    const sections = sbBody.querySelectorAll('details[data-sb-section]');
    for (const det of sections) {
      const key = det.dataset.sbSection;
      if (key) out[key] = !!det.open;
    }
    return out;
  },



  // Capture a DOM anchor for reflow-robust scroll restoration. Finds the
  // element closest to the top edge of `container` (but not above it) and
  // records both the element reference and its current pixel offset from
  // the container top. On restore we scrollIntoView() the anchor and apply
  // the offset — this survives reflows that change scrollHeight, unlike
  // a naive scrollTop assignment.
  _captureScrollAnchor(container, subtreeRoot) {
    if (!container || !container.isConnected) return null;
    if (!container.scrollTop) return null;
    const root = subtreeRoot || container;
    const containerRect = container.getBoundingClientRect();
    const containerTop = containerRect.top;
    let best = null;
    let bestDist = Infinity;
    try {
      // Walk the subtree breadth-first, looking at elements only (not text).
      // Cap at ~500 nodes so huge archive trees don't stall the push.
      const queue = [root];
      let examined = 0;
      while (queue.length && examined < 500) {
        const el = queue.shift();
        if (!el || !el.getBoundingClientRect) continue;
        examined++;
        const r = el.getBoundingClientRect();
        // Skip hidden/zero-sized elements
        if (r.height === 0 && r.width === 0) continue;
        // Only consider elements whose top edge is at or below the container top
        // (positive offset). Take the one closest to the top edge.
        const dist = r.top - containerTop;
        if (dist >= 0 && dist < bestDist) {
          bestDist = dist;
          best = { el, offset: dist };
          // Perfect match (flush with top) — stop walking
          if (dist < 1) break;
        }
        // Enqueue children
        const kids = el.children;
        if (kids) for (let i = 0; i < kids.length; i++) queue.push(kids[i]);
      }
    } catch (_) { /* best-effort */ }
    return best;
  },


  // Capture the current view's full state as a nav-stack frame WITHOUT
  // mutating the nav stack. Used by _navJumpTo's inline pop loop and by any
  // future caller that needs a snapshot (e.g. tests).
  _captureNavFrame(parentName) {
    const pc = document.getElementById('page-container');
    const docEl = pc && pc.firstElementChild;
    const viewerEl = document.getElementById('viewer');
    const sbBodyEl = document.getElementById('sb-body');
    const viewerScroll = viewerEl ? { top: viewerEl.scrollTop, left: viewerEl.scrollLeft } : null;
    const sbBodyScroll = sbBodyEl ? { top: sbBodyEl.scrollTop, left: sbBodyEl.scrollLeft } : null;
    const viewerAnchor = this._captureScrollAnchor(viewerEl, docEl);
    const sbBodyAnchor = this._captureScrollAnchor(sbBodyEl, sbBodyEl);
    let scrollSnapshot = null;
    if (docEl) scrollSnapshot = this._snapshotScroll(docEl);
    let pageNode = null;
    if (docEl) {
      try { pageNode = pc.removeChild(docEl); }
      catch (_) { pageNode = null; }
    }
    return {
      findings: this.findings,
      fileHashes: this.fileHashes,
      fileMeta: this._fileMeta,
      currentResult: this.currentResult,
      yaraResults: this._yaraResults,
      pageNode,
      scrollSnapshot,
      viewerScroll,
      sbBodyScroll,
      viewerAnchor,
      sbBodyAnchor,
      rawText: (docEl && docEl._rawText) || null,
      parentName: parentName || (this._fileMeta && this._fileMeta.name) || '',
      // Mirrors the `sectionOpenState` captured by `_pushNavState` above —
      // see `_snapshotSectionOpenState` for the key set.
      sectionOpenState: this._snapshotSectionOpenState(),
    };
  },


  // Restore a previously captured nav frame into the viewer/sidebar. If
  // re-attaching the detached DOM node fails, fall back to re-rendering
  // from the stored buffer.
  _restoreNavFrame(state) {
    // Tear down any active Timeline view — the frame being restored is a
    // regular analyser view that renders into #page-container inside #viewer,
    // which is hidden while body.has-timeline is set.
    if (this._timelineCurrent) {
      try { this._timelineCurrent.destroy(); } catch (_) { /* noop */ }
      this._timelineCurrent = null;
      const tlHost = document.getElementById('timeline-root');
      if (tlHost) tlHost.innerHTML = '';
      document.body.classList.remove('has-timeline');
    }

    this.findings = state.findings;
    this.fileHashes = state.fileHashes;
    this._fileMeta = state.fileMeta;
    // Route through `_setRenderResult` so the epoch bump fences any prior
    // dispatch that's still running. Without this, a back-navigation that
    // lands while the inner-file's renderer is still inflating would let
    // the inner file's late writes paint over the restored ancestor's
    // `currentResult` / `findings`.
    this._setRenderResult(state.currentResult || null);
    this._yaraResults = state.yaraResults;

    const pc = document.getElementById('page-container');
    while (pc.firstChild) pc.removeChild(pc.firstChild);

    let reattached = false;
    if (state.pageNode) {
      try {
        pc.appendChild(state.pageNode);
        if (state.rawText) state.pageNode._rawText = lfNormalize(state.rawText);
        if (state.scrollSnapshot) this._restoreScroll(state.scrollSnapshot);
        reattached = true;
      } catch (e) {
        console.warn('Failed to re-attach nav page node, falling back to re-render:', e);
        reattached = false;
      }
    }

    // Fallback: re-render from buffer if re-attach failed or pageNode missing
    const reBuf = state.currentResult && state.currentResult.buffer;
    if (!reattached && reBuf) {
      const name = (state.parentName || '').toLowerCase();
      if (name.endsWith('.zip')) this._reRenderZip(state, pc);
      else if (name.endsWith('.msi')) this._reRenderMsi(state, pc);
      else if (name.endsWith('.iso') || name.endsWith('.img')) this._reRenderIso(state, pc);
      else if (name.endsWith('.jar') || name.endsWith('.war') || name.endsWith('.ear') || name.endsWith('.class')) this._reRenderJar(state, pc);
    }

    // Hand the snapshotted section open-state and any drill-down
    // return-focus hint to `_renderSidebar` — consumed once on this render.
    // Preserves the user's manual collapse of Detections/IOCs/etc. across
    // the drill-down round-trip, and optionally scrolls+flashes the
    // originating Deobfuscation card when returning from a decode drill-down.
    this._pendingSectionOpenState = state.sectionOpenState || null;
    this._pendingReturnFocus = state.returnFocus || null;

    this._renderSidebar(state.parentName, null);

    // Ensure the viewer toolbar is visible — it may have been hidden by a
    // Timeline view that was active before this frame was restored.
    const vt = document.getElementById('viewer-toolbar');
    if (vt) vt.classList.remove('hidden');

    try {
      if (state.viewerScroll) {
        const v = document.getElementById('viewer');
        if (v) this._stickyRestoreScroll(v, state.viewerScroll, state.viewerAnchor);
      }
      if (state.sbBodyScroll) {
        const sb = document.getElementById('sb-body');
        if (sb) this._stickyRestoreScroll(sb, state.sbBodyScroll, state.sbBodyAnchor);
      }
    } catch (_) { /* best-effort */ }

    this._renderBreadcrumbs();
  },

  // Jump directly to a specific depth in the nav stack — the only entry
  // point for ancestor navigation now that back/forward
  // (Alt-arrow / mouse side-buttons) has been retired in favour of the
  // breadcrumb trail. Pops everything above `targetDepth` off the stack,
  // discards those intermediate frames, and restores the target frame in
  // a single pass. There is no forward/redo history — the only way back
  // into a deeper layer is to re-click the inner file.
  _navJumpTo(targetDepth) {
    if (targetDepth < 0) targetDepth = 0;
    if (!this._navStack || this._navStack.length <= targetDepth) return;
    // Drop every frame above the target; the last one popped IS the frame
    // we want to restore.
    let state = null;
    while (this._navStack.length > targetDepth) {
      state = this._navStack.pop();
    }
    if (state) this._restoreNavFrame(state);
  },



  // Snapshot scroll positions of the root node and every scrollable
  // descendant, keyed by element reference (which remains valid because we
  // re-attach the same nodes).
  _snapshotScroll(root) {
    const snap = new Map();
    try {
      const walk = (el) => {
        if (!el) return;
        if (el.scrollTop || el.scrollLeft) {
          snap.set(el, { top: el.scrollTop, left: el.scrollLeft });
        }
        const kids = el.children;
        if (kids) for (let i = 0; i < kids.length; i++) walk(kids[i]);
      };
      walk(root);
    } catch (_) { /* best-effort */ }
    return snap;
  },

  _restoreScroll(snap) {
    if (!snap || typeof snap.forEach !== 'function') return;
    // Restore on next frame so layout has settled after re-attach. We also
    // apply the sticky-retry logic to each scrollable descendant so that
    // panes whose content is measured asynchronously (e.g. JAR tab panes
    // that only lay out after the tab becomes visible) still land on the
    // saved offset instead of being clamped to a smaller scrollHeight.
    requestAnimationFrame(() => {
      try {
        snap.forEach((pos, el) => {
          if (!el || !el.isConnected) return;
          this._stickyRestoreScroll(el, pos);
        });
      } catch (_) { /* best-effort */ }
    });
  },

  // Apply a saved scroll offset to `el` and keep re-applying it across
  // multiple animation frames / timeouts until either the target sticks
  // (scrollTop within 1px of target) or a ~500ms budget elapses. If a
  // ResizeObserver is available, also re-apply whenever the element's
  // scrollable content grows — this covers the case where the #viewer's
  // page-container or a sidebar section measures its height
  // asynchronously after re-attach / re-render. Without this, the initial
  // scrollTop assignment gets clamped to (scrollHeight - clientHeight) when
  // the content is momentarily shorter than the saved offset, leaving the
  // user above where they were when they drilled into the inner file.
  _stickyRestoreScroll(el, pos, anchor) {
    if (!el || !pos) return;
    const targetTop = pos.top || 0;
    const targetLeft = pos.left || 0;

    // Numeric-offset application. Returns true if converged to within 1 px.
    const applyNumeric = () => {
      if (!el.isConnected) return false;
      el.scrollTop = targetTop;
      el.scrollLeft = targetLeft;
      return Math.abs(el.scrollTop - targetTop) <= 1 && Math.abs(el.scrollLeft - targetLeft) <= 1;
    };

    // Anchor-based application. Places `anchor.el`'s top edge at
    // `anchor.offset` px below the container top. Returns true if the anchor
    // is actually connected and reachable (so caller knows it was usable).
    const applyAnchor = () => {
      if (!anchor || !anchor.el || !anchor.el.isConnected || !el.isConnected) return false;
      try {
        const containerRect = el.getBoundingClientRect();
        const anchorRect = anchor.el.getBoundingClientRect();
        const currentOffset = anchorRect.top - containerRect.top;
        // Positive delta means the anchor is below where we want it → scroll down more.
        const delta = currentOffset - (anchor.offset || 0);
        if (Math.abs(delta) <= 1) return true;
        el.scrollTop = Math.max(0, el.scrollTop + delta);
        el.scrollLeft = targetLeft;
        return true;
      } catch (_) { return false; }
    };

    // One pass: try numeric first, then anchor if numeric didn't stick and
    // clamped to a smaller scrollHeight. This makes anchor the winner
    // whenever reflow changed content height.
    const applyBoth = () => {
      const numericStuck = applyNumeric();
      if (numericStuck) return true;
      // Numeric was clamped — fall through to anchor-based.
      return applyAnchor();
    };

    // Immediate apply (may be clamped if content hasn't laid out yet).
    applyBoth();

    // Retry on the next few frames, then a couple of longer timeouts.
    const schedule = [
      (cb) => requestAnimationFrame(cb),
      (cb) => requestAnimationFrame(() => requestAnimationFrame(cb)),
      (cb) => setTimeout(cb, 0),
      (cb) => setTimeout(cb, 50),
      (cb) => setTimeout(cb, 150),
      (cb) => setTimeout(cb, 350),
      (cb) => setTimeout(cb, 600),
    ];
    let done = false;
    const settle = () => { done = true; if (ro) try { ro.disconnect(); } catch (_) { /* noop */ } };
    schedule.forEach(s => s(() => {
      if (done) return;
      // Prefer anchor on every retry after the first — reflow is the usual
      // culprit when we didn't converge immediately, and anchor is robust
      // against reflow while numeric is not.
      const ok = applyAnchor() || applyNumeric();
      if (ok && anchor && anchor.el && anchor.el.isConnected) {
        // Final check: if anchor is usable, confirm it landed in place.
        const containerRect = el.getBoundingClientRect();
        const anchorRect = anchor.el.getBoundingClientRect();
        if (Math.abs((anchorRect.top - containerRect.top) - (anchor.offset || 0)) <= 1) settle();
      } else if (ok) {
        settle();
      }
    }));

    // Observe content growth: if the scrollable child's size changes and
    // we haven't reached the target yet, re-apply. Disconnect once we
    // succeed or after a hard 1 s ceiling.
    let ro = null;
    if (typeof ResizeObserver !== 'undefined') {
      try {
        ro = new ResizeObserver(() => {
          if (done) return;
          applyAnchor() || applyNumeric();
        });
        const target = el.firstElementChild || el;
        ro.observe(target);
        // Also observe the element itself in case its clientHeight changes.
        if (target !== el) ro.observe(el);
      } catch (_) { ro = null; }
    }
    setTimeout(settle, 1200);
  },

  async _reRenderZip(state, pc) {
    try {
      const r = new ZipRenderer();
      const buf = state.currentResult && state.currentResult.buffer;
      const docEl = await r.render(buf, state.parentName);
      this._wireInnerFileListener(docEl, state.parentName);
      pc.innerHTML = '';
      pc.appendChild(docEl);
    } catch (_) { /* fallback: static HTML already set */ }
  },

  _reRenderMsi(state, pc) {
    try {
      const r = new MsiRenderer();
      const buf = state.currentResult && state.currentResult.buffer;
      const docEl = r.render(buf, state.parentName);
      this._wireInnerFileListener(docEl, state.parentName);
      pc.innerHTML = '';
      pc.appendChild(docEl);
    } catch (_) { /* fallback: static HTML already set */ }
  },

  _reRenderIso(state, pc) {
    try {
      const r = new IsoRenderer();
      const buf = state.currentResult && state.currentResult.buffer;
      const docEl = r.render(buf, state.parentName);
      this._wireInnerFileListener(docEl, state.parentName);
      pc.innerHTML = '';
      pc.appendChild(docEl);
    } catch (_) { /* fallback: static HTML already set */ }
  },

  async _reRenderJar(state, pc) {
    try {
      const r = new JarRenderer();
      const buf = state.currentResult && state.currentResult.buffer;
      const docEl = await r.render(buf, state.parentName);
      this._wireInnerFileListener(docEl, state.parentName);
      pc.innerHTML = '';
      pc.appendChild(docEl);
    } catch (_) { /* fallback: static HTML already set */ }
  },

  // ── Breadcrumbs ─────────────────────────────────────────────────────────
  //
  // Renders the toolbar breadcrumb trail: one clickable crumb per ancestor
  // frame on `_navStack` + a non-clickable current-layer crumb built from
  // `_fileMeta`. Icons come from `_getFileIcon(name)`. When the trail is
  // wider than its container we collapse the middle crumbs into a `… ▾`
  // overflow dropdown to keep Open/Close + the root and current crumbs
  // always visible.
  //
  // Click handlers:
  //   • ancestor crumb → `_navJumpTo(depth)`
  //   • `… ▾` button → toggles overflow menu listing hidden crumbs
  //   • current crumb → no-op (user is already there)
  //
  // This is the single source of truth for toolbar file-path UI — there
  // is no back/forward button, keyboard shortcut, or mouse side-button
  // hook any more.
  _renderBreadcrumbs() {
    const nav = document.getElementById('breadcrumbs');
    if (!nav) return;

    // One-shot install of a debounced window-resize listener. Without
    // this, the staged collapse routine only re-measured on the events
    // that already triggered a render (load / drill-down / nav-jump),
    // so dragging the window narrower never collapsed the trail and
    // dragging it wider never restored full-width filenames. The
    // listener is rAF-debounced (cheap) and only fires a re-render
    // when a file is actually loaded.
    if (!this._breadcrumbResizeBound) {
      this._breadcrumbResizeBound = true;
      let pending = false;
      window.addEventListener('resize', () => {
        if (pending) return;
        pending = true;
        requestAnimationFrame(() => {
          pending = false;
          if (this._fileMeta && this._fileMeta.name) {
            try { this._renderBreadcrumbs(); } catch (_) { /* cosmetic */ }
          }
        });
      });
    }

    // No file loaded → hide breadcrumbs + restore base tab title
    if (!this._fileMeta || !this._fileMeta.name) {
      nav.classList.add('hidden');
      nav.innerHTML = '';
      document.title = 'Loupe';
      return;
    }

    // Build the full crumb list: ancestors (from nav stack) + current
    const stack = this._navStack || [];
    const crumbs = stack.map((s, i) => {
      const name = (s.fileMeta && s.fileMeta.name) || s.parentName || 'file';
      return { name, depth: i, current: false };
    });
    crumbs.push({ name: this._fileMeta.name, depth: stack.length, current: true });

    // Reflect loaded file (and any archive drill-down path) in the tab
    // title. Centralised here because _renderBreadcrumbs is invoked on
    // every state change that alters the displayed file — fresh loads,
    // metadata-enrichment re-renders, archive drill-down, and
    // breadcrumb back-navigation via _navJumpTo — so one hook covers
    // all cases without duplicating state in _loadFile / _clearFile.
    document.title = crumbs.map(c => c.name).join(' › ') + ' — Loupe';

    nav.classList.remove('hidden');
    // Always start each render at the most-permissive width state — the
    // staged collapse routine below re-applies `is-tight` /
    // `is-very-tight` only if the natural (uncapped) trail overflows.
    // Without these resets, widening the window after a drill-down would
    // leave stale cap classes attached and ellipsises would persist.
    nav.classList.remove('is-tight', 'is-very-tight');
    nav.innerHTML = '';

    // Render-helper: build a single crumb element (button for ancestors,
    // span for current). Keeps icon + label + optional meta consistent.
    // The first crumb in a multi-entry trail gets the `crumb-root`
    // modifier so the CSS shrink-hierarchy can have it surrender width
    // before mid-stack ancestors on deep recursive-archive paths.
    const renderCrumb = (c, opts) => {
      const isRoot = !!(opts && opts.root);
      const tag = c.current ? 'span' : 'button';
      const el = document.createElement(tag);
      el.className = 'crumb'
        + (c.current ? ' crumb-current' : '')
        + (isRoot && !c.current ? ' crumb-root' : '');
      if (c.current) el.setAttribute('aria-current', 'page');
      else {
        el.type = 'button';
        el.title = `Jump to ${c.name}`;
        el.addEventListener('click', () => this._navJumpTo(c.depth));
      }
      const icon = document.createElement('span');
      icon.className = 'crumb-icon';
      icon.textContent = this._getFileIcon(c.name);
      el.appendChild(icon);
      const label = document.createElement('span');
      label.className = 'crumb-label';
      label.textContent = c.name;
      el.appendChild(label);
      // Show page count / size meta on current crumb only
      if (c.current) {
        const parts = [];
        if (this._fileMeta.pages) parts.push(`${this._fileMeta.pages} page${this._fileMeta.pages !== 1 ? 's' : ''}`);
        if (typeof this._fileMeta.size === 'number' && this._fmtBytes) parts.push(this._fmtBytes(this._fileMeta.size));
        if (parts.length) {
          const meta = document.createElement('span');
          meta.className = 'crumb-meta';
          meta.textContent = '· ' + parts.join(' · ');
          el.appendChild(meta);
        }
      }
      return el;
    };

    const appendSep = () => {
      const sep = document.createElement('span');
      sep.className = 'crumb-sep';
      sep.textContent = '›';
      nav.appendChild(sep);
    };

    // Initial render: everything visible at its natural width. The
    // staged overflow routine below progressively tightens caps only if
    // the natural layout doesn't fit.
    crumbs.forEach((c, i) => {
      if (i > 0) appendSep();
      nav.appendChild(renderCrumb(c, { root: i === 0 && crumbs.length > 1 }));
    });

    // ── Staged overflow handling ─────────────────────────────────────────
    // Three cumulative stages, each only triggered if the previous one
    // didn't make the trail fit. Measuring must happen after a layout
    // pass so we defer with requestAnimationFrame.
    //
    //   Stage 1 — `is-tight`: per-crumb width caps kick in via CSS,
    //             ellipsising the root crumb first (highest flex-shrink
    //             weight + 120 px max-width), then mid-stack ancestors
    //             (160 px max-width). Current crumb keeps full width.
    //
    //   Stage 2 — middle-collapse: rebuild with the original
    //             `… ▾` overflow chip swallowing every crumb between
    //             root and current. Only runs when there are crumbs
    //             eligible to hide (`crumbs.length > 2`).
    //
    //   Stage 3 — `is-very-tight`: as a last resort the current
    //             crumb's *label* is allowed to ellipsise. Its meta
    //             suffix (` · 12 pages · 4.7 MB`) stays whole because
    //             `.crumb-meta { flex-shrink: 0 }`.
    const overflows = () => nav.scrollWidth > nav.clientWidth + 1;

    const buildCollapsedTrail = () => {
      // Rebuild with a collapsed middle. Mirrors the original
      // single-shot collapse but is now stage 2 of the staged routine.
      nav.innerHTML = '';
      const first = crumbs[0];
      const last = crumbs[crumbs.length - 1];
      const hidden = crumbs.slice(1, -1);

      nav.appendChild(renderCrumb(first, { root: true }));
      appendSep();

      // Overflow chip
      const wrap = document.createElement('span');
      wrap.className = 'crumb-overflow';
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'crumb-overflow-btn';
      btn.textContent = '… ▾';
      btn.title = `${hidden.length} more layer${hidden.length !== 1 ? 's' : ''}`;
      const menu = document.createElement('div');
      menu.className = 'crumb-overflow-menu hidden';
      hidden.forEach(h => {
        const item = renderCrumb(h);
        item.addEventListener('click', () => { menu.classList.add('hidden'); });
        menu.appendChild(item);
      });
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        menu.classList.toggle('hidden');
        if (!menu.classList.contains('hidden')) {
          // One-shot outside click / Esc to close
          const off = (ev) => {
            if (ev.type === 'keydown' && ev.key !== 'Escape') return;
            if (ev.type === 'mousedown' && wrap.contains(ev.target)) return;
            menu.classList.add('hidden');
            document.removeEventListener('mousedown', off, true);
            document.removeEventListener('keydown', off, true);
          };
          document.addEventListener('mousedown', off, true);
          document.addEventListener('keydown', off, true);
        }
      });
      wrap.appendChild(btn);
      wrap.appendChild(menu);
      nav.appendChild(wrap);

      appendSep();
      nav.appendChild(renderCrumb(last));
    };

    const maybeCollapse = () => {
      if (!overflows()) return;
      // Stage 1: shrink ancestors via CSS caps.
      nav.classList.add('is-tight');
      if (!overflows()) return;
      // Stage 2: collapse middle into `… ▾` chip (only when there's
      // something between root and current to hide).
      if (crumbs.length > 2) {
        buildCollapsedTrail();
        // The collapsed trail also wants the tight ancestor caps.
        if (!overflows()) return;
      }
      // Stage 3: allow current crumb's label to ellipsise too.
      nav.classList.add('is-very-tight');
    };
    requestAnimationFrame(maybeCollapse);
  },

  // Shared file-icon helper — duplicated from eml-renderer's _getFileIcon
  // so breadcrumbs and other surfaces can reuse a consistent icon vocab
  // without adding a cross-file import dependency.
  _getFileIcon(name) {
    const ext = (name || '').split('.').pop().toLowerCase();
    if (['exe', 'dll', 'scr', 'com', 'msi', 'sys', 'ocx', 'drv', 'cpl'].includes(ext)) return '⚙️';
    if (['bat', 'cmd', 'ps1', 'vbs', 'js', 'sh', 'wsf', 'wsh', 'wsc', 'hta'].includes(ext)) return '📜';
    if (['doc', 'docx', 'docm', 'odt', 'rtf'].includes(ext)) return '📄';
    if (['xls', 'xlsx', 'xlsm', 'ods', 'csv', 'tsv'].includes(ext)) return '📊';
    if (['ppt', 'pptx', 'pptm', 'odp'].includes(ext)) return '📽️';
    if (['pdf'].includes(ext)) return '📕';
    if (['zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'cab', 'jar', 'war', 'ear', 'iso', 'img'].includes(ext)) return '📦';
    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp', 'ico', 'tif', 'tiff'].includes(ext)) return '🖼️';
    if (['txt', 'log', 'md'].includes(ext)) return '📝';
    if (['html', 'htm', 'xml', 'json', 'mht', 'mhtml'].includes(ext)) return '🌐';
    if (['eml', 'msg'].includes(ext)) return '✉️';
    if (['pem', 'der', 'crt', 'cer', 'p12', 'pfx', 'key'].includes(ext)) return '🔐';
    if (['pgp', 'gpg', 'asc', 'sig'].includes(ext)) return '🔑';
    if (['lnk', 'url', 'webloc'].includes(ext)) return '🔗';
    return '📄';
  },


  // ── Interesting string extraction ────────────────────────────────────────
  //
  // Thin shim around the worker-marshalable `extractInterestingStringsCore`
  // (src/ioc-extract.js). The pure regex-only core lives there so the same
  // logic can run inside `src/workers/ioc-extract.worker.js` for large
  // non-timeline files (see `_extractInterestingStringsAsync` below).
  //
  // Per-type IOC quota: instead of a single global cap applied at return
  // time (which favoured whichever IOC class was extracted first — URLs —
  // and silently dropped everything that came after in large files like
  // a 1000-row CSV with both a URL and an email column), the core caps
  // each `IOC.*` type independently. `_droppedByType` is exposed on the
  // return value so the sidebar can surface a "Showing N of M <type>" note.
  //
  // **Synchronous** by design — used by the small-file path and by the
  // workers-unavailable / async-rejection fallback. The worker-side
  // dispatch lives in `_extractInterestingStringsAsync`.
  _extractInterestingStrings(text, findings) {
    const existingValues = [
      ...(findings.externalRefs || []),
      ...(findings.interestingStrings || []),
    ].map(r => r.url);
    const vbaModuleSources = (findings.modules || []).map(m => m.source || '');
    const out = extractInterestingStringsCore(text, { existingValues, vbaModuleSources });
    const results = out.findings;
    // Re-attach side-channel maps (would otherwise be lost when the host
    // spreads `extracted` into `findings.interestingStrings`).
    results._droppedByType = out.droppedByType;
    results._totalSeenByType = out.totalSeenByType;
    return results;
  },

  // ── Async IOC mass-extract dispatch (Batch A) ────────────────────────────
  //
  // Off-thread regex sweep for non-timeline files larger than
  // IOC_WORKER_THRESHOLD_BYTES. Fires `WorkerManager.runIocExtract`,
  // patches the resolved findings into `this.findings.interestingStrings`
  // (deduped against rows already pushed by the renderer / encoded-content
  // scan), removes the "Scanning IOCs…" placeholder, and asks the sidebar
  // to repaint.
  //
  // Supersession guards (the only way this method should bail without
  // patching findings):
  //   • render epoch advance — a newer load owns the UI, exit silently.
  //   • `'superseded'` rejection — `cancelIocExtract` was called for the
  //     same reason; exit silently.
  // For every other rejection (`'workers-unavailable'`, watchdog, worker
  // error) the synchronous in-tree shim runs as a fallback so the analyst
  // still sees IOCs from the file. The placeholder is always removed.
  _kickIocExtractWorker(text, vbaModuleSources, existingValues, fileName, epoch) {
    // Track the active dispatch on the App so future calls (e.g. quick
    // back-to-back loads) can supersede us via `cancelIocExtract`. We
    // don't await here — the caller has already painted the placeholder
    // and continues with renderer / encoded-content / sidebar work.
    WorkerManager.runIocExtract(text, { vbaModuleSources, existingValues }).then((out) => {
      this._patchIocFindingsFromWorker(out, epoch, fileName);
    }).catch((err) => {
      // Bail silently on supersession — `cancelIocExtract` was called by
      // a newer `_loadFile` and the placeholder will be wiped by the new
      // load's render pass. Same posture as the encoded-content path.
      if (err && err.message === 'superseded') return;
      if (epoch !== this._renderEpoch) return;
      // Worker probe failed, watchdog timeout, or worker reported error —
      // fall back to the synchronous shim so the analyst still sees IOCs.
      // `silent:true` keeps the IOC list clean while the breadcrumb
      // console.warn inside `_reportNonFatal` preserves the diagnostic
      // for devs (matches the encoded-content fallback posture).
      if (err && err.message !== 'workers-unavailable') {
        this._reportNonFatal('ioc-extract-worker-fallback', err, { silent: true });
      }
      try {
        // Strip the placeholder before the sync shim runs so it doesn't
        // bleed into the existingValues dedup set.
        this._removeIocPlaceholder();
        const extracted = this._extractInterestingStrings(text, this.findings);
        this.findings.interestingStrings = [
          ...(this.findings.interestingStrings || []),
          ...extracted,
        ];
        if (extracted._droppedByType && extracted._droppedByType.size > 0) {
          this.findings._iocTruncation = {
            droppedByType: extracted._droppedByType,
            totalSeenByType: extracted._totalSeenByType,
          };
        }
        // Defer the repaint until after the natural sidebar paint near
        // the end of `_loadFile` — without this guard the fallback can
        // race the page-DOM swap and paint the sidebar against an empty
        // viewer (or the previous file's analyzer). See review notes #4
        // from the 2026-04-27 audit.
        if (this._sidebarPainted) {
          this._renderSidebar(
            (this._fileMeta && this._fileMeta.name) || fileName || '',
            this._currentAnalyzer || null
          );
        }
      } catch (fallbackErr) {
        this._reportNonFatal('ioc-extract-fallback-shim', fallbackErr);
      }
    });
  },

  _removeIocPlaceholder() {
    const list = this.findings.interestingStrings;
    if (!Array.isArray(list)) return;
    const idx = list.findIndex(r => r && r._iocScanPlaceholder);
    if (idx >= 0) list.splice(idx, 1);
  },

  _patchIocFindingsFromWorker(out, epoch, fileName) {
    // Render-epoch supersession guard — a newer load owns the UI, do
    // nothing. Mirrors the QrDecoder async-snapshot pattern (see
    // CONTRIBUTING.md → Renderer Contract).
    if (epoch !== this._renderEpoch) return;
    this._removeIocPlaceholder();
    // Post-resolve dedup. The worker's `existingValues` seed (set at
    // dispatch time in `_loadFile`) already covered the renderer-pushed
    // rows; this catches IOCs added BETWEEN dispatch and resolve — the
    // encoded-content scan (`app-load.js:414`) pushes into
    // `findings.interestingStrings` while the worker is in flight. The
    // `externalRefs` half of the union is for rare late renderer updates
    // (PDF QR decode, OneNote inflate) that arrive via `updateFindings`.
    const existingValues = new Set([
      ...((this.findings.externalRefs || []).map(r => r.url)),
      ...((this.findings.interestingStrings || []).map(r => r.url)),
    ]);
    const fresh = [];
    for (const r of (out.findings || [])) {
      if (!r || !r.url || existingValues.has(r.url)) continue;
      existingValues.add(r.url);
      fresh.push(r);
    }
    this.findings.interestingStrings = [
      ...(this.findings.interestingStrings || []),
      ...fresh,
    ];
    if (out.droppedByType && out.droppedByType.size > 0) {
      this.findings._iocTruncation = {
        droppedByType: out.droppedByType,
        totalSeenByType: out.totalSeenByType,
      };
    }
    // Defer the repaint until after the natural sidebar paint near the
    // end of `_loadFile`. When the worker resolves DURING one of the
    // awaits earlier in `_loadFile` (encoded-content / hashPromise) the
    // page DOM swap hasn't happened yet and `_currentAnalyzer` may still
    // hold the previous file's value — the natural paint that follows
    // will snapshot `this.findings` (which we've just mutated) and pick
    // up the patched IOCs without an early stale render. See review
    // notes #4 from the 2026-04-27 audit.
    if (!this._sidebarPainted) return;
    // Re-tag the freshly-merged IOCs before the repaint so the sidebar
    // and any export consumer that runs after this point sees consistent
    // `_nicelisted` flags. Idempotent — the natural paint at the end of
    // `_loadFile` already called `annotateNicelist` once.
    if (typeof annotateNicelist === 'function') annotateNicelist(this.findings);
    // Repaint — `_renderSidebar` snapshots a fresh findings view from
    // `this.findings` so the patched IOC list lands in the next paint.
    // The `_currentAnalyzer` lookup mirrors the deferred-refresh path in
    // `App.updateFindings`.
    this._renderSidebar(
      (this._fileMeta && this._fileMeta.name) || fileName || '',
      this._currentAnalyzer || null
    );
  },

});
