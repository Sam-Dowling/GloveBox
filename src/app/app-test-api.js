// ════════════════════════════════════════════════════════════════════════════
// app-test-api.js — Build-flag-gated test API for Playwright / harness tests.
//
// **THIS FILE IS NEVER INCLUDED IN THE RELEASE BUNDLE.**
//
// `scripts/build.py --test-api` appends this file to `APP_JS_FILES` (and
// prepends `const __LOUPE_TEST_API__ = true;` to Block 1) when emitting
// `docs/index.test.html`. The default release build (`docs/index.html`) does
// neither, and a build gate (`_check_no_test_api_in_release` in build.py)
// asserts the released bundle contains neither marker.
//
// Tests drive ingress through `window.__loupeTest.loadBytes(name, u8)` which:
//   1. Wraps the bytes in a synthetic `File` (mirroring the file-picker /
//      drag-drop / paste paths exactly — same `App._loadFile` entrypoint).
//   2. Awaits the load to settle (renderer dispatch + auto-YARA scan).
//   3. Tests then call `__loupeTest.dumpFindings()` / `dumpResult()` to read
//      the canonical findings shape that the sidebar / STIX / MISP exports
//      consume — i.e. asserting on the same data the user-visible surfaces
//      project from, not on transient DOM markup that churns more freely.
//
// Read-only contract: this module never mutates `app.findings`,
// `app.currentResult`, `app._yaraResults`, or any other App state. The only
// side effect is the file load itself, which goes through the same path
// `_handleFiles` uses for real ingress.
// ════════════════════════════════════════════════════════════════════════════

extendApp({

  /** Reset cross-load state so successive `loadBytes`/`loadFile` calls
   *  observe a virgin App. The production `_loadFile` slow path tears
   *  down most of this on the way in, but two paths leak across loads:
   *
   *    1. Timeline fast-path (`_timelineTryHandle`) returns *before*
   *       any teardown — so a non-Timeline → Timeline transition
   *       leaves `currentResult` / `_fileMeta` from the prior
   *       renderer load intact and `dumpResult()` reports stale data.
   *
   *    2. Timeline zero-row escape sets `_skipTimelineRoute = true`
   *       inside a `try/finally`. The finally is awaited by the
   *       caller, but the test API's `waitForIdle` watches
   *       `currentResult` / `_yaraScanInProgress` — both of which
   *       can settle BEFORE the finally runs, leaking
   *       `_skipTimelineRoute = true` into the next load and
   *       diverting it away from the Timeline fast-path.
   *
   *  Tests that reuse a single page across fixtures
   *  (`useSharedBundlePage` in the e2e helpers) rely on this clear
   *  running before every load so the next file routes the same way
   *  it would on a virgin page.
   *
   *  Test-only contract: never reaches into App state mid-pipeline
   *  — only nulls cross-load fields that ARE about to be replaced
   *  by the incoming file. The reset never runs while a load is in
   *  flight (callers always `await _loadFile`/`waitForIdle` first).
   *
   *  We intentionally do NOT null `this.findings` here. The renderer
   *  pipeline's `_renderSidebar` reads `findings.risk` early on the
   *  Timeline-extensionless re-route path; nulling it pre-call
   *  surfaces a TypeError before `_loadFile` can re-stamp the field.
   *  Stale `findings` are overwritten by the next renderer's
   *  `analyzeForSecurity`, and the Timeline path leaves them as the
   *  empty projection the test API understands. */
  _testApiResetCrossLoadState() {
    if (this._timelineCurrent) {
      try { this._timelineCurrent.destroy(); } catch (_) { /* noop */ }
      this._timelineCurrent = null;
      const tlHost = (typeof document !== 'undefined')
        && document.getElementById('timeline-root');
      if (tlHost) tlHost.innerHTML = '';
      if (typeof document !== 'undefined') {
        document.body.classList.remove('has-timeline');
      }
    }
    this.currentResult = null;
    this._fileMeta = null;
    this._yaraResults = [];
    // Drop renderer-populated findings so a Timeline-routed load (which
    // never repopulates `findings`) doesn't surface IOCs from the
    // previous renderer's `analyzeForSecurity` in `dumpFindings()`.
    // Production `_clearFile` does the same on the close button. The
    // renderer pipeline that nulls `_fileMeta` will overwrite this
    // before any UI sees it; the early _renderSidebar that crashed on
    // `findings.risk` (during the Timeline zero-row escape's leaked
    // re-entry) is no longer reachable now that `waitForIdle` drains
    // `_timelineLoadInFlight` before returning.
    this.findings = null;
    // The Timeline zero-row escape's finally clause runs after the
    // test API's idle gate has already returned to the test body —
    // see the doc-comment above. Force-clear here so the next load's
    // fast-path sees a fresh slate.
    this._skipTimelineRoute = false;
    this._isCalledByTimelineFallback = false;
  },

  /** Construct a synthetic File around `bytesOrU8` and feed it through the
   *  regular load path. `opts.skipNavReset` is forwarded to `_handleFiles`
   *  so drill-down tests don't clobber the nav stack. Resolves once
   *  `_loadFile` returns AND the auto-YARA scan (worker or sync) has
   *  cleared its in-progress flag — i.e. when `findings` is the steady-
   *  state shape the sidebar paints from. */
  async _testApiLoadBytes(name, bytesOrU8, opts) {
    const o = opts || {};
    let u8;
    if (bytesOrU8 instanceof Uint8Array) {
      u8 = bytesOrU8;
    } else if (bytesOrU8 instanceof ArrayBuffer) {
      u8 = new Uint8Array(bytesOrU8);
    } else if (Array.isArray(bytesOrU8)) {
      u8 = Uint8Array.from(bytesOrU8);
    } else if (typeof bytesOrU8 === 'string') {
      // Plain-text shortcut — useful for paste-equivalent encoded-payload
      // tests where the fixture is text and we don't want to hand-build a
      // Uint8Array on the test side.
      const enc = new TextEncoder();
      u8 = enc.encode(bytesOrU8);
    } else {
      throw new Error('__loupeTest.loadBytes: bytes must be Uint8Array | ArrayBuffer | number[] | string');
    }
    const file = new File([u8], String(name || 'test.bin'),
      { type: o.type || 'application/octet-stream' });
    if (!o.skipNavReset) this._resetNavStack();
    this._testApiResetCrossLoadState();
    await this._loadFile(file);
    await this._testApiWaitForIdle({ timeoutMs: o.timeoutMs || 15000 });
    return this._testApiDumpFindings();
  },

  /** Forward a real File through the regular load path. Used by drag-drop
   *  / paste tests in Playwright that already have a File in hand. */
  async _testApiLoadFile(file, opts) {
    const o = opts || {};
    if (!o.skipNavReset) this._resetNavStack();
    this._testApiResetCrossLoadState();
    await this._loadFile(file);
    await this._testApiWaitForIdle({ timeoutMs: o.timeoutMs || 15000 });
    return this._testApiDumpFindings();
  },

  /** Resolve once the renderer pipeline has settled. Two stages:
   *
   *    1. Wait for either `currentResult` (renderer route) OR
   *       `_timelineCurrent` (Timeline fast-path route) to become
   *       non-null. `_loadFile` returns synchronously for Timeline
   *       formats — it kicks `_loadFileInTimeline(file)` without
   *       `await`, so a test that checks state immediately after
   *       `_loadFile` resolves would observe an "empty" page that's
   *       actually about to mount a Timeline. Polling here lets
   *       Timeline-routed tests assert against the synthetic
   *       `dumpResult()` shape exposed in `_testApiDumpResult` for
   *       Timeline mounts.
   *
   *    2. Wait for `_yaraScanInProgress` to clear. The encoded-content
   *       worker scan, QR decoders, and PE/ELF/Mach-O overlay-hash
   *       post-paint may still mutate findings asynchronously after
   *       this resolves — that's by design; tests opt into
   *       "steady-state at sidebar paint", not "every possible
   *       post-paint mutation has landed". Tests that care about late
   *       mutations should poll `dumpFindings()` themselves.
   *
   *  Both stages share the same `timeoutMs` budget; the timeout
   *  message identifies which stage stalled to make CI failures
   *  diagnosable without re-running with a debugger. */
  async _testApiWaitForIdle(opts) {
    const o = opts || {};
    const timeoutMs = typeof o.timeoutMs === 'number' ? o.timeoutMs : 15000;
    const t0 = Date.now();
    while (!this.currentResult && !this._timelineCurrent) {
      if (Date.now() - t0 > timeoutMs) {
        throw new Error(
          `__loupeTest.waitForIdle: no currentResult/_timelineCurrent after ${timeoutMs}ms`);
      }
      await new Promise(r => setTimeout(r, 25));
    }
    while (this._yaraScanInProgress) {
      if (Date.now() - t0 > timeoutMs) {
        throw new Error(
          `__loupeTest.waitForIdle: yara still in progress after ${timeoutMs}ms`);
      }
      await new Promise(r => setTimeout(r, 25));
    }
    // Drain in-flight Timeline mount. `_timelineTryHandle` kicks
    // `_loadFileInTimeline` fire-and-forget; the zero-row escape inside
    // that promise sets `_skipTimelineRoute=true` then re-enters
    // `_loadFile` and clears the flag in a `finally`. The two prior
    // wait loops resolve on `currentResult` / `_yaraScanInProgress`,
    // both of which can settle inside the inner `_loadFile` BEFORE the
    // outer `finally` runs — leaking `_skipTimelineRoute=true` into the
    // next test's load. Await the tracked promise to flush the outer
    // unwind before returning to the test body. Bounded by `timeoutMs`
    // through `Promise.race`. Swallow errors: the inner load's
    // failure path has already surfaced them via toast / console.
    if (this._timelineLoadInFlight) {
      const remaining = Math.max(0, timeoutMs - (Date.now() - t0));
      await Promise.race([
        this._timelineLoadInFlight.catch(() => {}),
        new Promise(r => setTimeout(r, remaining)),
      ]);
    }
  },

  /** JSON-serialisable snapshot of `app.findings` plus a summary of the
   *  IOC / Detection / YARA tables. Returns a fresh object; mutating the
   *  return value cannot disturb App state. */
  _testApiDumpFindings() {
    const f = this.findings || {};
    const ext = Array.isArray(f.externalRefs) ? f.externalRefs : [];
    const isr = Array.isArray(f.interestingStrings) ? f.interestingStrings : [];
    const allIocs = ext.concat(isr);
    const iocTypes = Array.from(new Set(allIocs.map(e => e && e.type).filter(Boolean))).sort();
    // YARA engine emits each hit as `{ ruleName, tags, meta, condition,
    // matches }` (see `YaraEngine.scan` in src/yara-engine.js:524). The
    // earlier projection here read `r.rule` which never existed — every
    // returned `rule` field came back `undefined`, hiding the rule name
    // from every Playwright assertion. Project from `ruleName` and also
    // surface `meta.tags` / `meta.id` (some YARA rules expose the human
    // identifier under `meta` rather than the AST `tags` array — both
    // are accepted by the test-side filter helpers).
    const yaraHits = Array.isArray(this._yaraResults)
      ? this._yaraResults.map(r => ({
          rule: r && (r.ruleName || r.rule || (r.meta && r.meta.id) || null),
          tags: Array.isArray(r && r.tags) ? r.tags.slice() : [],
          severity: r && r.meta && r.meta.severity,
        }))
      : [];
    return {
      risk: f.risk || null,
      iocTypes,
      iocs: allIocs.map(e => ({
        type: e.type,
        value: e.url,
        severity: e.severity,
        note: e.note,
      })),
      iocCount: allIocs.length,
      externalRefCount: ext.length,
      interestingStringCount: isr.length,
      detectionCount: Array.isArray(f.detections) ? f.detections.length : 0,
      metadata: f.metadata ? Object.assign({}, f.metadata) : {},
      yaraHits,
      yaraInProgress: !!this._yaraScanInProgress,
    };
  },

  /** Snapshot of `app.currentResult` minus the heavy buffers. Used by
   *  tests that need to assert the dispatched renderer / file metadata.
   *
   *  Returns `null` when no file is loaded AND no Timeline view is
   *  mounted. For Timeline-routed loads (CSV/TSV/EVTX/SQLite) the app
   *  short-circuits inside `_loadFile` at the `_timelineTryHandle`
   *  fast-path before ever stamping `currentResult`; in that case we
   *  surface a synthetic `{ timeline: true, … }` shape sourced from
   *  `app._timelineCurrent` so tests can still confirm the file
   *  actually parsed instead of silently no-op'd. */
  _testApiDumpResult() {
    const cr = this.currentResult || null;
    const tlView = this._timelineCurrent || null;
    if (!cr && !tlView) return null;
    if (!cr && tlView) {
      // Timeline-routed load. The TimelineView holds a reference to
      // the original File and, after parse, its row count + format
      // label. We only surface the cheap fields here — the full row
      // table would balloon `dumpResult()` to multi-MB on a real EVTX.
      const file = (tlView._file || tlView.file) || null;
      const rowCount = (Array.isArray(tlView._rows) && tlView._rows.length)
        || (Array.isArray(tlView.rows) && tlView.rows.length)
        || 0;
      return {
        filename: file ? (file.name || null) : null,
        dispatchId: null,
        formatTag: tlView._formatLabel || tlView.formatLabel || null,
        hasBuffer: false,
        hasYaraBuffer: false,
        bufferLength: file ? (file.size | 0) : 0,
        rawTextLength: 0,
        timeline: true,
        timelineRowCount: rowCount,
      };
    }
    return {
      filename: cr.filename || null,
      dispatchId: cr.dispatchId || null,
      formatTag: cr.formatTag || null,
      // Don't leak raw buffers — tests that need byte content can read
      // the synthetic File they passed in.
      hasBuffer: !!cr.buffer,
      hasYaraBuffer: !!cr.yaraBuffer,
      bufferLength: (cr.buffer && cr.buffer.byteLength) || 0,
      // `_rawText` is the LF-normalised plane click-to-focus searches.
      // It lives on the renderer's `docEl`, NOT on `currentResult` —
      // `currentResult` only carries `docEl`, `binary`, `yaraBuffer`
      // and a few metadata fields (see `RenderRoute._emptyResult` in
      // `src/render-route.js`). The previous read of `cr._rawText`
      // always returned 0 because that field never gets written; the
      // canonical source is `currentResult.docEl._rawText`. Fall back
      // to `cr.rawText` (the `RenderResult` typedef field set inside
      // `RenderRoute.run`) for renderers that produce text but never
      // attach a docEl.
      rawTextLength: ((cr.docEl && cr.docEl._rawText && cr.docEl._rawText.length)
        || (cr.rawText && cr.rawText.length) || 0),
      timeline: false,
      timelineRowCount: 0,
    };
  },

});

// Expose the public surface on `window.__loupeTest`. Each entry point is a
// thin wrapper around the App.prototype mixin so test code never needs to
// reach into `window.app` directly. `ready` resolves on the next tick —
// `new App().init()` is synchronous and runs at the end of
// `app-breadcrumbs.js` (the file directly before this one in `--test-api`
// builds), so by the time a test awaits `__loupeTest.ready` the App is
// fully constructed.
(function () {
  if (typeof window === 'undefined') return;
  const ready = new Promise(resolve => {
    const probe = () => {
      if (window.app && typeof window.app._loadFile === 'function') {
        resolve();
      } else {
        setTimeout(probe, 5);
      }
    };
    probe();
  });
  window.__loupeTest = {
    ready,
    async loadBytes(name, bytes, opts) {
      await ready;
      return window.app._testApiLoadBytes(name, bytes, opts);
    },
    async loadFile(file, opts) {
      await ready;
      return window.app._testApiLoadFile(file, opts);
    },
    async waitForIdle(opts) {
      await ready;
      return window.app._testApiWaitForIdle(opts);
    },
    dumpFindings() {
      if (!window.app) return null;
      return window.app._testApiDumpFindings();
    },
    dumpResult() {
      if (!window.app) return null;
      return window.app._testApiDumpResult();
    },
  };
})();
