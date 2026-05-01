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
    // Drop perf-marks from the previous load so the next harness
    // run starts fresh. Production builds never reach this path
    // (the test-API is omitted from `docs/index.html` entirely).
    this._testApiClearPerfMarks();
    this._perfWorkerParseMs = null;
    // Worker-internal marker bag + counters (additive). Reset
    // alongside `_perfWorkerParseMs` so a back-to-back load does not
    // surface the previous file's worker breakdown — same semantics
    // as the host marker bag above. Stamped from `timeline-router.js`
    // on the terminal `done` event, surfaced read-only via the
    // perf-state projection method.
    this._perfWorkerMarks = null;
    this._perfWorkerCounters = null;
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

  /** Stamp a perf sub-phase marker. Test-only — production code paths
   *  invoke this through the `window.__loupePerfMark` global which is
   *  ONLY defined in `--test-api` builds (see the IIFE at the bottom
   *  of this file). The release bundle's call sites read
   *  `window.__loupePerfMark` and short-circuit when undefined, so
   *  the production cost is one property miss per call — no method
   *  dispatch, no allocation.
   *
   *  Markers are stored on `this._perfMarks` (lazy-initialised) as
   *  `{ name: performance.now() }`. They are surfaced read-only via
   *  the perf-state projection's `.marks` field so the perf harness
   *  can compute per-sub-phase deltas of the load → first-paint
   *  critical path.
   *
   *  Each marker is overwritten on subsequent calls with the same
   *  name; this is the desired semantics for the harness because a
   *  fresh `_testApiResetCrossLoadState` cycle wipes the bag and the
   *  next file load re-stamps every marker. The "first occurrence
   *  wins" caller (e.g. `workerColumnsEvent`) is responsible for
   *  guarding its own call site. */
  _testApiPerfMark(name, value) {
    if (typeof name !== 'string' || !name) return;
    if (!this._perfMarks) this._perfMarks = Object.create(null);
    const t = (typeof value === 'number' && Number.isFinite(value))
      ? value
      : ((typeof performance !== 'undefined' && performance.now)
        ? performance.now() : Date.now());
    this._perfMarks[name] = t;
  },

  /** Drop the perf-marks bag. Called from `_testApiResetCrossLoadState`
   *  so consecutive harness loads don't see stale markers from the
   *  previous file. Production paths never call this — markers are
   *  observed once per file load via `perfState()` and the next
   *  load's reset clears them. */
  _testApiClearPerfMarks() {
    this._perfMarks = null;
  },

  /** Read-only snapshot of the App + active TimelineView state used by
   *  the performance harness (`tests/perf/`) to drive multi-phase
   *  measurements without polling internal app state from outside.
   *
   *  Returns a small JSON-safe object — every field is a primitive or
   *  primitive array. The harness polls this via `waitForFunction` to
   *  wait on phase transitions (Timeline mounted → auto-extract pump
   *  drained → GeoIP enrichment landed → fully idle).
   *
   *  Test-only contract: never mutates App / TimelineView state. The
   *  whole method is a sequence of property reads with defensive
   *  fallbacks for the brief windows where one structure exists but
   *  another isn't yet stamped (e.g. between `_loadFile` returning
   *  and the Timeline factory mounting). */
  _testApiPerfState() {
    const tl = this._timelineCurrent || null;
    const extractedCols = (tl && Array.isArray(tl._extractedCols)) ? tl._extractedCols : [];
    // Project per-extracted-column metadata cheaply — only the kind +
    // row-count are needed by the perf harness's `geoip enriched`
    // gate. Sample-values copying is deliberately avoided: the
    // harness should never read enrichment payloads through this API
    // (they belong in the existing `timeline-geoip.spec.ts` shape
    // assertions, not in a perf snapshot polled at 25 ms).
    const extractedSummary = extractedCols.map(c => ({
      kind: (c && c.kind) || null,
      name: (c && c.name) || null,
      rowCount: (c && Array.isArray(c.values)) ? c.values.length : 0,
    }));
    const geoipColCount = extractedSummary.reduce(
      (n, c) => n + (c.kind === 'geoip' ? 1 : 0), 0);
    // Project the perf-marks bag into a fresh JSON-safe object — the
    // harness reads `marks.workerDone` etc. as numbers (ms timestamps
    // from `performance.now()`). When no marks have been stamped yet
    // (e.g. between bundle load and the first file drop) `marks` is
    // an empty object rather than `null` so harness predicates can
    // treat absent keys as `undefined` without a null-guard. Spread
    // makes a shallow copy — direct exposure of `_perfMarks` would
    // let a perf-state consumer mutate live App state.
    const perfMarks = this._perfMarks || null;
    const marks = perfMarks ? Object.assign({}, perfMarks) : {};
    // Worker `parseMs` (the worker's self-reported parse time) is
    // surfaced separately when stamped. The host samples it from
    // `msg.parseMs` on the terminal `done` event — see
    // `src/app/timeline/timeline-router.js`. Held on a single slot
    // (overwritten on each load) for the same lifecycle reason as
    // `marks` above.
    const parseMs = (typeof this._perfWorkerParseMs === 'number')
      ? this._perfWorkerParseMs : null;
    // Worker-internal marker bag + counters (additive optional fields).
    // Same lifecycle as `parseMs` — overwritten per load. Shallow-copy
    // through `Object.assign({}, …)` so a perf-state consumer cannot
    // mutate the live App slot. Empty-object default (rather than
    // `null`) so harness predicates can read keys without a null-guard
    // — mirrors the `marks` field above.
    const wm = this._perfWorkerMarks;
    const wc = this._perfWorkerCounters;
    const workerMarks    = (wm && typeof wm === 'object') ? Object.assign({}, wm) : {};
    const workerCounters = (wc && typeof wc === 'object') ? Object.assign({}, wc) : {};
    return {
      // ── App stage flags ────────────────────────────────────────
      hasCurrentResult: !!this.currentResult,
      timelineMounted: !!tl,
      yaraScanInProgress: !!this._yaraScanInProgress,
      timelineLoadInFlight: !!this._timelineLoadInFlight,
      // ── TimelineView stage flags ───────────────────────────────
      autoExtractApplying: !!(tl && tl._autoExtractApplying),
      // `_autoExtractIdleHandle` carries `{ cancel }` while a tick
      // is scheduled and is nulled at the top of every tick body —
      // so a `null` value with `_autoExtractApplying === false`
      // means the apply pump has fully drained. Surface as a
      // boolean rather than the handle itself so the projection
      // stays JSON-safe.
      autoExtractIdleHandlePending: !!(tl && tl._autoExtractIdleHandle),
      // `null` = base GeoIP detect not yet run; `[]` = base detect
      // ran AND found nothing (the auto-extract terminal hook may
      // schedule a retry over extracted cols, then null it back);
      // non-empty array = base detect found IPs and enriched them.
      // The perf harness's "GeoIP done" gate combines this with
      // `geoipColCount > 0`.
      geoipBaseDetectKind: (tl && tl._geoipBaseDetectResult === null)
        ? 'null'
        : (Array.isArray(tl && tl._geoipBaseDetectResult)
          ? (tl._geoipBaseDetectResult.length === 0 ? 'empty-array' : 'non-empty-array')
          : 'absent'),
      pendingTasksSize: (tl && tl._pendingTasks && typeof tl._pendingTasks.size === 'number')
        ? tl._pendingTasks.size : 0,
      // ── Cheap volumetric counters for the report ───────────────
      timelineRowCount: (tl && tl.store && tl.store.rowCount) || 0,
      baseColCount: (tl && Array.isArray(tl._baseColumns)) ? tl._baseColumns.length : 0,
      extractedColCount: extractedCols.length,
      geoipColCount,
      extractedCols: extractedSummary,
      // ── Perf sub-phase markers ─────────────────────────────────
      // `marks[name] = performance.now()` for every `_perfMark`
      // call since the last `_testApiClearPerfMarks`. Empty object
      // until the first marker fires. See `_testApiPerfMark` above
      // for the lifecycle.
      marks,
      // Worker's self-reported parse time from the terminal `done`
      // event (`msg.parseMs`). `null` until stamped — the harness
      // skips its sub-phase if absent, no error.
      parseMs,
      // Worker-internal sub-phase markers — `{ csvParseStart, …,
      // dispatchEnd }` keyed by name, each value a `performance.now()`
      // timestamp from the worker's own monotonic clock (NOT the
      // host's). The harness computes deltas inside the worker via
      // `worker_subphaseDelta` (no cross-clock arithmetic). Empty
      // object until the first Timeline-routed load completes;
      // additive optional field so older harness bundles ignore it.
      workerMarks,
      // Worker-internal counters — `{ fastPathRows, slowPathRows,
      // chunksPosted, packAndPostMs }` for the CSV path. Diagnostic
      // only; the harness reports them in the Markdown summary so a
      // PR can demonstrate that an optimisation actually shifted
      // time out of the right bucket.
      workerCounters,
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
      // Phase 3: TimelineView keeps rows in a `RowStore` (`tlView.store`)
      // instead of a `string[][]` field. Older code paths used `_rows` /
      // `rows` array fields — kept here as a fallback for any pre-Phase-3
      // mock or transitional caller that still exposes them.
      const rowCount = (tlView.store && tlView.store.rowCount)
        || (Array.isArray(tlView._rows) && tlView._rows.length)
        || (Array.isArray(tlView.rows) && tlView.rows.length)
        || 0;
      // `timelineColumns` surfaces the resolved column header so e2e
      // tests can assert format-specific schemas (Syslog 3164's
      // 7-col canonical list, EVTX's 7-col EVTX_COLUMN_ORDER, …).
      // We pass through the live array reference deliberately — tests
      // assert `.toEqual([...])` which compares by value, not identity.
      const tlCols = (tlView && Array.isArray(tlView._columns))
        ? tlView._columns.slice()
        : (Array.isArray(tlView.columns) ? tlView.columns.slice() : []);
      // `timelineBaseColumns` surfaces the IMMUTABLE base schema (i.e.
      // the parser's column output before any `_extractedCols` are
      // appended by the auto-extract idle pump or GeoIP enrichment).
      // Tests that assert "the schema's trailing column is `_extra`"
      // or pin specific column indexes need this stable view —
      // `timelineColumns` (the live `tlView.columns` getter) grows
      // asynchronously after mount as `_autoExtractBestEffort` (+60 ms
      // post-mount idle ticks) and `_runGeoipEnrichment` (+100 ms +
      // post-`_app`-wire +0 ms) push extracted/enriched columns. The
      // base list is set once during parser construction and never
      // mutated afterwards, so a test that reads it via `dumpResult`
      // is race-free regardless of where the auto-extract pump is.
      const tlBaseCols = (tlView && Array.isArray(tlView._baseColumns))
        ? tlView._baseColumns.slice()
        : tlCols.slice();
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
        timelineColumns: tlCols,
        timelineBaseColumns: tlBaseCols,
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
  // Free-function entry point for in-app perf marker stamping. The
  // release bundle does NOT ship this file, so `window.__loupePerfMark`
  // is undefined and call sites short-circuit on a single property
  // miss with no method dispatch. Test builds get the live function
  // here. `value` is optional — when provided it overrides the default
  // `performance.now()` timestamp (used for the worker-side
  // `parseMs` plumbing).
  window.__loupePerfMark = function (name, value) {
    if (!window.app || typeof window.app._testApiPerfMark !== 'function') return;
    window.app._testApiPerfMark(name, value);
  };
  // Dedicated slot for the worker's `parseMs` self-report. Surfaced
  // separately on `perfState()` so the harness can attribute parse
  // time to the worker without inferring it from the
  // `workerFirstChunk → workerDone` delta (which includes the host's
  // `RowStoreBuilder.addChunk` cost too).
  window.__loupePerfWorkerParseMs = function (ms) {
    if (!window.app) return;
    if (typeof ms !== 'number' || !Number.isFinite(ms)) return;
    window.app._perfWorkerParseMs = ms;
  };
  // Worker-internal marker bag (additive). Receives the
  // `msg.workerMarks` object from the terminal `done` event in
  // `timeline-router.js`. The setter shallow-copies into a fresh
  // dictionary so the App slot is detached from the postMessage
  // payload (defensive: prevents a future "structured-clone returns
  // a frozen prototype" foot-gun). No-op if the argument isn't a
  // plain object — older worker bundles omit the field entirely.
  window.__loupePerfWorkerMarks = function (snapshot) {
    if (!window.app) return;
    if (!snapshot || typeof snapshot !== 'object') return;
    window.app._perfWorkerMarks = Object.assign({}, snapshot);
  };
  // Worker-internal counters (additive). Same contract as
  // `__loupePerfWorkerMarks`.
  window.__loupePerfWorkerCounters = function (snapshot) {
    if (!window.app) return;
    if (!snapshot || typeof snapshot !== 'object') return;
    window.app._perfWorkerCounters = Object.assign({}, snapshot);
  };

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
    // Read-only state observer for `tests/perf/`. Cheap synchronous
    // call (no awaits, no allocations besides the result object) so
    // the perf harness can poll it at 25 ms without skewing
    // measurements.
    perfState() {
      if (!window.app) return null;
      return window.app._testApiPerfState();
    },
    // Stamp a custom perf marker. Used by tests that want to mark a
    // boundary the harness can't reach via the existing in-app
    // markers (e.g. "harness saw the first .grid-row"). Production
    // call sites use the `_perfMark` global helper which no-ops in
    // release builds.
    perfMark(name) {
      if (!window.app) return;
      window.app._testApiPerfMark(name);
    },
  };
})();
