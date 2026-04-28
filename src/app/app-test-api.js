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
    await this._loadFile(file);
    await this._testApiWaitForIdle({ timeoutMs: o.timeoutMs || 15000 });
    return this._testApiDumpFindings();
  },

  /** Forward a real File through the regular load path. Used by drag-drop
   *  / paste tests in Playwright that already have a File in hand. */
  async _testApiLoadFile(file, opts) {
    const o = opts || {};
    if (!o.skipNavReset) this._resetNavStack();
    await this._loadFile(file);
    await this._testApiWaitForIdle({ timeoutMs: o.timeoutMs || 15000 });
    return this._testApiDumpFindings();
  },

  /** Resolve once `_yaraScanInProgress` is unset/false. The encoded-content
   *  worker scan, QR decoders, and PE/ELF/Mach-O overlay-hash post-paint
   *  may still mutate findings asynchronously after this resolves — that's
   *  by design; tests opt into "steady-state at sidebar paint", not "every
   *  possible post-paint mutation has landed". Tests that care about late
   *  mutations should poll `dumpFindings()` themselves. */
  async _testApiWaitForIdle(opts) {
    const o = opts || {};
    const timeoutMs = typeof o.timeoutMs === 'number' ? o.timeoutMs : 15000;
    const t0 = Date.now();
    while (this._yaraScanInProgress) {
      if (Date.now() - t0 > timeoutMs) {
        throw new Error(`__loupeTest.waitForIdle: timed out after ${timeoutMs}ms`);
      }
      await new Promise(r => setTimeout(r, 25));
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
    const yaraHits = Array.isArray(this._yaraResults)
      ? this._yaraResults.map(r => ({
          rule: r && r.rule,
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
   *  tests that need to assert the dispatched renderer / file metadata. */
  _testApiDumpResult() {
    const cr = this.currentResult || null;
    if (!cr) return null;
    return {
      filename: cr.filename || null,
      dispatchId: cr.dispatchId || null,
      formatTag: cr.formatTag || null,
      // Don't leak raw buffers — tests that need byte content can read
      // the synthetic File they passed in.
      hasBuffer: !!cr.buffer,
      hasYaraBuffer: !!cr.yaraBuffer,
      bufferLength: (cr.buffer && cr.buffer.byteLength) || 0,
      // _rawText is what click-to-focus searches; expose its length so
      // tests can sanity-check it was populated and LF-normalised.
      rawTextLength: (cr._rawText && cr._rawText.length) || 0,
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
