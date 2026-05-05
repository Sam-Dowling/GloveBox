// ════════════════════════════════════════════════════════════════════════════
// App — core class definition, constructor, init, drop-zone, toolbar wiring
// ════════════════════════════════════════════════════════════════════════════

// ── extendApp(obj) — collision-checked App.prototype mixin ───────────────────
// Every App-method file follows the `Object.assign(App.prototype, { ... })`
// pattern. The plain `Object.assign` is silently last-writer-wins: rename a
// method in two mixins and the second silently shadows the first with no
// runtime warning. `extendApp(obj)` is the same contract with one extra
// guarantee — if any key in `obj` is already defined on `App.prototype`, the
// build aborts loudly at load time so the conflict is visible the moment the
// page boots.
//
// Migrate every `Object.assign(App.prototype, { ... })` site to
// `extendApp({ ... })`; the build gate `_check_app_mixin_collisions` in
// `scripts/build.py` enforces the migration.
function extendApp(obj) {
  if (!obj || typeof obj !== 'object') return;
  for (const k of Object.keys(obj)) {
    if (Object.prototype.hasOwnProperty.call(App.prototype, k)) {
      throw new Error(
        `extendApp: App.prototype.${k} is already defined. ` +
        `Two mixins are colliding on the same method name — rename one.`
      );
    }
  }
  Object.assign(App.prototype, obj);
}
window.extendApp = extendApp;

class App {
  constructor() {
    this.zoom = 100; this.dark = true; this.findings = null;
    this.fileHashes = null; this.sidebarOpen = false; this.activeTab = 'summary';
    this.currentResult = null; this._yaraResults = null; this._yaraEscHandler = null;
    // ── Render-epoch fence (Phase-1 of the C1/C2/C3 fix) ────────────────
    // Monotonic counter bumped by `RenderRoute.run` on entry and on every
    // fallback (watchdog timeout, size-cap, generic renderer error). Phase-2
    // callers (PE/ELF/Mach-O/EVTX/encoded loops + WorkerManager + the next
    // `_loadFile` invocation) capture it and ignore stale callbacks. The
    // current contract: any code path that intends to write to `app.findings`
    // / `app.currentResult` long after `RenderRoute.run` returned should
    // capture this value at the moment the work is queued and bail when it
    // no longer matches. See PLAN.md C1 + the "Render-epoch fence" block in
    // src/render-route.js.
    this._renderEpoch = 0;
    // ── Drill-down navigation stack (single-owner, H6) ──────────────────
    // Always an Array — initialised here so every read site can rely on
    // the invariant without a `!this._navStack` guard. Mutated by the
    // drill-down helpers in `app-load.js` (push) / `_navJumpTo` (pop)
    // and cleared via `_resetNavStack()` (this file). Never overwritten
    // with a fresh `[]` literal — clears go through `_resetNavStack` so
    // breadcrumb repaint stays in lockstep.
    this._navStack = [];
    // ── Aggregate archive-expansion budget (single owner, H5) ───────────
    // Shared across every archive renderer in the recursive drill-down
    // chain. Reset only on top-level loads via `_handleFiles` —
    // drill-down loads (which call `_loadFile` directly) intentionally
    // share the budget so the recursion is bounded as a whole. See
    // `src/archive-budget.js` for the contract.
    this._archiveBudget = (typeof ArchiveBudget !== 'undefined')
      ? new ArchiveBudget()
      : null;
    // ── Single global App handle ───────────────────────────────────────
    // A handful of long-lived async tasks (PE/ELF/Mach-O overlay-hash
    // post-paint, worker-manager timeout breadcrumbs) need to reach back
    // into the App without threading a parameter through every layer.
    // They probe `window.app && typeof window.app.X === 'function'` and
    // no-op when the handle is missing — but until H5 nothing actually
    // assigned the handle, so those probes were silently always-false.
    // H5 also needs a stable reach-up so archive renderers can query
    // `window.app._archiveBudget` from inside their static `render()`
    // entry points without changing every renderer signature.
    //
    // The constructor is the right place: `new App().init()` is invoked
    // exactly once at the bottom of `app-breadcrumbs.js`, every consumer
    // runs strictly after `init()` returns, and overwriting on a
    // hypothetical second `new App()` is harmless because the old
    // instance has no live references by that point.
    if (typeof window !== 'undefined') window.app = this;
  }

  init() {
    this._initTheme();    // applies persisted theme preference or default
    this._initSettings(); // restores summary-budget step + paints ⚡ chip
    // Dev-mode debug breadcrumb ribbon. No-op unless the
    // `loupe_dev_breadcrumbs` localStorage flag is "1". Helper is defined
    // in `src/app/app-breadcrumbs.js` and is loaded after this file via
    // the JS_FILES order in scripts/build.py — guard with `typeof` so an
    // earlier-init crash here doesn't take the whole boot down with it.
    if (typeof this._initBreadcrumbs === 'function') {
      try { this._initBreadcrumbs(); } catch (_) { /* diagnostics are cosmetic */ }
    }
    // Subtle per-theme animated background on the landing surface.
    // Lives in its own module (`app-bg.js`) and exposes a tiny
    // `window.BgCanvas` singleton. Safe to no-op if the module failed to
    // load for any reason (we never want a cosmetic effect to break init).
    //
    // Deferred via `requestIdleCallback` (with a `setTimeout` fallback for
    // browsers without the API) so the canvas tiling/network build never
    // shares a task with the App constructor. Profiler markers showed the
    // dots-animation paint was acting as the visual "ready" cue for users,
    // who would attempt drag-and-drop just before it appeared and miss the
    // App's drop handlers — see `early-drop-bootstrap.js` for the other
    // half of that fix. Pushing the cosmetic build off the construct task
    // makes the page genuinely interactive ahead of the dots, removing
    // the misleading visual gate.
    try {
      if (window.BgCanvas) {
        const startBg = () => {
          try { window.BgCanvas.init(); } catch (_) { /* background is cosmetic */ }
        };
        if (typeof window.requestIdleCallback === 'function') {
          window.requestIdleCallback(startBg, { timeout: 500 });
        } else {
          setTimeout(startBg, 0);
        }
      }
    } catch (_) { /* background is cosmetic */ }
    // ── GeoIP provider resolvers ────────────────────────────────────────
    // Two parallel surfaces feed the Timeline GeoIP enrichment mixin:
    //
    //   `app.geoip`     — IPv4 → geo (country / iso / region / city).
    //                     Always set; falls back to BundledGeoip when no
    //                     MMDB has been uploaded.
    //   `app.geoipAsn`  — IPv4 → ASN (asn / org). Null until the analyst
    //                     uploads an ASN MMDB; no bundled fallback (the
    //                     bundled provider is RIR-country only).
    //
    // Three providers share one contract (`lookupIPv4` / `formatRow` /
    // `getFieldName` / `vintage` / `providerKind`); MmdbReader extends it
    // with `lookupAsn` / `formatAsnRow` / `getAsnFieldName` / `detectSchema`:
    //
    //   • BundledGeoip — RIR-derived IPv4-country, embedded in the bundle
    //     as `__GEOIP_BUNDLE_B64`. Always present (~140 K ranges). Geo only.
    //   • MmdbReader (geo slot) — user-uploaded city / country MMDB via
    //     Settings. Persisted in IndexedDB. Takes precedence over the
    //     bundled provider when present (richer data — adds region + city).
    //   • MmdbReader (asn slot) — user-uploaded ASN MMDB via Settings.
    //     Independent slot in IndexedDB. When present, the timeline mixin
    //     emits a SECOND column (`<ip>.asn`) alongside the geo column.
    //
    // The bundled provider is set synchronously so the Timeline view's
    // constructor (which fires shortly after init() returns) has a
    // working provider on first paint. Both MMDB hydrates are async and
    // run in parallel; if either lands later than first paint, the
    // Timeline mixin re-runs enrichment when the hydrate resolves.
    if (typeof BundledGeoip !== 'undefined') {
      this.geoip = BundledGeoip;
      this.geoipAsn = null;
      // Best-effort async hydrate of BOTH slots from IndexedDB. Failures
      // are silent per-slot — the bundled fallback already covers the
      // common geo case, and ASN is purely additive.
      if (typeof GeoipStore !== 'undefined' && typeof MmdbReader !== 'undefined') {
        const reEnrich = () => {
          if (this._timelineCurrent && typeof this._timelineCurrent._runGeoipEnrichment === 'function') {
            try { this._timelineCurrent._runGeoipEnrichment(); } catch (_) { /* noop */ }
          }
          // Sidebar IOC + Summary surfaces consume `app.geoip` /
          // `app.geoipAsn` via `_enrichIpForExport`. When the analyst
          // uploads an MMDB (or the IndexedDB hydrate completes after
          // first paint), re-render the sidebar so the geo / ASN lines
          // appear without forcing a file reload. Cheap when the
          // sidebar is hidden or no file is loaded — both early-exit.
          try {
            if (this.findings && typeof this._renderSidebar === 'function') {
              const sb = (typeof document !== 'undefined') ? document.getElementById('sidebar') : null;
              if (sb && !sb.classList.contains('hidden')) {
                this._renderSidebar(
                  (this._fileMeta && this._fileMeta.name) || '',
                  this._currentAnalyzer || null,
                );
              }
            }
          } catch (_) { /* sidebar re-render is additive */ }
        };
        (async () => {
          try {
            const rec = await GeoipStore.load('geo');
            if (!rec || !rec.blob) return;
            this.geoip = await MmdbReader.fromBlob(rec.blob);
            reEnrich();
          } catch (_) { /* geo MMDB hydrate is best-effort */ }
        })();
        (async () => {
          try {
            const rec = await GeoipStore.load('asn');
            if (!rec || !rec.blob) return;
            this.geoipAsn = await MmdbReader.fromBlob(rec.blob);
            reEnrich();
          } catch (_) { /* asn MMDB hydrate is best-effort */ }
        })();
      }
    }

    this._setupDrop();


    this._setupToolbar();
    this._setupSidebarResize();
    this._setupViewerPan();
    this._setupSearch();
    // Selection-decode chip — listens for click+drag selections inside the
    // content viewer and pipes the highlighted bytes through the encoded-
    // content pipeline as a synthetic File. Defined in
    // `src/app/app-selection-decode.js`; guard with `typeof` since module
    // load order is enforced by scripts/build.py but the chip is purely
    // additive — a missing module must not take the rest of init down.
    if (typeof this._setupSelectionDecode === 'function') {
      try { this._setupSelectionDecode(); } catch (_) { /* chip is additive */ }
    }
    this._initTimelineState();
    this._checkVersionParam();
    this._checkHostedMode();
    // Keyboard shortcuts: Ctrl/Cmd+Enter=⚡ Summary, S=toggle sidebar,
    // Y=YARA dialog, F=focus document search.
    // F (not Ctrl+F) is used because every major browser reserves Ctrl+F for its
    // own find-in-page bar and the hijack is brittle / user-hostile.
    // Drill-down navigation (archives, PDF attachments, etc.) is driven
    // exclusively by the toolbar breadcrumb trail — no back/forward
    // shortcuts or mouse side-button handlers are wired up.
    document.addEventListener('keydown', e => {
      // ── First-class shortcut: Ctrl+Enter / Cmd+Enter → ⚡ Summary ─────
      // Sits ABOVE the input/modifier guard so analysts can fire it from
      // any focused field (sidebar search, doc-search, YARA editor, etc.).
      // No-op when no file is loaded (viewer toolbar hidden). Forwards to
      // the toolbar button itself rather than calling _copyAnalysis()
      // directly, so any future button-level decoration (disabled state,
      // visual feedback) flows through one path.
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter' && !e.altKey && !e.shiftKey) {
        const tb = document.getElementById('viewer-toolbar');
        if (!tb || tb.classList.contains('hidden')) return;
        const btn = document.getElementById('btn-copy-analysis');
        if (btn && !btn.disabled) { e.preventDefault(); btn.click(); }
        return;
      }
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.altKey || e.ctrlKey || e.metaKey) return;
      if (e.key === 's' || e.key === 'S') this._toggleSidebar();
      else if (e.key === 'y' || e.key === 'Y') this._openYaraDialog();
      else if (e.key === 'n' || e.key === 'N') this._openSettingsDialog('nicelists');
      else if (e.key === 't' || e.key === 'T') this._openSettingsDialog('themes');
      else if (e.key === ',') this._openSettingsDialog('settings');
      else if (e.key === '?' || e.key === 'h' || e.key === 'H') this._openSettingsDialog('help');
      else if (e.key === 'f' || e.key === 'F') {
        // Only hijack F when a file is loaded (viewer toolbar is visible),
        // otherwise silently pass through so the user can still type F into
        // future inputs on the drop-zone screen.
        const tb = document.getElementById('viewer-toolbar');
        if (!tb || tb.classList.contains('hidden')) return;
        const si = document.getElementById('doc-search');
        if (si) { e.preventDefault(); si.focus(); si.select(); }
      }
    });

  }


  _setupDrop() {
    const dz = document.getElementById('drop-zone'), fi = document.getElementById('file-input');

    // ── Full-page drag overlay ──────────────────────────────────────────
    // Sits above everything so dropped files are captured by the app.
    // Combined with .html-drag-shield elements that cover iframes, this
    // prevents files from being opened/downloaded inside iframe content.
    const overlay = document.createElement('div');
    overlay.id = 'drag-overlay';
    document.body.appendChild(overlay);

    let _dragCounter = 0;

    const showOverlay = () => {
      overlay.style.display = 'block';
    };

    const hideOverlay = () => {
      overlay.style.display = '';
      _dragCounter = 0;
    };

    // ── Window-level drag handlers ──────────────────────────────────────
    // Handles drags that enter over normal page elements (not iframes).
    //
    // These handlers are only for **external file drags from the OS**.
    // Internal DOM drags (e.g. the Timeline "🏆 Top values" card reorder
    // in app-timeline.js — `head.draggable = true` + `dragstart` on
    // `.tl-col-head`) must be allowed to bubble to their own handlers.
    // If we preventDefault on dragover here for every drag, the whole
    // window "accepts drops" and `#drag-overlay` (z-index 99999) eclipses
    // the cards so the in-page drop never fires. Gate on
    // `DataTransfer.types` containing `'Files'` — which is only present
    // for OS file drags — so internal drags pass through cleanly.
    const isExternalFileDrag = (e) => {
      const t = e && e.dataTransfer && e.dataTransfer.types;
      if (!t) return false;
      // DOMStringList in some browsers, array-like in others — use
      // Array.from so `.includes` works uniformly.
      return Array.from(t).indexOf('Files') !== -1;
    };

    window.addEventListener('dragenter', e => {
      if (!isExternalFileDrag(e)) return;
      e.preventDefault();
      _dragCounter++;
      // Skip overlay when YARA dialog is open — let its own drag handlers fire
      if (_dragCounter === 1 && !document.getElementById('yara-dialog')) showOverlay();
    });

    window.addEventListener('dragover', e => {
      if (!isExternalFileDrag(e)) return;
      e.preventDefault();
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
      if (!dz.classList.contains('has-document')) dz.classList.add('drag-over');
    });

    window.addEventListener('dragleave', e => {
      if (!isExternalFileDrag(e)) return;
      _dragCounter--;
      if (_dragCounter <= 0) {
        hideOverlay();
        dz.classList.remove('drag-over');
      }
    });

    window.addEventListener('drop', e => {
      if (!isExternalFileDrag(e)) return;
      e.preventDefault();
      e.stopPropagation();
      hideOverlay();
      dz.classList.remove('drag-over');
      // Two ingress shapes:
      //   • `dataTransfer.items` — required for directory drops
      //     (`webkitGetAsEntry()` only lives on items, not files).
      //   • `dataTransfer.files` — flat fallback for browsers / drags
      //     that don't expose items (rare today; OS clipboard files
      //     pasted via drag are one historical source).
      const dt = e.dataTransfer;
      const items = (dt && dt.items) ? Array.from(dt.items) : [];
      const fsEntries = items
        .filter(it => it && it.kind === 'file' && typeof it.webkitGetAsEntry === 'function')
        .map(it => it.webkitGetAsEntry())
        .filter(Boolean);
      if (fsEntries.length) {
        // `_handleFiles` is the single-owner ingress; it picks the right
        // path (single-file vs synthetic folder) based on what's
        // available. We pass the entries on a side channel so it can
        // walk directories without us repeating the logic.
        this._handleFiles(dt.files, { fsEntries });
        return;
      }
      if (dt && dt.files && dt.files.length) {
        this._handleFiles(dt.files);
      }
    });

    window.addEventListener('dragend', () => {
      hideOverlay();
      dz.classList.remove('drag-over');
    });

    // ── Drag shield event handlers ──────────────────────────────────────
    // Handles drags that enter directly over sandboxed iframes. The
    // .html-drag-shield element dispatches these custom events because
    // normal drag events go directly to the iframe's content document.
    window.addEventListener('loupe-dragenter', () => {
      _dragCounter++;
      if (_dragCounter === 1) showOverlay();
    });

    window.addEventListener('loupe-dragleave', () => {
      _dragCounter--;
      if (_dragCounter <= 0) {
        hideOverlay();
        dz.classList.remove('drag-over');
      }
    });

    window.addEventListener('loupe-drop', e => {
      hideOverlay();
      dz.classList.remove('drag-over');
      if (e.detail?.files) {
        this._handleFiles(e.detail.files);
      }
    });

    // ── Drop-zone click / file-input ────────────────────────────────────
    dz.addEventListener('click', () => fi.click());
    fi.addEventListener('change', e => {
      const files = e.target.files;
      if (files && files.length) {
        // `webkitdirectory` is opt-in — when the picker is configured
        // for it, the browser walks the directory tree itself and the
        // FileList contains every leaf with a `webkitRelativePath`. We
        // route through `_handleFiles` either way; it picks the right
        // path (single file vs synthetic folder) based on whether the
        // FileList carries multiple entries / relative paths.
        this._handleFiles(files);
      }
      fi.value = '';
    });

    // ── Drain pending early-bootstrap drops/pastes ─────────────────────
    // `src/app/early-drop-bootstrap.js` runs before the heavy vendor
    // inlines and the App constructor. Any file the user dropped (or
    // pasted) during the cold-load window lands on
    // `window.__loupePendingDrop` / `window.__loupePendingPaste` as a
    // plain array of `File` objects. Now that the App owns drag/drop,
    // tear the bootstrap down and feed any captured files through the
    // normal load path. Drop wins over paste — a deliberate drag is the
    // stronger user intent and we don't want a stale clipboard to
    // override it. Both buffers are cleared so nothing leaks across
    // future loads.
    try {
      const earlyDrop = window.__loupePendingDrop;
      const earlyDropEntries = window.__loupePendingDropEntries;
      const earlyPaste = window.__loupePendingPaste;
      if (typeof window.__loupeEarlyDropTeardown === 'function') {
        window.__loupeEarlyDropTeardown();
      }
      window.__loupePendingDrop = null;
      window.__loupePendingDropEntries = null;
      window.__loupePendingPaste = null;
      if (Array.isArray(earlyDropEntries) && earlyDropEntries.length) {
        // Folder / multi-item drop captured before App boot. Route
        // through `_handleFiles` with the entries on the side channel
        // so directory walking happens via `webkitGetAsEntry`.
        this._handleFiles(earlyDrop, { fsEntries: earlyDropEntries });
      } else if (Array.isArray(earlyDrop) && earlyDrop.length) {
        // Use _handleFiles so the nav-stack clear lives in one place.
        this._handleFiles(earlyDrop);
      } else if (Array.isArray(earlyPaste) && earlyPaste.length) {
        this._handleFiles(earlyPaste);
      }
    } catch (_) { /* early-drop drain is cosmetic — never break boot */ }
  }

  _setupToolbar() {
    document.getElementById('btn-open').addEventListener('click', () => document.getElementById('file-input').click());
    document.getElementById('btn-close').addEventListener('click', () => {
      // Timeline view owns its own cleanup path; fall through to the regular
      // analyser close otherwise. `_timelineCurrent` is the single source of
      // truth for "a timeline file is loaded right now".
      if (this._timelineCurrent) this._clearTimelineFile();
      else this._clearFile();
    });

    document.getElementById('btn-security').addEventListener('click', () => this._toggleSidebar());
    document.getElementById('btn-yara').addEventListener('click', () => this._openYaraDialog());
    document.getElementById('btn-settings').addEventListener('click', () => this._openSettingsDialog('settings'));
    document.getElementById('btn-copy-analysis').addEventListener('click', () => this._copyAnalysis());
    document.getElementById('btn-export').addEventListener('click', () => this._toggleExportMenu());
    document.getElementById('btn-zoom-out').addEventListener('click', () => this._setZoom(this.zoom - 10));
    document.getElementById('btn-zoom-in').addEventListener('click', () => this._setZoom(this.zoom + 10));

    // Ctrl+V paste shortcut (when not focused on an input)
    document.addEventListener('paste', e => {
      // Don't intercept paste in text inputs, textareas, or YARA editor
      const tag = (e.target.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea') return;
      e.preventDefault();
      // Timeline mode gates paste behind a confirmation dialog: clipboards
      // frequently contain sensitive material (credentials, customer data),
      // and silently swapping out a loaded EVTX / CSV with whatever happens
      // to be on the clipboard is a foot-gun. The dialog previews the first
      // few hundred chars / reports non-text payload type so the analyst
      // can make an informed choice.
      if (this._timelineCurrent) {
        this._confirmTimelinePaste(e.clipboardData);
        return;
      }
      this._handlePasteEvent(e);
    });

    // Strip HTML from copy selections inside viewer panes so that
    // Ctrl+C / drag-select copies clean plain text, not table markup.
    //
    // When nothing is selected, Ctrl+C / Cmd+C copies the *whole raw
    // file* — mirrors the Export-menu "📋 Copy raw content" action so
    // the intuitive power-user gesture just works. We bail when focus
    // is on an editable surface (the browser's native empty-selection
    // copy is what the user expects there) and let `_isRawCopyable()`
    // gate out the binary denylist (PE / PDF / archives / bplist / …).
    document.addEventListener('copy', e => {
      const sel = window.getSelection();
      const hasSelection = sel && !sel.isCollapsed && sel.toString().length > 0;

      if (!hasSelection) {
        const ae = document.activeElement;
        const aeTag = ((ae && ae.tagName) || '').toLowerCase();
        const inEditable = aeTag === 'input' || aeTag === 'textarea' ||
          (ae && ae.isContentEditable);
        if (inEditable) return;
        if (!this.currentResult || !this.currentResult.buffer || !this._isRawCopyable()) return;
        e.preventDefault();
        this._copyContent();   // handles UTF-8 decode, _lastCopiedMeta, toast
        return;
      }

      const node = sel.anchorNode;
      if (!node) return;
      const el = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
      if (!el) return;
      if (el.closest('.plaintext-scroll, .html-source-pane, .hex-dump')) {
        e.preventDefault();
        e.clipboardData.setData('text/plain', sel.toString());
      }
    });
  }

  _handlePasteEvent(e) {
    const dt = e.clipboardData;
    if (!dt) return;
    this._loadPastePayload(dt);
  }

  // Extracts whatever is on the clipboard and feeds it to `_loadFile` using
  // the same priority order as the historical paste handler: OS files →
  // clipboard images → plain text (with same-session copy round-trip
  // preservation) → HTML fallback. Split out of `_handlePasteEvent` so the
  // timeline confirmation dialog can reuse the loading path without
  // re-reading the clipboard (which would be empty by the time the user
  // clicks "Load for analysis").
  _loadPastePayload(dt) {
    if (!dt) return;

    // Check for files (e.g., copied file from explorer, screenshot)
    if (dt.files && dt.files.length) {
      this._loadFile(dt.files[0]);
      return;
    }

    // Check for images in clipboard items
    for (const item of (dt.items || [])) {
      if (item.type && item.type.startsWith('image/')) {
        const blob = item.getAsFile();
        if (blob) {
          const ext = item.type.split('/')[1] === 'jpeg' ? 'jpg' : item.type.split('/')[1];
          const file = new File([blob], `clipboard.${ext}`, { type: item.type });
          this._loadFile(file);
          return;
        }
      }
    }

    // Prefer plain text over HTML so that pasting from apps like Slack
    // gives the actual text content, not rich formatting / table markup.
    const text = dt.getData('text/plain');
    if (text && text.trim()) {
      // Same-session round-trip: if this text matches what `_copyContent`
      // just put on the clipboard (modulo CRLF→LF normalisation that the
      // Web Clipboard API performs on text/plain), reload the original
      // bytes + filename instead of a freshly-built `clipboard.txt`.
      // Without this, pasting a just-copied .applescript silently changes
      // the file's SHA-256 and its extension, which in turn makes
      // `RendererRegistry.detect()` fall through to highlight.js auto-detect —

      // confusing in a security tool where the hash is the identity.
      const cached = this._lastCopiedMeta;
      if (cached && cached.buffer && cached.normText &&
        text.replace(/\r\n/g, '\n') === cached.normText) {
        const file = new File([cached.buffer], cached.name,
          { type: 'application/octet-stream' });
        this._loadFile(file);
        return;
      }
      const file = new File([text], 'clipboard.txt', { type: 'text/plain' });
      this._loadFile(file);
      return;
    }

    // Fallback to HTML if no plain text available
    const html = dt.getData('text/html');
    if (html && html.trim()) {
      const file = new File([html], 'clipboard.html', { type: 'text/html' });
      this._loadFile(file);
      return;
    }

    this._toast('Nothing to paste', 'error');
  }

  // Build a short, human-readable description + preview of whatever is
  // on the clipboard so the timeline paste-confirm dialog can tell the
  // user what they're about to load. Returns { kind, preview } where
  // `preview` is already truncated for display.
  _describePasteClipboard(dt) {
    if (!dt) return { kind: 'empty', preview: '' };

    if (dt.files && dt.files.length) {
      const f = dt.files[0];
      const kb = Math.max(1, Math.round((f.size || 0) / 1024));
      return { kind: 'file', preview: `[file: ${f.name || 'clipboard'} — ${kb} KB]` };
    }

    for (const item of (dt.items || [])) {
      if (item.type && item.type.startsWith('image/')) {
        return { kind: 'image', preview: `[image: ${item.type}]` };
      }
    }

    const text = dt.getData('text/plain');
    if (text && text.trim()) {
      const MAX = 400;
      const trimmed = text.length > MAX ? text.slice(0, MAX) + '…' : text;
      return { kind: 'text', preview: trimmed };
    }

    const html = dt.getData('text/html');
    if (html && html.trim()) {
      const MAX = 400;
      const trimmed = html.length > MAX ? html.slice(0, MAX) + '…' : html;
      return { kind: 'html', preview: trimmed };
    }

    return { kind: 'empty', preview: '' };
  }

  // Timeline paste gate: frost-overlay confirmation before replacing the
  // currently-loaded timeline with clipboard content. Reuses the
  // `.help-overlay` / `.help-dialog` / `.update-btn` classes so the look
  // matches the existing version-check modal and picks up every theme for
  // free. All user-controlled data (the clipboard preview) is set via
  // `textContent` — never `innerHTML` — so the strict CSP stays intact.
  _confirmTimelinePaste(dt) {
    const info = this._describePasteClipboard(dt);
    if (info.kind === 'empty') {
      this._toast('Nothing to paste', 'error');
      return;
    }

    // Snapshot clipboard data synchronously while DataTransfer is still
    // valid.  The browser invalidates the DataTransfer object once the
    // paste-event handler returns, so by the time the user clicks
    // "Load for analysis" the original `dt` would be empty.  The snapshot
    // mimics the DataTransfer surface that `_loadPastePayload` consumes.
    const snapshot = {
      files: dt.files && dt.files.length ? Array.from(dt.files) : [],
      items: [],
      _textPlain: dt.getData('text/plain'),
      _textHtml:  dt.getData('text/html'),
      getData(type) {
        if (type === 'text/plain') return this._textPlain;
        if (type === 'text/html')  return this._textHtml;
        return '';
      },
    };
    for (const item of (dt.items || [])) {
      if (item.type && item.type.startsWith('image/')) {
        const blob = item.getAsFile();
        if (blob) snapshot.items.push({ type: item.type, getAsFile: () => blob });
      }
    }

    const overlay = document.createElement('div');
    overlay.className = 'help-overlay timeline-paste-overlay';

    const dialog = document.createElement('div');
    dialog.className = 'help-dialog';

    const header = document.createElement('div');
    header.className = 'help-header';
    const title = document.createElement('div');
    title.className = 'help-title';
    title.textContent = 'Replace timeline with pasted content?';
    header.appendChild(title);
    const closeX = document.createElement('button');
    closeX.className = 'help-close';
    closeX.type = 'button';
    closeX.title = 'Cancel';
    closeX.textContent = '✕';
    header.appendChild(closeX);
    dialog.appendChild(header);

    const body = document.createElement('div');
    body.className = 'help-body';

    const p1 = document.createElement('p');
    p1.textContent = 'You pasted while a timeline was open. Loading clipboard content will close the current timeline and analyse the pasted data as a new file.';
    body.appendChild(p1);

    const p2 = document.createElement('p');
    const kindLabel = {
      file: 'a file from the clipboard',
      image: 'an image from the clipboard',
      text: 'plain text',
      html: 'HTML',
    }[info.kind] || 'clipboard content';
    p2.textContent = `Detected: ${kindLabel}. Preview:`;
    body.appendChild(p2);

    const pre = document.createElement('pre');
    pre.className = 'help-preview';
    pre.textContent = info.preview;
    body.appendChild(pre);

    const actions = document.createElement('div');
    actions.className = 'update-actions';
    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'update-btn update-btn-close';
    cancelBtn.type = 'button';
    cancelBtn.textContent = 'Cancel';
    const loadBtn = document.createElement('button');
    loadBtn.className = 'update-btn update-btn-download';
    loadBtn.type = 'button';
    loadBtn.textContent = 'Load for analysis';
    actions.appendChild(loadBtn);
    actions.appendChild(cancelBtn);
    body.appendChild(actions);

    dialog.appendChild(body);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    const close = () => {
      if (overlay.parentNode) overlay.remove();
      document.removeEventListener('keydown', escHandler);
    };
    const escHandler = e => { if (e.key === 'Escape') { e.preventDefault(); close(); } };
    document.addEventListener('keydown', escHandler);

    closeX.addEventListener('click', close);
    cancelBtn.addEventListener('click', close);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    loadBtn.addEventListener('click', () => {
      close();
      this._loadPastePayload(snapshot);
    });

    // Autofocus the safer action (Cancel) so Enter doesn't accidentally
    // replace the timeline.
    try { cancelBtn.focus(); } catch (_) { /* non-fatal */ }
  }

  // ── Hosted-mode privacy notice ──────────────────────────────────────
  // Detects whether Loupe is served from a web server (http/https) vs.
  // opened locally (file://). When hosted, two visual nudges appear:
  //   1. The drop-zone gets a dismissable warning line.
  //   2. A floating bar below the toolbar suggests downloading.
  // The bar is dismissable and persists the dismissal to localStorage
  // (`loupe_hosted_dismissed`) so it only appears once.
  _checkHostedMode() {
    const isHosted = location.protocol !== 'file:';
    if (!isHosted) return;

    const DL = 'https://github.com/Loupe-tools/Loupe/releases/latest/download/loupe.html';

    // 2. Floating bar below toolbar (unless previously dismissed)
    if (safeStorage.get('loupe_hosted_dismissed')) return;

    const bar = document.createElement('div');
    bar.id = 'hosted-bar';
    bar.innerHTML = '\u26A0 Hosted mode \u2014 your files never leave your browser, but for maximum privacy <a href="' + DL + '" target="_blank" rel="noopener">download Loupe</a> and run it offline';

    const dismiss = document.createElement('button');
    dismiss.className = 'hosted-bar-dismiss';
    dismiss.textContent = '\u2715';
    dismiss.title = 'Dismiss';
    dismiss.addEventListener('click', () => {
      bar.remove();
      safeStorage.set('loupe_hosted_dismissed', '1');
    });
    bar.appendChild(dismiss);

    const toolbar = document.getElementById('toolbar');
    if (toolbar) toolbar.insertAdjacentElement('afterend', bar);
  }

  // ── Non-fatal error surfacing ───────────────────────────────────────────
  // Centralises the "load chain caught a non-fatal error" idiom — replaces
  // the silent `catch (_) {}` blocks and ad-hoc console.warn + sidebar-IOC
  // dances scattered through the load path (auto-YARA failures, encoded-
  // content-detector worker rejections, deferred sidebar-refresh races).
  //
  // Behaviour:
  //   1. Always `console.warn(...)` so dev-tools sees the full stack. The
  //      `where` string identifies the call site (`'auto-yara'`,
  //      `'encoded-content'`, `'sidebar-refresh'`, etc.) and lands in
  //      both the console line and the sidebar IOC value.
  //   2. When `findings` is live and `opts.silent !== true`, push a single
  //      `IOC.INFO` row carrying `Parser warning at <where>: <message>`
  //      onto the findings table. The microtask coalescer
  //      (`_scheduleSidebarRefresh`) collapses multiple non-fatals in the
  //      same task into one repaint.
  //   3. `opts.silent` is the recursion guard for sidebar-refresh failures
  //      (and any future site whose surfacing would re-trigger the very
  //      pipeline that just failed). Console gets the warning either way.
  //   4. Every call also tees a breadcrumb into the dev-mode debug ribbon
  //      (`app-breadcrumbs.js`) so analysts running with
  //      `loupe_dev_breadcrumbs=1` can audit the non-fatal stream without
  //      scraping the console.
  //
  // @param {string} where    short call-site tag (kebab-case)
  // @param {Error}  err      the thrown error
  // @param {Object} [opts]
  //   @param {boolean} [opts.silent]   skip the sidebar IOC + repaint
  //   @param {string}  [opts.severity] override the default 'info' tier
  _reportNonFatal(where, err, opts) {
    opts = opts || {};
    const msg = (err && err.message) ? err.message : String(err);
    console.warn(`[loupe] ${where}: ${msg}`, err);
    // Tee every non-fatal into the dev-mode breadcrumb ribbon.
    // Always pushed (even when `opts.silent` skips the sidebar IOC row)
    // because a silent-true call site like `_scheduleSidebarRefresh`
    // failure is exactly the kind of pipeline glitch the dev-mode
    // observer most wants to see. The push is an O(1) array append into
    // a 50-entry circular buffer; the panel only re-renders when it's
    // mounted (i.e. the persisted flag is on).
    if (typeof this._breadcrumb === 'function') {
      this._breadcrumb('non-fatal:' + where, msg, {
        silent: !!opts.silent,
        severity: opts.severity || 'info',
      });
    }
    if (opts.silent) return;
    if (!this.findings) return;
    try {
      pushIOC(this.findings, {
        type: IOC.INFO,
        value: `Parser warning at ${where}: ${msg}`,
        severity: opts.severity || 'info',
      });
    } catch (_) { /* findings shape mismatch — console.warn above is enough */ }
    if (typeof this._scheduleSidebarRefresh === 'function') {
      this._scheduleSidebarRefresh(new Set(['iocs']));
    }
  }

  // Single-owner ingress for fresh file loads (drag-drop, file picker,
  // paste-files, early-drop drain). Decides whether to route as a single
  // file or as a synthetic folder root.
  //
  //   • One file, no FileSystemEntry hints, no `webkitRelativePath`
  //     → existing single-file path (`_loadFile`).
  //   • Any FileSystemEntry that's a directory  →  walk it via
  //     `FolderFile.fromEntries()`, dispatch the synthesised root
  //     through `_loadFile` so it lands on `FolderRenderer`.
  //   • Multiple loose files (no directory) → group them under a
  //     synthetic "Dropped files" root so the analyst gets a single
  //     drill-down surface instead of silently losing files 1..N. This
  //     fixes the long-standing `files[0]` truncation that swallowed
  //     extra ingress without diagnostic.
  //   • FileList carrying `webkitRelativePath` from a `webkitdirectory`
  //     picker → group by the first path segment; if every leaf shares
  //     the same root, use it as the folder name.
  //
  // `opts.fsEntries`  — Array<FileSystemEntry> from `webkitGetAsEntry()`,
  //                     supplied by the drop handler when items are present.
  // `opts.skipNavReset` — internal hook used by drill-down callers; not
  //                     wired today (drill-down goes through
  //                     `_pushNavState` + `_loadFile` directly).
  _handleFiles(files, opts) {
    const o = opts || {};
    const fileList = files
      ? (Array.isArray(files) ? files : Array.from(files))
      : [];
    const fsEntries = Array.isArray(o.fsEntries) ? o.fsEntries : [];

    // Path 1 — directory present in fsEntries → folder root.
    const hasDir = fsEntries.some(e => e && e.isDirectory);
    if (hasDir) {
      // Pass the original FileList through so that, if the browser's
      // directory walker fails (Chromium macOS EncodingError on
      // `readEntries()` is a known offender), the ingest can fall back
      // to any loose files sitting alongside the failed directory
      // instead of dispatching an empty tree.
      this._ingestFolderFromEntries(fsEntries, fileList);
      return;
    }

    // Path 2 — webkitdirectory picker (FileList carries
    // `webkitRelativePath`). The picker silently flattens the tree so
    // every leaf has a path like "Folder/sub/file.txt".
    const hasRelPaths = fileList.some(f =>
      f && typeof f.webkitRelativePath === 'string' && f.webkitRelativePath);
    if (hasRelPaths) {
      this._ingestFolderFromRelativePaths(fileList);
      return;
    }

    // Path 3 — multi-file loose drop / multi-select picker. Bundle into
    // a synthetic "Dropped files" root so we never silently drop file 2..N.
    if (fileList.length > 1) {
      this._ingestLooseMultiFile(fileList);
      return;
    }

    // Path 4 — single file, regular flow.
    if (!fileList.length) return;
    this._resetNavStack();
    this._loadFile(fileList[0]);
  }

  // ── Folder ingress: webkitGetAsEntry path ──────────────────────────
  // Walks each FileSystemEntry asynchronously up to MAX_FOLDER_ENTRIES
  // and dispatches the synthesised root. Uses the first directory entry
  // as the root name when there's exactly one top-level dir; otherwise
  // labels the synthetic root "Dropped items". The walker never blocks
  // the UI longer than the strictly-async readEntries / file-getter
  // round-trips.
  //
  // `looseFiles` is the original `DataTransfer.files` FileList (or a
  // plain array) threaded through from `_handleFiles`. When the walker
  // fails to enumerate a directory entirely — e.g. Chromium macOS
  // throws `EncodingError: A URI supplied to the API was malformed...`
  // from `readEntries()`, a known browser bug with no JS-side recovery
  // for the descriptor — we fall back to ingesting whatever loose
  // top-level files the drop also carried, so the analyst isn't left
  // staring at an empty tree under a misleading "truncated" toast.
  async _ingestFolderFromEntries(fsEntries, looseFiles) {
    const dirEntries = fsEntries.filter(e => e && e.isDirectory);
    const fileEntries = fsEntries.filter(e => e && e.isFile);
    let rootName;
    if (dirEntries.length === 1 && fileEntries.length === 0) {
      rootName = dirEntries[0].name;
    } else {
      rootName = 'Dropped items';
    }
    if (!(await this._confirmLargeFolderIngest(fsEntries.length))) return;

    this._setLoading(true);
    try {
      // Single-dir drop: that dir IS the synthetic root. Mark it
      // `asRoot` so `FolderFile.fromEntries` walks its children with an
      // empty path prefix instead of nesting them under a redundant
      // `<name>/<name>/…` subtree (the renderer's header already
      // displays `📁 <name>`). Mixed top-levels (multiple dirs and/or
      // loose files) sit one tier under the synthetic "Dropped items"
      // root with their bare names.
      const sources = (dirEntries.length === 1 && fileEntries.length === 0)
        ? [{ entry: dirEntries[0], asRoot: true }]
        : fsEntries.map(entry => ({ entry, path: entry.name }));
      const { folder, truncated, walkErrors } =
        await FolderFile.fromEntries(rootName, sources);

      // Distinguish "walk failed entirely → empty tree" from
      // "walk succeeded, hit entry cap". The former is the Chromium
      // macOS EncodingError path; the latter is the legitimate 4 096-
      // entry truncation. Without this split, the toast lied to the
      // analyst ("truncated at 4 096" when nothing was truncated, just
      // refused) and the tree rendered empty.
      const hasDirWalkFailure = Array.isArray(walkErrors) &&
        walkErrors.some(w => w && w.kind === 'dir');
      const fileCount = (folder._loupeFolderEntries || [])
        .filter(e => e && !e.dir).length;

      if (hasDirWalkFailure && fileCount === 0) {
        // The directory walker produced zero leaves because the browser
        // refused to enumerate. Fall back to the loose `DataTransfer.
        // files` list if the drop also carried files — at least the
        // analyst sees something. If there's nothing to fall back to,
        // surface an actionable toast pointing them at the Open button.
        const loose = Array.isArray(looseFiles) ? looseFiles
          : (looseFiles ? Array.from(looseFiles) : []);
        const firstErr = walkErrors.find(w => w && w.kind === 'dir') || {};
        const errTag = firstErr.name
          ? `${firstErr.name}: ${firstErr.message || ''}`.trim()
          : 'the browser refused to enumerate the directory';
        if (loose.length > 1) {
          this._toast(
            `Couldn't read folder "${rootName}" (${errTag}). ` +
            `Falling back to ${loose.length} loose file${loose.length === 1 ? '' : 's'} from the drop.`,
            'info');
          await this._ingestLooseMultiFile(loose);
          return;
        }
        if (loose.length === 1) {
          this._toast(
            `Couldn't read folder "${rootName}" (${errTag}). ` +
            'Opening the one loose file from the drop instead.',
            'info');
          this._resetNavStack();
          await this._loadFile(loose[0]);
          return;
        }
        this._toast(
          `Couldn't read folder "${rootName}" (${errTag}). ` +
          'This is a known Chromium macOS limitation on some folders — ' +
          'use the Open button (picker) or drag the files themselves.',
          'error');
        return;
      }

      if (truncated && !hasDirWalkFailure) {
        this._toast(
          `Folder ingest truncated at ${
            (PARSER_LIMITS.MAX_FOLDER_ENTRIES || 4096).toLocaleString()
          } entries — open a smaller subtree for full coverage.`,
          'info');
      } else if (truncated && hasDirWalkFailure) {
        // Partial walk: we got some leaves but at least one subtree
        // refused. Keep the analyst informed without conflating with
        // the cap-hit case.
        const failed = walkErrors.filter(w => w && w.kind === 'dir').length;
        this._toast(
          `Folder ingest partially failed: ${failed.toLocaleString()} ` +
          `subdirector${failed === 1 ? 'y' : 'ies'} couldn't be enumerated ` +
          '(Chromium FileSystem API). Drilled-in results reflect what was readable.',
          'info');
      }
      this._resetNavStack();
      // Stash the truncation flag so FolderRenderer.analyzeForSecurity
      // can surface the IOC.INFO row from inside its analyser hook (the
      // load pipeline doesn't pass per-file analysis options through).
      folder._loupeFolderTruncated = truncated;
      folder._loupeFolderWalkErrors = Array.isArray(walkErrors) ? walkErrors : [];
      await this._loadFile(folder);
    } catch (e) {
      console.error(e);
      this._toast(`Failed to ingest folder: ${e.message}`, 'error');
    } finally {
      this._setLoading(false);
    }
  }

  // ── Folder ingress: webkitdirectory FileList path ──────────────────
  // The picker flattens the directory tree but preserves
  // `webkitRelativePath` on every File. We use the first segment of
  // each path as the root name (a webkitdirectory picker always sees
  // exactly one top-level folder). If multiple distinct roots appear
  // (the analyst manually multi-selected at the OS level), label
  // synthetic root "Dropped items" — the per-leaf paths still tell the
  // analyst which folder each came from.
  async _ingestFolderFromRelativePaths(fileList) {
    if (!fileList.length) return;
    const roots = new Set();
    for (const file of fileList) {
      const rel = (file.webkitRelativePath || '').replace(/^\/+/, '');
      const seg = rel.split('/')[0] || file.name;
      roots.add(seg);
    }
    const singleRoot = roots.size === 1;
    const rootName = singleRoot ? [...roots][0] : 'Dropped items';
    // When every leaf shares the same root segment, that segment IS the
    // synthetic root and must be stripped from each leaf's path —
    // otherwise the tree shows `<root>/<root>/…` nested under the
    // renderer's `📁 <root>` header.
    const stripPrefix = singleRoot ? rootName + '/' : null;
    const sources = [];
    for (const file of fileList) {
      let rel = (file.webkitRelativePath || '').replace(/^\/+/, '');
      if (stripPrefix && rel.startsWith(stripPrefix)) {
        rel = rel.slice(stripPrefix.length);
      }
      sources.push({ file, path: rel || file.name });
    }
    if (!(await this._confirmLargeFolderIngest(fileList.length))) return;
    this._setLoading(true);
    try {
      const { folder, truncated } =
        await FolderFile.fromEntries(rootName, sources);
      if (truncated) {
        this._toast(
          `Folder ingest truncated at ${
            (PARSER_LIMITS.MAX_FOLDER_ENTRIES || 4096).toLocaleString()
          } entries — pick a smaller subtree for full coverage.`,
          'info');
      }
      this._resetNavStack();
      folder._loupeFolderTruncated = truncated;
      await this._loadFile(folder);
    } catch (e) {
      console.error(e);
      this._toast(`Failed to ingest folder: ${e.message}`, 'error');
    } finally {
      this._setLoading(false);
    }
  }

  // ── Folder ingress: loose multi-file drop / multi-select picker ────
  // Multiple loose files with no directory information. Bundle them
  // under a single synthetic root so the analyst gets a tree-view of
  // every file dropped instead of silently losing files 2..N (the
  // historical behaviour, which mis-served any "drag five samples in
  // at once" workflow). The label is deliberately neutral — the
  // analyst knows what they dropped.
  async _ingestLooseMultiFile(fileList) {
    if (!(await this._confirmLargeFolderIngest(fileList.length))) return;
    this._setLoading(true);
    try {
      // Each loose file sits at the top level of the synthetic root —
      // bare basenames, no `Dropped files/` prefix (the renderer header
      // carries that label).
      const sources = fileList.map(file => ({
        file,
        path: file.name,
      }));
      const { folder, truncated } =
        await FolderFile.fromEntries('Dropped files', sources);
      if (truncated) {
        this._toast(
          `Loose-file drop truncated at ${
            (PARSER_LIMITS.MAX_FOLDER_ENTRIES || 4096).toLocaleString()
          } files.`, 'info');
      }
      this._resetNavStack();
      folder._loupeFolderTruncated = truncated;
      await this._loadFile(folder);
    } catch (e) {
      console.error(e);
      this._toast(`Failed to ingest dropped files: ${e.message}`, 'error');
    } finally {
      this._setLoading(false);
    }
  }

  // ── Confirm prompt for very large folder ingest ─────────────────────
  // Block the user with a native confirm() above ENTRIES_CONFIRM_AT
  // entries (256). Below the cap, just go. Above MAX_FOLDER_ENTRIES,
  // the walker will truncate; the toast at ingest end mentions it.
  // Promise-shaped so the call sites can `await` regardless of whether
  // a prompt was actually shown.
  _confirmLargeFolderIngest(itemHint) {
    const ENTRIES_CONFIRM_AT = 256;
    const guess = Number.isFinite(itemHint) ? itemHint : 0;
    if (guess <= ENTRIES_CONFIRM_AT) return Promise.resolve(true);
    const msg =
      `You're about to ingest a folder containing roughly ${guess.toLocaleString()} ` +
      `top-level items (deeper subtrees are walked recursively up to ${
        (PARSER_LIMITS.MAX_FOLDER_ENTRIES || 4096).toLocaleString()
      } total entries).\n\n` +
      `This stays entirely offline — Loupe never uploads anything — but ` +
      `large drops can use significant memory.\n\nProceed?`;
    try {
      return Promise.resolve(window.confirm(msg));
    } catch (_) {
      // Headless / sandboxed environments without confirm() — fall
      // through to ingest. Tests bypass this prompt entirely by
      // injecting a pre-built `FolderFile` through the test API.
      return Promise.resolve(true);
    }
  }

  // ── Single-owner nav-stack reset (H6) ───────────────────────────────
  //
  // Canonical entry point for clearing the drill-down navigation stack.
  // Every "fresh load" surface (file picker, drag/drop, paste,
  // `_handleFiles`, `_clearFile`) routes through here instead of writing
  // `this._navStack = []` directly. Centralising the reset means:
  //
  //   * `_navStack` always exists as an Array — no later guard like
  //     `if (!this._navStack) this._navStack = []` is necessary;
  //   * the breadcrumb trail is repainted in lockstep with the clear,
  //     so we cannot end up with a stale crumb pointing at a frame that
  //     no longer has a backing entry on the stack;
  //   * any future per-frame teardown (release detached DOM, drop
  //     scrollSnapshot Maps, abort frame-scoped Workers) lands in one
  //     place rather than four.
  //
  // Drill-down loads must NOT call this helper — they push the current
  // frame via `_pushNavState` in `app-load.js` and rely on the stack
  // surviving the subsequent `_loadFile` call.
  _resetNavStack() {
    // Defensive — always restore the invariant even if some code path
    // nulled the stack out from under us.
    if (!Array.isArray(this._navStack)) this._navStack = [];
    if (this._navStack.length) this._navStack.length = 0;
    // Reset the aggregate archive-expansion budget alongside the nav
    // stack — the two have identical lifetimes (top-level loads only;
    // drill-downs share both). Co-locating the resets here means every
    // existing call site (file picker, drag/drop, paste, _handleFiles,
    // _clearFile, …) inherits the budget reset for free, and a future
    // refactor cannot accidentally clear one without the other. See
    // `src/archive-budget.js` (H5).
    if (this._archiveBudget && typeof this._archiveBudget.reset === 'function') {
      this._archiveBudget.reset();
    }
    // Repaint breadcrumbs so the trail can't visually outlive the
    // frames it was describing. `_renderBreadcrumbs` is mixed in by
    // `app-load.js` — guard for the (unlikely) case it loaded out of
    // order.
    if (typeof this._renderBreadcrumbs === 'function') {
      try { this._renderBreadcrumbs(); } catch (_) { /* cosmetic */ }
    }
  }

}
