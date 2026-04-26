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
    this._setupDrop();


    this._setupToolbar();
    this._setupSidebarResize();
    this._setupViewerPan();
    this._setupSearch();
    this._initTimelineState();
    this._checkVersionParam();
    this._checkHostedMode();
    // Keyboard shortcuts: S=toggle sidebar, Y=YARA dialog, F=focus document search.
    // F (not Ctrl+F) is used because every major browser reserves Ctrl+F for its
    // own find-in-page bar and the hijack is brittle / user-hostile.
    // Drill-down navigation (archives, PDF attachments, etc.) is driven
    // exclusively by the toolbar breadcrumb trail — no back/forward
    // shortcuts or mouse side-button handlers are wired up.
    document.addEventListener('keydown', e => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.altKey || e.ctrlKey || e.metaKey) return;
      if (e.key === 's' || e.key === 'S') this._toggleSidebar();
      else if (e.key === 'y' || e.key === 'Y') this._openYaraDialog();
      else if (e.key === 'n' || e.key === 'N') this._openSettingsDialog('nicelists');
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
      if (e.dataTransfer?.files?.length) {
        this._handleFiles(e.dataTransfer.files);
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
      const f = e.target.files[0];
      if (f) {
        // Clear nav stack for fresh file loads (not drill-down into archives).
        // Routes through the single-owner reset so the breadcrumb trail
        // is repainted in lockstep — see `_resetNavStack` (H6).
        this._resetNavStack();
        this._loadFile(f);
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
      const earlyPaste = window.__loupePendingPaste;
      if (typeof window.__loupeEarlyDropTeardown === 'function') {
        window.__loupeEarlyDropTeardown();
      }
      window.__loupePendingDrop = null;
      window.__loupePendingPaste = null;
      if (Array.isArray(earlyDrop) && earlyDrop.length) {
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
    // eslint-disable-next-line no-console
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

  _handleFiles(files) {
    if (!files || !files.length) return;
    // Clear nav stack for fresh file loads (not drill-down into archives)
    this._resetNavStack();
    this._loadFile(files[0]);
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
    // Repaint breadcrumbs so the trail can't visually outlive the
    // frames it was describing. `_renderBreadcrumbs` is mixed in by
    // `app-load.js` — guard for the (unlikely) case it loaded out of
    // order.
    if (typeof this._renderBreadcrumbs === 'function') {
      try { this._renderBreadcrumbs(); } catch (_) { /* cosmetic */ }
    }
  }

}
