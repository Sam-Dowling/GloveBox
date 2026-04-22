// ════════════════════════════════════════════════════════════════════════════
// App — core class definition, constructor, init, drop-zone, toolbar wiring
// ════════════════════════════════════════════════════════════════════════════
class App {
  constructor() {
    this.zoom = 100; this.dark = true; this.findings = null;
    this.fileHashes = null; this.sidebarOpen = false; this.activeTab = 'summary';
    this._fileBuffer = null; this._yaraBuffer = null; this._yaraResults = null; this._yaraEscHandler = null;
  }

  init() {
    this._initTheme();    // applies persisted theme (localStorage) or default
    this._initSettings(); // restores summary-budget step + paints ⚡ chip
    this._setupDrop();

    this._setupToolbar();
    this._setupSidebarResize();
    this._setupViewerPan();
    this._setupSearch();
    this._initTimelineMode();
    this._checkVersionParam();
    // Keyboard shortcuts: S=toggle sidebar, Y=YARA dialog, F=focus document search.
    // F (not Ctrl+F) is used because every major browser reserves Ctrl+F for its
    // own find-in-page bar and the hijack is brittle / user-hostile.
    // Drill-down navigation (archives, PDF attachments, etc.) is driven
    // exclusively by the toolbar breadcrumb trail — no back/forward
    // shortcuts or mouse side-button handlers are wired up.
    document.addEventListener('keydown', e => {
      if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.altKey || e.ctrlKey || e.metaKey) return;
      if (e.key === 's' || e.key === 'S') this._toggleSidebar();
      else if (e.key === 't' || e.key === 'T') this._toggleTimelineMode();
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
    window.addEventListener('dragenter', e => {
      e.preventDefault();
      _dragCounter++;
      // Skip overlay when YARA dialog is open — let its own drag handlers fire
      if (_dragCounter === 1 && !document.getElementById('yara-dialog')) showOverlay();
    });

    window.addEventListener('dragover', e => {
      e.preventDefault();
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
      if (!dz.classList.contains('has-document')) dz.classList.add('drag-over');
    });

    window.addEventListener('dragleave', () => {
      _dragCounter--;
      if (_dragCounter <= 0) {
        hideOverlay();
        dz.classList.remove('drag-over');
      }
    });

    window.addEventListener('drop', e => {
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
        // Clear nav stack for fresh file loads (not drill-down into archives)
        this._navStack = [];
        this._loadFile(f);
      }
      fi.value = '';
    });
  }

  _setupToolbar() {
    document.getElementById('btn-open').addEventListener('click', () => document.getElementById('file-input').click());
    document.getElementById('btn-close').addEventListener('click', () => {
      if (this._getMode && this._getMode() === 'timeline') this._clearTimelineFile();
      else this._clearFile();
    });

    const btnTimeline = document.getElementById('btn-timeline');
    if (btnTimeline) btnTimeline.addEventListener('click', () => this._toggleTimelineMode());
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
        if (!this._fileBuffer || !this._isRawCopyable()) return;
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

  // ── Paste from clipboard ────────────────────────────────────────────────
  async _pasteFromClipboard() {
    try {
      // Try the Clipboard API (requires HTTPS or localhost, user permission)
      if (navigator.clipboard && navigator.clipboard.read) {
        const items = await navigator.clipboard.read();
        for (const item of items) {
          // Check for files/images first
          for (const type of item.types) {
            if (type.startsWith('image/')) {
              const blob = await item.getType(type);
              const ext = type.split('/')[1] === 'jpeg' ? 'jpg' : type.split('/')[1];
              const file = new File([blob], `clipboard.${ext}`, { type });
              this._loadFile(file);
              return;
            }
          }
          // Check for text — prefer plain text over HTML so that pasting
          // from apps like Slack gives the actual text, not rich formatting.
          if (item.types.includes('text/plain')) {
            const blob = await item.getType('text/plain');
            const text = await blob.text();
            const file = new File([text], 'clipboard.txt', { type: 'text/plain' });
            this._loadFile(file);
            return;
          }
          if (item.types.includes('text/html')) {
            const blob = await item.getType('text/html');
            const text = await blob.text();
            const file = new File([text], 'clipboard.html', { type: 'text/html' });
            this._loadFile(file);
            return;
          }
        }
        this._toast('Clipboard is empty or contains unsupported content', 'error');
      } else {
        // Fallback: readText only
        const text = await navigator.clipboard.readText();
        if (text && text.trim()) {
          const file = new File([text], 'clipboard.txt', { type: 'text/plain' });
          this._loadFile(file);
        } else {
          this._toast('Clipboard is empty', 'error');
        }
      }
    } catch (e) {
      this._toast('Clipboard access denied — try Ctrl+V instead', 'error');
    }
  }

  _handlePasteEvent(e) {
    const dt = e.clipboardData;
    if (!dt) return;

    // Check for files (e.g., copied file from explorer, screenshot)
    if (dt.files && dt.files.length) {
      this._loadFile(dt.files[0]);
      return;
    }

    // Check for images in clipboard items
    for (const item of (dt.items || [])) {
      if (item.type.startsWith('image/')) {
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

  _handleFiles(files) {
    if (!files || !files.length) return;
    // Clear nav stack for fresh file loads (not drill-down into archives)
    this._navStack = [];
    this._loadFile(files[0]);
  }

}
