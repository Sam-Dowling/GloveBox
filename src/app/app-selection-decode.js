// ════════════════════════════════════════════════════════════════════════════
// app-selection-decode.js — "Decode selection" floating chip.
//
// Lets the analyst click-drag-select any region of text in the content viewer
// and pipe the highlighted bytes through the encoded-content pipeline as if
// it were a freshly-loaded file. The deobfuscation sidebar does the rest —
// the analyst sees every nested decode layer, every IOC, and every
// recursively-detected encoding without having to copy/paste into a separate
// tool.
//
// Why a synthetic File rather than a bespoke popover? `App.openInnerFile()`
// is the unified drill-down entry — it pushes a nav frame, re-enters
// `_loadFile`, and flows the full RenderRoute pipeline. Reusing it means the
// selection decode benefits from the entire deobfuscation card stack, the
// "Load for analysis" / "All the way" buttons, IOC nicelisting, YARA, and
// the navigation Back replay — for free. See CONTRIBUTING.md → "Drill-down
// (unified via App.openInnerFile)" for the contract.
//
// Trigger surface: any selection anchored inside `#page-container` whose
// nearest scroller is one of the documented text-viewer roots
// (plaintext-scroll / hta-source-pane / iqy-source / etc.). Sandboxed
// iframes (HTML / SVG previews) live in a different document and never
// receive the chip — getSelection() in the host frame returns the empty
// range for child-frame selections by design.
//
// Aggressive mode: the synthetic file is loaded with the
// `_aggressiveDecode` context flag, which `app-load.js` threads into the
// `EncodedContentDetector` constructor (`{ aggressive: true }`) so finder
// thresholds drop. The analyst has explicitly opted in to noise — they
// highlighted the region.
//
// Persistence: `loupe_deobf_selection_enabled` ("0" | "1", default "1").
// See the persistence-keys table in CONTRIBUTING.md.
// ════════════════════════════════════════════════════════════════════════════

extendApp({
  // CSS selector list of viewer surfaces where selection-decode is wired.
  // Anything outside these classes is ignored — the sidebar's own selection
  // (for the copy-as-markdown handler) and toolbar inputs must never spawn
  // the chip. Kept conservative: text-only viewers where a contiguous
  // selection is meaningful as input to the encoding pipeline.
  _SELECTION_DECODE_SELECTORS: [
    '.plaintext-scroll',
    '.html-source-pane',
    '.hta-source-pane',
    '.url-source',
    '.iqy-source',
    '.eml-body',
    '.json-tree',
    '.csv-view',
    '.ps1-source',
  ].join(','),

  _isSelectionDecodeEnabled() {
    // Default ON — the chip only appears on a deliberate text selection
    // inside a supported viewer, so the false-positive rate is near zero.
    const v = safeStorage.get('loupe_deobf_selection_enabled');
    return v === null || v === undefined || v === '1';
  },

  _setSelectionDecodeEnabled(on) {
    safeStorage.set('loupe_deobf_selection_enabled', on ? '1' : '0');
    if (!on) this._hideDecodeChip();
  },

  _setupSelectionDecode() {
    // Idempotent — Settings → "Re-init" or test harness can call repeatedly.
    if (this._selectionDecodeWired) return;
    this._selectionDecodeWired = true;

    const onSelectionChange = () => {
      try {
        if (!this._isSelectionDecodeEnabled()) { this._hideDecodeChip(); return; }
        const sel = window.getSelection && window.getSelection();
        if (!sel || sel.isCollapsed || sel.rangeCount === 0) { this._hideDecodeChip(); return; }

        const range = sel.getRangeAt(0);
        const txt = sel.toString();
        // Lower bound — short selections are almost never encoded payloads
        // and would just produce empty deobfuscation cards. The pipeline
        // itself bails on anything below ~6–32 chars depending on technique.
        if (!txt || txt.length < 8) { this._hideDecodeChip(); return; }

        // Anchor must live inside one of the supported viewer surfaces.
        // We check both endpoints because a selection that starts inside a
        // sandbox preview and extends outside is meaningless for decoding.
        const anchorNode = range.startContainer.nodeType === 1
          ? range.startContainer
          : range.startContainer.parentElement;
        if (!anchorNode || !anchorNode.closest) { this._hideDecodeChip(); return; }
        const viewerEl = anchorNode.closest(this._SELECTION_DECODE_SELECTORS);
        if (!viewerEl) { this._hideDecodeChip(); return; }
        // Must also be inside the page-container (not the sidebar text).
        if (!anchorNode.closest('#page-container')) { this._hideDecodeChip(); return; }

        const rect = range.getBoundingClientRect();
        if (!rect || (rect.width === 0 && rect.height === 0)) { this._hideDecodeChip(); return; }

        this._showDecodeChip(rect, txt);
      } catch (_) { /* selection state can race during DOM mutations — best-effort */ }
    };

    // `selectionchange` fires on every cursor motion, so we debounce a tiny
    // amount to avoid thrashing layout for users dragging slowly. Mouseup
    // and keyup are the moments where a "completed" selection is most
    // meaningful (the user has stopped dragging or stopped shift-arrowing).
    let pending = null;
    const schedule = () => {
      if (pending) cancelAnimationFrame(pending);
      pending = requestAnimationFrame(() => { pending = null; onSelectionChange(); });
    };
    document.addEventListener('selectionchange', schedule);
    document.addEventListener('mouseup', schedule);
    document.addEventListener('keyup', schedule);

    // Hide the chip on scroll inside the viewer (its anchor would drift
    // off-screen and the chip would float in the void). We rebind on
    // selectionchange anyway, but explicit scroll dismissal feels right.
    document.addEventListener('scroll', () => this._hideDecodeChip(), true);

    // Click outside the chip + outside the selection dismisses it without
    // triggering decode. The chip's own click handler stops propagation.
    document.addEventListener('mousedown', (e) => {
      const chip = this._decodeChipEl;
      if (!chip) return;
      if (chip.contains(e.target)) return;
      // Let the chip linger one frame — the selection will be cleared by
      // the click and `selectionchange` will hide us anyway. This branch
      // catches the "click on a different viewer area" case where the
      // browser doesn't always fire selectionchange before the click.
      this._hideDecodeChip();
    }, true);
  },

  _ensureDecodeChip() {
    if (this._decodeChipEl) return this._decodeChipEl;
    const chip = document.createElement('button');
    chip.type = 'button';
    chip.className = 'loupe-decode-chip hidden';
    chip.setAttribute('aria-label', 'Decode selection');
    chip.title = 'Decode selection — pipe highlighted bytes through the encoded-content analyser';
    chip.textContent = '🔍 Decode selection';
    // Stop the mousedown from clearing the selection before we read it.
    chip.addEventListener('mousedown', e => e.preventDefault());
    chip.addEventListener('click', e => {
      e.preventDefault();
      e.stopPropagation();
      try { this._decodeCurrentSelection(); } finally { this._hideDecodeChip(); }
    });
    document.body.appendChild(chip);
    this._decodeChipEl = chip;
    return chip;
  },

  _showDecodeChip(rect, _selectionText) {
    const chip = this._ensureDecodeChip();
    // Position above the selection, falling back to below if there's no
    // room. Coordinates are viewport-relative (position:fixed in the CSS).
    const chipH = 28;     // matches CSS height — keep in sync with core.css
    const margin = 6;
    let top = rect.top - chipH - margin;
    if (top < 8) top = rect.bottom + margin;
    let left = rect.left + (rect.width / 2) - 80; // ~half the chip width
    left = Math.max(8, Math.min(left, window.innerWidth - 180));
    chip.style.top = `${Math.round(top)}px`;
    chip.style.left = `${Math.round(left)}px`;
    chip.classList.remove('hidden');
  },

  _hideDecodeChip() {
    if (this._decodeChipEl) this._decodeChipEl.classList.add('hidden');
  },

  /**
   * Read the current selection, build a synthetic .txt File from its UTF-8
   * bytes, and dispatch through `openInnerFile` so the analyser pipeline
   * runs end-to-end against just the highlighted region. The
   * `_aggressiveDecode` context flag is read by `app-load.js` and threaded
   * into the `EncodedContentDetector` constructor so secondary finders use
   * lower thresholds. Falls back silently if the selection has been
   * cleared between chip-show and chip-click.
   */
  _decodeCurrentSelection() {
    const sel = window.getSelection && window.getSelection();
    if (!sel || sel.isCollapsed) return;
    const txt = sel.toString();
    if (!txt || txt.length < 8) return;

    // UTF-8 encode — we want byte semantics in the analyser, not UTF-16.
    let bytes;
    try { bytes = new TextEncoder().encode(txt); }
    catch (_) { return; }

    const parentName = (this.fileMeta && this.fileMeta.name) || 'selection';
    const synName = `selection-decode-${bytes.length}b.txt`;
    const blob = new Blob([bytes], { type: 'text/plain' });
    const synFile = new File([blob], synName, { type: 'text/plain' });

    try {
      this.openInnerFile(synFile, null, {
        parentName,
        _aggressiveDecode: true,
        returnFocus: { section: 'deobfuscation' },
      });
    } catch (err) {
      // Soft-fail — the analyser pipeline has its own error reporting via
      // the breadcrumbs ribbon. We never want a chip click to throw an
      // uncaught exception that surfaces as a browser-level error popup.
      try { this._reportNonFatal && this._reportNonFatal('selection-decode', err); } catch (_) {}
    }
  },
});
