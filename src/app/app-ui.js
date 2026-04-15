// ════════════════════════════════════════════════════════════════════════════
// App — UI utilities: tabs, sidebar toggle, downloads, clipboard, zoom, theme
// ════════════════════════════════════════════════════════════════════════════
Object.assign(App.prototype, {

  // ── Helper: section heading ──────────────────────────────────────────────
  _sec(label) {
    const d = document.createElement('div'); d.className = 'sb-section'; d.textContent = label; return d;
  },

  _toggleSidebar() {
    this.sidebarOpen = !this.sidebarOpen;
    document.getElementById('sidebar').classList.toggle('hidden', !this.sidebarOpen);
    document.getElementById('sidebar-resize').classList.toggle('hidden', !this.sidebarOpen);
  },

  // ── Sidebar resize ─────────────────────────────────────────────────────
  _setupSidebarResize() {
    const handle = document.getElementById('sidebar-resize');
    const sidebar = document.getElementById('sidebar');
    let startX, startW;
    const onMove = e => {
      const dx = startX - e.clientX;
      const newW = Math.min(Math.max(startW + dx, window.innerWidth * 0.33), window.innerWidth * 0.6);
      sidebar.style.width = newW + 'px';
    };
    const onUp = () => {
      document.body.classList.remove('sb-resizing');
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
    handle.addEventListener('mousedown', e => {
      e.preventDefault();
      startX = e.clientX;
      startW = sidebar.getBoundingClientRect().width;
      document.body.classList.add('sb-resizing');
      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onUp);
    });
  },

  // ── Save / Copy current content ─────────────────────────────────────────
  _saveContent() {
    if (!this._fileBuffer) { this._toast('No file loaded', 'error'); return; }
    const info = document.getElementById('file-info').textContent;
    const name = (info.split('·')[0] || 'file').trim() || 'file';
    const blob = new Blob([this._fileBuffer], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
    this._toast('File saved');
  },

  _copyContent() {
    if (!this._fileBuffer) { this._toast('No file loaded', 'error'); return; }
    try {
      const bytes = new Uint8Array(this._fileBuffer);
      // Try to decode as text; if it looks binary, fall back to hex
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      this._copyToClipboard(text);
    } catch (_) {
      // Binary file — copy hex representation
      const bytes = new Uint8Array(this._fileBuffer);
      const hex = Array.from(bytes.slice(0, 65536)).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const suffix = bytes.length > 65536 ? '\n… (truncated)' : '';
      this._copyToClipboard(hex + suffix);
    }
  },

  // ── Downloads ────────────────────────────────────────────────────────────
  _downloadMacros() {
    const f = this.findings;
    const info = document.getElementById('file-info').textContent;
    const base = info.split('·')[0].trim().replace(/\.[^.]+$/, '') || 'macros';
    const mods = (f.modules || []).filter(m => m.source);
    if (mods.length) {
      const sep = '='.repeat(60), lines = [];
      for (const mod of mods) { lines.push(`' ${sep}`); lines.push(`' VBA Module: ${mod.name}`); lines.push(`' ${sep}`); lines.push(mod.source); lines.push(''); }
      const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = base + '_macros.txt'; a.click();
      URL.revokeObjectURL(url); this._toast('Macro source downloaded');
    } else if (f.rawBin && f.rawBin.length) {
      const blob = new Blob([f.rawBin], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = base + '_vbaProject.bin'; a.click();
      URL.revokeObjectURL(url); this._toast('Raw VBA binary downloaded — use olevba/oledump to inspect');
    } else { this._toast('No macro data available', 'error'); }
  },

  _downloadExtracted(refs, fileName) {
    const base = (fileName || 'extracted').replace(/\.[^.]+$/, '');
    const lines = ['Type\tValue\tSeverity', ...refs.map(r => `${r.type}\t${r.url}\t${r.severity}`)];
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = base + '_extracted.txt'; a.click();
    URL.revokeObjectURL(url); this._toast('Extracted data downloaded');
  },

  // ── Clipboard ────────────────────────────────────────────────────────────
  _copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => this._toast('Copied!')).catch(() => this._copyFallback(text));
    } else this._copyFallback(text);
  },

  _copyFallback(text) {
    const ta = document.createElement('textarea'); ta.value = text; ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0;';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try { document.execCommand('copy'); this._toast('Copied!'); } catch (e) { this._toast('Copy failed', 'error'); }
    document.body.removeChild(ta);
  },

  // ── Clear file ────────────────────────────────────────────────────────────
  _clearFile() {
    // Reset viewer
    document.getElementById('page-container').innerHTML = '';
    // Restore drop zone
    const dz = document.getElementById('drop-zone');
    dz.className = ''; dz.innerHTML = '';
    const icon = document.createElement('span'); icon.className = 'dz-icon'; icon.textContent = '📄'; dz.appendChild(icon);
    const txt = document.createElement('div'); txt.className = 'dz-text'; txt.textContent = 'Drop a file here to analyse'; dz.appendChild(txt);
    const sub = document.createElement('div'); sub.className = 'dz-sub'; sub.textContent = 'docx · xlsx · pptx · pdf · doc · msg · eml · lnk · hta · csv · and any file · 100% offline'; dz.appendChild(sub);
    // Hide file info + close button + viewer toolbar
    document.getElementById('file-info').textContent = '';
    document.getElementById('btn-close').classList.add('hidden');
    document.getElementById('viewer-toolbar').classList.add('hidden');
    document.getElementById('doc-search').value = '';
    if (this._clearSearch) this._clearSearch();
    // Close sidebar and clear its content; reset locked width for fresh auto-sizing
    if (this.sidebarOpen) this._toggleSidebar();
    document.getElementById('sidebar').style.width = '';
    document.getElementById('sb-body').innerHTML = '';
    document.getElementById('sb-risk').className = 'sb-risk risk-low';
    document.getElementById('sb-risk-title').textContent = 'No threats detected';
    // Reset state
    this.findings = null; this.fileHashes = null;
    this._fileBuffer = null; this._yaraResults = null;
    this._fileMeta = null;
    // Clear navigation stack and hide back button
    this._navStack = [];
    const backBtn = document.getElementById('btn-nav-back');
    if (backBtn) backBtn.classList.add('hidden');
    // Remove pan cursor
    document.getElementById('viewer').classList.remove('pannable');
    // Reset zoom
    this._setZoom(100);
  },

  // ── Viewer pan (click-and-drag) ───────────────────────────────────────────
  _setupViewerPan() {
    const viewer = document.getElementById('viewer');
    let isPanning = false, startX, startY, scrollL, scrollT;
    viewer.addEventListener('mousedown', e => {
      // Only pan if a document is loaded (drop zone hidden) and not on interactive elements
      const dz = document.getElementById('drop-zone');
      if (!dz.classList.contains('has-document')) return;
      const tag = e.target.tagName;
      if (tag === 'BUTTON' || tag === 'INPUT' || tag === 'A' || tag === 'TEXTAREA' || tag === 'SELECT') return;
      if (e.target.closest('.zoom-fab') || e.target.closest('.tb-btn') || e.target.closest('.copy-url-btn')) return;
      // Don't pan on plaintext views (they have their own scrolling)
      if (e.target.closest('.plaintext-scroll') || e.target.closest('.sheet-content-area') || e.target.closest('.csv-scroll')) return;
      isPanning = true;
      startX = e.clientX; startY = e.clientY;
      scrollL = viewer.scrollLeft; scrollT = viewer.scrollTop;
      viewer.classList.add('panning');
      e.preventDefault();
    });
    window.addEventListener('mousemove', e => {
      if (!isPanning) return;
      viewer.scrollLeft = scrollL - (e.clientX - startX);
      viewer.scrollTop = scrollT - (e.clientY - startY);
    });
    window.addEventListener('mouseup', () => {
      if (!isPanning) return;
      isPanning = false;
      viewer.classList.remove('panning');
    });
  },

  // ── Zoom / theme / loading / toast ────────────────────────────────────────
  _setZoom(z) {
    this.zoom = Math.min(200, Math.max(50, z));
    document.getElementById('zoom-level').textContent = `${this.zoom}%`;
    document.getElementById('page-container').style.transform = `scale(${this.zoom / 100})`;
  },

  _toggleTheme() {
    this.dark = !this.dark;
    document.body.classList.toggle('dark', this.dark);
    document.getElementById('btn-theme').textContent = this.dark ? '☀' : '🌙';
  },

  _setLoading(on) {
    document.getElementById('loading').classList.toggle('hidden', !on);
  },

  _toast(msg, type = 'info') {
    const t = document.getElementById('toast'); t.textContent = msg;
    t.className = type === 'error' ? 'toast-error' : ''; t.classList.remove('hidden');
    setTimeout(() => t.classList.add('hidden'), 3000);
  },

  _fmtBytes(b) {
    if (!b || b < 1024) return (b || 0) + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    return (b / 1048576).toFixed(1) + ' MB';
  },

  // ── Document content search ───────────────────────────────────────────────
  _setupSearch() {
    const input = document.getElementById('doc-search');
    const countEl = document.getElementById('doc-search-count');
    const prevBtn = document.getElementById('doc-search-prev');
    const nextBtn = document.getElementById('doc-search-next');
    let marks = [], currentIdx = -1;

    const clearHighlights = () => {
      for (const m of document.querySelectorAll('#page-container mark.search-hl')) {
        const p = m.parentNode;
        p.replaceChild(document.createTextNode(m.textContent), m);
        p.normalize();
      }
      marks = []; currentIdx = -1;
      countEl.textContent = '';
    };

    const doSearch = () => {
      clearHighlights();
      const q = input.value.trim();
      if (!q) return;

      const container = document.getElementById('page-container');
      const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
      const textNodes = [];
      while (walker.nextNode()) textNodes.push(walker.currentNode);

      const qLower = q.toLowerCase();
      for (const node of textNodes) {
        const text = node.textContent;
        const lower = text.toLowerCase();
        let idx = lower.indexOf(qLower);
        if (idx === -1) continue;
        const frag = document.createDocumentFragment();
        let lastIdx = 0;
        while (idx !== -1) {
          if (idx > lastIdx) frag.appendChild(document.createTextNode(text.slice(lastIdx, idx)));
          const mark = document.createElement('mark');
          mark.className = 'search-hl';
          mark.textContent = text.slice(idx, idx + q.length);
          frag.appendChild(mark);
          lastIdx = idx + q.length;
          idx = lower.indexOf(qLower, lastIdx);
        }
        if (lastIdx < text.length) frag.appendChild(document.createTextNode(text.slice(lastIdx)));
        node.parentNode.replaceChild(frag, node);
      }

      marks = Array.from(document.querySelectorAll('#page-container mark.search-hl'));
      if (marks.length) {
        currentIdx = 0;
        marks[0].classList.add('search-hl-current');
        marks[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
        countEl.textContent = `1 / ${marks.length}`;
      } else {
        countEl.textContent = '0 results';
      }
    };

    const goTo = (dir) => {
      if (!marks.length) return;
      marks[currentIdx].classList.remove('search-hl-current');
      currentIdx = (currentIdx + dir + marks.length) % marks.length;
      marks[currentIdx].classList.add('search-hl-current');
      marks[currentIdx].scrollIntoView({ behavior: 'smooth', block: 'center' });
      countEl.textContent = `${currentIdx + 1} / ${marks.length}`;
    };

    let timer;
    input.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(doSearch, 300);
    });

    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        if (e.shiftKey) goTo(-1); else goTo(1);
      }
      if (e.key === 'Escape') {
        input.value = '';
        clearHighlights();
        input.blur();
      }
    });

    // Navigation button handlers
    prevBtn.addEventListener('click', () => goTo(-1));
    nextBtn.addEventListener('click', () => goTo(1));

    // Expose clear for _clearFile
    this._clearSearch = clearHighlights;
  },

  // ── Help / About dialog ───────────────────────────────────────────────────
  _openHelpDialog() {
    // Don't open twice
    if (document.querySelector('.help-overlay')) return;

    const version = typeof GLOVEBOX_VERSION !== 'undefined' ? GLOVEBOX_VERSION : 'dev';

    const overlay = document.createElement('div');
    overlay.className = 'help-overlay';
    overlay.innerHTML = `
      <div class="help-dialog">
        <div class="help-header">
          <span>🧤📦 GloveBox <small>v${version}</small></span>
          <button class="help-close" title="Close (Esc)">✕</button>
        </div>
        <div class="help-body">
          <p class="help-tagline">A 100% offline, single-file security analyser for suspicious files.<br>No server, no uploads, no tracking — just drop a file and inspect it.</p>

          <h3>Keyboard Shortcuts</h3>
          <table class="help-kbd-table">
            <tr><td><kbd class="help-kbd">S</kbd></td><td>Toggle security sidebar</td></tr>
            <tr><td><kbd class="help-kbd">Y</kbd></td><td>Open YARA rule editor</td></tr>
            <tr><td><kbd class="help-kbd">?</kbd> / <kbd class="help-kbd">H</kbd></td><td>Open this help dialog</td></tr>
            <tr><td><kbd class="help-kbd">Ctrl+F</kbd></td><td>Focus document search</td></tr>
            <tr><td><kbd class="help-kbd">Ctrl+V</kbd></td><td>Paste file from clipboard</td></tr>
            <tr><td><kbd class="help-kbd">Esc</kbd></td><td>Close dialog / clear search</td></tr>
          </table>

          <h3>Links</h3>
          <p>
            <a href="https://github.com/Sam-Dowling/GloveBox/releases/latest/download/glovebox.html" target="_blank" rel="noopener">Download GloveBox</a>
            ·
            <a href="https://github.com/Sam-Dowling/GloveBox" target="_blank" rel="noopener">GitHub Repository</a>
            ·
            <a href="https://sam-dowling.github.io/GloveBox/" target="_blank" rel="noopener">Live Demo</a>
          </p>

          <div style="text-align:center;margin-top:12px;">
            <a class="help-update-btn" href="https://sam-dowling.github.io/GloveBox/?v=v${version}" target="_blank" rel="noopener">🔄 Check for Updates</a>
          </div>

          <p style="margin-top:1.2em;opacity:0.5;font-size:0.85em;">Licensed under the GNU General Public License v3.0</p>
        </div>
      </div>`;

    document.body.appendChild(overlay);

    // Close handlers
    const close = () => this._closeHelpDialog();
    overlay.querySelector('.help-close').addEventListener('click', close);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });

    this._helpEscHandler = e => { if (e.key === 'Escape') close(); };
    document.addEventListener('keydown', this._helpEscHandler);
  },

  _closeHelpDialog() {
    const overlay = document.querySelector('.help-overlay');
    if (overlay) overlay.remove();
    if (this._helpEscHandler) {
      document.removeEventListener('keydown', this._helpEscHandler);
      this._helpEscHandler = null;
    }
  },

  // ── Version check (from ?v= query parameter) ─────────────────────────────
  _checkVersionParam() {
    const params = new URLSearchParams(window.location.search);
    const incoming = params.get('v');
    if (!incoming) return;

    // Strip leading 'v' prefix if present
    const remoteVersion = incoming.replace(/^v/, '');
    const localVersion = typeof GLOVEBOX_VERSION !== 'undefined' ? GLOVEBOX_VERSION : 'dev';

    // Clean the URL so the popup doesn't reappear on refresh
    const cleanUrl = window.location.pathname + window.location.hash;
    window.history.replaceState(null, '', cleanUrl);

    // Compare versions (YYYYMMDD.HHMM format — numeric comparison works)
    const remoteNum = parseFloat(remoteVersion) || 0;
    const localNum = parseFloat(localVersion) || 0;
    const isUpToDate = localVersion !== 'dev' && remoteNum >= localNum;

    // Build popup
    const overlay = document.createElement('div');
    overlay.className = 'help-overlay update-check-overlay';

    if (isUpToDate) {
      overlay.innerHTML = `
        <div class="update-dialog">
          <div class="update-icon update-icon-ok">✅</div>
          <h2 class="update-title">You're up to date!</h2>
          <p class="update-detail">Your version <strong>v${remoteVersion}</strong> matches the latest release.</p>
          <button class="update-btn update-btn-close">Close</button>
        </div>`;
    } else {
      const dlUrl = 'https://github.com/Sam-Dowling/GloveBox/releases/latest/download/glovebox.html';
      overlay.innerHTML = `
        <div class="update-dialog">
          <div class="update-icon update-icon-new">🔄</div>
          <h2 class="update-title">New update available!</h2>
          <p class="update-detail">You have <strong>v${remoteVersion}</strong> — the latest version is <strong>v${localVersion}</strong>.</p>
          <div class="update-actions">
            <a class="update-btn update-btn-download" href="${dlUrl}" target="_blank" rel="noopener">⬇️ Download Latest</a>
            <button class="update-btn update-btn-close">Close</button>
          </div>
        </div>`;
    }

    document.body.appendChild(overlay);

    // Close handlers
    const close = () => { if (overlay.parentNode) overlay.remove(); };
    overlay.querySelector('.update-btn-close').addEventListener('click', close);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    const escHandler = e => { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', escHandler); } };
    document.addEventListener('keydown', escHandler);
  },

});

document.addEventListener('DOMContentLoaded', () => new App().init());
