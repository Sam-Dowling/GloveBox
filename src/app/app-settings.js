// ════════════════════════════════════════════════════════════════════════════
// App — unified Settings / Help dialog
//
// Two-tabbed modal: Settings + Help.
//   - Settings tab: theme picker (reuses the THEMES registry + _setTheme in
//     app-ui.js) and a logarithmic summary-budget slider.
//   - Help tab: 1:1 port of the legacy _openHelpDialog body (keyboard
//     shortcuts table, tagline, 🔄 Check for Updates link).
//
// The YARA dialog (app-yara.js) is a separate surface and is deliberately
// NOT touched. The version-check popup (_checkVersionParam in app-ui.js)
// still uses the legacy `.help-overlay` / `.update-check-overlay` classes
// — those CSS rules in viewers.css are kept intact.
//
// Persistence keys:
//   - loupe_summary_chars  — integer 1..10 (slider step); default 5
//   - loupe_theme          — owned by app-ui.js (_initTheme / _setTheme)
// ════════════════════════════════════════════════════════════════════════════

// ── Summary budget: 10-step logarithmic scale ───────────────────────────────
// Char budgets roughly double each step. The label is a token-count
// approximation (~4 chars/token) shown as a chip next to the ⚡ Summary
// button so the analyst knows roughly how large the copied report will be.
// Step 10 is unbudgeted (Infinity) — _buildAnalysisText already has an
// UNBUDGETED code path for this exact case.
const SUMMARY_STEPS = [
  { step: 1, chars: 4000, label: '1K' },
  { step: 2, chars: 8000, label: '2K' },
  { step: 3, chars: 16000, label: '4K' },
  { step: 4, chars: 32000, label: '8K' },
  { step: 5, chars: 64000, label: '16K' },   // default — closest to legacy 50 000
  { step: 6, chars: 128000, label: '32K' },
  { step: 7, chars: 256000, label: '64K' },
  { step: 8, chars: 512000, label: '128K' },
  { step: 9, chars: 1048576, label: '256K' },
  { step: 10, chars: Infinity, label: 'MAX' },
];
const SUMMARY_DEFAULT_STEP = 5;
const SUMMARY_PREF_KEY = 'loupe_summary_chars';

Object.assign(App.prototype, {
  // ── Persisted state helpers ────────────────────────────────────────────
  _initSettings() {
    let saved = SUMMARY_DEFAULT_STEP;
    try {
      const raw = localStorage.getItem(SUMMARY_PREF_KEY);
      const n = parseInt(raw, 10);
      if (Number.isFinite(n) && n >= 1 && n <= SUMMARY_STEPS.length) saved = n;
    } catch (_) { /* storage blocked */ }
    this._summaryStep = saved;
    // Paint the Summary chip on boot so the badge reflects the restored
    // preference even before the user opens the Settings dialog.
    this._refreshSummaryBadge();
  },

  _getSummaryStep() {
    return this._summaryStep || SUMMARY_DEFAULT_STEP;
  },

  _getSummaryCharBudget() {
    const s = SUMMARY_STEPS.find(x => x.step === this._getSummaryStep())
      || SUMMARY_STEPS[SUMMARY_DEFAULT_STEP - 1];
    return s.chars;
  },

  _getSummaryBadgeLabel() {
    const s = SUMMARY_STEPS.find(x => x.step === this._getSummaryStep())
      || SUMMARY_STEPS[SUMMARY_DEFAULT_STEP - 1];
    return s.label;
  },

  _setSummaryStep(step) {
    const n = parseInt(step, 10);
    if (!Number.isFinite(n) || n < 1 || n > SUMMARY_STEPS.length) return;
    this._summaryStep = n;
    try { localStorage.setItem(SUMMARY_PREF_KEY, String(n)); } catch (_) { /* storage blocked */ }
    this._refreshSummaryBadge();
  },

  // Keep the chip inside `#btn-copy-analysis` in sync with the current step.
  // Called on boot, on slider input, and whenever the viewer toolbar is
  // (re-)built after a file load.
  _refreshSummaryBadge() {
    const chip = document.getElementById('summary-budget-chip');
    if (!chip) return;
    chip.textContent = this._getSummaryBadgeLabel();
  },

  // ── Dialog open / close ────────────────────────────────────────────────
  //
  // `tab` selects which pane is active on open:
  //   'settings' (default) — theme picker + summary slider
  //   'help'               — legacy help dialog content
  _openSettingsDialog(tab) {
    const activeTab = tab === 'help' ? 'help' : 'settings';

    // If already open, just switch tabs
    const existing = document.querySelector('.settings-overlay');
    if (existing) {
      this._switchSettingsTab(existing, activeTab);
      return;
    }

    const version = typeof LOUPE_VERSION !== 'undefined' ? LOUPE_VERSION : 'dev';

    const overlay = document.createElement('div');
    overlay.className = 'settings-overlay';
    overlay.innerHTML = `
      <div class="settings-dialog" role="dialog" aria-modal="true" aria-label="Settings">
        <div class="settings-header">
          <span class="settings-title">🕵🏻 Loupe <small class="settings-version">v${version}</small></span>
          <button class="settings-close" title="Close (Esc)" aria-label="Close">✕</button>
        </div>
        <div class="settings-tabs" role="tablist">
          <button class="settings-tab" data-tab="settings" role="tab" aria-selected="false">⚙ Settings</button>
          <button class="settings-tab" data-tab="help"     role="tab" aria-selected="false">? Help</button>
        </div>
        <div class="settings-body" data-tab-body></div>
      </div>`;

    document.body.appendChild(overlay);

    // Close handlers
    const close = () => this._closeSettingsDialog();
    overlay.querySelector('.settings-close').addEventListener('click', close);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    this._settingsEscHandler = e => { if (e.key === 'Escape') close(); };
    document.addEventListener('keydown', this._settingsEscHandler);

    // Tab switching
    for (const btn of overlay.querySelectorAll('.settings-tab')) {
      btn.addEventListener('click', () => this._switchSettingsTab(overlay, btn.dataset.tab));
    }

    this._switchSettingsTab(overlay, activeTab);
  },

  _closeSettingsDialog() {
    const overlay = document.querySelector('.settings-overlay');
    if (overlay) overlay.remove();
    if (this._settingsEscHandler) {
      document.removeEventListener('keydown', this._settingsEscHandler);
      this._settingsEscHandler = null;
    }
  },

  _switchSettingsTab(overlay, tab) {
    for (const btn of overlay.querySelectorAll('.settings-tab')) {
      const active = btn.dataset.tab === tab;
      btn.classList.toggle('settings-tab-active', active);
      btn.setAttribute('aria-selected', active ? 'true' : 'false');
    }
    const body = overlay.querySelector('[data-tab-body]');
    body.innerHTML = '';
    if (tab === 'help') this._renderHelpTab(body);
    else this._renderSettingsTab(body);
  },

  // ── Settings tab ───────────────────────────────────────────────────────
  _renderSettingsTab(body) {
    // Theme picker — one tile per entry in the THEMES registry (app-ui.js).
    // Delegates to _setTheme so the toolbar 🌙 dropdown and the Settings
    // picker stay in lock-step; localStorage persistence is handled there.
    const themeRow = document.createElement('div');
    themeRow.className = 'settings-row';
    themeRow.innerHTML = `
      <div class="settings-row-label">Theme</div>
      <div class="settings-hint">Switch the colour palette.</div>
      <div class="settings-theme-grid" id="settings-theme-grid"></div>`;
    body.appendChild(themeRow);

    const grid = themeRow.querySelector('#settings-theme-grid');
    // THEMES + _themeId are defined/owned by app-ui.js.
    const currentId = this._themeId;
    for (const t of THEMES) {
      const tile = document.createElement('button');
      tile.type = 'button';
      tile.className = 'settings-theme-tile';
      if (t.id === currentId) tile.classList.add('settings-theme-tile-active');
      tile.dataset.themeId = t.id;
      tile.innerHTML = `<span class="settings-theme-icon">${t.icon}</span><span class="settings-theme-label">${t.label}</span>`;
      tile.addEventListener('click', () => {
        this._setTheme(t.id);
        for (const el of grid.querySelectorAll('.settings-theme-tile')) {
          el.classList.toggle('settings-theme-tile-active', el.dataset.themeId === t.id);
        }
      });
      grid.appendChild(tile);
    }

    // Summary budget slider — logarithmic, 10 stops. Writing to
    // localStorage happens in _setSummaryStep so the chip stays in sync.
    const curStep = this._getSummaryStep();
    const curInfo = SUMMARY_STEPS[curStep - 1];

    const sumRow = document.createElement('div');
    sumRow.className = 'settings-row';
    sumRow.innerHTML = `
      <div class="settings-row-label">⚡ Summary size</div>
      <div class="settings-hint">Rough upper bound for the plaintext report copied by the ⚡ Summary button. Raising this also widens every table cap, per-field truncation, and metadata-tree depth — more PE imports, longer PDF/AutoHotkey scripts, fuller entitlements, deeper EVTX / SQLite table and so on.</div>

      <input type="range" class="settings-slider" id="settings-summary-slider"
             min="1" max="${SUMMARY_STEPS.length}" step="1" value="${curStep}">
      <div class="settings-slider-readout" id="settings-summary-readout"></div>`;
    body.appendChild(sumRow);

    const slider = sumRow.querySelector('#settings-summary-slider');
    const readout = sumRow.querySelector('#settings-summary-readout');
    const paintReadout = () => {
      const step = parseInt(slider.value, 10);
      const info = SUMMARY_STEPS[step - 1];
      const charsStr = info.chars === Infinity
        ? 'unbudgeted'
        : `${info.chars.toLocaleString()} chars`;
      readout.textContent = `~${info.label} tokens · ${charsStr}`;
    };
    paintReadout();
    slider.addEventListener('input', () => {
      this._setSummaryStep(slider.value);
      paintReadout();
    });

    // Quick sanity note — reminds the user the current value applies to the
    // toolbar Summary button.
    const foot = document.createElement('div');
    foot.className = 'settings-footnote';
    foot.innerHTML = `Default is ~${curInfo ? SUMMARY_STEPS[SUMMARY_DEFAULT_STEP - 1].label : '16K'} tokens.`;
    body.appendChild(foot);
  },

  // ── Help tab ───────────────────────────────────────────────────────────
  // 1:1 port of the legacy _openHelpDialog body. Reuses the existing
  // `.help-kbd-table`, `.help-kbd`, `.help-tagline`, `.help-update-btn`
  // classes from viewers.css verbatim.
  _renderHelpTab(body) {
    const version = typeof LOUPE_VERSION !== 'undefined' ? LOUPE_VERSION : 'dev';
    body.innerHTML = `
      <p class="help-tagline">A 100% offline, single-file security analyser for suspicious files.<br>No server, no uploads, no tracking — just drop a file and inspect it.</p>

      <h3>Keyboard Shortcuts</h3>
      <table class="help-kbd-table">
        <tr><td><kbd class="help-kbd">S</kbd></td><td>Toggle security sidebar</td></tr>
        <tr><td><kbd class="help-kbd">Y</kbd></td><td>Open YARA rule editor</td></tr>
        <tr><td><kbd class="help-kbd">,</kbd></td><td>Open Settings</td></tr>
        <tr><td><kbd class="help-kbd">?</kbd> / <kbd class="help-kbd">H</kbd></td><td>Open Help</td></tr>
        <tr><td><kbd class="help-kbd">F</kbd></td><td>Focus document search</td></tr>
        <tr><td><kbd class="help-kbd">Ctrl+C</kbd> / <kbd class="help-kbd">⌘C</kbd></td><td>Copy raw file content (when nothing is selected)</td></tr>
        <tr><td><kbd class="help-kbd">Ctrl+V</kbd></td><td>Paste file from clipboard</td></tr>
        <tr><td><kbd class="help-kbd">Esc</kbd></td><td>Close dialog / clear search</td></tr>
      </table>

      <h3>Links</h3>
      <p>
        <a href="https://github.com/Loupe-tools/Loupe/releases/latest/download/loupe.html" target="_blank" rel="noopener">Download Loupe</a>
        ·
        <a href="https://github.com/Loupe-tools/Loupe" target="_blank" rel="noopener">GitHub Repository</a>
        ·
        <a href="https://loupe.tools/" target="_blank" rel="noopener">Live Demo</a>
      </p>

      <div style="text-align:center;margin-top:12px;">
        <a class="help-update-btn" href="https://loupe.tools/?v=v${version}" target="_blank" rel="noopener">🔄 Check for Updates</a>
      </div>

      <p style="margin-top:1.2em;opacity:0.5;font-size:0.85em;">Licensed under the Mozilla Public License Version 2.0</p>`;
  },
});
