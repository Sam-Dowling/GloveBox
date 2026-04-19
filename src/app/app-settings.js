// ════════════════════════════════════════════════════════════════════════════
// App — unified Settings / Help dialog
//
// Two-tabbed modal: Settings + Help.
//   - Settings tab: theme picker (reuses the THEMES registry + _setTheme in
//     app-ui.js) and a 3-phase Summarize-target picker.
//   - Help tab: 1:1 port of the legacy _openHelpDialog body (keyboard
//     shortcuts table, tagline, 🔄 Check for Updates link).
//
// The YARA dialog (app-yara.js) is a separate surface and is deliberately
// NOT touched. The version-check popup (_checkVersionParam in app-ui.js)
// still uses the legacy `.help-overlay` / `.update-check-overlay` classes
// — those CSS rules in viewers.css are kept intact.
//
// Persistence keys:
//   - loupe_summary_target  — 'default' | 'large' | 'unlimited'; default 'default'
//   - loupe_theme           — owned by app-ui.js (_initTheme / _setTheme)
//
// A one-shot migration from the legacy `loupe_summary_chars` (integer 1..10
// step) is applied on boot: steps 1–4 → 'default', 5–8 → 'large', 9–10 →
// 'unlimited'. The old key is deleted after the migration write.
// ════════════════════════════════════════════════════════════════════════════

// ── Summarize target: 3-phase picker ────────────────────────────────────────
// The Summarize toolbar button (⚡ Summarize, _copyAnalysis in app-ui.js)
// builds the full plaintext report at maximum fidelity, measures the
// concatenated length, and only shrinks sections if the total exceeds the
// chosen target. 'unlimited' short-circuits every cap so raw scripts, small
// binaries, and tiny plists emit byte-identical to the legacy MAX output.
const SUMMARY_TARGETS = [
  { id: 'default',   chars: 64000,    label: 'Default',   sub: '~16K tokens' },
  { id: 'large',     chars: 200000,   label: 'Large',     sub: '~50K tokens' },
  { id: 'unlimited', chars: Infinity, label: 'Unlimited', sub: 'no limit'    },
];
const SUMMARY_DEFAULT_ID = 'default';
const SUMMARY_PREF_KEY = 'loupe_summary_target';
const SUMMARY_LEGACY_KEY = 'loupe_summary_chars';

Object.assign(App.prototype, {
  // ── Persisted state helpers ────────────────────────────────────────────
  _initSettings() {
    let saved = SUMMARY_DEFAULT_ID;
    try {
      const raw = localStorage.getItem(SUMMARY_PREF_KEY);
      if (raw && SUMMARY_TARGETS.some(t => t.id === raw)) {
        saved = raw;
      } else {
        // One-shot migration from the legacy 10-step integer key.
        const legacy = localStorage.getItem(SUMMARY_LEGACY_KEY);
        if (legacy != null) {
          const n = parseInt(legacy, 10);
          if (Number.isFinite(n)) {
            if (n >= 9)      saved = 'unlimited';
            else if (n >= 5) saved = 'large';
            else             saved = 'default';
          }
          try { localStorage.setItem(SUMMARY_PREF_KEY, saved); } catch (_) { /* storage blocked */ }
          try { localStorage.removeItem(SUMMARY_LEGACY_KEY); }   catch (_) { /* storage blocked */ }
        }
      }
    } catch (_) { /* storage blocked */ }
    this._summaryTarget = saved;
  },

  _getSummaryTarget() {
    return this._summaryTarget || SUMMARY_DEFAULT_ID;
  },

  // Public accessor used by _copyAnalysis / _buildAnalysisText. Returns a
  // character-count target (number) or Infinity for the unlimited phase.
  _getSummaryCharBudget() {
    const t = SUMMARY_TARGETS.find(x => x.id === this._getSummaryTarget())
      || SUMMARY_TARGETS[0];
    return t.chars;
  },

  _setSummaryTarget(id) {
    if (!SUMMARY_TARGETS.some(t => t.id === id)) return;
    this._summaryTarget = id;
    try { localStorage.setItem(SUMMARY_PREF_KEY, id); } catch (_) { /* storage blocked */ }
  },

  // ── Dialog open / close ────────────────────────────────────────────────
  //
  // `tab` selects which pane is active on open:
  //   'settings' (default) — theme picker + Summarize-target picker
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

    // Summarize target — 3 tiles (Default / Large / Unlimited). No hint,
    // no footnote; writing to localStorage happens in _setSummaryTarget.
    // The writer builds the report at full fidelity and only shrinks if
    // the total exceeds the chosen target, so picking a larger phase never
    // injects filler — it just raises the ceiling before per-section
    // truncation kicks in.
    const curId = this._getSummaryTarget();
    const sumRow = document.createElement('div');
    sumRow.className = 'settings-row';
    sumRow.innerHTML = `
      <div class="settings-row-label">⚡ Summarize target</div>
      <div class="settings-phase-grid" id="settings-summary-grid"></div>`;
    body.appendChild(sumRow);

    const phaseGrid = sumRow.querySelector('#settings-summary-grid');
    for (const t of SUMMARY_TARGETS) {
      const tile = document.createElement('button');
      tile.type = 'button';
      tile.className = 'settings-theme-tile settings-phase-tile';
      if (t.id === curId) tile.classList.add('settings-theme-tile-active');
      tile.dataset.phaseId = t.id;
      tile.innerHTML = `<span class="settings-phase-label">${t.label}</span><span class="settings-phase-sub">${t.sub}</span>`;
      tile.addEventListener('click', () => {
        this._setSummaryTarget(t.id);
        for (const el of phaseGrid.querySelectorAll('.settings-phase-tile')) {
          el.classList.toggle('settings-theme-tile-active', el.dataset.phaseId === t.id);
        }
      });
      phaseGrid.appendChild(tile);
    }
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
