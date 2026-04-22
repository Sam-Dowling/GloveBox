// ════════════════════════════════════════════════════════════════════════════
// App — unified Settings / Nicelists / Help dialog
//
// Three-tabbed modal:
//   ⚙ Settings   — theme picker + 3-phase Summarize target picker
//   🛡 Nicelists — built-in "Default Nicelist" toggle + user-managed custom
//                   lists (create / upload CSV/JSON/TXT / edit / delete /
//                   export). Matches the UX of the YARA-rule upload dialog.
//   ? Help       — 1:1 port of the legacy _openHelpDialog body
//
// The YARA dialog (app-yara.js) is a separate surface and is deliberately
// NOT touched. The version-check popup (_checkVersionParam in app-ui.js)
// still uses the legacy `.help-overlay` / `.update-check-overlay` classes
// — those CSS rules in viewers.css are kept intact.
//
// Persistence keys:
//   - loupe_summary_target            — 'default' | 'large' | 'unlimited'
//   - loupe_theme                     — owned by app-ui.js
//   - loupe_nicelist_builtin_enabled  — '0' | '1' (owned by nicelist.js;
//                                        toggled here via _NicelistUser)
//   - loupe_nicelists_user            — JSON blob, owned by nicelist-user.js
//
// A one-shot migration from the legacy `loupe_summary_chars` (integer 1..10
// step) is applied on boot: steps 1–4 → 'default', 5–8 → 'large', 9–10 →
// 'unlimited'. The old key is deleted after the migration write.
// ════════════════════════════════════════════════════════════════════════════

// ── Summarize target: 3-phase picker ────────────────────────────────────────
const SUMMARY_TARGETS = [
  { id: 'default', chars: 64000, label: 'Default', sub: '~16K tokens' },
  { id: 'large', chars: 200000, label: 'Large', sub: '~50K tokens' },
  { id: 'unlimited', chars: Infinity, label: 'Unlimited', sub: 'no limit' },
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
            if (n >= 9) saved = 'unlimited';
            else if (n >= 5) saved = 'large';
            else saved = 'default';
          }
          try { localStorage.setItem(SUMMARY_PREF_KEY, saved); } catch (_) { /* storage blocked */ }
          try { localStorage.removeItem(SUMMARY_LEGACY_KEY); } catch (_) { /* storage blocked */ }
        }
      }
    } catch (_) { /* storage blocked */ }
    this._summaryTarget = saved;
  },

  _getSummaryTarget() {
    return this._summaryTarget || SUMMARY_DEFAULT_ID;
  },

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
  //   'nicelists'          — built-in toggle + per-list cards
  //   'help'               — legacy help dialog content
  _openSettingsDialog(tab) {
    const validTabs = ['settings', 'nicelists', 'help'];
    const activeTab = validTabs.indexOf(tab) >= 0 ? tab : 'settings';

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
          <button class="settings-tab" data-tab="settings"  role="tab" aria-selected="false">⚙ Settings</button>
          <button class="settings-tab" data-tab="nicelists" role="tab" aria-selected="false">🛡 Nicelists</button>
          <button class="settings-tab" data-tab="help"      role="tab" aria-selected="false">? Help</button>
        </div>
        <div class="settings-body" data-tab-body></div>
      </div>`;

    document.body.appendChild(overlay);

    const close = () => this._closeSettingsDialog();
    overlay.querySelector('.settings-close').addEventListener('click', close);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    this._settingsEscHandler = e => { if (e.key === 'Escape') close(); };
    document.addEventListener('keydown', this._settingsEscHandler);

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
    else if (tab === 'nicelists') this._renderNicelistsTab(body);
    else this._renderSettingsTab(body);
  },

  // ── Settings tab ───────────────────────────────────────────────────────
  _renderSettingsTab(body) {
    const themeRow = document.createElement('div');
    themeRow.className = 'settings-row';
    themeRow.innerHTML = `
      <div class="settings-row-label">Theme</div>
      <div class="settings-theme-grid" id="settings-theme-grid"></div>`;
    body.appendChild(themeRow);

    const grid = themeRow.querySelector('#settings-theme-grid');
    const currentId = this._themeId;
    for (const t of THEMES) {
      const tile = document.createElement('button');
      tile.type = 'button';
      tile.className = 'settings-theme-tile';
      if (t.id === currentId) tile.classList.add('settings-theme-tile-active');
      tile.dataset.themeId = t.id;
      tile.setAttribute('aria-label', `${t.label} theme (${t.dark ? 'dark' : 'light'})`);
      tile.title = `Switch to ${t.label}`;
      // Inline-paint the preview swatches from the theme's own colour
      // triple so each card previews what that theme looks like before
      // it's applied. `.settings-theme-preview` reads these via
      // var(--tp-bg) / var(--tp-accent) / var(--tp-risk).
      const p = t.preview || {};
      const inlineVars =
        `--tp-bg:${p.bg || '#fff'};` +
        `--tp-accent:${p.accent || '#1a73e8'};` +
        `--tp-risk:${p.risk || '#dc2626'};`;
      tile.innerHTML = `
        <span class="settings-theme-preview" style="${inlineVars}">
          <span class="settings-theme-preview-dot settings-theme-preview-dot-accent"></span>
          <span class="settings-theme-preview-dot settings-theme-preview-dot-muted"></span>
          <span class="settings-theme-preview-dot settings-theme-preview-dot-risk"></span>
        </span>
        <span class="settings-theme-label-row">
          <span class="settings-theme-icon">${t.icon}</span>
          <span class="settings-theme-label">${t.label}</span>
          <span class="settings-theme-sub">${t.dark ? 'Dark' : 'Light'}</span>
        </span>
        <span class="settings-theme-check" aria-hidden="true">✓</span>`;
      tile.addEventListener('click', () => {
        this._setTheme(t.id);
        for (const el of grid.querySelectorAll('.settings-theme-tile')) {
          el.classList.toggle('settings-theme-tile-active', el.dataset.themeId === t.id);
        }
      });
      grid.appendChild(tile);
    }


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

  // ── Nicelists tab ──────────────────────────────────────────────────────

  //
  // Surface for managing "known-good" allow-lists that demote IOC rows to
  // the bottom of the sidebar table. Two tiers:
  //   • Default Nicelist (built-in) — curated global infrastructure list
  //     from `src/nicelist.js`. Toggled on/off as a whole, entries are
  //     read-only.
  //   • User nicelists             — unlimited number of custom lists
  //     created/edited here or uploaded from CSV/JSON/TXT files. Each has
  //     its own name, enabled toggle, and entry list. Use case: MDR
  //     customer-owned domains, employee emails, on-network hostnames.
  //
  // No network, no eval, no server. All state lives in localStorage under
  // the `loupe_nicelists_user` key via `_NicelistUser` (see
  // src/nicelist-user.js) and `loupe_nicelist_builtin_enabled` for the
  // built-in gate.
  _renderNicelistsTab(body) {
    // Toolbar — title + ＋New / ⬆ Import / ⬇ Export all
    const bar = document.createElement('div');
    bar.className = 'nicelists-toolbar';
    bar.innerHTML = `
      <div class="nicelists-toolbar-title">Nicelists</div>
      <button class="nicelist-btn nicelist-btn-primary" data-act="new">＋ New list</button>
      <button class="nicelist-btn" data-act="import">⬆ Import…</button>
      <button class="nicelist-btn" data-act="export-all" title="Download all user nicelists as JSON">⬇ Export all</button>
      <div class="nicelists-toolbar-hint">
        Nicelists demote matching URL / domain / hostname / email IOCs to the
        bottom of the sidebar table (and optionally hide them). They never
        suppress YARA detections. Use the Default Nicelist for common global
        infrastructure; add your own lists for customer-owned or employee
        assets.
      </div>`;
    body.appendChild(bar);

    // Hidden file input for ⬆ Import.
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.json,.csv,.txt,.tsv';
    fileInput.multiple = true;
    fileInput.style.display = 'none';
    body.appendChild(fileInput);

    bar.querySelector('[data-act="new"]').addEventListener('click', () => {
      const rec = window._NicelistUser.createList('New nicelist');
      if (!rec) {
        this._toast('Could not create list (storage quota reached?)');
        return;
      }
      this._rerenderNicelistsTab(body);
      this._refreshSidebarIfLoaded();
      // Open the newly created card so the user can immediately edit.
      requestAnimationFrame(() => {
        const card = body.querySelector(`.nicelist-card[data-list-id="${rec.id}"]`);
        if (card) {
          card.classList.add('nicelist-card-open');
          const name = card.querySelector('.nicelist-name-input');
          if (name) { name.focus(); name.select(); }
        }
      });
    });

    bar.querySelector('[data-act="import"]').addEventListener('click', () => fileInput.click());

    bar.querySelector('[data-act="export-all"]').addEventListener('click', () => {
      const json = window._NicelistUser.exportAll();
      try {
        this._downloadText(json, 'loupe-nicelists.json', 'application/json');
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn('[nicelists] download failed:', e);
        this._toast('Download failed');
      }
    });

    fileInput.addEventListener('change', async () => {
      const files = Array.from(fileInput.files || []);
      fileInput.value = ''; // allow re-picking the same file later
      if (!files.length) return;
      let createdLists = 0;
      let totalEntries = 0;
      const errors = [];
      for (const f of files) {
        try {
          const text = await f.text();
          // Detect bulk-export shape and branch to importAll (merge).
          let isBulk = false;
          const trimmed = text.trim();
          if (trimmed.startsWith('{')) {
            try {
              const j = JSON.parse(trimmed);
              if (j && (j.kind === 'loupe-nicelists' || (Array.isArray(j.lists) && j.lists.length > 1))) {
                isBulk = true;
                const res = window._NicelistUser.importAll(text, 'merge');
                if (res && res.imported) {
                  createdLists += res.imported;
                }
                if (res && res.error) errors.push(`${f.name}: ${res.error}`);
              }
            } catch (_) { /* fall through to single-list parse */ }
          }
          if (!isBulk) {
            const parsed = window._NicelistUser.parse(text, f.name);
            if (!parsed.entries.length) {
              errors.push(`${f.name}: no usable entries (expected one domain/email/hostname per line)`);
              continue;
            }
            const rec = window._NicelistUser.createList(parsed.name || f.name.replace(/\.[^.]+$/, ''));
            if (!rec) {
              errors.push(`${f.name}: storage cap reached`);
              continue;
            }
            const updated = window._NicelistUser.updateList(rec.id, { entries: parsed.entries });
            if (updated) {
              createdLists++;
              totalEntries += updated.entries.length;
            }
          }
        } catch (e) {
          errors.push(`${f.name}: ${e && e.message ? e.message : 'read failed'}`);
        }
      }
      this._rerenderNicelistsTab(body);
      this._refreshSidebarIfLoaded();
      if (createdLists) {
        const plural = createdLists === 1 ? '' : 's';
        this._toast(`Imported ${createdLists} list${plural}${totalEntries ? ` · ${totalEntries} entries` : ''}`);
      }
      if (errors.length) {
        // eslint-disable-next-line no-console
        console.warn('[nicelists] import errors:', errors);
        if (!createdLists) this._toast(`Import failed: ${errors[0]}`);
      }
    });

    // Card container — first the pinned "Default Nicelist", then user lists.
    const container = document.createElement('div');
    container.className = 'nicelist-cards';
    body.appendChild(container);

    this._appendBuiltinCard(container, body);

    const userLists = window._NicelistUser.load();
    if (!userLists.length) {
      const empty = document.createElement('div');
      empty.className = 'nicelist-empty';
      empty.textContent = 'No custom nicelists yet. Click ＋ New list or ⬆ Import to add one.';
      container.appendChild(empty);
    } else {
      for (const l of userLists) this._appendUserCard(container, body, l);
    }
  },

  // Re-render just the Nicelists tab body in place. Used after any
  // mutation (create/delete/import/toggle) so the dialog reflects the
  // latest state without blowing away focus on the active tab.
  _rerenderNicelistsTab(body) {
    body.innerHTML = '';
    this._renderNicelistsTab(body);
  },

  _appendBuiltinCard(container, body) {
    const enabled = window._NicelistUser.getBuiltinEnabled();
    // Built-in entry count: read from the frozen NICELIST array.
    const count = (typeof NICELIST !== 'undefined' && NICELIST.length) || 0;

    const card = document.createElement('div');
    card.className = 'nicelist-card nicelist-card-builtin';
    card.dataset.listId = '__builtin__';
    card.innerHTML = `
      <div class="nicelist-card-header">
        <button class="nicelist-disclosure" type="button" aria-label="Toggle entry list"></button>
        <div class="nicelist-name-static">Default Nicelist</div>
        <span class="nicelist-builtin-badge" title="Ships with Loupe. Curated list of global infrastructure domains, package registries, CA/OCSP responders and XML namespaces that show up as noise on most samples.">Built-in</span>
        <span class="nicelist-count">${count} entries</span>
        <label class="nicelist-switch" title="When off, no entries in this list will demote IOC rows.">
          <input type="checkbox" ${enabled ? 'checked' : ''} data-act="toggle-builtin">
          <span>Enabled</span>
        </label>
      </div>
      <div class="nicelist-card-body">
        <textarea class="nicelist-entries" readonly></textarea>
        <div class="nicelist-entries-meta">
          Read-only. These entries ship with Loupe and can't be edited here
          — but you can turn the whole list off with the Enabled switch.
        </div>
      </div>`;
    container.appendChild(card);

    // Populate the read-only textarea only if the user opens it — saves
    // the DOM cost for the common case where the card stays collapsed.
    const textarea = card.querySelector('.nicelist-entries');
    const disclosure = card.querySelector('.nicelist-disclosure');
    let populated = false;
    const toggleOpen = () => {
      const isOpen = card.classList.toggle('nicelist-card-open');
      if (isOpen && !populated && typeof NICELIST !== 'undefined') {
        textarea.value = NICELIST.slice().sort().join('\n');
        populated = true;
      }
    };
    disclosure.addEventListener('click', toggleOpen);
    card.querySelector('.nicelist-name-static').addEventListener('click', toggleOpen);

    card.querySelector('[data-act="toggle-builtin"]').addEventListener('change', e => {
      window._NicelistUser.setBuiltinEnabled(e.target.checked);
      this._refreshSidebarIfLoaded();
    });
  },

  _appendUserCard(container, body, rec) {
    const card = document.createElement('div');
    card.className = 'nicelist-card';
    card.dataset.listId = rec.id;
    card.innerHTML = `
      <div class="nicelist-card-header">
        <button class="nicelist-disclosure" type="button" aria-label="Toggle entry list"></button>
        <input class="nicelist-name-input" type="text" maxlength="80"
               value="${this._escapeAttr(rec.name)}"
               title="Edit list name">
        <span class="nicelist-count">${rec.entries.length} entries</span>
        <label class="nicelist-switch" title="When off, this list won't demote IOC rows.">
          <input type="checkbox" ${rec.enabled ? 'checked' : ''} data-act="toggle">
          <span>Enabled</span>
        </label>
      </div>
      <div class="nicelist-card-body">
        <textarea class="nicelist-entries" spellcheck="false"
                  placeholder="One entry per line — domains, hostnames, full emails, or URLs.&#10;example.com&#10;sub.example.co.uk&#10;jane@example.com"></textarea>
        <div class="nicelist-entries-meta" data-meta></div>
        <div class="nicelist-card-foot">
          <button class="nicelist-btn" data-act="save">💾 Save changes</button>
          <button class="nicelist-btn" data-act="export" title="Download this list as JSON">⬇ Export</button>
          <div class="nicelist-foot-spacer"></div>
          <button class="nicelist-btn nicelist-btn-danger" data-act="delete">🗑 Delete</button>
        </div>
      </div>`;
    container.appendChild(card);

    const textarea = card.querySelector('.nicelist-entries');
    const meta = card.querySelector('[data-meta]');
    const nameInput = card.querySelector('.nicelist-name-input');
    const disclosure = card.querySelector('.nicelist-disclosure');
    const countEl = card.querySelector('.nicelist-count');

    const updateMeta = () => {
      const lines = textarea.value.split(/\r?\n/).filter(l => l.trim()).length;
      meta.textContent = `${lines} line${lines === 1 ? '' : 's'} (click Save to normalise & deduplicate)`;
    };

    const populate = () => {
      textarea.value = rec.entries.join('\n');
      updateMeta();
    };

    let populated = false;
    const toggleOpen = () => {
      const isOpen = card.classList.toggle('nicelist-card-open');
      if (isOpen && !populated) { populate(); populated = true; }
    };
    disclosure.addEventListener('click', toggleOpen);
    // Clicking the whole header (but not the input/switch/buttons) also toggles.
    card.querySelector('.nicelist-card-header').addEventListener('click', e => {
      if (e.target === disclosure) return;
      if (e.target.closest('.nicelist-name-input, .nicelist-switch, input, button')) return;
      toggleOpen();
    });

    textarea.addEventListener('input', updateMeta);

    nameInput.addEventListener('change', () => {
      const updated = window._NicelistUser.updateList(rec.id, { name: nameInput.value });
      if (updated) {
        rec.name = updated.name;
        nameInput.value = updated.name;
        this._refreshSidebarIfLoaded();
      }
    });
    // Prevent header-toggle while typing in the name field.
    nameInput.addEventListener('click', e => e.stopPropagation());

    card.querySelector('[data-act="toggle"]').addEventListener('change', e => {
      const updated = window._NicelistUser.updateList(rec.id, { enabled: !!e.target.checked });
      if (updated) {
        rec.enabled = updated.enabled;
        this._refreshSidebarIfLoaded();
      }
    });

    card.querySelector('[data-act="save"]').addEventListener('click', () => {
      const entries = textarea.value.split(/\r?\n/);
      const updated = window._NicelistUser.updateList(rec.id, { entries });
      if (updated) {
        rec.entries = updated.entries;
        textarea.value = updated.entries.join('\n');
        countEl.textContent = `${updated.entries.length} entries`;
        updateMeta();
        this._refreshSidebarIfLoaded();
        this._toast(`Saved · ${updated.entries.length} entries`);
      } else {
        this._toast('Could not save (storage quota reached?)');
      }
    });

    card.querySelector('[data-act="export"]').addEventListener('click', () => {
      const json = window._NicelistUser.exportList(rec.id);
      if (!json) return;
      const safeName = (rec.name || 'nicelist').replace(/[^a-z0-9_-]+/gi, '-').replace(/^-+|-+$/g, '') || 'nicelist';
      try {
        this._downloadText(json, `loupe-${safeName}.json`, 'application/json');
      } catch (e) {
        // eslint-disable-next-line no-console
        console.warn('[nicelists] download failed:', e);
        this._toast('Download failed');
      }
    });

    card.querySelector('[data-act="delete"]').addEventListener('click', () => {
      // Intentional: no native confirm() — the CSP permits it, but we want
      // the flow to match the YARA dialog's two-click delete pattern.
      const btn = card.querySelector('[data-act="delete"]');
      if (btn.dataset.armed === '1') {
        window._NicelistUser.deleteList(rec.id);
        this._rerenderNicelistsTab(body);
        this._refreshSidebarIfLoaded();
        return;
      }
      btn.dataset.armed = '1';
      btn.textContent = '⚠ Click again to confirm';
      setTimeout(() => {
        if (btn.dataset.armed === '1') {
          btn.dataset.armed = '0';
          btn.textContent = '🗑 Delete';
        }
      }, 2500);
    });
  },

  // ── small helpers (local to this tab) ──────────────────────────────────
  // `_downloadText` is defined on `App.prototype` in app-ui.js and delegates
  // to `window.FileDownload.downloadText` (see src/file-download.js). Callers
  // in this file wrap it in try/catch to surface the nicelist-specific toast.

  _escapeAttr(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/"/g, '&quot;')
      .replace(/</g, '&lt;').replace(/>/g, '&gt;');
  },

  // Re-render the sidebar if a file is currently loaded so nicelist
  // mutations (toggle, add/remove entry, create/delete list) reflect
  // immediately. `_renderSidebar` is owned by app-sidebar.js and rebuilds
  // the entire panel from `this.findings`, so the newly-enabled/disabled
  // nicelist hits reorder without the user having to reload the file.
  _refreshSidebarIfLoaded() {
    try {
      if (!this._fileBuffer || !this.findings) return;
      if (typeof this._renderSidebar !== 'function') return;
      const fileName = (this._fileMeta && this._fileMeta.name) || '';
      this._renderSidebar(fileName, null);
    } catch (_) { /* sidebar rebuild is best-effort */ }
  },

  // ── Help tab ───────────────────────────────────────────────────────────
  _renderHelpTab(body) {
    const version = typeof LOUPE_VERSION !== 'undefined' ? LOUPE_VERSION : 'dev';
    body.innerHTML = `
      <h3>Keyboard Shortcuts</h3>
      <table class="help-kbd-table">
        <tr><td><kbd class="help-kbd">S</kbd></td><td>Toggle security sidebar</td></tr>
        <tr><td><kbd class="help-kbd">Y</kbd></td><td>Open YARA rule editor</td></tr>
        <tr><td><kbd class="help-kbd">N</kbd></td><td>Open Nicelists</td></tr>
        <tr><td><kbd class="help-kbd">,</kbd></td><td>Open Settings</td></tr>
        <tr><td><kbd class="help-kbd">?</kbd> / <kbd class="help-kbd">H</kbd></td><td>Open Help</td></tr>
        <tr><td><kbd class="help-kbd">F</kbd></td><td>Focus document search</td></tr>
        <tr><td><kbd class="help-kbd">Ctrl+C</kbd></td><td>Copy raw file content (when nothing is selected)</td></tr>
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
