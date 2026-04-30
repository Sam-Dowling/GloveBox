// ════════════════════════════════════════════════════════════════════════════
// App — unified Settings / Themes / Nicelists / Help dialog
//
// Four-tabbed modal:
//   ⚙ Settings   — 3-phase Summarize target picker + GeoIP / ASN database row
//   ◐ Themes    — six-theme tile grid (delegates to App._setTheme in app-ui)
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

extendApp({
  // ── Persisted state helpers ────────────────────────────────────────────
  _initSettings() {
    let saved = SUMMARY_DEFAULT_ID;
    const raw = safeStorage.get(SUMMARY_PREF_KEY);
    if (raw && SUMMARY_TARGETS.some(t => t.id === raw)) {
      saved = raw;
    } else {
      // One-shot migration from the legacy 10-step integer key.
      const legacy = safeStorage.get(SUMMARY_LEGACY_KEY);
      if (legacy != null) {
        const n = parseInt(legacy, 10);
        if (Number.isFinite(n)) {
          if (n >= 9) saved = 'unlimited';
          else if (n >= 5) saved = 'large';
          else saved = 'default';
        }
        safeStorage.set(SUMMARY_PREF_KEY, saved);
        safeStorage.remove(SUMMARY_LEGACY_KEY);
      }
    }
    this._summaryTarget = saved;

    // One-shot cleanup of a removed setting. The "Off-thread IOC scan"
    // checkbox was scrapped (the worker probe handles Firefox `file://`
    // automatically and broadening the flag to all workers would break
    // large CSV / EVTX timeline loads — see the IOC dispatch comment in
    // `src/app/app-load.js`). Garbage-collect any stale value so users
    // who toggled the box previously don't carry a dead key forever.
    safeStorage.remove('loupe_ioc_worker_disabled');
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
    safeStorage.set(SUMMARY_PREF_KEY, id);
  },


  // ── Dialog open / close ────────────────────────────────────────────────
  //
  // `tab` selects which pane is active on open:
  //   'settings' (default) — Summarize-target picker + GeoIP database row
  //   'themes'             — six-theme tile grid
  //   'nicelists'          — built-in toggle + per-list cards
  //   'help'               — legacy help dialog content
  _openSettingsDialog(tab) {
    const validTabs = ['settings', 'themes', 'nicelists', 'help'];
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
          <button class="settings-tab" data-tab="themes"    role="tab" aria-selected="false">◐ Themes</button>
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
    else if (tab === 'themes') this._renderThemesTab(body);
    else this._renderSettingsTab(body);
  },

  // ── Themes tab ─────────────────────────────────────────────────────────
  // Six-theme tile grid. Clicking a tile delegates to App._setTheme (defined
  // in app-ui.js), which updates `loupe_theme`, swaps the body class, and
  // re-runs the backdrop engine map (app-bg.js).
  _renderThemesTab(body) {
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
  },

  // ── Settings tab ───────────────────────────────────────────────────────
  _renderSettingsTab(body) {
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

    // ── GeoIP database row ─────────────────────────────────────────────
    // Bundled provider info + uploader for the optional MMDB override.
    // The Timeline view's GeoIP enrichment mixin reads `this._app.geoip`
    // (resolved in App.init()) — uploads here re-run enrichment on the
    // open view via `_runGeoipEnrichment()`.
    if (typeof BundledGeoip !== 'undefined') {
      this._renderGeoipRow(body);
    }
  },

  // Surface for the GeoIP MMDB overrides. The row is laid out as:
  //
  //   ┌ 🌍 GeoIP database ─────────────────────────────────────────────┐
  //   │ ╭─ bundled info strip ─────────────────────────────────────╮   │
  //   │ │ 🌐  Bundled: <vintage>   IPv4 → country, no setup needed │   │
  //   │ ╰──────────────────────────────────────────────────────────╯   │
  //   │ ╭─ Geo MMDB card ──────────────────────────────────────────╮   │
  //   │ │ Geo MMDB    country / region / city                      │   │
  //   │ │ No MMDB loaded                                           │   │
  //   │ │ Need one? Download GeoLite2-City (free, ~26 MB).         │   │
  //   │ │ [⬆ Upload .mmdb / .mmdb.gz]                             │   │
  //   │ ╰──────────────────────────────────────────────────────────╯   │
  //   │ ╭─ ASN MMDB card ──────────────────────────────────────────╮   │
  //   │ │ … same shape, links to GeoLite2-ASN …                    │   │
  //   │ ╰──────────────────────────────────────────────────────────╯   │
  //   └────────────────────────────────────────────────────────────────┘
  //
  // Slot semantics:
  //   geo  — IPv4 → country / region / city (overrides the bundled
  //          provider when present; falls back to bundled when empty).
  //   asn  — IPv4 → AS number / organisation. Optional, no fallback.
  //
  // Uploads are schema-sniffed via `reader.detectSchema()` and rejected
  // when the analyst pushes an obviously-wrong DB into the wrong slot
  // ("ASN MMDB into the geo slot" → toast, no save). DBs whose schema
  // can't be probed (every probe IP misses) are accepted — some private
  // / regional DBs lack global coverage.
  //
  // The "Need one? Download …" hint is rendered ONLY when the slot is
  // empty so the UI stays quiet for users who already have an override
  // configured. The links are plain `<a target="_blank">` to a public
  // CDN — no `fetch`, no `<script src>`, no CSP relaxation needed
  // (`default-src 'none'` does not gate `<a href>` navigation). The
  // browser handles the download outside the app context, after which
  // the user uploads the file via the slot's Upload button.
  //
  // The bundled provider is always present so analysts get useful
  // country data with zero configuration; the overrides exist for
  // users who want GeoLite2-City accuracy or AS-level enrichment. See
  // SECURITY.md for the rationale (no network → no licence-protected
  // DB shipped).
  _renderGeoipRow(body) {
    const row = document.createElement('div');
    row.className = 'settings-row';
    row.innerHTML = `
      <div class="settings-row-label">🌍 GeoIP database</div>
      <div class="settings-geoip" id="settings-geoip"></div>`;
    body.appendChild(row);
    const host = row.querySelector('#settings-geoip');

    // Bundled summary strip — shared by both slots, rendered once.
    // Reads `BundledGeoip.vintage` so the strip stays accurate across
    // bundle refreshes without any code change here.
    const bundled = document.createElement('div');
    bundled.className = 'settings-geoip-bundled-strip';
    const bundledVintage = (typeof BundledGeoip !== 'undefined' && BundledGeoip.vintage)
      ? BundledGeoip.vintage : 'IPv4 → country';
    bundled.innerHTML = `
      <span class="settings-geoip-bundled-icon" aria-hidden="true">🌐</span>
      <span class="settings-geoip-bundled-main">Bundled: ${this._escapeAttr(bundledVintage)}</span>
      <span class="settings-geoip-bundled-sub">IPv4 → country, no setup needed</span>`;
    host.appendChild(bundled);

    // One card per slot. Each card owns its own header + body and
    // delegates body content (state line, hint, button row) to
    // `_refreshGeoipSlot`, which re-renders in place after every
    // Upload / Remove.
    const geoCard = this._buildGeoipCard('geo', 'IP Geolocation Lookup', 'country / region / city');
    host.appendChild(geoCard);
    this._refreshGeoipSlot(
      geoCard.querySelector('.settings-geoip-card-body'),
      'geo',
      'GeoLite2-City',
      'https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-city-mmdb/geolite2-city-ipv4.mmdb',
      '~30 MB',
    );

    const asnCard = this._buildGeoipCard('asn', 'IP ASN Lookup', 'autonomous system / organisation');
    host.appendChild(asnCard);
    this._refreshGeoipSlot(
      asnCard.querySelector('.settings-geoip-card-body'),
      'asn',
      'GeoLite2-ASN',
      'https://cdn.jsdelivr.net/npm/@ip-location-db/geolite2-asn-mmdb/geolite2-asn-ipv4.mmdb',
      '~10 MB',
    );
  },

  // Construct the static card chrome (header + empty body) for a slot.
  // The body is populated by `_refreshGeoipSlot`, which is reentrant so
  // every Upload / Remove can refresh in-place without rebuilding the
  // header.
  _buildGeoipCard(slot, title, sub) {
    const card = document.createElement('div');
    card.className = 'settings-geoip-card';
    card.dataset.slot = slot;
    card.innerHTML = `
      <div class="settings-geoip-card-header">
        <span class="settings-geoip-card-title">${this._escapeAttr(title)}</span>
        <span class="settings-geoip-card-sub">${this._escapeAttr(sub)}</span>
      </div>
      <div class="settings-geoip-card-body"></div>`;
    return card;
  },

  // Render one slot's body content. Re-entrant: every Upload / Remove
  // handler calls back into this function with the same `host` (the
  // `.settings-geoip-card-body` element) to refresh state line, hint,
  // and button row.
  //
  //   suggestionLabel — display text for the inline `<a>` (e.g.
  //                     "GeoLite2-City"). Used in the hint that
  //                     appears only when no MMDB is loaded.
  //   suggestionUrl   — destination of the inline `<a>` (jsdelivr CDN
  //                     URL pointing at a vetted public MMDB).
  //   suggestionSize  — short size hint shown in parentheses after the
  //                     link, e.g. "~70 MB".
  _refreshGeoipSlot(host, slot, suggestionLabel, suggestionUrl, suggestionSize) {
    if (!host) return;
    host.innerHTML = '';
    const app = this;

    const stateLine = document.createElement('div');
    stateLine.className = 'settings-geoip-state';
    stateLine.textContent = '…';
    host.appendChild(stateLine);

    // Inline hint (only shown when no MMDB is loaded — see renderState).
    const hint = document.createElement('div');
    hint.className = 'settings-geoip-hint';
    host.appendChild(hint);

    const btnRow = document.createElement('div');
    btnRow.className = 'settings-geoip-btns';
    host.appendChild(btnRow);

    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.accept = '.mmdb,.gz';
    fileInput.style.display = 'none';
    host.appendChild(fileInput);

    const renderState = (meta) => {
      stateLine.innerHTML = '';
      btnRow.innerHTML = '';
      hint.innerHTML = '';
      if (meta) {
        const what = meta.databaseType || 'database override';
        const when = meta.vintage || (meta.savedAt
          ? `saved ${new Date(meta.savedAt).toISOString().slice(0, 10)}`
          : '');
        const fname = meta.filename ? ` (${meta.filename})` : '';
        stateLine.textContent = `Loaded: ${what}${when ? ' — ' + when : ''}${fname}`;
        // Hint is hidden once an MMDB is configured.
        hint.style.display = 'none';
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.className = 'nicelist-btn';
        remove.textContent = '✕ Remove';
        remove.addEventListener('click', async () => {
          const ok = await GeoipStore.clear(slot);
          if (ok) {
            if (slot === 'geo') {
              // Geo slot reverts to bundled provider.
              if (typeof BundledGeoip !== 'undefined') app.geoip = BundledGeoip;
            } else {
              // ASN slot has no fallback.
              app.geoipAsn = null;
            }
            if (app._timelineCurrent && typeof app._timelineCurrent._runGeoipEnrichment === 'function') {
              try { app._timelineCurrent._runGeoipEnrichment(); } catch (_) { /* noop */ }
            }
            app._toast(slot === 'geo'
              ? 'IP Geolocation database removed — using bundled IPv4 → country'
              : 'IP ASN database removed');
          } else {
            app._toast('Could not remove (storage blocked?)');
          }
          this._refreshGeoipSlot(host, slot, suggestionLabel, suggestionUrl, suggestionSize);
        });
        btnRow.appendChild(remove);
      } else {
        stateLine.textContent = 'No database loaded';
        // Show the suggested-download hint only in the empty state.
        hint.style.display = '';
        const safeLabel = this._escapeAttr(suggestionLabel);
        const safeUrl = this._escapeAttr(suggestionUrl);
        const safeSize = this._escapeAttr(suggestionSize || '');
        const sizeFrag = safeSize ? ` (free, ${safeSize})` : ' (free)';
        hint.innerHTML = `Need one? Download <a href="${safeUrl}" target="_blank" rel="noopener">${safeLabel}</a>${sizeFrag}.`;
      }
      const upload = document.createElement('button');
      upload.type = 'button';
      upload.className = 'nicelist-btn';
      upload.textContent = meta ? '⬆ Replace…' : '⬆ Upload .mmdb / .mmdb.gz';
      upload.title = (slot === 'geo')
        ? 'MaxMind / DB-IP city or country database — richer than bundled (region + city)'
        : 'MaxMind / DB-IP ASN database — emits a second column with AS number + organisation';
      upload.addEventListener('click', () => fileInput.click());
      btnRow.appendChild(upload);
    };

    fileInput.addEventListener('change', async () => {
      const f = fileInput.files && fileInput.files[0];
      fileInput.value = '';
      if (!f) return;
      let reader;
      try {
        reader = await MmdbReader.fromBlob(f);
      } catch (e) {
        console.warn('[geoip] mmdb load failed:', e);
        app._toast(`Database rejected: ${e && e.message ? e.message : 'invalid file'}`);
        return;
      }
      // Schema sniff — reject obvious slot mismatches at upload time.
      // Accept 'unknown' (regional / private DBs whose probe IPs miss).
      let schema = 'unknown';
      try { schema = reader.detectSchema(); } catch (_) { schema = 'unknown'; }
      if (schema !== 'unknown' && schema !== slot) {
        app._toast(`This looks like a ${schema.toUpperCase()} database — upload it into the ${schema.toUpperCase()} slot instead`);
        return;
      }
      const meta = {
        filename: f.name,
        size: f.size,
        savedAt: Date.now(),
        vintage: reader.vintage,
        databaseType: reader.databaseType,
        schema,
      };
      const ok = await GeoipStore.save(slot, f, meta);
      if (!ok) {
        app._toast('Could not save database (storage quota or blocked)');
        return;
      }
      if (slot === 'geo') app.geoip = reader;
      else app.geoipAsn = reader;
      app._toast(`IP ${slot === 'geo' ? 'Geolocation' : 'ASN'} database loaded: ${reader.vintage}`);
      if (app._timelineCurrent && typeof app._timelineCurrent._runGeoipEnrichment === 'function') {
        try { app._timelineCurrent._runGeoipEnrichment(); } catch (_) { /* noop */ }
      }
      this._refreshGeoipSlot(host, slot, suggestionLabel, suggestionUrl, suggestionSize);
    });

    // Kick off the meta fetch and render the appropriate state.
    if (typeof GeoipStore !== 'undefined') {
      GeoipStore.getMeta(slot).then(renderState).catch(() => renderState(null));
    } else {
      renderState(null);
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
      if (!this.currentResult || !this.currentResult.buffer || !this.findings) return;
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
        <tr><td><kbd class="help-kbd">T</kbd></td><td>Open Themes</td></tr>
        <tr><td><kbd class="help-kbd">,</kbd></td><td>Open Settings</td></tr>
        <tr><td><kbd class="help-kbd">?</kbd> / <kbd class="help-kbd">H</kbd></td><td>Open Help</td></tr>
        <tr><td><kbd class="help-kbd">F</kbd></td><td>Focus document search</td></tr>
        <tr><td><kbd class="help-kbd">Ctrl+Enter</kbd></td><td>Copy ⚡ Summary to clipboard</td></tr>
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
