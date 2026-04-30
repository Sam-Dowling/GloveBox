'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-popovers.js — TimelineView prototype mixin (B2d).
//
// Hosts every popover / menu / dialog the timeline opens above the
// chart or grid:
//
//   • Add-Sus popover (`_openAddSusPopover`) — bulk-paste suspicious
//     indicators against a chosen column.
//   • Right-click row context menu (`_openRowContextMenu`) — the
//     Include/Exclude/Pin/Sus/Copy submenu that pops on cell click.
//   • Generic popover lifecycle (`_closePopover`) — the single-slot
//     `_openPopover` teardown shared by the three above + the column
//     menu.
//   • Column header menu (`_openColumnMenu`) — the Excel-style
//     filter / sort / pin / hide / value-picker dialog.
//   • Generic dialog lifecycle (`_closeDialog`) — single-slot
//     `_openDialog` teardown shared with `_openExtractionDialog`.
//   • Extraction dialog (`_openExtractionDialog`) — the Smart-scan
//     + Regex + Clicker tabbed modal that lets users derive new
//     columns from raw text.
//
// Methods kept in core `timeline-view.js` (not moved):
//   `_ellipsis`, `_copyToClipboard`, `_positionFloating` — tiny
//   utilities consumed by these popovers AND by the chart / grid
//   mixins; centralising them here would create the wrong dependency
//   direction.
//
// Bodies are moved byte-identically. The Add-Sus copy ("bulk-add
// suspicious indicators…") and the Extraction-dialog tab labels
// ("Auto" / "JSON" / "Regex") are pinned by the parity test below
// because regressions in those strings would silently break user-
// visible affordances that no other test currently covers.
//
// Loads AFTER timeline-view.js (which declares `class TimelineView`).
// ════════════════════════════════════════════════════════════════════════════

Object.assign(TimelineView.prototype, {

  // ── "＋ Add Sus" popover ─────────────────────────────────────────────────

  // Compact form anchored on the Add-Sus button. Pick a column and one or
  // more values (one per line, or comma-separated — paste a CSV / wordlist
  // straight in) and push them onto `_susMarks` (persisted by column
  // name). Sus marks tint rows but do NOT filter — use the query bar for
  // row filtering.
  _openAddSusPopover(anchor) {
    this._closePopover();
    const menu = document.createElement('div');
    menu.className = 'tl-popover tl-add-sus';

    // Build column <select>. An "Any column" sentinel (value -1) is
    // offered first and selected by default — this is the most common
    // sus pattern ("flag this value wherever it appears") and having it
    // sit at the top avoids the footgun where a user flags "admin" under
    // the first real column and then can't see why a later row with
    // admin in a different column is tinted.
    const cols = this.columns;
    let colOptions = '<option value="-1" selected>＊ Any column</option>';
    for (let i = 0; i < cols.length; i++) {
      const name = cols[i] || `(col ${i + 1})`;
      const prefix = (i >= this._baseColumns.length) ? '⨯ ' : '';
      colOptions += `<option value="${i}">${_tlEsc(prefix + name)}</option>`;
    }

    menu.innerHTML = `
      <div class="tl-add-filter-form">
        <label class="tl-field">
          <span class="tl-field-label">Column</span>
          <select class="tl-field-select" data-f="col">${colOptions}</select>
        </label>
        <label class="tl-field tl-field-wide">
          <span class="tl-field-label">Value(s)</span>
           <textarea class="tl-field-select tl-field-textarea" data-f="val" rows="3" spellcheck="false" placeholder="one value per line, or comma-separated (substring, case-insensitive)"></textarea>
        </label>
        <div class="tl-add-filter-hint">🚩 Sus marks tint rows red. Paste multiple values — one per line, or comma-separated. Enter submits, Shift+Enter inserts a newline. Use <code>is:sus</code> in the query bar to filter to only sus rows.</div>
        <div class="tl-add-filter-actions">
          <button class="tl-tb-btn" type="button" data-act="cancel">Cancel</button>
          <button class="tl-tb-btn tl-tb-btn-primary" type="button" data-act="add">Mark suspicious</button>
        </div>
      </div>
    `;

    const colSel = menu.querySelector('[data-f="col"]');
    const valEl = menu.querySelector('[data-f="val"]');

    const submit = () => {
      const colIdx = parseInt(colSel.value, 10);
      // Bulk-add path: split on newlines and commas, trim, drop empties,
      // dedupe within the batch (case-insensitive — matches the lower-case
      // storage convention used everywhere else for sus marks). Lower-case
      // at the split site so the dedupe / "already exists" checks below all
      // operate on the canonical form.
      const seen = new Set();
      const tokens = [];
      for (const part of String(valEl.value).split(/[\r\n,]+/)) {
        const t = part.trim();
        if (!t) continue;
        const lc = t.toLowerCase();
        if (seen.has(lc)) continue;
        seen.add(lc);
        tokens.push(lc);
      }
      if (tokens.length === 0) { valEl.focus(); return; }

      // colIdx === -1 is the "Any column" sentinel. Everything else must
      // resolve to a live column index.
      const isAny = (colIdx === -1);
      if (!isAny && (!Number.isFinite(colIdx) || colIdx < 0 || colIdx >= cols.length)) return;
      const colName = isAny ? null : cols[colIdx];
      if (!isAny && colName == null) return;

      // Bulk add is purely additive: skip tokens that already match an
      // existing mark for the same scope. (Single-add right-click toggles
      // still work via `_addOrToggleChip(...,{op:'sus'})` — that path is
      // unchanged.)
      let pushed = 0;
      for (const lc of tokens) {
        const exists = isAny
          ? this._susMarks.some(m => m.any === true && m.val.toLowerCase() === lc)
          : this._susMarks.some(m => m.any !== true && m.colName === colName && m.val.toLowerCase() === lc);
        if (exists) continue;
        if (isAny) this._susMarks.push({ any: true, colName: null, val: lc });
        else       this._susMarks.push({ colName, val: lc });
        pushed++;
      }

      // Coalesce persist + bitmap rebuild + render to a single pass even
      // when N tokens were pushed.
      if (pushed > 0) {
        TimelineView._saveSusMarksFor(this._fileKey, this._susMarks);
        this._rebuildSusBitmap();
        this._recomputeFilter();
        this._scheduleRender(['chart', 'chips', 'grid', 'columns']);
      }
      this._closePopover();
    };
    menu.querySelector('[data-act="add"]').addEventListener('click', submit);
    menu.querySelector('[data-act="cancel"]').addEventListener('click', () => this._closePopover());
    valEl.addEventListener('keydown', (e) => {
      // Enter submits; Shift+Enter falls through so the textarea inserts
      // a newline (keeps muscle memory from the old single-line input
      // while still permitting multi-line composition by hand). Pasted
      // multi-line content is unaffected — paste doesn't fire keydown for
      // the inserted newlines.
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit(); }
      else if (e.key === 'Escape') { e.preventDefault(); this._closePopover(); }
    });

    // Anchor below the button.
    const rect = anchor.getBoundingClientRect();
    this._positionFloating(menu, rect.left, rect.bottom + 4);
    document.body.appendChild(menu);
    this._openPopover = menu;
    setTimeout(() => valEl.focus(), 0);
  },
  // ── Right-click row context menu ─────────────────────────────────────────
  _openRowContextMenu(e, colIdx, val, opts) {
    opts = opts || {};
    this._closePopover();
    const menu = document.createElement('div');
    menu.className = 'tl-popover tl-rowmenu';
    const items = [];
    items.push({ label: `✓ Include "${this._ellipsis(val, 60)}"`, act: () => this._addOrToggleChip(colIdx, val, { op: 'eq' }) });
    items.push({ label: `✕ Exclude "${this._ellipsis(val, 60)}"`, act: () => this._addOrToggleChip(colIdx, val, { op: 'ne' }) });
    // "Only …" is a shortcut for "clear this column's filters, then include X".
    // Hide it when the column has no existing non-sus chips, because in that
    // state it is functionally identical to the ✓ Include item above (the
    // `replace: true` wipe step has nothing to remove). `sus` chips are
    // preserved by `_addOrToggleChip` either way, so they don't count here.
    // Query-bar is the single source of truth for column filters; walk the
    // current AST's top-level clauses and ask if any of them target `colIdx`.
    // Sus marks live in `_susMarks` (not the query) so they can never show up
    // here, which matches the old `c.op !== 'sus'` carve-out.
    const _hasOtherChipsOnCol = this._queryTopLevelClauses(this._queryCurrentAst())
      .some(c => this._clauseTargetsCol(c, colIdx));
    if (_hasOtherChipsOnCol) {
      items.push({
        label: `↺ Only "${this._ellipsis(val, 60)}" on this column`,
        act: () => this._addOrToggleChip(colIdx, val, { op: 'eq', replace: true }),
      });
    }
    items.push({ sep: true });
    items.push({ label: `🚩 Mark suspicious`, act: () => this._addOrToggleChip(colIdx, val, { op: 'sus' }) });
    // Focus-around-this-event pills — only when the row has a parseable
    // timestamp. Shown on EVERY column (not just the time column) so the
    // analyst can pivot without having to first click the time cell.
    const origRow = opts.origRow;
    const rowTime = (origRow != null && this._timeMs) ? this._timeMs[origRow] : null;
    if (origRow != null && Number.isFinite(rowTime) && this._dataRange) {
      items.push({ sep: true });
      items.push({ label: `🕒 Focus around this event`, labelOnly: true });
      items.push({
        pills: [
          { label: '±10s', ms: 10_000 },
          { label: '±1m', ms: 60_000 },
          { label: '±5m', ms: 300_000 },
          { label: '±10m', ms: 600_000 },
          { label: '±30m', ms: 1_800_000 },
        ], origRow
      });
    }
    items.push({ sep: true });
    items.push({ label: `ƒx Extract values`, act: () => this._openExtractionDialog(colIdx, 'manual') });

    items.push({ sep: true });
    // Auto-pivot — pick a sensible Rows × Cols × Count triple based on the
    // clicked column + the current stack column (if any) and expand the
    // pivot section. See `_autoPivotFromColumn` for the heuristic (which
    // already prefers the current stack column as Cols when one is set, so
    // a single entry is sufficient here).
    items.push({ label: `🧮 Auto pivot on this column`, act: () => this._autoPivotFromColumn(colIdx) });
    items.push({ sep: true });
    items.push({ label: `Copy value`, act: () => this._copyToClipboard(val) });


    for (const it of items) {
      if (it.sep) {
        const sep = document.createElement('div');
        sep.className = 'tl-popover-sep';
        menu.appendChild(sep);
      } else if (it.labelOnly) {
        const lbl = document.createElement('div');
        lbl.className = 'tl-popover-label';
        lbl.textContent = it.label;
        menu.appendChild(lbl);
      } else if (it.pills) {
        const row = document.createElement('div');
        row.className = 'tl-popover-pills';
        for (const p of it.pills) {
          const pb = document.createElement('button');
          pb.type = 'button';
          pb.className = 'tl-popover-pill';
          pb.textContent = p.label;
          const ms = p.ms;
          const oRow = it.origRow;
          pb.addEventListener('click', () => {
            try {
              const t = this._timeMs[oRow];
              if (!Number.isFinite(t) || !this._dataRange) return;
              const lo = Math.max(this._dataRange.min, t - ms);
              const hi = Math.min(this._dataRange.max, t + ms);
              this._window = { min: lo, max: hi };
              this._applyWindowOnly();
              this._scheduleRender(['scrubber', 'chart', 'chips', 'grid', 'columns']);
            } finally { this._closePopover(); }
          });
          row.appendChild(pb);
        }
        menu.appendChild(row);
      } else {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'tl-popover-item';
        b.textContent = it.label;
        b.addEventListener('click', () => { try { it.act(); } finally { this._closePopover(); } });
        menu.appendChild(b);
      }
    }
    this._positionFloating(menu, e.clientX, e.clientY);
    document.body.appendChild(menu);
    this._openPopover = menu;
  },
  _closePopover() {
    if (this._openPopover && this._openPopover.parentNode) {
      this._openPopover.parentNode.removeChild(this._openPopover);
    }
    this._openPopover = null;
  },
  // ── Column menu (Excel-style) ────────────────────────────────────────────
  _openColumnMenu(colIdx, anchor) {
    // Toggle: if the menu is already open for this exact column, close it.
    if (this._openPopover && this._openPopover.dataset.colIdx === String(colIdx)) {
      this._closePopover();
      return;
    }
    this._closePopover();
    const menu = document.createElement('div');
    menu.dataset.colIdx = colIdx;
    menu.className = 'tl-popover tl-colmenu';
    const name = this.columns[colIdx] || `(col ${colIdx + 1})`;
    // Pre-fill the Contains input + Values checkboxes from the current
    // query AST rather than a separate chip list — the query bar is now
    // the single source of truth. For `existingContains`, match the
    // first top-level `contains` predicate on this column. For
    // `existingEqs`, collect the union of (positive) `eq` predicate
    // values AND the values inside any positive `IN (…)` clause on
    // this column — the Apply handler below emits either an eq or an
    // `IN` list depending on cardinality, so both round-trip cleanly.
    const _astClauses = this._queryTopLevelClauses(this._queryCurrentAst());
    const _containsClause = _astClauses.find(c => c.k === 'pred' && c.op === 'contains' && c.colIdx === colIdx);
    const existingContains = _containsClause ? { val: _containsClause.val } : null;
    // Positive membership: `col = v` or `col IN (…)` — these narrow to an
    // explicit whitelist, so checkboxes are painted *unchecked* except for
    // members of `eqSet`.
    const existingEqs = [];
    // Negative membership: `col != v` or `col NOT IN (…)` — these narrow by
    // exclusion, so the menu starts *all-checked* with members of `neSet`
    // unchecked. This is the round-trip of the "shorter list wins" Apply
    // handler below.
    const existingNes = [];
    for (const c of _astClauses) {
      if (c.k === 'pred' && c.op === 'eq' && c.colIdx === colIdx) existingEqs.push(String(c.val));
      else if (c.k === 'pred' && c.op === 'ne' && c.colIdx === colIdx) existingNes.push(String(c.val));
      else if (c.k === 'in' && !c.neg && c.colIdx === colIdx) {
        for (const v of c.vals) existingEqs.push(String(v));
      } else if (c.k === 'in' && c.neg && c.colIdx === colIdx) {
        for (const v of c.vals) existingNes.push(String(v));
      }
    }
    const eqSet = new Set(existingEqs);
    const neSet = new Set(existingNes);

    // Only offer "Use as Timestamp" when the column's values actually parse
    // as timestamps (or bare numbers suitable for a numeric axis). Reuses the
    // scorers already used by `_tlAutoDetectTimestampCol`. Extracted columns
    // are sampled via `_cellAt` since their values live in `_extractedCols`.
    // The button is also hidden for the column that's already the current
    // timestamp — setting it a second time is a no-op.
    const showTimeBtn = this._columnLooksLikeTimestamp(colIdx)
      && colIdx !== this._timeCol;

    // Show the "🌍 Enrich IP" entry only when the column actually
    // contains IPv4 addresses AND at least one provider (geo or ASN) is
    // wired. Walks up to 30 sampled cells via `_cellAt` so it works on
    // both base and extracted (auto-extracted IP) columns. Hidden on
    // enrichment-output columns themselves (`<src>.geo` / `<src>.asn`).
    // The IPv4 shape check matches `isStrictIPv4` in
    // `timeline-view-geoip.js` (intentionally inlined here).
    let showGeoipBtn = false;
    if (this._app && (this._app.geoip || this._app.geoipAsn)) {
      const ext = this._isExtractedCol(colIdx) ? this._extractedColFor(colIdx) : null;
      // Suppress on enrichment-output columns (`kind: 'geoip' | 'geoip-asn'`).
      if (!(ext && (ext.kind === 'geoip' || ext.kind === 'geoip-asn'))) {
        const sample = Math.min(this.store.rowCount, 30);
        let nonEmpty = 0;
        let hits = 0;
        const ipRe = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/; // safe: bounded literal, ANN-OK
        for (let r = 0; r < sample; r++) {
          const v = this._cellAt(r, colIdx);
          if (!v) continue;
          nonEmpty++;
          if (ipRe.test(v)) hits++;
        }
        // Same 80 % bar `_detectIpColumns` uses; needs ≥ 4 non-empty cells
        // in the small popover sample (lower than the detection-pass bar
        // of 8 because the analyst already eyeballed the column).
        showGeoipBtn = nonEmpty >= 4 && (hits / nonEmpty) >= 0.8;
      }
    }

    menu.innerHTML = `
      <div class="tl-colmenu-head">
        <strong>${_tlEsc(name)}</strong>
      </div>
      <div class="tl-colmenu-section">
        <label class="tl-colmenu-label">Contains</label>
        <input type="text" class="tl-colmenu-input" data-f="contains" placeholder="substring…" spellcheck="false" value="${_tlEsc((existingContains && existingContains.val) || '')}">
      </div>
      <div class="tl-colmenu-section">
        <div class="tl-colmenu-row">
          <label class="tl-colmenu-label">Values (top 200)</label>
          <input type="text" class="tl-colmenu-input tl-colmenu-input-sm" data-f="valsearch" placeholder="search values…" spellcheck="false">
          <button class="tl-colmenu-copy" type="button" data-act="copyvals" title="Copy visible values to clipboard">📋</button>
        </div>
        <div class="tl-colmenu-values"></div>
        <div class="tl-colmenu-valactions">
          <button class="tl-tb-btn" data-act="selall">All</button>
          <button class="tl-tb-btn" data-act="selnone">None</button>
        </div>
      </div>
      <div class="tl-colmenu-section">
        ${showTimeBtn ? '<button class="tl-tb-btn" data-act="timecol">Use as Timestamp</button>' : ''}
        <button class="tl-tb-btn" data-act="stackcol">Stack chart by this</button>
      </div>
      ${this._isExtractedCol(colIdx) ? '<div class="tl-colmenu-section"><button class="tl-tb-btn tl-tb-btn-danger" data-act="removeExtract">✕ Remove extracted column</button></div>' : ''}
      <div class="tl-colmenu-section">
        <button class="tl-tb-btn" data-act="extract">ƒx Extract values</button>
        <button class="tl-tb-btn" data-act="autopivot">🧮 Auto pivot on this column</button>
        ${showGeoipBtn
          ? '<button class="tl-tb-btn" data-act="geoip" title="Force enrichment for this column — emits geo and/or ASN columns from the configured providers">🌍 Enrich IP</button>'
          : ''}
      </div>
      <div class="tl-colmenu-foot">
        <button class="tl-tb-btn" data-act="reset">Reset filters</button>
        <button class="tl-tb-btn tl-tb-btn-primary" data-act="apply">Apply</button>
      </div>
    `;

    const valsWrap = menu.querySelector('.tl-colmenu-values');
    // Populate distinct values using the "all-but-this-column" filter so
    // the user can broaden a narrowed selection without hitting Reset
    // first. Excel-parity — see `_indexIgnoringColumn` for semantics.
    const items = this._distinctValuesFor(colIdx, this._indexIgnoringColumn(colIdx), 200);
    // Three round-trip modes:
    //   (a) positive-eq present → start with only `eqSet` checked;
    //   (b) negative-ne present (and no eq) → start all-checked, `neSet` off;
    //   (c) nothing on this column → start all-checked.
    const initialAll = existingEqs.length === 0 && existingNes.length === 0;
    const initialAllMinusNe = existingEqs.length === 0 && existingNes.length > 0;

    // Live checkbox state — survives paint() re-renders when the user
    // types in Search Values. Keyed by value string → boolean (checked).
    // Seeded from the initial round-trip mode so the first paint is
    // correct, then updated by individual checkbox toggles and All/None.
    const liveState = new Map();
    for (const [val] of items) {
      const checked = initialAll ? true
        : initialAllMinusNe ? !neSet.has(val)
          : eqSet.has(val);
      liveState.set(val, checked);
    }

    const paint = (filterText) => {
      valsWrap.innerHTML = '';
      const lo = (filterText || '').toLowerCase();
      for (const [val, count] of items) {
        if (lo && !val.toLowerCase().includes(lo)) continue;
        const line = document.createElement('label');
        line.className = 'tl-colmenu-value';
        const checked = liveState.get(val) !== false;
        line.innerHTML = `<input type="checkbox" ${checked ? 'checked' : ''} data-val="${_tlEsc(val)}"> <span class="tl-colmenu-value-label" title="${_tlEsc(val)}">${_tlEsc(val === '' ? '(empty)' : val)}</span> <span class="tl-colmenu-value-count">${count.toLocaleString()}</span>`;
        valsWrap.appendChild(line);
      }
      if (!valsWrap.firstChild) {
        const hint = document.createElement('div');
        hint.className = 'tl-colmenu-empty';
        hint.textContent = 'No matches.';
        valsWrap.appendChild(hint);
      }
    };
    paint('');

    menu.querySelector('[data-f="valsearch"]').addEventListener('input', (e) => paint(e.target.value));

    // Copy visible values — iterates the currently-rendered checkbox
    // rows (post search filter) and copies their values as newline-
    // separated text. Not every checkbox state is preserved across
    // searches; we copy whatever is visible regardless of checked
    // state since the analyst can see it.

    menu.querySelector('[data-act="copyvals"]').addEventListener('click', (e) => {
      e.stopPropagation();
      const rows = valsWrap.querySelectorAll('.tl-colmenu-value input[type=checkbox]');
      const vals = [];
      rows.forEach(cb => { if (cb.dataset.val != null) vals.push(cb.dataset.val); });
      if (!vals.length) return;
      this._copyToClipboard(vals.join('\n'));
      if (this._app && typeof this._app._toast === 'function') {
        this._app._toast(`Copied ${vals.length.toLocaleString()} value${vals.length === 1 ? '' : 's'} from "${name}"`, 'info');
      }
    });

    // Keep liveState in sync when the user toggles individual checkboxes.
    // Delegated on the wrapper so dynamically-created checkboxes after
    // paint() re-renders are covered without per-element listeners.
    valsWrap.addEventListener('change', (e) => {
      const cb = e.target;
      if (cb.type === 'checkbox' && cb.dataset.val != null) {
        liveState.set(cb.dataset.val, cb.checked);
      }
    });

    // Enter in either text input → Apply and close (mirrors the pattern
    // in _openAddSusPopover). Gives keyboard-driven analysts the
    // expected submit-on-Enter UX without reaching for the button.
    const applyBtn = menu.querySelector('[data-act="apply"]');
    menu.querySelector('[data-f="contains"]').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); applyBtn.click(); }
    });
    menu.querySelector('[data-f="valsearch"]').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); applyBtn.click(); }
    });

    // All / None affect only the currently visible (search-filtered)
    // checkboxes — so the user can search for "bob", click None to
    // deselect just the bob values, then search for something else and
    // those deselections persist in liveState across paint() calls.
    menu.querySelector('[data-act="selall"]').addEventListener('click', () => {
      valsWrap.querySelectorAll('input[type=checkbox]').forEach(cb => {
        cb.checked = true;
        liveState.set(cb.dataset.val, true);
      });
    });
    menu.querySelector('[data-act="selnone"]').addEventListener('click', () => {
      valsWrap.querySelectorAll('input[type=checkbox]').forEach(cb => {
        cb.checked = false;
        liveState.set(cb.dataset.val, false);
      });
    });
    // The `Use as Timestamp` button is now conditional (see `showTimeBtn`
    // above — hidden when the column doesn't parse as timestamps / numbers,
    // and on the already-selected timestamp column). Null-guard the wire
    // up; without this, if the button isn't rendered the following
    // `querySelector(...).addEventListener` throws mid-handler and kills
    // every subsequent listener wire-up in this menu — including the
    // value-search <input>, which is how the user most often discovers it.
    const timeColBtn = menu.querySelector('[data-act="timecol"]');
    if (timeColBtn) timeColBtn.addEventListener('click', () => {
      this._timeCol = colIdx;
      this._els.timeColSelect.value = String(colIdx);
      this._parseAllTimestamps();
      this._dataRange = this._computeDataRange();
      this._window = null;
      this._recomputeFilter();
      this._scheduleRender(['chart', 'scrubber', 'grid', 'columns', 'chips']);
      this._closePopover();
    });
    menu.querySelector('[data-act="stackcol"]').addEventListener('click', () => {
      this._stackCol = colIdx;
      this._buildStableStackColorMap();
      this._els.stackColSelect.value = String(colIdx);
      this._scheduleRender(['chart', 'grid', 'columns']);
      this._closePopover();
    });
    menu.querySelector('[data-act="extract"]').addEventListener('click', () => {
      this._closePopover();
      this._openExtractionDialog(colIdx, 'manual');
    });
    menu.querySelector('[data-act="autopivot"]').addEventListener('click', () => {
      this._closePopover();
      this._autoPivotFromColumn(colIdx);
    });
    const removeExtractBtn = menu.querySelector('[data-act="removeExtract"]');
    if (removeExtractBtn) removeExtractBtn.addEventListener('click', () => {
      this._removeExtractedCol(colIdx);
      this._closePopover();
    });
    // 🌍 Enrich IP — bypass the IPv4-detection threshold AND the skip
    // heuristic for this specific column. Fires every wired provider
    // (`this._app.geoip` and/or `this._app.geoipAsn`); the mixin's
    // per-source-col + per-kind dedup means a click on an already-
    // enriched column is a no-op.
    const geoipBtn = menu.querySelector('[data-act="geoip"]');
    if (geoipBtn) geoipBtn.addEventListener('click', () => {
      this._closePopover();
      if (typeof this._runGeoipEnrichment === 'function') {
        this._runGeoipEnrichment({ forceCol: colIdx });
      }
    });
    menu.querySelector('[data-act="reset"]').addEventListener('click', () => {
      // Strip every top-level clause targeting this column from the
      // query AST. Sus marks aren't query-bar clauses, so they're
      // unaffected — matches the old `c.op !== 'sus'` carve-out.
      this._queryReplaceAllForCol(colIdx);
      this._closePopover();
    });
    menu.querySelector('[data-act="apply"]').addEventListener('click', () => {
      // Contains
      const containsText = menu.querySelector('[data-f="contains"]').value.trim();
      this._addContainsChipsReplace(colIdx, containsText);
      // Eq set — read from `liveState` (all items, not just the
      // currently visible DOM) so values hidden by Search Values
      // aren't silently dropped. Pick the shorter representation
      // (`col IN (…)` vs `col NOT IN (…)`) so unchecking one value
      // out of 200 doesn't emit a 199-value IN list. NOT IN is
      // safe when the distinct set is complete, or when the user
      // started from an all-pass / NOT IN baseline (unchecking
      // means "exclude these" and hidden values should pass). NOT
      // IN is blocked only when a positive IN whitelist was active
      // — the user explicitly chose a subset and values beyond the
      // cap were never included.
      const entries = Array.from(liveState.entries());
      const allChecked = entries.length > 0 && entries.every(([, v]) => v);
      const noneChecked = entries.length > 0 && entries.every(([, v]) => !v);
      if (allChecked) {
        // "All selected" → no eq chip narrowing needed.
        this._replaceEqChipsForCol(colIdx, []);
      } else if (noneChecked) {
        // "None" → rarely useful, but treat as excluding all — user probably
        // means clear + contains only.
        this._replaceEqChipsForCol(colIdx, []);
      } else {
        const checked = entries.filter(([, v]) => v).map(([k]) => k);
        const unchecked = entries.filter(([, v]) => !v).map(([k]) => k);
        // NOT IN is always safe when the full distinct set is known.
        // When the set was truncated (cap exceeded), NOT IN is still
        // correct if the user started from an all-pass or NOT IN
        // baseline — unchecked items are exclusions and hidden values
        // beyond the cap should continue to pass through, matching the
        // prior "no filter" / "NOT IN" semantic.  Only when the
        // baseline was a positive IN whitelist do we stick with IN,
        // because the user explicitly selected a subset and values
        // beyond the cap were never included.
        const canNegate = !items.truncated || initialAll || initialAllMinusNe;
        if (canNegate && unchecked.length < checked.length) {
          this._queryReplaceNotInForCol(colIdx, unchecked);
        } else {
          this._replaceEqChipsForCol(colIdx, checked);
        }
      }
      this._closePopover();
    });

    // Anchor below the column head
    const rect = anchor.getBoundingClientRect();
    this._positionFloating(menu, rect.left, rect.bottom + 2);
    document.body.appendChild(menu);
    this._openPopover = menu;
    menu.querySelector('[data-f="contains"]').focus();
  },

  _closeDialog() {
    if (this._openDialog && this._openDialog.parentNode) {
      this._openDialog.parentNode.removeChild(this._openDialog);
    }
    this._openDialog = null;
  },

  // ── Extraction dialog (Smart scan + Regex + Clicker tabs) ────────────────
  _openExtractionDialog(preselectCol, defaultTab) {
    this._closePopover();
    this._closeDialog();
    const dlg = this._openDialog = document.createElement('div');
    dlg.className = 'tl-dialog';
    dlg.innerHTML = `
      <div class="tl-dialog-card tl-dialog-extract">
        <header class="tl-dialog-head">
          <strong>ƒx Extract values</strong>
          <span class="tl-dialog-spacer"></span>
          ${this._extractedCols.length
        ? `<button class="tl-tb-btn tl-tb-btn-danger" data-act="clear-all" title="Remove all extracted columns">✕ Clear all extracted (${this._extractedCols.length})</button>`
        : ''}
          <button class="tl-dialog-close" type="button" aria-label="Close">✕</button>
        </header>
        <div class="tl-dialog-tabs">
          <button class="tl-dialog-tab tl-dialog-tab-active" data-tab="auto">Auto</button>
          <button class="tl-dialog-tab" data-tab="manual">Manual</button>
        </div>
        <div class="tl-dialog-body">
          <section class="tl-dialog-pane tl-dialog-pane-auto">
            <div class="tl-auto-toolbar">
              <div class="tl-auto-bulk">
                <button type="button" class="tl-tb-btn" data-act="sel-all" title="Select all visible">✓ All</button>
                <button type="button" class="tl-tb-btn" data-act="sel-none" title="Deselect all visible">☐ None</button>
                <button type="button" class="tl-tb-btn" data-act="sel-invert" title="Invert selection (visible)">↔ Invert</button>
              </div>
              <span class="tl-auto-count" aria-live="polite">0 of 0 selected</span>
              <div class="tl-auto-facet" role="tablist">
                <button type="button" class="tl-auto-facet-btn tl-auto-facet-active" data-facet="all">All</button>
                <button type="button" class="tl-auto-facet-btn" data-facet="url" title="URL-shaped values">🌐 URL</button>
                <button type="button" class="tl-auto-facet-btn" data-facet="host" title="Hostnames">🖥 Host</button>
                <button type="button" class="tl-auto-facet-btn" data-facet="kv" title="Pipe-delimited Key=Value fields">🪵 Key=Value</button>
                <button type="button" class="tl-auto-facet-btn" data-facet="json" title="Generic JSON leaves">📝 JSON</button>
              </div>
              <input type="text" class="tl-auto-filter" placeholder="Search proposals…  ( / )" aria-label="Search proposals" spellcheck="false" autocomplete="off">
              <select class="tl-auto-sort" title="Sort proposals">
                <option value="match-desc">Match % ↓</option>
                <option value="match-asc">Match % ↑</option>
                <option value="column">Column</option>
                <option value="kind">Kind</option>
                <option value="name">Name</option>
              </select>
            </div>
            <details class="tl-auto-about"><summary>What does this do?</summary><p class="tl-dialog-muted">Scans the first 200 rows of every non-empty column for JSON leaves, pipe-delimited <code>Key=Value</code> fields (EVTX Event Data), and URL/hostname values. On browser-history SQLite the <code>url</code> column also yields host / path / query parts. Tick a row to turn it into a new column.</p></details>
            <div class="tl-auto-body">
              <div class="tl-auto-empty">Running auto-scan…</div>
            </div>
            <footer class="tl-dialog-foot">
              <button class="tl-tb-btn" data-act="auto-rescan">Rescan</button>
              <span class="tl-dialog-spacer"></span>
              <button class="tl-tb-btn tl-tb-btn-primary" data-act="auto-extract" disabled>⚡ Extract selected</button>
            </footer>
          </section>

          <section class="tl-dialog-pane tl-dialog-pane-manual" style="display:none">
            <div class="tl-regex-grid">
              <label class="tl-field">
                <span class="tl-field-label">Column</span>
                <select class="tl-field-select" data-field="col"></select>
              </label>
              <label class="tl-field">
                <span class="tl-field-label">Preset</span>
                <select class="tl-field-select" data-field="preset">
                  <option value="-1">— custom —</option>
                </select>
              </label>
              <label class="tl-field tl-field-wide">
                <span class="tl-field-label">Name</span>
                <input type="text" class="tl-field-select" data-field="name" placeholder="auto">
              </label>
            </div>
            <p class="tl-dialog-muted">Click a token or drag-select a substring in any sample row below — Loupe infers a regex that captures the same slot on every row and fills the Pattern field automatically. Or write a Pattern directly. The picked value is classified (digits, hex, IP, UUID, hostname, path, quoted, …) and surrounding characters become anchors.</p>
            <div class="tl-clicker-samples" aria-label="Sample rows — click a token to pick"></div>
            <div class="tl-regex-grid">
              <label class="tl-field tl-field-wide">
                <span class="tl-field-label">Pattern</span>
                <input type="text" class="tl-field-select" data-field="pattern" spellcheck="false" placeholder="e.g. \\b\\d+\\b">
              </label>
              <label class="tl-field">
                <span class="tl-field-label">Flags</span>
                <input type="text" class="tl-field-select" data-field="flags" value="i" maxlength="8" spellcheck="false">
              </label>
              <label class="tl-field">
                <span class="tl-field-label">Group</span>
                <input type="number" class="tl-field-select" data-field="group" value="0" min="0" max="9">
              </label>
            </div>
            <details class="tl-regex-cheatsheet">
              <summary>Regex cheatsheet</summary>
              <div class="tl-regex-hint">
                <code>\\b</code> word boundary · <code>\\d+</code> digits · <code>[a-z]+</code> letters ·
                <code>(...)</code> capture group · <code>\\.</code> literal dot · flags: <code>i</code> case-insensitive.
                Capture group <code>0</code> is the full match; <code>1</code> is the first <code>(...)</code>.
                <br>⚠ <code>|</code> is alternation — to match a literal pipe, escape it as <code>\\|</code>
                (e.g. in an EVTX Event Data cell, write <code>DestAddress=(.+?) \\|</code>, not <code>DestAddress=(.+?) |</code>).
              </div>
            </details>
            <div class="tl-regex-preview">
              <div class="tl-regex-status">Pick a value above or enter a pattern to preview.</div>
              <div class="tl-regex-samples"></div>
            </div>
            <footer class="tl-dialog-foot">
              <button class="tl-tb-btn" data-act="regex-test">Test</button>
              <span class="tl-dialog-spacer"></span>
              <button class="tl-tb-btn tl-tb-btn-primary" data-act="regex-extract">⚡ Extract</button>
            </footer>
          </section>
        </div>
      </div>
    `;
    document.body.appendChild(dlg);

    // Tabs — two panes: Auto / Manual. The Manual tab is a single unified
    // pane that combines Clicker (sample rows) + Regex (Pattern/Flags/Group)
    // wiring, sharing one Column dropdown, one Name field, and one preview.
    const tabs = dlg.querySelectorAll('.tl-dialog-tab');
    const panes = {
      auto: [dlg.querySelector('.tl-dialog-pane-auto')],
      manual: [dlg.querySelector('.tl-dialog-pane-manual')],
    };
    const _showTab = (which) => {
      tabs.forEach(x => x.classList.remove('tl-dialog-tab-active'));
      const btn = dlg.querySelector(`.tl-dialog-tab[data-tab="${which}"]`);
      if (btn) btn.classList.add('tl-dialog-tab-active');
      for (const [k, els] of Object.entries(panes)) {
        const vis = (k === which);
        for (const el of els) { if (el) el.style.display = vis ? '' : 'none'; }
      }
    };
    tabs.forEach(t => t.addEventListener('click', () => _showTab(t.dataset.tab)));
    // Activate requested tab (default = auto)
    _showTab(defaultTab && panes[defaultTab] ? defaultTab : 'auto');

    // Close
    const close = () => this._closeDialog();
    dlg.querySelector('.tl-dialog-close').addEventListener('click', close);
    dlg.addEventListener('click', (e) => { if (e.target === dlg) close(); });

    // Keyboard shortcuts:
    //   /      → focus the Smart-scan filter input (only when that tab
    //            is active; inside the filter itself it's a literal char).
    //   Space  → toggle the checkbox on the row currently hovered under
    //            the pointer (label-wide hit target).
    //   Enter  → trigger the active tab's primary action (Extract).
    // Esc is handled by the global `_onDocKey` listener (closes popover
    // or dialog).
    dlg.addEventListener('keydown', (e) => {
      if (e.key === '/') {
        const autoTab = dlg.querySelector('.tl-dialog-pane-auto');
        const inFilter = e.target && e.target.classList
          && e.target.classList.contains('tl-auto-filter');
        if (autoTab && autoTab.style.display !== 'none' && !inFilter
          && !(e.target && /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName))) {
          const f = dlg.querySelector('.tl-auto-filter');
          if (f) { e.preventDefault(); f.focus(); f.select(); }
          return;
        }
      }
      if (e.key === 'Enter') {
        // Don't steal Enter from text inputs (Regex-tab fields submit
        // via their own wiring, and multi-line textareas would be
        // sabotaged). Only act when focus is on a button / select or
        // the dialog chrome itself.
        const tag = e.target && e.target.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA') return;
        const activeTab = dlg.querySelector('.tl-dialog-tab.tl-dialog-tab-active');
        const which = activeTab ? activeTab.dataset.tab : 'auto';
        if (which === 'auto') {
          const btn = dlg.querySelector('[data-act="auto-extract"]');
          if (btn && !btn.disabled) { e.preventDefault(); btn.click(); }
        } else if (which === 'manual') {
          // Unified Manual tab — single Extract button covers both
          // clicker-inferred and hand-written patterns.
          const rBtn = dlg.querySelector('[data-act="regex-extract"]');
          if (rBtn) { e.preventDefault(); rBtn.click(); }
        }
      }
    });

    // Clear-all (only rendered when _extractedCols.length > 0)
    const clearAllBtn = dlg.querySelector('[data-act="clear-all"]');
    if (clearAllBtn) {
      clearAllBtn.addEventListener('click', () => {
        if (this._clearAllExtractedCols()) close();
      });
    }

    // ── Auto tab wiring
    const autoPane = dlg.querySelector('.tl-dialog-pane-auto');
    const autoBody = dlg.querySelector('.tl-auto-body');
    const autoExtractBtn = dlg.querySelector('[data-act="auto-extract"]');
    const autoCount = dlg.querySelector('.tl-auto-count');
    const autoFilter = dlg.querySelector('.tl-auto-filter');
    const autoSort = dlg.querySelector('.tl-auto-sort');
    const autoFacetBtns = dlg.querySelectorAll('.tl-auto-facet-btn');
    const autoToolbar = dlg.querySelector('.tl-auto-toolbar');

    // "Will create:" preview strip — injected between body and footer.
    const previewStrip = document.createElement('div');
    previewStrip.className = 'tl-dialog-preview';
    previewStrip.innerHTML = `<span class="tl-dialog-preview-label">Will create:</span><span class="tl-dialog-preview-list">(none selected)</span>`;
    autoBody.parentNode.insertBefore(previewStrip, autoBody.nextSibling);
    const previewListEl = previewStrip.querySelector('.tl-dialog-preview-list');

    // Facet → set of proposal kinds
    const FACET_KINDS = {
      all: null,
      url: new Set(['text-url', 'json-url', 'url-part']),
      host: new Set(['text-host', 'json-host']),
      kv: new Set(['kv-field']),
      json: new Set(['json-leaf']),
    };
    let currentFacet = 'all';

    // State used by the toolbar filters + renderer.
    //   _allProposals — every proposal from the last `_autoExtractScan()` pass.
    //   _visibleIndices — indices into `_allProposals` that pass the current
    //                     facet + search filter (the rows the list renders).
    //   _selection — stable Set<origIdx> of CHECKED proposals. Survives
    //                facet / search / sort changes, so a tick the analyst
    //                made before typing into the search box stays ticked
    //                once the row is re-revealed. Counts + preview +
    //                Extract all read from this Set, never from DOM
    //                checkboxes, so hidden-but-selected rows are honoured.
    let _allProposals = [];
    let _visibleIndices = [];
    const _selection = new Set();

    const countMatches = (kind) => {
      if (!_allProposals.length) return 0;
      const set = FACET_KINDS[kind];
      if (!set) return _allProposals.length;
      let n = 0;
      for (const p of _allProposals) if (set.has(p.kind)) n++;
      return n;
    };

    const updateFacetCounts = () => {
      autoFacetBtns.forEach(b => {
        const f = b.dataset.facet;
        const base = b.dataset.baseLabel || b.textContent;
        if (!b.dataset.baseLabel) b.dataset.baseLabel = base;
        const n = countMatches(f);
        b.textContent = (b.dataset.baseLabel) + ' (' + n + ')';
      });
    };

    const sortProposals = (arr, mode) => {
      const kindOrder = { 'text-url': 0, 'url-part': 1, 'json-url': 2, 'text-host': 3, 'json-host': 4, 'kv-field': 5, 'json-leaf': 6 };
      const nameOf = (p) => p.proposedName || '';
      const colOf = (p) => this.columns[p.sourceCol] || '';
      const cmp = {
        'match-desc': (a, b) => (b.matchPct || 0) - (a.matchPct || 0),
        'match-asc': (a, b) => (a.matchPct || 0) - (b.matchPct || 0),
        'column': (a, b) => colOf(a).localeCompare(colOf(b)) || (b.matchPct - a.matchPct),
        'kind': (a, b) => (kindOrder[a.kind] || 9) - (kindOrder[b.kind] || 9) || (b.matchPct - a.matchPct),
        'name': (a, b) => nameOf(a).localeCompare(nameOf(b)),
      }[mode] || ((a, b) => (b.matchPct || 0) - (a.matchPct || 0));
      return arr.slice().sort(cmp);
    };

    const updatePreview = () => {
      // Read from the stable _selection Set so hidden-but-ticked proposals
      // (e.g. after the user narrows the search box) still appear in the
      // "Will create:" strip and get extracted on submit.
      const picked = [];
      for (const i of _selection) {
        if (_allProposals[i]) picked.push(_allProposals[i].proposedName);
      }
      if (!picked.length) {
        previewListEl.textContent = '(none selected)';
        previewListEl.classList.add('tl-dialog-preview-empty');
      } else {
        previewListEl.classList.remove('tl-dialog-preview-empty');
        const maxShow = 8;
        const head = picked.slice(0, maxShow).map(n => `<span class="tl-dialog-preview-pill">${_tlEsc(n)}</span>`).join('');
        const more = picked.length > maxShow ? ` <span class="tl-dialog-preview-more">+${picked.length - maxShow} more</span>` : '';
        previewListEl.innerHTML = head + more;
      }
    };

    const updateCount = () => {
      // "N of V selected" where V is the number of currently-visible rows
      // (so search narrows the denominator) and N is the total stable
      // selection size (so ticks survive searching / faceting).
      const visN = _visibleIndices.length;
      const selN = _selection.size;
      autoCount.textContent = `${selN} of ${visN} selected`;
      autoExtractBtn.disabled = selN === 0;
      autoExtractBtn.textContent = selN > 0 ? `Extract ${selN} selected` : 'Extract selected';
    };


    const renderList = () => {
      if (!_allProposals.length) {
        autoBody.innerHTML = '<div class="tl-auto-empty">No extractable values found in the first 200 rows.</div>';
        _visibleIndices = [];
        autoExtractBtn.disabled = true;
        updateCount();
        updatePreview();
        return;
      }
      const facetSet = FACET_KINDS[currentFacet];
      const filterTxt = (autoFilter.value || '').toLowerCase();
      // Build visible list, preserving original indices for checkbox mapping.
      const sorted = sortProposals(_allProposals, autoSort.value);
      const origIndexOf = new Map(_allProposals.map((p, i) => [p, i]));
      _visibleIndices = [];
      const list = document.createElement('div');
      list.className = 'tl-auto-list';
      for (const p of sorted) {
        if (facetSet && !facetSet.has(p.kind)) continue;
        if (filterTxt) {
          const hay = (p.proposedName + ' ' + (this.columns[p.sourceCol] || '') + ' ' + (p.sample || '')).toLowerCase();
          if (hay.indexOf(filterTxt) === -1) continue;
        }
        const origI = origIndexOf.get(p);
        _visibleIndices.push(origI);
        const row = document.createElement('label');
        row.className = 'tl-auto-row';
        row.dataset.i = String(origI);
        const colName = this.columns[p.sourceCol] || `(col ${p.sourceCol + 1})`;
        // Checked state is driven by the stable _selection Set, NOT the
        // proposal's preselect hint — the hint only seeds _selection in
        // runAuto(). After seeding, survivorship across search / facet /
        // sort is absolute: a row's tick state is _selection.has(origI).
        const isChecked = _selection.has(origI);
        const samplePreview = p.sample || '';
        row.innerHTML = `
          <input type="checkbox" data-i="${origI}" ${isChecked ? 'checked' : ''}>

          <span class="tl-auto-kind" data-kind="${_tlEsc(p.kind)}">${_tlEsc(p.kindLabel)}</span>
          <span class="tl-auto-sample" title="${_tlEsc(samplePreview)}">${_tlEsc(this._ellipsis(samplePreview, 90))}</span>
          <span class="tl-auto-col" title="${_tlEsc(colName)}">${_tlEsc(colName)}</span>
          <span class="tl-auto-rate" title="match rate in sample">${(p.matchPct || 0).toFixed(0)}%</span>
        `;
        list.appendChild(row);
      }
      if (!_visibleIndices.length) {
        autoBody.innerHTML = '<div class="tl-auto-empty">No proposals match the current filter.</div>';
      } else {
        autoBody.innerHTML = '';
        autoBody.appendChild(list);
      }
      // Always start scrolled to the top so the first proposals are visible
      // immediately on open / rescan / facet-or-search change. Without this,
      // analysts saw a partially-scrolled list on entry which was jarring.
      autoBody.scrollTop = 0;
      updateCount();
      updatePreview();
    };

    // Bulk select buttons — operate on the *visible* rows only, but mutate
    // the stable `_selection` Set so ticks persist if the user subsequently
    // narrows the search box / switches facet. We re-render so the DOM
    // checkboxes pick up the new ticked state from `_selection.has()`.
    autoToolbar.querySelector('[data-act="sel-all"]').addEventListener('click', () => {
      for (const i of _visibleIndices) _selection.add(i);
      renderList();
    });
    autoToolbar.querySelector('[data-act="sel-none"]').addEventListener('click', () => {
      for (const i of _visibleIndices) _selection.delete(i);
      renderList();
    });
    autoToolbar.querySelector('[data-act="sel-invert"]').addEventListener('click', () => {
      for (const i of _visibleIndices) {
        if (_selection.has(i)) _selection.delete(i);
        else _selection.add(i);
      }
      renderList();
    });
    autoFacetBtns.forEach(b => b.addEventListener('click', () => {
      autoFacetBtns.forEach(x => x.classList.remove('tl-auto-facet-active'));
      b.classList.add('tl-auto-facet-active');
      currentFacet = b.dataset.facet;
      renderList();
    }));
    let filterTimer = 0;
    autoFilter.addEventListener('input', () => {
      clearTimeout(filterTimer);
      filterTimer = setTimeout(renderList, 80);
    });
    autoSort.addEventListener('change', renderList);
    autoBody.addEventListener('change', (e) => {
      if (e.target && e.target.type === 'checkbox') {
        const origI = +e.target.dataset.i;
        if (Number.isFinite(origI)) {
          if (e.target.checked) _selection.add(origI);
          else _selection.delete(origI);
        }
        updateCount();
        updatePreview();
      }
    });

    const runAuto = () => {
      autoBody.innerHTML = '<div class="tl-auto-empty">Running auto-scan…</div>';
      autoExtractBtn.disabled = true;
      setTimeout(() => {
        _allProposals = this._autoExtractScan() || [];
        autoExtractBtn._proposals = _allProposals;
        // Seed the stable selection from each proposal's preselect hint.
        // Subsequent ticks/unticks mutate this Set directly; facet/search/
        // sort changes only affect `_visibleIndices`, never `_selection`.
        _selection.clear();
        for (let i = 0; i < _allProposals.length; i++) {
          if (_allProposals[i].preselect !== false) _selection.add(i);
        }
        updateFacetCounts();
        renderList();
      }, 10);
    };
    dlg.querySelector('[data-act="auto-rescan"]').addEventListener('click', runAuto);

    autoExtractBtn.addEventListener('click', () => {
      const props = autoExtractBtn._proposals || [];
      // Extract every ticked proposal from the stable `_selection` Set —
      // NOT from the DOM, so rows currently hidden by search/facet are
      // still honoured.
      const pick = [];
      for (const i of _selection) {
        const p = props[i];
        if (p) pick.push(p);
      }
      if (!pick.length) return;
      const before = this._extractedCols.length;

      // Group picks by source column so we can decode each source CSV
      // column ONCE and reuse the materialised string array for every
      // proposal in the group. Without this, N JSON-leaf proposals on
      // the same column trigger N × rowCount calls into
      // `_cellAt` → `RowStore.getCell` → `_decodeAsciiSlice`. On a
      // 100k-row CSV with a JSON column that exposes ~10 leaves, that
      // was ~5 s of main-thread blocking on click (profile evidence:
      // `_decodeAsciiSlice` ~18 s of a 21 s click). Mirrors the
      // `applyStep` strategy in `timeline-view-autoextract.js` (apply
      // pump for the silent best-effort pass) — the same `srcValues`
      // contract is honoured by `_addJsonExtractedColNoRender` and
      // `_addRegexExtractNoRender` (both fall back to `_cellAt` when
      // the cache is absent).
      //
      // Iteration order: insertion-ordered Map preserves the user's
      // original tick order across groups, and within each bucket we
      // preserve the order in which `pick` saw them. The dedup logic
      // inside the helpers is independent of order, so the final
      // column set is identical to the legacy un-grouped path.
      const bySource = new Map();
      for (const p of pick) {
        if (!bySource.has(p.sourceCol)) bySource.set(p.sourceCol, []);
        bySource.get(p.sourceCol).push(p);
      }

      // Suppress per-call regex persistence for the duration of the
      // apply loop — `_addRegexExtractNoRender` would otherwise
      // serialise + write localStorage once per regex-kind pick.
      // Cleared in the `finally` so an exception inside the loop can't
      // leave the flag stuck on the view (which would silently break
      // future Manual-tab extracts that DO want their persist call).
      this._suppressRegexPersist = true;
      let sawRegex = false;
      try {
        for (const [sourceCol, bucket] of bySource) {
          // Materialise the source column once for this group. The
          // auto-extract scanner (`_autoExtractScan`) iterates only
          // base columns (`this._baseColumns.length`) when emitting
          // proposals, so `sourceCol` is GUARANTEED to be in
          // `[0, baseLen)`. We can therefore call `store.getCell`
          // directly and skip the `_cellAt` → `dataset.cellAt`
          // dispatch hop, shaving the per-cell tail-call + nullable
          // checks off a 100k-iteration hot loop. (The extracted-col
          // branch in `cellAt` is unreachable for any `sourceCol`
          // that came from `_autoExtractScan`.)
          const n = this.store.rowCount;
          const srcValues = new Array(n);
          const store = this.store;
          for (let i = 0; i < n; i++) srcValues[i] = store.getCell(i, sourceCol);
          for (const p of bucket) {
            if (p.kind !== 'json-url' && p.kind !== 'json-host' && p.kind !== 'json-leaf') {
              sawRegex = true;
            }
            // `_applyAutoProposal` does the same per-kind dispatch as
            // the silent best-effort pump (json-* → JSON helper;
            // text-* / kv-field / url-part → regex helper with the
            // right pattern / flags / group / trim) and threads
            // `srcValues` through to both helpers. Reusing it keeps
            // the dialog and the silent pump on a single code path,
            // so a future kind addition only needs to touch
            // `_applyAutoProposal`.
            try {
              this._applyAutoProposal(p, srcValues);
            } catch (e) {
              if (this._app && this._app.debug && typeof console !== 'undefined') {
                console.warn('[loupe] _applyAutoProposal threw in dialog apply:', e, 'proposal:', p);
              }
            }
          }
        }
      } finally {
        this._suppressRegexPersist = false;
      }
      // One persist for every regex-kind pick combined.
      if (sawRegex) {
        try { this._persistRegexExtracts(); } catch (_) { /* persistence is additive */ }
      }

      const added = this._extractedCols.length - before;
      const skipped = pick.length - added;
      if (this._app && this._app._toast) {
        if (added && skipped) this._app._toast(`Added ${added} column${added === 1 ? '' : 's'}; skipped ${skipped} duplicate${skipped === 1 ? '' : 's'}`, 'info');
        else if (added) this._app._toast(`Added ${added} column${added === 1 ? '' : 's'}`, 'info');
        else if (skipped) this._app._toast(`Skipped ${skipped} duplicate${skipped === 1 ? '' : 's'} — already extracted`, 'info');
      }
      // Hint the next 'columns' render task that the only structural
      // change is `added` new trailing extracted columns. The cold-
      // cache branch in `timeline-view.js`'s columns-render task
      // reads this and computes stats for the new cols synchronously
      // (paint cards immediately) while scheduling the base-col
      // stats async — eliminates the ~1.4 s blocking
      // `_computeColumnStatsAsync` sweep that dominated the post-
      // click async tail in the 100k-row repro. Consumed exactly
      // once; the render task clears it so a future cold cache
      // (e.g. user changes filter) goes back to the full sweep.
      if (added > 0) this._colStatsExtractAdvance = added;
      this._rebuildExtractedStateAndRender();
      close();
    });
    runAuto();

    // ── Manual tab wiring (unified Clicker + Regex)
    // The Manual tab is a single pane that shares one Column dropdown,
    // one Name field, and one preview between the click-to-pick sample
    // rows and the hand-authored Pattern/Flags/Group fields. Picking a
    // token / drag-selecting in a sample row infers a regex which is
    // written directly into the Pattern field — there is no separate
    // "Edit in Regex tab" step. The single Extract button at the foot
    // saves whatever pattern is currently in the form.
    const clickerSamples = dlg.querySelector('.tl-clicker-samples');

    // Token classifier — inspects a picked substring and returns a regex

    // fragment that matches the same shape. Ordered from most specific
    // to most general so a UUID doesn't degenerate to `[0-9a-f]+`.
    const _classifyPick = (s) => {
      if (!s) return { pattern: '\\S+', label: 'text' };
      if (/^\d+$/.test(s)) return { pattern: '\\d+', label: 'digits' };
      if (/^[+-]?\d+\.\d+$/.test(s)) return { pattern: '[+-]?\\d+\\.\\d+', label: 'decimal' };
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) {
        return { pattern: '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', label: 'UUID' };
      }
      if (/^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(s)) {
        return { pattern: '(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}', label: 'IPv4' };
      }
      if (/^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(s)) {
        return { pattern: '(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}', label: 'MAC' };
      }
      if (/^[0-9a-f]{32}$/i.test(s)) return { pattern: '[0-9a-f]{32}', label: 'MD5' };
      if (/^[0-9a-f]{40}$/i.test(s)) return { pattern: '[0-9a-f]{40}', label: 'SHA1' };
      if (/^[0-9a-f]{64}$/i.test(s)) return { pattern: '[0-9a-f]{64}', label: 'SHA256' };
      if (/^[0-9a-f]+$/i.test(s) && s.length >= 4) return { pattern: '[0-9a-f]+', label: 'hex' };
      if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/.test(s)) {
        return { pattern: '\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?', label: 'ISO timestamp' };
      }
      if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return { pattern: '\\d{4}-\\d{2}-\\d{2}', label: 'date' };
      if (/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(s)) {
        return { pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}', label: 'email' };
      }
      if (/^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(s)) {
        return { pattern: '[a-z][a-z0-9+.\\-]*:\\/\\/\\S+', label: 'URL' };
      }
      if (/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(s)) {
        return { pattern: '(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}', label: 'hostname' };
      }
      if (/^[A-Za-z]:\\/.test(s)) return { pattern: '[A-Za-z]:\\\\[^\\s"<>|?*]+', label: 'Windows path' };
      if (/^\/[^\s]+$/.test(s)) return { pattern: '\\/[^\\s]+', label: 'POSIX path' };
      if (/^[A-Za-z_][\w-]*$/.test(s)) return { pattern: '[A-Za-z_][\\w-]*', label: 'identifier' };
      if (/^\S+$/.test(s)) return { pattern: '\\S+', label: 'token' };
      return { pattern: '.+?', label: 'text' };
    };

    // Regex-escape a literal anchor. Newlines collapse to \n (so
    // multi-line cells don't paste a raw CR/LF into the pattern).
    const _escLiteral = (s) => String(s)
      .replace(/\\/g, '\\\\')
      .replace(/[.*+?^${}()|[\]]/g, '\\$&')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');

    // Collect up to 30 non-empty samples for the pick pane + anchor check.
    const _collectClickerSamples = (colIdx) => {
      const out = [];
      const cap = Math.min(this.store.rowCount, 400);
      for (let i = 0; i < cap && out.length < 30; i++) {
        const v = this._cellAt(i, colIdx);
        if (v) out.push(v);
      }
      return out;
    };

    // Generalise a left anchor: keep trimming from the LEFT (so the
    // anchor stays adjacent to the pick) until ≥ 70 % of samples match
    // `escAnchor + tokenPattern` somewhere. Empty anchor = use `\b`.
    const _generaliseAnchor = (rawAnchor, tokenPattern, samples, side) => {
      if (!rawAnchor) return side === 'left' ? '\\b' : '\\b';
      // Start from the full raw anchor and shrink.
      let anchor = rawAnchor;
      const threshold = Math.max(1, Math.ceil(samples.length * 0.7));
      // Try full → progressively shorter. For left side, drop chars from
      // the start; for right, drop from the end.
      while (anchor.length > 0) {
        const escAnchor = _escLiteral(anchor);
        let re;
        try {
          /* safeRegex: builtin */
          re = side === 'left'
            ? new RegExp(escAnchor + '(' + tokenPattern + ')', 'i')
            : new RegExp('(' + tokenPattern + ')' + escAnchor, 'i');
        } catch (_) { break; }
        let hits = 0;
        for (const s of samples) if (re.test(s)) hits++;
        if (hits >= threshold) return escAnchor;
        anchor = side === 'left' ? anchor.slice(1) : anchor.slice(0, -1);
      }
      return '\\b';
    };

    // ── Regex / pattern wiring (shared by the unified Manual pane)
    const colSel = dlg.querySelector('[data-field="col"]');
    colSel.innerHTML = '';
    for (let i = 0; i < this._baseColumns.length; i++) {
      const o = document.createElement('option');
      o.value = String(i); o.textContent = this._baseColumns[i] || `(col ${i + 1})`;
      colSel.appendChild(o);
    }
    for (let i = 0; i < this._extractedCols.length; i++) {
      const o = document.createElement('option');
      o.value = String(this._baseColumns.length + i);
      o.textContent = this._extractedCols[i].name + ' ⚡';
      colSel.appendChild(o);
    }
    if (preselectCol != null && preselectCol < this.columns.length) colSel.value = String(preselectCol);

    const presetSel = dlg.querySelector('[data-field="preset"]');
    for (const p of TL_REGEX_PRESETS) {
      const o = document.createElement('option');
      o.value = p.label; o.textContent = p.label; presetSel.appendChild(o);
    }
    const patternEl = dlg.querySelector('[data-field="pattern"]');
    const flagsEl = dlg.querySelector('[data-field="flags"]');
    const groupEl = dlg.querySelector('[data-field="group"]');
    const nameEl = dlg.querySelector('[data-field="name"]');
    const statusEl = dlg.querySelector('.tl-regex-status');
    const samplesEl = dlg.querySelector('.tl-regex-samples');

    // Render the clicker sample rows for the currently-selected column.
    // Each row carries its untruncated text on `_fullText` so `handlePick`
    // can compute pick offsets without re-reading the table.
    const renderClickerSamples = () => {
      const col = parseInt(colSel.value, 10);
      if (!Number.isFinite(col) || col < 0) { clickerSamples.innerHTML = ''; return; }
      const samples = _collectClickerSamples(col);
      clickerSamples.innerHTML = '';
      if (!samples.length) {
        const empty = document.createElement('div');
        empty.className = 'tl-clicker-empty';
        empty.textContent = '(no non-empty values in this column)';
        clickerSamples.appendChild(empty);
        return;
      }
      for (const s of samples) {
        const row = document.createElement('div');
        row.className = 'tl-clicker-row';
        row.textContent = s;
        row._fullText = s;
        clickerSamples.appendChild(row);
      }
    };

    // Pick handler — fires on mouseup inside a `.tl-clicker-row`. Builds a
    // regex from the picked / drag-selected substring + sniffed anchors,
    // writes it directly into the unified Pattern / Flags / Group fields,
    // resets the Preset dropdown to "— custom —", optionally seeds the
    // Name placeholder, then calls `runTest()` so the unified preview
    // updates. The user can fine-tune the pattern by hand and click
    // Extract — there is no separate "Edit in Regex tab" step.
    const handlePick = (rowEl) => {
      if (!rowEl) return;
      const full = rowEl._fullText || rowEl.textContent || '';
      if (!full) return;
      const sel = window.getSelection();
      let picked = '';
      let start = -1;
      if (sel && sel.rangeCount && !sel.isCollapsed) {
        const range = sel.getRangeAt(0);
        if (rowEl.contains(range.startContainer) && rowEl.contains(range.endContainer)) {
          picked = sel.toString();
          start = full.indexOf(picked);
        }
      }
      if (!picked) {
        // Click-only fallback: pick the first whitespace-delimited token.
        const visible = rowEl.textContent || '';
        const m = /\S+/.exec(visible);
        if (m) {
          picked = m[0];
          start = full.indexOf(picked);
        }
      }
      if (!picked) return;
      if (start < 0) start = 0;
      const end = start + picked.length;

      const ANCHOR_MAX = 24;
      let left = full.slice(Math.max(0, start - ANCHOR_MAX), start);
      let right = full.slice(end, end + ANCHOR_MAX);
      const leftWs = left.search(/\s\S*$/);
      if (leftWs >= 0) left = left.slice(leftWs);
      const rightWsEnd = right.search(/\s/);
      if (rightWsEnd > 0) right = right.slice(0, rightWsEnd);
      left = left.replace(/^\s+/, '');
      right = right.replace(/\s+$/, '');

      const cls = _classifyPick(picked);
      const col = parseInt(colSel.value, 10);
      const samples = Number.isFinite(col) ? _collectClickerSamples(col) : [];
      const leftEsc = _generaliseAnchor(left, cls.pattern, samples, 'left');
      const rightEsc = _generaliseAnchor(right, cls.pattern, samples, 'right');
      const inferred = leftEsc + '(' + cls.pattern + ')' + rightEsc;

      patternEl.value = inferred;
      flagsEl.value = 'i';
      groupEl.value = '1';
      if (presetSel) presetSel.value = '-1';

      // Default Name placeholder: "<colName>.<label>" — only set if the
      // user hasn't typed their own name. Keeps the value field empty so
      // the extract handler's `(nameEl.value || '').trim()` fallback to
      // `${colName} (regex)` still applies if the placeholder is rejected.
      const colName = this._baseColumns[col] || `col${col + 1}`;
      if (!nameEl.value.trim()) {
        nameEl.placeholder = `${colName}.${cls.label.replace(/\s+/g, '_')}`;
      }

      runTest();
    };

    clickerSamples.addEventListener('mouseup', (e) => {
      const row = e.target.closest('.tl-clicker-row');
      if (!row) return;
      // Give the browser a tick to finalise the selection before reading it.
      setTimeout(() => handlePick(row), 0);
    });

    presetSel.addEventListener('change', () => {

      const p = TL_REGEX_PRESETS.find(x => x.label === presetSel.value);
      if (p) {
        patternEl.value = p.pattern;
        flagsEl.value = p.flags || '';
        groupEl.value = String(p.group == null ? 0 : p.group);
        nameEl.value = p.label;
      }
    });

    // Detect an UNESCAPED top-level `|` in the pattern — that's alternation,
    // not a literal pipe. The classic footgun: `DestAddress=(.+?) |` reads as
    // the alternation `"DestAddress=(.+?) " OR ""`, so every row matches at
    // offset 0 with group 1 = undefined → the preview's old "matched" count
    // rings 100% while every saved value is empty. We strip out escaped `\|`
    // and character classes `[...]` before scanning so we only warn on the
    // genuine gotcha.
    const _hasTopLevelPipe = (src) => {
      if (!src) return false;
      // Remove escaped metacharacters (notably `\|`).
      let stripped = src.replace(/\\./g, '');
      // Remove character classes `[…]` — `|` inside a class is literal.
      stripped = stripped.replace(/\[[^\]]*\]/g, '');
      return stripped.indexOf('|') !== -1;
    };

    const runTest = () => {
      const pattern = patternEl.value;
      const flags = flagsEl.value;
      if (!pattern) { statusEl.textContent = 'Enter a pattern to preview.'; samplesEl.innerHTML = ''; return; }
      // Cap pattern length to prevent pathologically long inputs from
      // even reaching the engine. 1 KB is plenty for any realistic
      // extractor; anything longer is almost certainly a paste accident.
      if (pattern.length > 1024) {
        statusEl.textContent = 'Pattern too long (>1024 chars). Try anchoring or trimming it.';
        samplesEl.innerHTML = '';
        return;
      }
      const safe = safeRegex(pattern, flags);
      if (!safe.ok) {
        statusEl.textContent = 'Invalid or unsafe regex: ' + safe.error;
        samplesEl.innerHTML = '';
        return;
      }
      const re = safe.regex;
      if (safe.warning) {
        statusEl.textContent = '⚠ Pattern may be slow (' + safe.warning + ') — preview limited to 200 rows.';
      }
      const col = parseInt(colSel.value, 10);
      const gp = Math.max(0, Math.min(9, parseInt(groupEl.value, 10) || 0));
      const sampleMax = 200;
      const N = Math.min(this.store.rowCount, sampleMax);
      // `matched`  — rows where `re.exec()` returned any match at all.
      // `captured` — rows where the selected group `gp` captured a
      //              NON-EMPTY string. This is the count the user actually
      //              cares about: it's what the saved extractor will emit.
      //              Historical bug: the preview reported `matched` alone
      //              as "N/M matched (100%)" and then saved an all-empty
      //              column, because `DestAddress=(.+?) |` matches the
      //              empty alternative at offset 0 for every row and
      //              leaves group 1 undefined.
      let seen = 0, matched = 0, captured = 0, emptyCap = 0;
      const hits = [];
      // Per-preview wall-clock budget. A single `re.exec(v)` call is not
      // preemptible, but bounding the loop and the per-cell input length
      // keeps adversarial patterns from chewing through 200 rows.
      const _previewStart = Date.now();
      const _PREVIEW_BUDGET_MS = 250;
      let _bailedTimeout = false;
      for (let i = 0; i < N; i++) {
        const v = this._cellAt(i, col);
        if (!v) continue;
        seen++;
        // Cap per-cell input length to prevent a single long row from
        // dominating the preview budget.
        const _vCap = v.length > 8192 ? v.slice(0, 8192) : v;
        const m = re.exec(_vCap);
        if ((seen & 0x1F) === 0 && Date.now() - _previewStart > _PREVIEW_BUDGET_MS) {
          _bailedTimeout = true;
          break;
        }
        if (!m) continue;
        matched++;
        const cap = (gp < m.length) ? (m[gp] == null ? '' : m[gp]) : m[0];
        if (cap !== '') {
          captured++;
          if (hits.length < 20) hits.push({ src: v, cap });
        } else {
          emptyCap++;
        }
      }
      const capPct = seen ? (captured * 100 / seen) : 0;
      let status;
      if (matched === captured) {
        status = `${captured}/${seen} sampled rows captured (${capPct.toFixed(0)}%).`;
      } else {
        // The preview that will actually be saved is the non-empty column.
        // Surface both numbers so the user can see the honest gap.
        status = `${captured}/${seen} captured (${capPct.toFixed(0)}%) · ${matched} matched but ${emptyCap} produced empty values (group ${gp} was undefined / empty).`;
      }
      // Pipe-alternation footgun — strong hint that the user meant a
      // literal pipe. Only warn when there's a real discrepancy, to
      // avoid alarming users who intentionally wrote alternations.
      if (_hasTopLevelPipe(pattern) && matched > captured) {
        status += `  ⚠ Your pattern contains "|" (regex alternation). To match a literal pipe character use "\\|".`;
      }
      if (_bailedTimeout) {
        status = `Pattern timed out after ${seen} of ${N} sample rows — try anchoring or bounding it.`;
        statusEl.textContent = status;
        samplesEl.innerHTML = '';
        return;
      }
      statusEl.textContent = status;
      samplesEl.innerHTML = '';
      for (const h of hits) {
        const d = document.createElement('div');
        d.className = 'tl-regex-sample';
        d.innerHTML = `<span class="tl-regex-sample-cap">${_tlEsc(h.cap)}</span><span class="tl-regex-sample-src" title="${_tlEsc(h.src)}">${_tlEsc(this._ellipsis(h.src, 90))}</span>`;
        samplesEl.appendChild(d);
      }
    };
    // Debounce the keystroke-driven preview. Each keystroke previously fired
    // a fresh `runTest` synchronously over up to 200 rows; for adversarial
    // patterns this could stall the dialog. 100 ms is short enough to feel
    // responsive but coalesces typing bursts.
    let _runTestTimer = null;
    const runTestDebounced = () => {
      if (_runTestTimer != null) clearTimeout(_runTestTimer);
      _runTestTimer = setTimeout(() => { _runTestTimer = null; runTest(); }, 100);
    };
    patternEl.addEventListener('input', runTestDebounced);
    flagsEl.addEventListener('input', runTestDebounced);
    groupEl.addEventListener('input', runTestDebounced);
    // Column change repaints the click-to-pick samples (so users see rows
    // from the newly-selected column) and re-runs the regex preview.
    colSel.addEventListener('change', () => { renderClickerSamples(); runTest(); });
    dlg.querySelector('[data-act="regex-test"]').addEventListener('click', runTest);

    dlg.querySelector('[data-act="regex-extract"]').addEventListener('click', () => {
      const pattern = patternEl.value;
      if (!pattern) { if (this._app) this._app._toast('Enter a regex pattern', 'error'); return; }
      if (pattern.length > 1024) {
        if (this._app) this._app._toast('Pattern too long (>1024 chars)', 'error');
        return;
      }
      const safe = safeRegex(pattern, flagsEl.value);
      if (!safe.ok) { if (this._app) this._app._toast('Invalid or unsafe regex: ' + safe.error, 'error'); return; }
      const re = safe.regex;
      // Sample-budget gate: dry-run the compiled regex against up to 1k rows
      // with a 250 ms budget. If it can't keep up on the sample, the full
      // commit (which scans every row in the timeline) certainly can't.
      const sampleN = Math.min(this.store.rowCount, 1000);
      const col = parseInt(colSel.value, 10);
      const sampleStart = Date.now();
      let sampleBail = false;
      for (let i = 0; i < sampleN; i++) {
        const v = this._cellAt(i, col);
        if (!v) continue;
        const _vCap = v.length > 8192 ? v.slice(0, 8192) : v;
        try { re.exec(_vCap); } catch (_e) { /* ignore */ }
        if ((i & 0x3F) === 0 && Date.now() - sampleStart > 250) {
          sampleBail = true;
          break;
        }
      }
      if (sampleBail) {
        if (this._app) this._app._toast('Pattern too slow on sample — refusing to apply across full table', 'error');
        return;
      }
      const gp = Math.max(0, Math.min(9, parseInt(groupEl.value, 10) || 0));
      const colName = this._baseColumns[col] || `(col ${col + 1})`;
      const name = (nameEl.value || '').trim() || `${colName} (regex)`;
      const before = this._extractedCols.length;
      this._addRegexExtractNoRender({
        name, col, pattern, flags: flagsEl.value, group: gp, kind: 'regex',
      });
      if (this._extractedCols.length === before) {
        if (this._app && this._app._toast) this._app._toast('That column is already extracted', 'info');
        return;
      }
      this._rebuildExtractedStateAndRender();
      close();
      void re;  // re already constructed
    });

    // Initial paint of the click-to-pick samples for the preselected
    // column so the unified Manual pane shows rows the moment the dialog
    // opens — without this, samples only appeared after the user changed
    // the Column dropdown.
    renderClickerSamples();
  },

});
