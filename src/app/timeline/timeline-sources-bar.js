'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-sources-bar.js — TimelineView prototype mixin that renders the
// merged-timeline "source chip bar" sitting above the scrubber / chart.
//
// One chip per SourceRecord:
//   [⬤ events.csv · CSV · 12,345 rows · ☑]  [⬤ sec.evtx · EVTX · 4,567 · ☑]  [🗑]
//
// The color swatch (⬤) is taken from `TIMELINE_SOURCE_PALETTE` indexed
// by the chip's CURRENT position in the live `_sources` array (via
// `timelineSourceColor`). The same index drives the `tl-source-bg-N`
// tint applied to that source's `__source` cells in the grid, so a
// chip and its rows always share a hue. Adding or removing a source
// reshuffles the palette in lockstep across both surfaces.
// Clicking the checkbox toggles `source.enabled`, rebuilds the
// enabled bitmap, and re-runs `_recomputeFilter` so the grid / chart
// / top values / detections all update to reflect the new active
// set. Clicking the 🗑 removes the source — composite schema is
// re-built, view re-mounted.
//
// Visibility rule: the chip bar renders iff `this._sources` is
// non-null AND `this._sources.length >= 2`. Single-file views leave
// the bar hidden (the canonical columns are also hidden in that
// mode). The `_sources_length_hint()` helper returns the live count
// so render-dependent UI (the breadcrumb, the export menu) can gate
// on presence without peeking into the array directly.
//
// Keyboard: `Alt+1..9` toggles source index 0..8. Only wired when the
// chip bar is live.
//
// Loads AFTER `timeline-view.js` (needs `TimelineView.prototype`) and
// AFTER `timeline-sources.js` (uses the palette constant).
// ════════════════════════════════════════════════════════════════════════════

Object.assign(TimelineView.prototype, {

  // Build a permanent host for the chip bar. Called once from
  // `_buildDOM` (see the sentinel patch in timeline-view.js). Absent
  // patch, the bar still renders if the host exists in the DOM under
  // `this._els.sourcesBar` — callers can create it manually when
  // experimenting.
  _buildSourcesBar(host) {
    const wrap = document.createElement('div');
    wrap.className = 'tl-sources-bar';
    wrap.setAttribute('role', 'toolbar');
    wrap.setAttribute('aria-label', 'Merged Timeline sources');
    host.appendChild(wrap);
    this._els.sourcesBar = wrap;
    this._renderSourcesBar();
    return wrap;
  },

  // Render / re-render the chip bar into `this._els.sourcesBar`. Idempotent.
  _renderSourcesBar() {
    const host = this._els && this._els.sourcesBar;
    if (!host) return;
    host.innerHTML = '';
    if (!this._sources || this._sources.length < 2) {
      host.classList.add('hidden');
      return;
    }
    host.classList.remove('hidden');
    for (let i = 0; i < this._sources.length; i++) {
      const s = this._sources[i];
      const chip = document.createElement('div');
      chip.className = 'tl-source-chip' + (s.enabled === false ? ' tl-source-chip-off' : '');
      chip.dataset.sourceId = String(s.sourceId);
      chip.title = s.sourceLabel + ' — ' + (s.formatLabel || s.formatKind) +
        ' — ' + (s.baseStore ? s.baseStore.rowCount.toLocaleString() : '?') +
        ' rows';

      const swatch = document.createElement('span');
      swatch.className = 'tl-source-swatch';
      // Colour is derived from CURRENT array position, not a stored
      // `s.color` field — keeps the chip swatch in lockstep with the
      // `__source` cell tint (which uses the same index) when sources
      // are added or removed.
      swatch.style.backgroundColor = timelineSourceColor(i);
      chip.appendChild(swatch);

      const label = document.createElement('span');
      label.className = 'tl-source-label';
      label.textContent = s.sourceLabel;
      chip.appendChild(label);

      const meta = document.createElement('span');
      meta.className = 'tl-source-meta';
      meta.textContent = (s.formatLabel || s.formatKind || '').toUpperCase();
      chip.appendChild(meta);

      const count = document.createElement('span');
      count.className = 'tl-source-count';
      count.textContent = s.baseStore
        ? s.baseStore.rowCount.toLocaleString()
        : '0';
      chip.appendChild(count);

      const toggleBtn = document.createElement('button');
      toggleBtn.type = 'button';
      toggleBtn.className = 'tl-source-toggle';
      toggleBtn.setAttribute('aria-pressed', s.enabled === false ? 'false' : 'true');
      toggleBtn.title = s.enabled === false
        ? 'Enable this source'
        : 'Temporarily hide this source from the merged view';
      toggleBtn.textContent = s.enabled === false ? '☐' : '☑';
      toggleBtn.addEventListener('click', (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        this._toggleSource(s.sourceId);
      });
      chip.appendChild(toggleBtn);

      const trashBtn = document.createElement('button');
      trashBtn.type = 'button';
      trashBtn.className = 'tl-source-trash';
      trashBtn.title = 'Remove this source from the merged Timeline';
      trashBtn.textContent = '🗑';
      trashBtn.addEventListener('click', (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        this._removeSource(s.sourceId);
      });
      chip.appendChild(trashBtn);

      host.appendChild(chip);
    }

    // Trailing help tip — "Drop a file anywhere to add".
    const hint = document.createElement('span');
    hint.className = 'tl-source-hint';
    hint.textContent = '⤵ Drop another log file to merge it in';
    host.appendChild(hint);
  },

  // Toggle a source's enabled flag and refresh every downstream
  // state (bitmap, filter, sus bitmap sticks, detection bitmap,
  // chart, grid, top-values, pivot).
  _toggleSource(sourceId) {
    if (!this._sources) return;
    let changed = false;
    for (const s of this._sources) {
      if (s.sourceId === sourceId) {
        s.enabled = s.enabled === false;
        changed = true;
        break;
      }
    }
    if (!changed) return;
    // Rebuild the per-row enabled bitmap from scratch — cheaper than
    // hand-patching the slice belonging to this source (a bitmap write
    // is O(n) regardless, and the full rebuild is branch-free).
    this._sourceEnabledBitmap = buildEnabledBitmap(this._sources, this._sourceOfRow);
    this._recomputeFilter();
    this._renderSourcesBar();
    this._scheduleRender(['chart', 'scrubber', 'chips', 'grid', 'columns', 'detections', 'entities', 'pivot']);
  },

  // Remove a source from the merged Timeline. Composite schema
  // re-built; view re-mounted through `_app._timelineRemountFromSources`
  // if the app plumbed a re-mount hook, otherwise we mutate state in
  // place and re-render. Removing the last remaining source clears the
  // Timeline entirely.
  _removeSource(sourceId) {
    if (!this._sources) return;
    const idx = this._sources.findIndex(s => s.sourceId === sourceId);
    if (idx < 0) return;
    const removed = this._sources[idx];
    const remaining = this._sources.slice();
    remaining.splice(idx, 1);
    if (!remaining.length) {
      // Last source — tear down the whole Timeline surface.
      if (typeof releaseSourceRecord === 'function') releaseSourceRecord(removed);
      if (this._app && typeof this._app._clearTimelineFile === 'function') {
        this._app._clearTimelineFile();
      }
      return;
    }
    // ≥1 source left — ask the router to re-mount from the reduced
    // sources list. The router owns the full rebuild path (composite
    // schema, view construction, persistence carry-over).
    if (this._app && typeof this._app._timelineRemountFromSources === 'function') {
      this._app._timelineRemountFromSources(remaining, { removed });
    }
  },

  // Keyboard shortcut handler — wire `Alt+1..9` to `_toggleSource`.
  // Called from `_wireEvents` when the chip bar is live.
  _installSourcesKeyShortcuts() {
    if (this._onSourcesKey) return;
    this._onSourcesKey = (e) => {
      if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      if (!this._sources || this._sources.length < 2) return;
      const tag = (e.target && e.target.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || (e.target && e.target.isContentEditable)) return;
      const n = e.key >= '1' && e.key <= '9' ? (+e.key) - 1 : -1;
      if (n < 0 || n >= this._sources.length) return;
      e.preventDefault();
      this._toggleSource(this._sources[n].sourceId);
    };
    document.addEventListener('keydown', this._onSourcesKey, true);
  },

  _uninstallSourcesKeyShortcuts() {
    if (this._onSourcesKey) {
      document.removeEventListener('keydown', this._onSourcesKey, true);
      this._onSourcesKey = null;
    }
  },
});
