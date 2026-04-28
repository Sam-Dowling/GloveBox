'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-detections.js — TimelineView prototype mixin.
//
// Split out of the legacy app-timeline.js monolith. EVTX-only
// in-view Detections + Entities sections plus their helpers.
//
// **Analysis-bypass guard.** These methods consume the result of
// `EvtxDetector.analyzeForSecurity` (passed in via the TimelineView
// constructor's `evtxFindings` opt — see `app-timeline-router.js`'s
// `_buildTimelineViewFromWorker` and the synchronous fallback in
// `timeline-view.js`'s `static fromEvtx`). They render rows into the
// in-view sections only — they do NOT push to `app.findings`,
// `pushIOC`, the sidebar, or any global state. Adding any such call
// here would silently turn forensic logs into analyser inputs and
// break the Timeline route's intentional analysis-bypass property.
//
// Loads AFTER timeline-view.js (which declares `class TimelineView`).
// ════════════════════════════════════════════════════════════════════════════

// Display labels for IOC entity types — kept module-private so the
// Entities-section render can show "👤 Users" / "🌐 IPs" / etc. instead
// of the raw IOC.* string. Keys are the IOC.* constants from
// `src/constants.js`. New IOC types fall back to the raw type id.
const _TL_ENTITY_LABELS = {
  [IOC.USERNAME]: '👤 Users',
  [IOC.HOSTNAME]: '🖥 Hosts',
  [IOC.IP]: '🌐 IPs',
  [IOC.DOMAIN]: '🌐 Domains',
  [IOC.URL]: '🔗 URLs',
  [IOC.EMAIL]: '✉ Emails',
  [IOC.PROCESS]: '⚙ Processes',
  [IOC.COMMAND_LINE]: '📟 Command lines',
  [IOC.FILE_PATH]: '📄 File paths',
  [IOC.UNC_PATH]: '📂 UNC paths',
  [IOC.REGISTRY_KEY]: '🗝 Registry keys',
  [IOC.HASH]: '🔑 Hashes',
};

// Stable ordering for entity types — most useful pivots first. Types not
// in this list get appended (in insertion order) at the end.
const _TL_ENTITY_ORDER = [
  IOC.USERNAME, IOC.HOSTNAME, IOC.IP, IOC.DOMAIN, IOC.URL,
  IOC.EMAIL, IOC.PROCESS, IOC.COMMAND_LINE, IOC.FILE_PATH,
  IOC.UNC_PATH, IOC.REGISTRY_KEY, IOC.HASH,
];

Object.assign(TimelineView.prototype, {

  // ── EVTX Event-ID + ATT&CK pill renderer ─────────────────────────────
  // Shared by the GridViewer drawer's `detailAugment` callback (in
  // `_renderGridInto`), the Top-Values Event-ID card row injector (in
  // `_paintColumnCards`), and the Detections-table row builder (below).
  // Returns a `DocumentFragment` containing zero, one, or two `<span>`
  // pills — `.tl-evtx-eid-pill` (Microsoft summary) and
  // `.tl-evtx-mitre-pill` (compact ATT&CK technique list with full names
  // in the `title`).
  //
  // `eid` may be a string or number. `channel` is optional — when
  // omitted the registry falls back to the bare-id key (which covers
  // most Security IDs). Returns an empty fragment for non-EVTX files,
  // unknown event IDs, or when the EvtxEventIds module isn't loaded.
  _evtxEidPillsFor(eid, channel) {
    const frag = document.createDocumentFragment();
    if (!this._evtxFindings) return frag;
    if (eid == null || eid === '') return frag;
    const Reg = (typeof window !== 'undefined' && window.EvtxEventIds) || null;
    if (!Reg) return frag;
    let rec = null;
    try { rec = Reg.lookup(eid, channel || ''); } catch (_) { rec = null; }
    if (!rec) return frag;
    if (rec.summary) {
      const pill = document.createElement('span');
      pill.className = 'tl-evtx-eid-pill';
      pill.textContent = rec.summary;
      try {
        // Multi-line tooltip via `formatTooltip`, falling back to a
        // simple "category · name" join when the helper isn't present.
        if (typeof Reg.formatTooltip === 'function') pill.title = Reg.formatTooltip(rec);
        else if (rec.category) pill.title = `${rec.category} · ${rec.name || ''}`.trim();
      } catch (_) { /* ignore */ }
      frag.appendChild(pill);
    }
    if (Array.isArray(rec.mitre) && rec.mitre.length) {
      const mpill = document.createElement('span');
      mpill.className = 'tl-evtx-mitre-pill';
      mpill.textContent = 'ATT&CK ' + rec.mitre.join(' · ');
      const MT = (typeof window !== 'undefined' && window.MITRE) ? window.MITRE : null;
      if (MT) {
        const lines = rec.mitre.map(tid => {
          let info = null;
          try { info = MT.lookup(tid); } catch (_) { /* ignore */ }
          return info ? `${tid} — ${info.name || ''}` : tid;
        });
        mpill.title = lines.join('\n');
      }
      frag.appendChild(mpill);
    }
    return frag;
  },

  // ── Detections section renderer ─────────────────────────────────────
  // EVTX-only. Renders Sigma-style `IOC.PATTERN` hits from
  // `_evtxFindings.externalRefs` as a sortable, severity-stratified
  // table with MITRE technique pills, channel/category context, an
  // optional "Group by ATT&CK tactic" toggle, and a per-row right-click
  // context menu (Filter Event ID / Mark suspicious / open in MS docs
  // or attack.mitre.org).
  //
  // Layout:
  //   [severity summary strip]   ← 5 colour-coded counts + "Group by tactic" toggle
  //   [sortable headers]         ← click to cycle asc/desc on any column
  //   [body rows OR tactic groups]
  _renderDetections() {
    const sec = this._els.detectionsSection;
    const body = this._els.detectionsBody;
    if (!sec || !body) return;

    const refs = this._evtxFindings && Array.isArray(this._evtxFindings.externalRefs)
      ? this._evtxFindings.externalRefs.filter(r => r && r.type === IOC.PATTERN)
      : [];
    if (!refs.length) {
      sec.wrapper.classList.add('hidden');
      return;
    }
    sec.wrapper.classList.remove('hidden');

    // Force-expand the Detections section whenever it has content — analysts
    // glance at this section first on EVTX so a previously-collapsed state
    // carried over from a different file shouldn't hide the Sigma hits.
    if (sec.wrapper.classList.contains('collapsed')) {
      sec.wrapper.classList.remove('collapsed');
      this._sections.detections = false;
      TimelineView._saveSections(this._sections);
    }

    const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const Reg = (typeof window !== 'undefined' && window.EvtxEventIds) || null;
    const MT = (typeof window !== 'undefined' && window.MITRE) ? window.MITRE : null;

    // Resolve column indices for click-to-filter pivots through
    // RowStore.colIndex — same -1-on-miss semantics as the legacy
    // `_baseColumns.indexOf`, but RowStore lazily caches the
    // name → index map so repeated lookups (e.g. across re-renders
    // of the detections pane on column-set change) don't re-walk
    // the column array.
    const store = this._dataset ? this._dataset.store : this.store;
    const eventIdCol = store ? store.colIndex(EVTX_COLUMNS.EVENT_ID) : -1;
    const channelCol = store ? store.colIndex(EVTX_COLUMNS.CHANNEL) : -1;

    // Pre-decorate every detection row with the registry lookup +
    // primary tactic so sort / group / render passes don't re-hit the
    // EvtxEventIds map per row.
    const decorated = refs.map(r => {
      const eid = r.eventId == null ? '' : String(r.eventId);
      const raw = String(r.url || '');
      // The raw `url` field holds "<description> (N match(es))" or
      // "<description> (N events)" / "(N hit(s))" depending on which
      // detector populated it — strip every trailing-count variant so
      // the count never repeats next to the dedicated Hits column.
      const desc = raw.replace(/\s*\((\d+)\s+(?:match(?:es)?|event(?:s)?|hit(?:s)?)\)\s*$/i, '');
      let rec = null;
      if (Reg && eid) { try { rec = Reg.lookup(eid, ''); } catch (_) { rec = null; } }
      const mitre = rec && Array.isArray(rec.mitre) ? rec.mitre : [];
      let primaryTactic = '';
      if (mitre.length && MT && typeof MT.primaryTactic === 'function') {
        try { primaryTactic = MT.primaryTactic(mitre) || ''; } catch (_) { /* ignore */ }
      }
      // Fallback: pick the first technique's tactic from the lookup table.
      if (!primaryTactic && mitre.length && MT) {
        for (const tid of mitre) {
          try {
            const info = MT.lookup(tid);
            if (info && info.tactic) { primaryTactic = info.tactic; break; }
          } catch (_) { /* ignore */ }
        }
      }
      return {
        ref: r,
        eid,
        desc,
        severity: r.severity || 'info',
        sevRank: sevRank[r.severity] || 0,
        count: r.count || 0,
        rec,
        category: rec && rec.category ? rec.category : '',
        channel: rec && rec.channel ? rec.channel : '',
        mitre,
        primaryTactic,
      };
    });

    // Severity tally for the summary strip (uses every detection,
    // regardless of grouping / sort / filter state — the strip is the
    // analyst's read-out of what's available, not what's being shown).
    const sevTally = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const d of decorated) {
      if (sevTally[d.severity] != null) sevTally[d.severity]++;
      else sevTally.info++;
    }
    const totalDistinct = decorated.length;
    const totalHits = decorated.reduce((a, d) => a + (d.count || 0), 0);

    // Severity-filter state — null = show all tiers; a string ('critical',
    // 'high', 'medium', 'low', 'info') restricts both the flat-table
    // body and the per-tactic groups to that tier. Click the same pill
    // twice to clear. Session-only (no localStorage) — this is a
    // momentary lens, not a persistent preference.
    const sevFilter = this._detectionsSevFilter || null;

    // ── Header strip ────────────────────────────────────────────────
    body.innerHTML = '';
    const strip = document.createElement('div');
    strip.className = 'tl-detections-summary-strip';
    const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const sevLabels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
    const stripLeft = document.createElement('div');
    stripLeft.className = 'tl-detections-summary-counts';
    for (const sev of sevOrder) {
      const n = sevTally[sev] || 0;
      if (!n) continue;
      const pill = document.createElement('span');
      pill.className = 'tl-detections-summary-pill tl-det-sev-' + sev;
      const isActive = sevFilter === sev;
      if (isActive) pill.classList.add('tl-detections-summary-pill-active');
      pill.innerHTML = `<span class="tl-detections-summary-pill-label">${sevLabels[sev]}</span><span class="tl-detections-summary-pill-count">${n.toLocaleString()}</span>`;
      pill.title = isActive
        ? `Click to clear severity filter (currently showing ${sevLabels[sev]} only)`
        : `Click to filter table to ${sevLabels[sev]} severity rows`;
      pill.addEventListener('click', () => {
        // Toggle: same pill → off; different pill → switch.
        this._detectionsSevFilter = (this._detectionsSevFilter === sev) ? null : sev;
        this._renderDetections();
      });
      stripLeft.appendChild(pill);
    }
    const stripStat = document.createElement('span');
    stripStat.className = 'tl-detections-summary-stat';
    if (sevFilter) {
      const shownDistinct = decorated.filter(d => d.severity === sevFilter).length;
      const shownHits = decorated
        .filter(d => d.severity === sevFilter)
        .reduce((a, d) => a + (d.count || 0), 0);
      stripStat.textContent =
        `${shownDistinct.toLocaleString()} of ${totalDistinct.toLocaleString()} detection${totalDistinct === 1 ? '' : 's'} · `
        + `${shownHits.toLocaleString()} of ${totalHits.toLocaleString()} hit${totalHits === 1 ? '' : 's'} `
        + `(filter: ${sevLabels[sevFilter]})`;
    } else {
      stripStat.textContent = `${totalDistinct.toLocaleString()} detection${totalDistinct === 1 ? '' : 's'} · ${totalHits.toLocaleString()} hit${totalHits === 1 ? '' : 's'}`;
    }
    stripLeft.appendChild(stripStat);
    strip.appendChild(stripLeft);

    // Group-by-ATT&CK-tactic toggle (right side of strip).
    const stripRight = document.createElement('div');
    stripRight.className = 'tl-detections-summary-tools';
    const groupBtn = document.createElement('button');
    groupBtn.type = 'button';
    groupBtn.className = 'tl-tb-btn tl-detections-group-btn';
    if (this._detectionsGroup) groupBtn.classList.add('tl-detections-group-btn-active');
    groupBtn.textContent = this._detectionsGroup ? '▾ Grouped by ATT&CK tactic' : '▸ Group by ATT&CK tactic';
    groupBtn.title = 'Toggle grouping detections by primary MITRE ATT&CK tactic';
    groupBtn.addEventListener('click', () => {
      this._detectionsGroup = !this._detectionsGroup;
      TimelineView._saveDetectionsGroup(this._detectionsGroup);
      this._renderDetections();
    });
    stripRight.appendChild(groupBtn);
    strip.appendChild(stripRight);
    body.appendChild(strip);

    // ── Sort + render ────────────────────────────────────────────────
    const sort = this._detectionsSort || { col: 'severity', dir: 'desc' };
    const sortRows = (rows) => {
      const dir = sort.dir === 'asc' ? 1 : -1;
      const col = sort.col;
      rows.sort((a, b) => {
        let cmp = 0;
        switch (col) {
          case 'severity': cmp = a.sevRank - b.sevRank; break;
          case 'eid':
            cmp = (parseInt(a.eid, 10) || 0) - (parseInt(b.eid, 10) || 0);
            break;
          case 'desc': cmp = String(a.desc).localeCompare(String(b.desc)); break;
          case 'count': cmp = a.count - b.count; break;
          case 'channel': cmp = String(a.channel).localeCompare(String(b.channel)); break;
          case 'tactic': cmp = String(a.primaryTactic).localeCompare(String(b.primaryTactic)); break;
          default: cmp = a.sevRank - b.sevRank;
        }
        if (cmp === 0) {
          // Stable secondary order: severity desc, then count desc.
          cmp = (a.sevRank - b.sevRank);
          if (cmp === 0) cmp = (a.count - b.count);
          return -cmp;
        }
        return cmp * dir;
      });
    };

    // Apply session-only severity filter (set by clicking a summary
    // pill). Done after the tally + total counts so the strip always
    // shows the full available set, not just what's currently visible.
    const visible = sevFilter
      ? decorated.filter(d => d.severity === sevFilter)
      : decorated;

    // If the active filter has no rows (rare — the pill only shows for
    // tiers with `n > 0`, but a future race could expose this), emit a
    // friendly empty state instead of an empty `<table>`.
    if (!visible.length) {
      const empty = document.createElement('div');
      empty.className = 'tl-detections-empty';
      empty.textContent = `No ${sevLabels[sevFilter] || ''} detections — click the active pill to clear the filter.`;
      body.appendChild(empty);
      return;
    }

    if (this._detectionsGroup) {
      // Bucket detections by primary tactic; render one sub-table per
      // bucket. Detections without a resolvable tactic land in
      // "Unmapped".
      const buckets = new Map();
      for (const d of visible) {
        const key = d.primaryTactic || '__unmapped__';
        if (!buckets.has(key)) buckets.set(key, []);
        buckets.get(key).push(d);
      }
      // Sort tactic groups: highest-severity first, then count desc.
      const tacticOrder = Array.from(buckets.keys()).sort((a, b) => {
        const ar = buckets.get(a).reduce((m, d) => Math.max(m, d.sevRank), 0);
        const br = buckets.get(b).reduce((m, d) => Math.max(m, d.sevRank), 0);
        if (ar !== br) return br - ar;
        const ac = buckets.get(a).reduce((s, d) => s + d.count, 0);
        const bc = buckets.get(b).reduce((s, d) => s + d.count, 0);
        return bc - ac;
      });
      for (const key of tacticOrder) {
        const rows = buckets.get(key);
        sortRows(rows);
        const grp = document.createElement('div');
        grp.className = 'tl-detections-tactic-group';
        const head = document.createElement('header');
        head.className = 'tl-detections-tactic-head';
        const label = (key === '__unmapped__') ? '— Unmapped —' : key;
        const sum = rows.reduce((s, d) => s + d.count, 0);
        head.innerHTML = `<span class="tl-detections-tactic-name">${_tlEsc(label)}</span>
          <span class="tl-detections-tactic-stat">${rows.length} det. · ${sum.toLocaleString()} hit${sum === 1 ? '' : 's'}</span>`;
        grp.appendChild(head);
        grp.appendChild(this._buildDetectionsTable(rows, sort, eventIdCol, channelCol));
        body.appendChild(grp);
      }
    } else {
      sortRows(visible);
      body.appendChild(this._buildDetectionsTable(visible, sort, eventIdCol, channelCol));
    }
  },

  // Construct one detections `<table>` for the given (already-sorted)
  // row array. Factored out of `_renderDetections` so the
  // group-by-tactic mode can re-use it per bucket.
  _buildDetectionsTable(rows, sort, eventIdCol, channelCol) {
    const tbl = document.createElement('table');
    tbl.className = 'tl-detections-table';

    // Sortable headers — click to cycle asc/desc on the same column,
    // or switch to a new column (default desc on click).
    const arrowFor = (col) => sort && sort.col === col
      ? (sort.dir === 'asc' ? ' ↑' : ' ↓') : '';
    tbl.innerHTML = `
      <thead><tr>
        <th class="tl-det-sev tl-det-sortable" data-sort="severity">Severity${arrowFor('severity')}</th>
        <th class="tl-det-eid tl-det-sortable" data-sort="eid">Event${arrowFor('eid')}</th>
        <th class="tl-det-desc tl-det-sortable" data-sort="desc">Detection${arrowFor('desc')}</th>
        <th class="tl-det-channel tl-det-sortable" data-sort="channel">Channel${arrowFor('channel')}</th>
        <th class="tl-det-mitre tl-det-sortable" data-sort="tactic">ATT&amp;CK${arrowFor('tactic')}</th>
        <th class="tl-det-count tl-det-sortable" data-sort="count">Hits${arrowFor('count')}</th>
      </tr></thead>
      <tbody></tbody>`;
    tbl.querySelectorAll('th.tl-det-sortable').forEach(th => {
      th.addEventListener('click', () => {
        const col = th.dataset.sort;
        const cur = this._detectionsSort || { col: 'severity', dir: 'desc' };
        if (cur.col === col) {
          this._detectionsSort = { col, dir: cur.dir === 'asc' ? 'desc' : 'asc' };
        } else {
          // Default direction differs by column kind: numeric / severity
          // descend first (biggest hits), text columns ascend.
          const desc = (col === 'severity' || col === 'count' || col === 'eid');
          this._detectionsSort = { col, dir: desc ? 'desc' : 'asc' };
        }
        this._renderDetections();
      });
    });

    const tb = tbl.querySelector('tbody');
    for (const d of rows) {
      const tr = document.createElement('tr');
      tr.className = 'tl-det-row tl-det-sev-' + d.severity;

      // Severity cell — same vocabulary as the analyser sidebar.
      const sevTd = document.createElement('td');
      sevTd.className = 'tl-det-sev';
      sevTd.innerHTML = `<span class="tl-det-sev-badge">${_tlEsc(d.severity.toUpperCase())}</span>`;
      tr.appendChild(sevTd);

      // Event ID cell — bare value plus the shared summary / ATT&CK
      // pill set produced by `_evtxEidPillsFor`. The pill was removed
      // in an earlier round to fix inconsistent row heights; the
      // single-line ellipsis treatment in `viewers.css`
      // (`.tl-evtx-eid-pill { white-space: nowrap; overflow: hidden;
      // text-overflow: ellipsis; max-width: 360px }`) plus the wider
      // `.tl-detections-table .tl-det-eid` column lets the pill live
      // here again without re-introducing the row-height bug. The
      // pill carries its own `title` (full Microsoft summary +
      // category, formatted by `EvtxEventIds.formatTooltip`), so no
      // separate `eidTd.title` is needed.
      const eidTd = document.createElement('td');
      eidTd.className = 'tl-det-eid';
      eidTd.innerHTML = `<span class="tl-det-eid-val">${_tlEsc(d.eid)}</span>`;
      if (this._evtxEidPillsFor) {
        const pillFrag = this._evtxEidPillsFor(d.eid, d.channel || '');
        if (pillFrag && pillFrag.childNodes.length) eidTd.appendChild(pillFrag);
      }
      tr.appendChild(eidTd);

      // Description cell.
      const descTd = document.createElement('td');
      descTd.className = 'tl-det-desc';
      descTd.title = d.desc;
      descTd.textContent = d.desc;
      tr.appendChild(descTd);

      // Channel + category cell.
      const chTd = document.createElement('td');
      chTd.className = 'tl-det-channel';
      if (d.channel || d.category) {
        const chSpan = document.createElement('span');
        chSpan.className = 'tl-det-channel-name';
        chSpan.textContent = d.channel || '';
        chTd.appendChild(chSpan);
        if (d.category) {
          const catSpan = document.createElement('span');
          catSpan.className = 'tl-det-channel-cat';
          catSpan.textContent = d.category;
          chTd.appendChild(catSpan);
        }
      }
      tr.appendChild(chTd);

      // MITRE technique pills cell — primary tactic on a chip, then
      // each technique on its own pill (clicking the pill opens the
      // attack.mitre.org page in a new tab).
      const mTd = document.createElement('td');
      mTd.className = 'tl-det-mitre';
      if (d.primaryTactic) {
        const tacticPill = document.createElement('span');
        tacticPill.className = 'tl-det-tactic-pill';
        tacticPill.textContent = d.primaryTactic;
        mTd.appendChild(tacticPill);
      }
      if (d.mitre.length) {
        const MT = (typeof window !== 'undefined' && window.MITRE) ? window.MITRE : null;
        for (const tid of d.mitre) {
          const a = document.createElement('a');
          a.className = 'tl-det-tech-pill';
          a.textContent = tid;
          a.target = '_blank';
          a.rel = 'noopener noreferrer';
          if (MT) {
            try {
              const info = MT.lookup(tid);
              a.title = info && info.name ? `${tid} — ${info.name}` : tid;
              a.href = (typeof MT.urlFor === 'function' && MT.urlFor(tid))
                || (info && info.url) || `https://attack.mitre.org/techniques/${tid}/`;
            } catch (_) {
              a.href = `https://attack.mitre.org/techniques/${tid}/`;
              a.title = tid;
            }
          } else {
            a.href = `https://attack.mitre.org/techniques/${tid}/`;
            a.title = tid;
          }
          // Stop click bubbling so the row-level pivot handler doesn't
          // also fire when the analyst opens the technique URL.
          a.addEventListener('click', (e) => e.stopPropagation());
          mTd.appendChild(a);
        }
      }
      tr.appendChild(mTd);

      // Hit-count cell.
      const cntTd = document.createElement('td');
      cntTd.className = 'tl-det-count';
      cntTd.textContent = d.count ? d.count.toLocaleString() : '';
      tr.appendChild(cntTd);

      // Click on the row body (anywhere except the technique pills) →
      // filter the grid to this Event ID. Ctrl/Meta-click stacks the
      // filter on top of the existing query.
      if (d.eid && eventIdCol >= 0) {
        tr.classList.add('tl-det-row-clickable');
        tr.title = `Filter Event ID = ${d.eid} (Ctrl/⌘-click to add to current query · right-click for more)`;
        tr.addEventListener('click', (ev) => {
          if (ev.target.closest('a')) return;   // technique-pill anchors handle themselves
          const additive = ev.ctrlKey || ev.metaKey;
          if (!additive) this._queryCommitClauses([]);
          this._addOrToggleChip(eventIdCol, d.eid, { op: 'eq' });
        });
        // Right-click → context menu (Filter Event ID / Mark suspicious /
        // open MS docs / open ATT&CK tactic).
        tr.addEventListener('contextmenu', (ev) => {
          if (ev.target.closest('a')) return;
          ev.preventDefault();
          this._openDetectionContextMenu(ev, d, eventIdCol, channelCol);
        });
      }
      tb.appendChild(tr);
    }
    return tbl;
  },

  // Right-click context menu for a Detections-table row. Mirrors the
  // shape of `_openRowContextMenu` so the visual treatment is consistent.
  _openDetectionContextMenu(e, d, eventIdCol, channelCol) {
    this._closePopover();
    const menu = document.createElement('div');
    menu.className = 'tl-popover tl-rowmenu';

    const items = [];
    if (eventIdCol >= 0 && d.eid) {
      items.push({
        label: `🔎 Filter to Event ID ${d.eid}`,
        act: () => {
          this._queryCommitClauses([]);
          this._addOrToggleChip(eventIdCol, d.eid, { op: 'eq' });
        },
      });
      items.push({
        label: `＋ Add Event ID ${d.eid} to current query`,
        act: () => this._addOrToggleChip(eventIdCol, d.eid, { op: 'eq' }),
      });
    }
    if (channelCol >= 0 && d.channel) {
      items.push({
        label: `🔎 Filter to channel "${this._ellipsis(d.channel, 40)}"`,
        act: () => this._addOrToggleChip(channelCol, d.channel, { op: 'eq' }),
      });
    }
    if (d.eid) {
      items.push({
        label: `🚩 Mark Event ID ${d.eid} suspicious`,
        act: () => {
          if (eventIdCol < 0) return;
          this._addOrToggleChip(eventIdCol, d.eid, { op: 'sus' });
        },
      });
    }
    items.push({ sep: true });
    items.push({
      label: `Copy detection name`,
      act: () => this._copyToClipboard(d.desc),
    });

    // External-link section. CSP `default-src 'none'` doesn't block
    // top-level user-initiated navigation, so opening a learn.microsoft.com
    // or attack.mitre.org URL via window.open works fine.
    const ext = [];
    // MS Learn auditing-event docs for Security-channel events.
    if (d.eid && d.channel && /security/i.test(d.channel)) {
      ext.push({
        label: `🔗 Open Microsoft docs (event ${d.eid})`,
        url: `https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-${d.eid}`,
      });
    }
    // ATT&CK technique URLs.
    if (d.mitre.length) {
      const MT = (typeof window !== 'undefined' && window.MITRE) ? window.MITRE : null;
      for (const tid of d.mitre) {
        let url = `https://attack.mitre.org/techniques/${tid}/`;
        let name = tid;
        if (MT) {
          try {
            const info = MT.lookup(tid);
            if (typeof MT.urlFor === 'function') {
              const u = MT.urlFor(tid);
              if (u) url = u;
            } else if (info && info.url) {
              url = info.url;
            }
            if (info && info.name) name = `${tid} — ${info.name}`;
          } catch (_) { /* ignore */ }
        }
        ext.push({ label: `🔗 ATT&CK ${name}`, url });
      }
    }
    if (ext.length) {
      items.push({ sep: true });
      for (const x of ext) {
        items.push({
          label: x.label,
          act: () => {
            // `window.open` is fine under CSP `default-src 'none'`
            // because it triggers a top-level browsing context
            // (handled outside the document's CSP).
            try { window.open(x.url, '_blank', 'noopener,noreferrer'); } catch (_) { /* ignore */ }
          },
        });
      }
    }

    for (const it of items) {
      if (it.sep) {
        const sep = document.createElement('div');
        sep.className = 'tl-popover-sep';
        menu.appendChild(sep);
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

  // ── Entities (EVTX IOCs) ────────────────────────────────────────────────
  // Collects non-PATTERN / non-INFO IOCs from EVTX `externalRefs` (users,
  // hosts, hashes, processes, IPs, URLs, UNC paths, file paths, command
  // lines, registry keys, domains, emails). Results are grouped by IOC
  // type and rendered as Top-Values-style cards (pin / copy-visible /
  // sort-cycle / debounced search / drag-to-reorder), each capped at 100
  // values. Click-to-filter pivots route through `_pivotOnEntity`. CSV /
  // TSV are intentionally skipped — scanning every cell with URL +
  // hostname regexes was an O(rows × cols) drag on large logs, and the
  // analyser's sidebar already surfaces the same IOCs via the rawText
  // path.
  _renderEntities() {
    const sec = this._els.entitiesSection;
    const body = this._els.entitiesBody;
    if (!sec || !body) return;

    // EVTX-only feature — hide for CSV / TSV without running the collector.
    if (!this._evtxFindings) {
      sec.wrapper.classList.add('hidden');
      return;
    }

    const groups = this._collectEntities();
    if (!groups.size) {
      sec.wrapper.classList.add('hidden');
      return;
    }
    sec.wrapper.classList.remove('hidden');

    body.innerHTML = '';

    // Resolve display order: persisted drag-order first (filtered to
    // types still present), then any types missing from the persisted
    // order in the canonical default order, then any still-unseen IOC
    // types in insertion order.
    const present = new Set(groups.keys());
    const ordered = [];
    const seen = new Set();
    if (this._entOrder && this._entOrder.length) {
      for (const t of this._entOrder) {
        if (present.has(t) && !seen.has(t)) { ordered.push(t); seen.add(t); }
      }
    }
    for (const t of _TL_ENTITY_ORDER) {
      if (present.has(t) && !seen.has(t)) { ordered.push(t); seen.add(t); }
    }
    for (const t of groups.keys()) {
      if (!seen.has(t)) { ordered.push(t); seen.add(t); }
    }

    // Move pinned types to the front while preserving relative order
    // among pinned and unpinned groups.
    if (this._pinnedEntities && this._pinnedEntities.length) {
      const pinnedSet = new Set(this._pinnedEntities);
      const pinned = ordered.filter(t => pinnedSet.has(t));
      const rest = ordered.filter(t => !pinnedSet.has(t));
      ordered.length = 0;
      for (const t of pinned) ordered.push(t);
      for (const t of rest) ordered.push(t);
    }

    const wrap = document.createElement('div');
    wrap.className = 'tl-entities-wrap';

    const sortLabels = { 'count-desc': '# ↓', 'count-asc': '# ↑', 'az': 'A→Z', 'za': 'Z→A' };

    for (const t of ordered) {
      const entries = groups.get(t);
      if (!entries || !entries.length) continue;

      const card = document.createElement('div');
      card.className = 'tl-entity-group tl-entity-group-' + String(t).toLowerCase();
      card.dataset.entType = String(t);

      const entKey = 'entity:' + String(t);
      const savedSpan = this._cardSpanFor(entKey);
      if (savedSpan > 1) card.style.gridColumn = `span ${savedSpan}`;

      const isPinned = !!(this._pinnedEntities && this._pinnedEntities.indexOf(t) !== -1);
      if (isPinned) card.classList.add('tl-col-card-pinned');

      const typeLabel = _TL_ENTITY_LABELS[t] || String(t);

      // Card head — mirrors `.tl-col-head` from `_paintColumnCards` so
      // the existing CSS (centred name, hover-revealed action cluster,
      // pinned / drag-source modifiers) applies unchanged.
      const head = document.createElement('div');
      head.className = 'tl-col-head tl-entity-head';
      head.innerHTML = `
        <div class="tl-col-head-actions">
          <button class="tl-col-pin${isPinned ? ' tl-col-pin-active' : ''}" type="button" title="${isPinned ? 'Unpin entity card' : 'Pin entity card to top-left'}">📌</button>
          <button class="tl-col-copy" type="button" title="Copy visible values to clipboard">📋</button>
          <button class="tl-col-sort" type="button" title="Cycle sort (count ↓ → count ↑ → A→Z → Z→A · Alt-click to reset)" data-mode="count-desc">${sortLabels['count-desc']}</button>
        </div>
        <div class="tl-col-head-title">
          <span class="tl-col-name" title="${_tlEsc(typeLabel)} · Drag header to reorder">${_tlEsc(typeLabel)}</span>
          <span class="tl-col-sub" title="distinct values">${entries.length.toLocaleString()} unique</span>
        </div>
      `;
      card.appendChild(head);

      // Per-card debounced search — filters the visible values without
      // mutating any global state.
      const searchRow = document.createElement('div');
      searchRow.className = 'tl-col-search-wrap';
      searchRow.innerHTML = `<input type="text" class="tl-col-search" placeholder="filter values…" spellcheck="false" autocomplete="off">`;
      card.appendChild(searchRow);
      const searchInput = searchRow.querySelector('.tl-col-search');

      // Body list — kept simple (no virtualization) since
      // `_collectEntities` caps at 100 rows per type.
      const list = document.createElement('div');
      list.className = 'tl-entity-list';
      card.appendChild(list);

      // Local sort + filter state, mirroring `_paintColumnCards`.
      let displayValues = entries;
      const applySortAndFilter = () => {
        const mode = card._sortMode || 'count-desc';
        const q = (card._searchText || '').toLowerCase();
        let arr = entries;
        if (q) arr = arr.filter(e => String(e.value).toLowerCase().includes(q));
        if (mode !== 'count-desc') {
          arr = arr.slice();
          if (mode === 'count-asc') arr.sort((a, b) => a.count - b.count);
          else if (mode === 'az') arr.sort((a, b) => String(a.value).localeCompare(String(b.value)));
          else if (mode === 'za') arr.sort((a, b) => String(b.value).localeCompare(String(a.value)));
        }
        displayValues = arr;
      };
      const renderList = () => {
        list.innerHTML = '';
        if (!displayValues.length) {
          const empty = document.createElement('div');
          empty.className = 'tl-col-empty';
          empty.textContent = card._searchText ? 'No matches' : '—';
          list.appendChild(empty);
          return;
        }
        const topVal = entries[0] && entries[0].count ? entries[0].count : 1;
        for (const e of displayValues) {
          const row = document.createElement('div');
          row.className = 'tl-entity-row';
          row.title = `Filter rows containing "${e.value}"`;
          const pct = topVal > 0 ? Math.max(2, Math.round((e.count / topVal) * 100)) : 0;
          // Per-row count column intentionally omitted — the bar's width
          // already encodes relative frequency and the unique-count subtitle
          // in the card header carries the cardinality. Cosmetic
          // simplification (commit follow-up to fb053a7).
          row.innerHTML = `
            <span class="tl-col-bar" style="width:${pct}%"></span>
            <span class="tl-entity-val">${_tlEsc(e.value)}</span>`;
          row.addEventListener('click', () => this._pivotOnEntity(t, e.value));
          list.appendChild(row);
        }
      };
      applySortAndFilter();
      renderList();

      // Sort-cycle button.
      const sortBtn = head.querySelector('.tl-col-sort');
      sortBtn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        const order = ['count-desc', 'count-asc', 'az', 'za'];
        if (ev.altKey) {
          card._sortMode = 'count-desc';
        } else {
          const cur = card._sortMode || 'count-desc';
          const ix = order.indexOf(cur);
          card._sortMode = order[(ix + 1) % order.length];
        }
        sortBtn.dataset.mode = card._sortMode;
        sortBtn.textContent = sortLabels[card._sortMode];
        applySortAndFilter();
        renderList();
      });

      // Pin button — keyed by the IOC type identifier, persisted via
      // `_loadEntPinnedFor` / `_saveEntPinnedFor`.
      head.querySelector('.tl-col-pin').addEventListener('click', (ev) => {
        ev.stopPropagation();
        const arr = this._pinnedEntities || (this._pinnedEntities = []);
        const idx = arr.indexOf(t);
        if (idx >= 0) arr.splice(idx, 1);
        else arr.push(t);
        TimelineView._saveEntPinnedFor(this._fileKey, arr);
        this._scheduleRender(['entities']);
      });

      // Copy-visible-values button — copies the post-filter, post-sort
      // value list as newline-separated text.
      head.querySelector('.tl-col-copy').addEventListener('click', (ev) => {
        ev.stopPropagation();
        const txt = displayValues.map(e => String(e.value == null ? '' : e.value)).join('\n');
        this._copyToClipboard(txt);
        if (this._app && typeof this._app._toast === 'function') {
          this._app._toast(`Copied ${displayValues.length.toLocaleString()} value${displayValues.length === 1 ? '' : 's'} from "${typeLabel}"`, 'info');
        }
      });

      // Per-card search — debounced, Esc clears.
      let searchTimer = 0;
      searchInput.addEventListener('input', () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => {
          card._searchText = searchInput.value;
          applySortAndFilter();
          renderList();
        }, 80);
      });
      searchInput.addEventListener('keydown', (ev) => {
        if (ev.key === 'Escape' && searchInput.value) {
          ev.preventDefault();
          searchInput.value = '';
          card._searchText = '';
          applySortAndFilter();
          renderList();
        }
      });

      // Drag-to-reorder via the head — mirrors the column-card flow in
      // `_paintColumnCards`. Drop position commits a new persisted
      // entity order via `_loadEntOrderFor` / `_saveEntOrderFor`.
      head.draggable = true;
      head.addEventListener('dragstart', (ev) => {
        if (ev.target.closest('button')) { ev.preventDefault(); return; }
        card.classList.add('tl-col-drag-source');
        document.body.classList.add('tl-col-dragging');
        ev.dataTransfer.effectAllowed = 'move';
        ev.dataTransfer.setData('text/plain', String(t));
      });
      head.addEventListener('dragend', () => {
        card.classList.remove('tl-col-drag-source');
        document.body.classList.remove('tl-col-dragging');
        wrap.querySelectorAll('.tl-col-drag-over-before,.tl-col-drag-over-after').forEach(
          el => el.classList.remove('tl-col-drag-over-before', 'tl-col-drag-over-after')
        );
      });
      card.addEventListener('dragover', (ev) => {
        ev.preventDefault();
        ev.dataTransfer.dropEffect = 'move';
        const rect = card.getBoundingClientRect();
        const midX = rect.left + rect.width / 2;
        card.classList.toggle('tl-col-drag-over-before', ev.clientX < midX);
        card.classList.toggle('tl-col-drag-over-after', ev.clientX >= midX);
      });
      card.addEventListener('dragleave', () => {
        card.classList.remove('tl-col-drag-over-before', 'tl-col-drag-over-after');
      });
      card.addEventListener('drop', (ev) => {
        ev.preventDefault();
        card.classList.remove('tl-col-drag-over-before', 'tl-col-drag-over-after');
        const srcType = ev.dataTransfer.getData('text/plain');
        if (!srcType || srcType === String(t)) return;
        const srcCard = [...wrap.children].find(el => el.dataset.entType === srcType);
        if (!srcCard) return;
        const rect = card.getBoundingClientRect();
        const midX = rect.left + rect.width / 2;
        if (ev.clientX < midX) wrap.insertBefore(srcCard, card);
        else wrap.insertBefore(srcCard, card.nextSibling);
        // Read the new order off the DOM and persist.
        const order = [];
        for (const el of wrap.children) {
          if (el.dataset && el.dataset.entType) order.push(el.dataset.entType);
        }
        this._entOrder = order;
        TimelineView._saveEntOrderFor(this._fileKey, order);
      });

      // Resize handles — left and right edges (entity cards reuse the
      // column-card `_installCardResize` path with `entityMinW: 260`).
      const rR = document.createElement('div');
      rR.className = 'tl-col-resize';
      card.appendChild(rR);
      rR.addEventListener('pointerdown', (ev) => this._installCardResize(ev, card, entKey, 'right'));

      const rL = document.createElement('div');
      rL.className = 'tl-col-resize-left';
      card.appendChild(rL);
      rL.addEventListener('pointerdown', (ev) => this._installCardResize(ev, card, entKey, 'left'));

      wrap.appendChild(card);
    }
    body.appendChild(wrap);
  },

  // Gather entity groups for the Entities section. Returns a Map<type, Array<{value, count}>>.
  _collectEntities() {
    const groups = new Map();
    const ENTITY_CAP_PER_TYPE = 100;

    const push = (type, value) => {
      if (value == null) return;
      const v = String(value).trim();
      if (!v) return;
      if (!groups.has(type)) groups.set(type, new Map());
      const m = groups.get(type);
      m.set(v, (m.get(v) || 0) + 1);
    };

    // EVTX-only — use the findings from `analyzeForSecurity`. CSV / TSV
    // used to get a full-grid regex sweep here; it was quadratic on big
    // logs and has been removed. The analyser's sidebar still surfaces
    // the same IOCs for those formats via the rawText scan.
    if (this._evtxFindings && Array.isArray(this._evtxFindings.externalRefs)) {
      for (const r of this._evtxFindings.externalRefs) {
        if (!r || !r.type) continue;
        if (r.type === IOC.PATTERN || r.type === IOC.INFO || r.type === IOC.YARA) continue;
        const val = r.url || r.value;
        if (!val) continue;
        if (typeof isNicelisted === 'function' && isNicelisted(val, r.type)) continue;
        push(r.type, val);
      }
    }

    // Materialise as sorted arrays, capped per type.
    const out = new Map();
    for (const [type, m] of groups) {
      const arr = Array.from(m.entries()).map(([value, count]) => ({ value, count }));
      arr.sort((a, b) => b.count - a.count || (a.value < b.value ? -1 : 1));
      if (arr.length > ENTITY_CAP_PER_TYPE) arr.length = ENTITY_CAP_PER_TYPE;
      out.set(type, arr);
    }
    return out;
  },

  // Build a query chip (or set of chips) for a clicked entity.
  //
  // For USERNAME / HOSTNAME / IP we emit bareword "any-column contains"
  // clauses rather than guess a column. Rationale: EVTX auto-extract
  // scatters the logical entity across many possible columns depending
  // on the source event (e.g. a user can land in `Event Data.SubjectUserName`,
  // `TargetUserName`, `SamAccountName`, `AccountName`; a host in `Computer`,
  // `WorkstationName`, `ComputerName`, `SubjectDomainName`). Any fixed
  // column-hint map mis-matches for some rows and silently returns zero
  // results. A bareword AND-search matches iff each token appears
  // somewhere on the row — the correct semantic regardless of which
  // column carries it.
  //
  // USERNAME entities are synthesised as `DOMAIN\user` by
  // `_extractEvtxIOCs` (see `src/renderers/evtx-renderer.js:1690`); we
  // split on the first backslash so both halves participate in the AND.
  //
  // All other IOC types still fall through to a contains chip on the
  // Event Data column (EVTX) or the last column — unchanged.
  _pivotOnEntity(iocType, value) {
    const raw = String(value);

    if (iocType === IOC.USERNAME || iocType === IOC.HOSTNAME || iocType === IOC.IP) {
      let parts;
      if (iocType === IOC.USERNAME && raw.indexOf('\\') !== -1) {
        const bs = raw.indexOf('\\');
        parts = [raw.slice(0, bs), raw.slice(bs + 1)];
      } else {
        parts = [raw];
      }
      const needles = parts.map(s => s.trim()).filter(Boolean);
      if (needles.length > 0) this._pivotAnyContainsToggle(needles);
      return;
    }

    // Default — contains-chip on Event Data (EVTX) or last column.
    const cols = this.columns;
    const lowered = cols.map(c => String(c || '').toLowerCase());
    let ix = lowered.indexOf('event data');
    if (ix < 0) ix = cols.length - 1;
    if (ix < 0) return;
    this._addContainsChipsReplace(ix, raw);
  },

  // Atomic toggle of a set of `{ k: 'any', needle: N }` top-level
  // clauses. If every needle is already present the whole set is
  // removed; otherwise the missing needles are appended. One commit,
  // one recompute — a second click on the same entity undoes the
  // pivot in one step regardless of how many tokens it produced.
  _pivotAnyContainsToggle(needles) {
    const clauses = this._queryTopLevelClauses(this._queryCurrentAst());
    const findIdx = (n) => clauses.findIndex(c => c.k === 'any' && String(c.needle) === n);
    const findings = needles.map(n => ({ n, idx: findIdx(n) }));
    const allPresent = findings.every(f => f.idx >= 0);
    if (allPresent) {
      // Splice high-to-low so earlier removals don't shift later indices.
      const toRemove = findings.map(f => f.idx).sort((a, b) => b - a);
      for (const i of toRemove) clauses.splice(i, 1);
    } else {
      for (const f of findings) {
        if (f.idx < 0) clauses.push({ k: 'any', needle: f.n });
      }
    }
    this._queryCommitClauses(clauses);
  },

});
