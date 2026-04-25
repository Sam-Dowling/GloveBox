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

Object.assign(TimelineView.prototype, {

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
    // Also persist the uncollapsed state so it survives the next rebuild.
    if (sec.wrapper.classList.contains('collapsed')) {
      sec.wrapper.classList.remove('collapsed');
      this._sections.detections = false;
      TimelineView._saveSections(this._sections);
    }

    const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

    refs.sort((a, b) => {
      const sa = sevRank[a.severity] || 0, sb = sevRank[b.severity] || 0;
      if (sa !== sb) return sb - sa;
      return (b.count || 0) - (a.count || 0);
    });

    // Event ID column index for EVTX (matches `fromEvtx` schema).
    const eventIdCol = this._baseColumns.indexOf(EVTX_COLUMNS.EVENT_ID);

    body.innerHTML = '';
    const tbl = document.createElement('table');
    tbl.className = 'tl-detections-table';
    tbl.innerHTML = `
      <thead><tr>
        <th class="tl-det-sev">Severity</th>
        <th class="tl-det-desc">Detection</th>
        <th class="tl-det-eid">Event ID</th>
        <th class="tl-det-count">Hits</th>
      </tr></thead>
      <tbody></tbody>`;
    const tb = tbl.querySelector('tbody');
    for (const r of refs) {
      const tr = document.createElement('tr');
      tr.className = 'tl-det-row tl-det-sev-' + (r.severity || 'info');
      const eid = r.eventId == null ? '' : String(r.eventId);
      // The raw `url` field holds "<description> (N match(es))" — strip the
      // trailing count suffix for display since we show it in its own column.
      const raw = String(r.url || '');
      const desc = raw.replace(/\s*\((\d+)\s+match(?:es)?\)\s*$/i, '');
      const cnt = r.count != null ? r.count : '';
      tr.innerHTML = `
        <td class="tl-det-sev"><span class="tl-det-sev-badge">${_tlEsc((r.severity || 'info').toUpperCase())}</span></td>
        <td class="tl-det-desc" title="${_tlEsc(desc)}">${_tlEsc(desc)}</td>
        <td class="tl-det-eid">${_tlEsc(eid)}</td>
        <td class="tl-det-count">${cnt === '' ? '' : Number(cnt).toLocaleString()}</td>`;
      if (eid && eventIdCol >= 0) {
        tr.classList.add('tl-det-row-clickable');
        tr.title = `Filter Event ID = ${eid} (Ctrl/⌘-click to add to current query)`;
        tr.addEventListener('click', (ev) => {
          // Default: clear the whole query first so the detection stands
          // alone — otherwise a surviving `contains` / `NOT` / other-column
          // chip would keep filtering the result set to nothing. Ctrl/Meta
          // is an opt-out for analysts who want to stack detections
          // additively on top of an existing query.
          const additive = ev.ctrlKey || ev.metaKey;
          if (!additive) this._queryCommitClauses([]);
          this._addOrToggleChip(eventIdCol, eid, { op: 'eq' });
        });
      }
      tb.appendChild(tr);
    }
    body.appendChild(tbl);
  },

  // ── Entities (EVTX IOCs) ────────────────────────────────────────────────
  // Collects non-PATTERN / non-INFO IOCs from EVTX `externalRefs` (users,
  // hosts, hashes, processes, IPs, URLs, UNC paths, file paths, command
  // lines, registry keys, domains, emails). Results are grouped by type,
  // deduplicated (and capped) for display, and each row offers a
  // click-to-filter pivot against the best matching column. CSV / TSV are
  // intentionally skipped — scanning every cell with URL + hostname
  // regexes was an O(rows × cols) drag on large logs, and the analyser's
  // sidebar already surfaces the same IOCs via the rawText path.
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
    // Stable display order — most useful pivots first.
    const order = [
      IOC.USERNAME, IOC.HOSTNAME, IOC.IP, IOC.DOMAIN, IOC.URL,
      IOC.EMAIL, IOC.PROCESS, IOC.COMMAND_LINE, IOC.FILE_PATH,
      IOC.UNC_PATH, IOC.REGISTRY_KEY, IOC.HASH,
    ];
    const typeLabels = {
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

    const ordered = order.filter(t => groups.has(t));
    for (const t of groups.keys()) if (!ordered.includes(t)) ordered.push(t);

    const wrap = document.createElement('div');
    wrap.className = 'tl-entities-wrap';
    for (const t of ordered) {
      const entries = groups.get(t);
      if (!entries || !entries.length) continue;
      const grp = document.createElement('div');
      grp.className = 'tl-entity-group tl-entity-group-' + String(t).toLowerCase();

      // Restore persisted span for this entity card.
      const entKey = 'entity:' + String(t);
      const savedSpan = this._cardSpanFor(entKey);
      if (savedSpan > 1) grp.style.gridColumn = `span ${savedSpan}`;

      const head = document.createElement('div');
      head.className = 'tl-entity-head';
      head.innerHTML = `<span class="tl-entity-title">${_tlEsc(typeLabels[t] || t)}</span>
        <span class="tl-entity-count">${entries.length.toLocaleString()}</span>`;
      grp.appendChild(head);

      const list = document.createElement('div');
      list.className = 'tl-entity-list';
      for (const e of entries) {
        const row = document.createElement('div');
        row.className = 'tl-entity-row';
        row.title = `Filter rows containing "${e.value}"`;
        row.innerHTML = `
          <span class="tl-entity-val">${_tlEsc(e.value)}</span>
          <span class="tl-entity-hits">${e.count ? e.count.toLocaleString() : ''}</span>`;
        row.addEventListener('click', () => this._pivotOnEntity(t, e.value));
        list.appendChild(row);
      }
      grp.appendChild(list);

      // Resize handles — left and right edges
      const rR = document.createElement('div');
      rR.className = 'tl-col-resize';
      grp.appendChild(rR);
      rR.addEventListener('pointerdown', (ev) => this._installCardResize(ev, grp, entKey, 'right'));

      const rL = document.createElement('div');
      rL.className = 'tl-col-resize-left';
      grp.appendChild(rL);
      rL.addEventListener('pointerdown', (ev) => this._installCardResize(ev, grp, entKey, 'left'));

      wrap.appendChild(grp);
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
