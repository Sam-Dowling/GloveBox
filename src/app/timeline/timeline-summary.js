'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-summary.js — TimelineView prototype mixin.
//
// Implements the EVTX-only "⚡ Summarize" toolbar action: produces a
// Markdown-formatted, AI/LLM-friendly digest of the **whole file**
// (every event, no filter / window / query applied) plus a dedicated
// "Active Analyst View" sub-section that records what the human is
// currently looking at (query string, time window, visible/total
// counts, sus marks). The latter is metadata about the analyst's
// focus, not a constraint on the summarised data.
//
// Output content (priority-ordered for shrink-to-fit eviction; lower
// `priority` ⇒ kept, higher ⇒ evicted first):
//
//   1  File header  (name / size / hashes / format / event count /
//                    first-last timestamps / duration / channel +
//                    provider distribution)
//   2  Active Analyst View   (query DSL / time window / visible vs
//                    total / sus marks / cursor)
//   3  Risk summary  (severity tally + top tactics roll-up)
//   4  Detections    (Sigma-style hits — sorted critical→info, with
//                     first/last seen, burst flag, ATT&CK techniques
//                     and follow-up event suggestions)
//   5  Notable Event-ID activity  (every known EID via EvtxEventIds
//                     with name/category/first-last/count/MITRE)
//   6  Entities       (users / hosts / ips / domains / urls / hashes /
//                     processes)
//   7  Relationships  (Sysmon process trees, logon-failure→success
//                     transitions, network triples, beacon cadence,
//                     audit-log tampering, persistence drops)
//   8  Time clusters  (whole-file bucket histogram + top-5 hottest
//                     buckets with dominant stack key)
//   9  Cross-reference block (plain-bullet usernames / hostnames /
//                     ips / domains / hashes / registry keys for easy
//                     pivoting against other timelines / log sources)
//
// Honours `app._getSummaryCharBudget()` via the same build-full →
// measure → shrink-ladder pattern used by `_buildAnalysisText` in
// `app-ui.js`. SCALE controls per-section row caps (top-N tables,
// detection list, entity list, relationship cluster size).
//
// **Analysis-bypass.** Like the rest of `src/app/timeline/`, this
// mixin only reads from `this._evtxEvents` / `this._evtxFindings`
// (already-built side channels). It MUST NOT push to
// `this._app.findings`, `pushIOC`, the sidebar, or any global state.
//
// Loads AFTER timeline-detections.js (which it shares the IOC.*
// label table with).
// ════════════════════════════════════════════════════════════════════════════

(function () {
  if (typeof TimelineView === 'undefined') return;

  // ── Cap helper (mirrors app-ui.js `cap`) ──────────────────────────
  const _tlsCap = (text, max) => {
    if (!text) return '';
    if (max === Infinity) return text;
    return text.length <= max ? text : text.slice(0, max) + '\n… (section truncated)\n';
  };

  // ── Markdown table-cell escape: pipe + newline → safe glyphs ──────
  const _tp = (v) => String(v == null ? '' : v).replace(/\|/g, '∣').replace(/\n/g, ' ');

  // ── Shorten free text for inline list usage ───────────────────────
  const _short = (s, n) => {
    const t = String(s == null ? '' : s);
    return t.length <= n ? t : t.slice(0, n) + '…';
  };

  // ── Format ms duration as human-readable (5d 3h, 14m 12s, 350ms) ─
  const _fmtDur = (ms) => {
    if (!Number.isFinite(ms) || ms < 0) return '—';
    if (ms < 1000) return ms + 'ms';
    const s = Math.floor(ms / 1000);
    if (s < 60) return s + 's';
    const m = Math.floor(s / 60), rs = s % 60;
    if (m < 60) return m + 'm ' + rs + 's';
    const h = Math.floor(m / 60), rm = m % 60;
    if (h < 24) return h + 'h ' + rm + 'm';
    const d = Math.floor(h / 24), rh = h % 24;
    return d + 'd ' + rh + 'h';
  };

  // ── UTC timestamp formatter (delegates to global helper) ──────────
  const _ts = (ms) => {
    if (!Number.isFinite(ms)) return '—';
    if (typeof _tlFormatFullUtc === 'function') return _tlFormatFullUtc(ms, false) + 'Z';
    return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
  };

  // Wrap a possibly-missing parser. Returns [] on any error. Keeps
  // the per-event loop tight without try/catch noise.
  const _parsePairs = (eventData) => {
    if (!eventData) return [];
    if (typeof EvtxDetector !== 'undefined' && typeof EvtxDetector._parseEventDataPairs === 'function') {
      try { return EvtxDetector._parseEventDataPairs(eventData) || []; } catch (_) { /* fall through */ }
    }
    // Inline fallback identical to EvtxDetector — keeps the summary
    // working even if the detector module didn't load.
    return String(eventData).split(' | ').map(part => {
      const eq = part.indexOf('=');
      if (eq > 0 && eq < 60) return { key: part.substring(0, eq), val: part.substring(eq + 1) };
      return { key: '', val: part };
    });
  };

  // Look up an Event ID record without re-throwing if the registry
  // isn't loaded.
  const _eidLookup = (id, channel) => {
    const Reg = (typeof window !== 'undefined' && window.EvtxEventIds) || null;
    if (!Reg || id == null || id === '') return null;
    try { return Reg.lookup(id, channel || '') || null; } catch (_) { return null; }
  };

  // Resolve a list of MITRE technique IDs to "Tnnnn — Name" lines.
  const _mitreLines = (tids) => {
    if (!Array.isArray(tids) || !tids.length) return [];
    const MT = (typeof window !== 'undefined' && window.MITRE) ? window.MITRE : null;
    if (!MT) return tids.slice();
    return tids.map(t => {
      let info = null;
      try { info = MT.lookup(t); } catch (_) { /* ignore */ }
      return info && info.name ? `${t} — ${info.name}` : t;
    });
  };

  // Pick the primary tactic for an array of techniques.
  const _primaryTactic = (tids) => {
    if (!Array.isArray(tids) || !tids.length) return '';
    const MT = (typeof window !== 'undefined' && window.MITRE) ? window.MITRE : null;
    if (!MT) return '';
    if (typeof MT.primaryTactic === 'function') {
      try { return MT.primaryTactic(tids) || ''; } catch (_) { /* ignore */ }
    }
    for (const t of tids) {
      try {
        const info = MT.lookup(t);
        if (info && info.tactic) return String(info.tactic).split(',')[0].trim();
      } catch (_) { /* ignore */ }
    }
    return '';
  };

  // Top-N entries of a Map<string, number>, descending by value.
  const _topN = (map, n) => {
    const arr = [];
    for (const [k, v] of map) arr.push([k, v]);
    arr.sort((a, b) => b[1] - a[1]);
    return n === Infinity ? arr : arr.slice(0, n);
  };

  // Severity ranking for sort.
  const _SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  Object.assign(TimelineView.prototype, {

    // ── Public entry point ──────────────────────────────────────────
    // Wired to the toolbar `data-act="summarize"` button by `_wireEvents`.
    // Runs strictly read-only against this view's pre-built EVTX side
    // channels.
    _summarizeAndCopy() {
      if (!this._evtxFindings || !Array.isArray(this._evtxEvents)) {
        if (this._app && typeof this._app._toast === 'function') {
          this._app._toast('Summarize is only available for EVTX timelines', 'error');
        }
        return;
      }
      const budget = (this._app && typeof this._app._getSummaryCharBudget === 'function')
        ? this._app._getSummaryCharBudget() : 64 * 1024;
      let report = '';
      try {
        report = this._buildTimelineSummary(budget);
      } catch (e) {
        if (this._app && typeof this._app._toast === 'function') {
          this._app._toast('Summarize failed: ' + (e && e.message ? e.message : e), 'error');
        }
        return;
      }
      if (!report) {
        if (this._app && typeof this._app._toast === 'function') {
          this._app._toast('Nothing to summarize', 'error');
        }
        return;
      }
      if (this._app && typeof this._app._copyToClipboard === 'function') {
        this._app._copyToClipboard(report);
      } else {
        try { navigator.clipboard.writeText(report); } catch (_) { /* noop */ }
      }
      if (this._app && typeof this._app._toast === 'function') {
        this._app._toast('Timeline summary copied to clipboard', 'info');
      }
    },

    // ── Builder ─────────────────────────────────────────────────────
    // Mirrors app-ui.js's build-full → measure → shrink-ladder pattern.
    // Sections are produced by `_tlsBuildSectionsAtScale(SCALE)`.
    _buildTimelineSummary(budget) {
      const UNBUDGETED = !isFinite(budget);
      const BUDGET = UNBUDGETED ? Number.MAX_SAFE_INTEGER : budget;

      const buildAt = (SCALE) => this._tlsBuildSectionsAtScale(SCALE);

      const fullSections = buildAt(Infinity);
      const joinSorted = (secs) =>
        secs.slice().sort((a, b) => a.priority - b.priority).map(s => s.text).join('');

      if (UNBUDGETED) return joinSorted(fullSections);

      const fullText = joinSorted(fullSections);
      if (fullText.length <= BUDGET) return fullText;

      const SCALE_LADDER = [4, 2, 1, 0.5, 0.25];
      const variants = new Map();
      variants.set(Infinity, fullSections);
      for (const SCALE of SCALE_LADDER) variants.set(SCALE, buildAt(SCALE));

      const current = new Map();
      for (const sec of fullSections) current.set(sec.priority, sec);
      const priorities = [...current.keys()].sort((a, b) => a - b);

      // Walk most-expendable → least, swapping in tighter rebuilds.
      for (let i = priorities.length - 1; i >= 0; i--) {
        const prio = priorities[i];
        for (const SCALE of SCALE_LADDER) {
          const replacement = (variants.get(SCALE) || []).find(s => s.priority === prio);
          if (replacement) current.set(prio, replacement);
          const combined = joinSorted([...current.values()]);
          if (combined.length <= BUDGET) return combined;
        }
      }

      // Last-resort hard truncation per priority — mirrors app-ui.js.
      const finalSecs = [...current.values()].sort((a, b) => a.priority - b.priority);
      let remaining = BUDGET;
      const out = [];
      for (const sec of finalSecs) {
        if (remaining <= 0) break;
        const limit = Math.min(sec.maxLen || remaining, remaining);
        const text = _tlsCap(sec.text, limit);
        out.push(text);
        remaining -= text.length;
      }
      let report = out.join('');
      if (report.length > BUDGET) report = report.slice(0, BUDGET) + '\n… (report truncated)\n';
      return report;
    },

    // ── Per-SCALE section builder ───────────────────────────────────
    _tlsBuildSectionsAtScale(SCALE) {
      const rowCap = (n) => SCALE === Infinity ? Infinity : Math.max(5, Math.ceil(n * SCALE));
      const charCap = (n) => SCALE === Infinity ? Infinity : Math.max(120, Math.ceil(n * SCALE));
      const sections = [];

      // Pre-build per-scale aggregates once. Some are cached on the
      // instance because the rebuild cost is dominated by the O(n)
      // event walk; SCALE only affects row counts at emit time.
      if (!this._tlsAgg) this._tlsAgg = this._tlsCollectAggregates();
      const agg = this._tlsAgg;

      // ═══════ 1. File header ═════════════════════════════════════════
      sections.push({
        text: this._tlsBuildFileHeader(agg, rowCap, charCap),
        priority: 1,
        maxLen: charCap(2400),
      });

      // ═══════ 2. Active Analyst View (the metadata one) ═════════════
      sections.push({
        text: this._tlsBuildActiveViewSection(agg, rowCap, charCap),
        priority: 2,
        maxLen: charCap(1600),
      });

      // ═══════ 3. Risk summary ═══════════════════════════════════════
      const risk = this._tlsBuildRiskSummary(agg, rowCap, charCap);
      if (risk) sections.push({ text: risk, priority: 3, maxLen: charCap(1200) });

      // ═══════ 4. Detections ═════════════════════════════════════════
      const det = this._tlsBuildDetectionsSection(agg, rowCap, charCap);
      if (det) sections.push({ text: det, priority: 4, maxLen: charCap(14000) });

      // ═══════ 5. Notable Event-ID activity ══════════════════════════
      const eids = this._tlsBuildEventIdActivity(agg, rowCap, charCap);
      if (eids) sections.push({ text: eids, priority: 5, maxLen: charCap(8000) });

      // ═══════ 6. Entities ═══════════════════════════════════════════
      const ent = this._tlsBuildEntitiesSection(agg, rowCap, charCap);
      if (ent) sections.push({ text: ent, priority: 6, maxLen: charCap(8000) });

      // ═══════ 7. Relationships ═════════════════════════════════════
      const rel = this._tlsBuildRelationshipsSection(agg, rowCap, charCap);
      if (rel) sections.push({ text: rel, priority: 7, maxLen: charCap(10000) });

      // ═══════ 8. Time clusters ══════════════════════════════════════
      const tc = this._tlsBuildTimeClusters(agg, rowCap, charCap);
      if (tc) sections.push({ text: tc, priority: 8, maxLen: charCap(2400) });

      // ═══════ 9. Cross-reference block ══════════════════════════════
      const xr = this._tlsBuildCrossRef(agg, rowCap, charCap);
      if (xr) sections.push({ text: xr, priority: 9, maxLen: charCap(6000) });

      return sections;
    },

    // ── Aggregate pre-pass (single O(n) walk) ───────────────────────
    // Computes everything that the per-section builders need so they
    // each become near-pure formatters. Cached on `this._tlsAgg` so
    // repeat invocations across SCALE variants are O(1).
    _tlsCollectAggregates() {
      const events = this._evtxEvents || [];
      const findings = this._evtxFindings || {};
      const refs = Array.isArray(findings.externalRefs) ? findings.externalRefs : [];

      // ── First/last timestamps + valid-event count from _timeMs ──
      const tm = this._timeMs;
      let first = Infinity, last = -Infinity, parsed = 0;
      if (tm && tm.length) {
        for (let i = 0; i < tm.length; i++) {
          const v = tm[i];
          if (Number.isFinite(v)) {
            if (v < first) first = v;
            if (v > last) last = v;
            parsed++;
          }
        }
      }
      if (!Number.isFinite(first)) first = NaN;
      if (!Number.isFinite(last)) last = NaN;

      // ── Channel / provider / level / computer distribution ───────
      // Plus per-EID stats: count, channel, first ms, last ms, level.
      const chCount = new Map();
      const pvCount = new Map();
      const lvlCount = new Map();
      const computerCount = new Map();
      const eidStats = new Map(); // key = eid
      // Process trees: pid → {image, parent, ts, cmd, user, hashes}
      const procByPid = new Map();
      // Logon events (4625 / 4624 / 4634 / 4647 / 4648)
      const logonHits = [];
      // Network connections (Sysmon EID 3)
      const netHits = [];
      // Audit / log tamper
      const auditHits = [];
      // Persistence (services + scheduled tasks + autoruns)
      const persistHits = [];
      // PowerShell / WMI / RDP suspicious
      const psHits = [];
      // Defender alerts
      const defHits = [];

      // Entities by IOC type → Map<value, count>
      const ent = new Map();
      const entAdd = (type, val, sev) => {
        if (!val) return;
        let m = ent.get(type);
        if (!m) { m = new Map(); ent.set(type, m); }
        const cur = m.get(val);
        if (cur) { cur.count++; if (sev && _SEV_RANK[sev] > _SEV_RANK[cur.severity]) cur.severity = sev; }
        else m.set(val, { count: 1, severity: sev || 'info' });
      };

      // Pre-import IOCs that EvtxDetector already computed.
      for (const r of refs) {
        if (!r || !r.url) continue;
        // The detector emits IOC.PATTERN for Sigma hits — those are
        // detections, not entities. Skip them here; the detection
        // section reads `refs` directly.
        if (r.type === IOC.PATTERN) continue;
        if (r.type === IOC.INFO || r.type === IOC.YARA) continue;
        entAdd(r.type, r.url, r.severity || 'info');
      }

      // Walk every event for per-EID stats + relationship harvest.
      // `events[i]` aligns with `tm[i]` aligns with `this.rows[i]`.
      for (let i = 0; i < events.length; i++) {
        const ev = events[i];
        if (!ev) continue;
        const ts = tm && tm.length ? tm[i] : NaN;
        const eid = ev.eventId == null ? '' : String(ev.eventId);
        const channel = ev.channel || '';
        const provider = ev.provider || '';
        const level = ev.level || '';
        const computer = ev.computer || '';

        if (channel) chCount.set(channel, (chCount.get(channel) || 0) + 1);
        if (provider) pvCount.set(provider, (pvCount.get(provider) || 0) + 1);
        if (level) lvlCount.set(level, (lvlCount.get(level) || 0) + 1);
        if (computer) computerCount.set(computer, (computerCount.get(computer) || 0) + 1);

        // Per-EID rollup keyed by `eid|channel` so a Sysmon-1 doesn't
        // get conflated with a Security-1.
        const eKey = eid + '|' + channel;
        let er = eidStats.get(eKey);
        if (!er) {
          er = { eid, channel, count: 0, first: Infinity, last: -Infinity, level };
          eidStats.set(eKey, er);
        }
        er.count++;
        if (Number.isFinite(ts)) {
          if (ts < er.first) er.first = ts;
          if (ts > er.last) er.last = ts;
        }

        // Quick KV map for relationship harvesting. Skip events
        // without eventData to keep the loop hot for noisy logs.
        if (!ev.eventData) continue;
        const pairs = _parsePairs(ev.eventData);
        const kv = {};
        for (const p of pairs) if (p.key) kv[p.key] = p.val;

        // ── Sysmon EID 1 (process create) → process tree ──
        // Provider gate: only Sysmon. Bare ID 1 also fires from other
        // providers (System) and we don't want to misclassify those.
        if (eid === '1' && /sysmon/i.test(channel)) {
          const pid = kv.ProcessId || '';
          if (pid) {
            procByPid.set(pid, {
              ts,
              image: kv.Image || '',
              cmd: kv.CommandLine || '',
              user: kv.User || '',
              parentImage: kv.ParentImage || '',
              parentCmd: kv.ParentCommandLine || '',
              parentPid: kv.ParentProcessId || '',
              hashes: kv.Hashes || '',
              pid,
            });
          }
        }

        // ── Sysmon EID 3 (network connect) ──
        if (eid === '3' && /sysmon/i.test(channel)) {
          netHits.push({
            ts,
            image: kv.Image || '',
            user: kv.User || '',
            srcIp: kv.SourceIp || '',
            srcPort: kv.SourcePort || '',
            dstIp: kv.DestinationIp || '',
            dstPort: kv.DestinationPort || '',
            dstHost: kv.DestinationHostname || '',
            proto: kv.Protocol || '',
          });
        }

        // ── Logon family (Security channel) ──
        if (eid === '4624' || eid === '4625' || eid === '4634' || eid === '4647' || eid === '4648' || eid === '4672' || eid === '4769') {
          logonHits.push({
            ts, eid,
            user: kv.TargetUserName || '',
            domain: kv.TargetDomainName || '',
            type: kv.LogonType || '',
            ip: kv.IpAddress || '',
            workstation: kv.WorkstationName || '',
            status: kv.Status || kv.SubStatus || '',
            process: kv.ProcessName || '',
          });
        }

        // ── Audit / log tampering ──
        if (eid === '1102' || eid === '4719' || eid === '4739' || eid === '104') {
          auditHits.push({ ts, eid, user: kv.SubjectUserName || '', channel });
        }

        // ── Persistence ──
        // System 7045 (service install), Security 4697 (service install),
        // Security 4698 (sched task create), 4702 (sched task update),
        // Sysmon 12/13 (registry CreateKey/SetValue).
        if (eid === '7045' || eid === '4697') {
          persistHits.push({
            kind: 'service', ts, eid,
            name: kv.ServiceName || kv.SubjectUserName || '',
            image: kv.ImagePath || kv.ServiceFileName || '',
            startType: kv.StartType || kv.ServiceStartType || '',
            account: kv.AccountName || kv.SubjectUserName || '',
          });
        } else if (eid === '4698' || eid === '4702') {
          persistHits.push({
            kind: 'task', ts, eid,
            name: kv.TaskName || '',
            user: kv.SubjectUserName || '',
            content: _short(kv.TaskContent || '', 200),
          });
        } else if ((eid === '12' || eid === '13') && /sysmon/i.test(channel)) {
          const target = kv.TargetObject || '';
          if (target && /\\(Run|RunOnce|Image File Execution Options|AppInit_DLLs|Winlogon|Userinit|Services|CurrentControlSet\\Services)\\/i.test(target)) {
            persistHits.push({
              kind: 'registry', ts, eid,
              name: target,
              image: kv.Image || '',
              user: kv.User || '',
              details: _short(kv.Details || '', 160),
            });
          }
        }

        // ── PowerShell / WMI / RDP ──
        if (channel && /powershell/i.test(channel) && (eid === '4104' || eid === '4103' || eid === '4100')) {
          psHits.push({
            ts, eid,
            script: _short(kv.ScriptBlockText || kv.Payload || '', 300),
            user: kv.UserId || kv.User || '',
            host: kv.HostApplication || '',
          });
        }

        // ── Defender ──
        if (channel && /defender/i.test(channel) && (eid === '1116' || eid === '1117' || eid === '5001' || eid === '5007')) {
          defHits.push({
            ts, eid,
            threat: kv.ThreatName || '',
            path: kv.Path || kv['Detection User'] || '',
            severity: kv.Severity || '',
            action: kv.Action || '',
          });
        }
      }

      // Decorate detections with first/last timestamp + burst metric
      // by walking events that match each pattern's eventId. Detections
      // come from `findings.externalRefs` filtered to IOC.PATTERN.
      const detectionRefs = refs.filter(r => r && r.type === IOC.PATTERN);
      const decoratedDetections = [];
      for (const r of detectionRefs) {
        const eid = r.eventId == null ? '' : String(r.eventId);
        // Walk events to find min/max timestamps for this EID. Filter
        // to the same channel-family the detection's recommendation
        // implies (using EvtxEventIds.lookup if available).
        let dFirst = Infinity, dLast = -Infinity, dCount = 0;
        for (let i = 0; i < events.length; i++) {
          const ev = events[i];
          if (!ev || String(ev.eventId) !== eid) continue;
          dCount++;
          const ts = tm && tm.length ? tm[i] : NaN;
          if (Number.isFinite(ts)) {
            if (ts < dFirst) dFirst = ts;
            if (ts > dLast) dLast = ts;
          }
        }
        if (!Number.isFinite(dFirst)) dFirst = NaN;
        if (!Number.isFinite(dLast)) dLast = NaN;
        const rec = _eidLookup(eid, '');
        const tids = rec && Array.isArray(rec.mitre) ? rec.mitre : [];
        decoratedDetections.push({
          eid,
          rule: r.ruleName || '',
          desc: String(r.url || '').replace(/\s*\((\d+)\s+(?:match(?:es)?|event(?:s)?|hit(?:s)?)\)\s*$/i, ''),
          severity: r.severity || 'info',
          sevRank: _SEV_RANK[r.severity] || 0,
          count: r.count || dCount || 0,
          first: dFirst,
          last: dLast,
          rec,
          channel: rec && rec.channel ? rec.channel : '',
          category: rec && rec.category ? rec.category : '',
          mitre: tids,
          tactic: _primaryTactic(tids),
        });
      }
      decoratedDetections.sort((a, b) => {
        if (b.sevRank !== a.sevRank) return b.sevRank - a.sevRank;
        if ((b.count || 0) !== (a.count || 0)) return (b.count || 0) - (a.count || 0);
        return (a.first || 0) - (b.first || 0);
      });

      return {
        events,
        findings,
        first, last, parsed,
        chCount, pvCount, lvlCount, computerCount,
        eidStats,
        procByPid,
        logonHits,
        netHits,
        auditHits,
        persistHits,
        psHits,
        defHits,
        ent,
        detectionRefs,
        decoratedDetections,
      };
    },

    // ── Section: File header ────────────────────────────────────────
    _tlsBuildFileHeader(agg, rowCap, charCap) {
      const meta = (this._app && this._app._fileMeta) || {};
      const hashes = (this._app && this._app.fileHashes) || {};
      const fileName = (this.file && this.file.name) || meta.name || '(unnamed)';
      const sizeText = (typeof fmtBytes === 'function' && meta.size)
        ? `${fmtBytes(meta.size)} (${(meta.size).toLocaleString()} bytes)`
        : (meta.size ? meta.size.toLocaleString() + ' bytes' : '—');

      let s = '# EVTX Timeline Summary\n\n';
      s += '_Whole-file digest. Every section below covers the entire log unless explicitly noted (see "Active Analyst View")._\n\n';
      s += '## File\n| Property | Value |\n|----------|-------|\n';
      s += `| Filename | ${_tp(fileName)} |\n`;
      s += `| Format | Windows Event Log (.evtx) |\n`;
      s += `| Size | ${_tp(sizeText)} |\n`;
      if (hashes.md5) s += `| MD5 | \`${hashes.md5}\` |\n`;
      if (hashes.sha1) s += `| SHA-1 | \`${hashes.sha1}\` |\n`;
      if (hashes.sha256) s += `| SHA-256 | \`${hashes.sha256}\` |\n`;
      s += `| Total records | ${(agg.events.length).toLocaleString()} |\n`;
      s += `| Records with parseable timestamp | ${(agg.parsed).toLocaleString()} |\n`;
      s += `| First event | ${_ts(agg.first)} |\n`;
      s += `| Last event | ${_ts(agg.last)} |\n`;
      const dur = (Number.isFinite(agg.first) && Number.isFinite(agg.last)) ? (agg.last - agg.first) : NaN;
      s += `| Duration | ${_fmtDur(dur)} |\n`;
      s += `| Distinct event IDs | ${agg.eidStats.size.toLocaleString()} |\n`;
      s += '\n_All timestamps in this report are UTC._\n';

      // Top channels / providers / hosts.
      const chTop = _topN(agg.chCount, rowCap(8));
      const pvTop = _topN(agg.pvCount, rowCap(8));
      const hostTop = _topN(agg.computerCount, rowCap(6));
      if (chTop.length) {
        s += '\n### Channels\n| Channel | Events |\n|---------|-------:|\n';
        for (const [k, v] of chTop) s += `| ${_tp(k)} | ${v.toLocaleString()} |\n`;
        if (agg.chCount.size > chTop.length) s += `\n_… and ${agg.chCount.size - chTop.length} more channels._\n`;
      }
      if (pvTop.length) {
        s += '\n### Providers\n| Provider | Events |\n|----------|-------:|\n';
        for (const [k, v] of pvTop) s += `| ${_tp(k)} | ${v.toLocaleString()} |\n`;
        if (agg.pvCount.size > pvTop.length) s += `\n_… and ${agg.pvCount.size - pvTop.length} more providers._\n`;
      }
      if (hostTop.length) {
        s += '\n### Computers (system header)\n| Host | Events |\n|------|-------:|\n';
        for (const [k, v] of hostTop) s += `| ${_tp(k)} | ${v.toLocaleString()} |\n`;
      }
      return s;
    },

    // ── Section: Active Analyst View (the metadata section) ─────────
    // This is the ONE section that reflects what the human is currently
    // looking at. The rest of the report is whole-file.
    _tlsBuildActiveViewSection(agg /*, rowCap, charCap */) {
      const total = this._evtxEvents ? this._evtxEvents.length : 0;
      const visible = this._filteredIdx ? this._filteredIdx.length : total;
      const win = this._window;
      const winText = (win && Number.isFinite(win.min) && Number.isFinite(win.max))
        ? `${_ts(win.min)} → ${_ts(win.max)} (${_fmtDur(win.max - win.min)})`
        : '— full data range';
      const queryStr = (this._queryStr || '').trim();
      const sus = Array.isArray(this._susMarks) ? this._susMarks : [];
      const susBitmap = this._susBitmap;
      let susHitCount = 0;
      if (susBitmap && susBitmap.length) {
        for (let i = 0; i < susBitmap.length; i++) if (susBitmap[i]) susHitCount++;
      }

      let s = '\n## Active Analyst View\n';
      s += '_Metadata only — describes what the analyst is currently focused on. The rest of this report is whole-file._\n\n';
      s += '| Aspect | Value |\n|--------|-------|\n';
      s += `| Visible rows | ${visible.toLocaleString()} of ${total.toLocaleString()} |\n`;
      s += `| Time window | ${_tp(winText)} |\n`;
      s += `| Query | ${queryStr ? '`' + _tp(_short(queryStr, 600)) + '`' : '— none —'} |\n`;
      s += `| 🚩 Suspicious marks | ${sus.length} (matching ${susHitCount.toLocaleString()} rows) |\n`;
      const cursorTs = (this._cursorDataIdx != null && this._timeMs)
        ? this._timeMs[this._cursorDataIdx] : null;
      s += `| Cursor | ${cursorTs && Number.isFinite(cursorTs) ? _ts(cursorTs) : '— none —'} |\n`;
      s += `| Bucket | ${_tp(this._bucketId || '—')} |\n`;
      if (sus.length) {
        s += '\n### Active suspicious marks\n';
        for (const m of sus.slice(0, 24)) {
          const col = m.any ? '* (any column)' : (m.colName || '?');
          s += `- \`${_tp(col)}\` matches \`${_tp(_short(m.val || '', 120))}\`\n`;
        }
        if (sus.length > 24) s += `- … and ${sus.length - 24} more marks\n`;
      }
      return s;
    },

    // ── Section: Risk summary ───────────────────────────────────────
    _tlsBuildRiskSummary(agg, rowCap /*, charCap */) {
      const det = agg.decoratedDetections;
      if (!det.length) return '';
      const tally = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const d of det) tally[d.severity] = (tally[d.severity] || 0) + 1;
      const tactics = new Map();
      for (const d of det) {
        if (!d.tactic) continue;
        tactics.set(d.tactic, (tactics.get(d.tactic) || 0) + 1);
      }
      let topRisk = 'low';
      if (tally.critical) topRisk = 'critical';
      else if (tally.high) topRisk = 'high';
      else if (tally.medium) topRisk = 'medium';
      const sevIcon = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: '⚪' };
      let s = '\n## Risk Summary\n';
      s += `**Top severity:** ${sevIcon[topRisk]} ${topRisk.toUpperCase()}\n\n`;
      s += '| Severity | Distinct rules |\n|----------|---------------:|\n';
      for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
        if (tally[sev]) s += `| ${sev} | ${tally[sev]} |\n`;
      }
      const top = _topN(tactics, rowCap(8));
      if (top.length) {
        s += '\n**Top ATT&CK tactics:**\n';
        for (const [k, v] of top) s += `- ${_tp(k)} — ${v} rule${v === 1 ? '' : 's'}\n`;
      }
      return s;
    },

    // ── Section: Detections ─────────────────────────────────────────
    _tlsBuildDetectionsSection(agg, rowCap, charCap) {
      const det = agg.decoratedDetections;
      if (!det.length) return '';
      const cap = rowCap(80);
      const burstMs = 60 * 1000; // first→last under 1m == burst
      let s = '\n## Detections\n';
      s += '_Sigma-style hits across the whole log, sorted critical → info, then by event count._\n\n';
      const groupByTactic = !!this._detectionsGroup;
      const emitOne = (d) => {
        const ts1 = _ts(d.first), ts2 = _ts(d.last);
        const span = (Number.isFinite(d.first) && Number.isFinite(d.last)) ? (d.last - d.first) : NaN;
        const burst = (d.count > 3 && Number.isFinite(span) && span < burstMs) ? ' · 💥 burst (' + _fmtDur(span) + ')' : '';
        let block = `### [${d.severity.toUpperCase()}] ${_tp(d.desc || '(unnamed pattern)')}\n`;
        const meta = [];
        if (d.eid) meta.push('Event ID **' + d.eid + '**');
        if (d.channel) meta.push('Channel: ' + d.channel);
        if (d.category) meta.push('Category: ' + d.category);
        if (d.rule) meta.push('Rule: `' + d.rule + '`');
        if (d.count) meta.push('Hits: ' + d.count.toLocaleString());
        if (meta.length) block += '- ' + meta.join(' · ') + '\n';
        if (Number.isFinite(d.first) || Number.isFinite(d.last)) {
          block += `- First: ${ts1} · Last: ${ts2}${burst}\n`;
        }
        if (d.mitre.length) {
          const lines = _mitreLines(d.mitre);
          block += '- ATT&CK: ' + lines.map(x => '`' + _tp(x) + '`').join(', ') + '\n';
        }
        if (d.rec && d.rec.name && d.rec.name !== d.desc) {
          block += '- Microsoft: ' + _tp(_short(d.rec.name, 200)) + '\n';
        }
        return block + '\n';
      };

      if (groupByTactic) {
        const groups = new Map();
        for (const d of det) {
          const k = d.tactic || '(unmapped)';
          let arr = groups.get(k);
          if (!arr) { arr = []; groups.set(k, arr); }
          arr.push(d);
        }
        let emitted = 0;
        for (const [tactic, arr] of groups) {
          if (emitted >= cap) break;
          s += `#### Tactic: ${_tp(tactic)} (${arr.length})\n`;
          for (const d of arr) {
            if (emitted >= cap) break;
            s += emitOne(d);
            emitted++;
          }
        }
        if (det.length > emitted) s += `\n_… and ${det.length - emitted} more detection${det.length - emitted === 1 ? '' : 's'} omitted (budget)._\n`;
      } else {
        const slice = det.slice(0, cap);
        for (const d of slice) s += emitOne(d);
        if (det.length > slice.length) s += `\n_… and ${det.length - slice.length} more detection${det.length - slice.length === 1 ? '' : 's'} omitted (budget)._\n`;
      }
      return s;
    },

    // ── Section: Notable Event-ID activity ─────────────────────────
    // Every event-ID-stat record that resolved through EvtxEventIds is
    // emitted with first/last/count/MITRE so the LLM can correlate
    // EID-only intel from other tools.
    _tlsBuildEventIdActivity(agg, rowCap /*, charCap */) {
      const arr = [];
      for (const v of agg.eidStats.values()) {
        const rec = _eidLookup(v.eid, v.channel);
        if (!rec) continue;
        arr.push({
          eid: v.eid,
          channel: rec.channel || v.channel || '',
          name: rec.name || '',
          summary: rec.summary || '',
          category: rec.category || '',
          mitre: Array.isArray(rec.mitre) ? rec.mitre : [],
          count: v.count,
          first: Number.isFinite(v.first) ? v.first : NaN,
          last: Number.isFinite(v.last) ? v.last : NaN,
          noisy: !!rec.noisy,
        });
      }
      if (!arr.length) return '';
      // Sort: non-noisy first, then by count desc.
      arr.sort((a, b) => {
        if (a.noisy !== b.noisy) return a.noisy ? 1 : -1;
        return b.count - a.count;
      });
      const cap = rowCap(60);
      let s = '\n## Notable Event-ID activity\n';
      s += '| EID | Channel | Summary | Count | First | Last | ATT&CK |\n';
      s += '|----:|---------|---------|------:|-------|------|--------|\n';
      const slice = arr.slice(0, cap);
      for (const e of slice) {
        const tids = e.mitre.length ? e.mitre.join(' · ') : '';
        s += `| ${_tp(e.eid)} | ${_tp(e.channel)} | ${_tp(_short(e.summary || e.name, 80))}${e.noisy ? ' _(noisy)_' : ''} | ${e.count.toLocaleString()} | ${_ts(e.first)} | ${_ts(e.last)} | ${_tp(tids)} |\n`;
      }
      if (arr.length > slice.length) s += `\n_… and ${arr.length - slice.length} more known event ID${arr.length - slice.length === 1 ? '' : 's'}._\n`;
      return s;
    },

    // ── Section: Entities ──────────────────────────────────────────
    _tlsBuildEntitiesSection(agg, rowCap /*, charCap */) {
      if (!agg.ent.size) return '';
      // Stable ordering — most-useful pivots first.
      const ORDER = [
        IOC.USERNAME, IOC.HOSTNAME, IOC.IP, IOC.DOMAIN, IOC.URL,
        IOC.HASH, IOC.PROCESS, IOC.COMMAND_LINE, IOC.FILE_PATH,
        IOC.UNC_PATH, IOC.REGISTRY_KEY, IOC.EMAIL,
      ];
      const LABELS = {
        [IOC.USERNAME]: '👤 Users',
        [IOC.HOSTNAME]: '🖥 Hosts',
        [IOC.IP]: '🌐 IPs',
        [IOC.DOMAIN]: '🌐 Domains',
        [IOC.URL]: '🔗 URLs',
        [IOC.HASH]: '🔑 Hashes',
        [IOC.PROCESS]: '⚙ Processes',
        [IOC.COMMAND_LINE]: '📟 Command lines',
        [IOC.FILE_PATH]: '📄 Files',
        [IOC.UNC_PATH]: '📂 UNC paths',
        [IOC.REGISTRY_KEY]: '🗝 Registry keys',
        [IOC.EMAIL]: '✉ Emails',
      };
      let s = '\n## Entities\n';
      s += '_Cross-correlation handles. Counts are the number of distinct events the entity appears in (post-dedup)._\n';
      const seenTypes = new Set();
      const types = [...ORDER, ...[...agg.ent.keys()].filter(k => !ORDER.includes(k))];
      for (const t of types) {
        if (seenTypes.has(t)) continue;
        seenTypes.add(t);
        const m = agg.ent.get(t);
        if (!m || !m.size) continue;
        const arr = [];
        for (const [val, info] of m) arr.push({ val, count: info.count, severity: info.severity });
        arr.sort((a, b) => {
          const r = (_SEV_RANK[b.severity] || 0) - (_SEV_RANK[a.severity] || 0);
          if (r) return r;
          return b.count - a.count;
        });
        const cap = rowCap(20);
        const slice = arr.slice(0, cap);
        s += `\n### ${LABELS[t] || t} (${arr.length})\n`;
        for (const e of slice) {
          const sevTag = e.severity && e.severity !== 'info' ? ` _(${e.severity})_` : '';
          s += `- \`${_tp(_short(e.val, 220))}\` × ${e.count}${sevTag}\n`;
        }
        if (arr.length > slice.length) s += `- _… and ${arr.length - slice.length} more_\n`;
      }
      return s;
    },

    // ── Section: Relationships ─────────────────────────────────────
    _tlsBuildRelationshipsSection(agg, rowCap, charCap) {
      const out = [];

      // ── Sysmon process trees ──
      if (agg.procByPid.size) {
        const cap = rowCap(20);
        // Build parent → children map keyed by parent PID. PIDs alone
        // can collide across reboots; we don't have boot-id metadata so
        // we accept the imprecision and roll up by raw PID.
        const childrenByParent = new Map();
        for (const proc of agg.procByPid.values()) {
          const pp = proc.parentPid || '';
          if (!pp) continue;
          let arr = childrenByParent.get(pp);
          if (!arr) { arr = []; childrenByParent.set(pp, arr); }
          arr.push(proc);
        }
        // Pick "interesting" trees: parent has ≥2 children OR child
        // image is a known suspicious LOLBin / shell.
        const SUSP_RE = /\\(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|schtasks|wmic|msbuild|installutil)\.exe$/i;
        const trees = [];
        for (const [pid, children] of childrenByParent) {
          const parent = agg.procByPid.get(pid);
          const interesting = children.length >= 2
            || children.some(c => SUSP_RE.test(c.image || ''))
            || (parent && SUSP_RE.test(parent.image || ''));
          if (!interesting) continue;
          trees.push({ parent, children, pid });
        }
        if (trees.length) {
          let block = '\n### Sysmon process trees\n';
          const slice = trees.slice(0, cap);
          for (const t of slice) {
            const ph = t.parent ? `${_short(t.parent.image || '?', 120)} (pid ${t.pid})` : `(unknown parent, pid ${t.pid})`;
            const pcmd = t.parent ? _short(t.parent.cmd || '', 200) : '';
            block += `- **${_tp(ph)}**${pcmd ? ' — `' + _tp(pcmd) + '`' : ''}\n`;
            const ccap = rowCap(8);
            for (const c of t.children.slice(0, ccap)) {
              const ts = Number.isFinite(c.ts) ? ' @ ' + _ts(c.ts) : '';
              block += `  - ${_tp(_short(c.image || '?', 120))} (pid ${_tp(c.pid)})${ts}` +
                       (c.cmd ? ` — \`${_tp(_short(c.cmd, 220))}\`` : '') + '\n';
            }
            if (t.children.length > ccap) block += `  - _… and ${t.children.length - ccap} more children_\n`;
          }
          if (trees.length > slice.length) block += `\n_… and ${trees.length - slice.length} more interesting tree${trees.length - slice.length === 1 ? '' : 's'}._\n`;
          out.push(block);
        }
      }

      // ── Failed → success logon transitions ──
      if (agg.logonHits.length) {
        const fails = agg.logonHits.filter(l => l.eid === '4625');
        const succs = agg.logonHits.filter(l => l.eid === '4624');
        if (fails.length && succs.length) {
          // Group fails by user; for each, find the first 4624 that
          // follows under 24h with the same user (and matching
          // workstation/IP if present) — classic brute-force pivot.
          const succByUser = new Map();
          for (const s of succs) {
            const k = (s.user || '').toLowerCase();
            if (!succByUser.has(k)) succByUser.set(k, []);
            succByUser.get(k).push(s);
          }
          for (const arr of succByUser.values()) arr.sort((a, b) => (a.ts || 0) - (b.ts || 0));

          const transitions = [];
          for (const f of fails) {
            if (!f.user || !Number.isFinite(f.ts)) continue;
            const candidates = succByUser.get((f.user || '').toLowerCase()) || [];
            const win = 24 * 3600 * 1000;
            const hit = candidates.find(s => s.ts > f.ts && (s.ts - f.ts) <= win
              && (!f.ip || !s.ip || f.ip === s.ip));
            if (hit) {
              transitions.push({ user: f.user, fail: f, succ: hit });
            }
          }
          if (transitions.length) {
            const cap = rowCap(15);
            // Dedupe per (user, succ.ts) to surface unique escalations.
            const seen = new Set();
            const dedup = [];
            for (const t of transitions) {
              const k = (t.user || '') + '|' + (t.succ.ts || 0);
              if (seen.has(k)) continue;
              seen.add(k);
              dedup.push(t);
            }
            let block = '\n### Failed → successful logon transitions\n';
            block += '_4625 followed by 4624 within 24h for the same user. Strong brute-force / password-spray indicator._\n\n';
            block += '| User | First 4625 | First 4624 | Δ | IP | Workstation |\n';
            block += '|------|-----------|-----------|---|----|-------------|\n';
            for (const t of dedup.slice(0, cap)) {
              const dt = (t.succ.ts && t.fail.ts) ? _fmtDur(t.succ.ts - t.fail.ts) : '—';
              block += `| ${_tp(t.user)} | ${_ts(t.fail.ts)} | ${_ts(t.succ.ts)} | ${dt} | ${_tp(t.succ.ip || t.fail.ip || '—')} | ${_tp(t.succ.workstation || t.fail.workstation || '—')} |\n`;
            }
            if (dedup.length > cap) block += `\n_… and ${dedup.length - cap} more transition${dedup.length - cap === 1 ? '' : 's'}._\n`;
            out.push(block);
          }
        }
      }

      // ── Network triples (Sysmon EID 3) + beacon cadence ──
      if (agg.netHits.length) {
        // Group by (image, dstIp:dstPort) and compute inter-arrival
        // stats. A near-uniform delta is a beacon hint.
        const groups = new Map();
        for (const n of agg.netHits) {
          if (!n.image || !n.dstIp) continue;
          const k = (n.image || '').toLowerCase() + '|' + n.dstIp + ':' + (n.dstPort || '');
          let g = groups.get(k);
          if (!g) {
            g = { image: n.image, dstIp: n.dstIp, dstPort: n.dstPort, dstHost: n.dstHost, hits: [] };
            groups.set(k, g);
          }
          g.hits.push(n.ts);
        }
        const enriched = [];
        for (const g of groups.values()) {
          const ts = g.hits.filter(Number.isFinite).sort((a, b) => a - b);
          let beacon = null;
          if (ts.length >= 4) {
            const deltas = [];
            for (let i = 1; i < ts.length; i++) deltas.push(ts[i] - ts[i - 1]);
            const mean = deltas.reduce((a, b) => a + b, 0) / deltas.length;
            const variance = deltas.reduce((a, b) => a + (b - mean) * (b - mean), 0) / deltas.length;
            const stddev = Math.sqrt(variance);
            // Coefficient of variation < 0.25 ⇒ uniform cadence.
            if (mean > 0 && (stddev / mean) < 0.25 && mean > 5000) {
              beacon = { interval: mean, jitterPct: Math.round((stddev / mean) * 100) };
            }
          }
          enriched.push({
            image: g.image, dstIp: g.dstIp, dstPort: g.dstPort, dstHost: g.dstHost,
            count: g.hits.length, first: ts[0] || NaN, last: ts[ts.length - 1] || NaN, beacon,
          });
        }
        // Beacons first, then high-volume non-beacon.
        enriched.sort((a, b) => {
          if (!!b.beacon !== !!a.beacon) return b.beacon ? 1 : -1;
          return b.count - a.count;
        });
        const cap = rowCap(20);
        const slice = enriched.slice(0, cap);
        if (slice.length) {
          let block = '\n### Network connections (Sysmon EID 3)\n';
          block += '| Image | Destination | Hits | First | Last | Beacon |\n';
          block += '|-------|-------------|-----:|-------|------|--------|\n';
          for (const e of slice) {
            const dst = e.dstIp + (e.dstPort ? ':' + e.dstPort : '') + (e.dstHost ? ` (${e.dstHost})` : '');
            const beaconText = e.beacon
              ? `~${_fmtDur(e.beacon.interval)} ±${e.beacon.jitterPct}%`
              : '—';
            block += `| ${_tp(_short(e.image, 90))} | ${_tp(_short(dst, 90))} | ${e.count} | ${_ts(e.first)} | ${_ts(e.last)} | ${_tp(beaconText)} |\n`;
          }
          if (enriched.length > slice.length) block += `\n_… and ${enriched.length - slice.length} more connection group${enriched.length - slice.length === 1 ? '' : 's'}._\n`;
          out.push(block);
        }
      }

      // ── Audit / log tampering ──
      if (agg.auditHits.length) {
        const cap = rowCap(20);
        let block = '\n### Audit-policy / log-clear events\n';
        block += '_High-signal: cleared logs (1102), audit-policy changes (4719), domain-policy changes (4739)._\n\n';
        block += '| Time | EID | Channel | User |\n|------|----:|---------|------|\n';
        const slice = agg.auditHits.slice(0, cap);
        for (const a of slice) {
          block += `| ${_ts(a.ts)} | ${_tp(a.eid)} | ${_tp(a.channel)} | ${_tp(a.user || '—')} |\n`;
        }
        if (agg.auditHits.length > slice.length) block += `\n_… and ${agg.auditHits.length - slice.length} more audit event${agg.auditHits.length - slice.length === 1 ? '' : 's'}._\n`;
        out.push(block);
      }

      // ── Persistence drops ──
      if (agg.persistHits.length) {
        const cap = rowCap(20);
        let block = '\n### Persistence drops (services / scheduled tasks / autorun keys)\n';
        const slice = agg.persistHits.slice(0, cap);
        for (const p of slice) {
          if (p.kind === 'service') {
            block += `- ⚙ Service install @ ${_ts(p.ts)} — \`${_tp(_short(p.name || '', 100))}\``
              + (p.image ? ` → \`${_tp(_short(p.image, 200))}\`` : '')
              + (p.startType ? ` (start: ${_tp(p.startType)})` : '')
              + (p.account ? ` by ${_tp(p.account)}` : '') + '\n';
          } else if (p.kind === 'task') {
            block += `- ⏲ Scheduled task @ ${_ts(p.ts)} — \`${_tp(_short(p.name || '', 100))}\``
              + (p.user ? ` by ${_tp(p.user)}` : '')
              + (p.content ? ` — content: \`${_tp(_short(p.content, 160))}\`` : '') + '\n';
          } else if (p.kind === 'registry') {
            block += `- 🗝 Registry @ ${_ts(p.ts)} — \`${_tp(_short(p.name, 200))}\``
              + (p.image ? ` by ${_tp(_short(p.image, 120))}` : '')
              + (p.user ? ` (${_tp(p.user)})` : '') + '\n';
          }
        }
        if (agg.persistHits.length > slice.length) block += `\n_… and ${agg.persistHits.length - slice.length} more persistence event${agg.persistHits.length - slice.length === 1 ? '' : 's'}._\n`;
        out.push(block);
      }

      // ── PowerShell suspicious script blocks ──
      if (agg.psHits.length) {
        const cap = rowCap(10);
        let block = '\n### PowerShell activity\n';
        const slice = agg.psHits.slice(0, cap);
        for (const p of slice) {
          block += `- @ ${_ts(p.ts)} EID ${_tp(p.eid)} — \`${_tp(_short(p.script, 220))}\`\n`;
        }
        if (agg.psHits.length > slice.length) block += `\n_… and ${agg.psHits.length - slice.length} more PowerShell event${agg.psHits.length - slice.length === 1 ? '' : 's'}._\n`;
        out.push(block);
      }

      // ── Defender alerts ──
      if (agg.defHits.length) {
        const cap = rowCap(15);
        let block = '\n### Microsoft Defender alerts\n';
        block += '| Time | EID | Threat | Path | Severity | Action |\n';
        block += '|------|----:|--------|------|----------|--------|\n';
        const slice = agg.defHits.slice(0, cap);
        for (const d of slice) {
          block += `| ${_ts(d.ts)} | ${_tp(d.eid)} | ${_tp(_short(d.threat, 80))} | ${_tp(_short(d.path, 120))} | ${_tp(d.severity)} | ${_tp(d.action)} |\n`;
        }
        if (agg.defHits.length > slice.length) block += `\n_… and ${agg.defHits.length - slice.length} more Defender event${agg.defHits.length - slice.length === 1 ? '' : 's'}._\n`;
        out.push(block);
      }

      if (!out.length) return '';
      return '\n## Relationships\n' + out.join('');
    },

    // ── Section: Time clusters ─────────────────────────────────────
    _tlsBuildTimeClusters(agg, rowCap /*, charCap */) {
      if (!Number.isFinite(agg.first) || !Number.isFinite(agg.last) || agg.last === agg.first) return '';
      // Lightweight whole-file histogram — fixed 24-bucket span over
      // the entire range so the LLM gets a coarse activity picture
      // without paying for the chart pipeline.
      const N = 24;
      const span = agg.last - agg.first;
      const w = span / N;
      const buckets = new Array(N).fill(0);
      const tm = this._timeMs;
      if (!tm || !tm.length) return '';
      for (let i = 0; i < tm.length; i++) {
        const v = tm[i];
        if (!Number.isFinite(v)) continue;
        let idx = Math.floor((v - agg.first) / w);
        if (idx < 0) idx = 0;
        if (idx >= N) idx = N - 1;
        buckets[idx]++;
      }
      const top = [];
      for (let i = 0; i < N; i++) top.push({ idx: i, count: buckets[i] });
      top.sort((a, b) => b.count - a.count);
      const hot = top.slice(0, rowCap(5)).filter(x => x.count > 0);
      let s = '\n## Time clusters\n';
      s += `_Whole-file histogram across ${N} equal-width buckets (~${_fmtDur(w)} each)._\n\n`;
      s += '| # | Window start | Window end | Events |\n|---|--------------|-----------|-------:|\n';
      for (const h of hot) {
        const lo = agg.first + h.idx * w;
        const hi = lo + w;
        s += `| ${h.idx + 1} | ${_ts(lo)} | ${_ts(hi)} | ${h.count.toLocaleString()} |\n`;
      }
      return s;
    },

    // ── Section: Cross-reference block ─────────────────────────────
    // Plain bullet lists tuned for fast cross-correlation against
    // other timelines / log sources (downstream LLM grep, threat-intel
    // pivots).
    _tlsBuildCrossRef(agg, rowCap /*, charCap */) {
      const m = agg.ent;
      const SECTIONS = [
        { type: IOC.USERNAME, label: 'Usernames', cap: rowCap(60) },
        { type: IOC.HOSTNAME, label: 'Hostnames', cap: rowCap(40) },
        { type: IOC.IP, label: 'IP addresses', cap: rowCap(60) },
        { type: IOC.DOMAIN, label: 'Domains', cap: rowCap(40) },
        { type: IOC.URL, label: 'URLs', cap: rowCap(40) },
        { type: IOC.HASH, label: 'Hashes', cap: rowCap(60) },
        { type: IOC.REGISTRY_KEY, label: 'Registry keys', cap: rowCap(30) },
      ];
      const parts = [];
      for (const sec of SECTIONS) {
        const map = m.get(sec.type);
        if (!map || !map.size) continue;
        const arr = [...map.entries()]
          .sort((a, b) => (_SEV_RANK[b[1].severity] || 0) - (_SEV_RANK[a[1].severity] || 0)
                       || b[1].count - a[1].count);
        const slice = arr.slice(0, sec.cap);
        let block = `\n### ${sec.label}\n`;
        for (const [val] of slice) block += `- \`${_tp(_short(val, 240))}\`\n`;
        if (arr.length > slice.length) block += `- _… and ${arr.length - slice.length} more_\n`;
        parts.push(block);
      }
      if (!parts.length) return '';
      return '\n## Cross-reference block\n_For pivoting against other log sources / timelines / threat-intel feeds._\n' + parts.join('');
    },
  });
}());
