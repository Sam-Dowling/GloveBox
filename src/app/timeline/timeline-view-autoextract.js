'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-autoextract.js — TimelineView prototype mixin (B2e).
//
// Hosts the silent best-effort auto-extract pass that runs on first
// open and the heuristic scanner it consumes:
//
//   • `_autoExtractBestEffort` — the entry point. Runs the scanner
//     in one `requestIdleCallback` tick (or a `setTimeout(0)` Safari
//     fallback), then applies the high-confidence proposals one per
//     idle tick so the browser can paint between them. Each apply
//     calls `_rebuildExtractedStateAndRender` directly, which now
//     hands the new column array to the live GridViewer via
//     `_updateColumns` instead of destroying it — so the analyst
//     sees columns slide in one per idle frame rather than the
//     whole grid blinking out for a coalesced rebuild at the end.
//     The pass runs UNCONDITIONALLY on every file open: auto-
//     extracted columns are ephemeral (re-derived deterministically)
//     so re-running is correct. A toast-shown marker
//     (`loupe_timeline_autoextract_toast_shown_<fileKey>`) suppresses
//     the post-apply notification on reopens; the extraction itself
//     ignores the marker.
//
//   • `_applyAutoProposal` — the per-proposal apply, dispatching to
//     `_addJsonExtractedColNoRender` (json-url / json-host /
//     json-leaf), `_addRegexExtractNoRender` (text-url / text-host /
//     url-part), or a no-op for unknown kinds. Dedup is handled
//     inside the no-render helpers via `_findDuplicateExtractedCol`,
//     so re-running this for an already-extracted proposal is silent.
//
//   • `_autoExtractScan` — the read-only heuristic that walks up to
//     200 sample rows per base column and proposes JSON-leaf, URL,
//     URL-part, and text-host extractions. Returns proposals sorted
//     by `matchPct` descending. Pure (no side effects) — used both
//     here AND by the Auto tab inside `_openExtractionDialog`
//     (which sits in `timeline-view-popovers.js`).
//
// Build-order critical: this mixin calls
// `_addJsonExtractNoRender` / `_addRegexExtractNoRender` /
// `_rebuildExtractedStateAndRender` / `_findDuplicateExtractedCol`,
// all of which live in `timeline-drawer.js`. So
// `scripts/build.py` MUST register this file AFTER
// `timeline-drawer.js`. (The earlier B2 mixins all loaded between
// `timeline-view.js` and `timeline-detections.js`; this one breaks
// the pattern intentionally.)
//
// Bodies are moved byte-identically. The
// `requestIdleCallback`/`setTimeout(0)` idle-tick scheduling is
// performance-load-bearing — pinned by parity test below.
//
// Loads AFTER timeline-view.js (which declares `class TimelineView`).
// ════════════════════════════════════════════════════════════════════════════

Object.assign(TimelineView.prototype, {

  // ── Best-effort auto-extract ──────────────────────────────────────────
  // Replaces the old "nudge strip" prompt UX. On a freshly opened file
  // we silently apply the high-confidence subset of `_autoExtractScan()`
  // proposals so analysts get useful columns (URL host, JSON leaves,
  // EVTX forensic fields, …) without having to find + click an Extract
  // button. The full Extract Values dialog still exists for analysts
  // who want to opt into lower-coverage proposals manually.
  //
  // Eligibility — a proposal is auto-applied iff:
  //   • `matchPct >= 80`  (the analyst's "appears in most rows" rule), OR
  //   • EVTX file AND it's a `kv-field` whose name is in
  //     `TIMELINE_FORENSIC_EVTX_FIELDS_SET` (LogonType, IpAddress, …) —
  //     these are sparse-by-design but always investigatable, so we
  //     keep today's forensic-friendly defaults intact.
  //
  // Ranking + cap — eligible proposals are sorted by:
  //   1. kind priority: url-part / text-url / json-url → text-host /
  //      json-host → forensic kv-field → generic kv-field → json-leaf
  //   2. matchPct desc
  // …and (by default) ALL eligible proposals are applied. The cap of
  // 12 only kicks in when `_app._fileMeta.size >= LARGE_FILE_THRESHOLD`
  // (200 MB) — at that scale the per-proposal O(rows) cell-decode pass
  // adds up. Below 200 MB the analyst sees every extractable column so
  // they don't mistake the cap for "this is all the file has." Scanner-
  // internal soft caps (`JSON_LEAF_CAP = 60`, `KV_FIELD_CAP = 80` per
  // source column) still bound the proposal explosion at the source.
  //
  // Idempotence — auto-extracted columns are EPHEMERAL by design. The
  // pass runs on every file open and re-derives the same proposals
  // deterministically (the scanner is pure given the file content), so
  // there's no need to persist them. The toast notification ("Auto-
  // extracted N fields") would be noisy across reopens, so it's gated
  // on a one-shot per-file marker (`loupe_timeline_autoextract_toast_shown`)
  // that fires once on first open and stays silent after that.
  //
  // Why ephemeral? Because the regex-extracts persister (`_persistRegexExtracts`
  // in timeline-drawer.js) only stores `kind === 'regex'` entries — manual
  // Regex-tab work the analyst typed in by hand. The auto-extract pass
  // emits a mix of `kind: 'auto'` (text-host / text-url / kv-field /
  // url-part — regex-shaped, persistable) and `kind: 'json'` via the
  // JSON-leaf / json-host / json-url branches (path-shaped, NOT
  // persistable as a regex). Persisting only the regex-shaped half led
  // to silent column loss on reopen for JSON-shaped CSVs (10 of 12
  // columns vanished). Rather than introduce a parallel JSON-extract
  // persistence key, we just re-run the deterministic scanner — same
  // proposals, same outputs, no schema drift. Manual Regex-tab extracts
  // continue to persist via `_persistRegexExtracts`; the dedup inside
  // `_addJsonExtractedColNoRender` / `_addRegexExtractNoRender` ensures
  // re-running the auto pass against an already-replayed regex extract
  // is a silent no-op (user wins on overlap).
  //
  // Trade-off: the analyst can't "delete an auto-extracted column and
  // have it stay gone on reopen" — it'll come back. They CAN open the
  // Extract Values dialog and curate; they CAN add a manual Regex-tab
  // extract that persists. The Auto/Edit dialog's tick/untick
  // selections are session-only.
  //
  // Scheduling — historically this method ran the scan + every apply
  // synchronously after a 60 ms post-mount setTimeout. On 5M-row CSVs
  // that became a 4-5 s LongTask cluster (12 proposals × O(rows) cell
  // decodes through `_addJsonExtractedColNoRender` /
  // `_addRegexExtractNoRender`) immediately after the first paint —
  // the analyst saw the grid mount, then a long stall, then the toast,
  // then the columns slide in. Now the scan runs in one idle tick and
  // each proposal applies in its own subsequent idle tick. The total
  // CPU is unchanged, but the browser gets a paint frame between
  // proposals so the spinner stays smooth and the grid stays
  // scrollable. `requestIdleCallback` with a `setTimeout(0)` Safari
  // fallback mirrors `_scheduleIdleSearchTextBuild` in grid-viewer.js
  // (same handle bookkeeping idiom).
  _autoExtractBestEffort() {
    if (this._destroyed) return;
    if (!this._els || !this._els.host) return;
    // No extraction-side early-return. The auto-extract pass runs on
    // every file open; dedup inside the apply helpers handles overlap
    // with replayed manual regex extracts. The toast-shown marker is
    // read here but only consulted at the end of the apply loop to
    // suppress the toast — it does NOT gate the extraction itself.
    const toastShown = TimelineView._loadAutoExtractToastShownFor(this._fileKey);

    // Idle scheduler — pair the cancel API with the chosen scheduler so
    // `destroy()` doesn't have to remember which one we used. Stored on
    // `this._autoExtractIdleHandle` and cleared at the top of every
    // tick so a synchronous `destroy()` inside a callback doesn't leak
    // a stale record.
    const useIdle = typeof window !== 'undefined'
      && typeof window.requestIdleCallback === 'function';
    const schedule = (fn) => {
      if (useIdle) {
        const handle = window.requestIdleCallback(fn, { timeout: 1000 });
        return { cancel: () => { try { window.cancelIdleCallback(handle); } catch (_) { /* noop */ } } };
      }
      const handle = setTimeout(fn, 0);
      return { cancel: () => { try { clearTimeout(handle); } catch (_) { /* noop */ } } };
    };

    const scanStep = () => {
      this._autoExtractIdleHandle = null;
      if (this._destroyed) return;
      if (!this._els || !this._els.host) return;

      let proposals = [];
      try { proposals = this._autoExtractScan() || []; } catch (_) {
        // Scanner threw — bail. We don't stamp any persistent marker
        // here; the scanner is deterministic so it'll throw again next
        // open with the same input, and that's a real bug we want to
        // be loud about (in dev tools / debug mode) rather than masking
        // by stamping a "done" flag.
        return;
      }

      const isEvtx = this.formatLabel === 'EVTX'
        || (this._baseColumns && this._baseColumns.indexOf(EVTX_COLUMNS.EVENT_DATA) !== -1);

      const eligible = proposals.filter(p => {
        if ((p.matchPct || 0) >= 80) return true;
        if (isEvtx && p.kind === 'kv-field'
          && p.fieldName && TIMELINE_FORENSIC_EVTX_FIELDS_SET.has(p.fieldName)) return true;
        return false;
      });

      if (!eligible.length) {
        // No candidates met the bar — nothing to extract, nothing to
        // toast about. The scan is cheap (sample-capped at 200 rows)
        // so re-running it on every reopen of an unhelpful file is
        // affordable; no marker is set.
        return;
      }

      // Kind priority. URL-shaped values are typically the most
      // investigatable, so they win over generic JSON leaves; forensic
      // EVTX KV beats generic KV; KV beats raw json-leaf flattening.
      const kindRank = (p) => {
        if (p.kind === 'url-part' || p.kind === 'text-url' || p.kind === 'json-url') return 0;
        if (p.kind === 'text-host' || p.kind === 'json-host') return 1;
        if (p.kind === 'kv-field' && isEvtx
          && TIMELINE_FORENSIC_EVTX_FIELDS_SET.has(p.fieldName || '')) return 2;
        if (p.kind === 'kv-field') return 3;
        if (p.kind === 'json-leaf') return 4;
        return 9;
      };
      eligible.sort((a, b) => {
        const ka = kindRank(a), kb = kindRank(b);
        if (ka !== kb) return ka - kb;
        return (b.matchPct || 0) - (a.matchPct || 0);
      });

      // Size-conditional cap. Files ≥ LARGE_FILE_THRESHOLD (200 MB)
      // are kept on the historical 12-cap to avoid O(rows × proposals)
      // CPU blow-up; smaller files apply every eligible proposal so
      // the analyst sees the full extractable column set. File size
      // is read from `_app._fileMeta.size` (set by `timeline-router.js`
      // at load time); we treat a missing meta as "small" — the worst
      // case is that an unusually large file slips through uncapped,
      // which the apply pump still handles gracefully one idle tick
      // at a time.
      const fileSize = (this._app
        && this._app._fileMeta
        && Number.isFinite(this._app._fileMeta.size))
        ? this._app._fileMeta.size : 0;
      const HUGE_FILE_CAP = 12;
      const fileCapped = (fileSize >= RENDER_LIMITS.LARGE_FILE_THRESHOLD)
        ? eligible.slice(0, HUGE_FILE_CAP)
        : eligible;

      // Per-source-column cap. A single JSON blob with 30+ leaves
      // would otherwise generate 30+ extracted columns from one
      // source — the cascade is unbounded along the rank axis once
      // the global file-size cap doesn't fire. Capping at 12 per
      // source matches HUGE_FILE_CAP (the existing precedent for
      // "this is too many extracted cols to be useful") and keeps
      // the strongest 12 leaves per source so the analyst still
      // sees the top of every JSON column's cascade. Applied AFTER
      // the file-size cap so on huge files we keep the historical
      // 12-total semantics; smaller files now see ≤12 per source
      // instead of "every leaf that crossed the match-pct floor."
      const PER_SRC_CAP = 12;
      const perSrcCounts = new Map();
      const capped = [];
      for (const p of fileCapped) {
        const n = perSrcCounts.get(p.sourceCol) || 0;
        if (n >= PER_SRC_CAP) continue;
        perSrcCounts.set(p.sourceCol, n + 1);
        capped.push(p);
      }

      // Group proposals by `sourceCol` (stable — preserves rank order
      // within each group). Every proposal touches its source column
      // once per row via `_cellAt` → `RowStore._decodeAsciiSlice`; on a
      // 100k-row CSV with ~30 cols this single pass dominates the apply
      // budget (it shows up as the `_decodeAsciiSlice` hotspot in the
      // tab profile). Grouping lets `applyStep` decode each source
      // column ONCE per group and reuse the materialised `string[]`
      // across every proposal targeting that column.
      //
      // `Map` iteration is insertion-ordered, so the first proposal
      // (highest match-pct globally) keeps its leading slot and the
      // analyst sees the strongest column appear first — the user-
      // visible cascade ordering survives the regrouping.
      const bySource = new Map();
      for (const p of capped) {
        let bucket = bySource.get(p.sourceCol);
        if (!bucket) { bucket = []; bySource.set(p.sourceCol, bucket); }
        bucket.push(p);
      }
      const ranked = [];
      for (const bucket of bySource.values()) {
        for (const p of bucket) ranked.push(p);
      }
      let added = 0;
      let idx = 0;
      // Cache of decoded source columns. Populated lazily on the first
      // proposal of each `sourceCol` group and dropped at the group
      // boundary so we never hold onto more than one materialised
      // column at a time (each is `rowCount` strings — keeping all 30
      // would balloon memory on big files for no win).
      let cachedSrcCol = -1;
      let cachedSrcValues = null;

      const applyStep = () => {
        this._autoExtractIdleHandle = null;
        if (this._destroyed) {
          // Defensive: if a destroy raced the idle tick the flag would
          // otherwise stay true on this (now-orphaned) view. The flag
          // is read by `_rebuildExtractedStateAndRender`; clearing here
          // is belt-and-braces — `destroy()` clears it too.
          this._autoExtractApplying = false;
          return;
        }

        if (idx >= ranked.length) {
          // Apply pump finished. Drop the suppression flag so any
          // `_rebuildExtractedStateAndRender` from here onwards (e.g.
          // the GeoIP retry below, or a user clicking through the
          // Extract Values dialog) goes back to its normal task list.
          // Then schedule the deferred sweeps exactly once so all
          // suppressed surfaces refresh from the final column set
          // instead of churning per-proposal mid-pump:
          //   - 'columns' → Top Values strip recomputes column stats
          //   - 'chart'   → histogram redraws once with final stack
          //   - 'scrubber'/'chips' → cosmetic refresh of overlay state
          // The grid was already updated in-place during the pump.
          this._autoExtractApplying = false;
          this._scheduleRender(['columns', 'chart', 'scrubber', 'chips']);
          // Toast suppression: gated on the per-file `toast_shown`
          // marker captured at the top of `_autoExtractBestEffort`.
          // First open → toast fires + marker stamped. Reopens → no
          // toast (extraction itself ran unconditionally; dedup keeps
          // the count stable). `added > 0` guards the noisy zero-
          // result case where every proposal collided with a manually
          // persisted regex extract.
          if (added > 0 && !toastShown
              && this._app && typeof this._app._toast === 'function') {
            this._app._toast(`Auto-extracted ${added} field${added === 1 ? '' : 's'}`, 'info');
            TimelineView._saveAutoExtractToastShownFor(this._fileKey);
          }
          // Settle hook — auto-extract has fully landed. If the
          // initial GeoIP pass (constructor +100 ms) found no
          // IP-shaped BASE columns (`_geoipBaseDetectResult` is the
          // result-cache stamped by `_runGeoipEnrichment` on its
          // natural-detect path), retry detection over the extracted
          // columns we just installed and enrich whichever of them
          // is IPv4-shaped. This catches files where the IP lives
          // inside a JSON blob (json-leaf), an EVTX kv-field
          // (`SrcIp=…`), or any regex-extracted column. Skipped when
          // base detection already found IP cols (retry would be a
          // no-op) or no extracted cols were added (nothing new to
          // scan).
          if (added > 0
              && this._extractedCols && this._extractedCols.length
              && Array.isArray(this._geoipBaseDetectResult)
              && this._geoipBaseDetectResult.length === 0
              && typeof this._runGeoipEnrichment === 'function') {
            try {
              this._runGeoipEnrichment({ retryExtractedCols: true });
            } catch (_) { /* enrichment is additive */ }
            // Clear the gate so subsequent triggers (MMDB hydrate,
            // user upload, right-click) re-evaluate against the
            // current column set rather than this stale snapshot.
            this._geoipBaseDetectResult = null;
          }
          return;
        }

        const p = ranked[idx++];
        const before = this._extractedCols.length;
        // Materialise the source column on the first proposal of each
        // group, then reuse for every subsequent proposal in the
        // group. The lookahead at the group boundary (below) drops the
        // cache so we never carry it across to a new sourceCol — keeps
        // peak memory bounded to one extra `rowCount`-sized array.
        if (cachedSrcCol !== p.sourceCol) {
          cachedSrcCol = p.sourceCol;
          const n = this.store.rowCount;
          const buf = new Array(n);
          for (let i = 0; i < n; i++) buf[i] = this._cellAt(i, p.sourceCol);
          cachedSrcValues = buf;
        }
        try {
          this._applyAutoProposal(p, cachedSrcValues);
        } catch (e) {
          // Skip on error, keep going. Surface to console only when
          // the analyst has set `app.debug = true` so a regression in
          // the apply path is diagnosable without re-shipping.
          if (this._app && this._app.debug && typeof console !== 'undefined') {
            console.warn('[loupe] _applyAutoProposal threw:', e, 'proposal:', p);
          }
        }
        if (this._extractedCols.length > before) {
          added++;
          // Refresh per proposal — `_rebuildExtractedStateAndRender`
          // now patches the live GridViewer in place via
          // `_updateColumns` (no destroy/rebuild), so each idle tick
          // appears as one new column sliding into the existing grid.
          // Spreading the work across ticks (rather than coalescing a
          // single batched rebuild at the end) eliminates the visible
          // post-load "flash" — the analyst never sees the freshly-
          // mounted grid blink out and come back with extra columns.
          // The chart / chips / column-cards re-render is RAF-coalesced
          // by `_scheduleRender`, so per-tick rebuild churn is
          // bounded to the cheap `_buildHeaderCells` +
          // `_applyColumnTemplate` + `_forceFullRender` pass inside
          // `_updateColumns` (header cells are O(cols), not O(rows)).
          try {
            this._rebuildExtractedStateAndRender();
          } catch (e) {
            if (this._app && this._app.debug && typeof console !== 'undefined') {
              console.warn('[loupe] _rebuildExtractedStateAndRender threw:', e);
            }
          }
        }

        // Drop the source-column cache once the next proposal targets
        // a different column. `idx` has already been advanced, so
        // `ranked[idx]` is the next proposal (if any). Releasing the
        // reference keeps memory bounded to one cached column at a
        // time even on grids where the apply pump runs unbounded.
        const next = ranked[idx];
        if (!next || next.sourceCol !== cachedSrcCol) {
          cachedSrcValues = null;
          cachedSrcCol = -1;
        }
        // Note: we do NOT clear _jsonCache between source-column groups.
        // The cache is now keyed by (colIdx << 20 | rowIdx) so entries
        // from the finished group stay valid for any later non-pump caller
        // (Extract dialog, JSON-tree pick) that targets the same column.
        // Cross-column collisions are impossible with the compound key.

        // Yield between proposals — each `_applyAutoProposal` is itself
        // an O(rows) hot loop and will register as a LongTask on big
        // files, but the browser gets a paint frame and idle-callback
        // drain between them so the UI stays interactive.
        this._autoExtractIdleHandle = schedule(applyStep);
      };

      // Suppress per-proposal `'columns'` render scheduling for the
      // duration of the apply pump (read by
      // `_rebuildExtractedStateAndRender`). The terminating branch of
      // `applyStep` clears the flag and schedules `['columns']` exactly
      // once, so the Top Values strip populates from the final column
      // set rather than thrashing through ~N supersession-cancelled
      // sweeps mid-pump. Set here, AFTER the early-exit
      // `if (!eligible.length) return;` above, so a file with no
      // eligible proposals doesn't leave the flag stuck `true`.
      this._autoExtractApplying = true;
      this._autoExtractIdleHandle = schedule(applyStep);
    };

    this._autoExtractIdleHandle = schedule(scanStep);
  },

  // Apply a single proposal from `_autoExtractScan()` to the extracted-
  // column set without rendering. Caller is responsible for batching the
  // single `_rebuildExtractedStateAndRender()` after a multi-apply pass.
  // Dedup is handled inside `_addJsonExtractedColNoRender` /
  // `_addRegexExtractNoRender` via `_findDuplicateExtractedCol`, so
  // re-running this for an already-extracted proposal is a silent no-op.
  _applyAutoProposal(p, srcValues) {
    // Optional `srcValues` is a pre-decoded `string[]` of the proposal's
    // source column (length === store.rowCount). Threaded through from
    // `applyStep`, where the apply pump groups proposals by `sourceCol`
    // so a single decode pass amortises across every proposal in the
    // group. Helpers fall back to `_cellAt` when undefined / mismatched
    // — preserves the contract for direct callers (test fixtures,
    // future invocations).
    if (!p) return;
    if (p.kind === 'json-url' || p.kind === 'json-host' || p.kind === 'json-leaf') {
      this._addJsonExtractedColNoRender(p.sourceCol, p.path, p.proposedName, { autoKind: p.kind, srcValues });
    } else if (p.kind === 'text-url' || p.kind === 'text-host') {
      this._addRegexExtractNoRender({
        name: p.proposedName,
        col: p.sourceCol,
        pattern: (p.kind === 'text-url' ? TL_URL_RE.source : TL_HOSTNAME_INLINE_RE.source),
        flags: 'i',
        group: (p.kind === 'text-host') ? 1 : 0,
        kind: 'auto',
        srcValues,
      });
    } else if (p.kind === 'kv-field') {
      const esc = String(p.fieldName || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const pattern = `(?:^| \\| )${esc}=([\\s\\S]*?)(?= \\| [A-Za-z_][\\w.-]*=|$)`;
      this._addRegexExtractNoRender({
        name: p.proposedName,
        col: p.sourceCol,
        pattern,
        flags: '',
        group: 1,
        kind: 'auto',
        trim: true,
        srcValues,
      });
    } else if (p.kind === 'url-part') {
      this._addRegexExtractNoRender({
        name: p.proposedName,
        col: p.sourceCol,
        pattern: p.pattern,
        flags: '',
        group: p.group,
        kind: 'auto',
        srcValues,
      });
    }
  },
  // ── Auto-extract scanner ─────────────────────────────────────────────────

  _autoExtractScan() {
    const proposals = [];
    const sampleCap = Math.min(this.store.rowCount, 200);
    const cols = this._baseColumns.length;

    // EVTX detection: format label is "EVTX", or the base columns include
    // the synthesised "Event Data" column emitted by `fromEvtx`. When EVTX
    // is detected, the KV-field heuristic uses looser thresholds so sparse
    // but forensically-important fields (LogonType, UserAccountControl…)
    // surface in the dialog instead of being filtered out as noise.
    const isEvtx = this.formatLabel === 'EVTX'
      || (this._baseColumns && this._baseColumns.indexOf(EVTX_COLUMNS.EVENT_DATA) !== -1);

    // Forensics-grade EVTX fields: pre-selected by default (others stay
    // visible but unchecked) so analysts can Extract-selected and get a
    // tight investigatable column set without triaging 40 checkboxes.
    // Lifted to module scope (`TIMELINE_FORENSIC_EVTX_FIELDS_SET` in
    // timeline-helpers.js) so the best-effort auto-extract pass can also
    // gate on it.
    const FORENSIC_EVTX_FIELDS = TIMELINE_FORENSIC_EVTX_FIELDS_SET;

    // Browser-history SQLite — the `url` column gets three additional
    // `url-part` proposals (host / path / query) so analysts can split a
    // visited URL into its components with one click.
    const isBrowserHistory = typeof this.formatLabel === 'string'
      && this.formatLabel.indexOf('SQLite') === 0
      && this.formatLabel.indexOf('History') !== -1;

    for (let c = 0; c < cols; c++) {
      // Browser-history: emit url-part proposals for the `url` column
      // before the generic branches, so they appear at the top of the
      // list sorted by match %.
      if (isBrowserHistory && (this._baseColumns[c] || '').toLowerCase() === 'url') {
        const colName = this._baseColumns[c] || 'url';
        // Sample a value for the preview column.
        let sampleVal = '';
        for (let i = 0; i < Math.min(this.store.rowCount, 50); i++) {
          const v = this._cellAt(i, c);
          if (v) { sampleVal = v; break; }
        }
        const parts = [
          { sub: 'host', label: 'URL host', pattern: '^[a-z][a-z0-9+.\\-]*:\\/\\/([^\\/?#]+)', group: 1 },
          { sub: 'path', label: 'URL path', pattern: '^[a-z][a-z0-9+.\\-]*:\\/\\/[^\\/?#]+([^?#]*)', group: 1 },
          { sub: 'query', label: 'URL query', pattern: '\\?([^#]*)', group: 1 },
        ];
        for (const p of parts) {
          proposals.push({
            kind: 'url-part', kindLabel: p.label, sourceCol: c, path: null,
            subKind: p.sub, pattern: p.pattern, group: p.group,
            matchPct: 95,
            proposedName: `${colName}.${p.sub}`,
            sample: sampleVal,
            preselect: true,
          });
        }
      }

      // Sample cells.
      const samples = [];
      for (let i = 0; i < sampleCap; i++) {
        const v = this._cellAt(i, c);
        if (v !== '') samples.push({ i, v });
      }
      if (!samples.length) continue;

      // Determine: JSON-dominant column?
      let jsonOk = 0;
      const parsedList = new Array(samples.length);
      for (let i = 0; i < samples.length; i++) {
        const v = samples[i].v;
        if (_tlMaybeJson(v)) {
          try { parsedList[i] = JSON.parse(v); if (parsedList[i] != null && typeof parsedList[i] === 'object') jsonOk++; }
          catch (_) { parsedList[i] = null; }
        } else {
          parsedList[i] = null;
        }
      }
      if (jsonOk >= samples.length * 0.5 && jsonOk >= 3) {
        // Score path leaves.
        const pathStats = new Map();
        for (let i = 0; i < samples.length; i++) {
          const parsed = parsedList[i];
          if (parsed == null || typeof parsed !== 'object') continue;
          this._jsonCollectLeafPaths(parsed, [], (pathKey, path, v) => {
            let rec = pathStats.get(pathKey);
            if (!rec) { rec = { path: path.slice(), total: 0, url: 0, host: 0, sample: '' }; pathStats.set(pathKey, rec); }
            rec.total++;
            const vs = String(v);
            if (!rec.sample) rec.sample = vs;
            if (TL_URL_RE.test(vs)) rec.url++;
            else if (TL_HOSTNAME_RE.test(vs.trim())) rec.host++;
          }, 4);   // max depth
        }
        // Bounded enumeration of leaf paths → one proposal per distinct
        // leaf path, so the analyst can flatten an entire JSON column into
        // a set of CSV-like columns ("JSON → CSV"). URL / hostname paths
        // are already emitted above with their richer kind labels; all
        // other leaves fall through to the generic `json-leaf` proposal
        // here. Cap per-column to keep the Extract dialog readable on
        // pathological payloads.
        const JSON_LEAF_CAP = 60;
        let emittedLeaves = 0;
        for (const [, rec] of pathStats) {
          if (rec.total < Math.max(3, samples.length * 0.3)) continue;
          const isUrl = rec.url >= rec.total * 0.4;
          const isHost = !isUrl && rec.host >= rec.total * 0.4;
          if (isUrl) {
            proposals.push({
              kind: 'json-url', kindLabel: 'URL', sourceCol: c, path: rec.path,
              matchPct: rec.url * 100 / rec.total,
              proposedName: `${this._baseColumns[c] || 'col' + c}.${_tlJsonPathLabel(rec.path)}`,
              sample: rec.sample,
            });
          } else if (isHost) {
            proposals.push({
              kind: 'json-host', kindLabel: 'Hostname', sourceCol: c, path: rec.path,
              matchPct: rec.host * 100 / rec.total,
              proposedName: `${this._baseColumns[c] || 'col' + c}.${_tlJsonPathLabel(rec.path)}`,
              sample: rec.sample,
            });
          } else if (emittedLeaves < JSON_LEAF_CAP) {
            // Generic JSON leaf — lets the user flatten arbitrary nested
            // keys (`Events[*].EventID`, `response.status`, …) into
            // extracted columns via the Auto tab. Clamp to 100 because
            // `[*]` array recursion in `_jsonCollectLeafPaths` emits
            // one entry per element, so a path that touches every row
            // with multi-element arrays would otherwise exceed 100 %.
            proposals.push({
              kind: 'json-leaf', kindLabel: 'JSON leaf', sourceCol: c, path: rec.path,
              matchPct: Math.min(100, rec.total * 100 / samples.length),
              proposedName: `${this._baseColumns[c] || 'col' + c}.${_tlJsonPathLabel(rec.path)}`,
              sample: rec.sample,
            });
            emittedLeaves++;
          }
        }

      } else {
        // Pipe-delimited Key=Value detection — catches EVTX Event Data
        // (`TargetUserName=foo | SubjectUserName=bar | …`), Sysmon-style
        // key=value strings, and any other column whose cells encode an
        // ad-hoc mini-schema the analyst would otherwise have to rip
        // apart with hand-rolled regex. Runs BEFORE the URL/host branch
        // so KV-dominant columns don't also try to match whole-cell URLs
        // (noisy on EVTX) — if we detect enough KV rows we emit per-field
        // proposals and skip straight to the next column.
        //
        // Heuristic: split each cell on ` | ` (the exact separator emitted
        // by EvtxRenderer) and count parts starting with an identifier +
        // `=`. If ≥ 50 % of sampled rows have ≥ 2 such pairs, tally field
        // names across the whole sample and emit one `kv-field` proposal
        // per field that appears in ≥ 30 % of rows (min 3 occurrences).
        const KV_KEY_RE = /^([A-Za-z_][\w.-]{0,63})=/;
        const fieldStats = new Map();
        let kvRows = 0;
        for (const s of samples) {
          const parts = s.v.split(' | ');
          let pairs = 0;
          for (const part of parts) {
            const m = KV_KEY_RE.exec(part);
            if (!m) continue;
            pairs++;
            const name = m[1];
            let rec = fieldStats.get(name);
            if (!rec) {
              rec = { count: 0, sample: '' };
              fieldStats.set(name, rec);
            }
            rec.count++;
            if (!rec.sample) {
              const val = part.slice(m[0].length);
              // Keep the sample on a single line — multi-line values
              // (`UserAccountControl=\n%%2080\n…`) render fine as a
              // preview once collapsed.
              rec.sample = val.replace(/\s+/g, ' ').trim() || '(empty)';
            }
          }
          if (pairs >= 2) kvRows++;
        }
        // EVTX: lower the KV-dominance and per-field thresholds so sparse
        // but forensically important fields surface. On generic logs the
        // stricter 50 %/2 % defaults still apply — so a column that is only
        // occasionally `key=value` won't spuriously trigger.
        const kvDomFrac = isEvtx ? 0.1 : 0.5;
        const kvDominant = kvRows >= Math.max(3, samples.length * kvDomFrac);
        if (kvDominant && fieldStats.size) {
          const KV_FIELD_CAP = 80;
          const minCount = isEvtx
            ? Math.max(2, Math.floor(samples.length * 0.01))
            : Math.max(3, Math.floor(samples.length * 0.02));
          const ranked = Array.from(fieldStats.entries())
            .filter(([, rec]) => rec.count >= minCount)
            .sort((a, b) => b[1].count - a[1].count)
            .slice(0, KV_FIELD_CAP);
          for (const [name, rec] of ranked) {
            proposals.push({
              kind: 'kv-field', kindLabel: 'Field', sourceCol: c, path: null,
              fieldName: name,
              matchPct: rec.count * 100 / samples.length,
              proposedName: `${this._baseColumns[c] || 'col' + c}.${name}`,
              sample: rec.sample,
              // On EVTX, pre-check only forensic-grade fields so Extract-all
              // lands a tight investigatable set. Non-EVTX columns default
              // to checked so the classic "extract everything" flow still works.
              preselect: isEvtx ? FORENSIC_EVTX_FIELDS.has(name) : true,
            });
          }
          continue;   // skip URL / host probing on KV-dominant columns
        }

        // Plain-text column: test URL + hostname patterns directly.
        // Hostname detection uses the ANCHORED `TL_HOSTNAME_RE` (the
        // entire trimmed cell must look like a hostname), not the
        // unanchored inline variant. The unanchored form matched
        // hostname-shaped FRAGMENTS inside structured cells — most
        // visibly the `21.271Z` millisecond fragment of ISO-8601
        // timestamps (`2025-11-03T08:25:21.271Z`), which made every
        // CSV with a Timestamp column emit a junk `text-host` proposal.
        // Anchored matching is also a better fit for forensic CSVs
        // where each cell typically holds one structured value.
        // The EXTRACTION regex (`TL_HOSTNAME_INLINE_RE.source` in
        // `_applyAutoProposal` for `text-host`) stays unanchored so
        // legitimate hostname columns extract cleanly even when the
        // cell has stray surrounding whitespace.
        let urlHits = 0, hostHits = 0;
        let urlSample = '', hostSample = '';
        for (const s of samples) {
          if (TL_URL_RE.test(s.v)) { urlHits++; if (!urlSample) urlSample = s.v; }
          else {
            const trimmed = s.v.trim();
            if (TL_HOSTNAME_RE.test(trimmed)) {
              hostHits++;
              if (!hostSample) hostSample = trimmed;
            }
          }
        }
        const total = samples.length;
        if (urlHits >= Math.max(3, total * 0.3)) {
          proposals.push({
            kind: 'text-url', kindLabel: 'URL', sourceCol: c, path: null,
            matchPct: urlHits * 100 / total,
            proposedName: `${this._baseColumns[c] || 'col' + c} (URL)`,
            sample: urlSample,
          });
        }
        if (hostHits >= Math.max(3, total * 0.3) && !urlHits) {
          proposals.push({
            kind: 'text-host', kindLabel: 'Hostname', sourceCol: c, path: null,
            matchPct: hostHits * 100 / total,
            proposedName: `${this._baseColumns[c] || 'col' + c} (host)`,
            sample: hostSample,
          });
        }
      }
    }
    proposals.sort((a, b) => b.matchPct - a.matchPct);
    return proposals;
  },

});
