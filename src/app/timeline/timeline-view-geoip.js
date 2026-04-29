'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-geoip.js — TimelineView prototype mixin: GeoIP enrichment.
//
// Adds a `<ipcol>.geo` column next to every detected IPv4 column on first
// open, populated by the active GeoIP provider on `this._app.geoip`. The
// provider is one of:
//
//   • `BundledGeoip`  — RIR-derived IPv4 → ISO-2 + country name. Always
//                       available (~140 K ranges, embedded in the bundle).
//   • `MmdbReader`    — user-uploaded MaxMind DB / DB-IP MMDB, persisted
//                       in IndexedDB via GeoipStore. Adds region + city.
//
// Both expose the same surface; this mixin is provider-agnostic.
//
// ── Detection — `_detectIpColumns` ──────────────────────────────────────────
// Walks every base column, sampling up to 200 rows. A column qualifies as
// "an IPv4 column" when ≥ 80 % of non-empty sampled cells parse as a strict
// dotted-quad. The threshold is the same auto-extract uses for URL / host
// proposals (timeline-view-autoextract.js); we picked it to match the
// analyst's existing "appears in most rows" intuition. False-positive cost
// (a numeric column happens to look like IPs): one wasted enrichment column
// the analyst can right-click → Remove. False-negative cost (real IP
// column missed): the analyst right-clicks → "Look up GeoIP" to force.
//
// ── Skip heuristic — `_classifyColumnNeighbourhood` ─────────────────────────
// If a column WITHIN ±3 positions of the IP column already looks like geo
// data, we skip enrichment for that IP. Two signals trigger skip:
//
//   • Header substring match (case-insensitive) on a known geo-header set
//     (`country`, `city`, `region`, `geo`, `iso`, `state`, …).
//   • Content match: any sampled cell that looks like ISO-2 / ISO-3 / a
//     country name from the provider's table, OR matches the slash-
//     delimited shape (`Country/ISO`, `Country/ISO/State/City`).
//
// The "looser ±3 window + EITHER signal" rule was the user's preference
// (recap step). Right-click → "Look up GeoIP" overrides the skip.
//
// ── Idempotence ─────────────────────────────────────────────────────────────
// Same `loupe_timeline_autoextract_done_<fileKey>` per-file marker the
// auto-extract pass uses, scoped through TimelineView._loadAutoExtractDoneFor
// / _saveAutoExtractDoneFor. So:
//
//   • First open of a file → enrichment runs, geo cols appear, marker set.
//   • Analyst removes a geo col → marker stays set → reopen does NOT
//     resurrect it (the canonical "deleted-stays-deleted" rule).
//   • Analyst right-clicks → "Look up GeoIP" → bypasses marker for that
//     specific column → forces re-enrichment.
//
// Dedup at the per-column level: `_geoipDuplicateFor(sourceCol)` walks
// `_extractedCols` for an existing `kind: 'geoip'` entry against the same
// `sourceCol`. Re-running enrichment after the analyst uploads a richer
// MMDB would otherwise pile up duplicate columns.
//
// ── Re-enrichment on provider change ────────────────────────────────────────
// When the user uploads / removes an MMDB in Settings, app-settings.js
// calls `_timelineCurrent._runGeoipEnrichment()`. If `_extractedCols`
// already has `kind: 'geoip'` columns for the same source IP cols, they
// are dropped first and rebuilt with the new provider's data. The done-
// marker is NOT respected on this path (it's a forced refresh).
//
// Bypass: nothing in this mixin pushes IOCs, mutates `app.findings`, or
// calls `EncodedContentDetector` / `pushIOC`. The Timeline route stays
// analyser-free. Geo cells are pure presentation data.
// ════════════════════════════════════════════════════════════════════════════

(function () {
  // ── IPv4 parser ────────────────────────────────────────────────────────
  // Strict dotted-quad: four octets, each 0-255, no leading zeros except
  // the literal "0". Matches the contract `BundledGeoip._parseIPv4` /
  // `MmdbReader._parseIPv4` use internally — share the same shape so the
  // detection sample agrees with what the provider will accept.
  function isStrictIPv4(s) {
    if (typeof s !== 'string') return false;
    const len = s.length;
    if (len < 7 || len > 15) return false;
    let octets = 0;
    let cur = 0;
    let curDigits = 0;
    for (let i = 0; i < len; i++) {
      const c = s.charCodeAt(i);
      if (c >= 48 && c <= 57) {
        if (curDigits === 0 && c === 48 && i + 1 < len && s.charCodeAt(i + 1) >= 48 && s.charCodeAt(i + 1) <= 57) {
          return false;
        }
        cur = cur * 10 + (c - 48);
        curDigits++;
        if (cur > 255 || curDigits > 3) return false;
      } else if (c === 46) {  // '.'
        if (curDigits === 0) return false;
        octets++;
        if (octets > 3) return false;
        cur = 0;
        curDigits = 0;
      } else {
        return false;
      }
    }
    return curDigits > 0 && octets === 3;
  }

  // ── Geo-header / geo-content recognisers (skip heuristic) ─────────────
  // Header tokens that, if present in a column name within ±3 of an IP
  // column, suppress automatic enrichment. Lower-cased, substring-matched
  // — `City`, `dst_city`, `geoCountry`, `LocationISO` all trigger.
  const GEO_HEADER_TOKENS = [
    'country', 'city', 'region', 'state', 'province',
    'geo', 'geoip', 'location', 'iso', 'continent',
  ];

  // Strict ISO-3166 alpha-2 / alpha-3 shape (uppercase letters only).
  // The full code tables are huge; the shape check is enough to count a
  // single cell as a "geo signal". A non-geo column that happens to
  // contain "AU" cells (e.g. user initials) might trip this — but only
  // when it ALSO sits ±3 from an IP column, which is enough of a
  // coincidence to be a useful skip.
  const ISO2_SHAPE_RE = /^[A-Z]{2}$/;
  const ISO3_SHAPE_RE = /^[A-Z]{3}$/;
  // Slash-delimited geo cell — what THIS module produces. Also recognises
  // pre-existing columns the analyst (or another tool) emitted. The regex
  // is forgiving on the trailing parts.
  const SLASH_GEO_RE = /^[A-Za-z][A-Za-z .'-]+\/[A-Z]{2}(?:\/[^/]+(?:\/[^/]+)?)?$/;

  function looksLikeGeoCell(s) {
    if (typeof s !== 'string') return false;
    const t = s.trim();
    if (!t) return false;
    if (t.length <= 4 && (ISO2_SHAPE_RE.test(t) || ISO3_SHAPE_RE.test(t))) return true;
    if (t.length >= 4 && t.length <= 80 && SLASH_GEO_RE.test(t)) return true;
    return false;
  }

  function looksLikeGeoHeader(name) {
    if (typeof name !== 'string') return false;
    const lower = name.toLowerCase();
    for (const tok of GEO_HEADER_TOKENS) {
      if (lower.indexOf(tok) >= 0) return true;
    }
    return false;
  }

  Object.assign(TimelineView.prototype, {

    // ── Public entry point ──────────────────────────────────────────────
    // Called from:
    //   • TimelineView constructor — once on first mount per view, gated
    //     by the auto-extract-done marker.
    //   • App init — when an MMDB has finished hydrating from IndexedDB
    //     after the view was already constructed.
    //   • app-settings.js — after the user uploads / removes an MMDB.
    //   • The right-click "Look up GeoIP" override on a column header.
    //
    // `opts.force` (optional): bypass the per-file done-marker AND drop
    // any existing `kind: 'geoip'` columns first. Used by Settings on
    // provider change and by the right-click override (which also passes
    // an explicit `forceCol` so the skip heuristic is ignored too).
    //
    // `opts.forceCol` (optional): index of a single base column to enrich
    // unconditionally — bypasses both the IPv4 detection threshold and
    // the skip heuristic. Used by the right-click override.
    _runGeoipEnrichment(opts) {
      if (this._destroyed) return;
      if (!this._app || !this._app.geoip) return;
      const provider = this._app.geoip;
      const force = !!(opts && opts.force);
      const forceCol = (opts && Number.isInteger(opts.forceCol)) ? opts.forceCol : -1;

      // The forced-refresh path drops existing geoip columns first so
      // the new provider's data takes their place at the same index.
      // Idempotent for the no-existing-cols case.
      if (force || forceCol >= 0) {
        this._dropAllGeoipCols();
      } else {
        // Per-file done-marker. Same key the auto-extract pass uses, so
        // an analyst who deleted an auto-extracted geo col and reopens
        // the file does NOT see it return.
        if (TimelineView._loadAutoExtractDoneFor(this._fileKey)) {
          // Marker set — but auto-extract may have predated provider
          // hydration. Only short-circuit if there's already at least
          // one geoip column (i.e. enrichment ran successfully before).
          if (this._extractedCols.some(e => e && e.kind === 'geoip')) return;
        }
      }

      const targetCols = (forceCol >= 0)
        ? [forceCol]
        : this._detectIpColumns();

      if (!targetCols.length) {
        // Nothing to do; only stamp the marker on the natural-detect path
        // so a forced override on a file with no auto-detected IP cols
        // doesn't poison future opens.
        if (!force && forceCol < 0) {
          TimelineView._saveAutoExtractDoneFor(this._fileKey);
        }
        return;
      }

      // Skip heuristic — only on the natural-detect path. The right-
      // click override is supposed to bypass this.
      const filtered = (forceCol >= 0)
        ? targetCols
        : targetCols.filter(c => !this._classifyColumnNeighbourhood(c));

      if (!filtered.length) {
        if (!force) TimelineView._saveAutoExtractDoneFor(this._fileKey);
        return;
      }

      let added = 0;
      for (const col of filtered) {
        if (this._enrichSingleIpCol(col, provider)) added++;
      }

      // Re-render once after the batch — enrichment of a multi-IP CSV
      // is otherwise N grid blinks for N source columns.
      if (added > 0) {
        try { this._rebuildExtractedStateAndRender(); } catch (_) { /* noop */ }
        if (this._app && typeof this._app._toast === 'function') {
          this._app._toast(
            `GeoIP enrichment: ${added} column${added === 1 ? '' : 's'} added`,
            'info'
          );
        }
      }

      // Mark the file as enriched so a deletion is sticky.
      if (!force && forceCol < 0) {
        TimelineView._saveAutoExtractDoneFor(this._fileKey);
      }
    },

    // ── IPv4 column detection ───────────────────────────────────────────
    // Returns the indices (in `this._baseColumns` space) of every column
    // where ≥ 80 % of non-empty sampled cells parse as strict IPv4.
    // Sample size: 200 rows or `store.rowCount`, whichever is smaller.
    _detectIpColumns() {
      if (!this.store || !this.store.rowCount || !this._baseColumns) return [];
      const baseCount = this._baseColumns.length;
      const sample = Math.min(this.store.rowCount, 200);
      const out = [];
      for (let c = 0; c < baseCount; c++) {
        let nonEmpty = 0;
        let hits = 0;
        for (let r = 0; r < sample; r++) {
          const v = this.store.getCell(r, c);
          if (!v) continue;
          nonEmpty++;
          if (isStrictIPv4(v)) hits++;
        }
        // Require at least 8 non-empty samples to reduce false positives
        // on very-sparse columns. Files with < 8 rows pass through
        // unconditionally if every populated cell is an IP.
        if (nonEmpty >= 8 && (hits / nonEmpty) >= 0.8) out.push(c);
        else if (nonEmpty < 8 && nonEmpty > 0 && hits === nonEmpty) out.push(c);
      }
      return out;
    },

    // ── Skip heuristic ──────────────────────────────────────────────────
    // True ⇒ column `colIdx` is adjacent to existing geo data and should
    // be skipped on the natural-detect path.
    _classifyColumnNeighbourhood(colIdx) {
      const baseCount = this._baseColumns.length;
      const lo = Math.max(0, colIdx - 3);
      const hi = Math.min(baseCount - 1, colIdx + 3);
      const sample = Math.min(this.store.rowCount, 60);
      for (let c = lo; c <= hi; c++) {
        if (c === colIdx) continue;
        if (looksLikeGeoHeader(this._baseColumns[c])) return true;
        // Content sample — short walk; first hit wins.
        for (let r = 0; r < sample; r++) {
          const v = this.store.getCell(r, c);
          if (looksLikeGeoCell(v)) return true;
        }
      }
      return false;
    },

    // ── Per-column enrichment ───────────────────────────────────────────
    // Build the values array, name it `<src>.geo`, and route the
    // append through the dataset (same path as `_addRegexExtractNoRender`
    // / `_addJsonExtractedColNoRender` use). Dedup is local to this
    // mixin via `_geoipDuplicateFor` so the central
    // `_findDuplicateExtractedCol` doesn't have to learn a third kind.
    //
    // Returns true if a column was added.
    _enrichSingleIpCol(srcCol, provider) {
      if (!provider || typeof provider.lookupIPv4 !== 'function') return false;
      if (this._geoipDuplicateFor(srcCol) >= 0) return false;
      // `srcCol` may point at a base column OR an extracted column
      // (auto-extracted IP fields, right-click forced enrichment). Resolve
      // the source name through the unified column space so both work.
      let baseName;
      if (this._isExtractedCol(srcCol)) {
        const ext = this._extractedColFor(srcCol);
        baseName = (ext && ext.name) || ('col' + srcCol);
      } else {
        baseName = this._baseColumns[srcCol] || ('col' + srcCol);
      }
      const name = this._uniqueColName(baseName + '.geo');
      const N = this.store.rowCount;
      const values = new Array(N);
      // Tiny per-IP cache — the same address typically appears many
      // times in a log. Costs O(unique-IPs) memory; saves O(N) provider
      // lookups for high-cardinality logs.
      const cache = new Map();
      for (let r = 0; r < N; r++) {
        // Use `_cellAt` so this works for both base columns (sourceCol <
        // baseColCount) and extracted columns (sourceCol >= baseColCount).
        const ip = this._cellAt(r, srcCol);
        if (!ip) { values[r] = ''; continue; }
        let formatted = cache.get(ip);
        if (formatted === undefined) {
          let rec = null;
          try { rec = provider.lookupIPv4(ip); } catch (_) { rec = null; }
          formatted = rec ? provider.formatRow(rec) : '';
          cache.set(ip, formatted);
        }
        values[r] = formatted;
      }
      this._dataset.addExtractedCol({
        name,
        kind: 'geoip',
        sourceCol: srcCol,
        values,
        // Stamp the provider kind so we can tell (in tests, in future
        // export rows) which provider produced this column. Not read
        // anywhere on the hot path.
        providerKind: provider.providerKind || 'unknown',
      });
      // Insert the new geo column directly AFTER its IPv4 source in the
      // grid's display order. Without this nudge, `_updateColumns` (the
      // GridViewer in-place patch path) would append the new real-index
      // to the end of `_colOrder`, leaving the geo column visually
      // detached from the IP it enriches — analysts then have to drag it
      // every time they open a file with a non-trailing IPv4 column.
      // Persistence is intentionally NOT triggered: geo-insert is an
      // automatic placement choice, not a user-elected order. The user's
      // own drags are what hit `loupe_timeline_grid_col_order` (via
      // `onColumnReorder` → `_saveGridColOrderFor`).
      try { this._insertColAfterInDisplay(srcCol, name); } catch (_) { /* decorative only */ }
      return true;
    },

    // Mutate `this._gridColOrder` (an array of column NAMES) so that
    // `newName` lands immediately after the column at real index
    // `srcRealIdx`. Bootstraps a starter identity-order names array
    // when no saved order yet exists. Does NOT persist — see comment
    // at the call site in `_enrichSingleIpCol`.
    //
    // If `srcRealIdx` is out of range or the source name can't be
    // found in the current names array, the new name is appended at
    // the end (which is the same outcome `_updateColumns` produces
    // without our intervention — safe fallback).
    _insertColAfterInDisplay(srcRealIdx, newName) {
      if (!newName || typeof newName !== 'string') return;
      const cols = this.columns;
      if (!Array.isArray(cols) || !cols.length) return;
      // Resolve source column NAME. The geo column was just appended,
      // so it lives at the LAST slot of `cols`; everything before it
      // is the previous schema. `srcRealIdx` is in that previous space
      // (it's a base column index, or an index into already-extracted
      // cols — strictly less than `cols.length - 1`).
      const srcName = (Number.isInteger(srcRealIdx) && srcRealIdx >= 0 && srcRealIdx < cols.length)
        ? cols[srcRealIdx]
        : null;
      if (!srcName) return;
      // Bootstrap starter names array if no saved order yet exists.
      // Identity order EXCLUDING the just-appended geo column (it gets
      // spliced in below). This becomes the first `_gridColOrder`
      // value for files that had no user reorder before geo enrichment.
      if (!Array.isArray(this._gridColOrder) || !this._gridColOrder.length) {
        const starter = [];
        for (let i = 0; i < cols.length; i++) {
          const nm = cols[i];
          if (nm === newName) continue;
          starter.push(nm || ('col' + i));
        }
        this._gridColOrder = starter;
      }
      const order = this._gridColOrder;
      // Drop any prior entry for `newName` (defensive — an earlier
      // forced-refresh pass could leave a stale slot).
      for (let i = order.length - 1; i >= 0; i--) {
        if (order[i] === newName) order.splice(i, 1);
      }
      // Insert immediately after the source name; if not found, append.
      const srcPos = order.indexOf(srcName);
      if (srcPos < 0) order.push(newName);
      else order.splice(srcPos + 1, 0, newName);
    },

    _geoipDuplicateFor(sourceCol) {
      const cols = this._extractedCols || [];
      for (let i = 0; i < cols.length; i++) {
        const e = cols[i];
        if (e && e.kind === 'geoip' && e.sourceCol === sourceCol) return i;
      }
      return -1;
    },

    // Drop every `kind: 'geoip'` column. Called on forced refresh
    // (provider swap) so the rebuild lands at the same logical slot.
    // Walks back-to-front so splice indices stay stable.
    _dropAllGeoipCols() {
      const cols = this._extractedCols || [];
      const baseLen = this._dataset ? this._dataset.baseColCount : this._baseColumns.length;
      for (let i = cols.length - 1; i >= 0; i--) {
        const e = cols[i];
        if (e && e.kind === 'geoip') {
          // Strip query clauses targeting the column index it currently
          // occupies (base + i), mirroring `_removeExtractedCol`.
          this._queryRemoveClausesForCols([baseLen + i]);
          this._dataset.removeExtractedCol(i);
        }
      }
    },
  });
})();
