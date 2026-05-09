'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-composite.js — composite RowStore builder for merged Timelines.
//
// When a Timeline holds ≥1 sources, the view needs ONE RowStore whose
// rows are a concatenation of every enabled source's rows, each row
// carrying:
//
//   [ canonicalCells (TIMELINE_CANONICAL_COLS) | nativeCells (composite plane) ]
//
// The canonical cells are produced by the per-format mapper
// (`timeline-mapper.js`). The native cells either:
//   • occupy a FUSED column (shared across sources with compatible name
//     + content-shape), populated only for rows whose source has that
//     column, or
//   • occupy a SOURCE-SPECIFIC column (namespaced `<sourceLabel>·<col>`)
//     populated only for rows from that source, empty elsewhere.
//
// Co-located with this build:
//   • `buildCompositeSchema(sources)`   — resolves canonical + native
//     column layout, returns the column-assignment plan.
//   • `buildCompositeStore(sources, plan)` — streams every enabled
//     source's rows through its mapper + plan into a fresh
//     `RowStore`. Byte-intensive; runs main-thread post-parse.
//   • `buildCompositeTime(sources)`     — concats `baseTimeMs` arrays.
//   • `buildSourceOfRow(sources)`       — Uint32 mapping composite row
//     → source index (stable: re-derived after every toggle).
//   • `buildEnabledBitmap(sources, sourceOfRow)` — per-row 0/1 mask for
//     toggled-off sources. ANDed into `_chipFilteredIdx` inside
//     `_recomputeFilter`.
//   • `sortCompositeByTime(timeMs)`     — `Uint32Array` chrono sort.
//
// Mixed `baseTimeIsNumeric` across sources is REFUSED at schema-build
// time (`buildCompositeSchema` throws a typed Error that the router
// catches and surfaces as a toast). Merging a numeric-axis file (e.g. a
// CSV where the timestamp column is a sequence number) with a
// wall-clock file (EVTX) has no useful interpretation.
//
// Loads AFTER `src/row-store.js` (uses `RowStore` / `RowStoreBuilder`),
// AFTER `src/constants.js` (uses `TIMELINE_CANONICAL_COLS`), AFTER
// `timeline-mapper.js` (uses `timelineMapperFor`, `timelineColumnsCanFuse`).
//
// NOT in the worker bundle — mapping happens main-thread only.
// ════════════════════════════════════════════════════════════════════════════

// ── Schema resolver ────────────────────────────────────────────────────────

// Sample up to N non-empty values from a source's column. Used by the
// fusion predicate. Stays allocation-light — we only need enough to
// call `_tlmClassify` deterministically.
function _tlcSampleColumn(source, baseColIdx, limit) {
  const out = [];
  const store = source.baseStore;
  if (!store) return out;
  const n = Math.min(store.rowCount, limit || 200);
  for (let i = 0; i < n; i++) {
    const v = store.getCell(i, baseColIdx);
    if (v !== '') {
      out.push(v);
      if (out.length >= (limit || 200)) break;
    }
  }
  return out;
}

// Build the composite column schema + per-source mapping plan.
//
// Returns:
//   {
//     timeIsNumeric,    // bool — shared across sources
//     canonicalCols,    // TIMELINE_CANONICAL_COLS (always leading)
//     nativeCols,       // array of composite-native column descriptors:
//                       //   { name, kind: 'fused'|'namespaced', sources: [{sourceIdx, baseColIdx}] }
//     compositeColumns, // string[] — the final column list for RowStore (canonical + native)
//     sourceColPlans,   // array, one per source:
//                       //   [{ canonicalIdx: Map<canonicalColName, int>,
//                       //      nativeEmit: [{ compositeColIdx, baseColIdx }] }]
//   }
//
// Throws:
//   `Error('timeline-composite: mixed-time-domain merge')` when any two
//   sources disagree on `baseTimeIsNumeric`.
function buildCompositeSchema(sources) {
  if (!Array.isArray(sources) || !sources.length) {
    throw new Error('timeline-composite: sources must be a non-empty array');
  }

  // Gate 0 — time domain consistency.
  const first = sources[0];
  const tn = !!first.baseTimeIsNumeric;
  for (let i = 1; i < sources.length; i++) {
    if (!!sources[i].baseTimeIsNumeric !== tn) {
      const e = new Error(
        'timeline-composite: mixed-time-domain merge — ' +
        'cannot merge a numeric-axis source with a wall-clock source');
      e.code = 'MIXED_TIME_DOMAIN';
      throw e;
    }
  }

  const canonicalCols = Array.from(TIMELINE_CANONICAL_COLS);

  // Gather candidate native columns per source. Key by lowercase
  // trimmed name so case-differing headers still collide.
  //
  // `bySameName[normName]` = array of { sourceIdx, baseColIdx, origName }
  const bySameName = new Map();
  for (let s = 0; s < sources.length; s++) {
    const src = sources[s];
    const cols = src.baseColumns || [];
    for (let c = 0; c < cols.length; c++) {
      const origName = String(cols[c] || '');
      const norm = origName.trim().toLowerCase();
      if (!norm) continue;
      if (!bySameName.has(norm)) bySameName.set(norm, []);
      bySameName.get(norm).push({ sourceIdx: s, baseColIdx: c, origName });
    }
  }

  // Build native-column descriptors. Per name-key, decide fuse vs
  // namespace by pairwise fusion predicate; the first entry anchors
  // the group and each subsequent entry fuses into it iff it passes
  // the predicate against the anchor, otherwise gets its own
  // namespaced column.
  const nativeCols = [];
  // Iterate in stable source-then-column order so the composite
  // column list is deterministic (cheaper to diff in tests, saner UX).
  const seenNormNames = new Set();
  for (let s = 0; s < sources.length; s++) {
    const src = sources[s];
    const cols = src.baseColumns || [];
    for (let c = 0; c < cols.length; c++) {
      const origName = String(cols[c] || '');
      const norm = origName.trim().toLowerCase();
      if (!norm) continue;
      if (seenNormNames.has(norm)) continue;
      seenNormNames.add(norm);
      const group = bySameName.get(norm);  // every entry carrying this name
      const anchor = group[0];
      const anchorSrc = sources[anchor.sourceIdx];
      const anchorSamples = _tlcSampleColumn(anchorSrc, anchor.baseColIdx, 200);
      const fuseMembers = [{ sourceIdx: anchor.sourceIdx, baseColIdx: anchor.baseColIdx }];
      const namespacedMembers = [];
      for (let g = 1; g < group.length; g++) {
        const cand = group[g];
        const candSrc = sources[cand.sourceIdx];
        const candSamples = _tlcSampleColumn(candSrc, cand.baseColIdx, 200);
        const canFuse = timelineColumnsCanFuse(
          { formatKind: anchorSrc.formatKind, name: norm, samples: anchorSamples },
          { formatKind: candSrc.formatKind, name: norm, samples: candSamples });
        if (canFuse) fuseMembers.push({ sourceIdx: cand.sourceIdx, baseColIdx: cand.baseColIdx });
        else namespacedMembers.push(cand);
      }
      nativeCols.push({
        name: anchor.origName,
        kind: fuseMembers.length > 1 ? 'fused' : 'single',
        sources: fuseMembers,
      });
      // Any member that failed the fuse gets its own namespaced column.
      for (let n = 0; n < namespacedMembers.length; n++) {
        const m = namespacedMembers[n];
        const mSrc = sources[m.sourceIdx];
        const nsName = (mSrc.sourceLabel || ('src' + m.sourceIdx))
          + '·' + m.origName;
        nativeCols.push({
          name: nsName,
          kind: 'namespaced',
          sources: [{ sourceIdx: m.sourceIdx, baseColIdx: m.baseColIdx }],
        });
      }
    }
  }

  // ── Empty-canonical-column cull (merged views only) ──────────────────
  //
  // `TIMELINE_CANONICAL_COLS` is a fixed 9-entry list — but for any
  // given set of sources only a subset of canonical columns will
  // actually be populated by the per-format mappers. Keeping empty
  // canonicals in the composite schema wastes grid real-estate and
  // makes the "merged Timeline" view visibly cluttered with 100%-empty
  // columns (e.g. a CSV/CSV merge where neither side carries IPs
  // would otherwise show empty `SourceIP` / `DestIP` columns).
  //
  // For merged views (n≥2) we run a bounded sample-probe: for each
  // canonical column (other than `__source` — always kept when n≥2;
  // it discriminates rows by origin which is the whole point of the
  // merged surface), check whether ANY source's mapper emits a
  // non-empty value in a 50-row sample. Canonicals whose sample
  // yields zero hits across every source get dropped from
  // `canonicalCols` entirely — they never enter the RowStore, never
  // surface in the grid, never clutter the column picker.
  //
  // Single-source views (n=1) SKIP the cull — their canonical columns
  // are instead hidden by default via `_gridColOrder` so a subsequent
  // merge that adds a source capable of populating a canonical
  // brings it back cleanly without needing schema surgery.
  //
  // Sample size (50 rows) is bounded so this is O(sources × 50 × 9)
  // ≈ O(thousands of ops) regardless of total row count. False-negative
  // risk: a source that populates canonical `Host` only for rows >50
  // would have `Host` culled; the failure mode is benign (an
  // occasionally-empty column survives the cull — same as today).
  // In practice every source's mapper either populates a canonical
  // consistently (header-driven probe) or not at all (no matching
  // column name), so the first-50-rows probe is essentially a
  // schema-check.
  const CULL_SAMPLE_ROWS = 50;
  const ALWAYS_KEEP_CANONICAL = new Set(['__source']);
  const culledCanonicalCols = [];
  if (sources.length >= 2) {
    for (let i = 0; i < canonicalCols.length; i++) {
      const name = canonicalCols[i];
      if (ALWAYS_KEEP_CANONICAL.has(name)) {
        culledCanonicalCols.push(name);
        continue;
      }
      // Probe: does ANY source emit a non-empty value for this
      // canonical key in its first `CULL_SAMPLE_ROWS` mapped rows?
      let populated = false;
      for (let s = 0; s < sources.length && !populated; s++) {
        const src = sources[s];
        const mapper = timelineMapperFor(src.formatKind);
        const store = src.baseStore;
        if (!store) continue;
        const rc = Math.min(store.rowCount, CULL_SAMPLE_ROWS);
        const baseColCount = store.colCount;
        const rowBuf = new Array(baseColCount);
        for (let r = 0; r < rc; r++) {
          store.getRowInto(r, rowBuf);
          const mapped = mapper(src, rowBuf);
          const v = mapped && mapped[name];
          if (v != null && v !== '') { populated = true; break; }
        }
      }
      if (populated) culledCanonicalCols.push(name);
    }
  } else {
    // n=1: keep all canonicals (default-hide handled elsewhere).
    for (let i = 0; i < canonicalCols.length; i++) {
      culledCanonicalCols.push(canonicalCols[i]);
    }
  }
  // Replace the unfiltered canonical list with the culled one and
  // rebuild the canonical → index map against the new compact layout.
  const keptCanonical = culledCanonicalCols.slice();
  const keptCanonicalIndex = new Map();
  for (let i = 0; i < keptCanonical.length; i++) {
    keptCanonicalIndex.set(keptCanonical[i], i);
  }

  // Assemble the composite column list.
  const compositeColumns = keptCanonical.slice();
  for (let i = 0; i < nativeCols.length; i++) {
    compositeColumns.push(nativeCols[i].name);
  }

  // Build per-source plan: canonical index map + native-emit list.
  // `canonicalIdx` points at the CULLED canonical layout so the
  // mapper emitter below indexes into the correct composite slot
  // (or gets `undefined` for a culled key and silently skips it).
  const sourceColPlans = [];
  for (let s = 0; s < sources.length; s++) {
    const plan = { canonicalIdx: keptCanonicalIndex, nativeEmit: [] };
    for (let n = 0; n < nativeCols.length; n++) {
      const nc = nativeCols[n];
      for (let k = 0; k < nc.sources.length; k++) {
        if (nc.sources[k].sourceIdx === s) {
          plan.nativeEmit.push({
            compositeColIdx: keptCanonical.length + n,
            baseColIdx: nc.sources[k].baseColIdx,
          });
          break;  // one match per (source, native col) pair
        }
      }
    }
    sourceColPlans.push(plan);
  }

  return {
    timeIsNumeric: tn,
    canonicalCols: keptCanonical,
    nativeCols,
    compositeColumns,
    sourceColPlans,
  };
}

// ── Composite RowStore builder ─────────────────────────────────────────────

// Build a RowStore spanning every source's rows, populated via mapper +
// schema plan. Rows appear in source-add order (NOT time-sorted); the
// view's `_sortedFullIdx` handles chronology.
//
// Heap profile: allocates one `string[]` of length `compositeColumns.length`
// per source row, then delegates to `RowStoreBuilder.addRow`. The
// builder packs rows into chunks (~50k rows / 16 MB each) so peak
// intermediate allocation stays bounded even for multi-million-row
// merges.
function buildCompositeStore(sources, plan) {
  const builder = new RowStoreBuilder(plan.compositeColumns);
  const totalCols = plan.compositeColumns.length;
  // Pre-compute canonical col name → composite col index.
  // (plan.canonicalIdx is shared by every source's plan.)
  const canonicalIdx = plan.sourceColPlans[0]
    ? plan.sourceColPlans[0].canonicalIdx
    : new Map();

  // Per-source scratch row buffer (re-used for the mapper input only).
  // The output cell buffer MUST be freshly allocated per row because
  // `RowStoreBuilder.addRow` pushes references into a pending queue and
  // flushes them in batches — re-using one scratch array would leave
  // every pending row pointing at the last iteration's cells.
  const baseRowBuf = [];

  for (let s = 0; s < sources.length; s++) {
    const src = sources[s];
    const srcPlan = plan.sourceColPlans[s];
    const mapper = timelineMapperFor(src.formatKind);
    const store = src.baseStore;
    if (!store) continue;
    const rc = store.rowCount;
    const baseColCount = store.colCount;
    baseRowBuf.length = baseColCount;
    const sourceLabel = src.sourceLabel || '';
    // Pre-resolve canonical indices so the inner loop is straight-line.
    const iSource = canonicalIdx.get('__source');

    for (let r = 0; r < rc; r++) {
      // Fresh per-row cell buffer — see note above on builder batching.
      const cellBuf = new Array(totalCols);
      for (let c = 0; c < totalCols; c++) cellBuf[c] = '';
      store.getRowInto(r, baseRowBuf);

      // Stamp `__source` for every row (uniform). Format identity is
      // intentionally NOT a canonical column — the source filename
      // already conveys it and the per-chip format badge in the
      // source-bar covers the explicit case.
      if (iSource != null) cellBuf[iSource] = sourceLabel;

      // Project canonical cells via the format-specific mapper.
      const mapped = mapper(src, baseRowBuf);
      if (mapped) {
        for (const k in mapped) {
          const idx = canonicalIdx.get(k);
          if (idx != null) {
            const v = mapped[k];
            cellBuf[idx] = v == null ? '' : String(v);
          }
        }
      }

      // Emit this source's native cells into their composite positions.
      const emit = srcPlan.nativeEmit;
      for (let e = 0; e < emit.length; e++) {
        const cc = emit[e];
        const v = baseRowBuf[cc.baseColIdx];
        cellBuf[cc.compositeColIdx] = v == null ? '' : String(v);
      }

      builder.addRow(cellBuf);
    }
  }

  return builder.finalize();
}

// ── Time + bitmap + sort helpers ───────────────────────────────────────────

// Concatenate per-source `baseTimeMs` into a single Float64Array. The
// resulting array is aligned row-for-row with the composite RowStore
// built by `buildCompositeStore`.
function buildCompositeTime(sources) {
  let total = 0;
  for (let i = 0; i < sources.length; i++) {
    const t = sources[i].baseTimeMs;
    if (t) total += t.length;
  }
  const out = new Float64Array(total);
  let pos = 0;
  for (let i = 0; i < sources.length; i++) {
    const t = sources[i].baseTimeMs;
    if (!t || !t.length) continue;
    out.set(t, pos);
    pos += t.length;
  }
  return out;
}

// Build a Uint32 mapping from composite row → source index.
function buildSourceOfRow(sources) {
  let total = 0;
  for (let i = 0; i < sources.length; i++) {
    const s = sources[i].baseStore;
    if (s) total += s.rowCount;
  }
  const out = new Uint32Array(total);
  let pos = 0;
  for (let i = 0; i < sources.length; i++) {
    const s = sources[i].baseStore;
    if (!s) continue;
    const n = s.rowCount;
    for (let r = 0; r < n; r++) out[pos + r] = i;
    pos += n;
  }
  return out;
}

// Build the per-composite-row enabled bitmap (1 iff this row's source
// is enabled). ANDed into `_chipFilteredIdx` by `_recomputeFilter`.
// Cheap to rebuild (one pass over `sourceOfRow`) so toggle UI can call
// it synchronously on every checkbox flip.
function buildEnabledBitmap(sources, sourceOfRow) {
  const out = new Uint8Array(sourceOfRow.length);
  for (let i = 0; i < sourceOfRow.length; i++) {
    out[i] = sources[sourceOfRow[i]].enabled !== false ? 1 : 0;
  }
  return out;
}

// Chrono-sort helper — produces a Uint32Array of composite row indices
// sorted ascending by `timeMs`. NaNs sort LAST (stable-ish: JS Array
// sort isn't guaranteed stable in Array shape, but the typed-array
// path via ES2019+ is). Rows that failed to parse their timestamp land
// at the bottom of the grid when the user chooses chronological order,
// matching existing single-file Timeline behaviour.
function sortCompositeByTime(timeMs) {
  const n = timeMs.length;
  const idx = new Uint32Array(n);
  for (let i = 0; i < n; i++) idx[i] = i;
  // Typed-array `sort` accepts comparator; allocate once.
  idx.sort((a, b) => {
    const ta = timeMs[a];
    const tb = timeMs[b];
    const an = Number.isNaN(ta);
    const bn = Number.isNaN(tb);
    if (an && bn) return 0;
    if (an) return 1;
    if (bn) return -1;
    return ta < tb ? -1 : ta > tb ? 1 : 0;
  });
  return idx;
}

// ── Heap budget (cumulative, for drop-to-add) ──────────────────────────────
//
// `assertCompositeHeapOk(existingSources, newSource)` mirrors the
// single-file gate in `timeline-router.js` but sums every source's
// declared byte size and multiplies by
// `RENDER_LIMITS.TIMELINE_COMPOSITE_HEAP_OVERHEAD_FACTOR`. Throws a
// typed Error the caller turns into a toast. Silently passes on
// browsers without `performance.memory.jsHeapSizeLimit` (Firefox /
// Safari — their coarser gate in `timeline-router.js` still applies).
function assertCompositeHeapOk(existingSources, newSource) {
  let heapLimit = 0;
  try {
    if (typeof performance !== 'undefined'
        && performance.memory
        && typeof performance.memory.jsHeapSizeLimit === 'number') {
      heapLimit = performance.memory.jsHeapSizeLimit;
    }
  } catch (_) { /* introspection denied */ }
  if (!heapLimit) return;
  const budget = heapLimit * RENDER_LIMITS.ROWSTORE_HEAP_BUDGET_FRACTION;
  let sumSize = 0;
  for (let i = 0; i < existingSources.length; i++) {
    const f = existingSources[i] && existingSources[i].file;
    if (f && typeof f.size === 'number') sumSize += f.size;
  }
  if (newSource && newSource.file && typeof newSource.file.size === 'number') {
    sumSize += newSource.file.size;
  }
  const projected = sumSize * RENDER_LIMITS.TIMELINE_COMPOSITE_HEAP_OVERHEAD_FACTOR;
  if (projected > budget) {
    const pmb = (projected / (1024 * 1024)).toFixed(0);
    const bmb = (budget / (1024 * 1024)).toFixed(0);
    const e = new Error(
      'Merged Timeline would need ~' + pmb + ' MB of heap but only ~' +
      bmb + ' MB is available. Close other tabs or remove a source.');
    e.code = 'COMPOSITE_HEAP_EXCEEDED';
    throw e;
  }
}

// ── Globals ────────────────────────────────────────────────────────────────
if (typeof window !== 'undefined') {
  window.buildCompositeSchema = buildCompositeSchema;
  window.buildCompositeStore = buildCompositeStore;
  window.buildCompositeTime = buildCompositeTime;
  window.buildSourceOfRow = buildSourceOfRow;
  window.buildEnabledBitmap = buildEnabledBitmap;
  window.sortCompositeByTime = sortCompositeByTime;
  window.assertCompositeHeapOk = assertCompositeHeapOk;
}
