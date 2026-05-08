'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-sources.js — `SourceRecord` factories + per-merge utilities.
//
// A `SourceRecord` is the per-file blob the composite Timeline works
// against. It carries: parsed data (baseStore / baseTimeMs / optional
// evtxEvents), schema hints (formatKind / formatLabel / baseColumns /
// timeCol / stackCol), side-channels (evtxFindings), and UI state
// (enabled / color / sourceLabel). See full shape + invariants in the
// "SourceRecord shape" section of the merged-Timeline plan.
//
// Factories here wrap the existing per-format parsers — they don't
// duplicate parse logic. Every factory returns a Promise<SourceRecord>
// and never touches DOM / App / `_timelineCurrent`.
//
// Loads AFTER `timeline-view-factories.js` (reuses
// `TimelineView.fromCsvAsync` / `fromEvtx` / `fromStructuredLogAsync`
// as pre-parse helpers — those build a TimelineView-shaped intermediate
// whose fields we destructure into a SourceRecord). Also AFTER
// `timeline-mapper.js` (source records carry `_colIdxCache` lazily
// populated by mapper reads) and AFTER `timeline-composite.js`.
//
// The design choice to wrap `TimelineView.fromXxx` rather than re-
// implement is deliberate: those factories encapsulate ~1500 lines of
// tokeniser wiring, fallback logic, truncation handling, and IP-column
// detection. Running them and discarding the TimelineView part keeps
// the new surface small. The discarded view is never mounted — its
// `_root` never materialises because we never call `view.root()`.
// ════════════════════════════════════════════════════════════════════════════

// Stable source-color palette. Picked to be colour-blind friendly and
// distinguishable under Loupe's six themes. The chip bar cycles
// through this list by source index; when `length > palette.length` we
// wrap and rely on the source label for disambiguation.
//
// 32 entries (doubled from the original 16) — wrap-collision risk is
// now effectively zero for realistic analyst workflows (hard cap of
// 16 merged sources; soft cap of 8). Keeping 32 here gives a
// comfortable headroom if the caps are ever raised, and every chip +
// breadcrumb popover swatch + chart legend entry for a given source
// always lands on the SAME colour for the session because the
// monotonic source-id indexes directly into this array via modulo.
const TIMELINE_SOURCE_PALETTE = Object.freeze([
  // Original 16 — Tableau 20 / Category 10 inspired, muted saturations
  // that work on both light and dark panel backgrounds.
  '#4e79a7', '#f28e2b', '#59a14f', '#e15759', '#76b7b2',
  '#edc948', '#b07aa1', '#ff9da7', '#9c755f', '#bab0ac',
  '#1f77b4', '#d62728', '#2ca02c', '#ff7f0e', '#9467bd',
  '#8c564b',
  // Extended 16 — complementary hues filling gaps in the original
  // distribution (teal, indigo, magenta, olive, cyan, amber, rose,
  // brown, periwinkle, mint, salmon, steel, forest, mauve, sand,
  // coral) so a 17+ source merge still gets a distinct chip colour.
  '#17becf', '#393b79', '#d62789', '#8c6d31', '#31a354',
  '#bd9e39', '#e7969c', '#7b4173', '#a55194', '#6b6ecf',
  '#9ecae1', '#fd8d3c', '#756bb1', '#bcbd22', '#bd9a28',
  '#e377c2',
]);

function _tlsMonotonicId() {
  if (_tlsMonotonicId._next == null) _tlsMonotonicId._next = 1;
  return _tlsMonotonicId._next++;
}

// Resolve a unique label for a source. First tries the bare filename;
// appends " (2)", " (3)", ... against an `existingLabels` set to
// disambiguate.
function _tlsDedupLabel(desired, existingLabels) {
  let base = desired || 'source';
  if (!existingLabels.has(base)) return base;
  let i = 2;
  while (existingLabels.has(base + ' (' + i + ')')) i++;
  return base + ' (' + i + ')';
}

// Compute the stable per-file key used for session-only composite
// carry-over. Mirrors `_tlFileKey` semantics (name|size|lastModified).
function _tlsComputeFileKey(file) {
  if (!file) return '';
  const nm = file.name || '';
  const sz = typeof file.size === 'number' ? file.size : 0;
  const lm = file.lastModified || 0;
  return nm + '|' + sz + '|' + lm;
}

// Build a SourceRecord from an intermediate TimelineView (produced by
// one of the existing `fromXxx` factories). The view is NOT mounted;
// it was constructed purely to run the parse + `_parseAllTimestamps`
// pass. We destructure its fields into the SourceRecord and then
// destroy the view wrapper so its heavy data references don't linger.
function _tlsFromView(file, formatKind, view, existingLabels) {
  if (!view || !view.store) {
    throw new Error('timeline-sources: parse produced no store for .' + formatKind);
  }
  const sourceId = _tlsMonotonicId();
  const baseLabel = file && file.name ? file.name : ('source ' + sourceId);
  const sourceLabel = _tlsDedupLabel(baseLabel, existingLabels);
  const color = TIMELINE_SOURCE_PALETTE[
    (sourceId - 1) % TIMELINE_SOURCE_PALETTE.length];
  const record = {
    file,
    fileKey:   _tlsComputeFileKey(file),
    sourceId,
    sourceLabel,
    formatLabel: view.formatLabel || '',
    formatKind,
    baseColumns:  Array.from(view._baseColumns || view.columns || []),
    baseStore:    view.store,
    baseTimeMs:   view._timeMs,
    baseTimeIsNumeric: !!view._timeIsNumeric,
    timeCol:      Number.isInteger(view._timeCol) ? view._timeCol : 0,
    stackCol:     Number.isInteger(view._stackCol) ? view._stackCol : 1,
    evtxEvents:   view._evtxEvents || null,
    evtxFindings: view._evtxFindings || null,
    ipColumns:    Array.isArray(view._ipColumns) ? view._ipColumns.slice() : [],
    enabled:      true,
    color,
    truncated:    !!view.truncated,
    originalRowCount: view.originalRowCount || view.store.rowCount,
    _zeekPath:    view.formatLabel && /^Zeek/.test(view.formatLabel) ? view.formatLabel.replace(/^Zeek\s*/, '') : null,
  };
  // Wipe the view's references so the parsed RowStore / typed arrays
  // are uniquely owned by the SourceRecord and can be released via
  // `releaseSourceRecord()` without a stale back-reference pinning
  // them to the dead view.
  view._timeMs = null;
  view.store = null;
  view._evtxEvents = null;
  view._baseColumns = null;
  view._extractedCols = null;
  return record;
}

// Public factory. Dispatches on `formatKind` to the appropriate
// `TimelineView.fromXxx` intermediate parser. Returns a
// Promise<SourceRecord>. `existingLabels` is a Set of labels already
// used in the current merge — used to dedup filename collisions.
async function timelineSourceFromFile(file, buffer, formatKind, existingLabels) {
  let view = null;
  if (formatKind === 'evtx') {
    view = await TimelineView.fromEvtx(file, buffer);
  } else if (formatKind === 'csv' || formatKind === 'tsv' || formatKind === 'log') {
    const explicit = formatKind === 'tsv' ? '\t' : (formatKind === 'log' ? ' ' : null);
    view = await TimelineView.fromCsvAsync(
      file, buffer, explicit, formatKind === 'log' ? 'log' : null);
  } else if (formatKind === 'syslog3164' || formatKind === 'syslog5424'
          || formatKind === 'zeek' || formatKind === 'jsonl'
          || formatKind === 'cloudtrail' || formatKind === 'cef'
          || formatKind === 'leef' || formatKind === 'logfmt'
          || formatKind === 'w3c' || formatKind === 'apache-error'
          || formatKind === 'access-log') {
    view = await TimelineView.fromStructuredLogAsync(file, buffer, formatKind);
  } else {
    throw new Error('timeline-sources: unsupported merge formatKind=' + formatKind);
  }
  const labels = existingLabels instanceof Set
    ? existingLabels
    : new Set(Array.isArray(existingLabels) ? existingLabels : []);
  return _tlsFromView(file, formatKind, view, labels);
}

// Release heavy references so GC can reclaim the parsed bytes. Called
// when a source is removed from a merged Timeline (trash icon in chip
// bar) or when the whole view is destroyed.
function releaseSourceRecord(record) {
  if (!record) return;
  record.baseStore = null;
  record.baseTimeMs = null;
  record.evtxEvents = null;
  record.evtxFindings = null;
  record._colIdxCache = null;
}

if (typeof window !== 'undefined') {
  window.TIMELINE_SOURCE_PALETTE = TIMELINE_SOURCE_PALETTE;
  window.timelineSourceFromFile = timelineSourceFromFile;
  window.releaseSourceRecord = releaseSourceRecord;
  window._tlsComputeFileKey = _tlsComputeFileKey;
  window._tlsDedupLabel = _tlsDedupLabel;
}
