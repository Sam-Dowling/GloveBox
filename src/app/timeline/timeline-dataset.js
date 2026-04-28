'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-dataset.js — owns the four parallel-array slots that make up a
// loaded Timeline view: the base RowStore, per-row parsed timestamps,
// the optional EVTX side-channel, and any user/auto-extracted virtual
// columns. Centralises the "every parallel array has length === rowCount"
// invariant that previously lived as a series of separate fields on
// `TimelineView`.
//
// ─── WHY ──────────────────────────────────────────────────────────────────
// Before this class existed, `TimelineView` carried five things in
// parallel-array shape:
//
//   • this.store           — RowStore, the base columns
//   • this._timeMs         — Float64Array of parsed timestamps
//   • this._evtxEvents     — Array<object> for EVTX side-channel reads
//   • this._extractedCols  — Array<{name, values: string[]}>
//   • this._chipFilteredIdx / this._sortedFullIdx / this._filteredIdx
//                          — Uint32 permutation indexes (NOT owned here;
//                            those are render-state and live on the view)
//
// The **first four** must all be `length === store.rowCount`. The fifth
// is permutation state (orig→visible mapping), separate concern. The
// only enforcement of the cardinality invariant was via convention plus
// a single ad-hoc check in the TimelineView constructor (added in commit
// 9b10618 after the EVTX sync-path bug). Each new parallel-array slot
// added since RowStore (`_timeMs`, `_evtxEvents`, `_extractedCols`) was
// a fresh place where a future caller could desync without the language
// or the build catching it.
//
// `TimelineDataset` makes the invariant unrepresentable: every
// constructor + mutation method re-asserts the cardinality. Read-side
// callers (timeline-summary, timeline-detections, the grid-render path)
// will migrate to `dataset.cellAt(orig, col)` / `timeAt(orig)` /
// `evtxAt(orig)` / `extractedAt(orig, e)` in subsequent commits, at
// which point reaching into the underlying slots becomes a hand-tagged
// exception rather than the default.
//
// ─── WHAT THIS CLASS DOES NOT OWN ─────────────────────────────────────────
// • Render permutations (`_filteredIdx`, `_sortedFullIdx`, etc). Those
//   are concerns of the filter/sort pipeline — see `_recomputeFilter`
//   in `timeline-view.js`. The dataset takes an `origIdx` everywhere;
//   the view does the orig↔visible translation.
// • The `TimelineRowView` adapter for GridViewer. That adapter wraps
//   `{baseStore, extractedCols, baseLen, idx}` to satisfy GridViewer's
//   `rowCount`/`getCell`/`getRow` shape; it predates this dataset and
//   is independent (the dataset's read API is consumed by Timeline-
//   internal code paths, not by GridViewer).
// • Time-domain semantics (`_timeIsNumeric`, the chrono-sorted full
//   index). Those live on the view because they're computed from time
//   parse results plus user state (column choice, bucket size).
//
// ─── BUNDLE ORDER ─────────────────────────────────────────────────────────
// Loaded by `scripts/build.py` between `timeline-row-view.js` and
// `timeline-wheel.js`, and BEFORE `timeline-view.js` (which holds an
// instance and forwards reads through it). The class has no static
// dependencies — it references only built-in types (Float64Array,
// Array) and the shape of `RowStore` (rowCount, getCell, columns,
// colCount). Pure, side-effect-free, NOT loaded into the worker
// bundle: the worker builds RowStore + timeMs + evtx events as
// separate transferables and posts them; the dataset wrapper is
// consumed only on the main thread when the view is constructed.
// ════════════════════════════════════════════════════════════════════════════

class TimelineDataset {
  /**
   * @param {object}                              opts
   * @param {RowStore}                            opts.store          — required.
   * @param {Float64Array=}                       opts.timeMs         — `length === store.rowCount` (or null/undefined to allocate).
   * @param {Array<object>|null=}                 opts.evtxEvents     — EVTX side-channel; null/absent for non-EVTX views.
   * @param {Array<{name:string,values:string[],kind?:string,sourceCol?:number}>=}
   *                                              opts.extractedCols  — defaults to `[]`.
   */
  constructor(opts) {
    if (!opts || !opts.store || typeof opts.store.getCell !== 'function') {
      throw new TypeError('TimelineDataset: opts.store must be a RowStore-shaped object');
    }
    this._store = opts.store;
    // `_timeMs` is allocated up front (caller still has to populate it via
    // `_parseAllTimestamps`); the dataset only enforces "same length as
    // rowCount". Allow caller to pass a pre-built typed array (e.g. a
    // worker-streamed result) or to defer allocation by passing null.
    if (opts.timeMs == null) {
      this._timeMs = new Float64Array(this._store.rowCount);
    } else if (opts.timeMs instanceof Float64Array) {
      this._timeMs = opts.timeMs;
    } else {
      throw new TypeError(
        'TimelineDataset: opts.timeMs must be a Float64Array (got ' +
        Object.prototype.toString.call(opts.timeMs) + ')',
      );
    }
    // `_evtxEvents` is the EVTX-only side-channel. Null for CSV/SQLite
    // views. When present, MUST match store.rowCount — that's the
    // invariant the §2.1 bug violated on the sync EVTX path.
    if (opts.evtxEvents == null) {
      this._evtxEvents = null;
    } else if (Array.isArray(opts.evtxEvents)) {
      this._evtxEvents = opts.evtxEvents;
    } else {
      throw new TypeError(
        'TimelineDataset: opts.evtxEvents must be an Array or null (got ' +
        Object.prototype.toString.call(opts.evtxEvents) + ')',
      );
    }
    // Extracted virtual columns. Each entry is
    // `{name, values: string[], kind?, sourceCol?, ...}`. The dataset
    // only validates `values.length === store.rowCount`; the rest of
    // the entry is opaque payload that callers attach for their own
    // purposes (regex source, JSON path, persistence keys, ...).
    //
    // The dataset takes the array BY REFERENCE (no slice) so that the
    // owning view can keep its existing `this._extractedCols.push(...)`
    // / `.splice(...)` mutation patterns during the migration window
    // (B1b/B1c). Once consumers have migrated to dataset reads, the
    // view's mutations move through `addExtractedCol` /
    // `removeExtractedCol` / `clearExtractedCols` and the array
    // becomes truly private to the dataset (B1d).
    this._extractedCols = Array.isArray(opts.extractedCols)
      ? opts.extractedCols
      : [];
    this._validate();
  }

  // ── Read API ────────────────────────────────────────────────────────────

  /** @returns {number} */
  get rowCount() { return this._store.rowCount; }

  /** @returns {RowStore} the underlying base RowStore (read-only access). */
  get store() { return this._store; }

  /** Number of base columns (the RowStore's column count). */
  get baseColCount() { return this._store.colCount; }

  /** Number of base + extracted virtual columns. */
  get totalColCount() { return this._store.colCount + this._extractedCols.length; }

  /**
   * Read cell at (origRow, totalCol) where `totalCol` may be a base or
   * extracted column index. Returns the empty string for OOB indices,
   * matching `RowStore.getCell` semantics.
   */
  cellAt(origRow, totalCol) {
    if (totalCol < 0 || totalCol >= this.totalColCount) return '';
    const baseLen = this._store.colCount;
    if (totalCol < baseLen) return this._store.getCell(origRow, totalCol);
    const e = this._extractedCols[totalCol - baseLen];
    if (!e || !e.values) return '';
    if (origRow < 0 || origRow >= this.rowCount) return '';
    const v = e.values[origRow];
    return v == null ? '' : String(v);
  }

  /**
   * Parsed timestamp for `origRow` in milliseconds-since-epoch (or the
   * raw numeric domain when `_timeIsNumeric` mode is active on the
   * owning view). Returns NaN for OOB indices and rows whose timestamp
   * column failed to parse.
   */
  timeAt(origRow) {
    if (origRow < 0 || origRow >= this.rowCount) return NaN;
    return this._timeMs[origRow];
  }

  /**
   * EVTX event object at `origRow`, or `null` for non-EVTX datasets and
   * OOB rows. Callers MUST treat the returned object as read-only —
   * mutating it would propagate into every subsequent read.
   */
  evtxAt(origRow) {
    if (!this._evtxEvents) return null;
    if (origRow < 0 || origRow >= this.rowCount) return null;
    return this._evtxEvents[origRow] || null;
  }

  /**
   * Read extracted-column entry by index (NOT by total col). Useful
   * for callers that already know they want an extracted col (top-
   * values, regex/JSON drawer). Returns `''` for OOB rows / cols.
   */
  extractedAt(origRow, extIdx) {
    if (extIdx < 0 || extIdx >= this._extractedCols.length) return '';
    if (origRow < 0 || origRow >= this.rowCount) return '';
    const e = this._extractedCols[extIdx];
    if (!e || !e.values) return '';
    const v = e.values[origRow];
    return v == null ? '' : String(v);
  }

  /** Read-only snapshot of the extracted-column metadata array. */
  extractedColumns() { return this._extractedCols.slice(); }

  /** Number of extracted virtual columns. */
  get extractedCount() { return this._extractedCols.length; }

  /**
   * Concatenation of base columns + extracted-column names. Used by the
   * grid + drawer when they need a single flat header array.
   */
  allColumnNames() {
    const out = this._store.columns.slice();
    for (const e of this._extractedCols) out.push(e.name);
    return out;
  }

  // ── Mutation API ────────────────────────────────────────────────────────
  //
  // The four parallel-array slots are settable BUT every setter
  // re-validates the cardinality invariant. There is no way to mutate
  // a slot via the dataset without re-asserting `length === rowCount`.
  //
  // These setters take REFERENCES, not copies — the dataset is a thin
  // wrapper, not a full-data clone. Callers that hand off a typed
  // array via `setTimeMs(arr)` are giving up ownership; mutating `arr`
  // afterwards still mutates the dataset's view.

  /** Replace the parsed-timestamp Float64Array. */
  setTimeMs(arr) {
    if (!(arr instanceof Float64Array)) {
      throw new TypeError('TimelineDataset.setTimeMs: arr must be a Float64Array');
    }
    if (arr.length !== this.rowCount) {
      throw new Error(
        'TimelineDataset.setTimeMs: arr.length (' + arr.length +
        ') must equal rowCount (' + this.rowCount + ')',
      );
    }
    this._timeMs = arr;
  }

  /**
   * Append an extracted-column descriptor. The entry's `values` array
   * MUST have `length === rowCount`. Returns the new total extracted-
   * column count for the caller's convenience.
   */
  addExtractedCol(entry) {
    if (!entry || !Array.isArray(entry.values)) {
      throw new TypeError(
        'TimelineDataset.addExtractedCol: entry must have a values:string[] array',
      );
    }
    if (entry.values.length !== this.rowCount) {
      throw new Error(
        'TimelineDataset.addExtractedCol: values.length (' + entry.values.length +
        ') must equal rowCount (' + this.rowCount + ')',
      );
    }
    this._extractedCols.push(entry);
    return this._extractedCols.length;
  }

  /** Remove the extracted column at `extIdx`. No-op for OOB indices. */
  removeExtractedCol(extIdx) {
    if (extIdx < 0 || extIdx >= this._extractedCols.length) return;
    this._extractedCols.splice(extIdx, 1);
  }

  /** Drop all extracted columns. Used by the "Reset extracted columns" path. */
  clearExtractedCols() {
    this._extractedCols.length = 0;
  }

  // ── Direct slot access (transitional) ───────────────────────────────────
  //
  // The migration plan (B1b/B1c) moves consumers off these slots one
  // file at a time. Until that lands, callers reach in via these
  // getters; once the migration is done, the migration-final commit
  // (B1d) drops the getters and the slots become truly private.

  /** @deprecated Use `cellAt` / `timeAt` / `evtxAt` / `extractedAt`. */
  get timeMs() { return this._timeMs; }
  /** @deprecated Use `evtxAt(orig)` (returns null for non-EVTX). */
  get evtxEvents() { return this._evtxEvents; }
  /** @deprecated Use `extractedAt` / `extractedColumns()`. */
  get extractedCols() { return this._extractedCols; }

  // ── Internal — invariant assertion ──────────────────────────────────────
  //
  // Single source of truth for the cardinality rule. Called from the
  // constructor (after slot assignments). Mutation methods re-assert
  // their own slot rather than calling this catch-all because (a) the
  // narrower error message is more useful at the failure site and
  // (b) re-walking every extracted-col on every add is O(n²) when many
  // columns are auto-extracted in a single tick.
  _validate() {
    const n = this.rowCount;
    if (this._timeMs.length !== n) {
      throw new Error(
        'TimelineDataset: timeMs.length (' + this._timeMs.length +
        ') must equal store.rowCount (' + n + ')',
      );
    }
    if (this._evtxEvents && this._evtxEvents.length !== n) {
      throw new Error(
        'TimelineDataset: evtxEvents.length (' + this._evtxEvents.length +
        ') must equal store.rowCount (' + n + '); ' +
        'caller forgot to slice events to the truncated list.length.',
      );
    }
    for (let i = 0; i < this._extractedCols.length; i++) {
      const e = this._extractedCols[i];
      if (!e || !Array.isArray(e.values)) {
        throw new TypeError(
          'TimelineDataset: extractedCols[' + i + '] must have a values:string[] array',
        );
      }
      if (e.values.length !== n) {
        throw new Error(
          'TimelineDataset: extractedCols[' + i + '].values.length (' +
          e.values.length + ') must equal store.rowCount (' + n + ')',
        );
      }
    }
  }
}
