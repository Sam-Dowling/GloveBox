'use strict';
// ════════════════════════════════════════════════════════════════════════════
// row-store.js — flat-buffer, immutable-post-build row container shared by
// the Timeline pipeline (worker + main thread) and every GridViewer consumer
// (csv / sqlite / evtx renderers).
//
// ─── WHY ───────────────────────────────────────────────────────────────────
// The legacy grid container was `string[][]` — a JS array of JS arrays of
// JS strings. Every cell carries V8's per-string overhead (≈24 bytes on top
// of the UTF-16 char payload), every row carries per-array overhead
// (≈40 bytes), and the whole structure passes through structured-clone when
// it crosses the worker→main boundary. For a representative 1 000 000 × 10
// CSV with 80-char ASCII cells:
//
//                                 string[][]      RowStore
//   cell payload (decoded)        ~3.2 GB         (lazy decode)
//   per-string overhead           ~240 MB         0
//   per-row array overhead        ~40 MB          0
//   utf-8 cell bytes              —               ~840 MB
//   offsets                       —               ~40 MB
//   structured-clone working set  +full copy      0  (typed-array transfer)
//   ─────────────────────────────────────────────────────────────────────
//   peak main-heap footprint      ~4.1 GB         ~880 MB        (~4.7×)
//
// On Chromium with a ~4 GB per-renderer V8 heap cap, the legacy structure
// blew the cap on multi-hundred-MB CSVs and crashed the tab. RowStore is
// the dedicated container that fixes that.
//
// ─── DUAL HOME ─────────────────────────────────────────────────────────────
// This file is loaded BOTH:
//   1. into the main bundle via `APP_JS_FILES` in `scripts/build.py`,
//      immediately before `src/renderers/grid-viewer.js` (so every grid
//      consumer can build / read a RowStore); and
//   2. into the timeline parse-only worker bundle via
//      `_timeline_worker_bundle_src` in `scripts/build.py`, between
//      `timeline-worker-shim.js` and the renderers (so
//      `timeline.worker.js::_parseCsv` can produce chunks, and so the
//      worker-side EvtxRenderer / SqliteRenderer / CsvRenderer can produce
//      a RowStore directly when they are eventually wired up to do so).
//
// Same pattern as `src/ioc-extract.js`. No build-gate suppression needed —
// the file is plain class/function definitions with no top-level side
// effects.
//
// ─── INVARIANTS ────────────────────────────────────────────────────────────
// • A `RowStore` is **immutable post-build**. There is no `set`, `splice`,
//   or `sort` API. Sort and filter are layered on top by callers via
//   external `Uint32Array` index views (`_filteredIdx`, `_sortedIdx`) —
//   exactly how `timeline-view.js` already does it for `_timeMs`.
// • The chunk layout is **append-only during build**, **frozen after
//   `finalize()`**. Builders are single-shot; once finalized, the builder
//   must not be reused.
// • `getCell(r, c)` returns the empty string for nullish cells, OOB
//   indices, and decode errors — matching the legacy `_cellAt` semantics
//   in `timeline-view.js:625` and `grid-viewer.js`. Callers that need
//   to distinguish "missing" from "empty" must track that out-of-band
//   (no current consumer does).
// • UTF-8 is the on-disk encoding. The TextDecoder is allocated once per
//   store and reused across calls; this is safe because TextDecoder is
//   not stateful across `.decode(view)` calls when invoked without
//   `{ stream: true }`.
//
// ─── PERFORMANCE NOTES ─────────────────────────────────────────────────────
// • ASCII fast-path. Forensic logs are overwhelmingly ASCII (timestamps,
//   IPs, hex hashes, paths, usernames, channel/provider names). At pack
//   time `packRowChunk` ORs every emitted byte against 0x80; if the
//   accumulated mask stays clear, the chunk gets `allAscii = true` and
//   `getCell` / `getRow` decode via `String.fromCharCode` instead of
//   allocating a `Uint8Array.subarray` view + invoking `TextDecoder`.
//   The fast path is ~4–6× faster for sub-100 B cells in V8 because it
//   avoids both the subarray allocation and the UTF-8 state machine.
//   Multibyte chunks (Cyrillic, CJK, emoji) keep the slow `TextDecoder`
//   path so encoding fidelity is unchanged.
// • `getRow(r)` allocates a new `string[]` of length `colCount` and
//   one string per cell. Hot loops (sort comparators, filter predicates,
//   per-cell augmenters) MUST prefer `getCell` to avoid the row
//   allocation — the grep-able rule for reviewers is "no
//   `store.getRow(...)` inside a per-row inner loop". The legitimate
//   `getRow` callers are export paths (clipboard / CSV / JSON / share)
//   and the `TimelineRowView` adapter's per-visible-row resolution.
// • Chunked layout is a deliberate compromise: a single flat buffer
//   would simplify the binary search away but force a 1+ GB contiguous
//   `Uint8Array` allocation on completion — Chromium's allocator
//   refuses contiguous slabs above ~700 MB on a typical machine.
//   Chunk size targets (`CHUNK_ROWS_TARGET`, `CHUNK_BYTES_SOFT_CAP`)
//   are tuned so a 1 M-row CSV produces ~20 chunks of ~50 K rows each,
//   the binary search sees `O(log 20) = ~5` comparisons per `getCell`
//   call, and no individual chunk exceeds 64 MB.
// ════════════════════════════════════════════════════════════════════════════

// ── Tunables ───────────────────────────────────────────────────────────────
//
// These are deliberately NOT in `RENDER_LIMITS` because they're internal
// pack/flush thresholds, not user-visible caps. Changing them affects
// binary-search depth and per-chunk allocation cost, not correctness.

// Target rows per chunk during incremental building. A chunk flush is
// triggered when EITHER this row count is reached OR the soft byte cap
// below is exceeded. 50 000 rows × ~10 cols × ~80 chars/cell ≈ 40 MB —
// comfortably under the 64 MB chunk ceiling.
const _ROWSTORE_CHUNK_ROWS_TARGET = 50_000;

// Soft byte cap per chunk. Once the running estimate of cell-byte total
// crosses this, the chunk is flushed early so a row of unusually fat
// cells (long log-line bodies, embedded JSON blobs) doesn't blow the
// chunk budget.
const _ROWSTORE_CHUNK_BYTES_SOFT_CAP = 16 * 1024 * 1024;  // 16 MB

// ════════════════════════════════════════════════════════════════════════════
// packRowChunk(rows, colCount) — pack a `string[][]` batch into a single
// chunk's two typed arrays in one allocation pass. Used by
// `RowStoreBuilder._flushPending` AND directly by the timeline worker
// (`timeline.worker.js::_parseCsv`) so the worker can post a chunk's
// fresh ArrayBuffers in the postMessage transfer list (zero-copy across
// the worker boundary).
//
// Returns `{ bytes, offsets, rowCount, allAscii }`:
//   • `bytes`    Uint8Array; payload of all cells concatenated, UTF-8.
//   • `offsets`  Uint32Array of length `rowCount * (colCount + 1)`; cell
//                (r, c) occupies `bytes.subarray(offsets[r*S+c],
//                offsets[r*S+c+1])` where `S = colCount + 1`.
//   • `rowCount` integer copy of `rows.length`, returned for convenience
//                so callers don't have to read it back from the array
//                they just packed (the array reference will typically be
//                cleared by the caller right after the pack to release
//                the source `string[][]` to the GC).
//   • `allAscii` boolean — `true` iff every byte in `bytes` has the high
//                bit clear (i.e. every cell is pure 7-bit ASCII). Read
//                by `RowStore.getCell` / `getRow` to skip the UTF-8
//                TextDecoder for the common-in-forensic-logs case.
//                `RowStoreBuilder.addChunk` and `RowStore.fromChunks`
//                rescan the bytes when this field is missing, for
//                back-compat with chunks produced by older worker bundles
//                during a partial deploy.
//
// Both `bytes.buffer` and `offsets.buffer` are FRESH ArrayBuffers — they
// are safe to include in the postMessage transfer list. The function
// does not retain references to either after returning.
// ════════════════════════════════════════════════════════════════════════════
function packRowChunk(rows, colCount) {
  const rowCount = rows.length;
  const stride = colCount + 1;

  // Reusable encoder. Allocating a new TextEncoder per chunk costs a
  // few hundred microseconds; reusing one across packs is fine because
  // TextEncoder.encode is stateless.
  const encoder = (packRowChunk._encoder ||= new TextEncoder());

  // Pass 1 — classify every cell as ASCII (pure 7-bit) or "needs UTF-8
  // encoding", and sum byte lengths. For ASCII cells we keep the source
  // string verbatim and skip the per-cell `TextEncoder.encode` call —
  // this is the W3 hot-path saving on forensic-log inputs where ~95 %
  // of cells are ASCII. Pass 2 writes ASCII cells via a `charCodeAt`
  // loop directly into the destination buffer (no intermediate
  // Uint8Array allocation, no GC pressure from N million per-cell
  // typed-array headers).
  //
  // Slots:
  //   • null         — empty / nullish cell
  //   • a string `s` — ASCII fast-path; pass 2 writes `s.charCodeAt(i)`
  //                    directly into `bytes` for `i` in `[0, s.length)`
  //   • a Uint8Array — UTF-8 slow-path; pass 2 calls `bytes.set(e, pos)`
  //
  // The two-shape cell array is the source of W3's saving — keeping
  // ASCII strings in their JS-string form means no per-cell `encoder.
  // encode` allocation (which ran 2.4M times on the 100k×30 reference
  // CSV and dominated worker-side GC).
  const encoded = new Array(rowCount * colCount);
  let totalBytes = 0;
  let anyNonAscii = false;
  for (let r = 0; r < rowCount; r++) {
    const row = rows[r];
    if (!row) {
      // Defensive — shouldn't happen for well-formed callers, but keep
      // semantics aligned with `_cellAt`'s "empty for missing row".
      for (let c = 0; c < colCount; c++) encoded[r * colCount + c] = null;
      continue;
    }
    for (let c = 0; c < colCount; c++) {
      const v = row[c];
      if (v == null || v === '') {
        encoded[r * colCount + c] = null;
        continue;
      }
      const s = typeof v === 'string' ? v : String(v);
      // ASCII probe — `s.charCodeAt(i) >= 128` short-circuits on the
      // first non-ASCII char. For pure-ASCII cells this is a single
      // tight loop with no allocations; the cell is then stored as the
      // source string. For UTF-8 cells we drop into `encoder.encode`
      // and store the resulting Uint8Array instead.
      let isAscii = true;
      const sLen = s.length;
      for (let i = 0; i < sLen; i++) {
        if (s.charCodeAt(i) >= 128) { isAscii = false; break; }
      }
      if (isAscii) {
        encoded[r * colCount + c] = s;
        totalBytes += sLen;          // 1 byte/char for ASCII
      } else {
        const e = encoder.encode(s);
        encoded[r * colCount + c] = e;
        totalBytes += e.byteLength;
        anyNonAscii = true;
      }
    }
  }

  // Pass 2 — copy into the destination buffer, recording offsets. The
  // ASCII branch writes bytes directly via `charCodeAt`; the UTF-8
  // branch uses `bytes.set` (typed-array memcpy). The chunk-level
  // `allAscii` flag is now determined by `anyNonAscii` from Pass 1
  // (no need to OR every emitted byte) — a side benefit of the
  // probe-first design.
  const bytes = new Uint8Array(totalBytes);
  const offsets = new Uint32Array(rowCount * stride);
  let pos = 0;
  for (let r = 0; r < rowCount; r++) {
    const baseO = r * stride;
    offsets[baseO] = pos;
    for (let c = 0; c < colCount; c++) {
      const e = encoded[r * colCount + c];
      if (e !== null) {
        if (typeof e === 'string') {
          // ASCII fast path. `charCodeAt(i)` returns a UTF-16 code
          // unit which for ASCII inputs is identical to the byte
          // value (high byte is zero). Storing into a Uint8Array
          // truncates to 8 bits — for ASCII the truncation is a
          // no-op. The inner loop is one of the hottest pieces of
          // worker code on a CSV parse; keep it allocation-free
          // and branchless beyond the bounds check.
          const eLen = e.length;
          for (let i = 0; i < eLen; i++) {
            bytes[pos + i] = e.charCodeAt(i);
          }
          pos += eLen;
        } else {
          bytes.set(e, pos);
          pos += e.byteLength;
        }
      }
      offsets[baseO + c + 1] = pos;
    }
  }
  // `pos === totalBytes` post-condition — guaranteed by the two-pass
  // design. We don't assert it because that would slow the hot path,
  // but if the unit test changes invalidate it we'll see decode garbage
  // immediately on the first `getCell` call.

  return {
    bytes,
    offsets,
    rowCount,
    allAscii: !anyNonAscii,
  };
}

// Recompute `allAscii` from raw bytes — used by `RowStoreBuilder.addChunk`
// and `RowStore.fromChunks` when an externally-produced chunk arrives
// without the `allAscii` flag (older worker bundles, third-party builders).
// Fast on V8 (a tight typed-array loop with no allocation).
function _scanChunkAllAscii(bytes) {
  const n = bytes.byteLength;
  let mask = 0;
  for (let i = 0; i < n; i++) mask |= bytes[i];
  return (mask & 0x80) === 0;
}

// Decode a Uint8Array slice known to be pure 7-bit ASCII into a JS
// string. Faster than `TextDecoder.decode(bytes.subarray(start, end))`
// for sub-100 B cells (the dominant cell length in forensic logs)
// because it avoids both the subarray allocation and the UTF-8 state
// machine. The 4 KB chunk size keeps `String.fromCharCode.apply` below
// V8's argument-count threshold (the spec is engine-defined; 65 535 is
// the floor in V8, but Safari has historically been more conservative
// — 4 KB is comfortably under every observed limit).
function _decodeAsciiSlice(bytes, start, end) {
  const len = end - start;
  if (len === 0) return '';
  if (len <= 4096) {
    // V8 fast path — fromCharCode.apply on a typed-array view is
    // accelerated; the spread alternative (`...bytes.subarray(...)`)
    // is materially slower in jitted code.
    return String.fromCharCode.apply(null, bytes.subarray(start, end));
  }
  // Pathological "one giant cell" case — a JSON blob embedded in a
  // CSV column, etc. Concatenate 4 KB pieces. Still faster than
  // TextDecoder for ASCII because we skip the multibyte state machine.
  let out = '';
  let pos = start;
  while (pos < end) {
    const piece = Math.min(4096, end - pos);
    out += String.fromCharCode.apply(null, bytes.subarray(pos, pos + piece));
    pos += piece;
  }
  return out;
}

// ════════════════════════════════════════════════════════════════════════════
// RowStore — the immutable post-build read API.
// ════════════════════════════════════════════════════════════════════════════
class RowStore {
  // Use the static `fromChunks` / `fromStringMatrix` factories or a
  // `RowStoreBuilder` instead of `new RowStore(...)` directly. The
  // constructor accepts a fully-built `meta` object only because it's
  // simpler than threading a private symbol; callers that pass a
  // hand-rolled object are on their own.
  constructor(meta) {
    this.columns = meta.columns;
    this.colCount = meta.columns.length;
    this.rowCount = meta.rowCount;
    this.chunks = meta.chunks;
    // Cumulative row-start per chunk; length = chunks.length + 1, with
    // a trailing sentinel equal to `rowCount` so binary search can
    // treat the upper bound uniformly.
    this._chunkRowStart = meta.chunkRowStart;
    // Single decoder reused for the lifetime of the store. UTF-8 with
    // `fatal: false` matches the legacy parser's behaviour — corrupt
    // bytes become U+FFFD rather than throwing.
    this._decoder = new TextDecoder('utf-8', { fatal: false });

    // Cached column→index map for renderers / helpers that look up by
    // header name. Built lazily; populated on first `colIndex` call.
    // Held as an instance slot rather than a closure because tests
    // (and the GC) want to be able to observe / drop it.
    this._colIndex = null;

    // Deliberately NOT `Object.freeze(this)`. Freezing forbids re-assignment
    // of any slot (even slots already declared on the object), which would
    // break the lazy `_colIndex` cache below. The "immutable post-build"
    // contract is enforced by convention everywhere else in this file —
    // typed-array contents inside each chunk are technically writable too,
    // and no consumer mutates them.
  }

  // ── Read API ─────────────────────────────────────────────────────────────

  // Hot path. Returns the empty string for OOB indices and nullish cells.
  // Callers MUST NOT rely on identity / pre-interning — every call
  // produces a fresh string.
  getCell(rowIdx, colIdx) {
    if (rowIdx < 0 || rowIdx >= this.rowCount) return '';
    if (colIdx < 0 || colIdx >= this.colCount) return '';
    const ci = this._chunkIndexForRow(rowIdx);
    const chunk = this.chunks[ci];
    const localRow = rowIdx - this._chunkRowStart[ci];
    const stride = this.colCount + 1;
    const base = localRow * stride;
    const start = chunk.offsets[base + colIdx];
    const end = chunk.offsets[base + colIdx + 1];
    if (end <= start) return '';
    // ASCII fast-path — skip TextDecoder when the chunk packer flagged
    // every byte as 7-bit ASCII (the common case in forensic logs).
    if (chunk.allAscii) return _decodeAsciiSlice(chunk.bytes, start, end);
    return this._decoder.decode(chunk.bytes.subarray(start, end));
  }

  // Materialise a row as a freshly-allocated `string[]`. Use sparingly —
  // see "Performance notes" above. The CSV / TSV exporter and the
  // per-visible-row resolution inside `TimelineRowView` are the
  // legitimate callers.
  getRow(rowIdx) {
    const out = new Array(this.colCount);
    if (rowIdx < 0 || rowIdx >= this.rowCount) {
      for (let c = 0; c < this.colCount; c++) out[c] = '';
      return out;
    }
    const ci = this._chunkIndexForRow(rowIdx);
    const chunk = this.chunks[ci];
    const localRow = rowIdx - this._chunkRowStart[ci];
    const stride = this.colCount + 1;
    const base = localRow * stride;
    const offsets = chunk.offsets;
    const bytes = chunk.bytes;
    // Hoist the chunk-level ASCII flag check out of the per-cell loop —
    // every cell in a chunk shares the same encoding decision, so the
    // dispatch is once-per-row instead of once-per-cell.
    if (chunk.allAscii) {
      for (let c = 0; c < this.colCount; c++) {
        const start = offsets[base + c];
        const end = offsets[base + c + 1];
        out[c] = end <= start ? '' : _decodeAsciiSlice(bytes, start, end);
      }
      return out;
    }
    const dec = this._decoder;
    for (let c = 0; c < this.colCount; c++) {
      const start = offsets[base + c];
      const end = offsets[base + c + 1];
      out[c] = end <= start ? '' : dec.decode(bytes.subarray(start, end));
    }
    return out;
  }

  // Sum of cell-payload bytes + offsets bytes across every chunk.
  // Diagnostic / heap-budget telemetry only — does not include the
  // per-chunk JS object overhead, which is O(chunks.length) ≪ payload.
  get byteLength() {
    let n = 0;
    for (let i = 0; i < this.chunks.length; i++) {
      const c = this.chunks[i];
      n += c.bytes.byteLength + c.offsets.byteLength;
    }
    return n;
  }

  // Find a column index by header name (first match, case-sensitive).
  // Lazily builds + caches a `Map<columnName, index>`. Used by renderer
  // code that historically reached for `columns.findIndex(c => c === 'foo')`
  // on every grid build.
  colIndex(name) {
    if (!this._colIndex) {
      const m = new Map();
      for (let i = 0; i < this.columns.length; i++) {
        if (!m.has(this.columns[i])) m.set(this.columns[i], i);
      }
      this._colIndex = m;
    }
    return this._colIndex.has(name) ? this._colIndex.get(name) : -1;
  }

  // ── Internal — binary search row → chunk index ───────────────────────────
  //
  // `_chunkRowStart` is a strictly-increasing Uint32Array of length
  // `chunks.length + 1`. We want the largest `i` with
  // `_chunkRowStart[i] <= rowIdx`. Standard lower-bound search; runs in
  // O(log chunks.length) ≈ 4–5 comparisons for a typical 20-chunk store.
  _chunkIndexForRow(rowIdx) {
    const starts = this._chunkRowStart;
    let lo = 0, hi = this.chunks.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >>> 1;
      if (starts[mid] <= rowIdx) lo = mid;
      else hi = mid - 1;
    }
    return lo;
  }

  // ── Static factories ─────────────────────────────────────────────────────

  // Build directly from a fully-materialised `string[][]`. Used by every
  // current sync caller (sqlite-renderer, evtx-renderer, csv-renderer
  // sync fallback, timeline-view's `fromCsvAsync` sync fallback for tiny
  // files). For streaming/incremental construction use `RowStoreBuilder`
  // directly.
  static fromStringMatrix(columns, rows) {
    const builder = new RowStoreBuilder(columns);
    for (let i = 0; i < rows.length; i++) {
      builder.addRow(rows[i]);
    }
    return builder.finalize();
  }

  // Build from a list of pre-packed chunks (e.g. ones received from the
  // timeline worker over postMessage). Each chunk MUST have the layout
  // produced by `packRowChunk(...)`. The chunks are taken by reference
  // (no copy), which is what we want for transferred ArrayBuffers.
  //
  // Back-compat: chunks produced by older worker bundles may lack the
  // `allAscii` flag. We rescan the bytes once on construction so the
  // hot-path read in `getCell` / `getRow` doesn't have to branch on a
  // missing field on every call. The rescan is O(bytes) and runs once
  // per chunk on store construction; it's negligible relative to the
  // structured-clone the chunks already crossed.
  static fromChunks(columns, chunks) {
    const colCount = columns.length;
    const chunkRowStart = new Uint32Array(chunks.length + 1);
    let total = 0;
    for (let i = 0; i < chunks.length; i++) {
      chunkRowStart[i] = total;
      total += chunks[i].rowCount;
      // Defensive sanity: an offsets array of the wrong length means
      // someone packed with a different colCount than declared. Throwing
      // here points at the mistake immediately rather than producing
      // silently-mangled cells on first read.
      if (chunks[i].offsets.length !== chunks[i].rowCount * (colCount + 1)) {
        throw new Error(
          'RowStore.fromChunks: chunk ' + i + ' offsets length ' +
          chunks[i].offsets.length + ' does not match rowCount=' +
          chunks[i].rowCount + ' × (colCount+1)=' + (colCount + 1),
        );
      }
      // Backfill `allAscii` for chunks produced by an older shape.
      // Mutating the chunk record in place is fine here — the chunks
      // are about to become this RowStore's private property, and the
      // immutable-post-build contract starts from this constructor
      // returning, not from the caller's prior shape.
      if (typeof chunks[i].allAscii !== 'boolean') {
        chunks[i].allAscii = _scanChunkAllAscii(chunks[i].bytes);
      }
    }
    chunkRowStart[chunks.length] = total;
    return new RowStore({
      columns,
      rowCount: total,
      chunks,
      chunkRowStart,
    });
  }

  // Build an empty store (zero rows). Used by the worker bundle as the
  // "no data" signal and by tests.
  static empty(columns) {
    return new RowStore({
      columns,
      rowCount: 0,
      chunks: [],
      chunkRowStart: new Uint32Array(1),  // single sentinel zero
    });
  }
}

// ════════════════════════════════════════════════════════════════════════════
// RowStoreBuilder — incremental builder. Single-shot: call `addRow` and/or
// `addChunk` repeatedly, then `finalize()` exactly once.
//
// Two intake paths, freely interleaved:
//   • `addRow(cells: string[])` — accumulates pending rows into an
//     internal `string[][]` buffer. When the buffer crosses
//     `CHUNK_ROWS_TARGET` rows OR `CHUNK_BYTES_SOFT_CAP` (estimated)
//     bytes, the buffer is packed via `packRowChunk` and discarded.
//   • `addChunk({bytes, offsets, rowCount})` — appends a pre-packed
//     chunk directly. If pending rows exist they are flushed FIRST so
//     row order is preserved. This is the path used by the host when
//     it receives a `rows-chunk` message from the timeline worker.
//
// `rowCount` always reflects the live total (committed + pending), so
// the live-spinner subtitle in `timeline-router.js` reads it directly.
// ════════════════════════════════════════════════════════════════════════════
class RowStoreBuilder {
  constructor(columns, opts) {
    if (!Array.isArray(columns)) {
      throw new TypeError('RowStoreBuilder: columns must be an array');
    }
    this.columns = columns;
    this.colCount = columns.length;

    this._chunks = [];
    this._chunkRowStarts = [0];   // grows as `[0, c0.rowCount, c0+c1, ...]`
    this._committedRows = 0;

    this._pending = [];           // pending `string[][]` rows
    this._pendingBytes = 0;       // running estimate of pending payload
    this._finalized = false;

    const o = opts || {};
    this._chunkRowsTarget = o.chunkRowsTarget || _ROWSTORE_CHUNK_ROWS_TARGET;
    this._chunkBytesSoftCap = o.chunkBytesSoftCap || _ROWSTORE_CHUNK_BYTES_SOFT_CAP;
  }

  // Live total rows (committed chunks + pending un-flushed). Cheap;
  // suitable for use in a per-batch progress-callback hot path.
  get rowCount() {
    return this._committedRows + this._pending.length;
  }

  addRow(cells) {
    if (this._finalized) {
      throw new Error('RowStoreBuilder.addRow: builder already finalized');
    }
    // Estimate byte cost using `string.length` (UTF-16 code units).
    // For ASCII (the common case) this equals the UTF-8 byte length;
    // for multi-byte cells it's a slight under-estimate but the soft
    // cap is generous enough to absorb the slack.
    let approx = 0;
    for (let c = 0; c < this.colCount; c++) {
      const v = cells ? cells[c] : null;
      if (v == null || v === '') continue;
      approx += typeof v === 'string' ? v.length : String(v).length;
    }
    this._pending.push(cells);
    this._pendingBytes += approx;
    if (this._pending.length >= this._chunkRowsTarget ||
        this._pendingBytes >= this._chunkBytesSoftCap) {
      this._flushPending();
    }
  }

  // Append a pre-packed chunk. The chunk is taken by reference. If
  // pending `addRow` rows exist they are flushed first to preserve the
  // observed insertion order.
  //
  // Back-compat for `allAscii`: if the incoming chunk doesn't carry
  // the flag (older worker bundle, third-party caller), we scan the
  // bytes once on intake so the hot-path read in `getCell` / `getRow`
  // can rely on the flag being present.
  addChunk(chunk) {
    if (this._finalized) {
      throw new Error('RowStoreBuilder.addChunk: builder already finalized');
    }
    if (this._pending.length) this._flushPending();
    const u8 = chunk.bytes instanceof Uint8Array
      ? chunk.bytes
      : new Uint8Array(chunk.bytes);
    const u32 = chunk.offsets instanceof Uint32Array
      ? chunk.offsets
      : new Uint32Array(chunk.offsets);
    const rowCount = chunk.rowCount | 0;
    if (u32.length !== rowCount * (this.colCount + 1)) {
      throw new Error(
        'RowStoreBuilder.addChunk: offsets length ' + u32.length +
        ' does not match rowCount=' + rowCount +
        ' × (colCount+1)=' + (this.colCount + 1),
      );
    }
    const allAscii = typeof chunk.allAscii === 'boolean'
      ? chunk.allAscii
      : _scanChunkAllAscii(u8);
    this._chunks.push({ bytes: u8, offsets: u32, rowCount, allAscii });
    this._committedRows += rowCount;
    this._chunkRowStarts.push(this._committedRows);
  }

  finalize() {
    if (this._finalized) {
      throw new Error('RowStoreBuilder.finalize: already finalized');
    }
    if (this._pending.length) this._flushPending();
    this._finalized = true;
    return new RowStore({
      columns: this.columns,
      rowCount: this._committedRows,
      chunks: this._chunks,
      chunkRowStart: new Uint32Array(this._chunkRowStarts),
    });
  }

  // ── Internal ─────────────────────────────────────────────────────────────

  _flushPending() {
    if (!this._pending.length) return;
    const packed = packRowChunk(this._pending, this.colCount);
    this._chunks.push(packed);
    this._committedRows += packed.rowCount;
    this._chunkRowStarts.push(this._committedRows);
    // Drop references to the per-cell strings so the GC can reclaim
    // them now rather than at end-of-build. The replacement allocations
    // below are intentional (a fresh empty array, a single number) —
    // do not attempt to micro-optimise to `length = 0` because that
    // leaves the underlying slots holding their old refs in V8.
    this._pending = [];
    this._pendingBytes = 0;
  }
}
