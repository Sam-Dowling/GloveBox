'use strict';
// ════════════════════════════════════════════════════════════════════════════
// app-timeline.js — Timeline mode
//
// A separate top-level mode (button + 'T' shortcut) focused on **large CSV /
// TSV / EVTX** datasets. Everything about this surface is tuned for speed:
//
//   - No YARA scan. No sidebar. No IOC extraction. No EncodedContentDetector.
//   - No `_rawText` construction for offset-based sidebar nav.
//   - Reuses the existing CsvRenderer / EvtxRenderer parsers but bypasses
//     the `analyzeForSecurity()` pass, the `_extractInterestingStrings`
//     pipeline, and the whole `_loadFile` post-render branch.
//
// Layout (vertical stack, no page-level scroll):
//   [File chip + timestamp/stack col ▼ + bucket ▼ + Reset]    toolbar   40 px
//   [════════ range scrubber ══════════]                       scrubber  48 px
//   [░░░░░░░░ stacked bar chart ░░░░░░░]                       chart    240 px
//   [chip] [chip] [chip] …                                     chips     32 px
//   [grid — horizontally scrollable, fixed height]             grid     var
//   [──── vertical splitter ────]                              splitter   8 px
//   [col card | col card | col card | …  (1:1 with columns)]   columns  flex
//
// Rules:
//   - Only the grid is horizontally scrollable.
//   - Column top-values cards share the viewport width equally (grid CSS).
//   - Each card owns its own vertical overflow; the page does not scroll.
//   - Grid height is user-resizable via the splitter; persisted to
//     `loupe_timeline_grid_h`.
//   - Chart width = viewport; bucket count adapts on resize.
//
// Persistence keys (all under `loupe_` prefix):
//   - loupe_mode                  'analyser' | 'timeline'
//   - loupe_timeline_autoswitch   '0' | '1'   — default '1'
//   - loupe_timeline_grid_h       integer px  — default 320
//   - loupe_timeline_bucket       token       — default 'auto'
//
// Dispatch rules:
//   - If the user drops a **CSV / TSV / EVTX** and the Autoswitch setting is
//     enabled, we switch into Timeline mode and load it here. Otherwise the
//     legacy analyser path handles it unchanged.
//   - If the user is already in Timeline mode, only CSV / TSV / EVTX are
//     accepted. Everything else is refused with a toast pointing to the
//     'T' shortcut.
// ════════════════════════════════════════════════════════════════════════════

const TIMELINE_KEYS = Object.freeze({
  MODE: 'loupe_mode',
  AUTOSWITCH: 'loupe_timeline_autoswitch',
  GRID_H: 'loupe_timeline_grid_h',
  BUCKET: 'loupe_timeline_bucket',
});

// Hard row cap. CSV parser's own cap is 150k; EVTX parser's cap is 50k. We
// bound the Timeline view to the same 200k upper limit so the column-stats
// pass (O(rows × cols)) stays under ~50 ms for 20 cols.
const TIMELINE_MAX_ROWS = 200_000;

// Heuristic: a file qualifies for Timeline auto-switch if its extension is
// one of these AND (for CSV/TSV) its byte size is above MIN_BYTES. EVTX is
// always timelinable — even small logs read better here than in the generic
// grid.
const TIMELINE_MIN_BYTES_CSV = 1 * 1024 * 1024;   // 1 MB
const TIMELINE_EXTS = Object.freeze({
  csv: { minBytes: TIMELINE_MIN_BYTES_CSV, label: 'CSV' },
  tsv: { minBytes: TIMELINE_MIN_BYTES_CSV, label: 'TSV' },
  evtx: { minBytes: 0, label: 'EVTX' },
});

// Bucket presets. 'auto' picks the one that yields ~TIMELINE_BUCKETS_TARGET
// bars across the currently visible range.
const TIMELINE_BUCKETS_TARGET = 80;
const TIMELINE_BUCKET_OPTIONS = [
  { id: 'auto', label: 'Auto', ms: null },
  { id: '1s', label: '1 sec', ms: 1_000 },
  { id: '10s', label: '10 sec', ms: 10_000 },
  { id: '1m', label: '1 min', ms: 60_000 },
  { id: '5m', label: '5 min', ms: 300_000 },
  { id: '15m', label: '15 min', ms: 900_000 },
  { id: '1h', label: '1 hour', ms: 3_600_000 },
  { id: '6h', label: '6 hour', ms: 21_600_000 },
  { id: '1d', label: '1 day', ms: 86_400_000 },
  { id: '1w', label: '1 week', ms: 604_800_000 },
];

// Stack colours — keep the palette readable at 8 bars; any group beyond that
// collapses into "Other" (last colour). Works in both light + dark themes.
const TIMELINE_STACK_PALETTE = [
  '#4f8cff', '#f59e0b', '#22c55e', '#ef4444', '#a855f7',
  '#06b6d4', '#ec4899', '#84cc16', '#64748b',
];
const TIMELINE_STACK_MAX = 8;
const TIMELINE_COL_TOP_N = 500;          // per-card virtual list size
const TIMELINE_GRID_DEFAULT_H = 320;     // initial splitter height
const TIMELINE_GRID_MIN_H = 160;
const TIMELINE_GRID_MAX_BUFFER = 180;    // keep ≥ 180 px for column cards

// ════════════════════════════════════════════════════════════════════════════
// Time parsing — cheap, forgiving, covers the formats analysts actually see.
//   - ISO-8601 / RFC 3339                  2024-05-01T12:34:56.789Z
//   - "YYYY-MM-DD HH:MM:SS"                2024-05-01 12:34:56
//   - epoch seconds   (10 digits)          1714567890
//   - epoch millis    (13 digits)          1714567890123
//   - /Date(…)/                            EVTX-style WebJson
//   - Other strings: `Date.parse()` fallback
// ════════════════════════════════════════════════════════════════════════════
function _tlParseTimestamp(s) {
  if (s == null) return NaN;
  if (typeof s === 'number') return s;
  const str = String(s).trim();
  if (!str) return NaN;

  // Epoch seconds / millis
  if (/^-?\d{10}$/.test(str)) return Number(str) * 1000;
  if (/^-?\d{13}$/.test(str)) return Number(str);

  // YYYY-MM-DD HH:MM:SS[.fff] — patch the space to 'T' for Date.parse
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/.test(str)) {
    const ms = Date.parse(str.replace(' ', 'T'));
    return Number.isFinite(ms) ? ms : NaN;
  }

  // /Date(123456789)/ — EVTX binxml friend
  const webJson = /^\/Date\((-?\d+)\)\/$/.exec(str);
  if (webJson) return Number(webJson[1]);

  // Last resort
  const ms = Date.parse(str);
  return Number.isFinite(ms) ? ms : NaN;
}

// Score a column's timestamp-ness: percentage of non-empty cells parseable.
function _tlScoreColumnAsTimestamp(rows, colIdx, sampleMax) {
  const n = Math.min(rows.length, sampleMax || 400);
  if (!n) return 0;
  let seen = 0, ok = 0;
  for (let i = 0; i < n; i++) {
    const r = rows[i];
    if (!r) continue;
    const c = r[colIdx];
    if (c == null || c === '') continue;
    seen++;
    if (Number.isFinite(_tlParseTimestamp(c))) ok++;
  }
  if (!seen) return 0;
  return ok / seen;
}

const _TL_HEADER_HINT_RE = /^(?:time|timestamp|date|datetime|ts|created|modified|@timestamp|event[_-]?time|logged|occurred)/i;

function _tlAutoDetectTimestampCol(columns, rows) {
  // 1. Exact header-name hints win if they also parse usefully
  for (let i = 0; i < columns.length; i++) {
    if (_TL_HEADER_HINT_RE.test(String(columns[i] || '').trim())) {
      if (_tlScoreColumnAsTimestamp(rows, i, 200) >= 0.5) return i;
    }
  }
  // 2. Otherwise score every column, pick highest (≥ 0.6 threshold)
  let best = -1, bestScore = 0.6;
  for (let i = 0; i < columns.length; i++) {
    const s = _tlScoreColumnAsTimestamp(rows, i, 200);
    if (s > bestScore) { bestScore = s; best = i; }
  }
  return best >= 0 ? best : null;
}

// Auto-bucket: pick the smallest preset that yields ≤ target bars across the
// range. Falls back to the coarsest option if the range is huge.
function _tlAutoBucketMs(rangeMs, target) {
  if (!rangeMs || rangeMs <= 0) return 60_000;
  const ideal = rangeMs / (target || TIMELINE_BUCKETS_TARGET);
  for (const opt of TIMELINE_BUCKET_OPTIONS) {
    if (opt.ms == null) continue;
    if (opt.ms >= ideal) return opt.ms;
  }
  return TIMELINE_BUCKET_OPTIONS[TIMELINE_BUCKET_OPTIONS.length - 1].ms;
}

// Format a ms timestamp for axis labels — compact, context-aware.
function _tlFormatTick(ms, rangeMs) {
  if (!Number.isFinite(ms)) return '';
  const d = new Date(ms);
  const pad = n => String(n).padStart(2, '0');
  if (rangeMs < 120_000) return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  if (rangeMs < 86_400_000) return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
  if (rangeMs < 86_400_000 * 30) return `${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

function _tlFormatFullUtc(ms) {
  if (!Number.isFinite(ms)) return '—';
  const d = new Date(ms);
  const pad = n => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

function _tlFormatBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
  return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

function _tlEsc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ════════════════════════════════════════════════════════════════════════════
// TimelineView — owns all DOM + state for a single loaded file.
// ════════════════════════════════════════════════════════════════════════════
class TimelineView {

  // ── Factories ────────────────────────────────────────────────────────────
  // Return `{ columns, rows, sourceLabel, timestampColHint }` without running
  // any security analysis / IOC extraction / YARA pass.

  static fromCsv(file, buffer, explicitDelim) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(buffer);
    // Normalise line endings — CRLF would misalign timestamp parsing on
    // rows whose timestamp column happens to be last on the line.
    const norm = text.indexOf('\r') !== -1 ? text.replace(/\r\n?/g, '\n') : text;

    const r = new CsvRenderer();
    const delim = explicitDelim || r._delim(norm);
    const firstNl = norm.indexOf('\n');
    const headerLine = firstNl === -1 ? norm : norm.substring(0, firstNl);
    const columns = headerLine.indexOf('"') === -1
      ? headerLine.split(delim)
      : r._splitQuoted(headerLine, delim);

    const { rows } = r._parse(norm, delim, firstNl + 1);
    // Cap at TIMELINE_MAX_ROWS.
    let truncated = false;
    let rowSet = rows;
    if (rows.length > TIMELINE_MAX_ROWS) {
      rowSet = rows.slice(0, TIMELINE_MAX_ROWS);
      truncated = true;
    }

    return new TimelineView({
      file,
      columns,
      rows: rowSet,
      formatLabel: delim === '\t' ? 'TSV' : 'CSV',
      truncated,
      originalRowCount: rows.length,
    });
  }

  static fromEvtx(file, buffer) {
    const r = new EvtxRenderer();
    const events = r._parse(new Uint8Array(buffer));
    const columns = ['Timestamp', 'Event ID', 'Level', 'Provider', 'Channel', 'Computer', 'Event Data'];

    let truncated = false;
    let list = events;
    if (events.length > TIMELINE_MAX_ROWS) {
      list = events.slice(0, TIMELINE_MAX_ROWS);
      truncated = true;
    }
    const rows = new Array(list.length);
    for (let i = 0; i < list.length; i++) {
      const ev = list[i];
      rows[i] = [
        ev.timestamp ? ev.timestamp.replace('T', ' ').replace('Z', '') : '',
        ev.eventId || '',
        ev.level || '',
        ev.provider || '',
        ev.channel || '',
        ev.computer || '',
        ev.eventData || '',
      ];
    }

    return new TimelineView({
      file,
      columns,
      rows,
      formatLabel: 'EVTX',
      truncated,
      originalRowCount: events.length,
      // Defaults chosen for EVTX: timestamp is always col 0, stack by Event ID.
      defaultTimeColIdx: 0,
      defaultStackColIdx: 1,
    });
  }

  // ── Construction ─────────────────────────────────────────────────────────
  constructor(opts) {
    this.file = opts.file;
    this.columns = opts.columns || [];
    this.rows = opts.rows || [];
    this.formatLabel = opts.formatLabel || '';
    this.truncated = !!opts.truncated;
    this.originalRowCount = opts.originalRowCount || this.rows.length;

    // Time parsing — build a dense Float64Array of ms-since-epoch; NaN for
    // rows with no parseable timestamp (they're still visible in the grid
    // and column cards, just excluded from the chart + range window).
    this._timeCol = Number.isInteger(opts.defaultTimeColIdx)
      ? opts.defaultTimeColIdx
      : _tlAutoDetectTimestampCol(this.columns, this.rows);
    this._stackCol = Number.isInteger(opts.defaultStackColIdx) ? opts.defaultStackColIdx : null;
    this._bucketId = TimelineView._loadBucketPref();   // user pref
    this._timeMs = new Float64Array(this.rows.length);
    this._parseAllTimestamps();

    // Range: [min,max] over parseable timestamps. null if no timestamp col.
    this._dataRange = this._computeDataRange();
    this._window = null;   // user-selected sub-range [min,max] | null

    // Filter chips — array of { colIdx, op: 'eq'|'ne', val }
    this._chips = [];

    // Filter cache — Uint32Array of source row indices that satisfy the
    // current chip predicate + range window. Rebuilt lazily.
    this._filteredIdx = null;

    // Column stats — computed on first render and whenever the filter
    // changes. Map<colIdx, { total, values: Array<[val,count]> sorted desc }>.
    this._colStats = null;

    // Virtualised column-card scroll state (row offset per card).
    this._cardScrollRows = new Map();

    // Grid — we delegate virtual-scrolling to GridViewer (it's already
    // hardened for 150k+ rows and supports `setRows` for re-binding on
    // filter change). We hide its info bar + builtin timeline via CSS.
    this._grid = null;

    // Splitter
    this._gridH = TimelineView._loadGridH();

    // DOM
    this._root = null;
    this._els = {};
    this._destroyed = false;
    this._resizeObs = null;
    this._rafPending = false;
    this._pendingTasks = new Set();   // 'chart' | 'columns' | 'grid' | 'chips' | 'scrubber'

    this._buildDOM();
    this._wireEvents();
    this._recomputeFilter();
    this._scheduleRender(['chart', 'scrubber', 'chips', 'grid', 'columns']);
  }

  root() { return this._root; }

  destroy() {
    if (this._destroyed) return;
    this._destroyed = true;
    if (this._grid && typeof this._grid.destroy === 'function') {
      try { this._grid.destroy(); } catch (_) { /* grid teardown best-effort */ }
    }
    if (this._resizeObs) { try { this._resizeObs.disconnect(); } catch (_) { /* noop */ } }
    this._grid = null;
    this._resizeObs = null;
    this._els = {};
    if (this._root && this._root.parentNode) this._root.parentNode.removeChild(this._root);
    this._root = null;
  }

  // ── Persistence helpers (class-static so factories can call before ctor) ──
  static _loadBucketPref() {
    try {
      const v = localStorage.getItem(TIMELINE_KEYS.BUCKET);
      if (v && TIMELINE_BUCKET_OPTIONS.some(o => o.id === v)) return v;
    } catch (_) { /* storage blocked */ }
    return 'auto';
  }
  static _saveBucketPref(id) {
    try { localStorage.setItem(TIMELINE_KEYS.BUCKET, id); } catch (_) { /* storage blocked */ }
  }
  static _loadGridH() {
    try {
      const v = parseInt(localStorage.getItem(TIMELINE_KEYS.GRID_H), 10);
      if (Number.isFinite(v) && v >= TIMELINE_GRID_MIN_H) return v;
    } catch (_) { /* storage blocked */ }
    return TIMELINE_GRID_DEFAULT_H;
  }
  static _saveGridH(h) {
    try { localStorage.setItem(TIMELINE_KEYS.GRID_H, String(h)); } catch (_) { /* storage blocked */ }
  }

  // ── Timestamp parsing ────────────────────────────────────────────────────
  _parseAllTimestamps() {
    const col = this._timeCol;
    const rows = this.rows;
    const out = this._timeMs;
    if (col == null) { out.fill(NaN); return; }
    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];
      out[i] = r ? _tlParseTimestamp(r[col]) : NaN;
    }
  }

  _computeDataRange() {
    const t = this._timeMs;
    let lo = Infinity, hi = -Infinity;
    for (let i = 0; i < t.length; i++) {
      const v = t[i];
      if (Number.isFinite(v)) { if (v < lo) lo = v; if (v > hi) hi = v; }
    }
    if (!Number.isFinite(lo) || !Number.isFinite(hi) || lo === hi) {
      if (Number.isFinite(lo) && Number.isFinite(hi) && lo === hi) {
        return { min: lo - 500, max: hi + 500 };
      }
      return null;
    }
    return { min: lo, max: hi };
  }

  // ── Filter compilation + application ─────────────────────────────────────
  _recomputeFilter() {
    const chips = this._chips;
    const win = this._window;
    const tCol = this._timeCol;
    const times = this._timeMs;
    const rows = this.rows;
    const n = rows.length;

    // Build chip predicate as a direct array of (colIdx, op, val) tuples to
    // keep the inner loop monomorphic (no closures per row).
    const chipsArr = chips.map(c => [c.colIdx, c.op === 'ne' ? 1 : 0, String(c.val)]);

    // Worst-case allocation; we'll trim with .subarray at the end.
    const buf = new Uint32Array(n);
    let w = 0;
    const winLo = win ? win.min : -Infinity;
    const winHi = win ? win.max : Infinity;

    rowLoop:
    for (let i = 0; i < n; i++) {
      if (win && tCol != null) {
        const t = times[i];
        // Rows with unparseable timestamps are excluded by an active window.
        if (!Number.isFinite(t) || t < winLo || t > winHi) continue;
      }
      const r = rows[i];
      if (!r) continue;
      for (let c = 0; c < chipsArr.length; c++) {
        const spec = chipsArr[c];
        const cell = String(r[spec[0]] == null ? '' : r[spec[0]]);
        const matches = cell === spec[2];
        // op 0 = eq, op 1 = ne
        if (spec[1] === 0 ? !matches : matches) continue rowLoop;
      }
      buf[w++] = i;
    }
    this._filteredIdx = buf.subarray(0, w);
    this._colStats = null;   // invalidate — recomputed on render
  }

  _computeColumnStats() {
    const rows = this.rows;
    const idx = this._filteredIdx;
    const cols = this.columns.length;
    const stats = new Array(cols);
    // Use object-keyed Maps; string values dedupe for free.
    for (let c = 0; c < cols; c++) stats[c] = new Map();
    const total = idx.length;
    for (let i = 0; i < total; i++) {
      const r = rows[idx[i]];
      if (!r) continue;
      for (let c = 0; c < cols; c++) {
        const v = r[c] == null ? '' : String(r[c]);
        stats[c].set(v, (stats[c].get(v) || 0) + 1);
      }
    }
    // Sort descending, cap per column.
    const out = new Array(cols);
    for (let c = 0; c < cols; c++) {
      const arr = Array.from(stats[c].entries());
      arr.sort((a, b) => b[1] - a[1]);
      out[c] = {
        total,
        distinct: arr.length,
        values: arr.slice(0, TIMELINE_COL_TOP_N),
      };
    }
    this._colStats = out;
  }

  // ── Chart bucket aggregation ─────────────────────────────────────────────
  _bucketMs(rangeMs) {
    if (this._bucketId === 'auto') return _tlAutoBucketMs(rangeMs, TIMELINE_BUCKETS_TARGET);
    const opt = TIMELINE_BUCKET_OPTIONS.find(o => o.id === this._bucketId);
    return opt && opt.ms ? opt.ms : _tlAutoBucketMs(rangeMs, TIMELINE_BUCKETS_TARGET);
  }

  _computeChartData() {
    const dr = this._dataRange;
    if (!dr) return null;
    const viewLo = this._window ? this._window.min : dr.min;
    const viewHi = this._window ? this._window.max : dr.max;
    const rangeMs = Math.max(1, viewHi - viewLo);
    const bucketMs = this._bucketMs(rangeMs);
    const bucketCount = Math.max(1, Math.ceil(rangeMs / bucketMs));
    const idx = this._filteredIdx;
    const times = this._timeMs;
    const rows = this.rows;
    const stackCol = this._stackCol;

    // Stack keys — compute top-N categories over the filtered set (+ "Other").
    let stackKeys = null;
    let stackKeyOf = null;
    if (Number.isInteger(stackCol)) {
      const counts = new Map();
      for (let i = 0; i < idx.length; i++) {
        const r = rows[idx[i]];
        if (!r) continue;
        const v = r[stackCol] == null ? '' : String(r[stackCol]);
        counts.set(v, (counts.get(v) || 0) + 1);
      }
      const sorted = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
      const top = sorted.slice(0, TIMELINE_STACK_MAX - 1);
      const hasOther = sorted.length > top.length;
      stackKeys = top.map(e => e[0]);
      if (hasOther) stackKeys.push('__other__');
      const topSet = new Set(stackKeys);
      stackKeyOf = (r) => {
        const v = r[stackCol] == null ? '' : String(r[stackCol]);
        return topSet.has(v) ? v : '__other__';
      };
    }

    // Single O(filteredRows) pass.
    const k = stackKeys ? stackKeys.length : 1;
    const buckets = new Int32Array(bucketCount * k);
    for (let i = 0; i < idx.length; i++) {
      const t = times[idx[i]];
      if (!Number.isFinite(t)) continue;
      const rel = t - viewLo;
      if (rel < 0 || rel > rangeMs) continue;
      let b = Math.floor(rel / bucketMs);
      if (b >= bucketCount) b = bucketCount - 1;
      if (stackKeyOf) {
        const key = stackKeyOf(rows[idx[i]]);
        const ki = stackKeys.indexOf(key);
        buckets[b * k + (ki < 0 ? 0 : ki)]++;
      } else {
        buckets[b]++;
      }
    }

    // Totals per bucket — for max-height scaling.
    let maxTotal = 0;
    for (let b = 0; b < bucketCount; b++) {
      let s = 0;
      for (let j = 0; j < k; j++) s += buckets[b * k + j];
      if (s > maxTotal) maxTotal = s;
    }

    return {
      viewLo, viewHi, rangeMs, bucketMs, bucketCount,
      buckets, stackKeys, maxTotal,
    };
  }

  // ── DOM ──────────────────────────────────────────────────────────────────
  _buildDOM() {
    const root = document.createElement('div');
    root.className = 'timeline-view';
    root.style.setProperty('--tl-grid-h', this._gridH + 'px');

    // Toolbar
    const toolbar = document.createElement('div');
    toolbar.className = 'tl-toolbar';
    toolbar.innerHTML = `
      <span class="tl-file-chip" title="Source file">
        <span class="tl-file-icon">📈</span>
        <span class="tl-file-name"></span>
        <span class="tl-file-meta"></span>
      </span>
      <span class="tl-sep"></span>
      <label class="tl-field">
        <span class="tl-field-label">Timestamp</span>
        <select class="tl-field-select" data-field="time-col"></select>
      </label>
      <label class="tl-field">
        <span class="tl-field-label">Stack by</span>
        <select class="tl-field-select" data-field="stack-col"></select>
      </label>
      <label class="tl-field">
        <span class="tl-field-label">Bucket</span>
        <select class="tl-field-select" data-field="bucket"></select>
      </label>
      <span class="tl-spacer"></span>
      <span class="tl-row-stat"></span>
      <button class="tl-reset-btn" type="button" title="Clear range window + all filter chips">↺ Reset</button>
    `;
    root.appendChild(toolbar);

    // Scrubber
    const scrubber = document.createElement('div');
    scrubber.className = 'tl-scrubber';
    scrubber.innerHTML = `
      <span class="tl-scrubber-label tl-scrubber-label-left">—</span>
      <div class="tl-scrubber-track">
        <div class="tl-scrubber-window"></div>
        <div class="tl-scrubber-handle tl-scrubber-handle-l"></div>
        <div class="tl-scrubber-handle tl-scrubber-handle-r"></div>
      </div>
      <span class="tl-scrubber-label tl-scrubber-label-right">—</span>
    `;
    root.appendChild(scrubber);

    // Chart
    const chart = document.createElement('div');
    chart.className = 'tl-chart';
    chart.innerHTML = `
      <canvas class="tl-chart-canvas"></canvas>
      <div class="tl-chart-legend"></div>
      <div class="tl-chart-empty hidden">No parseable timestamps in the current filter.</div>
    `;
    root.appendChild(chart);

    // Chips
    const chips = document.createElement('div');
    chips.className = 'tl-chips';
    chips.innerHTML = `<span class="tl-chips-empty">Click a value in a column card below to filter. Shift-click = NOT.</span>`;
    root.appendChild(chips);

    // Grid + splitter
    const gridWrap = document.createElement('div');
    gridWrap.className = 'tl-grid';
    root.appendChild(gridWrap);

    const splitter = document.createElement('div');
    splitter.className = 'tl-splitter';
    splitter.setAttribute('role', 'separator');
    splitter.setAttribute('aria-orientation', 'horizontal');
    splitter.title = 'Drag to resize';
    root.appendChild(splitter);

    // Columns
    const cols = document.createElement('div');
    cols.className = 'tl-columns';
    root.appendChild(cols);

    this._root = root;
    this._els = {
      toolbar, scrubber, chart, chips, gridWrap, splitter, cols,
      fileName: toolbar.querySelector('.tl-file-name'),
      fileMeta: toolbar.querySelector('.tl-file-meta'),
      rowStat: toolbar.querySelector('.tl-row-stat'),
      timeColSelect: toolbar.querySelector('[data-field="time-col"]'),
      stackColSelect: toolbar.querySelector('[data-field="stack-col"]'),
      bucketSelect: toolbar.querySelector('[data-field="bucket"]'),
      resetBtn: toolbar.querySelector('.tl-reset-btn'),
      scrubLabelL: scrubber.querySelector('.tl-scrubber-label-left'),
      scrubLabelR: scrubber.querySelector('.tl-scrubber-label-right'),
      scrubTrack: scrubber.querySelector('.tl-scrubber-track'),
      scrubWindow: scrubber.querySelector('.tl-scrubber-window'),
      scrubHandleL: scrubber.querySelector('.tl-scrubber-handle-l'),
      scrubHandleR: scrubber.querySelector('.tl-scrubber-handle-r'),
      chartCanvas: chart.querySelector('.tl-chart-canvas'),
      chartLegend: chart.querySelector('.tl-chart-legend'),
      chartEmpty: chart.querySelector('.tl-chart-empty'),
      chipsEmpty: chips.querySelector('.tl-chips-empty'),
    };

    // Populate static dropdowns
    this._populateToolbarSelects();
    this._refreshFileChip();
  }

  _refreshFileChip() {
    const f = this.file;
    const label = f && f.name ? f.name : '(no file)';
    const sizeText = f ? _tlFormatBytes(f.size || 0) : '';
    const rowText = this.truncated
      ? `${this.rows.length.toLocaleString()} of ${this.originalRowCount.toLocaleString()} rows (capped)`
      : `${this.rows.length.toLocaleString()} rows`;
    this._els.fileName.textContent = label;
    this._els.fileMeta.textContent = ` · ${this.formatLabel}${sizeText ? ' · ' + sizeText : ''} · ${rowText}`;
  }

  _populateToolbarSelects() {
    const { timeColSelect, stackColSelect, bucketSelect } = this._els;

    timeColSelect.innerHTML = '';
    const emptyOpt = document.createElement('option');
    emptyOpt.value = '-1'; emptyOpt.textContent = '— none —';
    timeColSelect.appendChild(emptyOpt);
    for (let i = 0; i < this.columns.length; i++) {
      const opt = document.createElement('option');
      opt.value = String(i);
      opt.textContent = this.columns[i] || `(col ${i + 1})`;
      timeColSelect.appendChild(opt);
    }
    timeColSelect.value = this._timeCol == null ? '-1' : String(this._timeCol);

    stackColSelect.innerHTML = '';
    const noneOpt = document.createElement('option');
    noneOpt.value = '-1'; noneOpt.textContent = '— none —';
    stackColSelect.appendChild(noneOpt);
    for (let i = 0; i < this.columns.length; i++) {
      const opt = document.createElement('option');
      opt.value = String(i);
      opt.textContent = this.columns[i] || `(col ${i + 1})`;
      stackColSelect.appendChild(opt);
    }
    stackColSelect.value = this._stackCol == null ? '-1' : String(this._stackCol);

    bucketSelect.innerHTML = '';
    for (const o of TIMELINE_BUCKET_OPTIONS) {
      const opt = document.createElement('option');
      opt.value = o.id; opt.textContent = o.label;
      bucketSelect.appendChild(opt);
    }
    bucketSelect.value = this._bucketId;
  }

  // ── Event wiring ─────────────────────────────────────────────────────────
  _wireEvents() {
    const els = this._els;

    els.timeColSelect.addEventListener('change', () => {
      const v = parseInt(els.timeColSelect.value, 10);
      this._timeCol = v >= 0 ? v : null;
      this._parseAllTimestamps();
      this._dataRange = this._computeDataRange();
      this._window = null;
      this._recomputeFilter();
      this._scheduleRender(['chart', 'scrubber', 'grid', 'columns', 'chips']);
    });
    els.stackColSelect.addEventListener('change', () => {
      const v = parseInt(els.stackColSelect.value, 10);
      this._stackCol = v >= 0 ? v : null;
      this._scheduleRender(['chart']);
    });
    els.bucketSelect.addEventListener('change', () => {
      this._bucketId = els.bucketSelect.value;
      TimelineView._saveBucketPref(this._bucketId);
      this._scheduleRender(['chart']);
    });
    els.resetBtn.addEventListener('click', () => this._reset());

    // Chart clicks → filter chip or range window
    els.chartCanvas.addEventListener('click', (e) => this._onChartClick(e));

    // Scrubber drag
    this._installScrubberDrag();

    // Splitter drag
    this._installSplitterDrag();

    // Chart resize
    this._resizeObs = new ResizeObserver(() => {
      this._scheduleRender(['chart']);
    });
    this._resizeObs.observe(els.chart);
  }

  _reset() {
    this._window = null;
    this._chips = [];
    this._recomputeFilter();
    this._scheduleRender(['chart', 'scrubber', 'chips', 'grid', 'columns']);
  }

  // ── Render scheduler ─────────────────────────────────────────────────────
  _scheduleRender(tasks) {
    for (const t of tasks) this._pendingTasks.add(t);
    if (this._rafPending) return;
    this._rafPending = true;
    requestAnimationFrame(() => {
      this._rafPending = false;
      if (this._destroyed) return;
      const set = new Set(this._pendingTasks);
      this._pendingTasks.clear();
      // Column stats are shared by 'grid' and 'columns' rendering — compute
      // once if either is pending.
      if ((set.has('grid') || set.has('columns')) && !this._colStats) {
        this._computeColumnStats();
      }
      if (set.has('scrubber')) this._renderScrubber();
      if (set.has('chart')) this._renderChart();
      if (set.has('chips')) this._renderChips();
      if (set.has('grid')) this._renderGrid();
      if (set.has('columns')) this._renderColumns();
      this._refreshRowStat();
    });
  }

  _refreshRowStat() {
    const total = this.rows.length;
    const visible = this._filteredIdx ? this._filteredIdx.length : total;
    const txt = visible === total
      ? `${total.toLocaleString()} rows`
      : `${visible.toLocaleString()} / ${total.toLocaleString()} rows`;
    this._els.rowStat.textContent = txt;
  }

  // ── Scrubber ─────────────────────────────────────────────────────────────
  _renderScrubber() {
    const els = this._els;
    const dr = this._dataRange;
    if (!dr) {
      els.scrubLabelL.textContent = '—';
      els.scrubLabelR.textContent = '—';
      els.scrubWindow.style.left = '0%';
      els.scrubWindow.style.width = '100%';
      els.scrubHandleL.style.left = '0%';
      els.scrubHandleR.style.left = '100%';
      return;
    }
    els.scrubLabelL.textContent = _tlFormatFullUtc(dr.min);
    els.scrubLabelR.textContent = _tlFormatFullUtc(dr.max);

    const span = dr.max - dr.min;
    const win = this._window;
    const lo = win ? (win.min - dr.min) / span : 0;
    const hi = win ? (win.max - dr.min) / span : 1;
    const loPct = Math.max(0, Math.min(1, lo)) * 100;
    const hiPct = Math.max(0, Math.min(1, hi)) * 100;
    els.scrubWindow.style.left = loPct + '%';
    els.scrubWindow.style.width = Math.max(0.5, hiPct - loPct) + '%';
    els.scrubHandleL.style.left = loPct + '%';
    els.scrubHandleR.style.left = hiPct + '%';
  }

  _installScrubberDrag() {
    const track = this._els.scrubTrack;
    const handleL = this._els.scrubHandleL;
    const handleR = this._els.scrubHandleR;
    const winEl = this._els.scrubWindow;

    const pctAt = (clientX) => {
      const rect = track.getBoundingClientRect();
      return Math.max(0, Math.min(1, (clientX - rect.left) / rect.width));
    };
    const msAt = (pct) => {
      const dr = this._dataRange; if (!dr) return NaN;
      return dr.min + pct * (dr.max - dr.min);
    };

    const beginDrag = (mode, startX) => {
      if (!this._dataRange) return;
      let dragging = true;
      const startWindow = this._window ? { ...this._window } : { min: this._dataRange.min, max: this._dataRange.max };
      const startPct = pctAt(startX);
      const onMove = (e) => {
        if (!dragging) return;
        const pct = pctAt(e.clientX);
        const nowMs = msAt(pct);
        let lo, hi;
        if (mode === 'create') {
          // dragging from startPct to current
          const a = Math.min(startPct, pct), b = Math.max(startPct, pct);
          lo = msAt(a); hi = msAt(b);
        } else if (mode === 'left') {
          lo = Math.min(startWindow.max - 1, nowMs);
          hi = startWindow.max;
        } else if (mode === 'right') {
          lo = startWindow.min;
          hi = Math.max(startWindow.min + 1, nowMs);
        } else if (mode === 'move') {
          const deltaPct = pct - startPct;
          const deltaMs = deltaPct * (this._dataRange.max - this._dataRange.min);
          lo = startWindow.min + deltaMs;
          hi = startWindow.max + deltaMs;
          const span = hi - lo;
          if (lo < this._dataRange.min) { lo = this._dataRange.min; hi = lo + span; }
          if (hi > this._dataRange.max) { hi = this._dataRange.max; lo = hi - span; }
        }
        if (Number.isFinite(lo) && Number.isFinite(hi) && hi > lo) {
          this._window = {
            min: Math.max(this._dataRange.min, lo),
            max: Math.min(this._dataRange.max, hi),
          };
          this._recomputeFilter();
          this._scheduleRender(['scrubber', 'chart', 'grid', 'columns']);
        }
      };
      const onUp = () => {
        dragging = false;
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
      };
      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
    };

    track.addEventListener('pointerdown', (e) => {
      // Clicking a handle or the window lets those handlers take over.
      if (e.target === handleL) { beginDrag('left', e.clientX); return; }
      if (e.target === handleR) { beginDrag('right', e.clientX); return; }
      if (e.target === winEl) { beginDrag('move', e.clientX); return; }
      // Empty-track click: start a fresh window from that point.
      beginDrag('create', e.clientX);
    });
  }

  // ── Chart ────────────────────────────────────────────────────────────────
  _renderChart() {
    const canvas = this._els.chartCanvas;
    const data = this._computeChartData();
    if (!data) {
      this._els.chartEmpty.classList.remove('hidden');
      canvas.width = canvas.clientWidth; canvas.height = canvas.clientHeight;
      const ctx = canvas.getContext('2d');
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      this._els.chartLegend.innerHTML = '';
      this._lastChartData = null;
      return;
    }
    this._els.chartEmpty.classList.add('hidden');

    // Resize for DPR.
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    if (canvas.width !== w * dpr) { canvas.width = w * dpr; canvas.height = h * dpr; }
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const { buckets, bucketCount, maxTotal, stackKeys, rangeMs, viewLo } = data;
    const padL = 42, padR = 12, padT = 12, padB = 22;
    const plotW = Math.max(1, w - padL - padR);
    const plotH = Math.max(1, h - padT - padB);
    const barW = plotW / bucketCount;
    const k = stackKeys ? stackKeys.length : 1;

    // Axis grid — 4 horizontal lines
    ctx.strokeStyle = 'rgba(128,128,128,0.15)';
    ctx.lineWidth = 1;
    for (let g = 1; g <= 4; g++) {
      const y = padT + (plotH * g) / 5;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(padL + plotW, y); ctx.stroke();
    }

    // Y-axis labels (max count)
    ctx.fillStyle = 'rgba(128,128,128,0.8)';
    ctx.font = '10px system-ui, -apple-system, Segoe UI, sans-serif';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.fillText(String(maxTotal), padL - 4, padT);
    ctx.fillText('0', padL - 4, padT + plotH);

    // X-axis labels (4 ticks)
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    const ticks = 4;
    for (let i = 0; i <= ticks; i++) {
      const t = viewLo + (rangeMs * i) / ticks;
      const x = padL + (plotW * i) / ticks;
      ctx.fillText(_tlFormatTick(t, rangeMs), x, padT + plotH + 4);
    }

    // Bars
    const scale = maxTotal > 0 ? plotH / maxTotal : 0;
    for (let b = 0; b < bucketCount; b++) {
      let yAcc = padT + plotH;
      const x = padL + b * barW;
      for (let j = 0; j < k; j++) {
        const c = buckets[b * k + j];
        if (!c) continue;
        const barH = c * scale;
        ctx.fillStyle = TIMELINE_STACK_PALETTE[j % TIMELINE_STACK_PALETTE.length];
        // Inset by 1px so bars are separated.
        const bw = Math.max(1, barW - 1);
        ctx.fillRect(x, yAcc - barH, bw, barH);
        yAcc -= barH;
      }
    }

    // Frame
    ctx.strokeStyle = 'rgba(128,128,128,0.35)';
    ctx.strokeRect(padL, padT, plotW, plotH);

    // Legend
    const legend = this._els.chartLegend;
    legend.innerHTML = '';
    if (stackKeys && stackKeys.length) {
      const stackColName = this._stackCol != null ? (this.columns[this._stackCol] || '') : '';
      if (stackColName) {
        const hdr = document.createElement('span');
        hdr.className = 'tl-legend-hdr';
        hdr.textContent = `stacked by ${stackColName}:`;
        legend.appendChild(hdr);
      }
      for (let i = 0; i < stackKeys.length; i++) {
        const k2 = stackKeys[i];
        const chip = document.createElement('span');
        chip.className = 'tl-legend-chip';
        chip.innerHTML = `<span class="tl-legend-swatch" style="background:${TIMELINE_STACK_PALETTE[i % TIMELINE_STACK_PALETTE.length]}"></span>${_tlEsc(k2 === '__other__' ? 'Other' : k2)}`;
        legend.appendChild(chip);
      }
    }

    // Cache for click hit-testing
    this._lastChartData = { ...data, layout: { padL, padR, padT, padB, plotW, plotH, barW } };
  }

  _onChartClick(e) {
    const data = this._lastChartData;
    if (!data) return;
    const canvas = this._els.chartCanvas;
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const { padL, plotW, barW } = data.layout;
    if (x < padL || x > padL + plotW) return;
    const b = Math.min(data.bucketCount - 1, Math.max(0, Math.floor((x - padL) / barW)));
    const bucketLo = data.viewLo + b * data.bucketMs;
    const bucketHi = bucketLo + data.bucketMs;
    this._window = { min: bucketLo, max: bucketHi };
    this._recomputeFilter();
    this._scheduleRender(['scrubber', 'chart', 'grid', 'columns']);
  }

  // ── Chips ────────────────────────────────────────────────────────────────
  _renderChips() {
    const el = this._els.chips;
    el.innerHTML = '';
    if (!this._chips.length && !this._window) {
      const hint = document.createElement('span');
      hint.className = 'tl-chips-empty';
      hint.textContent = 'Click a value in a column card below to filter. Shift-click = NOT.';
      el.appendChild(hint);
      return;
    }
    if (this._window) {
      const chip = document.createElement('span');
      chip.className = 'tl-chip tl-chip-range';
      chip.innerHTML = `<span class="tl-chip-col">range</span><span class="tl-chip-val">${_tlEsc(_tlFormatFullUtc(this._window.min))} → ${_tlEsc(_tlFormatFullUtc(this._window.max))}</span><button class="tl-chip-x" title="Clear range">⊗</button>`;
      chip.querySelector('.tl-chip-x').addEventListener('click', () => {
        this._window = null;
        this._recomputeFilter();
        this._scheduleRender(['scrubber', 'chart', 'chips', 'grid', 'columns']);
      });
      el.appendChild(chip);
    }
    for (let i = 0; i < this._chips.length; i++) {
      const c = this._chips[i];
      const chip = document.createElement('span');
      chip.className = 'tl-chip' + (c.op === 'ne' ? ' tl-chip-not' : '');
      const colName = this.columns[c.colIdx] || `(col ${c.colIdx + 1})`;
      chip.innerHTML = `<span class="tl-chip-col">${_tlEsc(colName)}</span><span class="tl-chip-op">${c.op === 'ne' ? '≠' : '='}</span><span class="tl-chip-val">${_tlEsc(c.val)}</span><button class="tl-chip-x" title="Remove filter">⊗</button>`;
      chip.querySelector('.tl-chip-x').addEventListener('click', () => {
        this._chips.splice(i, 1);
        this._recomputeFilter();
        this._scheduleRender(['chart', 'chips', 'grid', 'columns']);
      });
      el.appendChild(chip);
    }
  }

  // ── Grid ─────────────────────────────────────────────────────────────────
  _renderGrid() {
    const wrap = this._els.gridWrap;
    // Materialise filtered rows. For 200k-row cap × typical 15 cols this is
    // a shallow reference copy, O(visible) — fine on main thread.
    const idx = this._filteredIdx;
    const filteredRows = new Array(idx.length);
    for (let i = 0; i < idx.length; i++) filteredRows[i] = this.rows[idx[i]];

    if (!this._grid) {
      const viewer = new GridViewer({
        columns: this.columns,
        rows: filteredRows,
        className: 'tl-grid-inner csv-view',
        hideFilterBar: true,
        infoText: '',
        // Turn OFF the built-in chart / scrubber strip — Timeline mode has
        // its own. `timeColumn: null` keeps the auto-sniffer from firing,
        // but the strip is also hidden via CSS inside `#timeline-root` for
        // belt-and-braces.
        timeColumn: -1,
      });
      wrap.innerHTML = '';
      wrap.appendChild(viewer.root());
      this._grid = viewer;
    } else {
      this._grid.setRows(filteredRows);
    }
  }

  // ── Column top-values cards ──────────────────────────────────────────────
  _renderColumns() {
    const host = this._els.cols;
    host.style.setProperty('--tl-col-count', String(this.columns.length));
    // Build fresh — DOM per card is small (header + virtual list viewport).
    // For 40 columns we're creating ~40 × 12 nodes = 480 nodes. Fine.
    host.innerHTML = '';
    const stats = this._colStats;
    const rowHeight = 22;                                            // sync with .tl-col-row
    const visibleRows = 10;                                           // fits in min card height

    for (let c = 0; c < this.columns.length; c++) {
      const s = stats ? stats[c] : { total: 0, distinct: 0, values: [] };
      const card = document.createElement('div');
      card.className = 'tl-col-card';
      card.dataset.colIdx = String(c);

      const title = this.columns[c] || `(col ${c + 1})`;
      const head = document.createElement('div');
      head.className = 'tl-col-head';
      head.innerHTML = `<span class="tl-col-name" title="${_tlEsc(title)}">${_tlEsc(title)}</span><span class="tl-col-sub" title="distinct values">${s.distinct.toLocaleString()}</span>`;
      card.appendChild(head);

      // Virtual list — absolute-positioned rows inside a sized sizer.
      const viewport = document.createElement('div');
      viewport.className = 'tl-col-viewport';
      const sizer = document.createElement('div');
      sizer.className = 'tl-col-sizer';
      sizer.style.height = (s.values.length * rowHeight) + 'px';
      viewport.appendChild(sizer);
      card.appendChild(viewport);

      const renderRows = () => {
        const scroll = viewport.scrollTop;
        const start = Math.max(0, Math.floor(scroll / rowHeight) - 2);
        const end = Math.min(s.values.length, start + visibleRows + 6);
        // Clear and repaint visible rows.
        // (Re-creating ~20 nodes per card per filter-change beats diffing.)
        while (sizer.firstChild) sizer.removeChild(sizer.firstChild);
        const topVal = s.values.length ? s.values[0][1] : 1;
        for (let i = start; i < end; i++) {
          const [val, count] = s.values[i];
          const row = document.createElement('div');
          row.className = 'tl-col-row';
          row.style.top = (i * rowHeight) + 'px';
          row.dataset.value = val;
          const pct = topVal > 0 ? Math.max(2, Math.round((count / topVal) * 100)) : 0;
          row.innerHTML = `
            <span class="tl-col-bar" style="width:${pct}%"></span>
            <span class="tl-col-val" title="${_tlEsc(val)}">${_tlEsc(val === '' ? '(empty)' : val)}</span>
            <span class="tl-col-count">${count.toLocaleString()}</span>`;
          sizer.appendChild(row);
        }
      };
      renderRows();

      viewport.addEventListener('scroll', () => {
        if (this._cardRaf) return;
        this._cardRaf = requestAnimationFrame(() => {
          this._cardRaf = null;
          renderRows();
        });
      });

      // Clicks on rows → add chip
      sizer.addEventListener('click', (e) => {
        const row = e.target.closest('.tl-col-row');
        if (!row) return;
        const val = row.dataset.value;
        const shift = e.shiftKey;
        const meta = e.ctrlKey || e.metaKey;
        this._addOrToggleChip(c, val, { op: shift ? 'ne' : 'eq', replace: meta });
      });

      host.appendChild(card);
    }
  }

  _addOrToggleChip(colIdx, val, opts) {
    const op = opts && opts.op === 'ne' ? 'ne' : 'eq';
    const replace = !!(opts && opts.replace);

    if (replace) {
      this._chips = this._chips.filter(c => c.colIdx !== colIdx);
    }
    // If an identical chip already exists, treat the click as "remove".
    const ix = this._chips.findIndex(c => c.colIdx === colIdx && c.op === op && c.val === val);
    if (ix >= 0) {
      this._chips.splice(ix, 1);
    } else {
      this._chips.push({ colIdx, op, val });
    }
    this._recomputeFilter();
    this._scheduleRender(['chart', 'chips', 'grid', 'columns']);
  }

  // ── Splitter ─────────────────────────────────────────────────────────────
  _installSplitterDrag() {
    const root = this._root;
    const splitter = this._els.splitter;
    splitter.addEventListener('pointerdown', (e) => {
      e.preventDefault();
      const startY = e.clientY;
      const startH = this._gridH;
      const rect = root.getBoundingClientRect();
      const maxH = Math.max(TIMELINE_GRID_MIN_H, rect.height - 400);
      const onMove = (ev) => {
        const dy = ev.clientY - startY;
        let h = startH + dy;
        if (h < TIMELINE_GRID_MIN_H) h = TIMELINE_GRID_MIN_H;
        if (h > maxH) h = maxH;
        this._gridH = h;
        root.style.setProperty('--tl-grid-h', h + 'px');
      };
      const onUp = () => {
        window.removeEventListener('pointermove', onMove);
        window.removeEventListener('pointerup', onUp);
        TimelineView._saveGridH(this._gridH);
      };
      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
    });
  }
}


// ════════════════════════════════════════════════════════════════════════════
// App mixin — mode lifecycle, auto-switch, file-type gate, toolbar wiring.
// ════════════════════════════════════════════════════════════════════════════
Object.assign(App.prototype, {

  // ── Persistence ────────────────────────────────────────────────────────
  _getMode() { return this._mode === 'timeline' ? 'timeline' : 'analyser'; },

  _initTimelineMode() {
    // Default mode is 'analyser'. We deliberately don't persist the mode
    // choice across reloads — the user always starts on Analyser and the
    // autoswitch heuristic (or the T shortcut / button) gets them into
    // Timeline from there. This avoids surprising reopens into Timeline
    // after they cleared state.
    this._mode = 'analyser';
    this._timelineCurrent = null;
    document.body.setAttribute('data-mode', 'analyser');

    // Note: the `#btn-timeline` toolbar click listener is wired once in
    // `app-core.js` alongside the other toolbar buttons. Wiring it here
    // as well would double-fire `_toggleTimelineMode()` on every click,
    // making the button appear to do nothing (enter → exit in the same
    // tick). The `T` keyboard shortcut is also handled in `app-core.js`.
  },


  _isTimelineAutoswitchEnabled() {
    try {
      const v = localStorage.getItem(TIMELINE_KEYS.AUTOSWITCH);
      // Default ON when unset.
      if (v == null) return true;
      return v !== '0';
    } catch (_) { return true; }
  },

  _setTimelineAutoswitchEnabled(on) {
    try {
      localStorage.setItem(TIMELINE_KEYS.AUTOSWITCH, on ? '1' : '0');
    } catch (_) { /* storage blocked */ }
  },

  // ── Heuristic ──────────────────────────────────────────────────────────
  // Pure extension check — used when the user is *explicitly* in Timeline
  // mode (they opted in via T / 📈). We don't gate by size because they've
  // already chosen the surface; a 1 KB `timeline.csv` is still a timeline.
  _isTimelineExt(file) {
    if (!file || !file.name) return false;
    const ext = file.name.split('.').pop().toLowerCase();
    return !!TIMELINE_EXTS[ext];
  },

  // Autoswitch heuristic: extension + minBytes threshold. Used only by the
  // auto-enter-on-drop path so analysts opening a tiny CSV in the analyser
  // aren't surprised by a mode change. Explicit Timeline-mode loads go via
  // `_isTimelineExt`.
  _isTimelinableFile(file) {
    if (!this._isTimelineExt(file)) return false;
    const ext = file.name.split('.').pop().toLowerCase();
    const meta = TIMELINE_EXTS[ext];
    if (meta.minBytes && (file.size || 0) < meta.minBytes) return false;
    return true;
  },

  // Called at the top of _loadFile. Returns true if this load was handled
  // (or explicitly refused) by Timeline mode; false to fall through to the
  // legacy analyser pipeline.
  _timelineTryHandle(file) {
    const inTimeline = this._getMode() === 'timeline';

    if (inTimeline) {
      // Already in Timeline — accept any CSV/TSV/EVTX regardless of size.
      if (!this._isTimelineExt(file)) {
        this._toast('Timeline mode only accepts CSV / TSV / EVTX — press T to exit and open other formats', 'error');
        return true; // handled (refused)
      }
      this._loadFileInTimeline(file);
      return true;
    }
    // Analyser mode — only auto-enter Timeline if the file is both a
    // timeline-capable extension AND crosses the autoswitch size threshold.
    if (this._isTimelinableFile(file) && this._isTimelineAutoswitchEnabled()) {
      this._enterTimelineMode();
      this._loadFileInTimeline(file);
      return true;
    }
    return false;
  },

  // ── Mode switching ─────────────────────────────────────────────────────
  _toggleTimelineMode() {
    if (this._getMode() === 'timeline') this._exitTimelineMode();
    else this._enterTimelineMode();
  },

  _enterTimelineMode() {
    if (this._getMode() === 'timeline') return;
    this._mode = 'timeline';
    document.body.setAttribute('data-mode', 'timeline');
    const btn = document.getElementById('btn-timeline');
    if (btn) btn.classList.add('tb-btn-active');

    // Swap out of the analyser viewer: hide it and clear sidebar state.
    // We don't actually destroy the existing docEl — the user may flip
    // back. But we do close the sidebar if it was open (Timeline mode has
    // no sidebar concept).
    if (this.sidebarOpen) {
      try { this._toggleSidebar(); } catch (_) { /* ignore toggle errors */ }
    }

    // Ensure the timeline root exists and is visible. The element is
    // created once on first entry so analyser mode keeps its DOM pristine.
    let tr = document.getElementById('timeline-root');
    if (!tr) {
      tr = document.createElement('div');
      tr.id = 'timeline-root';
      const main = document.getElementById('main-area') || document.body;
      main.appendChild(tr);
    }
    // Always (re)render the empty state on entry so mode-switching is
    // idempotent — if the user entered from the analyser with a file
    // loaded, or from a stale error splash, we paint a fresh prompt.
    this._renderTimelineEmptyState(tr);

    this._toast('Timeline mode', 'info');
  },

  _exitTimelineMode() {
    if (this._getMode() === 'analyser') return;
    this._mode = 'analyser';
    document.body.setAttribute('data-mode', 'analyser');
    const btn = document.getElementById('btn-timeline');
    if (btn) btn.classList.remove('tb-btn-active');
    // Tear down the current view; next re-entry rebuilds fresh.
    if (this._timelineCurrent) {
      try { this._timelineCurrent.destroy(); } catch (_) { /* noop */ }
      this._timelineCurrent = null;
    }
    this._toast('Analyser mode', 'info');
  },

  // Shared empty-state painter. Matches the Analyser #drop-zone affordance:
  // dashed border, clickable to open the file picker, hover/drag-over
  // highlight (see .timeline-empty / .timeline-empty.drag-over in
  // viewers.css). Re-renders on every entry / clear so stale error
  // splashes or stale "previous-file" markup never leak into a fresh
  // prompt.
  _renderTimelineEmptyState(host) {
    host.innerHTML = '';
    const empty = document.createElement('div');
    empty.className = 'timeline-empty';
    empty.setAttribute('role', 'button');
    empty.setAttribute('tabindex', '0');
    empty.innerHTML = `
      <span class="timeline-empty-icon" aria-hidden="true">📈</span>
      <div class="timeline-empty-title">Timeline mode</div>
      <div class="timeline-empty-body">Drop a CSV, TSV, or EVTX file here &mdash; press <kbd>T</kbd> to return to the analyser</div>`;
    // Click / keyboard-activate opens the same native file picker the
    // analyser drop-zone uses. Timeline-mode file-type gating happens in
    // `_timelineTryHandle` once the file arrives via `_loadFile`.
    const openPicker = () => {
      const fi = document.getElementById('file-input');
      if (fi) fi.click();
    };
    empty.addEventListener('click', openPicker);
    empty.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openPicker(); }
    });
    // Mirror the analyser drop-zone's `.drag-over` visual while a file is
    // being dragged over the window. Matches the cue analysts already
    // know. The handlers are installed exactly once (guarded by
    // `_timelineDragWired`) — re-rendering the empty surface simply
    // re-queries `#timeline-root .timeline-empty` each time they fire so
    // stale element refs don't leak across mode toggles.
    if (!this._timelineDragWired) {
      this._timelineDragWired = true;
      const currentEmpty = () =>
        document.querySelector('#timeline-root .timeline-empty');
      window.addEventListener('dragenter', () => {
        if (this._getMode() !== 'timeline') return;
        const el = currentEmpty();
        if (el) el.classList.add('drag-over');
      });
      window.addEventListener('dragleave', () => {
        const el = currentEmpty();
        if (el) el.classList.remove('drag-over');
      });
      window.addEventListener('drop', () => {
        const el = currentEmpty();
        if (el) el.classList.remove('drag-over');
      });
    }
    host.appendChild(empty);
  },

  // ── Load pipeline ──────────────────────────────────────────────────────
  async _loadFileInTimeline(file) {
    this._setLoading(true);
    try {
      // Destroy the previous view so we don't stack GridViewer instances.
      if (this._timelineCurrent) {
        try { this._timelineCurrent.destroy(); } catch (_) { /* noop */ }
        this._timelineCurrent = null;
      }
      const buffer = await ParserWatchdog.run(() => file.arrayBuffer());
      const ext = file.name.split('.').pop().toLowerCase();

      // Stash filemeta for the breadcrumb; mode='timeline' means the
      // sidebar is hidden so findings aren't wired up.
      this._fileMeta = {
        name: file.name, size: file.size,
        mimeType: file.type || '',
        lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : '',
      };
      this._renderBreadcrumbs();

      let view;
      if (ext === 'evtx') {
        view = TimelineView.fromEvtx(file, buffer);
      } else if (ext === 'csv' || ext === 'tsv') {
        view = TimelineView.fromCsv(file, buffer, ext === 'tsv' ? '\t' : null);
      } else {
        // Belt-and-braces — the entrypoint already rejects non-timelinable
        // extensions, but guard anyway.
        throw new Error('Unsupported Timeline format: .' + ext);
      }

      const host = document.getElementById('timeline-root');
      host.innerHTML = '';
      host.appendChild(view.root());
      this._timelineCurrent = view;

      // Show the analyser toolbar's close button so the user has the
      // same affordance for "close this file".
      const btnClose = document.getElementById('btn-close');
      if (btnClose) btnClose.classList.remove('hidden');

      // Hide the analyser viewer-toolbar (Summarize / Export / Search /
      // Zoom) — none of that applies in Timeline mode.
      const vt = document.getElementById('viewer-toolbar');
      if (vt) vt.classList.add('hidden');

    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('[timeline] load failed:', e);
      this._toast(`Failed to open in Timeline: ${e && e.message ? e.message : e}`, 'error');
      const host = document.getElementById('timeline-root');
      if (host) {
        host.innerHTML = '';
        const err = document.createElement('div');
        err.className = 'timeline-empty';
        err.innerHTML = `<div class="timeline-empty-icon">⚠</div><div class="timeline-empty-title">Failed to open</div><div class="timeline-empty-body">${_tlEsc(e && e.message ? e.message : String(e))}</div>`;
        host.appendChild(err);
      }
    } finally {
      this._setLoading(false);
    }
  },

  // ── Close handler override — route to timeline when in that mode ───────
  // Mirror the state reset in `app-ui.js::_clearFile()` so closing a
  // timeline file doesn't leave a stale breadcrumb, tab title, buffer,
  // findings, or binary-triage blob pointing at the previous sample.
  _clearTimelineFile() {
    if (this._timelineCurrent) {
      try { this._timelineCurrent.destroy(); } catch (_) { /* noop */ }
      this._timelineCurrent = null;
    }

    // Wipe per-file state. Timeline mode doesn't populate `findings` /
    // `fileHashes` / `_binaryParsed`, but clearing them anyway keeps the
    // invariant simple: after `_clearTimelineFile` no state survives that
    // could influence a subsequent analyser-mode load.
    this.findings = null;
    this.fileHashes = null;
    this._fileBuffer = null;
    this._yaraBuffer = null;
    this._yaraResults = null;
    this._fileMeta = null;
    this._binaryParsed = null;
    this._binaryFormat = null;
    this._navStack = [];
    // Breadcrumb hides itself + resets document.title when `_fileMeta` is
    // null.
    if (this._renderBreadcrumbs) this._renderBreadcrumbs();

    // Re-paint the Timeline drop affordance.
    const host = document.getElementById('timeline-root');
    if (host) this._renderTimelineEmptyState(host);

    const btnClose = document.getElementById('btn-close');
    if (btnClose) btnClose.classList.add('hidden');
  },
});
