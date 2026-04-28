'use strict';
// ════════════════════════════════════════════════════════════════════════════
// json-renderer.js — thin JSON renderer on top of GridViewer.
//
// When a `.json` / `.ndjson` file parses to a **tabular-shaped** array
// (array-of-objects, array-of-arrays, or array-of-scalars) we render it
// through the shared GridViewer so analysts get virtual scroll, the
// right-side drawer, filter, and IOC / YARA navigation for free — just
// like CSV / EVTX / XLSX / SQLite.
//
// Any JSON shape we can't flatten into a grid (root object, mixed array
// elements, primitive root) falls through to PlainTextRenderer so nothing
// ever becomes "unrenderable" just because it claimed the JSON slot.
//
// Detection contract with `src/renderer-registry.js`:
//   • The registry's `json` entry owns `.json` / `.ndjson` only when
//     `extDisambiguator` returns true — which it does when the bytes parse
//     as JSON with an array root, OR look like NDJSON (every line is a
//     standalone JSON value).
//   • `npm` runs earlier in the ext pass, so npm manifests / lockfiles
//     still route to NpmRenderer first.
//
// Tabular shapes accepted:
//   array-of-objects  — columns = union of keys (capped); nested values
//                       show as `{…}` / `[n]` placeholders in-cell, full
//                       pretty-printed JSON in the drawer.
//   array-of-arrays   — columns = `col_0`, `col_1`, …; inner values
//                       stringified the same way.
//   array-of-scalars  — single `value` column.
//
// Caps (bound DOM + memory on pathological inputs):
//   MAX_ROWS     = 50 000   — rows beyond this are truncated with a banner.
//   MAX_COLUMNS  = 200      — extra keys are dropped (rare; banner shown).
//   MAX_BYTES    = 64 MiB   — refuses to parse beyond this.
//
// The root element carries `._rawText` (one line per grid row, tab-joined)
// and `._csvFilters` (installed by GridViewer) so the sidebar click-to-focus
// engine in `app-sidebar-focus.js` works without any special case.
// ════════════════════════════════════════════════════════════════════════════
class JsonRenderer {
  constructor() {
    this.MAX_ROWS    = 50000;
    this.MAX_COLUMNS = 200;
    this.MAX_BYTES   = 64 * 1024 * 1024;
  }

  /**
   * Render JSON text. Returns a root DOM element with `._rawText` populated.
   *
   * @param {string} text      file contents
   * @param {string} fileName  used to distinguish `.ndjson` vs `.json`
   * @returns {HTMLElement}
   */
  render(text, fileName) {
    const ext = (fileName || '').split('.').pop().toLowerCase();
    if (!text || !text.length) {
      return this._emptyView('Empty file.');
    }
    if (text.length > this.MAX_BYTES) {
      return this._fallback(text, fileName,
        `JSON input exceeds ${Math.round(this.MAX_BYTES / (1024 * 1024))} MiB — showing as plain text.`);
    }

    // CRLF → LF for stable sidebar offsets.
    if (text.indexOf('\r') !== -1) text = text.replace(/\r\n?/g, '\n');

    // ── NDJSON path: every non-empty line is its own JSON value. We parse
    //    them into an array of-objects/arrays/scalars and hand the result
    //    to the same tabular flattener as ordinary JSON arrays.
    if (ext === 'ndjson' || ext === 'jsonl' || this._looksLikeNdjson(text)) {
      const nd = this._parseNdjson(text);
      if (nd && nd.items.length) {
        return this._renderArray(nd.items, fileName, {
          malformedLineNumbers: nd.malformed,
          perItemRawLines: nd.rawLines,   // preserves per-row byte offsets into the file
          shapeLabel: `NDJSON · ${nd.items.length.toLocaleString()} records`,
        });
      }
      // Fall through to plain-text view if NDJSON parse produced nothing.
      return this._fallback(text, fileName, 'NDJSON parse produced no records.');
    }

    // ── Ordinary JSON path ──────────────────────────────────────────────
    let root;
    try {
      root = JSON.parse(text);
    } catch (e) {
      return this._fallback(text, fileName, 'Not valid JSON — ' + (e && e.message ? e.message : 'parse error') + '.');
    }

    if (Array.isArray(root)) {
      return this._renderArray(root, fileName, {
        shapeLabel: `Array · ${root.length.toLocaleString()} items`,
      });
    }

    // Non-array root (object / string / number / …). Not our beat — let
    // PlainTextRenderer handle it so the analyst still sees syntax-highlighted
    // JSON with a working toolbar.
    return this._fallback(text, fileName, null);
  }

  // ── Empty / fallback wrappers ──────────────────────────────────────────

  _emptyView(msg) {
    const wrap = document.createElement('div');
    wrap.className = 'json-view grid-view';
    wrap.textContent = msg;
    wrap._rawText = lfNormalize('');
    return wrap;
  }

  _fallback(text, fileName, reason) {
    // Hand over to PlainTextRenderer so the analyst still gets a syntax-
    // highlighted, encoding-aware view. Wrap with a small banner if we
    // have a reason (so the user knows why it isn't the grid view).
    const host = document.createElement('div');
    host.className = 'json-view-fallback grid-view';
    if (reason) {
      const note = document.createElement('div');
      note.className = 'csv-info grid-trunc';
      note.textContent = reason;
      host.appendChild(note);
    }
    // PlainTextRenderer takes a byte buffer; re-encode the decoded text.
    const enc = new TextEncoder();
    const buf = enc.encode(text).buffer;
    try {
      const pt = new PlainTextRenderer();
      const el = pt.render(buf, fileName || 'data.json', 'application/json');
      host.appendChild(el);
      host._rawText = lfNormalize(el._rawText || text);
      host._rawBytes = el._rawBytes || new Uint8Array(buf);
    } catch (e) {
      const pre = document.createElement('pre');
      pre.textContent = text;
      host.appendChild(pre);
      host._rawText = lfNormalize(text);
    }
    return host;
  }

  // ── NDJSON detection / parse ───────────────────────────────────────────

  /**
   * Heuristic: does this blob look like NDJSON? True when >= 2 non-empty
   * lines and each of the first 8 non-empty lines starts with `{` or `[`.
   * False for ordinary JSON (which is one big `[` / `{` at the start with
   * the rest of the lines indented and not standalone values).
   */
  _looksLikeNdjson(text) {
    const sample = text.length > 16384 ? text.substring(0, 16384) : text;
    const lines = sample.split('\n').map(l => l.trim()).filter(Boolean);
    if (lines.length < 2) return false;
    const checkN = Math.min(8, lines.length);
    for (let i = 0; i < checkN; i++) {
      const first = lines[i][0];
      if (first !== '{' && first !== '[') return false;
      // Also insist the line parses on its own — an ordinary pretty-printed
      // JSON array will have lines like `[` or `{` by themselves which
      // wouldn't parse.
      try { JSON.parse(lines[i]); } catch (_) { return false; }
    }
    return true;
  }

  _parseNdjson(text) {
    const items = [];
    const malformed = [];
    const rawLines = [];
    const lines = text.split('\n');
    for (let i = 0; i < lines.length && items.length < this.MAX_ROWS; i++) {
      const raw = lines[i];
      const trimmed = raw.trim();
      if (!trimmed) continue;
      try {
        items.push(JSON.parse(trimmed));
        rawLines.push(trimmed);
      } catch (_) {
        malformed.push(i + 1);
      }
    }
    return { items, malformed, rawLines };
  }

  // ── Tabular-flattening entry point ─────────────────────────────────────

  _renderArray(arr, fileName, opts) {
    opts = opts || {};

    if (arr.length === 0) {
      const wrap = document.createElement('div');
      wrap.className = 'json-view grid-view';
      const info = document.createElement('div');
      info.className = 'csv-info';
      info.textContent = 'Empty array — no items to display.';
      wrap.appendChild(info);
      wrap._rawText = lfNormalize('[]');
      return wrap;
    }

    // Decide the flattening shape from the first ~100 items (avoids a
    // full-array scan on 1 M-row NDJSON just to classify the shape).
    const shape = this._classify(arr);

    if (shape === 'objects') {
      return this._renderObjects(arr, fileName, opts);
    }
    if (shape === 'arrays') {
      return this._renderArrays(arr, fileName, opts);
    }
    if (shape === 'scalars') {
      return this._renderScalars(arr, fileName, opts);
    }
    // Mixed — fall back to plain text.
    return this._fallback(JSON.stringify(arr, null, 2), fileName,
      'Mixed-shape JSON array — showing as plain text.');
  }

  _classify(arr) {
    const sample = arr.length > 200 ? arr.slice(0, 200) : arr;
    let objs = 0, arrs = 0, scls = 0;
    for (const v of sample) {
      if (v === null || typeof v !== 'object') scls++;
      else if (Array.isArray(v)) arrs++;
      else objs++;
    }
    const total = sample.length;
    // Need a clear majority — 95% threshold — to pick a shape.
    if (objs >= total * 0.95) return 'objects';
    if (arrs >= total * 0.95) return 'arrays';
    if (scls >= total * 0.95) return 'scalars';
    return 'mixed';
  }

  // ── Shape: array-of-objects ────────────────────────────────────────────

  _renderObjects(arr, fileName, opts) {
    const limit = Math.min(arr.length, this.MAX_ROWS);

    // Union of keys, in first-seen order, capped.
    const columns = [];
    const seenCols = new Set();
    let columnsTruncated = false;
    for (let i = 0; i < limit && columns.length < this.MAX_COLUMNS; i++) {
      const v = arr[i];
      if (!v || typeof v !== 'object' || Array.isArray(v)) continue;
      for (const k of Object.keys(v)) {
        if (seenCols.has(k)) continue;
        if (columns.length >= this.MAX_COLUMNS) { columnsTruncated = true; break; }
        seenCols.add(k);
        columns.push(k);
      }
    }
    // Check whether any later item introduced new columns that were dropped.
    if (!columnsTruncated) {
      for (let i = 0; i < limit; i++) {
        const v = arr[i];
        if (!v || typeof v !== 'object' || Array.isArray(v)) continue;
        for (const k of Object.keys(v)) {
          if (!seenCols.has(k)) { columnsTruncated = true; break; }
        }
        if (columnsTruncated) break;
      }
    }

    return this._buildGrid(arr, columns, limit, fileName, opts, /* getCell */
      (item, colIdx) => {
        if (!item || typeof item !== 'object' || Array.isArray(item)) {
          // Non-object element inside an object-shaped array — stringify.
          return colIdx === 0 ? this._summarise(item) : '';
        }
        return this._summarise(item[columns[colIdx]]);
      },
      { columnsTruncated }
    );
  }

  // ── Shape: array-of-arrays ─────────────────────────────────────────────

  _renderArrays(arr, fileName, opts) {
    const limit = Math.min(arr.length, this.MAX_ROWS);
    let maxCols = 0;
    for (let i = 0; i < limit; i++) {
      const v = arr[i];
      if (Array.isArray(v) && v.length > maxCols) maxCols = v.length;
    }
    let columnsTruncated = false;
    if (maxCols > this.MAX_COLUMNS) {
      columnsTruncated = true;
      maxCols = this.MAX_COLUMNS;
    }
    const columns = [];
    for (let c = 0; c < maxCols; c++) columns.push(`col_${c}`);

    return this._buildGrid(arr, columns, limit, fileName, opts,
      (item, colIdx) => {
        if (!Array.isArray(item)) return colIdx === 0 ? this._summarise(item) : '';
        return this._summarise(item[colIdx]);
      },
      { columnsTruncated }
    );
  }

  // ── Shape: array-of-scalars ────────────────────────────────────────────

  _renderScalars(arr, fileName, opts) {
    const limit = Math.min(arr.length, this.MAX_ROWS);
    const columns = ['value'];
    return this._buildGrid(arr, columns, limit, fileName, opts,
      (item) => this._summarise(item),
      { columnsTruncated: false }
    );
  }

  // ── Shared GridViewer construction ─────────────────────────────────────

  _buildGrid(arr, columns, limit, fileName, opts, getCell, meta) {
    // Phase 7: stream rows into a `RowStoreBuilder` so the parallel
    // `string[][]` accumulator is no longer needed; only the per-row
    // `parts` array (built and dropped per iteration) and the
    // `rowSearchText` cache remain on the side.
    const builder = new RowStoreBuilder(columns);
    const rowSearchText = new Array(limit);
    const rowOffsets = opts.perItemRawLines ? new Array(limit) : null;
    const rawLines = [];
    let cumOffset = 0;

    for (let i = 0; i < limit; i++) {
      const item = arr[i];
      const row = new Array(columns.length);
      const parts = [];
      for (let c = 0; c < columns.length; c++) {
        const cell = getCell(item, c);
        row[c] = cell;
        if (cell) parts.push(cell);
      }
      builder.addRow(row);
      rowSearchText[i] = parts.join(' ').toLowerCase();

      // Raw text: one JSON-stringified line per row. Byte offsets line up
      // with the sidebar click-to-focus engine's expectations.
      const line = opts.perItemRawLines
        ? opts.perItemRawLines[i]
        : this._rowToRawLine(item);
      rawLines.push(line);
      if (rowOffsets) {
        rowOffsets[i] = { start: cumOffset, end: cumOffset + line.length };
        cumOffset += line.length + 1; // +1 for '\n'
      }
    }
    const rawText = rawLines.join('\n');
    const store = builder.finalize();

    // Toolbar bits
    const truncNotes = [];
    if (arr.length > limit) {
      truncNotes.push(`Showing first ${limit.toLocaleString()} of ${arr.length.toLocaleString()} items (row cap is ${this.MAX_ROWS.toLocaleString()}).`);
    }
    if (meta && meta.columnsTruncated) {
      truncNotes.push(`Column cap reached (${this.MAX_COLUMNS}); additional keys were dropped.`);
    }
    if (opts.malformedLineNumbers && opts.malformedLineNumbers.length) {
      const ml = opts.malformedLineNumbers;
      const preview = ml.slice(0, 5).join(', ') + (ml.length > 5 ? `, +${ml.length - 5} more` : '');
      truncNotes.push(`${ml.length.toLocaleString()} malformed NDJSON line${ml.length > 1 ? 's' : ''} skipped (line${ml.length > 1 ? 's' : ''} ${preview}).`);
    }
    const truncNote = truncNotes.length ? '⚠ ' + truncNotes.join('  ') : '';

    const shapeLabel = opts.shapeLabel
      || `Array · ${arr.length.toLocaleString()} items`;
    const infoText = `${shapeLabel} · ${limit.toLocaleString()} rows × ${columns.length} columns`;

    const self = this;
    const viewer = new GridViewer({
      columns,
      store,
      rowSearchText,
      // JSON tables (often arrays of objects) are filter-first; keep
      // the eager search-text cache.
      searchTextCache: true,
      rowOffsets,
      rawText,
      className: 'json-view csv-view',
      infoText,
      truncationNote: truncNote,
      rowTitle: (dataIdx) => `Item ${dataIdx}`,
      cellClass: (_dataIdx, _colIdx, rawCell) => {
        const s = String(rawCell == null ? '' : rawCell);
        if (s === 'null' || s === 'NULL') return 'grid-cell-null';
        if (s === '{…}' || /^\[\d+\]$/.test(s)) return 'grid-cell-nested';
        return null;
      },
      detailBuilder: (dataIdx) => self._buildDetailPane(arr[dataIdx], dataIdx)
    });

    const wrap = viewer.root();
    wrap._rawText = lfNormalize(rawText);
    wrap._jsonViewer = viewer;
    return wrap;
  }

  // ── Detail pane — interactive collapsible JSON tree. ──────────────────
  //
  // Objects and arrays render as expandable nodes with ▸ / ▾ toggles;
  // primitives render inline. All value-side text still lives inside a
  // `.csv-detail-val` wrapper so the IOC / YARA drawer-highlight pipeline
  // (which walks `.csv-detail-val` descendants) keeps working.
  //
  // Tunables:
  //   DEPTH_AUTO_OPEN    = 2   — depth up to which nodes auto-expand
  //   CHILDREN_AUTO_OPEN = 50  — objects/arrays larger than this stay
  //                              collapsed even within auto-open depth, so
  //                              opening a 10k-key object doesn't wedge
  //                              layout. User can click to expand.
  _buildDetailPane(item, dataIdx) {
    const pane = document.createElement('div');
    pane.className = 'csv-detail-pane json-detail-pane';

    const meta = document.createElement('div');
    meta.className = 'json-detail-meta';
    const shape = item === null ? 'null'
      : Array.isArray(item) ? `array[${item.length}]`
      : typeof item === 'object' ? `object (${Object.keys(item).length} keys)`
      : typeof item;
    meta.textContent = `Item ${dataIdx} — ${shape}`;
    pane.appendChild(meta);

    // Build the tree. Whole thing sits inside one `.csv-detail-val` so
    // IOC/YARA highlight walkers find the text.
    const treeRoot = document.createElement('div');
    treeRoot.className = 'json-tree csv-detail-val';
    treeRoot.appendChild(this._buildJsonNode(item, null, 0));
    pane.appendChild(treeRoot);
    return pane;
  }

  /**
   * Recursively build a DOM node for one JSON value. `key` is the key/index
   * under which this value sits in its parent; `null` at the root.
   */
  _buildJsonNode(val, key, depth) {
    const DEPTH_AUTO_OPEN    = 2;
    const CHILDREN_AUTO_OPEN = 50;
    const MAX_DEPTH          = 16;   // hard recursion cap

    const node = document.createElement('div');
    node.className = 'json-tree-node';
    node.style.marginLeft = depth === 0 ? '0' : '14px';

    const isArr = Array.isArray(val);
    const isObj = !isArr && val !== null && typeof val === 'object';
    const isContainer = isArr || isObj;

    // Head row: [toggle] [key:] [summary / primitive value]
    const head = document.createElement('div');
    head.className = 'json-tree-head';

    let toggle = null;
    if (isContainer) {
      toggle = document.createElement('span');
      toggle.className = 'json-tree-toggle';
      toggle.textContent = '▸';
      toggle.setAttribute('role', 'button');
      toggle.setAttribute('aria-expanded', 'false');
      head.appendChild(toggle);
    } else {
      const spacer = document.createElement('span');
      spacer.className = 'json-tree-toggle json-tree-toggle-leaf';
      spacer.textContent = '·';
      head.appendChild(spacer);
    }

    if (key !== null) {
      const keyEl = document.createElement('span');
      keyEl.className = 'json-tree-key';
      // Numeric index → `[0]:` bracketed; string key → `name:`.
      keyEl.textContent = typeof key === 'number' ? `[${key}]` : `${key}:`;
      head.appendChild(keyEl);
    }

    if (isContainer) {
      const summary = document.createElement('span');
      summary.className = 'json-tree-summary';
      const childCount = isArr ? val.length : Object.keys(val).length;
      summary.textContent = isArr ? `Array(${childCount})` : `Object · ${childCount} key${childCount === 1 ? '' : 's'}`;
      head.appendChild(summary);
    } else {
      const valEl = document.createElement('span');
      valEl.className = 'json-tree-val ' + this._valClass(val);
      valEl.textContent = this._formatScalar(val);
      head.appendChild(valEl);
    }

    node.appendChild(head);

    // Container body — built lazily on first expand so huge blobs don't
    // pay layout cost until the user asks.
    if (isContainer && depth < MAX_DEPTH) {
      const body = document.createElement('div');
      body.className = 'json-tree-body';
      body.style.display = 'none';
      node.appendChild(body);

      const childCount = isArr ? val.length : Object.keys(val).length;
      const autoOpen = depth < DEPTH_AUTO_OPEN && childCount > 0 && childCount <= CHILDREN_AUTO_OPEN;
      let built = false;

      const buildBody = () => {
        if (built) return;
        built = true;
        const MAX_CHILDREN_RENDER = 1000;
        if (isArr) {
          const n = Math.min(val.length, MAX_CHILDREN_RENDER);
          for (let i = 0; i < n; i++) {
            body.appendChild(this._buildJsonNode(val[i], i, depth + 1));
          }
          if (val.length > MAX_CHILDREN_RENDER) {
            const more = document.createElement('div');
            more.className = 'json-tree-more';
            more.textContent = `… ${(val.length - MAX_CHILDREN_RENDER).toLocaleString()} more items not shown`;
            body.appendChild(more);
          }
        } else {
          const keys = Object.keys(val);
          const n = Math.min(keys.length, MAX_CHILDREN_RENDER);
          for (let i = 0; i < n; i++) {
            body.appendChild(this._buildJsonNode(val[keys[i]], keys[i], depth + 1));
          }
          if (keys.length > MAX_CHILDREN_RENDER) {
            const more = document.createElement('div');
            more.className = 'json-tree-more';
            more.textContent = `… ${(keys.length - MAX_CHILDREN_RENDER).toLocaleString()} more keys not shown`;
            body.appendChild(more);
          }
        }
      };

      const expand = (open) => {
        if (open) { buildBody(); body.style.display = ''; toggle.textContent = '▾'; toggle.setAttribute('aria-expanded', 'true'); }
        else     { body.style.display = 'none'; toggle.textContent = '▸'; toggle.setAttribute('aria-expanded', 'false'); }
      };

      head.addEventListener('click', (e) => {
        e.stopPropagation();
        expand(body.style.display === 'none');
      });

      if (autoOpen) expand(true);
    } else if (isContainer) {
      // Depth cap — render a terminal summary so the user knows we stopped.
      const note = document.createElement('div');
      note.className = 'json-tree-more';
      note.textContent = '… depth limit reached';
      node.appendChild(note);
    }

    return node;
  }

  _formatScalar(v) {
    if (v === null) return 'null';
    if (v === undefined) return 'undefined';
    const t = typeof v;
    if (t === 'string') {
      if (v.length > 512) return JSON.stringify(v.substring(0, 512)) + ' …';
      return JSON.stringify(v);
    }
    if (t === 'bigint') return String(v) + 'n';
    return String(v);
  }

  _valClass(v) {
    if (v === null) return 'json-tree-val-null';
    const t = typeof v;
    if (t === 'string')  return 'json-tree-val-str';
    if (t === 'number')  return 'json-tree-val-num';
    if (t === 'bigint')  return 'json-tree-val-num';
    if (t === 'boolean') return 'json-tree-val-bool';
    return 'json-tree-val-other';
  }

  // ── Stringification helpers ────────────────────────────────────────────

  /**
   * Render a single value as a short cell string. Nested objects / arrays
   * become `{…}` / `[n]` placeholders — the full value is available in
   * the drawer. Primitives are stringified as you'd expect.
   */
  _summarise(v) {
    if (v === undefined) return '';
    if (v === null) return 'null';
    const t = typeof v;
    if (t === 'string') return v;
    if (t === 'number' || t === 'boolean' || t === 'bigint') return String(v);
    if (Array.isArray(v)) return `[${v.length}]`;
    if (t === 'object') {
      // Tiny objects (≤ 2 scalar keys) inline nicely; show `{…}` otherwise.
      const keys = Object.keys(v);
      if (!keys.length) return '{}';
      if (keys.length <= 2) {
        const parts = [];
        for (const k of keys) {
          const kv = v[k];
          if (kv !== null && typeof kv === 'object') { return '{…}'; }
          const kvs = kv === undefined ? '' : String(kv);
          parts.push(`${k}: ${kvs.length > 32 ? kvs.substring(0, 32) + '…' : kvs}`);
        }
        return '{' + parts.join(', ') + '}';
      }
      return '{…}';
    }
    return String(v);
  }

  /**
   * Compact per-row raw line (for `_rawText` / byte offsets). We always
   * emit a single JSON.stringified line so the sidebar click-to-focus
   * engine has stable per-row anchors.
   */
  _rowToRawLine(item) {
    try { return JSON.stringify(item); }
    catch (_) { return ''; }
  }

  // ── Security analysis ──────────────────────────────────────────────────
  //
  // JSON doesn't have an execution surface on its own, but a few shapes
  // are worth flagging so the analyst sees them:
  //
  //   • JSON Web Tokens   — `"eyJ…"` strings that decode to JWT payloads
  //   • Data URIs         — `data:application/…;base64,` blobs
  //   • BOM / oversized   — pathological / smuggled framing
  //
  // Full IOC extraction runs post-render via the shared pipeline over
  // `_rawText`, so we deliberately keep this function small — it only
  // pushes signals that aren't cleanly captured by IOC regexes.
  analyzeForSecurity(text) {
    const f = { risk: 'low', hasMacros: false, macroSize: 0, autoExec: [], modules: [], externalRefs: [], metadata: {} };
    if (!text || !text.length) return f;

    // Data-URI payloads in cell values — a common exfil / dropper trick
    // for config-file smuggling.
    const dataUri = text.match(/"data:[a-z0-9.+/-]+;base64,[A-Za-z0-9+/=]{64,}"/i);
    if (dataUri) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'Base64-encoded data URI embedded in JSON value — common payload-smuggling shape',
        severity: 'medium',
      });
      if (f.risk === 'low') escalateRisk(f, 'medium');
    }

    // JSON Web Token shape in values: `eyJ<base64>.<base64>.<base64>`.
    if (/"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"/.test(text)) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'JSON Web Token (JWT) embedded in value — inspect for leaked secrets',
        severity: 'low',
      });
    }

    return f;
  }
}
