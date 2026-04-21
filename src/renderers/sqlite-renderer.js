'use strict';
// ════════════════════════════════════════════════════════════════════════════
// sqlite-renderer.js — SQLite binary parser + browser history viewer
// Pure JS — reads SQLite file format (header, B-tree pages, cell data)
// with auto-detection for Chrome/Edge/Firefox history databases.
// ════════════════════════════════════════════════════════════════════════════

class SqliteRenderer {

  // ── Public API ───────────────────────────────────────────────────────────
  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer);
    const db = this._parseDb(bytes);
    return this._buildView(db, fileName);
  }

  analyzeForSecurity(buffer, fileName) {
    const bytes = new Uint8Array(buffer);
    const f = { risk: 'low', hasMacros: false, macroSize: 0, macroHash: '', autoExec: [], modules: [], externalRefs: [], metadata: {} };
    try {
      const db = this._parseDb(bytes);
      f.metadata.sqliteVersion = db.version;
      f.metadata.pageSize = db.pageSize;
      f.metadata.pageCount = db.pageCount;
      f.metadata.tables = db.tables.map(t => t.name).join(', ');
      if (db.browserType) f.metadata.browserType = db.browserType;

      // Extract URLs as IOCs from browser history.
      // Emit each distinct URL through `pushIOC` so it lands in the IOC
      // table (and picks up a sibling IOC.DOMAIN via tldts when loaded).
      // Cap at 200 to keep pathological histories from flooding the pane.
      if (db.historyRows && db.historyRows.length) {
        const urlIdx = db.historyColumns ? db.historyColumns.findIndex(c => /^url$/i.test(c)) : -1;
        if (urlIdx >= 0) {
          const seen = new Set();
          const URL_CAP = 200;
          let emitted = 0;
          for (const row of db.historyRows) {
            const url = row[urlIdx];
            if (!url || typeof url !== 'string' || url.length <= 6) continue;
            if (seen.has(url)) continue;
            seen.add(url);
            if (emitted < URL_CAP && /^https?:\/\//i.test(url)) {
              pushIOC(f, {
                type: IOC.URL,
                value: url,
                severity: 'info',
                note: db.browserType ? `${db.browserType} history` : 'browser history',
                bucket: 'externalRefs',
              });
              emitted++;
            }
          }
          f.metadata.urlCount = seen.size;
          if (seen.size > URL_CAP) {
            f.externalRefs.push({
              type: IOC.INFO,
              url: `URL extraction truncated at ${URL_CAP} — history contains ${seen.size} distinct URLs`,
              severity: 'info',
            });
          }
        }
      }
    } catch (e) {
      f.externalRefs.push({ type: IOC.INFO, url: 'SQLite parse warning: ' + e.message, severity: 'info' });
    }
    return f;
  }

  // ── SQLite binary parsing ───────────────────────────────────────────────

  _parseDb(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    // Validate header: "SQLite format 3\000"
    const magic = String.fromCharCode(...bytes.subarray(0, 16));
    if (!magic.startsWith('SQLite format 3')) throw new Error('Not a valid SQLite database');

    const pageSize = this._getPageSize(dv);
    const pageCount = dv.getUint32(28, false); // big-endian
    const textEncoding = dv.getUint32(56, false); // 1=UTF-8, 2=UTF-16le, 3=UTF-16be
    const version = dv.getUint32(96, false);
    const versionStr = `${(version >> 16) & 0xFFFF}.${(version >> 8) & 0xFF}.${version & 0xFF}`;

    const db = {
      pageSize, pageCount, textEncoding, version: versionStr,
      tables: [], browserType: null,
      historyRows: null, historyColumns: null,
      allTableData: {},
    };

    // Parse schema from page 1 (sqlite_master table)
    db.tables = this._readSchema(bytes, dv, pageSize);

    // Detect browser type
    db.browserType = this._detectBrowser(db.tables);

    // Read history data based on browser type
    if (db.browserType === 'chrome' || db.browserType === 'edge') {
      this._readChromeHistory(bytes, dv, pageSize, db);
    } else if (db.browserType === 'firefox') {
      this._readFirefoxHistory(bytes, dv, pageSize, db);
    } else {
      // Generic: read first few tables
      this._readGenericTables(bytes, dv, pageSize, db);
    }

    return db;
  }

  _getPageSize(dv) {
    const raw = dv.getUint16(16, false); // big-endian
    // Page size 1 means 65536 (SQLite quirk)
    return raw === 1 ? 65536 : raw;
  }

  // ── Schema parsing ──────────────────────────────────────────────────────

  _readSchema(bytes, dv, pageSize) {
    // Page 1 contains the sqlite_master table as a B-tree
    // The first 100 bytes are the file header, then the B-tree page header starts at offset 100
    const rows = this._readBTreeTable(bytes, dv, 1, pageSize, 100);
    const tables = [];
    for (const row of rows) {
      // sqlite_master columns: type, name, tbl_name, rootpage, sql
      if (row.length >= 5) {
        const type = String(row[0] || '');
        const name = String(row[1] || '');
        const tblName = String(row[2] || '');
        const rootPage = typeof row[3] === 'number' ? row[3] : parseInt(row[3], 10) || 0;
        const sql = String(row[4] || '');
        tables.push({ type, name, tblName, rootPage, sql });
      }
    }
    return tables;
  }

  // ── B-tree table reader ─────────────────────────────────────────────────

  _readBTreeTable(bytes, dv, pageNum, pageSize, headerOffset) {
    const rows = [];
    const visited = new Set();
    this._walkBTree(bytes, dv, pageNum, pageSize, headerOffset || 0, rows, visited, 50000);
    return rows;
  }

  _walkBTree(bytes, dv, pageNum, pageSize, headerOffset, rows, visited, maxRows) {
    if (visited.has(pageNum) || rows.length >= maxRows) return;
    visited.add(pageNum);

    const pageOff = (pageNum - 1) * pageSize;
    if (pageOff + pageSize > bytes.length) return;

    const hdrOff = pageOff + headerOffset;
    if (hdrOff + 8 > bytes.length) return;

    const pageType = bytes[hdrOff];

    if (pageType === 13) {
      // Leaf table B-tree page
      this._readLeafTablePage(bytes, dv, pageOff, headerOffset, pageSize, rows, maxRows);
    } else if (pageType === 5) {
      // Interior table B-tree page
      const cellCount = dv.getUint16(hdrOff + 3, false);
      const rightChild = dv.getUint32(hdrOff + 8, false);

      // Read cell pointers
      const cellPtrOff = hdrOff + 12;
      const children = [];
      for (let i = 0; i < cellCount && cellPtrOff + i * 2 + 1 < bytes.length; i++) {
        const cellOff = dv.getUint16(cellPtrOff + i * 2, false);
        const absOff = pageOff + cellOff;
        if (absOff + 4 < bytes.length) {
          const childPage = dv.getUint32(absOff, false);
          children.push(childPage);
        }
      }

      // Recurse into children
      for (const child of children) {
        if (rows.length >= maxRows) break;
        this._walkBTree(bytes, dv, child, pageSize, 0, rows, visited, maxRows);
      }
      // Right-most child
      if (rightChild && rows.length < maxRows) {
        this._walkBTree(bytes, dv, rightChild, pageSize, 0, rows, visited, maxRows);
      }
    }
    // Other page types (index pages 2, 10) — skip
  }

  _readLeafTablePage(bytes, dv, pageOff, headerOffset, pageSize, rows, maxRows) {
    const hdrOff = pageOff + headerOffset;
    const cellCount = dv.getUint16(hdrOff + 3, false);
    const cellPtrOff = hdrOff + 8;

    for (let i = 0; i < cellCount && rows.length < maxRows; i++) {
      if (cellPtrOff + i * 2 + 1 >= bytes.length) break;
      const cellOff = dv.getUint16(cellPtrOff + i * 2, false);
      const absOff = pageOff + cellOff;
      if (absOff >= bytes.length) continue;

      try {
        const row = this._readLeafCell(bytes, absOff, pageOff + pageSize);
        if (row) rows.push(row);
      } catch (_) { /* skip malformed cell */ }
    }
  }

  _readLeafCell(bytes, off, pageEnd) {
    const ctx = { pos: off };
    const payloadLen = this._readVarint(bytes, ctx);
    const rowId = this._readVarint(bytes, ctx);

    // Payload starts here
    const payloadStart = ctx.pos;
    const usablePayload = Math.min(payloadLen, pageEnd - payloadStart, 65536);
    if (usablePayload < 2) return null;

    // Record header
    const headerStart = ctx.pos;
    const headerSize = this._readVarint(bytes, ctx);
    if (headerSize < 1 || headerSize > usablePayload) return null;
    const headerEnd = headerStart + headerSize;

    // Read serial types
    const types = [];
    while (ctx.pos < headerEnd && ctx.pos < bytes.length) {
      types.push(this._readVarint(bytes, ctx));
    }
    ctx.pos = headerEnd; // ensure we start at data

    // Read values
    const values = [];
    for (const st of types) {
      if (ctx.pos >= bytes.length) { values.push(null); continue; }
      values.push(this._readValue(bytes, ctx, st));
    }

    return values;
  }

  // ── Varint reader ───────────────────────────────────────────────────────

  _readVarint(bytes, ctx) {
    let result = 0;
    for (let i = 0; i < 9; i++) {
      if (ctx.pos >= bytes.length) return result;
      const b = bytes[ctx.pos++];
      if (i < 8) {
        result = (result << 7) | (b & 0x7F);
        if ((b & 0x80) === 0) return result;
      } else {
        result = (result << 8) | b;
        return result;
      }
    }
    return result;
  }

  // ── Value reader by serial type ─────────────────────────────────────────

  _readValue(bytes, ctx, serialType) {
    if (serialType === 0) return null; // NULL
    if (serialType === 1) { // 8-bit int
      if (ctx.pos + 1 > bytes.length) return null;
      const v = (bytes[ctx.pos] << 24) >> 24; ctx.pos += 1;
      return v;
    }
    if (serialType === 2) { // 16-bit int (big-endian)
      if (ctx.pos + 2 > bytes.length) return null;
      const v = (bytes[ctx.pos] << 8) | bytes[ctx.pos + 1];
      ctx.pos += 2;
      return (v << 16) >> 16; // sign extend
    }
    if (serialType === 3) { // 24-bit int
      if (ctx.pos + 3 > bytes.length) return null;
      const v = (bytes[ctx.pos] << 16) | (bytes[ctx.pos + 1] << 8) | bytes[ctx.pos + 2];
      ctx.pos += 3;
      return (v << 8) >> 8; // sign extend
    }
    if (serialType === 4) { // 32-bit int
      if (ctx.pos + 4 > bytes.length) return null;
      const v = (bytes[ctx.pos] << 24) | (bytes[ctx.pos + 1] << 16) | (bytes[ctx.pos + 2] << 8) | bytes[ctx.pos + 3];
      ctx.pos += 4;
      return v;
    }
    if (serialType === 5) { // 48-bit int
      if (ctx.pos + 6 > bytes.length) return null;
      const hi = (bytes[ctx.pos] << 8) | bytes[ctx.pos + 1];
      const lo = (bytes[ctx.pos + 2] << 24) | (bytes[ctx.pos + 3] << 16) | (bytes[ctx.pos + 4] << 8) | bytes[ctx.pos + 5];
      ctx.pos += 6;
      return ((hi << 16) >> 16) * 0x100000000 + (lo >>> 0); // sign extend hi
    }
    if (serialType === 6) { // 64-bit int
      if (ctx.pos + 8 > bytes.length) return null;
      const hi = (bytes[ctx.pos] << 24) | (bytes[ctx.pos + 1] << 16) | (bytes[ctx.pos + 2] << 8) | bytes[ctx.pos + 3];
      const lo = (bytes[ctx.pos + 4] << 24) | (bytes[ctx.pos + 5] << 16) | (bytes[ctx.pos + 6] << 8) | bytes[ctx.pos + 7];
      ctx.pos += 8;
      return hi * 0x100000000 + (lo >>> 0);
    }
    if (serialType === 7) { // IEEE 754 float
      if (ctx.pos + 8 > bytes.length) return null;
      const dv = new DataView(bytes.buffer, bytes.byteOffset + ctx.pos, 8);
      const v = dv.getFloat64(0, false); // big-endian
      ctx.pos += 8;
      return v;
    }
    if (serialType === 8) return 0; // Integer 0
    if (serialType === 9) return 1; // Integer 1
    if (serialType >= 12 && serialType % 2 === 0) {
      // BLOB: length = (serialType - 12) / 2
      const len = (serialType - 12) / 2;
      if (ctx.pos + len > bytes.length) { ctx.pos += len; return null; }
      const blob = bytes.subarray(ctx.pos, ctx.pos + len);
      ctx.pos += len;
      if (len > 100) return `[BLOB ${len} bytes]`;
      return Array.from(blob).map(b => b.toString(16).padStart(2, '0')).join(' ');
    }
    if (serialType >= 13 && serialType % 2 === 1) {
      // TEXT: length = (serialType - 13) / 2
      const len = (serialType - 13) / 2;
      if (ctx.pos + len > bytes.length) { ctx.pos += len; return ''; }
      const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(ctx.pos, ctx.pos + len));
      ctx.pos += len;
      return text;
    }
    return null;
  }

  // ── Browser detection ───────────────────────────────────────────────────

  _detectBrowser(tables) {
    const names = new Set(tables.filter(t => t.type === 'table').map(t => t.name));
    // Chrome / Edge: urls, visits, downloads, keyword_search_terms
    if (names.has('urls') && names.has('visits')) {
      return names.has('downloads') ? 'chrome' : 'chrome'; // Edge uses same schema
    }
    // Firefox: moz_places, moz_historyvisits, moz_bookmarks
    if (names.has('moz_places') && names.has('moz_historyvisits')) {
      return 'firefox';
    }
    return null;
  }

  // ── Chrome/Edge history reading ─────────────────────────────────────────

  _readChromeHistory(bytes, dv, pageSize, db) {
    const urlsTable = db.tables.find(t => t.name === 'urls' && t.type === 'table');
    if (!urlsTable || !urlsTable.rootPage) return;

    // Parse column names from CREATE TABLE sql
    const columns = this._parseColumns(urlsTable.sql);
    const rows = this._readBTreeTable(bytes, dv, urlsTable.rootPage, pageSize, 0);

    // Chrome urls table: id, url, title, visit_count, typed_count, last_visit_time, hidden
    // Map to display columns
    const colNames = columns.length ? columns : ['id', 'url', 'title', 'visit_count', 'typed_count', 'last_visit_time', 'hidden'];
    const urlIdx = colNames.findIndex(c => c === 'url');
    const titleIdx = colNames.findIndex(c => c === 'title');
    const visitCountIdx = colNames.findIndex(c => c === 'visit_count');
    const lastVisitIdx = colNames.findIndex(c => c === 'last_visit_time');

    // Transform rows for display
    const displayCols = ['URL', 'Title', 'Visit Count', 'Last Visited'];
    const displayRows = [];
    for (const row of rows) {
      const url = urlIdx >= 0 && urlIdx < row.length ? row[urlIdx] : '';
      const title = titleIdx >= 0 && titleIdx < row.length ? row[titleIdx] : '';
      const count = visitCountIdx >= 0 && visitCountIdx < row.length ? row[visitCountIdx] : '';
      const lastVisitRaw = lastVisitIdx >= 0 && lastVisitIdx < row.length ? row[lastVisitIdx] : 0;
      const lastVisit = this._chromeTimestamp(lastVisitRaw);
      displayRows.push([url || '', title || '', count, lastVisit]);
    }

    db.historyColumns = displayCols;
    db.historyRows = displayRows;
  }

  // ── Firefox history reading ─────────────────────────────────────────────

  _readFirefoxHistory(bytes, dv, pageSize, db) {
    const placesTable = db.tables.find(t => t.name === 'moz_places' && t.type === 'table');
    if (!placesTable || !placesTable.rootPage) return;

    const columns = this._parseColumns(placesTable.sql);
    const rows = this._readBTreeTable(bytes, dv, placesTable.rootPage, pageSize, 0);

    // moz_places: id, url, title, rev_host, visit_count, hidden, typed, frecency, last_visit_date, ...
    const colNames = columns.length ? columns : ['id', 'url', 'title', 'rev_host', 'visit_count', 'hidden', 'typed', 'frecency', 'last_visit_date'];
    const urlIdx = colNames.findIndex(c => c === 'url');
    const titleIdx = colNames.findIndex(c => c === 'title');
    const visitCountIdx = colNames.findIndex(c => c === 'visit_count');
    const lastVisitIdx = colNames.findIndex(c => c === 'last_visit_date');

    const displayCols = ['URL', 'Title', 'Visit Count', 'Last Visited'];
    const displayRows = [];
    for (const row of rows) {
      const url = urlIdx >= 0 && urlIdx < row.length ? row[urlIdx] : '';
      const title = titleIdx >= 0 && titleIdx < row.length ? row[titleIdx] : '';
      const count = visitCountIdx >= 0 && visitCountIdx < row.length ? row[visitCountIdx] : '';
      const lastVisitRaw = lastVisitIdx >= 0 && lastVisitIdx < row.length ? row[lastVisitIdx] : 0;
      const lastVisit = this._firefoxTimestamp(lastVisitRaw);
      displayRows.push([url || '', title || '', count, lastVisit]);
    }

    db.historyColumns = displayCols;
    db.historyRows = displayRows;
  }

  // ── Generic table reading ───────────────────────────────────────────────

  _readGenericTables(bytes, dv, pageSize, db) {
    const realTables = db.tables.filter(t => t.type === 'table' && !t.name.startsWith('sqlite_'));
    for (const tbl of realTables.slice(0, 10)) {
      if (!tbl.rootPage) continue;
      try {
        const columns = this._parseColumns(tbl.sql);
        const rows = this._readBTreeTable(bytes, dv, tbl.rootPage, pageSize, 0);
        db.allTableData[tbl.name] = { columns, rows: rows.slice(0, 5000) };
      } catch (_) { /* skip unreadable tables */ }
    }
  }

  // ── Column name parser from CREATE TABLE SQL ────────────────────────────

  _parseColumns(sql) {
    if (!sql) return [];
    // Match CREATE TABLE ... ( col1 type, col2 type, ... )
    const m = sql.match(/\(\s*([\s\S]+?)\s*\)\s*$/);
    if (!m) return [];
    const body = m[1];
    const cols = [];
    let depth = 0, current = '';
    for (const ch of body) {
      if (ch === '(') depth++;
      else if (ch === ')') depth--;
      else if (ch === ',' && depth === 0) {
        const name = current.trim().split(/\s+/)[0];
        if (name && !name.toUpperCase().startsWith('CONSTRAINT') && !name.toUpperCase().startsWith('PRIMARY') &&
            !name.toUpperCase().startsWith('UNIQUE') && !name.toUpperCase().startsWith('CHECK') &&
            !name.toUpperCase().startsWith('FOREIGN')) {
          cols.push(name);
        }
        current = '';
        continue;
      }
      current += ch;
    }
    if (current.trim()) {
      const name = current.trim().split(/\s+/)[0];
      if (name && !name.toUpperCase().startsWith('CONSTRAINT') && !name.toUpperCase().startsWith('PRIMARY') &&
          !name.toUpperCase().startsWith('UNIQUE') && !name.toUpperCase().startsWith('CHECK') &&
          !name.toUpperCase().startsWith('FOREIGN')) {
        cols.push(name);
      }
    }
    return cols;
  }

  // ── Timestamp converters ────────────────────────────────────────────────

  _chromeTimestamp(raw) {
    // Chrome: microseconds since 1601-01-01 (Windows FILETIME / 10)
    const n = typeof raw === 'number' ? raw : parseFloat(raw);
    if (!n || n <= 0 || isNaN(n)) return '';
    // Convert to Unix ms: subtract 11644473600 seconds (1601→1970), divide by 1000 (µs→ms)
    const ms = n / 1000 - 11644473600000;
    const d = new Date(ms);
    return isNaN(d.getTime()) ? '' : d.toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
  }

  _firefoxTimestamp(raw) {
    // Firefox: microseconds since Unix epoch
    const n = typeof raw === 'number' ? raw : parseFloat(raw);
    if (!n || n <= 0 || isNaN(n)) return '';
    const d = new Date(n / 1000);
    return isNaN(d.getTime()) ? '' : d.toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
  }

  // ── View builder ────────────────────────────────────────────────────────
  //
  // Wave-B rewrite: every tabular surface is now a GridViewer. The old
  // DOM-table + linear `rowEls[{tr, searchText}]` structure is gone. For
  // back-compat with the sidebar IOC click-to-focus engine
  // (src/app/app-sidebar-focus.js), the active GridViewer's root is tagged
  // `csv-view` so the existing `_csvFilters.scrollToRow(...)` branch handles
  // navigation; no sqlite-specific sidebar path is needed.
  //
  // Multi-table generic view: tabs swap the active GridViewer in a single
  // host slot. Only the active tab's root carries `.csv-view`, so
  // `pc.querySelector('.csv-view')` in the sidebar deterministically
  // resolves to the currently-visible table. Cross-tab IOC navigation is a
  // known limitation — the analyst switches tabs manually. Wave D's Data
  // Explorer will address cross-table search.

  _buildView(db, fileName) {
    const wrap = document.createElement('div');
    wrap.className = 'sqlite-view';

    // Info bar
    const info = document.createElement('div');
    info.className = 'csv-info sqlite-info';
    const parts = [`SQLite v${db.version}`, `${db.pageSize} byte pages`];
    if (db.browserType) parts.push(`${db.browserType.charAt(0).toUpperCase() + db.browserType.slice(1)} Browser History`);
    else parts.push(`${db.tables.filter(t => t.type === 'table').length} tables`);
    info.textContent = parts.join(' · ');
    wrap.appendChild(info);

    if (db.historyRows) {
      this._buildHistoryTable(wrap, db, fileName);
    } else {
      this._buildGenericView(wrap, db, fileName);
    }

    return wrap;
  }

  // ── Single-table (browser history) via GridViewer ───────────────────────
  _buildHistoryTable(wrap, db, fileName) {
    const cols = db.historyColumns;
    const rawRows = db.historyRows;

    // Cap at 20 000 entries for the virtual grid. CSV export gets the full set.
    const LIMIT = 20000;
    const limit = Math.min(rawRows.length, LIMIT);

    const rows = new Array(limit);
    const rowSearchText = new Array(limit);
    for (let i = 0; i < limit; i++) {
      const src = rawRows[i];
      const row = new Array(cols.length);
      const parts = [];
      for (let j = 0; j < cols.length; j++) {
        const v = src[j] == null ? '' : String(src[j]);
        row[j] = v;
        if (v) parts.push(v);
      }
      rows[i] = row;
      rowSearchText[i] = parts.join(' ').toLowerCase();
    }

    // Provide clean tab/newline-delimited text for IOC extraction. Without
    // this, DOM textContent merges adjacent cells (URL + Title + Visit Count
    // + Date) into one blob and the URL regex over-matches.
    const rawLines = [cols.join('\t')];
    for (const row of rawRows) {
      rawLines.push(row.map(v => v == null ? '' : String(v)).join('\t'));
    }
    const rawText = rawLines.join('\n');

    const truncNote = rawRows.length > limit
      ? `⚠ Showing first ${limit.toLocaleString()} of ${rawRows.length.toLocaleString()} entries`
      : '';

    const brand = db.browserType
      ? db.browserType.charAt(0).toUpperCase() + db.browserType.slice(1)
      : 'Browser';
    const infoText = `${brand} history · ${limit.toLocaleString()} of ${rawRows.length.toLocaleString()} entries`;

    const csvBar = this._buildCsvBar(cols, rawRows, fileName);

    // Right-align the numeric "Visit Count" column (index 2 in the
    // display columns array).
    const visitCountIdx = cols.findIndex(c => /visit count/i.test(c));

    // Wave-E: Opt the browser-history grid into the timeline strip by
    // naming the "Last Visit" / "Visit(ed) Date" / "Timestamp" column as
    // the grid's temporal axis. Falls back to GridViewer's auto-sniff
    // (which also passes for this column) when no match is found.
    const lastVisitIdx = cols.findIndex(c => /last visit|visit(ed)? ?date|timestamp/i.test(c));

    const viewer = new GridViewer({
      columns: cols,
      rows,
      rowSearchText,
      rawText,
      className: 'sqlite-grid csv-view',
      infoText,
      truncationNote: truncNote,
      extraToolbarEls: [csvBar],
      timeColumn: lastVisitIdx >= 0 ? lastVisitIdx : undefined,
      cellClass: (_dataIdx, colIdx) => (colIdx === visitCountIdx ? 'grid-cell-num' : null),
      rowTitle: (dataIdx) => `Entry ${(dataIdx + 1).toLocaleString()}`
    });


    wrap.appendChild(viewer.root());
    wrap._rawText = rawText;
    wrap._sqliteViewer = viewer;
  }

  // ── Multi-table generic view via GridViewer (lazy per-tab) ──────────────
  _buildGenericView(wrap, db, fileName) {
    const tableNames = Object.keys(db.allTableData);
    if (!tableNames.length) {
      const empty = document.createElement('div');
      empty.className = 'csv-info';
      empty.textContent = 'No readable tables found.';
      wrap.appendChild(empty);

      if (db.tables.length) {
        const schemaInfo = document.createElement('div');
        schemaInfo.className = 'csv-info';
        schemaInfo.textContent = 'Schema: ' + db.tables.map(t => `${t.name} (${t.type})`).join(', ');
        wrap.appendChild(schemaInfo);
      }
      return;
    }

    // Tab bar: one tab per table. Clicking a tab lazy-constructs its
    // GridViewer and swaps it into the host slot.
    const tabBar = document.createElement('div');
    tabBar.className = 'sqlite-tab-bar';
    wrap.appendChild(tabBar);

    const host = document.createElement('div');
    host.className = 'sqlite-grid-host';
    wrap.appendChild(host);

    const viewers = Object.create(null);
    const tabs    = Object.create(null);
    const self    = this;
    let activeName = null;

    const activate = (tName) => {
      if (activeName === tName) return;
      activeName = tName;
      for (const n in tabs) {
        tabs[n].classList.toggle('sqlite-tab-active', n === tName);
      }
      if (!viewers[tName]) {
        viewers[tName] = self._buildTableViewer(db.allTableData[tName], tName, fileName);
      }
      host.replaceChildren(viewers[tName].root());
      // Only the active viewer's root carries `csv-view` so the sidebar's
      // `pc.querySelector('.csv-view')` reliably resolves to the visible
      // grid and never races with a hidden tab's DOM.
      for (const n in viewers) {
        viewers[n].root().classList.toggle('csv-view', n === tName);
      }
      wrap._sqliteViewer = viewers[tName];
    };

    for (const tName of tableNames) {
      const tData = db.allTableData[tName];
      const tab = document.createElement('button');
      tab.className = 'tb-btn sqlite-tab';
      tab.dataset.tname = tName;
      tab.textContent = `${tName} (${tData.rows.length.toLocaleString()})`;
      tab.addEventListener('click', () => activate(tName));
      tabBar.appendChild(tab);
      tabs[tName] = tab;
    }

    // Concatenated raw text across every table (IOC extraction operates on
    // the whole database; sidebar IOC navigation into a specific row
    // still requires the matching tab to be the active one).
    const rawLines = [];
    for (const tName of tableNames) {
      const tData = db.allTableData[tName];
      const cols = tData.columns.length
        ? tData.columns
        : tData.rows.length
          ? Array.from({ length: tData.rows[0].length }, (_, i) => `col_${i}`)
          : [];
      rawLines.push(`-- Table: ${tName}`);
      rawLines.push(cols.join('\t'));
      for (const row of tData.rows) {
        rawLines.push(row.map(v => v == null ? '' : String(v)).join('\t'));
      }
    }
    wrap._rawText = rawLines.join('\n');

    // Activate the first table by default.
    activate(tableNames[0]);
  }

  // ── Build a GridViewer for one table (used by both history and generic
  //    paths' lazy-construct step). ─────────────────────────────────────────
  _buildTableViewer(tData, tName, fileName) {
    const columns = tData.columns.length
      ? tData.columns
      : tData.rows.length
        ? Array.from({ length: tData.rows[0].length }, (_, i) => `col_${i}`)
        : [];

    // Upper cap inherited from the old renderer to bound DOM cost on
    // pathological tables.
    const LIMIT = 10000;
    const total = tData.rows.length;
    const limit = Math.min(total, LIMIT);

    const rows = new Array(limit);
    const rowSearchText = new Array(limit);
    for (let i = 0; i < limit; i++) {
      const src = tData.rows[i];
      const row = new Array(columns.length);
      const parts = [];
      for (let j = 0; j < columns.length; j++) {
        const v = src[j];
        const s = v == null ? 'NULL' : String(v);
        row[j] = s;
        if (s && s !== 'NULL') parts.push(s);
      }
      rows[i] = row;
      rowSearchText[i] = parts.join(' ').toLowerCase();
    }

    const truncNote = total > limit
      ? `⚠ Showing first ${limit.toLocaleString()} of ${total.toLocaleString()} rows`
      : '';

    const infoText = `${tName} · ${limit.toLocaleString()} rows × ${columns.length} cols`;
    const csvBar = this._buildCsvBar(columns, tData.rows, fileName, tName);

    return new GridViewer({
      columns,
      rows,
      rowSearchText,
      rawText: '',
      // Construct WITHOUT `csv-view` — the active-tab activator adds it
      // on show and strips it on hide so only one `.csv-view` ever exists
      // in the DOM at a time.
      className: 'sqlite-grid',
      infoText,
      truncationNote: truncNote,
      extraToolbarEls: [csvBar],
      rowTitle: (dataIdx) => `${tName} · Row ${(dataIdx + 1).toLocaleString()}`,
      cellClass: (dataIdx, colIdx, rawCell) => {
        if (rawCell === 'NULL') return 'grid-cell-null';
        const s = String(rawCell == null ? '' : rawCell);
        return s && !isNaN(parseFloat(s)) && /^-?\d/.test(s.trim()) ? 'grid-cell-num' : null;
      }
    });
  }

  // ── CSV export helpers ──────────────────────────────────────────────────

  _buildCsvBar(columns, rows, fileName, tableName) {
    const bar = document.createElement('div');
    bar.className = 'csv-export-bar';

    const copyBtn = document.createElement('button');
    copyBtn.className = 'tb-btn csv-export-btn';
    copyBtn.textContent = '📋 Copy as CSV';
    copyBtn.title = 'Copy data as CSV to clipboard';
    copyBtn.addEventListener('click', () => {
      const csv = this._toCsv(columns, rows);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(csv).then(() => this._showToast('Copied!'));
      } else {
        const ta = document.createElement('textarea'); ta.value = csv; ta.style.cssText = 'position:fixed;opacity:0';
        document.body.appendChild(ta); ta.select(); document.execCommand('copy');
        document.body.removeChild(ta); this._showToast('Copied!');
      }
    });
    const dlBtn = document.createElement('button');
    dlBtn.className = 'tb-btn csv-export-btn';
    dlBtn.textContent = '💾 Download CSV';
    dlBtn.title = 'Download data as a CSV file';
    dlBtn.addEventListener('click', () => {
      const csv = this._toCsv(columns, rows);
      const base = (fileName || 'data').replace(/\.[^.]+$/, '');
      const suffix = tableName ? '_' + tableName : '';
      window.FileDownload.downloadText(csv, base + suffix + '.csv', 'text/csv;charset=utf-8');
      this._showToast('Downloaded!');
    });

    const pillGroup = document.createElement('div');
    pillGroup.className = 'btn-pill-group';
    pillGroup.appendChild(dlBtn);
    pillGroup.appendChild(copyBtn);
    bar.appendChild(pillGroup);

    return bar;
  }

  _toCsv(columns, rows) {
    const esc = v => {
      const s = String(v == null ? '' : v);
      return s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')
        ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    const lines = [columns.map(esc).join(',')];
    for (const row of rows) {
      lines.push(row.map(esc).join(','));
    }
    return lines.join('\r\n');
  }

  _showToast(msg) {
    const t = document.getElementById('toast');
    if (t) { t.textContent = msg; t.className = ''; setTimeout(() => t.classList.add('hidden'), 2000); }
  }
}
