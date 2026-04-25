'use strict';
// ════════════════════════════════════════════════════════════════════════════
// csv-renderer.js — thin CSV/TSV renderer on top of GridViewer.
//
// Virtual-scrolling, highlight state, drawer, filter, IOC/YARA navigation and
// lifecycle all live in GridViewer (see src/renderers/grid-viewer.js). This
// file's remaining jobs are:
//
//   1. Delimiter auto-detection (`,  ;  \t  |`) with quote-awareness.
//   2. Parsing CSV/TSV text into rows + byte offsets. For large files
//      (>2 MB) the parse runs in cooperative chunks so the main thread
//      stays responsive: GridViewer paints the first ~1 k rows within
//      200 ms and the rest streams in via `appendRows()`.
//   3. Formula-injection security analysis (CWE-1236).
//
// Exposes `render(text, fileName) → HTMLElement` and `analyzeForSecurity(text)`.
// The returned root element carries `._rawText` + `._csvFilters` so the sidebar
// click-to-focus engine in `app-sidebar-focus.js` works.
// ════════════════════════════════════════════════════════════════════════════
class CsvRenderer {
  constructor() {
    // Chunk tunables. Numbers chosen to paint within ~200 ms on a 50 MB file.
    this.CHUNK_BYTES_SYNC    = 2 * 1024 * 1024;   // ≤ 2 MB — parse synchronously
    this.CHUNK_ROWS_FIRST    = 1000;              // first painted chunk size
    this.CHUNK_ROWS_STREAM   = 5000;              // subsequent streamed chunks
    this.MAX_ROWS            = RENDER_LIMITS.MAX_CSV_ROWS; // hard cap on rendered rows
  }

  /**
   * Render a CSV/TSV text buffer. Returns the root DOM element immediately;
   * for large files the remaining rows stream in after first paint.
   *
   * @param {string} text      file contents (any line ending — we normalise)
   * @param {string} fileName  used only to pick TSV vs delimiter-auto-detect
   * @returns {HTMLElement}    root `.csv-view.grid-view` element
   */
  render(text, fileName) {
    // CRLF → LF. The sidebar click-to-focus engine uses `_rawText` offsets
    // for byte-accurate highlighting; mixed line endings misalign every
    // click after the first CR (see CONTRIBUTING → Gotchas).
    if (text.indexOf('\r') !== -1) text = text.replace(/\r\n?/g, '\n');

    const ext   = (fileName || '').split('.').pop().toLowerCase();
    const delim = ext === 'tsv' ? '\t' : this._delim(text);

    // Empty-file fast path.
    if (!text || !text.trim()) {
      const empty = document.createElement('div');
      empty.className = 'csv-view grid-view';
      empty.textContent = 'Empty file.';
      empty._rawText = '';
      return empty;
    }

    // Parse header + decide whether to go fully-sync or chunked-streaming.
    const firstNl    = text.indexOf('\n');
    const headerLine = firstNl === -1 ? text : text.substring(0, firstNl);
    const headerRow  = headerLine.indexOf('"') === -1
      ? headerLine.split(delim)
      : this._splitQuoted(headerLine, delim);

    const infoText = this._delimLabel(delim);

    // Build the viewer up front with an empty body so the user sees
    // something paint immediately on huge files.
    const viewer = new GridViewer({
      columns: headerRow,
      rows:    [],
      rawText: text,
      infoText,
      className: 'csv-view',   // keep the sidebar selector happy
      emptyMessage: 'Empty file.'
    });

    // Small file — parse synchronously and hand the rows to the viewer.
    if (text.length <= this.CHUNK_BYTES_SYNC) {
      const { rows, rowOffsets } = this._parse(text, delim, firstNl + 1);
      const { rows: capped, rowOffsets: cappedOff, truncated, originalCount } =
        this._capRows(rows, rowOffsets);
      const rowSearchText = new Array(capped.length);
      // Detect malformed rows: wrong column count, or any cell containing an
      // unbalanced '"' (suggesting quote-escape corruption the stream parser
      // recovered from but should be flagged).
      const malformed = new Set();
      const expectedCols = headerRow.length;
      for (let i = 0; i < capped.length; i++) {
        const r = capped[i];
        rowSearchText[i] = r.join(' ').toLowerCase();
        if (r.length !== expectedCols) {
          malformed.add(i);
          continue;
        }
        // Unbalanced-quote heuristic: any cell whose `"` count is odd.
        for (let c = 0; c < r.length; c++) {
          const cell = r[c];
          if (!cell || cell.indexOf('"') === -1) continue;
          let qc = 0;
          for (let k = 0; k < cell.length; k++) if (cell.charCodeAt(k) === 34) qc++;
          if (qc & 1) { malformed.add(i); break; }
        }
      }
      viewer.setRows(capped, rowSearchText, cappedOff);
      viewer._infoText = `${capped.length.toLocaleString()} rows × ${headerRow.length} columns · ${infoText}`;
      viewer._updateInfoBar();
      if (malformed.size) viewer.setMalformedRows(malformed);
      if (truncated) {
        viewer._truncNote = `⚠ Showing first ${capped.length.toLocaleString()} of ${originalCount.toLocaleString()} rows (row cap is ${this.MAX_ROWS.toLocaleString()}).`;
        const note = document.createElement('div');
        note.className = 'csv-info grid-trunc';
        note.textContent = viewer._truncNote;
        viewer.root().appendChild(note);
      }
      return viewer.root();
    }

    // Large file — chunked streaming parse. Paint first chunk now, stream
    // the rest. Progress bar is fed via the GridViewer parse-progress hooks.
    viewer._infoText = `Parsing ${this._fmtBytes(text.length)}…`;
    viewer._updateInfoBar();
    // Rough estimate of final row count: average a ~100-byte row.
    const estTotalRows = Math.min(this.MAX_ROWS, Math.max(1, Math.floor(text.length / 100)));
    viewer.beginParseProgress(estTotalRows);
    this._parseStreaming(text, delim, firstNl + 1, headerRow.length, viewer);
    return viewer.root();
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Label the auto-detected delimiter for the info bar.
  // ═══════════════════════════════════════════════════════════════════════
  _delimLabel(delim) {
    if (delim === ',')  return 'delimiter: Comma';
    if (delim === '\t') return 'delimiter: Tab';
    if (delim === ';')  return 'delimiter: Semicolon';
    if (delim === '|')  return 'delimiter: Pipe';
    return `delimiter: "${delim}"`;
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
    return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  }

  _capRows(rows, rowOffsets) {
    const originalCount = rows.length;
    const truncated = rows.length > this.MAX_ROWS;
    if (!truncated) return { rows, rowOffsets, truncated: false, originalCount };
    return {
      rows: rows.slice(0, this.MAX_ROWS),
      rowOffsets: rowOffsets.slice(0, this.MAX_ROWS),
      truncated: true,
      originalCount
    };
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Auto-detect delimiter by counting unquoted occurrences in the first line.
  // ═══════════════════════════════════════════════════════════════════════
  _delim(text) {
    let nl = text.indexOf('\n');
    if (nl === -1) nl = text.length;
    const line = text.substring(0, nl);
    const c = { ',': 0, ';': 0, '\t': 0, '|': 0 };
    let inQ = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') inQ = !inQ;
      else if (!inQ && c[ch] !== undefined) c[ch]++;
    }
    return Object.entries(c).sort((a, b) => b[1] - a[1])[0][0];
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Full-buffer synchronous parse (used for files ≤ CHUNK_BYTES_SYNC).
  //
  //  Fast path: quote-free lines use native String.split — dramatically
  //  faster than the per-character state machine. Lines that contain '"'
  //  fall through to _splitQuoted for RFC-4180 correctness.
  // ═══════════════════════════════════════════════════════════════════════
  _parse(text, delim, startOffset) {
    const rows = [];
    const rowOffsets = [];
    const len = text.length;
    let offset = startOffset || 0;

    while (offset < len) {
      let lineEnd = text.indexOf('\n', offset);
      if (lineEnd === -1) lineEnd = len;

      // \n-only at this point — CRLF has already been normalised by render().
      if (lineEnd > offset) {
        const line = text.substring(offset, lineEnd);
        const cells = line.indexOf('"') === -1
          ? line.split(delim)
          : this._splitQuoted(line, delim);
        rows.push(cells);
        rowOffsets.push({ start: offset, end: lineEnd });
      }
      offset = lineEnd + 1;
    }
    return { rows, rowOffsets };
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Streaming parse — yields control back to the event loop every
  //  CHUNK_ROWS_STREAM rows so the first paint isn't blocked by a 50 MB
  //  parse. Feeds the viewer via `appendRows()` + `updateParseProgress()`.
  // ═══════════════════════════════════════════════════════════════════════
  _parseStreaming(text, delim, startOffset, colCount, viewer) {
    const len = text.length;
    let offset = startOffset || 0;
    let totalRows = 0;
    const MAX = this.MAX_ROWS;
    let truncated = false;
    const malformed = new Set();

    const yieldNext = (fn) => {
      // Prefer MessageChannel for zero-delay yielding; fall back to setTimeout.
      if (typeof MessageChannel !== 'undefined') {
        const ch = new MessageChannel();
        ch.port1.onmessage = () => { ch.port1.close(); fn(); };
        ch.port2.postMessage(null);
      } else {
        setTimeout(fn, 0);
      }
    };

    const self = this;
    const parseChunk = (chunkCap) => {
      if (viewer._destroyed) return;
      if (offset >= len || totalRows >= MAX) {
        // End-of-file reached.
        viewer._infoText =
          `${totalRows.toLocaleString()} rows × ${colCount} columns · ${self._delimLabel(delim)}`;
        viewer._updateInfoBar();
        viewer.endParseProgress();
        if (truncated) {
          viewer._truncNote =
            `⚠ Showing first ${MAX.toLocaleString()} rows (row cap). File continues beyond this point.`;
          const note = document.createElement('div');
          note.className = 'csv-info grid-trunc';
          note.textContent = viewer._truncNote;
          viewer.root().appendChild(note);
        }
        return;
      }

      const chunkRows    = [];
      const chunkOffsets = [];
      const chunkSearch  = [];
      let parsed = 0;
      while (offset < len && parsed < chunkCap && totalRows + parsed < MAX) {
        let lineEnd = text.indexOf('\n', offset);
        if (lineEnd === -1) lineEnd = len;
        if (lineEnd > offset) {
          const line = text.substring(offset, lineEnd);
          const cells = line.indexOf('"') === -1
            ? line.split(delim)
            : self._splitQuoted(line, delim);
          chunkRows.push(cells);
          chunkOffsets.push({ start: offset, end: lineEnd });
          chunkSearch.push(line.toLowerCase());
          // Flag malformed: column count mismatch.
          if (cells.length !== colCount) {
            malformed.add(totalRows + parsed);
          }
          parsed++;
        }
        offset = lineEnd + 1;
      }
      if (totalRows + parsed >= MAX && offset < len) truncated = true;

      if (chunkRows.length) {
        viewer.appendRows(chunkRows, chunkSearch, chunkOffsets);
        totalRows += chunkRows.length;
        viewer.updateParseProgress(totalRows, Math.max(totalRows, Math.floor(len / Math.max(1, offset / Math.max(1, totalRows)))));
        // Republish the malformed set as it grows so the ribbon counter
        // animates up during the streaming parse.
        if (malformed.size) viewer.setMalformedRows(malformed);
      }
      yieldNext(() => parseChunk(self.CHUNK_ROWS_STREAM));
    };

    // Kick off with a smaller first chunk for faster first paint.
    parseChunk(this.CHUNK_ROWS_FIRST);
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Split a CSV line into cells (RFC-4180 quoted handling).
  //  Only used for lines that actually contain '"' — the common
  //  quote-free case is handled by native String.split.
  // ═══════════════════════════════════════════════════════════════════════
  _splitQuoted(line, delim) {
    const cells = [];
    let cur = '';
    let inQ = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQ && line[i + 1] === '"') { cur += '"'; i++; }
        else inQ = !inQ;
      } else if (ch === delim && !inQ) {
        cells.push(cur);
        cur = '';
      } else {
        cur += ch;
      }
    }
    cells.push(cur);
    return cells;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Decode an ArrayBuffer to a UTF-8 string with inline CRLF → LF
  //  normalisation and BOM stripping.  For buffers larger than
  //  DECODE_CHUNK_BYTES (16 MB) the decode runs in 16 MB slices via the
  //  streaming TextDecoder API so each intermediate string stays well
  //  under V8's ~512 M-character limit.  This replaces the previous
  //  `file.text()` call in the Route-B CSV handler, which could silently
  //  return an empty string for very large files under memory pressure.
  // ═══════════════════════════════════════════════════════════════════════
  static decodeBuffer(buffer) {
    const bytes = new Uint8Array(buffer);
    const CHUNK = RENDER_LIMITS.DECODE_CHUNK_BYTES; // 16 MB

    if (bytes.length <= CHUNK) {
      // Fast path — small buffer, single-shot decode.
      const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      const noBom = text.charCodeAt(0) === 0xFEFF ? text.slice(1) : text;
      return noBom.indexOf('\r') !== -1 ? noBom.replace(/\r\n?/g, '\n') : noBom;
    }

    // Chunked path — large buffer.
    const decoder = new TextDecoder('utf-8', { fatal: false });
    const parts = [];
    let first = true;
    for (let pos = 0; pos < bytes.length; pos += CHUNK) {
      const end = Math.min(pos + CHUNK, bytes.length);
      const stream = end < bytes.length;
      let chunk = decoder.decode(bytes.subarray(pos, end), { stream });
      if (first) {
        if (chunk.charCodeAt(0) === 0xFEFF) chunk = chunk.slice(1);
        first = false;
      }
      if (chunk.indexOf('\r') !== -1) chunk = chunk.replace(/\r\n?/g, '\n');
      parts.push(chunk);
    }
    return parts.join('');
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Security analysis — formula-injection (CWE-1236) detection.
  //  A bare leading =/+/-/@ is the baseline indicator (medium). When the
  //  formula also references a known dangerous function — DDE (`cmd|/C`,
  //  `powershell`), MSEXCEL/MSExcel DDE channels, or an external
  //  HYPERLINK/WEBSERVICE pointing outside the workbook — we escalate to
  //  critical, because the cell is actively weaponised, not just suspicious.
  // ═══════════════════════════════════════════════════════════════════════
  analyzeForSecurity(text) {
    const f = { risk: 'low', hasMacros: false, macroSize: 0, macroHash: '', autoExec: [], modules: [], externalRefs: [], metadata: {} };
    const lines = text.split('\n').slice(0, 5000);
    let anyFormula = false;
    let dangerHit = null;
    const DANGER_RE = /(cmd(?:\.exe)?\s*[|/]|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|\bDDE(?:AUTO)?\b|MSEXCEL\|['"]|MSExcel\|['"]|=\s*HYPERLINK\s*\(|=\s*WEBSERVICE\s*\(|=\s*IMPORTXML\s*\(|=\s*IMPORTDATA\s*\(|=\s*IMPORTHTML\s*\()/i;

    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      const t = l.trim();
      if (!t) continue;
      if (/^["']?[=+\-@]/.test(t) || /[,;\t|]["']?[=+\-@]/.test(l)) {
        anyFormula = true;
        if (!dangerHit) {
          const m = l.match(DANGER_RE);
          if (m) {
            const idx = m.index || 0;
            dangerHit = {
              line: i + 1,
              snippet: l.substring(Math.max(0, idx - 8), Math.min(l.length, idx + 80)).trim(),
            };
          }
        }
      }
    }

    if (dangerHit) {
      escalateRisk(f, 'critical');
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `Weaponised formula-injection payload (CWE-1236) on line ${dangerHit.line} — references command execution, DDE, or external data function: "${dangerHit.snippet}"`,
        severity: 'critical',
      });
    } else if (anyFormula) {
      escalateRisk(f, 'medium');
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'Formula injection risk (CWE-1236) — cells beginning with =, +, -, or @ detected. Opened in a spreadsheet these may execute if the user accepts the formula prompt.',
        severity: 'medium',
      });
    }
    return f;
  }
}
