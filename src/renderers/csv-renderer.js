'use strict';
// ════════════════════════════════════════════════════════════════════════════
// csv-renderer.js — thin CSV/TSV renderer on top of GridViewer.
//
// Virtual-scrolling, highlight state, drawer, filter, IOC/YARA navigation and
// lifecycle all live in GridViewer (see src/renderers/grid-viewer.js). This
// file's remaining jobs are:
//
//   1. Delimiter auto-detection (`,  ;  \t  |`) with quote-awareness.
//   2. Parsing CSV/TSV text into rows + byte offsets via an RFC-4180
//      state-machine parser. The parser is quote-aware across newlines —
//      a `\n` inside a `"..."` quoted cell is treated as literal cell
//      content, not a row terminator. State threads across calls so the
//      same parser drives both the in-memory sync path, the cooperative
//      streaming path (>2 MB files), and the off-thread timeline worker
//      (see src/workers/timeline.worker.js + src/app/timeline/timeline-view.js).
//   3. For files >2 MB the parse runs in cooperative chunks so the main
//      thread stays responsive: GridViewer paints the first ~1 k rows
//      within 200 ms and the rest streams in via `appendRows()`.
//   4. Formula-injection security analysis (CWE-1236).
//
// Exposes `render(text, fileName) → HTMLElement` and `analyzeForSecurity(text)`.
// The returned root element carries `._rawText` + `._csvFilters` so the sidebar
// click-to-focus engine in `app-sidebar-focus.js` works. Note that with the
// quote-aware parser a single logical row can span multiple physical `\n`
// characters; the `start`/`end` offsets handed to the grid viewer therefore
// span the whole multi-line cell, and `_rawText` remains the verbatim
// LF-normalised buffer (unmodified) so click-to-focus byte ranges still align.
// ════════════════════════════════════════════════════════════════════════════
class CsvRenderer {
  constructor() {
    // Chunk tunables. Numbers chosen to paint within ~200 ms on a 50 MB file.
    this.CHUNK_BYTES_SYNC    = 2 * 1024 * 1024;   // ≤ 2 MB — parse synchronously
    this.CHUNK_ROWS_FIRST    = 1000;              // first painted chunk size
    this.CHUNK_ROWS_STREAM   = 5000;              // subsequent streamed chunks
    this.MAX_ROWS            = RENDER_LIMITS.MAX_CSV_ROWS; // hard cap on rendered rows
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  RFC-4180 STATE-MACHINE PARSER (shared)
  //
  //  The single source of truth for CSV/TSV tokenisation in Loupe.
  //  Three callers:
  //    • this._parse              — sync in-memory parse (≤ CHUNK_BYTES_SYNC)
  //    • this._parseStreaming     — cooperative-yield parse for big files
  //    • timeline.worker.js       — chunked decoder feeding parser per chunk
  //    • timeline-view.js         — main-thread fallback for the worker path
  //
  //  Quote-aware across `\n`. A `"..."` cell may span any number of
  //  physical lines and contain literal `,` / `;` / `\t` / `|` / `\n`.
  //  Doubled quotes (`""`) inside a quoted cell escape to a single `"`.
  //
  //  parseChunk threads state across calls so the worker can feed
  //  successive decoded text chunks without ever materialising the full
  //  decoded buffer, and the in-memory streaming path can yield to the
  //  event loop between batches without losing parse state.
  //
  //  Returned rowOffsets are absolute char offsets into the caller's
  //  reference buffer (`baseOffset` + local index). For callers that
  //  don't care (the worker — it streams cells, not byte ranges) pass
  //  baseOffset:0 and ignore the rowOffsets array.
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Fresh parser state. Pass to parseChunk and reuse across calls.
   *   inQuotes          — currently inside a `"..."` cell?
   *   cur               — partial current cell content
   *   cells             — completed cells of the current partial row
   *   rowStart          — absolute char offset of the current partial
   *                       row's first content char (-1 = no row in flight)
   */
  static initParserState() {
    return { inQuotes: false, cur: '', cells: [], rowStart: -1 };
  }

  /**
   * Parse text into rows, threading `state` across calls.
   *
   * @param {string} text       buffer to scan
   * @param {number} fromIdx    char index to start from (inclusive)
   * @param {object} state      parser state from initParserState()
   * @param {string} delim      single-char field delimiter
   * @param {object} [opts]
   *   maxRows   {number}  emit at most this many rows then stop (0 = unbounded)
   *   baseOffset{number}  absolute char offset of `text[0]` in caller buffer
   *                       (used for rowOffsets); default 0
   *   flush     {boolean} if true and EOT reached with a pending row, emit it
   *                       (use on the FINAL parse call only)
   * @returns {{rows:Array<Array<string>>, rowOffsets:Array<{start,end}>,
   *           endIdx:number, endedInQuotes:boolean}}
   *   endIdx          — char index in `text` where parsing stopped (resume here)
   *   endedInQuotes   — true iff `flush` was true and the final emitted row
   *                     terminated mid-quoted-cell (caller should flag it
   *                     as malformed)
   */
  static parseChunk(text, fromIdx, state, delim, opts) {
    opts = opts || {};
    const maxRows    = opts.maxRows | 0;          // 0 = unbounded
    const baseOffset = opts.baseOffset | 0;
    const flush      = !!opts.flush;

    const len = text.length;
    const QUOTE = 34;   // '"'
    const NL    = 10;   // '\n'
    const delimCode = delim.charCodeAt(0);

    const rows       = [];
    const rowOffsets = [];

    // Hoist state into locals — measurable speedup over property access in
    // the hot loop on V8.
    let inQuotes = state.inQuotes;
    let cur      = state.cur;
    let cells    = state.cells;
    let rowStart = state.rowStart;

    let i = fromIdx | 0;

    while (i < len && (maxRows <= 0 || rows.length < maxRows)) {
      // ── Fast path: at the start of a fresh row, scan ahead for the
      //    next `\n` and the next `"`. If no quote appears before the
      //    newline we're looking at a plain unquoted line, which we can
      //    split natively (much faster than the char-by-char machine).
      //    This preserves the throughput of the previous line-based
      //    parser on the overwhelmingly common no-quote case.
      if (!inQuotes && rowStart < 0 && cells.length === 0 && cur === '') {
        const nlIdx = text.indexOf('\n', i);
        const lineEnd = nlIdx === -1 ? len : nlIdx;
        // Skip blank lines outright.
        if (lineEnd === i) { i = lineEnd + 1; continue; }
        const qIdx = text.indexOf('"', i);
        if (qIdx === -1 || qIdx >= lineEnd) {
          if (nlIdx === -1) {
            // No trailing newline — pending partial row. Fall through
            // to the char loop so flush semantics apply uniformly.
          } else {
            const line = text.substring(i, lineEnd);
            rows.push(line.split(delim));
            rowOffsets.push({ start: baseOffset + i, end: baseOffset + lineEnd });
            i = lineEnd + 1;
            continue;
          }
        }
      }

      const ch = text.charCodeAt(i);

      if (inQuotes) {
        if (ch === QUOTE) {
          // RFC-4180: doubled quote inside a quoted cell escapes to one quote.
          if (i + 1 < len && text.charCodeAt(i + 1) === QUOTE) {
            cur += '"';
            i += 2;
            continue;
          }
          inQuotes = false;
          i++;
          continue;
        }
        // Every other char (incl. \n, delim) is literal cell content.
        cur += text[i];
        i++;
        continue;
      }

      // Not in quotes.
      if (ch === NL) {
        // Blank physical line outside quotes — skip without emitting.
        if (rowStart < 0 && cells.length === 0 && cur === '') {
          i++;
          continue;
        }
        cells.push(cur);
        rows.push(cells);
        rowOffsets.push({
          start: rowStart < 0 ? baseOffset + i : rowStart,
          end:   baseOffset + i,
        });
        cells = [];
        cur = '';
        rowStart = -1;
        i++;
        continue;
      }

      // Any non-newline char marks the start of a row.
      if (rowStart < 0) rowStart = baseOffset + i;

      if (ch === QUOTE) {
        // Toggle into quoted mode. Mirrors the legacy _splitQuoted
        // behaviour (quote anywhere toggles); permissive vs strict
        // RFC-4180 (where a quote is only special at cell start) but
        // matches what real-world spreadsheets emit.
        inQuotes = true;
        i++;
        continue;
      }
      if (ch === delimCode) {
        cells.push(cur);
        cur = '';
        i++;
        continue;
      }
      cur += text[i];
      i++;
    }

    let endedInQuotes = false;
    if (flush && i >= len &&
        (cells.length > 0 || cur.length > 0 || rowStart >= 0 || inQuotes)) {
      // Final partial row — emit. If we're still inQuotes the cell was
      // never closed; surface that so the caller can flag the row.
      cells.push(cur);
      rows.push(cells);
      rowOffsets.push({
        start: rowStart < 0 ? baseOffset + len : rowStart,
        end:   baseOffset + len,
      });
      if (inQuotes) endedInQuotes = true;
      cells = [];
      cur = '';
      rowStart = -1;
      inQuotes = false;
    }

    state.inQuotes = inQuotes;
    state.cur      = cur;
    state.cells    = cells;
    state.rowStart = rowStart;

    return { rows, rowOffsets, endIdx: i, endedInQuotes };
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
      empty._rawText = lfNormalize('');
      return empty;
    }

    // Parse the header via the same state-machine parser as the body —
    // this is what makes a multi-line quoted header cell work. The
    // body parse resumes from `headerEndIdx`, so `_rawText` offsets
    // returned for body rows align with the original normalised text.
    const headerState = CsvRenderer.initParserState();
    const headerResult = CsvRenderer.parseChunk(text, 0, headerState, delim, {
      baseOffset: 0,
      maxRows:    1,
      flush:      false,
    });
    let headerRow;
    let headerEndIdx;
    if (headerResult.rows.length) {
      headerRow    = headerResult.rows[0];
      headerEndIdx = headerResult.endIdx;
    } else {
      // Single-line file with no trailing newline — flush to extract.
      const flushResult = CsvRenderer.parseChunk(text, headerResult.endIdx, headerState, delim, {
        baseOffset: 0,
        maxRows:    0,
        flush:      true,
      });
      headerRow    = flushResult.rows[0] || [];
      headerEndIdx = text.length;
    }

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
      const { rows, rowOffsets, endedInQuotes } = this._parse(text, delim, headerEndIdx);
      const { rows: capped, rowOffsets: cappedOff, truncated, originalCount } =
        this._capRows(rows, rowOffsets);
      const rowSearchText = new Array(capped.length);
      const malformed = new Set();
      const expectedCols = headerRow.length;
      for (let i = 0; i < capped.length; i++) {
        const r = capped[i];
        // Width policy: pad short rows silently (common for CSVs assembled
        // from multiple sources); flag rows that have MORE columns than
        // the header (more likely real corruption / quote-escape damage).
        if (r.length > expectedCols) {
          malformed.add(i);
        } else if (expectedCols && r.length < expectedCols) {
          while (r.length < expectedCols) r.push('');
        }
        rowSearchText[i] = r.join(' ').toLowerCase();
      }
      // An unterminated `"` at EOF means the last emitted row's final
      // cell ate everything to the end of the file. Flag it so the
      // analyst sees the malformed-row counter tick up by one.
      if (endedInQuotes && capped.length) malformed.add(capped.length - 1);
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
    this._parseStreaming(text, delim, headerEndIdx, headerRow.length, viewer);
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
  //  Auto-detect delimiter by counting unquoted occurrences over the first
  //  ~4 KB of the buffer. Quote-aware across newlines so a header with a
  //  multi-line quoted cell doesn't poison the sniff. Stops at the first
  //  *unquoted* `\n` (i.e. the end of the logical header row).
  // ═══════════════════════════════════════════════════════════════════════
  _delim(text) {
    const SAMPLE = 4096;
    const limit = Math.min(text.length, SAMPLE);
    const c = { ',': 0, ';': 0, '\t': 0, '|': 0 };
    let inQ = false;
    for (let i = 0; i < limit; i++) {
      const ch = text[i];
      if (ch === '"') { inQ = !inQ; continue; }
      if (inQ) continue;
      if (ch === '\n') break;        // end of logical header row
      if (c[ch] !== undefined) c[ch]++;
    }
    return Object.entries(c).sort((a, b) => b[1] - a[1])[0][0];
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Full-buffer synchronous parse (used for files ≤ CHUNK_BYTES_SYNC).
  //  Thin wrapper around parseChunk with flush:true so any trailing
  //  partial row (file ends without a newline, or mid-quoted-cell) is
  //  emitted.
  // ═══════════════════════════════════════════════════════════════════════
  _parse(text, delim, startOffset) {
    const state = CsvRenderer.initParserState();
    const result = CsvRenderer.parseChunk(text, startOffset || 0, state, delim, {
      baseOffset: 0,
      maxRows:    0,
      flush:      true,
    });
    return {
      rows:          result.rows,
      rowOffsets:    result.rowOffsets,
      endedInQuotes: result.endedInQuotes,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Streaming parse — yields control back to the event loop every
  //  CHUNK_ROWS_STREAM rows so the first paint isn't blocked by a 50 MB
  //  parse. Feeds the viewer via `appendRows()` + `updateParseProgress()`.
  //  Threads parser state across yields so multi-line quoted cells that
  //  straddle a chunk boundary are handled correctly.
  // ═══════════════════════════════════════════════════════════════════════
  _parseStreaming(text, delim, startOffset, colCount, viewer) {
    const state = CsvRenderer.initParserState();
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

    const ingestRows = (chunkRows, chunkOffsets) => {
      const chunkSearch = new Array(chunkRows.length);
      for (let i = 0; i < chunkRows.length; i++) {
        const r = chunkRows[i];
        if (r.length > colCount) {
          malformed.add(totalRows + i);
        } else if (colCount && r.length < colCount) {
          while (r.length < colCount) r.push('');
        }
        chunkSearch[i] = r.join(' ').toLowerCase();
      }
      viewer.appendRows(chunkRows, chunkSearch, chunkOffsets);
      totalRows += chunkRows.length;
      if (malformed.size) viewer.setMalformedRows(malformed);
    };

    const self = this;
    const parseChunk = (chunkCap) => {
      if (viewer._destroyed) return;

      if (offset >= len || totalRows >= MAX) {
        // EOF — final flush. If a partial row is still pending, emit it.
        if (offset >= len && totalRows < MAX) {
          const flushResult = CsvRenderer.parseChunk(text, offset, state, delim, {
            baseOffset: 0,
            maxRows:    0,
            flush:      true,
          });
          if (flushResult.rows.length) {
            ingestRows(flushResult.rows, flushResult.rowOffsets);
            if (flushResult.endedInQuotes) malformed.add(totalRows - 1);
            if (malformed.size) viewer.setMalformedRows(malformed);
          }
        }
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

      const cap = Math.min(chunkCap, MAX - totalRows);
      const result = CsvRenderer.parseChunk(text, offset, state, delim, {
        baseOffset: 0,
        maxRows:    cap,
        flush:      false,
      });
      offset = result.endIdx;

      if (result.rows.length) {
        ingestRows(result.rows, result.rowOffsets);
        viewer.updateParseProgress(
          totalRows,
          Math.max(totalRows, Math.floor(len / Math.max(1, offset / Math.max(1, totalRows))))
        );
      }

      if (totalRows >= MAX && offset < len) truncated = true;

      yieldNext(() => parseChunk(self.CHUNK_ROWS_STREAM));
    };

    // Kick off with a smaller first chunk for faster first paint.
    parseChunk(this.CHUNK_ROWS_FIRST);
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Legacy single-line splitter — retained for back-compat with any
  //  external caller that imported the old shape (none in-tree as of
  //  the parser refactor, but cheap to keep). Operates on a single line
  //  and ASSUMES the caller has already pre-split on `\n`. New code
  //  should use parseChunk instead.
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
