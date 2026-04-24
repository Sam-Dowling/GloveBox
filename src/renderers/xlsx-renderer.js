'use strict';
// ════════════════════════════════════════════════════════════════════════════
// xlsx-renderer.js — Renders .xlsx / .xlsm / .xls / .ods via SheetJS.
//
// Each sheet is rendered through the shared GridViewer (virtual scroll,
// right-side drawer, IOC/YARA highlight, filter). Merged-cell rendering is
// collapsed (the top-left of every merge carries the value; continuation
// cells become blank).
//
// Depends on: vba-utils.js, XLSX (vendor / SheetJS), JSZip (vendor)
// ════════════════════════════════════════════════════════════════════════════
class XlsxRenderer {
  render(buffer, fileName) {
    const wrap = document.createElement('div');
    wrap.className = 'xlsx-view';
    let wb;
    try {
      wb = XLSX.read(new Uint8Array(buffer), {
        type: 'array',
        cellStyles: true,
        cellDates: true,
        sheetRows: 10001
      });
    } catch (e) {
      return this._err(wrap, 'Failed to parse spreadsheet', e.message);
    }
    if (!wb.SheetNames.length) {
      wrap.textContent = 'No sheets found.';
      return wrap;
    }

    const tabBar = document.createElement('div');
    tabBar.className = 'sheet-tab-bar';
    wrap.appendChild(tabBar);

    const area = document.createElement('div');
    area.className = 'sheet-content-area';
    wrap.appendChild(area);

    const self = this;
    const panes = wb.SheetNames.map((name) => {
      const tab = document.createElement('button');
      tab.className = 'sheet-tab';
      tab.textContent = name;
      tabBar.appendChild(tab);

      const pane = document.createElement('div');
      pane.className = 'sheet-content';
      pane.style.display = 'none';
      area.appendChild(pane);

      const p = { tab, pane, done: false, viewer: null };
      tab.addEventListener('click', () => {
        panes.forEach(x => {
          x.tab.classList.remove('active');
          x.pane.style.display = 'none';
        });
        tab.classList.add('active');
        // `flex` (not `block`) so the new .sheet-content flex-column
        // layout in viewers.css engages — lets the embedded GridViewer
        // fill the fixed-height `.sheet-content-area` slot. See the
        // block-comment above `.sheet-content-area` for the full flex-
        // chain rationale.
        pane.style.display = 'flex';
        if (!p.done) {
          self._renderSheet(wb.Sheets[name], pane, name);
          p.done = true;
        }
      });
      return p;
    });
    panes[0].tab.click();
    return wrap;
  }

  // ── Render one sheet via GridViewer ────────────────────────────────────
  _renderSheet(ws, container, sheetName) {
    if (!ws || !ws['!ref']) {
      const p = document.createElement('p');
      p.style.cssText = 'color:#888;padding:20px';
      p.textContent = 'Empty sheet';
      container.appendChild(p);
      return;
    }

    const rng = XLSX.utils.decode_range(ws['!ref']);
    const maxR = Math.min(rng.e.r, rng.s.r + 9999);
    const merges = ws['!merges'] || [];

    // Merge-continuation cells: blank out everything that isn't the
    // top-left of a merge range. The top-left keeps its value.
    const mSkip = new Set();
    for (const m of merges) {
      for (let r = m.s.r; r <= m.e.r; r++) {
        for (let c = m.s.c; c <= m.e.c; c++) {
          if (r !== m.s.r || c !== m.s.c) mSkip.add(r + ',' + c);
        }
      }
    }

    // ── Columns: A, B, C, …  use spreadsheet letters so analyst-facing
    //    cell references line up with external docs / formulas.
    const columns = [];
    for (let c = rng.s.c; c <= rng.e.c; c++) {
      columns.push(XLSX.utils.encode_col(c));
    }

    // ── Rows: flatten into plain string arrays; prepend per-row search
    //    text index so GridViewer's filter reaches every rendered value.
    const rows = [];
    const rowSearchText = [];
    for (let r = rng.s.r; r <= maxR; r++) {
      const row = new Array(columns.length);
      const searchParts = [];
      for (let c = rng.s.c; c <= rng.e.c; c++) {
        const colIdx = c - rng.s.c;
        if (mSkip.has(r + ',' + c)) {
          row[colIdx] = '';
          continue;
        }
        const cell = ws[XLSX.utils.encode_cell({ r, c })];
        if (!cell) {
          row[colIdx] = '';
          continue;
        }
        const txt = cell.w !== undefined
          ? cell.w
          : (cell.t === 'b' ? (cell.v ? 'TRUE' : 'FALSE')
            : (cell.t === 'e' ? '#ERR'
              : String(cell.v == null ? '' : cell.v)));
        row[colIdx] = txt;
        if (txt) searchParts.push(txt);
      }
      rows.push(row);
      rowSearchText.push(searchParts.join(' ').toLowerCase());
    }

    const truncNote = maxR < rng.e.r
      ? `⚠ Showing first ${(maxR - rng.s.r + 1).toLocaleString()} of ${(rng.e.r - rng.s.r + 1).toLocaleString()} rows`
      : '';

    const infoText = `${sheetName} · ${rows.length.toLocaleString()} rows × ${columns.length} cols`
      + (merges.length ? ` · ${merges.length} merged range${merges.length > 1 ? 's' : ''}` : '');

    const self = this;
    const viewer = new GridViewer({
      columns,
      rows,
      rowSearchText,
      rawText: '',
      className: 'xlsx-sheet-view csv-view',
      infoText,
      truncationNote: truncNote,
      // Right-align numeric cells to mirror Excel's alignment convention.
      cellClass: (dataIdx, colIdx) => {
        const c = rng.s.c + colIdx;
        const cell = ws[XLSX.utils.encode_cell({ r: rng.s.r + dataIdx, c })];
        return (cell && cell.t === 'n') ? 'xlsx-cell-num' : null;
      },
      rowTitle: (dataIdx) => `Row ${rng.s.r + dataIdx + 1}`,
      detailBuilder: (dataIdx) => self._buildDetailPane(ws, rng, dataIdx, columns)
    });

    container.appendChild(viewer.root());
  }

  // ── Per-row detail pane: spreadsheet-style key/value layout with the
  //    raw cell value, the formula (if any), and the computed type. ──────
  _buildDetailPane(ws, rng, dataIdx, columns) {
    const container = document.createElement('div');
    const pane = document.createElement('div');
    pane.className = 'evtx-detail-pane';

    const heading = document.createElement('h4');
    heading.textContent = `Row ${rng.s.r + dataIdx + 1}`;
    pane.appendChild(heading);

    const grid = document.createElement('div');
    grid.className = 'evtx-detail-grid';

    for (let ci = 0; ci < columns.length; ci++) {
      const c = rng.s.c + ci;
      const cell = ws[XLSX.utils.encode_cell({ r: rng.s.r + dataIdx, c })];
      if (!cell) continue;

      const keyEl = document.createElement('div');
      keyEl.className = 'evtx-detail-key';
      keyEl.textContent = columns[ci];
      grid.appendChild(keyEl);

      const valEl = document.createElement('div');
      valEl.className = 'evtx-detail-val';
      const display = cell.w !== undefined
        ? cell.w
        : (cell.t === 'b' ? (cell.v ? 'TRUE' : 'FALSE')
          : (cell.t === 'e' ? '#ERR'
            : String(cell.v == null ? '' : cell.v)));
      valEl.textContent = display;
      grid.appendChild(valEl);

      // Formula row (if the cell carries one)
      if (cell.f) {
        const fKey = document.createElement('div');
        fKey.className = 'evtx-detail-key';
        fKey.textContent = columns[ci] + ' (formula)';
        fKey.style.opacity = '0.7';
        grid.appendChild(fKey);

        const fVal = document.createElement('div');
        fVal.className = 'evtx-detail-val';
        fVal.style.fontFamily = 'var(--font-mono, monospace)';
        fVal.textContent = '=' + cell.f;
        grid.appendChild(fVal);
      }
    }
    pane.appendChild(grid);
    container.appendChild(pane);
    return container;
  }

  // ── Security analysis ──────────────────────────────────────────────────
  async analyzeForSecurity(buffer, fileName) {
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const f = { risk: 'low', hasMacros: false, macroSize: 0, autoExec: [], modules: [], externalRefs: [], metadata: {} };
    try {
      const wb = XLSX.read(new Uint8Array(buffer), { type: 'array', bookVBA: true });
      if (wb.Props) {
        f.metadata = {
          title: wb.Props.Title || '',
          subject: wb.Props.Subject || '',
          creator: wb.Props.Author || '',
          lastModifiedBy: wb.Props.LastAuthor || '',
          created: wb.Props.CreatedDate ? new Date(wb.Props.CreatedDate).toLocaleString() : '',
          modified: wb.Props.ModifiedDate ? new Date(wb.Props.ModifiedDate).toLocaleString() : '',
        };
      }
      if (wb.vbaraw || ['xlsm', 'xltm', 'xlam'].includes(ext)) {
        f.hasMacros = true; f.risk = 'medium';
        if (wb.vbaraw) f.macroSize = wb.vbaraw.byteLength || wb.vbaraw.length || 0;
        try {
          const zip = await JSZip.loadAsync(buffer);
          const vbaEntry = zip.file('xl/vbaProject.bin') || zip.file('xl/vbaProject.bin'.replace('xl/', ''));
          if (vbaEntry) {
            const vbaData = await vbaEntry.async('uint8array');
            if (!f.macroSize) f.macroSize = vbaData.length;
            f.rawBin = vbaData;
            f.modules = parseVBAText(vbaData);
            for (const m of f.modules) {
              if (!m.source) continue;
              const pats = autoExecPatterns(m.source);
              if (pats.length) { f.autoExec.push({ module: m.name, patterns: pats }); f.risk = 'high'; }
            }
          }
          if (!f.rawBin && wb.vbaraw)
            f.rawBin = wb.vbaraw instanceof Uint8Array ? wb.vbaraw : new Uint8Array(wb.vbaraw);
        } catch (e) {
          if (!f.rawBin && wb.vbaraw) {
            try { f.rawBin = wb.vbaraw instanceof Uint8Array ? wb.vbaraw : new Uint8Array(wb.vbaraw); } catch (_) { }
          }
        }
      }
      if (['xlsx', 'xlsm', 'xltx', 'xltm', 'xlam', 'xlsb'].includes(ext)) {
        try {
          const zip = await JSZip.loadAsync(buffer);
          const relRefs = await OoxmlRelScanner.scan(zip);
          for (const r of relRefs) {
            f.externalRefs.push(r);
            if (r.severity === 'high') f.risk = 'high';
            else if (r.severity === 'medium' && f.risk === 'low') f.risk = 'medium';
          }
        } catch (e) { /* ignore */ }
      }

      const HIGH_RISK_FNS = new Set(['WEBSERVICE', 'IMPORTDATA', 'CALL', 'REGISTER', 'REGISTER.ID', 'EXEC', 'FORMULA', 'FWRITELN', 'FWRITE']);
      const MEDIUM_RISK_FNS = new Set(['HYPERLINK', 'RTD', 'DDEINIT', 'DDE']);
      const formulaHits = [];
      const urlHits = [];
      try {
        for (const name of (wb.SheetNames || [])) {
          const ws = wb.Sheets[name];
          if (!ws) continue;
          let hidden = ws.Hidden;
          if (hidden === undefined && wb.Workbook && Array.isArray(wb.Workbook.Sheets)) {
            const idx = wb.SheetNames.indexOf(name);
            if (idx >= 0 && wb.Workbook.Sheets[idx]) hidden = wb.Workbook.Sheets[idx].Hidden;
          }
          if (hidden === 2) {
            pushIOC(f, {
              type: IOC.PATTERN,
              value: `Very hidden sheet: "${name}"`,
              severity: 'medium',
              note: 'visibility state settable only from VBA editor',
              bucket: 'externalRefs',
            });
            if (f.risk === 'low') f.risk = 'medium';
          }
          if (!ws['!ref']) continue;
          const rng = XLSX.utils.decode_range(ws['!ref']);
          const CELL_BUDGET = 200_000;
          let scanned = 0;
          outer:
          for (let r = rng.s.r; r <= rng.e.r; r++) {
            for (let c = rng.s.c; c <= rng.e.c; c++) {
              if (++scanned > CELL_BUDGET) break outer;
              const cell = ws[XLSX.utils.encode_cell({ r, c })];
              if (!cell || !cell.f) continue;
              const fml = String(cell.f);
              const fnMatches = fml.match(/(?:_xl(?:fn|ws)\.)?[A-Z][A-Z0-9_.]*(?=\s*\()/gi) || [];
              for (const raw of fnMatches) {
                const fn = raw.replace(/^_xl(?:fn|ws)\./i, '').toUpperCase();
                if (HIGH_RISK_FNS.has(fn)) {
                  formulaHits.push({ sheet: name, addr: XLSX.utils.encode_cell({ r, c }), fn, formula: fml, sev: 'high' });
                } else if (MEDIUM_RISK_FNS.has(fn)) {
                  formulaHits.push({ sheet: name, addr: XLSX.utils.encode_cell({ r, c }), fn, formula: fml, sev: 'medium' });
                }
              }
              const urls = extractUrls(fml, 8);
              for (const u of urls) urlHits.push({ sheet: name, addr: XLSX.utils.encode_cell({ r, c }), url: u });
            }
          }
        }
      } catch (_) { }

      try {
        const names = (wb.Workbook && wb.Workbook.Names) || [];
        for (const n of names) {
          if (!n || !n.Name) continue;
          const nm = String(n.Name);
          const ref = String(n.Ref || '');
          if (/^Auto_Open$|^Auto_Close$|^Workbook_Open$|^Auto_Activate$|^Auto_Deactivate$/i.test(nm)) {
            pushIOC(f, {
              type: IOC.PATTERN,
              value: `Defined Name "${nm}" → ${ref || '(empty)'}`,
              severity: 'high',
              note: 'XLM/Excel-4.0 auto-exec name',
              bucket: 'externalRefs',
            });
            f.risk = 'high';
          }
          if (ref && /^\s*[\[\\]/.test(ref)) {
            pushIOC(f, {
              type: IOC.PATTERN,
              value: `Defined Name "${nm}" references external: ${ref}`,
              severity: 'medium',
              note: 'external-workbook or UNC-path link in defined name',
              bucket: 'externalRefs',
            });
            if (f.risk === 'low') f.risk = 'medium';
          }
          for (const u of extractUrls(ref, 4)) {
            pushIOC(f, { type: IOC.URL, value: u, severity: 'medium', note: `defined name "${nm}"`, bucket: 'externalRefs' });
          }
        }
      } catch (_) { }

      const FORMULA_CAP = 100;
      const shownFormulas = formulaHits.slice(0, FORMULA_CAP);
      for (const h of shownFormulas) {
        pushIOC(f, {
          type: IOC.PATTERN,
          value: `${h.fn}() in ${h.sheet}!${h.addr}`,
          severity: h.sev,
          highlightText: h.formula.length > 200 ? h.formula.slice(0, 200) + '…' : h.formula,
          note: h.sev === 'high' ? 'high-risk spreadsheet function' : 'network/hyperlink formula',
          bucket: 'externalRefs',
        });
        if (h.sev === 'high') f.risk = 'high';
        else if (h.sev === 'medium' && f.risk === 'low') f.risk = 'medium';
      }
      if (formulaHits.length > FORMULA_CAP) {
        pushIOC(f, {
          type: IOC.INFO,
          value: `+${formulaHits.length - FORMULA_CAP} more risky formulas truncated`,
          severity: 'info',
          bucket: 'externalRefs',
        });
      }
      const URL_CAP = 200;
      const seenUrl = new Set();
      let urlCount = 0;
      for (const u of urlHits) {
        if (seenUrl.has(u.url)) continue;
        seenUrl.add(u.url);
        if (++urlCount > URL_CAP) break;
        pushIOC(f, {
          type: IOC.URL,
          value: u.url,
          severity: 'medium',
          note: `formula in ${u.sheet}!${u.addr}`,
          bucket: 'externalRefs',
        });
        if (f.risk === 'low') f.risk = 'medium';
      }
    } catch (e) {
      f.metadata.parseError = e.message || 'Unknown parse error';
      if (typeof pushIOC === 'function') {
        pushIOC(f, {
          type: (typeof IOC !== 'undefined' && IOC.INFO) || 'info',
          value: 'Failed to parse: ' + (e.message || 'unknown error'),
          severity: 'medium',
          note: 'The spreadsheet could not be fully parsed — results may be incomplete',
          bucket: 'externalRefs',
        });
      }
    }
    return f;
  }

  _err(wrap, title, msg) {
    const b = document.createElement('div'); b.className = 'error-box';
    const h = document.createElement('h3'); h.textContent = title; b.appendChild(h);
    const p = document.createElement('p'); p.textContent = msg; b.appendChild(p);
    wrap.appendChild(b); return wrap;
  }
}
