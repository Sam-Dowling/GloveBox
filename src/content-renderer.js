'use strict';
// ════════════════════════════════════════════════════════════════════════════
// content-renderer.js — Converts a parsed DOCX structure into a DOM tree
// Depends on: constants.js, style-resolver.js, numbering-resolver.js
// ════════════════════════════════════════════════════════════════════════════
class ContentRenderer {
  constructor(parsed) {
    this.parsed = parsed;
    this.sr = new StyleResolver(parsed.styles);
    this.nr = new NumberingResolver(parsed.numbering);
    this.rels = this._buildRelMap(parsed.rels);
    this.pageNum = 0;
  }

  _buildRelMap(doc) {
    const map = {};
    if (!doc) return map;
    for (const rel of doc.getElementsByTagNameNS(PKG, 'Relationship')) {
      const id = rel.getAttribute('Id');
      if (id) map[id] = { type: rel.getAttribute('Type'), target: rel.getAttribute('Target'), mode: rel.getAttribute('TargetMode') };
    }
    return map;
  }

  render() {
    const container = document.createElement('div'); container.className = 'doc-container';
    if (!this.parsed.document) {
      const e = document.createElement('p'); e.className = 'error-inline'; e.textContent = '⚠ Failed to parse document.xml';
      container.appendChild(e); return container;
    }
    const body = this.parsed.document.getElementsByTagNameNS(W, 'body')[0];
    if (!body) { container.textContent = 'No document body found.'; return container; }

    let curSectPr = wfirst(body, 'sectPr');
    let curPage = this._newPage(this._pageProp(curSectPr));
    this.pageNum = 1;
    this._addHeader(curPage, curSectPr);
    container.appendChild(curPage);

    const nextPage = (sp) => {
      this._addFooter(curPage, curSectPr);
      const pg = this._newPage(this._pageProp(sp || curSectPr));
      this.pageNum++;
      this._addHeader(pg, sp || curSectPr);
      container.appendChild(pg);
      if (sp) curSectPr = sp;
      return pg;
    };

    for (const child of Array.from(body.childNodes)) {
      if (child.nodeType !== 1) continue;
      const ln = child.localName;
      try {
        if (ln === 'sectPr') {
          curPage = nextPage(child);
        } else if (ln === 'p') {
          const { nodes, pgBrkBefore, pgBrkAfter } = this._para(child);
          if (pgBrkBefore) curPage = nextPage();
          for (const n of nodes) curPage.appendChild(n);
          if (pgBrkAfter) curPage = nextPage();
        } else if (ln === 'tbl') {
          curPage.appendChild(this._table(child));
        } else if (ln === 'sdt') {
          const sc = wfirst(child, 'sdtContent');
          if (sc) this._sdtContent(sc, curPage, () => { curPage = nextPage(); return curPage; });
        } else if (ln === 'AlternateContent') {
          const fb = child.getElementsByTagNameNS(MC_NS, 'Fallback')[0];
          if (fb) for (const c of Array.from(fb.childNodes)) {
            if (c.nodeType !== 1) continue;
            if (c.localName === 'p') { const { nodes } = this._para(c); for (const n of nodes) curPage.appendChild(n); }
            else if (c.localName === 'tbl') curPage.appendChild(this._table(c));
          }
        }
      } catch (e) {
        const err = document.createElement('span'); err.className = 'error-inline';
        err.textContent = ` ⚠[${ln}: ${e.message}] `; curPage.appendChild(err);
      }
    }
    this._addFooter(curPage, curSectPr);
    return container;
  }

  _sdtContent(sc, curPage, getNewPage) {
    for (const c of Array.from(sc.childNodes)) {
      if (c.nodeType !== 1) continue;
      if (c.localName === 'p') { try { const { nodes } = this._para(c); for (const n of nodes) curPage.appendChild(n); } catch (e) { } }
      else if (c.localName === 'tbl') try { curPage.appendChild(this._table(c)); } catch (e) { }
    }
  }

  _pageProp(sectPr) {
    const d = { w: 12240, h: 15840, mt: 1440, mr: 1440, mb: 1440, ml: 1440 };
    if (!sectPr) return d;
    const pgSz = wfirst(sectPr, 'pgSz'); if (pgSz) { const w = wa(pgSz, 'w'), h = wa(pgSz, 'h'); if (w) d.w = parseInt(w); if (h) d.h = parseInt(h); }
    const pgMar = wfirst(sectPr, 'pgMar');
    if (pgMar) {
      const t = wa(pgMar, 'top'), r = wa(pgMar, 'right'), b = wa(pgMar, 'bottom'), l = wa(pgMar, 'left');
      if (t) d.mt = parseInt(t); if (r) d.mr = parseInt(r); if (b) d.mb = parseInt(b); if (l) d.ml = parseInt(l);
    }
    return d;
  }

  _newPage(pp) {
    const div = document.createElement('div'); div.className = 'page';
    div.style.width = `${dxaToPx(pp.w)}px`; div.style.minHeight = `${dxaToPx(pp.h)}px`;
    div.style.paddingTop = `${dxaToPx(pp.mt)}px`; div.style.paddingRight = `${dxaToPx(pp.mr)}px`;
    div.style.paddingBottom = `${dxaToPx(pp.mb)}px`; div.style.paddingLeft = `${dxaToPx(pp.ml)}px`;
    return div;
  }

  _getHFXml(sectPr, isHeader) {
    if (!sectPr) return this._firstHF(isHeader);
    const tag = isHeader ? 'headerReference' : 'footerReference';
    const store = isHeader ? this.parsed.headers : this.parsed.footers;
    for (const ref of sectPr.getElementsByTagNameNS(W, tag)) {
      const type = wa(ref, 'type'), rId = ra(ref, 'id');
      if ((type === 'default' || type === 'first') && rId) {
        const rel = this.rels[rId];
        if (rel) { const fn = rel.target.replace(/^\.\.\/word\//, '').split('/').pop(); if (store[fn]) return store[fn]; }
      }
    }
    return this._firstHF(isHeader);
  }

  _firstHF(isHeader) {
    const store = isHeader ? this.parsed.headers : this.parsed.footers;
    const vals = Object.values(store); return vals.length ? vals[0] : null;
  }

  _addHeader(page, sectPr) {
    const xml = this._getHFXml(sectPr, true); if (!xml) return;
    const div = document.createElement('div'); div.className = 'page-header';
    this._renderHF(div, xml); page.insertBefore(div, page.firstChild);
  }

  _addFooter(page, sectPr) {
    const xml = this._getHFXml(sectPr, false); if (!xml) return;
    const div = document.createElement('div'); div.className = 'page-footer';
    this._renderHF(div, xml); page.appendChild(div);
  }

  _renderHF(container, xmlDoc) {
    const body = xmlDoc.getElementsByTagNameNS(W, 'body')[0] || xmlDoc.documentElement;
    for (const c of Array.from(body.childNodes)) {
      if (c.nodeType !== 1) continue;
      if (c.localName === 'p') try { const { nodes } = this._para(c); for (const n of nodes) container.appendChild(n); } catch (e) { }
    }
  }

  // ── Paragraph ──────────────────────────────────────────────────────────────
  _para(pEl) {
    const nodes = []; let pgBrkBefore = false, pgBrkAfter = false;
    const pPr = wfirst(pEl, 'pPr');
    const dirPPr = pPr ? this.sr._ppr(pPr) : {};
    const styleDef = dirPPr.styleId ? this.sr.resolveParaStyle(dirPPr.styleId) : { pPr: {}, rPr: {} };
    const mergedPPr = { ...styleDef.pPr, ...dirPPr };
    const baseRPr = { ...styleDef.rPr };
    if (mergedPPr.pageBreakBefore) pgBrkBefore = true;
    const hlv = this.sr.isHeading(dirPPr.styleId || mergedPPr.styleId);
    const tag = hlv && hlv >= 1 && hlv <= 6 ? `h${hlv}` : 'p';
    const numId = mergedPPr.numId, ilvl = mergedPPr.ilvl || 0;
    const isList = numId && numId !== '0';

    let hasPgBrk = false;
    for (const c of pEl.childNodes) {
      if (c.nodeType !== 1) continue;
      if (c.localName === 'r') for (const br of c.getElementsByTagNameNS(W, 'br')) if (wa(br, 'type') === 'page') { hasPgBrk = true; break; }
      if (hasPgBrk) break;
    }
    if (hasPgBrk) pgBrkAfter = true;

    const el = document.createElement(tag);
    el.className = isList ? 'list-item' : 'para';
    this._applyPPr(el, mergedPPr, isList);

    if (isList) {
      const lv = this.nr.getLvl(numId, ilvl);
      const count = this.nr.nextCount(numId, ilvl);
      const indL = lv?.indent?.left || ((ilvl + 1) * 720);
      const hang = lv?.indent?.hanging || 360;
      el.style.paddingLeft = `${dxaToPx(indL)}px`;
      const mk = document.createElement('span'); mk.className = 'list-marker';
      mk.style.left = `${dxaToPx(indL - hang)}px`; mk.style.width = `${dxaToPx(hang)}px`;
      mk.textContent = this.nr.formatMarker(numId, ilvl, count);
      el.appendChild(mk);
    }
    const allRuns = Array.from(pEl.childNodes).filter(n => n.nodeType === 1);
    this._renderRuns(el, allRuns, baseRPr);
    nodes.push(el);
    return { nodes, pgBrkBefore, pgBrkAfter };
  }

  // ── Run collection ─────────────────────────────────────────────────────────
  _renderRuns(container, runEls, baseRPr) {
    for (const el of runEls) {
      if (el.nodeType !== 1) continue;
      const ln = el.localName;
      try {
        if (ln === 'r') this._run(container, el, baseRPr);
        else if (ln === 'hyperlink') this._hyperlink(container, el, baseRPr);
        else if (ln === 'bookmarkStart') {
          const anc = document.createElement('a'); const nm = wa(el, 'name'); if (nm) anc.id = nm; container.appendChild(anc);
        }
        else if (ln === 'ins') { for (const c of el.childNodes) { if (c.nodeType === 1 && c.localName === 'r') this._run(container, c, baseRPr); } }
        else if (ln === 'smartTag' || ln === 'customXml') {
          for (const c of el.childNodes) { if (c.nodeType === 1 && c.localName === 'r') this._run(container, c, baseRPr); }
        }
        else if (ln === 'sdt') {
          const sc = wfirst(el, 'sdtContent');
          if (sc) for (const c of sc.childNodes) { if (c.nodeType === 1 && c.localName === 'r') this._run(container, c, baseRPr); }
        }
        else if (ln === 'fldSimple') {
          const instr = (wa(el, 'instr') || '').trim();
          if (/^\s*PAGE\s*$/i.test(instr)) {
            const sp = document.createElement('span'); sp.textContent = String(this.pageNum); container.appendChild(sp);
          } else {
            for (const c of el.childNodes) { if (c.nodeType === 1 && c.localName === 'r') this._run(container, c, baseRPr); }
          }
        }
        else if (ln === 'AlternateContent') {
          const fb = el.getElementsByTagNameNS(MC_NS, 'Fallback')[0];
          if (fb) for (const c of fb.childNodes) { if (c.nodeType === 1 && c.localName === 'r') this._run(container, c, baseRPr); }
        }
      } catch (e) {
        const err = document.createElement('span'); err.className = 'error-inline'; err.textContent = '⚠'; container.appendChild(err);
      }
    }
  }

  // ── Single run ─────────────────────────────────────────────────────────────
  _run(container, rEl, baseRPr) {
    const rPr = wfirst(rEl, 'rPr');
    const dirRPr = rPr ? this.sr._rpr(rPr) : {};
    const styleRPr = dirRPr.rStyleId ? this.sr.resolveRunStyle(dirRPr.rStyleId) : {};
    const merged = { ...baseRPr, ...styleRPr, ...dirRPr };
    for (const child of rEl.childNodes) {
      if (child.nodeType !== 1) continue;
      const ln = child.localName;
      if (ln === 't') {
        const txt = child.textContent; if (!txt) continue;
        const sp = document.createElement('span'); this._applyRPr(sp, merged);
        sp.appendChild(document.createTextNode(txt)); container.appendChild(sp);
      } else if (ln === 'br') {
        if (wa(child, 'type') !== 'page') container.appendChild(document.createElement('br'));
      } else if (ln === 'tab') {
        const sp = document.createElement('span'); sp.className = 'tab'; container.appendChild(sp);
      } else if (ln === 'drawing') {
        const img = this._drawing(child); if (img) container.appendChild(img);
      } else if (ln === 'pict') {
        const img = this._pict(child); if (img) container.appendChild(img);
      } else if (ln === 'sym') {
        const sp = document.createElement('span');
        const font = wa(child, 'font'), char = wa(child, 'char');
        if (font) sp.style.fontFamily = font;
        if (char) sp.appendChild(document.createTextNode(String.fromCharCode(parseInt(char, 16))));
        container.appendChild(sp);
      }
    }
  }

  _hyperlink(container, hlEl, baseRPr) {
    const span = document.createElement('span'); span.className = 'doc-link';
    const rId = ra(hlEl, 'id'), anchor = wa(hlEl, 'anchor');
    let href = null;
    if (rId && this.rels[rId]) href = sanitizeUrl(this.rels[rId].target);
    else if (anchor) href = '#' + anchor;
    if (href) span.dataset.href = href;
    for (const c of hlEl.childNodes) { if (c.nodeType === 1 && c.localName === 'r') this._run(span, c, baseRPr); }
    container.appendChild(span);
  }

  _drawing(dwEl) {
    try {
      const blip = dwEl.getElementsByTagNameNS(A_NS, 'blip')[0]; if (!blip) return null;
      const rId = blip.getAttributeNS(R_NS, 'embed') || blip.getAttribute('r:embed');
      if (!rId || !this.rels[rId]) return null;
      const target = this.rels[rId].target.replace(/^\.\.\/word\//, '').replace(/^\//, '');
      // `this.parsed.media` is keyed as "media/<filename>" by docx-parser.js
      // (`m[p.replace('word/', '')]`), and relationship targets already use
      // that same shape, so a single direct lookup is sufficient here.
      const src = this.parsed.media[target];
      if (!src) return null;
      const img = document.createElement('img'); img.src = src; img.alt = '';
      img.style.maxWidth = '100%';
      const ext = dwEl.getElementsByTagNameNS(WP_NS, 'extent')[0];
      if (ext) {
        const cx = parseInt(ext.getAttribute('cx') || '0'), cy = parseInt(ext.getAttribute('cy') || '0');
        if (cx > 0) img.style.width = `${emuToPx(cx)}px`; if (cy > 0) img.style.height = `${emuToPx(cy)}px`;
      }
      return img;
    } catch (e) { return null; }
  }

  _pict(pictEl) {
    try {
      const idata = pictEl.getElementsByTagNameNS(V_NS, 'imagedata')[0]; if (!idata) return null;
      const rId = idata.getAttributeNS(R_NS, 'id') || idata.getAttribute('r:id');
      if (!rId || !this.rels[rId]) return null;
      const target = this.rels[rId].target.replace(/^\.\.\/word\//, '').replace(/^\//, '');
      const src = this.parsed.media[target]; if (!src) return null;
      const img = document.createElement('img'); img.src = src; img.alt = ''; img.style.maxWidth = '100%'; return img;
    } catch (e) { return null; }
  }

  // ── Table ──────────────────────────────────────────────────────────────────
  _table(tblEl) {
    const table = document.createElement('table'); table.className = 'doc-table';
    const tblPr = wfirst(tblEl, 'tblPr'); if (tblPr) this._applyTblPr(table, tblPr);
    const tblGrid = wfirst(tblEl, 'tblGrid');
    if (tblGrid) {
      const cg = document.createElement('colgroup');
      for (const gc of tblGrid.getElementsByTagNameNS(W, 'gridCol')) {
        const col = document.createElement('col'); const w = wa(gc, 'w');
        if (w) col.style.width = `${dxaToPx(parseInt(w))}px`; cg.appendChild(col);
      }
      table.appendChild(cg);
    }
    const tbody = document.createElement('tbody');
    for (const trEl of wdirect(tblEl, 'tr')) {
      const tr = document.createElement('tr');
      const trPr = wfirst(trEl, 'trPr');
      if (trPr) { const trH = wfirst(trPr, 'trHeight'); if (trH) { const v = wa(trH, 'val'); if (v) tr.style.height = `${dxaToPx(parseInt(v))}px`; } }
      let colIdx = 0;
      for (const tcEl of wdirect(trEl, 'tc')) {
        const tcPr = wfirst(tcEl, 'tcPr');
        const vMergeEl = tcPr ? wfirst(tcPr, 'vMerge') : null;
        const vMergeVal = vMergeEl ? wa(vMergeEl, 'val') : null;
        const isCont = vMergeEl && vMergeVal !== 'restart';
        if (isCont) { const gs = tcPr ? wfirst(tcPr, 'gridSpan') : null; colIdx += gs ? parseInt(wa(gs, 'val') || '1') : 1; continue; }
        const gsEl = tcPr ? wfirst(tcPr, 'gridSpan') : null;
        const colspan = gsEl ? parseInt(wa(gsEl, 'val') || '1') : 1;
        const td = document.createElement('td');
        if (colspan > 1) td.setAttribute('colspan', colspan);
        if (vMergeEl && vMergeVal === 'restart') {
          let rs = 1, nx = trEl.nextElementSibling;
          while (nx) {
            let ci = 0, found = false;
            for (const ntc of wdirect(nx, 'tc')) {
              if (ci === colIdx) {
                const nPr = wfirst(ntc, 'tcPr'), nvm = nPr ? wfirst(nPr, 'vMerge') : null;
                if (nvm && wa(nvm, 'val') !== 'restart') { rs++; found = true; } break;
              }
              const ngs = wfirst(wfirst(ntc, 'tcPr') || ntc, 'gridSpan');
              ci += ngs ? parseInt(wa(ngs, 'val') || '1') : 1;
            }
            if (!found) break; nx = nx.nextElementSibling;
          }
          if (rs > 1) td.setAttribute('rowspan', rs);
        }
        if (tcPr) this._applyTcPr(td, tcPr);
        for (const cc of Array.from(tcEl.childNodes)) {
          if (cc.nodeType !== 1) continue;
          if (cc.localName === 'p') { try { const { nodes } = this._para(cc); for (const n of nodes) td.appendChild(n); } catch (e) { } }
          else if (cc.localName === 'tbl') try { td.appendChild(this._table(cc)); } catch (e) { }
          else if (cc.localName === 'sdt') {
            const sc = wfirst(cc, 'sdtContent');
            if (sc) for (const c of sc.childNodes) {
              if (c.nodeType === 1 && c.localName === 'p') { try { const { nodes } = this._para(c); for (const n of nodes) td.appendChild(n); } catch (e) { } }
            }
          }
        }
        tr.appendChild(td); colIdx += colspan;
      }
      tbody.appendChild(tr);
    }
    table.appendChild(tbody); return table;
  }

  // ── Style application ──────────────────────────────────────────────────────
  _applyPPr(el, pp, skipIndent) {
    const jcMap = { center: 'center', right: 'right', both: 'justify', distribute: 'justify', left: 'left' };
    if (pp.jc && jcMap[pp.jc]) el.style.textAlign = jcMap[pp.jc];
    if (!skipIndent) {
      if (pp.indLeft) el.style.marginLeft = `${dxaToPx(pp.indLeft)}px`;
      if (pp.indRight) el.style.marginRight = `${dxaToPx(pp.indRight)}px`;
      if (pp.indHanging) { el.style.paddingLeft = `${dxaToPx(pp.indHanging)}px`; el.style.textIndent = `-${dxaToPx(pp.indHanging)}px`; }
      else if (pp.indFirstLine) el.style.textIndent = `${dxaToPx(pp.indFirstLine)}px`;
    }
    if (pp.spaceBefore !== undefined) el.style.marginTop = `${twipToPt(pp.spaceBefore)}pt`;
    if (pp.spaceAfter !== undefined) el.style.marginBottom = `${twipToPt(pp.spaceAfter)}pt`;
    if (pp.spaceLine !== undefined) {
      if (pp.spaceLineRule === 'exact' || pp.spaceLineRule === 'atLeast') el.style.lineHeight = `${twipToPt(pp.spaceLine)}pt`;
      else el.style.lineHeight = `${pp.spaceLine / 240}`;
    }
    if (pp.bgColor) el.style.backgroundColor = pp.bgColor;
    if (pp.borders) for (const [s, b] of Object.entries(pp.borders)) {
      el.style[`border${s[0].toUpperCase() + s.slice(1)}`] = `${b.width}px ${b.style} ${b.color}`;
      if (s === 'left' || s === 'right') el.style[`padding${s[0].toUpperCase() + s.slice(1)}`] = '4px';
    }
  }

  _applyRPr(el, rp) {
    if (!rp) return;
    const decs = [];
    if (rp.underline) decs.push('underline');
    if (rp.strike || rp.dstrike) decs.push('line-through');
    if (decs.length) el.style.textDecoration = decs.join(' ');
    if (rp.bold) el.style.fontWeight = 'bold';
    if (rp.italic) el.style.fontStyle = 'italic';
    if (rp.color) el.style.color = rp.color;
    if (rp.fontSize) el.style.fontSize = `${rp.fontSize}pt`;
    if (rp.fontFamily) el.style.fontFamily = `"${rp.fontFamily}",sans-serif`;
    if (rp.highlight) {
      const hl = {
        yellow: '#FFFF00', green: '#00FF00', cyan: '#00FFFF', magenta: '#FF00FF', blue: '#0000FF',
        red: '#FF0000', darkBlue: '#000080', darkCyan: '#008080', darkGreen: '#008000',
        darkMagenta: '#800080', darkRed: '#800000', darkYellow: '#808000',
        darkGray: '#808080', lightGray: '#C0C0C0', black: '#000000', white: '#FFFFFF'
      };
      const c = hl[rp.highlight]; if (c) el.style.backgroundColor = c;
    }
    if (rp.vertAlign === 'superscript') { el.style.verticalAlign = 'super'; el.style.fontSize = '0.75em'; }
    else if (rp.vertAlign === 'subscript') { el.style.verticalAlign = 'sub'; el.style.fontSize = '0.75em'; }
    if (rp.caps) el.style.textTransform = 'uppercase';
    if (rp.smallCaps) el.style.fontVariant = 'small-caps';
    if (rp.hidden) { el.style.backgroundColor = '#ffffc0'; el.title = 'Hidden text'; }
  }

  _applyTblPr(table, tblPr) {
    table.style.borderCollapse = 'collapse';
    const tblW = wfirst(tblPr, 'tblW');
    if (tblW) {
      const w = wa(tblW, 'w'), t = wa(tblW, 'type');
      if (t === 'pct' && w) table.style.width = `${parseInt(w) / 5000 * 100}%`;
      else if (t === 'dxa' && w) table.style.width = `${dxaToPx(parseInt(w))}px`;
      else if (t === 'auto') table.style.width = 'auto';
    }
    const jc = wfirst(tblPr, 'jc'); if (jc) {
      const v = wa(jc, 'val');
      if (v === 'center') { table.style.marginLeft = 'auto'; table.style.marginRight = 'auto'; }
      else if (v === 'right') table.style.marginLeft = 'auto';
    }
    const shd = wfirst(tblPr, 'shd'); if (shd) { const f = wa(shd, 'fill'); if (f && f !== 'auto') table.style.backgroundColor = '#' + f; }
  }

  _applyTcPr(td, tcPr) {
    const va = wfirst(tcPr, 'vAlign'); if (va) { const v = wa(va, 'val'); td.style.verticalAlign = v === 'center' ? 'middle' : v === 'bottom' ? 'bottom' : 'top'; }
    const shd = wfirst(tcPr, 'shd'); if (shd) { const f = wa(shd, 'fill'); if (f && f !== 'auto') td.style.backgroundColor = '#' + f; }
    const tcBd = wfirst(tcPr, 'tcBorders');
    if (tcBd) for (const s of ['top', 'bottom', 'left', 'right']) {
      const b = wfirst(tcBd, s); if (b) {
        const v = wa(b, 'val'), sz = wa(b, 'sz'), c = wa(b, 'color');
        if (v && v !== 'none') {
          const w2 = sz ? `${parseInt(sz) / 8}px` : '1px', col = c && c !== 'auto' ? '#' + c : '#ccc';
          td.style[`border${s[0].toUpperCase() + s.slice(1)}`] = `${w2} solid ${col}`;
        }
      }
    }
    const tcW = wfirst(tcPr, 'tcW'); if (tcW) { const w = wa(tcW, 'w'), t = wa(tcW, 'type'); if (t === 'dxa' && w) td.style.width = `${dxaToPx(parseInt(w))}px`; }
    const tcMar = wfirst(tcPr, 'tcMar');
    if (tcMar) for (const s of ['top', 'bottom', 'left', 'right']) {
      const m = wfirst(tcMar, s); if (m) { const w = wa(m, 'w'); if (w) td.style[`padding${s[0].toUpperCase() + s.slice(1)}`] = `${dxaToPx(parseInt(w))}px`; }
    }
  }
}
