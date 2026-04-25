'use strict';
// ════════════════════════════════════════════════════════════════════════════
// doc-renderer.js — Text extraction from .doc (Word 97-2003) binary files
// Depends on: ole-cfb-parser.js
// ════════════════════════════════════════════════════════════════════════════
class DocBinaryRenderer {
  render(buffer) {
    const wrap = document.createElement('div'); wrap.className = 'doc-text-view';
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    const bannerStrong = document.createElement('strong'); bannerStrong.textContent = 'Text Extraction Mode';
    banner.appendChild(bannerStrong);
    banner.appendChild(document.createTextNode(' — .doc (Word 97-2003) binary: content shown as plain text only; formatting, images and tables are not rendered.'));
    wrap.appendChild(banner);
    let paras = [];
    try {
      const cfb = new OleCfbParser(buffer).parse();
      paras = this._extract(cfb);
    } catch (e) {
      const b = document.createElement('div'); b.className = 'error-box';
      const h = document.createElement('h3'); h.textContent = 'Failed to parse .doc'; b.appendChild(h);
      const p = document.createElement('p'); p.textContent = e.message; b.appendChild(p);
      wrap.appendChild(b); return wrap;
    }
    const page = document.createElement('div');
    page.className = 'page';
    page.style.cssText = 'width:816px;min-height:1056px;padding:96px;margin:0 auto;';
    for (const text of paras) {
      const p = document.createElement('p'); p.className = 'para';
      p.style.marginBottom = '5px'; p.textContent = text || '\u00A0'; page.appendChild(p);
    }
    if (!paras.length) {
      const p = document.createElement('p'); p.style.cssText = 'color:#888;font-style:italic;';
      p.textContent = 'No text could be extracted.'; page.appendChild(p);
    }
    wrap.appendChild(page); return wrap;
  }

  _extract(cfb) {
    const wd = cfb.streams.get('worddocument');
    if (!wd) throw new Error('No WordDocument stream — not a valid .doc file');
    const dv = new DataView(wd.buffer, wd.byteOffset, wd.byteLength);
    const ccpText = wd.length > 72 ? dv.getUint32(68, true) : 0;
    const whtbl = wd.length > 11 ? (wd[11] >> 1) & 1 : 1;
    const fcClx = wd.length > 0x01AA ? dv.getUint32(0x01A2, true) : 0;
    const lcbClx = wd.length > 0x01AE ? dv.getUint32(0x01A6, true) : 0;
    const tbl = cfb.streams.get(whtbl ? '1table' : '0table') || cfb.streams.get('1table') || cfb.streams.get('0table');
    let text = '';
    if (tbl && fcClx > 0 && lcbClx > 0 && fcClx + lcbClx <= tbl.length) text = this._pieceTable(wd, tbl, fcClx, lcbClx) || '';
    if (!text && ccpText > 0) text = this._direct(wd, dv, ccpText);
    if (!text) text = this._scan(wd, dv);
    return text.split(/[\r\x07]/)
      .map(s => s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').replace(/\x13[^\x15]*\x15/g, '').trim())
      .filter((s, i) => s.length > 0 || i > 0);
  }

  _pieceTable(wd, tbl, fcClx, lcbClx) {
    let pos = fcClx;
    const tdv = new DataView(tbl.buffer, tbl.byteOffset, tbl.byteLength);
    while (pos < fcClx + lcbClx) {
      if (tbl[pos] === 0x02) break;
      if (tbl[pos] === 0x01) { const cb = tdv.getUint16(pos + 1, true); pos += 3 + cb; } else break;
    }
    if (pos >= fcClx + lcbClx || tbl[pos] !== 0x02) return '';
    pos++; const lcb = tdv.getUint32(pos, true); pos += 4;
    if (lcb < 4) return '';
    const n = Math.floor((lcb - 4) / 12); if (n <= 0) return '';
    const pcdBase = pos + (n + 1) * 4; let text = '';
    const wdv = new DataView(wd.buffer, wd.byteOffset, wd.byteLength);
    for (let i = 0; i < n; i++) {
      const cpEnd = tdv.getUint32(pos + (i + 1) * 4, true), pOff = pcdBase + i * 8;
      if (pOff + 8 > tbl.length) break;
      const cpStart = tdv.getUint32(pos + i * 4, true), count = cpEnd - cpStart;
      if (count <= 0 || count > 500000) continue;
      const fcRaw = tdv.getUint32(pOff + 2, true);
      const isAnsi = (fcRaw & 0x40000000) !== 0, fc = fcRaw & ~0x40000000;
      if (isAnsi) { for (let j = 0; j < count && fc + j < wd.length; j++) text += String.fromCharCode(wd[fc + j]); }
      else { for (let j = 0; j < count && fc + j * 2 + 1 < wd.length; j++) { const cp = wdv.getUint16(fc + j * 2, true); text += cp ? String.fromCharCode(cp) : ''; } }
    }
    return text;
  }

  _direct(wd, dv, ccpText) {
    const fibEnd = 892; if (wd.length <= fibEnd) return '';
    let uniScore = 0;
    for (let i = fibEnd; i < Math.min(fibEnd + 400, wd.length - 1); i += 2) if (wd[i] >= 32 && wd[i] < 127 && wd[i + 1] === 0) uniScore++;
    const count = Math.min(ccpText, Math.floor((wd.length - fibEnd) / (uniScore > 20 ? 2 : 1)));
    if (uniScore > 20) { let s = ''; for (let i = 0; i < count && fibEnd + i * 2 + 1 < wd.length; i++) s += String.fromCharCode(dv.getUint16(fibEnd + i * 2, true) || 32); return s; }
    let s = ''; for (let i = 0; i < count && fibEnd + i < wd.length; i++) s += String.fromCharCode(wd[fibEnd + i]); return s;
  }

  _scan(wd, dv) {
    const blocks = []; let cur = '';
    for (let i = 0; i < wd.length - 1; i += 2) {
      const cp = dv.getUint16(i, true);
      if (cp >= 32 && cp < 0xD800) { if (cp === 0x0D) { if (cur.trim()) blocks.push(cur); cur = ''; } else cur += String.fromCharCode(cp); }
      else if (cur.length > 2) { blocks.push(cur); cur = ''; }
    }
    if (cur.trim()) blocks.push(cur); return blocks.join('\r');
  }

  analyzeForSecurity(buffer) {
    const f = { risk: 'low', hasMacros: false, macroSize: 0, macroHash: '', autoExec: [], modules: [], externalRefs: [], metadata: {} };
    try {
      const cfb = new OleCfbParser(buffer).parse();
      // Collect the largest VBA/macro stream as rawBin for download fallback.
      let vbaStream = null;
      for (const [name, data] of cfb.streams.entries()) {
        if (name === 'vba/vba' || name.includes('vba') || name.includes('macro')) {
          f.hasMacros = true; escalateRisk(f, 'medium');
          if (!vbaStream || data.length > vbaStream.length) vbaStream = data;
        }
      }
      if (vbaStream) { f.macroSize = vbaStream.length; f.rawBin = vbaStream; }
      const si = cfb.streams.get('\x05summaryinformation');
      if (si) f.metadata = this._si(si);
    } catch (e) { }
    return f;
  }

  _si(data) {
    const meta = {}; try {
      const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
      const off0 = dv.getUint32(28, true); if (off0 + 8 > data.length) return meta;
      const count = dv.getUint32(off0 + 4, true);
      for (let i = 0; i < count && off0 + 8 + i * 8 + 8 <= data.length; i++) {
        const id = dv.getUint32(off0 + 8 + i * 8, true), ofs = dv.getUint32(off0 + 8 + i * 8 + 4, true) + off0;
        if (ofs + 8 > data.length) continue;
        const vt = dv.getUint32(ofs, true); if (vt !== 0x1E) continue;
        const len = dv.getUint32(ofs + 4, true); if (len <= 0 || ofs + 8 + len > data.length) continue;
        let s = ''; for (let j = 0; j < len - 1; j++) s += String.fromCharCode(data[ofs + 8 + j]);
        if (id === 2) meta.title = s.trim(); else if (id === 3) meta.subject = s.trim(); else if (id === 4) meta.creator = s.trim();
      }
    } catch (e) { } return meta;
  }
}
