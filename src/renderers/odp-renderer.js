'use strict';
// ════════════════════════════════════════════════════════════════════════════
// odp-renderer.js — OpenDocument Presentation (.odp) slide renderer
// Depends on: constants.js (IOC, escHtml), JSZip (vendor)
// ════════════════════════════════════════════════════════════════════════════
class OdpRenderer {

  constructor() {
    this.TEXT = 'urn:oasis:names:tc:opendocument:xmlns:text:1.0';
    this.DRAW = 'urn:oasis:names:tc:opendocument:xmlns:drawing:1.0';
    this.PRES = 'urn:oasis:names:tc:opendocument:xmlns:presentation:1.0';
    this.STYLE = 'urn:oasis:names:tc:opendocument:xmlns:style:1.0';
    this.FO = 'urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0';
    this.SVG = 'urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0';
    this.XLINK = 'http://www.w3.org/1999/xlink';
    this.OFFICE = 'urn:oasis:names:tc:opendocument:xmlns:office:1.0';
    this.META = 'urn:oasis:names:tc:opendocument:xmlns:meta:1.0';
    this.DC = 'http://purl.org/dc/elements/1.1/';
    this.TABLE = 'urn:oasis:names:tc:opendocument:xmlns:table:1.0';
  }

  async render(buffer) {
    const wrap = document.createElement('div'); wrap.className = 'pptx-view';
    let zip;
    try { zip = await JSZip.loadAsync(buffer); }
    catch (e) { return this._err(wrap, 'Failed to parse ODP file', e.message); }

    const contentXml = await this._xml(zip, 'content.xml');
    if (!contentXml) return this._err(wrap, 'Could not parse content.xml', 'File may be corrupted or not a valid ODP.');

    // Load images
    const media = await this._loadMedia(zip);

    // Find slide pages
    const body = contentXml.getElementsByTagNameNS(this.OFFICE, 'body')[0];
    const pres = body ? body.getElementsByTagNameNS(this.OFFICE, 'presentation')[0] : null;
    if (!pres) { wrap.textContent = 'No presentation content found.'; return wrap; }

    const pages = Array.from(pres.getElementsByTagNameNS(this.DRAW, 'page'));

    if (pages.length) {
      const lbl = document.createElement('div'); lbl.className = 'pptx-slide-counter';
      lbl.textContent = `${pages.length} slide${pages.length !== 1 ? 's' : ''}`;
      wrap.appendChild(lbl);
    }

    // Determine slide dimensions from page layout if available
    const { pxW, pxH, scale } = this._getSlideSize(contentXml);

    for (let i = 0; i < pages.length; i++) {
      wrap.appendChild(this._renderSlide(pages[i], i + 1, pages.length, pxW, pxH, scale, media));
    }

    if (!pages.length) {
      const p = document.createElement('p'); p.style.cssText = 'color:#888;padding:20px;text-align:center';
      p.textContent = 'No slides found.'; wrap.appendChild(p);
    }

    return wrap;
  }

  async analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    try {
      const zip = await JSZip.loadAsync(buffer);

      // Check for macros
      const macroEntries = [];
      zip.forEach((path) => { if (path.startsWith('Basic/') && !path.endsWith('/')) macroEntries.push(path); });
      if (macroEntries.length) {
        f.hasMacros = true; f.risk = 'medium';
        for (const path of macroEntries) {
          try {
            const src = await zip.file(path).async('string');
            f.modules.push({ name: path.replace('Basic/', ''), source: src });
            f.macroSize += src.length;
            const pats = autoExecPatterns(src);
            if (pats.length) { f.autoExec.push({ module: path, patterns: pats }); f.risk = 'high'; }
          } catch (e) { }
        }
      }

      // Metadata
      const metaXml = await this._xml(zip, 'meta.xml');
      if (metaXml) {
        const g = (ns, n) => {
          const el = metaXml.getElementsByTagNameNS(ns, n)[0];
          return el ? el.textContent.trim() : '';
        };
        f.metadata = {
          title: g(this.DC, 'title'),
          subject: g(this.DC, 'subject'),
          creator: g(this.META, 'initial-creator') || g(this.DC, 'creator'),
          lastModifiedBy: g(this.DC, 'creator'),
          created: g(this.META, 'creation-date'),
          modified: g(this.DC, 'date'),
        };
      }

      // External references
      const contentXml = await this._xml(zip, 'content.xml');
      if (contentXml) {
        const links = contentXml.getElementsByTagNameNS(this.TEXT, 'a');
        for (const a of Array.from(links)) {
          const href = a.getAttributeNS(this.XLINK, 'href') || a.getAttribute('xlink:href');
          if (href && /^https?:\/\//i.test(href)) {
            f.externalRefs.push({ type: IOC.URL, url: href, severity: 'info', note: 'Hyperlink' });
          }
        }
      }

    } catch (e) { }
    return f;
  }

  // ── Slide sizing ──────────────────────────────────────────────────────────

  _getSlideSize(xml) {
    // Try to read page layout dimensions
    const layouts = xml.getElementsByTagNameNS(this.STYLE, 'page-layout-properties');
    let width = '25.4cm', height = '19.05cm'; // Default 10" x 7.5"
    for (const l of Array.from(layouts)) {
      const w = l.getAttributeNS(this.FO, 'page-width') || l.getAttribute('fo:page-width');
      const h = l.getAttributeNS(this.FO, 'page-height') || l.getAttribute('fo:page-height');
      if (w) width = w;
      if (h) height = h;
      break;
    }
    const wPx = this._unitToPx(width);
    const hPx = this._unitToPx(height);
    const pxW = 720;
    const scale = pxW / wPx;
    const pxH = Math.round(hPx * scale);
    return { pxW, pxH, scale };
  }

  _unitToPx(val) {
    if (!val) return 720;
    const num = parseFloat(val);
    if (val.endsWith('cm')) return num * 96 / 2.54;
    if (val.endsWith('mm')) return num * 96 / 25.4;
    if (val.endsWith('in')) return num * 96;
    if (val.endsWith('pt')) return num * 96 / 72;
    if (val.endsWith('px')) return num;
    return num * 96 / 2.54; // default assume cm
  }

  // ── Slide rendering ──────────────────────────────────────────────────────

  _renderSlide(pageNode, num, total, w, h, scale, media) {
    const slide = document.createElement('div'); slide.className = 'pptx-slide';
    slide.style.cssText = `width:${w}px;height:${h}px;position:relative;overflow:hidden;`;
    const bg = document.createElement('div'); bg.style.cssText = 'position:absolute;inset:0;background:white;';
    slide.appendChild(bg);

    // Process shapes
    for (const child of Array.from(pageNode.childNodes)) {
      if (child.nodeType !== 1) continue;
      this._renderShape(child, slide, scale, media);
    }

    const badge = document.createElement('div'); badge.className = 'pptx-slide-num';
    badge.textContent = `${num}/${total}`;
    slide.appendChild(badge);
    return slide;
  }

  _renderShape(node, parent, scale, media) {
    const ln = node.localName;
    if (ln === 'frame') {
      this._renderFrame(node, parent, scale, media);
    } else if (ln === 'custom-shape' || ln === 'rect' || ln === 'circle' || ln === 'ellipse') {
      this._renderCustomShape(node, parent, scale);
    } else if (ln === 'g') {
      // Group
      for (const child of Array.from(node.childNodes)) {
        if (child.nodeType === 1) this._renderShape(child, parent, scale, media);
      }
    } else if (ln === 'connector' || ln === 'line') {
      // Lines/connectors — skip for now
    }
  }

  _renderFrame(frameNode, parent, scale, media) {
    const pos = this._getPosition(frameNode, scale);
    if (!pos) return;

    // Check for image
    const images = frameNode.getElementsByTagNameNS(this.DRAW, 'image');
    if (images.length) {
      const imgNode = images[0];
      const href = imgNode.getAttributeNS(this.XLINK, 'href') || imgNode.getAttribute('xlink:href');
      if (href) {
        const src = media.get(href) || media.get(href.replace(/^\.\//, ''));
        if (src) {
          const img = document.createElement('img'); img.src = src; img.alt = '';
          img.style.cssText = `position:absolute;left:${pos.x}px;top:${pos.y}px;width:${pos.w}px;height:${pos.h}px;object-fit:contain;`;
          parent.appendChild(img);
          return;
        }
      }
    }

    // Check for text box
    const textBoxes = frameNode.getElementsByTagNameNS(this.DRAW, 'text-box');
    if (textBoxes.length) {
      const div = document.createElement('div');
      div.style.cssText = `position:absolute;left:${pos.x}px;top:${pos.y}px;width:${pos.w}px;height:${pos.h}px;overflow:hidden;box-sizing:border-box;`;
      this._renderTextContent(textBoxes[0], div, scale);
      parent.appendChild(div);
      return;
    }

    // Check for table
    const tables = frameNode.getElementsByTagNameNS(this.TABLE, 'table');
    if (tables.length) {
      const wrap = document.createElement('div');
      wrap.style.cssText = `position:absolute;left:${pos.x}px;top:${pos.y}px;width:${pos.w}px;height:${pos.h}px;overflow:auto;`;
      this._renderSlideTable(tables[0], wrap, scale);
      parent.appendChild(wrap);
    }
  }

  _renderCustomShape(node, parent, scale) {
    const pos = this._getPosition(node, scale);
    if (!pos) return;

    const div = document.createElement('div');
    div.style.cssText = `position:absolute;left:${pos.x}px;top:${pos.y}px;width:${pos.w}px;height:${pos.h}px;overflow:hidden;box-sizing:border-box;`;

    // Background fill
    const graphicProps = node.getElementsByTagNameNS(this.DRAW, 'fill-color');
    // Simple: check style for fill
    const styleName = node.getAttribute('draw:style-name') || '';

    // Render text content inside shape
    this._renderTextContent(node, div, scale);

    if (div.childNodes.length > 0) {
      parent.appendChild(div);
    }
  }

  _renderTextContent(node, container, scale) {
    const paras = node.getElementsByTagNameNS(this.TEXT, 'p');
    for (const p of Array.from(paras)) {
      // Only direct children paragraphs (avoid nested table paragraphs)
      if (p.parentNode !== node && p.parentNode.localName !== 'text-box' && p.parentNode !== node) {
        // Check ancestry
        let ancestor = p.parentNode;
        let isDirectChild = false;
        while (ancestor && ancestor !== node) {
          if (ancestor.localName === 'table') break;
          if (ancestor === node) { isDirectChild = true; break; }
          ancestor = ancestor.parentNode;
        }
        if (ancestor && ancestor.localName === 'table') continue;
      }

      const pd = document.createElement('p');
      pd.style.cssText = 'margin:0;padding:0 2px;line-height:1.2;';

      // Alignment
      const pPr = p.getAttribute('text:style-name') || '';

      let has = false;
      for (const child of Array.from(p.childNodes)) {
        if (child.nodeType === 3 && child.textContent.trim()) {
          const span = document.createElement('span');
          span.textContent = child.textContent;
          span.style.fontSize = Math.round(12 * scale * 1.6) + 'px';
          pd.appendChild(span); has = true;
        } else if (child.nodeType === 1) {
          if (child.localName === 'span') {
            const span = document.createElement('span');
            span.textContent = child.textContent;
            // Style
            const fontSize = Math.round(12 * scale * 1.6);
            span.style.fontSize = fontSize + 'px';
            pd.appendChild(span); has = true;
          } else if (child.localName === 'a') {
            const span = document.createElement('span');
            span.style.cssText = `color:#06c;text-decoration:underline;font-size:${Math.round(12 * scale * 1.6)}px`;
            span.textContent = child.textContent;
            pd.appendChild(span); has = true;
          } else if (child.localName === 'line-break') {
            pd.appendChild(document.createElement('br')); has = true;
          }
        }
      }
      container.appendChild(has ? pd : document.createElement('br'));
    }
  }

  _renderSlideTable(tableNode, container, scale) {
    const tbl = document.createElement('table');
    tbl.style.cssText = 'border-collapse:collapse;width:100%;font-size:' + Math.round(10 * scale * 1.6) + 'px;';
    for (const row of Array.from(tableNode.childNodes)) {
      if (row.nodeType !== 1 || row.localName !== 'table-row') continue;
      const tr = document.createElement('tr');
      for (const cell of Array.from(row.childNodes)) {
        if (cell.nodeType !== 1 || cell.localName !== 'table-cell') continue;
        const td = document.createElement('td');
        td.style.cssText = 'border:1px solid #ccc;padding:2px 4px;vertical-align:top;';
        const colspan = cell.getAttribute('table:number-columns-spanned');
        if (colspan && parseInt(colspan) > 1) td.colSpan = parseInt(colspan);
        this._renderTextContent(cell, td, scale * 0.8);
        tr.appendChild(td);
      }
      tbl.appendChild(tr);
    }
    container.appendChild(tbl);
  }

  // ── Position helpers ──────────────────────────────────────────────────────

  _getPosition(node, scale) {
    const x = node.getAttributeNS(this.SVG, 'x') || node.getAttribute('svg:x') || node.getAttribute('draw:x');
    const y = node.getAttributeNS(this.SVG, 'y') || node.getAttribute('svg:y') || node.getAttribute('draw:y');
    const w = node.getAttributeNS(this.SVG, 'width') || node.getAttribute('svg:width') || node.getAttribute('draw:width');
    const h = node.getAttributeNS(this.SVG, 'height') || node.getAttribute('svg:height') || node.getAttribute('draw:height');
    if (!w && !h) return null;
    return {
      x: this._unitToPx(x || '0') * scale,
      y: this._unitToPx(y || '0') * scale,
      w: this._unitToPx(w || '0') * scale,
      h: this._unitToPx(h || '0') * scale,
    };
  }

  // ── Media loading ──────────────────────────────────────────────────────────

  async _loadMedia(zip) {
    const map = new Map();
    const MIME = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', bmp: 'image/bmp', svg: 'image/svg+xml' };
    for (const [path, file] of Object.entries(zip.files)) {
      if (file.dir) continue;
      if (!path.startsWith('Pictures/') && !path.startsWith('media/')) continue;
      const ext = path.split('.').pop().toLowerCase();
      if (!MIME[ext]) continue;
      try {
        const b64 = await file.async('base64');
        map.set(path, `data:${MIME[ext]};base64,${b64}`);
      } catch (e) { }
    }
    return map;
  }

  async _xml(zip, path) {
    try {
      const f = zip.file(path); if (!f) return null;
      const text = await f.async('string');
      const d = new DOMParser().parseFromString(text, 'text/xml');
      return d.getElementsByTagName('parsererror').length ? null : d;
    } catch (e) { return null; }
  }

  _err(wrap, title, msg) {
    const b = document.createElement('div'); b.className = 'error-box';
    const h = document.createElement('h3'); h.textContent = title; b.appendChild(h);
    const p = document.createElement('p'); p.textContent = msg; b.appendChild(p);
    wrap.appendChild(b); return wrap;
  }
}
