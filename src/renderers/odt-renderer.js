'use strict';
// ════════════════════════════════════════════════════════════════════════════
// odt-renderer.js — OpenDocument Text (.odt) renderer
// Depends on: constants.js (IOC, escHtml, emuToPx), JSZip (vendor)
// ════════════════════════════════════════════════════════════════════════════
class OdtRenderer {

  constructor() {
    this.TEXT = 'urn:oasis:names:tc:opendocument:xmlns:text:1.0';
    this.DRAW = 'urn:oasis:names:tc:opendocument:xmlns:drawing:1.0';
    this.TABLE = 'urn:oasis:names:tc:opendocument:xmlns:table:1.0';
    this.FO = 'urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0';
    this.STYLE = 'urn:oasis:names:tc:opendocument:xmlns:style:1.0';
    this.SVG = 'urn:oasis:names:tc:opendocument:xmlns:svg-compatible:1.0';
    this.XLINK = 'http://www.w3.org/1999/xlink';
    this.OFFICE = 'urn:oasis:names:tc:opendocument:xmlns:office:1.0';
    this.META = 'urn:oasis:names:tc:opendocument:xmlns:meta:1.0';
    this.DC = 'http://purl.org/dc/elements/1.1/';
  }

  async render(buffer) {
    const wrap = document.createElement('div'); wrap.className = 'odt-view';
    let zip;
    try { zip = await JSZip.loadAsync(buffer); }
    catch (e) { return this._err(wrap, 'Failed to parse ODT file', e.message); }

    const contentXml = await this._xml(zip, 'content.xml');
    if (!contentXml) return this._err(wrap, 'Could not parse content.xml', 'File may be corrupted or not a valid ODT.');

    // Load images
    const media = await this._loadMedia(zip);

    // Load styles for reference
    const styles = this._parseStyles(contentXml);
    const stylesXml = await this._xml(zip, 'styles.xml');
    if (stylesXml) Object.assign(styles, this._parseStyles(stylesXml));

    // Page container
    const page = document.createElement('div'); page.className = 'page';
    page.style.cssText = 'max-width:800px;margin:20px auto;padding:40px 60px;background:white;color:#222;min-height:600px;box-shadow:0 2px 8px rgba(0,0,0,.15);font-family:serif;font-size:12pt;line-height:1.5;';

    // Render body content
    const body = contentXml.getElementsByTagNameNS(this.OFFICE, 'body')[0];
    const textBody = body ? body.getElementsByTagNameNS(this.OFFICE, 'text')[0] : null;
    if (textBody) {
      this._renderChildren(textBody, page, styles, media);
    } else {
      page.textContent = 'No text content found.';
    }

    wrap.appendChild(page);
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

      // Check for macros (Basic/ directory)
      const macroEntries = [];
      zip.forEach((path) => { if (path.startsWith('Basic/') && !path.endsWith('/')) macroEntries.push(path); });
      if (macroEntries.length) {
        f.hasMacros = true; escalateRisk(f, 'medium');
        for (const path of macroEntries) {
          try {
            const src = await zip.file(path).async('string');
            f.modules.push({ name: path.replace('Basic/', ''), source: src });
            f.macroSize += src.length;
            const pats = autoExecPatterns(src);
            if (pats.length) { f.autoExec.push({ module: path, patterns: pats }); escalateRisk(f, 'high'); }
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

      // External references from content
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

  // ── Content rendering ──────────────────────────────────────────────────────

  _renderChildren(parent, container, styles, media) {
    for (const node of Array.from(parent.childNodes)) {
      if (node.nodeType !== 1) continue;
      const ln = node.localName;

      if (ln === 'p' || ln === 'h') {
        this._renderParagraph(node, container, styles, media, ln === 'h');
      } else if (ln === 'list') {
        this._renderList(node, container, styles, media);
      } else if (ln === 'table') {
        this._renderTable(node, container, styles, media);
      } else if (ln === 'section') {
        this._renderChildren(node, container, styles, media);
      }
    }
  }

  _renderParagraph(pNode, container, styles, media, isHeading) {
    const styleName = pNode.getAttribute('text:style-name') || '';
    const outlineLevel = pNode.getAttribute('text:outline-level');
    let tag = 'p';
    if (isHeading && outlineLevel) {
      const level = Math.min(parseInt(outlineLevel) || 1, 6);
      tag = 'h' + level;
    }
    const el = document.createElement(tag);
    if (tag === 'p') el.style.cssText = 'margin:0 0 6px 0;';
    this._applyParaStyle(el, styleName, styles);

    let hasContent = false;
    for (const child of Array.from(pNode.childNodes)) {
      if (child.nodeType === 3) {
        if (child.textContent) { el.appendChild(document.createTextNode(child.textContent)); hasContent = true; }
      } else if (child.nodeType === 1) {
        const ln = child.localName;
        if (ln === 'span') {
          const span = document.createElement('span');
          this._applyTextStyle(span, child.getAttribute('text:style-name') || '', styles);
          span.textContent = child.textContent;
          el.appendChild(span); hasContent = true;
        } else if (ln === 'a') {
          const a = document.createElement('span');
          a.style.cssText = 'color:#06c;text-decoration:underline;';
          a.textContent = child.textContent;
          a.title = child.getAttributeNS(this.XLINK, 'href') || child.getAttribute('xlink:href') || '';
          el.appendChild(a); hasContent = true;
        } else if (ln === 'line-break') {
          el.appendChild(document.createElement('br')); hasContent = true;
        } else if (ln === 'tab') {
          const tab = document.createTextNode('\t');
          el.appendChild(tab); hasContent = true;
        } else if (ln === 's') {
          const count = parseInt(child.getAttribute('text:c') || '1');
          el.appendChild(document.createTextNode(' '.repeat(count))); hasContent = true;
        } else if (ln === 'frame') {
          const img = this._renderFrame(child, media);
          if (img) { el.appendChild(img); hasContent = true; }
        } else if (ln === 'soft-page-break') {
          // ignore
        } else {
          // Recurse for other inline content
          if (child.textContent) { el.appendChild(document.createTextNode(child.textContent)); hasContent = true; }
        }
      }
    }

    if (!hasContent) {
      el.appendChild(document.createElement('br')); // empty paragraph
    }
    container.appendChild(el);
  }

  _renderList(listNode, container, styles, media) {
    const styleName = listNode.getAttribute('text:style-name') || '';
    // Determine ordered vs unordered from style or default
    const isOrdered = styleName.toLowerCase().includes('number') || styleName.toLowerCase().includes('ordered');
    const ul = document.createElement(isOrdered ? 'ol' : 'ul');
    ul.style.cssText = 'margin:4px 0;padding-left:24px;';

    for (const item of Array.from(listNode.childNodes)) {
      if (item.nodeType !== 1 || item.localName !== 'list-item') continue;
      const li = document.createElement('li');
      li.style.cssText = 'margin:2px 0;';
      for (const child of Array.from(item.childNodes)) {
        if (child.nodeType !== 1) continue;
        if (child.localName === 'p' || child.localName === 'h') {
          // Render paragraph content inline in the LI
          const span = document.createElement('span');
          this._renderInlineContent(child, span, styles, media);
          li.appendChild(span);
        } else if (child.localName === 'list') {
          this._renderList(child, li, styles, media);
        }
      }
      ul.appendChild(li);
    }
    container.appendChild(ul);
  }

  _renderInlineContent(pNode, container, styles, media) {
    for (const child of Array.from(pNode.childNodes)) {
      if (child.nodeType === 3) {
        container.appendChild(document.createTextNode(child.textContent));
      } else if (child.nodeType === 1) {
        if (child.localName === 'span') {
          const span = document.createElement('span');
          this._applyTextStyle(span, child.getAttribute('text:style-name') || '', styles);
          span.textContent = child.textContent;
          container.appendChild(span);
        } else if (child.localName === 'a') {
          const span = document.createElement('span');
          span.style.cssText = 'color:#06c;text-decoration:underline;';
          span.textContent = child.textContent;
          container.appendChild(span);
        } else if (child.localName === 'line-break') {
          container.appendChild(document.createElement('br'));
        } else if (child.localName === 'tab') {
          container.appendChild(document.createTextNode('\t'));
        } else if (child.localName === 's') {
          const count = parseInt(child.getAttribute('text:c') || '1');
          container.appendChild(document.createTextNode(' '.repeat(count)));
        } else {
          container.appendChild(document.createTextNode(child.textContent));
        }
      }
    }
  }

  _renderTable(tableNode, container, styles, media) {
    const tbl = document.createElement('table');
    tbl.style.cssText = 'border-collapse:collapse;width:100%;margin:8px 0;';

    for (const child of Array.from(tableNode.childNodes)) {
      if (child.nodeType !== 1) continue;
      if (child.localName === 'table-row') {
        const tr = document.createElement('tr');
        for (const cell of Array.from(child.childNodes)) {
          if (cell.nodeType !== 1 || cell.localName !== 'table-cell') continue;
          const td = document.createElement('td');
          td.style.cssText = 'border:1px solid #ccc;padding:4px 8px;vertical-align:top;';
          const colspan = cell.getAttribute('table:number-columns-spanned');
          const rowspan = cell.getAttribute('table:number-rows-spanned');
          if (colspan && parseInt(colspan) > 1) td.colSpan = parseInt(colspan);
          if (rowspan && parseInt(rowspan) > 1) td.rowSpan = parseInt(rowspan);
          this._renderChildren(cell, td, styles, media);
          tr.appendChild(td);

          // Handle repeated cells
          const repeat = parseInt(cell.getAttribute('table:number-columns-repeated') || '1');
          for (let r = 1; r < repeat && r < 100; r++) {
            const td2 = td.cloneNode(true);
            tr.appendChild(td2);
          }
        }
        tbl.appendChild(tr);
      } else if (child.localName === 'table-header-rows') {
        for (const row of Array.from(child.childNodes)) {
          if (row.nodeType !== 1 || row.localName !== 'table-row') continue;
          const tr = document.createElement('tr');
          for (const cell of Array.from(row.childNodes)) {
            if (cell.nodeType !== 1 || cell.localName !== 'table-cell') continue;
            const th = document.createElement('th');
            th.style.cssText = 'border:1px solid #ccc;padding:4px 8px;font-weight:bold;background:#f0f0f0;';
            this._renderChildren(cell, th, styles, media);
            tr.appendChild(th);
          }
          tbl.appendChild(tr);
        }
      }
    }
    container.appendChild(tbl);
  }

  _renderFrame(frameNode, media) {
    // Look for draw:image inside the frame
    const images = frameNode.getElementsByTagNameNS(this.DRAW, 'image');
    if (!images.length) return null;

    const imgEl = images[0];
    const href = imgEl.getAttributeNS(this.XLINK, 'href') || imgEl.getAttribute('xlink:href');
    if (!href) return null;

    const src = media.get(href) || media.get(href.replace(/^\.\//, ''));
    if (!src) return null;

    const img = document.createElement('img');
    img.src = src;
    img.alt = frameNode.getAttribute('draw:name') || '';
    img.style.cssText = 'max-width:100%;height:auto;display:block;margin:4px 0;';

    // Apply dimensions if specified
    const width = frameNode.getAttributeNS(this.SVG, 'width') || frameNode.getAttribute('svg:width');
    const height = frameNode.getAttributeNS(this.SVG, 'height') || frameNode.getAttribute('svg:height');
    if (width) img.style.width = width;
    if (height) img.style.height = height;

    return img;
  }

  // ── Style parsing ──────────────────────────────────────────────────────────

  _parseStyles(xml) {
    const styles = {};
    const styleEls = xml.getElementsByTagNameNS(this.STYLE, 'style');
    for (const s of Array.from(styleEls)) {
      const name = s.getAttribute('style:name');
      if (!name) continue;
      const family = s.getAttribute('style:family') || '';
      const parentStyle = s.getAttribute('style:parent-style-name') || '';
      const props = {};

      // Text properties
      const tp = s.getElementsByTagNameNS(this.STYLE, 'text-properties')[0];
      if (tp) {
        const fs = tp.getAttributeNS(this.FO, 'font-size') || tp.getAttribute('fo:font-size');
        const fw = tp.getAttributeNS(this.FO, 'font-weight') || tp.getAttribute('fo:font-weight');
        const fst = tp.getAttributeNS(this.FO, 'font-style') || tp.getAttribute('fo:font-style');
        const col = tp.getAttributeNS(this.FO, 'color') || tp.getAttribute('fo:color');
        const td = tp.getAttribute('style:text-underline-style');
        if (fs) props.fontSize = fs;
        if (fw) props.fontWeight = fw;
        if (fst) props.fontStyle = fst;
        if (col) props.color = col;
        if (td && td !== 'none') props.textDecoration = 'underline';
      }

      // Paragraph properties
      const pp = s.getElementsByTagNameNS(this.STYLE, 'paragraph-properties')[0];
      if (pp) {
        const ta = pp.getAttributeNS(this.FO, 'text-align') || pp.getAttribute('fo:text-align');
        const mb = pp.getAttributeNS(this.FO, 'margin-bottom') || pp.getAttribute('fo:margin-bottom');
        const mt = pp.getAttributeNS(this.FO, 'margin-top') || pp.getAttribute('fo:margin-top');
        const ml = pp.getAttributeNS(this.FO, 'margin-left') || pp.getAttribute('fo:margin-left');
        if (ta) props.textAlign = ta === 'start' ? 'left' : ta === 'end' ? 'right' : ta;
        if (mb) props.marginBottom = mb;
        if (mt) props.marginTop = mt;
        if (ml) props.marginLeft = ml;
      }

      styles[name] = { family, parent: parentStyle, props };
    }
    return styles;
  }

  _applyParaStyle(el, styleName, styles, depth = 0) {
    if (depth > 20) return; // Prevent infinite recursion on circular style references
    const s = styles[styleName];
    if (!s) return;
    const p = s.props;
    if (p.textAlign) el.style.textAlign = p.textAlign;
    if (p.marginBottom) el.style.marginBottom = p.marginBottom;
    if (p.marginTop) el.style.marginTop = p.marginTop;
    if (p.marginLeft) el.style.marginLeft = p.marginLeft;
    if (p.fontSize) el.style.fontSize = p.fontSize;
    if (p.fontWeight) el.style.fontWeight = p.fontWeight;
    if (p.fontStyle) el.style.fontStyle = p.fontStyle;
    if (p.color) el.style.color = p.color;
    // Inherit from parent (with depth limit)
    if (s.parent && styles[s.parent]) this._applyParaStyle(el, s.parent, styles, depth + 1);
  }

  _applyTextStyle(el, styleName, styles, depth = 0) {
    if (depth > 20) return; // Prevent infinite recursion on circular style references
    const s = styles[styleName];
    if (!s) return;
    const p = s.props;
    if (p.fontSize) el.style.fontSize = p.fontSize;
    if (p.fontWeight) el.style.fontWeight = p.fontWeight;
    if (p.fontStyle) el.style.fontStyle = p.fontStyle;
    if (p.color) el.style.color = p.color;
    if (p.textDecoration) el.style.textDecoration = p.textDecoration;
    if (s.parent && styles[s.parent]) this._applyTextStyle(el, s.parent, styles, depth + 1);
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
