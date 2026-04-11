'use strict';
// ════════════════════════════════════════════════════════════════════════════
// docx-parser.js — Parses .docx / .docm ZIP packages into a structured object
// Depends on: constants.js, vba-utils.js, JSZip (vendor)
// ════════════════════════════════════════════════════════════════════════════
class DocxParser {
  async parse(buffer) {
    const zip = await JSZip.loadAsync(buffer);
    const [document, styles, numbering, rels, metadata] = await Promise.all([
      this._xml(zip, 'word/document.xml'),
      this._xml(zip, 'word/styles.xml'),
      this._xml(zip, 'word/numbering.xml'),
      this._xml(zip, 'word/_rels/document.xml.rels'),
      this._xml(zip, 'docProps/core.xml'),
    ]);
    const headers = await this._parseHeaders(zip);
    const footers = await this._parseFooters(zip);
    const media   = await this._extractMedia(zip);
    const macros  = await this._extractMacros(zip);
    return {document, styles, numbering, rels, metadata, headers, footers, media, macros};
  }

  async _xml(zip, path) {
    try {
      const f = zip.file(path); if (!f) return null;
      const t = await f.async('string');
      const d = new DOMParser().parseFromString(t, 'text/xml');
      if (d.getElementsByTagName('parsererror').length) return null;
      return d;
    } catch(e) { return null; }
  }

  async _parseHeaders(zip) {
    const h = {};
    for (const p of Object.keys(zip.files))
      if (/^word\/header\d*\.xml$/.test(p))
        h[p.replace('word/','')] = await this._xml(zip, p);
    return h;
  }

  async _parseFooters(zip) {
    const f = {};
    for (const p of Object.keys(zip.files))
      if (/^word\/footer\d*\.xml$/.test(p))
        f[p.replace('word/','')] = await this._xml(zip, p);
    return f;
  }

  async _extractMedia(zip) {
    const mime = {png:'image/png',jpg:'image/jpeg',jpeg:'image/jpeg',gif:'image/gif',
                  bmp:'image/bmp',svg:'image/svg+xml',emf:'image/x-emf',wmf:'image/x-wmf',
                  tiff:'image/tiff',tif:'image/tiff',webp:'image/webp'};
    const m = {};
    for (const [p, f] of Object.entries(zip.files)) {
      if (p.startsWith('word/media/') && !f.dir) {
        try {
          const data = await f.async('base64');
          const ext  = p.split('.').pop().toLowerCase();
          m[p.replace('word/','')] = `data:${mime[ext]||'application/octet-stream'};base64,${data}`;
        } catch(e) {}
      }
    }
    return m;
  }

  async _extractMacros(zip) {
    const f = zip.file('word/vbaProject.bin');
    if (!f) return null;
    try {
      const data = await f.async('uint8array');
      // rawBin preserved so _downloadMacros can offer binary download when text decoding fails.
      return {present:true, size:data.length, sha256:await this._sha256(data), modules:parseVBAText(data), rawBin:data};
    } catch(e) { return {present:true, size:0, sha256:null, modules:[], error:e.message}; }
  }

  async _sha256(data) {
    try {
      const buf = await crypto.subtle.digest('SHA-256', data);
      return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
    } catch(e) { return null; }
  }
}
