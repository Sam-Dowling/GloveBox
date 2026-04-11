'use strict';
// ════════════════════════════════════════════════════════════════════════════
// pdf-renderer.js — Renders PDF files using pdf.js, with security analysis
// Requires pdfjsLib (pdf.js) and pdfjsWorker (pdf.worker.js) globals.
// ════════════════════════════════════════════════════════════════════════════
class PdfRenderer {

  /** Render every page of the PDF onto canvases, return a wrapper element. */
  async render(buffer) {
    const data = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer).slice();
    const pdf = await pdfjsLib.getDocument({ data, disableAutoFetch: true, disableStream: true }).promise;
    const wrap = document.createElement('div');
    wrap.className = 'pdf-view';

    const scale = 1.5;
    for (let i = 1; i <= pdf.numPages; i++) {
      const page = await pdf.getPage(i);
      const vp = page.getViewport({ scale });

      const pageDiv = document.createElement('div');
      pageDiv.className = 'page';
      pageDiv.style.width = Math.ceil(vp.width) + 'px';
      pageDiv.style.height = Math.ceil(vp.height) + 'px';
      pageDiv.style.position = 'relative';

      const canvas = document.createElement('canvas');
      canvas.width = Math.ceil(vp.width);
      canvas.height = Math.ceil(vp.height);
      canvas.style.display = 'block';

      await page.render({ canvasContext: canvas.getContext('2d'), viewport: vp }).promise;
      pageDiv.appendChild(canvas);

      // Hidden text layer so docEl.textContent exposes page text for IOC extraction
      try {
        const tc = await page.getTextContent();
        const spans = tc.items.map(it => it.str).join(' ');
        if (spans.trim()) {
          const tl = document.createElement('div');
          tl.className = 'pdf-text-layer';
          tl.style.cssText = 'position:absolute;left:-9999px;top:0;width:0;height:0;overflow:hidden;';
          tl.textContent = spans;
          pageDiv.appendChild(tl);
        }
      } catch (_) { /* text extraction failed — non-fatal */ }

      wrap.appendChild(pageDiv);
    }
    // Store page count for caller
    wrap.dataset.pageCount = pdf.numPages;
    return wrap;
  }

  /** Analyse PDF buffer for security-relevant artefacts. */
  async analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {}
    };

    // ── Raw byte scanning for suspicious operators ────────────────────────
    const raw = this._decodeRaw(buffer);
    const dangerousOps = [
      { pat: /\/JavaScript\b/gi,    label: '/JavaScript action',       sev: 'high' },
      { pat: /\/JS\s/g,             label: '/JS action (short form)',  sev: 'high' },
      { pat: /\/OpenAction\b/gi,    label: '/OpenAction (auto-run)',   sev: 'high' },
      { pat: /\/AA\b/g,             label: '/AA (additional actions)', sev: 'high' },
      { pat: /\/Launch\b/gi,        label: '/Launch action',           sev: 'high' },
      { pat: /\/SubmitForm\b/gi,    label: '/SubmitForm action',       sev: 'medium' },
      { pat: /\/EmbeddedFile\b/gi,  label: '/EmbeddedFile',            sev: 'medium' },
      { pat: /\/RichMedia\b/gi,     label: '/RichMedia (Flash/multimedia)', sev: 'medium' },
      { pat: /\/XFA\b/gi,           label: '/XFA (XML Forms)',         sev: 'medium' },
      { pat: /\/ObjStm\b/gi,        label: '/ObjStm (object stream — may hide content)', sev: 'info' },
      { pat: /\/AcroForm\b/gi,      label: '/AcroForm (interactive form)', sev: 'info' },
    ];

    for (const { pat, label, sev } of dangerousOps) {
      const matches = raw.match(pat);
      if (matches) {
        f.externalRefs.push({ type: 'PDF Structure', url: `${label} — ${matches.length} occurrence(s)`, severity: sev });
        if (sev === 'high') f.risk = 'high';
        else if (sev === 'medium' && f.risk !== 'high') f.risk = 'medium';
      }
    }

    // ── Extract URIs from raw stream ──────────────────────────────────────
    for (const m of raw.matchAll(/\/URI\s*\(([^)]{4,})\)/g)) {
      f.externalRefs.push({ type: 'URI (PDF)', url: m[1], severity: 'medium' });
      if (f.risk === 'low') f.risk = 'medium';
    }
    for (const m of raw.matchAll(/\/URI\s*<([0-9A-Fa-f]+)>/g)) {
      try {
        const decoded = m[1].match(/.{2}/g).map(h => String.fromCharCode(parseInt(h, 16))).join('');
        f.externalRefs.push({ type: 'URI (PDF hex)', url: decoded, severity: 'medium' });
        if (f.risk === 'low') f.risk = 'medium';
      } catch (_) { /* skip malformed */ }
    }

    // ── pdf.js metadata ───────────────────────────────────────────────────
    try {
      const data = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer).slice();
      const pdf = await pdfjsLib.getDocument({ data, disableAutoFetch: true, disableStream: true }).promise;
      const meta = await pdf.getMetadata();
      if (meta && meta.info) {
        const i = meta.info;
        f.metadata = {};
        if (i.Title)        f.metadata.title = i.Title;
        if (i.Author)       f.metadata.author = i.Author;
        if (i.Creator)      f.metadata.creator = i.Creator;
        if (i.Producer)     f.metadata.producer = i.Producer;
        if (i.CreationDate) f.metadata.created = i.CreationDate;
        if (i.ModDate)      f.metadata.modified = i.ModDate;
      }
      f.metadata.pages = pdf.numPages;

      // Extract URLs from link annotations on every page
      const seenUrls = new Set(f.externalRefs.map(r => r.url));
      for (let p = 1; p <= pdf.numPages; p++) {
        try {
          const page = await pdf.getPage(p);
          const annots = await page.getAnnotations();
          for (const a of annots) {
            if (a.url && !seenUrls.has(a.url)) {
              seenUrls.add(a.url);
              f.externalRefs.push({ type: 'URI (PDF annotation)', url: a.url, severity: 'medium' });
              if (f.risk === 'low') f.risk = 'medium';
            }
            if (a.unsafeUrl && !seenUrls.has(a.unsafeUrl)) {
              seenUrls.add(a.unsafeUrl);
              f.externalRefs.push({ type: 'URI (PDF annotation)', url: a.unsafeUrl, severity: 'medium' });
              if (f.risk === 'low') f.risk = 'medium';
            }
          }
        } catch (_) { /* skip page */ }
      }

      pdf.destroy();
    } catch (_) { /* metadata extraction failed — non-fatal */ }

    return f;
  }

  /** Decode buffer to a string for regex scanning (latin-1 for raw bytes). */
  _decodeRaw(buffer) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    // Scan in 512 KB chunks to avoid call-stack limits with String.fromCharCode
    const chunks = [];
    const CHUNK = 512 * 1024;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      chunks.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK)));
    }
    return chunks.join('');
  }
}
