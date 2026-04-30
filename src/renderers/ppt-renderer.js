'use strict';
// ════════════════════════════════════════════════════════════════════════════
// ppt-renderer.js — Legacy PowerPoint (.ppt) text extraction via OLE/CFB
// Depends on: ole-cfb-parser.js, vba-utils.js, constants.js (IOC)
// ════════════════════════════════════════════════════════════════════════════
class PptBinaryRenderer {

  // Record types for text extraction
  static RT_TextCharsAtom = 0x0FA0; // UTF-16 LE text
  static RT_TextBytesAtom = 0x0FA8; // ASCII/Latin-1 text
  static RT_SlideListWithText = 0x0FF0;
  static RT_SlidePersistAtom = 0x03F3;
  static RT_HeadersFootersContainer = 0x0FD9;
  static RT_CString = 0x0FBA;
  static RT_Document = 0x03E8;
  static RT_Slide = 0x03EE;
  static RT_MainMaster = 0x03F8;

  render(buffer) {
    const wrap = document.createElement('div'); wrap.className = 'doc-text-view';
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>Text Extraction Mode</strong> — .ppt (PowerPoint 97-2003) binary: ' +
      'content shown as plain text only; formatting, images and slide layouts are not rendered.';
    wrap.appendChild(banner);

    let slides = [];
    try {
      const cfb = new OleCfbParser(buffer).parse();
      slides = this._extract(cfb);
    } catch (e) {
      const b = document.createElement('div'); b.className = 'error-box';
      const h = document.createElement('h3'); h.textContent = 'Failed to parse .ppt';
      b.appendChild(h);
      const p = document.createElement('p'); p.textContent = e.message;
      b.appendChild(p); wrap.appendChild(b); return wrap;
    }

    if (!slides.length) {
      const p = document.createElement('p'); p.style.cssText = 'color:#888;padding:20px;text-align:center';
      p.textContent = 'No text content could be extracted from this presentation.';
      wrap.appendChild(p); return wrap;
    }

    // Slide counter
    const counter = document.createElement('div'); counter.className = 'pptx-slide-counter';
    counter.textContent = `${slides.length} slide${slides.length !== 1 ? 's' : ''} (text extracted)`;
    wrap.appendChild(counter);

    // Render each slide's text
    for (let i = 0; i < slides.length; i++) {
      const slideDiv = document.createElement('div'); slideDiv.className = 'ppt-slide-text';
      const header = document.createElement('div'); header.className = 'ppt-slide-header';
      header.textContent = `Slide ${i + 1}`;
      slideDiv.appendChild(header);

      const content = document.createElement('div'); content.className = 'ppt-slide-content';
      const texts = slides[i];
      if (texts.length) {
        for (const t of texts) {
          const p = document.createElement('p'); p.style.cssText = 'margin:2px 0;';
          p.textContent = t; content.appendChild(p);
        }
      } else {
        const p = document.createElement('p'); p.style.cssText = 'color:#888;font-style:italic';
        p.textContent = '(no text on this slide)'; content.appendChild(p);
      }
      slideDiv.appendChild(content);
      wrap.appendChild(slideDiv);
    }

    return wrap;
  }

  analyzeForSecurity(buffer) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    try {
      const cfb = new OleCfbParser(buffer).parse();

      // Check for VBA macros
      const vbaDir = cfb.streams.get('_vba_project_cur/vba/dir') || cfb.streams.get('vba/dir');
      const vbaProj = cfb.streams.get('_vba_project_cur/vbaproject.bin') || cfb.streams.get('vba/vbaproject.bin');
      if (vbaDir || vbaProj) {
        f.hasMacros = true; escalateRisk(f, 'medium');
      }

      // Try to extract VBA modules
      for (const [name, data] of cfb.streams.entries()) {
        if (/vba/i.test(name) && !name.endsWith('/')) {
          f.macroSize += data.length;
          if (!f.hasMacros) { f.hasMacros = true; escalateRisk(f, 'medium'); }
        }
      }

      // Parse VBA if we can find the project
      if (f.hasMacros) {
        // Try to get raw VBA binary for download
        const rawEntries = [];
        for (const [name, data] of cfb.streams.entries()) {
          if (/vba/i.test(name)) rawEntries.push({ name, data });
        }
        if (rawEntries.length) {
          // Concatenate all VBA-related streams
          let totalSize = 0;
          for (const e of rawEntries) totalSize += e.data.length;
          f.macroSize = totalSize;
        }
      }

      // Metadata from DocumentSummaryInfo / SummaryInfo streams
      const summaryInfo = cfb.streams.get('\x05summaryinformation') || cfb.streams.get('summaryinformation');
      if (summaryInfo) {
        try {
          f.metadata = this._parseSummaryInfo(summaryInfo);
        } catch (e) { }
      }

    } catch (e) { }

    // Pattern detection is handled entirely by YARA (auto-scan on file load)
    return f;
  }

  // ── Text extraction from PowerPoint binary ──────────────────────────────────

  _extract(cfb) {
    // Get the PowerPoint Document stream
    const pptDoc = cfb.streams.get('powerpoint document') || cfb.streams.get('powerpoint_document');
    if (!pptDoc) return this._extractFallback(cfb);

    const slides = [];
    let currentSlideTexts = [];
    const buf = pptDoc;
    let pos = 0;

    while (pos + 8 <= buf.length) {
      const recVer = buf[pos] & 0x0F;
      const _recInst = ((buf[pos] >> 4) | (buf[pos + 1] << 4)) & 0xFFF;
      const recType = buf[pos + 2] | (buf[pos + 3] << 8);
      const recLen = buf[pos + 4] | (buf[pos + 5] << 8) | (buf[pos + 6] << 16) | ((buf[pos + 7] << 24) >>> 0);

      if (recLen > buf.length - pos - 8) break; // Prevent overflow

      // Container records — recurse into header
      const isContainer = (recVer === 0x0F);

      if (recType === PptBinaryRenderer.RT_SlidePersistAtom) {
        // New slide boundary — save current and start new
        if (currentSlideTexts.length) slides.push(currentSlideTexts);
        currentSlideTexts = [];
        pos += 8 + recLen;
        continue;
      }

      if (recType === PptBinaryRenderer.RT_TextCharsAtom && !isContainer) {
        // UTF-16 LE text
        try {
          const textBuf = buf.slice(pos + 8, pos + 8 + recLen);
          const text = this._decodeUTF16(textBuf);
          if (text.trim()) currentSlideTexts.push(text.trim());
        } catch (e) { }
        pos += 8 + recLen;
        continue;
      }

      if (recType === PptBinaryRenderer.RT_TextBytesAtom && !isContainer) {
        // ASCII/Latin-1 text
        try {
          let text = '';
          for (let i = 0; i < recLen; i++) {
            text += String.fromCharCode(buf[pos + 8 + i]);
          }
          if (text.trim()) currentSlideTexts.push(text.trim());
        } catch (e) { }
        pos += 8 + recLen;
        continue;
      }

      if (recType === PptBinaryRenderer.RT_CString && !isContainer) {
        // Unicode string (used in headers/footers)
        try {
          const textBuf = buf.slice(pos + 8, pos + 8 + recLen);
          const text = this._decodeUTF16(textBuf);
          if (text.trim() && text.trim().length > 1) currentSlideTexts.push(text.trim());
        } catch (e) { }
        pos += 8 + recLen;
        continue;
      }

      if (isContainer) {
        // Recurse into container — just skip the 8-byte header
        pos += 8;
      } else {
        pos += 8 + recLen;
      }
    }

    // Push last slide
    if (currentSlideTexts.length) slides.push(currentSlideTexts);

    // If we got no slide boundaries but have text, make it one "slide"
    if (slides.length === 0 && currentSlideTexts.length) {
      slides.push(currentSlideTexts);
    }

    return slides;
  }

  _extractFallback(cfb) {
    // Fallback: try to extract any visible text from all streams
    const texts = [];
    for (const [name, data] of cfb.streams.entries()) {
      if (/powerpoint|current.*user/i.test(name)) {
        const extracted = this._extractTextFromStream(data);
        if (extracted.length) texts.push(...extracted);
      }
    }
    return texts.length ? [texts] : [];
  }

  _extractTextFromStream(buf) {
    const texts = [];
    let pos = 0;
    while (pos + 8 <= buf.length) {
      const recType = buf[pos + 2] | (buf[pos + 3] << 8);
      const recLen = buf[pos + 4] | (buf[pos + 5] << 8) | (buf[pos + 6] << 16) | ((buf[pos + 7] << 24) >>> 0);
      const recVer = buf[pos] & 0x0F;
      if (recLen > buf.length - pos - 8) break;
      const isContainer = (recVer === 0x0F);

      if (recType === PptBinaryRenderer.RT_TextCharsAtom && !isContainer) {
        try {
          const text = this._decodeUTF16(buf.slice(pos + 8, pos + 8 + recLen));
          if (text.trim()) texts.push(text.trim());
        } catch (e) { }
      } else if (recType === PptBinaryRenderer.RT_TextBytesAtom && !isContainer) {
        try {
          let text = '';
          for (let i = 0; i < recLen; i++) text += String.fromCharCode(buf[pos + 8 + i]);
          if (text.trim()) texts.push(text.trim());
        } catch (e) { }
      }

      if (isContainer) pos += 8;
      else pos += 8 + recLen;
    }
    return texts;
  }

  _decodeUTF16(buf) {
    let text = '';
    for (let i = 0; i + 1 < buf.length; i += 2) {
      const code = buf[i] | (buf[i + 1] << 8);
      if (code === 0) break;
      if (code === 0x0D) text += '\n';
      else text += String.fromCharCode(code);
    }
    return text;
  }

  _parseSummaryInfo(data) {
    // Basic SummaryInformation parser — extracts title, author, etc.
    const meta = {};
    try {
      // This is a simplified parser — full OLE property set parsing is complex
      const text = this._extractAsciiStrings(data);
      // Heuristic: first few readable strings are often title, subject, author
      if (text.length > 0) meta.title = text[0];
      if (text.length > 1) meta.creator = text[1];
      if (text.length > 2) meta.subject = text[2];
    } catch (e) { }
    return meta;
  }

  _extractAsciiStrings(data) {
    const strings = [];
    let current = '';
    for (let i = 0; i < data.length; i++) {
      const b = data[i];
      if (b >= 0x20 && b < 0x7F) {
        current += String.fromCharCode(b);
      } else {
        if (current.length >= 4) strings.push(current);
        current = '';
      }
    }
    if (current.length >= 4) strings.push(current);
    return strings.slice(0, 500); // Cap
  }
}
