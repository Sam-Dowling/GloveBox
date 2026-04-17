'use strict';
// ════════════════════════════════════════════════════════════════════════════
// html-renderer.js — Sandboxed HTML preview with DOM-aware security analysis
// Renders HTML files in an iframe sandbox (no scripts/forms/popups) and
// extracts all URLs/text from the parsed DOM for comprehensive scanning.
// ════════════════════════════════════════════════════════════════════════════

class HtmlRenderer {

  // URL-bearing attributes to extract from parsed DOM
  static URL_ATTRS = ['href', 'src', 'action', 'formaction', 'data', 'poster', 'background', 'cite', 'codebase', 'longdesc', 'usemap'];

  /**
   * Render HTML file with sandboxed iframe preview + source view.
   * @param {ArrayBuffer} buffer
   * @param {string} fileName
   * @returns {HTMLElement}
   */
  render(buffer, fileName) {
    const text = this._decode(buffer);
    const container = document.createElement('div');
    container.className = 'html-renderer';

    // ── Toolbar ──────────────────────────────────────────────────────────
    const toolbar = document.createElement('div');
    toolbar.className = 'html-toolbar';

    const previewBtn = document.createElement('button');
    previewBtn.className = 'tb-btn html-view-btn active';
    previewBtn.textContent = '🖼 Preview';
    previewBtn.title = 'Sandboxed HTML preview (no scripts)';

    const sourceBtn = document.createElement('button');
    sourceBtn.className = 'tb-btn html-view-btn';
    sourceBtn.textContent = '📝 Source';
    sourceBtn.title = 'View raw HTML source';

    toolbar.appendChild(previewBtn);
    toolbar.appendChild(sourceBtn);
    container.appendChild(toolbar);

    // ── Preview pane (sandboxed iframe) ──────────────────────────────────
    const previewPane = document.createElement('div');
    previewPane.className = 'html-preview-pane';

    const iframe = document.createElement('iframe');
    iframe.className = 'html-iframe';
    // allow-same-origin enables scroll forwarding via contentWindow.scrollBy()
    // while still blocking scripts, forms, popups, and top navigation
    iframe.sandbox = 'allow-same-origin';
    // Use srcdoc instead of blob URL - content is inline, works better with
    // allow-same-origin for scroll access across all protocols including file://
    // Inject an inner CSP to lock down the sandboxed document itself —
    // blocks scripts, fetches, fonts, objects; allows only inline styles and data: images
    const innerCSP = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:">';
    iframe.srcdoc = innerCSP + text;
    iframe.title = 'Sandboxed HTML preview';

    // ── Drag shield ──────────────────────────────────────────────────────
    // Always-active transparent overlay above the iframe. Intercepts drag/drop
    // events (preventing browser from navigating when files are dropped on the
    // iframe) and forwards scroll events to the iframe content programmatically.
    const dragShield = document.createElement('div');
    dragShield.className = 'html-drag-shield';

    // ── Drag event handlers ─────────────────────────────────────────────
    // Capture drag events and dispatch custom events for Loupe app handling
    dragShield.addEventListener('dragenter', e => {
      e.preventDefault();
      e.stopPropagation();
      window.dispatchEvent(new CustomEvent('loupe-dragenter'));
    });

    dragShield.addEventListener('dragover', e => {
      e.preventDefault();
      e.stopPropagation();
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
    });

    dragShield.addEventListener('dragleave', e => {
      e.preventDefault();
      e.stopPropagation();
      window.dispatchEvent(new CustomEvent('loupe-dragleave'));
    });

    dragShield.addEventListener('drop', e => {
      e.preventDefault();
      e.stopPropagation();
      if (e.dataTransfer?.files?.length) {
        window.dispatchEvent(new CustomEvent('loupe-drop', {
          detail: { files: e.dataTransfer.files }
        }));
      }
    });

    // ── Scroll forwarding ───────────────────────────────────────────────
    // Forward wheel events to the iframe content programmatically.
    // Works because we have allow-same-origin and srcdoc (same origin as parent).
    dragShield.addEventListener('wheel', (e) => {
      e.preventDefault();
      try {
        iframe.contentWindow.scrollBy(e.deltaX, e.deltaY);
      } catch (_) { /* ignore if cross-origin error */ }
    }, { passive: false });

    // ── Touch scroll support ────────────────────────────────────────────
    // Track touch movements and scroll the iframe content accordingly
    let touchStartY = 0;
    let touchStartX = 0;

    dragShield.addEventListener('touchstart', (e) => {
      if (e.touches.length === 1) {
        touchStartY = e.touches[0].clientY;
        touchStartX = e.touches[0].clientX;
      }
    }, { passive: true });

    dragShield.addEventListener('touchmove', (e) => {
      if (e.touches.length === 1) {
        const deltaY = touchStartY - e.touches[0].clientY;
        const deltaX = touchStartX - e.touches[0].clientX;
        touchStartY = e.touches[0].clientY;
        touchStartX = e.touches[0].clientX;
        try {
          iframe.contentWindow.scrollBy(deltaX, deltaY);
        } catch (_) { /* ignore if cross-origin error */ }
      }
    }, { passive: true });

    previewPane.appendChild(iframe);
    previewPane.appendChild(dragShield);
    container.appendChild(previewPane);

    // ── Source pane ─────────────────────────────────────────────────────
    //
    // Rendered as a `.plaintext-table` (one row per line) — the same layout
    // used by `PlainTextRenderer._buildTextPane` — so the shared sidebar
    // highlight machinery (`_highlightMatchesInline`) can wrap per-line
    // <mark> elements around YARA/IOC matches. `container._rawText` is
    // the authoritative character-offset surface those matches refer to.
    const sourcePane = document.createElement('div');
    sourcePane.className = 'html-source-pane hidden';

    const normalizedText = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const lines = normalizedText.split('\n');
    const maxLines = 100000;
    const lineCount = Math.min(lines.length, maxLines);

    // Apply XML syntax highlighting if available (limit to 100KB for performance)
    let highlightedLines = null;
    if (typeof hljs !== 'undefined' && normalizedText.length < 100 * 1024) {
      try {
        const result = hljs.highlight(normalizedText, { language: 'xml', ignoreIllegals: true });
        highlightedLines = result.value.split('\n');
      } catch (_) { /* fallback to plain */ }
    }

    const scroll = document.createElement('div');
    scroll.className = 'plaintext-scroll';

    const table = document.createElement('table');
    table.className = 'plaintext-table';

    for (let i = 0; i < lineCount; i++) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td');
      tdNum.className = 'plaintext-ln';
      tdNum.textContent = i + 1;
      const tdCode = document.createElement('td');
      tdCode.className = 'plaintext-code';
      if (highlightedLines && highlightedLines[i] !== undefined) {
        tdCode.innerHTML = highlightedLines[i] || '';
      } else {
        tdCode.textContent = lines[i];
      }
      tr.appendChild(tdNum);
      tr.appendChild(tdCode);
      table.appendChild(tr);
    }

    if (lines.length > maxLines) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 2;
      td.className = 'plaintext-truncated';
      td.textContent = `… truncated (${lines.length - maxLines} more lines)`;
      tr.appendChild(td);
      table.appendChild(tr);
    }

    scroll.appendChild(table);
    sourcePane.appendChild(scroll);
    container.appendChild(sourcePane);

    // Expose raw text + source-pane helper so the sidebar can auto-switch
    // from Preview → Source before trying to highlight.
    container._rawText = normalizedText;
    container._showSourcePane = () => {
      if (sourcePane.classList.contains('hidden')) {
        sourceBtn.click();
      }
    };


    // ── Hidden div with DOM-extracted text for scanning ──────────────────
    const domInfo = this._extractDomContent(text);
    const hiddenDiv = document.createElement('div');
    hiddenDiv.className = 'sr-only';
    hiddenDiv.style.cssText = 'position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);';
    hiddenDiv.textContent = domInfo.textContent + '\n' + domInfo.urls.join('\n');
    container.appendChild(hiddenDiv);

    // ── Toggle handlers ─────────────────────────────────────────────────
    previewBtn.addEventListener('click', () => {
      previewPane.classList.remove('hidden');
      sourcePane.classList.add('hidden');
      previewBtn.classList.add('active');
      sourceBtn.classList.remove('active');
    });
    sourceBtn.addEventListener('click', () => {
      sourcePane.classList.remove('hidden');
      previewPane.classList.add('hidden');
      sourceBtn.classList.add('active');
      previewBtn.classList.remove('active');
    });

    return container;
  }

  /**
   * Analyze HTML for security issues using DOM parsing.
   * Returns findings + augmented buffer for comprehensive YARA/threat scanning.
   * @param {ArrayBuffer} buffer
   * @param {string} fileName
   * @returns {{ risk, externalRefs, metadata, hasMacros, modules, autoExec, signatureMatches, augmentedBuffer }}
   */
  analyzeForSecurity(buffer, fileName) {
    const text = this._decode(buffer);
    const refs = [];
    let risk = 'low';

    // ── 1. DOM-aware URL extraction ──────────────────────────────────────
    const domInfo = this._extractDomContent(text);

    for (const url of domInfo.urls) {
      let sev = 'info';
      const lower = url.toLowerCase();
      // Skip data:image/* URLs — these are embedded images, not IOCs
      if (lower.startsWith('data:image/')) continue;
      if (lower.startsWith('javascript:') || lower.startsWith('vbscript:') || lower.startsWith('data:text/html')) {
        sev = 'high';
        if (risk !== 'high') risk = 'high';
      } else if (lower.startsWith('http:') || lower.startsWith('https:')) {
        sev = 'medium';
        if (risk === 'low') risk = 'medium';
      }
      refs.push({
        type: IOC.URL,
        url: url,
        severity: sev
      });
    }

    // ── 2. Form credential harvesting detection ─────────────────────────
    for (const form of domInfo.forms) {
      if (form.hasPassword) {
        refs.push({
          type: IOC.PATTERN,
          url: `Form with password field → action="${form.action || '(same page)'}"`,
          severity: 'high'
        });
        risk = 'high';
      }
    }

    // ── 3. Build augmented buffer (raw + DOM text + extracted URLs) ──────
    const augmentSections = [
      '\n\n=== RENDERED DOM TEXT ===\n\n',
      domInfo.textContent,
      '\n\n=== EXTRACTED DOM URLS ===\n\n',
      domInfo.urls.join('\n')
    ];
    const augmentText = augmentSections.join('');
    const augmentBytes = new TextEncoder().encode(augmentText);
    const rawBytes = new Uint8Array(buffer);
    const augmentedBuffer = new Uint8Array(rawBytes.length + augmentBytes.length);
    augmentedBuffer.set(rawBytes, 0);
    augmentedBuffer.set(augmentBytes, rawBytes.length);

    // Pattern detection is handled entirely by YARA (auto-scan on file load)

    // ── 4. Metadata extraction ───────────────────────────────────────────
    const metadata = {};
    const titleMatch = text.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    if (titleMatch) metadata.title = titleMatch[1].replace(/<[^>]*>/g, '').trim().slice(0, 200);

    return {
      risk,
      externalRefs: refs,
      metadata,
      hasMacros: false,
      modules: [],
      autoExec: [],
      signatureMatches: [],
      augmentedBuffer: augmentedBuffer.buffer
    };
  }

  // ── Internal: Parse HTML into DOM and extract content ──────────────────

  _extractDomContent(html) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');

    // Extract all URLs from attributes
    const urls = [];
    const seen = new Set();
    const allElements = doc.querySelectorAll('*');

    for (const el of allElements) {
      for (const attr of HtmlRenderer.URL_ATTRS) {
        const val = el.getAttribute(attr);
        if (val && val.trim() && !val.startsWith('#') && !val.startsWith('about:') && !seen.has(val.trim())) {
          seen.add(val.trim());
          urls.push(val.trim());
        }
      }
      // Check inline style for url()
      const style = el.getAttribute('style');
      if (style) {
        const urlMatches = style.matchAll(/url\s*\(\s*['"]?([^'")\s]+)['"]?\s*\)/gi);
        for (const m of urlMatches) {
          const u = m[1].trim();
          if (u && !seen.has(u)) { seen.add(u); urls.push(u); }
        }
      }
      // Check meta refresh
      if (el.tagName === 'META') {
        const content = el.getAttribute('content') || '';
        const refreshMatch = content.match(/url\s*=\s*['"]?([^'";\s]+)/i);
        if (refreshMatch && !seen.has(refreshMatch[1])) {
          seen.add(refreshMatch[1]);
          urls.push(refreshMatch[1]);
        }
      }
    }

    // Extract form info
    const forms = [];
    for (const form of doc.querySelectorAll('form')) {
      forms.push({
        action: form.getAttribute('action') || '',
        method: form.getAttribute('method') || 'GET',
        hasPassword: !!form.querySelector('input[type="password"]')
      });
    }

    // Full text content
    const textContent = (doc.body ? doc.body.textContent : doc.documentElement.textContent) || '';

    return { textContent, urls, forms };
  }

  // ── Internal: Decode buffer to string ──────────────────────────────────

  _decode(buffer) {
    const bytes = new Uint8Array(buffer);
    // Try UTF-8 first
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      return text;
    } catch (_) { }
    // Fallback to latin-1
    const chunks = [];
    const CHUNK = 32 * 1024;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      chunks.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK)));
    }
    return chunks.join('');
  }

  // ── Internal: Escape HTML ──────────────────────────────────────────────

  _escHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
}
