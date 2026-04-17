'use strict';
// ════════════════════════════════════════════════════════════════════════════
// svg-renderer.js — SVG security analyser with sandboxed preview
// Parses SVG/XML structure to detect embedded scripts, credential harvesting
// forms, event handlers, obfuscated JS, external resource loading, and other
// attack vectors used in SVG phishing (245% increase in 2025).
// ════════════════════════════════════════════════════════════════════════════

class SvgRenderer {

  // ── Event handler attributes commonly abused in SVG phishing ────────────
  static EVENT_ATTRS = [
    'onload', 'onclick', 'onmouseover', 'onmouseout', 'onmouseenter',
    'onmouseleave', 'onmousedown', 'onmouseup', 'onmousemove',
    'onfocus', 'onfocusin', 'onfocusout', 'onblur', 'onactivate',
    'onbegin', 'onend', 'onrepeat', 'onerror', 'onresize', 'onscroll',
    'onunload', 'onabort', 'oninput', 'onchange', 'onsubmit', 'onreset',
    'onkeydown', 'onkeyup', 'onkeypress', 'ontouchstart', 'ontouchend',
    'onanimationstart', 'onanimationend', 'ontransitionend'
  ];

  // ── URL-bearing attributes in SVG ──────────────────────────────────────
  static URL_ATTRS = [
    'href', 'xlink:href', 'src', 'action', 'formaction', 'data',
    'poster', 'background', 'from', 'to', 'values'
  ];

  // ── Suspicious JS patterns ─────────────────────────────────────────────
  static JS_SUSPICIOUS = [
    { pattern: /\beval\s*\(/gi, label: 'eval()' },
    { pattern: /\batob\s*\(/gi, label: 'atob()' },
    { pattern: /\bbtoa\s*\(/gi, label: 'btoa()' },
    { pattern: /String\.fromCharCode/gi, label: 'String.fromCharCode()' },
    { pattern: /\bunescape\s*\(/gi, label: 'unescape()' },
    { pattern: /document\.write/gi, label: 'document.write()' },
    { pattern: /document\.cookie/gi, label: 'document.cookie' },
    { pattern: /window\.location/gi, label: 'window.location' },
    { pattern: /document\.location/gi, label: 'document.location' },
    { pattern: /location\s*[.=]/gi, label: 'location redirect' },
    { pattern: /\.innerHTML\s*=/gi, label: 'innerHTML assignment' },
    { pattern: /\.outerHTML\s*=/gi, label: 'outerHTML assignment' },
    { pattern: /XMLHttpRequest/gi, label: 'XMLHttpRequest' },
    { pattern: /\bfetch\s*\(/gi, label: 'fetch()' },
    { pattern: /navigator\.\w+/gi, label: 'navigator access' },
    { pattern: /localStorage|sessionStorage/gi, label: 'Web Storage access' },
    { pattern: /\.submit\s*\(/gi, label: 'form.submit()' },
    { pattern: /\.execCommand/gi, label: 'execCommand()' },
    { pattern: /Function\s*\(/gi, label: 'Function constructor' },
    { pattern: /setTimeout\s*\(\s*['"`]/gi, label: 'setTimeout with string' },
    { pattern: /setInterval\s*\(\s*['"`]/gi, label: 'setInterval with string' },
  ];

  /**
   * Render SVG file with sandboxed preview + source view + security findings.
   * @param {ArrayBuffer} buffer
   * @param {string} fileName
   * @returns {HTMLElement}
   */
  render(buffer, fileName) {
    const text = this._decode(buffer);
    const container = document.createElement('div');
    container.className = 'svg-view';

    // ── Banner ──────────────────────────────────────────────────────────
    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    banner.textContent = `SVG Image — ${this._fmtBytes(buffer.byteLength)}`;
    container.appendChild(banner);

    // ── Toolbar ──────────────────────────────────────────────────────────
    const toolbar = document.createElement('div');
    toolbar.className = 'svg-toolbar';

    const previewBtn = document.createElement('button');
    previewBtn.className = 'tb-btn svg-view-btn active';
    previewBtn.textContent = '🖼 Preview';
    previewBtn.title = 'Sandboxed SVG preview (no scripts)';

    const sourceBtn = document.createElement('button');
    sourceBtn.className = 'tb-btn svg-view-btn';
    sourceBtn.textContent = '📝 Source';
    sourceBtn.title = 'View SVG source code';

    toolbar.appendChild(previewBtn);
    toolbar.appendChild(sourceBtn);
    container.appendChild(toolbar);

    // ── Preview pane (sandboxed iframe) ──────────────────────────────────
    const previewPane = document.createElement('div');
    previewPane.className = 'svg-preview-pane';

    const iframe = document.createElement('iframe');
    iframe.className = 'svg-iframe';
    iframe.sandbox = 'allow-same-origin';
    // Strip DOCTYPE (with optional internal subset) — HTML parsers don't handle
    // XML internal DTD subsets, causing ]> to render as visible text
    const previewText = text.replace(/<!DOCTYPE[^[>]*\[[^\]]*\]>/gi, '').replace(/<!DOCTYPE[^>]*>/gi, '');
    // Wrap SVG in minimal HTML with dark-mode aware background
    // Inner CSP locks down the sandboxed document — blocks scripts, fetches, fonts, objects
    const wrappedSvg = `<!DOCTYPE html><html><head><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:"><style>
      html,body{margin:0;padding:16px;display:flex;justify-content:center;align-items:center;min-height:100vh;box-sizing:border-box;
      background:repeating-conic-gradient(#f0f0f0 0% 25%,white 0% 50%) 50%/20px 20px;}
      svg{max-width:100%;max-height:90vh;}
    </style></head><body>${previewText}</body></html>`;
    iframe.srcdoc = wrappedSvg;
    iframe.title = 'SVG preview (sandboxed)';

    // Scroll forwarding
    const dragShield = document.createElement('div');
    dragShield.className = 'svg-drag-shield';
    dragShield.addEventListener('wheel', e => {
      e.preventDefault();
      try { iframe.contentWindow.scrollBy(0, e.deltaY); } catch (_) {}
    }, { passive: false });

    previewPane.appendChild(iframe);
    previewPane.appendChild(dragShield);
    container.appendChild(previewPane);

    // ── Source pane ──────────────────────────────────────────────────────
    //
    // Rendered as a `.plaintext-table` so the shared sidebar highlight
    // machinery (`_highlightMatchesInline`) can wrap per-line <mark>
    // elements around YARA/IOC matches using character offsets in the
    // `container._rawText` surface exposed below.
    const sourcePane = document.createElement('div');
    sourcePane.className = 'svg-source-pane';
    sourcePane.style.display = 'none';

    const normalizedText = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const lines = normalizedText.split('\n');

    let highlightedLines = null;
    if (typeof hljs !== 'undefined' && normalizedText.length <= 200000) {
      try {
        const result = hljs.highlight(normalizedText, { language: 'xml', ignoreIllegals: true });
        highlightedLines = result.value.split('\n');
      } catch (_) { /* fallback to plain */ }
    }

    const scroll = document.createElement('div');
    scroll.className = 'plaintext-scroll';
    const table = document.createElement('table');
    table.className = 'plaintext-table';

    for (let i = 0; i < lines.length; i++) {
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

    scroll.appendChild(table);
    sourcePane.appendChild(scroll);
    container.appendChild(sourcePane);

    // Expose raw text + source-pane helper so the sidebar can auto-switch
    // from Preview → Source before trying to highlight.
    container._rawText = normalizedText;
    container._showSourcePane = () => {
      if (sourcePane.style.display === 'none') {
        sourceBtn.click();
      }
    };


    // ── Tab switching ───────────────────────────────────────────────────
    previewBtn.addEventListener('click', () => {
      previewBtn.classList.add('active');
      sourceBtn.classList.remove('active');
      previewPane.style.display = '';
      sourcePane.style.display = 'none';
    });
    sourceBtn.addEventListener('click', () => {
      sourceBtn.classList.add('active');
      previewBtn.classList.remove('active');
      sourcePane.style.display = '';
      previewPane.style.display = 'none';
    });

    // ── Hidden text for content search ──────────────────────────────────
    const hidden = document.createElement('div');
    hidden.className = 'sr-only';
    hidden.style.cssText = 'position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0);';
    hidden.textContent = text;
    container.appendChild(hidden);

    return container;
  }

  /**
   * Analyze SVG for security issues — deep SVG-specific analysis.
   * @param {ArrayBuffer} buffer
   * @param {string} fileName
   * @returns {Object} findings
   */
  analyzeForSecurity(buffer, fileName) {
    const text = this._decode(buffer);
    const refs = [];
    let risk = 'low';

    const setRisk = (level) => {
      const levels = { low: 0, medium: 1, high: 2, critical: 3 };
      if (levels[level] > levels[risk]) risk = level;
    };

    // Parse SVG as XML
    const parser = new DOMParser();
    const doc = parser.parseFromString(text, 'image/svg+xml');
    const parseError = doc.querySelector('parsererror');

    // Even if XML parse fails, do regex-based analysis on raw text
    const allElements = parseError ? [] : Array.from(doc.querySelectorAll('*'));

    // ── 1. <script> elements ─────────────────────────────────────────────
    const scriptEls = parseError ? [] : doc.querySelectorAll('script');
    for (const script of scriptEls) {
      const content = script.textContent.trim();
      const src = script.getAttribute('href') || script.getAttribute('xlink:href') || '';
      if (content) {
        refs.push({
          type: IOC.PATTERN,
          url: `Embedded <script> element (${content.length} chars): ${this._truncate(content, 120)}`,
          severity: 'critical'
        });
        setRisk('critical');
        // Check for obfuscation in script content
        this._checkJsSuspicious(content, refs, setRisk);
      }
      if (src) {
        refs.push({
          type: IOC.URL,
          url: src,
          severity: 'critical'
        });
        refs.push({
          type: IOC.PATTERN,
          url: `External script reference: ${src}`,
          severity: 'critical'
        });
        setRisk('critical');
      }
    }

    // Regex fallback for scripts in CDATA or entity-encoded
    const scriptRegex = /<script[\s>][^]*?<\/script>/gi;
    let scriptMatch;
    while ((scriptMatch = scriptRegex.exec(text)) !== null) {
      if (scriptEls.length === 0) {
        refs.push({
          type: IOC.PATTERN,
          url: `<script> block detected in raw SVG (${scriptMatch[0].length} chars)`,
          severity: 'critical'
        });
        setRisk('critical');
      }
    }

    // ── 2. Event handler attributes ──────────────────────────────────────
    const eventHandlers = [];
    for (const el of allElements) {
      for (const attr of SvgRenderer.EVENT_ATTRS) {
        const val = el.getAttribute(attr);
        if (val && val.trim()) {
          eventHandlers.push({ element: el.tagName.toLowerCase(), attr, value: val.trim() });
        }
      }
    }
    if (eventHandlers.length > 0) {
      // Group by attribute for cleaner output
      const grouped = {};
      for (const h of eventHandlers) {
        const key = h.attr;
        if (!grouped[key]) grouped[key] = [];
        grouped[key].push(h);
      }
      for (const [attr, handlers] of Object.entries(grouped)) {
        const sample = handlers[0];
        const suffix = handlers.length > 1 ? ` (+${handlers.length - 1} more)` : '';
        refs.push({
          type: IOC.PATTERN,
          url: `Event handler ${attr} on <${sample.element}>: ${this._truncate(sample.value, 100)}${suffix}`,
          severity: 'high'
        });
        setRisk('high');
        // Check JS content in handlers
        for (const h of handlers) {
          this._checkJsSuspicious(h.value, refs, setRisk);
        }
      }
    }

    // Regex fallback for event handlers (catches entity-encoded attrs)
    const eventRegex = /\bon(?:load|click|mouseover|error|focus|begin|end|activate)\s*=\s*["']([^"']+)["']/gi;
    let evtMatch;
    while ((evtMatch = eventRegex.exec(text)) !== null) {
      if (eventHandlers.length === 0) {
        refs.push({
          type: IOC.PATTERN,
          url: `Event handler in raw SVG: ${evtMatch[0].substring(0, 100)}`,
          severity: 'high'
        });
        setRisk('high');
      }
    }

    // ── 3. <foreignObject> detection ─────────────────────────────────────
    const foreignObjects = parseError ? [] : doc.querySelectorAll('foreignObject');
    for (const fo of foreignObjects) {
      const html = fo.innerHTML || '';
      const hasForm = /<form[\s>]/i.test(html);
      const hasPassword = /<input[^>]+type\s*=\s*["']?password/i.test(html);
      const hasIframe = /<iframe[\s>]/i.test(html);
      const hasEmbed = /<(?:embed|object)[\s>]/i.test(html);
      const hasScript = /<script[\s>]/i.test(html);

      if (hasPassword) {
        refs.push({
          type: IOC.PATTERN,
          url: 'Credential harvesting: <foreignObject> contains password input field',
          severity: 'critical'
        });
        setRisk('critical');
      } else if (hasForm) {
        refs.push({
          type: IOC.PATTERN,
          url: 'Phishing form: <foreignObject> contains HTML form',
          severity: 'high'
        });
        setRisk('high');
      }
      if (hasIframe) {
        refs.push({
          type: IOC.PATTERN,
          url: '<foreignObject> contains <iframe> — potential redirect/phishing',
          severity: 'high'
        });
        setRisk('high');
      }
      if (hasEmbed) {
        refs.push({
          type: IOC.PATTERN,
          url: '<foreignObject> contains <embed>/<object> — potential payload delivery',
          severity: 'high'
        });
        setRisk('high');
      }
      if (hasScript) {
        refs.push({
          type: IOC.PATTERN,
          url: '<foreignObject> contains <script> — embedded JavaScript execution',
          severity: 'critical'
        });
        setRisk('critical');
      }
      if (!hasForm && !hasPassword && !hasIframe && !hasEmbed && !hasScript) {
        refs.push({
          type: IOC.PATTERN,
          url: `<foreignObject> element detected (${html.length} chars of embedded HTML)`,
          severity: 'medium'
        });
        setRisk('medium');
      }
    }

    // Regex fallback for foreignObject
    if (foreignObjects.length === 0 && /<foreignObject[\s>]/i.test(text)) {
      refs.push({
        type: IOC.PATTERN,
        url: '<foreignObject> detected in raw SVG markup',
        severity: 'medium'
      });
      setRisk('medium');
    }

    // ── 4. Base64-encoded payloads in attributes ─────────────────────────
    const dataUriRegex = /data:\s*([^;,\s]+)(?:;([^,\s]+))?\s*,\s*([A-Za-z0-9+/=]{20,})/g;
    let dataMatch;
    while ((dataMatch = dataUriRegex.exec(text)) !== null) {
      const mimeType = dataMatch[1].toLowerCase();
      const encoding = (dataMatch[2] || '').toLowerCase();
      const payload = dataMatch[3];

      // Script MIME types in data URIs
      if (/javascript|ecmascript|jscript|vbscript|html/i.test(mimeType)) {
        refs.push({
          type: IOC.PATTERN,
          url: `Data URI with script MIME type: data:${mimeType} (${payload.length} chars)`,
          severity: 'critical'
        });
        setRisk('critical');
      }
      // Base64-encoded payloads — try to decode and check
      if (encoding === 'base64' && !/^image\//i.test(mimeType)) {
        try {
          const decoded = atob(payload.substring(0, 500));
          if (/<script|javascript:|on\w+\s*=/i.test(decoded)) {
            refs.push({
              type: IOC.PATTERN,
              url: `Base64 data URI decodes to script content: ${this._truncate(decoded, 100)}`,
              severity: 'critical'
            });
            setRisk('critical');
          }
        } catch (_) { /* invalid base64 — skip */ }
      }
    }

    // ── 5. URL extraction from SVG attributes ────────────────────────────
    const urls = new Set();
    for (const el of allElements) {
      for (const attr of SvgRenderer.URL_ATTRS) {
        const val = el.getAttribute(attr);
        if (val && val.trim() && !val.startsWith('#')) {
          const u = val.trim();
          if (/^(?:https?:|\/\/|ftp:|data:)/i.test(u)) {
            urls.add(u);
          }
        }
      }
      // Check inline styles for url()
      const style = el.getAttribute('style');
      if (style) {
        const urlMatches = style.matchAll(/url\s*\(\s*['"]?([^'")\s]+)['"]?\s*\)/gi);
        for (const m of urlMatches) {
          const u = m[1].trim();
          if (u && /^(?:https?:|\/\/|ftp:|data:)/i.test(u)) urls.add(u);
        }
      }
    }
    // Also check <style> blocks
    const styleEls = parseError ? [] : doc.querySelectorAll('style');
    for (const sty of styleEls) {
      const cssText = sty.textContent || '';
      const urlMatches = cssText.matchAll(/url\s*\(\s*['"]?([^'")\s]+)['"]?\s*\)/gi);
      for (const m of urlMatches) {
        const u = m[1].trim();
        if (u && /^(?:https?:|\/\/|ftp:|data:)/i.test(u)) urls.add(u);
      }
    }

    for (const url of urls) {
      let sev = 'info';
      const lower = url.toLowerCase();
      if (lower.startsWith('data:image/')) continue; // skip embedded images
      if (lower.startsWith('javascript:') || lower.startsWith('vbscript:') || lower.startsWith('data:text/html')) {
        sev = 'high';
        setRisk('high');
      } else if (lower.startsWith('http:') || lower.startsWith('https:') || lower.startsWith('//')) {
        sev = 'medium';
        setRisk('medium');
      }
      refs.push({ type: IOC.URL, url, severity: sev });
    }

    // ── 6. SVG-specific attack vectors ───────────────────────────────────

    // <use> referencing external resources
    const useEls = parseError ? [] : doc.querySelectorAll('use');
    for (const u of useEls) {
      const href = u.getAttribute('href') || u.getAttribute('xlink:href') || '';
      if (href && !href.startsWith('#') && /^(?:https?:|\/\/|data:)/i.test(href)) {
        refs.push({
          type: IOC.PATTERN,
          url: `<use> element loads external resource: ${this._truncate(href, 150)}`,
          severity: 'medium'
        });
        setRisk('medium');
      }
    }

    // <animate>/<set> modifying href (runtime attribute manipulation)
    const animEls = parseError ? [] : doc.querySelectorAll('animate, set, animateTransform');
    for (const anim of animEls) {
      const attrName = (anim.getAttribute('attributeName') || '').toLowerCase();
      if (['href', 'xlink:href', 'src', 'action', 'data'].includes(attrName)) {
        const toVal = anim.getAttribute('to') || anim.getAttribute('values') || '';
        refs.push({
          type: IOC.PATTERN,
          url: `<${anim.tagName.toLowerCase()}> animates "${attrName}" → ${this._truncate(toVal, 100)}`,
          severity: 'high'
        });
        setRisk('high');
      }
    }

    // <feImage> with external filter reference
    const feImages = parseError ? [] : doc.querySelectorAll('feImage');
    for (const fi of feImages) {
      const href = fi.getAttribute('href') || fi.getAttribute('xlink:href') || '';
      if (href && !href.startsWith('#') && /^(?:https?:|\/\/|data:)/i.test(href)) {
        refs.push({
          type: IOC.PATTERN,
          url: `<feImage> loads external resource: ${this._truncate(href, 150)}`,
          severity: 'medium'
        });
        setRisk('medium');
      }
    }

    // <image> elements (can load external resources)
    const imageEls = parseError ? [] : doc.querySelectorAll('image');
    for (const img of imageEls) {
      const href = img.getAttribute('href') || img.getAttribute('xlink:href') || '';
      if (href && /^(?:https?:|\/\/)/i.test(href)) {
        refs.push({
          type: IOC.PATTERN,
          url: `<image> loads external URL: ${this._truncate(href, 150)}`,
          severity: 'medium'
        });
        setRisk('medium');
      }
    }

    // ── 7. Entity/DTD references in raw text ─────────────────────────────
    if (/<!ENTITY\s/i.test(text)) {
      refs.push({
        type: IOC.PATTERN,
        url: 'XML entity declaration detected — potential XXE or obfuscation',
        severity: 'high'
      });
      setRisk('high');
    }
    if (/<!DOCTYPE[^>]+SYSTEM\s/i.test(text)) {
      refs.push({
        type: IOC.PATTERN,
        url: 'DOCTYPE with SYSTEM reference — potential XXE',
        severity: 'high'
      });
      setRisk('high');
    }

    // ── 8. Obfuscation in raw text (catches entity-encoded JS) ───────────
    // Check for common obfuscation patterns outside of <script> tags
    const textWithoutScripts = text.replace(/<script[\s>][^]*?<\/script>/gi, '');
    this._checkJsSuspicious(textWithoutScripts, refs, setRisk, true);

    // ── 9. Meta refresh / redirect in foreignObject ──────────────────────
    const metaRefreshRegex = /<meta[^>]+http-equiv\s*=\s*["']?refresh[^>]+content\s*=\s*["']?\d+;\s*url\s*=\s*([^"'\s>]+)/gi;
    let metaMatch;
    while ((metaMatch = metaRefreshRegex.exec(text)) !== null) {
      refs.push({
        type: IOC.URL,
        url: metaMatch[1],
        severity: 'high'
      });
      refs.push({
        type: IOC.PATTERN,
        url: `Meta refresh redirect to: ${metaMatch[1]}`,
        severity: 'high'
      });
      setRisk('high');
    }

    // ── 10. Build augmented buffer for YARA scanning ─────────────────────
    const augmentSections = [text];
    // Add extracted URLs for YARA matching
    if (urls.size > 0) {
      augmentSections.push('\n\n=== EXTRACTED SVG URLS ===\n\n');
      augmentSections.push(Array.from(urls).join('\n'));
    }
    // Add decoded event handler values
    if (eventHandlers.length > 0) {
      augmentSections.push('\n\n=== SVG EVENT HANDLERS ===\n\n');
      augmentSections.push(eventHandlers.map(h => `${h.attr} on <${h.element}>: ${h.value}`).join('\n'));
    }
    const augmentText = augmentSections.join('');
    const augmentBytes = new TextEncoder().encode(augmentText);

    // ── 11. Metadata ─────────────────────────────────────────────────────
    const metadata = { format: 'SVG', size: this._fmtBytes(buffer.byteLength) };
    // Try to get SVG dimensions
    if (!parseError) {
      const svgRoot = doc.querySelector('svg');
      if (svgRoot) {
        const w = svgRoot.getAttribute('width');
        const h = svgRoot.getAttribute('height');
        const vb = svgRoot.getAttribute('viewBox');
        if (w && h) metadata.dimensions = `${w} × ${h}`;
        else if (vb) metadata.viewBox = vb;
      }
    }

    // ── Summary counts ───────────────────────────────────────────────────
    const scriptCount = scriptEls.length || (/<script[\s>]/i.test(text) ? 1 : 0);
    const foCount = foreignObjects.length || (/<foreignObject[\s>]/i.test(text) ? 1 : 0);
    const handlerCount = eventHandlers.length;
    if (scriptCount) metadata.embeddedScripts = scriptCount;
    if (foCount) metadata.foreignObjects = foCount;
    if (handlerCount) metadata.eventHandlers = handlerCount;
    if (urls.size) metadata.externalUrls = urls.size;

    return {
      risk,
      externalRefs: refs,
      metadata,
      hasMacros: false,
      modules: [],
      autoExec: [],
      signatureMatches: [],
      augmentedBuffer: augmentBytes.buffer
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Internal helpers
  // ═══════════════════════════════════════════════════════════════════════════

  /** Check JS content for suspicious patterns and push findings */
  _checkJsSuspicious(content, refs, setRisk, dedup = false) {
    const seen = dedup ? new Set(refs.map(r => r.url)) : null;
    for (const { pattern, label } of SvgRenderer.JS_SUSPICIOUS) {
      pattern.lastIndex = 0;
      if (pattern.test(content)) {
        const msg = `Suspicious JavaScript pattern: ${label}`;
        if (dedup && seen && seen.has(msg)) continue;
        if (dedup && seen) seen.add(msg);
        refs.push({
          type: IOC.PATTERN,
          url: msg,
          severity: 'high'
        });
        setRisk('high');
      }
    }
  }

  /** Build plain-text source with line numbers (fallback when no hljs) */
  _plainSource(lines, gutterW) {
    return lines.map((line, i) => {
      const num = String(i + 1).padStart(gutterW, ' ');
      return `<span class="svg-ln">${num}</span>${this._escHtml(line)}`;
    }).join('\n');
  }

  /** Decode ArrayBuffer to string */
  _decode(buffer) {
    const bytes = new Uint8Array(buffer);
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch (_) { }
    const chunks = [];
    const CHUNK = 32 * 1024;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      chunks.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK)));
    }
    return chunks.join('');
  }

  /** Escape HTML entities */
  _escHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  /** Truncate string to maxLen chars */
  _truncate(s, maxLen) {
    if (!s) return '';
    return s.length > maxLen ? s.substring(0, maxLen) + '…' : s;
  }

  /** Format bytes */
  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
