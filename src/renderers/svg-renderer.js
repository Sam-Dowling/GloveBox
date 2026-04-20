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

  // ── Magic-byte signatures for decoded data-URI/base64 blob identification ─
  // Sniffed against the first bytes of a base64-decoded attribute value.
  // Mirrors the table in onenote-renderer.js / encoded-content-detector.js.
  static MIME_SIGS = [
    { magic: [0x4D, 0x5A],                     type: 'PE Executable',       sev: 'critical' },
    { magic: [0x7F, 0x45, 0x4C, 0x46],         type: 'ELF Binary',          sev: 'critical' },
    { magic: [0xCF, 0xFA, 0xED, 0xFE],         type: 'Mach-O Binary',       sev: 'critical' },
    { magic: [0xCA, 0xFE, 0xBA, 0xBE],         type: 'Java Class',          sev: 'critical' },
    { magic: [0xD0, 0xCF, 0x11, 0xE0],         type: 'OLE/CFB Document',    sev: 'high' },
    { magic: [0x50, 0x4B, 0x03, 0x04],         type: 'ZIP/Office Archive',  sev: 'high' },
    { magic: [0x52, 0x61, 0x72, 0x21],         type: 'RAR Archive',         sev: 'high' },
    { magic: [0x37, 0x7A, 0xBC, 0xAF],         type: '7-Zip Archive',       sev: 'high' },
    { magic: [0x25, 0x50, 0x44, 0x46],         type: 'PDF Document',        sev: 'high' },
    { magic: [0x1F, 0x8B],                     type: 'Gzip Compressed',     sev: 'high' },
    { magic: [0x78, 0x9C],                     type: 'Zlib (default)',      sev: 'medium' },
    { magic: [0x78, 0xDA],                     type: 'Zlib (best)',         sev: 'medium' },
    { magic: [0x78, 0x01],                     type: 'Zlib (no/low)',       sev: 'medium' },
    { magic: [0x4C, 0x00, 0x00, 0x00],         type: 'Windows Shortcut',    sev: 'critical' },
    { magic: [0x89, 0x50, 0x4E, 0x47],         type: 'PNG Image',           sev: 'info' },
    { magic: [0xFF, 0xD8, 0xFF],               type: 'JPEG Image',          sev: 'info' },
    { magic: [0x47, 0x49, 0x46, 0x38],         type: 'GIF Image',           sev: 'info' },
    { magic: [0x42, 0x4D],                     type: 'BMP Image',           sev: 'info' },
    { magic: [0x52, 0x49, 0x46, 0x46],         type: 'RIFF (WAV/WebP)',     sev: 'info' },
  ];

  // ── Forcepoint X-Labs obfuscation fingerprints (SVG phishing loaders) ───
  // Patterns observed repeatedly in 2024–2025 SVG phishing campaigns where
  // the SVG itself is a self-decrypting loader for an HTML phishing page.
  // Each entry fires once per document; we attach a metadata counter.
  //
  // Categories:
  //   aes      — CryptoJS-style AES decryption of the real payload
  //   xor      — per-byte XOR loop with a key constant
  //   reverse  — String reversal chain (classic "hide from string scanners")
  //   replace  — no-op .replace() chains used to strip marker chars from a
  //              hex/base64 buffer (e.g. ".replace(/_/g,'')")
  //   chararr  — large String.fromCharCode(...) array with many args
  //   unesc    — unescape + %u/%x sequences feeding eval/Function
  static OBFUSCATION_FINGERPRINTS = [
    { key: 'aes', label: 'AES decryption (CryptoJS-style)',
      patterns: [
        /CryptoJS\s*\.\s*AES/i,
        /\bAES\s*\.\s*(?:encrypt|decrypt)\s*\(/i,
        /CryptoJS\s*\.\s*enc\s*\.\s*(?:Utf8|Hex|Base64)/i,
        /\bWordArray\s*\.\s*create/i,
      ]
    },
    { key: 'xor', label: 'Per-byte XOR loop',
      patterns: [
        /\.charCodeAt\s*\([^)]*\)\s*\^/,
        /String\.fromCharCode\s*\([^)]*\^[^)]*\)/,
        /\^\s*0x[0-9a-f]{2}\b/i,
        /\bfor\b[^{]*\{[^}]*\^=\s*[^;]*;[^}]*charCodeAt/,
      ]
    },
    { key: 'reverse', label: 'String reversal chain',
      patterns: [
        /\.split\s*\(\s*['"`]['"`]\s*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(/,
        /\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(\s*['"`]['"`]\s*\)/,
      ]
    },
    { key: 'replace', label: 'No-op .replace() chain (marker-char stripper)',
      patterns: [
        /(?:\.replace\s*\(\s*\/[^/\n]{1,20}\/g?\s*,\s*['"`][^'"`]{0,5}['"`]\s*\)\s*){2,}/,
        /\.replace\s*\(\s*\/[^/\n]{1,4}\/g\s*,\s*['"`]['"`]\s*\)\s*\.\s*replace\s*\(/,
      ]
    },
    { key: 'chararr', label: 'String.fromCharCode with large numeric array',
      patterns: [
        /String\.fromCharCode\s*\(\s*(?:\d{1,3}\s*,\s*){8,}\d{1,3}\s*\)/,
        /String\.fromCharCode\.apply\s*\(\s*(?:null|this)\s*,\s*\[/,
      ]
    },
    { key: 'unesc', label: 'unescape() of %u/%xx escape sequence',
      patterns: [
        /unescape\s*\(\s*['"`](?:%u[0-9a-f]{4}|%[0-9a-f]{2}){4,}/i,
        /decodeURIComponent\s*\(\s*['"`](?:%[0-9a-f]{2}){6,}/i,
      ]
    },
    { key: 'b64eval', label: 'atob() fed directly to eval/Function',
      patterns: [
        /eval\s*\(\s*atob\s*\(/i,
        /(?:Function|new\s+Function)\s*\(\s*atob\s*\(/i,
        /(?:setTimeout|setInterval)\s*\(\s*atob\s*\(/i,
      ]
    },
    { key: 'dottedeval', label: 'Indirect eval via window/this[\'ev\'+\'al\']',
      patterns: [
        /(?:window|self|this|globalThis)\s*\[\s*['"`](?:ev|eva|e)['"`]\s*\+\s*['"`](?:al|l)['"`]\s*\]/i,
        /['"`]ev['"`]\s*\+\s*['"`]al['"`]/i,
      ]
    },
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
    // Pre-locate every raw <script> block in the source for offset attachment.
    // We pair each DOM <script> with a raw range by looking up a short prefix
    // of its text content — this is robust against the DOM parser rejecting
    // malformed scripts (which would otherwise misalign a zip-by-index
    // pairing against subsequent scripts in the source).
    const scriptRanges = [];
    {
      // Closing `<\/script\b[^>]*>` accepts trailing attributes / whitespace
      // the way browsers do (js/bad-tag-filter #57). Backslash-escapes
      // above are load-bearing: without them the literal end-tag bytes
      // here would be seen by the HTML tokenizer once this file is
      // concatenated inline into docs/index.html's inline script bundle,
      // terminating it early.
      const re = /<script[\s>][\s\S]*?<\/script\b[^>]*>/gi;
      let mm;
      while ((mm = re.exec(text)) !== null) {
        scriptRanges.push({ offset: mm.index, length: mm[0].length, text: mm[0], taken: false });
      }
    }
    const findScriptRange = (content) => {
      if (!content) return null;
      // Match on the first non-whitespace-normalised slice of script content.
      // Fall back to empty-content range lookup if no content (e.g. src-only).
      const needle = content.slice(0, 64);
      for (const r of scriptRanges) {
        if (r.taken) continue;
        if (!needle || r.text.indexOf(needle) !== -1) {
          r.taken = true;
          return r;
        }
      }
      // Last resort: any remaining unclaimed range (preserves old behaviour
      // for src-only scripts with no text content).
      for (const r of scriptRanges) {
        if (!r.taken) { r.taken = true; return r; }
      }
      return null;
    };
    for (const script of scriptEls) {
      const content = script.textContent.trim();
      const src = script.getAttribute('href') || script.getAttribute('xlink:href') || '';
      const range = findScriptRange(content);
      if (content) {
        refs.push({
          type: IOC.PATTERN,
          url: `Embedded <script> element (${content.length} chars): ${this._truncate(content, 120)}`,
          severity: 'critical',
          _highlightText: range ? range.text : '<script',
          _sourceOffset: range ? range.offset : undefined,
          _sourceLength: range ? range.length : undefined,
        });
        setRisk('critical');
        // Check for obfuscation in script content
        this._checkJsSuspicious(content, refs, setRisk, false, text);
      }
      if (src) {
        refs.push({
          type: IOC.URL,
          url: src,
          severity: 'critical',
          _highlightText: src,
        });
        refs.push({
          type: IOC.PATTERN,
          url: `External script reference: ${src}`,
          severity: 'critical',
          _highlightText: src,
        });
        setRisk('critical');
      }
    }

    // Regex fallback for scripts in CDATA or entity-encoded.
    // Closing `<\/script\b[^>]*>` mirrors the HTML parser (js/bad-tag-filter #58).
    const scriptRegex = /<script[\s>][\s\S]*?<\/script\b[^>]*>/gi;
    let scriptMatch;
    while ((scriptMatch = scriptRegex.exec(text)) !== null) {
      if (scriptEls.length === 0) {
        refs.push({
          type: IOC.PATTERN,
          url: `<script> block detected in raw SVG (${scriptMatch[0].length} chars)`,
          severity: 'critical',
          _highlightText: scriptMatch[0],
          _sourceOffset: scriptMatch.index,
          _sourceLength: scriptMatch[0].length,
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
        // Locate the handler attribute in the raw source for precise highlight.
        const attrRe = new RegExp('\\b' + attr + '\\s*=', 'i');
        const attrIdx = text.search(attrRe);
        refs.push({
          type: IOC.PATTERN,
          url: `Event handler ${attr} on <${sample.element}>: ${this._truncate(sample.value, 100)}${suffix}`,
          severity: 'high',
          _highlightText: attr,
          _sourceOffset: attrIdx >= 0 ? attrIdx : undefined,
          _sourceLength: attrIdx >= 0 ? attr.length : undefined,
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
          severity: 'high',
          _highlightText: evtMatch[0],
          _sourceOffset: evtMatch.index,
          _sourceLength: evtMatch[0].length,
        });
        setRisk('high');
      }
    }

    // ── 3. <foreignObject> detection ─────────────────────────────────────
    const foreignObjects = parseError ? [] : doc.querySelectorAll('foreignObject');
    // Locate the first raw <foreignObject> tag for offset attachment.
    const foMatch = text.match(/<foreignObject[\s>]/i);
    const foHL = {
      _highlightText: '<foreignObject',
      _sourceOffset: foMatch ? foMatch.index : undefined,
      _sourceLength: foMatch ? '<foreignObject'.length : undefined,
    };
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
          severity: 'critical',
          ...foHL,
        });
        setRisk('critical');
      } else if (hasForm) {
        refs.push({
          type: IOC.PATTERN,
          url: 'Phishing form: <foreignObject> contains HTML form',
          severity: 'high',
          ...foHL,
        });
        setRisk('high');
      }
      if (hasIframe) {
        refs.push({
          type: IOC.PATTERN,
          url: '<foreignObject> contains <iframe> — potential redirect/phishing',
          severity: 'high',
          ...foHL,
        });
        setRisk('high');
      }
      if (hasEmbed) {
        refs.push({
          type: IOC.PATTERN,
          url: '<foreignObject> contains <embed>/<object> — potential payload delivery',
          severity: 'high',
          ...foHL,
        });
        setRisk('high');
      }
      if (hasScript) {
        refs.push({
          type: IOC.PATTERN,
          url: '<foreignObject> contains <script> — embedded JavaScript execution',
          severity: 'critical',
          ...foHL,
        });
        setRisk('critical');
      }
      if (!hasForm && !hasPassword && !hasIframe && !hasEmbed && !hasScript) {
        refs.push({
          type: IOC.PATTERN,
          url: `<foreignObject> element detected (${html.length} chars of embedded HTML)`,
          severity: 'medium',
          ...foHL,
        });
        setRisk('medium');
      }
    }

    // Regex fallback for foreignObject
    if (foreignObjects.length === 0 && /<foreignObject[\s>]/i.test(text)) {
      refs.push({
        type: IOC.PATTERN,
        url: '<foreignObject> detected in raw SVG markup',
        severity: 'medium',
        ...foHL,
      });
      setRisk('medium');
    }

    // ── 4. Base64-encoded payloads in attributes + magic-byte sniffing ───
    // Scan both data: URIs AND bare long base64 literals (phishing loaders
    // commonly store the real payload as a JS string constant, not a data:
    // URI — e.g. `var p = "TVqQA..."; var b = atob(p);`).
    const sniffedBlobTypes = [];
    const seenBlobPrefix = new Set();

    const dataUriRegex = /data:\s*([^;,\s]+)(?:;([^,\s]+))?\s*,\s*([A-Za-z0-9+/=]{20,})/g;
    let dataMatch;
    while ((dataMatch = dataUriRegex.exec(text)) !== null) {
      const mimeType = dataMatch[1].toLowerCase();
      const encoding = (dataMatch[2] || '').toLowerCase();
      const payload = dataMatch[3];

      // Anchor highlights on the start of the data: URI in the raw source.
      const dataHL = {
        _highlightText: dataMatch[0].substring(0, Math.min(64, dataMatch[0].length)),
        _sourceOffset: dataMatch.index,
        _sourceLength: Math.min(64, dataMatch[0].length),
      };

      // Script MIME types in data URIs
      if (/javascript|ecmascript|jscript|vbscript|html/i.test(mimeType)) {
        refs.push({
          type: IOC.PATTERN,
          url: `Data URI with script MIME type: data:${mimeType} (${payload.length} chars)`,
          severity: 'critical',
          ...dataHL,
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
              severity: 'critical',
              ...dataHL,
            });
            setRisk('critical');
          }
          // Magic-byte sniff of the decoded bytes
          const sniff = this._sniffBase64(payload);
          if (sniff && !seenBlobPrefix.has(payload.substring(0, 8))) {
            seenBlobPrefix.add(payload.substring(0, 8));
            sniffedBlobTypes.push(sniff.type);
            refs.push({
              type: IOC.PATTERN,
              url: `Data URI base64 blob decodes to ${sniff.type} (${payload.length} chars of base64)`,
              severity: sniff.sev,
              ...dataHL,
            });
            setRisk(sniff.sev);
          }
        } catch (_) { /* invalid base64 — skip */ }
      } else if (encoding === 'base64' && /^image\/(?:png|jpe?g|gif|webp|bmp)$/i.test(mimeType)) {
        // Even image/* data URIs can be polyglots — sniff if the declared
        // MIME doesn't match the decoded magic (e.g. image/png but MZ header).
        try {
          const sniff = this._sniffBase64(payload);
          if (sniff && !/image|info/i.test(sniff.sev)) {
            const declaredExt = mimeType.split('/')[1] || '';
            const actualLower = sniff.type.toLowerCase();
            if (!actualLower.includes(declaredExt.toLowerCase())) {
              refs.push({
                type: IOC.PATTERN,
                url: `Polyglot: declared ${mimeType} but decodes to ${sniff.type}`,
                severity: 'critical',
                ...dataHL,
              });
              setRisk('critical');
              sniffedBlobTypes.push(`POLYGLOT:${sniff.type}`);
            }
          }
        } catch (_) { }
      }
    }

    // Bare long base64 literals inside <script> or JS strings
    const bareB64Regex = /[A-Za-z0-9+/]{120,}={0,2}/g;
    let bareMatch;
    let bareScanned = 0;
    while ((bareMatch = bareB64Regex.exec(text)) !== null && bareScanned < 50) {
      bareScanned++;
      const b64 = bareMatch[0];
      const prefix = b64.substring(0, 8);
      if (seenBlobPrefix.has(prefix)) continue;
      try {
        const sniff = this._sniffBase64(b64);
        if (sniff) {
          seenBlobPrefix.add(prefix);
          sniffedBlobTypes.push(sniff.type);
          refs.push({
            type: IOC.PATTERN,
            url: `Bare base64 literal decodes to ${sniff.type} (${b64.length} chars, prefix "${prefix}…")`,
            severity: sniff.sev,
            _highlightText: b64.substring(0, Math.min(64, b64.length)),
            _sourceOffset: bareMatch.index,
            _sourceLength: Math.min(64, b64.length),
          });
          setRisk(sniff.sev);
        }
      } catch (_) { }
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
      // Strip ASCII whitespace/C0 controls so "\tjavascript:" and
      // "java\nscript:" can't bypass the scheme check — browsers strip
      // these when resolving the URL (js/incomplete-url-scheme-check #61).
      const normalized = lower.replace(/[\x00-\x20\x7f]/g, '');
      // Pre-filter: skip `data:image/*` before the broader `data:` check
      // below. image/* is the only data: subtype considered benign when
      // inlined into a document; everything else (text/html,
      // text/javascript, application/pdf;base64, application/octet-stream,
      // text/xml polyglots, …) is treated as high-severity. CodeQL's
      // js/incomplete-url-scheme-check requires the guard to match bare
      // `data:`, not a sub-MIME, to be considered complete.
      if (normalized.startsWith('data:image/')) continue;
      // eslint-disable-next-line no-script-url -- detecting, not navigating
      if (normalized.startsWith('javascript:') || normalized.startsWith('vbscript:') || normalized.startsWith('data:')) {

        sev = 'high';
        setRisk('high');
      } else if (normalized.startsWith('http:') || normalized.startsWith('https:') || normalized.startsWith('//')) {
        sev = 'medium';
        setRisk('medium');
      }
      refs.push({ type: IOC.URL, url, severity: sev, _highlightText: url });
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
          severity: 'medium',
          _highlightText: href,
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
          severity: 'high',
          _highlightText: toVal || attrName,
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
          severity: 'medium',
          _highlightText: href,
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
          severity: 'medium',
          _highlightText: href,
        });
        setRisk('medium');
      }
    }

    // ── 7. Entity/DTD references in raw text ─────────────────────────────
    const entityMatch = text.match(/<!ENTITY\s[^>]*>/i);
    if (entityMatch) {
      refs.push({
        type: IOC.PATTERN,
        url: 'XML entity declaration detected — potential XXE or obfuscation',
        severity: 'high',
        _highlightText: entityMatch[0],
        _sourceOffset: entityMatch.index,
        _sourceLength: entityMatch[0].length,
      });
      setRisk('high');
    }
    const dtdMatch = text.match(/<!DOCTYPE[^>]+SYSTEM\s[^>]*>/i);
    if (dtdMatch) {
      refs.push({
        type: IOC.PATTERN,
        url: 'DOCTYPE with SYSTEM reference — potential XXE',
        severity: 'high',
        _highlightText: dtdMatch[0],
        _sourceOffset: dtdMatch.index,
        _sourceLength: dtdMatch[0].length,
      });
      setRisk('high');
    }

    // ── 8. Obfuscation in raw text (catches entity-encoded JS) ───────────
    // Check for common obfuscation patterns outside of <script> tags.
    // Use a fixed-point strip with a tolerant closing tag so nested or
    // attribute-bearing `<\/script foo>` can't bypass the filter — a
    // single pass is flagged by CodeQL js/bad-tag-filter + js/incomplete-
    // multi-character-sanitization (#53, #59).
    const stripScriptRe = /<script[\s>][\s\S]*?<\/script\b[^>]*>/gi;
    let textWithoutScripts = text;
    let prevScriptStrip;
    do {
      prevScriptStrip = textWithoutScripts;
      textWithoutScripts = textWithoutScripts.replace(stripScriptRe, '');
    } while (textWithoutScripts !== prevScriptStrip);
    this._checkJsSuspicious(textWithoutScripts, refs, setRisk, true);

    // ── 8b. Forcepoint X-Labs obfuscation fingerprints ───────────────────
    // Runs across the entire SVG source (including <script> content) because
    // these loader patterns are often *inside* a script block.
    const obfuscationHits = [];
    for (const fp of SvgRenderer.OBFUSCATION_FINGERPRINTS) {
      for (const pat of fp.patterns) {
        pat.lastIndex = 0;
        const m = pat.exec(text);
        if (m) {
          obfuscationHits.push(fp.key);
          refs.push({
            type: IOC.PATTERN,
            url: `Obfuscation fingerprint [${fp.key}]: ${fp.label} — "${this._truncate(m[0], 80)}"`,
            severity: 'high',
            _highlightText: m[0],
            _sourceOffset: m.index,
            _sourceLength: m[0].length,
          });
          setRisk('high');
          break; // one hit per fingerprint category is enough
        }
      }
    }
    // Multiple independent obfuscation categories in one file is a strong
    // phishing-loader signal — escalate to critical.
    if (obfuscationHits.length >= 2) {
      refs.push({
        type: IOC.PATTERN,
        url: `Multi-layer obfuscation: ${obfuscationHits.length} distinct categories (${obfuscationHits.join(', ')}) — likely phishing loader`,
        severity: 'critical'
      });
      setRisk('critical');
    }

    // ── 9. Meta refresh / redirect in foreignObject ──────────────────────
    const metaRefreshRegex = /<meta[^>]+http-equiv\s*=\s*["']?refresh[^>]+content\s*=\s*["']?\d+;\s*url\s*=\s*([^"'\s>]+)/gi;
    let metaMatch;
    while ((metaMatch = metaRefreshRegex.exec(text)) !== null) {
      refs.push({
        type: IOC.URL,
        url: metaMatch[1],
        severity: 'high',
        _highlightText: metaMatch[1],
      });
      refs.push({
        type: IOC.PATTERN,
        url: `Meta refresh redirect to: ${metaMatch[1]}`,
        severity: 'high',
        _highlightText: metaMatch[0],
        _sourceOffset: metaMatch.index,
        _sourceLength: metaMatch[0].length,
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
    if (sniffedBlobTypes.length) metadata.sniffedBlobTypes = Array.from(new Set(sniffedBlobTypes));
    if (obfuscationHits.length) metadata.obfuscationFingerprints = obfuscationHits;

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

  /** Check JS content for suspicious patterns and push findings.
   *  When `rawText` is provided, we also try to pin the finding to an offset
   *  in the full source for click-to-highlight. */
  _checkJsSuspicious(content, refs, setRisk, dedup = false, rawText = null) {
    const seen = dedup ? new Set(refs.map(r => r.url)) : null;
    for (const { pattern, label } of SvgRenderer.JS_SUSPICIOUS) {
      pattern.lastIndex = 0;
      const m = pattern.exec(content);
      if (m) {
        const msg = `Suspicious JavaScript pattern: ${label}`;
        if (dedup && seen && seen.has(msg)) continue;
        if (dedup && seen) seen.add(msg);
        const ref = { type: IOC.PATTERN, url: msg, severity: 'high', _highlightText: m[0] };
        if (rawText) {
          const idx = rawText.indexOf(m[0]);
          if (idx >= 0) { ref._sourceOffset = idx; ref._sourceLength = m[0].length; }
        }
        refs.push(ref);
        setRisk('high');
      }
    }
  }

  /**
   * Decode the first ~64 bytes of a base64 string and sniff against MIME_SIGS.
   * Returns { type, sev } or null if no magic-byte match.
   * Silently returns null on invalid base64 / short decodes / image-noise.
   */
  _sniffBase64(b64) {
    if (!b64 || b64.length < 16) return null;
    // Trim to a safe prefix and pad to a multiple of 4 so atob() accepts it
    let prefix = b64.substring(0, 64).replace(/[^A-Za-z0-9+/]/g, '');
    while (prefix.length % 4 !== 0) prefix += '=';
    let decoded;
    try { decoded = atob(prefix); } catch (_) { return null; }
    if (decoded.length < 4) return null;
    const b0 = decoded.charCodeAt(0);
    const b1 = decoded.charCodeAt(1);
    const b2 = decoded.charCodeAt(2);
    const b3 = decoded.charCodeAt(3);
    for (const sig of SvgRenderer.MIME_SIGS) {
      const m = sig.magic;
      if (m.length === 2 && b0 === m[0] && b1 === m[1]) return sig;
      if (m.length === 3 && b0 === m[0] && b1 === m[1] && b2 === m[2]) return sig;
      if (m.length === 4 && b0 === m[0] && b1 === m[1] && b2 === m[2] && b3 === m[3]) return sig;
    }
    return null;
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
