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
    // The iframe + drag/scroll/drop shield are produced by the shared
    // `SandboxPreview` helper. The sandbox is
    // `allow-same-origin` so we can forward scroll deltas to the
    // iframe's contentWindow programmatically, but the inner CSP
    // (default in `SandboxPreview.DEFAULT_INNER_CSP` —
    // `default-src 'none'; style-src 'unsafe-inline'; img-src data:`)
    // still blocks scripts, network, fonts, and objects regardless of
    // what the file declares. The shield re-dispatches drag/drop as
    // `loupe-*` CustomEvents so files dropped on the preview open in
    // Loupe instead of being navigated to by the browser
    // (`app-core.js` listens). Convention: append iframe first, then
    // shield, both into a `position:relative` wrapper.
    const previewPane = document.createElement('div');
    previewPane.className = 'html-preview-pane';

    const { iframe, dragShield } = SandboxPreview.create({
      html: text,
      wrap: false,
      iframeClassName: 'html-iframe',
      shieldClassName: 'html-drag-shield',
      title: 'Sandboxed HTML preview',
      forwardScroll: true,
      forwardTouchScroll: true,
      forwardDragDrop: true,
    });

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

    const normalizedText = lfNormalize(text);
    const lines = normalizedText.split('\n');
    const maxLines = RENDER_LIMITS.MAX_TEXT_LINES;
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
    container._rawText = lfNormalize(text);
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

    // Length cap — DOM-text scans below run unbounded `matchAll` and
    // `test()` over the raw HTML; cap at 5 MB to avoid the worst case
    // on a giant inlined Base64 blob or a multi-MB single-page-app
    // bundle. Mirrors the parser-limits pattern in `src/constants.js`.
    const SCAN_CAP = 5 * 1024 * 1024;
    const scanText = text.length > SCAN_CAP ? text.slice(0, SCAN_CAP) : text;
    if (text.length > SCAN_CAP) {
      refs.push({
        type: IOC.PATTERN,
        url: `HTML body >${(SCAN_CAP / (1024 * 1024)).toFixed(0)} MB — security scan truncated`,
        severity: 'info'
      });
    }

    // ── 1. DOM-aware URL extraction ──────────────────────────────────────
    const domInfo = this._extractDomContent(scanText);

    for (const url of domInfo.urls) {
      let sev = 'info';
      const lower = url.toLowerCase();
      // Normalise by stripping ASCII whitespace and C0 controls before
      // scheme matching — browsers strip these when resolving a URL, so
      // "\tjavascript:" and "java\nscript:" both resolve to javascript:
      // (see CodeQL js/incomplete-url-scheme-check #60).
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
        if (risk !== 'high') risk = 'high';
      } else if (normalized.startsWith('http:') || normalized.startsWith('https:')) {
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
        // T3.1: Cross-origin form with password field
        const action = form.action || '';
        let isCrossOrigin = false;
        if (action && /^https?:\/\//i.test(action)) {
          isCrossOrigin = true;
        } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(action)) {
          isCrossOrigin = true;
        }
        refs.push({
          type: IOC.PATTERN,
          url: isCrossOrigin
            ? `Cross-origin form with password field → action="${action.slice(0, 120)}" — likely credential phishing`
            : `Form with password field → action="${action || '(same page)'}"`,
          severity: isCrossOrigin ? 'critical' : 'high'
        });
        risk = 'high';
      }
    }

    // ── 2a. ClickFix / fake-captcha detection (T3.2) ────────────────────
    {
      const hasClipboard = /navigator\.clipboard\.writetext|document\.execcommand\s*\(\s*['"]copy|clipboarddata/i.test(scanText);
      const hasPayload = /powershell|mshta|cmd\s*\/c|cmd\.exe|regsvr32|certutil|bitsadmin|wscript|cscript/i.test(scanText);
      const hasInstruction = /press\s+win\s*\+\s*r|win\+r|ctrl\s*\+\s*v|paste|verify\s+you\s+are\s+human|captcha|i\s*'?\s*m\s+not\s+a\s+robot|click\s+to\s+verify/i.test(scanText);
      if (hasClipboard && (hasPayload || hasInstruction)) {
        refs.push({
          type: IOC.PATTERN,
          url: 'ClickFix / fake-captcha pattern — instructs user to paste malicious command (T1204.001)',
          severity: 'critical'
        });
        risk = 'high';
      } else if (hasClipboard && /base64|atob|fromcharcode/i.test(scanText)) {
        refs.push({
          type: IOC.PATTERN,
          url: 'Clipboard write with encoded content — possible ClickFix variant',
          severity: 'high'
        });
        risk = 'high';
      }
    }

    // ── 2b. Data-URI iframe/embed/object/img smuggling (T3.3) ───────────
    // Combined alternation — single text walk instead of two separate
    // `matchAll` passes. The capture groups disambiguate which branch
    // hit so we can report the right tag in the finding.
    {
      const dataUriRE = /<(iframe|embed|object)\b[^>]+src\s*=\s*["']?\s*data:(?!image\/)|<(img)\b[^>]+src\s*=\s*["']?\s*data:text\/html/gi;
      for (const m of scanText.matchAll(dataUriRE)) {
        const tag = m[1] || m[2];
        const isImg = tag === 'img';
        refs.push({
          type: IOC.PATTERN,
          url: isImg
            ? 'Data-URI <img> with text/html MIME — HTML smuggling technique'
            : `Data-URI <${tag}> — HTML smuggling technique`,
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
    const titleMatch = text.match(/<title[^>]*>([\s\S]*?)<\/title\b[^>]*>/i);
    if (titleMatch) {
      // Fixed-point tag strip — a single pass can be bypassed by fragments
      // like "<img" with no closing ">" because the regex is greedy up to
      // the next ">" (js/incomplete-multi-character-sanitization #52).
      let stripped = titleMatch[1];
      let prev;
      do { prev = stripped; stripped = stripped.replace(/<[^>]*>/g, ''); } while (stripped !== prev);
      metadata.title = stripped.trim().slice(0, 200);
    }


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
