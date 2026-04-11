'use strict';
// ════════════════════════════════════════════════════════════════════════════
// html-renderer.js — Sandboxed HTML preview with DOM-aware security analysis
// Renders HTML files in an iframe sandbox (no scripts/forms/popups) and
// extracts all URLs/text from the parsed DOM for comprehensive scanning.
// ════════════════════════════════════════════════════════════════════════════

class HtmlRenderer {

  // URL-bearing attributes to extract from parsed DOM
  static URL_ATTRS = ['href','src','action','formaction','data','poster','background','cite','codebase','longdesc','usemap'];

  // HTML-specific security patterns
  static HTML_PATTERNS = [
    { rx: /<script[\s>]/gi,                   label: '<script> tag', sev: 'high' },
    { rx: /\bon\w+\s*=/gi,                    label: 'Inline event handler', sev: 'high' },
    { rx: /<iframe[\s>]/gi,                   label: '<iframe> tag', sev: 'high' },
    { rx: /<object[\s>]/gi,                   label: '<object> tag', sev: 'high' },
    { rx: /<embed[\s>]/gi,                    label: '<embed> tag', sev: 'high' },
    { rx: /<form[\s>]/gi,                     label: '<form> tag', sev: 'medium' },
    { rx: /type\s*=\s*["']?password/gi,       label: 'Password input field', sev: 'high' },
    { rx: /document\.cookie/gi,               label: 'document.cookie access', sev: 'high' },
    { rx: /window\.location/gi,               label: 'window.location redirect', sev: 'high' },
    { rx: /\.submit\s*\(/gi,                  label: 'Form auto-submit', sev: 'high' },
    { rx: /eval\s*\(/gi,                      label: 'eval() call', sev: 'high' },
    { rx: /document\.write/gi,                label: 'document.write', sev: 'medium' },
    { rx: /atob\s*\(/gi,                      label: 'Base64 decode (atob)', sev: 'medium' },
    { rx: /unescape\s*\(/gi,                  label: 'unescape() obfuscation', sev: 'medium' },
    { rx: /String\.fromCharCode/gi,           label: 'String.fromCharCode obfuscation', sev: 'medium' },
    { rx: /<meta[^>]+refresh/gi,              label: 'Meta refresh redirect', sev: 'medium' },
    { rx: /<base\s+href/gi,                   label: '<base href> tag', sev: 'medium' },
    { rx: /javascript\s*:/gi,                 label: 'javascript: URI', sev: 'high' },
    { rx: /data\s*:\s*text\/html/gi,          label: 'data: HTML URI', sev: 'high' },
    { rx: /vbscript\s*:/gi,                   label: 'vbscript: URI', sev: 'high' },
  ];

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

    const warning = document.createElement('span');
    warning.className = 'html-sandbox-badge';
    warning.textContent = '🔒 Sandboxed — scripts, forms & external resources blocked';

    toolbar.appendChild(previewBtn);
    toolbar.appendChild(sourceBtn);
    toolbar.appendChild(warning);
    container.appendChild(toolbar);

    // ── Preview pane (sandboxed iframe) ──────────────────────────────────
    const previewPane = document.createElement('div');
    previewPane.className = 'html-preview-pane';

    const blob = new Blob([text], { type: 'text/html' });
    const blobUrl = URL.createObjectURL(blob);

    const iframe = document.createElement('iframe');
    iframe.className = 'html-iframe';
    iframe.sandbox = ''; // Most restrictive: no scripts, no forms, no popups, unique origin
    iframe.src = blobUrl;
    iframe.title = 'Sandboxed HTML preview';
    // Clean up blob URL after load
    iframe.addEventListener('load', () => { URL.revokeObjectURL(blobUrl); }, { once: true });

    previewPane.appendChild(iframe);
    container.appendChild(previewPane);

    // ── Source pane (line-numbered) ──────────────────────────────────────
    const sourcePane = document.createElement('div');
    sourcePane.className = 'html-source-pane hidden';

    const lines = text.split('\n');
    const maxLines = 100000;
    const pre = document.createElement('pre');
    pre.className = 'plaintext-code';
    const gutter = document.createElement('span');
    gutter.className = 'line-gutter';
    const code = document.createElement('span');
    code.className = 'line-code';
    const lineCount = Math.min(lines.length, maxLines);
    const gutterLines = [];
    const codeLines = [];
    for (let i = 0; i < lineCount; i++) {
      gutterLines.push(String(i + 1));
      codeLines.push(this._escHtml(lines[i]));
    }
    if (lines.length > maxLines) {
      codeLines.push(`\n… truncated (${lines.length - maxLines} more lines)`);
    }
    gutter.textContent = gutterLines.join('\n');
    code.innerHTML = codeLines.join('\n');
    pre.appendChild(gutter);
    pre.appendChild(code);
    sourcePane.appendChild(pre);
    container.appendChild(sourcePane);

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

    // ── 1. HTML-specific pattern scanning ────────────────────────────────
    for (const pat of HtmlRenderer.HTML_PATTERNS) {
      const matches = text.match(pat.rx);
      if (matches) {
        refs.push({
          type: 'HTML Pattern',
          url: `${pat.label} (${matches.length} occurrence${matches.length > 1 ? 's' : ''})`,
          severity: pat.sev
        });
        if (pat.sev === 'high') risk = 'high';
        else if (pat.sev === 'medium' && risk === 'low') risk = 'medium';
      }
    }

    // ── 2. DOM-aware URL extraction ──────────────────────────────────────
    const domInfo = this._extractDomContent(text);

    for (const url of domInfo.urls) {
      let sev = 'info';
      const lower = url.toLowerCase();
      if (lower.startsWith('javascript:') || lower.startsWith('vbscript:') || lower.startsWith('data:text/html')) {
        sev = 'high';
        if (risk !== 'high') risk = 'high';
      } else if (lower.startsWith('http:') || lower.startsWith('https:')) {
        sev = 'medium';
        if (risk === 'low') risk = 'medium';
      }
      refs.push({
        type: 'URL',
        url: url,
        severity: sev
      });
    }

    // ── 3. Form credential harvesting detection ─────────────────────────
    for (const form of domInfo.forms) {
      if (form.hasPassword) {
        refs.push({
          type: 'Credential Harvest',
          url: `Form with password field → action="${form.action || '(same page)'}"`,
          severity: 'high'
        });
        risk = 'high';
      }
    }

    // ── 4. PlainTextRenderer danger patterns ─────────────────────────────
    if (typeof PlainTextRenderer !== 'undefined' && PlainTextRenderer.DANGER_PATTERNS) {
      for (const pat of PlainTextRenderer.DANGER_PATTERNS) {
        const matches = text.match(pat.rx);
        if (matches && !refs.some(r => r.url.includes(pat.label))) {
          refs.push({
            type: 'Pattern',
            url: `${pat.label} (${matches.length}×)`,
            severity: pat.sev
          });
          if (pat.sev === 'high' && risk !== 'high') risk = 'high';
          else if (pat.sev === 'medium' && risk === 'low') risk = 'medium';
        }
      }
    }

    // ── 5. ThreatScanner integration ─────────────────────────────────────
    let signatureMatches = [];
    if (typeof ThreatScanner !== 'undefined') {
      const cats = ['javascript', 'general_obfuscation'];
      signatureMatches = ThreatScanner.scan(text, cats);
      if (signatureMatches.length) {
        const level = ThreatScanner.computeThreatLevel(signatureMatches);
        if (level === 'high') risk = 'high';
        else if (level === 'medium' && risk === 'low') risk = 'medium';
        const sigFindings = ThreatScanner.toFindings(signatureMatches);
        refs.push(...sigFindings);
      }
    }

    // ── 6. Build augmented buffer (raw + DOM text + extracted URLs) ──────
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

    // ── 7. Metadata extraction ───────────────────────────────────────────
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
      signatureMatches,
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
    } catch (_) {}
    // Fallback to latin-1
    const chunks = [];
    const CHUNK = 512 * 1024;
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
