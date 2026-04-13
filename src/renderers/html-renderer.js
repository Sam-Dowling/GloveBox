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

    const blob = new Blob([text], { type: 'text/html' });
    const blobUrl = URL.createObjectURL(blob);

    const iframe = document.createElement('iframe');
    iframe.className = 'html-iframe';
    // Most restrictive sandbox: no scripts, no forms, no popups, unique origin
    iframe.sandbox = '';
    iframe.src = blobUrl;
    iframe.title = 'Sandboxed HTML preview';
    // Clean up blob URL after load
    iframe.addEventListener('load', () => { URL.revokeObjectURL(blobUrl); }, { once: true });

    // ── Drag shield ──────────────────────────────────────────────────────
    // Transparent overlay above the iframe. Inactive by default (pointer-events:
    // none in CSS) so wheel/touch scrolling passes through naturally. Activated
    // only during drag operations to intercept file drops.
    const dragShield = document.createElement('div');
    dragShield.className = 'html-drag-shield';

    // ── Conditional drag shield activation ──────────────────────────────
    // Activate shield when a drag operation enters the document, deactivate
    // when drag ends or files are dropped.
    const activateShield = () => dragShield.classList.add('active');
    const deactivateShield = () => dragShield.classList.remove('active');

    document.addEventListener('dragenter', activateShield);
    document.addEventListener('drop', deactivateShield);
    document.addEventListener('dragend', deactivateShield);

    // ── Drag event handlers (active when shield is enabled) ─────────────
    // Capture drag events and dispatch custom events for GloveBox app handling
    dragShield.addEventListener('dragenter', e => {
      e.preventDefault();
      e.stopPropagation();
      window.dispatchEvent(new CustomEvent('glovebox-dragenter'));
    });

    dragShield.addEventListener('dragover', e => {
      e.preventDefault();
      e.stopPropagation();
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
    });

    dragShield.addEventListener('dragleave', e => {
      e.preventDefault();
      e.stopPropagation();
      window.dispatchEvent(new CustomEvent('glovebox-dragleave'));
    });

    dragShield.addEventListener('drop', e => {
      e.preventDefault();
      e.stopPropagation();
      deactivateShield();
      if (e.dataTransfer?.files?.length) {
        window.dispatchEvent(new CustomEvent('glovebox-drop', {
          detail: { files: e.dataTransfer.files }
        }));
      }
    });

    previewPane.appendChild(iframe);
    previewPane.appendChild(dragShield);
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

    // ── 1. DOM-aware URL extraction ──────────────────────────────────────
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
