'use strict';
// ════════════════════════════════════════════════════════════════════════════
// plaintext-renderer.js — Catch-all viewer for unsupported file types
// Shows plain text (with line numbers) or hex dump depending on content.
// Supports encoding auto-detection (UTF-8, UTF-16LE, UTF-16BE, Latin-1),
// a toggle between text / hex views, and a syntax-highlight on/off toggle
// persisted as `loupe_plaintext_highlight`.
//
// Minified-JS footgun: a single logical line can be multiple megabytes.
// This renderer splits absurdly long lines into display-only chunks so the
// browser does not choke on a single 2 MB <td>, and disables hljs for such
// files regardless of total size (hljs produces a gigantic span tree on one
// long line even if the byte total is modest).
// ════════════════════════════════════════════════════════════════════════════
class PlainTextRenderer {

  // Extensions treated as known script / config types for keyword highlighting
  static SCRIPT_EXTS = new Set([
    'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'ps1', 'psm1', 'psd1',
    'bat', 'cmd', 'sh', 'bash', 'py', 'rb', 'pl',
    'hta', 'htm', 'html', 'mht', 'mhtml', 'xhtml', 'svg',
    'xml', 'xsl', 'xslt', 'xaml',
    'reg', 'inf', 'ini', 'cfg', 'conf', 'yml', 'yaml', 'toml', 'json',
    'rtf', 'eml', 'ics', 'vcf', 'url', 'desktop', 'lnk',
    'sql', 'php', 'asp', 'aspx', 'jsp', 'cgi',
    'txt', 'log', 'md', 'csv', 'tsv',
  ]);

  // Supported encodings for the selector
  static ENCODINGS = [
    { value: 'utf-8',     label: 'UTF-8' },
    { value: 'utf-16le',  label: 'UTF-16LE' },
    { value: 'utf-16be',  label: 'UTF-16BE' },
    { value: 'latin1',    label: 'Latin-1 (ISO 8859-1)' },
  ];

  // Map file extensions to highlight.js language names
  static LANG_MAP = {
    // PowerShell
    'ps1': 'powershell', 'psm1': 'powershell', 'psd1': 'powershell',
    // VBScript / VBA
    'vbs': 'vbscript', 'vbe': 'vbscript',
    // JavaScript
    'js': 'javascript', 'jse': 'javascript', 'mjs': 'javascript',
    // Batch / CMD
    'bat': 'dos', 'cmd': 'dos',
    // Shell / Bash
    'sh': 'bash', 'bash': 'bash', 'zsh': 'bash',
    // Python
    'py': 'python', 'pyw': 'python',
    // Ruby / Perl / PHP
    'rb': 'ruby', 'pl': 'perl', 'php': 'php',
    // XML / HTML / SVG
    'xml': 'xml', 'html': 'xml', 'htm': 'xml', 'xhtml': 'xml',
    'svg': 'xml', 'xsl': 'xml', 'xslt': 'xml', 'xaml': 'xml',
    'mht': 'xml', 'mhtml': 'xml',
    // JSON
    'json': 'json',
    // YAML
    'yml': 'yaml', 'yaml': 'yaml',
    // Config / INI
    'ini': 'ini', 'cfg': 'ini', 'conf': 'ini', 'toml': 'ini',
    'reg': 'ini', 'inf': 'ini',
    // SQL
    'sql': 'sql',
    // CSS
    'css': 'css',
    // C-family
    'c': 'c', 'h': 'c',
    'cpp': 'cpp', 'cc': 'cpp', 'cxx': 'cpp', 'hpp': 'cpp', 'hxx': 'cpp',
    'cs': 'csharp',
    'java': 'java',
    'go': 'go',
    'rs': 'rust',
    'swift': 'swift',
    'kt': 'kotlin', 'kts': 'kotlin',
    // TypeScript
    'ts': 'typescript', 'tsx': 'typescript',
    // Markdown
    'md': 'markdown', 'markdown': 'markdown',
    // Makefile
    'makefile': 'makefile', 'mk': 'makefile',
    // Lua
    'lua': 'lua',
    // R
    'r': 'r',
    // Diff
    'diff': 'diff', 'patch': 'diff',
  };

  // Map MIME types to highlight.js language names (fallback when extension is unknown)
  static MIME_TO_LANG = {
    // JavaScript
    'text/javascript': 'javascript',
    'application/javascript': 'javascript',
    'application/x-javascript': 'javascript',
    'text/ecmascript': 'javascript',
    'application/ecmascript': 'javascript',
    // TypeScript
    'text/typescript': 'typescript',
    'application/typescript': 'typescript',
    // JSON
    'application/json': 'json',
    'text/json': 'json',
    // XML / HTML
    'text/xml': 'xml',
    'application/xml': 'xml',
    'text/html': 'xml',
    'application/xhtml+xml': 'xml',
    'image/svg+xml': 'xml',
    // CSS
    'text/css': 'css',
    // Python
    'text/x-python': 'python',
    'application/x-python': 'python',
    'text/x-python-script': 'python',
    // Shell / Bash
    'text/x-sh': 'bash',
    'application/x-sh': 'bash',
    'text/x-shellscript': 'bash',
    // PHP
    'text/x-php': 'php',
    'application/x-php': 'php',
    // Ruby
    'text/x-ruby': 'ruby',
    'application/x-ruby': 'ruby',
    // Perl
    'text/x-perl': 'perl',
    'application/x-perl': 'perl',
    // C / C++
    'text/x-c': 'c',
    'text/x-csrc': 'c',
    'text/x-c++': 'cpp',
    'text/x-c++src': 'cpp',
    // Java
    'text/x-java': 'java',
    'text/x-java-source': 'java',
    // C#
    'text/x-csharp': 'csharp',
    // YAML
    'text/yaml': 'yaml',
    'text/x-yaml': 'yaml',
    'application/x-yaml': 'yaml',
    // SQL
    'text/x-sql': 'sql',
    'application/sql': 'sql',
    // Markdown
    'text/markdown': 'markdown',
    'text/x-markdown': 'markdown',
  };

  // Size limit for syntax highlighting (100 KB total text)
  static HIGHLIGHT_SIZE_LIMIT = 100 * 1024;
  // Per-line length limit — above this hljs is disabled AND lines are
  // soft-wrapped into display-only chunks (minified-JS defence).
  static LONG_LINE_THRESHOLD = 5000;
  // Display-only chunk size for soft-wrap (characters).
  static SOFT_WRAP_CHUNK = 2000;
  // Hard cap on total lines rendered to the DOM.
  static MAX_LINES = RENDER_LIMITS.MAX_TEXT_LINES;
  // localStorage key for the syntax-highlight on/off toggle.
  static HIGHLIGHT_PREF_KEY = 'loupe_plaintext_highlight';

  // ── Preference accessors ────────────────────────────────────────────────

  /** Read the user's syntax-highlight preference (default: on). */
  static _readHighlightPref() {
    try {
      const v = localStorage.getItem(PlainTextRenderer.HIGHLIGHT_PREF_KEY);
      return v !== 'off';
    } catch (_) {
      return true;
    }
  }

  /** Persist the user's syntax-highlight preference. */
  static _writeHighlightPref(enabled) {
    try {
      localStorage.setItem(PlainTextRenderer.HIGHLIGHT_PREF_KEY, enabled ? 'on' : 'off');
    } catch (_) { /* quota / disabled — ignore */ }
  }

  // ── Render ──────────────────────────────────────────────────────────────

  render(buffer, fileName, mimeType) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const detected = this._detectEncoding(bytes);
    const isTextByDefault = detected.isText;
    // Store mimeType for language detection
    this._mimeType = mimeType || '';

    // Build wrapper that holds both views + controls
    const wrap = document.createElement('div');
    wrap.className = isTextByDefault ? 'plaintext-view' : 'hex-view';

    // Decode text using detected encoding — normalised to \n so downstream
    // consumers (sidebar click-to-focus offsets, YARA scan buffer, IOC
    // extraction) don't drift on CRLF files. See `.clinerules` gotcha.
    const decodedText = this._normalizeNewlines(this._decodeAs(bytes, detected.encoding));

    // Pre-compute whether syntax highlighting is *possible at all* for
    // this file. If it isn't — hljs missing, file too large, or a single
    // pathologically long line present — we omit the Highlight toggle
    // entirely rather than leaving a button that does nothing when
    // clicked. (The same gate is applied again inside `_buildTextPane`;
    // we duplicate the computation here so the info bar can decide
    // whether to render the control at all.)
    const highlightPossible = this._canHighlight(decodedText);

    // ── Info bar with toggle + encoding selector ──────────────────────
    const info = document.createElement('div');
    info.className = 'plaintext-info';

    const infoText = document.createElement('span');
    infoText.className = 'plaintext-info-text';
    // Info text will be updated after building textPane to include detected language
    if (!isTextByDefault) {
      infoText.textContent = `${this._fmtBytes(bytes.length)}  ·  Binary file  ·  Hex dump view`;
    }
    info.appendChild(infoText);

    // Spacer
    const spacer = document.createElement('span');
    spacer.style.flex = '1';
    info.appendChild(spacer);

    // Syntax-highlight toggle (persisted). Only rendered when
    // highlighting is actually possible for this file — otherwise the
    // button would be a no-op.
    let highlightEnabled = PlainTextRenderer._readHighlightPref();
    let hlLabel = null;
    let hlBtn = null;
    if (highlightPossible) {
      hlLabel = document.createElement('label');
      hlLabel.className = 'plaintext-enc-label';
      hlLabel.textContent = 'Highlight:';
      info.appendChild(hlLabel);

      hlBtn = document.createElement('button');
      hlBtn.className = 'plaintext-toggle-btn';
      hlBtn.textContent = highlightEnabled ? 'On' : 'Off';
      hlBtn.title = 'Toggle syntax highlighting (persisted)';
      info.appendChild(hlBtn);
    } else {
      // Force highlighting off for this render so `_buildTextPane`
      // doesn't waste time re-checking the same gate.
      highlightEnabled = false;
    }


    // Encoding selector
    const encLabel = document.createElement('label');
    encLabel.className = 'plaintext-enc-label';
    encLabel.textContent = 'Encoding:';
    info.appendChild(encLabel);

    const encSelect = document.createElement('select');
    encSelect.className = 'plaintext-enc-select';
    encSelect.title = 'Change text encoding';
    for (const enc of PlainTextRenderer.ENCODINGS) {
      const opt = document.createElement('option');
      opt.value = enc.value;
      opt.textContent = enc.label;
      if (enc.value === detected.encoding) opt.selected = true;
      encSelect.appendChild(opt);
    }
    info.appendChild(encSelect);

    // Text/Hex toggle button
    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'plaintext-toggle-btn';
    toggleBtn.textContent = isTextByDefault ? '⬡ Hex' : '🔡 Text';
    toggleBtn.title = isTextByDefault ? 'Switch to hex dump view' : 'Switch to plain text view';
    info.appendChild(toggleBtn);

    wrap.appendChild(info);

    // ── Content area ─────────────────────────────────────────────────────
    const contentArea = document.createElement('div');
    contentArea.className = 'plaintext-content-area';

    // Build both views
    const textPane = this._buildTextPane(decodedText, fileName, this._mimeType, highlightEnabled);
    const hexPane = this._buildHexPane(bytes, fileName);

    // Show the correct one by default
    textPane.style.display = isTextByDefault ? '' : 'none';
    hexPane.style.display = isTextByDefault ? 'none' : '';

    contentArea.appendChild(textPane);
    contentArea.appendChild(hexPane);
    wrap.appendChild(contentArea);

    // ── State tracking ───────────────────────────────────────────────────
    let showingText = isTextByDefault;
    let currentEncoding = detected.encoding;
    let currentText = decodedText;
    let detectedLang = textPane._detectedLang || null;

    // Update initial info text now that we have the detected language
    if (isTextByDefault) {
      this._updateInfoText(infoText, true, bytes, currentEncoding, detectedLang, textPane._lineCount);
    }

    // Store raw decoded text for analysis pipeline (IOC extraction, encoded content detection)
    wrap._rawText = lfNormalize(currentText);
    wrap._rawBytes = bytes;

    // Mutable reference to the current text pane (may be replaced on re-render)
    contentArea._textPane = textPane;

    // Rebuild helper — used by both encoding change and highlight toggle
    const rebuildTextPane = () => {
      const oldTextPane = contentArea._textPane;
      const newTextPane = this._buildTextPane(currentText, fileName, this._mimeType, highlightEnabled);
      newTextPane.style.display = oldTextPane.style.display;
      contentArea.replaceChild(newTextPane, oldTextPane);
      contentArea._textPane = newTextPane;
      detectedLang = newTextPane._detectedLang || null;
      this._updateInfoText(infoText, showingText, bytes, currentEncoding, detectedLang, newTextPane._lineCount);
    };

    // ── Toggle handler (text ⇄ hex) ──────────────────────────────────────
    toggleBtn.addEventListener('click', () => {
      showingText = !showingText;
      const currentTextPane = contentArea._textPane;
      currentTextPane.style.display = showingText ? '' : 'none';
      hexPane.style.display = showingText ? 'none' : '';
      toggleBtn.textContent = showingText ? '⬡ Hex' : '🔡 Text';
      toggleBtn.title = showingText ? 'Switch to hex dump view' : 'Switch to plain text view';
      wrap.className = showingText ? 'plaintext-view' : 'hex-view';
      // Show/hide encoding selector + highlight toggle (only relevant for text view).
      // hlLabel / hlBtn may be null when highlighting is impossible for this file.
      encLabel.style.display = showingText ? '' : 'none';
      encSelect.style.display = showingText ? '' : 'none';
      if (hlLabel) hlLabel.style.display = showingText ? '' : 'none';
      if (hlBtn) hlBtn.style.display = showingText ? '' : 'none';
      this._updateInfoText(infoText, showingText, bytes, currentEncoding, detectedLang, contentArea._textPane._lineCount);
    });

    // ── Encoding change handler ──────────────────────────────────────────
    encSelect.addEventListener('change', () => {
      currentEncoding = encSelect.value;
      currentText = this._normalizeNewlines(this._decodeAs(bytes, currentEncoding));
      wrap._rawText = lfNormalize(currentText);
      rebuildTextPane();
    });

    // ── Highlight toggle handler ─────────────────────────────────────────
    // Only wire up the handler when the button was actually rendered —
    // for files where highlighting is impossible (hljs missing, too
    // large, or containing a pathologically long line) the button is
    // omitted from the info bar entirely.
    if (hlBtn) {
      hlBtn.addEventListener('click', () => {
        highlightEnabled = !highlightEnabled;
        PlainTextRenderer._writeHighlightPref(highlightEnabled);
        hlBtn.textContent = highlightEnabled ? 'On' : 'Off';
        rebuildTextPane();
      });
    }

    return wrap;
  }

  // ── Security analysis ───────────────────────────────────────────────────

  analyzeForSecurity(buffer, fileName) {
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const detected = this._detectEncoding(bytes);

    if (!detected.isText) {
      // For binary files, note that this is an unsupported binary format
      f.externalRefs.push({
        type: IOC.INFO,
        url: `Binary file rendered as hex dump (.${ext})`,
        severity: 'info'
      });
    }

    // Pattern detection is handled entirely by YARA (auto-scan on file load)
    return f;
  }

  // ── Highlight feasibility ───────────────────────────────────────────────

  /**
   * Would calling hljs on `text` actually produce any highlighting right
   * now? Mirrors the gate inside `_buildTextPane` but operates on the
   * text only — used by `render()` to decide whether to render the
   * Highlight toggle at all. Three things can block highlighting:
   *   1. hljs isn't loaded in this build.
   *   2. The total text is over `HIGHLIGHT_SIZE_LIMIT` (hljs slows to a
   *      crawl on multi-hundred-KB inputs).
   *   3. A single line is over `LONG_LINE_THRESHOLD` — the hljs span
   *      tree for one multi-megabyte minified-JS line can freeze or
   *      OOM the tab regardless of total size.
   * When any of these holds we hide the button instead of leaving it
   * present but inert.
   */
  _canHighlight(text) {
    if (typeof hljs === 'undefined') return false;
    if (text.length >= PlainTextRenderer.HIGHLIGHT_SIZE_LIMIT) return false;
    // Walk lines until we either exceed the long-line threshold or run
    // out of text. Early-exit keeps this O(n) with a very small constant
    // for normal files.
    let runStart = 0;
    const limit = PlainTextRenderer.LONG_LINE_THRESHOLD;
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 0x0A /* \n */) {
        if (i - runStart > limit) return false;
        runStart = i + 1;
      }
    }
    if (text.length - runStart > limit) return false;
    return true;
  }

  // ── Encoding auto-detection ─────────────────────────────────────────────

  /**
   * Detect the most likely text encoding for the given bytes.
   * Returns { encoding: string, isText: boolean }
   */
  _detectEncoding(bytes) {
    if (bytes.length < 2) return { encoding: 'utf-8', isText: this._isTextContent(bytes, 'utf-8') };

    // Check for BOM markers
    if (bytes[0] === 0xFF && bytes[1] === 0xFE) {
      return { encoding: 'utf-16le', isText: true };
    }
    if (bytes[0] === 0xFE && bytes[1] === 0xFF) {
      return { encoding: 'utf-16be', isText: true };
    }
    if (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) {
      return { encoding: 'utf-8', isText: true };
    }

    // Heuristic: check for UTF-16LE pattern (every other byte is 0x00 for ASCII text)
    if (bytes.length >= 8) {
      const sampleLen = Math.min(64, bytes.length);
      // Must be even length for UTF-16
      if (sampleLen % 2 === 0 || bytes.length % 2 === 0) {
        let nullHighCount = 0;
        let nullLowCount = 0;
        const checkLen = Math.min(sampleLen, bytes.length) & ~1; // ensure even
        for (let i = 0; i < checkLen; i += 2) {
          if (bytes[i + 1] === 0x00 && bytes[i] >= 0x20 && bytes[i] <= 0x7E) nullHighCount++;
          if (bytes[i] === 0x00 && bytes[i + 1] >= 0x20 && bytes[i + 1] <= 0x7E) nullLowCount++;
        }
        const pairs = checkLen / 2;
        if (pairs > 0 && nullHighCount / pairs >= 0.6) {
          return { encoding: 'utf-16le', isText: true };
        }
        if (pairs > 0 && nullLowCount / pairs >= 0.6) {
          return { encoding: 'utf-16be', isText: true };
        }
      }
    }

    // Standard UTF-8 text check
    if (this._isTextContent(bytes, 'utf-8')) {
      return { encoding: 'utf-8', isText: true };
    }

    // Not clearly text — default to UTF-8 but mark as non-text (hex dump default)
    return { encoding: 'utf-8', isText: false };
  }

  // ── Text decoding ───────────────────────────────────────────────────────

  /**
   * Decode bytes using the given encoding.
   * Falls back gracefully to replacement characters on errors.
   */
  _decodeAs(bytes, encoding) {
    try {
      if (encoding === 'latin1') {
        // TextDecoder doesn't always support 'latin1', use 'iso-8859-1'
        return new TextDecoder('iso-8859-1', { fatal: false }).decode(bytes);
      }
      return new TextDecoder(encoding, { fatal: false }).decode(bytes);
    } catch (_) {
      // Ultimate fallback
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    }
  }

  /**
   * Normalise CRLF / CR to LF. Required because `_rawText` is used by the
   * sidebar click-to-focus highlighter which indexes by character offset —
   * CR bytes left in the buffer misalign every offset after the first one.
   */
  _normalizeNewlines(text) {
    return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  }

  // ── Build text pane (line-numbered view with syntax highlighting) ────────

  _buildTextPane(text, fileName, mimeType, highlightEnabled) {
    const lines = text.split('\n');

    // Detect any pathologically long line — common in minified JS, CSS, JSON.
    // If one is present we disable hljs (span tree would explode on a
    // single-line megabyte) regardless of the global size gate.
    let maxLineLen = 0;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].length > maxLineLen) maxLineLen = lines[i].length;
      if (maxLineLen > PlainTextRenderer.LONG_LINE_THRESHOLD) break;
    }
    const hasLongLine = maxLineLen > PlainTextRenderer.LONG_LINE_THRESHOLD;

    // Get file extension and determine language
    const ext = (fileName || '').split('.').pop().toLowerCase();
    // Try extension first, then fall back to MIME type
    let lang = PlainTextRenderer.LANG_MAP[ext];
    if (!lang && mimeType) {
      lang = PlainTextRenderer.MIME_TO_LANG[mimeType];
    }

    // Gate: hljs must be available AND user preference on AND text small
    // enough AND no pathologically long line present.
    const shouldHighlight = highlightEnabled &&
                            typeof hljs !== 'undefined' &&
                            text.length < PlainTextRenderer.HIGHLIGHT_SIZE_LIMIT &&
                            !hasLongLine;

    let highlightedLines = null;
    let detectedLang = null;

    if (shouldHighlight) {
      try {
        let result;
        if (lang) {
          // Known language — use specific highlighting
          result = hljs.highlight(text, { language: lang, ignoreIllegals: true });
          detectedLang = lang;
        } else {
          // Unknown — try auto-detection
          result = hljs.highlightAuto(text);
          detectedLang = result.language || null;
        }
        // Split highlighted HTML by lines
        highlightedLines = result.value.split('\n');
      } catch (_) {
        // Fallback to plain text on error
        highlightedLines = null;
      }
    } else if (lang) {
      // Not highlighting but still advertise the detected language
      detectedLang = lang;
    }

    const scr = document.createElement('div');
    scr.className = 'plaintext-scroll';

    const table = document.createElement('table');
    table.className = 'plaintext-table';

    const maxLines = PlainTextRenderer.MAX_LINES;
    const count = Math.min(lines.length, maxLines);
    const chunkSize = PlainTextRenderer.SOFT_WRAP_CHUNK;

    // Pre-size the line-number column via <colgroup>. `.plaintext-table`
    // uses `table-layout: fixed` (load-bearing defence against multi-
    // megabyte minified-JS lines blowing out the viewer width — see
    // viewers.css), which resolves column widths from the first row only.
    // Without an explicit width the gutter locks to the width of "1" in
    // row 1, and every subsequent multi-digit line number ("10", "100",
    // …) overflows past the gutter's `border-right`, producing a visual
    // "1|0" glitch. Reserving `<digits>ch + padding + border` up front
    // keeps all line numbers inside their cell.
    const gutterDigits = String(count).length;
    const colgroup = document.createElement('colgroup');
    const colLn   = document.createElement('col');
    const colCode = document.createElement('col');
    // padding-left (10px) + padding-right (12px) + border-right (1px) = 23px
    colLn.style.width = `calc(${gutterDigits}ch + 23px)`;
    colgroup.appendChild(colLn);
    colgroup.appendChild(colCode);
    table.appendChild(colgroup);

    // Logical-line → first-<tr>-index map. Soft-wrap produces multiple
    // <tr>s per logical line, so the sidebar's YARA/IOC/encoded-content
    // highlighter can no longer assume `rows[lineIndex]` is the right
    // row. We stash this map on the table so app-sidebar.js can translate
    // (logicalLine, charPos) → (rowIndex, charPosWithinChunk). When no
    // long line is present this stays a trivial 0,1,2,… map.
    const lineToFirstRow = new Array(count);

    for (let i = 0; i < count; i++) {
      const lineText = lines[i];
      lineToFirstRow[i] = table.rows.length;
      // Soft-wrap absurdly long lines into display-only chunks so the DOM
      // doesn't have to paint a single multi-megabyte <td>. The first
      // chunk gets the real line number; continuation chunks show a
      // dimmed ellipsis to signal the visual wrap.
      if (hasLongLine && lineText.length > chunkSize) {
        const chunks = Math.ceil(lineText.length / chunkSize);
        for (let c = 0; c < chunks; c++) {
          const tr = document.createElement('tr');
          const tdNum = document.createElement('td');
          tdNum.className = 'plaintext-ln';
          tdNum.textContent = c === 0 ? (i + 1) : '↳';
          const tdCode = document.createElement('td');
          tdCode.className = 'plaintext-code';
          tdCode.textContent = lineText.substr(c * chunkSize, chunkSize);
          tr.appendChild(tdNum);
          tr.appendChild(tdCode);
          table.appendChild(tr);
        }
        continue;
      }

      const tr = document.createElement('tr');
      const tdNum = document.createElement('td');
      tdNum.className = 'plaintext-ln';
      tdNum.textContent = i + 1;
      const tdCode = document.createElement('td');
      tdCode.className = 'plaintext-code';

      if (highlightedLines && highlightedLines[i] !== undefined) {
        // Use highlighted HTML
        tdCode.innerHTML = highlightedLines[i] || '';
      } else {
        // Plain text fallback
        tdCode.textContent = lineText;
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

    scr.appendChild(table);

    // Stash soft-wrap map + chunk size on the <table> itself so
    // app-sidebar.js (which finds the table via
    // `pc.querySelector('.plaintext-table')`) can translate
    // (logicalLineIndex, charPos) → (rowIndex, charPosWithinChunk) for
    // YARA / IOC / encoded-content highlighting in minified-JS files.
    table._lineToFirstRow = lineToFirstRow;
    table._chunkSize      = chunkSize;
    table._hasLongLine    = hasLongLine;

    // Stash metadata for the info bar (avoids re-decoding the whole buffer
    // in _updateInfoText just to recount lines).
    scr._detectedLang = detectedLang;
    scr._lineCount = lines.length;
    scr._hasLongLine = hasLongLine;

    return scr;
  }

  // ── Build hex pane ──────────────────────────────────────────────────────

  _buildHexPane(bytes, fileName) {
    const scr = document.createElement('div');
    scr.className = 'plaintext-scroll';

    const pre = document.createElement('pre');
    pre.className = 'hex-dump';

    const maxBytes = 64 * 1024; // 64 KB cap
    const cap = Math.min(bytes.length, maxBytes);
    const lines = [];

    for (let off = 0; off < cap; off += 16) {
      const hex = [];
      const ascii = [];
      for (let j = 0; j < 16; j++) {
        if (off + j < cap) {
          const b = bytes[off + j];
          hex.push(b.toString(16).padStart(2, '0'));
          ascii.push(b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.');
        } else {
          hex.push('  ');
          ascii.push(' ');
        }
      }
      const addr = off.toString(16).padStart(8, '0');
      lines.push(`${addr}  ${hex.slice(0, 8).join(' ')}  ${hex.slice(8).join(' ')}  |${ascii.join('')}|`);
    }
    if (bytes.length > maxBytes) {
      lines.push(`\n… truncated at ${maxBytes.toLocaleString()} bytes (file is ${bytes.length.toLocaleString()} bytes)`);
    }

    pre.textContent = lines.join('\n');
    scr.appendChild(pre);
    return scr;
  }

  // ── Update info text helper ─────────────────────────────────────────────

  _updateInfoText(infoText, showingText, bytes, encoding, detectedLang, cachedLineCount) {
    if (showingText) {
      // Use the cached line count from the current text pane to avoid
      // re-decoding the entire buffer on every toggle / encoding change.
      const lineCount = (typeof cachedLineCount === 'number')
        ? cachedLineCount
        : this._normalizeNewlines(this._decodeAs(bytes, encoding)).split('\n').length;
      const encLabel = PlainTextRenderer.ENCODINGS.find(e => e.value === encoding);
      const encName = encLabel ? encLabel.label : encoding;
      let info = `${lineCount} line${lineCount !== 1 ? 's' : ''}  ·  ${this._fmtBytes(bytes.length)}  ·  ${encName}`;
      if (detectedLang) {
        // Capitalize first letter and prettify language name
        const langDisplay = this._prettifyLangName(detectedLang);
        info += `  ·  ${langDisplay}`;
      }
      infoText.textContent = info;
    } else {
      infoText.textContent = `${this._fmtBytes(bytes.length)}  ·  Binary file  ·  Hex dump view`;
    }
  }

  /** Prettify highlight.js language name for display */
  _prettifyLangName(lang) {
    const nameMap = {
      'javascript': 'JavaScript',
      'typescript': 'TypeScript',
      'powershell': 'PowerShell',
      'vbscript': 'VBScript',
      'csharp': 'C#',
      'cpp': 'C++',
      'dos': 'Batch',
      'bash': 'Shell',
      'python': 'Python',
      'ruby': 'Ruby',
      'perl': 'Perl',
      'php': 'PHP',
      'java': 'Java',
      'kotlin': 'Kotlin',
      'swift': 'Swift',
      'go': 'Go',
      'rust': 'Rust',
      'sql': 'SQL',
      'css': 'CSS',
      'xml': 'XML/HTML',
      'json': 'JSON',
      'yaml': 'YAML',
      'ini': 'INI/Config',
      'markdown': 'Markdown',
      'makefile': 'Makefile',
      'lua': 'Lua',
      'r': 'R',
      'diff': 'Diff',
      'c': 'C',
    };
    return nameMap[lang] || (lang.charAt(0).toUpperCase() + lang.slice(1));
  }

  // ── Helpers ─────────────────────────────────────────────────────────────

  /** Heuristic: check if the first 8 KB is mostly printable in the given encoding. */
  _isTextContent(bytes, encoding) {
    if (!encoding || encoding === 'utf-8') {
      const sample = bytes.subarray(0, 8192);
      let printable = 0;
      for (let i = 0; i < sample.length; i++) {
        const b = sample[i];
        // Printable ASCII, common whitespace, or high bytes (UTF-8 continuation)
        if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d || b >= 0x80) {
          printable++;
        }
      }
      return sample.length > 0 && (printable / sample.length) >= 0.90;
    }
    // For other encodings, try decoding and check for control chars
    try {
      const text = this._decodeAs(bytes.subarray(0, 8192), encoding);
      const controlCount = [...text].filter(c => {
        const cp = c.codePointAt(0);
        return cp < 32 && cp !== 9 && cp !== 10 && cp !== 13;
      }).length;
      return text.length > 0 && (controlCount / text.length) < 0.10;
    } catch (_) {
      return false;
    }
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
