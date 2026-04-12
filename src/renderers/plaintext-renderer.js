'use strict';
// ════════════════════════════════════════════════════════════════════════════
// plaintext-renderer.js — Catch-all viewer for unsupported file types
// Shows plain text (with line numbers) or hex dump depending on content.
// Supports encoding auto-detection (UTF-8, UTF-16LE, UTF-16BE, Latin-1)
// and a toggle between text / hex views.
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

  // ── Render ──────────────────────────────────────────────────────────────

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const detected = this._detectEncoding(bytes);
    const isTextByDefault = detected.isText;

    // Build wrapper that holds both views + controls
    const wrap = document.createElement('div');
    wrap.className = isTextByDefault ? 'plaintext-view' : 'hex-view';

    // Decode text using detected encoding
    const decodedText = this._decodeAs(bytes, detected.encoding);

    // ── Info bar with toggle + encoding selector ──────────────────────
    const info = document.createElement('div');
    info.className = 'plaintext-info';

    const infoText = document.createElement('span');
    infoText.className = 'plaintext-info-text';
    if (isTextByDefault) {
      const lines = decodedText.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
      infoText.textContent = `${lines.length} line${lines.length !== 1 ? 's' : ''}  ·  ${this._fmtBytes(bytes.length)}  ·  Plain text view`;
    } else {
      infoText.textContent = `${this._fmtBytes(bytes.length)}  ·  Binary file  ·  Hex dump view`;
    }
    info.appendChild(infoText);

    // Spacer
    const spacer = document.createElement('span');
    spacer.style.flex = '1';
    info.appendChild(spacer);

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

    // Toggle button
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
    const textPane = this._buildTextPane(decodedText, fileName);
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

    // Store raw decoded text for analysis pipeline (IOC extraction, encoded content detection)
    wrap._rawText = decodedText;
    wrap._rawBytes = bytes;

    // Mutable reference to the current text pane (may be replaced on encoding change)
    contentArea._textPane = textPane;

    // ── Toggle handler ───────────────────────────────────────────────────
    toggleBtn.addEventListener('click', () => {
      showingText = !showingText;
      const currentTextPane = contentArea._textPane;
      currentTextPane.style.display = showingText ? '' : 'none';
      hexPane.style.display = showingText ? 'none' : '';
      toggleBtn.textContent = showingText ? '⬡ Hex' : '🔡 Text';
      toggleBtn.title = showingText ? 'Switch to hex dump view' : 'Switch to plain text view';
      wrap.className = showingText ? 'plaintext-view' : 'hex-view';
      // Show/hide encoding selector (only relevant for text view)
      encLabel.style.display = showingText ? '' : 'none';
      encSelect.style.display = showingText ? '' : 'none';
      this._updateInfoText(infoText, showingText, bytes, currentEncoding);
    });

    // ── Encoding change handler ──────────────────────────────────────────
    encSelect.addEventListener('change', () => {
      currentEncoding = encSelect.value;
      const newText = this._decodeAs(bytes, currentEncoding);
      const oldTextPane = contentArea._textPane;
      const newTextPane = this._buildTextPane(newText, fileName);
      newTextPane.style.display = oldTextPane.style.display;
      contentArea.replaceChild(newTextPane, oldTextPane);
      contentArea._textPane = newTextPane;
      wrap._rawText = newText;
      this._updateInfoText(infoText, showingText, bytes, currentEncoding);
    });

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

  // ── Build text pane (line-numbered view) ────────────────────────────────

  _buildTextPane(text, fileName) {
    const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');

    const scr = document.createElement('div');
    scr.className = 'plaintext-scroll';

    const table = document.createElement('table');
    table.className = 'plaintext-table';

    const maxLines = 50000;
    const count = Math.min(lines.length, maxLines);
    for (let i = 0; i < count; i++) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td');
      tdNum.className = 'plaintext-ln';
      tdNum.textContent = i + 1;
      const tdCode = document.createElement('td');
      tdCode.className = 'plaintext-code';
      tdCode.textContent = lines[i];
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

  _updateInfoText(infoText, showingText, bytes, encoding) {
    if (showingText) {
      const text = this._decodeAs(bytes, encoding);
      const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
      const encLabel = PlainTextRenderer.ENCODINGS.find(e => e.value === encoding);
      const encName = encLabel ? encLabel.label : encoding;
      infoText.textContent = `${lines.length} line${lines.length !== 1 ? 's' : ''}  ·  ${this._fmtBytes(bytes.length)}  ·  Plain text view  ·  ${encName}`;
    } else {
      infoText.textContent = `${this._fmtBytes(bytes.length)}  ·  Binary file  ·  Hex dump view`;
    }
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
