'use strict';
// ════════════════════════════════════════════════════════════════════════════
// plaintext-renderer.js — Catch-all viewer for unsupported file types
// Shows plain text (with line numbers) or hex dump depending on content.
// ════════════════════════════════════════════════════════════════════════════
class PlainTextRenderer {

  // Extensions treated as known script / config types for keyword highlighting
  static SCRIPT_EXTS = new Set([
    'vbs','vbe','js','jse','wsf','wsh','ps1','psm1','psd1',
    'bat','cmd','sh','bash','py','rb','pl',
    'hta','htm','html','mht','mhtml','xhtml','svg',
    'xml','xsl','xslt','xaml',
    'reg','inf','ini','cfg','conf','yml','yaml','toml','json',
    'rtf','eml','ics','vcf','url','desktop','lnk',
    'sql','php','asp','aspx','jsp','cgi',
    'txt','log','md','csv','tsv',
  ]);

  // Dangerous patterns by category (checked against full text)
  static DANGER_PATTERNS = [
    // Shell / script execution
    { rx: /\bWScript\.Shell\b/gi,         label: 'WScript.Shell', sev: 'high' },
    { rx: /\bCreateObject\b/gi,           label: 'CreateObject', sev: 'high' },
    { rx: /\bGetObject\b/gi,              label: 'GetObject', sev: 'medium' },
    { rx: /\bShell\s*\(/gi,              label: 'Shell()', sev: 'high' },
    { rx: /\bShellExecute\b/gi,           label: 'ShellExecute', sev: 'high' },
    { rx: /\bInvoke-Expression\b/gi,      label: 'Invoke-Expression (iex)', sev: 'high' },
    { rx: /\biex\s/gi,                    label: 'iex alias', sev: 'high' },
    { rx: /\bInvoke-WebRequest\b/gi,      label: 'Invoke-WebRequest', sev: 'medium' },
    { rx: /\bInvoke-RestMethod\b/gi,      label: 'Invoke-RestMethod', sev: 'medium' },
    { rx: /\bStart-Process\b/gi,          label: 'Start-Process', sev: 'high' },
    { rx: /\bNew-Object\b/gi,             label: 'New-Object', sev: 'medium' },
    { rx: /\bDownloadFile\b/gi,           label: 'DownloadFile', sev: 'high' },
    { rx: /\bDownloadString\b/gi,         label: 'DownloadString', sev: 'high' },
    { rx: /\bNet\.WebClient\b/gi,         label: 'Net.WebClient', sev: 'high' },
    { rx: /\bXMLHTTP\b/gi,               label: 'XMLHTTP', sev: 'high' },
    { rx: /\bMSXML2\b/gi,                label: 'MSXML2', sev: 'medium' },
    { rx: /\bADODB\.Stream\b/gi,          label: 'ADODB.Stream', sev: 'high' },
    { rx: /\bScripting\.FileSystemObject\b/gi, label: 'FileSystemObject', sev: 'high' },
    { rx: /powershell\s+.*-[Ee]nc/g,      label: 'powershell -enc (encoded command)', sev: 'high' },
    { rx: /\bcmd\s*\/[ck]\b/gi,           label: 'cmd /c or cmd /k', sev: 'medium' },
    { rx: /\bcertutil\b/gi,               label: 'certutil', sev: 'high' },
    { rx: /\bbitsadmin\b/gi,              label: 'bitsadmin', sev: 'high' },
    { rx: /\bmshta\b/gi,                  label: 'mshta', sev: 'high' },
    { rx: /\bregsvr32\b/gi,               label: 'regsvr32', sev: 'high' },
    { rx: /\brundll32\b/gi,               label: 'rundll32', sev: 'medium' },
    { rx: /\bcscript\b/gi,                label: 'cscript', sev: 'medium' },
    { rx: /\bwscript\b/gi,                label: 'wscript', sev: 'medium' },
    // HTML / HTA specific
    { rx: /<script[\s>]/gi,               label: '<script> tag', sev: 'medium' },
    { rx: /\bActiveXObject\b/gi,          label: 'ActiveXObject', sev: 'high' },
    { rx: /\bclsid:/gi,                   label: 'CLSID reference', sev: 'medium' },
    // RTF specific
    { rx: /\\objdata\b/gi,                label: 'RTF \\objdata (embedded OLE)', sev: 'high' },
    { rx: /\\objautlink\b/gi,             label: 'RTF \\objautlink (auto-link OLE)', sev: 'high' },
    { rx: /\\equation\b/gi,               label: 'RTF \\equation (equation editor — exploit vector)', sev: 'high' },
    { rx: /\\objocx\b/gi,                 label: 'RTF \\objocx (ActiveX control)', sev: 'high' },
    { rx: /\\objhtml\b/gi,                label: 'RTF \\objhtml (HTML object)', sev: 'medium' },
    // Base64 / encoding patterns
    { rx: /\b(?:FromBase64String|atob)\b/gi, label: 'Base64 decoding function', sev: 'medium' },
    { rx: /-[Ee](?:ncodedcommand|nc)\s+[A-Za-z0-9+\/=]{20,}/g, label: 'Encoded PowerShell payload', sev: 'high' },
  ];

  // ── Render ──────────────────────────────────────────────────────────────

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const isText = this._isTextContent(bytes);
    if (isText) return this._renderText(bytes, fileName);
    return this._renderHex(bytes, fileName);
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
    const isText = this._isTextContent(bytes);

    if (isText) {
      const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);

      // Dangerous-pattern scan (legacy patterns)
      for (const { rx, label, sev } of PlainTextRenderer.DANGER_PATTERNS) {
        const matches = text.match(rx);
        if (matches) {
          f.externalRefs.push({
            type: 'Suspicious Pattern',
            url: `${label} — ${matches.length} occurrence(s)`,
            severity: sev
          });
          if (sev === 'high') f.risk = 'high';
          else if (sev === 'medium' && f.risk !== 'high') f.risk = 'medium';
        }
      }

      // Threat signature scan
      const categories = ThreatScanner.getCategories(fileName);
      const sigMatches = ThreatScanner.scan(text, categories);
      f.signatureMatches = sigMatches;
      f.externalRefs.push(...ThreatScanner.toFindings(sigMatches));
      const threatLevel = ThreatScanner.computeThreatLevel(sigMatches);
      if (threatLevel.level === 'high') f.risk = 'high';
      else if (threatLevel.level === 'medium' && f.risk !== 'high') f.risk = 'medium';
    } else {
      // For binary files, note that this is an unsupported binary format
      f.externalRefs.push({
        type: 'Info',
        url: `Binary file rendered as hex dump (.${ext})`,
        severity: 'info'
      });

      // Threat signature scan on binary (latin-1 decoded)
      const categories = ThreatScanner.getCategories(fileName);
      const sigMatches = ThreatScanner.scanBuffer(buffer, categories);
      f.signatureMatches = sigMatches;
      f.externalRefs.push(...ThreatScanner.toFindings(sigMatches));
      const threatLevel = ThreatScanner.computeThreatLevel(sigMatches);
      if (threatLevel.level === 'high') f.risk = 'high';
      else if (threatLevel.level === 'medium' && f.risk !== 'high') f.risk = 'medium';
    }

    return f;
  }

  // ── Text rendering with line numbers ────────────────────────────────────

  _renderText(bytes, fileName) {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
    const ext = (fileName || '').split('.').pop().toLowerCase();

    const wrap = document.createElement('div');
    wrap.className = 'plaintext-view';

    // Info bar
    const info = document.createElement('div');
    info.className = 'plaintext-info';
    info.textContent = `${lines.length} line${lines.length !== 1 ? 's' : ''}  ·  ${this._fmtBytes(bytes.length)}  ·  Plain text view`;
    wrap.appendChild(info);

    // Code block with line numbers
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
    wrap.appendChild(scr);
    return wrap;
  }

  // ── Hex dump rendering ──────────────────────────────────────────────────

  _renderHex(bytes, fileName) {
    const wrap = document.createElement('div');
    wrap.className = 'hex-view';

    const info = document.createElement('div');
    info.className = 'plaintext-info';
    info.textContent = `${this._fmtBytes(bytes.length)}  ·  Binary file  ·  Hex dump view`;
    wrap.appendChild(info);

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
      lines.push(`${addr}  ${hex.slice(0,8).join(' ')}  ${hex.slice(8).join(' ')}  |${ascii.join('')}|`);
    }
    if (bytes.length > maxBytes) {
      lines.push(`\n… truncated at ${maxBytes.toLocaleString()} bytes (file is ${bytes.length.toLocaleString()} bytes)`);
    }

    pre.textContent = lines.join('\n');
    scr.appendChild(pre);
    wrap.appendChild(scr);
    return wrap;
  }

  // ── Helpers ─────────────────────────────────────────────────────────────

  /** Heuristic: check if the first 8 KB is mostly printable UTF-8. */
  _isTextContent(bytes) {
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

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
