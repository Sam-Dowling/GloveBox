'use strict';
// ════════════════════════════════════════════════════════════════════════════
// rtf-renderer.js — RTF analysis: text extraction, OLE object detection,
//                   exploit pattern scanning
// Depends on: constants.js (IOC, escHtml)
// ════════════════════════════════════════════════════════════════════════════
class RtfRenderer {

  // RTF control words that indicate embedded OLE objects
  static OLE_KEYWORDS = [
    { kw: '\\objdata', label: '\\objdata — embedded OLE data', sev: 'high' },
    { kw: '\\objocx', label: '\\objocx — ActiveX OLE control', sev: 'high' },
    { kw: '\\objemb', label: '\\objemb — embedded OLE object', sev: 'high' },
    { kw: '\\objautlink', label: '\\objautlink — auto-link OLE', sev: 'high' },
    { kw: '\\objhtml', label: '\\objhtml — HTML OLE object', sev: 'medium' },
    { kw: '\\objlink', label: '\\objlink — linked OLE object', sev: 'medium' },
    { kw: '\\objupdate', label: '\\objupdate — auto-update OLE', sev: 'high' },
    { kw: '\\objclass', label: '\\objclass — OLE class specified', sev: 'medium' },
  ];

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('latin1').decode(bytes);
    const wrap = document.createElement('div'); wrap.className = 'rtf-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>RTF Analysis Mode</strong> — text extracted from Rich Text Format.';
    wrap.appendChild(banner);

    // Extract readable text
    const readable = this._extractText(text);

    // OLE object summary
    const oleFindings = this._findOleObjects(text);
    if (oleFindings.length) {
      const oleDiv = document.createElement('div'); oleDiv.className = 'rtf-ole-section';
      const oleH = document.createElement('h3'); oleH.textContent = `⚠ ${oleFindings.length} Embedded Object(s) Detected`;
      oleH.style.cssText = 'color:var(--risk-high);margin:0 0 8px 0'; oleDiv.appendChild(oleH);
      for (const o of oleFindings) {
        const item = document.createElement('div'); item.className = `rtf-ole-item rtf-ole-${o.sev}`;
        item.textContent = o.label; oleDiv.appendChild(item);
      }
      wrap.appendChild(oleDiv);
    }

    // Extracted text display
    const lines = readable.split('\n');
    const info = document.createElement('div'); info.className = 'plaintext-info';
    info.textContent = `${lines.length} line${lines.length !== 1 ? 's' : ''} extracted  ·  ${this._fmtBytes(bytes.length)} raw  ·  RTF analysis view`;
    wrap.appendChild(info);

    const scr = document.createElement('div'); scr.className = 'plaintext-scroll';
    const table = document.createElement('table'); table.className = 'plaintext-table';
    const maxLines = RENDER_LIMITS.MAX_TEXT_LINES;
    const count = Math.min(lines.length, maxLines);
    for (let i = 0; i < count; i++) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td'); tdNum.className = 'plaintext-ln'; tdNum.textContent = i + 1;
      const tdCode = document.createElement('td'); tdCode.className = 'plaintext-code'; tdCode.textContent = lines[i];
      tr.appendChild(tdNum); tr.appendChild(tdCode); table.appendChild(tr);
    }
    if (lines.length > maxLines) {
      const tr = document.createElement('tr'); const td = document.createElement('td');
      td.colSpan = 2; td.className = 'plaintext-truncated';
      td.textContent = `… truncated (${lines.length - maxLines} more lines)`;
      tr.appendChild(td); table.appendChild(tr);
    }
    scr.appendChild(table); wrap.appendChild(scr);

    // Raw RTF section (collapsed)
    const details = document.createElement('details'); details.className = 'rtf-raw-details';
    const summary = document.createElement('summary'); summary.textContent = 'Show Raw RTF Source';
    details.appendChild(summary);
    const rawPre = document.createElement('pre'); rawPre.className = 'rtf-raw-source';
    rawPre.textContent = text.length > 200000 ? text.slice(0, 200000) + '\n… truncated' : text;
    details.appendChild(rawPre); wrap.appendChild(details);

    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('latin1').decode(bytes);

    // OLE object detection
    const oleFindings = this._findOleObjects(text);
    for (const o of oleFindings) {
      f.externalRefs.push({ type: IOC.PATTERN, url: o.label, severity: o.sev });
      if (o.sev === 'high') escalateRisk(f, 'high');
      else if (o.sev === 'medium' && f.risk !== 'high') escalateRisk(f, 'medium');
    }

    // ── T2.8: objclass value extraction and classification ──────────────
    const objclassRE = /\\objclass\s+([^}\s\\]+)/gi;
    const exploitClasses = {
      'equation.3':        { family: 'Equation Editor (CVE-2017-11882 family)', sev: 'critical' },
      'equation.dsmt4':    { family: 'Equation Editor (CVE-2017-11882 family)', sev: 'critical' },
      'ole2link':          { family: 'OLE2Link remote template (CVE-2017-0199)', sev: 'critical' },
      'package':           { family: 'OLE Package — may contain embedded executable', sev: 'high' },
      'htmlfile':          { family: 'HTML smuggling via OLE', sev: 'high' },
      'msforms.htmlfile':  { family: 'HTML smuggling via OLE (MSForms)', sev: 'high' },
    };
    for (const m of text.matchAll(objclassRE)) {
      const cls = m[1].toLowerCase();
      const info = exploitClasses[cls];
      if (info) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `\\objclass "${m[1]}" — ${info.family}`,
          severity: info.sev
        });
        if (info.sev === 'critical') escalateRisk(f, 'high');
        else if (f.risk === 'low') escalateRisk(f, 'medium');
      }
    }

    // ── T2.9: Nested object depth counting ──────────────────────────────
    const objCount = (text.match(/\{\\object\b/gi) || []).length;
    if (objCount > 2) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `Multiple nested OLE objects detected (${objCount} objects) — possible parser-confusion evasion`,
        severity: 'high'
      });
      escalateRisk(f, 'high');
    }
    // Detect RTF-within-RTF (nested {\rtf1)
    const rtfHeads = (text.match(/\{\\rtf1\b/gi) || []).length;
    if (rtfHeads > 1) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `Nested RTF document detected (${rtfHeads} \\rtf1 headers) — RTF-within-RTF evasion technique`,
        severity: 'high'
      });
      escalateRisk(f, 'high');
    }

    // Structural: hex obfuscation analysis
    const hexEscapes = (text.match(/\\'[0-9a-fA-F]{2}/g) || []).length;
    if (hexEscapes > 500) {
      f.externalRefs.push({ type: IOC.PATTERN, url: `Heavy hex obfuscation — ${hexEscapes} hex-escaped chars`, severity: 'high' });
      escalateRisk(f, 'high');
    } else if (hexEscapes > 100) {
      f.externalRefs.push({ type: IOC.PATTERN, url: `Moderate hex encoding — ${hexEscapes} hex-escaped chars`, severity: 'medium' });
      if (f.risk === 'low') escalateRisk(f, 'medium');
    }

    // Structural: external template references
    const templateMatch = text.match(/\{\\[*]?\\template\s+([^\}]+)\}/g);
    if (templateMatch) {
      for (const t of templateMatch) {
        const url = t.replace(/\{\\[*]?\\template\s+/, '').replace(/\}$/, '').trim();
        if (url && /^https?:\/\//i.test(url)) {
          f.externalRefs.push({ type: IOC.URL, url, severity: 'high' });
          escalateRisk(f, 'high');
        }
      }
    }

    // Pattern detection is handled entirely by YARA (auto-scan on file load)

    // Extract metadata from RTF info group
    const infoMatch = text.match(/\{\\info\b([\s\S]*?)\}/);
    if (infoMatch) {
      const info = infoMatch[1];
      const getMeta = (kw) => {
        const m = info.match(new RegExp(`\\{\\\\${kw}\\s+([^\\}]*)\\}`, 'i'));
        return m ? m[1].trim() : '';
      };
      f.metadata = {
        title: getMeta('title'),
        subject: getMeta('subject'),
        creator: getMeta('author'),
        lastModifiedBy: getMeta('operator'),
        created: getMeta('creatim'),
        modified: getMeta('revtim'),
      };
    }

    return f;
  }

  // ── Text extraction from RTF ────────────────────────────────────────────────

  _extractText(rtf) {
    let result = '';
    let depth = 0;
    let skipGroup = 0;
    let i = 0;
    const len = rtf.length;

    // Skip groups that don't contain visible text
    const skipKw = new Set([
      'fonttbl', 'colortbl', 'stylesheet', 'listtable', 'listoverridetable',
      'info', 'pict', 'object', 'objdata', 'datastore', 'themedata',
      'colorschememapping', 'datafield', 'latentstyles', 'pgdsctbl',
      'xmlnstbl', 'wgrffmtfilter', 'falt', 'panose', 'bkmkstart', 'bkmkend',
    ]);

    while (i < len) {
      const ch = rtf[i];
      if (ch === '{') {
        depth++;
        // Check if next token is a skip-group keyword
        const peek = rtf.slice(i + 1, i + 40);
        const kwMatch = peek.match(/^\\([a-z]+)/i);
        if (kwMatch && skipKw.has(kwMatch[1])) skipGroup = depth;
        i++;
      } else if (ch === '}') {
        if (skipGroup === depth) skipGroup = 0;
        depth--;
        i++;
      } else if (skipGroup > 0) {
        i++;
      } else if (ch === '\\') {
        i++;
        if (i >= len) break;
        // Special characters
        if (rtf[i] === '\'') {
          // Hex escape: \'XX
          const hex = rtf.slice(i + 1, i + 3);
          const code = parseInt(hex, 16);
          if (!isNaN(code)) result += String.fromCharCode(code);
          i += 3;
        } else if (rtf[i] === '\\') { result += '\\'; i++; }
        else if (rtf[i] === '{') { result += '{'; i++; }
        else if (rtf[i] === '}') { result += '}'; i++; }
        else if (rtf[i] === '~') { result += '\u00A0'; i++; } // non-breaking space
        else if (rtf[i] === '-') { result += '\u00AD'; i++; } // soft hyphen
        else if (rtf[i] === '\n' || rtf[i] === '\r') { i++; }
        else {
          // Control word
          let kw = '';
          while (i < len && /[a-zA-Z]/.test(rtf[i])) { kw += rtf[i]; i++; }
          // Numeric param
          let param = '';
          if (i < len && (rtf[i] === '-' || /\d/.test(rtf[i]))) {
            if (rtf[i] === '-') { param += '-'; i++; }
            while (i < len && /\d/.test(rtf[i])) { param += rtf[i]; i++; }
          }
          // Trailing space consumed by control word
          if (i < len && rtf[i] === ' ') i++;
          // Map known control words
          if (kw === 'par' || kw === 'line') result += '\n';
          else if (kw === 'tab') result += '\t';
          else if (kw === 'u') {
            // Unicode character
            const code = parseInt(param);
            if (!isNaN(code)) {
              result += code < 0 ? String.fromCharCode(code + 65536) : String.fromCharCode(code);
              // Skip alternate representation
              if (i < len && rtf[i] === '?') i++;
            }
          }
        }
      } else if (ch === '\r' || ch === '\n') {
        i++;
      } else {
        result += ch;
        i++;
      }
    }

    // Clean up excessive whitespace
    return result.replace(/\n{3,}/g, '\n\n').trim();
  }

  // ── OLE object detection ────────────────────────────────────────────────────

  _findOleObjects(text) {
    const findings = [];
    for (const o of RtfRenderer.OLE_KEYWORDS) {
      if (text.toLowerCase().includes(o.kw.toLowerCase())) {
        findings.push(o);
      }
    }
    return findings;
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
