'use strict';
// ════════════════════════════════════════════════════════════════════════════
// url-renderer.js — Internet shortcut file analysis (.url, .webloc, .website)
// Depends on: constants.js (IOC, escHtml)
// ════════════════════════════════════════════════════════════════════════════
class UrlShortcutRenderer {

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const normalizedText = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const wrap = document.createElement('div'); wrap.className = 'url-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>Internet Shortcut Analysis</strong> — .url / .webloc / .website files can redirect users to malicious sites or UNC paths.';
    wrap.appendChild(banner);

    const parsed = ext === 'webloc' ? this._parseWebloc(text) : this._parseUrlFile(text);

    // URL display card
    const card = document.createElement('div'); card.className = 'url-card';

    // URL
    if (parsed.url) {
      const urlDiv = document.createElement('div'); urlDiv.className = 'url-target';
      const lbl = document.createElement('span'); lbl.className = 'url-label'; lbl.textContent = 'Target URL: ';
      const val = document.createElement('span'); val.className = 'url-value';
      val.textContent = parsed.url;
      urlDiv.appendChild(lbl); urlDiv.appendChild(val);
      card.appendChild(urlDiv);

      // Risk indicators
      const risks = this._assessUrl(parsed.url);
      if (risks.length) {
        const riskDiv = document.createElement('div'); riskDiv.className = 'url-risks';
        for (const r of risks) {
          const d = document.createElement('div'); d.className = `url-risk url-risk-${r.sev}`;
          d.textContent = r.msg; riskDiv.appendChild(d);
        }
        card.appendChild(riskDiv);
      }
    } else {
      const nf = document.createElement('div'); nf.className = 'url-no-target';
      nf.textContent = 'No target URL found.'; card.appendChild(nf);
    }

    // Additional fields
    if (parsed.iconFile) {
      const row = document.createElement('div'); row.className = 'url-field';
      const lbl = document.createElement('span'); lbl.className = 'url-label'; lbl.textContent = 'Icon File:';
      const val = document.createElement('span'); val.className = 'url-value'; val.textContent = parsed.iconFile;
      row.appendChild(lbl); row.appendChild(document.createTextNode(' ')); row.appendChild(val);
      card.appendChild(row);
    }
    if (parsed.iconIndex !== undefined) {
      const row = document.createElement('div'); row.className = 'url-field';
      const lbl = document.createElement('span'); lbl.className = 'url-label'; lbl.textContent = 'Icon Index:';
      const val = document.createElement('span'); val.className = 'url-value'; val.textContent = String(parsed.iconIndex);
      row.appendChild(lbl); row.appendChild(document.createTextNode(' ')); row.appendChild(val);
      card.appendChild(row);
    }
    if (parsed.workingDir) {
      const row = document.createElement('div'); row.className = 'url-field';
      const lbl = document.createElement('span'); lbl.className = 'url-label'; lbl.textContent = 'Working Directory:';
      const val = document.createElement('span'); val.className = 'url-value'; val.textContent = parsed.workingDir;
      row.appendChild(lbl); row.appendChild(document.createTextNode(' ')); row.appendChild(val);
      card.appendChild(row);
    }
    if (parsed.hotKey) {
      const row = document.createElement('div'); row.className = 'url-field';
      const lbl = document.createElement('span'); lbl.className = 'url-label'; lbl.textContent = 'Hot Key:';
      const val = document.createElement('span'); val.className = 'url-value'; val.textContent = parsed.hotKey;
      row.appendChild(lbl); row.appendChild(document.createTextNode(' ')); row.appendChild(val);
      card.appendChild(row);
    }

    wrap.appendChild(card);

    // ── Collapsible Raw File Content as a .plaintext-table ──────────────────
    // Uses the same shared highlight surface as SVG/HTA renderers so the
    // sidebar's `_highlightMatchesInline` can wrap <mark>s around YARA/IOC
    // matches using character offsets in `wrap._rawText`.
    const rawDetails = document.createElement('details');
    rawDetails.className = 'url-raw-details';
    const summary = document.createElement('summary');
    summary.textContent = 'Raw File Content';
    rawDetails.appendChild(summary);

    const sourcePane = document.createElement('div');
    sourcePane.className = 'url-source plaintext-scroll';
    const table = document.createElement('table');
    table.className = 'plaintext-table';
    const lines = normalizedText.split('\n');
    const maxLines = RENDER_LIMITS.MAX_TEXT_LINES_SMALL;
    const count = Math.min(lines.length, maxLines);

    // hljs highlighting — 'ini' for .url (INI-style), 'xml' for .webloc / .website
    // (both are XML plist-flavoured). 200 KB cap matches the other renderers.
    const lang = (ext === 'webloc' || ext === 'website') ? 'xml' : 'ini';
    let highlightedLines = null;
    if (typeof hljs !== 'undefined' && normalizedText.length <= 200000) {
      try {
        const result = hljs.highlight(normalizedText, { language: lang, ignoreIllegals: true });
        highlightedLines = result.value.split('\n');
      } catch (_) { /* fallback to plain text */ }
    }

    for (let i = 0; i < count; i++) {
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
    sourcePane.appendChild(table);
    rawDetails.appendChild(sourcePane);
    wrap.appendChild(rawDetails);

    wrap._rawText = normalizedText;
    wrap._showSourcePane = () => {
      rawDetails.open = true;
      // Wait for the <details> element to finish laying out its now-visible
      // contents before scrolling. A single requestAnimationFrame can fire
      // before layout has been applied to newly-opened <details>, so defer
      // via setTimeout(0) which guarantees we run after the current layout
      // pass in every browser we target.
      setTimeout(() => {
        rawDetails.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 0);
    };

    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    // Start 'low'; `_assessUrl()` results bump f.risk to 'medium'/'high' at
    // the per-risk loop below when evidence warrants it.
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const normalizedText = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const parsed = ext === 'webloc' ? this._parseWebloc(text) : this._parseUrlFile(text);

    // Helper — locate `needle` in the raw text and return offset/length (or null).
    const locate = (needle) => {
      if (!needle) return null;
      const idx = normalizedText.indexOf(needle);
      if (idx === -1) return null;
      return { offset: idx, length: needle.length };
    };

    if (parsed.url) {
      const risks = this._assessUrl(parsed.url);
      const loc = locate(parsed.url);
      for (const r of risks) {
        const ref = {
          type: IOC.PATTERN,
          url: r.msg,
          severity: r.sev,
          _highlightText: parsed.url
        };
        if (loc) { ref._sourceOffset = loc.offset; ref._sourceLength = loc.length; }
        f.externalRefs.push(ref);
        if (r.sev === 'high') escalateRisk(f, 'high');
        else if (r.sev === 'medium' && f.risk !== 'high') escalateRisk(f, 'medium');
      }
      // Add the URL itself as a finding
      const urlSev = /^\\\\|^file:/i.test(parsed.url) ? 'high' : 'medium';
      const urlRef = {
        type: IOC.URL,
        url: parsed.url,
        severity: urlSev,
        _highlightText: parsed.url
      };
      if (loc) { urlRef._sourceOffset = loc.offset; urlRef._sourceLength = loc.length; }
      f.externalRefs.push(urlRef);
    }

    if (parsed.iconFile) {
      const loc = locate(parsed.iconFile);
      const ref = {
        type: IOC.FILE_PATH,
        url: parsed.iconFile,
        severity: 'info',
        _highlightText: parsed.iconFile
      };
      if (loc) { ref._sourceOffset = loc.offset; ref._sourceLength = loc.length; }
      f.externalRefs.push(ref);
    }

    // Pattern detection is handled entirely by YARA (auto-scan on file load)
    return f;
  }

  // ── INI-format .url parser ──────────────────────────────────────────────────

  _parseUrlFile(text) {
    const result = {};
    const lines = text.split(/\r?\n/);
    for (const line of lines) {
      const m = line.match(/^\s*(\w+)\s*=\s*(.*?)\s*$/);
      if (!m) continue;
      const key = m[1].toLowerCase(), val = m[2];
      if (key === 'url') result.url = val;
      else if (key === 'iconfile') result.iconFile = val;
      else if (key === 'iconindex') result.iconIndex = val;
      else if (key === 'workingdirectory') result.workingDir = val;
      else if (key === 'hotkey') result.hotKey = val;
    }
    return result;
  }

  // ── XML plist .webloc parser ────────────────────────────────────────────────

  _parseWebloc(text) {
    const result = {};
    try {
      const doc = new DOMParser().parseFromString(text, 'text/xml');
      const strings = doc.getElementsByTagName('string');
      if (strings.length) result.url = strings[0].textContent.trim();
    } catch (e) { }
    return result;
  }

  // ── URL risk assessment ─────────────────────────────────────────────────────

  _assessUrl(url) {
    const risks = [];

    // UNC path — credential theft
    if (/^\\\\/.test(url)) {
      risks.push({ sev: 'high', msg: '⚠ UNC path — can steal NTLM credentials via SMB authentication' });
    }

    // file:// protocol
    if (/^file:/i.test(url)) {
      risks.push({ sev: 'high', msg: '⚠ file:// protocol — accesses local or network filesystem' });
    }

    // IP-based URL (no hostname)
    if (/^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(url)) {
      risks.push({ sev: 'medium', msg: 'IP-based URL — no domain name (common in phishing)' });
    }

    // Non-standard port
    const portMatch = url.match(/^https?:\/\/[^\/:]+(:\d+)/i);
    if (portMatch) {
      const port = parseInt(portMatch[1].slice(1));
      if (![80, 443, 8080, 8443].includes(port)) {
        risks.push({ sev: 'medium', msg: `Non-standard port: ${port}` });
      }
    }

    // Data URI
    if (/^data:/i.test(url)) {
      risks.push({ sev: 'high', msg: '⚠ data: URI — can embed executable content' });
    }

    // JavaScript URI
    if (/^javascript:/i.test(url)) {
      risks.push({ sev: 'high', msg: '⚠ javascript: URI — code execution' });
    }

    // URL shortener domains
    if (/^https?:\/\/(bit\.ly|goo\.gl|tinyurl|t\.co|is\.gd|buff\.ly|ow\.ly|rebrand\.ly)/i.test(url)) {
      risks.push({ sev: 'medium', msg: 'URL shortener — hides true destination' });
    }

    return risks;
  }
}
