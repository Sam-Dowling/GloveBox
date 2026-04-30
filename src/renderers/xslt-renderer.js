'use strict';
// ════════════════════════════════════════════════════════════════════════════
// xslt-renderer.js — XSLT stylesheet (.xsl / .xslt) analysis.
//
// XSLT is XML-based but has a notable weaponisation surface:
//
//   • SquiblyTwo (ATT&CK T1220 Signed Binary Proxy Execution) — `wmic.exe
//     /format:<url>` or `msxsl.exe <doc> <url>` downloads and executes
//     attacker-controlled XSL, bypassing AppLocker / WDAC because wmic
//     and msxsl are signed Microsoft binaries.
//
//   • <msxsl:script> blocks — embedded JScript / VBScript / C# code
//     inside the stylesheet that runs at transform time. The canonical
//     SquiblyTwo payload format.
//
//   • Remote <xsl:import> / <xsl:include> — pulls additional XSL from
//     attacker-controlled HTTP / UNC location at transform time.
//
//   • document() XPath function with remote URI — XSLT 1.0 native
//     remote-document loader; same risk as <xsl:include>.
//
// Detection scope:
//   • <msxsl:script> present → high (T1220 SquiblyTwo signal)
//   • <xsl:import|xsl:include href="http://…"|"\\…"> → high (remote XSL)
//   • document("http://…"|"\\…") → medium (data-loaded remote URI)
//   • Format banner — medium (XSL in user-supplied input is uncommon)
//
// Depends on: constants.js (IOC, escHtml, escalateRisk, lfNormalize, pushIOC)
// ════════════════════════════════════════════════════════════════════════════
class XsltRenderer {

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const wrap = document.createElement('div');
    wrap.className = 'xslt-view';

    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    const strong = document.createElement('strong');
    strong.textContent = '⚠ XSLT Stylesheet (.xsl / .xslt)';
    banner.appendChild(strong);
    banner.appendChild(document.createTextNode(
      ' — XML transformation stylesheet. Often weaponised for ATT&CK T1220 ' +
      '(SquiblyTwo signed-binary proxy execution via wmic.exe /format:<url> ' +
      'or msxsl.exe), and via embedded <msxsl:script> blocks running JScript / ' +
      'VBScript / C# at transform time.'
    ));
    wrap.appendChild(banner);

    const summary = XsltRenderer._summarize(text);
    const info = document.createElement('div');
    info.className = 'plaintext-info';
    info.textContent = `${summary.scripts} <msxsl:script> block(s)  ·  ${summary.remoteRefs} remote ref(s)  ·  ${this._fmtBytes(bytes.length)}  ·  XSLT file`;
    wrap.appendChild(info);

    if (summary.remoteRefs) {
      const card = document.createElement('div');
      card.className = 'xslt-card';
      const h = document.createElement('h4');
      h.textContent = 'Remote references';
      card.appendChild(h);
      const ul = document.createElement('ul');
      for (const ref of summary.remoteList) {
        const li = document.createElement('li');
        const code = document.createElement('code');
        code.textContent = ref.context;
        li.appendChild(code);
        li.appendChild(document.createTextNode(' → '));
        const span = document.createElement('span');
        span.textContent = ref.value;
        span.style.color = 'var(--risk-high, #c00)';
        li.appendChild(span);
        ul.appendChild(li);
      }
      card.appendChild(ul);
      wrap.appendChild(card);
    }

    this._addRawView(wrap, text, bytes.length);
    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const normalized = lfNormalize(text);

    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: [],
    };

    f.externalRefs.push({
      type: IOC.PATTERN,
      url: 'XSLT Stylesheet — XML transform language, often weaponised for T1220 SquiblyTwo signed-binary proxy execution',
      severity: 'medium',
    });

    // ── <msxsl:script> blocks — canonical SquiblyTwo payload ─────────────
    // Pattern: `<msxsl:script ... language="JScript|VBScript|C#">` open
    // tag. The content is opaque to us (could be JScript with eval, C#
    // System.Diagnostics.Process.Start, etc.); the mere presence is high.
    const scriptRe = /<msxsl:script\b[^>]*\blanguage\s*=\s*"([^"]+)"[^>]*>/gi;
    for (const m of normalized.matchAll(scriptRe)) {
      const lang = m[1];
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `<msxsl:script language="${lang}"> — T1220 inline script payload in XSLT`,
        severity: 'high',
        _highlightText: m[0],
        _sourceOffset: m.index,
        _sourceLength: m[0].length,
      });
    }

    // ── xsl:import / xsl:include with remote href ────────────────────────
    // <xsl:include href="http://…"/> pulls additional XSL at transform
    // time. Same risk class as document(); we surface it as high.
    const includeRe = /<xsl:(include|import)\b[^>]*\bhref\s*=\s*"([^"]+)"/gi;
    for (const m of normalized.matchAll(includeRe)) {
      const tag = m[1];
      const href = m[2];
      const offset = m.index + m[0].indexOf(href);
      if (/^https?:\/\//i.test(href)) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `<xsl:${tag} href="…"> remote URL — T1220 remote-XSL load`,
          severity: 'high',
          _highlightText: href,
          _sourceOffset: offset,
          _sourceLength: href.length,
        });
        pushIOC(f, {
          type: IOC.URL,
          value: href,
          severity: 'high',
          note: `<xsl:${tag} href>`,
          highlightText: href,
        });
      } else if (/^\\\\[^\\?]/.test(href)) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `<xsl:${tag} href="…"> UNC path — T1220 remote-XSL load via SMB`,
          severity: 'high',
          _highlightText: href,
          _sourceOffset: offset,
          _sourceLength: href.length,
        });
        pushIOC(f, {
          type: IOC.UNC_PATH,
          value: href,
          severity: 'high',
          note: `<xsl:${tag} href>`,
          highlightText: href,
        });
      }
    }

    // ── document(remote-uri) — XSLT 1.0 native remote loader ─────────────
    // Slightly lower confidence than the include directives because
    // document() is also used for legitimate same-document references
    // (e.g. document('')). We only flag explicit http / UNC URIs.
    const docRe = /\bdocument\s*\(\s*['"]([^'"]+)['"]/gi;
    for (const m of normalized.matchAll(docRe)) {
      const uri = m[1];
      const offset = m.index + m[0].indexOf(uri);
      if (/^https?:\/\//i.test(uri)) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: 'document() with remote URL — XSLT remote-document load',
          severity: 'medium',
          _highlightText: uri,
          _sourceOffset: offset,
          _sourceLength: uri.length,
        });
        pushIOC(f, {
          type: IOC.URL,
          value: uri,
          severity: 'medium',
          note: 'document()',
          highlightText: uri,
        });
      } else if (/^\\\\[^\\?]/.test(uri)) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: 'document() with UNC path — XSLT remote-document load via SMB',
          severity: 'medium',
          _highlightText: uri,
          _sourceOffset: offset,
          _sourceLength: uri.length,
        });
        pushIOC(f, {
          type: IOC.UNC_PATH,
          value: uri,
          severity: 'medium',
          note: 'document()',
          highlightText: uri,
        });
      }
    }

    // Risk calibration. Two highs (script + remote include) → high.
    const refs = f.externalRefs;
    const highs = refs.filter(r => r.severity === 'high').length;
    const hasCrit = refs.some(r => r.severity === 'critical');
    const hasMed = refs.some(r => r.severity === 'medium');
    if (hasCrit) escalateRisk(f, 'critical');
    else if (highs >= 1) escalateRisk(f, 'high');
    else if (hasMed) escalateRisk(f, 'medium');
    return f;
  }

  // ── Static summariser — used by render() and tests ───────────────────────
  static _summarize(text) {
    const remoteList = [];
    let scripts = 0;

    const scriptRe = /<msxsl:script\b[^>]*>/gi;
    for (const _ of text.matchAll(scriptRe)) scripts++;

    const includeRe = /<xsl:(include|import)\b[^>]*\bhref\s*=\s*"([^"]+)"/gi;
    let m;
    while ((m = includeRe.exec(text)) !== null) {
      if (/^(https?:\/\/|\\\\)/i.test(m[2])) {
        remoteList.push({ context: `<xsl:${m[1]} href>`, value: m[2] });
      }
    }
    const docRe = /\bdocument\s*\(\s*['"]([^'"]+)['"]/gi;
    while ((m = docRe.exec(text)) !== null) {
      if (/^(https?:\/\/|\\\\)/i.test(m[1])) {
        remoteList.push({ context: 'document()', value: m[1] });
      }
    }
    return { scripts, remoteRefs: remoteList.length, remoteList };
  }

  _addRawView(wrap, text, byteLen) {
    const normalizedText = lfNormalize(text);
    const lines = normalizedText.split('\n');

    const sourcePane = document.createElement('div');
    sourcePane.className = 'xslt-source plaintext-scroll';

    const table = document.createElement('table');
    table.className = 'plaintext-table';
    const maxLines = RENDER_LIMITS.MAX_TEXT_LINES_SMALL;
    const count = Math.min(lines.length, maxLines);
    let highlightedLines = null;
    if (typeof hljs !== 'undefined' && normalizedText.length <= 200000) {
      try {
        const result = hljs.highlight(normalizedText, { language: 'xml', ignoreIllegals: true });
        highlightedLines = result.value.split('\n');
      } catch (_) { /* fallback to plain textContent */ }
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
      tr.appendChild(tdNum); tr.appendChild(tdCode);
      table.appendChild(tr);
    }
    sourcePane.appendChild(table);
    wrap.appendChild(sourcePane);

    wrap._rawText = lfNormalize(text);
    wrap._showSourcePane = () => {
      sourcePane.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
