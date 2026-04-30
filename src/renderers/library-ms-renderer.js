'use strict';
// ════════════════════════════════════════════════════════════════════════════
// library-ms-renderer.js — Windows Library / Search-Connector analysis.
//
// Two closely-related XML formats both abused for ATT&CK T1187 (Forced
// Authentication / NTLM hash theft):
//
//   .library-ms          — Windows 7+ "Library" definition (Documents,
//                          Pictures, Music, Videos). XML root <libraryDescription>.
//   .searchConnector-ms  — Federated-search connector. XML root
//                          <searchConnectorDescription>.
//
// Both formats place file-system roots inside <searchConnectorDescription>
// → <simpleLocation> → <url> elements. Setting that URL to a UNC path
// causes the Windows Search indexer (or Explorer's preview pane) to
// auto-resolve the location, leaking the user's NTLM hash to the
// attacker — same primitive as `.scf` IconFile, but harder to filter
// because both formats also have legitimate use.
//
// Detection scope:
//   • <url> / <simpleLocation> / <description>.iconReference UNC path → high
//   • <url> http(s):// pointing at remote host → medium (also viable —
//     the indexer follows http URLs for OpenSearch protocol descriptors)
//   • Format banner — medium (rare in user-supplied files outside of
//     enterprise deployments; analyst should see them)
//
// Depends on: constants.js (IOC, escHtml, escalateRisk, lfNormalize, pushIOC)
// ════════════════════════════════════════════════════════════════════════════
class LibraryMsRenderer {

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const isLibrary = /<libraryDescription/i.test(text);
    const formatLabel = isLibrary ? 'Windows Library (.library-ms)' : 'Search Connector (.searchConnector-ms)';

    const wrap = document.createElement('div');
    wrap.className = 'library-ms-view';

    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    const strong = document.createElement('strong');
    strong.textContent = `⚠ ${formatLabel}`;
    banner.appendChild(strong);
    banner.appendChild(document.createTextNode(
      ' — XML descriptor consumed by Windows Explorer / Search. UNC paths ' +
      'inside <simpleLocation>/<url> trigger SMB authentication when the ' +
      'descriptor is rendered (T1187 Forced Authentication / NTLM hash theft).'
    ));
    wrap.appendChild(banner);

    // Surface every <url> / <simpleLocation> string we extracted, with
    // UNC and http highlighting.
    const locations = LibraryMsRenderer._extractLocations(text);
    if (locations.length) {
      const card = document.createElement('div');
      card.className = 'library-ms-card';
      const h = document.createElement('h4');
      h.textContent = 'Locations';
      card.appendChild(h);
      const ul = document.createElement('ul');
      for (const loc of locations) {
        const li = document.createElement('li');
        const tag = document.createElement('code');
        tag.textContent = `<${loc.tag}>`;
        li.appendChild(tag);
        li.appendChild(document.createTextNode(' '));
        const val = document.createElement('span');
        val.textContent = loc.value;
        if (loc.kind === 'unc') val.style.color = 'var(--risk-high, #c00)';
        li.appendChild(val);
        if (loc.kind) {
          const tag2 = document.createElement('span');
          tag2.className = 'library-ms-kind';
          tag2.textContent = ' [' + loc.kind + ']';
          li.appendChild(tag2);
        }
        ul.appendChild(li);
      }
      card.appendChild(ul);
      wrap.appendChild(card);
    }

    const info = document.createElement('div');
    info.className = 'plaintext-info';
    info.textContent = `${locations.length} location(s)  ·  ${this._fmtBytes(bytes.length)}  ·  ${formatLabel}`;
    wrap.appendChild(info);

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

    const isLibrary = /<libraryDescription/i.test(text);
    const formatLabel = isLibrary ? 'Windows Library (.library-ms)' : 'Search Connector (.searchConnector-ms)';

    f.externalRefs.push({
      type: IOC.PATTERN,
      url: `${formatLabel} — XML descriptor often weaponised for T1187 forced authentication`,
      severity: 'medium',
    });

    // Scan extracted <url> / <simpleLocation> / iconReference values.
    const locations = LibraryMsRenderer._extractLocations(normalized);
    for (const loc of locations) {
      if (loc.kind === 'unc') {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `<${loc.tag}> points at UNC path — T1187 forced authentication / NTLM hash leak`,
          severity: 'high',
          _highlightText: loc.value,
          _sourceOffset: loc.offset,
          _sourceLength: loc.value.length,
        });
        pushIOC(f, {
          type: IOC.UNC_PATH,
          value: loc.value,
          severity: 'high',
          note: `<${loc.tag}>`,
          highlightText: loc.value,
        });
      } else if (loc.kind === 'http') {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `<${loc.tag}> points at HTTP URL — remote location in a search/library descriptor`,
          severity: 'medium',
          _highlightText: loc.value,
          _sourceOffset: loc.offset,
          _sourceLength: loc.value.length,
        });
        pushIOC(f, {
          type: IOC.URL,
          value: loc.value,
          severity: 'medium',
          note: `<${loc.tag}>`,
          highlightText: loc.value,
        });
      }
    }

    // Risk calibration — identical shape to scf-renderer.
    const refs = f.externalRefs;
    const highs = refs.filter(r => r.severity === 'high').length;
    const hasCrit = refs.some(r => r.severity === 'critical');
    const hasMed = refs.some(r => r.severity === 'medium');
    if (hasCrit) escalateRisk(f, 'critical');
    else if (highs >= 1) escalateRisk(f, 'high');
    else if (hasMed) escalateRisk(f, 'medium');
    return f;
  }

  // ── Static parser — exposed for tests ────────────────────────────────────
  // Pulls every <url>, <simpleLocation> child URL, and iconReference
  // attribute. Returns array of { tag, value, kind, offset } where
  // `kind` is 'unc' | 'http' | 'other' for risk gating downstream.
  //
  // We do a regex-based pull rather than DOMParser because:
  //   1) It's the same approach `xlsx-renderer.js` uses for [Content_Types]
  //      detection — predictable, no DOMParser quirks across browsers.
  //   2) The library-ms / searchConnector-ms grammars are simple enough
  //      that a regex pull captures every legal value.
  //   3) Avoids paying for a DOMParser allocation on a 500-byte file.
  static _extractLocations(text) {
    const out = [];
    const tagRe = /<(url|simpleLocation)[^>]*>([\s\S]*?)<\/\1>/gi;
    let m;
    while ((m = tagRe.exec(text)) !== null) {
      const tag = m[1];
      const inner = m[2];
      // <simpleLocation> wraps a <url> child — extract that, otherwise
      // use the inner text directly.
      const urlChild = inner.match(/<url[^>]*>([\s\S]*?)<\/url>/i);
      const value = (urlChild ? urlChild[1] : inner).trim();
      if (!value) continue;
      const kind = LibraryMsRenderer._classifyLocation(value);
      // Compute offset of the value within the original text. Best-effort —
      // for nested <url>-inside-<simpleLocation> we report the inner offset.
      const innerOffset = m.index + m[0].indexOf(value);
      out.push({ tag: urlChild ? 'url' : tag, value, kind, offset: innerOffset });
    }
    // Also pull iconReference="..." attributes — Explorer uses them the
    // same way as <url>, including UNC support.
    const iconRe = /iconReference\s*=\s*"([^"]+)"/gi;
    while ((m = iconRe.exec(text)) !== null) {
      const value = m[1].trim();
      if (!value) continue;
      out.push({
        tag: 'iconReference',
        value,
        kind: LibraryMsRenderer._classifyLocation(value),
        offset: m.index + m[0].indexOf(value),
      });
    }
    return out;
  }

  static _classifyLocation(value) {
    if (/^\\\\[^\\?][^\\]*\\/.test(value)) return 'unc';
    if (/^\\\\\?\\UNC\\/i.test(value)) return 'unc';
    if (/^https?:\/\//i.test(value)) return 'http';
    return 'other';
  }

  _addRawView(wrap, text, byteLen) {
    const normalizedText = lfNormalize(text);
    const lines = normalizedText.split('\n');

    const sourcePane = document.createElement('div');
    sourcePane.className = 'library-ms-source plaintext-scroll';

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
