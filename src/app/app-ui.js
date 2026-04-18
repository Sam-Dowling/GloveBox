// ════════════════════════════════════════════════════════════════════════════
// App — UI utilities: tabs, sidebar toggle, downloads, clipboard, zoom, theme
// ════════════════════════════════════════════════════════════════════════════

// ── Theme registry ──────────────────────────────────────────────────────────
// Single source of truth for every available theme. To add a new theme:
//   1. Drop a `src/styles/themes/<id>.css` file containing
//      `body.theme-<id> { … overrides … }`.
//   2. Add the file to CSS_FILES in build.py.
//   3. Add a row to this array — no other wiring required.
// `dark: true` toggles the legacy `body.dark` class so the ~150 existing dark
// rules across core.css / viewers.css act as the baseline the overlay refines.
const THEMES = [
  { id: 'light',     label: 'Light',           icon: '☀',  dark: false },
  { id: 'dark',      label: 'Dark',            icon: '🌙', dark: true  },
  { id: 'midnight',  label: 'Midnight (OLED)', icon: '🌑', dark: true  },
  { id: 'solarized', label: 'Solarized',       icon: '🟡', dark: true  },
];
const _THEME_PREF_KEY = 'loupe_theme';
const _DEFAULT_THEME = 'dark';

Object.assign(App.prototype, {


  // ── Helper: section heading ──────────────────────────────────────────────
  _sec(label) {
    const d = document.createElement('div'); d.className = 'sb-section'; d.textContent = label; return d;
  },

  _toggleSidebar() {
    this.sidebarOpen = !this.sidebarOpen;
    document.getElementById('sidebar').classList.toggle('hidden', !this.sidebarOpen);
    document.getElementById('sidebar-resize').classList.toggle('hidden', !this.sidebarOpen);
  },

  // ── Sidebar resize ─────────────────────────────────────────────────────
  _setupSidebarResize() {
    const handle = document.getElementById('sidebar-resize');
    const sidebar = document.getElementById('sidebar');
    let startX, startW;
    const onMove = e => {
      const dx = startX - e.clientX;
      const newW = Math.min(Math.max(startW + dx, window.innerWidth * 0.33), window.innerWidth * 0.6);
      sidebar.style.width = newW + 'px';
    };
    const onUp = () => {
      document.body.classList.remove('sb-resizing');
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
    };
    handle.addEventListener('mousedown', e => {
      e.preventDefault();
      startX = e.clientX;
      startW = sidebar.getBoundingClientRect().width;
      document.body.classList.add('sb-resizing');
      window.addEventListener('mousemove', onMove);
      window.addEventListener('mouseup', onUp);
    });
  },

  // ── Save / Copy current content ─────────────────────────────────────────
  _saveContent() {
    if (!this._fileBuffer) { this._toast('No file loaded', 'error'); return; }
    // _fileMeta.name is now the single source of truth for the filename
    // (the toolbar used to render this via #file-info.textContent but that
    // element has been replaced by the breadcrumb trail).
    const name = (this._fileMeta && this._fileMeta.name) || 'file';

    const blob = new Blob([this._fileBuffer], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
    this._toast('File saved');
  },

  _copyContent() {
    if (!this._fileBuffer) { this._toast('No file loaded', 'error'); return; }
    try {
      const bytes = new Uint8Array(this._fileBuffer);
      // Try to decode as text; if it looks binary, fall back to hex
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      this._copyToClipboard(text);
    } catch (_) {
      // Binary file — copy hex representation
      const bytes = new Uint8Array(this._fileBuffer);
      const hex = Array.from(bytes.slice(0, 65536)).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const suffix = bytes.length > 65536 ? '\n… (truncated)' : '';
      this._copyToClipboard(hex + suffix);
    }
  },

  // ── ⚡ Copy Analysis (Summary) — structured report for AI / SOC ──────
  _copyAnalysis() {
    if (!this._fileBuffer || !this.findings) { this._toast('No file loaded', 'error'); return; }
    // Budget raised from 12 KB → 50 KB so the Summary can carry every
    // renderer's per-format deep data (PDF JavaScripts, MSI CustomActions,
    // EVTX event distribution, PGP key info, plist persistence, …) rather
    // than only a compact headline view.  Strict IOC/STIX/MISP exporters
    // are not affected — they live in _collectIocs / _buildStix / _buildMisp
    // and remain TIP-friendly.
    const report = this._buildAnalysisText(50000);
    this._copyToClipboard(report);
  },


  // Produce the plaintext summary report. When `budget === Infinity` the
  // per-section length caps are skipped so callers can obtain the full,
  // unbudgeted report (used by the Plaintext export). Otherwise behaves
  // exactly as the legacy _copyAnalysis body did — section order, tables,
  // and budget trimming are byte-identical so Summary output is unchanged.
  _buildAnalysisText(budget) {
    if (!this.findings) return '';
    const UNBUDGETED = !isFinite(budget);
    const BUDGET = UNBUDGETED ? Number.MAX_SAFE_INTEGER : budget;
    const f = this.findings;

    const meta = this._fileMeta || {};
    const hashes = this.fileHashes || {};
    const sections = [];

    // Helper: truncate a section to fit a max length
    const cap = (text, max) => {
      if (!text) return '';
      return text.length <= max ? text : text.slice(0, max) + '\n… (section truncated)\n';
    };
    // Helper: escape pipe characters for markdown tables
    const tp = (v) => String(v || '').replace(/\|/g, '∣').replace(/\n/g, ' ');

    // ═══════ 1. File Info (priority: always included) ════════════════════
    const FMT = {
      docx:'Word Document',docm:'Word Macro-Enabled Document',xlsx:'Excel Workbook',
      xlsm:'Excel Macro-Enabled Workbook',xls:'Excel 97-2003 Workbook',ods:'OpenDocument Spreadsheet',
      pptx:'PowerPoint Presentation',pptm:'PowerPoint Macro-Enabled Presentation',
      csv:'Comma-Separated Values',tsv:'Tab-Separated Values',doc:'Word 97-2003 Document',
      msg:'Outlook Message',eml:'Email Message',lnk:'Windows Shortcut',hta:'HTML Application',
      pdf:'PDF Document',rtf:'Rich Text Format',html:'HTML Document',htm:'HTML Document',
      one:'OneNote Document',iso:'Disk Image (ISO)',img:'Disk Image (IMG)',zip:'ZIP Archive',
      rar:'RAR Archive','7z':'7-Zip Archive',wsf:'Windows Script File',url:'Internet Shortcut',
      svg:'SVG Image',iqy:'Internet Query File',slk:'Symbolic Link File',evtx:'Windows Event Log',
      sqlite:'SQLite Database',db:'SQLite Database',exe:'PE Executable',dll:'PE Dynamic Library',
      sys:'PE Driver',elf:'ELF Binary',so:'ELF Shared Object',jar:'Java Archive',
      class:'Java Class',pem:'PEM Certificate',der:'DER Certificate',crt:'X.509 Certificate',
      p12:'PKCS#12 Keystore',war:'Java WAR',ear:'Java EAR',msi:'Windows Installer',
      reg:'Registry File',inf:'INF File',sct:'Scriptlet',scpt:'Compiled AppleScript',
      applescript:'AppleScript Source',jxa:'JavaScript for Automation',plist:'Property List',
      pfx:'PKCS#12 Keystore',cer:'X.509 Certificate',odt:'OpenDocument Text',
      odp:'OpenDocument Presentation',ppt:'PowerPoint 97-2003',dylib:'Mach-O Dynamic Library',
      bundle:'Mach-O Bundle',o:'Object File',cab:'Cabinet Archive',
      gz:'Gzip Archive',tgz:'Tar Gzip Archive',tar:'Tar Archive',
    };
    const fileName = (meta.name || '').toString();
    const ext = fileName.split('.').pop().toLowerCase();
    const fileType = FMT[ext] || (ext.toUpperCase() + ' File');
    let s = '# File Analysis Report\n\n## File Info\n| Property | Value |\n|----------|-------|\n';
    s += `| Filename | ${tp(fileName)} |\n| Type | ${fileType} (.${ext}) |\n`;
    if (meta.size) s += `| Size | ${fmtBytes(meta.size)} (${meta.size.toLocaleString()} bytes) |\n`;
    if (meta.magic) s += `| Magic | ${tp(meta.magic.label)}${meta.magic.hex ? ' [' + meta.magic.hex + ']' : ''} |\n`;
    if (hashes.md5) s += `| MD5 | \`${hashes.md5}\` |\n`;
    if (hashes.sha1) s += `| SHA-1 | \`${hashes.sha1}\` |\n`;
    if (hashes.sha256) s += `| SHA-256 | \`${hashes.sha256}\` |\n`;
    if (meta.entropy !== undefined) s += `| Entropy | ${meta.entropy.toFixed(3)} / 8.000 |\n`;
    sections.push({ text: s, priority: 1, maxLen: 800 });

    // ═══════ 2. Risk Assessment ══════════════════════════════════════════
    const risk = f.risk || f.riskLevel || '';
    if (risk) {
      const sev = { critical:'🔴 CRITICAL', high:'🟠 HIGH', medium:'🟡 MEDIUM', low:'🟢 LOW' };
      sections.push({ text: `\n## Risk Assessment\n**${sev[risk] || risk.toUpperCase()}**\n`, priority: 2, maxLen: 200 });
    }

    // ═══════ 3. Detections ═══════════════════════════════════════════════
    const detectionTypes = new Set([IOC.YARA, IOC.PATTERN, IOC.INFO]);
    const allRefs = [...(f.externalRefs || []), ...(f.interestingStrings || [])];
    const detections = allRefs.filter(r => detectionTypes.has(r.type));
    if (detections.length) {
      let d = '\n## Detections\n| Rule | Severity | Description |\n|------|----------|-------------|\n';
      for (const det of detections.slice(0, 250)) {
        d += `| ${tp(det.ruleName || det.type)} | ${(det.severity || 'info').toUpperCase()} | ${tp(det.description || det.url)} |\n`;
      }
      if (detections.length > 250) d += `\n… and ${detections.length - 250} more detections\n`;
      sections.push({ text: d, priority: 3, maxLen: 10000 });
    }

    // ═══════ 4. IOCs (ALL types except detections) ═══════════════════════
    const iocSeen = new Set();
    const iocs = [];
    for (const r of allRefs) {
      if (!detectionTypes.has(r.type) && r.url && !iocSeen.has(r.type + '|' + r.url)) {
        iocSeen.add(r.type + '|' + r.url);
        iocs.push(r);
      }
    }
    if (iocs.length) {
      let d = '\n## IOCs\n| Type | Value | Severity |\n|------|-------|----------|\n';
      for (const ioc of iocs.slice(0, 350)) {
        d += `| ${tp(ioc.type)} | \`${tp(ioc.url)}\` | ${ioc.severity || 'info'} |\n`;
      }
      if (iocs.length > 350) d += `\n… and ${iocs.length - 350} more IOCs\n`;
      sections.push({ text: d, priority: 4, maxLen: 10000 });
    }

    // ═══════ 5. Macros ═══════════════════════════════════════════════════
    if (f.hasMacros && f.modules && f.modules.length) {
      const mods = f.modules.filter(m => m.source);
      if (mods.length) {
        let d = '\n## Macros\n';
        if (f.autoExec && f.autoExec.length) {
          const items = f.autoExec.map(a => typeof a === 'string' ? a : `${a.module}: ${(a.patterns || []).join(', ')}`);
          d += '**Auto-exec:** ' + items.join('; ') + '\n\n';
        }
        for (const mod of mods) {
          d += `### ${mod.name}\n\`\`\`vba\n${mod.source}\n\`\`\`\n\n`;
        }
        sections.push({ text: d, priority: 5, maxLen: 12000 });
      }
    }

    // ═══════ 6. Deobfuscated Findings ════════════════════════════════════
    // Walk the full innerFindings tree — every decoded layer (including
    // deeper ones like Base64 → gzip → PowerShell) becomes its own section
    // so the analyst / LLM sees the actual payload, not just the outer
    // encoding. Duplicates are deduped by (chain + first 120 chars of
    // decoded text) so re-packaged identical payloads aren't emitted twice.
    const _flattenEncoded = (ef, out) => {
      out.push(ef);
      for (const inner of (ef.innerFindings || [])) _flattenEncoded(inner, out);
      return out;
    };
    const encoded = (f.encodedContent || []).reduce((a, ef) => _flattenEncoded(ef, a), []);
    const meaningful = encoded.filter(ef => {
      if (ef._deobfuscatedText) return true;
      if (ef.decodedBytes && ef.decodedBytes.length) {
        try {
          const t = new TextDecoder('utf-8', { fatal: true }).decode(ef.decodedBytes.slice(0, 2000));
          return [...t].filter(c => c.charCodeAt(0) < 32 && c !== '\n' && c !== '\r' && c !== '\t').length / t.length < 0.1;
        } catch (_) { return false; }
      }
      return false;
    });
    // Dedupe identical chain+payload so nested re-wrappings don't double up.
    const _seenLayers = new Set();
    const uniqueLayers = [];
    for (const ef of meaningful) {
      const keyText = ef._deobfuscatedText
        || (ef.decodedBytes ? (() => {
          try { return new TextDecoder('utf-8', { fatal: true }).decode(ef.decodedBytes.slice(0, 120)); }
          catch (_) { return ''; }
        })() : '');
      const key = ((ef.chain || []).join('→')) + '|' + keyText.slice(0, 120);
      if (_seenLayers.has(key)) continue;
      _seenLayers.add(key);
      uniqueLayers.push(ef);
    }
    if (uniqueLayers.length) {
      let d = '\n## Deobfuscated Findings\n';
      for (const ef of uniqueLayers) {

        const chain = (ef.chain && ef.chain.length) ? ef.chain.join(' → ') : ef.encoding || 'decoded';
        d += `### ${chain}\n`;
        if (ef.severity && ef.severity !== 'info') d += `**Severity:** ${ef.severity}\n`;
        let dec = ef._deobfuscatedText || '';
        if (!dec && ef.decodedBytes) { try { dec = new TextDecoder('utf-8', { fatal: true }).decode(ef.decodedBytes.slice(0, 16000)); } catch (_) {} }
        if (dec) d += '```\n' + (dec.length > 8000 ? dec.slice(0, 8000) + '\n… (truncated)' : dec) + '\n```\n';
        if (ef.iocs && ef.iocs.length) d += '**IOCs:** ' + ef.iocs.map(i => `${i.type}: \`${i.url}\``).join(', ') + '\n';
        d += '\n';
      }
      sections.push({ text: d, priority: 6, maxLen: 14000 });
    }

    // ═══════ 7. Format-Specific Deep Data ════════════════════════════════
    let deep = this._copyAnalysisFormatSpecific(f, tp);
    if (deep) sections.push({ text: deep, priority: 7, maxLen: BUDGET }); // gets remaining

    // ═══════ Assemble with budget ════════════════════════════════════════
    sections.sort((a, b) => a.priority - b.priority);
    let remaining = BUDGET;
    const output = [];
    for (const sec of sections) {
      if (remaining <= 0) break;
      // For the last section (format-specific), give it whatever remains
      const limit = sec.priority === 7 ? remaining : Math.min(sec.maxLen, remaining);
      const text = cap(sec.text, limit);
      output.push(text);
      remaining -= text.length;
    }
    let report = output.join('');
    if (report.length > BUDGET) report = report.slice(0, BUDGET) + '\n… (report truncated)';
    return report;
  },


  // Recursive pretty-printer for the generic metadata loop. The legacy
  // writer just did `${v}` which stringified arrays/objects as "[object
  // Object]" or "[object]","[object]","...". This formatter renders the
  // actual structure (bounded: depth ≤ 3, arrays ≤ 20, strings ≤ 500 chars)
  // so analysts get the real nested data without the report blowing up.
  _formatMetadataValue(v, depth) {
    depth = depth | 0;
    if (v == null) return '';
    const t = typeof v;
    if (t === 'string') {
      return v.length > 500 ? v.slice(0, 500) + '… (truncated)' : v;
    }
    if (t === 'number' || t === 'boolean') return String(v);
    if (v instanceof Uint8Array || (ArrayBuffer.isView && ArrayBuffer.isView(v))) {
      return `<${v.byteLength || v.length} bytes>`;
    }
    if (Array.isArray(v)) {
      if (!v.length) return '[]';
      if (depth >= 3) return `[${v.length} items]`;
      const shown = v.slice(0, 20).map(x => this._formatMetadataValue(x, depth + 1));
      // For scalar arrays use a compact inline representation; for
      // object/nested arrays lay them out one per line for legibility.
      const anyComplex = shown.some(s => s.includes('\n') || s.length > 60);
      const tail = v.length > 20 ? `, … and ${v.length - 20} more` : '';
      if (!anyComplex) return '[' + shown.join(', ') + tail + ']';
      return '\n' + shown.map(s => '  - ' + s.replace(/\n/g, '\n    ')).join('\n')
        + (tail ? '\n  ' + tail : '');
    }
    if (t === 'object') {
      if (depth >= 3) return '{…}';
      const keys = Object.keys(v);
      if (!keys.length) return '{}';
      const shown = keys.slice(0, 20).map(k => `${k}: ${this._formatMetadataValue(v[k], depth + 1)}`);
      const tail = keys.length > 20 ? `, … and ${keys.length - 20} more` : '';
      const anyComplex = shown.some(s => s.includes('\n') || s.length > 60);
      if (!anyComplex) return '{' + shown.join(', ') + tail + '}';
      return '\n' + shown.map(s => '  - ' + s.replace(/\n/g, '\n    ')).join('\n')
        + (tail ? '\n  ' + tail : '');
    }
    return String(v);
  },

  // ── Format-specific section builder for _copyAnalysis ─────────────────
  _copyAnalysisFormatSpecific(f, tp) {
    const parts = [];

    // ── Metadata ──
    if (f.metadata && typeof f.metadata === 'object' && Object.keys(f.metadata).length) {
      parts.push('\n## Metadata');
      for (const [k, v] of Object.entries(f.metadata)) {
        if (v === null || v === undefined || v === '' || v === '—') continue;
        const rendered = this._formatMetadataValue(v, 0);
        if (!rendered) continue;
        parts.push(`- **${k}:** ${rendered}`);
      }
    }

    // ── Security issues (autoExec for PE/ELF/Mach-O) ──
    if (f.autoExec && f.autoExec.length && !f.hasMacros) {
      parts.push('\n## Security Issues');
      for (const issue of f.autoExec) {
        const text = typeof issue === 'string' ? issue : `${issue.module}: ${(issue.patterns || []).join(', ')}`;
        parts.push(`- ⚠ ${text}`);
      }
    }

    // ── PE Binary ──
    if (f.peInfo) this._copyAnalysisPE(f.peInfo, parts, tp);

    // ── ELF Binary ──
    if (f.elfInfo) this._copyAnalysisELF(f.elfInfo, parts, tp);

    // ── Mach-O Binary ──
    if (f.machoInfo) this._copyAnalysisMachO(f.machoInfo, parts, tp);

    // ── X.509 Certificates ──
    if (f.x509Certs) this._copyAnalysisX509(f, parts, tp);

    // ── JAR / Java ──
    if (f.jarInfo) this._copyAnalysisJAR(f, parts, tp);

    // ── LNK-specific ──
    // The legacy writer only emitted target/args/workingDir; the LNK
    // renderer actually fills metadata with many more rich fields
    // (machineId, dropletMac, droidFile, msiProductCode, created,
    // modified, hotKey, iconLocation). Those come through the generic
    // metadata loop, but we also surface the three "headline" shortcut
    // pointers here as quotable inline values for analysts pasting into
    // a ticket.
    if (f.lnkTarget) parts.push(`\n## LNK Details\n- **Target:** \`${f.lnkTarget}\``);
    if (f.lnkArgs) parts.push(`- **Arguments:** \`${f.lnkArgs}\``);
    if (f.lnkWorkingDir) parts.push(`- **Working Dir:** \`${f.lnkWorkingDir}\``);

    // ── Email-specific ──
    if (f.authResults || f.spf || f.dkim || f.dmarc) {
      parts.push('\n## Email Authentication');
      if (f.authResults) parts.push(`- **Auth-Results:** ${f.authResults}`);
      if (f.spf) parts.push(`- **SPF:** ${f.spf}`);
      if (f.dkim) parts.push(`- **DKIM:** ${f.dkim}`);
      if (f.dmarc) parts.push(`- **DMARC:** ${f.dmarc}`);
    }

    // ── Format-family dispatch. Each helper is tolerant of its target
    //     data being absent; they only emit a section if something
    //     interesting is present, so ordering here is purely cosmetic. ──
    this._copyAnalysisPDF(f, parts, tp);
    this._copyAnalysisMSI(f, parts, tp);
    this._copyAnalysisOneNote(f, parts, tp);
    this._copyAnalysisRTF(f, parts, tp);
    this._copyAnalysisEML(f, parts, tp);
    this._copyAnalysisMSG(f, parts, tp);
    this._copyAnalysisHTML(f, parts, tp);
    this._copyAnalysisHTA(f, parts, tp);
    this._copyAnalysisSVG(f, parts, tp);
    this._copyAnalysisEVTX(f, parts, tp);
    this._copyAnalysisSQLite(f, parts, tp);
    this._copyAnalysisZIP(f, parts, tp);
    this._copyAnalysisISO(f, parts, tp);
    this._copyAnalysisImage(f, parts, tp);
    this._copyAnalysisPGP(f, parts, tp);
    this._copyAnalysisPlist(f, parts, tp);
    this._copyAnalysisOsascript(f, parts, tp);
    this._copyAnalysisOOXMLRels(f, parts, tp);

    return parts.length ? parts.join('\n') + '\n' : '';
  },

  // ── PE deep data ──────────────────────────────────────────────────────
  _copyAnalysisPE(pe, parts, tp) {
    parts.push('\n## PE Binary Details');

    // Headers
    if (pe.coff) {
      parts.push('\n### PE Headers');
      parts.push('| Field | Value |');
      parts.push('|-------|-------|');
      parts.push(`| Machine | ${tp(pe.coff.machineStr)} |`);
      parts.push(`| Sections | ${pe.coff.numSections} |`);
      parts.push(`| Timestamp | ${tp(pe.coff.timestampStr)} |`);
      if (pe.coff.characteristicsFlags) parts.push(`| Characteristics | ${tp(pe.coff.characteristicsFlags.join(', '))} |`);
      if (pe.optional) {
        parts.push(`| PE Format | ${tp(pe.optional.magicStr)} |`);
        parts.push(`| Entry Point | 0x${(pe.optional.entryPoint || 0).toString(16)} |`);
        parts.push(`| Image Base | 0x${(pe.optional.imageBase || 0).toString(16)} |`);
        parts.push(`| Subsystem | ${tp(pe.optional.subsystemStr)} |`);
        if (pe.optional.dllCharFlags) parts.push(`| DLL Characteristics | ${tp(pe.optional.dllCharFlags.join(', '))} |`);
      }
    }

    // Security features
    if (pe.security) {
      const s = pe.security;
      const feat = [];
      if (s.aslr !== undefined) feat.push(`ASLR: ${s.aslr ? '✅' : '❌'}`);
      if (s.dep !== undefined) feat.push(`DEP/NX: ${s.dep ? '✅' : '❌'}`);
      if (s.cfg !== undefined) feat.push(`CFG: ${s.cfg ? '✅' : '❌'}`);
      if (s.seh !== undefined) feat.push(`SEH: ${s.seh ? '✅' : '❌'}`);
      if (s.signed !== undefined) feat.push(`Signed: ${s.signed ? '✅' : '❌'}`);
      if (s.gs !== undefined) feat.push(`GS: ${s.gs ? '✅' : '❌'}`);
      if (s.highEntropyVA !== undefined) feat.push(`High Entropy VA: ${s.highEntropyVA ? '✅' : '❌'}`);
      if (feat.length) parts.push('\n### Security Features\n' + feat.join(', '));
    }

    // Version info / debug / imphash
    if (pe.versionInfo && Object.keys(pe.versionInfo).length) {
      parts.push('\n### Version Info');
      for (const [k, v] of Object.entries(pe.versionInfo)) parts.push(`- **${k}:** ${v}`);
    }
    if (pe.debugInfo && pe.debugInfo.pdbPath) parts.push(`\n**PDB Path:** \`${pe.debugInfo.pdbPath}\``);
    if (pe.debugInfo && pe.debugInfo.guid) parts.push(`**Debug GUID:** \`${pe.debugInfo.guid}\`${pe.debugInfo.age != null ? ` (age ${pe.debugInfo.age})` : ''}`);
    if (pe.imphash) parts.push(`**Imphash:** \`${pe.imphash}\``);
    // TLS callbacks — pointers to code that runs *before* the entry point,
    // a classic anti-debug / initial-exec hook. Surface the count so the
    // analyst knows to look at the TLS directory section.
    if (pe.tlsCallbacks && pe.tlsCallbacks.length) {
      parts.push(`**TLS Callbacks:** ${pe.tlsCallbacks.length}`);
    }
    // Overlay — bytes appended after the final PE section (often a
    // self-extracting payload or trailing signed blob).
    if (pe.overlayInfo && pe.overlayInfo.size) {
      parts.push(`**Overlay:** ${pe.overlayInfo.size} bytes at offset 0x${(pe.overlayInfo.offset||0).toString(16)}${pe.overlayInfo.entropy != null ? ` (entropy ${pe.overlayInfo.entropy.toFixed(2)})` : ''}`);
    }

    // Section table
    if (pe.sections && pe.sections.length) {
      parts.push('\n### Sections');
      parts.push('| Name | VirtSize | RawSize | Entropy | Flags |');
      parts.push('|------|----------|---------|---------|-------|');
      for (const s of pe.sections) {
        const entropy = s.entropy !== undefined ? s.entropy.toFixed(2) : '—';
        const flags = (s.charFlags || []).join(', ') || tp(s.characteristics);
        parts.push(`| ${tp(s.name)} | 0x${(s.virtualSize||0).toString(16)} | 0x${(s.rawSize||0).toString(16)} | ${entropy} | ${tp(flags)} |`);
      }
    }

    // Imports (prioritize suspicious)
    if (pe.imports && pe.imports.length) {
      parts.push(`\n### Imports (${pe.imports.length} DLLs)`);
      const suspicious = [];
      const normal = [];
      for (const imp of pe.imports) {
        const dll = imp.dllName || imp.dll || imp.name || '?';
        const funcs = imp.functions || [];
        const susp = funcs.filter(fn => fn.isSuspicious);
        if (susp.length) {
          suspicious.push(`**${dll}** — ⚠ ${susp.map(fn => fn.name).join(', ')}${funcs.length > susp.length ? ` + ${funcs.length - susp.length} others` : ''}`);
        } else {
          normal.push(`**${dll}** (${funcs.length}) — ${funcs.slice(0, 8).map(fn => fn.name).join(', ')}${funcs.length > 8 ? '…' : ''}`);
        }
      }
      if (suspicious.length) {
        parts.push('\n**Suspicious imports:**');
        for (const s of suspicious) parts.push(`- ${s}`);
      }
      // Show normal imports if we have budget
      const normalLimit = Math.max(5, 30 - suspicious.length);
      if (normal.length) {
        parts.push('\n**Other imports:**');
        for (const n of normal.slice(0, normalLimit)) parts.push(`- ${n}`);
        if (normal.length > normalLimit) parts.push(`- … and ${normal.length - normalLimit} more DLLs`);
      }
    }

    // Exports
    if (pe.exports && pe.exports.names && pe.exports.names.length) {
      const ex = pe.exports;
      parts.push(`\n### Exports (${ex.numNames || ex.names.length} functions)`);
      if (ex.dllName) parts.push(`**DLL name:** ${ex.dllName}`);
      const names = ex.names.slice(0, 30).map(n => n.name || `Ordinal#${n.ordinal}`);
      parts.push(names.join(', ') + (ex.names.length > 30 ? `… (+${ex.names.length - 30})` : ''));
    }

    // Rich Header
    if (pe.richHeader && pe.richHeader.entries && pe.richHeader.entries.length) {
      parts.push(`\n### Rich Header (XOR key: 0x${(pe.richHeader.xorKey||0).toString(16)})`);
      parts.push('| CompID | BuildID | Count |');
      parts.push('|--------|---------|-------|');
      for (const e of pe.richHeader.entries.slice(0, 20)) {
        parts.push(`| ${e.compId} | ${e.buildId} | ${e.count} |`);
      }
      if (pe.richHeader.entries.length > 20) parts.push(`… and ${pe.richHeader.entries.length - 20} more`);
    }

    // Authenticode Certificates
    if (pe.certificates && pe.certificates.length) {
      parts.push(`\n### Authenticode Certificates (${pe.certificates.length})`);
      for (const c of pe.certificates) {
        const label = (c.subject && c.subject.CN) || (c.subject && c.subject.O) || 'Certificate';
        parts.push(`\n**${label}**`);
        parts.push('| Field | Value |');
        parts.push('|-------|-------|');
        if (c.subjectStr) parts.push(`| Subject | ${tp(c.subjectStr)} |`);
        if (c.issuerStr) parts.push(`| Issuer | ${tp(c.issuerStr)} |`);
        if (c.serialNumber) parts.push(`| Serial | ${tp(c.serialNumber)} |`);
        if (c.notBeforeStr) parts.push(`| Not Before | ${tp(c.notBeforeStr)} |`);
        if (c.notAfterStr) parts.push(`| Not After | ${tp(c.notAfterStr)} |`);
        let pk = c.publicKeyAlgorithm || '';
        if (c.publicKeySize) pk += ` ${c.publicKeySize}-bit`;
        if (pk) parts.push(`| Public Key | ${tp(pk)} |`);
        if (c.signatureAlgorithm) parts.push(`| Signature | ${tp(c.signatureAlgorithm)} |`);
        if (c.isSelfSigned) parts.push(`| Self-Signed | Yes |`);
        if (c.isCA) parts.push(`| CA | Yes |`);
      }
    }

    // Resources
    if (pe.resources && pe.resources.length) {
      parts.push(`\n### Resources (${pe.resources.length} types)`);
      for (const r of pe.resources.slice(0, 20)) {
        parts.push(`- ${r.typeName || 'Type#' + r.id}${r.count ? ' (' + r.count + ' entries)' : ''}`);
      }
    }

    // Data Directories
    if (pe.dataDirectories && pe.dataDirectories.length) {
      const active = pe.dataDirectories.filter(d => d.size > 0);
      if (active.length) {
        parts.push('\n### Data Directories');
        parts.push('| Directory | RVA | Size |');
        parts.push('|-----------|-----|------|');
        for (const d of active) {
          parts.push(`| ${tp(d.name)} | 0x${(d.rva||0).toString(16)} | 0x${(d.size||0).toString(16)} |`);
        }
      }
    }
  },

  // ── ELF deep data ─────────────────────────────────────────────────────
  _copyAnalysisELF(elf, parts, tp) {
    parts.push('\n## ELF Binary Details');

    // Header
    if (elf.header || elf.ident) {
      parts.push('\n### ELF Header');
      parts.push('| Field | Value |');
      parts.push('|-------|-------|');
      if (elf.ident) {
        parts.push(`| Class | ${tp(elf.ident.classStr)} |`);
        parts.push(`| Endianness | ${tp(elf.ident.dataStr)} |`);
        if (elf.ident.osabiStr) parts.push(`| OS/ABI | ${tp(elf.ident.osabiStr)} |`);
      }
      if (elf.header) {
        parts.push(`| Type | ${tp(elf.header.typeStr)} |`);
        parts.push(`| Machine | ${tp(elf.header.machineStr)} |`);
        parts.push(`| Entry Point | 0x${(elf.header.entry || 0).toString(16)} |`);
      }
      if (elf.interpreter) parts.push(`| Interpreter | ${tp(elf.interpreter)} |`);
    }

    // Security features
    if (elf.security) {
      const s = elf.security;
      const feat = [];
      if (s.relro) feat.push(`RELRO: ${s.relro}`);
      if (s.nx !== undefined) feat.push(`NX: ${s.nx ? '✅' : '❌'}`);
      if (s.pie !== undefined) feat.push(`PIE: ${s.pie ? '✅' : '❌'}`);
      if (s.canary !== undefined) feat.push(`Stack Canary: ${s.canary ? '✅' : '❌'}`);
      if (s.fortify !== undefined) feat.push(`Fortify: ${s.fortify ? '✅' : '❌'}`);
      if (s.stripped !== undefined) feat.push(`Stripped: ${s.stripped ? 'Yes' : 'No'}`);
      if (feat.length) parts.push('\n### Security Features\n' + feat.join(', '));
    }

    // Sections
    if (elf.sections && elf.sections.length) {
      parts.push(`\n### Sections (${elf.sections.length})`);
      parts.push('| Name | Type | Size | Entropy | Flags |');
      parts.push('|------|------|------|---------|-------|');
      for (const s of elf.sections.slice(0, 40)) {
        const entropy = s.entropy !== undefined ? s.entropy.toFixed(2) : '—';
        parts.push(`| ${tp(s.name)} | ${tp(s.typeStr)} | 0x${(s.size||0).toString(16)} | ${entropy} | ${tp(s.flagsStr)} |`);
      }
      if (elf.sections.length > 40) parts.push(`… and ${elf.sections.length - 40} more`);
    }

    // Segments
    if (elf.segments && elf.segments.length) {
      parts.push(`\n### Segments (${elf.segments.length})`);
      parts.push('| Type | Flags | FileSize | MemSize |');
      parts.push('|------|-------|----------|---------|');
      for (const s of elf.segments) {
        parts.push(`| ${tp(s.typeStr)} | ${tp(s.flagsStr)} | 0x${(s.filesz||0).toString(16)} | 0x${(s.memsz||0).toString(16)} |`);
      }
    }

    // Dynamic entries
    if (elf.dynamic && elf.dynamic.length) {
      const interesting = elf.dynamic.filter(d => d.tagName !== 'DT_NULL');
      parts.push(`\n### Dynamic Entries (${interesting.length})`);
      parts.push('| Tag | Value |');
      parts.push('|-----|-------|');
      for (const d of interesting.slice(0, 40)) {
        parts.push(`| ${tp(d.tagName)} | ${tp(d.valStr || d.val)} |`);
      }
      if (interesting.length > 40) parts.push(`… and ${interesting.length - 40} more`);
    }

    // Dynamic libraries
    if (elf.neededLibs && elf.neededLibs.length) {
      parts.push(`\n### Dynamic Libraries (${elf.neededLibs.length})`);
      parts.push(elf.neededLibs.join(', '));
    }

    // Symbols
    const allSyms = [...(elf.dynsyms || []), ...(elf.symtab || [])];
    if (allSyms.length) {
      const suspicious = allSyms.filter(s => s._suspicious || s._risky);
      const named = allSyms.filter(s => s.name && s.name.length > 0);
      parts.push(`\n### Symbols (${named.length} named)`);
      if (suspicious.length) {
        parts.push('\n**Suspicious symbols:**');
        for (const s of suspicious.slice(0, 30)) parts.push(`- ⚠ \`${s.name}\` (${s.type || ''} ${s.bind || ''})`);
        if (suspicious.length > 30) parts.push(`… and ${suspicious.length - 30} more`);
      }
      const otherNamed = named.filter(s => !s._suspicious && !s._risky).slice(0, 40);
      if (otherNamed.length) {
        parts.push('\n**Imported/Exported:**');
        parts.push(otherNamed.map(s => `\`${s.name}\``).join(', ') + (named.length > 40 + suspicious.length ? '…' : ''));
      }
    }

    // Notes
    if (elf.notes && elf.notes.length) {
      parts.push(`\n### Notes (${elf.notes.length})`);
      for (const n of elf.notes.slice(0, 10)) {
        parts.push(`- **${tp(n.name)}** (type ${n.type}): ${tp(n.desc || '')}`);
      }
    }

    // Version-needed entries (.gnu.version_r) — maps soname → required
    // symbol versions. Useful for matching a stripped binary to a distro's
    // glibc / libstdc++ release.
    if (elf.verneed && elf.verneed.length) {
      parts.push(`\n### Version Needs (${elf.verneed.length})`);
      for (const v of elf.verneed.slice(0, 20)) {
        const versions = (v.versions || []).map(vv => vv.name).join(', ');
        parts.push(`- **${tp(v.file || '?')}**${versions ? `: ${tp(versions)}` : ''}`);
      }
    }

    // Extracted string count — quick proxy for "how much plaintext is in
    // this binary" without dumping every string (that would blow the
    // budget).
    if (elf.stringCount != null) parts.push(`\n**Strings extracted:** ${elf.stringCount}`);
  },

  // ── Mach-O deep data ──────────────────────────────────────────────────
  _copyAnalysisMachO(mo, parts, tp) {
    parts.push('\n## Mach-O Binary Details');

    // Fat/Universal
    if (mo.fatHeader) {
      parts.push(`\n### Universal Binary (${mo.fatHeader.nfat_arch} architectures)`);
      if (mo.fatHeader.archs) {
        for (const a of mo.fatHeader.archs) parts.push(`- ${tp(a.cputypeStr)} (${tp(a.cpusubtypeStr)}), offset ${a.offset}, size ${a.size}`);
      }
    }

    // Header
    parts.push('\n### Mach-O Header');
    parts.push('| Field | Value |');
    parts.push('|-------|-------|');
    parts.push(`| CPU Type | ${tp(mo.cputypeStr)} (${tp(mo.cpusubtypeStr)}) |`);
    parts.push(`| File Type | ${tp(mo.filetypeStr)} — ${tp(mo.filetypeDesc)} |`);
    parts.push(`| Load Commands | ${mo.ncmds} |`);
    if (mo.flagsList && mo.flagsList.length) parts.push(`| Flags | ${tp(mo.flagsList.join(', '))} |`);
    if (mo.uuid) parts.push(`| UUID | ${mo.uuid} |`);
    if (mo.entryPoint != null) parts.push(`| Entry Point | 0x${mo.entryPoint.toString(16)} |`);
    if (mo.buildVersion) {
      parts.push(`| Platform | ${tp(mo.buildVersion.platform)} |`);
      parts.push(`| Min OS | ${tp(mo.buildVersion.minos)} |`);
      parts.push(`| SDK | ${tp(mo.buildVersion.sdk)} |`);
    }

    // Security features
    if (mo.security) {
      const s = mo.security;
      const feat = [];
      if (s.pie !== undefined) feat.push(`PIE: ${s.pie ? '✅' : '❌'}`);
      if (s.arc !== undefined) feat.push(`ARC: ${s.arc ? '✅' : '❌'}`);
      if (s.stackCanary !== undefined) feat.push(`Stack Canary: ${s.stackCanary ? '✅' : '❌'}`);
      if (s.nx !== undefined) feat.push(`NX: ${s.nx ? '✅' : '❌'}`);
      if (s.codeSign !== undefined) feat.push(`Code Signed: ${s.codeSign ? '✅' : '❌'}`);
      if (s.encrypted !== undefined) feat.push(`Encrypted: ${s.encrypted ? 'Yes' : 'No'}`);
      if (s.fortify !== undefined) feat.push(`Fortify: ${s.fortify ? '✅' : '❌'}`);
      if (feat.length) parts.push('\n### Security Features\n' + feat.join(', '));
    }

    // Segments & Sections
    if (mo.segments && mo.segments.length) {
      parts.push(`\n### Segments (${mo.segments.length})`);
      parts.push('| Segment | VMSize | FileSize | MaxProt | Sections |');
      parts.push('|---------|--------|----------|---------|----------|');
      for (const seg of mo.segments) {
        parts.push(`| ${tp(seg.segname)} | 0x${(seg.vmsize||0).toString(16)} | 0x${(seg.filesize||0).toString(16)} | ${tp(seg.maxprot)} | ${(seg.sections||[]).length} |`);
      }
      // List interesting sections
      const allSects = (mo.sections || []);
      if (allSects.length) {
        parts.push(`\n**Sections (${allSects.length}):** ` +
          allSects.slice(0, 30).map(s => `${s.segname},${s.sectname}`).join(' · ') +
          (allSects.length > 30 ? '…' : ''));
      }
    }

    // Dynamic libraries
    if (mo.dylibs && mo.dylibs.length) {
      parts.push(`\n### Dynamic Libraries (${mo.dylibs.length})`);
      for (const d of mo.dylibs.slice(0, 30)) {
        parts.push(`- ${tp(d.name)}${d.currentVersion ? ' v' + d.currentVersion : ''}`);
      }
      if (mo.dylibs.length > 30) parts.push(`… and ${mo.dylibs.length - 30} more`);
    }

    // Symbols
    if (mo.symbols && mo.symbols.length) {
      const suspicious = mo.symbols.filter(s => s._suspicious || s.category === 'suspicious');
      const named = mo.symbols.filter(s => s.name && s.name.length > 1);
      parts.push(`\n### Symbols (${named.length} named)`);
      if (suspicious.length) {
        parts.push('\n**Suspicious symbols:**');
        for (const s of suspicious.slice(0, 30)) parts.push(`- ⚠ \`${s.name}\``);
        if (suspicious.length > 30) parts.push(`… and ${suspicious.length - 30} more`);
      }
      const others = named.filter(s => !s._suspicious && s.category !== 'suspicious').slice(0, 40);
      if (others.length) {
        parts.push('\n**Imported/Exported:**');
        parts.push(others.map(s => `\`${s.name}\``).join(', ') + (named.length > 40 + suspicious.length ? '…' : ''));
      }
    }

    // Code Signature
    if (mo.codeSignature) {
      const cs = mo.codeSignature;
      parts.push('\n### Code Signature');
      if (cs.identifier) parts.push(`- **Identifier:** ${cs.identifier}`);
      if (cs.teamID) parts.push(`- **Team ID:** ${cs.teamID}`);
      if (cs.cdhash) parts.push(`- **CDHash:** ${cs.cdhash}`);
      if (cs.flags != null) parts.push(`- **Flags:** 0x${cs.flags.toString(16)}`);
    }

    // Code Signing Certificates (from codeSignatureInfo)
    const csInfo = mo.codeSignatureInfo || mo.codeSignature;
    const csCerts = csInfo && csInfo.certificates;
    if (csCerts && csCerts.length) {
      parts.push(`\n### Code Signing Certificates (${csCerts.length})`);
      for (const c of csCerts) {
        const label = (c.subject && c.subject.CN) || (c.subject && c.subject.O) || 'Certificate';
        parts.push(`\n**${label}**`);
        parts.push('| Field | Value |');
        parts.push('|-------|-------|');
        if (c.subjectStr) parts.push(`| Subject | ${tp(c.subjectStr)} |`);
        if (c.issuerStr) parts.push(`| Issuer | ${tp(c.issuerStr)} |`);
        if (c.serialNumber) parts.push(`| Serial | ${tp(c.serialNumber)} |`);
        if (c.notBeforeStr) parts.push(`| Not Before | ${tp(c.notBeforeStr)} |`);
        if (c.notAfterStr) parts.push(`| Not After | ${tp(c.notAfterStr)} |`);
        let pk = c.publicKeyAlgorithm || '';
        if (c.publicKeySize) pk += ` ${c.publicKeySize}-bit`;
        if (pk) parts.push(`| Public Key | ${tp(pk)} |`);
        if (c.signatureAlgorithm) parts.push(`| Signature | ${tp(c.signatureAlgorithm)} |`);
        if (c.isSelfSigned) parts.push(`| Self-Signed | Yes |`);
        if (c.isCA) parts.push(`| CA | Yes |`);
      }
    }

    // Entitlements
    if (mo.entitlements) {
      parts.push('\n### Entitlements');
      parts.push('```xml');
      parts.push(mo.entitlements.length > 1000 ? mo.entitlements.slice(0, 1000) + '\n… (truncated)' : mo.entitlements);
      parts.push('```');
    }

    // RPATHs
    if (mo.rpaths && mo.rpaths.length) {
      parts.push('\n### RPATHs');
      for (const r of mo.rpaths) parts.push(`- ${r}`);
    }

    // Exports trie — the count is a useful gauge of how public a dylib is.
    if (mo.exportsTrie && mo.exportsTrie.length != null) {
      const n = Array.isArray(mo.exportsTrie) ? mo.exportsTrie.length : mo.exportsTrie.length;
      if (n) parts.push(`\n**Exports trie:** ${n} symbols`);
    }

    // Weak dylibs — loadable but not required; sometimes used to hide
    // optional persistence paths.
    if (mo.weakDylibs && mo.weakDylibs.length) {
      parts.push(`\n### Weak Dylibs (${mo.weakDylibs.length})`);
      for (const d of mo.weakDylibs.slice(0, 20)) {
        parts.push(`- ${tp(typeof d === 'string' ? d : (d.name || ''))}`);
      }
    }

    // Linker options baked in via LC_LINKER_OPTION.
    if (mo.linkerOpts && mo.linkerOpts.length) {
      parts.push('\n### Linker Options');
      parts.push(mo.linkerOpts.join(' '));
    }
  },

  // ── X.509 deep data ───────────────────────────────────────────────────
  _copyAnalysisX509(f, parts, tp) {
    const certs = f.x509Certs || [];
    if (!certs.length) return;

    parts.push(`\n## X.509 Certificates (${certs.length})`);
    if (f.summary) parts.push(`*${f.summary}*`);

    for (let i = 0; i < certs.length; i++) {
      const c = certs[i];
      parts.push(`\n### Certificate ${i + 1}${c.subject.CN ? ': ' + c.subject.CN : ''}`);
      parts.push('| Field | Value |');
      parts.push('|-------|-------|');
      parts.push(`| Subject | ${tp(c.subjectStr)} |`);
      parts.push(`| Issuer | ${tp(c.issuerStr)} |`);
      parts.push(`| Version | v${c.version} |`);
      parts.push(`| Serial | ${tp(c.serialNumber)} |`);
      parts.push(`| Not Before | ${tp(c.notBeforeStr)} |`);
      parts.push(`| Not After | ${tp(c.notAfterStr)} |`);
      let pk = c.publicKeyAlgorithm;
      if (c.publicKeySize) pk += ` ${c.publicKeySize}-bit`;
      if (c.publicKeyCurve) pk += ` (${c.publicKeyCurve})`;
      parts.push(`| Public Key | ${tp(pk)} |`);
      parts.push(`| Signature | ${tp(c.signatureAlgorithm)} |`);
      if (c.isSelfSigned) parts.push('| Self-Signed | Yes |');
      if (c.isCA) parts.push('| CA | Yes |');

      // Extensions summary. Extension values are truncated at 800 chars
      // to keep the report compact, EXCEPT for Subject Alternative Name
      // (oid 2.5.29.17) which frequently carries 100+ hostnames — that
      // is the entire point of looking at the cert in DFIR, so we let
      // it run up to 2000 chars before truncating.
      if (c.extensions && c.extensions.length) {
        parts.push('\n**Extensions:**');
        for (const ext of c.extensions) {
          const isSAN = (ext.oid === '2.5.29.17') || (ext.name === 'Subject Alternative Name');
          const limit = isSAN ? 2000 : 800;
          let val = ext.value || '';
          if (val.length > limit) val = val.slice(0, limit) + '…';
          parts.push(`- **${ext.name || ext.oid}**${ext.critical ? ' (CRITICAL)' : ''}: ${val}`);
        }
      }
    }

    // Detections from x509 findings
    if (f.detections && f.detections.length) {
      parts.push('\n### Certificate Issues');
      for (const d of f.detections) {
        parts.push(`- **${d.name}** [${(d.severity || 'info').toUpperCase()}]: ${d.description}`);
      }
    }
  },

  // ── JAR deep data ─────────────────────────────────────────────────────
  _copyAnalysisJAR(f, parts, tp) {
    const j = f.jarInfo;
    if (!j) return;

    parts.push('\n## JAR Details');

    // Manifest
    if (j.manifest && j.manifest.attrs && Object.keys(j.manifest.attrs).length) {
      parts.push('\n### MANIFEST.MF');
      for (const [k, v] of Object.entries(j.manifest.attrs)) {
        parts.push(`- **${k}:** ${v}`);
      }
    }

    // Suspicious APIs
    if (j.suspiciousAPIs && j.suspiciousAPIs.length) {
      parts.push(`\n### Suspicious APIs (${j.suspiciousAPIs.length})`);
      const seen = new Set();
      for (const s of j.suspiciousAPIs.slice(0, 30)) {
        const key = s.api;
        if (seen.has(key)) continue;
        seen.add(key);
        parts.push(`- ⚠ **${tp(s.api)}** [${(s.severity||'medium').toUpperCase()}]: ${tp(s.desc)}${s.mitre ? ' (' + s.mitre + ')' : ''}`);
      }
      if (j.suspiciousAPIs.length > 30) parts.push(`… and ${j.suspiciousAPIs.length - 30} more`);
    }

    // Obfuscation
    if (j.obfuscation && j.obfuscation.length) {
      parts.push('\n### Obfuscation Indicators');
      for (const o of j.obfuscation) parts.push(`- 🔒 ${o}`);
    }

    // Classes
    if (j.classes && j.classes.length) {
      parts.push(`\n### Classes (${j.classes.length})`);
      const display = j.classes.slice(0, 30).map(c => `\`${c}\``);
      parts.push(display.join(', ') + (j.classes.length > 30 ? `… (+${j.classes.length - 30})` : ''));
    }

    // Dependencies
    if (j.dependencies && j.dependencies.length) {
      parts.push(`\n### Dependencies (${j.dependencies.length})`);
      parts.push(j.dependencies.slice(0, 30).join(', ') + (j.dependencies.length > 30 ? '…' : ''));
    }

    // Config files
    if (j.configFiles && j.configFiles.length) {
      parts.push('\n### Config Files');
      for (const c of j.configFiles) parts.push(`- ${c}`);
    }

    // Main-Class — the executable jar entry point is a detection primitive.
    if (j.manifest && j.manifest.mainClass) {
      parts.push(`\n**Main-Class:** \`${tp(j.manifest.mainClass)}\``);
    }

    // Entry count / total compressed size — quick sanity check against
    // filesize.
    if (j.entryCount != null) parts.push(`**Entries:** ${j.entryCount}`);

    // Embedded JARs (jar-in-jar, e.g. Spring Boot / Shaded) — each one
    // is a separately-analysable payload.
    if (j.embeddedJars && j.embeddedJars.length) {
      parts.push(`\n### Embedded JARs (${j.embeddedJars.length})`);
      for (const ej of j.embeddedJars.slice(0, 20)) {
        const name = typeof ej === 'string' ? ej : (ej.name || ej.path || '?');
        parts.push(`- \`${tp(name)}\``);
      }
    }

    // Signing certificates — same shape as PE authenticode certs; print
    // fingerprints so the analyst can compare against known-good CAs.
    if (j.signingCerts && j.signingCerts.length) {
      parts.push(`\n### Signing Certificates (${j.signingCerts.length})`);
      for (const c of j.signingCerts) {
        const label = (c.subject && c.subject.CN) || c.subjectStr || 'Certificate';
        parts.push(`- **${tp(label)}**${c.issuerStr ? ` issued by ${tp(c.issuerStr)}` : ''}${c.sha256 ? ` (SHA-256: \`${c.sha256}\`)` : ''}`);
      }
    }
  },

  // ── PDF deep data ─────────────────────────────────────────────────────
  // PDF metadata is mostly scalars (encrypted/pages/acroFormPresent/xfa)
  // already visible in the generic metadata table; the value-add here is
  // the JavaScript bodies, embedded-file inventory, and the XFA packet
  // list — none of which render well via the generic formatter.
  _copyAnalysisPDF(f, parts, tp) {
    const m = f.metadata || {};
    // Only emit if there's at least one interesting PDF-specific field.
    if (!(m.pdfJavaScripts || m.embeddedFiles || m.xfa || m.xfaPackets ||
          m.acroFormPresent || m.encrypted || m.pages)) return;
    parts.push('\n## PDF Details');

    // JavaScript — the single most analysis-worthy surface in a PDF.
    const js = m.pdfJavaScripts || [];
    if (js.length) {
      parts.push(`\n### JavaScript Scripts (${js.length})`);
      for (const s of js) {
        parts.push(`\n**${tp(s.trigger || 'script')}** — ${s.size || 0} bytes${s.hash ? ` · hash \`${s.hash}\`` : ''}`);
        if (s.suspicious && s.suspicious.length) {
          parts.push(`⚠ Suspicious patterns: ${s.suspicious.join(', ')}`);
        }
        if (s.source) {
          const src = s.source.length > 800 ? s.source.slice(0, 800) + '\n… (truncated)' : s.source;
          parts.push('```javascript\n' + src + '\n```');
        }
      }
    }

    // Embedded files — attachments the PDF will offer to save/launch.
    const ef = m.embeddedFiles || [];
    if (ef.length) {
      parts.push(`\n### Embedded Files (${ef.length})`);
      parts.push('| Name | MIME | Size | Hash |');
      parts.push('|------|------|------|------|');
      for (const e of ef.slice(0, 30)) {
        parts.push(`| ${tp(e.name || '?')} | ${tp(e.mime || '—')} | ${e.size || 0} | ${e.hash ? '`' + e.hash + '`' : '—'} |`);
      }
      if (ef.length > 30) parts.push(`… and ${ef.length - 30} more`);
    }

    // XFA — dynamic forms use their own XFA packets; list them so the
    // analyst sees whether it's the form-stuffing or full-xfa variant.
    if (m.xfa || m.xfaPackets) {
      parts.push('\n### XFA Forms');
      if (m.xfa) parts.push(`- **Has XFA:** ${m.xfa}`);
      if (m.xfaPackets) {
        const pkts = Array.isArray(m.xfaPackets) ? m.xfaPackets : [m.xfaPackets];
        parts.push(`- **Packets:** ${pkts.map(p => typeof p === 'string' ? p : (p.name || '?')).join(', ')}`);
      }
    }
  },

  // ── MSI deep data ─────────────────────────────────────────────────────
  // MSI's CustomAction rows, authenticode string, and embedded CAB list
  // all go into externalRefs (note-tagged) rather than structured arrays
  // on metadata, so this helper filters externalRefs by note-prefix to
  // reconstruct the table the MSI viewer shows.
  _copyAnalysisMSI(f, parts, tp) {
    const m = f.metadata || {};
    const looksMsi = m.customActionCount != null || m.authenticode || m.binaryStreamCount != null ||
                     m.embeddedCabs || m.binaryStreamSniff;
    if (!looksMsi) return;
    parts.push('\n## MSI Details');

    if (m.customActionCount != null) parts.push(`- **CustomAction rows:** ${m.customActionCount}`);
    if (m.binaryStreamCount != null) parts.push(`- **Binary streams:** ${m.binaryStreamCount}`);
    if (m.authenticode) parts.push(`- **Authenticode:** ${m.authenticode}`);

    // CustomAction rows — the note on externalRefs entries is the
    // `CustomAction:` prefix used by msi-renderer.
    const ca = (f.externalRefs || []).filter(r =>
      r && r.note && /custom\s*action/i.test(r.note));
    if (ca.length) {
      parts.push(`\n### Custom Actions (${ca.length})`);
      for (const e of ca.slice(0, 30)) {
        parts.push(`- [${(e.severity || 'info').toUpperCase()}] ${tp(e.note || '')}: \`${tp(e.url || '')}\``);
      }
      if (ca.length > 30) parts.push(`… and ${ca.length - 30} more`);
    }

    if (m.embeddedCabs) {
      parts.push('\n### Embedded CABs');
      const cabs = Array.isArray(m.embeddedCabs) ? m.embeddedCabs : [m.embeddedCabs];
      for (const c of cabs) parts.push(`- ${tp(typeof c === 'string' ? c : (c.name || JSON.stringify(c)))}`);
    }
  },

  // ── OneNote deep data ─────────────────────────────────────────────────
  _copyAnalysisOneNote(f, parts, tp) {
    const m = f.metadata || {};
    if (m.embeddedObjectCount == null && !m.fileDataStoreGuids && !m.sniffedBlobTypes) return;
    parts.push('\n## OneNote Details');
    if (m.embeddedObjectCount != null) parts.push(`- **Embedded objects:** ${m.embeddedObjectCount}`);
    if (m.sniffedBlobTypes) {
      const t = typeof m.sniffedBlobTypes === 'string' ? m.sniffedBlobTypes
        : Array.isArray(m.sniffedBlobTypes) ? m.sniffedBlobTypes.join(', ') : JSON.stringify(m.sniffedBlobTypes);
      parts.push(`- **Sniffed blob types:** ${tp(t)}`);
    }
    if (m.fileDataStoreGuids) {
      const g = Array.isArray(m.fileDataStoreGuids) ? m.fileDataStoreGuids : [m.fileDataStoreGuids];
      parts.push(`- **FileDataStore GUIDs (${g.length}):** ${g.slice(0, 10).join(', ')}${g.length > 10 ? '…' : ''}`);
    }
  },

  // ── RTF deep data — OLE objects live on externalRefs ─────────────────
  _copyAnalysisRTF(f, parts, tp) {
    const ole = (f.externalRefs || []).filter(r =>
      r && r.note && /ole\s*object|objdata|objclass/i.test(r.note));
    if (!ole.length) return;
    parts.push(`\n## RTF OLE Objects (${ole.length})`);
    for (const e of ole.slice(0, 20)) {
      parts.push(`- [${(e.severity || 'info').toUpperCase()}] ${tp(e.note || '')}: \`${tp(e.url || '')}\``);
    }
    if (ole.length > 20) parts.push(`… and ${ole.length - 20} more`);
  },

  // ── EML deep data — Cc / Reply-To / attachment list ───────────────────
  _copyAnalysisEML(f, parts, tp) {
    const m = f.metadata || {};
    // Only emit if we actually have EML-specific fields beyond what the
    // generic email-auth block covers. (The metadata block above already
    // prints cc/replyTo/attachments via the recursive formatter; we add a
    // clean tabular attachment view here.)
    const atts = Array.isArray(m.attachments) ? m.attachments : null;
    if (!atts || !atts.length) return;
    parts.push(`\n## Email Attachments (${atts.length})`);
    parts.push('| Name | Size |');
    parts.push('|------|------|');
    for (const a of atts.slice(0, 30)) {
      parts.push(`| ${tp(a.name || '(unnamed)')} | ${a.size != null ? a.size : '—'} |`);
    }
    if (atts.length > 30) parts.push(`… and ${atts.length - 30} more`);
  },

  // ── MSG deep data — recipient / subject headline + attachments ───────
  _copyAnalysisMSG(f, parts, tp) {
    const m = f.metadata || {};
    // MSG renderers set title/creator/created on metadata; attachments
    // flow through externalRefs with type IOC.ATTACHMENT (string guard).
    const atts = (f.externalRefs || []).filter(r =>
      r && (r.type === (typeof IOC !== 'undefined' && IOC.ATTACHMENT) ||
            (r.note && /attachment/i.test(r.note))));
    if (!m.title && !m.creator && !atts.length) return;
    parts.push('\n## Outlook Message Details');
    if (m.title) parts.push(`- **Subject:** ${tp(m.title)}`);
    if (m.creator) parts.push(`- **Sender:** ${tp(m.creator)}`);
    if (m.created) parts.push(`- **Created:** ${tp(m.created)}`);
    if (atts.length) {
      parts.push(`\n### Attachments (${atts.length})`);
      for (const a of atts.slice(0, 30)) {
        parts.push(`- \`${tp(a.url || '')}\`${a.note ? ` — ${tp(a.note)}` : ''}`);
      }
      if (atts.length > 30) parts.push(`… and ${atts.length - 30} more`);
    }
  },

  // ── HTML deep data — forms, title ─────────────────────────────────────
  _copyAnalysisHTML(f, parts, tp) {
    const m = f.metadata || {};
    // Form entries live in externalRefs (PATTERN type) with notes like
    // "Form with password field" — scan for those.
    const forms = (f.externalRefs || []).filter(r =>
      r && r.url && /form/i.test(r.url + ' ' + (r.note || '')));
    if (!m.title && !forms.length) return;
    parts.push('\n## HTML Details');
    if (m.title) parts.push(`- **Title:** ${tp(m.title)}`);
    if (forms.length) {
      parts.push(`\n### Forms / credential harvesting indicators (${forms.length})`);
      for (const fm of forms.slice(0, 20)) {
        parts.push(`- [${(fm.severity || 'info').toUpperCase()}] ${tp(fm.url)}${fm.note ? ` — ${tp(fm.note)}` : ''}`);
      }
      if (forms.length > 20) parts.push(`… and ${forms.length - 20} more`);
    }
  },

  // ── HTA deep data — scripts / external refs ───────────────────────────
  _copyAnalysisHTA(f, parts, tp) {
    // HTA renderer doesn't set a distinctive top-level marker; only emit
    // when the file extension is .hta AND there are externalRefs flagged
    // as script-language indicators.
    const fileName = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase();
    if (!fileName.endsWith('.hta')) return;
    const scripts = (f.externalRefs || []).filter(r =>
      r && (r.note && /hta|script|vbscript|jscript/i.test(r.note)));
    if (!scripts.length) return;
    parts.push(`\n## HTA Script Indicators (${scripts.length})`);
    for (const s of scripts.slice(0, 20)) {
      parts.push(`- [${(s.severity || 'info').toUpperCase()}] ${tp(s.note || '')}: \`${tp(s.url || '')}\``);
    }
    if (scripts.length > 20) parts.push(`… and ${scripts.length - 20} more`);
  },

  // ── SVG deep data — script/handler/foreignObject counts ──────────────
  _copyAnalysisSVG(f, parts, tp) {
    const fileName = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase();
    if (!fileName.endsWith('.svg')) return;
    // SVG renderer emits notes like "script element", "event handler",
    // "foreignObject", "external reference" — bucket them.
    const refs = f.externalRefs || [];
    const buckets = { script: 0, handler: 0, external: 0, foreignObject: 0 };
    const samples = { script: [], handler: [], external: [], foreignObject: [] };
    for (const r of refs) {
      const note = String(r.note || '') + ' ' + String(r.url || '');
      let key = null;
      if (/\bscript\b/i.test(note)) key = 'script';
      else if (/handler|on[a-z]+\s*=/i.test(note)) key = 'handler';
      else if (/foreign\s*object/i.test(note)) key = 'foreignObject';
      else if (/xlink|external|href=/i.test(note)) key = 'external';
      if (key) {
        buckets[key]++;
        if (samples[key].length < 3) samples[key].push(r);
      }
    }
    const totals = Object.values(buckets).reduce((a, b) => a + b, 0);
    if (!totals) return;
    parts.push('\n## SVG Active-Content Inventory');
    parts.push(`- **Scripts:** ${buckets.script}`);
    parts.push(`- **Event handlers:** ${buckets.handler}`);
    parts.push(`- **foreignObject elements:** ${buckets.foreignObject}`);
    parts.push(`- **External references:** ${buckets.external}`);
    for (const [k, arr] of Object.entries(samples)) {
      if (arr.length) {
        parts.push(`\n**${k} samples:**`);
        for (const r of arr) parts.push(`- \`${tp(r.url || '')}\`${r.note ? ` — ${tp(r.note)}` : ''}`);
      }
    }
  },

  // ── EVTX deep data — event-id distribution from PATTERN entries ──────
  _copyAnalysisEVTX(f, parts, tp) {
    const m = f.metadata || {};
    if (m.eventCount == null && !m.channels && !m.providers) return;
    parts.push('\n## Windows Event Log Details');
    if (m.eventCount != null) parts.push(`- **Events:** ${m.eventCount}`);
    if (m.firstEvent) parts.push(`- **First event:** ${tp(m.firstEvent)}`);
    if (m.lastEvent) parts.push(`- **Last event:** ${tp(m.lastEvent)}`);
    if (m.channels) parts.push(`- **Channels:** ${tp(m.channels)}`);
    if (m.providers) parts.push(`- **Providers:** ${tp(m.providers)}`);

    // Derive the notable-event-ids table from PATTERN entries that match
    // the evtx-renderer's "Event NNNN: description" template.
    const evtRe = /^Event\s+(\d+)\s*:\s*(.+?)(?:\s*\((\d+)\s*events?\))?$/i;
    const hits = [];
    for (const r of (f.externalRefs || [])) {
      if (!r || !r.url) continue;
      const m2 = evtRe.exec(r.url);
      if (!m2) continue;
      hits.push({ id: m2[1], desc: m2[2], count: m2[3] ? parseInt(m2[3], 10) : 1, severity: r.severity || 'info' });
    }
    if (hits.length) {
      parts.push(`\n### Notable Event IDs (${hits.length})`);
      parts.push('| ID | Count | Severity | Description |');
      parts.push('|----|-------|----------|-------------|');
      for (const h of hits.slice(0, 40)) {
        parts.push(`| ${h.id} | ${h.count} | ${(h.severity || 'info').toUpperCase()} | ${tp(h.desc)} |`);
      }
      if (hits.length > 40) parts.push(`… and ${hits.length - 40} more`);
    }
  },

  // ── SQLite deep data — schema / version / browser-profile stats ──────
  _copyAnalysisSQLite(f, parts, tp) {
    const m = f.metadata || {};
    if (!m.sqliteVersion && m.tables == null && !m.browserType) return;
    parts.push('\n## SQLite Database Details');
    if (m.sqliteVersion) parts.push(`- **SQLite version:** ${tp(m.sqliteVersion)}`);
    if (m.pageSize != null) parts.push(`- **Page size:** ${m.pageSize}`);
    if (m.pageCount != null) parts.push(`- **Page count:** ${m.pageCount}`);
    if (m.browserType) parts.push(`- **Browser:** ${tp(m.browserType)}`);
    if (m.urlCount != null) parts.push(`- **URL count:** ${m.urlCount}`);

    // m.tables may be a number, a string ("42 tables"), or an array.
    if (Array.isArray(m.tables)) {
      parts.push(`\n### Tables (${m.tables.length})`);
      for (const t of m.tables.slice(0, 30)) {
        if (typeof t === 'string') parts.push(`- \`${tp(t)}\``);
        else parts.push(`- \`${tp(t.name || '?')}\`${t.rowCount != null ? ` (${t.rowCount} rows)` : ''}${t.columns ? ` — ${tp((t.columns || []).join(', '))}` : ''}`);
      }
      if (m.tables.length > 30) parts.push(`… and ${m.tables.length - 30} more`);
    } else if (m.tables != null) {
      parts.push(`- **Tables:** ${tp(m.tables)}`);
    }
  },

  // ── ZIP deep data — compression ratio (zip-bomb indicator), dangerous files ──
  _copyAnalysisZIP(f, parts, tp) {
    const m = f.metadata || {};
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (!['zip', 'jar', 'war', 'ear', 'apk'].includes(ext)) return;
    const hasInteresting = m.compressedSize != null || m.decompressedSize != null ||
      m.compressionRatio != null || m.zipEntries;
    const dangerFiles = (f.externalRefs || []).filter(r =>
      r && r.note && /danger|executable|macro|dropper/i.test(r.note));
    if (!hasInteresting && !dangerFiles.length) return;
    parts.push('\n## ZIP Archive Details');
    if (m.compressedSize != null) parts.push(`- **Compressed size:** ${m.compressedSize}`);
    if (m.decompressedSize != null) parts.push(`- **Decompressed size:** ${m.decompressedSize}`);
    if (m.compressionRatio != null) {
      const r = typeof m.compressionRatio === 'number' ? m.compressionRatio.toFixed(1) : m.compressionRatio;
      parts.push(`- **Compression ratio:** ${r}${typeof m.compressionRatio === 'number' && m.compressionRatio > 100 ? '×  ⚠ (zip-bomb indicator)' : ''}`);
    }
    if (dangerFiles.length) {
      parts.push(`\n### Suspicious Entries (${dangerFiles.length})`);
      for (const d of dangerFiles.slice(0, 30)) {
        parts.push(`- [${(d.severity || 'info').toUpperCase()}] \`${tp(d.url || '')}\`${d.note ? ` — ${tp(d.note)}` : ''}`);
      }
      if (dangerFiles.length > 30) parts.push(`… and ${dangerFiles.length - 30} more`);
    }
  },

  // ── ISO deep data — volume info ───────────────────────────────────────
  _copyAnalysisISO(f, parts, tp) {
    const m = f.metadata || {};
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (!['iso', 'img'].includes(ext)) return;
    if (!m.title && !m.creator && !m.subject) return;
    parts.push('\n## ISO / Disk Image Details');
    if (m.title) parts.push(`- **Volume ID:** ${tp(m.title)}`);
    if (m.creator) parts.push(`- **Publisher:** ${tp(m.creator)}`);
    if (m.subject) parts.push(`- **Subject:** ${tp(m.subject)}`);
  },

  // ── Image deep data — EXIF / dims / format ───────────────────────────
  _copyAnalysisImage(f, parts, tp) {
    const m = f.metadata || {};
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (!['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'ico', 'heic'].includes(ext)) return;
    if (!m.exif && !m.format && m.size == null) return;
    parts.push('\n## Image Details');
    if (m.format) parts.push(`- **Format:** ${tp(m.format)}`);
    if (m.size != null) parts.push(`- **Raw byte size:** ${m.size}`);
    if (m.exif) {
      const e = typeof m.exif === 'string' ? m.exif : JSON.stringify(m.exif);
      parts.push(`- **EXIF preview:** ${tp(e.length > 200 ? e.slice(0, 200) + '…' : e)}`);
    }
  },

  // ── PGP deep data — non-standard detections[] / formatSpecific[] ─────
  _copyAnalysisPGP(f, parts, tp) {
    const fs = Array.isArray(f.formatSpecific) ? f.formatSpecific : null;
    const dets = Array.isArray(f.detections) ? f.detections : null;
    if (!fs && !dets) return;
    if (fs && fs.length) {
      parts.push('\n## PGP Key Info');
      parts.push('| Field | Value |');
      parts.push('|-------|-------|');
      for (const kv of fs) {
        parts.push(`| ${tp(kv.label || '')} | ${tp(kv.value || '')} |`);
      }
    }
    if (dets && dets.length) {
      parts.push('\n### PGP Detections');
      for (const d of dets) {
        parts.push(`- **${tp(d.name || '')}** [${(d.severity || 'info').toUpperCase()}]${d.description ? ': ' + tp(d.description) : ''}`);
      }
    }
  },

  // ── Plist deep data — LaunchAgent persistence, URL schemes, UTIs ─────
  _copyAnalysisPlist(f, parts, tp) {
    const m = f.metadata || {};
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (ext !== 'plist') return;
    const interesting = m.label || m.bundleIdentifier || m.bundleName ||
      m.executable || m.program || m.programArguments || m.runAtLoad != null ||
      m.keepAlive != null || (Array.isArray(m.watchPaths) && m.watchPaths.length);
    const sigs = Array.isArray(f.signatureMatches) ? f.signatureMatches : [];
    if (!interesting && !sigs.length) return;
    parts.push('\n## Property List Details');
    if (m.label) parts.push(`- **Label:** ${tp(m.label)}`);
    if (m.bundleIdentifier) parts.push(`- **Bundle ID:** ${tp(m.bundleIdentifier)}`);
    if (m.bundleName) parts.push(`- **Bundle Name:** ${tp(m.bundleName)}`);
    if (m.executable) parts.push(`- **Executable:** \`${tp(m.executable)}\``);
    if (m.program) parts.push(`- **Program:** \`${tp(m.program)}\``);
    if (m.programArguments) {
      const a = Array.isArray(m.programArguments) ? m.programArguments.join(' ') : m.programArguments;
      parts.push(`- **Program Arguments:** \`${tp(a)}\``);
    }
    if (m.runAtLoad != null) parts.push(`- **RunAtLoad:** ${m.runAtLoad}`);
    if (m.keepAlive != null) parts.push(`- **KeepAlive:** ${JSON.stringify(m.keepAlive)}`);
    if (m.watchPaths) {
      const wp = Array.isArray(m.watchPaths) ? m.watchPaths : [m.watchPaths];
      parts.push(`- **WatchPaths:** ${wp.join(', ')}`);
    }
    if (sigs.length) {
      parts.push('\n### Persistence / Behaviour Signatures');
      for (const s of sigs.slice(0, 20)) {
        const name = s.name || s.rule || s.id || '?';
        parts.push(`- **${tp(name)}**${s.severity ? ` [${s.severity.toUpperCase()}]` : ''}${s.description ? ': ' + tp(s.description) : ''}`);
      }
    }
  },

  // ── Osascript deep data — decompiled source + signatures ─────────────
  _copyAnalysisOsascript(f, parts, tp) {
    const m = f.metadata || {};
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (!['scpt', 'applescript', 'jxa'].includes(ext)) return;
    const sigs = Array.isArray(f.signatureMatches) ? f.signatureMatches : [];
    if (!m.format && m.hasEmbeddedSource == null && m.lineCount == null && !sigs.length) return;
    parts.push('\n## Osascript Details');
    if (m.format) parts.push(`- **Format:** ${tp(m.format)}`);
    if (m.hasEmbeddedSource != null) parts.push(`- **Embedded source:** ${m.hasEmbeddedSource}`);
    if (m.lineCount != null) parts.push(`- **Lines:** ${m.lineCount}`);
    if (m.size != null) parts.push(`- **Size:** ${m.size}`);
    if (sigs.length) {
      parts.push(`\n### Behaviour Signatures (${sigs.length})`);
      for (const s of sigs.slice(0, 20)) {
        const name = s.name || s.rule || s.id || '?';
        parts.push(`- **${tp(name)}**${s.severity ? ` [${s.severity.toUpperCase()}]` : ''}${s.description ? ': ' + tp(s.description) : ''}`);
      }
    }
  },

  // ── OOXML relationship-scanner results (PPTX / XLSX) ─────────────────
  // These flow through externalRefs from OoxmlRelScanner, tagged with
  // notes like "OOXML Relationship (External)" — filter by that so the
  // scanner output is grouped separately from document-body IOCs.
  _copyAnalysisOOXMLRels(f, parts, tp) {
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (!['pptx', 'xlsx', 'pptm', 'xlsm'].includes(ext)) return;
    const rels = (f.externalRefs || []).filter(r =>
      r && r.note && /ooxml|relationship|external\s*target/i.test(r.note));
    if (!rels.length) return;
    parts.push(`\n## OOXML Relationships (${rels.length})`);
    parts.push('| Severity | Note | Target |');
    parts.push('|----------|------|--------|');
    for (const r of rels.slice(0, 40)) {
      parts.push(`| ${(r.severity || 'info').toUpperCase()} | ${tp(r.note || '')} | \`${tp(r.url || '')}\` |`);
    }
    if (rels.length > 40) parts.push(`… and ${rels.length - 40} more`);
  },

  // ── Downloads ────────────────────────────────────────────────────────────
  _downloadMacros() {
    const f = this.findings;
    const rawName = (this._fileMeta && this._fileMeta.name) || 'macros';
    const base = rawName.replace(/\.[^.]+$/, '') || 'macros';

    const mods = (f.modules || []).filter(m => m.source);
    if (mods.length) {
      const sep = '='.repeat(60), lines = [];
      for (const mod of mods) { lines.push(`' ${sep}`); lines.push(`' VBA Module: ${mod.name}`); lines.push(`' ${sep}`); lines.push(mod.source); lines.push(''); }
      this._downloadText(lines.join('\n'), base + '_macros.txt', 'text/plain;charset=utf-8');
      this._toast('Macro source downloaded');
    } else if (f.rawBin && f.rawBin.length) {
      const blob = new Blob([f.rawBin], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = base + '_vbaProject.bin';
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      URL.revokeObjectURL(url); this._toast('Raw VBA binary downloaded — use olevba/oledump to inspect');
    } else { this._toast('No macro data available', 'error'); }
  },


  // Download every script extracted from the current PDF as a single .js
  // file, with each script separated by a banner comment naming its trigger
  // (e.g. "/OpenAction", "Page 3: K"). Mirrors _downloadMacros' layout so
  // analysts can diff or grep across both macro and PDF-JS dumps the same
  // way. Per-script downloads live on the individual rows in the PDF JS
  // sidebar section — this button is the bulk-export convenience.
  _downloadPdfScripts() {
    const f = this.findings;
    const scripts = (f.metadata && f.metadata.pdfJavaScripts) || [];
    if (!scripts.length) { this._toast('No PDF JavaScript to download', 'error'); return; }
    const rawName = (this._fileMeta && this._fileMeta.name) || 'pdf';
    const base = rawName.replace(/\.[^.]+$/, '') || 'pdf';

    const sep = '='.repeat(60);
    const lines = [];
    scripts.forEach((s, idx) => {
      lines.push(`// ${sep}`);
      lines.push(`// PDF JavaScript #${idx + 1} — ${s.trigger}`);
      lines.push(`// size: ${s.size} bytes · hash: ${s.hash}`);
      if (s.suspicious && s.suspicious.length) {
        lines.push(`// suspicious: ${s.suspicious.join(', ')}`);
      }
      lines.push(`// ${sep}`);
      lines.push(s.source);
      lines.push('');
    });
    this._downloadText(lines.join('\n'), base + '_pdf_javascript.js', 'text/javascript;charset=utf-8');
    this._toast(`${scripts.length} PDF script${scripts.length !== 1 ? 's' : ''} downloaded`);
  },

  _downloadExtracted(refs, fileName) {
    const base = (fileName || 'extracted').replace(/\.[^.]+$/, '');
    const lines = ['Type\tValue\tSeverity', ...refs.map(r => `${r.type}\t${r.url}\t${r.severity}`)];
    this._downloadText(lines.join('\n'), base + '_extracted.txt', 'text/plain;charset=utf-8');
    this._toast('Extracted data downloaded');
  },

  // ── Generic download helpers ─────────────────────────────────────────────
  // Single choke-point for turning text/JSON into a browser download. Every
  // exporter (and the three legacy _downloadMacros/_downloadPdfScripts/
  // _downloadExtracted sites) routes through here so the blob-and-anchor
  // dance lives in exactly one place and object URLs are consistently
  // revoked.
  _downloadText(text, filename, mime) {
    const blob = new Blob([text], { type: mime || 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    // Give the browser a tick to pick up the href before we revoke it.
    setTimeout(() => URL.revokeObjectURL(url), 0);
  },

  _downloadJson(obj, filename) {
    this._downloadText(JSON.stringify(obj, null, 2), filename, 'application/json');
  },

  // Build "<base>.<suffix>.<ext>" from the loaded file's name, stripping the
  // original extension and sanitising to word-chars so the filename is safe
  // on every OS.
  _exportFilename(suffix, ext) {
    const raw = (this._fileMeta && this._fileMeta.name) || 'loupe';
    const stem = raw.replace(/\.[^.]+$/, '') || 'loupe';
    const safe = stem.replace(/[^\w.\-]+/g, '_');
    return `${safe}.${suffix}.${ext}`;
  },


  // ── Clipboard ────────────────────────────────────────────────────────────
  _copyToClipboard(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => this._toast('Copied!')).catch(() => this._copyFallback(text));
    } else this._copyFallback(text);
  },

  _copyFallback(text) {
    const ta = document.createElement('textarea'); ta.value = text; ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0;';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try { document.execCommand('copy'); this._toast('Copied!'); } catch (e) { this._toast('Copy failed', 'error'); }
    document.body.removeChild(ta);
  },

  // ── Clear file ────────────────────────────────────────────────────────────
  _clearFile() {
    // Reset viewer
    document.getElementById('page-container').innerHTML = '';
    // Restore drop zone
    const dz = document.getElementById('drop-zone');
    dz.className = ''; dz.innerHTML = '';
    const icon = document.createElement('span'); icon.className = 'dz-icon'; icon.textContent = '📄'; dz.appendChild(icon);
    const txt = document.createElement('div'); txt.className = 'dz-text'; txt.textContent = 'Drop a file here to analyse'; dz.appendChild(txt);
    const sub = document.createElement('div'); sub.className = 'dz-sub'; sub.textContent = 'Office · PDFs · executables · emails · archives · certificates · scripts · binaries · Java · SVG · and 60+ formats · 100% offline'; dz.appendChild(sub);
    // Hide close button + viewer toolbar. Breadcrumbs get hidden via
    // _renderBreadcrumbs() below once _fileMeta is cleared.
    document.getElementById('btn-close').classList.add('hidden');
    document.getElementById('viewer-toolbar').classList.add('hidden');

    document.getElementById('doc-search').value = '';
    if (this._clearSearch) this._clearSearch();
    // Close sidebar and clear its content; reset locked width for fresh auto-sizing.
    // Also clear the JAR-specific sidebar-clamp marker so the next (non-JAR) file
    // gets the regular 50vw ceiling back.
    if (this.sidebarOpen) this._toggleSidebar();
    document.body.classList.remove('jar-active');
    document.getElementById('sidebar').style.width = '';

    document.getElementById('sb-body').innerHTML = '';
    document.getElementById('sb-risk').className = 'sb-risk risk-low';
    document.getElementById('sb-risk-title').textContent = 'No threats detected';
    // Reset state
    this.findings = null; this.fileHashes = null;
    this._fileBuffer = null; this._yaraBuffer = null; this._yaraResults = null;
    this._fileMeta = null;
    // Clear navigation stack and hide breadcrumbs
    this._navStack = [];
    if (this._renderBreadcrumbs) this._renderBreadcrumbs();

    // Remove pan cursor
    document.getElementById('viewer').classList.remove('pannable');
    // Reset zoom
    this._setZoom(100);
  },

  // ── Viewer pan (click-and-drag) ───────────────────────────────────────────
  _setupViewerPan() {
    const viewer = document.getElementById('viewer');
    let isPanning = false, startX, startY, scrollL, scrollT;
    viewer.addEventListener('mousedown', e => {
      // Only pan if a document is loaded (drop zone hidden) and not on interactive elements
      const dz = document.getElementById('drop-zone');
      if (!dz.classList.contains('has-document')) return;
      const tag = e.target.tagName;
      if (tag === 'BUTTON' || tag === 'INPUT' || tag === 'A' || tag === 'TEXTAREA' || tag === 'SELECT') return;
      if (e.target.closest('.zoom-fab') || e.target.closest('.tb-btn') || e.target.closest('.copy-url-btn')) return;
      // Don't pan when the user is starting a text selection on any
      // text-centric viewer. These containers have their own scrolling and
      // should let the browser's native text-select gesture win.
      if (
        e.target.closest('.plaintext-scroll') ||
        e.target.closest('.sheet-content-area') ||
        e.target.closest('.csv-scroll') ||
        e.target.closest('.evtx-scroll') ||
        e.target.closest('.evtx-detail-pane') ||
        e.target.closest('.csv-detail-pane') ||
        e.target.closest('.sqlite-scroll') ||
        e.target.closest('.eml-body') ||
        e.target.closest('.rtf-text') ||
        e.target.closest('.doc-text') ||
        e.target.closest('.msg-body') ||
        e.target.closest('.user-select-text') ||
        e.target.closest('pre') ||
        e.target.closest('code')
      ) return;
      // Never start a pan if the user is already in a drag-select gesture.
      if (window.getSelection && window.getSelection().toString().length > 0) return;
      isPanning = true;

      startX = e.clientX; startY = e.clientY;
      scrollL = viewer.scrollLeft; scrollT = viewer.scrollTop;
      viewer.classList.add('panning');
      e.preventDefault();
    });
    window.addEventListener('mousemove', e => {
      if (!isPanning) return;
      viewer.scrollLeft = scrollL - (e.clientX - startX);
      viewer.scrollTop = scrollT - (e.clientY - startY);
    });
    window.addEventListener('mouseup', () => {
      if (!isPanning) return;
      isPanning = false;
      viewer.classList.remove('panning');
    });

    // ── Double-click to select whole non-whitespace token ─────────────────
    // Browsers stop word-selection at punctuation (/, ., :, -, _, =), which
    // splits URLs, hashes, base64 blobs, file paths, registry keys, etc.
    // In "codey" viewers (monospace font) we expand the native selection
    // outward to the nearest whitespace/block boundary so the full token
    // highlights even when it wraps across multiple visual lines via
    // word-break: break-all.
    this._setupViewerDoubleClickSelect(viewer);
  },

  // ── Double-click whole-token select in monospace viewers ─────────────────
  _setupViewerDoubleClickSelect(viewer) {
    const WS_RE = /[\s\u00a0\u200b\u200c\u200d]/;

    const isBoundaryEl = el => {
      if (!el || el.nodeType !== 1) return false;
      if (el.tagName === 'BR' || el.tagName === 'HR') return true;
      const d = getComputedStyle(el).display;
      return d && d !== 'inline' && d !== 'inline-block' && d !== 'inline-flex' && d !== 'contents';
    };

    const findBlockAncestor = (el, root) => {
      let cur = el;
      while (cur && cur !== root) {
        if (cur.nodeType === 1) {
          const t = cur.tagName;
          if (t === 'PRE' || t === 'CODE' || t === 'TD' || t === 'TH' || t === 'LI' ||
              t === 'P'   || t === 'DT'   || t === 'DD' || t === 'BLOCKQUOTE') return cur;
          const d = getComputedStyle(cur).display;
          if (d && d !== 'inline' && d !== 'inline-block' && d !== 'inline-flex' && d !== 'contents') return cur;
        }
        cur = cur.parentNode;
      }
      return root;
    };

    // Walk to previous text node in document order, bounded by `block`.
    // Returns null if a block/BR boundary is crossed first.
    const prevTextInBlock = (node, block) => {
      const walker = document.createTreeWalker(block, NodeFilter.SHOW_ALL);
      walker.currentNode = node;
      let cur;
      while ((cur = walker.previousNode())) {
        if (cur.nodeType === 1 && isBoundaryEl(cur)) return null;
        if (cur.nodeType === Node.TEXT_NODE) return cur;
      }
      return null;
    };

    const nextTextInBlock = (node, block) => {
      const walker = document.createTreeWalker(block, NodeFilter.SHOW_ALL);
      walker.currentNode = node;
      let cur;
      while ((cur = walker.nextNode())) {
        if (cur.nodeType === 1 && isBoundaryEl(cur)) return null;
        if (cur.nodeType === Node.TEXT_NODE) return cur;
      }
      return null;
    };

    viewer.addEventListener('dblclick', e => {
      const target = e.target;
      if (!target || target.nodeType !== 1) return;

      // Skip form controls — they have their own selection model.
      const tag = target.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
      if (target.isContentEditable || target.closest('[contenteditable="true"]')) return;

      // Skip the hex dump: there, a single byte/offset is the useful unit.
      if (target.closest('.hex-dump')) return;

      // Only apply in "codey" contexts — elements rendered in a monospace
      // font. This covers URLs in IOCs, hashes, paths, registry keys,
      // base64 blobs, plaintext viewer, pre/code blocks, table cells in
      // evtx/csv/sqlite detail panes, PGP/x509 fingerprints, etc.
      const ff = getComputedStyle(target).fontFamily || '';
      if (!/mono|consolas|menlo|monaco|courier|fira|sf mono/i.test(ff)) return;

      const sel = window.getSelection();
      if (!sel || sel.rangeCount === 0) return;
      const range = sel.getRangeAt(0);
      if (range.collapsed) return;

      const block = findBlockAncestor(target, viewer);

      // Expand start backward through non-whitespace.
      let startNode = range.startContainer;
      let startOffset = range.startOffset;
      while (startNode && startNode.nodeType === Node.TEXT_NODE) {
        const data = startNode.data;
        while (startOffset > 0 && !WS_RE.test(data[startOffset - 1])) startOffset--;
        if (startOffset > 0) break;
        const prev = prevTextInBlock(startNode, block);
        if (!prev) break;
        startNode = prev;
        startOffset = prev.data.length;
      }

      // Expand end forward through non-whitespace.
      let endNode = range.endContainer;
      let endOffset = range.endOffset;
      while (endNode && endNode.nodeType === Node.TEXT_NODE) {
        const data = endNode.data;
        while (endOffset < data.length && !WS_RE.test(data[endOffset])) endOffset++;
        if (endOffset < data.length) break;
        const next = nextTextInBlock(endNode, block);
        if (!next) break;
        endNode = next;
        endOffset = 0;
      }

      try {
        const newRange = document.createRange();
        newRange.setStart(startNode, startOffset);
        newRange.setEnd(endNode, endOffset);
        sel.removeAllRanges();
        sel.addRange(newRange);
      } catch (_) { /* bail quietly on any DOM hiccup */ }
    });
  },

  // ── Zoom / theme / loading / toast ────────────────────────────────────────

  _setZoom(z) {
    this.zoom = Math.min(200, Math.max(50, z));
    document.getElementById('zoom-level').textContent = `${this.zoom}%`;
    document.getElementById('page-container').style.transform = `scale(${this.zoom / 100})`;
  },

  // ── Theme system ─────────────────────────────────────────────────────────
  // Apply a theme by id. Looks the theme up in THEMES, wipes any previous
  // `theme-*` + `dark` classes, then re-applies the new ones. Persists the
  // choice to localStorage (same pattern as uploaded YARA rules) so the user
  // sees the same theme across reloads.
  _setTheme(id) {
    const theme = THEMES.find(t => t.id === id) || THEMES.find(t => t.id === _DEFAULT_THEME);
    const body = document.body;
    // Remove any previously-applied theme-* class
    for (const cls of Array.from(body.classList)) {
      if (cls.startsWith('theme-')) body.classList.remove(cls);
    }
    body.classList.add('theme-' + theme.id);
    body.classList.toggle('dark', !!theme.dark);
    this.dark = !!theme.dark;     // kept for any legacy callers
    this._themeId = theme.id;

    // Reflect the active theme in the toolbar button icon
    const btn = document.getElementById('btn-theme');
    if (btn) {
      btn.textContent = theme.icon;
      btn.setAttribute('title', `Theme: ${theme.label} — click to change`);
    }

    // Mark the active row in the dropdown (if built)
    const menu = document.getElementById('theme-menu');
    if (menu) {
      for (const item of menu.querySelectorAll('.tb-menu-item')) {
        item.classList.toggle('tb-menu-item-active', item.dataset.themeId === theme.id);
      }
    }

    try { localStorage.setItem(_THEME_PREF_KEY, theme.id); } catch (_) { /* storage blocked */ }
  },

  // Build the theme dropdown once from the THEMES registry. Subsequent calls
  // no-op — the menu's visibility is toggled via .hidden, not rebuilt.
  _buildThemeMenu() {
    const menu = document.getElementById('theme-menu');
    if (!menu || menu.dataset.built === '1') return;
    menu.dataset.built = '1';
    menu.setAttribute('role', 'menu');
    for (const t of THEMES) {
      const item = document.createElement('button');
      item.type = 'button';
      item.className = 'tb-menu-item';
      item.dataset.themeId = t.id;
      item.setAttribute('role', 'menuitemradio');
      item.innerHTML =
        `<span class="tb-menu-icon">${t.icon}</span>` +
        `<span class="tb-menu-label">${t.label}</span>` +
        `<span class="tb-menu-check">✓</span>`;
      item.addEventListener('click', () => {
        this._setTheme(t.id);
        this._closeThemeMenu();
      });
      menu.appendChild(item);
    }
  },

  _openThemeMenu() {
    this._buildThemeMenu();
    const menu = document.getElementById('theme-menu');
    const btn = document.getElementById('btn-theme');
    if (!menu || !btn) return;
    menu.classList.remove('hidden');
    btn.setAttribute('aria-expanded', 'true');
    // Re-mark the active row in case it changed elsewhere
    for (const item of menu.querySelectorAll('.tb-menu-item')) {
      item.classList.toggle('tb-menu-item-active', item.dataset.themeId === this._themeId);
    }
    // Dismiss on outside click / Escape
    const onDocDown = e => {
      if (menu.contains(e.target) || btn.contains(e.target)) return;
      this._closeThemeMenu();
    };
    const onEsc = e => { if (e.key === 'Escape') this._closeThemeMenu(); };
    this._themeMenuDismiss = () => {
      document.removeEventListener('mousedown', onDocDown, true);
      document.removeEventListener('keydown', onEsc, true);
      this._themeMenuDismiss = null;
    };
    // Defer to avoid catching the originating click
    setTimeout(() => {
      document.addEventListener('mousedown', onDocDown, true);
      document.addEventListener('keydown', onEsc, true);
    }, 0);
  },

  _closeThemeMenu() {
    const menu = document.getElementById('theme-menu');
    const btn = document.getElementById('btn-theme');
    if (menu) menu.classList.add('hidden');
    if (btn) btn.setAttribute('aria-expanded', 'false');
    if (this._themeMenuDismiss) this._themeMenuDismiss();
  },

  _toggleThemeMenu() {
    const menu = document.getElementById('theme-menu');
    if (menu && !menu.classList.contains('hidden')) this._closeThemeMenu();
    else this._openThemeMenu();
  },

  // Apply the persisted theme on startup. Call this in App.init().
  _initTheme() {
    let saved = null;
    try { saved = localStorage.getItem(_THEME_PREF_KEY); } catch (_) { /* storage blocked */ }
    const id = (saved && THEMES.some(t => t.id === saved)) ? saved : _DEFAULT_THEME;
    this._setTheme(id);
  },

  // Deprecated — kept as a thin alias so any external callers still work.
  _toggleTheme() { this._toggleThemeMenu(); },


  _setLoading(on) {
    document.getElementById('loading').classList.toggle('hidden', !on);
  },

  _toast(msg, type = 'info') {
    const t = document.getElementById('toast'); t.textContent = msg;
    t.className = type === 'error' ? 'toast-error' : ''; t.classList.remove('hidden');
    setTimeout(() => t.classList.add('hidden'), 3000);
  },

  _fmtBytes(b) {
    if (!b || b < 1024) return (b || 0) + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    return (b / 1048576).toFixed(1) + ' MB';
  },

  // ── Document content search ───────────────────────────────────────────────
  _setupSearch() {
    const input = document.getElementById('doc-search');
    const countEl = document.getElementById('doc-search-count');
    const prevBtn = document.getElementById('doc-search-prev');
    const nextBtn = document.getElementById('doc-search-next');
    let marks = [], currentIdx = -1;

    const clearHighlights = () => {
      for (const m of document.querySelectorAll('#page-container mark.search-hl')) {
        const p = m.parentNode;
        p.replaceChild(document.createTextNode(m.textContent), m);
        p.normalize();
      }
      marks = []; currentIdx = -1;
      countEl.textContent = '';
    };

    const doSearch = () => {
      clearHighlights();
      const q = input.value.trim();
      if (!q) return;

      const container = document.getElementById('page-container');
      const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT);
      const textNodes = [];
      while (walker.nextNode()) textNodes.push(walker.currentNode);

      const qLower = q.toLowerCase();
      for (const node of textNodes) {
        const text = node.textContent;
        const lower = text.toLowerCase();
        let idx = lower.indexOf(qLower);
        if (idx === -1) continue;
        const frag = document.createDocumentFragment();
        let lastIdx = 0;
        while (idx !== -1) {
          if (idx > lastIdx) frag.appendChild(document.createTextNode(text.slice(lastIdx, idx)));
          const mark = document.createElement('mark');
          mark.className = 'search-hl';
          mark.textContent = text.slice(idx, idx + q.length);
          frag.appendChild(mark);
          lastIdx = idx + q.length;
          idx = lower.indexOf(qLower, lastIdx);
        }
        if (lastIdx < text.length) frag.appendChild(document.createTextNode(text.slice(lastIdx)));
        node.parentNode.replaceChild(frag, node);
      }

      marks = Array.from(document.querySelectorAll('#page-container mark.search-hl'));
      if (marks.length) {
        currentIdx = 0;
        marks[0].classList.add('search-hl-current');
        marks[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
        countEl.textContent = `1 / ${marks.length}`;
      } else {
        countEl.textContent = '0 results';
      }
    };

    const goTo = (dir) => {
      if (!marks.length) return;
      marks[currentIdx].classList.remove('search-hl-current');
      currentIdx = (currentIdx + dir + marks.length) % marks.length;
      marks[currentIdx].classList.add('search-hl-current');
      marks[currentIdx].scrollIntoView({ behavior: 'smooth', block: 'center' });
      countEl.textContent = `${currentIdx + 1} / ${marks.length}`;
    };

    let timer;
    input.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(doSearch, 300);
    });

    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        if (e.shiftKey) goTo(-1); else goTo(1);
      }
      if (e.key === 'Escape') {
        input.value = '';
        clearHighlights();
        input.blur();
      }
    });

    // Navigation button handlers
    prevBtn.addEventListener('click', () => goTo(-1));
    nextBtn.addEventListener('click', () => goTo(1));

    // Expose clear for _clearFile
    this._clearSearch = clearHighlights;
  },

  // ── Help / About dialog ───────────────────────────────────────────────────
  _openHelpDialog() {
    // Don't open twice
    if (document.querySelector('.help-overlay')) return;

    const version = typeof LOUPE_VERSION !== 'undefined' ? LOUPE_VERSION : 'dev';

    const overlay = document.createElement('div');
    overlay.className = 'help-overlay';
    overlay.innerHTML = `
      <div class="help-dialog">
        <div class="help-header">
          <span>🕵🏻 Loupe <small>v${version}</small></span>
          <button class="help-close" title="Close (Esc)">✕</button>
        </div>
        <div class="help-body">
          <p class="help-tagline">A 100% offline, single-file security analyser for suspicious files.<br>No server, no uploads, no tracking — just drop a file and inspect it.</p>

          <h3>Keyboard Shortcuts</h3>
          <table class="help-kbd-table">
            <tr><td><kbd class="help-kbd">S</kbd></td><td>Toggle security sidebar</td></tr>
            <tr><td><kbd class="help-kbd">Y</kbd></td><td>Open YARA rule editor</td></tr>
            <tr><td><kbd class="help-kbd">?</kbd> / <kbd class="help-kbd">H</kbd></td><td>Open this help dialog</td></tr>
            <tr><td><kbd class="help-kbd">Ctrl+F</kbd></td><td>Focus document search</td></tr>
            <tr><td><kbd class="help-kbd">Ctrl+V</kbd></td><td>Paste file from clipboard</td></tr>
            <tr><td><kbd class="help-kbd">Esc</kbd></td><td>Close dialog / clear search</td></tr>
          </table>

          <h3>Links</h3>
          <p>
            <a href="https://github.com/Loupe-tools/Loupe/releases/latest/download/loupe.html" target="_blank" rel="noopener">Download Loupe</a>
            ·
            <a href="https://github.com/Loupe-tools/Loupe" target="_blank" rel="noopener">GitHub Repository</a>
            ·
            <a href="https://loupe.tools/" target="_blank" rel="noopener">Live Demo</a>
          </p>

          <div style="text-align:center;margin-top:12px;">
            <a class="help-update-btn" href="https://loupe.tools/?v=v${version}" target="_blank" rel="noopener">🔄 Check for Updates</a>
          </div>

          <p style="margin-top:1.2em;opacity:0.5;font-size:0.85em;">Licensed under the GNU General Public License v3.0</p>
        </div>
      </div>`;

    document.body.appendChild(overlay);

    // Close handlers
    const close = () => this._closeHelpDialog();
    overlay.querySelector('.help-close').addEventListener('click', close);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });

    this._helpEscHandler = e => { if (e.key === 'Escape') close(); };
    document.addEventListener('keydown', this._helpEscHandler);
  },

  _closeHelpDialog() {
    const overlay = document.querySelector('.help-overlay');
    if (overlay) overlay.remove();
    if (this._helpEscHandler) {
      document.removeEventListener('keydown', this._helpEscHandler);
      this._helpEscHandler = null;
    }
  },

  // ── Version check (from ?v= query parameter) ─────────────────────────────
  _checkVersionParam() {
    const params = new URLSearchParams(window.location.search);
    const incoming = params.get('v');
    if (!incoming) return;

    // Strip leading 'v' prefix if present
    const remoteVersion = incoming.replace(/^v/, '');
    const localVersion = typeof LOUPE_VERSION !== 'undefined' ? LOUPE_VERSION : 'dev';

    // Clean the URL so the popup doesn't reappear on refresh
    const cleanUrl = window.location.pathname + window.location.hash;
    window.history.replaceState(null, '', cleanUrl);

    // Compare versions (YYYYMMDD.HHMM format — numeric comparison works)
    const remoteNum = parseFloat(remoteVersion) || 0;
    const localNum = parseFloat(localVersion) || 0;
    const isUpToDate = localVersion !== 'dev' && remoteNum >= localNum;

    // Build popup
    const overlay = document.createElement('div');
    overlay.className = 'help-overlay update-check-overlay';

    if (isUpToDate) {
      overlay.innerHTML = `
        <div class="update-dialog">
          <div class="update-icon update-icon-ok">✅</div>
          <h2 class="update-title">You're up to date!</h2>
          <p class="update-detail">Your version <strong>v${remoteVersion}</strong> matches the latest release.</p>
          <button class="update-btn update-btn-close">Close</button>
        </div>`;
    } else {
      const dlUrl = 'https://github.com/Loupe-tools/Loupe/releases/latest/download/loupe.html';
      overlay.innerHTML = `
        <div class="update-dialog">
          <div class="update-icon update-icon-new">🔄</div>
          <h2 class="update-title">New update available!</h2>
          <p class="update-detail">You have <strong>v${remoteVersion}</strong> — the latest version is <strong>v${localVersion}</strong>.</p>
          <div class="update-actions">
            <a class="update-btn update-btn-download" href="${dlUrl}" target="_blank" rel="noopener">⬇️ Download Latest</a>
            <button class="update-btn update-btn-close">Close</button>
          </div>
        </div>`;
    }

    document.body.appendChild(overlay);

    // Close handlers
    const close = () => { if (overlay.parentNode) overlay.remove(); };
    overlay.querySelector('.update-btn-close').addEventListener('click', close);
    overlay.addEventListener('click', e => { if (e.target === overlay) close(); });
    const escHandler = e => { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', escHandler); } };
    document.addEventListener('keydown', escHandler);
  },

  // ════════════════════════════════════════════════════════════════════════
  // Export menu — shared entrypoint for every on-disk / clipboard export
  // ════════════════════════════════════════════════════════════════════════
  //
  // The toolbar's `📤 Export ▾` button opens a single dropdown that hosts
  // six actions: two raw-file passthroughs (the only true download is
  // Save-raw-file, carried over from the legacy `💾 Save` pill), plus four
  // clipboard-bound threat-intel exports (STIX 2.1 bundle, MISP event,
  // IOCs as JSON, IOCs as CSV). Plaintext / Markdown report exports were
  // removed because they duplicated the ⚡ Summary toolbar button's output.
  // All click handlers are wrapped in a single try/catch that toasts
  // "Export failed — see console" so a broken exporter never silently
  // breaks the menu.
  //
  // Styling reuses `.tb-menu` / `.tb-menu-item` verbatim (same classes as
  // the theme picker) so all four Loupe themes render it correctly with
  // zero new CSS.

  // Items: [{ id, icon, label, separator?, action: fn }]
  // `id` lets _setExportEnabled per-item-disable future file-specific
  // entries; unused for now but worth having.
  // The ⚡ Summary toolbar button (outside the dropdown) already copies the
  // plaintext/markdown analysis report, so Save/Copy-plaintext/Copy-markdown
  // would be duplicates. Save-raw-file is the only true download; everything
  // else in the dropdown goes to the clipboard so analysts can paste straight
  // into a ticket / TIP.
  _getExportMenuItems() {
    return [
      { id: 'save-raw',  icon: '💾',  label: 'Save raw file',                action: () => this._saveContent() },
      { id: 'copy-raw',  icon: '📋',  label: 'Copy raw content',             action: () => this._copyContent() },
      { separator: true },
      { id: 'stix',      icon: '🧾',  label: 'Copy STIX 2.1 bundle (JSON)',  action: () => this._exportStix() },
      { id: 'misp',      icon: '🎯',  label: 'Copy MISP event (JSON)',       action: () => this._exportMisp() },
      { id: 'iocs-json', icon: '{…}', label: 'Copy IOCs as JSON',            action: () => this._exportIocsJson() },
      { id: 'iocs-csv',  icon: '🔢',  label: 'Copy IOCs as CSV',             action: () => this._exportIocsCsv() },
    ];
  },


  _buildExportMenu() {
    const menu = document.getElementById('export-menu');
    if (!menu || menu.dataset.built === '1') return;
    menu.dataset.built = '1';
    menu.setAttribute('role', 'menu');
    for (const item of this._getExportMenuItems()) {
      if (item.separator) {
        const sep = document.createElement('div');
        sep.className = 'tb-menu-separator';
        sep.setAttribute('role', 'separator');
        sep.style.cssText = 'height:1px;margin:4px 2px;background:currentColor;opacity:.12;';
        menu.appendChild(sep);
        continue;
      }
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'tb-menu-item';
      btn.dataset.exportId = item.id;
      btn.setAttribute('role', 'menuitem');
      btn.innerHTML =
        `<span class="tb-menu-icon">${item.icon}</span>` +
        `<span class="tb-menu-label">${item.label}</span>`;
      btn.addEventListener('click', () => {
        this._closeExportMenu();
        try {
          item.action();
        } catch (err) {
          console.error('Export failed:', err);
          this._toast('Export failed — see console', 'error');
        }
      });
      menu.appendChild(btn);
    }
  },

  _openExportMenu() {
    this._buildExportMenu();
    const menu = document.getElementById('export-menu');
    const btn = document.getElementById('btn-export');
    if (!menu || !btn) return;
    menu.classList.remove('hidden');
    btn.setAttribute('aria-expanded', 'true');
    const onDocDown = e => {
      if (menu.contains(e.target) || btn.contains(e.target)) return;
      this._closeExportMenu();
    };
    const onEsc = e => { if (e.key === 'Escape') this._closeExportMenu(); };
    this._exportMenuDismiss = () => {
      document.removeEventListener('mousedown', onDocDown, true);
      document.removeEventListener('keydown', onEsc, true);
      this._exportMenuDismiss = null;
    };
    setTimeout(() => {
      document.addEventListener('mousedown', onDocDown, true);
      document.addEventListener('keydown', onEsc, true);
    }, 0);
  },

  _closeExportMenu() {
    const menu = document.getElementById('export-menu');
    const btn = document.getElementById('btn-export');
    if (menu) menu.classList.add('hidden');
    if (btn) btn.setAttribute('aria-expanded', 'false');
    if (this._exportMenuDismiss) this._exportMenuDismiss();
  },

  _toggleExportMenu() {
    const menu = document.getElementById('export-menu');
    if (menu && !menu.classList.contains('hidden')) this._closeExportMenu();
    else this._openExportMenu();
  },

  // ════════════════════════════════════════════════════════════════════════
  // Threat-intel exporters — all copy to clipboard
  // ════════════════════════════════════════════════════════════════════════
  //
  // Every exporter here writes to the clipboard (no file dialog) so the
  // analyst's one-click flow is "Export → paste into ticket/TIP". The
  // ⚡ Summary button handles plaintext/Markdown reports, so we deliberately
  // don't duplicate that here. _saveContent() (💾 Save raw file) is the
  // only true download in the dropdown.

  _exportIocsJson() {
    if (!this.findings) { this._toast('No file loaded', 'error'); return; }
    const iocs = this._collectIocs();
    const payload = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      tool: { name: 'Loupe', version: (typeof LOUPE_VERSION !== 'undefined' ? LOUPE_VERSION : 'dev') },
      file: this._fileSourceRecord(),
      iocs: iocs.map(i => ({
        type: i.type, value: i.value, severity: i.severity || 'info',
        note: i.note || '', source: i.source || '',
      })),
    };
    this._copyToClipboard(JSON.stringify(payload, null, 2));
    this._toast(iocs.length
      ? `${iocs.length} IOC${iocs.length !== 1 ? 's' : ''} copied as JSON`
      : 'No IOCs — empty JSON copied');
  },

  _exportIocsCsv() {
    if (!this.findings) { this._toast('No file loaded', 'error'); return; }
    const iocs = this._collectIocs();
    const csv = this._buildIocsCsv(iocs);
    this._copyToClipboard(csv);
    this._toast(iocs.length
      ? `${iocs.length} IOC${iocs.length !== 1 ? 's' : ''} copied as CSV`
      : 'No IOCs — empty CSV copied');
  },

  _exportStix() {
    if (!this.findings) { this._toast('No file loaded', 'error'); return; }
    this._buildStixBundle().then(bundle => {
      this._copyToClipboard(JSON.stringify(bundle, null, 2));
      this._toast('STIX 2.1 bundle copied to clipboard');
    }).catch(err => {
      console.error('Export failed:', err);
      this._toast('Export failed — see console', 'error');
    });
  },

  _exportMisp() {
    if (!this.findings) { this._toast('No file loaded', 'error'); return; }
    const event = this._buildMispEvent();
    this._copyToClipboard(JSON.stringify(event, null, 2));
    this._toast('MISP event copied to clipboard');
  },


  // ════════════════════════════════════════════════════════════════════════
  // Shared IOC collection + CSV builder
  // ════════════════════════════════════════════════════════════════════════
  //
  // All threat-intel exporters (STIX, MISP, IOC JSON, IOC CSV) consume the
  // same flat list produced here. Each entry has a normalised STIX-style
  // sub-type in `.stixType` (e.g. 'url', 'ipv4', 'hash-sha256') so the
  // downstream builders don't re-implement classification.

  _collectIocs() {
    const f = this.findings || {};
    const allRefs = [...(f.externalRefs || []), ...(f.interestingStrings || [])];
    const detectionTypes = new Set([IOC.YARA, IOC.PATTERN, IOC.INFO]);
    const seen = new Set();
    const out = [];
    for (const r of allRefs) {
      if (!r || !r.url) continue;
      if (detectionTypes.has(r.type)) continue;       // detections live in `detections`, not here
      const key = r.type + '|' + r.url;
      if (seen.has(key)) continue;
      seen.add(key);
      const stixType = this._classifyIocForStix(r.type, r.url);
      out.push({
        type:     r.type,
        value:    r.url,
        severity: r.severity || 'info',
        note:     r.description || r.ruleName || '',
        source:   r._source || r.section || '',
        stixType, // may be null for unmappable types (skipped by STIX)
      });
    }
    out.sort((a, b) => (a.type + a.value).localeCompare(b.type + b.value));
    return out;
  },

  // Classify a Loupe IOC into a STIX/MISP-friendly sub-type. Anything the
  // caller doesn't explicitly recognise maps to `null` so the STIX builder
  // can skip it rather than fabricate a bogus pattern.
  _classifyIocForStix(iocType, value) {
    if (!value) return null;
    const v = String(value);
    if (iocType === IOC.URL) {
      // Some "URL" refs are bare domains / IPs — promote them so STIX/MISP
      // produce cleaner SCOs.
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'ipv4';
      if (/^[0-9a-f:]+$/i.test(v) && v.includes(':')) return 'ipv6';
      return 'url';
    }
    if (iocType === IOC.IP) {
      return v.includes(':') ? 'ipv6' : 'ipv4';
    }
    if (iocType === IOC.EMAIL) return 'email';
    if (iocType === IOC.HOSTNAME) return 'domain';
    if (iocType === IOC.HASH) {
      const h = v.trim().toLowerCase();
      if (/^[0-9a-f]{32}$/.test(h)) return 'hash-md5';
      if (/^[0-9a-f]{40}$/.test(h)) return 'hash-sha1';
      if (/^[0-9a-f]{64}$/.test(h)) return 'hash-sha256';
      return null;
    }
    if (iocType === IOC.FILE_PATH || iocType === IOC.UNC_PATH) return 'file-path';
    // Command-line, process, registry-key, username, MAC, attachment —
    // these don't have a clean STIX pattern. Returning null means the STIX
    // builder skips them (but CSV / JSON / MISP still include them as
    // text-category attributes).
    return null;
  },

  _buildIocsCsv(iocs) {
    // RFC 4180: fields containing ',', '"' or CR/LF are wrapped in double
    // quotes and embedded quotes are doubled. Sort order is done by caller
    // so diffing two exports of the same file is byte-stable.
    const q = (v) => {
      const s = v == null ? '' : String(v);
      if (/[",\r\n]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
      return s;
    };
    const lines = ['type,value,severity,note,source'];
    for (const i of iocs) {
      lines.push([q(i.type), q(i.value), q(i.severity || 'info'), q(i.note || ''), q(i.source || '')].join(','));
    }
    // BOM-less UTF-8; use CRLF per RFC 4180 for maximal Excel friendliness.
    return lines.join('\r\n') + '\r\n';
  },

  _fileSourceRecord() {
    const meta = this._fileMeta || {};
    const hashes = this.fileHashes || {};
    return {
      name: meta.name || null,
      size: meta.size || null,
      detectedType: (meta.name || '').split('.').pop().toLowerCase() || null,
      magic: meta.magic ? (meta.magic.label || null) : null,
      entropy: (meta.entropy !== undefined) ? Number(meta.entropy.toFixed(3)) : null,
      hashes: {
        md5: hashes.md5 || null,
        sha1: hashes.sha1 || null,
        sha256: hashes.sha256 || null,
      },
    };
  },

  // ════════════════════════════════════════════════════════════════════════
  // STIX 2.1 bundle builder
  // ════════════════════════════════════════════════════════════════════════
  //
  // Produces a self-contained STIX 2.1 bundle: one `identity` (Loupe itself
  // as producer), one `file` SCO with md5/sha1/sha256 hashes, one
  // `indicator` per supported IOC, and a `malware-analysis` `report` SDO
  // that ties everything together and lists YARA rule names in its
  // description. All object IDs are deterministic UUIDv5 values so
  // re-exporting the same file produces byte-identical IDs — TIPs dedupe
  // cleanly.

  async _buildStixBundle() {
    const model = this._fileSourceRecord();
    const f = this.findings || {};
    const iocs = this._collectIocs();
    const nowIso = new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z');
    const LOUPE_NS = 'f3a5c0de-1011-5a10-9abc-1a2b3c4d5e6f';
    const sha256 = (model.hashes && model.hashes.sha256) || '';

    const objects = [];

    // Producer identity (deterministic — constant UUIDv5 of "Loupe" in the
    // Loupe namespace so every export shares the same identity id).
    const identityId = 'identity--' + (await this._uuidv5('Loupe', LOUPE_NS));
    objects.push({
      type: 'identity', spec_version: '2.1', id: identityId,
      created: nowIso, modified: nowIso,
      name: 'Loupe', identity_class: 'system',
      description: 'Loupe — offline single-file security analyser',
    });

    // File SCO
    const fileHashes = {};
    if (model.hashes.md5) fileHashes['MD5'] = model.hashes.md5;
    if (model.hashes.sha1) fileHashes['SHA-1'] = model.hashes.sha1;
    if (model.hashes.sha256) fileHashes['SHA-256'] = model.hashes.sha256;
    const fileKey = `file|${model.name || ''}|${sha256 || ''}`;
    const fileId = 'file--' + (await this._uuidv5(fileKey, LOUPE_NS));
    const fileObj = { type: 'file', spec_version: '2.1', id: fileId };
    if (Object.keys(fileHashes).length) fileObj.hashes = fileHashes;
    if (model.name) fileObj.name = model.name;
    if (model.size) fileObj.size = model.size;
    objects.push(fileObj);

    // Indicators
    const patternFor = (type, val) => {
      // Escape any single quotes in the literal.
      const esc = String(val).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
      switch (type) {
        case 'url':         return `[url:value = '${esc}']`;
        case 'ipv4':        return `[ipv4-addr:value = '${esc}']`;
        case 'ipv6':        return `[ipv6-addr:value = '${esc}']`;
        case 'email':       return `[email-addr:value = '${esc}']`;
        case 'domain':      return `[domain-name:value = '${esc}']`;
        case 'hash-md5':    return `[file:hashes.'MD5' = '${esc}']`;
        case 'hash-sha1':   return `[file:hashes.'SHA-1' = '${esc}']`;
        case 'hash-sha256': return `[file:hashes.'SHA-256' = '${esc}']`;
        case 'file-path': {
          // Take basename, skip drive/UNC prefix.
          const base = String(val).replace(/\\/g, '/').split('/').filter(Boolean).pop() || val;
          const e = String(base).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
          return `[file:name = '${e}']`;
        }
        default: return null;
      }
    };

    const indicatorIds = [];
    for (const ioc of iocs) {
      if (!ioc.stixType) continue;
      const pattern = patternFor(ioc.stixType, ioc.value);
      if (!pattern) continue;
      const idKey = `indicator|${sha256}|${ioc.stixType}|${ioc.value}`;
      const id = 'indicator--' + (await this._uuidv5(idKey, LOUPE_NS));
      const ind = {
        type: 'indicator', spec_version: '2.1', id,
        created: nowIso, modified: nowIso,
        pattern, pattern_type: 'stix',
        valid_from: nowIso,
        name: `${ioc.type}: ${ioc.value}`.slice(0, 250),
        created_by_ref: identityId,
      };
      const sev = (ioc.severity || 'info').toLowerCase();
      if (sev === 'critical' || sev === 'high') ind.indicator_types = ['malicious-activity'];
      else if (sev === 'medium') ind.indicator_types = ['anomalous-activity'];
      // low/info: omit indicator_types per STIX optionality rules.
      if (ioc.note) ind.description = ioc.note;
      objects.push(ind);
      indicatorIds.push(id);
    }

    // Malware-analysis report SDO tying it all together.
    const yaraRules = [];
    for (const r of (f.externalRefs || []).concat(f.interestingStrings || [])) {
      if (r && r.type === IOC.YARA && r.ruleName) yaraRules.push(r.ruleName);
    }
    const uniqueYara = Array.from(new Set(yaraRules));
    const reportKey = `report|${sha256}|${nowIso}`;
    const reportId = 'report--' + (await this._uuidv5(reportKey, LOUPE_NS));
    const descLines = [];
    if (f.risk) descLines.push(`Risk: ${String(f.risk).toUpperCase()}`);
    if (uniqueYara.length) descLines.push(`YARA: ${uniqueYara.join(', ')}`);
    objects.push({
      type: 'report', spec_version: '2.1', id: reportId,
      created: nowIso, modified: nowIso,
      name: `Loupe analysis — ${model.name || 'unknown file'}`,
      report_types: ['malware-analysis'],
      published: nowIso,
      object_refs: [fileId, ...indicatorIds],
      created_by_ref: identityId,
      description: descLines.join('\n') || 'Automated analysis by Loupe.',
    });

    // Bundle (no spec_version at bundle level in STIX 2.1)
    const bundleId = 'bundle--' + this._uuidv4();
    return { type: 'bundle', id: bundleId, objects };
  },

  // RFC 4122 v4 UUID using crypto.getRandomValues — used only for the
  // bundle wrapper where determinism isn't required (the bundle id is the
  // export timestamp's identity, not the analysis's).
  _uuidv4() {
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = Array.from(b).map(x => x.toString(16).padStart(2, '0'));
    return `${h.slice(0,4).join('')}-${h.slice(4,6).join('')}-${h.slice(6,8).join('')}-${h.slice(8,10).join('')}-${h.slice(10,16).join('')}`;
  },

  // Deterministic UUID v5 (RFC 4122 §4.3). Accepts a canonical namespace
  // UUID string and an input name, returns a 36-char UUID string. Uses
  // SubtleCrypto's SHA-1 so no new vendored library is needed.
  async _uuidv5(name, namespaceUuid) {
    const nsBytes = this._uuidToBytes(namespaceUuid);
    const nameBytes = new TextEncoder().encode(String(name));
    const input = new Uint8Array(nsBytes.length + nameBytes.length);
    input.set(nsBytes, 0);
    input.set(nameBytes, nsBytes.length);
    const hashBuf = await crypto.subtle.digest('SHA-1', input);
    const h = new Uint8Array(hashBuf, 0, 16);
    h[6] = (h[6] & 0x0f) | 0x50;  // version 5
    h[8] = (h[8] & 0x3f) | 0x80;  // variant RFC 4122
    const hex = Array.from(h).map(x => x.toString(16).padStart(2, '0'));
    return `${hex.slice(0,4).join('')}-${hex.slice(4,6).join('')}-${hex.slice(6,8).join('')}-${hex.slice(8,10).join('')}-${hex.slice(10,16).join('')}`;
  },

  _uuidToBytes(uuid) {
    const hex = uuid.replace(/-/g, '');
    if (hex.length !== 32) throw new Error('Invalid UUID: ' + uuid);
    const out = new Uint8Array(16);
    for (let i = 0; i < 16; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  },

  // ════════════════════════════════════════════════════════════════════════
  // MISP event builder
  // ════════════════════════════════════════════════════════════════════════
  //
  // Emits a single MISP event (v2 "Event" JSON shape). The IOC → MISP
  // attribute mapping table below is the authoritative surface reviewers
  // should check; unknown types fall back to `text`/`Other` with
  // to_ids:false so they aren't silently dropped but also don't create
  // bogus detection logic on the server side.

  _buildMispEvent() {
    const f = this.findings || {};
    const meta = this._fileMeta || {};
    const hashes = this.fileHashes || {};
    const iocs = this._collectIocs();
    const nowIso = new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z');
    const today = nowIso.slice(0, 10);

    const risk = String(f.risk || 'info').toLowerCase();
    const threatLevel = (risk === 'high' || risk === 'critical') ? '1'
                      : (risk === 'medium') ? '2'
                      : (risk === 'low') ? '3' : '4';

    // IOC → MISP attribute mapping. The table here is deliberately pinned
    // near the top of the builder so reviewers see the full surface.
    //
    //  | stixType    | misp.type | category          | to_ids |
    //  |-------------|-----------|-------------------|--------|
    //  | url         | url       | Network activity  | true   |
    //  | ipv4/ipv6   | ip-dst    | Network activity  | true   |
    //  | domain      | domain    | Network activity  | true   |
    //  | email       | email-src | Payload delivery  | true   |
    //  | hash-md5    | md5       | Payload delivery  | true   |
    //  | hash-sha1   | sha1      | Payload delivery  | true   |
    //  | hash-sha256 | sha256    | Payload delivery  | true   |
    //  | file-path   | filename  | Payload delivery  | false  |
    //  | (unknown)   | text      | Other             | false  |
    const mapMisp = (ioc) => {
      const base = { value: ioc.value, comment: ioc.note || ioc.type, distribution: '5' };
      switch (ioc.stixType) {
        case 'url':         return { ...base, type: 'url',      category: 'Network activity', to_ids: '1' };
        case 'ipv4':
        case 'ipv6':        return { ...base, type: 'ip-dst',   category: 'Network activity', to_ids: '1' };
        case 'domain':      return { ...base, type: 'domain',   category: 'Network activity', to_ids: '1' };
        case 'email':       return { ...base, type: 'email-src',category: 'Payload delivery', to_ids: '1' };
        case 'hash-md5':    return { ...base, type: 'md5',      category: 'Payload delivery', to_ids: '1' };
        case 'hash-sha1':   return { ...base, type: 'sha1',     category: 'Payload delivery', to_ids: '1' };
        case 'hash-sha256': return { ...base, type: 'sha256',   category: 'Payload delivery', to_ids: '1' };
        case 'file-path':   return { ...base, type: 'filename', category: 'Payload delivery', to_ids: '0' };
        default:            return { ...base, type: 'text',     category: 'Other',            to_ids: '0' };
      }
    };

    const attributes = [];
    const pushAttr = (a) => { attributes.push(a); };

    // File-level attributes (always emitted if we have the data).
    if (meta.name) pushAttr({ type: 'filename', category: 'Payload delivery', to_ids: '0', distribution: '5', value: meta.name, comment: 'Analysed file' });
    if (hashes.md5) pushAttr({ type: 'md5',    category: 'Payload delivery', to_ids: '1', distribution: '5', value: hashes.md5,    comment: 'File hash (MD5)' });
    if (hashes.sha1) pushAttr({ type: 'sha1',  category: 'Payload delivery', to_ids: '1', distribution: '5', value: hashes.sha1,   comment: 'File hash (SHA-1)' });
    if (hashes.sha256) pushAttr({ type: 'sha256', category: 'Payload delivery', to_ids: '1', distribution: '5', value: hashes.sha256, comment: 'File hash (SHA-256)' });

    // IOCs
    for (const ioc of iocs) {
      const a = mapMisp(ioc);
      // Loupe-side "info" severity forces to_ids:false regardless of type.
      if ((ioc.severity || '').toLowerCase() === 'info') a.to_ids = '0';
      pushAttr(a);
    }

    // YARA rule hits → one attribute each (type=yara, to_ids:false — rule
    // name alone isn't a detection primitive).
    const yaraSeen = new Set();
    for (const r of (f.externalRefs || []).concat(f.interestingStrings || [])) {
      if (r && r.type === IOC.YARA && r.ruleName && !yaraSeen.has(r.ruleName)) {
        yaraSeen.add(r.ruleName);
        pushAttr({
          type: 'yara', category: 'Payload delivery', to_ids: '0', distribution: '5',
          value: r.ruleName,
          comment: r.description || 'YARA rule hit',
        });
      }
    }

    const tags = [
      { name: 'tlp:clear' },
      { name: `loupe:risk="${risk}"` },
    ];
    const ext = (meta.name || '').split('.').pop().toLowerCase();
    if (ext) tags.push({ name: `loupe:detected-type="${ext}"` });

    return {
      Event: {
        info: `Loupe analysis — ${meta.name || 'unknown file'}`,
        date: today,
        threat_level_id: threatLevel,
        analysis: '2',          // Completed
        distribution: '0',      // Your org only
        published: false,
        uuid: this._uuidv4(),
        Attribute: attributes,
        Tag: tags,
      },
    };
  },

});

document.addEventListener('DOMContentLoaded', () => new App().init());

