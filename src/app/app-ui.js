// ════════════════════════════════════════════════════════════════════════════
// App — UI utilities: tabs, sidebar toggle, downloads, clipboard, zoom, theme
// ════════════════════════════════════════════════════════════════════════════
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
    const info = document.getElementById('file-info').textContent;
    const name = (info.split('·')[0] || 'file').trim() || 'file';
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

  // ── ⚡ Copy Analysis — structured report for AI / SOC ─────────────────
  _copyAnalysis() {
    if (!this._fileBuffer || !this.findings) { this._toast('No file loaded', 'error'); return; }
    const BUDGET = 12000;
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
      for (const det of detections.slice(0, 60)) {
        d += `| ${tp(det.ruleName || det.type)} | ${(det.severity || 'info').toUpperCase()} | ${tp(det.description || det.url)} |\n`;
      }
      if (detections.length > 60) d += `\n… and ${detections.length - 60} more detections\n`;
      sections.push({ text: d, priority: 3, maxLen: 2500 });
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
      for (const ioc of iocs.slice(0, 80)) {
        d += `| ${tp(ioc.type)} | \`${tp(ioc.url)}\` | ${ioc.severity || 'info'} |\n`;
      }
      if (iocs.length > 80) d += `\n… and ${iocs.length - 80} more IOCs\n`;
      sections.push({ text: d, priority: 4, maxLen: 2500 });
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
        sections.push({ text: d, priority: 5, maxLen: 3000 });
      }
    }

    // ═══════ 6. Deobfuscated Findings ════════════════════════════════════
    const encoded = f.encodedContent || [];
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
    if (meaningful.length) {
      let d = '\n## Deobfuscated Findings\n';
      for (const ef of meaningful) {
        const chain = (ef.chain && ef.chain.length) ? ef.chain.join(' → ') : ef.encoding || 'decoded';
        d += `### ${chain}\n`;
        if (ef.severity && ef.severity !== 'info') d += `**Severity:** ${ef.severity}\n`;
        let dec = ef._deobfuscatedText || '';
        if (!dec && ef.decodedBytes) { try { dec = new TextDecoder('utf-8', { fatal: true }).decode(ef.decodedBytes.slice(0, 4000)); } catch (_) {} }
        if (dec) d += '```\n' + (dec.length > 2000 ? dec.slice(0, 2000) + '\n… (truncated)' : dec) + '\n```\n';
        if (ef.iocs && ef.iocs.length) d += '**IOCs:** ' + ef.iocs.map(i => `${i.type}: \`${i.url}\``).join(', ') + '\n';
        d += '\n';
      }
      sections.push({ text: d, priority: 6, maxLen: 2500 });
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
    this._copyToClipboard(report);
  },

  // ── Format-specific section builder for _copyAnalysis ─────────────────
  _copyAnalysisFormatSpecific(f, tp) {
    const parts = [];

    // ── Metadata ──
    if (f.metadata && typeof f.metadata === 'object' && Object.keys(f.metadata).length) {
      parts.push('\n## Metadata');
      for (const [k, v] of Object.entries(f.metadata)) {
        if (v && v !== '—') parts.push(`- **${k}:** ${v}`);
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
    if (pe.imphash) parts.push(`**Imphash:** \`${pe.imphash}\``);

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

      // Extensions summary
      if (c.extensions && c.extensions.length) {
        parts.push('\n**Extensions:**');
        for (const ext of c.extensions) {
          let val = ext.value || '';
          if (val.length > 200) val = val.slice(0, 200) + '…';
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
  },

  // ── Downloads ────────────────────────────────────────────────────────────
  _downloadMacros() {
    const f = this.findings;
    const info = document.getElementById('file-info').textContent;
    const base = info.split('·')[0].trim().replace(/\.[^.]+$/, '') || 'macros';
    const mods = (f.modules || []).filter(m => m.source);
    if (mods.length) {
      const sep = '='.repeat(60), lines = [];
      for (const mod of mods) { lines.push(`' ${sep}`); lines.push(`' VBA Module: ${mod.name}`); lines.push(`' ${sep}`); lines.push(mod.source); lines.push(''); }
      const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = base + '_macros.txt'; a.click();
      URL.revokeObjectURL(url); this._toast('Macro source downloaded');
    } else if (f.rawBin && f.rawBin.length) {
      const blob = new Blob([f.rawBin], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = base + '_vbaProject.bin'; a.click();
      URL.revokeObjectURL(url); this._toast('Raw VBA binary downloaded — use olevba/oledump to inspect');
    } else { this._toast('No macro data available', 'error'); }
  },

  _downloadExtracted(refs, fileName) {
    const base = (fileName || 'extracted').replace(/\.[^.]+$/, '');
    const lines = ['Type\tValue\tSeverity', ...refs.map(r => `${r.type}\t${r.url}\t${r.severity}`)];
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = base + '_extracted.txt'; a.click();
    URL.revokeObjectURL(url); this._toast('Extracted data downloaded');
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
    // Hide file info + close button + viewer toolbar
    document.getElementById('file-info').textContent = '';
    document.getElementById('btn-close').classList.add('hidden');
    document.getElementById('viewer-toolbar').classList.add('hidden');
    document.getElementById('doc-search').value = '';
    if (this._clearSearch) this._clearSearch();
    // Close sidebar and clear its content; reset locked width for fresh auto-sizing
    if (this.sidebarOpen) this._toggleSidebar();
    document.getElementById('sidebar').style.width = '';
    document.getElementById('sb-body').innerHTML = '';
    document.getElementById('sb-risk').className = 'sb-risk risk-low';
    document.getElementById('sb-risk-title').textContent = 'No threats detected';
    // Reset state
    this.findings = null; this.fileHashes = null;
    this._fileBuffer = null; this._yaraBuffer = null; this._yaraResults = null;
    this._fileMeta = null;
    // Clear navigation stack and hide back button
    this._navStack = [];
    const backBtn = document.getElementById('btn-nav-back');
    if (backBtn) backBtn.classList.add('hidden');
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
      // Don't pan on plaintext views (they have their own scrolling)
      if (e.target.closest('.plaintext-scroll') || e.target.closest('.sheet-content-area') || e.target.closest('.csv-scroll')) return;
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
  },

  // ── Zoom / theme / loading / toast ────────────────────────────────────────
  _setZoom(z) {
    this.zoom = Math.min(200, Math.max(50, z));
    document.getElementById('zoom-level').textContent = `${this.zoom}%`;
    document.getElementById('page-container').style.transform = `scale(${this.zoom / 100})`;
  },

  _toggleTheme() {
    this.dark = !this.dark;
    document.body.classList.toggle('dark', this.dark);
    document.getElementById('btn-theme').textContent = this.dark ? '☀' : '🌙';
  },

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

    const version = typeof GLOVEBOX_VERSION !== 'undefined' ? GLOVEBOX_VERSION : 'dev';

    const overlay = document.createElement('div');
    overlay.className = 'help-overlay';
    overlay.innerHTML = `
      <div class="help-dialog">
        <div class="help-header">
          <span>🧤📦 GloveBox <small>v${version}</small></span>
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
            <a href="https://github.com/Sam-Dowling/GloveBox/releases/latest/download/glovebox.html" target="_blank" rel="noopener">Download GloveBox</a>
            ·
            <a href="https://github.com/Sam-Dowling/GloveBox" target="_blank" rel="noopener">GitHub Repository</a>
            ·
            <a href="https://sam-dowling.github.io/GloveBox/" target="_blank" rel="noopener">Live Demo</a>
          </p>

          <div style="text-align:center;margin-top:12px;">
            <a class="help-update-btn" href="https://sam-dowling.github.io/GloveBox/?v=v${version}" target="_blank" rel="noopener">🔄 Check for Updates</a>
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
    const localVersion = typeof GLOVEBOX_VERSION !== 'undefined' ? GLOVEBOX_VERSION : 'dev';

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
      const dlUrl = 'https://github.com/Sam-Dowling/GloveBox/releases/latest/download/glovebox.html';
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

});

document.addEventListener('DOMContentLoaded', () => new App().init());
