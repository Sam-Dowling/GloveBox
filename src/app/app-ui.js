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
// Each entry also carries a `preview` triple { bg, accent, risk } used by the
// Settings-tab theme-picker to render an in-palette swatch strip per card —
// the actual CSS custom properties only activate when the theme class is on
// <body>, so the picker bakes the preview colours directly.
const THEMES = [
  { id: 'light',     label: 'Light',           icon: '☀', dark: false,
    preview: { bg: '#ffffff', accent: '#1a73e8', risk: '#dc2626' } },
  { id: 'dark',      label: 'Dark',            icon: '🌙', dark: true,
    preview: { bg: '#12131c', accent: '#22d3ee', risk: '#f87171' } },
  { id: 'midnight',  label: 'Midnight',        icon: '🌑', dark: true,
    preview: { bg: '#000000', accent: '#22d3ee', risk: '#f87171' } },
  { id: 'solarized', label: 'Solarized',       icon: '🟡', dark: true,
    preview: { bg: '#073642', accent: '#b58900', risk: '#dc322f' } },
  { id: 'mocha',     label: 'Mocha',           icon: '🌺', dark: true,
    preview: { bg: '#1e1e2e', accent: '#cba6f7', risk: '#f38ba8' } },
  { id: 'latte',     label: 'Latte',           icon: '🍵', dark: false,
    preview: { bg: '#eff1f5', accent: '#8839ef', risk: '#d20f39' } },
];

const _THEME_PREF_KEY = 'loupe_theme';
const _DEFAULT_THEME = 'dark';

extendApp({


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
    if (!this.currentResult || !this.currentResult.buffer) {
      this._toast('No file loaded', 'error'); return;
    }
    // _fileMeta.name is now the single source of truth for the filename
    // (the toolbar used to render this via #file-info.textContent but that
    // element has been replaced by the breadcrumb trail).
    const name = (this._fileMeta && this._fileMeta.name) || 'file';
    this._downloadBytes(this.currentResult.buffer, name, 'application/octet-stream');
    this._toast('File saved');
  },

  // ── Is "📋 Copy raw content" safe for this file? ─────────────────────────
  // The Web Clipboard's text channel only faithfully round-trips UTF-8 text.
  // Binary formats (PE, Mach-O, ELF, JAR/class, compiled .scpt, PDF, MSI, OLE
  // containers, OOXML/ODF, archives, disk images, forensic DBs, images,
  // binary plist, DER/PKCS#12) all either (a) fail to paste at all because
  // `application/octet-stream` is not a recognised clipboard MIME in most
  // target apps, or (b) silently truncate at the first NUL via the
  // String.fromCharCode fallback. Worse, a few binary formats (compiled
  // .scpt in particular) happen to pass a UTF-8 `fatal:true` decode and
  // would get copied as a garbled text dump that includes the renderer's
  // extracted-strings view rather than the original bytes. So we treat
  // "copyable as text" as: fatal-UTF-8-decode succeeds AND the detected
  // type is not on the explicit binary denylist. 💾 Save raw file remains
  // the canonical "get the bytes out" path for every file.
  _RAW_COPY_BINARY_DENYLIST: new Set([
    // Native binaries
    'pe', 'elf', 'macho', 'exe', 'dll', 'sys', 'scr', 'cpl', 'ocx', 'drv',
    'so', 'o', 'dylib', 'bundle',
    // Java
    'jar', 'war', 'ear', 'class',
    // Documents / OLE / OOXML / ODF containers
    'pdf', 'msi', 'ole', 'doc', 'xls', 'ppt', 'msg',
    'docx', 'docm', 'xlsx', 'xlsm', 'pptx', 'pptm',
    'odt', 'ods', 'odp',
    // Archives / disk images
    'zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'cab', 'iso', 'img',
    // Forensic / DB / logs
    'evtx', 'sqlite', 'db', 'onenote', 'one',
    // Images
    'image', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'tif', 'tiff', 'avif',
    // Compiled AppleScript (extensionless/FasTX)
    'scpt', 'scptd',
    // Binary cert containers
    'der', 'p12', 'pfx',
  ]),

  _isRawCopyable() {
    if (!this.currentResult || !this.currentResult.buffer) return false;
    const bytes = new Uint8Array(this.currentResult.buffer);

    // Binary-plist sniff — some .plist files are XML (text, copyable), but
    // `bplist00` files are binary. detectedType='plist' doesn't distinguish.
    if (bytes.length >= 8) {
      const h = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
      if (h === 'bplist') return false;
    }

    // Detected-type denylist — catches spuriously UTF-8-decodable binaries
    // like compiled .scpt whose FasTX bytes happen to pass fatal decode.
    const meta = this._fileMeta || {};
    const detected = (meta.detectedType || '').toLowerCase();
    const ext = ((meta.name || '').split('.').pop() || '').toLowerCase();
    if (this._RAW_COPY_BINARY_DENYLIST.has(detected)) return false;
    if (this._RAW_COPY_BINARY_DENYLIST.has(ext)) return false;

    // Fatal UTF-8 decode — any high-bit sequence that isn't valid UTF-8
    // means this isn't text and the text-channel copy would mangle it.
    try {
      new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      return true;
    } catch (_) {
      return false;
    }
  },

  _copyContent() {
    if (!this.currentResult || !this.currentResult.buffer) {
      this._toast('No file loaded', 'error'); return;
    }
    if (!this._isRawCopyable()) {
      // Menu gates this already, but stay defensive in case it's invoked
      // via a direct keybinding or future code path.
      this._toast('Binary file — use 💾 Save raw file instead', 'error');
      return;
    }
    const bytes = new Uint8Array(this.currentResult.buffer);
    const asText = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    // Stash the original bytes + filename so a same-session paste can
    // recover them byte-for-byte. The Web Clipboard API's text/plain
    // channel normalises CRLF→LF (and a few browsers strip trailing
    // newlines), which silently changes the file hash — a confusing
    // result for a security tool. `_handlePasteEvent` checks this cache
    // first and, if the pasted text matches what we just copied (modulo
    // line-ending normalisation), re-loads the original File instead of
    // a freshly-built clipboard.txt.
    this._lastCopiedMeta = {
      name: (this._fileMeta && this._fileMeta.name) || 'clipboard.txt',
      buffer: this.currentResult.buffer,
      normText: asText.replace(/\r\n/g, '\n'),
    };
    this._copyToClipboard(asText);
  },

  // ── ⚡ Copy Analysis (Summary) — structured report for AI / SOC ──────
  _copyAnalysis() {
    if (!this.currentResult || !this.currentResult.buffer || !this.findings) {
      this._toast('No file loaded', 'error'); return;
    }
    // Budget is user-configurable via the Settings dialog (logarithmic
    // 10-step slider from ~4 KB to unbudgeted). The default step (~64 KB)
    // carries every renderer's per-format deep data (PDF JavaScripts,
    // MSI CustomActions, EVTX event distribution, PGP key info, plist
    // persistence, …) rather than only a compact headline view.  Strict
    // IOC/STIX/MISP exporters are not affected — they live in
    // _collectIocs / _buildStix / _buildMisp and remain TIP-friendly.
    const report = this._buildAnalysisText(this._getSummaryCharBudget());
    this._copyToClipboard(report);
  },


  // Produce the plaintext summary report.
  //
  // ── Target semantics (as of the 3-phase Summarize picker) ───────────
  // `budget` is a **target character count**, not a hard threshold. The
  // algorithm is build-full → measure → shrink-to-fit:
  //
  //   1. Build every section at full fidelity (SCALE = Infinity — no row
  //      caps, no per-field truncation). Raw scripts, full tables, full
  //      metadata trees.
  //   2. If the assembled total fits under `budget`, emit it unchanged.
  //      This is the whole point: a tiny file whose raw content fits
  //      inside the target should land in the report verbatim.
  //   3. If over budget, walk sections from the **most expendable**
  //      (highest priority number — 7: Format-specific, 6: Deobfuscated,
  //      …) down toward File Info (priority 1), swapping each section's
  //      text for a tighter-SCALE rebuild along the ladder
  //      [4, 2, 1, 0.5, 0.25]. Re-measure after every swap; stop the
  //      instant the total fits.
  //   4. If still over at SCALE=0.25 for every section, fall back to the
  //      legacy per-section `maxLen` cap + hard slice so we never exceed
  //      the target.
  //
  // `budget === Infinity` (Unlimited phase) short-circuits step 1: the
  // full-fidelity build is returned directly, no measurement, no caps.
  _buildAnalysisText(budget) {
    if (!this.findings) return '';
    const UNBUDGETED = !isFinite(budget);
    const BUDGET = UNBUDGETED ? Number.MAX_SAFE_INTEGER : budget;
    const f = this.findings;
    const meta = this._fileMeta || {};
    const hashes = this.fileHashes || {};

    // Helper: truncate a section to fit a max length. A max of Infinity
    // short-circuits so unbudgeted / fitted reports skip the comparison
    // entirely.
    const cap = (text, max) => {
      if (!text) return '';
      if (max === Infinity) return text;
      return text.length <= max ? text : text.slice(0, max) + '\n… (section truncated)\n';
    };
    // Helper: escape pipe characters for markdown tables
    const tp = (v) => String(v || '').replace(/\|/g, '∣').replace(/\n/g, ' ');

    // ── buildSectionsAtScale(SCALE) ──────────────────────────────────────
    // Re-runs the entire section-building pipeline at a given SCALE and
    // returns the resulting `sections` array. Every `_copyAnalysisXxx`
    // helper in App.prototype reads caps from `this._sCaps`, so setting
    // it here propagates to the whole format-specific deep-dive section.
    //
    //   SCALE   rowCap(n)              charCap(n)
    //    ∞       Infinity               Infinity           (full fidelity)
    //    4       max(5, ⌈n×4⌉)          max(120, ⌈n×4⌉)
    //    2       max(5, ⌈n×2⌉)          max(120, ⌈n×2⌉)
    //    1       max(5, n)              max(120, n)        (legacy default)
    //    0.5     max(5, ⌈n÷2⌉)          max(120, ⌈n÷2⌉)
    //    0.25    max(5, ⌈n÷4⌉)          max(120, ⌈n÷4⌉)   (tightest)
    const _prevCaps = this._sCaps;
    const buildSectionsAtScale = (SCALE) => {
      const rowCap  = (n) => SCALE === Infinity ? Infinity : Math.max(5,   Math.ceil(n * SCALE));
      const charCap = (n) => SCALE === Infinity ? Infinity : Math.max(120, Math.ceil(n * SCALE));
      this._sCaps = { SCALE, rowCap, charCap };
      const sections = [];

      // ═══════ 1. File Info (priority: always included) ════════════════════
      const FMT = {
        docx: 'Word Document', docm: 'Word Macro-Enabled Document', xlsx: 'Excel Workbook',
        xlsm: 'Excel Macro-Enabled Workbook', xls: 'Excel 97-2003 Workbook', ods: 'OpenDocument Spreadsheet',
        pptx: 'PowerPoint Presentation', pptm: 'PowerPoint Macro-Enabled Presentation',
        csv: 'Comma-Separated Values', tsv: 'Tab-Separated Values', doc: 'Word 97-2003 Document',
        msg: 'Outlook Message', eml: 'Email Message', lnk: 'Windows Shortcut', hta: 'HTML Application',
        pdf: 'PDF Document', rtf: 'Rich Text Format', html: 'HTML Document', htm: 'HTML Document',
        one: 'OneNote Document', iso: 'Disk Image (ISO)', img: 'Disk Image (IMG)', zip: 'ZIP Archive',
        rar: 'RAR Archive', '7z': '7-Zip Archive', wsf: 'Windows Script File', url: 'Internet Shortcut',
        svg: 'SVG Image', iqy: 'Internet Query File', slk: 'Symbolic Link File', evtx: 'Windows Event Log',
        sqlite: 'SQLite Database', db: 'SQLite Database', exe: 'PE Executable', dll: 'PE Dynamic Library',
        sys: 'PE Driver', elf: 'ELF Binary', so: 'ELF Shared Object', jar: 'Java Archive',
        class: 'Java Class', pem: 'PEM Certificate', der: 'DER Certificate', crt: 'X.509 Certificate',
        p12: 'PKCS#12 Keystore', war: 'Java WAR', ear: 'Java EAR', msi: 'Windows Installer',
        reg: 'Registry File', inf: 'INF File', sct: 'Scriptlet', scpt: 'Compiled AppleScript',
        applescript: 'AppleScript Source', jxa: 'JavaScript for Automation', plist: 'Property List',
        pfx: 'PKCS#12 Keystore', cer: 'X.509 Certificate', odt: 'OpenDocument Text',
        odp: 'OpenDocument Presentation', ppt: 'PowerPoint 97-2003', dylib: 'Mach-O Dynamic Library',
        bundle: 'Mach-O Bundle', o: 'Object File', cab: 'Cabinet Archive',
        gz: 'Gzip Archive', tgz: 'Tar Gzip Archive', tar: 'Tar Archive',
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
      sections.push({ text: s, priority: 1, maxLen: charCap(800) });

      // ═══════ 2. Risk Assessment ══════════════════════════════════════════
      const risk = f.risk || f.riskLevel || '';
      if (risk) {
        const sev = { critical: '🔴 CRITICAL', high: '🟠 HIGH', medium: '🟡 MEDIUM', low: '🟢 LOW' };
        sections.push({ text: `\n## Risk Assessment\n**${sev[risk] || risk.toUpperCase()}**\n`, priority: 2, maxLen: charCap(200) });
      }

      // ═══════ 3. Detections ═══════════════════════════════════════════════
      const detectionTypes = new Set([IOC.YARA, IOC.PATTERN, IOC.INFO]);
      const allRefs = [...(f.externalRefs || []), ...(f.interestingStrings || [])];
      const detections = allRefs.filter(r => detectionTypes.has(r.type));
      if (detections.length) {
        const detCap = rowCap(250);
        let d = '\n## Detections\n| Rule | Severity | Description |\n|------|----------|-------------|\n';
        for (const det of detections.slice(0, detCap)) {
          d += `| ${tp(det.ruleName || det.type)} | ${(det.severity || 'info').toUpperCase()} | ${tp(det.description || det.url)} |\n`;
        }
        if (detections.length > detCap) d += `\n… and ${detections.length - detCap} more detections\n`;
        sections.push({ text: d, priority: 3, maxLen: charCap(10000) });
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
        const iocCap = rowCap(350);
        let d = '\n## IOCs\n| Type | Value | Severity |\n|------|-------|----------|\n';
        for (const ioc of iocs.slice(0, iocCap)) {
          d += `| ${tp(ioc.type)} | \`${tp(ioc.url)}\` | ${ioc.severity || 'info'} |\n`;
        }
        if (iocs.length > iocCap) d += `\n… and ${iocs.length - iocCap} more IOCs\n`;
        sections.push({ text: d, priority: 4, maxLen: charCap(10000) });
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
            // At shrinking SCALEs we still emit whole modules intact at
            // the section-build stage — any trim happens through the
            // section maxLen cap in the final fallback path. Tightening
            // VBA source mid-decompilation produces garbage output.
            d += `### ${mod.name}\n\`\`\`vba\n${mod.source}\n\`\`\`\n\n`;
          }
          sections.push({ text: d, priority: 5, maxLen: charCap(12000) });
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
        // Per-layer decode/emit budgets scale with the current SCALE so
        // the shrink-to-fit ladder can claw back space from bulky
        // decoded blobs without nuking the section entirely.
        const decodeMax = charCap(16000);
        const emitMax = charCap(8000);
        let d = '\n## Deobfuscated Findings\n';
        for (const ef of uniqueLayers) {
          const chain = (ef.chain && ef.chain.length) ? ef.chain.join(' → ') : ef.encoding || 'decoded';
          d += `### ${chain}\n`;
          if (ef.severity && ef.severity !== 'info') d += `**Severity:** ${ef.severity}\n`;
          let dec = ef._deobfuscatedText || '';
          if (!dec && ef.decodedBytes) {
            try {
              const sliceN = decodeMax === Infinity ? ef.decodedBytes.length : decodeMax;
              dec = new TextDecoder('utf-8', { fatal: true }).decode(ef.decodedBytes.slice(0, sliceN));
            } catch (_) { }
          }
          if (dec) d += '```\n' + ((emitMax !== Infinity && dec.length > emitMax) ? dec.slice(0, emitMax) + '\n… (truncated)' : dec) + '\n```\n';
          if (ef.iocs && ef.iocs.length) d += '**IOCs:** ' + ef.iocs.map(i => `${i.type}: \`${i.url}\``).join(', ') + '\n';
          d += '\n';
        }
        sections.push({ text: d, priority: 6, maxLen: charCap(14000) });
      }

      // ═══════ 7. Format-Specific Deep Data ════════════════════════════════
      // The per-format helpers (PE, ELF, Mach-O, PDF, MSI, EVTX, SQLite,
      // X.509, JAR, …) all read caps from `this._sCaps`, which we set at
      // the top of this closure.
      const deep = this._copyAnalysisFormatSpecific(f, tp);
      if (deep) sections.push({ text: deep, priority: 7, maxLen: BUDGET });

      return sections;
    };

    try {
      // ── Pass 1: full fidelity ──────────────────────────────────────────
      const fullSections = buildSectionsAtScale(Infinity);
      const joinSorted = (secs) =>
        secs.slice().sort((a, b) => a.priority - b.priority).map(s => s.text).join('');

      // Unlimited phase — emit full-fidelity output untouched.
      if (UNBUDGETED) return joinSorted(fullSections);

      const fullText = joinSorted(fullSections);
      if (fullText.length <= BUDGET) return fullText;

      // ── Pass 2: shrink-to-fit ladder ───────────────────────────────────
      // Pre-build every SCALE variant once so the inner loop is just
      // string concatenation. 5 extra builds is cheap compared with the
      // YARA / parsing pipeline that produced `f` in the first place.
      const SCALE_LADDER = [4, 2, 1, 0.5, 0.25];
      const variants = new Map();
      variants.set(Infinity, fullSections);
      for (const SCALE of SCALE_LADDER) {
        variants.set(SCALE, buildSectionsAtScale(SCALE));
      }

      // Walk sections from the most expendable (highest priority number)
      // down, swapping in progressively tighter rebuilds for each one.
      // Measure after every swap so we stop at the first fit.
      const current = new Map(); // priority → section (start from full fidelity)
      for (const sec of fullSections) current.set(sec.priority, sec);
      const priorities = [...current.keys()].sort((a, b) => a - b);

      for (let i = priorities.length - 1; i >= 0; i--) {
        const prio = priorities[i];
        for (const SCALE of SCALE_LADDER) {
          const replacement = (variants.get(SCALE) || []).find(s => s.priority === prio);
          if (replacement) current.set(prio, replacement);
          const combined = joinSorted([...current.values()]);
          if (combined.length <= BUDGET) return combined;
        }
      }

      // ── Pass 3: last-resort hard truncation ────────────────────────────
      // Even at SCALE=0.25 for every section the report exceeds BUDGET
      // (rare — usually huge deobfuscated PowerShell or a massive
      // embedded cert chain). Fall back to the legacy per-section maxLen
      // cap + hard slice so the output is always ≤ BUDGET.
      const finalSecs = [...current.values()].sort((a, b) => a.priority - b.priority);
      let remaining = BUDGET;
      const output = [];
      for (const sec of finalSecs) {
        if (remaining <= 0) break;
        const limit = sec.priority === 7 ? remaining : Math.min(sec.maxLen, remaining);
        const text = cap(sec.text, limit);
        output.push(text);
        remaining -= text.length;
      }
      let report = output.join('');
      if (report.length > BUDGET) report = report.slice(0, BUDGET) + '\n… (report truncated)';
      return report;
    } finally {
      // Restore caps in case a nested _buildAnalysisText call (or a
      // future re-entrancy) stashed one before us.
      this._sCaps = _prevCaps;
    }
  },


  // Recursive pretty-printer for the generic metadata loop. The legacy
  // writer just did `${v}` which stringified arrays/objects as "[object
  // Object]" or "[object]","[object]","...". This formatter renders the
  // actual structure so analysts get the real nested data without the
  // report blowing up.
  //
  // Caps are scaled by the Summary budget via `this._sCaps` (set by
  // _buildAnalysisText). At the 64 K default (SCALE=1) this matches the
  // legacy behaviour — depth ≤ 3, arrays/objects ≤ 20, strings ≤ 500 chars
  // — byte-for-byte. At 256 K the tree opens up (depth 5, ≤80 items,
  // ≤2 000-char strings) so previously-hidden nested fields (plist
  // MachServices, EML Received: chains, SQLite per-table columns, etc.)
  // reach the report. At MAX the caps are all Infinity.
  _formatMetadataValue(v, depth) {
    depth = depth || 0;
    if (v == null) return '';
    const t = typeof v;
    // Resolve caps from the cap set stashed by _buildAnalysisText. If a
    // caller invokes this directly without a budget (shouldn't happen,
    // but keep the old bounds as a fallback) we honour the legacy 500 /
    // 20 / 3 literals.
    const caps = this._sCaps || null;
    const S = caps ? caps.SCALE : 1;
    const strMax  = caps ? caps.charCap(500) : 500;
    const itemMax = caps ? caps.rowCap(20)   : 20;
    // Depth scales in three steps: default ≤3, 2× →4, ≥4× →5, MAX ∞.
    const depthMax = (S === Infinity) ? Infinity
      : S >= 4 ? 5
      : S >= 2 ? 4
      : 3;
    if (t === 'string') {
      if (strMax === Infinity || v.length <= strMax) return v;
      return v.slice(0, strMax) + '… (truncated)';
    }
    if (t === 'number' || t === 'boolean') return String(v);
    if (v instanceof Uint8Array || (ArrayBuffer.isView && ArrayBuffer.isView(v))) {
      return `<${v.byteLength || v.length} bytes>`;
    }
    if (Array.isArray(v)) {
      if (!v.length) return '[]';
      if (depth >= depthMax) return `[${v.length} items]`;
      const take = itemMax === Infinity ? v.length : Math.min(v.length, itemMax);
      const shown = v.slice(0, take).map(x => this._formatMetadataValue(x, depth + 1));
      // For scalar arrays use a compact inline representation; for
      // object/nested arrays lay them out one per line for legibility.
      const anyComplex = shown.some(s => s.includes('\n') || s.length > 60);
      const tail = v.length > take ? `, … and ${v.length - take} more` : '';
      if (!anyComplex) return '[' + shown.join(', ') + tail + ']';
      return '\n' + shown.map(s => '  - ' + s.replace(/\n/g, '\n    ')).join('\n')
        + (tail ? '\n  ' + tail : '');
    }
    if (t === 'object') {
      if (depth >= depthMax) return '{…}';
      const keys = Object.keys(v);
      if (!keys.length) return '{}';
      const take = itemMax === Infinity ? keys.length : Math.min(keys.length, itemMax);
      const shown = keys.slice(0, take).map(k => `${k}: ${this._formatMetadataValue(v[k], depth + 1)}`);
      const tail = keys.length > take ? `, … and ${keys.length - take} more` : '';
      const anyComplex = shown.some(s => s.includes('\n') || s.length > 60);
      if (!anyComplex) return '{' + shown.join(', ') + tail + '}';
      return '\n' + shown.map(s => '  - ' + s.replace(/\n/g, '\n    ')).join('\n')
        + (tail ? '\n  ' + tail : '');
    }
    return String(v);
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
      this._downloadBytes(f.rawBin, base + '_vbaProject.bin', 'application/octet-stream');
      this._toast('Raw VBA binary downloaded — use olevba/oledump to inspect');
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
  // Single choke-point for turning text / JSON / raw bytes into a browser
  // download. Every exporter (and the legacy _downloadMacros /
  // _downloadPdfScripts / _downloadExtracted / _saveContent sites, plus
  // attachment / strings-dump / object-carving paths in the renderers)
  // routes through these helpers so the blob-and-anchor dance lives in
  // exactly one place and object URLs are consistently revoked.
  // These thin wrappers exist so app-level call sites read naturally
  // (`this._downloadText(...)`) without having to know about the global
  // `FileDownload` module. The real ceremony lives in `src/file-download.js`
  // so renderers (which don't have `this` = App) share exactly one code path.
  _downloadText(text, filename, mime) {
    window.FileDownload.downloadText(text, filename, mime);
  },

  _downloadBytes(bytes, filename, mime) {
    // Accepts a Uint8Array, ArrayBuffer, or anything Blob's constructor
    // understands. Binary MIME defaults to application/octet-stream.
    window.FileDownload.downloadBytes(bytes, filename, mime);
  },

  _downloadBlob(blob, filename) {
    window.FileDownload.downloadBlob(blob, filename);
  },

  _downloadJson(obj, filename) {
    window.FileDownload.downloadJson(obj, filename);
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
    console.warn('Loupe: _copyFallback is deprecated — execCommand("copy") is removed in modern browsers');
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
    this._yaraResults = null;
    this._fileMeta = null;
    // Copy-content cache holds a reference to the previous file's
    // ArrayBuffer (for same-session paste round-trip). Without clearing
    // it, every load/clear cycle leaks the full buffer.
    this._lastCopiedMeta = null;
    // ── currentResult teardown + render-epoch fence ───────────────────────
    // Drop the entire RenderRoute result in one assignment. Every renderer
    // and per-format helper reads its file bytes / parsed binary / yara
    // buffer through `this.currentResult.{buffer, yaraBuffer, binary}`, so
    // nulling the wrapper transparently clears all four channels at once.
    // Routing through `_setRenderResult` also bumps `_renderEpoch`, which
    // fences any continued in-flight work from the just-cleared file's
    // renderer (an EVTX chunk loop, an OneNote inflate) — when it finally
    // checks the captured epoch it sees a stale value and no-ops on its
    // `app.findings` / `currentResult` writes.
    this._setRenderResult(null);

    // ── Stale-load guard reset ────────────────────────────────────────────
    // `_loadToken` is the monotonic counter `_loadFile` bumps on every
    // invocation; deferred mutations (pdf-worker QR decode, async overlay
    // SHA-256, OneNote inflate, etc.) capture it and pass it to
    // `App.updateFindings({...}, { token })` so a stranded post-close
    // mutation no-ops instead of painting into the next file's findings.
    // Reset to 0 here so a deferred call queued *during* the now-cleared
    // load doesn't accidentally match the next file's first token of 1.
    // `_currentAnalyzer` was stashed by `_loadFile` so the deferred
    // sidebar refresh can re-render with the same DOCX `SecurityAnalyzer`
    // instance — null it on close. `_pendingSbSections` /
    // `_sbRefreshScheduled` are the microtask coalescing flags; clear so
    // a stale microtask doesn't try to repaint the sidebar after teardown.
    this._loadToken = 0;
    this._currentAnalyzer = null;
    this._pendingSbSections = null;
    this._sbRefreshScheduled = false;

    // ── Sidebar highlight teardown ────────────────────────────────────────
    // Pending highlight timers hold closures over stale findings / DOM
    // refs. The *ActiveView properties reference the old file's
    // GridViewer — without clearing them, the entire old view (and its
    // row data) stays alive until the 5 s timer fires.
    if (this._matchHighlightTimer) { clearTimeout(this._matchHighlightTimer); this._matchHighlightTimer = null; }
    if (this._iocEvtxHighlightTimer) { clearTimeout(this._iocEvtxHighlightTimer); this._iocEvtxHighlightTimer = null; }
    this._yaraHighlightActiveView = null;
    this._iocCsvHighlightActiveView = null;

    // Clear navigation stack and hide breadcrumbs. Routes through the
    // single-owner reset (`_resetNavStack` in app-core.js, H6) so the
    // breadcrumb repaint is centralised — we just need to ensure the
    // post-clear repaint still picks up the now-null `_fileMeta` (the
    // helper repaints internally; this duplicate call is the
    // belt-and-braces no-op for any future helper short-circuit).
    this._resetNavStack();

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
        // Any renderer that emits a line-numbered source table uses the
        // `.plaintext-table` marker (osascript / JXA / AppleScript, etc.).
        // Matching on the table itself — not just the wrapper — lets future
        // renderers reuse the layout without inventing new exclusions.
        e.target.closest('.plaintext-table') ||
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
            t === 'P' || t === 'DT' || t === 'DD' || t === 'BLOCKQUOTE') return cur;
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
  //
  // The sole UI surface is the tile grid in the ⚙ Settings dialog
  // (`app-settings.js` → `_renderSettingsTab`); the legacy toolbar dropdown
  // has been retired.
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

    safeStorage.set(_THEME_PREF_KEY, theme.id);

    // Retint the landing-surface background canvas to match. The module
    // rebuilds its engine on every call (never reuses across themes) so
    // there's zero state bleed between e.g. mocha hearts and solarized
    // phyllotaxis. Guarded because `BgCanvas` may not be loaded yet on
    // the very first _setTheme() call during _initTheme() — that's fine,
    // BgCanvas.init() bootstraps from the theme class on <body> itself.
    try { if (window.BgCanvas) window.BgCanvas.setTheme(theme.id); } catch (_) { /* background is cosmetic */ }
  },


  // Apply the persisted theme on startup. Call this in App.init().
  //
  // Priority:
  //   1. The explicit `localStorage.loupe_theme` value (if present and valid).
  //   2. The OS `prefers-color-scheme` hint on FIRST boot only (no saved
  //      pref yet) — 'dark' maps to `_DEFAULT_THEME`, 'light' maps to
  //      `'light'`. Matches what the FOUC-prevention inline script in
  //      build.py does so the class set in <head> never changes on first
  //      paint.
  //   3. Hard-coded fallback (`_DEFAULT_THEME` = 'dark').
  //
  // The FOUC-prevention script in build.py's <head> resolves the same
  // priority and sets the theme + dark classes on <body> before CSS
  // applies, so `_initTheme` is mostly a re-apply + internal-state sync.
  _initTheme() {
    const saved = safeStorage.get(_THEME_PREF_KEY);
    let id;
    if (saved && THEMES.some(t => t.id === saved)) {
      id = saved;
    } else {
      // First boot — honour the OS preference. `matchMedia` is not
      // available in e.g. old embedded WebViews, hence the guard.
      let prefersLight = false;
      try {
        prefersLight = !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches);
      } catch (_) { /* matchMedia unavailable */ }
      id = prefersLight ? 'light' : _DEFAULT_THEME;
    }
    this._setTheme(id);
  },



  _setLoading(on) {
    const el = document.getElementById('loading');
    if (on) {
      const spans = el.querySelectorAll('.loading-msg .lm');
      const indices = Array.from({length: spans.length}, (_, i) => i);
      for (let i = indices.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        const tmp = indices[i]; indices[i] = indices[j]; indices[j] = tmp;
      }
      spans.forEach((s, i) => s.style.setProperty('--i', indices[i]));
    }
    el.classList.toggle('hidden', !on);
  },

  _toast(msg, type = 'info') {
    const t = document.getElementById('toast'); t.textContent = msg;
    t.className = type === 'error' ? 'toast-error' : ''; t.classList.remove('hidden');
    setTimeout(() => t.classList.add('hidden'), 3000);
  },

  _fmtBytes(b) { return fmtBytes(b || 0); },

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
  //
  // The Help pane lives in the unified Settings dialog (see app-settings.js).
  // This section used to own a standalone `.help-overlay` modal built by
  // `_openHelpDialog`; that code moved to `_renderHelpTab` and the old
  // entry-point keyboard shortcut (`?` / `H`) now routes through
  // `_openSettingsDialog('help')` — wired in app-core.js.

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

    // Compare versions (YYYYMMDD.HHMM format). Split on '.' to compare
    // the date and time parts independently as integers, avoiding float
    // precision issues where parseFloat('20260424.1400') silently drops
    // the trailing zero, producing wrong comparisons for certain HHMM values.
    const _vparts = (v) => { const p = String(v).split('.'); return [parseInt(p[0], 10) || 0, parseInt(p[1], 10) || 0]; };
    const [rDate, rTime] = _vparts(remoteVersion);
    const [lDate, lTime] = _vparts(localVersion);
    const isUpToDate = localVersion !== 'dev' && (rDate > lDate || (rDate === lDate && rTime >= lTime));

    // Build popup using createElement/textContent so the `?v=` query param
    // (attacker-controlled) can never reach the DOM as HTML. CodeQL flags the
    // previous innerHTML template form (alerts js/xss-through-dom #64, #65)
    // because the `incoming` value is interpolated into an HTML template
    // string — even though LOUPE_VERSION is a build constant, the
    // remoteVersion pathway is not. Using textContent here neutralises both.
    const overlay = document.createElement('div');
    overlay.className = 'help-overlay update-check-overlay';

    const dialog = document.createElement('div');
    dialog.className = 'update-dialog';

    const icon = document.createElement('div');
    icon.className = isUpToDate ? 'update-icon update-icon-ok' : 'update-icon update-icon-new';
    icon.textContent = isUpToDate ? '✅' : '🔄';
    dialog.appendChild(icon);

    const title = document.createElement('h2');
    title.className = 'update-title';
    title.textContent = isUpToDate ? "You're up to date!" : 'New update available!';
    dialog.appendChild(title);

    const detail = document.createElement('p');
    detail.className = 'update-detail';
    if (isUpToDate) {
      detail.appendChild(document.createTextNode('Your version '));
      const s = document.createElement('strong');
      s.textContent = 'v' + remoteVersion;
      detail.appendChild(s);
      detail.appendChild(document.createTextNode(' matches the latest release.'));
    } else {
      detail.appendChild(document.createTextNode('You have '));
      const s1 = document.createElement('strong');
      s1.textContent = 'v' + remoteVersion;
      detail.appendChild(s1);
      detail.appendChild(document.createTextNode(' — the latest version is '));
      const s2 = document.createElement('strong');
      s2.textContent = 'v' + localVersion;
      detail.appendChild(s2);
      detail.appendChild(document.createTextNode('.'));
    }
    dialog.appendChild(detail);

    const closeBtn = document.createElement('button');
    closeBtn.className = 'update-btn update-btn-close';
    closeBtn.textContent = 'Close';

    if (isUpToDate) {
      dialog.appendChild(closeBtn);
    } else {
      const actions = document.createElement('div');
      actions.className = 'update-actions';
      const dl = document.createElement('a');
      dl.className = 'update-btn update-btn-download';
      // Static constant — not attacker-derived — so it's safe as an href.
      dl.href = 'https://github.com/Loupe-tools/Loupe/releases/latest/download/loupe.html';
      dl.target = '_blank';
      dl.rel = 'noopener';
      dl.textContent = '⬇️ Download Latest';
      actions.appendChild(dl);
      actions.appendChild(closeBtn);
      dialog.appendChild(actions);
    }

    overlay.appendChild(dialog);
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
      { id: 'save-raw', icon: '💾', label: 'Save raw file', action: () => this._saveContent() },
      // `enabled` is re-evaluated on every menu open (see _buildExportMenu)
      // so the "Copy raw content" row greys out for binary formats that
      // can't survive a clipboard text round-trip. Tooltip spells out the
      // canonical alternative (💾 Save raw file) so users understand why.
      {
        id: 'copy-raw', icon: '📋', label: 'Copy raw content', action: () => this._copyContent(),
        enabled: () => this._isRawCopyable(),
        disabledTooltip: 'Binary file — use 💾 Save raw file instead',
      },
      { separator: true },
      { id: 'stix', icon: '🧾', label: 'Copy STIX 2.1 bundle (JSON)', action: () => this._exportStix() },
      { id: 'misp', icon: '🎯', label: 'Copy MISP event (JSON)', action: () => this._exportMisp() },
      { id: 'iocs-json', icon: '{…}', label: 'Copy IOCs as JSON', action: () => this._exportIocsJson() },
      { id: 'iocs-csv', icon: '🔢', label: 'Copy IOCs as CSV', action: () => this._exportIocsCsv() },
    ];
  },


  // Rebuilt on every open so per-file `enabled()` predicates (e.g. the
  // "Copy raw content" gate that depends on whether the loaded buffer is
  // text) are re-evaluated against the currently-loaded file rather than
  // being frozen at first-open time.
  _buildExportMenu() {
    const menu = document.getElementById('export-menu');
    if (!menu) return;
    menu.innerHTML = '';
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
      const iconSpan = document.createElement('span');
      iconSpan.className = 'tb-menu-icon';
      iconSpan.textContent = item.icon;
      btn.appendChild(iconSpan);
      const labelSpan = document.createElement('span');
      labelSpan.className = 'tb-menu-label';
      labelSpan.textContent = item.label;
      btn.appendChild(labelSpan);
      const isEnabled = item.enabled ? !!item.enabled() : true;
      if (!isEnabled) {
        btn.disabled = true;
        btn.setAttribute('aria-disabled', 'true');
        btn.classList.add('tb-menu-item-disabled');
        if (item.disabledTooltip) btn.title = item.disabledTooltip;
      }
      btn.addEventListener('click', () => {
        if (btn.disabled) return;
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
        type: r.type,
        value: r.url,
        severity: r.severity || 'info',
        note: r.description || r.ruleName || '',
        source: r._source || r.section || '',
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
        case 'url': return `[url:value = '${esc}']`;
        case 'ipv4': return `[ipv4-addr:value = '${esc}']`;
        case 'ipv6': return `[ipv6-addr:value = '${esc}']`;
        case 'email': return `[email-addr:value = '${esc}']`;
        case 'domain': return `[domain-name:value = '${esc}']`;
        case 'hash-md5': return `[file:hashes.'MD5' = '${esc}']`;
        case 'hash-sha1': return `[file:hashes.'SHA-1' = '${esc}']`;
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
    return `${h.slice(0, 4).join('')}-${h.slice(4, 6).join('')}-${h.slice(6, 8).join('')}-${h.slice(8, 10).join('')}-${h.slice(10, 16).join('')}`;
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
    return `${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex.slice(6, 8).join('')}-${hex.slice(8, 10).join('')}-${hex.slice(10, 16).join('')}`;
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
        case 'url': return { ...base, type: 'url', category: 'Network activity', to_ids: '1' };
        case 'ipv4':
        case 'ipv6': return { ...base, type: 'ip-dst', category: 'Network activity', to_ids: '1' };
        case 'domain': return { ...base, type: 'domain', category: 'Network activity', to_ids: '1' };
        case 'email': return { ...base, type: 'email-src', category: 'Payload delivery', to_ids: '1' };
        case 'hash-md5': return { ...base, type: 'md5', category: 'Payload delivery', to_ids: '1' };
        case 'hash-sha1': return { ...base, type: 'sha1', category: 'Payload delivery', to_ids: '1' };
        case 'hash-sha256': return { ...base, type: 'sha256', category: 'Payload delivery', to_ids: '1' };
        case 'file-path': return { ...base, type: 'filename', category: 'Payload delivery', to_ids: '0' };
        default: return { ...base, type: 'text', category: 'Other', to_ids: '0' };
      }
    };

    const attributes = [];
    const pushAttr = (a) => { attributes.push(a); };

    // File-level attributes (always emitted if we have the data).
    if (meta.name) pushAttr({ type: 'filename', category: 'Payload delivery', to_ids: '0', distribution: '5', value: meta.name, comment: 'Analysed file' });
    if (hashes.md5) pushAttr({ type: 'md5', category: 'Payload delivery', to_ids: '1', distribution: '5', value: hashes.md5, comment: 'File hash (MD5)' });
    if (hashes.sha1) pushAttr({ type: 'sha1', category: 'Payload delivery', to_ids: '1', distribution: '5', value: hashes.sha1, comment: 'File hash (SHA-1)' });
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

// NOTE: The `new App().init();` kick-off used to live here but had to move
// to the END of the App bundle (now at the bottom of
// `src/app/app-breadcrumbs.js` — the last entry in `APP_JS_FILES`).
//
// Why: the bundle is concatenated in `JS_FILES` order and emitted as a
// single inline `<script>`. `Object.assign(App.prototype, …)` runs at
// statement-time (not hoisted), so calling `new App().init()` from the
// middle of the bundle triggers `init()` *before* later mixin files
// (`app-copy-analysis.js`, `app-settings.js`, `app-breadcrumbs.js`) have
// landed their methods on the prototype. `App.init()` calls
// `this._initSettings()` (defined in `app-settings.js`) directly, so a
// mid-bundle kick-off threw `TypeError: this._initSettings is not a
// function`, which in turn aborted `App.init()` between
// `BgCanvas.setTheme()` (called from `_initTheme`) and `BgCanvas.init()`
// — leaving the background canvas running on an unsized 0×0 surface.
//
// Putting the kick-off in the LAST mixin preserves the Tier 3 property
// (App `<script>` runs ahead of the heavy renderer vendors) while
// guaranteeing every `Object.assign` mixin has executed first. See
// `src/app/app-breadcrumbs.js` for the actual call site.

