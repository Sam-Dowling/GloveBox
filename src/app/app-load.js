// ════════════════════════════════════════════════════════════════════════════
// _md5  — compact pure-JS MD5 (crypto.subtle doesn't support MD5)
// ════════════════════════════════════════════════════════════════════════════
function _md5(bytes) {
  function add(x, y) { const l = (x & 0xFFFF) + (y & 0xFFFF); return (((x >> 16) + (y >> 16) + (l >> 16)) << 16) | (l & 0xFFFF); }
  function rol(x, n) { return (x << n) | (x >>> (32 - n)); }
  const T = []; for (let i = 1; i <= 64; i++)T[i] = Math.floor(Math.abs(Math.sin(i)) * 0x100000000) >>> 0;
  const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const n = bytes.length, pad = new Uint8Array((n + 72) & ~63);
  pad.set(bytes); pad[n] = 0x80;
  const dv = new DataView(pad.buffer);
  dv.setUint32(pad.length - 8, n << 3, true); dv.setUint32(pad.length - 4, n >>> 29, true);
  let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
  for (let o = 0; o < pad.length; o += 64) {
    const W = []; for (let i = 0; i < 16; i++)W[i] = dv.getUint32(o + i * 4, true);
    let A = a, B = b, C = c, D = d;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = 7 * i % 16; }
      F = add(add(add(F, A), W[g]), T[i + 1]);
      A = D; D = C; C = B; B = add(B, rol(F, S[i]));
    }
    a = add(a, A); b = add(b, B); c = add(c, C); d = add(d, D);
  }
  return [a, b, c, d].map(v => [v & 255, v >> 8 & 255, v >> 16 & 255, v >> 24 & 255].map(x => x.toString(16).padStart(2, '0')).join('')).join('');
}

// ════════════════════════════════════════════════════════════════════════════
// App — file loading, hashing, interesting-string extraction
// ════════════════════════════════════════════════════════════════════════════
Object.assign(App.prototype, {

  async _loadFile(file) {
    this._setLoading(true);
    document.getElementById('file-info').textContent = file.name;
    const ext = file.name.split('.').pop().toLowerCase();
    try {
      const buffer = await file.arrayBuffer();
      // Store buffer for YARA scanning
      this._fileBuffer = buffer;
      let docEl, analyzer = null;

      // Store file metadata for sidebar display
      this._fileMeta = {
        name: file.name,
        size: file.size,
        mimeType: file.type || '',
        lastModified: file.lastModified ? new Date(file.lastModified).toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC') : '',
        magic: this._detectMagic(new Uint8Array(buffer)),
        entropy: this._computeEntropy(new Uint8Array(buffer)),
      };

      // Compute file hashes in parallel with parsing
      const hashPromise = this._hashFile(buffer);

      if (['docx', 'docm'].includes(ext)) {
        const parsed = await new DocxParser().parse(buffer);
        analyzer = new SecurityAnalyzer();
        this.findings = analyzer.analyze(parsed);
        docEl = new ContentRenderer(parsed).render();
      } else if (['xlsx', 'xlsm', 'xls', 'ods'].includes(ext)) {
        const r = new XlsxRenderer();
        this.findings = await r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (['pptx', 'pptm'].includes(ext)) {
        const r = new PptxRenderer();
        this.findings = await r.analyzeForSecurity(buffer, file.name);
        docEl = await r.render(buffer);
      } else if (ext === 'odt') {
        const r = new OdtRenderer();
        this.findings = await r.analyzeForSecurity(buffer, file.name);
        docEl = await r.render(buffer);
      } else if (ext === 'odp') {
        const r = new OdpRenderer();
        this.findings = await r.analyzeForSecurity(buffer, file.name);
        docEl = await r.render(buffer);
      } else if (ext === 'ppt') {
        const r = new PptBinaryRenderer();
        this.findings = r.analyzeForSecurity(buffer);
        docEl = r.render(buffer);
      } else if (['csv', 'tsv'].includes(ext)) {
        const text = await file.text();
        const r = new CsvRenderer();
        this.findings = r.analyzeForSecurity(text);
        docEl = r.render(text, file.name);
      } else if (ext === 'doc') {
        const r = new DocBinaryRenderer();
        this.findings = r.analyzeForSecurity(buffer);
        docEl = r.render(buffer);
      } else if (ext === 'msg') {
        const r = new MsgRenderer();
        this.findings = r.analyzeForSecurity(buffer);
        docEl = r.render(buffer);
      } else if (ext === 'eml') {
        const r = new EmlRenderer();
        this.findings = r.analyzeForSecurity(buffer);
        docEl = r.render(buffer);
      } else if (ext === 'lnk') {
        const r = new LnkRenderer();
        this.findings = r.analyzeForSecurity(buffer);
        docEl = r.render(buffer);
      } else if (ext === 'hta') {
        const r = new HtaRenderer();
        this.findings = r.analyzeForSecurity(buffer);
        docEl = r.render(buffer);
      } else if (ext === 'rtf') {
        const r = new RtfRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (['zip', 'rar', '7z', 'cab', 'gz', 'tar'].includes(ext)) {
        const r = new ZipRenderer();
        this.findings = await r.analyzeForSecurity(buffer, file.name);
        docEl = await r.render(buffer, file.name);
        // Listen for inner-file open events from clickable archive entries
        docEl.addEventListener('open-inner-file', (e) => {
          const innerFile = e.detail;
          if (innerFile) {
            this._pushNavState(file.name);
            this._loadFile(innerFile);
          }
        });
      } else if (['iso', 'img'].includes(ext)) {
        const r = new IsoRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (['url', 'webloc', 'website'].includes(ext)) {
        const r = new UrlShortcutRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (ext === 'one') {
        const r = new OneNoteRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (['iqy', 'slk'].includes(ext)) {
        const r = new IqySlkRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (['wsf', 'wsc', 'wsh'].includes(ext)) {
        const r = new WsfRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (['html', 'htm', 'mht', 'mhtml', 'xhtml', 'svg'].includes(ext)) {
        const r = new HtmlRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        if (this.findings.augmentedBuffer) {
          this._fileBuffer = this.findings.augmentedBuffer;
        }
        docEl = r.render(buffer, file.name);
      } else if (ext === 'pdf') {
        const r = new PdfRenderer();
        this.findings = await r.analyzeForSecurity(buffer, file.name);
        docEl = await r.render(buffer);
      } else if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'tif', 'tiff', 'avif'].includes(ext)) {
        const r = new ImageRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else {
        // Catch-all: plain text or hex dump for any unrecognised format
        const r = new PlainTextRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      }

      // Extract interesting strings from rendered text + VBA source
      // Use ._rawText if available (PlainTextRenderer provides clean decoded text
      // instead of hex dump output that would break IOC extraction)
      const analysisText = docEl._rawText || docEl.textContent;
      this.findings.interestingStrings = this._extractInterestingStrings(analysisText, this.findings);

      // ── Encoded content detection ─────────────────────────────────────
      try {
        const detector = new EncodedContentDetector();
        const encodedFindings = await detector.scan(
          analysisText,
          new Uint8Array(buffer),
          {
            fileType: ext,
            existingIOCs: this.findings.interestingStrings,
            mimeAttachments: this.findings._mimeAttachments || null,
          }
        );
        this.findings.encodedContent = encodedFindings;
        // Store raw bytes reference on compressed findings for lazy decompression
        for (const ef of encodedFindings) {
          if (ef.needsDecompression) ef._rawBytes = new Uint8Array(buffer);
          // Merge IOCs from decoded content into main findings
          if (ef.iocs && ef.iocs.length) {
            const existingUrls = new Set((this.findings.interestingStrings || []).map(r => r.url));
            for (const ioc of ef.iocs) {
              if (!existingUrls.has(ioc.url)) {
                this.findings.interestingStrings.push(ioc);
                existingUrls.add(ioc.url);
              }
            }
          }
        }
      } catch (encErr) {
        console.warn('Encoded content detection error:', encErr);
        this.findings.encodedContent = [];
      }

      // Bump overall risk if encoded content findings have high severity
      this._updateRiskFromEncodedContent();

      const pc = document.getElementById('page-container');
      pc.innerHTML = ''; pc.appendChild(docEl);

      const dz = document.getElementById('drop-zone');
      dz.className = 'has-document'; dz.innerHTML = '';

      const pages = pc.querySelectorAll('.page').length;
      const pi = pages > 0 ? `  ·  ${pages} page${pages !== 1 ? 's' : ''}` : '';
      document.getElementById('file-info').textContent = `${file.name}${pi}  ·  ${this._fmtBytes(file.size)}`;
      document.getElementById('btn-close').classList.remove('hidden');
      document.getElementById('viewer-toolbar').classList.remove('hidden');

      // Enable grab-to-pan on non-plaintext views
      const viewer = document.getElementById('viewer');
      const isPlaintext = !!pc.querySelector('.plaintext-view, .hex-view');
      viewer.classList.toggle('pannable', !isPlaintext);

      // Await hashes and render sidebar
      this.fileHashes = await hashPromise;
      this._renderSidebar(file.name, analyzer);

      // If the renderer decoded non-UTF-8 content (e.g. UTF-16LE PowerShell),
      // re-encode as UTF-8 for YARA scanning so text-based rules can match.
      // Hashes are already computed from the original raw bytes above.
      if (docEl._rawText) {
        this._fileBuffer = new TextEncoder().encode(docEl._rawText).buffer;
      }

      // Auto-run YARA scan against loaded file
      this._autoYaraScan();

      // Show/hide back button for archive navigation
      this._updateNavBackButton();
    } catch (e) {
      console.error(e);
      this._toast(`Failed to open: ${e.message}`, 'error');
      const pc = document.getElementById('page-container'); pc.innerHTML = '';
      const eb = document.createElement('div'); eb.className = 'error-box';
      const h3 = document.createElement('h3'); h3.textContent = 'Failed to open file'; eb.appendChild(h3);
      const p1 = document.createElement('p'); p1.textContent = e.message; eb.appendChild(p1);
      pc.appendChild(eb);
    } finally { this._setLoading(false); }
  },

  // ── Hashing ─────────────────────────────────────────────────────────────
  async _hashFile(buffer) {
    const data = buffer instanceof ArrayBuffer ? buffer : buffer.buffer;
    try {
      const [s1, s256] = await Promise.all([
        crypto.subtle.digest('SHA-1', data),
        crypto.subtle.digest('SHA-256', data)
      ]);
      const hex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
      return { md5: _md5(new Uint8Array(data)), sha1: hex(s1), sha256: hex(s256) };
    } catch (e) { return { md5: '—', sha1: '—', sha256: '—' }; }
  },

  // ── File magic detection ────────────────────────────────────────────────
  _detectMagic(bytes) {
    if (bytes.length < 4) return { hex: '', label: 'Unknown' };
    const h = n => Array.from(bytes.subarray(0, n)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
    // Check common signatures
    if (bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04)
      return { hex: h(4), label: 'ZIP / OOXML (PK)' };
    if (bytes[0] === 0xD0 && bytes[1] === 0xCF && bytes[2] === 0x11 && bytes[3] === 0xE0)
      return { hex: h(4), label: 'OLE/CFB Compound File' };
    if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46)
      return { hex: h(4), label: 'PDF Document' };
    if (bytes[0] === 0x4D && bytes[1] === 0x5A)
      return { hex: h(2), label: 'PE Executable (MZ)' };
    if (bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46)
      return { hex: h(4), label: 'ELF Binary' };
    if (bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72)
      return { hex: h(3), label: 'RAR Archive' };
    if (bytes[0] === 0x37 && bytes[1] === 0x7A && bytes[2] === 0xBC && bytes[3] === 0xAF)
      return { hex: h(4), label: '7-Zip Archive' };
    if (bytes[0] === 0x4C && bytes[1] === 0x00 && bytes[2] === 0x00 && bytes[3] === 0x00)
      return { hex: h(4), label: 'Windows Shortcut (LNK)' };
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47)
      return { hex: h(4), label: 'PNG Image' };
    if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF)
      return { hex: h(3), label: 'JPEG Image' };
    if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46)
      return { hex: h(3), label: 'GIF Image' };
    // Text-based detection
    const head = String.fromCharCode(...bytes.subarray(0, Math.min(20, bytes.length)));
    if (head.startsWith('{\\rtf')) return { hex: h(5), label: 'Rich Text Format (RTF)' };
    if (head.startsWith('<!DOCTYPE') || head.startsWith('<html') || head.startsWith('<HTML'))
      return { hex: h(6), label: 'HTML Document' };
    if (head.startsWith('<HTA:') || head.includes('<HTA:'))
      return { hex: h(6), label: 'HTML Application (HTA)' };
    if (head.startsWith('<?xml') || head.startsWith('<xml'))
      return { hex: h(5), label: 'XML Document' };
    if (head.startsWith('[InternetShortcut]'))
      return { hex: h(8), label: 'Internet Shortcut (.url)' };
    if (head.startsWith('From ') || head.startsWith('Received:') || head.startsWith('MIME-Version'))
      return { hex: h(6), label: 'Email Message (RFC 5322)' };
    if (bytes.length > 32768 + 5) {
      const iso = String.fromCharCode(bytes[32769], bytes[32770], bytes[32771], bytes[32772], bytes[32773]);
      if (iso === 'CD001') return { hex: 'CD001', label: 'ISO 9660 Disk Image' };
    }
    // OneNote magic
    if (bytes.length >= 16 && bytes[0] === 0xE4 && bytes[1] === 0x52 && bytes[2] === 0x5C && bytes[3] === 0x7B)
      return { hex: h(4), label: 'OneNote Document' };
    return { hex: h(Math.min(4, bytes.length)), label: 'Unknown' };
  },

  // ── Shannon entropy ─────────────────────────────────────────────────────
  _computeEntropy(bytes) {
    if (bytes.length === 0) return 0;
    const freq = new Uint32Array(256);
    for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
    let entropy = 0;
    const len = bytes.length;
    for (let i = 0; i < 256; i++) {
      if (freq[i] === 0) continue;
      const p = freq[i] / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 1000) / 1000;
  },

  // ── Navigation stack (for going back from inner archive files) ──────────
  _pushNavState(parentName) {
    if (!this._navStack) this._navStack = [];
    const pc = document.getElementById('page-container');
    this._navStack.push({
      findings: this.findings,
      fileHashes: this.fileHashes,
      fileMeta: this._fileMeta,
      fileBuffer: this._fileBuffer,
      yaraResults: this._yaraResults,
      pageHTML: pc.innerHTML,
      fileInfoText: document.getElementById('file-info').textContent,
      parentName,
    });
  },

  _navBack() {
    if (!this._navStack || !this._navStack.length) return;
    const state = this._navStack.pop();
    this.findings = state.findings;
    this.fileHashes = state.fileHashes;
    this._fileMeta = state.fileMeta;
    this._fileBuffer = state.fileBuffer;
    this._yaraResults = state.yaraResults;

    const pc = document.getElementById('page-container');
    pc.innerHTML = state.pageHTML;
    document.getElementById('file-info').textContent = state.fileInfoText;

    // Re-attach click handlers on ZIP rows (innerHTML loses event listeners)
    // We need to re-render from the stored buffer instead
    // For simplicity, just show the saved HTML — the user can re-open the archive file if needed
    // But we DO need to re-wire the open-inner-file listeners
    const zipView = pc.querySelector('.zip-view');
    if (zipView && state.fileBuffer) {
      // Re-render the ZIP to get working click handlers
      this._reRenderZip(state, pc);
    }

    // Re-render sidebar
    this._renderSidebar(state.parentName, null);

    // Update back button visibility
    this._updateNavBackButton();
  },

  async _reRenderZip(state, pc) {
    try {
      const r = new ZipRenderer();
      const buf = state.fileBuffer;
      const docEl = await r.render(buf, state.parentName);
      docEl.addEventListener('open-inner-file', (e) => {
        const innerFile = e.detail;
        if (innerFile) {
          this._pushNavState(state.parentName);
          this._loadFile(innerFile);
        }
      });
      pc.innerHTML = '';
      pc.appendChild(docEl);
    } catch (_) { /* fallback: static HTML already set */ }
  },

  _updateNavBackButton() {
    let btn = document.getElementById('btn-nav-back');
    if (this._navStack && this._navStack.length > 0) {
      if (!btn) {
        btn = document.createElement('button');
        btn.id = 'btn-nav-back';
        btn.className = 'tb-btn nav-back-btn';
        btn.textContent = '← Back';
        btn.title = 'Return to parent archive';
        btn.addEventListener('click', () => this._navBack());
        const fileInfoWrap = document.getElementById('file-info-wrap');
        fileInfoWrap.parentNode.insertBefore(btn, fileInfoWrap);
      }
      btn.classList.remove('hidden');
    } else {
      if (btn) btn.classList.add('hidden');
    }
  },

  // ── Interesting string extraction ────────────────────────────────────────
  _extractInterestingStrings(text, findings) {
    const seen = new Set((findings.externalRefs || []).map(r => r.url));
    const results = [];
    const add = (type, val, sev) => {
      val = (val || '').trim().replace(/[.,;:!?)\]>]+$/, '');
      if (!val || val.length < 4 || val.length > 400 || seen.has(val)) return;
      seen.add(val); results.push({ type, url: val, severity: sev });
    };
    // Scan rendered text + VBA modules
    const sources = [text, ...(findings.modules || []).map(m => m.source || '')];
    const full = sources.join('\n');
    for (const m of full.matchAll(/https?:\/\/[^\s"'<>()\[\]{}\u0000-\u001F]{6,}/g)) add(IOC.URL, m[0], 'info');
    for (const m of full.matchAll(/\b[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b/g)) add(IOC.EMAIL, m[0], 'info');
    for (const m of full.matchAll(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g)) {
      const parts = m[0].split('.').map(Number);
      if (parts.every(p => p <= 255) && !m[0].startsWith('0.')) add(IOC.IP, m[0], 'medium');
    }
    for (const m of full.matchAll(/[A-Za-z]:\\(?:[\w\-. ]+\\)+[\w\-. ]{2,}/g)) add(IOC.FILE_PATH, m[0], 'medium');
    for (const m of full.matchAll(/\\\\[\w.\-]{2,}(?:\\[\w.\-]{1,})+/g)) add(IOC.UNC_PATH, m[0], 'medium');
    // VBA-specific URL scan with higher severity
    for (const mod of (findings.modules || [])) {
      for (const m of (mod.source || '').matchAll(/https?:\/\/[^\s"']{6,}/g)) {
        const v = m[0].replace(/[.,;:!?)\]>]+$/, '');
        if (!seen.has(v)) { seen.add(v); results.push({ type: IOC.URL, url: v, severity: 'high' }); }
      }
    }
    return results.slice(0, 300);
  },

});
