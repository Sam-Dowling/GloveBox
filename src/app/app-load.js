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
// SafeLink URL unwrapping — delegates to EncodedContentDetector.unwrapSafeLink
// ════════════════════════════════════════════════════════════════════════════

/**
 * Unwrap Proofpoint URLDefense and Microsoft SafeLinks URLs.
 * @param {string} url  The potentially wrapped URL.
 * @returns {object|null}  { originalUrl, emails: [], provider } or null if not a SafeLink.
 */
function _unwrapSafeLink(url) {
  return EncodedContentDetector.unwrapSafeLink(url);
}

// ════════════════════════════════════════════════════════════════════════════
// Defanged URL/IP/email refanging — converts security-defanged IOCs to normal
// ════════════════════════════════════════════════════════════════════════════

/**
 * Refang a defanged URL, IP, domain, or email address.
 * Common defang patterns: hxxp → http, [.] → ., [@] → @, [://] → ://
 * @param {string} str - Potentially defanged string.
 * @returns {object|null} - { original, refanged } or null if not defanged.
 */
function _refangString(str) {
  if (!str || typeof str !== 'string') return null;

  let refanged = str;
  let changed = false;

  // Protocol: hxxp → http, hxxps → https (case-insensitive)
  refanged = refanged.replace(/\bhxxps?/gi, m => {
    changed = true;
    return m.toLowerCase().replace('xx', 'tt');
  });

  // Protocol separator variants: [://], [:], [:/], etc. → ://
  refanged = refanged.replace(/\[:\/\/\]/g, () => { changed = true; return '://'; });
  refanged = refanged.replace(/\[:\/\]/g, () => { changed = true; return '://'; });
  refanged = refanged.replace(/\[:\]/g, () => { changed = true; return ':'; });

  // Dots: [.] → .
  refanged = refanged.replace(/\[\.\]/g, () => { changed = true; return '.'; });

  // At symbol: [@] → @
  refanged = refanged.replace(/\[@\]/g, () => { changed = true; return '@'; });

  return changed ? { original: str, refanged } : null;
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
      const buffer = await ParserWatchdog.run(() => file.arrayBuffer());
      // Store buffer for YARA scanning
      this._fileBuffer = buffer;
      // Reset YARA state from previous file to prevent stale results bleeding over
      this._yaraBuffer = null;
      this._yaraResults = null;
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
      } else if (ext === 'evtx') {
        const r = new EvtxRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (ext === 'sqlite' || ext === 'db') {
        const r = new SqliteRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (ext === 'doc') {
        const r = new DocBinaryRenderer();
        this.findings = r.analyzeForSecurity(buffer);
        docEl = r.render(buffer);
      } else if (ext === 'msg') {
        const r = new MsgRenderer();
        this.findings = r.analyzeForSecurity(buffer);
        docEl = r.render(buffer);
        // Listen for inner-file open events from MSG attachments
        docEl.addEventListener('open-inner-file', (e) => {
          const innerFile = e.detail;
          if (innerFile) {
            this._pushNavState(file.name);
            this._loadFile(innerFile);
          }
        });
      } else if (ext === 'eml') {
        const r = new EmlRenderer();
        this.findings = r.analyzeForSecurity(buffer);
        docEl = r.render(buffer);
        // Listen for inner-file open events from EML attachments
        docEl.addEventListener('open-inner-file', (e) => {
          const innerFile = e.detail;
          if (innerFile) {
            this._pushNavState(file.name);
            this._loadFile(innerFile);
          }
        });
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
      } else if (['jar', 'war', 'ear', 'class'].includes(ext)) {
        // Mark the body so core.css can clamp the sidebar to 33vw (vs the
        // default 50vw ceiling). JAR viewers have dense tables, a file tree,
        // and a tab strip that need horizontal room; this is done before
        // `_renderSidebar()` runs so the width-lock captures the clamped value.
        document.body.classList.add('jar-active');
        const r = new JarRenderer();
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
      } else if (['zip', 'rar', '7z', 'cab', 'gz', 'gzip', 'tar', 'tgz'].includes(ext)) {
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
      } else if (ext === 'reg') {
        const r = new RegRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (['inf', 'sct'].includes(ext)) {
        const r = new InfSctRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (ext === 'msi') {
        const r = new MsiRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
        // Listen for stream open events from clickable MSI stream entries
        docEl.addEventListener('open-inner-file', (e) => {
          const innerFile = e.detail;
          if (innerFile) {
            this._pushNavState(file.name);
            this._loadFile(innerFile);
          }
        });
      } else if (ext === 'svg') {
        const r = new SvgRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        if (this.findings.augmentedBuffer) {
          this._yaraBuffer = this.findings.augmentedBuffer;
        }
        docEl = r.render(buffer, file.name);
      } else if (['html', 'htm', 'mht', 'mhtml', 'xhtml'].includes(ext)) {
        const r = new HtmlRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        if (this.findings.augmentedBuffer) {
          this._yaraBuffer = this.findings.augmentedBuffer;
        }
        docEl = r.render(buffer, file.name);
      } else if (ext === 'pdf') {
        const r = new PdfRenderer();
        this.findings = await r.analyzeForSecurity(buffer, file.name);
        docEl = await r.render(buffer, file.name, this.findings);
        // Listen for inner-file open events from embedded /Filespec attachments
        docEl.addEventListener('open-inner-file', (e) => {
          const innerFile = e.detail;
          if (innerFile) {
            this._pushNavState(file.name);
            this._loadFile(innerFile);
          }
        });
      } else if (['pgp', 'gpg', 'asc', 'sig'].includes(ext) ||
                 (['key', 'pem', 'crt', 'cer', 'der'].includes(ext) &&
                  this._looksLikePgp(new Uint8Array(buffer)))) {
        const r = new PgpRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (['pem', 'der', 'crt', 'cer', 'p12', 'pfx', 'key'].includes(ext)) {
        const r = new X509Renderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'ico', 'tif', 'tiff', 'avif'].includes(ext)) {
        const r = new ImageRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (['exe', 'dll', 'sys', 'scr', 'cpl', 'ocx', 'drv', 'com'].includes(ext)) {
        const r = new PeRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (['elf', 'so', 'o'].includes(ext)) {
        const r = new ElfRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (['dylib', 'bundle'].includes(ext)) {
        const r = new MachoRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        docEl = r.render(buffer, file.name);
      } else if (ext === 'plist') {
        const r = new PlistRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        if (this.findings.augmentedBuffer) {
          this._yaraBuffer = this.findings.augmentedBuffer;
        }
        docEl = r.render(buffer, file.name);
      } else if (['applescript', 'jxa', 'scpt', 'scptd'].includes(ext)) {
        const r = new OsascriptRenderer();
        this.findings = r.analyzeForSecurity(buffer, file.name);
        if (this.findings.augmentedBuffer) {
          this._yaraBuffer = this.findings.augmentedBuffer;
        }
        docEl = r.render(buffer, file.name);
      } else {
        // ── Content-based detection fallback for extensionless/unknown files ──
        // Detect file type by magic bytes when extension is missing or unrecognized
        const bytes = new Uint8Array(buffer);
        const detectedType = this._detectFileType(bytes);
        
        if (detectedType === 'sqlite') {
          const r = new SqliteRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'evtx') {
          const r = new EvtxRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'lnk') {
          const r = new LnkRenderer();
          this.findings = r.analyzeForSecurity(buffer);
          docEl = r.render(buffer);
        } else if (detectedType === 'pdf') {
          const r = new PdfRenderer();
          this.findings = await r.analyzeForSecurity(buffer, file.name);
          docEl = await r.render(buffer, file.name, this.findings);
          docEl.addEventListener('open-inner-file', (e) => {
            const innerFile = e.detail;
            if (innerFile) {
              this._pushNavState(file.name);
              this._loadFile(innerFile);
            }
          });
        } else if (detectedType === 'zip') {
          // ZIP could be DOCX, XLSX, PPTX, ODT, ODP, ODS, or plain ZIP
          // Try to identify OOXML/ODF by checking internal structure
          const r = new ZipRenderer();
          this.findings = await r.analyzeForSecurity(buffer, file.name);
          docEl = await r.render(buffer, file.name);
          // Listen for inner-file open events
          docEl.addEventListener('open-inner-file', (e) => {
            const innerFile = e.detail;
            if (innerFile) {
              this._pushNavState(file.name);
              this._loadFile(innerFile);
            }
          });
        } else if (detectedType === 'ole') {
          // OLE/CFB could be doc, xls, ppt, msg, or msi - try to identify
          const oleType = this._tryOleCfbDisambiguation(buffer);
          
          if (oleType === 'doc') {
            const r = new DocBinaryRenderer();
            this.findings = r.analyzeForSecurity(buffer);
            docEl = r.render(buffer);
          } else if (oleType === 'xls') {
            const r = new XlsxRenderer();
            this.findings = await r.analyzeForSecurity(buffer, file.name);
            docEl = r.render(buffer, file.name);
          } else if (oleType === 'ppt') {
            const r = new PptBinaryRenderer();
            this.findings = r.analyzeForSecurity(buffer);
            docEl = r.render(buffer);
          } else if (oleType === 'msg') {
            const r = new MsgRenderer();
            this.findings = r.analyzeForSecurity(buffer);
            docEl = r.render(buffer);
            // Listen for inner-file open events from MSG attachments
            docEl.addEventListener('open-inner-file', (e) => {
              const innerFile = e.detail;
              if (innerFile) {
                this._pushNavState(file.name);
                this._loadFile(innerFile);
              }
            });
          } else if (oleType === 'msi') {
            const r = new MsiRenderer();
            this.findings = r.analyzeForSecurity(buffer, file.name);
            docEl = r.render(buffer, file.name);
          } else {
            // Unknown OLE type - try msg first (most common for forensics), then doc
            try {
              const r = new MsgRenderer();
              this.findings = r.analyzeForSecurity(buffer);
              docEl = r.render(buffer);
              // Listen for inner-file open events from MSG attachments
              docEl.addEventListener('open-inner-file', (e) => {
                const innerFile = e.detail;
                if (innerFile) {
                  this._pushNavState(file.name);
                  this._loadFile(innerFile);
                }
              });
            } catch (e) {
              try {
                const r = new DocBinaryRenderer();
                this.findings = r.analyzeForSecurity(buffer);
                docEl = r.render(buffer);
              } catch (e2) {
                // Fall through to plain text
                const r = new PlainTextRenderer();
                this.findings = r.analyzeForSecurity(buffer, file.name);
                docEl = r.render(buffer, file.name, file.type);
              }
            }
          }
        } else if (detectedType === 'image') {
          const r = new ImageRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'rtf') {
          const r = new RtfRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'html') {
          const r = new HtmlRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          if (this.findings.augmentedBuffer) {
            this._yaraBuffer = this.findings.augmentedBuffer;
          }
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'hta') {
          const r = new HtaRenderer();
          this.findings = r.analyzeForSecurity(buffer);
          docEl = r.render(buffer);
        } else if (detectedType === 'eml') {
          const r = new EmlRenderer();
          this.findings = r.analyzeForSecurity(buffer);
          docEl = r.render(buffer);
          // Listen for inner-file open events from EML attachments
          docEl.addEventListener('open-inner-file', (e) => {
            const innerFile = e.detail;
            if (innerFile) {
              this._pushNavState(file.name);
              this._loadFile(innerFile);
            }
          });
        } else if (detectedType === 'url') {
          const r = new UrlShortcutRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'reg') {
          const r = new RegRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'inf') {
          const r = new InfSctRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'iso') {
          const r = new IsoRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'onenote') {
          const r = new OneNoteRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'pe') {
          const r = new PeRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'elf') {
          const r = new ElfRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'jar') {
          // See the extension-based branch above — same rationale for
          // clamping the sidebar for JAR content.
          document.body.classList.add('jar-active');
          const r = new JarRenderer();
          this.findings = await r.analyzeForSecurity(buffer, file.name);
          docEl = await r.render(buffer, file.name);

          docEl.addEventListener('open-inner-file', (e) => {
            const innerFile = e.detail;
            if (innerFile) {
              this._pushNavState(file.name);
              this._loadFile(innerFile);
            }
          });
        } else if (detectedType === 'svg') {
          const r = new SvgRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          if (this.findings.augmentedBuffer) {
            this._yaraBuffer = this.findings.augmentedBuffer;
          }
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'macho') {
          const r = new MachoRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'scpt') {
          const r = new OsascriptRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          if (this.findings.augmentedBuffer) {
            this._yaraBuffer = this.findings.augmentedBuffer;
          }
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'plist') {
          const r = new PlistRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          if (this.findings.augmentedBuffer) {
            this._yaraBuffer = this.findings.augmentedBuffer;
          }
          docEl = r.render(buffer, file.name);
        } else if (detectedType === 'pgp') {
          const r = new PgpRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name);
        } else {
          // Catch-all: plain text or hex dump for any unrecognised format
          const r = new PlainTextRenderer();
          this.findings = r.analyzeForSecurity(buffer, file.name);
          docEl = r.render(buffer, file.name, file.type);
        }
      }

      // Extract interesting strings from rendered text + VBA source
      // Use ._rawText if available (PlainTextRenderer provides clean decoded text
      // instead of hex dump output that would break IOC extraction)
      const analysisText = docEl._rawText || docEl.textContent;
      const rendererIOCs = this.findings.interestingStrings || [];
      this.findings.interestingStrings = [...rendererIOCs, ...this._extractInterestingStrings(analysisText, this.findings)];

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
        // Speculatively decode lazy findings so sidebar can show decoded previews
        // immediately (base64/hex decode is lightweight; skip compressed blobs)
        await Promise.all(
          encodedFindings
            .filter(ef => ef.rawCandidate && !ef.decodedBytes)
            .map(ef => detector.lazyDecode(ef))
        );
        // Store raw bytes reference on compressed findings for lazy decompression
        for (const ef of encodedFindings) {
          if (ef.needsDecompression) ef._rawBytes = new Uint8Array(buffer);
          // Merge IOCs from decoded content into main findings.
          // Attach source location metadata so clicking an IOC from a nested
          // decoded layer will smooth-scroll and highlight the *encoded blob*
          // in the original document from which this IOC was extracted.
          if (ef.iocs && ef.iocs.length) {
            const existingUrls = new Set((this.findings.interestingStrings || []).map(r => r.url));
            for (const ioc of ef.iocs) {
              if (!existingUrls.has(ioc.url)) {
                // Point back to the parent encoded blob's location in the source text
                if (ef.offset !== undefined && ef.length) {
                  ioc._sourceOffset = ef.offset;
                  ioc._sourceLength = ef.length;
                  ioc._highlightText = ef.snippet || (analysisText ? analysisText.substring(ef.offset, ef.offset + Math.min(ef.length, 200)) : '');
                }
                // Note which decode chain produced this IOC
                if (ef.chain && ef.chain.length) {
                  ioc._decodedFrom = ef.chain.join(' → ');
                }
                // Back-reference to parent encoded finding for cross-flash linking
                ioc._encodedFinding = ef;
                this.findings.interestingStrings.push(ioc);
                existingUrls.add(ioc.url);
              } else {
                // IOC already exists from plaintext extraction — set back-reference
                // on the existing entry so cross-flash linking from Encoded Content
                // "IOCs" badge scrolls to the correct Signatures & IOCs row
                const existing = this.findings.interestingStrings.find(r => r.url === ioc.url);
                if (existing && !existing._encodedFinding) {
                  existing._encodedFinding = ef;
                  if (ef.chain && ef.chain.length) {
                    existing._decodedFrom = ef.chain.join(' → ');
                  }
                }
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
    if (bytes[0] === 0xCF && bytes[1] === 0xFA && bytes[2] === 0xED && bytes[3] === 0xFE)
      return { hex: h(4), label: 'Mach-O Binary (64-bit)' };
    if (bytes[0] === 0xCE && bytes[1] === 0xFA && bytes[2] === 0xED && bytes[3] === 0xFE)
      return { hex: h(4), label: 'Mach-O Binary (32-bit)' };
    if (bytes[0] === 0xCA && bytes[1] === 0xFE && bytes[2] === 0xBA && bytes[3] === 0xBE) {
      if (typeof JarRenderer !== 'undefined' && JarRenderer.isJavaClass(bytes))
        return { hex: h(4), label: 'Java Class File' };
      return { hex: h(4), label: 'Mach-O Fat/Universal Binary' };
    }
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
    // Registry files: REGEDIT4 or "Windows Registry Editor Version 5.00" (may have UTF-16LE BOM FF FE)
    if (head.startsWith('REGEDIT4') || head.startsWith('Windows Registry'))
      return { hex: h(8), label: 'Windows Registry File (.reg)' };
    if (bytes.length >= 4 && bytes[0] === 0xFF && bytes[1] === 0xFE) {
      const u16 = new TextDecoder('utf-16le', { fatal: false }).decode(bytes.subarray(0, Math.min(80, bytes.length)));
      if (u16.startsWith('Windows Registry'))
        return { hex: 'FF FE', label: 'Windows Registry File (.reg, UTF-16LE)' };
    }
    // INF: Setup Information files start with [Version] section
    if (head.startsWith('[Version]') || head.startsWith('[version]'))
      return { hex: h(9), label: 'Setup Information File (.inf)' };
    if (head.startsWith('From ') || head.startsWith('Received:') || head.startsWith('MIME-Version'))
      return { hex: h(6), label: 'Email Message (RFC 5322)' };
    // EVTX: "ElfFile\0"
    if (bytes[0] === 0x45 && bytes[1] === 0x6C && bytes[2] === 0x66 && bytes[3] === 0x46 &&
        bytes[4] === 0x69 && bytes[5] === 0x6C && bytes[6] === 0x65 && bytes[7] === 0x00)
      return { hex: h(8), label: 'Windows Event Log (EVTX)' };
    // SQLite: "SQLite format 3\000"
    if (bytes[0] === 0x53 && bytes[1] === 0x51 && bytes[2] === 0x4C && bytes[3] === 0x69 &&
        bytes[4] === 0x74 && bytes[5] === 0x65 && bytes[6] === 0x20)
      return { hex: h(6), label: 'SQLite Database' };
    if (bytes.length > 32768 + 5) {
      const iso = String.fromCharCode(bytes[32769], bytes[32770], bytes[32771], bytes[32772], bytes[32773]);
      if (iso === 'CD001') return { hex: 'CD001', label: 'ISO 9660 Disk Image' };
    }
    // OneNote magic
    if (bytes.length >= 16 && bytes[0] === 0xE4 && bytes[1] === 0x52 && bytes[2] === 0x5C && bytes[3] === 0x7B)
      return { hex: h(4), label: 'OneNote Document' };
    // Binary plist: "bplist"
    if (bytes.length >= 8 && bytes[0] === 0x62 && bytes[1] === 0x70 && bytes[2] === 0x6C &&
        bytes[3] === 0x69 && bytes[4] === 0x73 && bytes[5] === 0x74)
      return { hex: h(8), label: 'Binary Property List (bplist)' };
    // OpenPGP ASCII armor (text-based: -----BEGIN PGP ...)
    if (head.startsWith('-----BEGIN PGP'))
      return { hex: h(14), label: 'OpenPGP ASCII-Armored Data' };
    // PEM certificate (text-based: -----BEGIN ...)
    if (head.startsWith('-----BEGIN '))
      return { hex: h(11), label: 'PEM Encoded Data' };
    // OpenPGP binary packet stream: Public-Key (0x99 / 0xC6), Secret-Key (0x95 / 0xC5),
    // Public-Subkey (0xB9 / 0xCE), Secret-Subkey (0x9D / 0xC7) — followed by a version
    // byte in {3,4,5,6}. Check tight byte patterns to avoid false positives.
    if (bytes.length >= 3 &&
        [0x99, 0x95, 0xB9, 0x9D, 0xC6, 0xC5, 0xCE, 0xC7].includes(bytes[0])) {
      // For old-format packets (0x9X / 0xBX) the version byte is at offset 3 (after 2-byte length);
      // for new-format (0xCX) it follows the length byte(s). We accept either if we see a plausible version in the first 8 bytes.
      const scan = bytes.subarray(0, Math.min(8, bytes.length));
      if ([3, 4, 5, 6].some(v => Array.from(scan).includes(v))) {
        return { hex: h(4), label: 'OpenPGP Binary Key / Signature' };
      }
    }
    // DER certificate (ASN.1 SEQUENCE with long-form length)
    if (bytes[0] === 0x30 && bytes[1] === 0x82)
      return { hex: h(4), label: 'DER / ASN.1 Data' };
    return { hex: h(Math.min(4, bytes.length)), label: 'Unknown' };
  },

  // ── Heuristic: does this buffer look like OpenPGP data? ─────────────────
  // Used to disambiguate .key between X.509 private key (PEM) and PGP key.
  _looksLikePgp(bytes) {
    if (!bytes || bytes.length < 4) return false;
    // ASCII-armored
    const head = String.fromCharCode(...bytes.subarray(0, Math.min(64, bytes.length)));
    if (head.includes('-----BEGIN PGP ')) return true;
    // Binary OpenPGP packet headers (Public-Key, Secret-Key, their subkey variants,
    // both old-format and new-format)
    const first = bytes[0];
    if ([0x99, 0x95, 0xB9, 0x9D, 0xC6, 0xC5, 0xCE, 0xC7].includes(first)) return true;
    return false;
  },


  // ── OLE/CFB disambiguation (determine doc/xls/ppt/msg/msi from OLE compound) ──
  _tryOleCfbDisambiguation(buffer) {
    // Try to identify the specific OLE compound file type
    // by checking internal structure and stream names.
    // Uses metadata-only parsing to avoid loading large stream content.
    try {
      // Parse OLE structure to get stream names (metadata only)
      const parser = new OleCfbParser(buffer);
      parser.parseMetadataOnly();
      
      // Get all stream names (already lowercase from parser)
      const streamNames = Array.from(parser.streamMeta.keys());
      
      // MSG (Outlook message): has __substg1.0_ streams
      if (streamNames.some(n => n.startsWith('__substg1.0_')))
        return 'msg';
      
      // MSI (Windows Installer): has specific streams
      if (streamNames.includes('!_stringpool') || streamNames.includes('!_stringdata'))
        return 'msi';
      
      // DOC (Word): has WordDocument stream
      if (streamNames.includes('worddocument'))
        return 'doc';
      
      // XLS (Excel): has Workbook stream
      if (streamNames.includes('workbook'))
        return 'xls';
      
      // PPT (PowerPoint): has PowerPoint Document or Current User stream
      if (streamNames.includes('powerpoint document') || streamNames.includes('current user'))
        return 'ppt';
      
    } catch (e) {
      // If parsing fails, return null and let it try renderers in sequence
    }
    
    return null; // Unknown OLE type - will try renderers in sequence
  },

  // ── Content-based file type detection (fallback for extensionless files) ──
  _detectFileType(bytes) {
    if (bytes.length < 4) return null;
    
    // SQLite: "SQLite format 3\000"
    if (bytes[0] === 0x53 && bytes[1] === 0x51 && bytes[2] === 0x4C && bytes[3] === 0x69 &&
        bytes[4] === 0x74 && bytes[5] === 0x65 && bytes[6] === 0x20)
      return 'sqlite';
    
    // EVTX: "ElfFile\0"
    if (bytes[0] === 0x45 && bytes[1] === 0x6C && bytes[2] === 0x66 && bytes[3] === 0x46 &&
        bytes[4] === 0x69 && bytes[5] === 0x6C && bytes[6] === 0x65 && bytes[7] === 0x00)
      return 'evtx';
    
    // Windows Shortcut (LNK)
    if (bytes[0] === 0x4C && bytes[1] === 0x00 && bytes[2] === 0x00 && bytes[3] === 0x00)
      return 'lnk';
    
    // PDF
    if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46)
      return 'pdf';
    
    // ZIP / OOXML (could be docx, xlsx, pptx, odt, odp, ods, or just zip)
    if (bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04)
      return 'zip';
    
    // OLE/CFB Compound File (could be doc, xls, ppt, msg, msi)
    if (bytes[0] === 0xD0 && bytes[1] === 0xCF && bytes[2] === 0x11 && bytes[3] === 0xE0)
      return 'ole';
    
    // PNG Image
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47)
      return 'image';
    
    // JPEG Image
    if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF)
      return 'image';
    
    // GIF Image
    if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46)
      return 'image';
    
    // RAR Archive
    if (bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72)
      return 'zip'; // Route to ZipRenderer which handles RAR
    
    // 7-Zip Archive
    if (bytes[0] === 0x37 && bytes[1] === 0x7A && bytes[2] === 0xBC && bytes[3] === 0xAF)
      return 'zip'; // Route to ZipRenderer
    
    // PE Executable (MZ header)
    if (bytes[0] === 0x4D && bytes[1] === 0x5A)
      return 'pe';
    
    // ELF Binary
    if (bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46)
      return 'elf';
    
    // Mach-O Binary (64-bit LE: CF FA ED FE, 32-bit LE: CE FA ED FE)
    if ((bytes[0] === 0xCF && bytes[1] === 0xFA && bytes[2] === 0xED && bytes[3] === 0xFE) ||
        (bytes[0] === 0xCE && bytes[1] === 0xFA && bytes[2] === 0xED && bytes[3] === 0xFE))
      return 'macho';
    
    // CA FE BA BE — shared by Java class files and Mach-O Fat/Universal binaries
    if (bytes[0] === 0xCA && bytes[1] === 0xFE && bytes[2] === 0xBA && bytes[3] === 0xBE) {
      if (typeof JarRenderer !== 'undefined' && JarRenderer.isJavaClass(bytes))
        return 'jar';
      return 'macho';
    }
    
    // Gzip
    if (bytes[0] === 0x1F && bytes[1] === 0x8B)
      return 'zip'; // Route to ZipRenderer which handles gzip
    
    // TAR (check for "ustar" magic at offset 257)
    if (bytes.length > 262) {
      const tarMagic = String.fromCharCode(bytes[257], bytes[258], bytes[259], bytes[260], bytes[261]);
      if (tarMagic === 'ustar') return 'zip'; // Route to ZipRenderer which handles TAR
    }
    
    // ISO 9660 Disk Image (check at offset 32769)
    if (bytes.length > 32768 + 5) {
      const iso = String.fromCharCode(bytes[32769], bytes[32770], bytes[32771], bytes[32772], bytes[32773]);
      if (iso === 'CD001') return 'iso';
    }
    
    // OneNote
    if (bytes.length >= 16 && bytes[0] === 0xE4 && bytes[1] === 0x52 && bytes[2] === 0x5C && bytes[3] === 0x7B)
      return 'onenote';
    
    // Binary plist: "bplist" (0x62 0x70 0x6C 0x69 0x73 0x74)
    if (bytes.length >= 8 && bytes[0] === 0x62 && bytes[1] === 0x70 && bytes[2] === 0x6C &&
        bytes[3] === 0x69 && bytes[4] === 0x73 && bytes[5] === 0x74)
      return 'plist';
    
    // Compiled AppleScript (FasTX magic: 0x46 0x61 0x73 0x54)
    if (bytes[0] === 0x46 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x54)
      return 'scpt';
    
    // Binary OpenPGP packet stream — first byte is an OpenPGP packet header
    // (Public-Key, Secret-Key, Public-Subkey, Secret-Subkey in both old+new format).
    // Check tight byte patterns + plausible version byte to avoid false positives.
    if ([0x99, 0x95, 0xB9, 0x9D, 0xC6, 0xC5, 0xCE, 0xC7].includes(bytes[0])) {
      const scan = bytes.subarray(0, Math.min(8, bytes.length));
      if ([3, 4, 5, 6].some(v => Array.from(scan).includes(v)))
        return 'pgp';
    }
    
    // Text-based detection (check first 20 bytes as string)
    const head = String.fromCharCode(...bytes.subarray(0, Math.min(20, bytes.length)));
    
    // RTF
    if (head.startsWith('{\\rtf')) return 'rtf';
    
    // SVG (check before HTML — SVG is valid XML that starts with <?xml or <svg)
    if (head.startsWith('<svg') || head.includes('<svg'))
      return 'svg';
    // SVG with XML declaration — check more bytes
    if (head.startsWith('<?xml')) {
      const head200 = String.fromCharCode(...bytes.subarray(0, Math.min(200, bytes.length)));
      if (/<svg[\s>]/i.test(head200)) return 'svg';
    }
    
    // HTML / HTA
    if (head.startsWith('<!DOCTYPE') || head.startsWith('<html') || head.startsWith('<HTML'))
      return 'html';
    if (head.startsWith('<HTA:') || head.includes('<HTA:'))
      return 'hta';
    
    // Email (RFC 5322)
    if (head.startsWith('From ') || head.startsWith('Received:') || head.startsWith('MIME-Version'))
      return 'eml';
    
    // URL shortcut
    if (head.startsWith('[InternetShortcut]'))
      return 'url';
    
    // OpenPGP ASCII armor (-----BEGIN PGP PUBLIC KEY BLOCK-----, etc.)
    if (head.startsWith('-----BEGIN PGP'))
      return 'pgp';
    
    // Registry files
    if (head.startsWith('REGEDIT4') || head.startsWith('Windows Registry'))
      return 'reg';
    if (bytes.length >= 4 && bytes[0] === 0xFF && bytes[1] === 0xFE) {
      const u16 = new TextDecoder('utf-16le', { fatal: false }).decode(bytes.subarray(0, Math.min(80, bytes.length)));
      if (u16.startsWith('Windows Registry'))
        return 'reg';
    }
    
    // INF Setup Information files
    if (head.startsWith('[Version]') || head.startsWith('[version]'))
      return 'inf';
    
    // XML plist (text-based — check for <plist or <!DOCTYPE plist)
    if (head.startsWith('<?xml') || head.startsWith('<plist') || head.startsWith('<!DOCTYPE')) {
      const head500 = String.fromCharCode(...bytes.subarray(0, Math.min(500, bytes.length)));
      if (/<plist[\s>]/i.test(head500) || /<!DOCTYPE\s+plist/i.test(head500))
        return 'plist';
    }
    
    return null; // Unknown - will fall through to PlainTextRenderer
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
  //
  // Strategy: instead of serialising the rendered DOM via innerHTML (which
  // destroys event listeners, tab state, tree expansion, scroll position,
  // and any JS-held references), we *detach* the live DOM node from the
  // page container and park it on the nav stack. When the user clicks Back,
  // we re-attach the exact same node tree — preserving everything.
  //
  // Safety net: if re-attachment fails (detached node missing, renderer
  // mismatch), we fall back to re-rendering from the stored buffer via the
  // per-format helpers below.
  _pushNavState(parentName) {
    if (!this._navStack) this._navStack = [];
    // Enforce nesting depth limit to prevent recursive archive bombs
    if (this._navStack.length >= PARSER_LIMITS.MAX_DEPTH) {
      console.warn(`Nesting depth limit reached (${PARSER_LIMITS.MAX_DEPTH}) — refusing to open inner file`);
      const toast = document.getElementById('toast');
      if (toast) { toast.textContent = `⚠ Nesting depth limit (${PARSER_LIMITS.MAX_DEPTH}) reached — cannot open further nested files.`; toast.className = ''; setTimeout(() => toast.className = 'hidden', 4000); }
      throw new Error('DEPTH_LIMIT');
    }
    const pc = document.getElementById('page-container');
    const docEl = pc && pc.firstElementChild;

    // CAPTURE ORDER MATTERS: we must read #viewer.scrollTop and walk the
    // live DOM for a scroll anchor *before* detaching the JAR view,
    // because removeChild() empties #page-container which instantly
    // clamps #viewer.scrollTop to 0 and detaches every element we would
    // want to anchor on (detached elements report zero-sized bounding
    // rects). If we read after the detach we save garbage (scroll=0,
    // anchor=null), leaving Back navigation unable to restore position.
    //
    // In addition to the numeric scrollTop we capture a DOM *anchor*: a
    // direct reference to the element that was sitting at the top of the
    // viewport, plus its offset from the pane top. When we restore, the
    // re-rendered sidebar can cause #viewer to change width by a few pixels,
    // which reflows the JAR view and makes the saved scrollTop point at a
    // slightly different visual row. Scrolling the anchor element into view
    // instead locks onto the same row regardless of reflow.
    const viewerEl = document.getElementById('viewer');
    const sbBodyEl = document.getElementById('sb-body');
    const viewerScroll = viewerEl ? { top: viewerEl.scrollTop, left: viewerEl.scrollLeft } : null;
    const sbBodyScroll = sbBodyEl ? { top: sbBodyEl.scrollTop, left: sbBodyEl.scrollLeft } : null;
    const viewerAnchor = this._captureScrollAnchor(viewerEl, docEl);
    const sbBodyAnchor = this._captureScrollAnchor(sbBodyEl, sbBodyEl);

    // Also snapshot scroll of every scrollable descendant of the JAR view
    // itself (inner tab panes, search results list, etc.) before detaching.
    let scrollSnapshot = null;
    if (docEl) scrollSnapshot = this._snapshotScroll(docEl);

    // NOW detach the live node (removes it from the DOM but keeps all
    // handlers, child state, and scroll intact). scrollTop/scrollLeft are
    // saved as a belt-and-braces measure for cases where the browser resets
    // them on re-attach (rare, but observed with some overflow containers).
    let pageNode = null;
    if (docEl) {
      try {
        pageNode = pc.removeChild(docEl);
      } catch (e) {
        console.warn('Failed to detach page node for nav state:', e);
        pageNode = null;
      }
    }

    this._navStack.push({
      findings: this.findings,
      fileHashes: this.fileHashes,
      fileMeta: this._fileMeta,
      fileBuffer: this._fileBuffer,
      yaraResults: this._yaraResults,
      pageNode,                 // detached live DOM node (preferred)
      scrollSnapshot,           // Map<element,{top,left}> for restoration
      viewerScroll,             // #viewer scroll position (outer pane)
      sbBodyScroll,             // #sb-body scroll position (sidebar pane)
      viewerAnchor,             // { el, offset } — anchor for reflow-robust restore
      sbBodyAnchor,             // { el, offset } — anchor for reflow-robust restore
      rawText: (docEl && docEl._rawText) || null,
      fileInfoText: document.getElementById('file-info').textContent,
      parentName,
    });
  },

  // Capture a DOM anchor for reflow-robust scroll restoration. Finds the
  // element closest to the top edge of `container` (but not above it) and
  // records both the element reference and its current pixel offset from
  // the container top. On restore we scrollIntoView() the anchor and apply
  // the offset — this survives reflows that change scrollHeight, unlike
  // a naive scrollTop assignment.
  _captureScrollAnchor(container, subtreeRoot) {
    if (!container || !container.isConnected) return null;
    if (!container.scrollTop) return null;
    const root = subtreeRoot || container;
    const containerRect = container.getBoundingClientRect();
    const containerTop = containerRect.top;
    let best = null;
    let bestDist = Infinity;
    try {
      // Walk the subtree breadth-first, looking at elements only (not text).
      // Cap at ~500 nodes so huge archive trees don't stall the push.
      const queue = [root];
      let examined = 0;
      while (queue.length && examined < 500) {
        const el = queue.shift();
        if (!el || !el.getBoundingClientRect) continue;
        examined++;
        const r = el.getBoundingClientRect();
        // Skip hidden/zero-sized elements
        if (r.height === 0 && r.width === 0) continue;
        // Only consider elements whose top edge is at or below the container top
        // (positive offset). Take the one closest to the top edge.
        const dist = r.top - containerTop;
        if (dist >= 0 && dist < bestDist) {
          bestDist = dist;
          best = { el, offset: dist };
          // Perfect match (flush with top) — stop walking
          if (dist < 1) break;
        }
        // Enqueue children
        const kids = el.children;
        if (kids) for (let i = 0; i < kids.length; i++) queue.push(kids[i]);
      }
    } catch (_) { /* best-effort */ }
    return best;
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

    // Clear whatever is currently in the container (the inner file's view)
    while (pc.firstChild) pc.removeChild(pc.firstChild);

    // Preferred path: re-attach the detached node. This preserves event
    // listeners, tab state, tree expansion, search input text, and scroll.
    let reattached = false;
    if (state.pageNode) {
      try {
        pc.appendChild(state.pageNode);
        // Re-attach _rawText JS property if present
        if (state.rawText) state.pageNode._rawText = state.rawText;
        // Restore scroll positions (browser sometimes resets on re-attach)
        if (state.scrollSnapshot) this._restoreScroll(state.scrollSnapshot);
        reattached = true;
      } catch (e) {
        console.warn('Failed to re-attach nav page node, falling back to re-render:', e);
        reattached = false;
      }
    }

    document.getElementById('file-info').textContent = state.fileInfoText;

    // Fallback: re-render from buffer if re-attach failed or pageNode missing
    if (!reattached && state.fileBuffer) {
      const name = (state.parentName || '').toLowerCase();
      if (name.endsWith('.zip')) this._reRenderZip(state, pc);
      else if (name.endsWith('.msi')) this._reRenderMsi(state, pc);
      else if (name.endsWith('.jar') || name.endsWith('.war') || name.endsWith('.ear') || name.endsWith('.class')) this._reRenderJar(state, pc);
      // Other renderers that dispatch open-inner-file but have no
      // dedicated re-render helper will simply show an empty container;
      // the user can reopen the parent file manually. This is safer than
      // attempting a generic re-render we can't validate.
    }

    // Re-render sidebar
    this._renderSidebar(state.parentName, null);

    // Restore scroll positions on the outer viewer and sidebar panes. These
    // live *outside* the detached docEl subtree so they weren't touched by
    // _restoreScroll(state.scrollSnapshot) above. The JAR viewer in
    // particular measures its page-container height progressively after
    // re-attach (tab-strip layout, tree expansion sync, etc.), so a single
    // rAF isn't enough — the scrollTop assignment would clamp to a
    // momentarily-smaller scrollHeight and leave the user slightly above
    // where they were. _stickyRestoreScroll keeps re-applying the target
    // across multiple frames + a ResizeObserver until it sticks.
    //
    // We also pass the DOM anchor (captured in _pushNavState) — this is
    // the element that was flush with the pane top when the user drilled
    // in. The sticky restore uses it as a fallback whenever the numeric
    // scrollTop can't converge, which happens when sidebar re-render
    // reflows #viewer to a slightly different width and the JAR view's
    // rows wrap differently. Anchor-based restore locks onto the same
    // visual row regardless of reflow.
    try {
      if (state.viewerScroll) {
        const v = document.getElementById('viewer');
        if (v) this._stickyRestoreScroll(v, state.viewerScroll, state.viewerAnchor);
      }
      if (state.sbBodyScroll) {
        const sb = document.getElementById('sb-body');
        if (sb) this._stickyRestoreScroll(sb, state.sbBodyScroll, state.sbBodyAnchor);
      }
    } catch (_) { /* best-effort */ }

    // Update back button visibility
    this._updateNavBackButton();
  },


  // Snapshot scroll positions of the root node and every scrollable
  // descendant, keyed by element reference (which remains valid because we
  // re-attach the same nodes).
  _snapshotScroll(root) {
    const snap = new Map();
    try {
      const walk = (el) => {
        if (!el) return;
        if (el.scrollTop || el.scrollLeft) {
          snap.set(el, { top: el.scrollTop, left: el.scrollLeft });
        }
        const kids = el.children;
        if (kids) for (let i = 0; i < kids.length; i++) walk(kids[i]);
      };
      walk(root);
    } catch (_) { /* best-effort */ }
    return snap;
  },

  _restoreScroll(snap) {
    if (!snap || typeof snap.forEach !== 'function') return;
    // Restore on next frame so layout has settled after re-attach. We also
    // apply the sticky-retry logic to each scrollable descendant so that
    // panes whose content is measured asynchronously (e.g. JAR tab panes
    // that only lay out after the tab becomes visible) still land on the
    // saved offset instead of being clamped to a smaller scrollHeight.
    requestAnimationFrame(() => {
      try {
        snap.forEach((pos, el) => {
          if (!el || !el.isConnected) return;
          this._stickyRestoreScroll(el, pos);
        });
      } catch (_) { /* best-effort */ }
    });
  },

  // Apply a saved scroll offset to `el` and keep re-applying it across
  // multiple animation frames / timeouts until either the target sticks
  // (scrollTop within 1px of target) or a ~500ms budget elapses. If a
  // ResizeObserver is available, also re-apply whenever the element's
  // scrollable content grows — this covers the case where the #viewer's
  // page-container or a sidebar section measures its height
  // asynchronously after re-attach / re-render. Without this, the initial
  // scrollTop assignment gets clamped to (scrollHeight - clientHeight) when
  // the content is momentarily shorter than the saved offset, leaving the
  // user above where they were when they drilled into the inner file.
  _stickyRestoreScroll(el, pos, anchor) {
    if (!el || !pos) return;
    const targetTop = pos.top || 0;
    const targetLeft = pos.left || 0;

    // Numeric-offset application. Returns true if converged to within 1 px.
    const applyNumeric = () => {
      if (!el.isConnected) return false;
      el.scrollTop = targetTop;
      el.scrollLeft = targetLeft;
      return Math.abs(el.scrollTop - targetTop) <= 1 && Math.abs(el.scrollLeft - targetLeft) <= 1;
    };

    // Anchor-based application. Places `anchor.el`'s top edge at
    // `anchor.offset` px below the container top. Returns true if the anchor
    // is actually connected and reachable (so caller knows it was usable).
    const applyAnchor = () => {
      if (!anchor || !anchor.el || !anchor.el.isConnected || !el.isConnected) return false;
      try {
        const containerRect = el.getBoundingClientRect();
        const anchorRect = anchor.el.getBoundingClientRect();
        const currentOffset = anchorRect.top - containerRect.top;
        // Positive delta means the anchor is below where we want it → scroll down more.
        const delta = currentOffset - (anchor.offset || 0);
        if (Math.abs(delta) <= 1) return true;
        el.scrollTop = Math.max(0, el.scrollTop + delta);
        el.scrollLeft = targetLeft;
        return true;
      } catch (_) { return false; }
    };

    // One pass: try numeric first, then anchor if numeric didn't stick and
    // clamped to a smaller scrollHeight. This makes anchor the winner
    // whenever reflow changed content height.
    const applyBoth = () => {
      const numericStuck = applyNumeric();
      if (numericStuck) return true;
      // Numeric was clamped — fall through to anchor-based.
      return applyAnchor();
    };

    // Immediate apply (may be clamped if content hasn't laid out yet).
    applyBoth();

    // Retry on the next few frames, then a couple of longer timeouts.
    const schedule = [
      (cb) => requestAnimationFrame(cb),
      (cb) => requestAnimationFrame(() => requestAnimationFrame(cb)),
      (cb) => setTimeout(cb, 0),
      (cb) => setTimeout(cb, 50),
      (cb) => setTimeout(cb, 150),
      (cb) => setTimeout(cb, 350),
      (cb) => setTimeout(cb, 600),
    ];
    let done = false;
    const settle = () => { done = true; if (ro) try { ro.disconnect(); } catch (_) { /* noop */ } };
    schedule.forEach(s => s(() => {
      if (done) return;
      // Prefer anchor on every retry after the first — reflow is the usual
      // culprit when we didn't converge immediately, and anchor is robust
      // against reflow while numeric is not.
      const ok = applyAnchor() || applyNumeric();
      if (ok && anchor && anchor.el && anchor.el.isConnected) {
        // Final check: if anchor is usable, confirm it landed in place.
        const containerRect = el.getBoundingClientRect();
        const anchorRect = anchor.el.getBoundingClientRect();
        if (Math.abs((anchorRect.top - containerRect.top) - (anchor.offset || 0)) <= 1) settle();
      } else if (ok) {
        settle();
      }
    }));

    // Observe content growth: if the scrollable child's size changes and
    // we haven't reached the target yet, re-apply. Disconnect once we
    // succeed or after a hard 1 s ceiling.
    let ro = null;
    if (typeof ResizeObserver !== 'undefined') {
      try {
        ro = new ResizeObserver(() => {
          if (done) return;
          applyAnchor() || applyNumeric();
        });
        const target = el.firstElementChild || el;
        ro.observe(target);
        // Also observe the element itself in case its clientHeight changes.
        if (target !== el) ro.observe(el);
      } catch (_) { ro = null; }
    }
    setTimeout(settle, 1200);
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

  _reRenderMsi(state, pc) {
    try {
      const r = new MsiRenderer();
      const buf = state.fileBuffer;
      const docEl = r.render(buf, state.parentName);
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

  async _reRenderJar(state, pc) {
    try {
      const r = new JarRenderer();
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
    const btn = document.getElementById('btn-nav-back');
    if (!btn) return;
    if (this._navStack && this._navStack.length > 0) {
      btn.classList.remove('hidden');
    } else {
      btn.classList.add('hidden');
    }
  },

  // ── Interesting string extraction ────────────────────────────────────────
  _extractInterestingStrings(text, findings) {
    const seen = new Set([...(findings.externalRefs || []), ...(findings.interestingStrings || [])].map(r => r.url));
    const results = [];

    // Enhanced add function that tracks source location for click-to-highlight
    const add = (type, val, sev, note, sourceInfo) => {
      val = (val || '').trim().replace(/[.,;:!?)\]>]+$/, '');
      if (!val || val.length < 4 || val.length > 400 || seen.has(val)) return;
      seen.add(val);
      const entry = { type, url: val, severity: sev };
      if (note) entry.note = note;
      // Source location info for click-to-highlight functionality
      if (sourceInfo) {
        entry._sourceOffset = sourceInfo.offset;
        entry._sourceLength = sourceInfo.length;
        // For SafeLinks: store the wrapper URL text to highlight instead of extracted value
        if (sourceInfo.highlightText) entry._highlightText = sourceInfo.highlightText;
      }
      results.push(entry);
    };

    // Helper to process a URL — checks for SafeLink wrappers and adds both
    const processUrl = (rawUrl, baseSeverity, matchOffset, matchLength) => {
      const url = (rawUrl || '').trim().replace(/[.,;:!?)\]>]+$/, '');
      if (!url || url.length < 6) return;

      const unwrapped = _unwrapSafeLink(url);
      if (unwrapped) {
        // Add the wrapper URL as info-level (with its own source location)
        add(IOC.URL, url, 'info', `${unwrapped.provider} wrapper`, {
          offset: matchOffset,
          length: matchLength
        });
        // Add the extracted original URL with higher severity
        // Point _highlightText to the wrapper URL so clicking highlights the wrapper
        add(IOC.URL, unwrapped.originalUrl, 'high', `Extracted from ${unwrapped.provider}`, {
          offset: matchOffset,
          length: matchLength,
          highlightText: url  // Highlight the wrapper, not the extracted URL
        });
        // Add any extracted emails from Microsoft SafeLinks data parameter
        // These also point back to the wrapper URL for highlighting
        for (const email of unwrapped.emails) {
          add(IOC.EMAIL, email, 'medium', 'Extracted from SafeLinks', {
            offset: matchOffset,
            length: matchLength,
            highlightText: url
          });
        }
      } else {
        // Regular URL — add as-is with source location
        add(IOC.URL, url, baseSeverity, null, {
          offset: matchOffset,
          length: matchLength
        });
      }
    };

    // Scan rendered text + VBA modules
    const sources = [text, ...(findings.modules || []).map(m => m.source || '')];
    const full = sources.join('\n');

    // Extract and process URLs (check for SafeLinks) — now with offset tracking
    for (const m of full.matchAll(/https?:\/\/[^\s"'<>()\[\]{}\u0000-\u001F]{6,}/g)) {
      processUrl(m[0], 'info', m.index, m[0].length);
    }

    // Other IOC types — now with offset tracking
    for (const m of full.matchAll(/\b[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b/g)) {
      add(IOC.EMAIL, m[0], 'info', null, { offset: m.index, length: m[0].length });
    }
    for (const m of full.matchAll(/(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\d.])/g)) {
      const parts = m[0].split('.').map(Number);
      if (parts.every(p => p <= 255) && !m[0].startsWith('0.')) {
        add(IOC.IP, m[0], 'medium', null, { offset: m.index, length: m[0].length });
      }
    }
    for (const m of full.matchAll(/[A-Za-z]:\\(?:[\w\-. ]+\\)+[\w\-. ]{2,}/g)) {
      const path = _trimPathExtGarbage(m[0]);
      add(IOC.FILE_PATH, path, 'medium', null, { offset: m.index, length: path.length });
    }
    for (const m of full.matchAll(/\\\\[\w.\-]{2,}(?:\\[\w.\-]{1,})+/g)) {
      add(IOC.UNC_PATH, m[0], 'medium', null, { offset: m.index, length: m[0].length });
    }
    // Unix file paths (e.g. /usr/bin/bash, /etc/passwd, /tmp/payload)
    // Requires at least 2 path components to avoid false positives on single slashes
    for (const m of full.matchAll(/\/(?:usr|etc|bin|sbin|tmp|var|opt|home|root|dev|proc|sys|lib|mnt|run|srv|Library|Applications|System|private)\/[\w.\-/]{2,}/g)) {
      add(IOC.FILE_PATH, m[0], 'info', null, { offset: m.index, length: m[0].length });
    }
    // Windows registry keys (e.g. HKEY_LOCAL_MACHINE\SOFTWARE\..., HKLM\...)
    for (const m of full.matchAll(/\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HK(?:LM|CU|CR|U|CC))\\[\w\-. \\]{4,}/g)) {
      add(IOC.REGISTRY_KEY, m[0], 'medium', null, { offset: m.index, length: m[0].length });
    }

    // ── Defanged IOC extraction ──────────────────────────────────────────────
    // Detect defanged URLs (hxxp[s][://]...[.]...), IPs (1[.]2[.]3[.]4), and emails (user[@]domain[.]com)
    // Refang them and add to IOCs with source highlighting pointing to the defanged original

    // Defanged URLs: hxxp/hxxps with optional [://] and [.] in domain
    // Pattern matches: hxxps[://]www[.]example[.]com/path or hxxp://example[.]com
    const defangedUrlRe = /\bhxxps?(?:\[:\/?\/?\]|:\/\/)[^\s"'<>]{4,}/gi;
    for (const m of full.matchAll(defangedUrlRe)) {
      const result = _refangString(m[0]);
      if (result && result.refanged.match(/^https?:\/\//i)) {
        // Clean trailing punctuation from refanged URL
        const cleaned = result.refanged.replace(/[.,;:!?)\]>]+$/, '');
        if (!seen.has(cleaned) && cleaned.length >= 10) {
          add(IOC.URL, cleaned, 'medium', 'Refanged', {
            offset: m.index,
            length: m[0].length,
            highlightText: m[0]
          });
        }
      }
    }

    // Defanged domains/URLs with [.] but no hxxp prefix (e.g., www[.]evil[.]com or evil[.]com/path)
    // Must have at least one [.] to be considered defanged
    const defangedDomainRe = /\b[\w\-]+(?:\[\.\][\w\-]+)+(?:\/[^\s"'<>]*)?\b/g;
    for (const m of full.matchAll(defangedDomainRe)) {
      const result = _refangString(m[0]);
      if (result) {
        const cleaned = result.refanged.replace(/[.,;:!?)\]>]+$/, '');
        // Check if it looks like a valid domain (has at least one dot and a TLD-like ending)
        if (!seen.has(cleaned) && /^[\w\-]+\.[\w\-]+/.test(cleaned) && cleaned.length >= 4) {
          add(IOC.URL, cleaned, 'medium', 'Refanged domain', {
            offset: m.index,
            length: m[0].length,
            highlightText: m[0]
          });
        }
      }
    }

    // Defanged IPs: 192[.]168[.]1[.]1
    const defangedIpRe = /(?<![\d.])\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}(?![\d.])/g;
    for (const m of full.matchAll(defangedIpRe)) {
      const result = _refangString(m[0]);
      if (result) {
        const parts = result.refanged.split('.').map(Number);
        if (parts.length === 4 && parts.every(p => p >= 0 && p <= 255) && !result.refanged.startsWith('0.')) {
          if (!seen.has(result.refanged)) {
            add(IOC.IP, result.refanged, 'medium', 'Refanged', {
              offset: m.index,
              length: m[0].length,
              highlightText: m[0]
            });
          }
        }
      }
    }

    // Defanged emails: user[@]domain[.]com
    const defangedEmailRe = /\b[a-zA-Z0-9._%+\-]+\[@\][a-zA-Z0-9.\-\[\]]+\b/g;
    for (const m of full.matchAll(defangedEmailRe)) {
      const result = _refangString(m[0]);
      if (result) {
        const cleaned = result.refanged.replace(/[.,;:!?)\]>]+$/, '');
        // Validate it looks like an email after refanging
        if (!seen.has(cleaned) && /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(cleaned)) {
          add(IOC.EMAIL, cleaned, 'medium', 'Refanged', {
            offset: m.index,
            length: m[0].length,
            highlightText: m[0]
          });
        }
      }
    }

    // VBA-specific URL scan with higher severity (also check for SafeLinks)
    // Note: VBA modules are appended to 'full' after the main text, so offsets
    // are relative to 'full' and will work for highlighting in combined view
    for (const mod of (findings.modules || [])) {
      for (const m of (mod.source || '').matchAll(/https?:\/\/[^\s"']{6,}/g)) {
        const v = m[0].replace(/[.,;:!?)\]>]+$/, '');
        if (!seen.has(v)) {
          const unwrapped = _unwrapSafeLink(v);
          if (unwrapped) {
            add(IOC.URL, v, 'medium', `${unwrapped.provider} wrapper (VBA)`);
            add(IOC.URL, unwrapped.originalUrl, 'critical', `Extracted from ${unwrapped.provider} (VBA)`, {
              highlightText: v
            });
            for (const email of unwrapped.emails) {
              add(IOC.EMAIL, email, 'high', 'Extracted from SafeLinks (VBA)', {
                highlightText: v
              });
            }
          } else {
            seen.add(v);
            results.push({ type: IOC.URL, url: v, severity: 'high' });
          }
        }
      }
    }
    return results.slice(0, 300);
  },

});
