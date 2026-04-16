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
      } else if (['pem', 'der', 'crt', 'cer', 'p12', 'pfx'].includes(ext)) {
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
          docEl = await r.render(buffer);
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
            this._fileBuffer = this.findings.augmentedBuffer;
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
        } else if (detectedType === 'macho') {
          const r = new MachoRenderer();
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
    // PEM certificate (text-based: -----BEGIN ...)
    if (head.startsWith('-----BEGIN '))
      return { hex: h(11), label: 'PEM Encoded Data' };
    // DER certificate (ASN.1 SEQUENCE with long-form length)
    if (bytes[0] === 0x30 && bytes[1] === 0x82)
      return { hex: h(4), label: 'DER / ASN.1 Data' };
    return { hex: h(Math.min(4, bytes.length)), label: 'Unknown' };
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
    
    // Text-based detection (check first 20 bytes as string)
    const head = String.fromCharCode(...bytes.subarray(0, Math.min(20, bytes.length)));
    
    // RTF
    if (head.startsWith('{\\rtf')) return 'rtf';
    
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
  _pushNavState(parentName) {
    if (!this._navStack) this._navStack = [];
    const pc = document.getElementById('page-container');
    const docEl = pc && pc.firstElementChild;
    this._navStack.push({
      findings: this.findings,
      fileHashes: this.fileHashes,
      fileMeta: this._fileMeta,
      fileBuffer: this._fileBuffer,
      yaraResults: this._yaraResults,
      pageHTML: pc.innerHTML,
      rawText: (docEl && docEl._rawText) || null,
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
    // Re-attach _rawText (JS property lost during innerHTML serialisation)
    if (state.rawText && pc.firstElementChild) {
      pc.firstElementChild._rawText = state.rawText;
    }
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

    // Re-attach click handlers on MSI streams (innerHTML loses event listeners)
    const msiView = pc.querySelector('.msi-view');
    if (msiView && state.fileBuffer) {
      this._reRenderMsi(state, pc);
    }

    // Re-attach click handlers on JAR entries (innerHTML loses event listeners)
    const jarView = pc.querySelector('.jar-view');
    if (jarView && state.fileBuffer) {
      this._reRenderJar(state, pc);
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
    for (const m of full.matchAll(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g)) {
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
    const defangedIpRe = /\b\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\b/g;
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
