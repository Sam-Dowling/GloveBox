// ════════════════════════════════════════════════════════════════════════════
// EncodedContentDetector — scans for encoded/compressed blobs, decodes them,
// extracts IOCs, classifies decoded payloads, and supports recursive decode.
// ════════════════════════════════════════════════════════════════════════════

class EncodedContentDetector {

  constructor(opts = {}) {
    this.maxRecursionDepth = opts.maxRecursionDepth || 4;
    this.maxCandidatesPerType = opts.maxCandidatesPerType || 50;
  }

  // ════════════════════════════════════════════════════════════════════════
  // STATIC: SafeLink URL unwrapping (Proofpoint & Microsoft)
  // ════════════════════════════════════════════════════════════════════════

  /**
   * Unwrap Proofpoint URLDefense and Microsoft SafeLinks URLs.
   * @param {string} url  The potentially wrapped URL.
   * @returns {object|null}  { originalUrl, emails: [], provider } or null if not a SafeLink.
   */
  static unwrapSafeLink(url) {
    if (!url || typeof url !== 'string') return null;

    // ── Proofpoint URLDefense v3 ──
    // Format: https://urldefense.com/v3/__<URL>__;!!<token>
    const ppV3Re = /^https?:\/\/urldefense\.com\/v3\/__(.+?)__;/i;
    let m = url.match(ppV3Re);
    if (m) {
      let extracted = m[1];
      // Proofpoint v3 replaces certain chars with * followed by a hex code
      extracted = extracted.replace(/\*([0-9A-Fa-f]{2})/g, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16))
      );
      return { originalUrl: extracted, emails: [], provider: 'Proofpoint v3' };
    }

    // ── Proofpoint URLDefense v2 ──
    // Format: https://urldefense.proofpoint.com/v2/url?u=<encoded>&d=...
    const ppV2Re = /^https?:\/\/urldefense\.proofpoint\.com\/v2\/url\?/i;
    if (ppV2Re.test(url)) {
      try {
        const params = new URL(url).searchParams;
        let encoded = params.get('u');
        if (encoded) {
          // Proofpoint v2 encoding: - → %, _ → /
          encoded = encoded.replace(/-/g, '%').replace(/_/g, '/');
          const extracted = decodeURIComponent(encoded);
          return { originalUrl: extracted, emails: [], provider: 'Proofpoint v2' };
        }
      } catch (_) { /* malformed URL */ }
    }

    // ── Proofpoint URLDefense v1 ──
    // Format: https://urldefense.proofpoint.com/v1/url?u=<encoded>&k=...
    const ppV1Re = /^https?:\/\/urldefense\.proofpoint\.com\/v1\/url\?/i;
    if (ppV1Re.test(url)) {
      try {
        const params = new URL(url).searchParams;
        let encoded = params.get('u');
        if (encoded) {
          encoded = encoded.replace(/-/g, '%').replace(/_/g, '/');
          const extracted = decodeURIComponent(encoded);
          return { originalUrl: extracted, emails: [], provider: 'Proofpoint v1' };
        }
      } catch (_) { /* malformed URL */ }
    }

    // ── Microsoft SafeLinks ──
    // Format: https://*.safelinks.protection.outlook.com/?url=<encoded>&data=...
    const msRe = /^https?:\/\/[a-z0-9]+\.safelinks\.protection\.outlook\.com\/?\?/i;
    if (msRe.test(url)) {
      try {
        const params = new URL(url).searchParams;
        const encodedUrl = params.get('url');
        const data = params.get('data');
        const emails = [];

        // Extract email from data parameter
        if (data) {
          let dataDecoded = data;
          try { dataDecoded = decodeURIComponent(data); } catch (_) {}
          const emailRe = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;
          let em;
          while ((em = emailRe.exec(dataDecoded)) !== null) {
            if (!emails.includes(em[0])) emails.push(em[0]);
          }
        }

        if (encodedUrl) {
          const extracted = decodeURIComponent(encodedUrl);
          return { originalUrl: extracted, emails, provider: 'Microsoft SafeLinks' };
        }
      } catch (_) { /* malformed URL */ }
    }

    return null;
  }

  // ── Helper: propagate severity & IOCs from inner findings ────────────────
  static _propagateInnerFindings(severity, iocs, innerFindings) {
    if (!innerFindings || innerFindings.length === 0) return severity;
    const sevRank = { critical: 4, high: 3, medium: 2, info: 1 };
    const seen = new Set(iocs.map(i => i.url));
    for (const inner of innerFindings) {
      if ((sevRank[inner.severity] || 0) > (sevRank[severity] || 0)) {
        severity = inner.severity;
      }
      if (inner.iocs) {
        for (const ioc of inner.iocs) {
          if (!seen.has(ioc.url)) {
            seen.add(ioc.url);
            iocs.push(ioc);
          }
        }
      }
    }
    return severity;
  }

  // ── Magic byte signatures for decoded binary identification ──────────────
  static MAGIC_BYTES = [
    { magic: [0x4D, 0x5A],                     ext: '.exe',  type: 'PE Executable' },
    { magic: [0x50, 0x4B, 0x03, 0x04],         ext: '.zip',  type: 'ZIP Archive' },
    { magic: [0x25, 0x50, 0x44, 0x46],         ext: '.pdf',  type: 'PDF Document' },
    { magic: [0xD0, 0xCF, 0x11, 0xE0],         ext: '.ole',  type: 'OLE/CFB Document' },
    { magic: [0x1F, 0x8B],                     ext: '.gz',   type: 'Gzip Compressed' },
    { magic: [0x78, 0x9C],                     ext: '.zlib', type: 'Zlib Compressed (default)' },
    { magic: [0x78, 0xDA],                     ext: '.zlib', type: 'Zlib Compressed (best)' },
    { magic: [0x78, 0x01],                     ext: '.zlib', type: 'Zlib Compressed (no/low)' },
    { magic: [0x78, 0x5E],                     ext: '.zlib', type: 'Zlib Compressed (fast)' },
    { magic: [0x52, 0x61, 0x72, 0x21],         ext: '.rar',  type: 'RAR Archive' },
    { magic: [0x7F, 0x45, 0x4C, 0x46],         ext: '.elf',  type: 'ELF Binary' },
    { magic: [0x89, 0x50, 0x4E, 0x47],         ext: '.png',  type: 'PNG Image' },
    { magic: [0xFF, 0xD8, 0xFF],               ext: '.jpg',  type: 'JPEG Image' },
    { magic: [0xCA, 0xFE, 0xBA, 0xBE],         ext: '.class', type: 'Java Class' },
    { magic: [0xCF, 0xFA, 0xED, 0xFE],         ext: '.macho', type: 'Mach-O Binary' },
    { magic: [0x37, 0x7A, 0xBC, 0xAF],         ext: '.7z',  type: '7-Zip Archive' },
    { magic: [0xEF, 0xBB, 0xBF],               ext: '.txt',  type: 'UTF-8 BOM Text' },
  ];

  // ── Text-based signatures at the start of decoded content ────────────────
  static TEXT_SIGNATURES = [
    { pattern: /^<script/i,                         ext: '.html', type: 'HTML/Script' },
    { pattern: /^<HTA:APPLICATION/i,                ext: '.hta',  type: 'HTA Application' },
    { pattern: /^#!(\/usr\/bin|\/bin)\//,            ext: '.sh',   type: 'Shell Script' },
    { pattern: /^(Sub |Function |Dim |Private )/i,  ext: '.vbs',  type: 'VBScript' },
    { pattern: /^\$[A-Za-z]|^function |^param\s*\(/i, ext: '.ps1', type: 'PowerShell' },
    { pattern: /^<\?xml\s/i,                        ext: '.xml',  type: 'XML Document' },
    { pattern: /^<!DOCTYPE\s|^<html/i,              ext: '.html', type: 'HTML Document' },
    { pattern: /^\{\\rtf/,                          ext: '.rtf',  type: 'RTF Document' },
  ];

  // ── High-confidence Base64 prefixes (known magic bytes when B64-encoded) ─
  static HIGH_CONFIDENCE_B64 = [
    { prefix: 'TVqQ', desc: 'PE executable (MZ)' },
    { prefix: 'TVpQ', desc: 'PE executable (MZ variant)' },
    { prefix: 'TVro', desc: 'PE executable (MZ variant)' },
    { prefix: 'H4sI', desc: 'Gzip compressed' },
    { prefix: 'eJw',  desc: 'Zlib compressed (default)' },
    { prefix: 'eNo',  desc: 'Zlib compressed (best)' },
    { prefix: 'eAE',  desc: 'Zlib compressed (no/low)' },
    { prefix: 'eF4',  desc: 'Zlib compressed (fast)' },
    { prefix: 'UEsD', desc: 'ZIP archive (PK)' },
    { prefix: 'JVBE', desc: 'PDF document (%PDF)' },
    { prefix: '0M8R', desc: 'OLE/CFB document' },
    { prefix: 'UmFy', desc: 'RAR archive' },
    { prefix: 'N3q8', desc: '7-Zip archive' },
    { prefix: 'f0VM', desc: 'ELF binary' },
  ];

  // ════════════════════════════════════════════════════════════════════════
  // PUBLIC API
  // ════════════════════════════════════════════════════════════════════════

  /**
   * Scan content for encoded/compressed blobs.
   * @param {string}     textContent  Text representation of the file.
   * @param {Uint8Array} rawBytes     Raw file bytes.
   * @param {object}     context      { fileType, existingIOCs, mimeAttachments }
   * @returns {Promise<Array>}  Array of finding objects.
   */
  async scan(textContent, rawBytes, context = {}) {
    const findings = [];

    // Phase 1: Find candidates in text content
    const b64Candidates = this._findBase64Candidates(textContent, context);
    const hexCandidates = this._findHexCandidates(textContent, context);
    const b32Candidates = this._findBase32Candidates(textContent, context);

    // Phase 1c: Additional encoding candidates
    const urlEncCandidates = this._findUrlEncodedCandidates(textContent, context);
    const htmlEntCandidates = this._findHtmlEntityCandidates(textContent, context);
    const unicodeEscCandidates = this._findUnicodeEscapeCandidates(textContent, context);
    const charArrayCandidates = this._findCharArrayCandidates(textContent, context);
    const octalCandidates = this._findOctalEscapeCandidates(textContent, context);
    const scriptEncCandidates = this._findScriptEncodedCandidates(textContent, context);
    const spaceHexCandidates = this._findSpaceDelimitedHexCandidates(textContent, context);
    const rot13Candidates = this._findRot13Candidates(textContent, context);
    const splitJoinCandidates = this._findSplitJoinCandidates(textContent, context);

    // Phase 1d: Command obfuscation candidates
    const cmdObfCandidates = this._findCommandObfuscationCandidates(textContent, context);

    // Phase 1b: Find compressed blob candidates in raw bytes
    const compressedCandidates = this._findCompressedBlobCandidates(rawBytes, context);

    // Phase 2 & 3: Decode and classify each candidate
    for (const cand of b64Candidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of hexCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of b32Candidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of urlEncCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of htmlEntCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of unicodeEscCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of charArrayCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of octalCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of scriptEncCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of spaceHexCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of rot13Candidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of splitJoinCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of cmdObfCandidates) {
      const result = await this._processCommandObfuscation(cand);
      if (result) findings.push(result);
    }
    for (const cand of compressedCandidates) {
      const result = await this._processCompressedCandidate(cand, rawBytes);
      if (result) findings.push(result);
    }

    return findings;
  }

  // ════════════════════════════════════════════════════════════════════════
  // PHASE 1: CANDIDATE IDENTIFICATION
  // ════════════════════════════════════════════════════════════════════════

  _findBase64Candidates(text, context) {
    if (!text || text.length < 40) return [];
    const candidates = [];

    // Standard Base64 (including URL-safe variant)
    const b64Re = /[A-Za-z0-9+\/\-_]{40,}={0,2}/g;
    let m;
    while ((m = b64Re.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;

      const raw = m[0];
      const offset = m.index;

      // ── Whitelist filters ──
      if (this._isDataURI(text, offset)) continue;
      if (this._isPEMBlock(text, offset)) continue;
      if (this._isCSSFontData(text, offset)) continue;
      if (this._isMIMEBody(text, offset, context)) continue;

      // Determine confidence BEFORE entropy gate so high-confidence skips it
      const highConf = EncodedContentDetector.HIGH_CONFIDENCE_B64.find(h => raw.startsWith(h.prefix));
      const psContext = this._isPowerShellEncodedCommand(text, offset);

      // Entropy gate (skipped for high-confidence matches)
      const entropy = this._shannonEntropyString(raw);
      if (!highConf && !psContext) {
        if (entropy < 3.5 || entropy > 5.8) continue;
      }

      // Reject if purely alphanumeric (no +, /, =, -, _) — likely an identifier
      // Exception: strings inside quotes (variable assignments in scripts) are
      // likely intentional encoded payloads, not identifiers
      if (/^[A-Za-z0-9]+$/.test(raw) && raw.length < 200 && !highConf && !psContext) {
        const prevChar = offset > 0 ? text[offset - 1] : '';
        const afterEnd = offset + raw.length < text.length ? text[offset + raw.length] : '';
        const inQuotes = (prevChar === '"' || prevChar === "'") && (afterEnd === '"' || afterEnd === "'");
        if (!inQuotes) {
          // Also try speculative decode — if decoded content is printable text
          // (e.g. hex digits, another base64 layer), it's real encoded content
          const specDec = this._decodeBase64(raw);
          const specText = specDec && this._tryDecodeUTF8(specDec);
          const looksTextual = specText && specText.length > 16 &&
            /^[\x20-\x7E\r\n\t]{16,}$/.test(specText.substring(0, Math.min(64, specText.length)));
          if (!looksTextual) continue;
        }
      }

      candidates.push({
        type: 'Base64',
        raw,
        offset,
        length: raw.length,
        entropy,
        confidence: (highConf || psContext) ? 'high' : 'normal',
        hint: highConf ? highConf.desc : (psContext ? 'PowerShell -EncodedCommand' : null),
        autoDecoded: !!(highConf || psContext),
      });
    }

    return candidates;
  }

  _findHexCandidates(text, context) {
    if (!text || text.length < 32) return [];
    const candidates = [];

    // Continuous hex strings
    const hexContRe = /(?:0x)?([0-9a-fA-F]{32,})/g;
    let m;
    while ((m = hexContRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[1]; // just the hex digits
      const offset = m.index;
      if (raw.length % 2 !== 0) continue; // must be even

      // Whitelist: skip known hash lengths
      if (this._isHashLength(raw)) continue;
      if (this._isGUID(text, offset)) continue;

      // Check for high-confidence: starts with PE header hex or common shellcode
      const startsWithMZ = /^4d5a/i.test(raw);
      const startsWithShellcode = /^(fc4883|fc4889|e8[0-9a-f]{6}00|31c0|33c0)/i.test(raw);
      const isHighConf = startsWithMZ || startsWithShellcode;

      const entropy = this._shannonEntropyString(raw);
      // Hex has a natural max entropy of log2(16)=4.0, so upper bound must allow that
      if (!isHighConf && (entropy < 2.5 || entropy > 4.2)) continue;

      candidates.push({
        type: 'Hex',
        raw,
        offset,
        length: raw.length,
        entropy,
        confidence: isHighConf ? 'high' : 'normal',
        hint: startsWithMZ ? 'PE executable header (4D5A)' : (startsWithShellcode ? 'Shellcode prologue' : null),
        autoDecoded: isHighConf,
      });
    }

    // Escaped hex sequences: \x4d\x5a...
    const hexEscRe = /(?:\\x[0-9a-fA-F]{2}){16,}/g;
    while ((m = hexEscRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      const hexOnly = raw.replace(/\\x/g, '');
      const offset = m.index;

      candidates.push({
        type: 'Hex (escaped)',
        raw: hexOnly,
        offset,
        length: raw.length,
        entropy: this._shannonEntropyString(hexOnly),
        confidence: /^4d5a/i.test(hexOnly) ? 'high' : 'normal',
        hint: /^4d5a/i.test(hexOnly) ? 'PE executable header' : null,
        autoDecoded: /^4d5a/i.test(hexOnly),
      });
    }

    // PowerShell byte arrays: 0x4d,0x5a,0x90,...
    const psByteRe = /(?:0x[0-9a-fA-F]{2},?\s*){16,}/g;
    while ((m = psByteRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      const hexOnly = [...raw.matchAll(/0x([0-9a-fA-F]{2})/gi)].map(x => x[1]).join('');
      if (hexOnly.length < 32) continue;
      const offset = m.index;

      candidates.push({
        type: 'Hex (PS byte array)',
        raw: hexOnly,
        offset,
        length: raw.length,
        entropy: this._shannonEntropyString(hexOnly),
        confidence: /^4d5a/i.test(hexOnly) ? 'high' : 'normal',
        hint: /^4d5a/i.test(hexOnly) ? 'PE executable header' : null,
        autoDecoded: /^4d5a/i.test(hexOnly),
      });
    }

    return candidates;
  }

  _findBase32Candidates(text, context) {
    if (!text || text.length < 40) return [];
    const candidates = [];

    const b32Re = /[A-Z2-7]{40,}={0,6}/g;
    let m;
    while ((m = b32Re.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      const offset = m.index;

      // Base32 is low-frequency — require contextual evidence
      if (!this._hasBase32Context(text, offset)) continue;

      const entropy = this._shannonEntropyString(raw);
      if (entropy < 3.0 || entropy > 5.0) continue;

      candidates.push({
        type: 'Base32',
        raw,
        offset,
        length: raw.length,
        entropy,
        confidence: 'normal',
        hint: null,
        autoDecoded: false,
      });
    }

    return candidates;
  }

  _findCompressedBlobCandidates(bytes, context) {
    if (!bytes || bytes.length < 8) return [];
    const candidates = [];
    const fileType = context.fileType || '';

    // Skip scanning inside files whose compression is already handled,
    // including ZIP-based container formats (OOXML, ODF, etc.) whose internal
    // PK\x03\x04 local file headers are structure, not embedded payloads
    const zipContainers = [
      'zip', 'rar', '7z', 'cab', 'gz', 'tar', 'iso', 'img',
      'docx', 'docm', 'xlsx', 'xlsm', 'pptx', 'pptm',
      'odt', 'ods', 'odp', 'jar', 'apk', 'xpi', 'epub',
    ];
    if (zipContainers.includes(fileType)) return [];

    // Scan for magic bytes at each offset
    const magics = [
      { bytes: [0x1F, 0x8B], format: 'gzip', label: 'Gzip' },
      { bytes: [0x78, 0x9C], format: 'zlib', label: 'Zlib (default)' },
      { bytes: [0x78, 0x01], format: 'zlib', label: 'Zlib (no/low)' },
      { bytes: [0x78, 0xDA], format: 'zlib', label: 'Zlib (best)' },
      { bytes: [0x78, 0x5E], format: 'zlib', label: 'Zlib (fast)' },
      { bytes: [0x50, 0x4B, 0x03, 0x04], format: 'zip', label: 'Embedded ZIP' },
    ];

    for (let i = 0; i < bytes.length - 4 && candidates.length < this.maxCandidatesPerType; i++) {
      for (const sig of magics) {
        let match = true;
        for (let j = 0; j < sig.bytes.length; j++) {
          if (bytes[i + j] !== sig.bytes[j]) { match = false; break; }
        }
        if (!match) continue;

        // For PDF files, skip content stream compressed blobs (handled by PdfRenderer)
        if (fileType === 'pdf') continue;

        candidates.push({
          type: 'Compressed',
          format: sig.format,
          label: sig.label,
          offset: i,
          autoDecoded: true,
        });
        break; // Only match first format at this offset
      }
    }

    return candidates;
  }

  // ════════════════════════════════════════════════════════════════════════
  // PHASE 2: DECODE & VALIDATE
  // ════════════════════════════════════════════════════════════════════════

  /**
   * Process a text-encoding candidate (Base64/Hex/Base32).
   * For high-confidence candidates, auto-decode. Others get lazy metadata.
   */
  async _processCandidate(candidate, depth) {
    if (depth > this.maxRecursionDepth) {
      return this._makeDepthExceededFinding(candidate, depth);
    }

    // Attempt decode
    let decoded;
    try {
      decoded = this._decodeCandidate(candidate);
    } catch (_) {
      return null; // Decode failed, not a valid encoded blob
    }

    if (!decoded || decoded.length === 0) return null;

    // Classify the decoded content
    const classification = this._classify(decoded);

    // Check entropy of decoded content
    const decodedEntropy = this._shannonEntropyBytes(decoded);

    // Build decode chain
    const chain = [candidate.type];

    // If decoded content is compressed (gzip or zlib), try to decompress.
    // Instead of replacing decoded in-place (which loses the intermediate
    // compressed layer), keep decoded as the compressed bytes and store the
    // decompressed result as a synthetic inner finding.  This lets the sidebar
    // offer "Load for analysis" (one layer deep — the compressed blob) and
    // "All the way" (deepest layer — the decompressed payload) separately.
    let syntheticDecompFinding = null;
    const cType = (classification.type || '').toLowerCase();
    if (cType.includes('gzip') || cType.includes('zlib') || classification.ext === '.gz' || classification.ext === '.zlib') {
      try {
        const decompResult = await Decompressor.tryAll(decoded, 0);
        if (decompResult && decompResult.data && decompResult.data.length > 0) {
          const decompData = decompResult.data;
          const innerClass = this._classify(decompData);
          const decompEntropy = this._shannonEntropyBytes(decompData);
          const decompIocs = this._extractIOCsFromDecoded(decompData);
          const decompSev = this._assessSeverity(innerClass, decompIocs, decompData);
          const decompExt = innerClass.ext || (this._isValidUTF8(decompData) ? '.txt' : '.bin');
          const decompChain = [decompResult.format || 'decompressed'];
          if (innerClass.type) decompChain.push(innerClass.type);
          else if (this._isValidUTF8(decompData)) decompChain.push('text');
          else decompChain.push('binary data');

          // Recursively scan decompressed content for further encoding layers
          let decompInner = [];
          if (depth < this.maxRecursionDepth && decompData.length > 32) {
            const decompText = this._tryDecodeUTF8(decompData);
            if (decompText && decompText.length > 32) {
              const innerDet = new EncodedContentDetector({
                maxRecursionDepth: this.maxRecursionDepth,
                maxCandidatesPerType: this.maxCandidatesPerType,
              });
              decompInner = await innerDet.scan(decompText, decompData, { fileType: '' });
              for (const f of decompInner) {
                f.chain = [...decompChain, ...f.chain];
                f.depth = (f.depth || 0) + 1;
              }
            }
          }

          syntheticDecompFinding = {
            type: 'encoded-content',
            severity: decompSev,
            encoding: decompResult.format || 'decompressed',
            offset: 0,
            length: decompData.length,
            decodedSize: decompData.length,
            decodedBytes: decompData,
            chain: decompChain,
            classification: innerClass,
            entropy: decompEntropy,
            hint: `Decompressed from ${classification.type || 'compressed data'} (${decompData.length.toLocaleString()} bytes)`,
            iocs: decompIocs,
            innerFindings: decompInner,
            autoDecoded: true,
            canLoad: !!(innerClass.type || this._isValidUTF8(decompData)),
            ext: decompExt,
            snippet: '',
          };
        }
      } catch (_) { /* decompression failed, continue with raw decoded */ }
    }

    // If still high-entropy binary (>7.5), flag but don't recurse
    const finalEntropy = this._shannonEntropyBytes(decoded);
    if (finalEntropy > 7.5 && !classification.type) {
      return {
        type: 'encoded-content',
        severity: 'medium',
        encoding: candidate.type,
        offset: candidate.offset,
        length: candidate.length,
        decodedSize: decoded.length,
        decodedBytes: candidate.autoDecoded ? decoded : null,
        chain: [...chain, 'high-entropy binary'],
        classification: { type: 'Encrypted/Packed Data', ext: '.bin' },
        entropy: finalEntropy,
        hint: candidate.hint,
        iocs: [],
        note: 'High entropy suggests encryption or packing — manual analysis recommended',
        autoDecoded: candidate.autoDecoded,
        canLoad: false,
        snippet: candidate.raw ? candidate.raw.substring(0, 120) : '',
      };
    }

    // Extract IOCs from decoded content
    const iocs = this._extractIOCsFromDecoded(decoded);

    // Run YARA if available (will be done by caller)
    // Determine severity
    let severity = this._assessSeverity(classification, iocs, decoded);

    // Recursive scan: check if decoded content contains more encoding layers
    let innerFindings = [];
    if (depth < this.maxRecursionDepth && decoded.length > 32) {
      const decodedText = this._tryDecodeUTF8(decoded);
      if (decodedText && decodedText.length > 32) {
        const innerDetector = new EncodedContentDetector({
          maxRecursionDepth: this.maxRecursionDepth,
          maxCandidatesPerType: this.maxCandidatesPerType,
        });
        innerFindings = await innerDetector.scan(decodedText, decoded, { fileType: '' });
        // Add parent chain to inner findings
        for (const f of innerFindings) {
          f.chain = [...chain, ...f.chain];
          f.depth = (f.depth || 0) + 1;
        }
      }
    }

    // If we created a synthetic decompressed finding, prepend it to innerFindings
    // so it appears as the primary "deeper layer" for the sidebar's "All the way" button
    if (syntheticDecompFinding) {
      innerFindings.unshift(syntheticDecompFinding);
    }

    // Propagate severity and IOCs from inner findings — if nested content is
    // more dangerous, the parent finding should reflect that; IOCs discovered
    // in deeper layers (e.g. a URL inside Hex → Base64 → text) surface here
    // so the analyst sees them without having to drill down manually.
    severity = EncodedContentDetector._propagateInnerFindings(severity, iocs, innerFindings);

    // Determine the file extension for the synthetic file
    const ext = classification.ext || (this._isValidUTF8(decoded) ? '.txt' : '.bin');

    // Determine chain description
    if (classification.type) chain.push(classification.type);
    else if (this._isValidUTF8(decoded)) chain.push('text');
    else chain.push('binary data');

    const finding = {
      type: 'encoded-content',
      severity,
      encoding: candidate.type,
      offset: candidate.offset,
      length: candidate.length,
      decodedSize: decoded.length,
      decodedBytes: candidate.autoDecoded ? decoded : null,
      rawCandidate: candidate.autoDecoded ? null : candidate.raw,
      chain,
      classification,
      entropy: finalEntropy,
      hint: candidate.hint,
      iocs,
      innerFindings,
      autoDecoded: candidate.autoDecoded,
      canLoad: !!(classification.type || this._isValidUTF8(decoded)),
      ext,
      snippet: candidate.raw ? candidate.raw.substring(0, 120) : '',
    };

    return finding;
  }

  /**
   * Process a compressed blob candidate found via binary scan.
   * @param {object}     candidate  Candidate info from _findCompressedBlobCandidates.
   * @param {Uint8Array} rawBytes   Full file raw bytes (for ZIP validation).
   */
  async _processCompressedCandidate(candidate, rawBytes) {
    // Always auto-decode compressed blobs
    const findingBase = {
      type: 'encoded-content',
      encoding: candidate.label,
      offset: candidate.offset,
      autoDecoded: true,
    };

    if (candidate.format === 'zip') {
      // Validate the embedded ZIP by trying to parse it with JSZip.
      // Prune false positives (partial PK headers, container entry headers, etc.)
      if (rawBytes && typeof JSZip !== 'undefined') {
        try {
          const zipBytes = rawBytes.subarray(candidate.offset);
          const zip = await JSZip.loadAsync(zipBytes);
          const entries = Object.keys(zip.files);
          if (entries.length === 0) return null; // No valid entries — not a real ZIP
        } catch (_) {
          return null; // JSZip couldn't parse it — prune this false positive
        }
      }

      // Embedded ZIP — don't decompress, just flag it
      return {
        ...findingBase,
        severity: 'medium',
        decodedSize: 0,
        decodedBytes: null,
        chain: ['Embedded ZIP'],
        classification: { type: 'ZIP Archive', ext: '.zip' },
        entropy: 0,
        hint: 'ZIP local file header found inside file',
        iocs: [],
        innerFindings: [],
        canLoad: true,
        ext: '.zip',
        embeddedZipOffset: candidate.offset,
      };
    }

    // Attempt eager decompression of zlib/gzip blobs
    if (rawBytes && typeof Decompressor !== 'undefined') {
      try {
        const result = await Decompressor.tryAll(rawBytes, candidate.offset);
        if (result && result.data && result.data.length > 0) {
          const decoded = result.data;
          const classification = this._classify(decoded);
          const entropy = this._shannonEntropyBytes(decoded);
          const iocs = this._extractIOCsFromDecoded(decoded);
          const chain = [candidate.label];
          if (classification.type) chain.push(classification.type);
          else if (this._isValidUTF8(decoded)) chain.push('text');
          else chain.push('binary data');
          const severity = this._assessSeverity(classification, iocs, decoded);
          const ext = classification.ext || (this._isValidUTF8(decoded) ? '.txt' : '.bin');

          return {
            ...findingBase,
            severity,
            decodedSize: decoded.length,
            decodedBytes: decoded,
            chain,
            classification,
            entropy,
            hint: `${candidate.label} compressed data at offset ${candidate.offset} — decompressed ${decoded.length.toLocaleString()} bytes`,
            iocs,
            innerFindings: [],
            canLoad: !!(classification.type || this._isValidUTF8(decoded)),
            ext,
          };
        }
      } catch (_) {
        // Decompression failed — fall through to lazy marker
      }
    }

    // Fallback: mark for lazy decompression if eager attempt was skipped or failed
    return {
      ...findingBase,
      severity: 'info',
      decodedSize: 0,
      decodedBytes: null,
      chain: [candidate.label],
      classification: { type: 'Compressed Data', ext: '.bin' },
      entropy: 0,
      hint: `${candidate.label} magic bytes at offset ${candidate.offset}`,
      iocs: [],
      innerFindings: [],
      canLoad: false,
      needsDecompression: true,
      compressionFormat: candidate.format,
      ext: '.bin',
    };
  }

  /**
   * Lazily decode a candidate that wasn't auto-decoded.
   * Called when user clicks "Decode" button.
   */
  async lazyDecode(finding) {
    if (finding.decodedBytes) return finding; // Already decoded

    if (finding.needsDecompression && finding._rawBytes) {
      // Decompress from raw bytes
      const fmt = finding.compressionFormat === 'zlib' ? 'deflate' : finding.compressionFormat;
      const result = await Decompressor.tryDecompress(finding._rawBytes, finding.offset, fmt);
      if (result.success) {
        finding.decodedBytes = result.data;
        finding.decodedSize = result.data.length;
        finding.classification = this._classify(result.data);
        finding.entropy = this._shannonEntropyBytes(result.data);
        finding.iocs = this._extractIOCsFromDecoded(result.data);
        finding.canLoad = true;
        finding.chain.push(finding.classification.type || 'binary data');
        finding.severity = this._assessSeverity(finding.classification, finding.iocs, result.data);
        // Propagate severity and IOCs from existing inner findings
        finding.severity = EncodedContentDetector._propagateInnerFindings(finding.severity, finding.iocs, finding.innerFindings);
      }
      return finding;
    }

    if (finding.rawCandidate) {
      // Decode the text candidate
      const pseudoCandidate = {
        type: finding.encoding,
        raw: finding.rawCandidate,
        offset: finding.offset,
        length: finding.length,
        autoDecoded: true,
      };
      const decoded = this._decodeCandidate(pseudoCandidate);
      if (decoded && decoded.length > 0) {
        finding.decodedBytes = decoded;
        finding.decodedSize = decoded.length;
        finding.classification = this._classify(decoded);
        finding.entropy = this._shannonEntropyBytes(decoded);
        finding.iocs = this._extractIOCsFromDecoded(decoded);
        finding.canLoad = !!(finding.classification.type || this._isValidUTF8(decoded));
        const chain = [finding.encoding];
        if (finding.classification.type) chain.push(finding.classification.type);
        else if (this._isValidUTF8(decoded)) chain.push('text');
        else chain.push('binary data');
        finding.chain = chain;
        finding.severity = this._assessSeverity(finding.classification, finding.iocs, decoded);
        // Propagate severity and IOCs from existing inner findings
        finding.severity = EncodedContentDetector._propagateInnerFindings(finding.severity, finding.iocs, finding.innerFindings);
        finding.ext = finding.classification.ext || (this._isValidUTF8(decoded) ? '.txt' : '.bin');
        finding.autoDecoded = true;
        finding.rawCandidate = null;
      }
      return finding;
    }

    return finding;
  }

  // ════════════════════════════════════════════════════════════════════════
  // DECODERS (primary switch is in ADDITIONAL DECODERS section below)
  // ════════════════════════════════════════════════════════════════════════

  _decodeBase64(str) {
    try {
      // Normalise URL-safe chars
      const normalised = str.replace(/-/g, '+').replace(/_/g, '/');
      // Pad if needed
      const padded = normalised + '=='.slice(0, (4 - normalised.length % 4) % 4);
      const bin = atob(padded);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return bytes;
    } catch (_) {
      return null;
    }
  }

  _decodeHex(hexStr) {
    try {
      const clean = hexStr.replace(/\s+/g, '');
      if (clean.length % 2 !== 0) return null;
      const bytes = new Uint8Array(clean.length / 2);
      for (let i = 0; i < clean.length; i += 2) {
        bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
      }
      return bytes;
    } catch (_) {
      return null;
    }
  }

  _decodeBase32(str) {
    try {
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      const clean = str.replace(/=+$/, '');
      const bits = [];
      for (const ch of clean) {
        const val = alphabet.indexOf(ch.toUpperCase());
        if (val === -1) return null;
        bits.push(...val.toString(2).padStart(5, '0').split('').map(Number));
      }
      const bytes = new Uint8Array(Math.floor(bits.length / 8));
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = bits.slice(i * 8, i * 8 + 8).reduce((acc, b) => (acc << 1) | b, 0);
      }
      return bytes;
    } catch (_) {
      return null;
    }
  }

  // ════════════════════════════════════════════════════════════════════════
  // PHASE 3: CLASSIFY & REPORT
  // ════════════════════════════════════════════════════════════════════════

  _classify(bytes) {
    if (!bytes || bytes.length < 2) return { type: null, ext: null };

    // Binary magic byte check
    for (const sig of EncodedContentDetector.MAGIC_BYTES) {
      if (bytes.length < sig.magic.length) continue;
      let match = true;
      for (let i = 0; i < sig.magic.length; i++) {
        if (bytes[i] !== sig.magic[i]) { match = false; break; }
      }
      if (match) return { type: sig.type, ext: sig.ext };
    }

    // Text-based signature check (UTF-8)
    const head = this._tryDecodeUTF8(bytes.subarray(0, Math.min(200, bytes.length)));
    if (head) {
      for (const sig of EncodedContentDetector.TEXT_SIGNATURES) {
        if (sig.pattern.test(head)) return { type: sig.type, ext: sig.ext };
      }
    }

    // UTF-16LE detection (common with PowerShell -EncodedCommand)
    const u16Head = this._tryDecodeUTF16LE(bytes.subarray(0, Math.min(400, bytes.length)));
    if (u16Head) {
      for (const sig of EncodedContentDetector.TEXT_SIGNATURES) {
        if (sig.pattern.test(u16Head)) return { type: sig.type + ' (UTF-16LE)', ext: sig.ext };
      }
      // Generic UTF-16LE text (e.g. PowerShell commands that don't start with a keyword)
      if (u16Head.length > 8 && /[a-zA-Z]{3,}/.test(u16Head)) {
        return { type: 'UTF-16LE Text', ext: '.txt' };
      }
    }

    return { type: null, ext: null };
  }

  _assessSeverity(classification, iocs, decoded) {
    const t = (classification.type || '').toLowerCase();

    // Critical file types
    if (t.includes('pe executable') || t.includes('elf binary') || t.includes('mach-o'))
      return 'high';

    // Dangerous script types
    if (t.includes('hta') || t.includes('powershell') || t.includes('vbscript') || t.includes('shell script'))
      return 'high';

    // Archives and documents
    if (t.includes('zip') || t.includes('rar') || t.includes('ole') || t.includes('pdf'))
      return 'medium';

    // IOCs found in decoded content
    if (iocs.length > 0) return 'medium';

    // Recognised text/binary with no specific threat
    if (classification.type) return 'info';

    // Unknown decoded content
    return 'info';
  }

  // ════════════════════════════════════════════════════════════════════════
  // IOC EXTRACTION FROM DECODED CONTENT
  // ════════════════════════════════════════════════════════════════════════

  _extractIOCsFromDecoded(bytes) {
    // Try UTF-8 first, fall back to UTF-16LE (PowerShell -EncodedCommand uses UTF-16LE)
    let text = this._tryDecodeUTF8(bytes);
    if (!text || text.length < 8) text = this._tryDecodeUTF16LE(bytes);
    if (!text || text.length < 8) return [];

    const iocs = [];
    const seen = new Set();
    const add = (type, val, sev, note) => {
      val = (val || '').trim().replace(/[.,;:!?)\]>]+$/, '');
      if (!val || val.length < 4 || val.length > 400 || seen.has(val)) return;
      seen.add(val);
      const entry = { type, url: val, severity: sev };
      if (note) entry.note = note;
      iocs.push(entry);
    };

    // Process URLs with SafeLink unwrapping
    for (const m of text.matchAll(/https?:\/\/[^\s"'<>()\[\]{}\u0000-\u001F]{6,}/g)) {
      const url = (m[0] || '').trim().replace(/[.,;:!?)\]>]+$/, '');
      const unwrapped = EncodedContentDetector.unwrapSafeLink(url);
      if (unwrapped) {
        // Add wrapper URL at info level
        add(IOC.URL, url, 'medium', `${unwrapped.provider} wrapper`);
        // Add extracted URL at high severity (found in encoded content)
        add(IOC.URL, unwrapped.originalUrl, 'high', `Extracted from ${unwrapped.provider}`);
        // Add any extracted emails
        for (const email of unwrapped.emails) {
          add(IOC.EMAIL, email, 'high', 'Extracted from SafeLinks');
        }
      } else {
        add(IOC.URL, url, 'high');
      }
    }

    for (const m of text.matchAll(/\b[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b/g))
      add(IOC.EMAIL, m[0], 'medium');
    for (const m of text.matchAll(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g)) {
      const parts = m[0].split('.').map(Number);
      if (parts.every(p => p <= 255) && !m[0].startsWith('0.')) add(IOC.IP, m[0], 'high');
    }
    for (const m of text.matchAll(/[A-Za-z]:\\(?:[\w\-. ]+\\)+[\w\-. ]{2,}/g))
      add(IOC.FILE_PATH, m[0], 'medium');
    for (const m of text.matchAll(/\\\\[\w.\-]{2,}(?:\\[\w.\-]{1,})+/g))
      add(IOC.UNC_PATH, m[0], 'medium');

    return iocs;
  }

  // ════════════════════════════════════════════════════════════════════════
  // WHITELIST / SKIP RULES
  // ════════════════════════════════════════════════════════════════════════

  _isDataURI(text, offset) {
    // Check if the Base64 candidate follows a data: URI scheme
    const lookback = text.substring(Math.max(0, offset - 80), offset);
    return /data:[a-z]+\/[a-z0-9.+\-]+;base64,\s*$/i.test(lookback);
  }

  _isPEMBlock(text, offset) {
    const lookback = text.substring(Math.max(0, offset - 60), offset);
    return /-----BEGIN [A-Z ]+-----\s*$/i.test(lookback);
  }

  _isCSSFontData(text, offset) {
    const lookback = text.substring(Math.max(0, offset - 100), offset);
    return /src:\s*url\(data:(font|application\/x-font)/i.test(lookback);
  }

  _isMIMEBody(text, offset, context) {
    // Skip Base64 blocks that are MIME-encoded attachment bodies (already handled by EmlRenderer)
    if (context.fileType !== 'eml') return false;
    // Check if preceded by Content-Transfer-Encoding: base64 header
    const lookback = text.substring(Math.max(0, offset - 300), offset);
    return /Content-Transfer-Encoding:\s*base64/i.test(lookback);
  }

  _isHashLength(hexStr) {
    const len = hexStr.length;
    return len === 32 || len === 40 || len === 64 || len === 128;
  }

  _isGUID(text, offset) {
    // Check if this is part of a GUID pattern
    const region = text.substring(Math.max(0, offset - 5), offset + 40);
    return /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i.test(region);
  }

  _isPowerShellEncodedCommand(text, offset) {
    const lookback = text.substring(Math.max(0, offset - 60), offset);
    return /-(enc|encodedcommand|ec|EncodedCommand)\s+$/i.test(lookback);
  }

  _hasBase32Context(text, offset) {
    const lookback = text.substring(Math.max(0, offset - 100), offset);
    // Require contextual keywords
    return /(base32|encoded|payload|data|command|parameter|secret)/i.test(lookback) ||
           /['"]$/.test(lookback.trim());
  }

  // ════════════════════════════════════════════════════════════════════════
  // ENTROPY & UTILITY FUNCTIONS
  // ════════════════════════════════════════════════════════════════════════

  _shannonEntropyString(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    const len = str.length;
    return -Object.values(freq).reduce((sum, f) => {
      const p = f / len;
      return sum + p * Math.log2(p);
    }, 0);
  }

  _shannonEntropyBytes(bytes) {
    if (!bytes || bytes.length === 0) return 0;
    const freq = new Uint32Array(256);
    for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
    const len = bytes.length;
    let entropy = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] === 0) continue;
      const p = freq[i] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  _tryDecodeUTF8(bytes) {
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      // Reject if too many control characters (likely binary)
      const controlCount = [...text].filter(c => {
        const cp = c.codePointAt(0);
        return cp < 32 && cp !== 9 && cp !== 10 && cp !== 13; // allow tab, LF, CR
      }).length;
      if (controlCount > text.length * 0.1) return null;
      return text;
    } catch (_) {
      return null;
    }
  }

  _isValidUTF8(bytes) {
    return this._tryDecodeUTF8(bytes) !== null;
  }

  _tryDecodeUTF16LE(bytes) {
    try {
      if (!bytes || bytes.length < 4 || bytes.length % 2 !== 0) return null;
      // Heuristic: UTF-16LE ASCII text has every other byte as 0x00
      // Check first ~20 code units for the pattern
      const sampleLen = Math.min(40, bytes.length);
      let nullCount = 0;
      for (let i = 1; i < sampleLen; i += 2) {
        if (bytes[i] === 0x00) nullCount++;
      }
      // At least 60% of high bytes should be 0x00 for ASCII-as-UTF-16LE
      if (nullCount < (sampleLen / 2) * 0.6) return null;

      // Skip BOM if present
      const start = (bytes[0] === 0xFF && bytes[1] === 0xFE) ? 2 : 0;
      const text = new TextDecoder('utf-16le').decode(bytes.subarray(start));
      // Reject if too many control characters
      const controlCount = [...text].filter(c => {
        const cp = c.codePointAt(0);
        return cp < 32 && cp !== 9 && cp !== 10 && cp !== 13;
      }).length;
      if (controlCount > text.length * 0.1) return null;
      return text;
    } catch (_) {
      return null;
    }
  }

  // ════════════════════════════════════════════════════════════════════════
  // ADDITIONAL ENCODING CANDIDATE FINDERS
  // ════════════════════════════════════════════════════════════════════════

  /**
   * URL-encoded strings: %70%6F%77%65%72%73%68%65%6C%6C
   * Requires ≥10 consecutive %XX sequences to avoid false positives.
   */
  _findUrlEncodedCandidates(text, context) {
    if (!text || text.length < 30) return [];
    const candidates = [];
    // Match 10+ consecutive %XX sequences (may have non-encoded chars between)
    const re = /(?:%[0-9a-fA-F]{2}){10,}/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      const offset = m.index;
      // Skip if inside a URL that's already a normal parameter
      const lookback = text.substring(Math.max(0, offset - 10), offset);
      if (/[?&=]$/.test(lookback)) continue;
      candidates.push({
        type: 'URL Encoding',
        raw,
        offset,
        length: raw.length,
        entropy: this._shannonEntropyString(raw),
        confidence: 'high',
        hint: 'URL percent-encoded data',
        autoDecoded: true,
      });
    }
    return candidates;
  }

  /**
   * HTML entity encoded sequences: &#112;&#111;&#119; or &#x70;&#x6f;&#x77;
   * Requires ≥8 consecutive entities.
   */
  _findHtmlEntityCandidates(text, context) {
    if (!text || text.length < 30) return [];
    const candidates = [];
    // Decimal entities: &#NNN; sequences
    const decRe = /(?:&#\d{1,5};){8,}/g;
    let m;
    while ((m = decRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      candidates.push({
        type: 'HTML Entities',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: 'HTML decimal entity encoded',
        autoDecoded: true,
        _subtype: 'decimal',
      });
    }
    // Hex entities: &#xHH; sequences
    const hexRe = /(?:&#x[0-9a-fA-F]{1,4};){8,}/g;
    while ((m = hexRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      candidates.push({
        type: 'HTML Entities',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: 'HTML hex entity encoded',
        autoDecoded: true,
        _subtype: 'hex',
      });
    }
    return candidates;
  }

  /**
   * Unicode escape sequences: \u0070\u006f\u0077\u0065 (8+ sequences)
   */
  _findUnicodeEscapeCandidates(text, context) {
    if (!text || text.length < 40) return [];
    const candidates = [];
    const re = /(?:\\u[0-9a-fA-F]{4}){8,}/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      candidates.push({
        type: 'Unicode Escape',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: 'Unicode escape sequence',
        autoDecoded: true,
      });
    }
    return candidates;
  }

  /**
   * Decimal character arrays: [112,111,119,101,114] or Chr(112)&Chr(111)&...
   * Also matches: String.fromCharCode(72,101,108,...) and [char]72+[char]101+...
   */
  _findCharArrayCandidates(text, context) {
    if (!text || text.length < 20) return [];
    const candidates = [];
    let m;

    // JavaScript-style: [NNN,NNN,...] with 10+ entries of printable ASCII range
    const jsArrayRe = /\[(\d{1,3}(?:\s*,\s*\d{1,3}){9,})\]/g;
    while ((m = jsArrayRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const nums = m[1].split(',').map(s => parseInt(s.trim(), 10));
      // Verify most values are in printable ASCII range
      const printable = nums.filter(n => n >= 32 && n <= 126).length;
      if (printable < nums.length * 0.6) continue;
      candidates.push({
        type: 'Char Array',
        raw: m[1],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: 'Decimal character array',
        autoDecoded: true,
        _subtype: 'js-array',
      });
    }

    // String.fromCharCode(N,N,N,...)
    const sfccRe = /String\.fromCharCode\s*\(\s*(\d{1,3}(?:\s*,\s*\d{1,3}){4,})\s*\)/gi;
    while ((m = sfccRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      candidates.push({
        type: 'Char Array',
        raw: m[1],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: 'String.fromCharCode()',
        autoDecoded: true,
        _subtype: 'fromCharCode',
      });
    }

    // VBScript-style: Chr(N)&Chr(N)&... or ChrW(N)&ChrW(N)&...
    const chrRe = /(?:ChrW?\(\d{1,5}\)\s*[&+]\s*){5,}ChrW?\(\d{1,5}\)/gi;
    while ((m = chrRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      candidates.push({
        type: 'Char Array',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: 'VBScript Chr()/ChrW() concatenation',
        autoDecoded: true,
        _subtype: 'vbs-chr',
      });
    }

    // PowerShell-style: [char]72+[char]101+[char]108+...
    const psCharRe = /(?:\[char\]\d{1,5}\s*\+\s*){4,}\[char\]\d{1,5}/gi;
    while ((m = psCharRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      candidates.push({
        type: 'Char Array',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: 'PowerShell [char] casting',
        autoDecoded: true,
        _subtype: 'ps-char',
      });
    }

    // PowerShell @(N,N,N,...) array syntax with 10+ entries
    const psArrayRe = /@\((\d{1,3}(?:\s*,\s*\d{1,3}){9,})\)/g;
    while ((m = psArrayRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const nums = m[1].split(',').map(s => parseInt(s.trim(), 10));
      const printable = nums.filter(n => n >= 32 && n <= 126).length;
      if (printable < nums.length * 0.6) continue;
      candidates.push({
        type: 'Char Array',
        raw: m[1],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: 'PowerShell @() array',
        autoDecoded: true,
        _subtype: 'js-array',  // decoded the same way as JS arrays
      });
    }

    // Bare comma-separated integers assigned to a variable (PowerShell allows $x = 1,2,3)
    // Match: = N,N,N,N,N,... with 10+ entries in printable ASCII range
    const bareArrayRe = /=\s*(\d{1,3}(?:\s*,\s*\d{1,3}){9,})\s*$/gm;
    while ((m = bareArrayRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const nums = m[1].split(',').map(s => parseInt(s.trim(), 10));
      const printable = nums.filter(n => n >= 32 && n <= 126).length;
      if (printable < nums.length * 0.6) continue;
      candidates.push({
        type: 'Char Array',
        raw: m[1],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: 'Bare integer array assignment',
        autoDecoded: true,
        _subtype: 'js-array',
      });
    }

    // Python-style: chr(104)+chr(116)+chr(116)+chr(112)+...
    const pyChrRe = /(?:chr\(\d{1,5}\)\s*\+\s*){5,}chr\(\d{1,5}\)/gi;
    while ((m = pyChrRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      candidates.push({
        type: 'Char Array',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: 'Python chr() concatenation',
        autoDecoded: true,
        _subtype: 'py-chr',
      });
    }

    // Perl-style: chr(104).chr(116).chr(116).chr(112)....
    const perlChrRe = /(?:chr\(\d{1,5}\)\s*\.\s*){5,}chr\(\d{1,5}\)/gi;
    while ((m = perlChrRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      candidates.push({
        type: 'Char Array',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: 'Perl chr() concatenation',
        autoDecoded: true,
        _subtype: 'perl-chr',
      });
    }

    // Python bytes([N,N,N,...]) constructor
    const pyBytesRe = /bytes\s*\(\s*\[(\d{1,3}(?:\s*,\s*\d{1,3}){9,})\]\s*\)/gi;
    while ((m = pyBytesRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      candidates.push({
        type: 'Char Array',
        raw: m[1],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: 'Python bytes() constructor',
        autoDecoded: true,
        _subtype: 'js-array',
      });
    }

    return candidates;
  }

  /**
   * Octal escape sequences: \160\157\167\145\162 (8+ sequences)
   */
  _findOctalEscapeCandidates(text, context) {
    if (!text || text.length < 24) return [];
    const candidates = [];
    // Octal: \NNN where NNN is 1-3 octal digits, no 'x' or 'u' after backslash
    const re = /(?:\\[0-3]?[0-7]{2}){8,}/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      // Ensure these aren't hex escapes (\x..) accidentally matched
      if (/\\x/i.test(m[0])) continue;
      candidates.push({
        type: 'Octal Escape',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'normal',
        hint: 'Octal escape sequence',
        autoDecoded: true,
      });
    }
    return candidates;
  }

  /**
   * JScript.Encode / VBScript.Encode: #@~^ marker
   */
  _findScriptEncodedCandidates(text, context) {
    if (!text || text.length < 12) return [];
    const candidates = [];
    // The Microsoft Script Encoder format: #@~^XXXXXX==^#~@
    const re = /#@~\^[A-Za-z0-9+\/=]{6,}[=]*\^#~@/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      candidates.push({
        type: 'Script.Encode',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: 'Microsoft Script Encoder (JSE/VBE)',
        autoDecoded: true,
      });
    }
    return candidates;
  }

  // ════════════════════════════════════════════════════════════════════════
  // ADDITIONAL DECODERS (extended _decodeCandidate)
  // ════════════════════════════════════════════════════════════════════════

  // Override _decodeCandidate to handle new types
  _decodeCandidate(candidate) {
    switch (candidate.type) {
      case 'Base64': return this._decodeBase64(candidate.raw);
      case 'Hex':
      case 'Hex (escaped)':
      case 'Hex (PS byte array)': return this._decodeHex(candidate.raw);
      case 'Base32': return this._decodeBase32(candidate.raw);
      case 'URL Encoding': return this._decodeUrlEncoded(candidate.raw);
      case 'HTML Entities': return this._decodeHtmlEntities(candidate.raw, candidate._subtype);
      case 'Unicode Escape': return this._decodeUnicodeEscapes(candidate.raw);
      case 'Char Array': return this._decodeCharArray(candidate.raw, candidate._subtype);
      case 'Octal Escape': return this._decodeOctalEscapes(candidate.raw);
      case 'Script.Encode': return this._decodeScriptEncoded(candidate.raw);
      case 'Hex (space-delimited)': return this._decodeSpaceDelimitedHex(candidate.raw);
      case 'ROT13': return this._decodeRot13(candidate.raw);
      case 'Split-Join': return this._decodeSplitJoin(candidate.raw, candidate._separator);
      default: return null;
    }
  }

  _decodeUrlEncoded(str) {
    try {
      const decoded = decodeURIComponent(str);
      return new TextEncoder().encode(decoded);
    } catch (_) {
      try {
        // Fallback: manual decode for malformed sequences
        const decoded = str.replace(/%([0-9a-fA-F]{2})/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        );
        return new TextEncoder().encode(decoded);
      } catch (_2) { return null; }
    }
  }

  _decodeHtmlEntities(str, subtype) {
    try {
      let decoded;
      if (subtype === 'hex') {
        decoded = str.replace(/&#x([0-9a-fA-F]{1,4});/gi, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        );
      } else {
        decoded = str.replace(/&#(\d{1,5});/g, (_, dec) =>
          String.fromCharCode(parseInt(dec, 10))
        );
      }
      return new TextEncoder().encode(decoded);
    } catch (_) { return null; }
  }

  _decodeUnicodeEscapes(str) {
    try {
      const decoded = str.replace(/\\u([0-9a-fA-F]{4})/gi, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16))
      );
      return new TextEncoder().encode(decoded);
    } catch (_) { return null; }
  }

  _decodeCharArray(raw, subtype) {
    try {
      let nums;
      if (subtype === 'vbs-chr') {
        nums = [...raw.matchAll(/ChrW?\((\d{1,5})\)/gi)].map(m => parseInt(m[1], 10));
      } else if (subtype === 'ps-char') {
        nums = [...raw.matchAll(/\[char\](\d{1,5})/gi)].map(m => parseInt(m[1], 10));
      } else if (subtype === 'py-chr' || subtype === 'perl-chr') {
        nums = [...raw.matchAll(/chr\((\d{1,5})\)/gi)].map(m => parseInt(m[1], 10));
      } else {
        // js-array, fromCharCode, ps-array, bare assignment, bytes()
        nums = raw.split(',').map(s => parseInt(s.trim(), 10));
      }
      if (!nums.length) return null;
      const decoded = nums.map(n => String.fromCharCode(n)).join('');
      return new TextEncoder().encode(decoded);
    } catch (_) { return null; }
  }

  _decodeOctalEscapes(str) {
    try {
      const decoded = str.replace(/\\([0-3]?[0-7]{1,2})/g, (_, oct) =>
        String.fromCharCode(parseInt(oct, 8))
      );
      return new TextEncoder().encode(decoded);
    } catch (_) { return null; }
  }

  /**
   * Microsoft Script Encoder decoder (#@~^...^#~@)
   * Implements the substitution cipher used by screnc.exe / JScript.Encode / VBScript.Encode.
   */
  _decodeScriptEncoded(str) {
    try {
      // Strip the #@~^ prefix and ^#~@ suffix
      let payload = str;
      if (payload.startsWith('#@~^')) payload = payload.substring(4);
      if (payload.endsWith('^#~@')) payload = payload.substring(0, payload.length - 4);
      // The encoded payload has a 6-char length prefix and 6-char checksum suffix separated by ==
      // Format: LEN==ENCODED_DATA==CHECKSUM
      // For simplicity, try to decode the middle section
      const eqIdx = payload.indexOf('==');
      if (eqIdx >= 0) payload = payload.substring(eqIdx + 2);
      const eqIdx2 = payload.lastIndexOf('==');
      if (eqIdx2 >= 0) payload = payload.substring(0, eqIdx2);

      // Microsoft Script Encoder substitution tables
      const decTable = [
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x57,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
        0x2E,0x47,0x7A,0x56,0x42,0x6A,0x2F,0x26,0x49,0x41,0x34,0x32,0x5B,0x76,0x72,0x43,
        0x38,0x39,0x70,0x45,0x68,0x71,0x51,0x73,0x74,0x75,0x09,0x02,0x28,0x29,0x2A,0x3F,
        0x40,0x5A,0x2B,0x5E,0x7D,0x29,0x2C,0x22,0x50,0x6F,0x4E,0x53,0x6E,0x67,0x2D,0x30,
        0x65,0x3D,0x61,0x53,0x55,0x40,0x37,0x24,0x48,0x23,0x36,0x7C,0x5D,0x7E,0x5C,0x21,
        0x60,0x69,0x54,0x27,0x46,0x25,0x33,0x35,0x44,0x6D,0x4C,0x2E,0x66,0x63,0x3E,0x58,
        0x31,0x52,0x6B,0x4F,0x59,0x4D,0x77,0x5F,0x64,0x62,0x7B,0x78,0x79,0x3B,0x3A,0x20,
      ];

      const pickEnc = [1, 2, 0, 1, 2, 0, 2, 0, 0, 2, 0, 2, 1, 0, 2, 0, 1, 0, 2, 0, 1, 1, 2, 0, 0, 2, 1, 0, 2, 0, 0, 2,
        1, 1, 0, 2, 0, 2, 0, 1, 0, 1, 1, 2, 0, 1, 0, 2, 1, 0, 2, 0, 1, 1, 2, 0, 0, 1, 1, 2, 0, 1, 0, 2];

      const dec3 = [
        [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x7B,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
         0x32,0x30,0x21,0x29,0x5B,0x38,0x33,0x3D,0x58,0x3A,0x35,0x65,0x39,0x5C,0x56,0x73,
         0x66,0x4E,0x45,0x6B,0x62,0x59,0x78,0x5E,0x7D,0x4A,0x6D,0x71,0x00,0x60,0x00,0x53,
         0x00,0x42,0x27,0x48,0x72,0x75,0x31,0x37,0x4D,0x52,0x22,0x54,0x6C,0x70,0x3E,0x34,
         0x67,0x55,0x63,0x24,0x76,0x43,0x79,0x28,0x23,0x41,0x7E,0x4B,0x26,0x2E,0x25,0x2D,
         0x2A,0x2F,0x49,0x6F,0x36,0x6E,0x5F,0x47,0x7C,0x57,0x51,0x3F,0x4F,0x5D,0x5A,0x7A,
         0x2B,0x44,0x2C,0x46,0x69,0x68,0x40,0x7F,0x6A,0x61,0x50,0x77,0x3B,0x4C,0x64,0x74],
        [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x57,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
         0x2E,0x47,0x7A,0x56,0x42,0x6A,0x2F,0x26,0x49,0x41,0x34,0x32,0x5B,0x76,0x72,0x43,
         0x38,0x39,0x70,0x45,0x68,0x71,0x51,0x73,0x74,0x75,0x09,0x02,0x28,0x29,0x2A,0x3F,
         0x40,0x5A,0x2B,0x5E,0x7D,0x29,0x2C,0x22,0x50,0x6F,0x4E,0x53,0x6E,0x67,0x2D,0x30,
         0x65,0x3D,0x61,0x53,0x55,0x40,0x37,0x24,0x48,0x23,0x36,0x7C,0x5D,0x7E,0x5C,0x21,
         0x60,0x69,0x54,0x27,0x46,0x25,0x33,0x35,0x44,0x6D,0x4C,0x2E,0x66,0x63,0x3E,0x58,
         0x31,0x52,0x6B,0x4F,0x59,0x4D,0x77,0x5F,0x64,0x62,0x7B,0x78,0x79,0x3B,0x3A,0x20],
        [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x6E,0x0A,0x0B,0x0C,0x06,0x0E,0x0F,
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
         0x2D,0x75,0x52,0x60,0x71,0x5E,0x49,0x5C,0x62,0x7D,0x29,0x36,0x20,0x7C,0x7A,0x7F,
         0x6B,0x63,0x33,0x2B,0x68,0x51,0x66,0x76,0x31,0x64,0x54,0x43,0x3C,0x3A,0x00,0x7E,
         0x00,0x45,0x2C,0x2A,0x74,0x27,0x37,0x44,0x79,0x59,0x2F,0x6F,0x26,0x72,0x6A,0x39,
         0x7B,0x3F,0x38,0x77,0x67,0x53,0x47,0x34,0x78,0x5D,0x30,0x23,0x5A,0x5B,0x6C,0x48,
         0x55,0x70,0x69,0x2E,0x4C,0x21,0x24,0x4E,0x50,0x09,0x56,0x73,0x35,0x61,0x4B,0x58,
         0x3B,0x57,0x22,0x6D,0x4D,0x25,0x28,0x46,0x4A,0x32,0x41,0x3D,0x5F,0x4F,0x42,0x65],
      ];

      let result = '';
      let idx = 0;
      for (let i = 0; i < payload.length; i++) {
        const ch = payload.charCodeAt(i);
        if (ch === 1 && i + 1 < payload.length) {
          // Escape byte — next char is literal
          i++;
          result += payload[i];
        } else if (ch < 128) {
          const tableIdx = pickEnc[idx % 64];
          result += String.fromCharCode(dec3[tableIdx][ch]);
          idx++;
        } else {
          result += payload[i];
        }
      }
      if (!result || result.length < 4) return null;
      return new TextEncoder().encode(result);
    } catch (_) { return null; }
  }

  // ════════════════════════════════════════════════════════════════════════
  // COMMAND OBFUSCATION DETECTION & DEOBFUSCATION
  // ════════════════════════════════════════════════════════════════════════

  /**
   * Find command obfuscation patterns (CMD and PowerShell).
   * Each candidate includes the obfuscated text and the technique detected.
   */
  _findCommandObfuscationCandidates(text, context) {
    if (!text || text.length < 10) return [];
    const candidates = [];

    // ── CMD caret insertion: p^o^w^e^r^s^h^e^l^l ──
    // Match words with 3+ carets interspersed
    const caretRe = /\b[a-zA-Z]\^[a-zA-Z](?:\^?[a-zA-Z]){3,}\b/g;
    let m;
    while ((m = caretRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const deobfuscated = m[0].replace(/\^/g, '');
      if (deobfuscated.length < 3) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'CMD Caret Insertion',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated,
      });
    }

    // ── CMD set variable concatenation ──
    // Pattern: multiple "set X=..." followed by %X%%Y%%Z% or !X!!Y!!Z!
    const setRe = /(?:^|\n)\s*set\s+["']?(\w+)["']?\s*=\s*([^\r\n]*)/gim;
    const vars = {};
    while ((m = setRe.exec(text)) !== null) {
      vars[m[1].toLowerCase()] = { value: m[2].trim(), offset: m.index };
    }
    if (Object.keys(vars).length >= 2) {
      // Look for variable concatenation: %var1%%var2% or !var1!!var2! or %var1:~N,M%
      const concatRe = /(?:%(\w+)%|!(\w+)!){2,}/g;
      while ((m = concatRe.exec(text)) !== null) {
        if (candidates.length >= this.maxCandidatesPerType) break;
        let resolved = m[0];
        let anyResolved = false;
        // Resolve %var% references
        resolved = resolved.replace(/%(\w+)%/gi, (full, vname) => {
          const v = vars[vname.toLowerCase()];
          if (v) { anyResolved = true; return v.value; }
          return full;
        });
        // Resolve !var! references (delayed expansion)
        resolved = resolved.replace(/!(\w+)!/gi, (full, vname) => {
          const v = vars[vname.toLowerCase()];
          if (v) { anyResolved = true; return v.value; }
          return full;
        });
        if (anyResolved && resolved !== m[0] && resolved.length >= 3) {
          candidates.push({
            type: 'cmd-obfuscation',
            technique: 'CMD Variable Concatenation',
            raw: m[0],
            offset: m.index,
            length: m[0].length,
            deobfuscated: resolved,
            _vars: vars,
          });
        }
      }
    }

    // ── CMD environment variable substring abuse: %COMSPEC:~-7,1% ──
    const envSubRe = /%\w+:~-?\d+(?:,\d+)?%/g;
    const envSubMatches = [];
    while ((m = envSubRe.exec(text)) !== null) {
      envSubMatches.push({ match: m[0], offset: m.index });
    }
    if (envSubMatches.length >= 3) {
      // Find the line(s) containing these, treat entire line as obfuscated command
      const lineRe = /^.*%\w+:~-?\d+(?:,\d+)?%.*$/gm;
      while ((m = lineRe.exec(text)) !== null) {
        if (candidates.length >= this.maxCandidatesPerType) break;
        const subCount = (m[0].match(/%\w+:~-?\d+(?:,\d+)?%/g) || []).length;
        if (subCount < 3) continue;
        candidates.push({
          type: 'cmd-obfuscation',
          technique: 'CMD Env Var Substring',
          raw: m[0],
          offset: m.index,
          length: m[0].length,
          deobfuscated: `[${subCount} env var substring operations — partial decode not reliable without runtime]`,
        });
      }
    }

    // ── PowerShell string concatenation: ('Down'+'loadStr'+'ing') ──
    const psConcat = /\(\s*'[^']{1,40}'\s*(?:\+\s*'[^']{1,40}'\s*){2,}\)/g;
    while ((m = psConcat.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const parts = [...m[0].matchAll(/'([^']*)'/g)].map(p => p[1]);
      const joined = parts.join('');
      if (joined.length < 4) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell String Concatenation',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: joined,
      });
    }
    // Also match with double quotes
    const psConcatDQ = /\(\s*"[^"]{1,40}"\s*(?:\+\s*"[^"]{1,40}"\s*){2,}\)/g;
    while ((m = psConcatDQ.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const parts = [...m[0].matchAll(/"([^"]*)"/g)].map(p => p[1]);
      const joined = parts.join('');
      if (joined.length < 4) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell String Concatenation',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: joined,
      });
    }

    // ── PowerShell -replace chain: 'XYZ'.replace('X','a').replace('Y','b') ──
    const psReplace = /'[^']{2,80}'(?:\s*\.\s*replace\s*\(\s*'[^']*'\s*,\s*'[^']*'\s*\)){2,}/gi;
    while ((m = psReplace.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      let result = m[0].match(/^'([^']*)'/)[1];
      const replacements = [...m[0].matchAll(/\.replace\s*\(\s*'([^']*)'\s*,\s*'([^']*)'\s*\)/gi)];
      for (const rep of replacements) {
        result = result.split(rep[1]).join(rep[2]);
      }
      if (result.length < 3 || result === m[0]) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell -replace Chain',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: result,
      });
    }

    // ── PowerShell backtick escape: I`nv`o`ke-`E`xp`ression ──
    // Match words with 2+ backticks that form known cmdlets/keywords
    const backtickRe = /[a-zA-Z`]{4,}(?:-[a-zA-Z`]{3,})?/g;
    while ((m = backtickRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if ((raw.match(/`/g) || []).length < 2) continue;
      const cleaned = raw.replace(/`/g, '');
      // Must resolve to a known suspicious keyword
      const suspiciousKeywords = /^(invoke-expression|invoke-webrequest|invoke-restmethod|downloadstring|downloadfile|start-process|new-object|set-executionpolicy|invoke-command|get-credential|convertto-securestring|frombase64string|encodedcommand|invoke-mimikatz|invoke-shellcode|powershell|cmd|wscript|cscript|mshta|certutil|bitsadmin|regsvr32|rundll32)$/i;
      if (!suspiciousKeywords.test(cleaned)) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell Backtick Escape',
        raw,
        offset: m.index,
        length: raw.length,
        deobfuscated: cleaned,
      });
    }

    // ── PowerShell format operator: '{0}{1}' -f 'Inv','oke-Expression' ──
    const fmtRe = /'(\{[0-9]\}[^']{0,60})'\s*-f\s*'([^']+)'(?:\s*,\s*'([^']+)')*(?:\s*,\s*'([^']+)')*/gi;
    while ((m = fmtRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      // Capture the full expression including all arguments
      const fullExpr = m[0];
      const template = m[1];
      const args = [...fullExpr.matchAll(/-f\s+((?:'[^']*'(?:\s*,\s*)?)+)/gi)];
      if (!args.length) continue;
      const argValues = [...args[0][1].matchAll(/'([^']*)'/g)].map(a => a[1]);
      let result = template;
      for (let i = 0; i < argValues.length; i++) {
        result = result.replace(new RegExp('\\{' + i + '\\}', 'g'), argValues[i]);
      }
      if (result.length < 3 || result === template) continue;
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell Format Operator (-f)',
        raw: fullExpr,
        offset: m.index,
        length: fullExpr.length,
        deobfuscated: result,
      });
    }

    // ── PowerShell reverse string: 'sserpxE-ekovnI'[-1..-100] -join '' ──
    const revRe = /'([^']{4,80})'\s*\[\s*-1\s*\.\.\s*-\d+\s*\]\s*-join\s*['"]['"]['"]/gi;
    while ((m = revRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const reversed = m[1].split('').reverse().join('');
      candidates.push({
        type: 'cmd-obfuscation',
        technique: 'PowerShell String Reversal',
        raw: m[0],
        offset: m.index,
        length: m[0].length,
        deobfuscated: reversed,
      });
    }

    return candidates;
  }

  /**
   * Process a command obfuscation candidate into a finding.
   */
  async _processCommandObfuscation(candidate) {
    const deobf = candidate.deobfuscated;
    if (!deobf || deobf.length < 3) return null;

    const deobfBytes = new TextEncoder().encode(deobf);
    const iocs = this._extractIOCsFromDecoded(deobfBytes);

    // Check for dangerous patterns in deobfuscated output
    const dangerousPatterns = [
      /powershell/i, /cmd\.exe/i, /wscript/i, /cscript/i, /mshta/i,
      /certutil/i, /bitsadmin/i, /regsvr32/i, /rundll32/i,
      /invoke-expression/i, /invoke-webrequest/i, /downloadstring/i,
      /downloadfile/i, /new-object/i, /start-process/i,
      /net\.webclient/i, /frombase64string/i, /encodedcommand/i,
      /shellexecute/i, /wscript\.shell/i, /MSXML2\.XMLHTTP/i,
      /http:\/\//i, /https:\/\//i, /\\\\/,
    ];
    const matchedPatterns = dangerousPatterns.filter(p => p.test(deobf));
    let severity = 'medium';
    if (matchedPatterns.length >= 2) severity = 'high';
    if (matchedPatterns.length >= 3) severity = 'critical';
    if (iocs.length > 0) severity = severity === 'critical' ? 'critical' : 'high';

    return {
      type: 'encoded-content',
      severity,
      encoding: candidate.technique,
      offset: candidate.offset,
      length: candidate.length,
      decodedSize: deobf.length,
      decodedBytes: deobfBytes,
      chain: [candidate.technique, 'Deobfuscated Command'],
      classification: { type: 'Deobfuscated Command', ext: '.txt' },
      entropy: this._shannonEntropyBytes(deobfBytes),
      hint: candidate.technique,
      iocs,
      innerFindings: [],
      autoDecoded: true,
      canLoad: true,
      ext: '.txt',
      snippet: candidate.raw.substring(0, 120),
      _deobfuscatedText: deobf,
      _obfuscatedText: candidate.raw,
    };
  }

  // ════════════════════════════════════════════════════════════════════════
  // NEW ENCODING FINDERS & DECODERS
  // ════════════════════════════════════════════════════════════════════════

  /**
   * Space/colon/dash-delimited hex strings: "57 72 69 74 65 2D 4F 75 74 70 75 74"
   * Requires ≥10 hex byte values, most in printable ASCII range.
   */
  _findSpaceDelimitedHexCandidates(text, context) {
    if (!text || text.length < 29) return [];
    const candidates = [];
    // Match 10+ two-digit hex bytes separated by spaces, colons, or dashes
    const re = /(?:[0-9a-fA-F]{2}[\s:\-]){9,}[0-9a-fA-F]{2}/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      const offset = m.index;
      // Extract just the hex values
      const hexBytes = raw.match(/[0-9a-fA-F]{2}/g);
      if (!hexBytes || hexBytes.length < 10) continue;
      // Verify most decode to printable ASCII
      const printable = hexBytes.filter(h => {
        const v = parseInt(h, 16);
        return v >= 32 && v <= 126;
      }).length;
      if (printable < hexBytes.length * 0.6) continue;
      // Skip if this looks like a hash or GUID
      const hexOnly = hexBytes.join('');
      if (this._isHashLength(hexOnly)) continue;
      candidates.push({
        type: 'Hex (space-delimited)',
        raw,
        offset,
        length: raw.length,
        entropy: 0,
        confidence: 'high',
        hint: 'Space/colon/dash-delimited hex bytes',
        autoDecoded: true,
      });
    }
    return candidates;
  }

  _decodeSpaceDelimitedHex(str) {
    try {
      const hexBytes = str.match(/[0-9a-fA-F]{2}/g);
      if (!hexBytes || hexBytes.length < 4) return null;
      const bytes = new Uint8Array(hexBytes.length);
      for (let i = 0; i < hexBytes.length; i++) {
        bytes[i] = parseInt(hexBytes[i], 16);
      }
      return bytes;
    } catch (_) { return null; }
  }

  /**
   * ROT13 detection: strings inside quotes that when ROT13-decoded produce
   * recognizable commands/code, especially near eval() or execution context.
   */
  _findRot13Candidates(text, context) {
    if (!text || text.length < 20) return [];
    const candidates = [];
    // Match: ROT13 implementation pattern near a quoted string
    // Look for the classic JS ROT13 pattern: .replace(/[a-zA-Z]/g, function(c){...charCodeAt(0)+13...})
    const rot13PatternRe = /["']([a-zA-Z][a-zA-Z0-9\s.()\\/"'!@#$%^&*\-_+=:;,<>?{}[\]|~`]{10,})["']\s*[;,)]/g;
    let m;
    while ((m = rot13PatternRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[1];
      const offset = m.index;
      // Check if nearby context mentions ROT13 or charCodeAt+13
      const region = text.substring(Math.max(0, offset - 200), Math.min(text.length, offset + raw.length + 200));
      const hasRot13Context = /charCodeAt\s*\(\s*0?\s*\)\s*\+\s*13/i.test(region) ||
                              /rot13/i.test(region) ||
                              /charCode.*\+\s*13/i.test(region);
      if (!hasRot13Context) continue;
      // Verify the ROT13-decoded result contains recognizable words
      const decoded = raw.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
      });
      // Check if decoded has recognizable patterns
      const hasKeywords = /(console|alert|document|window|eval|exec|function|write|log|http|shell|script|import|require)/i.test(decoded);
      if (!hasKeywords) continue;
      candidates.push({
        type: 'ROT13',
        raw,
        offset,
        length: raw.length,
        entropy: 0,
        confidence: 'high',
        hint: 'ROT13-encoded string',
        autoDecoded: true,
      });
    }
    return candidates;
  }

  _decodeRot13(str) {
    try {
      const decoded = str.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
      });
      return new TextEncoder().encode(decoded);
    } catch (_) { return null; }
  }

  /**
   * Split-Join deobfuscation: "c o n s o l e . l o g".split(' ').join('')
   * Detects spaced-out strings that are reassembled via split/join or -split/-join.
   */
  _findSplitJoinCandidates(text, context) {
    if (!text || text.length < 20) return [];
    const candidates = [];
    let m;
    // JS: "spaced string".split('X').join('') or .split("X").join("")
    const jsSplitJoinRe = /["']([^"']{10,})["']\s*\.\s*split\s*\(\s*["'](.{1,3})["']\s*\)\s*\.\s*join\s*\(\s*["']['"]?\s*\)/g;
    while ((m = jsSplitJoinRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[1];
      const sep = m[2];
      // Verify removing separator produces something meaningful
      const decoded = raw.split(sep).join('');
      if (decoded.length < 6) continue;
      // Check decoded is mostly printable
      if (!/^[\x20-\x7E]{6,}$/.test(decoded)) continue;
      candidates.push({
        type: 'Split-Join',
        raw,
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: `Split-Join deobfuscation (separator: "${sep}")`,
        autoDecoded: true,
        _separator: sep,
      });
    }
    // PowerShell: "spaced" -split 'X' -join ''
    const psSplitJoinRe = /["']([^"']{10,})["']\s*-split\s*["'](.{1,3})["']\s*-join\s*["']['"]?/gi;
    while ((m = psSplitJoinRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[1];
      const sep = m[2];
      const decoded = raw.split(sep).join('');
      if (decoded.length < 6 || !/^[\x20-\x7E]{6,}$/.test(decoded)) continue;
      candidates.push({
        type: 'Split-Join',
        raw,
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: 'high',
        hint: `PowerShell Split-Join deobfuscation (separator: "${sep}")`,
        autoDecoded: true,
        _separator: sep,
      });
    }
    return candidates;
  }

  _decodeSplitJoin(str, separator) {
    try {
      if (!separator) separator = ' ';
      const decoded = str.split(separator).join('');
      return new TextEncoder().encode(decoded);
    } catch (_) { return null; }
  }
}
