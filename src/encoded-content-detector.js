// ════════════════════════════════════════════════════════════════════════════
// EncodedContentDetector — scans for encoded/compressed blobs, decodes them,
// extracts IOCs, classifies decoded payloads, and supports recursive decode.
// ════════════════════════════════════════════════════════════════════════════

class EncodedContentDetector {

  constructor(opts = {}) {
    this.maxRecursionDepth = opts.maxRecursionDepth || 4;
    this.maxCandidatesPerType = opts.maxCandidatesPerType || 50;
  }

  // ── Magic byte signatures for decoded binary identification ──────────────
  static MAGIC_BYTES = [
    { magic: [0x4D, 0x5A],                     ext: '.exe',  type: 'PE Executable' },
    { magic: [0x50, 0x4B, 0x03, 0x04],         ext: '.zip',  type: 'ZIP Archive' },
    { magic: [0x25, 0x50, 0x44, 0x46],         ext: '.pdf',  type: 'PDF Document' },
    { magic: [0xD0, 0xCF, 0x11, 0xE0],         ext: '.ole',  type: 'OLE/CFB Document' },
    { magic: [0x1F, 0x8B],                     ext: '.gz',   type: 'Gzip Compressed' },
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
    if (!text || text.length < 64) return [];
    const candidates = [];

    // Standard Base64 (including URL-safe variant)
    const b64Re = /[A-Za-z0-9+\/\-_]{64,}={0,2}/g;
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
      if (/^[A-Za-z0-9]+$/.test(raw) && raw.length < 200 && !highConf && !psContext) continue;

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

        // Skip if this is at offset 0 (the file itself is this format — already handled)
        if (i === 0) continue;

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

    // If decoded content is compressed, try to decompress
    if (classification.type === 'Gzip Compressed' || classification.ext === '.gz') {
      try {
        const inflated = await Decompressor.inflate(decoded, 'gzip');
        if (inflated && inflated.length > 0) {
          chain.push('gzip');
          decoded = inflated;
          const innerClass = this._classify(decoded);
          Object.assign(classification, innerClass);
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

    // Propagate severity from inner findings — if nested content is more dangerous,
    // the parent finding should reflect that
    if (innerFindings.length > 0) {
      const sevRank = { critical: 4, high: 3, medium: 2, info: 1 };
      for (const inner of innerFindings) {
        if ((sevRank[inner.severity] || 0) > (sevRank[severity] || 0)) {
          severity = inner.severity;
        }
      }
    }

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

    // Try decompression
    // We need the raw bytes — they'll be passed by the caller
    // For now, mark it for lazy decompression
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
        // Propagate severity from existing inner findings
        if (finding.innerFindings && finding.innerFindings.length) {
          const sevRank = { critical: 4, high: 3, medium: 2, info: 1 };
          for (const inner of finding.innerFindings) {
            if ((sevRank[inner.severity] || 0) > (sevRank[finding.severity] || 0)) {
              finding.severity = inner.severity;
            }
          }
        }
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
        // Propagate severity from existing inner findings
        if (finding.innerFindings && finding.innerFindings.length) {
          const sevRank = { critical: 4, high: 3, medium: 2, info: 1 };
          for (const inner of finding.innerFindings) {
            if ((sevRank[inner.severity] || 0) > (sevRank[finding.severity] || 0)) {
              finding.severity = inner.severity;
            }
          }
        }
        finding.ext = finding.classification.ext || (this._isValidUTF8(decoded) ? '.txt' : '.bin');
        finding.autoDecoded = true;
        finding.rawCandidate = null;
      }
      return finding;
    }

    return finding;
  }

  // ════════════════════════════════════════════════════════════════════════
  // DECODERS
  // ════════════════════════════════════════════════════════════════════════

  _decodeCandidate(candidate) {
    switch (candidate.type) {
      case 'Base64': return this._decodeBase64(candidate.raw);
      case 'Hex':
      case 'Hex (escaped)':
      case 'Hex (PS byte array)': return this._decodeHex(candidate.raw);
      case 'Base32': return this._decodeBase32(candidate.raw);
      default: return null;
    }
  }

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
    const add = (type, val, sev) => {
      val = (val || '').trim().replace(/[.,;:!?)\]>]+$/, '');
      if (!val || val.length < 4 || val.length > 400 || seen.has(val)) return;
      seen.add(val);
      iocs.push({ type, url: val, severity: sev });
    };

    for (const m of text.matchAll(/https?:\/\/[^\s"'<>()\[\]{}\u0000-\u001F]{6,}/g))
      add(IOC.URL, m[0], 'high');
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
}
