// ════════════════════════════════════════════════════════════════════════════
// EncodedContentDetector — scans for encoded/compressed blobs, decodes them,
// extracts IOCs, classifies decoded payloads, and supports recursive decode.
//
// This file is the **class root**. Per-feature methods are mounted onto
// `EncodedContentDetector.prototype` via `Object.assign(...)` from the
// sibling files in `src/decoders/`:
//
//   safelinks.js          — static unwrapSafeLink (Proofpoint v1/v2/v3 + MS)
//   whitelist.js          — _isDataURI / _isPEM / _isCSSFontData / _isMIMEBody /
//                           _isHashLength / _isGUID / _isPowerShellEncodedCommand /
//                           _hasBase32Context
//   entropy.js            — _classify / _assessSeverity /
//                           _shannonEntropyString / _shannonEntropyBytes /
//                           _tryDecodeUTF8 / _isValidUTF8 / _tryDecodeUTF16LE
//   ioc-extract.js        — _extractIOCsFromDecoded
//   base64-hex.js         — Base64 / Hex / Base32 finders + decoders
//   zlib.js               — _findCompressedBlobCandidates /
//                           _processCompressedCandidate
//   encoding-finders.js   — URL-enc / HTML-ent / Unicode-esc / Char-Array /
//                           Octal / Script.Encode / space-hex / ROT13 /
//                           Split-Join finders
//   encoding-decoders.js  — _decodeCandidate switch + the above decoders
//   cmd-obfuscation.js    — _findCommandObfuscationCandidates /
//                           _processCommandObfuscation (CMD + PowerShell)
//
// `scripts/build.py` concatenates these files in the JS_FILES order so the
// class declaration appears before any helper module attaches. The same
// ordered concatenation is reused for the off-thread bundle in
// `WorkerManager.runEncoded()` (see `_encoded_worker_bundle_src` in build.py).
// ════════════════════════════════════════════════════════════════════════════

class EncodedContentDetector {

  constructor(opts = {}) {
    this.maxRecursionDepth = opts.maxRecursionDepth || 4;
    this.maxCandidatesPerType = opts.maxCandidatesPerType || 50;
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

    // Find primary text-encoding candidates (Base64 / Hex / Base32).
    const b64Candidates = this._findBase64Candidates(textContent, context);
    const hexCandidates = this._findHexCandidates(textContent, context);
    const b32Candidates = this._findBase32Candidates(textContent, context);

    // Find secondary encoding candidates (URL-enc / HTML entities /
    // \\uXXXX / char-array / octal / Script.Encode / space-hex / ROT13 /
    // split-join).
    const urlEncCandidates = this._findUrlEncodedCandidates(textContent, context);
    const htmlEntCandidates = this._findHtmlEntityCandidates(textContent, context);
    const unicodeEscCandidates = this._findUnicodeEscapeCandidates(textContent, context);
    const charArrayCandidates = this._findCharArrayCandidates(textContent, context);
    const octalCandidates = this._findOctalEscapeCandidates(textContent, context);
    const scriptEncCandidates = this._findScriptEncodedCandidates(textContent, context);
    const spaceHexCandidates = this._findSpaceDelimitedHexCandidates(textContent, context);
    const rot13Candidates = this._findRot13Candidates(textContent, context);
    const splitJoinCandidates = this._findSplitJoinCandidates(textContent, context);

    // Find CMD / PowerShell command-obfuscation candidates.
    const cmdObfCandidates = this._findCommandObfuscationCandidates(textContent, context);

    // Find compressed-blob candidates in the raw bytes (zlib / gzip / etc.).
    const compressedCandidates = this._findCompressedBlobCandidates(rawBytes, context);

    // Decode and classify every candidate.
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
  // CORE: candidate processing + recursion driver
  // (Per-encoding finders / decoders / classifier / IOC extraction live in
  //  the `src/decoders/*.js` modules attached via Object.assign.)
  // ════════════════════════════════════════════════════════════════════════

  /**
   * Build a finding for a candidate that exceeded the recursion-depth limit.
   * Prevents a TypeError when maxRecursionDepth is breached.
   */
  _makeDepthExceededFinding(candidate, depth) {
    return {
      type: 'encoded-content',
      severity: 'info',
      encoding: candidate.type,
      offset: candidate.offset,
      length: candidate.length,
      decodedSize: 0,
      decodedBytes: null,
      chain: [candidate.type, 'depth-exceeded'],
      classification: { type: null, ext: null },
      entropy: 0,
      hint: `Recursion depth limit exceeded (depth ${depth})`,
      iocs: [],
      innerFindings: [],
      autoDecoded: false,
      canLoad: false,
      snippet: candidate.raw ? candidate.raw.substring(0, 120) : '',
    };
  }

  /**
   * Process a text-encoding candidate (Base64/Hex/Base32 + secondary family).
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
}
