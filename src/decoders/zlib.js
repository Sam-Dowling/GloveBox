// ════════════════════════════════════════════════════════════════════════════
// zlib.js — Embedded compressed-blob detection + eager decompression for the
// encoded-content detector.
//
// Hosts:
//   * `_findCompressedBlobCandidates(bytes, context)` — magic-byte scan for
//     gzip (0x1F 0x8B), zlib (0x78 0x9C / 0x01 / 0xDA / 0x5E with header
//     checksum gate per RFC 1950 §2.2) and embedded ZIP (PK\x03\x04). Skips
//     ZIP-based container formats whose internal local-file headers are
//     structure rather than payload.
//   * `_processCompressedCandidate(candidate, rawBytes)` — validates ZIP
//     candidates by attempting `JSZip.loadAsync`, eagerly decompresses
//     gzip/zlib via `Decompressor.tryAll`, and returns either a populated
//     finding (with classification + IOCs from the decompressed bytes) or
//     `null` to prune false positives.
//
// External deps (provided by the host bundle / worker):
//   `JSZip`, `Decompressor`, plus `_classify` / `_shannonEntropyBytes` /
//   `_extractIOCsFromDecoded` / `_assessSeverity` / `_isValidUTF8` from the
//   sibling decoder modules.
//
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
// ════════════════════════════════════════════════════════════════════════════

Object.assign(EncodedContentDetector.prototype, {
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

        // Zlib header checksum (RFC 1950 §2.2): first two bytes as a
        // big-endian uint16 must be divisible by 31.  This cheaply prunes
        // random byte sequences that accidentally start with 0x78.
        if (sig.format === 'zlib') {
          const check = (bytes[i] << 8) | bytes[i + 1];
          if (check % 31 !== 0) continue;
        }

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
  },

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
    let eagerAttempted = false;
    if (rawBytes && typeof Decompressor !== 'undefined') {
      eagerAttempted = true;
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
        // Decompression failed — fall through
      }
    }

    // If eager decompression was attempted but produced nothing, the magic
    // bytes were a false positive — prune it instead of showing a useless
    // "Decompress & Analyse" entry that will also fail.
    if (eagerAttempted) return null;

    // Fallback: mark for lazy decompression only when Decompressor was unavailable
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
  },
});
