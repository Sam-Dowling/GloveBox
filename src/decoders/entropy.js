// ════════════════════════════════════════════════════════════════════════════
// entropy.js — Entropy / decode-validation utilities + classification &
// severity for the encoded-content detector.
//
// Hosts:
//   * `_shannonEntropyString` / `_shannonEntropyBytes` — Shannon entropy
//     calculators used by the candidate finders to gate Base64/hex/Base32.
//   * `_tryDecodeUTF8` / `_isValidUTF8` / `_tryDecodeUTF16LE` — best-effort
//     text decoders that reject blobs containing >10 % control chars (filters
//     out random binary that just happens to be valid UTF-8 byte-wise).
//   * `_classify` — magic-byte / text-signature lookup over the static
//     `MAGIC_BYTES` and `TEXT_SIGNATURES` tables (declared on the host class).
//   * `_assessSeverity` — final severity tier ('high' / 'medium' / 'info')
//     derived from classification + IOCs found in decoded content.
//
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
// ════════════════════════════════════════════════════════════════════════════

Object.assign(EncodedContentDetector.prototype, {
  // ── Classification ────────────────────────────────────────────────────────

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
  },

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
  },

  // ── Entropy ────────────────────────────────────────────────────────────────

  _shannonEntropyString(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    const len = str.length;
    return -Object.values(freq).reduce((sum, f) => {
      const p = f / len;
      return sum + p * Math.log2(p);
    }, 0);
  },

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
  },

  // ── Text decoders ─────────────────────────────────────────────────────────

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
  },

  _isValidUTF8(bytes) {
    return this._tryDecodeUTF8(bytes) !== null;
  },

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
  },
});
