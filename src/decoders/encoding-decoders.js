// ════════════════════════════════════════════════════════════════════════════
// encoding-decoders.js — `_decodeCandidate` dispatch + per-encoding decoders
// for the secondary encoding family.
//
// `_decodeCandidate` is the single switch dispatched by `_processCandidate`.
// All cases ultimately produce a `Uint8Array` (or `null` on failure) that is
// then handed to `_classify` / `_extractIOCsFromDecoded`. Bare-string
// `candidate.type` values are intentional — they are the candidate-internal
// labels chosen by the finders, NOT IOC types (those use `IOC.*` constants
// elsewhere — see Build Gate B2).
//
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
// ════════════════════════════════════════════════════════════════════════════

Object.assign(EncodedContentDetector.prototype, {
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
  },

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
  },

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
  },

  _decodeUnicodeEscapes(str) {
    try {
      const decoded = str.replace(/\\u([0-9a-fA-F]{4})/gi, (_, hex) =>
        String.fromCharCode(parseInt(hex, 16))
      );
      return new TextEncoder().encode(decoded);
    } catch (_) { return null; }
  },

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
  },

  _decodeOctalEscapes(str) {
    try {
      const decoded = str.replace(/\\([0-3]?[0-7]{1,2})/g, (_, oct) =>
        String.fromCharCode(parseInt(oct, 8))
      );
      return new TextEncoder().encode(decoded);
    } catch (_) { return null; }
  },

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
  },

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
  },

  _decodeRot13(str) {
    try {
      const decoded = str.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
      });
      return new TextEncoder().encode(decoded);
    } catch (_) { return null; }
  },

  _decodeSplitJoin(str, separator) {
    try {
      if (!separator) separator = ' ';
      const decoded = str.split(separator).join('');
      return new TextEncoder().encode(decoded);
    } catch (_) { return null; }
  },
});
