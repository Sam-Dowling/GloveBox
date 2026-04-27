// ════════════════════════════════════════════════════════════════════════════
// base64-hex.js — Candidate finders + decoders for Base64, Hex (continuous,
// `\xNN` escape sequences, PowerShell `0x..,0x..` byte arrays) and Base32.
// Extracted from `encoded-content-detector.js`.
//
// Each `_findX*Candidates()` returns objects of shape:
//   { type, raw, offset, length, entropy, confidence, hint, autoDecoded }
// to be consumed by `_processCandidate()` in the host class.
//
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
// ════════════════════════════════════════════════════════════════════════════

Object.assign(EncodedContentDetector.prototype, {
  // ── Finders ────────────────────────────────────────────────────────────────

  _findBase64Candidates(text, context) {
    // Bruteforce ("kitchen sink") mode runs over analyst-selected
    // regions which are often only a few dozen chars; the 40-char gate
    // and the per-candidate whitelist filters (data: / PEM / CSS-font
    // / MIME-body) are exactly what stops short inputs from ever
    // surfacing. Bypass both — every plausible Base64 / hex run gets
    // a chance to decode. Aggressive mode (`_aggressive` only, set
    // implicitly when bruteforce is on) is a softer relaxation.
    const minLen = this._bruteforce ? 4 : (this._aggressive ? 16 : 40);
    if (!text || text.length < minLen) return [];
    const candidates = [];

    // Standard Base64 (including URL-safe variant). The {N,} length
    // floor is interpolated so bruteforce mode catches `aGk=` (4 chars
    // → "hi") that the default 40-char gate would silently drop.
    /* safeRegex: builtin */
    const b64Re = new RegExp(`[A-Za-z0-9+\\/\\-_]{${minLen},}={0,2}`, 'g');
    let m;
    while ((m = b64Re.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;

      const raw = m[0];
      const offset = m.index;

      // ── Whitelist filters ──  (skipped entirely in bruteforce mode)
      if (!this._bruteforce) {
        if (this._isDataURI(text, offset)) continue;
        if (this._isPEMBlock(text, offset)) continue;
        if (this._isCSSFontData(text, offset)) continue;
        if (this._isMIMEBody(text, offset, context)) continue;
      }

      // Reject compound identifiers (kebab-case, snake_case) that only
      // incidentally overlap with the Base64URL character set.
      // Real Base64 almost always contains +, /, or = padding; strings with
      // 3+ hyphens/underscores and none of those are programming identifiers.
      if (!/[+\/=]/.test(raw)) {
        const sepCount = (raw.match(/[-_]/g) || []).length;
        if (sepCount >= 3) continue;
      }

      // Determine confidence BEFORE entropy gate so high-confidence skips it
      const highConf = EncodedContentDetector.HIGH_CONFIDENCE_B64.find(h => raw.startsWith(h.prefix));
      const psContext = this._isPowerShellEncodedCommand(text, offset);

      // Entropy gate (skipped for high-confidence matches and in
      // bruteforce mode — short B64 like `aGk=` has entropy below the
      // 3.5 floor but is a perfectly valid candidate the analyst wants
      // to see decoded).
      const entropy = this._shannonEntropyString(raw);
      if (!highConf && !psContext && !this._bruteforce) {
        if (entropy < 3.5 || entropy > 5.8) continue;
      }

      // Reject if purely alphanumeric (no +, /, =, -, _) — likely an identifier
      // Exception: strings inside quotes (variable assignments in scripts) are
      // likely intentional encoded payloads, not identifiers
      if (/^[A-Za-z0-9]+$/.test(raw) && raw.length < 200 && !highConf && !psContext && !this._bruteforce) {
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
        // Bruteforce mode auto-decodes everything so the analyst sees
        // results without hand-clicking each row.
        autoDecoded: !!(highConf || psContext) || this._bruteforce,
      });
    }

    return candidates;
  },

  _findHexCandidates(text, context) {
    // Bruteforce mode lowers the floor to 6 hex chars (3 bytes) and
    // skips the GUID / hash-length whitelist filters. Aggressive mode
    // halves the default 32-char gate for selection-driven decode of
    // medium-length runs.
    const minLen = this._bruteforce ? 6 : (this._aggressive ? 16 : 32);
    if (!text || text.length < minLen) return [];
    const candidates = [];

    // Continuous hex strings
    /* safeRegex: builtin */
    const hexContRe = new RegExp(`(?:0x)?([0-9a-fA-F]{${minLen},})`, 'g');
    let m;
    while ((m = hexContRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[1]; // just the hex digits
      const offset = m.index;
      if (raw.length % 2 !== 0) continue; // must be even

      // Whitelist: skip known hash lengths and GUIDs (skipped in
      // bruteforce mode — analyst selecting a UUID-shaped value still
      // wants to see the byte-decoded result).
      if (!this._bruteforce) {
        if (this._isHashLength(raw)) continue;
        if (this._isGUID(text, offset)) continue;
      }

      // Check for high-confidence: starts with PE header hex or common shellcode
      const startsWithMZ = /^4d5a/i.test(raw);
      const startsWithShellcode = /^(fc4883|fc4889|e8[0-9a-f]{6}00|31c0|33c0)/i.test(raw);
      const isHighConf = startsWithMZ || startsWithShellcode;

      const entropy = this._shannonEntropyString(raw);
      // Hex has a natural max entropy of log2(16)=4.0, so upper bound
      // must allow that. Bruteforce mode skips the entropy gate for
      // the same reason as Base64.
      if (!isHighConf && !this._bruteforce && (entropy < 2.5 || entropy > 4.2)) continue;

      candidates.push({
        type: 'Hex',
        raw,
        offset,
        length: raw.length,
        entropy,
        confidence: isHighConf ? 'high' : 'normal',
        hint: startsWithMZ ? 'PE executable header (4D5A)' : (startsWithShellcode ? 'Shellcode prologue' : null),
        autoDecoded: isHighConf || this._bruteforce,
      });
    }

    // Escaped hex sequences: \x4d\x5a...
    // Bruteforce mode lowers the floor from 16 escapes to 2 — `\x48\x69`
    // ("Hi") is a perfectly valid candidate.
    const hexEscMin = this._bruteforce ? 2 : (this._aggressive ? 8 : 16);
    /* safeRegex: builtin */
    const hexEscRe = new RegExp(`(?:\\\\x[0-9a-fA-F]{2}){${hexEscMin},}`, 'g');
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
    const psByteMin = this._bruteforce ? 2 : (this._aggressive ? 8 : 16);
    /* safeRegex: builtin */
    const psByteRe = new RegExp(`(?:0x[0-9a-fA-F]{2},?\\s*){${psByteMin},}`, 'g');
    while ((m = psByteRe.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      const hexOnly = [...raw.matchAll(/0x([0-9a-fA-F]{2})/gi)].map(x => x[1]).join('');
      const psHexMin = this._bruteforce ? 4 : 32;
      if (hexOnly.length < psHexMin) continue;
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
  },

  _findBase32Candidates(text, context) {
    if (!text || text.length < 40) return [];
    const candidates = [];

    const b32Re = /[A-Z2-7]{40,}={0,6}/g;
    let m;
    while ((m = b32Re.exec(text)) !== null) {
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      const offset = m.index;

      // Base32 is low-frequency — require contextual evidence (skipped
      // in bruteforce mode).
      if (!this._bruteforce && !this._hasBase32Context(text, offset)) continue;

      const entropy = this._shannonEntropyString(raw);
      if (!this._bruteforce && (entropy < 3.0 || entropy > 5.0)) continue;

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
  },

  // ── Decoders ──────────────────────────────────────────────────────────────

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
  },

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
  },

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
  },
});
