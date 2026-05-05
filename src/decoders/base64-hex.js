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
    // Default-mode floor raised 40→64 to clear the cliff above webpack
    // chunk hashes / source-map keys / asset cache busters that crowd
    // 40-50 char range. High-confidence prefix matches (TVqQ MZ etc.)
    // and PowerShell -EncodedCommand context still trigger at the lower
    // 24-char gate via the high-confidence rescue pass at the bottom of
    // this function (see "High-confidence rescue pass" below).
    const minLen = this._bruteforce ? 4 : (this._aggressive ? 16 : 64);
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
          // (e.g. hex digits, another base64 layer), it's real encoded content.
          // Tightened: in default mode require either an exec-intent keyword
          // hit or that the speculatively-decoded text is itself another
          // long encoded run (≥20 chars of hex / Base64 / Base32). Stops
          // compound IDs that decode to other compound IDs from sneaking
          // through the printable-only gate.
          const specDec = this._decodeBase64(raw);
          const specText = specDec && this._tryDecodeUTF8(specDec);
          const isPrintable = specText && specText.length > 16 &&
            /^[\x20-\x7E\r\n\t]{16,}$/.test(specText.substring(0, Math.min(64, specText.length)));
          let looksTextual = isPrintable;
          if (looksTextual && !this._aggressive && !this._bruteforce) {
            const stricter = _EXEC_INTENT_RE.test(specText)
              || /[A-Za-z0-9+\/]{20,}={0,2}/.test(specText)
              || /[0-9a-fA-F]{20,}/.test(specText)
              || /[A-Z2-7]{20,}={0,6}/.test(specText);
            looksTextual = stricter;
          }
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
        hint: highConf ? highConf.desc : (psContext ? 'PowerShell encoded string' : null),
        // Bruteforce mode auto-decodes everything so the analyst sees
        // results without hand-clicking each row.
        autoDecoded: !!(highConf || psContext) || this._bruteforce,
      });
    }

    // ── High-confidence rescue pass (default mode only) ─────────────
    //
    // The default-mode floor is 64 chars to suppress webpack chunk
    // hashes and similar 40-50-char identifier noise. But that floor
    // also silently drops short Base64 strings inside known-malicious
    // contexts: a recursive PowerShell `[Convert]::FromBase64String('…')`
    // chain whose inner B64 has shrunk to ~30-50 chars, or a shellcode
    // string starting with `TVqQ`/`fc4883` that's only 40 chars long.
    //
    // This second pass scans at minLen=24 but ONLY emits candidates
    // that satisfy `_isPowerShellEncodedCommand` (the `-EncodedCommand`
    // / `FromBase64String('...')` / `ConvertFrom-Base64` lookback) OR
    // start with one of the HIGH_CONFIDENCE_B64 prefixes. The same
    // whitelist filters as the main loop apply (data: URI, PEM,
    // CSS-font, MIME body) so we never re-emit suppressed noise.
    //
    // Bruteforce mode skips this pass — it already runs at minLen=4.
    // Aggressive mode skips because its minLen=16 already covers this
    // floor.  Only fires when default mode would otherwise miss the
    // candidate entirely.
    if (!this._bruteforce && !this._aggressive && minLen > 24) {
      const seenOffsets = new Set(candidates.map(c => c.offset));
      /* safeRegex: builtin */
      const rescueRe = new RegExp(`[A-Za-z0-9+\\/\\-_]{24,}={0,2}`, 'g');
      let rm;
      while ((rm = rescueRe.exec(text)) !== null) {
        if (candidates.length >= this.maxCandidatesPerType) break;
        if (seenOffsets.has(rm.index)) continue;
        const raw = rm[0];
        // Skip runs the main loop would already have emitted — only
        // strictly-shorter rescue candidates make it past.
        if (raw.length >= minLen) continue;
        const offset = rm.index;
        const psContext = this._isPowerShellEncodedCommand(text, offset);
        const highConf = EncodedContentDetector.HIGH_CONFIDENCE_B64.find(h => raw.startsWith(h.prefix));
        // AppleScript rescue: `set <var> to "<base64>"` followed (within
        // ≤ 2 KiB) by a `base64 -D|-d|--decode` pipeline referencing the
        // same var. The AppleScript char-code / property-binding
        // decoder (`applescript-obfuscation.js`) resolves the sink's
        // shell-command envelope (`echo … | base64 -D | bash`) but
        // doesn't recursively decode base64 inside resolved command
        // strings — so without this rescue pass, a 60-char base64
        // payload wrapped in `set b64 to "…"` sits below the 64-char
        // default-mode floor and no top-level Base64 finding emits.
        // IOCs embedded inside the decoded command (the real `curl
        // http://attacker.com/...` line) would only surface AFTER an
        // analyst clicks "Load for analysis" on the AppleScript sink.
        //
        // The gate is deliberately narrow: the candidate must be inside
        // a `"..."`-quoted AppleScript variable assignment AND the
        // same identifier must appear downstream in a `base64 -…` decode
        // context. Real-world FPs are unlikely because benign 24-64 char
        // quoted blobs are almost never followed by `base64 -D|-d`.
        const asCtx = this._isAppleScriptBase64DecodeVarContext(text, offset, raw);
        if (!psContext && !highConf && !asCtx) continue;
        // Same whitelist gates as the main loop.
        if (this._isDataURI(text, offset)) continue;
        if (this._isPEMBlock(text, offset)) continue;
        if (this._isCSSFontData(text, offset)) continue;
        if (this._isMIMEBody(text, offset, context)) continue;
        candidates.push({
          type: 'Base64',
          raw,
          offset,
          length: raw.length,
          entropy: this._shannonEntropyString(raw),
          confidence: 'high',
          hint: highConf ? highConf.desc
                         : psContext ? 'PowerShell encoded string'
                                     : 'AppleScript base64-decode variable',
          autoDecoded: true,
        });
      }
    }

    return candidates;
  },

  // Detect `set <var> to "<base64>"` + downstream
  // `<var> … base64 -D|--decode` usage on the same AppleScript file.
  // Used as a rescue trigger in `_findBase64Candidates` so base64
  // blobs smaller than the default-mode 64-char floor still emit as
  // high-confidence candidates when the surrounding AppleScript
  // context strongly implies "this base64 is decoded at runtime and
  // piped to a shell".
  //
  // Conservative predicate — both legs must match for the rescue to
  // fire:
  //   1. The candidate's byte before is `"`, and within the preceding
  //      ≤ 64 chars on the same line we find `set\s+(NAME)\s+to\s+"$`
  //   2. Within the following ≤ 2048 chars, we find NAME again in a
  //      context containing `base64\s+-(?:d|decode|D)`
  //
  // Returns `true` iff both conditions hold. No partial credit.
  _isAppleScriptBase64DecodeVarContext(text, offset, raw) {
    if (typeof text !== 'string' || offset < 1 || offset >= text.length) return false;
    // The candidate must be immediately preceded by `"` — i.e. the
    // base64 is the body of a string literal. Bail cheaply otherwise.
    if (text[offset - 1] !== '"') return false;
    const endOffset = offset + raw.length;
    if (endOffset >= text.length || text[endOffset] !== '"') return false;
    // Look backwards on the same line (up to 128 chars) for
    // `set\s+(NAME)\s+to\s+"`.
    const lineStart = Math.max(0, offset - 128);
    const preamble = text.substring(lineStart, offset - 1);
    /* safeRegex: builtin */
    const setRe = /(?:^|[\r\n])\s*set\s+([_A-Za-z][A-Za-z0-9_]{0,63})\s+to\s+$/;
    const m = setRe.exec(preamble);
    if (!m) return false;
    const varName = m[1];
    // Look forward up to 2 KiB for the variable reappearing in a
    // `base64 -D|-d|--decode` pipeline. This is structural, not a
    // strict dependency order — the decode may happen before the
    // string reference in the sink expression.
    const window = text.substring(endOffset + 1, Math.min(text.length, endOffset + 1 + 2048));
    if (!window.includes(varName)) return false;
    /* safeRegex: builtin */
    const decodeRe = /\bbase64\s+-(?:d|D|-decode|-Decode)\b/;
    return decodeRe.test(window);
  },

  _findHexCandidates(text, context) {
    // Bruteforce mode lowers the floor to 6 hex chars (3 bytes) and
    // skips the GUID / hash-length whitelist filters. Aggressive mode
    // halves the default 48-char gate for selection-driven decode of
    // medium-length runs.
    //
    // Default-mode floor raised 32→48 because 32-hex (16 bytes) is the
    // size of a wide range of benign identifiers (MD5, IPv6, color
    // runs concatenated). 48 hex digits / 24 bytes is past the noisy
    // band. High-conf MZ/shellcode prefixes still bypass the
    // post-match plausibility gate below.
    const minLen = this._bruteforce ? 6 : (this._aggressive ? 16 : 48);
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

      // Default-mode plausibility gate: hex finds without any of (high-
      // conf prefix, XOR context, exec-intent vocabulary in surrounding
      // ±200 chars, OR decoded bytes that look like printable text) are
      // overwhelmingly noise (cert fingerprints, hashes, identifier-like
      // runs that snuck past the GUID/hash whitelist). The "decoded
      // looks textual" branch is the recursion escape-hatch — a hex-
      // encoded URL inside Base64 has no surrounding exec context but
      // its bytes ARE printable ASCII and should still be picked up.
      // Aggressive (selection-driven) and bruteforce modes skip this.
      if (!isHighConf && !this._bruteforce && !this._aggressive) {
        const winStart = Math.max(0, offset - 200);
        const winEnd   = Math.min(text.length, offset + raw.length + 200);
        const window   = text.substring(winStart, winEnd);
        const ctxXor = (typeof this._hasXorContext === 'function')
          && this._hasXorContext(text, offset, raw);
        const ctxExec = _EXEC_INTENT_RE.test(window);
        let decodedTextual = false;
        if (!ctxXor && !ctxExec) {
          // Cheap speculative decode: if the bytes are predominantly
          // printable ASCII, the hex is likely a real text payload.
          try {
            const dec = this._decodeHex(raw);
            if (dec && dec.length >= 6) {
              let printable = 0;
              for (const b of dec) {
                if (b >= 0x20 && b <= 0x7E) printable++;
                else if (b === 0x09 || b === 0x0A || b === 0x0D) printable++;
              }
              if (printable >= dec.length * 0.85) decodedTextual = true;
            }
          } catch (_) { /* decode failed → treat as not textual */ }
        }
        if (!ctxXor && !ctxExec && !decodedTextual) continue;
      }

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
