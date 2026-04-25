// ════════════════════════════════════════════════════════════════════════════
// encoding-finders.js — Candidate finders for the "secondary" encoding family
// (PLAN Track E2). One finder per technique; each emits the same candidate
// object shape consumed by `_processCandidate()`:
//
//   { type, raw, offset, length, entropy, confidence, hint, autoDecoded, … }
//
// Covers:
//   * URL percent-encoding (`%70%6F%77…`)
//   * HTML decimal & hex entities (`&#112;` / `&#x70;`)
//   * Unicode escapes (`\u0070`)
//   * Decimal char arrays — JS `[…]`, `String.fromCharCode(…)`, VBS `Chr/W`,
//     PowerShell `[char]`, PowerShell `@(…)`, bare `= n,n,n`, Python `chr()`,
//     Python `bytes([…])`, Perl `chr().chr()`
//   * Octal escapes (`\160\157\167…`)
//   * Microsoft Script Encoder (`#@~^…^#~@`)
//   * Space/colon/dash-delimited hex (`57 72 69 74…`)
//   * ROT13 (only when the surrounding code mentions ROT13 / charCodeAt+13)
//   * `.split('X').join('')` / `-split 'X' -join ''` reassembly
//
// Each finder caps results at `this.maxCandidatesPerType` to bound runtime on
// large inputs. Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
// ════════════════════════════════════════════════════════════════════════════

Object.assign(EncodedContentDetector.prototype, {
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
  },

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
  },

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
  },

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
  },

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
  },

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
  },

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
  },

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
  },

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
  },
});
