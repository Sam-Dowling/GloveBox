// ════════════════════════════════════════════════════════════════════════════
// encoding-finders.js — Candidate finders for the "secondary" encoding family
//. One finder per technique; each emits the same candidate
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
//   * JS `\xHH` hex-escape sequences inside string literals
//   * Reverse-string transforms (`.reverse()`, `[-1..-n]`, `[::-1]`)
//   * Literal string-concat assembly (`'foo'+'bar'+'baz'`)
//   * Token-spaced obfuscation (`W  r  i  t  e  -  O  u  t  p  u  t`)
//   * Identifier-split-by-comments (`console /* x */ . /* y */ log /* z */ (…)`)
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
      throwIfAborted();
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
      throwIfAborted();
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
      throwIfAborted();
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
      throwIfAborted();
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
      throwIfAborted();
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
      throwIfAborted();
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
      throwIfAborted();
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
      throwIfAborted();
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
      throwIfAborted();
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
    // Match: = N,N,N,N,N,... with 10+ entries in printable ASCII range.
    //
    // The previous form anchored to `\s*$` (multiline EOL), which silently
    // dropped the very common one-liner shape
    //   $chars = 87,114,105,…,100; iex ([string]::Join('', [char[]]$chars))
    // because the `; iex …` after the array meant the run never reached EOL.
    // Allow any non-digit terminator (`;`, `)`, `]`, whitespace, EOL).
    const bareArrayRe = /=\s*(\d{1,3}(?:\s*,\s*\d{1,3}){9,})(?=\s*(?:[;)\]\r\n]|$))/g;
    while ((m = bareArrayRe.exec(text)) !== null) {
      throwIfAborted();
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
      throwIfAborted();
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
      throwIfAborted();
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
      throwIfAborted();
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
      throwIfAborted();
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
      throwIfAborted();
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
      throwIfAborted();
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
    //
    // Inner-class quantifier capped at 400 to prevent quadratic backtracking
    // on adversarial inputs full of long quoted strings (the previous open
    // `{10,}` form scanned every quoted blob in the file, then ran the
    // `hasRot13Context` window scan against each one — quadratic for
    // megabyte-scale inputs).
    const rot13PatternRe = /["']([a-zA-Z][a-zA-Z0-9\s.()\\/"'!@#$%^&*\-_+=:;,<>?{}[\]|~`]{10,400})["']\s*[;,)]/g;

    let m;
    while ((m = rot13PatternRe.exec(text)) !== null) {
      throwIfAborted();
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
      throwIfAborted();
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
      throwIfAborted();
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

  /**
   * JS `\xHH` hex-escape sequences inside string literals.
   *   "\x48\x65\x6c\x6c\x6f"   →   "Hello"
   *
   * The base64-hex finder catches `\xNN` runs of ≥ 16 entries inside ANY
   * source position (including outside quotes), but the much more common
   * malware shape is a string of 4–15 escapes embedded inside an
   * `eval(…)` / `Function(…)` / `IEX(…)` argument with extra quoted
   * fragments before/after. This finder targets that case: ≥ 4 contiguous
   * `\xNN` escapes anywhere in the text. Lower threshold than the
   * base64-hex variant because the value here is in catching short
   * obfuscated method/property names (`window["\x63\x6f…"]`) that the
   * 16-escape gate misses entirely.
   *
   * The aggressive-mode (selection-decode) variant lowers the threshold
   * further to 2 escapes — the user has already opted into the noise.
   */
  _findJsHexEscapeCandidates(text, context) {
    if (!text || text.length < 12) return [];
    const candidates = [];
    const minRun = this._aggressive ? 2 : 4;
    const re = new RegExp(`(?:\\\\x[0-9a-fA-F]{2}){${minRun},}`, 'g');
    let m;
    while ((m = re.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      // Skip if the base64-hex finder will already match this run (≥ 16
      // escapes is its threshold) — avoids duplicate findings on the
      // long-form shellcode case.
      const escapeCount = raw.length / 4; // each \xNN = 4 chars
      if (!this._aggressive && escapeCount >= 16) continue;
      candidates.push({
        type: 'JS Hex Escape',
        raw,
        offset: m.index,
        length: raw.length,
        entropy: 0,
        confidence: 'high',
        hint: `JS \\xHH escape sequence (${escapeCount} bytes)`,
        autoDecoded: true,
      });
    }
    return candidates;
  },

  /**
   * Reverse-string transforms.
   *   PowerShell: $s[-1..-$s.Length] -join ''
   *               $s[-1..-($s.Length)] -join ''
   *   JS:         […].reverse().join('')
   *               s.split('').reverse().join('')
   *   Python:     s[::-1]
   *
   * Strategy: find a quoted string literal in close proximity (±200 chars)
   * to a reverse-operator marker, reverse it, and check whether the
   * reversed form contains an execution-intent keyword. If yes, emit the
   * REVERSED string as a "Reversed" candidate that gets re-fed through
   * the candidate pipeline (so the reversed Base64 / hex / etc. is
   * picked up by recursion).
   */
  _findReverseStringCandidates(text, context) {
    if (!text || text.length < 20) return [];
    const candidates = [];

    // Trigger patterns — any of these in the surrounding context flags
    // a quoted string nearby as a reverse-decode candidate.
    const reverseMarkers = [
      /\[-1\.\.-(?:\$?[a-zA-Z_][\w]*\.Length|\d+|\([^)]*\))\]\s*-join/i, // PS: $s[-1..-$s.Length] -join
      /\.reverse\s*\(\s*\)\s*\.\s*join\s*\(/i,                            // JS: .reverse().join(
      /\.split\s*\(\s*['"]['"]\s*\)\s*\.\s*reverse\s*\(/i,                 // JS: .split('').reverse(
      /\[\s*::\s*-\s*1\s*\]/,                                               // Py: s[::-1]
      /\breversed\s*\(/i,                                                   // Py: reversed("…") / reversed(s)
      /\bstrrev\s*\(/i,                                                     // PHP / Perl
    ];

    // Find quoted literals (single or double quotes), 8..400 chars.
    const quotedRe = /["']([^"'\\\n\r]{8,400})["']/g;
    let m;
    while ((m = quotedRe.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[1];
      const offset = m.index;

      // Look ±200 chars either side for any reverse-marker.
      const winStart = Math.max(0, offset - 200);
      const winEnd   = Math.min(text.length, offset + raw.length + 200);
      const region   = text.substring(winStart, winEnd);
      const hasMarker = reverseMarkers.some(rx => rx.test(region));
      if (!hasMarker) continue;

      // Reverse the literal.
      const reversed = [...raw].reverse().join('');
      // Plausibility: the reversed form should look textual (printable
      // ASCII, no NULs) AND either contain an exec keyword OR look like
      // a Base64 / hex blob the recursion can pick up.
      if (!/^[\x20-\x7E]{8,}$/.test(reversed)) continue;
      const looksExec = /(eval|exec|invoke|iex|console|alert|powershell|cmd\.exe|http|shell|write|import|require|fromCharCode)/i.test(reversed);
      const looksB64  = /^[A-Za-z0-9+\/=_\-]{20,}$/.test(reversed);
      const looksHex  = /^[0-9a-fA-F]{20,}$/.test(reversed);
      if (!(looksExec || looksB64 || looksHex)) continue;

      candidates.push({
        type: 'Reversed',
        raw: reversed,                  // store the ALREADY-REVERSED text
        offset,
        length: raw.length + 2,         // +2 for the quotes
        entropy: 0,
        confidence: 'high',
        hint: 'Reverse-string transform (reversed candidate fed to decoder pipeline)',
        autoDecoded: true,
      });
    }
    return candidates;
  },

  /**
   * Literal string-concatenation assembly.
   *   ('Inv'+'oke'+'-Exp'+'ression')   →   "Invoke-Expression"
   *   "Po" + "wer" + "Shell"            →   "PowerShell"
   *
   * Detects ≥ 3 quoted-string fragments joined by `+` (JS/PS) and emits
   * the assembled string as a "String Concat" candidate. The recursion
   * then re-feeds the assembled text through every other finder so a
   * `('TVqQ'+'AAMA…')` chain ends up classified as Base64 → PE.
   *
   * Lives as a SECONDARY finder (subject to the wall-clock budget) so
   * adversarial inputs full of harmless string-concat in normal code can
   * never blow the worker budget.
   */
  _findStringConcatCandidates(text, context) {
    if (!text || text.length < 20) return [];
    const candidates = [];
    const minFrags = this._aggressive ? 2 : 3;

    // Match 3+ quoted fragments joined by + (allow single OR double quotes).
    // Cap each fragment at 80 chars to keep regex backtracking bounded.
    // We capture the WHOLE chain and post-process out the literal pieces.
    // Built via `new RegExp(...)` because the `{minFrags - 1},` repetition
    // bound is dynamic (varies with this._aggressive).
    const reSrc = `(?:["'][^"'\\\\\\n\\r]{0,80}["']\\s*\\+\\s*){${minFrags - 1},}["'][^"'\\\\\\n\\r]{0,80}["']`;
    const re = new RegExp(reSrc, 'g');

    let m;
    while ((m = re.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      // Pull every literal fragment out (single OR double quoted).
      const fragRe = /["']([^"'\\\n\r]{0,80})["']/g;
      const parts = [];
      let f;
      while ((f = fragRe.exec(raw)) !== null) parts.push(f[1]);
      if (parts.length < minFrags) continue;
      const assembled = parts.join('');
      // Plausibility — at least 6 chars, mostly printable, and either
      // contains an exec keyword OR looks like a Base64 / hex blob the
      // recursion can pick up.
      if (assembled.length < 6) continue;
      if (!/^[\x20-\x7E]{6,}$/.test(assembled)) continue;
      // Plausibility regex includes Python wrapper-side keywords (`print`,
      // `raise`, `os.system`) so chains like `exec("pri" + "nt" +
      // "('Hello, World!')")` — where the assembled fragments form
      // `print('Hello, World!')` — pass the gate. Without `print`, the
      // assembled side is rejected and the chain is silently dropped.
      const looksExec = /(eval|exec|invoke|iex|console|alert|powershell|cmd\.exe|http|shell|write|import|require|fromCharCode|Output|Download|print|raise|os\.system|subprocess|popen)/i.test(assembled);
      const looksB64  = /^[A-Za-z0-9+\/=_\-]{20,}$/.test(assembled);
      const looksHex  = /^[0-9a-fA-F]{20,}$/.test(assembled);
      // In normal mode require one of the strong signals; in aggressive
      // mode (selection-decode) accept any printable assembly.
      if (!this._aggressive && !(looksExec || looksB64 || looksHex)) continue;

      candidates.push({
        type: 'String Concat',
        raw: assembled,
        offset: m.index,
        length: m[0].length,
        entropy: 0,
        confidence: looksExec ? 'high' : 'normal',
        hint: `Literal string concatenation (${parts.length} fragments)`,
        autoDecoded: true,
      });
    }
    return candidates;
  },

  /**
   * Token-spaced obfuscation — every printable character separated by 1+
   * spaces, with no Split-Join wrapper.
   *
   *   `W  r  i  t  e   -  O  u  t  p  u  t     ' H e l l o     W o r l d '`
   *
   * Distinct from `_findSplitJoinCandidates` (which requires an explicit
   * `.split(' ').join('')` reassembly call) and from
   * `_findSpaceDelimitedHexCandidates` (which operates on `[0-9a-fA-F]`
   * pairs). This finder targets the bare token-spacing trick where the
   * attacker relies on the analyst's eye to read the characters but the
   * obfuscation breaks string-search and naive grep-based detections.
   *
   * Strategy: scan whole lines. A line qualifies when ≥ 70 % of its
   * non-whitespace characters are themselves single characters separated
   * from each-other by ≥ 1 space (i.e. the run-length of single-char
   * tokens is at least 16, and the line has ≤ 2 tokens longer than 1
   * char). Collapse the spaces (preserving multi-space gaps as a single
   * literal space — the token-spacing trick uses double-spaces to encode
   * a real space) and re-emit. The recursion driver then re-feeds the
   * collapsed text through every other finder, so a token-spaced Base64
   * payload still gets classified as Base64.
   *
   * Threshold tuned to avoid matching ASCII-art and prose with
   * occasional initialisms (`U S A`, `F B I`) — those are very rarely
   * 16+ tokens long and rarely span ≥ 70 % of a line.
   */
  _findSpacedTokenCandidates(text, context) {
    if (!text || text.length < 24) return [];
    const candidates = [];

    // Scan line-by-line so the regex backtracking is bounded by line
    // length, not file length. The split() materialises the array once
    // — fine for the multi-MB input cap enforced by the secondary
    // finder budget.
    const lines = text.split(/\r?\n/);
    let cursor = 0;
    const minTokens = this._aggressive ? 8 : 16;

    for (let li = 0; li < lines.length; li++) {
      const line = lines[li];
      // Walk forward to the next line; record this line's offset.
      const lineOffset = cursor;
      cursor += line.length + 1; // +1 for the consumed \n

      if (line.length < minTokens * 2) continue;
      // Tokenise on whitespace runs so multi-space gaps stay attached to
      // their word boundaries — we use the raw whitespace runs as
      // sentinels for "real" spaces in the cleartext. A double-space
      // between two single-char tokens becomes one space; a single-space
      // becomes nothing.
      const trimmed = line.replace(/^\s+|\s+$/g, '');
      if (trimmed.length < minTokens * 2) continue;

      // Quick reject: if the trimmed line has any sequence of 4+
      // non-whitespace chars, it's almost certainly normal code/prose
      // (the spaced-token form is by definition all 1-char tokens).
      // Allow ONE such "long" run (a quoted phrase ' H e l l o ' counts
      // as a single 8-char token after the prelim split because the
      // outer quotes hug whitespace on each side); cap at two for the
      // aggressive path.
      const longRunCap = this._aggressive ? 3 : 2;
      const longRuns = (trimmed.match(/\S{4,}/g) || []).length;
      if (longRuns > longRunCap) continue;

      // Tokenise on whitespace; count single-char tokens.
      const toks = trimmed.split(/\s+/);
      if (toks.length < minTokens) continue;
      const singleCount = toks.filter(t => t.length === 1).length;
      if (singleCount < minTokens) continue;
      if (singleCount < toks.length * 0.7) continue;

      // Reject lines that are mostly digits (tabular numeric data).
      const digitTokens = toks.filter(t => /^\d$/.test(t)).length;
      if (digitTokens > toks.length * 0.5) continue;

      // Collapse: walk the trimmed line, copying every non-space
      // character; collapse runs of 2+ consecutive spaces to a single
      // space (the encoded form uses 2+ spaces to mean "real space"),
      // and drop runs of exactly 1 space (the inter-character padding).
      let collapsed = '';
      for (let i = 0; i < trimmed.length; ) {
        const ch = trimmed[i];
        if (ch === ' ' || ch === '\t') {
          let runLen = 0;
          while (i < trimmed.length && (trimmed[i] === ' ' || trimmed[i] === '\t')) {
            runLen++;
            i++;
          }
          if (runLen >= 2) collapsed += ' ';
          // runLen === 1 → drop (it's just inter-character padding)
        } else {
          collapsed += ch;
          i++;
        }
      }

      if (collapsed.length < 8) continue;
      if (!/^[\x20-\x7E]{8,}$/.test(collapsed)) continue;

      // Plausibility — the collapsed result should look like a real
      // command, URL, or known-suspicious shape. We deliberately mirror
      // the keyword set used elsewhere (string-concat / reversed) so a
      // benign spaced phrase like "T h i s   i s   a   t e s t"
      // doesn't generate a finding.
      const looksCmd = /(write-output|write-host|invoke|iex|powershell|cmd\.exe|console|eval|exec|http:|https:|shell|net\.webclient|frombase64string|downloadstring|downloadfile|new-object|start-process)/i.test(collapsed);
      if (!this._aggressive && !looksCmd) continue;

      // Offset = start of the line plus its leading-whitespace run, so
      // the sidebar's source-anchor click lands on the first encoded
      // character (not on the indentation).
      const leadingWs = line.length - line.replace(/^\s+/, '').length;
      candidates.push({
        type: 'Spaced Tokens',
        raw: collapsed,                 // store the ALREADY-COLLAPSED text
        offset: lineOffset + leadingWs,
        length: trimmed.length,
        entropy: 0,
        confidence: looksCmd ? 'high' : 'normal',
        hint: `Token-spaced obfuscation (${toks.length} tokens)`,
        autoDecoded: true,
      });
      if (candidates.length >= this.maxCandidatesPerType) break;
    }
    return candidates;
  },

  /**
   * Identifier-split-by-comments deobfuscation.
   *
   *   `/* *\/ console /* obf *\/ . /* layer *\/ log /* test *\/ ("Hello World")`
   *
   * No existing finder targets `<ident> /* … *\/ <op> /* … *\/ <ident>` runs.
   * The token sequence reads as ordinary code with comments, so renderers
   * never strip comments before scanning (intentionally — comments can
   * carry payload). This finder targets the specific shape: an identifier
   * followed by ≥ 2 alternations of `<C-style comment> <op> <ident>` and
   * a trailing call/index, where `<op>` is `.`, `[`, or `(`.
   *
   * Strategy:
   *   1. Anchored regex captures the whole run (≤ 240 chars to bound
   *      backtracking; comment body is non-greedy so a stray `**` can't
   *      blow the engine).
   *   2. Strip every `/* … *\/` from the captured run.
   *   3. Plausibility gate: the stripped form must contain one of the
   *      execution-intent keywords; otherwise the finding is dropped
   *      (legitimate JSDoc-decorated method chains pass the regex but
   *      not this gate).
   *
   * The decoder is the trivial UTF-8 passthrough already used for
   * Reversed / String Concat / Spaced Tokens — recursion in
   * `_processCandidate` re-feeds the stripped text through every other
   * finder so an `eval(…)` argument that itself contains a Base64 /
   * char-array layer collapses one ply per round.
   *
   * In aggressive mode (selection-decode) the exec-keyword gate is
   * dropped — the analyst has already opted into the noise.
   */
  _findCommentObfuscationCandidates(text, context) {
    if (!text || text.length < 24) return [];
    const candidates = [];
    // ≥ 2 comment-separated `<op> <ident>` alternations, optional
    // trailing comment + open paren / bracket. Length-capped at 240 to
    // bound backtracking on adversarial inputs.
    const re = /\b[a-zA-Z_$][\w$]{0,40}\s*(?:\/\*[^*]{0,200}?\*\/\s*[.\[(]\s*[a-zA-Z_$][\w$]{0,40}\s*){2,}(?:\/\*[^*]{0,200}?\*\/\s*)?[(\[]/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      throwIfAborted();
      if (candidates.length >= this.maxCandidatesPerType) break;
      const raw = m[0];
      if (raw.length > 240) continue;
      // Strip every `/* … */` block, then collapse the residual
      // whitespace runs so the assembled token sequence reads as code.
      const stripped = raw.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\s+/g, '');
      if (stripped.length < 6) continue;
      if (!/^[\x20-\x7E]{6,}$/.test(stripped)) continue;
      // Plausibility — gate on execution-intent keywords. Without this
      // the finder false-positives on legitimate JSDoc-heavy method
      // chains (`fooClient /* @returns Foo */ . /* see #42 */ get(...)`).
      const looksExec = /(console|alert|eval|exec|invoke|iex|fetch|XMLHttpRequest|WScript|Shell\.Application|document|window|new\s+Function)/i.test(stripped);
      if (!this._aggressive && !looksExec) continue;
      candidates.push({
        type: 'Comment-Stripped',
        raw: stripped,                  // store the ALREADY-STRIPPED text
        offset: m.index,
        length: raw.length,
        entropy: 0,
        confidence: looksExec ? 'high' : 'normal',
        hint: 'Identifier-split-by-comments deobfuscation',
        autoDecoded: true,
      });
    }
    return candidates;
  },
});
