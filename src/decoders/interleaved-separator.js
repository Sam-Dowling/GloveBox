// ════════════════════════════════════════════════════════════════════════════
// interleaved-separator.js — Periodicity-based de-interleaving finder.
//
// Detects obfuscation that interleaves a fixed separator between every
// real character so a string scanner / signature engine doesn't see the
// underlying token. Real-world examples:
//
//   $\x00W\x00C\x00=\x00N\x00e\x00w\x00-\x00O\x00b\x00j\x00E\x00c\x00T\x00
//                          ↓ strip every literal `\x00`
//   $WC=New-ObjEcT
//
//   a.b.c.d.e.f.g.h.i.j.k.l   →  abcdefghijkl   (S = '.')
//   N&#0;O&#0;P&#0;Q&#0;R     →  NOPQR          (S = '&#0;')
//
// The strategy is intentionally simple: walk the input, look for runs
// where every (k+stride)-th character is the same separator (or every
// (k+stride*sep_len)-th run of `sep_len` characters is the same literal
// separator), strip it, and emit the result as a candidate. The
// recursion driver in `_processCandidate` then re-feeds the stripped
// string through every other finder, so a Base64 / Hex / Reverse / etc.
// payload buried under the interleave still gets recovered.
//
// Plausibility gate (normal / aggressive mode):
//   • collapsed run must be ≥ 6 printable ASCII chars
//   • collapsed run must contain ≥ 3 ASCII letters OR an exec-keyword
//     (eval / iex / invoke / powershell / cmd / http / etc.)
// In bruteforce ("kitchen sink") mode both gates are dropped.
//
// Decoded value is the stripped UTF-8 string itself (already plain
// text), wrapped in a Uint8Array so the recursion driver and YARA
// engine can work with it in their canonical byte form.
//
// Mounted via `Object.assign(EncodedContentDetector.prototype, …)`.
// ════════════════════════════════════════════════════════════════════════════

Object.assign(EncodedContentDetector.prototype, {
  /**
   * Find runs where every Nth character (or every Nth fixed-width
   * literal) is the same separator.
   *
   * Returns objects of shape consumed by `_processCandidate`:
   *   { type: 'Interleaved Separator (…)',
   *     raw, offset, length, entropy, confidence, hint, autoDecoded:true }
   *
   * @param {string} text  Source text to scan.
   * @returns {Array}      Candidate objects (may be empty).
   */
  _findInterleavedSeparatorCandidates(text /* , context */) {
    if (!text || typeof text !== 'string') return [];
    const minLen = this._bruteforce ? 8 : (this._aggressive ? 16 : 24);
    if (text.length < minLen) return [];

    const candidates = [];

    // Tightened plausibility gate (default mode):
    //   • collapsed run must be ≥ 6 printable ASCII chars
    //   • collapsed run must contain ≥ 6 ASCII letters AND match
    //     `_EXEC_INTENT_RE` (LOLBin / cmdlet / URL vocabulary).
    // The previous `≥ 3 letters OR exec` gate fired 47 FPs on a single
    // benign bash binary (man-page-style help text in `.rodata` whose
    // multi-space column padding looked like a periodic stride-3/4
    // separator). Aggressive mode keeps the looser OR gate; bruteforce
    // mode bypasses everything.
    const _looksPlausible = (collapsed) => {
      if (this._bruteforce) return true;
      if (!collapsed || collapsed.length < 6) return false;
      // Must be mostly printable ASCII.
      const printable = (collapsed.match(/[\x20-\x7E]/g) || []).length;
      if (printable < collapsed.length * 0.85) return false;
      const letters = (collapsed.match(/[A-Za-z]/g) || []).length;
      if (this._aggressive) {
        // Aggressive: ≥ 3 letters OR exec keyword (legacy behaviour).
        if (letters >= 3) return true;
        return _EXEC_INTENT_RE.test(collapsed);
      }
      // Default mode: ≥ 6 letters AND exec keyword.
      if (letters < 6) return false;
      return _EXEC_INTENT_RE.test(collapsed);
    };

    // ── Pass 1: single-character separator at fixed stride ──────────
    // Walk the input and at each position try strides 2 (a.b.c…), 3
    // (ab.cd.ef…), and 4 (abc.def.ghi…) for any non-alphanumeric
    // separator byte. The separator is fixed across the whole run; we
    // accept the longest run we can grow from each starting position.
    const seenSpans = new Set();
    const tryStride = (i, stride) => {
      if (i + stride * 4 > text.length) return null;
      const sep = text.charCodeAt(i + stride - 1);
      // Reject if separator is an alnum or doesn't repeat at the
      // expected positions early on.
      if ((sep >= 0x30 && sep <= 0x39) || (sep >= 0x41 && sep <= 0x5A) || (sep >= 0x61 && sep <= 0x7A)) return null;
      // Run-length check: count how many strides repeat the separator.
      let runs = 1;
      let j = i + stride;
      while (j + stride - 1 < text.length && text.charCodeAt(j + stride - 1) === sep) {
        runs++;
        j += stride;
      }
      // Need at least 4 strides (≥ 4 real chars decoded).
      if (runs < 4) return null;
      const endExclusive = j;  // last stride didn't include separator past end
      const key = `${i}:${endExclusive}:${stride}`;
      if (seenSpans.has(key)) return null;
      // Build the collapsed string by taking (stride - 1) chars from
      // each block — i.e. everything except the trailing separator.
      let collapsed = '';
      for (let k = 0; k < runs; k++) {
        const blockStart = i + k * stride;
        for (let b = 0; b < stride - 1; b++) {
          collapsed += text[blockStart + b];
        }
      }
      // Tail: trailing chars after the last separator, if the run ends
      // with one more chunk lacking a separator.
      // (Already handled via endExclusive — we stopped before any
      //  partial block.)
      if (!_looksPlausible(collapsed)) return null;
      seenSpans.add(key);
      return { start: i, end: endExclusive, sep: String.fromCharCode(sep), stride, collapsed };
    };

    for (let i = 0; i < text.length - 8; i++) {
      // Skip whitespace-only starts; those almost never anchor a real
      // interleave and explode the candidate count on prose input.
      const c0 = text.charCodeAt(i);
      if (c0 === 0x20 || c0 === 0x09 || c0 === 0x0A || c0 === 0x0D) continue;
      for (const stride of [2, 3, 4]) {
        const hit = tryStride(i, stride);
        if (hit) {
          const sepDisp = hit.sep === '\u0000' ? '\\x00'
            : hit.sep === '\t' ? '\\t'
            : hit.sep === '\n' ? '\\n'
            : hit.sep === '\r' ? '\\r'
            : hit.sep;
          const raw = text.substring(hit.start, hit.end);
          candidates.push({
            type: `Interleaved Separator (${sepDisp})`,
            raw,
            offset: hit.start,
            length: hit.end - hit.start,
            entropy: this._shannonEntropyString(hit.collapsed),
            confidence: 'normal',
            hint: `Periodic separator '${sepDisp}' stride ${hit.stride} → ${hit.collapsed.length} char${hit.collapsed.length === 1 ? '' : 's'}`,
            autoDecoded: true,
            // Stash the collapsed string so `_decodeCandidate`'s
            // dispatch can return it directly without re-stripping.
            _collapsed: hit.collapsed,
          });
          // Don't try smaller strides at the same position once a
          // run was found — outer for-i loop advances past anyway.
          if (candidates.length >= this.maxCandidatesPerType) return candidates;
          // Skip ahead so we don't re-emit a sub-run starting at i+1.
          i = hit.end - 1;
          break;
        }
      }
    }

    // ── Pass 2: multi-character literal separator (e.g. `\x00`,
    // `&#0;`, `&nbsp;`). These show up when source code itself uses
    // an escape sequence — e.g. `"$\x00W\x00C\x00=…"` is 4 characters
    // of literal text per separator, not a single null byte. The
    // separator candidates we test are the most common in real
    // obfuscation samples; everything else is best left to Pass 1.
    const litSeparators = [
      { lit: '\\x00', display: '\\\\x00' },     // string-literal escape for NUL
      { lit: '\\u0000', display: '\\\\u0000' },
      { lit: '&#0;', display: '&#0;' },
      { lit: '&nbsp;', display: '&nbsp;' },
      { lit: '&#x00;', display: '&#x00;' },
    ];
    for (const { lit, display } of litSeparators) {
      let searchFrom = 0;
      while (searchFrom < text.length) {
        const first = text.indexOf(lit, searchFrom);
        if (first < 0) break;
        // Real character is between (first - 1) and first; we need a
        // whole run of (real, lit, real, lit, …). Validate by walking
        // forward and counting how many `lit` instances repeat with
        // exactly one character between them.
        let pos = first;
        let realStart = first - 1;
        if (realStart < 0) { searchFrom = first + lit.length; continue; }
        let runs = 0;
        let collapsed = '';
        while (pos < text.length) {
          // Real char at `pos - 1`, lit at `pos..pos+lit.length`.
          const ch = text[pos - 1];
          if (!ch) break;
          // Must match lit exactly here.
          if (text.substr(pos, lit.length) !== lit) break;
          collapsed += ch;
          runs++;
          pos += lit.length;
          // Next iteration expects a single real char before the next
          // lit (so advance past one real char).
          if (pos >= text.length) break;
          // Look ahead: is next lit at pos+1?
          if (text.substr(pos + 1, lit.length) !== lit) {
            // Possibly the very last real char after the final lit —
            // include it and stop.
            const tail = text[pos];
            if (tail) collapsed += tail;
            pos += 1;
            break;
          }
          pos += 1; // consume the real char so next iteration sees lit
        }
        // Default-mode floor raised 3→5 runs (≥5 real chars decoded);
        // shorter runs are pure noise without the exec-keyword AND-gate.
        const minRuns = this._bruteforce ? 3 : (this._aggressive ? 3 : 5);
        if (runs >= minRuns && _looksPlausible(collapsed)) {
          const end = pos;
          const start = realStart;
          const raw = text.substring(start, end);
          candidates.push({
            type: `Interleaved Separator (${display})`,
            raw,
            offset: start,
            length: end - start,
            entropy: this._shannonEntropyString(collapsed),
            confidence: 'normal',
            hint: `Literal separator '${display}' interleaved → ${collapsed.length} char${collapsed.length === 1 ? '' : 's'}`,
            autoDecoded: true,
            _collapsed: collapsed,
          });
          if (candidates.length >= this.maxCandidatesPerType) return candidates;
          searchFrom = end;
        } else {
          searchFrom = first + lit.length;
        }
      }
    }

    return candidates;
  },

  /**
   * Decode an interleaved-separator candidate. The finder already
   * stashed the collapsed string in `cand._collapsed`; we just
   * UTF-8-encode it.
   */
  _decodeInterleavedSeparator(cand) {
    const collapsed = cand && typeof cand._collapsed === 'string' ? cand._collapsed : '';
    if (!collapsed) return null;
    try {
      return new TextEncoder().encode(collapsed);
    } catch (_) {
      return null;
    }
  },
});
