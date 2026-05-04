'use strict';
// ════════════════════════════════════════════════════════════════════════════
// EncodedReassembler — whole-file reconstruction of a script whose
// obfuscation is spread across MULTIPLE parallel techniques (Base64 here,
// char-array there, cmd-obfuscation somewhere else).
//
// `EncodedContentDetector` already unwinds sequential layers inside one
// span via its `innerFindings` tree (Base64 → zlib → PowerShell → command).
// What it cannot do is stitch together N independent spans at N different
// byte offsets. The analyst gets three separate sidebar cards for a dropper
// whose `iex "$a $b $c"` line is the whole payload; reading it back to a
// single runnable script is left to their eyes and clipboard.
//
// This module closes that gap. For each top-level `EncodedContentDetector`
// finding we take the deepest decoded text we can extract, splice it into
// the original source at that finding's byte range, and emit a single
// `reconstructedScript` object. The sidebar paints one composite card
// above the per-finding cards; analysts see the stitched script first
// and drop to per-finding detail only when they need the provenance of a
// particular span.
//
// Language-agnostic by design. Offset-splicing works for every script
// surface (.ps1, .bat/.cmd, .js, .sh, .py, .php, embedded <script> in
// .hta/.svg/.html) without per-language parsers. Variable-flow resolution
// (`$a = base64…; iex $a`) is a future extension; the offset-splicing
// foundation here is a pre-requisite either way.
//
// Mode gating mirrors the existing auto / aggressive / bruteforce tri-mode:
//   • auto        — only findings that SURVIVED `_pruneFindings` in the
//                   detector are eligible; safest default.
//   • aggressive  — same as auto (reassembly is additive signal, not noise
//                   amplification; keeping `aggressive` equivalent keeps
//                   the surface predictable across the two auto modes).
//   • bruteforce  — stitches every finding, including low-confidence decodes;
//                   the analyst opted into noise by clicking the chip.
//
// Non-goals (deliberately deferred — see AGENTS.md plan discussion):
//   • Variable-flow / taint-aware reassembly
//   • Cross-file stitching (multi-stage droppers across archive members)
//   • Re-running EncodedContentDetector on the reconstructed text (phase 3)
//
// Phase 1 scope: build the reconstruction object + the sidebar composite
// card. No re-analysis (Phase 2 adds IOC-diff + decoded-payload YARA scan).
// ════════════════════════════════════════════════════════════════════════════

(function () {

  // ── Tunables (wired through PARSER_LIMITS.REASSEMBLY_* below) ───────────
  // Numeric floors / ceilings that bound CPU and memory. Exceeding any of
  // these produces a reconstructedScript with `truncated = true` rather
  // than an exception; the analyst still gets a partial stitched view.
  const DEFAULTS = Object.freeze({
    MIN_FINDINGS_USED:  2,        // < 2 usable spans → no composite (per-finding card already tells the whole story)
    MIN_COVERAGE:       0.05,     // < 5% of source replaced → no composite
    MAX_FINDINGS:       64,       // cap spans processed per file
    MAX_OUTPUT_BYTES:   4 * 1024 * 1024,  // 4 MiB hard ceiling on reconstructed text
    MAX_DECODE_PREVIEW: 32 * 1024,        // per-span decoded-text slice we splice in
  });

  // Invisible sentinel pair — U+2063 (INVISIBLE SEPARATOR) wrapping every
  // spliced span. Pure whitespace-semantic to the shell interpreter; lets
  // the sidebar locate insertion boundaries in the stitched text without
  // a sidecar offset table and without corrupting tokenisation. Four
  // repeats keeps collisions with raw source effectively impossible.
  const SENTINEL_OPEN  = '\u2063\u2063\u2063\u2063';
  const SENTINEL_CLOSE = '\u2063\u2063\u2063\u2063';

  // ── UTF-8 / UTF-16LE text extraction ────────────────────────────────────
  // Mirrors `_extractTextPreview` in `app-sidebar.js` — a decoded Uint8Array
  // is first tried as UTF-8 (strict, so the control-char heuristic fires
  // only for clean text), then UTF-16LE (common for
  // `[Convert]::FromBase64String("…")` PowerShell payloads). Returns null
  // for binary buffers; callers treat null as "not splice-able".
  function _decodeAsText(bytes) {
    if (!bytes || typeof bytes.byteLength !== 'number' || bytes.byteLength === 0) return null;
    const slice = bytes.slice(0, DEFAULTS.MAX_DECODE_PREVIEW);
    try {
      const t = new TextDecoder('utf-8', { fatal: true }).decode(slice);
      const cc = 0;
      // Count the run of non-printable bytes (ignoring \t \n \r) as a
      // sanity filter. Same 10% threshold the sidebar uses.
      let ctrl = 0;
      for (let i = 0; i < t.length; i++) {
        const cp = t.charCodeAt(i);
        if (cp < 32 && cp !== 9 && cp !== 10 && cp !== 13) ctrl++;
      }
      if (ctrl <= t.length * 0.1) return t;
    } catch (_) { /* not valid UTF-8 — try UTF-16LE */ }
    // UTF-16LE detection: `every-other byte is 0x00` heuristic over the
    // first 64 bytes; same shape probe the detector uses.
    const probe = Math.min(64, slice.length);
    let nulOdd = 0, nulEven = 0;
    for (let i = 0; i < probe; i++) {
      if (slice[i] === 0) (i & 1 ? nulOdd++ : nulEven++);
    }
    const looksUTF16LE = nulOdd > probe * 0.4 || nulEven > probe * 0.4;
    if (looksUTF16LE) {
      try {
        const t = new TextDecoder('utf-16le', { fatal: false }).decode(slice);
        let ctrl = 0;
        for (let i = 0; i < t.length; i++) {
          const cp = t.charCodeAt(i);
          if (cp < 32 && cp !== 9 && cp !== 10 && cp !== 13) ctrl++;
        }
        if (ctrl <= t.length * 0.1) return t;
      } catch (_) { /* fall through */ }
    }
    return null;
  }

  // ── Deepest-wins walk over a finding's innerFindings tree ───────────────
  // Returns the finding node that carries the richest decoded text for
  // this top-level span. Prefers explicit `_deobfuscatedText` (the
  // cmd-obfuscation path), then textual `decodedBytes`, then the outer
  // finding itself if nothing below it produced usable text.
  function _pickDeepestTextNode(finding) {
    let best = null;
    let bestDepth = -1;
    const walk = (f, depth) => {
      if (!f || typeof f !== 'object') return;
      const text = (typeof f._deobfuscatedText === 'string' && f._deobfuscatedText)
        || _decodeAsText(f.decodedBytes);
      if (text && depth > bestDepth) {
        best = { node: f, text, depth };
        bestDepth = depth;
      }
      if (Array.isArray(f.innerFindings)) {
        for (const c of f.innerFindings) walk(c, depth + 1);
      }
    };
    walk(finding, 0);
    return best;
  }

  // ── Severity ranking for overlap resolution ─────────────────────────────
  const _SEV_RANK = { info: 1, low: 1, medium: 2, high: 3, critical: 4 };

  /** Build a reconstruction object from a detector's output.
   *
   *  @param {string}  source          the file's analysisText (lf-normalised)
   *  @param {Array}   encodedFindings top-level `EncodedContentDetector.scan()` output
   *  @param {object}  [opts]
   *  @param {string}  [opts.mode]     'auto' | 'aggressive' | 'bruteforce' (default 'auto')
   *  @param {object}  [opts.limits]   override DEFAULTS.*
   *  @returns {object|null}
   *    {
   *      text, spans, sourceMap, coverage, collisions, mode, reconstructedHash,
   *      truncated, techniques, skipReason?
   *    }
   *    Null when there is nothing to stitch (eligible findings < MIN_FINDINGS_USED).
   */
  function build(source, encodedFindings, opts) {
    const mode = (opts && opts.mode) || 'auto';
    const limits = Object.assign({}, DEFAULTS, (opts && opts.limits) || {});
    if (typeof source !== 'string' || source.length === 0) {
      return { skipReason: 'no-source' };
    }
    if (!Array.isArray(encodedFindings) || encodedFindings.length === 0) {
      return { skipReason: 'no-findings' };
    }

    // ── 1. Gather candidate spans ──────────────────────────────────────
    // Each top-level finding contributes AT MOST ONE span (its deepest
    // textual descendant). innerFindings belonging to the same top-level
    // occupy the SAME byte range in the source, so stitching deeper
    // nested spans would double-count the offset.
    const srcLen = source.length;
    const candidates = [];
    let processed = 0;
    for (const f of encodedFindings) {
      if (processed++ >= limits.MAX_FINDINGS) break;
      if (!f || typeof f !== 'object') continue;
      // finder-budget diagnostic stubs and zero-length findings aren't
      // reassembly candidates.
      if (f.encoding === 'finder-budget') continue;
      if (typeof f.offset !== 'number' || typeof f.length !== 'number') continue;
      if (f.length <= 0) continue;
      if (f.offset < 0 || f.offset + f.length > srcLen) continue;

      const pick = _pickDeepestTextNode(f);
      if (!pick || !pick.text || pick.text.length === 0) continue;

      // Mode gating. `auto` / `aggressive` require at least one of:
      //   • the span carries IOCs (including Pattern mirrors —
      //     reassembly cares about the semantic payload, not just
      //     pivotable indicators),
      //   • or the decoded text passes the existing exec-intent gate
      //     (reuse the detector's `_EXEC_INTENT_RE` when visible),
      //   • or the classification is retention-worthy (PE / script /
      //     archive etc.).
      // `bruteforce` skips this gate — analyst opted into noise.
      if (mode !== 'bruteforce') {
        const hasIOCs = Array.isArray(pick.node.iocs) && pick.node.iocs.length > 0;
        const sev = pick.node.severity || f.severity || 'info';
        const highEnough = sev === 'high' || sev === 'critical' || sev === 'medium';
        const execLike = /\b(?:iex|invoke-expression|powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget|nc|ncat|netcat|bash|sh|python|perl|php|ruby|eval|exec|system|popen|shell_exec|downloadstring|downloadfile|frombase64string|new-object|start-process|shellexecute)\b|https?:\/\/|\/dev\/tcp\//i.test(pick.text);
        if (!hasIOCs && !highEnough && !execLike) continue;
      }

      candidates.push({
        offset: f.offset,
        length: f.length,
        text: pick.text,
        node: pick.node,
        finding: f,
        severity: pick.node.severity || f.severity || 'info',
        chain: (pick.node.chain && pick.node.chain.length) ? pick.node.chain : (f.chain || [f.encoding]),
      });
    }

    if (candidates.length < limits.MIN_FINDINGS_USED) {
      return { skipReason: 'too-few-findings', findingsEligible: candidates.length };
    }

    // ── 2. Sort by offset + resolve overlaps ────────────────────────────
    // Two-finding collision: keep the one with (higher severity, longer
    // decoded text, smaller offset) — ties broken deterministically so
    // the output is reproducible across runs.
    candidates.sort((a, b) => (a.offset - b.offset) || (b.length - a.length));
    const accepted = [];
    const collisions = [];
    for (const c of candidates) {
      const last = accepted.length ? accepted[accepted.length - 1] : null;
      if (last && c.offset < last.offset + last.length) {
        // Overlap. Decide which one stays.
        const lastSev = _SEV_RANK[last.severity] || 0;
        const curSev  = _SEV_RANK[c.severity]    || 0;
        let winner = last, loser = c;
        if (curSev > lastSev ||
            (curSev === lastSev && c.text.length > last.text.length)) {
          winner = c; loser = last;
          accepted[accepted.length - 1] = c;
        }
        collisions.push({
          keptOffset:    winner.offset,
          keptLength:    winner.length,
          keptEncoding:  (winner.finding && winner.finding.encoding) || '',
          droppedOffset: loser.offset,
          droppedLength: loser.length,
          droppedEncoding: (loser.finding && loser.finding.encoding) || '',
        });
        continue;
      }
      accepted.push(c);
    }

    if (accepted.length < limits.MIN_FINDINGS_USED) {
      return { skipReason: 'too-few-after-overlap-resolution',
               findingsEligible: accepted.length,
               collisions };
    }

    // ── 3. Splice accepted spans into the source ───────────────────────
    // Build `text` by interleaving source slices with sentinel-wrapped
    // decoded replacements. Track `spans` with the reconstructed-text
    // offsets so the UI can navigate span boundaries without re-scanning.
    let text = '';
    const spans = [];
    const sourceMap = [];  // array of { reconOffset, sourceOffset, length, isSplice }
    let cursor = 0;  // position in source
    let truncated = false;
    let bytesReplaced = 0;

    for (const c of accepted) {
      // Copy pre-span source prefix.
      if (c.offset > cursor) {
        const chunk = source.slice(cursor, c.offset);
        sourceMap.push({
          reconOffset: text.length,
          sourceOffset: cursor,
          length: chunk.length,
          isSplice: false,
        });
        text += chunk;
      }

      // Splice the decoded text wrapped in sentinels. The sentinel pair
      // is always invisible to a shell but easy to locate via indexOf
      // when the UI wants to highlight spliced-in regions.
      const inserted = c.text.length > limits.MAX_DECODE_PREVIEW
        ? c.text.slice(0, limits.MAX_DECODE_PREVIEW)
        : c.text;
      const replaceStart = text.length;
      text += SENTINEL_OPEN;
      const textStart = text.length;
      text += inserted;
      const textEnd = text.length;
      text += SENTINEL_CLOSE;
      const replaceEnd = text.length;
      sourceMap.push({
        reconOffset: replaceStart,
        sourceOffset: c.offset,
        length: c.length,
        isSplice: true,
        sourceLength: c.length,
      });
      spans.push({
        sourceOffset:   c.offset,
        sourceLength:   c.length,
        replaceStart,       // includes the opening sentinel
        replaceEnd,         // includes the closing sentinel
        textStart,          // just the decoded body
        textEnd,
        chain:          c.chain,
        encoding:       (c.finding && c.finding.encoding) || (c.chain[0] || 'decoded'),
        severity:       c.severity,
        deobfuscatedText: inserted,
        findingOffset:  c.finding.offset,
      });
      bytesReplaced += c.length;
      cursor = c.offset + c.length;

      // Respect the output-byte ceiling. When we breach it, stop
      // splicing more spans and tell the sidebar the reconstruction is
      // partial. Still emit — a partial reconstruction is more useful
      // than none.
      if (text.length >= limits.MAX_OUTPUT_BYTES) {
        truncated = true;
        break;
      }
    }

    // Copy trailing source (only if we didn't bail on truncation).
    if (!truncated && cursor < srcLen) {
      const tail = source.slice(cursor);
      // If appending the tail would breach the ceiling, clip it.
      const room = limits.MAX_OUTPUT_BYTES - text.length;
      if (room > 0) {
        const chunk = room < tail.length ? tail.slice(0, room) : tail;
        sourceMap.push({
          reconOffset: text.length,
          sourceOffset: cursor,
          length: chunk.length,
          isSplice: false,
        });
        text += chunk;
        if (chunk.length < tail.length) truncated = true;
      } else {
        truncated = true;
      }
    }

    // ── 4. Coverage gate ────────────────────────────────────────────────
    const ratio = srcLen > 0 ? (bytesReplaced / srcLen) : 0;
    if (ratio < limits.MIN_COVERAGE && !truncated) {
      return { skipReason: 'below-coverage', coverage: { ratio, bytesReplaced, sourceBytes: srcLen, findingsUsed: accepted.length } };
    }

    // ── 5. Techniques summary + stable fingerprint ─────────────────────
    const techniqueSet = new Set();
    for (const s of spans) {
      // Prefer the outermost encoding label (technique name the user
      // recognises: "Base64", "CMD Obfuscation", "Char Array"). Fall
      // back to the first chain entry.
      const label = s.encoding || (s.chain && s.chain[0]) || 'encoded';
      techniqueSet.add(String(label));
    }
    const techniques = Array.from(techniqueSet);

    // `reconstructedHash` — stable fingerprint of the stitched text
    // (SHA-256 hex, first 16 chars) for dedupe against a prior
    // reconstruction (e.g. re-scan invocation) and for use in the
    // virtual drill-down filename. Lightweight FNV-1a avoids a
    // cross-realm crypto dependency; 64-bit width is more than enough
    // for per-session dedupe.
    let h = 0xcbf29ce484222325n;
    const FNV_PRIME = 0x100000001b3n;
    const MASK = (1n << 64n) - 1n;
    for (let i = 0; i < text.length; i++) {
      h = (h ^ BigInt(text.charCodeAt(i) & 0xff)) * FNV_PRIME & MASK;
    }
    const reconstructedHash = h.toString(16).padStart(16, '0');

    // ── 6. Severity rollup (max of any contributing span) ──────────────
    let maxSevRank = 0;
    let maxSev = 'info';
    for (const s of spans) {
      const r = _SEV_RANK[s.severity] || 0;
      if (r > maxSevRank) { maxSevRank = r; maxSev = s.severity; }
    }

    return {
      text,
      spans,
      sourceMap,
      coverage: {
        ratio,
        bytesReplaced,
        sourceBytes: srcLen,
        findingsUsed: accepted.length,
      },
      collisions,
      techniques,
      reconstructedHash,
      severity: maxSev,
      mode,
      truncated,
      sentinelOpen: SENTINEL_OPEN,
      sentinelClose: SENTINEL_CLOSE,
    };
  }

  /** Map a reconstructed-text offset back to its originating source
   *  offset. Used by the sidebar's "pivot to original" button on the
   *  composite card. Returns null when the offset doesn't land inside
   *  any known span.
   *
   *  @param {object} reconstructed  a `build()` result
   *  @param {number} reconOffset
   *  @returns {number|null}
   */
  function mapReconToSource(reconstructed, reconOffset) {
    if (!reconstructed || !Array.isArray(reconstructed.sourceMap)) return null;
    for (const entry of reconstructed.sourceMap) {
      const end = entry.reconOffset + entry.length
        + (entry.isSplice ? (SENTINEL_OPEN.length + SENTINEL_CLOSE.length + (entry.sourceLength || 0)) : 0);
      // For splice entries `length` is the SOURCE-side length; the
      // reconstructed span width includes the sentinels + decoded text.
      if (entry.isSplice) {
        const spliceReconEnd = entry.reconOffset + SENTINEL_OPEN.length + (entry.sourceLength || 0) + SENTINEL_CLOSE.length;
        if (reconOffset >= entry.reconOffset && reconOffset < spliceReconEnd) {
          return entry.sourceOffset;
        }
      } else {
        if (reconOffset >= entry.reconOffset && reconOffset < entry.reconOffset + entry.length) {
          return entry.sourceOffset + (reconOffset - entry.reconOffset);
        }
      }
      // next iteration
      void end;
    }
    return null;
  }

  /** Strip sentinels from a reconstructed `text`, producing the raw
   *  stitched script suitable for clipboard copy / YARA scan / drill-
   *  down file body. Idempotent.
   *
   *  @param {string} text
   *  @returns {string}
   */
  function stripSentinels(text) {
    if (typeof text !== 'string' || text.length === 0) return '';
    // Two replace passes. The open and close strings are identical
    // today (four U+2063 each) so a single `replaceAll` of the 4-char
    // sequence removes every occurrence.
    // Fall-through supports environments without String.prototype.replaceAll.
    if (typeof text.replaceAll === 'function') {
      return text.replaceAll(SENTINEL_OPEN, '');
    }
    return text.split(SENTINEL_OPEN).join('');
  }

  window.EncodedReassembler = {
    build,
    mapReconToSource,
    stripSentinels,
    // Exposed for unit tests and the sidebar UI layer.
    DEFAULTS,
    SENTINEL_OPEN,
    SENTINEL_CLOSE,
    // Exposed for the `_decodeAsText` regression tests.
    _decodeAsText,
    _pickDeepestTextNode,
  };

})();
