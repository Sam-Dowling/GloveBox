// ════════════════════════════════════════════════════════════════════════════
// EncodedContentDetector — scans for encoded/compressed blobs, decodes them,
// extracts IOCs, classifies decoded payloads, and supports recursive decode.
//
// This file is the **class root**. Per-feature methods are mounted onto
// `EncodedContentDetector.prototype` via `Object.assign(...)` from the
// sibling files in `src/decoders/`:
//
//   safelinks.js          — static unwrapSafeLink (Proofpoint v1/v2/v3 + MS)
//   whitelist.js          — _isDataURI / _isPEM / _isCSSFontData / _isMIMEBody /
//                           _isHashLength / _isGUID / _isPowerShellEncodedCommand /
//                           _hasBase32Context
//   entropy.js            — _classify / _assessSeverity /
//                           _shannonEntropyString / _shannonEntropyBytes /
//                           _tryDecodeUTF8 / _isValidUTF8 / _tryDecodeUTF16LE
//   ioc-extract.js        — _extractIOCsFromDecoded
//   base64-hex.js         — Base64 / Hex / Base32 finders + decoders
//   zlib.js               — _findCompressedBlobCandidates /
//                           _processCompressedCandidate
//   encoding-finders.js   — URL-enc / HTML-ent / Unicode-esc / Char-Array /
//                           Octal / Script.Encode / space-hex / ROT13 /
//                           Split-Join finders
//   encoding-decoders.js  — _decodeCandidate switch + the above decoders
//   cmd-obfuscation.js    — _findCommandObfuscationCandidates /
//                           _processCommandObfuscation (CMD + PowerShell)
//   xor-bruteforce.js     — _tryXorBruteforce (single-byte XOR cipher
//                           recovery) + _hasXorContext (call-site gate)
//
// `scripts/build.py` concatenates these files in the JS_FILES order so the
// class declaration appears before any helper module attaches. The same
// ordered concatenation is reused for the off-thread bundle in
// `WorkerManager.runEncoded()` (see `_encoded_worker_bundle_src` in build.py).
// ════════════════════════════════════════════════════════════════════════════

class EncodedContentDetector {

  constructor(opts = {}) {
    this.maxRecursionDepth = opts.maxRecursionDepth || 4;
    this.maxCandidatesPerType = opts.maxCandidatesPerType || 50;
    // Aggressive mode lowers finder thresholds for selection-driven
    // decode (the analyst has explicitly highlighted a region they
    // suspect is encoded — accept higher noise in exchange for catching
    // shorter chains: 2-escape `\xHH` runs, 2-fragment string-concat,
    // etc.). Threaded through to nested detectors via the recursion
    // constructor calls inside `_processCandidate`.
    this._aggressive = !!opts.aggressive;
  }

  // ── Helper: propagate severity & IOCs from inner findings ────────────────
  static _propagateInnerFindings(severity, iocs, innerFindings) {
    if (!innerFindings || innerFindings.length === 0) return severity;
    const sevRank = { critical: 4, high: 3, medium: 2, info: 1 };
    const seen = new Set(iocs.map(i => i.url));
    for (const inner of innerFindings) {
      if ((sevRank[inner.severity] || 0) > (sevRank[severity] || 0)) {
        severity = inner.severity;
      }
      if (inner.iocs) {
        for (const ioc of inner.iocs) {
          if (!seen.has(ioc.url)) {
            seen.add(ioc.url);
            iocs.push(ioc);
          }
        }
      }
    }
    return severity;
  }

  // ── Magic byte signatures for decoded binary identification ──────────────
  static MAGIC_BYTES = [
    { magic: [0x4D, 0x5A],                     ext: '.exe',  type: 'PE Executable' },
    { magic: [0x50, 0x4B, 0x03, 0x04],         ext: '.zip',  type: 'ZIP Archive' },
    { magic: [0x25, 0x50, 0x44, 0x46],         ext: '.pdf',  type: 'PDF Document' },
    { magic: [0xD0, 0xCF, 0x11, 0xE0],         ext: '.ole',  type: 'OLE/CFB Document' },
    { magic: [0x1F, 0x8B],                     ext: '.gz',   type: 'Gzip Compressed' },
    { magic: [0x78, 0x9C],                     ext: '.zlib', type: 'Zlib Compressed (default)' },
    { magic: [0x78, 0xDA],                     ext: '.zlib', type: 'Zlib Compressed (best)' },
    { magic: [0x78, 0x01],                     ext: '.zlib', type: 'Zlib Compressed (no/low)' },
    { magic: [0x78, 0x5E],                     ext: '.zlib', type: 'Zlib Compressed (fast)' },
    { magic: [0x52, 0x61, 0x72, 0x21],         ext: '.rar',  type: 'RAR Archive' },
    { magic: [0x7F, 0x45, 0x4C, 0x46],         ext: '.elf',  type: 'ELF Binary' },
    { magic: [0x89, 0x50, 0x4E, 0x47],         ext: '.png',  type: 'PNG Image' },
    { magic: [0xFF, 0xD8, 0xFF],               ext: '.jpg',  type: 'JPEG Image' },
    { magic: [0xCA, 0xFE, 0xBA, 0xBE],         ext: '.class', type: 'Java Class' },
    { magic: [0xCF, 0xFA, 0xED, 0xFE],         ext: '.macho', type: 'Mach-O Binary' },
    { magic: [0x37, 0x7A, 0xBC, 0xAF],         ext: '.7z',  type: '7-Zip Archive' },
    { magic: [0xEF, 0xBB, 0xBF],               ext: '.txt',  type: 'UTF-8 BOM Text' },
  ];

  // ── Text-based signatures at the start of decoded content ────────────────
  static TEXT_SIGNATURES = [
    { pattern: /^<script/i,                         ext: '.html', type: 'HTML/Script' },
    { pattern: /^<HTA:APPLICATION/i,                ext: '.hta',  type: 'HTA Application' },
    { pattern: /^#!(\/usr\/bin|\/bin)\//,            ext: '.sh',   type: 'Shell Script' },
    { pattern: /^(Sub |Function |Dim |Private )/i,  ext: '.vbs',  type: 'VBScript' },
    { pattern: /^\$[A-Za-z]|^function |^param\s*\(/i, ext: '.ps1', type: 'PowerShell' },
    { pattern: /^<\?xml\s/i,                        ext: '.xml',  type: 'XML Document' },
    { pattern: /^<!DOCTYPE\s|^<html/i,              ext: '.html', type: 'HTML Document' },
    { pattern: /^\{\\rtf/,                          ext: '.rtf',  type: 'RTF Document' },
  ];

  // ── High-confidence Base64 prefixes (known magic bytes when B64-encoded) ─
  static HIGH_CONFIDENCE_B64 = [
    { prefix: 'TVqQ', desc: 'PE executable (MZ)' },
    { prefix: 'TVpQ', desc: 'PE executable (MZ variant)' },
    { prefix: 'TVro', desc: 'PE executable (MZ variant)' },
    { prefix: 'H4sI', desc: 'Gzip compressed' },
    { prefix: 'eJw',  desc: 'Zlib compressed (default)' },
    { prefix: 'eNo',  desc: 'Zlib compressed (best)' },
    { prefix: 'eAE',  desc: 'Zlib compressed (no/low)' },
    { prefix: 'eF4',  desc: 'Zlib compressed (fast)' },
    { prefix: 'UEsD', desc: 'ZIP archive (PK)' },
    { prefix: 'JVBE', desc: 'PDF document (%PDF)' },
    { prefix: '0M8R', desc: 'OLE/CFB document' },
    { prefix: 'UmFy', desc: 'RAR archive' },
    { prefix: 'N3q8', desc: '7-Zip archive' },
    { prefix: 'f0VM', desc: 'ELF binary' },
  ];

  // ════════════════════════════════════════════════════════════════════════
  // PUBLIC API
  // ════════════════════════════════════════════════════════════════════════

  /**
   * Scan content for encoded/compressed blobs.
   * @param {string}     textContent  Text representation of the file.
   * @param {Uint8Array} rawBytes     Raw file bytes.
   * @param {object}     context      { fileType, existingIOCs, mimeAttachments }
   * @returns {Promise<Array>}  Array of finding objects.
   */
  async scan(textContent, rawBytes, context = {}) {
    const findings = [];

    // Stash the source text on `this` so `_processCandidate` can run the
    // XOR-context check (`_hasXorContext`) against the surrounding ±200
    // chars when a Char-Array / Base64 / Hex decode produces high-entropy
    // bytes. The synthetic XOR finding is emitted from inside
    // `_processCandidate`. See PLAN.md → D1 / src/decoders/xor-bruteforce.js.
    this._scanText = (typeof textContent === 'string') ? textContent : '';

    // ── Primary finders: tight patterns, always run. ────────────────────

    // Base64 / Hex / Base32 / compressed-blob finders use anchored
    // patterns where match cost is dominated by decode-and-classify
    // (already capped via `maxCandidatesPerType`).
    const b64Candidates = this._findBase64Candidates(textContent, context);
    const hexCandidates = this._findHexCandidates(textContent, context);
    const b32Candidates = this._findBase32Candidates(textContent, context);

    // ── Secondary finders + cmd-obfuscation: regex-heavy, bounded. ──────
    // The secondary family (URL-enc, HTML entities, Unicode escapes, char
    // arrays, octal, Script.Encode, space-hex, ROT13, split-join) and the
    // CMD / PowerShell obfuscation finders historically had at least two
    // patterns with catastrophic-backtracking exposure on adversarial
    // inputs (rot13, backtick-escape). Bound them with an input-size gate
    // and a cumulative wall-clock budget so a hostile sample can never
    // hang the worker even if a future regex regresses.
    const finderMaxBytes  = (typeof PARSER_LIMITS !== 'undefined') ? PARSER_LIMITS.FINDER_MAX_INPUT_BYTES : (4 * 1024 * 1024);
    const finderBudgetMs  = (typeof PARSER_LIMITS !== 'undefined') ? PARSER_LIMITS.FINDER_BUDGET_MS       : 2_500;
    const finderStart     = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
    const oversize        = (typeof textContent === 'string') && textContent.length > finderMaxBytes;
    let   budgetExhausted = false;
    let   skipReason      = oversize
      ? `Encoded-content secondary scan skipped: text size ${textContent.length.toLocaleString()} bytes exceeds finder cap of ${finderMaxBytes.toLocaleString()} bytes`
      : null;

    const _runFinder = (fn) => {
      if (oversize || budgetExhausted) return [];
      const now = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
      if (now - finderStart > finderBudgetMs) {
        budgetExhausted = true;
        skipReason = `Encoded-content secondary scan truncated: cumulative finder budget of ${finderBudgetMs} ms exhausted (partial coverage)`;
        return [];
      }
      try {
        return fn.call(this, textContent, context) || [];
      } catch (err) {
        // Treat any per-finder failure (regex backtracking abort, etc.)
        // as a "skip the rest" signal — we'd rather lose secondary
        // coverage than hang the worker.
        if (err && err.name === 'AbortError') throw err;
        budgetExhausted = true;
        skipReason = `Encoded-content secondary scan aborted: ${(err && err.message) || 'finder error'}`;
        return [];
      }
    };

    const urlEncCandidates       = _runFinder(this._findUrlEncodedCandidates);
    const htmlEntCandidates      = _runFinder(this._findHtmlEntityCandidates);
    const unicodeEscCandidates   = _runFinder(this._findUnicodeEscapeCandidates);
    const charArrayCandidates    = _runFinder(this._findCharArrayCandidates);
    const octalCandidates        = _runFinder(this._findOctalEscapeCandidates);
    const scriptEncCandidates    = _runFinder(this._findScriptEncodedCandidates);
    const spaceHexCandidates     = _runFinder(this._findSpaceDelimitedHexCandidates);
    const rot13Candidates        = _runFinder(this._findRot13Candidates);
    const splitJoinCandidates    = _runFinder(this._findSplitJoinCandidates);
    const jsHexEscCandidates     = _runFinder(this._findJsHexEscapeCandidates);
    const reverseCandidates      = _runFinder(this._findReverseStringCandidates);
    const concatCandidates       = _runFinder(this._findStringConcatCandidates);
    const spacedTokenCandidates  = _runFinder(this._findSpacedTokenCandidates);
    const commentObfCandidates   = _runFinder(this._findCommentObfuscationCandidates);
    const cmdObfCandidates       = _runFinder(this._findCommandObfuscationCandidates);

    // Surface a single info-level finding so the analyst knows the
    // secondary scan ran in degraded mode. Without this, an oversize
    // input would silently miss URL-encoded / char-array / cmd-obfusc
    // matches with no breadcrumb in the sidebar.
    if (skipReason) {
      findings.push({
        type: 'encoded-content',
        severity: 'info',
        encoding: 'finder-budget',
        offset: 0,
        length: 0,
        decodedSize: 0,
        decodedBytes: null,
        chain: ['finder-budget'],
        classification: { type: null, ext: null },
        entropy: 0,
        hint: skipReason,
        iocs: [],
        innerFindings: [],
        autoDecoded: false,
        canLoad: false,
        snippet: '',
      });
    }


    // Find compressed-blob candidates in the raw bytes (zlib / gzip / etc.).
    const compressedCandidates = this._findCompressedBlobCandidates(rawBytes, context);

    // Decode and classify every candidate.
    for (const cand of b64Candidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of hexCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of b32Candidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of urlEncCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of htmlEntCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of unicodeEscCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of charArrayCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of octalCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of scriptEncCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of spaceHexCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of rot13Candidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of splitJoinCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of jsHexEscCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of reverseCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of concatCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of spacedTokenCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of commentObfCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of cmdObfCandidates) {
      const result = await this._processCommandObfuscation(cand);
      if (result) findings.push(result);
    }
    for (const cand of compressedCandidates) {
      const result = await this._processCompressedCandidate(cand, rawBytes);
      if (result) findings.push(result);
    }

    return findings;
  }

  // ════════════════════════════════════════════════════════════════════════
  // CORE: candidate processing + recursion driver
  // (Per-encoding finders / decoders / classifier / IOC extraction live in
  //  the `src/decoders/*.js` modules attached via Object.assign.)
  // ════════════════════════════════════════════════════════════════════════

  /**
   * Build a finding for a candidate that exceeded the recursion-depth limit.
   * Prevents a TypeError when maxRecursionDepth is breached.
   */
  _makeDepthExceededFinding(candidate, depth) {
    return {
      type: 'encoded-content',
      severity: 'info',
      encoding: candidate.type,
      offset: candidate.offset,
      length: candidate.length,
      decodedSize: 0,
      decodedBytes: null,
      chain: [candidate.type, 'depth-exceeded'],
      classification: { type: null, ext: null },
      entropy: 0,
      hint: `Recursion depth limit exceeded (depth ${depth})`,
      iocs: [],
      innerFindings: [],
      autoDecoded: false,
      canLoad: false,
      snippet: candidate.raw ? candidate.raw.substring(0, 120) : '',
    };
  }

  /**
   * Process a text-encoding candidate (Base64/Hex/Base32 + secondary family).
   * For high-confidence candidates, auto-decode. Others get lazy metadata.
   */
  async _processCandidate(candidate, depth) {
    if (depth > this.maxRecursionDepth) {
      return this._makeDepthExceededFinding(candidate, depth);
    }

    // Attempt decode
    let decoded;
    try {
      decoded = this._decodeCandidate(candidate);
    } catch (_) {
      return null; // Decode failed, not a valid encoded blob
    }

    if (!decoded || decoded.length === 0) return null;

    // Classify the decoded content
    const classification = this._classify(decoded);

    // Build decode chain
    const chain = [candidate.type];

    // If decoded content is compressed (gzip or zlib), try to decompress.
    // Instead of replacing decoded in-place (which loses the intermediate
    // compressed layer), keep decoded as the compressed bytes and store the
    // decompressed result as a synthetic inner finding.  This lets the sidebar
    // offer "Load for analysis" (one layer deep — the compressed blob) and
    // "All the way" (deepest layer — the decompressed payload) separately.
    let syntheticDecompFinding = null;
    const cType = (classification.type || '').toLowerCase();
    if (cType.includes('gzip') || cType.includes('zlib') || classification.ext === '.gz' || classification.ext === '.zlib') {
      try {
        const decompResult = await Decompressor.tryAll(decoded, 0);
        if (decompResult && decompResult.data && decompResult.data.length > 0) {
          const decompData = decompResult.data;
          const innerClass = this._classify(decompData);
          const decompEntropy = this._shannonEntropyBytes(decompData);
          const decompIocs = this._extractIOCsFromDecoded(decompData);
          const decompSev = this._assessSeverity(innerClass, decompIocs, decompData);
          const decompExt = innerClass.ext || (this._isValidUTF8(decompData) ? '.txt' : '.bin');
          const decompChain = [decompResult.format || 'decompressed'];
          if (innerClass.type) decompChain.push(innerClass.type);
          else if (this._isValidUTF8(decompData)) decompChain.push('text');
          else decompChain.push('binary data');

          // Recursively scan decompressed content for further encoding layers
          let decompInner = [];
          if (depth < this.maxRecursionDepth && decompData.length > 32) {
            const decompText = this._tryDecodeUTF8(decompData);
            if (decompText && decompText.length > 32) {
              const innerDet = new EncodedContentDetector({
                maxRecursionDepth: this.maxRecursionDepth,
                maxCandidatesPerType: this.maxCandidatesPerType,
                aggressive: this._aggressive,
              });
              decompInner = await innerDet.scan(decompText, decompData, { fileType: '' });
              for (const f of decompInner) {
                f.chain = [...decompChain, ...f.chain];
                f.depth = (f.depth || 0) + 1;
              }
            }
          }

          syntheticDecompFinding = {
            type: 'encoded-content',
            severity: decompSev,
            encoding: decompResult.format || 'decompressed',
            offset: 0,
            length: decompData.length,
            decodedSize: decompData.length,
            decodedBytes: decompData,
            chain: decompChain,
            classification: innerClass,
            entropy: decompEntropy,
            hint: `Decompressed from ${classification.type || 'compressed data'} (${decompData.length.toLocaleString()} bytes)`,
            iocs: decompIocs,
            innerFindings: decompInner,
            autoDecoded: true,
            canLoad: !!(innerClass.type || this._isValidUTF8(decompData)),
            ext: decompExt,
            snippet: '',
          };
        }
      } catch (_) { /* decompression failed, continue with raw decoded */ }
    }

    // If still high-entropy binary (>7.5), flag but don't recurse
    const finalEntropy = this._shannonEntropyBytes(decoded);
    if (finalEntropy > 7.5 && !classification.type) {
      return {
        type: 'encoded-content',
        severity: 'medium',
        encoding: candidate.type,
        offset: candidate.offset,
        length: candidate.length,
        decodedSize: decoded.length,
        decodedBytes: candidate.autoDecoded ? decoded : null,
        chain: [...chain, 'high-entropy binary'],
        classification: { type: 'Encrypted/Packed Data', ext: '.bin' },
        entropy: finalEntropy,
        hint: candidate.hint,
        iocs: [],
        note: 'High entropy suggests encryption or packing — manual analysis recommended',
        autoDecoded: candidate.autoDecoded,
        canLoad: false,
        snippet: candidate.raw ? candidate.raw.substring(0, 120) : '',
      };
    }

    // Extract IOCs from decoded content
    const iocs = this._extractIOCsFromDecoded(decoded);

    // Run YARA if available (will be done by caller)
    // Determine severity
    let severity = this._assessSeverity(classification, iocs, decoded);

    // ── Synthetic XOR-cleartext inner finding (PLAN.md → D1) ─────────────
    // If the decoded bytes look gibberish (high entropy, no classification,
    // not valid UTF-8 text) AND the surrounding source mentions an XOR
    // operator, brute-force a single-byte XOR key. A clear winner becomes a
    // synthetic inner finding labelled `XOR (key 0xNN)` so the analyst sees
    // the recovered cleartext + the discovered key. The XOR finder fires
    // only when:
    //   • we have a `_tryXorBruteforce` helper attached (defensive guard
    //     so the bundle still works if the prototype mixin order changes), and
    //   • the candidate is one of the carriers known to wrap XOR'd bytes
    //     (Char-Array, Base64, Hex, Hex-escape, PS byte array), and
    //   • the surrounding source matches the XOR-context regex within
    //     ±200 chars.
    // The bruteforce itself caps the work at 64 KiB with dual-window
    // sampling beyond that — see src/decoders/xor-bruteforce.js.
    let syntheticXorFinding = null;
    if (typeof this._tryXorBruteforce === 'function' && decoded && decoded.length >= 24) {
      const xorCarriers = new Set([
        'Char Array', 'Base64', 'Hex', 'Hex (escaped)', 'Hex (PS byte array)',
      ]);
      const cleartextLooksLikeText =
        !!classification.type ||
        (this._isValidUTF8(decoded) && /[A-Za-z]{4,}/.test(this._tryDecodeUTF8(decoded) || ''));
      // Only attempt XOR if the primary decode produced gibberish — text
      // that already classifies (script, document, etc.) is not the
      // post-XOR product.
      if (xorCarriers.has(candidate.type) && !cleartextLooksLikeText) {
        const scanText = this._scanText || '';
        const ctxOK = scanText && this._hasXorContext(scanText, candidate.offset, candidate.raw);
        if (ctxOK) {
          let xorResult = null;
          try {
            xorResult = this._tryXorBruteforce(decoded);
          } catch (_) { xorResult = null; }
          if (xorResult && xorResult.bytes && xorResult.bytes.length > 0) {
            const xorBytes = xorResult.bytes;
            const xorKey   = xorResult.key;
            const keyHex   = '0x' + xorKey.toString(16).toUpperCase().padStart(2, '0');
            const xorClass = this._classify(xorBytes);
            const xorEntropy = this._shannonEntropyBytes(xorBytes);
            const xorIocs = this._extractIOCsFromDecoded(xorBytes);
            const xorSev = this._assessSeverity(xorClass, xorIocs, xorBytes);
            const xorExt = xorClass.ext || (this._isValidUTF8(xorBytes) ? '.txt' : '.bin');
            const xorChain = [`XOR (key ${keyHex})`];
            if (xorClass.type) xorChain.push(xorClass.type);
            else if (this._isValidUTF8(xorBytes)) xorChain.push('text');
            else xorChain.push('binary data');

            // Recursively scan the XOR cleartext for further layers
            // (e.g. the canonical block-14 case is Base64 → XOR → "iex
            // Write-Output Hello World" — the recursion picks up CMD-obf
            // / variable / IOC findings inside the cleartext).
            let xorInner = [];
            if (depth < this.maxRecursionDepth && xorBytes.length > 32) {
              const xorText = this._tryDecodeUTF8(xorBytes);
              if (xorText && xorText.length > 32) {
                const innerDet = new EncodedContentDetector({
                  maxRecursionDepth: this.maxRecursionDepth,
                  maxCandidatesPerType: this.maxCandidatesPerType,
                  aggressive: this._aggressive,
                });
                xorInner = await innerDet.scan(xorText, xorBytes, { fileType: '' });
                for (const f of xorInner) {
                  f.chain = [...xorChain, ...f.chain];
                  f.depth = (f.depth || 0) + 1;
                }
              }
            }

            syntheticXorFinding = {
              type: 'encoded-content',
              severity: xorSev,
              encoding: `XOR (key ${keyHex})`,
              offset: candidate.offset,
              length: candidate.length,
              decodedSize: xorBytes.length,
              decodedBytes: xorBytes,
              chain: xorChain,
              classification: xorClass,
              entropy: xorEntropy,
              hint: `Single-byte XOR cipher (key ${keyHex}) — bruteforced cleartext`,
              iocs: xorIocs,
              innerFindings: xorInner,
              autoDecoded: true,
              canLoad: !!(xorClass.type || this._isValidUTF8(xorBytes)),
              ext: xorExt,
              snippet: '',
            };
          }
        }
      }
    }

    // Recursive scan: check if decoded content contains more encoding layers
    let innerFindings = [];

    if (depth < this.maxRecursionDepth && decoded.length > 32) {
      const decodedText = this._tryDecodeUTF8(decoded);
      if (decodedText && decodedText.length > 32) {
        const innerDetector = new EncodedContentDetector({
          maxRecursionDepth: this.maxRecursionDepth,
          maxCandidatesPerType: this.maxCandidatesPerType,
          aggressive: this._aggressive,
        });
        innerFindings = await innerDetector.scan(decodedText, decoded, { fileType: '' });
        // Add parent chain to inner findings
        for (const f of innerFindings) {
          f.chain = [...chain, ...f.chain];
          f.depth = (f.depth || 0) + 1;
        }
      }
    }

    // If we created a synthetic decompressed finding, prepend it to innerFindings
    // so it appears as the primary "deeper layer" for the sidebar's "All the way" button
    if (syntheticDecompFinding) {
      innerFindings.unshift(syntheticDecompFinding);
    }

    // Same treatment for the synthetic XOR-cleartext finding (PLAN.md → D1).
    // Prepended AFTER the decompressed finding so a Base64 → zlib → XOR
    // chain still surfaces the decompressed layer first; the XOR layer
    // is the one the analyst clicks "All the way" on.
    if (syntheticXorFinding) {
      innerFindings.unshift(syntheticXorFinding);
    }

    // Propagate severity and IOCs from inner findings — if nested content is
    // more dangerous, the parent finding should reflect that; IOCs discovered
    // in deeper layers (e.g. a URL inside Hex → Base64 → text) surface here
    // so the analyst sees them without having to drill down manually.
    severity = EncodedContentDetector._propagateInnerFindings(severity, iocs, innerFindings);

    // Determine the file extension for the synthetic file
    const ext = classification.ext || (this._isValidUTF8(decoded) ? '.txt' : '.bin');

    // Determine chain description
    if (classification.type) chain.push(classification.type);
    else if (this._isValidUTF8(decoded)) chain.push('text');
    else chain.push('binary data');

    const finding = {
      type: 'encoded-content',
      severity,
      encoding: candidate.type,
      offset: candidate.offset,
      length: candidate.length,
      decodedSize: decoded.length,
      decodedBytes: candidate.autoDecoded ? decoded : null,
      rawCandidate: candidate.autoDecoded ? null : candidate.raw,
      chain,
      classification,
      entropy: finalEntropy,
      hint: candidate.hint,
      iocs,
      innerFindings,
      autoDecoded: candidate.autoDecoded,
      canLoad: !!(classification.type || this._isValidUTF8(decoded)),
      ext,
      snippet: candidate.raw ? candidate.raw.substring(0, 120) : '',
    };

    return finding;
  }

  /**
   * Lazily decode a candidate that wasn't auto-decoded.
   * Called when user clicks "Decode" button.
   */
  async lazyDecode(finding) {
    if (finding.decodedBytes) return finding; // Already decoded

    if (finding.needsDecompression && finding._rawBytes) {
      // Decompress from raw bytes
      const fmt = finding.compressionFormat === 'zlib' ? 'deflate' : finding.compressionFormat;
      const result = await Decompressor.tryDecompress(finding._rawBytes, finding.offset, fmt);
      if (result.success) {
        finding.decodedBytes = result.data;
        finding.decodedSize = result.data.length;
        finding.classification = this._classify(result.data);
        finding.entropy = this._shannonEntropyBytes(result.data);
        finding.iocs = this._extractIOCsFromDecoded(result.data);
        finding.canLoad = true;
        finding.chain.push(finding.classification.type || 'binary data');
        finding.severity = this._assessSeverity(finding.classification, finding.iocs, result.data);
        // Propagate severity and IOCs from existing inner findings
        finding.severity = EncodedContentDetector._propagateInnerFindings(finding.severity, finding.iocs, finding.innerFindings);
      }
      return finding;
    }

    if (finding.rawCandidate) {
      // Decode the text candidate
      const pseudoCandidate = {
        type: finding.encoding,
        raw: finding.rawCandidate,
        offset: finding.offset,
        length: finding.length,
        autoDecoded: true,
      };
      const decoded = this._decodeCandidate(pseudoCandidate);
      if (decoded && decoded.length > 0) {
        finding.decodedBytes = decoded;
        finding.decodedSize = decoded.length;
        finding.classification = this._classify(decoded);
        finding.entropy = this._shannonEntropyBytes(decoded);
        finding.iocs = this._extractIOCsFromDecoded(decoded);
        finding.canLoad = !!(finding.classification.type || this._isValidUTF8(decoded));
        const chain = [finding.encoding];
        if (finding.classification.type) chain.push(finding.classification.type);
        else if (this._isValidUTF8(decoded)) chain.push('text');
        else chain.push('binary data');
        finding.chain = chain;
        finding.severity = this._assessSeverity(finding.classification, finding.iocs, decoded);
        // Propagate severity and IOCs from existing inner findings
        finding.severity = EncodedContentDetector._propagateInnerFindings(finding.severity, finding.iocs, finding.innerFindings);
        finding.ext = finding.classification.ext || (this._isValidUTF8(decoded) ? '.txt' : '.bin');
        finding.autoDecoded = true;
        finding.rawCandidate = null;
      }
      return finding;
    }

    return finding;
  }
}
