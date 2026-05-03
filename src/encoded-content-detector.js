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

// ── Shared FP-suppression constants ─────────────────────────────────────────
// `_EXEC_INTENT_RE` and `_RETAIN_CLASSIFICATIONS` drive both the per-finder
// plausibility gates and the centralized post-scan `_pruneFindings()` pass.
// Keeping them at module scope means the per-finder modules (attached via
// Object.assign onto `EncodedContentDetector.prototype`) can reference them
// directly without an extra `this.` indirection.
//
// `_EXEC_INTENT_RE` matches the execution-intent vocabulary that almost
// every real malicious decoded payload contains (LOLBin names, PowerShell
// cmdlets, http(s):// URLs). A finding without IOCs that ALSO doesn't match
// this regex is overwhelmingly noise — the canonical example is the bash
// help-text interleaved-separator FP class (47 findings, zero exec hits).
//
// Cross-shell vocabulary (bash / sh / python / php / ruby / perl) is
// included so payloads decoded by bash-obfuscation.js / python-obfuscation.js
// / php-obfuscation.js survive `_pruneFindings`. The pattern is a single
// safeRegex builtin — keep additions strictly literal alternations to
// avoid catastrophic-backtracking hazards.
const _EXEC_INTENT_RE = /\b(eval|exec|invoke|iex|powershell|pwsh|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin|schtasks|wmic|finger|tftp|curl|wget|nltest|installutil|msbuild|downloadstring|downloadfile|frombase64string|new-object|start-process|shellexecute|invoke-expression|invoke-webrequest|set-executionpolicy|encodedcommand|fromcharcode|bash|zsh|ksh|dash|nc|ncat|netcat|socat|ssh|scp|rsync|telnet|chmod|chattr|crontab|systemctl|sudo|setuid|os\.system|os\.popen|subprocess|pty\.spawn|__import__|marshal\.loads|zlib\.decompress|codecs\.decode|base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|shell_exec|passthru|proc_open|preg_replace|create_function|file_get_contents|fsockopen|backtick)\b|https?:\/\/|\/dev\/tcp\/|php:\/\/|data:[^,]*;base64,/i; /* safeRegex: builtin */

// `_RETAIN_CLASSIFICATIONS` lists decoded-content classifications that are
// always worth surfacing even without an IOC or exec-keyword match (PE/ELF
// payloads, scripts, archives, encrypted/packed blobs in XOR contexts).
const _RETAIN_CLASSIFICATIONS = /pe executable|elf|mach-o|hta|powershell|vbscript|shell script|jscript|wsf|ole|pdf|rtf|java class|zip archive|rar archive|7-zip|gzip|zlib|deobfuscated command|encrypted\/packed/i;

class EncodedContentDetector {

  constructor(opts = {}) {
    // Bruteforce mode (kitchen-sink) has the highest cap because the
    // analyst is staring at a 200-char selection — depth 6 still costs
    // peanuts on that scope.
    this.maxRecursionDepth   = opts.maxRecursionDepth   || (opts.bruteforce ? 6 : 4);
    this.maxCandidatesPerType = opts.maxCandidatesPerType || (opts.bruteforce ? 200 : 50);
    // Aggressive mode lowers finder thresholds for selection-driven
    // decode (the analyst has explicitly highlighted a region they
    // suspect is encoded — accept higher noise in exchange for catching
    // shorter chains: 2-escape `\xHH` runs, 2-fragment string-concat,
    // etc.). Threaded through to nested detectors via the recursion
    // constructor calls inside `_processCandidate`.
    this._aggressive = !!opts.aggressive;
    // Bruteforce mode (one rung above aggressive) — only reached via the
    // "Decode selection" chip, never auto-fired. On top of `aggressive`'s
    // lowered thresholds it ALSO:
    //   • bypasses every whitelist filter (PEM / data: / MIME / hash /
    //     GUID / base32-context) — analyst is looking at a small region
    //     and has explicitly opted in;
    //   • drops the exec-keyword plausibility gates on the synthetic
    //     finders (Reversed / String Concat / Spaced Tokens /
    //     Comment-Stripped / Interleaved Separator);
    //   • extends ROT13 to ROT-1…ROT-25 over every quoted literal;
    //   • runs single-byte XOR unconditionally + adds 2/3/4-byte
    //     repeating-key crib analysis;
    //   • raises the secondary-finder wall-clock budget;
    //   • runs the new `interleaved-separator.js` finder for the
    //     `$\x00W\x00C\x00=…` / `a.b.c.d…` / `&#0;…` family.
    // Implies aggressive — every aggressive-only knob also fires.
    this._bruteforce = !!opts.bruteforce;
    if (this._bruteforce) this._aggressive = true;
    // Shared cumulative finder-budget object across the recursion tree.
    // The parent scan() lazily creates this on first use; child detectors
    // spawned by `_processCandidate` inherit the SAME reference (not a
    // copy) so total secondary-finder wall-clock is bounded by
    // FINDER_BUDGET_MS regardless of recursion depth. Without this, a
    // 5-deep UTF-16LE-PowerShell chain would burn 5 × 2.5 s = 12.5 s of
    // regex backtracking on the same shape of input at every layer.
    // Shape: { start: number, ms: number, exhausted: boolean, reason: string|null }
    this._finderBudget = opts._finderBudget || null;
  }


  // ── Helper: pick the right text decoder for a byte buffer ────────────────
  //
  // Recursion sites need to feed the inner detector a string, but the
  // bytes may be either UTF-8 or UTF-16LE depending on the encoding
  // chain. The canonical PowerShell `[Convert]::FromBase64String("…")`
  // shape produces UTF-16LE text every other byte (`H\x00e\x00…`).
  // Probing the first 64 bytes for a strong "every-other byte is 0x00"
  // signal lets us pick the correct decoder on the first try, without
  // relying on `_tryDecodeUTF8` rejecting the bytes via its NUL-control
  // heuristic (which works for ASCII-in-UTF16LE but is fragile for
  // other shapes — e.g. UTF-16LE with BOM, partially-mangled buffers,
  // or 1-byte-padded UTF-16LE that fails the even-length gate).
  // Falls back to UTF-8 → UTF-16LE → null in order; returns null if
  // neither yields a sufficiently long string.
  _decodeAsLikelyText(bytes, minLen = 32) {
    if (!bytes || bytes.length < minLen) return null;
    let nulEven = 0, nulOdd = 0;
    const sample = Math.min(64, bytes.length);
    for (let i = 0; i < sample; i++) {
      if (bytes[i] === 0) (i & 1 ? nulOdd++ : nulEven++);
    }
    const looksUTF16LE = nulOdd > sample * 0.4 || nulEven > sample * 0.4;
    if (looksUTF16LE && typeof this._tryDecodeUTF16LE === 'function') {
      const u16 = this._tryDecodeUTF16LE(bytes);
      if (u16 && u16.length > minLen) return u16;
    }
    const u8 = this._tryDecodeUTF8(bytes);
    if (u8 && u8.length > minLen) return u8;
    if (!looksUTF16LE && typeof this._tryDecodeUTF16LE === 'function') {
      const u16 = this._tryDecodeUTF16LE(bytes);
      if (u16 && u16.length > minLen) return u16;
    }
    return null;
  }

  // ── Helper: recursively prepend a chain prefix to a finding subtree ──
  //
  // `_processCandidate` builds an `innerFindings` array via a child
  // detector and needs to stamp its own `[candidate.type]` (the parent's
  // pre-classifier chain) onto every descendant's `chain` so the deepest
  // finding's `chain` reflects the FULL ancestor lineage from root to
  // leaf.
  //
  // The prior implementation only mutated direct children (a flat for-of
  // over `innerFindings`), so a chain of N nested peels surfaced as a
  // 3-element string `[parent, self, classifier]` at every grandchild —
  // visually capping the deobfuscation card at "2 layers" no matter how
  // deep the unwrap. The bug was hidden until the recursion-unblock fix
  // landed because pre-fix recursion stalled at depth 2 anyway.
  //
  // Recursive walk is safe because `innerFindings` is a tree (each
  // finding object is owned by exactly one parent's array; the detector
  // never aliases a finding into multiple parents).
  _prependChainRecursive(f, parentChain) {
    if (!f) return;
    f.chain = [...parentChain, ...(f.chain || [])];
    f.depth = (f.depth || 0) + 1;
    if (Array.isArray(f.innerFindings)) {
      for (const ch of f.innerFindings) {
        this._prependChainRecursive(ch, parentChain);
      }
    }
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
    // PowerShell anchor list — recognises the surfaces real-world PS
    // payloads actually start with after a Base64 → UTF-16LE unwrap:
    //   • $Var / function / param( — original keyword set;
    //   • IEX / Invoke-Expression / Invoke-Command (and the Verb-Noun
    //     cmdlet family using Microsoft's standard verbs from Get-Verb);
    //   • [scriptblock]::Create(...) and [System.*]::* / [Convert]::*
    //     style .NET calls used by the `[scriptblock]::Create(
    //     [System.Text.Encoding]::Unicode.GetString(
    //       [System.Convert]::FromBase64String("...")))` recursion shape.
    // Without this, layers 1..N of a recursive Unicode-base64 chain were
    // classified as generic 'UTF-16LE Text' (severity=info) and pruned.
    { pattern: /^\$[A-Za-z]|^function |^param\s*\(|^(?:I[Ee][Xx]|Invoke-|Get-|Set-|New-|Start-|Stop-|Add-|Out-|ConvertTo-|ConvertFrom-|Write-|Read-|Remove-|Test-|Select-|Where-|ForEach-|Import-|Export-|Enable-|Disable-|Register-|Unregister-)\b|^\[(?:scriptblock|System\.|Convert|Text\.Encoding|Reflection\.|Net\.|Diagnostics\.|IO\.)/i, ext: '.ps1', type: 'PowerShell' },
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
    // Bruteforce mode (kitchen-sink decode of an analyst-selected region)
    // gets a much fatter wall-clock budget — selections are by definition
    // small, so the regex-cost we're guarding against is bounded by input
    // size, not by the budget.
    const finderBudgetMs  = this._bruteforce
      ? 8_000
      : ((typeof PARSER_LIMITS !== 'undefined') ? PARSER_LIMITS.FINDER_BUDGET_MS : 2_500);

    // Cumulative budget: parent detector lazily creates a shared object
    // on first scan(); child detectors spawned during recursion inherit
    // the SAME reference via constructor `opts._finderBudget` so the
    // 2.5 s wall-clock spans the entire recursion tree, not 2.5 s per
    // depth (which would let a 5-layer chain burn 12.5 s of regex
    // backtracking on the same shape of UTF-16LE PowerShell text).
    // `isRootScan` is true only for the outermost detector — used below
    // to gate the single-stub diagnostic emission so child detectors
    // don't duplicate the breadcrumb at every recursion depth.
    const isRootScan = !this._finderBudget;
    if (isRootScan) {
      const startNow = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
      this._finderBudget = { start: startNow, ms: finderBudgetMs, exhausted: false, reason: null };
    }
    const budget          = this._finderBudget;
    const oversize        = (typeof textContent === 'string') && textContent.length > finderMaxBytes;
    if (oversize && !budget.reason) {
      budget.reason = `Encoded-content secondary scan skipped: text size ${textContent.length.toLocaleString()} bytes exceeds finder cap of ${finderMaxBytes.toLocaleString()} bytes`;
    }

    const _runFinder = (fn) => {
      if (oversize || budget.exhausted) return [];
      const now = (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now();
      if (now - budget.start > budget.ms) {
        budget.exhausted = true;
        if (!budget.reason) {
          budget.reason = `Encoded-content secondary scan truncated: cumulative finder budget of ${budget.ms} ms exhausted (partial coverage)`;
        }
        return [];
      }
      try {
        return fn.call(this, textContent, context) || [];
      } catch (err) {
        // Treat any per-finder failure (regex backtracking abort, etc.)
        // as a "skip the rest" signal — we'd rather lose secondary
        // coverage than hang the worker.
        if (err && err.name === 'AbortError') throw err;
        budget.exhausted = true;
        if (!budget.reason) {
          budget.reason = `Encoded-content secondary scan aborted: ${(err && err.message) || 'finder error'}`;
        }
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
    const psVarResCandidates     = _runFinder(this._findPsVariableResolutionCandidates);
    // JS string-array obfuscation resolver (obfuscator.io shape).
    // Defensively guarded so a missing prototype method doesn't blow up
    // the bundle if the mixin order regresses.
    const jsStringArrayCandidates = (typeof this._findJsStringArrayCandidates === 'function')
      ? _runFinder(this._findJsStringArrayCandidates)
      : [];
    // Bash / POSIX-shell obfuscation finder. Emits the same
    // `cmd-obfuscation` candidate shape as cmd-obfuscation.js and
    // ps-mini-evaluator.js so the `_processCommandObfuscation`
    // post-processor (severity scoring, IOC mirroring, ClickFix marks)
    // is reused unchanged. Defensively guarded against mixin-order
    // regressions.
    const bashObfCandidates       = (typeof this._findBashObfuscationCandidates === 'function')
      ? _runFinder(this._findBashObfuscationCandidates)
      : [];
    // Python obfuscation finder. Emits the same `cmd-obfuscation`
    // candidate shape (six branches: P1 zlib+base64 carrier, P2 marshal
    // loads, P3 codecs.decode, P4 char-array reassembly, P5 builtin
    // string-concat, P6 subprocess/os.system/socket sinks). Defensively
    // guarded against mixin-order regressions.
    const pyObfCandidates         = (typeof this._findPythonObfuscationCandidates === 'function')
      ? _runFinder(this._findPythonObfuscationCandidates)
      : [];
    // PHP webshell / dropper finder. Emits the same `cmd-obfuscation`
    // candidate shape (six branches: PHP1 eval(decoder-onion), PHP2
    // variable-variables, PHP3 chr/pack reassembly, PHP4 preg_replace
    // /e modifier, PHP5 superglobal eval, PHP6 data:/php:// stream
    // wrapper include). Defensively guarded.
    const phpObfCandidates        = (typeof this._findPhpObfuscationCandidates === 'function')
      ? _runFinder(this._findPhpObfuscationCandidates)
      : [];
    // JS additional obfuscator shapes — packer.js (Dean Edwards),
    // aaencode/jjencode (Hasegawa pure-symbol encoders), and
    // Function-wrapper carriers (Function(atob('...'))(),
    // Function(unescape('...'))(), Function.constructor RCE).
    // Defensively guarded against mixin-order regressions.
    const jsPackerCandidates      = (typeof this._findJsPackerCandidates === 'function')
      ? _runFinder(this._findJsPackerCandidates)
      : [];
    const jsAaJjCandidates        = (typeof this._findJsAaJjEncodeCandidates === 'function')
      ? _runFinder(this._findJsAaJjEncodeCandidates)
      : [];
    const jsFnWrapperCandidates   = (typeof this._findJsFunctionWrapperCandidates === 'function')
      ? _runFinder(this._findJsFunctionWrapperCandidates)
      : [];
    // Interleaved-separator finder (`$\x00W\x00C\x00=…`, `a.b.c.d…`,
    // `&#0;A&#0;B…`). Defensively guarded so a missing prototype method
    // doesn't blow up the bundle if the mixin order regresses.
    const interleavedCandidates  = (typeof this._findInterleavedSeparatorCandidates === 'function')
      ? _runFinder(this._findInterleavedSeparatorCandidates)
      : [];


    // Surface a single info-level finding so the analyst knows the
    // secondary scan ran in degraded mode. Without this, an oversize
    // input would silently miss URL-encoded / char-array / cmd-obfusc
    // matches with no breadcrumb in the sidebar. Only the outermost
    // (root) detector emits this stub — child detectors share the same
    // budget object and would otherwise duplicate the breadcrumb at
    // every recursion depth.
    if (isRootScan && budget.reason) {
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
        hint: budget.reason,
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
    for (const cand of interleavedCandidates) {
      const result = await this._processCandidate(cand, 0);
      if (result) findings.push(result);
    }
    for (const cand of cmdObfCandidates) {
      const result = await this._processCommandObfuscation(cand);
      if (result) findings.push(result);
    }
    for (const cand of psVarResCandidates) {
      const result = await this._processCommandObfuscation(cand);
      if (result) findings.push(result);
    }
    for (const cand of jsStringArrayCandidates) {
      const result = await this._processCommandObfuscation(cand);
      if (result) findings.push(result);
    }
    for (const cand of bashObfCandidates) {
      const result = await this._processCommandObfuscation(cand);
      if (result) findings.push(result);
    }
    for (const cand of pyObfCandidates) {
      const result = await this._processCommandObfuscation(cand);
      if (result) findings.push(result);
    }
    for (const cand of phpObfCandidates) {
      const result = await this._processCommandObfuscation(cand);
      if (result) findings.push(result);
    }
    for (const cand of jsPackerCandidates) {
      const result = await this._processCommandObfuscation(cand);
      if (result) findings.push(result);
    }
    for (const cand of jsAaJjCandidates) {
      const result = await this._processCommandObfuscation(cand);
      if (result) findings.push(result);
    }
    for (const cand of jsFnWrapperCandidates) {
      const result = await this._processCommandObfuscation(cand);
      if (result) findings.push(result);
    }
    for (const cand of compressedCandidates) {
      const result = await this._processCompressedCandidate(cand, rawBytes);
      if (result) findings.push(result);
    }

    // ── FP-suppression post-scan filter (PLAN: strict-default mode) ─────
    // In bruteforce / kitchen-sink mode the analyst has explicitly
    // selected a region they suspect is encoded — they want EVERY hit
    // including noisy ones, so the prune pass is skipped there. In all
    // other modes (default + aggressive), drop findings without IOCs,
    // recognized executable/script classifications, or exec-intent
    // keywords in their decoded text. See `_pruneFindings` for the full
    // retention predicate.
    if (!this._bruteforce) {
      return this._pruneFindings(findings);
    }

    return findings;
  }

  // ── FP-suppression post-scan filter ──────────────────────────────────────
  // Recursively walk the findings tree (top-level + every `innerFindings`
  // subtree) and drop any finding that doesn't satisfy at least one
  // retention rule:
  //   1. severity is `high` or `critical` (e.g. detected PE payload)
  //   2. has at least one extracted IOC (URL / IP / domain)
  //   3. classification matches `_RETAIN_CLASSIFICATIONS` (PE/ELF/script/
  //      archive/encrypted-packed)
  //   4. cmd-obfuscation finding whose deobfuscated text matches
  //      `SENSITIVE_CMD_KEYWORDS` (powershell, cmd, regsvr32, certutil…)
  //   5. decoded text matches `_EXEC_INTENT_RE` (LOLBin / cmdlet / URL
  //      vocabulary)
  //   6. has at least one surviving inner-finding child after recursive
  //      prune (so an intermediate carrier whose subtree contains a real
  //      hit is retained as the chain anchor)
  //
  // Children are pruned BEFORE the parent so rule 6 sees the post-prune
  // subtree. The `finder-budget` info stub is always retained — it's a
  // diagnostic breadcrumb, not a noise finding.
  _pruneFindings(findings) {
    if (!Array.isArray(findings) || findings.length === 0) return findings;
    const kept = [];
    for (const f of findings) {
      if (!f || typeof f !== 'object') continue;
      // Always retain the secondary-scan diagnostic stub.
      if (f.encoding === 'finder-budget') {
        kept.push(f);
        continue;
      }
      // Prune children first.
      if (Array.isArray(f.innerFindings) && f.innerFindings.length > 0) {
        f.innerFindings = this._pruneFindings(f.innerFindings);
      }
      if (this._shouldRetainFinding(f)) {
        kept.push(f);
      }
    }
    return kept;
  }

  _shouldRetainFinding(f) {
    // Rule 1: high/critical severity always survives.
    if (f.severity === 'high' || f.severity === 'critical') return true;
    // Rule 2: any IOC.
    if (Array.isArray(f.iocs) && f.iocs.length > 0) return true;
    // Rule 3: recognized classification.
    const ctype = f.classification && f.classification.type;
    if (ctype && _RETAIN_CLASSIFICATIONS.test(ctype)) return true;
    // Rule 4: cmd-obfuscation with sensitive cmd keywords in deobfuscated text.
    if (f.encoding === 'cmd-obfuscation') {
      const deob = (f.deobfuscated || f.decodedText || '');
      // SENSITIVE_CMD_KEYWORDS lives in cmd-obfuscation.js as a module
      // const; use _EXEC_INTENT_RE here as a superset that always covers
      // it (powershell, cmd.exe, regsvr32, certutil, mshta, etc.).
      if (deob && _EXEC_INTENT_RE.test(deob)) return true;
    }
    // Rule 5: exec-intent keyword in any text representation of the
    // decoded payload. Try: explicit deobfuscated text, decoded UTF-8
    // bytes, decoded UTF-16LE bytes (the canonical PowerShell
    // `[Convert]::FromBase64String("…")` of a Unicode-encoded payload
    // shape — without this fallback, `Invoke-Command` / `IEX` /
    // `frombase64string` keywords in UTF-16LE bytes are silently
    // invisible and the finding gets pruned), and the chain string
    // (covers the "PowerShell" / "Mach-O" chain entries).
    //
    // Both UTF-8 and UTF-16LE are tried unconditionally (not as
    // mutually-exclusive `if`/`else if`) because some byte buffers
    // decode validly under both — e.g. UTF-8 ASCII text containing an
    // embedded UTF-16LE PowerShell snippet — and we want the keyword
    // search to scan every plausible textual representation.
    const texts = [];
    if (f.deobfuscated) texts.push(f.deobfuscated);
    if (f.decodedText) texts.push(f.decodedText);
    if (f.decodedBytes && typeof this._tryDecodeUTF8 === 'function') {
      const t8 = this._tryDecodeUTF8(f.decodedBytes);
      if (t8) texts.push(t8);
      if (typeof this._tryDecodeUTF16LE === 'function') {
        const t16 = this._tryDecodeUTF16LE(f.decodedBytes);
        if (t16) texts.push(t16);
      }
    }
    if (Array.isArray(f.chain)) texts.push(f.chain.join(' '));
    for (const t of texts) {
      if (t && _EXEC_INTENT_RE.test(t)) return true;
    }
    // Rule 6: surviving inner-finding child.
    if (Array.isArray(f.innerFindings) && f.innerFindings.length > 0) return true;
    return false;
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

          // Recursively scan decompressed content for further encoding layers.
          // `_decodeAsLikelyText` shape-detects UTF-16LE (every-other byte 0x00)
          // and prefers it over UTF-8 when the signal is strong, so a
          // Base64 → zlib chain whose decompressed bytes happen to be
          // UTF-16LE PowerShell text actually unwraps on the first try.
          let decompInner = [];
          if (depth < this.maxRecursionDepth && decompData.length > 32) {
            const decompText = this._decodeAsLikelyText(decompData, 32);
            if (decompText && decompText.length > 32) {
              const innerDet = new EncodedContentDetector({
                maxRecursionDepth: this.maxRecursionDepth,
                maxCandidatesPerType: this.maxCandidatesPerType,
                aggressive: this._aggressive,
                bruteforce: this._bruteforce,
                _finderBudget: this._finderBudget,
              });
              decompInner = await innerDet.scan(decompText, decompData, { fileType: '' });
              // Recursive prepend so every descendant's chain reflects the
              // decompression layer, not just direct children.
              for (const f of decompInner) this._prependChainRecursive(f, decompChain);
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
      // FP-suppression: a generic "Encrypted/Packed Data" emission on
      // every high-entropy decode produces overwhelming noise on benign
      // hex finds (random IDs, UUIDs, cert fingerprints, hashes) and on
      // any compressed/encrypted blob that happens to land inside a B64
      // run. Only emit when:
      //   • bruteforce (kitchen-sink) mode — analyst opted in to noise;
      //   • surrounding source has XOR context (`_hasXorContext`) — the
      //     payload is plausibly the input to an XOR cipher; OR
      //   • the candidate carrier is one of the known XOR-wrapper types
      //     (Char Array / Hex (PS byte array)) — the packer family that
      //     typically wraps a high-entropy XOR payload as a byte array.
      const xorWrapperCarriers = new Set(['Char Array', 'Hex (PS byte array)']);
      const isXorWrapper = xorWrapperCarriers.has(candidate.type);
      const scanText = this._scanText || '';
      const ctxXor = scanText && typeof this._hasXorContext === 'function'
        && this._hasXorContext(scanText, candidate.offset, candidate.raw);
      if (!this._bruteforce && !isXorWrapper && !ctxXor) {
        return null;
      }
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
      // In bruteforce mode (kitchen-sink decode-selection), bypass both the
      // carrier whitelist and the XOR-context regex — try XOR against every
      // candidate's decoded bytes regardless of surrounding source.
      const xorCarrierOK = this._bruteforce || xorCarriers.has(candidate.type);
      if (xorCarrierOK && !cleartextLooksLikeText) {
        const scanText = this._scanText || '';
        const ctxOK = this._bruteforce
          || (scanText && this._hasXorContext(scanText, candidate.offset, candidate.raw));
        if (ctxOK) {
          let xorResult = null;
          try {
            xorResult = this._tryXorBruteforce(decoded);
            // Bruteforce mode also tries multi-byte (L=2,3,4) keys.
            if (!xorResult && this._bruteforce
                && typeof this._tryXorBruteforceMulti === 'function') {
              xorResult = this._tryXorBruteforceMulti(decoded);
            }
          } catch (_) { xorResult = null; }
          if (xorResult && xorResult.bytes && xorResult.bytes.length > 0) {
            const xorBytes = xorResult.bytes;
            const xorKey   = xorResult.key;
            // Single-byte key is a Number; multi-byte key is already a
            // pre-formatted '0x<HEX...>' string (see _tryXorBruteforceMulti).
            const keyHex   = (typeof xorKey === 'number')
              ? '0x' + xorKey.toString(16).toUpperCase().padStart(2, '0')
              : String(xorKey);
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
            // `_decodeAsLikelyText` shape-detects UTF-16LE so an XOR-revealed
            // PowerShell payload encoded in UTF-16LE unwraps on the first
            // try (rather than relying on `_tryDecodeUTF8` rejecting the
            // bytes via its NUL-control heuristic).
            let xorInner = [];
            if (depth < this.maxRecursionDepth && xorBytes.length > 32) {
              const xorText = this._decodeAsLikelyText(xorBytes, 32);
              if (xorText && xorText.length > 32) {
                const innerDet = new EncodedContentDetector({
                  maxRecursionDepth: this.maxRecursionDepth,
                  maxCandidatesPerType: this.maxCandidatesPerType,
                  aggressive: this._aggressive,
                  bruteforce: this._bruteforce,
                  _finderBudget: this._finderBudget,
                });
                xorInner = await innerDet.scan(xorText, xorBytes, { fileType: '' });
                // Recursive prepend so every descendant's chain reflects the
                // XOR layer, not just direct children.
                for (const f of xorInner) this._prependChainRecursive(f, xorChain);
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

    // Recursive scan: check if decoded content contains more encoding layers.
    // `_decodeAsLikelyText` shape-detects UTF-16LE (every-other-byte 0x00
    // signal in the first 64 bytes) and prefers it over UTF-8 when the
    // signal is strong, so canonical PowerShell recursion shapes —
    // `[Convert]::FromBase64String("…")` of a UTF-16LE-encoded payload,
    // used by the `[scriptblock]::Create([System.Text.Encoding]::
    // Unicode.GetString(...))` family — unwrap on the first try at every
    // depth. `_extractIOCsFromDecoded` does the same dual-decoder probe
    // for IOCs.
    let innerFindings = [];

    if (depth < this.maxRecursionDepth && decoded.length > 32) {
      const decodedText = this._decodeAsLikelyText(decoded, 32);
      if (decodedText && decodedText.length > 32) {
        const innerDetector = new EncodedContentDetector({
          maxRecursionDepth: this.maxRecursionDepth,
          maxCandidatesPerType: this.maxCandidatesPerType,
          aggressive: this._aggressive,
          bruteforce: this._bruteforce,
          // Share the parent's cumulative finder budget so total
          // secondary-finder wall-clock across the recursion tree is
          // bounded by FINDER_BUDGET_MS, not depth × FINDER_BUDGET_MS.
          _finderBudget: this._finderBudget,
        });
        innerFindings = await innerDetector.scan(decodedText, decoded, { fileType: '' });
        // Recursively prepend the parent's chain onto the entire descendant
        // subtree so a layer N+2 finding's chain reflects all of layer N,
        // N+1, N+2 — not just N+1+self. Without the recursion, every
        // grandchild capped at a 3-element chain `[parent, self, classifier]`
        // and the sidebar's "N layers" badge under-counted the true depth.
        for (const f of innerFindings) this._prependChainRecursive(f, chain);
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
