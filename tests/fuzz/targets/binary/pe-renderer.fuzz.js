'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/binary/pe-renderer.fuzz.js
//
// Fuzz `PeRenderer.prototype.analyzeForSecurity(buffer, fileName)` — the
// security-analysis entry point invoked by `App._rendererDispatch.pe()`
// (`src/app/app-load.js:1344`). The companion `render()` method is NOT
// exercised: it builds DOM via `document.createElement`, which the
// vm.Context sandbox does not provide.
//
// `analyzeForSecurity` invokes `_parse(bytes)` which walks the full PE
// structure tree — DOS header, COFF, optional header, data directories,
// section table, Rich header, imports, exports, resources, debug
// directory, TLS callbacks, certificate table, overlay. Every one of
// those parsers is in scope.
//
// Seed corpus:
//   • Real fixtures from `examples/pe/` (.exe, .dll, .xll). The renderer
//     gets exercised on the same byte streams it ships against.
//   • Mutator (Phase 0 dumb byte/header flipper from harness.js) drives
//     coverage from there.
//
// Invariants per iteration:
//   1. analyzeForSecurity returns an object with the documented shape
//      (risk ∈ {safe..critical}, arrays for the standard buckets).
//   2. No emitted externalRef.type sits outside the canonical IOC.* set.
//   3. No iteration exceeds the per-iter budget — caught by the harness.
//   4. Watchdog timeouts (`err._watchdogTimeout=true`) and explicitly
//      thrown parser-limit aborts are NOT crashes (they're the
//      documented PE-bomb defence).
//
// History (relevant fix-points fuzz aims to keep regression-free):
//   • 02b1592 — trust-tier + binaryClass gating to cut native-binary FPs
//   • 5516ee3 — resource-only DLL packing-risk FP
//   • <pending> — pin currentResult.yaraBuffer = buffer in pe()/elf()/macho()
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { loadSeeds } = require('../../helpers/seed-corpus.js');

const VALID_RISK = new Set(['safe', 'low', 'medium', 'high', 'critical']);
const VALID_IOC_VALUES = new Set();

const fuzz = defineFuzzTarget({
  // Canonical load order mirrors the binary-renderer prefix in
  // scripts/build.py § JS_FILES. Anything PeRenderer.analyzeForSecurity
  // touches must precede it. Static-analysis revealed the live deps
  // (analyse-time, not render-time) are: BinaryClass, BinaryOverlay,
  // BinaryStrings, BinaryExports, Capabilities, MITRE, TrustedCAs.
  modules: [
    'src/constants.js',
    'src/hashes.js',
    'src/mitre.js',
    'src/trusted-cas.js',
    'src/binary-class.js',
    'src/capabilities.js',
    'src/binary-overlay.js',
    'src/binary-strings.js',
    'src/binary-exports.js',
    'src/renderers/pe-renderer.js',
  ],
  expose: [
    'IOC',
    'PeRenderer',
    'BinaryClass',
    'Capabilities',
    'MITRE',
  ],

  // Real PE fixtures range up to ~5 MiB (examples/pe/signed-example.exe).
  // The Loupe production cap for the `pe` dispatch is
  // PARSER_LIMITS.MAX_FILE_BYTES_BY_DISPATCH.pe (256 MiB) — but for fuzz
  // we cap aggressively to keep iterations cheap. The mutator already
  // reaches "interesting" header-byte coverage at small sizes.
  maxBytes: 8 * 1024 * 1024,
  perIterBudgetMs: 5_000,

  // Parser-limit aborts and watchdog timeouts are documented defences,
  // not crashes. Harness already filters watchdog; explicitly whitelist
  // the parser-limit family.
  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    if (err.message.startsWith('parser-limit:')) return true;
    if (err.message.startsWith('aggregate-budget:')) return true;
    return false;
  },

  onIteration(ctx, data) {
    const { IOC, PeRenderer } = ctx;
    if (!PeRenderer) throw new Error('harness: PeRenderer not exposed');
    if (VALID_IOC_VALUES.size === 0) {
      for (const v of Object.values(IOC)) VALID_IOC_VALUES.add(v);
    }

    // Cheap MZ-magic gate: a Uint8Array starting with bytes other than
    // `M Z` (0x4D 0x5A) gets rejected by `_parse()` long before the
    // interesting structure walks. We let it through anyway — testing
    // the rejection path itself is valuable — but the mutator's
    // first-byte preservation strategy means most iterations DO reach
    // the deep parser code paths.
    const r = new PeRenderer();
    const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);

    let findings;
    try {
      findings = r.analyzeForSecurity(buf, 'fuzz.exe');
    } catch (err) {
      // Surface anything that ISN'T already filtered by isExpectedError.
      // The harness's catch block re-throws after stack-hashing; we just
      // need to NOT swallow.
      throw err;
    }

    // ── Invariant 1: shape ────────────────────────────────────────────
    if (!findings || typeof findings !== 'object') {
      throw new Error('invariant: analyzeForSecurity returned non-object');
    }
    if (typeof findings.risk !== 'string' || !VALID_RISK.has(findings.risk)) {
      throw new Error(`invariant: findings.risk ${JSON.stringify(findings.risk)} invalid`);
    }
    for (const k of ['externalRefs', 'autoExec', 'modules', 'interestingStrings']) {
      if (!Array.isArray(findings[k])) {
        throw new Error(`invariant: findings.${k} not array (got ${typeof findings[k]})`);
      }
    }
    if (findings.metadata && typeof findings.metadata !== 'object') {
      throw new Error('invariant: findings.metadata not object');
    }

    // ── Invariant 2: externalRef IOC.* type ───────────────────────────
    for (const ref of findings.externalRefs) {
      if (!ref || typeof ref !== 'object') {
        throw new Error('invariant: externalRef not object');
      }
      if (ref.type !== undefined && !VALID_IOC_VALUES.has(ref.type)) {
        throw new Error(
          `invariant: externalRef.type ${JSON.stringify(ref.type)} not in IOC.*`,
        );
      }
    }

    // ── Invariant 3: peInfo when present must be an object ────────────
    if (findings.peInfo !== null && typeof findings.peInfo !== 'object') {
      throw new Error('invariant: findings.peInfo neither null nor object');
    }
  },
});

// Real-fixture seeds: every PE under examples/pe/. The walker caps each
// at perFileMaxBytes (1 MiB by default) and the total at totalMaxBytes
// (4 MiB) — enough variety, bounded replay budget. Jazzer.js will copy
// these into its persistent corpus dir on first run.
const seeds = loadSeeds({
  dirs: ['pe'],
  perFileMaxBytes: 2 * 1024 * 1024,
  totalMaxBytes: 16 * 1024 * 1024,
  maxSeeds: 32,
});

// Synthetic minimal-PE seed: an MZ header + e_lfanew=0x40 → PE\0\0 →
// COFF { Machine=0x14C i386, NumberOfSections=0, TimeDateStamp=0,
// PointerToSymbolTable=0, NumberOfSymbols=0, SizeOfOptionalHeader=0,
// Characteristics=0 } → no optional header, no sections.
// Drives a path the real fixtures don't: zero-section PE.
function syntheticMinimalPe() {
  const buf = Buffer.alloc(0x60);
  buf[0] = 0x4D; buf[1] = 0x5A;            // 'MZ'
  buf.writeUInt32LE(0x40, 0x3C);            // e_lfanew
  buf[0x40] = 0x50; buf[0x41] = 0x45;       // 'PE'
  buf[0x42] = 0x00; buf[0x43] = 0x00;
  buf.writeUInt16LE(0x014C, 0x44);          // Machine = i386
  buf.writeUInt16LE(0x0000, 0x46);          // NumberOfSections = 0
  // Rest of COFF + optional header zero-filled.
  return buf;
}

seeds.push(syntheticMinimalPe());

module.exports = { fuzz, seeds, name: 'pe-renderer' };
