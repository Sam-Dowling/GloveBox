'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/binary/macho-renderer.fuzz.js
//
// Fuzz `MachoRenderer.prototype.analyzeForSecurity(buffer, fileName)` —
// the security-analysis entry point invoked by
// `App._rendererDispatch.macho()` (`src/app/app-load.js:1381`).
//
// Mach-O has TWO entry magics fuzz must exercise:
//   • Thin Mach-O (32/64-bit, LE/BE): 0xFEEDFACE / 0xFEEDFACF (and BE).
//   • Fat / Universal: 0xCAFEBABE / 0xBEBAFECA — `_parseFatHeader` walks
//     the arch table, picks a preferred slice, then `_parse(bytes,
//     offset)` walks the embedded Mach-O image.
// `analyzeForSecurity` wraps the entire parse in try/catch + escalateRisk
// — same pattern as PE / ELF — so it never throws to the caller. Any
// throw escaping the function is a real fuzz finding.
//
// History (relevant fix-points fuzz aims to keep regression-free):
//   • <pending> — pin currentResult.yaraBuffer = buffer in macho() route
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { loadSeeds } = require('../../helpers/seed-corpus.js');

const VALID_RISK = new Set(['safe', 'low', 'medium', 'high', 'critical']);
const VALID_IOC_VALUES = new Set();

const fuzz = defineFuzzTarget({
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
    'src/renderers/macho-renderer.js',
  ],
  expose: ['IOC', 'MachoRenderer'],

  maxBytes: 8 * 1024 * 1024,
  perIterBudgetMs: 5_000,

  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    if (err.message.startsWith('parser-limit:')) return true;
    if (err.message.startsWith('aggregate-budget:')) return true;
    return false;
  },

  onIteration(ctx, data) {
    const { IOC, MachoRenderer } = ctx;
    if (!MachoRenderer) throw new Error('harness: MachoRenderer not exposed');
    if (VALID_IOC_VALUES.size === 0) {
      for (const v of Object.values(IOC)) VALID_IOC_VALUES.add(v);
    }

    const r = new MachoRenderer();
    const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    const findings = r.analyzeForSecurity(buf, 'fuzz.macho');

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
    if (findings.machoInfo !== null && typeof findings.machoInfo !== 'object') {
      throw new Error('invariant: findings.machoInfo neither null nor object');
    }
  },
});

const seeds = loadSeeds({
  // examples/macos-system holds .dylib + .plist + .pkg + .dmg etc.
  // The plist/pkg/dmg fixtures will fail magic-byte gating cheaply,
  // exercising the early-throw path. Cheap and useful.
  dirs: ['macos-system'],
  perFileMaxBytes: 2 * 1024 * 1024,
  totalMaxBytes: 16 * 1024 * 1024,
  maxSeeds: 32,
});

// Synthetic minimal thin Mach-O 64 (little-endian): magic=0xFEEDFACF,
// cputype=0x01000007 (X86_64), cpusubtype=3 (ALL), filetype=2 (MH_EXECUTE),
// ncmds=0, sizeofcmds=0, flags=0, reserved=0. 32 bytes total — a header
// with zero load commands. Drives a path the real fixtures don't.
function syntheticMinimalMacho64() {
  const buf = Buffer.alloc(32);
  buf.writeUInt32LE(0xFEEDFACF, 0);   // magic
  buf.writeUInt32LE(0x01000007, 4);   // cputype = X86_64
  buf.writeUInt32LE(0x00000003, 8);   // cpusubtype
  buf.writeUInt32LE(0x00000002, 12);  // filetype = MH_EXECUTE
  buf.writeUInt32LE(0,          16);  // ncmds
  buf.writeUInt32LE(0,          20);  // sizeofcmds
  buf.writeUInt32LE(0,          24);  // flags
  buf.writeUInt32LE(0,          28);  // reserved (64-bit only)
  return buf;
}

// Synthetic minimal Fat header: magic=0xCAFEBABE (BE), nfat_arch=0.
// Drives the `Fat binary has no architecture slices` early throw path
// (which `analyzeForSecurity` catches and downgrades — never escapes).
function syntheticEmptyFat() {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(0xCAFEBABE, 0);
  buf.writeUInt32BE(0, 4);
  return buf;
}

seeds.push(syntheticMinimalMacho64());
seeds.push(syntheticEmptyFat());

module.exports = { fuzz, seeds, name: 'macho-renderer' };
