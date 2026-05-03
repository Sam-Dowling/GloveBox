'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/binary/elf-renderer.fuzz.js
//
// Fuzz `ElfRenderer.prototype.analyzeForSecurity(buffer, fileName)` —
// the security-analysis entry point invoked by
// `App._rendererDispatch.elf()` (`src/app/app-load.js:1367`).
// `_parse(bytes)` walks the full ELF tree: ELF header, program-header
// segments, section table, dynamic table, symbol tables (.dynsym /
// .symtab + matching .dynstr / .strtab), notes (PT_NOTE + SHT_NOTE),
// and the overlay scanner.
//
// `render()` is NOT exercised — it builds DOM via document.createElement
// which the vm.Context sandbox does not expose. The deep parsers all
// live in analyse, so coverage doesn't suffer.
//
// History (relevant fix-points fuzz aims to keep regression-free):
//   • 02b1592 — trust-tier + binaryClass gating to cut native-binary FPs
//   • 3ab47db — cut ELF/PE false-positive critical band on benign tools
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
    'src/renderers/elf-renderer.js',
  ],
  expose: ['IOC', 'ElfRenderer'],

  maxBytes: 8 * 1024 * 1024,
  perIterBudgetMs: 5_000,

  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    if (err.message.startsWith('parser-limit:')) return true;
    if (err.message.startsWith('aggregate-budget:')) return true;
    return false;
  },

  onIteration(ctx, data) {
    const { IOC, ElfRenderer } = ctx;
    if (!ElfRenderer) throw new Error('harness: ElfRenderer not exposed');
    if (VALID_IOC_VALUES.size === 0) {
      for (const v of Object.values(IOC)) VALID_IOC_VALUES.add(v);
    }

    const r = new ElfRenderer();
    const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    const findings = r.analyzeForSecurity(buf, 'fuzz.elf');

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
    if (findings.elfInfo !== undefined
        && findings.elfInfo !== null
        && typeof findings.elfInfo !== 'object') {
      throw new Error('invariant: findings.elfInfo neither null nor object');
    }
  },
});

const seeds = loadSeeds({
  dirs: ['elf'],
  perFileMaxBytes: 2 * 1024 * 1024,
  totalMaxBytes: 16 * 1024 * 1024,
  maxSeeds: 32,
});

// Synthetic minimal ELF64: e_ident magic + class=64 + data=LE +
// version=1 + osabi=SysV. e_type=ET_NONE, e_machine=0, e_version=1,
// e_entry/phoff/shoff=0, e_flags=0, e_ehsize=64, phnum=0, shnum=0.
// Drives a "header but no segments/sections" path the real fixtures
// don't reach.
function syntheticMinimalElf64() {
  const buf = Buffer.alloc(64);
  buf[0] = 0x7F; buf[1] = 0x45; buf[2] = 0x4C; buf[3] = 0x46; // \x7FELF
  buf[4] = 2;     // EI_CLASS = ELFCLASS64
  buf[5] = 1;     // EI_DATA  = ELFDATA2LSB
  buf[6] = 1;     // EI_VERSION
  buf[7] = 0;     // EI_OSABI = System V
  // e_type @ 0x10 = 0 (ET_NONE)
  // e_machine @ 0x12 = 0
  buf.writeUInt32LE(1, 0x14);  // e_version = 1
  // e_entry/phoff/shoff zero-filled
  buf.writeUInt16LE(64, 0x34); // e_ehsize = 64
  // phentsize/phnum/shentsize/shnum/shstrndx zero-filled
  return buf;
}

seeds.push(syntheticMinimalElf64());

module.exports = { fuzz, seeds, name: 'elf-renderer' };
