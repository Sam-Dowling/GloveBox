'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/binary/lnk-renderer.fuzz.js
//
// Fuzz `LnkRenderer.prototype.analyzeForSecurity(buffer)` — walks the
// Windows Shell Link (.lnk) format: ShellLinkHeader → optional LinkInfo
// → optional StringData (NAME/RELATIVE_PATH/WORKING_DIR/COMMAND_LINE_
// ARGUMENTS/ICON_LOCATION) → ExtraData (TrackerDataBlock with machineId
// + birthMac/etc.). Heavy length-prefix arithmetic; classic LNK-malware
// surface.
//
// The signature is `analyzeForSecurity(buffer)` — no fileName arg.
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { loadSeeds } = require('../../helpers/seed-corpus.js');

const VALID_RISK = new Set(['safe', 'low', 'medium', 'high', 'critical']);
const VALID_IOC_VALUES = new Set();

const fuzz = defineFuzzTarget({
  modules: [
    'src/constants.js',
    'src/renderers/lnk-renderer.js',
  ],
  expose: ['IOC', 'LnkRenderer'],

  maxBytes: 4 * 1024 * 1024,
  perIterBudgetMs: 5_000,

  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    if (err.message.startsWith('parser-limit:')) return true;
    return false;
  },

  onIteration(ctx, data) {
    const { IOC, LnkRenderer } = ctx;
    if (!LnkRenderer) throw new Error('harness: LnkRenderer not exposed');
    if (VALID_IOC_VALUES.size === 0) {
      for (const v of Object.values(IOC)) VALID_IOC_VALUES.add(v);
    }

    const r = new LnkRenderer();
    const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    const findings = r.analyzeForSecurity(buf);

    if (!findings || typeof findings !== 'object') {
      throw new Error('invariant: analyzeForSecurity returned non-object');
    }
    if (typeof findings.risk !== 'string' || !VALID_RISK.has(findings.risk)) {
      throw new Error(`invariant: findings.risk ${JSON.stringify(findings.risk)} invalid`);
    }
    for (const k of ['externalRefs', 'autoExec', 'modules']) {
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
  },
});

const seeds = loadSeeds({
  dirs: ['windows-scripts'],
  extensions: ['lnk'],
  perFileMaxBytes: 1 * 1024 * 1024,
  totalMaxBytes: 4 * 1024 * 1024,
  maxSeeds: 16,
});

// Synthetic minimal valid LNK header: HeaderSize=0x4C + LinkCLSID
// 00021401-0000-0000-C000-000000000046 + LinkFlags=0 + everything-else=0.
// 76 bytes total. Drives a "valid header, no LinkInfo, no StringData,
// no ExtraData" path the real fixture won't hit.
function syntheticMinimalLnk() {
  const buf = Buffer.alloc(0x4C);
  buf.writeUInt32LE(0x4C, 0);   // HeaderSize
  // LinkCLSID @ offset 4, 16 bytes (mixed endian per MS-SHLLINK)
  buf.writeUInt32LE(0x00021401, 4);
  buf.writeUInt16LE(0,          8);
  buf.writeUInt16LE(0,          10);
  buf[12] = 0xC0; buf[13] = 0; buf[14] = 0; buf[15] = 0;
  buf[16] = 0;    buf[17] = 0; buf[18] = 0; buf[19] = 0;
  buf[20] = 0x46; // …rest of the CLSID GUID tail-byte
  // LinkFlags @ 0x14, FileAttributes @ 0x18, times @ 0x1C..0x33,
  // FileSize @ 0x34, IconIndex @ 0x38, ShowCommand @ 0x3C,
  // HotKey @ 0x40, Reserved... — all zero.
  return buf;
}

seeds.push(syntheticMinimalLnk());

module.exports = { fuzz, seeds, name: 'lnk-renderer' };
