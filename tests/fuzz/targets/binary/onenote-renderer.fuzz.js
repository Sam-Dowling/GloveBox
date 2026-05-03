'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/binary/onenote-renderer.fuzz.js
//
// Fuzz `OneNoteRenderer.prototype.analyzeForSecurity(buffer, fileName)`
// — async (QR decode of embedded image blobs). Walks the OneNote .one
// file format looking for FileDataStoreObject blocks: 16-byte GUID
// header + 8-byte size + payload. The payload classifier sniffs PE/
// ELF/Mach-O/script/HTA magic bytes — the high-severity branch flags
// known phishing-vector embedded executables.
//
// `QrDecoder` is conditionally referenced (typeof guard); not loaded
// here, so the QR sub-target is dormant. Without it the analyser still
// walks every embedded object and emits its IOCs.
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { loadSeeds } = require('../../helpers/seed-corpus.js');

const VALID_RISK = new Set(['safe', 'low', 'medium', 'high', 'critical']);
const VALID_IOC_VALUES = new Set();

const fuzz = defineFuzzTarget({
  modules: [
    'src/constants.js',
    'src/renderers/onenote-renderer.js',
  ],
  expose: ['IOC', 'OneNoteRenderer'],

  maxBytes: 4 * 1024 * 1024,
  perIterBudgetMs: 5_000,

  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    if (err.message.startsWith('parser-limit:')) return true;
    return false;
  },

  async onIteration(ctx, data) {
    const { IOC, OneNoteRenderer } = ctx;
    if (!OneNoteRenderer) throw new Error('harness: OneNoteRenderer not exposed');
    if (VALID_IOC_VALUES.size === 0) {
      for (const v of Object.values(IOC)) VALID_IOC_VALUES.add(v);
    }

    const r = new OneNoteRenderer();
    const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    const findings = await r.analyzeForSecurity(buf, 'fuzz.one');

    if (!findings || typeof findings !== 'object') {
      throw new Error('invariant: analyzeForSecurity returned non-object');
    }
    if (typeof findings.risk !== 'string' || !VALID_RISK.has(findings.risk)) {
      throw new Error(`invariant: findings.risk ${JSON.stringify(findings.risk)} invalid`);
    }
    for (const k of ['externalRefs', 'autoExec', 'modules', 'signatureMatches']) {
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
  dirs: ['onenote'],
  perFileMaxBytes: 2 * 1024 * 1024,
  totalMaxBytes: 8 * 1024 * 1024,
  maxSeeds: 8,
});

// Synthetic minimal OneNote: 16-byte file-type GUID then nothing.
// Drives the "header but no FileDataStoreObject" path.
function syntheticMinimalOneNote() {
  // OneNote section file GUID (.one): {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
  // Stored as little-endian {Data1: u32, Data2: u16, Data3: u16, Data4: u8[8]}
  const buf = Buffer.alloc(16);
  buf.writeUInt32LE(0x7B5C52E4, 0);
  buf.writeUInt16LE(0xD88C,     4);
  buf.writeUInt16LE(0x4DA7,     6);
  buf[8]  = 0xAE; buf[9]  = 0xB1;
  buf[10] = 0x53; buf[11] = 0x78;
  buf[12] = 0xD0; buf[13] = 0x29;
  buf[14] = 0x96; buf[15] = 0xD3;
  return buf;
}

seeds.push(syntheticMinimalOneNote());

module.exports = { fuzz, seeds, name: 'onenote-renderer' };
