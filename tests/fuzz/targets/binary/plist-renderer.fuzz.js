'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/binary/plist-renderer.fuzz.js
//
// Fuzz `PlistRenderer.prototype.analyzeForSecurity(buffer, fileName)` —
// covers BOTH plist representations:
//   • Binary plist (bplist00 magic) — trailer-driven offset table walker.
//   • XML plist (`<?xml`/`<plist`) — full XML parser path.
// `PlistRenderer.detectFormat(bytes)` selects the branch.
//
// Heavy on length-field arithmetic for binary; safeRegex-driven for XML.
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { loadSeeds } = require('../../helpers/seed-corpus.js');

const VALID_RISK = new Set(['safe', 'low', 'medium', 'high', 'critical']);
const VALID_IOC_VALUES = new Set();

const fuzz = defineFuzzTarget({
  modules: [
    'src/constants.js',
    'src/renderers/plist-renderer.js',
  ],
  expose: ['IOC', 'PlistRenderer'],

  maxBytes: 8 * 1024 * 1024,
  perIterBudgetMs: 5_000,

  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    if (err.message.startsWith('parser-limit:')) return true;
    return false;
  },

  onIteration(ctx, data) {
    const { IOC, PlistRenderer } = ctx;
    if (!PlistRenderer) throw new Error('harness: PlistRenderer not exposed');
    if (VALID_IOC_VALUES.size === 0) {
      for (const v of Object.values(IOC)) VALID_IOC_VALUES.add(v);
    }

    const r = new PlistRenderer();
    const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    const findings = r.analyzeForSecurity(buf, 'fuzz.plist');

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
  },
});

const seeds = loadSeeds({
  dirs: ['macos-system'],
  extensions: ['plist'],
  perFileMaxBytes: 1 * 1024 * 1024,
  totalMaxBytes: 4 * 1024 * 1024,
  maxSeeds: 16,
});

// Synthetic minimal binary plist: "bplist00" magic + 32-byte trailer
// (offsetIntSize=1, objectRefSize=1, numObjects=1, topObject=0,
// offsetTableOffset=8). 40 bytes total. Drives the binary trailer
// parser without any real objects.
function syntheticMinimalBplist() {
  const buf = Buffer.alloc(40);
  buf.write('bplist00', 0, 'binary');
  // Trailer @ offset 8 (last 32 bytes):
  // 6 unused bytes, offsetIntSize=1, objectRefSize=1,
  // 8 bytes numObjects=1, 8 bytes topObject=0, 8 bytes offsetTableOffset=8
  buf[14] = 1;  // offsetIntSize
  buf[15] = 1;  // objectRefSize
  buf.writeBigUInt64BE(1n, 16);  // numObjects
  buf.writeBigUInt64BE(0n, 24);  // topObject
  buf.writeBigUInt64BE(8n, 32);  // offsetTableOffset (just past magic)
  return buf;
}

// Synthetic minimal XML plist
function syntheticMinimalXmlPlist() {
  return Buffer.from(
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    + '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
    + '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
    + '<plist version="1.0"><dict/></plist>\n',
    'utf8',
  );
}

seeds.push(syntheticMinimalBplist());
seeds.push(syntheticMinimalXmlPlist());

module.exports = { fuzz, seeds, name: 'plist-renderer' };
