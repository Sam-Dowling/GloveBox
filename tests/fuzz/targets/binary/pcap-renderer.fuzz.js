'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/binary/pcap-renderer.fuzz.js
//
// Fuzz `PcapRenderer.prototype.analyzeForSecurity(buffer, fileName)` —
// the security-analysis entry point invoked by
// `App._rendererDispatch.pcap()`. It chains:
//   PcapRenderer._parse(bytes)            ← static; walks libpcap + pcapng
//   PcapRenderer._analyzePcapInfo(parsed) ← static; risk + IOC emit
//
// Only `analyzeForSecurity` is in scope — `render()` builds DOM. All
// deep parsing happens in the two static helpers above.
//
// The pcap parser handles four wire formats (libpcap LE/BE, pcapng LE/BE)
// plus per-packet decoders for Ethernet / IPv4 / IPv6 / TCP / UDP / DNS.
// Heavy header arithmetic; ideal fuzz target.
//
// History (relevant fix-points):
//   • 7a4a169 — cap PCAPNG block walk to bound non-packet padding
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { loadSeeds } = require('../../helpers/seed-corpus.js');

const VALID_RISK = new Set(['safe', 'low', 'medium', 'high', 'critical']);
const VALID_IOC_VALUES = new Set();

const fuzz = defineFuzzTarget({
  // PcapRenderer references EvtxDetector by name (typeof guard) only on
  // the timeline hybrid path. analyzeForSecurity itself is self-contained
  // — only IOC/pushIOC/escalateRisk/throwIfAborted/lfNormalize from
  // constants.js.
  modules: [
    'src/constants.js',
    'src/renderers/pcap-renderer.js',
  ],
  expose: ['IOC', 'PcapRenderer'],

  maxBytes: 8 * 1024 * 1024,
  perIterBudgetMs: 5_000,

  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    if (err.message.startsWith('parser-limit:')) return true;
    if (err.message.startsWith('aggregate-budget:')) return true;
    return false;
  },

  onIteration(ctx, data) {
    const { IOC, PcapRenderer } = ctx;
    if (!PcapRenderer) throw new Error('harness: PcapRenderer not exposed');
    if (VALID_IOC_VALUES.size === 0) {
      for (const v of Object.values(IOC)) VALID_IOC_VALUES.add(v);
    }

    const r = new PcapRenderer();
    const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    const findings = r.analyzeForSecurity(buf, 'fuzz.pcap');

    if (!findings || typeof findings !== 'object') {
      throw new Error('invariant: analyzeForSecurity returned non-object');
    }
    if (typeof findings.risk !== 'string' || !VALID_RISK.has(findings.risk)) {
      throw new Error(`invariant: findings.risk ${JSON.stringify(findings.risk)} invalid`);
    }
    for (const k of ['externalRefs', 'detections', 'capabilities', 'interestingStrings']) {
      if (!Array.isArray(findings[k])) {
        throw new Error(`invariant: findings.${k} not array (got ${typeof findings[k]})`);
      }
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
  dirs: ['forensics'],
  extensions: ['pcap', 'pcapng'],
  perFileMaxBytes: 2 * 1024 * 1024,
  totalMaxBytes: 8 * 1024 * 1024,
  maxSeeds: 16,
});

// Synthetic minimal libpcap (little-endian): magic 0xA1B2C3D4 + version
// 2.4 + thiszone 0 + sigfigs 0 + snaplen 65535 + network 1 (Ethernet).
// 24-byte global header followed by zero packet records — drives the
// "valid header, no packets" path the real fixture doesn't touch.
function syntheticEmptyPcapLE() {
  const buf = Buffer.alloc(24);
  buf.writeUInt32LE(0xA1B2C3D4, 0);
  buf.writeUInt16LE(2,          4);   // version_major
  buf.writeUInt16LE(4,          6);   // version_minor
  buf.writeInt32LE(0,           8);   // thiszone
  buf.writeUInt32LE(0,          12);  // sigfigs
  buf.writeUInt32LE(65535,      16);  // snaplen
  buf.writeUInt32LE(1,          20);  // network = LINKTYPE_ETHERNET
  return buf;
}

// Synthetic minimal pcapng: SHB (Section Header Block) only.
//   block_type = 0x0A0D0D0A
//   block_total_length = 28
//   byte_order_magic = 0x1A2B3C4D
//   version_major/minor = 1/0
//   section_length = -1 (unknown)
//   block_total_length (trailer) = 28
function syntheticEmptyPcapng() {
  const buf = Buffer.alloc(28);
  buf.writeUInt32LE(0x0A0D0D0A, 0);
  buf.writeUInt32LE(28,         4);
  buf.writeUInt32LE(0x1A2B3C4D, 8);
  buf.writeUInt16LE(1,          12);
  buf.writeUInt16LE(0,          14);
  // section_length = -1 (0xFFFFFFFFFFFFFFFF, 8 bytes)
  buf.writeInt32LE(-1,          16);
  buf.writeInt32LE(-1,          20);
  buf.writeUInt32LE(28,         24);
  return buf;
}

seeds.push(syntheticEmptyPcapLE());
seeds.push(syntheticEmptyPcapng());

module.exports = { fuzz, seeds, name: 'pcap-renderer' };
