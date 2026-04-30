'use strict';
// pcap-renderer.test.js — libpcap + PCAPNG parser & security analyser.
//
// All fixtures are hand-built byte arrays so the tests exercise the
// parser end-to-end without any vendored sample. Build helpers below
// emit byte arrays for: ethernet + IPv4 + UDP + DNS query, ethernet +
// IPv4 + TCP + HTTP request, ethernet + IPv4 + TCP + TLS ClientHello
// (with SNI). All multi-byte integers use big-endian on the wire as
// specified by the relevant RFC; the libpcap header itself we generate
// in little-endian (the common modern default).

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(
  ['src/constants.js', 'src/renderers/pcap-renderer.js'],
  { expose: ['PcapRenderer', 'IOC', 'escalateRisk', 'pushIOC', 'lfNormalize'] },
);
const { PcapRenderer, IOC } = ctx;

// ── Builders ──────────────────────────────────────────────────────────────

function u16be(n) { return [(n >> 8) & 0xff, n & 0xff]; }
function u32le(n) {
  return [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >> 24) & 0xff];
}
function u32be(n) {
  return [(n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
}
function asciiBytes(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i) & 0xff);
  return out;
}

// libpcap global header (LE, μs, snaplen=65535, linktype=1=ETHERNET).
function pcapHeaderLE(linktype = 1) {
  return [
    0xd4, 0xc3, 0xb2, 0xa1,  // magic LE μs
    ...u16be(0), 0x02, 0,     // major=2 (LE bytes: 02 00)
    0, 0, 0x04, 0,            // minor=4 (LE bytes: 04 00) — ah wait, u16 LE = lsb first
  ].slice(0, 8).concat([
    // Re-do properly using LE u16:
  ]);
}

// Cleaner helper — build the full 24-byte global header LE.
function pcapGlobalHeaderLE(linktype) {
  return [
    0xd4, 0xc3, 0xb2, 0xa1,
    0x02, 0x00,                                  // major = 2
    0x04, 0x00,                                  // minor = 4
    0, 0, 0, 0,                                  // thiszone
    0, 0, 0, 0,                                  // sigfigs
    0xff, 0xff, 0, 0,                            // snaplen 65535
    ...u32le(linktype),
  ];
}

// Per-packet record header (LE).
function pcapRecordHeaderLE(tsSec, payloadLen) {
  return [
    ...u32le(tsSec),
    0, 0, 0, 0,                  // ts_usec
    ...u32le(payloadLen),        // incl_len
    ...u32le(payloadLen),        // orig_len
  ];
}

// Ethernet II frame: dst MAC, src MAC, ethertype.
function ethHdr(ethertype) {
  return [
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,   // dst
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,   // src
    ...u16be(ethertype),
  ];
}

// Minimal IPv4 header: 20 bytes, IHL=5, TTL=64, given proto + src + dst.
// totalLen MUST equal 20 + payloadLen.
function ipv4Hdr(proto, srcOctets, dstOctets, payloadLen) {
  const totalLen = 20 + payloadLen;
  return [
    0x45, 0x00,
    ...u16be(totalLen),
    0, 0, 0, 0,                                  // id, flags, frag
    64, proto,
    0, 0,                                        // checksum (ignored)
    ...srcOctets,
    ...dstOctets,
  ];
}

// UDP header: src port, dst port, length, checksum.
function udpHdr(sport, dport, payloadLen) {
  return [
    ...u16be(sport),
    ...u16be(dport),
    ...u16be(8 + payloadLen),
    0, 0,
  ];
}

// TCP header (20 bytes, no options). data_offset=5 (×4 = 20).
function tcpHdr(sport, dport) {
  return [
    ...u16be(sport),
    ...u16be(dport),
    0, 0, 0, 1,                  // seq
    0, 0, 0, 0,                  // ack
    0x50, 0x18,                  // data offset 5, flags PSH+ACK
    0xff, 0xff,                  // window
    0, 0, 0, 0,                  // checksum + urg
  ];
}

// DNS query for `name`. Returns the DNS payload bytes (no UDP header).
function dnsQuery(name) {
  // Header: id(2) flags(2)=0x0100 qd=1 an=0 ns=0 ar=0
  const hdr = [
    0x12, 0x34,
    0x01, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  ];
  const labels = [];
  for (const part of name.split('.')) {
    labels.push(part.length);
    labels.push(...asciiBytes(part));
  }
  labels.push(0);
  // QTYPE=A(1), QCLASS=IN(1)
  const qfooter = [0, 1, 0, 1];
  return [...hdr, ...labels, ...qfooter];
}

// Build an HTTP request with a Host header.
function httpRequest(host, extraHeaders = '') {
  return asciiBytes(
    `GET /index.html HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: test\r\n${extraHeaders}\r\n`,
  );
}

// Build a TLS ClientHello with a single SNI extension. Wraps in a
// TLS record header. `host` is the server name.
function tlsClientHello(host) {
  const hostBytes = asciiBytes(host);
  // SNI extension data:
  //   server_name_list_len(2) name_type(1)=0 name_len(2) name_bytes
  const sniData = [
    ...u16be(3 + hostBytes.length),
    0,
    ...u16be(hostBytes.length),
    ...hostBytes,
  ];
  // Extension wrapper: type(2)=0 data_len(2) data
  const sniExt = [
    0, 0,
    ...u16be(sniData.length),
    ...sniData,
  ];
  // ClientHello body:
  //   version(2)=0x0303  random(32)  sid_len(1)=0
  //   cipher_suites_len(2)=2 ciphers(2)
  //   compression_len(1)=1 comp(1)
  //   extensions_len(2) extensions
  const body = [
    0x03, 0x03,
    ...new Array(32).fill(0),
    0,
    0, 2, 0x13, 0x01,
    1, 0,
    ...u16be(sniExt.length),
    ...sniExt,
  ];
  // Handshake header: type(1)=1 length(3)
  const hs = [
    1,
    (body.length >> 16) & 0xff,
    (body.length >> 8) & 0xff,
    body.length & 0xff,
    ...body,
  ];
  // TLS record header: type(1)=22 version(2)=0x0303 length(2)
  return [
    22,
    0x03, 0x03,
    ...u16be(hs.length),
    ...hs,
  ];
}

function bufFrom(arr) {
  return new Uint8Array(arr).buffer;
}

// ── Parser tests ──────────────────────────────────────────────────────────

test('pcap: too-small input → parse error', () => {
  const parsed = PcapRenderer._parse(new Uint8Array([0xd4, 0xc3]));
  assert.equal(parsed.kind, null);
  assert.match(parsed.error, /too small/i);
});

test('pcap: bad magic → parse error', () => {
  const parsed = PcapRenderer._parse(new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]));
  assert.equal(parsed.kind, null);
  assert.match(parsed.error, /bad magic/i);
});

test('pcap: classic LE μs header parses cleanly with no packets', () => {
  const bytes = new Uint8Array(pcapGlobalHeaderLE(1));
  const parsed = PcapRenderer._parse(bytes);
  assert.equal(parsed.kind, 'pcap');
  assert.equal(parsed.linktype, 1);
  assert.equal(parsed.linktypeName, 'ETHERNET');
  assert.equal(parsed.snaplen, 65535);
  assert.equal(parsed.packetCount, 0);
  assert.equal(parsed.error, null);
});

test('pcap: BE μs magic recognised', () => {
  const bytes = new Uint8Array([
    0xa1, 0xb2, 0xc3, 0xd4,
    0, 2, 0, 4,                         // major/minor BE
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0xff, 0xff,                   // snaplen BE
    0, 0, 0, 1,                         // linktype BE = 1
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.equal(parsed.kind, 'pcap');
  assert.equal(parsed.linktype, 1);
  assert.match(parsed.formatLabel, /big-endian/);
});

test('pcap: nanosecond magic recognised', () => {
  const bytes = new Uint8Array([
    0x4d, 0x3c, 0xb2, 0xa1,
    0x02, 0x00, 0x04, 0x00,
    0, 0, 0, 0, 0, 0, 0, 0,
    0xff, 0xff, 0, 0,
    1, 0, 0, 0,
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.equal(parsed.kind, 'pcap');
  assert.match(parsed.formatLabel, /ns,.*little-endian/);
});

test('pcap: corrupt incl_len bails with error, no infinite loop', () => {
  const bytes = new Uint8Array([
    ...pcapGlobalHeaderLE(1),
    // Record claiming a 1 GiB packet — exceeds MAX_PACKET_BYTES.
    ...u32le(1),
    0, 0, 0, 0,
    ...u32le(0x40000000),
    ...u32le(0x40000000),
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.equal(parsed.kind, 'pcap');
  assert.match(parsed.error, /MAX_PACKET_BYTES|incl_len/);
});

test('pcap: truncated packet payload → parse warning, partial result', () => {
  const bytes = new Uint8Array([
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000000, 100),
    // …no body bytes follow, so the record is truncated.
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.equal(parsed.kind, 'pcap');
  assert.match(parsed.error, /truncated/i);
  assert.equal(parsed.packetCount, 0);
});

// ── App-layer extraction (DNS) ───────────────────────────────────────────

test('pcap: DNS query name extracted', () => {
  const dns = dnsQuery('evil.example.com');
  const udp = udpHdr(54321, 53, dns.length);
  const ip = ipv4Hdr(17, [10, 0, 0, 1], [8, 8, 8, 8], udp.length + dns.length);
  const eth = ethHdr(0x0800);
  const packet = [...eth, ...ip, ...udp, ...dns];
  const bytes = new Uint8Array([
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000000, packet.length),
    ...packet,
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.equal(parsed.packetCount, 1);
  assert.deepEqual(parsed.dnsNames, ['evil.example.com']);
  assert.equal(parsed.ipCounts.get('10.0.0.1'), 1);
  assert.equal(parsed.ipCounts.get('8.8.8.8'), 1);
});

test('pcap: garbage DNS payload doesn\'t pollute IOCs', () => {
  // UDP/53 packet with non-ASCII label bytes — must be rejected.
  const garbage = [
    0x12, 0x34, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    5, 0x80, 0x81, 0x82, 0x83, 0x84,    // label with non-ASCII bytes
    0,
    0, 1, 0, 1,
  ];
  const udp = udpHdr(54321, 53, garbage.length);
  const ip = ipv4Hdr(17, [10, 0, 0, 2], [8, 8, 8, 8], udp.length + garbage.length);
  const eth = ethHdr(0x0800);
  const packet = [...eth, ...ip, ...udp, ...garbage];
  const bytes = new Uint8Array([
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000000, packet.length),
    ...packet,
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.deepEqual(parsed.dnsNames, []);
});

// ── App-layer extraction (HTTP) ──────────────────────────────────────────

test('pcap: HTTP Host header extracted', () => {
  const http = httpRequest('phish.example.test');
  const tcp = tcpHdr(50000, 80);
  const ip = ipv4Hdr(6, [10, 0, 0, 5], [203, 0, 113, 7], tcp.length + http.length);
  const eth = ethHdr(0x0800);
  const packet = [...eth, ...ip, ...tcp, ...http];
  const bytes = new Uint8Array([
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000001, packet.length),
    ...packet,
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.deepEqual(parsed.httpHosts, ['phish.example.test']);
  assert.equal(parsed.httpBasicAuthCount, 0);
});

test('pcap: HTTP Authorization Basic increments counter', () => {
  const http = httpRequest('login.example.test', 'Authorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n');
  const tcp = tcpHdr(50001, 80);
  const ip = ipv4Hdr(6, [10, 0, 0, 6], [203, 0, 113, 8], tcp.length + http.length);
  const eth = ethHdr(0x0800);
  const packet = [...eth, ...ip, ...tcp, ...http];
  const bytes = new Uint8Array([
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000002, packet.length),
    ...packet,
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.deepEqual(parsed.httpHosts, ['login.example.test']);
  assert.equal(parsed.httpBasicAuthCount, 1);
});

test('pcap: HTTP response (not request) is ignored', () => {
  const respBody = asciiBytes('HTTP/1.1 200 OK\r\nServer: nginx\r\nHost: spoofed.example\r\n\r\n');
  const tcp = tcpHdr(80, 50000);
  const ip = ipv4Hdr(6, [203, 0, 113, 9], [10, 0, 0, 7], tcp.length + respBody.length);
  const eth = ethHdr(0x0800);
  const packet = [...eth, ...ip, ...tcp, ...respBody];
  const bytes = new Uint8Array([
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000003, packet.length),
    ...packet,
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.deepEqual(parsed.httpHosts, []);
});

// ── App-layer extraction (TLS SNI) ───────────────────────────────────────

test('pcap: TLS ClientHello SNI extracted', () => {
  const tls = tlsClientHello('login.example.com');
  const tcp = tcpHdr(60001, 443);
  const ip = ipv4Hdr(6, [10, 0, 0, 8], [198, 51, 100, 25], tcp.length + tls.length);
  const eth = ethHdr(0x0800);
  const packet = [...eth, ...ip, ...tcp, ...tls];
  const bytes = new Uint8Array([
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000004, packet.length),
    ...packet,
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.deepEqual(parsed.tlsSnis, ['login.example.com']);
});

test('pcap: telnet/FTP traffic flagged', () => {
  const payload = asciiBytes('login: \r\n');
  const tcp = tcpHdr(60002, 23);
  const ip = ipv4Hdr(6, [10, 0, 0, 9], [203, 0, 113, 50], tcp.length + payload.length);
  const eth = ethHdr(0x0800);
  const pkt23 = [...eth, ...ip, ...tcp, ...payload];

  const tcp21 = tcpHdr(60003, 21);
  const ip21 = ipv4Hdr(6, [10, 0, 0, 10], [203, 0, 113, 51], tcp21.length + payload.length);
  const pkt21 = [...eth, ...ip21, ...tcp21, ...payload];

  const bytes = new Uint8Array([
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000005, pkt23.length), ...pkt23,
    ...pcapRecordHeaderLE(1700000005, pkt21.length), ...pkt21,
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.equal(parsed.telnetSeen, true);
  assert.equal(parsed.ftpSeen, true);
});

test('pcap: VLAN-tagged ethernet frame still routes IPv4', () => {
  const dns = dnsQuery('vlan.example.test');
  const udp = udpHdr(54321, 53, dns.length);
  const ip = ipv4Hdr(17, [10, 0, 0, 11], [8, 8, 4, 4], udp.length + dns.length);
  // Ethernet header + 802.1Q VLAN tag.
  const eth = [
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    ...u16be(0x8100),
    0, 100,                                      // VLAN id 100, prio 0
    ...u16be(0x0800),                            // inner ethertype IPv4
  ];
  const packet = [...eth, ...ip, ...udp, ...dns];
  const bytes = new Uint8Array([
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000006, packet.length),
    ...packet,
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.deepEqual(parsed.dnsNames, ['vlan.example.test']);
});

test('pcap: linktype RAW (101) decodes IP directly without ethernet', () => {
  const dns = dnsQuery('raw.example.test');
  const udp = udpHdr(54321, 53, dns.length);
  const ip = ipv4Hdr(17, [10, 0, 0, 12], [8, 8, 8, 8], udp.length + dns.length);
  const packet = [...ip, ...udp, ...dns];
  const bytes = new Uint8Array([
    ...pcapGlobalHeaderLE(101),
    ...pcapRecordHeaderLE(1700000007, packet.length),
    ...packet,
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.equal(parsed.linktype, 101);
  assert.deepEqual(parsed.dnsNames, ['raw.example.test']);
});

test('pcap: unknown linktype still parses headers, skips app-layer', () => {
  const bytes = new Uint8Array([
    ...pcapGlobalHeaderLE(999),
    ...pcapRecordHeaderLE(1700000008, 4),
    1, 2, 3, 4,
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.equal(parsed.linktype, 999);
  assert.match(parsed.linktypeName, /^LINKTYPE_999$/);
  assert.equal(parsed.packetCount, 1);
  assert.equal(parsed.dnsNames.length, 0);
});

// ── PCAPNG ───────────────────────────────────────────────────────────────

test('pcapng: SHB + IDB + EPB with DNS query parses end to end', () => {
  // SHB: blockType(4)=0x0a0d0d0a length(4) BOM(4) major(2) minor(2) sectionLen(8) trailer(4)
  // = 4+4+4+2+2+8+4 = 28 bytes
  const shb = [
    0x0a, 0x0d, 0x0d, 0x0a,
    ...u32le(28),
    0x4d, 0x3c, 0x2b, 0x1a,                // BOM (LE byte pattern of 0x1a2b3c4d)
    0x01, 0x00,
    0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ...u32le(28),
  ];
  // IDB: type=1 length linktype(2)=1 reserved(2) snaplen(4) trailer
  // length = 4+4+2+2+4+4 = 20
  const idb = [
    ...u32le(1),
    ...u32le(20),
    0x01, 0x00,
    0x00, 0x00,
    0xff, 0xff, 0x00, 0x00,
    ...u32le(20),
  ];
  // EPB: type=6 length interface_id(4)=0 ts_high(4) ts_low(4) capLen(4) origLen(4)
  //       data + padding-to-4 + trailer
  // data = ethernet+IPv4+UDP+DNS (must align to 4 bytes; pad)
  const dns = dnsQuery('pcapng.example.test');
  const udp = udpHdr(54321, 53, dns.length);
  const ip = ipv4Hdr(17, [10, 0, 0, 1], [8, 8, 8, 8], udp.length + dns.length);
  const eth = ethHdr(0x0800);
  const data = [...eth, ...ip, ...udp, ...dns];
  const padLen = (4 - (data.length & 3)) & 3;
  const dataPadded = [...data, ...new Array(padLen).fill(0)];
  const epbBodyLen = 4 + 4 + 4 + 4 + 4 + dataPadded.length; // interface + ts_high + ts_low + capLen + origLen + dataPadded
  const epbTotalLen = 4 + 4 + epbBodyLen + 4;
  const epb = [
    ...u32le(6),
    ...u32le(epbTotalLen),
    0, 0, 0, 0,
    0, 0, 0, 0,
    0, 0, 0, 0,
    ...u32le(data.length),
    ...u32le(data.length),
    ...dataPadded,
    ...u32le(epbTotalLen),
  ];
  const bytes = new Uint8Array([...shb, ...idb, ...epb]);
  const parsed = PcapRenderer._parse(bytes);
  assert.equal(parsed.kind, 'pcapng');
  assert.equal(parsed.linktype, 1);
  assert.equal(parsed.packetCount, 1);
  assert.deepEqual(parsed.dnsNames, ['pcapng.example.test']);
});

test('pcapng: bad byte-order magic → parse error', () => {
  const bytes = new Uint8Array([
    0x0a, 0x0d, 0x0d, 0x0a,
    ...u32le(28),
    0xde, 0xad, 0xbe, 0xef,
    0x01, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ...u32le(28),
  ]);
  const parsed = PcapRenderer._parse(bytes);
  assert.equal(parsed.kind, 'pcapng');
  assert.match(parsed.error, /byte-order/);
});

// ── analyzeForSecurity ────────────────────────────────────────────────────

test('analyze: empty PCAP → low risk + format banner only', () => {
  const r = new PcapRenderer();
  const f = r.analyzeForSecurity(bufFrom(pcapGlobalHeaderLE(1)), 'a.pcap');
  assert.equal(f.risk, 'low');
  assert.ok(f.externalRefs.some((x) => x.type === IOC.PATTERN && /libpcap/.test(x.url)));
});

test('analyze: bad magic → info IOC only, no crash', () => {
  const r = new PcapRenderer();
  const f = r.analyzeForSecurity(new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]).buffer, 'bad.pcap');
  assert.equal(f.risk, 'low');
  assert.ok(f.externalRefs.some((x) => x.type === IOC.INFO && /parse error/i.test(x.url)));
});

test('analyze: DNS query → DOMAIN IOC in interestingStrings', () => {
  const dns = dnsQuery('mal.example.test');
  const udp = udpHdr(54321, 53, dns.length);
  const ip = ipv4Hdr(17, [10, 0, 0, 1], [203, 0, 113, 5], udp.length + dns.length);
  const eth = ethHdr(0x0800);
  const packet = [...eth, ...ip, ...udp, ...dns];
  const bytes = [
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000010, packet.length),
    ...packet,
  ];
  const r = new PcapRenderer();
  const f = r.analyzeForSecurity(bufFrom(bytes), 'q.pcap');
  assert.ok(f.interestingStrings.some(
    (x) => x.type === IOC.DOMAIN && x.url === 'mal.example.test'),
    `expected DNS IOC, got: ${JSON.stringify(f.interestingStrings)}`);
  // The destination IP 203.0.113.5 is public (TEST-NET-3) so it's emitted;
  // the source 10.0.0.1 is RFC1918 and suppressed.
  assert.ok(f.interestingStrings.some(
    (x) => x.type === IOC.IP && x.url === '203.0.113.5'));
  assert.ok(!f.interestingStrings.some(
    (x) => x.type === IOC.IP && x.url === '10.0.0.1'));
});

test('analyze: HTTP request → escalates to medium + T1040 capability', () => {
  const http = httpRequest('phish.example.test');
  const tcp = tcpHdr(50000, 80);
  const ip = ipv4Hdr(6, [10, 0, 0, 2], [203, 0, 113, 6], tcp.length + http.length);
  const eth = ethHdr(0x0800);
  const packet = [...eth, ...ip, ...tcp, ...http];
  const bytes = [
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000011, packet.length),
    ...packet,
  ];
  const r = new PcapRenderer();
  const f = r.analyzeForSecurity(bufFrom(bytes), 'h.pcap');
  assert.equal(f.risk, 'medium');
  assert.ok(f.capabilities.some((c) => c.id === 'T1040'));
  assert.ok(f.externalRefs.some((x) => /plaintext HTTP/.test(x.url)));
});

test('analyze: HTTP Basic auth → escalates to high', () => {
  const http = httpRequest('login.example.test', 'Authorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n');
  const tcp = tcpHdr(50001, 80);
  const ip = ipv4Hdr(6, [10, 0, 0, 3], [203, 0, 113, 7], tcp.length + http.length);
  const eth = ethHdr(0x0800);
  const packet = [...eth, ...ip, ...tcp, ...http];
  const bytes = [
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000012, packet.length),
    ...packet,
  ];
  const r = new PcapRenderer();
  const f = r.analyzeForSecurity(bufFrom(bytes), 'auth.pcap');
  assert.equal(f.risk, 'high');
  assert.ok(f.externalRefs.some((x) => /Authorization: Basic/.test(x.url)));
});

test('analyze: TLS SNI → DOMAIN IOC, low risk (encrypted is not by itself bad)', () => {
  const tls = tlsClientHello('cdn.example.test');
  const tcp = tcpHdr(60001, 443);
  const ip = ipv4Hdr(6, [10, 0, 0, 4], [198, 51, 100, 25], tcp.length + tls.length);
  const eth = ethHdr(0x0800);
  const packet = [...eth, ...ip, ...tcp, ...tls];
  const bytes = [
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000013, packet.length),
    ...packet,
  ];
  const r = new PcapRenderer();
  const f = r.analyzeForSecurity(bufFrom(bytes), 'tls.pcap');
  assert.equal(f.risk, 'low');
  assert.ok(f.interestingStrings.some(
    (x) => x.type === IOC.DOMAIN && x.url === 'cdn.example.test'));
});

test('analyze: telnet traffic → escalates medium', () => {
  const payload = asciiBytes('Login: \r\n');
  const tcp = tcpHdr(60010, 23);
  const ip = ipv4Hdr(6, [10, 0, 0, 5], [203, 0, 113, 50], tcp.length + payload.length);
  const eth = ethHdr(0x0800);
  const packet = [...eth, ...ip, ...tcp, ...payload];
  const bytes = [
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000014, packet.length),
    ...packet,
  ];
  const r = new PcapRenderer();
  const f = r.analyzeForSecurity(bufFrom(bytes), 't.pcap');
  assert.equal(f.risk, 'medium');
  assert.ok(f.externalRefs.some((x) => /Telnet/.test(x.url)));
});

test('analyze: private IPs are suppressed from IP IOC list', () => {
  // All packets entirely within RFC1918 — IP IOCs should be empty.
  const dns = dnsQuery('a.example.test');
  const udp = udpHdr(54321, 53, dns.length);
  const ip = ipv4Hdr(17, [192, 168, 1, 1], [192, 168, 1, 2], udp.length + dns.length);
  const eth = ethHdr(0x0800);
  const packet = [...eth, ...ip, ...udp, ...dns];
  const bytes = [
    ...pcapGlobalHeaderLE(1),
    ...pcapRecordHeaderLE(1700000015, packet.length),
    ...packet,
  ];
  const r = new PcapRenderer();
  const f = r.analyzeForSecurity(bufFrom(bytes), 'priv.pcap');
  assert.ok(!f.interestingStrings.some((x) => x.type === IOC.IP));
});

// ── Helper unit tests ─────────────────────────────────────────────────────

test('helper: _ip4 formats correctly', () => {
  const b = new Uint8Array([0, 0, 0, 192, 0, 2, 1]);
  assert.equal(PcapRenderer._ip4(b, 3), '192.0.2.1');
});

test('helper: _ip6 collapses zero runs', () => {
  // 2001:db8::1
  const b = new Uint8Array([
    0x20, 0x01, 0x0d, 0xb8,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1,
  ]);
  assert.equal(PcapRenderer._ip6(b, 0), '2001:db8::1');
});

test('helper: _isPrivateOrLoopback covers IPv4 and IPv6 private ranges', () => {
  assert.equal(PcapRenderer._isPrivateOrLoopback('10.1.2.3'), true);
  assert.equal(PcapRenderer._isPrivateOrLoopback('172.16.0.1'), true);
  assert.equal(PcapRenderer._isPrivateOrLoopback('192.168.1.1'), true);
  assert.equal(PcapRenderer._isPrivateOrLoopback('127.0.0.1'), true);
  assert.equal(PcapRenderer._isPrivateOrLoopback('169.254.1.1'), true);
  assert.equal(PcapRenderer._isPrivateOrLoopback('224.0.0.1'), true);
  assert.equal(PcapRenderer._isPrivateOrLoopback('203.0.113.5'), false);
  assert.equal(PcapRenderer._isPrivateOrLoopback('::1'), true);
  assert.equal(PcapRenderer._isPrivateOrLoopback('fe80::1'), true);
  assert.equal(PcapRenderer._isPrivateOrLoopback('fd00::1'), true);
  assert.equal(PcapRenderer._isPrivateOrLoopback('2001:db8::1'), false);
});
