'use strict';
// ════════════════════════════════════════════════════════════════════════════
// pcap-renderer.js — libpcap (.pcap) and PCAPNG (.pcapng) packet capture
// triage analyser.
//
// Loupe is not a replacement for Wireshark — full protocol decoding is
// outside the scope of an offline single-file analyser. What this
// renderer does is extract the high-signal IOCs an analyst wants to
// pivot on within seconds of dropping a capture into the tab:
//
//   • Format / byte-order / version / snaplen / link-layer type
//   • Capture window (first / last packet timestamp)
//   • Packet count and a hard cap (`MAX_PACKETS`) to bound work on
//     hostile / huge captures — exceeded ⇒ truncation IOC
//   • Top talkers (src/dst IPv4 + IPv6) by packet count
//   • DNS query names (UDP/53 → RFC 1035 label decoder)
//   • HTTP `Host:` headers (TCP/80 → first-line + headers sniff)
//   • TLS Server Name Indication (TCP/443 → ClientHello SNI extension)
//
// All extracted hosts are emitted as IOCs (`IOC.DOMAIN` for DNS / Host /
// SNI, `IOC.IP` for the IP set). The sidebar's URL → punycode / abuse-
// suffix sibling logic in `pushIOC` then catches IDN homograph and
// DDNS / tunnelling surface domains for free.
//
// We support BOTH file formats in a single renderer:
//
//   • libpcap classic format. 24-byte global header. Magic dispatch:
//        a1 b2 c3 d4 — big-endian, microsecond timestamps
//        d4 c3 b2 a1 — little-endian, microsecond timestamps
//        a1 b2 3c 4d — big-endian, nanosecond timestamps
//        4d 3c b2 a1 — little-endian, nanosecond timestamps
//     Per-packet record: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
//     followed by `incl_len` bytes of link-layer-framed packet data.
//
//   • PCAPNG (PCAP Next Generation). Block-based. Magic dispatch on
//     SHB block-type = 0x0a0d0d0a, then a Byte-Order Magic
//     (0x1a2b3c4d) to disambiguate endianness. Blocks we care about:
//        SHB (0x0a0d0d0a) — section header, sets endianness
//        IDB (0x00000001) — interface description, captures linktype
//        EPB (0x00000006) — enhanced packet block (the common case)
//        SPB (0x00000003) — simple packet block (no interface id)
//     Other blocks (NRB / ISB / DSB / custom) are skipped via their
//     declared block_total_length. Spec: PCAP-NG draft, RFC pending.
//
// Link-layer types we decode (LINKTYPE_*):
//        1   ETHERNET
//      113   LINUX_SLL (cooked v1)
//      276   LINUX_SLL2
//      101   RAW (IPv4 or IPv6 directly, no link header)
//      228   IPV4
//      229   IPV6
// Other linktypes parse the header (so timestamps + counts are honest)
// but skip app-layer extraction. We DO NOT decode 802.11 (143/127),
// PPPoE, or other esoteric tunnels in M3 — the IOC yield isn't worth
// the parser surface area.
//
// All multi-byte reads are bounds-checked. A truncated packet record
// or impossible incl_len ⇒ stop walking, surface a parse-error info
// IOC, keep the partial result. Same fail-graceful posture as every
// other Loupe binary parser.
//
// Depends on: constants.js (IOC, escHtml, escalateRisk, lfNormalize,
//             pushIOC).
// ════════════════════════════════════════════════════════════════════════════

class PcapRenderer {

  // ── Hard caps ──────────────────────────────────────────────────────────
  // Per-file packet parse cap. Beyond this we stop walking and emit a
  // truncation info IOC. 1_000_000 packets is the upper bound of the
  // streaming Timeline grid (rows are packed into RowStore chunks via
  // packRowChunk); main-thread fallback parses still tolerate this
  // because per-packet work is constant-time and ~12 bytes of fixed
  // overhead per pkt record. A hostile billion-packet file is bounded
  // at 1M iterations.
  static MAX_PACKETS = 1_000_000;

  // ── Timeline grid columns (Wireshark + ports) ──────────────────────────
  // Threaded through TimelineView.fromPcap factory + timeline worker.
  // Index 1 is the time column (defaultTimeColIdx); index 6 is the
  // protocol column used for histogram stacking by default.
  static TIMELINE_COLUMNS = Object.freeze([
    'No.', 'Time', 'Source', 'Src Port',
    'Destination', 'Dst Port', 'Protocol', 'Length', 'Info',
  ]);
  static TIMELINE_TIME_COL_IDX = 1;
  static TIMELINE_STACK_COL_IDX = 6;
  // Schema-known IPv4/IPv6 endpoint columns (Source, Destination). The
  // GeoIP / ASN auto-enrichment in `timeline-view-geoip.js` consumes
  // this via the TimelineView ctor's `ipColumns` field as a
  // deterministic override of the heuristic 80%-IPv4 sample scan in
  // `_detectIpColumns()`. Necessary because mixed IPv4/IPv6 captures
  // can drop both endpoint columns below the heuristic gate; we KNOW
  // these are IP columns regardless of cell-shape distribution. See
  // `TimelineView._ipColumns` and `_detectIpColumns` for the consumer
  // side of the contract.
  static TIMELINE_IP_COL_INDICES = Object.freeze([2, 4]);

  // PCAPNG-only iteration cap. The PCAPNG walk visits every block
  // (SHB / IDB / EPB / SPB / NRB / ISB / DSB / custom), but we only
  // *count* EPB/SPB toward MAX_PACKETS. A hostile file padded with
  // billions of zero-length NRB blocks could otherwise spin past the
  // packet cap. We bound the block walk at 4× MAX_PACKETS — leaves
  // plenty of headroom for legitimate decorator blocks while killing
  // the pathological case.
  static MAX_PCAPNG_BLOCKS = 200000;

  // Per-packet incl_len sanity ceiling. Real-world snaplen is ~65535
  // (jumbo frames at most); anything wildly larger means the file is
  // corrupt or the byte-order detection got wrong. 262144 = 256 KiB
  // is a comfortable ceiling that still flags catastrophic corruption.
  static MAX_PACKET_BYTES = 262144;

  // App-layer extraction caps — bound the IOC explosion on captures
  // with thousands of unique resolvers / hosts. Hit the cap ⇒ emit a
  // single info IOC noting the truncation.
  static MAX_DNS_QUERIES = 1000;
  static MAX_HTTP_HOSTS  = 1000;
  static MAX_TLS_SNIS    = 1000;

  // Top-N talkers shown in the UI (and emitted as IP IOCs). Past this
  // we emit one info IOC summarising the long tail.
  static TOP_TALKERS = 25;

  // ── PCAP magic-byte tables ─────────────────────────────────────────────
  static PCAP_MAGICS = Object.freeze([
    { bytes: [0xa1, 0xb2, 0xc3, 0xd4], le: false, nano: false, label: 'libpcap (μs, big-endian)' },
    { bytes: [0xd4, 0xc3, 0xb2, 0xa1], le: true,  nano: false, label: 'libpcap (μs, little-endian)' },
    { bytes: [0xa1, 0xb2, 0x3c, 0x4d], le: false, nano: true,  label: 'libpcap (ns, big-endian)' },
    { bytes: [0x4d, 0x3c, 0xb2, 0xa1], le: true,  nano: true,  label: 'libpcap (ns, little-endian)' },
  ]);

  static PCAPNG_BLOCK_SHB = 0x0a0d0d0a;
  static PCAPNG_BYTEORDER_MAGIC = 0x1a2b3c4d;

  // ── Link-layer type names (LINKTYPE_*) ────────────────────────────────
  // Wireshark / tcpdump / libpcap tap.h. We name a small subset; the
  // header card shows the numeric type for unrecognised entries so the
  // analyst can still pivot.
  static LINKTYPES = Object.freeze({
    0:   'NULL (BSD loopback)',
    1:   'ETHERNET',
    9:   'PPP',
    101: 'RAW (IP)',
    105: '802.11',
    113: 'LINUX_SLL',
    127: '802.11 + radiotap',
    143: 'DOCSIS',
    192: 'PPI',
    228: 'IPV4',
    229: 'IPV6',
    276: 'LINUX_SLL2',
  });

  // Byte-set classification for app-layer parsing dispatch.
  static APP_PARSEABLE_LINKTYPES = Object.freeze(new Set([1, 101, 113, 228, 229, 276]));

  // ── Public renderer entry points ──────────────────────────────────────
  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const parsed = PcapRenderer._parse(bytes);
    return PcapRenderer._buildView(parsed, fileName);
  }

  analyzeForSecurity(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const parsed = PcapRenderer._parse(bytes);
    return PcapRenderer._analyzePcapInfo(parsed, fileName);
  }

  // ── Parsed-info → findings (shared with the Timeline route) ────────────
  // Split out from `analyzeForSecurity` so the timeline-router hybrid
  // path (TimelineView.fromPcap / _buildTimelineViewFromWorker) can
  // synthesise findings from the worker-pre-parsed `pcapInfo` without
  // re-parsing the buffer. Mirrors the EVTX hybrid pattern in
  // `EvtxDetector.analyzeForSecurity(buffer, name, prebuiltEvents)`.
  // Pure function: reads `info`, returns a fresh findings object;
  // never mutates `info`.
  static _analyzePcapInfo(parsed, fileName) {
    const f = {
      risk: 'low',
      externalRefs: [],
      detections: [],
      capabilities: [],
      interestingStrings: [],
    };

    if (parsed.error && !parsed.kind) {
      pushIOC(f, {
        type: IOC.INFO,
        value: `PCAP parse error: ${parsed.error}`,
        severity: 'info',
        bucket: 'externalRefs',
      });
      return f;
    }

    // Format banner — always emit so the sidebar shows the capture's
    // identity even on a pristine PCAP with zero IOCs.
    f.externalRefs.push({
      type: IOC.PATTERN,
      url: `${parsed.kind === 'pcapng' ? 'PCAPNG' : 'libpcap'} capture — ${parsed.formatLabel || 'unknown'}`,
      severity: 'info',
    });

    if (parsed.error) {
      pushIOC(f, {
        type: IOC.INFO,
        value: `PCAP parse warning: ${parsed.error}`,
        severity: 'info',
        bucket: 'externalRefs',
      });
    }

    if (parsed.truncated) {
      pushIOC(f, {
        type: IOC.INFO,
        value: `PCAP truncated at ${PcapRenderer.MAX_PACKETS.toLocaleString('en-US')} packets (analysis cap)`,
        severity: 'info',
        bucket: 'externalRefs',
      });
    }

    // ── IP IOCs from top talkers ───────────────────────────────────────
    const topTalkers = PcapRenderer._rankTopN(parsed.ipCounts, PcapRenderer.TOP_TALKERS);
    for (const { key, count } of topTalkers) {
      if (PcapRenderer._isPrivateOrLoopback(key)) continue;
      pushIOC(f, {
        type: IOC.IP,
        value: key,
        severity: 'info',
        note: `${count} packet${count === 1 ? '' : 's'}`,
      });
    }

    // ── DNS query names → DOMAIN IOCs ──────────────────────────────────
    for (const name of parsed.dnsNames) {
      pushIOC(f, {
        type: IOC.DOMAIN,
        value: name,
        severity: 'info',
        note: 'DNS query',
      });
    }
    if (parsed.dnsTruncated) {
      pushIOC(f, {
        type: IOC.INFO,
        value: `DNS query extraction capped at ${PcapRenderer.MAX_DNS_QUERIES} unique names`,
        severity: 'info',
        bucket: 'externalRefs',
      });
    }

    // ── HTTP Host headers → DOMAIN IOCs (medium — plaintext HTTP) ──────
    for (const host of parsed.httpHosts) {
      pushIOC(f, {
        type: IOC.DOMAIN,
        value: host,
        severity: 'info',
        note: 'HTTP Host header (plaintext)',
      });
    }
    if (parsed.httpHosts.length > 0) {
      // Plaintext HTTP in 2026 is itself a finding for credential / cookie
      // exposure. T1040 (network sniffing) covers the analyst-side case;
      // the operator-side risk is unencrypted credential transit.
      escalateRisk(f, 'medium');
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${parsed.httpHosts.length} plaintext HTTP host${parsed.httpHosts.length === 1 ? '' : 's'} observed — credential / cookie exposure surface`,
        severity: 'medium',
      });
      f.capabilities.push({ id: 'T1040', source: 'pcap-http-plaintext' });
    }

    // ── HTTP Basic auth → high (T1040 plaintext credentials) ───────────
    if (parsed.httpBasicAuthCount > 0) {
      escalateRisk(f, 'high');
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `Authorization: Basic header observed in ${parsed.httpBasicAuthCount} request${parsed.httpBasicAuthCount === 1 ? '' : 's'} — plaintext credentials over HTTP (T1040)`,
        severity: 'high',
      });
    }

    // ── TLS SNIs → DOMAIN IOCs ─────────────────────────────────────────
    for (const sni of parsed.tlsSnis) {
      pushIOC(f, {
        type: IOC.DOMAIN,
        value: sni,
        severity: 'info',
        note: 'TLS SNI',
      });
    }

    // ── Unencrypted-FTP / Telnet command-and-control surfaces ──────────
    if (parsed.telnetSeen) {
      escalateRisk(f, 'medium');
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'Telnet (TCP/23) traffic observed — unencrypted shell over network (T1021.001 / T1040)',
        severity: 'medium',
      });
    }
    if (parsed.ftpSeen) {
      escalateRisk(f, 'medium');
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'FTP control-channel (TCP/21) traffic observed — plaintext credentials risk (T1040)',
        severity: 'medium',
      });
    }

    // Stash full parsed-capture shape on the findings object so
    // `_copyAnalysisPcap` (in app-copy-analysis.js) can render the
    // header / DNS / HTTP host / TLS-SNI / top-talker tables without
    // re-parsing. Mirrors the `findings.peInfo` pattern.
    f.pcapInfo = parsed;

    return f;
  }

  // ── Top-level dispatch parse ──────────────────────────────────────────
  static _parse(bytes) {
    if (!bytes || bytes.length < 8) {
      return PcapRenderer._emptyResult('File too small for any PCAP / PCAPNG header');
    }
    // PCAPNG starts with the SHB block-type 0x0a0d0d0a in BIG-ENDIAN
    // byte order on the wire. PCAPNG is the only block format whose
    // header isn't ambiguous w.r.t. classic PCAP magics.
    if (bytes[0] === 0x0a && bytes[1] === 0x0d && bytes[2] === 0x0d && bytes[3] === 0x0a) {
      return PcapRenderer._parsePcapng(bytes);
    }
    for (const m of PcapRenderer.PCAP_MAGICS) {
      if (bytes[0] === m.bytes[0] && bytes[1] === m.bytes[1]
          && bytes[2] === m.bytes[2] && bytes[3] === m.bytes[3]) {
        return PcapRenderer._parsePcap(bytes, m);
      }
    }
    return PcapRenderer._emptyResult('Bad magic — not a PCAP or PCAPNG file');
  }

  static _emptyResult(error) {
    return {
      kind: null,
      error,
      formatLabel: null,
      version: null,
      snaplen: null,
      linktype: null,
      linktypeName: null,
      packetCount: 0,
      truncated: false,
      // Whole-second window for the existing summary block (legacy
      // shape — `_copyAnalysisPcap` reads firstTs/lastTs).
      firstTs: null,
      lastTs: null,
      // Full-microsecond resolution for the Timeline grid's Time
      // column. tsMicros is set per-packet on `pkts`; firstTsMicros /
      // lastTsMicros mirror the whole-second window with sub-second
      // detail for the capture-window header.
      firstTsMicros: null,
      lastTsMicros: null,
      ipCounts: new Map(),
      dnsNames: [],
      dnsTruncated: false,
      httpHosts: [],
      httpBasicAuthCount: 0,
      tlsSnis: [],
      telnetSeen: false,
      ftpSeen: false,
      // Per-packet rows for the Timeline grid. Each entry:
      //   { no, tsMicros, src, dst, sport, dport, proto, length, info }
      // sport/dport are 0 when transport doesn't carry ports (ICMP /
      // non-IP / parse-incomplete frames). proto is the highest-layer
      // label resolved during dispatch ('DNS' / 'HTTP' / 'TLS' /
      // 'Telnet' / 'FTP' / 'TCP' / 'UDP' / 'ICMP' / 'ICMPv6' /
      // 'IPv4' / 'IPv6' / 'ARP' / 'ETH' / '?'). info is a short
      // human-readable summary used as the grid's Info cell.
      pkts: [],
    };
  }

  // ── Classic libpcap parser ────────────────────────────────────────────
  static _parsePcap(bytes, magic) {
    const result = PcapRenderer._emptyResult(null);
    result.kind = 'pcap';
    result.formatLabel = magic.label;

    if (bytes.length < 24) {
      result.error = 'libpcap global header truncated (need 24 bytes)';
      return result;
    }
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const le = magic.le;
    const major = dv.getUint16(4, le);
    const minor = dv.getUint16(6, le);
    // bytes[8..16] are thiszone + sigfigs — analyst-irrelevant
    const snaplen = dv.getUint32(16, le);
    const linktype = dv.getUint32(20, le) & 0xffffffff;
    result.version = `${major}.${minor}`;
    result.snaplen = snaplen;
    result.linktype = linktype;
    result.linktypeName = PcapRenderer.LINKTYPES[linktype] || `LINKTYPE_${linktype}`;

    const appParseable = PcapRenderer.APP_PARSEABLE_LINKTYPES.has(linktype);
    const dnsSet = new Set();
    const httpHostSet = new Set();
    const tlsSniSet = new Set();
    // Sub-second multiplier for libpcap's per-packet sub-second field.
    // ns-pcap variants store nanoseconds; scale to microseconds (the
    // precision used by the Timeline grid + RFC 3339 millisecond
    // formatter) by dividing by 1000.
    const subDivisor = magic.nano ? 1000 : 1;
    let p = 24;
    let n = 0;
    while (p + 16 <= bytes.length) {
      if (n >= PcapRenderer.MAX_PACKETS) {
        result.truncated = true;
        break;
      }
      const tsSec = dv.getUint32(p, le);
      const tsSubRaw = dv.getUint32(p + 4, le);
      const tsMicros = tsSec * 1_000_000 + Math.floor(tsSubRaw / subDivisor);
      const inclLen = dv.getUint32(p + 8, le);
      const origLen = dv.getUint32(p + 12, le);
      if (inclLen > PcapRenderer.MAX_PACKET_BYTES) {
        result.error = `Packet ${n}: incl_len ${inclLen} > MAX_PACKET_BYTES (corrupt or wrong endianness)`;
        break;
      }
      if (p + 16 + inclLen > bytes.length) {
        result.error = `Packet ${n}: truncated at offset ${p}`;
        break;
      }
      if (n === 0) {
        result.firstTs = tsSec;
        result.firstTsMicros = tsMicros;
      }
      result.lastTs = tsSec;
      result.lastTsMicros = tsMicros;

      const pkt = PcapRenderer._newPkt(n, tsMicros, origLen || inclLen);
      if (appParseable && inclLen > 0) {
        PcapRenderer._dispatchPacket(
          bytes, p + 16, inclLen, linktype, result, dnsSet, httpHostSet, tlsSniSet, pkt
        );
      }
      result.pkts.push(pkt);
      p += 16 + inclLen;
      n += 1;
    }
    result.packetCount = n;
    result.dnsNames = Array.from(dnsSet);
    result.httpHosts = Array.from(httpHostSet);
    result.tlsSnis = Array.from(tlsSniSet);
    return result;
  }

  // ── PCAPNG parser ─────────────────────────────────────────────────────
  static _parsePcapng(bytes) {
    const result = PcapRenderer._emptyResult(null);
    result.kind = 'pcapng';
    result.formatLabel = 'PCAPNG';

    // The first block must be SHB. Its byte-order magic determines
    // endianness for every subsequent block in this section.
    if (bytes.length < 28) {
      result.error = 'PCAPNG SHB truncated';
      return result;
    }
    // SHB layout (after the 4-byte block_type):
    //   block_total_length(4)  byte-order-magic(4)  major(2)  minor(2)
    //   section_length(8)  options(...)  block_total_length(4 trailer)
    // We read block_total_length in BOTH endiannesses since we don't
    // know which one yet — the byte-order magic at offset 8 settles it.
    const bomLE = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(8, true);
    const le = (bomLE === PcapRenderer.PCAPNG_BYTEORDER_MAGIC);
    if (!le) {
      const bomBE = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(8, false);
      if (bomBE !== PcapRenderer.PCAPNG_BYTEORDER_MAGIC) {
        result.error = 'PCAPNG byte-order magic invalid';
        return result;
      }
    }
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const shbMajor = dv.getUint16(12, le);
    const shbMinor = dv.getUint16(14, le);
    result.version = `${shbMajor}.${shbMinor}`;
    result.formatLabel = `PCAPNG ${shbMajor}.${shbMinor} (${le ? 'LE' : 'BE'})`;

    // Walk subsequent blocks. The first block's total length is at
    // offset 4 of the SHB; we read it regardless of which block we're
    // looking at.
    let interfaceLinktype = null;
    const dnsSet = new Set();
    const httpHostSet = new Set();
    const tlsSniSet = new Set();

    let p = 0;
    let n = 0;
    let blocks = 0;
    while (p + 8 <= bytes.length) {
      if (n >= PcapRenderer.MAX_PACKETS) {
        result.truncated = true;
        break;
      }
      if (blocks >= PcapRenderer.MAX_PCAPNG_BLOCKS) {
        result.truncated = true;
        result.error = result.error || `PCAPNG block walk capped at ${PcapRenderer.MAX_PCAPNG_BLOCKS}`;
        break;
      }
      blocks += 1;
      const blockType = dv.getUint32(p, le);
      const blockLen = dv.getUint32(p + 4, le);
      if (blockLen < 12 || (blockLen & 3) !== 0 || p + blockLen > bytes.length) {
        result.error = `PCAPNG block at offset ${p}: invalid length ${blockLen}`;
        break;
      }
      // PCAPNG spec § 4.1: each section's SHB declares its own
      // Byte-Order Magic; sections may legally have different
      // endianness within a single file. For triage we deliberately
      // do NOT re-read BOM on subsequent SHBs and keep the first
      // section's `le` — multi-section files are vanishingly rare in
      // malware artefacts and the spec violation is bounded
      // (counters/timestamps in later sections may be wrong, but
      // block-walking still terminates because blockLen is read with
      // the stale endianness consistently and is sanity-checked
      // against bytes.length on every iteration).
      if (blockType === PcapRenderer.PCAPNG_BLOCK_SHB) {
        // body already consumed for the first SHB; subsequent ones
        // start a new section but we keep the same endianness.
      } else if (blockType === 1) {
        // IDB: linktype(2) reserved(2) snaplen(4) options(...)
        if (blockLen >= 16) {
          interfaceLinktype = dv.getUint16(p + 8, le);
          const snap = dv.getUint32(p + 12, le);
          if (result.linktype === null) {
            result.linktype = interfaceLinktype;
            result.linktypeName = PcapRenderer.LINKTYPES[interfaceLinktype]
              || `LINKTYPE_${interfaceLinktype}`;
            result.snaplen = snap;
          }
        }
      } else if (blockType === 6) {
        // EPB: interface_id(4) ts_high(4) ts_low(4) cap_len(4) orig_len(4) data… opts… trailer
        if (blockLen >= 32) {
          const tsHigh = dv.getUint32(p + 12, le);
          const tsLow  = dv.getUint32(p + 16, le);
          const capLen = dv.getUint32(p + 20, le);
          const origLen = dv.getUint32(p + 24, le);
          // PCAPNG ts is 64-bit µs (default if_tsresol). We surface
          // both whole-second (legacy `firstTs`/`lastTs` for the
          // copy-analysis builder) and the µs-precise timestamp the
          // Timeline grid uses for sort + bucket math.
          const tsMicros = tsHigh * 4_294_967_296 + tsLow;
          const tsSec = Math.floor(tsMicros / 1_000_000);
          if (result.firstTs === null) {
            result.firstTs = tsSec;
            result.firstTsMicros = tsMicros;
          }
          result.lastTs = tsSec;
          result.lastTsMicros = tsMicros;
          const dataStart = p + 28;
          if (capLen > 0 && dataStart + capLen <= p + blockLen
              && capLen <= PcapRenderer.MAX_PACKET_BYTES) {
            const lt = result.linktype;
            const pkt = PcapRenderer._newPkt(n, tsMicros, origLen || capLen);
            if (lt !== null && PcapRenderer.APP_PARSEABLE_LINKTYPES.has(lt)) {
              PcapRenderer._dispatchPacket(
                bytes, dataStart, capLen, lt, result, dnsSet, httpHostSet, tlsSniSet, pkt
              );
            }
            result.pkts.push(pkt);
            n += 1;
          }
        }
      } else if (blockType === 3) {
        // SPB: orig_len(4) data… trailer
        if (blockLen >= 16) {
          const origLen = dv.getUint32(p + 8, le);
          // SPB has no cap_len, so the data length is bounded by
          // (block_total_length − 16) and orig_len.
          const dataStart = p + 12;
          const dataLen = Math.min(origLen, blockLen - 16);
          if (dataLen > 0 && dataLen <= PcapRenderer.MAX_PACKET_BYTES) {
            const lt = result.linktype;
            // SPB carries no per-packet timestamp; reuse the most
            // recent EPB timestamp (or 0 if none seen yet) so the
            // grid Time column degrades gracefully rather than NaN.
            const tsMicros = result.lastTsMicros || 0;
            const pkt = PcapRenderer._newPkt(n, tsMicros, origLen || dataLen);
            if (lt !== null && PcapRenderer.APP_PARSEABLE_LINKTYPES.has(lt)) {
              PcapRenderer._dispatchPacket(
                bytes, dataStart, dataLen, lt, result, dnsSet, httpHostSet, tlsSniSet, pkt
              );
            }
            result.pkts.push(pkt);
            n += 1;
          }
        }
      }
      // skip every other block type via blockLen — we don't decode
      // NRB / ISB / DSB / custom for triage.
      p += blockLen;
    }
    result.packetCount = n;
    result.dnsNames = Array.from(dnsSet);
    result.httpHosts = Array.from(httpHostSet);
    result.tlsSnis = Array.from(tlsSniSet);
    return result;
  }

  // ── Per-packet dispatch (link-layer → IPv4/IPv6 → app-layer) ─────────
  // `pkt` is the per-packet record accumulator built by `_newPkt`. The
  // dispatch chain mutates `pkt.proto` / `pkt.src` / `pkt.dst` /
  // `pkt.sport` / `pkt.dport` / `pkt.info` in place as the highest-
  // available layer is decoded. Same buffer-bounds discipline as the
  // pre-pkt path; nothing here pushes IOCs (analysis lives in
  // `_analyzePcapInfo`).

  // Allocate a per-packet record. Caller-set fields (`no`, `tsMicros`,
  // `length`) are populated up front; everything else gets a stable
  // default so `_pktToRow` can read every slot without `undefined`
  // checks (those would balloon the row-build loop on a 1 M packet
  // capture). `proto = '?'` is the fallback when no link-layer / IP /
  // app-layer dispatch resolves anything more specific.
  static _newPkt(no, tsMicros, length) {
    return {
      no,
      tsMicros: tsMicros || 0,
      length: length | 0,
      src: '',
      dst: '',
      sport: 0,
      dport: 0,
      proto: '?',
      info: '',
    };
  }
  static _dispatchPacket(bytes, off, len, linktype, result, dnsSet, httpHostSet, tlsSniSet, pkt) {
    let ipOff = -1;
    if (linktype === 1) {
      // ETHERNET — 14-byte MAC header. Optional 802.1Q VLAN tag at
      // offset 12-13 = 0x8100 inserts 4 bytes.
      if (len < 14) { if (pkt) pkt.proto = 'ETH'; return; }
      let etherType = (bytes[off + 12] << 8) | bytes[off + 13];
      let ipStart = off + 14;
      if (etherType === 0x8100 && len >= 18) {
        etherType = (bytes[off + 16] << 8) | bytes[off + 17];
        ipStart = off + 18;
      }
      if (etherType === 0x0800 || etherType === 0x86dd) {
        ipOff = ipStart;
      } else if (etherType === 0x0806) {
        if (pkt) { pkt.proto = 'ARP'; pkt.info = 'ARP'; }
        return;
      } else {
        if (pkt) pkt.proto = 'ETH';
        return;
      }
    } else if (linktype === 113) {
      // LINUX_SLL v1 — 16-byte cooked header.
      if (len < 16) { if (pkt) pkt.proto = 'SLL'; return; }
      const proto = (bytes[off + 14] << 8) | bytes[off + 15];
      if (proto === 0x0800 || proto === 0x86dd) ipOff = off + 16;
      else { if (pkt) pkt.proto = 'SLL'; return; }
    } else if (linktype === 276) {
      // LINUX_SLL2 — 20-byte cooked header. Protocol at offset 0.
      if (len < 20) { if (pkt) pkt.proto = 'SLL2'; return; }
      const proto = (bytes[off] << 8) | bytes[off + 1];
      if (proto === 0x0800 || proto === 0x86dd) ipOff = off + 20;
      else { if (pkt) pkt.proto = 'SLL2'; return; }
    } else if (linktype === 101 || linktype === 228 || linktype === 229) {
      // RAW (IP) — first byte's high nibble is the IP version, no link
      // header. 228/229 force the family.
      ipOff = off;
    }
    if (ipOff < 0) { if (pkt && pkt.proto === '?') pkt.proto = 'LL'; return; }
    const end = off + len;
    PcapRenderer._dispatchIP(bytes, ipOff, end, result, dnsSet, httpHostSet, tlsSniSet, pkt);
  }

  static _dispatchIP(bytes, ipOff, end, result, dnsSet, httpHostSet, tlsSniSet, pkt) {
    if (ipOff + 1 > end) return;
    const version = (bytes[ipOff] >> 4) & 0xf;
    if (version === 4) {
      if (ipOff + 20 > end) { if (pkt) pkt.proto = 'IPv4'; return; }
      const ihl = (bytes[ipOff] & 0xf) * 4;
      if (ihl < 20 || ipOff + ihl > end) { if (pkt) pkt.proto = 'IPv4'; return; }
      const proto = bytes[ipOff + 9];
      const totalLen = (bytes[ipOff + 2] << 8) | bytes[ipOff + 3];
      const ipEnd = Math.min(end, ipOff + Math.max(totalLen, ihl));
      const src = PcapRenderer._ip4(bytes, ipOff + 12);
      const dst = PcapRenderer._ip4(bytes, ipOff + 16);
      PcapRenderer._countIp(result.ipCounts, src);
      PcapRenderer._countIp(result.ipCounts, dst);
      if (pkt) { pkt.src = src; pkt.dst = dst; pkt.proto = 'IPv4'; }
      PcapRenderer._dispatchTransport(bytes, ipOff + ihl, ipEnd, proto, result, dnsSet, httpHostSet, tlsSniSet, pkt);
    } else if (version === 6) {
      if (ipOff + 40 > end) { if (pkt) pkt.proto = 'IPv6'; return; }
      const proto = bytes[ipOff + 6]; // next-header (skip extension hdrs)
      const payloadLen = (bytes[ipOff + 4] << 8) | bytes[ipOff + 5];
      const ipEnd = Math.min(end, ipOff + 40 + payloadLen);
      const src = PcapRenderer._ip6(bytes, ipOff + 8);
      const dst = PcapRenderer._ip6(bytes, ipOff + 24);
      PcapRenderer._countIp(result.ipCounts, src);
      PcapRenderer._countIp(result.ipCounts, dst);
      if (pkt) { pkt.src = src; pkt.dst = dst; pkt.proto = 'IPv6'; }
      PcapRenderer._dispatchTransport(bytes, ipOff + 40, ipEnd, proto, result, dnsSet, httpHostSet, tlsSniSet, pkt);
    }
  }

  static _dispatchTransport(bytes, off, end, proto, result, dnsSet, httpHostSet, tlsSniSet, pkt) {
    if (proto === 17) {
      // UDP: src(2) dst(2) len(2) cksum(2) payload…
      if (off + 8 > end) { if (pkt) pkt.proto = 'UDP'; return; }
      const sport = (bytes[off] << 8) | bytes[off + 1];
      const dport = (bytes[off + 2] << 8) | bytes[off + 3];
      const payloadOff = off + 8;
      if (pkt) {
        pkt.proto = 'UDP'; pkt.sport = sport; pkt.dport = dport;
      }
      if (sport === 53 || dport === 53) {
        PcapRenderer._extractDnsNames(bytes, payloadOff, end, dnsSet, pkt);
      }
    } else if (proto === 6) {
      // TCP: src(2) dst(2) seq(4) ack(4) data_offset_flags(2) win(2) cksum(2) urg(2) options…
      if (off + 20 > end) { if (pkt) pkt.proto = 'TCP'; return; }
      const sport = (bytes[off] << 8) | bytes[off + 1];
      const dport = (bytes[off + 2] << 8) | bytes[off + 3];
      const dataOffset = ((bytes[off + 12] >> 4) & 0xf) * 4;
      if (pkt) {
        pkt.proto = 'TCP'; pkt.sport = sport; pkt.dport = dport;
      }
      if (dataOffset < 20) return;
      const payloadOff = off + dataOffset;
      if (payloadOff >= end) return;
      if (sport === 80 || dport === 80) {
        PcapRenderer._extractHttp(bytes, payloadOff, end, result, httpHostSet, pkt);
      } else if (sport === 443 || dport === 443) {
        PcapRenderer._extractTlsSni(bytes, payloadOff, end, tlsSniSet, pkt);
      } else if (sport === 23 || dport === 23) {
        result.telnetSeen = true;
        if (pkt) { pkt.proto = 'Telnet'; }
      } else if (sport === 21 || dport === 21) {
        result.ftpSeen = true;
        if (pkt) { pkt.proto = 'FTP'; }
      }
    } else if (proto === 1) {
      if (pkt) { pkt.proto = 'ICMP'; }
    } else if (proto === 58) {
      if (pkt) { pkt.proto = 'ICMPv6'; }
    }
  }

  // ── DNS query name extraction (RFC 1035 label decoder) ───────────────
  // Walks the question section only; ignores answers, authority, and
  // additional records. Caps individual labels at 63 bytes (spec limit)
  // and total name length at 255 bytes (spec limit). Stops on the first
  // length-octet whose top two bits are 0b11 (compression pointer) since
  // we don't follow pointers in question sections (they're spec-illegal
  // there anyway).
  static _extractDnsNames(bytes, off, end, dnsSet, pkt) {
    if (off + 12 > end) return;
    // Header: id(2) flags(2) qd(2) an(2) ns(2) ar(2)
    const flags = (bytes[off + 2] << 8) | bytes[off + 3];
    const qdcount = (bytes[off + 4] << 8) | bytes[off + 5];
    if (qdcount === 0 || qdcount > 8) return; // 8 queries in one packet is already pathological
    let p = off + 12;
    let firstName = null;
    for (let q = 0; q < qdcount && p < end; q++) {
      const label = PcapRenderer._readDnsName(bytes, p, end);
      if (!label) return;
      if (label.value && dnsSet.size < PcapRenderer.MAX_DNS_QUERIES) {
        dnsSet.add(label.value);
      }
      if (firstName === null && label.value) firstName = label.value;
      p = label.next;
      // skip QTYPE(2) + QCLASS(2)
      p += 4;
    }
    if (pkt) {
      pkt.proto = 'DNS';
      const isResponse = (flags & 0x8000) !== 0;
      pkt.info = (isResponse ? 'Response' : 'Query') + (firstName ? ' ' + firstName : '');
    }
  }

  static _readDnsName(bytes, p, end) {
    const labels = [];
    let total = 0;
    while (p < end) {
      const lenOct = bytes[p];
      if (lenOct === 0) {
        return { value: labels.join('.'), next: p + 1 };
      }
      if ((lenOct & 0xc0) !== 0) return null; // pointer or reserved
      if (lenOct > 63) return null;
      if (p + 1 + lenOct > end) return null;
      total += lenOct + 1;
      if (total > 255) return null;
      const labelBytes = bytes.subarray(p + 1, p + 1 + lenOct);
      // DNS labels are LDH (letters/digits/hyphen) plus underscore for
      // SRV. Reject anything containing control bytes or non-ASCII so a
      // garbage UDP/53 packet doesn't turn into a poisoned IOC.
      for (const b of labelBytes) {
        if (b < 0x20 || b > 0x7e) return null;
      }
      labels.push(String.fromCharCode.apply(null, Array.from(labelBytes)).toLowerCase());
      p += 1 + lenOct;
    }
    return null;
  }

  // ── HTTP Host header + Basic auth extraction ──────────────────────────
  // Reads up to the first 1.5 KiB of TCP payload looking for `Host: ` and
  // `Authorization: Basic` lines. We don't reassemble TCP segments —
  // anything that lands in a single first-segment with a request line
  // will be caught; anything across a segment boundary is dropped. This
  // is the standard triage trade-off (Wireshark's HTTP dissector does
  // the reassembly properly; we don't).
  static _extractHttp(bytes, off, end, result, httpHostSet, pkt) {
    const window = Math.min(end - off, 1536);
    if (window <= 0) return;
    const slice = bytes.subarray(off, off + window);
    // Cheap method-line check — only proceed if this looks like a
    // request, otherwise we'd extract garbage from response bodies.
    if (!PcapRenderer._looksLikeHttpRequest(slice)) return;
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: false }).decode(slice);
    } catch {
      return;
    }
    const lines = text.split(/\r?\n/);
    let host = '';
    let requestLine = '';
    if (lines.length > 0) {
      // Truncate request line to a reasonable length so the grid Info
      // column doesn't balloon on hostile input.
      requestLine = lines[0].slice(0, 200);
    }
    for (const line of lines) {
      if (line.length === 0) break; // end of headers
      const colon = line.indexOf(':');
      if (colon < 0) continue;
      const name = line.slice(0, colon).toLowerCase();
      const value = line.slice(colon + 1).trim();
      if (name === 'host') {
        // Strip any port suffix: "example.com:8080" → "example.com".
        const h = value.split(':')[0].toLowerCase();
        if (PcapRenderer._looksLikeHostName(h)) {
          host = h;
          if (httpHostSet.size < PcapRenderer.MAX_HTTP_HOSTS) {
            httpHostSet.add(h);
          }
        }
      } else if (name === 'authorization' && value.toLowerCase().startsWith('basic ')) {
        result.httpBasicAuthCount += 1;
      }
    }
    if (pkt) {
      pkt.proto = 'HTTP';
      pkt.info = host
        ? `${requestLine} (Host: ${host})`
        : requestLine;
    }
  }

  static _looksLikeHttpRequest(slice) {
    // Match the first 8 bytes against common HTTP method prefixes.
    // Anything else (including responses that start with "HTTP/") gets
    // skipped — we don't want to surface server-side `Host:` echoes.
    const head = String.fromCharCode.apply(null,
      Array.from(slice.subarray(0, Math.min(8, slice.length))));
    return /^(GET |POST |HEAD |PUT |DELETE |PATCH |OPTIONS |CONNECT )/.test(head);
  }

  static _looksLikeHostName(s) {
    // RFC-ish: at least one dot OR an IPv4 literal, all printable ASCII,
    // no whitespace, no internal "/" or "?" or "#".
    if (!s || s.length > 253) return false;
    if (!/^[a-z0-9.\-_]+$/.test(s)) return false;
    return s.includes('.') || /^\d+\.\d+\.\d+\.\d+$/.test(s);
  }

  // ── TLS ClientHello SNI extraction ────────────────────────────────────
  // Parses a single TLS record at the start of the TCP payload. We
  // recognise:
  //   record header: type(1)=22 (handshake) version(2) length(2)
  //   handshake header: type(1)=1 (client_hello) length(3)
  //   client_hello body: client_version(2) random(32) sid_len(1) sid(...)
  //                      cipher_suites_len(2) ciphers... compression_len(1) comps...
  //                      extensions_len(2) extensions...
  //   each extension: type(2) data_len(2) data
  //   SNI extension type = 0x0000:
  //     server_name_list_len(2) name_type(1)=0 name_len(2) name(name_len)
  static _extractTlsSni(bytes, off, end, tlsSniSet, pkt) {
    if (off + 5 > end) return;
    if (bytes[off] !== 22) {
      // Not a handshake record (could be application data on an
      // already-established TLS session — still TLS, just nothing for
      // us to extract).
      if (pkt) pkt.proto = 'TLS';
      return;
    }
    const recLen = (bytes[off + 3] << 8) | bytes[off + 4];
    const recEnd = Math.min(end, off + 5 + recLen);
    let p = off + 5;
    if (p + 4 > recEnd) { if (pkt) pkt.proto = 'TLS'; return; }
    if (bytes[p] !== 1) { if (pkt) pkt.proto = 'TLS'; return; } // not client_hello
    const hsLen = (bytes[p + 1] << 16) | (bytes[p + 2] << 8) | bytes[p + 3];
    const hsEnd = Math.min(recEnd, p + 4 + hsLen);
    p += 4;
    if (p + 2 + 32 + 1 > hsEnd) { if (pkt) pkt.proto = 'TLS'; return; }
    p += 2 + 32; // client_version + random
    const sidLen = bytes[p]; p += 1 + sidLen;
    if (p + 2 > hsEnd) { if (pkt) pkt.proto = 'TLS'; return; }
    const csLen = (bytes[p] << 8) | bytes[p + 1]; p += 2 + csLen;
    if (p + 1 > hsEnd) { if (pkt) pkt.proto = 'TLS'; return; }
    const compLen = bytes[p]; p += 1 + compLen;
    if (p + 2 > hsEnd) { if (pkt) pkt.proto = 'TLS'; return; }
    const extLen = (bytes[p] << 8) | bytes[p + 1]; p += 2;
    const extEnd = Math.min(hsEnd, p + extLen);
    let extractedSni = null;
    while (p + 4 <= extEnd) {
      const extType = (bytes[p] << 8) | bytes[p + 1];
      const extDataLen = (bytes[p + 2] << 8) | bytes[p + 3];
      const extDataEnd = p + 4 + extDataLen;
      if (extDataEnd > extEnd) break;
      if (extType === 0x0000) {
        // SNI extension. Walk the server_name_list.
        let q = p + 4;
        if (q + 2 > extDataEnd) break;
        const listLen = (bytes[q] << 8) | bytes[q + 1];
        const listEnd = Math.min(extDataEnd, q + 2 + listLen);
        q += 2;
        while (q + 3 <= listEnd) {
          const nameType = bytes[q];
          const nameLen = (bytes[q + 1] << 8) | bytes[q + 2];
          if (q + 3 + nameLen > listEnd) break;
          if (nameType === 0 && nameLen > 0 && nameLen <= 255) {
            const slice = bytes.subarray(q + 3, q + 3 + nameLen);
            // SNI must be lowercase ASCII per RFC 6066. Validate to
            // avoid garbage IOC injection.
            let ok = true;
            for (const b of slice) {
              if (b < 0x20 || b > 0x7e) { ok = false; break; }
            }
            if (ok) {
              const host = String.fromCharCode.apply(null, Array.from(slice)).toLowerCase();
              if (PcapRenderer._looksLikeHostName(host)) {
                if (extractedSni === null) extractedSni = host;
                if (tlsSniSet.size < PcapRenderer.MAX_TLS_SNIS) {
                  tlsSniSet.add(host);
                }
              }
            }
          }
          q += 3 + nameLen;
        }
        break;
      }
      p = extDataEnd;
    }
    if (pkt) {
      pkt.proto = 'TLS';
      pkt.info = extractedSni
        ? `Client Hello (SNI=${extractedSni})`
        : 'Client Hello';
    }
  }

  // ── Per-packet → RowStore-shaped row ─────────────────────────────────
  // Used by both `TimelineView.fromPcap` (sync main-thread fallback)
  // and the timeline.worker.js pcap branch (which packs the resulting
  // string[] rows via packRowChunk). Returns a 9-element string[] in
  // the column order declared by `PcapRenderer.TIMELINE_COLUMNS`.
  // Time formatting: ISO-8601 UTC with millisecond precision when the
  // packet has a non-zero timestamp; empty string otherwise. We keep
  // this stable so `Date.parse(...)` succeeds inside GridViewer's
  // time-column auto-sniff and the histogram's bucket math.
  static _pktToRow(pkt) {
    return [
      String(pkt.no),
      PcapRenderer._formatPktTime(pkt.tsMicros),
      pkt.src || '',
      pkt.sport ? String(pkt.sport) : '',
      pkt.dst || '',
      pkt.dport ? String(pkt.dport) : '',
      pkt.proto || '',
      String(pkt.length | 0),
      pkt.info || '',
    ];
  }

  // Stream pkts as Timeline rows into a duck-typed single-row sink. The
  // sink is a function `(string[]) => void` so this helper can drive both
  // paths without importing either:
  //   • Worker bundle: `row => stream.push(row)` where `stream` is the
  //     `_makeRowStreamer` packed-chunk streamer in timeline.worker.js.
  //   • Sync main-thread fallback (`TimelineView.fromPcap`):
  //     `row => builder.addRow(row)` against a `RowStoreBuilder`.
  // Polls the AbortSignal every 256 packets per the renderer-contract
  // amortised-cancel rule (AGENTS.md §12). MAX_PACKETS is 1 000 000 so
  // a per-packet poll would dominate runtime.
  static _streamPacketRows(pkts, addRow, signal) {
    if (!pkts || !pkts.length || typeof addRow !== 'function') return;
    for (let i = 0; i < pkts.length; i++) {
      if ((i & 0xFF) === 0 && signal) throwIfAborted(signal);
      addRow(PcapRenderer._pktToRow(pkts[i]));
    }
  }

  static _formatPktTime(tsMicros) {
    if (!tsMicros) return '';
    // ms-precision Date — sub-millisecond goes into the fractional
    // text directly rather than via Date so we don't lose 3 µs of
    // precision to floating-point ms math.
    const ms = Math.floor(tsMicros / 1000);
    const subMs = tsMicros - ms * 1000;     // remaining microseconds (0..999)
    let iso;
    try {
      iso = new Date(ms).toISOString();
    } catch (_) {
      return '';
    }
    if (subMs === 0) return iso;
    // Splice the µs digits onto the existing ms component:
    // "2024-01-02T03:04:05.123Z" → "2024-01-02T03:04:05.123456Z"
    const dot = iso.lastIndexOf('.');
    if (dot < 0) return iso;
    const z = iso.indexOf('Z', dot);
    if (z < 0) return iso;
    const usPart = String(subMs).padStart(3, '0');
    return iso.slice(0, z) + usPart + iso.slice(z);
  }

  // ── IP-string formatters ──────────────────────────────────────────────
  static _ip4(bytes, off) {
    return `${bytes[off]}.${bytes[off + 1]}.${bytes[off + 2]}.${bytes[off + 3]}`;
  }

  static _ip6(bytes, off) {
    // Standard colon-hex with the longest run of zero-words collapsed to
    // '::'. We keep this hand-rolled so the renderer has zero deps.
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((bytes[off + i] << 8) | bytes[off + i + 1]).toString(16));
    }
    // Find longest run of '0'.
    let bestStart = -1, bestLen = 0;
    let curStart = -1, curLen = 0;
    for (let i = 0; i < 8; i++) {
      if (parts[i] === '0') {
        if (curStart < 0) curStart = i;
        curLen += 1;
        if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
      } else {
        curStart = -1; curLen = 0;
      }
    }
    if (bestLen >= 2) {
      const before = parts.slice(0, bestStart).join(':');
      const after = parts.slice(bestStart + bestLen).join(':');
      return `${before}::${after}`;
    }
    return parts.join(':');
  }

  static _countIp(map, ip) {
    map.set(ip, (map.get(ip) || 0) + 1);
  }

  static _rankTopN(map, n) {
    return Array.from(map.entries())
      .map(([key, count]) => ({ key, count }))
      .sort((a, b) => b.count - a.count || (a.key < b.key ? -1 : 1))
      .slice(0, n);
  }

  static _isPrivateOrLoopback(ip) {
    if (!ip) return true;
    if (ip.includes(':')) {
      // IPv6: ::1 (loopback), fe80::/10 (link-local), fc00::/7 (ULA),
      // unspecified (::).
      const lower = ip.toLowerCase();
      if (lower === '::' || lower === '::1') return true;
      if (lower.startsWith('fe8') || lower.startsWith('fe9')
          || lower.startsWith('fea') || lower.startsWith('feb')) return true;
      if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
      return false;
    }
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
    if (!m) return true;
    const a = +m[1], b = +m[2];
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 0) return true;
    if (a >= 224) return true; // multicast / reserved
    return false;
  }

  // ── UI ────────────────────────────────────────────────────────────────
  static _buildView(parsed, fileName) {
    const wrap = document.createElement('div');
    wrap.className = 'pcap-renderer';

    if (!parsed.kind) {
      const err = document.createElement('div');
      err.className = 'pcap-error';
      err.textContent = `PCAP parse error: ${parsed.error || 'unknown'}`;
      wrap.appendChild(err);
      wrap._rawText = lfNormalize(`PCAP parse error: ${parsed.error || 'unknown'}`);
      return wrap;
    }

    const headerCard = document.createElement('div');
    headerCard.className = 'pcap-card';
    const ht = document.createElement('table');
    ht.className = 'pcap-kv';
    const addRow = (table, k, v) => {
      const tr = document.createElement('tr');
      const tk = document.createElement('th'); tk.textContent = k;
      const tv = document.createElement('td'); tv.textContent = v;
      tr.appendChild(tk); tr.appendChild(tv);
      table.appendChild(tr);
    };
    addRow(ht, 'File', fileName || '(unknown)');
    addRow(ht, 'Format', parsed.formatLabel || '(unknown)');
    if (parsed.version) addRow(ht, 'Version', parsed.version);
    if (parsed.snaplen != null) addRow(ht, 'Snaplen', String(parsed.snaplen));
    if (parsed.linktype != null) {
      addRow(ht, 'Link-layer', `${parsed.linktypeName} (${parsed.linktype})`);
    }
    addRow(ht, 'Packets parsed', parsed.packetCount.toLocaleString('en-US')
      + (parsed.truncated ? ` (cap ${PcapRenderer.MAX_PACKETS.toLocaleString('en-US')} reached)` : ''));
    if (parsed.firstTs != null && parsed.lastTs != null) {
      const start = new Date(parsed.firstTs * 1000).toISOString();
      const finish = new Date(parsed.lastTs * 1000).toISOString();
      addRow(ht, 'Capture window', `${start} → ${finish}`);
    }
    if (parsed.error) addRow(ht, 'Parse warning', parsed.error);
    headerCard.appendChild(ht);
    wrap.appendChild(headerCard);

    // Top talkers card
    const topTalkers = PcapRenderer._rankTopN(parsed.ipCounts, PcapRenderer.TOP_TALKERS);
    if (topTalkers.length > 0) {
      const card = document.createElement('div');
      card.className = 'pcap-card';
      const title = document.createElement('h3');
      title.textContent = `Top talkers (${topTalkers.length} of ${parsed.ipCounts.size})`;
      card.appendChild(title);
      const tt = document.createElement('table');
      tt.className = 'pcap-kv';
      for (const { key, count } of topTalkers) {
        addRow(tt, key, `${count.toLocaleString('en-US')} packet${count === 1 ? '' : 's'}`);
      }
      card.appendChild(tt);
      wrap.appendChild(card);
    }

    // DNS / HTTP / SNI lists
    const addList = (heading, items) => {
      if (!items || items.length === 0) return;
      const card = document.createElement('div');
      card.className = 'pcap-card';
      const h = document.createElement('h3');
      h.textContent = `${heading} (${items.length})`;
      card.appendChild(h);
      const ul = document.createElement('ul');
      ul.className = 'pcap-list';
      for (const it of items.slice(0, 200)) {
        const li = document.createElement('li');
        li.textContent = it;
        ul.appendChild(li);
      }
      if (items.length > 200) {
        const li = document.createElement('li');
        li.textContent = `… and ${items.length - 200} more`;
        ul.appendChild(li);
      }
      card.appendChild(ul);
      wrap.appendChild(card);
    };
    addList('DNS query names', parsed.dnsNames);
    addList('HTTP Host headers', parsed.httpHosts);
    addList('TLS SNIs', parsed.tlsSnis);

    wrap._rawText = lfNormalize(PcapRenderer._renderTextDigest(parsed));
    return wrap;
  }

  static _renderTextDigest(parsed) {
    const lines = [];
    lines.push(`format: ${parsed.formatLabel || ''}`);
    if (parsed.version) lines.push(`version: ${parsed.version}`);
    if (parsed.snaplen != null) lines.push(`snaplen: ${parsed.snaplen}`);
    if (parsed.linktype != null) lines.push(`linktype: ${parsed.linktypeName} (${parsed.linktype})`);
    lines.push(`packets: ${parsed.packetCount}`);
    if (parsed.firstTs != null && parsed.lastTs != null) {
      lines.push(`window: ${new Date(parsed.firstTs * 1000).toISOString()} → ${new Date(parsed.lastTs * 1000).toISOString()}`);
    }
    if (parsed.dnsNames.length > 0) {
      lines.push('');
      lines.push('-- DNS --');
      for (const n of parsed.dnsNames) lines.push(n);
    }
    if (parsed.httpHosts.length > 0) {
      lines.push('');
      lines.push('-- HTTP Host --');
      for (const h of parsed.httpHosts) lines.push(h);
    }
    if (parsed.tlsSnis.length > 0) {
      lines.push('');
      lines.push('-- TLS SNI --');
      for (const s of parsed.tlsSnis) lines.push(s);
    }
    return lines.join('\n');
  }
}

// Expose globally for renderer-registry.js bootstrap. Guarded with
// `typeof window` because this file is also concatenated into the
// timeline.worker.js bundle (DedicatedWorkerGlobalScope has `self` /
// `globalThis` but no `window`); the unguarded assignment threw a
// ReferenceError there, halting bundle parsing before the
// `self.onmessage` dispatcher could register and freezing every
// Timeline-routed file load until the watchdog timeout. Other
// renderers (EvtxRenderer, SqliteRenderer, …) rely on the script-
// scope `class` declaration alone for cross-file access, so the
// `window.*` rebind is technically redundant in the main bundle —
// kept for symmetry with the original commit's intent.
if (typeof window !== 'undefined') {
  window.PcapRenderer = PcapRenderer;
}
