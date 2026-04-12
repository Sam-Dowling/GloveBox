'use strict';
// ════════════════════════════════════════════════════════════════════════════
// evtx-renderer.js — Windows Event Log (.evtx) binary parser + table view
// Pure JS — parses ElfFile header, chunks, records, and BinXml-encoded XML.
// ════════════════════════════════════════════════════════════════════════════

class EvtxRenderer {

  // ── Public API ───────────────────────────────────────────────────────────
  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer);
    const events = this._parse(bytes);
    return this._buildView(events, fileName);
  }

  analyzeForSecurity(buffer, fileName) {
    const bytes = new Uint8Array(buffer);
    const f = { risk: 'low', hasMacros: false, macroSize: 0, macroHash: '', autoExec: [], modules: [], externalRefs: [], metadata: {} };
    try {
      const events = this._parse(bytes);
      f.metadata.eventCount = events.length;
      if (events.length) {
        const first = events[0], last = events[events.length - 1];
        if (first.timestamp) f.metadata.firstEvent = first.timestamp;
        if (last.timestamp) f.metadata.lastEvent = last.timestamp;
      }
      // Collect unique channels/providers
      const channels = new Set(), providers = new Set();
      for (const ev of events) {
        if (ev.channel) channels.add(ev.channel);
        if (ev.provider) providers.add(ev.provider);
      }
      if (channels.size) f.metadata.channels = [...channels].join(', ');
      if (providers.size) f.metadata.providers = [...providers].slice(0, 20).join(', ');

      // Flag suspicious event IDs — comprehensive threat-hunting patterns
      // Each entry: [eventId, description, severity, riskEscalation]
      // riskEscalation: null = no change, 'high'/'medium' = escalate if currently lower
      const suspiciousPatterns = [
        // ── Security log tampering ───────────────────────────────────────
        [1100, 'Event 1100: Event logging service shut down', 'high', 'high'],
        [1102, 'Event 1102: Security audit log was cleared', 'high', 'high'],
        [104,  'Event 104: System log was cleared', 'high', 'high'],

        // ── Authentication & logon ───────────────────────────────────────
        [4624, 'Event 4624: Successful logon events present', 'info', null],
        [4625, 'Event 4625: Failed logon attempts present', 'medium', null],
        [4634, 'Event 4634: Account logoff events present', 'info', null],
        [4648, 'Event 4648: Logon using explicit credentials (pass-the-hash indicator)', 'high', 'medium'],
        [4672, 'Event 4672: Special privilege logon events', 'medium', null],

        // ── Kerberos & NTLM ─────────────────────────────────────────────
        [4768, 'Event 4768: Kerberos TGT requested', 'info', null],
        [4769, 'Event 4769: Kerberos service ticket requested', 'info', null],
        [4771, 'Event 4771: Kerberos pre-authentication failed', 'medium', null],
        [4776, 'Event 4776: NTLM credential validation', 'info', null],

        // ── Process creation & execution ─────────────────────────────────
        [4688, 'Event 4688: Process creation events present', 'medium', null],
        [4689, 'Event 4689: Process termination events present', 'info', null],

        // ── Account & group management ───────────────────────────────────
        [4720, 'Event 4720: User account created', 'medium', null],
        [4722, 'Event 4722: User account enabled', 'medium', null],
        [4723, 'Event 4723: Password change attempt', 'info', null],
        [4724, 'Event 4724: Password reset attempt', 'medium', null],
        [4725, 'Event 4725: User account disabled', 'medium', null],
        [4726, 'Event 4726: User account deleted', 'medium', null],
        [4728, 'Event 4728: Member added to security-enabled global group', 'medium', null],
        [4732, 'Event 4732: Member added to security-enabled local group', 'medium', null],
        [4733, 'Event 4733: Member removed from security-enabled local group', 'medium', null],
        [4735, 'Event 4735: Security-enabled local group changed', 'medium', null],
        [4738, 'Event 4738: User account changed', 'medium', null],
        [4740, 'Event 4740: User account locked out', 'medium', null],
        [4756, 'Event 4756: Member added to universal security group', 'medium', null],

        // ── Object access & registry ─────────────────────────────────────
        [4656, 'Event 4656: Handle to an object was requested', 'info', null],
        [4657, 'Event 4657: Registry value was modified', 'medium', null],
        [4663, 'Event 4663: Attempt to access an object', 'info', null],

        // ── Services & scheduled tasks ───────────────────────────────────
        [4697, 'Event 4697: Service installed in the system', 'medium', 'medium'],
        [4698, 'Event 4698: Scheduled task created', 'medium', 'medium'],
        [4699, 'Event 4699: Scheduled task deleted', 'medium', null],
        [4700, 'Event 4700: Scheduled task enabled', 'medium', null],
        [4701, 'Event 4701: Scheduled task disabled', 'info', null],
        [4702, 'Event 4702: Scheduled task updated', 'medium', null],
        [7034, 'Event 7034: Service crashed unexpectedly', 'medium', null],
        [7036, 'Event 7036: Service entered running/stopped state', 'info', null],
        [7040, 'Event 7040: Service start type changed (persistence indicator)', 'medium', 'medium'],
        [7045, 'Event 7045: New service installed in the system', 'medium', 'medium'],

        // ── Network share access ─────────────────────────────────────────
        [5140, 'Event 5140: Network share object was accessed', 'medium', null],
        [5145, 'Event 5145: Network share object access checked', 'info', null],
        [5156, 'Event 5156: Windows Filtering Platform allowed a connection', 'info', null],

        // ── PowerShell ───────────────────────────────────────────────────
        [4103, 'Event 4103: PowerShell module logging', 'medium', 'medium'],
        [4104, 'Event 4104: PowerShell script block logging', 'medium', 'medium'],
        [40961, 'Event 40961: PowerShell console started', 'info', null],
        [40962, 'Event 40962: PowerShell console ready', 'info', null],
        [53504, 'Event 53504: PowerShell ISE session started', 'info', null],

        // ── Sysmon ───────────────────────────────────────────────────────
        [1,  'Sysmon Event 1: Process created', 'medium', null],
        [2,  'Sysmon Event 2: File creation time changed (timestomping)', 'high', 'medium'],
        [3,  'Sysmon Event 3: Network connection detected', 'medium', null],
        [5,  'Sysmon Event 5: Process terminated', 'info', null],
        [6,  'Sysmon Event 6: Driver loaded', 'medium', null],
        [7,  'Sysmon Event 7: Image loaded (DLL)', 'info', null],
        [8,  'Sysmon Event 8: CreateRemoteThread (process injection indicator)', 'high', 'high'],
        [9,  'Sysmon Event 9: RawAccessRead (direct disk access)', 'high', 'medium'],
        [10, 'Sysmon Event 10: Process accessed (credential dumping indicator)', 'high', 'high'],
        [11, 'Sysmon Event 11: File created', 'info', null],
        [12, 'Sysmon Event 12: Registry object added or deleted', 'medium', null],
        [13, 'Sysmon Event 13: Registry value set', 'medium', null],
        [14, 'Sysmon Event 14: Registry object renamed', 'medium', null],
        [15, 'Sysmon Event 15: File stream created (Alternate Data Streams)', 'medium', 'medium'],
        [17, 'Sysmon Event 17: Pipe created', 'medium', null],
        [18, 'Sysmon Event 18: Pipe connected', 'medium', null],
        [19, 'Sysmon Event 19: WMI EventFilter activity detected', 'high', 'medium'],
        [20, 'Sysmon Event 20: WMI EventConsumer activity detected', 'high', 'medium'],
        [21, 'Sysmon Event 21: WMI EventConsumerToFilter activity detected', 'high', 'medium'],
        [22, 'Sysmon Event 22: DNS query', 'info', null],
        [23, 'Sysmon Event 23: File deleted', 'info', null],
        [24, 'Sysmon Event 24: Clipboard change', 'medium', null],
        [25, 'Sysmon Event 25: Process tampering (hollowing/herpaderping)', 'high', 'high'],
        [26, 'Sysmon Event 26: File delete logged', 'info', null],
        [27, 'Sysmon Event 27: File block executable', 'medium', null],
        [28, 'Sysmon Event 28: File block shredding', 'medium', null],
        [29, 'Sysmon Event 29: File executable detected', 'medium', null],

        // ── Windows Defender ─────────────────────────────────────────────
        [1006, 'Defender Event 1006: Malware or unwanted software detected', 'high', 'high'],
        [1007, 'Defender Event 1007: Action to protect system from malware', 'high', 'high'],
        [1008, 'Defender Event 1008: Failed to take action on malware', 'high', 'high'],
        [1009, 'Defender Event 1009: Item restored from quarantine', 'medium', null],
        [1116, 'Defender Event 1116: Detected malware or unwanted software', 'high', 'high'],
        [1117, 'Defender Event 1117: Performed action to protect from malware', 'high', 'high'],
        [5001, 'Defender Event 5001: Real-time protection disabled', 'high', 'high'],
        [5004, 'Defender Event 5004: Real-time protection config changed', 'medium', null],
        [5007, 'Defender Event 5007: Antimalware platform config changed', 'medium', null],
        [5010, 'Defender Event 5010: Scanning for malware disabled', 'high', 'medium'],
        [5012, 'Defender Event 5012: Scanning for viruses disabled', 'high', 'medium'],

        // ── WMI ──────────────────────────────────────────────────────────
        [5857, 'WMI Event 5857: Provider started', 'info', null],
        [5858, 'WMI Event 5858: Provider error', 'medium', null],
        [5859, 'WMI Event 5859: Subscription operation', 'medium', 'medium'],
        [5860, 'WMI Event 5860: Temporary event created', 'medium', null],
        [5861, 'WMI Event 5861: Permanent event subscription (persistence)', 'high', 'medium'],

        // ── AppLocker ────────────────────────────────────────────────────
        [8003, 'AppLocker Event 8003: Executable was allowed', 'info', null],
        [8004, 'AppLocker Event 8004: Executable was blocked', 'medium', null],
        [8006, 'AppLocker Event 8006: Script/MSI was allowed', 'info', null],
        [8007, 'AppLocker Event 8007: Script/MSI was blocked', 'medium', null],

        // ── Remote Desktop ───────────────────────────────────────────────
        [1149, 'RDP Event 1149: User authentication succeeded (remote logon)', 'medium', null],
        [4778, 'Event 4778: Session reconnected to a window station', 'info', null],
        [4779, 'Event 4779: Session disconnected from a window station', 'info', null],

        // ── Bits / SMB ───────────────────────────────────────────────────
        [60, 'BITS Event 60: BITS transfer started (possible data exfil)', 'medium', null],
      ];

      // Build lookup of IDs to detect
      const suspiciousIds = new Set(suspiciousPatterns.map(p => p[0]));

      // Also track provider context to differentiate Sysmon EIDs from Security EIDs
      const foundByProvider = new Map(); // eid -> Set<provider>
      const found = new Set();
      for (const ev of events) {
        const eid = parseInt(ev.eventId, 10);
        if (suspiciousIds.has(eid)) {
          found.add(eid);
          if (!foundByProvider.has(eid)) foundByProvider.set(eid, new Set());
          if (ev.provider) foundByProvider.get(eid).add(ev.provider);
        }
      }

      // Count events per suspicious ID for enriched messages
      const eidCounts = {};
      for (const ev of events) {
        const eid = parseInt(ev.eventId, 10);
        if (found.has(eid)) eidCounts[eid] = (eidCounts[eid] || 0) + 1;
      }

      const riskRank = { low: 0, medium: 1, high: 2, critical: 3 };
      // Sysmon events (low EIDs 1-29) should only match when provider is Sysmon
      const sysmonEids = new Set([1,2,3,5,6,7,8,9,10,11,12,13,14,15,17,18,19,20,21,22,23,24,25,26,27,28,29]);

      for (const [eid, desc, severity, riskEsc] of suspiciousPatterns) {
        if (!found.has(eid)) continue;

        // For Sysmon EIDs, only report if the provider is actually Sysmon
        if (sysmonEids.has(eid)) {
          const providers = foundByProvider.get(eid);
          const isSysmon = providers && [...providers].some(p => /sysmon/i.test(p));
          if (!isSysmon) continue;
        }

        const count = eidCounts[eid] || 0;
        const countSuffix = count > 1 ? ` (${count} events)` : '';
        f.externalRefs.push({ type: IOC.PATTERN, url: desc + countSuffix, severity });

        if (riskEsc && (riskRank[riskEsc] || 0) > (riskRank[f.risk] || 0)) {
          f.risk = riskEsc;
        }
      }

      if (f.risk === 'low' && f.externalRefs.length > 0) f.risk = 'medium';

      // ── Extract IOCs from event data fields ─────────────────────────
      this._extractEvtxIOCs(events, f);
    } catch (e) {
      f.externalRefs.push({ type: IOC.INFO, url: 'EVTX parse warning: ' + e.message, severity: 'info' });
    }
    return f;
  }

  // ── EVTX binary parsing ─────────────────────────────────────────────────

  _parse(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    // Validate file header magic: "ElfFile\0"
    const magic = String.fromCharCode(...bytes.subarray(0, 8));
    if (magic !== 'ElfFile\0') throw new Error('Not a valid EVTX file (bad magic)');

    const chunkCount = dv.getUint16(0x28, true);
    const headerSize = 4096; // File header is always 4096 bytes
    const chunkSize = 65536; // Each chunk is 64KB

    const events = [];
    const maxEvents = 50000; // Safety limit

    for (let ci = 0; ci < chunkCount && events.length < maxEvents; ci++) {
      const chunkOff = headerSize + ci * chunkSize;
      if (chunkOff + chunkSize > bytes.length) break;

      // Validate chunk magic: "ElfChnk\0"
      const cMagic = String.fromCharCode(...bytes.subarray(chunkOff, chunkOff + 8));
      if (cMagic !== 'ElfChnk\0') continue;

      // Parse string table from chunk header for BinXml string references
      const stringTable = this._parseChunkStringTable(bytes, dv, chunkOff);

      // Records start at offset 0x200 within the chunk (512 bytes after chunk header)
      let recOff = chunkOff + 0x200;
      const chunkEnd = chunkOff + chunkSize;

      while (recOff + 24 < chunkEnd && events.length < maxEvents) {
        // Record magic: 0x00002a2a
        const recMagic = dv.getUint32(recOff, true);
        if (recMagic !== 0x00002a2a) break;

        const recSize = dv.getUint32(recOff + 4, true);
        if (recSize < 24 || recOff + recSize > chunkEnd) break;

        const recordId = this._getUint64(dv, recOff + 8, true);
        const timestamp = this._fileTimeToDate(dv, recOff + 16);

        // BinXml starts at recOff + 24
        const binXmlOff = recOff + 24;
        const binXmlLen = recSize - 24 - 4; // minus header and trailing copy of size

        let ev = { recordId, timestamp: timestamp ? timestamp.toISOString() : '', eventId: '', level: '', channel: '', provider: '', computer: '', eventData: '' };
        try {
          const xml = this._decodeBinXml(bytes, dv, binXmlOff, binXmlLen, stringTable, chunkOff);
          Object.assign(ev, xml);
        } catch (_) { /* best-effort */ }

        events.push(ev);
        recOff += recSize;
      }
    }
    return events;
  }

  // ── Chunk string table ──────────────────────────────────────────────────
  _parseChunkStringTable(bytes, dv, chunkOff) {
    // The chunk header contains a table of 64 string offsets at offset 0x80
    const table = {};
    for (let i = 0; i < 64; i++) {
      const strOff = dv.getUint32(chunkOff + 0x80 + i * 4, true);
      if (strOff === 0) continue;
      const absOff = chunkOff + strOff;
      if (absOff + 6 > bytes.length) continue;
      // Each string entry: next_offset(4) + hash(2) + length(2) + utf16le chars
      try {
        const len = dv.getUint16(absOff + 6, true);
        if (len > 0 && absOff + 8 + len * 2 <= bytes.length) {
          table[strOff] = this._readUtf16(bytes, absOff + 8, len);
        }
      } catch (_) { /* skip */ }
    }
    return table;
  }

  // ── BinXml decoder ──────────────────────────────────────────────────────
  _decodeBinXml(bytes, dv, off, maxLen, stringTable, chunkOff) {
    const result = { eventId: '', level: '', channel: '', provider: '', computer: '', opcode: '', task: '', eventData: '' };
    const end = off + maxLen;
    const eventDataParts = [];

    // State tracking for element path
    const elemStack = [];
    let currentAttrName = '';
    let inSystem = false, inEventData = false, inUserData = false;
    let lastDataName = '';

    const ctx = { pos: off };

    const readToken = () => {
      if (ctx.pos >= end) return null;
      const token = bytes[ctx.pos++];
      return token;
    };

    const peekByte = () => ctx.pos < end ? bytes[ctx.pos] : -1;

    // Read a BinXml string: uint16 length + utf16le chars + NUL (2 bytes)
    const readBinXmlString = () => {
      if (ctx.pos + 2 > end) return '';
      const len = dv.getUint16(ctx.pos, true); ctx.pos += 2;
      if (len === 0) return '';
      const str = this._readUtf16(bytes, ctx.pos, len);
      ctx.pos += len * 2 + 2; // +2 for NUL terminator
      return str;
    };

    // Read a string from chunk string table reference
    const readStringRef = () => {
      if (ctx.pos + 4 > end) return '';
      const strOff = dv.getUint32(ctx.pos, true); ctx.pos += 4;
      if (stringTable[strOff]) return stringTable[strOff];
      // Try reading directly from chunk
      const absOff = chunkOff + strOff;
      if (absOff + 8 < bytes.length) {
        try {
          const len = dv.getUint16(absOff + 6, true);
          if (len > 0 && len < 500 && absOff + 8 + len * 2 <= bytes.length) {
            return this._readUtf16(bytes, absOff + 8, len);
          }
        } catch (_) { }
      }
      return '';
    };

    // Read a name from BinXml: offset(4) to name entry
    // Name entry format: next_offset(4) + hash(2) + char_count(2) + utf16le + NUL(2)
    // If the name entry is inline (first occurrence), it sits at the current stream position
    // and we must skip past it.
    const readName = () => {
      if (ctx.pos + 4 > end) return '';
      const nameOff = dv.getUint32(ctx.pos, true); ctx.pos += 4;
      const absOff = chunkOff + nameOff;

      // Inline name entry: the name data is at the current position
      if (absOff === ctx.pos && ctx.pos + 8 <= bytes.length) {
        try {
          const nLen = dv.getUint16(ctx.pos + 6, true);
          const skipSize = 4 + 2 + 2 + (nLen > 0 && nLen < 500 ? nLen * 2 : 0) + 2;
          const name = (nLen > 0 && nLen < 500 && ctx.pos + 8 + nLen * 2 + 2 <= bytes.length)
            ? this._readUtf16(bytes, ctx.pos + 8, nLen) : '';
          ctx.pos += skipSize;
          return name;
        } catch (_) { }
      }

      // Not inline — read from previously stored offset
      if (absOff + 8 < bytes.length) {
        try {
          const nLen = dv.getUint16(absOff + 6, true);
          if (nLen > 0 && nLen < 500 && absOff + 8 + nLen * 2 + 2 <= bytes.length) {
            return this._readUtf16(bytes, absOff + 8, nLen);
          }
        } catch (_) { }
      }
      return '';
    };

    // Read a typed value
    const readValue = (type) => {
      switch (type) {
        case 0x00: return ''; // Null
        case 0x01: { // UnicodeString — uint16 charCount + utf16le chars
          if (ctx.pos + 2 > end) return '';
          const len = dv.getUint16(ctx.pos, true); ctx.pos += 2;
          const s = this._readUtf16(bytes, ctx.pos, len);
          ctx.pos += len * 2;
          return s;
        }
        case 0x02: { // AnsiString
          if (ctx.pos + 2 > end) return '';
          const len = dv.getUint16(ctx.pos, true); ctx.pos += 2;
          const s = String.fromCharCode(...bytes.subarray(ctx.pos, ctx.pos + len));
          ctx.pos += len;
          return s;
        }
        case 0x03: { // Int8
          if (ctx.pos + 1 > end) return '';
          const v = (bytes[ctx.pos] << 24) >> 24; ctx.pos += 1;
          return String(v);
        }
        case 0x04: { // UInt8
          if (ctx.pos + 1 > end) return '';
          return String(bytes[ctx.pos++]);
        }
        case 0x05: { // Int16
          if (ctx.pos + 2 > end) return '';
          const v = dv.getInt16(ctx.pos, true); ctx.pos += 2;
          return String(v);
        }
        case 0x06: { // UInt16
          if (ctx.pos + 2 > end) return '';
          const v = dv.getUint16(ctx.pos, true); ctx.pos += 2;
          return String(v);
        }
        case 0x07: { // Int32
          if (ctx.pos + 4 > end) return '';
          const v = dv.getInt32(ctx.pos, true); ctx.pos += 4;
          return String(v);
        }
        case 0x08: { // UInt32
          if (ctx.pos + 4 > end) return '';
          const v = dv.getUint32(ctx.pos, true); ctx.pos += 4;
          return String(v);
        }
        case 0x09: { // Int64
          if (ctx.pos + 8 > end) return '';
          const lo = dv.getUint32(ctx.pos, true), hi = dv.getInt32(ctx.pos + 4, true);
          ctx.pos += 8;
          return String(hi * 0x100000000 + lo);
        }
        case 0x0A: { // UInt64
          if (ctx.pos + 8 > end) return '';
          const lo = dv.getUint32(ctx.pos, true), hi = dv.getUint32(ctx.pos + 4, true);
          ctx.pos += 8;
          if (hi === 0) return String(lo);
          return String(hi * 0x100000000 + lo);
        }
        case 0x0B: { // Float
          if (ctx.pos + 4 > end) return '';
          const v = dv.getFloat32(ctx.pos, true); ctx.pos += 4;
          return String(v);
        }
        case 0x0C: { // Double
          if (ctx.pos + 8 > end) return '';
          const v = dv.getFloat64(ctx.pos, true); ctx.pos += 8;
          return String(v);
        }
        case 0x0D: { // Boolean
          if (ctx.pos + 4 > end) return '';
          const v = dv.getUint32(ctx.pos, true); ctx.pos += 4;
          return v ? 'true' : 'false';
        }
        case 0x0E: { // Binary
          if (ctx.pos + 2 > end) return '';
          const len = dv.getUint16(ctx.pos, true); ctx.pos += 2;
          const hex = Array.from(bytes.subarray(ctx.pos, ctx.pos + Math.min(len, 64))).map(b => b.toString(16).padStart(2, '0')).join(' ');
          ctx.pos += len;
          return hex + (len > 64 ? '…' : '');
        }
        case 0x0F: { // GUID
          if (ctx.pos + 16 > end) return '';
          const g = this._readGuid(dv, ctx.pos);
          ctx.pos += 16;
          return g;
        }
        case 0x10: { // SizeT (pointer-sized, assume 8 bytes)
          if (ctx.pos + 8 > end) return '';
          const v = this._getUint64(dv, ctx.pos, true);
          ctx.pos += 8;
          return String(v);
        }
        case 0x11: { // FILETIME
          if (ctx.pos + 8 > end) return '';
          const d = this._fileTimeToDate(dv, ctx.pos);
          ctx.pos += 8;
          return d ? d.toISOString() : '0';
        }
        case 0x12: { // SYSTEMTIME
          if (ctx.pos + 16 > end) return '';
          const yr = dv.getUint16(ctx.pos, true), mo = dv.getUint16(ctx.pos + 2, true);
          const dy = dv.getUint16(ctx.pos + 6, true), hr = dv.getUint16(ctx.pos + 8, true);
          const mi = dv.getUint16(ctx.pos + 10, true), sc = dv.getUint16(ctx.pos + 12, true);
          const ms = dv.getUint16(ctx.pos + 14, true);
          ctx.pos += 16;
          return `${yr}-${String(mo).padStart(2,'0')}-${String(dy).padStart(2,'0')}T${String(hr).padStart(2,'0')}:${String(mi).padStart(2,'0')}:${String(sc).padStart(2,'0')}.${String(ms).padStart(3,'0')}Z`;
        }
        case 0x13: { // SID
          if (ctx.pos + 2 > end) return '';
          const len = dv.getUint16(ctx.pos, true); ctx.pos += 2;
          const sidBytes = bytes.subarray(ctx.pos, ctx.pos + len);
          ctx.pos += len;
          return this._parseSid(sidBytes);
        }
        case 0x14: { // HexInt32
          if (ctx.pos + 4 > end) return '';
          const v = dv.getUint32(ctx.pos, true); ctx.pos += 4;
          return '0x' + v.toString(16).padStart(8, '0');
        }
        case 0x15: { // HexInt64
          if (ctx.pos + 8 > end) return '';
          const lo = dv.getUint32(ctx.pos, true), hi = dv.getUint32(ctx.pos + 4, true);
          ctx.pos += 8;
          return '0x' + hi.toString(16).padStart(8, '0') + lo.toString(16).padStart(8, '0');
        }
        case 0x21: { // BinXml (nested)
          // Skip — too complex to recurse safely here
          return '[nested XML]';
        }
        default: return '';
      }
    };

    // Simple iterative BinXml walk — extract fields without full tree building
    const MAX_ITERS = 200000;
    let iters = 0;

    try {
      while (ctx.pos < end && iters++ < MAX_ITERS) {
        const tokenByte = bytes[ctx.pos];
        if (tokenByte === undefined) break;

        // The high nibble can carry flags (0x40 = has attributes, 0x80 = ...)
        const token = tokenByte & 0x0F;

        if (token === 0x00) { // EOF
          ctx.pos++;
          break;
        }

        if (token === 0x01) { // OpenStartElement
          ctx.pos++; // token
          // Dependency ID (2 bytes) - for template substitutions
          if (tokenByte & 0x40) { ctx.pos += 2; } // has dependency
          const dataSize = dv.getUint32(ctx.pos, true); ctx.pos += 4;
          const name = readName();
          // Skip attribute count (4 bytes)
          ctx.pos += 4;

          elemStack.push(name);
          if (name === 'System') inSystem = true;
          if (name === 'EventData') inEventData = true;
          if (name === 'UserData') inUserData = true;
          if (name === 'Data' && (inEventData || inUserData)) lastDataName = '';
          continue;
        }

        if (token === 0x02) { // CloseStartElement
          ctx.pos++;
          continue;
        }

        if (token === 0x03) { // CloseEmptyElement
          ctx.pos++;
          const popped = elemStack.pop() || '';
          if (popped === 'System') inSystem = false;
          if (popped === 'EventData') inEventData = false;
          if (popped === 'UserData') inUserData = false;
          continue;
        }

        if (token === 0x04) { // CloseElement
          ctx.pos++;
          const popped = elemStack.pop() || '';
          if (popped === 'System') inSystem = false;
          if (popped === 'EventData') inEventData = false;
          if (popped === 'UserData') inUserData = false;
          continue;
        }

        if (token === 0x05) { // Value (text content)
          ctx.pos++; // token
          const valType = bytes[ctx.pos++];
          const val = readValue(valType);
          const cur = elemStack[elemStack.length - 1] || '';

          if (inSystem) {
            if (cur === 'EventID' && !result.eventId) result.eventId = val;
            else if (cur === 'Level') result.level = this._levelName(val);
            else if (cur === 'Channel') result.channel = val;
            else if (cur === 'Computer') result.computer = val;
            else if (cur === 'Opcode') result.opcode = val;
            else if (cur === 'Task') result.task = val;
          }
          if ((inEventData || inUserData) && val) {
            const prefix = lastDataName ? lastDataName + '=' : '';
            eventDataParts.push(prefix + val);
          }
          continue;
        }

        if (token === 0x06) { // Attribute
          ctx.pos++; // token
          const attrName = readName();
          currentAttrName = attrName;
          continue;
        }

        if (token === 0x07) { // CDataSection — skip
          ctx.pos++;
          continue;
        }

        if (token === 0x08) { // CharRef — skip
          ctx.pos++;
          continue;
        }

        if (token === 0x09) { // EntityRef
          ctx.pos++; // token
          readName();
          continue;
        }

        if (token === 0x0A) { // PITarget
          ctx.pos++; // token
          readName();
          continue;
        }

        if (token === 0x0B) { // PIData
          ctx.pos++; // token
          readBinXmlString();
          continue;
        }

        if (token === 0x0C) { // Template instance
          ctx.pos++; // token
          ctx.pos++; // unknown/reserved byte
          ctx.pos += 4; // skip template ID hash (4 bytes)
          const templateOff = dv.getUint32(ctx.pos, true); ctx.pos += 4;

          // Try to parse the template definition from chunk
          // Template: next_offset(4) + GUID(16) + data_size(4) + data...
          const absTemplOff = chunkOff + templateOff;
          let templateDataSize = 0;
          let templateNames = [];
          if (absTemplOff + 24 < bytes.length) {
            templateDataSize = dv.getUint32(absTemplOff + 20, true);
            // Parse template to get element/attribute names
            templateNames = this._parseTemplateLite(bytes, dv, absTemplOff + 24, templateDataSize, chunkOff);
          }

          // If template definition is inline at current position, skip past it
          // Template layout: next_offset(4) + GUID(16) + data_size(4) + data(templateDataSize)
          if (absTemplOff === ctx.pos) {
            ctx.pos = absTemplOff + 24 + templateDataSize;
          }

          // Substitution array follows: numValues(4) + (size(2) + type(1)) * numValues + values
          if (ctx.pos + 4 > end) break;
          const numValues = dv.getUint32(ctx.pos, true); ctx.pos += 4;

          // Read descriptor array: for each value, size(2) + type(1) + padding(1) = 4 bytes
          const descs = [];
          for (let i = 0; i < numValues && ctx.pos + 4 <= end; i++) {
            const vSize = dv.getUint16(ctx.pos, true); ctx.pos += 2;
            const vType = bytes[ctx.pos]; ctx.pos += 2; // type(1) + padding(1)
            descs.push({ size: vSize, type: vType });
          }

          // Read actual values, saving offsets for nested BinXml extraction
          const values = [];
          const valueOffsets = [];
          for (let i = 0; i < numValues && ctx.pos < end; i++) {
            const desc = descs[i];
            valueOffsets.push(ctx.pos);
            if (desc.size === 0) { values.push(''); continue; }
            const vStart = ctx.pos;
            const val = this._readSubstitutionValue(bytes, dv, ctx.pos, desc.type, desc.size);
            values.push(val);
            ctx.pos = vStart + desc.size;
          }

          // Map template names to values; returns any unpaired Data.Name field names
          const outerFieldNames = this._applyTemplate(result, templateNames, values, eventDataParts) || [];

          // Extract EventData from nested BinXml substitution values (type 0x21)
          for (let i = 0; i < descs.length; i++) {
            if (descs[i].type === 0x21 && descs[i].size > 0 && i < valueOffsets.length) {
              try {
                const nestedData = this._extractNestedEventData(bytes, dv, valueOffsets[i], descs[i].size, stringTable, chunkOff);
                if (nestedData) {
                  // If we have outer field names (e.g., Sysmon Data.Name attributes),
                  // zip them with the flat values from the nested blob
                  if (outerFieldNames.length > 0) {
                    const innerParts = nestedData.split(' | ');
                    if (innerParts.length === outerFieldNames.length) {
                      // Perfect match — label each value with its field name
                      for (let j = 0; j < outerFieldNames.length; j++) {
                        eventDataParts.push(outerFieldNames[j] + '=' + innerParts[j]);
                      }
                    } else if (innerParts.length > 0 && outerFieldNames.length > innerParts.length) {
                      // More names than values — label what we can
                      for (let j = 0; j < innerParts.length; j++) {
                        eventDataParts.push(outerFieldNames[j] + '=' + innerParts[j]);
                      }
                    } else {
                      // Mismatch — push as-is
                      eventDataParts.push(nestedData);
                    }
                  } else {
                    eventDataParts.push(nestedData);
                  }
                }
              } catch (_) { /* best effort */ }
            }
          }
          continue;
        }

        if (token === 0x0D) { // Normal substitution
          ctx.pos++;
          if (ctx.pos + 3 > end) break;
          ctx.pos += 2; // subId
          ctx.pos += 1; // valType
          continue;
        }

        if (token === 0x0E) { // Optional substitution
          ctx.pos++;
          if (ctx.pos + 3 > end) break;
          ctx.pos += 2; // subId
          ctx.pos += 1; // valType
          continue;
        }

        if (token === 0x0F) { // FragmentHeader — skip token + major + minor + flags
          ctx.pos += 4;
          continue;
        }

        // Unknown token — try to skip
        ctx.pos++;
      }
    } catch (_) { /* best-effort parsing */ }

    if (eventDataParts.length) {
      result.eventData = eventDataParts.join(' | ');
    }
    return result;
  }

  // ── Template lite parser — extracts element names + substitution mapping ─
  _parseTemplateLite(bytes, dv, off, maxLen, chunkOff) {
    const names = []; // { idx, elem, attr, type }
    const end = off + maxLen;
    const elemStack = [];
    let currentAttrName = '';
    let pos = off;
    let iters = 0;

    // Helper to read name at chunk-relative offset
    // Name entry: next_offset(4) + hash(2) + char_count(2) + utf16le + NUL(2)
    const readNameAt = (nameOff) => {
      const absOff = chunkOff + nameOff;
      if (absOff + 8 < bytes.length) {
        const nLen = dv.getUint16(absOff + 6, true);
        if (nLen > 0 && nLen < 500 && absOff + 8 + nLen * 2 + 2 <= bytes.length) {
          return this._readUtf16(bytes, absOff + 8, nLen);
        }
      }
      return '';
    };

    try {
      while (pos < end && iters++ < 10000) {
        const tokenByte = bytes[pos];
        const token = tokenByte & 0x0F;

        if (token === 0x00) break; // EOF

        if (token === 0x0F) { // FragmentHeader — skip 4 bytes
          pos += 4;
          continue;
        }

        if (token === 0x01) { // OpenStartElement
          pos++;
          pos += 2; // dependency ID — always present in template bodies
          pos += 4; // data size
          if (pos + 4 > end) break;
          const nameOff = dv.getUint32(pos, true); pos += 4;
          // Skip inline name entry if present (first occurrence stores name data inline)
          if (chunkOff + nameOff === pos && pos + 8 <= bytes.length) {
            const nLen = dv.getUint16(pos + 6, true);
            pos += 4 + 2 + 2 + (nLen > 0 && nLen < 500 ? nLen * 2 : 0) + 2;
          }
          const name = readNameAt(nameOff);
          if (tokenByte & 0x40) pos += 4; // attribute list size — only when 0x40 flag set
          elemStack.push(name);
          continue;
        }

        if (token === 0x02 || token === 0x03) { // CloseStartElement / CloseEmptyElement
          pos++;
          if (token === 0x03) elemStack.pop();
          continue;
        }

        if (token === 0x04) { // CloseElement
          pos++;
          elemStack.pop();
          continue;
        }

        if (token === 0x05) { // Value — read literal value from template body
          pos++; // token
          if (pos >= end) break;
          const vType = bytes[pos++]; // type
          const cur = elemStack[elemStack.length - 1] || '';
          // Read and capture literal value, then skip data
          switch (vType) {
            case 0x01: { // UnicodeString: uint16 charCount + utf16le chars
              if (pos + 2 > end) break;
              const vLen = dv.getUint16(pos, true); pos += 2;
              if (vLen > 0 && vLen < 2000 && pos + vLen * 2 <= end) {
                const lit = this._readUtf16(bytes, pos, vLen);
                if (lit && cur) names.push({ idx: -1, elem: cur, attr: currentAttrName, type: -1, literal: lit });
                currentAttrName = '';
              }
              pos += vLen * 2;
              break;
            }
            case 0x02: case 0x0E: case 0x13: { // AnsiString/Binary/SID: uint16 byteLen + data
              if (pos + 2 > end) break;
              const vLen = dv.getUint16(pos, true); pos += 2;
              pos += vLen;
              break;
            }
            case 0x03: case 0x04: pos += 1; break; // Int8/UInt8
            case 0x05: case 0x06: pos += 2; break; // Int16/UInt16
            case 0x07: case 0x08: case 0x0B: case 0x0D: case 0x14: pos += 4; break; // Int32/UInt32/Float/Bool/HexInt32
            case 0x09: case 0x0A: case 0x0C: case 0x10: case 0x11: case 0x15: pos += 8; break; // Int64/UInt64/Double/SizeT/FILETIME/HexInt64
            case 0x0F: case 0x12: pos += 16; break; // GUID/SYSTEMTIME
            default: break;
          }
          continue;
        }

        if (token === 0x06) { // Attribute
          pos++;
          if (pos + 4 > end) break;
          const nameOff = dv.getUint32(pos, true); pos += 4;
          // Skip inline name entry if present (first occurrence stores name data inline)
          if (chunkOff + nameOff === pos && pos + 8 <= bytes.length) {
            const nLen = dv.getUint16(pos + 6, true);
            pos += 4 + 2 + 2 + (nLen > 0 && nLen < 500 ? nLen * 2 : 0) + 2;
          }
          currentAttrName = readNameAt(nameOff);
          continue;
        }

        if (token === 0x07) { // CDataSection — skip
          pos++;
          continue;
        }

        if (token === 0x0D || token === 0x0E) { // Normal/Optional Substitution
          pos++;
          if (pos + 3 > end) break;
          const subId = dv.getUint16(pos, true); pos += 2;
          const valType = bytes[pos++];
          const cur = elemStack[elemStack.length - 1] || '';
          names.push({ idx: subId, elem: cur, attr: currentAttrName, type: valType });
          currentAttrName = '';
          continue;
        }

        if (token === 0x0C) { // Nested TemplateInstance — stop
          break;
        }

        pos++; // unknown token — skip
      }
    } catch (_) { /* best effort */ }
    return names;
  }

  // ── Apply template substitution values to result ─────────────────────────
  _applyTemplate(result, templateNames, values, eventDataParts) {
    // Two-pass approach: first handle system fields, then pair Data.Name with Data text
    const dataNames = [];   // { index, nameVal }
    const dataTexts = [];   // { index, textVal }

    for (let i = 0; i < templateNames.length; i++) {
      const n = templateNames[i];

      // Handle literal values embedded in the template body (e.g., Computer name, Data.Name)
      if (n.literal !== undefined) {
        const val = n.literal;
        if (!val) continue;
        if (n.elem === 'Computer' && !result.computer) { result.computer = val; continue; }
        if (n.elem === 'Channel' && !result.channel) { result.channel = val; continue; }
        if (n.elem === 'EventID' && !result.eventId) { result.eventId = val; continue; }
        // Literal Data.Name attributes (e.g., Sysmon hardcoded field names like "RuleName")
        if (n.elem === 'Data' && n.attr === 'Name') {
          dataNames.push({ index: i, nameVal: val });
          continue;
        }
        continue;
      }

      const val = (n.idx >= 0 && n.idx < values.length) ? values[n.idx] : '';

      // System element fields
      if (n.attr === 'Name' && n.elem === 'Provider') { if (val) result.provider = val; continue; }
      if (n.attr === 'SystemTime' && n.elem === 'TimeCreated') continue;
      if (n.attr === 'Guid') continue;

      // Collect Data.Name attributes for pairing
      if (n.attr === 'Name' && n.elem === 'Data') {
        dataNames.push({ index: i, nameVal: val });
        continue;
      }

      // Collect Data text content for pairing — must be before empty-val skip
      // so empty values still maintain alignment with their Data.Name partners
      if (n.elem === 'Data' && !n.attr) {
        dataTexts.push({ index: i, textVal: val });
        continue;
      }

      if (!val) continue;

      if (n.elem === 'EventID' && !n.attr && !result.eventId) { result.eventId = val; continue; }
      if (n.elem === 'Level' && !n.attr) { result.level = this._levelName(val); continue; }
      if (n.elem === 'Channel' && !n.attr) { result.channel = val; continue; }
      if (n.elem === 'Computer' && !n.attr) { result.computer = val; continue; }
      if (n.elem === 'Task' && !n.attr) { result.task = val; continue; }
      if (n.elem === 'Opcode' && !n.attr) { result.opcode = val; continue; }

      // Execution ProcessID/ThreadID
      if (n.attr === 'ProcessID' && n.elem === 'Execution') continue;
      if (n.attr === 'ThreadID' && n.elem === 'Execution') continue;
    }

    // Pair Data.Name attributes with their following Data text values
    const usedTextIndices = new Set();
    const unpairedNames = [];
    for (const dn of dataNames) {
      // Find the next Data text entry that comes after this Name entry
      let paired = false;
      for (const dt of dataTexts) {
        if (dt.index > dn.index && !usedTextIndices.has(dt.index)) {
          const label = dn.nameVal || '';
          eventDataParts.push(label ? label + '=' + dt.textVal : dt.textVal);
          usedTextIndices.add(dt.index);
          paired = true;
          break;
        }
      }
      if (!paired && dn.nameVal) {
        unpairedNames.push(dn.nameVal);
      }
    }
    // Collect any unpaired Data text values
    for (const dt of dataTexts) {
      if (!usedTextIndices.has(dt.index)) {
        eventDataParts.push(dt.textVal);
      }
    }
    // Return unpaired field names (for zipping with nested BinXml values)
    return unpairedNames;
  }

  // ── Extract EventData from nested BinXml (type 0x21) ───────────────────
  _extractNestedEventData(bytes, dv, off, size, stringTable, chunkOff) {
    const parts = [];
    const end = off + size;
    let pos = off;

    // Skip FragmentHeader (0x0F) if present — 4 bytes (token + major + minor + flags)
    if (pos < end && (bytes[pos] & 0x0F) === 0x0F) {
      pos += 4;
    }

    // Expect TemplateInstance (0x0C) — this is the most common case
    if (pos < end && (bytes[pos] & 0x0F) === 0x0C) {
      pos++; // token (0x0C)
      pos++; // unknown/reserved byte
      pos += 4; // template ID hash
      if (pos + 4 > end) return '';
      const templateOff = dv.getUint32(pos, true); pos += 4;

      // Parse the inner template definition
      const absTemplOff = chunkOff + templateOff;
      let templateDataSize = 0;
      let templateNames = [];
      if (absTemplOff + 24 < bytes.length) {
        templateDataSize = dv.getUint32(absTemplOff + 20, true);
        templateNames = this._parseTemplateLite(bytes, dv, absTemplOff + 24, templateDataSize, chunkOff);
      }

      // Skip inline template definition if present
      if (absTemplOff === pos) {
        pos = absTemplOff + 24 + templateDataSize;
      }

      // Read substitution descriptors: numValues(4) + descriptors(4*N)
      if (pos + 4 > end) return '';
      const numValues = dv.getUint32(pos, true); pos += 4;

      const descs = [];
      for (let i = 0; i < numValues && pos + 4 <= end; i++) {
        const vSize = dv.getUint16(pos, true); pos += 2;
        const vType = bytes[pos]; pos += 2; // type(1) + padding(1)
        descs.push({ size: vSize, type: vType });
      }

      // Read substitution values
      const values = [];
      for (let i = 0; i < numValues && pos < end; i++) {
        if (descs[i].size === 0) { values.push(''); continue; }
        const vStart = pos;
        const val = this._readSubstitutionValue(bytes, dv, pos, descs[i].type, descs[i].size);
        values.push(val);
        pos = vStart + descs[i].size;
      }

      // Build name=value pairs from template mappings
      // Pass 1: Find Data.Name attributes and pair with their text content values
      const usedIndices = new Set();
      for (let i = 0; i < templateNames.length; i++) {
        const n = templateNames[i];
        if (n.attr === 'Name' && n.elem === 'Data') {
          // Handle both literal Data.Name (e.g., Sysmon hardcoded field names)
          // and substitution-based Data.Name attributes
          const nameVal = (n.literal !== undefined) ? n.literal :
                          (n.idx >= 0 && n.idx < values.length) ? values[n.idx] : '';
          // Find the next Data text content entry (same element, no attr)
          for (let j = i + 1; j < templateNames.length; j++) {
            const m = templateNames[j];
            if (m.elem === 'Data' && !m.attr && m.literal === undefined) {
              const textVal = (m.idx >= 0 && m.idx < values.length) ? values[m.idx] : '';
              if (nameVal) {
                parts.push(nameVal + '=' + textVal);
              } else if (textVal) {
                parts.push(textVal);
              }
              usedIndices.add(i);
              usedIndices.add(j);
              break;
            }
            // Hit another Data.Name before finding text — previous Data has no text
            if (m.attr === 'Name' && m.elem === 'Data') break;
          }
        }
      }

      // Pass 2: Collect any unpaired Data text values
      for (let i = 0; i < templateNames.length; i++) {
        if (usedIndices.has(i)) continue;
        const n = templateNames[i];
        if (n.literal !== undefined) continue;
        if (n.elem === 'Data' && !n.attr) {
          const val = (n.idx >= 0 && n.idx < values.length) ? values[n.idx] : '';
          if (val) parts.push(val);
          usedIndices.add(i);
        }
      }

      // Pass 3: Collect non-System, non-Data element values (UserData custom elements)
      const systemElems = new Set(['EventID', 'Level', 'Channel', 'Computer', 'Provider', 'Task',
        'Opcode', 'Execution', 'TimeCreated', 'Correlation', 'Security', 'EventRecordID',
        'Keywords', 'Version', 'System', 'EventData', 'UserData', 'Event']);
      for (let i = 0; i < templateNames.length; i++) {
        if (usedIndices.has(i)) continue;
        const n = templateNames[i];
        if (n.literal !== undefined) continue;
        if (systemElems.has(n.elem)) continue;
        if (n.attr === 'Name' || n.attr === 'Guid' || n.attr === 'SystemTime') continue;
        const val = (n.idx >= 0 && n.idx < values.length) ? values[n.idx] : '';
        if (val) {
          const label = n.elem ? (n.attr ? n.elem + '.' + n.attr : n.elem) : '';
          parts.push(label ? label + '=' + val : val);
        }
      }

      if (parts.length > 0) return parts.join(' | ');
    }

    // Fallback: scan for readable UTF-16LE strings in the raw blob
    return this._extractStringsFromBlob(bytes, off, size);
  }

  // ── Fallback: extract readable strings from a binary blob ───────────────
  _extractStringsFromBlob(bytes, off, size) {
    const strings = [];
    const end = Math.min(off + size, bytes.length - 1);
    let i = off;
    while (i + 1 < end) {
      if (bytes[i] >= 0x20 && bytes[i] < 0x7F && bytes[i + 1] === 0) {
        const strStart = i;
        let len = 0;
        while (i + 1 < end && bytes[i] >= 0x20 && bytes[i] < 0x7F && bytes[i + 1] === 0) {
          len++;
          i += 2;
        }
        if (len >= 3) {
          strings.push(this._readUtf16(bytes, strStart, len));
        }
      } else {
        i += 2;
      }
    }
    return strings.length > 0 ? strings.join(' | ') : '';
  }

  // ── Read substitution value by type and known size ──────────────────────
  _readSubstitutionValue(bytes, dv, off, type, size) {
    if (size === 0) return '';
    try {
      switch (type) {
        case 0x00: return ''; // Null
        case 0x01: return this._readUtf16(bytes, off, size / 2).replace(/\0+$/, ''); // UnicodeString
        case 0x02: return String.fromCharCode(...bytes.subarray(off, off + size)).replace(/\0+$/, ''); // AnsiString
        case 0x03: return String((bytes[off] << 24) >> 24); // Int8
        case 0x04: return String(bytes[off]); // UInt8
        case 0x05: return String(dv.getInt16(off, true)); // Int16
        case 0x06: return String(dv.getUint16(off, true)); // UInt16
        case 0x07: return String(dv.getInt32(off, true)); // Int32
        case 0x08: return String(dv.getUint32(off, true)); // UInt32
        case 0x09: { // Int64
          const lo = dv.getUint32(off, true), hi = dv.getInt32(off + 4, true);
          return String(hi * 0x100000000 + lo);
        }
        case 0x0A: { // UInt64
          const lo = dv.getUint32(off, true), hi = dv.getUint32(off + 4, true);
          if (hi === 0) return String(lo);
          return String(hi * 0x100000000 + lo);
        }
        case 0x0B: return String(dv.getFloat32(off, true)); // Float
        case 0x0C: return String(dv.getFloat64(off, true)); // Double
        case 0x0D: return dv.getUint32(off, true) ? 'true' : 'false'; // Boolean
        case 0x0E: { // Binary
          return Array.from(bytes.subarray(off, off + Math.min(size, 64))).map(b => b.toString(16).padStart(2, '0')).join(' ') + (size > 64 ? '…' : '');
        }
        case 0x0F: return this._readGuid(dv, off); // GUID
        case 0x10: { // SizeT
          if (size >= 8) return String(this._getUint64(dv, off, true));
          if (size >= 4) return String(dv.getUint32(off, true));
          return '';
        }
        case 0x11: { // FILETIME
          const d = this._fileTimeToDate(dv, off);
          return d ? d.toISOString() : '0';
        }
        case 0x12: { // SYSTEMTIME
          const yr = dv.getUint16(off, true), mo = dv.getUint16(off + 2, true);
          const dy = dv.getUint16(off + 6, true), hr = dv.getUint16(off + 8, true);
          const mi = dv.getUint16(off + 10, true), sc = dv.getUint16(off + 12, true);
          return `${yr}-${String(mo).padStart(2,'0')}-${String(dy).padStart(2,'0')}T${String(hr).padStart(2,'0')}:${String(mi).padStart(2,'0')}:${String(sc).padStart(2,'0')}Z`;
        }
        case 0x13: return this._parseSid(bytes.subarray(off, off + size)); // SID
        case 0x14: return '0x' + dv.getUint32(off, true).toString(16).padStart(8, '0'); // HexInt32
        case 0x15: { // HexInt64
          const lo = dv.getUint32(off, true), hi = dv.getUint32(off + 4, true);
          return '0x' + hi.toString(16).padStart(8, '0') + lo.toString(16).padStart(8, '0');
        }
        default: return '';
      }
    } catch (_) { return ''; }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  _readUtf16(bytes, off, charCount) {
    const chars = [];
    for (let i = 0; i < charCount && off + i * 2 + 1 < bytes.length; i++) {
      const code = bytes[off + i * 2] | (bytes[off + i * 2 + 1] << 8);
      if (code === 0) break;
      chars.push(code);
    }
    return String.fromCharCode(...chars);
  }

  _fileTimeToDate(dv, off) {
    const lo = dv.getUint32(off, true);
    const hi = dv.getUint32(off + 4, true);
    if (lo === 0 && hi === 0) return null;
    // FILETIME: 100-nanosecond intervals since 1601-01-01
    const ft = hi * 0x100000000 + lo;
    const msFromEpoch = ft / 10000 - 11644473600000;
    const d = new Date(msFromEpoch);
    return isNaN(d.getTime()) ? null : d;
  }

  _getUint64(dv, off) {
    const lo = dv.getUint32(off, true);
    const hi = dv.getUint32(off + 4, true);
    return hi * 0x100000000 + lo;
  }

  _readGuid(dv, off) {
    const d1 = dv.getUint32(off, true).toString(16).padStart(8, '0');
    const d2 = dv.getUint16(off + 4, true).toString(16).padStart(4, '0');
    const d3 = dv.getUint16(off + 6, true).toString(16).padStart(4, '0');
    const d4 = Array.from(new Uint8Array(dv.buffer, dv.byteOffset + off + 8, 2)).map(b => b.toString(16).padStart(2, '0')).join('');
    const d5 = Array.from(new Uint8Array(dv.buffer, dv.byteOffset + off + 10, 6)).map(b => b.toString(16).padStart(2, '0')).join('');
    return `{${d1}-${d2}-${d3}-${d4}-${d5}}`;
  }

  _parseSid(sidBytes) {
    if (sidBytes.length < 8) return Array.from(sidBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const rev = sidBytes[0];
    const subCount = sidBytes[1];
    const auth = (sidBytes[2] << 40) | (sidBytes[3] << 32) | (sidBytes[4] << 24) | (sidBytes[5] << 16) | (sidBytes[6] << 8) | sidBytes[7];
    let s = `S-${rev}-${auth}`;
    const dv = new DataView(sidBytes.buffer, sidBytes.byteOffset, sidBytes.byteLength);
    for (let i = 0; i < subCount && 8 + i * 4 + 3 < sidBytes.length; i++) {
      s += '-' + dv.getUint32(8 + i * 4, true);
    }
    return s;
  }

  _levelName(val) {
    const n = parseInt(val, 10);
    const map = { 0: 'LogAlways', 1: 'Critical', 2: 'Error', 3: 'Warning', 4: 'Information', 5: 'Verbose' };
    return map[n] || val;
  }

  // ── Notable Event IDs for SOC triage ────────────────────────────────────
  _isNotableEventId(eid) {
    const n = parseInt(eid, 10);
    const notable = new Set([
      1102, 4624, 4625, 4648, 4672, 4688, 4720, 4726, 4728, 4732, 4733, 4735,
      7045, 4104, 4103, 4697, 4698, 4699, 4700, 4701, 4702,
      1, 3, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 22, 23, 25
    ]);
    return notable.has(n);
  }

  // ── Level badge HTML ────────────────────────────────────────────────────
  _createLevelBadge(level) {
    const span = document.createElement('span');
    const lv = String(level).toLowerCase();
    span.className = 'evtx-badge evtx-badge-' + (lv || 'default');
    span.textContent = level || '—';
    return span;
  }

  // ── Parse Event Data string into key-value pairs ────────────────────────
  _parseEventDataPairs(eventData) {
    if (!eventData) return [];
    return eventData.split(' | ').map(part => {
      const eqIdx = part.indexOf('=');
      if (eqIdx > 0 && eqIdx < 60) {
        return { key: part.substring(0, eqIdx), val: part.substring(eqIdx + 1) };
      }
      return { key: '', val: part };
    });
  }

  // ── Extract IOCs from parsed EVTX events ────────────────────────────────
  _extractEvtxIOCs(events, f) {
    const seen = new Set();
    const add = (type, val, sev) => {
      val = (val || '').trim();
      if (!val || val.length < 3 || val.length > 500 || seen.has(val.toLowerCase())) return;
      seen.add(val.toLowerCase());
      f.externalRefs.push({ type, url: val, severity: sev });
    };

    // Keys in Sysmon / Security event data that contain process paths
    const processKeys = new Set([
      'Image', 'ParentImage', 'TargetImage', 'SourceImage',
      'ImageLoaded', 'Device', 'TargetFilename', 'SourceFilename',
      'Destination',
    ]);

    // Keys that contain command lines
    const cmdLineKeys = new Set([
      'CommandLine', 'ParentCommandLine',
    ]);

    // Keys that contain IP addresses
    const ipKeys = new Set([
      'SourceIp', 'DestinationIp',
    ]);

    // Keys that contain hostnames
    const hostnameKeys = new Set([
      'DestinationHostname', 'SourceHostname',
    ]);

    // Common system paths to skip (reduce noise)
    const boringPaths = new Set([
      'c:\\windows\\system32\\svchost.exe',
      'c:\\windows\\system32\\services.exe',
      'c:\\windows\\system32\\lsass.exe',
      'c:\\windows\\system32\\wininit.exe',
      'c:\\windows\\system32\\csrss.exe',
      'c:\\windows\\system32\\smss.exe',
      'c:\\windows\\system32\\winlogon.exe',
      'c:\\windows\\explorer.exe',
      'c:\\windows\\system32\\conhost.exe',
      'c:\\windows\\system32\\dwm.exe',
      'c:\\windows\\system32\\taskhostw.exe',
      'c:\\windows\\system32\\sihost.exe',
      'c:\\windows\\system32\\runtimebroker.exe',
      'c:\\windows\\system32\\dllhost.exe',
      'c:\\windows\\system32\\wuauclt.exe',
      'c:\\windows\\system32\\spoolsv.exe',
      'system',
    ]);

    // Hash regex: matches SHA256, SHA1, MD5, IMPHASH patterns from Sysmon Hashes field
    const hashRe = /\b(?:SHA256|SHA1|MD5|IMPHASH|SHA384|SHA512)=([A-Fa-f0-9]{32,128})\b/g;
    // Standalone hex hash (40 = SHA1, 32 = MD5, 64 = SHA256)
    const standaloneHashRe = /\b([A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b/;

    for (const ev of events) {
      if (!ev.eventData) continue;
      const pairs = this._parseEventDataPairs(ev.eventData);

      for (const p of pairs) {
        const key = p.key;
        const val = p.val;
        if (!val) continue;

        // ── Hashes (from Sysmon "Hashes" field: SHA1=xxx,MD5=xxx,...) ──
        if (key === 'Hashes' || key === 'Hash') {
          let m;
          hashRe.lastIndex = 0;
          while ((m = hashRe.exec(val)) !== null) {
            const hashType = m[0].split('=')[0];
            const hashVal = m[1].toUpperCase();
            add(IOC.HASH, `${hashType}:${hashVal}`, 'medium');
          }
          continue;
        }

        // ── Process paths ──
        if (processKeys.has(key)) {
          const lower = val.toLowerCase().replace(/\0+$/, '');
          if (lower && !boringPaths.has(lower) && /^[a-z]:\\/i.test(val)) {
            add(IOC.PROCESS, val, 'medium');
          }
          continue;
        }

        // ── Command lines ──
        if (cmdLineKeys.has(key)) {
          const trimmed = val.replace(/\0+$/, '').trim();
          // Skip very short or boring command lines
          if (trimmed.length > 5 && !/^"?[A-Z]:\\Windows\\System32\\svchost\.exe"?\s*-k\s/i.test(trimmed)) {
            add(IOC.COMMAND_LINE, trimmed, 'medium');
          }
          continue;
        }

        // ── IP addresses ──
        if (ipKeys.has(key)) {
          const ip = val.trim();
          // Skip loopback/unspecified
          if (ip && ip !== '0.0.0.0' && ip !== '127.0.0.1' && ip !== '::1' && ip !== '::' && ip !== '-') {
            add(IOC.IP, ip, 'medium');
          }
          continue;
        }

        // ── Hostnames ──
        if (hostnameKeys.has(key)) {
          const host = val.trim();
          if (host && host !== '-' && host.length > 2) {
            add(IOC.HOSTNAME, host, 'info');
          }
          continue;
        }
      }

      // ── Scan entire eventData for URLs ──
      for (const m of ev.eventData.matchAll(/https?:\/\/[^\s"'<>()\[\]{}\x00-\x1F|]{6,}/g)) {
        add(IOC.URL, m[0].replace(/[.,;:!?)\]>]+$/, ''), 'medium');
      }

      // ── Scan for file paths not caught by key matching ──
      for (const m of ev.eventData.matchAll(/[A-Za-z]:\\(?:[\w\-. ]+\\)+[\w\-. ]{2,}/g)) {
        const lower = m[0].toLowerCase();
        if (!boringPaths.has(lower) && !seen.has(lower)) {
          add(IOC.FILE_PATH, m[0], 'info');
        }
      }

      // ── Scan for UNC paths ──
      for (const m of ev.eventData.matchAll(/\\\\[\w.\-]{2,}(?:\\[\w.\-]{1,})+/g)) {
        add(IOC.UNC_PATH, m[0], 'medium');
      }

      // ── Scan for standalone hashes in unkeyed data ──
      // Only if the event has unstructured data that might contain hashes
      for (const p of pairs) {
        if (p.key) continue; // skip keyed pairs already processed
        let m;
        hashRe.lastIndex = 0;
        while ((m = hashRe.exec(p.val)) !== null) {
          const hashType = m[0].split('=')[0];
          const hashVal = m[1].toUpperCase();
          add(IOC.HASH, `${hashType}:${hashVal}`, 'medium');
        }
      }
    }
  }

  // ── View builder ────────────────────────────────────────────────────────

  _buildView(events, fileName) {
    const wrap = document.createElement('div');
    wrap.className = 'evtx-view csv-view';

    // ── Summary stats bar ──────────────────────────────────────────────
    const stats = document.createElement('div');
    stats.className = 'evtx-stats';

    // Event count + time range
    let summaryText = `${events.length.toLocaleString()} events`;
    if (events.length) {
      const first = events[0].timestamp, last = events[events.length - 1].timestamp;
      if (first && last) summaryText += ` · ${first} → ${last}`;
    }
    const countSpan = document.createElement('span');
    countSpan.className = 'evtx-stat-item';
    countSpan.innerHTML = `<span class="evtx-stat-count">${events.length.toLocaleString()}</span> events`;
    stats.appendChild(countSpan);

    if (events.length) {
      const first = events[0].timestamp, last = events[events.length - 1].timestamp;
      if (first && last) {
        const sep1 = document.createElement('span');
        sep1.className = 'evtx-stat-sep';
        sep1.textContent = '·';
        stats.appendChild(sep1);
        const rangeSpan = document.createElement('span');
        rangeSpan.className = 'evtx-stat-item';
        rangeSpan.textContent = `${first.replace('T', ' ').replace('Z', '')} → ${last.replace('T', ' ').replace('Z', '')}`;
        stats.appendChild(rangeSpan);
      }
    }

    // Level counts
    const levelCounts = {};
    const eidCounts = {};
    for (const ev of events) {
      const lv = ev.level || 'Unknown';
      levelCounts[lv] = (levelCounts[lv] || 0) + 1;
      if (ev.eventId) eidCounts[ev.eventId] = (eidCounts[ev.eventId] || 0) + 1;
    }
    const levelOrder = ['Critical', 'Error', 'Warning', 'Information', 'Verbose', 'LogAlways'];
    for (const lv of levelOrder) {
      if (!levelCounts[lv]) continue;
      const sep = document.createElement('span');
      sep.className = 'evtx-stat-sep';
      sep.textContent = '·';
      stats.appendChild(sep);
      const item = document.createElement('span');
      item.className = 'evtx-stat-item';
      const badge = this._createLevelBadge(lv);
      item.appendChild(badge);
      const ct = document.createElement('span');
      ct.textContent = ` ${levelCounts[lv]}`;
      item.appendChild(ct);
      stats.appendChild(item);
    }
    wrap.appendChild(stats);

    // ── CSV action bar ─────────────────────────────────────────────────
    const bar = this._buildCsvBar(events, fileName);

    // Expand All / Collapse All toggle button
    const expandToggle = document.createElement('button');
    expandToggle.className = 'tb-btn csv-export-btn';
    expandToggle.textContent = '📂 Expand All';
    expandToggle.title = 'Expand all visible event rows';
    let allExpanded = false;
    bar.appendChild(expandToggle);

    wrap.appendChild(bar);

    // ── Filter bar ─────────────────────────────────────────────────────
    const filterBar = document.createElement('div');
    filterBar.className = 'evtx-filter-bar';

    const searchLabel = document.createElement('span');
    searchLabel.className = 'evtx-filter-label';
    searchLabel.textContent = '🔍';
    filterBar.appendChild(searchLabel);

    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.placeholder = 'Search all fields…';
    filterBar.appendChild(searchInput);

    const eidLabel = document.createElement('span');
    eidLabel.className = 'evtx-filter-label';
    eidLabel.textContent = 'Event ID';
    filterBar.appendChild(eidLabel);

    const eidInput = document.createElement('input');
    eidInput.type = 'text';
    eidInput.className = 'evtx-eid-input';
    eidInput.placeholder = 'e.g. 4624';
    filterBar.appendChild(eidInput);

    const levelLabel = document.createElement('span');
    levelLabel.className = 'evtx-filter-label';
    levelLabel.textContent = 'Level';
    filterBar.appendChild(levelLabel);

    const levelSelect = document.createElement('select');
    levelSelect.innerHTML = '<option value="">All Levels</option>';
    for (const lv of levelOrder) {
      if (!levelCounts[lv]) continue;
      levelSelect.innerHTML += `<option value="${lv}">${lv} (${levelCounts[lv]})</option>`;
    }
    filterBar.appendChild(levelSelect);

    const filterCount = document.createElement('span');
    filterCount.className = 'evtx-filter-count';
    filterCount.textContent = `Showing ${events.length.toLocaleString()} of ${events.length.toLocaleString()}`;
    filterBar.appendChild(filterCount);

    wrap.appendChild(filterBar);

    // ── Table ──────────────────────────────────────────────────────────
    const scr = document.createElement('div');
    scr.className = 'csv-scroll';
    scr.style.cssText = 'overflow:auto;max-height:calc(100vh - 260px)';

    const tbl = document.createElement('table');
    tbl.className = 'xlsx-table csv-table evtx-table';

    // Header
    const thead = document.createElement('thead');
    const htr = document.createElement('tr');
    const cols = [
      { label: '#', cls: 'evtx-col-row' },
      { label: 'Timestamp', cls: 'evtx-col-ts' },
      { label: 'Event ID', cls: 'evtx-col-eid' },
      { label: 'Level', cls: 'evtx-col-level' },
      { label: 'Provider', cls: 'evtx-col-provider' },
      { label: 'Channel', cls: 'evtx-col-channel' },
      { label: 'Computer', cls: 'evtx-col-computer' },
      { label: 'Event Data', cls: 'evtx-col-data' },
    ];
    for (const c of cols) {
      const th = document.createElement('th');
      th.className = 'xlsx-col-header csv-header ' + c.cls;
      th.textContent = c.label;
      htr.appendChild(th);
    }
    thead.appendChild(htr);
    tbl.appendChild(thead);

    // Body
    const tbody = document.createElement('tbody');
    const limit = Math.min(events.length, 20000);
    const rows = []; // Track { tr, detailTr, ev, visible } for filtering

    for (let i = 0; i < limit; i++) {
      const ev = events[i];
      const tr = document.createElement('tr');
      tr.dataset.idx = i;

      // # column with expand icon
      const tdRow = document.createElement('td');
      tdRow.className = 'xlsx-row-header';
      tdRow.innerHTML = `<span class="evtx-expand-icon">▶</span> ${i + 1}`;
      tr.appendChild(tdRow);

      // Timestamp (formatted shorter)
      const tdTs = document.createElement('td');
      tdTs.className = 'xlsx-cell';
      tdTs.textContent = ev.timestamp ? ev.timestamp.replace('T', ' ').replace('Z', '') : '';
      tr.appendChild(tdTs);

      // Event ID with notable indicator
      const tdEid = document.createElement('td');
      tdEid.className = 'xlsx-cell';
      if (this._isNotableEventId(ev.eventId)) {
        tdEid.className += ' evtx-eid-notable';
      }
      tdEid.textContent = ev.eventId;
      tr.appendChild(tdEid);

      // Level badge
      const tdLevel = document.createElement('td');
      tdLevel.className = 'xlsx-cell';
      tdLevel.appendChild(this._createLevelBadge(ev.level));
      tr.appendChild(tdLevel);

      // Provider
      const tdProv = document.createElement('td');
      tdProv.className = 'xlsx-cell';
      tdProv.textContent = ev.provider;
      tdProv.title = ev.provider;
      tr.appendChild(tdProv);

      // Channel
      const tdChan = document.createElement('td');
      tdChan.className = 'xlsx-cell';
      tdChan.textContent = ev.channel;
      tdChan.title = ev.channel;
      tr.appendChild(tdChan);

      // Computer
      const tdComp = document.createElement('td');
      tdComp.className = 'xlsx-cell';
      tdComp.textContent = ev.computer;
      tr.appendChild(tdComp);

      // Event Data preview
      const tdData = document.createElement('td');
      tdData.className = 'xlsx-cell evtx-data-cell';
      const preview = ev.eventData ? ev.eventData.substring(0, 120) : '';
      tdData.textContent = preview + (ev.eventData && ev.eventData.length > 120 ? '…' : '');
      tdData.title = 'Click to expand';
      tr.appendChild(tdData);

      tbody.appendChild(tr);

      // Detail row (hidden by default)
      const detailTr = document.createElement('tr');
      detailTr.className = 'evtx-detail-row';
      detailTr.style.display = 'none';
      const detailTd = document.createElement('td');
      detailTd.colSpan = cols.length;
      detailTr.appendChild(detailTd);
      tbody.appendChild(detailTr);

      rows.push({ tr, detailTr, detailTd, ev, visible: true });

      // Click to expand/collapse
      tr.addEventListener('click', () => {
        const isOpen = detailTr.style.display !== 'none';
        if (isOpen) {
          detailTr.style.display = 'none';
          tr.classList.remove('evtx-row-selected');
        } else {
          // Build detail pane on first open
          if (!detailTd.hasChildNodes()) {
            this._buildDetailPane(detailTd, ev);
          }
          detailTr.style.display = '';
          tr.classList.add('evtx-row-selected');
        }
      });
    }
    tbl.appendChild(tbody);
    scr.appendChild(tbl);
    wrap.appendChild(scr);

    if (events.length > limit) {
      const note = document.createElement('div');
      note.className = 'csv-info';
      note.textContent = `⚠ Showing first ${limit.toLocaleString()} of ${events.length.toLocaleString()} events`;
      wrap.appendChild(note);
    }

    // ── Filter logic ───────────────────────────────────────────────────
    const applyFilters = () => {
      const searchTerm = searchInput.value.toLowerCase().trim();
      const eidFilter = eidInput.value.trim();
      const levelFilter = levelSelect.value;
      let shown = 0;

      for (const r of rows) {
        let match = true;
        if (levelFilter && r.ev.level !== levelFilter) match = false;
        if (eidFilter && String(r.ev.eventId) !== eidFilter) match = false;
        if (searchTerm && match) {
          const haystack = [r.ev.eventId, r.ev.level, r.ev.provider, r.ev.channel, r.ev.computer, r.ev.timestamp, r.ev.eventData].join(' ').toLowerCase();
          if (!haystack.includes(searchTerm)) match = false;
        }
        r.tr.style.display = match ? '' : 'none';
        // Respect current expand/collapse state
        if (allExpanded && match) {
          if (!r.detailTd.hasChildNodes()) this._buildDetailPane(r.detailTd, r.ev);
          r.detailTr.style.display = '';
          r.tr.classList.add('evtx-row-selected');
        } else {
          r.detailTr.style.display = 'none';
          r.tr.classList.remove('evtx-row-selected');
        }
        r.visible = match;
        if (match) shown++;
      }
      filterCount.textContent = `Showing ${shown.toLocaleString()} of ${events.length.toLocaleString()}`;
    };

    // Helper: expand all currently visible rows
    const expandAllVisible = () => {
      allExpanded = true;
      for (const r of rows) {
        if (!r.visible) continue;
        if (!r.detailTd.hasChildNodes()) this._buildDetailPane(r.detailTd, r.ev);
        r.detailTr.style.display = '';
        r.tr.classList.add('evtx-row-selected');
      }
      expandToggle.textContent = '📁 Collapse All';
      expandToggle.title = 'Collapse all expanded event rows';
    };

    let filterTimeout;
    const debouncedFilter = () => {
      clearTimeout(filterTimeout);
      filterTimeout = setTimeout(applyFilters, 150);
    };
    searchInput.addEventListener('input', debouncedFilter);
    eidInput.addEventListener('input', debouncedFilter);
    levelSelect.addEventListener('change', applyFilters);

    // ── Expose filter controls for sidebar navigation ─────────────────
    wrap._evtxFilters = {
      searchInput,
      eidInput,
      levelSelect,
      applyFilters: () => applyFilters(),
      expandAll: () => expandAllVisible(),
      scrollContainer: scr,
    };

    // ── Expand All / Collapse All toggle handler ───────────────────────
    expandToggle.addEventListener('click', () => {
      allExpanded = !allExpanded;
      for (const r of rows) {
        if (!r.visible) continue;
        if (allExpanded) {
          // Build detail pane lazily on first open
          if (!r.detailTd.hasChildNodes()) {
            this._buildDetailPane(r.detailTd, r.ev);
          }
          r.detailTr.style.display = '';
          r.tr.classList.add('evtx-row-selected');
        } else {
          r.detailTr.style.display = 'none';
          r.tr.classList.remove('evtx-row-selected');
        }
      }
      expandToggle.textContent = allExpanded ? '📁 Collapse All' : '📂 Expand All';
      expandToggle.title = allExpanded ? 'Collapse all expanded event rows' : 'Expand all visible event rows';
    });

    return wrap;
  }

  // ── Build detail pane for expanded row ──────────────────────────────────
  _buildDetailPane(container, ev) {
    const pane = document.createElement('div');
    pane.className = 'evtx-detail-pane';

    // System fields summary
    const sysInfo = document.createElement('div');
    sysInfo.className = 'evtx-detail-sysinfo';
    sysInfo.textContent = `Record ${ev.recordId} · ${ev.timestamp} · Event ${ev.eventId} · ${ev.provider}`;
    pane.appendChild(sysInfo);

    // Event Data as key-value grid
    if (ev.eventData) {
      const heading = document.createElement('h4');
      heading.textContent = 'Event Data';
      pane.appendChild(heading);

      const pairs = this._parseEventDataPairs(ev.eventData);
      if (pairs.length > 0 && pairs.some(p => p.key)) {
        // Structured key-value display
        const grid = document.createElement('div');
        grid.className = 'evtx-detail-grid';
        for (const p of pairs) {
          if (p.key) {
            const keyEl = document.createElement('div');
            keyEl.className = 'evtx-detail-key';
            keyEl.textContent = p.key;
            grid.appendChild(keyEl);
            const valEl = document.createElement('div');
            valEl.className = 'evtx-detail-val';
            valEl.textContent = p.val;
            grid.appendChild(valEl);
          } else {
            const keyEl = document.createElement('div');
            keyEl.className = 'evtx-detail-key';
            keyEl.textContent = '·';
            grid.appendChild(keyEl);
            const valEl = document.createElement('div');
            valEl.className = 'evtx-detail-val';
            valEl.textContent = p.val;
            grid.appendChild(valEl);
          }
        }
        pane.appendChild(grid);
      } else {
        // Plain text display
        const pre = document.createElement('div');
        pre.className = 'evtx-detail-plaintext';
        pre.textContent = ev.eventData;
        pane.appendChild(pre);
      }
    } else {
      const empty = document.createElement('div');
      empty.className = 'evtx-detail-empty';
      empty.textContent = 'No event data';
      pane.appendChild(empty);
    }

    container.appendChild(pane);
  }

  // ── CSV export helpers ──────────────────────────────────────────────────

  _buildCsvBar(events, fileName) {
    const bar = document.createElement('div');
    bar.className = 'csv-export-bar';

    const copyBtn = document.createElement('button');
    copyBtn.className = 'tb-btn csv-export-btn';
    copyBtn.textContent = '📋 Copy as CSV';
    copyBtn.title = 'Copy all events as CSV to clipboard';
    copyBtn.addEventListener('click', () => {
      const csv = this._toCsv(events);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(csv).then(() => this._showToast(bar, 'Copied!'));
      } else {
        const ta = document.createElement('textarea'); ta.value = csv; ta.style.cssText = 'position:fixed;opacity:0';
        document.body.appendChild(ta); ta.select(); document.execCommand('copy');
        document.body.removeChild(ta); this._showToast(bar, 'Copied!');
      }
    });
    bar.appendChild(copyBtn);

    const dlBtn = document.createElement('button');
    dlBtn.className = 'tb-btn csv-export-btn';
    dlBtn.textContent = '💾 Download CSV';
    dlBtn.title = 'Download all events as a CSV file';
    dlBtn.addEventListener('click', () => {
      const csv = this._toCsv(events);
      const base = (fileName || 'events').replace(/\.[^.]+$/, '');
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = base + '.csv'; a.click();
      URL.revokeObjectURL(url);
      this._showToast(bar, 'Downloaded!');
    });
    bar.appendChild(dlBtn);

    return bar;
  }

  _toCsv(events) {
    const headers = ['Record ID', 'Timestamp', 'Event ID', 'Level', 'Provider', 'Channel', 'Computer', 'Event Data'];
    const esc = v => {
      const s = String(v == null ? '' : v);
      return s.includes(',') || s.includes('"') || s.includes('\n') || s.includes('\r')
        ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    const lines = [headers.join(',')];
    for (const ev of events) {
      lines.push([ev.recordId, ev.timestamp, ev.eventId, ev.level, ev.provider, ev.channel, ev.computer, ev.eventData].map(esc).join(','));
    }
    return lines.join('\r\n');
  }

  _showToast(parent, msg) {
    const t = document.getElementById('toast');
    if (t) { t.textContent = msg; t.className = ''; setTimeout(() => t.classList.add('hidden'), 2000); }
  }
}
