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

  // Optional `prebuiltEvents` lets a caller (e.g. the Timeline view, which
  // has already parsed the file to build its grid) skip the second `_parse`
  // pass on a multi-hundred-MB EVTX. When omitted the behaviour is
  // identical to the single-arg form. The array is consumed read-only.
  //
  // Implementation lives in `src/evtx-detector.js` (extracted to keep the
  // Timeline parse-only worker bundle small — the worker never references
  // detection code). This method is a one-line forward; both the Timeline
  // route and the standard analyser pipeline in `app-load.js` go through
  // it unchanged.
  analyzeForSecurity(buffer, fileName, prebuiltEvents) {
    return EvtxDetector.analyzeForSecurity(buffer, fileName, prebuiltEvents);
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
    const maxEvents = RENDER_LIMITS.MAX_EVTX_EVENTS; // Safety limit

    for (let ci = 0; ci < chunkCount && events.length < maxEvents; ci++) {
      throwIfAborted();
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

        // Use .slice() instead of .subarray() so each event owns an
        // independent copy.  With .subarray() every event's rawRecord
        // shares the original multi-hundred-MB ArrayBuffer, preventing GC
        // even after the main buffer reference is released.  The copies
        // are small (typically < 10 KB each) and collectively smaller
        // than the file (chunks + headers aren't duplicated).
        let ev = { recordId, timestamp: timestamp ? timestamp.toISOString() : '', eventId: '', level: '', channel: '', provider: '', computer: '', eventData: '', rawRecord: bytes.slice(recOff, recOff + recSize) };
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

  // ── Async EVTX parse with cooperative yielding ──────────────────────────
  //
  // Identical logic to `_parse()` but yields to the event loop every
  // `YIELD_INTERVAL` chunks (≈ 6.4 MB of data).  This prevents the
  // browser from showing "page unresponsive" on large EVTX files where
  // the synchronous parse would block the main thread for 10–30+ seconds.
  //
  // Accepts an optional `onProgress(parsedEvents, totalChunks)` callback
  // so callers can wire up a progress indicator.
  async _parseAsync(bytes, onProgress) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const magic = String.fromCharCode(...bytes.subarray(0, 8));
    if (magic !== 'ElfFile\0') throw new Error('Not a valid EVTX file (bad magic)');

    const chunkCount = dv.getUint16(0x28, true);
    const headerSize = 4096;
    const chunkSize = 65536;
    const YIELD_INTERVAL = 100; // yield every 100 chunks (~6.4 MB)

    const events = [];
    const maxEvents = RENDER_LIMITS.MAX_EVTX_EVENTS;

    const yieldTick = () => new Promise(resolve => {
      if (typeof MessageChannel !== 'undefined') {
        const ch = new MessageChannel();
        ch.port1.onmessage = () => { ch.port1.close(); resolve(); };
        ch.port2.postMessage(null);
      } else {
        setTimeout(resolve, 0);
      }
    });

    for (let ci = 0; ci < chunkCount && events.length < maxEvents; ci++) {
      throwIfAborted();
      const chunkOff = headerSize + ci * chunkSize;
      if (chunkOff + chunkSize > bytes.length) break;

      const cMagic = String.fromCharCode(...bytes.subarray(chunkOff, chunkOff + 8));
      if (cMagic !== 'ElfChnk\0') continue;

      const stringTable = this._parseChunkStringTable(bytes, dv, chunkOff);

      let recOff = chunkOff + 0x200;
      const chunkEnd = chunkOff + chunkSize;

      while (recOff + 24 < chunkEnd && events.length < maxEvents) {
        const recMagic = dv.getUint32(recOff, true);
        if (recMagic !== 0x00002a2a) break;

        const recSize = dv.getUint32(recOff + 4, true);
        if (recSize < 24 || recOff + recSize > chunkEnd) break;

        const recordId = this._getUint64(dv, recOff + 8, true);
        const timestamp = this._fileTimeToDate(dv, recOff + 16);

        const binXmlOff = recOff + 24;
        const binXmlLen = recSize - 24 - 4;

        let ev = { recordId, timestamp: timestamp ? timestamp.toISOString() : '', eventId: '', level: '', channel: '', provider: '', computer: '', eventData: '', rawRecord: bytes.slice(recOff, recOff + recSize) };
        try {
          const xml = this._decodeBinXml(bytes, dv, binXmlOff, binXmlLen, stringTable, chunkOff);
          Object.assign(ev, xml);
        } catch (_) { /* best-effort */ }

        events.push(ev);
        recOff += recSize;
      }

      // Yield to the event loop periodically so the UI stays responsive.
      if ((ci + 1) % YIELD_INTERVAL === 0 && ci + 1 < chunkCount) {
        if (onProgress) onProgress(events.length, chunkCount);
        await yieldTick();
      }
    }
    if (onProgress) onProgress(events.length, chunkCount);
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
  //
  // INVARIANT: `_decodeBinXml` is a synchronous per-record decoder. It
  // does NOT yield to the event loop. Callers that walk many records must
  // batch yields themselves — see `_parseAsync` (yields every 100 chunks
  // ≈ 6.4 MB) and the timeline worker (`src/workers/timeline.worker.js`,
  // off the main thread). The legacy synchronous `_parse()` entry point
  // is retained only for `EvtxDetector` reentrant analysis paths where
  // the buffer is already known to be small (see `src/evtx-detector.js`).
  // Do NOT call `_parse` (and therefore `_decodeBinXml`) directly from
  // the main thread on user-supplied EVTX bytes — go through `_parseAsync`
  // or the timeline worker.
  _decodeBinXml(bytes, dv, off, maxLen, stringTable, chunkOff) {
    const result = { eventId: '', level: '', channel: '', provider: '', computer: '', opcode: '', task: '', eventData: '' };
    const end = off + maxLen;
    const eventDataParts = [];

    // State tracking for element path
    const elemStack = [];
    let inSystem = false, inEventData = false, inUserData = false;
    let lastDataName = '';

    const ctx = { pos: off };

    // Read a BinXml string: uint16 length + utf16le chars + NUL (2 bytes)
    const readBinXmlString = () => {
      if (ctx.pos + 2 > end) return '';
      const len = dv.getUint16(ctx.pos, true); ctx.pos += 2;
      if (len === 0) return '';
      const str = this._readUtf16(bytes, ctx.pos, len);
      ctx.pos += len * 2 + 2; // +2 for NUL terminator
      return str;
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
          return `${yr}-${String(mo).padStart(2, '0')}-${String(dy).padStart(2, '0')}T${String(hr).padStart(2, '0')}:${String(mi).padStart(2, '0')}:${String(sc).padStart(2, '0')}.${String(ms).padStart(3, '0')}Z`;
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
          const _dataSize = dv.getUint32(ctx.pos, true); ctx.pos += 4;
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
          readName();
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
  // Per-blob scan budget (256 KB) — record blobs are ≤64 KB by design, so
  // this is generous, but still bounds the worst case if a corrupt record
  // slips a giant declared `size` past the chunk parser.
  _extractStringsFromBlob(bytes, off, size) {
    const strings = [];
    const SCAN_CAP = 256 * 1024;
    const cappedSize = Math.min(size, SCAN_CAP);
    const end = Math.min(off + cappedSize, bytes.length - 1);
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
          if (strings.length >= 256) break;
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
          return `${yr}-${String(mo).padStart(2, '0')}-${String(dy).padStart(2, '0')}T${String(hr).padStart(2, '0')}:${String(mi).padStart(2, '0')}:${String(sc).padStart(2, '0')}Z`;
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

  _getUint64(dv, off, _le) {
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
    const auth = sidBytes[2] * 0x10000000000 + sidBytes[3] * 0x100000000 + (sidBytes[4] << 24 | sidBytes[5] << 16 | sidBytes[6] << 8 | sidBytes[7]) >>> 0;
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

  // ── Human-readable Event ID descriptions for SOC analysts ───────────────
  _getEventDescription(eventId, provider) {
    const eid = parseInt(eventId, 10);
    if (isNaN(eid)) return '';

    const provLower = (provider || '').toLowerCase();
    const isSysmon = /sysmon/i.test(provLower);

    // Sysmon events (provider-specific — low EIDs overlap with other providers)
    if (isSysmon) {
      const sysmonDescs = EvtxRenderer._SYSMON_DESCS;
      if (sysmonDescs[eid]) return sysmonDescs[eid];
    }

    // General / Security / System event IDs
    const descriptions = EvtxRenderer._EVENT_DESCS;

    if (descriptions[eid]) return descriptions[eid];
    return '';
  }

  // ── Notable Event IDs for SOC triage ────────────────────────────────────
  _isNotableEventId(eid) {
    const n = parseInt(eid, 10);
    return EvtxRenderer._NOTABLE_EIDS.has(n);
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

  // NOTE: `_extractEvtxIOCs` and the `_SUSPICIOUS_PATTERNS` table that
  // formerly lived here have moved to `src/evtx-detector.js`. They are
  // analysis-only and the Timeline parse-only worker bundle deliberately
  // does not include them. View / drawer / detail-pane code in this file
  // continues to use `_parseEventDataPairs` (kept above) for rendering.

  // ── View builder ─────────────────────────────────────────────────────────
  //
  // EVTX shares the virtual-scroll core with CSV / XLSX / SQLite / JSON via
  // `GridViewer` (see src/renderers/grid-viewer.js). Everything below is
  // "how EVTX wants its toolbar, cells, and drawer body to look" — the
  // scroll, filter, highlight, drawer, and IOC/YARA plumbing is inherited.
  //
  // The existing sidebar click-to-focus engine in
  // `src/app/app-sidebar-focus.js` reads `wrap._evtxFilters = { searchInput,
  // eidInput, levelSelect, applyFilters, scrollContainer, scrollToRow,
  // state, expandAll, collapseAll, forceRender }`. We rebuild that surface
  // on top of the GridViewer below so that integration keeps working
  // verbatim. `state.filteredIndices` and `state.expandedRows` are the two
  // fields the sidebar reads; both are honoured.

  _buildView(events, fileName) {
    const MAX_EVENTS = RENDER_LIMITS.MAX_EVTX_EVENTS; // Maximum events to process

    // Limit events
    const totalEvents = events.length;
    const limitedEvents = events.slice(0, MAX_EVENTS);

    // ── Summary stats bar ─────────────────────────────────────────────
    const stats = document.createElement('div');
    stats.className = 'evtx-stats';

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
    for (const ev of events) {
      const lv = ev.level || 'Unknown';
      levelCounts[lv] = (levelCounts[lv] || 0) + 1;
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

    // ── CSV action bar ─────────────────────────────────────────────────
    const csvBar = this._buildCsvBar(events, fileName);

    // ── Filter bar (custom — three inputs, not just a single search box) ─
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
    const defaultOpt = document.createElement('option');
    defaultOpt.value = '';
    defaultOpt.textContent = 'All Levels';
    levelSelect.appendChild(defaultOpt);
    for (const lv of levelOrder) {
      if (!levelCounts[lv]) continue;
      const opt = document.createElement('option');
      opt.value = lv;
      opt.textContent = lv + ' (' + levelCounts[lv] + ')';
      levelSelect.appendChild(opt);
    }
    filterBar.appendChild(levelSelect);

    const clearBtn = document.createElement('button');
    clearBtn.className = 'tb-btn csv-export-btn evtx-clear-btn';
    clearBtn.textContent = '🗑 Clear';
    clearBtn.title = 'Clear all filters';
    filterBar.appendChild(clearBtn);

    const filterCount = document.createElement('span');
    filterCount.className = 'evtx-filter-count';
    filterCount.textContent = `Showing ${limitedEvents.length.toLocaleString()} of ${limitedEvents.length.toLocaleString()}`;
    filterBar.appendChild(filterCount);

    // ── Pre-compute search text for fast filtering ─────────────────────
    const eventSearchText = limitedEvents.map(ev =>
      [ev.eventId, ev.level, ev.provider, ev.channel, ev.computer, ev.timestamp, ev.eventData]
        .join(' ').toLowerCase()
    );

    // ── Build the GridViewer — inherits virtual scroll, drawer, IOC/YARA
    //    highlighting, filter → same primitive as CSV/XLSX/SQLite. ───────
    //
    // Phase 7: stream rows directly into a `RowStoreBuilder` so the
    // intermediate `string[][]` matrix never coexists in heap with the
    // packed RowStore. For a 50 K-event EVTX (≈8 MB of cell payload)
    // this saves ~25 MB of peak (the per-string + per-row JS overhead
    // of a parallel `string[][]`).
    const columns = [...EVTX_COLUMN_ORDER];
    const builder = new RowStoreBuilder(columns);
    for (let i = 0; i < limitedEvents.length; i++) {
      const ev = limitedEvents[i];
      builder.addRow([
        ev.timestamp ? ev.timestamp.replace('T', ' ').replace('Z', '') : '',
        ev.eventId || '',
        ev.level || '',
        ev.provider || '',
        ev.channel || '',
        ev.computer || '',
        ev.eventData || ''
      ]);
    }
    const store = builder.finalize();

    const self = this;
    const truncNote = totalEvents > MAX_EVENTS
      ? `⚠ Showing first ${MAX_EVENTS.toLocaleString()} of ${totalEvents.toLocaleString()} events`
      : '';

    // Timestamp lives in column 0 (see the `columns` array above). Passing
    // `timeColumn: 0` opts this grid into the timeline strip and skips the
    // auto-sniff heuristic. `onFilterRecompute` tells the grid to re-run
    // EVTX's external filter (search / EID / Level) whenever the user moves
    // the timeline window — see `applyFilters` below, which intersects
    // `viewer._timeWindow` via `viewer._dataIdxInTimeWindow()`.
    const viewer = new GridViewer({
      columns,
      // Explicit column-kind hints so the width algorithm knows which
      // columns are fixed-shape (tight-fit, no viewport growth) and
      // which should absorb all leftover slack. Order mirrors `columns`
      // above: Timestamp · Event ID · Level · Provider · Channel ·
      // Computer · Event Data.  'blob' on the last cell is what lets
      // Event Data stretch to fill the right-hand side of the viewport
      // on a typical SOC analyst layout instead of being pinned at the
      // old 480 px fill-cap while every other column over-inflates.
      columnKinds: ['timestamp', 'id', 'enum', 'short', 'short', 'short', 'blob'],
      store,
      rowSearchText: eventSearchText,
      // EVTX's filter bar is hidden in favour of the EID/Level/search
      // chip toolbar (`hideFilterBar: true`), but `applyFilters` still
      // runs the cached `rowSearchText` substring match — preserve it.
      searchTextCache: true,
      rawText: '',
      className: 'evtx-view csv-view',
      infoText: '',   // our stats bar replaces it
      truncationNote: truncNote,
      hideFilterBar: true,
      extraToolbarEls: [stats, csvBar, filterBar],
      timeColumn: 0,
      // Stack the histogram by Event ID (column 1) on load — matches the
      // analyst mental model of "how many 4624/4688/4672s fired per time
      // slice?". User can switch to Level / Provider / any other column
      // via the column-header "Stack timeline by this column" item.
      timelineStackColumn: 1,
      onFilterRecompute: () => applyFilters(),

      // Mark notable Event IDs with a coloured dot (EVTX-specific styling).
      cellClass: (dataIdx, colIdx /* , rawCell */) => {
        if (colIdx === 1 /* Event ID */ && self._isNotableEventId(limitedEvents[dataIdx].eventId)) {
          return 'evtx-eid-notable';
        }
        return null;
      },
      rowTitle: (dataIdx) => {
        const ev = limitedEvents[dataIdx];
        return `Event ${ev.eventId || '—'} · Record ${ev.recordId || '—'}`;
      },
      detailBuilder: (dataIdx /* , row, cols */) => {
        const container = document.createElement('div');
        self._buildDetailPane(container, limitedEvents[dataIdx]);
        // `_buildDetailPane` appends a `.evtx-detail-pane` into the
        // container; return the container itself so GridViewer can wrap /
        // IOC-decorate it.
        return container;
      }
    });

    const wrap = viewer.root();
    // GridViewer sets its own `grid-main` scroll container; the sidebar
    // reads `wrap._evtxFilters.scrollContainer` for scroll-into-view calls.
    const scr = viewer._scr;

    // ── Wire the three EVTX-specific filter inputs onto the shared
    //    GridViewer filtered-index store. Sidebar + `_evtxFilters`
    //    back-compat surface both drive off `viewer.state.filteredIndices`.
    // EVTX owns the filter pipeline, so the timeline window must be
    // intersected here — GridViewer's own `_applyFilter()` is bypassed
    // when `onFilterRecompute` is supplied. When neither the inputs nor
    // the timeline window are active, keep `filteredIndices = null` so
    // the grid's "no filter" fast path can skip the per-row check.
    const applyFilters = () => {
      const s = searchInput.value.toLowerCase().trim();
      const e = eidInput.value.trim();
      const l = levelSelect.value;
      const tw = viewer._timeWindow;
      if (!s && !e && !l && !tw) {
        viewer.state.filteredIndices = null;
      } else {
        const out = [];
        for (let i = 0; i < limitedEvents.length; i++) {
          const ev = limitedEvents[i];
          if (l && ev.level !== l) continue;
          if (e && String(ev.eventId) !== e) continue;
          if (s && !eventSearchText[i].includes(s)) continue;
          if (tw && !viewer._dataIdxInTimeWindow(i)) continue;
          out.push(i);
        }
        viewer.state.filteredIndices = out;
      }
      scr.scrollTop = 0;
      viewer._forceFullRender();
      // EVTX bypasses GridViewer's `_applyFilter()` (we supply
      // `onFilterRecompute`), so the bucket-refresh hook there never fires.
      // Call it directly so histogram counts track the filtered set —
      // including the "clear all" path that sets `filteredIndices = null`.
      viewer._refreshTimelineBuckets();
      const shown = viewer.state.filteredIndices
        ? viewer.state.filteredIndices.length
        : limitedEvents.length;
      const twSuffix = viewer._timeWindow ? ' · timeline window' : '';
      filterCount.textContent =
        `Showing ${shown.toLocaleString()} of ${limitedEvents.length.toLocaleString()}${twSuffix}`;
    };


    let filterTimeout = null;
    const debouncedFilter = () => {
      clearTimeout(filterTimeout);
      filterTimeout = setTimeout(applyFilters, 150);
    };
    searchInput.addEventListener('input', debouncedFilter);
    eidInput.addEventListener('input', debouncedFilter);
    levelSelect.addEventListener('change', applyFilters);
    clearBtn.addEventListener('click', () => {
      searchInput.value = '';
      eidInput.value = '';
      levelSelect.value = '';
      applyFilters();
    });

    // ═══════════════════════════════════════════════════════════════════════
    // EXPOSE API FOR EXTERNAL ACCESS (IOC navigation from sidebar)
    // `src/app/app-sidebar-focus.js` reads `wrap._evtxFilters`.
    // ═══════════════════════════════════════════════════════════════════════
    wrap._evtxFilters = {
      searchInput,
      eidInput,
      levelSelect,
      applyFilters,
      scrollContainer: scr,
      scrollToRow: (dataIdx, flash = true) => viewer._scrollToRow(+dataIdx, flash),
      state: viewer.state,
      getVisibleRowCount: () => viewer._visibleCount(),
      getDataIndex: (v) => viewer._dataIdxOf(v),
      getVirtualIndex: (d) => viewer._virtualIdxOf(d),
      // Drawer-based detail: "expand all" in the old inline-expansion model
      // mapped onto "open the drawer on the first filtered row" so the
      // sidebar's IOC highlighter has a `.evtx-detail-pane` to walk.
      expandAll: () => {
        if (viewer._visibleCount() === 0) return;
        const firstData = viewer._dataIdxOf(0);
        viewer._openDrawer(+firstData);
      },
      collapseAll: () => {
        if (viewer.state.drawer.open) viewer._closeDrawer();
      },
      forceRender: () => viewer._forceFullRender(),
      // IOC / YARA bridges re-use the GridViewer highlight state machine.
      scrollToRowWithIocHighlight: (dataIdx, term, clearMs = 5000, onExpire = null) => {
        viewer._setHighlight({ mode: 'ioc', dataIdx: +dataIdx, term, clearMs, onExpire });
        return viewer._scrollToRow(+dataIdx, false);
      },
      clearIocHighlight: () => viewer._clearHighlight(false)
    };

    return wrap;
  }

  // ── Build detail pane for expanded row ──────────────────────────────────
  _buildDetailPane(container, ev) {
    const pane = document.createElement('div');
    pane.className = 'evtx-detail-pane';

    // ── Event ID description (human-readable for SOC analysts) ──────
    const desc = this._getEventDescription(ev.eventId, ev.provider);
    if (desc) {
      const descEl = document.createElement('div');
      descEl.className = 'evtx-detail-desc';
      const descIcon = document.createElement('span');
      descIcon.className = 'evtx-detail-desc-icon';
      descIcon.textContent = '📋';
      descEl.appendChild(descIcon);
      const descText = document.createElement('span');
      descText.textContent = desc;
      descEl.appendChild(descText);
      pane.appendChild(descEl);
    }

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

    // ── Raw record data (collapsible, human-readable) ─────────────────
    if (ev.rawRecord && ev.rawRecord.length > 0) {
      const rawDetails = document.createElement('details');
      rawDetails.className = 'evtx-raw-details';

      const rawSummary = document.createElement('summary');
      rawSummary.textContent = '📦 Raw Record (' + ev.rawRecord.length + ' bytes)';
      rawDetails.appendChild(rawSummary);

      const rawContent = document.createElement('div');
      rawContent.className = 'evtx-raw-content';

      // Copy button
      const copyBtn = document.createElement('button');
      copyBtn.className = 'tb-btn evtx-raw-copy-btn';
      copyBtn.textContent = '📋 Copy Text';
      copyBtn.title = 'Copy Raw Record to clipboard';
      rawContent.appendChild(copyBtn);

      // Build human-readable record reconstruction
      const readableText = this._buildReadableRecord(ev);
      const pre = document.createElement('pre');
      pre.className = 'evtx-raw-hex';
      const code = document.createElement('code');
      code.textContent = readableText;
      pre.appendChild(code);
      rawContent.appendChild(pre);

      rawDetails.appendChild(rawContent);
      pane.appendChild(rawDetails);

      // Copy handler
      copyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(readableText).then(() => {
            copyBtn.textContent = '✓ Copied!';
            setTimeout(() => { copyBtn.textContent = '📋 Copy Text'; }, 1500);
          });
        } else {
          const ta = document.createElement('textarea');
          ta.value = readableText;
          ta.style.cssText = 'position:fixed;opacity:0';
          document.body.appendChild(ta);
          ta.select();
          document.execCommand('copy');
          document.body.removeChild(ta);
          copyBtn.textContent = '✓ Copied!';
          setTimeout(() => { copyBtn.textContent = '📋 Copy Text'; }, 1500);
        }
      });
    }

    container.appendChild(pane);
  }

  // ── Build human-readable record reconstruction from parsed event ────────
  _buildReadableRecord(ev) {
    const lines = [];
    const sep = '─'.repeat(60);

    // ── System Fields ──────────────────────────────────────────────────
    lines.push('┌' + sep + '┐');
    lines.push('│  SYSTEM FIELDS');
    lines.push('├' + sep + '┤');
    const sysFields = [
      ['Record ID', ev.recordId],
      ['Timestamp', ev.timestamp],
      ['Event ID', ev.eventId],
      ['Level', ev.level],
      ['Provider', ev.provider],
      ['Channel', ev.channel],
      ['Computer', ev.computer],
    ];
    // Include opcode/task if present (from BinXml decode)
    if (ev.opcode) sysFields.push(['Opcode', ev.opcode]);
    if (ev.task) sysFields.push(['Task', ev.task]);

    const maxKeyLen = Math.max(...sysFields.map(f => f[0].length));
    for (const [key, val] of sysFields) {
      lines.push('│  ' + key.padEnd(maxKeyLen + 2) + ': ' + (val != null ? String(val) : ''));
    }
    lines.push('└' + sep + '┘');

    // ── Event Description ──────────────────────────────────────────────
    const desc = this._getEventDescription(ev.eventId, ev.provider);
    if (desc) {
      lines.push('');
      lines.push('DESCRIPTION: ' + desc);
    }

    // ── Event Data (parsed key-value pairs) ────────────────────────────
    if (ev.eventData) {
      lines.push('');
      lines.push('┌' + sep + '┐');
      lines.push('│  EVENT DATA');
      lines.push('├' + sep + '┤');

      const pairs = this._parseEventDataPairs(ev.eventData);
      if (pairs.length > 0 && pairs.some(p => p.key)) {
        const dataKeyLen = Math.max(...pairs.filter(p => p.key).map(p => p.key.length), 1);
        for (const p of pairs) {
          if (p.key) {
            // For long values (command lines, etc.), show on next line indented
            if (p.val && p.val.length > 80) {
              lines.push('│  ' + p.key.padEnd(dataKeyLen + 2) + ':');
              // Wrap long values at ~76 chars with continuation indent
              const indent = '│    ';
              const maxWidth = 72;
              let remaining = p.val;
              while (remaining.length > 0) {
                lines.push(indent + remaining.substring(0, maxWidth));
                remaining = remaining.substring(maxWidth);
              }
            } else {
              lines.push('│  ' + p.key.padEnd(dataKeyLen + 2) + ': ' + (p.val || ''));
            }
          } else if (p.val) {
            lines.push('│  ' + p.val);
          }
        }
      } else {
        // Plain text event data — wrap it nicely
        const maxWidth = 72;
        const indent = '│  ';
        let remaining = ev.eventData;
        while (remaining.length > 0) {
          lines.push(indent + remaining.substring(0, maxWidth));
          remaining = remaining.substring(maxWidth);
        }
      }
      lines.push('└' + sep + '┘');
    }

    // ── Additional strings from raw record ─────────────────────────────
    // Extract any readable strings from raw bytes that might not have been
    // captured by the structured parser (e.g., partially parsed XML fragments,
    // embedded paths, registry keys, etc.)
    if (ev.rawRecord && ev.rawRecord.length > 0) {
      const extraStrings = this._extractExtraStrings(ev);
      if (extraStrings.length > 0) {
        lines.push('');
        lines.push('┌' + sep + '┐');
        lines.push('│  ADDITIONAL STRINGS FROM RAW RECORD');
        lines.push('├' + sep + '┤');
        for (const s of extraStrings) {
          // Wrap long strings
          if (s.length > 72) {
            let remaining = s;
            while (remaining.length > 0) {
              lines.push('│  ' + remaining.substring(0, 72));
              remaining = remaining.substring(72);
            }
          } else {
            lines.push('│  ' + s);
          }
        }
        lines.push('└' + sep + '┘');
      }
    }

    // ── Record metadata ────────────────────────────────────────────────
    lines.push('');
    lines.push('── Record Size: ' + (ev.rawRecord ? ev.rawRecord.length : 0) + ' bytes ──');

    return lines.join('\n');
  }

  // ── Extract readable strings from raw bytes not already in parsed fields ─
  _extractExtraStrings(ev) {
    const raw = ev.rawRecord;
    if (!raw || raw.length === 0) return [];

    // Collect all known parsed values to deduplicate
    const knownValues = new Set();
    const addKnown = (val) => {
      if (!val) return;
      const s = String(val).trim().toLowerCase();
      if (s.length >= 3) knownValues.add(s);
    };
    addKnown(ev.provider);
    addKnown(ev.channel);
    addKnown(ev.computer);
    addKnown(ev.eventData);
    // Also add individual event data values
    if (ev.eventData) {
      for (const part of ev.eventData.split(' | ')) {
        const eqIdx = part.indexOf('=');
        if (eqIdx > 0) {
          addKnown(part.substring(eqIdx + 1));
        } else {
          addKnown(part);
        }
      }
    }

    // Known BinXml structural/element names to skip
    const structuralNames = new Set([
      'event', 'system', 'eventdata', 'userdata', 'provider', 'eventid',
      'version', 'level', 'task', 'opcode', 'keywords', 'timecreated',
      'eventrecordid', 'correlation', 'execution', 'channel', 'computer',
      'security', 'data', 'name', 'guid', 'systemtime', 'processid',
      'threadid', 'activityid', 'qualifiers', 'userid',
      'xmlns', 'http', 'schemas.microsoft.com',
    ]);

    // Extract UTF-16LE strings from raw bytes
    const strings = [];
    const end = raw.length - 1;
    let i = 0;
    while (i + 1 < end) {
      if (raw[i] >= 0x20 && raw[i] < 0x7F && raw[i + 1] === 0) {
        const strStart = i;
        let len = 0;
        while (i + 1 < end && raw[i] >= 0x20 && raw[i] < 0x7F && raw[i + 1] === 0) {
          len++;
          i += 2;
        }
        if (len >= 4) { // Minimum 4 chars to reduce noise
          const str = this._readUtf16(raw, strStart, len);
          const lower = str.trim().toLowerCase();
          // Skip if it's a known parsed value, structural name, or very short noise
          if (!knownValues.has(lower) && !structuralNames.has(lower) &&
            !/^[\s\x00-\x1f]+$/.test(str) && // skip whitespace-only
            !/^[{(]?[0-9a-f]{8}-[0-9a-f]{4}/i.test(str) && // skip GUIDs
            !/^https?:\/\/schemas\./i.test(str) && // skip XML namespace URLs
            str.trim().length >= 4) {
            strings.push(str.trim());
          }
        }
      } else {
        i += 2;
      }
    }

    // Also try extracting ASCII strings (some records contain ASCII-encoded data)
    // Build a Set of lowercased UTF-16 strings for O(1) dedup instead of O(n²).
    const utf16Lower = new Set(strings.map(s => s.toLowerCase()));
    i = 0;
    while (i < raw.length) {
      if (raw[i] >= 0x20 && raw[i] < 0x7F) {
        const strStart = i;
        while (i < raw.length && raw[i] >= 0x20 && raw[i] < 0x7F) i++;
        const len = i - strStart;
        if (len >= 8) { // Longer threshold for ASCII to reduce false positives
          const str = String.fromCharCode(...raw.subarray(strStart, strStart + len));
          const lower = str.trim().toLowerCase();
          if (!knownValues.has(lower) && !structuralNames.has(lower) &&
            !utf16Lower.has(lower) && // deduplicate with UTF-16 results (O(1))
            !/^[\s.]+$/.test(str) && // skip dots/spaces
            !/^https?:\/\/schemas\./i.test(str) &&
            str.trim().length >= 8) {
            strings.push('[ASCII] ' + str.trim());
          }
        }
      } else {
        i++;
      }
    }

    // Deduplicate and limit results
    const unique = [...new Set(strings)];
    return unique.slice(0, 50); // Cap at 50 strings to avoid huge output
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
    const dlBtn = document.createElement('button');
    dlBtn.className = 'tb-btn csv-export-btn';
    dlBtn.textContent = '💾 Download CSV';
    dlBtn.title = 'Download all events as a CSV file';
    dlBtn.addEventListener('click', () => {
      const csv = this._toCsv(events);
      const base = (fileName || 'events').replace(/\.[^.]+$/, '');
      window.FileDownload.downloadText(csv, base + '.csv', 'text/csv;charset=utf-8');
      this._showToast(bar, 'Downloaded!');
    });

    const pillGroup = document.createElement('div');
    pillGroup.className = 'btn-pill-group';
    pillGroup.appendChild(dlBtn);
    pillGroup.appendChild(copyBtn);
    bar.appendChild(pillGroup);

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

// Static constants — hoisted out of method bodies to avoid re-allocating
// large arrays/objects on every analyzeForSecurity / _getEventDescription /
// _isNotableEventId call. Especially important for EVTX files with 100k+
// events where _isNotableEventId is called per-row.

EvtxRenderer._NOTABLE_EIDS = new Set([
  1102, 4624, 4625, 4648, 4672, 4688, 4720, 4726, 4728, 4732, 4733, 4735,
  7045, 4104, 4103, 4697, 4698, 4699, 4700, 4701, 4702,
  1, 3, 7, 8, 10, 11, 12, 13, 14, 15, 17, 18, 22, 23, 25
]);

// `_SUSPICIOUS_PATTERNS` table moved to `src/evtx-detector.js` —
// see `EvtxDetector._SUSPICIOUS_PATTERNS`. Keeping it out of the renderer
// shaves the parse-only Timeline worker bundle and removes the only
// analyzer-side dependency from the renderer.

EvtxRenderer._SYSMON_DESCS = {
  1: 'Process Created \u2014 A new process was started on the system.',
  2: 'File Creation Time Changed \u2014 A process modified the creation timestamp of a file (possible timestomping).',
  3: 'Network Connection Detected \u2014 A TCP/UDP network connection was initiated by a process.',
  4: 'Sysmon Service State Changed \u2014 The Sysmon service started or stopped.',
  5: 'Process Terminated \u2014 A process exited.',
  6: 'Driver Loaded \u2014 A kernel driver was loaded into the system.',
  7: 'Image Loaded \u2014 A DLL or executable image was loaded into a process.',
  8: 'CreateRemoteThread \u2014 A thread was created in another process (possible process injection).',
  9: 'RawAccessRead \u2014 A process performed a raw disk read bypassing the filesystem.',
  10: 'Process Accessed \u2014 A process opened a handle to another process (possible credential dumping via LSASS).',
  11: 'File Created \u2014 A new file was created or overwritten.',
  12: 'Registry Object Added or Deleted \u2014 A registry key or value was created or deleted.',
  13: 'Registry Value Set \u2014 A registry value was modified.',
  14: 'Registry Object Renamed \u2014 A registry key or value was renamed.',
  15: 'File Stream Created \u2014 An Alternate Data Stream (ADS) was written to a file.',
  16: 'Sysmon Configuration Changed \u2014 The Sysmon configuration was updated.',
  17: 'Named Pipe Created \u2014 A named pipe was created for inter-process communication.',
  18: 'Named Pipe Connected \u2014 A client connected to a named pipe.',
  19: 'WMI EventFilter Activity \u2014 A WMI event filter was registered (possible persistence).',
  20: 'WMI EventConsumer Activity \u2014 A WMI event consumer was registered (possible persistence).',
  21: 'WMI EventConsumerToFilter \u2014 A WMI consumer was bound to a filter (possible persistence).',
  22: 'DNS Query \u2014 A process performed a DNS lookup.',
  23: 'File Deleted \u2014 A file was deleted and archived by Sysmon.',
  24: 'Clipboard Changed \u2014 The clipboard contents were modified by a process.',
  25: 'Process Tampering \u2014 A process image was replaced or hollowed (process hollowing/herpaderping).',
  26: 'File Delete Logged \u2014 A file deletion was detected and logged.',
  27: 'File Block Executable \u2014 An executable file write was blocked by Sysmon.',
  28: 'File Block Shredding \u2014 A file shredding operation was blocked by Sysmon.',
  29: 'File Executable Detected \u2014 An executable file was detected being written to disk.',
  255: 'Sysmon Error \u2014 An error occurred within the Sysmon service.',
};

EvtxRenderer._EVENT_DESCS = {
  1100: 'Event Logging Service Shut Down \u2014 The Windows Event Log service was stopped.',
  1102: 'Security Audit Log Cleared \u2014 The Security event log was cleared (possible anti-forensics).',
  104: 'System Log Cleared \u2014 A system event log was cleared.',
  4624: 'Successful Logon \u2014 A user account successfully logged on to the computer.',
  4625: 'Failed Logon \u2014 A logon attempt failed (wrong password, locked account, expired, etc.).',
  4634: 'Account Logoff \u2014 A user account logged off.',
  4647: 'User-Initiated Logoff \u2014 A user initiated a logoff.',
  4648: 'Explicit Credential Logon \u2014 A logon was attempted using explicit credentials (pass-the-hash indicator).',
  4672: 'Special Privileges Assigned \u2014 Administrative or special privileges were assigned to a new logon session.',
  4675: 'SIDs Filtered \u2014 SIDs were filtered during logon.',
  4768: 'Kerberos TGT Requested \u2014 A Kerberos Ticket Granting Ticket (TGT) was requested.',
  4769: 'Kerberos Service Ticket Requested \u2014 A Kerberos service ticket (TGS) was requested.',
  4770: 'Kerberos Service Ticket Renewed \u2014 A Kerberos service ticket was renewed.',
  4771: 'Kerberos Pre-Authentication Failed \u2014 Kerberos pre-auth failed (possible password spray/brute-force).',
  4776: 'NTLM Credential Validation \u2014 The domain controller validated credentials via NTLM.',
  4688: 'Process Created \u2014 A new process was created on the system.',
  4689: 'Process Exited \u2014 A process was terminated.',
  4720: 'User Account Created \u2014 A new user account was created.',
  4722: 'User Account Enabled \u2014 A user account was enabled.',
  4723: 'Password Change Attempted \u2014 An attempt was made to change an account\'s password.',
  4724: 'Password Reset Attempted \u2014 An attempt was made to reset an account\'s password.',
  4725: 'User Account Disabled \u2014 A user account was disabled.',
  4726: 'User Account Deleted \u2014 A user account was deleted.',
  4728: 'Member Added to Global Security Group \u2014 A member was added to a security-enabled global group.',
  4729: 'Member Removed from Global Security Group \u2014 A member was removed from a security-enabled global group.',
  4732: 'Member Added to Local Security Group \u2014 A member was added to a security-enabled local group.',
  4733: 'Member Removed from Local Security Group \u2014 A member was removed from a security-enabled local group.',
  4735: 'Local Security Group Changed \u2014 A security-enabled local group was modified.',
  4737: 'Global Security Group Changed \u2014 A security-enabled global group was modified.',
  4738: 'User Account Changed \u2014 A user account was modified.',
  4740: 'Account Locked Out \u2014 A user account was locked out due to failed logon attempts.',
  4741: 'Computer Account Created \u2014 A computer account was created in Active Directory.',
  4742: 'Computer Account Changed \u2014 A computer account was modified.',
  4743: 'Computer Account Deleted \u2014 A computer account was deleted.',
  4756: 'Member Added to Universal Security Group \u2014 A member was added to a security-enabled universal group.',
  4757: 'Member Removed from Universal Security Group \u2014 A member was removed from a security-enabled universal group.',
  4656: 'Handle Requested \u2014 A handle to an object (file, key, etc.) was requested.',
  4657: 'Registry Value Modified \u2014 A registry value was changed.',
  4658: 'Handle Closed \u2014 A handle to an object was closed.',
  4660: 'Object Deleted \u2014 An object was deleted.',
  4663: 'Object Access Attempted \u2014 An attempt was made to access an object.',
  4670: 'Object Permissions Changed \u2014 Permissions on an object were changed.',
  4697: 'Service Installed \u2014 A new service was installed in the system.',
  4698: 'Scheduled Task Created \u2014 A new scheduled task was created.',
  4699: 'Scheduled Task Deleted \u2014 A scheduled task was deleted.',
  4700: 'Scheduled Task Enabled \u2014 A scheduled task was enabled.',
  4701: 'Scheduled Task Disabled \u2014 A scheduled task was disabled.',
  4702: 'Scheduled Task Updated \u2014 A scheduled task was updated.',
  7034: 'Service Crashed \u2014 A service terminated unexpectedly.',
  7036: 'Service State Changed \u2014 A service entered the running or stopped state.',
  7040: 'Service Start Type Changed \u2014 The start type of a service was changed (possible persistence).',
  7045: 'New Service Installed \u2014 A new service was installed in the system.',
  5140: 'Network Share Accessed \u2014 A network share object was accessed.',
  5142: 'Network Share Added \u2014 A network share object was added.',
  5144: 'Network Share Deleted \u2014 A network share object was deleted.',
  5145: 'Network Share Access Checked \u2014 Access to a network share object was checked.',
  5156: 'WFP Connection Allowed \u2014 Windows Filtering Platform allowed a network connection.',
  5157: 'WFP Connection Blocked \u2014 Windows Filtering Platform blocked a network connection.',
  4103: 'PowerShell Module Logging \u2014 A PowerShell module was loaded and logged.',
  4104: 'PowerShell Script Block Logged \u2014 A PowerShell script block was captured for analysis.',
  40961: 'PowerShell Console Started \u2014 A PowerShell console host session was started.',
  40962: 'PowerShell Console Ready \u2014 A PowerShell console host session is ready for input.',
  53504: 'PowerShell ISE Session \u2014 A Windows PowerShell ISE session was started.',
  1006: 'Defender: Malware Detected \u2014 Windows Defender detected malware or potentially unwanted software.',
  1007: 'Defender: Protection Action \u2014 Windows Defender took action to protect the system from malware.',
  1008: 'Defender: Action Failed \u2014 Windows Defender failed to take action on detected malware.',
  1009: 'Defender: Item Restored \u2014 An item was restored from Windows Defender quarantine.',
  1116: 'Defender: Threat Detected \u2014 Windows Defender detected a threat.',
  1117: 'Defender: Protection Action Taken \u2014 Windows Defender performed an action against a threat.',
  5001: 'Defender: Real-Time Protection Disabled \u2014 Windows Defender real-time protection was disabled.',
  5004: 'Defender: Configuration Changed \u2014 Windows Defender real-time protection config was changed.',
  5007: 'Defender: Platform Configuration Changed \u2014 The antimalware platform configuration was changed.',
  5010: 'Defender: Malware Scanning Disabled \u2014 Scanning for malware and spyware was disabled.',
  5012: 'Defender: Virus Scanning Disabled \u2014 Scanning for viruses was disabled.',
  5857: 'WMI Provider Started \u2014 A WMI provider was loaded and started.',
  5858: 'WMI Provider Error \u2014 A WMI provider encountered an error.',
  5859: 'WMI Subscription Operation \u2014 A WMI event subscription operation was performed.',
  5860: 'WMI Temporary Event Created \u2014 A temporary WMI event subscription was created.',
  5861: 'WMI Permanent Event Subscription \u2014 A permanent WMI event subscription was created (possible persistence).',
  8003: 'AppLocker: Executable Allowed \u2014 An executable file was allowed to run by AppLocker.',
  8004: 'AppLocker: Executable Blocked \u2014 An executable file was blocked by AppLocker policy.',
  8006: 'AppLocker: Script/MSI Allowed \u2014 A script or MSI file was allowed by AppLocker.',
  8007: 'AppLocker: Script/MSI Blocked \u2014 A script or MSI file was blocked by AppLocker.',
  1149: 'RDP Authentication Succeeded \u2014 A user was successfully authenticated via Remote Desktop.',
  4778: 'Session Reconnected \u2014 A session was reconnected to a Window Station.',
  4779: 'Session Disconnected \u2014 A session was disconnected from a Window Station.',
  60: 'BITS Transfer Started \u2014 A Background Intelligent Transfer Service job was started.',
  6005: 'Event Log Service Started \u2014 The Event Log service was started (system boot).',
  6006: 'Event Log Service Stopped \u2014 The Event Log service was stopped (clean shutdown).',
  6008: 'Unexpected Shutdown \u2014 The previous system shutdown was unexpected.',
  6009: 'OS Information Logged \u2014 Operating system version information logged at boot.',
  6013: 'System Uptime \u2014 System uptime information.',
  1501: 'Group Policy Applied \u2014 Group Policy settings were applied successfully.',
  1502: 'Group Policy Failed \u2014 Group Policy processing failed.',
  106: 'Task Registered \u2014 A new task was registered in Task Scheduler.',
  140: 'Task Updated \u2014 A task was updated in Task Scheduler.',
  141: 'Task Removed \u2014 A task was removed from Task Scheduler.',
  200: 'Task Action Started \u2014 A scheduled task action was started.',
  201: 'Task Action Completed \u2014 A scheduled task action completed.',
  2003: 'Firewall Rule Added \u2014 A Windows Firewall rule was added.',
  2004: 'Firewall Rule Modified \u2014 A Windows Firewall rule was modified.',
  2005: 'Firewall Rule Deleted \u2014 A Windows Firewall rule was deleted.',
  2006: 'Firewall Rules Deleted \u2014 Windows Firewall rules were deleted (batch).',
  4719: 'Audit Policy Changed \u2014 System audit policy was changed.',
  4907: 'Auditing Settings Changed \u2014 Auditing settings on an object were changed.',
};
