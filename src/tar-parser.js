'use strict';
// ════════════════════════════════════════════════════════════════════════════
// tar-parser.js — Robust TAR archive parser with PAX / GNU extension support
// Handles: POSIX ustar, PAX extended headers (x/g), GNU long name/link (L/K),
//          GNU old-style sparse (S), PAX sparse v0.0/v0.1/v1.0, base-256 numerics
// Depends on: constants.js (PARSER_LIMITS)
// ════════════════════════════════════════════════════════════════════════════

// eslint-disable-next-line no-unused-vars
const TarParser = {

  // ── Public API ────────────────────────────────────────────────────────────

  /**
   * Parse a TAR archive into an array of entries.
   *
   * Each entry: { path, name, dir, size, mtime, offset, linkName,
   *               sparseData: Uint8Array|null, sparseMap: [{off,len}]|null,
   *               sparseRealSize: number|null }
   *
   * `offset` / `size` point at the raw data inside `bytes`.
   * For sparse entries, callers must use `reassembleSparse()` instead of
   * a direct `bytes.subarray(offset, offset+size)`.
   */
  parse(bytes) {
    const entries = [];
    let offset = 0;
    const cap = PARSER_LIMITS.MAX_ENTRIES;

    // State carried across headers for GNU long-name / long-link / PAX
    let pendingName = null;
    let pendingLink = null;
    let globalPax = {};

    while (offset + 512 <= bytes.length && entries.length < cap) {
      const header = bytes.subarray(offset, offset + 512);

      // End-of-archive: two consecutive 512-byte zero blocks
      if (this._isNullBlock(header)) break;

      // ── Parse standard header fields ────────────────────────────────
      const rawName  = this._readString(header, 0, 100);
      const rawSize  = this._readNumeric(header, 124, 12);
      const rawMtime = this._readNumeric(header, 136, 12);
      const typeFlag = header[156];
      const rawLink  = this._readString(header, 157, 100);
      const prefix   = this._readString(header, 345, 155);

      // Data blocks that follow this header (based on raw header size)
      const dataBytes  = rawSize;
      const dataBlocks = Math.ceil(dataBytes / 512);
      const dataStart  = offset + 512;

      // ── Dispatch on type flag ───────────────────────────────────────

      // PAX global extended header ('g' = 0x67)
      if (typeFlag === 0x67) {
        if (dataBytes > 0 && dataStart + dataBytes <= bytes.length) {
          const paxData = bytes.subarray(dataStart, dataStart + dataBytes);
          globalPax = this._parsePaxData(paxData);
        }
        offset = dataStart + dataBlocks * 512;
        continue;
      }

      // PAX per-file extended header ('x' = 0x78)
      if (typeFlag === 0x78) {
        let localPax = {};
        if (dataBytes > 0 && dataStart + dataBytes <= bytes.length) {
          const paxData = bytes.subarray(dataStart, dataStart + dataBytes);
          localPax = this._parsePaxData(paxData);
        }
        offset = dataStart + dataBlocks * 512;

        // The NEXT header is the real file entry — read it now
        if (offset + 512 > bytes.length) break;
        const realResult = this._readRealEntry(
          bytes, offset, localPax, globalPax, pendingName, pendingLink, cap - entries.length
        );
        if (realResult) {
          for (const e of realResult.entries) entries.push(e);
          offset = realResult.nextOffset;
        }
        pendingName = null;
        pendingLink = null;
        continue;
      }

      // GNU long name ('L' = 0x4C)
      if (typeFlag === 0x4C) {
        if (dataBytes > 0 && dataStart + dataBytes <= bytes.length) {
          const raw = bytes.subarray(dataStart, dataStart + dataBytes);
          pendingName = this._readNullTerminated(raw);
        }
        offset = dataStart + dataBlocks * 512;
        continue;
      }

      // GNU long link ('K' = 0x4B)
      if (typeFlag === 0x4B) {
        if (dataBytes > 0 && dataStart + dataBytes <= bytes.length) {
          const raw = bytes.subarray(dataStart, dataStart + dataBytes);
          pendingLink = this._readNullTerminated(raw);
        }
        offset = dataStart + dataBlocks * 512;
        continue;
      }

      // GNU old-style sparse ('S' = 0x53)
      if (typeFlag === 0x53) {
        const sparseResult = this._parseGnuSparse(bytes, offset, header, rawName, prefix, rawMtime, pendingName);
        if (sparseResult) entries.push(sparseResult.entry);
        offset = sparseResult ? sparseResult.nextOffset : (dataStart + dataBlocks * 512);
        pendingName = null;
        pendingLink = null;
        continue;
      }

      // ── Regular entry (type '0'/NUL, '5' directory, '2' symlink, etc.) ──
      const entry = this._buildEntry(
        rawName, prefix, rawSize, rawMtime, typeFlag, rawLink,
        dataStart, globalPax, pendingName, pendingLink
      );
      entries.push(entry);
      offset = dataStart + dataBlocks * 512;
      pendingName = null;
      pendingLink = null;
    }

    return entries;
  },

  /**
   * Detect whether `bytes` looks like a TAR archive.
   */
  isTar(bytes) {
    // POSIX/UStar magic at offset 257
    if (bytes.length > 262) {
      const m = String.fromCharCode(bytes[257], bytes[258], bytes[259], bytes[260], bytes[261]);
      if (m === 'ustar') return true;
    }
    // GNU/legacy heuristic: valid filename + octal size field
    if (bytes.length > 512) {
      const nameEnd = bytes.indexOf(0);
      if (nameEnd > 0 && nameEnd < 100) {
        const sizeStr = this._readString(bytes, 124, 12).trim();
        if (/^[0-7]+$/.test(sizeStr)) return true;
      }
    }
    return false;
  },

  /**
   * Extract an entry's file data from the archive bytes.
   * Handles sparse reassembly transparently.
   * Returns a Uint8Array of the file content, or null for dirs / zero-size.
   */
  extractEntry(bytes, entry) {
    if (entry.dir || !entry.size) return null;

    // Sparse entry — needs reassembly
    if (entry.sparseMap && entry.sparseRealSize != null) {
      return this._reassembleSparse(bytes, entry);
    }

    // Normal entry — direct slice
    return bytes.subarray(entry.offset, entry.offset + entry.size);
  },


  // ── Internal: read the real entry that follows a PAX 'x' header ─────────

  /**
   * After consuming a PAX 'x' header, read the subsequent real entry and
   * apply PAX overrides (path, size, linkpath, mtime, sparse).
   * Returns { entries: [...], nextOffset } or null.
   */
  _readRealEntry(bytes, offset, localPax, globalPax, pendingName, pendingLink, remaining) {
    if (remaining <= 0) return null;
    const header = bytes.subarray(offset, offset + 512);
    if (this._isNullBlock(header)) return null;

    const rawName  = this._readString(header, 0, 100);
    const prefix   = this._readString(header, 345, 155);
    const rawSize  = this._readNumeric(header, 124, 12);
    const rawMtime = this._readNumeric(header, 136, 12);
    const typeFlag = header[156];
    const rawLink  = this._readString(header, 157, 100);

    const dataBytes  = rawSize;
    const dataBlocks = Math.ceil(dataBytes / 512);
    const dataStart  = offset + 512;

    // Merge PAX overrides:  local > pending GNU > global > header
    const pax = Object.assign({}, globalPax, localPax);

    const fullPathRaw = pendingName
      || pax['path']
      || (prefix ? prefix + '/' + rawName : rawName);

    const linkName = pendingLink
      || pax['linkpath']
      || rawLink || null;

    const mtime = pax['mtime'] != null
      ? parseFloat(pax['mtime'])
      : rawMtime;

    const isDir = typeFlag === 0x35 || fullPathRaw.endsWith('/');
    const fullPath = fullPathRaw.replace(/\/$/, '');

    // ── PAX sparse detection (v0.0 / v0.1 / v1.0) ──────────────────
    const sparseMajor = pax['GNU.sparse.major'];
    const sparseMinor = pax['GNU.sparse.minor'];

    // v1.0: sparse map is at the start of the data block
    if (sparseMajor === '1' && sparseMinor === '0') {
      const sparseName = pax['GNU.sparse.name'] || fullPath;
      const sparseRealSize = parseInt(pax['GNU.sparse.realsize'] || '0', 10);
      const data = (dataBytes > 0 && dataStart + dataBytes <= bytes.length)
        ? bytes.subarray(dataStart, dataStart + dataBytes)
        : new Uint8Array(0);
      const parsed = this._parseSparseMapFromData(data);

      const entry = {
        path: sparseName.replace(/\/$/, ''),
        name: sparseName.replace(/\/$/, '').split('/').pop(),
        dir: false,
        size: sparseRealSize,
        mtime: mtime > 0 ? new Date(mtime * 1000) : null,
        offset: dataStart,
        linkName: null,
        sparseMap: parsed.map,
        sparseRealSize: sparseRealSize,
        _sparseDataOffset: dataStart + parsed.dataOffset,
        _sparseDataLength: dataBytes - parsed.dataOffset,
      };
      return { entries: [entry], nextOffset: dataStart + dataBlocks * 512 };
    }

    // v0.1: sparse map as comma-separated string in PAX header
    if (pax['GNU.sparse.map']) {
      const sparseRealSize = parseInt(
        pax['GNU.sparse.realsize'] || pax['GNU.sparse.size'] || '0', 10
      );
      const sparseMap = this._parseSparseMapString(pax['GNU.sparse.map']);

      const entry = {
        path: fullPath,
        name: fullPath.split('/').pop(),
        dir: false,
        size: sparseRealSize,
        mtime: mtime > 0 ? new Date(mtime * 1000) : null,
        offset: dataStart,
        linkName: null,
        sparseMap: sparseMap,
        sparseRealSize: sparseRealSize,
        _sparseDataOffset: dataStart,
        _sparseDataLength: dataBytes,
      };
      return { entries: [entry], nextOffset: dataStart + dataBlocks * 512 };
    }

    // v0.0: repeated GNU.sparse.offset / GNU.sparse.numbytes in PAX
    if (pax['GNU.sparse.numblocks'] || pax._sparseOffsets) {
      const sparseRealSize = parseInt(
        pax['GNU.sparse.realsize'] || pax['GNU.sparse.size'] || '0', 10
      );
      const sparseMap = (pax._sparseOffsets || []).map((off, i) => ({
        off: off,
        len: (pax._sparseNumbytes || [])[i] || 0,
      }));

      const entry = {
        path: fullPath,
        name: fullPath.split('/').pop(),
        dir: false,
        size: sparseRealSize,
        mtime: mtime > 0 ? new Date(mtime * 1000) : null,
        offset: dataStart,
        linkName: null,
        sparseMap: sparseMap,
        sparseRealSize: sparseRealSize,
        _sparseDataOffset: dataStart,
        _sparseDataLength: dataBytes,
      };
      return { entries: [entry], nextOffset: dataStart + dataBlocks * 512 };
    }

    // ── Non-sparse PAX file — use PAX size for logical size ───────────
    const logicalSize = pax['size'] != null
      ? parseInt(pax['size'], 10)
      : rawSize;

    const entry = {
      path: fullPath,
      name: fullPath.split('/').pop(),
      dir: isDir,
      size: isDir ? 0 : logicalSize,
      mtime: mtime > 0 ? new Date(mtime * 1000) : null,
      offset: dataStart,
      linkName: linkName || null,
      sparseMap: null,
      sparseRealSize: null,
      _sparseDataOffset: null,
      _sparseDataLength: null,
    };
    return { entries: [entry], nextOffset: dataStart + dataBlocks * 512 };
  },


  // ── Internal: build a standard (non-PAX) entry ──────────────────────────

  _buildEntry(rawName, prefix, rawSize, rawMtime, typeFlag, rawLink,
              dataStart, globalPax, pendingName, pendingLink) {

    const fullPathRaw = pendingName
      || globalPax['path']
      || (prefix ? prefix + '/' + rawName : rawName);

    const linkName = pendingLink
      || globalPax['linkpath']
      || rawLink || null;

    const isDir = typeFlag === 0x35 || fullPathRaw.endsWith('/');
    const fullPath = fullPathRaw.replace(/\/$/, '');

    return {
      path: fullPath,
      name: fullPath.split('/').pop(),
      dir: isDir,
      size: isDir ? 0 : rawSize,
      mtime: rawMtime > 0 ? new Date(rawMtime * 1000) : null,
      offset: dataStart,
      linkName: linkName || null,
      sparseMap: null,
      sparseRealSize: null,
      _sparseDataOffset: null,
      _sparseDataLength: null,
    };
  },


  // ── GNU old-style sparse ('S') ──────────────────────────────────────────

  /**
   * Parse a GNU old-style sparse header (type flag 'S').
   * The sparse map is embedded in the 512-byte header at offset 386.
   */
  _parseGnuSparse(bytes, headerOffset, header, rawName, prefix, rawMtime, pendingName) {
    // Real (expanded) file size at offset 483, 12 bytes octal
    const realSize = this._readNumeric(header, 483, 12);

    // Read the 4 inline sparse map entries (offset 386, 24 bytes each)
    const sparseMap = [];
    for (let i = 0; i < 4; i++) {
      const base = 386 + i * 24;
      const off = this._readNumeric(header, base, 12);
      const len = this._readNumeric(header, base + 12, 12);
      if (off === 0 && len === 0) break;
      sparseMap.push({ off: off, len: len });
    }

    // isextended flag at offset 482
    let isExtended = header[482] !== 0;
    let extOffset = headerOffset + 512;

    // Walk extended sparse blocks (each 512 bytes, 21 entries of 24 bytes)
    while (isExtended && extOffset + 512 <= bytes.length) {
      const extBlock = bytes.subarray(extOffset, extOffset + 512);
      for (let i = 0; i < 21; i++) {
        const base = i * 24;
        const off = this._readNumeric(extBlock, base, 12);
        const len = this._readNumeric(extBlock, base + 12, 12);
        if (off === 0 && len === 0) break;
        sparseMap.push({ off: off, len: len });
      }
      isExtended = extBlock[504] !== 0;
      extOffset += 512;
    }

    // Raw data size from header (sum of all sparse chunk lengths)
    const rawSize = this._readNumeric(header, 124, 12);
    const dataBlocks = Math.ceil(rawSize / 512);

    // Data starts after the header + any extended sparse blocks
    const dataStart = extOffset;

    const fullPathRaw = pendingName || (prefix ? prefix + '/' + rawName : rawName);
    const fullPath = fullPathRaw.replace(/\/$/, '');

    const entry = {
      path: fullPath,
      name: fullPath.split('/').pop(),
      dir: false,
      size: realSize,
      mtime: rawMtime > 0 ? new Date(rawMtime * 1000) : null,
      offset: dataStart,
      linkName: null,
      sparseMap: sparseMap,
      sparseRealSize: realSize,
      _sparseDataOffset: dataStart,
      _sparseDataLength: rawSize,
    };

    return { entry: entry, nextOffset: dataStart + dataBlocks * 512 };
  },


  // ── PAX data parsing ────────────────────────────────────────────────────

  /**
   * Parse PAX extended header data: "length key=value\n" records.
   * Returns a plain object of key→value pairs.
   * For v0.0 sparse, also collects _sparseOffsets / _sparseNumbytes arrays.
   */
  _parsePaxData(dataBytes) {
    const result = {};
    const text = new TextDecoder('utf-8', { fatal: false }).decode(dataBytes);
    let pos = 0;

    // v0.0 sparse: collect repeated offset/numbytes pairs in order
    const sparseOffsets = [];
    const sparseNumbytes = [];

    while (pos < text.length) {
      // Read the length prefix (decimal digits up to the first space)
      const spaceIdx = text.indexOf(' ', pos);
      if (spaceIdx < 0) break;
      const len = parseInt(text.substring(pos, spaceIdx), 10);
      if (!len || len <= 0 || pos + len > text.length) break;

      // The record is text[pos .. pos+len-1], ending with '\n'
      const record = text.substring(spaceIdx + 1, pos + len - 1); // strip trailing \n
      const eqIdx = record.indexOf('=');
      if (eqIdx > 0) {
        const key = record.substring(0, eqIdx);
        const value = record.substring(eqIdx + 1);

        // v0.0 sparse: collect offset/numbytes pairs sequentially
        if (key === 'GNU.sparse.offset') {
          sparseOffsets.push(parseInt(value, 10) || 0);
        } else if (key === 'GNU.sparse.numbytes') {
          sparseNumbytes.push(parseInt(value, 10) || 0);
        } else {
          result[key] = value;
        }
      }

      pos += len;
    }

    // Attach v0.0 sparse arrays if any were found
    if (sparseOffsets.length) {
      result._sparseOffsets = sparseOffsets;
      result._sparseNumbytes = sparseNumbytes;
    }

    return result;
  },


  // ── Sparse helpers ──────────────────────────────────────────────────────

  /**
   * Parse the v1.0 sparse map that is prepended to the data block.
   * Format: count\n(offset\nnumbytes\n)*  followed by actual file data.
   * Returns { map: [{off, len}], dataOffset: bytesParsed }.
   */
  _parseSparseMapFromData(data) {
    const map = [];
    let pos = 0;

    const readLine = () => {
      const start = pos;
      while (pos < data.length && data[pos] !== 0x0A) pos++;
      const line = new TextDecoder('utf-8', { fatal: false })
        .decode(data.subarray(start, pos));
      if (pos < data.length) pos++; // skip \n
      return line;
    };

    const countStr = readLine();
    const count = parseInt(countStr, 10) || 0;

    for (let i = 0; i < count; i++) {
      const off = parseInt(readLine(), 10) || 0;
      const len = parseInt(readLine(), 10) || 0;
      map.push({ off: off, len: len });
    }

    // GNU tar v1.0 pads the sparse map text to a 512-byte block boundary
    // before the actual sparse data begins.
    const alignedOffset = Math.ceil(pos / 512) * 512;
    return { map: map, dataOffset: alignedOffset };
  },

  /**
   * Parse a v0.1 sparse map from a comma-separated string.
   * "offset,numbytes,offset,numbytes,..."
   */
  _parseSparseMapString(str) {
    const parts = (str || '').split(',');
    const map = [];
    for (let i = 0; i + 1 < parts.length; i += 2) {
      map.push({
        off: parseInt(parts[i], 10) || 0,
        len: parseInt(parts[i + 1], 10) || 0,
      });
    }
    return map;
  },

  /**
   * Reassemble a sparse file from its packed data and sparse map.
   * Returns a Uint8Array of the complete (expanded) file.
   */
  _reassembleSparse(bytes, entry) {
    const realSize = entry.sparseRealSize || 0;
    // Safety cap: don't allocate more than MAX_UNCOMPRESSED
    const cappedSize = Math.min(realSize, PARSER_LIMITS.MAX_UNCOMPRESSED);
    const output = new Uint8Array(cappedSize); // zero-filled by default

    const dataOffset = entry._sparseDataOffset || entry.offset;
    const dataLength = entry._sparseDataLength != null
      ? entry._sparseDataLength : entry.size;
    const rawData = bytes.subarray(dataOffset, dataOffset + dataLength);

    let readPos = 0;
    for (const chunk of (entry.sparseMap || [])) {
      if (chunk.len <= 0) continue;
      if (chunk.off + chunk.len > cappedSize) break;   // would overflow output
      if (readPos + chunk.len > rawData.length) break;  // would overflow input
      output.set(rawData.subarray(readPos, readPos + chunk.len), chunk.off);
      readPos += chunk.len;
    }

    return output;
  },


  // ── Low-level header field readers ──────────────────────────────────────

  /** Read a NUL-terminated UTF-8 string from a header field. */
  _readString(header, offset, length) {
    let end = offset;
    while (end < offset + length && header[end] !== 0) end++;
    if (end === offset) return '';
    return new TextDecoder('utf-8', { fatal: false }).decode(header.subarray(offset, end));
  },

  /**
   * Read a numeric field, supporting both octal ASCII and GNU base-256.
   * Base-256: if the high bit of the first byte is set, the remaining
   * bytes are a big-endian unsigned integer.
   */
  _readNumeric(header, offset, length) {
    const first = header[offset];

    // GNU base-256 encoding: high bit set
    if (first & 0x80) {
      // Positive value: first byte is 0x80, remaining bytes are big-endian
      let val = 0;
      for (let i = 1; i < length; i++) {
        val = val * 256 + header[offset + i];
        // Safety: JavaScript can't precisely represent >2^53
        if (val > Number.MAX_SAFE_INTEGER) return val;
      }
      return val;
    }

    // Standard octal ASCII
    const str = this._readString(header, offset, length).trim();
    return str ? (parseInt(str, 8) || 0) : 0;
  },

  /** Read a NUL-terminated string from a raw data block. */
  _readNullTerminated(bytes) {
    let end = 0;
    while (end < bytes.length && bytes[end] !== 0) end++;
    if (end === 0) return '';
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, end));
  },

  /** Check if a 512-byte block is all zeros. */
  _isNullBlock(block) {
    for (let i = 0; i < block.length; i++) {
      if (block[i] !== 0) return false;
    }
    return true;
  },

};
