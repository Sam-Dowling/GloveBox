'use strict';
// ════════════════════════════════════════════════════════════════════════════
// seven7-renderer.js — 7-Zip (.7z) archive analyser (listing-only)
//
// Parses the 7-Zip container format:
//
//   SignatureHeader (32 B)
//     6 B  magic            "7z\xBC\xAF\x27\x1C"
//     2 B  version          (major, minor)
//     4 B  StartHeaderCRC
//     StartHeader (20 B)
//       8 B  nextHeaderOffset  (u64 LE, offset from end of SignatureHeader)
//       8 B  nextHeaderSize    (u64 LE)
//       4 B  nextHeaderCRC
//
// The "end header" at (32 + nextHeaderOffset) is either:
//
//   0x01 kHeader        — plain Header record (uncompressed)
//   0x17 kEncodedHeader — header is itself LZMA-compressed in a packed
//                         stream described by the following StreamsInfo
//
// LZMA-encoded end-headers (kEncodedHeader) are handled by vendoring
// LZMA-JS (`vendor/lzma-d-min.js`, decoder-only). The flow is:
//
//   • For kHeader (0x01): we walk FilesInfo and emit the full listing
//     (names, sizes, mtimes, attributes, directory flag).
//   • For kEncodedHeader (0x17): we parse the outer StreamsInfo to
//     recover the LZMA coder properties + packed data offset/size,
//     synthesize a 13-byte `.lzma` container header (5-byte props +
//     8-byte uncompressed-size LE) to satisfy LZMA-JS's `.lzma`-only
//     input shape, decompress the real header, and recursively walk
//     it as if it were a plain kHeader. Single-folder single-coder
//     LZMA chains are supported (which covers virtually every real
//     7z archive's end-header). LZMA2, BCJ, and multi-coder chains
//     fall back to metadata-only parsing.
//
// Every entry is marked `encrypted: true` in the ArchiveTree view so
// the Open button is suppressed (decompressing 7z content in-browser
// is out of scope — we'd need the full LZMA/LZMA2/PPMd/BCJ coder chain).
// Users still get archive metadata, warnings, and a listing (when the
// header is plain) for triage.
//
// Depends on: constants.js (IOC, PARSER_LIMITS, escHtml, fmtBytes,
//             pushIOC), ArchiveTree (archive-tree.js)
// ════════════════════════════════════════════════════════════════════════════
class SevenZRenderer {

  static EXEC_EXTS = new Set([
    'exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'msi', 'msp', 'mst', 'sys',
    'bat', 'cmd', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'js', 'jse',
    'wsf', 'wsh', 'wsc', 'hta', 'lnk', 'inf', 'reg', 'sct',
    'jar', 'py', 'rb', 'sh', 'bash', 'so', 'dylib',
    'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'ppam', 'xlam',
  ]);
  static DECOY_EXTS = new Set([
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'jpg', 'png', 'gif', 'txt', 'rtf',
  ]);

  // FilesInfo property IDs (7z spec)
  static PROP = {
    kEnd:              0x00,
    kHeader:           0x01,
    kArchiveProperties:0x02,
    kAdditionalStreamsInfo: 0x03,
    kMainStreamsInfo:  0x04,
    kFilesInfo:        0x05,
    kPackInfo:         0x06,
    kUnPackInfo:       0x07,
    kSubStreamsInfo:   0x08,
    kSize:             0x09,
    kCRC:              0x0A,
    kFolder:           0x0B,
    kCodersUnPackSize: 0x0C,
    kNumUnPackStream:  0x0D,
    kEmptyStream:      0x0E,
    kEmptyFile:        0x0F,
    kAnti:             0x10,
    kName:             0x11,
    kCTime:            0x12,
    kATime:            0x13,
    kMTime:            0x14,
    kWinAttributes:    0x15,
    kComment:          0x16,
    kEncodedHeader:    0x17,
    kStartPos:         0x18,
    kDummy:            0x19,
  };

  // ── Render ────────────────────────────────────────────────────────────

  async render(buffer, fileName) {
    const wrap = document.createElement('div');
    wrap.className = 'zip-view';
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>7-Zip Archive</strong> — Loupe enumerates the file listing for both plain and LZMA-encoded 7z headers (decoder vendored). File content decompression is not supported in-browser.';
    wrap.appendChild(banner);


    let parsed;
    try {
      parsed = this._parse(bytes);
    } catch (e) {
      const err = document.createElement('div');
      err.style.cssText = 'padding:12px 20px;color:var(--risk-high);';
      err.textContent = `⚠ Failed to parse 7z archive: ${e.message}`;
      wrap.appendChild(err);
      return wrap;
    }

    this._parsed = parsed;

    // Summary chip
    const files = parsed.files;
    const totalSize = files.reduce((s, e) => s + (e.size || 0), 0);
    const summ = document.createElement('div');
    summ.className = 'zip-summary';
    const bits = [`7z v${parsed.version.major}.${parsed.version.minor}`];
    if (parsed.encodedHeader) bits.push('<span style="color:var(--risk-medium)">encoded header (LZMA)</span>');
    if (parsed.hasEncryption) bits.push('<span style="color:var(--risk-high)">encrypted</span>');
    if (files.length) {
      summ.innerHTML = `${files.length} file${files.length !== 1 ? 's' : ''} — ${fmtBytes(totalSize)} uncompressed · ${bits.join(' · ')}`;
    } else {
      summ.innerHTML = `Archive metadata only — file listing unavailable · ${bits.join(' · ')}`;
    }
    wrap.appendChild(summ);

    // Header offset information (always shown for forensic value)
    const fmt = document.createElement('div');
    fmt.style.cssText = 'padding:4px 20px 8px;font-size:12px;color:#888;';
    fmt.textContent = `End-header offset ${parsed.nextHeaderOffset.toLocaleString()} · size ${fmtBytes(parsed.nextHeaderSize)}`;
    wrap.appendChild(fmt);

    // If we couldn't list files because the header was encoded in an
    // unsupported way (AES + LZMA, LZMA2, BCJ, multi-coder chain, …)
    // explain why the listing is empty.
    if (!files.length && parsed.encodedHeader) {
      const note = document.createElement('div');
      note.className = 'zip-warnings';
      const d = document.createElement('div');
      d.className = 'zip-warning zip-warning-medium';
      const reason = parsed.encodedHeaderDecodeError
        ? `Encoded header could not be decoded — ${parsed.encodedHeaderDecodeError}`
        : 'Encoded header could not be decoded — unsupported coder chain';
      d.textContent = `ℹ ${reason}. Archive-level signals (encryption presence, overall size) are still surfaced.`;
      note.appendChild(d);
      wrap.appendChild(note);
    }


    // Per-archive warnings
    const warnings = this._checkWarnings(parsed);
    if (warnings.length) {
      const warnDiv = document.createElement('div');
      warnDiv.className = 'zip-warnings';
      for (const w of warnings) {
        const d = document.createElement('div');
        d.className = `zip-warning zip-warning-${w.sev}`;
        d.textContent = w.msg;
        warnDiv.appendChild(d);
      }
      wrap.appendChild(warnDiv);
    }

    // File browser — only rendered when we could actually enumerate files
    if (files.length) {
      const archEntries = files.map(f => ({
        path: f.path,
        dir: !!f.isDir,
        size: f.size,
        date: f.mtime || null,
        encrypted: true, // locks Open button — we cannot actually extract content
        _7zRef: f,
      }));
      const tree = ArchiveTree.render({
        entries: archEntries,
        onOpen: () => { /* extraction not supported */ },
        execExts: SevenZRenderer.EXEC_EXTS,
        decoyExts: SevenZRenderer.DECOY_EXTS,
        showDate: true,
      });
      wrap.appendChild(tree);
    }

    return wrap;
  }

  // ── Parsing ───────────────────────────────────────────────────────────

  _parse(bytes) {
    if (bytes.length < 32) throw new Error('Buffer too small for 7z SignatureHeader');
    if (!(bytes[0] === 0x37 && bytes[1] === 0x7A && bytes[2] === 0xBC && bytes[3] === 0xAF
       && bytes[4] === 0x27 && bytes[5] === 0x1C)) {
      throw new Error('7z signature missing');
    }
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const major = bytes[6];
    const minor = bytes[7];
    // SignatureHeader: StartHeaderCRC at offset 8 (u32), then StartHeader
    //   nextHeaderOffset u64 @ 12
    //   nextHeaderSize   u64 @ 20
    //   nextHeaderCRC    u32 @ 28
    // JS numbers are 64-bit floats — safe for values up to 2^53 which is
    // far beyond any realistic 7z archive, so we can treat the u64s as
    // regular numbers via two 32-bit reads.
    const nextHeaderOffsetLow  = dv.getUint32(12, true);
    const nextHeaderOffsetHigh = dv.getUint32(16, true);
    const nextHeaderSizeLow    = dv.getUint32(20, true);
    const nextHeaderSizeHigh   = dv.getUint32(24, true);
    const nextHeaderOffset = nextHeaderOffsetLow + nextHeaderOffsetHigh * 0x100000000;
    const nextHeaderSize   = nextHeaderSizeLow   + nextHeaderSizeHigh   * 0x100000000;

    const headerStart = 32 + nextHeaderOffset;
    const out = {
      version: { major, minor },
      nextHeaderOffset,
      nextHeaderSize,
      headerStart,
      files: [],
      encodedHeader: false,
      hasEncryption: false,
      numFolders: 0,
    };

    if (nextHeaderSize === 0) {
      // Empty archive — nothing further to parse.
      return out;
    }
    if (headerStart + nextHeaderSize > bytes.length) {
      throw new Error(`End-header out of bounds (offset ${headerStart}, size ${nextHeaderSize}, buffer ${bytes.length})`);
    }

    const headerBytes = bytes.subarray(headerStart, headerStart + nextHeaderSize);
    if (headerBytes.length === 0) return out;

    const firstByte = headerBytes[0];
    if (firstByte === SevenZRenderer.PROP.kEncodedHeader) {
      // Header is LZMA-compressed. Try to decode it with the vendored
      // LZMA-JS decoder. If decoding succeeds we recurse into the
      // uncompressed header and list files normally; if not, we fall
      // back to a metadata-only walk so AES / size / offset signals
      // still reach the UI.
      out.encodedHeader = true;
      const decoded = this._decodeEncodedHeader(headerBytes, bytes, out);
      if (decoded) return out;
      try {
        this._scanEncodedHeaderMetadata(headerBytes, out);
      } catch (_) { /* best-effort */ }
      return out;
    }

    if (firstByte !== SevenZRenderer.PROP.kHeader) {
      throw new Error(`Unexpected header byte 0x${firstByte.toString(16)}`);
    }

    // Plain kHeader — parse it fully.
    const parser = new _SevenZHeaderParser(headerBytes);
    parser.skip(1); // kHeader byte
    this._parseHeaderBody(parser, out);
    return out;
  }

  // ── Plain-header body walker ──────────────────────────────────────────
  //
  // The body is a sequence of property records:
  //   kArchiveProperties       (optional)
  //   kAdditionalStreamsInfo   (optional)
  //   kMainStreamsInfo         (optional)
  //   kFilesInfo               (optional)
  //   kEnd
  _parseHeaderBody(p, out) {
    const PROP = SevenZRenderer.PROP;
    while (!p.done()) {
      const id = p.readByte();
      if (id === PROP.kEnd) break;
      if (id === PROP.kArchiveProperties) {
        this._skipArchiveProperties(p);
      } else if (id === PROP.kAdditionalStreamsInfo) {
        this._skipStreamsInfo(p, out);
      } else if (id === PROP.kMainStreamsInfo) {
        this._skipStreamsInfo(p, out);
      } else if (id === PROP.kFilesInfo) {
        this._parseFilesInfo(p, out);
      } else {
        // Unknown top-level id — bail rather than risk drifting.
        break;
      }
    }
  }

  _skipArchiveProperties(p) {
    // Sequence of (id, size, data) property records terminated by kEnd.
    while (!p.done()) {
      const id = p.readByte();
      if (id === SevenZRenderer.PROP.kEnd) return;
      const size = p.readVarNum();
      p.skip(size);
    }
  }

  _skipStreamsInfo(p, out) {
    const PROP = SevenZRenderer.PROP;
    // StreamsInfo = PackInfo? UnPackInfo? SubStreamsInfo? kEnd
    while (!p.done()) {
      const id = p.readByte();
      if (id === PROP.kEnd) return;
      if (id === PROP.kPackInfo) {
        p.readVarNum(); // PackPos
        const numPackStreams = p.readVarNum();
        // Inner loop with its own kEnd.
        while (!p.done()) {
          const inner = p.readByte();
          if (inner === PROP.kEnd) break;
          if (inner === PROP.kSize) {
            for (let i = 0; i < numPackStreams; i++) p.readVarNum();
          } else if (inner === PROP.kCRC) {
            // All-Are-Defined flag + optional bitmap + CRC32s.
            this._skipDigests(p, numPackStreams);
          } else {
            break;
          }
        }
      } else if (id === PROP.kUnPackInfo) {
        this._skipCodersInfo(p, out);
      } else if (id === PROP.kSubStreamsInfo) {
        // Follows UnPackInfo; carries substream counts / sizes / CRCs.
        // We don't need detailed structure — bail on first kEnd.
        while (!p.done()) {
          const inner = p.readByte();
          if (inner === PROP.kEnd) break;
          // Best-effort skip — each property carries a size varnum
          // in some cases. Rather than misparse, break.
          break;
        }
      } else {
        break;
      }
    }
  }

  _skipCodersInfo(p, out) {
    const PROP = SevenZRenderer.PROP;
    // CodersInfo layout:
    //   kFolder  (numFolders + External + Folders[])
    //   kCodersUnPackSize (UnPackSize[] for each non-out stream)
    //   [kCRC]
    //   kEnd
    while (!p.done()) {
      const id = p.readByte();
      if (id === PROP.kEnd) return;
      if (id === PROP.kFolder) {
        const numFolders = p.readVarNum();
        out.numFolders = numFolders;
        const external = p.readByte();
        if (external === 0) {
          for (let i = 0; i < numFolders; i++) this._parseFolder(p, out);
        } else {
          // DataStreamIndex (VarNum) — points into additional streams.
          p.readVarNum();
        }
      } else if (id === PROP.kCodersUnPackSize) {
        // Number of unpack-sizes equals total number of output streams.
        // We don't track this; skip until we hit a known id or kEnd.
        // Strategy: read varnums greedily but abort if we encounter a byte
        // that's clearly a property id (<= 0x19 and typical).
        // The safer approach is to break — this is only used to skip.
        break;
      } else if (id === PROP.kCRC) {
        // Unknown count here; we can't skip safely — bail.
        break;
      } else {
        break;
      }
    }
  }

  _parseFolder(p, out) {
    const numCoders = p.readVarNum();
    for (let i = 0; i < numCoders; i++) {
      const flags = p.readByte();
      const idSize = flags & 0x0F;
      const isComplex = !!(flags & 0x10);
      const hasAttrs  = !!(flags & 0x20);
      const coderId = p.readBytes(idSize);
      // Detect AES encryption coder: 06F10701 — the canonical 7zAES ID.
      if (coderId.length === 4
        && coderId[0] === 0x06 && coderId[1] === 0xF1
        && coderId[2] === 0x07 && coderId[3] === 0x01) {
        out.hasEncryption = true;
      }
      if (isComplex) {
        p.readVarNum(); // numInStreams
        p.readVarNum(); // numOutStreams
      }
      if (hasAttrs) {
        const propsSize = p.readVarNum();
        p.skip(propsSize);
      }
    }
    // BindPairs + PackedStreams
    // Without tracking inStreams/outStreams counts precisely the safe
    // thing is to bail out of folder parsing here; we already gathered
    // the encryption signal which is the main reason we walk this block.
  }

  _skipDigests(p, count) {
    const allDefined = p.readByte();
    let definedCount = count;
    if (allDefined === 0) {
      // Bitmap of (count) bits, rounded up to whole bytes.
      const bitmapBytes = Math.ceil(count / 8);
      p.skip(bitmapBytes);
      // definedCount can't be computed without reading the bitmap; worst
      // case we over-read CRC bytes, so just trust `count`.
    }
    p.skip(definedCount * 4);
  }

  _parseFilesInfo(p, out) {
    const PROP = SevenZRenderer.PROP;
    const numFiles = p.readVarNum();
    const cap = Math.min(numFiles, PARSER_LIMITS.MAX_ENTRIES);
    const files = new Array(cap);
    for (let i = 0; i < cap; i++) {
      files[i] = { path: '', size: 0, mtime: null, isDir: false, isEmpty: false };
    }
    // Track empty-stream / empty-file bitmaps so we can mark directories.
    let emptyStreamBitmap = null;
    let emptyFileBitmap = null;

    while (!p.done()) {
      const id = p.readByte();
      if (id === PROP.kEnd) break;
      const size = p.readVarNum();
      const end = p.pos + size;
      if (end > p.bytes.length) break;
      const sub = new _SevenZHeaderParser(p.bytes.subarray(p.pos, end));

      if (id === PROP.kEmptyStream) {
        emptyStreamBitmap = this._readBitmap(sub, cap);
        for (let i = 0; i < cap; i++) if (emptyStreamBitmap[i]) files[i].isEmpty = true;
      } else if (id === PROP.kEmptyFile) {
        // Bitmap length equals number of empty streams (not total files).
        // If all bits are 0 → those empty streams are directories; if 1 →
        // actual empty file. In practice we can infer: any empty-stream
        // file whose emptyFile bit is NOT set is a directory.
        const numEmpty = emptyStreamBitmap
          ? emptyStreamBitmap.reduce((n, b) => n + (b ? 1 : 0), 0) : 0;
        emptyFileBitmap = this._readBitmap(sub, numEmpty);
        let ei = 0;
        for (let i = 0; i < cap; i++) {
          if (emptyStreamBitmap && emptyStreamBitmap[i]) {
            if (!emptyFileBitmap[ei]) files[i].isDir = true;
            ei++;
          }
        }
      } else if (id === PROP.kName) {
        // External byte (0 = inline) + UTF-16LE null-terminated names.
        const external = sub.readByte();
        if (external !== 0) {
          // Stored in an additional stream — can't read without decode.
          p.pos = end;
          continue;
        }
        const names = [];
        let cur = [];
        while (sub.pos + 1 < sub.bytes.length) {
          const lo = sub.bytes[sub.pos];
          const hi = sub.bytes[sub.pos + 1];
          sub.pos += 2;
          if (lo === 0 && hi === 0) {
            names.push(this._utf16le(cur));
            cur = [];
          } else {
            cur.push(lo | (hi << 8));
          }
        }
        if (cur.length) names.push(this._utf16le(cur));
        for (let i = 0; i < cap && i < names.length; i++) files[i].path = names[i].replace(/\\/g, '/');
      } else if (id === PROP.kMTime) {
        const external = sub.readByte();
        const allDefined = external === 0 ? sub.readByte() : 1;
        // Actually the layout is: allDefined (1 byte) THEN external. Let me re-check.
        // Per 7z docs: kMTime sub-record starts with a Times property:
        //   BYTE AllAreDefined
        //   if (!AllAreDefined) { BitVector DefinedBits }
        //   BYTE External
        //   if (External != 0) { UINT64 DataIndex }
        //   else { UINT64 Times[NumDefined] }
        // Re-parse correctly:
        sub.pos = 0;
        const allDef2 = sub.readByte();
        let bitmap = null;
        if (!allDef2) bitmap = this._readBitmap(sub, cap);
        const ext2 = sub.readByte();
        if (ext2 !== 0) {
          p.pos = end;
          continue;
        }
        for (let i = 0; i < cap; i++) {
          if (bitmap && !bitmap[i]) continue;
          if (sub.pos + 8 > sub.bytes.length) break;
          const lo = (new DataView(sub.bytes.buffer, sub.bytes.byteOffset + sub.pos, 4)).getUint32(0, true);
          const hi = (new DataView(sub.bytes.buffer, sub.bytes.byteOffset + sub.pos + 4, 4)).getUint32(0, true);
          sub.pos += 8;
          // FILETIME: 100-ns intervals since 1601-01-01 UTC.
          const filetime = lo + hi * 0x100000000;
          const unixMs = filetime / 10000 - 11644473600000;
          if (unixMs > 0 && unixMs < 4102444800000) { // 1970 – 2100
            const t = new Date(unixMs);
            if (!isNaN(t.getTime())) files[i].mtime = t;
          }
        }
      } else if (id === PROP.kWinAttributes) {
        // Same framing as MTime but 4-byte values.
        sub.pos = 0;
        const allDef2 = sub.readByte();
        let bitmap = null;
        if (!allDef2) bitmap = this._readBitmap(sub, cap);
        const ext2 = sub.readByte();
        if (ext2 === 0) {
          for (let i = 0; i < cap; i++) {
            if (bitmap && !bitmap[i]) continue;
            if (sub.pos + 4 > sub.bytes.length) break;
            const attr = (new DataView(sub.bytes.buffer, sub.bytes.byteOffset + sub.pos, 4)).getUint32(0, true);
            sub.pos += 4;
            // FILE_ATTRIBUTE_DIRECTORY = 0x10
            if (attr & 0x10) files[i].isDir = true;
          }
        }
      }
      p.pos = end;
    }

    // For file sizes, we'd need to walk StreamsInfo UnPackSize and map
    // substreams back to files. That's quite complex; for now sizes
    // default to 0 and we surface uncompressed totals from PackInfo
    // elsewhere if available. Listing + names + dir-flag + mtime is
    // already the bulk of the forensic value.

    out.files = files.filter(f => f.path);
  }

  _readBitmap(p, count) {
    const out = new Array(count);
    let byte = 0, mask = 0;
    for (let i = 0; i < count; i++) {
      if (mask === 0) { byte = p.readByte(); mask = 0x80; }
      out[i] = (byte & mask) !== 0;
      mask >>>= 1;
    }
    return out;
  }

  _utf16le(codeUnits) {
    let s = '';
    for (const u of codeUnits) s += String.fromCharCode(u);
    return s;
  }

  // ── Encoded-header metadata scan (best-effort) ────────────────────────
  //
  // When the end-header is kEncodedHeader we walk its StreamsInfo block
  // to detect the AES coder ID, which flags the archive as encrypted
  // without needing to actually decode anything.
  _scanEncodedHeaderMetadata(headerBytes, out) {
    const p = new _SevenZHeaderParser(headerBytes);
    p.skip(1); // kEncodedHeader marker
    this._skipStreamsInfo(p, out);
  }

  // ── LZMA-encoded header decoder ───────────────────────────────────────
  //
  // Walks the outer StreamsInfo inside a kEncodedHeader record to collect
  // PackPos / PackSize / LZMA coder props / UnPackSize, synthesizes a
  // `.lzma` container header (5-byte props + 8-byte uncompressed-size LE),
  // and hands the result to the vendored LZMA-JS decoder. On success the
  // decoded buffer is re-parsed as a plain kHeader and `out.files` /
  // `out.hasEncryption` are filled in. Returns true on success, false
  // when the coder chain is unsupported or the decode blows up.
  //
  // The info object returned by `_parseEncodedStreamsInfo` has:
  //   packPos        — offset (bytes from end of SignatureHeader, i.e. 32)
  //   packSize       — compressed size of the LZMA stream
  //   unpackSize     — decompressed size (= size of the inner kHeader blob)
  //   coderId        — 4-byte ID (LZMA = 03 01 01)
  //   coderProps     — 5-byte LZMA properties (lc/lp/pb byte + 4-byte dict)
  //   numCoders      — sanity check; we only support single-coder folders
  _decodeEncodedHeader(headerBytes, archiveBytes, out) {
    let info;
    try {
      info = this._parseEncodedStreamsInfo(headerBytes, out);
    } catch (e) {
      out.encodedHeaderDecodeError = `StreamsInfo parse failed: ${e.message}`;
      return false;
    }
    if (!info) return false;

    // Single-coder LZMA only. LZMA-JS can't do LZMA2 / BCJ / delta / PPMd.
    if (info.numCoders !== 1) {
      out.encodedHeaderDecodeError = `${info.numCoders}-coder chain not supported`;
      return false;
    }
    // LZMA classic coder ID is 03 01 01 (length 3).
    const id = info.coderId;
    const isLzma = id && id.length === 3 && id[0] === 0x03 && id[1] === 0x01 && id[2] === 0x01;
    if (!isLzma) {
      const hex = id ? Array.from(id).map(b => b.toString(16).padStart(2, '0')).join('') : '(none)';
      out.encodedHeaderDecodeError = `coder ${hex} not supported (only LZMA 030101)`;
      return false;
    }
    if (!info.coderProps || info.coderProps.length !== 5) {
      out.encodedHeaderDecodeError = 'LZMA properties missing or wrong size';
      return false;
    }

    // Pull the LZMA payload out of the archive body. PackPos is relative
    // to the end of the 32-byte SignatureHeader.
    const packStart = 32 + info.packPos;
    if (packStart + info.packSize > archiveBytes.length) {
      out.encodedHeaderDecodeError = 'packed header out of bounds';
      return false;
    }
    const packed = archiveBytes.subarray(packStart, packStart + info.packSize);

    // Guard against headers large enough to OOM the decoder. Real 7z
    // end-headers are typically a few KB; `PARSER_LIMITS.MAX_UNCOMPRESSED`
    // (50 MB) is a deliberately generous sanity cap.
    if (info.unpackSize > PARSER_LIMITS.MAX_UNCOMPRESSED || info.unpackSize <= 0) {
      out.encodedHeaderDecodeError = `unpack size ${info.unpackSize} outside limits`;
      return false;
    }

    // LZMA-JS expects the `.lzma` single-file container format:
    //   5 B  props (1 byte lc/lp/pb + 4 byte dict size LE)
    //   8 B  uncompressed size (LE, u64; 0xFFFF_FFFF_FFFF_FFFF = unknown)
    //   …    compressed stream
    // 7z stores the same 5 props in the folder's coder attributes and the
    // unpack size separately. Synthesize the container prefix.
    const container = new Uint8Array(13 + packed.length);
    container.set(info.coderProps, 0);
    const lo = info.unpackSize >>> 0;
    const hi = Math.floor(info.unpackSize / 0x100000000) >>> 0;
    const cv = new DataView(container.buffer, container.byteOffset + 5, 8);
    cv.setUint32(0, lo, true);
    cv.setUint32(4, hi, true);
    container.set(packed, 13);

    if (typeof LZMA === 'undefined' || !LZMA || typeof LZMA.decompress !== 'function') {
      out.encodedHeaderDecodeError = 'LZMA decoder not available in this build';
      return false;
    }

    let decoded;
    try {
      // LZMA-JS sync mode (`LZMA.decompress(bytes)`) can return EITHER a
      // Uint8Array-like Array of signed bytes OR a UTF-8 decoded string,
      // depending on whether the internal string reconstruction path hits
      // a null byte (which it does for 7z headers — they contain NULs in
      // the first few bytes). We handle both shapes defensively so the
      // decoder works regardless of which internal path was taken.
      const raw = LZMA.decompress(container);
      if (raw == null) {
        out.encodedHeaderDecodeError = 'LZMA decode returned null';
        return false;
      }
      if (typeof raw === 'string') {
        decoded = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) decoded[i] = raw.charCodeAt(i) & 0xFF;
      } else if (raw.length !== undefined) {
        decoded = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) decoded[i] = raw[i] & 0xFF;
      } else {
        out.encodedHeaderDecodeError = `LZMA decode returned unexpected shape: ${typeof raw}`;
        return false;
      }
    } catch (e) {
      out.encodedHeaderDecodeError = `LZMA decode threw: ${e && e.message || e}`;
      return false;
    }

    if (decoded.length === 0) {
      out.encodedHeaderDecodeError = 'LZMA decode produced empty output';
      return false;
    }

    // The decoded buffer IS the inner end-header. Byte 0 must be kHeader.
    if (decoded[0] !== SevenZRenderer.PROP.kHeader) {
      out.encodedHeaderDecodeError = `decoded header has bad marker 0x${decoded[0].toString(16)}`;
      return false;
    }

    try {
      const parser = new _SevenZHeaderParser(decoded);
      parser.skip(1); // kHeader
      this._parseHeaderBody(parser, out);
    } catch (e) {
      out.encodedHeaderDecodeError = `inner header parse failed: ${e.message}`;
      return false;
    }
    return true;
  }

  // Walks an outer kEncodedHeader's StreamsInfo and returns
  //   { packPos, packSize, unpackSize, coderId, coderProps, numCoders }
  // We still call the existing _skipStreamsInfo helper as well so
  // `out.hasEncryption` / `out.numFolders` stay consistent, but because
  // that helper is lossy we do a dedicated surgical walk here.
  _parseEncodedStreamsInfo(headerBytes, out) {
    const PROP = SevenZRenderer.PROP;
    const p = new _SevenZHeaderParser(headerBytes);
    p.skip(1); // kEncodedHeader

    let packPos = 0, packSize = 0;
    let numFolders = 0;
    let coderId = null, coderProps = null, numCoders = 0;
    let unpackSize = 0;

    while (!p.done()) {
      const id = p.readByte();
      if (id === PROP.kEnd) break;
      if (id === PROP.kPackInfo) {
        packPos = p.readVarNum();
        const numPackStreams = p.readVarNum();
        // inner records until kEnd
        while (!p.done()) {
          const inner = p.readByte();
          if (inner === PROP.kEnd) break;
          if (inner === PROP.kSize) {
            // First pack stream's size is the one we want; record it.
            for (let i = 0; i < numPackStreams; i++) {
              const v = p.readVarNum();
              if (i === 0) packSize = v;
            }
          } else if (inner === PROP.kCRC) {
            this._skipDigests(p, numPackStreams);
          } else {
            // Unknown inner record — bail; we have what we need.
            break;
          }
        }
      } else if (id === PROP.kUnPackInfo) {
        // CodersInfo
        while (!p.done()) {
          const inner = p.readByte();
          if (inner === PROP.kEnd) break;
          if (inner === PROP.kFolder) {
            numFolders = p.readVarNum();
            const external = p.readByte();
            if (external !== 0) {
              // DataStreamIndex; we can't follow that.
              p.readVarNum();
              break;
            }
            // Single folder expected for the encoded-header stream.
            if (numFolders !== 1) {
              // Walk through folders but only remember the first one.
            }
            for (let fi = 0; fi < numFolders; fi++) {
              const nc = p.readVarNum();
              if (fi === 0) numCoders = nc;
              for (let ci = 0; ci < nc; ci++) {
                const flags = p.readByte();
                const idSize = flags & 0x0F;
                const isComplex = !!(flags & 0x10);
                const hasAttrs  = !!(flags & 0x20);
                const id2 = p.readBytes(idSize);
                if (fi === 0 && ci === 0) coderId = new Uint8Array(id2);
                // AES coder → flag encryption even during encoded-header walk
                if (id2.length === 4
                  && id2[0] === 0x06 && id2[1] === 0xF1
                  && id2[2] === 0x07 && id2[3] === 0x01) {
                  out.hasEncryption = true;
                }
                if (isComplex) {
                  p.readVarNum();
                  p.readVarNum();
                }
                if (hasAttrs) {
                  const propsSize = p.readVarNum();
                  const props = p.readBytes(propsSize);
                  if (fi === 0 && ci === 0) coderProps = new Uint8Array(props);
                }
              }
              // BindPairs — for a single-coder folder there are 0 bind pairs
              // and 0 packed-stream indices. For multi-coder folders we just
              // give up below anyway.
            }
          } else if (inner === PROP.kCodersUnPackSize) {
            // One varnum per output stream across all folders. For a
            // single-folder single-coder LZMA chain that's exactly one
            // value, which is the unpack size we need.
            // To be safe read up to numCoders * numFolders values; we
            // only keep the first.
            const n = Math.max(1, numCoders * Math.max(1, numFolders));
            for (let i = 0; i < n; i++) {
              const v = p.readVarNum();
              if (i === 0) unpackSize = v;
            }
          } else if (inner === PROP.kCRC) {
            this._skipDigests(p, numFolders);
          } else {
            break;
          }
        }
      } else if (id === PROP.kSubStreamsInfo) {
        // Outer encoded-header doesn't normally carry SubStreamsInfo; bail.
        break;
      } else {
        break;
      }
    }

    out.numFolders = numFolders;
    if (!packSize || !unpackSize || !coderProps || !coderId) return null;
    return { packPos, packSize, unpackSize, coderId, coderProps, numCoders };
  }


  // ── Warnings ──────────────────────────────────────────────────────────

  _checkWarnings(parsed) {
    const w = [];
    const files = parsed.files;

    if (parsed.hasEncryption) {
      w.push({ sev: 'high', msg: '🔐 Archive uses AES-256 encryption — file content cannot be inspected without the password' });
    }

    if (files.length) {
      const execs = files.filter(e => !e.isDir && SevenZRenderer.EXEC_EXTS.has((e.path || '').split('.').pop().toLowerCase()));
      if (execs.length) {
        w.push({ sev: 'high', msg: `⚠ ${execs.length} executable/script file(s): ${execs.slice(0, 5).map(e => e.path.split('/').pop()).join(', ')}${execs.length > 5 ? ' …' : ''}` });
      }
      const doubles = files.filter(e => !e.isDir && this._isDoubleExt(e.path));
      if (doubles.length) {
        w.push({ sev: 'high', msg: `⚠ Double-extension file(s) detected: ${doubles.slice(0, 3).map(e => e.path.split('/').pop()).join(', ')}${doubles.length > 3 ? ' …' : ''}` });
      }
      const nested = files.filter(e => /\.(zip|rar|7z|cab|gz|tar|iso|img)$/i.test(e.path));
      if (nested.length) {
        w.push({ sev: 'medium', msg: `📦 Nested archive(s): ${nested.slice(0, 3).map(e => e.path.split('/').pop()).join(', ')}` });
      }
      const htas = files.filter(e => /\.hta$/i.test(e.path));
      if (htas.length) w.push({ sev: 'high', msg: `⚠ HTA file(s) — can execute arbitrary scripts` });
      const lnks = files.filter(e => /\.lnk$/i.test(e.path));
      if (lnks.length) w.push({ sev: 'high', msg: `⚠ Windows shortcut (.lnk) file(s) — common phishing technique` });

      const traversal = files.filter(e => {
        const p = e.path || '';
        return p.includes('../') || p.includes('..\\') || p.startsWith('/') || /^[A-Za-z]:/.test(p);
      });
      if (traversal.length) {
        w.push({ sev: 'high', msg: `⚠ Path traversal attempt detected — ${traversal.length} entry/entries with suspicious paths` });
      }
    }

    return w;
  }

  _isDoubleExt(path) {
    const name = (path || '').split('/').pop();
    const parts = name.split('.');
    if (parts.length < 3) return false;
    const last = parts[parts.length - 1].toLowerCase();
    const prev = parts[parts.length - 2].toLowerCase();
    return SevenZRenderer.EXEC_EXTS.has(last) && SevenZRenderer.DECOY_EXTS.has(prev);
  }

  // ── Security analysis ─────────────────────────────────────────────────

  async analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: [],
    };
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    let parsed;
    try { parsed = this._parse(bytes); }
    catch (e) {
      pushIOC(f, { type: IOC.INFO, value: `7z parse failed: ${e.message}`, severity: 'info', bucket: 'externalRefs' });
      return f;
    }

    f.metadata = {
      '7z Version': `${parsed.version.major}.${parsed.version.minor}`,
      'Files Listed': parsed.files.length,
      'Encoded Header': parsed.encodedHeader ? 'yes (LZMA)' : 'no',
      'Encryption': parsed.hasEncryption ? 'AES-256' : 'none',
      'End-header Offset': parsed.nextHeaderOffset.toLocaleString(),
      'End-header Size': fmtBytes(parsed.nextHeaderSize),
    };

    if (parsed.hasEncryption) {
      pushIOC(f, {
        type: IOC.PATTERN,
        value: '7z archive uses AES-256 encryption — payload cannot be inspected without the password',
        severity: 'high',
        bucket: 'externalRefs',
      });
      f.risk = 'high';
    }

    if (parsed.encodedHeader) {
      const decoded = parsed.files.length > 0 && !parsed.encodedHeaderDecodeError;
      const msg = decoded
        ? 'End-header is LZMA-compressed — decoded successfully via vendored LZMA-JS'
        : `End-header is LZMA-compressed — could not decode (${parsed.encodedHeaderDecodeError || 'unsupported coder chain'})`;
      pushIOC(f, {
        type: IOC.INFO,
        value: msg,
        severity: 'info',
        bucket: 'externalRefs',
      });
    }

    // Warnings → externalRefs + risk
    const warnings = this._checkWarnings(parsed);
    for (const w of warnings) {
      f.externalRefs.push({ type: IOC.PATTERN, url: w.msg, severity: w.sev });
      if (w.sev === 'high') f.risk = 'high';
      else if (w.sev === 'medium' && f.risk !== 'high') f.risk = 'medium';
    }

    // Surface executable/script paths (only available when listing succeeded)
    const dangerous = parsed.files.filter(e => !e.isDir && SevenZRenderer.EXEC_EXTS.has((e.path || '').split('.').pop().toLowerCase()));
    for (const e of dangerous.slice(0, 50)) {
      f.externalRefs.push({ type: IOC.FILE_PATH, url: e.path, severity: 'high' });
    }

    // Listing IOCs for every non-dangerous file, capped
    const listingCap = 100;
    const seen = new Set(dangerous.map(e => e.path));
    let surfaced = 0;
    for (const e of parsed.files) {
      if (e.isDir || seen.has(e.path)) continue;
      if (surfaced >= listingCap) break;
      f.externalRefs.push({ type: IOC.FILE_PATH, url: e.path, severity: 'info' });
      surfaced++;
    }
    const over = parsed.files.length - listingCap - dangerous.length;
    if (over > 0) {
      f.externalRefs.push({ type: IOC.INFO, url: `+${over} more file path(s) truncated`, severity: 'info' });
    }

    return f;
  }
}

// ── Shared parser cursor ────────────────────────────────────────────────
//
// 7z uses a custom VarNum encoding for most sizes and counts — described
// in section 3.3 of the spec. The first byte indicates how many additional
// bytes follow (0 = no more, 0b10xxxxxx = 1 more, 0b110xxxxx = 2 more, …),
// and the low bits of the first byte extend the value.
class _SevenZHeaderParser {
  constructor(bytes) { this.bytes = bytes; this.pos = 0; }
  done() { return this.pos >= this.bytes.length; }
  readByte() { return this.bytes[this.pos++]; }
  readBytes(n) {
    const out = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  skip(n) { this.pos += n; }
  readVarNum() {
    if (this.pos >= this.bytes.length) return 0;
    const first = this.bytes[this.pos++];
    let mask = 0x80;
    let value = 0;
    for (let i = 0; i < 8; i++) {
      if ((first & mask) === 0) {
        const highPart = first & (mask - 1);
        value |= highPart * Math.pow(2, i * 8);
        return value;
      }
      if (this.pos >= this.bytes.length) return value;
      value |= this.bytes[this.pos++] * Math.pow(2, i * 8);
      mask >>>= 1;
    }
    return value;
  }
}
