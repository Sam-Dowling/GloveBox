'use strict';
// ════════════════════════════════════════════════════════════════════════════
// rar-renderer.js — RAR archive analyser (listing-only)
//
// Parses both RAR v4 ("Rar!\x1A\x07\x00") and RAR v5 ("Rar!\x1A\x07\x01\x00")
// headers to enumerate file entries, their sizes, timestamps, and the
// compression / encryption flags. Extraction is NOT supported:
//
//   • RAR's compression (RAR, RAR5) is a proprietary LZSS / PPMd variant
//     with no open-source pure-JS decoder small enough to ship offline.
//   • Even the listing pass surfaces more forensic signal than most
//     reverse-engineered samples need: file names, sizes, exec / script
//     classifications, encrypted-header detection, solid-mode flag, and
//     multi-volume continuation warnings.
//
// Every entry is marked `encrypted: true` in the ArchiveTree view so the
// Open button is suppressed — users can still inspect the listing and
// the per-archive analysis. A banner at the top of the view explains why.
//
// Emits the usual archive signals (exec/script/HTA/LNK content, double
// extensions, nested archives, path-traversal patterns, encrypted
// headers, solid / multi-volume flags).
//
// Depends on: constants.js (IOC, PARSER_LIMITS, escHtml, fmtBytes,
//             pushIOC), ArchiveTree (archive-tree.js)
// ════════════════════════════════════════════════════════════════════════════
class RarRenderer {

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

  // ── Render ────────────────────────────────────────────────────────────

  async render(buffer, fileName) {
    const wrap = document.createElement('div');
    wrap.className = 'zip-view';
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>RAR Archive</strong> — Loupe lists RAR contents for forensic review but cannot decompress RAR-compressed data (proprietary LZSS/PPMd). File names, sizes, timestamps, and flags are authoritative; body content cannot be extracted in-browser.';
    wrap.appendChild(banner);

    let parsed;
    try {
      parsed = this._parse(bytes);
    } catch (e) {
      const err = document.createElement('div');
      err.style.cssText = 'padding:12px 20px;color:var(--risk-high);';
      err.textContent = `⚠ Failed to parse RAR archive: ${e.message}`;
      wrap.appendChild(err);
      return wrap;
    }

    this._parsed = parsed;

    // Summary chip
    const files = parsed.files.length;
    const totalSize = parsed.files.reduce((s, e) => s + (e.size || 0), 0);
    const totalPacked = parsed.files.reduce((s, e) => s + (e.packedSize || 0), 0);
    const summ = document.createElement('div');
    summ.className = 'zip-summary';
    const bits = [`RAR ${parsed.version}`];
    if (parsed.solid) bits.push('<span style="color:var(--risk-med)">solid</span>');
    if (parsed.encryptedHeaders) bits.push('<span style="color:var(--risk-high)">encrypted headers</span>');
    if (parsed.multiVolume) bits.push('<span style="color:var(--risk-med)">multi-volume</span>');
    if (parsed.recoveryRecord) bits.push('recovery record');
    summ.innerHTML = `${files} file${files !== 1 ? 's' : ''} — ${fmtBytes(totalSize)} uncompressed` +
      (totalPacked ? ` / ${fmtBytes(totalPacked)} packed` : '') +
      ` · ${bits.join(' · ')}`;
    wrap.appendChild(summ);

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

    // File browser — every entry marked `encrypted: true` to suppress
    // the Open button (we cannot actually extract RAR-compressed data).
    const archEntries = parsed.files.map(f => ({
      path: f.path,
      dir: !!f.isDir,
      size: f.size,
      compressedSize: f.packedSize,
      date: f.date || null,
      encrypted: true, // locks the Open button per-entry
      _rarRef: f,
    }));

    const tree = ArchiveTree.render({
      entries: archEntries,
      onOpen: () => { /* extraction not supported */ },
      execExts: RarRenderer.EXEC_EXTS,
      decoyExts: RarRenderer.DECOY_EXTS,
      showCompressed: true,
      showDate: true,
    });
    wrap.appendChild(tree);

    return wrap;
  }

  // ── Parsing ───────────────────────────────────────────────────────────

  _parse(bytes) {
    if (bytes.length < 8) throw new Error('Buffer too small for RAR header');
    if (bytes[0] !== 0x52 || bytes[1] !== 0x61 || bytes[2] !== 0x72 || bytes[3] !== 0x21
      || bytes[4] !== 0x1A || bytes[5] !== 0x07) {
      throw new Error('RAR signature missing');
    }
    // Byte 6: 0x00 = RAR 1.5 – 4.x ; 0x01 = RAR 5.x (followed by 0x00).
    if (bytes[6] === 0x00) {
      return this._parseV4(bytes);
    } else if (bytes[6] === 0x01) {
      if (bytes[7] !== 0x00) throw new Error('Malformed RAR5 signature');
      return this._parseV5(bytes);
    } else {
      throw new Error(`Unknown RAR variant byte 0x${bytes[6].toString(16)}`);
    }
  }

  // ── RAR4 parser ───────────────────────────────────────────────────────
  //
  // RAR4 block layout:
  //   HEAD_CRC   u16
  //   HEAD_TYPE  u8   (0x73 main, 0x74 file, 0x7A newsub, 0x7B end, …)
  //   HEAD_FLAGS u16
  //   HEAD_SIZE  u16
  //   [ADD_SIZE  u32] — present if flags & 0x8000 (LHD_LONG_BLOCK)
  //   … type-specific body …
  //
  // For FILE blocks the body carries packed/unpacked sizes, name length,
  // file attributes, and the filename. We walk until we hit HEAD_TYPE
  // 0x7B (end-of-archive) or run out of buffer.
  _parseV4(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    let off = 7; // skip the 7-byte marker block
    const files = [];
    let solid = false;
    let multiVolume = false;
    let encryptedHeaders = false;
    let recoveryRecord = false;
    let passedMainHeader = false;
    // H5: aggregate archive-expansion budget shared across the recursive
    // drill-down chain (top-level ZIP → JAR → MSIX → 7z → RAR…). When
    // exhausted, we stop appending entries and surface the cap upstream.
    const aggBudget = (typeof window !== 'undefined' && window.app)
      ? window.app._archiveBudget
      : null;
    let aggExhausted = false;


    const MAX_BLOCKS = PARSER_LIMITS.MAX_ENTRIES * 2;
    for (let iter = 0; iter < MAX_BLOCKS; iter++) {
      if (off + 7 > bytes.length) break;
      const _headCrc = dv.getUint16(off, true);
      const headType = bytes[off + 2];
      const headFlags = dv.getUint16(off + 3, true);
      const headSize = dv.getUint16(off + 5, true);
      if (headSize < 7) break; // malformed
      let addSize = 0;
      // Body begins immediately after the 7-byte header prefix. For FILE_HEAD
      // blocks the generic ADD_SIZE field and the body's first field PACK_SIZE
      // occupy the SAME 4 bytes at off+7 (see unrar TechInfo.txt §3.3 "File
      // header" — PACK_SIZE is ADD_SIZE for FILE blocks). Advancing bodyOff
      // to off+11 would shift every subsequent read by 4 bytes and make
      // NAME_SIZE land on garbage, silently truncating the listing.
      const bodyOff = off + 7;
      if (headFlags & 0x8000) {
        if (off + 11 > bytes.length) break;
        addSize = dv.getUint32(off + 7, true); // used only for blockEnd math below
      }
      const blockEnd = off + headSize + addSize;
      if (blockEnd > bytes.length || headSize > 0x10000) break;

      if (headType === 0x73) {
        // MAIN_HEAD
        passedMainHeader = true;
        if (headFlags & 0x0001) multiVolume = true;    // MHD_VOLUME
        if (headFlags & 0x0008) solid = true;          // MHD_SOLID
        if (headFlags & 0x0080) encryptedHeaders = true; // MHD_PASSWORD (headers+data)
        if (headFlags & 0x0002) ; // MHD_COMMENT
        // RR flag (recovery record) is 0x0040 on older versions.
        if (headFlags & 0x0040) recoveryRecord = true;
      } else if (headType === 0x74) {
        // FILE_HEAD — bodyOff points at the file-header body.
        //   u32 PACK_SIZE     — already the low 32 bits of add_size usually
        //   u32 UNP_SIZE
        //   u8  HOST_OS
        //   u32 FILE_CRC
        //   u32 FTIME (DOS)
        //   u8  UNP_VER
        //   u8  METHOD
        //   u16 NAME_SIZE
        //   u32 ATTR
        //   [u32 HIGH_PACK_SIZE] if LHD_LARGE (0x0100)
        //   [u32 HIGH_UNP_SIZE ] if LHD_LARGE
        //   name[NAME_SIZE]
        //   [SALT (8 bytes)] if LHD_SALT (0x0400)
        //   [EXT_TIME] if LHD_EXTTIME (0x1000)
        if (bodyOff + 25 > bytes.length) break;
        let bp = bodyOff;
        let packSize = dv.getUint32(bp, true); bp += 4;
        let unpSize  = dv.getUint32(bp, true); bp += 4;
        const hostOs   = bytes[bp]; bp += 1;
        /* const fileCrc  = */ dv.getUint32(bp, true); bp += 4;
        const ftime    = dv.getUint32(bp, true); bp += 4;
        /* const unpVer = */ bytes[bp]; bp += 1;
        const method   = bytes[bp]; bp += 1;
        const nameSize = dv.getUint16(bp, true); bp += 2;
        const attr     = dv.getUint32(bp, true); bp += 4;
        if (headFlags & 0x0100) { // LHD_LARGE
          if (bp + 8 > bytes.length) break;
          const highPack = dv.getUint32(bp, true); bp += 4;
          const highUnp  = dv.getUint32(bp, true); bp += 4;
          packSize += highPack * 0x100000000;
          unpSize  += highUnp  * 0x100000000;
        }
        if (bp + nameSize > bytes.length) break;
        const nameBytes = bytes.subarray(bp, bp + nameSize);
        let name;
        if (headFlags & 0x0200) { // LHD_UNICODE — dual ASCII/Unicode encoding
          const nul = nameBytes.indexOf(0);
          if (nul >= 0) {
            name = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes.subarray(0, nul));
            // Remainder is a compressed Unicode table; fall back to ASCII head.
          } else {
            name = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes);
          }
        } else {
          name = new TextDecoder('utf-8', { fatal: false }).decode(nameBytes);
        }
        const path = name.replace(/\\/g, '/');
        const encrypted = !!(headFlags & 0x0004); // LHD_PASSWORD
        // RAR4 LHD_DIRECTORY is flags & 0xE0 === 0xE0 (equality, not
        // "any bit set in the mask" — the lower dictionary-size bits
        // share 0xE0). The Windows DIR attribute is platform-specific
        // so we accept either signal.
        const isDir = ((headFlags & 0xE0) === 0xE0) && !!(attr & 0x10);
        // Fallback for RAR4 dirs on non-Windows hosts: METHOD=0x30
        // (stored) + size=0 + DIR attribute bit.
        const dir2 = (method === 0x30 && unpSize === 0 && !!(attr & 0x10));
        const date = this._dosDate(ftime);
        if (encrypted) encryptedHeaders = encryptedHeaders || encrypted;
        // H5: gate the push against the shared aggregate budget. The
        // per-archive `MAX_ENTRIES` cap below still fires for a single
        // pathological RAR; this consult fires when the *recursion*
        // through nested archives has already burned through the
        // shared budget.
        if (aggBudget && !aggBudget.consume(1, unpSize | 0)) {
          aggExhausted = true;
          break;
        }
        files.push({
          path,
          size: unpSize,
          packedSize: packSize,
          date,
          method,
          attr,
          hostOs,
          encrypted,
          isDir: dir2 || isDir,
        });
        if (files.length >= PARSER_LIMITS.MAX_ENTRIES) break;

      } else if (headType === 0x7B) {
        // END_ARC
        break;
      } else if (!passedMainHeader && headType !== 0x72) {
        // Something is wrong — expected MAIN before FILE.
        // (0x72 is MARK_HEAD which we already skipped via the offset.)
      }

      off = blockEnd;
      if (off <= 0 || off > bytes.length) break;
    }

    return {
      version: '4',
      solid, multiVolume, encryptedHeaders, recoveryRecord,
      files,
      aggExhausted,
      aggReason: aggExhausted && aggBudget ? aggBudget.reason : '',
    };
  }


  // ── RAR5 parser ───────────────────────────────────────────────────────
  //
  // RAR5 uses vuint-encoded fields throughout. Each block:
  //   vuint header_crc32
  //   vuint header_size          — size of the rest of the header
  //   vuint header_type          — 1=main, 2=file, 3=service, 4=encryption, 5=end
  //   vuint header_flags
  //   [vuint extra_area_size]    — if flags & 0x0001
  //   [vuint data_size]          — if flags & 0x0002
  //   … type-specific body …
  //   [extra_area ...]
  //   [data ...]
  _parseV5(bytes) {
    let off = 8; // skip 8-byte RAR5 signature
    const files = [];
    let solid = false;
    let multiVolume = false;
    let encryptedHeaders = false;
    let recoveryRecord = false;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    // H5: aggregate archive-expansion budget — see `_parseV4` for context.
    const aggBudget = (typeof window !== 'undefined' && window.app)
      ? window.app._archiveBudget
      : null;
    let aggExhausted = false;


    const readVuint = (p) => {
      let shift = 0, result = 0, count = 0;
      while (p < bytes.length && count < 10) {
        const b = bytes[p++];
        result += (b & 0x7F) * Math.pow(2, shift);
        if ((b & 0x80) === 0) return { value: result, pos: p };
        shift += 7;
        count++;
      }
      return { value: result, pos: p };
    };

    const MAX_BLOCKS = PARSER_LIMITS.MAX_ENTRIES * 2;
    for (let iter = 0; iter < MAX_BLOCKS; iter++) {
      if (off + 7 > bytes.length) break;
      // header_crc32 (4 raw bytes)
      off += 4;
      let v = readVuint(off); const headerSize = v.value; off = v.pos;
      const headerStart = off;
      if (headerSize === 0 || off + headerSize > bytes.length) break;
      v = readVuint(off); const headerType = v.value; off = v.pos;
      v = readVuint(off); const headerFlags = v.value; off = v.pos;
      // RAR5 header flags 0x0001 / 0x0002 carry extra-area-size and
      // data-size vuints that we read structurally to advance `off`
      // but don't otherwise use here.
      let dataSize = 0;
      if (headerFlags & 0x0001) { v = readVuint(off); off = v.pos; }
      if (headerFlags & 0x0002) { v = readVuint(off); dataSize = v.value; off = v.pos; }

      if (headerType === 1) {
        // Main archive header.
        //   vuint archive_flags
        //   [vuint volume_number] if flags & 0x0002
        v = readVuint(off); const archFlags = v.value; off = v.pos;
        if (archFlags & 0x0001) multiVolume = true;
        if (archFlags & 0x0004) solid = true;
        if (archFlags & 0x0008) recoveryRecord = true;
      } else if (headerType === 4) {
        // Encryption header — all subsequent headers are encrypted.
        encryptedHeaders = true;
      } else if (headerType === 2 || headerType === 3) {
        // File or service header — both share the same layout. Services
        // carry things like STM (data stream), CMT (comment), RR, QO etc.
        // We surface FILE headers only.
        v = readVuint(off); const fileFlags = v.value; off = v.pos;
        v = readVuint(off); const unpSize    = v.value; off = v.pos;
        v = readVuint(off); /* attributes  */ off = v.pos;
        let mtime = 0;
        if (fileFlags & 0x0002) {
          // mtime present — may be unix (flags & 0x0001 of compression_info? no,
          // that's controlled by its own flag in common layout. RAR5 uses
          // flag 0x0002 for presence, and a separate "unix time" toggle at
          // the field level which is normally on in modern RAR). We'll just
          // treat it as a unix timestamp; if it looks nonsensical, discard.
          if (off + 4 > bytes.length) break;
          mtime = dv.getUint32(off, true);
          off += 4;
        }
        if (fileFlags & 0x0004) off += 4; // CRC32 present
        v = readVuint(off); /* compression info */ off = v.pos;
        v = readVuint(off); /* host OS        */ off = v.pos;
        v = readVuint(off); const nameLength = v.value; off = v.pos;
        if (off + nameLength > bytes.length) break;
        const name = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(off, off + nameLength));
        off += nameLength;

        if (headerType === 2) {
          // Actual file entry
          const path = name.replace(/\\/g, '/');
          const isDir = !!(fileFlags & 0x0001);
          let date = null;
          if (mtime) {
            const t = new Date(mtime * 1000);
            if (!isNaN(t.getTime()) && t.getFullYear() > 1980 && t.getFullYear() < 2200) date = t;
          }
          // H5: shared aggregate budget consult before push (see _parseV4).
          if (aggBudget && !aggBudget.consume(1, unpSize | 0)) {
            aggExhausted = true;
            break;
          }
          files.push({
            path,
            size: unpSize,
            packedSize: dataSize,
            date,
            isDir,
            encrypted: false, // determined by encryption extra record; listed separately
          });
          if (files.length >= PARSER_LIMITS.MAX_ENTRIES) break;
        }

      } else if (headerType === 5) {
        // End of archive
        break;
      }

      // Advance past the rest of the header + data payload.
      const headerEnd = headerStart + headerSize;
      off = headerEnd + dataSize;
      if (off <= 0 || off > bytes.length) break;
    }

    return {
      version: '5',
      solid, multiVolume, encryptedHeaders, recoveryRecord,
      files,
      aggExhausted,
      aggReason: aggExhausted && aggBudget ? aggBudget.reason : '',
    };
  }


  // ── Helpers ───────────────────────────────────────────────────────────

  _dosDate(ftime) {
    if (!ftime) return null;
    try {
      const dosDate = (ftime >>> 16) & 0xFFFF;
      const dosTime = ftime & 0xFFFF;
      const y = ((dosDate >> 9) & 0x7F) + 1980;
      const mo = ((dosDate >> 5) & 0x0F) || 1;
      const d  = (dosDate & 0x1F) || 1;
      const h  = (dosTime >> 11) & 0x1F;
      const mi = (dosTime >> 5) & 0x3F;
      const s  = (dosTime & 0x1F) * 2;
      const t = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
      if (isNaN(t.getTime())) return null;
      return t;
    } catch (_) { return null; }
  }

  _checkWarnings(parsed) {
    const w = [];
    const files = parsed.files;

    if (parsed.encryptedHeaders) {
      w.push({ sev: 'high', msg: '🔐 Encrypted archive — file content cannot be inspected; only the listing (if unencrypted) is available' });
    }
    if (parsed.multiVolume) {
      w.push({ sev: 'medium', msg: '📦 Multi-volume archive — this is only one part of a larger set; payload is incomplete on its own' });
    }
    if (parsed.solid) {
      w.push({ sev: 'info', msg: 'ℹ Solid archive — files compressed together as a single stream (common for delivery of coordinated payloads)' });
    }

    const execs = files.filter(e => !e.isDir && RarRenderer.EXEC_EXTS.has((e.path || '').split('.').pop().toLowerCase()));
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

    if (parsed.aggExhausted) {
      w.push({ sev: 'info', msg: `ℹ ${parsed.aggReason || 'Aggregate archive-expansion budget exhausted — listing truncated'}` });
    }

    return w;
  }


  _isDoubleExt(path) {
    const name = (path || '').split('/').pop();
    const parts = name.split('.');
    if (parts.length < 3) return false;
    const last = parts[parts.length - 1].toLowerCase();
    const prev = parts[parts.length - 2].toLowerCase();
    return RarRenderer.EXEC_EXTS.has(last) && RarRenderer.DECOY_EXTS.has(prev);
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
      pushIOC(f, { type: IOC.INFO, value: `RAR parse failed: ${e.message}`, severity: 'info', bucket: 'externalRefs' });
      return f;
    }

    f.metadata = {
      'RAR Version': parsed.version,
      'Files': parsed.files.length,
      'Solid': parsed.solid ? 'yes' : 'no',
      'Multi-volume': parsed.multiVolume ? 'yes' : 'no',
      'Encrypted Headers': parsed.encryptedHeaders ? 'yes' : 'no',
      'Recovery Record': parsed.recoveryRecord ? 'yes' : 'no',
    };

    if (parsed.encryptedHeaders) {
      pushIOC(f, {
        type: IOC.PATTERN,
        value: 'RAR archive has encrypted headers — file content cannot be inspected without the password',
        severity: 'high',
        bucket: 'externalRefs',
      });
      escalateRisk(f, 'high');
    }
    if (parsed.multiVolume) {
      pushIOC(f, {
        type: IOC.PATTERN,
        value: 'Multi-volume RAR — this volume is part of a larger set; contents may be incomplete on its own',
        severity: 'medium',
        bucket: 'externalRefs',
      });
      if (f.risk === 'low') escalateRisk(f, 'medium');
    }
    if (parsed.solid) {
      pushIOC(f, {
        type: IOC.INFO,
        value: 'Solid archive — all files compressed together as a single stream (extraction requires sequential decode)',
        severity: 'info',
        bucket: 'externalRefs',
      });
    }

    // Warnings → externalRefs + risk
    const warnings = this._checkWarnings(parsed);
    for (const w of warnings) {
      f.externalRefs.push({ type: IOC.PATTERN, url: w.msg, severity: w.sev });
      if (w.sev === 'high') escalateRisk(f, 'high');
      else if (w.sev === 'medium' && f.risk !== 'high') escalateRisk(f, 'medium');
    }

    // H5: surface aggregate-budget exhaustion as a clean IOC.INFO row so
    // sidebar filtering can pick it up without trawling the PATTERN
    // warning blob.
    if (parsed.aggExhausted) {
      pushIOC(f, {
        type: IOC.INFO,
        value: parsed.aggReason || 'Aggregate archive-expansion budget exhausted — listing truncated',
        severity: 'info',
        bucket: 'externalRefs',
      });
    }


    // Surface executable/script paths as FILE_PATH IOCs
    const dangerous = parsed.files.filter(e => !e.isDir && RarRenderer.EXEC_EXTS.has((e.path || '').split('.').pop().toLowerCase()));
    if (dangerous.length) {
      for (const e of dangerous.slice(0, 50)) {
        f.externalRefs.push({ type: IOC.FILE_PATH, url: e.path, severity: 'high' });
      }
    }

    // Listing: path IOCs for every file, capped so pathological archives
    // don't flood the sidebar.
    const listingCap = 100;
    const seen = new Set(dangerous.map(e => e.path));
    let surfaced = 0;
    for (const e of parsed.files) {
      if (e.isDir) continue;
      if (seen.has(e.path)) continue;
      if (surfaced >= listingCap) break;
      f.externalRefs.push({ type: IOC.FILE_PATH, url: e.path, severity: 'info' });
      surfaced++;
    }
    if (parsed.files.length > listingCap + dangerous.length) {
      f.externalRefs.push({ type: IOC.INFO, url: `+${parsed.files.length - listingCap - dangerous.length} more file path(s) truncated`, severity: 'info' });
    }

    return f;
  }
}
