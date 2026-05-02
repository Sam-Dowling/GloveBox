'use strict';
// ════════════════════════════════════════════════════════════════════════════
// cab-renderer.js — Microsoft Cabinet (.cab / MSCF) archive analyser
//
// Parses the Microsoft Cabinet File Format (MS-CAB):
//
//   CFHEADER ─► CFFOLDER[] ─► CFFILE[] ─► CFDATA[]
//
// and renders the file listing through the shared `ArchiveTree` component
// (identical UI to zip / msix / jar / pkg). Supported extraction:
//
//   • Uncompressed (typeCompress = 0) — raw copy
//   • MSZIP        (typeCompress = 1) — 'CK' + deflate, via pako
//   • LZX / Quantum (2, 3) — listing only; extraction surface marks entries
//                            as "compressed data — extraction not supported"
//
// No decompressor is ever invoked during the listing pass, so a malicious
// archive declaring gigabytes of decompressed output cannot blow the
// budget from the file-browser alone. Per-entry decompression only runs
// on explicit click, and is capped by PARSER_LIMITS.MAX_UNCOMPRESSED.
//
// Emits the usual archive signals (exec/script/HTA/LNK content, double
// extensions, macOS .app bundles, path-traversal / "Zip Slip" style
// paths, split cabinets, reserved-field presence).
//
// Depends on: constants.js (IOC, PARSER_LIMITS, escHtml, fmtBytes,
//             pushIOC), ArchiveTree (archive-tree.js), pako (vendor)
// ════════════════════════════════════════════════════════════════════════════
class CabRenderer {

  // Same classifier sets as ZipRenderer — keep these in lock-step so the
  // sidebar grading is consistent across every archive renderer.
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
    banner.innerHTML = '<strong>Cabinet (MSCF) Archive</strong> — click any file to extract it for analysis. Uncompressed and MSZIP entries are supported; LZX / Quantum content is listed but cannot be decompressed in-browser.';
    wrap.appendChild(banner);

    let parsed;
    try {
      parsed = this._parse(bytes);
    } catch (e) {
      const err = document.createElement('div');
      err.style.cssText = 'padding:12px 20px;color:var(--risk-high);';
      err.textContent = `⚠ Failed to parse cabinet: ${e.message}`;
      wrap.appendChild(err);
      return wrap;
    }

    this._parsed = parsed;

    // Summary chip
    const files = parsed.files.length;
    const totalSize = parsed.files.reduce((s, e) => s + (e.size || 0), 0);
    const summ = document.createElement('div');
    summ.className = 'zip-summary';
    const flagsBits = [];
    if (parsed.header.prevCabinet) flagsBits.push(`continued from ${escHtml(parsed.header.prevCabinet)}`);
    if (parsed.header.nextCabinet) flagsBits.push(`continues in ${escHtml(parsed.header.nextCabinet)}`);
    summ.innerHTML = `${files} file${files !== 1 ? 's' : ''}, ${parsed.folders.length} folder descriptor${parsed.folders.length !== 1 ? 's' : ''} — ${fmtBytes(totalSize)} uncompressed` +
      (flagsBits.length ? ` · <span style="color:var(--risk-med)">${flagsBits.join(', ')}</span>` : '');
    wrap.appendChild(summ);

    // Per-folder compression / reserve bits
    if (parsed.folders.length) {
      const fmt = document.createElement('div');
      fmt.style.cssText = 'padding:4px 20px 8px;font-size:12px;color:#888;';
      const compSummary = parsed.folders
        .map((fd, i) => `folder ${i}: ${fd.compressionLabel}`)
        .slice(0, 4)
        .join(' · ');
      fmt.textContent = `Compression — ${compSummary}${parsed.folders.length > 4 ? ' …' : ''}`;
      wrap.appendChild(fmt);
    }

    // Per-archive warnings (reuses the same grammar as the ZIP renderer)
    const warnings = this._checkWarnings(parsed.files);
    if (parsed.aggExhausted) {
      const aggBudget = (typeof window !== 'undefined' && window.app)
        ? window.app._archiveBudget : null;
      warnings.unshift({
        sev: 'high',
        msg: `⚠ ${aggBudget && aggBudget.reason ? aggBudget.reason : 'Aggregate archive-expansion budget exhausted — entry listing was truncated'}`,
      });
    }
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

    // File browser
    const archEntries = parsed.files.map(f => ({
      path: f.path,
      dir: false,
      size: f.size,
      date: f.date || null,
      _cabRef: f,
      // If the folder uses LZX/Quantum mark the entry as "encrypted-style"
      // (locked) so the Open button is suppressed — user can still see
      // every other forensic signal.
      encrypted: !!f._extractionBlocked,
    }));

    const tree = ArchiveTree.render({
      entries: archEntries,
      onOpen: (entry) => this._extractAndOpen(entry._cabRef || entry, wrap),
      execExts: CabRenderer.EXEC_EXTS,
      decoyExts: CabRenderer.DECOY_EXTS,
      showDate: true,
      expandAll: 'auto',
    });
    wrap.appendChild(tree);

    return wrap;
  }

  // ── Parsing ───────────────────────────────────────────────────────────

  _parse(bytes) {
    if (bytes.length < 36) throw new Error('Buffer too small for CFHEADER');
    if (bytes[0] !== 0x4D || bytes[1] !== 0x53 || bytes[2] !== 0x43 || bytes[3] !== 0x46) {
      throw new Error('MSCF signature missing');
    }
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    const cbCabinet  = dv.getUint32(8, true);
    const coffFiles  = dv.getUint32(16, true);
    const vMinor     = bytes[24];
    const vMajor     = bytes[25];
    const cFolders   = dv.getUint16(26, true);
    const cFiles     = dv.getUint16(28, true);
    const flags      = dv.getUint16(30, true);
    const setID      = dv.getUint16(32, true);
    const iCabinet   = dv.getUint16(34, true);

    const PREV_CAB       = 0x0001;
    const NEXT_CAB       = 0x0002;
    const RESERVE_PRESENT = 0x0004;

    let off = 36;
    let cbCFHeader = 0, cbCFFolder = 0, cbCFData = 0;
    if (flags & RESERVE_PRESENT) {
      if (off + 4 > bytes.length) throw new Error('Truncated CFHEADER reserve');
      cbCFHeader = dv.getUint16(off, true);     off += 2;
      cbCFFolder = bytes[off];                  off += 1;
      cbCFData   = bytes[off];                  off += 1;
      off += cbCFHeader; // skip abReserve
    }
    let prevCabinet = null, nextCabinet = null;
    const readCString = () => {
      const start = off;
      while (off < bytes.length && bytes[off] !== 0) off++;
      const s = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(start, off));
      off++; // skip null
      return s;
    };
    if (flags & PREV_CAB) {
      prevCabinet = readCString(); // szCabinetPrev
      readCString();                // szDiskPrev (unused)
    }
    if (flags & NEXT_CAB) {
      nextCabinet = readCString(); // szCabinetNext
      readCString();                // szDiskNext (unused)
    }

    // CFFOLDER entries — `cFolders` × (8 + cbCFFolder) bytes.
    const folders = [];
    const folderStride = 8 + cbCFFolder;
    const maxFolders = Math.min(cFolders, PARSER_LIMITS.MAX_ENTRIES);
    for (let i = 0; i < maxFolders; i++) {
      if (off + folderStride > bytes.length) throw new Error('Truncated CFFOLDER table');
      const coffCabStart = dv.getUint32(off, true);
      const cCFData      = dv.getUint16(off + 4, true);
      const typeCompress = dv.getUint16(off + 6, true);
      off += folderStride;
      const ctype = typeCompress & 0x000F;
      const clevel = (typeCompress & 0xFFF0) >>> 8; // low byte of level
      let label = 'Unknown';
      let extractable = false;
      switch (ctype) {
        case 0: label = 'Stored (no compression)'; extractable = true; break;
        case 1: label = 'MSZIP (deflate)'; extractable = true; break;
        case 2: label = `Quantum (level ${clevel})`; extractable = false; break;
        case 3: label = `LZX (window bits ${clevel})`; extractable = false; break;
      }
      folders.push({
        index: i,
        coffCabStart,
        cCFData,
        typeCompress: ctype,
        compressionLabel: label,
        extractable,
        // Populated below once CFDATA blocks are walked.
        dataBlocks: null,
        decompressed: null,
      });
    }

    // CFFILE entries — starts at `coffFiles`.
    let fp = coffFiles;
    const files = [];
    // Aggregate archive-expansion budget shared across the recursive
    // drill-down chain (H5). Pre-clip the file enumeration cap so a
    // hostile CAB nested inside a deeper chain can't inflate the
    // aggregate count past the cross-renderer ceiling.
    const aggBudget = (typeof window !== 'undefined' && window.app)
      ? window.app._archiveBudget : null;
    let maxFiles = Math.min(cFiles, PARSER_LIMITS.MAX_ENTRIES);
    let aggExhausted = false;
    if (aggBudget) {
      const room = Math.max(0, PARSER_LIMITS.MAX_AGGREGATE_ENTRIES - aggBudget.entries);
      if (maxFiles > room) { maxFiles = room; aggExhausted = true; }
      if (maxFiles > 0) aggBudget.consume(maxFiles, 0);
    }
    for (let i = 0; i < maxFiles; i++) {
      if (fp + 16 > bytes.length) throw new Error('Truncated CFFILE table');
      const size     = dv.getUint32(fp + 0, true);
      const uoff     = dv.getUint32(fp + 4, true);
      const iFolder  = dv.getUint16(fp + 8, true);
      const dosDate  = dv.getUint16(fp + 10, true);
      const dosTime  = dv.getUint16(fp + 12, true);
      const attribs  = dv.getUint16(fp + 14, true);
      fp += 16;
      // Null-terminated filename. Bit 0x80 of attribs => UTF-8; otherwise
      // legacy OEM (we treat as Latin-1 which is a strict superset for
      // printable ASCII and is good enough for sidebar display).
      const nameStart = fp;
      while (fp < bytes.length && bytes[fp] !== 0) fp++;
      if (fp >= bytes.length) throw new Error('Unterminated CFFILE name');
      const nameBytes = bytes.subarray(nameStart, fp);
      fp++; // skip null
      const utf8 = (attribs & 0x80) !== 0;
      const name = new TextDecoder(utf8 ? 'utf-8' : 'windows-1252', { fatal: false }).decode(nameBytes);
      // Normalise backslashes → forward slashes so ArchiveTree draws the
      // folder hierarchy correctly.
      const path = name.replace(/\\/g, '/');
      // DOS date/time
      let date = null;
      try {
        if (dosDate || dosTime) {
          const y = ((dosDate >> 9) & 0x7F) + 1980;
          const mo = ((dosDate >> 5) & 0x0F) || 1;
          const d  = (dosDate & 0x1F) || 1;
          const h  = (dosTime >> 11) & 0x1F;
          const mi = (dosTime >> 5) & 0x3F;
          const s  = (dosTime & 0x1F) * 2;
          date = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
          if (isNaN(date.getTime())) date = null;
        }
      } catch (_) { date = null; }

      // Resolve folder index. Special values:
      //   0xFFFD — continued from prev cabinet
      //   0xFFFE — continued to next cabinet
      //   0xFFFF — continued from prev & into next
      const special = (iFolder >= 0xFFFD);
      const folder = !special ? folders[iFolder] : null;
      const blocked = special || (folder && !folder.extractable);

      files.push({
        path, name, size,
        uoffFolderStart: uoff,
        iFolder, special,
        dosDate, dosTime, date,
        attribs,
        folder,
        _extractionBlocked: blocked,
      });
    }

    return {
      header: {
        cbCabinet, version: `${vMajor}.${vMinor}`,
        cFolders, cFiles, flags, setID, iCabinet,
        reservePresent: !!(flags & RESERVE_PRESENT),
        cbCFHeader, cbCFFolder, cbCFData,
        prevCabinet, nextCabinet,
      },
      folders,
      files,
      aggExhausted,
      _bytes: bytes,
      _cbCFData: cbCFData,
    };
  }

  // ── Folder extraction (lazy) ──────────────────────────────────────────
  //
  // Walk a folder's CFDATA blocks and build the full uncompressed
  // payload. Budget-capped; aborts if the accumulated output exceeds
  // PARSER_LIMITS.MAX_UNCOMPRESSED.
  _ensureFolderDecompressed(folder) {
    if (folder.decompressed) return folder.decompressed;
    if (!folder.extractable) throw new Error(`Compression type unsupported: ${folder.compressionLabel}`);

    const bytes = this._parsed._bytes;
    const cbCFData = this._parsed._cbCFData;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    let off = folder.coffCabStart;
    let chunks = [];
    let totalOut = 0;

    for (let i = 0; i < folder.cCFData; i++) {
      if (off + 8 + cbCFData > bytes.length) throw new Error('Truncated CFDATA block');
      const cbData    = dv.getUint16(off + 4, true);
      const cbUncomp  = dv.getUint16(off + 6, true);
      const dataOff   = off + 8 + cbCFData;
      if (dataOff + cbData > bytes.length) throw new Error('CFDATA payload past EOF');
      const payload = bytes.subarray(dataOff, dataOff + cbData);

      let decoded;
      if (folder.typeCompress === 0) {
        // Stored. cbData and cbUncomp must match.
        decoded = payload;
      } else if (folder.typeCompress === 1) {
        // MSZIP block. Each block is 'CK' (0x43 0x4B) + raw deflate.
        if (payload.length < 2 || payload[0] !== 0x43 || payload[1] !== 0x4B) {
          throw new Error('MSZIP block missing "CK" signature');
        }
        try {
          decoded = pako.inflateRaw(payload.subarray(2));
        } catch (e) {
          throw new Error(`MSZIP inflate failed: ${e.message}`);
        }
        if (decoded.length !== cbUncomp) {
          // Tolerate small mismatches (trailing alignment) but surface
          // catastrophic ones so callers don't render garbage.
          if (Math.abs(decoded.length - cbUncomp) > 32) {
            throw new Error(`MSZIP size mismatch: ${decoded.length} vs ${cbUncomp}`);
          }
        }
      } else {
        throw new Error(`Unsupported compression type ${folder.typeCompress}`);
      }

      chunks.push(decoded);
      totalOut += decoded.length;
      if (totalOut > PARSER_LIMITS.MAX_UNCOMPRESSED) {
        throw new Error(`Folder payload exceeds ${fmtBytes(PARSER_LIMITS.MAX_UNCOMPRESSED)} budget`);
      }
      off = dataOff + cbData;
    }

    // Flatten
    const out = new Uint8Array(totalOut);
    let p = 0;
    for (const c of chunks) { out.set(c, p); p += c.length; }
    folder.decompressed = out;
    return out;
  }

  _extractAndOpen(entry, wrap) {
    if (!entry || entry._extractionBlocked) return;
    try {
      const folderPayload = this._ensureFolderDecompressed(entry.folder);
      const start = entry.uoffFolderStart;
      const end = start + entry.size;
      if (end > folderPayload.length) throw new Error('Entry slice past folder end');
      const data = folderPayload.slice(start, end);
      const name = entry.path.split('/').pop();
      const file = new File([data], name, { type: 'application/octet-stream' });
      wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
    } catch (e) {
      console.warn('CAB extract failed:', e.message);
      const toast = document.getElementById('toast');
      if (toast) {
        toast.textContent = `⚠ Extraction failed: ${e.message}`;
        toast.className = '';
        setTimeout(() => toast.className = 'hidden', 4000);
      }
    }
  }

  // ── Warnings — parallels ZipRenderer._checkWarnings ───────────────────

  _checkWarnings(files) {
    const w = [];
    const execs = files.filter(e => CabRenderer.EXEC_EXTS.has((e.path || '').split('.').pop().toLowerCase()));
    if (execs.length) {
      w.push({ sev: 'high', msg: `⚠ ${execs.length} executable/script file(s): ${execs.slice(0, 5).map(e => e.path.split('/').pop()).join(', ')}${execs.length > 5 ? ' …' : ''}` });
    }
    const doubles = files.filter(e => this._isDoubleExt(e.path));
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

    const split = files.filter(e => e.special);
    if (split.length) {
      w.push({ sev: 'medium', msg: `📦 ${split.length} entry/entries are split across cabinets — payload is incomplete on its own` });
    }

    return w;
  }

  _isDoubleExt(path) {
    const name = (path || '').split('/').pop();
    const parts = name.split('.');
    if (parts.length < 3) return false;
    const last = parts[parts.length - 1].toLowerCase();
    const prev = parts[parts.length - 2].toLowerCase();
    return CabRenderer.EXEC_EXTS.has(last) && CabRenderer.DECOY_EXTS.has(prev);
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
      pushIOC(f, { type: IOC.INFO, value: `CAB parse failed: ${e.message}`, severity: 'info', bucket: 'externalRefs' });
      return f;
    }

    f.metadata = {
      'CAB Version': parsed.header.version,
      'Total Size': fmtBytes(parsed.header.cbCabinet),
      'Folders': parsed.folders.length,
      'Files': parsed.files.length,
      'Set ID': parsed.header.setID,
      'Cabinet Index': parsed.header.iCabinet,
    };
    if (parsed.header.prevCabinet) f.metadata['Previous Cabinet'] = parsed.header.prevCabinet;
    if (parsed.header.nextCabinet) f.metadata['Next Cabinet'] = parsed.header.nextCabinet;

    // Compression breakdown (per-folder)
    for (const fd of parsed.folders) {
      pushIOC(f, {
        type: IOC.INFO,
        value: `Folder ${fd.index}: ${fd.compressionLabel} · ${fd.cCFData} data block${fd.cCFData !== 1 ? 's' : ''}`,
        severity: 'info',
        bucket: 'externalRefs',
      });
    }
    if (parsed.folders.some(fd => !fd.extractable)) {
      pushIOC(f, {
        type: IOC.INFO,
        value: 'LZX/Quantum folder(s) present — extraction not supported in-browser',
        severity: 'info',
        bucket: 'externalRefs',
      });
    }
    if (parsed.header.prevCabinet || parsed.header.nextCabinet) {
      pushIOC(f, {
        type: IOC.PATTERN,
        value: 'Split cabinet (part of a multi-volume set) — contents may be incomplete without the companion file(s)',
        severity: 'medium',
        bucket: 'externalRefs',
      });
      if (f.risk === 'low') escalateRisk(f, 'medium');
    }
    if (parsed.header.reservePresent) {
      pushIOC(f, {
        type: IOC.INFO,
        value: `Reserve area present (CFHEADER ${parsed.header.cbCFHeader} B · CFFOLDER ${parsed.header.cbCFFolder} B · CFDATA ${parsed.header.cbCFData} B)`,
        severity: 'info',
        bucket: 'externalRefs',
      });
    }

    if (parsed.aggExhausted) {
      const aggBudget = (typeof window !== 'undefined' && window.app)
        ? window.app._archiveBudget : null;
      pushIOC(f, {
        type: IOC.INFO,
        value: aggBudget && aggBudget.reason ? aggBudget.reason : 'Aggregate archive-expansion budget exhausted — CAB entry listing was truncated',
        severity: 'info',
        bucket: 'externalRefs',
      });
    }

    // Warnings → externalRefs + risk
    const warnings = this._checkWarnings(parsed.files);
    for (const w of warnings) {
      f.externalRefs.push({ type: IOC.PATTERN, url: w.msg, severity: w.sev });
      if (w.sev === 'high') escalateRisk(f, 'high');
      else if (w.sev === 'medium' && f.risk !== 'high') escalateRisk(f, 'medium');
    }

    // Surface executable/script paths as FILE_PATH IOCs (same grammar as zip-renderer)
    const dangerous = parsed.files.filter(e => CabRenderer.EXEC_EXTS.has((e.path || '').split('.').pop().toLowerCase()));
    if (dangerous.length) {
      f.externalRefs.push({ type: IOC.PATTERN, url: `${dangerous.length} executable/script file(s) inside cabinet`, severity: 'high' });
      escalateRisk(f, 'high');
      for (const e of dangerous.slice(0, 50)) {
        f.externalRefs.push({ type: IOC.FILE_PATH, url: e.path, severity: 'high' });
      }
    }

    // Listing: path IOCs for every file, capped so pathological cabs
    // don't flood the sidebar. Useful as pivot data for triage.
    const listingCap = 100;
    for (const e of parsed.files.slice(0, listingCap)) {
      if (dangerous.includes(e)) continue;
      f.externalRefs.push({ type: IOC.FILE_PATH, url: e.path, severity: 'info' });
    }
    if (parsed.files.length > listingCap) {
      f.externalRefs.push({ type: IOC.INFO, url: `+${parsed.files.length - listingCap} more file path(s) truncated`, severity: 'info' });
    }

    return f;
  }
}
