'use strict';
// ════════════════════════════════════════════════════════════════════════════
// iso-renderer.js — ISO 9660 / UDF disk image content listing
// Lists files in .iso and .img disk images without mounting them.
// Depends on: constants.js (IOC, escHtml)
// ════════════════════════════════════════════════════════════════════════════
class IsoRenderer {

  // Dangerous file extensions inside disk images
  static EXEC_EXTS = new Set([
    'exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'msi', 'msp', 'mst',
    'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'wsc',
    'hta', 'lnk', 'inf', 'reg', 'sct',
    'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm',
  ]);

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const wrap = document.createElement('div'); wrap.className = 'iso-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>Disk Image Analysis</strong> — listing files inside the ISO/IMG image. ' +
      'Disk images are increasingly used in phishing to bypass Mark-of-the-Web (MOTW) protection.';
    wrap.appendChild(banner);

    const entries = this._parseISO9660(bytes);
    if (!entries) {
      const p = document.createElement('p'); p.style.cssText = 'color:var(--risk-high);padding:20px';
      p.textContent = 'Could not parse ISO 9660 filesystem. File may be UDF-only, corrupted, or a different image format.';
      wrap.appendChild(p);

      // Show basic file info
      const det = document.createElement('div'); det.style.cssText = 'padding:10px 20px;';
      det.innerHTML = `<p><strong>File size:</strong> ${this._fmtBytes(bytes.length)}</p>` +
        `<p style="color:var(--risk-high);margin-top:8px">⚠ ISO/IMG files are used in phishing to deliver malicious payloads while bypassing MOTW.</p>`;
      wrap.appendChild(det);
      return wrap;
    }

    // Volume info
    if (entries._vol) {
      const vol = document.createElement('div'); vol.className = 'iso-volume-info';
      vol.innerHTML = `<strong>Volume:</strong> ${escHtml(entries._vol.id)} &nbsp;·&nbsp; ` +
        `<strong>System:</strong> ${escHtml(entries._vol.system)} &nbsp;·&nbsp; ` +
        `<strong>Size:</strong> ${this._fmtBytes(entries._vol.size)}`;
      wrap.appendChild(vol);
    }

    const files = entries.files || [];
    const dirs = files.filter(e => e.dir).length;
    const fileCount = files.filter(e => !e.dir).length;

    const summ = document.createElement('div'); summ.className = 'zip-summary';
    summ.textContent = `${fileCount} file${fileCount !== 1 ? 's' : ''}, ${dirs} folder${dirs !== 1 ? 's' : ''}`;
    wrap.appendChild(summ);

    // Warnings
    const warnings = this._checkWarnings(files);
    if (warnings.length) {
      const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
      for (const w of warnings) {
        const d = document.createElement('div'); d.className = `zip-warning zip-warning-${w.sev}`;
        d.textContent = w.msg; warnDiv.appendChild(d);
      }
      wrap.appendChild(warnDiv);
    }

    // File listing — shared ArchiveTree (tree + flat + search + sort).
    // ISO 9660 files are stored uncompressed as contiguous byte runs at
    // `lba * blockSize`, so per-file extraction is a plain buffer slice —
    // dispatch `open-inner-file` and let app-load.js drill into the child.
    if (files.length) {
      const byPath = new Map();
      for (const e of files) byPath.set(e.path || e.name, e);
      const archEntries = files.map(e => ({
        path: e.path || e.name,
        dir: !!e.dir,
        size: e.size || 0,
        // ISO stores date as "YYYY-MM-DD HH:MM:SS" — convert for flat-view sorting.
        date: e.date ? new Date(e.date.replace(' ', 'T') + 'Z') : null,
      }));
      const tree = ArchiveTree.render({
        entries: archEntries,
        onOpen: (archEntry) => {
          const src = byPath.get(archEntry.path);
          if (!src || src.dir) return;
          const data = this._extractFile(bytes, src);
          if (!data) return;
          const name = src.name || (archEntry.path.split('/').pop());
          const file = new File([data], name, { type: 'application/octet-stream' });
          wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
        },
        execExts: IsoRenderer.EXEC_EXTS,
        showDate: true,
      });
      wrap.appendChild(tree);
    }

    return wrap;
  }

  // Slice a file's contents out of the ISO buffer. ISO 9660 stores file data
  // uncompressed as a contiguous run starting at `lba * blockSize` for `size`
  // bytes, so extraction is a bounds-clamped subarray.
  _extractFile(bytes, entry) {
    const blockSize = entry._blockSize || 2048;
    const lba = entry._lba | 0;
    const size = entry.size | 0;
    if (lba <= 0 || size <= 0) return null;
    const start = lba * blockSize;
    if (start >= bytes.length) return null;
    const end = Math.min(start + size, bytes.length);
    return bytes.subarray(start, end);
  }

  analyzeForSecurity(buffer, fileName) {
    // Start 'low'; the "bypasses MOTW" banner ships at severity:'medium',
    // and the dangerous-content branches below flip f.risk to 'high'
    // whenever executables / .lnk / autorun.inf are present.
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    // ISO/IMG are inherently suspicious in email context
    f.externalRefs.push({
      type: IOC.PATTERN,
      url: 'Disk image file — bypasses Mark-of-the-Web (MOTW) protection',
      severity: 'medium'
    });

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const entries = this._parseISO9660(bytes);

    if (entries && entries.files) {
      const files = entries.files.filter(e => !e.dir);
      const dangerous = files.filter(e => IsoRenderer.EXEC_EXTS.has(e.name.split('.').pop().toLowerCase()));

      if (dangerous.length) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `${dangerous.length} executable/script file(s) inside disk image`,
          severity: 'high'
        });
        escalateRisk(f, 'high');
        for (const e of dangerous) {
          f.externalRefs.push({ type: IOC.FILE_PATH, url: e.path || e.name, severity: 'high' });
        }
      }

      // LNK files
      const lnks = files.filter(e => /\.lnk$/i.test(e.name));
      if (lnks.length) {
        f.externalRefs.push({ type: IOC.PATTERN, url: 'Windows shortcut (.lnk) inside disk image — common phishing technique', severity: 'high' });
        escalateRisk(f, 'high');
      }

      // autorun.inf
      const autorun = files.filter(e => /^autorun\.inf$/i.test(e.name));
      if (autorun.length) {
        f.externalRefs.push({ type: IOC.PATTERN, url: 'autorun.inf detected — may auto-execute content', severity: 'high' });
        escalateRisk(f, 'high');
      }

      // Hidden files (starting with .)
      const hidden = files.filter(e => e.name.startsWith('.') && e.name !== '.' && e.name !== '..');
      if (hidden.length) {
        f.externalRefs.push({ type: IOC.PATTERN, url: `${hidden.length} hidden file(s) in disk image`, severity: 'medium' });
      }

      if (entries._vol) {
        f.metadata = {
          title: entries._vol.id || '',
          creator: entries._vol.system || '',
          subject: `ISO 9660 Volume — ${this._fmtBytes(entries._vol.size)}`,
        };
      }
    }

    // Pattern detection is handled entirely by YARA (auto-scan on file load)
    return f;
  }

  // ── ISO 9660 parser ─────────────────────────────────────────────────────────

  _parseISO9660(bytes) {
    // ISO 9660 Primary Volume Descriptor starts at sector 16 (byte 32768)
    const PVD_OFFSET = 16 * 2048;
    if (bytes.length < PVD_OFFSET + 2048) return null;

    // Check for CD001 signature
    const sig = String.fromCharCode(bytes[PVD_OFFSET + 1], bytes[PVD_OFFSET + 2], bytes[PVD_OFFSET + 3], bytes[PVD_OFFSET + 4], bytes[PVD_OFFSET + 5]);
    if (sig !== 'CD001') return null;

    const type = bytes[PVD_OFFSET]; // 1 = primary volume descriptor
    if (type !== 1) return null;

    // Extract volume info
    const volId = this._readStr(bytes, PVD_OFFSET + 40, 32);
    const sysId = this._readStr(bytes, PVD_OFFSET + 8, 32);
    const volSize = this._read32Both(bytes, PVD_OFFSET + 80) * 2048; // logical block size assumed 2048
    const blockSize = this._read16Both(bytes, PVD_OFFSET + 128);

    // Root directory record is at offset 156 in PVD, 34 bytes
    const rootOff = PVD_OFFSET + 156;
    const rootLba = this._read32Both(bytes, rootOff + 2);
    const rootLen = this._read32Both(bytes, rootOff + 10);

    const result = {
      _vol: { id: volId, system: sysId, size: volSize },
      files: [],
      aggExhausted: false,
    };

    // Read directory tree
    this._readDirectory(bytes, rootLba * (blockSize || 2048), rootLen, '', result, blockSize || 2048, 0);

    return result;
  }

  _readDirectory(bytes, offset, length, prefix, result, blockSize, depth) {
    const files = result.files;
    if (depth > PARSER_LIMITS.MAX_DEPTH) return; // prevent infinite recursion
    if (files.length >= PARSER_LIMITS.MAX_ENTRIES) return; // entry count cap
    // Aggregate archive-expansion budget shared across the recursive
    // drill-down chain (H5).
    const aggBudget = (typeof window !== 'undefined' && window.app)
      ? window.app._archiveBudget : null;
    if (aggBudget && aggBudget.exhausted) { result.aggExhausted = true; return; }
    let pos = offset;
    const end = offset + length;

    while (pos < end && pos < bytes.length) {
      const recLen = bytes[pos];
      if (recLen === 0) {
        // Padding — skip to next sector boundary
        const next = (Math.floor(pos / blockSize) + 1) * blockSize;
        if (next <= pos || next >= end) break;
        pos = next;
        continue;
      }
      if (pos + recLen > bytes.length) break;

      const extAttrLen = bytes[pos + 1];
      const lba = this._read32Both(bytes, pos + 2);
      const size = this._read32Both(bytes, pos + 10);
      const flags = bytes[pos + 25];
      const nameLen = bytes[pos + 32];
      const isDir = !!(flags & 0x02);

      let name = '';
      for (let i = 0; i < nameLen; i++) {
        const b = bytes[pos + 33 + i];
        if (b === 0) break;
        name += String.fromCharCode(b);
      }

      // Skip . and .. entries
      if (nameLen === 1 && (bytes[pos + 33] === 0 || bytes[pos + 33] === 1)) {
        pos += recLen;
        continue;
      }

      // Clean up name: remove version suffix (;1)
      name = name.replace(/;.*$/, '').replace(/\.$/, '');

      const path = prefix ? prefix + '/' + name : name;
      const date = this._readDate(bytes, pos + 18);

      // Charge each emitted entry against the aggregate cross-renderer
      // budget. `consume` returns false when either cap trips.
      if (aggBudget && !aggBudget.consume(1, isDir ? 0 : (size | 0))) {
        result.aggExhausted = true;
        return;
      }

      // `_lba` / `_blockSize` are kept for `_extractFile` to slice the raw
      // file bytes back out of the ISO buffer on drill-down.
      files.push({ name, path, size, dir: isDir, date, _lba: lba, _blockSize: blockSize });

      // Recurse into subdirectories
      if (isDir && lba > 0 && size > 0) {
        this._readDirectory(bytes, lba * blockSize, size, path, result, blockSize, depth + 1);
        if (result.aggExhausted) return;
      }

      pos += recLen;
    }
  }

  _readDate(bytes, off) {
    if (off + 7 > bytes.length) return '';
    const y = 1900 + bytes[off];
    const m = bytes[off + 1];
    const d = bytes[off + 2];
    const h = bytes[off + 3];
    const min = bytes[off + 4];
    const s = bytes[off + 5];
    if (y < 1980 || m < 1 || m > 12 || d < 1 || d > 31) return '';
    return `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')} ${String(h).padStart(2, '0')}:${String(min).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  }

  _read32Both(bytes, off) {
    // ISO 9660 "both-byte" 32-bit: little-endian at off, big-endian at off+4
    if (off + 4 > bytes.length) return 0;
    return bytes[off] | (bytes[off + 1] << 8) | (bytes[off + 2] << 16) | ((bytes[off + 3] << 24) >>> 0);
  }

  _read16Both(bytes, off) {
    if (off + 2 > bytes.length) return 0;
    return bytes[off] | (bytes[off + 1] << 8);
  }

  _readStr(bytes, off, len) {
    let s = '';
    for (let i = 0; i < len && off + i < bytes.length; i++) {
      s += String.fromCharCode(bytes[off + i]);
    }
    return s.trim();
  }

  _checkWarnings(files) {
    const w = [];
    const nonDirs = files.filter(e => !e.dir);

    const execs = nonDirs.filter(e => IsoRenderer.EXEC_EXTS.has(e.name.split('.').pop().toLowerCase()));
    if (execs.length) w.push({ sev: 'high', msg: `⚠ ${execs.length} executable/script file(s): ${execs.slice(0, 5).map(e => e.name).join(', ')}${execs.length > 5 ? ' …' : ''}` });

    const lnks = nonDirs.filter(e => /\.lnk$/i.test(e.name));
    if (lnks.length) w.push({ sev: 'high', msg: '⚠ Windows shortcut (.lnk) file(s) — common ISO-based phishing technique' });

    const autorun = nonDirs.filter(e => /^autorun\.inf$/i.test(e.name));
    if (autorun.length) w.push({ sev: 'high', msg: '⚠ autorun.inf — may auto-execute content when mounted' });

    if (nonDirs.length <= 3 && execs.length > 0) {
      w.push({ sev: 'high', msg: '⚠ Small number of files with executable content — likely a targeted payload delivery' });
    }

    return w;
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1073741824).toFixed(1) + ' GB';
  }
}
