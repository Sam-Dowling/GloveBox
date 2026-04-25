'use strict';
// ════════════════════════════════════════════════════════════════════════════
// onenote-renderer.js — OneNote (.one) file analysis and embedded object extraction
// OneNote became a major phishing vector after Microsoft disabled macros by default.
// Depends on: constants.js (IOC, escHtml)
// ════════════════════════════════════════════════════════════════════════════
class OneNoteRenderer {

  // GUID for OneNote revision store file format
  static ONE_MAGIC = [0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
    0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3];

  // FileDataStoreObject header GUID: {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
  static FDS_HEADER_GUID = [0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45,
    0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC];

  // FileDataStoreObject footer GUID: {71FBA722-0F79-4A0B-BB13-899256426B24}
  static FDS_FOOTER_GUID = [0x22, 0xA7, 0xFB, 0x71, 0x79, 0x0F, 0x0B, 0x4A,
    0xBB, 0x13, 0x89, 0x92, 0x56, 0x42, 0x6B, 0x24];

  // Magic-byte MIME sniff table (kept in sync with EncodedContentDetector)
  static MIME_SIGS = [
    { magic: [0x4D, 0x5A],                     ext: 'exe',   type: 'PE Executable',      sev: 'high' },
    { magic: [0x7F, 0x45, 0x4C, 0x46],         ext: 'elf',   type: 'ELF Binary',         sev: 'high' },
    { magic: [0xCF, 0xFA, 0xED, 0xFE],         ext: 'macho', type: 'Mach-O Binary',      sev: 'high' },
    { magic: [0xCA, 0xFE, 0xBA, 0xBE],         ext: 'class', type: 'Java Class',         sev: 'high' },
    { magic: [0x50, 0x4B, 0x03, 0x04],         ext: 'zip',   type: 'ZIP/Office Archive', sev: 'medium' },
    { magic: [0x52, 0x61, 0x72, 0x21],         ext: 'rar',   type: 'RAR Archive',        sev: 'medium' },
    { magic: [0x37, 0x7A, 0xBC, 0xAF],         ext: '7z',    type: '7-Zip Archive',      sev: 'medium' },
    { magic: [0x25, 0x50, 0x44, 0x46],         ext: 'pdf',   type: 'PDF Document',       sev: 'medium' },
    { magic: [0xD0, 0xCF, 0x11, 0xE0],         ext: 'ole',   type: 'OLE/CFB Document',   sev: 'medium' },
    { magic: [0x1F, 0x8B],                     ext: 'gz',    type: 'Gzip Compressed',    sev: 'medium' },
    { magic: [0x78, 0x9C],                     ext: 'zlib',  type: 'Zlib (default)',     sev: 'low' },
    { magic: [0x78, 0xDA],                     ext: 'zlib',  type: 'Zlib (best)',        sev: 'low' },
    { magic: [0x78, 0x01],                     ext: 'zlib',  type: 'Zlib (no/low)',      sev: 'low' },
    { magic: [0x89, 0x50, 0x4E, 0x47],         ext: 'png',   type: 'PNG Image',          sev: 'low' },
    { magic: [0xFF, 0xD8, 0xFF],               ext: 'jpg',   type: 'JPEG Image',         sev: 'low' },
    { magic: [0x47, 0x49, 0x46, 0x38],         ext: 'gif',   type: 'GIF Image',          sev: 'low' },
    { magic: [0x42, 0x4D],                     ext: 'bmp',   type: 'BMP Image',          sev: 'low' },
    { magic: [0x52, 0x49, 0x46, 0x46],         ext: 'riff',  type: 'RIFF (WAV/AVI/WebP)', sev: 'low' },
    { magic: [0x25, 0x21, 0x50, 0x53],         ext: 'ps',    type: 'PostScript',         sev: 'low' },
    { magic: [0x4C, 0x00, 0x00, 0x00],         ext: 'lnk',   type: 'Windows Shortcut',   sev: 'high' },
  ];

  // Text-content sniff (applied after UTF-8/UTF-16 decode of first bytes)
  static TEXT_SIGS = [
    { pat: /^\s*<\?xml/i,                          type: 'XML',              sev: 'low' },
    { pat: /^\s*<!DOCTYPE\s+html|^\s*<html/i,      type: 'HTML',             sev: 'medium' },
    { pat: /^\s*<HTA:APPLICATION/i,                type: 'HTA Application',  sev: 'high' },
    { pat: /^\s*<script/i,                         type: 'HTML/Script',      sev: 'high' },
    { pat: /^\s*\{\\rtf/,                          type: 'RTF Document',     sev: 'medium' },
    { pat: /^\s*#!(\/usr\/bin|\/bin)\//,           type: 'Shell Script',     sev: 'high' },
    { pat: /^\s*(Sub |Function |Dim |Private |Attribute VB_)/i, type: 'VBScript/VBA', sev: 'high' },
    { pat: /^\s*\$[A-Za-z_]|^\s*function\s|^\s*param\s*\(/i, type: 'PowerShell', sev: 'high' },
    { pat: /^\s*@echo\s+off|^\s*echo\s+off/i,      type: 'Batch Script',     sev: 'high' },
    { pat: /^\s*(WScript|CreateObject)/i,          type: 'WSH Script',       sev: 'high' },
  ];

  // Known dangerous extensions for embedded objects
  static DANGEROUS_EXTS = new Set([
    'exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'msi', 'bat', 'cmd', 'ps1',
    'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'wsc', 'hta', 'lnk', 'inf',
    'reg', 'sct', 'chm', 'jar',
  ]);

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const wrap = document.createElement('div'); wrap.className = 'onenote-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>OneNote File Analysis</strong> — .one files are a common phishing vector. ' +
      'Attackers embed malicious scripts behind fake "Double-click to view" buttons.';
    wrap.appendChild(banner);

    // Verify format
    const isOneNote = this._isOneNote(bytes);
    if (!isOneNote) {
      const info = document.createElement('div'); info.style.cssText = 'padding:20px;';
      info.innerHTML = `<p>File does not appear to be a valid OneNote file.</p>` +
        `<p><strong>File size:</strong> ${this._fmtBytes(bytes.length)}</p>`;
      wrap.appendChild(info);
      return wrap;
    }

    // Extract embedded objects
    const objects = this._findEmbeddedObjects(bytes);
    const strings = this._extractStrings(bytes);

    // Summary
    const summ = document.createElement('div'); summ.className = 'zip-summary';
    summ.textContent = `OneNote file — ${this._fmtBytes(bytes.length)}` +
      (objects.length ? ` — ${objects.length} embedded object(s) detected` : ' — no embedded objects found');
    wrap.appendChild(summ);

    // Warnings
    if (objects.length) {
      const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
      const w = document.createElement('div'); w.className = 'zip-warning zip-warning-high';
      w.textContent = `⚠ ${objects.length} embedded file object(s) — OneNote files with embedded objects are a known phishing technique`;
      warnDiv.appendChild(w);

      const dangerous = objects.filter(o => this._isDangerous(o));
      if (dangerous.length) {
        const w2 = document.createElement('div'); w2.className = 'zip-warning zip-warning-high';
        w2.textContent = `⚠ ${dangerous.length} executable/script object(s) embedded: ` +
          dangerous.map(o => this._label(o)).join(', ');
        warnDiv.appendChild(w2);
      }
      wrap.appendChild(warnDiv);
    }

    // Embedded objects table
    if (objects.length) {
      const sec = document.createElement('div'); sec.className = 'onenote-objects';
      const h = document.createElement('h3'); h.textContent = 'Embedded Objects';
      h.style.cssText = 'margin:16px 0 8px 0;padding:0 8px;'; sec.appendChild(h);

      const tbl = document.createElement('table'); tbl.className = 'zip-table';
      const thead = document.createElement('thead');
      const hr = document.createElement('tr');
      for (const col of ['', 'Name / Object', 'Size', 'Sniffed Type', 'GUID']) {
        const th = document.createElement('th'); th.textContent = col; hr.appendChild(th);
      }
      thead.appendChild(hr); tbl.appendChild(thead);

      const tbody = document.createElement('tbody');
      for (const obj of objects) {
        const tr = document.createElement('tr');
        const isDanger = this._isDangerous(obj);
        if (isDanger) tr.className = 'zip-row-danger';

        const tdIcon = document.createElement('td'); tdIcon.className = 'zip-icon';
        tdIcon.textContent = isDanger ? '⚠️' : '📎';
        tr.appendChild(tdIcon);

        const tdName = document.createElement('td'); tdName.className = 'zip-path';
        tdName.textContent = this._label(obj);
        if (isDanger) {
          const badge = document.createElement('span'); badge.className = 'zip-badge-danger';
          badge.textContent = 'EXECUTABLE'; tdName.appendChild(badge);
        }
        tr.appendChild(tdName);

        const tdSize = document.createElement('td'); tdSize.className = 'zip-size';
        tdSize.textContent = obj.size ? this._fmtBytes(obj.size) : '—';
        tr.appendChild(tdSize);

        const tdType = document.createElement('td'); tdType.className = 'zip-date';
        tdType.textContent = obj.sniffedType || obj.type || '—';
        tr.appendChild(tdType);

        const tdGuid = document.createElement('td'); tdGuid.className = 'zip-date';
        tdGuid.textContent = obj.storeGuid ? obj.storeGuid.slice(0, 8) + '…' : '—';
        tdGuid.title = obj.storeGuid || '';
        tr.appendChild(tdGuid);

        tbody.appendChild(tr);
      }
      tbl.appendChild(tbody); sec.appendChild(tbl);
      wrap.appendChild(sec);
    }

    // Extracted text
    if (strings.length) {
      const textSec = document.createElement('div'); textSec.style.cssText = 'padding:8px;';
      const details = document.createElement('details'); details.className = 'rtf-raw-details';
      const summary = document.createElement('summary');
      summary.textContent = `Extracted Text Strings (${strings.length})`;
      details.appendChild(summary);
      const pre = document.createElement('pre'); pre.className = 'rtf-raw-source';
      pre.textContent = strings.join('\n');
      details.appendChild(pre); textSec.appendChild(details);
      wrap.appendChild(textSec);
    }

    return wrap;
  }

  async analyzeForSecurity(buffer, fileName) {
    const f = {
      // Start 'low'; the embedded-object branch below flips f.risk to 'high'
      // whenever a FileDataStoreObject contains an executable (PE / ELF /
      // Mach-O / .lnk / script / HTA), which is the true OneNote threat.
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    // OneNote files are inherently suspicious in email context
    f.externalRefs.push({
      type: IOC.PATTERN,
      url: 'OneNote file — commonly used as phishing vector since macro-blocking',
      severity: 'medium'
    });

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const objects = this._findEmbeddedObjects(bytes);

    if (objects.length) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${objects.length} embedded file object(s) in OneNote`,
        severity: 'high'
      });
      escalateRisk(f, 'high');

      f.metadata.embeddedObjectCount = objects.length;
      const guids = [];
      const sniffs = [];
      // QR-decode cap for embedded image blobs. OneNote phishing samples
      // often tile a QR under the fake "Double-click to open" button to
      // smuggle the true payload URL past text scanners.
      const QR_EMBED_CAP = 32;
      let qrEmbedScanned = 0;
      let qrIndex = 0;
      const qrPromises = [];
      // Map our sniff labels back to the MIME strings QrDecoder.decodeBlob
      // accepts ("image/png", "image/jpeg", …). Non-image sniffs skip QR.
      const sniffToMime = (t) => {
        if (!t) return null;
        if (/PNG/i.test(t))  return 'image/png';
        if (/JPEG/i.test(t)) return 'image/jpeg';
        if (/GIF/i.test(t))  return 'image/gif';
        if (/BMP/i.test(t))  return 'image/bmp';
        if (/WebP/i.test(t)) return 'image/webp';
        return null;
      };
      for (const obj of objects) {
        const label = this._label(obj);
        if (obj.storeGuid) guids.push(obj.storeGuid);
        if (obj.sniffedType) sniffs.push(obj.sniffedType);
        const isDanger = this._isDangerous(obj);
        const sev = isDanger ? 'high' : (obj.sniffedSev || 'medium');
        const note = obj.sniffedType
          ? `FileDataStoreObject blob — sniffed as ${obj.sniffedType} (${this._fmtBytes(obj.size || 0)})`
          : `FileDataStoreObject blob (${this._fmtBytes(obj.size || 0)})`;
        f.externalRefs.push({
          type: obj.name ? IOC.FILE_PATH : IOC.PATTERN,
          url: label,
          severity: sev,
          note,
        });

        // ── QR-decode embedded image blobs ─────────────────────────────
        const mime = sniffToMime(obj.sniffedType);
        if (mime && typeof QrDecoder !== 'undefined' &&
            qrEmbedScanned < QR_EMBED_CAP &&
            obj.offset != null && obj.size > 0 &&
            obj.offset + obj.size <= bytes.length) {
          qrEmbedScanned++;
          const idx = ++qrIndex;
          const slice = bytes.subarray(obj.offset, obj.offset + obj.size);
          // Copy to a standalone ArrayBuffer — decodeBlob uses
          // URL.createObjectURL which can't index into a subarray view.
          const ab = new Uint8Array(slice).buffer;
          qrPromises.push(
            QrDecoder.decodeBlob(ab, mime)
              .then(qr => { if (qr) QrDecoder.applyToFindings(f, qr, `onenote-embed-${idx}`); })
              .catch(() => { /* swallow */ })
          );
        }
      }

      if (guids.length) f.metadata.fileDataStoreGuids = Array.from(new Set(guids)).slice(0, 16);
      if (sniffs.length) f.metadata.sniffedBlobTypes = Array.from(new Set(sniffs));

      // Wait for every in-flight QR decode to resolve — _renderSidebar
      // reads a one-shot snapshot of findings after this method resolves,
      // so fire-and-forget would land the QR IOC after first paint.
      if (qrPromises.length) {
        try { await Promise.all(qrPromises); } catch (_) { /* swallow */ }
      }
    }

    // Extract URLs from text content.
    // Offsets are into the synthesized string-extraction concatenation (not
    // the file bytes), so we emit _highlightText only — the sidebar's
    // match-by-text lookup can still locate the URL inside the rendered
    // "Extracted Text Strings" block for click-to-focus navigation.
    const strings = this._extractStrings(bytes);
    const fullText = strings.join('\n');
    const URL_CAP = 200;
    let urlCount = 0;
    let urlTruncated = false;
    for (const m of fullText.matchAll(/https?:\/\/[^\s"'<>]{6,}/g)) {
      if (urlCount >= URL_CAP) { urlTruncated = true; break; }
      urlCount++;
      f.externalRefs.push({
        type: IOC.URL,
        url: m[0],
        severity: 'medium',
        _highlightText: m[0],
      });
    }
    if (urlTruncated) {
      f.externalRefs.push({
        type: IOC.INFO,
        url: `URL extraction truncated at ${URL_CAP} — file contains additional URLs not listed`,
        severity: 'info',
      });
    }


    // Pattern detection is handled entirely by YARA (auto-scan on file load)
    return f;
  }

  // ── Helpers for object labelling / classification ───────────────────────────

  _isDangerous(obj) {
    if (obj.name) {
      const ext = obj.name.split('.').pop().toLowerCase();
      if (OneNoteRenderer.DANGEROUS_EXTS.has(ext)) return true;
    }
    if (obj.sniffedSev === 'high') return true;
    if (obj.sniffedExt && OneNoteRenderer.DANGEROUS_EXTS.has(obj.sniffedExt)) return true;
    return false;
  }

  _label(obj) {
    if (obj.name) return obj.name;
    if (obj.sniffedType) {
      const sizeStr = obj.size ? ` (${this._fmtBytes(obj.size)})` : '';
      return `[${obj.sniffedType}]${sizeStr}`;
    }
    return `Object (${this._fmtBytes(obj.size || 0)})`;
  }

  // ── OneNote format detection ────────────────────────────────────────────────

  _isOneNote(bytes) {
    if (bytes.length < 16) return false;
    for (let i = 0; i < 16; i++) {
      if (bytes[i] !== OneNoteRenderer.ONE_MAGIC[i]) return false;
    }
    return true;
  }

  // ── Embedded object detection ───────────────────────────────────────────────
  //
  // OneNote's FileDataStoreObject layout (MS-ONESTORE §2.6.12):
  //   +0x00  guidHeader (16B)   = {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
  //   +0x10  cbLength  (u64)    = size of FileData (rounded up to 8-byte boundary)
  //   +0x18  unused    (u32)    = 0
  //   +0x1C  reserved  (u64)    = 0
  //   +0x24  FileData  (cbLength bytes, padded to 8)
  //   +end   guidFooter (16B)   = {71FBA722-0F79-4A0B-BB13-899256426B24}

  _findEmbeddedObjects(bytes) {
    const objects = [];
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

    // Method 1: Walk every FileDataStoreObject header GUID and parse the
    // structure properly so we can MIME-sniff the data.
    const claimedRanges = []; // to avoid method-2 double-reporting inside blobs
    for (let i = 0; i + 0x24 < bytes.length; i++) {
      if (!this._matchGuid(bytes, i, OneNoteRenderer.FDS_HEADER_GUID)) continue;

      // Read u64 length (we only use the low 32 bits; any blob >4GB is absurd here).
      const lenLo = dv.getUint32(i + 0x10, true);
      const lenHi = dv.getUint32(i + 0x14, true);
      const cbLength = lenHi > 0 ? 0xFFFFFFFF : lenLo;
      const dataOff = i + 0x24;

      if (cbLength === 0 || dataOff + cbLength > bytes.length) {
        // Malformed entry — record header only
        objects.push({
          storeGuid: this._guidStr(bytes, i),
          size: 0,
          offset: i,
          sniffedType: null,
          name: null,
        });
        continue;
      }

      // Sniff MIME on the first bytes of the embedded blob
      const sniff = this._sniff(bytes, dataOff, Math.min(cbLength, 4096));

      // Try to find a filename stored near the blob (OneNote often stores
      // filenames as UTF-16LE in the surrounding metadata).
      const name = this._findNearbyFilename(bytes, Math.max(0, i - 512), i) ||
                   this._findNearbyFilename(bytes, dataOff + cbLength,
                                            Math.min(bytes.length, dataOff + cbLength + 512));

      objects.push({
        storeGuid: this._guidStr(bytes, i),
        size: cbLength,
        offset: dataOff,
        name,
        sniffedType: sniff.type,
        sniffedExt: sniff.ext,
        sniffedSev: sniff.sev,
        type: sniff.type || (name ? 'File' : 'Object'),
      });
      claimedRanges.push([dataOff, dataOff + cbLength]);

      // Skip past this blob to avoid scanning inside
      i = dataOff + cbLength - 1;
    }

    // Method 2: Raw magic-byte scan outside claimed FDS ranges (catches
    // files where the GUID header is missing/corrupt).
    const inClaimed = off => claimedRanges.some(([s, e]) => off >= s && off < e);
    if (objects.length === 0) {
      // Only do the expensive full-scan when we found no structured blobs
      for (let i = 256; i < bytes.length - 4; i++) {
        if (inClaimed(i)) continue;
        const sniff = this._sniff(bytes, i, 32);
        if (sniff.type && ['PE Executable', 'ELF Binary', 'Mach-O Binary',
                           'ZIP/Office Archive', 'PDF Document', 'Windows Shortcut'].includes(sniff.type)) {
          objects.push({
            size: 0,
            offset: i,
            sniffedType: sniff.type,
            sniffedExt: sniff.ext,
            sniffedSev: sniff.sev,
            type: sniff.type,
            name: null,
          });
          // Only record first of each type to keep the list reasonable
          if (objects.length >= 8) break;
        }
      }
    }

    // Method 3: Scan for filename patterns (UTF-16LE) with dangerous extensions
    this._findEmbeddedFilenames(bytes, objects);

    return objects;
  }

  _matchGuid(bytes, offset, guid) {
    if (offset + guid.length > bytes.length) return false;
    for (let i = 0; i < guid.length; i++) {
      if (bytes[offset + i] !== guid[i]) return false;
    }
    return true;
  }

  _guidStr(bytes, off) {
    if (off + 16 > bytes.length) return '';
    const h2 = b => b.toString(16).padStart(2, '0');
    const le4 = o => h2(bytes[o + 3]) + h2(bytes[o + 2]) + h2(bytes[o + 1]) + h2(bytes[o]);
    const le2 = o => h2(bytes[o + 1]) + h2(bytes[o]);
    const be2 = o => h2(bytes[o]) + h2(bytes[o + 1]);
    let node = '';
    for (let i = 10; i < 16; i++) node += h2(bytes[off + i]);
    return `${le4(off)}-${le2(off + 4)}-${le2(off + 6)}-${be2(off + 8)}-${node}`;
  }

  // ── MIME sniff: magic bytes + text signatures ──────────────────────────────
  _sniff(bytes, off, maxLen) {
    const view = bytes.subarray(off, Math.min(bytes.length, off + maxLen));
    for (const s of OneNoteRenderer.MIME_SIGS) {
      if (view.length < s.magic.length) continue;
      let ok = true;
      for (let k = 0; k < s.magic.length; k++) {
        if (view[k] !== s.magic[k]) { ok = false; break; }
      }
      if (ok) return { type: s.type, ext: s.ext, sev: s.sev };
    }
    // Text sniff (UTF-8 head)
    try {
      const head = new TextDecoder('utf-8', { fatal: false })
        .decode(view.subarray(0, Math.min(200, view.length)));
      for (const s of OneNoteRenderer.TEXT_SIGS) {
        if (s.pat.test(head)) return { type: s.type, ext: null, sev: s.sev };
      }
    } catch (_) {}
    return { type: null, ext: null, sev: null };
  }

  _findNearbyFilename(bytes, start, end) {
    start = Math.max(0, start);
    end = Math.min(bytes.length - 2, end);

    // Look for UTF-16LE filename with extension
    for (let i = start; i < end - 10; i++) {
      if (bytes[i] === 0x2E && bytes[i + 1] === 0x00) { // "." in UTF-16LE
        // Read backwards to find the start of the filename
        let nameStart = i;
        while (nameStart > start + 2 &&
          ((bytes[nameStart - 2] >= 0x20 && bytes[nameStart - 2] < 0x7F && bytes[nameStart - 1] === 0x00) ||
            (bytes[nameStart - 2] >= 0x80 && bytes[nameStart - 1] !== 0x00))) {
          nameStart -= 2;
        }

        // Read the extension after the dot
        let extEnd = i + 2;
        while (extEnd < end - 1 && bytes[extEnd] >= 0x61 && bytes[extEnd] <= 0x7A && bytes[extEnd + 1] === 0x00) {
          extEnd += 2;
        }

        const extLen = (extEnd - i - 2) / 2;
        if (extLen >= 2 && extLen <= 5) {
          let name = '';
          for (let j = nameStart; j < extEnd; j += 2) {
            if (j + 1 < bytes.length) {
              const code = bytes[j] | (bytes[j + 1] << 8);
              if (code >= 0x20 && code < 0xFFFE) name += String.fromCharCode(code);
            }
          }
          if (name.length >= 3 && name.includes('.')) return name;
        }
      }
    }
    return null;
  }

  _findEmbeddedFilenames(bytes, objects) {
    const existing = new Set(objects.map(o => o.name).filter(Boolean));
    for (let i = 0; i < bytes.length - 20; i++) {
      if (bytes[i] === 0x2E && bytes[i + 1] === 0x00) {
        // Potential extension start
        let ext = '';
        let j = i + 2;
        while (j < bytes.length - 1 && j < i + 12 && bytes[j] >= 0x61 && bytes[j] <= 0x7A && bytes[j + 1] === 0x00) {
          ext += String.fromCharCode(bytes[j]);
          j += 2;
        }
        if (ext.length >= 2 && ext.length <= 5 && OneNoteRenderer.DANGEROUS_EXTS.has(ext)) {
          // Read back for filename
          let nameStart = i;
          let nameChars = 0;
          while (nameStart > 2 && nameChars < 100 &&
            bytes[nameStart - 2] >= 0x20 && bytes[nameStart - 1] === 0x00) {
            nameStart -= 2;
            nameChars++;
          }
          if (nameChars >= 2) {
            let name = '';
            for (let k = nameStart; k < j; k += 2) {
              const code = bytes[k] | (bytes[k + 1] << 8);
              if (code >= 0x20 && code < 0xFFFE) name += String.fromCharCode(code);
            }
            if (name.length >= 3 && !existing.has(name)) {
              existing.add(name);
              objects.push({ name, size: 0, type: 'Embedded file (name found)', offset: nameStart });
            }
          }
        }
      }
    }
  }

  // ── Text string extraction ──────────────────────────────────────────────────

  _extractStrings(bytes) {
    const strings = [];
    const seen = new Set();

    // Extract UTF-16LE strings
    let current = '';
    for (let i = 0; i < bytes.length - 1; i += 2) {
      const code = bytes[i] | (bytes[i + 1] << 8);
      if (code >= 0x20 && code < 0xFFFE && code !== 0xFFFD) {
        current += String.fromCharCode(code);
      } else {
        if (current.length >= 8 && !seen.has(current)) {
          seen.add(current);
          strings.push(current);
        }
        current = '';
      }
    }
    if (current.length >= 8 && !seen.has(current)) strings.push(current);

    // Also extract ASCII strings
    current = '';
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b >= 0x20 && b < 0x7F) {
        current += String.fromCharCode(b);
      } else {
        if (current.length >= 12 && !seen.has(current)) {
          seen.add(current);
          strings.push(current);
        }
        current = '';
      }
    }
    if (current.length >= 12 && !seen.has(current)) strings.push(current);

    return strings.slice(0, 1000); // Cap at 1000
  }

  _fmtBytes(n) {
    if (!n && n !== 0) return '0 B';
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
