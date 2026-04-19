'use strict';
// ════════════════════════════════════════════════════════════════════════════
// zip-renderer.js — Archive content listing for .zip / .gz / .tar / .7z / .rar / .cab
// Supports: clickable file extraction, ZipCrypto password cracking, gzip decompression, TAR parsing
// Depends on: constants.js (IOC), JSZip (vendor), Decompressor (decompressor.js)
// ════════════════════════════════════════════════════════════════════════════
class ZipRenderer {

  // Extensions considered dangerous inside archives
  static EXEC_EXTS = new Set([
    'exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'msi', 'msp', 'mst',
    'bat', 'cmd', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'wsc',
    'hta', 'lnk', 'inf', 'reg', 'sct',
    'jar', 'py', 'rb', 'sh', 'bash',
    'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'ppam', 'xlam',
  ]);

  // macOS .app bundle path regex — matches the root segment of a bundle,
  // e.g. "MyApp.app/" or "Foo/.Bar.app/". Tight start-anchor rejects
  // random mid-string ".app" runs that aren't real bundle roots.
  static MACAPP_RE = /(?:^|\/)([A-Za-z0-9][A-Za-z0-9 _\-.]{0,63}\.app)\//;

  // IOC cap for .app bundle FILE_PATH emission — mirrors DMG renderer.
  static APP_IOC_CAP = 30;

  // Double-extension patterns attackers use (e.g. invoice.pdf.exe)
  static DECOY_EXTS = new Set([
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'png', 'gif', 'txt', 'rtf',
  ]);

  // Common passwords for malware samples
  static PASSWORD_LIST = ['password', 'infected', 'suspicious', 'malware', 'virus', 'sample',
    'test', '123456', 'Password1', 'infected!', 'abc123'];

  async render(buffer, fileName) {
    const wrap = document.createElement('div'); wrap.className = 'zip-view';
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    // ── Check for Gzip format (magic: 1F 8B) ────────────────────────────────
    if (bytes[0] === 0x1F && bytes[1] === 0x8B) {
      return await this._handleGzip(wrap, bytes, fileName);
    }

    // ── Check for TAR format (magic "ustar" at offset 257) ──────────────────
    if (this._isTar(bytes)) {
      return this._handleTar(wrap, bytes, fileName);
    }

    // Banner for ZIP
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>Archive Contents</strong> — click any file to open it for analysis.';
    wrap.appendChild(banner);

    // Try to load as ZIP
    let zip;
    try { zip = await JSZip.loadAsync(buffer); }
    catch (e) {
      // May be encrypted or non-ZIP — check for encryption first
      const encrypted = this._detectEncryption(bytes);
      if (encrypted) {
        return await this._handleEncrypted(wrap, buffer, fileName);
      }
      return this._nonZip(wrap, buffer, fileName);
    }

    // Check if any entries are encrypted (JSZip parses headers but fails on decompress)
    const hasEncrypted = await this._hasEncryptedEntries(zip);
    if (hasEncrypted) {
      return await this._handleEncrypted(wrap, buffer, fileName);
    }

    // Store zip for file extraction
    this._zip = zip;
    return this._renderZipContents(wrap, zip, buffer, fileName);
  }

  // ── Gzip handling ─────────────────────────────────────────────────────────

  async _handleGzip(wrap, bytes, fileName) {
    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>Gzip Compressed File</strong> — decompressing content for analysis.';
    wrap.appendChild(banner);

    // Parse gzip header for info
    const gzInfo = this._parseGzipHeader(bytes);

    // Show gzip info
    const infoDiv = document.createElement('div'); infoDiv.style.cssText = 'padding:12px 20px;';
    infoDiv.innerHTML = `<p><strong>Format:</strong> Gzip compressed${gzInfo.method ? ` (${escHtml(gzInfo.method)})` : ''}</p>` +
      `<p><strong>Compressed size:</strong> ${this._fmtBytes(bytes.length)}</p>` +
      (gzInfo.originalName ? `<p><strong>Original filename:</strong> ${escHtml(gzInfo.originalName)}</p>` : '') +
      (gzInfo.mtime ? `<p><strong>Modified:</strong> ${escHtml(gzInfo.mtime)}</p>` : '');
    wrap.appendChild(infoDiv);

    // Try to decompress
    let decompressed = null;
    try {
      decompressed = await Decompressor.inflate(bytes, 'gzip');
    } catch (e) {
      // Decompression failed
    }

    if (!decompressed) {
      const errDiv = document.createElement('div');
      errDiv.style.cssText = 'padding:12px 20px;color:var(--risk-high);';
      errDiv.innerHTML = '<p>⚠ Decompression failed — file may be corrupted or truncated.</p>';
      wrap.appendChild(errDiv);

      // Show hex dump of compressed data
      const hexSection = this._buildHexDump(bytes);
      wrap.appendChild(hexSection);
      return wrap;
    }

    // Successfully decompressed - determine inner file name
    let innerName = gzInfo.originalName || (fileName || 'file').replace(/\.(gz|gzip)$/i, '') || 'decompressed';
    // If no extension after stripping .gz, try to detect from content
    if (!innerName.includes('.') || innerName === fileName) {
      innerName = this._guessFilename(decompressed, innerName);
    }

    const decompInfo = document.createElement('div'); decompInfo.style.cssText = 'padding:0 20px 12px;';
    const compressionRatio = decompressed.length > 0 ? ((1 - bytes.length / decompressed.length) * 100).toFixed(1) : '0.0';
    decompInfo.innerHTML = `<p><strong>Decompressed size:</strong> ${this._fmtBytes(decompressed.length)}</p>` +
      `<p><strong>Compression ratio:</strong> ${compressionRatio}%</p>`;
    wrap.appendChild(decompInfo);

    // Check if decompressed content is a TAR archive
    if (this._isTar(decompressed)) {
      const tarBanner = document.createElement('div'); tarBanner.className = 'doc-extraction-banner';
      tarBanner.style.marginTop = '12px';
      tarBanner.innerHTML = '<strong>TAR Archive Detected</strong> — click any file to open it for analysis.';
      wrap.appendChild(tarBanner);

      return this._renderTarContents(wrap, decompressed, fileName);
    }

    // Not a TAR — offer to open the decompressed file for analysis
    const openDiv = document.createElement('div'); openDiv.style.cssText = 'padding:12px 20px;';
    const openBtn = document.createElement('button');
    openBtn.className = 'zip-extract-btn';
    openBtn.style.cssText = 'padding:8px 16px;background:#0af;color:#000;border:none;border-radius:4px;cursor:pointer;font-weight:600;';
    openBtn.textContent = `Open "${innerName}" for analysis`;
    openBtn.addEventListener('click', () => {
      const file = new File([decompressed], innerName, { type: 'application/octet-stream' });
      wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
    });
    openDiv.appendChild(openBtn);
    wrap.appendChild(openDiv);

    // Show preview of decompressed content
    const previewDiv = document.createElement('div'); previewDiv.style.cssText = 'margin-top:12px;';
    const previewHeader = document.createElement('div');
    previewHeader.style.cssText = 'padding:8px 20px;background:rgba(0,0,0,0.2);border-top:1px solid rgba(255,255,255,0.1);font-weight:600;';
    previewHeader.textContent = 'Decompressed Content Preview';
    previewDiv.appendChild(previewHeader);

    // Check if it looks like text
    const isText = this._looksLikeText(decompressed.subarray(0, 1024));
    if (isText) {
      const textPre = document.createElement('pre');
      textPre.style.cssText = 'margin:0;padding:12px 20px;background:rgba(0,0,0,0.15);max-height:300px;overflow:auto;white-space:pre-wrap;word-break:break-all;font-size:12px;';
      const preview = new TextDecoder('utf-8', { fatal: false }).decode(decompressed.subarray(0, 8192));
      textPre.textContent = preview + (decompressed.length > 8192 ? '\n\n... (truncated)' : '');
      previewDiv.appendChild(textPre);
    } else {
      const hexPane = this._buildHexDump(decompressed, 4096);
      previewDiv.appendChild(hexPane);
    }
    wrap.appendChild(previewDiv);

    return wrap;
  }

  _parseGzipHeader(bytes) {
    const info = { method: null, originalName: null, mtime: null };
    if (bytes.length < 10) return info;

    // Byte 2: compression method (8 = deflate)
    if (bytes[2] === 0x08) info.method = 'Deflate';

    // Byte 3: flags
    const flags = bytes[3];
    const FTEXT = 0x01, FHCRC = 0x02, FEXTRA = 0x04, FNAME = 0x08, FCOMMENT = 0x10;

    // Bytes 4-7: modification time (Unix timestamp)
    const mtime = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24);
    if (mtime > 0) {
      try {
        info.mtime = new Date(mtime * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
      } catch (e) {}
    }

    // Parse optional fields
    let offset = 10;

    // FEXTRA: skip extra field
    if (flags & FEXTRA) {
      if (offset + 2 > bytes.length) return info;
      const xlen = bytes[offset] | (bytes[offset + 1] << 8);
      offset += 2 + xlen;
    }

    // FNAME: original file name (null-terminated)
    if (flags & FNAME) {
      const start = offset;
      while (offset < bytes.length && bytes[offset] !== 0) offset++;
      if (offset > start) {
        info.originalName = new TextDecoder('latin1').decode(bytes.subarray(start, offset));
      }
      offset++; // skip null terminator
    }

    return info;
  }

  _guessFilename(bytes, baseName) {
    // Check for common file signatures
    if (bytes[0] === 0x50 && bytes[1] === 0x4B) return baseName + '.zip';
    if (bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46) return baseName + '.elf';
    if (bytes[0] === 0x4D && bytes[1] === 0x5A) return baseName + '.exe';
    if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return baseName + '.pdf';
    if (this._isTar(bytes)) return baseName + '.tar';
    // Check for text/script content
    if (this._looksLikeText(bytes.subarray(0, 512))) {
      const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 256)).toLowerCase();
      if (text.startsWith('<?xml')) return baseName + '.xml';
      if (text.startsWith('<!doctype html') || text.startsWith('<html')) return baseName + '.html';
      if (text.startsWith('{') || text.startsWith('[')) return baseName + '.json';
      return baseName + '.txt';
    }
    return baseName;
  }

  _looksLikeText(bytes) {
    if (bytes.length === 0) return false;
    let printable = 0;
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d) printable++;
    }
    return printable / bytes.length > 0.85;
  }

  // ── TAR handling ──────────────────────────────────────────────────────────

  _isTar(bytes) {
    // Check for "ustar" magic at offset 257 (POSIX tar)
    if (bytes.length > 262) {
      const magic = String.fromCharCode(bytes[257], bytes[258], bytes[259], bytes[260], bytes[261]);
      if (magic === 'ustar') return true;
    }
    // Also check for older GNU tar format
    if (bytes.length > 512) {
      // Check if first block looks like a tar header (filename at 0, null padding, size at 124)
      // Tar headers have specific structure: 100 bytes filename, then mode/uid/gid/size fields
      const nameEnd = bytes.indexOf(0);
      if (nameEnd > 0 && nameEnd < 100) {
        // Check if there's a valid octal size at offset 124
        const sizeBytes = bytes.subarray(124, 135);
        const sizeStr = String.fromCharCode(...sizeBytes).replace(/\0/g, '').trim();
        if (/^[0-7]+$/.test(sizeStr)) return true;
      }
    }
    return false;
  }

  _handleTar(wrap, bytes, fileName) {
    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>TAR Archive Contents</strong> — click any file to extract and analyze.';
    wrap.appendChild(banner);

    return this._renderTarContents(wrap, bytes, fileName);
  }

  _renderTarContents(wrap, bytes, fileName) {
    const entries = this._parseTar(bytes);

    if (!entries.length) {
      const p = document.createElement('p'); p.style.cssText = 'color:#888;padding:20px;text-align:center';
      p.textContent = 'Archive is empty or could not be parsed.';
      wrap.appendChild(p);
      return wrap;
    }

    // Summary
    const dirs = entries.filter(e => e.dir).length;
    const files = entries.filter(e => !e.dir).length;
    const totalSize = entries.reduce((s, e) => s + (e.size || 0), 0);

    const summ = document.createElement('div'); summ.className = 'zip-summary';
    summ.textContent = `${files} file${files !== 1 ? 's' : ''}, ${dirs} folder${dirs !== 1 ? 's' : ''} — ${this._fmtBytes(totalSize)} total`;
    wrap.appendChild(summ);

    // Warnings
    const warnings = this._checkWarnings(entries);
    if (warnings.length) {
      const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
      for (const w of warnings) {
        const d = document.createElement('div'); d.className = `zip-warning zip-warning-${w.sev}`;
        d.textContent = w.msg; warnDiv.appendChild(d);
      }
      wrap.appendChild(warnDiv);
    }

    // File table
    const scr = document.createElement('div'); scr.style.cssText = 'overflow:auto;max-height:calc(100vh - 220px)';
    const tbl = document.createElement('table'); tbl.className = 'zip-table';

    const thead = document.createElement('thead');
    const hr = document.createElement('tr');
    for (const h of ['', 'Path', 'Size', 'Date', '']) {
      const th = document.createElement('th'); th.textContent = h; hr.appendChild(th);
    }
    thead.appendChild(hr); tbl.appendChild(thead);

    const tbody = document.createElement('tbody');
    for (const entry of entries) {
      const tr = document.createElement('tr');
      const ext = (entry.path || '').split('.').pop().toLowerCase();
      const isDangerous = !entry.dir && ZipRenderer.EXEC_EXTS.has(ext);
      const isDouble = this._isDoubleExt(entry.path);
      if (isDangerous || isDouble) tr.className = 'zip-row-danger';

      if (!entry.dir) {
        tr.classList.add('zip-row-clickable');
        tr.addEventListener('click', () => this._extractTarEntry(bytes, entry, wrap));
      }

      // Icon
      const tdIcon = document.createElement('td'); tdIcon.className = 'zip-icon';
      tdIcon.textContent = entry.dir ? '📁' : (isDangerous ? '⚠️' : this._getFileIcon(entry.path));
      tr.appendChild(tdIcon);

      // Path
      const tdPath = document.createElement('td'); tdPath.className = 'zip-path';
      tdPath.textContent = entry.path;
      if (isDangerous) { const badge = document.createElement('span'); badge.className = 'zip-badge-danger'; badge.textContent = 'EXECUTABLE'; tdPath.appendChild(badge); }
      if (isDouble) { const badge = document.createElement('span'); badge.className = 'zip-badge-danger'; badge.textContent = 'DOUBLE EXT'; tdPath.appendChild(badge); }
      tr.appendChild(tdPath);

      // Size
      const tdSize = document.createElement('td'); tdSize.className = 'zip-size';
      tdSize.textContent = entry.dir ? '—' : this._fmtBytes(entry.size);
      tr.appendChild(tdSize);

      // Date
      const tdDate = document.createElement('td'); tdDate.className = 'zip-date';
      tdDate.textContent = entry.mtime ? entry.mtime.toISOString().slice(0, 16).replace('T', ' ') : '—';
      tr.appendChild(tdDate);

      // Action column
      const tdAction = document.createElement('td'); tdAction.className = 'zip-action';
      if (!entry.dir) {
        const openBtn = document.createElement('span'); openBtn.className = 'zip-badge-open';
        openBtn.textContent = '🔍 Open';
        openBtn.title = `Open ${entry.path.split('/').pop()} for analysis`;
        openBtn.addEventListener('click', (ev) => {
          ev.stopPropagation();
          this._extractTarEntry(bytes, entry, wrap);
        });
        tdAction.appendChild(openBtn);
      }
      tr.appendChild(tdAction);

      tbody.appendChild(tr);
    }

    tbl.appendChild(tbody); scr.appendChild(tbl); wrap.appendChild(scr);

    // Store bytes for extraction
    this._tarBytes = bytes;

    return wrap;
  }

  _parseTar(bytes) {
    const entries = [];
    let offset = 0;

    while (offset + 512 <= bytes.length && entries.length < PARSER_LIMITS.MAX_ENTRIES) {
      // Each tar entry starts with a 512-byte header
      const header = bytes.subarray(offset, offset + 512);

      // Check if this is a null block (end of archive)
      if (header.every(b => b === 0)) break;

      // Parse header fields
      const name = this._tarString(header, 0, 100);
      if (!name) break;

      const mode = this._tarString(header, 100, 8);
      const uid = this._tarOctal(header, 108, 8);
      const gid = this._tarOctal(header, 116, 8);
      const size = this._tarOctal(header, 124, 12);
      const mtime = this._tarOctal(header, 136, 12);
      const typeFlag = header[156];
      const linkName = this._tarString(header, 157, 100);
      const prefix = this._tarString(header, 345, 155);

      // Combine prefix and name for full path
      const fullPath = prefix ? prefix + '/' + name : name;

      // Type: '0' or 0 = regular file, '5' = directory, '2' = symlink
      const isDir = typeFlag === 53 || typeFlag === 0x35 || fullPath.endsWith('/');

      entries.push({
        path: fullPath.replace(/\/$/, ''),
        name: fullPath.split('/').pop(),
        dir: isDir,
        size: isDir ? 0 : size,
        mtime: mtime > 0 ? new Date(mtime * 1000) : null,
        offset: offset + 512, // Data starts after header
        linkName: linkName || null,
      });

      // Move to next entry: header (512) + data (rounded up to 512-byte blocks)
      const dataBlocks = Math.ceil(size / 512);
      offset += 512 + dataBlocks * 512;
    }

    return entries;
  }

  _tarString(header, offset, length) {
    let end = offset;
    while (end < offset + length && header[end] !== 0) end++;
    if (end === offset) return '';
    return new TextDecoder('utf-8', { fatal: false }).decode(header.subarray(offset, end));
  }

  _tarOctal(header, offset, length) {
    const str = this._tarString(header, offset, length).trim();
    return str ? parseInt(str, 8) || 0 : 0;
  }

  _extractTarEntry(bytes, entry, wrap) {
    if (entry.dir || !entry.size) return;

    const data = bytes.subarray(entry.offset, entry.offset + entry.size);
    const name = entry.path.split('/').pop();
    const file = new File([data], name, { type: 'application/octet-stream' });
    wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
  }

  _getFileIcon(path) {
    const ext = (path || '').split('.').pop().toLowerCase();
    if (['exe', 'dll', 'scr', 'com', 'msi'].includes(ext)) return '⚙️';
    if (['bat', 'cmd', 'ps1', 'vbs', 'js', 'sh'].includes(ext)) return '📜';
    if (['doc', 'docx', 'docm', 'odt', 'rtf'].includes(ext)) return '📄';
    if (['xls', 'xlsx', 'xlsm', 'ods', 'csv'].includes(ext)) return '📊';
    if (['ppt', 'pptx', 'pptm', 'odp'].includes(ext)) return '📽️';
    if (['pdf'].includes(ext)) return '📕';
    if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return '📦';
    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg'].includes(ext)) return '🖼️';
    if (['txt', 'log', 'md'].includes(ext)) return '📝';
    if (['html', 'htm', 'xml', 'json'].includes(ext)) return '🌐';
    return '📄';
  }

  // ── Render ZIP contents table with clickable rows ─────────────────────────

  _renderZipContents(wrap, zip, buffer, fileName) {
    const entries = [];
    let truncated = false;
    zip.forEach((path, entry) => {
      if (entries.length >= PARSER_LIMITS.MAX_ENTRIES) { truncated = true; return; }
      const uncompSize = entry._data ? (entry._data.uncompressedSize || 0) : 0;
      const compSize = entry._data ? (entry._data.compressedSize || 0) : 0;
      // Per-entry compression ratio check — skip entries with ratio > MAX_RATIO
      if (compSize > 0 && uncompSize / compSize > PARSER_LIMITS.MAX_RATIO) {
        truncated = true; // flag that some entries were skipped
        return;
      }
      entries.push({
        path,
        dir: entry.dir,
        size: uncompSize,
        date: entry.date || null,
        compressed: compSize,
      });
    });

    if (truncated) {
      const warnDiv = document.createElement('div');
      warnDiv.className = 'zip-warnings';
      const d = document.createElement('div');
      d.className = 'zip-warning zip-warning-high';
      d.textContent = `⚠ Archive processing was limited — entry count capped at ${PARSER_LIMITS.MAX_ENTRIES.toLocaleString()} or entries with compression ratio > ${PARSER_LIMITS.MAX_RATIO}× were skipped (potential zip bomb).`;
      warnDiv.appendChild(d);
      wrap.appendChild(warnDiv);
    }

    if (!entries.length) {
      const p = document.createElement('p'); p.style.cssText = 'color:#888;padding:20px;text-align:center';
      p.textContent = 'Archive is empty.'; wrap.appendChild(p); return wrap;
    }

    // Summary
    const dirs = entries.filter(e => e.dir).length;
    const files = entries.filter(e => !e.dir).length;
    const totalSize = entries.reduce((s, e) => s + e.size, 0);
    const summ = document.createElement('div'); summ.className = 'zip-summary';
    summ.textContent = `${files} file${files !== 1 ? 's' : ''}, ${dirs} folder${dirs !== 1 ? 's' : ''} — ${this._fmtBytes(totalSize)} uncompressed`;
    wrap.appendChild(summ);

    // Warnings
    const warnings = this._checkWarnings(entries);
    if (warnings.length) {
      const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
      for (const w of warnings) {
        const d = document.createElement('div'); d.className = `zip-warning zip-warning-${w.sev}`;
        d.textContent = w.msg; warnDiv.appendChild(d);
      }
      wrap.appendChild(warnDiv);
    }

    // Table
    const scr = document.createElement('div'); scr.style.cssText = 'overflow:auto;max-height:calc(100vh - 200px)';
    const tbl = document.createElement('table'); tbl.className = 'zip-table';
    const thead = document.createElement('thead');
    const hr = document.createElement('tr');
    for (const h of ['', 'Path', 'Size', 'Compressed', 'Date', '']) {
      const th = document.createElement('th'); th.textContent = h; hr.appendChild(th);
    }
    thead.appendChild(hr); tbl.appendChild(thead);

    const tbody = document.createElement('tbody');
    const sorted = entries.slice().sort((a, b) => a.path.localeCompare(b.path));
    for (const e of sorted) {
      const tr = document.createElement('tr');
      const ext = e.path.split('.').pop().toLowerCase();
      const isDangerous = !e.dir && ZipRenderer.EXEC_EXTS.has(ext);
      const isDouble = this._isDoubleExt(e.path);
      if (isDangerous || isDouble) tr.className = 'zip-row-danger';

      // Highlight file rows on hover (clickable via Open button)
      if (!e.dir) {
        tr.classList.add('zip-row-clickable');
      }

      // Icon
      const tdIcon = document.createElement('td'); tdIcon.className = 'zip-icon';
      tdIcon.textContent = e.dir ? '📁' : (isDangerous ? '⚠️' : '📄'); tr.appendChild(tdIcon);

      // Path
      const tdPath = document.createElement('td'); tdPath.className = 'zip-path';
      tdPath.textContent = e.path;
      if (isDangerous) { const badge = document.createElement('span'); badge.className = 'zip-badge-danger'; badge.textContent = 'EXECUTABLE'; tdPath.appendChild(badge); }
      if (isDouble) { const badge = document.createElement('span'); badge.className = 'zip-badge-danger'; badge.textContent = 'DOUBLE EXT'; tdPath.appendChild(badge); }
      tr.appendChild(tdPath);

      // Size
      const tdSize = document.createElement('td'); tdSize.className = 'zip-size';
      tdSize.textContent = e.dir ? '—' : this._fmtBytes(e.size); tr.appendChild(tdSize);

      // Compressed
      const tdComp = document.createElement('td'); tdComp.className = 'zip-size';
      tdComp.textContent = e.dir ? '—' : this._fmtBytes(e.compressed); tr.appendChild(tdComp);

      // Date
      const tdDate = document.createElement('td'); tdDate.className = 'zip-date';
      tdDate.textContent = e.date ? e.date.toISOString().slice(0, 19).replace('T', ' ') : '—';
      tr.appendChild(tdDate);

      // Action column
      const tdAction = document.createElement('td'); tdAction.className = 'zip-action';
      if (!e.dir) {
        const openBtn = document.createElement('span'); openBtn.className = 'zip-badge-open';
        openBtn.textContent = '🔍 Open';
        openBtn.title = `Open ${e.path.split('/').pop()} for analysis`;
        openBtn.addEventListener('click', (ev) => {
          ev.stopPropagation();
          this._extractAndOpen(zip, e.path, wrap);
        });
        tdAction.appendChild(openBtn);
      }
      tr.appendChild(tdAction);

      tbody.appendChild(tr);
    }
    tbl.appendChild(tbody); scr.appendChild(tbl); wrap.appendChild(scr);
    return wrap;
  }

  // ── Extract file from ZIP and dispatch open event ─────────────────────────

  async _extractAndOpen(zip, path, wrap) {
    const entry = zip.file(path);
    if (!entry) return;

    try {
      const data = await entry.async('arraybuffer');
      const name = path.split('/').pop();
      const file = new File([data], name, { type: 'application/octet-stream' });
      // Dispatch custom event for the app to handle
      wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
    } catch (e) {
      // May be encrypted or corrupted
      console.warn('Failed to extract:', path, e.message);
    }
  }

  // ── Password-protected ZIP handling ───────────────────────────────────────

  async _handleEncrypted(wrap, buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    // Show encryption banner
    const encBanner = document.createElement('div'); encBanner.className = 'zip-warnings';
    const w = document.createElement('div'); w.className = 'zip-warning zip-warning-high';
    w.textContent = '🔒 Password-protected archive detected — attempting common passwords…';
    encBanner.appendChild(w);
    wrap.appendChild(encBanner);

    // Try common passwords
    const result = await this._tryPasswords(bytes, ZipRenderer.PASSWORD_LIST);

    if (result.success) {
      // Password found!
      encBanner.innerHTML = '';
      const successW = document.createElement('div'); successW.className = 'zip-warning zip-warning-medium';
      successW.innerHTML = `🔓 <strong>Password cracked:</strong> "${escHtml(result.password)}" — archive decrypted successfully`;
      encBanner.appendChild(successW);

      // Load decrypted ZIP
      try {
        const zip = await JSZip.loadAsync(result.decryptedBuffer);
        this._zip = zip;
        return this._renderZipContents(wrap, zip, result.decryptedBuffer, fileName);
      } catch (e) {
        const errP = document.createElement('p'); errP.style.cssText = 'color:var(--risk-high);padding:10px;';
        errP.textContent = 'Decryption appeared successful but ZIP parsing failed: ' + e.message;
        wrap.appendChild(errP);
      }
    } else {
      // Password not found
      encBanner.innerHTML = '';
      const failW = document.createElement('div'); failW.className = 'zip-warning zip-warning-high';
      failW.textContent = `🔒 Password not in common list (tried: ${ZipRenderer.PASSWORD_LIST.join(', ')})`;
      encBanner.appendChild(failW);

      // Show manual password input
      const inputDiv = document.createElement('div'); inputDiv.style.cssText = 'padding:12px;display:flex;gap:8px;align-items:center;';
      const input = document.createElement('input');
      input.type = 'text'; input.placeholder = 'Enter password…'; input.className = 'ext-search';
      input.style.cssText = 'flex:1;max-width:300px;';
      const btn = document.createElement('button'); btn.className = 'tb-btn';
      btn.textContent = '🔑 Try Password';
      btn.addEventListener('click', async () => {
        const pwd = input.value.trim();
        if (!pwd) return;
        btn.disabled = true; btn.textContent = 'Trying…';
        const r = await this._tryPasswords(bytes, [pwd]);
        if (r.success) {
          try {
            const zip = await JSZip.loadAsync(r.decryptedBuffer);
            this._zip = zip;
            // Clear and re-render
            while (wrap.firstChild) wrap.removeChild(wrap.firstChild);
            const successBanner = document.createElement('div'); successBanner.className = 'doc-extraction-banner';
            successBanner.innerHTML = `<strong>Archive Contents</strong> — decrypted with password "<strong>${escHtml(pwd)}</strong>". Click any file to open it.`;
            wrap.appendChild(successBanner);
            this._renderZipContents(wrap, zip, r.decryptedBuffer, fileName);
          } catch (e) {
            btn.disabled = false; btn.textContent = '🔑 Try Password';
            input.style.borderColor = 'var(--risk-high)';
          }
        } else {
          btn.disabled = false; btn.textContent = '🔑 Try Password';
          input.style.borderColor = 'var(--risk-high)';
          input.value = ''; input.placeholder = 'Wrong password — try again…';
        }
      });
      input.addEventListener('keydown', e => { if (e.key === 'Enter') btn.click(); });
      inputDiv.appendChild(input); inputDiv.appendChild(btn);
      wrap.appendChild(inputDiv);

      // Still show file listing from central directory (names are not encrypted)
      this._showEncryptedListing(wrap, bytes);
    }

    return wrap;
  }

  // ── Show file listing from encrypted ZIP (names visible in central dir) ───

  _showEncryptedListing(wrap, bytes) {
    // Parse central directory to show filenames even when encrypted
    const entries = this._parseCentralDirectory(bytes);
    if (!entries.length) return;

    const summ = document.createElement('div'); summ.className = 'zip-summary';
    summ.textContent = `${entries.length} file(s) in encrypted archive (contents locked)`;
    wrap.appendChild(summ);

    const scr = document.createElement('div'); scr.style.cssText = 'overflow:auto;max-height:calc(100vh - 300px)';
    const tbl = document.createElement('table'); tbl.className = 'zip-table';
    const thead = document.createElement('thead');
    const hr = document.createElement('tr');
    for (const h of ['', 'Path', 'Size', 'Compressed']) {
      const th = document.createElement('th'); th.textContent = h; hr.appendChild(th);
    }
    thead.appendChild(hr); tbl.appendChild(thead);
    const tbody = document.createElement('tbody');

    for (const e of entries) {
      const tr = document.createElement('tr');
      const ext = e.name.split('.').pop().toLowerCase();
      const isDangerous = ZipRenderer.EXEC_EXTS.has(ext);
      if (isDangerous) tr.className = 'zip-row-danger';
      tr.style.opacity = '0.6';

      const tdIcon = document.createElement('td'); tdIcon.className = 'zip-icon';
      tdIcon.textContent = isDangerous ? '⚠️🔒' : '📄🔒'; tr.appendChild(tdIcon);

      const tdPath = document.createElement('td'); tdPath.className = 'zip-path';
      tdPath.textContent = e.name;
      if (isDangerous) { const badge = document.createElement('span'); badge.className = 'zip-badge-danger'; badge.textContent = 'EXECUTABLE'; tdPath.appendChild(badge); }
      tr.appendChild(tdPath);

      const tdSize = document.createElement('td'); tdSize.className = 'zip-size';
      tdSize.textContent = this._fmtBytes(e.uncompSize); tr.appendChild(tdSize);

      const tdComp = document.createElement('td'); tdComp.className = 'zip-size';
      tdComp.textContent = this._fmtBytes(e.compSize); tr.appendChild(tdComp);

      tbody.appendChild(tr);
    }
    tbl.appendChild(tbody); scr.appendChild(tbl); wrap.appendChild(scr);
  }

  // ── ZipCrypto decryption implementation ───────────────────────────────────

  async _tryPasswords(bytes, passwords) {
    const entries = this._parseCentralDirectory(bytes);
    if (!entries.length) return { success: false };

    // Find first non-directory entry to test against
    const testEntry = entries.find(e => e.compSize > 0);
    if (!testEntry) return { success: false };

    for (const password of passwords) {
      try {
        const decrypted = this._decryptZip(bytes, password, entries);
        if (decrypted) {
          return { success: true, password, decryptedBuffer: decrypted.buffer };
        }
      } catch (e) { /* password didn't work */ }
    }
    return { success: false };
  }

  _decryptZip(zipBytes, password, entries) {
    // Create a copy and decrypt all entries in-place
    const out = new Uint8Array(zipBytes.length);
    out.set(zipBytes);

    let anyDecrypted = false;

    for (const entry of entries) {
      if (!entry.encrypted || entry.compSize === 0) continue;

      // Initialize ZipCrypto keys from password
      const keys = this._initKeys(password);

      // Find the local file header for this entry
      const localOff = entry.localHeaderOffset;
      if (localOff + 30 > out.length) continue;

      // Read local file header to get actual data offset
      const nameLen = out[localOff + 26] | (out[localOff + 27] << 8);
      const extraLen = out[localOff + 28] | (out[localOff + 29] << 8);
      const dataOff = localOff + 30 + nameLen + extraLen;

      // Encrypted data = 12-byte encryption header + compressed data
      const encDataLen = entry.compSize;
      if (dataOff + encDataLen > out.length) continue;

      // Decrypt the 12-byte header
      const header = new Uint8Array(12);
      for (let i = 0; i < 12; i++) {
        header[i] = this._decryptByte(keys, out[dataOff + i]);
      }

      // Validate: last byte of header should match high byte of CRC or file time
      // Traditional ZipCrypto uses CRC >> 24 for validation
      const crcCheck = (entry.crc32 >>> 24) & 0xFF;
      const timeCheck = (entry.modTime >>> 8) & 0xFF;
      if (header[11] !== crcCheck && header[11] !== timeCheck) {
        continue; // Wrong password
      }

      // Decrypt the rest of the data
      for (let i = 12; i < encDataLen; i++) {
        out[dataOff + i] = this._decryptByte(keys, out[dataOff + i]);
      }

      // Shift decrypted data to remove 12-byte header
      // Update compressed size in local and central headers
      const newCompSize = encDataLen - 12;
      out.copyWithin(dataOff, dataOff + 12, dataOff + encDataLen);

      // Update local file header: compressed size and clear encryption flag
      out[localOff + 18] = newCompSize & 0xFF;
      out[localOff + 19] = (newCompSize >> 8) & 0xFF;
      out[localOff + 20] = (newCompSize >> 16) & 0xFF;
      out[localOff + 21] = (newCompSize >> 24) & 0xFF;
      // Clear encryption bit (bit 0 of general purpose flag)
      out[localOff + 6] &= 0xFE;

      anyDecrypted = true;
    }

    if (!anyDecrypted) return null;

    // Also update central directory entries
    for (const entry of entries) {
      if (!entry.encrypted) continue;
      const cdOff = entry.centralDirOffset;
      if (cdOff + 46 > out.length) continue;

      const newCompSize = entry.compSize - 12;
      out[cdOff + 20] = newCompSize & 0xFF;
      out[cdOff + 21] = (newCompSize >> 8) & 0xFF;
      out[cdOff + 22] = (newCompSize >> 16) & 0xFF;
      out[cdOff + 23] = (newCompSize >> 24) & 0xFF;
      // Clear encryption bit
      out[cdOff + 8] &= 0xFE;
    }

    return out;
  }

  // ── ZipCrypto key management ──────────────────────────────────────────────

  _initKeys(password) {
    const keys = [0x12345678, 0x23456789, 0x34567890];
    for (let i = 0; i < password.length; i++) {
      this._updateKeys(keys, password.charCodeAt(i));
    }
    return keys;
  }

  _updateKeys(keys, byte) {
    keys[0] = this._crc32Update(keys[0], byte);
    keys[1] = (keys[1] + (keys[0] & 0xFF)) >>> 0;
    keys[1] = (Math.imul(keys[1], 134775813) + 1) >>> 0; // Math.imul for proper 32-bit multiply
    keys[2] = this._crc32Update(keys[2], (keys[1] >>> 24) & 0xFF);
  }

  _decryptByte(keys, encByte) {
    const temp = (keys[2] | 2) & 0xFFFF; // Must be 16-bit to avoid JS integer overflow
    const decByte = (encByte ^ ((temp * (temp ^ 1)) >>> 8)) & 0xFF;
    this._updateKeys(keys, decByte);
    return decByte;
  }

  _crc32Update(crc, byte) {
    return (ZipRenderer._CRC32_TABLE[((crc ^ byte) & 0xFF)] ^ (crc >>> 8)) >>> 0;
  }

  // ── CRC-32 lookup table (precomputed) ─────────────────────────────────────

  static _CRC32_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) {
        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[n] = c >>> 0;
    }
    return table;
  })();

  // ── ZIP structure parsing ─────────────────────────────────────────────────

  _detectEncryption(bytes) {
    // Quick check: look for PK signature + encryption bit in first local header
    if (bytes.length < 30) return false;
    if (bytes[0] !== 0x50 || bytes[1] !== 0x4B || bytes[2] !== 0x03 || bytes[3] !== 0x04) return false;
    const flags = bytes[6] | (bytes[7] << 8);
    return !!(flags & 0x01); // Bit 0 = encrypted
  }

  async _hasEncryptedEntries(zip) {
    // Try to decompress the first non-directory entry
    for (const [, entry] of Object.entries(zip.files)) {
      if (!entry.dir && entry._data && entry._data.compressedSize > 0) {
        try { await entry.async('uint8array'); return false; }
        catch (e) { return true; }
      }
    }
    return false;
  }

  _parseCentralDirectory(bytes) {
    const entries = [];
    // Find End of Central Directory record (search backwards for PK\x05\x06)
    let eocdOff = -1;
    for (let i = bytes.length - 22; i >= 0 && i >= bytes.length - 65557; i--) {
      if (bytes[i] === 0x50 && bytes[i + 1] === 0x4B && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) {
        eocdOff = i; break;
      }
    }
    if (eocdOff < 0) return entries;

    const cdEntries = bytes[eocdOff + 10] | (bytes[eocdOff + 11] << 8);
    let cdOffset = bytes[eocdOff + 16] | (bytes[eocdOff + 17] << 8) |
      (bytes[eocdOff + 18] << 16) | ((bytes[eocdOff + 19] << 24) >>> 0);

    for (let i = 0; i < cdEntries && cdOffset + 46 <= bytes.length; i++) {
      // Verify central dir signature PK\x01\x02
      if (bytes[cdOffset] !== 0x50 || bytes[cdOffset + 1] !== 0x4B ||
        bytes[cdOffset + 2] !== 0x01 || bytes[cdOffset + 3] !== 0x02) break;

      const flags = bytes[cdOffset + 8] | (bytes[cdOffset + 9] << 8);
      const method = bytes[cdOffset + 10] | (bytes[cdOffset + 11] << 8);
      const modTime = bytes[cdOffset + 12] | (bytes[cdOffset + 13] << 8);
      const crc32 = (bytes[cdOffset + 16] | (bytes[cdOffset + 17] << 8) |
        (bytes[cdOffset + 18] << 16) | ((bytes[cdOffset + 19] << 24) >>> 0)) >>> 0;
      const compSize = bytes[cdOffset + 20] | (bytes[cdOffset + 21] << 8) |
        (bytes[cdOffset + 22] << 16) | ((bytes[cdOffset + 23] << 24) >>> 0);
      const uncompSize = bytes[cdOffset + 24] | (bytes[cdOffset + 25] << 8) |
        (bytes[cdOffset + 26] << 16) | ((bytes[cdOffset + 27] << 24) >>> 0);
      const nameLen = bytes[cdOffset + 28] | (bytes[cdOffset + 29] << 8);
      const extraLen = bytes[cdOffset + 30] | (bytes[cdOffset + 31] << 8);
      const commentLen = bytes[cdOffset + 32] | (bytes[cdOffset + 33] << 8);
      const localHeaderOffset = bytes[cdOffset + 42] | (bytes[cdOffset + 43] << 8) |
        (bytes[cdOffset + 44] << 16) | ((bytes[cdOffset + 45] << 24) >>> 0);

      let name = '';
      for (let j = 0; j < nameLen && cdOffset + 46 + j < bytes.length; j++) {
        name += String.fromCharCode(bytes[cdOffset + 46 + j]);
      }

      const encrypted = !!(flags & 0x01);
      const isAES = !!(flags & 0x40); // Strong encryption flag

      entries.push({
        name, encrypted, isAES, method, modTime, crc32,
        compSize, uncompSize, localHeaderOffset,
        centralDirOffset: cdOffset,
      });

      cdOffset += 46 + nameLen + extraLen + commentLen;
    }

    return entries;
  }

  // ── Security analysis ─────────────────────────────────────────────────────

  async analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    // ── Gzip handling ────────────────────────────────────────────────────────
    if (bytes[0] === 0x1F && bytes[1] === 0x8B) {
      f.externalRefs.push({ type: IOC.INFO, url: 'Gzip compressed file', severity: 'info' });

      // Try to decompress and analyze contents
      try {
        const decompressed = await Decompressor.inflate(bytes, 'gzip');
        if (decompressed) {
          f.metadata.compressedSize = bytes.length;
          f.metadata.decompressedSize = decompressed.length;
          f.metadata.compressionRatio = decompressed.length > 0 ? ((1 - bytes.length / decompressed.length) * 100).toFixed(1) + '%' : 'N/A';

          // Check if it's a tar archive
          if (this._isTar(decompressed)) {
            const entries = this._parseTar(decompressed);
            return this._analyzeArchiveEntries(f, entries);
          }
        }
      } catch (e) {
        f.externalRefs.push({ type: IOC.INFO, url: 'Gzip decompression failed — file may be corrupted', severity: 'medium' });
      }
      return f;
    }

    // ── TAR handling ─────────────────────────────────────────────────────────
    if (this._isTar(bytes)) {
      f.externalRefs.push({ type: IOC.INFO, url: 'TAR archive', severity: 'info' });
      const entries = this._parseTar(bytes);
      return this._analyzeArchiveEntries(f, entries);
    }

    // ── ZIP encryption check ─────────────────────────────────────────────────
    if (this._detectEncryption(bytes)) {
      f.externalRefs.push({ type: IOC.PATTERN, url: 'Password-protected archive detected', severity: 'high' });
      f.risk = 'high';

      // Try to crack password
      const result = await this._tryPasswords(bytes, ZipRenderer.PASSWORD_LIST);
      if (result.success) {
        f.externalRefs.push({ type: IOC.PATTERN, url: `Archive password cracked: "${result.password}"`, severity: 'high' });
      }

      // Show filenames from central directory
      const cdEntries = this._parseCentralDirectory(bytes);
      const dangerous = cdEntries.filter(e => ZipRenderer.EXEC_EXTS.has(e.name.split('.').pop().toLowerCase()));
      if (dangerous.length) {
        f.externalRefs.push({ type: IOC.PATTERN, url: `${dangerous.length} executable/script file(s) inside encrypted archive`, severity: 'high' });
        for (const e of dangerous) f.externalRefs.push({ type: IOC.FILE_PATH, url: e.name, severity: 'high' });
      }
      return f;
    }

    // ── ZIP handling ─────────────────────────────────────────────────────────
    let zip;
    try { zip = await JSZip.loadAsync(buffer); } catch (e) {
      // Not a valid ZIP — check for other archive formats
      if (bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72) {
        f.externalRefs.push({ type: IOC.INFO, url: 'RAR archive — extraction not supported in-browser', severity: 'info' });
      } else if (bytes[0] === 0x37 && bytes[1] === 0x7A && bytes[2] === 0xBC && bytes[3] === 0xAF) {
        f.externalRefs.push({ type: IOC.INFO, url: '7-Zip archive — extraction not supported in-browser', severity: 'info' });
      } else if (bytes[0] === 0x4D && bytes[1] === 0x53 && bytes[2] === 0x43 && bytes[3] === 0x46) {
        f.externalRefs.push({ type: IOC.INFO, url: 'CAB archive — extraction not supported in-browser', severity: 'info' });
      } else {
        f.externalRefs.push({ type: IOC.INFO, url: 'Archive format not fully parseable', severity: 'info' });
      }
      return f;
    }

    const entries = [];
    zip.forEach((path, entry) => entries.push({ path, dir: entry.dir }));

    return this._analyzeArchiveEntries(f, entries);
  }

  _analyzeArchiveEntries(f, entries) {
    const warnings = this._checkWarnings(entries);
    for (const w of warnings) {
      f.externalRefs.push({ type: IOC.PATTERN, url: w.msg, severity: w.sev });
      if (w.sev === 'high') f.risk = 'high';
      else if (w.sev === 'medium' && f.risk !== 'high') f.risk = 'medium';
    }

    // Count dangerous files
    const dangerous = entries.filter(e => !e.dir && ZipRenderer.EXEC_EXTS.has((e.path || '').split('.').pop().toLowerCase()));
    if (dangerous.length) {
      f.externalRefs.push({ type: IOC.PATTERN, url: `${dangerous.length} executable/script file(s) inside archive`, severity: 'high' });
      f.risk = 'high';
    }
    for (const e of dangerous) {
      f.externalRefs.push({ type: IOC.FILE_PATH, url: e.path, severity: 'high' });
    }

    // ── macOS .app bundle detection ────────────────────────────────────────
    // Emit one IOC.FILE_PATH per unique bundle root, capped at APP_IOC_CAP.
    const bundles = this._findAppBundles(entries);
    if (bundles.size) {
      const roots = Array.from(bundles);
      const cap = ZipRenderer.APP_IOC_CAP;
      for (const root of roots.slice(0, cap)) {
        f.externalRefs.push({ type: IOC.FILE_PATH, url: root + '/', severity: 'medium' });
      }
      if (roots.length > cap) {
        f.externalRefs.push({
          type: IOC.INFO,
          url: `… and ${roots.length - cap} more .app bundle path(s) not shown`,
          severity: 'info',
        });
      }
    }

    return f;
  }

  // Return a Set of unique `.app` bundle root paths (e.g. "Foo.app",
  // "nested/.Bar.app") found among archive entries.
  _findAppBundles(entries) {
    const roots = new Set();
    for (const e of entries) {
      const p = e.path || e.name || '';
      const m = p.match(ZipRenderer.MACAPP_RE);
      if (!m) continue;
      // Reconstruct the full root path up to and including the .app segment.
      const idx = p.indexOf(m[1] + '/');
      if (idx < 0) continue;
      const root = p.slice(0, idx) + m[1];
      roots.add(root);
    }
    return roots;
  }


  // ── Warnings ────────────────────────────────────────────────────────────────

  _checkWarnings(entries) {
    const w = [];
    const files = entries.filter(e => !e.dir);

    const execs = files.filter(e => ZipRenderer.EXEC_EXTS.has((e.path || e.name || '').split('.').pop().toLowerCase()));
    if (execs.length) w.push({ sev: 'high', msg: `⚠ ${execs.length} executable/script file(s): ${execs.slice(0, 5).map(e => (e.path || e.name).split('/').pop()).join(', ')}${execs.length > 5 ? ' …' : ''}` });

    const doubles = files.filter(e => this._isDoubleExt(e.path || e.name || ''));
    if (doubles.length) w.push({ sev: 'high', msg: `⚠ Double-extension file(s) detected: ${doubles.slice(0, 3).map(e => (e.path || e.name).split('/').pop()).join(', ')}${doubles.length > 3 ? ' …' : ''}` });

    const nested = files.filter(e => /\.(zip|rar|7z|cab|gz|tar|iso|img)$/i.test(e.path || e.name || ''));
    if (nested.length) w.push({ sev: 'medium', msg: `📦 Nested archive(s): ${nested.slice(0, 3).map(e => (e.path || e.name).split('/').pop()).join(', ')}` });

    const lnks = files.filter(e => /\.lnk$/i.test(e.path || e.name || ''));
    if (lnks.length) w.push({ sev: 'high', msg: `⚠ Windows shortcut (.lnk) file(s) — common phishing technique` });

    const htas = files.filter(e => /\.hta$/i.test(e.path || e.name || ''));
    if (htas.length) w.push({ sev: 'high', msg: `⚠ HTA file(s) — can execute arbitrary scripts` });

    // Path traversal detection (Zip Slip vulnerability)
    const traversal = entries.filter(e => {
      const p = e.path || e.name || '';
      return p.includes('../') || p.includes('..\\') || p.startsWith('/') || /^[A-Za-z]:/.test(p);
    });
    if (traversal.length) w.push({ sev: 'high', msg: `⚠ Path traversal attempt detected (Zip Slip) — ${traversal.length} entry/entries with suspicious paths` });

    // ── macOS .app bundle detection ────────────────────────────────────────
    // Flag ZIP-wrapped `.app` bundles — the common delivery shape for
    // unsigned macOS malware outside the App Store. Mirrors the DMG
    // renderer's equivalent warnings for drag-to-install trojan layouts.
    const bundles = this._findAppBundles(entries);
    if (bundles.size) {
      const roots = Array.from(bundles);
      const sample = roots.slice(0, 3).map(r => r.split('/').pop()).join(', ');
      w.push({
        sev: 'high',
        msg: `⚠ ${roots.length} macOS .app bundle(s) inside archive: ${sample}${roots.length > 3 ? ' …' : ''} — drop-delivery shape for macOS malware`,
      });
      const hidden = roots.filter(r => /(^|\/)\./.test(r));
      if (hidden.length) {
        w.push({
          sev: 'high',
          msg: `⚠ ${hidden.length} hidden .app bundle(s) (leading dot) — likely evasion of Finder visibility`,
        });
      }
      const unsigned = roots.filter(r => {
        const prefix = r + '/';
        const hasBinary = entries.some(e => (e.path || e.name || '').startsWith(prefix + 'Contents/MacOS/'));
        const hasSig = entries.some(e => (e.path || e.name || '').startsWith(prefix + 'Contents/_CodeSignature/'));
        return hasBinary && !hasSig;
      });
      if (unsigned.length) {
        w.push({
          sev: 'high',
          msg: `⚠ ${unsigned.length} .app bundle(s) with a Mach-O binary but no _CodeSignature — unsigned / ad-hoc binary`,
        });
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
    return ZipRenderer.EXEC_EXTS.has(last) && ZipRenderer.DECOY_EXTS.has(prev);
  }

  // ── Non-ZIP fallback (RAR, 7z, CAB etc.) ──────────────────────────────────

  _nonZip(wrap, buffer, fileName) {
    const bytes = new Uint8Array(buffer);
    const ext = (fileName || '').split('.').pop().toLowerCase();
    let format = 'Unknown archive';
    let extraInfo = '';

    // Detect format from magic bytes
    if (bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72) {
      format = 'RAR archive';
      // RAR version detection
      if (bytes[3] === 0x21 && bytes[4] === 0x1A && bytes[5] === 0x07) {
        if (bytes[6] === 0x00) extraInfo = 'RAR 4.x format';
        else if (bytes[6] === 0x01) extraInfo = 'RAR 5.x format';
      }
    } else if (bytes[0] === 0x37 && bytes[1] === 0x7A && bytes[2] === 0xBC && bytes[3] === 0xAF) {
      format = '7-Zip archive';
      // 7z header parsing: version at bytes 6-7
      if (bytes.length >= 8) {
        const majorVer = bytes[6];
        const minorVer = bytes[7];
        extraInfo = `7-Zip format version ${majorVer}.${minorVer}`;
      }
    } else if (bytes[0] === 0x4D && bytes[1] === 0x53 && bytes[2] === 0x43 && bytes[3] === 0x46) {
      format = 'CAB (Cabinet) archive';
    } else if (bytes[0] === 0x1F && bytes[1] === 0x8B) {
      format = 'Gzip compressed';
      // Gzip header: compression method at byte 2, flags at byte 3
      if (bytes[2] === 0x08) extraInfo = 'Deflate compression';
    }

    const info = document.createElement('div'); info.className = 'doc-extraction-banner';
    info.innerHTML = `<strong>${format}</strong> — this archive format cannot be fully extracted in-browser. Showing file info and hex dump.`;
    wrap.innerHTML = ''; wrap.appendChild(info);

    const det = document.createElement('div'); det.style.cssText = 'padding:20px;';
    det.innerHTML = `<p><strong>Format:</strong> ${escHtml(format)}${extraInfo ? ` (${escHtml(extraInfo)})` : ''}</p>` +
      `<p><strong>File size:</strong> ${this._fmtBytes(bytes.length)}</p>` +
      `<p><strong>Extension:</strong> .${escHtml(ext)}</p>` +
      `<p style="color:var(--risk-high);margin-top:12px">⚠ Archives are a common delivery mechanism for phishing payloads. ` +
      `Extract with caution in a sandbox environment.</p>`;
    wrap.appendChild(det);

    // Add hex dump view
    const hexSection = this._buildHexDump(bytes);
    wrap.appendChild(hexSection);

    return wrap;
  }

  // ── Hex dump builder ────────────────────────────────────────────────────────

  _buildHexDump(bytes, maxBytes = 65536) {
    const container = document.createElement('div');
    container.style.cssText = 'margin-top:16px;';

    const header = document.createElement('div');
    header.style.cssText = 'padding:8px 20px;background:rgba(0,0,0,0.2);border-top:1px solid rgba(255,255,255,0.1);font-weight:600;';
    header.textContent = `Hex Dump (first ${this._fmtBytes(Math.min(bytes.length, maxBytes))} of ${this._fmtBytes(bytes.length)})`;
    container.appendChild(header);

    const scr = document.createElement('div');
    scr.style.cssText = 'overflow:auto;max-height:400px;background:rgba(0,0,0,0.15);';

    const pre = document.createElement('pre');
    pre.className = 'hex-dump';
    pre.style.cssText = 'margin:0;padding:12px 20px;font-family:monospace;font-size:12px;line-height:1.5;white-space:pre;';

    const cap = Math.min(bytes.length, maxBytes);
    const lines = [];

    for (let off = 0; off < cap; off += 16) {
      const hex = [];
      const ascii = [];
      for (let j = 0; j < 16; j++) {
        if (off + j < cap) {
          const b = bytes[off + j];
          hex.push(b.toString(16).padStart(2, '0'));
          ascii.push(b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.');
        } else {
          hex.push('  ');
          ascii.push(' ');
        }
      }
      const addr = off.toString(16).padStart(8, '0');
      lines.push(`${addr}  ${hex.slice(0, 8).join(' ')}  ${hex.slice(8).join(' ')}  |${ascii.join('')}|`);
    }

    pre.textContent = lines.join('\n');
    scr.appendChild(pre);
    container.appendChild(scr);

    if (bytes.length > maxBytes) {
      const note = document.createElement('div');
      note.style.cssText = 'padding:8px 20px;color:#888;font-size:12px;';
      note.textContent = `Showing first ${this._fmtBytes(maxBytes)} of ${this._fmtBytes(bytes.length)}. Full file available for YARA scanning and hash computation.`;
      container.appendChild(note);
    }

    return container;
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
