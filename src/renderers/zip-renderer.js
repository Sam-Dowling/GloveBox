'use strict';
// ════════════════════════════════════════════════════════════════════════════
// zip-renderer.js — Archive content listing for .zip / .7z / .rar / .cab
// Supports: clickable file extraction, ZipCrypto password cracking
// Depends on: constants.js (IOC), JSZip (vendor)
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

  // Double-extension patterns attackers use (e.g. invoice.pdf.exe)
  static DECOY_EXTS = new Set([
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'jpg', 'png', 'gif', 'txt', 'rtf',
  ]);

  // Common passwords for malware samples
  static PASSWORD_LIST = ['password', 'infected', 'suspicious', 'malware', 'virus', 'sample',
    'test', '123456', 'Password1', 'infected!', 'abc123'];

  async render(buffer, fileName) {
    const wrap = document.createElement('div'); wrap.className = 'zip-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>Archive Contents</strong> — click any file to open it for analysis.';
    wrap.appendChild(banner);

    // Try to load as ZIP
    let zip;
    try { zip = await JSZip.loadAsync(buffer); }
    catch (e) {
      // May be encrypted or non-ZIP — check for encryption first
      const encrypted = this._detectEncryption(new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer));
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

  // ── Render ZIP contents table with clickable rows ─────────────────────────

  _renderZipContents(wrap, zip, buffer, fileName) {
    const entries = [];
    zip.forEach((path, entry) => {
      entries.push({
        path,
        dir: entry.dir,
        size: entry._data ? (entry._data.uncompressedSize || 0) : 0,
        date: entry.date || null,
        compressed: entry._data ? (entry._data.compressedSize || 0) : 0,
      });
    });

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
        const errP = document.createElement('p'); errP.style.cssText = 'color:#f88;padding:10px;';
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
            input.style.borderColor = '#f88';
          }
        } else {
          btn.disabled = false; btn.textContent = '🔑 Try Password';
          input.style.borderColor = '#f88';
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

    // Check for encryption first
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

    let zip;
    try { zip = await JSZip.loadAsync(buffer); } catch (e) {
      f.externalRefs.push({ type: IOC.INFO, url: 'Archive format not fully parseable (not ZIP)', severity: 'info' });
      return f;
    }

    const entries = [];
    zip.forEach((path, entry) => entries.push({ path, dir: entry.dir }));

    const warnings = this._checkWarnings(entries);
    for (const w of warnings) {
      f.externalRefs.push({ type: IOC.PATTERN, url: w.msg, severity: w.sev });
      if (w.sev === 'high') f.risk = 'high';
      else if (w.sev === 'medium' && f.risk !== 'high') f.risk = 'medium';
    }

    // Count dangerous files
    const dangerous = entries.filter(e => !e.dir && ZipRenderer.EXEC_EXTS.has(e.path.split('.').pop().toLowerCase()));
    if (dangerous.length) {
      f.externalRefs.push({ type: IOC.PATTERN, url: `${dangerous.length} executable/script file(s) inside archive`, severity: 'high' });
      f.risk = 'high';
    }
    for (const e of dangerous) {
      f.externalRefs.push({ type: IOC.FILE_PATH, url: e.path, severity: 'high' });
    }

    return f;
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
    if (bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72) format = 'RAR archive';
    else if (bytes[0] === 0x37 && bytes[1] === 0x7A && bytes[2] === 0xBC && bytes[3] === 0xAF) format = '7-Zip archive';
    else if (bytes[0] === 0x4D && bytes[1] === 0x53 && bytes[2] === 0x43 && bytes[3] === 0x46) format = 'CAB (Cabinet) archive';

    const info = document.createElement('div'); info.className = 'doc-extraction-banner';
    info.innerHTML = `<strong>${format}</strong> — only ZIP archives can be fully listed and extracted. Showing file signature and basic info.`;
    wrap.innerHTML = ''; wrap.appendChild(info);

    const det = document.createElement('div'); det.style.cssText = 'padding:20px;';
    det.innerHTML = `<p><strong>Format:</strong> ${escHtml(format)}</p>` +
      `<p><strong>File size:</strong> ${this._fmtBytes(bytes.length)}</p>` +
      `<p><strong>Extension:</strong> .${escHtml(ext)}</p>` +
      `<p style="color:#f88;margin-top:12px">⚠ Archives are a common delivery mechanism for phishing payloads. ` +
      `Extract with caution in a sandbox environment.</p>`;
    wrap.appendChild(det);
    return wrap;
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
