'use strict';
// ════════════════════════════════════════════════════════════════════════════
// lnk-renderer.js — Parses and renders Windows Shell Link (.lnk) files
// Implements MS-SHLLINK binary format parsing. No external dependencies.
// ════════════════════════════════════════════════════════════════════════════
class LnkRenderer {

  render(buffer) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const wrap = document.createElement('div');
    wrap.className = 'lnk-view';

    try {
      const info = this._parse(bytes);

      // Danger banner if suspicious
      const dangers = this._findDangers(info);
      if (dangers.length) {
        const ban = document.createElement('div');
        ban.className = 'lnk-danger-banner';
        ban.textContent = '⚠ Suspicious shortcut — ' + dangers.map(d => d.label).join(', ');
        wrap.appendChild(ban);
      }

      // Info table
      const tbl = document.createElement('table');
      tbl.className = 'lnk-info-table';
      const rows = [
        ['Target', info.targetPath || info.localBasePath || info.netSharePath || '(unknown)'],
        ['Arguments', info.arguments || '(none)'],
        ['Working Dir', info.workingDir || '(none)'],
        ['Icon Location', info.iconLocation || '(none)'],
        ['Relative Path', info.relativePath || '(none)'],
        ['Description', info.name || '(none)'],
        ['Show Command', info.showCommand],
        ['File Size', info.fileSize != null ? info.fileSize.toLocaleString() + ' bytes' : '—'],
        ['File Attributes', info.attrStr || '—'],
        ['Created', info.creationTime || '—'],
        ['Modified', info.writeTime || '—'],
        ['Accessed', info.accessTime || '—'],
      ];
      for (const [lbl, val] of rows) {
        const tr = document.createElement('tr');
        const tdL = document.createElement('td');
        tdL.className = 'lnk-lbl';
        tdL.textContent = lbl;
        const tdV = document.createElement('td');
        tdV.className = 'lnk-val';
        tdV.textContent = val;
        tr.appendChild(tdL);
        tr.appendChild(tdV);
        tbl.appendChild(tr);
      }
      wrap.appendChild(tbl);

      // Command line preview
      const cmdLine = (info.targetPath || info.localBasePath || info.relativePath || '') +
        (info.arguments ? ' ' + info.arguments : '');
      if (cmdLine.trim()) {
        const cmdH = document.createElement('div');
        cmdH.className = 'lnk-section-hdr';
        cmdH.textContent = 'Reconstructed Command';
        wrap.appendChild(cmdH);
        const pre = document.createElement('pre');
        pre.className = 'lnk-cmdline';
        pre.textContent = cmdLine;
        wrap.appendChild(pre);
      }

      // Environment variable path (ExtraData)
      if (info.envPath) {
        const eh = document.createElement('div');
        eh.className = 'lnk-section-hdr';
        eh.textContent = 'Environment Variable Path';
        wrap.appendChild(eh);
        const ep = document.createElement('pre');
        ep.className = 'lnk-cmdline';
        ep.textContent = info.envPath;
        wrap.appendChild(ep);
      }

    } catch (e) {
      const eb = document.createElement('div');
      eb.className = 'error-box';
      const h3 = document.createElement('h3');
      h3.textContent = 'Failed to parse .lnk file';
      eb.appendChild(h3);
      const p = document.createElement('p');
      p.textContent = e.message;
      eb.appendChild(p);
      wrap.appendChild(eb);
    }

    return wrap;
  }

  analyzeForSecurity(buffer) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {}
    };

    try {
      const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
      const info = this._parse(bytes);

      f.metadata = {};
      if (info.targetPath || info.localBasePath) f.metadata.target = info.targetPath || info.localBasePath;
      if (info.arguments) f.metadata.arguments = info.arguments;
      if (info.workingDir) f.metadata.workingDir = info.workingDir;
      if (info.creationTime) f.metadata.created = info.creationTime;
      if (info.writeTime) f.metadata.modified = info.writeTime;

      const dangers = this._findDangers(info);
      for (const d of dangers) {
        f.externalRefs.push({ type: 'LNK Danger', url: d.label + ': ' + d.detail, severity: d.sev });
        if (d.sev === 'high') f.risk = 'high';
        else if (d.sev === 'medium' && f.risk !== 'high') f.risk = 'medium';
      }

      // Check for UNC paths (credential theft)
      const allPaths = [info.targetPath, info.localBasePath, info.iconLocation, info.workingDir,
        info.netSharePath, info.envPath].filter(Boolean).join('\n');
      for (const m of allPaths.matchAll(/\\\\[^\s\\]+\\[^\s]+/g)) {
        f.externalRefs.push({ type: 'UNC Path (LNK)', url: m[0], severity: 'medium' });
        if (f.risk === 'low') f.risk = 'medium';
      }

    } catch (_) { /* parse failed — non-fatal */ }

    return f;
  }

  // ── LNK binary parsing ──────────────────────────────────────────────────

  _parse(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (bytes.length < 76) throw new Error('File too small for LNK header');

    // Validate magic: 4C 00 00 00
    if (dv.getUint32(0, true) !== 0x4C) throw new Error('Invalid LNK magic number');

    const flags = dv.getUint32(20, true);
    const attrs = dv.getUint32(24, true);

    const info = {
      flags,
      hasLinkTargetIDList: !!(flags & 0x01),
      hasLinkInfo:         !!(flags & 0x02),
      hasName:             !!(flags & 0x04),
      hasRelativePath:     !!(flags & 0x08),
      hasWorkingDir:       !!(flags & 0x10),
      hasArguments:        !!(flags & 0x20),
      hasIconLocation:     !!(flags & 0x40),
      isUnicode:           !!(flags & 0x80),
      fileSize:  dv.getUint32(52, true),
      showCommand: this._showCmd(dv.getUint32(60, true)),
      attrStr: this._attrStr(attrs),
      creationTime: this._fileTime(dv, 28),
      accessTime:   this._fileTime(dv, 36),
      writeTime:    this._fileTime(dv, 44),
    };

    let off = 76;

    // LinkTargetIDList
    if (info.hasLinkTargetIDList && off + 2 <= bytes.length) {
      const idListSize = dv.getUint16(off, true);
      off += 2 + idListSize;
    }

    // LinkInfo — extract local base path
    if (info.hasLinkInfo && off + 4 <= bytes.length) {
      const liSize = dv.getUint32(off, true);
      const liEnd = off + liSize;
      if (off + 8 <= bytes.length) {
        const liHeaderSize = dv.getUint32(off + 4, true);
        const liFlags = dv.getUint32(off + 8, true);
        // VolumeIDAndLocalBasePath
        if ((liFlags & 0x01) && off + 16 <= bytes.length) {
          const lbpOff = dv.getUint32(off + 16, true);
          if (lbpOff > 0 && off + lbpOff < bytes.length) {
            info.localBasePath = this._readAnsiStr(bytes, off + lbpOff);
          }
        }
        // CommonNetworkRelativeLink
        if ((liFlags & 0x02) && off + 20 <= bytes.length) {
          const cnOff = dv.getUint32(off + 20, true);
          if (cnOff > 0 && off + cnOff + 8 < bytes.length) {
            const nsOff = dv.getUint32(off + cnOff + 8, true);
            if (nsOff > 0) {
              info.netSharePath = this._readAnsiStr(bytes, off + cnOff + nsOff);
            }
          }
        }
        // Unicode local base path
        if (liHeaderSize >= 0x24 && off + 0x24 <= bytes.length) {
          const ulbpOff = dv.getUint32(off + 0x1C, true);
          if (ulbpOff > 0 && off + ulbpOff < bytes.length) {
            const ubp = this._readUnicodeStr(bytes, off + ulbpOff);
            if (ubp) info.localBasePath = ubp;
          }
        }
      }
      off = liEnd;
    }

    // StringData — counted strings in order
    const stringFields = ['name', 'relativePath', 'workingDir', 'arguments', 'iconLocation'];
    const fieldFlags = [info.hasName, info.hasRelativePath, info.hasWorkingDir, info.hasArguments, info.hasIconLocation];
    for (let i = 0; i < stringFields.length; i++) {
      if (fieldFlags[i] && off + 2 <= bytes.length) {
        const charCount = dv.getUint16(off, true);
        off += 2;
        if (info.isUnicode) {
          const strBytes = charCount * 2;
          if (off + strBytes <= bytes.length) {
            info[stringFields[i]] = this._decodeUTF16(bytes, off, charCount);
            off += strBytes;
          }
        } else {
          if (off + charCount <= bytes.length) {
            info[stringFields[i]] = this._decodeAnsi(bytes, off, charCount);
            off += charCount;
          }
        }
      }
    }

    // Build target path
    info.targetPath = info.localBasePath || info.netSharePath || '';
    if (info.relativePath && !info.targetPath) {
      info.targetPath = info.relativePath;
    }

    // ExtraData — scan for EnvironmentVariableDataBlock
    while (off + 8 <= bytes.length) {
      const blockSize = dv.getUint32(off, true);
      if (blockSize < 4) break;
      const sig = dv.getUint32(off + 4, true);
      if (sig === 0xA0000001 && off + 268 <= bytes.length) {
        // EnvironmentVariableDataBlock: ANSI at +8 (260 bytes)
        info.envPath = this._readAnsiStr(bytes, off + 8);
        // Unicode at +268 (520 bytes) if available
        if (off + 788 <= bytes.length) {
          const uPath = this._readUnicodeStrFixed(bytes, off + 268, 260);
          if (uPath) info.envPath = uPath;
        }
      }
      off += blockSize;
    }

    return info;
  }

  _findDangers(info) {
    const dangers = [];
    const allText = [info.targetPath, info.arguments, info.localBasePath,
      info.workingDir, info.iconLocation, info.envPath, info.relativePath]
      .filter(Boolean).join(' ').toLowerCase();

    const suspExes = [
      'powershell', 'pwsh', 'cmd.exe', 'cmd /c', 'cmd /k', 'mshta',
      'wscript', 'cscript', 'certutil', 'bitsadmin', 'rundll32',
      'regsvr32', 'msiexec', 'curl', 'wget', 'explorer.exe /e',
    ];
    for (const exe of suspExes) {
      if (allText.includes(exe)) {
        dangers.push({ label: exe + ' in command', detail: allText.substring(0, 200), sev: 'high' });
      }
    }

    const suspArgs = [
      { pat: /-e(nc(odedcommand)?)\b/i, label: 'Encoded command flag' },
      { pat: /-nop(rofile)?\b/i, label: '-NoProfile flag' },
      { pat: /-w(indowstyle)?\s+hidden/i, label: 'Hidden window' },
      { pat: /-ep\s+bypass/i, label: 'Execution policy bypass' },
      { pat: /\bdownloadstring\b/i, label: 'DownloadString' },
      { pat: /\bdownloadfile\b/i, label: 'DownloadFile' },
      { pat: /\biex\b/i, label: 'IEX (Invoke-Expression)' },
      { pat: /\bfrombase64string\b/i, label: 'Base64 decoding' },
    ];
    for (const { pat, label } of suspArgs) {
      if (pat.test(allText)) {
        dangers.push({ label, detail: (info.arguments || '').substring(0, 200), sev: 'high' });
      }
    }

    // Hidden/system file attributes
    const attrs = info.flags != null ? (new DataView(new ArrayBuffer(4))).getUint32(0, true) : 0;
    if (info.attrStr && (info.attrStr.includes('Hidden') || info.attrStr.includes('System'))) {
      dangers.push({ label: 'Hidden/System file attributes', detail: info.attrStr, sev: 'medium' });
    }

    return dangers;
  }

  // ── Helpers ─────────────────────────────────────────────────────────────

  _fileTime(dv, off) {
    const lo = dv.getUint32(off, true);
    const hi = dv.getUint32(off + 4, true);
    if (lo === 0 && hi === 0) return null;
    // Windows FILETIME: 100-ns intervals since 1601-01-01
    const ms = (hi * 0x100000000 + lo) / 10000 - 11644473600000;
    try { return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC'); }
    catch (_) { return null; }
  }

  _showCmd(val) {
    if (val === 3) return 'Maximized';
    if (val === 7) return 'Minimized';
    return 'Normal';
  }

  _attrStr(attrs) {
    const flags = [];
    if (attrs & 0x01) flags.push('ReadOnly');
    if (attrs & 0x02) flags.push('Hidden');
    if (attrs & 0x04) flags.push('System');
    if (attrs & 0x10) flags.push('Directory');
    if (attrs & 0x20) flags.push('Archive');
    if (attrs & 0x80) flags.push('Normal');
    if (attrs & 0x100) flags.push('Temporary');
    if (attrs & 0x800) flags.push('Compressed');
    if (attrs & 0x2000) flags.push('NotIndexed');
    if (attrs & 0x4000) flags.push('Encrypted');
    return flags.join(', ') || 'None';
  }

  _readAnsiStr(bytes, off) {
    let s = '';
    for (let i = off; i < bytes.length && bytes[i] !== 0; i++) {
      s += String.fromCharCode(bytes[i]);
    }
    return s;
  }

  _readUnicodeStr(bytes, off) {
    let s = '';
    for (let i = off; i + 1 < bytes.length; i += 2) {
      const c = bytes[i] | (bytes[i + 1] << 8);
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }

  _readUnicodeStrFixed(bytes, off, maxChars) {
    let s = '';
    for (let i = 0; i < maxChars && off + i * 2 + 1 < bytes.length; i++) {
      const c = bytes[off + i * 2] | (bytes[off + i * 2 + 1] << 8);
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s;
  }

  _decodeUTF16(bytes, off, charCount) {
    let s = '';
    for (let i = 0; i < charCount; i++) {
      s += String.fromCharCode(bytes[off + i * 2] | (bytes[off + i * 2 + 1] << 8));
    }
    return s;
  }

  _decodeAnsi(bytes, off, count) {
    let s = '';
    for (let i = 0; i < count; i++) s += String.fromCharCode(bytes[off + i]);
    return s;
  }
}
