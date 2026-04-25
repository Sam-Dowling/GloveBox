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
        ['HotKey', info.hotKey || '(none)'],
        ['File Size', info.fileSize != null ? info.fileSize.toLocaleString() + ' bytes' : '—'],
        ['File Attributes', info.attrStr || '—'],
        ['Created', info.creationTime || '—'],
        ['Modified', info.writeTime || '—'],
        ['Accessed', info.accessTime || '—'],
      ];
      if (info.tracker) {
        if (info.tracker.machineId) rows.push(['Machine ID', info.tracker.machineId]);
        if (info.tracker.mac) rows.push(['Droplet MAC', info.tracker.mac]);
        else if (info.tracker.birthMac) rows.push(['Droplet MAC', info.tracker.birthMac]);
        if (info.tracker.droidFile) rows.push(['File Droid', info.tracker.droidFile]);
        if (info.tracker.birthFile && info.tracker.birthFile !== info.tracker.droidFile)
          rows.push(['Birth File Droid', info.tracker.birthFile]);
      }
      if (info.darwinProduct) rows.push(['MSI Product Code', info.darwinProduct]);
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

      // Icon environment path
      if (info.iconEnvPath) {
        const ih = document.createElement('div');
        ih.className = 'lnk-section-hdr';
        ih.textContent = 'Icon Environment Path';
        wrap.appendChild(ih);
        const ip = document.createElement('pre');
        ip.className = 'lnk-cmdline';
        ip.textContent = info.iconEnvPath;
        wrap.appendChild(ip);
      }

      // Shell-item chain (LinkTargetIDList)
      if (info.shellItems && info.shellItems.length) {
        const sh = document.createElement('div');
        sh.className = 'lnk-section-hdr';
        sh.textContent = 'Shell Item Chain (Target ID List)';
        wrap.appendChild(sh);
        const sp = document.createElement('pre');
        sp.className = 'lnk-cmdline';
        sp.textContent = info.shellItems.map((it, i) =>
          `[${i}] ${it.kind}: ${it.label}`).join('\n');
        wrap.appendChild(sp);
      }

      // ExtraData block summary
      if (info.extraBlocks && info.extraBlocks.length) {
        const eh = document.createElement('div');
        eh.className = 'lnk-section-hdr';
        eh.textContent = 'ExtraData Blocks';
        wrap.appendChild(eh);
        const ep = document.createElement('pre');
        ep.className = 'lnk-cmdline';
        ep.textContent = info.extraBlocks.map(b => `• ${b}`).join('\n');
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
      if (info.iconLocation) f.metadata.iconLocation = info.iconLocation;
      if (info.hotKey) f.metadata.hotKey = info.hotKey;
      if (info.creationTime) f.metadata.created = info.creationTime;
      if (info.writeTime) f.metadata.modified = info.writeTime;
      if (info.tracker && info.tracker.machineId) f.metadata.machineId = info.tracker.machineId;
      if (info.tracker && (info.tracker.mac || info.tracker.birthMac))
        f.metadata.dropletMac = info.tracker.mac || info.tracker.birthMac;
      if (info.tracker && info.tracker.droidFile) f.metadata.droidFile = info.tracker.droidFile;
      if (info.darwinProduct) f.metadata.msiProductCode = info.darwinProduct;

      // Emit each path / argument field as a separate IOC instead of
      // concatenating them into one ugly composite string. This makes the
      // sidebar navigable one-click-per-field and matches the behaviour the
      // user expects (each field gets its own row + copy button).
      //
      // NOTE ON SEVERITIES: every per-field LNK IOC emitted here (and the
      // TrackerDataBlock host/MAC IOCs below) is intentionally severity
      // 'info'. These are metadata/provenance indicators — target path,
      // working directory, arguments, originating machine ID, burned-in
      // MAC — that are valuable for incident-response pivoting but are
      // not themselves active threat indicators. The actual threat
      // scoring is driven by `_findDangers()` further down, which emits
      // high/medium-severity IOC.PATTERN findings for dangerous commands
      // (PowerShell/cmd/mshta/etc.), UNC credential-theft patterns and
      // other suspicious target shapes. Those drive the overall risk
      // rating; the per-field info IOCs are deliberately quiet.
      const seenVal = new Set();
      const addField = (val, type, sev, note) => {
        if (!val) return;
        const s = String(val).trim();
        if (!s) return;
        const key = type + '|' + s;
        if (seenVal.has(key)) return;
        seenVal.add(key);
        const ref = { type, url: s, severity: sev || 'info' };
        if (note) ref.note = note;
        f.externalRefs.push(ref);
      };
      addField(info.localBasePath || info.netSharePath, IOC.FILE_PATH, 'info', 'Shortcut target');
      addField(info.relativePath, IOC.FILE_PATH, 'info', 'Relative path');
      addField(info.workingDir,   IOC.FILE_PATH, 'info', 'Working directory');
      addField(info.arguments,    IOC.COMMAND_LINE, 'info', 'Shortcut arguments');
      // Icon location — only emit as plain FILE_PATH when it isn't a UNC/URL
      // (those variants are handled below with a higher severity).
      if (info.iconLocation &&
          !/^\\\\/.test(info.iconLocation) &&
          !/^https?:\/\//i.test(info.iconLocation)) {
        addField(info.iconLocation, IOC.FILE_PATH, 'info', 'Icon location');
      }

      // TrackerDataBlock — originating machine name + MAC burned into the
      // shortcut at creation time by the Windows Link Tracking Service.
      // These are high-value pivot IOCs for incident response.
      if (info.tracker) {
        if (info.tracker.machineId) {
          const host = info.tracker.machineId.trim();
          if (host) {
            f.externalRefs.push({
              type: IOC.HOSTNAME, url: host, severity: 'info',
              note: 'TrackerDataBlock machine ID'
            });
          }
        }
        const mac = info.tracker.mac || info.tracker.birthMac;
        if (mac) {
          f.externalRefs.push({
            type: IOC.MAC, url: mac, severity: 'info',
            note: 'TrackerDataBlock MAC address'
          });
        }
      }

      // Droid file-object GUID (generated by Link Tracking Service at
      // shortcut creation; pivots across all shortcuts pointing at the
      // same volume/object) and MSI product/component GUIDs from the
      // Darwin (Windows Installer) advertised-link payload. Both are
      // classic IR pivots — fold them into the IOC table via pushIOC so
      // the sidebar shows them as clickable rows.
      mirrorMetadataIOCs(f, {
        'droidFile':      IOC.GUID,
        'msiProductCode': IOC.GUID,
      });

      const dangers = this._findDangers(info);

      for (const d of dangers) {
        f.externalRefs.push({ type: IOC.PATTERN, url: d.label + ': ' + d.detail, severity: d.sev });
        if (d.sev === 'high') escalateRisk(f, 'high');
        else if (d.sev === 'medium' && f.risk !== 'high') escalateRisk(f, 'medium');
      }

      // Check for UNC paths (credential theft) in any parsed path string
      const pathSources = [info.targetPath, info.localBasePath, info.iconLocation,
      info.workingDir, info.netSharePath, info.envPath, info.iconEnvPath].filter(Boolean);
      // also include shell item labels that look like UNC/URI
      if (info.shellItems) {
        for (const it of info.shellItems) {
          if (it && it.label) pathSources.push(it.label);
        }
      }
      const allPaths = pathSources.join('\n');
      const uncSeen = new Set();
      for (const m of allPaths.matchAll(/\\\\[^\s\\]+\\[^\s]+/g)) {
        if (uncSeen.has(m[0])) continue;
        uncSeen.add(m[0]);
        f.externalRefs.push({ type: IOC.UNC_PATH, url: m[0], severity: 'medium' });
        if (f.risk === 'low') escalateRisk(f, 'medium');
      }

      // Icon pulled from UNC or HTTP(S) — known credential-theft / staging technique
      for (const src of [info.iconLocation, info.iconEnvPath]) {
        if (!src) continue;
        if (/^\\\\/.test(src)) {
          f.externalRefs.push({
            type: IOC.UNC_PATH, url: src, severity: 'high',
            note: 'Icon fetched from UNC (credential-theft/SMB beacon)'
          });
          escalateRisk(f, 'high');
        } else if (/^https?:\/\//i.test(src)) {
          const u = sanitizeUrl(src);
          if (u) {
            f.externalRefs.push({
              type: IOC.URL, url: u, severity: 'high',
              note: 'Icon fetched from remote URL'
            });
            escalateRisk(f, 'high');
          }
        }
      }

      // URI shell items (rare, but seen in exploit kits)
      if (info.shellItems) {
        for (const it of info.shellItems) {
          if (!it || !it.label) continue;
          if (/^https?:\/\//i.test(it.label)) {
            const u = sanitizeUrl(it.label);
            if (u) {
              f.externalRefs.push({ type: IOC.URL, url: u, severity: 'medium' });
              if (f.risk === 'low') escalateRisk(f, 'medium');
            }
          }
        }
      }

      // HotKey assignment on a shortcut is unusual outside the Start Menu
      if (info.hotKey) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: 'HotKey assigned: ' + info.hotKey,
          severity: 'low',
          note: 'Shortcut has a keyboard HotKey (unusual for droppers)'
        });
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

    // HotKey at offset 0x40 (64) — u16: low=vkey, high=modifiers
    const hkRaw = dv.getUint16(0x40, true);
    const hotKey = hkRaw ? this._hotkey(hkRaw & 0xFF, (hkRaw >> 8) & 0xFF) : null;

    const info = {
      flags,
      hasLinkTargetIDList: !!(flags & 0x01),
      hasLinkInfo: !!(flags & 0x02),
      hasName: !!(flags & 0x04),
      hasRelativePath: !!(flags & 0x08),
      hasWorkingDir: !!(flags & 0x10),
      hasArguments: !!(flags & 0x20),
      hasIconLocation: !!(flags & 0x40),
      isUnicode: !!(flags & 0x80),
      fileSize: dv.getUint32(52, true),
      showCommand: this._showCmd(dv.getUint32(60, true)),
      hotKey,
      attrStr: this._attrStr(attrs),
      creationTime: this._fileTime(dv, 28),
      accessTime: this._fileTime(dv, 36),
      writeTime: this._fileTime(dv, 44),
      shellItems: [],
      extraBlocks: [],
    };

    let off = 76;

    // LinkTargetIDList — walk shell items instead of skipping
    if (info.hasLinkTargetIDList && off + 2 <= bytes.length) {
      const idListSize = dv.getUint16(off, true);
      if (idListSize > 0 && off + 2 + idListSize <= bytes.length) {
        info.shellItems = this._walkIdList(bytes, off + 2, idListSize);
      }
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
    // Fallback: reconstruct from shell items if target still empty
    if (!info.targetPath && info.shellItems && info.shellItems.length) {
      info.targetPath = this._reconstructFromShellItems(info.shellItems);
    }

    // ExtraData — full dispatcher
    while (off + 8 <= bytes.length) {
      const blockSize = dv.getUint32(off, true);
      if (blockSize < 4 || blockSize === 0) break;
      if (off + blockSize > bytes.length) break;
      const sig = dv.getUint32(off + 4, true);
      const label = this._extraBlockLabel(sig);
      let detail = '';
      switch (sig) {
        case 0xA0000001: // EnvironmentVariableDataBlock
          if (blockSize >= 0x0C + 260) {
            info.envPath = this._readAnsiStr(bytes, off + 8);
            if (blockSize >= 0x10C + 520) {
              const u = this._readUnicodeStrFixed(bytes, off + 0x10C, 260);
              if (u) info.envPath = u;
            }
            detail = info.envPath || '';
          }
          break;
        case 0xA0000002: // ConsoleDataBlock
          detail = 'console properties';
          break;
        case 0xA0000003: // TrackerDataBlock — MAC, MachineID
          info.tracker = this._extractTrackerData(bytes, off, blockSize);
          if (info.tracker) {
            const parts = [];
            if (info.tracker.machineId) parts.push('machine=' + info.tracker.machineId);
            if (info.tracker.mac) parts.push('mac=' + info.tracker.mac);
            else if (info.tracker.birthMac) parts.push('mac=' + info.tracker.birthMac);
            detail = parts.join(' ');
          }
          break;
        case 0xA0000004: // ConsoleFEDataBlock
          detail = 'console codepage';
          break;
        case 0xA0000005: // SpecialFolderDataBlock
          if (blockSize >= 0x10) {
            const sfId = dv.getUint32(off + 8, true);
            detail = 'CSIDL=0x' + sfId.toString(16);
          }
          break;
        case 0xA0000006: // DarwinDataBlock — MSI product code
          if (blockSize >= 0x0C + 260) {
            const ansi = this._readAnsiStr(bytes, off + 8);
            let uni = '';
            if (blockSize >= 0x10C + 520) {
              uni = this._readUnicodeStrFixed(bytes, off + 0x10C, 260);
            }
            info.darwinProduct = uni || ansi || '';
            detail = info.darwinProduct;
          }
          break;
        case 0xA0000007: // IconEnvironmentDataBlock — icon env var
          if (blockSize >= 0x0C + 260) {
            info.iconEnvPath = this._readAnsiStr(bytes, off + 8);
            if (blockSize >= 0x10C + 520) {
              const u = this._readUnicodeStrFixed(bytes, off + 0x10C, 260);
              if (u) info.iconEnvPath = u;
            }
            detail = info.iconEnvPath || '';
          }
          break;
        case 0xA0000008: // ShimDataBlock
          if (blockSize > 8) detail = this._readUnicodeStrFixed(bytes, off + 8, 64) || '';
          break;
        case 0xA0000009: // PropertyStoreDataBlock
          detail = 'property store (' + (blockSize - 8) + ' bytes)';
          break;
        case 0xA000000B: // KnownFolderDataBlock
          if (blockSize >= 0x1C) {
            const guid = this._guid(bytes, off + 8);
            const idx = dv.getUint32(off + 0x18, true);
            detail = 'KnownFolder ' + (this._knownGuid(guid) || guid) + ' @' + idx;
          }
          break;
        case 0xA000000C: // VistaAndAboveIDListDataBlock
          detail = 'Vista+ IDList (' + (blockSize - 8) + ' bytes)';
          break;
        default:
          detail = '';
      }
      info.extraBlocks.push(detail ? `${label}: ${detail}` : label);
      off += blockSize;
    }

    return info;
  }

  // ── Shell Item (TargetIDList) walker ────────────────────────────────────

  _walkIdList(bytes, off, listSize) {
    const items = [];
    const end = Math.min(off + listSize, bytes.length);
    let p = off;
    let guard = 0;
    while (p + 2 <= end && guard++ < 256) {
      const sz = bytes[p] | (bytes[p + 1] << 8);
      if (sz === 0) break;          // terminator
      if (sz < 2 || p + sz > end) break;
      const it = this._parseShellItem(bytes, p + 2, sz - 2);
      if (it) items.push(it);
      p += sz;
    }
    return items;
  }

  _parseShellItem(bytes, off, len) {
    if (len < 1) return null;
    const type = bytes[off];
    const cls = type & 0x70;

    // Root/My Computer — CLSID follows at +2
    if ((type === 0x1F || cls === 0x10) && len >= 18) {
      const guid = this._guid(bytes, off + 2);
      return { kind: 'Root', label: this._knownGuid(guid) || ('{' + guid + '}') };
    }
    // Volume / drive letter — "C:\" at +1 (ANSI, 3 bytes)
    if (cls === 0x20 && len >= 4) {
      const drv = this._readAnsiFixed(bytes, off + 1, 22) || '';
      return { kind: 'Drive', label: drv.trim() };
    }
    // File or folder (0x30..0x3F) — MS-SHLLINK v2 shell item layout
    // Relative to `off` (the byte after the 2-byte size field):
    //   +0  u8  type  (0x31 folder, 0x32 file, with 0x40/0x80 Unicode flags)
    //   +1  u8  unused (0)
    //   +2  u32 file size (0 for directories)
    //   +6  u32 DOS last-modified date+time
    //   +10 u16 file attributes
    //   +12 ANSI NUL-terminated primary name
    //   after the name, WORD-aligned: optional BEEF0004 extension block
    //   containing the UTF-16LE long filename (preferred over ANSI 8.3).
    if (cls === 0x30 && len >= 12) {
      const nameStart = off + 12;
      // ANSI short name (8.3) first — null-terminated.
      let ansiName = '';
      let nameEnd = nameStart;
      for (let i = nameStart; i < off + len; i++) {
        const c = bytes[i];
        if (c === 0) { nameEnd = i; break; }
        ansiName += String.fromCharCode(c);
        nameEnd = i + 1;
      }

      // Look for a BEEF0004 extension block containing the long UTF-16 name.
      // The extension block starts on a WORD (2-byte) boundary after the
      // ANSI name's NUL terminator.
      let extStart = nameEnd + 1;        // skip the ANSI NUL
      if ((extStart - off) & 1) extStart++; // WORD-align
      let longName = '';
      if (extStart + 10 <= off + len) {
        const extSize = bytes[extStart] | (bytes[extStart + 1] << 8);
        const extVer  = bytes[extStart + 2] | (bytes[extStart + 3] << 8);
        const extSig  = bytes[extStart + 4] | (bytes[extStart + 5] << 8) |
                        (bytes[extStart + 6] << 16) | (bytes[extStart + 7] << 24);
        if (extSig === 0xBEEF0004 && extSize >= 14 && extStart + extSize <= off + len) {
          // Primary UTF-16 name offset depends on extension version:
          //   v7 (Win7+) : offset 0x1E   (after 2B size, 2B ver, 4B sig,
          //                4B created, 4B accessed, 2B ident, 2B pad,
          //                8B FileRef, 8B Unknown2)
          //   v3+        : offset 0x0E
          const uniOff = extVer >= 7 ? extStart + 0x1E : extStart + 0x0E;
          if (uniOff + 2 <= extStart + extSize) {
            for (let i = uniOff; i + 1 < extStart + extSize; i += 2) {
              const c = bytes[i] | (bytes[i + 1] << 8);
              if (c === 0) break;
              longName += String.fromCharCode(c);
            }
          }
        }
      }

      const name = longName || ansiName || '(unnamed)';
      return { kind: (type & 0x01) ? 'Dir' : 'File', label: name };
    }

    // Network location or URI
    if (cls === 0x40 && len >= 5) {
      let s = '';
      for (let i = off + 5; i < off + len; i++) {
        const c = bytes[i];
        if (c === 0) break;
        s += String.fromCharCode(c);
      }
      const kind = /^https?:|^ftp:|^mailto:/i.test(s) ? 'URI' : 'Network';
      return { kind, label: s || '(empty)' };
    }
    // Control Panel / GUID-based (Vista+ property bag delegate)
    if (type === 0x71 || type === 0x74) {
      if (len >= 18) {
        const guid = this._guid(bytes, off + len - 16);
        return { kind: 'KnownFolder', label: this._knownGuid(guid) || ('{' + guid + '}') };
      }
    }
    // Delegate / shell extension (0x2E, 0x74)
    if (type === 0x2E && len >= 20) {
      const guid = this._guid(bytes, off + 4);
      return { kind: 'ShellExt', label: this._knownGuid(guid) || ('{' + guid + '}') };
    }
    return { kind: '0x' + type.toString(16).padStart(2, '0'), label: `(${len}B)` };
  }

  _reconstructFromShellItems(items) {
    const parts = [];
    for (const it of items) {
      if (!it || !it.label) continue;
      if (it.kind === 'Root' || it.kind === 'ShellExt' || it.kind === 'KnownFolder') continue;
      if (it.kind === 'Drive') parts.push(it.label.replace(/\\$/, ''));
      else if (it.kind === 'File' || it.kind === 'Dir') parts.push(it.label);
    }
    return parts.join('\\');
  }

  // ── TrackerDataBlock (sig 0xA0000003) ───────────────────────────────────
  // Layout (relative to block start):
  //   0x00  u32 BlockSize (0x60)
  //   0x04  u32 Signature (0xA0000003)
  //   0x08  u32 Length (0x58)
  //   0x0C  u32 Version
  //   0x10  16B MachineID (ANSI NetBIOS, null-padded)
  //   0x20  16B Droid[0]        — birth volume GUID
  //   0x30  16B Droid[1]        — birth object GUID (UUID v1: last 6B = MAC)
  //   0x40  16B DroidBirth[0]   — volume GUID
  //   0x50  16B DroidBirth[1]   — object GUID (UUID v1: last 6B = MAC)
  _extractTrackerData(bytes, off, blockSize) {
    if (blockSize < 0x60 || off + 0x60 > bytes.length) return null;
    const machineId = this._readAnsiFixed(bytes, off + 0x10, 16);
    const droidVolume = this._guid(bytes, off + 0x20);
    const droidFile = this._guid(bytes, off + 0x30);
    const birthVolume = this._guid(bytes, off + 0x40);
    const birthFile = this._guid(bytes, off + 0x50);
    // MAC = last 6 bytes (node field of UUID v1)
    const mac = this._mac(bytes, off + 0x30 + 10);
    const birthMac = this._mac(bytes, off + 0x50 + 10);
    return { machineId, droidVolume, droidFile, birthVolume, birthFile, mac, birthMac };
  }

  _mac(bytes, off) {
    if (off + 6 > bytes.length) return null;
    const parts = [];
    let zero = 0, ff = 0;
    for (let i = 0; i < 6; i++) {
      const b = bytes[off + i];
      if (b === 0x00) zero++;
      if (b === 0xFF) ff++;
      parts.push(b.toString(16).padStart(2, '0'));
    }
    if (zero === 6 || ff === 6) return null;
    return parts.join(':');
  }

  _guid(bytes, off) {
    if (off + 16 > bytes.length) return '';
    const h2 = b => b.toString(16).padStart(2, '0');
    const le4 = o => h2(bytes[o + 3]) + h2(bytes[o + 2]) + h2(bytes[o + 1]) + h2(bytes[o]);
    const le2 = o => h2(bytes[o + 1]) + h2(bytes[o]);
    const be2 = o => h2(bytes[o]) + h2(bytes[o + 1]);
    let node = '';
    for (let i = 10; i < 16; i++) node += h2(bytes[off + i]);
    return `${le4(off)}-${le2(off + 4)}-${le2(off + 6)}-${be2(off + 8)}-${node}`;
  }

  _knownGuid(g) {
    const map = {
      '20d04fe0-3aea-1069-a2d8-08002b30309d': 'My Computer',
      '450d8fba-ad25-11d0-98a8-0800361b1103': 'My Documents',
      '208d2c60-3aea-1069-a2d7-08002b30309d': 'My Network Places',
      '871c5380-42a0-1069-a2ea-08002b30309d': 'Internet Explorer',
      '21ec2020-3aea-1069-a2dd-08002b30309d': 'Control Panel',
      'de974d24-d9c6-4d3e-bf91-f4455120b917': 'Common Files',
      '2559a1f2-21d7-11d4-bdaf-00c04f60b9f0': 'Search',
      '00021401-0000-0000-c000-000000000046': 'ShellLink',
      'b4bfcc3a-db2c-424c-b029-7fe99a87c641': 'Desktop',
      'f02c1a0d-be21-4350-88b0-7367fc96ef3c': 'Network',
      '0ac0837c-bbf8-452a-850d-79d08e667ca7': 'Computer',
      '4336a54d-038b-4685-ab02-99bb52d3fb8b': 'Samples',
      '1f4de370-d627-11d1-ba4f-00a0c91eedba': 'Search Results',
      'cc48e737-e74d-4d58-8e20-8dd0b8554f31': 'Documents',
      '088e3905-0323-4b02-9826-5d99428e115f': 'Downloads',
    };
    return map[g.toLowerCase()];
  }

  _extraBlockLabel(sig) {
    switch (sig) {
      case 0xA0000001: return 'EnvironmentVariableDataBlock';
      case 0xA0000002: return 'ConsoleDataBlock';
      case 0xA0000003: return 'TrackerDataBlock';
      case 0xA0000004: return 'ConsoleFEDataBlock';
      case 0xA0000005: return 'SpecialFolderDataBlock';
      case 0xA0000006: return 'DarwinDataBlock';
      case 0xA0000007: return 'IconEnvironmentDataBlock';
      case 0xA0000008: return 'ShimDataBlock';
      case 0xA0000009: return 'PropertyStoreDataBlock';
      case 0xA000000B: return 'KnownFolderDataBlock';
      case 0xA000000C: return 'VistaAndAboveIDListDataBlock';
      default: return 'ExtraData 0x' + sig.toString(16);
    }
  }

  // ── HotKey decode ───────────────────────────────────────────────────────

  _hotkey(low, high) {
    if (!low) return null;
    const mods = [];
    if (high & 0x01) mods.push('Shift');
    if (high & 0x02) mods.push('Ctrl');
    if (high & 0x04) mods.push('Alt');
    if (high & 0x08) mods.push('ExtKey');
    let keyName;
    if (low >= 0x30 && low <= 0x39) keyName = String.fromCharCode(low);          // 0-9
    else if (low >= 0x41 && low <= 0x5A) keyName = String.fromCharCode(low);      // A-Z
    else if (low >= 0x70 && low <= 0x87) keyName = 'F' + (low - 0x6F);            // F1-F24
    else keyName = '0x' + low.toString(16).toUpperCase();
    return (mods.length ? mods.join('+') + '+' : '') + keyName;
  }

  _findDangers(info) {
    const dangers = [];
    const allText = [info.targetPath, info.arguments, info.localBasePath,
    info.workingDir, info.iconLocation, info.envPath, info.iconEnvPath, info.relativePath]
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
    if (info.attrStr && (info.attrStr.includes('Hidden') || info.attrStr.includes('System'))) {
      dangers.push({ label: 'Hidden/System file attributes', detail: info.attrStr, sev: 'medium' });
    }

    // ShowCommand = SW_HIDE (value 0) — link runs its target with a hidden window
    if (info.showCommand === 'SW_HIDE') {
      dangers.push({ label: 'ShowCommand is SW_HIDE — link runs its target with a hidden window', detail: 'ShowCommand = 0', sev: 'medium' });
    }

    // Icon path vs target mismatch — icon masquerades as document but target is executable
    if (info.iconLocation && info.targetPath) {
      const iconExt = (info.iconLocation.match(/\.([a-z0-9]{1,6})$/i) || [])[1] || '';
      const targetExt = (info.targetPath.match(/\.([a-z0-9]{1,6})$/i) || [])[1] || '';
      const docExts = new Set(['pdf','doc','docx','xls','xlsx','ppt','jpg','png','jpeg','gif','bmp','txt','rtf','csv']);
      const exeExts = new Set(['exe','cmd','bat','ps1','vbs','js','com','scr','hta','msi','pif','wsh','wsf']);
      if (docExts.has(iconExt.toLowerCase()) && exeExts.has(targetExt.toLowerCase())) {
        dangers.push({ label: `Icon masquerades as .${iconExt} but target is .${targetExt}`, detail: `icon="${info.iconLocation}" target="${info.targetPath}"`, sev: 'high' });
      }
    }

    // Suspicious working directory — user-writable staging locations
    if (info.workingDir) {
      const wd = info.workingDir.toLowerCase();
      const stagingPaths = ['%temp%', '%tmp%', '%appdata%', '%localappdata%', '%public%', 'c:\\users\\public'];
      for (const sp of stagingPaths) {
        if (wd.includes(sp)) {
          dangers.push({ label: 'Working directory points to user-writable staging location', detail: info.workingDir, sev: 'medium' });
          break;
        }
      }
    }

    // Icon from UNC/URL — staging / credential theft
    for (const src of [info.iconLocation, info.iconEnvPath]) {
      if (!src) continue;
      if (/^\\\\/.test(src)) {
        dangers.push({ label: 'Icon from UNC', detail: src, sev: 'high' });
      } else if (/^https?:\/\//i.test(src)) {
        dangers.push({ label: 'Icon from remote URL', detail: src, sev: 'high' });
      }
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
    if (val === 0) return 'SW_HIDE';
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

  _readAnsiFixed(bytes, off, len) {
    let s = '';
    for (let i = 0; i < len && off + i < bytes.length; i++) {
      const c = bytes[off + i];
      if (c === 0) break;
      s += String.fromCharCode(c);
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
