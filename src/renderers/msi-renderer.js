'use strict';
// ════════════════════════════════════════════════════════════════════════════
// msi-renderer.js — Windows Installer (.msi) analysis
// Uses OleCfbParser to read the OLE compound file structure, lists streams,
// extracts summary information, and flags suspicious content.
// Depends on: ole-cfb-parser.js, constants.js (IOC, escHtml)
// ════════════════════════════════════════════════════════════════════════════
class MsiRenderer {

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const wrap = document.createElement('div'); wrap.className = 'msi-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>⚠ Windows Installer Package (.msi)</strong> — MSI files execute with elevated privileges during installation. They can run custom actions (scripts, executables), modify the registry, install services, and alter system files.';
    wrap.appendChild(banner);

    let analysis;
    try {
      analysis = this._analyze(bytes);
    } catch (e) {
      const err = document.createElement('div'); err.className = 'error-box';
      err.textContent = `Failed to parse MSI: ${e.message}`;
      wrap.appendChild(err);
      return wrap;
    }

    // Summary info
    const infoDiv = document.createElement('div'); infoDiv.className = 'plaintext-info';
    infoDiv.textContent = `${analysis.streams.length} stream(s)  ·  ${this._fmtBytes(bytes.length)}  ·  Windows Installer Package`;
    wrap.appendChild(infoDiv);

    // Warnings
    if (analysis.warnings.length) {
      const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
      for (const w of analysis.warnings) {
        const d = document.createElement('div');
        d.className = `zip-warning zip-warning-${w.sev}`;
        d.textContent = `⚠ ${w.label}`;
        warnDiv.appendChild(d);
      }
      wrap.appendChild(warnDiv);
    }

    // Summary Information (document properties)
    if (analysis.summaryInfo && Object.keys(analysis.summaryInfo).length) {
      const siH = document.createElement('div'); siH.className = 'hta-section-hdr';
      siH.textContent = 'Summary Information';
      wrap.appendChild(siH);

      const tbl = document.createElement('table'); tbl.className = 'lnk-info-table';
      for (const [key, val] of Object.entries(analysis.summaryInfo)) {
        const tr = document.createElement('tr');
        const tdL = document.createElement('td'); tdL.className = 'lnk-lbl'; tdL.textContent = key;
        const tdV = document.createElement('td'); tdV.className = 'lnk-val'; tdV.textContent = val;
        tr.appendChild(tdL); tr.appendChild(tdV); tbl.appendChild(tr);
      }
      wrap.appendChild(tbl);
    }

    // MSI tables detected
    if (analysis.tables.length) {
      const tH = document.createElement('div'); tH.className = 'hta-section-hdr';
      tH.textContent = `MSI Database Tables (${analysis.tables.length})`;
      wrap.appendChild(tH);

      const tblDiv = document.createElement('div'); tblDiv.style.cssText = 'padding:4px 8px;';
      const chips = document.createElement('div');
      chips.style.cssText = 'display:flex;flex-wrap:wrap;gap:4px;';
      for (const t of analysis.tables) {
        const chip = document.createElement('span');
        chip.style.cssText = `display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-family:monospace;${t.isSuspicious ? 'background:rgba(255,136,136,0.15);color:#f88;border:1px solid rgba(255,136,136,0.3);' : 'background:rgba(68,170,255,0.08);color:#8cf;border:1px solid rgba(68,170,255,0.15);'}`;
        chip.textContent = t.name;
        chip.title = t.isSuspicious ? 'Potentially dangerous table' : '';
        chips.appendChild(chip);
      }
      tblDiv.appendChild(chips); wrap.appendChild(tblDiv);
    }

    // Custom Actions
    if (analysis.customActions.length) {
      const caH = document.createElement('div'); caH.className = 'hta-section-hdr';
      caH.textContent = `Custom Actions (${analysis.customActions.length})`;
      wrap.appendChild(caH);

      const caDiv = document.createElement('div'); caDiv.style.cssText = 'padding:0 8px;';
      for (const ca of analysis.customActions) {
        const d = document.createElement('div');
        d.className = `zip-warning zip-warning-${ca.sev}`;
        d.textContent = ca.label;
        caDiv.appendChild(d);
      }
      wrap.appendChild(caDiv);
    }

    // OLE Streams
    if (analysis.streams.length) {
      const stH = document.createElement('div'); stH.className = 'hta-section-hdr';
      stH.textContent = `OLE Streams (${analysis.streams.length})`;
      wrap.appendChild(stH);

      const stTbl = document.createElement('table'); stTbl.className = 'lnk-info-table';
      // Header
      const hdr = document.createElement('tr');
      for (const h of ['Stream Name', 'Size', 'Flags']) {
        const th = document.createElement('td'); th.className = 'lnk-lbl';
        th.style.cssText = 'font-weight:bold;'; th.textContent = h;
        hdr.appendChild(th);
      }
      stTbl.appendChild(hdr);

      for (const s of analysis.streams) {
        const tr = document.createElement('tr');
        const tdN = document.createElement('td'); tdN.className = 'lnk-val';
        tdN.textContent = s.name;
        tdN.style.cssText = `font-family:monospace;font-size:12px;${s.isSuspicious ? 'color:#f88;' : ''}`;
        const tdS = document.createElement('td'); tdS.className = 'lnk-val';
        tdS.textContent = this._fmtBytes(s.size);
        tdS.style.cssText = 'min-width:80px;';
        const tdF = document.createElement('td'); tdF.className = 'lnk-val';
        tdF.textContent = s.flags.join(', ') || '—';
        tdF.style.cssText = s.flags.length ? 'color:#f88;' : 'opacity:0.5;';
        tr.appendChild(tdN); tr.appendChild(tdS); tr.appendChild(tdF);
        stTbl.appendChild(tr);
      }
      wrap.appendChild(stTbl);
    }

    // Embedded binary data preview (for large Binary streams)
    if (analysis.embeddedBinaries.length) {
      const ebH = document.createElement('div'); ebH.className = 'hta-section-hdr';
      ebH.textContent = `Embedded Binaries (${analysis.embeddedBinaries.length})`;
      wrap.appendChild(ebH);

      for (const eb of analysis.embeddedBinaries) {
        const d = document.createElement('div');
        d.style.cssText = 'padding:4px 8px;margin:4px 0;';
        const label = document.createElement('div');
        label.style.cssText = 'font-family:monospace;font-size:12px;margin-bottom:4px;';
        label.textContent = `${eb.name} — ${this._fmtBytes(eb.size)} — ${eb.magic}`;
        label.style.cssText += eb.isPE ? 'color:#f44;font-weight:bold;' : '';
        d.appendChild(label);

        // Hex preview of first 64 bytes
        const pre = document.createElement('pre'); pre.className = 'rtf-raw-source';
        pre.style.cssText += 'max-height:60px;overflow:auto;font-size:11px;';
        pre.textContent = eb.hexPreview;
        d.appendChild(pre);
        wrap.appendChild(d);
      }
    }

    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'medium', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    f.externalRefs.push({
      type: IOC.INFO,
      url: 'Windows Installer Package (.msi) — executes with elevated privileges during installation',
      severity: 'high'
    });

    try {
      const analysis = this._analyze(bytes);

      // Summary info as metadata
      f.metadata = analysis.summaryInfo;

      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${analysis.streams.length} OLE stream(s), ${analysis.tables.length} MSI table(s)`,
        severity: 'info'
      });

      // Report warnings
      for (const w of analysis.warnings) {
        f.externalRefs.push({ type: IOC.PATTERN, url: w.label, severity: w.sev });
      }

      // Report custom actions
      for (const ca of analysis.customActions) {
        f.externalRefs.push({ type: IOC.PATTERN, url: ca.label, severity: ca.sev });
      }

      // Escalate risk
      const hasCustomActions = analysis.customActions.length > 0;
      const hasEmbeddedPE = analysis.embeddedBinaries.some(b => b.isPE);
      const highWarnings = analysis.warnings.filter(w => w.sev === 'high' || w.sev === 'critical').length;

      if (hasEmbeddedPE) {
        f.risk = 'critical';
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `Embedded PE executable(s) detected in MSI binary streams`,
          severity: 'critical'
        });
      } else if (hasCustomActions || highWarnings >= 2) {
        f.risk = 'high';
      }
    } catch (e) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `MSI parse error: ${e.message}`,
        severity: 'info'
      });
    }

    return f;
  }

  // ── MSI analysis ─────────────────────────────────────────────────────────

  _analyze(bytes) {
    const result = {
      streams: [],
      tables: [],
      summaryInfo: {},
      warnings: [],
      customActions: [],
      embeddedBinaries: [],
    };

    // Parse OLE structure
    const ole = new OleCfbParser(bytes.buffer).parse();

    // Enumerate streams
    for (const [name, data] of ole.streams) {
      const flags = [];
      const ln = name.toLowerCase();
      let isSuspicious = false;

      // Detect PE headers in stream data
      const isPE = data.length >= 2 && data[0] === 0x4D && data[1] === 0x5A;
      if (isPE) { flags.push('PE executable'); isSuspicious = true; }

      // Detect script content
      if (data.length > 10) {
        const head = this._peekString(data, 200);
        if (/^\s*<script|^\s*function\s|^\s*sub\s|^\s*dim\s/i.test(head)) {
          flags.push('Script content'); isSuspicious = true;
        }
        if (/powershell|cmd\.exe|wscript|cscript/i.test(head)) {
          flags.push('Command execution'); isSuspicious = true;
        }
      }

      // Large binary streams
      if (data.length > 100000) flags.push('Large binary');

      // Known suspicious stream name patterns
      if (ln.includes('customaction') || ln.includes('binary')) {
        isSuspicious = true;
      }

      result.streams.push({ name, size: data.length, flags, isSuspicious });

      // Collect embedded binaries for detailed view
      if ((isPE || data.length > 50000) && (ln.includes('binary') || isPE)) {
        result.embeddedBinaries.push({
          name,
          size: data.length,
          isPE,
          magic: this._detectStreamMagic(data),
          hexPreview: this._hexPreview(data, 64),
        });
      }
    }

    // Identify MSI database tables from stream names
    // MSI encodes table names with a specific prefix pattern
    for (const [name] of ole.streams) {
      const tableName = this._decodeMsiTableName(name);
      if (tableName) {
        const isSuspicious = this._isSuspiciousTable(tableName);
        result.tables.push({ name: tableName, isSuspicious });

        if (isSuspicious) {
          result.warnings.push({
            label: `Suspicious MSI table: ${tableName}`,
            sev: 'medium'
          });
        }
      }
    }

    // Detect CustomAction table presence
    if (result.tables.some(t => t.name === 'CustomAction')) {
      result.customActions.push({
        label: 'CustomAction table present — installer can execute arbitrary code',
        sev: 'high'
      });
    }

    // Detect Binary table
    if (result.tables.some(t => t.name === 'Binary')) {
      result.customActions.push({
        label: 'Binary table present — contains embedded executables, DLLs, or scripts',
        sev: 'medium'
      });
    }

    // Check for specific dangerous tables
    if (result.tables.some(t => t.name === 'ServiceInstall')) {
      result.warnings.push({
        label: 'Service installation: MSI will install Windows service(s)',
        sev: 'high'
      });
    }
    if (result.tables.some(t => t.name === 'ServiceControl')) {
      result.warnings.push({
        label: 'Service control: MSI modifies Windows service state',
        sev: 'medium'
      });
    }
    if (result.tables.some(t => t.name === 'Registry')) {
      result.warnings.push({
        label: 'Registry modification: MSI writes to Windows registry',
        sev: 'medium'
      });
    }
    if (result.tables.some(t => t.name === 'LaunchCondition')) {
      result.warnings.push({
        label: 'Launch conditions: MSI checks system conditions before install',
        sev: 'info'
      });
    }
    if (result.tables.some(t => t.name === 'AppSearch')) {
      result.warnings.push({
        label: 'Application search: MSI searches for installed applications',
        sev: 'info'
      });
    }

    // Detect embedded PE files across all streams
    const peStreams = result.streams.filter(s => s.flags.includes('PE executable'));
    if (peStreams.length) {
      result.warnings.push({
        label: `${peStreams.length} stream(s) contain embedded PE executable(s): ${peStreams.map(s => s.name).join(', ')}`,
        sev: 'critical'
      });
    }

    // Detect script content
    const scriptStreams = result.streams.filter(s => s.flags.includes('Script content'));
    if (scriptStreams.length) {
      result.warnings.push({
        label: `${scriptStreams.length} stream(s) contain script content`,
        sev: 'high'
      });
    }

    // Extract Summary Information
    this._extractSummaryInfo(ole, result);

    // Deduplicate warnings
    const seen = new Set();
    result.warnings = result.warnings.filter(w => {
      if (seen.has(w.label)) return false;
      seen.add(w.label); return true;
    });

    return result;
  }

  // ── MSI table name decoding ──────────────────────────────────────────────
  // MSI stores table/column names in OLE stream names with a specific encoding:
  // Characters 0-9, A-Z, a-z, _, . are valid; encoded with a base-62 scheme.
  // Stream names prefixed with special chars indicate system tables.

  _decodeMsiTableName(streamName) {
    // MSI table streams have names that start with certain patterns
    // Skip known non-table streams
    const skip = [
      '\x05summaryinformation', '\x05documentsummaryinformation',
      '\x01comptobj', '\x05digital signature',
    ];
    if (skip.includes(streamName.toLowerCase())) return null;
    if (streamName.startsWith('\x05') || streamName.startsWith('\x01')) return null;

    // Known MSI table names — if the stream name matches directly
    const knownTables = [
      'ActionText', 'AdminExecuteSequence', 'AdminUISequence', 'AdvtExecuteSequence',
      'AdvtUISequence', 'AppId', 'AppSearch', 'BBControl', 'Billboard', 'Binary',
      'BindImage', 'CCPSearch', 'CheckBox', 'Class', 'ComboBox', 'CompLocator',
      'Complus', 'Component', 'Condition', 'Control', 'ControlCondition',
      'ControlEvent', 'CreateFolder', 'CustomAction', 'Dialog', 'Directory',
      'DrLocator', 'DuplicateFile', 'Environment', 'Error', 'EventMapping',
      'Extension', 'Feature', 'FeatureComponents', 'File', 'FileSFPCatalog',
      'Font', 'Icon', 'IniFile', 'IniLocator', 'InstallExecuteSequence',
      'InstallUISequence', 'IsolatedComponent', 'LaunchCondition', 'ListBox',
      'ListView', 'LockPermissions', 'Media', 'MIME', 'MoveFile',
      'MsiAssembly', 'MsiAssemblyName', 'MsiDigitalCertificate',
      'MsiDigitalSignature', 'MsiEmbeddedChainer', 'MsiEmbeddedUI',
      'MsiFileHash', 'MsiLockPermissionsEx', 'MsiPackageCertificate',
      'MsiPatchCertificate', 'MsiPatchHeaders', 'MsiPatchMetadata',
      'MsiPatchOldAssemblyFile', 'MsiPatchOldAssemblyName',
      'MsiPatchSequence', 'MsiServiceConfig', 'MsiServiceConfigFailureActions',
      'MsiShortcutProperty', 'ODBCAttribute', 'ODBCDataSource', 'ODBCDriver',
      'ODBCSourceAttribute', 'ODBCTranslator', 'Patch', 'PatchPackage',
      'ProgId', 'Property', 'PublishComponent', 'RadioButton', 'Registry',
      'RegLocator', 'RemoveFile', 'RemoveIniFile', 'RemoveRegistry',
      'ReserveCost', 'SelfReg', 'ServiceControl', 'ServiceInstall',
      'SFPCatalog', 'Shortcut', 'Signature', 'TextStyle', 'TypeLib',
      'UIText', 'Upgrade', 'Verb', '_Validation', '_Columns', '_Tables',
      '_StringData', '_StringPool',
    ];

    // Check if stream name matches a known table or looks like a valid table name
    if (knownTables.includes(streamName)) return streamName;

    // Check if it looks like a valid MSI identifier (alphanumeric + underscore)
    if (/^[A-Za-z_][A-Za-z0-9_.]*$/.test(streamName) && streamName.length <= 64) {
      return streamName;
    }

    return null;
  }

  _isSuspiciousTable(tableName) {
    const suspicious = [
      'CustomAction', 'Binary', 'ServiceInstall', 'ServiceControl',
      'Registry', 'RemoveRegistry', 'Environment', 'SelfReg',
      'MsiEmbeddedChainer', 'MsiEmbeddedUI',
    ];
    return suspicious.includes(tableName);
  }

  // ── Summary Information extraction ───────────────────────────────────────

  _extractSummaryInfo(ole, result) {
    // Try to read the \x05SummaryInformation stream
    const siStream = ole.streams.get('\x05summaryinformation') || ole.streams.get('\u0005summaryinformation');
    if (!siStream || siStream.length < 48) return;

    try {
      const dv = new DataView(siStream.buffer, siStream.byteOffset, siStream.byteLength);

      // Property Set Header
      // Byte order, version, OS, CLSID, num property sets
      const numSets = dv.getUint32(24, true);
      if (numSets < 1) return;

      // First property set offset
      const setOffset = dv.getUint32(44, true);
      if (setOffset >= siStream.length) return;

      const setSize = dv.getUint32(setOffset, true);
      const numProps = dv.getUint32(setOffset + 4, true);

      const propNames = {
        2: 'Title', 3: 'Subject', 4: 'Author', 5: 'Keywords',
        6: 'Comments', 7: 'Template', 8: 'Last Author',
        9: 'Revision Number', 12: 'Create Time', 13: 'Last Save Time',
        14: 'Page Count', 15: 'Word Count', 16: 'Character Count',
        18: 'Application', 19: 'Security',
      };

      for (let i = 0; i < Math.min(numProps, 30); i++) {
        const pidOff = setOffset + 8 + i * 8;
        if (pidOff + 8 > siStream.length) break;

        const pid = dv.getUint32(pidOff, true);
        const valOff = setOffset + dv.getUint32(pidOff + 4, true);
        if (valOff + 4 > siStream.length) continue;

        const propName = propNames[pid];
        if (!propName) continue;

        const vType = dv.getUint32(valOff, true);

        if (vType === 30) { // VT_LPSTR
          const len = dv.getUint32(valOff + 4, true);
          if (valOff + 8 + len <= siStream.length) {
            const str = new TextDecoder('utf-8', { fatal: false })
              .decode(siStream.subarray(valOff + 8, valOff + 8 + len - 1));
            if (str.trim()) result.summaryInfo[propName] = str.trim();
          }
        } else if (vType === 3) { // VT_I4
          result.summaryInfo[propName] = dv.getInt32(valOff + 4, true).toString();
        } else if (vType === 64) { // VT_FILETIME
          try {
            const lo = dv.getUint32(valOff + 4, true);
            const hi = dv.getUint32(valOff + 8, true);
            const ft = (BigInt(hi) << 32n) | BigInt(lo);
            const ms = Number(ft / 10000n) - 11644473600000;
            if (ms > 0 && ms < 4102444800000) {
              result.summaryInfo[propName] = new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
            }
          } catch (e) { }
        }
      }
    } catch (e) {
      // Silently fail — summary info is optional
    }
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  _peekString(data, maxLen) {
    const len = Math.min(data.length, maxLen);
    return new TextDecoder('utf-8', { fatal: false }).decode(data.subarray(0, len));
  }

  _detectStreamMagic(data) {
    if (data.length < 4) return 'Unknown';
    if (data[0] === 0x4D && data[1] === 0x5A) return 'PE Executable (MZ)';
    if (data[0] === 0x50 && data[1] === 0x4B) return 'ZIP / Cabinet';
    if (data[0] === 0xD0 && data[1] === 0xCF) return 'Nested OLE/CFB';
    if (data[0] === 0x89 && data[1] === 0x50 && data[2] === 0x4E && data[3] === 0x47) return 'PNG Image';
    if (data[0] === 0xFF && data[1] === 0xD8) return 'JPEG Image';
    if (data[0] === 0x47 && data[1] === 0x49 && data[2] === 0x46) return 'GIF Image';
    const head = this._peekString(data, 50);
    if (head.includes('<?xml') || head.includes('<html') || head.includes('<script')) return 'XML/HTML/Script';
    return 'Binary data';
  }

  _hexPreview(data, maxBytes) {
    const len = Math.min(data.length, maxBytes);
    const parts = [];
    for (let i = 0; i < len; i++) {
      parts.push(data[i].toString(16).padStart(2, '0').toUpperCase());
    }
    // Format as rows of 16 bytes
    const rows = [];
    for (let i = 0; i < parts.length; i += 16) {
      const hex = parts.slice(i, i + 16).join(' ');
      const ascii = Array.from(data.subarray(i, Math.min(i + 16, len)))
        .map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
      rows.push(`${i.toString(16).padStart(6, '0')}  ${hex.padEnd(47)}  ${ascii}`);
    }
    return rows.join('\n');
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
