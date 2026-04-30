'use strict';
// ════════════════════════════════════════════════════════════════════════════
// msi-renderer.js — Windows Installer (.msi) analysis (lightweight)
// Uses OleCfbParser in metadata-only mode to avoid loading large stream content.
// Extracts: Summary Information, MSI table names, stream listing (name+size).
// Depends on: ole-cfb-parser.js, constants.js (IOC, escHtml)
// ════════════════════════════════════════════════════════════════════════════

const MSI_SIZE_LIMIT = 50 * 1024 * 1024; // 50MB - show simplified view above this

// ── MSI CustomAction type code classification ───────────────────────────────
// The CustomAction.Type column is a bit-field. The low 6 bits (mask 0x3F)
// identify the action source/target. Upper bits control scheduling, impersonation,
// synchronisation, etc. See:
//   https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-reference
const MSI_CA_TYPES = Object.freeze({
  0x01: { label: 'DLL stored in Binary table',             sev: 'high' },
  0x02: { label: 'EXE stored in Binary table',             sev: 'critical' },
  0x05: { label: 'JScript stored in Binary table',         sev: 'critical' },
  0x06: { label: 'VBScript stored in Binary table',        sev: 'critical' },
  0x11: { label: 'DLL installed with product',             sev: 'high' },
  0x12: { label: 'EXE installed with product',             sev: 'high' },
  0x15: { label: 'JScript referenced by installed file',   sev: 'critical' },
  0x16: { label: 'VBScript referenced by installed file',  sev: 'critical' },
  0x22: { label: 'EXE with command-line (existing file)',  sev: 'critical' },
  0x23: { label: 'Directory set by formatted text',        sev: 'info' },
  0x25: { label: 'JScript from property',                  sev: 'critical' },
  0x26: { label: 'VBScript from property',                 sev: 'critical' },
  0x32: { label: 'EXE command-line via Directory',         sev: 'critical' },
  0x33: { label: 'Property set from formatted text',       sev: 'info' },
  0x35: { label: 'JScript with formatted source+target',   sev: 'critical' },
  0x36: { label: 'VBScript with formatted source+target',  sev: 'critical' },
  0x37: { label: 'JScript from nested CA source',          sev: 'critical' },
  0x38: { label: 'VBScript from nested CA source',         sev: 'critical' },
  0x3E: { label: 'Concurrent advertisement (nested)',      sev: 'medium' },
});
const MSI_CA_FLAGS = Object.freeze([
  { mask: 0x0040, label: 'Continue-on-error' },
  { mask: 0x0080, label: 'Async (no wait)' },
  { mask: 0x0100, label: 'Return-code ignored' },
  { mask: 0x0400, label: 'First-sequence' },
  { mask: 0x0800, label: 'Once-per-process' },
  { mask: 0x1000, label: 'Commit-phase' },
  { mask: 0x2000, label: 'Rollback-phase' },
  { mask: 0x4000, label: 'Deferred execution' },
  { mask: 0x3000, label: 'In-script (deferred)' },
]);

class MsiRenderer {


  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const wrap = document.createElement('div'); wrap.className = 'msi-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    const bannerStrong = document.createElement('strong'); bannerStrong.textContent = 'Windows Installer Package (.msi)';
    banner.appendChild(bannerStrong);
    banner.appendChild(document.createTextNode(' — click any stream to analyze its contents. MSI files execute with elevated privileges and can run custom actions, modify the registry, and install services.'));
    wrap.appendChild(banner);

    // Cleanup previous OLE parser reference to prevent memory leaks
    this._ole = null;

    // Check for large files
    if (bytes.length > MSI_SIZE_LIMIT) {
      return this._renderLargeFileView(wrap, bytes, fileName);
    }

    let analysis;
    try {
      analysis = this._analyze(bytes);
    } catch (e) {
      const err = document.createElement('div'); err.className = 'error-box';
      err.textContent = `Failed to parse MSI: ${e.message}`;
      wrap.appendChild(err);
      return wrap;
    }

    // Summary info line
    const infoDiv = document.createElement('div'); infoDiv.className = 'plaintext-info';
    infoDiv.textContent = `${analysis.streams.length} stream(s)  ·  ${this._fmtBytes(bytes.length)}  ·  Windows Installer Package`;
    wrap.appendChild(infoDiv);

    // Warnings
    if (analysis.warnings.length) {
      const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
      for (const w of analysis.warnings) {
        const d = document.createElement('div');
        d.className = `zip-warning zip-warning-${w.sev}`;
        d.textContent = `${w.sev === 'critical' ? '🚨' : '⚠'} ${w.label}`;
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
        chip.style.cssText = `display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-family:monospace;${t.isSuspicious ? 'background:rgb(var(--risk-high-rgb) / .15);color:var(--risk-high);border:1px solid rgb(var(--risk-high-rgb) / .3);' : 'background:rgb(var(--accent-rgb) / .08);color:var(--accent);border:1px solid rgb(var(--accent-rgb) / .15);'}`;
        chip.textContent = t.name;
        chip.title = t.isSuspicious ? 'Potentially dangerous table' : '';
        chips.appendChild(chip);
      }
      tblDiv.appendChild(chips); wrap.appendChild(tblDiv);
    }

    // Custom Actions / Security Warnings
    if (analysis.customActions.length) {
      const caH = document.createElement('div'); caH.className = 'hta-section-hdr';
      caH.textContent = `Security Concerns (${analysis.customActions.length})`;
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

    // OLE Streams (clickable for analysis)
    if (analysis.streams.length) {
      const stH = document.createElement('div'); stH.className = 'hta-section-hdr';
      stH.textContent = `OLE Streams (${analysis.streams.length})`;
      wrap.appendChild(stH);

      const stTbl = document.createElement('table'); stTbl.className = 'lnk-info-table';
      // Header
      const hdr = document.createElement('tr');
      for (const h of ['Stream Name', 'Size', 'Action']) {
        const th = document.createElement('td'); th.className = 'lnk-lbl';
        th.style.cssText = 'font-weight:bold;'; th.textContent = h;
        hdr.appendChild(th);
      }
      stTbl.appendChild(hdr);

      for (const s of analysis.streams) {
        const tr = document.createElement('tr');
        tr.classList.add('zip-row-clickable');

        const tdN = document.createElement('td'); tdN.className = 'lnk-val';
        tdN.textContent = s.name;
        tdN.style.cssText = 'font-family:monospace;font-size:12px;';

        const tdS = document.createElement('td'); tdS.className = 'lnk-val';
        tdS.textContent = this._fmtBytes(s.size);
        tdS.style.cssText = 'min-width:80px;';

        const tdAction = document.createElement('td'); tdAction.className = 'lnk-val';
        if (s.size > 0) {
          const openBtn = document.createElement('span'); openBtn.className = 'zip-badge-open';
          openBtn.textContent = '🔍 Open';
          openBtn.title = `Open ${s.name} for analysis`;
          openBtn.addEventListener('click', (ev) => {
            ev.stopPropagation();
            this._extractAndOpenStream(s.rawName, s.name, s.size, wrap);
          });
          tdAction.appendChild(openBtn);
        }

        tr.appendChild(tdN); tr.appendChild(tdS); tr.appendChild(tdAction);
        stTbl.appendChild(tr);
      }
      wrap.appendChild(stTbl);
    }

    return wrap;
  }

  /**
   * Render a simplified view for very large MSI files (>50MB)
   */
  _renderLargeFileView(wrap, bytes, fileName) {
    const infoDiv = document.createElement('div'); infoDiv.className = 'plaintext-info';
    infoDiv.textContent = `${this._fmtBytes(bytes.length)}  ·  Windows Installer Package  ·  Large file mode`;
    wrap.appendChild(infoDiv);

    const noteDiv = document.createElement('div');
    noteDiv.className = 'zip-warning zip-warning-info';
    noteDiv.style.cssText = 'margin:8px;';
    noteDiv.textContent = 'Large MSI file — showing summary information only for performance.';
    wrap.appendChild(noteDiv);

    // Try to extract just the Summary Information
    try {
      const ole = new OleCfbParser(bytes.buffer).parseMetadataOnly();
      const summaryInfo = this._extractSummaryInfoLazy(ole);

      if (summaryInfo && Object.keys(summaryInfo).length) {
        const siH = document.createElement('div'); siH.className = 'hta-section-hdr';
        siH.textContent = 'Summary Information';
        wrap.appendChild(siH);

        const tbl = document.createElement('table'); tbl.className = 'lnk-info-table';
        for (const [key, val] of Object.entries(summaryInfo)) {
          const tr = document.createElement('tr');
          const tdL = document.createElement('td'); tdL.className = 'lnk-lbl'; tdL.textContent = key;
          const tdV = document.createElement('td'); tdV.className = 'lnk-val'; tdV.textContent = val;
          tr.appendChild(tdL); tr.appendChild(tdV); tbl.appendChild(tr);
        }
        wrap.appendChild(tbl);
      }

      // Show stream count and list table names only
      const streamCount = ole.streamMeta.size;
      const tables = [];
      for (const [name] of ole.streamMeta) {
        const tableName = this._decodeMsiTableName(name);
        if (tableName) tables.push({ name: tableName, isSuspicious: this._isSuspiciousTable(tableName) });
      }

      if (streamCount > 0) {
        const countDiv = document.createElement('div'); countDiv.className = 'plaintext-info';
        countDiv.style.cssText = 'margin-top:8px;';
        countDiv.textContent = `Contains ${streamCount} OLE stream(s), ${tables.length} MSI table(s)`;
        wrap.appendChild(countDiv);
      }

      // Show suspicious tables if any
      const suspicious = tables.filter(t => t.isSuspicious);
      if (suspicious.length) {
        const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
        for (const t of suspicious) {
          const d = document.createElement('div');
          d.className = 'zip-warning zip-warning-medium';
          d.textContent = `⚠ Contains ${t.name} table`;
          warnDiv.appendChild(d);
        }
        wrap.appendChild(warnDiv);
      }

    } catch (e) {
      const err = document.createElement('div'); err.className = 'error-box';
      err.textContent = `Could not extract metadata: ${e.message}`;
      wrap.appendChild(err);
    }

    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    const f = {
      // Start 'low'; the monotonic `bumpRisk()` helper below is driven by
      // real evidence (CustomActions, scripts, suspicious commands, signature
      // verdict) — so a clean MSI stays 'low'.
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    f.externalRefs.push({
      type: IOC.INFO,
      url: 'Windows Installer Package (.msi) — executes with elevated privileges during installation',
      severity: 'high'
    });

    const bumpRisk = (s) => escalateRisk(f, s);

    try {
      // Use metadata-only parsing for security analysis too
      const ole = new OleCfbParser(bytes.buffer).parseMetadataOnly();

      // Extract summary info (loads one small stream)
      const summaryInfo = this._extractSummaryInfoLazy(ole);
      f.metadata = summaryInfo || {};

      // Identify tables from stream names
      const tables = [];
      for (const [name] of ole.streamMeta) {
        const tableName = this._decodeMsiTableName(name);
        if (tableName) tables.push(tableName);
      }

      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${ole.streamMeta.size} OLE stream(s), ${tables.length} MSI table(s)`,
        severity: 'info'
      });

      // ── T2.11: _Validation table absence flag ─────────────────────────
      if (!tables.includes('_Validation')) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: 'MSI lacks _Validation table — common in repackaged/trojanized installers',
          severity: 'medium'
        });
        bumpRisk('medium');
      }

      // Check for dangerous tables
      const hasCustomAction = tables.includes('CustomAction');
      const hasBinary = tables.includes('Binary');
      const hasServiceInstall = tables.includes('ServiceInstall');
      const hasRegistry = tables.includes('Registry');

      if (hasCustomAction) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: 'CustomAction table present — installer can execute arbitrary code',
          severity: 'high'
        });
        bumpRisk('high');
      }

      if (hasBinary) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: 'Binary table present — contains embedded executables, DLLs, or scripts',
          severity: 'medium'
        });
      }

      if (hasServiceInstall) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: 'ServiceInstall table — MSI will install Windows service(s)',
          severity: 'high'
        });
        bumpRisk('high');
      }

      if (hasRegistry) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: 'Registry table — MSI modifies Windows registry',
          severity: 'medium'
        });
      }

      // Escalate to high if multiple concerning tables
      const concernCount = [hasCustomAction, hasBinary, hasServiceInstall].filter(Boolean).length;
      if (concernCount >= 2) bumpRisk('high');

      // ── Deep decode: string pool + CustomAction rows + Binary streams ───
      const stringPool = this._parseStringPool(ole);
      if (stringPool) {
        f.metadata.stringPoolEntries = stringPool.length;

        // CustomAction rows — per-row type classification
        if (hasCustomAction) {
          const rows = this._parseCustomActionRows(ole, stringPool);
          if (rows && rows.length) {
            f.metadata.customActionCount = rows.length;
            const typeSummary = new Map();
            for (const row of rows) {
              const lowType = row.type & 0x3F;
              const info = MSI_CA_TYPES[lowType];
              const flagBits = [];
              for (const fl of MSI_CA_FLAGS) {
                if ((row.type & fl.mask) === fl.mask) flagBits.push(fl.label);
              }
              const typeLabel = info ? info.label : `unknown CA type 0x${lowType.toString(16)}`;
              const sev = info ? info.sev : 'medium';
              const key = `${lowType}:${row.source || ''}`;
              if (!typeSummary.has(key)) typeSummary.set(key, 0);
              typeSummary.set(key, typeSummary.get(key) + 1);
              const noteParts = [
                `CustomAction "${row.action}"`,
                `type 0x${row.type.toString(16).padStart(4, '0')} (${typeLabel})`,
              ];
              if (row.source) noteParts.push(`source="${this._truncateStr(row.source, 48)}"`);
              if (row.target) noteParts.push(`target="${this._truncateStr(row.target, 96)}"`);
              if (flagBits.length) noteParts.push(`flags=[${flagBits.join(', ')}]`);
              const isInScript = (row.type & 0x3000) !== 0;
              const finalSev = isInScript && sev === 'high' ? 'critical' : sev;
              f.externalRefs.push({
                type: IOC.COMMAND_LINE,
                url: noteParts.join(' · '),
                severity: finalSev
              });
              bumpRisk(finalSev);

              // Surface likely command-line payloads as raw IOCs too
              if (row.target && [0x02, 0x12, 0x22, 0x32].includes(lowType)) {
                f.externalRefs.push({
                  type: IOC.COMMAND_LINE,
                  url: row.target,
                  severity: 'critical'
                });
                bumpRisk('critical');
              }
              // JScript/VBScript payload body
              if (row.target && [0x05, 0x06, 0x15, 0x16, 0x25, 0x26, 0x35, 0x36, 0x37, 0x38].includes(lowType)) {
                f.externalRefs.push({
                  type: IOC.PATTERN,
                  url: `Inline script body (${lowType === 0x05 || lowType === 0x15 || lowType === 0x25 || lowType === 0x35 || lowType === 0x37 ? 'JScript' : 'VBScript'}): ${this._truncateStr(row.target, 160)}`,
                  severity: 'critical'
                });
                bumpRisk('critical');
              }
            }
          }
        }

        // Binary stream enumeration — sniff magic bytes of each Binary.{name}
        if (hasBinary) {
          const binStreams = this._enumerateBinaryStreams(ole);
          if (binStreams.length) {
            f.metadata.binaryStreamCount = binStreams.length;
            const sniffTypes = [];
            let cabCount = 0;
            for (const bs of binStreams) {
              sniffTypes.push(`${bs.name}(${bs.magic.type})`);
              if (bs.magic.isCab) cabCount++;
              const sevMap = {
                'PE Executable': 'high',
                'DLL': 'high',
                'Microsoft Cabinet': 'high',
                'JScript/VBScript': 'critical',
                'Batch/Shell Script': 'high',
                'PowerShell Script': 'critical',
                'ZIP Archive': 'medium',
                '7z Archive': 'medium',
                'Unknown/Data': 'info',
              };
              const sev = sevMap[bs.magic.type] || 'medium';
              f.externalRefs.push({
                type: IOC.PATTERN,
                url: `Binary stream "${bs.name}" (${this._fmtBytes(bs.size)}) — magic: ${bs.magic.type}`,
                severity: sev
              });
              if (sev === 'high' || sev === 'critical') bumpRisk(sev);
            }
            if (cabCount) {
              f.metadata.embeddedCabs = cabCount;
              f.externalRefs.push({
                type: IOC.PATTERN,
                url: `${cabCount} embedded Microsoft Cabinet (CAB) archive(s) in Binary table — payloads inside are not recursively unpacked`,
                severity: 'high'
              });
              bumpRisk('high');
            }
            if (sniffTypes.length <= 20) f.metadata.binaryStreamSniff = sniffTypes;
          }
        }
      }

      // ── Authenticode signature verdict ────────────────────────────────
      const sigVerdict = this._checkAuthenticode(ole);
      if (sigVerdict) {
        f.metadata.authenticode = sigVerdict.summary;
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: sigVerdict.note,
          severity: sigVerdict.severity
        });
        if (sigVerdict.severity === 'high') bumpRisk('high');
      }

    } catch (e) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `MSI parse error: ${e.message}`,
        severity: 'info'
      });
    }

    // Mirror classic-pivot metadata into the IOC table. MSI Summary
    // Information carries no GUIDs, but "Author" / "Last Author" are
    // genuine usernames embedded by authoring tools.
    mirrorMetadataIOCs(f, {
      'Author':       IOC.USERNAME,
      'Last Author':  IOC.USERNAME,
    });

    return f;
  }

  // ── MSI analysis (lightweight, metadata-only) ────────────────────────────

  _analyze(bytes) {
    const result = {
      streams: [],
      tables: [],
      summaryInfo: {},
      warnings: [],
      customActions: [],
    };

    // Parse OLE structure in metadata-only mode (no stream content loading)
    const ole = new OleCfbParser(bytes.buffer).parseMetadataOnly();
    // Store OLE parser for on-demand stream extraction when user clicks
    this._ole = ole;

    // Enumerate streams (metadata only - name and size, decoded + raw for extraction)
    for (const [name, meta] of ole.streamMeta) {
      result.streams.push({
        name: this._decodeMsiStreamName(name),  // Decoded display name
        rawName: name,                           // Raw name for getStream() lookup
        size: meta.size
      });
    }

    // Identify MSI database tables from stream names
    for (const [name] of ole.streamMeta) {
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

    // Extract Summary Information (loads one small stream on demand)
    result.summaryInfo = this._extractSummaryInfoLazy(ole) || {};

    // Deduplicate warnings
    const seen = new Set();
    result.warnings = result.warnings.filter(w => {
      if (seen.has(w.label)) return false;
      seen.add(w.label); return true;
    });

    return result;
  }

  // ── MSI stream name decoding ──────────────────────────────────────────────
  // MSI encodes stream names using a base-64-like scheme:
  // - 0x4840 = start marker (skip)
  // - 0x3800-0x383F = single character (base-64 digit)
  // - 0x3840-0x483F = two characters (high = val/64, low = val%64)
  // Base-64 mapping: 0-9=0-9, A-Z=10-35, a-z=36-61, _=62, .=63

  _decodeMsiStreamName(encoded) {
    let result = '';
    const decodeDigit = (val) => {
      if (val < 10) return String.fromCharCode(0x30 + val);        // 0-9
      if (val < 36) return String.fromCharCode(0x41 + val - 10);   // A-Z
      if (val < 62) return String.fromCharCode(0x61 + val - 36);   // a-z
      if (val === 62) return '_';
      if (val === 63) return '.';
      return '?';
    };

    for (const c of encoded) {
      const code = c.charCodeAt(0);
      if (code === 0x4840) continue; // Skip start marker

      if (code >= 0x3800 && code < 0x3840) {
        // Single character encoding
        result += decodeDigit(code - 0x3800);
      } else if (code >= 0x3840 && code < 0x4840) {
        // Two-character encoding
        const val = code - 0x3840;
        result += decodeDigit(Math.floor(val / 64));
        result += decodeDigit(val % 64);
      } else {
        // Pass through other characters (e.g., regular ASCII)
        result += c;
      }
    }
    return result;
  }

  _decodeMsiTableName(streamName) {
    // Skip known non-table streams (check original name before decoding)
    const lowerName = streamName.toLowerCase();
    const skip = [
      '\x05summaryinformation', '\x05documentsummaryinformation',
      '\x01comptobj', '\x05digital signature',
    ];
    if (skip.includes(lowerName)) return null;
    if (streamName.charAt(0) === '\x05' || streamName.charAt(0) === '\x01') return null;

    // Decode MSI-encoded stream name
    const decoded = this._decodeMsiStreamName(streamName);
    if (!decoded) return null;

    // Known MSI table names (for proper casing in output)
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

    // Check against known tables (case-insensitive) and return proper casing
    const lowerDecoded = decoded.toLowerCase();
    for (const tableName of knownTables) {
      if (tableName.toLowerCase() === lowerDecoded) return tableName;
    }

    // Check if it looks like a valid MSI identifier (alphanumeric + underscore)
    if (/^[A-Za-z_][A-Za-z0-9_.]*$/.test(decoded) && decoded.length <= 64) {
      return decoded;
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

  // ── Summary Information extraction (lazy loading) ────────────────────────

  _extractSummaryInfoLazy(ole) {
    // Load Summary Information stream on demand
    const siStream = ole.getStream('\x05summaryinformation') || ole.getStream('\u0005summaryinformation');
    if (!siStream || siStream.length < 48) return null;

    return this._parseSummaryInfo(siStream);
  }

  _parseSummaryInfo(siStream) {
    const result = {};

    try {
      const dv = new DataView(siStream.buffer, siStream.byteOffset, siStream.byteLength);

      // Property Set Header
      const numSets = dv.getUint32(24, true);
      if (numSets < 1) return result;

      // First property set offset
      const setOffset = dv.getUint32(44, true);
      if (setOffset >= siStream.length) return result;

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
            if (str.trim()) result[propName] = str.trim();
          }
        } else if (vType === 3) { // VT_I4
          result[propName] = dv.getInt32(valOff + 4, true).toString();
        } else if (vType === 64) { // VT_FILETIME
          try {
            const lo = dv.getUint32(valOff + 4, true);
            const hi = dv.getUint32(valOff + 8, true);
            const ft = (BigInt(hi) << 32n) | BigInt(lo);
            const ms = Number(ft / 10000n) - 11644473600000;
            if (ms > 0 && ms < 4102444800000) {
              result[propName] = new Date(ms).toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
            }
          } catch (e) { }
        }
      }
    } catch (e) {
      // Silently fail — summary info is optional
    }

    return result;
  }

  // ── Stream extraction for click-to-open ───────────────────────────────────

  _extractAndOpenStream(rawName, displayName, size, wrap) {
    if (!this._ole) {
      console.warn('OLE parser not available for stream extraction');
      return;
    }

    try {
      // Get stream content from OLE parser (on-demand loading)
      const data = this._ole.getStream(rawName);
      if (!data || data.length === 0) {
        console.warn('Stream empty or not found:', rawName);
        return;
      }

      // Create a File object with the stream content
      // Use displayName for the filename (decoded MSI name)
      const file = new File([data], displayName, { type: 'application/octet-stream' });

      // Dispatch custom event for the app to handle (same pattern as ZIP renderer)
      wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
    } catch (e) {
      console.warn('Failed to extract stream:', rawName, e.message);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Deep MSI decoding — string pool, CustomAction rows, Binary streams,
  // Authenticode signature verdict. Called by analyzeForSecurity only.
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Parse the MSI _StringPool + _StringData streams into a flat array of
   * strings indexed by string-id (1-based; index 0 = empty/null).
   *
   *   _StringPool: u16 recordCount; records of (u16 len, u16 refCount)
   *                — a zero-length record followed by a non-zero len means
   *                  the previous record was a long-string high-word.
   *   _StringData: concatenated UTF-8 bytes for each record's length.
   *
   * Returns null if either stream is absent or malformed.
   */
  _parseStringPool(ole) {
    const pool = this._findMsiStream(ole, '_StringPool');
    const data = this._findMsiStream(ole, '_StringData');
    if (!pool || !data) return null;
    const strings = [''];
    try {
      const dv = new DataView(pool.buffer, pool.byteOffset, pool.byteLength);
      const dec = new TextDecoder('utf-8', { fatal: false });
      // First record is the codepage/header at offset 0 (u32). Skip it.
      let p = 4;
      let d = 0;
      const dataLen = data.length;
      while (p + 4 <= pool.byteLength && strings.length < 200000) {
        let len = dv.getUint16(p, true);
        p += 2;
        const refCount = dv.getUint16(p, true);
        p += 2;
        // Long-string encoding: len==0 with refCount != 0 means the next
        // record's len field is actually the high word of a 32-bit length.
        if (len === 0 && refCount !== 0) {
          if (p + 4 > pool.byteLength) break;
          const loLen = dv.getUint16(p, true);
          const _hiRef = dv.getUint16(p + 2, true); // real refCount for this long record — unused here
          p += 4;
          len = (refCount << 16) | loLen;
        }
        if (len === 0) {
          strings.push('');
          continue;
        }
        if (d + len > dataLen) break;
        const s = dec.decode(data.subarray(d, d + len));
        strings.push(s);
        d += len;
      }
    } catch (_) { return null; }
    return strings;
  }

  /**
   * Parse the CustomAction table. The MSI table format stores columns as
   * parallel arrays: the stream contains column 0's values for all rows,
   * then column 1's values, etc. Strings are stored as string-pool IDs
   * (u16 or u32 depending on pool size). CustomAction has 4 columns:
   *   Action (Identifier, string), Type (Integer, u16), Source (string?),
   *   Target (string?). An optional 5th ExtendedType column exists on
   *   newer MSIs but isn't critical here.
   */
  _parseCustomActionRows(ole, pool) {
    const stream = this._findMsiStream(ole, 'CustomAction');
    if (!stream) return null;
    const wide = pool.length >= 0x10000; // use u32 string IDs if pool is huge
    const strSize = wide ? 4 : 2;
    const rowSize = strSize + 2 + strSize + strSize; // Action+Type+Source+Target
    const nRows = Math.floor(stream.length / rowSize);
    if (!nRows) return null;
    const dv = new DataView(stream.buffer, stream.byteOffset, stream.byteLength);
    const readStr = (off) => {
      if (off + strSize > stream.length) return '';
      const id = wide ? dv.getUint32(off, true) : dv.getUint16(off, true);
      if (id === 0 || id >= pool.length) return '';
      return pool[id] || '';
    };
    // Column offsets (each column stores nRows entries contiguously)
    const col0 = 0;                   // Action
    const col1 = col0 + strSize * nRows; // Type
    const col2 = col1 + 2 * nRows;    // Source
    const col3 = col2 + strSize * nRows; // Target
    if (col3 + strSize * nRows > stream.length) {
      // Fall back: treat the stream as row-major if column-major decode
      // would overrun. Extremely rare, but keeps us resilient.
      const rows = [];
      for (let r = 0; r < nRows && rows.length < 200; r++) {
        const base = r * rowSize;
        rows.push({
          action: readStr(base),
          type:   dv.getUint16(base + strSize, true),
          source: readStr(base + strSize + 2),
          target: readStr(base + strSize + 2 + strSize),
        });
      }
      return rows;
    }
    const rows = [];
    for (let r = 0; r < nRows && rows.length < 200; r++) {
      rows.push({
        action: readStr(col0 + r * strSize),
        type:   dv.getUint16(col1 + r * 2, true),
        source: readStr(col2 + r * strSize),
        target: readStr(col3 + r * strSize),
      });
    }
    return rows;
  }

  /**
   * Enumerate Binary.* streams, sniff magic bytes of each. Returns array of
   *   { name, size, magic: { type, isCab } }
   */
  _enumerateBinaryStreams(ole) {
    const out = [];
    for (const [rawName, meta] of ole.streamMeta) {
      if (!rawName || rawName.charAt(0) === '\x05' || rawName.charAt(0) === '\x01') continue;
      const decoded = this._decodeMsiStreamName(rawName);
      if (!/^Binary\./i.test(decoded)) continue;
      const data = ole.getStream(rawName);
      if (!data || data.length < 2) continue;
      out.push({
        name: decoded,
        size: meta.size,
        magic: this._sniffBinaryMagic(data),
      });
      if (out.length >= 50) break;
    }
    return out;
  }

  _sniffBinaryMagic(bytes) {
    const n = bytes.length;
    if (n >= 2 && bytes[0] === 0x4D && bytes[1] === 0x5A) {
      // PE — check Characteristics for DLL bit at IMAGE_FILE_HEADER
      try {
        const dv = new DataView(bytes.buffer, bytes.byteOffset, Math.min(n, 256));
        const peOff = dv.getUint32(0x3C, true);
        if (peOff + 24 < n && dv.getUint32(peOff, true) === 0x00004550) {
          const chars = dv.getUint16(peOff + 4 + 18, true);
          if (chars & 0x2000) return { type: 'DLL', isCab: false };
        }
      } catch (_) { }
      return { type: 'PE Executable', isCab: false };
    }
    if (n >= 4 && bytes[0] === 0x4D && bytes[1] === 0x53 && bytes[2] === 0x43 && bytes[3] === 0x46) {
      return { type: 'Microsoft Cabinet', isCab: true };
    }
    if (n >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04) {
      return { type: 'ZIP Archive', isCab: false };
    }
    if (n >= 4 && bytes[0] === 0x37 && bytes[1] === 0x7A && bytes[2] === 0xBC && bytes[3] === 0xAF) {
      return { type: '7z Archive', isCab: false };
    }
    // Text sniff on first 512 bytes
    try {
      const sample = new TextDecoder('utf-8', { fatal: false })
        .decode(bytes.subarray(0, Math.min(n, 512)));
      if (/^\s*#!/i.test(sample) || /^\s*@echo\s+off/i.test(sample) || /^\s*echo\s+off/i.test(sample)) {
        return { type: 'Batch/Shell Script', isCab: false };
      }
      if (/^\s*(?:param\s*\(|function\s+\w+|\$[A-Za-z_])/i.test(sample) ||
          /Invoke-Expression|IEX\s*\(|FromBase64String/i.test(sample)) {
        return { type: 'PowerShell Script', isCab: false };
      }
      if (/\b(?:WScript|CreateObject|MsgBox|Sub\s+\w+\s*\(|Function\s+\w+\s*\()/i.test(sample) ||
          /\bvar\s+\w+\s*=|document\.|window\./i.test(sample)) {
        return { type: 'JScript/VBScript', isCab: false };
      }
    } catch (_) { }
    return { type: 'Unknown/Data', isCab: false };
  }

  /**
   * Locate the Binary/CustomAction/_StringPool etc. stream by MSI-encoded name.
   */
  _findMsiStream(ole, logicalName) {
    for (const [rawName] of ole.streamMeta) {
      if (!rawName) continue;
      if (rawName.charAt(0) === '\x05' || rawName.charAt(0) === '\x01') continue;
      const decoded = this._decodeMsiStreamName(rawName);
      if (decoded === logicalName) return ole.getStream(rawName);
    }
    return null;
  }

  /**
   * Detect Authenticode / MsiDigitalSignature stream presence. This is a
   * list-only verdict — we report whether the PKCS#7 signature blob is
   * present and its length, without verifying the cert chain (offline, no
   * CRL/OCSP). An absent signature is surfaced as an info-level finding.
   */
  _checkAuthenticode(ole) {
    // MSI signatures live in these possible streams:
    //   \x05DigitalSignature       — root-level Authenticode blob (PKCS#7)
    //   \x05MsiDigitalSignatureEx  — extended/hash-of-substorages variant
    //   MsiDigitalSignature        — MSI table (per-row signatures)
    const candidates = ['\x05DigitalSignature', '\x05MsiDigitalSignatureEx'];
    let sigBlob = null;
    let sigName = null;
    for (const c of candidates) {
      const lower = c.toLowerCase();
      for (const [rawName] of ole.streamMeta) {
        if (rawName.toLowerCase() === lower) {
          sigBlob = ole.getStream(rawName);
          sigName = c;
          break;
        }
      }
      if (sigBlob) break;
    }
    if (!sigBlob || sigBlob.length < 16) {
      return {
        summary: 'unsigned',
        note: 'Unsigned MSI — no Authenticode \x05DigitalSignature stream present',
        severity: 'medium',
      };
    }
    // Sniff the signature bytes — PKCS#7 SignedData starts with a SEQUENCE
    // (0x30) followed by a length. We don't chain-validate (offline), just
    // report presence + length.
    const looksPkcs7 = sigBlob[0] === 0x30;
    return {
      summary: `signed (${this._fmtBytes(sigBlob.length)}${looksPkcs7 ? '' : ', malformed'})`,
      note: `Authenticode signature present — ${sigName} stream (${this._fmtBytes(sigBlob.length)}, PKCS#7 ${looksPkcs7 ? 'SEQUENCE' : 'unrecognised'}). Signature validity is not verified offline.`,
      severity: 'info',
    };
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  _truncateStr(s, maxLen) {
    if (!s) return '';
    const str = String(s);
    return str.length > maxLen ? str.substring(0, maxLen) + '…' : str;
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
