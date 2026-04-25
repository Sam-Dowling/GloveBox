'use strict';
// ════════════════════════════════════════════════════════════════════════════
// reg-renderer.js — Windows Registry File (.reg) analysis
// Parses registry entries, highlights dangerous keys/values, security scanning.
// Depends on: constants.js (IOC, escHtml)
// ════════════════════════════════════════════════════════════════════════════
class RegRenderer {

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = this._decodeText(bytes);
    const wrap = document.createElement('div'); wrap.className = 'reg-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>⚠ Windows Registry File (.reg)</strong> — Importing this file will modify the Windows registry. Registry changes can alter system behaviour, disable security features, install persistence mechanisms, and enable malware execution.';
    wrap.appendChild(banner);

    // Detect version header
    const version = text.trimStart().startsWith('Windows Registry Editor Version 5.00')
      ? 'Windows Registry Editor Version 5.00 (Unicode/Win2K+)'
      : text.trimStart().startsWith('REGEDIT4')
        ? 'REGEDIT4 (ANSI/Win9x legacy)'
        : 'Unknown format';

    // Parse entries
    const analysis = this._analyze(text);

    // Summary info
    const infoDiv = document.createElement('div'); infoDiv.className = 'plaintext-info';
    infoDiv.textContent = `${version}  ·  ${analysis.keys.length} key(s)  ·  ${analysis.values.length} value(s)  ·  ${analysis.deletions.length} deletion(s)`;
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

    // Registry key/value table
    if (analysis.keys.length) {
      const secH = document.createElement('div'); secH.className = 'hta-section-hdr';
      secH.textContent = `Registry Keys (${analysis.keys.length})`;
      wrap.appendChild(secH);

      for (const key of analysis.keys) {
        const keyDiv = document.createElement('div');
        keyDiv.style.cssText = 'margin:8px 0 2px 0;';

        const keyLabel = document.createElement('div');
        keyLabel.style.cssText = `padding:4px 8px;font-family:monospace;font-size:13px;border-left:3px solid ${key.isDeletion ? 'var(--risk-high)' : key.isSuspicious ? 'var(--risk-high)' : 'var(--accent)'};background:${key.isDeletion ? 'rgb(var(--risk-high-rgb) / .12)' : key.isSuspicious ? 'rgb(var(--risk-high-rgb) / .08)' : 'rgb(var(--accent-rgb) / .05)'};`;
        keyLabel.textContent = (key.isDeletion ? '🗑 DELETE: ' : '📁 ') + key.path;
        keyDiv.appendChild(keyLabel);

        // Values under this key
        const keyValues = analysis.values.filter(v => v.keyPath === key.path);
        if (keyValues.length) {
          const tbl = document.createElement('table'); tbl.className = 'lnk-info-table';
          tbl.style.cssText = 'margin:0 0 0 16px;';
          for (const v of keyValues) {
            const tr = document.createElement('tr');
            const tdN = document.createElement('td'); tdN.className = 'lnk-lbl';
            tdN.textContent = v.name || '(Default)';
            tdN.style.cssText += v.isSuspicious ? 'color:var(--risk-high);' : '';
            const tdT = document.createElement('td'); tdT.className = 'lnk-lbl';
            tdT.textContent = v.type;
            tdT.style.cssText = 'opacity:0.6;min-width:80px;';
            const tdV = document.createElement('td'); tdV.className = 'lnk-val';
            tdV.textContent = v.isDeletion ? '(DELETED)' : v.data;
            tdV.style.cssText += v.isSuspicious ? 'color:var(--risk-high);' : '';
            tdV.style.cssText += v.isDeletion ? 'color:var(--risk-high);font-style:italic;' : '';
            tr.appendChild(tdN); tr.appendChild(tdT); tr.appendChild(tdV);
            tbl.appendChild(tr);
          }
          keyDiv.appendChild(tbl);
        }

        wrap.appendChild(keyDiv);
      }
    }

    // Full source with line numbers
    const srcH = document.createElement('div'); srcH.className = 'hta-section-hdr';
    srcH.textContent = 'Full Source';
    wrap.appendChild(srcH);

    const lines = text.split('\n');
    const srcInfo = document.createElement('div'); srcInfo.className = 'plaintext-info';
    srcInfo.textContent = `${lines.length} line${lines.length !== 1 ? 's' : ''}  ·  ${this._fmtBytes(bytes.length)}`;
    wrap.appendChild(srcInfo);

    const scr = document.createElement('div'); scr.className = 'plaintext-scroll';
    const table = document.createElement('table'); table.className = 'plaintext-table';
    const maxLines = RENDER_LIMITS.MAX_TEXT_LINES;
    const count = Math.min(lines.length, maxLines);
    let highlightedLines = null;
    if (typeof hljs !== 'undefined' && text.length <= 200000) {
      try {
        const result = hljs.highlight(text, { language: 'ini', ignoreIllegals: true });
        highlightedLines = result.value.split('\n');
      } catch (_) { /* fallback to plain textContent */ }
    }
    for (let i = 0; i < count; i++) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td'); tdNum.className = 'plaintext-ln'; tdNum.textContent = i + 1;
      const tdCode = document.createElement('td'); tdCode.className = 'plaintext-code';
      if (highlightedLines && highlightedLines[i] !== undefined) {
        tdCode.innerHTML = highlightedLines[i] || '';
      } else {
        tdCode.textContent = lines[i];
      }
      tr.appendChild(tdNum); tr.appendChild(tdCode); table.appendChild(tr);
    }
    scr.appendChild(table); wrap.appendChild(scr);

    // Expose raw text for IOC extraction, YARA match highlighting and click-to-scroll
    wrap._rawText = text;
    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    // Start 'low'; the format banner and parsed warnings drive the final
    // risk via the calibration block at the end. Registry imports are only
    // actually dangerous if they touch dangerous keys — let evidence decide.
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: [], interestingStrings: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = this._decodeText(bytes);

    f.externalRefs.push({
      type: IOC.INFO,
      url: 'Windows Registry File (.reg) — imports registry changes when double-clicked or merged',
      severity: 'high'
    });

    const analysis = this._analyze(text);

    // Report key/value counts
    f.externalRefs.push({
      type: IOC.PATTERN,
      url: `${analysis.keys.length} registry key(s), ${analysis.values.length} value(s), ${analysis.deletions.length} deletion(s)`,
      severity: 'info'
    });

    // Report warnings as findings
    for (const w of analysis.warnings) {
      f.externalRefs.push({ type: IOC.PATTERN, url: w.label, severity: w.sev });
    }

    // Emit FILE_PATH / PROCESS / REGISTRY_KEY IOCs from parsed values.
    // Values in .reg files use doubled backslashes ("C:\\Program Files\\...")
    // which the generic scanner's path regex doesn't match, so we unescape
    // them here and feed the clean form into interestingStrings.
    this._emitRegIocs(f, text, analysis);

    // Evidence-based risk calibration — see cross-renderer-sanity-check audit.
    // Keep the "3+ high warnings → critical" semantics via the rank check.
    const highCount = analysis.warnings.filter(w => w.sev === 'high' || w.sev === 'critical').length;
    const highs = f.externalRefs.filter(r => r.severity === 'high').length;
    const hasCrit = f.externalRefs.some(r => r.severity === 'critical');
    const hasMed = f.externalRefs.some(r => r.severity === 'medium');
    let tier = 'low';
    if (hasCrit || highCount >= 3) tier = 'critical';
    else if (highs >= 2) tier = 'high';
    else if (highs >= 1) tier = 'medium';
    else if (hasMed) tier = 'low';
    escalateRisk(f, tier);

    return f;
  }

  // Emit IOCs parsed from registry values. We already unescape REG_SZ data in
  // _analyze(), so here we just classify each value.
  _emitRegIocs(f, text, analysis) {
    const seen = new Set((f.interestingStrings || []).map(r => r.url));
    const exeRe = /\.(exe|dll|bat|cmd|vbs|js|ps1|hta|scr|com|pif|sys|ocx|cpl)\b/i;
    const drivePathRe = /^[A-Za-z]:[\\/]/;
    const uncPathRe = /^\\\\[\w.\-]+\\/;

    const add = (type, val, sev) => {
      const v = (val || '').trim();
      if (!v || seen.has(v)) return;
      seen.add(v);
      const entry = { type, url: v, severity: sev };
      // Source highlight: locate either the unescaped string or, failing that,
      // the escaped form (doubled backslashes + escaped quotes) in the text.
      let offset = text.indexOf(v);
      let length = v.length;
      if (offset < 0) {
        const escaped = v.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        offset = text.indexOf(escaped);
        if (offset >= 0) length = escaped.length;
      }
      if (offset >= 0) { entry._sourceOffset = offset; entry._sourceLength = length; }
      f.interestingStrings.push(entry);
    };

    // Registry key paths themselves are first-class IOCs
    for (const key of analysis.keys) {
      add(IOC.REGISTRY_KEY, key.path, key.isSuspicious ? 'high' : 'medium');
    }

    // Scan each value's unescaped data for paths and executables
    for (const v of analysis.values) {
      if (v.isDeletion || !v.data) continue;
      // Only scan string-type values (REG_SZ / REG_EXPAND_SZ); hex/dword
      // types aren't meaningful paths without decoding.
      if (v.type !== 'REG_SZ' && v.type !== 'REG_EXPAND_SZ') continue;
      const data = v.data;

      // Full drive-letter path → FILE_PATH + PROCESS if it ends in an exe
      if (drivePathRe.test(data)) {
        // The path may be followed by command-line args; split to the first
        // executable and use that as the canonical file path.
        const m = data.match(/^[A-Za-z]:[\\/][^"*?<>|\r\n]+?\.(?:exe|dll|bat|cmd|vbs|js|ps1|hta|scr|com|pif|sys|ocx|cpl)\b/i);
        if (m) {
          add(IOC.FILE_PATH, m[0], v.isSuspicious ? 'high' : 'medium');
          // Also add bare filename as PROCESS
          const fn = m[0].split(/[\\/]/).pop();
          if (fn) add(IOC.PROCESS, fn, v.isSuspicious ? 'high' : 'medium');
        } else {
          // Directory path
          add(IOC.FILE_PATH, data, v.isSuspicious ? 'high' : 'medium');
        }
      } else if (uncPathRe.test(data)) {
        add(IOC.UNC_PATH, data, 'high');
      } else if (exeRe.test(data)) {
        // Bare executable reference with no drive letter
        const m = data.match(/[\w.\-]+\.(?:exe|dll|bat|cmd|vbs|js|ps1|hta|scr|com|pif|sys|ocx|cpl)\b/i);
        if (m) add(IOC.PROCESS, m[0], v.isSuspicious ? 'high' : 'medium');
      }
    }
  }

  // ── Registry file analysis ──────────────────────────────────────────────

  _analyze(text) {
    const result = { keys: [], values: [], deletions: [], warnings: [] };
    const lines = text.split(/\r?\n/);
    let currentKey = null;
    let continuedLine = '';

    for (let i = 0; i < lines.length; i++) {
      let line = lines[i];

      // Handle line continuations (backslash at end)
      if (continuedLine) {
        line = continuedLine + line.trim();
        continuedLine = '';
      }
      if (line.endsWith('\\')) {
        continuedLine = line.slice(0, -1);
        continue;
      }

      // Skip comments and blank lines
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith(';')) continue;

      // Version header
      if (trimmed.startsWith('Windows Registry Editor') || trimmed === 'REGEDIT4') continue;

      // Registry key line: [HKEY_...]  or  [-HKEY_...] for deletion
      const keyMatch = trimmed.match(/^\[(-?)(HKEY_[^\]]+)\]\s*$/);
      if (keyMatch) {
        const isDeletion = keyMatch[1] === '-';
        const path = keyMatch[2];
        const isSuspicious = this._isSuspiciousKey(path);
        currentKey = { path, isDeletion, isSuspicious };
        result.keys.push(currentKey);
        if (isDeletion) result.deletions.push(path);

        if (isSuspicious) {
          result.warnings.push({
            label: `Suspicious registry key: ${path}`,
            sev: 'high'
          });
        }
        if (isDeletion) {
          result.warnings.push({
            label: `Key deletion: ${path}`,
            sev: this._isSuspiciousKey(path) ? 'high' : 'medium'
          });
        }
        continue;
      }

      // Value line: "name"=type:data  or  @=data (default value)  or  "name"=-  (delete value)
      if (currentKey) {
        const valMatch = trimmed.match(/^(?:"([^"]*)"|([@]))=(.*)$/);
        if (valMatch) {
          const name = valMatch[1] !== undefined ? valMatch[1] : valMatch[2] === '@' ? '' : valMatch[2];
          const rawData = valMatch[3];
          const isDeletion = rawData === '-';

          let type = 'REG_SZ';
          let data = rawData;

          if (!isDeletion) {
            if (rawData.startsWith('"')) {
              type = 'REG_SZ';
              data = rawData.slice(1, rawData.lastIndexOf('"'));
              // Unescape REG_SZ string in a single pass. The previous
              // two-step form `replace(/\\\\/g, '\\').replace(/\\"/g, '"')`
              // triggered CodeQL js/identity-replacement (the first pass
              // looks like '\\' → '\\') and, worse, was wrong for inputs
              // like  \\"  (a literal backslash followed by an escaped
              // quote): step 1 collapsed the first two characters to a
              // single backslash, then step 2 saw `\"` and turned it into
              // `"` — producing the string  \"  instead of the correct
              // \". A single alternation pass handles both escape forms
              // atomically and is immune to that reordering hazard.
              data = data.replace(/\\([\\"])/g, '$1');
            } else if (rawData.startsWith('dword:')) {
              type = 'REG_DWORD';
              data = rawData.slice(6);
            } else if (rawData.startsWith('hex(b):')) {
              type = 'REG_QWORD';
              data = rawData.slice(7);
            } else if (rawData.startsWith('hex(7):')) {
              type = 'REG_MULTI_SZ';
              data = rawData.slice(7);
            } else if (rawData.startsWith('hex(2):')) {
              type = 'REG_EXPAND_SZ';
              data = rawData.slice(7);
            } else if (rawData.startsWith('hex(0):')) {
              type = 'REG_NONE';
              data = rawData.slice(7);
            } else if (rawData.startsWith('hex:')) {
              type = 'REG_BINARY';
              data = rawData.slice(4);
            }
          }

          const isSuspicious = this._isSuspiciousValue(name, data, currentKey.path);

          result.values.push({
            keyPath: currentKey.path,
            name, type, data, isDeletion, isSuspicious
          });

          if (isDeletion) {
            result.deletions.push(`${currentKey.path}\\${name || '(Default)'}`);
          }

          if (isSuspicious) {
            result.warnings.push({
              label: `Suspicious value: "${name || '(Default)'}" = ${data.length > 80 ? data.slice(0, 80) + '…' : data}`,
              sev: 'high'
            });
          }
        }
      }
    }

    // Additional pattern checks
    if (/\\currentversion\\run\b/i.test(text)) {
      result.warnings.push({ label: 'Persistence: Modifies Run/RunOnce autostart registry keys', sev: 'critical' });
    }
    if (/\\services\\/i.test(text)) {
      result.warnings.push({ label: 'Service modification: Targets Windows Services registry keys', sev: 'high' });
    }
    if (/\\image file execution options\\/i.test(text)) {
      result.warnings.push({ label: 'IFEO hijack: Modifies Image File Execution Options (debugger trap)', sev: 'critical' });
    }
    if (/\\policies\\microsoft\\windows defender/i.test(text)) {
      result.warnings.push({ label: 'Security tampering: Targets Windows Defender policy settings', sev: 'critical' });
    }
    if (/\\policies\\microsoft\\windows\\windowsupdate/i.test(text)) {
      result.warnings.push({ label: 'Security tampering: Targets Windows Update policy settings', sev: 'high' });
    }
    if (/disableantispyware|disablerealtimemonitoring|disablebehaviormonitoring/i.test(text)) {
      result.warnings.push({ label: 'Security disable: Attempts to disable antimalware protection', sev: 'critical' });
    }
    if (/\\currentversion\\explorer\\shell folders/i.test(text) || /\\currentversion\\explorer\\user shell folders/i.test(text)) {
      result.warnings.push({ label: 'Shell folder redirect: Modifies special folder paths', sev: 'high' });
    }

    // Deduplicate warnings
    const seen = new Set();
    result.warnings = result.warnings.filter(w => {
      if (seen.has(w.label)) return false;
      seen.add(w.label); return true;
    });

    return result;
  }

  _isSuspiciousKey(path) {
    const lp = path.toLowerCase();
    const patterns = [
      'currentversion\\run', 'currentversion\\runonce', 'currentversion\\runonceex',
      'currentversion\\runservices', 'currentversion\\runservicesonce',
      'currentversion\\explorer\\shell', 'currentversion\\explorer\\shellexecutehooks',
      'currentversion\\policies', 'currentversion\\windows\\load', 'currentversion\\windows\\run',
      'currentversion\\winlogon', 'currentversion\\image file execution options',
      'currentversion\\app paths', 'currentversion\\uninstall',
      '\\services\\', '\\control\\safeboot',
      '\\appinit_dlls', '\\lsa\\', '\\security\\',
      '\\currentversion\\explorer\\browser helper objects',
      '\\classes\\clsid\\', '\\classes\\*\\shell',
      '\\classes\\exefile\\', '\\classes\\.exe\\',
      '\\classes\\htmlfile\\', '\\classes\\http\\',
      '\\environment\\', 'currentversion\\explorer\\startup',
      'microsoft\\windows nt\\currentversion\\windows',
      'microsoft\\windows defender', 'microsoft\\windows\\windowsupdate',
      '\\scheduleagents\\', '\\installedcomponents\\',
      'currentversion\\authentication\\', 'currentversion\\credential',
      '\\system\\currentcontrolset\\control\\session manager',
    ];
    return patterns.some(p => lp.includes(p));
  }

  _isSuspiciousValue(name, data, keyPath) {
    const ld = (data || '').toLowerCase();
    const ln = (name || '').toLowerCase();
    // Known dangerous value names
    const dangerousNames = [
      'debugger', 'appinit_dlls', 'loadappinit_dlls', 'userinit',
      'shell', 'taskbar', 'load', 'run', 'autorun',
      'disableantispyware', 'disablerealtimemonitoring', 'disablebehaviormonitoring',
      'disableonaccessprotection', 'disablescanonrealtimeenable',
      'enablelua', 'consentpromptbehavioradmin', 'promptonsecuredesktop',
      'noautorun', 'nodrivetypeautorun',
    ];
    if (dangerousNames.includes(ln)) return true;

    // Suspicious data patterns
    const suspiciousData = [
      'powershell', 'cmd.exe', 'cmd /c', 'wscript', 'cscript', 'mshta',
      'regsvr32', 'rundll32', 'certutil', 'bitsadmin', 'msiexec',
      'http://', 'https://', 'ftp://', '\\\\',
      'frombase64string', '-enc ', '-encodedcommand',
      'downloadstring', 'downloadfile', 'invoke-expression', 'iex ',
      'new-object system.net',
    ];
    if (suspiciousData.some(p => ld.includes(p))) return true;

    // Large hex binary data could hide embedded payloads
    if (data && data.length > 500 && /^[0-9a-f,\s]+$/.test(data)) return true;

    return false;
  }

  _decodeText(bytes) {
    // .reg files can be UTF-16LE (Version 5.00) or ANSI (REGEDIT4)
    // Check for BOM
    if (bytes.length >= 2 && bytes[0] === 0xFF && bytes[1] === 0xFE) {
      return new TextDecoder('utf-16le', { fatal: false }).decode(bytes);
    }
    // Check for UTF-16LE without BOM (look for null bytes interleaved)
    if (bytes.length >= 4 && bytes[1] === 0x00 && bytes[3] === 0x00) {
      return new TextDecoder('utf-16le', { fatal: false }).decode(bytes);
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
