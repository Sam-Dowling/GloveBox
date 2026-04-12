'use strict';
// ════════════════════════════════════════════════════════════════════════════
// inf-renderer.js — Windows Setup Information File (.inf) and
//                    Windows Script Component (.sct) analysis
// Parses INI sections, flags dangerous directives. SCT files get XML analysis
// similar to WSC scriptlets (Squiblydoo attack vector).
// Depends on: constants.js (IOC, escHtml)
// ════════════════════════════════════════════════════════════════════════════
class InfSctRenderer {

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const wrap = document.createElement('div'); wrap.className = 'inf-view';

    if (ext === 'sct') return this._renderSct(wrap, text, bytes, fileName);
    return this._renderInf(wrap, text, bytes, fileName);
  }

  // ── INF rendering ────────────────────────────────────────────────────────

  _renderInf(wrap, text, bytes, fileName) {
    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>⚠ Windows Setup Information File (.inf)</strong> — INF files configure driver and software installation. They can execute arbitrary commands via right-click "Install" and are abused for <code>CMSTP</code> UAC bypass, DLL side-loading, and malware persistence.';
    wrap.appendChild(banner);

    const analysis = this._analyzeInf(text);

    // Summary
    const infoDiv = document.createElement('div'); infoDiv.className = 'plaintext-info';
    infoDiv.textContent = `${analysis.sections.length} section(s)  ·  ${analysis.directives.length} directive(s)  ·  Setup Information File`;
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

    // Sections display
    if (analysis.sections.length) {
      const secH = document.createElement('div'); secH.className = 'hta-section-hdr';
      secH.textContent = `INF Sections (${analysis.sections.length})`;
      wrap.appendChild(secH);

      for (const sec of analysis.sections) {
        const secDiv = document.createElement('div'); secDiv.style.cssText = 'margin:8px 0 2px 0;';

        const secLabel = document.createElement('div');
        secLabel.style.cssText = `padding:4px 8px;font-family:monospace;font-size:13px;font-weight:bold;border-left:3px solid ${sec.isSuspicious ? '#f88' : '#4af'};background:${sec.isSuspicious ? 'rgba(255,136,136,0.08)' : 'rgba(68,170,255,0.05)'};`;
        secLabel.textContent = `[${sec.name}]`;
        secDiv.appendChild(secLabel);

        if (sec.entries.length) {
          const tbl = document.createElement('table'); tbl.className = 'lnk-info-table';
          tbl.style.cssText = 'margin:0 0 0 16px;';
          for (const entry of sec.entries) {
            const tr = document.createElement('tr');
            const tdK = document.createElement('td'); tdK.className = 'lnk-lbl';
            tdK.textContent = entry.key || '';
            tdK.style.cssText += entry.isSuspicious ? 'color:#f88;' : '';
            const tdV = document.createElement('td'); tdV.className = 'lnk-val';
            tdV.textContent = entry.value || entry.line;
            tdV.style.cssText += entry.isSuspicious ? 'color:#f88;' : '';
            tr.appendChild(tdK); tr.appendChild(tdV);
            tbl.appendChild(tr);
          }
          secDiv.appendChild(tbl);
        }
        wrap.appendChild(secDiv);
      }
    }

    // Full source
    this._appendSource(wrap, text, bytes);
    return wrap;
  }

  // ── SCT rendering ────────────────────────────────────────────────────────

  _renderSct(wrap, text, bytes, fileName) {
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>⚠ Windows Script Component (.sct)</strong> — COM scriptlet that executes via <code>regsvr32 /s /n /u /i:file.sct scrobj.dll</code> (Squiblydoo attack). Can run VBScript/JScript with full system access and download remote payloads.';
    wrap.appendChild(banner);

    const analysis = this._analyzeSct(text);

    // Script blocks
    if (analysis.scripts.length) {
      const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
      const w = document.createElement('div'); w.className = 'zip-warning zip-warning-high';
      w.textContent = `⚠ ${analysis.scripts.length} script block(s) found — ${analysis.scripts.map(s => s.language).join(', ')}`;
      warnDiv.appendChild(w);
      wrap.appendChild(warnDiv);

      for (let i = 0; i < analysis.scripts.length; i++) {
        const s = analysis.scripts[i];
        const sec = document.createElement('div'); sec.className = 'wsf-script-block';
        const h = document.createElement('h3');
        h.textContent = `Script ${i + 1}: ${s.language}`;
        h.style.cssText = 'margin:12px 0 4px 0;padding:4px 8px;background:#332;border-left:3px solid #f88;';
        sec.appendChild(h);

        if (s.code) {
          const pre = document.createElement('pre'); pre.className = 'rtf-raw-source';
          pre.style.cssText += 'max-height:300px;overflow:auto;';
          pre.textContent = s.code.length > 50000 ? s.code.slice(0, 50000) + '\n… truncated' : s.code;
          sec.appendChild(pre);
        }
        wrap.appendChild(sec);
      }
    }

    // Warnings
    if (analysis.warnings.length) {
      const pSec = document.createElement('div'); pSec.style.cssText = 'padding:0 8px;';
      const h = document.createElement('h3');
      h.textContent = `${analysis.warnings.length} Suspicious Pattern(s)`;
      h.style.cssText = 'margin:12px 0 4px 0;color:#f88;';
      pSec.appendChild(h);
      for (const p of analysis.warnings) {
        const d = document.createElement('div'); d.className = `zip-warning zip-warning-${p.sev}`;
        d.textContent = p.label; pSec.appendChild(d);
      }
      wrap.appendChild(pSec);
    }

    // Registration info
    if (analysis.registration.length) {
      const rSec = document.createElement('div'); rSec.style.cssText = 'padding:0 8px;';
      const h = document.createElement('h3'); h.textContent = 'COM Registration';
      h.style.cssText = 'margin:12px 0 4px 0;';
      rSec.appendChild(h);
      const tbl = document.createElement('table'); tbl.className = 'lnk-info-table';
      for (const r of analysis.registration) {
        const tr = document.createElement('tr');
        const tdL = document.createElement('td'); tdL.className = 'lnk-lbl'; tdL.textContent = r.type;
        const tdV = document.createElement('td'); tdV.className = 'lnk-val'; tdV.textContent = r.value;
        tr.appendChild(tdL); tr.appendChild(tdV); tbl.appendChild(tr);
      }
      rSec.appendChild(tbl); wrap.appendChild(rSec);
    }

    // Full source
    this._appendSource(wrap, text, bytes);
    return wrap;
  }

  // ── Security analysis ────────────────────────────────────────────────────

  analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'high', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const ext = (fileName || '').split('.').pop().toLowerCase();

    if (ext === 'sct') {
      f.externalRefs.push({
        type: IOC.INFO,
        url: 'Windows Script Component (.sct) — COM scriptlet, Squiblydoo attack vector via regsvr32',
        severity: 'high'
      });
      const analysis = this._analyzeSct(text);
      for (const s of analysis.scripts) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `Script block: ${s.language} — ${s.code ? s.code.length + ' chars' : 'empty'}`,
          severity: 'high'
        });
        if (s.code) f.modules.push({ name: `sct_script_${s.language}`, source: s.code });
      }
      for (const w of analysis.warnings) {
        f.externalRefs.push({ type: IOC.PATTERN, url: w.label, severity: w.sev });
      }
      for (const r of analysis.registration) {
        f.externalRefs.push({ type: IOC.PATTERN, url: `${r.type}: ${r.value}`, severity: 'medium' });
      }
    } else {
      f.externalRefs.push({
        type: IOC.INFO,
        url: 'Windows Setup Information File (.inf) — can execute commands via right-click Install or CMSTP',
        severity: 'high'
      });
      const analysis = this._analyzeInf(text);
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${analysis.sections.length} section(s), ${analysis.directives.length} directive(s)`,
        severity: 'info'
      });
      for (const w of analysis.warnings) {
        f.externalRefs.push({ type: IOC.PATTERN, url: w.label, severity: w.sev });
      }
      const highCount = analysis.warnings.filter(w => w.sev === 'high' || w.sev === 'critical').length;
      if (highCount >= 3) f.risk = 'critical';
    }

    return f;
  }

  // ── INF analysis ─────────────────────────────────────────────────────────

  _analyzeInf(text) {
    const result = { sections: [], directives: [], warnings: [] };
    const lines = text.split(/\r?\n/);
    let currentSection = null;

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith(';')) continue;

      // Section header: [SectionName]
      const secMatch = trimmed.match(/^\[([^\]]+)\]$/);
      if (secMatch) {
        currentSection = { name: secMatch[1], entries: [], isSuspicious: false };
        result.sections.push(currentSection);

        // Check if section name is suspicious
        const ln = secMatch[1].toLowerCase();
        const dangerousSections = [
          'defaultinstall', 'defaultinstall.nt', 'defaultuninstall',
          'runpresetupcommands', 'runpostsetupcommands',
          'registerocxs', 'unregisterocxs',
        ];
        if (dangerousSections.some(s => ln === s || ln.startsWith(s + '.'))) {
          currentSection.isSuspicious = true;
          result.warnings.push({
            label: `Dangerous section: [${secMatch[1]}] — can execute commands during installation`,
            sev: 'high'
          });
        }
        continue;
      }

      if (currentSection) {
        const kvMatch = trimmed.match(/^([^=]+?)\s*=\s*(.*)$/);
        if (kvMatch) {
          const key = kvMatch[1].trim();
          const value = kvMatch[2].trim();
          const isSuspicious = this._isSuspiciousInfDirective(key, value, currentSection.name);

          result.directives.push({ section: currentSection.name, key, value });
          currentSection.entries.push({ key, value, isSuspicious });

          if (isSuspicious) {
            result.warnings.push({
              label: `Suspicious directive: ${key} = ${value.length > 60 ? value.slice(0, 60) + '…' : value}`,
              sev: 'high'
            });
          }
        } else {
          // Bare line (e.g., file list entry or command)
          const isSuspicious = this._isSuspiciousInfLine(trimmed, currentSection.name);
          currentSection.entries.push({ key: '', value: '', line: trimmed, isSuspicious });
          if (isSuspicious) {
            result.warnings.push({
              label: `Suspicious entry in [${currentSection.name}]: ${trimmed.length > 60 ? trimmed.slice(0, 60) + '…' : trimmed}`,
              sev: 'high'
            });
          }
        }
      }
    }

    // Pattern-level checks
    const lt = text.toLowerCase();
    if (/runpresetupcommands/i.test(text)) {
      result.warnings.push({ label: 'Command execution: RunPreSetupCommands section present', sev: 'critical' });
    }
    if (/runpostsetupcommands/i.test(text)) {
      result.warnings.push({ label: 'Command execution: RunPostSetupCommands section present', sev: 'critical' });
    }
    if (/cmstp/i.test(text)) {
      result.warnings.push({ label: 'CMSTP abuse: References CMSTP (UAC bypass technique)', sev: 'critical' });
    }
    if (/scrobj\.dll/i.test(text)) {
      result.warnings.push({ label: 'Scriptlet reference: scrobj.dll (COM scriptlet host)', sev: 'high' });
    }
    if (/rundll32|regsvr32/i.test(text)) {
      result.warnings.push({ label: 'LOLBin reference: rundll32/regsvr32 in INF directives', sev: 'high' });
    }
    if (/powershell|cmd\.exe|wscript|cscript|mshta/i.test(text)) {
      result.warnings.push({ label: 'Script interpreter: References command/script execution tool', sev: 'high' });
    }
    if (/https?:\/\//i.test(text)) {
      result.warnings.push({ label: 'URL reference: INF contains HTTP/HTTPS URL(s)', sev: 'medium' });
    }

    // Deduplicate
    const seen = new Set();
    result.warnings = result.warnings.filter(w => {
      if (seen.has(w.label)) return false;
      seen.add(w.label); return true;
    });

    return result;
  }

  _isSuspiciousInfDirective(key, value, section) {
    const lk = key.toLowerCase();
    const lv = value.toLowerCase();
    const ls = section.toLowerCase();

    // Dangerous directive keys
    const dangerousKeys = [
      'runpresetupcommands', 'runpostsetupcommands', 'registerocxs', 'unregisterocxs',
      'registerdlls', 'unregisterdlls', 'profileitems', 'addreg', 'delreg',
      'taskname', 'servicename',
    ];
    if (dangerousKeys.includes(lk)) return true;

    // Commands in values
    const cmdPatterns = [
      'powershell', 'cmd.exe', 'cmd /c', 'cmd /k', 'wscript', 'cscript',
      'mshta', 'regsvr32', 'rundll32', 'certutil', 'bitsadmin', 'msiexec',
      'cmstp', 'scrobj.dll',
      'http://', 'https://', '\\\\',
    ];
    if (cmdPatterns.some(p => lv.includes(p))) return true;

    // Executable extensions in values
    if (/\.(exe|dll|bat|cmd|vbs|js|ps1|hta|scr|com|pif)\b/i.test(value)) return true;

    return false;
  }

  _isSuspiciousInfLine(line, section) {
    const ll = line.toLowerCase();
    const ls = section.toLowerCase();

    // Commands in command sections
    if ((ls.includes('presetup') || ls.includes('postsetup') || ls.includes('command')) &&
        (ll.includes('cmd') || ll.includes('powershell') || ll.includes('wscript') ||
         ll.includes('cscript') || ll.includes('mshta') || ll.includes('regsvr32') ||
         ll.includes('rundll32') || ll.includes('certutil') || ll.includes('cmstp'))) {
      return true;
    }

    // Executables referenced in file copy sections
    if (/\.(exe|dll|bat|cmd|vbs|js|ps1|hta|scr)\s*$/i.test(line)) return true;

    return false;
  }

  // ── SCT analysis ─────────────────────────────────────────────────────────

  _analyzeSct(text) {
    const result = { scripts: [], warnings: [], registration: [] };

    // Try XML parsing
    try {
      const doc = new DOMParser().parseFromString(text, 'text/xml');
      if (!doc.getElementsByTagName('parsererror').length) {
        // Extract <script> blocks
        const scripts = doc.getElementsByTagName('script');
        for (const s of Array.from(scripts)) {
          result.scripts.push({
            language: s.getAttribute('language') || 'JScript',
            code: s.textContent.trim(),
          });
        }

        // Extract <registration> elements
        const regs = doc.getElementsByTagName('registration');
        for (const r of Array.from(regs)) {
          const progid = r.getAttribute('progid');
          const classid = r.getAttribute('classid');
          const desc = r.getAttribute('description');
          if (progid) result.registration.push({ type: 'ProgID', value: progid });
          if (classid) result.registration.push({ type: 'ClassID', value: classid });
          if (desc) result.registration.push({ type: 'Description', value: desc });
        }

        // Extract <object> elements
        const objs = doc.getElementsByTagName('object');
        for (const o of Array.from(objs)) {
          const progid = o.getAttribute('progid');
          const classid = o.getAttribute('classid');
          const id = o.getAttribute('id');
          if (progid) result.registration.push({ type: 'Object ProgID', value: progid });
          if (classid) result.registration.push({ type: 'Object ClassID', value: classid });
          if (id) result.registration.push({ type: 'Object ID', value: id });
        }
      }
    } catch (e) { }

    // Fallback regex for scripts
    if (result.scripts.length === 0) {
      const rx = /<script[^>]*language\s*=\s*["']?([^"'\s>]+)["']?[^>]*>([\s\S]*?)<\/script>/gi;
      let m;
      while ((m = rx.exec(text)) !== null) {
        result.scripts.push({ language: m[1], code: m[2].trim() });
      }
    }

    // Pattern warnings
    const lt = text.toLowerCase();
    if (/regsvr32/i.test(text)) {
      result.warnings.push({ label: 'Squiblydoo: References regsvr32 (COM registration abuse)', sev: 'critical' });
    }
    if (/scrobj\.dll/i.test(text)) {
      result.warnings.push({ label: 'Scriptlet host: References scrobj.dll', sev: 'high' });
    }
    if (/createobject|getobject/i.test(text)) {
      result.warnings.push({ label: 'COM instantiation: CreateObject/GetObject calls detected', sev: 'high' });
    }
    if (/wscript\.shell|shell\.application/i.test(text)) {
      result.warnings.push({ label: 'Shell access: WScript.Shell or Shell.Application usage', sev: 'high' });
    }
    if (/xmlhttp|msxml2|winhttp/i.test(text)) {
      result.warnings.push({ label: 'Network access: HTTP object instantiation', sev: 'high' });
    }
    if (/adodb\.stream|scripting\.filesystemobject/i.test(text)) {
      result.warnings.push({ label: 'File system access: ADODB.Stream or FileSystemObject', sev: 'high' });
    }
    if (/powershell|cmd\.exe|wscript|cscript|mshta/i.test(text)) {
      result.warnings.push({ label: 'Script interpreter: References command execution tool', sev: 'high' });
    }
    if (/https?:\/\//i.test(text)) {
      result.warnings.push({ label: 'URL reference: SCT contains HTTP/HTTPS URL(s)', sev: 'medium' });
    }
    if (/frombase64string|atob|base64/i.test(text)) {
      result.warnings.push({ label: 'Encoding: Base64 decode operations detected', sev: 'medium' });
    }

    // Deduplicate
    const seen = new Set();
    result.warnings = result.warnings.filter(w => {
      if (seen.has(w.label)) return false;
      seen.add(w.label); return true;
    });

    return result;
  }

  // ── Shared helpers ───────────────────────────────────────────────────────

  _appendSource(wrap, text, bytes) {
    const srcH = document.createElement('div'); srcH.className = 'hta-section-hdr';
    srcH.textContent = 'Full Source';
    wrap.appendChild(srcH);

    const lines = text.split('\n');
    const info = document.createElement('div'); info.className = 'plaintext-info';
    info.textContent = `${lines.length} line${lines.length !== 1 ? 's' : ''}  ·  ${this._fmtBytes(bytes.length)}`;
    wrap.appendChild(info);

    const scr = document.createElement('div'); scr.className = 'plaintext-scroll';
    const table = document.createElement('table'); table.className = 'plaintext-table';
    const maxLines = 50000;
    const count = Math.min(lines.length, maxLines);
    for (let i = 0; i < count; i++) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td'); tdNum.className = 'plaintext-ln'; tdNum.textContent = i + 1;
      const tdCode = document.createElement('td'); tdCode.className = 'plaintext-code'; tdCode.textContent = lines[i];
      tr.appendChild(tdNum); tr.appendChild(tdCode); table.appendChild(tr);
    }
    scr.appendChild(table); wrap.appendChild(scr);
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
