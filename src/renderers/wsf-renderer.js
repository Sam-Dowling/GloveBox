'use strict';
// ════════════════════════════════════════════════════════════════════════════
// wsf-renderer.js — Windows Script File (.wsf / .wsh / .wsc) analysis
// WSF is an XML container that can hold multiple scripting languages.
// Depends on: constants.js (IOC, escHtml)
// ════════════════════════════════════════════════════════════════════════════
class WsfRenderer {

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const wrap = document.createElement('div'); wrap.className = 'wsf-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = ext === 'wsf'
      ? '<strong>⚠ Windows Script File (.wsf)</strong> — XML container that can execute VBScript, JScript, and other scripting languages via Windows Script Host.'
      : ext === 'wsc'
        ? '<strong>⚠ Windows Script Component (.wsc)</strong> — COM scriptlet that can execute arbitrary code when registered.'
        : '<strong>⚠ Windows Script Host Settings (.wsh)</strong> — Configuration file for Windows Script Host execution.';
    wrap.appendChild(banner);

    // Parse and analyze
    const analysis = this._analyze(text, ext);

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
        h.textContent = `Script ${i + 1}: ${s.language}${s.src ? ' (external: ' + s.src + ')' : ''}`;
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

    // Dangerous patterns
    if (analysis.patterns.length) {
      const pSec = document.createElement('div'); pSec.style.cssText = 'padding:0 8px;';
      const h = document.createElement('h3');
      h.textContent = `${analysis.patterns.length} Suspicious Pattern(s)`;
      h.style.cssText = 'margin:12px 0 4px 0;color:#f88;';
      pSec.appendChild(h);

      for (const p of analysis.patterns) {
        const d = document.createElement('div'); d.className = `zip-warning zip-warning-${p.sev}`;
        d.textContent = p.label; pSec.appendChild(d);
      }
      wrap.appendChild(pSec);
    }

    // References
    if (analysis.references.length) {
      const rSec = document.createElement('div'); rSec.style.cssText = 'padding:0 8px;';
      const h = document.createElement('h3'); h.textContent = 'References';
      h.style.cssText = 'margin:12px 0 4px 0;';
      rSec.appendChild(h);
      for (const ref of analysis.references) {
        const d = document.createElement('div'); d.style.cssText = 'padding:2px 0;';
        d.textContent = `${ref.type}: ${ref.value}`; rSec.appendChild(d);
      }
      wrap.appendChild(rSec);
    }

    // Raw source
    const info = document.createElement('div'); info.className = 'plaintext-info';
    const lines = text.split('\n');
    info.textContent = `${lines.length} line${lines.length !== 1 ? 's' : ''}  ·  ${this._fmtBytes(bytes.length)}  ·  Windows Script File`;
    wrap.appendChild(info);

    const scr = document.createElement('div'); scr.className = 'plaintext-scroll';
    const table = document.createElement('table'); table.className = 'plaintext-table';
    const maxLines = 10000;
    const count = Math.min(lines.length, maxLines);
    for (let i = 0; i < count; i++) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td'); tdNum.className = 'plaintext-ln'; tdNum.textContent = i + 1;
      const tdCode = document.createElement('td'); tdCode.className = 'plaintext-code'; tdCode.textContent = lines[i];
      tr.appendChild(tdNum); tr.appendChild(tdCode); table.appendChild(tr);
    }
    scr.appendChild(table); wrap.appendChild(scr);

    // Expose raw source text so the sidebar's click-to-highlight logic can
    // locate YARA/IOC matches inside the rendered `.plaintext-table`.
    wrap._rawText = text;

    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    // Start 'low'; the format banner and parsed script blocks below are all
    // severity:'high', so evidence-based calibration at the end will lift this
    // to 'high' whenever real content warrants it.
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const ext = (fileName || '').split('.').pop().toLowerCase();

    f.externalRefs.push({
      type: IOC.PATTERN,
      url: `Windows Script File (.${ext}) — executes via Windows Script Host`,
      severity: 'high'
    });

    const analysis = this._analyze(text, ext);

    // Scripts as findings
    for (const s of analysis.scripts) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `Script block: ${s.language}${s.src ? ' (external: ' + s.src + ')' : ''} — ${s.code ? s.code.length + ' chars' : 'no inline code'}`,
        severity: 'high'
      });
      if (s.code) {
        f.modules.push({ name: `script_${s.language}`, source: s.code });
      }
      if (s.src) {
        f.externalRefs.push({ type: IOC.URL, url: s.src, severity: 'high' });
      }
    }

    // Patterns
    for (const p of analysis.patterns) {
      f.externalRefs.push({ type: IOC.PATTERN, url: p.label, severity: p.sev });
    }

    // References
    for (const ref of analysis.references) {
      if (ref.type === 'URL') f.externalRefs.push({ type: IOC.URL, url: ref.value, severity: 'high' });
      else if (ref.type === 'CLSID') f.externalRefs.push({ type: IOC.PATTERN, url: `CLSID: ${ref.value}`, severity: 'medium' });
      else if (ref.type === 'ProgID') f.externalRefs.push({ type: IOC.PATTERN, url: `ProgID: ${ref.value}`, severity: 'medium' });
    }

    // Pattern detection is handled entirely by YARA (auto-scan on file load)

    // Evidence-based risk calibration — see cross-renderer-sanity-check audit.
    const highs = f.externalRefs.filter(r => r.severity === 'high').length;
    const hasCrit = f.externalRefs.some(r => r.severity === 'critical');
    const hasMed = f.externalRefs.some(r => r.severity === 'medium');
    if (hasCrit) f.risk = 'critical';
    else if (highs >= 2) f.risk = 'high';
    else if (highs >= 1) f.risk = 'medium';
    else if (hasMed) f.risk = 'low';
    return f;
  }

  // ── WSF analysis ──────────────────────────────────────────────────────────

  _analyze(text, ext) {
    const result = { scripts: [], patterns: [], references: [] };

    // Try XML parsing for WSF/WSC
    if (ext === 'wsf' || ext === 'wsc') {
      try {
        const doc = new DOMParser().parseFromString(text, 'text/xml');
        if (!doc.getElementsByTagName('parsererror').length) {
          // Extract <script> blocks
          const scripts = doc.getElementsByTagName('script');
          for (const s of Array.from(scripts)) {
            result.scripts.push({
              language: s.getAttribute('language') || 'JScript',
              src: s.getAttribute('src') || '',
              code: s.textContent.trim(),
            });
          }

          // Extract <reference> elements
          const refs = doc.getElementsByTagName('reference');
          for (const r of Array.from(refs)) {
            const guid = r.getAttribute('guid') || r.getAttribute('object');
            if (guid) result.references.push({ type: 'CLSID', value: guid });
          }

          // Extract <object> elements
          const objs = doc.getElementsByTagName('object');
          for (const o of Array.from(objs)) {
            const progid = o.getAttribute('progid');
            const classid = o.getAttribute('classid');
            if (progid) result.references.push({ type: 'ProgID', value: progid });
            if (classid) result.references.push({ type: 'CLSID', value: classid });
          }
        }
      } catch (e) { }
    }

    // Fallback: regex extraction for script blocks
    if (result.scripts.length === 0) {
      const scriptRx = /<script[^>]*language\s*=\s*["']?([^"'\s>]+)["']?[^>]*>([\s\S]*?)<\/script>/gi;
      let m;
      while ((m = scriptRx.exec(text)) !== null) {
        result.scripts.push({ language: m[1], src: '', code: m[2].trim() });
      }
    }

    // WSH settings file
    if (ext === 'wsh') {
      const lines = text.split(/\r?\n/);
      for (const line of lines) {
        const kv = line.match(/^\s*(\w+)\s*=\s*(.*?)\s*$/);
        if (kv) {
          result.references.push({ type: kv[1], value: kv[2] });
        }
      }
    }

    // Extract URLs from all script code + full text
    const allCode = result.scripts.map(s => s.code).join('\n');
    const fullText = allCode + '\n' + text;

    // Pattern detection is handled entirely by YARA (auto-scan on file load)

    for (const m of fullText.matchAll(/https?:\/\/[^\s"'<>]+/g)) {
      result.references.push({ type: 'URL', value: m[0] });
    }

    return result;
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
