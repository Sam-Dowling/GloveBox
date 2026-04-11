'use strict';
// ════════════════════════════════════════════════════════════════════════════
// security-analyzer.js — DOCX security analysis (macros, external refs, metadata)
// Depends on: constants.js, vba-utils.js
// ════════════════════════════════════════════════════════════════════════════
class SecurityAnalyzer {
  /**
   * Analyse a parsed DOCX structure and return a findings object.
   * @param {object} parsed  Output of DocxParser.parse()
   * @returns {object}  findings: { hasMacros, autoExec, externalRefs, modules,
   *                               metadata, risk, macroSize, macroHash, rawBin }
   */
  analyze(parsed) {
    const f = {hasMacros:false, autoExec:[], externalRefs:[], modules:[],
               metadata:{}, risk:'low', macroSize:0, macroHash:null, rawBin:null};
    if (parsed.metadata) f.metadata = this._metadata(parsed.metadata);
    if (parsed.macros?.present) {
      f.hasMacros = true;
      f.modules   = parsed.macros.modules || [];
      f.macroSize = parsed.macros.size    || 0;
      f.macroHash = parsed.macros.sha256;
      if (parsed.macros.rawBin) f.rawBin = parsed.macros.rawBin;
      for (const m of f.modules) {
        if (m.source) {
          const p = autoExecPatterns(m.source);
          if (p.length) f.autoExec.push({module: m.name, patterns: p});
        }
      }
    }
    f.externalRefs = this._externalRefs(parsed);
    if (f.hasMacros && f.autoExec.length) f.risk = 'high';
    else if (f.hasMacros || f.externalRefs.length) f.risk = 'medium';
    return f;
  }

  _metadata(doc) {
    const g = (ns, nm) => doc.getElementsByTagNameNS(ns, nm)[0]?.textContent?.trim() || null;
    const DC = 'http://purl.org/dc/elements/1.1/';
    const CP = 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties';
    const DT = 'http://purl.org/dc/terms/';
    return {
      title:          g(DC,'title'),
      subject:        g(DC,'subject'),
      creator:        g(DC,'creator'),
      lastModifiedBy: g(CP,'lastModifiedBy'),
      revision:       g(CP,'revision'),
      created:        g(DT,'created'),
      modified:       g(DT,'modified'),
    };
  }

  _externalRefs(parsed) {
    const refs = [];
    const typeNames = {
      'hyperlink':        'Hyperlink',
      'image':            'External Image',
      'oleObject':        'OLE Object',
      'frame':            'External Frame',
      'subDocument':      'Sub-Document',
      'attachedTemplate': 'Template Injection',
      'externalLinkPath': 'External Link',
    };
    // Scan relationship file for External targets
    if (parsed.rels) {
      for (const rel of parsed.rels.getElementsByTagNameNS(PKG,'Relationship')) {
        const mode   = rel.getAttribute('TargetMode');
        const target = rel.getAttribute('Target');
        const type   = rel.getAttribute('Type') || '';
        if (mode === 'External' && target) {
          const typeName = Object.entries(typeNames).find(([k]) => type.endsWith('/'+k))?.[1] || 'External';
          refs.push({type: typeName, url: target,
            severity: typeName==='Hyperlink'?'info' : typeName==='External Image'?'medium' : 'high'});
        }
      }
    }
    // Also scan w:instrText nodes for HYPERLINK field codes
    if (parsed.document) {
      const seen = new Set(refs.map(r => r.url));
      try {
        for (const instr of Array.from(parsed.document.getElementsByTagNameNS(W,'instrText'))) {
          const text = (instr.textContent || '').trim();
          const m = text.match(/\bHYPERLINK\s+"([^"]+)"/i);
          if (!m) continue;
          const url = m[1].trim();
          if (!url || seen.has(url)) continue;
          seen.add(url);
          const safe = sanitizeUrl(url);
          refs.push({type:'Hyperlink (field code)', url, severity: safe ? 'info' : 'medium'});
        }
      } catch(e) {}
    }
    return refs;
  }

  /** Apply syntax highlighting to decoded VBA source. */
  highlightVBA(src) {
    const esc = src.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    return esc.replace(
      /\b(AutoOpen|Document_Open|Auto_Open|Workbook_Open|Shell|WScript\.Shell|PowerShell|cmd\.exe|URLDownloadToFile|XMLHTTP|WinHttpRequest|RegWrite|RegDelete|Kill|CreateObject|GetObject|CallByName|Environ)\b/gi,
      '<mark class="vba-danger">$&</mark>'
    );
  }
}
