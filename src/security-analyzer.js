'use strict';
// ════════════════════════════════════════════════════════════════════════════
// security-analyzer.js — DOCX security analysis (macros, external refs, metadata)
// Depends on: constants.js, vba-utils.js, yara-engine.js (pattern detection via YARA)
// ════════════════════════════════════════════════════════════════════════════

// ── Shared: deep OOXML relationship scanner ────────────────────────────────
// Walks every _rels/*.rels file in an OOXML package (docx/pptx/xlsx) and
// returns structured findings. Callers flatten the returned array into
// their `externalRefs` list (shape: { type, url, severity, note }).
//
// Relationship-type keywords we classify (case-insensitive endsWith):
//   attachedTemplate  — Follina / APT29 template-injection vector     → high
//   oleObject         — remote OLE embedding                           → high
//   subDocument       — external subdoc load                           → high
//   frame             — external frame                                 → high
//   externalLink      — Excel external-link reference                  → high
//   externalLinkPath  — ditto (path variant)                           → high
//   package           — embedded package (OLE replacement)             → high
//   hyperlink         — user-visible hyperlink                         → info/medium
//   image             — remote image                                   → medium
//   header / footer   — external header/footer refs                    → medium
//   settings          — references to external settings.xml targets    → medium
//   (unknown)         — anything else with TargetMode="External"       → high
//
// Protocol-based escalation even when mode isn't "External":
//   UNC (\\host\share)        → high (NTLM credential theft vector)
//   file://                   → medium
//   mhtml:/ms-*:              → high (handler abuse — ms-word, ms-excel, etc.)
//   webdav / http URL ending in .dot[x|m]? or .dotx (remote template) → high
class OoxmlRelScanner {
  static _SEV_BY_KEY = Object.freeze({
    'attachedtemplate': 'high',
    'oleobject': 'high',
    'subdocument': 'high',
    'frame': 'high',
    'externallink': 'high',
    'externallinkpath': 'high',
    'package': 'high',
    'hyperlink': 'info',
    'image': 'medium',
    'header': 'medium',
    'footer': 'medium',
    'settings': 'medium',
  });

  // Return an array of ref objects: { type, url, severity, note }.
  // `rels` is either:
  //   - array of {path, owner, dom} (preferred — shape from DocxParser._parseAllRels)
  //   - a JSZip instance (we'll scan every *.rels ourselves)
  static async scan(rels) {
    const out = [];
    const entries = Array.isArray(rels) ? rels : await OoxmlRelScanner._fromZip(rels);
    for (const { path, dom } of entries) {
      if (!dom) continue;
      for (const rel of dom.getElementsByTagNameNS(PKG, 'Relationship')) {
        const mode = rel.getAttribute('TargetMode') || '';
        const target = (rel.getAttribute('Target') || '').trim();
        const type = rel.getAttribute('Type') || '';
        if (!target) continue;
        const keyMatch = type.match(/\/([^/]+)$/);
        const key = keyMatch ? keyMatch[1].toLowerCase() : '';
        const baseSev = OoxmlRelScanner._SEV_BY_KEY[key];
        // Classify the target
        const cls = OoxmlRelScanner._classifyTarget(target);
        if (mode === 'External') {
          // Always surface an external rel — severity = max(baseSev, protocolSev)
          const sev = OoxmlRelScanner._max(baseSev ?? 'high', cls.severity);
          out.push({
            type: cls.iocType,
            url: target,
            severity: sev,
            note: OoxmlRelScanner._note(key, cls, path),
          });
        } else if (baseSev === 'high' && /oleobject|attachedtemplate|subdocument|frame|externallink|package/.test(key)) {
          // Structural high-risk rel types should be surfaced even if
          // TargetMode isn't explicitly "External" (some samples omit it).
          if (cls.severity !== 'info') {
            out.push({
              type: cls.iocType,
              url: target,
              severity: 'high',
              note: OoxmlRelScanner._note(key, cls, path),
            });
          }
        } else if (cls.severity === 'high' && cls.iocType === IOC.UNC_PATH) {
          // UNC path inside any rel is credential-theft territory
          out.push({
            type: IOC.UNC_PATH,
            url: target,
            severity: 'high',
            note: `UNC path in ${path}${key ? ' (' + key + ')' : ''}`,
          });
        }
      }
    }
    return out;
  }

  static async _fromZip(zip) {
    const out = [];
    for (const p of Object.keys(zip.files)) {
      if (zip.files[p].dir) continue;
      if (!/(^|\/)_rels\/[^/]+\.rels$/.test(p)) continue;
      try {
        const t = await zip.file(p).async('string');
        const d = new DOMParser().parseFromString(t, 'text/xml');
        if (d.getElementsByTagName('parsererror').length) continue;
        out.push({ path: p, owner: null, dom: d });
      } catch (e) { /* ignore */ }
    }
    return out;
  }

  // Return { iocType, severity, protocol }.
  // severity is the *floor* implied by the target itself (not the rel type).
  static _classifyTarget(target) {
    const t = target.trim();
    // UNC path: \\host\share\... or \\?\UNC\host\share
    if (/^\\\\(?!\?\\)[^\\]+\\/.test(t) || /^\\\\\?\\UNC\\/i.test(t)) {
      return { iocType: IOC.UNC_PATH, severity: 'high', protocol: 'unc' };
    }
    // file:// scheme
    if (/^file:\/\//i.test(t)) {
      return { iocType: IOC.FILE_PATH, severity: 'medium', protocol: 'file' };
    }
    // mhtml: / ms-*: protocol handlers (e.g. ms-word:ofe|u|...)
    if (/^(mhtml|ms-[a-z]+|ms-word|ms-excel|ms-powerpoint):/i.test(t)) {
      return { iocType: IOC.URL, severity: 'high', protocol: 'msproto' };
    }
    // Remote Office template (common in injection attacks)
    if (/^https?:\/\/.+\.(dot[xm]?|dotm|dotx|dot|docx?|docm|xlt[xm]?|pot[xm]?)(\?|#|$)/i.test(t)) {
      return { iocType: IOC.URL, severity: 'high', protocol: 'remote-template' };
    }
    // WebDAV-shaped URL (http/https with trailing path that looks like WebDAV)
    if (/^https?:\/\/[^/]+\/.*(?:webdav|\/dav\/|\.asmx)/i.test(t)) {
      return { iocType: IOC.URL, severity: 'high', protocol: 'webdav' };
    }
    if (/^https?:\/\//i.test(t)) {
      return { iocType: IOC.URL, severity: 'medium', protocol: 'http' };
    }
    if (/^mailto:/i.test(t)) {
      return { iocType: IOC.EMAIL, severity: 'info', protocol: 'mailto' };
    }
    // Relative target (resolved inside the package) — not external
    return { iocType: IOC.URL, severity: 'info', protocol: 'relative' };
  }

  static _note(key, cls, relPath) {
    const bits = [];
    if (key) bits.push(key);
    if (cls.protocol === 'remote-template') bits.push('remote template (template injection)');
    else if (cls.protocol === 'unc') bits.push('UNC — NTLM credential theft vector');
    else if (cls.protocol === 'webdav') bits.push('WebDAV path');
    else if (cls.protocol === 'msproto') bits.push('MS protocol handler');
    else if (cls.protocol === 'file') bits.push('file:// target');
    if (relPath) bits.push('in ' + relPath);
    return bits.join(' · ');
  }

  static _max(a, b) {
    const order = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    return (order[a] || 0) >= (order[b] || 0) ? a : b;
  }
}

// Map of YARA rules whose sidebar display used to be suppressed when an
// equivalent structural IOC.PATTERN finding was already emitted by a
// renderer (PDF, OOXML, SVG). That de-duplication turned out to hide
// genuinely useful YARA context (e.g. a PDF with JavaScript showed the
// structural "/JS or /JavaScript object(s)" pattern but silently dropped
// the matching `PDF_JavaScript_Execution` rule, so the user never saw
// both signals side-by-side).
//
// The map is intentionally kept (rather than removed outright) so that
// the lookup machinery in `app-yara.js → _updateSidebarWithYara()` keeps
// working unchanged; an empty map simply means "suppress nothing", i.e.
// structural + YARA findings now appear together in the sidebar.
//   key   = YARA rule name
//   value = regex (case-insensitive) tested against externalRef.note /
//           externalRef.url; suppress only if any ref matches.
const YARA_SUPPRESS_IF_STRUCTURAL = new Map();



class SecurityAnalyzer {

  /**
   * Analyse a parsed DOCX structure and return a findings object.
   * @param {object} parsed  Output of DocxParser.parse()
   * @returns {object}  findings: { hasMacros, autoExec, externalRefs, modules,
   *                               metadata, risk, macroSize, macroHash, rawBin }
   */
  analyze(parsed) {
    const f = {
      hasMacros: false, autoExec: [], externalRefs: [], modules: [],
      metadata: {}, risk: 'low', macroSize: 0, macroHash: null, rawBin: null,
      signatureMatches: []
    };
    if (parsed.metadata) f.metadata = this._metadata(parsed.metadata);
    if (parsed.macros?.present) {
      f.hasMacros = true;
      f.modules = parsed.macros.modules || [];
      f.macroSize = parsed.macros.size || 0;
      f.macroHash = parsed.macros.sha256;
      if (parsed.macros.rawBin) f.rawBin = parsed.macros.rawBin;
      for (const m of f.modules) {
        if (m.source) {
          const p = autoExecPatterns(m.source);
          if (p.length) f.autoExec.push({ module: m.name, patterns: p });
        }
      }
      // Pattern detection against VBA source is handled by YARA (auto-scan on file load)
    }
    f.externalRefs.push(...this._externalRefs(parsed));

    // ── T3.4: docProps/custom.xml IOC scanning ──────────────────────────
    if (parsed.customProps) {
      try {
        const props = parsed.customProps.getElementsByTagName('property');
        for (const prop of Array.from(props)) {
          const valEl = prop.querySelector('vt\\:lpwstr, lpwstr, vt\\:bstr, bstr');
          const val = valEl ? (valEl.textContent || '').trim() : '';
          if (!val || val.length < 8) continue;
          // URL scan
          const urls = val.match(/https?:\/\/[^\s"'<>]+/gi) || [];
          for (const url of urls) {
            f.externalRefs.push({
              type: IOC.URL, url, severity: 'high',
              note: `Hidden in docProps/custom.xml property "${prop.getAttribute('name') || '?'}"`
            });
            if (f.risk !== 'high') escalateRisk(f, 'high');
          }
          // IP scan
          const ips = val.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
          for (const ip of ips) {
            if (!/^(0\.|127\.|255\.|10\.|192\.168\.)/.test(ip)) {
              f.externalRefs.push({
                type: IOC.IP, url: ip, severity: 'medium',
                note: `In docProps/custom.xml property "${prop.getAttribute('name') || '?'}"`
              });
              if (f.risk === 'low') escalateRisk(f, 'medium');
            }
          }
          // Base64 blob scan
          if (/^[A-Za-z0-9+/=]{100,}$/.test(val)) {
            f.externalRefs.push({
              type: IOC.PATTERN,
              url: `Base64 blob in custom property "${prop.getAttribute('name') || '?'}" (${val.length} chars)`,
              severity: 'high',
              note: 'Possible encoded payload in docProps/custom.xml'
            });
            if (f.risk !== 'high') escalateRisk(f, 'high');
          }
        }
      } catch (_) { /* custom.xml parse failure — non-fatal */ }
    }

    // ── T3.5: Field code walking (w:instrText / w:fldSimple) ────────────
    if (parsed.document) {
      try {
        const dangerousFields = [
          { re: /\bDDEAUTO\b/i, label: 'DDEAUTO', sev: 'critical' },
          { re: /\bDDE\s/i, label: 'DDE', sev: 'critical' },
          { re: /\bINCLUDETEXT\b/i, label: 'INCLUDETEXT', sev: 'high' },
          { re: /\bINCLUDEPICTURE\b/i, label: 'INCLUDEPICTURE', sev: 'high' },
          { re: /\bIMPORT\s/i, label: 'IMPORT', sev: 'medium' },
          { re: /\bQUOTE\s/i, label: 'QUOTE', sev: 'medium' },
          { re: /\bMACROBUTTON\b/i, label: 'MACROBUTTON', sev: 'medium' },
        ];
        const seen = new Set();
        // w:instrText elements
        for (const instr of Array.from(parsed.document.getElementsByTagNameNS(W, 'instrText'))) {
          const text = (instr.textContent || '').trim();
          if (!text) continue;
          for (const df of dangerousFields) {
            if (df.re.test(text) && !seen.has(df.label + ':' + text.slice(0, 80))) {
              seen.add(df.label + ':' + text.slice(0, 80));
              f.externalRefs.push({
                type: IOC.PATTERN,
                url: `Field code: ${df.label} — "${text.slice(0, 120)}"`,
                severity: df.sev
              });
              if (df.sev === 'critical') escalateRisk(f, 'high');
              else if (f.risk === 'low') escalateRisk(f, 'medium');
            }
          }
          // Extract URLs from field instructions
          const urlM = text.match(/https?:\/\/[^\s"']+/gi) || [];
          for (const url of urlM) {
            if (!seen.has('url:' + url)) {
              seen.add('url:' + url);
              f.externalRefs.push({ type: IOC.URL, url, severity: 'high', note: 'URL in field instruction' });
              if (f.risk !== 'high') escalateRisk(f, 'high');
            }
          }
        }
        // w:fldSimple attributes
        for (const fld of Array.from(parsed.document.getElementsByTagNameNS(W, 'fldSimple'))) {
          const instr = (fld.getAttribute('w:instr') || fld.getAttribute('instr') || '').trim();
          if (!instr) continue;
          for (const df of dangerousFields) {
            if (df.re.test(instr) && !seen.has(df.label + ':' + instr.slice(0, 80))) {
              seen.add(df.label + ':' + instr.slice(0, 80));
              f.externalRefs.push({
                type: IOC.PATTERN,
                url: `Field code: ${df.label} — "${instr.slice(0, 120)}"`,
                severity: df.sev
              });
              if (df.sev === 'critical') escalateRisk(f, 'high');
              else if (f.risk === 'low') escalateRisk(f, 'medium');
            }
          }
        }
      } catch (_) { /* field-code walk failure — non-fatal */ }
    }

    if (f.hasMacros && f.autoExec.length) escalateRisk(f, 'high');
    else if (f.hasMacros || f.externalRefs.length) if (f.risk === 'low') escalateRisk(f, 'medium');
    return f;
  }

  _metadata(doc) {
    const g = (ns, nm) => doc.getElementsByTagNameNS(ns, nm)[0]?.textContent?.trim() || null;
    const DC = 'http://purl.org/dc/elements/1.1/';
    const CP = 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties';
    const DT = 'http://purl.org/dc/terms/';
    return {
      title: g(DC, 'title'),
      subject: g(DC, 'subject'),
      creator: g(DC, 'creator'),
      lastModifiedBy: g(CP, 'lastModifiedBy'),
      revision: g(CP, 'revision'),
      created: g(DT, 'created'),
      modified: g(DT, 'modified'),
    };
  }

  _externalRefs(parsed) {
    const refs = [];
    // Deep scan — walk every _rels/*.rels in the package, classifying by
    // relationship type and target protocol. Note: OoxmlRelScanner.scan is
    // async when given a JSZip; here we pass a pre-parsed rels array, so
    // the resolved promise is synchronously available via DOMParser output.
    // We use a sync fallback for single parsed.rels in case allRels is absent.
    const scan = (rels) => {
      // Inline, synchronous clone of OoxmlRelScanner.scan for Array input.
      const out = [];
      for (const { path, dom } of (rels || [])) {
        if (!dom) continue;
        for (const rel of dom.getElementsByTagNameNS(PKG, 'Relationship')) {
          const mode = rel.getAttribute('TargetMode') || '';
          const target = (rel.getAttribute('Target') || '').trim();
          const type = rel.getAttribute('Type') || '';
          if (!target) continue;
          const keyMatch = type.match(/\/([^/]+)$/);
          const key = keyMatch ? keyMatch[1].toLowerCase() : '';
          const baseSev = OoxmlRelScanner._SEV_BY_KEY[key];
          const cls = OoxmlRelScanner._classifyTarget(target);
          if (mode === 'External') {
            const sev = OoxmlRelScanner._max(baseSev ?? 'high', cls.severity);
            out.push({ type: cls.iocType, url: target, severity: sev, note: OoxmlRelScanner._note(key, cls, path) });
          } else if (baseSev === 'high' && /oleobject|attachedtemplate|subdocument|frame|externallink|package/.test(key)) {
            if (cls.severity !== 'info') {
              out.push({ type: cls.iocType, url: target, severity: 'high', note: OoxmlRelScanner._note(key, cls, path) });
            }
          } else if (cls.severity === 'high' && cls.iocType === IOC.UNC_PATH) {
            out.push({ type: IOC.UNC_PATH, url: target, severity: 'high', note: `UNC path in ${path}${key ? ' (' + key + ')' : ''}` });
          }
        }
      }
      return out;
    };
    if (parsed.allRels && parsed.allRels.length) {
      refs.push(...scan(parsed.allRels));
    } else if (parsed.rels) {
      // Fallback: only document.xml.rels available
      refs.push(...scan([{ path: 'word/_rels/document.xml.rels', dom: parsed.rels }]));
    }
    // Also scan w:instrText nodes for HYPERLINK field codes (these appear in
    // document.xml body, not in rels — catches macro-less redirect attacks)
    if (parsed.document) {
      const seen = new Set(refs.map(r => r.url));
      try {
        for (const instr of Array.from(parsed.document.getElementsByTagNameNS(W, 'instrText'))) {
          const text = (instr.textContent || '').trim();
          const m = text.match(/\bHYPERLINK\s+"([^"]+)"/i);
          if (!m) continue;
          const url = m[1].trim();
          if (!url || seen.has(url)) continue;
          seen.add(url);
          const safe = sanitizeUrl(url);
          refs.push({ type: IOC.URL, url, severity: safe ? 'info' : 'medium', note: 'HYPERLINK field code' });
        }
      } catch (e) { }
    }
    // De-duplicate by url — prefer the highest-severity note
    const byUrl = new Map();
    const order = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
    for (const r of refs) {
      const existing = byUrl.get(r.url);
      if (!existing || (order[r.severity] || 0) > (order[existing.severity] || 0)) byUrl.set(r.url, r);
    }
    return Array.from(byUrl.values());
  }


  /** Apply syntax highlighting to decoded VBA source. */
  highlightVBA(src) {
    const esc = src.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return esc.replace(
      /\b(AutoOpen|Document_Open|Auto_Open|Workbook_Open|Shell|WScript\.Shell|PowerShell|cmd\.exe|URLDownloadToFile|XMLHTTP|WinHttpRequest|RegWrite|RegDelete|Kill|CreateObject|GetObject|CallByName|Environ)\b/gi,
      '<mark class="vba-danger">$&</mark>'
    );
  }
}
