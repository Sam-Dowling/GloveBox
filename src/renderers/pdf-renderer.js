'use strict';
// ════════════════════════════════════════════════════════════════════════════
// pdf-renderer.js — Renders PDF files using pdf.js, with deep security analysis
// Requires pdfjsLib (pdf.js) and pdfjsWorker (pdf.worker.js) globals.
// ════════════════════════════════════════════════════════════════════════════
//
// In addition to page rendering, this extracts:
//   • XFA form bodies (including dynamic XFA) + suspicious XFA patterns
//   • /EmbeddedFile streams (list of name/MIME/size entries)
//   • Actions: /OpenAction, /AA (Additional Actions), /Launch, /URI, /GoToR,
//     /SubmitForm, /ImportData, /GoToE (embedded-go-to)
//   • JavaScript objects (/JS, /JavaScript)
//   • XMP metadata block
//   • Encryption flag (trailer /Encrypt)
//
// Structural findings are surfaced with richer context than YARA; when any of
// those fire, we suppress their matching YARA rules (see YARA_SUPPRESS_IF_
// STRUCTURAL in security-analyzer.js).
// ════════════════════════════════════════════════════════════════════════════
class PdfRenderer {

  /** Render every page of the PDF onto canvases, return a wrapper element. */
  async render(buffer) {
    if (typeof pdfjsLib === 'undefined') throw new Error('PDF.js library not loaded — cannot render PDF');
    const data = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer).slice();
    const pdf = await pdfjsLib.getDocument({ data, disableAutoFetch: true, disableStream: true }).promise;
    const wrap = document.createElement('div');
    wrap.className = 'pdf-view';

    const scale = 1.5;
    for (let i = 1; i <= pdf.numPages; i++) {
      const page = await pdf.getPage(i);
      const vp = page.getViewport({ scale });

      const pageDiv = document.createElement('div');
      pageDiv.className = 'page';
      pageDiv.style.width = Math.ceil(vp.width) + 'px';
      pageDiv.style.height = Math.ceil(vp.height) + 'px';
      pageDiv.style.position = 'relative';

      const canvas = document.createElement('canvas');
      canvas.width = Math.ceil(vp.width);
      canvas.height = Math.ceil(vp.height);
      canvas.style.display = 'block';

      await page.render({ canvasContext: canvas.getContext('2d'), viewport: vp }).promise;
      pageDiv.appendChild(canvas);

      // Hidden text layer so docEl.textContent exposes page text for IOC extraction
      try {
        const tc = await page.getTextContent();
        const spans = tc.items.map(it => it.str).join(' ');
        if (spans.trim()) {
          const tl = document.createElement('div');
          tl.className = 'pdf-text-layer';
          tl.style.cssText = 'position:absolute;left:-9999px;top:0;width:0;height:0;overflow:hidden;';
          tl.textContent = spans;
          pageDiv.appendChild(tl);
        }
      } catch (_) { /* text extraction failed — non-fatal */ }

      wrap.appendChild(pageDiv);
    }
    // Store page count for caller
    wrap.dataset.pageCount = pdf.numPages;
    return wrap;
  }

  /** Analyse PDF buffer for security-relevant artefacts. */
  async analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    // ── Raw-string scan (always runs; survives pdf.js parse failures) ─────
    const raw = this._decodeRaw(buffer);

    // URIs — parenthesised
    const uriSeen = new Set();
    for (const m of raw.matchAll(/\/URI\s*\(((?:\\\)|\\\\|[^)])+)\)/g)) {
      const uri = this._unescapePdfString(m[1]);
      if (uri && !uriSeen.has(uri)) {
        uriSeen.add(uri);
        f.externalRefs.push({ type: IOC.URL, url: uri, severity: 'medium', note: '/URI action' });
        if (f.risk === 'low') f.risk = 'medium';
      }
    }
    // URIs — hex-escaped
    for (const m of raw.matchAll(/\/URI\s*<([0-9A-Fa-f]+)>/g)) {
      try {
        const decoded = m[1].match(/.{2}/g).map(h => String.fromCharCode(parseInt(h, 16))).join('')
          .replace(/\u0000/g, '').trim();
        if (decoded && !uriSeen.has(decoded)) {
          uriSeen.add(decoded);
          f.externalRefs.push({ type: IOC.URL, url: decoded, severity: 'medium', note: '/URI action' });
          if (f.risk === 'low') f.risk = 'medium';
        }
      } catch (_) { /* skip malformed */ }
    }

    // ── /Launch actions (F / Win launch) ───────────────────────────────────
    for (const m of raw.matchAll(/\/Launch\b[^>]{0,400}?\/F\s*\(((?:\\\)|\\\\|[^)])+)\)/g)) {
      const target = this._unescapePdfString(m[1]);
      if (target) {
        f.externalRefs.push({
          type: IOC.COMMAND_LINE, url: target, severity: 'high',
          note: '/Launch action target (executes local file)'
        });
        f.risk = 'high';
      }
    }
    // /Launch with embedded Win dict
    for (const m of raw.matchAll(/\/Win\b[^>]{0,400}?\/F\s*\(((?:\\\)|\\\\|[^)])+)\)/g)) {
      const target = this._unescapePdfString(m[1]);
      if (target) {
        f.externalRefs.push({
          type: IOC.COMMAND_LINE, url: target, severity: 'high',
          note: '/Launch /Win target'
        });
        f.risk = 'high';
      }
    }

    // ── /GoToR (remote file jump) ──────────────────────────────────────────
    for (const m of raw.matchAll(/\/S\s*\/GoToR\b[^>]{0,400}?\/F\s*\(((?:\\\)|\\\\|[^)])+)\)/g)) {
      const target = this._unescapePdfString(m[1]);
      if (target) {
        const isUrl = /^(https?|ftp):\/\//i.test(target);
        f.externalRefs.push({
          type: isUrl ? IOC.URL : IOC.FILE_PATH,
          url: target, severity: 'high',
          note: '/GoToR remote jump'
        });
        f.risk = 'high';
      }
    }

    // ── /GoToE (embedded-file jump) ────────────────────────────────────────
    const goToECount = (raw.match(/\/S\s*\/GoToE\b/g) || []).length;
    if (goToECount) {
      f.externalRefs.push({
        type: IOC.PATTERN, url: `${goToECount} /GoToE action(s)`,
        severity: 'high', note: '/GoToE jumps into an embedded PDF (malware staging)'
      });
      f.risk = 'high';
    }

    // ── /SubmitForm and /ImportData ───────────────────────────────────────
    const submitCount = (raw.match(/\/S\s*\/SubmitForm\b/g) || []).length;
    if (submitCount) {
      f.externalRefs.push({
        type: IOC.PATTERN, url: `${submitCount} /SubmitForm action(s)`,
        severity: 'medium', note: 'Form submission exfil vector'
      });
      if (f.risk === 'low') f.risk = 'medium';
    }
    const importCount = (raw.match(/\/S\s*\/ImportData\b/g) || []).length;
    if (importCount) {
      f.externalRefs.push({
        type: IOC.PATTERN, url: `${importCount} /ImportData action(s)`,
        severity: 'medium', note: 'Imports FDF/XFDF at open'
      });
      if (f.risk === 'low') f.risk = 'medium';
    }

    // ── JavaScript ────────────────────────────────────────────────────────
    const jsCount = (raw.match(/\/(JS|JavaScript)\b/g) || []).length;
    if (jsCount) {
      f.externalRefs.push({
        type: IOC.PATTERN, url: `${jsCount} /JS or /JavaScript object(s)`,
        severity: 'high', note: 'PDF JavaScript — used by exploits and phishing'
      });
      f.risk = 'high';
    }

    // ── /OpenAction / /AA (additional actions) presence ───────────────────
    if (/\/OpenAction\b/.test(raw)) {
      f.externalRefs.push({
        type: IOC.PATTERN, url: '/OpenAction present',
        severity: 'medium', note: 'Action runs automatically on open'
      });
      if (f.risk === 'low') f.risk = 'medium';
    }
    const aaCount = (raw.match(/\/AA\b/g) || []).length;
    if (aaCount) {
      f.externalRefs.push({
        type: IOC.PATTERN, url: `/AA additional-actions (${aaCount})`,
        severity: 'medium', note: 'Trigger on page/field events'
      });
      if (f.risk === 'low') f.risk = 'medium';
    }

    // ── Embedded files (/EmbeddedFile streams) ────────────────────────────
    const ef = this._extractEmbeddedFiles(raw);
    if (ef.length) {
      f.metadata.embeddedFiles = ef.map(e => ({
        name: e.name, mime: e.mime, size: e.size,
      }));
      for (const e of ef) {
        const isDanger = this._isDangerousExt(e.name) ||
          /application\/x-(ms-)?(dos|win)?exec|application\/x-msdownload|application\/octet-stream/i.test(e.mime || '');
        f.externalRefs.push({
          type: IOC.FILE_PATH,
          url: e.name || '(unnamed embedded file)',
          severity: isDanger ? 'high' : 'medium',
          note: `/EmbeddedFile — ${e.mime || 'unknown MIME'}${e.size ? ', ' + this._fmtBytes(e.size) : ''}`
        });
        if (isDanger) f.risk = 'high';
        else if (f.risk === 'low') f.risk = 'medium';
      }
    }

    // ── XFA forms ─────────────────────────────────────────────────────────
    const xfa = this._extractXfa(raw);
    if (xfa.present) {
      const note = `XFA form${xfa.dynamic ? ' (dynamic)' : ''}` +
        (xfa.bodySize ? ` — ${this._fmtBytes(xfa.bodySize)}` : '');
      f.externalRefs.push({
        type: IOC.PATTERN, url: note,
        severity: xfa.dynamic ? 'high' : 'medium',
        note: 'XFA has been used for CVE-2018-4990-style exploitation'
      });
      if (xfa.dynamic) f.risk = 'high';
      else if (f.risk === 'low') f.risk = 'medium';
      f.metadata.xfa = xfa.dynamic ? 'dynamic' : 'static';

      // Extract URLs and suspicious scripts from XFA bodies
      for (const url of xfa.urls) {
        if (!uriSeen.has(url)) {
          uriSeen.add(url);
          f.externalRefs.push({ type: IOC.URL, url, severity: 'medium', note: 'XFA form URL' });
          if (f.risk === 'low') f.risk = 'medium';
        }
      }
      for (const note2 of xfa.scriptHints) {
        f.externalRefs.push({
          type: IOC.PATTERN, url: note2, severity: 'high', note: 'XFA suspicious script'
        });
        f.risk = 'high';
      }
    }

    // ── Encryption ────────────────────────────────────────────────────────
    if (/\/Encrypt\b/.test(raw)) {
      f.metadata.encrypted = true;
      f.externalRefs.push({
        type: IOC.PATTERN, url: 'Encrypted PDF',
        severity: 'medium', note: 'Content may be obfuscated from static scanners'
      });
      if (f.risk === 'low') f.risk = 'medium';
    }

    // ── XMP metadata ──────────────────────────────────────────────────────
    const xmp = this._extractXmp(raw);
    if (xmp) {
      if (xmp.creatorTool) f.metadata.xmpCreatorTool = xmp.creatorTool;
      if (xmp.producer) f.metadata.xmpProducer = xmp.producer;
      if (xmp.createDate) f.metadata.xmpCreateDate = xmp.createDate;
      if (xmp.modifyDate) f.metadata.xmpModifyDate = xmp.modifyDate;
      if (xmp.documentId) f.metadata.xmpDocumentId = xmp.documentId;
      if (xmp.instanceId) f.metadata.xmpInstanceId = xmp.instanceId;
      if (xmp.creator) f.metadata.xmpCreator = xmp.creator;
      if (xmp.title) f.metadata.xmpTitle = xmp.title;
    }

    // ── pdf.js metadata + annotations ──────────────────────────────────────
    try {
      if (typeof pdfjsLib === 'undefined') return f;
      const data = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer).slice();
      const pdf = await pdfjsLib.getDocument({ data, disableAutoFetch: true, disableStream: true }).promise;
      const meta = await pdf.getMetadata();
      if (meta && meta.info) {
        const i = meta.info;
        if (i.Title) f.metadata.title = i.Title;
        if (i.Author) f.metadata.author = i.Author;
        if (i.Creator) f.metadata.creator = i.Creator;
        if (i.Producer) f.metadata.producer = i.Producer;
        if (i.CreationDate) f.metadata.created = i.CreationDate;
        if (i.ModDate) f.metadata.modified = i.ModDate;
        if (i.PDFFormatVersion) f.metadata.pdfVersion = i.PDFFormatVersion;
        if (i.IsXFAPresent) f.metadata.xfaPresent = true;
        if (i.IsAcroFormPresent) f.metadata.acroFormPresent = true;
      }
      f.metadata.pages = pdf.numPages;

      // pdf.js also exposes attachments via getAttachments()
      try {
        const atts = await pdf.getAttachments();
        if (atts) {
          const names = Object.keys(atts);
          if (names.length && !f.metadata.embeddedFiles) {
            f.metadata.embeddedFiles = [];
          }
          for (const name of names) {
            const a = atts[name];
            const existing = f.metadata.embeddedFiles &&
              f.metadata.embeddedFiles.some(e => e.name === (a.filename || name));
            if (!existing) {
              const entry = {
                name: a.filename || name,
                size: a.content ? a.content.length : undefined,
              };
              if (!f.metadata.embeddedFiles) f.metadata.embeddedFiles = [];
              f.metadata.embeddedFiles.push(entry);
              const isDanger = this._isDangerousExt(entry.name);
              f.externalRefs.push({
                type: IOC.FILE_PATH,
                url: entry.name,
                severity: isDanger ? 'high' : 'medium',
                note: `/EmbeddedFile (via pdf.js)${entry.size ? ' — ' + this._fmtBytes(entry.size) : ''}`
              });
              if (isDanger) f.risk = 'high';
              else if (f.risk === 'low') f.risk = 'medium';
            }
          }
        }
      } catch (_) { /* attachments not available */ }

      // Extract URLs from link annotations on every page
      for (let p = 1; p <= pdf.numPages; p++) {
        try {
          const page = await pdf.getPage(p);
          const annots = await page.getAnnotations();
          for (const a of annots) {
            for (const field of ['url', 'unsafeUrl']) {
              const val = a[field];
              if (val && !uriSeen.has(val)) {
                uriSeen.add(val);
                f.externalRefs.push({
                  type: IOC.URL, url: val, severity: 'medium',
                  note: `Annotation /URI (page ${p})`
                });
                if (f.risk === 'low') f.risk = 'medium';
              }
            }
            // Annotation actions (pdf.js exposes .action for Launch/Named etc.)
            if (a.action && typeof a.action === 'string') {
              f.externalRefs.push({
                type: IOC.PATTERN,
                url: `Annotation action: ${a.action} (page ${p})`,
                severity: 'low',
              });
            }
          }
        } catch (_) { /* skip page */ }
      }

      pdf.destroy();
    } catch (_) { /* metadata extraction failed — non-fatal */ }

    return f;
  }

  // ════════════════════════════════════════════════════════════════════════
  // Parsers
  // ════════════════════════════════════════════════════════════════════════

  /** Extract /EmbeddedFile entries from the raw stream. */
  _extractEmbeddedFiles(raw) {
    const out = [];
    // /Filespec → /EF << /F <stream-ref> /UF <stream-ref> >>
    // We walk every /Filespec dictionary and harvest the /F name + UF + Size + Subtype
    const fsRe = /\/Type\s*\/Filespec\b([\s\S]{0,2048}?)(?=endobj|\/Type\s*\/|$)/g;
    let m;
    while ((m = fsRe.exec(raw)) !== null) {
      const body = m[1];
      const name = this._pdfStr(body, /\/UF\s*\(((?:\\\)|\\\\|[^)])+)\)/) ||
                   this._pdfStr(body, /\/F\s*\(((?:\\\)|\\\\|[^)])+)\)/) ||
                   this._pdfHex(body, /\/UF\s*<([0-9A-Fa-f]+)>/) ||
                   this._pdfHex(body, /\/F\s*<([0-9A-Fa-f]+)>/);
      const desc = this._pdfStr(body, /\/Desc\s*\(((?:\\\)|\\\\|[^)])+)\)/);
      // Subtype is the MIME (as Name, maybe hex-encoded). PDF names begin with /.
      const mime = (body.match(/\/Subtype\s*\/([^\s\/\>]+)/) || [])[1] || '';
      // Size sometimes in /Params /Size
      const sizeM = body.match(/\/Size\s+(\d+)/);
      out.push({
        name: name || desc || '(unnamed)',
        mime: mime ? mime.replace(/#20/g, ' ').replace(/#([0-9A-Fa-f]{2})/g,
          (_, h) => String.fromCharCode(parseInt(h, 16))) : '',
        size: sizeM ? parseInt(sizeM[1], 10) : 0,
      });
    }

    // Also catch legacy /Type /EmbeddedFile streams without /Filespec wrappers
    // (their /Subtype indicates MIME; name is harder to recover here)
    const efRe = /\/Type\s*\/EmbeddedFile\b([\s\S]{0,512}?)(?=stream|endobj|\/Type\s*\/|$)/g;
    while ((m = efRe.exec(raw)) !== null) {
      const body = m[1];
      const mime = (body.match(/\/Subtype\s*\/([^\s\/\>]+)/) || [])[1] || '';
      const sizeM = body.match(/\/Length\s+(\d+)/);
      // Only add if we don't already have an equivalent Filespec-based entry
      if (!out.some(o => o.mime === mime && (o.size || 0) === (sizeM ? parseInt(sizeM[1], 10) : 0))) {
        out.push({
          name: '(stream)',
          mime: mime ? mime.replace(/#20/g, ' ') : '',
          size: sizeM ? parseInt(sizeM[1], 10) : 0,
        });
      }
    }

    return out;
  }

  /** Detect and summarise XFA forms. */
  _extractXfa(raw) {
    // /XFA can be a packet array (dynamic) or a single stream ref (static).
    // Fast presence check:
    const xfaRef = raw.match(/\/XFA\s*(\[|<<|\d+\s+\d+\s+R)/);
    if (!xfaRef) return { present: false, dynamic: false, bodySize: 0, urls: [], scriptHints: [] };

    // Dynamic XFA = packet array containing at least the "xdp:xdp" / "config" / "template" pairs
    const dynamic = /\/XFA\s*\[[^\]]{10,}\]/.test(raw) ||
                    /<xdp:xdp[\s>]|<config[\s>]|<template[\s>]|<xfa:datasets[\s>]/i.test(raw);

    // Pull out any XFA XML bodies (inside stream ... endstream blocks).
    // We scan all stream contents for xfa namespaces / tags.
    const urls = [];
    const urlSeen = new Set();
    const scriptHints = [];
    let bodySize = 0;

    // XFA body regex - any embedded XML fragment containing xfa or xdp namespace
    const xfaBodyRe = /<\?xml[\s\S]{0,200}?\?>[\s\S]*?<\/(?:xdp|xfa|template|config|datasets)[^>]*>/gi;
    let m;
    while ((m = xfaBodyRe.exec(raw)) !== null) {
      bodySize += m[0].length;
      // URLs
      for (const u of m[0].matchAll(/\bhttps?:\/\/[^\s"'<>\]]+/g)) {
        if (!urlSeen.has(u[0]) && urls.length < 32) {
          urls.push(u[0]);
          urlSeen.add(u[0]);
        }
      }
      // Suspicious script constructs (XFA scripts are JS-like)
      if (/<script[^>]*>/i.test(m[0])) {
        // count script blocks and collect unique hints
        const scripts = m[0].match(/<script[^>]*>([\s\S]*?)<\/script>/gi) || [];
        const hintPatterns = [
          { pat: /\bapp\.launchURL\b/i,      label: 'XFA: app.launchURL' },
          { pat: /\bxfa\.host\.messageBox\b/i, label: 'XFA: messageBox' },
          { pat: /\beval\s*\(/i,             label: 'XFA: eval()' },
          { pat: /\bfromCharCode\s*\(/i,      label: 'XFA: fromCharCode()' },
          { pat: /\bunescape\s*\(/i,          label: 'XFA: unescape()' },
          { pat: /\butil\.prints?[cf]\b/i,    label: 'XFA: util.print*' },
          { pat: /\bgetField\s*\([^)]*\)\.value/i, label: 'XFA: field read' },
          { pat: /\bdata\s*=\s*"[A-Za-z0-9+/=]{80,}"/i, label: 'XFA: long base64 literal' },
          { pat: /\bActiveXObject\b/i,        label: 'XFA: ActiveXObject' },
          { pat: /\bexec(Dialog|CmdFilter)?\s*\(/i, label: 'XFA: exec*' },
        ];
        const joined = scripts.join('\n');
        for (const { pat, label } of hintPatterns) {
          if (pat.test(joined) && !scriptHints.includes(label)) scriptHints.push(label);
        }
      }
    }

    return { present: true, dynamic, bodySize, urls, scriptHints };
  }

  /** Extract core XMP metadata from an <x:xmpmeta>...</x:xmpmeta> block. */
  _extractXmp(raw) {
    const m = raw.match(/<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/);
    if (!m) return null;
    const xmp = m[0];
    const pick = re => {
      const mm = xmp.match(re);
      if (!mm) return null;
      return mm[1].replace(/\s+/g, ' ').trim();
    };
    return {
      creatorTool: pick(/<xmp:CreatorTool>([\s\S]*?)<\/xmp:CreatorTool>/) ||
                   pick(/xmp:CreatorTool="([^"]+)"/),
      producer:    pick(/<pdf:Producer>([\s\S]*?)<\/pdf:Producer>/) ||
                   pick(/pdf:Producer="([^"]+)"/),
      createDate:  pick(/<xmp:CreateDate>([\s\S]*?)<\/xmp:CreateDate>/) ||
                   pick(/xmp:CreateDate="([^"]+)"/),
      modifyDate:  pick(/<xmp:ModifyDate>([\s\S]*?)<\/xmp:ModifyDate>/) ||
                   pick(/xmp:ModifyDate="([^"]+)"/),
      documentId:  pick(/<xmpMM:DocumentID>([\s\S]*?)<\/xmpMM:DocumentID>/) ||
                   pick(/xmpMM:DocumentID="([^"]+)"/),
      instanceId:  pick(/<xmpMM:InstanceID>([\s\S]*?)<\/xmpMM:InstanceID>/) ||
                   pick(/xmpMM:InstanceID="([^"]+)"/),
      creator:     pick(/<dc:creator>[\s\S]*?<rdf:li[^>]*>([\s\S]*?)<\/rdf:li>/),
      title:       pick(/<dc:title>[\s\S]*?<rdf:li[^>]*>([\s\S]*?)<\/rdf:title>/) ||
                   pick(/<dc:title>[\s\S]*?<rdf:li[^>]*>([\s\S]*?)<\/rdf:li>/),
    };
  }

  // ════════════════════════════════════════════════════════════════════════
  // Utilities
  // ════════════════════════════════════════════════════════════════════════

  _pdfStr(body, re) {
    const m = body.match(re);
    return m ? this._unescapePdfString(m[1]) : null;
  }
  _pdfHex(body, re) {
    const m = body.match(re);
    if (!m) return null;
    try {
      return m[1].match(/.{2}/g).map(h => String.fromCharCode(parseInt(h, 16))).join('')
        .replace(/\u0000/g, '').trim();
    } catch (_) { return null; }
  }

  _unescapePdfString(s) {
    // PDF literal strings use \n \r \t \b \f \( \) \\ and octal \ddd escapes
    return s
      .replace(/\\([nrtbf()\\])/g, (_, c) => ({ n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', '(': '(', ')': ')', '\\': '\\' }[c]))
      .replace(/\\([0-7]{1,3})/g, (_, o) => String.fromCharCode(parseInt(o, 8)))
      .replace(/[\x00-\x08\x0E-\x1F]/g, '');
  }

  _isDangerousExt(name) {
    if (!name) return false;
    const ext = (name.split('.').pop() || '').toLowerCase();
    return ['exe','dll','scr','com','pif','cpl','msi','bat','cmd','ps1',
            'vbs','vbe','js','jse','wsf','wsh','wsc','hta','lnk','inf',
            'reg','sct','chm','jar','iso','img','vhd','vhdx'].includes(ext);
  }

  _fmtBytes(n) {
    if (n == null) return '';
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  /** Decode buffer to a string for regex scanning (latin-1 for raw bytes). */
  _decodeRaw(buffer) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    // Scan in 32 KB chunks to avoid call-stack limits with String.fromCharCode
    const chunks = [];
    const CHUNK = 32 * 1024;
    for (let i = 0; i < bytes.length; i += CHUNK) {
      chunks.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK)));
    }
    return chunks.join('');
  }
}
