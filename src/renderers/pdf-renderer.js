'use strict';
// ════════════════════════════════════════════════════════════════════════════
// pdf-renderer.js — Renders PDF files using pdf.js, with deep security analysis
// Requires pdfjsLib (pdf.js) and pdfjsWorker (pdf.worker.js) globals.
// ════════════════════════════════════════════════════════════════════════════
//
// In addition to page rendering, this extracts:
//   • XFA form bodies (including dynamic XFA) + suspicious XFA patterns
//   • /EmbeddedFile streams — bytes retained for "open inline" + download
//   • Actions: /OpenAction, /AA (Additional Actions), /Launch, /URI, /GoToR,
//     /SubmitForm, /ImportData, /GoToE (embedded-go-to)
//   • JavaScript — /JS and /JavaScript bodies resolved from indirect refs,
//     literal strings, hex strings, and pdf.js document/page JS actions.
//     Decoded scripts are retained on f.metadata.pdfJavaScripts and surfaced
//     in the viewer (Extracted Files banner) plus the sidebar.
//   • XMP metadata block
//   • Encryption flag (trailer /Encrypt)
//
// Structural findings are surfaced with richer context than YARA; when any of
// those fire, we suppress their matching YARA rules (see YARA_SUPPRESS_IF_
// STRUCTURAL in security-analyzer.js).
// ════════════════════════════════════════════════════════════════════════════
class PdfRenderer {

  /**
   * Render every page of the PDF onto canvases, return a wrapper element.
   * When security analysis already ran and produced extracted artefacts
   * (JavaScript, embedded files) on `app.findings`, we prepend a clickable
   * "Extracted Files" banner mirroring the MSG / EML / ZIP UX so users can
   * open attachments inline or download JS scripts directly from the viewer.
   *
   * **PLAN F3 — pdf.worker lifecycle.** pdf.js owns its own dedicated worker
   * (`vendor/pdf.worker.js`, spawned independently of the C1–C4
   * `WorkerManager` channels). Every open `PDFDocumentProxy` is registered
   * on the static `_activeDocs` set so a Back-then-forward navigation can
   * call `PdfRenderer.disposeWorker()` from `App._loadFile` and preempt
   * any in-flight `getPage(i)` / `page.render(...)` / `analyzeForSecurity`
   * promises against the previous file. The page loop is wrapped so the
   * `Worker was destroyed` rejection that pdf.js surfaces post-`destroy()`
   * doesn't bubble to `_loadFile`'s outer "Failed to open file" toast —
   * a partial render is the expected outcome of a deliberate cancellation.
   */
  async render(buffer, fileName, findings) {
    if (typeof pdfjsLib === 'undefined') throw new Error('PDF.js library not loaded — cannot render PDF');
    const data = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer).slice();
    const pdf = await pdfjsLib.getDocument({ data, disableAutoFetch: true, disableStream: true }).promise;
    PdfRenderer._activeDocs.add(pdf);
    const wrap = document.createElement('div');
    wrap.className = 'pdf-view';

    // ── Extracted files / scripts banner ──────────────────────────────────
    // Rendered at the top so users always see extractable artefacts before
    // scrolling through pages. Only appears when something was extracted.
    this._renderExtractedBanner(wrap, findings, fileName);

    const scale = 1.5;
    try {
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
    } catch (err) {
      // PLAN F3: cancellation via `PdfRenderer.disposeWorker()` calls
      // `pdf.destroy()` mid-loop, after which any pending `getPage(...)` /
      // `page.render(...)` promise rejects with a pdf.js "Worker was
      // destroyed" / `AbortException`. Treat both as benign supersession
      // (the *next* file is already loading) and return the partial wrap;
      // genuine parse failures still bubble.
      const msg = (err && (err.message || err.name || String(err))) || '';
      const cancelled = err && (err.name === 'AbortException'
        || /worker\s+was\s+destroyed/i.test(msg)
        || /transport\s+closed/i.test(msg));
      if (!cancelled) throw err;
      wrap.dataset.pageCount = String(wrap.querySelectorAll('.page').length);
      wrap.dataset.cancelled = '1';
    }
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
    const rawBytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    // URIs — parenthesised
    const uriSeen = new Set();
    for (const m of raw.matchAll(/\/URI\s*\(((?:\\[\s\S]|[^\\)])*)\)/g)) {
      const uri = this._unescapePdfString(m[1]);
      if (uri && !uriSeen.has(uri)) {
        uriSeen.add(uri);
        f.externalRefs.push({ type: IOC.URL, url: uri, severity: 'medium', note: '/URI action' });
        if (f.risk === 'low') escalateRisk(f, 'medium');
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
          if (f.risk === 'low') escalateRisk(f, 'medium');
        }
      } catch (_) { /* skip malformed */ }
    }

    // ── /Launch actions (F / Win launch) ───────────────────────────────────
    for (const m of raw.matchAll(/\/Launch\b[^>]{0,400}?\/F\s*\(((?:\\[\s\S]|[^\\)])*)\)/g)) {
      const target = this._unescapePdfString(m[1]);
      if (target) {
        f.externalRefs.push({
          type: IOC.COMMAND_LINE, url: target, severity: 'high',
          note: '/Launch action target (executes local file)'
        });
        escalateRisk(f, 'high');
      }
    }
    // /Launch with embedded Win dict
    for (const m of raw.matchAll(/\/Win\b[^>]{0,400}?\/F\s*\(((?:\\[\s\S]|[^\\)])*)\)/g)) {
      const target = this._unescapePdfString(m[1]);
      if (target) {
        f.externalRefs.push({
          type: IOC.COMMAND_LINE, url: target, severity: 'high',
          note: '/Launch /Win target'
        });
        escalateRisk(f, 'high');
      }
    }

    // ── /GoToR (remote file jump) ──────────────────────────────────────────
    for (const m of raw.matchAll(/\/S\s*\/GoToR\b[^>]{0,400}?\/F\s*\(((?:\\[\s\S]|[^\\)])*)\)/g)) {
      const target = this._unescapePdfString(m[1]);
      if (target) {
        const isUrl = /^(https?|ftp):\/\//i.test(target);
        f.externalRefs.push({
          type: isUrl ? IOC.URL : IOC.FILE_PATH,
          url: target, severity: 'high',
          note: '/GoToR remote jump'
        });
        escalateRisk(f, 'high');
      }
    }

    // ── /GoToE (embedded-file jump) ────────────────────────────────────────
    const goToECount = (raw.match(/\/S\s*\/GoToE\b/g) || []).length;
    if (goToECount) {
      f.externalRefs.push({
        type: IOC.PATTERN, url: `${goToECount} /GoToE action(s)`,
        severity: 'high', note: '/GoToE jumps into an embedded PDF (malware staging)'
      });
      escalateRisk(f, 'high');
    }

    // ── /SubmitForm and /ImportData ───────────────────────────────────────
    const submitCount = (raw.match(/\/S\s*\/SubmitForm\b/g) || []).length;
    if (submitCount) {
      f.externalRefs.push({
        type: IOC.PATTERN, url: `${submitCount} /SubmitForm action(s)`,
        severity: 'medium', note: 'Form submission exfil vector'
      });
      if (f.risk === 'low') escalateRisk(f, 'medium');
    }
    const importCount = (raw.match(/\/S\s*\/ImportData\b/g) || []).length;
    if (importCount) {
      f.externalRefs.push({
        type: IOC.PATTERN, url: `${importCount} /ImportData action(s)`,
        severity: 'medium', note: 'Imports FDF/XFDF at open'
      });
      if (f.risk === 'low') escalateRisk(f, 'medium');
    }

    // ── JavaScript: count distinctly, then extract bodies ─────────────────
    //
    // Counting: a JS action dictionary looks like `<< /S /JavaScript /JS …>>`.
    // A bare `/JavaScript` name-tree entry in the Names dictionary refers to
    // a JS action by name. We count them separately instead of OR-matching
    // `/(JS|JavaScript)` — that double-counted every action (one hit for
    // `/JavaScript`, one for `/JS`).
    const jsActionCount = (raw.match(/\/S\s*\/JavaScript\b/g) || []).length;
    const jsNameCount = (raw.match(/\/JavaScript\b/g) || []).length - jsActionCount;
    const jsCount = jsActionCount + Math.max(0, jsNameCount);
    if (jsCount) {
      f.externalRefs.push({
        type: IOC.PATTERN, url: `${jsCount} /JS or /JavaScript object(s)`,
        severity: 'high', note: 'PDF JavaScript — used by exploits and phishing'
      });
      escalateRisk(f, 'high');
    }

    // ── /OpenAction / /AA (additional actions) presence ───────────────────
    if (/\/OpenAction\b/.test(raw)) {
      f.externalRefs.push({
        type: IOC.PATTERN, url: '/OpenAction present',
        severity: 'medium', note: 'Action runs automatically on open'
      });
      if (f.risk === 'low') escalateRisk(f, 'medium');
    }
    const aaCount = (raw.match(/\/AA\b/g) || []).length;
    if (aaCount) {
      f.externalRefs.push({
        type: IOC.PATTERN, url: `/AA additional-actions (${aaCount})`,
        severity: 'medium', note: 'Trigger on page/field events'
      });
      if (f.risk === 'low') escalateRisk(f, 'medium');
    }

    // ── Embedded files (/EmbeddedFile streams, names only at this stage) ──
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
        if (isDanger) escalateRisk(f, 'high');
        else if (f.risk === 'low') escalateRisk(f, 'medium');
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
      if (xfa.dynamic) escalateRisk(f, 'high');
      else if (f.risk === 'low') escalateRisk(f, 'medium');
      f.metadata.xfa = xfa.dynamic ? 'dynamic' : 'static';
      // Retain XFA XML bodies for downstream extraction/download
      if (xfa.packets && xfa.packets.length) f.metadata.xfaPackets = xfa.packets;

      // Extract URLs and suspicious scripts from XFA bodies
      for (const url of xfa.urls) {
        if (!uriSeen.has(url)) {
          uriSeen.add(url);
          f.externalRefs.push({ type: IOC.URL, url, severity: 'medium', note: 'XFA form URL' });
          if (f.risk === 'low') escalateRisk(f, 'medium');
        }
      }
      for (const note2 of xfa.scriptHints) {
        f.externalRefs.push({
          type: IOC.PATTERN, url: note2, severity: 'high', note: 'XFA suspicious script'
        });
        escalateRisk(f, 'high');
      }
    }

    // ── Encryption ────────────────────────────────────────────────────────
    if (/\/Encrypt\b/.test(raw)) {
      f.metadata.encrypted = true;
      f.externalRefs.push({
        type: IOC.PATTERN, url: 'Encrypted PDF',
        severity: 'medium', note: 'Content may be obfuscated from static scanners'
      });
      if (f.risk === 'low') escalateRisk(f, 'medium');
    }

    // ── T2.12: JBIG2 / CCITTFax filter chain flagging ──────────────────
    const jbig2Count = (raw.match(/\/JBIG2Decode\b/g) || []).length;
    if (jbig2Count) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${jbig2Count} /JBIG2Decode filter(s) — historically associated with exploit chains (FORCEDENTRY class)`,
        severity: 'medium',
        note: 'CVE-2021-30860 and related pdfium vulnerabilities use JBIG2'
      });
      if (f.risk === 'low') escalateRisk(f, 'medium');
    }
    const ccittCount = (raw.match(/\/CCITTFaxDecode\b/g) || []).length;
    if (ccittCount) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${ccittCount} /CCITTFaxDecode filter(s) — historically associated with exploit chains`,
        severity: 'medium',
        note: 'CCITTFax combined with other filters has been used in PDF exploits'
      });
      if (f.risk === 'low') escalateRisk(f, 'medium');
    }

    // ── T3.10: Object stream density abuse ──────────────────────────────
    const objStmCount = (raw.match(/\/ObjStm\b/g) || []).length;
    if (objStmCount > 10) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `High object-stream density (${objStmCount} /ObjStm entries) — potential anti-analysis obfuscation`,
        severity: 'medium',
        note: 'Object streams compress multiple objects into single streams, making static analysis harder'
      });
      if (f.risk === 'low') escalateRisk(f, 'medium');
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

    // ── Extract JavaScript bodies (raw-scan, works even if pdf.js fails) ──
    const rawScripts = await this._extractJsFromRaw(raw, rawBytes);

    // ── pdf.js metadata + annotations + JS actions + attachment bytes ─────
    try {
      if (typeof pdfjsLib === 'undefined') {
        // pdf.js absent — still surface raw-scan results
        this._attachJavaScripts(f, rawScripts);
        return f;
      }
      const data = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer).slice();
      const pdf = await pdfjsLib.getDocument({ data, disableAutoFetch: true, disableStream: true }).promise;
      // PLAN F3: register the analyser doc so a Back-then-forward navigation
      // can preempt a long-running deep scan via `PdfRenderer.disposeWorker()`.
      // Removed from the set on the normal `pdf.destroy()` path below; the
      // outer catch handles the cancellation case.
      PdfRenderer._activeDocs.add(pdf);
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

      // ─── Document permissions (encrypted PDFs only) ──────────────────
      // pdf.js returns an array of PermissionFlag enum values or null when
      // the PDF has no owner-password restrictions. Restrictions on PRINT
      // + COPY + MODIFY_CONTENTS are characteristic of DRM-ish samples but
      // also of some phishing PDFs that want to block analyst triage.
      try {
        const perms = await pdf.getPermissions();
        if (Array.isArray(perms) && perms.length) {
          // PermissionFlag values from the PDF 1.7 spec (pdf.js mirrors them):
          //   PRINT=4, MODIFY_CONTENTS=8, COPY=16, MODIFY_ANNOTATIONS=32,
          //   FILL_INTERACTIVE_FORMS=256, COPY_FOR_ACCESSIBILITY=512,
          //   ASSEMBLE=1024, PRINT_HIGH_QUALITY=2048.
          const PERM_NAMES = {
            4: 'print', 8: 'modify', 16: 'copy', 32: 'annotate',
            256: 'fillForms', 512: 'copyForAccessibility',
            1024: 'assemble', 2048: 'printHighQuality',
          };
          const allowed = perms.map(p => PERM_NAMES[p] || `flag${p}`);
          // Spec defines "allowed" flags; the set of *denied* capabilities
          // is what analysts care about (what is the author trying to
          // prevent the viewer from doing?).
          const ALL = ['print', 'modify', 'copy', 'annotate', 'fillForms', 'assemble'];
          const denied = ALL.filter(x => !allowed.includes(x));
          f.metadata.permissionsAllowed = allowed;
          if (denied.length) {
            f.metadata.permissionsDenied = denied;
            pushIOC(f, {
              type: IOC.PATTERN,
              value: `PDF restricts: ${denied.join(', ')}`,
              severity: 'info',
              note: 'owner-password-protected document',
              bucket: 'externalRefs',
            });
          }
        }
      } catch (_) { /* unencrypted — nothing to surface */ }

      // ─── /OpenAction — what fires when the document is opened ────────
      // pdf.js rolls the OpenAction script into getJSActions() already, but
      // a /Launch, /GoToR, or /URI OpenAction (non-JS) is only visible via
      // getOpenAction(). Surface the action type regardless; a bare JS
      // open-action is already covered below.
      try {
        const oa = await pdf.getOpenAction();
        if (oa) {
          // The pdf.js shape is `{ action: string, dest: any } | { url, newWindow }`.
          if (oa.url) {
            pushIOC(f, {
              type: IOC.URL,
              value: String(oa.url),
              severity: 'high',
              note: '/OpenAction auto-navigates on document open',
              bucket: 'externalRefs',
            });
            escalateRisk(f, 'high');
          } else if (oa.action && typeof oa.action === 'string' && oa.action !== 'JavaScript') {
            pushIOC(f, {
              type: IOC.PATTERN,
              value: `/OpenAction: ${oa.action}`,
              severity: 'medium',
              note: 'non-JavaScript action fires on document open',
              bucket: 'externalRefs',
            });
            if (f.risk === 'low') escalateRisk(f, 'medium');
          }
        }
      } catch (_) { /* no /OpenAction */ }

      // Document-level JS actions: { OpenAction: ['...'], Foo: ['...'] }
      const pdfJsScripts = [];
      try {
        const docJs = await pdf.getJSActions();

        if (docJs) {
          for (const [trigger, scripts] of Object.entries(docJs)) {
            for (const src of (scripts || [])) {
              if (src && typeof src === 'string') {
                pdfJsScripts.push({ trigger: `Document: ${trigger}`, source: src });
              }
            }
          }
        }
      } catch (_) { /* no document-level JS */ }

      // pdf.js exposes attachments via getAttachments() — keep the bytes.
      try {
        const atts = await pdf.getAttachments();
        if (atts) {
          const names = Object.keys(atts);
          if (names.length && !f.metadata.embeddedFiles) {
            f.metadata.embeddedFiles = [];
          }
          for (const name of names) {
            const a = atts[name];
            const filename = a.filename || name;
            let entry = f.metadata.embeddedFiles &&
              f.metadata.embeddedFiles.find(e => e.name === filename);
            if (!entry) {
              entry = {
                name: filename,
                size: a.content ? a.content.length : undefined,
              };
              if (!f.metadata.embeddedFiles) f.metadata.embeddedFiles = [];
              f.metadata.embeddedFiles.push(entry);
            }
            // Keep the raw bytes so the sidebar / viewer can offer "Download"
            // and "Load for analysis" (recursive open) actions.
            if (a.content && !entry.data) {
              entry.data = a.content;
              if (!entry.size) entry.size = a.content.length;
            }
            // Only add a fresh externalRef when this file is newly discovered
            // here (raw-scan can miss binary-only /Filespecs).
            const alreadyFlagged = f.externalRefs.some(r =>
              r.type === IOC.FILE_PATH && r.url === filename);
            if (!alreadyFlagged) {
              const isDanger = this._isDangerousExt(filename);
              f.externalRefs.push({
                type: IOC.FILE_PATH,
                url: filename,
                severity: isDanger ? 'high' : 'medium',
                note: `/EmbeddedFile (via pdf.js)${entry.size ? ' — ' + this._fmtBytes(entry.size) : ''}`
              });
              if (isDanger) escalateRisk(f, 'high');
              else if (f.risk === 'low') escalateRisk(f, 'medium');
            }
          }
        }
      } catch (_) { /* attachments not available */ }

      // Extract URLs from link annotations + per-page JS actions.
      // Also rasterize each page (up to QR_PAGE_CAP) and scan for QR codes —
      // "quishing" hides the real phishing URL inside a rendered QR that
      // never touches the text layer or any /URI string, so a per-page
      // raster scan is the only reliable way to surface it.
      const QR_PAGE_CAP = 20;
      let qrPagesScanned = 0;
      for (let p = 1; p <= pdf.numPages; p++) {
        try {
          const page = await pdf.getPage(p);

          // ─── QR decode on page raster ───────────────────────────────
          // Rasterize at 1.5× scale to roughly match the viewer's
          // canvas size. Capped so a 300-page PDF doesn't turn analysis
          // into a render loop.
          if (typeof QrDecoder !== 'undefined' && qrPagesScanned < QR_PAGE_CAP) {
            try {
              const qrVp = page.getViewport({ scale: 1.5 });
              const qrCanvas = document.createElement('canvas');
              qrCanvas.width = Math.ceil(qrVp.width);
              qrCanvas.height = Math.ceil(qrVp.height);
              const qrCtx = qrCanvas.getContext('2d');
              await page.render({ canvasContext: qrCtx, viewport: qrVp }).promise;
              const imgData = qrCtx.getImageData(0, 0, qrCanvas.width, qrCanvas.height);
              const qr = QrDecoder.decodeRGBA(imgData.data, qrCanvas.width, qrCanvas.height);
              if (qr) QrDecoder.applyToFindings(f, qr, `pdf-page-${p}`);
              qrPagesScanned++;
            } catch (_) { /* QR raster/decode is best-effort */ }
          }

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
                if (f.risk === 'low') escalateRisk(f, 'medium');
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
            // ─── Dangerous annotation subtypes ──────────────────────────
            // pdf.js exposes `.subtype` on every annotation; the PDF spec
            // defines a handful of subtypes that imply content execution
            // or form submission on interaction. We surface each with a
            // severity that reflects the worst-case abuse:
            //   • Screen / Movie / Sound / RichMedia / 3D — load inline
            //     media, historically an exploit surface in Reader plugins
            //   • FileAttachment — clicking opens an embedded file (the
            //     bytes are already covered by getAttachments() above, but
            //     the annotation placement tells you *where* it's
            //     triggered from the document)
            if (a.subtype && typeof a.subtype === 'string') {
              const sub = a.subtype;
              const MEDIUM = new Set(['Movie', 'Sound', 'Screen', 'FileAttachment']);
              const HIGH   = new Set(['RichMedia', '3D']);
              if (HIGH.has(sub)) {
                pushIOC(f, {
                  type: IOC.PATTERN,
                  value: `Annotation /${sub} on page ${p}`,
                  severity: 'high',
                  note: 'inline rich-media annotation (historical exploit surface)',
                  bucket: 'externalRefs',
                });
                escalateRisk(f, 'high');
              } else if (MEDIUM.has(sub)) {
                pushIOC(f, {
                  type: IOC.PATTERN,
                  value: `Annotation /${sub} on page ${p}`,
                  severity: 'medium',
                  note: sub === 'FileAttachment' ? 'clickable embedded file' : 'inline media annotation',
                  bucket: 'externalRefs',
                });
                if (f.risk === 'low') escalateRisk(f, 'medium');
              }
            }
            // ─── AcroForm field fingerprints ────────────────────────────
            // Form fields don't automatically fire JS, but fields whose
            // name matches common credential-phish templates (password,
            // ssn, creditcard, pin, …) are an informational pivot that
            // complements the body-text phishing signal.
            if (a.fieldName && typeof a.fieldName === 'string') {
              const fn = a.fieldName.trim();
              if (fn && /\b(password|passwd|pwd|pin|ssn|social.?security|credit.?card|ccnum|cvv|cvc|account.?number|routing|mfa|otp|2fa)\b/i.test(fn)) {
                pushIOC(f, {
                  type: IOC.PATTERN,
                  value: `AcroForm credential-style field: "${fn}"`,
                  severity: 'medium',
                  note: `field on page ${p}`,
                  bucket: 'externalRefs',
                });
                if (f.risk === 'low') escalateRisk(f, 'medium');
              }
            }

          }
          // Per-page JavaScript actions ({ O: [...], C: [...] } etc.)
          try {
            const pageJs = await page.getJSActions();
            if (pageJs) {
              for (const [trigger, scripts] of Object.entries(pageJs)) {
                for (const src of (scripts || [])) {
                  if (src && typeof src === 'string') {
                    pdfJsScripts.push({ trigger: `Page ${p}: ${trigger}`, source: src });
                  }
                }
              }
            }
          } catch (_) { /* no per-page JS */ }
        } catch (_) { /* skip page */ }
      }

      PdfRenderer._activeDocs.delete(pdf);
      pdf.destroy();

      // Merge pdf.js-derived scripts with raw-scan scripts (dedup by hash)
      this._attachJavaScripts(f, [...pdfJsScripts, ...rawScripts]);
      this._mirrorPdfMetadataIOCs(f);
      return f;
    } catch (_) {
      // pdf.js failed (malformed / malicious) — rely on raw-scan alone.
      // (Includes the PLAN F3 cancellation case, where `disposeWorker()`
      // tore the doc down mid-scan; the catch leaves us with whatever
      // raw-scan results were already gathered before the doc opened.)
      this._attachJavaScripts(f, rawScripts);
      this._mirrorPdfMetadataIOCs(f);
      return f;
    }
  }


  // ── Mirror classic-pivot PDF metadata into the IOC table ──────────────
  // PDF Info-dict + XMP carry a handful of fields that are real IR pivots:
  //   • xmpDocumentId / xmpInstanceId — GUIDs burned into the file by the
  //     authoring tool; pivots across every save of the same document
  //   • author / xmpCreator — user / organisation name (classic provenance
  //     pivot; still flagged 'info' severity by pushIOC)
  // Attribution fluff (title, creator tool, producer, dates) intentionally
  // stays metadata-only per the "Option B" classic-pivot policy.
  _mirrorPdfMetadataIOCs(f) {
    mirrorMetadataIOCs(f, {
      'xmpDocumentId': IOC.GUID,
      'xmpInstanceId': IOC.GUID,
      'author':        IOC.USERNAME,
      'xmpCreator':    IOC.USERNAME,
    });
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
      const name = this._pdfStr(body, /\/UF\s*\(((?:\\[\s\S]|[^\\)])*)\)/) ||
                   this._pdfStr(body, /\/F\s*\(((?:\\[\s\S]|[^\\)])*)\)/) ||
                   this._pdfHex(body, /\/UF\s*<([0-9A-Fa-f]+)>/) ||
                   this._pdfHex(body, /\/F\s*<([0-9A-Fa-f]+)>/);
      const desc = this._pdfStr(body, /\/Desc\s*\(((?:\\[\s\S]|[^\\)])*)\)/);
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

  /**
   * Extract JavaScript bodies via raw-buffer scanning. Handles all three
   * carriers found in real-world samples:
   *   1. `/JS ( … )`           — literal string (PDF string-escape rules apply)
   *   2. `/JS < HEX …HEX >`    — hex-string
   *   3. `/JS N 0 R`           — indirect reference → resolve object, extract
   *                              stream (applying /Filter /FlateDecode via
   *                              the shared Decompressor) or inline content.
   * Returns [{ trigger, source }].
   */
  async _extractJsFromRaw(raw, rawBytes) {
    const out = [];

    // 1. Literal strings ---------------------------------------------------
    // We greedily match up to a closing paren with PDF escape handling.
    for (const m of raw.matchAll(/\/JS\s*\(((?:\\[\s\S]|[^\\)])*)\)/g)) {
      const src = this._unescapePdfString(m[1]);
      if (src && src.trim()) out.push({ trigger: '/JS literal string', source: src });
    }

    // 2. Hex strings -------------------------------------------------------
    for (const m of raw.matchAll(/\/JS\s*<([0-9A-Fa-f\s]+)>/g)) {
      try {
        const hex = m[1].replace(/\s+/g, '');
        if (hex.length >= 2) {
          const bytes = hex.match(/.{2}/g).map(h => parseInt(h, 16));
          const src = String.fromCharCode(...bytes).replace(/\u0000+$/, '').trim();
          if (src) out.push({ trigger: '/JS hex string', source: src });
        }
      } catch (_) { /* skip malformed */ }
    }

    // 3. Indirect references ----------------------------------------------
    // Collect every `/JS N 0 R` then resolve each.
    const refs = [];
    for (const m of raw.matchAll(/\/JS\s+(\d+)\s+(\d+)\s+R\b/g)) {
      refs.push({ id: parseInt(m[1], 10), gen: parseInt(m[2], 10) });
    }
    for (const { id, gen } of refs) {
      const src = await this._resolveIndirectScript(raw, rawBytes, id, gen);
      if (src) out.push({ trigger: `/JS ${id} ${gen} R`, source: src });
    }

    return out;
  }

  /**
   * Resolve a `/JS N 0 R` reference by locating the `N 0 obj … endobj` body
   * in the raw buffer. If the object contains a stream, decompress it
   * (respecting /Filter /FlateDecode). Otherwise return any embedded string.
   */
  async _resolveIndirectScript(raw, rawBytes, id, gen) {
    // Locate the object header. PDF allows flexible whitespace.
    const hdrRe = new RegExp(`\\b${id}\\s+${gen}\\s+obj\\b`, 'g');
    const hdr = hdrRe.exec(raw);
    if (!hdr) return null;
    const bodyStart = hdr.index + hdr[0].length;
    const endIdx = raw.indexOf('endobj', bodyStart);
    if (endIdx < 0) return null;
    const body = raw.slice(bodyStart, endIdx);

    // Case A: stream object. Extract the byte range between
    // "stream\n" … "\nendstream" from rawBytes so binary deflate data
    // survives the latin-1 round-trip.
    const streamM = body.match(/stream\r?\n/);
    if (streamM) {
      // Absolute byte offsets of stream/endstream in the original buffer.
      // We can reuse `raw` offsets because `_decodeRaw` produces a 1:1
      // latin-1 mapping (each char code ≡ one byte).
      const sAbs = bodyStart + streamM.index + streamM[0].length;
      const eAbs = endIdx - ((/\r?\n\s*$/.test(raw.slice(0, endIdx))) ? 1 : 0);
      // More precise: find the "endstream" preceding endobj.
      const endStreamIdx = raw.lastIndexOf('endstream', endIdx);
      const streamEnd = endStreamIdx > sAbs ? endStreamIdx : eAbs;
      // Trim trailing CR/LF that precedes "endstream".
      let finalEnd = streamEnd;
      while (finalEnd > sAbs && (rawBytes[finalEnd - 1] === 0x0A || rawBytes[finalEnd - 1] === 0x0D)) finalEnd--;
      const streamBytes = rawBytes.subarray(sAbs, finalEnd);
      const decoded = await this._maybeInflate(streamBytes, body);
      if (decoded) {
        try {
          // Most JS streams are plain ASCII / UTF-8; fall back to latin-1.
          return new TextDecoder('utf-8', { fatal: false }).decode(decoded).trim();
        } catch (_) {
          return String.fromCharCode(...decoded).trim();
        }
      }
      return null;
    }

    // Case B: inline literal — some rare producers emit "<< /JS (src) >>"
    // directly inside the referenced object. We recover the paren-string.
    const litM = body.match(/\(([\s\S]{1,65536}?)\)/);
    if (litM) {
      const src = this._unescapePdfString(litM[1]);
      if (src && src.trim()) return src;
    }
    // Case C: inline hex string.
    const hexM = body.match(/<([0-9A-Fa-f\s]{4,})>/);
    if (hexM) {
      try {
        const hex = hexM[1].replace(/\s+/g, '');
        const bytes = hex.match(/.{2}/g).map(h => parseInt(h, 16));
        return String.fromCharCode(...bytes).replace(/\u0000+$/, '').trim();
      } catch (_) { /* skip */ }
    }
    return null;
  }

  /**
   * If the object body declares /Filter /FlateDecode, use Decompressor to
   * inflate the stream bytes. Otherwise return the bytes unchanged.
   */
  async _maybeInflate(bytes, body) {
    if (!bytes || !bytes.length) return null;
    // Honour explicit filter declarations. Ignore crypt / DCT / CCITT etc.
    if (/\/Filter\s*(?:\/FlateDecode|\[\s*\/FlateDecode)/.test(body)) {
      if (typeof Decompressor === 'undefined') return bytes;
      // PDF streams usually have a zlib header; fall back to raw deflate.
      const r = (await Decompressor.inflate(bytes, 'deflate')) ||
                (await Decompressor.inflate(bytes, 'deflate-raw'));
      return r || bytes;
    }
    if (/\/Filter\b/.test(body)) {
      // Unknown/unsupported filter (ASCIIHex, ASCII85, LZW …) — return raw;
      // some samples still yield readable fragments.
      return bytes;
    }
    return bytes;
  }

  /**
   * Merge extracted script bodies onto the findings object, deduping by a
   * small content hash and bumping risk/refs with heuristics.
   */
  _attachJavaScripts(f, scripts) {
    if (!scripts || !scripts.length) return;
    const seen = new Set();
    const final = [];
    for (const s of scripts) {
      if (!s || !s.source) continue;
      const key = this._shortHash(s.source);
      if (seen.has(key)) continue;
      seen.add(key);
      final.push({
        trigger: s.trigger || 'JavaScript',
        source: s.source,
        size: s.source.length,
        hash: key,
        suspicious: this._jsSuspiciousHints(s.source),
      });
    }
    if (!final.length) return;
    f.metadata.pdfJavaScripts = final;
    // Any extracted JS implies high risk (same policy as XFA dynamic scripts).
    escalateRisk(f, 'high');
    // Surface each script as a finding with a short preview so the IOC /
    // detections table reflects the extracted payload, not just a count.
    for (const s of final) {
      const preview = s.source.length > 120 ?
        s.source.slice(0, 117).replace(/\s+/g, ' ') + '…' :
        s.source.replace(/\s+/g, ' ');
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${s.trigger}: ${preview}`,
        severity: 'high',
        note: `Extracted JavaScript (${this._fmtBytes(s.size)})` +
          (s.suspicious.length ? ` — ${s.suspicious.join(', ')}` : ''),
      });
    }
  }

  /** Short fingerprint for dedup (not cryptographic). */
  _shortHash(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
    }
    return ('00000000' + h.toString(16)).slice(-8);
  }

  /** Flag well-known suspicious JS constructs in extracted PDF scripts. */
  _jsSuspiciousHints(src) {
    const hints = [];
    const checks = [
      [/\bapp\.launchURL\s*\(/,             'app.launchURL'],
      [/\bapp\.alert\s*\(/,                 'app.alert'],
      [/\bapp\.openDoc\s*\(/,               'app.openDoc'],
      [/\bthis\.exportDataObject\s*\(/,     'this.exportDataObject'],
      [/\bthis\.getAnnots?\s*\(/,           'this.getAnnots'],
      [/\bthis\.submitForm\s*\(/,           'this.submitForm'],
      [/\butil\.prints?[cfd]\s*\(/,         'util.print*'],
      [/\beval\s*\(/,                       'eval()'],
      [/\bunescape\s*\(/,                   'unescape()'],
      [/\bString\.fromCharCode\s*\(/,       'fromCharCode()'],
      [/\batob\s*\(/,                       'atob()'],
      [/\bbtoa\s*\(/,                       'btoa()'],
      [/%u[0-9A-Fa-f]{4}/,                  'unicode-escape shellcode'],
      [/\\x[0-9A-Fa-f]{2}\\x[0-9A-Fa-f]{2}/, 'hex-escape shellcode'],
      [/[A-Za-z0-9+/=]{200,}/,              'long base64 blob'],
      [/\b(?:CVE-\d{4}-\d{4,7})\b/i,        'CVE reference'],
    ];
    for (const [re, label] of checks) if (re.test(src)) hints.push(label);
    return hints;
  }

  /** Detect and summarise XFA forms. */
  _extractXfa(raw) {
    // /XFA can be a packet array (dynamic) or a single stream ref (static).
    // Fast presence check:
    const xfaRef = raw.match(/\/XFA\s*(\[|<<|\d+\s+\d+\s+R)/);
    if (!xfaRef) return { present: false, dynamic: false, bodySize: 0, urls: [], scriptHints: [], packets: [] };

    // Dynamic XFA = packet array containing at least the "xdp:xdp" / "config" / "template" pairs
    const dynamic = /\/XFA\s*\[[^\]]{10,}\]/.test(raw) ||
                    /<xdp:xdp[\s>]|<config[\s>]|<template[\s>]|<xfa:datasets[\s>]/i.test(raw);

    // Pull out any XFA XML bodies (inside stream ... endstream blocks).
    // We scan all stream contents for xfa namespaces / tags.
    const urls = [];
    const urlSeen = new Set();
    const scriptHints = [];
    const packets = [];
    let bodySize = 0;

    // XFA body regex - any embedded XML fragment containing xfa or xdp namespace
    const xfaBodyRe = /<\?xml[\s\S]{0,200}?\?>[\s\S]*?<\/(?:xdp|xfa|template|config|datasets)[^>]*>/gi;
    let m;
    while ((m = xfaBodyRe.exec(raw)) !== null) {
      bodySize += m[0].length;
      // Retain up to 5 packets for download (bound total at 2 MB to avoid
      // leaking huge PDFs into findings memory)
      if (packets.length < 5 && bodySize < 2 * 1024 * 1024) {
        packets.push(m[0]);
      }
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
        // Tolerant closing tag — `<\/script foo>` is accepted by browsers
        // and would bypass a plain `<\/script>` (js/bad-tag-filter #56).
        // The backslash-escapes above are load-bearing: without them the
        // literal end-tag bytes in this comment would be seen by the HTML
        // tokenizer once this file is concatenated inline into
        // docs/index.html's inline script bundle, terminating it early.
        const scripts = m[0].match(/<script[^>]*>[\s\S]*?<\/script\b[^>]*>/gi) || [];

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

    return { present: true, dynamic, bodySize, urls, scriptHints, packets };
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
  // Viewer UI: extracted-files banner
  // ════════════════════════════════════════════════════════════════════════

  /**
   * Prepend an interactive table of extracted artefacts (JS scripts + embedded
   * attachments) to the PDF viewer. Mirrors MsgRenderer / EmlRenderer so users
   * can click-through embedded files or download scripts without leaving the
   * viewer. Silent when nothing was extracted.
   */
  _renderExtractedBanner(wrap, findings, fileName) {
    if (!findings || !findings.metadata) return;
    const scripts = findings.metadata.pdfJavaScripts || [];
    const files = (findings.metadata.embeddedFiles || []).filter(e => !!e);
    if (!scripts.length && !files.length) return;

    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    const strong = document.createElement('strong');
    const parts = [];
    if (files.length) parts.push(`${files.length} embedded file${files.length !== 1 ? 's' : ''}`);
    if (scripts.length) parts.push(`${scripts.length} JavaScript block${scripts.length !== 1 ? 's' : ''}`);
    strong.textContent = `Extracted from PDF — ${parts.join(', ')}`;
    banner.appendChild(strong);
    banner.appendChild(document.createTextNode(
      files.length ? ' — click any file to open it for analysis.' : ''));
    wrap.appendChild(banner);

    // ── Embedded files table ─────────────────────────────────────────────
    if (files.length) {
      const attTbl = document.createElement('table'); attTbl.className = 'zip-table';
      const thead = document.createElement('thead');
      const headerRow = document.createElement('tr');
      for (const h of ['', 'Filename', 'MIME', 'Size', '']) {
        const th = document.createElement('th'); th.textContent = h; headerRow.appendChild(th);
      }
      thead.appendChild(headerRow); attTbl.appendChild(thead);

      const tbody = document.createElement('tbody');
      for (const e of files) {
        const tr = document.createElement('tr');
        if (e.data) tr.classList.add('zip-row-clickable');

        const tdIcon = document.createElement('td'); tdIcon.className = 'zip-icon';
        tdIcon.textContent = this._getFileIcon(e.name); tr.appendChild(tdIcon);

        const tdName = document.createElement('td'); tdName.className = 'zip-path';
        tdName.textContent = e.name || '(unnamed)';
        const ext = (e.name || '').split('.').pop().toLowerCase();
        if (/^(exe|dll|scr|com|bat|cmd|vbs|js|ps1|hta|msi|jar)$/.test(ext)) {
          const b = document.createElement('span'); b.className = 'zip-badge-danger';
          b.textContent = 'EXECUTABLE'; tdName.appendChild(b);
        }
        tr.appendChild(tdName);

        const tdMime = document.createElement('td'); tdMime.className = 'zip-size';
        tdMime.textContent = e.mime || '—'; tr.appendChild(tdMime);

        const tdSize = document.createElement('td'); tdSize.className = 'zip-size';
        tdSize.textContent = e.size ? this._fmtBytes(e.size) : '—'; tr.appendChild(tdSize);

        const tdAct = document.createElement('td'); tdAct.className = 'zip-action';
        if (e.data) {
          const openBtn = document.createElement('span'); openBtn.className = 'zip-badge-open';
          openBtn.textContent = '🔍 Open';
          openBtn.title = `Open ${e.name} for analysis`;
          openBtn.addEventListener('click', (ev) => {
            ev.stopPropagation();
            this._openEmbedded(e, wrap);
          });
          tdAct.appendChild(openBtn);

          const dlBtn = document.createElement('span'); dlBtn.className = 'zip-badge-open';
          dlBtn.style.marginLeft = '6px';
          dlBtn.textContent = '⬇';
          dlBtn.title = `Download ${e.name}`;
          dlBtn.addEventListener('click', (ev) => {
            ev.stopPropagation();
            this._downloadEmbedded(e);
          });
          tdAct.appendChild(dlBtn);

          tr.addEventListener('click', () => this._openEmbedded(e, wrap));
        } else {
          const span = document.createElement('span');
          span.style.cssText = 'font-size:10px;color:#888;font-style:italic;';
          span.textContent = 'bytes unavailable';
          tdAct.appendChild(span);
        }
        tr.appendChild(tdAct);
        tbody.appendChild(tr);
      }
      attTbl.appendChild(tbody); wrap.appendChild(attTbl);
    }

    // ── JavaScript scripts table ─────────────────────────────────────────
    if (scripts.length) {
      const jsTbl = document.createElement('table'); jsTbl.className = 'zip-table';
      jsTbl.style.marginTop = '10px';
      const thead = document.createElement('thead');
      const headerRow = document.createElement('tr');
      for (const h of ['', 'Trigger', 'Size', 'Indicators', '']) {
        const th = document.createElement('th'); th.textContent = h; headerRow.appendChild(th);
      }
      thead.appendChild(headerRow); jsTbl.appendChild(thead);

      const tbody = document.createElement('tbody');
      const baseName = (fileName || 'pdf').replace(/\.[^.]+$/, '');
      scripts.forEach((s, idx) => {
        const tr = document.createElement('tr');

        const tdIcon = document.createElement('td'); tdIcon.className = 'zip-icon';
        tdIcon.textContent = '📜'; tr.appendChild(tdIcon);

        const tdTrig = document.createElement('td'); tdTrig.className = 'zip-path';
        tdTrig.textContent = s.trigger;
        const b = document.createElement('span'); b.className = 'zip-badge-danger';
        b.textContent = 'SCRIPT'; tdTrig.appendChild(b);
        tr.appendChild(tdTrig);

        const tdSize = document.createElement('td'); tdSize.className = 'zip-size';
        tdSize.textContent = this._fmtBytes(s.size); tr.appendChild(tdSize);

        const tdHints = document.createElement('td'); tdHints.className = 'zip-size';
        tdHints.textContent = (s.suspicious && s.suspicious.length) ?
          s.suspicious.slice(0, 3).join(', ') + (s.suspicious.length > 3 ? '…' : '') : '—';
        tr.appendChild(tdHints);

        const tdAct = document.createElement('td'); tdAct.className = 'zip-action';
        const openBtn = document.createElement('span'); openBtn.className = 'zip-badge-open';
        openBtn.textContent = '🔍 Open';
        openBtn.title = 'Open this script as an inner child for full analysis';
        openBtn.addEventListener('click', (ev) => {
          ev.stopPropagation();
          const safeTrigger = String(s.trigger || 'script').replace(/[^A-Za-z0-9_.-]+/g, '_');
          const safeName = `${baseName}_${String(idx + 1).padStart(2, '0')}_${safeTrigger}_${s.hash}.js`;
          this._openScript(s, safeName, wrap);
        });
        tdAct.appendChild(openBtn);
        tr.appendChild(tdAct);

        tbody.appendChild(tr);

        // Expandable source preview under each row
        const trCode = document.createElement('tr');
        const tdCode = document.createElement('td');
        tdCode.colSpan = 5;
        tdCode.style.cssText = 'padding:0;background:transparent;';
        const det = document.createElement('details');
        det.style.cssText = 'margin:0;padding:0;';
        const sum = document.createElement('summary');
        sum.style.cssText = 'cursor:pointer;padding:6px 12px;font-size:11px;color:#666;';
        sum.textContent = 'Show source';
        det.appendChild(sum);
        const pre = document.createElement('pre');
        pre.style.cssText = 'margin:0;padding:10px 14px;background:#0d1117;color:#c9d1d9;' +
          'font-size:11px;line-height:1.5;overflow-x:auto;max-height:320px;' +
          'border-top:1px solid #30363d;';
        pre.textContent = s.source;
        det.appendChild(pre);
        tdCode.appendChild(det);
        trCode.appendChild(tdCode);
        tbody.appendChild(trCode);
      });
      jsTbl.appendChild(tbody); wrap.appendChild(jsTbl);
    }
  }

  _openEmbedded(entry, wrap) {
    if (!entry.data) return;
    const bytes = entry.data instanceof Uint8Array ? entry.data : new Uint8Array(entry.data);
    const file = new File([bytes], entry.name || 'embedded',
      { type: entry.mime || 'application/octet-stream' });
    wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
  }

  /**
   * Open an extracted PDF JavaScript block as an inner child file — the
   * application's open-inner-file listener will push a nav state and route
   * the Uint8Array through the regular file-loading pipeline (script viewer +
   * YARA scan + IOC extraction).
   */
  _openScript(script, filename, wrap) {
    if (!script || !script.source) return;
    const bytes = new TextEncoder().encode(script.source);
    const file = new File([bytes], filename, { type: 'application/javascript' });
    wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
  }

  _downloadEmbedded(entry) {
    if (!entry.data) return;
    const bytes = entry.data instanceof Uint8Array ? entry.data : new Uint8Array(entry.data);
    window.FileDownload.downloadBytes(
      bytes,
      entry.name || 'embedded',
      entry.mime || 'application/octet-stream',
    );
  }

  _getFileIcon(name) {
    const ext = (name || '').split('.').pop().toLowerCase();
    if (['exe', 'dll', 'scr', 'com', 'msi'].includes(ext)) return '⚙️';
    if (['bat', 'cmd', 'ps1', 'vbs', 'js', 'sh'].includes(ext)) return '📜';
    if (['doc', 'docx', 'docm', 'odt', 'rtf'].includes(ext)) return '📄';
    if (['xls', 'xlsx', 'xlsm', 'ods', 'csv'].includes(ext)) return '📊';
    if (['ppt', 'pptx', 'pptm', 'odp'].includes(ext)) return '📽️';
    if (['pdf'].includes(ext)) return '📕';
    if (['zip', 'rar', '7z', 'tar', 'gz'].includes(ext)) return '📦';
    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg'].includes(ext)) return '🖼️';
    if (['txt', 'log', 'md'].includes(ext)) return '📝';
    if (['html', 'htm', 'xml', 'json'].includes(ext)) return '🌐';
    if (['eml', 'msg'].includes(ext)) return '✉️';
    return '📄';
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

// ════════════════════════════════════════════════════════════════════════════
// PLAN F3 — pdf.worker lifecycle.
//
// pdf.js owns its own dedicated worker (`vendor/pdf.worker.js`) outside the
// C1–C4 `WorkerManager` channels. `_activeDocs` tracks every open
// `PDFDocumentProxy` from both `render()` and `analyzeForSecurity()` so a
// rapid file switch (Back-then-forward, drag-and-drop while a render is in
// flight) can preempt in-flight `getPage()` / `page.render()` /
// `getJSActions()` work via `PdfRenderer.disposeWorker()` from
// `App._loadFile`.
//
// We deliberately do NOT terminate `pdfjsLib.GlobalWorkerOptions.workerPort`
// — pdf.js re-uses the global worker cheaply for the next document, and
// tearing it down forces an expensive re-spawn. `pdf.destroy()` per-doc is
// sufficient: it cancels the pending tasks for *that* document and lets the
// renderer / analyser catch the resulting `Worker was destroyed` /
// `AbortException` rejections as benign supersession.
// ════════════════════════════════════════════════════════════════════════════
PdfRenderer._activeDocs = new Set();

PdfRenderer.disposeWorker = async function disposeWorker() {
  const docs = Array.from(PdfRenderer._activeDocs);
  PdfRenderer._activeDocs.clear();
  if (!docs.length) return;
  await Promise.allSettled(docs.map(d => {
    try {
      const r = d && typeof d.destroy === 'function' ? d.destroy() : null;
      return Promise.resolve(r).catch(() => {});
    } catch (_) {
      return Promise.resolve();
    }
  }));
};
