// ════════════════════════════════════════════════════════════════════════════
// App — sidebar rendering (single scrollable pane with collapsible sections)
// ════════════════════════════════════════════════════════════════════════════

// Shared severity ranking — used by both the deobfuscation and IOC/refs sections.
const _SIDEBAR_SEV_ORDER = { critical: 0, high: 1, medium: 2, info: 3 };

Object.assign(App.prototype, {

  // Shared helper: create a synthetic file from decoded bytes and dispatch
  // it through the unified `App.openInnerFile` drill-down.
  // Deduplicated from the five "Decode & Analyse" / "Load for analysis" /
  // "Load embedded ZIP" / "Decompress & Analyse" / "All the way" button
  // handlers in the encoded-content card. The returnFocus payload tells
  // `_renderSidebar` to scroll + flash the originating Deobfuscation
  // finding when the user navigates back from the drill-down.
  _drillDownToSynthetic(bytes, synName, mime, fileName, findingOffset) {
    const blob = new Blob([bytes], { type: mime || 'application/octet-stream' });
    const syntheticFile = new File([blob], synName, { type: mime || 'application/octet-stream' });
    this.openInnerFile(syntheticFile, null, {
      parentName: fileName,
      returnFocus: { section: 'deobfuscation', findingOffset },
    });
  },


  // Truncate a string shown inside a match toast to keep the notification
  // compact. IOCs extracted from decoded blobs can be kilobytes long.
  _truncateToast(s, max) {
    if (!s) return '';
    max = max || 80;
    return s.length > max ? s.slice(0, max - 1) + '…' : s;
  },

  // ── Nicelist hide-toggle persistence ────────────────────────────────────
  // Tiny accessors for the "Hide common infrastructure" preference in the
  // IOCs section. Default is **false** (show nicelisted rows, just dimmed
  // and demoted below the divider) so a first-time user still sees every
  // IOC. The toggle is a pure presentation / sort concern — it never
  // affects Detections, never drops anything from the analyser's evidence
  // store, and cannot escalate or suppress severity.
  //
  // Key: `loupe_ioc_hide_nicelisted`  →  "0" | "1"
  // (see the persistence-keys table in CONTRIBUTING.md).
  _getHideNicelisted() {
    try { return localStorage.getItem('loupe_ioc_hide_nicelisted') === '1'; }
    catch (_) { return false; }
  },
  _setHideNicelisted(v) {
    try { localStorage.setItem('loupe_ioc_hide_nicelisted', v ? '1' : '0'); }
    catch (_) { /* storage blocked — in-memory only, toggle still works for this session */ }
  },

  _renderSidebar(fileName, analyzer) {
    // Clear any lingering encoded-content highlights from previous view
    this._clearEncodedHighlight();

    // ── Pending return-navigation state ─────────────────────────────────
    // `_pendingSectionOpenState` carries the user's manual collapse/expand
    // choices for each top-level section across a drill-down round-trip
    // (captured by `_pushNavState` → replayed here). Consumed once.
    //
    // `_pendingReturnFocus` is an explicit "scroll to this finding and flash
    // it" instruction set by deobfuscation drill-down buttons. When present
    // it also force-expands its owning section, overriding any stored
    // collapse — the user explicitly returned to focus there.
    this._sectionOpenOverrides = this._pendingSectionOpenState || null;
    const returnFocus = this._pendingReturnFocus || null;
    this._pendingSectionOpenState = null;
    this._pendingReturnFocus = null;
    // Transient flag consumed by `_renderEncodedContentSection` to force
    // the Deobfuscation <details> open regardless of any stored collapse.
    this._forceDeobfuscationOpen = !!(returnFocus && returnFocus.section === 'deobfuscation');


    const f = this.findings;
    const yaraCount = (this._yaraResults || []).length;


    // ── Risk bar ─────────────────────────────────────────────────────────
    const rb = document.getElementById('sb-risk');
    rb.className = `sb-risk risk-${f.risk}`;
    let riskText;
    if (f.risk === 'critical') {
      riskText = yaraCount ? '🟣 CRITICAL — Critical YARA rules matched' : '🟣 CRITICAL — Critical threats detected';
    } else if (f.risk === 'high') {
      if (f.hasMacros && (f.autoExec || []).length) riskText = '🔴 HIGH RISK — Auto-execute macros detected';
      else if (yaraCount) riskText = '🔴 HIGH RISK — YARA rules matched';
      else riskText = '🔴 HIGH RISK — Dangerous content detected';
    } else if (f.risk === 'medium') {
      riskText = f.hasMacros ? '🟡 Macros present' : '🟡 Potential risks detected';
    } else {
      riskText = '🟢 No threats detected';
    }
    document.getElementById('sb-risk-title').textContent = riskText;

    // ── Populate single scrollable body ──────────────────────────────────
    const body = document.getElementById('sb-body');
    body.innerHTML = '';

    // 1. File Info (collapsed by default)
    this._renderFileInfoSection(body, fileName);

    // 2. Detections (YARA matches, patterns, info) & 3. IOCs (URLs, IPs, hashes, etc.)
    const allRefs = [...(f.externalRefs || []), ...(f.interestingStrings || [])];
    const _DETECTION_TYPES = new Set([IOC.YARA, IOC.PATTERN, IOC.INFO]);
    const detections = allRefs.filter(r => _DETECTION_TYPES.has(r.type));
    const iocRefs = allRefs.filter(r => !_DETECTION_TYPES.has(r.type));
    this._renderFindingsTableSection(body, detections, fileName, '🚨', 'Detections', '✅ No detections triggered.');
    this._renderFindingsTableSection(body, iocRefs, fileName, '📡', 'IOCs', '✅ No indicators of compromise found.');

    // 3b. Binary triage surfaces — only present when the currently loaded
    // file routed through one of the three native-binary renderers. Both
    // sections read from `this.currentResult.binary` (`{format, parsed}`)
    // populated by app-load.js dispatchers, and are a no-op otherwise.
    // Keeps the sidebar focused on pivot + MITRE rollup — the heavy
    // structural detail stays in the main viewer's Tier-C cards.
    if (this.currentResult && this.currentResult.binary) {
      this._renderBinaryMetadataSection(body, fileName);
      this._renderMitreSection(body, fileName);
    }

    // 4. Macros (only if detected; auto-opens when auto-exec found)
    if (f.hasMacros) {
      this._renderMacrosSection(body, analyzer);
    }

    // 4b. PDF JavaScript (only if the PDF renderer extracted any script bodies)
    if (f.metadata && f.metadata.pdfJavaScripts && f.metadata.pdfJavaScripts.length) {
      this._renderPdfJavaScriptSection(body, fileName);
    }

    // 5. Deobfuscation (only if detected)
    if (f.encodedContent && f.encodedContent.length) {
      this._renderEncodedContentSection(body, f.encodedContent, fileName);
    }

    // ── Return-focus handling ───────────────────────────────────────────
    // When the user returns from a drill-down triggered by a Deobfuscation
    // action (Load for analysis / Decode & Analyse / All the way / etc.),
    // scroll the originating card into view and flash it so they can resume
    // iterating through the findings without hunting or scrolling. Wrapped
    // in rAF so the sidebar layout has settled before we measure/scroll.
    if (returnFocus && returnFocus.section === 'deobfuscation') {
      requestAnimationFrame(() => this._applyDeobfuscationReturnFocus(returnFocus));
    }

    // Show sidebar
    if (!this.sidebarOpen) this._toggleSidebar();


    // Lock sidebar width after initial render so filter toggles don't cause resizing.
    // Uses requestAnimationFrame to read the computed fit-content width after layout,
    // then sets it as a fixed pixel value. Manual drag-resize still works because
    // _setupSidebarResize() sets style.width directly. Cleared in _clearFile().
    const sidebar = document.getElementById('sidebar');
    requestAnimationFrame(() => {
      if (!sidebar.classList.contains('hidden')) {
        sidebar.style.width = sidebar.getBoundingClientRect().width + 'px';
      }
    });
  },

  // Helper: resolve the `<details open>` state for a top-level sidebar
  // section, honouring any pending open-state overrides snapshotted from
  // the previous render (e.g. when the user returns from drilling into a
  // decoded child file — their manual collapses/expansions on each section
  // persist across that round-trip).
  _resolveSectionOpen(key, fallback) {
    const overrides = this._sectionOpenOverrides;
    if (overrides && Object.prototype.hasOwnProperty.call(overrides, key)) {
      return !!overrides[key];
    }
    return !!fallback;
  },

  // ── File Info section ──────────────────────────────────────────────────
  _renderFileInfoSection(container, fileName) {
    const f = this.findings;
    const det = document.createElement('details');
    det.className = 'sb-details';
    det.dataset.sbSection = 'fileInfo';
    det.open = this._resolveSectionOpen('fileInfo', true);


    const sum = document.createElement('summary');
    sum.className = 'sb-details-summary';
    sum.textContent = '📋 File Info';
    det.appendChild(sum);

    const body = document.createElement('div');
    body.className = 'sb-details-body';

    // File properties table
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const FMT = {
      docx: 'Word Document', docm: 'Word Macro-Enabled Document',
      xlsx: 'Excel Workbook', xlsm: 'Excel Macro-Enabled Workbook',
      xls: 'Excel 97-2003 Workbook', ods: 'OpenDocument Spreadsheet',
      pptx: 'PowerPoint Presentation', pptm: 'PowerPoint Macro-Enabled Presentation',
      csv: 'Comma-Separated Values', tsv: 'Tab-Separated Values',
      doc: 'Word 97-2003 Document', msg: 'Outlook Message',
      eml: 'Email Message', lnk: 'Windows Shortcut', hta: 'HTML Application',
      pdf: 'PDF Document', rtf: 'Rich Text Format', html: 'HTML Document',
      htm: 'HTML Document', one: 'OneNote Document', iso: 'Disk Image (ISO)',
      img: 'Disk Image (IMG)', zip: 'ZIP Archive', rar: 'RAR Archive',
      '7z': '7-Zip Archive', wsf: 'Windows Script File', url: 'Internet Shortcut',
      svg: 'SVG Image', iqy: 'Internet Query File', slk: 'Symbolic Link File',
      evtx: 'Windows Event Log', sqlite: 'SQLite Database', db: 'SQLite Database',
      plist: 'Property List',
    };
    const meta = this._fileMeta || {};
    body.appendChild(this._sec('File Properties'));
    const ft = document.createElement('table'); ft.className = 'meta-table';
    const fileProps = [
      ['Filename', meta.name || fileName || '—'],
      ['Format', (FMT[ext] || ext.toUpperCase() + ' File') + ' (.' + ext + ')'],
      ['Size', meta.size ? this._fmtBytes(meta.size) + ' (' + meta.size.toLocaleString() + ' bytes)' : '—'],
    ];
    if (meta.mimeType) fileProps.push(['MIME Type', meta.mimeType]);
    if (meta.lastModified) fileProps.push(['Last Modified', meta.lastModified]);
    if (meta.magic) {
      const magicLabel = meta.magic.label + (meta.magic.hex ? ' [' + meta.magic.hex + ']' : '');
      fileProps.push(['Magic Bytes', magicLabel]);
    }
    if (meta.entropy !== undefined) {
      const ent = meta.entropy;
      let entLabel = ent.toFixed(3) + ' / 8.000';
      if (ent > 7.5) entLabel += ' ⚠ very high (encrypted/packed?)';
      else if (ent > 6.5) entLabel += ' (compressed)';
      else if (ent < 1.5) entLabel += ' (very low — sparse/empty)';
      fileProps.push(['Entropy', entLabel]);
    }
    for (const [k, v] of fileProps) {
      const tr = document.createElement('tr');
      const td1 = document.createElement('td'); td1.textContent = k;
      const td2 = document.createElement('td'); td2.textContent = v;
      tr.appendChild(td1); tr.appendChild(td2); ft.appendChild(tr);
    }
    body.appendChild(ft);

    // Hashes
    body.appendChild(this._sec('File Hashes'));
    const ht = document.createElement('table');
    ht.className = 'hash-table';
    const hashes = this.fileHashes
      ? [['MD5', this.fileHashes.md5], ['SHA-1', this.fileHashes.sha1], ['SHA-256', this.fileHashes.sha256]]
      : [['MD5', 'computing…'], ['SHA-1', 'computing…'], ['SHA-256', 'computing…']];
    for (const [alg, val] of hashes) {
      const tr = document.createElement('tr');
      const td1 = document.createElement('td'); td1.textContent = alg;
      const td2 = document.createElement('td'); td2.className = 'hash-val';
      const sp = document.createElement('span'); sp.textContent = val; td2.appendChild(sp);
      if (val && val.length > 10) {
        const cb = document.createElement('button'); cb.className = 'copy-url-btn'; cb.textContent = '📋'; cb.title = 'Copy';
        cb.addEventListener('click', () => this._copyToClipboard(val)); td2.appendChild(cb);
      }
      if (alg === 'SHA-256' && this.fileHashes && this.fileHashes.sha256.length > 10) {
        const vt = document.createElement('a');
        vt.href = 'https://www.virustotal.com/gui/file/' + val + '/detection';
        vt.target = '_blank'; vt.rel = 'noopener noreferrer';
        vt.textContent = '🔎 VT'; vt.title = 'Search on VirusTotal';
        vt.style.cssText = 'font-size:10px;margin-left:6px;color:#1a73e8;text-decoration:none;';
        td2.appendChild(vt);
      }
      tr.appendChild(td1); tr.appendChild(td2); ht.appendChild(tr);
    }
    body.appendChild(ht);

    // VBA project info
    if (f.hasMacros && f.macroHash) {
      body.appendChild(this._sec('VBA Project'));
      const vt = document.createElement('table'); vt.className = 'hash-table';
      const r1 = document.createElement('tr');
      const r1a = document.createElement('td'); r1a.textContent = 'Size';
      const r1b = document.createElement('td'); r1b.className = 'hash-val'; r1b.textContent = this._fmtBytes(f.macroSize || 0);
      r1.appendChild(r1a); r1.appendChild(r1b); vt.appendChild(r1);
      const r2 = document.createElement('tr');
      const r2a = document.createElement('td'); r2a.textContent = 'SHA-256';
      const r2b = document.createElement('td'); r2b.className = 'hash-val';
      const sp2 = document.createElement('span'); sp2.textContent = f.macroHash; r2b.appendChild(sp2);
      const cb2 = document.createElement('button'); cb2.className = 'copy-url-btn'; cb2.textContent = '📋';
      cb2.addEventListener('click', () => this._copyToClipboard(f.macroHash)); r2b.appendChild(cb2);
      r2.appendChild(r2a); r2.appendChild(r2b); vt.appendChild(r2);
      body.appendChild(vt);
    }

    // Metadata
    const metaVals = Object.entries(f.metadata || {}).filter(([, v]) => v);
    if (metaVals.length) {
      body.appendChild(this._sec('Document Metadata'));
      const mt = document.createElement('table'); mt.className = 'meta-table';
      const labels = {
        title: 'Title', subject: 'Subject', creator: 'Author',
        lastModifiedBy: 'Last Modified By', created: 'Created',
        modified: 'Modified', revision: 'Revision',
      };
      for (const [k, v] of metaVals) {
        const tr = document.createElement('tr');
        const td1 = document.createElement('td'); td1.textContent = labels[k] || k;
        const td2 = document.createElement('td');
        // Route non-scalar values (e.g. EML attachments array-of-objects,
        // PDF pdfJavaScripts) through the shared formatter so they render
        // legibly instead of collapsing to "[object Object]" via default
        // string coercion.
        td2.textContent = (v !== null && typeof v === 'object')
          ? this._formatMetadataValue(v, 0)
          : String(v);
        tr.appendChild(td1); tr.appendChild(td2); mt.appendChild(tr);
      }
      body.appendChild(mt);
    }
    if (!metaVals.length && !f.hasMacros) {
      const p = document.createElement('p');
      p.style.cssText = 'color:#888;font-size:11px;margin-top:8px;';
      p.textContent = 'No metadata found.';
      body.appendChild(p);
    }

    det.appendChild(body);
    container.appendChild(det);
  },

  // ── Macros section ─────────────────────────────────────────────────────
  _renderMacrosSection(container, analyzer) {
    const f = this.findings;
    const det = document.createElement('details');
    det.className = 'sb-details';
    det.dataset.sbSection = 'macros';
    // Auto-open if auto-exec patterns detected
    det.open = this._resolveSectionOpen('macros', !!(f.autoExec && f.autoExec.length));


    const sum = document.createElement('summary');
    sum.className = 'sb-details-summary';
    const modCount = (f.modules || []).filter(m => m.source).length || (f.modules || []).length;
    let sumText = `⚡ Macros (${modCount} module${modCount !== 1 ? 's' : ''})`;
    sum.textContent = sumText;
    if (f.autoExec && f.autoExec.length) {
      const badge = document.createElement('span');
      badge.className = 'badge badge-high';
      badge.style.marginLeft = '6px';
      badge.textContent = '⚠ auto-exec';
      sum.appendChild(badge);
    }
    det.appendChild(sum);

    const body = document.createElement('div');
    body.className = 'sb-details-body';

    const hasSource = f.modules && f.modules.some(m => m.source);

    // Download button
    const dl = document.createElement('button'); dl.className = 'tb-btn';
    dl.style.cssText = 'font-size:11px;margin-bottom:10px;width:100%;display:block;';
    dl.textContent = hasSource ? '💾 Download Macros (.txt)' : '💾 Download Macros (.bin)';
    dl.addEventListener('click', () => this._downloadMacros());
    body.appendChild(dl);

    // Auto-exec warning
    if (f.autoExec && f.autoExec.length) {
      const w = document.createElement('div');
      w.style.cssText = 'background:#f8d7da;border:1px solid #f5c6cb;border-radius:4px;padding:8px 10px;margin-bottom:10px;font-size:11px;color:#721c24;';
      w.innerHTML = '<strong>🚨 Auto-execute patterns:</strong>';
      const ul = document.createElement('ul'); ul.style.cssText = 'margin:4px 0 0 16px;';
      for (const { module, patterns } of f.autoExec) for (const pat of patterns) {
        const li = document.createElement('li'); li.textContent = `${module}: ${pat}`; ul.appendChild(li);
      }
      w.appendChild(ul); body.appendChild(w);
    }

    // Obfuscation hint
    if (f.rawBin && f.rawBin.length > 0 && hasSource) {
      const srcLen = (f.modules || []).reduce((s, m) => s + (m.source || '').length, 0);
      if (srcLen > 0 && f.rawBin.length > srcLen * 5) {
        const hint = document.createElement('div');
        hint.style.cssText = 'background:#fff3cd;border:1px solid #ffc107;border-radius:4px;padding:8px 10px;margin-bottom:10px;font-size:11px;color:#856404;';
        hint.textContent = `⚠ Decoded source (${this._fmtBytes(srcLen)}) is much smaller than VBA binary (${this._fmtBytes(f.rawBin.length)}) — possible obfuscation or compression.`;
        body.appendChild(hint);
      }
    }

    if (!hasSource) {
      const note = document.createElement('p');
      note.style.cssText = 'color:#888;font-size:11px;font-style:italic;margin-bottom:8px;';
      note.textContent = 'Source could not be decoded as text. Raw binary available for download above.';
      body.appendChild(note);
    } else {
      // Module source blocks
      const hi = analyzer || { highlightVBA: s => escHtml(s) };
      for (const mod of (f.modules || [])) {
        if (!mod.source) continue;
        const hasAuto = (f.autoExec || []).some(a => a.module === mod.name);
        const modDet = document.createElement('details');
        modDet.open = (f.modules.filter(m => m.source).length === 1);
        const modSum = document.createElement('summary');
        modSum.style.cssText = 'cursor:pointer;font-weight:600;font-size:11px;padding:4px 0;';
        modSum.textContent = `📄 ${mod.name}`;
        if (hasAuto) {
          const b = document.createElement('span'); b.className = 'badge badge-high';
          b.style.marginLeft = '6px'; b.textContent = 'auto-exec';
          modSum.appendChild(b);
        }
        modDet.appendChild(modSum);
        const pre = document.createElement('pre'); pre.className = 'vba-code';
        pre.innerHTML = hi.highlightVBA(mod.source);
        modDet.appendChild(pre); body.appendChild(modDet);
      }
    }

    det.appendChild(body);
    container.appendChild(det);
  },

  // ── PDF JavaScript section ─────────────────────────────────────────────
  // Surfaces JS bodies extracted from /JS, /JavaScript, document-level and
  // per-page actions (see pdf-renderer.js::_attachJavaScripts). Each script
  // is an independent download — we don't concat them into a single blob
  // because each one represents a distinct trigger (OpenAction vs. an
  // /AA entry on a specific annotation, for example) and forensic analysts
  // usually want to review them separately. A "Download all" convenience
  // button (_downloadPdfScripts in app-ui.js) joins them for bulk export.
  _renderPdfJavaScriptSection(container, fileName) {
    const f = this.findings;
    const scripts = (f.metadata && f.metadata.pdfJavaScripts) || [];
    if (!scripts.length) return;

    const det = document.createElement('details');
    det.className = 'sb-details';
    det.dataset.sbSection = 'pdfJs';
    // Default-open: any extracted PDF JS is high signal. Honour user's
    // manual collapse across drill-down round-trips.
    det.open = this._resolveSectionOpen('pdfJs', true);


    const sum = document.createElement('summary');
    sum.className = 'sb-details-summary';
    sum.textContent = `📜 PDF JavaScript (${scripts.length})`;
    const badge = document.createElement('span');
    badge.className = 'badge badge-high';
    badge.style.marginLeft = '6px';
    badge.textContent = '⚠ extracted';
    sum.appendChild(badge);
    det.appendChild(sum);

    const body = document.createElement('div');
    body.className = 'sb-details-body';

    // Download-all button (mirrors Macros section)
    const dl = document.createElement('button'); dl.className = 'tb-btn';
    dl.style.cssText = 'font-size:11px;margin-bottom:10px;width:100%;display:block;';
    dl.textContent = '💾 Download all scripts (.js)';
    dl.addEventListener('click', () => this._downloadPdfScripts());
    body.appendChild(dl);

    // Per-script blocks: trigger + suspicious-hint badges + source pre
    scripts.forEach((s, idx) => {
      const modDet = document.createElement('details');
      modDet.open = (scripts.length === 1);

      const modSum = document.createElement('summary');
      modSum.style.cssText = 'cursor:pointer;font-weight:600;font-size:11px;padding:4px 0;';
      modSum.textContent = `📜 ${s.trigger}`;

      // Hint badges (e.g. eval, unescape, launchURL) — flag suspicious APIs
      if (s.suspicious && s.suspicious.length) {
        for (const hint of s.suspicious.slice(0, 5)) {
          const b = document.createElement('span');
          b.className = 'badge badge-high';
          b.style.marginLeft = '4px';
          b.textContent = hint;
          modSum.appendChild(b);
        }
      }

      // Size hint at right
      const sizeEl = document.createElement('span');
      sizeEl.style.cssText = 'margin-left:8px;color:#888;font-weight:normal;';
      sizeEl.textContent = this._fmtBytes(s.size);
      modSum.appendChild(sizeEl);
      modDet.appendChild(modSum);

      // Per-script body: source only. Per-script download has been replaced
      // by the "🔍 Open" action in the viewer banner (which routes the script
      // through the inner-child loader for full analysis). The sidebar's
      // top-level "Download all scripts (.js)" button still covers bulk export.
      const sBody = document.createElement('div');
      sBody.style.cssText = 'margin-top:6px;';

      const pre = document.createElement('pre');
      pre.className = 'vba-code';
      pre.style.whiteSpace = 'pre-wrap';
      pre.textContent = s.source;
      sBody.appendChild(pre);

      modDet.appendChild(sBody);
      body.appendChild(modDet);
    });

    det.appendChild(body);
    container.appendChild(det);
  },

  // ── Encoded Content section ────────────────────────────────────────────
  _renderEncodedContentSection(container, encodedFindings, fileName) {
    // Determine if we have a plaintext view with accessible source text for highlighting
    const _pc = document.getElementById('page-container');
    const _docEl = _pc && _pc.firstElementChild;
    const _sourceText = _docEl && _docEl._rawText;
    const _isPlaintextView = !!(_pc && _pc.querySelector('.plaintext-table'));

    const det = document.createElement('details');
    det.className = 'sb-details';
    det.dataset.sbSection = 'deobfuscation';
    // Auto-open if any high-severity findings, decoded content, or IOCs extracted.
    // Honour user's manual collapse across drill-down round-trips, UNLESS the
    // user is explicitly returning from a Deobfuscation finding drill-down —
    // in that case force-open so the originating card is visible/focusable.
    const hasHigh = encodedFindings.some(f => f.severity === 'high' || f.severity === 'critical');
    const hasDecoded = encodedFindings.some(f => f.decodedBytes);
    const hasIOCs = encodedFindings.some(f => f.iocs && f.iocs.length);
    const defaultOpen = hasHigh || hasDecoded || hasIOCs;
    // Force-open the section when we're returning from a Deobfuscation
    // drill-down (the originating card is about to be scrolled into view
    // and flashed — it MUST be visible). Otherwise honour the user's
    // manual collapse captured before the drill-down.
    const forceOpen = !!this._forceDeobfuscationOpen;
    det.open = forceOpen ? true : this._resolveSectionOpen('deobfuscation', defaultOpen);



    const sum = document.createElement('summary');
    sum.className = 'sb-details-summary';
    sum.textContent = `🧅 Deobfuscation (${encodedFindings.length})`;
    if (hasHigh) {
      const badge = document.createElement('span');
      badge.className = 'badge badge-high';
      badge.style.marginLeft = '6px';
      badge.textContent = '⚠ payload';
      sum.appendChild(badge);
    }
    det.appendChild(sum);

    const body = document.createElement('div');
    body.className = 'sb-details-body';

    // ── Filter state ──────────────────────────────────────────────────────
    const activeSeverities = new Set();

    // ── Severity config ───────────────────────────────────────────────────
    const sevConfig = {
      critical: { icon: '🟣', color: '#4a1a7a' },
      high:     { icon: '🔴', color: '#721c24' },
      medium:   { icon: '🟡', color: '#856404' },
      info:     { icon: '🔵', color: '#666' },
    };

    // ── Store references ──────────────────────────────────────────────────
    const sevFilterElements = new Map();
    const cardElements = [];

    // ── Severity filter bar (clickable) ───────────────────────────────────
    const sevBar = document.createElement('div'); sevBar.className = 'sev-bar';

    for (const sev of ['critical', 'high', 'medium', 'info']) {
      const count = encodedFindings.filter(f => f.severity === sev).length;
      if (!count) continue;

      const { icon, color } = sevConfig[sev];
      const s = document.createElement('span');
      s.className = 'sev-filter';
      s.dataset.severity = sev;
      s.style.color = color;
      s.textContent = `${icon} ${count} ${sev}`;
      s.title = `Click to filter by ${sev} severity`;
      s.addEventListener('click', () => {
        if (activeSeverities.has(sev)) {
          activeSeverities.delete(sev);
          s.classList.remove('sev-filter-active');
        } else {
          activeSeverities.add(sev);
          s.classList.add('sev-filter-active');
        }
        applyEncFilters();
      });
      sevBar.appendChild(s);
      sevFilterElements.set(sev, s);
    }
    if (sevBar.children.length) body.appendChild(sevBar);

    // Render each finding as a card
    const sorted = [...encodedFindings].sort((a, b) => (_SIDEBAR_SEV_ORDER[a.severity] ?? 9) - (_SIDEBAR_SEV_ORDER[b.severity] ?? 9));
    for (const finding of sorted) {
      const card = document.createElement('div');
      card.className = `enc-finding-card enc-sev-${finding.severity}`;
      // Stamp the finding's offset as a DOM attribute so
      // `_applyDeobfuscationReturnFocus` can locate the originating card
      // after a drill-down round-trip (the `_cardEl` reference below lives
      // on the finding object which survives re-renders too, but the dataset
      // attribute makes this queryable even when scanning stale state).
      if (finding.offset !== undefined && finding.offset !== null) {
        card.dataset.encOffset = String(finding.offset);
      }

      // Store DOM reference for bidirectional cross-flash linking
      finding._cardEl = card;

      // Keep any rows already registered by _renderIocsSection (which runs
      // BEFORE this section — see _renderSidebar ordering). Overwriting with
      // a fresh `[]` here would wipe those registrations and break the
      // "IOCs: N URL" click-to-flash handler below.
      finding._iocRows = finding._iocRows || [];

      // ── Compute the FULL deobfuscation lineage up-front ─────────────
      // Every downstream UI element (header depth badge, chain pill row,
      // size-delta row, per-hop tooltips) derives from these two values,
      // so we build them once and share across the rest of the card.
      //
      // `_deepest`   — the leaf node in the innerFindings tree (may be
      //                identical to `finding` for single-layer findings).
      // `_fullChain` — the concatenated encoding / decoded-type lineage
      //                from outer source all the way to the deepest
      //                decoded output. Prefers the deepest node's chain
      //                (the detector stores cumulative lineage there) and
      //                falls back to the outer finding's chain when the
      //                tree has no inner findings.
      const _deepest = this._getDeepestFinding(finding);
      const _outerChain = (finding.chain && finding.chain.length) ? finding.chain : [];
      const _deepChain = (_deepest && _deepest !== finding && _deepest.chain && _deepest.chain.length)
        ? _deepest.chain
        : [];
      // Dedupe consecutive repeats (defensive — the detector occasionally
      // pushes "text" twice when a classifier and a utf-8 sniff both fire).
      const _fullChainRaw = _deepChain.length >= _outerChain.length ? _deepChain : _outerChain;
      const _fullChain = [];
      for (const h of _fullChainRaw) {
        if (!_fullChain.length || _fullChain[_fullChain.length - 1] !== h) _fullChain.push(h);
      }

      // Header line: severity badge + encoding type + depth badge
      const header = document.createElement('div');
      header.className = 'enc-finding-header';
      const badge = document.createElement('span');
      badge.className = `badge badge-${finding.severity}`;
      badge.textContent = finding.severity;
      header.appendChild(badge);
      const title = document.createElement('span');
      title.className = 'enc-finding-title';
      title.textContent = `${finding.encoding}-encoded content`;
      if (finding.hint) title.textContent += ` — ${finding.hint}`;
      header.appendChild(title);
      // Depth badge: only shown for multi-layer findings (≥ 2 hops in the
      // full chain). Mirrors the `⚠ payload` header badge pattern so the
      // analyst knows at-a-glance how much peeling is going on without
      // having to read the chain row. Singleton layers (e.g. Base64 → text)
      // are intentionally unbadged — the chain row itself is the signal.
      if (_fullChain.length >= 2) {
        const depthBadge = document.createElement('span');
        depthBadge.className = 'enc-depth-badge';
        depthBadge.textContent = `${_fullChain.length} layers`;
        depthBadge.title = `Deobfuscation chain has ${_fullChain.length} layers — hover the chain pills below for per-layer details`;
        header.appendChild(depthBadge);
      }
      card.appendChild(header);

      // Details
      const details = document.createElement('div');
      details.className = 'enc-finding-details';

      // Compute line range for plaintext views — consumed by both the
      // consolidated metadata strip (see below) and the card-level
      // click / hover handlers that scroll the source into view. When
      // the view isn't plaintext we skip the work entirely; the strip
      // will fall back to the raw byte offset.
      //
      // Historically this block produced its own "95 B · line 1 🔍"
      // meta row with an inline locate button. The button is gone now:
      // clicking anywhere on the card does the scroll-and-flash, matching
      // how IOC rows already behave, so there is nothing to duplicate.
      let _canLocate = false;
      if (_isPlaintextView && _sourceText && finding.length) {
        const beforeText = _sourceText.substring(0, finding.offset);
        const startLine = (beforeText.match(/\n/g) || []).length + 1;
        const encodedSpan = _sourceText.substring(finding.offset, finding.offset + finding.length);
        const lineSpan = (encodedSpan.match(/\n/g) || []).length;
        const endLine = startLine + lineSpan;
        finding._startLine = startLine;
        finding._endLine = endLine;
        _canLocate = true;
      }

      // Decoded/deobfuscated content preview (prioritized over raw snippet —
      // hovering the card already highlights the encoded source in the view).
      // Shared helper so the "deepest layer" block below can reuse the same
      // UTF-8-safe text-extraction rules.
      const _extractTextPreview = (f) => {
        if (f._deobfuscatedText) return f._deobfuscatedText;
        if (f.decodedBytes && f.decodedBytes.length > 0) {
          try {
            const t = new TextDecoder('utf-8', { fatal: true }).decode(f.decodedBytes.slice(0, 800));
            const cc = [...t].filter(c => { const cp = c.codePointAt(0); return cp < 32 && cp !== 9 && cp !== 10 && cp !== 13; }).length;
            if (cc <= t.length * 0.1) return t;
          } catch (_) { /* binary content — no text preview */ }
        }
        return null;
      };

      // ─── 3-tier preview stack ────────────────────────────────────────────
      // 1. GREY   — raw encoded snippet as it appears in the source
      // 2. GREEN  — finding's immediate decoded output (one layer peeled)
      // 3. PURPLE — deepest decoded layer ("all the way" output)
      // Each pair is separated by a small `.enc-decode-depth-sep` divider
      // that names the layer(s) being peeled. Any tier can be skipped
      // independently (e.g. no source text → no grey; binary decode → no
      // green; single-layer encoding → no purple). The purple tier may
      // decode asynchronously — see the lazyDecode branch below.
      //
      // All three previews share the same HARD character cap (`maxLen`) via
      // the `truncate()` helper — keeps card heights consistent and prevents
      // one oversized layer from dominating the sidebar.
      const maxLen = 200;
      const truncate = s => (s.length > maxLen ? s.substring(0, maxLen) + '\u2026' : s);

      const _greenText = _extractTextPreview(finding);


      // Small helper: build a separator with the given label + optional
      // `deep` styling (purple tint) or base (muted grey) styling.
      const mkSep = (labelText, deep) => {
        const sep = document.createElement('div');
        sep.className = 'enc-decode-depth-sep' + (deep ? ' enc-depth-sep-deep' : '');
        const sepLabel = document.createElement('span');
        sepLabel.className = 'enc-decode-depth-label';
        sepLabel.textContent = labelText;
        sep.title = labelText;
        sep.appendChild(sepLabel);
        return sep;
      };

      // ── 1. GREY — raw encoded snippet ─────────────────────────────────
      // Previously only rendered as a fallback when no green preview was
      // available. Now always shown (when source text is available) so the
      // analyst can see both the encoded source AND the decoded payload
      // side-by-side. `.snippet` from the detector wins over slicing
      // _sourceText because the detector already trims & formats it.
      //
      // Truncated through the shared `truncate(maxLen)` helper so the grey,
      // green, and purple blocks all obey the same hard character cap.
      const _rawSnippet = finding.snippet || (_sourceText && finding.length
        ? _sourceText.substring(finding.offset, finding.offset + finding.length)
        : null);
      if (_rawSnippet) {
        const snippetEl = document.createElement('div');
        snippetEl.className = 'enc-snippet';
        snippetEl.textContent = truncate(_rawSnippet);
        // The snippet previously had its own click handler that duplicated
        // the card-level locate action. With the whole card now handling
        // scroll-and-flash on click (see below), the snippet falls through
        // to the card's listener — no bespoke cursor / handler needed.
        details.appendChild(snippetEl);
      }

      // Preserve previous variable name used further below as a
      // presence flag for rendering the grey/green separator.
      const _snippetText = _rawSnippet;

      // ── 2. GREEN — immediate decoded text (one layer peeled) ──────────
      let greenEl = null;
      if (_greenText) {
        // Insert a separator between grey and green ONLY when both exist.
        // Label describes what was peeled: the finding's encoding +
        // classification (e.g. "↓ 1 layer · Base64 → text").
        if (_snippetText) {
          const firstChain = (finding.chain && finding.chain.length)
            ? finding.chain.join(' → ')
            : (finding.encoding || 'decoded');
          details.appendChild(mkSep(`\u2193 1 layer · ${firstChain}`, false));
        }
        greenEl = document.createElement('div');
        greenEl.className = 'enc-decoded-preview';
        greenEl.textContent = truncate(_greenText);
        details.appendChild(greenEl);
      }

      // ── 3. PURPLE — deepest "all the way" output ──────────────────────
      // Three content modes, in priority order:
      //   (a) Deepest decoded layer's text (binary → hex → text, etc.)
      //   (b) The deepest finding's own classification / snippet
      //   (c) IOC-driven fallback: if the detector extracted any IOCs from
      //       the chain, list them here ("IOCs ARE the ultimate payload")
      //
      // Rendered whenever EITHER there's a distinct deeper layer OR the
      // finding produced IOCs. An IOC-only finding (single-layer encoding
      // that yielded a URL, etc.) still gets a purple block because the
      // IOCs themselves are what an analyst cares about seeing.
      const _hasIOCs = finding.iocs && finding.iocs.length > 0;
      const _hasDeepPath = finding.innerFindings && finding.innerFindings.length;
      if (_hasDeepPath || _hasIOCs) {
        // Reuse `_deepest` computed earlier (line ~607) instead of re-traversing.
        const deepest = _hasDeepPath ? _deepest : null;
        const distinctDeep = deepest && deepest !== finding;

        // Build separator label. Prefer a chain-aware label when we have a
        // distinct deeper layer; otherwise fall back to an IOC summary.
        let sepLabel;
        if (distinctDeep) {
          const parentLen = (finding.chain && finding.chain.length) || 0;
          const innerChain = (deepest.chain && deepest.chain.length > parentLen)
            ? deepest.chain.slice(parentLen)
            : (deepest.chain || []);
          const extraLayers = innerChain.length || 1;
          const chainStr = innerChain.length
            ? innerChain.join(' \u2192 ')
            : (deepest.encoding || 'deeper layer');
          sepLabel = `\u2193 ${extraLayers} more layer${extraLayers !== 1 ? 's' : ''} \u00b7 ${chainStr}`;
        } else if (_hasIOCs) {
          sepLabel = `\u2193 all the way \u00b7 ${finding.iocs.length} IOC${finding.iocs.length !== 1 ? 's' : ''} extracted`;
        }

        // Helper: format IOCs as one-per-line text for the purple block.
        // Deduped (type+value), capped at 20 entries / 800 chars for sanity.
        const _iocsAsText = () => {
          if (!_hasIOCs) return null;
          const seen = new Set();
          const lines = [];
          for (const ioc of finding.iocs) {
            const key = (ioc.type || '') + '\u0000' + (ioc.url || '');
            if (seen.has(key)) continue;
            seen.add(key);
            lines.push(`${ioc.type}: ${ioc.url}`);
            if (lines.length >= 20) break;
          }
          return lines.join('\n');
        };

        // Track whether we've already rendered a purple block so the async
        // retry path doesn't double up on top of a sync-rendered block.
        let purpleRendered = false;

        // Closure that appends (purple separator + preview). Idempotent;
        // safe to call from sync path AND lazyDecode handlers. Returns true
        // if a block was actually appended.
        //
        // NOTE: we deliberately DO NOT guard on `details.isConnected` — in
        // the sync path `details` is still detached (card.appendChild runs
        // further below). appendChild on a detached element is valid and
        // the node becomes connected when the card is attached to body.
        const appendPurple = () => {
          if (purpleRendered) return true;
          let text = null;
          let title = 'Final decoded output after following the entire encoding chain';

          if (distinctDeep) {
            const deepText = _extractTextPreview(deepest);
            if (deepText && deepText !== _greenText) {
              text = truncate(deepText);
            }
          }
          // Fall back to IOC list when we have no usable deeper text.
          if (!text && _hasIOCs) {
            text = _iocsAsText();
            title = 'Indicators extracted from the deepest decoded layer';
          }
          if (!text) return false;

          details.appendChild(mkSep(sepLabel, /* deep = */ true));
          const deepEl = document.createElement('div');
          deepEl.className = 'enc-deepest-preview';
          deepEl.title = title;
          deepEl.textContent = text;
          details.appendChild(deepEl);
          purpleRendered = true;
          return true;
        };

        // Last-ditch: if we still have no purple text, show the deepest
        // rawCandidate (or finding.snippet) with a note so the 3rd tier is
        // never empty when a deeper chain exists. Rendered as a plain
        // `.enc-deepest-preview` so it visually matches the successful
        // path — analyst still sees "deep something" even if we couldn't
        // decode it.
        const appendPurpleRaw = () => {
          if (purpleRendered) return true;
          let rawText = null;
          if (distinctDeep && deepest.rawCandidate) {
            rawText = truncate(String(deepest.rawCandidate));
          } else if (distinctDeep && deepest.snippet) {
            rawText = truncate(String(deepest.snippet));
          }
          if (!rawText) return false;
          details.appendChild(mkSep(sepLabel || '\u2193 deepest layer (encoded)', true));
          const deepEl = document.createElement('div');
          deepEl.className = 'enc-deepest-preview';
          deepEl.title = 'Deepest layer (still encoded — click "All the way ⏩" to decode)';
          deepEl.textContent = rawText;
          details.appendChild(deepEl);
          purpleRendered = true;
          return true;
        };

        // Try synchronous render first. If it produced nothing AND the
        // deepest node needs decoding, lazy-decode it and retry. We retry
        // appendPurple on BOTH resolve and reject so the IOC-fallback branch
        // gets a chance even when lazyDecode succeeds but yields binary.
        // If all three strategies fail, appendPurpleRaw shows the deepest
        // rawCandidate as a visual confirmation that depth exists.
        if (!appendPurple()) {
          const deepNeedsDecode = distinctDeep && deepest.rawCandidate && !deepest.decodedBytes;
          if (deepNeedsDecode) {
            const finishAsync = () => {
              if (!appendPurple()) appendPurpleRaw();
            };
            try {
              const detector = new EncodedContentDetector();
              detector.lazyDecode(deepest).then(finishAsync).catch(finishAsync);
            } catch (_) { finishAsync(); }
          } else {
            // No lazy work to do — try the raw fallback immediately.
            appendPurpleRaw();
          }
        }
      }


      // ── Decode chain — full lineage as pill hops ────────────────────
      // Always rendered (even for single-hop findings) so the Deobfuscation
      // card has a consistent visual grammar. Each hop is a coloured pill
      // that categorises the layer (encoding / compression / payload) and
      // tooltips with the per-layer size + classification harvested from
      // the innerFindings tree.
      if (_fullChain.length > 0) {
        // Classify a hop label into a palette bucket. Case-insensitive
        // substring match is fine here — every string comes from the
        // detector's own fixed label vocabulary (see encoded-content-
        // detector.js chain assignments + _classify()).
        const hopCategory = (label) => {
          const s = (label || '').toLowerCase();
          // Dangerous payloads first (overrides the generic 'text' match).
          if (/(pe executable|elf|mach-o|shellcode|powershell|vbscript|hta|wsf|jscript|shell script|deobfuscated command|javascript)/.test(s))
            return 'payload-danger';
          // Compression / archive layers.
          if (/(gzip|deflate|zlib|brotli|compressed|embedded zip|rar|7z|\bzip\b)/.test(s))
            return 'compression';
          // Benign final classifications.
          if (/^(text|utf-?8|utf-?16|xml|json|html|markdown|binary data|high-entropy binary)/.test(s))
            return 'payload-benign';
          // Default: an encoding layer (Base64, Hex, URL-encoded, etc.).
          return 'encoding';
        };

        // Walk the innerFindings tree to build a layer-index → finding map
        // so each pill can tooltip with "encoded X → decoded Y" info. The
        // outer finding occupies chain-indexes up to `finding.chain.length`;
        // each inner finding extends the chain by its own encoding hops.
        const chainNodes = new Array(_fullChain.length).fill(null);
        let walker = finding;
        while (walker) {
          const end = Math.min(walker.chain ? walker.chain.length : 0, _fullChain.length);
          for (let i = 0; i < end; i++) {
            if (!chainNodes[i]) chainNodes[i] = walker;
          }
          if (walker.innerFindings && walker.innerFindings.length) {
            // Descend into the highest-severity inner finding — matches the
            // priority `_getDeepestFinding` uses so the chain nodes line up
            // with the deepest-path we're displaying.
            const sevRank = { critical: 4, high: 3, medium: 2, info: 1 };
            walker = walker.innerFindings.reduce((a, b) =>
              (sevRank[b.severity] || 0) > (sevRank[a.severity] || 0) ? b : a
            );
          } else {
            walker = null;
          }
        }

        const chainWrap = document.createElement('div');
        chainWrap.className = 'enc-finding-chain';
        const chainLabel = document.createElement('span');
        chainLabel.className = 'enc-chain-label';
        chainLabel.textContent = 'Chain:';
        chainWrap.appendChild(chainLabel);

        // Ellipsise > 6 hops — keeps the card compact on pathological
        // multi-layer samples while preserving the full chain in a tooltip
        // on the wrapper. Show first 3 + last 2, with a "…" pill in between.
        const MAX_HOPS = 6;
        let displayHops;
        if (_fullChain.length > MAX_HOPS) {
          displayHops = [
            ..._fullChain.slice(0, 3).map((l, i) => ({ label: l, idx: i })),
            { label: '…', idx: -1, ellipsis: true },
            ..._fullChain.slice(-2).map((l, i) => ({ label: l, idx: _fullChain.length - 2 + i })),
          ];
          chainWrap.title = `Full chain:\n${_fullChain.join(' → ')}`;
        } else {
          displayHops = _fullChain.map((l, i) => ({ label: l, idx: i }));
        }

        for (let i = 0; i < displayHops.length; i++) {
          const h = displayHops[i];
          if (i > 0) {
            const arrow = document.createElement('span');
            arrow.className = 'enc-chain-arrow';
            arrow.textContent = '→';
            arrow.setAttribute('aria-hidden', 'true');
            chainWrap.appendChild(arrow);
          }
          const pill = document.createElement('span');
          pill.className = h.ellipsis
            ? 'enc-chain-hop enc-chain-hop-ellipsis'
            : `enc-chain-hop enc-chain-hop-${hopCategory(h.label)}`;
          pill.textContent = h.label;
          if (!h.ellipsis) {
            // Per-hop tooltip: pull size + classification from the
            // matching innerFindings node when available. Falls back to
            // just the label for hops we couldn't map.
            const node = chainNodes[h.idx];
            const bits = [];
            if (node) {
              if (node.decodedSize > 0) bits.push(this._fmtBytes(node.decodedSize));
              if (node.classification && node.classification.type && node.classification.type !== h.label) {
                bits.push(node.classification.type);
              }
            }
            pill.title = bits.length ? `${h.label} — ${bits.join(' · ')}` : h.label;
          } else {
            pill.title = `${_fullChain.length - 5} hops hidden`;
          }
          chainWrap.appendChild(pill);
        }
        details.appendChild(chainWrap);
      }

      // ── Consolidated metadata strip ────────────────────────────────────
      // A single dense row of pill-chips that collapses what used to be
      // three separate rows (location, size-delta, entropy) into one
      // scannable line directly under the chain.
      //
      //   [⟨ line 12 ⟩]  [⟨ 95 B → 12 KB · 128× ⟩]  [⟨ H 7.82 ⚠ ⟩]
      //
      // Chips are hidden independently when their source data is absent,
      // so an IOC-only single-layer finding still renders a compact strip.
      // Full explanatory text lives in each chip's `title` tooltip so the
      // visual line stays short without losing information.
      const _encLen = finding.length || (finding.rawCandidate ? finding.rawCandidate.length : 0);
      const _decSize = (_deepest && _deepest.decodedSize) || finding.decodedSize || 0;

      const metaStrip = document.createElement('div');
      metaStrip.className = 'enc-finding-metastrip';

      // 1. Location chip — line range for plaintext views, raw offset
      //    otherwise. When clickable, the *card* (not the chip) handles
      //    the scroll-and-flash — see the card-level click handler further
      //    below. The chip exists purely to surface the location info in
      //    the strip; we do not attach its own click handler (IOC parity).
      const locChip = document.createElement('span');
      locChip.className = 'enc-metachip enc-metachip-loc';
      if (_canLocate && finding._startLine) {
        locChip.textContent = finding._startLine === finding._endLine
          ? `line ${finding._startLine}`
          : `lines ${finding._startLine}\u2013${finding._endLine}`;
        locChip.title = `${this._fmtBytes(_encLen || 0) || 'encoded content'} starting at line ${finding._startLine}`;
      } else {
        locChip.textContent = `offset ${finding.offset.toLocaleString()}`;
        locChip.title = `Encoded content at byte offset ${finding.offset.toLocaleString()} (no line mapping available for this view)`;
      }
      metaStrip.appendChild(locChip);

      // 2. Size-delta chip — encoded → decoded with expansion ratio.
      //    Colour-tinted via `.enc-sizedelta-expand` / `.enc-sizedelta-shrink`
      //    when the ratio is notable (≥ 5× or < 0.8×).
      if (_encLen > 0 && _decSize > 0) {
        const sizeChip = document.createElement('span');
        sizeChip.className = 'enc-metachip enc-metachip-size';
        const ratio = _decSize / _encLen;
        const ratioStr = ratio >= 10 ? ratio.toFixed(0) + '×'
          : ratio >= 1 ? ratio.toFixed(1) + '×'
          : (1 / ratio).toFixed(1) + '× shrink';
        sizeChip.textContent = `${this._fmtBytes(_encLen)} → ${this._fmtBytes(_decSize)} · ${ratioStr}`;
        sizeChip.title = `Encoded source was ${this._fmtBytes(_encLen)}; decoded output is ${this._fmtBytes(_decSize)} (ratio ${ratioStr})`;
        if (ratio >= 5) sizeChip.classList.add('enc-sizedelta-expand');
        else if (ratio < 0.8) sizeChip.classList.add('enc-sizedelta-shrink');
        metaStrip.appendChild(sizeChip);
      }

      // 3. Entropy chip — compact "H 7.82" form so the chip stays short.
      //    Tint orange when > 7.5 (encrypted / packed territory); the
      //    explanatory text ("high (encrypted/packed?)") lives in the
      //    tooltip, preserving the old row's information at a smaller
      //    visual footprint.
      if (finding.entropy > 0) {
        const entChip = document.createElement('span');
        entChip.className = 'enc-metachip enc-metachip-entropy';
        const entVal = finding.entropy.toFixed(2);
        let entTip = `Shannon entropy: ${entVal} / 8.00`;
        if (finding.entropy > 7.5) {
          entChip.textContent = `H ${entVal} ⚠`;
          entChip.classList.add('enc-metachip-entropy-high');
          entTip += ' — very high, likely encrypted, packed, or already-compressed data';
        } else if (finding.entropy > 6.5) {
          entChip.textContent = `H ${entVal}`;
          entTip += ' — high, compatible with compressed or encoded content';
        } else if (finding.entropy < 1.5) {
          entChip.textContent = `H ${entVal}`;
          entChip.classList.add('enc-metachip-entropy-low');
          entTip += ' — very low, likely sparse or padding';
        } else {
          entChip.textContent = `H ${entVal}`;
        }
        entChip.title = entTip;
        metaStrip.appendChild(entChip);
      }

      if (metaStrip.children.length) details.appendChild(metaStrip);


      // IOCs found in decoded content — clickable to flash IOC rows
      if (finding.iocs && finding.iocs.length) {
        const iocLine = document.createElement('div');
        iocLine.className = 'enc-finding-iocs';
        iocLine.setAttribute('data-clickable', '');
        const counts = {};
        for (const ioc of finding.iocs) counts[ioc.type] = (counts[ioc.type] || 0) + 1;
        iocLine.textContent = 'IOCs: ' + Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', ');
        iocLine.title = 'Click to highlight related IOC rows';
        iocLine.addEventListener('click', (e) => {
          e.stopPropagation();
          this._flashIocRows(finding);
        });
        details.appendChild(iocLine);
      }

      // Note (e.g., depth exceeded)
      if (finding.note) {
        const note = document.createElement('div');
        note.className = 'enc-finding-note';
        note.textContent = `⚠ ${finding.note}`;
        details.appendChild(note);
      }

      card.appendChild(details);

      // Action buttons row
      const actions = document.createElement('div');
      actions.className = 'enc-finding-actions';

      // Combined "Decode & Analyse" button for lazy candidates, or "Load for analysis" if already decoded
      if (!finding.autoDecoded && finding.rawCandidate && !finding.decodedBytes) {
        // Needs decoding first, then load
        const decodeLoadBtn = document.createElement('button');
        decodeLoadBtn.className = 'tb-btn enc-btn-load';
        decodeLoadBtn.textContent = '▶ Decode & Analyse';
        decodeLoadBtn.title = 'Decode and open in the analysis pipeline';
        decodeLoadBtn.addEventListener('click', async () => {
          decodeLoadBtn.disabled = true;
          decodeLoadBtn.textContent = '⏳ Decoding…';
          try {
            const detector = new EncodedContentDetector();
            await detector.lazyDecode(finding);
            this._updateRiskFromEncodedContent();
            if (finding.decodedBytes) {
              const ext = finding.ext || '.bin';
              const synName = `decoded_${finding.encoding.toLowerCase().replace(/[^a-z0-9]/g, '_')}_offset${finding.offset}${ext}`;
              this._drillDownToSynthetic(finding.decodedBytes, synName, 'application/octet-stream', fileName, finding.offset);
            } else {
              this._toast('Decoded but no bytes produced', 'error');
              decodeLoadBtn.disabled = false;
              decodeLoadBtn.textContent = '▶ Decode & Analyse';
            }

          } catch (err) {
            this._toast('Decode failed: ' + err.message, 'error');
            decodeLoadBtn.disabled = false;
            decodeLoadBtn.textContent = '▶ Decode & Analyse';
          }
        });
        actions.appendChild(decodeLoadBtn);
      } else if (finding.decodedBytes) {
        // Already decoded — load directly
        const loadBtn = document.createElement('button');
        loadBtn.className = 'tb-btn enc-btn-load';
        loadBtn.textContent = '▶ Load for analysis';
        loadBtn.title = 'Open decoded content in the analysis pipeline';
        loadBtn.addEventListener('click', () => {
          const ext = finding.ext || '.bin';
          const synName = `decoded_${finding.encoding.toLowerCase().replace(/[^a-z0-9]/g, '_')}_offset${finding.offset}${ext}`;
          this._drillDownToSynthetic(finding.decodedBytes, synName, 'application/octet-stream', fileName, finding.offset);
        });
        actions.appendChild(loadBtn);

      }

      // "Load for analysis" for embedded ZIP (extract from raw bytes)
      if (finding.embeddedZipOffset !== undefined && !finding.decodedBytes) {
        const loadZipBtn = document.createElement('button');
        loadZipBtn.className = 'tb-btn enc-btn-load';
        loadZipBtn.textContent = '▶ Load embedded ZIP';
        loadZipBtn.title = 'Extract and open the embedded ZIP archive';
        loadZipBtn.addEventListener('click', () => {
          const rawBytes = new Uint8Array(this.currentResult.buffer);
          const zipBytes = rawBytes.subarray(finding.embeddedZipOffset);
          this._drillDownToSynthetic(zipBytes, `embedded_zip_offset${finding.offset}.zip`, 'application/zip', fileName, finding.offset);
        });
        actions.appendChild(loadZipBtn);

      }

      // "Decompress & Analyse" for compressed blobs that weren't eagerly decompressed
      if (finding.needsDecompression && !finding.decodedBytes) {
        const decompBtn = document.createElement('button');
        decompBtn.className = 'tb-btn enc-btn-load';
        decompBtn.textContent = '▶ Decompress & Analyse';
        decompBtn.title = 'Attempt decompression and open in the analysis pipeline';
        decompBtn.addEventListener('click', async () => {
          decompBtn.disabled = true;
          decompBtn.textContent = '⏳ Decompressing…';
          try {
            const detector = new EncodedContentDetector();
            await detector.lazyDecode(finding);
            this._updateRiskFromEncodedContent();
            if (finding.decodedBytes) {
              const ext = finding.ext || '.bin';
              const synName = `decompressed_${finding.encoding.toLowerCase().replace(/[^a-z0-9]/g, '_')}_offset${finding.offset}${ext}`;
              this._drillDownToSynthetic(finding.decodedBytes, synName, 'application/octet-stream', fileName, finding.offset);

            } else {
              this._toast('Decompression failed — data may be corrupt or truncated', 'error');
              decompBtn.disabled = false;
              decompBtn.textContent = '▶ Decompress & Analyse';
            }
          } catch (err) {
            this._toast('Decompression failed: ' + err.message, 'error');
            decompBtn.disabled = false;
            decompBtn.textContent = '▶ Decompress & Analyse';
          }
        });
        actions.appendChild(decompBtn);
      }

      // "All the way" — deep decode to innermost layer (for multi-layer encoding)
      if (finding.innerFindings && finding.innerFindings.length > 0) {
        const deepest = this._getDeepestFinding(finding);
        if (deepest && deepest !== finding && (deepest.decodedBytes || deepest.rawCandidate)) {
          const atwBtn = document.createElement('button');
          // Primary action for multi-layer findings — "All the way" is
          // almost always what the analyst wants when a deobfuscation chain
          // exists. The `enc-btn-primary` modifier makes it visually
          // dominate over the sibling "Decode & Analyse" / "Load for
          // analysis" buttons so the happy path is obvious at a glance.
          atwBtn.className = 'tb-btn enc-btn-alltheway enc-btn-primary';
          atwBtn.textContent = 'All the way ⏩';
          atwBtn.title = 'Follow encoding chain to deepest decoded content (recommended)';
          atwBtn.addEventListener('click', async () => {
            atwBtn.disabled = true;
            atwBtn.textContent = '⏳ Decoding…';
            try {
              // Lazy decode the deepest finding if needed
              if (!deepest.decodedBytes && deepest.rawCandidate) {
                const detector = new EncodedContentDetector();
                await detector.lazyDecode(deepest);
              }
              if (deepest.decodedBytes) {
                const ext = deepest.ext || '.bin';
                const chainLabel = deepest.chain ? deepest.chain.join('_').replace(/[^a-z0-9_]/gi, '') : 'deep';
                const synName = `deep_decoded_${chainLabel}_offset${finding.offset}${ext}`;
                this._drillDownToSynthetic(deepest.decodedBytes, synName, 'application/octet-stream', fileName, finding.offset);

              } else {
                this._toast('Deep decode produced no bytes', 'error');
                atwBtn.disabled = false;
                atwBtn.textContent = 'All the way ⏩';
              }
            } catch (err) {
              this._toast('Deep decode failed: ' + err.message, 'error');
              atwBtn.disabled = false;
              atwBtn.textContent = 'All the way ⏩';
            }
          });
          actions.appendChild(atwBtn);
        }
      }

      if (actions.children.length > 0) card.appendChild(actions);

      // Nested-layer info previously rendered as a <details> dropdown is now
      // covered by the 3-tier preview stack above (grey → green → purple,
      // with labelled dividers showing the chain). No separate dropdown.

      // ── Card-level locate affordance (IOC parity) ─────────────────────
      // Hover gives a soft "peek" highlight (no scroll); click does a hard
      // scroll-and-flash of the encoded region in the view pane. This
      // replaces the old inline 🔍 button — the entire card is now the
      // click target, matching the IOC row behaviour one section up.
      //
      // Guards:
      //   • Buttons in `.enc-finding-actions` stop propagation themselves
      //     (they navigate / decode, not locate).
      //   • The `.enc-finding-iocs` chip stops propagation too — clicking
      //     it flashes the linked IOC rows instead of locating in source.
      //   • Keyboard parity via tabindex + Enter / Space.
      if (_canLocate) {
        card.setAttribute('data-locatable', '');
        card.setAttribute('tabindex', '0');
        card.setAttribute('role', 'button');
        card.title = 'Click to locate in source · hover to preview';
        card.addEventListener('mouseenter', () => this._highlightEncodedInView(finding, false));
        card.addEventListener('mouseleave', () => this._clearEncodedHighlight());
        card.addEventListener('click', (e) => {
          // Don't hijack clicks on interactive descendants (buttons in
          // `.enc-finding-actions`, the IOCs chip, copy icons, etc.).
          // Those handlers either stopPropagation themselves or live on
          // <button>s that we skip explicitly here.
          const t = e.target;
          if (t && (t.closest('button') ||
                    t.closest('.enc-finding-actions') ||
                    t.closest('.enc-finding-iocs'))) return;
          this._highlightEncodedInView(finding, /* flash = */ true);
        });
        card.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            this._highlightEncodedInView(finding, /* flash = */ true);
          }
        });
      }

      body.appendChild(card);

      cardElements.push({ el: card, severity: finding.severity });
    }

    // ── Encoded content severity filter function ──────────────────────────
    const applyEncFilters = () => {
      let visibleCount = 0;
      for (const { el, severity } of cardElements) {
        const visible = activeSeverities.size === 0 || activeSeverities.has(severity);
        el.classList.toggle('hidden', !visible);
        if (visible) visibleCount++;
      }

      // Update severity bar counts based on visible items
      for (const [sev, el] of sevFilterElements) {
        const count = cardElements.filter(c => c.severity === sev).length;
        if (count > 0) {
          el.style.display = '';
          el.textContent = `${sevConfig[sev].icon} ${count} ${sev}`;
        } else {
          el.style.display = 'none';
        }
      }

      // Update summary count
      if (activeSeverities.size > 0) {
        sum.textContent = `🧅 Deobfuscation (${visibleCount}/${encodedFindings.length})`;
      } else {
        sum.textContent = `🧅 Deobfuscation (${encodedFindings.length})`;
      }
    };

    det.appendChild(body);
    container.appendChild(det);
  },

  // ── Generic findings table section (used for Detections + IOCs) ────────
  _renderFindingsTableSection(container, refs, fileName, sectionEmoji, sectionTitle, emptyMessage) {
    const det = document.createElement('details');
    det.className = 'sb-details';
    // Section key for manual collapse-state preservation across nav
    // round-trips (Detections / IOCs). Must match the keys used by
    // `_snapshotSectionOpenState` in app-load.js and `_resolveSectionOpen`.
    const _sbKey = sectionTitle === 'Detections' ? 'detections' : 'iocs';
    det.dataset.sbSection = _sbKey;
    det.open = this._resolveSectionOpen(_sbKey, refs.length > 0);


    const sum = document.createElement('summary');
    sum.className = 'sb-details-summary';
    sum.textContent = refs.length
      ? `${sectionEmoji} ${sectionTitle} (${refs.length})`
      : `${sectionEmoji} ${sectionTitle}`;
    det.appendChild(sum);

    const body = document.createElement('div');
    body.className = 'sb-details-body';

    // ── IOC extraction truncation note ──────────────────────────────────
    // `_extractInterestingStrings` (app-load.js) enforces a per-type quota
    // (PER_TYPE_CAP). When any type was capped, it stashes a drop map on
    // `findings._iocTruncation` so the user sees "Showing N of M Email"
    // rather than silently losing IOCs — the original symptom that made
    // a 1000-row CSV of emails produce zero Email IOCs because 1000 URLs
    // filled the old global 300-entry cap first. Rendered IOCs-section
    // only, and only for IOC types (Detections use a separate pipeline
    // that doesn't go through the quota).
    const _iocTruncation = this.findings && this.findings._iocTruncation;
    if (sectionTitle === 'IOCs' && _iocTruncation && _iocTruncation.droppedByType && _iocTruncation.droppedByType.size > 0) {
      const note = document.createElement('div');
      note.className = 'ioc-truncation-note';
      note.style.cssText = 'color:#856404;background:#fff3cd;border:1px solid #ffeeba;padding:6px 8px;margin:8px 0;font-size:11px;border-radius:3px;line-height:1.4;';
      const parts = [];
      for (const [type, dropped] of _iocTruncation.droppedByType.entries()) {
        const total = _iocTruncation.totalSeenByType.get(type) || 0;
        const shown = total - dropped;
        parts.push(`${shown.toLocaleString()} of ${total.toLocaleString()} ${type}`);
      }
      note.textContent = '⚠ IOC extraction truncated — showing ' + parts.join('; ') + '. Per-type cap reached.';
      note.title = 'Large files may contain more IOCs of a given type than Loupe retains in the sidebar. The per-type cap keeps the UI responsive and ensures every IOC class has representation. Use YARA rules or exports to scan the full raw source.';
      body.appendChild(note);
    }

    if (!refs.length) {
      const p = document.createElement('p');
      p.style.cssText = 'color:#888;text-align:center;margin-top:12px;font-size:12px;';
      p.textContent = emptyMessage;
      body.appendChild(p);
      det.appendChild(body);
      container.appendChild(det);
      return;
    }

    // ── Nicelist: mark benign global-infrastructure IOCs so they sort to
    //    the bottom of the table and can be hidden via toggle. Applied only
    //    to the IOCs section (never to Detections — a YARA hit that names a
    //    nicelisted host is still authoritative). Two sources:
    //      • `isNicelisted` (src/nicelist.js) — the built-in "Default
    //        Nicelist" of global infrastructure.
    //      • `_NicelistUser.match` (src/nicelist-user.js) — user-defined
    //        custom lists managed from Settings → Nicelists.
    //    Both load before this file per JS_FILES order. When a row matches
    //    a user list we stash the list's display name on `_nicelistSource`
    //    so the bar tooltip can break down the hit-count by source.
    const isIocSection = _sbKey === 'iocs';
    const _hasUserNicelists = typeof _NicelistUser !== 'undefined' && _NicelistUser && typeof _NicelistUser.match === 'function';
    if (isIocSection) {
      for (const r of refs) {
        let source = null;
        if (typeof isNicelisted === 'function' && isNicelisted(r.url, r.type)) {
          source = 'Default Nicelist';
        } else if (_hasUserNicelists) {
          const userHit = _NicelistUser.match(r.url, r.type);
          if (userHit) source = userHit;
        }
        if (source) {
          r._nicelisted = true;
          r._nicelistSource = source;
        } else {
          r._nicelisted = false;
          r._nicelistSource = null;
        }
      }
    }
    const niceCount = isIocSection ? refs.filter(r => r._nicelisted).length : 0;


    // Sort by: nicelisted (false first) → severity (critical → info).
    // Nicelisted rows land at the end regardless of severity so an info-
    // tier benign CDN URL never sits above a medium-tier genuine IOC.
    refs.sort((a, b) => {
      const an = a._nicelisted ? 1 : 0;
      const bn = b._nicelisted ? 1 : 0;
      if (an !== bn) return an - bn;
      return (_SIDEBAR_SEV_ORDER[a.severity] ?? 9) - (_SIDEBAR_SEV_ORDER[b.severity] ?? 9);
    });

    // ── Filter state ─────────────────────────────────────────────────────
    const activeSeverities = new Set();
    const activeTypes = new Set();
    // Nicelist hide toggle — IOCs section only. Persisted to
    // localStorage['loupe_ioc_hide_nicelisted'].
    let hideNicelisted = isIocSection && this._getHideNicelisted();

    // ── Severity config ──────────────────────────────────────────────────
    const sevConfig = {
      critical: { icon: '🟣', color: '#4a1a7a' },
      high:     { icon: '🔴', color: '#721c24' },
      medium:   { icon: '🟡', color: '#856404' },
      info:     { icon: '🔵', color: '#666' },
    };

    // ── Store references to filter elements ──────────────────────────────
    const sevFilterElements = new Map();  // severity -> element
    const typeFilterElements = new Map(); // type -> element

    // ── Severity filter bar (clickable) ──────────────────────────────────
    const sevBar = document.createElement('div'); sevBar.className = 'sev-bar';

    for (const sev of ['critical', 'high', 'medium', 'info']) {
      const count = refs.filter(r => r.severity === sev).length;
      if (!count) continue;

      const { icon, color } = sevConfig[sev];
      const s = document.createElement('span');
      s.className = 'sev-filter';
      s.dataset.severity = sev;
      s.style.color = color;
      s.textContent = `${icon} ${count} ${sev}`;
      s.title = `Click to filter by ${sev} severity`;
      s.addEventListener('click', () => {
        if (activeSeverities.has(sev)) {
          activeSeverities.delete(sev);
          s.classList.remove('sev-filter-active');
        } else {
          activeSeverities.add(sev);
          s.classList.add('sev-filter-active');
        }
        applyFilters();
      });
      sevBar.appendChild(s);
      sevFilterElements.set(sev, s);
    }
    body.appendChild(sevBar);

    // ── Type filter bar (clickable pills with type-specific colors) ──────
    const typeCounts = {};
    for (const r of refs) {
      typeCounts[r.type] = (typeCounts[r.type] || 0) + 1;
    }
    // Sort types by count descending, then alphabetically
    const sortedTypes = Object.entries(typeCounts)
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));

    const typeBar = document.createElement('div'); typeBar.className = 'type-bar';
    for (const [type, count] of sortedTypes) {
      const typeKey = type.toLowerCase().replace(/\s+/g, '-');
      const pill = document.createElement('span');
      pill.className = `type-filter type-filter-${typeKey}`;
      pill.dataset.type = type;
      pill.textContent = `${type} (${count})`;
      pill.title = `Click to filter by ${type}`;
      pill.addEventListener('click', () => {
        if (activeTypes.has(type)) {
          activeTypes.delete(type);
          pill.classList.remove('type-filter-active');
        } else {
          activeTypes.add(type);
          pill.classList.add('type-filter-active');
        }
        applyFilters();
      });
      typeBar.appendChild(pill);
      typeFilterElements.set(type, pill);
    }
    body.appendChild(typeBar);

    // ── Nicelist toggle (IOCs section only, shown only if any row is flagged)
    //    Two-state switch: "Show dimmed at bottom" (default) vs. "Hide".
    //    The Show state sorts nicelisted rows below a dashed divider and
    //    fades them to ~50% opacity; Hide removes them from the table
    //    entirely until toggled back on. State is persisted across loads
    //    via localStorage['loupe_ioc_hide_nicelisted'].
    let niceToggleBtn = null;
    if (isIocSection && niceCount > 0) {
      const niceBar = document.createElement('div');
      niceBar.className = 'nice-bar';
      const niceLbl = document.createElement('span');
      niceLbl.className = 'nice-bar-label';
      // Always show the total count in the visible label — the per-source
      // breakdown lives in the hover tooltip so the bar stays compact and
      // predictable regardless of how many user lists are active.
      niceLbl.textContent = `🌐 Nicelisted: ${niceCount}`;
      const bySource = new Map();
      for (const r of refs) {
        if (!r._nicelisted) continue;
        const key = r._nicelistSource || 'Default Nicelist';
        bySource.set(key, (bySource.get(key) || 0) + 1);
      }
      const sources = [...bySource.entries()].sort((a, b) => b[1] - a[1]);
      const breakdown = sources.map(([k, v]) => `${v} from ${k}`).join(', ');
      niceLbl.title = 'Rows matched by an active nicelist (sorted to the bottom of the IOCs table, never affects Detections). Breakdown: ' +
        breakdown + '. Manage custom nicelists from Settings → Nicelists (press N).';
      niceBar.appendChild(niceLbl);


      niceToggleBtn = document.createElement('button');
      niceToggleBtn.type = 'button';
      niceToggleBtn.className = 'nice-toggle';
      const syncToggle = () => {
        if (hideNicelisted) {
          niceToggleBtn.textContent = '👁 Show';
          niceToggleBtn.classList.add('nice-toggle-hiding');
          niceToggleBtn.title = 'Nicelisted rows hidden — click to show them (dimmed, at bottom).';
        } else {
          niceToggleBtn.textContent = '🙈 Hide';
          niceToggleBtn.classList.remove('nice-toggle-hiding');
          niceToggleBtn.title = 'Nicelisted rows shown (dimmed, at bottom) — click to hide them.';
        }
      };
      syncToggle();
      niceToggleBtn.addEventListener('click', () => {
        hideNicelisted = !hideNicelisted;
        this._setHideNicelisted(hideNicelisted);
        syncToggle();
        applyFilters();
      });
      niceBar.appendChild(niceToggleBtn);
      body.appendChild(niceBar);
    }

    // ── Text search input ────────────────────────────────────────────────
    const srch = document.createElement('input');
    srch.type = 'text'; srch.placeholder = 'Filter findings…'; srch.className = 'ext-search';
    body.appendChild(srch);

    // ── Table ────────────────────────────────────────────────────────────
    const tbl = document.createElement('table'); tbl.className = 'ext-table';
    const thead = document.createElement('thead');
    const htr = document.createElement('tr');
    for (const h of ['Type', 'Value', 'Risk']) {
      const th = document.createElement('th'); th.textContent = h; htr.appendChild(th);
    }
    thead.appendChild(htr); tbl.appendChild(thead);

    const tbody = document.createElement('tbody');
    for (const ref of refs) {
      const tr = document.createElement('tr');
      tr.className = 'ioc-clickable';
      tr.dataset.search = (ref.type + ' ' + (ref.url || '')).toLowerCase();
      tr.dataset.severity = ref.severity;
      tr.dataset.type = ref.type;
      // Nicelist: tag row so CSS can dim it + dashed-divider it from the
      // first non-nicelisted row, and `applyFilters()` can hide it when
      // `hideNicelisted` is on. Only set on IOC rows (the `_nicelisted`
      // flag is never populated for the Detections section).
      if (ref._nicelisted) {
        tr.classList.add('ioc-nicelisted');
        tr.dataset.nicelisted = '1';
      }

      const td1 = document.createElement('td'); td1.textContent = ref.type;
      td1.className = 'ioc-type ioc-type-' + ref.type.toLowerCase().replace(/\s+/g, '-');
      const td2 = document.createElement('td'); td2.className = 'ext-val';
      if (ref._yaraRuleName) {
        // ── YARA match: structured, scannable layout ────────────────
        //   • Title row: bold humanised rule name + always-visible ➕/➖
        //     expand-toggle and 📐 "view rule" button (once per rule,
        //     never hidden).
        //   • Description (when present) on its own muted line.
        //   • Per-string breakdown as a compact list — each row shows
        //     just the matched value (+ hit count), keeping columns
        //     aligned regardless of `$var` length. Clicking the ➕
        //     toggle reveals the "reason for detection" sub-rows for
        //     every match at once (the `$var` chip and the rule's
        //     condition with matched identifiers bolded); clicking ➖
        //     collapses them again.
        // Falls back gracefully when `_yaraStrings` is absent (older
        // findings) by just showing the rule name.
        const titleRow = document.createElement('div');
        titleRow.className = 'yara-sidebar-title';

        const strong = document.createElement('strong');
        strong.textContent = ref._yaraRuleName.replace(/_/g, ' ');
        titleRow.appendChild(strong);

        // Colour-coded category pill — sits inline with the rule name,
        // immediately left of the ➕ / 📐 buttons. Clicking opens a modal
        // with a plain-English explanation of the category (MITRE tactic
        // mapping, typical indicators) so an analyst who doesn't know the
        // bucket by heart can learn it without leaving the sidebar. The
        // palette lives in core.css alongside the Detections / IOCs
        // type-filter classes so it can't drift.
        if (ref._yaraCategory) {
          // Match the key normalisation used by the YARA dialog so a rule
          // tagged `credential_theft` or `MSIX / APPX` lands on the same
          // palette entry in both surfaces.
          const catKey = ref._yaraCategory.toLowerCase()
            .replace(/[^a-z0-9]+/g, '-')
            .replace(/^-+|-+$/g, '');
          const catPill = document.createElement('span');
          // Note: no `.type-filter` class — its generic colour rules would
          // override the `.yara-cat-pill-<key>` tints (see CONTRIBUTING's
          // "Category pill colouring" note).
          catPill.className = 'yara-cat-pill yara-cat-pill-' +
            catKey + ' yara-sidebar-cat';
          catPill.textContent = ref._yaraCategory;
          catPill.title = 'YARA category: ' + ref._yaraCategory +
            ' \u2014 click to learn what this means';
          catPill.addEventListener('click', (e) => {
            e.stopPropagation();
            this._openYaraCategoryInfo(ref._yaraCategory);
          });
          titleRow.appendChild(catPill);
        }

        // "Toggle match details" button - always visible when there are
        // per-string matches to reveal. Sticky click-driven replacement
        // for the old hover-reveal, so expanded reason rows can be read
        // (and copied from) without the mouse hovering the card.
        let toggleBtn = null;
        if (ref._yaraStrings && ref._yaraStrings.length) {
          toggleBtn = document.createElement('button');
          toggleBtn.className = 'yara-toggle-reasons-btn';
          toggleBtn.textContent = '\u2795'; // ➕
          toggleBtn.title = 'Show match details';
          toggleBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const expanded = td2.classList.toggle('yara-expanded');
            toggleBtn.textContent = expanded ? '\u2796' : '\u2795'; // ➖ / ➕
            toggleBtn.title = expanded ? 'Hide match details' : 'Show match details';
          });
          titleRow.appendChild(toggleBtn);
        }

        // "View YARA rule" button - always visible, once per rule.
        // Opens the rule viewer filtered to this rule.
        const titleViewBtn = document.createElement('button');
        titleViewBtn.className = 'yara-view-rule-btn';
        titleViewBtn.textContent = '\u{1F4D0}';
        titleViewBtn.title = 'View YARA rule';
        titleViewBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          this._openYaraDialog(ref._yaraRuleName);
        });
        titleRow.appendChild(titleViewBtn);

        td2.appendChild(titleRow);

        // Description line (from rule meta.description)
        if (ref.description) {
          const descEl = document.createElement('div');
          descEl.className = 'yara-sidebar-desc';
          descEl.textContent = ref.description;
          td2.appendChild(descEl);
        }

        // Per-string breakdown
        const ys = ref._yaraStrings;
        if (ys && ys.length) {
          // Pre-render the rule's condition expression once: escape + bold
          // matched $vars, dim unmatched ones. Shared with the YARA dialog
          // via `_yaraBoldCond` so the two surfaces can't drift.
          const matchedIdSet = new Set(ys.map(s => s.id.toLowerCase()));
          const condHtml = (typeof this._yaraBoldCond === 'function')
            ? this._yaraBoldCond(ref._yaraCondition, matchedIdSet)
            : null;

          const list = document.createElement('ul');
          list.className = 'yara-sidebar-strings';
          const MAX_SHOWN = 6;
          const shown = ys.slice(0, MAX_SHOWN);
          for (const s of shown) {
            const li = document.createElement('li');
            // Preserve the rule's variable name as a native tooltip so it
            // remains recoverable without cluttering column alignment.
            li.title = s.id;

            const val = document.createElement('span');
            val.className = 'yara-sidebar-val';
            val.textContent = s.value;
            li.appendChild(val);

            if (s.hits && s.hits > 1) {
              const hits = document.createElement('span');
              hits.className = 'yara-sidebar-hits';
              hits.textContent = s.hits + '\u00D7';
              li.appendChild(hits);
            }

            // ── Hover-revealed "reason for detection" sub-row ────────
            //   [$id] → <rule condition with matched $vars bolded> [📐]
            // For trivial conditions (any/all/N of them) we fall back to
            // "$id · matched" so the $var stays recoverable on hover.
            const reason = document.createElement('div');
            reason.className = 'yara-sidebar-reason';

            const idChip = document.createElement('code');
            idChip.className = 'yara-sidebar-sid';
            idChip.textContent = s.id;
            reason.appendChild(idChip);

            const sep = document.createElement('span');
            sep.className = 'yara-sidebar-sep';
            sep.textContent = condHtml ? '\u2192' : '\u00b7';
            reason.appendChild(sep);

            if (condHtml) {
              const condSpan = document.createElement('span');
              condSpan.className = 'yara-sidebar-cond';
              condSpan.innerHTML = condHtml;
              reason.appendChild(condSpan);
            } else {
              const em = document.createElement('em');
              em.textContent = 'matched';
              reason.appendChild(em);
            }

            li.appendChild(reason);
            list.appendChild(li);
          }
          if (ys.length > MAX_SHOWN) {
            const more = document.createElement('li');
            more.className = 'yara-sidebar-more';
            more.textContent = '\u2026 +' + (ys.length - MAX_SHOWN) + ' more';
            list.appendChild(more);
          }
          td2.appendChild(list);
        } else if (ref.url) {
          // Legacy fallback when `_yaraStrings` isn't populated.
          const rest = document.createElement('div');
          rest.className = 'yara-sidebar-desc';
          rest.textContent = ref.url;
          td2.appendChild(rest);
        }
      } else {

        const sp = document.createElement('span'); sp.textContent = ref.url || ''; td2.appendChild(sp);
      }
      // Show decode chain note for IOCs extracted from encoded/obfuscated layers
      if (ref._decodedFrom) {
        const noteEl = document.createElement('div');
        noteEl.className = 'ioc-decoded-from';
        noteEl.textContent = '↳ Decoded from: ' + ref._decodedFrom;
        if (ref._encodedFinding && ref._encodedFinding._cardEl) {
          noteEl.style.cursor = 'pointer';
          noteEl.title = 'Click to locate parent encoded content finding';
          noteEl.addEventListener('click', (e) => {
            e.stopPropagation();
            this._flashEncodedCard(ref._encodedFinding);
          });
        }
        td2.appendChild(noteEl);
      } else if (ref.note) {
        const noteEl = document.createElement('div');
        noteEl.className = 'ioc-decoded-from';
        noteEl.textContent = '↳ ' + ref.note;
        td2.appendChild(noteEl);
      }
      if (IOC_COPYABLE.has(ref.type) && ref.url) {
        const cb = document.createElement('button'); cb.className = 'copy-url-btn';
        cb.textContent = '📋'; cb.title = 'Copy';
        let copyVal = ref.url;
        const hm = copyVal.match(/^(?:SHA256|SHA1|MD5|IMPHASH|SHA384|SHA512):(.+)$/i);
        if (hm) copyVal = hm[1];
        cb.addEventListener('click', (e) => { e.stopPropagation(); this._copyToClipboard(copyVal); });
        td2.appendChild(cb);
      }
      const td3 = document.createElement('td');
      const badge = document.createElement('span');
      badge.className = `badge badge-${ref.severity}`; badge.textContent = ref.severity;
      td3.appendChild(badge);
      tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3);

      // Click-to-navigate: apply filter in EVTX view or scroll to match in content
      tr.addEventListener('click', () => this._navigateToFinding(ref, tr));

      // Register IOC row back to parent encoded finding for cross-flash.
      // Lazy-init _iocRows here because the IOCs table is rendered BEFORE
      // the Deobfuscation section (see _renderSidebar ordering) — otherwise
      // rows registered here would be dropped and "IOCs: N URL" clicks on a
      // Deobfuscation card would silently do nothing on first render.
      if (ref._encodedFinding) {
        (ref._encodedFinding._iocRows ||= []).push(tr);
      }

      tbody.appendChild(tr);
    }
    tbl.appendChild(tbody); body.appendChild(tbl);

    // ── Unified filter function with dynamic cross-filtering ─────────────
    const applyFilters = () => {
      const q = srch.value.toLowerCase();

      // Step 1: Find all rows matching text search
      const textMatchingRows = [];
      for (const tr of tbody.rows) {
        if (!q || tr.dataset.search.includes(q)) {
          textMatchingRows.push(tr);
        }
      }

      // Step 2: Compute available severities (considering active type filters)
      // These are severities that would show results if selected
      const availableSevCounts = {};
      for (const tr of textMatchingRows) {
        if (activeTypes.size === 0 || activeTypes.has(tr.dataset.type)) {
          const sev = tr.dataset.severity;
          availableSevCounts[sev] = (availableSevCounts[sev] || 0) + 1;
        }
      }

      // Step 3: Compute available types (considering active severity filters)
      const availableTypeCounts = {};
      for (const tr of textMatchingRows) {
        if (activeSeverities.size === 0 || activeSeverities.has(tr.dataset.severity)) {
          const t = tr.dataset.type;
          availableTypeCounts[t] = (availableTypeCounts[t] || 0) + 1;
        }
      }

      // Step 4: Update severity bar - show/hide and update counts
      for (const [sev, el] of sevFilterElements) {
        const count = availableSevCounts[sev] || 0;
        if (count > 0) {
          el.style.display = '';
          el.textContent = `${sevConfig[sev].icon} ${count} ${sev}`;
        } else {
          el.style.display = 'none';
          // Auto-deselect if it was active but now has no matches
          if (activeSeverities.has(sev)) {
            activeSeverities.delete(sev);
            el.classList.remove('sev-filter-active');
          }
        }
      }

      // Step 5: Update type bar - show/hide and update counts
      for (const [type, el] of typeFilterElements) {
        const count = availableTypeCounts[type] || 0;
        if (count > 0) {
          el.style.display = '';
          el.textContent = `${type} (${count})`;
        } else {
          el.style.display = 'none';
          // Auto-deselect if it was active but now has no matches
          if (activeTypes.has(type)) {
            activeTypes.delete(type);
            el.classList.remove('type-filter-active');
          }
        }
      }

      // Step 6: Filter table rows using all four filters (text, severity,
      // type, and nicelist-hide). Nicelisted rows are sorted to the bottom
      // already; this just drops them from the DOM when the user clicks
      // the "🙈 Hide" toggle.
      let visibleCount = 0;
      for (const tr of tbody.rows) {
        const matchesText = !q || tr.dataset.search.includes(q);
        const matchesSev = activeSeverities.size === 0 || activeSeverities.has(tr.dataset.severity);
        const matchesType = activeTypes.size === 0 || activeTypes.has(tr.dataset.type);
        const matchesNice = !hideNicelisted || !tr.dataset.nicelisted;

        const visible = matchesText && matchesSev && matchesType && matchesNice;
        tr.classList.toggle('hidden', !visible);
        if (visible) visibleCount++;
      }

      // Update summary count if filters are active
      const hasActiveFilters = activeSeverities.size > 0 || activeTypes.size > 0 || q;
      if (hasActiveFilters) {
        sum.textContent = `${sectionEmoji} ${sectionTitle} (${visibleCount}/${refs.length})`;
      } else {
        sum.textContent = `${sectionEmoji} ${sectionTitle} (${refs.length})`;
      }
    };

    // ── Initial filter pass ──────────────────────────────────────────────
    // Applies the persisted `hideNicelisted` state to the freshly-rendered
    // table. Without this, reloading the page with "Hide" active would
    // leave the button labelled "Show" (correctly reflecting state) but
    // the nicelisted rows would still be visible because `applyFilters`
    // had never run.
    applyFilters();

    // ── Event listeners ──────────────────────────────────────────────────
    srch.addEventListener('input', applyFilters);

    det.appendChild(body);
    container.appendChild(det);
  },

});
