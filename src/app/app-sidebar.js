// ════════════════════════════════════════════════════════════════════════════
// App — sidebar rendering (single scrollable pane with collapsible sections)
// ════════════════════════════════════════════════════════════════════════════
Object.assign(App.prototype, {

  // Truncate a string shown inside a match toast to keep the notification
  // compact. IOCs extracted from decoded blobs can be kilobytes long.
  _truncateToast(s, max) {
    if (!s) return '';
    max = max || 80;
    return s.length > max ? s.slice(0, max - 1) + '…' : s;
  },

  _renderSidebar(fileName, analyzer) {
    // Clear any lingering encoded-content highlights from previous view
    this._clearEncodedHighlight();

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

  // ── File Info section ──────────────────────────────────────────────────
  _renderFileInfoSection(container, fileName) {
    const f = this.findings;
    const det = document.createElement('details');
    det.className = 'sb-details';
    det.open = true;

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
        const td2 = document.createElement('td'); td2.textContent = v;
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
    // Auto-open if auto-exec patterns detected
    if (f.autoExec && f.autoExec.length) det.open = true;

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
    det.open = true;  // always auto-open — any extracted PDF JS is high signal

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
    const baseName = (fileName || 'pdf').replace(/\.[^.]+$/, '');
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
    // Auto-open if any high-severity findings, decoded content, or IOCs extracted
    const hasHigh = encodedFindings.some(f => f.severity === 'high' || f.severity === 'critical');
    const hasDecoded = encodedFindings.some(f => f.decodedBytes);
    const hasIOCs = encodedFindings.some(f => f.iocs && f.iocs.length);
    det.open = hasHigh || hasDecoded || hasIOCs;

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
    const sevOrder = { critical: 0, high: 1, medium: 2, info: 3 };
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
    const sorted = [...encodedFindings].sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));
    for (const finding of sorted) {
      const card = document.createElement('div');
      card.className = `enc-finding-card enc-sev-${finding.severity}`;

      // Store DOM reference for bidirectional cross-flash linking
      finding._cardEl = card;
      // Keep any rows already registered by _renderIocsSection (which runs
      // BEFORE this section — see _renderSidebar ordering). Overwriting with
      // a fresh `[]` here would wipe those registrations and break the
      // "IOCs: N URL" click-to-flash handler below.
      finding._iocRows = finding._iocRows || [];

      // Header line: severity badge + encoding type
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
      card.appendChild(header);

      // Details
      const details = document.createElement('div');
      details.className = 'enc-finding-details';

      // Size & offset
      const meta = document.createElement('div');
      meta.className = 'enc-finding-meta';
      const sizeTxt = finding.decodedSize > 0
        ? this._fmtBytes(finding.decodedSize)
        : (finding.length ? `${finding.length} chars encoded` : `offset ${finding.offset.toLocaleString()}`);

      // Convert offset to line numbers for plaintext views
      let _canLocate = false;
      if (_isPlaintextView && _sourceText && finding.length) {
        const beforeText = _sourceText.substring(0, finding.offset);
        const startLine = (beforeText.match(/\n/g) || []).length + 1;
        const encodedSpan = _sourceText.substring(finding.offset, finding.offset + finding.length);
        const lineSpan = (encodedSpan.match(/\n/g) || []).length;
        const endLine = startLine + lineSpan;
        finding._startLine = startLine;
        finding._endLine = endLine;
        meta.textContent = startLine === endLine
          ? `${sizeTxt} · line ${startLine}`
          : `${sizeTxt} · lines ${startLine}\u2013${endLine}`;
        _canLocate = true;
      } else {
        meta.textContent = `${sizeTxt} at offset ${finding.offset.toLocaleString()}`;
      }

      // Clickable locate icon for plaintext views
      if (_canLocate) {
        const locateBtn = document.createElement('span');
        locateBtn.className = 'enc-locate-btn';
        locateBtn.textContent = ' \uD83D\uDD0D';
        locateBtn.title = 'Scroll to and highlight in view';
        meta.appendChild(locateBtn);
        meta.classList.add('enc-meta-clickable');
        meta.addEventListener('click', (e) => { e.stopPropagation(); this._highlightEncodedInView(finding, true); });
      }
      details.appendChild(meta);

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
        if (_canLocate) {
          snippetEl.title = 'Click to locate in view';
          snippetEl.style.cursor = 'pointer';
          snippetEl.addEventListener('click', () => this._highlightEncodedInView(finding, true));
        }
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
        const deepest = _hasDeepPath ? this._getDeepestFinding(finding) : null;
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


      // Decoded type
      if (finding.classification && finding.classification.type) {
        const typeLine = document.createElement('div');
        typeLine.className = 'enc-finding-type';
        typeLine.textContent = `Decoded: ${finding.classification.type}`;
        details.appendChild(typeLine);
      }

      // Decode chain
      if (finding.chain && finding.chain.length > 1) {
        const chainLine = document.createElement('div');
        chainLine.className = 'enc-finding-chain';
        chainLine.textContent = `Chain: ${finding.chain.join(' → ')}`;
        details.appendChild(chainLine);
      }

      // Entropy
      if (finding.entropy > 0) {
        const entLine = document.createElement('div');
        entLine.className = 'enc-finding-entropy';
        let entText = `Entropy: ${finding.entropy.toFixed(2)} / 8.00`;
        if (finding.entropy > 7.5) entText += ' ⚠ high (encrypted/packed?)';
        entLine.textContent = entText;
        details.appendChild(entLine);
      }

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
              const blob = new Blob([finding.decodedBytes], { type: 'application/octet-stream' });
              const syntheticFile = new File([blob], synName, { type: 'application/octet-stream' });
              this._pushNavState(fileName);
              this._loadFile(syntheticFile);
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
          const blob = new Blob([finding.decodedBytes], { type: 'application/octet-stream' });
          const syntheticFile = new File([blob], synName, { type: 'application/octet-stream' });
          this._pushNavState(fileName);
          this._loadFile(syntheticFile);
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
          const rawBytes = new Uint8Array(this._fileBuffer);
          const zipBytes = rawBytes.subarray(finding.embeddedZipOffset);
          const blob = new Blob([zipBytes], { type: 'application/zip' });
          const syntheticFile = new File([blob], `embedded_zip_offset${finding.offset}.zip`, { type: 'application/zip' });
          this._pushNavState(fileName);
          this._loadFile(syntheticFile);
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
              const blob = new Blob([finding.decodedBytes], { type: 'application/octet-stream' });
              const syntheticFile = new File([blob], synName, { type: 'application/octet-stream' });
              this._pushNavState(fileName);
              this._loadFile(syntheticFile);
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
          atwBtn.className = 'tb-btn enc-btn-alltheway';
          atwBtn.textContent = 'All the way ⏩';
          atwBtn.title = 'Follow encoding chain to deepest decoded content';
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
                const blob = new Blob([deepest.decodedBytes], { type: 'application/octet-stream' });
                const syntheticFile = new File([blob], synName, { type: 'application/octet-stream' });
                this._pushNavState(fileName);
                this._loadFile(syntheticFile);
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

      // Hover-to-highlight in view pane

      if (_canLocate) {
        card.setAttribute('data-locatable', '');
        card.addEventListener('mouseenter', () => this._highlightEncodedInView(finding, false));
        card.addEventListener('mouseleave', () => this._clearEncodedHighlight());
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
    if (refs.length) det.open = true;

    const sum = document.createElement('summary');
    sum.className = 'sb-details-summary';
    sum.textContent = refs.length
      ? `${sectionEmoji} ${sectionTitle} (${refs.length})`
      : `${sectionEmoji} ${sectionTitle}`;
    det.appendChild(sum);

    const body = document.createElement('div');
    body.className = 'sb-details-body';

    if (!refs.length) {
      const p = document.createElement('p');
      p.style.cssText = 'color:#888;text-align:center;margin-top:12px;font-size:12px;';
      p.textContent = emptyMessage;
      body.appendChild(p);
      det.appendChild(body);
      container.appendChild(det);
      return;
    }

    // Sort by severity: critical → high → medium → info
    const sevOrder = { critical: 0, high: 1, medium: 2, info: 3 };
    refs.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));

    // ── Filter state ─────────────────────────────────────────────────────
    const activeSeverities = new Set();
    const activeTypes = new Set();

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
      tr.dataset.search = (ref.type + ' ' + ref.url).toLowerCase();
      tr.dataset.severity = ref.severity;
      tr.dataset.type = ref.type;

      const td1 = document.createElement('td'); td1.textContent = ref.type;
      td1.className = 'ioc-type ioc-type-' + ref.type.toLowerCase().replace(/\s+/g, '-');
      const td2 = document.createElement('td'); td2.className = 'ext-val';
      if (ref._yaraRuleName) {
        // YARA match: bold humanised rule name + description
        const strong = document.createElement('strong');
        strong.textContent = ref._yaraRuleName.replace(/_/g, ' ');
        td2.appendChild(strong);
        // "View YARA rule" button — opens rule viewer filtered to this rule
        const viewBtn = document.createElement('button');
        viewBtn.className = 'yara-view-rule-btn';
        viewBtn.textContent = '\u{1F4D0}';
        viewBtn.title = 'View YARA rule';
        viewBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          this._openYaraDialog(ref._yaraRuleName);
        });
        td2.appendChild(viewBtn);
        if (ref.url) {
          const rest = document.createElement('span');
          rest.textContent = ' — ' + ref.url;
          td2.appendChild(rest);
        }
      } else {
        const sp = document.createElement('span'); sp.textContent = ref.url; td2.appendChild(sp);
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
      if (IOC_COPYABLE.has(ref.type)) {
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

      // Step 6: Filter table rows using all three filters
      let visibleCount = 0;
      for (const tr of tbody.rows) {
        const matchesText = !q || tr.dataset.search.includes(q);
        const matchesSev = activeSeverities.size === 0 || activeSeverities.has(tr.dataset.severity);
        const matchesType = activeTypes.size === 0 || activeTypes.has(tr.dataset.type);

        const visible = matchesText && matchesSev && matchesType;
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

    // ── Event listeners ──────────────────────────────────────────────────
    srch.addEventListener('input', applyFilters);

    det.appendChild(body);
    container.appendChild(det);
  },

  // ── Navigate to finding in content view ─────────────────────────────────
  //
  // Two unified click flows (see _highlightMatchesInline for the mechanics):
  //   • YARA match: highlight every string match returned by the engine.
  //   • IOC (URL / IP / hash / path / …): scan the rendered source text for
  //     every occurrence of the IOC value and highlight them all.
  // First click = highlight all + scroll-only-if-nothing-in-view.
  // Subsequent clicks (within 5 s) cycle `ref._currentMatchIndex` and always
  // scroll the current match into view. A 5 s no-click timer clears the
  // highlights and resets the index so the next click counts as "first" again.
  _navigateToFinding(ref, rowEl) {
    // Visual feedback — flash the clicked row
    rowEl.classList.add('ioc-flash');
    setTimeout(() => rowEl.classList.remove('ioc-flash'), 600);

    const pc = document.getElementById('page-container');
    const containerEl = pc && pc.firstElementChild;

    // Renderers with a Preview/Source toggle (HTML, SVG) expose
    // `_showSourcePane()` so the highlight surface is actually visible before
    // we try to scroll a <mark> into view.
    if (containerEl && typeof containerEl._showSourcePane === 'function') {
      try { containerEl._showSourcePane(); } catch (_) { /* best effort */ }
    }

    // ── YARA match: highlight ALL matches with click cycling ───────────────
    if (ref.type === IOC.YARA && ref._yaraMatches && ref._yaraMatches.length > 0) {
      const sourceText = containerEl && containerEl._rawText;
      const plaintextTable = pc && pc.querySelector('.plaintext-table');
      const matches = ref._yaraMatches;
      const totalMatches = matches.length;

      // First click = no current index tracked; subsequent clicks advance.
      const isFirstClick = (ref._currentMatchIndex === undefined);
      if (isFirstClick) {
        ref._currentMatchIndex = 0;
      } else {
        ref._currentMatchIndex = (ref._currentMatchIndex + 1) % totalMatches;
      }
      const focusIdx = ref._currentMatchIndex;
      const focusMatch = matches[focusIdx];

      // Match counter toast
      this._toast(`Match ${focusIdx + 1}/${totalMatches}: ${this._truncateToast(focusMatch.stringId)}`);

      if (plaintextTable && sourceText) {
        this._highlightMatchesInline(
          plaintextTable, sourceText, matches, focusIdx,
          /* forceScroll = */ !isFirstClick, ref, 'yara'
        );
        return;
      }

      // ── YARA match in CSV view: highlight in detail pane ──────────────────
      const csvView = pc && pc.querySelector('.csv-view');
      if (csvView && csvView._csvFilters && sourceText) {
        this._highlightYaraMatchesInCsv(
          csvView, sourceText, matches, focusIdx, /* forceScroll = */ !isFirstClick, ref
        );
        return;
      }
    }


    // Check if we have an EVTX view with filter controls
    const evtxView = pc && pc.querySelector('.evtx-view');
    if (evtxView && evtxView._evtxFilters) {
      const filters = evtxView._evtxFilters;

      // For IOC.PATTERN type: try to extract Event ID from the description
      if (ref.type === IOC.PATTERN || ref.type === IOC.INFO) {
        // Match patterns like "Event 1102:", "Sysmon Event 1:", "Defender Event 1006:", etc.
        const eidMatch = ref.url.match(/Event\s+(\d+)\s*:/);
        if (eidMatch) {
          // Apply Event ID filter
          filters.searchInput.value = '';
          filters.eidInput.value = eidMatch[1];
          filters.levelSelect.value = '';
          filters.applyFilters();
          // Expand ALL filtered rows for IOC navigation
          if (filters.expandAll) {
            filters.expandAll();
          }
          // Scroll the EVTX table into view
          filters.scrollContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
          // Flash the filter bar to draw attention
          const filterBar = evtxView.querySelector('.evtx-filter-bar');
          if (filterBar) {
            filterBar.classList.add('evtx-filter-flash');
            setTimeout(() => filterBar.classList.remove('evtx-filter-flash'), 1000);
          }
          // Subtle highlight of matched text inside expanded detail panes
          this._highlightIocInEvtxRows(evtxView, 'Event ' + eidMatch[1], ref);
          return;
        }
      }

      // For all other IOC types: use text search filter
      const searchVal = ref.url || '';
      if (searchVal) {
        // For hashes like "SHA256:ABCDEF...", just search the hash value part
        let searchTerm = searchVal;
        const hashMatch = searchVal.match(/^(?:SHA256|SHA1|MD5|IMPHASH):(.+)$/i);
        if (hashMatch) searchTerm = hashMatch[1];
        // For DOMAIN\User usernames, search just the username part (domain and
        // username are stored as separate fields in EVTX event data)
        if (ref.type === IOC.USERNAME && searchTerm.includes('\\')) {
          searchTerm = searchTerm.split('\\').pop();
        }
        // For very long values, truncate to avoid overly specific search
        if (searchTerm.length > 80) searchTerm = searchTerm.substring(0, 80);

        filters.eidInput.value = '';
        filters.searchInput.value = searchTerm;
        filters.levelSelect.value = '';
        filters.applyFilters();
        // Expand ALL filtered rows for IOC navigation
        if (filters.expandAll) {
          filters.expandAll();
        }
        filters.scrollContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
        const filterBar = evtxView.querySelector('.evtx-filter-bar');
        if (filterBar) {
          filterBar.classList.add('evtx-filter-flash');
          setTimeout(() => filterBar.classList.remove('evtx-filter-flash'), 1000);
        }
        // Subtle highlight of matched text inside expanded detail panes
        this._highlightIocInEvtxRows(evtxView, searchTerm, ref);
        return;
      }
    }

    // Check if we have a CSV view — scroll to matching row and auto-expand
    const csvView = pc && pc.querySelector('.csv-view');
    if (csvView && csvView._csvFilters) {
      const filters = csvView._csvFilters;
      const searchVal = ref.url || '';
      if (searchVal && filters.dataRows && filters.dataRows.length > 0) {
        // For hashes like "SHA256:ABCDEF...", just search the hash value part
        let searchTerm = searchVal;
        const hashMatch = searchVal.match(/^(?:SHA256|SHA1|MD5|IMPHASH):(.+)$/i);
        if (hashMatch) searchTerm = hashMatch[1];
        // Truncate very long values
        if (searchTerm.length > 80) searchTerm = searchTerm.substring(0, 80);

        // Find matching row and use virtual scrolling API
        const term = searchTerm.toLowerCase();
        for (const r of filters.dataRows) {
          if (r.searchText && r.searchText.includes(term)) {
            // Use the new scrollToRow method for virtual scrolling
            if (filters.scrollToRow) {
              this._highlightIocInCsvRow(csvView, searchTerm, r.dataIndex, ref);
            } else {
              // Fallback for non-virtual scrolling (shouldn't happen)
              filters.expandRow(r);
            }
            return;
          }
        }

        // Fallback: if exact row match not found, try partial match on first few chars
        const shortTerm = term.length > 20 ? term.substring(0, 20) : term;
        if (shortTerm !== term) {
          for (const r of filters.dataRows) {
            if (r.searchText && r.searchText.includes(shortTerm)) {
              if (filters.scrollToRow) {
                this._highlightIocInCsvRow(csvView, shortTerm, r.dataIndex, ref);
              } else {
                filters.expandRow(r);
              }
              return;
            }
          }
        }
      }
    }

    // Check if we have a SQLite view — scroll to matching row
    const sqliteView = pc && pc.querySelector('.sqlite-view');
    if (sqliteView && sqliteView._sqliteRows) {
      const rows = sqliteView._sqliteRows;
      const searchVal = (ref.url || '').toLowerCase();
      if (searchVal) {
        // Try full match first, then progressively shorter prefixes
        const attempts = [searchVal];
        if (searchVal.length > 40) attempts.push(searchVal.substring(0, 40));
        if (searchVal.length > 20) attempts.push(searchVal.substring(0, 20));

        for (const term of attempts) {
          for (const r of rows) {
            if (r.tr.style.display === 'none') continue;
            if (r.searchText.includes(term)) {
              // Scroll the row into view within the scroll container
              const scrContainer = sqliteView._sqliteScrollContainer;
              if (scrContainer) {
                const rowTop = r.tr.offsetTop - scrContainer.offsetTop;
                scrContainer.scrollTo({ top: rowTop - 60, behavior: 'smooth' });
              } else {
                r.tr.scrollIntoView({ behavior: 'smooth', block: 'center' });
              }
              // Flash highlight the row
              r.tr.classList.add('sqlite-row-flash');
              setTimeout(() => r.tr.classList.remove('sqlite-row-flash'), 1500);
              return;
            }
          }
        }
      }
    }

    // ── IOC highlighting with click-cycle semantics ─────────────────────────
    //
    // Mirrors the YARA flow: find every occurrence of the IOC value in the
    // rendered source text, highlight all, first click scroll-only-if-none-in-
    // view, subsequent clicks cycle `ref._currentMatchIndex`, auto-clear 5 s
    // after the last click.
    //
    // Falls back silently when there is no source text surface available
    // (visual-only renderers like images, PDF pages, archive listings).
    const sourceText = containerEl && containerEl._rawText;
    const plaintextTable = pc && pc.querySelector('.plaintext-table');
    if (plaintextTable && sourceText) {
      const iocMatches = this._findIOCMatches(ref, sourceText);
      if (iocMatches.length) {
        const totalMatches = iocMatches.length;
        const isFirstClick = (ref._currentMatchIndex === undefined);
        if (isFirstClick) {
          ref._currentMatchIndex = 0;
        } else {
          ref._currentMatchIndex = (ref._currentMatchIndex + 1) % totalMatches;
        }
        const focusIdx = ref._currentMatchIndex;
        const focusValue = ref.url || iocMatches[focusIdx].value || '';
        this._toast(`Match ${focusIdx + 1}/${totalMatches}: ${this._truncateToast(focusValue)}`);

        this._highlightMatchesInline(
          plaintextTable, sourceText, iocMatches, focusIdx,
          /* forceScroll = */ !isFirstClick, ref, 'ioc'
        );
        return;
      }
    }

    // ── Fallback for non-plaintext content: TreeWalker-based highlighting ──
    // Best effort: flash the first occurrence of the IOC value anywhere in
    // the rendered DOM. No cycling / no inline marks persisting.
    if (pc && ref.url) {
      // For SafeLinks, search for the wrapper URL if available
      const searchText = ref._highlightText || ref.url;
      const textContent = pc.textContent || '';
      if (textContent.includes(searchText) || textContent.toLowerCase().includes(searchText.toLowerCase())) {
        try {
          const sel = window.getSelection();
          sel.removeAllRanges();
          // Walk text nodes to find the match
          const walker = document.createTreeWalker(pc, NodeFilter.SHOW_TEXT, null);
          const searchLower = searchText.toLowerCase();
          let node;
          while ((node = walker.nextNode())) {
            const idx = node.textContent.toLowerCase().indexOf(searchLower);
            if (idx >= 0) {
              const range = document.createRange();
              range.setStart(node, idx);
              range.setEnd(node, Math.min(idx + searchText.length, node.textContent.length));
              sel.addRange(range);
              node.parentElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
              // Flash highlight effect
              const mark = document.createElement('mark');
              mark.className = 'ioc-highlight ioc-highlight-flash';
              try { range.surroundContents(mark); } catch (_) { /* cross-boundary */ }
              setTimeout(() => {
                if (mark.parentNode) {
                  mark.replaceWith(...mark.childNodes);
                }
              }, 2000);
              return;
            }
          }
        } catch (_) { /* best effort */ }
      }
    }
    // Last resort: nothing visible to highlight. Fail silently — the sidebar
    // row-flash already gave click feedback.
  },

  // ── Build list of IOC occurrences in source text ────────────────────────
  //
  // Returns an array of {offset, length, value} entries covering every
  // occurrence of the IOC's highlight text within `sourceText`. Case-
  // insensitive search is used as a fallback if the exact-case search
  // yields no hits. The renderer-provided _sourceOffset/_sourceLength is
  // always included (deduped) so at least one guaranteed match is present.
  _findIOCMatches(ref, sourceText) {
    const matches = [];
    const seen = new Set(); // offsets already recorded

    const push = (offset, length, value) => {
      if (offset == null || length <= 0) return;
      if (offset < 0 || offset + length > sourceText.length) return;
      if (seen.has(offset)) return;
      seen.add(offset);
      matches.push({ offset, length, value: value || sourceText.substring(offset, offset + length) });
    };

    // 1. Authoritative location supplied by renderer, if any.
    if (ref._sourceOffset !== undefined && ref._sourceLength) {
      push(ref._sourceOffset, ref._sourceLength, null);
    }

    // 2. Every occurrence of the IOC value (or SafeLink wrapper).
    const searchText = ref._highlightText || ref.url;
    if (searchText && searchText.length > 0 && searchText.length <= 2048) {
      // Exact-case first.
      let from = 0;
      while (from <= sourceText.length) {
        const idx = sourceText.indexOf(searchText, from);
        if (idx === -1) break;
        push(idx, searchText.length, searchText);
        from = idx + Math.max(1, searchText.length);
      }
      // If nothing hit exact-case (common for URLs re-cased in HTML), try CI.
      if (matches.length === 0 || (matches.length === 1 && ref._sourceOffset !== undefined)) {
        const haystack = sourceText.toLowerCase();
        const needle = searchText.toLowerCase();
        let fromL = 0;
        while (fromL <= haystack.length) {
          const idx = haystack.indexOf(needle, fromL);
          if (idx === -1) break;
          push(idx, searchText.length,
            sourceText.substring(idx, idx + searchText.length));
          fromL = idx + Math.max(1, searchText.length);
        }
      }
    }

    // Sort by offset so cycling walks the document top-to-bottom.
    matches.sort((a, b) => a.offset - b.offset);
    return matches;
  },

  // ── Highlight ALL matches inline (character-level precision) ──────────
  //
  // `matches` is the full array of {offset, length, stringId, ...} entries.
  // `focusIdx` is the index of the match that should be scrolled to.
  // `forceScroll` is true when the user has cycled (always scroll the focus
  //   match into view); when false (first click), we only scroll if *no*
  //   currently-wrapped match is already visible in the viewport.
  // `ref` is the YARA/IOC ref so the 5-second timer can reset _currentMatchIndex.
  // `kind` is 'yara' | 'ioc' and selects the CSS classes used for the
  //   inline <mark>s and the line-background highlight.
  _highlightMatchesInline(table, sourceText, matches, focusIdx, forceScroll, ref, kind) {
    // Clear any existing match highlights + pending clear-timer first.
    this._clearMatchHighlight();

    // Resolve CSS classes for this highlight kind.
    // yara → blue marks + blue line bg; ioc → yellow marks + yellow line bg.
    const isIoc = kind === 'ioc';
    const markClass   = isIoc ? 'ioc-highlight'      : 'yara-highlight';
    const flashClass  = isIoc ? 'ioc-highlight-flash' : 'yara-highlight-flash';
    const lineClass   = isIoc ? 'ioc-highlight-line'  : 'yara-line-highlight';
    const dataAttr    = isIoc ? 'data-ioc-match'      : 'data-yara-match';
    const datasetKey  = isIoc ? 'iocMatch'            : 'yaraMatch';


    const rows = table.rows;

    // ── 1. Compute (lineIndex, charPos, length) for each match ──────────
    //    and group them by line so each line only gets a single rewrite.
    const perMatch = [];
    const matchesByLine = new Map(); // lineIndex -> array of {charPos, length, matchIdx}
    for (let i = 0; i < matches.length; i++) {
      const m = matches[i];
      if (m.offset == null || !m.length) continue;
      const beforeText = sourceText.substring(0, m.offset);
      const lineIndex = (beforeText.match(/\n/g) || []).length;
      const lastNewline = beforeText.lastIndexOf('\n');
      const charPos = lastNewline === -1 ? m.offset : m.offset - lastNewline - 1;
      if (lineIndex >= rows.length) continue;
      perMatch.push({ matchIdx: i, lineIndex, charPos, length: m.length });
      let arr = matchesByLine.get(lineIndex);
      if (!arr) { arr = []; matchesByLine.set(lineIndex, arr); }
      arr.push({ charPos, length: m.length, matchIdx: i });
    }
    if (!perMatch.length) return;

    // ── 2. For each affected line, insert <mark> elements for every match.
    //    Sort by charPos so we can walk the line text left-to-right.
    //    The generated <mark>s are tagged with the kind-specific data-attr
    //    (data-yara-match / data-ioc-match) so we can later locate the
    //    focus match for scrolling.
    const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    for (const [lineIndex, lineMatches] of matchesByLine) {
      const row = rows[lineIndex];
      const codeCell = row.querySelector('.plaintext-code');
      if (!codeCell) continue;

      // Sort left-to-right and drop overlapping matches (keep the first).
      lineMatches.sort((a, b) => a.charPos - b.charPos);
      const nonOverlapping = [];
      let cursor = -1;
      for (const lm of lineMatches) {
        if (lm.charPos >= cursor) {
          nonOverlapping.push(lm);
          cursor = lm.charPos + lm.length;
        }
      }

      const hasHighlighting = codeCell.innerHTML !== codeCell.textContent;

      if (hasHighlighting) {
        // Syntax-highlighted HTML: insert marks via TreeWalker for each match
        // in reverse order so earlier offsets stay valid.
        for (let i = nonOverlapping.length - 1; i >= 0; i--) {
          const lm = nonOverlapping[i];
          this._highlightInHtmlNode(codeCell, lm.charPos, lm.length, lm.matchIdx, kind);
        }
      } else {
        // Plain text cell: build a single innerHTML in one pass.
        const cellText = codeCell.textContent;
        let out = '';
        let pos = 0;
        for (const lm of nonOverlapping) {
          if (lm.charPos > cellText.length) break;
          const end = Math.min(lm.charPos + lm.length, cellText.length);
          if (lm.charPos > pos) out += esc(cellText.substring(pos, lm.charPos));
          const matchedText = cellText.substring(lm.charPos, end);
          out += `<mark class="${markClass} ${flashClass}" ${dataAttr}="${lm.matchIdx}">${esc(matchedText)}</mark>`;
          pos = end;
        }
        if (pos < cellText.length) out += esc(cellText.substring(pos));
        codeCell.innerHTML = out;
      }

      row.classList.add(lineClass);
    }

    // ── 3. Determine whether to scroll. ──────────────────────────────────
    //    On first click (forceScroll=false) we only scroll if *no* mark is
    //    currently visible in the viewport. On subsequent clicks we always
    //    scroll the focused match.
    const pc = document.getElementById('page-container');
    const allMarks = Array.from((pc || document).querySelectorAll('mark.' + markClass));
    const focusMark = allMarks.find(m => m.dataset[datasetKey] === String(focusIdx)) || allMarks[0];

    let shouldScroll = forceScroll;
    if (!forceScroll) {
      // Check if any mark intersects the current viewport.
      const vh = window.innerHeight || document.documentElement.clientHeight;
      const vw = window.innerWidth || document.documentElement.clientWidth;
      const anyInView = allMarks.some(m => {
        const r = m.getBoundingClientRect();
        return r.bottom > 0 && r.top < vh && r.right > 0 && r.left < vw && r.width > 0 && r.height > 0;
      });
      shouldScroll = !anyInView;
    }

    if (shouldScroll && focusMark) {
      focusMark.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    // ── 4. Schedule the 5-second clear timer. ────────────────────────────
    //    Any new click resets the timer (we cleared the previous one at the
    //    top of this method). When it fires, we remove all highlights and
    //    reset the ref's _currentMatchIndex so the NEXT click counts as a
    //    fresh "first click".
    this._matchHighlightTimer = setTimeout(() => {
      this._clearMatchHighlight();
      if (ref) ref._currentMatchIndex = undefined;
      this._matchHighlightTimer = null;
    }, 5000);
  },



  // ── Highlight within syntax-highlighted HTML content ────────────────────
  //
  // Optional `matchIdx` is stamped on the resulting <mark> as
  // `data-yara-match="<idx>"` (or `data-ioc-match` for kind='ioc') so
  // _highlightMatchesInline can locate the focus match for scrolling.
  _highlightInHtmlNode(container, charPos, length, matchIdx, kind) {
    const isIoc = kind === 'ioc';
    const markClass  = isIoc ? 'ioc-highlight'       : 'yara-highlight';
    const flashClass = isIoc ? 'ioc-highlight-flash' : 'yara-highlight-flash';
    const datasetKey = isIoc ? 'iocMatch'            : 'yaraMatch';

    // Collect every text node in the container with its running character
    // offset so we can locate which node(s) any match range intersects. This
    // correctly handles matches that span multiple text nodes — a common
    // situation when highlight.js tokenises paths like `C:\temp\update.exe`
    // into separate <span>s for each punctuation character.
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, null);
    const segments = [];
    let runningPos = 0;
    let n;
    while ((n = walker.nextNode())) {
      const len = n.nodeValue.length;
      segments.push({ node: n, start: runningPos, end: runningPos + len });
      runningPos += len;
    }

    const matchEnd = charPos + length;
    const hits = [];
    for (const s of segments) {
      if (s.end <= charPos) continue;
      if (s.start >= matchEnd) break;
      const localStart = Math.max(0, charPos - s.start);
      const localEnd   = Math.min(s.end - s.start, matchEnd - s.start);
      if (localEnd > localStart) hits.push({ seg: s, localStart, localEnd });
    }
    if (!hits.length) return;

    // Wrap each intersecting slice in its own <mark>, walking in reverse so
    // splitText() calls on earlier nodes don't invalidate offsets of later
    // hits. All generated marks share the same matchIdx/dataset attribute so
    // focus-scrolling + cross-flash can locate any of them.
    for (let i = hits.length - 1; i >= 0; i--) {
      const h = hits[i];
      const tn = h.seg.node;
      // Detach the tail that lies after the match region, if any.
      if (h.localEnd < tn.nodeValue.length) tn.splitText(h.localEnd);
      // Detach the head that lies before the match region, if any; the
      // returned node then represents exactly the matched slice.
      let targetNode = tn;
      if (h.localStart > 0) targetNode = tn.splitText(h.localStart);
      const mark = document.createElement('mark');
      mark.className = markClass + ' ' + flashClass;
      if (matchIdx !== undefined) mark.dataset[datasetKey] = String(matchIdx);
      targetNode.parentNode.insertBefore(mark, targetNode);
      mark.appendChild(targetNode);
    }
  },



  // ── Clear YARA + IOC inline highlights ──────────────────────────────────
  //
  // Single clear-all for both YARA (blue) and IOC (yellow) match highlights.
  // Cancels any pending auto-clear timer (both legacy `_yaraHighlightTimer`
  // used by the CSV path and the newer unified `_matchHighlightTimer`).
  _clearMatchHighlight() {
    // Cancel any pending auto-clear timers so they don't fire later and
    // reset an unrelated ref's _currentMatchIndex.
    if (this._yaraHighlightTimer) {
      clearTimeout(this._yaraHighlightTimer);
      this._yaraHighlightTimer = null;
    }
    if (this._matchHighlightTimer) {
      clearTimeout(this._matchHighlightTimer);
      this._matchHighlightTimer = null;
    }

    const pc = document.getElementById('page-container');
    if (!pc) return;

    // Remove line-background highlights (both kinds)
    const highlightedLines = pc.querySelectorAll('.yara-line-highlight, .ioc-highlight-line');
    for (const el of highlightedLines) {
      el.classList.remove('yara-line-highlight', 'ioc-highlight-line');
    }

    // Remove inline <mark> elements and restore text (both kinds)
    const marks = pc.querySelectorAll('mark.yara-highlight, mark.ioc-highlight');
    for (const mark of marks) {
      const textNode = document.createTextNode(mark.textContent);
      mark.parentNode.replaceChild(textNode, mark);
    }

    // Normalize text nodes (merge adjacent text nodes)
    const codesCells = pc.querySelectorAll('.plaintext-code');
    for (const cell of codesCells) {
      cell.normalize();
    }

    // Also clear CSV detail pane highlights
    const csvMarks = pc.querySelectorAll('mark.csv-yara-highlight');
    for (const mark of csvMarks) {
      const textNode = document.createTextNode(mark.textContent);
      mark.parentNode.replaceChild(textNode, mark);
    }
    // Normalize detail value cells
    const detailVals = pc.querySelectorAll('.csv-detail-val');
    for (const cell of detailVals) {
      cell.normalize();
    }
  },

  // Backwards-compatible alias used by CSV highlighter and other callers.
  _clearYaraHighlight() { this._clearMatchHighlight(); },


  // ── Highlight YARA matches in CSV detail pane ──────────────────────────
  //
  // Same contract as _highlightYaraMatchesInline but for the CSV virtualised
  // view. We expand the focus match's row, and after the virtual scroll has
  // rendered, highlight *all* matches that fall within any currently rendered
  // detail pane (typically this is just the focus row's pane plus any other
  // rows the user has already expanded). Matches in off-screen virtualised
  // rows can't be highlighted simultaneously without expanding many rows —
  // cycling through clicks will visit each focus row in turn.
  _highlightYaraMatchesInCsv(csvView, sourceText, matches, focusIdx, forceScroll, ref) {
    // Clear existing YARA highlights + pending timer first.
    this._clearYaraHighlight();

    const filters = csvView._csvFilters;
    if (!filters || !filters.dataRows) return;

    const focusMatch = matches[focusIdx];
    if (!focusMatch) return;

    // Find which row the focus match belongs to.
    let focusRow = null;
    for (const r of filters.dataRows) {
      if (focusMatch.offset >= r.offsetStart && focusMatch.offset < r.offsetEnd) {
        focusRow = r;
        break;
      }
    }
    if (!focusRow) return;

    const dataIdx = focusRow.dataIndex;

    // Helper: escape HTML entities.
    const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    // Helper: highlight all matches inside a given detail pane.
    // Returns the <mark> element corresponding to focusIdx (or null).
    const highlightPane = (detailPane, rowMatches) => {
      let focusMarkEl = null;
      const detailVals = detailPane.querySelectorAll('.csv-detail-val');
      for (const valEl of detailVals) {
        // For each cell, find every match string that occurs in it and wrap
        // them in <mark>. Multiple matches per cell are supported; overlaps
        // are resolved by taking earliest position wins.
        const cellText = valEl.textContent;
        if (!cellText) continue;

        // Find all (cellStart, cellEnd, matchIdx) hits within this cell.
        const hits = [];
        for (const rm of rowMatches) {
          const matchStr = sourceText.substring(rm.offset, rm.offset + rm.length);
          if (!matchStr) continue;
          let idx = cellText.indexOf(matchStr);
          if (idx === -1) {
            idx = cellText.toLowerCase().indexOf(matchStr.toLowerCase());
          }
          if (idx !== -1) {
            hits.push({ start: idx, end: idx + matchStr.length, matchIdx: rm._matchIdx });
          }
        }
        if (!hits.length) continue;

        hits.sort((a, b) => a.start - b.start);
        // Drop overlaps.
        const keep = [];
        let cursor = -1;
        for (const h of hits) {
          if (h.start >= cursor) { keep.push(h); cursor = h.end; }
        }

        // Build innerHTML in one pass.
        let out = '';
        let pos = 0;
        for (const h of keep) {
          if (h.start > pos) out += esc(cellText.substring(pos, h.start));
          const matchedText = cellText.substring(h.start, h.end);
          out += `<mark class="csv-yara-highlight csv-yara-highlight-flash" data-yara-match="${h.matchIdx}">${esc(matchedText)}</mark>`;
          pos = h.end;
        }
        if (pos < cellText.length) out += esc(cellText.substring(pos));
        valEl.innerHTML = out;

        // Locate focus mark if present.
        if (!focusMarkEl) {
          focusMarkEl = valEl.querySelector(`mark.csv-yara-highlight[data-yara-match="${focusIdx}"]`);
        }
      }
      return focusMarkEl;
    };

    // Group matches by which CSV row they belong to (by offset range).
    // Attach original matchIdx so we can locate the focus mark.
    const matchesByRowIdx = new Map(); // dataIndex -> [{offset, length, _matchIdx}, ...]
    for (let i = 0; i < matches.length; i++) {
      const m = matches[i];
      if (m.offset == null || !m.length) continue;
      for (const r of filters.dataRows) {
        if (m.offset >= r.offsetStart && m.offset < r.offsetEnd) {
          let arr = matchesByRowIdx.get(r.dataIndex);
          if (!arr) { arr = []; matchesByRowIdx.set(r.dataIndex, arr); }
          arr.push({ offset: m.offset, length: m.length, _matchIdx: i });
          break;
        }
      }
    }

    // Scroll the focus row into view & expand it (virtual scroll).
    if (filters.scrollToRow) {
      filters.scrollToRow(dataIdx, false);
    }

    // Wait for virtual scroll to render, then apply highlights.
    setTimeout(() => {
      const tbody = csvView.querySelector('tbody');
      if (!tbody) return;

      // Highlight every currently-rendered detail pane whose row has matches.
      let focusMarkEl = null;
      for (const [rowDataIdx, rowMatches] of matchesByRowIdx) {
        const tr = tbody.querySelector(`tr[data-idx="${rowDataIdx}"]`);
        if (!tr) continue;
        tr.classList.add('csv-yara-row-highlight');
        const detailTr = tr.nextElementSibling;
        if (!detailTr || !detailTr.classList.contains('csv-detail-row')) continue;
        const detailPane = detailTr.querySelector('.csv-detail-pane');
        if (!detailPane) continue;
        const fm = highlightPane(detailPane, rowMatches);
        if (fm && !focusMarkEl) focusMarkEl = fm;
      }

      // Decide whether to scroll the focus mark into view.
      let shouldScroll = forceScroll;
      if (!forceScroll && focusMarkEl) {
        const vh = window.innerHeight || document.documentElement.clientHeight;
        const vw = window.innerWidth || document.documentElement.clientWidth;
        const allMarks = csvView.querySelectorAll('mark.csv-yara-highlight');
        const anyInView = Array.from(allMarks).some(m => {
          const rc = m.getBoundingClientRect();
          return rc.bottom > 0 && rc.top < vh && rc.right > 0 && rc.left < vw && rc.width > 0 && rc.height > 0;
        });
        shouldScroll = !anyInView;
      }
      if (shouldScroll && focusMarkEl) {
        focusMarkEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }

      // Schedule the 5-second auto-clear timer.
      this._yaraHighlightTimer = setTimeout(() => {
        this._clearYaraHighlight();
        if (ref) ref._currentMatchIndex = undefined;
        this._yaraHighlightTimer = null;
      }, 5000);
    }, 400); // Wait for virtual scroll to complete
  },


  // ── Update overall risk from encoded content severity ──────────────────
  _updateRiskFromEncodedContent() {
    if (!this.findings || !this.findings.encodedContent) return;
    const riskRank = { critical: 4, high: 3, medium: 2, low: 1 };
    const sevToRisk = { critical: 'critical', high: 'high', medium: 'medium' };
    const currentRank = riskRank[this.findings.risk] || 1;
    let maxRisk = null;
    for (const ef of this.findings.encodedContent) {
      const mapped = sevToRisk[ef.severity];
      if (mapped && (riskRank[mapped] || 0) > (riskRank[maxRisk] || 0)) {
        maxRisk = mapped;
      }
    }
    if (maxRisk && (riskRank[maxRisk] || 0) > currentRank) {
      this.findings.risk = maxRisk;
    }
  },

  // ── Highlight encoded content in the view pane ──────────────────────────
  _highlightEncodedInView(finding, flash) {
    this._clearEncodedHighlight();
    const pc = document.getElementById('page-container');
    if (!pc) return;
    const table = pc.querySelector('.plaintext-table');
    if (!table || !finding._startLine) return;

    const rows = table.rows;
    const start = finding._startLine - 1;
    const end = finding._endLine - 1;

    for (let i = start; i <= end && i < rows.length; i++) {
      rows[i].classList.add('enc-highlight-line');
      if (flash) rows[i].classList.add('enc-highlight-flash');
    }

    if (flash && start < rows.length) {
      rows[start].scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    if (flash) {
      setTimeout(() => {
        for (let i = start; i <= end && i < rows.length; i++) {
          rows[i].classList.remove('enc-highlight-flash');
        }
      }, 2000);
    }
  },

  _clearEncodedHighlight() {
    const pc = document.getElementById('page-container');
    if (!pc) return;
    const highlighted = pc.querySelectorAll('.enc-highlight-line');
    for (const el of highlighted) {
      el.classList.remove('enc-highlight-line', 'enc-highlight-flash');
    }
  },

  // ── Flash encoded content card ──────────────────────────────────────────
  _flashEncodedCard(finding) {
    const card = finding._cardEl;
    if (!card) return;
    // Ensure the Encoded Content section is open
    const encDetails = card.closest('.sb-details');
    if (encDetails && !encDetails.open) encDetails.open = true;
    card.classList.remove('enc-card-flash');
    void card.offsetWidth; // force reflow to restart animation
    card.classList.add('enc-card-flash');
    card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    setTimeout(() => card.classList.remove('enc-card-flash'), 1500);
  },

  // ── Flash IOC rows linked to an encoded finding ─────────────────────────
  _flashIocRows(finding) {
    const rows = finding._iocRows;
    if (!rows || !rows.length) return;
    // Ensure parent section is open
    const sigDetails = rows[0].closest('.sb-details');
    if (sigDetails && !sigDetails.open) sigDetails.open = true;
    // Small delay to let section expand before scrolling
    setTimeout(() => {
      for (const tr of rows) {
        tr.classList.remove('ioc-encoded-flash');
        void tr.offsetWidth;
        tr.classList.add('ioc-encoded-flash');
      }
      rows[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
      setTimeout(() => { for (const tr of rows) tr.classList.remove('ioc-encoded-flash'); }, 1500);
    }, 50);
  },

  // ── IOC subtle-highlight inside CSV expanded row ────────────────────────
  //
  // Complements _highlightYaraMatchesInCsv but for simple IOC navigation:
  // scroll the matching row into view, expand it, and wrap every occurrence
  // of `searchTerm` inside each .csv-detail-val cell in a subtle yellow
  // <mark>. Auto-clears after 5 seconds.
  _highlightIocInCsvRow(csvView, searchTerm, dataIdx, ref) {
    this._clearIocCsvHighlight();
    const filters = csvView && csvView._csvFilters;
    if (!filters || !filters.scrollToRow || !searchTerm) return;
    filters.scrollToRow(dataIdx, false);

    const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const termLower = searchTerm.toLowerCase();

    // csv-renderer's scrollToRow() schedules its OWN 400ms setTimeout that
    // renders the virtual row + creates the detail <tr>. If we used a single
    // matching setTimeout here we'd race with it (broken first click on a
    // collapsed CSV, works on second click when row is already in DOM).
    // Instead, poll for the detail row up to ~1.5s.
    const deadline = performance.now() + 1500;
    const tryHighlight = () => {
      const tbody = csvView.querySelector('tbody');
      const tr = tbody && tbody.querySelector(`tr[data-idx="${dataIdx}"]`);
      const detailTr = tr && tr.nextElementSibling;
      const detailReady = detailTr && detailTr.classList.contains('csv-detail-row');
      if (!detailReady) {
        if (performance.now() < deadline) {
          this._iocCsvHighlightPoll = setTimeout(tryHighlight, 60);
        } else {
          this._iocCsvHighlightPoll = null;
        }
        return;
      }
      this._iocCsvHighlightPoll = null;

      tr.classList.add('csv-ioc-row-highlight');
      const valEls = detailTr.querySelectorAll('.csv-detail-val');
      let firstMark = null;
      for (const valEl of valEls) {
        const text = valEl.textContent;
        if (!text) continue;
        const idx = text.toLowerCase().indexOf(termLower);
        if (idx === -1) continue;
        const before = esc(text.slice(0, idx));
        const matched = esc(text.slice(idx, idx + searchTerm.length));
        const after = esc(text.slice(idx + searchTerm.length));
        valEl.innerHTML = `${before}<mark class="csv-ioc-highlight csv-ioc-highlight-flash">${matched}</mark>${after}`;
        if (!firstMark) firstMark = valEl.querySelector('mark.csv-ioc-highlight');
      }
      if (firstMark) firstMark.scrollIntoView({ behavior: 'smooth', block: 'center' });

      this._iocCsvHighlightTimer = setTimeout(() => {
        this._clearIocCsvHighlight();
        if (ref) ref._currentMatchIndex = undefined;
        this._iocCsvHighlightTimer = null;
      }, 5000);
    };
    // csv-renderer.js::scrollToRow() runs its OWN internal setTimeout(400)
    // that tears down and rebuilds the entire visible tbody (resets
    // state.renderedRange and calls renderVisibleRows()). If we wrap a
    // <mark> before that rebuild happens it gets wiped — the user sees the
    // row highlight but no cell-level mark (and it only appears on the 2nd
    // click, when the row is already expanded and the rebuild is a no-op).
    // Wait 450 ms so our wrap runs AFTER the rebuild finishes; the poll
    // below then handles any slower renders (up to 1.5 s).
    this._iocCsvHighlightPoll = setTimeout(tryHighlight, 450);
  },

  _clearIocCsvHighlight() {
    if (this._iocCsvHighlightTimer) {
      clearTimeout(this._iocCsvHighlightTimer);
      this._iocCsvHighlightTimer = null;
    }
    document.querySelectorAll('mark.csv-ioc-highlight').forEach(m => {
      const parent = m.parentNode;
      if (!parent) return;
      while (m.firstChild) parent.insertBefore(m.firstChild, m);
      parent.removeChild(m);
      parent.normalize();
    });
    document.querySelectorAll('tr.csv-ioc-row-highlight').forEach(tr => {
      tr.classList.remove('csv-ioc-row-highlight');
    });
  },

  // ── IOC subtle-highlight inside EVTX expanded detail panes ──────────────
  //
  // After filters+expandAll renders the relevant rows, walk every visible
  // detail pane and wrap the first occurrence of `searchTerm` (per text node)
  // in a subtle yellow <mark>. Auto-clears after 5 seconds.
  _highlightIocInEvtxRows(evtxView, searchTerm, ref) {
    this._clearIocEvtxHighlight();
    if (!searchTerm || !evtxView) return;
    const termLower = searchTerm.toLowerCase();

    requestAnimationFrame(() => {
      const panes = evtxView.querySelectorAll('.evtx-detail-pane, .evtx-record-readable');
      let firstMark = null;
      for (const pane of panes) {
        const walker = document.createTreeWalker(pane, NodeFilter.SHOW_TEXT, null);
        const nodes = [];
        let n;
        while ((n = walker.nextNode())) {
          // Skip text already inside a <mark> (defensive)
          if (n.parentNode && n.parentNode.tagName === 'MARK') continue;
          nodes.push(n);
        }
        for (const tn of nodes) {
          const text = tn.nodeValue;
          const idx = text.toLowerCase().indexOf(termLower);
          if (idx === -1) continue;
          // Split and wrap (work on tail → mid so offsets stay valid)
          tn.splitText(idx + searchTerm.length);
          const mid = tn.splitText(idx);
          const mark = document.createElement('mark');
          mark.className = 'evtx-ioc-highlight evtx-ioc-highlight-flash';
          mid.parentNode.insertBefore(mark, mid);
          mark.appendChild(mid);
          if (!firstMark) firstMark = mark;
        }
      }
      if (firstMark) firstMark.scrollIntoView({ behavior: 'smooth', block: 'center' });

      this._iocEvtxHighlightTimer = setTimeout(() => {
        this._clearIocEvtxHighlight();
        if (ref) ref._currentMatchIndex = undefined;
        this._iocEvtxHighlightTimer = null;
      }, 5000);
    });
  },

  _clearIocEvtxHighlight() {
    if (this._iocEvtxHighlightTimer) {
      clearTimeout(this._iocEvtxHighlightTimer);
      this._iocEvtxHighlightTimer = null;
    }
    document.querySelectorAll('mark.evtx-ioc-highlight').forEach(m => {
      const parent = m.parentNode;
      if (!parent) return;
      while (m.firstChild) parent.insertBefore(m.firstChild, m);
      parent.removeChild(m);
      parent.normalize();
    });
  },

  // ── Get deepest decoded finding in innerFindings tree ───────────────────
  _getDeepestFinding(finding) {
    if (!finding.innerFindings || !finding.innerFindings.length) return finding;
    const sevRank = { critical: 4, high: 3, medium: 2, info: 1 };
    const best = finding.innerFindings.reduce((a, b) =>
      (sevRank[b.severity] || 0) > (sevRank[a.severity] || 0) ? b : a
    );
    if (best.decodedBytes || best.rawCandidate || (best.innerFindings && best.innerFindings.length)) {
      return this._getDeepestFinding(best);
    }
    return (best.decodedBytes || best.rawCandidate) ? best : finding;
  },

});
