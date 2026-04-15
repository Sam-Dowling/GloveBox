// ════════════════════════════════════════════════════════════════════════════
// App — sidebar rendering (single scrollable pane with collapsible sections)
// ════════════════════════════════════════════════════════════════════════════
Object.assign(App.prototype, {

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

    // 2. Macros (only if detected; auto-opens when auto-exec found)
    if (f.hasMacros) {
      this._renderMacrosSection(body, analyzer);
    }

    // 3. Encoded Content (only if detected)
    if (f.encodedContent && f.encodedContent.length) {
      this._renderEncodedContentSection(body, f.encodedContent, fileName);
    }

    // 4. Signatures & IOCs (sorted by severity, open if findings exist)
    const allRefs = [...(f.externalRefs || []), ...(f.interestingStrings || [])];
    this._renderSignaturesSection(body, allRefs, fileName);

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
    sum.textContent = `🔓 Encoded Content (${encodedFindings.length})`;
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
      finding._iocRows = [];

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

      // Snippet preview of the raw encoded content
      const _snippetText = finding.snippet || (_sourceText && finding.length
        ? _sourceText.substring(finding.offset, finding.offset + Math.min(finding.length, 120))
        : null);
      if (_snippetText) {
        const snippetEl = document.createElement('div');
        snippetEl.className = 'enc-snippet';
        snippetEl.textContent = _snippetText.length < (finding.length || Infinity)
          ? _snippetText + '\u2026'
          : _snippetText;
        if (_canLocate) {
          snippetEl.title = 'Click to locate in view';
          snippetEl.style.cursor = 'pointer';
          snippetEl.addEventListener('click', () => this._highlightEncodedInView(finding, true));
        }
        details.appendChild(snippetEl);
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
        iocLine.title = 'Click to highlight IOC rows in Signatures & IOCs';
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

      // Inner findings (recursive)
      if (finding.innerFindings && finding.innerFindings.length) {
        const innerDet = document.createElement('details');
        innerDet.className = 'enc-inner-findings';
        const innerSum = document.createElement('summary');
        innerSum.style.cssText = 'cursor:pointer;font-size:10px;font-weight:600;color:#888;margin-top:6px;';
        innerSum.textContent = `${finding.innerFindings.length} nested encoded layer${finding.innerFindings.length !== 1 ? 's' : ''} detected`;
        innerDet.appendChild(innerSum);
        for (const inner of finding.innerFindings) {
          const innerCard = document.createElement('div');
          innerCard.className = 'enc-finding-inner-card';
          innerCard.textContent = `${inner.encoding}: ${inner.chain.join(' → ')}`;
          if (inner.classification && inner.classification.type) {
            innerCard.textContent += ` → ${inner.classification.type}`;
          }
          innerDet.appendChild(innerCard);
        }
        card.appendChild(innerDet);
      }

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
        sum.textContent = `🔓 Encoded Content (${visibleCount}/${encodedFindings.length})`;
      } else {
        sum.textContent = `🔓 Encoded Content (${encodedFindings.length})`;
      }
    };

    det.appendChild(body);
    container.appendChild(det);
  },

  // ── Signatures & IOCs section ──────────────────────────────────────────
  _renderSignaturesSection(container, refs, fileName) {
    const det = document.createElement('details');
    det.className = 'sb-details';
    if (refs.length) det.open = true;

    const sum = document.createElement('summary');
    sum.className = 'sb-details-summary';
    sum.textContent = refs.length
      ? `🔍 Signatures & IOCs (${refs.length})`
      : '🔍 Signatures & IOCs';
    det.appendChild(sum);

    const body = document.createElement('div');
    body.className = 'sb-details-body';

    if (!refs.length) {
      const p = document.createElement('p');
      p.style.cssText = 'color:#888;text-align:center;margin-top:12px;font-size:12px;';
      p.textContent = '✅ No signatures or indicators found.';
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

      // Register IOC row back to parent encoded finding for cross-flash
      if (ref._encodedFinding && ref._encodedFinding._iocRows) {
        ref._encodedFinding._iocRows.push(tr);
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
        sum.textContent = `🔍 Signatures & IOCs (${visibleCount}/${refs.length})`;
      } else {
        sum.textContent = `🔍 Signatures & IOCs (${refs.length})`;
      }
    };

    // ── Event listeners ──────────────────────────────────────────────────
    srch.addEventListener('input', applyFilters);

    det.appendChild(body);
    container.appendChild(det);
  },

  // ── Navigate to finding in content view ─────────────────────────────────
  _navigateToFinding(ref, rowEl) {
    // Visual feedback — flash the clicked row
    rowEl.classList.add('ioc-flash');
    setTimeout(() => rowEl.classList.remove('ioc-flash'), 600);

    const pc = document.getElementById('page-container');

    // ── YARA match: inline highlight with cycling ───────────────────────────
    if (ref.type === IOC.YARA && ref._yaraMatches && ref._yaraMatches.length > 0) {
      const docEl = pc && pc.firstElementChild;
      const sourceText = docEl && docEl._rawText;
      const plaintextTable = pc && pc.querySelector('.plaintext-table');

      if (plaintextTable && sourceText) {
        const matches = ref._yaraMatches;

        // Track current match index on the ref object for cycling
        if (ref._currentMatchIndex === undefined) ref._currentMatchIndex = 0;
        else ref._currentMatchIndex = (ref._currentMatchIndex + 1) % matches.length;

        const match = matches[ref._currentMatchIndex];
        const totalMatches = matches.length;
        const currentNum = ref._currentMatchIndex + 1;

        // Show match counter toast
        this._toast(`Match ${currentNum}/${totalMatches}: ${match.stringId}`);

        // Highlight the match inline
        this._highlightYaraMatchInline(plaintextTable, sourceText, match.offset, match.length);
        return;
      }

      // ── YARA match in CSV view: highlight in detail pane ──────────────────
      const csvView = pc && pc.querySelector('.csv-view');
      if (csvView && csvView._csvFilters && sourceText) {
        const matches = ref._yaraMatches;

        // Track current match index on the ref object for cycling
        if (ref._currentMatchIndex === undefined) ref._currentMatchIndex = 0;
        else ref._currentMatchIndex = (ref._currentMatchIndex + 1) % matches.length;

        const match = matches[ref._currentMatchIndex];
        const totalMatches = matches.length;
        const currentNum = ref._currentMatchIndex + 1;

        // Show match counter toast
        this._toast(`Match ${currentNum}/${totalMatches}: ${match.stringId}`);

        // Highlight the match in the CSV detail pane
        this._highlightYaraMatchInCsv(csvView, sourceText, match.offset, match.length);
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
              filters.scrollToRow(r.dataIndex, true);
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
                filters.scrollToRow(r.dataIndex, true);
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

    // ── Plaintext view with offset-based line highlighting ──────────────────
    // Check if we have a plaintext view with _rawText for precise highlighting
    const docEl = pc && pc.firstElementChild;
    const sourceText = docEl && docEl._rawText;
    const plaintextTable = pc && pc.querySelector('.plaintext-table');

    if (plaintextTable && sourceText) {
      // Determine what text to search for:
      // - For SafeLinks, use _highlightText (the wrapper URL) if available
      // - Otherwise use the IOC value itself
      const highlightText = ref._highlightText || ref.url;

      // Try offset-based highlighting first (most accurate)
      if (ref._sourceOffset !== undefined && ref._sourceLength) {
        const offset = ref._sourceOffset;
        const length = ref._sourceLength;

        // Calculate line numbers from offset
        const beforeText = sourceText.substring(0, offset);
        const startLine = (beforeText.match(/\n/g) || []).length + 1;
        const matchedText = sourceText.substring(offset, offset + length);
        const lineSpan = (matchedText.match(/\n/g) || []).length;
        const endLine = startLine + lineSpan;

        // Use the encoded content highlight mechanism (already implemented)
        this._highlightIOCInPlaintext(plaintextTable, startLine, endLine);
        return;
      }

      // Fallback: search for the text in sourceText and calculate line numbers
      const searchText = highlightText || ref.url;
      if (searchText) {
        const idx = sourceText.indexOf(searchText);
        if (idx >= 0) {
          const beforeText = sourceText.substring(0, idx);
          const startLine = (beforeText.match(/\n/g) || []).length + 1;
          const matchedText = sourceText.substring(idx, idx + searchText.length);
          const lineSpan = (matchedText.match(/\n/g) || []).length;
          const endLine = startLine + lineSpan;

          this._highlightIOCInPlaintext(plaintextTable, startLine, endLine);
          return;
        }
        // Try case-insensitive search
        const idxLower = sourceText.toLowerCase().indexOf(searchText.toLowerCase());
        if (idxLower >= 0) {
          const beforeText = sourceText.substring(0, idxLower);
          const startLine = (beforeText.match(/\n/g) || []).length + 1;
          const matchedText = sourceText.substring(idxLower, idxLower + searchText.length);
          const lineSpan = (matchedText.match(/\n/g) || []).length;
          const endLine = startLine + lineSpan;

          this._highlightIOCInPlaintext(plaintextTable, startLine, endLine);
          return;
        }
      }
    }

    // ── Fallback for non-plaintext content: TreeWalker-based highlighting ──
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
              mark.className = 'ioc-highlight-flash';
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
  },

  // ── Highlight IOC lines in plaintext view ───────────────────────────────
  _highlightIOCInPlaintext(table, startLine, endLine) {
    // Clear any existing IOC highlights
    this._clearIOCHighlight();

    const rows = table.rows;
    const start = startLine - 1;  // Convert to 0-indexed
    const end = endLine - 1;

    for (let i = start; i <= end && i < rows.length; i++) {
      rows[i].classList.add('ioc-highlight-line');
      rows[i].classList.add('ioc-highlight-flash');
    }

    // Scroll the first highlighted row into view
    if (start < rows.length) {
      rows[start].scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

    // Remove flash effect after animation, but keep the highlight briefly
    setTimeout(() => {
      for (let i = start; i <= end && i < rows.length; i++) {
        rows[i].classList.remove('ioc-highlight-flash');
      }
    }, 2000);

    // Remove highlight entirely after a longer delay
    setTimeout(() => {
      this._clearIOCHighlight();
    }, 4000);
  },

  // ── Clear IOC line highlights ───────────────────────────────────────────
  _clearIOCHighlight() {
    const pc = document.getElementById('page-container');
    if (!pc) return;
    const highlighted = pc.querySelectorAll('.ioc-highlight-line');
    for (const el of highlighted) {
      el.classList.remove('ioc-highlight-line', 'ioc-highlight-flash');
    }
  },

  // ── Highlight YARA match inline with character-level precision ──────────
  _highlightYaraMatchInline(table, sourceText, offset, length) {
    // Clear any existing YARA highlights
    this._clearYaraHighlight();

    // Calculate which line the offset falls on
    const beforeText = sourceText.substring(0, offset);
    const lineIndex = (beforeText.match(/\n/g) || []).length;  // 0-indexed

    // Calculate character position within the line
    const lastNewline = beforeText.lastIndexOf('\n');
    const charPos = lastNewline === -1 ? offset : offset - lastNewline - 1;

    const rows = table.rows;
    if (lineIndex >= rows.length) return;

    const row = rows[lineIndex];
    const codeCell = row.querySelector('.plaintext-code');
    if (!codeCell) return;

    // Check if syntax highlighting is applied (HTML content)
    const hasHighlighting = codeCell.innerHTML !== codeCell.textContent;

    if (hasHighlighting) {
      // For syntax-highlighted content, we need to walk text nodes
      this._highlightInHtmlNode(codeCell, charPos, length);
    } else {
      // For plain text, we can use simple string manipulation
      const cellText = codeCell.textContent;
      const before = cellText.substring(0, charPos);
      const matched = cellText.substring(charPos, charPos + length);
      const after = cellText.substring(charPos + length);

      // Escape HTML entities
      const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

      codeCell.innerHTML = esc(before) +
        `<mark class="yara-highlight yara-highlight-flash">${esc(matched)}</mark>` +
        esc(after);
    }

    // Scroll the row into view
    row.scrollIntoView({ behavior: 'smooth', block: 'center' });

    // Also add a subtle line highlight
    row.classList.add('yara-line-highlight');

    // Remove highlights after animation
    setTimeout(() => {
      this._clearYaraHighlight();
    }, 3000);
  },

  // ── Highlight within syntax-highlighted HTML content ────────────────────
  _highlightInHtmlNode(container, charPos, length) {
    // Walk through text nodes to find the correct position
    const walker = document.createTreeWalker(container, NodeFilter.SHOW_TEXT, null);
    let currentPos = 0;
    let node;
    let startNode = null, startOffset = 0;
    let endNode = null, endOffset = 0;

    while ((node = walker.nextNode())) {
      const nodeLen = node.textContent.length;
      const nodeEnd = currentPos + nodeLen;

      // Find start position
      if (!startNode && charPos < nodeEnd) {
        startNode = node;
        startOffset = charPos - currentPos;
      }

      // Find end position
      if (startNode && charPos + length <= nodeEnd) {
        endNode = node;
        endOffset = charPos + length - currentPos;
        break;
      }

      currentPos = nodeEnd;
    }

    if (!startNode) return;  // Could not find position

    // If start and end are in the same node, simple case
    if (startNode === endNode) {
      const text = startNode.textContent;
      const before = text.substring(0, startOffset);
      const matched = text.substring(startOffset, endOffset);
      const after = text.substring(endOffset);

      const frag = document.createDocumentFragment();
      if (before) frag.appendChild(document.createTextNode(before));

      const mark = document.createElement('mark');
      mark.className = 'yara-highlight yara-highlight-flash';
      mark.textContent = matched;
      frag.appendChild(mark);

      if (after) frag.appendChild(document.createTextNode(after));

      startNode.parentNode.replaceChild(frag, startNode);
    } else {
      // Multi-node match: wrap from startNode to endNode
      // For simplicity, just highlight the first node portion and line
      const text = startNode.textContent;
      const before = text.substring(0, startOffset);
      const matched = text.substring(startOffset);

      const frag = document.createDocumentFragment();
      if (before) frag.appendChild(document.createTextNode(before));

      const mark = document.createElement('mark');
      mark.className = 'yara-highlight yara-highlight-flash';
      mark.textContent = matched;
      frag.appendChild(mark);

      startNode.parentNode.replaceChild(frag, startNode);
    }
  },

  // ── Clear YARA inline highlights ────────────────────────────────────────
  _clearYaraHighlight() {
    const pc = document.getElementById('page-container');
    if (!pc) return;

    // Remove line highlights
    const highlighted = pc.querySelectorAll('.yara-line-highlight');
    for (const el of highlighted) {
      el.classList.remove('yara-line-highlight');
    }

    // Remove inline mark elements and restore text
    const marks = pc.querySelectorAll('mark.yara-highlight');
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

  // ── Highlight YARA match in CSV detail pane ─────────────────────────────
  _highlightYaraMatchInCsv(csvView, sourceText, offset, length) {
    // Clear any existing highlights first
    this._clearYaraHighlight();

    const filters = csvView._csvFilters;
    if (!filters || !filters.dataRows) return;

    // Find which row contains this offset
    let targetRow = null;
    for (const r of filters.dataRows) {
      if (offset >= r.offsetStart && offset < r.offsetEnd) {
        targetRow = r;
        break;
      }
    }

    if (!targetRow) return;

    const matchText = sourceText.substring(offset, offset + length);
    const dataIdx = targetRow.dataIndex;

    // Use virtual scrolling API to scroll to and expand the row
    if (filters.scrollToRow) {
      filters.scrollToRow(dataIdx, false); // Don't use default highlight, we'll do YARA-specific highlight

      // Wait for virtual scroll to render, then highlight the match
      setTimeout(() => {
        // Find the rendered row element
        const tbody = csvView.querySelector('tbody');
        const tr = tbody && tbody.querySelector(`tr[data-idx="${dataIdx}"]`);
        if (!tr) return;

        // Add row highlight
        tr.classList.add('csv-yara-row-highlight');

        // Find the detail row (next sibling)
        const detailTr = tr.nextElementSibling;
        if (!detailTr || !detailTr.classList.contains('csv-detail-row')) return;

        // Find and highlight the match in the detail pane
        const detailPane = detailTr.querySelector('.csv-detail-pane');
        if (detailPane) {
          const detailVals = detailPane.querySelectorAll('.csv-detail-val');
          let found = false;
          for (const valEl of detailVals) {
            if (found) break;
            const cellText = valEl.textContent;
            
            // Try exact match first, then case-insensitive (for nocase YARA rules)
            let matchIdx = cellText.indexOf(matchText);
            let actualMatch = matchText;
            if (matchIdx === -1) {
              matchIdx = cellText.toLowerCase().indexOf(matchText.toLowerCase());
              if (matchIdx !== -1) {
                actualMatch = cellText.substring(matchIdx, matchIdx + matchText.length);
              }
            }
            
            if (matchIdx !== -1) {
              // Found the match - highlight it
              const before = cellText.substring(0, matchIdx);
              const matched = cellText.substring(matchIdx, matchIdx + actualMatch.length);
              const after = cellText.substring(matchIdx + actualMatch.length);

              // Escape HTML entities
              const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

              valEl.innerHTML = esc(before) +
                `<mark class="csv-yara-highlight csv-yara-highlight-flash">${esc(matched)}</mark>` +
                esc(after);

              // Scroll the highlighted element into view within the detail pane
              const mark = valEl.querySelector('.csv-yara-highlight');
              if (mark) {
                mark.scrollIntoView({ behavior: 'smooth', block: 'center' });
              }
              found = true;
            }
          }
        }

        // Remove highlights after animation
        setTimeout(() => {
          tr.classList.remove('csv-yara-row-highlight');
          const marks = csvView.querySelectorAll('mark.csv-yara-highlight');
          for (const mark of marks) {
            mark.classList.remove('csv-yara-highlight-flash');
          }
        }, 3000);

        // Clean up mark elements after longer delay
        setTimeout(() => {
          const marks = csvView.querySelectorAll('mark.csv-yara-highlight');
          for (const mark of marks) {
            const textNode = document.createTextNode(mark.textContent);
            mark.parentNode.replaceChild(textNode, mark);
          }
          // Normalize
          const detailVals = csvView.querySelectorAll('.csv-detail-val');
          for (const cell of detailVals) {
            cell.normalize();
          }
        }, 5000);
      }, 400); // Wait for virtual scroll to complete
    }
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
    // Ensure Signatures & IOCs section is open
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
