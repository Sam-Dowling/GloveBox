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
    // Auto-open if any high-severity findings or any decoded content
    const hasHigh = encodedFindings.some(f => f.severity === 'high' || f.severity === 'critical');
    const hasDecoded = encodedFindings.some(f => f.decodedBytes);
    det.open = hasHigh || hasDecoded;

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

    // Severity summary bar
    const sevOrder = { critical: 0, high: 1, medium: 2, info: 3 };
    const high = encodedFindings.filter(f => f.severity === 'high').length;
    const med = encodedFindings.filter(f => f.severity === 'medium').length;
    const inf = encodedFindings.filter(f => f.severity === 'info').length;
    if (high || med || inf) {
      const bar = document.createElement('div'); bar.className = 'sev-bar';
      if (high) { const s = document.createElement('span'); s.style.color = '#721c24'; s.textContent = `🔴 ${high} high`; bar.appendChild(s); }
      if (med) { const s = document.createElement('span'); s.style.color = '#856404'; s.textContent = `🟡 ${med} medium`; bar.appendChild(s); }
      if (inf) { const s = document.createElement('span'); s.style.color = '#666'; s.textContent = `🔵 ${inf} info`; bar.appendChild(s); }
      body.appendChild(bar);
    }

    // Render each finding as a card
    const sorted = [...encodedFindings].sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));
    for (const finding of sorted) {
      const card = document.createElement('div');
      card.className = `enc-finding-card enc-sev-${finding.severity}`;

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

      // IOCs found in decoded content
      if (finding.iocs && finding.iocs.length) {
        const iocLine = document.createElement('div');
        iocLine.className = 'enc-finding-iocs';
        const counts = {};
        for (const ioc of finding.iocs) counts[ioc.type] = (counts[ioc.type] || 0) + 1;
        iocLine.textContent = 'IOCs: ' + Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', ');
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
    }

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

    // Severity summary bar
    const crit = refs.filter(r => r.severity === 'critical').length;
    const high = refs.filter(r => r.severity === 'high').length;
    const med = refs.filter(r => r.severity === 'medium').length;
    const inf = refs.filter(r => r.severity === 'info').length;
    const bar = document.createElement('div'); bar.className = 'sev-bar';
    if (crit) { const s = document.createElement('span'); s.style.color = '#4a1a7a'; s.textContent = `🟣 ${crit} critical`; bar.appendChild(s); }
    if (high) { const s = document.createElement('span'); s.style.color = '#721c24'; s.textContent = `🔴 ${high} high`; bar.appendChild(s); }
    if (med) { const s = document.createElement('span'); s.style.color = '#856404'; s.textContent = `🟡 ${med} medium`; bar.appendChild(s); }
    if (inf) { const s = document.createElement('span'); s.style.color = '#666'; s.textContent = `🔵 ${inf} info`; bar.appendChild(s); }
    body.appendChild(bar);

    // Filter search
    const srch = document.createElement('input');
    srch.type = 'text'; srch.placeholder = 'Filter findings…'; srch.className = 'ext-search';
    body.appendChild(srch);

    // Download all
    const dl = document.createElement('button'); dl.className = 'tb-btn';
    dl.style.cssText = 'font-size:11px;margin-bottom:8px;width:100%;display:block;';
    dl.textContent = '⬇ Download All (.txt)';
    dl.addEventListener('click', () => this._downloadExtracted(refs, fileName));
    body.appendChild(dl);

    // Table
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
      const td1 = document.createElement('td'); td1.textContent = ref.type;
      td1.className = 'ioc-type ioc-type-' + ref.type.toLowerCase().replace(/\s+/g, '-');
      const td2 = document.createElement('td'); td2.className = 'ext-val';
      const sp = document.createElement('span'); sp.textContent = ref.url; td2.appendChild(sp);
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

      tbody.appendChild(tr);
    }
    tbl.appendChild(tbody); body.appendChild(tbl);

    // Filter handler
    srch.addEventListener('input', () => {
      const q = srch.value.toLowerCase();
      for (const tr of tbody.rows) tr.classList.toggle('hidden', !!q && !tr.dataset.search.includes(q));
    });

    det.appendChild(body);
    container.appendChild(det);
  },

  // ── Navigate to finding in content view ─────────────────────────────────
  _navigateToFinding(ref, rowEl) {
    // Visual feedback — flash the clicked row
    rowEl.classList.add('ioc-flash');
    setTimeout(() => rowEl.classList.remove('ioc-flash'), 600);

    // Check if we have an EVTX view with filter controls
    const pc = document.getElementById('page-container');
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
          // Auto-expand all filtered results
          if (filters.expandAll) filters.expandAll();
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
        // Auto-expand all filtered results
        if (filters.expandAll) filters.expandAll();
        filters.scrollContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
        const filterBar = evtxView.querySelector('.evtx-filter-bar');
        if (filterBar) {
          filterBar.classList.add('evtx-filter-flash');
          setTimeout(() => filterBar.classList.remove('evtx-filter-flash'), 1000);
        }
        return;
      }
    }

    // Check if we have a CSV view with filter controls
    const csvView = pc && pc.querySelector('.csv-view');
    if (csvView && csvView._csvFilters) {
      const filters = csvView._csvFilters;
      const searchVal = ref.url || '';
      if (searchVal) {
        // For hashes like "SHA256:ABCDEF...", just search the hash value part
        let searchTerm = searchVal;
        const hashMatch = searchVal.match(/^(?:SHA256|SHA1|MD5|IMPHASH):(.+)$/i);
        if (hashMatch) searchTerm = hashMatch[1];
        // Truncate very long values
        if (searchTerm.length > 80) searchTerm = searchTerm.substring(0, 80);

        filters.filterInput.value = searchTerm;
        filters.applyFilter();
        filters.scrollToFirstMatch();
        filters.scrollContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // Flash the filter bar for feedback
        const filterBar = csvView.querySelector('.csv-filter-bar');
        if (filterBar) {
          filterBar.classList.add('csv-filter-flash');
          setTimeout(() => filterBar.classList.remove('csv-filter-flash'), 1000);
        }
        return;
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

});
