// ════════════════════════════════════════════════════════════════════════════
// App — YARA rule editor dialog, scanning, and result display
// Depends on: yara-engine.js
// ════════════════════════════════════════════════════════════════════════════
Object.assign(App.prototype, {

  /** Open the YARA rules dialog. */
  _openYaraDialog() {
    // Prevent duplicate
    if (document.getElementById('yara-dialog')) return;

    const overlay = document.createElement('div');
    overlay.id = 'yara-dialog';
    overlay.className = 'yara-overlay';

    const dialog = document.createElement('div');
    dialog.className = 'yara-dialog';

    // ── Header ──────────────────────────────────────────────────────────
    const header = document.createElement('div');
    header.className = 'yara-header';
    const title = document.createElement('span');
    title.className = 'yara-title';
    title.textContent = '📐 YARA Rules';
    header.appendChild(title);
    const closeBtn = document.createElement('button');
    closeBtn.className = 'yara-close';
    closeBtn.textContent = '✕';
    closeBtn.title = 'Close (Esc)';
    closeBtn.addEventListener('click', () => this._closeYaraDialog());
    header.appendChild(closeBtn);
    dialog.appendChild(header);

    // ── Toolbar ─────────────────────────────────────────────────────────
    const toolbar = document.createElement('div');
    toolbar.className = 'yara-toolbar';

    const loadBtn = document.createElement('button');
    loadBtn.className = 'tb-btn yara-tb-btn';
    loadBtn.textContent = '📂 Load .yar';
    loadBtn.title = 'Load YARA rules from file';
    loadBtn.addEventListener('click', () => this._yaraLoadFile());
    toolbar.appendChild(loadBtn);

    const saveBtn = document.createElement('button');
    saveBtn.className = 'tb-btn yara-tb-btn';
    saveBtn.textContent = '💾 Save .yar';
    saveBtn.title = 'Download rules as .yar file';
    saveBtn.addEventListener('click', () => this._yaraSaveFile());
    toolbar.appendChild(saveBtn);

    const validateBtn = document.createElement('button');
    validateBtn.className = 'tb-btn yara-tb-btn';
    validateBtn.textContent = '✓ Validate';
    validateBtn.title = 'Check rules for syntax errors';
    validateBtn.addEventListener('click', () => this._yaraValidate());
    toolbar.appendChild(validateBtn);

    const spacer = document.createElement('span');
    spacer.style.flex = '1';
    toolbar.appendChild(spacer);

    const scanBtn = document.createElement('button');
    scanBtn.className = 'tb-btn yara-scan-btn';
    scanBtn.textContent = '▶ Run Scan';
    scanBtn.title = 'Scan loaded file against these rules';
    scanBtn.addEventListener('click', () => this._yaraRunScan());
    toolbar.appendChild(scanBtn);

    dialog.appendChild(toolbar);

    // ── Editor ──────────────────────────────────────────────────────────
    const editorWrap = document.createElement('div');
    editorWrap.className = 'yara-editor-wrap';
    const editor = document.createElement('textarea');
    editor.id = 'yara-editor';
    editor.className = 'yara-editor';
    editor.spellcheck = false;
    editor.placeholder = 'Paste or type YARA rules here…';
    // Load from localStorage or use examples
    const saved = null;
    try { const s = localStorage.getItem('phishfinder_yara_rules'); if (s) editor.value = s; } catch(_){}
    if (!editor.value) editor.value = YaraEngine.EXAMPLE_RULES;
    // Auto-save on change
    editor.addEventListener('input', () => {
      try { localStorage.setItem('phishfinder_yara_rules', editor.value); } catch(_){}
    });
    editorWrap.appendChild(editor);
    dialog.appendChild(editorWrap);

    // ── Status bar ──────────────────────────────────────────────────────
    const status = document.createElement('div');
    status.id = 'yara-status';
    status.className = 'yara-status';
    status.textContent = 'Ready — load a file and click Run Scan';
    dialog.appendChild(status);

    // ── Results area ────────────────────────────────────────────────────
    const results = document.createElement('div');
    results.id = 'yara-results';
    results.className = 'yara-results';
    dialog.appendChild(results);

    // ── Hidden file input for loading .yar ──────────────────────────────
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.id = 'yara-file-input';
    fileInput.accept = '.yar,.yara,.txt';
    fileInput.style.display = 'none';
    fileInput.addEventListener('change', e => {
      const f = e.target.files[0];
      if (!f) return;
      const reader = new FileReader();
      reader.onload = () => {
        document.getElementById('yara-editor').value = reader.result;
        try { localStorage.setItem('phishfinder_yara_rules', reader.result); } catch(_){}
        this._yaraSetStatus(`Loaded: ${f.name}`, 'info');
      };
      reader.readAsText(f);
      fileInput.value = '';
    });
    dialog.appendChild(fileInput);

    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    // Close on overlay click or Esc
    overlay.addEventListener('click', e => { if (e.target === overlay) this._closeYaraDialog(); });
    this._yaraEscHandler = e => { if (e.key === 'Escape') this._closeYaraDialog(); };
    document.addEventListener('keydown', this._yaraEscHandler);

    // Focus editor
    setTimeout(() => editor.focus(), 100);
  },

  /** Close the YARA dialog. */
  _closeYaraDialog() {
    const el = document.getElementById('yara-dialog');
    if (el) el.remove();
    if (this._yaraEscHandler) {
      document.removeEventListener('keydown', this._yaraEscHandler);
      this._yaraEscHandler = null;
    }
  },

  /** Load .yar file into editor. */
  _yaraLoadFile() {
    const fi = document.getElementById('yara-file-input');
    if (fi) fi.click();
  },

  /** Save editor contents as .yar file. */
  _yaraSaveFile() {
    const editor = document.getElementById('yara-editor');
    if (!editor) return;
    const blob = new Blob([editor.value], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'phishfinder_rules.yar';
    a.click();
    URL.revokeObjectURL(url);
    this._yaraSetStatus('Rules saved to phishfinder_rules.yar', 'info');
  },

  /** Validate YARA rules syntax. */
  _yaraValidate() {
    const editor = document.getElementById('yara-editor');
    if (!editor || !editor.value.trim()) {
      this._yaraSetStatus('No rules to validate', 'error');
      return;
    }
    const result = YaraEngine.validate(editor.value);
    if (result.valid) {
      this._yaraSetStatus(`✓ Valid — ${result.ruleCount} rule(s) parsed successfully`, 'success');
    } else {
      this._yaraSetStatus(`✗ ${result.errors.join('; ')}`, 'error');
    }
  },

  /** Run YARA scan against currently loaded file. */
  _yaraRunScan() {
    if (!this._fileBuffer) {
      this._yaraSetStatus('No file loaded — open a file first, then scan', 'error');
      return;
    }
    const editor = document.getElementById('yara-editor');
    if (!editor || !editor.value.trim()) {
      this._yaraSetStatus('No YARA rules defined', 'error');
      return;
    }

    this._yaraSetStatus('Parsing rules…', 'info');

    const { rules, errors } = YaraEngine.parseRules(editor.value);
    if (errors.length) {
      this._yaraSetStatus(`Parse errors: ${errors.join('; ')}`, 'error');
      return;
    }
    if (!rules.length) {
      this._yaraSetStatus('No rules found', 'error');
      return;
    }

    this._yaraSetStatus(`Scanning ${rules.length} rule(s)…`, 'info');

    // Run scan (use setTimeout to allow UI update)
    setTimeout(() => {
      try {
        const t0 = performance.now();
        const results = YaraEngine.scan(this._fileBuffer, rules);
        const elapsed = ((performance.now() - t0) / 1000).toFixed(2);

        if (results.length === 0) {
          this._yaraSetStatus(`✓ Scan complete in ${elapsed}s — no rules matched`, 'success');
          this._yaraRenderResults([]);
        } else {
          this._yaraSetStatus(`⚠ ${results.length} rule(s) matched in ${elapsed}s`, 'warning');
          this._yaraRenderResults(results);
        }

        // Store YARA results in findings for sidebar display
        this._yaraResults = results;
        if (this.findings) {
          this._updateSidebarWithYara(results);
        }
      } catch (e) {
        this._yaraSetStatus(`Scan error: ${e.message}`, 'error');
      }
    }, 50);
  },

  /** Set YARA status bar text + style. */
  _yaraSetStatus(text, type) {
    const el = document.getElementById('yara-status');
    if (!el) return;
    el.textContent = text;
    el.className = 'yara-status yara-status-' + (type || 'info');
  },

  /** Render YARA scan results into the results panel. */
  _yaraRenderResults(results) {
    const container = document.getElementById('yara-results');
    if (!container) return;
    container.innerHTML = '';

    if (!results.length) {
      const empty = document.createElement('div');
      empty.className = 'yara-no-results';
      empty.textContent = 'No matches';
      container.appendChild(empty);
      return;
    }

    for (const r of results) {
      const card = document.createElement('div');
      card.className = 'yara-result-card';

      const hdr = document.createElement('div');
      hdr.className = 'yara-result-header';
      const name = document.createElement('span');
      name.className = 'yara-rule-name';
      name.textContent = r.ruleName;
      hdr.appendChild(name);
      if (r.tags) {
        const tags = document.createElement('span');
        tags.className = 'yara-rule-tags';
        tags.textContent = r.tags;
        hdr.appendChild(tags);
      }
      const badge = document.createElement('span');
      badge.className = 'badge badge-high';
      badge.textContent = 'MATCH';
      hdr.appendChild(badge);
      card.appendChild(hdr);

      // String matches
      for (const sm of r.matches) {
        const row = document.createElement('div');
        row.className = 'yara-match-row';
        const id = document.createElement('span');
        id.className = 'yara-match-id';
        id.textContent = sm.id;
        row.appendChild(id);
        const val = document.createElement('span');
        val.className = 'yara-match-val';
        val.textContent = sm.value;
        row.appendChild(val);
        const count = document.createElement('span');
        count.className = 'yara-match-count';
        count.textContent = `${sm.offsets.length} hit${sm.offsets.length !== 1 ? 's' : ''}`;
        row.appendChild(count);

        // Show first few offsets
        if (sm.offsets.length > 0) {
          const offsets = document.createElement('div');
          offsets.className = 'yara-match-offsets';
          const displayed = sm.offsets.slice(0, 10);
          offsets.textContent = 'Offsets: ' + displayed.map(o => '0x' + o.toString(16)).join(', ');
          if (sm.offsets.length > 10) offsets.textContent += ` … (+${sm.offsets.length - 10} more)`;
          row.appendChild(offsets);
        }
        card.appendChild(row);
      }

      container.appendChild(card);
    }
  },

  /** Auto-run YARA scan when a file is loaded (uses saved or default rules). */
  _autoYaraScan() {
    if (!this._fileBuffer) return;
    let source = '';
    try { source = localStorage.getItem('phishfinder_yara_rules') || ''; } catch(_){}
    if (!source) source = YaraEngine.EXAMPLE_RULES;
    if (!source) return;

    const { rules } = YaraEngine.parseRules(source);
    if (!rules.length) return;

    try {
      const results = YaraEngine.scan(this._fileBuffer, rules);
      this._yaraResults = results;
      if (this.findings) this._updateSidebarWithYara(results);
    } catch(_){ /* silently ignore scan errors during auto-scan */ }
  },

  /** Update sidebar extracted tab with YARA results. */
  _updateSidebarWithYara(results) {
    if (!this.findings) return;
    // Remove any previous YARA findings
    this.findings.externalRefs = (this.findings.externalRefs || []).filter(r => r.type !== 'YARA Match');
    // Add new YARA findings
    for (const r of results) {
      const desc = (r.meta && r.meta.description) ? r.meta.description : null;
      const strings = r.matches.map(m => `${m.id}=${m.value}`).join(', ');
      let text = `Rule "${r.ruleName}"`;
      if (desc) text += ` — ${desc}`;
      text += ` — ${r.matches.length} string(s) matched: ${strings}`;
      this.findings.externalRefs.push({
        type: 'YARA Match',
        url: text,
        severity: 'high'
      });
    }
    // If YARA matches found, bump risk
    if (results.length > 0 && this.findings.risk === 'low') {
      this.findings.risk = 'medium';
    }
    // Re-render sidebar
    const fileName = (document.getElementById('file-info').textContent || '').split('·')[0].trim();
    this._renderSidebar(fileName, null);
  },

});
