// ════════════════════════════════════════════════════════════════════════════
// App — YARA rule viewer dialog, scanning, and result display
// Depends on: yara-engine.js
// ════════════════════════════════════════════════════════════════════════════

// Keyword set for YARA syntax highlighting (module-level for reuse)
const _YARA_KW = new Set([
  'rule', 'meta', 'strings', 'condition', 'import', 'include', 'private', 'global',
  'and', 'or', 'not', 'any', 'all', 'of', 'them', 'true', 'false', 'at', 'in', 'for',
  'filesize', 'entrypoint', 'fullword', 'nocase', 'wide', 'ascii',
  'uint8', 'uint16', 'uint32', 'int8', 'int16', 'int32'
]);

// localStorage key for user-uploaded YARA rules
const _YARA_UPLOAD_KEY = 'loupe_uploaded_yara';

Object.assign(App.prototype, {

  // ═══════════════════════════════════════════════════════════════════════
  //  Category-aware YARA parser
  // ═══════════════════════════════════════════════════════════════════════

  /** Parse DEFAULT_YARA_RULES into categorized, sorted rule groups.
   *  @param {string} source — full YARA source with // @category: markers
   *  @returns {Array<{name:string, rules:Array, isUploaded?:boolean}>} */
  _parseYaraCategories(source) {
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const validSevs = new Set(['critical', 'high', 'medium', 'low', 'info']);
    const parts = source.split(/^\/\/\s*@category:\s*(.+)$/m);

    // Fallback: no markers → one group
    if (parts.length <= 1) {
      return [{ name: 'All Rules', rules: this._extractRulesFromSource(source, sevOrder, validSevs) }];
    }

    const categories = [];
    for (let i = 1; i < parts.length; i += 2) {
      const catName = parts[i].trim();
      const catSource = parts[i + 1] || '';
      const rules = this._extractRulesFromSource(catSource, sevOrder, validSevs);
      if (rules.length) categories.push({ name: catName, rules });
    }
    categories.sort((a, b) => a.name.localeCompare(b.name));

    // Prepend uploaded rules category if any exist
    const uploaded = this._getUploadedYaraRules();
    if (uploaded) {
      const upRules = this._extractRulesFromSource(uploaded, sevOrder, validSevs);
      if (upRules.length) {
        categories.unshift({ name: 'Uploaded', rules: upRules, isUploaded: true });
      }
    }

    return categories;
  },

  /** Extract rules from a YARA source segment, returning parsed + raw source.
   *  @private */
  _extractRulesFromSource(catSource, sevOrder, validSevs) {
    const { rules: parsed } = YaraEngine.parseRules(catSource);
    const rawRx = /\brule\s+\w+\s*(?::\s*[\w\s]+?)?\s*\{[\s\S]*?\n\}/g;
    const rawBlocks = [];
    let m;
    while ((m = rawRx.exec(catSource)) !== null) rawBlocks.push(m[0]);

    const rules = parsed.map((r, idx) => {
      const rawSev = (r.meta && r.meta.severity) ? r.meta.severity.toLowerCase() : 'high';
      return {
        name: r.name,
        tags: r.tags,
        meta: r.meta,
        severity: validSevs.has(rawSev) ? rawSev : 'high',
        description: (r.meta && r.meta.description) ? r.meta.description : '',
        rawSource: rawBlocks[idx] || ''
      };
    });
    rules.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));
    return rules;
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  Uploaded rules persistence (localStorage)
  // ═══════════════════════════════════════════════════════════════════════

  /** Get user-uploaded YARA rules from localStorage. */
  _getUploadedYaraRules() {
    try { return localStorage.getItem(_YARA_UPLOAD_KEY) || ''; }
    catch (_) { return ''; }
  },

  /** Set user-uploaded YARA rules in localStorage. */
  _setUploadedYaraRules(source) {
    try {
      if (source) localStorage.setItem(_YARA_UPLOAD_KEY, source);
      else localStorage.removeItem(_YARA_UPLOAD_KEY);
    } catch (_) { /* storage full or blocked */ }
  },

  /** Remove a single rule by name from uploaded rules. Returns true if removed. */
  _removeUploadedRule(ruleName) {
    const src = this._getUploadedYaraRules();
    if (!src) return false;
    const rx = new RegExp('\\brule\\s+' + ruleName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*(?::\\s*[\\w\\s]+?)?\\s*\\{[\\s\\S]*?\\n\\}', 'g');
    const newSrc = src.replace(rx, '').trim();
    this._setUploadedYaraRules(newSrc || '');
    return newSrc !== src;
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  YARA syntax highlighter (tokenizer-based)
  // ═══════════════════════════════════════════════════════════════════════

  /** Syntax-highlight YARA rule source → HTML string. */
  _highlightYaraSyntax(source) {
    const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    let out = '';
    let i = 0;
    const n = source.length;
    const s = source;

    while (i < n) {
      const c = s[i];

      // ── Block comment /* … */ ────────────────────────────────────────
      if (c === '/' && s[i + 1] === '*') {
        const end = s.indexOf('*/', i + 2);
        const j = end < 0 ? n : end + 2;
        out += '<span class="yr-cmt">' + esc(s.slice(i, j)) + '</span>';
        i = j; continue;
      }

      // ── Line comment // … ───────────────────────────────────────────
      if (c === '/' && s[i + 1] === '/') {
        const end = s.indexOf('\n', i);
        const j = end < 0 ? n : end;
        out += '<span class="yr-cmt">' + esc(s.slice(i, j)) + '</span>';
        i = j; continue;
      }

      // ── String "…" ──────────────────────────────────────────────────
      if (c === '"') {
        let j = i + 1;
        while (j < n && s[j] !== '"') { if (s[j] === '\\') j++; j++; }
        if (j < n) j++; // closing quote
        out += '<span class="yr-str">' + esc(s.slice(i, j)) + '</span>';
        i = j; continue;
      }

      // ── Regex /pattern/flags (only after = on same line) ────────────
      if (c === '/') {
        let k = i - 1;
        while (k >= 0 && s[k] === ' ') k--;
        if (k >= 0 && s[k] === '=') {
          let j = i + 1;
          let escaped = false;
          while (j < n && (s[j] !== '/' || escaped) && s[j] !== '\n') {
            escaped = !escaped && s[j] === '\\';
            j++;
          }
          if (j < n && s[j] === '/') {
            j++; // closing slash
            while (j < n && /[ism]/.test(s[j])) j++; // flags
            out += '<span class="yr-rx">' + esc(s.slice(i, j)) + '</span>';
            i = j; continue;
          }
        }
        out += esc(c); i++; continue;
      }

      // ── Hex pattern { … } ──────────────────────────────────────────
      if (c === '{') {
        const end = s.indexOf('}', i + 1);
        if (end > 0 && end - i < 2000) {
          const inner = s.slice(i + 1, end);
          if (/^[\s0-9a-fA-F?|\[\]\-()~]+$/.test(inner) && inner.trim().length > 0) {
            out += '<span class="yr-hex">' + esc(s.slice(i, end + 1)) + '</span>';
            i = end + 1; continue;
          }
        }
        out += esc(c); i++; continue;
      }

      // ── Variable $name, #name, @name ────────────────────────────────
      if ((c === '$' || c === '#' || c === '@') && i + 1 < n && /\w/.test(s[i + 1])) {
        let j = i + 1;
        while (j < n && /\w/.test(s[j])) j++;
        out += '<span class="yr-var">' + esc(s.slice(i, j)) + '</span>';
        i = j; continue;
      }

      // ── Word (keyword or identifier) ────────────────────────────────
      if (/[a-zA-Z_]/.test(c)) {
        let j = i;
        while (j < n && /\w/.test(s[j])) j++;
        const word = s.slice(i, j);
        if (_YARA_KW.has(word)) {
          out += '<span class="yr-kw">' + esc(word) + '</span>';
        } else {
          out += esc(word);
        }
        i = j; continue;
      }

      // ── Number ──────────────────────────────────────────────────────
      if (/\d/.test(c)) {
        let j = i;
        if (c === '0' && i + 1 < n && /[xX]/.test(s[i + 1])) {
          j += 2;
          while (j < n && /[0-9a-fA-F]/.test(s[j])) j++;
        } else {
          while (j < n && /\d/.test(s[j])) j++;
        }
        out += '<span class="yr-num">' + esc(s.slice(i, j)) + '</span>';
        i = j; continue;
      }

      // ── Everything else ─────────────────────────────────────────────
      out += esc(c);
      i++;
    }
    return out;
  },

  /** Escape HTML for safe insertion. */
  _escHtmlYara(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  },

  /**
   * Escape a YARA condition expression and wrap each `$var` reference so
   * matched identifiers render bold and unmatched ones render dimmed.
   * Shared by the YARA results dialog and the sidebar IOC rows so the two
   * surfaces can't drift in how they describe the "reason for detection".
   *
   * @param {string} condition        Raw rule condition (e.g. "$a and #b > 2").
   * @param {Set<string>} matchedIds  Lowercased identifiers that produced hits.
   * @returns {string|null}           HTML fragment, or null when the condition
   *                                  is trivial (`any of them` / `N of them`)
   *                                  and wouldn't add explanatory value.
   */
  _yaraBoldCond(condition, matchedIds) {
    const raw = (condition || '').trim();
    if (!raw) return null;
    if (/^any\s+of\s+them$/i.test(raw)) return null;
    if (/^all\s+of\s+them$/i.test(raw)) return null;
    if (/^\d+\s+of\s+them$/i.test(raw)) return null;
    return this._escHtmlYara(raw).replace(/\$\w+\*?/g, (ref) => {
      const key = ref.replace(/\*$/, '').toLowerCase();
      if (matchedIds.has(key)) {
        return '<strong>' + ref + '</strong>';
      }
      return '<span class="yara-match-unmatched">' + ref + '</span>';
    });
  },


  // ═══════════════════════════════════════════════════════════════════════
  //  File helpers (save / upload / import)
  // ═══════════════════════════════════════════════════════════════════════

  /** Import YARA rules from a File object — shared by Upload button and drag-and-drop.
   *  Validates, merges with existing uploaded rules, shows status, and rebuilds dialog.
   *  @param {File} file */
  _yaraImportFile(file) {
    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result;
      const { valid, errors, warnings, ruleCount } = YaraEngine.validate(text);
      if (!valid) {
        this._yaraSetStatus('Upload failed: ' + (errors.length ? errors.join('; ') : 'No valid rules found'), 'error');
        return;
      }
      // Merge with existing uploaded rules
      const existing = this._getUploadedYaraRules();
      const merged = existing ? existing + '\n' + text : text;
      this._setUploadedYaraRules(merged);
      let uploadMsg = '\u2713 Uploaded ' + ruleCount + ' rule(s) from ' + file.name;
      if (warnings && warnings.length) {
        uploadMsg += ' \u2014 ' + warnings.length + ' warning(s): ' + warnings.join('; ');
      }
      this._yaraSetStatus(uploadMsg, warnings && warnings.length ? 'warning' : 'success');
      // Rebuild dialog
      this._closeYaraDialog();
      this._openYaraDialog();
    };
    reader.readAsText(file);
  },

  /** Download a string as a .yar file. */
  _yaraSaveFile(content, filename) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 100);
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  Combine all rules source (built-in + uploaded)
  // ═══════════════════════════════════════════════════════════════════════

  /** Get combined YARA rules source (built-in + uploaded). */
  _getAllYaraSource() {
    let src = YaraEngine.EXAMPLE_RULES || '';
    const uploaded = this._getUploadedYaraRules();
    if (uploaded) src += '\n' + uploaded;
    return src;
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  Dialog lifecycle
  // ═══════════════════════════════════════════════════════════════════════

  /** Open the YARA rules viewer dialog.
   *  @param {string} [filterRule] — optional rule name to auto-filter to */
  _openYaraDialog(filterRule) {
    // If already open, just update search filter
    if (document.getElementById('yara-dialog')) {
      if (filterRule) {
        const srch = document.getElementById('yara-search');
        if (srch) {
          srch.value = filterRule;
          srch.dispatchEvent(new Event('input'));
        }
      }
      return;
    }

    const overlay = document.createElement('div');
    overlay.id = 'yara-dialog';
    overlay.className = 'yara-overlay';

    const dialog = document.createElement('div');
    dialog.className = 'yara-dialog';

    // ── Parse rules into categories ──────────────────────────────────
    const source = YaraEngine.EXAMPLE_RULES;
    const categories = this._parseYaraCategories(source);
    const totalRules = categories.reduce((sum, c) => sum + c.rules.length, 0);

    // ── Header ──────────────────────────────────────────────────────
    const header = document.createElement('div');
    header.className = 'yara-header';
    const title = document.createElement('span');
    title.className = 'yara-title';
    title.id = 'yara-title';
    title.textContent = '\u{1F4D0} YARA Rules (' + totalRules + ')';
    header.appendChild(title);
    const closeBtn = document.createElement('button');
    closeBtn.className = 'yara-close';
    closeBtn.textContent = '\u2715';
    closeBtn.title = 'Close (Esc)';
    closeBtn.addEventListener('click', () => this._closeYaraDialog());
    header.appendChild(closeBtn);
    dialog.appendChild(header);

    // ── Toolbar (search + save + upload + scan) ─────────────────────
    const toolbar = document.createElement('div');
    toolbar.className = 'yara-toolbar';

    const searchWrap = document.createElement('div');
    searchWrap.className = 'yara-search-wrap';

    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.id = 'yara-search';
    searchInput.className = 'yara-search';
    searchInput.placeholder = 'Search rules\u2026';
    searchInput.spellcheck = false;
    searchWrap.appendChild(searchInput);

    const prevBtn = document.createElement('button');
    prevBtn.className = 'yara-search-nav';
    prevBtn.textContent = '\u25C0';
    prevBtn.title = 'Previous match (Shift+Enter)';
    searchWrap.appendChild(prevBtn);

    const nextBtn = document.createElement('button');
    nextBtn.className = 'yara-search-nav';
    nextBtn.textContent = '\u25B6';
    nextBtn.title = 'Next match (Enter)';
    searchWrap.appendChild(nextBtn);

    const countSpan = document.createElement('span');
    countSpan.className = 'yara-search-count';
    countSpan.id = 'yara-search-count';
    searchWrap.appendChild(countSpan);

    toolbar.appendChild(searchWrap);

    const spacer = document.createElement('span');
    spacer.style.flex = '1';
    toolbar.appendChild(spacer);

    // ── Save dropdown button ────────────────────────────────────────
    const saveWrap = document.createElement('span');
    saveWrap.style.position = 'relative';
    saveWrap.style.display = 'inline-block';

    const saveBtn = document.createElement('button');
    saveBtn.className = 'tb-btn yara-tb-btn';
    saveBtn.textContent = '\u{1F4BE} Save';
    saveBtn.title = 'Save rules to .yar file';

    let saveMenuOpen = false;
    const saveMenu = document.createElement('div');
    saveMenu.className = 'yara-save-menu';
    saveMenu.style.display = 'none';

    const allItem = document.createElement('button');
    allItem.className = 'yara-save-menu-item';
    allItem.textContent = 'All Rules';
    allItem.addEventListener('click', () => {
      saveMenu.style.display = 'none';
      saveMenuOpen = false;
      this._yaraSaveFile(this._getAllYaraSource(), 'loupe-rules-all.yar');
    });
    saveMenu.appendChild(allItem);

    const upItem = document.createElement('button');
    upItem.className = 'yara-save-menu-item';
    upItem.textContent = 'Uploaded Only';
    const upSrc = this._getUploadedYaraRules();
    if (!upSrc) { upItem.disabled = true; }
    upItem.addEventListener('click', () => {
      saveMenu.style.display = 'none';
      saveMenuOpen = false;
      const u = this._getUploadedYaraRules();
      if (u) this._yaraSaveFile(u, 'loupe-rules-uploaded.yar');
    });
    saveMenu.appendChild(upItem);

    saveBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      saveMenuOpen = !saveMenuOpen;
      saveMenu.style.display = saveMenuOpen ? '' : 'none';
    });

    // Close save menu on any click outside
    const closeSaveMenu = () => { saveMenu.style.display = 'none'; saveMenuOpen = false; };
    overlay.addEventListener('click', closeSaveMenu);

    saveWrap.appendChild(saveMenu);
    saveWrap.appendChild(saveBtn);
    toolbar.appendChild(saveWrap);

    // ── Upload button ───────────────────────────────────────────────
    const uploadInput = document.createElement('input');
    uploadInput.type = 'file';
    uploadInput.accept = '.yar,.yara,.txt';
    uploadInput.style.display = 'none';

    const uploadBtn = document.createElement('button');
    uploadBtn.className = 'tb-btn yara-tb-btn';
    uploadBtn.textContent = '\u{1F4C2} Upload';
    uploadBtn.title = 'Upload .yar rules file';
    uploadBtn.addEventListener('click', () => uploadInput.click());

    uploadInput.addEventListener('change', () => {
      const file = uploadInput.files[0];
      if (!file) return;
      this._yaraImportFile(file);
      uploadInput.value = ''; // reset so same file can be re-uploaded
    });

    toolbar.appendChild(uploadInput);
    toolbar.appendChild(uploadBtn);

    // ── Info button (ℹ) ─────────────────────────────────────────────
    const infoBtn = document.createElement('button');
    infoBtn.className = 'yara-info-btn';
    infoBtn.textContent = 'i';
    infoBtn.title = 'YARA rule writing reference';
    infoBtn.addEventListener('click', () => this._openYaraInfoPopup(dialog));
    toolbar.appendChild(infoBtn);

    // ── Validate button ─────────────────────────────────────────────
    const validateBtn = document.createElement('button');
    validateBtn.className = 'tb-btn yara-validate-btn';
    validateBtn.textContent = '\u2714 Validate';
    validateBtn.title = 'Validate all rules (built-in + uploaded)';
    validateBtn.addEventListener('click', () => {
      const allSrc = this._getAllYaraSource();
      if (!allSrc.trim()) {
        this._yaraSetStatus('No rules to validate', 'error');
        return;
      }
      const { valid, errors, warnings, ruleCount } = YaraEngine.validate(allSrc);
      if (valid) {
        let msg = '\u2713 All ' + ruleCount + ' rule(s) validated successfully';
        if (warnings.length) {
          msg += ' \u2014 ' + warnings.length + ' warning(s): ' + warnings.join('; ');
        } else {
          msg += ' \u2014 no errors';
        }
        this._yaraSetStatus(msg, warnings.length ? 'warning' : 'success');
      } else {
        this._yaraSetStatus('\u2717 Validation failed: ' + errors.join('; '), 'error');
      }
    });
    toolbar.appendChild(validateBtn);

    // ── Scan button ─────────────────────────────────────────────────
    const scanBtn = document.createElement('button');
    scanBtn.className = 'tb-btn yara-scan-btn';
    scanBtn.textContent = '\u25B6 Run Scan';
    scanBtn.title = 'Scan loaded file against these rules';
    scanBtn.addEventListener('click', () => this._yaraRunScan());
    toolbar.appendChild(scanBtn);

    dialog.appendChild(toolbar);

    // ── Rule browser (scrollable accordion) ─────────────────────────
    const browser = document.createElement('div');
    browser.className = 'yara-browser';

    // Track all rule detail elements for search
    const allRuleEls = [];
    let matchedEls = [];
    let matchIdx = -1;

    for (const cat of categories) {
      const catEl = document.createElement('details');
      catEl.className = 'yara-cat';

      const catSum = document.createElement('summary');
      catSum.className = 'yara-cat-summary';
      const catNameSpan = document.createElement('span');
      catNameSpan.className = 'yara-cat-name';
      catNameSpan.textContent = cat.name;
      const catCountSpan = document.createElement('span');
      catCountSpan.className = 'yara-cat-count';
      catCountSpan.textContent = '(' + cat.rules.length + ')';
      catSum.appendChild(catNameSpan);
      catSum.appendChild(catCountSpan);

      // Red ✕ to clear all uploaded rules (on "Uploaded" category header)
      if (cat.isUploaded) {
        const catDelBtn = document.createElement('button');
        catDelBtn.className = 'yara-del-btn';
        catDelBtn.textContent = '\u2715';
        catDelBtn.title = 'Remove all uploaded rules';
        catDelBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          e.preventDefault();
          if (confirm('Remove all uploaded YARA rules?')) {
            this._setUploadedYaraRules('');
            this._yaraSetStatus('All uploaded rules removed', 'info');
            this._closeYaraDialog();
            this._openYaraDialog();
          }
        });
        catSum.appendChild(catDelBtn);
      }

      catEl.appendChild(catSum);

      const catBody = document.createElement('div');
      catBody.className = 'yara-cat-body';

      for (const rule of cat.rules) {
        const ruleEl = document.createElement('details');
        ruleEl.className = 'yara-rule-row';

        const ruleSum = document.createElement('summary');
        ruleSum.className = 'yara-rule-summary yara-rule-sev-' + rule.severity;

        const badge = document.createElement('span');
        badge.className = 'badge badge-' + rule.severity;
        badge.textContent = rule.severity;
        ruleSum.appendChild(badge);

        const nameSpan = document.createElement('span');
        nameSpan.className = 'yara-rule-name';
        nameSpan.textContent = rule.name;
        ruleSum.appendChild(nameSpan);

        if (rule.description) {
          const descSpan = document.createElement('span');
          descSpan.className = 'yara-rule-desc';
          descSpan.textContent = rule.description;
          ruleSum.appendChild(descSpan);
        }

        // Red ✕ to delete individual uploaded rule
        if (cat.isUploaded) {
          const delBtn = document.createElement('button');
          delBtn.className = 'yara-del-btn';
          delBtn.textContent = '\u2715';
          delBtn.title = 'Remove this uploaded rule';
          delBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            e.preventDefault();
            this._removeUploadedRule(rule.name);
            ruleEl.remove();
            // Update category count or remove category if empty
            const remaining = catBody.querySelectorAll('.yara-rule-row');
            if (remaining.length === 0) {
              catEl.remove();
            } else {
              catCountSpan.textContent = '(' + remaining.length + ')';
            }
            // Update total count
            const allRemaining = browser.querySelectorAll('.yara-rule-row');
            const titleEl = document.getElementById('yara-title');
            if (titleEl) titleEl.textContent = '\u{1F4D0} YARA Rules (' + allRemaining.length + ')';
          });
          ruleSum.appendChild(delBtn);
        }

        ruleEl.appendChild(ruleSum);

        // Lazy-load syntax highlighting on first expand
        let sourceRendered = false;
        ruleEl.addEventListener('toggle', () => {
          if (ruleEl.open && !sourceRendered) {
            const pre = document.createElement('pre');
            pre.className = 'yara-rule-source';
            const code = document.createElement('code');
            code.innerHTML = this._highlightYaraSyntax(rule.rawSource);
            pre.appendChild(code);
            ruleEl.appendChild(pre);
            sourceRendered = true;
          }
        });

        // Store refs for search
        ruleEl._catEl = catEl;
        ruleEl._rule = rule;
        ruleEl._searchText = (rule.name + ' ' + rule.description + ' ' + rule.rawSource).toLowerCase();
        allRuleEls.push(ruleEl);

        catBody.appendChild(ruleEl);
      }

      catEl.appendChild(catBody);
      browser.appendChild(catEl);
    }

    dialog.appendChild(browser);

    // ── Status bar ──────────────────────────────────────────────────
    const status = document.createElement('div');
    status.id = 'yara-status';
    status.className = 'yara-status';
    status.textContent = 'Ready \u2014 load a file and click Run Scan';
    dialog.appendChild(status);

    // ── Results area ────────────────────────────────────────────────
    const results = document.createElement('div');
    results.id = 'yara-results';
    results.className = 'yara-results';
    dialog.appendChild(results);

    // ── Search logic ────────────────────────────────────────────────
    const scrollToMatch = () => {
      const prev = browser.querySelector('.yara-rule-active');
      if (prev) prev.classList.remove('yara-rule-active');
      if (matchIdx >= 0 && matchIdx < matchedEls.length) {
        const el = matchedEls[matchIdx];
        el.classList.add('yara-rule-active');
        el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        countSpan.textContent = (matchIdx + 1) + '/' + matchedEls.length;
      }
    };

    const doSearch = () => {
      const q = searchInput.value.trim().toLowerCase();
      matchedEls = [];
      matchIdx = -1;

      // Remove active highlight
      const prevActive = browser.querySelector('.yara-rule-active');
      if (prevActive) prevActive.classList.remove('yara-rule-active');

      if (!q) {
        // Collapse everything — default state
        for (const re of allRuleEls) {
          re.style.display = '';
          re.open = false;
        }
        for (const catEl of browser.querySelectorAll('.yara-cat')) {
          catEl.style.display = '';
          catEl.open = false;
        }
        countSpan.textContent = '';
        return;
      }

      // Find matches and track categories with matches
      const catsWithMatches = new Set();
      for (const re of allRuleEls) {
        if (re._searchText.includes(q)) {
          re.style.display = '';
          re.open = true;
          catsWithMatches.add(re._catEl);
          matchedEls.push(re);
        } else {
          re.style.display = 'none';
          re.open = false;
        }
      }

      // Show/hide categories
      for (const catEl of browser.querySelectorAll('.yara-cat')) {
        if (catsWithMatches.has(catEl)) {
          catEl.style.display = '';
          catEl.open = true;
        } else {
          catEl.style.display = 'none';
        }
      }

      // Navigate to first match
      if (matchedEls.length) {
        matchIdx = 0;
        scrollToMatch();
      } else {
        countSpan.textContent = '0';
      }
    };

    let debounce;
    searchInput.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(doSearch, 150);
    });

    searchInput.addEventListener('keydown', (e) => {
      // Esc with text → clear search; Esc empty → let dialog close handler fire
      if (e.key === 'Escape' && searchInput.value) {
        e.stopPropagation();
        searchInput.value = '';
        doSearch();
        return;
      }
      if (e.key === 'Enter') {
        e.preventDefault();
        if (matchedEls.length) {
          matchIdx = e.shiftKey
            ? (matchIdx - 1 + matchedEls.length) % matchedEls.length
            : (matchIdx + 1) % matchedEls.length;
          scrollToMatch();
        }
      }
    });

    prevBtn.addEventListener('click', () => {
      if (matchedEls.length) {
        matchIdx = (matchIdx - 1 + matchedEls.length) % matchedEls.length;
        scrollToMatch();
      }
    });

    nextBtn.addEventListener('click', () => {
      if (matchedEls.length) {
        matchIdx = (matchIdx + 1) % matchedEls.length;
        scrollToMatch();
      }
    });

    // ── Drop hint overlay (shown during drag) ───────────────────────
    const dropHint = document.createElement('div');
    dropHint.className = 'yara-drop-hint';
    const dropHintSpan = document.createElement('span');
    dropHintSpan.textContent = '\u{1F4C2} Drop .yar / .yara file to upload rules';
    dropHint.appendChild(dropHintSpan);
    dialog.appendChild(dropHint);

    // ── Drag-and-drop .yar/.yara files onto dialog ──────────────────
    let _yaraDragCounter = 0;
    const _isYaraFile = (f) => /\.(yar|yara)$/i.test(f.name);

    dialog.addEventListener('dragenter', (e) => {
      e.preventDefault();
      _yaraDragCounter++;
      if (_yaraDragCounter === 1) dialog.classList.add('drag-over');
    });

    dialog.addEventListener('dragover', (e) => {
      e.preventDefault();
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
    });

    dialog.addEventListener('dragleave', () => {
      _yaraDragCounter--;
      if (_yaraDragCounter <= 0) {
        _yaraDragCounter = 0;
        dialog.classList.remove('drag-over');
      }
    });

    dialog.addEventListener('drop', (e) => {
      _yaraDragCounter = 0;
      dialog.classList.remove('drag-over');
      const mainDz = document.getElementById('drop-zone');
      if (mainDz) mainDz.classList.remove('drag-over');
      const files = e.dataTransfer?.files;
      if (!files || !files.length) return;
      const file = files[0];

      if (_isYaraFile(file)) {
        // YARA file → import as rules, stop event from reaching window handler
        e.preventDefault();
        e.stopPropagation();
        this._yaraImportFile(file);
      }
      // Non-YARA file → let event propagate to window drop handler for normal loading
    });

    // ── Assemble and mount ──────────────────────────────────────────
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    // Close on overlay click or Esc
    overlay.addEventListener('click', e => { if (e.target === overlay) this._closeYaraDialog(); });
    this._yaraEscHandler = e => { if (e.key === 'Escape') this._closeYaraDialog(); };
    document.addEventListener('keydown', this._yaraEscHandler);

    // If filterRule provided, pre-fill search; otherwise focus search
    if (filterRule) {
      searchInput.value = filterRule;
      setTimeout(doSearch, 50);
    } else {
      setTimeout(() => searchInput.focus(), 100);
    }
  },

  /** Close the YARA dialog. */
  _closeYaraDialog() {
    const el = document.getElementById('yara-dialog');
    if (el) el.remove();
    if (this._yaraEscHandler) {
      document.removeEventListener('keydown', this._yaraEscHandler);
      this._yaraEscHandler = null;
    }
    // Belt-and-braces: clear any stuck drag-over on the main drop-zone
    const mainDz = document.getElementById('drop-zone');
    if (mainDz) mainDz.classList.remove('drag-over');
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  Scanning
  // ═══════════════════════════════════════════════════════════════════════

  /** Run YARA scan against currently loaded file. */
  _yaraRunScan() {
    if (!this._fileBuffer && !this._yaraBuffer) {
      this._yaraSetStatus('No file loaded \u2014 open a file first, then scan', 'error');
      return;
    }

    const source = this._getAllYaraSource();
    if (!source) {
      this._yaraSetStatus('No YARA rules available', 'error');
      return;
    }

    this._yaraSetStatus('Parsing rules\u2026', 'info');

    const { rules, errors } = YaraEngine.parseRules(source);
    if (errors.length) {
      this._yaraSetStatus('Parse errors: ' + errors.join('; '), 'error');
      return;
    }
    if (!rules.length) {
      this._yaraSetStatus('No rules found', 'error');
      return;
    }

    this._yaraSetStatus('Scanning ' + rules.length + ' rule(s)\u2026', 'info');

    // Run scan (setTimeout allows UI update)
    setTimeout(() => {
      try {
        const t0 = performance.now();
        const results = YaraEngine.scan(this._yaraBuffer || this._fileBuffer, rules);
        const elapsed = ((performance.now() - t0) / 1000).toFixed(2);

        if (results.length === 0) {
          this._yaraSetStatus('\u2713 Scan complete in ' + elapsed + 's \u2014 no rules matched', 'success');
          this._yaraRenderResults([]);
        } else {
          this._yaraSetStatus('\u26A0 ' + results.length + ' rule(s) matched in ' + elapsed + 's', 'warning');
          this._yaraRenderResults(results);
        }

        // Store results and update sidebar
        this._yaraResults = results;
        if (this.findings) {
          this._updateSidebarWithYara(results);
        }
      } catch (e) {
        this._yaraSetStatus('Scan error: ' + e.message, 'error');
      }
    }, 50);
  },

  /** Set YARA status bar text + style. For multi-item error lists, renders
   *  each item on its own line and adds a Copy button for the full text. */
  _yaraSetStatus(text, type) {
    const el = document.getElementById('yara-status');
    if (!el) return;
    el.className = 'yara-status yara-status-' + (type || 'info');
    el.innerHTML = '';

    // Split error/warning lists on "; " boundary (the separator every caller uses).
    // Anything after the first ":" in the summary header is treated as the item block.
    const splitColon = text.indexOf(': ');
    const isList = (type === 'error' || type === 'warning') &&
                   splitColon !== -1 && text.indexOf('; ', splitColon) !== -1;

    if (!isList) {
      // Single-line status — keep the existing compact look
      const span = document.createElement('span');
      span.className = 'yara-status-text';
      span.textContent = text;
      el.appendChild(span);
      return;
    }

    // Multi-item status: summary + bulleted list + copy button
    const header = text.slice(0, splitColon);
    const items = text.slice(splitColon + 2).split('; ').filter(Boolean);

    const summary = document.createElement('div');
    summary.className = 'yara-status-summary';
    const summaryText = document.createElement('span');
    summaryText.textContent = header + ' \u2014 ' + items.length +
      (type === 'error' ? ' error' : ' warning') + (items.length === 1 ? '' : 's');
    summary.appendChild(summaryText);

    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'yara-status-copy-btn';
    copyBtn.textContent = '\u{1F4CB} Copy';
    copyBtn.title = 'Copy full error text to clipboard';
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const payload = header + '\n' + items.map(s => '  \u2022 ' + s).join('\n');
      const done = () => {
        if (this._toast) this._toast('Copied error to clipboard');
        const orig = copyBtn.textContent;
        copyBtn.textContent = '\u2713 Copied';
        setTimeout(() => { copyBtn.textContent = orig; }, 1500);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(payload).then(done, () => {
          // Fallback to execCommand if clipboard API is blocked
          const ta = document.createElement('textarea');
          ta.value = payload; ta.style.position = 'fixed'; ta.style.opacity = '0';
          document.body.appendChild(ta); ta.select();
          try { document.execCommand('copy'); done(); }
          catch (_) { if (this._toast) this._toast('Copy failed', 'error'); }
          finally { document.body.removeChild(ta); }
        });
      } else {
        const ta = document.createElement('textarea');
        ta.value = payload; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); done(); }
        catch (_) { if (this._toast) this._toast('Copy failed', 'error'); }
        finally { document.body.removeChild(ta); }
      }
    });
    summary.appendChild(copyBtn);
    el.appendChild(summary);

    const list = document.createElement('ul');
    list.className = 'yara-status-list';
    for (const it of items) {
      const li = document.createElement('li');
      li.textContent = it;
      list.appendChild(li);
    }
    el.appendChild(list);
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
      name.className = 'yara-result-rule-name';
      name.textContent = r.ruleName;
      hdr.appendChild(name);
      if (r.tags) {
        const tags = document.createElement('span');
        tags.className = 'yara-rule-tags';
        tags.textContent = r.tags;
        hdr.appendChild(tags);
      }
      const severity = (r.meta && r.meta.severity) ? r.meta.severity.toLowerCase() : 'high';
      const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
      const sevClass = validSeverities.includes(severity) ? severity : 'high';
      const badge = document.createElement('span');
      badge.className = 'badge badge-' + sevClass;
      badge.textContent = severity;
      hdr.appendChild(badge);
      card.appendChild(hdr);

      // Build the set of identifiers that actually produced hits — used to
      // emphasise matched $vars inside the condition expression on hover.
      const matchedIdSet = new Set(r.matches.map(m => m.id.toLowerCase()));
      const condHtml = this._yaraBoldCond(r.condition, matchedIdSet);


      // String matches
      for (const sm of r.matches) {
        const row = document.createElement('div');
        row.className = 'yara-match-row';
        // Preserve the rule's variable name as a native tooltip so it stays
        // recoverable without cluttering the column alignment.
        row.title = sm.id;

        const val = document.createElement('span');
        val.className = 'yara-match-val';
        val.textContent = sm.value;
        row.appendChild(val);

        const count = document.createElement('span');
        count.className = 'yara-match-count';
        count.textContent = sm.matches.length + ' hit' + (sm.matches.length !== 1 ? 's' : '');
        row.appendChild(count);

        // Hover-revealed detection reason: this row's $var + the rule's
        // condition with matched $vars emphasised.
        const reason = document.createElement('div');
        reason.className = 'yara-match-reason';
        const idChip = '<span class="yara-match-id">' + this._escHtmlYara(sm.id) + '</span>';
        if (condHtml) {
          reason.innerHTML = idChip + ' <span class="yara-match-sep">\u2192</span> ' + condHtml;
        } else {
          // Fallback for trivial conditions — still shows the $var name so
          // nothing is lost, just without a meaningful expression to bold.
          reason.innerHTML = idChip + ' <span class="yara-match-sep">\u00b7</span> <em>matched</em>';
        }
        row.appendChild(reason);

        card.appendChild(row);
      }

      container.appendChild(card);
    }
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  Auto-scan & sidebar integration
  // ═══════════════════════════════════════════════════════════════════════

  /** Auto-run YARA scan when a file is loaded (uses built-in + uploaded rules). */
  _autoYaraScan() {
    if (!this._fileBuffer && !this._yaraBuffer) return;
    const source = this._getAllYaraSource();
    if (!source) return;

    const { rules } = YaraEngine.parseRules(source);
    if (!rules.length) return;

    try {
      const results = YaraEngine.scan(this._yaraBuffer || this._fileBuffer, rules);
      this._yaraResults = results;
      if (this.findings) this._updateSidebarWithYara(results);
    } catch (_) { /* silently ignore scan errors during auto-scan */ }
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  YARA Info Reference Popup
  // ═══════════════════════════════════════════════════════════════════════

  /** Open the YARA rule-writing reference popup inside the dialog.
   *  @param {HTMLElement} dialogEl — the .yara-dialog container */
  _openYaraInfoPopup(dialogEl) {
    // Prevent duplicate
    if (dialogEl.querySelector('.yara-info-overlay')) return;

    // ── Overlay ──────────────────────────────────────────────────────
    const ov = document.createElement('div');
    ov.className = 'yara-info-overlay';

    // ── Card ─────────────────────────────────────────────────────────
    const card = document.createElement('div');
    card.className = 'yara-info-card';

    // ── Header ───────────────────────────────────────────────────────
    const hdr = document.createElement('div');
    hdr.className = 'yara-info-header';
    const h3 = document.createElement('h3');
    h3.textContent = '\u{1F4D6} YARA Rule Reference';
    hdr.appendChild(h3);
    const closeBtn = document.createElement('button');
    closeBtn.textContent = '\u2715';
    closeBtn.title = 'Close';
    closeBtn.addEventListener('click', () => ov.remove());
    hdr.appendChild(closeBtn);
    card.appendChild(hdr);

    // ── Body (scrollable) ────────────────────────────────────────────
    const body = document.createElement('div');
    body.className = 'yara-info-body';

    // Helper: create a section heading
    const h = (text) => { const el = document.createElement('h4'); el.textContent = text; return el; };

    // Helper: build a table from header + rows arrays
    const table = (headers, rows, sevRow) => {
      const t = document.createElement('table');
      const thead = document.createElement('thead');
      const tr = document.createElement('tr');
      for (const h of headers) { const th = document.createElement('th'); th.textContent = h; tr.appendChild(th); }
      thead.appendChild(tr);
      t.appendChild(thead);
      const tbody = document.createElement('tbody');
      for (const row of rows) {
        const r = document.createElement('tr');
        if (sevRow) r.className = 'yara-info-sev-row';
        for (const cell of row) {
          const td = document.createElement('td');
          if (typeof cell === 'object' && cell._html) td.innerHTML = cell._html;
          else td.textContent = cell;
          r.appendChild(td);
        }
        tbody.appendChild(r);
      }
      t.appendChild(tbody);
      return t;
    };

    // Helper: inline <code> wrapper
    const c = (text) => ({ _html: '<code>' + this._escHtmlYara(text) + '</code>' });

    // ── 1. Rule Structure ────────────────────────────────────────────
    body.appendChild(h('Rule Structure'));
    const structPre = document.createElement('pre');
    structPre.innerHTML = this._highlightYaraSyntax(
      'rule Suspicious_PowerShell_Download\n' +
      '{\n' +
      '    meta:\n' +
      '        description = "What this rule detects"\n' +
      '        severity    = "high"\n' +
      '        category    = "execution"\n' +
      '        mitre       = "T1059.001"\n' +
      '\n' +
      '    strings:\n' +
      '        $text1 = "suspicious string"\n' +
      '        $hex1  = { 4D 5A 90 00 }\n' +
      '        $re1   = /eval\\(base64_decode/i\n' +
      '\n' +
      '    condition:\n' +
      '        any of them\n' +
      '}'
    );
    body.appendChild(structPre);

    const structNote = document.createElement('p');
    structNote.innerHTML = '<strong>Required:</strong> <code>rule NAME { condition: ... }</code> &mdash; '
      + '<code>meta:</code> and <code>strings:</code> are optional but recommended.';
    body.appendChild(structNote);

    // ── 2. String Types ──────────────────────────────────────────────
    body.appendChild(h('String Types'));
    body.appendChild(table(
      ['Type', 'Syntax', 'Example', 'Notes'],
      [
        ['Text', c('"..."'), c('$s = "cmd.exe"'), 'Exact byte match'],
        ['Hex', c('{ XX XX }'), c('$h = { 4D 5A 90 }'), 'Raw bytes; supports wildcards'],
        ['Regex', c('/pattern/flags'), c('$r = /eval\\(.{0,40}\\)/i'), 'RE after = sign; i s m flags'],
      ]
    ));

    // ── 3. Hex Pattern Features ──────────────────────────────────────
    body.appendChild(h('Hex Pattern Features'));
    body.appendChild(table(
      ['Feature', 'Syntax', 'Meaning'],
      [
        ['Wildcard byte', c('??'), 'Matches any single byte'],
        ['Nibble wildcard', c('4? or ?A'), 'Matches half-byte'],
        ['Jump (range)', c('[2-4]'), 'Skip 2 to 4 bytes'],
        ['Unbounded jump', c('[-]'), 'Skip any number of bytes'],
        ['Alternative', c('( AA | BB )'), 'Match either sequence'],
      ]
    ));

    // ── 4. String Modifiers ──────────────────────────────────────────
    body.appendChild(h('String Modifiers'));
    body.appendChild(table(
      ['Modifier', 'Effect', 'Example'],
      [
        [c('nocase'), 'Case-insensitive match', c('$s = "cmd" nocase')],
        [c('wide'), 'UTF-16LE encoding (2 bytes/char)', c('$s = "cmd" wide')],
        [c('ascii'), 'ASCII encoding (default, explicit)', c('$s = "cmd" ascii wide')],
        [c('fullword'), 'Must be delimited by non-alphanumeric', c('$s = "eval" fullword')],
      ]
    ));

    // ── 5. Condition Keywords ────────────────────────────────────────
    body.appendChild(h('Condition Keywords'));
    body.appendChild(table(
      ['Keyword / Operator', 'Example', 'Description'],
      [
        [c('any of them'), c('condition: any of them'), 'Any defined string matches'],
        [c('all of them'), c('condition: all of them'), 'Every defined string matches'],
        [c('N of them'), c('condition: 2 of them'), 'At least N strings match'],
        [c('any of ($a*)'), c('condition: any of ($a*)'), 'Any string starting with $a'],
        [c('#s > N'), c('condition: #s > 3'), 'String $s matches > N times'],
        [c('$s at N'), c('condition: $s at 0'), 'String $s at exact offset'],
        [c('$s in (X..Y)'), c('condition: $s in (0..256)'), 'String $s within byte range'],
        [c('filesize'), c('condition: filesize < 100KB'), 'Size of scanned data'],
        [c('and / or / not'), c('condition: $a and not $b'), 'Boolean logic'],
        [c('for N of ... : (...)'), c('for all of ($s*) : (# > 1)'), 'Iterate with sub-condition'],
      ]
    ));

    // ── 6. Severity Levels (Loupe-specific) ──────────────────────
    body.appendChild(h('Severity Levels (Loupe)'));
    const sevNote = document.createElement('p');
    sevNote.textContent = 'Set via meta: severity = "level". Controls badge colour and risk scoring.';
    body.appendChild(sevNote);
    body.appendChild(table(
      ['Level', 'Colour', 'Use for'],
      [
        ['critical', '\u{1F534} Red', 'Active exploitation, weaponised payloads'],
        ['high', '\u{1F7E0} Orange', 'Shellcode, obfuscated scripts, known malware'],
        ['medium', '\u{1F7E1} Yellow', 'Suspicious patterns, dual-use tools'],
        ['low', '\u{1F535} Blue', 'Informational artefacts, unusual but benign'],
        ['info', '\u26AA Grey', 'Metadata, structural markers, FYI only'],
      ],
      true // sevRow class
    ));

    // ── 7. Meta Fields (Loupe) ───────────────────────────────────
    body.appendChild(h('Meta Fields (Loupe)'));
    const metaNote = document.createElement('p');
    metaNote.textContent = 'Loupe recognises four standardised meta fields. All are optional but recommended.';
    body.appendChild(metaNote);
    body.appendChild(table(
      ['Field', 'Type', 'Example', 'Purpose'],
      [
        [c('description'), 'string', c('"Detects PowerShell download cradle"'), 'Shown in sidebar findings and scan results'],
        [c('severity'), 'string', c('"high"'), 'Badge colour & risk scoring (see Severity Levels above)'],
        [c('category'), 'string', c('"execution"'), 'Groups the rule logically (e.g. execution, persistence, evasion)'],
        [c('mitre'), 'string', c('"T1059.001"'), 'MITRE ATT&CK technique ID for cross-referencing'],
      ]
    ));

    // ── 8. Naming Convention ─────────────────────────────────────────
    body.appendChild(h('Naming Convention'));
    const nameNote = document.createElement('p');
    nameNote.innerHTML = 'Rule names use <code>Prefix_Words_With_Underscores</code>. '
      + 'Loupe automatically converts underscores to spaces for display in the '
      + '<strong>Detections</strong> sidebar &mdash; e.g. <code>Suspicious_PowerShell_Download</code> '
      + '&rarr; <em>Suspicious PowerShell Download</em>.';
    body.appendChild(nameNote);
    const nameTip = document.createElement('p');
    nameTip.innerHTML = '<strong>Tip:</strong> Use a descriptive prefix like '
      + '<code>Suspicious_</code>, <code>Malicious_</code>, or <code>Contains_</code> '
      + 'to give analysts quick context in the sidebar.';
    body.appendChild(nameTip);

    // ── 9. Complete Example ──────────────────────────────────────────
    body.appendChild(h('Complete Example'));
    const exPre = document.createElement('pre');
    exPre.innerHTML = this._highlightYaraSyntax(
      'rule Suspicious_PowerShell_Download\n' +
      '{\n' +
      '    meta:\n' +
      '        description = "Detects PowerShell download cradle patterns"\n' +
      '        severity    = "high"\n' +
      '        category    = "execution"\n' +
      '        mitre       = "T1059.001"\n' +
      '\n' +
      '    strings:\n' +
      '        $iwr  = "Invoke-WebRequest" nocase\n' +
      '        $iex  = "IEX" fullword nocase\n' +
      '        $net  = "Net.WebClient" nocase\n' +
      '        $dl   = "DownloadString" nocase\n' +
      '        $b64  = /FromBase64String\\(.{1,64}\\)/i\n' +
      '        $hex  = { 49 00 45 00 58 00 }\n' +
      '\n' +
      '    condition:\n' +
      '        2 of them\n' +
      '}'
    );
    body.appendChild(exPre);

    card.appendChild(body);
    ov.appendChild(card);

    // ── Dismiss handlers ─────────────────────────────────────────────
    ov.addEventListener('click', (e) => { if (e.target === ov) ov.remove(); });
    const escHandler = (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        ov.remove();
        document.removeEventListener('keydown', escHandler, true);
      }
    };
    document.addEventListener('keydown', escHandler, true);

    dialogEl.appendChild(ov);
  },

  /** Build a byte-offset → JS-char-offset map for the rendered rawText.
   *  YARA reports byte offsets into the UTF-8 encoded file buffer, but the
   *  text view (`plaintext-table`) works in JavaScript string (UTF-16 code
   *  unit) coordinates. For files containing multi-byte UTF-8 characters
   *  (e.g. `──` U+2500 = 3 bytes / 1 JS char) the two coordinate systems
   *  diverge, causing highlights to land on the wrong text.
   *
   *  Returns a Map<byteOffset, charOffset> with entries at every character
   *  boundary, plus a final entry at text.length for end-position lookups.
   *  Returns null if no rawText is available. */
  _buildYaraByteToCharMap() {
    const pc = document.getElementById('page-container');
    const docEl = pc && pc.firstElementChild;
    const rawText = docEl && docEl._rawText;
    if (typeof rawText !== 'string' || !rawText.length) return null;
    const map = new Map();
    let bi = 0;
    for (let ci = 0; ci < rawText.length; ci++) {
      map.set(bi, ci);
      const code = rawText.charCodeAt(ci);
      if (code < 0x80) bi += 1;
      else if (code < 0x800) bi += 2;
      else if (code >= 0xD800 && code <= 0xDBFF) {
        // high surrogate: supplementary plane char is 4 UTF-8 bytes,
        // and spans 2 JS chars (surrogate pair).
        bi += 4; ci++;
      } else {
        bi += 3;
      }
    }
    map.set(bi, rawText.length);
    return map;
  },

  /** Update sidebar extracted tab with YARA results. */
  _updateSidebarWithYara(results) {
    if (!this.findings) return;
    // Remove any previous YARA findings
    this.findings.externalRefs = (this.findings.externalRefs || []).filter(r => r.type !== IOC.YARA);
    // Add new YARA findings with severity from rule meta
    const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
    let maxSeverity = null;
    const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

    // Convert YARA's byte offsets → JS char offsets so that downstream
    // highlighting (which works on _rawText char indices) lands on the
    // correct text even when the file contains multi-byte UTF-8 sequences.
    const byteToChar = this._buildYaraByteToCharMap();

    // Build a per-rule "structural finding present?" check: YARA_SUPPRESS_IF_
    // STRUCTURAL is a Map<ruleName, regex>; for each entry, if any existing
    // externalRef's `note` or `url` matches the regex, suppress the YARA rule
    // from the sidebar (it remains visible in the YARA results dialog).
    const refsForMatch = (this.findings.externalRefs || []).filter(r => r && r.type !== IOC.YARA);
    const ruleHasStructural = (ruleName) => {
      if (typeof YARA_SUPPRESS_IF_STRUCTURAL === 'undefined') return false;
      const re = YARA_SUPPRESS_IF_STRUCTURAL.get(ruleName);
      if (!re) return false;
      return refsForMatch.some(r =>
        (r.note && re.test(r.note)) || (r.url && re.test(r.url))
      );
    };

    for (const r of results) {
      // Suppress YARA rule if its structural equivalent already fired
      if (ruleHasStructural(r.ruleName)) continue;

      const desc = (r.meta && r.meta.description) ? r.meta.description : null;
      const severity = (r.meta && r.meta.severity) ? r.meta.severity.toLowerCase() : 'high';
      const sev = validSeverities.includes(severity) ? severity : 'high';
      const strings = r.matches.map(m => m.id + '=' + m.value).join(', ');

      // `url` is kept as a single flat line so that Markdown summary,
      // clipboard share, STIX / MISP exporters and the search index keep
      // working against the existing `ref.url` contract. The structured
      // `_yaraStrings` / `description` fields below are what the sidebar
      // renderer uses to build the pretty per-string table.
      let text = '';
      if (desc) text += desc + ' \u2014 ';
      text += r.matches.length + ' string(s) matched: ' + strings;

      // Structured per-string list for the sidebar's pretty renderer.
      // One entry per YARA string identifier ($a / $s1 / …), with its
      // matched value and number of hits.
      const yaraStrings = r.matches.map(m => ({
        id: m.id,
        value: m.value,
        hits: (m.matches && m.matches.length) || 0,
      }));

      // Build flat list of all match locations for click-to-highlight
      const allMatches = [];
      for (const m of r.matches) {
        for (const loc of m.matches) {
          let offset = loc.offset;
          let length = loc.length;
          if (byteToChar) {
            const startChar = byteToChar.get(loc.offset);
            const endChar = byteToChar.get(loc.offset + loc.length);
            // Only remap when both endpoints fall on char boundaries.
            // If they don't (e.g. a hex-pattern match straddles a multi-byte
            // char), fall back to the raw byte offsets — highlighting may be
            // imprecise but at least won't be catastrophically wrong.
            if (startChar !== undefined && endChar !== undefined) {
              offset = startChar;
              length = endChar - startChar;
            }
          }
          allMatches.push({ offset, length, stringId: m.id, value: m.value });
        }
      }
      allMatches.sort((a, b) => a.offset - b.offset);
      this.findings.externalRefs.push({
        type: IOC.YARA,
        url: text,
        severity: sev,
        description: desc || '',       // exposed for Summary / STIX / MISP
        _yaraRuleName: r.ruleName,
        _yaraStrings: yaraStrings,     // structured per-string breakdown for the sidebar
        _yaraCondition: r.condition || '',  // raw condition expression for the sidebar's hover-revealed "reason for detection"
        _yaraMatches: allMatches       // For click-to-highlight cycling
      });

      if (!maxSeverity || sevRank[sev] > sevRank[maxSeverity]) maxSeverity = sev;
    }
    // Bump overall risk based on highest YARA severity
    if (results.length > 0) {
      const riskRank = { critical: 4, high: 3, medium: 2, low: 1 };
      const currentRank = riskRank[this.findings.risk] || 1;
      if (maxSeverity === 'critical' && currentRank < 4) this.findings.risk = 'critical';
      else if (maxSeverity === 'high' && currentRank < 3) this.findings.risk = 'high';
      else if (maxSeverity === 'medium' && currentRank < 2) this.findings.risk = 'medium';
    }
    // Re-render sidebar. Use _fileMeta as single source of truth for the
    // filename (legacy #file-info element was replaced by the breadcrumb trail).
    const fileName = (this._fileMeta && this._fileMeta.name) || '';
    this._renderSidebar(fileName, null);
  },

});
