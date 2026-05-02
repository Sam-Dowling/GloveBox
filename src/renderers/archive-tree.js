'use strict';
// ════════════════════════════════════════════════════════════════════════════
// archive-tree.js — Shared collapsible / searchable / sortable archive browser
//
// Single UI used by zip-renderer, msix-renderer, browserext-renderer (and any
// future archive-like renderer). Provides:
//
//   • Tree view (default) — nested collapsible folders, per-folder item
//     counts, "Expand all / Collapse all" controls.
//   • Flat view            — sortable table with sticky header (click column
//     header to toggle asc/desc; arrow indicator).
//   • Search                — instant filter across both views; highlights
//     the matched substring and auto-expands ancestor folders in tree mode.
//     `/` focuses the search box, `Esc` clears it.
//   • Keyboard              — ↑/↓ move, ←/→ collapse/expand folder, Enter
//     opens file, Home/End jump, Space toggles folder.
//   • Safety                — enforces PARSER_LIMITS.MAX_DEPTH so a
//     hand-crafted archive can't blow the recursion budget.
//
// Callers pass a flat `entries` array with the shape:
//   { path, dir, size, compressed?, date?, encrypted?, linkName?,
//     danger?, dangerLabel? }
// plus an `onOpen(entry)` callback. See ZipRenderer._renderZipContents for a
// reference call site.
//
// `danger: true` lets callers mark arbitrary entries as risky even when the
// file extension isn't in `execExts` — used by PkgRenderer for install
// scripts named `preinstall` / `postinstall` (no extension). `dangerLabel`
// overrides the default "EXEC" badge text (e.g. "INSTALL SCRIPT").
//
// Depends on: constants.js (escHtml, fmtBytes, PARSER_LIMITS)
// ════════════════════════════════════════════════════════════════════════════
class ArchiveTree {

  // Rendered before any of the extension-classifier helpers run, so keep the
  // icon table small and stable.
  static _ICON_BY_EXT = {
    // Executables / scripts
    exe: '⚙️', dll: '⚙️', sys: '⚙️', scr: '⚙️', com: '⚙️', msi: '⚙️',
    so: '⚙️', dylib: '⚙️', o: '⚙️',
    bat: '📜', cmd: '📜', ps1: '📜', psm1: '📜', psd1: '📜',
    vbs: '📜', vbe: '📜', js: '📜', jse: '📜', wsf: '📜', wsh: '📜',
    hta: '📜', sh: '📜', bash: '📜', py: '📜', rb: '📜', pl: '📜',
    // Documents
    doc: '📄', docx: '📄', docm: '📄', odt: '📄', rtf: '📄', txt: '📝',
    xls: '📊', xlsx: '📊', xlsm: '📊', ods: '📊', csv: '📊', tsv: '📊',
    ppt: '📽️', pptx: '📽️', pptm: '📽️', odp: '📽️',
    pdf: '📕',
    // Archives / code
    zip: '📦', rar: '📦', '7z': '📦', tar: '📦', gz: '📦', gzip: '📦',
    cab: '📦', jar: '☕', war: '☕', ear: '☕', class: '☕',
    // Images / media
    jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️', bmp: '🖼️',
    svg: '🖼️', ico: '🖼️', webp: '🖼️', tif: '🖼️', tiff: '🖼️',
    // Web / data
    html: '🌐', htm: '🌐', xml: '🌐', json: '🌐', xhtml: '🌐',
    yml: '📝', yaml: '📝', ini: '📝', cfg: '📝', log: '📝', md: '📝',
    mf: '📝', properties: '📝',
    // Crypto
    pem: '🔑', der: '🔑', crt: '🔑', cer: '🔑', p12: '🔑', pfx: '🔑', key: '🔑',
    pgp: '🔑', gpg: '🔑', asc: '🔑', sig: '🔑',
  };

  // Default extension sets — callers may override via the options object.
  static DEFAULT_EXEC_EXTS = new Set([
    'exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'msi', 'msp', 'mst', 'sys',
    'bat', 'cmd', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'js', 'jse',
    'wsf', 'wsh', 'wsc', 'hta', 'lnk', 'inf', 'reg', 'sct',
    'jar', 'py', 'rb', 'sh', 'bash', 'so', 'dylib',
    'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'ppam', 'xlam',
  ]);

  static DEFAULT_DECOY_EXTS = new Set([
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'jpg', 'png', 'gif', 'txt', 'rtf',
  ]);

  // Auto-expand threshold for `render({ expandAll: 'auto' })`. Trees
  // with `entries.length <= AUTO_EXPAND_MAX_ENTRIES` open fully expanded
  // on first paint; larger trees stay collapsed so a 10k-entry archive
  // doesn't flash a wall of rows. Tuned for the median archive drop;
  // analysts can still hit `⤵ Expand all` on the toolbar.
  static AUTO_EXPAND_MAX_ENTRIES = 256;

  // ══════════════════════════════════════════════════════════════════════
  // Public entry point
  // ══════════════════════════════════════════════════════════════════════
  //
  // opts:
  //   entries         — [{ path, dir, size, compressed?, date?, encrypted?, linkName? }]
  //   onOpen          — (entry) => void         (invoked for file rows)
  //   execExts        — Set<string>             (defaults to DEFAULT_EXEC_EXTS)
  //   decoyExts       — Set<string>             (defaults to DEFAULT_DECOY_EXTS)
  //   showCompressed  — bool                    (Flat view: Compressed column)
  //   showDate        — bool                    (Flat view: Date column)
  //   initialView     — 'tree' | 'flat'         (default 'tree')
  //   emptyText       — string                  (default "Archive is empty.")
  //   expandAll       — true | false | 'auto'   (default false / collapsed)
  //                     true   — expand every folder on first paint.
  //                     'auto' — expand iff `entries.length` is at or below
  //                              `ArchiveTree.AUTO_EXPAND_MAX_ENTRIES`
  //                              (default 256). Used by archive renderers
  //                              so small ZIP/TAR/MSIX/etc. drops open
  //                              fully expanded while huge archives stay
  //                              collapsed to bound first-paint cost.
  //                     false  — leave the tree collapsed (the historical
  //                              default; the toolbar `⤵ Expand all`
  //                              button still works).
  //
  // Returns: HTMLElement — append it to the renderer's wrap and we're done.
  //
  static render(opts) {
    const entries = Array.isArray(opts && opts.entries) ? opts.entries : [];
    const onOpen = (opts && typeof opts.onOpen === 'function') ? opts.onOpen : null;
    const execExts = (opts && opts.execExts instanceof Set) ? opts.execExts : ArchiveTree.DEFAULT_EXEC_EXTS;
    const decoyExts = (opts && opts.decoyExts instanceof Set) ? opts.decoyExts : ArchiveTree.DEFAULT_DECOY_EXTS;
    const showCompressed = !!(opts && opts.showCompressed);
    const showDate = !!(opts && opts.showDate);
    const initialView = (opts && opts.initialView === 'flat') ? 'flat' : 'tree';
    const emptyText = (opts && opts.emptyText) || 'Archive is empty.';
    const expandAllOpt = opts ? opts.expandAll : false;
    const shouldExpandAll =
      expandAllOpt === true ||
      (expandAllOpt === 'auto' &&
       entries.length <= ArchiveTree.AUTO_EXPAND_MAX_ENTRIES);

    const root = document.createElement('div');
    root.className = 'arch-view';

    if (!entries.length) {
      const empty = document.createElement('div');
      empty.className = 'arch-empty';
      empty.textContent = emptyText;
      root.appendChild(empty);
      return root;
    }

    // ── Toolbar ─────────────────────────────────────────────────────────
    const toolbar = document.createElement('div');
    toolbar.className = 'arch-toolbar';
    toolbar.innerHTML = `
      <div class="arch-search-wrap">
        <input type="text" class="arch-search" placeholder="🔍 Search path or filename…   (press / to focus, Esc to clear)" spellcheck="false" autocomplete="off">
        <span class="arch-search-count" hidden></span>
      </div>
      <div class="arch-view-toggle" role="tablist" aria-label="View mode">
        <button type="button" class="arch-view-btn${initialView === 'tree' ? ' active' : ''}" data-arch-view="tree" role="tab" aria-selected="${initialView === 'tree'}" title="Tree view — nested folders">🌳 Tree</button>
        <button type="button" class="arch-view-btn${initialView === 'flat' ? ' active' : ''}" data-arch-view="flat" role="tab" aria-selected="${initialView === 'flat'}" title="Flat view — sortable table">📋 Flat</button>
      </div>
      <div class="arch-tree-controls">
        <button type="button" class="arch-tree-btn" data-arch-toggle="expand" title="Expand all folders">⤵ Expand all</button>
        <button type="button" class="arch-tree-btn" data-arch-toggle="collapse" title="Collapse all folders">⤴ Collapse all</button>
      </div>
    `;
    root.appendChild(toolbar);

    // ── Tree view ───────────────────────────────────────────────────────
    const treePane = document.createElement('div');
    treePane.className = 'arch-pane arch-pane-tree';
    treePane.hidden = initialView !== 'tree';
    treePane.innerHTML = ArchiveTree._buildTreeHTML(entries, { execExts, decoyExts });
    root.appendChild(treePane);

    // ── Flat view ───────────────────────────────────────────────────────
    const flatPane = document.createElement('div');
    flatPane.className = 'arch-pane arch-pane-flat';
    flatPane.hidden = initialView !== 'flat';
    flatPane.appendChild(ArchiveTree._buildFlatTable(entries, { execExts, decoyExts, showCompressed, showDate }));
    root.appendChild(flatPane);

    // ── Wire interactions ───────────────────────────────────────────────
    ArchiveTree._wireToolbar(root);
    ArchiveTree._wireTree(root);
    ArchiveTree._wireFlatSort(root);
    ArchiveTree._wireOpen(root, entries, onOpen);
    ArchiveTree._wireSearch(root);
    ArchiveTree._wireKeyboard(root);

    // Optional: open every folder on first paint. Same code path the
    // toolbar `⤵ Expand all` button uses, so semantics, ARIA state, and
    // keyboard nav are identical to a manual expand. Folders that don't
    // exist yet (e.g. inside the still-collapsed `[hidden]` children)
    // are reachable here because `_buildTreeHTML` materialises every
    // `<li class="arch-tree-folder">` up front.
    if (shouldExpandAll) {
      root.querySelectorAll('.arch-tree-folder').forEach(
        li => ArchiveTree._toggleFolder(li, true));
    }

    return root;
  }

  // ══════════════════════════════════════════════════════════════════════
  // Tree view: build nested <ul> HTML from a flat path list
  // ══════════════════════════════════════════════════════════════════════
  static _buildTreeHTML(entries, ctx) {
    // Build a nested node map keyed by path segment. Files carry a reference
    // to their source entry so the click handler can resolve by path.
    const root = { children: new Map(), files: [] };

    // Sorting the input first keeps folder listings deterministic. We also
    // produce a synthetic directory entry even when the archive only ships
    // files (most archives omit trailing "dir/" entries).
    const sorted = [...entries].sort((a, b) => a.path.localeCompare(b.path));
    for (const e of sorted) {
      const parts = (e.path || '').split('/').filter(Boolean);
      if (!parts.length) continue;
      if (e.dir) {
        // Ensure every explicit dir is materialised even if it has no files.
        let node = root;
        for (const seg of parts) {
          if (!node.children.has(seg)) node.children.set(seg, { children: new Map(), files: [] });
          node = node.children.get(seg);
        }
        continue;
      }
      let node = root;
      for (let i = 0; i < parts.length - 1; i++) {
        const seg = parts[i];
        if (!node.children.has(seg)) node.children.set(seg, { children: new Map(), files: [] });
        node = node.children.get(seg);
      }
      node.files.push({ name: parts[parts.length - 1], entry: e });
    }

    const MAX_DEPTH = (typeof PARSER_LIMITS !== 'undefined' && PARSER_LIMITS && PARSER_LIMITS.MAX_DEPTH) || 32;

    const renderNode = (node, pathPrefix, depth) => {
      if (depth > MAX_DEPTH) {
        return `<li class="arch-tree-truncated">⚠ Tree depth limit (${MAX_DEPTH}) reached — deeper entries hidden</li>`;
      }
      let html = '';
      const folderNames = [...node.children.keys()].sort((a, b) => a.localeCompare(b));
      for (const name of folderNames) {
        const child = node.children.get(name);
        const childPath = pathPrefix ? pathPrefix + '/' + name : name;
        const stats = ArchiveTree._summariseNode(child);
        html += `<li class="arch-tree-folder" data-arch-folder-path="${escHtml(childPath)}">
          <div class="arch-tree-row arch-tree-folder-row" tabindex="0" role="treeitem" aria-expanded="false">
            <span class="arch-tree-caret" aria-hidden="true">▸</span>
            <span class="arch-tree-icon" aria-hidden="true">📁</span>
            <span class="arch-tree-name">${escHtml(name)}</span>
            <span class="arch-tree-meta">${stats.files} item${stats.files === 1 ? '' : 's'}${stats.size > 0 ? ' · ' + fmtBytes(stats.size) : ''}</span>
          </div>
          <ul class="arch-tree-children" role="group" hidden>${renderNode(child, childPath, depth + 1)}</ul>
        </li>`;
      }
      const files = [...node.files].sort((a, b) => a.name.localeCompare(b.name));
      for (const f of files) {
        const entry = f.entry;
        const ext = f.name.split('.').pop().toLowerCase();
        const isExec = ctx.execExts.has(ext);
        const isDecoy = ArchiveTree._isDoubleExt(f.name, ctx);
        // Caller-supplied `danger` flag (e.g. PkgRenderer tagging install
        // scripts with no extension) also triggers the danger styling.
        const isExplicit = !!entry.danger;
        const isDanger = isExec || isExplicit;
        const icon = ArchiveTree._ICON_BY_EXT[ext] || '📄';
        const rowClasses = ['arch-tree-row', 'arch-tree-file-row'];
        if (isDanger || isDecoy) rowClasses.push('arch-tree-danger');
        if (entry.encrypted) rowClasses.push('arch-tree-encrypted');
        let badges = '';
        if (isExec) badges += '<span class="arch-badge arch-badge-danger">EXEC</span>';
        else if (isExplicit) badges += `<span class="arch-badge arch-badge-danger">${escHtml(entry.dangerLabel || 'DANGER')}</span>`;
        if (isDecoy) badges += '<span class="arch-badge arch-badge-danger">DOUBLE EXT</span>';
        if (entry.encrypted) badges += '<span class="arch-badge arch-badge-lock">🔒</span>';
        if (entry.linkName) badges += `<span class="arch-badge arch-badge-link" title="Symlink target: ${escHtml(entry.linkName)}">🔗 ${escHtml(entry.linkName)}</span>`;
        const sizeStr = entry.dir ? '—' : fmtBytes(entry.size || 0);
        const openBtn = entry.encrypted
          ? ''
          : `<button type="button" class="arch-open-btn" data-arch-open="${escHtml(entry.path)}" title="Open ${escHtml(f.name)} for analysis">🔍 Open</button>`;
        html += `<li class="arch-tree-file" data-arch-file-name="${escHtml(f.name)}" data-arch-file-path="${escHtml(entry.path)}" role="none">
          <div class="${rowClasses.join(' ')}" tabindex="-1" role="treeitem">
            <span class="arch-tree-caret arch-tree-caret-leaf" aria-hidden="true"></span>
            <span class="arch-tree-icon" aria-hidden="true">${icon}</span>
            <span class="arch-tree-name" title="${escHtml(entry.path)}">${escHtml(f.name)}</span>
            ${badges}
            <span class="arch-tree-meta">${escHtml(sizeStr)}</span>
            ${openBtn}
          </div>
        </li>`;
      }
      return html;
    };

    const body = renderNode(root, '', 0);
    if (!body) return '<div class="arch-empty">Archive is empty.</div>';
    return `<ul class="arch-tree" role="tree">${body}</ul>`;
  }

  static _summariseNode(node) {
    let files = node.files.length;
    let size = node.files.reduce((s, f) => s + (f.entry && f.entry.size ? f.entry.size : 0), 0);
    for (const child of node.children.values()) {
      const sub = ArchiveTree._summariseNode(child);
      files += sub.files;
      size += sub.size;
    }
    return { files, size };
  }

  static _isDoubleExt(name, ctx) {
    const parts = name.split('.');
    if (parts.length < 3) return false;
    const last = parts[parts.length - 1].toLowerCase();
    const prev = parts[parts.length - 2].toLowerCase();
    return ctx.execExts.has(last) && ctx.decoyExts.has(prev);
  }

  // ══════════════════════════════════════════════════════════════════════
  // Flat view: sortable table
  // ══════════════════════════════════════════════════════════════════════
  static _buildFlatTable(entries, ctx) {
    const scr = document.createElement('div');
    scr.className = 'arch-flat-scroll';

    const tbl = document.createElement('table');
    tbl.className = 'arch-flat-table';

    const cols = [];
    cols.push({ key: 'icon', label: '', sortable: false });
    cols.push({ key: 'path', label: 'Path', sortable: true });
    cols.push({ key: 'size', label: 'Size', sortable: true, cls: 'arch-col-num' });
    if (ctx.showCompressed) cols.push({ key: 'compressed', label: 'Compressed', sortable: true, cls: 'arch-col-num' });
    if (ctx.showDate) cols.push({ key: 'date', label: 'Date', sortable: true });
    cols.push({ key: 'action', label: '', sortable: false });

    const thead = document.createElement('thead');
    const hr = document.createElement('tr');
    for (const c of cols) {
      const th = document.createElement('th');
      th.textContent = c.label;
      if (c.cls) th.classList.add(c.cls);
      if (c.sortable) {
        th.classList.add('arch-sortable');
        th.dataset.archSort = c.key;
        th.setAttribute('tabindex', '0');
        th.setAttribute('role', 'button');
        th.setAttribute('title', `Sort by ${c.label}`);
        const arrow = document.createElement('span');
        arrow.className = 'arch-sort-arrow';
        arrow.textContent = '';
        th.appendChild(document.createTextNode(' '));
        th.appendChild(arrow);
      }
      hr.appendChild(th);
    }
    thead.appendChild(hr);
    tbl.appendChild(thead);

    const tbody = document.createElement('tbody');
    // Default sort: folders first, then alphabetical by path.
    const sorted = entries.slice().sort((a, b) => {
      if (!!a.dir !== !!b.dir) return a.dir ? -1 : 1;
      return (a.path || '').localeCompare(b.path || '');
    });
    for (const e of sorted) tbody.appendChild(ArchiveTree._buildFlatRow(e, ctx));
    tbl.appendChild(tbody);

    scr.appendChild(tbl);
    return scr;
  }

  static _buildFlatRow(e, ctx) {
    const ext = (e.path || '').split('.').pop().toLowerCase();
    const name = (e.path || '').split('/').pop() || e.path;
    const isDanger = !e.dir && ctx.execExts.has(ext);
    const isDecoy = !e.dir && ArchiveTree._isDoubleExt(name, ctx);
    const tr = document.createElement('tr');
    tr.className = 'arch-flat-row';
    if (e.dir) tr.classList.add('arch-flat-dir');
    if (isDanger || isDecoy) tr.classList.add('arch-flat-danger');
    if (e.encrypted) tr.classList.add('arch-flat-encrypted');
    tr.dataset.archPath = e.path || '';
    tr.dataset.archIsdir = e.dir ? '1' : '0';
    tr.dataset.archSize = String(e.size || 0);
    tr.dataset.archCompressed = String(e.compressed || 0);
    tr.dataset.archDate = e.date ? String(e.date.getTime()) : '0';

    // Icon
    const tdIcon = document.createElement('td');
    tdIcon.className = 'arch-col-icon';
    tdIcon.textContent = e.dir ? '📁' : (isDanger ? '⚠️' : (ArchiveTree._ICON_BY_EXT[ext] || '📄'));
    tr.appendChild(tdIcon);

    // Path
    const tdPath = document.createElement('td');
    tdPath.className = 'arch-col-path';
    tdPath.textContent = e.path || '';
    if (isDanger) tdPath.appendChild(ArchiveTree._badge('EXEC', 'arch-badge-danger'));
    if (isDecoy) tdPath.appendChild(ArchiveTree._badge('DOUBLE EXT', 'arch-badge-danger'));
    if (e.encrypted) tdPath.appendChild(ArchiveTree._badge('🔒', 'arch-badge-lock'));
    if (e.linkName) {
      const b = ArchiveTree._badge('🔗 ' + e.linkName, 'arch-badge-link');
      b.title = 'Symlink target: ' + e.linkName;
      tdPath.appendChild(b);
    }
    tr.appendChild(tdPath);

    // Size
    const tdSize = document.createElement('td');
    tdSize.className = 'arch-col-num';
    tdSize.textContent = e.dir ? '—' : fmtBytes(e.size || 0);
    tr.appendChild(tdSize);

    // Compressed (optional)
    if (Object.prototype.hasOwnProperty.call(ctx, 'showCompressed') && ctx.showCompressed) {
      const tdC = document.createElement('td');
      tdC.className = 'arch-col-num';
      tdC.textContent = e.dir ? '—' : fmtBytes(e.compressed || 0);
      tr.appendChild(tdC);
    }

    // Date (optional)
    if (Object.prototype.hasOwnProperty.call(ctx, 'showDate') && ctx.showDate) {
      const tdD = document.createElement('td');
      tdD.className = 'arch-col-date';
      tdD.textContent = e.date ? e.date.toISOString().slice(0, 19).replace('T', ' ') : '—';
      tr.appendChild(tdD);
    }

    // Action
    const tdAct = document.createElement('td');
    tdAct.className = 'arch-col-action';
    if (!e.dir && !e.encrypted) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'arch-open-btn';
      btn.textContent = '🔍 Open';
      btn.dataset.archOpen = e.path || '';
      btn.title = `Open ${name} for analysis`;
      tdAct.appendChild(btn);
    }
    tr.appendChild(tdAct);
    return tr;
  }

  static _badge(text, cls) {
    const b = document.createElement('span');
    b.className = 'arch-badge ' + cls;
    b.textContent = text;
    return b;
  }

  // ══════════════════════════════════════════════════════════════════════
  // Wiring
  // ══════════════════════════════════════════════════════════════════════

  static _wireToolbar(root) {
    // View toggle
    root.addEventListener('click', (ev) => {
      const viewBtn = ev.target.closest('[data-arch-view]');
      if (viewBtn && root.contains(viewBtn)) {
        const v = viewBtn.getAttribute('data-arch-view');
        root.querySelectorAll('[data-arch-view]').forEach(b => {
          const active = b.getAttribute('data-arch-view') === v;
          b.classList.toggle('active', active);
          b.setAttribute('aria-selected', active ? 'true' : 'false');
        });
        const tree = root.querySelector('.arch-pane-tree');
        const flat = root.querySelector('.arch-pane-flat');
        if (tree) tree.hidden = v !== 'tree';
        if (flat) flat.hidden = v !== 'flat';
        // Tree-only controls dim in flat mode.
        const ctrls = root.querySelector('.arch-tree-controls');
        if (ctrls) ctrls.classList.toggle('arch-disabled', v !== 'tree');
        return;
      }

      // Expand/Collapse all
      const toggleBtn = ev.target.closest('[data-arch-toggle]');
      if (toggleBtn && root.contains(toggleBtn)) {
        const force = toggleBtn.getAttribute('data-arch-toggle') === 'expand';
        root.querySelectorAll('.arch-tree-folder').forEach(li => ArchiveTree._toggleFolder(li, force));
      }
    });
  }

  static _toggleFolder(li, force) {
    const row = li.querySelector(':scope > .arch-tree-folder-row');
    const kids = li.querySelector(':scope > .arch-tree-children');
    if (!row || !kids) return;
    const open = typeof force === 'boolean' ? force : kids.hasAttribute('hidden');
    if (open) {
      kids.removeAttribute('hidden');
      row.setAttribute('aria-expanded', 'true');
      li.classList.add('arch-tree-open');
    } else {
      kids.setAttribute('hidden', '');
      row.setAttribute('aria-expanded', 'false');
      li.classList.remove('arch-tree-open');
    }
  }

  static _wireTree(root) {
    const tree = root.querySelector('.arch-tree');
    if (!tree) return;
    tree.addEventListener('click', (ev) => {
      // Don't hijack Open button clicks — handled by _wireOpen.
      if (ev.target.closest('[data-arch-open]')) return;
      const folderRow = ev.target.closest('.arch-tree-folder-row');
      if (folderRow) {
        ArchiveTree._toggleFolder(folderRow.parentElement);
      }
    });
  }

  static _wireFlatSort(root) {
    const table = root.querySelector('.arch-flat-table');
    if (!table) return;
    let sortKey = null;
    let sortDir = 1; // 1 asc, -1 desc

    const applySort = () => {
      const tbody = table.querySelector('tbody');
      if (!tbody) return;
      const rows = Array.from(tbody.querySelectorAll('tr'));
      rows.sort((a, b) => {
        // Always keep directories clustered at the top within a group.
        const aDir = a.dataset.archIsdir === '1';
        const bDir = b.dataset.archIsdir === '1';
        if (aDir !== bDir) return aDir ? -1 : 1;
        let va, vb;
        switch (sortKey) {
          case 'size':
            va = Number(a.dataset.archSize || 0); vb = Number(b.dataset.archSize || 0);
            break;
          case 'compressed':
            va = Number(a.dataset.archCompressed || 0); vb = Number(b.dataset.archCompressed || 0);
            break;
          case 'date':
            va = Number(a.dataset.archDate || 0); vb = Number(b.dataset.archDate || 0);
            break;
          case 'path':
          default:
            va = (a.dataset.archPath || '').toLowerCase();
            vb = (b.dataset.archPath || '').toLowerCase();
            break;
        }
        if (va < vb) return -1 * sortDir;
        if (va > vb) return 1 * sortDir;
        return 0;
      });
      // Re-append in sorted order.
      const frag = document.createDocumentFragment();
      rows.forEach(r => frag.appendChild(r));
      tbody.appendChild(frag);
      // Update header arrow indicators.
      table.querySelectorAll('.arch-sortable').forEach(th => {
        const arrow = th.querySelector('.arch-sort-arrow');
        if (!arrow) return;
        if (th.dataset.archSort === sortKey) {
          arrow.textContent = sortDir === 1 ? '▲' : '▼';
          th.classList.add('arch-sort-active');
        } else {
          arrow.textContent = '';
          th.classList.remove('arch-sort-active');
        }
      });
    };

    const onHeader = (th) => {
      const key = th.dataset.archSort;
      if (!key) return;
      if (sortKey === key) sortDir = -sortDir;
      else { sortKey = key; sortDir = 1; }
      applySort();
    };
    table.addEventListener('click', (ev) => {
      const th = ev.target.closest('.arch-sortable');
      if (th && table.contains(th)) onHeader(th);
    });
    table.addEventListener('keydown', (ev) => {
      if (ev.key !== 'Enter' && ev.key !== ' ') return;
      const th = ev.target.closest('.arch-sortable');
      if (th && table.contains(th)) { ev.preventDefault(); onHeader(th); }
    });
  }

  static _wireOpen(root, entries, onOpen) {
    // Build a path → entry lookup so both views can dispatch identically.
    const byPath = new Map();
    for (const e of entries) { if (!e.dir) byPath.set(e.path, e); }
    root.addEventListener('click', (ev) => {
      const btn = ev.target.closest('[data-arch-open]');
      if (!btn || !root.contains(btn)) return;
      ev.stopPropagation();
      const path = btn.getAttribute('data-arch-open');
      const entry = byPath.get(path);
      if (!entry) return;
      if (onOpen) {
        try { onOpen(entry); } catch (e) { /* swallow */ }
      } else {
        root.dispatchEvent(new CustomEvent('arch-open', { bubbles: true, detail: entry }));
      }
    });
    // Enter / double-click on a file row also opens.
    root.addEventListener('dblclick', (ev) => {
      const fileLi = ev.target.closest('.arch-tree-file');
      if (fileLi && root.contains(fileLi)) {
        const path = fileLi.getAttribute('data-arch-file-path');
        const entry = byPath.get(path);
        if (entry && onOpen) { try { onOpen(entry); } catch (_) {} }
        return;
      }
      const flatRow = ev.target.closest('.arch-flat-row');
      if (flatRow && root.contains(flatRow) && flatRow.dataset.archIsdir !== '1') {
        const entry = byPath.get(flatRow.dataset.archPath);
        if (entry && onOpen) { try { onOpen(entry); } catch (_) {} }
      }
    });
  }

  // ── Search: filter + highlight across tree and flat ──────────────────
  static _wireSearch(root) {
    const input = root.querySelector('.arch-search');
    const status = root.querySelector('.arch-search-count');
    if (!input) return;
    let debounce = null;

    const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

    const applyFilter = (q) => {
      let total = 0;
      const hasQuery = !!q;

      // Tree filter ---------------------------------------------------------
      const tree = root.querySelector('.arch-tree');
      if (tree) {
        // Reset any prior auto-expansion / highlights.
        tree.querySelectorAll('.arch-tree-hit').forEach(el => el.classList.remove('arch-tree-hit'));
        tree.querySelectorAll('.arch-tree-auto-expanded').forEach(li => {
          li.classList.remove('arch-tree-auto-expanded');
          if (!li.dataset.archKeepOpen) {
            ArchiveTree._toggleFolder(li, false);
          }
        });
        tree.querySelectorAll('.arch-tree-hidden').forEach(el => el.classList.remove('arch-tree-hidden'));
        // Restore any highlighted substring spans. We saved the raw text in
        // data-arch-orig (not HTML), so restoring via textContent avoids any
        // possibility of reinterpreting attacker-controlled filename text as
        // HTML on reset.
        tree.querySelectorAll('.arch-tree-name[data-arch-orig]').forEach(n => {
          n.textContent = n.getAttribute('data-arch-orig') || '';
          n.removeAttribute('data-arch-orig');
        });

        if (hasQuery) {
          const files = tree.querySelectorAll('li.arch-tree-file');
          let treeHits = 0;
          // Highlight operates on the *escaped* text, so the needle must be
          // escaped with the same transform to line up — otherwise a query
          // containing '<' would fail to highlight a filename containing '<'.
          /* safeRegex: builtin */
          const markRe = new RegExp(escapeRegex(escHtml(q)), 'ig');
          files.forEach(li => {
            const path = (li.getAttribute('data-arch-file-path') || '').toLowerCase();
            const name = (li.getAttribute('data-arch-file-name') || '').toLowerCase();
            const match = path.includes(q) || name.includes(q);
            if (match) {
              li.classList.add('arch-tree-hit');
              treeHits++;
              // Highlight inside the displayed name (not the full path).
              const nameEl = li.querySelector('.arch-tree-name');
              if (nameEl) {
                // Save raw text (never HTML) so a malicious filename like
                // `<img onerror=…>` can never be reinterpreted as HTML when
                // the search is cleared and this element is restored.
                const rawText = nameEl.textContent;
                nameEl.setAttribute('data-arch-orig', rawText);
                nameEl.innerHTML = escHtml(rawText).replace(
                  markRe, (m) => `<mark class="arch-mark">${m}</mark>`);
              }
              // Auto-expand ancestors
              let parent = li.parentElement;
              while (parent && parent !== tree) {
                if (parent.tagName === 'LI' && parent.classList.contains('arch-tree-folder')) {
                  parent.classList.add('arch-tree-auto-expanded');
                  ArchiveTree._toggleFolder(parent, true);
                }
                parent = parent.parentElement;
              }
            } else {
              li.classList.add('arch-tree-hidden');
            }
          });
          // Hide folders that have no matching descendants.
          tree.querySelectorAll('li.arch-tree-folder').forEach(folder => {
            const anyHit = folder.querySelector('.arch-tree-hit');
            if (!anyHit) folder.classList.add('arch-tree-hidden');
          });
          total += treeHits;
        }
      }

      // Flat filter ---------------------------------------------------------
      const flat = root.querySelector('.arch-flat-table');
      if (flat) {
        // Highlight regex operates on *escaped* text (so the needle is also
        // escaped) — guarantees that a filename containing HTML
        // meta-characters can never be re-interpreted as markup.
        /* safeRegex: builtin */
        const markRe = hasQuery ? new RegExp(escapeRegex(escHtml(q)), 'ig') : null;
        const rows = flat.querySelectorAll('tbody tr');
        rows.forEach(tr => {
          // Restore original text first (archOrig stores *sanitised* HTML
          // produced below, so reusing it as innerHTML is safe)
          const pathCell = tr.querySelector('.arch-col-path');
          if (pathCell && pathCell.dataset.archOrig) {
            pathCell.innerHTML = pathCell.dataset.archOrig;
            delete pathCell.dataset.archOrig;
          }
          if (!hasQuery) { tr.classList.remove('arch-flat-hidden', 'arch-flat-hit'); return; }
          const path = (tr.dataset.archPath || '').toLowerCase();
          const match = path.includes(q);
          if (match) {
            tr.classList.remove('arch-flat-hidden');
            tr.classList.add('arch-flat-hit');
            if (pathCell) {
              // Preserve badges by highlighting only the text node. The raw
              // path is escaped *first*, then the highlight marks are
              // injected — so filename text can never become live HTML.
              const text = tr.dataset.archPath || '';
              const badges = Array.from(pathCell.querySelectorAll('.arch-badge')).map(b => b.outerHTML).join('');
              pathCell.dataset.archOrig = pathCell.innerHTML;
              pathCell.innerHTML = escHtml(text).replace(
                markRe, (m) => `<mark class="arch-mark">${m}</mark>`) + badges;
            }
            // Count flat hits separately only if tree isn't present — otherwise
            // the tree count is authoritative (they render the same entries).
            if (!tree) total++;
          } else {
            tr.classList.add('arch-flat-hidden');
            tr.classList.remove('arch-flat-hit');
          }
        });
      }

      if (hasQuery) {
        status.hidden = false;
        status.textContent = total === 0 ? 'No matches' : `${total} match${total === 1 ? '' : 'es'}`;
      } else {
        status.hidden = true;
        status.textContent = '';
      }
    };

    input.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => applyFilter(input.value.toLowerCase().trim()), 150);
    });
    input.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape') {
        ev.preventDefault();
        input.value = '';
        applyFilter('');
        input.blur();
      }
    });
  }

  // ── Keyboard navigation (tree view) + '/' to focus search ────────────
  static _wireKeyboard(root) {
    const tree = root.querySelector('.arch-tree');
    if (tree) {
      tree.addEventListener('keydown', (ev) => {
        const row = ev.target.closest('.arch-tree-row');
        if (!row) return;
        const li = row.parentElement;
        const isFolder = li.classList.contains('arch-tree-folder');
        switch (ev.key) {
          case 'ArrowRight':
            if (isFolder) {
              ev.preventDefault();
              ArchiveTree._toggleFolder(li, true);
            }
            break;
          case 'ArrowLeft':
            if (isFolder && li.classList.contains('arch-tree-open')) {
              ev.preventDefault();
              ArchiveTree._toggleFolder(li, false);
            }
            break;
          case 'Enter':
          case ' ':
            if (isFolder) {
              ev.preventDefault();
              ArchiveTree._toggleFolder(li);
            } else {
              const openBtn = li.querySelector('[data-arch-open]');
              if (openBtn) { ev.preventDefault(); openBtn.click(); }
            }
            break;
        }
      });
    }
    // '/' focuses search when not already in a text field.
    root.addEventListener('keydown', (ev) => {
      if (ev.key !== '/') return;
      const t = ev.target;
      const isField = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);
      if (isField) return;
      const input = root.querySelector('.arch-search');
      if (input) { ev.preventDefault(); input.focus(); input.select(); }
    });
  }
}
