// json-tree.js — shared lightweight collapsible JSON tree.
//
// Used by GridViewer's drawer (CSV / EVTX / SQLite / XLSX / JSON rows that
// contain a JSON blob in a cell) and by Timeline's "ƒx Extract → raw cell"
// popup. Zero dependencies, no framework — renders plain DOM with ▸ / ▾
// toggles, lazy child build on first expand.
//
// API:
//   JsonTree.render(value, opts) → HTMLElement
//     opts.onPick(path, value, action) — optional; fired when the user
//                                   right-clicks a key and picks an item
//                                   from the context menu. `path` is an
//                                   array of string segments (string keys
//                                   verbatim, array indices as `[0]`,
//                                   `[12]`, …), `value` is the node's
//                                   current value, `action` is one of:
//                                     'extract' — just extract the column
//                                     'include' — extract + filter = value
//                                     'exclude' — extract + filter ≠ value
//                                   (Composite object/array keys have no
//                                    context menu — only scalar leaves do.)
//     opts.autoOpenDepth         — defaults to 1 (top level auto-expanded).
//                                   Pass `Infinity` to auto-expand every
//                                   level (still capped by MAX_DEPTH=16).
//     opts.maxChildren           — per-level render cap (default 200)
//
//   JsonTree.pathGet(value, path)        — resolve a path-array against a
//                                          parsed value (bracketed indices
//                                          dereference arrays).
//   JsonTree.pathLabel(path)             — pretty-print a path for UI
//                                          ("foo.bar[0].baz").
//   JsonTree.maybeJson(str)              — cheap sniff: does `str` begin
//                                          with `{` or `[` (after
//                                          whitespace)?
//   JsonTree.tryParse(str)               — safe JSON.parse that returns
//                                          `undefined` on failure or on
//                                          non-object/array results. Used
//                                          by the drawer to decide whether
//                                          to render a tree or fall back to
//                                          plain text.
//
// Kept deliberately framework-free so both GridViewer and Timeline can
// share one implementation. No CSS assumptions beyond the `.json-tree-*`
// class namespace declared in `src/styles/viewers.css`.

class JsonTree {

  static maybeJson(s) {
    if (s == null) return false;
    const str = typeof s === 'string' ? s : String(s);
    // Fast path — skip leading whitespace without regex.
    let i = 0;
    while (i < str.length && (str.charCodeAt(i) <= 32)) i++;
    if (i >= str.length) return false;
    const ch = str.charAt(i);
    return ch === '{' || ch === '[';
  }

  // Returns a parsed object/array, or `undefined` if the string doesn't
  // parse or parses to a scalar. Callers that want scalar-accepting parse
  // should use JSON.parse directly.
  static tryParse(s) {
    if (!JsonTree.maybeJson(s)) return undefined;
    try {
      const v = JSON.parse(s);
      if (v && typeof v === 'object') return v;
    } catch (_) { /* fall through */ }
    return undefined;
  }

  // Evaluate a JSON path-array against a parsed value. Paths look like
  //   ['user', '[2]', 'name'] — bracketed integers select array indices,
  //   '[*]' globs every array entry (returns the first found leaf).
  static pathGet(value, path) {
    if (!path || !path.length) return value;
    // Fast path for plain dotted paths (no stars) — single cursor.
    let hasStar = false;
    for (const s of path) { if (s === '[*]') { hasStar = true; break; } }
    if (!hasStar) {
      let cur = value;
      for (const seg of path) {
        if (cur == null) return undefined;
        if (/^\[\d+\]$/.test(seg)) {
          const i = Number(seg.slice(1, -1));
          cur = cur[i];
        } else {
          cur = cur[seg];
        }
      }
      return cur;
    }
    // Star path — walk every branch, return first found scalar leaf.
    let cur = [value];
    for (const seg of path) {
      const next = [];
      for (const v of cur) {
        if (v == null) continue;
        if (seg === '[*]' && Array.isArray(v)) {
          for (const el of v) next.push(el);
        } else if (/^\[\d+\]$/.test(seg) && Array.isArray(v)) {
          next.push(v[Number(seg.slice(1, -1))]);
        } else if (typeof v === 'object') {
          next.push(v[seg]);
        }
      }
      cur = next;
      if (!cur.length) return undefined;
    }
    for (const v of cur) {
      if (v != null && typeof v !== 'object') return v;
    }
    return undefined;
  }

  static pathLabel(path) {
    if (!path || !path.length) return '(root)';
    return path.map(s => /^\[.*\]$/.test(s) ? s : '.' + s).join('').replace(/^\./, '');
  }

  // Walk every leaf in `value`, emitting `cb(pathKey, path, leafValue)` for
  // each scalar. Arrays collapse to `[*]` so sibling elements share a path
  // — mirrors the Timeline auto-extractor's sampling semantics.
  static collectLeafPaths(value, cb, opts) {
    const maxDepth = (opts && opts.maxDepth) || 8;
    const walk = (v, path) => {
      if (path.length >= maxDepth) return;
      if (v == null) return;
      if (typeof v === 'object') {
        if (Array.isArray(v)) {
          // Sample the first few entries only — paths merge under [*].
          const sampleN = Math.min(v.length, (opts && opts.arraySample) || 5);
          for (let i = 0; i < sampleN; i++) walk(v[i], path.concat('[*]'));
        } else {
          for (const k of Object.keys(v)) walk(v[k], path.concat(k));
        }
      } else {
        if (!path.length) return;
        cb(path.join('·'), path, v);
      }
    };
    walk(value, []);
  }

  /**
   * Render a parsed JSON value as a collapsible tree.
   *   value               — any JSON-shaped value (object/array/scalar)
   *   opts.onPick         — optional (path, value) callback
   *   opts.autoOpenDepth  — default 1; `Infinity` auto-expands all levels
   *   opts.maxChildren    — default 200
   *   opts.className      — override wrapper class (default 'json-tree')
   */
  static render(value, opts) {
    opts = opts || {};
    const onPick = typeof opts.onPick === 'function' ? opts.onPick : null;
    // Accept any non-NaN number — including `Infinity` for "expand every
    // level up to MAX_DEPTH". `Number.isFinite` would silently reject
    // Infinity and fall back to 1, which bit the grid drawer.
    const autoOpenDepth = (typeof opts.autoOpenDepth === 'number' && !Number.isNaN(opts.autoOpenDepth))
      ? opts.autoOpenDepth
      : 1;
    const maxChildren   = Number.isFinite(opts.maxChildren)   ? opts.maxChildren   : 200;
    const MAX_DEPTH     = 16;

    const wrap = document.createElement('div');
    wrap.className = opts.className || 'json-tree';

    const renderNode = (v, path, label, parent, depth) => {
      const row = document.createElement('div');
      row.className = 'json-tree-row';

      const kind = v === null ? 'null'
        : Array.isArray(v) ? 'array'
        : typeof v;
      const isComposite = (kind === 'object' || kind === 'array');

      const toggle = document.createElement('span');
      toggle.className = 'json-tree-toggle';
      toggle.textContent = isComposite ? '▸' : ' ';
      if (!isComposite) toggle.classList.add('json-tree-toggle-leaf');
      row.appendChild(toggle);

      if (label != null) {
        const key = document.createElement('span');
        key.className = 'json-tree-key';
        key.textContent = label;
        if (onPick && !isComposite) key.title = 'Right-click for Extract / Include / Exclude';
        row.appendChild(key);
        row.appendChild(document.createTextNode(': '));

        // Right-click a scalar leaf → context menu with Extract / Include /
        // Exclude. Composite (object/array) keys have no menu — subtrees
        // have no scalar value to compare and an "extract whole subtree"
        // column would just stringify the object, which isn't useful.
        if (onPick && !isComposite) {
          key.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            e.stopPropagation();
            JsonTree._openKeyMenu(e, path.slice(), v, onPick);
          });
        }
      }

      const val = document.createElement('span');
      val.className = 'json-tree-val json-tree-val-' + kind;
      if (kind === 'string') {
        // Clip extremely long strings so a 100 KB blob doesn't lock up
        // layout. Full text still visible on click-to-copy via title.
        const s = v.length > 2000 ? v.substring(0, 2000) + ' …' : v;
        val.textContent = JSON.stringify(s);
        if (v.length > 200) val.title = v.length > 10000 ? v.substring(0, 10000) + '…' : v;
      } else if (kind === 'object') {
        val.textContent = `{…${Object.keys(v).length}}`;
      } else if (kind === 'array') {
        val.textContent = `[…${v.length}]`;
      } else {
        val.textContent = String(v);
      }
      row.appendChild(val);

      parent.appendChild(row);

      if (!isComposite || depth >= MAX_DEPTH) {
        if (isComposite) {
          const hint = document.createElement('div');
          hint.className = 'json-tree-hint';
          hint.textContent = '… depth limit reached';
          parent.appendChild(hint);
        }
        return;
      }

      const child = document.createElement('div');
      child.className = 'json-tree-child';
      child.style.display = 'none';
      parent.appendChild(child);

      let built = false;
      const buildChildren = () => {
        if (built) return; built = true;
        if (kind === 'array') {
          const n = Math.min(v.length, maxChildren);
          for (let i = 0; i < n; i++) {
            renderNode(v[i], path.concat('[' + i + ']'), '[' + i + ']', child, depth + 1);
          }
          if (v.length > maxChildren) {
            const hint = document.createElement('div');
            hint.className = 'json-tree-hint';
            hint.textContent = `… +${(v.length - maxChildren).toLocaleString()} more items`;
            child.appendChild(hint);
          }
        } else {
          const keys = Object.keys(v);
          const n = Math.min(keys.length, maxChildren);
          for (let i = 0; i < n; i++) {
            renderNode(v[keys[i]], path.concat(keys[i]), keys[i], child, depth + 1);
          }
          if (keys.length > maxChildren) {
            const hint = document.createElement('div');
            hint.className = 'json-tree-hint';
            hint.textContent = `… +${(keys.length - maxChildren).toLocaleString()} more keys`;
            child.appendChild(hint);
          }
        }
      };

      const expand = (open) => {
        if (open) { buildChildren(); child.style.display = ''; toggle.textContent = '▾'; }
        else     { child.style.display = 'none'; toggle.textContent = '▸'; }
      };

      toggle.addEventListener('click', (e) => {
        e.stopPropagation();
        expand(child.style.display === 'none');
      });
      // Left-clicking the key also toggles expand/collapse. (The
      // contextmenu handler above — only wired on scalar leaves — is
      // what drives Extract / Include / Exclude, and doesn't conflict
      // because `contextmenu` fires on right-click only.)
      if (label != null) {
        row.querySelector('.json-tree-key').addEventListener('click', (e) => {
          e.stopPropagation();
          expand(child.style.display === 'none');
        });
      }

      if (depth < autoOpenDepth) expand(true);
    };

    renderNode(value, [], null, wrap, 0);
    return wrap;
  }

  // Open the right-click context menu on a `.json-tree-key` span.
  // Only wired on scalar leaves (Extract column / Include value /
  // Exclude value). Composite keys intentionally have no menu.
  // Closes on outside click, Escape, and on scroll/resize.
  static _openKeyMenu(ev, path, value, onPick) {
    // Tear down any previous menu first.
    JsonTree._closeKeyMenu();

    const items = [];
    items.push({ label: 'ƒx Extract column', action: 'extract' });
    items.push({ sep: true });
    items.push({ label: '✓ Include value',   action: 'include' });
    items.push({ label: '✕ Exclude value',   action: 'exclude' });

    const menu = document.createElement('div');
    menu.className = 'json-tree-menu';
    menu.setAttribute('role', 'menu');
    for (const it of items) {
      if (it.sep) {
        const s = document.createElement('div');
        s.className = 'json-tree-menu-sep';
        menu.appendChild(s);
        continue;
      }
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'json-tree-menu-item';
      b.textContent = it.label;
      b.addEventListener('click', (e) => {
        e.stopPropagation();
        JsonTree._closeKeyMenu();
        try { onPick(path.slice(), value, it.action); }
        catch (_) { /* host callback */ }
      });
      menu.appendChild(b);
    }

    // Position at cursor, then nudge into viewport after measuring.
    menu.style.position = 'fixed';
    menu.style.left = ev.clientX + 'px';
    menu.style.top  = ev.clientY + 'px';
    menu.style.zIndex = '10000';
    document.body.appendChild(menu);
    const rect = menu.getBoundingClientRect();
    const vw = window.innerWidth, vh = window.innerHeight;
    if (rect.right > vw)  menu.style.left = Math.max(0, vw - rect.width - 4) + 'px';
    if (rect.bottom > vh) menu.style.top  = Math.max(0, vh - rect.height - 4) + 'px';

    // Autoclose handlers — registered once, torn down on close.
    const close = () => JsonTree._closeKeyMenu();
    const onDocDown = (e) => { if (!menu.contains(e.target)) close(); };
    const onKey = (e) => { if (e.key === 'Escape') close(); };
    // Defer the pointerdown handler registration by one tick so the
    // originating contextmenu event (which sometimes synthesises an
    // immediate pointerdown on the key itself) doesn't insta-close us.
    setTimeout(() => {
      document.addEventListener('pointerdown', onDocDown, true);
    }, 0);
    document.addEventListener('keydown', onKey, true);
    window.addEventListener('scroll', close, true);
    window.addEventListener('resize', close, true);

    JsonTree._activeMenu = {
      el: menu,
      cleanup: () => {
        document.removeEventListener('pointerdown', onDocDown, true);
        document.removeEventListener('keydown', onKey, true);
        window.removeEventListener('scroll', close, true);
        window.removeEventListener('resize', close, true);
      },
    };
  }

  static _closeKeyMenu() {
    const m = JsonTree._activeMenu;
    if (!m) return;
    try { m.cleanup(); } catch (_) { /* noop */ }
    if (m.el && m.el.parentNode) m.el.parentNode.removeChild(m.el);
    JsonTree._activeMenu = null;
  }
}

// Expose globally so it's usable from the non-module concatenated build.
if (typeof window !== 'undefined') window.JsonTree = JsonTree;
