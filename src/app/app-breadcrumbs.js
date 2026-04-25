// ════════════════════════════════════════════════════════════════════════════
// App — Debug breadcrumbs
//
// A lightweight, always-on, opt-in-visibility diagnostic stream. The
// non-fatal helper (`App._reportNonFatal`) and a handful of load-chain
// milestones tee into `App._breadcrumb(scope, msg, data?)`, which:
//
//   1. Pushes an entry onto a fixed-size circular buffer (50 entries; oldest
//      drops off the back). Every push is sub-microsecond — this is the hot
//      path even when no panel is mounted, because we want a user who flips
//      the dev-mode flag mid-session to see the last 50 events that already
//      happened, not start with an empty list.
//
//   2. If the dev-mode flag (`localStorage.loupe_dev_breadcrumbs === '1'`)
//      is on, mounts a small fixed-position overlay in the bottom-right
//      corner and renders the buffer as a stack of rows
//      `[+Δms] scope · msg`. Row click expands the optional `data` payload
//      as a single-line JSON.stringify (truncated to 240 chars). Theme-
//      aware via the existing CSS custom properties — no new tokens.
//
//   3. Exposes `app._toggleDevBreadcrumbs()` so a dev can flip the flag
//      from the browser console without poking localStorage by hand. The
//      panel re-mounts immediately; close-button does the inverse.
//
// Out of scope (deliberate):
//   • Persisting buffer across reloads — diagnostics are session-scoped;
//     persisting would defeat the "what just happened?" purpose.
//   • A keyboard shortcut — none today. Add later if wanted; the toggle
//     entry points are documented in CONTRIBUTING.
//   • Renderer-side breadcrumbs — the seed sites (load entry, size cap,
//     non-fatal helper, watchdog timeout, worker timeout) cover the
//     "format X failed to detect Y" reporter use-case. Renderers can opt
//     in later via `if (typeof this._breadcrumb === 'function') …`.
// ════════════════════════════════════════════════════════════════════════════

const _DEV_BREADCRUMBS_KEY = 'loupe_dev_breadcrumbs';
const _BREADCRUMB_MAX = 50;
const _DATA_PREVIEW_MAX_CHARS = 240;

Object.assign(App.prototype, {

  // Wired into App.init() (src/app/app-core.js). Reads the persisted flag
  // and, if set, mounts the overlay panel. The buffer itself is a
  // lazy-initialised array on `_breadcrumb()` calls, so the helper is safe
  // to call before init runs.
  _initBreadcrumbs() {
    let on = false;
    try { on = localStorage.getItem(_DEV_BREADCRUMBS_KEY) === '1'; } catch (_) { /* private mode */ }
    if (on) this._mountBreadcrumbsPanel();
  },

  // Public diagnostic primitive. Always pushes to the buffer; renders only
  // if the panel is mounted. Callers should keep `scope` short and
  // kebab-case — it's the dominant tag in the visible row.
  _breadcrumb(scope, msg, data) {
    if (!this._breadcrumbBuf) this._breadcrumbBuf = [];
    const buf = this._breadcrumbBuf;
    buf.push({
      t: (typeof performance !== 'undefined' && performance.now) ? performance.now() : Date.now(),
      scope: String(scope == null ? '' : scope),
      msg: String(msg == null ? '' : msg),
      data: data,
    });
    // Drop oldest entries past the cap. Splice at the front because the
    // buffer is small (50) — the cost is negligible compared to a row
    // re-render and keeps the array logically a queue.
    if (buf.length > _BREADCRUMB_MAX) buf.splice(0, buf.length - _BREADCRUMB_MAX);
    if (this._breadcrumbsPanel) this._renderBreadcrumbsPanel();
  },

  // Console-friendly entry point for flipping the persisted flag. Returns
  // the new state ('on' | 'off') so an analyst poking from devtools
  // immediately sees what happened.
  _toggleDevBreadcrumbs() {
    let cur = false;
    try { cur = localStorage.getItem(_DEV_BREADCRUMBS_KEY) === '1'; } catch (_) {}
    const next = !cur;
    try {
      if (next) localStorage.setItem(_DEV_BREADCRUMBS_KEY, '1');
      else localStorage.removeItem(_DEV_BREADCRUMBS_KEY);
    } catch (_) { /* private mode — fall back to in-session toggle only */ }
    if (next) this._mountBreadcrumbsPanel();
    else this._unmountBreadcrumbsPanel();
    return next ? 'on' : 'off';
  },

  _mountBreadcrumbsPanel() {
    if (this._breadcrumbsPanel) return;
    const panel = document.createElement('div');
    panel.className = 'loupe-breadcrumbs-panel';
    panel.setAttribute('role', 'log');
    panel.setAttribute('aria-label', 'Loupe debug breadcrumbs');

    const header = document.createElement('div');
    header.className = 'loupe-breadcrumbs-header';

    const title = document.createElement('span');
    title.className = 'loupe-breadcrumbs-title';
    title.textContent = 'Debug breadcrumbs';
    header.appendChild(title);

    const spacer = document.createElement('span');
    spacer.className = 'loupe-breadcrumbs-spacer';
    header.appendChild(spacer);

    const clearBtn = document.createElement('button');
    clearBtn.type = 'button';
    clearBtn.className = 'loupe-breadcrumbs-btn';
    clearBtn.textContent = 'Clear';
    clearBtn.title = 'Empty the breadcrumb buffer';
    clearBtn.addEventListener('click', () => {
      this._breadcrumbBuf = [];
      this._renderBreadcrumbsPanel();
    });
    header.appendChild(clearBtn);

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'loupe-breadcrumbs-btn';
    closeBtn.textContent = '✕';
    closeBtn.title = 'Hide panel and disable breadcrumbs (loupe_dev_breadcrumbs flag cleared)';
    closeBtn.addEventListener('click', () => { this._toggleDevBreadcrumbs(); });
    header.appendChild(closeBtn);

    panel.appendChild(header);

    const list = document.createElement('div');
    list.className = 'loupe-breadcrumbs-list';
    panel.appendChild(list);

    document.body.appendChild(panel);
    this._breadcrumbsPanel = panel;
    this._breadcrumbsList = list;
    this._renderBreadcrumbsPanel();
  },

  _unmountBreadcrumbsPanel() {
    const p = this._breadcrumbsPanel;
    if (!p) return;
    try { p.remove(); } catch (_) {}
    this._breadcrumbsPanel = null;
    this._breadcrumbsList = null;
  },

  _renderBreadcrumbsPanel() {
    const list = this._breadcrumbsList;
    if (!list) return;
    const buf = this._breadcrumbBuf || [];
    // Render newest-first so the latest event is always visible without
    // scrolling. Truncate to the cap defensively in case a future caller
    // pushes past it.
    const rows = buf.slice(-_BREADCRUMB_MAX).reverse();
    list.textContent = '';
    if (!rows.length) {
      const empty = document.createElement('div');
      empty.className = 'loupe-breadcrumbs-empty';
      empty.textContent = '(no breadcrumbs yet — load a file)';
      list.appendChild(empty);
      return;
    }
    const t0 = rows[rows.length - 1].t; // earliest visible event
    for (const e of rows) {
      const row = document.createElement('div');
      row.className = 'loupe-breadcrumbs-row';
      const dt = Math.max(0, Math.round(e.t - t0));
      const head = document.createElement('div');
      head.className = 'loupe-breadcrumbs-head';
      const ts = document.createElement('span');
      ts.className = 'loupe-breadcrumbs-ts';
      ts.textContent = '+' + dt + 'ms';
      head.appendChild(ts);
      const sc = document.createElement('span');
      sc.className = 'loupe-breadcrumbs-scope';
      sc.textContent = e.scope;
      head.appendChild(sc);
      const ms = document.createElement('span');
      ms.className = 'loupe-breadcrumbs-msg';
      ms.textContent = e.msg;
      head.appendChild(ms);
      row.appendChild(head);
      if (e.data !== undefined) {
        let preview = '';
        try {
          preview = JSON.stringify(e.data);
        } catch (_) {
          // e.g. circular references, BigInt, etc. — fall back to a
          // shallow toString so the breadcrumb still has *something*
          // useful to inspect.
          try { preview = String(e.data); } catch (__) { preview = '<unserialisable>'; }
        }
        if (preview && preview.length > _DATA_PREVIEW_MAX_CHARS) {
          preview = preview.slice(0, _DATA_PREVIEW_MAX_CHARS) + '… (truncated)';
        }
        if (preview) {
          const dataEl = document.createElement('div');
          dataEl.className = 'loupe-breadcrumbs-data';
          dataEl.textContent = preview;
          row.appendChild(dataEl);
        }
      }
      list.appendChild(row);
    }
  },

});
