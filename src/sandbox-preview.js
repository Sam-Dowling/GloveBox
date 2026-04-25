'use strict';
// ════════════════════════════════════════════════════════════════════════════
// sandbox-preview.js — Shared sandboxed-iframe + drag-shield helper
// ════════════════════════════════════════════════════════════════════════════
//
// Single source of truth for the "render some untrusted markup in a
// sandboxed iframe with an overlay drag/scroll shield" recipe shared by
// `html-renderer.js` and `svg-renderer.js`. Each call site previously
// hand-rolled its own `<iframe>` + `sandbox` attribute + inner CSP +
// drag-shield `<div>` + wheel/touch/drag/drop event wiring (~60 LOC of
// near-duplicated boilerplate per renderer). This file is the canonical
// implementation; renderers must call `SandboxPreview.create({...})`
// rather than re-rolling the ceremony — see CONTRIBUTING.md
// "Iframe sandbox helper" subsection and Tripwires.
//
// Boundary contract (preserved from the original sites verbatim):
//
//   • iframe.sandbox = 'allow-same-origin'
//       Required for `iframe.contentWindow.scrollBy(...)` to work from
//       the parent (we forward wheel/touch deltas programmatically). The
//       inner content is still scriptless because the inner CSP below
//       blocks `script-src` entirely.
//
//   • Inner CSP <meta> tag:
//       default-src 'none'; style-src 'unsafe-inline'; img-src data:
//     Locks the sandboxed document down regardless of what the file
//     declares — blocks scripts, network fetches, fonts, objects;
//     allows only inline styles and inline (data:) images.
//
//   • iframe.srcdoc carries the inner CSP + content. We never use a
//     blob: URL — `srcdoc` works under `file://` (Loupe's primary
//     deployment target) and is same-origin with the parent so
//     `scrollBy` is reachable.
//
//   • Drag-shield `<div>` is appended **after** the iframe inside the
//     same `position:relative` wrapper, so it covers the iframe and
//     intercepts wheel/touch/drag events that would otherwise go to the
//     iframe's content document.
//
//   • Drag-drop interception (when `forwardDragDrop:true`) re-dispatches
//     `loupe-dragenter` / `loupe-dragleave` / `loupe-drop` CustomEvents
//     on `window`. `app-core.js` listens for these and routes them
//     through `_handleFiles` so a file dropped on the iframe overlay
//     opens in Loupe instead of being navigated to by the browser.
//
// The helper deliberately does NOT mount its returned elements — the
// caller decides the wrapper class and append order. Convention: append
// the iframe first, then the drag shield, both into the same
// `position:relative` container.
//
// ════════════════════════════════════════════════════════════════════════════

(function () {

  // Default inner CSP applied to the sandboxed document. Pinned here so
  // the literal can't drift between html-renderer and svg-renderer.
  const DEFAULT_INNER_CSP =
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:";

  /**
   * Create a sandboxed iframe + drag/scroll shield pair.
   *
   * @param {Object} opts
   * @param {string} opts.html
   *   Inner content. Treated as full document body (or full HTML when
   *   `wrap:false`) injected into `iframe.srcdoc`.
   * @param {boolean} [opts.wrap=false]
   *   When false (html-renderer path), the inner CSP `<meta>` is
   *   prepended to `html` and the result is assigned directly to
   *   `srcdoc` — preserves caller-controlled `<!DOCTYPE>` / `<html>`.
   *   When true (svg-renderer path), the helper assembles a full
   *   `<!DOCTYPE html><html><head><meta CSP><style>${wrapStyle}</style>
   *   </head><body>${html}</body></html>` shell.
   * @param {string} [opts.wrapStyle='']
   *   `<style>` block injected into the wrap shell when `wrap:true`.
   * @param {string} [opts.csp]  Override the inner CSP literal.
   * @param {string} [opts.sandbox='allow-same-origin']  iframe.sandbox.
   * @param {string} [opts.title='Sandboxed preview']  iframe.title.
   * @param {string} [opts.iframeClassName='']  iframe.className.
   * @param {string} [opts.shieldClassName='']  drag-shield div.className.
   * @param {boolean} [opts.forwardScroll=true]
   *   Wire wheel events on the shield → `iframe.contentWindow.scrollBy(deltaX, deltaY)`.
   * @param {boolean} [opts.forwardTouchScroll=false]
   *   Wire touchstart/touchmove → `scrollBy` based on touch delta.
   * @param {boolean} [opts.forwardDragDrop=false]
   *   Re-dispatch dragenter/dragleave/drop as `loupe-*` CustomEvents on
   *   `window`, with `dataTransfer.dropEffect='copy'` set during
   *   dragover (matches the legacy html-renderer semantics).
   * @returns {{iframe: HTMLIFrameElement, dragShield: HTMLDivElement}}
   */
  function create(opts) {
    const o = opts || {};
    const html = typeof o.html === 'string' ? o.html : '';
    const wrap = !!o.wrap;
    const wrapStyle = typeof o.wrapStyle === 'string' ? o.wrapStyle : '';
    const csp = typeof o.csp === 'string' ? o.csp : DEFAULT_INNER_CSP;
    const sandbox = typeof o.sandbox === 'string' ? o.sandbox : 'allow-same-origin';
    const title = typeof o.title === 'string' ? o.title : 'Sandboxed preview';
    const iframeClassName = o.iframeClassName || '';
    const shieldClassName = o.shieldClassName || '';
    const forwardScroll = o.forwardScroll !== false;  // default true
    const forwardTouchScroll = !!o.forwardTouchScroll;
    const forwardDragDrop = !!o.forwardDragDrop;

    // ── Build iframe ─────────────────────────────────────────────────
    const iframe = document.createElement('iframe');
    if (iframeClassName) iframe.className = iframeClassName;
    iframe.sandbox = sandbox;
    iframe.title = title;

    const cspMeta = '<meta http-equiv="Content-Security-Policy" content="' + csp + '">';
    if (wrap) {
      iframe.srcdoc =
        '<!DOCTYPE html><html><head>' + cspMeta +
        (wrapStyle ? '<style>' + wrapStyle + '</style>' : '') +
        '</head><body>' + html + '</body></html>';
    } else {
      iframe.srcdoc = cspMeta + html;
    }

    // ── Build drag shield ────────────────────────────────────────────
    const dragShield = document.createElement('div');
    if (shieldClassName) dragShield.className = shieldClassName;

    // ── Drag/drop forwarding (html-renderer parity) ─────────────────
    if (forwardDragDrop) {
      dragShield.addEventListener('dragenter', e => {
        e.preventDefault();
        e.stopPropagation();
        window.dispatchEvent(new CustomEvent('loupe-dragenter'));
      });

      dragShield.addEventListener('dragover', e => {
        e.preventDefault();
        e.stopPropagation();
        if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
      });

      dragShield.addEventListener('dragleave', e => {
        e.preventDefault();
        e.stopPropagation();
        window.dispatchEvent(new CustomEvent('loupe-dragleave'));
      });

      dragShield.addEventListener('drop', e => {
        e.preventDefault();
        e.stopPropagation();
        if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
          window.dispatchEvent(new CustomEvent('loupe-drop', {
            detail: { files: e.dataTransfer.files }
          }));
        }
      });
    }

    // ── Scroll forwarding ────────────────────────────────────────────
    // Works because of allow-same-origin + srcdoc — the iframe document
    // is same-origin with the parent so contentWindow.scrollBy is
    // reachable. The try/catch is a defensive guard against future
    // sandbox tweaks that drop allow-same-origin.
    if (forwardScroll) {
      dragShield.addEventListener('wheel', e => {
        e.preventDefault();
        try {
          iframe.contentWindow.scrollBy(e.deltaX, e.deltaY);
        } catch (_) { /* ignore if cross-origin error */ }
      }, { passive: false });
    }

    // ── Touch-scroll forwarding (html-renderer parity) ──────────────
    if (forwardTouchScroll) {
      let touchStartY = 0;
      let touchStartX = 0;

      dragShield.addEventListener('touchstart', e => {
        if (e.touches.length === 1) {
          touchStartY = e.touches[0].clientY;
          touchStartX = e.touches[0].clientX;
        }
      }, { passive: true });

      dragShield.addEventListener('touchmove', e => {
        if (e.touches.length === 1) {
          const deltaY = touchStartY - e.touches[0].clientY;
          const deltaX = touchStartX - e.touches[0].clientX;
          touchStartY = e.touches[0].clientY;
          touchStartX = e.touches[0].clientX;
          try {
            iframe.contentWindow.scrollBy(deltaX, deltaY);
          } catch (_) { /* ignore if cross-origin error */ }
        }
      }, { passive: true });
    }

    return { iframe, dragShield };
  }

  // Public surface — attached to window so renderers (which are loaded
  // after this file per JS_FILES order) can reach the helper without
  // an import.
  window.SandboxPreview = {
    create: create,
    DEFAULT_INNER_CSP: DEFAULT_INNER_CSP
  };

})();
