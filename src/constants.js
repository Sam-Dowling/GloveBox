'use strict';
// ════════════════════════════════════════════════════════════════════════════
// constants.js — XML namespace constants, unit converters, DOM/XML helpers
// Loaded first; used by every other module.
// ════════════════════════════════════════════════════════════════════════════

// ── XML namespace constants ───────────────────────────────────────────────────
const W    = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
const R_NS = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
const A_NS = 'http://schemas.openxmlformats.org/drawingml/2006/main';
const WP_NS= 'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing';
const V_NS = 'urn:schemas-microsoft-com:vml';
const MC_NS= 'http://schemas.openxmlformats.org/markup-compatibility/2006';
const PKG  = 'http://schemas.openxmlformats.org/package/2006/relationships';

// ── Unit converters ───────────────────────────────────────────────────────────
const dxaToPx = v => (v / 1440) * 96;   // twentieths-of-a-point → CSS pixels
const emuToPx = v => (v / 914400) * 96; // English Metric Units  → CSS pixels
const twipToPt= v => v / 20;            // twips → points

// ── Namespaced attribute helpers ──────────────────────────────────────────────
function wa(el, name) {
  if (!el) return null;
  return el.getAttributeNS(W, name) || el.getAttribute('w:' + name) || null;
}
function ra(el, name) {
  if (!el) return null;
  return el.getAttributeNS(R_NS, name) || el.getAttribute('r:' + name) || null;
}

// ── Child-element helpers ─────────────────────────────────────────────────────
/** First child element in the W namespace with the given local name. */
function wfirst(parent, localName) {
  if (!parent) return null;
  const nl = parent.getElementsByTagNameNS(W, localName);
  return nl.length ? nl[0] : null;
}
/** Direct element children in the W namespace with the given local name. */
function wdirect(parent, localName) {
  if (!parent) return [];
  return Array.from(parent.childNodes).filter(
    n => n.nodeType === 1 && n.localName === localName
  );
}

// ── URL sanitiser ─────────────────────────────────────────────────────────────
/** Returns the URL if it is http/https/mailto, otherwise null. */
function sanitizeUrl(url) {
  if (!url) return null;
  try {
    const p = new URL(url, 'https://placeholder.invalid');
    if (['http:', 'https:', 'mailto:'].includes(p.protocol)) return url;
  } catch(e) {}
  return null;
}

// ── String helpers ────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
                  .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function toRoman(n) {
  const v=[1000,900,500,400,100,90,50,40,10,9,5,4,1];
  const s=['M','CM','D','CD','C','XC','L','XL','X','IX','V','IV','I'];
  let r=''; for(let i=0;i<v.length;i++) while(n>=v[i]){r+=s[i];n-=v[i];} return r;
}
