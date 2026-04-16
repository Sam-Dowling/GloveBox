'use strict';
// ════════════════════════════════════════════════════════════════════════════
// constants.js — XML namespace constants, unit converters, DOM/XML helpers
// Loaded first; used by every other module.
// ════════════════════════════════════════════════════════════════════════════

// ── XML namespace constants ───────────────────────────────────────────────────
const W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main';
const R_NS = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships';
const A_NS = 'http://schemas.openxmlformats.org/drawingml/2006/main';
const WP_NS = 'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing';
const V_NS = 'urn:schemas-microsoft-com:vml';
const MC_NS = 'http://schemas.openxmlformats.org/markup-compatibility/2006';
const PKG = 'http://schemas.openxmlformats.org/package/2006/relationships';

// ── Unit converters ───────────────────────────────────────────────────────────
const dxaToPx = v => (v / 1440) * 96;   // twentieths-of-a-point → CSS pixels
const emuToPx = v => (v / 914400) * 96; // English Metric Units  → CSS pixels
const twipToPt = v => v / 20;            // twips → points

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
  } catch (e) { }
  return null;
}

// ── Standardised IOC types ────────────────────────────────────────────────────
/** IOC type constants used for all findings / externalRefs / interestingStrings. */
const IOC = Object.freeze({
  URL: 'URL',
  EMAIL: 'Email',
  IP: 'IP Address',
  FILE_PATH: 'File Path',
  UNC_PATH: 'UNC Path',
  ATTACHMENT: 'Attachment',
  YARA: 'YARA Match',
  PATTERN: 'Pattern',
  INFO: 'Info',
  HASH: 'Hash',
  COMMAND_LINE: 'Command Line',
  PROCESS: 'Process',
  HOSTNAME: 'Hostname',
  USERNAME: 'Username',
  REGISTRY_KEY: 'Registry Key',
});

/** IOC types whose values are directly copyable in the sidebar. */
const IOC_COPYABLE = new Set([IOC.URL, IOC.EMAIL, IOC.IP, IOC.FILE_PATH, IOC.UNC_PATH, IOC.HASH, IOC.COMMAND_LINE, IOC.PROCESS, IOC.HOSTNAME, IOC.USERNAME, IOC.REGISTRY_KEY]);

// ── String helpers ────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function toRoman(n) {
  const v = [1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1];
  const s = ['M', 'CM', 'D', 'CD', 'C', 'XC', 'L', 'XL', 'X', 'IX', 'V', 'IV', 'I'];
  let r = ''; for (let i = 0; i < v.length; i++) while (n >= v[i]) { r += s[i]; n -= v[i]; } return r;
}

// ── File path trimming ────────────────────────────────────────────────────────
/**
 * Trim garbage appended after file extensions in binary-extracted path strings.
 * PE/ELF string extraction can fuse adjacent printable data into one string,
 * e.g. "file.pdbtEXtSoftwareAdobe..." → should be "file.pdb".
 * If the last component's extension part is unreasonably long (>10 chars) and
 * doesn't match a known extension, trim at the first recognized extension.
 */
const _KNOWN_EXT_RE = /^\.(exe|dll|sys|drv|ocx|cpl|scr|com|pdb|lib|obj|exp|pif|lnk|url|bat|cmd|ps1|py|vbs|vbe|js|jse|wsh|wsf|wsc|hta|sct|inf|reg|msi|msp|mst|txt|log|ini|cfg|conf|config|xml|html?|json|ya?ml|toml|csv|tsv|sql|sqlite|db|mdb|accdb|doc[xm]?|xls[xmb]?|ppt[xm]?|pdf|rtf|odt|ods|odp|one|eml|msg|pst|evtx?|zip|rar|7z|gz|tar|bz2|xz|cab|iso|img|vhdx?|vmdk|dmp|bak|tmp|old|dat|bin|pyc|pyo|pyw|rb|java|class|jar|war|apk|cpp|hpp|cs|go|rs|php|aspx?|jsp|sh|so|dylib|manifest|pem|crt|cer|der|key|pfx|ico|png|jpe?g|gif|bmp|svg|webp|tiff?|mp[34]|avi|mov|wmv|wav|ogg|woff2?|ttf|otf|eot)/i;
function _trimPathExtGarbage(path) {
  const ls = path.lastIndexOf('\\');
  if (ls < 0) return path;
  const fn = path.slice(ls + 1);
  const dot = fn.lastIndexOf('.');
  if (dot < 0) return path;
  const ext = fn.slice(dot + 1);
  if (ext.length <= 10) return path;           // extension is a reasonable length
  const tail = fn.slice(dot);                   // e.g. ".pdbtEXtSoftwareAdobe"
  const extM = tail.match(_KNOWN_EXT_RE);
  return extM ? path.slice(0, ls + 1 + dot + extM[0].length) : path;
}

// ── Byte formatting ───────────────────────────────────────────────────────────
/** Format bytes to human-readable string (B, KB, MB, GB). */
function fmtBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
  return (n / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}
