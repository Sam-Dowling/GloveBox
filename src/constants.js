'use strict';
// ════════════════════════════════════════════════════════════════════════════
// constants.js — XML namespace constants, unit converters, DOM/XML helpers
// Loaded first; used by every other module.
// ════════════════════════════════════════════════════════════════════════════

// ── Parser safety limits ──────────────────────────────────────────────────────
const PARSER_LIMITS = Object.freeze({
  MAX_DEPTH:        32,                   // Max recursion / nesting depth
  MAX_UNCOMPRESSED: 50 * 1024 * 1024,     // 50 MB — max decompressed output
  MAX_RATIO:        100,                  // Per-entry compression ratio abort
  MAX_ENTRIES:      10_000,               // Max archive entries before truncation
  TIMEOUT_MS:       60_000,               // Parser timeout (60 s)
});

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
  MAC: 'MAC Address',
  DOMAIN: 'Domain',
  GUID: 'GUID',
  FINGERPRINT: 'Fingerprint',
  PACKAGE_NAME: 'Package Name',
});

/** IOC types whose values are directly copyable in the sidebar. */
const IOC_COPYABLE = new Set([IOC.URL, IOC.EMAIL, IOC.IP, IOC.FILE_PATH, IOC.UNC_PATH, IOC.HASH, IOC.COMMAND_LINE, IOC.PROCESS, IOC.HOSTNAME, IOC.USERNAME, IOC.REGISTRY_KEY, IOC.MAC, IOC.DOMAIN, IOC.GUID, IOC.FINGERPRINT, IOC.PACKAGE_NAME]);

/**
 * Canonical severity floors per IOC type. These are the default severities
 * renderers should emit for passive extractions (URLs in a document, emails
 * in a PGP UID, etc.) — renderers are free to *escalate* when context
 * demands it (e.g. a URL inside a phishing EML with authTripleFail), but
 * they should never emit below the floor.
 *
 * The values here are descriptive, not enforced at runtime; every renderer
 * passes the severity through unchanged. This table exists so the IOC
 * conformity audit has a single source of truth to grade against.
 */
const IOC_CANONICAL_SEVERITY = Object.freeze({
  [IOC.URL]:           'info',      // passive URL extraction; escalate for phishing/C2 context
  [IOC.EMAIL]:         'info',      // sender/recipient/UID; escalate on auth-fail + body-URL
  [IOC.IP]:            'info',
  [IOC.FILE_PATH]:     'info',
  [IOC.UNC_PATH]:      'medium',    // UNC in binary = credential-harvest candidate
  [IOC.ATTACHMENT]:    'medium',    // attachments carry macro/script risk by default
  [IOC.YARA]:          'info',      // severity comes from the rule meta; renderer mirrors it
  [IOC.PATTERN]:       'info',      // Detection → IOC mirror; severity carried from detection
  [IOC.INFO]:          'info',      // truncation markers and stats
  [IOC.HASH]:          'info',      // extraction only; no reputation lookup
  [IOC.COMMAND_LINE]:  'high',      // cmd/powershell strings are actionable on sight
  [IOC.PROCESS]:       'info',
  [IOC.HOSTNAME]:      'info',
  [IOC.USERNAME]:      'info',
  [IOC.REGISTRY_KEY]:  'medium',    // persistence-key indicator
  [IOC.MAC]:           'info',
  [IOC.DOMAIN]:        'info',      // auto-derived from URL via tldts (if loaded); pure pivot
  [IOC.GUID]:          'info',      // droid/bundle/product codes; pure pivot
  [IOC.FINGERPRINT]:   'info',      // cert/PGP key thumbprint; pure pivot
  [IOC.PACKAGE_NAME]:  'info',      // npm / dependency identifiers; pure pivot
});

// ── Shared IOC extractors ─────────────────────────────────────────────────────
// Used by renderers that need to pull classic pivot values out of a blob of
// joined strings (PE/ELF/Mach-O string tables, PDF object streams, etc.).
// All functions return a de-duplicated array capped at `cap` entries so a
// pathological input can't blow up the IOC table.

const _URL_RE   = /\b(?:https?|ftp|ftps):\/\/[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+/g;
const _UNC_RE   = /\\\\[A-Za-z0-9._\-$]+(?:\\[A-Za-z0-9._\-$%]+){1,}/g;
const _EMAIL_RE = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;
const _MAC_RE   = /\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g;
const _GUID_RE  = /\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b/g;
const _IPV4_RE  = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/g;
const _HASH_RE  = /\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b/g;

function _dedupCap(arr, cap) {
  const out = [];
  const seen = new Set();
  const lim = cap || 200;
  for (const v of arr) {
    if (!v) continue;
    const k = String(v);
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(k);
    if (out.length >= lim) break;
  }
  return out;
}

function extractUrls(text, cap)         { return _dedupCap((String(text || '').match(_URL_RE)   || []), cap); }
function extractUncPaths(text, cap)     { return _dedupCap((String(text || '').match(_UNC_RE)   || []), cap); }
function extractEmails(text, cap)       { return _dedupCap((String(text || '').match(_EMAIL_RE) || []), cap); }
function extractMacAddresses(text, cap) {
  const raw = String(text || '').match(_MAC_RE) || [];
  // Filter obvious padding / null MACs
  const filtered = raw.filter(m => {
    const hex = m.replace(/[:\-]/g, '').toLowerCase();
    return hex !== '000000000000' && hex !== 'ffffffffffff';
  });
  return _dedupCap(filtered, cap);
}
function extractGuids(text, cap) {
  const raw = String(text || '').match(_GUID_RE) || [];
  // Drop the nil GUID — it's never a pivot
  return _dedupCap(raw.filter(g => g.toLowerCase() !== '00000000-0000-0000-0000-000000000000'), cap);
}
function extractIpAddresses(text, cap) {
  const raw = String(text || '').match(_IPV4_RE) || [];
  // Drop private / loopback / broadcast noise — pure pivot use
  const filtered = raw.filter(ip => {
    if (ip === '0.0.0.0' || ip === '255.255.255.255' || ip === '127.0.0.1') return false;
    const o = ip.split('.').map(Number);
    if (o[0] === 10) return false;
    if (o[0] === 127) return false;
    if (o[0] === 169 && o[1] === 254) return false;
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false;
    if (o[0] === 192 && o[1] === 168) return false;
    if (o[0] >= 224) return false;
    return true;
  });
  return _dedupCap(filtered, cap);
}
function extractHashes(text, cap) { return _dedupCap((String(text || '').match(_HASH_RE) || []), cap); }

/**
 * Private/abuse-friendly public suffixes frequently used for phishing,
 * DDNS, and tunnelling C2 (Cloudflare Tunnel, ngrok, localhost.run, etc.).
 * When tldts reports a URL's registrable domain sitting on one of these
 * suffixes the host is surfaced with an INFO note so analysts can pivot
 * on "is this a free-host / DDNS / tunnelled service?" without having to
 * memorise the current list of abuse-vector providers.
 *
 * Keep this list narrow — each entry must be a suffix that legitimate
 * orgs rarely use as their canonical public surface but that attackers
 * routinely spin up disposable subdomains on. Entries are matched as
 * exact `publicSuffix` values from tldts, so both `trycloudflare.com`
 * and `duckdns.org` register as "private" suffixes when tldts is in
 * ICANN+PRIVATE mode (the default).
 */
const _ABUSE_SUFFIXES = new Set([
  // Tunnelling / reverse-proxy-as-a-service
  'trycloudflare.com', 'cloudflare.net', 'ngrok.io', 'ngrok-free.app',
  'loca.lt', 'localhost.run', 'serveo.net', 'lhrtunnel.link', 'lhr.life',
  // Dynamic DNS / free subdomains (classic C2)
  'duckdns.org', 'no-ip.com', 'no-ip.org', 'no-ip.biz', 'ddns.net',
  'hopto.org', 'zapto.org', 'dynu.net', 'freeddns.org', 'dynv6.net',
  // Static-hosting-as-pastebin
  'github.io', 'gitlab.io', 'pages.dev', 'workers.dev', 'netlify.app',
  'vercel.app', 'firebaseapp.com', 'web.app', 'glitch.me', 'repl.co',
  'replit.app', 'on.fleek.co', 'herokuapp.com', 'r2.dev',
  // IPFS / decentralised web gateways
  'ipfs.dweb.link', 'ipfs.io',
  // Blog/CMS freemium hosts common in phishing kits
  'blogspot.com', 'wordpress.com', 'weebly.com', 'tumblr.com',
  'webflow.io', 'wixsite.com', 'mystrikingly.com', 'yolasite.com',
]);

/**
 * Parse a URL with tldts and return the richest host context we can assemble
 * cheaply. Returns `null` when tldts is unavailable or the URL has no valid
 * host. The returned shape is:
 *   {
 *     hostname,       // full host incl. subdomain ("paypal.attacker.xyz")
 *     domain,         // registrable domain ("attacker.xyz") — null for IPs
 *     subdomain,      // "paypal" — empty string when absent
 *     publicSuffix,   // "xyz" / "co.uk" / "trycloudflare.com"
 *     isIp,           // true for raw-IP hosts
 *     isIcann,        // true when publicSuffix is ICANN-managed
 *     isPrivate,      // true when publicSuffix is a private/abuse suffix
 *     isPunycode,     // true when any label starts with xn-- (IDN/homoglyph)
 *     isAbuseSuffix,  // true when publicSuffix is in _ABUSE_SUFFIXES
 *   }
 */
function _parseUrlHost(url) {
  try {
    if (typeof tldts === 'undefined' || !tldts || !tldts.parse) return null;
    const r = tldts.parse(String(url || ''));
    if (!r || !r.hostname) return null;
    const hostname = String(r.hostname || '');
    const isPunycode = /(^|\.)xn--/i.test(hostname);
    const ps = r.publicSuffix ? String(r.publicSuffix).toLowerCase() : '';
    return {
      hostname,
      domain: r.domain || null,
      subdomain: r.subdomain || '',
      publicSuffix: ps,
      isIp: !!r.isIp,
      isIcann: r.isIcann !== false && !r.isIp,
      isPrivate: !!r.isPrivate,
      isPunycode,
      isAbuseSuffix: !!ps && _ABUSE_SUFFIXES.has(ps),
    };
  } catch (_) { return null; }
}

/**
 * Extract the registrable domain from a URL using tldts (if the vendor lib
 * has been loaded). Returns `null` if tldts is unavailable or the URL
 * doesn't parse to a public-suffix-valid domain. Used by `pushIOC` to
 * auto-emit an `IOC.DOMAIN` sibling for every `IOC.URL`.
 */
function _domainFromUrl(url) {
  const h = _parseUrlHost(url);
  return h && h.domain && !h.isIp ? h.domain : null;
}

/**
 * Canonical IOC pusher. Every renderer that emits IOCs should route through
 * this helper so:
 *   • the on-wire shape is identical (`{type, url, severity, _highlightText, note}`),
 *   • the sidebar's copy/filter logic has a single target, and
 *   • an `IOC.URL` automatically gets a sibling `IOC.DOMAIN` if tldts is
 *     loaded and the URL resolves to a real registrable domain.
 *
 * @param {object}   findings         `analyzeForSecurity()` findings object
 * @param {object}   opts
 * @param {string}   opts.type        one of `IOC.*`
 * @param {string}   opts.value       the IOC value (stored in `.url` for sidebar parity)
 * @param {string}  [opts.severity]   'info' | 'medium' | 'high' | 'critical'
 * @param {string}  [opts.highlightText] click-to-focus needle (defaults to `value`)
 * @param {string}  [opts.note]       short human context
 * @param {string}  [opts.bucket]     'externalRefs' | 'interestingStrings' (default 'interestingStrings')
 */
function pushIOC(findings, opts) {
  if (!findings || !opts || !opts.type || !opts.value) return;
  const bucket = opts.bucket || 'interestingStrings';
  if (!Array.isArray(findings[bucket])) findings[bucket] = [];
  const sev = opts.severity || IOC_CANONICAL_SEVERITY[opts.type] || 'info';
  const entry = {
    type: opts.type,
    url: String(opts.value),
    severity: sev,
  };
  if (opts.highlightText) entry._highlightText = String(opts.highlightText);
  if (opts.note) entry.note = String(opts.note);
  findings[bucket].push(entry);

  // Auto-emit host-derived sibling IOCs when a URL lands and tldts is loaded.
  // Three siblings can fire off a single URL push:
  //   1. IOC.DOMAIN — registrable domain for non-IP hosts (always).
  //   2. IOC.IP     — the raw host when the URL embeds an IP literal
  //                   (e.g. http://192.0.2.1/a). Previously dropped on the
  //                   floor; now surfaced so sidebar pivoting works.
  //   3. IOC.PATTERN — punycode/IDN homoglyph detection (medium sev) and
  //                   abuse-suffix detection (DDNS / tunnelling / free-host
  //                   surfaces used as C2 backbones; info sev). Both are
  //                   emitted only once per unique host so a renderer that
  //                   pushes 30 URLs for one C2 host doesn't flood the IOC
  //                   table with 30 duplicate punycode warnings.
  if (opts.type === IOC.URL && !opts._noDomainSibling) {
    const h = _parseUrlHost(opts.value);
    if (h) {
      if (h.domain && !h.isIp) {
        const existing = findings[bucket].some(
          e => e && e.type === IOC.DOMAIN && e.url === h.domain
        );
        if (!existing) {
          findings[bucket].push({
            type: IOC.DOMAIN,
            url: h.domain,
            severity: IOC_CANONICAL_SEVERITY[IOC.DOMAIN],
            note: 'derived from URL',
          });
        }
      }
      if (h.isIp && h.hostname) {
        const existing = findings[bucket].some(
          e => e && e.type === IOC.IP && e.url === h.hostname
        );
        if (!existing) {
          findings[bucket].push({
            type: IOC.IP,
            url: h.hostname,
            severity: 'medium',
            note: 'URL uses raw IP literal (no domain validation)',
          });
        }
      }
      if (h.isPunycode) {
        const patternNote = `Punycode/IDN host: ${h.hostname} — possible homoglyph`;
        const existing = findings[bucket].some(
          e => e && e.type === IOC.PATTERN && e.url === patternNote
        );
        if (!existing) {
          findings[bucket].push({
            type: IOC.PATTERN,
            url: patternNote,
            severity: 'medium',
            _highlightText: h.hostname,
          });
        }
      }
      if (h.isAbuseSuffix && h.domain) {
        const note = `Disposable/abuse-prone host: ${h.hostname} (suffix: ${h.publicSuffix})`;
        const existing = findings[bucket].some(
          e => e && e.type === IOC.PATTERN && e.url === note
        );
        if (!existing) {
          findings[bucket].push({
            type: IOC.PATTERN,
            url: note,
            severity: 'info',
            _highlightText: h.hostname,
          });
        }
      }
    }
  }
}

/**
 * Mirror selected `findings.metadata` entries into `findings.interestingStrings`
 * so they appear in the sidebar's IOC table (which is fed *only* from
 * externalRefs + interestingStrings — metadata alone never reaches it).
 *
 * Call this at the END of `analyzeForSecurity()` after populating
 * `findings.metadata`, passing a map of `{ metadataKey: IOC.TYPE }`. Only
 * classic-pivot fields (hashes, paths, GUIDs, MAC, emails, fingerprints)
 * should be mirrored — attribution fluff like CompanyName / FileDescription
 * / ProductName should stay metadata-only.
 *
 * @param {object} findings
 * @param {object} fieldMap  `{ 'Imphash': IOC.HASH, 'PDB Path': IOC.FILE_PATH, ... }`
 * @param {object} [opts]    `{ severity: 'info', noteFn: (key,val) => string }`
 */
function mirrorMetadataIOCs(findings, fieldMap, opts) {
  if (!findings || !findings.metadata || !fieldMap) return;
  opts = opts || {};
  for (const [key, iocType] of Object.entries(fieldMap)) {
    const val = findings.metadata[key];
    if (val == null || val === '') continue;
    // Array-valued metadata (e.g. dylibs[]) → one IOC per element
    const values = Array.isArray(val) ? val : [val];
    for (const v of values) {
      if (v == null || v === '') continue;
      const sv = String(v).trim();
      if (!sv) continue;
      pushIOC(findings, {
        type: iocType,
        value: sv,
        severity: opts.severity || IOC_CANONICAL_SEVERITY[iocType] || 'info',
        highlightText: sv,
        note: opts.noteFn ? opts.noteFn(key, sv) : key,
      });
    }
  }
}



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

// ── Generic ASCII + UTF-16LE string scanner ──────────────────────────────────
/**
 * Extract printable ASCII and UTF-16LE strings from a byte range.
 *
 * Shared helper used by binary renderers (ELF, Mach-O, …) that need to
 * surface embedded strings for IOC extraction and YARA scanning. Two passes:
 *   1. UTF-16LE   — pairs of `[printable ASCII byte][0x00]`, minimum
 *                   `utf16Min` code units.
 *   2. ASCII 1-byte — runs of `0x20..0x7E`, minimum `asciiMin` bytes.
 *
 * Strings are deduplicated across both passes (ASCII wins; UTF-16 is only
 * emitted if not already seen in the ASCII output) so a single latin-script
 * string stored as UTF-16 doesn't show up twice. The scan stops after `cap`
 * total strings to bound memory.
 *
 * @param {Uint8Array} bytes
 * @param {{ start?: number, end?: number, asciiMin?: number, utf16Min?: number, cap?: number }} [opts]
 * @returns {{ ascii: string[], utf16: string[] }}
 */
function extractAsciiAndUtf16leStrings(bytes, opts) {
  const o = opts || {};
  const start = o.start | 0;
  const end = Math.min(o.end == null ? bytes.length : o.end, bytes.length);
  const asciiMin = o.asciiMin || 4;
  const utf16Min = o.utf16Min || 4;
  const cap = o.cap || 10000;

  const ascii = [];
  const utf16 = [];
  const seen = new Set();

  // Pass 1: ASCII runs
  let cur = '';
  for (let i = start; i < end; i++) {
    const b = bytes[i];
    if (b >= 0x20 && b < 0x7F) {
      cur += String.fromCharCode(b);
    } else {
      if (cur.length >= asciiMin && !seen.has(cur)) {
        seen.add(cur);
        ascii.push(cur);
        if (ascii.length + utf16.length >= cap) return { ascii, utf16 };
      }
      cur = '';
    }
  }
  if (cur.length >= asciiMin && !seen.has(cur)) {
    seen.add(cur);
    ascii.push(cur);
  }

  // Pass 2: UTF-16LE runs
  cur = '';
  for (let i = start; i + 1 < end; i += 2) {
    const lo = bytes[i], hi = bytes[i + 1];
    if (hi === 0 && lo >= 0x20 && lo < 0x7F) {
      cur += String.fromCharCode(lo);
    } else {
      if (cur.length >= utf16Min && !seen.has(cur)) {
        seen.add(cur);
        utf16.push(cur);
        if (ascii.length + utf16.length >= cap) return { ascii, utf16 };
      }
      cur = '';
    }
  }
  if (cur.length >= utf16Min && !seen.has(cur)) {
    seen.add(cur);
    utf16.push(cur);
  }

  return { ascii, utf16 };
}

