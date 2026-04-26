'use strict';
// ════════════════════════════════════════════════════════════════════════════
// constants.js — XML namespace constants, unit converters, DOM/XML helpers
// Loaded first; used by every other module.
// ════════════════════════════════════════════════════════════════════════════

// ── Parser safety limits ──────────────────────────────────────────────────────
const PARSER_LIMITS = Object.freeze({
  MAX_DEPTH:            32,                  // Max recursion / nesting depth
  MAX_UNCOMPRESSED:     50 * 1024 * 1024,    // 50 MB — max decompressed output
  MAX_RATIO:            100,                 // Per-entry compression ratio abort
  MAX_ENTRIES:          10_000,              // Max archive entries before truncation
  TIMEOUT_MS:           60_000,              // Buffer-read cap (`file.arrayBuffer()`)
                                             // — also the default for any
                                             // `ParserWatchdog.run(fn)` call site
                                             // that doesn't pass an explicit
                                             // `{ timeout }` budget.
  RENDERER_TIMEOUT_MS:  30_000,              // 30 s — per-renderer dispatch cap
                                             //. When a single renderer
                                             // hangs on a hostile file, the watchdog
                                             // aborts and `_loadFile` falls back to
                                             // `PlainTextRenderer` with a sidebar
                                             // `IOC.INFO` note. Keep this strictly
                                             // < `TIMEOUT_MS` so the renderer-level
                                             // bound triggers first; the buffer-read
                                             // cap is a different scope (one read
                                             // per file vs. arbitrary parser work).
  SYNC_YARA_FALLBACK_MAX_BYTES:  32 * 1024 * 1024,
                                             // 32 MiB — synchronous main-thread
                                             // auto-YARA size gate. Auto-YARA
                                             // runs in a Web Worker
                                             // (`src/workers/yara.worker.js`) by
                                             // default; the worker's preemptive
                                             // `terminate()` makes scan time a
                                             // non-issue, so this cap is *only*
                                             // enforced on the synchronous main-
                                             // thread fallback path used when
                                             // `Worker(blob:)` is denied (e.g.
                                             // Firefox `file://` default). Above
                                             // the cap on that path,
                                             // `_autoYaraScanSync()` skips scanning
                                             // and emits a sidebar IOC.INFO note
                                             // pointing the user at the manual
                                             // YARA tab (which is unrestricted on
                                             // both worker and fallback paths).
  WORKER_TIMEOUT_MS:    300_000,             // 5 min — preemptive deadline on
                                             // any `WorkerManager.run*` job
                                             //. On expiry the active
                                             // worker is `terminate()`-d (real
                                             // preemption, unlike the post-hoc
                                             // main-thread `ParserWatchdog`)
                                             // and the promise rejects with a
                                             // watchdog-shaped error
                                             // (`_watchdogTimeout = true`,
                                             // `_watchdogName`,
                                             // `_watchdogTimeoutMs`). The
                                             // budget is intentionally larger
                                             // than `RENDERER_TIMEOUT_MS`
                                             // (30 s) because workerised work
                                             // is off-main-thread — the UI
                                             // stays responsive, so legitimate
                                             // large-file YARA / encoded /
                                             // timeline scans should not be
                                             // false-positively killed at
                                             // 30 s. Callers fall back to the
                                             // synchronous in-tree path on
                                             // any rejection (workers-
                                             // unavailable, worker error, or
                                             // watchdog timeout) — same
                                             // contract as before C5.

  // ── Per-dispatch file-size caps ──────────────────────────
  // Maximum file size the structured renderer for each dispatch id will
  // accept. Above the cap, `RenderRoute.run` (`src/render-route.js`)
  // skips the structured handler, falls back to `PlainTextRenderer`
  // (the same fallback used by the watchdog-timeout path), and pushes a
  // single visible `IOC.INFO` row explaining the skip. The buffer is
  // already in memory at the time of the check — F1 guards parser CPU
  // cost, not memory pressure (memory pressure is covered separately by
  // `RENDER_LIMITS.HUGE_FILE_WARN`). Caps are deliberately conservative
  // and graceful: the analyst can still inspect the raw bytes via the
  // plaintext view, and the manual YARA tab still scans the unmodified
  // buffer regardless of this cap. Tune via empirical feedback rather
  // than ahead-of-time speculation. Keys are the dispatch ids used by
  // `App.prototype._rendererDispatch` (see `src/app/app-load.js`).
  // `_DEFAULT` is the fallback when a dispatch id has no explicit row.
  // Unit: bytes.
  MAX_FILE_BYTES_BY_DISPATCH: Object.freeze({
    // Heavy structured-binary parsers (full-file walks, symbol tables,
    // overlay scans).
    pe:        256 * 1024 * 1024,
    elf:       256 * 1024 * 1024,
    macho:     256 * 1024 * 1024,
    // Forensic / paginated parsers.
    pdf:       256 * 1024 * 1024,
    evtx:      512 * 1024 * 1024,
    sqlite:    512 * 1024 * 1024,
    onenote:   256 * 1024 * 1024,
    // Archives — entry walking is cheap per entry; the real cost is
    // the number of entries (already capped by `MAX_ENTRIES`) and
    // recursive sniffing. Allow large container files.
    zip:       512 * 1024 * 1024,
    cab:       512 * 1024 * 1024,
    rar:       512 * 1024 * 1024,
    sevenz:    512 * 1024 * 1024,
    tar:       512 * 1024 * 1024,
    iso:     1_024 * 1024 * 1024,
    dmg:     1_024 * 1024 * 1024,
    pkg:       512 * 1024 * 1024,
    msi:       512 * 1024 * 1024,
    jar:       256 * 1024 * 1024,
    msix:      512 * 1024 * 1024,
    browserext:256 * 1024 * 1024,
    npm:       256 * 1024 * 1024,
    // Office (OOXML + ODF + legacy CFB).
    docx:      128 * 1024 * 1024,
    xlsx:      256 * 1024 * 1024,
    pptx:      256 * 1024 * 1024,
    odt:       128 * 1024 * 1024,
    odp:       256 * 1024 * 1024,
    ods:       256 * 1024 * 1024,
    doc:       128 * 1024 * 1024,
    ppt:       256 * 1024 * 1024,
    xls:       256 * 1024 * 1024,
    // Email containers.
    msg:       128 * 1024 * 1024,
    eml:       128 * 1024 * 1024,
    // Tabular / textual.
    csv:       512 * 1024 * 1024,
    json:      256 * 1024 * 1024,
    // Markup / lightweight viewers.
    html:       64 * 1024 * 1024,
    svg:        64 * 1024 * 1024,
    hta:        64 * 1024 * 1024,
    rtf:        64 * 1024 * 1024,
    // Config / scripts.
    url:         8 * 1024 * 1024,
    reg:        64 * 1024 * 1024,
    inf:        16 * 1024 * 1024,
    iqyslk:     16 * 1024 * 1024,
    wsf:        16 * 1024 * 1024,
    clickonce:  16 * 1024 * 1024,
    plist:      64 * 1024 * 1024,
    scpt:       64 * 1024 * 1024,
    lnk:        16 * 1024 * 1024,
    // Crypto / signatures.
    pgp:        64 * 1024 * 1024,
    x509:       16 * 1024 * 1024,
    // Media.
    image:     128 * 1024 * 1024,
    // Plaintext is the fallback target — never gated.
    plaintext:        Number.POSITIVE_INFINITY,
    // Catch-all for any future dispatch id without an explicit row.
    _DEFAULT:  128 * 1024 * 1024,
  }),
});


// ── Render / data-truncation limits ───────────────────────────────────────────
// PARSER_LIMITS above is the *safety* envelope (abort-if-breached); the caps
// below govern how much **parsed data** the UI actually renders. They are
// deliberately separate so they can be raised without weakening the parser
// safety story. Renderers that cap their output should reference one of these
// constants rather than inventing their own magic number.
const RENDER_LIMITS = Object.freeze({
  MAX_TEXT_LINES:       100_000,   // Primary text viewers (plaintext/html/hta/inf/reg/rtf)
  MAX_TEXT_LINES_SMALL:  10_000,   // Config/manifest viewers (browserext/clickonce/url/iqy/msix/npm/wsf/plist-fallback/pe-strings)
  MAX_CSV_ROWS:       1_000_000,   // CSV/TSV grid
  MAX_TIMELINE_ROWS:  1_000_000,   // Timeline dashboard (CSV/TSV/EVTX/browser history)
  MAX_EVTX_EVENTS:    1_000_000,   // EVTX parser + viewer
  LARGE_FILE_THRESHOLD: 200 * 1024 * 1024,  // 200 MB — use chunked decode unconditionally
  HUGE_FILE_WARN:       500 * 1024 * 1024,  // 500 MB — show warning toast before loading
  DECODE_CHUNK_BYTES:   16 * 1024 * 1024,   // 16 MB — TextDecoder chunk size for large files
});

// ── EVTX column schema ────────────────────────────────────────────────────────
// Canonical column names for the EVTX timeline view.  Used by
// evtx-renderer.js (parser output), app-timeline.js (column lookups),
// and grid-viewer.js (column-specific styling).
// Changing a name here automatically propagates everywhere.
const EVTX_COLUMNS = Object.freeze({
  TIMESTAMP:  'Timestamp',
  EVENT_ID:   'Event ID',
  LEVEL:      'Level',
  PROVIDER:   'Provider',
  CHANNEL:    'Channel',
  COMPUTER:   'Computer',
  EVENT_DATA: 'Event Data',
});
const EVTX_COLUMN_ORDER = Object.freeze([
  EVTX_COLUMNS.TIMESTAMP,
  EVTX_COLUMNS.EVENT_ID,
  EVTX_COLUMNS.LEVEL,
  EVTX_COLUMNS.PROVIDER,
  EVTX_COLUMNS.CHANNEL,
  EVTX_COLUMNS.COMPUTER,
  EVTX_COLUMNS.EVENT_DATA,
]);

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
// IPv4 dotted-decimal. Each octet must be either a single `0`, a 1–3 digit
// number that does NOT start with `0` (so `01`, `007`, `09` are rejected),
// or one of the explicit 2xx forms. This deliberately rejects leading-zero
// forms like `01.9.0.8` / `001.009.000.008` which never appear in
// RFC-strict IPv4 text but DO appear in zero-padded build numbers that
// pattern-matched as IPs in earlier revisions.
const _IPV4_RE  = /\b(?:(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.){3}(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\b/g;

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
  // Drop bogon ranges — these never appear on the public internet and
  // are pure pivot noise if they ever match. Explicit ranges covered:
  //   0.0.0.0, 255.255.255.255, 127.0.0.1         — classic null / broadcast / loopback
  //   10.0.0.0/8, 127.0.0.0/8                     — RFC1918 + loopback
  //   169.254.0.0/16                              — link-local (APIPA)
  //   172.16.0.0/12, 192.168.0.0/16               — RFC1918
  //   224.0.0.0/4                                 — multicast + class-E reserved + broadcast
  //   100.64.0.0/10                               — CGNAT / shared space (RFC 6598)
  //   192.0.0.0/24                                — IETF protocol assignments (RFC 6890)
  //   192.0.2.0/24                                — TEST-NET-1 (RFC 5737)
  //   198.18.0.0/15                               — benchmarking (RFC 2544)
  //   198.51.100.0/24                             — TEST-NET-2 (RFC 5737)
  //   203.0.113.0/24                              — TEST-NET-3 (RFC 5737)
  const filtered = raw.filter(ip => {
    if (ip === '0.0.0.0' || ip === '255.255.255.255' || ip === '127.0.0.1') return false;
    const o = ip.split('.').map(Number);
    if (o[0] === 10) return false;
    if (o[0] === 127) return false;
    if (o[0] === 169 && o[1] === 254) return false;
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false;
    if (o[0] === 192 && o[1] === 168) return false;
    if (o[0] >= 224) return false;
    // CGNAT — 100.64.0.0/10 covers 100.64.0.0 through 100.127.255.255
    if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return false;
    // IETF protocol assignments + TEST-NET-1
    if (o[0] === 192 && o[1] === 0 && (o[2] === 0 || o[2] === 2)) return false;
    // Benchmarking — 198.18.0.0/15 covers 198.18.x.x and 198.19.x.x
    if (o[0] === 198 && (o[1] === 18 || o[1] === 19)) return false;
    // TEST-NET-2
    if (o[0] === 198 && o[1] === 51 && o[2] === 100) return false;
    // TEST-NET-3
    if (o[0] === 203 && o[1] === 0 && o[2] === 113) return false;
    return true;
  });
  return _dedupCap(filtered, cap);
}

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

// ── Risk-tier escalation ──────────────────────────────────────────────────────
// Renderers must initialise `findings.risk = 'low'` and only ever escalate
// from evidence pushed onto `findings.externalRefs` / `interestingStrings`.
// Pre-stamping a higher tier produces false-positive risk colouring on benign
// samples — see CONTRIBUTING.md → Risk Tier Calibration. The build script
// rejects bare `findings.risk = '<tier>'` writes outside this file.
const _RISK_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });

/**
 * Rank-monotonically lift `findings.risk` to `tier`. Never lowers an existing
 * higher tier; safe to call repeatedly. The canonical helper for risk
 * escalation across every renderer.
 *
 * @param {object} findings  the `analyzeForSecurity()` findings object
 * @param {string} tier      'info' | 'low' | 'medium' | 'high' | 'critical'
 */
function escalateRisk(findings, tier) {
  if (!findings || !tier) return;
  const cur  = _RISK_RANK[findings.risk] || 0;
  const next = _RISK_RANK[tier] || 0;
  if (next > cur) findings.risk = tier;
}

// ── Line-ending normaliser ────────────────────────────────────────────────────
// Every renderer that builds a `container._rawText` string for the sidebar's
// click-to-focus engine MUST route the text through `lfNormalize()` first.
// CRLF / bare-CR sequences leaking into `_rawText` desynchronise every
// click-to-focus offset after the first CR (the highlighter searches the
// post-render DOM, which the browser has collapsed CRs in, so a CRLF in
// `_rawText` shifts every subsequent match by one character per CR). The
// build script enforces this by rejecting `*._rawText = <expr>` writes whose
// RHS is not a `lfNormalize(...)` call, an empty/literal string sentinel, an
// `'\n'`-join of binary-extracted strings, or a passthrough from another
// already-normalised `_rawText`. See CONTRIBUTING.md → Tripwires and
// Renderer Contract rule #3.
//
// The single-pass `\r\n?` regex covers both classic CRLF and bare-CR
// (Mac-classic) line endings — equivalent to the older two-pass
// `replace(/\r\n/g, '\n').replace(/\r/g, '\n')` chain that used to be
// copy-pasted across renderers, but cheaper.
//
// @param {string} s
// @returns {string} `s` with every `\r\n` and bare `\r` replaced by `\n`;
//                   non-string inputs collapse to `''`.
function lfNormalize(s) {
  return typeof s === 'string' ? s.replace(/\r\n?/g, '\n') : '';
}

// ── Renderer cancellation poll ────────────────────────────────────────────────
// Long-running renderer loops (PE / ELF / Mach-O section walks, EVTX chunk
// decode, encoded-content candidate scan, …) call `throwIfAborted()` between
// chunks / rows / candidates so a watchdog timeout — or any future
// caller-initiated abort — can short-circuit the loop instead of burning CPU
// to completion on a buffer whose result will be orphaned anyway.
//
// `RenderRoute.run` parks the active `AbortSignal` on
// `ParserWatchdog._activeSignal` for the duration of the per-renderer
// dispatch, then restores the previous value in `.finally()`. The watchdog
// `abort()`s that signal the moment its deadline fires (see
// `parser-watchdog.js` — abort happens *before* the timeout reject lands so a
// renderer racing the timer always sees `signal.aborted === true`).
//
// This helper is contractually a no-op when:
//   • `ParserWatchdog` isn't loaded yet (early bootstrap);
//   • no signal is active (renderer invoked outside `RenderRoute.run`, e.g.
//     from the manual YARA tab or a sidebar drill-down);
//   • the signal exists but hasn't been aborted.
//
// On abort it throws a `DOMException('aborted', 'AbortError')` (with a
// plain-`Error` fallback). `RenderRoute.run`'s catch already routes any
// thrown error through `_fallbackToPlaintext`, so an `AbortError` from
// inside a renderer paints the plaintext view + an `IOC.INFO` row exactly
// like the existing watchdog-timeout-from-outside-the-renderer path does.
//
// Renderers SHOULD poll once per chunk / row / section — never per byte.
// The cost of one property read + one branch is negligible at the cadence
// of a section header or BinXml template; sprinkled inside an inner byte
// loop it would dwarf the actual parsing.
function throwIfAborted() {
  const sig = (typeof ParserWatchdog !== 'undefined' && ParserWatchdog)
    ? ParserWatchdog._activeSignal
    : null;
  if (sig && sig.aborted) {
    const err = (typeof DOMException !== 'undefined')
      ? new DOMException('Renderer aborted', 'AbortError')
      : Object.assign(new Error('Renderer aborted'), { name: 'AbortError' });
    throw err;
  }
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

