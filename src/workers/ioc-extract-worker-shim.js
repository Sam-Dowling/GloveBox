'use strict';
// ════════════════════════════════════════════════════════════════════════════
// ioc-extract-worker-shim.js — Worker-bundle prelude for the IOC extract worker
//
// First file `scripts/build.py` concatenates into the
// `__IOC_EXTRACT_WORKER_BUNDLE_SRC` template-literal that powers the
// `iocExtract` channel of `WorkerManager`. It declares the small subset of
// constants and host-side helpers that `src/ioc-extract.js` reaches for at
// module load and must therefore be defined **before** it.
//
// Bundle order (set in `scripts/build.py`):
//   1. src/workers/ioc-extract-worker-shim.js   ← this file
//   2. src/ioc-extract.js                       ← the regex-only IOC core
//   3. src/workers/ioc-extract.worker.js        ← onmessage dispatcher
//
// What lives here vs `src/constants.js`
// -------------------------------------
// Only the values `extractInterestingStringsCore` actually reads at runtime:
//   • IOC.* type constants (canonical strings — must match src/constants.js)
//   • `looksLikeIpVersionString`  — version-string suppression for IPv4
//   • `stripDerTail`              — DER tail-junk stripper for URLs
//   • `_trimPathExtGarbage`       — Windows-path tail-junk stripper
// Inlining the whole `src/constants.js` would pull in `escalateRisk`,
// `pushIOC`, `mirrorMetadataIOCs`, the full ICON.* table, NICELIST helpers,
// and other analyzer-side concerns the worker doesn't need. If
// `src/constants.js` ever changes one of these values, update this block too
// — the build's `scripts/check_shim_parity.py` gate diffs them.
// ════════════════════════════════════════════════════════════════════════════

// ── IOC type constants (mirrors src/constants.js, IOC table) ────────────────
//
// `extractInterestingStringsCore` shapes its output rows with `type: IOC.URL`,
// `IOC.EMAIL`, `IOC.IP`, `IOC.FILE_PATH`, `IOC.UNC_PATH`, `IOC.REGISTRY_KEY`.
// The host's `app-load.js` post-scan loop merges these rows into
// `findings.interestingStrings` verbatim, so the values must match the
// canonical strings defined in `src/constants.js`. Keep this object in sync
// with the real `IOC` table — `scripts/check_shim_parity.py` diffs them.
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
  CRYPTO_ADDRESS: 'Crypto Address',
  SECRET: 'Secret',
});

// ── looksLikeIpVersionString (mirrors src/constants.js) ─────────────────────
//
// Suppresses `v1.2.3.4`, `build 2.0.0.1`, etc. — anything where fewer than 4
// digits appear across all four octets. Body byte-equivalent with
// `src/constants.js`.
function looksLikeIpVersionString(ipPart) {
  if (!ipPart) return false;
  return String(ipPart).replace(/\D/g, '').length < 4;
}

// ── stripDerTail (mirrors src/constants.js) ─────────────────────────────────
//
// Strips DER tag/length bytes that fuse onto URLs scraped from binary string
// dumps and ASN.1 IA5String fields. Body byte-equivalent with
// `src/constants.js`.
const DER_TAIL_RX_TERMINATED = /([^0-9])0[\d]{0,2}[^a-zA-Z0-9]{1,3}$/;
const DER_TAIL_RX_TLD        = /(\.[A-Za-z]{2,})[0-9]{1,3}$/;
function stripDerTail(s) {
  if (typeof s !== 'string') return s;
  s = s.replace(DER_TAIL_RX_TERMINATED, '$1');
  const protoIdx = s.indexOf('://');
  const afterProto = protoIdx >= 0 ? s.slice(protoIdx + 3) : s;
  if (!/[\/?#]/.test(afterProto)) {
    s = s.replace(DER_TAIL_RX_TLD, '$1');
  }
  return s;
}

// ── _trimPathExtGarbage (mirrors src/constants.js + encoded-worker-shim.js) ─
//
// `extractInterestingStringsCore` calls this on every Windows-style path it
// finds in the scan surface to trim string-extraction garbage that fused
// adjacent printable bytes onto the end of a path (e.g.
// `"file.pdbtEXtSoftwareAdobe…"` → `"file.pdb"`). Body byte-equivalent with
// `src/constants.js`.
const _KNOWN_EXT_RE = /^\.(exe|dll|sys|drv|ocx|cpl|scr|com|pdb|lib|obj|exp|pif|lnk|url|bat|cmd|ps1|py|vbs|vbe|js|jse|wsh|wsf|wsc|hta|sct|inf|reg|msi|msp|mst|txt|log|ini|cfg|conf|config|xml|html?|json|ya?ml|toml|csv|tsv|sql|sqlite|db|mdb|accdb|doc[xm]?|xls[xmb]?|ppt[xm]?|pdf|rtf|odt|ods|odp|one|eml|msg|pst|evtx?|zip|rar|7z|gz|tar|bz2|xz|cab|iso|img|vhdx?|vmdk|dmp|bak|tmp|old|dat|bin|pyc|pyo|pyw|rb|java|class|jar|war|apk|cpp|hpp|cs|go|rs|php|aspx?|jsp|sh|so|dylib|manifest|pem|crt|cer|der|key|pfx|ico|png|jpe?g|gif|bmp|svg|webp|tiff?|mp[34]|avi|mov|wmv|wav|ogg|woff2?|ttf|otf|eot)/i;
function _trimPathExtGarbage(path) {
  const ls = path.lastIndexOf('\\');
  if (ls < 0) return path;
  const fn = path.slice(ls + 1);
  const dot = fn.lastIndexOf('.');
  if (dot < 0) return path;
  const ext = fn.slice(dot + 1);
  if (ext.length <= 10) return path;
  const tail = fn.slice(dot);
  const extM = tail.match(_KNOWN_EXT_RE);
  return extM ? path.slice(0, ls + 1 + dot + extM[0].length) : path;
}

// ── safeMatchAll (mirrors src/constants.js) ─────────────────────────────────
//
// Bounded regex-match iterator used by `extractInterestingStringsCore` so a
// single pathological regex on a long single-line input cannot monopolise
// the worker. Body byte-equivalent with `src/constants.js`; the parity gate
// (`scripts/check_shim_parity.py`) diffs them.
function safeMatchAll(re, str, budgetMs, maxMatches) {
  const matches = [];
  if (!re || typeof str !== 'string') return { matches, truncated: false, timedOut: false };
  // Force `g` flag so `exec` advances; otherwise we would infinite loop.
  let rx = re;
  if (!rx.global) {
    /* safeRegex: builtin */
    try { rx = new RegExp(rx.source, rx.flags + 'g'); }
    catch (_e) { return { matches, truncated: false, timedOut: false }; }
  }
  rx.lastIndex = 0;
  const cap = maxMatches || 10000;
  const budget = budgetMs || 100;
  const start = Date.now();
  let truncated = false, timedOut = false;
  let i = 0;
  let m;
  try {
    while ((m = rx.exec(str)) !== null) {
      matches.push(m);
      // Always advance on zero-width match
      if (m.index === rx.lastIndex) rx.lastIndex++;
      if (matches.length >= cap) { truncated = true; break; }
      if ((++i & 0xFF) === 0 && Date.now() - start > budget) {
        timedOut = true;
        break;
      }
    }
  } catch (_e) { /* swallow */ }
  return { matches, truncated, timedOut };
}
