'use strict';
// ════════════════════════════════════════════════════════════════════════════
// encoded-worker-shim.js — Worker-bundle prelude for the EncodedContentDetector
//
// First file `scripts/build.py` concatenates into the
// `__ENCODED_WORKER_BUNDLE_SRC` template-literal that powers the encoded-
// content scan worker. It declares the small subset of constants
// and IOC-side helpers that `src/encoded-content-detector.js` and
// `src/decompressor.js` reach for at module load and must therefore be
// defined **before** them.
//
// Bundle order (set in `scripts/build.py`):
//   1. src/workers/encoded-worker-shim.js   ← this file
//   2. vendor/pako.min.js                   ← Decompressor's sync fallback
//   3. vendor/jszip.min.js                  ← embedded-ZIP validator
//   4. src/decompressor.js                  ← gzip/zlib/deflate inflate
//   5. src/encoded-content-detector.js      ← scanner (the actual workload)
//   6. src/workers/encoded.worker.js        ← onmessage dispatcher
//
// All six layers are concatenated, the result is wrapped in a JS template
// literal, and `src/worker-manager.js::runEncoded()` blob-URL spawns it.
// `src/workers/encoded.worker.js` carries the full design rationale
// (postMessage protocol, fallback contract, CSP note, etc.) — keep this
// shim deliberately tight.
//
// What lives here vs `src/constants.js`
// -------------------------------------
// Only the values the detector actually reads at runtime. Inlining the
// whole `src/constants.js` would pull in `escalateRisk`, `pushIOC`,
// `mirrorMetadataIOCs`, the full ICON.* table, NICELIST helpers, and other
// analyzer-side concerns the worker doesn't need. If `constants.js` ever
// changes one of these values, update this block too — the build will not
// catch the drift.
// ════════════════════════════════════════════════════════════════════════════

// ── IOC type constants (mirrors src/constants.js, IOC table) ────────────────
//
// `_extractIOCsFromDecoded()` shapes its output rows with `type: IOC.URL`,
// `IOC.EMAIL`, `IOC.IP`, `IOC.FILE_PATH`, `IOC.UNC_PATH`. The host's
// `app-load.js` post-scan loop merges these rows into
// `findings.interestingStrings` verbatim, so the values must match the
// canonical strings defined in `src/constants.js`. Keep this object in sync
// with the real `IOC` table — there's no build-time check for drift between
// the worker shim and the main constants table.
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

// ── PARSER_LIMITS subset (Decompressor MAX_OUTPUT) ──────────────────────────
//
// `src/decompressor.js` reads `PARSER_LIMITS.MAX_UNCOMPRESSED` at module
// load to set its zip-bomb expansion cap. Match the main-thread value
// exactly — see `src/constants.js`.
const PARSER_LIMITS = Object.freeze({
  MAX_UNCOMPRESSED: 50 * 1024 * 1024,  // 50 MB
});

// ── _trimPathExtGarbage (mirrors src/constants.js) ──────────────────────────
//
// `_extractIOCsFromDecoded()` calls this on every Windows-style path it
// finds in the decoded payload to trim string-extraction garbage that
// fused adjacent printable bytes onto the end of a path (e.g.
// `"file.pdbtEXtSoftwareAdobe…"` → `"file.pdb"`). Source-of-truth lives
// in `src/constants.js`; keep this copy in sync.
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

// ── throwIfAborted no-op (mirrors src/workers/timeline-worker-shim.js) ──────
//
// `throwIfAborted` is the render-epoch / watchdog poll site defined in
// `src/constants.js` for the host thread. Decoder helpers
// (`src/decoders/encoding-finders.js`, `src/decoders/cmd-obfuscation.js`)
// call it between candidate scans so the host can preempt long parses on
// supersession / watchdog timeout. Workers never participate in the host's
// render-epoch fence — they're terminated wholesale by `worker.terminate()`
// — so this is a no-op stub. Without it the finder helpers would throw
// `ReferenceError: throwIfAborted is not defined`, and the
// secondary-scan `catch` would surface the failure as the misleading
// "finder-budget — throwIfAborted is not defined" Info row.
function throwIfAborted() { /* no-op in worker */ }

