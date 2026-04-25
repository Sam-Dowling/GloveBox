'use strict';
// ════════════════════════════════════════════════════════════════════════════
// strings-worker-shim.js — Worker-bundle prelude for the binary-string scanner
//
// First file `scripts/build.py` concatenates into the
// `__STRINGS_WORKER_BUNDLE_SRC` template-literal that powers the binary-
// string extractor worker (PLAN C4). It declares the small subset of
// helpers `src/workers/strings.worker.js` reaches for at module load and
// must therefore be defined **before** it.
//
// Bundle order (set in `scripts/build.py`):
//   1. src/workers/strings-worker-shim.js   ← this file
//   2. src/workers/strings.worker.js        ← `self.onmessage` dispatcher
//
// Both layers are concatenated, the result is wrapped in a JS template
// literal, and `src/worker-manager.js::runStrings()` blob-URL spawns it.
// `src/workers/strings.worker.js` carries the full design rationale
// (postMessage protocol, fallback contract, CSP note, etc.) — keep this
// shim deliberately tight.
//
// What lives here vs `src/constants.js`
// -------------------------------------
// Only the function the worker actually invokes at runtime:
// `extractAsciiAndUtf16leStrings`. Pulling in the rest of `constants.js`
// would drag in `escalateRisk`, `pushIOC`, `mirrorMetadataIOCs`, the IOC
// table, NICELIST helpers, and other analyser-side concerns the worker
// doesn't need. If `constants.js` ever changes the extraction routine,
// update this copy too — the build will not catch the drift.
// ════════════════════════════════════════════════════════════════════════════

// ── extractAsciiAndUtf16leStrings (mirrors src/constants.js) ────────────────
//
// Two-pass printable-string extractor used by PE / ELF / Mach-O / DMG to
// surface embedded strings for IOC extraction and YARA scanning. Returns
// `{ ascii, utf16 }` arrays, deduplicated across both passes (ASCII wins;
// UTF-16 is only emitted if not already seen as ASCII). Source-of-truth
// lives in `src/constants.js`; keep this copy byte-equivalent so the
// worker and main-thread fallback behave identically.
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
