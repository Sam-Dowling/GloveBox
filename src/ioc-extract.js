'use strict';
// ════════════════════════════════════════════════════════════════════════════
// ioc-extract.js — Pure regex-based IOC extraction core.
//
// Extracted from `App.prototype._extractInterestingStrings` (app-load.js) so
// the same logic can run inside `src/workers/ioc-extract.worker.js` for
// large non-timeline files. The host keeps a thin shim
// (`_extractInterestingStrings`) that calls into this core; the worker bundle
// concatenates this file directly and the dispatcher invokes the core on the
// posted text.
//
// Inputs / outputs
// ----------------
//   extractInterestingStringsCore(text, opts) → {
//     findings:        Array<{type, url, severity, note?, _sourceOffset?,
//                              _sourceLength?, _highlightText?}>,
//     droppedByType:   Map<type,count>,
//     totalSeenByType: Map<type,count>
//   }
//
// `opts`:
//   • `existingValues: string[]`  pre-seeded `seen` set so the host can
//                                 dedupe against rows already pushed by the
//                                 renderer (e.g. `findings.externalRefs`).
//                                 The worker-side caller passes `[]`.
//   • `vbaModuleSources: string[]` optional VBA module sources to scan with
//                                 elevated severity. Empty array on the
//                                 worker path unless the host pre-flattens
//                                 them and ships them across.
//
// Worker-marshalable surface
// --------------------------
// This file references only globals that exist in BOTH the host bundle
// and the worker bundle:
//   • `IOC.*`                     — host: src/constants.js   worker: shim
//   • `looksLikeIpVersionString`  — host: src/constants.js   worker: shim
//   • `stripDerTail`              — host: src/constants.js   worker: shim
//   • `_trimPathExtGarbage`       — host: src/constants.js   worker: shim
//   • `_unwrapSafeLink`           — defined here (both bundles)
//   • `_refangString`             — defined here (both bundles)
//
// Renderers that mid-parse-mutate `findings.interestingStrings` (eml,
// msg) keep using `EncodedContentDetector.unwrapSafeLink`; the body of
// `_unwrapSafeLink` here is a verbatim copy and must stay in lockstep
// with `src/decoders/safelinks.js`. The two are pure (no shared state)
// so drift risk is contained — but if you change one, change both.
// ════════════════════════════════════════════════════════════════════════════

// ── _unwrapSafeLink (mirrors src/decoders/safelinks.js verbatim) ────────────
//
// Worker-safe global so the core IOC extractor can call it both on the host
// (where `EncodedContentDetector.unwrapSafeLink` is also defined) and inside
// the IOC worker bundle (where `EncodedContentDetector` does not exist).
// Body is a byte-for-byte copy of `EncodedContentDetector.unwrapSafeLink`.
function _unwrapSafeLink(url) {
  if (!url || typeof url !== 'string') return null;

  // ── Proofpoint URLDefense v3 ──
  // Format: https://urldefense.com/v3/__<URL>__;!!<token>
  const ppV3Re = /^https?:\/\/urldefense\.com\/v3\/__(.+?)__;/i;
  let m = url.match(ppV3Re);
  if (m) {
    let extracted = m[1];
    // Proofpoint v3 replaces certain chars with * followed by a hex code
    extracted = extracted.replace(/\*([0-9A-Fa-f]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
    return { originalUrl: extracted, emails: [], provider: 'Proofpoint v3' };
  }

  // ── Proofpoint URLDefense v2 ──
  const ppV2Re = /^https?:\/\/urldefense\.proofpoint\.com\/v2\/url\?/i;
  if (ppV2Re.test(url)) {
    try {
      const params = new URL(url).searchParams;
      let encoded = params.get('u');
      if (encoded) {
        encoded = encoded.replace(/-/g, '%').replace(/_/g, '/');
        const extracted = decodeURIComponent(encoded);
        return { originalUrl: extracted, emails: [], provider: 'Proofpoint v2' };
      }
    } catch (_) { /* malformed URL */ }
  }

  // ── Proofpoint URLDefense v1 ──
  const ppV1Re = /^https?:\/\/urldefense\.proofpoint\.com\/v1\/url\?/i;
  if (ppV1Re.test(url)) {
    try {
      const params = new URL(url).searchParams;
      let encoded = params.get('u');
      if (encoded) {
        encoded = encoded.replace(/-/g, '%').replace(/_/g, '/');
        const extracted = decodeURIComponent(encoded);
        return { originalUrl: extracted, emails: [], provider: 'Proofpoint v1' };
      }
    } catch (_) { /* malformed URL */ }
  }

  // ── Microsoft SafeLinks ──
  const msRe = /^https?:\/\/[a-z0-9]+\.safelinks\.protection\.outlook\.com\/?\?/i;
  if (msRe.test(url)) {
    try {
      const params = new URL(url).searchParams;
      const encodedUrl = params.get('url');
      const data = params.get('data');
      const emails = [];

      if (data) {
        let dataDecoded = data;
        try { dataDecoded = decodeURIComponent(data); } catch (_) { /* keep raw */ }
        const emailRe = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;
        let em;
        while ((em = emailRe.exec(dataDecoded)) !== null) {
          if (!emails.includes(em[0])) emails.push(em[0]);
        }
      }

      if (encodedUrl) {
        const extracted = decodeURIComponent(encodedUrl);
        return { originalUrl: extracted, emails, provider: 'Microsoft SafeLinks' };
      }
    } catch (_) { /* malformed URL */ }
  }

  return null;
}

// ── _refangString — moved from app/app-load.js (verbatim) ────────────────────
//
// Refang a defanged URL, IP, domain, or email address.
// Common defang patterns: hxxp → http, [.] → ., [@] → @, [://] → ://
// Returns { original, refanged } or null if not defanged.
function _refangString(str) {
  if (!str || typeof str !== 'string') return null;

  let refanged = str;
  let changed = false;

  // Protocol: hxxp → http, hxxps → https (case-insensitive)
  refanged = refanged.replace(/\bhxxps?/gi, m => {
    changed = true;
    return m.toLowerCase().replace('xx', 'tt');
  });

  // Protocol separator variants
  refanged = refanged.replace(/\[:\/\/\]/g, () => { changed = true; return '://'; });
  refanged = refanged.replace(/\[:\/\]/g, () => { changed = true; return '://'; });
  refanged = refanged.replace(/\[:\]/g, () => { changed = true; return ':'; });

  // Dots: [.] → .
  refanged = refanged.replace(/\[\.\]/g, () => { changed = true; return '.'; });

  // At symbol: [@] → @
  refanged = refanged.replace(/\[@\]/g, () => { changed = true; return '@'; });

  return changed ? { original: str, refanged } : null;
}

// ── extractInterestingStringsCore — the regex-only IOC core ─────────────────
//
// Pure function (no `this`, no DOM, no `EncodedContentDetector` reach-through).
// Logic moved verbatim from `App.prototype._extractInterestingStrings` —
// behaviour, severity tiers, dedup rules, and per-type quotas are byte-
// equivalent. The only API difference is the inputs (`text + opts`) and
// outputs (`{findings, droppedByType, totalSeenByType}`); the host shim
// re-stamps the side-channel maps onto the array exactly where the old
// code did.
//
// Per-type quota of 200 prevents URL-heavy inputs from starving every other
// IOC class. `_droppedByType` / `_totalSeenByType` are returned so the
// sidebar can render "Showing N of M <type>" notes.
function extractInterestingStringsCore(text, opts) {
  const o = opts || {};
  const existingValues = Array.isArray(o.existingValues) ? o.existingValues : [];
  const vbaModuleSources = Array.isArray(o.vbaModuleSources) ? o.vbaModuleSources : [];

  const seen = new Set(existingValues);
  const results = [];
  const PER_TYPE_CAP = 200;
  const typeCounts = new Map();
  const droppedByType = new Map();
  const totalSeenByType = new Map();

  const add = (type, val, sev, note, sourceInfo) => {
    val = (val || '').trim().replace(/[.,;:!?)\]>]+$/, '');
    if (!val || val.length < 4 || val.length > 400 || seen.has(val)) return false;
    seen.add(val);
    const accepted = typeCounts.get(type) || 0;
    totalSeenByType.set(type, (totalSeenByType.get(type) || 0) + 1);
    if (accepted >= PER_TYPE_CAP) {
      droppedByType.set(type, (droppedByType.get(type) || 0) + 1);
      return false;
    }
    typeCounts.set(type, accepted + 1);
    const entry = { type, url: val, severity: sev };
    if (note) entry.note = note;
    if (sourceInfo) {
      entry._sourceOffset = sourceInfo.offset;
      entry._sourceLength = sourceInfo.length;
      if (sourceInfo.highlightText) entry._highlightText = sourceInfo.highlightText;
    }
    results.push(entry);
    return true;
  };

  // SafeLink-aware URL processor — first strip trailing punctuation, then DER
  // tail-junk via the shared `stripDerTail`.
  const processUrl = (rawUrl, baseSeverity, matchOffset, matchLength) => {
    const url = stripDerTail((rawUrl || '').trim().replace(/[.,;:!?)\]>]+$/, ''));
    if (!url || url.length < 6) return;

    const unwrapped = _unwrapSafeLink(url);
    if (unwrapped) {
      add(IOC.URL, url, 'info', `${unwrapped.provider} wrapper`, {
        offset: matchOffset,
        length: matchLength
      });
      add(IOC.URL, unwrapped.originalUrl, 'high', `Extracted from ${unwrapped.provider}`, {
        offset: matchOffset,
        length: matchLength,
        highlightText: url
      });
      for (const email of unwrapped.emails) {
        add(IOC.EMAIL, email, 'medium', 'Extracted from SafeLinks', {
          offset: matchOffset,
          length: matchLength,
          highlightText: url
        });
      }
    } else {
      add(IOC.URL, url, baseSeverity, null, {
        offset: matchOffset,
        length: matchLength
      });
    }
  };

  // Combined scan surface = main text + every VBA module source on a fresh line.
  const sources = [text || '', ...vbaModuleSources];
  const full = sources.join('\n');

  // ── URL extraction ─────────────────────────────────────────────────────
  const urlSpans = [];
  /* safeRegex: builtin */
  for (const m of full.matchAll(/https?:\/\/[^\s"'<>()\[\]{}\u0000-\u001F]{6,}/g)) {
    urlSpans.push([m.index, m.index + m[0].length]);
    processUrl(m[0], 'info', m.index, m[0].length);
  }
  const _insideUrl = (idx) => urlSpans.some(([s, e]) => idx >= s && idx < e);

  // ── Email extraction ───────────────────────────────────────────────────
  /* safeRegex: builtin */
  for (const m of full.matchAll(/\b[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b/g)) {
    add(IOC.EMAIL, m[0], 'info', null, { offset: m.index, length: m[0].length });
  }

  // ── IPv4 extraction ────────────────────────────────────────────────────
  // URL > Domain > IP severity tiering.
  // Baseline is 'info' (per IOC_CANONICAL_SEVERITY). Escalate to 'medium' only
  // when a port is attached (`1.2.3.4:8080`). Private / loopback / link-local /
  // reserved / multicast / broadcast IPs are dropped entirely. Anti-version
  // lookbehind kills `v1.2.3.4`, `build 2.0.0.1`, etc.
  const _isReservedIp = (octets) => {
    const [a, b] = octets;
    if (a === 0) return true;                          // 0.0.0.0/8
    if (a === 10) return true;                         // 10/8 private
    if (a === 127) return true;                        // loopback
    if (a === 169 && b === 254) return true;           // link-local
    if (a === 172 && b >= 16 && b <= 31) return true;  // 172.16/12 private
    if (a === 192 && b === 168) return true;           // 192.168/16 private
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
    if (a >= 224) return true;                         // multicast + reserved + 255.255.255.255
    return false;
  };
  /* safeRegex: builtin */
  const ipRe = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?::(\d{1,5}))?(?![\d.])/g;
  for (const m of full.matchAll(ipRe)) {
    if (_insideUrl(m.index)) continue;
    const preceding = full.slice(Math.max(0, m.index - 16), m.index);
    if (/\b(?:v|ver|version|build|release|rev|revision|compiled)\b[\s.:#=_-]*$/i.test(preceding)) continue;
    const ipPart = m[0].split(':')[0];
    const parts = ipPart.split('.').map(Number);
    if (!parts.every(p => p <= 255)) continue;
    if (_isReservedIp(parts)) continue;
    const port = m[1] ? Number(m[1]) : null;
    if (port !== null && (port < 1 || port > 65535)) continue;
    if (port === null && looksLikeIpVersionString(ipPart)) continue;
    const sev = port !== null ? 'medium' : 'info';
    add(IOC.IP, m[0], sev, port !== null ? 'With port' : null, { offset: m.index, length: m[0].length });
  }

  // ── Windows file paths ─────────────────────────────────────────────────
  // ReDoS-hardened: per-segment length capped at NTFS-component max (255)
  // and depth capped at 32 (well above any real path). The original
  // unbounded `(?:[\w\-. ]+\\)+` could backtrack catastrophically on a
  // long unterminated `C:\aaa…aaa` input. Bounds preserve every
  // legitimate match shape — Windows MAX_PATH is 260 chars total.
  /* safeRegex: builtin */
  for (const m of full.matchAll(/[A-Za-z]:\\(?:[\w\-. ]{1,255}\\){1,32}[\w\-. ]{2,255}/g)) {
    const path = _trimPathExtGarbage(m[0]);
    add(IOC.FILE_PATH, path, 'medium', null, { offset: m.index, length: path.length });
  }

  // ── UNC paths ──────────────────────────────────────────────────────────
  // ReDoS-hardened: server name ≤255, segments ≤255, depth ≤32 (parity
  // with the renderer-side _UNC_RE in constants.js).
  /* safeRegex: builtin */
  for (const m of full.matchAll(/\\\\[\w.\-]{2,255}(?:\\[\w.\-]{1,255}){1,32}/g)) {
    add(IOC.UNC_PATH, m[0], 'medium', null, { offset: m.index, length: m[0].length });
  }

  // ── Unix file paths ────────────────────────────────────────────────────
  /* safeRegex: builtin */
  for (const m of full.matchAll(/\/(?:usr|etc|bin|sbin|tmp|var|opt|home|root|dev|proc|sys|lib|mnt|run|srv|Library|Applications|System|private)\/[\w.\-/]{2,}/g)) {
    add(IOC.FILE_PATH, m[0], 'info', null, { offset: m.index, length: m[0].length });
  }

  // ── Windows registry keys ──────────────────────────────────────────────
  /* safeRegex: builtin */
  for (const m of full.matchAll(/\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HK(?:LM|CU|CR|U|CC))\\[\w\-. \\]{4,}/g)) {
    add(IOC.REGISTRY_KEY, m[0], 'medium', null, { offset: m.index, length: m[0].length });
  }

  // ── Defanged IOC extraction ────────────────────────────────────────────
  // Detect defanged URLs (hxxp[s][://]...[.]...), IPs (1[.]2[.]3[.]4), and
  // emails (user[@]domain[.]com); refang and add to IOCs with source
  // highlighting that points to the defanged original.

  /* safeRegex: builtin */
  const defangedUrlRe = /\bhxxps?(?:\[:\/?\/?\]|:\/\/)[^\s"'<>]{4,}/gi;
  for (const m of full.matchAll(defangedUrlRe)) {
    const result = _refangString(m[0]);
    if (result && result.refanged.match(/^https?:\/\//i)) {
      const cleaned = result.refanged.replace(/[.,;:!?)\]>]+$/, '');
      if (!seen.has(cleaned) && cleaned.length >= 10) {
        add(IOC.URL, cleaned, 'medium', 'Refanged', {
          offset: m.index,
          length: m[0].length,
          highlightText: m[0]
        });
      }
    }
  }

  // ReDoS-hardened: domain label ≤63 chars (RFC 1035), max 8 labels
  // (real-world FQDNs rarely exceed 5), path body ≤2048 chars.
  /* safeRegex: builtin */
  const defangedDomainRe = /\b[\w\-]{1,63}(?:\[\.\][\w\-]{1,63}){1,8}(?:\/[^\s"'<>]{0,2048})?\b/g;
  for (const m of full.matchAll(defangedDomainRe)) {
    const result = _refangString(m[0]);
    if (result) {
      const cleaned = result.refanged.replace(/[.,;:!?)\]>]+$/, '');
      if (!seen.has(cleaned) && /^[\w\-]+\.[\w\-]+/.test(cleaned) && cleaned.length >= 4) {
        add(IOC.URL, cleaned, 'medium', 'Refanged domain', {
          offset: m.index,
          length: m[0].length,
          highlightText: m[0]
        });
      }
    }
  }

  /* safeRegex: builtin */
  const defangedIpRe = /(?<![\d.])\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}(?![\d.])/g;
  for (const m of full.matchAll(defangedIpRe)) {
    const result = _refangString(m[0]);
    if (result) {
      const parts = result.refanged.split('.').map(Number);
      if (parts.length === 4 && parts.every(p => p >= 0 && p <= 255) && !result.refanged.startsWith('0.')) {
        if (!seen.has(result.refanged)) {
          add(IOC.IP, result.refanged, 'medium', 'Refanged', {
            offset: m.index,
            length: m[0].length,
            highlightText: m[0]
          });
        }
      }
    }
  }

  /* safeRegex: builtin */
  const defangedEmailRe = /\b[a-zA-Z0-9._%+\-]+\[@\][a-zA-Z0-9.\-\[\]]+\b/g;
  for (const m of full.matchAll(defangedEmailRe)) {
    const result = _refangString(m[0]);
    if (result) {
      const cleaned = result.refanged.replace(/[.,;:!?)\]>]+$/, '');
      if (!seen.has(cleaned) && /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(cleaned)) {
        add(IOC.EMAIL, cleaned, 'medium', 'Refanged', {
          offset: m.index,
          length: m[0].length,
          highlightText: m[0]
        });
      }
    }
  }

  // ── VBA-specific URL scan (higher severity, also SafeLink-aware) ────────
  // VBA modules are appended to `full` after the main text, so offsets are
  // relative to `full` and will work for highlighting in combined view.
  for (const src of vbaModuleSources) {
    /* safeRegex: builtin */
    for (const m of (src || '').matchAll(/https?:\/\/[^\s"']{6,}/g)) {
      const v = m[0].replace(/[.,;:!?)\]>]+$/, '');
      if (!seen.has(v)) {
        const unwrapped = _unwrapSafeLink(v);
        if (unwrapped) {
          add(IOC.URL, v, 'medium', `${unwrapped.provider} wrapper (VBA)`);
          add(IOC.URL, unwrapped.originalUrl, 'critical', `Extracted from ${unwrapped.provider} (VBA)`, {
            highlightText: v
          });
          for (const email of unwrapped.emails) {
            add(IOC.EMAIL, email, 'high', 'Extracted from SafeLinks (VBA)', {
              highlightText: v
            });
          }
        } else {
          add(IOC.URL, v, 'high');
        }
      }
    }
  }

  return { findings: results, droppedByType, totalSeenByType };
}
