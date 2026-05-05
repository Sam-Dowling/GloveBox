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

  // Nested-URL-in-query decoder.
  //
  // ClickFix / lure-page redirectors commonly embed the real payload URL as
  // a percent-encoded query parameter on a benign-looking host, e.g.
  //   https://benign.example.com/a/b.php?a=https%3A%2F%2Fevil%2Ecom%2F%3Fpayload%3D…
  // The outer URL alone would land as an info-severity IOC and the analyst
  // loses the actual C2 host. This helper percent-decodes the query portion
  // (host/path left alone — `UrlNormalizeUtil` already handles those) and
  // runs the canonical URL regex over the decoded form. Any inner URL is
  // handed back to `processUrl` (at medium severity, with a 'Nested URL
  // (query param)' note) so SafeLink / normalise / refang / domain-sibling
  // logic all apply uniformly.
  //
  // Bounds:
  //   • depth is capped at 1. Deeper nesting (?a=?b=?c=) would require a
  //     genuine redirector chain, which is rare and fuzz-risk territory.
  //   • decoded query length capped at MAX_QUERY_DECODE_LEN to keep the
  //     hot loop O(short-strings).
  //   • fast-path short-circuit when the query is empty or `%`-free.
  const MAX_NEST_DEPTH = 1;
  const MAX_QUERY_DECODE_LEN = 8192;

  const _decodePercentBestEffort = (s) => {
    if (typeof s !== 'string' || s.indexOf('%') < 0) return s;
    try {
      return decodeURIComponent(s);
    } catch (_) {
      // Partial-decode fallback: decode each %XX token individually so a
      // single malformed sequence doesn't suppress the rest.
      return s.replace(/%([0-9A-Fa-f]{2})/g, (m, hex) => {
        try { return decodeURIComponent('%' + hex); } catch (_e) { return m; }
      });
    }
  };

  const _scanNestedUrlsInQuery = (outerUrl, outerOffset, outerLength, depth) => {
    if (depth >= MAX_NEST_DEPTH) return;
    if (typeof outerUrl !== 'string' || outerUrl.length > MAX_QUERY_DECODE_LEN) return;
    const qIdx = outerUrl.indexOf('?');
    if (qIdx < 0) return;
    // Fragment-trim: `?a=…#frag` — decode only up to the fragment.
    const hashIdx = outerUrl.indexOf('#', qIdx + 1);
    const rawQuery = hashIdx >= 0
      ? outerUrl.slice(qIdx + 1, hashIdx)
      : outerUrl.slice(qIdx + 1);
    if (!rawQuery || rawQuery.length < 8) return;
    // Fast-path: only bother decoding when the query actually contains the
    // markers of a URL-in-URL (`%3A%2F%2F` in either case, or `hxxp`).
    if (!/%3[Aa]|%2[Ff]|hxxps?/i.test(rawQuery)) return;
    const decoded = _decodePercentBestEffort(rawQuery);
    if (decoded === rawQuery) return;

    // Run the canonical URL regex over the decoded query. `safeMatchAll`
    // bounds wall-clock + match count so a pathological decoded payload
    // can't monopolise the thread.
    /* safeRegex: builtin */
    const innerRe = /https?:\/\/[^\s"'<>()\[\]{}\u0000-\u001F]{6,}/g;
    for (const im of safeMatchAll(innerRe, decoded, 200, 32).matches) {
      const innerRaw = im[0];
      if (!innerRaw || innerRaw.length < 10) continue;
      // Hand the inner URL back through `processUrl` so SafeLinks,
      // obfuscation-normalise, and the default push all apply. The
      // nestedFrom argument tags the recursion so the inner emit carries
      // the right provenance note and severity bump.
      processUrl(innerRaw, 'medium', outerOffset, outerLength, depth + 1, outerUrl);
    }
  };

  // SafeLink-aware URL processor — first strip trailing punctuation, then DER
  // tail-junk via the shared `stripDerTail`.
  //
  // Obfuscation-decoding is layered after the SafeLink unwrap: when
  // `UrlNormalizeUtil.normalizeUrl` reports a change (unicode/hex escapes,
  // percent-encoding, hex/octal/decimal-encoded IP host), the original is
  // pushed at the existing severity with note 'Obfuscated URL' and the
  // decoded form is pushed at 'medium' severity (matching SafeLinks /
  // refanged precedent — obfuscation is itself a signal). When the decoded
  // host is a dotted-quad we also push an `IOC.IP` sibling so GeoIP
  // enrichment kicks in. The `processUrl` helper has no `findings` ref to
  // call `pushIOC` (which is host-only and reaches into `tldts`); manual
  // sibling emission keeps the worker bundle self-contained.
  //
  // `depth` tracks nested-URL recursion (see `_scanNestedUrlsInQuery`). A
  // non-zero depth means we were invoked from a query-param decode; in that
  // case the emitted primary row carries a 'Nested URL (query param)' note
  // so the analyst can pivot back to the outer URL via `highlightText`.
  // `nestedFrom` is the outer URL string (used as `highlightText` for the
  // inner row so click-to-focus lands on the visible source).
  const processUrl = (rawUrl, baseSeverity, matchOffset, matchLength, depth, nestedFrom) => {
    const url = stripDerTail((rawUrl || '').trim().replace(/[.,;:!?)\]>]+$/, ''));
    if (!url || url.length < 6) return;
    depth = depth | 0;
    const isNested = depth > 0;
    const nestedNote = isNested ? 'Nested URL (query param)' : null;
    const nestedHighlight = isNested ? (nestedFrom || url) : null;

    const unwrapped = _unwrapSafeLink(url);
    if (unwrapped) {
      add(IOC.URL, url, isNested ? 'medium' : 'info',
        isNested
          ? `${unwrapped.provider} wrapper (nested in query)`
          : `${unwrapped.provider} wrapper`,
        {
          offset: matchOffset,
          length: matchLength,
          highlightText: nestedHighlight,
        });
      add(IOC.URL, unwrapped.originalUrl, 'high',
        `Extracted from ${unwrapped.provider}`,
        {
          offset: matchOffset,
          length: matchLength,
          highlightText: nestedHighlight || url,
        });
      for (const email of unwrapped.emails) {
        add(IOC.EMAIL, email, 'medium', 'Extracted from SafeLinks', {
          offset: matchOffset,
          length: matchLength,
          highlightText: nestedHighlight || url,
        });
      }
      _scanNestedUrlsInQuery(url, matchOffset, matchLength, depth);
      return;
    }

    // Obfuscation normalisation. Pure helper from src/util/url-normalize.js;
    // returns null only on non-string input. `changed` is false for the
    // overwhelming majority of URLs (no extra cost when nothing matches).
    let norm = null;
    try {
      if (typeof UrlNormalizeUtil !== 'undefined' && UrlNormalizeUtil) {
        norm = UrlNormalizeUtil.normalizeUrl(url);
      }
    } catch (_) { /* best-effort */ }

    if (norm && norm.changed && norm.normalized && norm.normalized !== url) {
      // Original first, at the captured severity, annotated as obfuscated.
      add(IOC.URL, url, isNested ? 'medium' : baseSeverity,
        isNested ? 'Nested URL (query param) — Obfuscated' : 'Obfuscated URL',
        {
          offset: matchOffset,
          length: matchLength,
          highlightText: nestedHighlight,
        });
      const noteParts = norm.transformations && norm.transformations.length
        ? norm.transformations.join(', ') : 'obfuscation';
      add(IOC.URL, norm.normalized, 'medium', `Decoded from ${noteParts}`, {
        offset: matchOffset,
        length: matchLength,
        highlightText: nestedHighlight || url,
      });
      // Sibling IP for the decoded host. Manual emit because this core
      // doesn't reach into pushIOC / tldts (worker-bundle constraint).
      if (norm.hostIsIp && norm.normalizedHost) {
        add(IOC.IP, norm.normalizedHost, 'medium', 'Decoded from obfuscated URL', {
          offset: matchOffset,
          length: matchLength,
          highlightText: nestedHighlight || url,
        });
      }
      _scanNestedUrlsInQuery(norm.normalized, matchOffset, matchLength, depth);
      return;
    }

    add(IOC.URL, url, isNested ? 'medium' : baseSeverity, nestedNote, {
      offset: matchOffset,
      length: matchLength,
      highlightText: nestedHighlight,
    });
    _scanNestedUrlsInQuery(url, matchOffset, matchLength, depth);
  };

  // Combined scan surface = main text + every VBA module source on a fresh line.
  const sources = [text || '', ...vbaModuleSources];
  const full = sources.join('\n');

  // Bounded `matchAll` shim — every IOC regex below routes through this so a
  // single pathological regex (e.g. unbounded quantifier-around-rare-char on a
  // long single-line input) cannot monopolise the main thread. Caps each
  // regex at 500 ms wall-clock and 10 000 matches; both are well above the
  // realistic worst case (per-type IOC cap is 200, every regex below is a
  // tight prefix-anchored shape that matches in <1 ms on legitimate input).
  // Returns a plain array so existing `for (const m of ...)` loops are
  // byte-equivalent at the call site. Defence-in-depth on top of the bounded
  // quantifiers — see CONTRIBUTING.md § Regex Safety. Args mirror the
  // canonical `safeMatchAll(re, str, budgetMs, maxMatches)` signature in
  // src/constants.js / src/workers/encoded-worker-shim.js.
  const _matchAll = (str, re) => safeMatchAll(re, str, 500, 10000).matches;

  // ── URL extraction ─────────────────────────────────────────────────────
  const urlSpans = [];
  /* safeRegex: builtin */
  for (const m of _matchAll(full, /https?:\/\/[^\s"'<>()\[\]{}\u0000-\u001F]{6,}/g)) {
    urlSpans.push([m.index, m.index + m[0].length]);
    processUrl(m[0], 'info', m.index, m[0].length);
  }
  const _insideUrl = (idx) => urlSpans.some(([s, e]) => idx >= s && idx < e);

  // ── Email extraction ───────────────────────────────────────────────────
  /* safeRegex: builtin */
  for (const m of _matchAll(full, /\b[a-zA-Z0-9._%+\-]{2,}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,6}\b/g)) {
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
  for (const m of _matchAll(full, ipRe)) {
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

  // ── IPv6 extraction ────────────────────────────────────────────────────
  // Two recognised shapes:
  //   • bracketed-in-URL form: `[2001:db8::1]` (also covers `:port` suffix)
  //   • bare RFC 5952 form: `2001:db8::1`, `fe80::1`, fully-spelled
  //                         `2001:0db8:0000:0000:0000:ff00:0042:8329`
  // Strict acceptance:
  //   - must contain `::` OR exactly 8 hextet groups (no shorter forms);
  //   - at least one hextet must be ≥ 2 hex digits (kills `1:2:3:4:5:6:7:8`-
  //     style false positives from version strings, port pairs, MAC fragments);
  //   - drop loopback (`::1`), unspecified (`::`), link-local (`fe80::/10`),
  //     unique-local (`fc00::/7`), multicast (`ff00::/8`), documentation
  //     (`2001:db8::/32`), and IPv4-mapped (`::ffff:0:0/96`);
  //   - anti-version lookbehind on the preceding 16 chars matches the IPv4
  //     scanner exactly.
  // Bracketed matches are emitted as the bare address (without brackets);
  // `_highlightText` carries the original literal so the click-to-focus
  // path lands on the bracketed form the analyst sees.
  const _ipv6CompressedRe = /(?<![:\w])((?:[0-9A-Fa-f]{1,4}:){0,7}:(?:[0-9A-Fa-f]{1,4}:){0,7}[0-9A-Fa-f]{0,4})(?![:\w.])/g;
  const _ipv6FullRe = /(?<![:\w])((?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})(?![:\w.])/g;
  // ReDoS bound: `{2,}` would match an unbounded run of `[hex]:` / `:` chars.
  // Real IPv6 addresses have at most 8 hextet groups, so `{2,9}` (one extra
  // for the trailing colon in `::`) suffices and prevents O(n²)-shaped
  // backtracking on long colon-rich inputs (binary blobs, hex dumps).
  const _ipv6BracketRe = /\[((?:[0-9A-Fa-f]{1,4}:|:){2,9}[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{1,4}){0,7})\](?::(\d{1,5}))?/g;

  const _expandIpv6 = (addr) => {
    // Returns the 8-hextet array on success, null on malformed input.
    if (!addr) return null;
    const a = addr.toLowerCase();
    if ((a.match(/::/g) || []).length > 1) return null;
    let head, tail;
    if (a.includes('::')) {
      const parts = a.split('::');
      head = parts[0] ? parts[0].split(':') : [];
      tail = parts[1] ? parts[1].split(':') : [];
    } else {
      head = a.split(':');
      tail = [];
    }
    const groups = head.length + tail.length;
    if (groups > 8) return null;
    const fill = a.includes('::') ? new Array(8 - groups).fill('0') : [];
    const all = [...head, ...fill, ...tail];
    if (all.length !== 8) return null;
    for (const g of all) {
      if (g === '') return null;
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    }
    return all.map(g => parseInt(g, 16));
  };

  const _isReservedIpv6 = (groups) => {
    if (!groups) return true;
    const [g0, g1] = groups;
    // Unspecified (::) and loopback (::1)
    if (groups.every(g => g === 0)) return true;
    if (groups.slice(0, 7).every(g => g === 0) && groups[7] === 1) return true;
    // Link-local fe80::/10
    if ((g0 & 0xffc0) === 0xfe80) return true;
    // Unique-local fc00::/7
    if ((g0 & 0xfe00) === 0xfc00) return true;
    // Multicast ff00::/8
    if ((g0 & 0xff00) === 0xff00) return true;
    // Documentation 2001:db8::/32
    if (g0 === 0x2001 && g1 === 0x0db8) return true;
    // IPv4-mapped ::ffff:0:0/96 — these are IPv4 addresses in disguise; the
    // IPv4 scanner already handles them. Drop to avoid double-pivoting.
    if (groups.slice(0, 5).every(g => g === 0) && groups[5] === 0xffff) return true;
    return false;
  };

  const _candidateLooksLikeIpv6 = (candidate) => {
    // Must contain `::` (compressed) or 8 colon-separated groups.
    if (candidate.includes('::')) return true;
    const groups = candidate.split(':');
    if (groups.length !== 8) return false;
    // Reject if every hextet is 1 char — almost certainly a version triplet
    // ("1:2:3:4:5:6:7:8") rather than a real address.
    if (groups.every(g => g.length <= 1)) return false;
    return true;
  };

  const _processIpv6 = (literal, addr, port, offset, length, highlight) => {
    if (!_candidateLooksLikeIpv6(addr)) return;
    if (port !== null && (port < 1 || port > 65535)) return;
    const groups = _expandIpv6(addr);
    if (!groups) return;
    if (_isReservedIpv6(groups)) return;
    // Anti-version lookbehind — same posture as the IPv4 scanner.
    const preceding = full.slice(Math.max(0, offset - 16), offset);
    if (/\b(?:v|ver|version|build|release|rev|revision|compiled)\b[\s.:#=_-]*$/i.test(preceding)) return;
    const value = port !== null ? `[${addr}]:${port}` : addr;
    const sev = port !== null ? 'medium' : 'info';
    const sourceInfo = { offset, length };
    if (highlight) sourceInfo.highlightText = highlight;
    add(IOC.IP, value, sev, port !== null ? 'IPv6 with port' : 'IPv6', sourceInfo);
  };

  /* safeRegex: builtin */
  for (const m of _matchAll(full, _ipv6BracketRe)) {
    const port = m[2] ? Number(m[2]) : null;
    _processIpv6(m[0], m[1], port, m.index, m[0].length, m[0]);
  }
  /* safeRegex: builtin */
  for (const m of _matchAll(full, _ipv6CompressedRe)) {
    if (_insideUrl(m.index)) continue;
    _processIpv6(m[0], m[1], null, m.index, m[0].length, null);
  }
  /* safeRegex: builtin */
  for (const m of _matchAll(full, _ipv6FullRe)) {
    if (_insideUrl(m.index)) continue;
    _processIpv6(m[0], m[1], null, m.index, m[0].length, null);
  }

  // ── Windows file paths ─────────────────────────────────────────────────
  // ReDoS-hardened: per-segment length capped at NTFS-component max (255)
  // and depth capped at 32 (well above any real path). The original
  // unbounded `(?:[\w\-. ]+\\)+` could backtrack catastrophically on a
  // long unterminated `C:\aaa…aaa` input. Bounds preserve every
  // legitimate match shape — Windows MAX_PATH is 260 chars total.
  /* safeRegex: builtin */
  for (const m of _matchAll(full, /[A-Za-z]:\\(?:[\w\-. ]{1,255}\\){1,32}[\w\-. ]{2,255}/g)) {
    const path = _trimPathExtGarbage(m[0]);
    add(IOC.FILE_PATH, path, 'medium', null, { offset: m.index, length: path.length });
  }

  // ── UNC paths ──────────────────────────────────────────────────────────
  // ReDoS-hardened: server name ≤255, segments ≤255, depth ≤32 (parity
  // with the renderer-side _UNC_RE in constants.js).
  /* safeRegex: builtin */
  for (const m of _matchAll(full, /\\\\[\w.\-]{2,255}(?:\\[\w.\-]{1,255}){1,32}/g)) {
    add(IOC.UNC_PATH, m[0], 'medium', null, { offset: m.index, length: m[0].length });
  }

  // ── Unix file paths ────────────────────────────────────────────────────
  /* safeRegex: builtin */
  for (const m of _matchAll(full, /\/(?:usr|etc|bin|sbin|tmp|var|opt|home|root|dev|proc|sys|lib|mnt|run|srv|Library|Applications|System|private)\/[\w.\-/]{2,}/g)) {
    add(IOC.FILE_PATH, m[0], 'info', null, { offset: m.index, length: m[0].length });
  }

  // ── Windows registry keys ──────────────────────────────────────────────
  /* safeRegex: builtin */
  for (const m of _matchAll(full, /\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HK(?:LM|CU|CR|U|CC))\\[\w\-. \\]{4,}/g)) {
    add(IOC.REGISTRY_KEY, m[0], 'medium', null, { offset: m.index, length: m[0].length });
  }

  // ── Defanged IOC extraction ────────────────────────────────────────────
  // Detect defanged URLs (hxxp[s][://]...[.]...), IPs (1[.]2[.]3[.]4), and
  // emails (user[@]domain[.]com); refang and add to IOCs with source
  // highlighting that points to the defanged original.

  /* safeRegex: builtin */
  const defangedUrlRe = /\bhxxps?(?:\[:\/?\/?\]|:\/\/)[^\s"'<>]{4,}/gi;
  for (const m of _matchAll(full, defangedUrlRe)) {
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
  for (const m of _matchAll(full, defangedDomainRe)) {
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
  for (const m of _matchAll(full, defangedIpRe)) {
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
  for (const m of _matchAll(full, defangedEmailRe)) {
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
    for (const m of _matchAll((src || ''), /https?:\/\/[^\s"']{6,}/g)) {
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

  // ── Crypto-currency / dark-web / IPFS address pivots ───────────────────
  // Shape-only validators — keccak256 / base58check / bech32 polymod
  // verification would require either an async hop (crypto.subtle is
  // async) or several KB of inline crypto. We rely on tight character-
  // class bounds + length anchors + per-class caps instead. False-
  // positive rate is acceptable for an analyst-facing surface; every hit
  // emits with `note: '<variant>'` so an analyst can skim provenance.
  //
  // Each variant emits IOC.CRYPTO_ADDRESS at MEDIUM severity (canonical
  // floor). Capped at 32 hits per scan to keep document-size files (which
  // can have thousands of incidental base58-shaped strings) from drowning
  // the sidebar. The `_insideUrl` guard avoids double-emitting addresses
  // that already appear inside extracted URLs (e.g. block-explorer links).
  try {
    const CRYPTO_CAP = 32;
    let cryptoHits = 0;

    const _emitCrypto = (value, variant, offset, length) => {
      if (cryptoHits++ >= CRYPTO_CAP) return;
      add(IOC.CRYPTO_ADDRESS, value, 'medium', variant,
        { offset, length, highlightText: value });
    };

    // BTC legacy P2PKH / P2SH — base58 starting with 1 or 3, 26-35 chars.
    // The leading-version-byte constraint (1 = P2PKH mainnet, 3 = P2SH
    // mainnet) plus the strict base58 alphabet (no 0OIl) makes the
    // shape-only regex specific enough that random text rarely matches.
    /* safeRegex: builtin */
    const btcLegacyRe = /(?<![A-Za-z0-9])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![A-Za-z0-9])/g;
    for (const m of _matchAll(full, btcLegacyRe)) {
      if (_insideUrl(m.index)) continue;
      if (cryptoHits >= CRYPTO_CAP) break;
      _emitCrypto(m[0], 'BTC (legacy P2PKH/P2SH)', m.index, m[0].length);
    }

    // BTC bech32 / bech32m — `bc1` lowercase, 39 / 59 char body. Bech32
    // alphabet excludes `1`, `b`, `i`, `o` to avoid visual confusion.
    /* safeRegex: builtin */
    const btcBech32Re = /(?<![a-z0-9])bc1[02-9ac-hj-np-z]{6,87}(?![a-z0-9])/g;
    for (const m of _matchAll(full, btcBech32Re)) {
      if (_insideUrl(m.index)) continue;
      if (cryptoHits >= CRYPTO_CAP) break;
      // Bech32 addresses are 42 chars (P2WPKH) or 62 chars (P2WSH);
      // bech32m taproot addresses are 62 chars. Filter to those exact
      // lengths to suppress base32-shaped noise.
      if (m[0].length !== 42 && m[0].length !== 62) continue;
      _emitCrypto(m[0], 'BTC (bech32 / taproot)', m.index, m[0].length);
    }

    // Ethereum — `0x` + 40 hex. Requires word-boundary isolation so 64-
    // hex hashes preceded by `0x` don't match. Also drop the all-zero
    // burn address (well-known, not a pivot).
    /* safeRegex: builtin */
    const ethRe = /(?<![A-Za-z0-9])0x[0-9a-fA-F]{40}(?![0-9a-fA-F])/g;
    for (const m of _matchAll(full, ethRe)) {
      if (_insideUrl(m.index)) continue;
      if (cryptoHits >= CRYPTO_CAP) break;
      const lower = m[0].toLowerCase();
      if (lower === '0x' + '0'.repeat(40)) continue;
      _emitCrypto(m[0], 'ETH (or EVM-chain) address', m.index, m[0].length);
    }

    // Monero — base58, 95 chars (standard) starting with `4`, or 106 chars
    // (integrated, with payment ID) starting with `4`. The leading-`4`
    // constraint corresponds to network byte 0x12 (mainnet standard
    // address). Tight enough that random text rarely matches the exact
    // length + leading-byte combo.
    /* safeRegex: builtin */
    const xmrRe = /(?<![A-Za-z0-9])4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?:[1-9A-HJ-NP-Za-km-z]{11})?(?![A-Za-z0-9])/g;
    for (const m of _matchAll(full, xmrRe)) {
      if (_insideUrl(m.index)) continue;
      if (cryptoHits >= CRYPTO_CAP) break;
      if (m[0].length !== 95 && m[0].length !== 106) continue;
      const variant = m[0].length === 106 ? 'XMR (integrated)' : 'XMR';
      _emitCrypto(m[0], variant, m.index, m[0].length);
    }

    // Tor onion v3 — 56-char base32 (lowercase a-z + 2-7) ending in `.onion`.
    // Requiring the `.onion` suffix drops the false-positive rate dramatically
    // vs. raw 56-char base32 strings (which appear in many binary blobs).
    /* safeRegex: builtin */
    const onionRe = /(?<![a-z0-9])([a-z2-7]{56})\.onion(?![a-z0-9])/g;
    for (const m of _matchAll(full, onionRe)) {
      if (cryptoHits >= CRYPTO_CAP) break;
      _emitCrypto(m[0], 'Tor onion v3', m.index, m[0].length);
    }

    // IPFS CIDv0 — `Qm` + 44 base58 (multihash for SHA-256). Length is
    // exact, leading bytes are fixed.
    /* safeRegex: builtin */
    const ipfsV0Re = /(?<![A-Za-z0-9])Qm[1-9A-HJ-NP-Za-km-z]{44}(?![A-Za-z0-9])/g;
    for (const m of _matchAll(full, ipfsV0Re)) {
      if (_insideUrl(m.index)) continue;
      if (cryptoHits >= CRYPTO_CAP) break;
      _emitCrypto(m[0], 'IPFS CIDv0', m.index, m[0].length);
    }

    // IPFS CIDv1 (base32) — `bafy…` for sha256 dag-pb / dag-cbor; 59 chars
    // is the canonical length for the most common SHA-256 multihash.
    // Stricter than catching any `b…` base32 to keep the noise down.
    /* safeRegex: builtin */
    const ipfsV1Re = /(?<![a-z0-9])bafy[a-z2-7]{55}(?![a-z0-9])/g;
    for (const m of _matchAll(full, ipfsV1Re)) {
      if (_insideUrl(m.index)) continue;
      if (cryptoHits >= CRYPTO_CAP) break;
      _emitCrypto(m[0], 'IPFS CIDv1', m.index, m[0].length);
    }
  } catch (_) { /* crypto-address scan is best-effort */ }

  // ── Secret-leak detection ──────────────────────────────────────────────
  // Vendor-specific credential patterns chosen for high precision: every
  // family below has either a fixed prefix (AWS `AKIA`, GitHub `ghp_`,
  // Google `AIza`, Slack `xox[a-z]-`, Stripe `sk_live_/rk_live_`) or a
  // PEM `-----BEGIN …-----` armour, all of which are extremely rare
  // outside the credential context. We deliberately exclude the
  // contextual "AWS_SECRET_ACCESS_KEY = <40-base64>" pattern: the FP
  // rate on bare 40-base64 strings is too high (PE digest tables, JSON
  // signatures, etc.) without the surrounding key=value context, which
  // is renderer-specific and belongs in a future targeted detector.
  //
  // Each hit emits `IOC.SECRET` at the canonical floor (`high` — these
  // are exposed credentials) and is mirrored to `externalRefs` as an
  // `IOC.PATTERN` so the existing risk-rollup escalates `findings.risk`.
  // JWTs ship at `medium` because they're often non-sensitive (signed
  // session tokens for public APIs, OIDC `id_token` shipped to logs).
  //
  // Per-family caps default to 8 — these are credentials, not pivots, so
  // a flood of identical AKIA hits in a build artefact is more useful
  // capped than enumerated.
  try {
    const SECRET_CAP = 8;
    const seenSecrets = new Map(); // family → count

    const _emitSecret = (value, family, severity, offset, length) => {
      const c = (seenSecrets.get(family) || 0);
      if (c >= SECRET_CAP) return;
      seenSecrets.set(family, c + 1);
      add(IOC.SECRET, value, severity, family,
        { offset, length, highlightText: value });
    };

    // AWS access key IDs — five flavours by leading 4 chars, all 20-char
    // total. AKIA = long-term IAM, ASIA = STS temp credential, AGPA =
    // group key, AROA = IAM role, AIDA = IAM user.
    /* safeRegex: builtin */
    const awsRe = /(?<![A-Z0-9])(AKIA|ASIA|AGPA|AROA|AIDA)[0-9A-Z]{16}(?![A-Z0-9])/g;
    for (const m of _matchAll(full, awsRe)) {
      _emitSecret(m[0], 'AWS access key ID', 'high', m.index, m[0].length);
    }

    // GitHub tokens — six prefixes (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_)
    // each followed by base62-with-underscore body. ghp_/gho_/ghu_/ghs_/ghr_
    // are 36-char body; github_pat_ is the new fine-grained PAT format with
    // 82-char body (3 segments separated by underscores).
    /* safeRegex: builtin */
    const githubRe = /(?<![A-Za-z0-9_])gh[opusr]_[A-Za-z0-9]{36}(?![A-Za-z0-9_])/g;
    for (const m of _matchAll(full, githubRe)) {
      _emitSecret(m[0], 'GitHub token', 'high', m.index, m[0].length);
    }
    /* safeRegex: builtin */
    const githubPatRe = /(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{82}(?![A-Za-z0-9_])/g;
    for (const m of _matchAll(full, githubPatRe)) {
      _emitSecret(m[0], 'GitHub fine-grained PAT', 'high', m.index, m[0].length);
    }

    // Slack tokens — `xox[abprs]-` followed by digits and hyphens then a
    // base62 secret. We require at least three hyphen-separated numeric
    // segments before the secret to suppress matches against arbitrary
    // `xoxsomething` text.
    /* safeRegex: builtin */
    const slackRe = /(?<![A-Za-z0-9])xox[abprs]-\d+-\d+-\d+-[A-Za-z0-9]{32,}(?![A-Za-z0-9])/g;
    for (const m of _matchAll(full, slackRe)) {
      _emitSecret(m[0], 'Slack token', 'high', m.index, m[0].length);
    }

    // Stripe live API keys — `sk_live_` (secret) and `rk_live_` (restricted)
    // followed by 24+ base62 chars. Stripe also issues `pk_live_` (publishable),
    // which is intentionally not a secret and is excluded.
    /* safeRegex: builtin */
    const stripeRe = /(?<![A-Za-z0-9_])(?:sk|rk)_live_[A-Za-z0-9]{24,}(?![A-Za-z0-9])/g;
    for (const m of _matchAll(full, stripeRe)) {
      _emitSecret(m[0], 'Stripe live API key', 'high', m.index, m[0].length);
    }

    // Google API keys — fixed `AIza` prefix + 35 base64url chars. Used for
    // Maps / YouTube / Cloud APIs; equivalent to a credit-card on a public
    // GitHub repo. Must be word-boundary isolated.
    /* safeRegex: builtin */
    const googleRe = /(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g;
    for (const m of _matchAll(full, googleRe)) {
      _emitSecret(m[0], 'Google API key', 'high', m.index, m[0].length);
    }

    // PEM private-key armour — eight variants. We detect the BEGIN line
    // and emit it as the IOC value (truncated to the armour string itself,
    // not the body, to keep sidebar rows readable). The KEY-NAME class is
    // tightly bound to known PEM types: RSA / DSA / EC / DH / OPENSSH /
    // PGP / PRIVATE / ENCRYPTED PRIVATE.
    /* safeRegex: builtin */
    const pemRe = /-----BEGIN (?:RSA |DSA |EC |DH |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g;
    for (const m of _matchAll(full, pemRe)) {
      _emitSecret(m[0], 'PEM private key', 'high', m.index, m[0].length);
    }

    // JWT — three base64url segments separated by `.`. The first segment
    // must start `eyJ` (which is `{"` base64url-encoded — guaranteed by
    // any JSON header object). We don't validate the header decodes to
    // valid JSON; the prefix + tri-segment shape is specific enough.
    // Severity is medium (not high) because OIDC `id_token` values are
    // routinely logged and aren't a credential by themselves.
    /* safeRegex: builtin */
    const jwtRe = /(?<![A-Za-z0-9_=-])eyJ[A-Za-z0-9_=-]{10,}\.eyJ[A-Za-z0-9_=-]{10,}\.[A-Za-z0-9_=-]{10,}(?![A-Za-z0-9_=-])/g;
    for (const m of _matchAll(full, jwtRe)) {
      _emitSecret(m[0], 'JWT', 'medium', m.index, m[0].length);
    }
  } catch (_) { /* secret-leak scan is best-effort */ }

  // ── Trojan Source / Unicode bidi flag (CVE-2021-42574) ─────────────────
  // Detects three classes of source-code-hostile Unicode use:
  //
  //   • Bidirectional control characters (LRE/RLE/PDF/LRO/RLO/LRI/RLI/FSI/PDI)
  //     — the Trojan Source family. A single RLO inside a comment can flip
  //     the rendered order of the rest of the line, so a reviewer sees one
  //     thing while the compiler sees another. CVSS-rated medium per CERT.
  //   • Invisible / zero-width formatting characters (ZWSP/ZWNJ/ZWJ/WJ/BOM
  //     when not at file start) inside identifier-like runs — used to fork
  //     two visually-identical identifiers into distinct symbols.
  //   • Mixed-script identifiers — Latin + Cyrillic (`раypal` vs `paypal`)
  //     or Latin + Greek (`scаle` Cyrillic-a). High-confidence homoglyph
  //     attack signal in source / config / documentation.
  //
  // Each class surfaces as IOC.PATTERN at MEDIUM severity, capped at 8
  // entries to keep a maliciously dense file from flooding the sidebar.
  // The matched run is included verbatim in `_highlightText` so the
  // sidebar's click-to-focus walks straight to the offending bytes.
  //
  // Caps are intentionally tight; the goal is "hey, look at this", not
  // an exhaustive lint pass.
  try {
    const TROJAN_BIDI_CHARS = '\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069';
    const INVIS_CHARS = '\u200B\u200C\u200D\u2060\uFEFF';
    const TROJAN_CAP = 8;

    // Bidi controls — flag every line that contains any.
    let bidiHits = 0;
    /* safeRegex: builtin */
    const bidiLineRe = new RegExp(
      `[^\\n]{0,200}[${TROJAN_BIDI_CHARS}][^\\n]{0,200}`, 'g'
    );
    for (const m of _matchAll(full, bidiLineRe)) {
      if (bidiHits++ >= TROJAN_CAP) break;
      /* safeRegex: builtin */
      const ch = m[0].match(new RegExp(`[${TROJAN_BIDI_CHARS}]`));
      const cp = ch ? `U+${ch[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}` : 'U+????';
      add(IOC.PATTERN, `Trojan Source — bidi control ${cp} in source (CVE-2021-42574)`, 'medium',
        'Unicode bidi control character — text renders in a different order than parsers see',
        { offset: m.index, length: m[0].length, highlightText: m[0] });
    }

    // Invisible characters embedded in identifier-like runs (≥ 2 word chars
    // either side, ≤ 64 — real identifiers don't legitimately exceed that).
    // The {2,64} bound is critical: an unbounded `\w{2,}` on both sides of
    // a rare-char class produces catastrophic O(n²) backtracking on long
    // single-line `\w` inputs (e.g. 165 KB base64 PowerShell payloads froze
    // the main thread for ~7 s before the bound was added). Catches
    // `pas\u200Bsword` shape splits without firing on legitimate ZWNJ
    // inside Devanagari / Arabic text (which is bracketed by non-word
    // chars). Mirrors the bounded shape `mixedRe` already uses.
    let invisHits = 0;
    /* safeRegex: builtin */
    const invisRe = new RegExp(
      `\\w{2,64}[${INVIS_CHARS}]\\w{2,64}`, 'g'
    );
    for (const m of _matchAll(full, invisRe)) {
      if (invisHits++ >= TROJAN_CAP) break;
      /* safeRegex: builtin */
      const ch = m[0].match(new RegExp(`[${INVIS_CHARS}]`));
      const cp = ch ? `U+${ch[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}` : 'U+????';
      add(IOC.PATTERN, `Invisible character ${cp} inside identifier "${m[0].replace(/[\u200B\u200C\u200D\u2060\uFEFF]/g, '·')}"`, 'medium',
        'Zero-width / invisible character splits a visually-identical identifier',
        { offset: m.index, length: m[0].length, highlightText: m[0] });
    }

    // Mixed-script identifier — Latin paired with Cyrillic OR Greek inside a
    // single word-shaped run. Restrict the run to ≤ 64 chars so document-
    // level mixed-language prose doesn't trigger.
    let mixedHits = 0;
    /* safeRegex: builtin */
    const mixedRe = /[A-Za-z\u0400-\u04FF\u0370-\u03FF]{2,64}/g;
    for (const m of _matchAll(full, mixedRe)) {
      if (mixedHits >= TROJAN_CAP) break;
      const w = m[0];
      const hasLatin = /[A-Za-z]/.test(w);
      const hasCyrillic = /[\u0400-\u04FF]/.test(w);
      const hasGreek = /[\u0370-\u03FF]/.test(w);
      const scripts = (hasLatin ? 1 : 0) + (hasCyrillic ? 1 : 0) + (hasGreek ? 1 : 0);
      if (scripts < 2) continue;
      // Ignore scripts > 4 chars all the same script — already filtered.
      mixedHits++;
      const blend = hasLatin && hasCyrillic ? 'Latin + Cyrillic'
        : hasLatin && hasGreek ? 'Latin + Greek'
        : 'Cyrillic + Greek';
      add(IOC.PATTERN, `Mixed-script identifier "${w}" (${blend}) — possible homoglyph`, 'medium',
        'Identifier mixes alphabets that visually overlap — common phishing / typosquat shape',
        { offset: m.index, length: w.length, highlightText: w });
    }
  } catch (_) { /* Unicode scan is best-effort */ }

  return { findings: results, droppedByType, totalSeenByType };
}
