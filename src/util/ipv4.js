'use strict';
// ════════════════════════════════════════════════════════════════════════════
// ipv4.js — strict IPv4 parser + non-routable-range classifier shared
// between the Timeline GeoIP enrichment mixin (`timeline-view-geoip.js`)
// and the sidebar / summary IOC enrichment path (`app-sidebar.js`,
// `app-ui.js`).
//
// Single source of truth for "is this string a strict dotted-quad?" and
// "is this IPv4 within a non-routable range we should NOT bother sending
// to a GeoIP / ASN provider?". Lifted verbatim from the timeline mixin's
// previous file-private implementation; behaviour is byte-equivalent for
// `isStrictIPv4`. The `isPrivateIPv4` helper is new — it lets the IOC
// enrichment surfaces silently skip RFC1918 / loopback / link-local /
// multicast / broadcast / CGNAT / 0.0.0.0/8 addresses (every bundled
// provider returns null for these anyway, so emitting an empty
// "Enrichment" cell would just add noise).
//
// Surface (single global, no module system per project conventions):
//
//   Ipv4Util.isStrictIPv4(s)   → boolean
//   Ipv4Util.isPrivateIPv4(s)  → boolean (false for non-IPv4 inputs)
//
// CSP-safe: pure string parsing, no regex backtracking, no eval.
// ════════════════════════════════════════════════════════════════════════════

const Ipv4Util = (function () {
  // Parse a strict dotted-quad. Rejects leading zeros (e.g. "01.2.3.4"),
  // octets > 255, and anything outside [7..15] characters. Returns
  // booleans only — callers that need the four octets re-parse via
  // `_parseOctets` below.
  function isStrictIPv4(s) {
    if (typeof s !== 'string') return false;
    const len = s.length;
    if (len < 7 || len > 15) return false;
    let octets = 0;
    let cur = 0;
    let curDigits = 0;
    for (let i = 0; i < len; i++) {
      const c = s.charCodeAt(i);
      if (c >= 48 && c <= 57) {
        if (curDigits === 0 && c === 48 && i + 1 < len && s.charCodeAt(i + 1) >= 48 && s.charCodeAt(i + 1) <= 57) {
          return false;
        }
        cur = cur * 10 + (c - 48);
        curDigits++;
        if (cur > 255 || curDigits > 3) return false;
      } else if (c === 46) {  // '.'
        if (curDigits === 0) return false;
        octets++;
        if (octets > 3) return false;
        cur = 0;
        curDigits = 0;
      } else {
        return false;
      }
    }
    return curDigits > 0 && octets === 3;
  }

  // Decode a strict dotted-quad into its four octet integers. Returns
  // null when input is not a strict IPv4. Callers that already know the
  // input is valid can rely on the array shape.
  function _parseOctets(s) {
    if (!isStrictIPv4(s)) return null;
    const parts = s.split('.');
    return [
      parseInt(parts[0], 10),
      parseInt(parts[1], 10),
      parseInt(parts[2], 10),
      parseInt(parts[3], 10),
    ];
  }

  // RFC1918 + loopback + link-local + multicast + broadcast + CGNAT +
  // "this network". GeoIP / ASN providers all return null for these so
  // the IOC enrichment path skips them rather than emitting empty cells.
  // Returns false for non-IPv4 inputs (caller can decide separately
  // whether to enrich at all).
  function isPrivateIPv4(s) {
    const o = _parseOctets(s);
    if (!o) return false;
    const a = o[0], b = o[1];
    if (a === 0) return true;                     // 0.0.0.0/8 — "this network"
    if (a === 10) return true;                    // 10.0.0.0/8 (RFC1918)
    if (a === 127) return true;                   // 127.0.0.0/8 (loopback)
    if (a === 169 && b === 254) return true;      // 169.254.0.0/16 (link-local)
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 (RFC1918)
    if (a === 192 && b === 168) return true;      // 192.168.0.0/16 (RFC1918)
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT, RFC6598)
    if (a >= 224 && a <= 239) return true;        // 224.0.0.0/4 (multicast)
    if (a >= 240) return true;                    // 240.0.0.0/4 (reserved) + 255.255.255.255 (broadcast)
    return false;
  }

  return { isStrictIPv4, isPrivateIPv4 };
})();

if (typeof window !== 'undefined') {
  window.Ipv4Util = Ipv4Util;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { Ipv4Util };
}
