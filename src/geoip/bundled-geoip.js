'use strict';
// ════════════════════════════════════════════════════════════════════════════
// bundled-geoip.js — RIR-derived IPv4-to-country lookup using the binary
// blob produced by `scripts/fetch_geoip.py` and inlined into the App
// bundle by `scripts/build.py` as the `__GEOIP_BUNDLE_B64` const.
//
// Provider contract (mirrored by `mmdb-reader.js` for user uploads):
//
//   provider.lookupIPv4(ipStr)  → { country, iso, region?, city? } | null
//   provider.formatRow(rec)     → 'Ireland/IE' | 'United States/US/.../...' | ''
//   provider.getFieldName()     → 'geo'  (suffix appended to source col name)
//   provider.vintage            → human label, shown in Settings dialog
//   provider.providerKind       → 'bundled' | 'mmdb'
//
// Loupe uses one resolver: `app.geoip` is set to the user's MMDB reader
// when one is uploaded, otherwise to this BundledGeoip singleton. The
// Timeline mixin queries the resolver via `lookupIPv4` + `formatRow` and
// materialises a single `<sourceCol>.geo` column per detected IP column.
//
// Binary layout (matches scripts/fetch_geoip.py):
//
//   Offset Bytes Field
//   ------ ----- ---------------------------------------------------
//        0     4 Magic 'LGEO'
//        4     2 Format version (uint16 LE)
//        6     2 Reserved (zeros)
//        8     4 Range count R (uint32 LE)
//       12     2 Country count C (uint16 LE)
//       14     2 Reserved (zeros)
//       16     . Country table (C entries, ISO-sorted):
//                  2 bytes ISO alpha-2 ASCII
//                  1 byte  name length N (≤64)
//                  N bytes UTF-8 country name
//        .     . Range table (R entries, sorted by start ascending):
//                  4 bytes start IPv4 (uint32 BE)
//                  2 bytes country index (uint16 LE)
//
// At runtime we decode the base64 once, build three typed-array slices
// (Uint32Array of starts, Uint16Array of country indices, two parallel
// JS string arrays for ISO codes and names), and binary-search for the
// largest `start ≤ ip` per query. End-IP is omitted because adjacent
// same-country runs were coalesced offline; the slot's country is
// correct for every IP up to the next slot's start.
//
// CSP-safe: pure ArrayBuffer + DataView + atob; no eval, no new Function,
// no fetch.
// ════════════════════════════════════════════════════════════════════════════

const BundledGeoip = (() => {
  // The base64 const is injected at the top of Block 1 by scripts/build.py.
  // If it's missing (e.g. unit tests loading this file without the build
  // wrapper), we degrade to a stub so callers still get the contract.
  const b64 = (typeof __GEOIP_BUNDLE_B64 === 'string') ? __GEOIP_BUNDLE_B64 : '';

  // Stub provider used when the bundle is missing — every lookup misses.
  // Production builds always have the const; this is a unit-test safety net.
  const STUB = {
    lookupIPv4: () => null,
    formatRow: () => '',
    getFieldName: () => 'geo',
    vintage: 'unavailable',
    providerKind: 'bundled',
    rangeCount: 0,
    countryCount: 0,
  };

  if (!b64) return STUB;

  let bytes;
  try {
    const bin = atob(b64);
    bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  } catch (_) {
    return STUB;
  }

  // ── Header / magic check ───────────────────────────────────────────────
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 16
      || bytes[0] !== 0x4C || bytes[1] !== 0x47
      || bytes[2] !== 0x45 || bytes[3] !== 0x4F) {
     
    console.warn('[bundled-geoip] bad magic; bundled DB unavailable');
    return STUB;
  }
  const version = dv.getUint16(4, true);
  if (version !== 1) {
     
    console.warn('[bundled-geoip] unsupported format version', version);
    return STUB;
  }
  const rangeCount = dv.getUint32(8, true);
  const countryCount = dv.getUint16(12, true);

  // ── Country table parse ────────────────────────────────────────────────
  // Walks `countryCount` (iso, length-prefixed-name) records starting at
  // offset 16. Returns the cursor offset for the range-table parse.
  const isos = new Array(countryCount);
  const names = new Array(countryCount);
  let cursor = 16;
  // Decode UTF-8 name bytes via TextDecoder when available, else fall
  // back to a tiny manual ASCII-only path (every name in the bundled
  // table is plain ASCII, so the fallback is lossless in practice).
  const td = (typeof TextDecoder !== 'undefined') ? new TextDecoder('utf-8') : null;
  for (let i = 0; i < countryCount; i++) {
    if (cursor + 3 > bytes.length) {
       
      console.warn('[bundled-geoip] truncated country table');
      return STUB;
    }
    const iso = String.fromCharCode(bytes[cursor], bytes[cursor + 1]);
    const nlen = bytes[cursor + 2];
    cursor += 3;
    if (cursor + nlen > bytes.length) {
       
      console.warn('[bundled-geoip] truncated country name');
      return STUB;
    }
    const slice = bytes.subarray(cursor, cursor + nlen);
    let name;
    if (td) {
      name = td.decode(slice);
    } else {
      // ASCII fallback — every name in the bundled table fits in 7-bit ASCII.
      let s = '';
      for (let k = 0; k < slice.length; k++) s += String.fromCharCode(slice[k]);
      name = s;
    }
    isos[i] = iso;
    names[i] = name;
    cursor += nlen;
  }

  // ── Range table parse ──────────────────────────────────────────────────
  // R × 6 bytes: 4-byte start (uint32 BE) + 2-byte country index (uint16 LE).
  // Stored in two parallel typed arrays so the lookup is cache-friendly.
  const expectedRangeBytes = rangeCount * 6;
  if (cursor + expectedRangeBytes > bytes.length) {
     
    console.warn('[bundled-geoip] truncated range table');
    return STUB;
  }
  const starts = new Uint32Array(rangeCount);
  const idxs = new Uint16Array(rangeCount);
  for (let i = 0; i < rangeCount; i++) {
    const off = cursor + i * 6;
    // BE uint32 read — `getUint32(off, false)` would also work but we
    // assemble manually to make endian intent explicit and survive any
    // hypothetical DataView quirk on exotic JS engines.
    starts[i] = (
      (bytes[off]     << 24) |
      (bytes[off + 1] << 16) |
      (bytes[off + 2] << 8)  |
       bytes[off + 3]
    ) >>> 0;
    idxs[i] = bytes[off + 4] | (bytes[off + 5] << 8);
  }

  // Sentinel for IANA reserved space — countries that should NOT appear in
  // the analyst's geo column. We resolve "Reserved" lookups to null so the
  // cell renders empty instead of the literal "Reserved" string. The bundle
  // includes the sentinel as ISO `--` per `scripts/fetch_geoip.py`.
  const RESERVED_IDX = (() => {
    for (let i = 0; i < countryCount; i++) if (isos[i] === '--') return i;
    return -1;
  })();

  // Build a publication-date label from the SHA-256 + range count for the
  // Settings dialog. The actual publish date is captured at refresh time
  // by `scripts/fetch_geoip.py`; we don't have it at runtime, so we display
  // the range count as a coarse vintage proxy. (The refresh PR title in
  // CI carries the actual date for users browsing git history.)
  const vintage = `RIR snapshot — ${rangeCount.toLocaleString()} ranges, ${countryCount} countries`;

  // ── IPv4 string → uint32 ──────────────────────────────────────────────
  // Strict dotted-quad only; no leading zeros, no whitespace. Returns
  // -1 on any parse failure. Hot path — keep allocation-free.
  function parseIPv4(s) {
    if (typeof s !== 'string') return -1;
    const len = s.length;
    if (len < 7 || len > 15) return -1;
    let n = 0;
    let octet = 0;
    let octetDigits = 0;
    let octetCount = 0;
    for (let i = 0; i < len; i++) {
      const c = s.charCodeAt(i);
      if (c >= 48 && c <= 57) {
        if (octetDigits === 0 && c === 48 && i + 1 < len && s.charCodeAt(i + 1) >= 48 && s.charCodeAt(i + 1) <= 57) {
          // Reject leading zeros (e.g. '01.2.3.4' — ambiguous octal-ish).
          return -1;
        }
        octet = octet * 10 + (c - 48);
        octetDigits++;
        if (octet > 255 || octetDigits > 3) return -1;
      } else if (c === 46) { // '.'
        if (octetDigits === 0) return -1;
        n = (n * 256) + octet;
        octet = 0;
        octetDigits = 0;
        octetCount++;
        if (octetCount > 3) return -1;
      } else {
        return -1;
      }
    }
    if (octetDigits === 0 || octetCount !== 3) return -1;
    n = (n * 256) + octet;
    return n >>> 0;
  }

  // ── Binary search: largest start ≤ ip ──────────────────────────────────
  // Standard lower-bound–style search. Returns the slot index, or -1 if
  // `ip` precedes the first range (extremely rare — implies a private
  // address before 1.0.0.0, which only 0.0.0.0 satisfies and we cover
  // that as IANA "this network").
  function findSlot(ip) {
    let lo = 0;
    let hi = rangeCount;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      if (starts[mid] <= ip) lo = mid + 1;
      else hi = mid;
    }
    return lo - 1;
  }

  // ── Public API ─────────────────────────────────────────────────────────
  return {
    /** @param {string} ipStr — dotted-quad IPv4. Returns null on miss / bad input.
     *  Reserved / private space resolves to null (the cell renders empty). */
    lookupIPv4(ipStr) {
      const ip = parseIPv4(ipStr);
      if (ip < 0) return null;
      const slot = findSlot(ip);
      if (slot < 0) return null;
      const ci = idxs[slot];
      if (ci === RESERVED_IDX) return null;
      return { country: names[ci], iso: isos[ci] };
    },

    /** Render a record into the single-column display string.
     *  Bundled provider only ever returns country + iso, so the format is
     *  always 'Country/ISO'. Trailing / internal empties are not possible
     *  for this provider but we still strip defensively for parity with
     *  the MMDB path. */
    formatRow(rec) {
      if (!rec) return '';
      const parts = [rec.country, rec.iso, rec.region, rec.city]
        .filter(p => p != null && p !== '');
      // Strip purely-internal empties: filter() already drops them. Trim
      // any accidental trailing slash that future provider extensions
      // might introduce.
      const out = parts.join('/');
      return out.endsWith('/') ? out.slice(0, -1) : out;
    },

    getFieldName() { return 'geo'; },

    get vintage() { return vintage; },
    get providerKind() { return 'bundled'; },
    get rangeCount() { return rangeCount; },
    get countryCount() { return countryCount; },
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  // Node test harness — let `tests/unit/*.test.js` import the const.
  module.exports = { BundledGeoip };
}
