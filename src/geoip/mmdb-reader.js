'use strict';
// ════════════════════════════════════════════════════════════════════════════
// mmdb-reader.js — minimal MaxMind DB (MMDB) format reader for the
// Timeline GeoIP enrichment override path.
//
// This is a hand-rolled, audit-friendly implementation of the subset of
// the MMDB spec that Loupe needs. Spec reference:
//   https://maxmind.github.io/MaxMind-DB/
//
// The full MaxMind reader (`mmdb-lib` / `node-maxmind`) supports every
// type, IPv6, prefix-length tuples, and a multi-MB query cache. Loupe
// needs none of that — only:
//   • Parse the metadata block (`\xab\xcd\xefMaxMind.com` sentinel +
//     a single decoded map containing record_size, node_count,
//     ip_version, database_type, build_epoch).
//   • Walk the binary search tree for IPv4 lookups (32-bit walk; for
//     IPv6 databases we descend through the IPv4-in-IPv6 prefix the
//     same way every other reader does).
//   • Decode pointer / map / utf8 string / uint16 / uint32 / uint64 /
//     array control bytes. Other types (bytes, doubles, signed ints,
//     containers) are recognised but skipped — we never read them
//     because the only fields we care about are utf-8 strings and
//     uint32s.
//
// Provider contract — mirrored by `bundled-geoip.js`:
//
//   provider.lookupIPv4(ipStr) → { country, iso, region?, city? } | null
//   provider.formatRow(rec)    → 'United States/US/Louisiana/New Orleans'
//   provider.getFieldName()    → 'geo'
//   provider.vintage           → 'GeoLite2-City built 2026-04-01'
//   provider.providerKind      → 'mmdb'
//
// The reader supports `.mmdb` and `.mmdb.gz` blobs. Gzip is detected by
// the 1f 8b magic, not by extension, so renamed files still work. The
// decompression path goes through `Decompressor` (native
// DecompressionStream with pako fallback) — same surface every other
// renderer uses.
//
// Bounded inputs: the reader caps the input blob at 256 MB before
// gunzip and rejects the file if any tree walk attempts to follow more
// than 256 hops (way more than the 32 needed for IPv4). Both bounds
// throw `MmdbInvalidError` so the Settings dialog can display a clean
// message instead of leaking a stack trace.
//
// CSP-safe: pure ArrayBuffer + DataView + UTF-8 decode. No fetch, no
// eval, no `URL.createObjectURL` (the Blob is passed in by Settings).
// ════════════════════════════════════════════════════════════════════════════

class MmdbInvalidError extends Error {
  constructor(msg) { super(msg); this.name = 'MmdbInvalidError'; }
}

// Maximum accepted MMDB blob size, after gunzip. GeoLite2-City is ~70 MB
// uncompressed; the cap leaves comfortable headroom for paid City+ISP
// joins without admitting absurd inputs.
const MMDB_MAX_SIZE = 256 * 1024 * 1024;

// Maximum hops in a single binary-search-tree walk. IPv4 in an IPv6
// tree is at most 128 hops; the cap protects against malformed
// databases that loop a node back onto itself.
const MMDB_MAX_TREE_DEPTH = 256;

// MaxMind metadata sentinel — appears once, near the end of the file.
const MMDB_METADATA_MARKER = new Uint8Array([
  0xAB, 0xCD, 0xEF, 0x4D, 0x61, 0x78, 0x4D, 0x69, 0x6E, 0x64, 0x2E, 0x63, 0x6F, 0x6D
]); // \xab\xcd\xef + "MaxMind.com"

// Find the LAST occurrence of `needle` in `hay`. The MMDB spec mandates
// the metadata sentinel appear at most 128 KB before EOF; we search the
// trailing 128 KB only to keep this O(64KB) regardless of file size.
function _findMetadataMarker(bytes) {
  const tailStart = Math.max(0, bytes.length - 128 * 1024);
  const needle = MMDB_METADATA_MARKER;
  // Scan backwards so the FIRST hit we see in reverse order is the
  // last hit forwards (which is what the spec wants — a metadata-like
  // bytestring earlier in the file shouldn't fool us).
  for (let i = bytes.length - needle.length; i >= tailStart; i--) {
    let match = true;
    for (let j = 0; j < needle.length; j++) {
      if (bytes[i + j] !== needle[j]) { match = false; break; }
    }
    if (match) return i;
  }
  return -1;
}

// ── MMDB type tags (control-byte high nibble or "extended" base + 7) ────
// Values come straight from the spec; only the ones we actually
// dispatch on are commented in the decoder. The rest exist to make
// switch coverage explicit.
const MMDB_TYPE_EXTENDED   = 0;
const MMDB_TYPE_POINTER    = 1;
const MMDB_TYPE_UTF8       = 2;
const MMDB_TYPE_DOUBLE     = 3;
const MMDB_TYPE_BYTES      = 4;
const MMDB_TYPE_UINT16     = 5;
const MMDB_TYPE_UINT32     = 6;
const MMDB_TYPE_MAP        = 7;
const MMDB_TYPE_INT32      = 8;
const MMDB_TYPE_UINT64     = 9;
const MMDB_TYPE_UINT128    = 10;
const MMDB_TYPE_ARRAY      = 11;
const MMDB_TYPE_CONTAINER  = 12;
const MMDB_TYPE_END_MARKER = 13;
const MMDB_TYPE_BOOLEAN    = 14;
const MMDB_TYPE_FLOAT      = 15;

// ── Decoder ────────────────────────────────────────────────────────────
// One instance per loaded MMDB. The `dataSectionStart` offset is the
// byte position where the data section begins — every pointer in a
// decoded value is RELATIVE to this position, not absolute.

class MmdbDecoder {
  constructor(bytes, dataSectionStart) {
    this._b = bytes;
    this._dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this._dataStart = dataSectionStart;
    this._td = (typeof TextDecoder !== 'undefined') ? new TextDecoder('utf-8') : null;
  }

  /** Decode the value at absolute byte offset `off`. Returns
   *  { value, next } where `next` is the byte position immediately
   *  after the consumed control byte + payload (NOT after a pointer's
   *  destination — pointers are followed but the cursor stays put). */
  decode(off, depth) {
    if (depth > 64) throw new MmdbInvalidError('decode depth limit exceeded');
    const ctrl = this._b[off];
    if (ctrl === undefined) throw new MmdbInvalidError('decode past EOF');
    let typ = ctrl >> 5;
    let payloadLen = ctrl & 0x1F;
    let cursor = off + 1;
    if (typ === MMDB_TYPE_EXTENDED) {
      // Extended type: the next byte's value + 7 gives the real type.
      const ext = this._b[cursor];
      if (ext === undefined) throw new MmdbInvalidError('extended type past EOF');
      typ = ext + 7;
      cursor += 1;
    }
    // Pointers have a special length encoding (see spec §"Pointer").
    if (typ === MMDB_TYPE_POINTER) {
      const ptrSize = ((ctrl >> 3) & 0x03) + 1;  // 1..4 bytes of pointer payload
      let ptr;
      if (ptrSize === 1) {
        ptr = ((ctrl & 0x07) << 8) | this._b[cursor];
      } else if (ptrSize === 2) {
        ptr = ((ctrl & 0x07) << 16)
            | (this._b[cursor] << 8)
            | this._b[cursor + 1];
        ptr += 2048;
      } else if (ptrSize === 3) {
        ptr = ((ctrl & 0x07) << 24)
            | (this._b[cursor] << 16)
            | (this._b[cursor + 1] << 8)
            | this._b[cursor + 2];
        ptr += 526336;
      } else {
        // 4-byte pointer payload — value is read as plain BE uint32, no
        // implicit "+ x" added. JS bitwise ops are 32-bit signed; use
        // multiplication to avoid sign extension on the high bit.
        ptr = (this._b[cursor] * 0x1000000)
            + (this._b[cursor + 1] << 16)
            + (this._b[cursor + 2] << 8)
            +  this._b[cursor + 3];
      }
      cursor += ptrSize;
      // Pointer destination is RELATIVE to data-section start.
      const target = this._dataStart + ptr;
      const { value } = this.decode(target, depth + 1);
      return { value, next: cursor };
    }
    // Length encoding for non-pointer types (spec §"Reading the Payload Size").
    if (payloadLen >= 29) {
      if (payloadLen === 29) {
        payloadLen = 29 + this._b[cursor];
        cursor += 1;
      } else if (payloadLen === 30) {
        payloadLen = 285
                   + (this._b[cursor] << 8)
                   +  this._b[cursor + 1];
        cursor += 2;
      } else { // 31
        payloadLen = 65821
                   + (this._b[cursor] * 0x10000)
                   + (this._b[cursor + 1] << 8)
                   +  this._b[cursor + 2];
        cursor += 3;
      }
    }
    // ── Per-type body decode ─────────────────────────────────────────
    switch (typ) {
      case MMDB_TYPE_UTF8: {
        const slice = this._b.subarray(cursor, cursor + payloadLen);
        let s;
        if (this._td) s = this._td.decode(slice);
        else { s = ''; for (let i = 0; i < slice.length; i++) s += String.fromCharCode(slice[i]); }
        return { value: s, next: cursor + payloadLen };
      }
      case MMDB_TYPE_UINT16:
      case MMDB_TYPE_UINT32: {
        let v = 0;
        for (let i = 0; i < payloadLen; i++) v = (v * 256) + this._b[cursor + i];
        return { value: v >>> 0, next: cursor + payloadLen };
      }
      case MMDB_TYPE_UINT64:
      case MMDB_TYPE_UINT128: {
        // Loupe doesn't read these for any required field (build_epoch is
        // a uint64 but JS Number is enough for the Unix-seconds value
        // through year ~285,000 AD). Decode best-effort to a Number.
        let v = 0;
        for (let i = 0; i < payloadLen; i++) v = (v * 256) + this._b[cursor + i];
        return { value: v, next: cursor + payloadLen };
      }
      case MMDB_TYPE_INT32: {
        // Sign-extend payloadLen bytes (≤4).
        let v = 0;
        for (let i = 0; i < payloadLen; i++) v = (v * 256) + this._b[cursor + i];
        if (payloadLen > 0 && (this._b[cursor] & 0x80)) {
          v -= Math.pow(256, payloadLen);
        }
        return { value: v, next: cursor + payloadLen };
      }
      case MMDB_TYPE_DOUBLE: {
        const v = this._dv.getFloat64(cursor, false);
        return { value: v, next: cursor + payloadLen };
      }
      case MMDB_TYPE_FLOAT: {
        const v = this._dv.getFloat32(cursor, false);
        return { value: v, next: cursor + payloadLen };
      }
      case MMDB_TYPE_BOOLEAN: {
        return { value: payloadLen !== 0, next: cursor };
      }
      case MMDB_TYPE_BYTES: {
        return {
          value: this._b.subarray(cursor, cursor + payloadLen),
          next: cursor + payloadLen,
        };
      }
      case MMDB_TYPE_MAP: {
        const obj = {};
        let p = cursor;
        for (let i = 0; i < payloadLen; i++) {
          const k = this.decode(p, depth + 1);
          // Map keys are required by the spec to be utf-8 strings (or
          // pointers to utf-8 strings). `decode` follows pointers, so
          // `k.value` is already a string.
          if (typeof k.value !== 'string') {
            throw new MmdbInvalidError('non-string map key');
          }
          p = k.next;
          const v = this.decode(p, depth + 1);
          p = v.next;
          obj[k.value] = v.value;
        }
        return { value: obj, next: p };
      }
      case MMDB_TYPE_ARRAY: {
        const arr = new Array(payloadLen);
        let p = cursor;
        for (let i = 0; i < payloadLen; i++) {
          const v = this.decode(p, depth + 1);
          arr[i] = v.value;
          p = v.next;
        }
        return { value: arr, next: p };
      }
      case MMDB_TYPE_END_MARKER:
      case MMDB_TYPE_CONTAINER:
        // Should never appear in a well-formed data section we care about.
        return { value: null, next: cursor };
      default:
        throw new MmdbInvalidError('unknown mmdb type: ' + typ);
    }
  }
}

// ── Reader ─────────────────────────────────────────────────────────────
// One instance per uploaded MMDB. Holds the raw bytes (typically tens
// of MB), the parsed metadata, the data-section offset, and the search
// tree's record geometry.

class MmdbReader {
  /** Construct from a Blob (typically straight from the Settings file
   *  picker). Auto-detects gzip via 1f 8b magic and routes through the
   *  shared `Decompressor` so the same DecompressionStream / pako
   *  fallback used by every renderer applies here too. */
  static async fromBlob(blob) {
    if (!blob || typeof blob.arrayBuffer !== 'function') {
      throw new MmdbInvalidError('not a Blob');
    }
    let buf = await blob.arrayBuffer();
    if (buf.byteLength === 0) throw new MmdbInvalidError('empty file');
    if (buf.byteLength > MMDB_MAX_SIZE) {
      throw new MmdbInvalidError(`file too large (>${MMDB_MAX_SIZE} bytes)`);
    }
    let bytes = new Uint8Array(buf);
    // Gzip magic 1f 8b → gunzip via shared Decompressor.
    if (bytes.length >= 2 && bytes[0] === 0x1F && bytes[1] === 0x8B) {
      if (typeof Decompressor === 'undefined' || !Decompressor.tryDecompress) {
        throw new MmdbInvalidError('gzip detected but Decompressor unavailable');
      }
      const r = await Decompressor.tryDecompress(bytes, 0, 'gzip');
      if (!r.success || !r.data) throw new MmdbInvalidError('gunzip failed');
      bytes = r.data;
      if (bytes.length > MMDB_MAX_SIZE) {
        throw new MmdbInvalidError(`gunzipped DB too large (>${MMDB_MAX_SIZE} bytes)`);
      }
    }
    return new MmdbReader(bytes);
  }

  constructor(bytes) {
    this._b = bytes;
    this._parseMetadata();
  }

  _parseMetadata() {
    const markerOff = _findMetadataMarker(this._b);
    if (markerOff < 0) throw new MmdbInvalidError('not an MMDB (no metadata marker)');
    const metaStart = markerOff + MMDB_METADATA_MARKER.length;
    // The metadata is itself a fully-decoded value (a map) starting
    // immediately after the marker. Per spec, pointers in the metadata
    // section are RELATIVE to the metadata start.
    const tmpDecoder = new MmdbDecoder(this._b, metaStart);
    const { value: meta } = tmpDecoder.decode(metaStart, 0);
    if (!meta || typeof meta !== 'object') {
      throw new MmdbInvalidError('metadata not a map');
    }
    this._meta = meta;
    const recordSize = meta.record_size | 0;
    const nodeCount = meta.node_count | 0;
    const ipVersion = meta.ip_version | 0;
    if (![24, 28, 32].includes(recordSize)) {
      throw new MmdbInvalidError(`unsupported record_size: ${recordSize}`);
    }
    if (nodeCount <= 0 || nodeCount > 100_000_000) {
      throw new MmdbInvalidError(`bad node_count: ${nodeCount}`);
    }
    if (ipVersion !== 4 && ipVersion !== 6) {
      throw new MmdbInvalidError(`bad ip_version: ${ipVersion}`);
    }
    this._recordSize = recordSize;
    this._nodeByteSize = (recordSize * 2) / 8;  // 6 / 7 / 8 bytes per node
    this._nodeCount = nodeCount;
    this._ipVersion = ipVersion;
    // Search-tree size in bytes; data section starts 16 bytes after.
    this._treeSize = nodeCount * this._nodeByteSize;
    this._dataStart = this._treeSize + 16;
    if (this._dataStart >= markerOff) {
      throw new MmdbInvalidError('data section overlaps metadata');
    }
    this._decoder = new MmdbDecoder(this._b, this._dataStart);
    this._dbType = String(meta.database_type || 'unknown');
    this._buildEpoch = Number(meta.build_epoch) || 0;
    // For IPv6 databases the IPv4 subtree begins after walking the
    // first 96 zero bits (IPv4-in-IPv6 prefix). Resolve once at
    // construction so per-row lookups skip that walk.
    this._ipv4Start = (ipVersion === 4) ? 0 : this._findIpv4Start();
  }

  _findIpv4Start() {
    let node = 0;
    for (let i = 0; i < 96 && node < this._nodeCount; i++) {
      node = this._readLeftRecord(node);
    }
    return node;
  }

  /** Read the LEFT record value of `nodeIdx`. Reused for the v4-start
   *  walk where every step descends through the 0-bit branch. */
  _readLeftRecord(nodeIdx) {
    const off = nodeIdx * this._nodeByteSize;
    const b = this._b;
    if (this._recordSize === 24) {
      return (b[off] << 16) | (b[off + 1] << 8) | b[off + 2];
    }
    if (this._recordSize === 28) {
      // 28-bit records: low 4 bits of the middle byte belong to LEFT.
      const high = (b[off + 3] >> 4) & 0x0F;
      return (high << 24) | (b[off] << 16) | (b[off + 1] << 8) | b[off + 2];
    }
    // 32-bit
    return (b[off] * 0x1000000) + (b[off + 1] << 16) + (b[off + 2] << 8) + b[off + 3];
  }

  /** Read the RIGHT record value of `nodeIdx`. */
  _readRightRecord(nodeIdx) {
    const off = nodeIdx * this._nodeByteSize;
    const b = this._b;
    if (this._recordSize === 24) {
      return (b[off + 3] << 16) | (b[off + 4] << 8) | b[off + 5];
    }
    if (this._recordSize === 28) {
      const high = b[off + 3] & 0x0F;
      return (high << 24) | (b[off + 4] << 16) | (b[off + 5] << 8) | b[off + 6];
    }
    // 32-bit
    return (b[off + 4] * 0x1000000) + (b[off + 5] << 16) + (b[off + 6] << 8) + b[off + 7];
  }

  /** Walk the tree for a 32-bit IPv4 address. Returns the data-section
   *  pointer (already adjusted to a real byte offset), or -1 on miss. */
  _findIpv4(ip) {
    let node = this._ipv4Start;
    if (node >= this._nodeCount) {
      // The v4 subtree is itself a leaf — the database has no
      // IPv4 data; treat as miss.
      if (node === this._nodeCount) return -1;
      return this._dataStart + (node - this._nodeCount);
    }
    for (let i = 0; i < 32; i++) {
      // Walk MSB-first across the 32-bit IP. `bit` is 0 (left) or 1 (right).
      const bit = (ip >>> (31 - i)) & 1;
      node = bit ? this._readRightRecord(node) : this._readLeftRecord(node);
      if (node === this._nodeCount) return -1;          // explicit "no data"
      if (node > this._nodeCount) {
        // Data section pointer: `(node - nodeCount) - 16` bytes into the
        // data section. The "-16" comes from the 16-byte separator
        // between the tree and the data section.
        return this._dataStart + (node - this._nodeCount) - 16;
      }
      if (i >= MMDB_MAX_TREE_DEPTH) {
        throw new MmdbInvalidError('tree depth exceeded');
      }
    }
    return -1;
  }

  // ── Public API ────────────────────────────────────────────────────────

  /** IPv4-only lookup. Returns null on miss / bad input.
   *  Result shape: { country, iso, region?, city? }. */
  lookupIPv4(ipStr) {
    const ip = _parseIPv4(ipStr);
    if (ip < 0) return null;
    let dataOff;
    try { dataOff = this._findIpv4(ip); }
    catch (_) { return null; }
    if (dataOff < 0) return null;
    let data;
    try { data = this._decoder.decode(dataOff, 0).value; }
    catch (_) { return null; }
    if (!data || typeof data !== 'object') return null;
    return _projectGeoFields(data);
  }

  formatRow(rec) {
    if (!rec) return '';
    // Ordered: country, iso, region, city. Drop empties, including
    // internal ones — your existing pipeline-format strips them too.
    const parts = [rec.country, rec.iso, rec.region, rec.city]
      .filter(p => p != null && p !== '');
    const out = parts.join('/');
    return out.endsWith('/') ? out.slice(0, -1) : out;
  }

  getFieldName() { return 'geo'; }

  get vintage() {
    if (this._buildEpoch > 0) {
      const d = new Date(this._buildEpoch * 1000);
      const y = d.getUTCFullYear();
      const m = String(d.getUTCMonth() + 1).padStart(2, '0');
      const day = String(d.getUTCDate()).padStart(2, '0');
      return `${this._dbType} built ${y}-${m}-${day}`;
    }
    return this._dbType;
  }

  get providerKind() { return 'mmdb'; }
  get databaseType() { return this._dbType; }
  get buildEpoch() { return this._buildEpoch; }
  get nodeCount() { return this._nodeCount; }
  get ipVersion() { return this._ipVersion; }
}

// ── Shared helpers ───────────────────────────────────────────────────────

/** Strict dotted-quad IPv4 parse → uint32 (or -1). Hot-path; allocation-free. */
function _parseIPv4(s) {
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
        return -1;
      }
      octet = octet * 10 + (c - 48);
      octetDigits++;
      if (octet > 255 || octetDigits > 3) return -1;
    } else if (c === 46) {
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

/** Project a decoded MMDB record map into Loupe's uniform shape.
 *  Looks at the standard GeoLite2 / GeoIP2 paths:
 *    country.names.en, country.iso_code,
 *    subdivisions[0].names.en, city.names.en
 *  and the legacy "registered_country" fallback when no country block
 *  is present. */
function _projectGeoFields(data) {
  let countryName = null, iso = null, region = null, city = null;
  if (data.country && typeof data.country === 'object') {
    if (data.country.names && typeof data.country.names === 'object') {
      countryName = _firstString(data.country.names.en, data.country.names);
    }
    if (typeof data.country.iso_code === 'string') iso = data.country.iso_code;
  }
  if ((!countryName || !iso) && data.registered_country && typeof data.registered_country === 'object') {
    if (!countryName && data.registered_country.names) {
      countryName = _firstString(data.registered_country.names.en, data.registered_country.names);
    }
    if (!iso && typeof data.registered_country.iso_code === 'string') {
      iso = data.registered_country.iso_code;
    }
  }
  if (Array.isArray(data.subdivisions) && data.subdivisions.length > 0) {
    const sd = data.subdivisions[0];
    if (sd && sd.names && typeof sd.names === 'object') {
      region = _firstString(sd.names.en, sd.names);
    }
  }
  if (data.city && data.city.names && typeof data.city.names === 'object') {
    city = _firstString(data.city.names.en, data.city.names);
  }
  if (!countryName && !iso) return null;
  return { country: countryName || '', iso: iso || '', region: region || '', city: city || '' };
}

function _firstString(preferred, fallback) {
  if (typeof preferred === 'string' && preferred.length > 0) return preferred;
  if (fallback && typeof fallback === 'object') {
    for (const k of Object.keys(fallback)) {
      const v = fallback[k];
      if (typeof v === 'string' && v.length > 0) return v;
    }
  }
  return null;
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { MmdbReader, MmdbInvalidError };
}
