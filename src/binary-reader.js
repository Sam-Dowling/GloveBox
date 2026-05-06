'use strict';
// ════════════════════════════════════════════════════════════════════════════
// binary-reader.js — pure endian-aware byte read helpers.
//
// Extracted from the duplicated `_u8` / `_u16` / `_u32` / `_u64` / `_str` /
// `_hex` / `_entropy` / `_esc` blocks at the top of every native-binary
// renderer (`pe-renderer.js`, `elf-renderer.js`, `macho-renderer.js`). All
// three previously carried near-identical copies of these helpers, with
// minor drift (PE rounded entropy to 3 decimals; ELF / Mach-O did not;
// PE was hardcoded LE while ELF / Mach-O branched on `this._le`).
//
// The helper exposes both endian explicitly (no implicit `this._le`) so
// per-renderer wrappers can pick the right variant once and stay tiny:
//
//     _u16(bytes, off) {
//       return this._le ? BinaryReader.u16le(bytes, off) : BinaryReader.u16be(bytes, off);
//     }
//
// Pure: no DOM, no app state, no allocations beyond the local frequency
// array in `entropy()`. Loaded once at the top of the bundle and shared
// by every consumer.
// ════════════════════════════════════════════════════════════════════════════
const BinaryReader = Object.freeze({

  // ── 1-byte ────────────────────────────────────────────────────────────────
  u8(bytes, off) { return bytes[off]; },

  // ── 2-byte (16-bit) ───────────────────────────────────────────────────────
  u16le(bytes, off) {
    return bytes[off] | (bytes[off + 1] << 8);
  },
  u16be(bytes, off) {
    return (bytes[off] << 8) | bytes[off + 1];
  },

  // ── 4-byte (32-bit, unsigned) ─────────────────────────────────────────────
  u32le(bytes, off) {
    return (bytes[off]
          | (bytes[off + 1] << 8)
          | (bytes[off + 2] << 16)
          | (bytes[off + 3] << 24)) >>> 0;
  },
  u32be(bytes, off) {
    return ((bytes[off] << 24)
          | (bytes[off + 1] << 16)
          | (bytes[off + 2] << 8)
          |  bytes[off + 3]) >>> 0;
  },

  // ── 8-byte (64-bit, returns Number — safe up to 2^53) ─────────────────────
  // The `as Number` precision loss is intentional and matches every
  // upstream caller (PE / ELF / Mach-O all returned a Number). When the
  // high 11 bits matter, the caller already had to pull the BigInt
  // form themselves; this helper preserves the historical behaviour.
  u64le(bytes, off) {
    const lo = BinaryReader.u32le(bytes, off);
    const hi = BinaryReader.u32le(bytes, off + 4);
    return hi * 0x100000000 + lo;
  },
  u64be(bytes, off) {
    const hi = BinaryReader.u32be(bytes, off);
    const lo = BinaryReader.u32be(bytes, off + 4);
    return hi * 0x100000000 + lo;
  },

  // ── Null-terminated C-string with bounded scan ────────────────────────────
  // Reads up to `maxLen` ASCII chars from `bytes` starting at `off`,
  // stopping at the first 0 byte. Mirrors the historical
  // `_str(bytes, off, maxLen)` shape used by every binary renderer.
  cstring(bytes, off, maxLen) {
    let s = '';
    for (let i = 0; i < maxLen && off + i < bytes.length; i++) {
      if (bytes[off + i] === 0) break;
      s += String.fromCharCode(bytes[off + i]);
    }
    return s;
  },

  // ── Hex formatter `0x...` with zero-padding ───────────────────────────────
  hex(v, digits) {
    if (typeof v !== 'number') return '0x0';
    return '0x' + v.toString(16).toUpperCase().padStart(digits || 0, '0');
  },

  // ── Shannon entropy over a byte slice ─────────────────────────────────────
  // Returns entropy ∈ [0..8]. `round` controls precision: omit / 0 for
  // raw float (Mach-O / ELF default), `1000` for 3-decimal-place rounding
  // (PE renderer's historical default).
  entropy(bytes, off, len, round) {
    if (!len || len <= 0 || off + len > bytes.length) return 0;
    const freq = new Uint32Array(256);
    const end = Math.min(off + len, bytes.length);
    const actual = end - off;
    for (let i = off; i < end; i++) freq[bytes[i]]++;
    let ent = 0;
    for (let i = 0; i < 256; i++) {
      if (freq[i] === 0) continue;
      const p = freq[i] / actual;
      ent -= p * Math.log2(p);
    }
    return round ? Math.round(ent * round) / round : ent;
  },

  // ── HTML escape for binary-renderer UI ────────────────────────────────────
  esc(s) {
    return (s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  },
});
