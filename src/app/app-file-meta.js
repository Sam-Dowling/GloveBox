// ════════════════════════════════════════════════════════════════════════════
// app-file-meta.js — pure file-metadata helpers extracted from app-load.js.
//
// Pure / near-pure helpers that don't depend on App lifecycle state but were
// historically kept inside the giant `app-load.js` mixin.  Extracted here so
// `app-load.js` can shrink toward orchestration only.  Behaviour is bit-for-
// bit identical to the prior in-file definitions; this file only moves them.
//
// Provides:
//   • `_md5(bytes)` — top-level pure function (crypto.subtle has no MD5).
//   • `_hashFile(buffer)` — App method, returns `{md5, sha1, sha256}`.
//   • `_detectMagic(bytes)` — App method, returns `{hex, label}`.
//   • `_looksLikePgp(bytes)` — App method, OpenPGP key/armor sniff.
//   • `_computeEntropy(bytes)` — App method, Shannon entropy ∈ [0..8].
//
// Load order: AFTER `src/app/app-core.js` (defines `extendApp`) and BEFORE
// `src/app/app-load.js` (consumes these methods on `this`).
// ════════════════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════════════
// _md5  — compact pure-JS MD5 (crypto.subtle doesn't support MD5)
// ════════════════════════════════════════════════════════════════════════════
function _md5(bytes) {
  function add(x, y) { const l = (x & 0xFFFF) + (y & 0xFFFF); return (((x >> 16) + (y >> 16) + (l >> 16)) << 16) | (l & 0xFFFF); }
  function rol(x, n) { return (x << n) | (x >>> (32 - n)); }
  const T = []; for (let i = 1; i <= 64; i++)T[i] = Math.floor(Math.abs(Math.sin(i)) * 0x100000000) >>> 0;
  const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const n = bytes.length, pad = new Uint8Array((n + 72) & ~63);
  pad.set(bytes); pad[n] = 0x80;
  const dv = new DataView(pad.buffer);
  dv.setUint32(pad.length - 8, n << 3, true); dv.setUint32(pad.length - 4, n >>> 29, true);
  let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
  for (let o = 0; o < pad.length; o += 64) {
    const W = []; for (let i = 0; i < 16; i++)W[i] = dv.getUint32(o + i * 4, true);
    let A = a, B = b, C = c, D = d;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = 7 * i % 16; }
      F = add(add(add(F, A), W[g]), T[i + 1]);
      A = D; D = C; C = B; B = add(B, rol(F, S[i]));
    }
    a = add(a, A); b = add(b, B); c = add(c, C); d = add(d, D);
  }
  return [a, b, c, d].map(v => [v & 255, v >> 8 & 255, v >> 16 & 255, v >> 24 & 255].map(x => x.toString(16).padStart(2, '0')).join('')).join('');
}

extendApp({

  // ── Hashing ─────────────────────────────────────────────────────────────
  async _hashFile(buffer) {
    const data = buffer instanceof ArrayBuffer ? buffer : buffer.buffer;
    try {
      const [s1, s256] = await Promise.all([
        crypto.subtle.digest('SHA-1', data),
        crypto.subtle.digest('SHA-256', data)
      ]);
      const hex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
      return { md5: _md5(new Uint8Array(data)), sha1: hex(s1), sha256: hex(s256) };
    } catch (e) { return { md5: '—', sha1: '—', sha256: '—' }; }
  },

  // ── File magic detection ────────────────────────────────────────────────
  _detectMagic(bytes) {
    if (bytes.length < 4) return { hex: '', label: 'Unknown' };
    const h = n => Array.from(bytes.subarray(0, n)).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
    // Check common signatures
    if (bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04)
      return { hex: h(4), label: 'ZIP / OOXML (PK)' };
    if (bytes[0] === 0xD0 && bytes[1] === 0xCF && bytes[2] === 0x11 && bytes[3] === 0xE0)
      return { hex: h(4), label: 'OLE/CFB Compound File' };
    if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46)
      return { hex: h(4), label: 'PDF Document' };
    if (bytes[0] === 0x4D && bytes[1] === 0x5A)
      return { hex: h(2), label: 'PE Executable (MZ)' };
    if (bytes[0] === 0x7F && bytes[1] === 0x45 && bytes[2] === 0x4C && bytes[3] === 0x46)
      return { hex: h(4), label: 'ELF Binary' };
    if (bytes[0] === 0xCF && bytes[1] === 0xFA && bytes[2] === 0xED && bytes[3] === 0xFE)
      return { hex: h(4), label: 'Mach-O Binary (64-bit)' };
    if (bytes[0] === 0xCE && bytes[1] === 0xFA && bytes[2] === 0xED && bytes[3] === 0xFE)
      return { hex: h(4), label: 'Mach-O Binary (32-bit)' };
    if (bytes[0] === 0xCA && bytes[1] === 0xFE && bytes[2] === 0xBA && bytes[3] === 0xBE) {
      if (typeof JarRenderer !== 'undefined' && JarRenderer.isJavaClass(bytes))
        return { hex: h(4), label: 'Java Class File' };
      return { hex: h(4), label: 'Mach-O Fat/Universal Binary' };
    }
    if (bytes[0] === 0x52 && bytes[1] === 0x61 && bytes[2] === 0x72)
      return { hex: h(3), label: 'RAR Archive' };
    if (bytes[0] === 0x37 && bytes[1] === 0x7A && bytes[2] === 0xBC && bytes[3] === 0xAF)
      return { hex: h(4), label: '7-Zip Archive' };
    if (bytes[0] === 0x4C && bytes[1] === 0x00 && bytes[2] === 0x00 && bytes[3] === 0x00)
      return { hex: h(4), label: 'Windows Shortcut (LNK)' };
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47)
      return { hex: h(4), label: 'PNG Image' };
    if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF)
      return { hex: h(3), label: 'JPEG Image' };
    if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46)
      return { hex: h(3), label: 'GIF Image' };
    // Text-based detection
    const head = String.fromCharCode(...bytes.subarray(0, Math.min(20, bytes.length)));
    if (head.startsWith('{\\rtf')) return { hex: h(5), label: 'Rich Text Format (RTF)' };
    if (head.startsWith('<!DOCTYPE') || head.startsWith('<html') || head.startsWith('<HTML'))
      return { hex: h(6), label: 'HTML Document' };
    if (head.startsWith('<HTA:') || head.includes('<HTA:'))
      return { hex: h(6), label: 'HTML Application (HTA)' };
    if (head.startsWith('<?xml') || head.startsWith('<xml'))
      return { hex: h(5), label: 'XML Document' };
    if (head.startsWith('[InternetShortcut]'))
      return { hex: h(8), label: 'Internet Shortcut (.url)' };
    // Registry files: REGEDIT4 or "Windows Registry Editor Version 5.00" (may have UTF-16LE BOM FF FE)
    if (head.startsWith('REGEDIT4') || head.startsWith('Windows Registry'))
      return { hex: h(8), label: 'Windows Registry File (.reg)' };
    if (bytes.length >= 4 && bytes[0] === 0xFF && bytes[1] === 0xFE) {
      const u16 = new TextDecoder('utf-16le', { fatal: false }).decode(bytes.subarray(0, Math.min(80, bytes.length)));
      if (u16.startsWith('Windows Registry'))
        return { hex: 'FF FE', label: 'Windows Registry File (.reg, UTF-16LE)' };
    }
    // INF: Setup Information files start with [Version] section
    if (head.startsWith('[Version]') || head.startsWith('[version]'))
      return { hex: h(9), label: 'Setup Information File (.inf)' };
    if (head.startsWith('From ') || head.startsWith('Received:') || head.startsWith('MIME-Version'))
      return { hex: h(6), label: 'Email Message (RFC 5322)' };
    // EVTX: "ElfFile\0"
    if (bytes[0] === 0x45 && bytes[1] === 0x6C && bytes[2] === 0x66 && bytes[3] === 0x46 &&
      bytes[4] === 0x69 && bytes[5] === 0x6C && bytes[6] === 0x65 && bytes[7] === 0x00)
      return { hex: h(8), label: 'Windows Event Log (EVTX)' };
    // SQLite: "SQLite format 3\000"
    if (bytes[0] === 0x53 && bytes[1] === 0x51 && bytes[2] === 0x4C && bytes[3] === 0x69 &&
      bytes[4] === 0x74 && bytes[5] === 0x65 && bytes[6] === 0x20)
      return { hex: h(6), label: 'SQLite Database' };
    if (bytes.length > 32768 + 5) {
      const iso = String.fromCharCode(bytes[32769], bytes[32770], bytes[32771], bytes[32772], bytes[32773]);
      if (iso === 'CD001') return { hex: 'CD001', label: 'ISO 9660 Disk Image' };
    }
    // OneNote magic
    if (bytes.length >= 16 && bytes[0] === 0xE4 && bytes[1] === 0x52 && bytes[2] === 0x5C && bytes[3] === 0x7B)
      return { hex: h(4), label: 'OneNote Document' };
    // Binary plist: "bplist"
    if (bytes.length >= 8 && bytes[0] === 0x62 && bytes[1] === 0x70 && bytes[2] === 0x6C &&
      bytes[3] === 0x69 && bytes[4] === 0x73 && bytes[5] === 0x74)
      return { hex: h(8), label: 'Binary Property List (bplist)' };
    // OpenPGP ASCII armor (text-based: -----BEGIN PGP ...)
    if (head.startsWith('-----BEGIN PGP'))
      return { hex: h(14), label: 'OpenPGP ASCII-Armored Data' };
    // PEM certificate (text-based: -----BEGIN ...)
    if (head.startsWith('-----BEGIN '))
      return { hex: h(11), label: 'PEM Encoded Data' };
    // OpenPGP binary packet stream: Public-Key (0x99 / 0xC6), Secret-Key (0x95 / 0xC5),
    // Public-Subkey (0xB9 / 0xCE), Secret-Subkey (0x9D / 0xC7) — followed by a version
    // byte in {3,4,5,6}. Check tight byte patterns to avoid false positives.
    if (bytes.length >= 3 &&
      [0x99, 0x95, 0xB9, 0x9D, 0xC6, 0xC5, 0xCE, 0xC7].includes(bytes[0])) {
      // For old-format packets (0x9X / 0xBX) the version byte is at offset 3 (after 2-byte length);
      // for new-format (0xCX) it follows the length byte(s). We accept either if we see a plausible version in the first 8 bytes.
      const scan = bytes.subarray(0, Math.min(8, bytes.length));
      if ([3, 4, 5, 6].some(v => Array.from(scan).includes(v))) {
        return { hex: h(4), label: 'OpenPGP Binary Key / Signature' };
      }
    }
    // DER certificate (ASN.1 SEQUENCE with long-form length)
    if (bytes[0] === 0x30 && bytes[1] === 0x82)
      return { hex: h(4), label: 'DER / ASN.1 Data' };
    return { hex: h(Math.min(4, bytes.length)), label: 'Unknown' };
  },

  // ── Heuristic: does this buffer look like OpenPGP data? ─────────────────
  // Used to disambiguate .key between X.509 private key (PEM) and PGP key.
  _looksLikePgp(bytes) {
    if (!bytes || bytes.length < 4) return false;
    // ASCII-armored
    const head = String.fromCharCode(...bytes.subarray(0, Math.min(64, bytes.length)));
    if (head.includes('-----BEGIN PGP ')) return true;
    // Binary OpenPGP packet headers (Public-Key, Secret-Key, their subkey variants,
    // both old-format and new-format)
    const first = bytes[0];
    if ([0x99, 0x95, 0xB9, 0x9D, 0xC6, 0xC5, 0xCE, 0xC7].includes(first)) return true;
    return false;
  },

  // ── Shannon entropy helper (bytes -> entropy in [0..8]) ─────────────────
  _computeEntropy(bytes) {
    if (bytes.length === 0) return 0;
    const freq = new Uint32Array(256);
    for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
    let entropy = 0;
    const len = bytes.length;
    for (let i = 0; i < 256; i++) {
      if (freq[i] === 0) continue;
      const p = freq[i] / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 1000) / 1000;
  },

});
