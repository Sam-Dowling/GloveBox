'use strict';
// ════════════════════════════════════════════════════════════════════════════
// pgp-renderer.js — OpenPGP public / private key parser + viewer (RFC 4880 /
// RFC 9580). Parses ASCII-armored and binary key material, enumerates packets,
// extracts user IDs, subkeys, signatures, and flags interesting security
// properties for SOC/DFIR investigation. Parse-only — no signature verification
// and no decryption of protected secret keys.
// ════════════════════════════════════════════════════════════════════════════

class PgpRenderer {

  // ── Public-key algorithm IDs (RFC 4880 §9.1 + RFC 6637 / RFC 9580) ────────
  static PK_ALGO = {
    1:  'RSA (Encrypt or Sign)',
    2:  'RSA Encrypt-Only',
    3:  'RSA Sign-Only',
    16: 'Elgamal (Encrypt-Only)',
    17: 'DSA',
    18: 'ECDH',
    19: 'ECDSA',
    20: 'Elgamal (Encrypt or Sign)',   // deprecated / dangerous
    21: 'DH (X9.42)',
    22: 'EdDSA (legacy)',
    23: 'AEDH (reserved)',
    24: 'AEDSA (reserved)',
    25: 'X25519',
    26: 'X448',
    27: 'Ed25519',
    28: 'Ed448',
  };

  // ── Symmetric-key algorithm IDs (§9.2) ───────────────────────────────────
  static SYM_ALGO = {
    0: 'Plaintext', 1: 'IDEA', 2: '3DES', 3: 'CAST5', 4: 'Blowfish',
    5: 'Reserved', 6: 'Reserved',
    7: 'AES-128', 8: 'AES-192', 9: 'AES-256', 10: 'Twofish',
    11: 'Camellia-128', 12: 'Camellia-192', 13: 'Camellia-256',
  };

  // ── Hash algorithm IDs (§9.4) ────────────────────────────────────────────
  static HASH_ALGO = {
    1:  'MD5',
    2:  'SHA-1',
    3:  'RIPEMD-160',
    8:  'SHA-256',
    9:  'SHA-384',
    10: 'SHA-512',
    11: 'SHA-224',
    12: 'SHA3-256',
    14: 'SHA3-512',
  };

  // ── Compression algorithm IDs (§9.3) ─────────────────────────────────────
  static COMP_ALGO = {
    0: 'Uncompressed', 1: 'ZIP', 2: 'ZLIB', 3: 'BZip2',
  };

  // ── Signature types (§5.2.1) — subset relevant to keys ───────────────────
  static SIG_TYPE = {
    0x00: 'Binary document signature',
    0x01: 'Canonical text document signature',
    0x02: 'Standalone signature',
    0x10: 'Generic certification of User ID',
    0x11: 'Persona certification of User ID',
    0x12: 'Casual certification of User ID',
    0x13: 'Positive certification of User ID',
    0x18: 'Subkey binding',
    0x19: 'Primary key binding',
    0x1F: 'Direct key signature',
    0x20: 'Key revocation',
    0x28: 'Subkey revocation',
    0x30: 'Certification revocation',
    0x40: 'Timestamp signature',
    0x50: 'Third-party confirmation',
  };

  // ── Packet tag names (§4.3) ──────────────────────────────────────────────
  static PKT_NAME = {
    0:  'Reserved',
    1:  'Public-Key Encrypted Session Key',
    2:  'Signature',
    3:  'Symmetric-Key Encrypted Session Key',
    4:  'One-Pass Signature',
    5:  'Secret-Key',
    6:  'Public-Key',
    7:  'Secret-Subkey',
    8:  'Compressed Data',
    9:  'Symmetrically Encrypted Data',
    10: 'Marker',
    11: 'Literal Data',
    12: 'Trust',
    13: 'User ID',
    14: 'Public-Subkey',
    17: 'User Attribute',
    18: 'Symmetrically Encrypted and Integrity Protected Data',
    19: 'Modification Detection Code',
    20: 'AEAD Encrypted Data',
    60: 'Private/Experimental',
    61: 'Private/Experimental',
    62: 'Private/Experimental',
    63: 'Private/Experimental',
  };

  // ── ECC curve OIDs (byte-prefix encoded in packet) ───────────────────────
  static CURVE_OIDS = {
    '2a8648ce3d030107':       'NIST P-256 (secp256r1)',
    '2b81040022':             'NIST P-384 (secp384r1)',
    '2b81040023':             'NIST P-521 (secp521r1)',
    '2b8104000a':             'secp256k1',
    '2b2403030208010107':     'brainpoolP256r1',
    '2b240303020801010d':     'brainpoolP384r1',
    '2b240303020801010b':     'brainpoolP512r1',
    '2b06010401da470f01':     'Ed25519 (legacy)',
    '2b060104019755010501':   'Curve25519 / X25519 (legacy)',
    '2b656e':                 'X448',
    '2b6570':                 'Ed25519',
    '2b6571':                 'Ed448',
  };

  // ── CRC-24 for ASCII armor checksum (RFC 4880 §6.1) ──────────────────────
  _crc24(bytes) {
    let crc = 0xB704CE;
    for (let i = 0; i < bytes.length; i++) {
      crc ^= bytes[i] << 16;
      for (let j = 0; j < 8; j++) {
        crc <<= 1;
        if (crc & 0x1000000) crc ^= 0x1864CFB;
      }
    }
    return crc & 0xFFFFFF;
  }

  _bytesToHex(bytes, sep = '') {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(sep);
  }

  _escHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  _fmtBytes(n) {
    if (n < 1024) return `${n} bytes`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(2)} MB`;
  }

  _fmtDate(sec) {
    if (!sec) return '—';
    try {
      const d = new Date(sec * 1000);
      return d.toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
    } catch (e) { return String(sec); }
  }

  // ── ASCII armor handling ─────────────────────────────────────────────────
  _isArmored(bytes) {
    // Look for "-----BEGIN PGP " within the first 64 bytes (allow BOM / leading ws)
    const head = new TextDecoder('utf-8', { fatal: false })
      .decode(bytes.subarray(0, Math.min(200, bytes.length)));
    return /-----BEGIN PGP [A-Z0-9 ]+-----/.test(head);
  }

  /** Parse all armored blocks in the input text. Returns [{label, data, crcOk, crcExpected, crcActual, warnings}]. */
  _decodeArmor(text) {
    const blocks = [];
    const re = /-----BEGIN PGP ([A-Z0-9 ]+)-----([\s\S]*?)-----END PGP \1-----/g;
    let m;
    while ((m = re.exec(text)) !== null) {
      const label = m[1].trim();
      const body = m[2];
      const warnings = [];

      // Split header lines from Base64 body: a blank line separates them.
      // Handle both CRLF and LF.
      const normalised = body.replace(/\r\n/g, '\n');
      const blankIdx = normalised.indexOf('\n\n');
      let headersText = '';
      let payload = normalised;
      if (blankIdx !== -1) {
        headersText = normalised.substring(0, blankIdx);
        payload = normalised.substring(blankIdx + 2);
      }

      // Parse headers (Version:, Comment:, Charset:, MessageID:, Hash:)
      const headers = {};
      if (headersText.trim()) {
        for (const line of headersText.split('\n')) {
          const i = line.indexOf(':');
          if (i > 0) headers[line.substring(0, i).trim()] = line.substring(i + 1).trim();
        }
      }

      // Split Base64 body from CRC-24 checksum line (starts with '=')
      const lines = payload.split('\n').map(l => l.trim()).filter(l => l.length > 0);
      let crcLine = '';
      const bodyLines = [];
      for (const l of lines) {
        if (l.startsWith('=') && l.length === 5) { crcLine = l.substring(1); continue; }
        bodyLines.push(l);
      }

      let data = null;
      try {
        const b64 = bodyLines.join('');
        const bin = atob(b64);
        data = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) data[i] = bin.charCodeAt(i);
      } catch (e) {
        warnings.push(`Base64 decode error: ${e.message}`);
      }

      let crcOk = null;
      let crcExpected = null;
      let crcActual = null;
      if (data && crcLine) {
        try {
          const crcBin = atob(crcLine);
          crcExpected = (crcBin.charCodeAt(0) << 16) | (crcBin.charCodeAt(1) << 8) | crcBin.charCodeAt(2);
          crcActual = this._crc24(data);
          crcOk = (crcExpected === crcActual);
          if (!crcOk) warnings.push('CRC-24 checksum mismatch — armor may be truncated or corrupt');
        } catch (e) {
          warnings.push(`CRC parse error: ${e.message}`);
        }
      } else if (data && !crcLine) {
        warnings.push('Missing CRC-24 checksum line');
      }

      blocks.push({ label, headers, data, crcOk, crcExpected, crcActual, warnings });
    }
    return blocks;
  }

  // ── OpenPGP packet stream walker (RFC 4880 §4 + RFC 9580 §4) ─────────────
  /**
   * Parse the packet stream from `bytes`. Returns [{tag, tagName, offset, length,
   * headerLen, oldFormat, body}]. Stops gracefully on malformed data.
   */
  _parsePackets(bytes) {
    const packets = [];
    let off = 0;
    let safety = 0;
    while (off < bytes.length && safety++ < 10000) {
      const startOff = off;
      const tagByte = bytes[off++];
      if (!(tagByte & 0x80)) {
        // Not a valid packet header — bail out
        break;
      }
      let tag, length, partial = false, oldFormat = false;
      if (tagByte & 0x40) {
        // New-format (RFC 4880 §4.2.2)
        tag = tagByte & 0x3F;
        if (off >= bytes.length) break;
        const o = bytes[off++];
        if (o < 192) {
          length = o;
        } else if (o < 224) {
          if (off >= bytes.length) break;
          length = ((o - 192) << 8) + bytes[off++] + 192;
        } else if (o < 255) {
          // Partial body length — we don't reassemble, just skip the partial chunk
          length = 1 << (o & 0x1F);
          partial = true;
        } else {
          if (off + 4 > bytes.length) break;
          length = (bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3];
          length = length >>> 0;
          off += 4;
        }
      } else {
        // Old-format (§4.2.1)
        oldFormat = true;
        tag = (tagByte >> 2) & 0x0F;
        const lenType = tagByte & 0x03;
        if (lenType === 0) {
          if (off >= bytes.length) break;
          length = bytes[off++];
        } else if (lenType === 1) {
          if (off + 2 > bytes.length) break;
          length = (bytes[off] << 8) | bytes[off + 1];
          off += 2;
        } else if (lenType === 2) {
          if (off + 4 > bytes.length) break;
          length = (bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3];
          length = length >>> 0;
          off += 4;
        } else {
          // Indeterminate length — treat as "rest of stream"
          length = bytes.length - off;
        }
      }

      if (length < 0 || off + length > bytes.length) {
        // truncated
        packets.push({
          tag, tagName: PgpRenderer.PKT_NAME[tag] || `Unknown (${tag})`,
          offset: startOff, headerLen: off - startOff, length,
          body: bytes.subarray(off, bytes.length),
          oldFormat, partial, truncated: true,
        });
        break;
      }

      packets.push({
        tag, tagName: PgpRenderer.PKT_NAME[tag] || `Unknown (${tag})`,
        offset: startOff, headerLen: off - startOff, length,
        body: bytes.subarray(off, off + length),
        oldFormat, partial, truncated: false,
      });
      off += length;
    }
    return packets;
  }

  // ── Key packet parser (§5.5.2 / §5.5.3) ──────────────────────────────────
  /** Parse a Public-Key or Secret-Key packet body. */
  _parseKeyPacket(body, tag) {
    const key = {
      tag,
      isSecret: (tag === 5 || tag === 7),
      isSubkey: (tag === 14 || tag === 7),
      version: null,
      created: null,
      algo: null, algoName: null,
      bits: null, curve: null,
      raw: body,
      _publicBlobLen: 0,  // offset where public key material ends (needed for fingerprint)
      secretInfo: null,   // populated for secret keys
    };
    if (body.length < 1) return key;
    let p = 0;
    key.version = body[p++];

    if (key.version === 3) {
      // v3: created (4) + validityDays (2) + algo (1) + MPIs
      if (p + 7 > body.length) return key;
      key.created = (body[p] << 24) | (body[p + 1] << 16) | (body[p + 2] << 8) | body[p + 3];
      key.created = key.created >>> 0;
      p += 4;
      p += 2; // validity days
      key.algo = body[p++];
    } else if (key.version === 4 || key.version === 5 || key.version === 6) {
      // v4: created (4) + algo (1) + algo-specific
      if (p + 5 > body.length) return key;
      key.created = (body[p] << 24) | (body[p + 1] << 16) | (body[p + 2] << 8) | body[p + 3];
      key.created = key.created >>> 0;
      p += 4;
      if (key.version === 5 || key.version === 6) {
        // v5/v6: 4-byte key-material length (count-style)
        p += 4;
      }
      key.algo = body[p++];
    } else {
      return key;
    }

    key.algoName = PgpRenderer.PK_ALGO[key.algo] || `Unknown (${key.algo})`;

    // Parse algorithm-specific public material to determine bits / curve.
    try {
      if (key.algo === 1 || key.algo === 2 || key.algo === 3) {
        // RSA: n (MPI), e (MPI)
        const n = this._readMPI(body, p); if (!n) { key._publicBlobLen = p; return key; }
        p = n.nextOff;
        key.bits = n.bits;
        const e = this._readMPI(body, p); if (e) p = e.nextOff;
      } else if (key.algo === 17) {
        // DSA: p, q, g, y
        const pmpi = this._readMPI(body, p); if (!pmpi) { key._publicBlobLen = p; return key; }
        key.bits = pmpi.bits;
        p = pmpi.nextOff;
        const q = this._readMPI(body, p); if (q) p = q.nextOff;
        const g = this._readMPI(body, p); if (g) p = g.nextOff;
        const y = this._readMPI(body, p); if (y) p = y.nextOff;
      } else if (key.algo === 16 || key.algo === 20) {
        // Elgamal: p, g, y
        const pm = this._readMPI(body, p); if (!pm) { key._publicBlobLen = p; return key; }
        key.bits = pm.bits;
        p = pm.nextOff;
        const g = this._readMPI(body, p); if (g) p = g.nextOff;
        const y = this._readMPI(body, p); if (y) p = y.nextOff;
      } else if (key.algo === 18 || key.algo === 19 || key.algo === 22) {
        // ECDH (18), ECDSA (19), EdDSA-legacy (22): curve OID length + OID bytes + MPI + (ECDH only) KDF params
        if (p >= body.length) { key._publicBlobLen = p; return key; }
        const oidLen = body[p++];
        if (p + oidLen > body.length) { key._publicBlobLen = p; return key; }
        const oidHex = this._bytesToHex(body.subarray(p, p + oidLen));
        key.curve = PgpRenderer.CURVE_OIDS[oidHex] || `OID 0x${oidHex}`;
        p += oidLen;
        const pt = this._readMPI(body, p);
        if (pt) { key.bits = pt.bits; p = pt.nextOff; }
        if (key.algo === 18) {
          // KDF parameters: 1-byte length + reserved + hash + symmetric
          if (p < body.length) {
            const klen = body[p++];
            p += klen;
          }
        }
      } else if (key.algo === 25 || key.algo === 26 || key.algo === 27 || key.algo === 28) {
        // RFC 9580 native X25519 / X448 / Ed25519 / Ed448: fixed-size public key, no MPI framing
        const sizes = { 25: 32, 26: 56, 27: 32, 28: 57 };
        const sz = sizes[key.algo];
        if (p + sz <= body.length) {
          key.bits = sz * 8;
          if (key.algo === 25 || key.algo === 27) key.curve = 'Curve25519';
          else if (key.algo === 26 || key.algo === 28) key.curve = 'Curve448';
          p += sz;
        }
      }
    } catch (e) { /* swallow — partial parse is still useful */ }

    key._publicBlobLen = p;

    // Secret-key material (after public)
    if (key.isSecret && p < body.length) {
      const s2k = {};
      s2k.usage = body[p++];
      if (s2k.usage === 0) {
        // Unencrypted — immediately followed by the private MPIs (+ checksum)
        s2k.encrypted = false;
        s2k.cipher = 'None (unprotected)';
      } else if (s2k.usage === 253 || s2k.usage === 254 || s2k.usage === 255) {
        s2k.encrypted = true;
        if (p + 1 > body.length) { key.secretInfo = s2k; return key; }
        const cipher = body[p++];
        s2k.cipher = PgpRenderer.SYM_ALGO[cipher] || `Unknown (${cipher})`;
        if (s2k.usage === 253) {
          // AEAD: aead algo + S2K len + S2K
          if (p < body.length) s2k.aead = body[p++];
        }
        // S2K specifier
        if (p < body.length) {
          const s2kType = body[p++];
          s2k.s2kType = s2kType;
          if (s2kType === 0) { s2k.s2kName = 'Simple'; if (p < body.length) s2k.hash = body[p++]; }
          else if (s2kType === 1) { s2k.s2kName = 'Salted'; if (p < body.length) s2k.hash = body[p++]; p += 8; }
          else if (s2kType === 3) {
            s2k.s2kName = 'Iterated + Salted';
            if (p < body.length) s2k.hash = body[p++];
            p += 8; // salt
            if (p < body.length) s2k.iterCount = body[p++];
          } else {
            s2k.s2kName = `Type ${s2kType}`;
          }
        }
        if (s2k.hash !== undefined) s2k.hashName = PgpRenderer.HASH_ALGO[s2k.hash] || `Unknown (${s2k.hash})`;
      } else {
        // Legacy: usage == symmetric algo ID directly
        s2k.encrypted = true;
        s2k.cipher = PgpRenderer.SYM_ALGO[s2k.usage] || `Unknown (${s2k.usage})`;
        s2k.legacy = true;
      }
      key.secretInfo = s2k;
    }

    return key;
  }

  /** Read an MPI (multi-precision integer) from body at offset. Returns {bits, nextOff} or null. */
  _readMPI(body, off) {
    if (off + 2 > body.length) return null;
    const bits = (body[off] << 8) | body[off + 1];
    const byteLen = Math.floor((bits + 7) / 8);
    if (off + 2 + byteLen > body.length) return null;
    return { bits, byteLen, nextOff: off + 2 + byteLen };
  }

  /** Compute the fingerprint of a key packet. v4 = SHA-1(0x99 || 2-byte len || pubkey),
   *  v5/v6 = SHA-256(0x9A || 4-byte len || pubkey), v3 = MD5(n || e) (not computed). */
  async _computeFingerprint(key) {
    if (!crypto || !crypto.subtle) return null;
    try {
      const pubBody = key.raw.subarray(0, key._publicBlobLen);
      if (key.version === 4) {
        const buf = new Uint8Array(3 + pubBody.length);
        buf[0] = 0x99;
        buf[1] = (pubBody.length >> 8) & 0xFF;
        buf[2] = pubBody.length & 0xFF;
        buf.set(pubBody, 3);
        const hash = await crypto.subtle.digest('SHA-1', buf);
        return this._bytesToHex(new Uint8Array(hash)).toUpperCase();
      } else if (key.version === 5 || key.version === 6) {
        const buf = new Uint8Array(5 + pubBody.length);
        buf[0] = 0x9A;
        buf[1] = (pubBody.length >>> 24) & 0xFF;
        buf[2] = (pubBody.length >>> 16) & 0xFF;
        buf[3] = (pubBody.length >>> 8) & 0xFF;
        buf[4] = pubBody.length & 0xFF;
        buf.set(pubBody, 5);
        const hash = await crypto.subtle.digest('SHA-256', buf);
        return this._bytesToHex(new Uint8Array(hash)).toUpperCase();
      }
      return null;
    } catch (e) { return null; }
  }

  /** Key ID (low 64 bits of fingerprint for v4; for v5/v6 high 64 bits). */
  _keyIdFromFp(fp, version) {
    if (!fp) return null;
    if (version === 4) return fp.substring(fp.length - 16);
    if (version === 5 || version === 6) return fp.substring(0, 16);
    return null;
  }

  // ── Signature packet parser (§5.2) — just enough to surface subpackets ───
  _parseSignaturePacket(body) {
    const sig = { version: null, sigType: null, pkAlgo: null, hashAlgo: null,
                  hashedSubs: [], unhashedSubs: [], flags: {}, created: null,
                  expires: null, keyExpires: null, issuerKeyId: null,
                  issuerFingerprint: null, preferredHash: [], preferredSym: [] };
    if (body.length < 1) return sig;
    let p = 0;
    sig.version = body[p++];
    if (sig.version === 3 || sig.version === 2) {
      // v3: hashed material length (1 byte, must be 5), then sigType, created, issuerKeyID...
      if (p + 19 > body.length) return sig;
      p++; // hashed len
      sig.sigType = body[p++];
      sig.created = (body[p] << 24) | (body[p + 1] << 16) | (body[p + 2] << 8) | body[p + 3];
      sig.created = sig.created >>> 0;
      p += 4;
      sig.issuerKeyId = this._bytesToHex(body.subarray(p, p + 8)).toUpperCase();
      p += 8;
      sig.pkAlgo = body[p++];
      sig.hashAlgo = body[p++];
    } else if (sig.version === 4 || sig.version === 5 || sig.version === 6) {
      if (p + 5 > body.length) return sig;
      sig.sigType = body[p++];
      sig.pkAlgo = body[p++];
      sig.hashAlgo = body[p++];
      // Hashed subpacket length (2 bytes for v4, 4 bytes for v5/v6)
      let hLen;
      if (sig.version === 4) {
        hLen = (body[p] << 8) | body[p + 1]; p += 2;
      } else {
        if (p + 4 > body.length) return sig;
        hLen = (body[p] << 24) | (body[p + 1] << 16) | (body[p + 2] << 8) | body[p + 3];
        hLen = hLen >>> 0;
        p += 4;
      }
      if (p + hLen <= body.length) {
        sig.hashedSubs = this._parseSubpackets(body.subarray(p, p + hLen));
        p += hLen;
      }
      // Unhashed subpackets
      let uLen;
      if (sig.version === 4) {
        if (p + 2 > body.length) return sig;
        uLen = (body[p] << 8) | body[p + 1]; p += 2;
      } else {
        if (p + 4 > body.length) return sig;
        uLen = (body[p] << 24) | (body[p + 1] << 16) | (body[p + 2] << 8) | body[p + 3];
        uLen = uLen >>> 0;
        p += 4;
      }
      if (p + uLen <= body.length) {
        sig.unhashedSubs = this._parseSubpackets(body.subarray(p, p + uLen));
      }
    }

    // Extract well-known fields
    const all = [...sig.hashedSubs, ...sig.unhashedSubs];
    for (const sp of all) {
      const type = sp.type & 0x7F;
      const d = sp.data;
      if (type === 2 && d.length >= 4) {
        // Signature Creation Time
        sig.created = ((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]) >>> 0;
      } else if (type === 3 && d.length >= 4) {
        // Signature Expiration Time (seconds after created)
        sig.expires = ((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]) >>> 0;
      } else if (type === 9 && d.length >= 4) {
        // Key Expiration Time (seconds after key created)
        sig.keyExpires = ((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]) >>> 0;
      } else if (type === 16 && d.length >= 8) {
        // Issuer Key ID
        sig.issuerKeyId = this._bytesToHex(d.subarray(0, 8)).toUpperCase();
      } else if (type === 33 && d.length >= 21) {
        // Issuer Fingerprint (1-byte version + fingerprint)
        sig.issuerFingerprint = this._bytesToHex(d.subarray(1)).toUpperCase();
      } else if (type === 27 && d.length >= 1) {
        // Key Flags
        const f = d[0];
        sig.flags.certify   = !!(f & 0x01);
        sig.flags.sign      = !!(f & 0x02);
        sig.flags.encryptComms = !!(f & 0x04);
        sig.flags.encryptStorage = !!(f & 0x08);
        sig.flags.splitKey  = !!(f & 0x10);
        sig.flags.auth      = !!(f & 0x20);
        sig.flags.groupKey  = !!(f & 0x80);
      } else if (type === 21) {
        sig.preferredHash = Array.from(d);
      } else if (type === 11) {
        sig.preferredSym = Array.from(d);
      }
    }
    return sig;
  }

  /** Parse a subpacket blob: sequence of (len + type-byte + data). */
  _parseSubpackets(blob) {
    const out = [];
    let p = 0;
    let safety = 0;
    while (p < blob.length && safety++ < 512) {
      const o = blob[p++];
      let len;
      if (o < 192) {
        len = o;
      } else if (o < 255) {
        if (p >= blob.length) break;
        len = ((o - 192) << 8) + blob[p++] + 192;
      } else {
        if (p + 4 > blob.length) break;
        len = (blob[p] << 24) | (blob[p + 1] << 16) | (blob[p + 2] << 8) | blob[p + 3];
        len = len >>> 0;
        p += 4;
      }
      if (len < 1 || p + len > blob.length) break;
      const type = blob[p];
      out.push({ type, data: blob.subarray(p + 1, p + len), raw: blob.subarray(p, p + len) });
      p += len;
    }
    return out;
  }

  // ── Group packets into key + attached metadata ───────────────────────────
  /** Given a flat packet list, group them into primary keys (with their UIDs,
   *  subkeys, and signatures). Returns [{primary, userIds, userAttrs, subkeys, signatures}]. */
  _groupKeys(packets) {
    const groups = [];
    let current = null;
    let attachTo = null; // 'primary' | {uid object} | {subkey object}

    for (const pkt of packets) {
      if (pkt.tag === 6 || pkt.tag === 5) {
        // New primary (public or secret)
        if (current) groups.push(current);
        const key = this._parseKeyPacket(pkt.body, pkt.tag);
        current = { primary: key, userIds: [], userAttrs: [], subkeys: [], signatures: [], otherPackets: [] };
        attachTo = 'primary';
      } else if (pkt.tag === 14 || pkt.tag === 7) {
        // Subkey
        if (!current) { continue; }
        const sub = this._parseKeyPacket(pkt.body, pkt.tag);
        const entry = { key: sub, signatures: [] };
        current.subkeys.push(entry);
        attachTo = entry;
      } else if (pkt.tag === 13) {
        // User ID
        if (!current) continue;
        const text = new TextDecoder('utf-8', { fatal: false }).decode(pkt.body);
        const parsed = this._parseUserId(text);
        const entry = { text, ...parsed, signatures: [] };
        current.userIds.push(entry);
        attachTo = entry;
      } else if (pkt.tag === 17) {
        // User Attribute (typically a photo)
        if (!current) continue;
        const entry = { length: pkt.body.length, signatures: [] };
        current.userAttrs.push(entry);
        attachTo = entry;
      } else if (pkt.tag === 2) {
        // Signature — attach to last context
        if (!current) continue;
        const sig = this._parseSignaturePacket(pkt.body);
        sig.sigTypeName = PgpRenderer.SIG_TYPE[sig.sigType] || `Type 0x${(sig.sigType || 0).toString(16)}`;
        sig.pkAlgoName = PgpRenderer.PK_ALGO[sig.pkAlgo] || `Unknown (${sig.pkAlgo})`;
        sig.hashAlgoName = PgpRenderer.HASH_ALGO[sig.hashAlgo] || `Unknown (${sig.hashAlgo})`;
        current.signatures.push(sig);
        if (attachTo === 'primary') {
          // directs / revocations / self-certs on primary end up here
        } else if (attachTo && typeof attachTo === 'object') {
          attachTo.signatures.push(sig);
        }
      } else {
        if (current) current.otherPackets.push(pkt);
      }
    }
    if (current) groups.push(current);
    return groups;
  }

  /** Very small User ID parser. RFC 4880 is loose here — commonly "Name (Comment) <email>". */
  _parseUserId(text) {
    const out = { name: null, comment: null, email: null };
    const m = text.match(/^\s*(.*?)\s*(?:\(([^)]*)\))?\s*<([^>]+)>\s*$/);
    if (m) {
      out.name = (m[1] || '').trim() || null;
      out.comment = (m[2] || '').trim() || null;
      out.email = (m[3] || '').trim() || null;
    } else {
      // Fallback: just try to pull an email
      const e = text.match(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/);
      if (e) out.email = e[0];
      out.name = text.trim();
    }
    return out;
  }

  // ════════════════════════════════════════════════════════════════════════
  // render() — main entry point
  // ════════════════════════════════════════════════════════════════════════
  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : (buffer.buffer || buffer));
    const wrap = document.createElement('div');
    wrap.className = 'pgp-view';

    try {
      const armored = this._isArmored(bytes);
      let armorBlocks = [];
      if (armored) {
        const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        armorBlocks = this._decodeArmor(text);
        if (armorBlocks.length === 0) throw new Error('No valid PGP armor blocks found');
      } else {
        // Treat as raw binary packet stream
        armorBlocks = [{ label: 'BINARY OPENPGP DATA', data: bytes, crcOk: null, warnings: [], headers: {} }];
      }

      // Banner
      const banner = document.createElement('div');
      banner.className = 'pgp-banner';
      const hasPrivate = armorBlocks.some(b => b.label.includes('PRIVATE KEY'));
      banner.classList.add(hasPrivate ? 'pgp-banner-private' : 'pgp-banner-public');
      const icon = hasPrivate ? '🔐' : '🔑';
      banner.textContent = `${icon} OpenPGP ${armored ? 'ASCII-Armored ' : 'Binary '}Data — ${armorBlocks.length} block${armorBlocks.length > 1 ? 's' : ''} detected`;
      wrap.appendChild(banner);

      for (let bi = 0; bi < armorBlocks.length; bi++) {
        const blk = armorBlocks[bi];
        const blockWrap = document.createElement('div');
        blockWrap.className = 'pgp-block';

        // Block header
        const blockHeader = document.createElement('div');
        blockHeader.className = 'pgp-block-header';
        blockHeader.textContent = blk.label;
        blockWrap.appendChild(blockHeader);

        // Armor metadata / warnings
        if (armored) {
          const meta = document.createElement('div');
          meta.className = 'pgp-armor-meta';
          const parts = [];
          if (blk.headers.Version) parts.push(`<span class="pgp-armor-tag">Version: ${this._escHtml(blk.headers.Version)}</span>`);
          if (blk.headers.Comment) parts.push(`<span class="pgp-armor-tag">Comment: ${this._escHtml(blk.headers.Comment)}</span>`);
          if (blk.crcOk === true) parts.push('<span class="pgp-armor-tag pgp-ok">✓ CRC-24 OK</span>');
          else if (blk.crcOk === false) parts.push('<span class="pgp-armor-tag pgp-bad">⚠ CRC mismatch</span>');
          if (blk.data) parts.push(`<span class="pgp-armor-tag">${this._fmtBytes(blk.data.length)} decoded</span>`);
          meta.innerHTML = parts.join(' ');
          blockWrap.appendChild(meta);

          for (const w of blk.warnings) {
            const warn = document.createElement('div');
            warn.className = 'pgp-warning';
            warn.textContent = `⚠ ${w}`;
            blockWrap.appendChild(warn);
          }
        }

        // Skip deeper parsing for non-key blocks (messages, signatures-only)
        if (!blk.data) {
          wrap.appendChild(blockWrap);
          continue;
        }

        const packets = this._parsePackets(blk.data);

        // If this is a signature-only or message block, just render the packet list
        const hasKey = packets.some(p => p.tag === 5 || p.tag === 6);

        if (!hasKey) {
          const notice = document.createElement('div');
          notice.className = 'pgp-notice';
          if (blk.label.includes('SIGNATURE')) {
            notice.textContent = '📝 This block contains detached signature data only (no key material).';
          } else if (blk.label.includes('MESSAGE')) {
            notice.textContent = '✉ This block contains an encrypted or signed message (not a key).';
          } else {
            notice.textContent = '(No key packets found in this block.)';
          }
          blockWrap.appendChild(notice);
          blockWrap.appendChild(this._renderPacketTable(packets));
          wrap.appendChild(blockWrap);
          continue;
        }

        const groups = this._groupKeys(packets);
        for (let gi = 0; gi < groups.length; gi++) {
          const group = groups[gi];
          const card = this._renderKeyGroup(group, gi + 1, groups.length);
          blockWrap.appendChild(card);
        }

        // Raw packet table (collapsible)
        blockWrap.appendChild(this._renderPacketTable(packets));
        wrap.appendChild(blockWrap);
      }

      // Asynchronously compute fingerprints & key IDs and populate placeholders
      this._populateFingerprints(wrap);

    } catch (e) {
      const err = document.createElement('div');
      err.className = 'pgp-error';
      err.textContent = `⚠ PGP parse error: ${e.message}`;
      wrap.appendChild(err);
    }

    return wrap;
  }

  /** Render a single key group (primary + uids + subkeys). */
  _renderKeyGroup(group, index, total) {
    const card = document.createElement('div');
    card.className = 'pgp-key-card';

    const primary = group.primary;
    const title = document.createElement('div');
    title.className = 'pgp-key-title';
    const primaryName = (group.userIds[0] && group.userIds[0].name) || (group.userIds[0] && group.userIds[0].email) || '(no user ID)';
    const keyKind = primary.isSecret ? 'Secret Key' : 'Public Key';
    title.textContent = total > 1 ? `Key #${index} — ${keyKind} — ${primaryName}` : `${keyKind} — ${primaryName}`;
    card.appendChild(title);

    // Badges
    const badges = document.createElement('div');
    badges.className = 'pgp-badges';
    badges.appendChild(this._badge('version', `v${primary.version || '?'}`));
    badges.appendChild(this._badge('algo', primary.algoName || '—'));
    if (primary.bits) badges.appendChild(this._badge('size', `${primary.bits}-bit`));
    if (primary.curve) badges.appendChild(this._badge('curve', primary.curve));
    if (primary.isSecret) {
      if (primary.secretInfo && primary.secretInfo.encrypted === false) {
        badges.appendChild(this._badge('unprotected', '🔓 Unprotected'));
      } else {
        badges.appendChild(this._badge('protected', '🔒 Passphrase-Protected'));
      }
    }
    // Expiry / revocation info from self-sigs on primary
    const primarySelfSig = group.signatures.find(s => s.sigType === 0x1F || (s.sigType >= 0x10 && s.sigType <= 0x13));
    const revoc = group.signatures.find(s => s.sigType === 0x20);
    if (revoc) badges.appendChild(this._badge('revoked', '🚫 Revoked'));
    if (primarySelfSig && primarySelfSig.keyExpires && primary.created) {
      const expiresAt = primary.created + primarySelfSig.keyExpires;
      if (Date.now() / 1000 > expiresAt) badges.appendChild(this._badge('expired', '⏰ Expired'));
    }
    card.appendChild(badges);

    // Info table
    const table = document.createElement('table');
    table.className = 'pgp-info-table';
    this._row(table, 'Version', `v${primary.version}`);
    this._row(table, 'Algorithm', primary.algoName || '—');
    if (primary.bits) this._row(table, 'Key Size', `${primary.bits}-bit`);
    if (primary.curve) this._row(table, 'Curve', primary.curve);
    this._row(table, 'Created', this._fmtDate(primary.created));

    if (primarySelfSig && primarySelfSig.keyExpires) {
      const expiresAt = primary.created + primarySelfSig.keyExpires;
      this._row(table, 'Expires', this._fmtDate(expiresAt));
    } else {
      this._row(table, 'Expires', 'Never');
    }

    // Fingerprint / key-id placeholders (filled async)
    const fpVal = this._row(table, 'Fingerprint', 'Computing…');
    fpVal.dataset.pgpFp = '1';
    fpVal.classList.add('pgp-fingerprint');
    const kidVal = this._row(table, 'Key ID', 'Computing…');
    kidVal.dataset.pgpKid = '1';
    kidVal.classList.add('pgp-fingerprint');

    // Stash the pubBody so the async pass can re-find the key from the DOM if needed.
    card.dataset.pgpPrimaryVersion = String(primary.version);
    card._pgpPrimary = primary;  // direct ref (retained since card is kept in DOM)
    card._pgpFpCell = fpVal;
    card._pgpKidCell = kidVal;

    // Key flags (from primary self-sig)
    if (primarySelfSig && Object.keys(primarySelfSig.flags).length) {
      const caps = [];
      if (primarySelfSig.flags.certify) caps.push('Certify');
      if (primarySelfSig.flags.sign) caps.push('Sign');
      if (primarySelfSig.flags.encryptComms || primarySelfSig.flags.encryptStorage) caps.push('Encrypt');
      if (primarySelfSig.flags.auth) caps.push('Authenticate');
      if (caps.length) this._row(table, 'Capabilities', caps.join(' · '));
    }
    if (primarySelfSig && primarySelfSig.preferredHash.length) {
      const names = primarySelfSig.preferredHash.map(h => PgpRenderer.HASH_ALGO[h] || `#${h}`).join(', ');
      this._row(table, 'Preferred Hash', names);
    }
    if (primarySelfSig && primarySelfSig.preferredSym.length) {
      const names = primarySelfSig.preferredSym.map(s => PgpRenderer.SYM_ALGO[s] || `#${s}`).join(', ');
      this._row(table, 'Preferred Cipher', names);
    }

    // Secret-key protection details
    if (primary.isSecret && primary.secretInfo) {
      const s = primary.secretInfo;
      this._row(table, 'Secret Protection', s.encrypted ? 'Encrypted' : '⚠ Unprotected (no passphrase)');
      if (s.encrypted) {
        this._row(table, 'Cipher', s.cipher || '—');
        if (s.s2kName) this._row(table, 'S2K', s.s2kName + (s.hashName ? ` (${s.hashName})` : ''));
      }
    }

    card.appendChild(table);

    // User IDs section
    if (group.userIds.length) {
      const uidTitle = document.createElement('div');
      uidTitle.className = 'pgp-section-title';
      uidTitle.textContent = `User IDs (${group.userIds.length})`;
      card.appendChild(uidTitle);

      const uidTable = document.createElement('table');
      uidTable.className = 'pgp-subtable';
      const thead = document.createElement('thead');
      thead.innerHTML = '<tr><th>Name</th><th>Email</th><th>Comment</th><th>Signed</th></tr>';
      uidTable.appendChild(thead);
      const tbody = document.createElement('tbody');
      for (const uid of group.userIds) {
        const tr = document.createElement('tr');
        const selfSig = uid.signatures.find(s => s.sigType >= 0x10 && s.sigType <= 0x13);
        tr.innerHTML = `<td>${this._escHtml(uid.name || '')}</td>` +
                       `<td>${this._escHtml(uid.email || '')}</td>` +
                       `<td>${this._escHtml(uid.comment || '')}</td>` +
                       `<td>${selfSig ? this._escHtml(this._fmtDate(selfSig.created)) : ''}</td>`;
        tbody.appendChild(tr);
      }
      uidTable.appendChild(tbody);
      card.appendChild(uidTable);
    }

    // User attributes (photos)
    if (group.userAttrs.length) {
      const p = document.createElement('div');
      p.className = 'pgp-notice';
      p.textContent = `📷 ${group.userAttrs.length} user attribute packet(s) (photo ID or similar).`;
      card.appendChild(p);
    }

    // Subkeys section
    if (group.subkeys.length) {
      const subTitle = document.createElement('div');
      subTitle.className = 'pgp-section-title';
      subTitle.textContent = `Subkeys (${group.subkeys.length})`;
      card.appendChild(subTitle);

      for (const subEntry of group.subkeys) {
        const sub = subEntry.key;
        const subCard = document.createElement('div');
        subCard.className = 'pgp-subkey-card';

        const subBadges = document.createElement('div');
        subBadges.className = 'pgp-badges';
        subBadges.appendChild(this._badge('version', `v${sub.version || '?'}`));
        subBadges.appendChild(this._badge('algo', sub.algoName || '—'));
        if (sub.bits) subBadges.appendChild(this._badge('size', `${sub.bits}-bit`));
        if (sub.curve) subBadges.appendChild(this._badge('curve', sub.curve));
        if (sub.isSecret) {
          if (sub.secretInfo && sub.secretInfo.encrypted === false) subBadges.appendChild(this._badge('unprotected', '🔓 Unprotected'));
          else subBadges.appendChild(this._badge('protected', '🔒 Protected'));
        }
        subCard.appendChild(subBadges);

        const subTable = document.createElement('table');
        subTable.className = 'pgp-info-table';
        this._row(subTable, 'Created', this._fmtDate(sub.created));
        const bindSig = subEntry.signatures.find(s => s.sigType === 0x18);
        if (bindSig) {
          if (bindSig.keyExpires) {
            this._row(subTable, 'Expires', this._fmtDate(sub.created + bindSig.keyExpires));
          } else {
            this._row(subTable, 'Expires', 'Never');
          }
          if (Object.keys(bindSig.flags).length) {
            const caps = [];
            if (bindSig.flags.certify) caps.push('Certify');
            if (bindSig.flags.sign) caps.push('Sign');
            if (bindSig.flags.encryptComms || bindSig.flags.encryptStorage) caps.push('Encrypt');
            if (bindSig.flags.auth) caps.push('Authenticate');
            if (caps.length) this._row(subTable, 'Capabilities', caps.join(' · '));
          }
        }
        const subFp = this._row(subTable, 'Fingerprint', 'Computing…');
        subFp.dataset.pgpFp = '1';
        subFp.classList.add('pgp-fingerprint');
        const subKid = this._row(subTable, 'Key ID', 'Computing…');
        subKid.dataset.pgpKid = '1';
        subKid.classList.add('pgp-fingerprint');
        subCard._pgpPrimary = sub;
        subCard._pgpFpCell = subFp;
        subCard._pgpKidCell = subKid;

        // Secret protection on subkey
        if (sub.isSecret && sub.secretInfo) {
          this._row(subTable, 'Secret Protection', sub.secretInfo.encrypted ? 'Encrypted' : '⚠ Unprotected');
          if (sub.secretInfo.encrypted) {
            this._row(subTable, 'Cipher', sub.secretInfo.cipher || '—');
          }
        }

        subCard.appendChild(subTable);
        card.appendChild(subCard);
      }
    }

    return card;
  }

  /** Render the raw packet listing (collapsible). */
  _renderPacketTable(packets) {
    const details = document.createElement('details');
    details.className = 'pgp-packets-details';
    const summary = document.createElement('summary');
    summary.textContent = `Raw packet listing (${packets.length} packet${packets.length !== 1 ? 's' : ''})`;
    details.appendChild(summary);

    const table = document.createElement('table');
    table.className = 'pgp-packet-table';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>#</th><th>Offset</th><th>Tag</th><th>Name</th><th>Length</th><th>Format</th><th>First bytes</th></tr>';
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    for (let i = 0; i < packets.length; i++) {
      const p = packets[i];
      const preview = this._bytesToHex(p.body.subarray(0, Math.min(16, p.body.length)), ' ');
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${i + 1}</td>` +
                     `<td>0x${p.offset.toString(16)}</td>` +
                     `<td>${p.tag}</td>` +
                     `<td>${this._escHtml(p.tagName)}</td>` +
                     `<td>${p.length}</td>` +
                     `<td>${p.oldFormat ? 'Old' : 'New'}${p.partial ? ' · partial' : ''}${p.truncated ? ' · ⚠ truncated' : ''}</td>` +
                     `<td class="pgp-hex">${preview}${p.body.length > 16 ? '…' : ''}</td>`;
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    details.appendChild(table);
    return details;
  }

  _badge(kind, text) {
    const span = document.createElement('span');
    span.className = `pgp-badge pgp-badge-${kind}`;
    span.textContent = text;
    return span;
  }

  _row(table, label, value) {
    const tr = document.createElement('tr');
    const td1 = document.createElement('td'); td1.className = 'pgp-lbl'; td1.textContent = label;
    const td2 = document.createElement('td'); td2.className = 'pgp-val'; td2.textContent = value;
    tr.appendChild(td1); tr.appendChild(td2); table.appendChild(tr);
    return td2;
  }

  /** Find every card with a stashed key and compute fingerprint + keyID. */
  async _populateFingerprints(wrap) {
    const cards = wrap.querySelectorAll('.pgp-key-card, .pgp-subkey-card');
    for (const card of cards) {
      const key = card._pgpPrimary;
      if (!key) continue;
      try {
        const fp = await this._computeFingerprint(key);
        if (fp) {
          const spaced = fp.match(/.{1,4}/g).join(' ');
          if (card._pgpFpCell) card._pgpFpCell.textContent = spaced;
          const kid = this._keyIdFromFp(fp, key.version);
          if (card._pgpKidCell) card._pgpKidCell.textContent = kid ? (kid.match(/.{1,4}/g).join(' ')) : '—';
          // Stash resolved values back on the DOM for IOC extraction
          card.dataset.pgpFingerprint = fp;
          if (kid) card.dataset.pgpKeyId = kid;
        } else {
          if (card._pgpFpCell) card._pgpFpCell.textContent = '(v3 — MD5 fingerprint not computed)';
          if (card._pgpKidCell) card._pgpKidCell.textContent = '—';
        }
      } catch (e) {
        if (card._pgpFpCell) card._pgpFpCell.textContent = `(error: ${e.message})`;
        if (card._pgpKidCell) card._pgpKidCell.textContent = '—';
      }
    }
  }

  // ════════════════════════════════════════════════════════════════════════
  // analyzeForSecurity()
  // ════════════════════════════════════════════════════════════════════════
  analyzeForSecurity(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : (buffer.buffer || buffer));
    const findings = {
      detections: [],
      interestingStrings: [],
      formatSpecific: [],
      riskScore: 0,
      riskLevel: 'low',
      summary: '',
    };

    try {
      const armored = this._isArmored(bytes);
      let armorBlocks;
      if (armored) {
        const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        armorBlocks = this._decodeArmor(text);
        if (armorBlocks.length === 0) {
          findings.summary = 'No valid PGP armor blocks found';
          escalateRisk(findings, findings.riskLevel);
          findings.metadata = {};
          findings.externalRefs = [];
          return findings;
        }
      } else {
        armorBlocks = [{ label: 'BINARY OPENPGP DATA', data: bytes, crcOk: null, warnings: [], headers: {} }];
      }

      let totalPrimaries = 0;
      let totalSubkeys = 0;
      let totalUserIds = 0;
      let hasPrivate = false;

      for (const blk of armorBlocks) {
        if (blk.label.includes('PRIVATE KEY')) hasPrivate = true;
        if (blk.crcOk === false) {
          findings.detections.push({
            name: 'Corrupt PGP Armor',
            description: `CRC-24 checksum mismatch on "${blk.label}" block (expected 0x${(blk.crcExpected || 0).toString(16)}, got 0x${(blk.crcActual || 0).toString(16)}). The armored block may be truncated, modified, or have transmission damage.`,
            severity: 'medium',
          });
          findings.riskScore += 10;
        }

        if (!blk.data) continue;
        const packets = this._parsePackets(blk.data);
        const groups = this._groupKeys(packets);

        for (const group of groups) {
          const primary = group.primary;
          totalPrimaries++;
          totalSubkeys += group.subkeys.length;
          totalUserIds += group.userIds.length;

          const primaryName = (group.userIds[0] && (group.userIds[0].email || group.userIds[0].name)) || 'key';
          const allKeys = [{ key: primary, label: `primary (${primaryName})` },
                           ...group.subkeys.map((s, i) => ({ key: s.key, label: `subkey #${i + 1} of ${primaryName}` }))];

          // ── Unprotected private key ──
          for (const { key, label } of allKeys) {
            if (key.isSecret && key.secretInfo && key.secretInfo.encrypted === false) {
              findings.detections.push({
                name: 'Unprotected PGP Private Key',
                description: `The ${label} is a secret key stored without a passphrase (S2K usage = 0). Anyone with access to this file can use it to sign or decrypt. This is highly unusual outside of automated systems and is treated as a critical exposure.`,
                severity: 'critical',
              });
              findings.riskScore += 60;
            } else if (key.isSecret) {
              findings.detections.push({
                name: 'PGP Private Key Present',
                description: `File contains a ${label} protected by a passphrase. Private keys should never be stored outside of a keyring.`,

                severity: 'medium',
              });
              findings.riskScore += 15;
            }
          }

          // ── Weak algorithm / key size ──
          for (const { key, label } of allKeys) {
            // RSA / DSA / Elgamal: check bits
            if ([1, 2, 3, 16, 17, 20].includes(key.algo) && key.bits) {
              if (key.bits < 1024) {
                findings.detections.push({
                  name: 'Critically Weak PGP Key',
                  description: `${label} uses ${key.bits}-bit ${key.algoName}. Under 1024 bits is trivially factorable with modern hardware.`,
                  severity: 'high',
                });
                findings.riskScore += 30;
              } else if (key.bits < 2048) {
                findings.detections.push({
                  name: 'Weak PGP Key Size',
                  description: `${label} uses ${key.bits}-bit ${key.algoName}. NIST and RFC 4880bis recommend a minimum of 2048-bit RSA/DSA.`,
                  severity: 'medium',
                });
                findings.riskScore += 15;
              }
            }
            // Elgamal (sign+encrypt variant, algo 20) is explicitly deprecated
            if (key.algo === 20) {
              findings.detections.push({
                name: 'Deprecated Elgamal Sign+Encrypt Key',
                description: `${label} uses Elgamal (algo 20, encrypt-or-sign). This variant was deprecated and removed in RFC 9580 due to its security implications.`,
                severity: 'medium',
              });
              findings.riskScore += 10;
            }
          }

          // ── v3 / legacy format key ──
          if (primary.version && primary.version < 4) {
            findings.detections.push({
              name: 'Legacy v3 PGP Key',
              description: `Primary key is version ${primary.version}. v3 keys use MD5 fingerprints and pre-date RFC 4880. Modern OpenPGP software has been phasing out v3 support.`,
              severity: 'medium',
            });
            findings.riskScore += 15;
          }

          // ── Revocation check ──
          if (group.signatures.some(s => s.sigType === 0x20)) {
            findings.detections.push({
              name: 'Revoked PGP Key',
              description: `Primary key for ${primaryName} carries a revocation signature. The owner has declared this key compromised or retired.`,
              severity: 'medium',
            });
            findings.riskScore += 10;
          }

          // ── Expiry / never-expires ──
          const selfSig = group.signatures.find(s => s.sigType === 0x1F || (s.sigType >= 0x10 && s.sigType <= 0x13))
                       || group.userIds.flatMap(u => u.signatures).find(s => s.sigType >= 0x10 && s.sigType <= 0x13);
          if (selfSig && selfSig.keyExpires && primary.created) {
            const expiresAt = primary.created + selfSig.keyExpires;
            if (Date.now() / 1000 > expiresAt) {
              findings.detections.push({
                name: 'Expired PGP Key',
                description: `Primary key for ${primaryName} expired on ${this._fmtDate(expiresAt)}.`,
                severity: 'low',
              });
              findings.riskScore += 5;
            }
          } else if (primary.created) {
            const ageYears = (Date.now() / 1000 - primary.created) / (365.25 * 24 * 3600);
            if (ageYears > 10) {
              findings.detections.push({
                name: 'Very Old PGP Key with No Expiry',
                description: `Primary key for ${primaryName} was created ${ageYears.toFixed(1)} years ago (${this._fmtDate(primary.created)}) and carries no expiration. Long-lived keys without expiry are a common operational hygiene issue.`,
                severity: 'low',
              });
              findings.riskScore += 3;
            }
          }

          // ── SHA-1 preferred hash ──
          if (selfSig && selfSig.preferredHash.length && selfSig.preferredHash[0] === 2) {
            findings.detections.push({
              name: 'Weak Preferred Hash (SHA-1)',
              description: `Primary key for ${primaryName} lists SHA-1 as its most preferred hash algorithm. SHA-1 is deprecated for digital signatures.`,
              severity: 'low',
            });
            findings.riskScore += 5;
          }

          // ── Modern crypto — informational (helps analysts spot benign keys) ──
          if (primary.algo === 22 || primary.algo === 27 || primary.algo === 25) {
            findings.detections.push({
              name: 'Modern PGP Key (EdDSA / Curve25519)',
              description: `Primary key uses ${primary.algoName}${primary.curve ? ' on ' + primary.curve : ''}. This is a modern, recommended cryptographic suite.`,
              severity: 'info',
            });
          }

          // ── Format-specific panel info ──
          findings.formatSpecific.push({ label: 'Primary Algorithm', value: primary.algoName || '—' });
          if (primary.bits) findings.formatSpecific.push({ label: 'Key Size', value: `${primary.bits}-bit` });
          if (primary.curve) findings.formatSpecific.push({ label: 'Curve', value: primary.curve });
          if (primary.created) findings.formatSpecific.push({ label: 'Created', value: this._fmtDate(primary.created) });
          findings.formatSpecific.push({ label: 'User IDs', value: String(group.userIds.length) });
          findings.formatSpecific.push({ label: 'Subkeys', value: String(group.subkeys.length) });

          // ── IOC extraction: email addresses ──
          for (const uid of group.userIds) {
            if (uid.email) {
              pushIOC(findings, {
                type: IOC.EMAIL,
                value: uid.email,
                severity: 'info',
                note: 'PGP User ID',
                highlightText: uid.email,
              });
            }
          }
        }
      }

      // ── Summary ──
      const parts = [];
      parts.push(`${totalPrimaries} primary key${totalPrimaries !== 1 ? 's' : ''}`);
      if (totalSubkeys) parts.push(`${totalSubkeys} subkey${totalSubkeys !== 1 ? 's' : ''}`);
      if (totalUserIds) parts.push(`${totalUserIds} user ID${totalUserIds !== 1 ? 's' : ''}`);
      if (hasPrivate) parts.push('🔐 private key material');
      const issues = findings.detections.filter(d => d.severity !== 'info').length;
      findings.summary = parts.join(', ') + (issues ? ` — ${issues} issue${issues > 1 ? 's' : ''}` : '');

      // Risk level
      if (findings.riskScore >= 50) findings.riskLevel = 'critical';
      else if (findings.riskScore >= 30) findings.riskLevel = 'high';
      else if (findings.riskScore >= 10) findings.riskLevel = 'medium';
      else findings.riskLevel = 'low';

      // Normalise to sidebar-compatible shape
      escalateRisk(findings, findings.riskLevel);
      findings.metadata = {};
      for (const fs of findings.formatSpecific) findings.metadata[fs.label] = fs.value;
      findings.externalRefs = findings.detections.map(d => ({
        type: IOC.PATTERN,
        url: `${d.name} — ${d.description}`,
        severity: d.severity,
      }));

      // Mirror classic-pivot fingerprints + Key IDs into the IOC table.
      // The PGP renderer stores these under human-readable labels that
      // match what formatSpecific emitted (e.g. "Fingerprint", "Key ID",
      // "Subkey Fingerprint", "Subkey Key ID"). Only real hex values make
      // it through — placeholder strings like "(computing…)" won't match.
      const fingerprintFields = {};
      for (const key of Object.keys(findings.metadata || {})) {
        if (/fingerprint/i.test(key)) fingerprintFields[key] = IOC.FINGERPRINT;
        else if (/^key id$/i.test(key) || /\bkey id\b/i.test(key)) fingerprintFields[key] = IOC.FINGERPRINT;
      }
      if (Object.keys(fingerprintFields).length) {
        mirrorMetadataIOCs(findings, fingerprintFields);
      }
    } catch (e) {
      findings.summary = `Analysis error: ${e.message}`;
      escalateRisk(findings, findings.riskLevel);
      findings.metadata = {};
      findings.externalRefs = [];
    }

    return findings;
  }
}
