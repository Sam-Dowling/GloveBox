'use strict';
// ════════════════════════════════════════════════════════════════════════════
// x509-renderer.js — X.509 Certificate / PEM / DER / PKCS#12 viewer
// Pure-JS ASN.1/DER parser with certificate field extraction and security
// analysis for SOC/DFIR investigation. No external dependencies.
// ════════════════════════════════════════════════════════════════════════════

class X509Renderer {

  // ── Well-known OIDs ──────────────────────────────────────────────────────
  static OID_MAP = {
    // Distinguished Name attributes
    '2.5.4.3':  'CN',   '2.5.4.4':  'SN',   '2.5.4.5':  'serialNumber',
    '2.5.4.6':  'C',    '2.5.4.7':  'L',    '2.5.4.8':  'ST',
    '2.5.4.9':  'street', '2.5.4.10': 'O',  '2.5.4.11': 'OU',
    '2.5.4.12': 'title', '2.5.4.17': 'postalCode',
    '2.5.4.41': 'name', '2.5.4.42': 'givenName',
    '2.5.4.46': 'dnQualifier',
    '1.2.840.113549.1.9.1': 'emailAddress',
    '0.9.2342.19200300.100.1.25': 'DC',
    // Signature algorithms
    '1.2.840.113549.1.1.1':  'RSA',
    '1.2.840.113549.1.1.4':  'md5WithRSAEncryption',
    '1.2.840.113549.1.1.5':  'sha1WithRSAEncryption',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
    '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.113549.1.1.7':  'RSAES-OAEP',
    '1.2.840.10045.2.1':     'EC Public Key',
    '1.2.840.10045.4.3.2':   'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3':   'ecdsa-with-SHA384',
    '1.2.840.10045.4.3.4':   'ecdsa-with-SHA512',
    '1.3.101.112':            'Ed25519',
    '1.3.101.113':            'Ed448',
    // EC named curves
    '1.2.840.10045.3.1.7':   'P-256 (prime256v1)',
    '1.3.132.0.34':           'P-384 (secp384r1)',
    '1.3.132.0.35':           'P-521 (secp521r1)',
    '1.3.132.0.10':           'secp256k1',
    // Extensions
    '2.5.29.14': 'Subject Key Identifier',
    '2.5.29.15': 'Key Usage',
    '2.5.29.17': 'Subject Alternative Name',
    '2.5.29.18': 'Issuer Alternative Name',
    '2.5.29.19': 'Basic Constraints',
    '2.5.29.31': 'CRL Distribution Points',
    '2.5.29.32': 'Certificate Policies',
    '2.5.29.35': 'Authority Key Identifier',
    '2.5.29.37': 'Extended Key Usage',
    '1.3.6.1.5.5.7.1.1':  'Authority Info Access',
    '1.3.6.1.5.5.7.1.3':  'Qualified Cert Statements',
    '1.3.6.1.4.1.11129.2.4.2': 'SCT List (CT)',
    '2.5.29.9':  'Subject Directory Attributes',
    '2.5.29.30': 'Name Constraints',
    '2.5.29.33': 'Policy Mappings',
    '2.5.29.36': 'Policy Constraints',
    '2.5.29.46': 'Freshest CRL',
    '2.5.29.54': 'Inhibit Any Policy',
    // Extended Key Usage values
    '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication',
    '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication',
    '1.3.6.1.5.5.7.3.3': 'Code Signing',
    '1.3.6.1.5.5.7.3.4': 'Email Protection (S/MIME)',
    '1.3.6.1.5.5.7.3.8': 'Time Stamping',
    '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
    '1.3.6.1.4.1.311.10.3.3': 'Microsoft SGC',
    '1.3.6.1.4.1.311.10.3.4': 'Microsoft EFS',
    '1.3.6.1.4.1.311.2.1.22': 'Microsoft Commercial Code Signing',
    '2.16.840.1.113730.4.1': 'Netscape SGC',
    // Access methods
    '1.3.6.1.5.5.7.48.1': 'OCSP',
    '1.3.6.1.5.5.7.48.2': 'CA Issuers',
    // PKCS#12
    '1.2.840.113549.1.12.10.1.1': 'PKCS#12 Key Bag',
    '1.2.840.113549.1.12.10.1.2': 'PKCS#12 PKCS8 Shrouded Key Bag',
    '1.2.840.113549.1.12.10.1.3': 'PKCS#12 Cert Bag',
    '1.2.840.113549.1.12.10.1.5': 'PKCS#12 Secret Bag',
    '1.2.840.113549.1.12.10.1.6': 'PKCS#12 Safe Contents Bag',
    '1.2.840.113549.1.7.1':  'PKCS#7 Data',
    '1.2.840.113549.1.7.6':  'PKCS#7 Encrypted Data',
  };

  // Key Usage bit definitions (bit 0 = MSB of first octet)
  static KEY_USAGE_BITS = [
    'Digital Signature', 'Non Repudiation', 'Key Encipherment',
    'Data Encipherment', 'Key Agreement', 'Key Cert Sign',
    'CRL Sign', 'Encipher Only', 'Decipher Only',
  ];

  // ── ASN.1/DER Parser ────────────────────────────────────────────────────
  /** Parse a DER-encoded ASN.1 structure from bytes at offset. Returns {tag, constructed, cls, length, value, children, end}. */
  _parseDER(bytes, offset = 0, depth = 0) {
    if (depth > 50) throw new Error('ASN.1 recursion limit exceeded');
    if (offset >= bytes.length) throw new Error('Unexpected end of DER data');

    const startOffset = offset;
    const tagByte = bytes[offset++];
    const cls = (tagByte >> 6) & 3;         // 0=Universal, 1=Application, 2=Context, 3=Private
    const constructed = !!(tagByte & 0x20);
    let tag = tagByte & 0x1F;

    // Long-form tag
    if (tag === 0x1F) {
      tag = 0;
      let b;
      do {
        if (offset >= bytes.length) throw new Error('Truncated tag');
        b = bytes[offset++];
        tag = (tag << 7) | (b & 0x7F);
      } while (b & 0x80);
    }

    // Length
    if (offset >= bytes.length) throw new Error('Truncated length');
    let length = bytes[offset++];
    if (length & 0x80) {
      const numBytes = length & 0x7F;
      if (numBytes === 0) throw new Error('Indefinite length not supported');
      if (numBytes > 4) throw new Error('Length too large');
      length = 0;
      for (let i = 0; i < numBytes; i++) {
        if (offset >= bytes.length) throw new Error('Truncated length');
        length = (length << 8) | bytes[offset++];
      }
    }

    const valueStart = offset;
    const end = offset + length;
    if (end > bytes.length) throw new Error(`ASN.1 value overflows buffer (need ${end}, have ${bytes.length})`);

    const value = bytes.subarray(valueStart, end);
    let children = null;

    // Parse children for constructed types (SEQUENCE, SET, or context-specific constructed)
    if (constructed) {
      children = [];
      let childOffset = valueStart;
      let safetyLimit = 10000;
      while (childOffset < end && --safetyLimit > 0) {
        const child = this._parseDER(bytes, childOffset, depth + 1);
        children.push(child);
        childOffset = child.end;
      }
    }

    return { tag, constructed, cls, length, value, children, end, offset: startOffset, valueStart };
  }

  /** Decode an ASN.1 OID from bytes. */
  _decodeOID(bytes) {
    if (bytes.length === 0) return '';
    const parts = [];
    parts.push(Math.floor(bytes[0] / 40));
    parts.push(bytes[0] % 40);
    let val = 0;
    for (let i = 1; i < bytes.length; i++) {
      val = (val << 7) | (bytes[i] & 0x7F);
      if (!(bytes[i] & 0x80)) {
        parts.push(val);
        val = 0;
      }
    }
    return parts.join('.');
  }

  /** Decode an ASN.1 integer to hex string. */
  _decodeInteger(bytes) {
    // Remove leading zero byte (sign byte) for display
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    return Array.from(bytes.subarray(start)).map(b => b.toString(16).padStart(2, '0')).join(':');
  }

  /** Decode an ASN.1 integer to a JS number (for small values). */
  _decodeSmallInt(bytes) {
    let val = 0;
    for (let i = 0; i < bytes.length && i < 6; i++) {
      val = val * 256 + bytes[i];
    }
    return val;
  }

  /** Decode a BIT STRING — returns the actual bit content (strips unused-bits byte). */
  _decodeBitString(bytes) {
    if (bytes.length < 1) return new Uint8Array(0);
    // First byte is number of unused bits in the last byte
    return bytes.subarray(1);
  }

  /** Decode GeneralizedTime or UTCTime to a readable date string. */
  _decodeTime(bytes, tag) {
    const str = new TextDecoder('ascii').decode(bytes);
    let y, m, d, hh, mm, ss;
    if (tag === 0x17) { // UTCTime: YYMMDDHHMMSSZ
      y = parseInt(str.substring(0, 2), 10);
      y += y < 50 ? 2000 : 1900;
      m  = str.substring(2, 4);
      d  = str.substring(4, 6);
      hh = str.substring(6, 8);
      mm = str.substring(8, 10);
      ss = str.substring(10, 12);
    } else { // GeneralizedTime: YYYYMMDDHHMMSSZ
      y  = str.substring(0, 4);
      m  = str.substring(4, 6);
      d  = str.substring(6, 8);
      hh = str.substring(8, 10);
      mm = str.substring(10, 12);
      ss = str.substring(12, 14);
    }
    return `${y}-${m}-${d} ${hh}:${mm}:${ss} UTC`;
  }

  /** Parse a Date from ASN.1 time bytes. */
  _parseDate(bytes, tag) {
    const str = new TextDecoder('ascii').decode(bytes);
    let y, m, d, hh, mm, ss;
    if (tag === 0x17) {
      y = parseInt(str.substring(0, 2), 10);
      y += y < 50 ? 2000 : 1900;
      m  = parseInt(str.substring(2, 4), 10) - 1;
      d  = parseInt(str.substring(4, 6), 10);
      hh = parseInt(str.substring(6, 8), 10);
      mm = parseInt(str.substring(8, 10), 10);
      ss = parseInt(str.substring(10, 12), 10);
    } else {
      y  = parseInt(str.substring(0, 4), 10);
      m  = parseInt(str.substring(4, 6), 10) - 1;
      d  = parseInt(str.substring(6, 8), 10);
      hh = parseInt(str.substring(8, 10), 10);
      mm = parseInt(str.substring(10, 12), 10);
      ss = parseInt(str.substring(12, 14), 10);
    }
    return new Date(Date.UTC(y, m, d, hh, mm, ss));
  }

  /** Decode ASN.1 string types. */
  _decodeString(node) {
    // UTF8String, PrintableString, IA5String, T61String, BMPString, VisibleString
    if (node.tag === 0x0C || node.tag === 0x13 || node.tag === 0x16 ||
        node.tag === 0x14 || node.tag === 0x1A) {
      return new TextDecoder('utf-8', { fatal: false }).decode(node.value);
    }
    if (node.tag === 0x1E) { // BMPString (UTF-16BE)
      const chars = [];
      for (let i = 0; i < node.value.length - 1; i += 2) {
        chars.push(String.fromCharCode((node.value[i] << 8) | node.value[i + 1]));
      }
      return chars.join('');
    }
    // Fallback
    return new TextDecoder('utf-8', { fatal: false }).decode(node.value);
  }

  /** Lookup OID label. */
  _oidName(oid) {
    return X509Renderer.OID_MAP[oid] || oid;
  }

  // ── PEM / DER Detection ─────────────────────────────────────────────────
  /** Detect and decode PEM blocks from text. Returns array of {label, der}. */
  _decodePEM(text) {
    const blocks = [];
    const re = /-----BEGIN ([A-Z0-9 ]+)-----\r?\n([\s\S]*?)-----END \1-----/g;
    let match;
    while ((match = re.exec(text)) !== null) {
      const label = match[1];
      const b64 = match[2].replace(/[\s\r\n]/g, '');
      try {
        const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        blocks.push({ label, der: bin });
      } catch (e) { /* skip invalid base64 */ }
    }
    return blocks;
  }

  /** Check if bytes look like PEM text. */
  _isPEM(bytes) {
    if (bytes.length < 27) return false;
    const head = new TextDecoder('ascii', { fatal: false }).decode(bytes.subarray(0, Math.min(40, bytes.length)));
    return head.includes('-----BEGIN ');
  }

  /** Check if bytes look like DER-encoded ASN.1 (SEQUENCE tag + long-form length). */
  _isDER(bytes) {
    if (bytes.length < 4) return false;
    // DER SEQUENCE starts with 0x30 and typically has long-form length (0x82 xx xx) for certs
    return bytes[0] === 0x30 && (bytes[1] & 0x80);
  }

  /** Check if bytes look like PKCS#12/PFX container. */
  _isPKCS12(bytes) {
    // PKCS#12 is a DER SEQUENCE containing a specific version + OID structure
    // First must be a SEQUENCE, then contains INTEGER(3) and SEQUENCE with OID 1.2.840.113549.1.7.1
    if (bytes.length < 24 || bytes[0] !== 0x30) return false;
    try {
      const root = this._parseDER(bytes);
      if (!root.children || root.children.length < 2) return false;
      // First child should be INTEGER with value 3
      const ver = root.children[0];
      if (ver.tag === 0x02) {
        const v = this._decodeSmallInt(ver.value);
        if (v === 3) {
          // Second child should be a SEQUENCE with OID 1.2.840.113549.1.7.1
          const authSafe = root.children[1];
          if (authSafe.tag === 0x06 || (authSafe.children && authSafe.children[0] && authSafe.children[0].tag === 0x06)) {
            return true;
          }
        }
      }
    } catch (e) { /* not PKCS#12 */ }
    return false;
  }

  // ── Certificate Parsing ─────────────────────────────────────────────────
  /** Parse X.509 certificate from DER bytes. Returns structured cert object. */
  _parseCertificate(der) {
    const root = this._parseDER(der);
    if (root.tag !== 0x10 || !root.constructed) throw new Error('Not a valid ASN.1 SEQUENCE');
    if (!root.children || root.children.length < 3) throw new Error('Certificate structure incomplete');

    const tbsCert = root.children[0];       // TBSCertificate
    const sigAlg  = root.children[1];       // Signature algorithm
    const sigVal  = root.children[2];       // Signature value

    if (!tbsCert.children) throw new Error('TBSCertificate has no children');

    const cert = {
      version: 1,
      serialNumber: '',
      signatureAlgorithm: '',
      signatureAlgorithmOID: '',
      issuer: {},
      issuerStr: '',
      subject: {},
      subjectStr: '',
      notBefore: null,
      notBeforeStr: '',
      notAfter: null,
      notAfterStr: '',
      publicKeyAlgorithm: '',
      publicKeyAlgorithmOID: '',
      publicKeySize: null,
      publicKeyCurve: '',
      publicKeyBytes: null,
      extensions: [],
      isSelfSigned: false,
      isCA: false,
      sha1: '',
      sha256: '',
      derBytes: der,
    };

    let idx = 0;

    // Version (explicit tag [0])
    if (tbsCert.children[idx] && tbsCert.children[idx].cls === 2 && tbsCert.children[idx].tag === 0) {
      const verNode = tbsCert.children[idx].children ? tbsCert.children[idx].children[0] : null;
      if (verNode) cert.version = this._decodeSmallInt(verNode.value) + 1;
      idx++;
    }

    // Serial Number
    if (tbsCert.children[idx] && tbsCert.children[idx].tag === 0x02) {
      cert.serialNumber = this._decodeInteger(tbsCert.children[idx].value).toUpperCase();
      idx++;
    }

    // Signature Algorithm (inner)
    if (tbsCert.children[idx]) {
      const algNode = tbsCert.children[idx];
      if (algNode.children && algNode.children[0]) {
        const oid = this._decodeOID(algNode.children[0].value);
        cert.signatureAlgorithmOID = oid;
        cert.signatureAlgorithm = this._oidName(oid);
      }
      idx++;
    }

    // Issuer
    if (tbsCert.children[idx]) {
      cert.issuer = this._parseDN(tbsCert.children[idx]);
      cert.issuerStr = this._dnToString(cert.issuer);
      idx++;
    }

    // Validity
    if (tbsCert.children[idx] && tbsCert.children[idx].children) {
      const validity = tbsCert.children[idx].children;
      if (validity[0]) {
        cert.notBeforeStr = this._decodeTime(validity[0].value, validity[0].tag);
        cert.notBefore = this._parseDate(validity[0].value, validity[0].tag);
      }
      if (validity[1]) {
        cert.notAfterStr = this._decodeTime(validity[1].value, validity[1].tag);
        cert.notAfter = this._parseDate(validity[1].value, validity[1].tag);
      }
      idx++;
    }

    // Subject
    if (tbsCert.children[idx]) {
      cert.subject = this._parseDN(tbsCert.children[idx]);
      cert.subjectStr = this._dnToString(cert.subject);
      idx++;
    }

    // Subject Public Key Info
    if (tbsCert.children[idx] && tbsCert.children[idx].children) {
      const spki = tbsCert.children[idx].children;
      // Algorithm
      if (spki[0] && spki[0].children && spki[0].children[0]) {
        const oid = this._decodeOID(spki[0].children[0].value);
        cert.publicKeyAlgorithmOID = oid;
        cert.publicKeyAlgorithm = this._oidName(oid);
        // EC curve parameter
        if (spki[0].children[1] && spki[0].children[1].tag === 0x06) {
          const curveOid = this._decodeOID(spki[0].children[1].value);
          cert.publicKeyCurve = this._oidName(curveOid);
        }
      }
      // Public key bits
      if (spki[1] && spki[1].tag === 0x03) {
        const keyBits = this._decodeBitString(spki[1].value);
        cert.publicKeyBytes = keyBits;
        // Determine key size
        if (cert.publicKeyAlgorithm === 'RSA') {
          // RSA public key is a SEQUENCE { modulus INTEGER, exponent INTEGER }
          try {
            const rsaKey = this._parseDER(keyBits);
            if (rsaKey.children && rsaKey.children[0]) {
              // Modulus bit length (subtract leading zero byte if present)
              const mod = rsaKey.children[0].value;
              let bitLen = mod.length * 8;
              if (mod[0] === 0 && mod.length > 1) bitLen -= 8;
              cert.publicKeySize = bitLen;
            }
          } catch (e) { /* can't parse RSA key */ }
        } else if (cert.publicKeyAlgorithm === 'EC Public Key') {
          // EC key size from curve name or uncompressed point length
          if (cert.publicKeyCurve.includes('256')) cert.publicKeySize = 256;
          else if (cert.publicKeyCurve.includes('384')) cert.publicKeySize = 384;
          else if (cert.publicKeyCurve.includes('521')) cert.publicKeySize = 521;
          else cert.publicKeySize = (keyBits.length - 1) * 4; // approximate from uncompressed point
        } else if (cert.publicKeyAlgorithm === 'Ed25519') {
          cert.publicKeySize = 256;
        } else if (cert.publicKeyAlgorithm === 'Ed448') {
          cert.publicKeySize = 448;
        }
      }
      idx++;
    }

    // Extensions (explicit tag [3])
    for (let i = idx; i < tbsCert.children.length; i++) {
      const node = tbsCert.children[i];
      if (node.cls === 2 && node.tag === 3 && node.children) {
        // Extensions is a SEQUENCE of SEQUENCE
        const extsSeq = node.children[0];
        if (extsSeq && extsSeq.children) {
          for (const extNode of extsSeq.children) {
            if (extNode.children) {
              cert.extensions.push(this._parseExtension(extNode));
            }
          }
        }
      }
    }

    // Self-signed detection
    cert.isSelfSigned = cert.issuerStr === cert.subjectStr;

    // CA detection from Basic Constraints
    const bc = cert.extensions.find(e => e.oid === '2.5.29.19');
    if (bc && bc.isCA) cert.isCA = true;

    return cert;
  }

  /** Parse a Distinguished Name (SEQUENCE of SET of SEQUENCE { OID, value }). */
  _parseDN(node) {
    const dn = {};
    if (!node.children) return dn;
    for (const rdnSet of node.children) {
      if (!rdnSet.children) continue;
      for (const attrSeq of rdnSet.children) {
        if (!attrSeq.children || attrSeq.children.length < 2) continue;
        const oid = this._decodeOID(attrSeq.children[0].value);
        const label = this._oidName(oid);
        const val = this._decodeString(attrSeq.children[1]);
        if (dn[label]) {
          // Multiple values for same attribute
          if (Array.isArray(dn[label])) dn[label].push(val);
          else dn[label] = [dn[label], val];
        } else {
          dn[label] = val;
        }
      }
    }
    return dn;
  }

  /** Format a DN object as a readable string. */
  _dnToString(dn) {
    const order = ['CN', 'O', 'OU', 'L', 'ST', 'C', 'emailAddress', 'DC'];
    const parts = [];
    for (const key of order) {
      if (dn[key]) {
        const vals = Array.isArray(dn[key]) ? dn[key] : [dn[key]];
        for (const v of vals) parts.push(`${key}=${v}`);
      }
    }
    // Add any remaining keys not in the standard order
    for (const key of Object.keys(dn)) {
      if (!order.includes(key)) {
        const vals = Array.isArray(dn[key]) ? dn[key] : [dn[key]];
        for (const v of vals) parts.push(`${key}=${v}`);
      }
    }
    return parts.join(', ');
  }

  /** Parse a single X.509 extension. */
  _parseExtension(extNode) {
    const ext = { oid: '', name: '', critical: false, value: null, raw: null };
    let idx = 0;

    // OID
    if (extNode.children[idx] && extNode.children[idx].tag === 0x06) {
      ext.oid = this._decodeOID(extNode.children[idx].value);
      ext.name = this._oidName(ext.oid);
      idx++;
    }

    // Critical flag (optional BOOLEAN)
    if (extNode.children[idx] && extNode.children[idx].tag === 0x01) {
      ext.critical = extNode.children[idx].value[0] !== 0;
      idx++;
    }

    // Value (OCTET STRING wrapping extension-specific ASN.1)
    if (extNode.children[idx] && extNode.children[idx].tag === 0x04) {
      ext.raw = extNode.children[idx].value;
      try {
        this._parseExtensionValue(ext);
      } catch (e) {
        ext.value = this._hexDump(ext.raw);
      }
    }

    return ext;
  }

  /** Parse extension-specific value from the OCTET STRING content. */
  _parseExtensionValue(ext) {
    const inner = this._parseDER(ext.raw);

    switch (ext.oid) {
      case '2.5.29.19': // Basic Constraints
        ext.isCA = false;
        ext.pathLength = null;
        if (inner.children) {
          if (inner.children[0] && inner.children[0].tag === 0x01) {
            ext.isCA = inner.children[0].value[0] !== 0;
          }
          if (inner.children[1] && inner.children[1].tag === 0x02) {
            ext.pathLength = this._decodeSmallInt(inner.children[1].value);
          }
        }
        ext.value = ext.isCA ? `CA: TRUE${ext.pathLength !== null ? `, pathlen: ${ext.pathLength}` : ''}` : 'CA: FALSE';
        break;

      case '2.5.29.15': // Key Usage
        if (inner.tag === 0x03) {
          const bits = this._decodeBitString(inner.value);
          const usages = [];
          for (let i = 0; i < X509Renderer.KEY_USAGE_BITS.length && i < bits.length * 8; i++) {
            const byteIdx = Math.floor(i / 8);
            const bitIdx = 7 - (i % 8);
            if (bits[byteIdx] & (1 << bitIdx)) {
              usages.push(X509Renderer.KEY_USAGE_BITS[i]);
            }
          }
          ext.keyUsages = usages;
          ext.value = usages.join(', ') || '(none)';
        }
        break;

      case '2.5.29.37': // Extended Key Usage
        if (inner.children) {
          const usages = inner.children
            .filter(c => c.tag === 0x06)
            .map(c => this._oidName(this._decodeOID(c.value)));
          ext.extKeyUsages = usages;
          ext.value = usages.join(', ') || '(none)';
        }
        break;

      case '2.5.29.17': // Subject Alternative Name
      case '2.5.29.18': // Issuer Alternative Name
        ext.altNames = this._parseGeneralNames(inner);
        ext.value = ext.altNames.map(n => `${n.type}: ${n.value}`).join(', ');
        break;

      case '2.5.29.14': // Subject Key Identifier
        if (inner.tag === 0x04) {
          ext.value = Array.from(inner.value).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
        }
        break;

      case '2.5.29.35': // Authority Key Identifier
        if (inner.children) {
          for (const child of inner.children) {
            if (child.cls === 2 && child.tag === 0) {
              ext.keyId = Array.from(child.value).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
              ext.value = `KeyID: ${ext.keyId}`;
            }
          }
        }
        if (!ext.value) ext.value = this._hexDump(ext.raw);
        break;

      case '2.5.29.31': // CRL Distribution Points
        ext.crlPoints = [];
        if (inner.children) {
          for (const dp of inner.children) {
            if (dp.children) {
              for (const dpn of dp.children) {
                if (dpn.cls === 2 && dpn.tag === 0 && dpn.children) {
                  for (const gn of dpn.children) {
                    if (gn.cls === 2 && gn.tag === 6) { // uniformResourceIdentifier
                      const uri = X509Renderer._cleanDerUri(new TextDecoder('ascii').decode(gn.value));
                      ext.crlPoints.push(uri);
                    }
                  }
                }
              }
            }
          }
        }
        ext.value = ext.crlPoints.join(', ') || this._hexDump(ext.raw);
        break;

      case '1.3.6.1.5.5.7.1.1': // Authority Information Access
        ext.accessMethods = [];
        if (inner.children) {
          for (const am of inner.children) {
            if (am.children && am.children.length >= 2) {
              const methodOid = this._decodeOID(am.children[0].value);
              const methodName = this._oidName(methodOid);
              let location = '';
              if (am.children[1].cls === 2 && am.children[1].tag === 6) {
                location = X509Renderer._cleanDerUri(new TextDecoder('ascii').decode(am.children[1].value));
              }
              ext.accessMethods.push({ method: methodName, location });
            }
          }
        }
        ext.value = ext.accessMethods.map(a => `${a.method}: ${a.location}`).join(', ') || this._hexDump(ext.raw);
        break;

      case '2.5.29.32': // Certificate Policies
        ext.policies = [];
        if (inner.children) {
          for (const pi of inner.children) {
            if (pi.children && pi.children[0] && pi.children[0].tag === 0x06) {
              ext.policies.push(this._decodeOID(pi.children[0].value));
            }
          }
        }
        ext.value = ext.policies.join(', ') || this._hexDump(ext.raw);
        break;

      default:
        ext.value = this._hexDump(ext.raw.subarray(0, Math.min(64, ext.raw.length)));
        if (ext.raw.length > 64) ext.value += '…';
        break;
    }
  }

  /** Parse GeneralNames from a SEQUENCE. */
  _parseGeneralNames(seq) {
    const names = [];
    if (!seq.children) return names;
    for (const gn of seq.children) {
      if (gn.cls === 2) {
        switch (gn.tag) {
          case 1: // rfc822Name (email)
            names.push({ type: 'Email', value: new TextDecoder('ascii').decode(gn.value) });
            break;
          case 2: // dNSName
            names.push({ type: 'DNS', value: new TextDecoder('ascii').decode(gn.value) });
            break;
          case 4: // directoryName
            try {
              const dn = this._parseDN(this._parseDER(gn.value));
              names.push({ type: 'DirName', value: this._dnToString(dn) });
            } catch (e) {
              names.push({ type: 'DirName', value: this._hexDump(gn.value) });
            }
            break;
          case 6: // uniformResourceIdentifier
            names.push({ type: 'URI', value: X509Renderer._cleanDerUri(new TextDecoder('ascii').decode(gn.value)) });
            break;
          case 7: // iPAddress
            if (gn.value.length === 4) {
              names.push({ type: 'IP', value: gn.value.join('.') });
            } else if (gn.value.length === 16) {
              const parts = [];
              for (let i = 0; i < 16; i += 2) parts.push(((gn.value[i] << 8) | gn.value[i+1]).toString(16));
              names.push({ type: 'IP', value: parts.join(':') });
            } else {
              names.push({ type: 'IP', value: this._hexDump(gn.value) });
            }
            break;
          default:
            names.push({ type: `[${gn.tag}]`, value: this._hexDump(gn.value) });
        }
      }
    }
    return names;
  }

  /** Format bytes as a hex dump string. */
  _hexDump(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
  }

  // ── Fingerprint Computation ─────────────────────────────────────────────
  /** Compute SHA-1 and SHA-256 fingerprints of DER bytes. Returns {sha1, sha256}. */
  async _computeFingerprints(der) {
    try {
      const [s1, s256] = await Promise.all([
        crypto.subtle.digest('SHA-1', der),
        crypto.subtle.digest('SHA-256', der),
      ]);
      const hex = b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0').toUpperCase()).join(':');
      return { sha1: hex(s1), sha256: hex(s256) };
    } catch (e) {
      return { sha1: '(unavailable)', sha256: '(unavailable)' };
    }
  }

  // ── PKCS#12 Metadata ───────────────────────────────────────────────────
  /** Extract metadata from a PKCS#12/PFX container (without decryption). */
  _parsePKCS12Metadata(bytes) {
    const info = { version: null, bagTypes: [], macAlgorithm: '', encrypted: true };
    try {
      const root = this._parseDER(bytes);
      if (!root.children) return info;
      // Version
      if (root.children[0] && root.children[0].tag === 0x02) {
        info.version = this._decodeSmallInt(root.children[0].value);
      }
      // AuthenticatedSafe content type
      if (root.children[1] && root.children[1].children) {
        const contentType = root.children[1].children[0];
        if (contentType && contentType.tag === 0x06) {
          info.contentOID = this._oidName(this._decodeOID(contentType.value));
        }
      }
      // MAC data (last child if SEQUENCE with digest info)
      const lastChild = root.children[root.children.length - 1];
      if (lastChild && lastChild.children && lastChild.children.length >= 2) {
        // Try to find digest algorithm in MAC data
        const macData = lastChild;
        if (macData.children[0] && macData.children[0].children) {
          const digestAlg = macData.children[0].children[0];
          if (digestAlg && digestAlg.children && digestAlg.children[0] && digestAlg.children[0].tag === 0x06) {
            info.macAlgorithm = this._oidName(this._decodeOID(digestAlg.children[0].value));
          }
        }
      }
    } catch (e) { /* partial parse is fine */ }
    return info;
  }

  // ── Render ──────────────────────────────────────────────────────────────
  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer || buffer);
    const wrap = document.createElement('div');
    wrap.className = 'x509-view';

    try {
      // Detect format: PEM, PKCS#12, or DER
      if (this._isPEM(bytes)) {
        const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        const blocks = this._decodePEM(text);
        if (blocks.length === 0) throw new Error('No valid PEM blocks found');

        // Banner
        const banner = document.createElement('div');
        banner.className = 'x509-banner';
        banner.textContent = `📜 PEM File — ${blocks.length} block${blocks.length > 1 ? 's' : ''} detected`;
        wrap.appendChild(banner);

        // Process each PEM block
        for (let i = 0; i < blocks.length; i++) {
          const block = blocks[i];
          const blockWrap = document.createElement('div');
          blockWrap.className = 'x509-block';

          if (block.label === 'CERTIFICATE' || block.label === 'X509 CERTIFICATE' || block.label === 'TRUSTED CERTIFICATE') {
            try {
              const cert = this._parseCertificate(block.der);
              this._renderCertificate(cert, blockWrap, i + 1, blocks.length);
            } catch (e) {
              this._renderGenericPEM(block, blockWrap, `Parse error: ${e.message}`);
            }
          } else {
            this._renderGenericPEM(block, blockWrap);
          }
          wrap.appendChild(blockWrap);
        }
      } else if (this._isPKCS12(bytes)) {
        this._renderPKCS12(bytes, wrap, fileName);
      } else if (this._isDER(bytes)) {
        // Try to parse as certificate
        const banner = document.createElement('div');
        banner.className = 'x509-banner';
        banner.textContent = '📜 DER-Encoded Certificate';
        wrap.appendChild(banner);

        const blockWrap = document.createElement('div');
        blockWrap.className = 'x509-block';
        const cert = this._parseCertificate(bytes);
        this._renderCertificate(cert, blockWrap, 1, 1);
        wrap.appendChild(blockWrap);
      } else {
        throw new Error('File does not appear to be a valid PEM, DER, or PKCS#12 certificate');
      }

      // Trigger async fingerprint computation
      this._computeAllFingerprints(wrap);

    } catch (e) {
      const errDiv = document.createElement('div');
      errDiv.className = 'x509-error';
      errDiv.textContent = `⚠ Certificate parse error: ${e.message}`;
      wrap.appendChild(errDiv);

      // Show hex dump of first 256 bytes
      const hexDiv = document.createElement('div');
      hexDiv.className = 'x509-hex';
      const hexPre = document.createElement('pre');
      hexPre.textContent = this._formatHexBlock(bytes.subarray(0, Math.min(256, bytes.length)));
      hexDiv.appendChild(hexPre);
      wrap.appendChild(hexDiv);
    }

    return wrap;
  }

  /** Render a parsed certificate into a container element. */
  _renderCertificate(cert, container, index, total) {
    // Header
    const header = document.createElement('div');
    header.className = 'x509-cert-header';
    const titleParts = [];
    if (total > 1) titleParts.push(`Certificate #${index}`);
    if (cert.subject.CN) titleParts.push(cert.subject.CN);
    else if (cert.subjectStr) titleParts.push(cert.subjectStr.substring(0, 60));
    else titleParts.push('(unnamed)');
    header.textContent = titleParts.join(' — ');
    container.appendChild(header);

    // Status badges
    const badges = document.createElement('div');
    badges.className = 'x509-badges';
    this._renderBadges(cert, badges);
    container.appendChild(badges);

    // Info table
    const table = document.createElement('table');
    table.className = 'x509-info-table';

    // Subject
    this._addRow(table, 'Subject', cert.subjectStr || '(empty)');

    // Issuer
    this._addRow(table, 'Issuer', cert.issuerStr || '(empty)');

    // Version
    this._addRow(table, 'Version', `v${cert.version}`);

    // Serial Number
    this._addRow(table, 'Serial Number', cert.serialNumber || '(none)');

    // Validity
    const now = new Date();
    let validityClass = 'x509-valid';
    let validityLabel = '✅ Valid';
    if (cert.notAfter && now > cert.notAfter) {
      validityClass = 'x509-expired';
      validityLabel = '❌ Expired';
    } else if (cert.notBefore && now < cert.notBefore) {
      validityClass = 'x509-not-yet-valid';
      validityLabel = '⏳ Not Yet Valid';
    }

    const validityStr = `${cert.notBeforeStr || '?'} → ${cert.notAfterStr || '?'}`;
    const validityTd = this._addRow(table, 'Validity', '');
    const validitySpan = document.createElement('span');
    validitySpan.className = validityClass;
    validitySpan.textContent = `${validityLabel}  ·  ${validityStr}`;
    if (cert.notBefore && cert.notAfter) {
      const days = Math.round((cert.notAfter - cert.notBefore) / (1000 * 60 * 60 * 24));
      const remaining = cert.notAfter > now ? Math.round((cert.notAfter - now) / (1000 * 60 * 60 * 24)) : 0;
      validitySpan.textContent += `  (${days} day validity`;
      if (cert.notAfter > now) validitySpan.textContent += `, ${remaining} days remaining`;
      validitySpan.textContent += ')';
    }
    validityTd.textContent = '';
    validityTd.appendChild(validitySpan);

    // Signature Algorithm
    this._addRow(table, 'Signature Algorithm', cert.signatureAlgorithm || cert.signatureAlgorithmOID || '(unknown)');

    // Public Key
    let pkStr = cert.publicKeyAlgorithm || '(unknown)';
    if (cert.publicKeySize) pkStr += ` ${cert.publicKeySize}-bit`;
    if (cert.publicKeyCurve) pkStr += ` (${cert.publicKeyCurve})`;
    this._addRow(table, 'Public Key', pkStr);

    // Fingerprints (populated async)
    const sha1Td = this._addRow(table, 'SHA-1 Fingerprint', '(computing…)');
    sha1Td.className += ' x509-fingerprint';
    sha1Td.dataset.fpType = 'sha1';
    sha1Td.dataset.certIndex = index;

    const sha256Td = this._addRow(table, 'SHA-256 Fingerprint', '(computing…)');
    sha256Td.className += ' x509-fingerprint';
    sha256Td.dataset.fpType = 'sha256';
    sha256Td.dataset.certIndex = index;

    container.appendChild(table);

    // Store DER bytes for fingerprint computation
    container.dataset.certIndex = index;
    container._certDER = cert.derBytes;

    // Extensions
    if (cert.extensions.length > 0) {
      const extDetails = document.createElement('details');
      extDetails.className = 'x509-extensions';
      extDetails.open = true;
      const extSummary = document.createElement('summary');
      extSummary.textContent = `Extensions (${cert.extensions.length})`;
      extDetails.appendChild(extSummary);

      const extTable = document.createElement('table');
      extTable.className = 'x509-ext-table';

      for (const ext of cert.extensions) {
        const tr = document.createElement('tr');
        const tdName = document.createElement('td');
        tdName.className = 'x509-ext-name';
        tdName.textContent = ext.name || ext.oid;
        if (ext.critical) {
          const critBadge = document.createElement('span');
          critBadge.className = 'x509-critical';
          critBadge.textContent = 'CRITICAL';
          tdName.appendChild(document.createTextNode(' '));
          tdName.appendChild(critBadge);
        }
        const tdVal = document.createElement('td');
        tdVal.className = 'x509-ext-val';

        // Special rendering for SANs
        if ((ext.oid === '2.5.29.17' || ext.oid === '2.5.29.18') && ext.altNames) {
          for (const an of ext.altNames) {
            const line = document.createElement('div');
            line.className = 'x509-san-entry';
            const typeBadge = document.createElement('span');
            typeBadge.className = 'x509-san-type';
            typeBadge.textContent = an.type;
            line.appendChild(typeBadge);
            line.appendChild(document.createTextNode(' ' + an.value));
            tdVal.appendChild(line);
          }
        } else if (ext.oid === '1.3.6.1.5.5.7.1.1' && ext.accessMethods) {
          for (const am of ext.accessMethods) {
            const line = document.createElement('div');
            line.textContent = `${am.method}: ${am.location}`;
            tdVal.appendChild(line);
          }
        } else if (ext.oid === '2.5.29.31' && ext.crlPoints) {
          for (const uri of ext.crlPoints) {
            const line = document.createElement('div');
            line.textContent = uri;
            tdVal.appendChild(line);
          }
        } else {
          tdVal.textContent = ext.value || '(empty)';
        }

        tr.appendChild(tdName);
        tr.appendChild(tdVal);
        extTable.appendChild(tr);
      }

      extDetails.appendChild(extTable);
      container.appendChild(extDetails);
    }
  }

  /** Render status badges for a certificate. */
  _renderBadges(cert, container) {
    const add = (text, cls) => {
      const badge = document.createElement('span');
      badge.className = `x509-badge ${cls}`;
      badge.textContent = text;
      container.appendChild(badge);
    };

    // Version
    add(`v${cert.version}`, 'x509-badge-version');

    // Self-signed
    if (cert.isSelfSigned) add('Self-Signed', 'x509-badge-self-signed');

    // CA
    if (cert.isCA) add('CA', 'x509-badge-ca');

    // Key algorithm
    if (cert.publicKeyAlgorithm) {
      let keyLabel = cert.publicKeyAlgorithm;
      if (cert.publicKeySize) keyLabel += ` ${cert.publicKeySize}`;
      add(keyLabel, 'x509-badge-key');
    }

    // Validity status
    const now = new Date();
    if (cert.notAfter && now > cert.notAfter) {
      add('Expired', 'x509-badge-expired');
    } else if (cert.notBefore && now < cert.notBefore) {
      add('Not Yet Valid', 'x509-badge-not-yet');
    } else if (cert.notBefore && cert.notAfter) {
      add('Valid', 'x509-badge-valid');
    }

    // Weak algorithms
    const weakSig = cert.signatureAlgorithm.toLowerCase();
    if (weakSig.includes('md5') || weakSig.includes('md2')) {
      add('Weak Signature (MD5)', 'x509-badge-weak');
    } else if (weakSig.includes('sha1')) {
      add('Weak Signature (SHA-1)', 'x509-badge-weak');
    }

    // Weak key size
    if (cert.publicKeyAlgorithm === 'RSA' && cert.publicKeySize && cert.publicKeySize < 2048) {
      add(`Weak Key (${cert.publicKeySize}-bit)`, 'x509-badge-weak');
    }
    if (cert.publicKeyAlgorithm === 'EC Public Key' && cert.publicKeySize && cert.publicKeySize < 256) {
      add(`Weak Key (${cert.publicKeySize}-bit)`, 'x509-badge-weak');
    }

    // Wildcard
    const cn = cert.subject.CN || '';
    const sans = cert.extensions.find(e => e.oid === '2.5.29.17');
    if (cn.startsWith('*.') || (sans && sans.altNames && sans.altNames.some(n => n.value.startsWith('*.')))) {
      add('Wildcard', 'x509-badge-wildcard');
    }
  }

  /** Render a non-certificate PEM block (key, CSR, etc.). */
  _renderGenericPEM(block, container, error) {
    const header = document.createElement('div');
    header.className = 'x509-cert-header x509-generic';
    header.textContent = `📄 ${block.label}`;
    container.appendChild(header);

    if (error) {
      const errDiv = document.createElement('div');
      errDiv.className = 'x509-error';
      errDiv.textContent = error;
      container.appendChild(errDiv);
    }

    const infoTable = document.createElement('table');
    infoTable.className = 'x509-info-table';
    this._addRow(infoTable, 'Type', block.label);
    this._addRow(infoTable, 'Size', `${block.der.length} bytes`);
    container.appendChild(infoTable);

    // Show hex preview
    const hexDetails = document.createElement('details');
    hexDetails.className = 'x509-hex-details';
    const hexSummary = document.createElement('summary');
    hexSummary.textContent = 'DER Hex Preview';
    hexDetails.appendChild(hexSummary);
    const pre = document.createElement('pre');
    pre.className = 'x509-hex';
    pre.textContent = this._formatHexBlock(block.der.subarray(0, Math.min(256, block.der.length)));
    if (block.der.length > 256) pre.textContent += '\n…';
    hexDetails.appendChild(pre);
    container.appendChild(hexDetails);
  }

  /** Render PKCS#12/PFX container metadata. */
  _renderPKCS12(bytes, wrap, fileName) {
    const banner = document.createElement('div');
    banner.className = 'x509-banner x509-pkcs12-banner';
    banner.textContent = '🔐 PKCS#12 / PFX Container (Password-Protected)';
    wrap.appendChild(banner);

    const info = this._parsePKCS12Metadata(bytes);

    const notice = document.createElement('div');
    notice.className = 'x509-pkcs12-notice';
    notice.textContent = 'This is an encrypted PKCS#12 container. Certificate contents cannot be extracted without the password. Metadata shown below.';
    wrap.appendChild(notice);

    const table = document.createElement('table');
    table.className = 'x509-info-table';
    this._addRow(table, 'Format', 'PKCS#12 / PFX');
    if (info.version) this._addRow(table, 'Version', String(info.version));
    this._addRow(table, 'File Size', `${bytes.length.toLocaleString()} bytes`);
    if (info.macAlgorithm) this._addRow(table, 'MAC Algorithm', info.macAlgorithm);
    this._addRow(table, 'Encrypted', 'Yes');
    wrap.appendChild(table);
  }

  /** Add a row to an info table, returns the value TD element. */
  _addRow(table, label, value) {
    const tr = document.createElement('tr');
    const tdL = document.createElement('td');
    tdL.className = 'x509-lbl';
    tdL.textContent = label;
    const tdV = document.createElement('td');
    tdV.className = 'x509-val';
    tdV.textContent = value;
    tr.appendChild(tdL);
    tr.appendChild(tdV);
    table.appendChild(tr);
    return tdV;
  }

  /** Format bytes as a multi-line hex block with ASCII column. */
  _formatHexBlock(bytes) {
    const lines = [];
    for (let i = 0; i < bytes.length; i += 16) {
      const chunk = bytes.subarray(i, Math.min(i + 16, bytes.length));
      const offset = i.toString(16).padStart(8, '0');
      const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, '0')).join(' ');
      const ascii = Array.from(chunk).map(b => b >= 0x20 && b < 0x7F ? String.fromCharCode(b) : '.').join('');
      lines.push(`${offset}  ${hex.padEnd(48)}  ${ascii}`);
    }
    return lines.join('\n');
  }

  /** Compute fingerprints for all certs in the view and update the DOM. */
  async _computeAllFingerprints(wrap) {
    const blocks = wrap.querySelectorAll('.x509-block');
    for (const block of blocks) {
      if (!block._certDER) continue;
      const fp = await this._computeFingerprints(block._certDER);
      const index = block.dataset.certIndex;
      const sha1Td = wrap.querySelector(`.x509-fingerprint[data-fp-type="sha1"][data-cert-index="${index}"]`);
      const sha256Td = wrap.querySelector(`.x509-fingerprint[data-fp-type="sha256"][data-cert-index="${index}"]`);
      if (sha1Td) sha1Td.textContent = fp.sha1;
      if (sha256Td) sha256Td.textContent = fp.sha256;
    }
  }

  // ── Security Analysis ───────────────────────────────────────────────────
  analyzeForSecurity(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer || buffer);
    const findings = {
      detections: [],
      interestingStrings: [],
      riskLevel: 'low',
      riskScore: 0,
      summary: '',
      formatSpecific: [],
    };

    try {
      let certs = [];

      if (this._isPEM(bytes)) {
        const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        const blocks = this._decodePEM(text);
        for (const block of blocks) {
          if (block.label === 'CERTIFICATE' || block.label === 'X509 CERTIFICATE' || block.label === 'TRUSTED CERTIFICATE') {
            try { certs.push(this._parseCertificate(block.der)); } catch (e) { /* skip */ }
          }
          // Flag private keys
          if (block.label.includes('PRIVATE KEY')) {
            findings.detections.push({
              name: 'Private Key Detected',
              description: `File contains a ${block.label} (${block.der.length} bytes). Private keys should never be shared or stored unprotected.`,
              severity: 'high',
            });
            findings.riskScore += 40;
          }
        }
      } else if (this._isPKCS12(bytes)) {
        findings.formatSpecific.push({ label: 'Format', value: 'PKCS#12 / PFX (encrypted container)' });
        findings.formatSpecific.push({ label: 'Contains', value: 'Certificates + private keys (password-protected)' });
        findings.detections.push({
          name: 'PKCS#12 Container',
          description: 'Password-protected PKCS#12/PFX file — may contain private keys and certificates.',
          severity: 'info',
        });
        findings.summary = 'PKCS#12/PFX container';
        return findings;
      } else if (this._isDER(bytes)) {
        try { certs.push(this._parseCertificate(bytes)); } catch (e) { /* skip */ }
      }

      if (certs.length === 0) {
        findings.summary = 'No certificates could be parsed';
        return findings;
      }

      // Analyze each certificate
      for (const cert of certs) {
        const cn = cert.subject.CN || cert.subjectStr || '(unnamed)';
        const now = new Date();

        // ── Self-signed ──
        if (cert.isSelfSigned && !cert.isCA) {
          findings.detections.push({
            name: 'Self-Signed Certificate',
            description: `"${cn}" is self-signed (issuer matches subject). Common for C2 infrastructure, development servers, and malicious redirectors.`,
            severity: 'medium',
          });
          findings.riskScore += 15;
        }

        // ── Expired ──
        if (cert.notAfter && now > cert.notAfter) {
          const daysExpired = Math.round((now - cert.notAfter) / (1000 * 60 * 60 * 24));
          findings.detections.push({
            name: 'Expired Certificate',
            description: `"${cn}" expired ${daysExpired} days ago (${cert.notAfterStr}).`,
            severity: 'low',
          });
          findings.riskScore += 5;
        }

        // ── Not yet valid ──
        if (cert.notBefore && now < cert.notBefore) {
          findings.detections.push({
            name: 'Certificate Not Yet Valid',
            description: `"${cn}" is not valid until ${cert.notBeforeStr}.`,
            severity: 'medium',
          });
          findings.riskScore += 10;
        }

        // ── Weak signature algorithm ──
        const sigLow = cert.signatureAlgorithm.toLowerCase();
        if (sigLow.includes('md5') || sigLow.includes('md2')) {
          findings.detections.push({
            name: 'Critically Weak Signature Algorithm',
            description: `"${cn}" uses ${cert.signatureAlgorithm} which is cryptographically broken. Susceptible to collision attacks.`,
            severity: 'high',
          });
          findings.riskScore += 30;
        } else if (sigLow.includes('sha1')) {
          findings.detections.push({
            name: 'Weak Signature Algorithm',
            description: `"${cn}" uses ${cert.signatureAlgorithm}. SHA-1 is deprecated and considered insecure for digital signatures.`,
            severity: 'medium',
          });
          findings.riskScore += 15;
        }

        // ── Weak key size ──
        if (cert.publicKeyAlgorithm === 'RSA' && cert.publicKeySize) {
          if (cert.publicKeySize < 1024) {
            findings.detections.push({
              name: 'Critically Weak RSA Key',
              description: `"${cn}" uses ${cert.publicKeySize}-bit RSA. Keys under 1024-bit can be factored.`,
              severity: 'high',
            });
            findings.riskScore += 30;
          } else if (cert.publicKeySize < 2048) {
            findings.detections.push({
              name: 'Weak RSA Key',
              description: `"${cn}" uses ${cert.publicKeySize}-bit RSA. NIST recommends a minimum of 2048-bit.`,
              severity: 'medium',
            });
            findings.riskScore += 15;
          }
        }
        if (cert.publicKeyAlgorithm === 'EC Public Key' && cert.publicKeySize && cert.publicKeySize < 256) {
          findings.detections.push({
            name: 'Weak EC Key',
            description: `"${cn}" uses ${cert.publicKeySize}-bit EC key. Minimum 256-bit recommended.`,
            severity: 'medium',
          });
          findings.riskScore += 15;
        }

        // ── Very long validity period (suspicious for C2) ──
        if (cert.notBefore && cert.notAfter) {
          const days = (cert.notAfter - cert.notBefore) / (1000 * 60 * 60 * 24);
          if (days > 3650 && cert.isSelfSigned) { // 10+ years, self-signed
            findings.detections.push({
              name: 'Unusually Long Validity (Self-Signed)',
              description: `"${cn}" has a ${Math.round(days / 365)}-year validity period. Self-signed certificates with very long validity are common in C2 infrastructure and malware.`,
              severity: 'medium',
            });
            findings.riskScore += 10;
          }
        }

        // ── Missing SAN extension ──
        const hasSAN = cert.extensions.some(e => e.oid === '2.5.29.17');
        if (!hasSAN && cert.version >= 3) {
          findings.detections.push({
            name: 'Missing Subject Alternative Name',
            description: `"${cn}" has no SAN extension. Modern browsers require SAN for TLS validation. May indicate a test, legacy, or malicious certificate.`,
            severity: 'low',
          });
          findings.riskScore += 3;
        }

        // ── Wildcard certificate ──
        const wildcard = (cert.subject.CN || '').startsWith('*.');
        const sanExt = cert.extensions.find(e => e.oid === '2.5.29.17');
        const sanWildcard = sanExt && sanExt.altNames && sanExt.altNames.some(n => n.value.startsWith('*.'));
        if (wildcard || sanWildcard) {
          findings.formatSpecific.push({ label: 'Wildcard', value: 'This is a wildcard certificate' });
        }

        // ── Format-specific info ──
        findings.formatSpecific.push({ label: 'Subject', value: cert.subjectStr || '(empty)' });
        findings.formatSpecific.push({ label: 'Issuer', value: cert.issuerStr || '(empty)' });
        findings.formatSpecific.push({ label: 'Serial', value: cert.serialNumber || '(none)' });
        let pkInfo = cert.publicKeyAlgorithm;
        if (cert.publicKeySize) pkInfo += ` ${cert.publicKeySize}-bit`;
        findings.formatSpecific.push({ label: 'Public Key', value: pkInfo });
        findings.formatSpecific.push({ label: 'Signature', value: cert.signatureAlgorithm });
        if (cert.notBeforeStr) findings.formatSpecific.push({ label: 'Valid From', value: cert.notBeforeStr });
        if (cert.notAfterStr) findings.formatSpecific.push({ label: 'Valid To', value: cert.notAfterStr });
        if (cert.isSelfSigned) findings.formatSpecific.push({ label: 'Self-Signed', value: 'Yes' });
        if (cert.isCA) findings.formatSpecific.push({ label: 'CA Certificate', value: 'Yes' });

        // Extract Subject CN as IOC (hostname — not a scheme-bearing URL).
        // Route every IOC through `pushIOC` so the canonical on-wire shape is
        // emitted and URL-typed pushes automatically get an `IOC.DOMAIN`
        // sibling via tldts — which is how the sidebar's domain-pivot row
        // gets populated for CRL / AIA endpoints and any scheme-bearing SAN.
        const subjectCN = cert.subject.CN || '';
        if (subjectCN && subjectCN.includes('.')) {
          pushIOC(findings, {
            type: IOC.HOSTNAME, value: subjectCN, severity: 'info', note: 'Subject CN',
          });
        }

        // Extract IOCs from SANs (domains, IPs, emails, URIs).
        // SAN (DNS) is a bare hostname, not a URL. SAN (URI) is only emitted
        // as IOC.URL if it actually has a scheme — otherwise it's a hostname.
        if (sanExt && sanExt.altNames) {
          for (const an of sanExt.altNames) {
            if (an.type === 'DNS') {
              pushIOC(findings, { type: IOC.HOSTNAME, value: an.value, severity: 'medium', note: 'SAN (DNS)' });
            } else if (an.type === 'IP') {
              pushIOC(findings, { type: IOC.IP, value: an.value, severity: 'medium', note: 'SAN (IP)' });
            } else if (an.type === 'Email') {
              pushIOC(findings, { type: IOC.EMAIL, value: an.value, severity: 'medium', note: 'SAN (Email)' });
            } else if (an.type === 'URI') {
              const isUrl = /^[a-z][a-z0-9+.\-]*:/i.test(an.value);
              pushIOC(findings, {
                type: isUrl ? IOC.URL : IOC.HOSTNAME,
                value: an.value, severity: 'medium', note: 'SAN (URI)',
              });
            }
          }
        }

        // Extract IOCs from CRL Distribution Points and AIA
        for (const ext of cert.extensions) {
          if (ext.crlPoints) {
            for (const uri of ext.crlPoints) {
              pushIOC(findings, { type: IOC.URL, value: uri, severity: 'info', note: 'CRL Distribution Point' });
            }
          }
          if (ext.accessMethods) {
            for (const am of ext.accessMethods) {
              if (am.location) {
                pushIOC(findings, { type: IOC.URL, value: am.location, severity: 'info', note: `AIA (${am.method})` });
              }
            }
          }
        }
      }

      // Store parsed certificates for analysis copy
      findings.x509Certs = certs;

      // Set risk level
      if (findings.riskScore >= 50) findings.riskLevel = 'critical';
      else if (findings.riskScore >= 30) findings.riskLevel = 'high';
      else if (findings.riskScore >= 10) findings.riskLevel = 'medium';
      else findings.riskLevel = 'low';

      // Normalize to standard findings format for sidebar/copy compatibility
      escalateRisk(findings, findings.riskLevel);
      findings.metadata = {};
      for (const fs of findings.formatSpecific) findings.metadata[fs.label] = fs.value;
      findings.externalRefs = findings.detections.map(d => ({
        type: IOC.PATTERN,
        url: `${d.name} — ${d.description}`,
        severity: d.severity,
      }));

      // Mirror classic-pivot fingerprints into the IOC table. X.509
      // certs are pivoted on SHA-1 and SHA-256 thumbprints — treat any
      // metadata row whose label mentions "Fingerprint", "SHA-1", or
      // "SHA-256" as an IOC.FINGERPRINT. Serial numbers are kept
      // metadata-only to avoid noise from self-signed dev certs.
      const fingerprintFields = {};
      for (const key of Object.keys(findings.metadata || {})) {
        if (/fingerprint|thumbprint/i.test(key)) fingerprintFields[key] = IOC.FINGERPRINT;
        else if (/^sha-?1\b/i.test(key) || /^sha-?256\b/i.test(key)) fingerprintFields[key] = IOC.FINGERPRINT;
      }
      if (Object.keys(fingerprintFields).length) {
        mirrorMetadataIOCs(findings, fingerprintFields);
      }

      // Summary
      const certCount = certs.length;
      const issues = findings.detections.length;
      findings.summary = `${certCount} certificate${certCount > 1 ? 's' : ''} analyzed${issues > 0 ? `, ${issues} issue${issues > 1 ? 's' : ''} found` : ', no issues'}`;

    } catch (e) {
      findings.summary = `Analysis error: ${e.message}`;
      escalateRisk(findings, findings.riskLevel);
      findings.metadata = {};
      findings.externalRefs = [];
    }

    return findings;
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  Static helper: extract X.509 certs from CMS/PKCS#7 SignedData
  //  Used by PE (Authenticode) and Mach-O (code signature) renderers.
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * @param {Uint8Array} cmsBytes - Raw DER-encoded CMS ContentInfo
   * @returns {{ certs: Array, error: string|null }}
   */
  /**
   * Strip trailing DER tag/length bytes that sometimes leak into URIs
   * decoded from ASN.1 IA5String fields.  The most common artifact is
   * 0x30 (SEQUENCE, ASCII '0') followed by one or two length / tag
   * bytes that happen to be printable ASCII.  Require a non-digit
   * immediately before the spurious '0' so that legitimate paths
   * ending in multi-digit numbers (e.g. /file20) are never shortened.
   * @param {string} s  The raw decoded URI string
   * @returns {string}  The cleaned URI
   */
  static _cleanDerUri(s) {
    return s.replace(/([^0-9])0[\d]{0,2}[^a-zA-Z0-9]{0,3}$/, '$1');
  }

  static parseCertificatesFromCMS(cmsBytes) {
    try {
      const r = new X509Renderer();
      const root = r._parseDER(cmsBytes);

      // ContentInfo SEQUENCE { contentType OID, content [0] EXPLICIT { SignedData } }
      if (root.tag !== 0x10 || !root.children || root.children.length < 2)
        return { certs: [], error: 'Not a valid ContentInfo' };

      // The [0] EXPLICIT wrapper around SignedData
      const contentWrapper = root.children[1];
      if (!contentWrapper.children || !contentWrapper.children.length)
        return { certs: [], error: 'No SignedData content' };

      // SignedData SEQUENCE
      const signedData = contentWrapper.children[0];
      if (signedData.tag !== 0x10 || !signedData.children)
        return { certs: [], error: 'Invalid SignedData' };

      // Find the [0] IMPLICIT SET OF Certificate (cls=2, tag=0, constructed)
      let certSet = null;
      for (const child of signedData.children) {
        if (child.cls === 2 && child.tag === 0 && child.constructed) {
          certSet = child; break;
        }
      }
      if (!certSet || !certSet.children || !certSet.children.length)
        return { certs: [], error: null }; // no certs — not an error

      const certs = [];
      for (const certNode of certSet.children) {
        try {
          const certDer = cmsBytes.subarray(certNode.offset, certNode.end);
          certs.push(r._parseCertificate(certDer));
        } catch (_) { /* skip unparseable */ }
      }
      return { certs, error: null };
    } catch (e) {
      return { certs: [], error: e.message };
    }
  }
}
