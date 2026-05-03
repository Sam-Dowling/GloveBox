'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/binary/x509-renderer.fuzz.js
//
// Fuzz `X509Renderer.prototype.analyzeForSecurity(buffer, fileName)` —
// covers ALL of:
//   • Raw DER-encoded X.509 certificates
//   • PEM-encoded (`-----BEGIN CERTIFICATE-----`)
//   • PKCS#7/CMS containers (.p7b / .p7c)
//   • PKCS#12/PFX (`-----BEGIN PFX-----` flag-only branch — full ASN.1
//     decode lives in a different module)
//   • Bare private-key PEM blocks
//
// Heavy ASN.1 walker (TLV: tag → length → value). One of the most
// fuzz-rewarding targets because length-decoding bugs in ASN.1 parsers
// are a perennial CVE class.
//
// X.509 findings shape DIFFERS from the PE/ELF/Mach-O family:
//   { detections, interestingStrings, riskLevel, riskScore, summary,
//     formatSpecific, x509Certs?, metadata?, externalRefs?, risk? }
// `risk` is set by escalateRisk; `riskLevel` is the renderer's own field.
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { loadSeeds } = require('../../helpers/seed-corpus.js');

const VALID_RISK = new Set(['safe', 'low', 'medium', 'high', 'critical']);
const VALID_IOC_VALUES = new Set();

const fuzz = defineFuzzTarget({
  // x509-renderer references `md5` from hashes.js (computeImportHashFromList
  // path is unused on x509 but `md5` is referenced for fingerprint hash).
  modules: [
    'src/constants.js',
    'src/hashes.js',
    'src/renderers/x509-renderer.js',
  ],
  expose: ['IOC', 'X509Renderer'],

  maxBytes: 4 * 1024 * 1024,
  perIterBudgetMs: 5_000,

  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    if (err.message.startsWith('parser-limit:')) return true;
    return false;
  },

  onIteration(ctx, data) {
    const { IOC, X509Renderer } = ctx;
    if (!X509Renderer) throw new Error('harness: X509Renderer not exposed');
    if (VALID_IOC_VALUES.size === 0) {
      for (const v of Object.values(IOC)) VALID_IOC_VALUES.add(v);
    }

    const r = new X509Renderer();
    const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    const findings = r.analyzeForSecurity(buf, 'fuzz.cer');

    if (!findings || typeof findings !== 'object') {
      throw new Error('invariant: analyzeForSecurity returned non-object');
    }
    // riskLevel: x509-specific tier name; risk: set by escalateRisk
    // (only when there's a finding to escalate). Both must be one of
    // the canonical strings IF present.
    if (typeof findings.riskLevel !== 'string' || !VALID_RISK.has(findings.riskLevel)) {
      throw new Error(`invariant: findings.riskLevel ${JSON.stringify(findings.riskLevel)} invalid`);
    }
    if (findings.risk !== undefined
        && (typeof findings.risk !== 'string' || !VALID_RISK.has(findings.risk))) {
      throw new Error(`invariant: findings.risk ${JSON.stringify(findings.risk)} invalid`);
    }
    if (typeof findings.riskScore !== 'number'
        || !Number.isFinite(findings.riskScore)
        || findings.riskScore < 0) {
      throw new Error(`invariant: findings.riskScore ${findings.riskScore} not non-neg finite`);
    }
    for (const k of ['detections', 'interestingStrings', 'formatSpecific']) {
      if (!Array.isArray(findings[k])) {
        throw new Error(`invariant: findings.${k} not array (got ${typeof findings[k]})`);
      }
    }
    if (Array.isArray(findings.externalRefs)) {
      for (const ref of findings.externalRefs) {
        if (!ref || typeof ref !== 'object') {
          throw new Error('invariant: externalRef not object');
        }
        if (ref.type !== undefined && !VALID_IOC_VALUES.has(ref.type)) {
          throw new Error(
            `invariant: externalRef.type ${JSON.stringify(ref.type)} not in IOC.*`,
          );
        }
      }
    }
  },
});

const seeds = loadSeeds({
  dirs: ['crypto'],
  extensions: ['der', 'crt', 'cer', 'pem', 'p7b', 'p7c', 'p12', 'pfx'],
  perFileMaxBytes: 1 * 1024 * 1024,
  totalMaxBytes: 4 * 1024 * 1024,
  maxSeeds: 24,
});

// Synthetic minimal PEM CERTIFICATE block — empty payload (zero-length
// SEQUENCE: 0x30 0x00). Drives the PEM split + base64 decode + ASN.1
// "empty top-level SEQUENCE" path the real fixtures don't hit.
function syntheticMinimalPem() {
  const der = Buffer.from([0x30, 0x00]);
  const b64 = der.toString('base64');
  return Buffer.from(
    '-----BEGIN CERTIFICATE-----\n'
    + b64 + '\n'
    + '-----END CERTIFICATE-----\n',
    'utf8',
  );
}

// Synthetic minimal DER: empty top-level SEQUENCE.
function syntheticMinimalDer() {
  return Buffer.from([0x30, 0x00]);
}

seeds.push(syntheticMinimalPem());
seeds.push(syntheticMinimalDer());

module.exports = { fuzz, seeds, name: 'x509-renderer' };
