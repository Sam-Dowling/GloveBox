// ════════════════════════════════════════════════════════════════════════════
// crypto.spec.ts — Smoke coverage for the X.509 + PGP renderer pair.
//
// X.509 (`src/renderers/x509-renderer.js`) handles PEM, DER, P12 and
// PFX. PGP (`src/renderers/pgp-renderer.js`) handles ASCII-armoured
// `.asc`, binary `.gpg`, OpenPGP private `.key` files, and `.sig`
// detached signatures.
//
// Two anchor invariants are exercised:
//
//   1. A leaf certificate with embedded plaintext private key
//      escalates risk to 'critical' via the
//      `SSH_Private_Key_Reference` YARA rule.
//   2. PKCS#12 / PFX files surface a `Pattern` external ref and at
//      least one `Detection` (the regression fix landed in Phase 1.5
//      — pre-fix these returned an empty findings).
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  isRiskAtLeast,
  ruleNames,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('crypto / X.509 renderer', () => {
  const ctx = useSharedBundlePage();

  test('PEM CA certificate (DER-encoded variant) parses without error', async () => {
    const findings = await loadFixture(ctx.page, 'examples/crypto/example-ca.der');
    // Self-signed CA — at minimum the CA fact lands as a Pattern row.
    expect(findings.iocTypes).toContain('Pattern');
  });

  test('expired certificate flags expiry', async () => {
    const findings = await loadFixture(ctx.page, 'examples/crypto/example-expired.crt');
    // The expiry detection lives on `findings.detections`; the
    // mirrored Pattern row is the user-visible signal.
    expect(findings.detectionCount).toBeGreaterThan(0);
    expect(findings.iocTypes).toContain('Pattern');
    expect(isRiskAtLeast(findings.risk, 'medium')).toBe(true);
  });

  test('SAN-rich certificate enumerates host IOCs', async () => {
    const findings = await loadFixture(ctx.page, 'examples/crypto/example-san.pem');
    // SubjectAlternativeName fields surface as Hostname / Domain /
    // IP Address / Email.
    const expected = ['Domain', 'Email', 'Hostname', 'IP Address'];
    for (const t of expected) expect(findings.iocTypes).toContain(t);
  });

  test('self-signed certificate surfaces Pattern and Hostname rows', async () => {
    const findings = await loadFixture(ctx.page, 'examples/crypto/example-selfsigned.pem');
    expect(findings.iocTypes).toContain('Pattern');
    expect(findings.iocTypes).toContain('Hostname');
    expect(isRiskAtLeast(findings.risk, 'medium')).toBe(true);
  });

  test('certificate-with-embedded-key escalates to critical', async () => {
    // The single most important regression target — a PEM bundle
    // that ships the private key alongside the cert. The
    // `SSH_Private_Key_Reference` YARA rule must fire and the risk
    // floor must be 'critical'.
    const findings = await loadFixture(ctx.page, 'examples/crypto/example-with-key.pem');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    expect(ruleNames(findings)).toContain('SSH_Private_Key_Reference');
  });

  test('Google certificate chain enumerates hostnames + URLs', async () => {
    const findings = await loadFixture(ctx.page, 'examples/crypto/google-chain.pem');
    expect(findings.iocTypes).toContain('Hostname');
    expect(findings.iocTypes).toContain('URL');
    expect(findings.detectionCount).toBeGreaterThan(0);
  });

  test('PKCS#12 (.p12) surfaces Pattern + Detection (regression)', async () => {
    // Fix landed in Phase 1.5 — before the fix the early-return path
    // skipped the externalRefs mirror and the file showed an empty
    // findings panel. Lock both anchors in place.
    const findings = await loadFixture(ctx.page, 'examples/crypto/example.p12');
    expect(findings.detectionCount).toBeGreaterThan(0);
    expect(findings.externalRefCount).toBeGreaterThan(0);
    expect(findings.iocTypes).toContain('Pattern');
  });

  test('PKCS#12 (.pfx) surfaces Pattern + Detection (regression)', async () => {
    const findings = await loadFixture(ctx.page, 'examples/crypto/example.pfx');
    expect(findings.detectionCount).toBeGreaterThan(0);
    expect(findings.externalRefCount).toBeGreaterThan(0);
    expect(findings.iocTypes).toContain('Pattern');
  });
});

test.describe('crypto / PGP renderer', () => {
  const ctx = useSharedBundlePage();

  test('ASCII-armoured public key (.asc) parses', async () => {
    const findings = await loadFixture(ctx.page, 'examples/crypto/example.asc');
    // The PGP renderer surfaces the user-id email as IOC.EMAIL.
    expect(findings.iocTypes).toContain('Email');
  });

  test('binary public key (.gpg) parses', async () => {
    const findings = await loadFixture(ctx.page, 'examples/crypto/example.gpg');
    expect(findings.iocTypes).toContain('Email');
  });

  test('OpenPGP private key (.key) flags secret-key presence', async () => {
    const findings = await loadFixture(ctx.page, 'examples/crypto/example.key');
    // Private-key presence lands as a Pattern row — regression: this
    // must be present alongside the user-id email.
    expect(findings.iocTypes).toContain('Pattern');
    expect(findings.detectionCount).toBeGreaterThan(0);
  });

  test('binary signature (.sig) parses without error', async () => {
    // `.sig` files are detached signatures — there's no user-id and
    // no IOCs. We only assert no-crash.
    const findings = await loadFixture(ctx.page, 'examples/crypto/example.sig');
    // Findings projection is well-formed; iocCount may be zero.
    expect(findings.iocCount).toBeGreaterThanOrEqual(0);
    expect(findings.yaraInProgress).toBe(false);
  });

  test('ASCII-armoured PGP envelope (.pgp) parses', async () => {
    const findings = await loadFixture(ctx.page, 'examples/crypto/example.pgp');
    expect(findings.iocTypes).toContain('Email');
  });
});
