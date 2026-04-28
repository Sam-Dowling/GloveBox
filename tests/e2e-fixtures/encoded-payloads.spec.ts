// ════════════════════════════════════════════════════════════════════════════
// encoded-payloads.spec.ts — Fixture-driven smoke for the encoded-content
// decoder pipeline (base64 / hex / zlib / nested combinations).
//
// The encoded-payloads renderer is one of Loupe's signature features:
// nested decoders unwrap layered obfuscations and re-feed the decoded
// payload back through the IOC extractor. We assert that a small
// hand-picked subset of fixtures still surface the IOC types we expect
// after one or two decode hops.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import { gotoBundle, loadFixture } from '../helpers/playwright-helpers';

test.describe('encoded-payloads renderer (fixture-driven)', () => {
  test.beforeEach(async ({ page }) => {
    await gotoBundle(page);
  });

  test('nested-b64-hex-url surfaces a URL after layered decode', async ({ page }) => {
    // Fixture: outer base64 → inner hex → URL string. Tests the
    // decoder's ability to drive recursive decode hops and re-extract
    // IOCs from the innermost text. A regression where the recursive
    // step stops firing would zero out URL findings here.
    const findings = await loadFixture(
      page, 'examples/encoded-payloads/nested-b64-hex-url.txt');
    expect(findings.iocTypes).toContain('URL');
  });

  test('encoded-base64-pe yields PE detection and at least one finding', async ({ page }) => {
    // Fixture: a base64-encoded PE binary embedded in plain text. The
    // decoder should detect the embedded PE and dispatch a sub-render —
    // surfacing detections / metadata even though the outer file is
    // text. Asserting `findings.iocCount + externalRefCount > 0` is a
    // permissive smoke; exact PE-side counts vary by build.
    const findings = await loadFixture(
      page, 'examples/encoded-payloads/encoded-base64-pe.txt');
    expect(findings.iocCount + findings.externalRefCount).toBeGreaterThan(0);
    // Risk should not be 'low' — an embedded PE in obfuscated text is a
    // textbook dropper shape that the renderer's externalRefs should
    // escalate.
    expect(findings.risk).not.toBe('low');
  });

  test('defanged-iocs.txt refangs hxxp:// → http://', async ({ page }) => {
    // Direct fixture for the refanging path tested in unit-land. End-to-end
    // version verifies the renderer-level wiring (extractor result →
    // findings.interestingStrings → sidebar projection) works.
    const findings = await loadFixture(
      page, 'examples/encoded-payloads/defanged-iocs.txt');
    expect(findings.iocTypes).toContain('URL');
    // At least one URL entry should carry the 'Refanged' note when
    // the source has hxxp[://] / [.] obfuscations in it.
    const refangedNote = findings.iocs.some(
      i => i.type === 'URL' && (i.note || '').toLowerCase().includes('refang'),
    );
    expect(refangedNote).toBe(true);
  });
});
