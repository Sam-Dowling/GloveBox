// ════════════════════════════════════════════════════════════════════════════
// images.spec.ts — Smoke for the image renderer
// (`src/renderers/image-renderer.js`) plus its polyglot + QR siblings.
//
// Anchor invariants:
//   1. Plain image formats (BMP/GIF/TIFF/WebP/AVIF) load cleanly with
//      zero IOCs — no false positives from the strings sweep.
//   2. PNG / JPG with appended data fire the
//      `Info_PNG_Appended_Data` / `Info_JPEG_Appended_Data` YARA rule
//      via the suspicious-content scanner.
//   3. Polyglot PNG (PNG header + appended ZIP central directory)
//      escalates risk and surfaces `Embedded_ZIP_In_Non_Archive`.
//   4. QR-coded images decode the URL and surface it as `URL` IOC
//      with a `Domain` sibling auto-emitted by `pushIOC`.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  isRiskAtLeast,
  ruleNames,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('image renderer', () => {
  const ctx = useSharedBundlePage();

  test.describe('benign image formats — zero IOCs / no YARA hits', () => {
    const benign = [
      'examples/images/example.avif',
      'examples/images/example.bmp',
      'examples/images/example.gif',
      'examples/images/example.tiff',
      'examples/images/example.webp',
    ];
    for (const path of benign) {
      const name = path.split('/').pop();
      test(`${name} parses cleanly`, async () => {
        const findings = await loadFixture(ctx.page, path);
        expect(findings.iocCount).toBe(0);
        expect(findings.risk).toBe('low');
        expect(findings.yaraInProgress).toBe(false);
      });
    }
  });

  test('ICO with embedded compressed stream fires YARA rule', async () => {
    const findings = await loadFixture(ctx.page, 'examples/images/example.ico');
    expect(ruleNames(findings)).toContain('Embedded_Compressed_Stream');
  });

  test('JPEG with appended data fires JPEG_Appended_Data rule', async () => {
    const findings = await loadFixture(ctx.page, 'examples/images/example.jpg');
    expect(ruleNames(findings)).toContain('Info_JPEG_Appended_Data');
  });

  test('PNG with appended data fires PNG_Appended_Data rule', async () => {
    const findings = await loadFixture(ctx.page, 'examples/images/example.png');
    expect(ruleNames(findings)).toContain('Info_PNG_Appended_Data');
  });

  test('polyglot PNG/ZIP escalates risk and fires ZIP-in-non-archive rule', async () => {
    const findings = await loadFixture(ctx.page, 'examples/images/polyglot-example.png');
    expect(isRiskAtLeast(findings.risk, 'medium')).toBe(true);
    const rules = ruleNames(findings);
    expect(rules).toContain('Embedded_ZIP_In_Non_Archive');
    expect(rules).toContain('Info_PNG_Appended_Data');
    expect(findings.iocTypes).toContain('Pattern');
  });

  test('QR-coded PNG decodes the embedded URL', async () => {
    const findings = await loadFixture(ctx.page, 'examples/images/qr-example.png');
    // QR decoder is async — `loadFixture` waits for `yaraInProgress`
    // to settle, but the QR sweep runs inside `analyzeForSecurity`
    // which is awaited before `_rebuildSidebar`. So the URL must be
    // present by the time we read findings.
    expect(findings.iocTypes).toContain('URL');
    expect(findings.iocTypes).toContain('Domain');
    expect(isRiskAtLeast(findings.risk, 'medium')).toBe(true);
  });
});
