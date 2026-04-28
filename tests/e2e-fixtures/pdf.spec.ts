// ════════════════════════════════════════════════════════════════════════════
// pdf.spec.ts — Smoke for the PDF renderer
// (`src/renderers/pdf-renderer.js`).
//
// Anchor invariants:
//   1. Plain PDF carries an embedded compressed stream and surfaces
//      one or more URLs.
//   2. JS-bearing PDF fires both `PDF_AutoOpen_Action` and
//      `PDF_JavaScript_Execution` and escalates to high.
//   3. QR-bearing PDF: the PDF page renderer rasterises the page and
//      runs the QR decoder over the bitmap; the decoded URL surfaces
//      via `pushIOC` with its `Domain` sibling.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  isRiskAtLeast,
  ruleNames,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('PDF renderer', () => {
  const ctx = useSharedBundlePage();

  test('plain PDF parses with URL + Embedded_Compressed_Stream', async () => {
    const findings = await loadFixture(ctx.page, 'examples/pdf/example.pdf');
    expect(findings.iocTypes).toContain('URL');
    expect(ruleNames(findings)).toContain('Embedded_Compressed_Stream');
  });

  test('JS-bearing PDF fires AutoOpen + JavaScript_Execution rules', async () => {
    const findings = await loadFixture(ctx.page, 'examples/pdf/javascript-example.pdf');
    const rules = ruleNames(findings);
    expect(rules).toContain('PDF_AutoOpen_Action');
    expect(rules).toContain('PDF_JavaScript_Execution');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
  });

  test('QR-bearing PDF decodes the embedded URL', async () => {
    const findings = await loadFixture(ctx.page, 'examples/pdf/qr-example.pdf');
    expect(findings.iocTypes).toContain('URL');
    expect(findings.iocTypes).toContain('Domain');
    // The phishing-QR companion rule must also fire.
    expect(ruleNames(findings)).toContain('PDF_Phishing_QR_Code_Indicators');
    expect(isRiskAtLeast(findings.risk, 'medium')).toBe(true);
  });
});
