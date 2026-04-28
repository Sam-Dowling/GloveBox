// ════════════════════════════════════════════════════════════════════════════
// web.spec.ts — Fixture-driven smoke for the HTML renderer.
//
// `examples/web/encoded-entities.html` carries IOCs hidden behind HTML
// entity encoding (`&#x68;ttps://…` etc.) that the renderer must decode
// before pushing through the IOC extractor. A regression where the
// entity decoder stops firing would zero out URL findings here.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import { gotoBundle, loadFixture } from '../helpers/playwright-helpers';

test('HTML renderer decodes entity-obfuscated IOCs', async ({ page }) => {
  await gotoBundle(page);
  const findings = await loadFixture(page, 'examples/web/encoded-entities.html');
  expect(findings.iocTypes).toContain('URL');
  // Entity-decoded URLs should still carry severity → risk should
  // escalate above the default `'low'` floor.
  expect(findings.risk).not.toBe('low');
});
