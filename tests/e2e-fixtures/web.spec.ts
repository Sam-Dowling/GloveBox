// ════════════════════════════════════════════════════════════════════════════
// web.spec.ts — Fixture-driven smoke for the HTML / SVG / HTA renderers.
//
// `examples/web/encoded-entities.html` carries IOCs hidden behind HTML
// entity encoding (`&#x68;ttps://…` etc.) that the renderer must decode
// before pushing through the IOC extractor. A regression where the
// entity decoder stops firing would zero out URL findings here.
//
// `example-malicious.svg` packs the SVG-as-phish-vector cluster: the
// `HTML_Credential_Phish_Form`, `HTML_Invisible_Iframe`,
// `SVG_Redirect_Phish` rules among others. `example.hta` exercises the
// HTA renderer's identity rule plus VBScript indicator detection.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  isRiskAtLeast,
  ruleNames,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('web renderer family', () => {
  const ctx = useSharedBundlePage();

  test('HTML renderer decodes entity-obfuscated IOCs', async () => {
    const findings = await loadFixture(ctx.page, 'examples/web/encoded-entities.html');
    expect(findings.iocTypes).toContain('URL');
    // Entity-decoded URLs should still carry severity → risk should
    // escalate above the default `'low'` floor.
    expect(findings.risk).not.toBe('low');
    const rules = ruleNames(findings);
    expect(rules).toContain('HTML_Entity_Obfuscated_Script');
  });

  test('plain HTML surfaces URL', async () => {
    const findings = await loadFixture(ctx.page, 'examples/web/example.html');
    expect(findings.iocTypes).toContain('URL');
  });

  test('plain SVG fires Info_SVG_Image_Present', async () => {
    const findings = await loadFixture(ctx.page, 'examples/web/example.svg');
    expect(ruleNames(findings)).toContain('Info_SVG_Image_Present');
  });

  test('malicious SVG escalates to critical with phish + iframe rules', async () => {
    const findings = await loadFixture(ctx.page, 'examples/web/example-malicious.svg');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    const rules = ruleNames(findings);
    expect(rules).toContain('HTML_Credential_Phish_Form');
    expect(rules).toContain('HTML_Invisible_Iframe');
    // Plus the dense URL/Email enumeration that drives risk.
    expect(findings.iocTypes).toContain('Email');
    expect(findings.iocTypes).toContain('URL');
  });

  test('HTA file fires HTA_Any_Presence + VBScript indicators', async () => {
    const findings = await loadFixture(ctx.page, 'examples/web/example.hta');
    const rules = ruleNames(findings);
    expect(rules).toContain('HTA_Any_Presence');
    expect(rules).toContain('Standalone_HTA_VBScript_Indicators');
    expect(isRiskAtLeast(findings.risk, 'medium')).toBe(true);
  });
});
