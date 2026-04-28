// ════════════════════════════════════════════════════════════════════════════
// browser-extensions.spec.ts — Smoke for the `BrowserExt` renderer
// (handles `.crx` Chrome packs and `.xpi` Firefox add-ons; both are
// essentially ZIPs around a `manifest.json`).
//
// The renderer parses `manifest.json`, surfaces the host_permissions
// list, web_accessible_resources globs, CSP, content_scripts, and
// injects a YARA scan over `manifest.json` itself. Permissions to
// `<all_urls>` / `*://*/*` and friends are flagged via the
// `BrowserExt_HostPermission_AllUrls` /
// `BrowserExt_WebAccessibleResources_AllUrls` rules.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  isRiskAtLeast,
  ruleNames,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('browser-extensions renderer', () => {
  const ctx = useSharedBundlePage();

  test('benign Firefox xpi loads without crash', async () => {
    const findings = await loadFixture(
      ctx.page, 'examples/browser-extensions/benign-firefox.xpi');
    // Benign — at minimum a URL to the homepage_url and zero high
    // severity rule hits. We allow any non-zero IOC count.
    expect(findings.iocCount).toBeGreaterThan(0);
    expect(findings.iocTypes).toContain('Pattern');
  });

  test('example.crx surfaces all-URLs host permission', async () => {
    const findings = await loadFixture(
      ctx.page, 'examples/browser-extensions/example.crx');
    const rules = ruleNames(findings);
    // The two flagship "broad permission" rules must fire.
    expect(rules).toContain('BrowserExt_HostPermission_AllUrls');
    expect(rules).toContain('BrowserExt_WebAccessibleResources_AllUrls');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
  });

  test('suspicious Chrome crx surfaces critical risk', async () => {
    const findings = await loadFixture(
      ctx.page, 'examples/browser-extensions/suspicious-chrome.crx');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    const rules = ruleNames(findings);
    // Must hit the cookie/history/debugger combo rules.
    expect(rules.some(r => r.startsWith('BrowserExt_'))).toBe(true);
  });

  test('uBlock-style xpi rule cluster fires', async () => {
    const findings = await loadFixture(
      ctx.page, 'examples/browser-extensions/ublock-example.xpi');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    expect(findings.iocCount).toBeGreaterThan(20);
  });
});
