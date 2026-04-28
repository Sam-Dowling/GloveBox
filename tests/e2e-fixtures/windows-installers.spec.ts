// ════════════════════════════════════════════════════════════════════════════
// windows-installers.spec.ts — Smoke for Windows installer / package
// formats. Covers MSI, MSIX, AppInstaller (XML), ClickOnce
// (.application + .manifest + malicious variant).
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  isRiskAtLeast,
  ruleNames,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('Windows installers', () => {
  const ctx = useSharedBundlePage();

  test('MSI installer parses with Pattern + Info rows', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-installers/example.msi');
    expect(findings.iocTypes).toContain('Pattern');
    expect(findings.iocTypes).toContain('Info');
    expect(isRiskAtLeast(findings.risk, 'medium')).toBe(true);
  });

  test('MSIX package escalates to critical with capability rules', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-installers/example.msix');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    const rules = ruleNames(findings);
    // Must hit at least one MSIX_* rule.
    expect(rules.some(r => r.startsWith('MSIX_'))).toBe(true);
  });

  test('AppInstaller XML escalates to critical with HTTP + auto-update rules', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-installers/example.appinstaller');
    const rules = ruleNames(findings);
    expect(rules).toContain('MSIX_AppInstaller_HTTP');
    expect(rules).toContain('MSIX_AppInstaller_Silent_AutoUpdate');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
  });

  test('benign ClickOnce .application parses with URL/IP', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-installers/example.application');
    expect(findings.iocTypes).toContain('URL');
    expect(findings.iocTypes).toContain('IP Address');
  });

  test('ClickOnce manifest fires FullTrust_Requested', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-installers/example.manifest');
    expect(ruleNames(findings)).toContain('ClickOnce_FullTrust_Requested');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
  });

  test('malicious ClickOnce escalates to critical with override + DDNS rules', async () => {
    const findings = await loadFixture(
      ctx.page, 'examples/windows-installers/malicious-example.application');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    const rules = ruleNames(findings);
    expect(rules).toContain('ClickOnce_AppDomainManager_Override');
    expect(rules).toContain('ClickOnce_FullTrust_Requested');
  });
});
