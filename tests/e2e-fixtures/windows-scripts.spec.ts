// ════════════════════════════════════════════════════════════════════════════
// windows-scripts.spec.ts — Smoke for Windows script formats.
// Covers BAT/CMD, PowerShell, VBS, JS, WSF/WSC/WSH, INF/SCT,
// LNK / URL / REG.
//
// These fixtures pack a lot of obfuscation tricks; we anchor each to
// its identity rule plus a risk-band check.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  isRiskAtLeast,
  ruleNames,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('Windows scripts', () => {
  const ctx = useSharedBundlePage();

  test('cmd-obfuscation.bat fires CMD_Caret + BAT_Download_Execute', async () => {
    const findings = await loadFixture(
      ctx.page, 'examples/windows-scripts/cmd-obfuscation.bat');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    const rules = ruleNames(findings);
    expect(rules).toContain('CMD_Caret_Obfuscation');
    expect(rules).toContain('BAT_Download_Execute');
  });

  test('encoded-powershell.bat fires BAT_Download_Execute', async () => {
    const findings = await loadFixture(
      ctx.page, 'examples/windows-scripts/encoded-powershell.bat');
    expect(ruleNames(findings)).toContain('BAT_Download_Execute');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
  });

  test('example.cmd fires Registry_Persistence + LOLBin rules', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-scripts/example.cmd');
    const rules = ruleNames(findings);
    expect(rules).toContain('BAT_Registry_Persistence');
    expect(rules).toContain('Standalone_LOLBin_Indicators');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
  });

  test('INF script fires INF_* rule cluster', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-scripts/example.inf');
    const rules = ruleNames(findings);
    expect(rules).toContain('INF_Any_Presence');
    expect(rules.some(r => r.startsWith('INF_'))).toBe(true);
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
  });

  test('JS dropper fires JS_WSH_Dropper + JS_ActiveX rules', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-scripts/example.js');
    const rules = ruleNames(findings);
    expect(rules).toContain('JS_WSH_Dropper');
    expect(rules).toContain('JS_ActiveX_With_XMLHttp');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
  });

  test('LNK shortcut surfaces command line + GUID', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-scripts/example.lnk');
    expect(findings.iocTypes).toContain('Command Line');
    expect(findings.iocTypes).toContain('GUID');
    expect(findings.iocTypes).toContain('Hostname');
    expect(isRiskAtLeast(findings.risk, 'medium')).toBe(true);
  });

  test('REG file fires REG_* rule cluster + Process IOCs', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-scripts/example.reg');
    const rules = ruleNames(findings);
    expect(rules).toContain('REG_Any_Presence');
    expect(rules.some(r => /REG_Persistence_Run_Key|REG_COM_Hijack/.test(r))).toBe(true);
    expect(findings.iocTypes).toContain('Process');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
  });

  test('SCT scriptlet fires SCT_* rule cluster', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-scripts/example.sct');
    const rules = ruleNames(findings);
    expect(rules).toContain('SCT_Any_Presence');
    expect(rules.some(r => r.startsWith('SCT_'))).toBe(true);
  });

  test('URL shortcut fires URL_Shortcut rules', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-scripts/example.url');
    const rules = ruleNames(findings);
    expect(rules).toContain('URL_Shortcut_Any_Presence');
    expect(rules).toContain('URL_Shortcut_Suspicious');
    expect(findings.iocTypes).toContain('URL');
  });

  test('VBS dropper fires Standalone_COM_Objects rule', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-scripts/example.vbs');
    expect(ruleNames(findings)).toContain('Standalone_COM_Objects');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
  });

  test('WSF multi-engine script fires WSF_MultiEngine_Script', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-scripts/example.wsf');
    expect(ruleNames(findings)).toContain('WSF_MultiEngine_Script');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
  });

  test('WSC component file surfaces Pattern row', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-scripts/example.wsc');
    expect(findings.iocTypes).toContain('Pattern');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
  });

  test('WSH script surfaces Pattern + URL', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-scripts/example.wsh');
    expect(findings.iocTypes).toContain('Pattern');
    expect(findings.iocTypes).toContain('URL');
  });

  test('PS1 obfuscation fires PS_* rule cluster', async () => {
    const findings = await loadFixture(ctx.page, 'examples/windows-scripts/ps-obfuscation.ps1');
    const rules = ruleNames(findings);
    expect(rules).toContain('Obfuscated_IEX_Invocation');
    expect(rules.some(r => r.startsWith('PS_'))).toBe(true);
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
  });
});
