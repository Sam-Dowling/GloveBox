// ════════════════════════════════════════════════════════════════════════════
// macos.spec.ts — Combined smoke for macOS-script + macOS-system
// fixtures. Covers: AppleScript / JXA / .scpt, plist (XML + binary),
// .app bundles (ZIP-shaped), .dmg, .dylib, .pkg, .webloc URL aliases.
//
// The osascript/jxa rule families and the plist persistence rule
// family produce some of the densest detection clusters in the
// engine; we anchor a representative subset rather than every rule.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  isRiskAtLeast,
  ruleNames,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('macOS scripts (osascript / JXA / scpt)', () => {
  const ctx = useSharedBundlePage();

  test('AppleScript stealer surfaces critical risk', async () => {
    const findings = await loadFixture(ctx.page, 'examples/macos-scripts/example.applescript');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    const rules = ruleNames(findings);
    // At least one of the osascript_* rule cluster must fire.
    expect(rules.some(r => r.startsWith('osascript_'))).toBe(true);
    // Stealer fixture must surface filesystem + network IOCs.
    expect(findings.iocTypes).toContain('Domain');
    expect(findings.iocTypes).toContain('IP Address');
  });

  test('JXA stealer surfaces critical risk', async () => {
    const findings = await loadFixture(ctx.page, 'examples/macos-scripts/example.jxa');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    const rules = ruleNames(findings);
    // The jxa_* rule cluster must fire.
    expect(rules.some(r => r.startsWith('jxa_'))).toBe(true);
  });

  test('compiled .scpt fires osascript_* rules', async () => {
    const findings = await loadFixture(ctx.page, 'examples/macos-scripts/example.scpt');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    expect(findings.iocTypes).toContain('Pattern');
    const rules = ruleNames(findings);
    expect(rules.some(r => r.startsWith('osascript_'))).toBe(true);
  });
});

test.describe('macOS system fixtures', () => {
  const ctx = useSharedBundlePage();

  test('XML plist with persistence keys surfaces critical risk', async () => {
    const findings = await loadFixture(ctx.page, 'examples/macos-system/example.plist');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    const rules = ruleNames(findings);
    // The plist_* rule cluster must fire.
    expect(rules.some(r => r.startsWith('plist_'))).toBe(true);
  });

  test('binary plist surfaces critical risk + plist_* rules', async () => {
    const findings = await loadFixture(ctx.page, 'examples/macos-system/example-binary.plist');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    const rules = ruleNames(findings);
    expect(rules.some(r => r.startsWith('plist_'))).toBe(true);
  });

  test('.app bundle (zip-shaped) escalates risk', async () => {
    const findings = await loadFixture(ctx.page, 'examples/macos-system/example.app');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
    expect(findings.iocTypes).toContain('File Path');
  });

  test('.dmg disk image enumerates entries', async () => {
    const findings = await loadFixture(ctx.page, 'examples/macos-system/example.dmg');
    expect(findings.iocTypes).toContain('Pattern');
    expect(findings.iocTypes).toContain('YARA Match');
  });

  test('.dylib MachO parses with file paths + GUID', async () => {
    const findings = await loadFixture(ctx.page, 'examples/macos-system/example.dylib');
    expect(findings.iocTypes).toContain('File Path');
    expect(findings.iocTypes).toContain('GUID');
    // (SymHash and the file-trio hashes are clustering metadata, not
    // IOCs — kept in `findings.metadata` only.)
  });

  test('overlay-random.dylib (MachO + appended random data) escalates risk', async () => {
    const findings = await loadFixture(ctx.page, 'examples/macos-system/overlay-random.dylib');
    expect(isRiskAtLeast(findings.risk, 'medium')).toBe(true);
    expect(findings.iocTypes).toContain('Pattern');
  });

  test('.pkg installer fires PKG_Xar_Archive', async () => {
    const findings = await loadFixture(ctx.page, 'examples/macos-system/example.pkg');
    expect(ruleNames(findings)).toContain('PKG_Xar_Archive');
  });

  test('.webloc shortcut surfaces URL + Info_Shortcut_WEBLOC', async () => {
    const findings = await loadFixture(ctx.page, 'examples/macos-system/example.webloc');
    expect(findings.iocTypes).toContain('URL');
    expect(ruleNames(findings)).toContain('Info_Shortcut_WEBLOC');
  });
});
