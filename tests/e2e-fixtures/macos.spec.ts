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

  test('property-dropper reassembles char-code bindings to cleartext shell command', async () => {
    const findings = await loadFixture(ctx.page, 'examples/macos-scripts/property-dropper.applescript');
    expect(isRiskAtLeast(findings.risk, 'critical')).toBe(true);
    const rules = ruleNames(findings);
    // Raw-source char-code rules must still fire — these key on real
    // source bytes (`(ASCII character N)` primitives, `property _X :`
    // declarations, `do shell script` + `administrator privileges`
    // tokens) so their YARA offsets anchor click-to-scroll correctly.
    expect(rules).toContain('osascript_char_code_obfuscation');
    expect(rules).toContain('osascript_randomised_property_names');
    // Admin-shell reassembly triggers T1548.004.
    expect(rules).toContain('osascript_char_code_admin_shell_reassembly');
    // Two former YARA rules (`osascript_property_char_code_dropper`,
    // `osascript_property_reassembled_shell_sink`) were migrated to
    // Detection Patterns because their old implementation matched on
    // Loupe-synthesised `augmentedBuffer` sentinels (broke
    // click-to-scroll). They now surface as Pattern IOCs anchored at
    // the real `property _X :` declaration / `do shell script` sink.
    const patternIocs = (findings.iocs || []).filter((i: { type?: string }) => i.type === 'Pattern');
    const patternValues = patternIocs.map((i: { value: string }) => i.value);
    expect(patternValues.some((v: string) => /AppleScript Reassembled Shell Sink/.test(v))).toBe(true);
    expect(patternValues.some((v: string) => /AppleScript Property Char-Code Dropper/.test(v))).toBe(true);
    // Reassembled URL should produce a URL IOC.
    expect(findings.iocTypes).toContain('URL');
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
