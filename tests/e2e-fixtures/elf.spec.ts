// ════════════════════════════════════════════════════════════════════════════
// elf.spec.ts — Smoke for the ELF renderer (`src/renderers/elf-renderer.js`).
//
// Mirrors the PE renderer in shape: section listing, hash trio,
// embedded-strings IOC sweep. The ELF analyser is responsible for
// flagging reverse-shell shapes via YARA when binary contains the
// classic `socket()/connect()` cluster.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  isRiskAtLeast,
  ruleNames,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('ELF renderer', () => {
  const ctx = useSharedBundlePage();

  test('reverse-shell ELF binary fires reverse-shell rule', async () => {
    const findings = await loadFixture(ctx.page, 'examples/elf/example');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
    expect(ruleNames(findings)).toContain('Info_Reverse_Shell_Patterns');
    // Expect a sizeable strings extraction.
    expect(findings.iocCount).toBeGreaterThan(20);
    // Hash trio must surface.
    expect(findings.iocTypes).toContain('Hash');
  });

  test('shared object (.so) parses with file-path enumeration', async () => {
    const findings = await loadFixture(ctx.page, 'examples/elf/example.so');
    expect(findings.iocTypes).toContain('File Path');
    expect(findings.iocTypes).toContain('Hash');
  });

  test('overlay-zip-elf polyglot loads as ELF first', async () => {
    // The fixture is a valid ELF whose appended overlay is a ZIP —
    // first-pass dispatch picks ELF (the magic at byte 0 wins). The
    // appended-data check happens inside the ELF renderer.
    const findings = await loadFixture(ctx.page, 'examples/elf/overlay-zip-elf');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
    expect(findings.iocTypes).toContain('Hash');
  });
});
