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
    // (Telfhash-style import hash and file-trio hashes are family-
    // clustering metadata, not IOCs — kept in `findings.metadata` only.)
  });

  test('shared object (.so) parses with file-path enumeration', async () => {
    const findings = await loadFixture(ctx.page, 'examples/elf/example.so');
    expect(findings.iocTypes).toContain('File Path');
  });

  test('overlay-zip-elf polyglot loads as ELF first', async () => {
    // The fixture is a valid ELF whose appended overlay is a ZIP —
    // first-pass dispatch picks ELF (the magic at byte 0 wins). The
    // appended-data check happens inside the ELF renderer.
    const findings = await loadFixture(ctx.page, 'examples/elf/overlay-zip-elf');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
  });

  test('riskScore + riskReasons populated so verdict band agrees with sidebar', async () => {
    // Regression for the dual-verdict bug: `BinaryVerdict.summarize` reads
    // `findings.riskScore` to seed the gauge; before the fix the renderers
    // kept that score in a local variable, so the gauge displayed 0 ("No
    // obvious threat") even when the sidebar tier was correctly High. This
    // test pins the plumbing: any High-risk ELF must surface a non-zero
    // numeric `riskScore` AND a non-empty `riskReasons` audit trail so
    // the "Why this risk?" panels have content to display.
    const findings = await loadFixture(ctx.page, 'examples/elf/example');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
    expect(typeof findings.riskScore).toBe('number');
    expect(findings.riskScore).toBeGreaterThanOrEqual(5);
    expect(Array.isArray(findings.riskReasons)).toBe(true);
    expect(findings.riskReasons.length).toBeGreaterThan(0);
    // Each row should have a label and numeric delta — the renderReasons
    // panel sorts by delta descending and shows label + delta + category.
    for (const r of findings.riskReasons) {
      expect(typeof r.label).toBe('string');
      expect(r.label.length).toBeGreaterThan(0);
      expect(typeof r.delta).toBe('number');
    }
  });
});
