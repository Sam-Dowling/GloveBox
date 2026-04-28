// ════════════════════════════════════════════════════════════════════════════
// java.spec.ts — Smoke for Java-shaped fixtures
// (.class direct, .jar / .war / .ear archives).
//
// `.class` is dispatched via the `JavaClass` magic-bytes route to the
// jar renderer's single-class peek. `.war` / `.ear` are essentially
// JARs (themselves ZIPs) and route via the renderer-registry's
// extension fallback to the archive viewer with the
// `Info_Contains_Java_JAR` rule firing on the inner content.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  isRiskAtLeast,
  ruleNames,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('Java renderer', () => {
  const ctx = useSharedBundlePage();

  test('standalone .class file routes to JAR peek', async () => {
    const findings = await loadFixture(ctx.page, 'examples/java/Example.class');
    // The jar renderer fires `Info_Contains_Java_Class` on the
    // single-class peek; the embedded MachO-magic false-positive
    // also lands as `Info_Contains_MachO_Binary` (acceptable —
    // these are info-class).
    expect(ruleNames(findings)).toContain('Info_Contains_Java_Class');
  });

  test('plain .jar enumerates entries + URL strings', async () => {
    const findings = await loadFixture(ctx.page, 'examples/java/example.jar');
    expect(findings.iocTypes).toContain('URL');
    expect(findings.iocTypes).toContain('Domain');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
    expect(ruleNames(findings)).toContain('Info_Contains_Java_JAR');
  });

  test('.war routes via archive viewer', async () => {
    const findings = await loadFixture(ctx.page, 'examples/java/example.war');
    expect(ruleNames(findings)).toContain('Info_Contains_Java_JAR');
  });

  test('.ear routes via archive viewer', async () => {
    const findings = await loadFixture(ctx.page, 'examples/java/example.ear');
    expect(ruleNames(findings)).toContain('Info_Contains_Java_JAR');
  });
});
