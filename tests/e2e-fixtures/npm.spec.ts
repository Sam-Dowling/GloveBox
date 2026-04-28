// ════════════════════════════════════════════════════════════════════════════
// npm.spec.ts — Smoke for npm tarball fixtures.
//
// The `.tgz` is dispatched via the gzip-then-tar path. The renderer
// surfaces entry paths as `IOC.FILE_PATH` and runs the suspicious-
// content YARA scan over each entry's text body.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  isRiskAtLeast,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('npm tarball renderer', () => {
  const ctx = useSharedBundlePage();

  test('npm-example.tgz enumerates entries and escalates risk', async () => {
    const findings = await loadFixture(ctx.page, 'examples/npm/npm-example.tgz');
    expect(findings.iocTypes).toContain('File Path');
    expect(findings.iocTypes).toContain('Pattern');
    expect(isRiskAtLeast(findings.risk, 'high')).toBe(true);
  });
});
