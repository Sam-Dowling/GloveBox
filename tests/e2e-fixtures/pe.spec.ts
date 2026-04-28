// ════════════════════════════════════════════════════════════════════════════
// pe.spec.ts — Fixture-driven smoke for the PE renderer.
//
// Loupe's PE renderer is the largest single renderer in the codebase
// (~3 700 lines). We don't aim for unit-level coverage from here — that
// belongs in dedicated unit tests against the parsing helpers. What this
// test asserts is the high-level invariant: a real PE binary loads,
// detects as PE, surfaces IOC content, and the auto-YARA scan
// completes without leaving the in-progress flag stuck.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import { loadFixture, useSharedBundlePage } from '../helpers/playwright-helpers';

test.describe('PE renderer (fixture-driven)', () => {
  const ctx = useSharedBundlePage();

  test('PE renderer loads example.exe and surfaces metadata', async () => {
    const findings = await loadFixture(ctx.page, 'examples/pe/example.exe');

  // Smoke: a well-formed PE produces non-empty findings (imports,
  // resources, version strings, etc. all surface as IOCs / refs).
  expect(findings.externalRefCount + findings.iocCount).toBeGreaterThan(0);

  // The PE renderer must mirror at least one Detection into externalRefs
  // as `IOC.PATTERN` — otherwise STIX/MISP exports lose detection rows.
  // See AGENTS.md: "Mirror every Detection into externalRefs as
  // IOC.PATTERN or it won't appear in Summary / Share / STIX / MISP."
  // We assert via `iocTypes.includes('Pattern')` rather than
  // `detectionCount > 0` because `findings.detections` may also be
  // populated through a different code path on some renderers.
  expect(findings.iocTypes).toContain('Pattern');

  // Auto-YARA must have completed; otherwise the snapshot was taken
  // before the scan settled and `yaraInProgress` would still be true.
  expect(findings.yaraInProgress).toBe(false);
  });
});
