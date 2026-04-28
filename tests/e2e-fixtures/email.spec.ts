// ════════════════════════════════════════════════════════════════════════════
// email.spec.ts — Fixture-driven smoke for the email renderer.
//
// Loads two committed `.eml` fixtures from `examples/email/` through the
// production ingress path (synthetic File → `App._loadFile`) and asserts
// that the canonical findings shape contains the expected IOC types.
// We assert on `iocTypes` rather than exact IOC values so the test stays
// stable against minor regex tweaks while still catching a regression
// where the renderer stops emitting URLs / domains / emails entirely.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import { loadFixture, useSharedBundlePage } from '../helpers/playwright-helpers';

test.describe('email renderer (fixture-driven)', () => {
  const ctx = useSharedBundlePage();

  test('phishing example surfaces URL + email IOCs', async () => {
    const findings = await loadFixture(ctx.page, 'examples/email/phishing-example.eml');
    // The phishing fixture is hand-curated to contain at least one URL
    // and one email address. If either regresses to zero count it
    // indicates either the renderer stopped firing or the IOC.* constants
    // got renamed without updating the renderer — both real bugs.
    // Strings here mirror the display values frozen in `IOC`
    // (src/constants.js:411). We deliberately do NOT assert `'Domain'`
    // here: whether a URL→Domain auto-emit fires depends on the URL
    // host shape (skipped for IP-host URLs), so a fixture-content tweak
    // shouldn't fail the test.
    expect(findings.iocTypes).toContain('URL');
    expect(findings.iocTypes).toContain('Email');
    // `risk` is escalated from externalRefs severities at the end of
    // `analyzeForSecurity`; for a phishing fixture with high-severity
    // refs the final risk should never be 'low'.
    expect(findings.risk).not.toBe('low');
  });

  test('benign example.eml does not crash the renderer', async () => {
    // Smoke: the benign-side fixture should load to a non-error state
    // with at least *some* findings (every well-formed EML carries
    // headers worth surfacing). Zero findings means the renderer
    // silently bailed early — which is itself a regression.
    const findings = await loadFixture(ctx.page, 'examples/email/example.eml');
    expect(findings.iocCount + findings.externalRefCount).toBeGreaterThan(0);
    // YARA scan must have completed before the snapshot was taken; if
    // `yaraInProgress` is still true the harness's wait-for-idle helper
    // gave up, which is itself a problem worth surfacing here.
    expect(findings.yaraInProgress).toBe(false);
  });
});
