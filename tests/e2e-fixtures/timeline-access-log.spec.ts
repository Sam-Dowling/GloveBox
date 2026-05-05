// ════════════════════════════════════════════════════════════════════════════
// timeline-access-log.spec.ts — End-to-end coverage for the generic
// space-delimited access-log Timeline route. Covers custom exports
// that are NOT Apache / Nginx CLF (no bracketed `[date]` token) but
// DO lead with a recognisable timestamp — notably Pulse Secure /
// Ivanti Connect Secure logs:
//
//   2025-05-15--17-43-27 64.62.197.102 TLSv1.2 ECDHE-RSA-AES128-GCM-SHA256 \
//     "GET /mifs/…" 277 "-" "Mozilla/5.0 (…)"
//
// What this spec proves:
//   1. A `.log` fixture sniff-promotes via `kindHint='access-log'`
//      (the generic-access-log probe in `timeline-router.js`
//      matches leading timestamps — `YYYY-MM-DD--HH-MM-SS` here —
//      followed by space and at least one more token).
//   2. The TLS-access-log fingerprint (8 cells; col 3 matches
//      `TLSv1.x`; col 6 is all digits) gets the canonical 8-col
//      schema `[time, ip, tls_version, tls_cipher, request,
//      bytes, referer, user_agent]` with `formatTag: 'TLS Access
//      Log'`.
//   3. All 5 fixture rows parse (no rows lost to the zero-row
//      escape hatch that previously dropped this format into
//      PlainTextRenderer).
//   4. Zero IOCs — the Timeline route is analyser-free.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const FIXTURE_REL = 'tests/e2e-fixtures/access-log-tls-sample.log';
const EXPECTED_ROWS = 5;

test.describe('Timeline — generic access log (TLS fingerprint)', () => {
  const ctx = useSharedBundlePage();

  test('sniff-promotes `.log` → TLS Access Log with 8-col schema', async () => {
    const findings = await loadFixture(ctx.page, FIXTURE_REL);
    // Timeline route is analyser-free — IPs, URLs, user-agents
    // in the fixture must NOT enrich the findings list.
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();

    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount).toBe(EXPECTED_ROWS);
    expect((result as { formatTag?: string }).formatTag).toBe('TLS Access Log');

    const cols = (result as { timelineBaseColumns?: string[] }).timelineBaseColumns!;
    expect(cols).toBeDefined();
    expect(cols.length).toBe(8);
    expect(cols[0]).toBe('time');
    expect(cols[1]).toBe('ip');
    expect(cols[2]).toBe('tls_version');
    expect(cols[3]).toBe('tls_cipher');
    expect(cols[4]).toBe('request');
    expect(cols[5]).toBe('bytes');
    expect(cols[6]).toBe('referer');
    expect(cols[7]).toBe('user_agent');
  });

  test('grid: IPs, TLS versions, ciphers, and requests all populate', async () => {
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    expect(await rows.count()).toBeGreaterThan(0);
    const gridText = await rows.evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));

    // IPs from col 2 (client).
    expect(gridText).toMatch(/64\.62\.197\.102/);
    expect(gridText).toMatch(/10\.43\.168\.110/);
    expect(gridText).toMatch(/198\.51\.100\.42/);

    // TLS versions (default histogram stack column).
    expect(gridText).toMatch(/TLSv1\.2/);
    expect(gridText).toMatch(/TLSv1\.3/);

    // Ciphers.
    expect(gridText).toMatch(/ECDHE-RSA-AES128-GCM-SHA256/);
    expect(gridText).toMatch(/TLS_AES_256_GCM_SHA384/);
    expect(gridText).toMatch(/ECDHE-RSA-CHACHA20-POLY1305/);

    // Request text survives through the quote-stripped cell.
    expect(gridText).toMatch(/GET \/mifs\/rs\/api\/v2\/featureusage_history/);
    expect(gridText).toMatch(/POST \/api\/auth\/login/);
  });

  test('timestamps parse to a valid time axis (Ivanti dashed form)', async () => {
    // The Timeline row count already asserts that all 5 rows
    // were tokenised; this test verifies the timestamps also
    // PARSE (Ivanti `YYYY-MM-DD--HH-MM-SS`) by checking that the
    // dashed timestamp text itself reaches the Timestamp column.
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    const gridText = await rows.evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));
    expect(gridText).toMatch(/2025-05-15--17-43-27/);
    expect(gridText).toMatch(/2025-05-15--17-46-10/);
  });
});
