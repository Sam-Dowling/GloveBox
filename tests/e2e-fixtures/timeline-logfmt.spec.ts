// ════════════════════════════════════════════════════════════════════════════
// timeline-logfmt.spec.ts — End-to-end coverage for the logfmt
// Timeline route.
//
// logfmt is a flat `key=value key="quoted value"` line format
// without any header — used by Heroku, Logrus, Hashicorp tools
// (Consul/Vault/Nomad), and many Go services. There's no
// canonical extension; files arrive as `.log` and the router
// sniff promotes them when ≥60 % of the first 5 lines parse as
// ≥2 logfmt key=value pairs (and the prefix before the first key
// is short relative to the line).
//
// What this spec proves:
//   1. A `.log` fixture full of logfmt lines is sniff-promoted to
//      the logfmt route with `formatTag: 'logfmt'` and parses all
//      10 fixture rows.
//   2. The schema is locked from the first record's keys (`time`,
//      `level`, `msg`, `service`, `port`) plus a trailing
//      `_extra` column.
//   3. Quoted values with embedded spaces and escapes round-trip
//      to the grid (the `dsn=`, `query=`, and `err=` cells).
//   4. Records carrying ext keys not in the locked schema (`dsn`,
//      `pool`, `query`, `dur_ms`, `method`, `path`, `status`,
//      `client`, `user`, `attempts`, …) populate `_extra`.
//   5. Zero IOCs are emitted despite the fixture carrying public
//      IPv4s — the logfmt Timeline route is analyser-free.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const FIXTURE_REL = 'tests/e2e-fixtures/logfmt-sample.log';
const EXPECTED_ROWS = 10;

test.describe('Timeline — logfmt', () => {
  const ctx = useSharedBundlePage();

  test('sniff-promotes `.log` → logfmt; schema locks from first record', async () => {
    const findings = await loadFixture(ctx.page, FIXTURE_REL);
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();
    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount).toBe(EXPECTED_ROWS);
    expect((result as { formatTag?: string }).formatTag).toBe('logfmt');

    const cols = (result as { timelineColumns?: string[] }).timelineColumns!;
    expect(cols).toBeDefined();
    // Schema locked from first record: time, level, msg, service,
    // port — in declaration order.
    expect(cols).toContain('time');
    expect(cols).toContain('level');
    expect(cols).toContain('msg');
    expect(cols).toContain('service');
    expect(cols).toContain('port');
    expect(cols).toContain('_extra');
    // `_extra` must sit past every locked key (GeoIP / hostname
    // enrichment may append further `.geo` / `(host)` columns
    // after it).
    expect(cols.indexOf('_extra')).toBeGreaterThan(cols.indexOf('port'));
  });

  test('grid renders quoted values + reflects all 10 rows', async () => {
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    expect(await rows.count()).toBeGreaterThan(0);
    const gridText = await rows.evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));
    // Quoted message round-trips intact.
    expect(gridText).toMatch(/server starting/);
    expect(gridText).toMatch(/auth failed: bad password/);
    expect(gridText).toMatch(/db connection lost/);
    // Quoted value containing `:` and `/` survives.
    expect(gridText).toMatch(/postgres:\/\/app@10\.0\.0\.1:5432\/app/);
    // Free-text quoted query.
    expect(gridText).toMatch(/SELECT \* FROM events/);
    // IPs from bare values.
    expect(gridText).toMatch(/185\.220\.101\.33/);
    expect(gridText).toMatch(/203\.0\.113\.99/);
    // All severity levels visible in the locked `level` column.
    expect(gridText).toMatch(/info/);
    expect(gridText).toMatch(/warn/);
    expect(gridText).toMatch(/error/);
    expect(gridText).toMatch(/fatal/);
  });

  test('keys not in the locked schema spill into _extra', async () => {
    // First record locks: time, level, msg, service, port. Every
    // other record carries keys outside that set (`dsn`, `query`,
    // `method`, `path`, `status`, `client`, `user`, `attempts`,
    // `signal`, `version`, `err`, etc.) — they must surface
    // inside the `_extra` JSON sub-object.
    const result = await dumpResult(ctx.page);
    const cols = (result as { timelineColumns?: string[] }).timelineColumns!;
    expect(cols.indexOf('_extra')).toBeGreaterThanOrEqual(0);

    const gridText = await ctx.page.locator('.grid-row').evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));
    // Pairs that must appear inside the JSON-encoded `_extra` cell.
    expect(gridText).toMatch(/"method":\s*"POST"/);
    expect(gridText).toMatch(/"status":\s*"401"/);
    expect(gridText).toMatch(/"user":\s*"alice"/);
    expect(gridText).toMatch(/"attempts":\s*"3"/);
    expect(gridText).toMatch(/"signal":\s*"SIGHUP"/);
  });
});
