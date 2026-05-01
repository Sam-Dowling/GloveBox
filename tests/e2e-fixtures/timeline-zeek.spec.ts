// ════════════════════════════════════════════════════════════════════════════
// timeline-zeek.spec.ts — End-to-end coverage for the Zeek TSV
// Timeline route.
//
// What this spec proves:
//   1. A `.log` fixture starting with `#separator \x09` is sniffed as
//      Zeek by `_sniffTimelineContent` and routed through the
//      structured-log worker path (kindHint='zeek'). The Zeek sniff
//      runs ahead of every other `.log`-applicable sniff (CLF /
//      syslog 3164 / 5424) so that magic prefix wins immediately.
//   2. `dumpResult()` reports `timeline:true` with the schema parsed
//      from the file's own `#fields` line — NOT a hard-coded list.
//      The fixture's schema (conn.log) has 18 fields including the
//      Zeek dotted-field names like `id.orig_h`.
//   3. `formatLabel` becomes `'Zeek (conn)'` thanks to the `#path`
//      directive — proving the dynamic-label override works through
//      the worker → `defaultStackColIdx` / `formatLabel` pathway.
//   4. Zero IOCs are emitted despite the fixture containing IPv4
//      addresses (10.0.0.42, 8.8.8.8, 1.1.1.1, etc.) — the
//      structured-log Timeline route stays analyser-free, mirroring
//      every other Timeline-routed format.
//   5. `(empty)` and `-` cells are blanked in the rendered grid (Zeek
//      NILVALUE conventions).
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const FIXTURE_REL = 'tests/e2e-fixtures/zeek-conn-sample.log';
const EXPECTED_ROWS = 10;
// File schema (parsed from `#fields`).
const SCHEMA_COLUMNS = [
  'ts', 'uid', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
  'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
  'conn_state', 'missed_bytes', 'history',
  'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
];
// After the Timeline route mounts, the GeoIP enricher detects the
// IPv4 source columns `id.orig_h` / `id.resp_h` and appends a
// `<src>.geo` enrichment column for each. The post-enrichment list
// is what the LIVE `timelineColumns` (`tlView.columns` getter)
// eventually returns once the +0 ms post-`_app`-wire and +100 ms
// in-ctor `setTimeout`s fire and `_runGeoipEnrichment` pushes onto
// `_extractedCols`.
const EXPECTED_COLUMNS_AFTER_GEOIP = SCHEMA_COLUMNS.concat([
  'id.orig_h.geo', 'id.resp_h.geo',
]);

test.describe('Timeline — Zeek TSV', () => {
  const ctx = useSharedBundlePage();

  test('sniffs Zeek, parses #fields schema, routes through Timeline', async () => {
    const findings = await loadFixture(ctx.page, FIXTURE_REL);

    // Timeline route: no IOCs. The fixture's IPv4 columns
    // (id.orig_h / id.resp_h) are exactly the kind of cells that
    // would surface in the global findings sidebar if the Zeek file
    // had been mis-routed into the analyser pipeline.
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();

    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount).toBe(EXPECTED_ROWS);
    // Dynamic label from `#path conn`. A regression that lost the
    // path-aware label would show `'Zeek'` instead.
    expect((result as { formatTag?: string }).formatTag).toBe('Zeek (conn)');
    // Schema parsed from the file's own `#fields` line. Reading the
    // IMMUTABLE `timelineBaseColumns` (vs the live `timelineColumns`
    // getter, which mutates as auto-extract / GeoIP enrichment land)
    // makes the schema assertion race-free. A regression that fell
    // back to synthetic `col 1 …` names (the no-`#fields`-seen
    // fallback) surfaces here as a length mismatch.
    expect((result as { timelineBaseColumns?: string[] }).timelineBaseColumns)
      .toEqual(SCHEMA_COLUMNS);
    // GeoIP enrichment is async (post-mount `setTimeout(0)` after
    // `_app` is wired). Poll the live `timelineColumns` until the
    // two `.geo` columns land — a regression that lost GeoIP
    // enrichment would time out here.
    await expect.poll(async () => {
      const r = await dumpResult(ctx.page);
      return (r as { timelineColumns?: string[] }).timelineColumns;
    }, { timeout: 5_000 }).toEqual(EXPECTED_COLUMNS_AFTER_GEOIP);
  });

  test('Timeline grid paints rows with NILVALUEs blanked', async () => {
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    expect(await rows.count()).toBeGreaterThan(0);

    // First column is `ts` — a unix-epoch float ('1697371200.123456').
    // The 5424 / 3164 routes would render '2024-10-15T...' or
    // 'YYYY-MM-DD HH:MM:SS' here, so the float shape is a
    // sufficient discriminator that we landed on the Zeek path.
    const firstRowCells = rows.first().locator('.grid-cell:not(.grid-row-num)');
    const tsCell = firstRowCells.nth(0);
    const tsText = (await tsCell.textContent()) || '';
    expect(tsText).toMatch(/^\d{10}\.\d+$/);

    // The literal NILVALUE strings `(empty)` and `-` from the
    // fixture must NOT appear anywhere in the rendered grid — the
    // tokeniser blanks them per Zeek convention. We check the full
    // grid text rather than a specific cell because the visible
    // column order is decided by the auto-display-order pipeline
    // (timestamp first, GeoIP enrichment columns inserted immediately
    // after their IP source) and isn't tied 1:1 to schema order.
    // A regression that skipped `_empty_field` / `_unset_field`
    // handling would surface here as a literal `(empty)` or a `-`
    // cell.
    const gridText = await ctx.page.locator('.grid-row').evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));
    expect(gridText).not.toMatch(/\(empty\)/);
    // The fixture's `proto` column legitimately contains tokens like
    // `tcp` / `udp` / `icmp` and the `history` column contains tokens
    // like `Dd` / `S` — we only care that no whole-cell `-` survived
    // NILVALUE replacement. The grid renders cells separated by
    // whitespace inside `.grid-row`, so a literal `-` cell would
    // surface as a tab-or-space-bounded `-`. Use a word-boundary
    // check that excludes legitimate hyphens inside Zeek `history`
    // string codes (those never stand alone — they're embedded in
    // longer alphanumeric runs like `ShADadFf`).
    expect(gridText).not.toMatch(/\s-\s/);
  });
});
