// ════════════════════════════════════════════════════════════════════════════
// timeline-syslog-3164.spec.ts — End-to-end coverage for the RFC 3164
// syslog Timeline route.
//
// What this spec proves:
//   1. A `.log` fixture whose contents start with `<PRI>MMM DD HH:MM:SS …`
//      is sniffed as Syslog 3164 by `_sniffTimelineContent` and routed
//      through the structured-log worker path (kindHint='syslog3164').
//      The CLF default for `.log` does NOT take precedence — the syslog
//      sniff upgrade in `_loadFileInTimeline` fires.
//   2. `dumpResult()` reports `timeline:true` with the canonical column
//      list ['Timestamp','Severity','Facility','Host','Program','PID',
//      'Message'] and `formatLabel: 'Syslog (RFC 3164)'`.
//   3. Row count matches the non-empty line count in the fixture.
//   4. The structured-log path stays analyser-free: zero IOCs are
//      emitted (no `pushIOC`, no global findings sidebar). This mirrors
//      every other Timeline-routed format and is the load-bearing
//      invariant in `src/app/timeline/timeline-router.js`.
//
// Fixture is a small (~1 KB) checked-in `.log` file containing 15
// hand-crafted RFC 3164 lines spanning facility=auth, cron, daemon,
// kernel, and various severities. Determinism is trivial: the file is
// static and the parser is pure.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const FIXTURE_REL = 'tests/e2e-fixtures/syslog-3164-sample.log';
const EXPECTED_ROWS = 15;
const EXPECTED_COLUMNS = [
  'Timestamp', 'Severity', 'Facility', 'Host', 'Program', 'PID', 'Message',
];

test.describe('Timeline — Syslog RFC 3164', () => {
  const ctx = useSharedBundlePage();

  test('sniffs syslog 3164, routes through Timeline, populates RowStore', async () => {
    const findings = await loadFixture(ctx.page, FIXTURE_REL);

    // Timeline route: no IOCs emitted, no global risk stamp. The
    // fixture contains IPv4 addresses (10.0.0.42, 192.0.2.13, etc.)
    // which the analyser route would otherwise extract — observing
    // zero IOCs proves the structured-log Timeline route stayed
    // analysis-free. A regression that re-routed `.log` syslog into
    // `_loadFile`'s text/IOC pipeline would surface here as
    // `iocCount: 5`.
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();

    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount).toBe(EXPECTED_ROWS);
    // `formatTag` is set by the structured-log factory + worker;
    // a regression that swaps the file into the CLF (`'LOG'`) or
    // generic CSV (`'CSV'`) path would surface here.
    expect((result as { formatTag?: string }).formatTag).toBe('Syslog (RFC 3164)');
    // `timelineBaseColumns` mirrors the canonical 7-column header
    // (the IMMUTABLE post-parse schema, before the auto-extract
    // pump's "(host)" columns can land). A schema regression (column
    // rename, reorder, missing PID) surfaces immediately via
    // `.toEqual([...])`.
    expect((result as { timelineBaseColumns?: string[] }).timelineBaseColumns)
      .toEqual(EXPECTED_COLUMNS);
  });

  test('Timeline grid paints rows with severity column populated', async () => {
    // The window renderer mounts visible rows on first paint; a
    // non-empty store always yields ≥ 1 `.grid-row`.
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    expect(await rows.count()).toBeGreaterThan(0);

    // First data row, second cell after the row-number column = Timestamp.
    // We check the timestamp column starts with a 4-digit year, which is
    // what the structured-log tokeniser emits ('YYYY-MM-DD HH:MM:SS').
    // CLF would render '11/Oct/…' here, so this cell shape is a
    // sufficient discriminator.
    const firstRowCells = rows.first().locator('.grid-cell:not(.grid-row-num)');
    const tsCell = firstRowCells.nth(0);
    const tsText = (await tsCell.textContent()) || '';
    expect(tsText).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    // Second data column is Severity — non-empty for every fixture line.
    const sevCell = firstRowCells.nth(1);
    const sevText = (await sevCell.textContent()) || '';
    expect(sevText.trim().length).toBeGreaterThan(0);
  });
});
