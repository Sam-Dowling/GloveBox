// ════════════════════════════════════════════════════════════════════════════
// timeline-syslog-5424.spec.ts — End-to-end coverage for the RFC 5424
// syslog Timeline route.
//
// What this spec proves:
//   1. A `.log` fixture whose lines start with `<PRI>VER ` (the digit
//      version field that distinguishes 5424 from 3164) is sniffed as
//      Syslog 5424 by `_sniffTimelineContent` and routed through the
//      structured-log worker path (kindHint='syslog5424'). The 5424
//      sniff runs BEFORE 3164 in the router so a file matching both
//      regexes resolves to 5424.
//   2. `dumpResult()` reports `timeline:true` with the canonical
//      9-column header ['Timestamp','Severity','Facility','Host','App',
//      'ProcID','MsgID','StructuredData','Message'] and
//      `formatLabel: 'Syslog (RFC 5424)'`.
//   3. The structured-log path stays analyser-free: zero IOCs are
//      emitted despite the fixture containing IPv4 addresses
//      (10.0.0.42, 192.0.2.13). This mirrors every other Timeline-
//      routed format and is the load-bearing invariant in
//      `src/app/timeline/timeline-router.js`.
//
// Fixture (`syslog-5424-sample.log`) is a 15-line static file
// covering the four RFC 5424 § 6.5 example shapes plus realistic
// auth / nginx / firewall / sshd traffic — including escaped quotes
// and multiple back-to-back SD blocks.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const FIXTURE_REL = 'tests/e2e-fixtures/syslog-5424-sample.log';
const EXPECTED_ROWS = 15;
const EXPECTED_COLUMNS = [
  'Timestamp', 'Severity', 'Facility', 'Host',
  'App', 'ProcID', 'MsgID', 'StructuredData', 'Message',
];

test.describe('Timeline — Syslog RFC 5424', () => {
  const ctx = useSharedBundlePage();

  test('sniffs syslog 5424, routes through Timeline, populates RowStore', async () => {
    const findings = await loadFixture(ctx.page, FIXTURE_REL);

    // Timeline route: no IOCs emitted, no global risk stamp. The
    // fixture carries IPv4 addresses inside MSG bodies and SD blocks
    // (10.0.0.42, 192.0.2.13, 192.0.2.99). Observing zero IOCs proves
    // the structured-log Timeline route stayed analysis-free; a
    // regression that re-routed `.log` 5424 into `_loadFile`'s
    // text/IOC pipeline would surface here as a non-zero count.
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();

    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount).toBe(EXPECTED_ROWS);
    // `formatTag` is set by the structured-log factory + worker. A
    // regression that swaps the file into the 3164 path or the
    // generic CSV path would surface here.
    expect((result as { formatTag?: string }).formatTag).toBe('Syslog (RFC 5424)');
    // `timelineBaseColumns` mirrors the canonical 9-column header
    // (the IMMUTABLE post-parse schema, before the auto-extract
    // pump's "(host)" columns can land). Any schema regression
    // (column rename, reorder, missing SD column) surfaces
    // immediately via `.toEqual([...])`.
    expect((result as { timelineBaseColumns?: string[] }).timelineBaseColumns)
      .toEqual(EXPECTED_COLUMNS);
  });

  test('Timeline grid paints rows with ISO 8601 timestamps and SD blocks intact', async () => {
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    expect(await rows.count()).toBeGreaterThan(0);

    // First data row, first non-row-number cell = Timestamp. The 5424
    // tokeniser passes the raw ISO 8601 string through unchanged
    // (no normalisation), so we expect the original `2024-10-15T...`
    // shape with the trailing `Z` or `±HH:MM` offset. A regression
    // that misclassified this as 3164 would emit `YYYY-MM-DD HH:MM:SS`
    // (no `T`, no offset) — the regex below would then fail.
    const firstRowCells = rows.first().locator('.grid-cell:not(.grid-row-num)');
    const tsCell = firstRowCells.nth(0);
    const tsText = (await tsCell.textContent()) || '';
    expect(tsText).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/);

    // Second column = Severity, populated for every line.
    const sevCell = firstRowCells.nth(1);
    expect(((await sevCell.textContent()) || '').trim().length).toBeGreaterThan(0);
  });
});
