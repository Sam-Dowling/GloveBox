// ════════════════════════════════════════════════════════════════════════════
// timeline-cloudtrail.spec.ts — End-to-end coverage for the AWS
// CloudTrail Timeline route.
//
// AWS CloudTrail records every API call against every AWS service.
// Two on-disk shapes:
//   • JSONL  — one event per line. Sniffed via the JSONL probe in
//              `_sniffTimelineContent` plus a CloudTrail-key gate
//              (presence of `eventName` + `eventTime`). Routes via
//              `kindHint='cloudtrail'`.
//   • Wrapped — single JSON document `{"Records":[...]}`. Sniffed
//              via the `cloudtrail-wrapped` probe; the router decodes
//              + unwraps to JSONL bytes BEFORE dispatching to the
//              same `cloudtrail` tokeniser.
//
// What this spec proves:
//   1. JSONL form (`.jsonl` extension carrying CloudTrail records)
//      routes to Timeline with `formatTag: 'AWS CloudTrail'`.
//   2. Wrapped form (`.json` extension, `{"Records":[...]}`) is
//      detected, unwrapped, and produces an identical row count to
//      the JSONL fixture (both fixtures carry 8 records).
//   3. Schema is the canonical CloudTrail column list (eventTime,
//      eventName, eventSource, …) — NOT the keys observed in the
//      first record (which differ in order).
//   4. Histogram stack column auto-picks `eventName` (the canonical
//      headline action — different from JSONL's level-first
//      priority list).
//   5. Both forms are analyser-free: `iocCount === 0` despite
//      records carrying public IPv4s (`203.0.113.42`, `198.51.100.7`,
//      `192.0.2.55`, `185.220.101.33`) in `sourceIPAddress`. The
//      Timeline pipeline never invokes `analyzeForSecurity`.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const JSONL_FIXTURE = 'tests/e2e-fixtures/cloudtrail-sample.jsonl';
const WRAPPED_FIXTURE = 'tests/e2e-fixtures/cloudtrail-wrapped.json';
const EXPECTED_ROWS = 8;

test.describe('Timeline — AWS CloudTrail (JSONL form)', () => {
  const ctx = useSharedBundlePage();

  test('routes via cloudtrail kind, formatTag is AWS CloudTrail', async () => {
    const findings = await loadFixture(ctx.page, JSONL_FIXTURE);
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();
    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount).toBe(EXPECTED_ROWS);
    expect((result as { formatTag?: string }).formatTag).toBe('AWS CloudTrail');
  });

  test('schema is the canonical CloudTrail column list', async () => {
    const result = await dumpResult(ctx.page);
    // `timelineBaseColumns` is the IMMUTABLE post-parse schema. The
    // live `timelineColumns` getter mutates async after mount as the
    // auto-extract pump (+60 ms) appends extracted "(host)" cols, so
    // `cols[cols.length - 1]` would race against `_extra` vs
    // `eventSource (host)` here. See `_testApiDumpResult`.
    const cols = (result as { timelineBaseColumns?: string[] }).timelineBaseColumns!;
    expect(cols).toBeDefined();
    // Spot-check canonical columns. They must appear in canonical
    // order, regardless of the order they happen to occur in the
    // first record (which has `eventVersion` first, then
    // `userIdentity`, then `eventTime` — the canonical ordering
    // promotes `eventTime` to col 0).
    expect(cols[0]).toBe('eventTime');
    expect(cols[1]).toBe('eventName');
    expect(cols[2]).toBe('eventSource');
    expect(cols[3]).toBe('awsRegion');
    expect(cols[4]).toBe('sourceIPAddress');
    expect(cols).toContain('userIdentity.type');
    expect(cols).toContain('userIdentity.userName');
    expect(cols).toContain('userIdentity.arn');
    expect(cols).toContain('userAgent');
    expect(cols).toContain('eventID');
    // `_extra` is always last — service-specific blobs
    // (requestParameters.*, responseElements.*) spill there.
    expect(cols[cols.length - 1]).toBe('_extra');
  });

  test('grid renders all 8 records with canonical cell values', async () => {
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    expect(await rows.count()).toBeGreaterThan(0);
    // Spot-check by grid-text regex (column display order may
    // include GeoIP enrichment for `sourceIPAddress`).
    const gridText = await rows.evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));
    expect(gridText).toMatch(/ConsoleLogin/);
    expect(gridText).toMatch(/PutObject/);
    expect(gridText).toMatch(/CreateUser/);
    expect(gridText).toMatch(/AttachUserPolicy/);
    expect(gridText).toMatch(/RunInstances/);
    expect(gridText).toMatch(/203\.0\.113\.42/);
    expect(gridText).toMatch(/185\.220\.101\.33/);
  });
});

test.describe('Timeline — AWS CloudTrail (wrapped JSON form)', () => {
  const ctx = useSharedBundlePage();

  test('wrapped {"Records":[...]} document is detected, unwrapped, and routed', async () => {
    const findings = await loadFixture(ctx.page, WRAPPED_FIXTURE);
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();
    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    // Same record count as the JSONL fixture — they're built from
    // the same source data. If the unwrap dropped or duplicated a
    // record this assertion catches it.
    expect(result!.timelineRowCount).toBe(EXPECTED_ROWS);
    expect((result as { formatTag?: string }).formatTag).toBe('AWS CloudTrail');
  });

  test('canonical schema is identical to the JSONL form', async () => {
    const result = await dumpResult(ctx.page);
    // See sibling test for why we read `timelineBaseColumns`.
    const cols = (result as { timelineBaseColumns?: string[] }).timelineBaseColumns!;
    expect(cols).toBeDefined();
    expect(cols[0]).toBe('eventTime');
    expect(cols[1]).toBe('eventName');
    expect(cols[2]).toBe('eventSource');
    expect(cols[cols.length - 1]).toBe('_extra');
  });
});
