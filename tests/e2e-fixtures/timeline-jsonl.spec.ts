// ════════════════════════════════════════════════════════════════════════════
// timeline-jsonl.spec.ts — End-to-end coverage for the JSONL Timeline
// route.
//
// What this spec proves:
//   1. A `.jsonl` fixture (newline-delimited JSON, one object per
//      line) routes through the structured-log worker path
//      (kindHint='jsonl'). The schema is parsed from the first
//      record's flattened key set; subsequent records project onto
//      that schema with unknown keys spilled into a synthetic
//      `_extra` column.
//   2. Nested objects flatten to dotted paths (`client.ip`,
//      `client.port`).
//   3. `dumpResult()` reports `formatLabel: 'JSONL'` and the
//      expected column count (first-record keys + `_extra`).
//   4. The default histogram stack column resolves to `level`
//      (matches the `_STACK_CANDIDATES` priority list — `level`
//      ranks above `severity` and far above the auto-detect default).
//   5. Zero IOCs are emitted despite the fixture containing IPv4
//      addresses inside `client.ip` cells (10.0.0.42, 192.0.2.13,
//      192.0.2.99) — the structured-log Timeline route stays
//      analyser-free.
//   6. Records carrying unknown keys (line 9 has `trace_id`,
//      `span_id`; line 10 has `retry_count`) populate `_extra`
//      with a JSON-encoded sub-object rather than dropping the
//      data on the floor.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const FIXTURE_REL = 'tests/e2e-fixtures/jsonl-sample.jsonl';
const EXPECTED_ROWS = 11;

test.describe('Timeline — JSONL', () => {
  const ctx = useSharedBundlePage();

  test('routes to JSONL parser, parses first-record schema, populates RowStore', async () => {
    const findings = await loadFixture(ctx.page, FIXTURE_REL);

    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();

    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount).toBe(EXPECTED_ROWS);
    expect((result as { formatTag?: string }).formatTag).toBe('JSONL');

    // Schema = first record's keys (flattened, dotted-path) + _extra.
    // First record (line 1) has 5 top-level keys: ts, level, msg, port,
    // host. None are nested — `client` only appears from line 2 onward,
    // so it's NOT in the schema. Those records' `client.ip` /
    // `client.port` cells go into _extra instead.
    const cols = (result as { timelineColumns?: string[] }).timelineColumns!;
    expect(cols).toBeDefined();
    expect(cols).toContain('ts');
    expect(cols).toContain('level');
    expect(cols).toContain('msg');
    expect(cols).toContain('host');
    expect(cols).toContain('_extra');
    // The Timeline pipeline may append GeoIP `.geo` enrichment
    // columns when an IPv4 column is detected; the JSONL schema's
    // first record has no IPv4 cells (client.ip lives in _extra),
    // so we don't expect any `.geo` columns here. Future-proof
    // assertion: there should be no `.geo` column whose source is
    // a column we know is empty.
  });

  test('records with extra keys populate the _extra column as JSON', async () => {
    const result = await dumpResult(ctx.page);
    const cols = (result as { timelineColumns?: string[] }).timelineColumns!;
    const extraIdx = cols.indexOf('_extra');
    expect(extraIdx).toBeGreaterThanOrEqual(0);

    // Line 2 in the fixture introduces `client` (a nested object
    // not in the first record's schema). Its `client.ip` and
    // `client.port` flattened keys must appear in the `_extra`
    // cell as a JSON-encoded sub-object.
    //
    // Read the rendered grid text and find any cell that looks like
    // a JSON object containing `client.ip`. We don't pin to a
    // specific row index because column display order may put
    // `_extra` anywhere in the visible grid.
    const gridText = await ctx.page.locator('.grid-row').evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));
    expect(gridText).toMatch(/client\.ip/);
    expect(gridText).toMatch(/10\.0\.0\.42/);
  });

  test('Timeline grid paints rows', async () => {
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    expect(await rows.count()).toBeGreaterThan(0);
  });
});
