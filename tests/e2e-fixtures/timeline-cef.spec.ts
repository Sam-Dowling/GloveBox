// ════════════════════════════════════════════════════════════════════════════
// timeline-cef.spec.ts — End-to-end coverage for the CEF (Common
// Event Format / ArcSight) Timeline route.
//
// CEF is the lingua franca of SIEM appliances. Lines look like:
//   CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|key=val key=val…
// Real-world CEF is overwhelmingly tunneled inside a syslog wrapper
// (`<134>Oct 15 …host vendor: CEF:0|…`); the fixture mixes raw CEF
// with syslog-wrapped CEF to exercise both paths.
//
// What this spec proves:
//   1. A `.cef` fixture routes via `kindHint='cef'` with
//      `formatTag: 'CEF'` and parses all 10 fixture rows.
//   2. The schema is the 7-column CEF header (Version, Vendor,
//      Product, ProductVersion, SignatureID, Name, Severity)
//      followed by extension keys locked from the first record's
//      `key=value` block, then `_extra`.
//   3. Syslog-wrapped CEF lines (rows 7-8 in the fixture) are
//      successfully unwrapped — the Vendor / Product / Name cells
//      reflect the CEF body, NOT the syslog header.
//   4. Records carrying ext keys not in the locked schema (rows
//      6 with `app=`, 7 with `fname=`, 8 with `url=`) populate
//      `_extra` rather than dropping the data.
//   5. Zero IOCs are emitted despite the fixture carrying public
//      IPv4s and a URL — the CEF Timeline route is analyser-free.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const FIXTURE_REL = 'tests/e2e-fixtures/cef-sample.cef';
const EXPECTED_ROWS = 10;

test.describe('Timeline — CEF', () => {
  const ctx = useSharedBundlePage();

  test('routes to CEF parser, schema is header + ext keys + _extra', async () => {
    const findings = await loadFixture(ctx.page, FIXTURE_REL);
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();
    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount).toBe(EXPECTED_ROWS);
    expect((result as { formatTag?: string }).formatTag).toBe('CEF');

    // Read the IMMUTABLE base schema. `timelineColumns` (the live
    // `tlView.columns` getter) is base + `_extractedCols`, and the
    // auto-extract idle pump (+60 ms post-mount) appends extracted
    // columns asynchronously after `loadFixture` resolves — by the
    // time the next assertion runs, `cols[cols.length - 1]` may be
    // an auto-extracted "ProductVersion (host)" column rather than
    // the trailing `_extra`. `timelineBaseColumns` is set once during
    // parser construction and never mutated.
    const cols = (result as { timelineBaseColumns?: string[] }).timelineBaseColumns!;
    expect(cols).toBeDefined();
    // 7 canonical header columns in canonical order.
    expect(cols[0]).toBe('Version');
    expect(cols[1]).toBe('Vendor');
    expect(cols[2]).toBe('Product');
    expect(cols[3]).toBe('ProductVersion');
    expect(cols[4]).toBe('SignatureID');
    expect(cols[5]).toBe('Name');
    expect(cols[6]).toBe('Severity');
    // Extension keys from the first record (FortiGate row): src,
    // dst, spt, dpt, proto, act.
    expect(cols).toContain('src');
    expect(cols).toContain('dst');
    expect(cols).toContain('spt');
    expect(cols).toContain('dpt');
    expect(cols).toContain('proto');
    expect(cols).toContain('act');
    // `_extra` is always the trailing column.
    expect(cols[cols.length - 1]).toBe('_extra');
  });

  test('grid renders header cells and ext values from raw + syslog-wrapped CEF', async () => {
    const rows = ctx.page.locator('.grid-row');
    await expect(rows.first()).toBeVisible({ timeout: 5_000 });
    expect(await rows.count()).toBeGreaterThan(0);
    const gridText = await rows.evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));
    // Vendor / Product values present.
    expect(gridText).toMatch(/FortiGate/);
    expect(gridText).toMatch(/PaloAlto/);
    expect(gridText).toMatch(/CheckPoint/);
    expect(gridText).toMatch(/McAfee/);
    // Names visible (raw + wrapped).
    expect(gridText).toMatch(/firewall accept/);
    expect(gridText).toMatch(/ips alert/);
    expect(gridText).toMatch(/antivirus block/);   // syslog-wrapped row 7
    expect(gridText).toMatch(/web filter/);        // syslog-wrapped row 8
    // Ext IPs.
    expect(gridText).toMatch(/10\.0\.0\.1/);
    expect(gridText).toMatch(/185\.220\.101\.33/);
  });

  test('extension keys not in the locked schema spill into _extra', async () => {
    // The first record (FortiGate firewall accept) locks the
    // schema as src/dst/spt/dpt/proto/act. Subsequent records
    // carry `user` (PaloAlto), `app` (FortiGate app control),
    // `fname` (FortiGate antivirus), `url` (FortiGate web filter).
    // None of those are in the locked schema → they must appear
    // in the `_extra` cell as a JSON sub-object.
    const result = await dumpResult(ctx.page);
    const cols = (result as { timelineColumns?: string[] }).timelineColumns!;
    const extraIdx = cols.indexOf('_extra');
    expect(extraIdx).toBeGreaterThanOrEqual(0);

    const gridText = await ctx.page.locator('.grid-row').evaluateAll(els =>
      els.map(el => el.textContent || '').join('\n'));
    // The unknown keys must appear somewhere in the grid text
    // (specifically inside the JSON-encoded _extra cell).
    expect(gridText).toMatch(/"user":\s*"alice"/);
    expect(gridText).toMatch(/"app":\s*"facebook"/);
    expect(gridText).toMatch(/"fname":\s*"malware\.exe"/);
    expect(gridText).toMatch(/"url"/);
  });
});
