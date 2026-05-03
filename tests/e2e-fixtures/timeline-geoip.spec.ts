// ════════════════════════════════════════════════════════════════════════════
// timeline-geoip.spec.ts — Smoke for the bundled-GeoIP enrichment pass.
//
// Loads `tests/e2e-fixtures/timeline-geoip.csv` (10 rows, single
// `client_ip` column with a mix of well-known public IPv4 addresses
// from multiple RIRs). Asserts:
//
//   1. The file lands in the Timeline route.
//   2. `app.geoip` resolves synchronously to the bundled provider.
//   3. After the constructor's +100 ms enrichment timer fires, exactly
//      one `kind: 'geoip'` extracted column exists, named
//      `client_ip.geo`, with non-empty cells whose shape matches the
//      provider's `<Country>/<ISO2>` slash format.
//   4. Reserved/private IPs (when present) render empty — but the
//      fixture deliberately uses only globally-routable addresses so
//      every row should be enriched.
//
// ── What this DOES NOT cover ────────────────────────────────────────────────
// • The MMDB upload path (`MmdbReader` + IndexedDB hydrate). That
//   surface is exercised by `tests/unit/mmdb-reader.test.js` against
//   the real DB-IP fixture under `examples/mmdb/`.
// • The right-click "Look up GeoIP" override on extracted columns —
//   the popover surface lives behind a 2-click interaction we don't
//   need to exercise here; the underlying `_runGeoipEnrichment({
//   forceCol })` path is unit-tested in
//   `tests/unit/timeline-view-geoip.test.js`.
// • The done-marker idempotence on file reopen — covered by the unit
//   test against `_loadAutoExtractDoneFor`.
//
// ── Timing note ─────────────────────────────────────────────────────────────
// The TimelineView constructor schedules `_runGeoipEnrichment()` at
// +100 ms; the router schedules a follow-up at +0 ms after stamping
// `_app`. Either path produces the column. We wait for the column to
// appear via `waitForFunction` rather than a fixed sleep, so a future
// timing change in the constructor doesn't flake this test.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import * as path from 'node:path';
import {
  loadFixture,
  dumpResult,
  REPO_ROOT,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const FIXTURE_REL = path.join('tests', 'e2e-fixtures', 'timeline-geoip.csv');
const ROWS = 10;

test.describe('Timeline GeoIP — bundled provider', () => {
  const ctx = useSharedBundlePage();

  test('CSV with IPv4 column gets a `<src>.geo` enrichment column', async () => {
    const findings = await loadFixture(ctx.page, FIXTURE_REL);
    // Timeline-routed loads never stamp findings (matches the existing
    // example.csv assertion in office.spec.ts).
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();

    const result = await dumpResult(ctx.page);
    expect(result).not.toBeNull();
    expect(result!.timeline).toBe(true);
    expect(result!.timelineRowCount).toBe(ROWS);

    // `app.geoip` must resolve to the bundled provider on first paint —
    // the async MMDB hydrate from IndexedDB shouldn't be on the critical
    // path. `BundledGeoip.providerKind === 'bundled'` is the contract.
    const providerKind = await ctx.page.evaluate(() => {
      const w = window as unknown as { app: { geoip?: { providerKind?: string } } };
      return (w.app && w.app.geoip && w.app.geoip.providerKind) || null;
    });
    expect(providerKind).toBe('bundled');

    // Wait for the geo column to materialise. The constructor schedules
    // enrichment at +100 ms post-mount; the router schedules a follow-up
    // at +0 ms after `view._app = this` (line 525 in timeline-router.js).
    // Either path produces the column. 5 s budget is generous on cold CI.
    await ctx.page.waitForFunction(() => {
      const w = window as unknown as { app: { _timelineCurrent?: { _extractedCols?: Array<{ kind?: string }> } } };
      const tl = w.app && w.app._timelineCurrent;
      if (!tl || !Array.isArray(tl._extractedCols)) return false;
      return tl._extractedCols.some(e => e && e.kind === 'geoip');
    }, null, { timeout: 5_000 });

    // Inspect the extracted column directly — the test API doesn't
    // surface this today (extracted cols are an internal Timeline
    // concept), so we read off `app._timelineCurrent._extractedCols`.
    // The shape mirrors `_dataset.addExtractedCol` payload in
    // `timeline-view-geoip.js::_enrichSingleIpCol`.
    const geoCols = await ctx.page.evaluate(() => {
      const w = window as unknown as { app: { _timelineCurrent: { _extractedCols: Array<{ name: string; kind?: string; sourceCol?: number; values: unknown[]; providerKind?: string }> } } };
      const cols = w.app._timelineCurrent._extractedCols;
      return cols
        .filter(c => c && c.kind === 'geoip')
        .map(c => ({
          name: c.name,
          sourceCol: c.sourceCol,
          providerKind: c.providerKind,
          rowCount: Array.isArray(c.values) ? c.values.length : 0,
          // Sample the first 5 cells; serialising the full 10-row array
          // is fine but we only need a handful to assert shape.
          sampleValues: Array.isArray(c.values) ? c.values.slice(0, 5).map(v => String(v || '')) : [],
        }));
    });

    expect(geoCols.length).toBe(1);
    const geo = geoCols[0];
    expect(geo.name).toBe('client_ip.geo');
    expect(geo.providerKind).toBe('bundled');
    expect(geo.rowCount).toBe(ROWS);

    // The bundled provider's `formatRow` returns `<Country>/<ISO2>` for
    // routable IPv4 (no region/city). All 5 sampled IPs are public
    // addresses that fall inside the RIR-derived ranges, so every cell
    // must be non-empty AND match the slash shape.
    const slashShape = /^[A-Za-z][A-Za-z .,'\-()]*\/[A-Z]{2}$/; // safe: bounded literal, ANN-OK
    for (const cell of geo.sampleValues) {
      expect(cell.length).toBeGreaterThan(2);
      expect(cell).toMatch(slashShape);
    }
  });

  test('Geo column cells render non-empty at first paint (no filter / sort needed)', async () => {
    // Regression for the "empty geo cells until you filter" bug. The
    // GridViewer's row materialiser reads through a `TimelineRowView`
    // adapter that snapshots `_totalCols` at construction time. Before
    // the fix, `_rebuildExtractedStateAndRender`'s fast path (the one
    // that calls `_grid._updateColumns(...)` in place) skipped the
    // `setRows(rowView, ...)` call — so even though the new column was
    // present in `this.columns`, every grid cell for it materialised
    // as `''` until the next filter / sort triggered a fresh rowView.
    //
    // Read the geo cell text straight off the DOM. Cells stamp
    // `data-col` with the REAL column index (display reorder safe);
    // we look up the geo column's real index dynamically in case a
    // future schema change shifts it.
    // Wait for the grid to actually paint the geo cells into the DOM.
    // `_rebuildExtractedStateAndRender` updates `_extractedCols` synchronously
    // but schedules the grid repaint via requestAnimationFrame; on slow CI
    // machines the RAF may not have executed by the time a plain evaluate()
    // runs. We wait here for at least one non-empty cell to appear — this also
    // serves as the regression assertion: with the old empty-cell bug this
    // waitForFunction would time out because cells would render as '' forever.
    await ctx.page.waitForFunction(() => {
      const w = window as unknown as {
        app: { _timelineCurrent?: { columns?: string[] } };
      };
      const cols = w.app?._timelineCurrent?.columns;
      if (!cols) return false;
      const geoIdx = cols.indexOf('client_ip.geo');
      if (geoIdx < 0) return false;
      const cells = document.querySelectorAll(
        `.tl-grid .grid-row .grid-cell[data-col="${geoIdx}"]`
      );
      return Array.from(cells).some(c => (c.textContent || '').trim().length > 0);
    }, null, { timeout: 5_000 });

    const geoCellTexts = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: { _timelineCurrent: { columns: string[] } };
      };
      const cols = w.app._timelineCurrent.columns;
      const geoIdx = cols.indexOf('client_ip.geo');
      if (geoIdx < 0) return null;
      const cells = document.querySelectorAll(
        `.tl-grid .grid-row .grid-cell[data-col="${geoIdx}"]`
      );
      return Array.from(cells).slice(0, 5).map(c => (c.textContent || '').trim());
    });
    expect(geoCellTexts).not.toBeNull();
    // We rendered five rows; every visible geo cell must be non-empty
    // (10/10 IPs in the fixture are public, none are reserved).
    expect(geoCellTexts!.length).toBeGreaterThan(0);
    for (const txt of geoCellTexts!) {
      expect(txt.length).toBeGreaterThan(2);
      expect(txt).toMatch(/\//);
    }
  });

  test('Geo column lands in the display order immediately after its IPv4 source', async () => {
    // Regression for the "geo column at the far right" bug. The fixture
    // has columns: timestamp, user, client_ip, action. Geo enrichment
    // appends `client_ip.geo` to `_extractedCols`, so its REAL index
    // is 4 (last). But its display position must be slot 4 — between
    // `client_ip` (real 2 / display 3 because row# occupies slot 0)
    // and `action` (real 3 / display 5).
    const headerLayout = await ctx.page.evaluate(() => {
      // Walk the main grid's header in DOM order, collecting the real
      // column index off `data-col`. The row-number cell has no
      // `data-col`, so it's skipped; the resulting array is the
      // post-reorder display sequence keyed by REAL index.
      const cells = document.querySelectorAll('.tl-grid .grid-header-cell[data-col]');
      return Array.from(cells).map(c => parseInt((c as HTMLElement).dataset.col || '-1', 10));
    });
    expect(headerLayout.length).toBeGreaterThan(0);
    // Resolve real indices for the columns we care about. `columns`
    // is the live array on the TimelineView.
    const indices = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: { _timelineCurrent: { columns: string[] } };
      };
      const cols = w.app._timelineCurrent.columns;
      return {
        clientIp: cols.indexOf('client_ip'),
        geo: cols.indexOf('client_ip.geo'),
        action: cols.indexOf('action'),
      };
    });
    expect(indices.clientIp).toBeGreaterThanOrEqual(0);
    expect(indices.geo).toBeGreaterThanOrEqual(0);
    expect(indices.action).toBeGreaterThanOrEqual(0);
    // Display position of each in the header DOM.
    const dispClient = headerLayout.indexOf(indices.clientIp);
    const dispGeo = headerLayout.indexOf(indices.geo);
    const dispAction = headerLayout.indexOf(indices.action);
    expect(dispClient).toBeGreaterThanOrEqual(0);
    expect(dispGeo).toBeGreaterThanOrEqual(0);
    expect(dispAction).toBeGreaterThanOrEqual(0);
    // The contract: geo lives BETWEEN `client_ip` and `action`.
    expect(dispGeo).toBe(dispClient + 1);
    expect(dispAction).toBe(dispGeo + 1);
  });

  test('Geo column survives a query narrow without rebuild', async () => {
    // The query bar filter operates on the visible-row mask, NOT on
    // `_extractedCols`. Typing a query that narrows rows must not
    // remove the geoip column or change its sourceCol. Pinned because
    // a regression here would silently break analyst workflow ("type a
    // query → countries disappear").
    const input = ctx.page.locator('.tl-query-input');
    await expect(input).toBeVisible();
    await input.fill('login');
    await input.press('Enter');

    // Geo column should still exist after the query narrows.
    const stillThere = await ctx.page.evaluate(() => {
      const w = window as unknown as { app: { _timelineCurrent: { _extractedCols: Array<{ kind?: string }> } } };
      return w.app._timelineCurrent._extractedCols.some(c => c && c.kind === 'geoip');
    });
    expect(stillThere).toBe(true);
  });
});
