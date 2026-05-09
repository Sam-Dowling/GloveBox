// ════════════════════════════════════════════════════════════════════════════
// timeline-merge.spec.ts — End-to-end coverage for the merged-Timeline
// feature: drop-to-add on an already-loaded Timeline, source chip bar
// rendering, toggle-off filtering, canonical columns (`__source` /
// `__format`), and source: query facet.
//
// What this spec proves:
//   1. Loading a first CSV opens a single-source Timeline (no chip bar).
//   2. Loading a second CSV onto the existing view triggers the merge
//      path — `_timelineCurrent._sources.length === 2`, composite row
//      count == sum of per-source rows, chip bar is visible.
//   3. Canonical columns (`__source`, `__format`, etc.) exist in
//      `timelineColumns` and carry per-row values.
//   4. Toggling a source off via the API dims its rows — the filtered
//      grid row count drops to the kept source's rows.
//   5. The `source:` query facet resolves to the `__source` column.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

const FIXTURE_A = 'tests/e2e-fixtures/timeline-geoip.csv';
const FIXTURE_B = 'tests/e2e-fixtures/timeline-merge-second.csv';
// M365-audit-shaped fixtures — identical 9-col schema. Regression
// guard for the empty-column-cull pass: the post-merge composite
// must not carry any 100%-empty canonical column (Host / DestIP),
// and the mapper's M365-aware aliases must populate User / EventID
// / Severity / Category from UserId / EventName / Outcome / Workload
// respectively. Wide-narrative columns (UserAgent / Raw /
// TargetResource) stay on each source's native plane — they don't
// belong in the canonical cross-source pivot schema.
const FIXTURE_M365_A = 'tests/e2e-fixtures/m365-audit-a.csv';
const FIXTURE_M365_B = 'tests/e2e-fixtures/m365-audit-b.csv';
// Disjoint-time-range fixtures — `chrono-newer.csv` spans 12:00–12:20,
// `chrono-older.csv` spans 09:00–09:20. Loading newer first then
// merging older produces source-concat order [12:00..12:20,
// 09:00..09:20] which is NOT chronological — exercises the regression
// where the grid header advertised "asc by Timestamp" while rows
// painted in source-concat order. Used by the chrono-order pin below.
const FIXTURE_CHRONO_NEWER = 'tests/e2e-fixtures/timeline-merge-chrono-newer.csv';
const FIXTURE_CHRONO_OLDER = 'tests/e2e-fixtures/timeline-merge-chrono-older.csv';
// Synthetic EDR / endpoint-export fixtures, one per Tier-1 vendor.
// Each fixture's column header set matches the vendor's real export
// shape so the CSV mapper's probe-list aliases (in
// `src/app/timeline/timeline-mapper.js`) populate the canonical
// columns from vendor-specific names. Hand-crafted (~10 rows each),
// privacy-safe placeholder identities. Timestamps are intentionally
// disjoint per fixture so the chrono-sort path also gets exercised
// when all four are merged.
const FIXTURE_EDR_FALCON = 'tests/e2e-fixtures/edr-falcon.csv';
const FIXTURE_EDR_MDE = 'tests/e2e-fixtures/edr-mde.csv';
const FIXTURE_EDR_SENTINELONE = 'tests/e2e-fixtures/edr-sentinelone.csv';
const FIXTURE_EDR_CORTEX = 'tests/e2e-fixtures/edr-cortex.csv';

test.describe('Timeline — merged sources', () => {
  const ctx = useSharedBundlePage();

  test('single-source load leaves _sources null (single-file path unchanged)', async () => {
    await loadFixture(ctx.page, FIXTURE_A);
    const tl = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: {
          _timelineCurrent: {
            _sources: unknown;
            store: { rowCount: number };
          } | null;
        };
      };
      const v = w.app._timelineCurrent;
      if (!v) return null;
      return { sources: v._sources, rowCount: v.store.rowCount };
    });
    expect(tl).not.toBeNull();
    expect(tl!.sources).toBeNull();
    expect(tl!.rowCount).toBe(10);
  });

  test('REGRESSION: second file through real drop path merges (not replaces)', async () => {
    // This test drives BOTH fixtures through the real drop entry point
    // (`__loupeTest.loadBytes` → `App._loadFile` → `_timelineTryHandle`).
    // The original regression: `_timelineTryHandle`'s merge gate
    // checked `_timelineCurrent._sources` which is null after a
    // legacy single-file load, so the second drop fell through to the
    // replace path and the first file vanished.
    //
    // Guards Bug 1 of the multi-source fix pass: a freshly-loaded
    // single-file Timeline must still trigger the merge branch when a
    // second eligible file arrives via `_loadFile`.
    await loadFixture(ctx.page, FIXTURE_A);
    // Confirm starting state — 10 rows, no _sources.
    const first = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: { _timelineCurrent: {
          _sources: unknown;
          store: { rowCount: number };
        } | null };
      };
      return {
        sources: w.app._timelineCurrent?._sources ?? null,
        rowCount: w.app._timelineCurrent?.store.rowCount ?? 0,
      };
    });
    expect(first.sources).toBeNull();
    expect(first.rowCount).toBe(10);

    // Load the second fixture via the same real entry point, but
    // with `skipCrossLoadReset` so the test API's
    // `_testApiResetCrossLoadState` doesn't destroy the first view
    // before the merge gate has a chance to see it. Real user drops
    // naturally preserve the prior Timeline (no test-side teardown
    // hook); this option models that real-user behaviour.
    await loadFixture(ctx.page, FIXTURE_B, undefined, { skipCrossLoadReset: true });

    // After the second load we should see a composite Timeline
    // carrying BOTH sources, not a fresh single-file replacement.
    const merged = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: {
          _timelineCurrent: {
            _sources: Array<{ sourceLabel: string }> | null;
            store: { rowCount: number };
          } | null;
        };
      };
      const v = w.app._timelineCurrent;
      return {
        hasSources: !!(v && v._sources),
        sourceCount: v && v._sources ? v._sources.length : 0,
        sourceLabels: v && v._sources ? v._sources.map(s => s.sourceLabel) : [],
        totalRows: v ? v.store.rowCount : 0,
      };
    });
    expect(merged.hasSources).toBe(true);
    expect(merged.sourceCount).toBe(2);
    expect(merged.sourceLabels).toEqual(['timeline-geoip.csv', 'timeline-merge-second.csv']);
    expect(merged.totalRows).toBe(15);
  });

  test('single-source load leaves _sources null (re-asserted for later tests)', async () => {
    // The shared page now holds the merged view from the previous test.
    // Reset by opening a fresh first fixture — `_timelineAddFile` only
    // runs when the current view exists; a brand-new drop into a clean
    // state lands on the legacy single-file path.
    await ctx.page.evaluate(() => {
      const w = window as unknown as { app: { _clearTimelineFile?: () => void } };
      if (w.app._clearTimelineFile) w.app._clearTimelineFile();
    });
    await loadFixture(ctx.page, FIXTURE_A);
    const tl = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: { _timelineCurrent: {
          _sources: unknown;
          store: { rowCount: number };
        } | null };
      };
      const v = w.app._timelineCurrent;
      return v ? { sources: v._sources, rowCount: v.store.rowCount } : null;
    });
    expect(tl).not.toBeNull();
    expect(tl!.sources).toBeNull();
    expect(tl!.rowCount).toBe(10);
  });

  test('drop-to-add: second fixture merges in, creating a composite view', async () => {
    // Feed the second CSV via `_timelineAddFile` directly so we don't
    // depend on the DataTransfer drop-event plumbing (tested separately
    // via the drop-zone specs). This exercises the same code path the
    // drop handler calls.
    const merged = await ctx.page.evaluate(async (payload) => {
      const bin = atob(payload.b64);
      const u8 = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
      const file = new File([u8], payload.name, { type: 'text/csv' });
      const w = window as unknown as {
        app: {
          _timelineAddFile: (f: File) => Promise<void>;
          _timelineCurrent: {
            _sources: Array<{ sourceLabel: string; baseStore: { rowCount: number } }>;
            store: { rowCount: number; colIndex: (n: string) => number };
            _sourceEnabledBitmap: Uint8Array;
          } | null;
        };
      };
      await w.app._timelineAddFile(file);
      const v = w.app._timelineCurrent!;
      return {
        sourceCount: v._sources.length,
        sourceLabels: v._sources.map(s => s.sourceLabel),
        totalRows: v.store.rowCount,
        hasSourceCol: v.store.colIndex('__source') >= 0,
        hasFormatCol: v.store.colIndex('__format') >= 0,
      };
    }, {
      b64: require('node:fs')
        .readFileSync(require('node:path').join(
          __dirname, '..', '..', FIXTURE_B))
        .toString('base64'),
      name: 'timeline-merge-second.csv',
    });

    expect(merged.sourceCount).toBe(2);
    expect(merged.sourceLabels[0]).toBe('timeline-geoip.csv');
    expect(merged.sourceLabels[1]).toBe('timeline-merge-second.csv');
    expect(merged.totalRows).toBe(15);   // 10 + 5
    expect(merged.hasSourceCol).toBe(true);
    expect(merged.hasFormatCol).toBe(true);
  });

  test('chip bar is rendered when sources.length >= 2', async () => {
    const bar = ctx.page.locator('.tl-sources-bar');
    await expect(bar).toBeVisible();
    const chips = ctx.page.locator('.tl-source-chip');
    expect(await chips.count()).toBe(2);
  });

  test('canonical __source column is populated per row', async () => {
    const firstRow = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: {
          _timelineCurrent: {
            store: {
              colIndex: (n: string) => number;
              getCell: (r: number, c: number) => string;
              rowCount: number;
            };
          } | null;
        };
      };
      const s = w.app._timelineCurrent!.store;
      const iSrc = s.colIndex('__source');
      return {
        row0: s.getCell(0, iSrc),
        rowLast: s.getCell(s.rowCount - 1, iSrc),
      };
    });
    // First rows come from the first-loaded source; last rows from the
    // second-loaded source.
    expect(firstRow.row0).toBe('timeline-geoip.csv');
    expect(firstRow.rowLast).toBe('timeline-merge-second.csv');
  });

  test('toggling a source off reduces visible rows', async () => {
    const before = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: { _timelineCurrent: {
          _chipFilteredIdx: { length: number };
        } };
      };
      return w.app._timelineCurrent._chipFilteredIdx.length;
    });
    expect(before).toBe(15);

    // Toggle off the first source.
    await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: {
          _timelineCurrent: {
            _sources: Array<{ sourceId: number }>;
            _toggleSource: (id: number) => void;
          };
        };
      };
      w.app._timelineCurrent._toggleSource(w.app._timelineCurrent._sources[0].sourceId);
    });

    const after = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: { _timelineCurrent: { _chipFilteredIdx: { length: number } } };
      };
      return w.app._timelineCurrent._chipFilteredIdx.length;
    });
    expect(after).toBe(5);  // only the second source's rows

    // Re-enable for subsequent tests (shared page).
    await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: {
          _timelineCurrent: {
            _sources: Array<{ sourceId: number }>;
            _toggleSource: (id: number) => void;
          };
        };
      };
      w.app._timelineCurrent._toggleSource(w.app._timelineCurrent._sources[0].sourceId);
    });
  });

  test('source: query facet resolves to the __source column', async () => {
    // Set the query via the test API's state access. Going through the
    // query editor DOM is brittle in a shared-page context; calling the
    // AST-compile + apply path directly proves the facet resolver works.
    const count = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: {
          _timelineCurrent: {
            _queryStr: string;
            _applyQueryString: (s: string) => void;
            _chipFilteredIdx: { length: number };
          };
        };
      };
      const v = w.app._timelineCurrent;
      v._applyQueryString('source:timeline-merge-second.csv');
      return v._chipFilteredIdx.length;
    });
    // Only the second source's rows should match.
    expect(count).toBe(5);

    // Clear the query so the shared page is clean for subsequent tests.
    await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: { _timelineCurrent: { _applyQueryString: (s: string) => void } };
      };
      w.app._timelineCurrent._applyQueryString('');
    });
  });

  test('REGRESSION: M365-audit merge yields no 100%-empty canonical columns', async () => {
    // Regression guard for the "merged CSV had 7 empty canonical
    // columns" bug. The M365-audit schema is 9 cols that each map to
    // a canonical via the CSV mapper's alias list — merging two of
    // these must produce a composite whose every column is populated
    // by at least one row.
    //
    // Reset the shared page so we land on a clean single-source view.
    await ctx.page.evaluate(() => {
      const w = window as unknown as { app: { _clearTimelineFile?: () => void } };
      if (w.app._clearTimelineFile) w.app._clearTimelineFile();
    });
    await loadFixture(ctx.page, FIXTURE_M365_A);
    await loadFixture(ctx.page, FIXTURE_M365_B, undefined, { skipCrossLoadReset: true });

    const result = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: {
          _timelineCurrent: {
            _sources: Array<{ sourceLabel: string }> | null;
            store: {
              rowCount: number;
              colCount: number;
              columns: string[];
              getCell: (r: number, c: number) => string;
            };
          } | null;
        };
      };
      const v = w.app._timelineCurrent;
      if (!v || !v._sources) return null;
      const cols = v.store.columns;
      const rowCount = v.store.rowCount;
      // For every column, compute its populated-row count.
      const populated: Record<string, number> = {};
      const empties: string[] = [];
      for (let c = 0; c < cols.length; c++) {
        let hits = 0;
        for (let r = 0; r < rowCount; r++) {
          if (v.store.getCell(r, c) !== '') hits++;
        }
        populated[cols[c]] = hits;
        if (hits === 0) empties.push(cols[c]);
      }
      return {
        sourceCount: v._sources.length,
        rowCount,
        columns: cols,
        populated,
        empties,
      };
    });

    expect(result).not.toBeNull();
    expect(result!.sourceCount).toBe(2);
    expect(result!.rowCount).toBe(20);   // 10 + 10
    // ZERO empty columns is the whole point of the cull pass.
    expect(result!.empties).toEqual([]);
    // Canonical columns expected for M365-audit schema: mapper aliases
    // catch UserId / EventName / Workload / Outcome / ClientIP →
    // User / EventID / Category / Severity / SourceIP. Host + DestIP
    // have no source column so get culled. UserAgent / Raw /
    // TargetResource stay on each source's native plane (not
    // canonical).
    expect(result!.columns).toContain('__source');
    expect(result!.columns).toContain('__format');
    expect(result!.columns).toContain('Timestamp');
    expect(result!.columns).toContain('User');
    expect(result!.columns).toContain('EventID');
    expect(result!.columns).toContain('Severity');
    expect(result!.columns).toContain('Category');
    expect(result!.columns).toContain('SourceIP');
    // Wide-narrative columns (UserAgent / Raw / TargetResource) stay
    // on the source's native plane — the canonical schema only holds
    // short identifier-shape values. `Process` and `Message` are
    // intentionally NOT canonical.
    expect(result!.columns).not.toContain('Process');
    expect(result!.columns).not.toContain('Message');
    expect(result!.columns).not.toContain('Host');
    expect(result!.columns).not.toContain('DestIP');
  });

  test('breadcrumb reflects merged sources with composite label + popover', async () => {
    // Regression for "breadcrumb still shows test1 after test2 merges":
    // `_timelineAddFile` never touched `_fileMeta` / `_renderBreadcrumbs`,
    // so the breadcrumb stayed pinned to the first file. The fix adds
    // a merged-Timeline branch to `_renderBreadcrumbs` and calls it
    // from `_swapTimelineView` after every merge / remove.
    await ctx.page.evaluate(() => {
      const w = window as unknown as { app: { _clearTimelineFile?: () => void } };
      if (w.app._clearTimelineFile) w.app._clearTimelineFile();
    });

    // First load — breadcrumb shows the single filename (legacy crumb).
    await loadFixture(ctx.page, FIXTURE_A);
    const firstLabel = await ctx.page
      .locator('#breadcrumbs .crumb-label').first().textContent();
    expect(firstLabel).toBe('timeline-geoip.csv');
    expect(await ctx.page.locator('#breadcrumbs .crumb-merged').count()).toBe(0);

    // Merge the second fixture. Uses `skipCrossLoadReset` so the
    // test API doesn't destroy `_timelineCurrent` before the merge
    // gate intercepts — see the earlier regression test.
    await loadFixture(ctx.page, FIXTURE_B, undefined, { skipCrossLoadReset: true });

    // Merged crumb visible, with n=2 "first-source + 1 other" shape.
    const mergedLabel = await ctx.page
      .locator('#breadcrumbs .crumb-merged .crumb-label').textContent();
    expect(mergedLabel).toBe('timeline-geoip.csv + 1 other');
    const mergedMeta = await ctx.page
      .locator('#breadcrumbs .crumb-merged .crumb-meta').textContent();
    expect(mergedMeta).toContain('15 rows');

    // Tab title reflects the merge.
    const title = await ctx.page.title();
    expect(title).toBe('2 sources merged — Loupe');

    // Click ▾ — sources popover opens, listing both sources.
    await ctx.page.locator('.crumb-sources-btn').click();
    const menu = ctx.page.locator('.crumb-sources-menu');
    await expect(menu).toBeVisible();
    const items = menu.locator('.crumb-sources-menu-item');
    expect(await items.count()).toBe(2);
    const labels = await menu.locator('.crumb-sources-menu-label').allTextContents();
    expect(labels).toEqual(['timeline-geoip.csv', 'timeline-merge-second.csv']);

    // Escape dismisses the popover.
    await ctx.page.keyboard.press('Escape');
    await expect(menu).not.toBeVisible();

    // Remove the first source via the in-view API; n drops to 1 so
    // the breadcrumb falls back to the legacy single-file crumb and
    // `_fileMeta` is refreshed to the surviving source.
    await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: {
          _timelineCurrent: {
            _sources: Array<{ sourceId: number }>;
            _removeSource: (id: number) => void;
          };
        };
      };
      const v = w.app._timelineCurrent;
      v._removeSource(v._sources[0].sourceId);
    });

    // Legacy single-file crumb back, showing the surviving source.
    expect(await ctx.page.locator('#breadcrumbs .crumb-merged').count()).toBe(0);
    const restoredLabel = await ctx.page
      .locator('#breadcrumbs .crumb-label').first().textContent();
    expect(restoredLabel).toBe('timeline-merge-second.csv');
  });

  test('__source column carries the canonical differentiator classes', async () => {
    // After a merge the canonical `__source` column stamps every row
    // with its origin filename. That column is Loupe bookkeeping, not
    // source data, so the grid tags it with a soft dashed-accent
    // differentiator distinct from the Stack-by palette's solid bars.
    // Pin the class application end-to-end so a future refactor that
    // drops the `headerClass` opt or narrows the `cellClass` check
    // surfaces here.
    //
    // Reset so we land on a clean single-source view.
    await ctx.page.evaluate(() => {
      const w = window as unknown as { app: { _clearTimelineFile?: () => void } };
      if (w.app._clearTimelineFile) w.app._clearTimelineFile();
    });
    await loadFixture(ctx.page, FIXTURE_A);
    // Single-source: no canonical classes anywhere (the __source
    // column is hidden by default for n=1 views via the composite
    // schema's "only keep __source+__format always" rule, so the
    // column exists but carries no differentiator regressively
    // because n<2. Assert the CSS class is absent to pin that
    // invariant.
    expect(await ctx.page.locator('.tl-grid .grid-header-canonical').count()).toBe(0);
    expect(await ctx.page.locator('.tl-grid .tl-canonical-cell').count()).toBe(0);

    // Merge B → now __source gets the differentiator everywhere.
    await loadFixture(ctx.page, FIXTURE_B, undefined, { skipCrossLoadReset: true });

    // Grid header — the __source column's header cell carries
    // `grid-header-canonical`. Find by label text to avoid
    // depending on a specific column index.
    const canonicalHeader = ctx.page.locator(
      '.tl-grid .grid-header-cell.grid-header-canonical',
    );
    await expect(canonicalHeader).toHaveCount(1);
    const labelText = await canonicalHeader.locator('.grid-header-label').textContent();
    expect(labelText).toBe('__source');

    // Grid data cells — at least one row's __source cell carries
    // `tl-canonical-cell`. Cells are lazily rendered (virtual
    // scroll); assert against the first few that are in view.
    const canonicalCells = ctx.page.locator('.tl-grid .grid-cell.tl-canonical-cell');
    expect(await canonicalCells.count()).toBeGreaterThan(0);
    const firstCellText = await canonicalCells.first().textContent();
    // Must carry an actual filename (from FIXTURE_A or FIXTURE_B).
    expect(firstCellText).toMatch(/timeline-(geoip|merge-second)\.csv/);

    // Top-Values card — the __source card carries
    // `tl-col-card-canonical`. The card exists because __source has
    // exactly 2 distinct values (one per source) which top-values
    // renders by default.
    const canonicalCard = ctx.page.locator('.tl-col-card.tl-col-card-canonical');
    await expect(canonicalCard).toHaveCount(1);

    // Negative assertion: a non-canonical column's header must NOT
    // carry the differentiator. Find ANY `.grid-header-cell` whose
    // label is NOT `__source` / `__format` and assert it lacks the
    // canonical class.
    const nonCanonicalClassCount = await ctx.page.evaluate(() => {
      const cells = document.querySelectorAll(
        '.tl-grid .grid-header-cell[data-col]');
      let canonicalMarkedButNotSource = 0;
      for (const el of Array.from(cells)) {
        const label = (el.querySelector('.grid-header-label')?.textContent || '').trim();
        const isMarked = el.classList.contains('grid-header-canonical');
        if (isMarked && label !== '__source') canonicalMarkedButNotSource++;
      }
      return canonicalMarkedButNotSource;
    });
    expect(nonCanonicalClassCount).toBe(0);

    // Per-source cell background — each distinct source in
    // `_timelineCurrent._sources` gets its own `tl-source-bg-N`
    // class, and no two sources share a class. Read class
    // membership off `.tl-grid .grid-cell.tl-canonical-cell`
    // scoped to the active timeline-root so a stale prior view's
    // DOM can't poison the check in the shared-page run.
    const bgCheck = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: {
          _timelineCurrent: {
            _sources: Array<{ sourceId: number; sourceLabel: string }>;
          } | null;
        };
      };
      const v = w.app._timelineCurrent;
      if (!v || !v._sources) return null;
      const root = document.getElementById('timeline-root');
      if (!root) return null;
      const cells = root.querySelectorAll('.tl-grid .grid-cell.tl-canonical-cell');
      const filenamesByBg: Record<string, Set<string>> = {};
      for (const el of Array.from(cells)) {
        const name = (el.textContent || '').trim();
        if (!name) continue;
        for (const cls of Array.from(el.classList)) {
          if (cls.indexOf('tl-source-bg-') === 0) {
            if (!filenamesByBg[cls]) filenamesByBg[cls] = new Set();
            filenamesByBg[cls].add(name);
          }
        }
      }
      const out: Record<string, string[]> = {};
      for (const k of Object.keys(filenamesByBg)) {
        out[k] = Array.from(filenamesByBg[k]).sort();
      }
      return {
        sourceLabels: v._sources.map(s => s.sourceLabel).sort(),
        filenamesByBg: out,
      };
    });
    expect(bgCheck).not.toBeNull();
    expect(bgCheck!.sourceLabels)
      .toEqual(['timeline-geoip.csv', 'timeline-merge-second.csv']);
    const bgClasses = Object.keys(bgCheck!.filenamesByBg);
    expect(bgClasses.length).toBeGreaterThan(0);
    // PURITY — every bg class maps to exactly one filename.
    for (const cls of bgClasses) {
      expect(bgCheck!.filenamesByBg[cls]).toHaveLength(1);
      expect(cls).toMatch(/^tl-source-bg-\d+$/);
    }
    // DISTINCTNESS — the two sources get different bg classes.
    const aCls = bgClasses.find(c => bgCheck!.filenamesByBg[c][0] === 'timeline-geoip.csv');
    const bCls = bgClasses.find(c => bgCheck!.filenamesByBg[c][0] === 'timeline-merge-second.csv');
    expect(aCls).toBeDefined();
    expect(bCls).toBeDefined();
    expect(aCls).not.toBe(bCls);

    // Computed-style sanity: canonical cells must NOT inherit the
    // old italic / muted-text treatment (previously-too-grey bug).
    // The user asked for colouring via background, not via grey text.
    const computed = await ctx.page.evaluate(() => {
      const el = document.querySelector('.tl-grid .grid-cell.tl-canonical-cell');
      if (!el) return null;
      const cs = getComputedStyle(el);
      return { fontStyle: cs.fontStyle };
    });
    expect(computed).not.toBeNull();
    expect(computed!.fontStyle).toBe('normal');
  });

  test('REGRESSION: merged Timeline grid paints rows chronologically (not source-concat order)', async () => {
    // Guard for the user-reported bug: after merging a second file,
    // the grid header advertised "sorted ascending by Timestamp" but
    // rows displayed in source-concat order ([source-A rows…,
    // source-B rows…]) until manual re-sort.
    //
    // Root cause: `_rebuildExtractedStateAndRender`'s in-place fast
    // path (called once per applied auto-extract proposal, ~60 ms
    // post-mount) ran `_recomputeFilter()` which reset `_filteredIdx`
    // to the unsorted identity index, then handed that to
    // `GridViewer.setRows(rowView, …, { preSorted: true })`.
    // `setRows` preserved the asc-Timestamp `_sortSpec` but stamped
    // an identity `_sortOrder` against the now-unsorted rowView, so
    // the grid painted in source-concat order while the indicator
    // claimed chronological.
    //
    // Fix: a shared `_chronoSortIdx` helper that the fast path now
    // calls before constructing the rowView. The helper reuses the
    // cached `_sortedFullIdx` populated on first paint (O(1) hit on
    // every subsequent auto-extract tick).
    //
    // The fixtures used here have DISJOINT time ranges
    // (newer = 12:00-12:20, older = 09:00-09:20) so the bug is
    // unmistakable: identity order shows newer-then-older, chrono
    // order shows older-then-newer. The existing FIXTURE_A/B pair
    // has interleaved ranges where a partial regression could
    // accidentally satisfy a monotonic check; disjoint ranges make
    // the assertion bulletproof.

    // Reset the shared page so we land on a clean single-source view.
    await ctx.page.evaluate(() => {
      const w = window as unknown as { app: { _clearTimelineFile?: () => void } };
      if (w.app._clearTimelineFile) w.app._clearTimelineFile();
    });
    // Load NEWER file first, then merge OLDER on top — composite
    // store row order is [newer A1…A5, older B1…B5], deliberately
    // anti-chronological.
    await loadFixture(ctx.page, FIXTURE_CHRONO_NEWER);
    await loadFixture(ctx.page, FIXTURE_CHRONO_OLDER, undefined, { skipCrossLoadReset: true });

    // Wait for the auto-extract pump to settle. Even a single
    // proposal trips the regression because `_rebuildExtractedStateAndRender`
    // runs once per proposal and resets `_filteredIdx` each time.
    // The pump terminus clears `_autoExtractApplying`; poll on that
    // flag (and the post-pump RAF) so we assert against the FINAL
    // grid state, not a mid-pump snapshot.
    await ctx.page.waitForFunction(() => {
      const w = window as unknown as {
        app: {
          _timelineCurrent: {
            _autoExtractApplying?: boolean;
            _sources?: unknown;
          } | null;
        };
      };
      const v = w.app._timelineCurrent;
      return !!(v && v._sources && v._autoExtractApplying === false);
    }, { timeout: 10_000 });
    // One more RAF + microtask tick so any post-pump deferred-surface
    // schedules (`['columns', 'chart', 'scrubber', 'chips']`) have
    // landed before we read the grid.
    await ctx.page.evaluate(() => new Promise<void>(r => requestAnimationFrame(() => r())));

    // Read the chrono-relevant state directly off `_timelineCurrent`:
    //   - `_filteredIdx`: the permutation handed to the GridViewer's
    //     rowView. After the fix, this MUST be chrono-sorted.
    //   - `_timeMs[_filteredIdx[i]]` for i ∈ [0, n): must be
    //     monotonically non-decreasing (NaN-last is permitted at the
    //     tail; these fixtures have no NaN timestamps).
    //   - `_grid._sortSpec`: header indicator state. Must declare
    //     `dir: 'asc'` against `_timeCol`.
    const snapshot = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: {
          _timelineCurrent: {
            _timeMs: Float64Array;
            _timeCol: number;
            _filteredIdx: Uint32Array | null;
            _sources: Array<{ sourceLabel: string }> | null;
            store: { rowCount: number };
            _grid: {
              _sortSpec: { colIdx: number; dir: 'asc' | 'desc' } | null;
              _sortOrder: number[] | null;
            } | null;
          };
        };
      };
      const v = w.app._timelineCurrent;
      const idx = v._filteredIdx;
      if (!idx) return { ready: false };
      const times: number[] = new Array(idx.length);
      for (let i = 0; i < idx.length; i++) times[i] = v._timeMs[idx[i]];
      return {
        ready: true,
        sourceLabels: (v._sources || []).map(s => s.sourceLabel),
        rowCount: v.store.rowCount,
        timeCol: v._timeCol,
        filteredLen: idx.length,
        times,
        sortSpec: v._grid ? v._grid._sortSpec : null,
      };
    });

    expect(snapshot.ready).toBe(true);
    // Sanity: both sources merged.
    expect(snapshot.sourceLabels).toEqual([
      'timeline-merge-chrono-newer.csv',
      'timeline-merge-chrono-older.csv',
    ]);
    expect(snapshot.rowCount).toBe(10);
    expect(snapshot.filteredLen).toBe(10);

    // PRIMARY ASSERTION: the visible row order is chronological.
    // Identity (source-concat) order would yield
    //   times = [12:00, 12:05, 12:10, 12:15, 12:20, 09:00, 09:05, …]
    // which fails monotonicity at the 5→6 boundary.
    for (let i = 1; i < snapshot.times!.length; i++) {
      const prev = snapshot.times![i - 1];
      const curr = snapshot.times![i];
      expect(
        prev <= curr,
        `row ${i}: _timeMs[_filteredIdx[${i - 1}]]=${prev} must be <= _timeMs[_filteredIdx[${i}]]=${curr} ` +
        `(grid painted in source-concat order — chrono-sort regression)`,
      ).toBe(true);
    }

    // Secondary assertion: the header advertises asc-Timestamp.
    // A regression that fixes the order but flips the indicator
    // (or clears `_sortSpec` entirely) would also break the
    // user-visible contract.
    expect(snapshot.sortSpec).not.toBeNull();
    expect(snapshot.sortSpec!.dir).toBe('asc');
    expect(snapshot.sortSpec!.colIdx).toBe(snapshot.timeCol);

    // Tertiary assertion: the FIRST row carries the OLDER source's
    // earliest timestamp (09:00:00Z), not the NEWER source's
    // earliest (12:00:00Z). Belt-and-braces — same condition as
    // the monotonicity loop, but anchored on a known cell value
    // so a future refactor that changed `_filteredIdx` semantics
    // (e.g. window-clip in place of chrono-sort) lights up
    // separately.
    const firstRowTs = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: {
          _timelineCurrent: {
            _filteredIdx: Uint32Array;
            store: {
              colIndex: (n: string) => number;
              getCell: (r: number, c: number) => string;
            };
          };
        };
      };
      const v = w.app._timelineCurrent;
      const tsCol = v.store.colIndex('Timestamp');
      const dataIdx = v._filteredIdx[0];
      return v.store.getCell(dataIdx, tsCol);
    });
    expect(firstRowTs).toMatch(/^2025-04-02T09:00:00/);
  });

  test('EDR vendor merge: canonical columns populate from CrowdStrike + MDE + SentinelOne + Cortex headers', async () => {
    // Pin the EDR / endpoint-export alias coverage end-to-end. Each
    // vendor's CSV uses a different column-naming convention for the
    // same conceptual fields:
    //   - CrowdStrike Falcon:   ComputerName / event_simpleName / UserName
    //                           / LocalAddressIP4 / RemoteAddressIP4
    //   - Microsoft Defender:   DeviceName / ActionType / AccountName
    //                           / RemoteIP
    //   - SentinelOne:          dotted agent.name / event.type
    //                           / src.process.user / src.ip.address
    //                           / dst.ip.address
    //   - Cortex XDR:           agent_hostname / event_type / actor_user
    //                           / action_local_ip / action_remote_ip
    // After the alias expansion in `timeline-mapper.js`, all four
    // populate the canonical Host / EventID / User / SourceIP / DestIP
    // columns regardless of which vendor each row originated from. A
    // regression that drops any vendor's alias would surface as an
    // empty canonical cell on rows from that vendor.

    // Reset the shared page so we start from a clean state.
    await ctx.page.evaluate(() => {
      const w = window as unknown as { app: { _clearTimelineFile?: () => void } };
      if (w.app._clearTimelineFile) w.app._clearTimelineFile();
    });
    // Load the four fixtures sequentially. First load takes the
    // single-file path; subsequent loads merge via `_timelineAddFile`
    // (skipCrossLoadReset preserves the existing view).
    await loadFixture(ctx.page, FIXTURE_EDR_FALCON);
    await loadFixture(ctx.page, FIXTURE_EDR_MDE, undefined, { skipCrossLoadReset: true });
    await loadFixture(ctx.page, FIXTURE_EDR_SENTINELONE, undefined, { skipCrossLoadReset: true });
    await loadFixture(ctx.page, FIXTURE_EDR_CORTEX, undefined, { skipCrossLoadReset: true });

    // Read the canonical projection per source. For each source we
    // sample the first row that originated there (via `_sourceOfRow`)
    // and read the canonical Host / User / EventID / SourceIP cells
    // off the composite store. None of them must be empty.
    const snapshot = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: {
          _timelineCurrent: {
            _sources: Array<{ sourceLabel: string }> | null;
            _sourceOfRow: Uint32Array | null;
            store: {
              rowCount: number;
              colIndex: (n: string) => number;
              getCell: (r: number, c: number) => string;
            };
          } | null;
        };
      };
      const v = w.app._timelineCurrent;
      if (!v || !v._sources || !v._sourceOfRow) return { ready: false };
      const iHost = v.store.colIndex('Host');
      const iUser = v.store.colIndex('User');
      const iEid = v.store.colIndex('EventID');
      const iSip = v.store.colIndex('SourceIP');
      const iDip = v.store.colIndex('DestIP');
      // For each source, find the first row index that came from it
      // and read the canonical cells.
      const perSource: Array<{
        label: string;
        host: string; user: string; eid: string; sip: string; dip: string;
      }> = [];
      for (let s = 0; s < v._sources.length; s++) {
        let firstRow = -1;
        for (let r = 0; r < v.store.rowCount; r++) {
          if (v._sourceOfRow[r] === s) { firstRow = r; break; }
        }
        if (firstRow < 0) continue;
        perSource.push({
          label: v._sources[s].sourceLabel,
          host: iHost >= 0 ? v.store.getCell(firstRow, iHost) : '',
          user: iUser >= 0 ? v.store.getCell(firstRow, iUser) : '',
          eid: iEid >= 0 ? v.store.getCell(firstRow, iEid) : '',
          sip: iSip >= 0 ? v.store.getCell(firstRow, iSip) : '',
          dip: iDip >= 0 ? v.store.getCell(firstRow, iDip) : '',
        });
      }
      return {
        ready: true,
        sourceCount: v._sources.length,
        rowCount: v.store.rowCount,
        canonicalsPresent: {
          host: iHost >= 0,
          user: iUser >= 0,
          eid: iEid >= 0,
          sip: iSip >= 0,
          dip: iDip >= 0,
        },
        perSource,
      };
    });

    expect(snapshot.ready).toBe(true);
    expect(snapshot.sourceCount).toBe(4);
    expect(snapshot.rowCount).toBe(40); // 4 × 10 rows

    // Every canonical column we care about must survive the cull —
    // each is populated by ≥1 source.
    expect(snapshot.canonicalsPresent!.host).toBe(true);
    expect(snapshot.canonicalsPresent!.user).toBe(true);
    expect(snapshot.canonicalsPresent!.eid).toBe(true);
    expect(snapshot.canonicalsPresent!.sip).toBe(true);
    // DestIP may be empty on some rows (e.g. local-only events) but
    // the column must exist because at least Falcon's first row
    // populates it (`203.0.113.7`).
    expect(snapshot.canonicalsPresent!.dip).toBe(true);

    // Per-source: every source contributed at least one row whose
    // canonical Host / User / EventID cells are populated by the
    // vendor's distinctive column. The first row of each fixture is
    // hand-crafted to populate these.
    expect(snapshot.perSource).toHaveLength(4);
    for (const s of snapshot.perSource!) {
      expect(s.host, `Host empty for source ${s.label}`).not.toBe('');
      expect(s.user, `User empty for source ${s.label}`).not.toBe('');
      expect(s.eid, `EventID empty for source ${s.label}`).not.toBe('');
    }
    // SourceIP / DestIP coverage is per-vendor: Falcon / SentinelOne /
    // Cortex carry an agent-perspective LocalIP column on every event,
    // while MDE's `RemoteIP` only fills DestIP (no LocalIP equivalent
    // ships in the standard Advanced Hunting export). Assert the
    // expected partial coverage explicitly so a future regression that
    // dropped, say, Falcon's `LocalAddressIP4` alias would light up.
    const populatedSip = snapshot.perSource!.filter(s => s.sip !== '').map(s => s.label).sort();
    expect(populatedSip).toEqual(
      ['edr-cortex.csv', 'edr-falcon.csv', 'edr-sentinelone.csv'].sort(),
    );
    const populatedDip = snapshot.perSource!.filter(s => s.dip !== '').map(s => s.label).sort();
    // All four populate DestIP on row 0 in the synthetic fixtures.
    expect(populatedDip).toEqual(
      ['edr-cortex.csv', 'edr-falcon.csv', 'edr-mde.csv', 'edr-sentinelone.csv'].sort(),
    );

    // Spot-check the vendor-specific values to prove the alias
    // routing is what's actually doing the work. Order follows the
    // load sequence (Falcon → MDE → SentinelOne → Cortex).
    const byLabel = Object.fromEntries(
      snapshot.perSource!.map(s => [s.label, s]),
    );
    expect(byLabel['edr-falcon.csv']!.host).toBe('WIN-DC01');               // ComputerName
    expect(byLabel['edr-falcon.csv']!.eid).toBe('ProcessRollup2');          // event_simpleName
    expect(byLabel['edr-falcon.csv']!.user).toBe('alice@example.invalid'); // UserName
    expect(byLabel['edr-falcon.csv']!.sip).toBe('10.0.0.5');                // LocalAddressIP4
    expect(byLabel['edr-falcon.csv']!.dip).toBe('203.0.113.7');             // RemoteAddressIP4

    expect(byLabel['edr-mde.csv']!.host).toBe('WIN-WS-007');                // DeviceName
    expect(byLabel['edr-mde.csv']!.eid).toBe('ProcessCreated');             // ActionType
    expect(byLabel['edr-mde.csv']!.user).toBe('bob');                       // AccountName
    expect(byLabel['edr-mde.csv']!.dip).toBe('198.51.100.42');              // RemoteIP

    expect(byLabel['edr-sentinelone.csv']!.host).toBe('mac-laptop-13');     // agent.name
    expect(byLabel['edr-sentinelone.csv']!.eid).toBe('Process Creation');   // event.type
    expect(byLabel['edr-sentinelone.csv']!.user).toBe('carol');             // src.process.user
    expect(byLabel['edr-sentinelone.csv']!.sip).toBe('10.0.0.42');          // src.ip.address
    expect(byLabel['edr-sentinelone.csv']!.dip).toBe('203.0.113.99');       // dst.ip.address

    expect(byLabel['edr-cortex.csv']!.host).toBe('host-cortex-01');         // agent_hostname
    expect(byLabel['edr-cortex.csv']!.eid).toBe('NETWORK_CONNECTION');      // event_type
    expect(byLabel['edr-cortex.csv']!.user).toBe('NT AUTHORITY\\SYSTEM');   // actor_user
    expect(byLabel['edr-cortex.csv']!.sip).toBe('10.0.0.77');               // action_local_ip
    expect(byLabel['edr-cortex.csv']!.dip).toBe('203.0.113.21');            // action_remote_ip

    // Wide-narrative columns survive on the source's native plane —
    // the canonical schema doesn't carry a Process / Message slot
    // (per the trim), so each vendor's command-line column is still
    // pivotable by its original header name.
    const nativeCols = await ctx.page.evaluate(() => {
      const w = window as unknown as {
        app: { _timelineCurrent: { store: { columns: string[] } } };
      };
      return w.app._timelineCurrent.store.columns;
    });
    expect(nativeCols).toContain('CommandLine');                  // Falcon
    expect(nativeCols).toContain('ProcessCommandLine');           // MDE
    expect(nativeCols).toContain('src.process.cmdline');          // SentinelOne
    expect(nativeCols).toContain('actor_process_command_line');   // Cortex
    // And the canonical schema does NOT carry Process or Message:
    expect(nativeCols).not.toContain('Process');
    expect(nativeCols).not.toContain('Message');
  });
});
