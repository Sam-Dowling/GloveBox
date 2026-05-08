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
// / Severity / Category / Process from UserId / EventName / Outcome
// / Workload / UserAgent respectively.
const FIXTURE_M365_A = 'tests/e2e-fixtures/m365-audit-a.csv';
const FIXTURE_M365_B = 'tests/e2e-fixtures/m365-audit-b.csv';

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
    // now catch UserId / EventName / Workload / Outcome / ClientIP /
    // UserAgent / Raw → User / EventID / Category / Severity / SourceIP
    // / Process / Message. Host + DestIP have no source column so get
    // culled.
    expect(result!.columns).toContain('__source');
    expect(result!.columns).toContain('__format');
    expect(result!.columns).toContain('Timestamp');
    expect(result!.columns).toContain('User');
    expect(result!.columns).toContain('EventID');
    expect(result!.columns).toContain('Severity');
    expect(result!.columns).toContain('Category');
    expect(result!.columns).toContain('SourceIP');
    expect(result!.columns).toContain('Process');
    expect(result!.columns).toContain('Message');
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
});
