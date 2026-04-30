// ════════════════════════════════════════════════════════════════════════════
// timeline-100k.spec.ts — Performance harness for the Timeline route on a
// 100 K-row generated CSV. Opt-in only; skipped unless `LOUPE_PERF=1` is
// set in the environment.
//
// What this measures (one set of samples per run, 3 runs by default):
//
//   Phase 1 — load-start → grid first paint
//     Wall-time from `setInputFiles` returning to the first
//     `.grid-row` becoming visible. This is the cold-load critical
//     path: file read → CSV worker → RowStoreBuilder → Timeline mount
//     → first window-render.
//
//   Phase 2 — grid paint → auto-extract pump drained
//     Wall-time from first paint to `_autoExtractApplying === false
//     && _autoExtractIdleHandle === null`. On a 100 K-row CSV with
//     JSON-shaped columns this is currently the dominant phase.
//
//   Phase 3 — auto-extract done → GeoIP enrichment landed
//     Wall-time until at least one `kind === 'geoip'` extracted
//     column exists with `rowCount === ROWS`, AND the base-detect
//     result cache has been re-niled by the retry hook (or the
//     base-detect path enriched directly without retry). Captures
//     bundled-provider lookup throughput at scale.
//
//   Phase 4 — GeoIP done → fully idle
//     Wall-time until `pendingTasksSize === 0 && !yaraScanInProgress
//     && !timelineLoadInFlight && !autoExtractIdleHandlePending`,
//     stable for 250 ms. Captures the post-enrichment quiescence
//     (deferred chart redraw, top-values strip recompute, etc.).
//
//   Phase 0 — load-start → fully idle  (wall-clock total; computed
//     post-hoc from phase 1+2+3+4 durations).
//
// Per-phase metrics: `JSHeapUsedSize` / `JSHeapTotalSize` (Chromium
// CDP `Performance.getMetrics`) for absolute heap, plus
// `Documents` / `Nodes` / `LayoutCount` for DOM-leak detection.
//
// Output: `dist/perf-report.json` (full per-run + summary), Markdown
// table to stdout.
//
// ── Why a separate suite, not a fixture spec ─────────────────────────────────
// Two reasons. First, the fixture is 160 MB at 100 K rows; running it
// inside the default e2e loop would balloon CI wall-time by 30+ s and
// the OOM-on-stress-load flake risk is real. Second, the perf path
// REQUIRES a fresh page per run — the existing `useSharedBundlePage`
// pattern intentionally reuses a single page for ~290 fixture loads,
// which is the opposite of what a perf measurement wants (the prior
// fixture's findings/store leak into the next baseline).
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import * as path from 'node:path';
import * as fs from 'node:fs';
import {
  REPO_ROOT,
  getPerfConfig,
  ensureFixture,
  attachCdp,
  pollPerfState,
  getPerfState,
  summarise,
  writeReport,
  markdownSummary,
  PERF_SCHEMA_VERSION,
} from './perf-helpers';
import type {
  RunReport,
  PhaseSample,
  PhaseName,
  PerfReport,
  MetricBag,
} from './perf-helpers';

const RUN = process.env.LOUPE_PERF === '1';

test.describe('Timeline performance — generated CSV', () => {
  // Self-skip when not opted in. The whole perf suite costs ~90 s on a
  // warm machine even at the default 100 K rows; nobody wants that on
  // the default `make.py test-e2e` loop.
  test.skip(!RUN, 'set LOUPE_PERF=1 to run the perf suite');

  // Long timeout — the spec times multiple full file loads end-to-end,
  // each of which can be ≥ 30 s on cold runners. The per-phase polls
  // have their own (shorter) budgets via `phaseTimeoutMs`.
  test.setTimeout(20 * 60 * 1000);

  test('Timeline 100k.csv — load → auto-extract → geoip → idle', async ({ browser }) => {
    const cfg = getPerfConfig();
    const fixturePath = ensureFixture(cfg.rows, cfg.seed);
    const fixtureSizeMb = fs.statSync(fixturePath).size / (1024 * 1024);
    const bundlePath = path.join(REPO_ROOT, 'docs', 'index.test.html');
    if (!fs.existsSync(bundlePath)) {
      throw new Error(
        `perf: docs/index.test.html not found. Run \`python make.py test-build\` ` +
        `(or rebuild via run_perf.py which auto-rebuilds when stale).`);
    }

    const runs: RunReport[] = [];

    for (let runIdx = 1; runIdx <= cfg.runs; runIdx++) {
      // eslint-disable-next-line no-console
      console.log(`\n[perf] === run ${runIdx} / ${cfg.runs} ===`);
      // Fresh context (and therefore fresh BrowserContext-scoped
      // Service Worker / IndexedDB / cache / heap) per run. This is
      // the cleanest way to get a fresh JS heap baseline without
      // poking around inside V8.
      const context = await browser.newContext();
      const page = await context.newPage();
      try {
        await page.goto('');
        await page.waitForFunction(() => {
          const w = window as unknown as { __loupeTest?: { ready: Promise<void> } };
          return !!(w.__loupeTest && w.__loupeTest.ready);
        });
        await page.evaluate(() => {
          const w = window as unknown as { __loupeTest: { ready: Promise<void> } };
          return w.__loupeTest.ready;
        });

        const cdp = await attachCdp(context, page);

        // Baseline metrics — captured AFTER bundle load + App.init() but
        // BEFORE any file is loaded. The "delta" reported per phase
        // subtracts this so the numbers are about the file load, not
        // the empty App's overhead.
        const baselineMetrics = await cdp.snapshot();
        // eslint-disable-next-line no-console
        console.log(`[perf] baseline heap=${baselineMetrics.jsHeapUsedMb.toFixed(1)} MB nodes=${baselineMetrics.nodes}`);

        // Locate the hidden file picker (mirrors `tests/e2e-ui/file-picker.spec.ts`).
        const fileInput = page.locator('input[type="file"]').first();
        await expect(fileInput).toHaveCount(1);

        // ── Phase 1 — load-start → first grid paint ────────────────
        const tLoadStart = Date.now();
        // `setInputFiles` returns once the browser has staged the file
        // for the input; the synchronous `change` event fires on the
        // way out. By the time this resolves, `_handleFiles` has been
        // invoked. The actual parse happens asynchronously inside the
        // Timeline route — we measure to first `.grid-row` paint next.
        await fileInput.setInputFiles(fixturePath);

        const firstRow = page.locator('.grid-row').first();
        await expect(firstRow).toBeVisible({ timeout: cfg.phaseTimeoutMs });
        const phase1Wall = Date.now() - tLoadStart;
        const phase1Metrics = await cdp.snapshot();
        // eslint-disable-next-line no-console
        console.log(`[perf]  phase1 (paint):       ${phase1Wall} ms  heap=${phase1Metrics.jsHeapUsedMb.toFixed(1)} MB`);

        // ── Phase 2 — first paint → auto-extract pump drained ──────
        // Predicate: timeline mounted, apply pump not active, no idle
        // handle pending, AND we've actually attempted to extract
        // something (`extractedColCount > 0`) OR the base-detect
        // already settled with no proposals (`autoExtractApplying`
        // never flipped on, but `geoipBaseDetectKind !== 'absent'`
        // tells us GeoIP at least observed the mounted view).
        // Stable for 250 ms to avoid catching a transient gap between
        // proposals.
        const tPhase2Start = Date.now();
        await pollPerfState(page,
          { kind: 'autoextract-done' },
          {
            timeoutMs: cfg.phaseTimeoutMs,
            pollMs: cfg.pollIntervalMs,
            stableMs: 250,
            label: 'phase2-autoextract-done',
          });
        const phase2Wall = Date.now() - tPhase2Start;
        const phase2Metrics = await cdp.snapshot();
        // eslint-disable-next-line no-console
        console.log(`[perf]  phase2 (auto-extract): ${phase2Wall} ms  heap=${phase2Metrics.jsHeapUsedMb.toFixed(1)} MB nodes=${phase2Metrics.nodes}`);

        // ── Phase 3 — auto-extract done → GeoIP enrichment landed ──
        // Two acceptance paths:
        //   (a) base detect found IPs and enriched directly →
        //       `geoipColCount >= 1 && rowCount === ROWS` and
        //       `geoipBaseDetectKind === 'non-empty-array'` (cache
        //       not yet cleared, but the column is present).
        //   (b) base detect found nothing → auto-extract retry hook
        //       fired → `geoipColCount >= 1` AND the cache has been
        //       cleared back to `null` by the retry's terminal
        //       branch.
        // Either branch satisfies "geoip pass complete".
        // For fixtures where GeoIP can't enrich (no IPv4-shaped
        // column reachable), the spec falls through after 30 s with
        // `geoipColCount === 0` — the markdown summary surfaces
        // this as a warning rather than failing the run, since the
        // harness's job is to report perf, not assert on enrichment
        // (the existing `timeline-geoip.spec.ts` does that).
        const tPhase3Start = Date.now();
        const phase3Budget = Math.min(cfg.phaseTimeoutMs, 60_000);
        let phase3Wall = 0;
        let phase3Metrics: MetricBag = phase2Metrics;
        try {
          await pollPerfState(page,
            { kind: 'geoip-enriched', rows: cfg.rows },
            {
              timeoutMs: phase3Budget,
              pollMs: cfg.pollIntervalMs,
              stableMs: 0,
              label: 'phase3-geoip-done',
            });
          phase3Wall = Date.now() - tPhase3Start;
          phase3Metrics = await cdp.snapshot();
          // eslint-disable-next-line no-console
          console.log(`[perf]  phase3 (geoip):       ${phase3Wall} ms  heap=${phase3Metrics.jsHeapUsedMb.toFixed(1)} MB`);
        } catch (e) {
          // GeoIP didn't land within the budget. Record the elapsed
          // time anyway so the report shows the wall cost; the
          // markdown summary's "geoipColCount === 0" warning will
          // flag this for the analyst.
          phase3Wall = Date.now() - tPhase3Start;
          phase3Metrics = await cdp.snapshot();
          // eslint-disable-next-line no-console
          console.log(`[perf]  phase3 (geoip):       ${phase3Wall} ms  (no enrichment within ${phase3Budget} ms — see warning in summary)`);
        }

        // ── Phase 4 — fully idle (debounced 250 ms) ─────────────────
        const tPhase4Start = Date.now();
        await pollPerfState(page,
          { kind: 'fully-idle' },
          {
            timeoutMs: cfg.phaseTimeoutMs,
            pollMs: cfg.pollIntervalMs,
            stableMs: 250,
            label: 'phase4-fully-idle',
          });
        const phase4Wall = Date.now() - tPhase4Start;
        const phase4Metrics = await cdp.snapshot();
        // eslint-disable-next-line no-console
        console.log(`[perf]  phase4 (idle):        ${phase4Wall} ms  heap=${phase4Metrics.jsHeapUsedMb.toFixed(1)} MB`);

        const totalWall = Date.now() - tLoadStart;
        // eslint-disable-next-line no-console
        console.log(`[perf]  total:               ${totalWall} ms`);

        // Final state — used by the summary's "did GeoIP actually
        // enrich anything" sanity check.
        const finalState = await getPerfState(page);

        const mkSample = (wallMs: number, m: MetricBag): PhaseSample => {
          const delta: MetricBag = {
            jsHeapUsedMb: m.jsHeapUsedMb - baselineMetrics.jsHeapUsedMb,
            jsHeapTotalMb: m.jsHeapTotalMb - baselineMetrics.jsHeapTotalMb,
            documents: m.documents - baselineMetrics.documents,
            nodes: m.nodes - baselineMetrics.nodes,
            jsEventListeners: m.jsEventListeners - baselineMetrics.jsEventListeners,
            layoutCount: m.layoutCount - baselineMetrics.layoutCount,
            recalcStyleCount: m.recalcStyleCount - baselineMetrics.recalcStyleCount,
            layoutDurationMs: m.layoutDurationMs - baselineMetrics.layoutDurationMs,
            recalcStyleDurationMs: m.recalcStyleDurationMs - baselineMetrics.recalcStyleDurationMs,
            scriptDurationMs: m.scriptDurationMs - baselineMetrics.scriptDurationMs,
            taskDurationMs: m.taskDurationMs - baselineMetrics.taskDurationMs,
            v8HeapUsedMb: m.v8HeapUsedMb - baselineMetrics.v8HeapUsedMb,
          };
          return { wallMs, metrics: m, metricsDelta: delta };
        };

        const phases: Record<PhaseName, PhaseSample> = {
          'load-start-to-grid-paint':       mkSample(phase1Wall, phase1Metrics),
          'grid-paint-to-autoextract-done': mkSample(phase2Wall, phase2Metrics),
          'autoextract-to-geoip-done':      mkSample(phase3Wall, phase3Metrics),
          'geoip-to-fully-idle':            mkSample(phase4Wall, phase4Metrics),
          'load-start-to-fully-idle':       mkSample(totalWall, phase4Metrics),
        };

        // Sub-phase markers — sampled once at the end of the run.
        // The marks bag is monotonically grown over a load (each
        // `__loupePerfMark` call writes by name; we never clear it
        // mid-load) so reading it here captures every marker that
        // fired. `parseMs` is the worker's self-reported parse time
        // (`msg.parseMs` from the terminal `done` event), surfaced
        // separately because it isn't a host-side `performance.now()`
        // — it's the worker's own `performance.now()` delta.
        const marks = (finalState && finalState.marks)
          ? { ...finalState.marks }
          : {};
        const parseMs = (finalState && typeof finalState.parseMs === 'number')
          ? finalState.parseMs
          : null;
        // Worker-internal markers + counters (additive — older
        // worker/host bundles emit empty objects). We copy through
        // the spread so the run JSON is detached from the App slot
        // (otherwise a back-to-back run could share the reference).
        const workerMarks = (finalState && finalState.workerMarks)
          ? { ...finalState.workerMarks }
          : {};
        const workerCounters = (finalState && finalState.workerCounters)
          ? { ...finalState.workerCounters }
          : {};
        // eslint-disable-next-line no-console
        console.log(
          `[perf]  marks: ${Object.keys(marks).length}  parseMs=${parseMs ?? '—'}  workerMarks=${Object.keys(workerMarks).length}  fastPath=${workerCounters.fastPathRows ?? '—'}/slowPath=${workerCounters.slowPathRows ?? '—'}`);

        runs.push({
          index: runIdx,
          fixturePath,
          fixtureSizeMb,
          rows: cfg.rows,
          baselineMetrics,
          phases,
          finalState,
          marks,
          parseMs,
          workerMarks,
          workerCounters,
        });

        await cdp.close();
      } finally {
        await page.close();
        await context.close();
      }
    }

    // Aggregate. For each phase we summarise wall-time, the peak
    // `jsHeapUsedMb` recorded at THIS phase's snapshot (not across
    // the run — the report's per-run JSON has the trajectory if we
    // ever need it), and the peak `nodes` count.
    const phases: PhaseName[] = [
      'load-start-to-grid-paint',
      'grid-paint-to-autoextract-done',
      'autoextract-to-geoip-done',
      'geoip-to-fully-idle',
      'load-start-to-fully-idle',
    ];
    const summary = {} as PerfReport['summary'];
    for (const p of phases) {
      summary[p] = {
        wallMs: summarise(runs.map(r => r.phases[p].wallMs)),
        peakHeapMb: summarise(runs.map(r => r.phases[p].metrics.jsHeapUsedMb)),
        peakNodes: summarise(runs.map(r => r.phases[p].metrics.nodes)),
      };
    }

    const report: PerfReport = {
      schemaVersion: PERF_SCHEMA_VERSION,
      generatedAt: new Date().toISOString(),
      config: cfg,
      bundlePath,
      runs,
      summary,
    };
    const reportPath = writeReport(report);
    const md = markdownSummary(report);
    // eslint-disable-next-line no-console
    console.log(md);
    // eslint-disable-next-line no-console
    console.log(`\n[perf] full report: ${reportPath}\n`);

    // Sanity: every run produced a Timeline-routed load with our
    // expected row count. If not, the harness silently measured
    // something other than what we asked for and the numbers are
    // worthless — fail loudly so a regression in the file picker /
    // Timeline router doesn't masquerade as a perf number.
    for (const r of runs) {
      expect(r.finalState.timelineRowCount).toBe(cfg.rows);
    }
  });
});
