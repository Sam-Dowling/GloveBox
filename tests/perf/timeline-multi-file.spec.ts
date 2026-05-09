// ════════════════════════════════════════════════════════════════════════════
// timeline-multi-file.spec.ts — Performance harness for the merged
// Timeline path. Loads a primary CSV through the regular file-picker
// flow (driving the same four phases as `timeline-100k.spec.ts`),
// then merges N smaller CSVs on top via `__loupeTest.loadBytes` with
// `skipCrossLoadReset: true` (which models a real user drop-to-add).
//
// What this measures, per merged source:
//
//   • merge-add-to-swap-paint   — `_timelineAddFile` start →
//                                  `_swapTimelineView` end. Captures
//                                  buffer read + parse + composite
//                                  schema rebuild + DOM swap + first
//                                  grid paint. Computed from the
//                                  production-code markers
//                                  `mergeAddStart` / `mergeSwapPaint`
//                                  (stamped via `__loupePerfMark`,
//                                  no-op in release builds).
//   • merge-swap-to-autoextract — swap-paint → auto-extract pump
//                                  drained for the post-merge view.
//   • merge-swap-to-fully-idle  — swap-paint → fully idle.
//
// Plus per-source heap snapshot for cumulative-cost trending.
//
// Opt-in: skipped unless BOTH `LOUPE_PERF=1` AND `LOUPE_PERF_MULTI=1`.
// The single-file spec (`timeline-100k.spec.ts`) only requires
// `LOUPE_PERF=1`, so the default `python scripts/run_perf.py` flow
// continues to run only the single-file harness; multi-file is
// surfaced via `python scripts/run_perf.py --mode multi` (or
// `--mode both`).
//
// Default scenario: 1× 100K + 4× 5K = 5 sources, 120K rows total.
// Tunable via env: LOUPE_PERF_MULTI_PRIMARY_ROWS,
// LOUPE_PERF_MULTI_SOURCES (count of additional sources beyond the
// primary), LOUPE_PERF_MULTI_ROWS_EACH (rows per additional source).
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
  MergeSample,
} from './perf-helpers';

const RUN = process.env.LOUPE_PERF === '1' && process.env.LOUPE_PERF_MULTI === '1';

// Multi-file knobs. Defaults give a realistic "1 large primary log +
// 4 enrichment sources" profile.
function multiCfg() {
  const num = (k: string, d: number): number => {
    const v = process.env[k];
    if (!v) return d;
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? n : d;
  };
  return {
    primaryRows: num('LOUPE_PERF_MULTI_PRIMARY_ROWS', 100_000),
    sources: num('LOUPE_PERF_MULTI_SOURCES', 4),
    rowsEach: num('LOUPE_PERF_MULTI_ROWS_EACH', 5_000),
    // Distinct seeds so each merged file has different content (more
    // realistic mapper / cull behaviour than 4 byte-identical CSVs).
    // The primary uses the standard seed (42); merged sources use 43+.
    seedBase: num('LOUPE_PERF_MULTI_SEED_BASE', 43),
  };
}

test.describe('Timeline performance — multi-source merge', () => {
  test.skip(!RUN,
    'set LOUPE_PERF=1 LOUPE_PERF_MULTI=1 to run the multi-file perf suite');

  // 30-min total budget. Per-merge phases are bounded by
  // cfg.phaseTimeoutMs from the shared config.
  test.setTimeout(30 * 60 * 1000);

  test('Timeline merge — primary load + N merges to fully idle', async ({ browser }) => {
    const cfg = getPerfConfig();
    const m = multiCfg();
    const primaryFixture = ensureFixture(m.primaryRows, cfg.seed);
    // Generate (or hit cached) fixtures for the merged sources.
    const mergeFixtures: Array<{ path: string; rows: number; label: string }> = [];
    for (let i = 0; i < m.sources; i++) {
      const seed = m.seedBase + i;
      const p = ensureFixture(m.rowsEach, seed);
      mergeFixtures.push({
        path: p,
        rows: m.rowsEach,
        // Distinct label per source — `_timelineAddFile` dedupes by
        // label, so two identical labels would error. The path
        // basename is unique per (rows, seed) so we get distinct
        // labels for free.
        label: path.basename(p),
      });
    }

    const bundlePath = path.join(REPO_ROOT, 'docs', 'index.test.html');
    if (!fs.existsSync(bundlePath)) {
      throw new Error(
        `perf: docs/index.test.html not found. Run \`python make.py test-build\` ` +
        `(or rebuild via run_perf.py which auto-rebuilds when stale).`);
    }

    const runs: RunReport[] = [];

    for (let runIdx = 1; runIdx <= cfg.runs; runIdx++) {
      // eslint-disable-next-line no-console
      console.log(`\n[perf-multi] === run ${runIdx} / ${cfg.runs} ===`);
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
        const baselineMetrics = await cdp.snapshot();
        // eslint-disable-next-line no-console
        console.log(`[perf-multi] baseline heap=${baselineMetrics.jsHeapUsedMb.toFixed(1)} MB`);

        // ── Primary load (same four-phase model as single-file spec) ─────
        const fileInput = page.locator('input[type="file"]').first();
        await expect(fileInput).toHaveCount(1);

        const tLoadStart = Date.now();
        await fileInput.setInputFiles(primaryFixture);
        const firstRow = page.locator('.grid-row').first();
        await expect(firstRow).toBeVisible({ timeout: cfg.phaseTimeoutMs });
        const phase1Wall = Date.now() - tLoadStart;
        const phase1Metrics = await cdp.snapshot();
        // eslint-disable-next-line no-console
        console.log(`[perf-multi]  primary phase1 (paint):   ${phase1Wall} ms`);

        const tPhase2Start = Date.now();
        await pollPerfState(page,
          { kind: 'autoextract-done' },
          { timeoutMs: cfg.phaseTimeoutMs, pollMs: cfg.pollIntervalMs, stableMs: 250,
            label: 'primary-phase2' });
        const phase2Wall = Date.now() - tPhase2Start;
        const phase2Metrics = await cdp.snapshot();
        // eslint-disable-next-line no-console
        console.log(`[perf-multi]  primary phase2 (autoex.): ${phase2Wall} ms`);

        const tPhase3Start = Date.now();
        const phase3Budget = Math.min(cfg.phaseTimeoutMs, 60_000);
        let phase3Wall = 0;
        let phase3Metrics: MetricBag = phase2Metrics;
        try {
          await pollPerfState(page,
            { kind: 'geoip-enriched', rows: m.primaryRows },
            { timeoutMs: phase3Budget, pollMs: cfg.pollIntervalMs, stableMs: 0,
              label: 'primary-phase3' });
          phase3Wall = Date.now() - tPhase3Start;
          phase3Metrics = await cdp.snapshot();
        } catch (_e) {
          phase3Wall = Date.now() - tPhase3Start;
          phase3Metrics = await cdp.snapshot();
          // eslint-disable-next-line no-console
          console.log(`[perf-multi]  primary phase3 (geoip):   no enrichment within budget`);
        }

        const tPhase4Start = Date.now();
        await pollPerfState(page,
          { kind: 'fully-idle' },
          { timeoutMs: cfg.phaseTimeoutMs, pollMs: cfg.pollIntervalMs, stableMs: 250,
            label: 'primary-phase4' });
        const phase4Wall = Date.now() - tPhase4Start;
        const phase4Metrics = await cdp.snapshot();
        const totalWallPrimary = Date.now() - tLoadStart;
        // eslint-disable-next-line no-console
        console.log(`[perf-multi]  primary total:            ${totalWallPrimary} ms`);

        // ── Per-merge passes ─────────────────────────────────────────────
        // Each merge:
        //   1. Read marker bag's `mergeAddStart` BEFORE — used as a
        //      sentinel to detect that the merge actually re-stamped
        //      the marker (overwrites are atomic w.r.t. the harness
        //      because polling happens after the merge resolves).
        //   2. Send the file via `__loupeTest.loadBytes(...,
        //      {skipCrossLoadReset: true})` so the load goes through
        //      the SAME `App._loadFile` entry point a real user drop
        //      would hit, which routes into `_timelineAddFile` for
        //      timeline-eligible kinds.
        //   3. Read `mergeAddStart` / `mergeSwapPaint` after — the
        //      delta is the merge's swap cost.
        //   4. Poll for autoextract-done + fully-idle, recording
        //      wall-times against the production marker.
        const mergeSamples: MergeSample[] = [];
        let cumulativeRows = m.primaryRows;
        for (let i = 0; i < mergeFixtures.length; i++) {
          const f = mergeFixtures[i];
          const mergeIdx = i + 2;   // human-friendly: source #2, #3, …
          const bytes = fs.readFileSync(f.path);
          // eslint-disable-next-line no-console
          console.log(`[perf-multi]  merge #${mergeIdx} (${f.label}, ${f.rows.toLocaleString()} rows)…`);

          // Drive the merge through the same entry point a real user
          // drop would hit. `skipCrossLoadReset: true` is critical —
          // without it, `_testApiResetCrossLoadState` destroys the
          // current Timeline before `_timelineTryHandle` can intercept,
          // which would defeat the merge gate entirely.
          //
          // Bytes are passed as base64 (NOT `Array.from(buf)`) so the
          // CDP payload doesn't balloon — `Array.from(Uint8Array)`
          // produces a JS Array of numbers which structured-clone
          // serialises as ~24 bytes per element, blowing past
          // Chromium's IPC budget on multi-MB fixtures and SIGKILLing
          // the worker. Same approach `timeline-merge.spec.ts` uses
          // for the same reason.
          await page.evaluate(async (payload) => {
            const w = window as unknown as {
              __loupeTest: {
                loadBytes(name: string, bytes: Uint8Array,
                  opts?: { skipCrossLoadReset?: boolean }): Promise<void>;
              };
            };
            const bin = atob(payload.b64);
            const u8 = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
            await w.__loupeTest.loadBytes(payload.name, u8,
              { skipCrossLoadReset: true });
          }, { name: f.label, b64: bytes.toString('base64') });

          // Read marker bag — `mergeAddStart` and `mergeSwapPaint`
          // were both overwritten by THIS merge.
          const stateAfterAdd = await getPerfState(page);
          const tAddStart = stateAfterAdd.marks?.mergeAddStart;
          const tSwapPaint = stateAfterAdd.marks?.mergeSwapPaint;
          const addToSwap = (typeof tAddStart === 'number' && typeof tSwapPaint === 'number')
            ? tSwapPaint - tAddStart
            : NaN;
          // From swap-paint forward — wall-time the post-merge
          // autoextract drain and full-idle wait. Use the harness's
          // `Date.now()` because the markers don't carry these
          // semantics (and we don't want to add more production
          // markers when they aren't needed). The clock skew between
          // page-realm `performance.now()` and host `Date.now()` is
          // immaterial here — we measure each delta in a single clock
          // domain.
          const tSwapWall = Date.now();

          await pollPerfState(page,
            { kind: 'autoextract-done' },
            { timeoutMs: cfg.phaseTimeoutMs, pollMs: cfg.pollIntervalMs, stableMs: 250,
              label: `merge${mergeIdx}-autoextract` });
          const swapToAutoextract = Date.now() - tSwapWall;

          await pollPerfState(page,
            { kind: 'fully-idle' },
            { timeoutMs: cfg.phaseTimeoutMs, pollMs: cfg.pollIntervalMs, stableMs: 250,
              label: `merge${mergeIdx}-idle` });
          const swapToFullyIdle = Date.now() - tSwapWall;

          const metricsAfter = await cdp.snapshot();
          cumulativeRows += f.rows;

          // Read auto-extract diagnostic counters NOW (post-fully-
          // idle). The pump's terminal branch stamped
          // `autoExtractApplyEnd` and the iteration / schedule /
          // max-gap counters along the way. Reading after fully-idle
          // ensures the terminal stamp has landed even on a slow
          // run — it's monotonically the last thing the pump does
          // before returning. Missing markers (e.g. file with no
          // eligible proposals → no apply pump) leave the fields
          // undefined.
          const stateAfterIdle = await getPerfState(page);
          const tApplyStart = stateAfterIdle.marks?.autoExtractApplyStart;
          const tApplyEnd = stateAfterIdle.marks?.autoExtractApplyEnd;
          const applyMs = (typeof tApplyStart === 'number'
              && typeof tApplyEnd === 'number')
            ? tApplyEnd - tApplyStart
            : undefined;
          const iterations = stateAfterIdle.marks?.autoExtractIterations;
          const scheduleCount = stateAfterIdle.marks?.autoExtractScheduleCount;
          const maxGapMs = stateAfterIdle.marks?.autoExtractMaxGapMs;

          // eslint-disable-next-line no-console
          console.log(
            `[perf-multi]    add→swap=${Number.isFinite(addToSwap) ? Math.round(addToSwap) : '—'} ms  ` +
            `swap→auto=${swapToAutoextract} ms  ` +
            `swap→idle=${swapToFullyIdle} ms  ` +
            `heap=${metricsAfter.jsHeapUsedMb.toFixed(1)} MB  ` +
            `applyMs=${applyMs !== undefined ? Math.round(applyMs) : '—'}  ` +
            `iters=${iterations ?? '—'}  ` +
            `sched=${scheduleCount ?? '—'}  ` +
            `maxGap=${maxGapMs !== undefined ? Math.round(maxGapMs) : '—'}`);

          const metricsAfterDelta: MetricBag = {
            jsHeapUsedMb:          metricsAfter.jsHeapUsedMb          - baselineMetrics.jsHeapUsedMb,
            jsHeapTotalMb:         metricsAfter.jsHeapTotalMb         - baselineMetrics.jsHeapTotalMb,
            documents:             metricsAfter.documents             - baselineMetrics.documents,
            nodes:                 metricsAfter.nodes                 - baselineMetrics.nodes,
            jsEventListeners:      metricsAfter.jsEventListeners      - baselineMetrics.jsEventListeners,
            layoutCount:           metricsAfter.layoutCount           - baselineMetrics.layoutCount,
            recalcStyleCount:      metricsAfter.recalcStyleCount      - baselineMetrics.recalcStyleCount,
            layoutDurationMs:      metricsAfter.layoutDurationMs      - baselineMetrics.layoutDurationMs,
            recalcStyleDurationMs: metricsAfter.recalcStyleDurationMs - baselineMetrics.recalcStyleDurationMs,
            scriptDurationMs:      metricsAfter.scriptDurationMs      - baselineMetrics.scriptDurationMs,
            taskDurationMs:        metricsAfter.taskDurationMs        - baselineMetrics.taskDurationMs,
            v8HeapUsedMb:          metricsAfter.v8HeapUsedMb          - baselineMetrics.v8HeapUsedMb,
          };
          mergeSamples.push({
            index: mergeIdx,
            sourceLabel: f.label,
            rows: f.rows,
            cumulativeRows,
            addToSwapPaintMs: addToSwap,
            swapToAutoextractMs: swapToAutoextract,
            swapToFullyIdleMs: swapToFullyIdle,
            metricsAfter,
            metricsAfterDelta,
            autoExtractApplyMs: applyMs,
            autoExtractIterations: typeof iterations === 'number' ? iterations : undefined,
            autoExtractScheduleCount: typeof scheduleCount === 'number' ? scheduleCount : undefined,
            autoExtractMaxGapMs: typeof maxGapMs === 'number' ? maxGapMs : undefined,
          });
        }

        // Final sanity — `_sources.length` matches what we merged.
        const finalState = await getPerfState(page);
        const sourceCount = await page.evaluate(() => {
          const w = window as unknown as {
            app: { _timelineCurrent: { _sources: unknown } | null };
          };
          const v = w.app._timelineCurrent;
          if (!v || !Array.isArray(v._sources)) return 0;
          return v._sources.length;
        });
        // eslint-disable-next-line no-console
        console.log(`[perf-multi]  final: ${sourceCount} sources, ${finalState.timelineRowCount.toLocaleString()} rows`);

        const mkSample = (wallMs: number, mb: MetricBag): PhaseSample => {
          const delta: MetricBag = {
            jsHeapUsedMb:          mb.jsHeapUsedMb          - baselineMetrics.jsHeapUsedMb,
            jsHeapTotalMb:         mb.jsHeapTotalMb         - baselineMetrics.jsHeapTotalMb,
            documents:             mb.documents             - baselineMetrics.documents,
            nodes:                 mb.nodes                 - baselineMetrics.nodes,
            jsEventListeners:      mb.jsEventListeners      - baselineMetrics.jsEventListeners,
            layoutCount:           mb.layoutCount           - baselineMetrics.layoutCount,
            recalcStyleCount:      mb.recalcStyleCount      - baselineMetrics.recalcStyleCount,
            layoutDurationMs:      mb.layoutDurationMs      - baselineMetrics.layoutDurationMs,
            recalcStyleDurationMs: mb.recalcStyleDurationMs - baselineMetrics.recalcStyleDurationMs,
            scriptDurationMs:      mb.scriptDurationMs      - baselineMetrics.scriptDurationMs,
            taskDurationMs:        mb.taskDurationMs        - baselineMetrics.taskDurationMs,
            v8HeapUsedMb:          mb.v8HeapUsedMb          - baselineMetrics.v8HeapUsedMb,
          };
          return { wallMs, metrics: mb, metricsDelta: delta };
        };

        const phases: Record<PhaseName, PhaseSample> = {
          'load-start-to-grid-paint':       mkSample(phase1Wall, phase1Metrics),
          'grid-paint-to-autoextract-done': mkSample(phase2Wall, phase2Metrics),
          'autoextract-to-geoip-done':      mkSample(phase3Wall, phase3Metrics),
          'geoip-to-fully-idle':            mkSample(phase4Wall, phase4Metrics),
          'load-start-to-fully-idle':       mkSample(totalWallPrimary, phase4Metrics),
        };

        const marks = (finalState && finalState.marks)
          ? { ...finalState.marks } : {};
        const parseMs = (finalState && typeof finalState.parseMs === 'number')
          ? finalState.parseMs : null;
        const workerMarks = (finalState && finalState.workerMarks)
          ? { ...finalState.workerMarks } : {};
        const workerCounters = (finalState && finalState.workerCounters)
          ? { ...finalState.workerCounters } : {};

        runs.push({
          index: runIdx,
          fixturePath: primaryFixture,
          fixtureSizeMb: fs.statSync(primaryFixture).size / (1024 * 1024),
          rows: m.primaryRows,
          baselineMetrics,
          phases,
          finalState,
          marks,
          parseMs,
          workerMarks,
          workerCounters,
          mergeSamples,
        });

        // Sanity assertion — every merge actually produced a marker
        // pair AND increased `_sources.length` by one. Fails the run
        // (not just emits a warning) so a regression that breaks the
        // merge plumbing surfaces immediately rather than masquerading
        // as a perf number.
        expect(sourceCount).toBe(1 + mergeFixtures.length);
        for (const s of mergeSamples) {
          // `addToSwapPaintMs` is NaN when the marker pair didn't
          // populate — signals a failure of `__loupePerfMark` plumbing.
          expect(Number.isFinite(s.addToSwapPaintMs)).toBe(true);
        }

        await cdp.close();
      } finally {
        await page.close();
        await context.close();
      }
    }

    // Aggregate primary-load phases (same shape as single-file spec).
    const phaseList: PhaseName[] = [
      'load-start-to-grid-paint',
      'grid-paint-to-autoextract-done',
      'autoextract-to-geoip-done',
      'geoip-to-fully-idle',
      'load-start-to-fully-idle',
    ];
    const summary = {} as PerfReport['summary'];
    for (const p of phaseList) {
      summary[p] = {
        wallMs: summarise(runs.map(r => r.phases[p].wallMs)),
        peakHeapMb: summarise(runs.map(r => r.phases[p].metrics.jsHeapUsedMb)),
        peakNodes: summarise(runs.map(r => r.phases[p].metrics.nodes)),
      };
    }

    const report: PerfReport = {
      schemaVersion: PERF_SCHEMA_VERSION,
      generatedAt: new Date().toISOString(),
      // Override the single-file `cfg.rows` (which the helper reads
      // from `LOUPE_PERF_ROWS`, defaulted to 100K) with the multi-file
      // spec's actual primary-row count so the Markdown header
      // ("rows: 100,000") doesn't lie when a smoke run is invoked
      // with a smaller `--multi-primary-rows`.
      config: { ...cfg, rows: m.primaryRows },
      bundlePath,
      runs,
      summary,
    };
    const reportPath = writeReport(report);
    const md = markdownSummary(report);
    // eslint-disable-next-line no-console
    console.log(md);
    // eslint-disable-next-line no-console
    console.log(`\n[perf-multi] full report: ${reportPath}\n`);
  });
});
