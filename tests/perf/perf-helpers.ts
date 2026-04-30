// ════════════════════════════════════════════════════════════════════════════
// perf-helpers.ts — Shared utilities for the Timeline performance harness.
//
// Sibling of `tests/helpers/playwright-helpers.ts` but **deliberately
// separate** — perf code has different lifetime semantics (fresh page
// per run, opt-in only, CDP attached) and importing the e2e helpers
// would couple perf to the shared-page pattern that's hostile to
// repeatable measurement (a previous fixture's heap leaks into the
// next run's baseline).
//
// Public surface:
//
//   • `getPerfConfig()`         — read env-overridable rows / runs /
//                                  seed / report path.
//   • `ensureFixture(rows,seed)` — invoke `scripts/misc/generate_sample_csv.py`
//                                  and cache by (rows, seed) under `dist/`.
//   • `attachCdp(context, page)` — open a CDP session, enable
//                                  `Performance` domain, return a
//                                  `snapshot()` callable that returns
//                                  a normalised metric bag.
//   • `pollPerfState(page, predicate, opts)` — typed wrapper around
//                                  `waitForFunction` that calls
//                                  `__loupeTest.perfState()` inside
//                                  the page realm.
//   • `summarise(samples)`      — median / min / max / stdev across N
//                                  numeric samples (NaN-safe).
//   • `writeReport(payload)`    — write JSON to the configured path.
//   • `markdownSummary(payload)` — pretty-print a stdout table.
//
// All sync work runs on the host (Node) side; only `pollPerfState`
// crosses the CDP bridge, and that uses the existing test-API surface.
// ════════════════════════════════════════════════════════════════════════════

import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import type { BrowserContext, Page, CDPSession } from '@playwright/test';

export const REPO_ROOT = path.resolve(__dirname, '..', '..');
export const DIST_DIR = path.join(REPO_ROOT, 'dist');

// ── Config ─────────────────────────────────────────────────────────────────
// Every knob is env-overridable so `scripts/run_perf.py` can wire CLI
// flags through without tunnelling them via the Playwright command line
// (which would fight `playwright test`'s own argument parser).

export interface PerfConfig {
  rows: number;
  runs: number;
  seed: number;
  reportPath: string;
  // Per-phase timeout budget. The 100 K row CSV currently lands in
  // ~25 s on a warm laptop — 180 s is generous for slower hardware
  // and OOM-prone first runs without making genuine hangs invisible.
  phaseTimeoutMs: number;
  // Polling cadence for `pollPerfState`. 25 ms matches the
  // `_testApiWaitForIdle` rhythm and keeps the polling itself off the
  // critical path (each poll is one structured-clone of a small
  // object across the CDP bridge).
  pollIntervalMs: number;
}

export function getPerfConfig(): PerfConfig {
  const numEnv = (k: string, def: number): number => {
    const v = process.env[k];
    if (!v) return def;
    const n = Number(v);
    return Number.isFinite(n) && n > 0 ? n : def;
  };
  return {
    rows: numEnv('LOUPE_PERF_ROWS', 100_000),
    runs: numEnv('LOUPE_PERF_RUNS', 3),
    seed: numEnv('LOUPE_PERF_SEED', 42),
    reportPath: process.env.LOUPE_PERF_REPORT
      || path.join(DIST_DIR, 'perf-report.json'),
    phaseTimeoutMs: numEnv('LOUPE_PERF_PHASE_TIMEOUT_MS', 180_000),
    pollIntervalMs: numEnv('LOUPE_PERF_POLL_MS', 50),
  };
}

// ── Fixture generation ─────────────────────────────────────────────────────
// We deliberately mirror the runtime-generated fixture pattern from
// `timeline-large-csv.spec.ts` rather than depending on a pre-existing
// `dist/100k.csv`. The cache key embeds rows + seed so a perf sweep
// across multiple sizes ({1k, 10k, 100k}) doesn't repeatedly regenerate
// the same file. `mtime`-based staleness is intentional: if the
// generator script itself is newer than the cached CSV, regenerate
// (otherwise a column-schema bump in the generator would be invisible
// to the perf harness for the lifetime of the dist cache).

export function ensureFixture(rows: number, seed: number): string {
  const fname = `loupe-perf-${rows}-seed${seed}.csv`;
  const abs = path.join(DIST_DIR, fname);
  fs.mkdirSync(DIST_DIR, { recursive: true });
  const generator = path.join(REPO_ROOT, 'scripts', 'misc', 'generate_sample_csv.py');
  const cacheUsable = fs.existsSync(abs)
    && fs.statSync(abs).mtimeMs > fs.statSync(generator).mtimeMs;
  if (cacheUsable) return abs;

  const py = process.env.PYTHON || 'python3';
  const t0 = Date.now();
  // eslint-disable-next-line no-console
  console.log(`[perf] generating fixture: ${rows.toLocaleString()} rows, seed=${seed} → ${path.relative(REPO_ROOT, abs)}`);
  const r = spawnSync(
    py,
    [generator, '--rows', String(rows), '--seed', String(seed), '--output', abs],
    { stdio: ['ignore', 'inherit', 'inherit'] });
  if (r.status !== 0) {
    throw new Error(`generate_sample_csv.py exit=${r.status} (set $PYTHON if 'python3' is not on PATH)`);
  }
  if (!fs.existsSync(abs)) {
    throw new Error(`fixture generator did not produce ${abs}`);
  }
  const dt = Date.now() - t0;
  // eslint-disable-next-line no-console
  console.log(`[perf] fixture ready in ${(dt / 1000).toFixed(1)}s (${(fs.statSync(abs).size / (1024 * 1024)).toFixed(1)} MB)`);
  return abs;
}

// ── CDP metric capture ─────────────────────────────────────────────────────
// Chromium's `Performance.getMetrics` returns a bag of named scalars.
// We project a stable subset into our own typed shape so the report
// schema is decoupled from CDP version drift. Every value is a number
// in either bytes (heap), counts (DOM/layout), or seconds (timestamps).

export interface MetricBag {
  // From `Performance.getMetrics`
  jsHeapUsedMb: number;
  jsHeapTotalMb: number;
  documents: number;
  nodes: number;
  jsEventListeners: number;
  layoutCount: number;
  recalcStyleCount: number;
  layoutDurationMs: number;
  recalcStyleDurationMs: number;
  scriptDurationMs: number;
  taskDurationMs: number;
  // From `process.memoryUsage()` proxied through `Memory.getProcessHeapStats`
  // when available; otherwise zero (Chromium occasionally returns no
  // record for the field on Linux without the precise-memory flag,
  // which Loupe deliberately does not enable).
  v8HeapUsedMb: number;
}

const METRIC_KEYS = new Set([
  'JSHeapUsedSize', 'JSHeapTotalSize', 'Documents', 'Nodes',
  'JSEventListeners', 'LayoutCount', 'RecalcStyleCount',
  'LayoutDuration', 'RecalcStyleDuration', 'ScriptDuration', 'TaskDuration',
]);

export interface CdpHandle {
  client: CDPSession;
  snapshot(): Promise<MetricBag>;
  close(): Promise<void>;
}

export async function attachCdp(context: BrowserContext, page: Page): Promise<CdpHandle> {
  const client = await context.newCDPSession(page);
  await client.send('Performance.enable');
  let closed = false;

  const snapshot = async (): Promise<MetricBag> => {
    if (closed) throw new Error('attachCdp: snapshot called after close');
    const { metrics } = await client.send('Performance.getMetrics');
    const bag: Record<string, number> = {};
    for (const m of metrics) {
      if (METRIC_KEYS.has(m.name)) bag[m.name] = m.value;
    }
    const toMb = (b: number | undefined) => (typeof b === 'number' ? b / (1024 * 1024) : 0);
    return {
      jsHeapUsedMb: toMb(bag.JSHeapUsedSize),
      jsHeapTotalMb: toMb(bag.JSHeapTotalSize),
      documents: bag.Documents | 0,
      nodes: bag.Nodes | 0,
      jsEventListeners: bag.JSEventListeners | 0,
      layoutCount: bag.LayoutCount | 0,
      recalcStyleCount: bag.RecalcStyleCount | 0,
      layoutDurationMs: (bag.LayoutDuration || 0) * 1000,
      recalcStyleDurationMs: (bag.RecalcStyleDuration || 0) * 1000,
      scriptDurationMs: (bag.ScriptDuration || 0) * 1000,
      taskDurationMs: (bag.TaskDuration || 0) * 1000,
      // V8-side total isn't exposed via Performance domain; keep the
      // field for forwards compat (we may wire `Memory.getDOMCounters`
      // here when the report grows a DOM-leak phase).
      v8HeapUsedMb: 0,
    };
  };

  const close = async (): Promise<void> => {
    if (closed) return;
    closed = true;
    try { await client.detach(); } catch (_) { /* best effort */ }
  };

  return { client, snapshot, close };
}

// ── Page-side state polling ────────────────────────────────────────────────
// `predicate` is serialised across CDP and re-evaluated against
// `__loupeTest.perfState()` until it returns truthy or `timeoutMs`
// elapses. We pass the predicate as a function string and let
// `waitForFunction` re-invoke it — Playwright handles the
// argument-passing serialisation.

export interface PerfStateProjection {
  hasCurrentResult: boolean;
  timelineMounted: boolean;
  yaraScanInProgress: boolean;
  timelineLoadInFlight: boolean;
  autoExtractApplying: boolean;
  autoExtractIdleHandlePending: boolean;
  geoipBaseDetectKind: 'null' | 'empty-array' | 'non-empty-array' | 'absent';
  pendingTasksSize: number;
  timelineRowCount: number;
  baseColCount: number;
  extractedColCount: number;
  geoipColCount: number;
  extractedCols: Array<{ kind: string | null; name: string | null; rowCount: number }>;
  // Sub-phase markers stamped via `window.__loupePerfMark` from the
  // load critical path. Each value is a `performance.now()` timestamp
  // (ms, monotonic, page-realm clock). Empty object when no markers
  // have stamped (e.g. before the first file load). The harness reads
  // these to compute load → first-paint sub-phase deltas; missing
  // markers are tolerated by the markdown renderer (NaN in the table).
  marks: Record<string, number>;
  // Worker self-reported parse time (`msg.parseMs` from the terminal
  // `done` event). `null` when no Timeline-routed file has been
  // loaded yet, OR when the worker omitted the field for any reason.
  parseMs: number | null;
  // Worker-internal sub-phase markers. Keys come from
  // `WORKER_PERF_MARKER_ORDER` below; values are `performance.now()`
  // timestamps from the WORKER's own monotonic clock — never compare
  // these to host-side `marks` directly, only via deltas
  // (`workerSubphaseDelta`). Empty object when no Timeline-routed
  // load has completed yet, or when the worker bundle predates the
  // marker plumbing.
  workerMarks?: Record<string, number>;
  // Worker-internal counters (`fastPathRows`, `slowPathRows`,
  // `chunksPosted`, `packAndPostMs`). Diagnostic only; surfaced in
  // the Markdown summary so PRs can demonstrate the right bucket
  // moved.
  workerCounters?: Record<string, number>;
}

// ── Sub-phase marker names ─────────────────────────────────────────────────
// Mirrors the call sites in `src/app/timeline/timeline-router.js`,
// `src/app/timeline/timeline-view.js`, and
// `src/app/timeline/timeline-view-render-grid.js`. Adding a new marker
// in the page-side code MUST add the name here too — the harness
// surfaces every entry of this list in the per-run report (with `NaN`
// for missing markers, so a regression that drops a marker is visible
// in the Markdown summary).
export const PERF_MARKER_ORDER = [
  'fileBufferReady',
  'workerColumnsEvent',
  'workerFirstChunk',
  'workerDone',
  'rowStoreFinalized',
  'timelineViewCtorStart',
  'timelineViewCtorEnd',
  'parseTimestampsStart',
  'parseTimestampsEnd',
  'firstGridPaint',
] as const;

export type PerfMarker = (typeof PERF_MARKER_ORDER)[number];

// ── Sub-phase derivations ──────────────────────────────────────────────────
// Each sub-phase is `[from, to]`, both names from `PERF_MARKER_ORDER`.
// The order here is the order they execute in a normal cold load —
// the markdown renderer prints them in this order so the report reads
// top-to-bottom as a flame chart.
//
// `parseTimestamps*` brackets the per-row time-column decode pump
// inside `_parseAllTimestamps`. On a cold load it fires DURING the
// view ctor (between `timelineViewCtorStart` and `timelineViewCtorEnd`)
// — the row is reported separately so the contribution of timestamp
// parsing is observable distinctly from the rest of the ctor work
// (sus-bitmap rebuild, dataset wrapping, DOM mount setup).
// ── Worker-internal markers ────────────────────────────────────────────────
// Stamped from `src/workers/timeline.worker.js` and shipped on the
// terminal `done` event as `msg.workerMarks`. Values are
// `performance.now()` timestamps from the WORKER realm clock, NOT the
// host realm — never compute deltas across the two clocks. The harness
// reports per-marker pair deltas via `workerSubphaseDelta` and surfaces
// them as a separate "Worker sub-phase breakdown" section in the
// Markdown summary. Adding a marker on the worker side MUST add the
// name here too (a missing entry renders as `—` in the summary).
export const WORKER_PERF_MARKER_ORDER = [
  'dispatchStart',
  'csvParseStart',
  'csvFirstDecodeEnd',
  'csvFirstChunkPosted',
  'csvParseLoopEnd',
  'csvFlushEnd',
  'evtxParseStart',
  'sqliteParseStart',
  'dispatchEnd',
] as const;

export type WorkerPerfMarker = (typeof WORKER_PERF_MARKER_ORDER)[number];

// Per-CSV-parse worker sub-phases. Each `[from, to]` is a delta computed
// from the per-run `workerMarks` bag. Order matches the CSV cold-load
// flow so the Markdown summary reads top-to-bottom.
export const WORKER_PERF_SUBPHASES: Array<{
  name: string;
  from: WorkerPerfMarker;
  to: WorkerPerfMarker;
  note?: string;
}> = [
  { name: 'worker dispatch→csv start', from: 'dispatchStart', to: 'csvParseStart' },
  { name: 'worker csv start→first decode end', from: 'csvParseStart', to: 'csvFirstDecodeEnd',
    note: 'first TextDecoder.decode call returned' },
  { name: 'worker first decode→first chunk posted', from: 'csvFirstDecodeEnd', to: 'csvFirstChunkPosted' },
  { name: 'worker first chunk posted→parse loop end', from: 'csvFirstChunkPosted', to: 'csvParseLoopEnd',
    note: 'main parseChunk loop body — usually the dominant slice' },
  { name: 'worker parse loop end→flush end', from: 'csvParseLoopEnd', to: 'csvFlushEnd' },
  { name: 'worker flush end→dispatch end', from: 'csvFlushEnd', to: 'dispatchEnd' },
];

// Worker-counter keys surfaced in the Markdown summary. Adding a key
// on the worker side requires adding it here for the renderer to pick
// it up.
export const WORKER_PERF_COUNTERS = [
  'fastPathRows',
  'slowPathRows',
  'chunksPosted',
  'packAndPostMs',
] as const;

export type WorkerPerfCounter = (typeof WORKER_PERF_COUNTERS)[number];

/** Compute `to - from` from a worker marks bag. Same NaN semantics as
 *  `subphaseDelta`. */
export function workerSubphaseDelta(
  marks: Record<string, number> | undefined,
  from: WorkerPerfMarker,
  to: WorkerPerfMarker,
): number {
  if (!marks) return NaN;
  const a = marks[from];
  const b = marks[to];
  if (typeof a !== 'number' || typeof b !== 'number') return NaN;
  return b - a;
}

export const PERF_SUBPHASES: Array<{
  name: string;
  from: PerfMarker;
  to: PerfMarker;
  // Optional explanatory note shown alongside the row when present.
  note?: string;
}> = [
  { name: 'buffer→worker columns', from: 'fileBufferReady', to: 'workerColumnsEvent' },
  { name: 'worker columns→first chunk', from: 'workerColumnsEvent', to: 'workerFirstChunk' },
  { name: 'worker first chunk→done', from: 'workerFirstChunk', to: 'workerDone' },
  { name: 'worker done→rowStore finalized', from: 'workerDone', to: 'rowStoreFinalized' },
  { name: 'rowStore→view ctor start', from: 'rowStoreFinalized', to: 'timelineViewCtorStart' },
  { name: 'view ctor', from: 'timelineViewCtorStart', to: 'timelineViewCtorEnd' },
  { name: 'view ctor→first grid paint', from: 'timelineViewCtorEnd', to: 'firstGridPaint' },
  { name: 'parseTimestamps (subset of view ctor)', from: 'parseTimestampsStart', to: 'parseTimestampsEnd',
    note: 'inside the view ctor — reported separately to attribute time to per-row decode' },
];

/** Compute `to - from` from a marks bag. Returns `NaN` when either
 *  marker is missing (rather than `0`) so the renderer can format
 *  unsampled phases distinctly from genuinely instant ones. */
export function subphaseDelta(
  marks: Record<string, number>,
  from: PerfMarker,
  to: PerfMarker,
): number {
  const a = marks[from];
  const b = marks[to];
  if (typeof a !== 'number' || typeof b !== 'number') return NaN;
  return b - a;
}

export async function getPerfState(page: Page): Promise<PerfStateProjection> {
  return page.evaluate(() => {
    const w = window as unknown as {
      __loupeTest: { perfState(): unknown };
    };
    return w.__loupeTest.perfState() as unknown;
  }) as Promise<PerfStateProjection>;
}

// Predicate kinds enumerated rather than `new Function`-d. Loupe's
// CSP is `default-src 'none'; script-src 'unsafe-inline'` — explicitly
// no `unsafe-eval` — so any path that tries to materialise JS from a
// string at runtime (`new Function`, `eval`) inside the page realm is
// rejected. Playwright's `waitForFunction` injects its predicate via
// the CDP-instrumented bypass and is fine, but the predicate body
// itself MUST NOT call `new Function` / `eval`. We dispatch on a
// closed enum here so the predicate can read fields off `state`
// directly.
export type PerfPhasePredicate =
  | { kind: 'autoextract-done' }
  | { kind: 'geoip-enriched'; rows: number }
  | { kind: 'fully-idle' };

/** Poll `__loupeTest.perfState()` until `predicate(state)` is satisfied.
 *  `stableMs` debounces transient successes — useful for the
 *  "fully idle" gate where `pendingTasks` briefly empties between
 *  scheduled task batches. The predicate is a closed-enum dispatch
 *  rather than a `new Function`-evaluated string because Loupe's CSP
 *  forbids `unsafe-eval`. */
export async function pollPerfState(
  page: Page,
  predicate: PerfPhasePredicate,
  opts: { timeoutMs: number; pollMs: number; stableMs?: number; label: string },
): Promise<void> {
  const stableMs = opts.stableMs || 0;
  await page.waitForFunction(
    ({ pred, stableForMs }) => {
      const w = window as unknown as {
        __loupeTest: { perfState(): Record<string, unknown> };
        __loupePerfStable?: number;
      };
      const state = w.__loupeTest.perfState();
      let ok = false;
      switch (pred.kind) {
        case 'autoextract-done':
          ok = !!state.timelineMounted
            && !state.autoExtractApplying
            && !state.autoExtractIdleHandlePending;
          break;
        case 'geoip-enriched': {
          const cols = state.extractedCols as Array<{ kind?: string; rowCount?: number }>;
          ok = (state.geoipColCount as number) >= 1
            && Array.isArray(cols)
            && cols.some(c => c && c.kind === 'geoip' && c.rowCount === pred.rows);
          break;
        }
        case 'fully-idle':
          ok = !state.yaraScanInProgress
            && !state.timelineLoadInFlight
            && !state.autoExtractApplying
            && !state.autoExtractIdleHandlePending
            && (state.pendingTasksSize as number) === 0;
          break;
        default:
          ok = false;
      }
      if (!ok) {
        w.__loupePerfStable = 0;
        return false;
      }
      if (!stableForMs) return true;
      const now = performance.now();
      if (!w.__loupePerfStable) {
        w.__loupePerfStable = now;
        return false;
      }
      return now - w.__loupePerfStable >= stableForMs;
    },
    { pred: predicate, stableForMs: stableMs },
    { timeout: opts.timeoutMs, polling: opts.pollMs },
  ).catch((err) => {
    throw new Error(`pollPerfState[${opts.label}] timed out after ${opts.timeoutMs}ms: ${err.message}`);
  });
}

// ── Statistics ─────────────────────────────────────────────────────────────
// Median is preferred over mean because perf samples are right-skewed
// (one slow run drags the mean up far more than it should). Stdev is
// reported in addition to min/max so a high-variance phase shows up
// even when min/max look reasonable individually.

export interface Stat {
  median: number;
  min: number;
  max: number;
  stdev: number;
  n: number;
}

export function summarise(samples: number[]): Stat {
  const xs = samples.slice().sort((a, b) => a - b);
  const n = xs.length;
  if (!n) return { median: 0, min: 0, max: 0, stdev: 0, n: 0 };
  const median = n % 2
    ? xs[(n - 1) >> 1]
    : (xs[(n / 2) - 1] + xs[n / 2]) / 2;
  const min = xs[0];
  const max = xs[n - 1];
  const mean = xs.reduce((a, b) => a + b, 0) / n;
  const variance = xs.reduce((a, b) => a + (b - mean) * (b - mean), 0) / n;
  const stdev = Math.sqrt(variance);
  return { median, min, max, stdev, n };
}

// ── Report payload ─────────────────────────────────────────────────────────
// One JSON object per invocation. The `runs` array is the full per-run
// data; the `summary` block aggregates across runs. Schema is committed
// to here — a follow-up PR introducing a perf-diff tool will read this
// shape; bumping the major version of the schema means bumping
// `schemaVersion` and updating any consumers.

export const PERF_SCHEMA_VERSION = 1;

export type PhaseName =
  | 'load-start-to-grid-paint'
  | 'grid-paint-to-autoextract-done'
  | 'autoextract-to-geoip-done'
  | 'geoip-to-fully-idle'
  | 'load-start-to-fully-idle';

export interface PhaseSample {
  wallMs: number;
  metrics: MetricBag;
  // Delta from the run's baseline (pre-load) snapshot. Useful when
  // a single phase is suspected of being the heap culprit.
  metricsDelta: MetricBag;
}

export interface RunReport {
  index: number;
  fixturePath: string;
  fixtureSizeMb: number;
  rows: number;
  baselineMetrics: MetricBag;
  phases: Record<PhaseName, PhaseSample>;
  // Final extracted-col snapshot for sanity-checking the run did the
  // expected work (e.g. geoipColCount > 0 confirms enrichment ran).
  finalState: PerfStateProjection;
  // Sub-phase markers sampled at the end of the run (the marks bag
  // is monotonically-grown over a load, so reading it once at the
  // end captures every marker that fired). Missing keys are
  // omitted — the renderer fills with NaN.
  marks: Record<string, number>;
  // Worker `parseMs` self-report. Same semantics as the field on
  // `PerfStateProjection` — `null` means "not stamped".
  parseMs: number | null;
  // Worker-internal markers + counters from
  // `PerfStateProjection.workerMarks` / `.workerCounters`. Optional
  // additive fields — the schema stays at version 1 because consumers
  // tolerate missing keys (older bundles emit no worker markers).
  workerMarks?: Record<string, number>;
  workerCounters?: Record<string, number>;
}

export interface PerfReport {
  schemaVersion: number;
  generatedAt: string;
  config: PerfConfig;
  bundlePath: string;
  runs: RunReport[];
  summary: Record<PhaseName, {
    wallMs: Stat;
    peakHeapMb: Stat;
    peakNodes: Stat;
  }>;
}

export function writeReport(report: PerfReport, outPath?: string): string {
  const out = outPath || report.config.reportPath;
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(report, null, 2) + '\n');
  return out;
}

// ── Markdown summary ───────────────────────────────────────────────────────
// Designed for terminal viewing — fits in 80 columns, leaves the JSON
// file as the authoritative source for tooling. Numbers rounded to
// human-friendly precision (ms to nearest int, MB to one decimal).

export function markdownSummary(report: PerfReport): string {
  const fmtMs = (n: number) => `${Math.round(n).toLocaleString()} ms`;
  const fmtMb = (n: number) => `${n.toFixed(1)} MB`;
  const fmtCount = (n: number) => Math.round(n).toLocaleString();
  const lines: string[] = [];
  const cfg = report.config;
  lines.push('');
  lines.push(`# Loupe Timeline Performance Report`);
  lines.push('');
  lines.push(`- rows: **${cfg.rows.toLocaleString()}**`);
  lines.push(`- runs: **${cfg.runs}**  (seed=${cfg.seed})`);
  lines.push(`- bundle: \`${path.relative(REPO_ROOT, report.bundlePath)}\``);
  lines.push(`- generated: ${report.generatedAt}`);
  lines.push(`- report: \`${path.relative(REPO_ROOT, cfg.reportPath)}\``);
  lines.push('');

  const phases: PhaseName[] = [
    'load-start-to-grid-paint',
    'grid-paint-to-autoextract-done',
    'autoextract-to-geoip-done',
    'geoip-to-fully-idle',
    'load-start-to-fully-idle',
  ];

  lines.push('## Phase wall-time (ms)');
  lines.push('');
  lines.push('| Phase | median | min | max | stdev |');
  lines.push('|---|---:|---:|---:|---:|');
  for (const p of phases) {
    const s = report.summary[p].wallMs;
    lines.push(`| ${p} | ${fmtMs(s.median)} | ${fmtMs(s.min)} | ${fmtMs(s.max)} | ${fmtMs(s.stdev)} |`);
  }
  lines.push('');

  lines.push('## Peak JS heap (MB) per phase');
  lines.push('');
  lines.push('| Phase | median | min | max |');
  lines.push('|---|---:|---:|---:|');
  for (const p of phases) {
    const s = report.summary[p].peakHeapMb;
    lines.push(`| ${p} | ${fmtMb(s.median)} | ${fmtMb(s.min)} | ${fmtMb(s.max)} |`);
  }
  lines.push('');

  lines.push('## DOM nodes (max) per phase');
  lines.push('');
  lines.push('| Phase | median | min | max |');
  lines.push('|---|---:|---:|---:|');
  for (const p of phases) {
    const s = report.summary[p].peakNodes;
    lines.push(`| ${p} | ${fmtCount(s.median)} | ${fmtCount(s.min)} | ${fmtCount(s.max)} |`);
  }
  lines.push('');

  // Sub-phase breakdown of the load → first-paint critical path.
  // Aggregated as median across runs. `NaN` (rendered as `—`) means
  // the marker pair was never populated for that run — most often
  // because the build wasn't a `--test-api` build, or because a
  // cold-load aborted before the marker fired.
  if (report.runs.length) {
    const fmtOpt = (n: number) => Number.isFinite(n) ? `${Math.round(n).toLocaleString()} ms` : '—';
    lines.push('## Sub-phase breakdown (median across runs)');
    lines.push('');
    lines.push('| Sub-phase | median | min | max | n |');
    lines.push('|---|---:|---:|---:|---:|');
    for (const sp of PERF_SUBPHASES) {
      const samples: number[] = [];
      for (const r of report.runs) {
        const dt = subphaseDelta(r.marks || {}, sp.from, sp.to);
        if (Number.isFinite(dt)) samples.push(dt);
      }
      if (!samples.length) {
        lines.push(`| ${sp.name} | — | — | — | 0 |`);
        continue;
      }
      const s = summarise(samples);
      lines.push(`| ${sp.name} | ${fmtOpt(s.median)} | ${fmtOpt(s.min)} | ${fmtOpt(s.max)} | ${s.n} |`);
    }
    // Worker-side parse time, sampled separately from the marker
    // bag (see `PerfStateProjection.parseMs`).
    const parseSamples = report.runs
      .map(r => r.parseMs)
      .filter((n): n is number => typeof n === 'number');
    if (parseSamples.length) {
      const s = summarise(parseSamples);
      lines.push(`| worker parseMs (self-reported) | ${fmtOpt(s.median)} | ${fmtOpt(s.min)} | ${fmtOpt(s.max)} | ${s.n} |`);
    }
    lines.push('');
    // Footnotes for sub-phases with notes.
    const noted = PERF_SUBPHASES.filter(sp => sp.note);
    if (noted.length) {
      for (const sp of noted) {
        lines.push(`> *${sp.name}*: ${sp.note}`);
      }
      lines.push('');
    }

    // ── Worker sub-phase breakdown ─────────────────────────────────
    // Same shape as the host-side breakdown, but every delta is
    // computed from the worker-realm `workerMarks` bag (NOT host
    // marks). Skipped entirely when no run carries a worker bag —
    // older worker bundles silently omit the field, the renderer
    // handles that by emitting nothing rather than a wall of `—`s.
    const anyWorkerMarks = report.runs.some(
      r => r.workerMarks && Object.keys(r.workerMarks).length > 0);
    if (anyWorkerMarks) {
      lines.push('## Worker sub-phase breakdown (median across runs)');
      lines.push('');
      lines.push('| Sub-phase | median | min | max | n |');
      lines.push('|---|---:|---:|---:|---:|');
      for (const sp of WORKER_PERF_SUBPHASES) {
        const samples: number[] = [];
        for (const r of report.runs) {
          const dt = workerSubphaseDelta(r.workerMarks, sp.from, sp.to);
          if (Number.isFinite(dt)) samples.push(dt);
        }
        if (!samples.length) {
          lines.push(`| ${sp.name} | — | — | — | 0 |`);
          continue;
        }
        const s = summarise(samples);
        lines.push(`| ${sp.name} | ${fmtOpt(s.median)} | ${fmtOpt(s.min)} | ${fmtOpt(s.max)} | ${s.n} |`);
      }
      lines.push('');
      const wnoted = WORKER_PERF_SUBPHASES.filter(sp => sp.note);
      if (wnoted.length) {
        for (const sp of wnoted) {
          lines.push(`> *${sp.name}*: ${sp.note}`);
        }
        lines.push('');
      }
    }

    // ── Worker counters ────────────────────────────────────────────
    // Diagnostic counters from the worker (fastPathRows, slowPathRows,
    // chunksPosted, packAndPostMs). Reported as median-across-runs so
    // a PR can demonstrate that an optimisation moved the right
    // bucket — e.g. converting a quoted-row workload from slow-path to
    // fast-path should show `slowPathRows` falling and `fastPathRows`
    // rising in lock-step.
    const anyWorkerCounters = report.runs.some(
      r => r.workerCounters && Object.keys(r.workerCounters).length > 0);
    if (anyWorkerCounters) {
      const fmtCnt = (n: number) =>
        Number.isFinite(n) ? Math.round(n).toLocaleString() : '—';
      lines.push('## Worker counters (median across runs)');
      lines.push('');
      lines.push('| Counter | median | min | max | n |');
      lines.push('|---|---:|---:|---:|---:|');
      for (const k of WORKER_PERF_COUNTERS) {
        const samples: number[] = [];
        for (const r of report.runs) {
          const v = r.workerCounters && r.workerCounters[k];
          if (typeof v === 'number' && Number.isFinite(v)) samples.push(v);
        }
        if (!samples.length) {
          lines.push(`| ${k} | — | — | — | 0 |`);
          continue;
        }
        const s = summarise(samples);
        lines.push(`| ${k} | ${fmtCnt(s.median)} | ${fmtCnt(s.min)} | ${fmtCnt(s.max)} | ${s.n} |`);
      }
      lines.push('');
    }
  }

  // Per-run final-state spot-check. If `geoipColCount` is 0 across
  // every run the test "succeeded" by wall-time but the GeoIP
  // enrichment never actually ran (e.g. `_geoipBaseDetectResult`
  // settled before the harness even started polling). Flag that
  // here so it's visible at a glance.
  const allGeoZero = report.runs.every(r => r.finalState.geoipColCount === 0);
  if (allGeoZero) {
    lines.push('> **WARNING:** `geoipColCount === 0` in every run.');
    lines.push('> The harness measured wall-time but the GeoIP phase may not have done any work.');
    lines.push('> Verify the fixture has IPv4-shaped columns reachable to the natural-detect path.');
    lines.push('');
  }

  return lines.join('\n');
}
