# Loupe Timeline performance harness

Opt-in performance tests for the Timeline route. Two suites:

- **Single-file** (`timeline-100k.spec.ts`) — drives an end-to-end load
  through the production file-picker path on a generated CSV fixture,
  splits the wall-time into four phases, samples Chromium CDP heap /
  DOM metrics at each phase boundary, and emits a JSON report plus a
  Markdown summary. The 95% case.

- **Multi-source merge** (`timeline-multi-file.spec.ts`) — exercises
  the merged-Timeline path. Loads a primary CSV (same four-phase
  model) then merges N additional CSVs on top via the same
  `__loupeTest.loadBytes` path a real user drop hits, recording the
  per-merge swap / auto-extract / fully-idle cost.

Neither suite is a CI gate. They exist to drive optimisation work and
to make perf regressions diff-able across commits. Numbers are
reported, not asserted.

## Running

```bash
# Single-file (default — backwards-compatible)
python scripts/run_perf.py                                 # 100 K rows × 3
python scripts/run_perf.py --rows 10000 --runs 1           # smoke
python scripts/run_perf.py --rows 1000000 --runs 2         # stress

# Multi-source merge (1× primary + N additional sources)
python scripts/run_perf.py --mode multi                    # 1×100K + 4×5K
python scripts/run_perf.py --mode multi --multi-sources 8 --multi-rows-each 2500
python scripts/run_perf.py --mode multi --runs 1 --multi-primary-rows 5000 --multi-sources 2 --multi-rows-each 1000  # smoke

# Both back-to-back (writes dist/perf-report.json + dist/perf-report-multi.json)
python scripts/run_perf.py --mode both --runs 5

# Custom report paths
python scripts/run_perf.py --report dist/perf-after.json
python scripts/run_perf.py --mode multi --multi-report dist/perf-multi-after.json
```

`scripts/run_perf.py` is a thin wrapper around
`scripts/run_tests_e2e.py` that sets `LOUPE_PERF=1` (the gate the
specs self-check) and forwards CLI flags as env vars
(`LOUPE_PERF_ROWS`, `LOUPE_PERF_RUNS`, `LOUPE_PERF_SEED`,
`LOUPE_PERF_REPORT`). `--mode multi` additionally sets
`LOUPE_PERF_MULTI=1` and forwards multi-file knobs
(`LOUPE_PERF_MULTI_PRIMARY_ROWS`, `LOUPE_PERF_MULTI_SOURCES`,
`LOUPE_PERF_MULTI_ROWS_EACH`, `LOUPE_PERF_MULTI_SEED_BASE`). The same
Playwright pin / Chromium / `docs/index.test.html` bundle as the
rest of the e2e suite is reused; the harness adds nothing to the
runtime cost of `python make.py test-e2e`.

`python make.py perf` is the equivalent invocation through the
make.py orchestrator (mirrors the opt-in `sbom` step).

## What gets measured

### Single-file (`timeline-100k.spec.ts`)

| Phase | What it covers |
|---|---|
| `load-start-to-grid-paint` | `setInputFiles` returns → first `.grid-row` becomes visible. Cold-load critical path: file → CSV worker → RowStore → Timeline mount → first window-render. |
| `grid-paint-to-autoextract-done` | First paint → `_autoExtractApplying === false` and no idle handle pending. Auto-extract apply pump's wall-cost on the post-paint plane. **Currently dominant** on 100 K JSON-shaped CSVs. |
| `autoextract-to-geoip-done` | Auto-extract finishes → at least one `kind === 'geoip'` extracted column with `rowCount === ROWS`. Bundled-provider lookup throughput. |
| `geoip-to-fully-idle` | GeoIP done → `pendingTasksSize === 0` and YARA / Timeline-load drained, debounced 250 ms. Post-enrichment quiescence. |
| `load-start-to-fully-idle` | Wall-clock total. |

Per-phase metrics captured via Chromium CDP `Performance.getMetrics`:

- `JSHeapUsedSize` / `JSHeapTotalSize` — JS heap (after last GC).
- `Documents` / `Nodes` — DOM-leak detection.
- `JSEventListeners` — listener-leak detection.
- `LayoutCount` / `RecalcStyleCount` — layout/style thrash.
- `ScriptDuration` / `TaskDuration` — main-thread CPU spent in JS / tasks.

Each metric is recorded as an absolute snapshot AND as a delta versus
the per-run baseline (captured after `App.init()` but before the file
loads), so a single phase can be attributed without doing arithmetic
by hand.

### Multi-source merge (`timeline-multi-file.spec.ts`)

The spec drives a primary CSV through the regular file-picker path
(producing the same four phases above) and then merges N additional
CSVs on top via `__loupeTest.loadBytes(..., {skipCrossLoadReset: true})`
— the same code path a real user drop-to-add hits, going through
`App._loadFile` → `_timelineTryHandle` → `_timelineAddFile`.

For every merged source (sources 2..N) the harness records:

| Sub-phase | What it covers |
|---|---|
| `add→swap-paint` | `_timelineAddFile` start → `_swapTimelineView` end. Captures buffer read, parse, composite-schema rebuild, view-ctor, DOM swap, first grid paint. Computed from production-code markers `mergeAddStart` / `mergeSwapPaint` (stamped via `__loupePerfMark`, no-op in release builds). |
| `swap→autoextract` | swap-paint → auto-extract pump drained for the post-merge view. |
| `swap→fully-idle` | swap-paint → fully idle (`pendingTasksSize === 0` etc., debounced 250 ms). |

Plus a per-merge heap snapshot (`jsHeapUsedMb`) so cumulative cost
is visible at a glance — a linear-growth curve is good, super-linear
is a red flag.

The first source's load-cost is measured the same way as the
single-file spec (four phases against `setInputFiles`) so a
"primary load on a multi-file run" can be diffed against a pure
single-file run with `scripts/perf_diff.py` directly.

Defaults: 1× 100K + 4× 5K (= 5 sources, 120K total rows). Tunable
via `--multi-primary-rows`, `--multi-sources`, `--multi-rows-each`.

## Reading the report

The Markdown summary printed to stdout is the human-readable view.
The JSON report at `dist/perf-report.json` (or
`dist/perf-report-multi.json` for `--mode multi`) is the source of
truth for diffing across commits — schema is
`tests/perf/perf-helpers.ts :: PerfReport` (versioned via
`schemaVersion`). The multi-file run adds an optional
`runs[*].mergeSamples: MergeSample[]` array; existing consumers (the
single-file diff path, the markdown renderer's existing tables)
ignore the field when absent, so the schema version stays at 1.

Quick before/after diff of the dominant phase wall-time:

```bash
jq '.summary["grid-paint-to-autoextract-done"].wallMs' dist/perf-before.json
jq '.summary["grid-paint-to-autoextract-done"].wallMs' dist/perf-after.json
```

Per-run trajectory of heap usage:

```bash
jq '.runs[] | { run: .index, phases: (.phases | to_entries | map({phase: .key, heapMb: .value.metrics.jsHeapUsedMb})) }' \
  dist/perf-report.json
```

Multi-file: per-merge swap cost across runs:

```bash
jq '.runs[].mergeSamples[] | { idx: .index, addToSwapMs: .addToSwapPaintMs, label: .sourceLabel }' \
  dist/perf-report-multi.json
```

`scripts/perf_diff.py` works against either report shape (it reads
the four-phase summary, which both single and multi-file runs
produce). For multi-only deltas, diff the `mergeSamples` arrays
manually with `jq`.

## Troubleshooting

- **`docs/index.test.html not found`** — `scripts/run_perf.py` calls
  through to `scripts/run_tests_e2e.py`, which auto-rebuilds the test
  bundle when stale. If the rebuild itself fails you'll see the
  build-script error first.
- **`geoipColCount === 0` warning in summary** — the harness
  measured wall-time but the GeoIP enrichment never ran for this
  fixture. The default-seed generator produces public IPv4 in
  `client_ip`-style columns so the natural-detect path should pick
  them up; if a future generator change moves the IP column or
  changes its name, the perf phase still completes (no assertion
  failure) but the warning surfaces.
- **High variance across runs** — the harness defaults to 3 runs;
  bump with `--runs 5` (or higher) for serious benchmarking. JS-heap
  numbers are bucketed by V8's last-GC state, so transient fluctuations
  of ±5 MB are normal.
- **OOM at 1 M rows** — the 1 M-row CSV is ≈1.6 GB on disk and the
  in-memory RowStore + extracted columns push Chromium's heap
  above 4 GB on JSON-shaped logs. This is exactly the case the
  harness exists to fix; reduce to `--rows 500000` while you work
  the optimisation.

## Why not in CI?

CI gates need to be stable and cheap. The 100 K perf run is ~90 s of
wall-time even on a warm worker, the fixture generation is another
~30 s, and the per-phase numbers vary by 10–20% across runners. Hard
thresholds would flake; soft thresholds would just become noise. A
follow-up PR can wire a soft regression check once a few hundred
runs across PR/main produce a stable baseline. Until then, run the
harness manually around any change you suspect of changing perf
characteristics, and attach the Markdown summary to the PR.

## Adding a new phase or metric

The phase list is the `PhaseName` union in `perf-helpers.ts`. Adding
a new phase requires:

1. A new `pollPerfState` predicate inside the spec.
2. An entry in `PhaseName`, the `phases: PhaseName[]` array in the
   spec, and the `phases` record in the per-run aggregator.
3. A row in the Markdown summary's three tables (auto-generated
   from the iteration; just add the new name to the array).

A new metric in `MetricBag` requires extending `METRIC_KEYS` (the
CDP-side filter) and the snapshot projection. Bump
`PERF_SCHEMA_VERSION` when changing the JSON shape so any consumer
script can detect the format change.

## Sub-phase markers

In addition to the four coarse phases, the harness collects fine-grained
sub-phase markers stamped from the production code. The markers split
phase 1 (`load-start-to-grid-paint`) into a flame-chart-shaped breakdown:

```
fileBufferReady
 └─ buffer→worker columns        (file.arrayBuffer + worker boot)
workerColumnsEvent
 └─ worker columns→first chunk
workerFirstChunk
 └─ worker first chunk→done      ← typically dominant phase 1 cost
workerDone
 └─ worker done→rowStore finalized
rowStoreFinalized
 └─ rowStore→view ctor start
timelineViewCtorStart
 └─ view ctor                    (parseTimestamps fires inside this)
timelineViewCtorEnd
 └─ view ctor→first grid paint
firstGridPaint
```

Plus `parseTimestampsStart` / `parseTimestampsEnd` which bracket the
typed-array fill inside `_parseAllTimestamps` (a subset of `view ctor`),
and the worker's self-reported `parseMs` (from the terminal `done`
event's `msg.parseMs` field) — captured separately because it's the
worker's own clock, not the host's `performance.now()`.

### Stamping a marker

```js
// In any production code path on the load critical path:
if (typeof window !== 'undefined' && window.__loupePerfMark) {
  window.__loupePerfMark('mySubPhaseStart');
}
```

The global `window.__loupePerfMark` is defined ONLY in `--test-api`
builds (the IIFE at the bottom of `src/app/app-test-api.js`). The
release bundle never includes the file, so production cost is one
undefined-property miss per call (~one cycle).

### Surfacing a new marker in the report

Three small edits in lockstep:

1. Stamp it from production code (above).
2. Append the name to `PERF_MARKER_ORDER` in `perf-helpers.ts`. This
   is the canonical list — every name must match a stamping call site.
3. Optionally add an entry to `PERF_SUBPHASES` so it appears as a row
   in the Markdown summary.

Existing markers are checked by `tests/unit/app-test-api-perf-state.test.js`
which pins (a) the test-API surface (`_testApiPerfMark`,
`_testApiClearPerfMarks`, `__loupePerfMark`,
`__loupePerfWorkerParseMs`) and (b) the reset cycle that clears the
marker bag between back-to-back loads.

### Why this is opt-in

Every marker is a no-op in release builds, but the source still
contains the call sites — they're a debug-print equivalent for the
load critical path. Keep the names short and informative; the harness
uses them verbatim as Markdown table row labels.
