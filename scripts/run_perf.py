#!/usr/bin/env python3
"""run_perf.py — execute the Loupe Timeline performance harness.

Thin wrapper around `scripts/run_tests_e2e.py` that:
  1. Sets `LOUPE_PERF=1` so the perf specs un-skip themselves.
  2. Forwards `--rows`, `--runs`, `--seed`, `--report` as
     `LOUPE_PERF_*` environment variables.
  3. Selects which spec(s) to run via `--mode`:
       * `single` (default) — `tests/perf/timeline-100k.spec.ts`
         only. Backwards-compatible with the original wrapper.
       * `multi`           — `tests/perf/timeline-multi-file.spec.ts`
         only. Sets `LOUPE_PERF_MULTI=1` so the multi-file spec
         un-skips. Forwards multi-file knobs
         (`--multi-sources` / `--multi-rows-each` /
         `--multi-primary-rows`) as `LOUPE_PERF_MULTI_*` env vars.
       * `both`            — sequentially run single then multi,
         each with its own `--report` (multi appends a `-multi`
         suffix unless `--multi-report` is supplied).

Usage
-----
    python scripts/run_perf.py                              # single, 100K × 3
    python scripts/run_perf.py --rows 10000 --runs 1        # single smoke run
    python scripts/run_perf.py --mode multi                 # 1×100K + 4×5K merge
    python scripts/run_perf.py --mode multi --multi-sources 8 --multi-rows-each 2500
    python scripts/run_perf.py --mode both --runs 5
    python scripts/run_perf.py --report dist/perf-after.json --runs 5

Notes
-----
* The fixture is generated on demand by
  `scripts/misc/generate_sample_csv.py` and cached at
  `dist/loupe-perf-<rows>-seed<seed>.csv`. First run takes ~30 s for
  100 K rows, then the cache is hit on subsequent runs. Multi-file
  runs reuse the same cache for every (rows, seed) pair, so
  back-to-back invocations only pay the generator cost once.
* Per-run JSON reports land at `dist/perf-report.json` (single) and
  `dist/perf-report-multi.json` (multi). Markdown summaries print to
  stdout regardless.
* `LOUPE_PERF=1` is the gate the single-file spec self-checks; the
  multi-file spec gates on `LOUPE_PERF=1 LOUPE_PERF_MULTI=1`.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN_TESTS_E2E = os.path.join(BASE, 'scripts', 'run_tests_e2e.py')


def _build_env(args: argparse.Namespace, *, multi: bool, report_path: str) -> dict[str, str]:
    """Construct the env dict for one Playwright invocation.
    `multi` toggles `LOUPE_PERF_MULTI=1` and forwards multi-file knobs.
    `report_path` is the destination JSON. Caller resolves both."""
    env = os.environ.copy()
    env['LOUPE_PERF'] = '1'
    env['LOUPE_PERF_ROWS'] = str(args.rows)
    env['LOUPE_PERF_RUNS'] = str(args.runs)
    env['LOUPE_PERF_SEED'] = str(args.seed)
    env['LOUPE_PERF_REPORT'] = os.path.abspath(report_path)
    env['LOUPE_PERF_PHASE_TIMEOUT_MS'] = str(args.phase_timeout_ms)
    env['LOUPE_PERF_POLL_MS'] = str(args.poll_ms)
    if multi:
        env['LOUPE_PERF_MULTI'] = '1'
        env['LOUPE_PERF_MULTI_PRIMARY_ROWS'] = str(args.multi_primary_rows)
        env['LOUPE_PERF_MULTI_SOURCES'] = str(args.multi_sources)
        env['LOUPE_PERF_MULTI_ROWS_EACH'] = str(args.multi_rows_each)
        env['LOUPE_PERF_MULTI_SEED_BASE'] = str(args.multi_seed_base)
    else:
        # Make sure `LOUPE_PERF_MULTI` doesn't leak from a prior shell
        # export and accidentally cause the multi-file spec to run
        # alongside the single-file one in `--mode single`.
        env.pop('LOUPE_PERF_MULTI', None)
    return env


def _invoke(spec_selector: str, env: dict[str, str], extra: list[str],
            *, ui: bool, debug: bool) -> int:
    cmd = [sys.executable, RUN_TESTS_E2E, spec_selector, '--workers=1']
    if ui:
        cmd.append('--ui')
    if debug:
        cmd.append('--debug')
    cmd.extend(extra)
    print(
        f'[perf] $ LOUPE_PERF=1'
        + (' LOUPE_PERF_MULTI=1' if env.get('LOUPE_PERF_MULTI') == '1' else '')
        + f' LOUPE_PERF_ROWS={env["LOUPE_PERF_ROWS"]}'
        + f' LOUPE_PERF_RUNS={env["LOUPE_PERF_RUNS"]} '
        + ' '.join(cmd[1:]),
        flush=True)
    return subprocess.call(cmd, cwd=BASE, env=env)


def main() -> int:
    p = argparse.ArgumentParser(
        description='Run the Loupe Timeline performance harness.',
    )
    p.add_argument('--mode', choices=['single', 'multi', 'both'],
                   default='single',
                   help='Which spec(s) to run (default: single)')
    # Single-file (also: primary-load) knobs.
    p.add_argument('--rows', type=int, default=100_000,
                   help='Row count for the single-file CSV (default: 100000)')
    p.add_argument('--runs', type=int, default=3,
                   help='Number of fresh-page runs to average over (default: 3)')
    p.add_argument('--seed', type=int, default=42,
                   help='Seed for the deterministic generator (default: 42)')
    p.add_argument('--report', type=str,
                   default=os.path.join(BASE, 'dist', 'perf-report.json'),
                   help='Path for the single-file JSON report '
                        '(default: dist/perf-report.json)')
    p.add_argument('--phase-timeout-ms', type=int, default=180_000,
                   help='Per-phase timeout budget in ms (default: 180000)')
    p.add_argument('--poll-ms', type=int, default=50,
                   help='Page-state poll interval in ms (default: 50)')
    # Multi-file knobs.
    p.add_argument('--multi-primary-rows', type=int, default=100_000,
                   help='Rows in the primary CSV for --mode multi '
                        '(default: 100000)')
    p.add_argument('--multi-sources', type=int, default=4,
                   help='Number of additional sources merged on top '
                        'of the primary (default: 4 → 5 total)')
    p.add_argument('--multi-rows-each', type=int, default=5_000,
                   help='Rows per additional source (default: 5000)')
    p.add_argument('--multi-seed-base', type=int, default=43,
                   help='First seed for the merged sources; subsequent '
                        'sources increment from this (default: 43)')
    p.add_argument('--multi-report', type=str, default=None,
                   help='Path for the multi-file JSON report (default: '
                        '<single-report>-multi.json or dist/perf-report-multi.json)')
    p.add_argument('--ui', action='store_true',
                   help='Pass --ui to playwright test (interactive runner)')
    p.add_argument('--debug', action='store_true',
                   help='Pass --debug to playwright test (single-test debug)')
    args, extra = p.parse_known_args()

    # Resolve the multi-file report path. If unset, derive from
    # `--report` so a user who passes `--report dist/perf-after.json
    # --mode both` gets `dist/perf-after-multi.json` for the multi
    # output, keeping the pair adjacent in the dist dir.
    if args.multi_report is None:
        root, ext = os.path.splitext(args.report)
        derived = f'{root}-multi{ext or ".json"}'
        # If --report wasn't customised, prefer the conventional name.
        default_single = os.path.join(BASE, 'dist', 'perf-report.json')
        if os.path.abspath(args.report) == os.path.abspath(default_single):
            args.multi_report = os.path.join(BASE, 'dist', 'perf-report-multi.json')
        else:
            args.multi_report = derived

    rc_single = 0
    rc_multi = 0
    if args.mode in ('single', 'both'):
        env = _build_env(args, multi=False, report_path=args.report)
        rc_single = _invoke('tests/perf/timeline-100k.spec.ts',
                            env, extra, ui=args.ui, debug=args.debug)
    if args.mode in ('multi', 'both'):
        # In `--mode multi` the harness runs only the multi-file spec.
        # In `--mode both` we run multi after single completes; note
        # `_invoke` is synchronous (`subprocess.call`), so this is a
        # strict serial chain — fresh-page-per-run isolation inside
        # each spec is preserved.
        env = _build_env(args, multi=True, report_path=args.multi_report)
        rc_multi = _invoke('tests/perf/timeline-multi-file.spec.ts',
                           env, extra, ui=args.ui, debug=args.debug)

    # Non-zero exit if either invocation failed; prefer the single-file
    # rc so a CI step that ran both can attribute failure correctly.
    return rc_single or rc_multi


if __name__ == '__main__':
    sys.exit(main())
