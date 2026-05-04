#!/usr/bin/env python3
"""perf_diff.py — compare two Loupe performance reports.

Reads two `dist/perf-report.json` files produced by `scripts/run_perf.py`
and prints a side-by-side comparison table showing absolute deltas and
percentage changes for every phase and sub-phase metric.

Usage
-----
    python scripts/perf_diff.py dist/perf-before.json dist/perf-after.json
    python scripts/perf_diff.py --warn-pct 10 before.json after.json
    python scripts/perf_diff.py --phases-only before.json after.json
    python scripts/perf_diff.py --json before.json after.json  # machine-readable diff

Exit codes
----------
    0  — no regressions detected (or --warn-pct not set)
    1  — at least one phase regressed beyond --warn-pct threshold (phase 0
         wall-time median is the primary gate; individual phases are
         advisory)
    2  — input error (missing file, wrong schema version, etc.)

Notes
-----
* "Regression" is defined as: new_median > old_median × (1 + warn_pct/100).
  Improvements (new_median < old_median) are never flagged as failures.
* Phase 0 (`load-start-to-fully-idle`) is the composite total. If that
  improves, individual phase regressions are only warnings.
* Sub-phases use the median across all runs, same as `markdownSummary`.
  Missing sub-phase markers emit `—` rather than failing.
* Schema version must match between files (schemaVersion key); a mismatch
  is a hard error because the field layout may differ.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from typing import Any


# ── Phase order (mirrors perf-helpers.ts PhaseName) ──────────────────────────
PHASES = [
    'load-start-to-grid-paint',
    'grid-paint-to-autoextract-done',
    'autoextract-to-geoip-done',
    'geoip-to-fully-idle',
    'load-start-to-fully-idle',
]

PHASE_LABELS = {
    'load-start-to-grid-paint':        'P1 load→grid-paint',
    'grid-paint-to-autoextract-done':  'P2 paint→autoextract',
    'autoextract-to-geoip-done':       'P3 autoextract→geoip',
    'geoip-to-fully-idle':             'P4 geoip→idle',
    'load-start-to-fully-idle':        'P0 total',
}

# Sub-phase marker pairs (mirrors PERF_SUBPHASES in perf-helpers.ts).
# Only host-side markers are diffed here; worker markers are included
# in the summary table if present.
SUBPHASES = [
    ('buffer→worker columns',       'fileBufferReady',       'workerColumnsEvent'),
    ('worker columns→first decode', 'workerColumnsEvent',    'workerFirstChunk'),
    ('worker first decode→done',    'workerFirstChunk',      'workerDone'),
    ('worker done→rowStore',        'workerDone',            'rowStoreFinalized'),
    ('rowStore→view ctor',          'rowStoreFinalized',     'timelineViewCtorStart'),
    ('view ctor',                   'timelineViewCtorStart', 'timelineViewCtorEnd'),
    ('view ctor→first paint',       'timelineViewCtorStart', 'firstGridPaint'),
    ('parseTimestamps (in ctor)',    'parseTimestampsStart',  'parseTimestampsEnd'),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _median(values: list[float]) -> float | None:
    xs = sorted(v for v in values if math.isfinite(v))
    if not xs:
        return None
    n = len(xs)
    if n % 2:
        return xs[(n - 1) // 2]
    return (xs[n // 2 - 1] + xs[n // 2]) / 2


def _delta_str(old: float | None, new: float | None) -> tuple[str, str, str, bool]:
    """Return (old_str, new_str, delta_str, is_regression_hint).
    A 'regression hint' is just new > old; the caller decides if it's
    above the threshold."""
    if old is None or new is None:
        return ('—', '—', '—', False)
    delta = new - old
    pct = (delta / old * 100) if old != 0 else float('nan')
    sign = '+' if delta >= 0 else ''
    pct_str = f'{sign}{pct:.1f}%' if math.isfinite(pct) else '—'
    return (
        f'{old:,.0f}',
        f'{new:,.0f}',
        f'{sign}{delta:,.0f} ({pct_str})',
        delta > 0,
    )


def _load(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except FileNotFoundError:
        print(f'[perf_diff] error: file not found: {path}', file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f'[perf_diff] error: invalid JSON in {path}: {e}', file=sys.stderr)
        sys.exit(2)


def _phase_medians(report: dict[str, Any]) -> dict[str, dict[str, float | None]]:
    """Extract median wallMs, peakHeapMb, peakNodes per phase from the summary block."""
    out: dict[str, dict[str, float | None]] = {}
    summary = report.get('summary', {})
    for phase in PHASES:
        if phase not in summary:
            out[phase] = {'wallMs': None, 'peakHeapMb': None, 'peakNodes': None}
            continue
        p = summary[phase]
        out[phase] = {
            'wallMs':     p.get('wallMs', {}).get('median'),
            'peakHeapMb': p.get('peakHeapMb', {}).get('median'),
            'peakNodes':  p.get('peakNodes', {}).get('median'),
        }
    return out


def _subphase_medians(report: dict[str, Any]) -> dict[str, float | None]:
    """Compute median subphase delta across all runs."""
    runs = report.get('runs', [])
    if not runs:
        return {}
    out: dict[str, float | None] = {}
    for name, from_key, to_key in SUBPHASES:
        samples: list[float] = []
        for run in runs:
            marks = run.get('marks', {}) or {}
            t0 = marks.get(from_key)
            t1 = marks.get(to_key)
            if t0 is not None and t1 is not None and math.isfinite(t0) and math.isfinite(t1):
                samples.append(t1 - t0)
        out[name] = _median(samples)
    return out


def _worker_counter_medians(report: dict[str, Any]) -> dict[str, float | None]:
    """Median worker counters across runs."""
    runs = report.get('runs', [])
    if not runs:
        return {}
    keys: set[str] = set()
    for run in runs:
        keys.update((run.get('workerCounters') or {}).keys())
    out: dict[str, float | None] = {}
    for k in sorted(keys):
        samples = [
            run['workerCounters'][k]
            for run in runs
            if run.get('workerCounters') and k in run['workerCounters']
        ]
        out[k] = _median([float(s) for s in samples if s is not None])
    return out


# ── Formatting ────────────────────────────────────────────────────────────────

def _col_widths(*cols: list[str]) -> list[int]:
    """Max width per column across all rows."""
    return [max(len(c) for c in col) for col in cols]


def _table(rows: list[tuple[str, ...]], header: tuple[str, ...]) -> str:
    cols = list(zip(header, *rows))
    widths = [max(len(cell) for cell in col) for col in cols]
    sep = '  '.join('-' * w for w in widths)
    def fmt_row(r: tuple[str, ...]) -> str:
        return '  '.join(cell.ljust(w) for cell, w in zip(r, widths))
    lines = [fmt_row(header), sep]
    for r in rows:
        lines.append(fmt_row(r))
    return '\n'.join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser(
        description='Compare two Loupe perf-report.json files.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split('Usage')[0].strip(),
    )
    p.add_argument('before', help='Baseline perf-report.json')
    p.add_argument('after', help='Comparison perf-report.json')
    p.add_argument('--warn-pct', type=float, default=None,
                   help='Exit 1 if any phase regresses by more than this %% '
                        '(default: warn-only, never exit 1 due to regression)')
    p.add_argument('--phases-only', action='store_true',
                   help='Omit sub-phase and worker-counter tables')
    p.add_argument('--json', action='store_true',
                   help='Emit machine-readable JSON diff instead of text tables')
    args = p.parse_args()

    before = _load(args.before)
    after  = _load(args.after)

    # Schema version check.
    bv = before.get('schemaVersion')
    av = after.get('schemaVersion')
    if bv != av:
        print(f'[perf_diff] warning: schema versions differ '
              f'(before={bv}, after={av}); comparison may be unreliable.',
              file=sys.stderr)

    bcfg = before.get('config', {})
    acfg = after.get('config', {})
    b_rows = bcfg.get('rows', '?')
    a_rows = acfg.get('rows', '?')
    b_runs = bcfg.get('runs', '?')
    a_runs = acfg.get('runs', '?')
    b_at   = before.get('generatedAt', '?')
    a_at   = after.get('generatedAt', '?')

    # ── Phase comparison ──────────────────────────────────────────────────────
    b_phases = _phase_medians(before)
    a_phases = _phase_medians(after)

    phase_rows: list[tuple[str, str, str, str, str, str]] = []
    regressions: list[str] = []

    for phase in PHASES:
        label = PHASE_LABELS[phase]
        b = b_phases[phase]
        a = a_phases[phase]

        bw, aw, dw, reg_wall = _delta_str(b['wallMs'], a['wallMs'])
        bh, ah, dh, _        = _delta_str(b['peakHeapMb'], a['peakHeapMb'])
        bn, an, dn, _        = _delta_str(b['peakNodes'],  a['peakNodes'])

        phase_rows.append((label, f'{bw} ms', f'{aw} ms', dw, f'{bh} MB', dh))

        if reg_wall and b['wallMs'] is not None and a['wallMs'] is not None:
            pct = (a['wallMs'] - b['wallMs']) / b['wallMs'] * 100
            if args.warn_pct is not None and pct > args.warn_pct:
                regressions.append(
                    f'{label}: {b["wallMs"]:,.0f} ms → {a["wallMs"]:,.0f} ms '
                    f'(+{pct:.1f}%)')

    # ── Sub-phase comparison ──────────────────────────────────────────────────
    b_sub = _subphase_medians(before)
    a_sub = _subphase_medians(after)

    sub_rows: list[tuple[str, str, str, str]] = []
    for name, _, _ in SUBPHASES:
        bv_  = b_sub.get(name)
        av_  = a_sub.get(name)
        bw, aw, dw, _ = _delta_str(bv_, av_)
        sub_rows.append((name, f'{bw} ms', f'{aw} ms', dw))

    # ── Worker counter comparison ─────────────────────────────────────────────
    b_wc = _worker_counter_medians(before)
    a_wc = _worker_counter_medians(after)
    all_wc_keys = sorted(set(list(b_wc) + list(a_wc)))
    wc_rows: list[tuple[str, str, str, str]] = []
    for k in all_wc_keys:
        bv_, av_ = b_wc.get(k), a_wc.get(k)
        bw, aw, dw, _ = _delta_str(bv_, av_)
        wc_rows.append((k, bw, aw, dw))

    # ── JSON output ───────────────────────────────────────────────────────────
    if args.json:
        diff = {
            'before': {'path': args.before, 'generatedAt': b_at, 'rows': b_rows, 'runs': b_runs},
            'after':  {'path': args.after,  'generatedAt': a_at, 'rows': a_rows, 'runs': a_runs},
            'phases': {},
            'subphases': {},
            'workerCounters': {},
        }
        for phase in PHASES:
            b = b_phases[phase]
            a = a_phases[phase]
            def _pct(old: float | None, new: float | None) -> float | None:
                if old is None or new is None or old == 0:
                    return None
                return (new - old) / old * 100
            diff['phases'][phase] = {
                'wallMs':     {'before': b['wallMs'],     'after': a['wallMs'],     'deltaPct': _pct(b['wallMs'], a['wallMs'])},
                'peakHeapMb': {'before': b['peakHeapMb'], 'after': a['peakHeapMb'], 'deltaPct': _pct(b['peakHeapMb'], a['peakHeapMb'])},
                'peakNodes':  {'before': b['peakNodes'],  'after': a['peakNodes'],  'deltaPct': _pct(b['peakNodes'], a['peakNodes'])},
            }
        for name, _, _ in SUBPHASES:
            bv_, av_ = b_sub.get(name), a_sub.get(name)
            diff['subphases'][name] = {
                'before': bv_, 'after': av_,
                'deltaPct': None if bv_ is None or av_ is None or bv_ == 0 else (av_ - bv_) / bv_ * 100,
            }
        for k in all_wc_keys:
            bv_, av_ = b_wc.get(k), a_wc.get(k)
            diff['workerCounters'][k] = {
                'before': bv_, 'after': av_,
                'deltaPct': None if bv_ is None or av_ is None or bv_ == 0 else (av_ - bv_) / bv_ * 100,
            }
        if regressions:
            diff['regressions'] = regressions
        print(json.dumps(diff, indent=2))
        return 1 if regressions else 0

    # ── Text output ───────────────────────────────────────────────────────────
    W = 80
    print()
    print('=' * W)
    print('  Loupe perf diff')
    print(f'  before: {args.before}')
    print(f'          generated {b_at} — {b_rows} rows × {b_runs} runs')
    print(f'  after:  {args.after}')
    print(f'          generated {a_at} — {a_rows} rows × {a_runs} runs')
    print('=' * W)
    print()

    print('Phase wall-time + heap (median across runs)')
    print()
    ph_header = ('phase', 'before (ms)', 'after (ms)', 'Δ wall', 'before (MB)', 'Δ heap')
    print(_table(phase_rows, ph_header))
    print()

    if not args.phases_only:
        print('Sub-phase breakdown (host-side markers, median across runs)')
        print()
        sp_header = ('sub-phase', 'before (ms)', 'after (ms)', 'delta')
        print(_table(sub_rows, sp_header))
        print()

        if wc_rows:
            print('Worker counters (median across runs)')
            print()
            wc_header = ('counter', 'before', 'after', 'delta')
            print(_table(wc_rows, wc_header))
            print()

    if regressions:
        print(f'REGRESSIONS (>{args.warn_pct:.0f}% threshold):')
        for r in regressions:
            print(f'  ✗ {r}')
        print()
        return 1

    if args.warn_pct is not None:
        print(f'No regressions detected (>{args.warn_pct:.0f}% threshold).')
        print()

    return 0


if __name__ == '__main__':
    sys.exit(main())
