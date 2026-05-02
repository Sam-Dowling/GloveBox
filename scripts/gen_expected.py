#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════════════
# scripts/gen_expected.py — Re-derive `tests/e2e-fixtures/expected.jsonl`
# from the latest exploration baseline at `dist/fixture-report.json`.
#
# `expected.jsonl` is the snapshot matrix the `snapshot-matrix.spec.ts`
# walks fixture-by-fixture. Every record encodes range-based assertions
# (NOT exact pins) so a renderer that adds a new IOC row, ratchets risk
# from 'medium' to 'high', or grows its rule cluster doesn't break the
# matrix — but a regression that drops a row, demotes a rule, or
# zeroes findings *will* break it.
#
# Schema (one record per line, sorted by path):
#
#   path                      Repo-relative path to the fixture.
#   formatTag                 Exact `app.currentResult.formatTag` pin
#                             (or `null` for Timeline-routed loads).
#                             These are enum-stable.
#   timeline                  `true` if Timeline-routed; the matrix
#                             spec asserts via `dumpResult().timeline`.
#   riskFloor                 'low' | 'medium' | 'high' | 'critical' |
#                             'any' | null. Asserted via
#                             `isRiskAtLeast`. `'any'` skips the check
#                             (useful for clean-baseline fixtures
#                             where risk is currently 'low' but a
#                             benign change might bump it).
#   iocTypeMustInclude        Subset of IOC `type` strings (using
#                             `IOC.*` constant labels) that the
#                             findings projection MUST contain. We
#                             derive this from the empirical types
#                             list, dropping `'YARA Match'` and
#                             `'Info'` which are too noisy to anchor.
#   iocCountAtLeast           Lower bound on `iocCount`. Set to
#                             `floor(empirical * 0.5)` to absorb minor
#                             refactors that drop one or two strings.
#   yaraRulesMustInclude      Subset of high-confidence YARA rule
#                             names. Drawn from the empirical list,
#                             keeping at most three identity rules
#                             per fixture (the family-anchor rules
#                             like `BAT_Download_Execute`,
#                             `MSIX_AppInstaller_HTTP`, etc).
#
# To regenerate after a fixture-baseline shift:
#
#     LOUPE_EXPLORE=1 python scripts/run_tests_e2e.py tests/explore/dump-fixtures.spec.ts
#     python scripts/gen_expected.py
#     git diff tests/e2e-fixtures/expected.jsonl
#
# Eyeball the diff — every line that flipped should correspond to a
# real renderer change. If a line dropped IOCs / rules, that's a
# regression to investigate.
# ════════════════════════════════════════════════════════════════════════════

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORT = REPO_ROOT / 'dist' / 'fixture-report.json'
OUT = REPO_ROOT / 'tests' / 'e2e-fixtures' / 'expected.jsonl'

# ── IOC type strings deliberately NOT anchored. `YARA Match` is too
#    noisy (we anchor specific rules instead via `yaraRulesMustInclude`).
#    `Info` is an open-ended bucket the renderers freely add to.
DROP_IOC_TYPES = frozenset({'YARA Match', 'Info'})

# ── YARA rules deliberately NOT anchored. `Embedded_Compressed_Stream`
#    is so generic that it fires on most archives; pinning it would
#    produce a snapshot that breaks every time the suspicious-content
#    scanner is tuned. `Info_*` rules are likewise too volatile —
#    informational, by-design noisy.
DROP_YARA_RULES_PREFIXES = ('Info_',)
DROP_YARA_RULES_EXACT = frozenset({'Embedded_Compressed_Stream'})

# ── Per-fixture max number of high-confidence rules to anchor. The
#    family-anchor rules (e.g. `BAT_Download_Execute`,
#    `MSIX_AppInstaller_HTTP`) are stable enough to pin, but anchoring
#    a long tail invites drift. Keep 3.
MAX_RULES_PER_FIXTURE = 3


def risk_floor(empirical: str | None) -> str | None:
    """Map an empirical risk to its range-floor pin.

    `low` → `any`  (don't pin — fixture could escalate without being
                    a regression).
    `medium`/`high`/`critical` → same string (pin the floor — a
                    demotion below this band IS a regression).
    `null` (Timeline route) → `null`.
    """
    if empirical is None:
        return None
    if empirical == 'low':
        return 'any'
    return empirical


def filter_rules(rules: list[str]) -> list[str]:
    keep = []
    for r in rules:
        if r in DROP_YARA_RULES_EXACT:
            continue
        if any(r.startswith(p) for p in DROP_YARA_RULES_PREFIXES):
            continue
        keep.append(r)
    return sorted(keep)[:MAX_RULES_PER_FIXTURE]


def filter_types(types: list[str]) -> list[str]:
    return sorted(t for t in types if t not in DROP_IOC_TYPES)


def main() -> int:
    if not REPORT.exists():
        sys.stderr.write(
            f'error: {REPORT.relative_to(REPO_ROOT)} missing — run\n'
            '       LOUPE_EXPLORE=1 python scripts/run_tests_e2e.py '
            'tests/explore/dump-fixtures.spec.ts\n'
            '       first.\n')
        return 2
    rep = json.loads(REPORT.read_text())
    rows = rep.get('rows', [])

    # Categorise: a row's `formatTag` is null AND it landed via Timeline
    # iff `_timelineCurrent` was set. We can't read that here (the
    # report was generated before the synthetic dumpResult landed) —
    # so we infer Timeline from the file extension set hard-coded in
    # `src/app/timeline/timeline-router.js` (the `TIMELINE_EXTS` set).
    # Mirror `TIMELINE_EXTS` in `src/app/timeline/timeline-helpers.js`.
    # Out-of-sync sets silently flip `.log` / `.jsonl` / `.cef` / `.leef`
    # rows from `timeline:true` to `timeline:false` and break the
    # snapshot matrix routing assertion.
    TIMELINE_EXTS = frozenset({
        'csv', 'tsv', 'evtx', 'sqlite', 'db',
        'log', 'jsonl', 'ndjson', 'cef', 'leef',
        'pcap', 'pcapng', 'cap',
    })

    out_records: list[dict] = []
    for r in sorted(rows, key=lambda r: (r['category'], r['file'])):
        path = f"examples/{r['category']}/{r['file']}"
        ext = r['file'].rsplit('.', 1)[-1].lower() if '.' in r['file'] else ''
        # Timeline if Timeline-eligible extension AND empirical risk is
        # null (the regular-analyser fallback path produces a non-null
        # risk, so a `null` risk is the unique Timeline signature).
        is_timeline = ext in TIMELINE_EXTS and r.get('risk') is None
        rec = {
            'path': path,
            'formatTag': r.get('formatTag'),
            'timeline': is_timeline,
            'riskFloor': risk_floor(r.get('risk')),
            'iocTypeMustInclude': filter_types(r.get('iocTypes', [])),
            'iocCountAtLeast': max(0, r.get('iocCount', 0) // 2),
            'yaraRulesMustInclude': filter_rules(r.get('yaraRules', [])),
        }
        out_records.append(rec)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open('w', encoding='utf-8') as fh:
        for rec in out_records:
            fh.write(json.dumps(rec, sort_keys=True, separators=(',', ':')) + '\n')

    print(f'OK  Wrote {len(out_records)} records → {OUT.relative_to(REPO_ROOT)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
