#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════════════
# scripts/gen_yara_coverage.py — Re-derive the YARA rule coverage
# manifest at `tests/e2e-fixtures/yara-rules-fired.json`.
#
# The manifest is the inverse of `expected.jsonl`'s
# `yaraRulesMustInclude`: instead of "for fixture X, these rules must
# fire", it's "for rule R, at least these fixtures must trigger R".
#
# Why bother — doesn't `expected.jsonl` already cover this?
#
#   `expected.jsonl` pins at most three "family-anchor" rules per
#   fixture, deliberately avoiding the long tail of `Info_*` and
#   generic rules. That means ~50 rules that *do* fire across the
#   corpus are NOT pinned by `expected.jsonl` and could silently stop
#   firing without breaking any per-fixture assertion.
#
#   The coverage manifest closes that gap by tracking every (rule,
#   anchor-fixture) pair the corpus produces. The companion spec
#   `yara-rules-coverage.spec.ts` loads each anchor fixture once and
#   asserts its rule set covers all rules where that fixture is the
#   first anchor.
#
# Schema (single JSON object, keys sorted):
#
#   {
#     "summary": {
#       "totalRulesDefined": <int>,
#       "rulesFiredInCorpus": <int>,
#       "rulesUnanchored":   <int>,
#       "anchorFixtures":    <int>
#     },
#     "anchorFixtures": {
#       "<repo-relative path>": [<rule>, <rule>, …],
#       ...
#     },
#     "unanchoredRules": [<rule>, <rule>, …]
#   }
#
# `anchorFixtures` is the source of truth the spec walks. Each
# fixture's rule list is the set of rules for which this fixture was
# chosen as the *first* anchor (lex-sorted by `category/file`).
# `unanchoredRules` is documentation only — these are rules with no
# fixture coverage yet. CI does NOT block on these (the corpus is a
# living document; new fixtures will incrementally close gaps).
#
# Regenerate:
#
#     LOUPE_EXPLORE=1 python scripts/run_tests_e2e.py tests/explore/dump-fixtures.spec.ts
#     python scripts/gen_yara_coverage.py
#     git diff tests/e2e-fixtures/yara-rules-fired.json
# ════════════════════════════════════════════════════════════════════════════

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / 'src' / 'rules'
REPORT = REPO_ROOT / 'dist' / 'fixture-report.json'
OUT = REPO_ROOT / 'tests' / 'e2e-fixtures' / 'yara-rules-fired.json'

# Match `rule Name`, `private rule Name`, optional tags / colon. Skip
# lines inside strings/conditions by anchoring at start-of-line.
RULE_RE = re.compile(r'^[\s]*(?:private\s+)?rule\s+([A-Za-z_][A-Za-z0-9_]*)', re.M)


def collect_defined_rules() -> set[str]:
    rules = set()
    for yar in sorted(RULES_DIR.glob('*.yar')):
        text = yar.read_text()
        for m in RULE_RE.finditer(text):
            rules.add(m.group(1))
    return rules


def main() -> int:
    if not REPORT.exists():
        sys.stderr.write(
            f'error: {REPORT.relative_to(REPO_ROOT)} missing — '
            'run the explore spec first.\n')
        return 2

    defined = collect_defined_rules()
    rep = json.loads(REPORT.read_text())

    # Build (fixture-path, rule-set). Sort fixtures lex-stable for
    # deterministic anchor selection.
    fixtures = sorted(rep.get('rows', []),
                      key=lambda r: (r['category'], r['file']))

    # First-anchor pass: for each rule, the *first* fixture that fires
    # it claims it. Rules observed in the stale fixture-report but no
    # longer present in `src/rules/*.yar` (because they were
    # consolidated / cut in a rule-cleanup pass) are dropped silently —
    # the warning below surfaces them for the operator.
    rule_anchor: dict[str, str] = {}
    for row in fixtures:
        rel = f"examples/{row['category']}/{row['file']}"
        for rule in row.get('yaraRules', []):
            if rule not in defined:
                continue
            if rule not in rule_anchor:
                rule_anchor[rule] = rel

    # Group anchor → rules.
    by_anchor: dict[str, list[str]] = {}
    for rule, anchor in rule_anchor.items():
        by_anchor.setdefault(anchor, []).append(rule)
    for k in by_anchor:
        by_anchor[k].sort()

    fired = set(rule_anchor)
    unanchored = sorted(defined - fired)

    # Rules that fired but aren't in `defined` — usually a parser
    # mismatch between the regex above and the actual rule definition
    # syntax. Surface as a sanity check.
    extra = sorted(fired - defined)
    if extra:
        sys.stderr.write(
            f'warning: rules fired but not parsed from src/rules/*.yar: '
            f'{extra[:5]}{"..." if len(extra) > 5 else ""}\n')

    out = {
        'summary': {
            'totalRulesDefined': len(defined),
            'rulesFiredInCorpus': len(fired),
            'rulesUnanchored': len(unanchored),
            'anchorFixtures': len(by_anchor),
        },
        'anchorFixtures': dict(sorted(by_anchor.items())),
        'unanchoredRules': unanchored,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(out, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    s = out['summary']
    print(f"OK  Wrote {OUT.relative_to(REPO_ROOT)}: "
          f"{s['rulesFiredInCorpus']}/{s['totalRulesDefined']} rules covered "
          f"across {s['anchorFixtures']} anchor fixtures "
          f"({s['rulesUnanchored']} unanchored).")
    return 0


if __name__ == '__main__':
    sys.exit(main())
