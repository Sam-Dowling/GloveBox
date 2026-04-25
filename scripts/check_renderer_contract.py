#!/usr/bin/env python3
"""Static contract check for files under ``src/renderers/``.

Turns the de-facto Renderer Contract documented in
``CONTRIBUTING.md → Renderer Contract — Reference`` into a runnable,
renderer-scoped check.

The four build gates in ``scripts/build.py`` (risk pre-stamp, bare-string
IOC ``type:`` values, ``_rawText`` LF-normalisation, ``new Worker(``
allow-list) already enforce most of these invariants *tree-wide*; this
script re-validates the three of them that apply to the renderer surface
(risk / IOC type / ``_rawText`` — the worker-spawn rule lives in
``src/worker-manager.js``, not ``src/renderers/``) narrowed to
``src/renderers/`` and adds the renderer-only structural checks (a class
definition exists, a ``render(`` method exists). The narrower scope buys
two things:

  1. A per-renderer report — when a contract violation lands in a renderer
     the offender is named in renderer terms ("PE renderer pre-stamps
     risk", not just "src/renderers/pe-renderer.js:1234").
  2. A renderer-only sanity wall for the structural checks that don't
     belong in the tree-wide build gates: every non-helper file under
     ``src/renderers/`` defines a ``class`` and a ``render(`` method.

The script is intentionally thin and grep-based — every regex it runs is
either copy-of-or-narrower-than the equivalent ``scripts/build.py`` gate.
It does **not** import any application code; it does **not** evaluate JS;
it does **not** require Node. Static text checks only.

CSP-forbidden APIs (``eval``, ``new Function``, ``fetch``, ``XMLHttpRequest``)
are intentionally **not** checked here — the runtime CSP
(``default-src 'none'``) already blocks every one of them, and renderers
that detect the *literal token* in user-supplied SVG / HTML / JS content
(see ``svg-renderer.js`` threat-pattern tables) would otherwise produce
false positives. The four contract rules below are sufficient.

Helpers under ``src/renderers/`` that are not per-format renderers are
allow-listed up front (``HELPER_FILES``); they are not required to expose a
class-and-``render`` pair, although several happen to.

Exit codes
----------
  0 — every renderer passes every contract rule
  1 — one or more renderers violate a rule (offender table printed to
       stderr); the build is not safe to ship.

Run directly (``python scripts/check_renderer_contract.py``) or via
``python make.py contract`` (added to ``DEFAULT_STEPS`` so a bare
``python make.py`` runs verify → build → contract → codemap).
"""
from __future__ import annotations

import os
import re
import sys

# scripts/check_renderer_contract.py → repo root is one level up.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RENDERERS_DIR = os.path.join(BASE, 'src', 'renderers')

# Helpers under src/renderers/ that are not per-format renderers — they're
# UI / parser libraries shared by the real renderers and don't have to
# expose a `render()` method against the format dispatch contract. The
# three content-rule contract checks (risk pre-stamp / bare IOC / `_rawText`
# LF) still apply to them, since they ship in the same concatenated bundle.
HELPER_FILES = {
    'archive-tree.js',     # collapsible inner-file tree shared by archive renderers
    'grid-viewer.js',      # virtualised grid used by csv / xlsx / json renderers
    'ole-cfb-parser.js',   # Compound File Binary parser used by office binaries
    'protobuf-reader.js',  # protobuf wire-format reader used by clickonce et al.
}

# ── Regexes (each mirrors a build-time gate from scripts/build.py) ────────

# Risk pre-stamp — `findings.risk = '<tier>'` writes outside
# `escalateRisk()`.
_RISK_PRE_STAMP_RE = re.compile(
    r"""\.risk\s*=\s*['"](low|medium|high|critical|info)['"]"""
)

# Bare-string IOC `type:` paired with `severity:` on the same line.
# The two-key fingerprint is unique to IOC entries; renderer-internal DTOs
# without a sibling `severity:` field do not match.
_BARE_IOC_TYPE_RE = re.compile(
    r"""\btype:\s*['"][A-Za-z][A-Za-z _]*['"][^}\n]*?\bseverity\s*:"""
)

# `*._rawText = <RHS>` writes whose RHS does not begin with
# `lfNormalize(`.
_RAW_TEXT_LHS_RE = re.compile(r"\._rawText\s*=\s*(.+?)\s*;?\s*$")

# Structural — at least one `class <Name>` + at least one `render(`
# method declaration somewhere in the file. Async / static / instance
# variants all match (the de-facto contract today is mixed and
# `_rendererDispatch` adapts both shapes).
_CLASS_RE = re.compile(r"""^\s*class\s+[A-Z][A-Za-z0-9_]*\s*\{?""", re.MULTILINE)
_RENDER_METHOD_RE = re.compile(
    r"""^\s*(?:async\s+|static\s+|static\s+async\s+)?render\s*\(""",
    re.MULTILINE,
)


def _is_comment_line(line: str) -> bool:
    """Skip pure comment lines so reference snippets in docstrings don't trip the gate."""
    s = line.lstrip()
    return s.startswith('//') or s.startswith('*')


def _scan_file(rel: str, text: str, *, is_helper: bool) -> list[tuple[str, str]]:
    """Return a list of (rule, location) violations for one file."""
    violations: list[tuple[str, str]] = []
    lines = text.splitlines()

    # Per-line content gates (narrowed copies of the tree-wide build
    # gates in scripts/build.py).
    for lineno, line in enumerate(lines, start=1):
        if _is_comment_line(line):
            continue

        if _RISK_PRE_STAMP_RE.search(line):
            violations.append((
                'risk-pre-stamp',
                f"{rel}:{lineno}: {line.strip()}",
            ))

        if _BARE_IOC_TYPE_RE.search(line):
            violations.append((
                'bare-ioc-type',
                f"{rel}:{lineno}: {line.strip()}",
            ))

        m = _RAW_TEXT_LHS_RE.search(line)
        if m:
            rhs = m.group(1).lstrip()
            if not rhs.startswith('lfNormalize('):
                violations.append((
                    'rawtext-not-lf-normalised',
                    f"{rel}:{lineno}: {line.strip()}",
                ))

    # File-level structural gate. Helpers are exempt — they don't
    # participate in the format dispatch contract.
    if not is_helper:
        if not _CLASS_RE.search(text):
            violations.append((
                'no-class-definition',
                f"{rel}: file under src/renderers/ defines no `class …`",
            ))
        if not _RENDER_METHOD_RE.search(text):
            violations.append((
                'no-render-method',
                f"{rel}: file under src/renderers/ defines no `render(` method",
            ))

    return violations


def main() -> int:
    if not os.path.isdir(RENDERERS_DIR):
        print(
            f"ERROR  renderer directory not found: {RENDERERS_DIR}",
            file=sys.stderr,
        )
        return 2

    files = sorted(
        f for f in os.listdir(RENDERERS_DIR)
        if f.endswith('.js')
    )

    if not files:
        print(
            f"ERROR  no .js files under {RENDERERS_DIR}",
            file=sys.stderr,
        )
        return 2

    rule_counts: dict[str, int] = {}
    all_violations: list[tuple[str, str]] = []
    checked = 0

    for fname in files:
        rel = os.path.join('src', 'renderers', fname)
        path = os.path.join(RENDERERS_DIR, fname)
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                text = fh.read()
        except OSError as e:
            print(f"ERROR  could not read {rel}: {e}", file=sys.stderr)
            return 2

        is_helper = fname in HELPER_FILES
        v = _scan_file(rel, text, is_helper=is_helper)
        all_violations.extend(v)
        for rule, _ in v:
            rule_counts[rule] = rule_counts.get(rule, 0) + 1
        checked += 1

    if not all_violations:
        print(
            f"OK    {checked} renderer file(s) checked, "
            f"{len(HELPER_FILES)} helper(s) allow-listed; "
            f"every contract rule satisfied."
        )
        return 0

    # Group offenders by rule for a readable report.
    by_rule: dict[str, list[str]] = {}
    for rule, loc in all_violations:
        by_rule.setdefault(rule, []).append(loc)

    print(
        f"FAIL  renderer contract violations: "
        f"{len(all_violations)} across {len(by_rule)} rule(s)",
        file=sys.stderr,
    )
    for rule in sorted(by_rule):
        print(f"\n  ── rule: {rule} ({len(by_rule[rule])}) ──", file=sys.stderr)
        for loc in by_rule[rule]:
            print(f"    {loc}", file=sys.stderr)

    print(
        "\nSee CONTRIBUTING.md → Renderer Contract — Reference for the "
        "rule meanings, fix-up snippets, and the build-time gates that "
        "back each rule.",
        file=sys.stderr,
    )
    return 1


if __name__ == '__main__':
    sys.exit(main())
