#!/usr/bin/env python3
"""make.py — single-command orchestrator for Loupe's build toolchain.

Loupe ships with four standalone Python scripts under ``scripts/`` — each
intentionally usable on its own (and driven independently by CI):

  * scripts/verify_vendored.py    — SHA-256 pin-check every file in vendor/ against VENDORED.md
  * scripts/build.py              — concatenate src/ + vendor/ into docs/index.html
  * scripts/generate_codemap.py   — (re)generate CODEMAP.md from the current src/ tree
  * scripts/generate_sbom.py      — emit CycloneDX SBOM (dist/loupe.cdx.json) from VENDORED.md

This orchestrator chains them into a single `python make.py` invocation for
the common local workflow (verify → build → codemap). The SBOM step is opt-in
because it is only relevant at release time. The underlying scripts are
untouched — CI and one-off usage keep working exactly as before.

Usage
-----
    python make.py                 # run verify, build, codemap (default)
    python make.py all             # same as default
    python make.py verify          # just verify_vendored.py
    python make.py build           # just build.py
    python make.py codemap         # just generate_codemap.py
    python make.py sbom            # just generate_sbom.py  (opt-in)
    python make.py build codemap   # any subset, in the order given

Exit code is the first non-zero exit code encountered. Subsequent steps are
skipped on failure — there's no point generating a codemap for a tree that
won't build.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

# Fix Windows console encoding — the banner uses arrow (→) glyphs and we want
# child-script stdout (build.py, etc.) to pass through cleanly too.
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

BASE = os.path.dirname(os.path.abspath(__file__))

# step id → (human label, script path relative to BASE). Kept in canonical
# execution order. 'sbom' is deliberately omitted from DEFAULT_STEPS — it is
# only relevant at release time and the artefact is regenerated in CI.
STEPS: dict[str, tuple[str, str]] = {
    'verify':  ('Verify vendored SHA-256 pins', 'scripts/verify_vendored.py'),
    'build':   ('Build docs/index.html',        'scripts/build.py'),
    'codemap': ('Regenerate CODEMAP.md',        'scripts/generate_codemap.py'),
    'sbom':    ('Generate CycloneDX SBOM',      'scripts/generate_sbom.py'),
}

DEFAULT_STEPS = ['verify', 'build', 'codemap']
ALL_STEPS = list(STEPS.keys())


def _run(step: str) -> int:
    label, script = STEPS[step]
    path = os.path.join(BASE, script)
    if not os.path.isfile(path):
        print(f"ERROR  {script} not found next to make.py", file=sys.stderr)
        return 2

    banner = f" {label} ".center(60, '─')
    print(f"\n{banner}")
    print(f"$ python {script}", flush=True)
    t0 = time.perf_counter()
    # Run with the same interpreter so a venv / pyenv is honoured. cwd=BASE
    # so the child scripts' relative paths (src/, vendor/, docs/, …) resolve
    # exactly as they do when invoked directly.
    rc = subprocess.call([sys.executable, path], cwd=BASE)
    dt = time.perf_counter() - t0
    status = 'OK' if rc == 0 else f'FAIL ({rc})'
    print(f"[{status}] {step} — {dt:.2f}s")
    return rc


def _parse_args(argv: list[str]) -> list[str]:
    if not argv or argv == ['all']:
        return list(DEFAULT_STEPS)
    # Allow any subset, preserving order, deduplicated.
    seen: set[str] = set()
    out: list[str] = []
    for a in argv:
        if a in ('-h', '--help', 'help'):
            print(__doc__)
            sys.exit(0)
        if a == 'all':
            # 'all' inside a list just means "the rest of the defaults" —
            # expand and stop. To run every step including sbom, list them
            # explicitly (e.g. `python make.py verify build codemap sbom`).
            for s in DEFAULT_STEPS:
                if s not in seen:
                    seen.add(s)
                    out.append(s)
            continue
        if a not in STEPS:
            print(f"ERROR  unknown step '{a}'. Valid: {', '.join(ALL_STEPS)}, all",
                  file=sys.stderr)
            sys.exit(2)
        if a not in seen:
            seen.add(a)
            out.append(a)
    return out


def main() -> int:
    steps = _parse_args(sys.argv[1:])
    print(f"Loupe make — running: {', '.join(steps)}")
    t0 = time.perf_counter()
    for step in steps:
        rc = _run(step)
        if rc != 0:
            # Bail on first failure. A broken verify or build means the
            # subsequent steps would be operating on a known-bad tree.
            print(f"\nFAIL  '{step}' exited with status {rc}; "
                  f"skipping remaining steps.", file=sys.stderr)
            return rc
    dt = time.perf_counter() - t0
    print(f"\nOK    all {len(steps)} step(s) completed in {dt:.2f}s")
    return 0


if __name__ == '__main__':
    sys.exit(main())
