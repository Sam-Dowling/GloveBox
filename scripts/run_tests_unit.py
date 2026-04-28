#!/usr/bin/env python3
"""run_tests_unit.py — execute Node's stdlib `node:test` over tests/unit/.

Loupe deliberately uses Node's built-in test runner (Node ≥ 20) instead of
Vitest / Jest so the project's "no runtime deps, no committed lockfile"
stance also covers the CI test path. The harness in
`tests/helpers/load-bundle.js` reads source files from `src/` directly into
a `vm.Context` (with the same shimming the worker bundles use) and exposes
the populated globals to the tests — so unit tests don't depend on a
prior `python scripts/build.py --test-api` invocation. They DO depend on
a Node installation; CI's `lint` job already provisions Node 24, so the
test-unit job inherits the same setup.

Returns whatever exit code `node --test` returns, so a single failing test
fails the orchestrator step exactly as ESLint does today.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.join(BASE, 'tests', 'unit')

if not os.path.isdir(TESTS_DIR):
    print(f"ERROR  tests/unit not found at {TESTS_DIR}", file=sys.stderr)
    sys.exit(2)

node = shutil.which('node')
if not node:
    print('ERROR  `node` not on PATH. Loupe unit tests require Node ≥ 20 '
          '(stdlib node:test). Install Node and re-run.', file=sys.stderr)
    sys.exit(2)

# Discover every `*.test.js` under tests/unit/ in deterministic (sorted)
# order. We pass an explicit file list rather than the directory because
# Node 22's `--test <dir>` is unreliable for nested layouts; explicit
# files are also what CI's argv-logging will print, so failures are
# easier to reproduce.
import glob  # noqa: E402  (kept local — only needed in this script)

test_files = sorted(glob.glob(os.path.join(TESTS_DIR, '**', '*.test.js'),
                              recursive=True))
if not test_files:
    print(f'ERROR  no *.test.js files found under {TESTS_DIR}', file=sys.stderr)
    sys.exit(2)

cmd = [node, '--test', '--test-reporter=spec'] + test_files
# Print a compact form of the command (the absolute file list can be
# very long) — enough to reproduce, not enough to drown the log.
print(f'$ node --test --test-reporter=spec {len(test_files)} file(s) '
      f'under tests/unit/', flush=True)
sys.exit(subprocess.call(cmd, cwd=BASE))
