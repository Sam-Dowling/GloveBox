#!/usr/bin/env python3
"""check_regex_safety.py — fail the build on unannotated `new RegExp(...)` callsites.

Background
----------
`src/constants.js` ships a `safeRegex` / `safeExec` / `safeTest` /
`safeMatchAll` harness that wraps user-supplied regex with a length cap, a
ReDoS-prone-shape heuristic, and a wall-clock budget. Every user-input
regex compile in the codebase must route through that harness; every
builtin / hardcoded-source compile must be explicitly annotated so it is
visible in review.

This script enumerates every `new RegExp(...)` callsite under `src/` and
fails if it is neither (a) wrapped by `safeRegex(...)` on the same logical
statement, nor (b) preceded within 2 lines by a
``/* safeRegex: builtin */`` comment.

Output is deterministic (sorted file list, sorted line numbers) so the
build remains reproducible per `scripts/build.py`'s determinism rules.

Mirrors the marker style already used for `loupe-allow:safe-storage` etc.
"""
from __future__ import annotations

import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(BASE, 'src')

# Marker that opts a callsite out of the lint. Any occurrence within the
# 2 lines preceding the `new RegExp(` line counts.
OPT_OUT = '/* safeRegex: builtin */'

# Regex-compile patterns we police. Bare `new RegExp(` covers every
# constructor invocation. Two-line lookback handles the common
# multi-line declaration where the annotation sits above the assignment.
NEW_REGEXP_RE = re.compile(r'\bnew\s+RegExp\s*\(')
SAFE_REGEX_RE = re.compile(r'\bsafeRegex\s*\(')


def _sorted_js_files() -> list[str]:
    """Return all .js files under src/ in sorted order. No os.walk —
    the iteration order would otherwise be filesystem-dependent and
    violate the reproducible-build determinism rule."""
    out: list[str] = []
    stack = [SRC]
    while stack:
        d = stack.pop()
        try:
            entries = sorted(os.listdir(d))
        except OSError:
            continue
        for name in entries:
            full = os.path.join(d, name)
            if os.path.isdir(full):
                stack.append(full)
            elif name.endswith('.js'):
                out.append(full)
    out.sort()
    return out


def _strip_comments(text: str) -> str:
    """Remove `//` line comments and `/* ... */` block comments so the
    `new RegExp(` literal scan doesn't trip on prose. Strings are left
    intact — none of our annotated callsites embed `new RegExp(` inside
    a quoted literal, so we don't pay the JS-tokenizer cost. Comment
    chars are replaced with spaces / newlines so line numbers stay
    aligned with the original file."""
    out: list[str] = []
    i, n = 0, len(text)
    in_block = False
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ''
        if in_block:
            if c == '*' and nxt == '/':
                in_block = False
                out.append('  ')
                i += 2
                continue
            out.append('\n' if c == '\n' else ' ')
            i += 1
            continue
        if c == '/' and nxt == '*':
            in_block = True
            out.append('  ')
            i += 2
            continue
        if c == '/' and nxt == '/':
            while i < n and text[i] != '\n':
                out.append(' ')
                i += 1
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def _check_file(path: str) -> list[tuple[int, str]]:
    """Return a list of (line_number, source_line) violations."""
    with open(path, 'r', encoding='utf-8') as f:
        raw = f.read()
    raw_lines = raw.splitlines()
    stripped_lines = _strip_comments(raw).splitlines()
    violations: list[tuple[int, str]] = []
    for i, line in enumerate(stripped_lines):
        if not NEW_REGEXP_RE.search(line):
            continue
        # Skip if the same logical statement routes through safeRegex.
        if SAFE_REGEX_RE.search(line):
            continue
        # Look back up to 3 lines for the OPT_OUT marker (raw, not
        # stripped — we *want* to see annotation comments).
        window = '\n'.join(raw_lines[max(0, i - 3):i + 1])
        if OPT_OUT in window:
            continue
        raw_line = raw_lines[i] if i < len(raw_lines) else ''
        violations.append((i + 1, raw_line))
    return violations


def main() -> int:
    files = _sorted_js_files()
    bad: list[tuple[str, int, str]] = []
    for path in files:
        for line_no, source in _check_file(path):
            bad.append((path, line_no, source))

    if not bad:
        print(f'OK  check_regex_safety: 0 unannotated callsites in '
              f'{len(files)} file(s)')
        return 0

    bad.sort()
    rel = lambda p: os.path.relpath(p, BASE)
    print('FAIL  check_regex_safety: unannotated `new RegExp(` callsite(s)',
          file=sys.stderr)
    print('', file=sys.stderr)
    for path, line_no, source in bad:
        print(f'  {rel(path)}:{line_no}: {source.strip()}', file=sys.stderr)
    print('', file=sys.stderr)
    print('Each callsite must either:', file=sys.stderr)
    print('  • route through `safeRegex(...)` (preferred for user-supplied input), or',
          file=sys.stderr)
    print('  • carry `/* safeRegex: builtin */` within the 3 lines above',
          file=sys.stderr)
    print('See CONTRIBUTING.md § Regex Safety.', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
