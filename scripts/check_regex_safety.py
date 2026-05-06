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
statement, nor (b) preceded within 3 lines by an approved opt-out marker.

Approved opt-out markers (any form grants an exemption; stricter forms
carry a semantic meaning the reviewer can verify at a glance):

  /* safeRegex: builtin */          Literal / hardcoded-source regex.
                                    Constructor args are string literals
                                    or come from a compile-time constant.
                                    ZERO runtime input reaches the source.

  /* safeRegex: escaped-input */    Regex source assembled from user-
                                    input string that was escaped with
                                    an `escapeRegex()` / `_escLiteral()`
                                    helper before being spliced in. Any
                                    dynamic metacharacters were made
                                    literal.

  /* safeRegex: generated-bounded */ Regex source generated from finite
                                    code-derived data (lookup tables,
                                    bounded lists). Reviewer has verified
                                    the generator cannot produce an
                                    unbounded quantifier or an alternation
                                    with nested star quantification.

  /* safeRegex: builtin */          BACK-COMPAT — identical to the
                                    categorized `builtin` form above.

The script additionally FAILS when a callsite is annotated with
`escaped-input` but no escaping call is found in the same 3-line window,
because the annotation then asserts a property the source can't show.
This turns the annotation from a bare opt-out into a checkable claim.

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

# ── Opt-out markers ──────────────────────────────────────────────────────────
# Each form grants an exemption; the categorized forms additionally assert
# a reviewable property. New categories MUST be added here before a call
# site can depend on them.
OPT_OUT_BUILTIN         = '/* safeRegex: builtin */'
OPT_OUT_ESCAPED         = '/* safeRegex: escaped-input */'
OPT_OUT_GENERATED       = '/* safeRegex: generated-bounded */'
ALL_OPT_OUTS = (OPT_OUT_BUILTIN, OPT_OUT_ESCAPED, OPT_OUT_GENERATED)

# For the `escaped-input` category, require a nearby escape call so the
# annotation isn't an unverifiable claim. The three names below are the
# canonical escaping helpers in the codebase — any one is sufficient.
# We ALSO accept the inline-replace shape that splices the historical
# regex-metacharacter class (`[.*+?^${}()|[]\\]`) — used by a few older
# call sites that haven't been refactored to a named helper.
ESCAPE_CALL_RE = re.compile(
    r'\b(?:escapeRegex|escapeRegExp|_escLiteral|_escapeRegExp|regexEscape)\s*\('
    r'|'
    r'\.replace\s*\(\s*/\[\.\*\+\?\^\$\{\}\(\)\|\[\\\]\\\\\]/'
)

# Regex-compile patterns we police. Bare `new RegExp(` covers every
# constructor invocation. Three-line lookback handles the common
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


def _check_file(path: str) -> list[tuple[int, str, str]]:
    """Return a list of (line_number, kind, source_line) violations.
    `kind` is one of:
      - 'unannotated'        — no opt-out marker within lookback window.
      - 'unverified-escape'  — `escaped-input` marker without a visible
                               escape call in the surrounding scope.
    """
    with open(path, 'r', encoding='utf-8') as f:
        raw = f.read()
    raw_lines = raw.splitlines()
    stripped_lines = _strip_comments(raw).splitlines()
    violations: list[tuple[int, str, str]] = []
    for i, line in enumerate(stripped_lines):
        if not NEW_REGEXP_RE.search(line):
            continue
        # Skip if the same logical statement routes through safeRegex.
        if SAFE_REGEX_RE.search(line):
            continue
        # Look back up to 3 lines for any opt-out marker (raw, not
        # stripped — we *want* to see annotation comments).
        marker_window = '\n'.join(raw_lines[max(0, i - 3):i + 1])
        has_marker = any(m in marker_window for m in ALL_OPT_OUTS)
        raw_line = raw_lines[i] if i < len(raw_lines) else ''
        if not has_marker:
            violations.append((i + 1, 'unannotated', raw_line))
            continue
        # Categorized check: `escaped-input` requires a visible escape
        # call in the enclosing local scope. We widen the window to the
        # preceding ~40 lines of stripped source — large enough to cover
        # the common shape where the escape call happens once at the top
        # of a loop / function and the regex is constructed inside a
        # nested block.
        if OPT_OUT_ESCAPED in marker_window:
            scope_window = '\n'.join(stripped_lines[max(0, i - 40):i + 1])
            if not ESCAPE_CALL_RE.search(scope_window):
                violations.append((i + 1, 'unverified-escape', raw_line))
    return violations


def main() -> int:
    files = _sorted_js_files()
    bad: list[tuple[str, int, str, str]] = []
    for path in files:
        for line_no, kind, source in _check_file(path):
            bad.append((path, line_no, kind, source))

    if not bad:
        print(f'OK  check_regex_safety: 0 unannotated callsites in '
              f'{len(files)} file(s)')
        return 0

    bad.sort()
    rel = lambda p: os.path.relpath(p, BASE)
    print('FAIL  check_regex_safety: `new RegExp(` lint violation(s)',
          file=sys.stderr)
    print('', file=sys.stderr)
    for path, line_no, kind, source in bad:
        tag = {
            'unannotated': 'no-opt-out',
            'unverified-escape': 'escaped-input annotation without escape call',
        }.get(kind, kind)
        print(f'  [{tag}] {rel(path)}:{line_no}: {source.strip()}',
              file=sys.stderr)
    print('', file=sys.stderr)
    print('Each callsite must either:', file=sys.stderr)
    print('  • route through `safeRegex(...)` (preferred for user-supplied input), or',
          file=sys.stderr)
    print('  • carry one of these markers within the 3 lines above:',
          file=sys.stderr)
    print('      /* safeRegex: builtin */           '
          'literal/hardcoded source, zero runtime input',
          file=sys.stderr)
    print('      /* safeRegex: escaped-input */     '
          'source assembled from user input escaped via escapeRegex()',
          file=sys.stderr)
    print('      /* safeRegex: generated-bounded */ '
          'source generated from finite code-derived data',
          file=sys.stderr)
    print('See CONTRIBUTING.md § Regex Safety.', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
