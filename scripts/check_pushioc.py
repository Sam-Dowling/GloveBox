#!/usr/bin/env python3
"""check_pushioc.py — fail the build on bare `findings.*.push({...})` call sites.

Background
----------
`CONTRIBUTING.md → Footguns Cheat-Sheet` rule #4 and `AGENTS.md → The hard
invariants` rule #4 require every IOC emission to route through
`pushIOC(findings, opts)` from `src/constants.js`. Bare pushes
(`findings.interestingStrings.push({...})` /
`findings.externalRefs.push({...})`) silently skip:

    • wire-shape validation (type + value required; canonical severity
      default; unresolved-sentinel sentinel filter)
    • URL sibling emission (auto-emitted `IOC.DOMAIN`, `IOC.IP`,
      `IOC.PATTERN` punycode + abuse-suffix rows via tldts)
    • metadata whitelist for YARA/EVTX extras

This module exposes `scan_bare_pushioc(rel, text)` which `scripts/build.py`
calls for every `src/*.js` file in `EARLY_JS_FILES + APP_JS_FILES`, and
`scripts/test_check_pushioc.py` exercises directly with synthetic input.
Extracted out of `build.py` specifically so the gate is unit-testable
without paying the full build concatenation cost on every test run.

Detection strategy — two overlapping scans:

    1. Single-line scan of raw source, skipping pure-comment lines so
       reference snippets in docstrings / migration-history comments
       don't trip the gate.

    2. Whole-file multi-line regex (DOTALL) that catches fluent calls
       split across lines — e.g.

           findings.externalRefs
             .push({ ... })

       The single-line regex would miss these entirely; the multi-line
       scan with `\\s*` between the bucket name and `.push(` picks
       them up.

Violations are deduplicated by (file, line) before being reported so each
offending site appears once regardless of which scan matched it.

The single exemption is `src/constants.js` because `pushIOC()` and
`emitUrlSiblings()` there push into `findings[bucket]` directly — that's
the atomic terminal step the chokepoint defines.
"""
from __future__ import annotations

import re

_BARE_PUSH_SINGLE_LINE_RE = re.compile(
    r'\.(?:interestingStrings|externalRefs)\.push\s*\('
)
_BARE_PUSH_MULTI_LINE_RE = re.compile(
    r'\.(?:interestingStrings|externalRefs)\s*\.\s*push\s*\(',
    re.DOTALL,
)

# The `pushIOC()` / `emitUrlSiblings()` chokepoint is the only place that
# may push into `findings[bucket]` directly.
ALLOWLIST: frozenset[str] = frozenset({'src/constants.js'})


def _strip_comments(text: str) -> str:
    """Replace JS comment contents with spaces (preserving newlines and
    length) so line numbers survive.

    Needed because the multi-line (DOTALL) scan would otherwise flag
    reference snippets inside `/* … */` block comments — e.g. a
    migration-history comment that says "old form:
    `f.interestingStrings.push(...)`" would match the multi-line regex
    even though the single-line scan correctly skips it. Stripping
    comment bodies to spaces preserves character offsets so
    `text.count('\\n', 0, m.start())` still gives the right line number
    when we report matches against the ORIGINAL text.

    This is a pragmatic tokenizer — it handles `//` line comments and
    `/* … */` block comments but NOT string literals or regex literals.
    A `.push(` inside a JS string is vanishingly rare in Loupe's source
    (we'd be constructing source code to eval, which CSP forbids); the
    few template-literal snippets in docstrings live inside block
    comments which we DO strip. If this assumption ever breaks, the
    gate becomes stricter than required — it flags a false positive,
    which is louder than silently missing a real one.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        # Block comment: replace body (except newlines) with spaces.
        if c == '/' and i + 1 < n and text[i + 1] == '*':
            out.append('  ')  # the '/*'
            i += 2
            while i < n:
                if text[i] == '*' and i + 1 < n and text[i + 1] == '/':
                    out.append('  ')  # the '*/'
                    i += 2
                    break
                out.append('\n' if text[i] == '\n' else ' ')
                i += 1
            continue
        # Line comment: replace from `//` to end-of-line (not the newline).
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':
                out.append(' ')
                i += 1
            continue
        out.append(c)
        i += 1
    return ''.join(out)


def scan_bare_pushioc(rel: str, text: str) -> list[str]:
    """Return a sorted list of `"rel:lineno: <snippet>"` violations.

    Pure function: no I/O, no globals beyond the two module-level
    compiled regexes. Callers pass the relative path (for reporting)
    and the file contents.
    """
    seen: set[tuple[str, int]] = set()
    violations: list[tuple[int, str]] = []

    # Comment-stripped view used for BOTH scans so docstring / migration-
    # history reference snippets don't produce false positives. Line
    # numbers and character offsets are preserved because block-comment
    # bodies are replaced with spaces + newlines of the same length.
    stripped = _strip_comments(text)

    # Single-line scan of the stripped source. (The previous pure-comment-
    # line prefix check still holds trivially because a stripped `//`
    # line contains only whitespace, which the regex won't match.)
    for lineno, line in enumerate(stripped.splitlines(), start=1):
        if _BARE_PUSH_SINGLE_LINE_RE.search(line):
            key = (rel, lineno)
            if key not in seen:
                seen.add(key)
                # Report the ORIGINAL line (not the stripped one) so
                # reviewers see the real source.
                real_line = text.splitlines()[lineno - 1] if lineno - 1 < len(text.splitlines()) else ''
                violations.append((lineno, real_line.strip()))

    # Multi-line scan — catches fluent calls where `.push(` is on a
    # subsequent line. Reports against the line where the bucket
    # reference starts.
    for m in _BARE_PUSH_MULTI_LINE_RE.finditer(stripped):
        start = m.start()
        lineno = stripped.count('\n', 0, start) + 1
        key = (rel, lineno)
        if key in seen:
            continue
        seen.add(key)
        # Snippet from the ORIGINAL text; collapse whitespace so the
        # report stays one-line-per-violation.
        snippet = text[start:min(start + 80, len(text))]
        snippet = ' '.join(snippet.split())
        violations.append((lineno, snippet))

    violations.sort()
    return [f"{rel}:{lineno}: {snippet}" for lineno, snippet in violations]
