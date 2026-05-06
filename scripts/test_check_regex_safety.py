#!/usr/bin/env python3
"""Tests for the categorized regex-safety gate.

Exercises both the positive and negative paths of the three accepted
opt-out categories:

    /* safeRegex: builtin */
    /* safeRegex: escaped-input */
    /* safeRegex: generated-bounded */

Plus the stricter `escaped-input` cross-check that requires a visible
escape call in the surrounding scope.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / 'scripts/check_regex_safety.py'


def run_against(js_source: str) -> tuple[int, str, str]:
    """Write `js_source` as a single .js file under a synthetic src/
    tree and run the gate against it. Returns (returncode, stdout, stderr).
    """
    with tempfile.TemporaryDirectory() as tmp:
        src_dir = Path(tmp) / 'src'
        src_dir.mkdir()
        (src_dir / 'sample.js').write_text(js_source)
        # The gate hardcodes `SRC = <repo>/src`, so we need to run it
        # with cwd set such that `os.path.dirname(dirname(abspath(__file__)))`
        # resolves to our tmp dir. The simplest trick: copy the gate
        # alongside a synthetic scripts/ directory that points at src/.
        scripts_dir = Path(tmp) / 'scripts'
        scripts_dir.mkdir()
        shim = scripts_dir / 'check_regex_safety.py'
        shim.write_text(SCRIPT.read_text())
        proc = subprocess.run(
            [sys.executable, str(shim)],
            capture_output=True, text=True,
        )
        return proc.returncode, proc.stdout, proc.stderr


def test_bare_new_regexp_fails():
    rc, out, err = run_against("const r = new RegExp('abc');\n")
    assert rc == 1, f'expected fail, got rc={rc}'
    assert 'no-opt-out' in err, err


def test_safeRegex_wrap_passes():
    rc, _, _ = run_against("const r = safeRegex('abc');\n")
    assert rc == 0


def test_builtin_annotation_passes():
    rc, out, err = run_against(textwrap.dedent('''\
        /* safeRegex: builtin */
        const r = new RegExp('abc');
    '''))
    assert rc == 0, err


def test_escaped_input_annotation_passes_with_named_helper():
    rc, out, err = run_against(textwrap.dedent('''\
        const escaped = escapeRegex(needle);
        /* safeRegex: escaped-input */
        const r = new RegExp(escaped, 'g');
    '''))
    assert rc == 0, err


def test_escaped_input_annotation_passes_with_underscore_helper():
    rc, out, err = run_against(textwrap.dedent('''\
        const safe = _escLiteral(user);
        /* safeRegex: escaped-input */
        const r = new RegExp(safe);
    '''))
    assert rc == 0, err


def test_escaped_input_annotation_fails_without_escape_call():
    rc, out, err = run_against(textwrap.dedent('''\
        const raw = userInput;
        /* safeRegex: escaped-input */
        const r = new RegExp(raw);
    '''))
    assert rc == 1
    assert 'escaped-input annotation without escape call' in err, err


def test_generated_bounded_annotation_passes():
    rc, out, err = run_against(textwrap.dedent('''\
        const n = 10;
        /* safeRegex: generated-bounded */
        const r = new RegExp(`[a-z]{${n},}`);
    '''))
    assert rc == 0, err


def test_backcompat_builtin_works_on_categorized_source():
    # Historical call sites still use `builtin`; they should keep passing
    # even after the gate gains the stricter categories.
    rc, out, err = run_against(textwrap.dedent('''\
        const user = getInput();
        /* safeRegex: builtin */
        const r = new RegExp(user);
    '''))
    # This SHOULD pass — `builtin` is still a valid opt-out. The
    # categorized check only bites when the author chose the
    # `escaped-input` label.
    assert rc == 0, err


def test_escape_call_accepted_across_local_scope():
    # Regression for real site in timeline-view-popovers.js: the
    # escape call runs once at the top of a loop and the new RegExp
    # is constructed inside a nested block several lines below.
    rc, out, err = run_against(textwrap.dedent('''\
        while (anchor.length > 0) {
          const escAnchor = _escLiteral(anchor);
          let re;
          try {
            // Commentary about why this is escaped input.
            // Broken across multiple lines.
            // Still escaped though.
            /* safeRegex: escaped-input */
            re = new RegExp(escAnchor + '(' + tokenPattern + ')', 'i');
          } catch (_) { break; }
        }
    '''))
    assert rc == 0, err


def test_inline_replace_escape_pattern_accepted():
    # The canonical `escapeRegex`-equivalent inline form used at a few
    # older call sites (e.g. `src/app/app-yara.js:239`) splices the
    # historical regex-metacharacter class directly:
    #
    #     const escaped = needle.replace(/[.*+?^${}()|[]\\]/g, '\\$&');
    #     const r = new RegExp(escaped);
    #
    # The gate accepts this shape as a valid escape call — the
    # `ESCAPE_CALL_RE` in check_regex_safety.py has a second
    # alternation branch specifically for it. Previously untested;
    # a regression that removed this branch would break the YARA
    # compiler's highlight-token surface without the unit suite
    # catching it.
    rc, out, err = run_against(textwrap.dedent(r'''
        function build(needle) {
          const escaped = needle.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          /* safeRegex: escaped-input */
          return new RegExp(escaped, 'g');
        }
    '''))
    assert rc == 0, err


def test_inline_replace_escape_pattern_required_for_escaped_input_annotation():
    # Red-first companion to the test above: if the `.replace()` call
    # is removed, the `escaped-input` annotation is no longer
    # verifiable and the gate must fail. Proves the cross-check
    # actually looks at the inline form, not just the presence of
    # `.replace(` in general.
    rc, out, err = run_against(textwrap.dedent(r'''
        function build(needle) {
          const escaped = needle;
          /* safeRegex: escaped-input */
          return new RegExp(escaped, 'g');
        }
    '''))
    assert rc == 1
    assert 'escaped-input annotation without escape call' in err, err


def test_inline_replace_different_char_class_is_not_accepted():
    # A `.replace()` that strips a different character class (e.g.
    # just `/\s+/g` for whitespace) is NOT an escape — the gate's
    # inline branch matches the FULL metacharacter set literally.
    # A future contributor who writes a bespoke replace shouldn't
    # accidentally satisfy the cross-check.
    rc, out, err = run_against(textwrap.dedent(r'''
        function build(needle) {
          const escaped = needle.replace(/\s+/g, '_');
          /* safeRegex: escaped-input */
          return new RegExp(escaped, 'g');
        }
    '''))
    assert rc == 1
    assert 'escaped-input annotation without escape call' in err, err


if __name__ == '__main__':
    import traceback
    tests = [(n, v) for n, v in globals().items() if n.startswith('test_')]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f'ok  {name}')
        except AssertionError as e:
            failed += 1
            print(f'FAIL {name}')
            traceback.print_exc()
        except Exception as e:
            failed += 1
            print(f'FAIL {name} ({type(e).__name__})')
            traceback.print_exc()
    if failed:
        print(f'\n{failed}/{len(tests)} test(s) failed')
        sys.exit(1)
    print(f'\n{len(tests)}/{len(tests)} test(s) passed')
