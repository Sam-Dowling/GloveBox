#!/usr/bin/env python3
"""Tests for `scripts/check_pushioc.py::scan_bare_pushioc`.

Pins the detection contract of the `pushIOC()`-only build gate:

    * Bare same-line `findings.<bucket>.push({...})` → violation.
    * Fluent split-call (`findings.<bucket>\\n  .push({...})`) → violation.
      This is the hardening motivating commit — the previous regex was
      single-line-only and would silently miss this shape.
    * `pushIOC(f, {...})` chokepoint → no violation.
    * A bare push on a pure-comment line (reference snippet in a
      docstring) → no violation.

Run with:  python3 scripts/test_check_pushioc.py
       or: python3 -m unittest scripts/test_check_pushioc.py
"""
from __future__ import annotations

import os
import sys
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_pushioc import scan_bare_pushioc  # noqa: E402


class ScanBarePushIocTests(unittest.TestCase):

    def test_bare_single_line_push_is_flagged(self):
        text = textwrap.dedent('''\
            function emit(f) {
              f.externalRefs.push({ type: 'url', url: 'x' });
            }
        ''')
        v = scan_bare_pushioc('src/sample.js', text)
        self.assertEqual(len(v), 1, v)
        self.assertIn('src/sample.js:2', v[0])
        self.assertIn('.externalRefs.push(', v[0])

    def test_bare_interestingStrings_push_is_flagged(self):
        text = textwrap.dedent('''\
            f.interestingStrings.push({ type: 'pattern', url: 'x' });
        ''')
        v = scan_bare_pushioc('src/sample.js', text)
        self.assertEqual(len(v), 1, v)
        self.assertIn('.interestingStrings.push(', v[0])

    def test_multi_line_fluent_push_is_flagged(self):
        # Red-first: the pre-hardening regex would miss this shape. The
        # DOTALL scan in scan_bare_pushioc catches it.
        text = textwrap.dedent('''\
            function emit(f) {
              f.externalRefs
                .push({ type: 'url', url: 'x' });
            }
        ''')
        v = scan_bare_pushioc('src/sample.js', text)
        self.assertEqual(len(v), 1, v)
        # Reported at the line where the bucket reference starts.
        self.assertIn('src/sample.js:2', v[0])

    def test_pushIOC_chokepoint_is_not_flagged(self):
        text = textwrap.dedent('''\
            function emit(f) {
              pushIOC(f, { type: IOC.URL, value: 'x', bucket: 'externalRefs' });
            }
        ''')
        v = scan_bare_pushioc('src/sample.js', text)
        self.assertEqual(v, [])

    def test_comment_lines_are_not_flagged(self):
        # Reference snippets in docstrings / migration-history comments
        # must not trip the gate. The single-line scan skips pure-comment
        # lines (`//` or `*` prefix).
        text = textwrap.dedent('''\
            // Example (migration history): f.externalRefs.push({...}) → pushIOC()
            /*
             * Old form: f.interestingStrings.push(...)
             */
            pushIOC(f, { type: IOC.URL, value: 'x' });
        ''')
        v = scan_bare_pushioc('src/sample.js', text)
        self.assertEqual(v, [])

    def test_dedupe_between_single_and_multi_line_scans(self):
        # A plain same-line bare push matches BOTH the single-line scan
        # and the multi-line DOTALL scan. The violation list must
        # deduplicate so the site reports once, not twice.
        text = 'f.externalRefs.push({ type: "url", url: "x" });\n'
        v = scan_bare_pushioc('src/sample.js', text)
        self.assertEqual(len(v), 1, v)

    def test_multiple_distinct_violations_report_separately(self):
        text = textwrap.dedent('''\
            f.externalRefs.push(a);
            g.interestingStrings.push(b);
            h.externalRefs
              .push(c);
        ''')
        v = scan_bare_pushioc('src/sample.js', text)
        self.assertEqual(len(v), 3, v)
        # Violations are sorted by line number.
        self.assertIn(':1:', v[0])
        self.assertIn(':2:', v[1])
        self.assertIn(':3:', v[2])

    def test_unrelated_push_sites_are_not_flagged(self):
        text = textwrap.dedent('''\
            myArray.push(x);
            container.children.push(el);
            parts.push(segment);
        ''')
        v = scan_bare_pushioc('src/sample.js', text)
        self.assertEqual(v, [])

    def test_optional_whitespace_between_bucket_and_push(self):
        # The multi-line regex permits whitespace around the dots
        # (tolerates prettier formatting). Same-line weird-whitespace
        # forms must still match.
        text = 'f.externalRefs .push(a);\n'
        v = scan_bare_pushioc('src/sample.js', text)
        self.assertEqual(len(v), 1, v)


if __name__ == '__main__':
    unittest.main()
