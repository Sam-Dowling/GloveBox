#!/usr/bin/env python3
"""fuzz_promote.py — synthesise a permanent unit-test reproducer from a
crash dir.

A crash artefact at::

    dist/fuzz-crashes/<target>/<sha>/
        input.bin
        stack.txt
        minimised.bin   ← optional, written by scripts/fuzz_minimise.py

is ephemeral — it lives in ``dist/`` (gitignored).  The moment the bug
is fixed, we want a permanent ``node:test`` reproducer committed under
``tests/unit/`` so a future regression on the same buffer fails the
default ``python make.py test-unit`` gate.  This script automates that
hand-off, producing a file that follows the same shape as every other
``tests/unit/*.test.js``:

    tests/unit/<target>-fuzz-regress-<sha>.test.js

The generated test:

  • Loads the target's existing ``*.fuzz.js`` module — that's the
    single source of truth for which ``src/`` files to evaluate, which
    expose list to use, and which ``onIteration`` invariants to assert.
    No code duplication.
  • Inlines the (minimised, if available) crash bytes as a base64
    string.  Inlining keeps the test self-contained and robust to
    later cleanup of ``dist/`` or the original crash dir.
  • Asserts that running the target's fuzz function on those bytes
    *does not throw*.  The whole point of promoting a fuzz finding is
    that the fix has already landed; the test pins the absence of the
    regression.
  • Carries a comment block with the original error name + message + a
    truncated stack so a future failure surfaces context immediately.

Usage:

    python scripts/fuzz_promote.py <target> <crash-dir-or-input-or-sha>
    python scripts/fuzz_promote.py --use original \\
        text/ioc-extract dist/fuzz-crashes/text/ioc-extract/abc1234567890123

    # All flags:
    --use {minimised,original,auto}
                       which input file to inline (default: auto =
                       prefer minimised.bin if present)
    --output <path>    write generated test elsewhere (default:
                       ``tests/unit/<target-slug>-fuzz-regress-<sha>.test.js``)
    --note '<text>'    extra one-line note appended to the file header
    --dry-run          print the generated test to stdout and exit
    --force            overwrite an existing reproducer for the same sha

Exit codes:
    0   reproducer written (or dry-run printed)
    1   crash artefacts incomplete (no input.bin / no stack.txt)
    2   misuse / missing files / target not found
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import sys
import textwrap
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_FUZZ = os.path.join(BASE, 'tests', 'fuzz')
TARGETS_DIR = os.path.join(TESTS_FUZZ, 'targets')
TESTS_UNIT_DIR = os.path.join(BASE, 'tests', 'unit')
CRASHES_DIR = os.path.join(BASE, 'dist', 'fuzz-crashes')

SHA_RE = re.compile(r'^[0-9a-f]{16}$')


# ── Target / crash-dir resolution (kept in sync with fuzz_minimise.py) ──────
def _discover_targets() -> list[str]:
    out = []
    for root, _dirs, files in os.walk(TARGETS_DIR):
        for f in files:
            if f.endswith('.fuzz.js'):
                rel = os.path.relpath(os.path.join(root, f), TARGETS_DIR)
                rel = rel[:-len('.fuzz.js')].replace(os.sep, '/')
                out.append(rel)
    return sorted(out)


def _resolve_target(name: str) -> tuple[str, str]:
    cand = name.replace(os.sep, '/').replace('.fuzz.js', '')
    abs_path = os.path.join(TARGETS_DIR, *cand.split('/')) + '.fuzz.js'
    if os.path.isfile(abs_path):
        return abs_path, cand
    matches = [t for t in _discover_targets()
               if t.endswith('/' + cand) or t == cand]
    if len(matches) == 1:
        ident = matches[0]
        return os.path.join(TARGETS_DIR, *ident.split('/')) + '.fuzz.js', ident
    if not matches:
        sys.exit(f'no fuzz target matches {name!r}. Run `python scripts/run_fuzz.py --list`.')
    sys.exit(f'ambiguous target name {name!r} — matches: {", ".join(matches)}')


def _resolve_crash_dir(target_id: str, crash_arg: str) -> tuple[str, str]:
    """Return (crash directory, sha)."""
    cand = os.path.abspath(crash_arg)
    if os.path.isfile(cand):
        crash_dir = os.path.dirname(cand)
    elif os.path.isdir(cand):
        crash_dir = cand
    elif SHA_RE.match(crash_arg.lower()):
        crash_dir = os.path.join(CRASHES_DIR, *target_id.split('/'),
                                 crash_arg.lower())
        if not os.path.isdir(crash_dir):
            sys.exit(f'no crash dir at {crash_dir}')
    else:
        sys.exit(f'cannot resolve crash {crash_arg!r}')
    sha = os.path.basename(crash_dir.rstrip(os.sep))
    if not SHA_RE.match(sha):
        sys.exit(f'crash dir {crash_dir} does not look like <16-hex-sha>')
    return crash_dir, sha


# ── Stack-text parsing ──────────────────────────────────────────────────────
def _parse_stack_txt(stack_path: str) -> dict:
    """Pull err.name, err.message, kind, inputBytes, stack from stack.txt.

    The replay-runner writes::

        kind=<seed|mutation|reproduce>
        inputBytes=<N>
        error.name=<NAME>
        error.message=<MSG>

        <full stack>

    We parse the header KV lines until the first blank line, then keep
    the rest verbatim as the stack text.
    """
    info = {'kind': '', 'inputBytes': '', 'errName': 'Error',
            'errMessage': '', 'stack': ''}
    if not os.path.isfile(stack_path):
        return info
    with open(stack_path, 'r', encoding='utf-8') as f:
        text = f.read()
    head, _sep, tail = text.partition('\n\n')
    for line in head.splitlines():
        if '=' not in line:
            continue
        k, _eq, v = line.partition('=')
        k = k.strip()
        v = v.strip()
        if k == 'kind': info['kind'] = v
        elif k == 'inputBytes': info['inputBytes'] = v
        elif k == 'error.name': info['errName'] = v
        elif k == 'error.message': info['errMessage'] = v
    info['stack'] = tail.strip()
    return info


# ── Code generation ─────────────────────────────────────────────────────────
def _slugify(target_id: str) -> str:
    """Convert a target identifier ('text/ioc-extract') to a filename
    fragment ('text-ioc-extract')."""
    return target_id.replace('/', '-')


def _wrap_js_comment(text: str, width: int = 78) -> str:
    """Wrap `text` to a `// ` comment block.  Preserves explicit blank
    lines."""
    out_lines = []
    for para in text.split('\n'):
        if not para.strip():
            out_lines.append('//')
            continue
        wrapped = textwrap.wrap(para, width=width - 3) or ['']
        out_lines.extend(f'// {w}' for w in wrapped)
    return '\n'.join(out_lines)


def _format_base64_block(b64: str, indent: str = '  ', cols: int = 76) -> str:
    """Split a base64 string into a JS multi-line concat that fits
    cleanly inside an editor.  Output looks like::

          'AAAA'
          + 'BBBB'
          + 'CCCC'
    """
    lines = [b64[i:i + cols] for i in range(0, len(b64), cols)]
    if not lines:
        return f"{indent}''"
    out = [f"{indent}'{lines[0]}'"]
    for line in lines[1:]:
        out.append(f"{indent}+ '{line}'")
    return '\n'.join(out)


_TEST_TEMPLATE = """\
'use strict';
// ════════════════════════════════════════════════════════════════════════════
// {basename} — fuzz regression reproducer.
//
// Auto-generated by `scripts/fuzz_promote.py` on {iso_date}.
// Source crash:    dist/fuzz-crashes/{target_id}/{sha}/  (ephemeral)
// Source target:   tests/fuzz/targets/{target_id}.fuzz.js
// Stack hash:      {sha}
// Input variant:   {input_variant} ({input_bytes} bytes)
// Original throw:  {err_name}: {err_message}
//
// {note_line}This test pins the absence of the regression. The fuzz finding's
// minimised input is base64-inlined below, fed through the SAME fuzz
// target (and therefore the SAME vm.Context, expose list, and
// invariants) that found the bug originally.  A future re-introduction
// of the bug will fail this test under `python make.py test-unit`,
// long before anyone re-runs the full fuzzer.
//
// Original stack (truncated to {stack_max_lines} lines):
{stack_block}
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

// Load the fuzz target itself — single source of truth for which src/
// files to evaluate, which symbols to expose, and what invariants to
// assert per iteration.  No duplication.
const targetPath = path.resolve(
  __dirname, '..', 'fuzz', 'targets', '{target_id}.fuzz.js',
);
const target = require(targetPath);

// Minimised crashing input, base64-encoded.
const INPUT_B64 =
{b64_block};
const INPUT = Buffer.from(INPUT_B64, 'base64');

test('fuzz-regress[{target_id}/{sha}]: target runs cleanly on the historical crash buffer', async () => {{
  // The target's `fuzz(buf)` already enforces the per-iteration budget
  // (DEFAULT_PER_ITER_BUDGET_MS=2500 in harness.js) and re-throws any
  // non-expected error with a stack-hash attached.  We simply assert
  // it doesn't throw.
  await assert.doesNotReject(target.fuzz(INPUT),
    `regression at hash {sha}: ${{INPUT.length}} bytes still triggers a fuzz failure`);
}});
"""


def _render_test(target_id: str, sha: str, input_b64: str, input_bytes: int,
                 input_variant: str, stack_info: dict, note: str | None) -> str:
    note_line = f'NOTE: {note}\n//\n// ' if note else ''
    stack_lines = stack_info['stack'].splitlines()[:14]
    stack_block = _wrap_js_comment(
        '\n'.join(stack_lines) if stack_lines else '<no stack recorded>'
    )
    basename = f'{_slugify(target_id)}-fuzz-regress-{sha}.test.js'
    err_name = stack_info['errName'] or 'Error'
    err_message = stack_info['errMessage'] or '<unrecorded>'
    # Escape `*/` in case it appears in the message — JS comment only.
    err_message = err_message.replace('*/', '* /')
    return _TEST_TEMPLATE.format(
        basename=basename,
        iso_date=time.strftime('%Y-%m-%d', time.gmtime()),
        target_id=target_id,
        sha=sha,
        input_variant=input_variant,
        input_bytes=input_bytes,
        err_name=err_name,
        err_message=err_message,
        note_line=note_line,
        stack_max_lines=len(stack_lines),
        stack_block=stack_block,
        b64_block=_format_base64_block(input_b64),
    )


# ── CLI ─────────────────────────────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(
        prog='fuzz_promote.py',
        description='Synthesise a permanent unit-test reproducer from a fuzz crash dir.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('target', help='target identifier (e.g. text/ioc-extract)')
    parser.add_argument('crash', help='crash directory, input.bin path, or 16-hex sha')
    parser.add_argument('--use', choices=('minimised', 'original', 'auto'),
                        default='auto',
                        help='which input variant to inline (default: auto)')
    parser.add_argument('--output', type=str, default=None,
                        help='output path (default: tests/unit/<slug>-fuzz-regress-<sha>.test.js)')
    parser.add_argument('--note', type=str, default=None,
                        help='extra one-line note appended to the test header')
    parser.add_argument('--dry-run', action='store_true',
                        help='print generated test to stdout instead of writing')
    parser.add_argument('--force', action='store_true',
                        help='overwrite an existing reproducer for the same sha')
    args = parser.parse_args()

    target_path, target_id = _resolve_target(args.target)
    if not os.path.isfile(target_path):
        sys.exit(f'fuzz-promote: target file not found at {target_path}')

    crash_dir, sha = _resolve_crash_dir(target_id, args.crash)
    original = os.path.join(crash_dir, 'input.bin')
    minimised = os.path.join(crash_dir, 'minimised.bin')
    stack_txt = os.path.join(crash_dir, 'stack.txt')

    if not os.path.isfile(original):
        sys.exit(f'fuzz-promote: {original} missing — incomplete crash dir')

    use = args.use
    if use == 'auto':
        use = 'minimised' if os.path.isfile(minimised) else 'original'

    if use == 'minimised' and not os.path.isfile(minimised):
        sys.exit(f'fuzz-promote: --use minimised but {minimised} missing. '
                 f'Run `python scripts/fuzz_minimise.py {target_id} {crash_dir}` first.')
    chosen = minimised if use == 'minimised' else original
    with open(chosen, 'rb') as f:
        buf = f.read()
    if not buf:
        sys.exit(f'fuzz-promote: {chosen} is empty — cannot promote')
    b64 = base64.b64encode(buf).decode('ascii')

    stack_info = _parse_stack_txt(stack_txt)

    test_src = _render_test(
        target_id=target_id,
        sha=sha,
        input_b64=b64,
        input_bytes=len(buf),
        input_variant=use,
        stack_info=stack_info,
        note=args.note,
    )

    if args.dry_run:
        sys.stdout.write(test_src)
        return 0

    out_path = args.output or os.path.join(
        TESTS_UNIT_DIR, f'{_slugify(target_id)}-fuzz-regress-{sha}.test.js',
    )
    if os.path.exists(out_path) and not args.force:
        sys.exit(f'fuzz-promote: {out_path} already exists. Pass --force to overwrite.')
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(test_src)

    rel = os.path.relpath(out_path, BASE)
    print(f'OK    promoted {target_id}/{sha} → {rel}  '
          f'(input={use}, {len(buf)} bytes)')
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
