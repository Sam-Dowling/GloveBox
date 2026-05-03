#!/usr/bin/env python3
"""fuzz_coverage_aggregate.py — turn raw V8 coverage dumps into a
per-`src/<file>.js` line-coverage table for the fuzz harness.

Usage as a library
------------------
``scripts/run_fuzz.py`` lazy-imports `aggregate_and_render(...)` when
the user passes ``--coverage``. The function reads each target's
NODE_V8_COVERAGE JSON dumps + manifest sidecar (written by
``tests/fuzz/helpers/harness.js`` when ``LOUPE_FUZZ_COVERAGE_DIR`` is
set), maps coverage ranges through the manifest's char-offset →
``src/<file>.js`` mapping, and returns a Markdown table block to be
appended to ``dist/fuzz-coverage/summary.md``.

Standalone CLI
--------------

    python scripts/fuzz_coverage_aggregate.py [--coverage-dir DIR] [--md]

Useful for re-rendering after a manual run::

    NODE_V8_COVERAGE=/tmp/cov LOUPE_FUZZ_COVERAGE_DIR=/tmp/cov \\
        node tests/fuzz/helpers/replay-runner.js \\
            tests/fuzz/targets/text/ioc-extract.fuzz.js
    python scripts/fuzz_coverage_aggregate.py --coverage-dir /tmp/cov \\
        --target text/ioc-extract --md

Algorithm
---------
V8's source-coverage report (the kind ``NODE_V8_COVERAGE`` writes)
encodes each function as a list of ``ranges``. The outermost range
spans the whole function body and its ``count`` is the entry hit
count. Inner ranges carve out sub-blocks (e.g. an ``else`` arm never
taken has ``count == 0`` over the sub-range). Critically, **nested
ranges override outer ones** — that is the c8 / istanbul-compatible
interpretation of V8 block coverage.

We use a per-char "paint" approach over the bundle source:

    1. Initialise a bitmap of length ``manifest.totalChars`` with
       ``UNKNOWN`` (-1).
    2. For each coverage entry whose ``url`` matches the manifest's
       ``filename``, walk every function's ranges OUTER-FIRST and
       paint each char in [start, end) with ``COVERED`` or
       ``UNCOVERED`` depending on ``range.count``.
    3. Char positions outside any function range remain ``UNKNOWN``
       — this is top-level statement bytes that V8 attributes to the
       implicit module function (which V8 always emits as the first
       function with empty ``functionName``, so they're rarely
       missed).
    4. For each src file, slice the bitmap to ``[file.start,
       file.end)`` and project covered/uncovered chars onto line
       numbers. A line is **covered** if any non-newline char on it
       is COVERED, **uncovered** if at least one char is UNCOVERED
       and none is COVERED, **unknown** otherwise.
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import sys
from typing import Dict, List, Optional, Tuple

# Bitmap states for the paint algorithm.
UNKNOWN = -1
UNCOVERED = 0
COVERED = 1


# ── Manifest + coverage IO ──────────────────────────────────────────────────
def _load_manifests(target_dir: str) -> List[dict]:
    """Return all manifest sidecars under ``target_dir``.

    The harness writes one per process (suffixed with pid + timestamp)
    so multi-process fuzz runs (Jazzer.js workers) each get their own.
    They all describe the SAME bundle layout for one target, so any one
    is sufficient — we still load them all to surface a divergence
    error if the bundle layout disagrees across processes.
    """
    out: List[dict] = []
    for fp in sorted(glob.glob(os.path.join(target_dir, 'manifest-*.json'))):
        with open(fp, 'r', encoding='utf-8') as f:
            out.append(json.load(f))
    return out


def _canonical_manifest(manifests: List[dict], target_id: str) -> Optional[dict]:
    """Pick one manifest as canonical and assert all others match.

    A divergence here would indicate a serious harness bug (different
    src/ files loaded across processes for the same target). We surface
    via a printed warning rather than raising — coverage is opportunistic.
    """
    if not manifests:
        return None
    first = manifests[0]
    for m in manifests[1:]:
        if m['filename'] != first['filename']:
            print(f'WARN  {target_id}: manifest filename divergence',
                  file=sys.stderr)
        if m['totalChars'] != first['totalChars']:
            print(f'WARN  {target_id}: manifest totalChars divergence',
                  file=sys.stderr)
    return first


def _load_v8_coverage_entries(target_dir: str, target_filename: str) -> List[dict]:
    """Pull all coverage entries whose url matches the target's bundle.

    Each ``coverage-*.json`` file contains a top-level ``{result:
    [...]}`` array per V8's spec. We filter to entries with
    ``url == target_filename`` and return the list. Multiple entries
    are possible across multiple dump files (one per process).
    """
    entries: List[dict] = []
    for fp in sorted(glob.glob(os.path.join(target_dir, 'coverage-*.json'))):
        try:
            with open(fp, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            # Truncated dump (process killed?) — skip silently. The
            # remaining dumps are usable.
            continue
        for r in data.get('result', []):
            if r.get('url') == target_filename:
                entries.append(r)
    return entries


# ── Paint algorithm ─────────────────────────────────────────────────────────
def _paint_bitmap(entries: List[dict], total_chars: int) -> bytearray:
    """Build a per-char COVERED / UNCOVERED / UNKNOWN bitmap of size
    ``total_chars`` from the V8 coverage entries.

    We use a ``bytearray`` with three sentinel values (offset by 1 so
    UNKNOWN=0 maps to bytearray's default-zero, and COVERED/UNCOVERED
    are non-zero). 1 byte per char × ~120k chars × 18 targets ≈ 2 MiB,
    well below any threshold.

    Algorithm — per-process paint with cross-process union:
      1. Within ONE process's coverage entry, ranges are emitted
         OUTER-FIRST then nested. Each range overrides its parent's
         paint within its span. We honour that by painting in
         declaration order, letting the inner ranges overwrite.
      2. Across processes, ``count > 0`` from any process beats
         ``count == 0`` from any other (the union semantics fuzz
         coverage actually wants — a process that exited before
         entering an inner branch shouldn't be able to mark that
         branch uncovered if another process did enter it).
      3. Once a char is COVERED, no later UNCOVERED paint can demote
         it. We achieve this by tracking a per-process bitmap, then
         OR-merging with the running union.
    """
    # 0x00 = UNKNOWN (no coverage info), 0x01 = UNCOVERED, 0x02 = COVERED.
    union = bytearray(total_chars)

    for entry in entries:
        per_proc = bytearray(total_chars)  # all UNKNOWN
        for fn in entry.get('functions', []):
            ranges = fn.get('ranges') or []
            # V8 emits ranges OUTER-FIRST. Painting in declaration
            # order means an inner range's UNCOVERED paint correctly
            # overrides its outer parent's COVERED paint within the
            # inner span.
            for rng in ranges:
                s = rng.get('startOffset', 0)
                e = rng.get('endOffset', 0)
                if s < 0 or e > total_chars or s >= e:
                    continue
                count = rng.get('count', 0)
                paint = 0x02 if count > 0 else 0x01
                # bytearray slice assignment is the fastest fill in
                # CPython for a ~10k-byte span; faster than a Python
                # for-loop.
                per_proc[s:e] = bytes([paint]) * (e - s)

        # Merge into the cross-process union: COVERED beats UNCOVERED
        # beats UNKNOWN. We can't use a plain max() because bytearray
        # doesn't expose element-wise max — fall back to a fast Python
        # path that exits early if there's nothing to merge.
        for i in range(total_chars):
            v = per_proc[i]
            if v > union[i]:
                union[i] = v

    return union


# ── Per-file line attribution ───────────────────────────────────────────────
def _line_offsets_for_region(bundle: str, start: int, end: int) -> List[int]:
    """Return the absolute char offsets at which lines start within
    ``bundle[start:end]``.

    The first line starts at ``start``; subsequent lines start at
    each ``\\n + 1`` boundary inside the slice.
    """
    out = [start]
    i = start
    while i < end:
        nl = bundle.find('\n', i, end)
        if nl == -1:
            break
        out.append(nl + 1)
        i = nl + 1
    return out


def _per_file_line_coverage(bundle: str,
                            bm: bytearray,
                            file_entries: List[dict],
                            ) -> Dict[str, dict]:
    """For each src/<file>.js entry in the manifest, project the paint
    bitmap onto per-line coverage.

    Returns ``{rel: {covered, uncovered, unknown, total}}`` line counts.
    """
    out: Dict[str, dict] = {}
    for fe in file_entries:
        rel = fe['rel']
        s = fe['start']
        e = fe['end']
        line_starts = _line_offsets_for_region(bundle, s, e)
        # Append a sentinel so each line has a clean [start, end).
        line_starts.append(e)

        covered = 0
        uncovered = 0
        unknown = 0
        # A line is "blank" (only whitespace + newline) if every
        # non-newline char is whitespace. We don't count blank lines as
        # uncovered — they have no semantic content.
        blank = 0
        for idx in range(len(line_starts) - 1):
            ls = line_starts[idx]
            le = line_starts[idx + 1]
            line_text = bundle[ls:le]
            stripped = line_text.strip()
            if not stripped:
                blank += 1
                continue
            # Pure-comment lines are also non-executable from V8's POV.
            # Cheap heuristic: leading // or starts with /* / *. We
            # skip these to keep the % covered metric meaningful.
            stripped_first = stripped.lstrip()
            if (stripped_first.startswith('//')
                or stripped_first.startswith('/*')
                or stripped_first.startswith('*/')
                or stripped_first.startswith('* ')
                or stripped_first == '*'):
                blank += 1
                continue

            # Aggregate the bitmap over this line's char span.
            line_state = UNKNOWN
            for ci in range(ls, le):
                v = bm[ci]
                if v == 0x02:  # COVERED — winning state
                    line_state = COVERED
                    break
                elif v == 0x01 and line_state == UNKNOWN:
                    line_state = UNCOVERED
            if line_state == COVERED:
                covered += 1
            elif line_state == UNCOVERED:
                uncovered += 1
            else:
                unknown += 1

        executable = covered + uncovered + unknown
        out[rel] = {
            'rel': rel,
            'covered': covered,
            'uncovered': uncovered,
            'unknown': unknown,
            'blank': blank,
            'executable': executable,
            'total_lines': fe.get('lines', 0),
            'pct': (100.0 * covered / executable) if executable else 0.0,
        }
    return out


# ── Bundle reconstruction ───────────────────────────────────────────────────
def _reconstruct_bundle(repo_root: str, manifest: dict) -> str:
    """Rebuild the exact JS string that was passed to vm.runInContext.

    The harness assembles the bundle from concrete src/ files plus a
    sentinel comment per file. We mirror that so the manifest's char
    offsets line up with our reconstruction. ``totalChars`` from the
    manifest acts as an integrity check.
    """
    parts: List[str] = []
    for fe in manifest.get('files', []):
        # Sentinel injected by load-bundle.js BEFORE each file body.
        parts.append(f'\n// ─── load-bundle: {fe["rel"]} ───\n')
        abs_path = os.path.join(repo_root, fe['rel'])
        with open(abs_path, 'r', encoding='utf-8') as f:
            parts.append(f.read())
    bundle = ''.join(parts)
    # We also need the trailing exposure block to push totalChars to
    # the manifest's value, but for line coverage we only ever index
    # into [file.start, file.end) — the exposure block is irrelevant.
    # Pad with NULs to satisfy any out-of-range bitmap reads.
    if len(bundle) < manifest['totalChars']:
        bundle = bundle + '\x00' * (manifest['totalChars'] - len(bundle))
    elif len(bundle) > manifest['totalChars']:
        # Shouldn't happen (manifest is captured AFTER full bundle
        # construction including expose block); truncate to be safe.
        bundle = bundle[:manifest['totalChars']]
    return bundle


# ── Public entry ────────────────────────────────────────────────────────────
def aggregate_target(coverage_dir: str, repo_root: str,
                     target_id: str) -> Optional[dict]:
    """Aggregate coverage for one target. Returns None if no manifest
    or no coverage dump was found (target ran without --coverage)."""
    target_dir = os.path.join(coverage_dir, *target_id.split('/'))
    if not os.path.isdir(target_dir):
        return None
    manifests = _load_manifests(target_dir)
    if not manifests:
        return None
    manifest = _canonical_manifest(manifests, target_id)
    entries = _load_v8_coverage_entries(target_dir, manifest['filename'])
    if not entries:
        return {
            'target': target_id,
            'files': [],
            'rollup': _empty_rollup(),
            'note': 'no V8 coverage entries matched the bundle filename',
        }
    bundle = _reconstruct_bundle(repo_root, manifest)
    bm = _paint_bitmap(entries, manifest['totalChars'])
    files = _per_file_line_coverage(bundle, bm, manifest.get('files', []))
    return {
        'target': target_id,
        'files': sorted(files.values(), key=lambda f: f['rel']),
        'rollup': _rollup_files(files.values()),
    }


def _empty_rollup() -> dict:
    return {'covered': 0, 'uncovered': 0, 'unknown': 0,
            'executable': 0, 'pct': 0.0}


def _rollup_files(files) -> dict:
    covered = sum(f['covered'] for f in files)
    uncovered = sum(f['uncovered'] for f in files)
    unknown = sum(f['unknown'] for f in files)
    executable = covered + uncovered + unknown
    return {
        'covered': covered,
        'uncovered': uncovered,
        'unknown': unknown,
        'executable': executable,
        'pct': (100.0 * covered / executable) if executable else 0.0,
    }


# ── Markdown rendering ──────────────────────────────────────────────────────
def _render_md(per_target: List[dict]) -> str:
    """Render the per-target × per-src/file coverage matrix."""
    if not per_target:
        return '## Coverage\n\n_no targets reported coverage data_\n'

    lines: List[str] = []
    lines.append('## Coverage (V8 source-coverage)\n')
    lines.append(
        'Per-target line coverage of the `src/` files each target loads. '
        'Lines that contain only whitespace, comments, or `*` block-comment '
        'continuation are excluded from the executable line count. '
        '`unknown` lines are inside the bundle but outside any V8-tracked '
        'function range — typically top-level constant declarations the '
        'V8 implicit-module function does cover but reports without '
        'attribution.\n'
    )

    # Per-target rollup table.
    lines.append('### Per-target rollup\n')
    lines.append('| target | files | exec | covered | uncovered | unknown | % |')
    lines.append('|---|---:|---:|---:|---:|---:|---:|')
    for entry in per_target:
        r = entry['rollup']
        lines.append(
            f'| {entry["target"]} '
            f'| {len(entry["files"])} '
            f'| {r["executable"]} '
            f'| {r["covered"]} '
            f'| {r["uncovered"]} '
            f'| {r["unknown"]} '
            f'| {r["pct"]:.1f} |'
        )
    lines.append('')

    # Per-target file detail.
    for entry in per_target:
        if not entry['files']:
            continue
        lines.append(f'### `{entry["target"]}`\n')
        lines.append('| src file | exec | covered | uncovered | unknown | % |')
        lines.append('|---|---:|---:|---:|---:|---:|')
        for f in entry['files']:
            lines.append(
                f'| `{f["rel"]}` '
                f'| {f["executable"]} '
                f'| {f["covered"]} '
                f'| {f["uncovered"]} '
                f'| {f["unknown"]} '
                f'| {f["pct"]:.1f} |'
            )
        lines.append('')

    # Cross-target src/<file>.js rollup — answers "which src/ files are
    # the LEAST covered overall?".
    by_rel: Dict[str, dict] = collections.defaultdict(
        lambda: {'covered': 0, 'uncovered': 0, 'unknown': 0,
                 'executable': 0, 'targets': 0})
    for entry in per_target:
        for f in entry['files']:
            agg = by_rel[f['rel']]
            agg['covered'] += f['covered']
            agg['uncovered'] += f['uncovered']
            agg['unknown'] += f['unknown']
            agg['executable'] += f['executable']
            agg['targets'] += 1
    if by_rel:
        lines.append('### Per-`src/` file rollup (across all targets)\n')
        lines.append('| src file | targets | exec | covered | uncovered | unknown | % |')
        lines.append('|---|---:|---:|---:|---:|---:|---:|')
        # Sort by ascending coverage % so the gaps are at the top.
        ranked = sorted(by_rel.items(),
                        key=lambda kv: (kv[1]['executable']
                                        and kv[1]['covered'] / kv[1]['executable']
                                        or 0.0))
        for rel, agg in ranked:
            pct = (100.0 * agg['covered'] / agg['executable']
                   if agg['executable'] else 0.0)
            lines.append(
                f'| `{rel}` '
                f'| {agg["targets"]} '
                f'| {agg["executable"]} '
                f'| {agg["covered"]} '
                f'| {agg["uncovered"]} '
                f'| {agg["unknown"]} '
                f'| {pct:.1f} |'
            )
        lines.append('')

    return '\n'.join(lines) + '\n'


def aggregate_and_render(coverage_dir: str, repo_root: str,
                         target_ids: List[str]) -> str:
    """Aggregate coverage for every target_id and return a Markdown
    block ready to be appended to summary.md. Targets that didn't run
    under --coverage (no manifest) are silently skipped."""
    per_target: List[dict] = []
    for tid in target_ids:
        agg = aggregate_target(coverage_dir, repo_root, tid)
        if agg is not None:
            per_target.append(agg)
    return _render_md(per_target)


# ── CLI ─────────────────────────────────────────────────────────────────────
def _cli() -> int:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_cov = os.path.join(repo_root, 'dist', 'fuzz-coverage', 'v8')

    parser = argparse.ArgumentParser(
        prog='fuzz_coverage_aggregate.py',
        description='Aggregate V8 fuzz-coverage dumps into a per-src/file table.',
    )
    parser.add_argument('--coverage-dir', type=str, default=default_cov,
                        help=f'directory containing per-target coverage subdirs '
                             f'(default: {os.path.relpath(default_cov, repo_root)})')
    parser.add_argument('--target', action='append', default=None,
                        help='target id to render (repeat for multiple). '
                             'Default: every subdir of --coverage-dir.')
    parser.add_argument('--md', action='store_true',
                        help='emit Markdown to stdout (default).')
    parser.add_argument('--json', action='store_true',
                        help='emit JSON to stdout instead of Markdown.')
    args = parser.parse_args()

    targets = args.target
    if not targets:
        # Walk the coverage dir to find every target. Targets are nested
        # under their forward-slash-shaped id.
        targets = []
        for root, _dirs, files in os.walk(args.coverage_dir):
            if any(f.startswith('manifest-') and f.endswith('.json')
                   for f in files):
                rel = os.path.relpath(root, args.coverage_dir)
                targets.append(rel.replace(os.sep, '/'))
        targets.sort()
    if not targets:
        print(f'no targets found under {args.coverage_dir}', file=sys.stderr)
        return 1

    per_target = []
    for tid in targets:
        agg = aggregate_target(args.coverage_dir, repo_root, tid)
        if agg is not None:
            per_target.append(agg)

    if args.json:
        json.dump(per_target, sys.stdout, indent=2)
        print()
    else:
        sys.stdout.write(_render_md(per_target))
    return 0


if __name__ == '__main__':
    sys.exit(_cli())
