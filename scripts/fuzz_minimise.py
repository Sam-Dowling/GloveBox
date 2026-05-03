#!/usr/bin/env python3
"""fuzz_minimise.py — shrink a crashing fuzz input while preserving the bug.

Loupe's fuzz crash artefact layout:

    dist/fuzz-crashes/<target>/<sha>/
        input.bin        ← original failing input (NEVER modified)
        stack.txt        ← captured at first-crash time
        minimised.bin    ← (output) smallest input found that still throws
                           with the same stack hash

The minimiser is a *delta-debugger*-style greedy reducer with a single
verifier:

    fuzz(buf)  threw with the same 16-hex stack hash as the original?

If yes → the candidate replaces the current best; otherwise → reverted.
A reduction pass terminates when one full pass over the candidate
strategies produces no further improvement. Strategies, in order:

    1. Halve from the end (binary slice)         O(log n) length probes
    2. Halve from the start                       O(log n)
    3. Drop a sliding window of size 8/4/2/1     O(n) per window size
    4. Replace single bytes with 0x20            O(n)
       (after length-minimisation; bytes-only "normalise" pass)

Why a separate Python script and not a Jazzer.js feature?  libFuzzer
has its own minimiser (`-minimize_crash=1`) but it doesn't understand
our stack-hash dedup contract — it minimises by "any exception", which
collapses two distinct bugs that happen to share a target.  Driving
each candidate through `tests/fuzz/helpers/run-once.js` keeps the
verifier identical to the harness used at find-time.

Speed.  Each candidate spawns a fresh `node`, paying ~80 ms of
vm.Context init.  At 1024 candidates that's ~80 s — acceptable
for an interactive `you fix the bug now` workflow.  We surface
progress every 16 candidates so the user sees the size curve drop.

Usage:

    python scripts/fuzz_minimise.py <target> <crash-dir-or-input.bin>
    python scripts/fuzz_minimise.py text/ioc-extract dist/fuzz-crashes/text/ioc-extract/abc123…
    python scripts/fuzz_minimise.py --time 60 yara/parse-rules dist/fuzz-crashes/yara/parse-rules/abc123…/input.bin

Flags:
    --time <seconds>       wall-clock cap; minimisation is greedy and may
                           plateau early — without --time it runs to
                           convergence.
    --target-hash <16hex>  override the computed hash (rare; useful when
                           inspecting an input.bin that wasn't recorded
                           with a stack.txt)
    --output <path>        write minimised bytes here instead of
                           ``<crash-dir>/minimised.bin``
    --quiet                only emit the final summary line

Exit codes:
    0   minimisation converged (or --time exhausted with progress)
    1   the supplied input did not actually crash the target — the
        minimiser refuses to operate on a non-reproducer
    2   misuse / missing files
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_FUZZ = os.path.join(BASE, 'tests', 'fuzz')
TARGETS_DIR = os.path.join(TESTS_FUZZ, 'targets')
RUN_ONCE_JS = os.path.join(TESTS_FUZZ, 'helpers', 'run-once.js')
CRASHES_DIR = os.path.join(BASE, 'dist', 'fuzz-crashes')

# 16-hex stack-hash regex: extracted from stack.txt header or directory name.
SHA_RE = re.compile(r'^[0-9a-f]{16}$')


# ── Subprocess primitive ────────────────────────────────────────────────────
def _build_run_once_env() -> dict:
    """Construct the env passed to every run-once.js spawn.

    Critically, we **strip** any inherited ``NODE_V8_COVERAGE`` /
    ``LOUPE_FUZZ_COVERAGE_DIR`` so that minimisation runs (which
    invoke run-once.js hundreds of times per pass) do NOT write
    coverage dumps on every candidate. A user who set those vars in
    their shell, or who ran the minimiser straight after a
    ``run_fuzz.py --coverage`` session, would otherwise accumulate
    junk dumps in the coverage dir AND pay a real wall-clock penalty
    per candidate (V8 source coverage is documented to slow heavy
    parsers ~9×; that compounds across hundreds of candidates into
    minutes of wasted reduction time).

    Coverage measurement is a property of full fuzz runs (see
    ``scripts/run_fuzz.py --coverage``). Minimisation is a different
    workflow with its own goals (shrink the input, preserve the
    stack hash) that has nothing to gain from per-candidate coverage.
    """
    env = os.environ.copy()
    env.pop('NODE_V8_COVERAGE', None)
    env.pop('LOUPE_FUZZ_COVERAGE_DIR', None)
    return env


def _run_once(target_path: str, candidate_path: str, target_hash: str | None,
              timeout_s: float) -> dict:
    """Spawn run-once.js once and parse the resulting JSON line.

    Returns a dict matching run-once.js's IPC contract, plus
    ``_aborted`` and ``_durationMs`` fields the minimiser sets itself.
    On node-side hard failure (exit code 2) returns {'_aborted': True}
    so the caller can decide to bail.
    """
    cmd = ['node', RUN_ONCE_JS, target_path, candidate_path]
    if target_hash:
        cmd += ['--target-hash', target_hash]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, cwd=BASE, capture_output=True, text=True,
            timeout=timeout_s, env=_build_run_once_env(),
        )
    except subprocess.TimeoutExpired:
        return {'_aborted': False, 'ok': False, 'threw': False,
                'stackHash': '', 'errName': 'Timeout', 'errMessage': '',
                '_durationMs': timeout_s * 1000, '_timeout': True}

    duration_ms = (time.monotonic() - t0) * 1000

    # rc 2 == run-once harness itself broke. rc 0 == "still crashing with
    # target hash"; rc 1 == "doesn't crash with that hash".  All three
    # should still emit valid JSON on stdout (the harness fails loudly
    # via stderr in the rc=2 case, but never without JSON when target
    # actually loaded).
    if proc.returncode == 2 and not proc.stdout.strip():
        sys.stderr.write(f'fuzz-minimise: run-once harness crashed:\n{proc.stderr}')
        return {'_aborted': True, '_durationMs': duration_ms}

    # Take the LAST line — Node's stderr/stdout interleaving is normally
    # disjoint here but we'd rather be defensive.
    out_lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if not out_lines:
        sys.stderr.write(
            f'fuzz-minimise: empty stdout from run-once.js (rc={proc.returncode})\n'
            f'stderr:\n{proc.stderr}\n'
        )
        return {'_aborted': True, '_durationMs': duration_ms}
    try:
        result = json.loads(out_lines[-1])
    except json.JSONDecodeError as e:
        sys.stderr.write(
            f'fuzz-minimise: run-once.js stdout is not JSON ({e}):\n{out_lines[-1]}\n'
        )
        return {'_aborted': True, '_durationMs': duration_ms}

    result['_aborted'] = False
    result['_durationMs'] = duration_ms
    return result


# ── Target / crash-dir resolution ───────────────────────────────────────────
def _discover_targets() -> list[str]:
    """Mirror run_fuzz.py's logic — return target identifiers."""
    out = []
    for root, _dirs, files in os.walk(TARGETS_DIR):
        for f in files:
            if f.endswith('.fuzz.js'):
                rel = os.path.relpath(os.path.join(root, f), TARGETS_DIR)
                rel = rel[:-len('.fuzz.js')].replace(os.sep, '/')
                out.append(rel)
    return sorted(out)


def _resolve_target(name: str) -> tuple[str, str]:
    """Return (absolute path, identifier) for a user-supplied target name."""
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


def _resolve_crash(target_id: str, crash_arg: str) -> tuple[str, str]:
    """Return (absolute input.bin path, crash directory).

    ``crash_arg`` may be a stack-hash directory, a path to input.bin
    inside one, OR an arbitrary file (the minimiser still accepts it
    but writes the output next to itself rather than into a crash dir).
    """
    cand = os.path.abspath(crash_arg)
    # Case A — explicit input.bin
    if os.path.isfile(cand):
        crash_dir = os.path.dirname(cand) if os.path.basename(cand) == 'input.bin' \
                    else os.path.dirname(cand)
        return cand, crash_dir
    # Case B — crash directory
    if os.path.isdir(cand):
        inp = os.path.join(cand, 'input.bin')
        if not os.path.isfile(inp):
            sys.exit(f'crash dir {cand} has no input.bin')
        return inp, cand
    # Case C — bare 16-hex sha (under the target's crash dir)
    if SHA_RE.match(crash_arg.lower()):
        guess = os.path.join(CRASHES_DIR, *target_id.split('/'), crash_arg.lower())
        if os.path.isdir(guess):
            inp = os.path.join(guess, 'input.bin')
            if os.path.isfile(inp):
                return inp, guess
    sys.exit(f'cannot resolve crash {crash_arg!r}: not a file, directory, or sha under '
             f'dist/fuzz-crashes/{target_id}/')


# ── Reduction strategies ────────────────────────────────────────────────────
def _candidates_halve_from_end(buf: bytes):
    """Try keeping prefixes of length n//2, n//4, … down to 1."""
    n = len(buf)
    cut = n // 2
    while cut >= 1:
        yield buf[:cut]
        cut //= 2


def _candidates_halve_from_start(buf: bytes):
    """Try keeping suffixes."""
    n = len(buf)
    cut = n // 2
    while cut >= 1:
        yield buf[cut:]
        cut //= 2


def _candidates_drop_window(buf: bytes, window: int):
    """Slide a window over the buffer, yielding versions with that window
    removed.  Stride = window (non-overlapping passes; aggressive)."""
    n = len(buf)
    if window >= n:
        return
    i = 0
    while i + window <= n:
        yield buf[:i] + buf[i + window:]
        i += window


def _candidates_replace_byte(buf: bytes, fill: int):
    """Try replacing each byte with a constant (0x20 default — printable
    space, almost never load-bearing for a parser bug)."""
    n = len(buf)
    for i in range(n):
        if buf[i] != fill:
            yield bytes(buf[:i]) + bytes([fill]) + bytes(buf[i + 1:])


# ── Main minimisation loop ──────────────────────────────────────────────────
def _minimise(target_path: str, target_id: str, input_path: str,
              target_hash: str | None, time_budget_s: float | None,
              quiet: bool) -> tuple[bytes, str, dict]:
    """Iteratively shrink ``input_path`` until no strategy makes progress.

    Returns ``(best_bytes, locked_hash, stats)`` where ``locked_hash`` is
    the hash the minimiser is preserving (computed from the original
    crash if not supplied).
    """
    with open(input_path, 'rb') as f:
        original = f.read()
    if not original:
        sys.exit(f'{input_path}: empty file — nothing to minimise')

    deadline = (time.monotonic() + time_budget_s) if time_budget_s else None

    # ── Probe original ──────────────────────────────────────────────────
    if not quiet:
        print(f'fuzz-minimise: target={target_id} input={input_path} '
              f'size={len(original)} bytes')
    probe = _run_once(target_path, input_path, target_hash, timeout_s=30.0)
    if probe.get('_aborted'):
        sys.exit('fuzz-minimise: aborted (run-once harness failure)')
    if not probe['threw']:
        sys.exit(f'fuzz-minimise: input does not crash target — clean run in '
                 f'{probe["wallMs"]:.0f} ms')
    locked_hash = (target_hash or probe['stackHash']).lower()
    if probe['stackHash'] != locked_hash:
        sys.exit(f'fuzz-minimise: original input crashes with hash '
                 f'{probe["stackHash"]} but --target-hash {locked_hash} was supplied')
    if not quiet:
        print(f'  original throws  {probe["errName"]}: {probe["errMessage"]!r}')
        print(f'  preserving hash  {locked_hash}')

    best = original
    stats = {
        'original_size': len(original),
        'candidates_tried': 0,
        'candidates_accepted': 0,
        'passes': 0,
        'time_seconds': 0.0,
        'time_budget_exhausted': False,
    }
    t_start = time.monotonic()

    def out_of_time() -> bool:
        if deadline is not None and time.monotonic() >= deadline:
            stats['time_budget_exhausted'] = True
            return True
        return False

    def try_candidate(buf: bytes) -> bool:
        """Verify ``buf`` against the target.  Mutates ``best`` on success."""
        nonlocal best
        stats['candidates_tried'] += 1
        # Tmp file in the same dir as input — keeps fs traffic local.
        tmp = input_path + '.tmp.minimise'
        with open(tmp, 'wb') as f:
            f.write(buf)
        try:
            result = _run_once(target_path, tmp, locked_hash, timeout_s=15.0)
        finally:
            try: os.remove(tmp)
            except OSError: pass
        if result.get('_aborted'):
            return False
        if result.get('ok'):
            best = buf
            stats['candidates_accepted'] += 1
            return True
        return False

    def progress(label: str):
        if quiet:
            return
        elapsed = time.monotonic() - t_start
        print(f'  [{elapsed:6.1f}s] {label:<28} '
              f'best={len(best):>7} bytes  '
              f'tried={stats["candidates_tried"]:>5}  '
              f'accepted={stats["candidates_accepted"]:>4}',
              flush=True)

    # ── Pass loop: keep iterating until a full pass changes nothing ─────
    while True:
        stats['passes'] += 1
        size_at_pass_start = len(best)
        if not quiet:
            print(f'-- pass {stats["passes"]} (start size {size_at_pass_start}) --')

        # 1. Halve from end / start.
        for label, gen in (('halve-from-end',  _candidates_halve_from_end),
                           ('halve-from-start', _candidates_halve_from_start)):
            if out_of_time(): break
            for cand in gen(best):
                if out_of_time(): break
                if len(cand) >= len(best):
                    continue
                if try_candidate(cand):
                    progress(label)
                    # Restart this strategy from the new (smaller) base.
                    break
        if out_of_time(): break

        # 2. Slide a window of decreasing size.
        for window in (16, 8, 4, 2, 1):
            if out_of_time(): break
            if window >= len(best):
                continue
            improved = True
            while improved and not out_of_time():
                improved = False
                for cand in _candidates_drop_window(best, window):
                    if out_of_time(): break
                    if try_candidate(cand):
                        improved = True
                        progress(f'drop-window-{window}')
                        break
            if out_of_time(): break

        # 3. Byte-replace pass — content-normalise after length is locked.
        if not out_of_time():
            improved = True
            while improved and not out_of_time():
                improved = False
                for cand in _candidates_replace_byte(best, 0x20):
                    if out_of_time(): break
                    if try_candidate(cand):
                        improved = True
                        progress('replace-byte-0x20')
                        break

        # Pass converged?
        if len(best) == size_at_pass_start or out_of_time():
            break

    stats['time_seconds'] = round(time.monotonic() - t_start, 2)
    return best, locked_hash, stats


# ── CLI ─────────────────────────────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(
        prog='fuzz_minimise.py',
        description='Shrink a crashing fuzz input while preserving its stack hash.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('target', help='target identifier (e.g. text/ioc-extract)')
    parser.add_argument('crash', help='crash directory, input.bin path, or 16-hex sha')
    parser.add_argument('--time', type=float, default=None,
                        help='wall-clock budget in seconds')
    parser.add_argument('--target-hash', type=str, default=None,
                        help='override the stack hash to preserve')
    parser.add_argument('--output', type=str, default=None,
                        help='write minimised bytes here (default: <crash-dir>/minimised.bin)')
    parser.add_argument('--quiet', action='store_true',
                        help='emit only the final one-line summary')
    args = parser.parse_args()

    if not shutil.which('node'):
        sys.exit('fuzz-minimise: `node` not on PATH')
    if not os.path.isfile(RUN_ONCE_JS):
        sys.exit(f'fuzz-minimise: run-once.js missing at {RUN_ONCE_JS}')

    target_path, target_id = _resolve_target(args.target)
    input_path, crash_dir = _resolve_crash(target_id, args.crash)

    target_hash = args.target_hash.lower() if args.target_hash else None
    if target_hash and not SHA_RE.match(target_hash):
        sys.exit(f'--target-hash {target_hash!r}: expected 16 hex chars')

    best, locked_hash, stats = _minimise(
        target_path=target_path,
        target_id=target_id,
        input_path=input_path,
        target_hash=target_hash,
        time_budget_s=args.time,
        quiet=args.quiet,
    )

    out_path = args.output or os.path.join(crash_dir, 'minimised.bin')
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(best)

    rel_out = os.path.relpath(out_path, BASE)
    reduction = 100.0 * (1.0 - len(best) / stats['original_size']) \
                if stats['original_size'] else 0.0
    print(
        f'OK    {target_id} → {rel_out}  '
        f'{stats["original_size"]} → {len(best)} bytes ({reduction:.1f}% smaller)  '
        f'hash={locked_hash}  '
        f'tried={stats["candidates_tried"]}  '
        f'passes={stats["passes"]}  '
        f't={stats["time_seconds"]}s'
        f'{"  [budget-exhausted]" if stats["time_budget_exhausted"] else ""}'
    )
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
