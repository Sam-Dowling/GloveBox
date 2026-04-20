#!/usr/bin/env python3
"""Verify every file in vendor/ matches the SHA-256 pin in VENDORED.md.

Parses the markdown table in VENDORED.md (which is the source of truth for
vendored library hashes, per CONTRIBUTING.md) and compares
the recorded hash against a freshly-computed SHA-256 of the on-disk file.

Exit codes:
  0  every vendored file matches its pin
  1  one or more mismatches, missing files, or unpinned files in vendor/
  2  VENDORED.md could not be parsed

Run directly (`python verify_vendored.py`) or from CI.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
VENDORED_MD = os.path.join(BASE, 'VENDORED.md')
VENDOR_DIR = os.path.join(BASE, 'vendor')


def parse_vendored_md(path: str) -> dict[str, str]:
    """Return {relative_vendor_path: sha256_hex} pulled from the markdown table.

    The table format is:
        | File | Version | Licence | SHA-256 | Upstream |
        |---|---|---|---|---|
        | `vendor/foo.js` | ... | ... | `deadbeef...` | ... |

    Rows without a backticked `vendor/...` path in column 1 are ignored.
    """
    if not os.path.isfile(path):
        print(f"ERROR  {path} not found", file=sys.stderr)
        sys.exit(2)

    pinned: dict[str, str] = {}
    row_re = re.compile(
        r'^\|\s*`(vendor/[^`]+)`\s*\|'      # col 1: `vendor/foo.js`
        r'[^|]*\|'                           # col 2: version
        r'[^|]*\|'                           # col 3: licence
        r'\s*`([0-9a-fA-F]{64})`\s*\|',     # col 4: `<sha256>`
    )

    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            m = row_re.match(line.strip())
            if m:
                rel, sha = m.group(1), m.group(2).lower()
                pinned[rel] = sha

    if not pinned:
        print(f"ERROR  no vendor rows parsed from {path}", file=sys.stderr)
        sys.exit(2)
    return pinned


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    pinned = parse_vendored_md(VENDORED_MD)

    errors: list[str] = []
    ok: list[str] = []

    # 1. Every pinned file exists and matches.
    for rel, expected in pinned.items():
        abs_path = os.path.join(BASE, rel)
        if not os.path.isfile(abs_path):
            errors.append(f"MISSING  {rel}  (pinned in VENDORED.md but not on disk)")
            continue
        actual = sha256_of(abs_path)
        if actual != expected:
            errors.append(
                f"MISMATCH {rel}\n"
                f"           expected {expected}\n"
                f"           actual   {actual}"
            )
        else:
            ok.append(rel)

    # 2. Every file in vendor/ is pinned.
    if os.path.isdir(VENDOR_DIR):
        on_disk = {
            f'vendor/{name}'
            for name in os.listdir(VENDOR_DIR)
            if os.path.isfile(os.path.join(VENDOR_DIR, name))
        }
        unpinned = sorted(on_disk - set(pinned.keys()))
        for rel in unpinned:
            errors.append(
                f"UNPINNED {rel}  (present in vendor/ but no row in VENDORED.md)"
            )

    # Report.
    for rel in ok:
        print(f"OK       {rel}")
    for line in errors:
        print(line, file=sys.stderr)

    if errors:
        print(
            f"\nFAIL  {len(errors)} problem(s); "
            f"{len(ok)} vendored file(s) verified.",
            file=sys.stderr,
        )
        return 1
    print(f"\nOK    {len(ok)} vendored file(s) verified.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
