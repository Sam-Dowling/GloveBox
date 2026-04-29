#!/usr/bin/env python3
"""update_geoip_vendored_row.py — refresh the geoip row in VENDORED.md.

Used by `.github/workflows/refresh-geoip.yml` after running
`scripts/fetch_geoip.py`. Updates two fields in the geoip row:

  • The "Snapshot YYYY-MM-DD" date in the second column. Sourced from
    today's UTC date when the workflow runs (the RIR files publish
    daily, and the workflow runs monthly; "today" is close enough to
    the actual file mtime that we don't need a separate metadata
    parse).
  • The SHA-256 in the fourth column. Computed fresh from
    `vendor/geoip-country-ipv4.bin` on disk.

Idempotent: running this twice on the same input produces the same
output. Determinism: matches the rest of the build (no os.walk, no
randomness).

Usage (no arguments):
    python scripts/update_geoip_vendored_row.py

Exit codes:
    0  row updated, OR row already matches the current binary (no diff)
    1  binary missing / VENDORED.md missing / row not found / ambiguous
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import os
import re
import sys


BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDOR_BIN = os.path.join(BASE, 'vendor', 'geoip-country-ipv4.bin')
VENDORED_MD = os.path.join(BASE, 'VENDORED.md')

# Match the geoip row uniquely. The leading backtick-quoted path is
# the anchor; everything from there to the end of the line is replaced
# with a freshly-built row matching the existing column structure.
ROW_PREFIX = '| `vendor/geoip-country-ipv4.bin` |'


def _die(msg: str, code: int = 1) -> None:
    print(f'ERROR  {msg}', file=sys.stderr)
    sys.exit(code)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if not os.path.isfile(VENDOR_BIN):
        _die(f'binary not found: {VENDOR_BIN}')
    if not os.path.isfile(VENDORED_MD):
        _die(f'VENDORED.md not found: {VENDORED_MD}')

    new_sha = _sha256(VENDOR_BIN)
    # UTC date — match the format used in the existing row.
    today = _dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%d')

    with open(VENDORED_MD, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    matches = [i for i, line in enumerate(lines) if line.startswith(ROW_PREFIX)]
    if len(matches) == 0:
        _die(f'geoip row not found in VENDORED.md (looking for: {ROW_PREFIX!r})')
    if len(matches) > 1:
        _die(f'multiple geoip rows found in VENDORED.md: lines {matches}')

    row_idx = matches[0]
    old_row = lines[row_idx]

    # Build the replacement row. We preserve the rest of the row
    # structure by parsing the existing pipe-delimited columns and
    # only updating the date + SHA fields. This way the License /
    # Notes columns are never accidentally clobbered if the cron
    # runs against a row that's been edited for other reasons.
    cols = [c.strip() for c in old_row.strip().strip('|').split('|')]
    if len(cols) < 5:
        _die(f'unexpected column count in geoip row: {len(cols)} (expected 5)')

    # Column 2: replace "Snapshot YYYY-MM-DD" / "RIR ... YYYY-MM-DD"
    # date string. Fallback: append a fresh "Snapshot YYYY-MM-DD" if
    # no date pattern is found.
    date_re = re.compile(r'\b(\d{4}-\d{2}-\d{2})\b')   # safe: bounded literal
    if date_re.search(cols[1]):
        cols[1] = date_re.sub(today, cols[1])
    else:
        cols[1] = f'{cols[1]} {today}'.strip()

    # Column 4: SHA-256 wrapped in backticks. We expect exactly one
    # 64-hex-char run; replace it.
    sha_re = re.compile(r'`[0-9a-fA-F]{64}`')          # safe: bounded literal
    if not sha_re.search(cols[3]):
        _die(f'no SHA-256 found in column 4 of geoip row: {cols[3]!r}')
    cols[3] = sha_re.sub(f'`{new_sha}`', cols[3])

    new_row = '| ' + ' | '.join(cols) + ' |\n'

    if new_row == old_row:
        print(f'OK  no changes needed (date={today}, sha={new_sha[:16]}…)', flush=True)
        return 0

    lines[row_idx] = new_row
    with open(VENDORED_MD, 'w', encoding='utf-8') as f:
        f.writelines(lines)

    print(f'OK  updated VENDORED.md geoip row', flush=True)
    print(f'    date:   {today}', flush=True)
    print(f'    sha256: {new_sha}', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
