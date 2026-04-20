#!/usr/bin/env python3
"""scripts/generate_sbom.py — emit a CycloneDX 1.5 SBOM for Loupe.

Loupe has no package manager — every third-party library lives under
``vendor/`` and is pinned by SHA-256 in ``VENDORED.md``. That table is the
single source of truth for the project's supply-chain surface, so this
script parses it and emits a spec-compliant CycloneDX 1.5 JSON document
describing:

  * the Loupe application itself (metadata.component, type=application)
      — with a SHA-256 hash of the built docs/index.html when present
  * every vendored library as a components[] entry (type=library) with
      version, licence, SHA-256, and VCS external reference

Usage
-----
    python scripts/generate_sbom.py                # writes dist/loupe.cdx.json
    python scripts/generate_sbom.py --out FILE     # custom output path
    python scripts/generate_sbom.py --stdout       # print to stdout

Exit codes
----------
    0  SBOM written (or printed) successfully
    1  VENDORED.md could not be parsed, or a pinned vendor file is missing
    2  invalid CLI arguments

Spec: https://cyclonedx.org/docs/1.5/json/
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

# scripts/generate_sbom.py → repo root is one level up.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VENDORED_MD = os.path.join(BASE, 'VENDORED.md')
BUILT_BUNDLE = os.path.join(BASE, 'docs', 'index.html')

# Canonical bom-ref prefix for this project. Stable values let downstream
# tooling (dependency-track, trivy, etc.) diff two SBOMs across releases
# without treating every row as a new component.
BOM_REF_PREFIX = 'pkg:loupe/vendor/'
APP_BOM_REF = 'pkg:loupe/app'

# Parse the full VENDORED.md row: file, version, licence, sha256, upstream.
# Anchored on the vendor/ backtick in column 1 and the 64-hex SHA in col 4
# so free-form prose above and below the table is ignored.
_ROW_RE = re.compile(
    r'^\|\s*`(vendor/[^`]+)`\s*\|'     # 1: `vendor/foo.js`
    r'\s*([^|]+?)\s*\|'                # 2: version cell
    r'\s*([^|]+?)\s*\|'                # 3: licence cell
    r'\s*`([0-9a-fA-F]{64})`\s*\|'     # 4: `<sha256>`
    r'\s*(.+?)\s*\|'                   # 5: upstream cell
)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _strip_md(text: str) -> str:
    """Drop bold/italic markers and backticks so cells read cleanly in JSON."""
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'\*(.+?)\*', r'\1', text)
    text = text.replace('`', '')
    return text.strip()


def _extract_upstream_url(cell: str) -> str:
    """Return the first bare or bracketed URL in a VENDORED.md upstream cell."""
    m = re.search(r'https?://\S+', cell)
    if not m:
        return ''
    url = m.group(0).rstrip('.,;)]')
    return url


def _purl_from_github(upstream: str, version: str) -> str:
    """Build a pkg:github/<owner>/<repo>@<ver> purl if we can, else ''.

    Loupe has no registry coordinates — most upstreams are GitHub repos and
    pkg:github is the closest pURL type that exists. The version component
    is the raw VENDORED.md string (e.g. 'v7.1.3') so it round-trips.
    """
    m = re.search(r'github\.com/([^/\s]+)/([^/\s#?]+)', upstream)
    if not m:
        return ''
    owner, repo = m.group(1), m.group(2)
    repo = repo.removesuffix('.git')
    ver = version.strip() or 'unknown'
    return f'pkg:github/{owner}/{repo}@{ver}'


def _licenses_field(cell: str) -> list[dict]:
    """CycloneDX licenses[] entry for a vendor-cell licence string.

    Multiple licences separated by ``or`` / ``/`` / ``,`` become multiple
    entries. We emit ``license.id`` when the token looks like a recognised
    SPDX short-id (uppercase letters, digits, dots, dashes) and fall back
    to ``license.name`` for anything else. We do not attempt to validate
    against the SPDX list — getting that wrong is worse than being
    permissive.
    """
    raw = _strip_md(cell)
    # Split on "or" (dual licence) and commas. Keep slashes as delimiters too.
    parts = re.split(r'\s+or\s+|,|/', raw)
    out = []
    for p in parts:
        token = p.strip()
        if not token:
            continue
        if re.match(r'^[A-Za-z0-9.\-]+$', token):
            out.append({'license': {'id': token}})
        else:
            out.append({'license': {'name': token}})
    return out or [{'license': {'name': raw}}] if raw else []


def parse_vendored() -> list[dict]:
    """Return a list of dicts — one per vendor row in VENDORED.md.

    Each dict has keys: path, name, version, licence_cell, sha256, upstream.
    """
    if not os.path.isfile(VENDORED_MD):
        print(f"ERROR  {VENDORED_MD} not found", file=sys.stderr)
        sys.exit(1)

    rows = []
    with open(VENDORED_MD, 'r', encoding='utf-8') as f:
        for line in f:
            m = _ROW_RE.match(line.rstrip('\n'))
            if not m:
                continue
            path, version_cell, licence_cell, sha, upstream_cell = m.groups()
            # Cell may read e.g. "exifr **v7.1.3**" — collapse markdown to
            # text and pull the version-ish token. Preserve the bolded
            # value if present, otherwise take the whole cell.
            ver_m = re.search(r'\*\*([^*]+)\*\*', version_cell)
            version = _strip_md(ver_m.group(1) if ver_m else version_cell)
            name = os.path.basename(path)  # vendor/foo.min.js → foo.min.js
            rows.append({
                'path': path,
                'name': name,
                'version': version,
                'licence_cell': licence_cell,
                'sha256': sha.lower(),
                'upstream': _extract_upstream_url(upstream_cell),
            })

    if not rows:
        print(f"ERROR  no vendor rows parsed from {VENDORED_MD}",
              file=sys.stderr)
        sys.exit(1)
    return rows


def build_sbom(rows: list[dict], app_version: str) -> dict:
    """Assemble the full CycloneDX 1.5 JSON document."""
    # Serial number — CycloneDX requires a urn:uuid:. We use a deterministic
    # value derived from the app version + a SHA-256 of the combined vendor
    # pin list so the SBOM is reproducible (same inputs → same serial).
    serial_seed = '|'.join(
        f"{r['path']}:{r['sha256']}" for r in sorted(rows, key=lambda r: r['path'])
    ) + f'|{app_version}'
    serial_digest = hashlib.sha256(serial_seed.encode('utf-8')).hexdigest()
    # Format as urn:uuid: with hyphens in the canonical positions.
    uuid_like = (
        f'{serial_digest[0:8]}-{serial_digest[8:12]}-{serial_digest[12:16]}-'
        f'{serial_digest[16:20]}-{serial_digest[20:32]}'
    )
    serial_number = f'urn:uuid:{uuid_like}'

    # Timestamp — honour SOURCE_DATE_EPOCH for reproducible-build parity
    # with scripts/build.py. Default to "now" for ad-hoc local runs.
    epoch = os.environ.get('SOURCE_DATE_EPOCH')
    if epoch:
        ts = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    else:
        ts = datetime.now(tz=timezone.utc)
    timestamp = ts.strftime('%Y-%m-%dT%H:%M:%SZ')

    # Application component — hash docs/index.html when it exists. In CI
    # the reproducibility job and the release job both build before calling
    # us, so the file will be present. Local runs without a prior build
    # just omit the hash rather than fail.
    app_component: dict = {
        'type': 'application',
        'bom-ref': APP_BOM_REF,
        'name': 'loupe',
        'version': app_version,
        'description': (
            '100% offline single-file HTML security analyser for suspicious '
            'files. No server, no uploads, no tracking.'
        ),
        'licenses': [{'license': {'id': 'MIT'}}],
        'externalReferences': [
            {'type': 'vcs', 'url': 'https://github.com/Loupe-tools/Loupe'},
            {'type': 'website', 'url': 'https://github.com/Loupe-tools/Loupe'},
        ],
    }
    if os.path.isfile(BUILT_BUNDLE):
        app_component['hashes'] = [
            {'alg': 'SHA-256', 'content': _sha256(BUILT_BUNDLE)}
        ]

    # Vendor library components + dependency edges.
    components: list[dict] = []
    dep_refs: list[str] = []
    for r in sorted(rows, key=lambda r: r['path']):
        bom_ref = BOM_REF_PREFIX + r['name']
        dep_refs.append(bom_ref)
        entry: dict = {
            'type': 'library',
            'bom-ref': bom_ref,
            'name': r['name'],
            'version': r['version'],
            'hashes': [{'alg': 'SHA-256', 'content': r['sha256']}],
            'licenses': _licenses_field(r['licence_cell']),
        }
        purl = _purl_from_github(r['upstream'], r['version'])
        if purl:
            entry['purl'] = purl
        if r['upstream']:
            entry['externalReferences'] = [
                {'type': 'vcs', 'url': r['upstream']},
                {'type': 'distribution', 'url': r['upstream']},
            ]
        components.append(entry)

    return {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.5',
        'serialNumber': serial_number,
        'version': 1,
        'metadata': {
            'timestamp': timestamp,
            'tools': [
                {
                    'vendor': 'Loupe',
                    'name': 'generate_sbom.py',
                    'version': app_version,
                }
            ],
            'component': app_component,
        },
        'components': components,
        'dependencies': [
            {'ref': APP_BOM_REF, 'dependsOn': dep_refs},
        ],
    }


def _extract_app_version() -> str:
    """Best-effort read of LOUPE_VERSION from docs/index.html, else 'unversioned'.

    LOUPE_VERSION sits in the mid-file app JS (after vendored libraries,
    before the embedded YARA rules), not at the tail — so we scan the
    whole file. Reading ~6 MiB of bytes is cheap and keeps the lookup
    robust against any future reshuffle of the concatenation order.
    """
    if not os.path.isfile(BUILT_BUNDLE):
        return 'unversioned'
    try:
        with open(BUILT_BUNDLE, 'rb') as f:
            data = f.read()
        m = re.search(rb"LOUPE_VERSION\s*=\s*'([^']+)'", data)
        if m:
            return m.group(1).decode('utf-8', errors='replace')
    except OSError:
        pass
    return 'unversioned'



def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        '--out', default=os.path.join(BASE, 'dist', 'loupe.cdx.json'),
        help='Output path (default: dist/loupe.cdx.json in the repo root).',
    )
    ap.add_argument(
        '--stdout', action='store_true',
        help='Write to stdout instead of --out.',
    )
    args = ap.parse_args()

    rows = parse_vendored()
    app_version = _extract_app_version()
    sbom = build_sbom(rows, app_version)
    payload = json.dumps(sbom, indent=2, sort_keys=False) + '\n'

    if args.stdout:
        sys.stdout.write(payload)
        return 0

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or '.', exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as f:
        f.write(payload)
    size = os.path.getsize(args.out)
    print(f"OK  Wrote {args.out}  ({size:,} bytes, "
          f"{len(rows)} vendored component(s), app version {app_version})")
    return 0


if __name__ == '__main__':
    sys.exit(main())
