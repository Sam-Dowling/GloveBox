#!/usr/bin/env python3
"""build_test_mmdb.py — emit a minimal valid MMDB fixture for unit tests.

Used by tests/unit/mmdb-reader.test.js. The output goes to
`tests/fixtures/test-country.mmdb` (committed) so CI can run the parser
unit tests without requiring the 8 MB DB-IP fixture.

Format reference:
  https://maxmind.github.io/MaxMind-DB/

What this builder produces:
  • IPv4-only tree (`ip_version: 4`), 24-bit records (smallest legal
    record_size — 6 bytes per node).
  • Four leaf records mapped to four canonical IPv4 prefixes:
      8.8.8.0/24      → United States   / US
      1.1.1.0/24      → Australia       / AU
      193.0.0.0/24    → Netherlands     / NL
      210.130.0.0/16  → Japan           / JP
    All other addresses fall through to "no record" (record value
    equal to node_count, which the reader treats as a miss).
  • Decoded metadata map with all required fields:
      binary_format_major_version: 2
      binary_format_minor_version: 0
      build_epoch: 1761955200 (2025-11-01 UTC; pinned)
      database_type: 'Loupe-Test-Country'
      ip_version: 4
      languages: ['en']
      node_count: <computed>
      record_size: 24

The output file is byte-deterministic for a given source — the build
script uses `SOURCE_DATE_EPOCH` to pin `build_epoch` if the env var is
set (CI sets this; locally it falls back to a hard-coded value so the
fixture diff stays empty across rebuilds).

Encoding helpers below intentionally cover ONLY the types this fixture
needs: utf-8 strings, uint16, uint32, maps. The reader supports more,
but every additional encoder is more code to audit.

Re-run with:
  python scripts/misc/build_test_mmdb.py

The output is committed to `tests/fixtures/test-country.mmdb`. CI does
NOT regenerate it on every build — the fixture is treated as a static
asset, and a regression in this script would surface as a unit-test
failure (the reader's expected ISO codes wouldn't match).
"""

from __future__ import annotations

import os
import sys


# ── Type-byte constants (MMDB type field, stored in high 3 bits) ──────────
T_POINTER = 1
T_UTF8    = 2
T_UINT16  = 5
T_UINT32  = 6
T_MAP     = 7
T_ARRAY   = 11


def _control_byte(typ: int, payload_len: int) -> bytes:
    """Encode the control byte + (optional) length-extension bytes.

    Per spec, payload_len < 29 fits in the low 5 bits of the control
    byte; 29..284 uses one extension byte (29 + extra); 285..65820 uses
    two extension bytes; etc. This fixture only ever emits short
    payloads (≤28 bytes), so we keep the length encoding minimal.

    Types 0..7 fit the high-3-bits field directly. Types 8..15 use the
    "extended" form: high 3 bits = 0, and one extra byte after the
    control byte holds (real_type - 7). Both branches are needed
    because this fixture uses MMDB_TYPE_ARRAY (11) for the `languages`
    metadata field.
    """
    if payload_len >= 29:
        raise NotImplementedError(
            'test fixture stays under 29-byte payloads on purpose; '
            'extend if you need longer strings/maps'
        )
    if typ <= 7:
        return bytes([(typ << 5) | payload_len])
    # Extended type: high 3 bits = 0 (MMDB_TYPE_EXTENDED), payload_len
    # in the low 5 bits, then one byte = typ - 7.
    return bytes([payload_len, typ - 7])


def enc_utf8(s: str) -> bytes:
    """UTF-8 string with a 5-bit-length control byte."""
    payload = s.encode('utf-8')
    if len(payload) >= 29:
        raise ValueError(f'string too long for minimal encoder: {s!r}')
    return _control_byte(T_UTF8, len(payload)) + payload


def enc_uint(typ: int, n: int) -> bytes:
    """Big-endian uint with minimal-byte encoding (drop leading zeros)."""
    if n < 0:
        raise ValueError(f'unsigned only, got {n}')
    if n == 0:
        return _control_byte(typ, 0)
    payload = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return _control_byte(typ, len(payload)) + payload


def enc_uint16(n: int) -> bytes:
    return enc_uint(T_UINT16, n)


def enc_uint32(n: int) -> bytes:
    return enc_uint(T_UINT32, n)


def enc_map(items: list[tuple[str, bytes]]) -> bytes:
    """A map is `<control-byte: type=7, payload_len = entry-count>`
    followed by `entry-count` (key, value) pairs. Keys are utf-8."""
    if len(items) >= 29:
        raise NotImplementedError('large maps not needed in test fixture')
    out = bytearray(_control_byte(T_MAP, len(items)))
    for key, val_bytes in items:
        out += enc_utf8(key)
        out += val_bytes
    return bytes(out)


def enc_array(elements: list[bytes]) -> bytes:
    if len(elements) >= 29:
        raise NotImplementedError('large arrays not needed in test fixture')
    out = bytearray(_control_byte(T_ARRAY, len(elements)))
    for el in elements:
        out += el
    return bytes(out)


# ── Record builder for one leaf "country" entry ───────────────────────────
def country_record(country_name: str, iso2: str) -> bytes:
    """Produce the GeoLite2-shaped data record for a country-only entry.

    Shape:
      { country: { iso_code: <ISO2>, names: { en: <Name> } } }
    """
    names_map = enc_map([('en', enc_utf8(country_name))])
    country_map = enc_map([
        ('iso_code', enc_utf8(iso2)),
        ('names', names_map),
    ])
    return enc_map([('country', country_map)])


# ── 24-bit search-tree node encoder ───────────────────────────────────────
def encode_node_24(left: int, right: int) -> bytes:
    """24-bit record: 6 bytes per node (3 bytes left, 3 bytes right)."""
    if left < 0 or left > 0xFFFFFF or right < 0 or right > 0xFFFFFF:
        raise ValueError('24-bit overflow')
    return left.to_bytes(3, 'big') + right.to_bytes(3, 'big')


# ── Tree construction ─────────────────────────────────────────────────────
# We build a minimal IPv4 prefix-trie. Each node has left (0-bit branch)
# and right (1-bit branch). For an internal node, the branches point at
# child node indices (< node_count). For a leaf, the branch points at
# `node_count + dataOffsetWithin DataSection + 16` per the MMDB spec
# convention: "values >= node_count refer to data records; subtract
# node_count + 16 to get the byte offset into the data section after
# the 16-byte zero separator". (The reader walks tree until value
# >= node_count, then computes data_offset = value - node_count - 16
# relative to data section start. See `_findIpv4` in mmdb-reader.js.)
#
# Special "no record" sentinel: any branch pointing at `node_count`
# itself is treated as a miss by the reader.


def build_tree(prefixes: list[tuple[int, int, int]]) -> tuple[bytes, dict[int, int], int]:
    """Build a 32-level binary trie covering the supplied prefixes.

    `prefixes` is a list of `(start_ip_uint32, prefix_len, data_record_index)`.
    `data_record_index` is the position of the leaf's data record within
    the DATA-RECORDS-CONCATENATED-IN-ORDER sequence; we resolve those
    to byte offsets later once we know the data section's layout.

    Returns:
      tree_bytes              — 6 * node_count bytes
      data_idx_to_node_value  — map from data_record_index to the leaf
                                value that should be stored at the
                                appropriate tree slot. Computed once
                                we know node_count + each record's
                                offset within the data section.
      node_count              — number of nodes in the tree
    """
    # Each internal node lives at an index. Index 0 is the root.
    # We allocate as we descend each prefix, splitting nodes that are
    # currently "no record" (left=right=0 placeholder, fixed up
    # later).
    NO_RECORD_PLACEHOLDER = -1  # resolved to node_count post-build
    LEAF_PLACEHOLDER = -2       # marks "this is a leaf for this prefix"

    nodes: list[list[int]] = [[NO_RECORD_PLACEHOLDER, NO_RECORD_PLACEHOLDER]]

    # Track which (node_idx, branch) is a leaf for which data record so
    # we can fix up after we know node_count.
    leaf_assignments: list[tuple[int, int, int]] = []  # (node_idx, branch, data_record_idx)

    for start_ip, prefix_len, data_idx in prefixes:
        if prefix_len < 1 or prefix_len > 32:
            raise ValueError(f'bad prefix_len: {prefix_len}')
        cur = 0
        for depth in range(prefix_len - 1):
            bit = (start_ip >> (31 - depth)) & 1
            child = nodes[cur][bit]
            if child < 0:
                # Allocate a fresh internal node here; the placeholder
                # gets replaced with the new node's index.
                new_idx = len(nodes)
                nodes.append([NO_RECORD_PLACEHOLDER, NO_RECORD_PLACEHOLDER])
                nodes[cur][bit] = new_idx
                cur = new_idx
            else:
                cur = child
        # Final bit: assign a leaf
        leaf_bit = (start_ip >> (31 - (prefix_len - 1))) & 1
        leaf_assignments.append((cur, leaf_bit, data_idx))
        nodes[cur][leaf_bit] = LEAF_PLACEHOLDER

    return nodes, leaf_assignments


def main() -> int:
    out_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'tests', 'fixtures',
    )
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'test-country.mmdb')

    # ── Define the four prefix → country mappings ─────────────────────
    # Each tuple: (start_ip_uint32, prefix_len, country_name, iso2)
    #
    # 8.8.8.0/24    = 0x08080800 / 24
    # 1.1.1.0/24    = 0x01010100 / 24
    # 193.0.0.0/24  = 0xC1000000 / 24
    # 210.130.0.0/16 = 0xD2820000 / 16
    mappings = [
        (0x08080800, 24, 'United States', 'US'),
        (0x01010100, 24, 'Australia', 'AU'),
        (0xC1000000, 24, 'Netherlands', 'NL'),
        (0xD2820000, 16, 'Japan', 'JP'),
    ]

    # ── Encode each data record once ─────────────────────────────────
    # We'll concatenate them with their offsets recorded so the tree
    # leaves can point at them.
    record_blobs: list[bytes] = []
    record_offsets: list[int] = []
    cursor = 0
    for _start, _plen, country, iso in mappings:
        record_blobs.append(country_record(country, iso))
        record_offsets.append(cursor)
        cursor += len(record_blobs[-1])

    # ── Build the tree ───────────────────────────────────────────────
    prefix_input = [(s, p, i) for i, (s, p, _c, _iso) in enumerate(mappings)]
    nodes, leaf_assignments = build_tree(prefix_input)

    node_count = len(nodes)
    # Leaf "value" stored in a tree branch when that branch resolves to
    # a data record: value = node_count + 16 + data_byte_offset. The
    # reader's `_findIpv4` adds the 16 bytes back when computing the
    # data section offset; reading mmdb-reader.js::_findIpv4: data_off =
    # rec - node_count - 16 + this._dataStart. So we encode
    #   rec = data_byte_offset + node_count + 16.
    NO_RECORD_VALUE = node_count  # reader treats `>= node_count` with
                                  # value == node_count as miss only when
                                  # data offset resolves to before data
                                  # start. To guarantee miss, we point
                                  # at the safe "no record" sentinel: the
                                  # value `node_count` itself, which by
                                  # MMDB convention means "no value".

    # Resolve placeholders → concrete branch values.
    LEAF_PLACEHOLDER = -2
    NO_RECORD_PLACEHOLDER = -1

    # First pass: leaf_assignments tells us which (node, branch) pairs
    # are leaves for which data record.
    leaf_table: dict[tuple[int, int], int] = {}  # (node_idx, branch) → record_idx
    for node_idx, branch, data_idx in leaf_assignments:
        leaf_table[(node_idx, branch)] = data_idx

    final_nodes: list[tuple[int, int]] = []
    for idx, (left, right) in enumerate(nodes):
        new_left = left
        new_right = right
        if new_left == LEAF_PLACEHOLDER:
            data_idx = leaf_table[(idx, 0)]
            new_left = node_count + 16 + record_offsets[data_idx]
        elif new_left == NO_RECORD_PLACEHOLDER:
            new_left = NO_RECORD_VALUE
        if new_right == LEAF_PLACEHOLDER:
            data_idx = leaf_table[(idx, 1)]
            new_right = node_count + 16 + record_offsets[data_idx]
        elif new_right == NO_RECORD_PLACEHOLDER:
            new_right = NO_RECORD_VALUE
        final_nodes.append((new_left, new_right))

    # ── Encode tree bytes ────────────────────────────────────────────
    tree_bytes = bytearray()
    for left, right in final_nodes:
        tree_bytes += encode_node_24(left, right)

    # ── Encode data section ──────────────────────────────────────────
    data_section = bytearray()
    for blob in record_blobs:
        data_section += blob

    # ── Encode metadata block (decoded value: a map) ────────────────
    SOURCE_DATE_EPOCH = int(os.environ.get('SOURCE_DATE_EPOCH', '1761955200'))
    metadata_map = enc_map([
        ('binary_format_major_version', enc_uint16(2)),
        ('binary_format_minor_version', enc_uint16(0)),
        ('build_epoch', enc_uint32(SOURCE_DATE_EPOCH)),
        ('database_type', enc_utf8('Loupe-Test-Country')),
        ('ip_version', enc_uint16(4)),
        ('languages', enc_array([enc_utf8('en')])),
        ('node_count', enc_uint32(node_count)),
        ('record_size', enc_uint16(24)),
    ])

    # ── Assemble ─────────────────────────────────────────────────────
    metadata_marker = bytes([
        0xAB, 0xCD, 0xEF,
        0x4D, 0x61, 0x78, 0x4D, 0x69, 0x6E, 0x64, 0x2E, 0x63, 0x6F, 0x6D,
    ])
    payload = bytes(tree_bytes) + b'\x00' * 16 + bytes(data_section) + metadata_marker + metadata_map

    with open(out_path, 'wb') as f:
        f.write(payload)

    print(f'OK  Wrote {out_path}  ({len(payload):,} bytes, '
          f'{node_count} nodes, {len(mappings)} prefixes)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
