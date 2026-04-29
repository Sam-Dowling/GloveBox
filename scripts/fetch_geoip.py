#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fetch and compile bundled IPv4 country data for Loupe.

This is a maintainer / scheduled-CI helper. It is NOT run by the regular
build (`scripts/build.py`). Instead, the regular build reads the
already-vendored binary file produced by this script.

Data sources (all public domain — see the NRO statistics-exchange README
at https://www.nro.net/wp-content/uploads/nro-extended-stats-readme5.txt):

  - https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest
  - https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest
  - https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest
  - https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest
  - https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest

The five Regional Internet Registries publish daily delegation files in a
shared pipe-separated format. We download them, keep IPv4 records that
were allocated or assigned, coalesce adjacent same-country ranges, overlay
the standard reserved IPv4 blocks, and emit a tiny binary file
`vendor/geoip-country-ipv4.bin` that the runtime decodes for IP-to-country
lookups in the Timeline view.

After running this script, paste the printed SHA-256 into the matching
row of VENDORED.md and rebuild via `python make.py`.
"""

from __future__ import annotations

import datetime
import hashlib
import io
import os
import struct
import sys
import urllib.request
# Constants for the Loupe bundled IPv4-country compiler.
# Pure data: source URLs, output paths, format magic, and a static
# ISO-3166 alpha-2 -> English name table.

# scripts/<this>.py -> repo root is one level up.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_REL = 'vendor/geoip-country-ipv4.bin'
OUTPUT_ABS = os.path.join(BASE_DIR, OUTPUT_REL)

# Five RIR delegated-stats sources. Each is a plain text file, pipe-
# separated, with a header section and per-record lines. We treat them
# as authoritative and merge into a single global view.
RIR_SOURCES = [
    ('arin',     'https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest'),
    ('ripencc',  'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest'),
    ('apnic',    'https://ftp.apnic.net/pub/stats/apnic/delegated-apnic-latest'),
    ('afrinic',  'https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest'),
    ('lacnic',   'https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest'),
]

# Polite user agent so the RIR access logs reflect what we are.
USER_AGENT = 'loupe-geoip-fetch/1.0 (+https://github.com/Loupe-tools/Loupe)'

# Output binary header: 4-byte ASCII magic + 2-byte format version.
FORMAT_MAGIC = b'LGEO'
FORMAT_VERSION = 1

# Sentinel ISO code used for IANA reserved / private / loopback /
# multicast / link-local space, so an analyst sees "Reserved" rather
# than the surrounding allocation's country name leaking in.
RESERVED_ISO = '--'
RESERVED_NAME = 'Reserved'
# ISO-3166 alpha-2 to English short name lookup table, part 1 of 4.
# This is published reference data from the ISO 3166 Maintenance Agency,
# considered factual and uncopyrightable. Used to render bundled country
# names when the data feed only carries the alpha-2 code.

ISO_NAMES_PART_1 = {
    'AD': 'Andorra',
    'AE': 'United Arab Emirates',
    'AF': 'Afghanistan',
    'AG': 'Antigua and Barbuda',
    'AI': 'Anguilla',
    'AL': 'Albania',
    'AM': 'Armenia',
    'AO': 'Angola',
    'AQ': 'Antarctica',
    'AR': 'Argentina',
    'AS': 'American Samoa',
    'AT': 'Austria',
    'AU': 'Australia',
    'AW': 'Aruba',
    'AX': 'Aland Islands',
    'AZ': 'Azerbaijan',
    'BA': 'Bosnia and Herzegovina',
    'BB': 'Barbados',
    'BD': 'Bangladesh',
    'BE': 'Belgium',
    'BF': 'Burkina Faso',
    'BG': 'Bulgaria',
    'BH': 'Bahrain',
    'BI': 'Burundi',
    'BJ': 'Benin',
    'BL': 'Saint Barthelemy',
    'BM': 'Bermuda',
    'BN': 'Brunei Darussalam',
    'BO': 'Bolivia',
    'BQ': 'Bonaire, Sint Eustatius and Saba',
    'BR': 'Brazil',
    'BS': 'Bahamas',
    'BT': 'Bhutan',
    'BV': 'Bouvet Island',
    'BW': 'Botswana',
    'BY': 'Belarus',
    'BZ': 'Belize',
    'CA': 'Canada',
    'CC': 'Cocos (Keeling) Islands',
    'CD': 'Congo (Democratic Republic of the)',
    'CF': 'Central African Republic',
    'CG': 'Congo',
    'CH': 'Switzerland',
    'CI': "Cote d'Ivoire",
    'CK': 'Cook Islands',
    'CL': 'Chile',
    'CM': 'Cameroon',
    'CN': 'China',
    'CO': 'Colombia',
    'CR': 'Costa Rica',
    'CU': 'Cuba',
    'CV': 'Cabo Verde',
    'CW': 'Curacao',
    'CX': 'Christmas Island',
    'CY': 'Cyprus',
    'CZ': 'Czechia',
    'DE': 'Germany',
    'DJ': 'Djibouti',
    'DK': 'Denmark',
    'DM': 'Dominica',
    'DO': 'Dominican Republic',
    'DZ': 'Algeria',
    'EC': 'Ecuador',
    'EE': 'Estonia',
    'EG': 'Egypt',
    'EH': 'Western Sahara',
    'ER': 'Eritrea',
}
# ISO-3166 alpha-2 to English short name lookup table, part 2 of 4.

ISO_NAMES_PART_2 = {
    'ES': 'Spain',
    'ET': 'Ethiopia',
    'FI': 'Finland',
    'FJ': 'Fiji',
    'FK': 'Falkland Islands',
    'FM': 'Micronesia',
    'FO': 'Faroe Islands',
    'FR': 'France',
    'GA': 'Gabon',
    'GB': 'United Kingdom',
    'GD': 'Grenada',
    'GE': 'Georgia',
    'GF': 'French Guiana',
    'GG': 'Guernsey',
    'GH': 'Ghana',
    'GI': 'Gibraltar',
    'GL': 'Greenland',
    'GM': 'Gambia',
    'GN': 'Guinea',
    'GP': 'Guadeloupe',
    'GQ': 'Equatorial Guinea',
    'GR': 'Greece',
    'GS': 'South Georgia and the South Sandwich Islands',
    'GT': 'Guatemala',
    'GU': 'Guam',
    'GW': 'Guinea-Bissau',
    'GY': 'Guyana',
    'HK': 'Hong Kong',
    'HM': 'Heard Island and McDonald Islands',
    'HN': 'Honduras',
    'HR': 'Croatia',
    'HT': 'Haiti',
    'HU': 'Hungary',
    'ID': 'Indonesia',
    'IE': 'Ireland',
    'IL': 'Israel',
    'IM': 'Isle of Man',
    'IN': 'India',
    'IO': 'British Indian Ocean Territory',
    'IQ': 'Iraq',
    'IR': 'Iran',
    'IS': 'Iceland',
    'IT': 'Italy',
    'JE': 'Jersey',
    'JM': 'Jamaica',
    'JO': 'Jordan',
    'JP': 'Japan',
    'KE': 'Kenya',
    'KG': 'Kyrgyzstan',
    'KH': 'Cambodia',
    'KI': 'Kiribati',
    'KM': 'Comoros',
    'KN': 'Saint Kitts and Nevis',
    'KP': 'North Korea',
    'KR': 'South Korea',
    'KW': 'Kuwait',
    'KY': 'Cayman Islands',
    'KZ': 'Kazakhstan',
    'LA': 'Lao PDR',
    'LB': 'Lebanon',
    'LC': 'Saint Lucia',
    'LI': 'Liechtenstein',
    'LK': 'Sri Lanka',
    'LR': 'Liberia',
    'LS': 'Lesotho',
    'LT': 'Lithuania',
    'LU': 'Luxembourg',
    'LV': 'Latvia',
    'LY': 'Libya',
}
# ISO-3166 alpha-2 to English short name lookup table, part 3 of 4.

ISO_NAMES_PART_3 = {
    'MA': 'Morocco',
    'MC': 'Monaco',
    'MD': 'Moldova',
    'ME': 'Montenegro',
    'MF': 'Saint Martin (French part)',
    'MG': 'Madagascar',
    'MH': 'Marshall Islands',
    'MK': 'North Macedonia',
    'ML': 'Mali',
    'MM': 'Myanmar',
    'MN': 'Mongolia',
    'MO': 'Macao',
    'MP': 'Northern Mariana Islands',
    'MQ': 'Martinique',
    'MR': 'Mauritania',
    'MS': 'Montserrat',
    'MT': 'Malta',
    'MU': 'Mauritius',
    'MV': 'Maldives',
    'MW': 'Malawi',
    'MX': 'Mexico',
    'MY': 'Malaysia',
    'MZ': 'Mozambique',
    'NA': 'Namibia',
    'NC': 'New Caledonia',
    'NE': 'Niger',
    'NF': 'Norfolk Island',
    'NG': 'Nigeria',
    'NI': 'Nicaragua',
    'NL': 'Netherlands',
    'NO': 'Norway',
    'NP': 'Nepal',
    'NR': 'Nauru',
    'NU': 'Niue',
    'NZ': 'New Zealand',
    'OM': 'Oman',
    'PA': 'Panama',
    'PE': 'Peru',
    'PF': 'French Polynesia',
    'PG': 'Papua New Guinea',
    'PH': 'Philippines',
    'PK': 'Pakistan',
    'PL': 'Poland',
    'PM': 'Saint Pierre and Miquelon',
    'PN': 'Pitcairn',
    'PR': 'Puerto Rico',
    'PS': 'Palestine',
    'PT': 'Portugal',
    'PW': 'Palau',
    'PY': 'Paraguay',
    'QA': 'Qatar',
    'RE': 'Reunion',
    'RO': 'Romania',
    'RS': 'Serbia',
    'RU': 'Russia',
    'RW': 'Rwanda',
    'SA': 'Saudi Arabia',
    'SB': 'Solomon Islands',
    'SC': 'Seychelles',
    'SD': 'Sudan',
    'SE': 'Sweden',
    'SG': 'Singapore',
    'SH': 'Saint Helena, Ascension and Tristan da Cunha',
    'SI': 'Slovenia',
    'SJ': 'Svalbard and Jan Mayen',
    'SK': 'Slovakia',
    'SL': 'Sierra Leone',
}
# ISO-3166 alpha-2 to English short name lookup table, part 4 of 4.

ISO_NAMES_PART_4 = {
    'SM': 'San Marino',
    'SN': 'Senegal',
    'SO': 'Somalia',
    'SR': 'Suriname',
    'SS': 'South Sudan',
    'ST': 'Sao Tome and Principe',
    'SV': 'El Salvador',
    'SX': 'Sint Maarten (Dutch part)',
    'SY': 'Syria',
    'SZ': 'Eswatini',
    'TC': 'Turks and Caicos Islands',
    'TD': 'Chad',
    'TF': 'French Southern Territories',
    'TG': 'Togo',
    'TH': 'Thailand',
    'TJ': 'Tajikistan',
    'TK': 'Tokelau',
    'TL': 'Timor-Leste',
    'TM': 'Turkmenistan',
    'TN': 'Tunisia',
    'TO': 'Tonga',
    'TR': 'Turkiye',
    'TT': 'Trinidad and Tobago',
    'TV': 'Tuvalu',
    'TW': 'Taiwan',
    'TZ': 'Tanzania',
    'UA': 'Ukraine',
    'UG': 'Uganda',
    'UM': 'United States Minor Outlying Islands',
    'US': 'United States',
    'UY': 'Uruguay',
    'UZ': 'Uzbekistan',
    'VA': 'Holy See',
    'VC': 'Saint Vincent and the Grenadines',
    'VE': 'Venezuela',
    'VG': 'Virgin Islands (British)',
    'VI': 'Virgin Islands (U.S.)',
    'VN': 'Viet Nam',
    'VU': 'Vanuatu',
    'WF': 'Wallis and Futuna',
    'WS': 'Samoa',
    'XK': 'Kosovo',
    'YE': 'Yemen',
    'YT': 'Mayotte',
    'ZA': 'South Africa',
    'ZM': 'Zambia',
    'ZW': 'Zimbabwe',
    # ── Non-ISO codes used by the RIR delegated-stats files ──────────────
    # The five RIRs occasionally use umbrella codes for ranges allocated
    # to multinational / regional entities. These are not ISO-3166
    # countries but appear regularly in the source data. Treat them as
    # informational labels rather than countries.
    'EU': 'European Union',
    'AP': 'Asia/Pacific',
    # Sentinel for IANA reserved space (loopback, private, multicast,
    # link-local, future-use). Filled into ranges that aren't allocated
    # to any RIR so the column reads "Reserved" instead of "" for those
    # IPs.
    '--': 'Reserved',
}

# Combined view used elsewhere in the script.
ISO_NAMES = {
    **ISO_NAMES_PART_1,
    **ISO_NAMES_PART_2,
    **ISO_NAMES_PART_3,
    **ISO_NAMES_PART_4,
}
# IANA-reserved IPv4 blocks (RFC 6890 / RFC 5735 summary). These are
# overlaid on top of the RIR data after coalescing so they always read
# "Reserved" instead of leaking the surrounding allocation's country.
#
# Each entry is (start_ip_string, prefix_length).
RESERVED_BLOCKS = [
    ('0.0.0.0',         8),    # "This network"
    ('10.0.0.0',        8),    # Private (RFC 1918)
    ('100.64.0.0',     10),    # Carrier-grade NAT (RFC 6598)
    ('127.0.0.0',       8),    # Loopback
    ('169.254.0.0',    16),    # Link-local
    ('172.16.0.0',     12),    # Private (RFC 1918)
    ('192.0.0.0',      24),    # IETF protocol assignments
    ('192.0.2.0',      24),    # Documentation (TEST-NET-1)
    ('192.88.99.0',    24),    # Formerly 6to4 anycast
    ('192.168.0.0',    16),    # Private (RFC 1918)
    ('198.18.0.0',     15),    # Benchmarking (RFC 2544)
    ('198.51.100.0',   24),    # Documentation (TEST-NET-2)
    ('203.0.113.0',    24),    # Documentation (TEST-NET-3)
    ('224.0.0.0',       4),    # Multicast
    ('240.0.0.0',       4),    # Reserved for future use / broadcast
]


def _ip_str_to_uint32(ip_str: str) -> int:
    """Parse a dotted-quad IPv4 string into a 32-bit unsigned integer.

    Stdlib-only; we deliberately don't import `ipaddress` so the script
    is self-contained and easy to audit.
    """
    parts = ip_str.split('.')
    if len(parts) != 4:
        raise ValueError(f"not a dotted-quad IPv4 string: {ip_str!r}")
    n = 0
    for p in parts:
        v = int(p, 10)
        if v < 0 or v > 255:
            raise ValueError(f"octet out of range in {ip_str!r}")
        n = (n << 8) | v
    return n


def _expand_reserved_blocks() -> list[tuple[int, int, str]]:
    """Return [(start_uint32, end_uint32, RESERVED_ISO), ...]."""
    out = []
    for start_str, prefix in RESERVED_BLOCKS:
        start = _ip_str_to_uint32(start_str)
        size = 1 << (32 - prefix)
        end = start + size - 1
        out.append((start, end, RESERVED_ISO))
    return out
# Network fetch + delegated-stats parser for the five RIR sources.

def _http_get(url: str) -> bytes:
    """Fetch `url` over HTTPS and return the body bytes.

    Stdlib only. Sets a clear, identifying User-Agent so RIR access logs
    show the request came from a Loupe maintenance run, not an
    anonymous scraper.
    """
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(req, timeout=120) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status} fetching {url}")
        return resp.read()


def _parse_delegated_stats(text: str, rir_label: str) -> tuple[list[tuple[int, int, str]], str | None]:
    """Parse one RIR delegated-stats file body.

    Format reference:
      https://www.nro.net/wp-content/uploads/nro-extended-stats-readme5.txt

    Lines look like (pipe-separated):
      arin|US|ipv4|3.0.0.0|16777216|20141118|allocated|...
      ripencc|GB|ipv4|2.16.0.0|524288|20100129|allocated|...

    We keep `ipv4` records with status `allocated` or `assigned` and
    a real two-letter country code. Returns the list of records plus
    the file's "serial" / publication date when present in the header.
    """
    records: list[tuple[int, int, str]] = []
    publish_date: str | None = None

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('|')
        # Version / header line: <ver>|registry|serial|records|startdate|enddate|UTC-offset
        # e.g.  2.3|arin|1777381239726|203305|19700101|20260428|-0400
        # We detect it as: first field looks like a version (contains a
        # dot or is a single digit), second field is the registry label.
        if len(parts) >= 6 and parts[1].lower() == rir_label and parts[3].isdigit():
            # Field 5 is the end date of the reporting period (publication).
            publish_date = parts[5] if parts[5].isdigit() else publish_date
            continue
        # Summary lines look like: arin|*|ipv4|*|N|summary
        if len(parts) >= 6 and parts[5] == 'summary':
            continue
        # Record lines: registry|cc|type|start|count|date|status|...
        if len(parts) < 7:
            continue
        if parts[2] != 'ipv4':
            continue
        status = parts[6].lower()
        if status not in ('allocated', 'assigned'):
            continue
        cc = parts[1].upper()
        if not cc.isalpha() or len(cc) != 2:
            continue
        try:
            start = _ip_str_to_uint32(parts[3])
            count = int(parts[4], 10)
        except ValueError:
            continue
        if count <= 0:
            continue
        end = start + count - 1
        records.append((start, end, cc))

    return records, publish_date


def _fetch_all_rirs() -> tuple[list[tuple[int, int, str]], dict[str, str]]:
    """Download and parse every RIR file. Returns (records, publish_dates)."""
    all_records: list[tuple[int, int, str]] = []
    publish_dates: dict[str, str] = {}
    for label, url in RIR_SOURCES:
        print(f"  fetching {label} ({url}) ...", flush=True)
        body = _http_get(url)
        text = body.decode('utf-8', errors='replace')
        records, pub = _parse_delegated_stats(text, label)
        print(f"    {len(records):>8,} ipv4 records  pub={pub or '?'}", flush=True)
        all_records.extend(records)
        if pub:
            publish_dates[label] = pub
    return all_records, publish_dates
# Coalesce + reserved-block overlay logic.
#
# After the five RIR feeds are concatenated we have hundreds of thousands
# of small records, often adjacent allocations to the same country. We
# merge them so the runtime lookup table stays small (a few tens of
# thousands of ranges total).

def _coalesce_ranges(records: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Sort and merge overlapping / adjacent same-country ranges.

    Input records may overlap (different RIRs occasionally repeat
    legacy ranges). We resolve any overlap by keeping the first
    record's country code in source order, since RIR feeds are
    treated as authoritative for their own range.
    """
    if not records:
        return []
    # Sort by start ascending, then by end ascending so overlap
    # resolution is deterministic.
    records = sorted(records, key=lambda r: (r[0], r[1]))
    merged: list[tuple[int, int, str]] = []
    cur_start, cur_end, cur_cc = records[0]
    for start, end, cc in records[1:]:
        if start <= cur_end + 1 and cc == cur_cc:
            # Adjacent or overlapping with the same country; extend.
            if end > cur_end:
                cur_end = end
        elif start <= cur_end:
            # Overlapping with a different country; keep the earlier
            # record (already in `cur_*`) and skip the newer one's
            # overlapping head. If the new range extends past the
            # current one, emit the trailing slice as a separate run.
            if end > cur_end:
                merged.append((cur_start, cur_end, cur_cc))
                cur_start, cur_end, cur_cc = cur_end + 1, end, cc
            # else: fully contained, ignore.
        else:
            merged.append((cur_start, cur_end, cur_cc))
            cur_start, cur_end, cur_cc = start, end, cc
    merged.append((cur_start, cur_end, cur_cc))
    return merged


def _overlay_reserved(ranges: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Stamp the IANA-reserved blocks over whatever the RIRs claimed.

    Reserved blocks ALWAYS win — even if some legacy stats file lists
    a country code for, say, 127.0.0.0/8, we want loopback to read
    "Reserved" in the analyst's view.
    """
    reserved = _expand_reserved_blocks()
    # Build a lookup of reserved start -> end for sweep.
    reserved.sort()
    out: list[tuple[int, int, str]] = []
    # Two-pointer sweep: walk the (already-coalesced) ranges and the
    # sorted reserved list together, slicing the reserved windows out
    # of the country ranges.
    i = 0
    for start, end, cc in ranges:
        cursor = start
        # Skip reserved blocks that end before `cursor`.
        while i < len(reserved) and reserved[i][1] < cursor:
            # Reserved block lies entirely before this range; emit it.
            out.append(reserved[i])
            i += 1
        # Carve out any reserved windows that overlap `cursor..end`.
        j = i
        while j < len(reserved) and reserved[j][0] <= end:
            r_start, r_end, _r_cc = reserved[j]
            if r_start > cursor:
                out.append((cursor, r_start - 1, cc))
            r_clip_end = min(r_end, end)
            out.append((r_start, r_clip_end, RESERVED_ISO))
            cursor = r_clip_end + 1
            if r_end > end:
                # Reserved window extends past this range; the tail
                # will be handled by the next iteration / final flush.
                break
            j += 1
        i = j
        if cursor <= end:
            out.append((cursor, end, cc))
    # Flush any reserved blocks past the last RIR-known range.
    while i < len(reserved):
        out.append(reserved[i])
        i += 1
    # Collapse contiguous duplicate-cc runs that the carve-out may have
    # introduced.
    return _coalesce_ranges(out)
# Encode the coalesced ranges into the compact bundled binary format.
#
# Layout:
#
#   Offset Bytes Field
#   ------ ----- ---------------------------------------------------
#        0     4 Magic 'LGEO'
#        4     2 Format version (uint16 LE) — currently 1
#        6     2 Reserved / padding (zeros)
#        8     4 Range count R (uint32 LE)
#       12     2 Country count C (uint16 LE)
#       14     2 Reserved / padding (zeros)
#       16     . Country table (C entries, sorted by ISO code):
#                  2 bytes  ISO alpha-2 (ASCII)
#                  1 byte   name length N (max 64)
#                  N bytes  UTF-8 country name
#        .     . Range table (R entries, sorted by start ascending):
#                  4 bytes  start IPv4 (uint32 BE)
#                  2 bytes  country index (uint16 LE)
#
# We omit the range end-IP. At lookup time we binary-search for the
# largest start <= the query IP; the slot's country index is the
# answer. Ranges that don't appear in the table fall through to the
# preceding slot's country, which is correct because adjacent
# same-country runs were already coalesced.

def _build_country_table(ranges: list[tuple[int, int, str]]) -> tuple[list[str], dict[str, int]]:
    """Return (sorted unique ISO codes, code->index map).

    Reserved sentinel '--' is always present so reserved ranges always
    have an entry to point at, even if no RIR record happens to use it.
    """
    seen = {RESERVED_ISO}
    for _start, _end, cc in ranges:
        seen.add(cc)
    isos = sorted(seen)
    return isos, {code: idx for idx, code in enumerate(isos)}


def _encode(ranges: list[tuple[int, int, str]]) -> bytes:
    """Serialize the coalesced ranges into the binary output format."""
    isos, iso_to_idx = _build_country_table(ranges)

    # Validate that every ISO code we saw has a name in our table.
    missing = [c for c in isos if c not in ISO_NAMES]
    if missing:
        raise SystemExit(
            "ISO codes seen in RIR data but not in ISO_NAMES table: "
            + ', '.join(missing)
            + "\nAdd them to scripts/fetch_geoip.py and re-run."
        )

    out = io.BytesIO()
    out.write(FORMAT_MAGIC)
    out.write(struct.pack('<H', FORMAT_VERSION))
    out.write(b'\x00\x00')                    # padding
    out.write(struct.pack('<I', len(ranges)))
    out.write(struct.pack('<H', len(isos)))
    out.write(b'\x00\x00')                    # padding

    # Country table.
    for code in isos:
        name = ISO_NAMES[code]
        name_bytes = name.encode('utf-8')
        if len(name_bytes) > 64:
            raise SystemExit(f"Country name too long for code {code!r}: {name!r}")
        out.write(code.encode('ascii'))
        out.write(struct.pack('<B', len(name_bytes)))
        out.write(name_bytes)

    # Range table — sorted ascending by start IP. Stored without the
    # end IP; the runtime infers ranges from neighbouring entries.
    for start, _end, cc in ranges:
        out.write(struct.pack('>I', start))         # start, network order
        out.write(struct.pack('<H', iso_to_idx[cc]))

    return out.getvalue()
# Top-level orchestration: download, parse, coalesce, encode, write.

def _format_publish_summary(publish_dates: dict[str, str]) -> str:
    """Render a human-readable summary of source publish dates."""
    if not publish_dates:
        return 'unknown'
    parts = []
    for label, _url in RIR_SOURCES:
        d = publish_dates.get(label)
        if d and len(d) == 8:
            parts.append(f"{label}={d[0:4]}-{d[4:6]}-{d[6:8]}")
        else:
            parts.append(f"{label}=?")
    return ', '.join(parts)


def main() -> int:
    print(f"loupe geoip-fetch — writing {OUTPUT_REL}", flush=True)

    print("downloading RIR delegated-stats files ...", flush=True)
    raw_records, publish_dates = _fetch_all_rirs()
    print(f"  total raw ipv4 records: {len(raw_records):,}", flush=True)

    print("coalescing adjacent same-country ranges ...", flush=True)
    coalesced = _coalesce_ranges(raw_records)
    print(f"  coalesced ranges:       {len(coalesced):,}", flush=True)

    print("overlaying IANA reserved blocks ...", flush=True)
    final_ranges = _overlay_reserved(coalesced)
    print(f"  final range count:      {len(final_ranges):,}", flush=True)

    blob = _encode(final_ranges)
    digest = hashlib.sha256(blob).hexdigest()

    os.makedirs(os.path.dirname(OUTPUT_ABS), exist_ok=True)
    with open(OUTPUT_ABS, 'wb') as f:
        f.write(blob)

    print("", flush=True)
    print(f"OK  wrote {OUTPUT_REL}  ({len(blob):,} bytes)", flush=True)
    print(f"    sha-256: {digest}", flush=True)
    print(f"    publish dates: {_format_publish_summary(publish_dates)}", flush=True)
    print("", flush=True)
    print("Next steps:", flush=True)
    print("  1. Update the geoip row in VENDORED.md with the SHA-256 above.", flush=True)
    print("  2. Run `python make.py` to rebuild docs/index.html.", flush=True)
    print("  3. Commit the new vendor/geoip-country-ipv4.bin together", flush=True)
    print("     with the VENDORED.md change in a single commit.", flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
