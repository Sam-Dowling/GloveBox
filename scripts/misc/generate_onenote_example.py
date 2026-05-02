#!/usr/bin/env python3
# scripts/misc/generate_onenote_example.py — One-shot fixture generator
# for `examples/onenote/onenote-example.one`.
#
# Produces a minimal but VALID OneNote file structured as:
#   • 16-byte OneNote magic GUID (revision-store file format header)
#   • short padding
#   • one FileDataStoreObject (MS-ONESTORE §2.6.12):
#       header GUID  {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}
#       cbLength     (u64)
#       unused       (u32)  = 0
#       reserved     (u64)  = 0
#       FileData                 — minimal PE-MZ stub bytes
#       footer GUID  {71FBA722-0F79-4A0B-BB13-899256426B24}
#
# A PE-MZ embedded payload exercises both the OneNote renderer's
# embedded-object enumerator AND the high-severity "embedded object"
# `escalateRisk` path. The payload is intentionally dummy — just an MZ
# header so the magic-byte sniff fires.
#
# Run from the repo root:
#     python scripts/misc/generate_onenote_example.py
import struct, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
OUT = ROOT / 'examples' / 'onenote' / 'onenote-example.one'

ONE_MAGIC = bytes([
    0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
    0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3,
])
FDS_HEADER_GUID = bytes([
    0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45,
    0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC,
])
FDS_FOOTER_GUID = bytes([
    0x22, 0xA7, 0xFB, 0x71, 0x79, 0x0F, 0x0B, 0x4A,
    0xBB, 0x13, 0x89, 0x92, 0x56, 0x42, 0x6B, 0x24,
])

# Minimal PE-MZ stub: MZ header + just enough bytes for the renderer's
# `_sniff` to bind it to "PE Executable" (high-sev). Real PE parsing
# happens in the binary triage layer; here we only need the magic to
# trip the OneNote embedded-object high-severity branch.
PE_STUB = (
    b'MZ' + b'\x00' * 58 +              # DOS header
    struct.pack('<I', 0x80) +           # e_lfanew → 0x80
    b'\x00' * 0x40 +                    # rest of MZ + DOS stub
    b'PE\x00\x00' +                     # PE signature
    b'\x4c\x01' +                       # Machine = i386
    b'\x00' * 64                        # rest of NT headers (bogus but bounded)
)
# Pad payload to an 8-byte boundary (OneNote stores cbLength rounded up).
pad_to_8 = (-len(PE_STUB)) & 0x7
PAYLOAD = PE_STUB + b'\x00' * pad_to_8

# Some surrounding "metadata" bytes between MAGIC and FDS so the
# renderer's `_findNearbyFilename` heuristic has room to NOT find a
# legible name (we want the renderer to fall back to the sniffed type).
PRELUDE = b'\x00' * 32 + 'OneNote analyzer fixture'.encode('utf-16-le') + b'\x00' * 16

fds = (
    FDS_HEADER_GUID
    + struct.pack('<Q', len(PAYLOAD))   # cbLength
    + struct.pack('<I', 0)              # unused
    + struct.pack('<Q', 0)              # reserved
    + PAYLOAD
    + FDS_FOOTER_GUID
)

blob = ONE_MAGIC + PRELUDE + fds

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_bytes(blob)
sys.stdout.write(f'Wrote {OUT.relative_to(ROOT)} — {len(blob)} bytes\n')
