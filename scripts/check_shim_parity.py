#!/usr/bin/env python3
"""
check_shim_parity.py — Diff the mirrored safeRegex blocks across canonical
constants.js and the worker shims, fail the build on drift.

Mirrored blocks must stay byte-equivalent (after whitespace normalisation):

  • const SAFE_REGEX_MAX_PATTERN_LEN = ...;
  • const _REDOS_NESTED_QUANT_RE = ...;
  • const _REDOS_DUPLICATE_GROUP_RE = ...;
  • function looksRedosProne(src) { ... }
  • function safeRegex(pattern, flags) { ... }

Canonical source: src/constants.js
Mirrors:
  src/workers/encoded-worker-shim.js
  src/workers/timeline-worker-shim.js

Stdlib-only, deterministic. Invoked by `python make.py verify`.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANON = ROOT / "src" / "constants.js"
MIRRORS = [
    ROOT / "src" / "workers" / "encoded-worker-shim.js",
    ROOT / "src" / "workers" / "timeline-worker-shim.js",
]

# Block extractors. Each returns the raw source (incl. body) for a named
# top-level declaration. Whitespace is normalised before comparison.

CONST_NAMES = [
    "SAFE_REGEX_MAX_PATTERN_LEN",
    "_REDOS_NESTED_QUANT_RE",
    "_REDOS_DUPLICATE_GROUP_RE",
]
FN_NAMES = ["looksRedosProne", "safeRegex"]


def _extract_const(src: str, name: str):
    # Match `const NAME = <expr>;` where <expr> may span multiple lines but
    # never crosses another top-level `const`/`function` keyword.
    pat = re.compile(
        r"^const\s+" + re.escape(name) + r"\s*=\s*([\s\S]*?);[ \t]*\n",
        re.MULTILINE,
    )
    m = pat.search(src)
    return m.group(1).strip() if m else None


def _extract_fn(src: str, name: str):
    # Match `function NAME(...args) { ... }` with brace-balanced body.
    head = re.compile(
        r"^function\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{",
        re.MULTILINE,
    )
    m = head.search(src)
    if not m:
        return None
    i = m.end()
    depth = 1
    while i < len(src) and depth:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    return src[m.start():i]


def _normalise(s: str) -> str:
    # Collapse runs of whitespace, drop full-line `//` comments to keep the
    # diff focused on semantic content.
    out = []
    for line in s.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        out.append(stripped)
    joined = " ".join(out)
    return re.sub(r"\s+", " ", joined).strip()


def _check(canon_path: Path, mirror_path: Path) -> list[str]:
    canon_src = canon_path.read_text(encoding="utf-8")
    mirror_src = mirror_path.read_text(encoding="utf-8")
    errors = []
    for name in CONST_NAMES:
        a = _extract_const(canon_src, name)
        b = _extract_const(mirror_src, name)
        if a is None:
            errors.append(f"{canon_path}: missing const {name}")
            continue
        if b is None:
            errors.append(f"{mirror_path}: missing const {name}")
            continue
        if _normalise(a) != _normalise(b):
            errors.append(
                f"shim drift: const {name}\n"
                f"  canonical ({canon_path}): {_normalise(a)}\n"
                f"  mirror    ({mirror_path}): {_normalise(b)}"
            )
    for name in FN_NAMES:
        a = _extract_fn(canon_src, name)
        b = _extract_fn(mirror_src, name)
        if a is None:
            errors.append(f"{canon_path}: missing function {name}")
            continue
        if b is None:
            errors.append(f"{mirror_path}: missing function {name}")
            continue
        if _normalise(a) != _normalise(b):
            errors.append(
                f"shim drift: function {name}\n"
                f"  canonical ({canon_path}): {_normalise(a)[:200]}...\n"
                f"  mirror    ({mirror_path}): {_normalise(b)[:200]}..."
            )
    return errors


def main():
    all_errors = []
    for mirror in sorted(MIRRORS):
        all_errors.extend(_check(CANON, mirror))
    if all_errors:
        sys.stderr.write("FAIL  check_shim_parity:\n")
        for e in all_errors:
            sys.stderr.write("  " + e + "\n")
        sys.stderr.write(
            "\nThe safeRegex / looksRedosProne / SAFE_REGEX_MAX_PATTERN_LEN\n"
            "blocks in the worker shims must stay byte-equivalent (modulo\n"
            "whitespace) with src/constants.js. Update the shim(s) above to\n"
            "match the canonical source.\n"
        )
        sys.exit(1)
    print(f"OK  check_shim_parity: {len(MIRRORS)} shim(s) match src/constants.js")


if __name__ == "__main__":
    main()
