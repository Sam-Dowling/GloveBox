#!/usr/bin/env python3
"""
check_shim_parity.py — Diff the mirrored declarations across canonical
constants.js (and a handful of other host modules) and the worker shims,
fail the build on drift.

Workers don't share globals with the host bundle, so a small subset of
constants and helpers has to be re-declared inside each worker shim. Those
mirrored blocks must stay byte-equivalent (after whitespace normalisation)
with their canonical source — silent drift is a known footgun (Risk #3 of
plans/2026-04-27-loupe-perf-redos-followup-finish-v1.md).

Each shim declares its own manifest in MIRRORS below, naming the canonical
host file plus the constants / functions it mirrors. The IOC shim mirrors a
narrow IOC-extract surface (no safeRegex); the timeline + encoded shims
mirror the safeRegex / looksRedosProne block (their detector code calls
safeRegex on user-supplied regex). All three mirror `_trimPathExtGarbage`
because every worker that touches a Windows-style path needs it.

Stdlib-only, deterministic. Invoked by `python make.py verify`.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANON = ROOT / "src" / "constants.js"

# Per-shim parity manifest. Each entry names the mirror file plus the
# constants / functions whose bodies must stay byte-equivalent (modulo
# whitespace) with the canonical host source.
#
# `consts` and `fns` are checked against `src/constants.js` unless the
# entry overrides `canon` to a different path.
MIRRORS = [
    {
        "path": ROOT / "src" / "workers" / "encoded-worker-shim.js",
        "consts": [
            "SAFE_REGEX_MAX_PATTERN_LEN",
            "_REDOS_NESTED_QUANT_RE",
            "_REDOS_DUPLICATE_GROUP_RE",
            "_KNOWN_EXT_RE",
        ],
        "fns": [
            "looksRedosProne",
            "safeRegex",
            "_trimPathExtGarbage",
        ],
        # Object-literal table parity: every IOC.* key emitted by the
        # main-thread bundle must also exist in the worker shim, with
        # the same string value. Catches the silent-drift class where
        # a renderer adds `IOC.NEW_THING` in `src/constants.js` but
        # forgets to mirror it into the worker, so the worker pipeline
        # silently emits `undefined` for that type. (See M1.2 / M1.3
        # post-mortem.)
        "ioc_table": True,
        # Numeric scalar parity: a single PARSER_LIMITS member the
        # decompressor inside the worker reads at module load. The
        # shim's standalone `PARSER_LIMITS` literal must match the
        # canonical value exactly.
        "parser_limits": ["MAX_UNCOMPRESSED"],
    },
    {
        "path": ROOT / "src" / "workers" / "timeline-worker-shim.js",
        "consts": [
            "SAFE_REGEX_MAX_PATTERN_LEN",
            "_REDOS_NESTED_QUANT_RE",
            "_REDOS_DUPLICATE_GROUP_RE",
        ],
        "fns": [
            "looksRedosProne",
            "safeRegex",
        ],
        # Timeline shim uses `IOC = new Proxy(...)` so every key resolves
        # to its own name — no real table to mirror.
        "ioc_table": False,
    },
    {
        # IOC mass-extract worker shim. Mirrors the regex-only subset of
        # constants.js the IOC core reads at module load. No safeRegex —
        # every regex literal in `extractInterestingStringsCore` is a
        # `/* safeRegex: builtin */` builtin, not a user-supplied pattern.
        # `safeMatchAll` is mirrored here because the IOC core routes every
        # `matchAll` site through it as defence-in-depth against ReDoS.
        "path": ROOT / "src" / "workers" / "ioc-extract-worker-shim.js",
        "consts": [
            "_KNOWN_EXT_RE",
        ],
        "fns": [
            "looksLikeIpVersionString",
            "stripDerTail",
            "_trimPathExtGarbage",
            "safeMatchAll",
        ],
        "ioc_table": True,
    },
]


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


def _extract_ioc_table(src: str):
    """Parse `const IOC = Object.freeze({ KEY: 'value', ... });` into an
    ordered dict {KEY: value}. Returns None if not found. Does NOT support
    nested objects, computed keys, or methods — the IOC table is a flat
    string-to-string map and any structural change should fail the parse
    (and therefore the parity check) loudly."""
    head = re.compile(r"^const\s+IOC\s*=\s*Object\.freeze\s*\(\s*\{",
                      re.MULTILINE)
    m = head.search(src)
    if not m:
        return None
    # Brace-balanced read of the object body.
    i = m.end()
    depth = 1
    start = i
    while i < len(src) and depth:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    body = src[start:i]
    # Strip line comments before parsing entries.
    lines = []
    for line in body.splitlines():
        s = re.sub(r"//.*$", "", line).strip().rstrip(",")
        if s:
            lines.append(s)
    table = {}
    entry_re = re.compile(r"""^([A-Z_][A-Z0-9_]*)\s*:\s*'([^']*)'$""")
    for entry in lines:
        em = entry_re.match(entry)
        if not em:
            return None  # unparseable structural element → fail loud
        table[em.group(1)] = em.group(2)
    return table


def _extract_parser_limit(src: str, name: str):
    """Pull a numeric `KEY: <expr>,` member out of a `PARSER_LIMITS = ...`
    object literal. Returns the raw expression text (e.g. `256 * 1024 * 1024`)
    so the comparator can apply text equality after whitespace normalisation —
    we deliberately don't `eval` the expression because the shim and the
    canonical source might use different but equivalent forms (`256*1024*1024`
    vs `256 * 1024 * 1024`); they should be kept textually consistent so a
    drift is visible at a glance."""
    head = re.compile(r"PARSER_LIMITS\s*=\s*Object\.freeze\s*\(\s*\{")
    m = head.search(src)
    if not m:
        # Fallback: bare `PARSER_LIMITS = { ... }` (no Object.freeze wrap).
        head = re.compile(r"PARSER_LIMITS\s*=\s*\{")
        m = head.search(src)
        if not m:
            return None
    # Brace-balanced read.
    i = m.end()
    depth = 1
    start = i
    while i < len(src) and depth:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    body = src[start:i]
    pat = re.compile(
        r"^\s*" + re.escape(name) + r"\s*:\s*([^,\n]+?)\s*,?\s*(?://.*)?$",
        re.MULTILINE,
    )
    em = pat.search(body)
    return em.group(1).strip() if em else None


def _normalise(s: str) -> str:
    # Collapse runs of whitespace, drop full-line `//` comments and
    # end-of-line `//` comments to keep the diff focused on semantic
    # content. The end-of-line strip is conservative — it only fires when
    # `//` is preceded by whitespace AND is not part of a URL-like
    # `://` token, which is the only `//` substring that legitimately
    # appears inside the mirrored bodies (string literals containing
    # `://` would otherwise be truncated).
    out = []
    for line in s.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        # Strip trailing `// …` only when preceded by whitespace and
        # NOT immediately preceded by `:` (which would mark a URL).
        m = re.search(r"(?<!:)\s+//.*$", stripped)
        if m:
            stripped = stripped[: m.start()].rstrip()
        out.append(stripped)
    joined = " ".join(out)
    return re.sub(r"\s+", " ", joined).strip()


def _check(canon_path: Path, manifest: dict) -> list[str]:
    mirror_path = manifest["path"]
    canon_src = canon_path.read_text(encoding="utf-8")
    mirror_src = mirror_path.read_text(encoding="utf-8")
    errors = []
    for name in manifest.get("consts", []):
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
    for name in manifest.get("fns", []):
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
    # ── IOC table parity ────────────────────────────────────────────────────
    if manifest.get("ioc_table"):
        a = _extract_ioc_table(canon_src)
        b = _extract_ioc_table(mirror_src)
        if a is None:
            errors.append(f"{canon_path}: failed to parse IOC table")
        elif b is None:
            errors.append(f"{mirror_path}: failed to parse IOC table")
        else:
            missing_in_mirror = sorted(set(a) - set(b))
            extra_in_mirror = sorted(set(b) - set(a))
            mismatched = sorted(
                k for k in (set(a) & set(b)) if a[k] != b[k]
            )
            if missing_in_mirror:
                errors.append(
                    f"shim drift: IOC table — keys present in {canon_path.name}"
                    f" but missing in {mirror_path.name}: "
                    + ", ".join(f"IOC.{k}" for k in missing_in_mirror)
                )
            if extra_in_mirror:
                errors.append(
                    f"shim drift: IOC table — keys present in {mirror_path.name}"
                    f" but missing in {canon_path.name}: "
                    + ", ".join(f"IOC.{k}" for k in extra_in_mirror)
                )
            for k in mismatched:
                errors.append(
                    f"shim drift: IOC.{k} value mismatch\n"
                    f"  canonical ({canon_path}): {a[k]!r}\n"
                    f"  mirror    ({mirror_path}): {b[k]!r}"
                )
    # ── PARSER_LIMITS scalar parity ─────────────────────────────────────────
    for name in manifest.get("parser_limits", []) or []:
        a = _extract_parser_limit(canon_src, name)
        b = _extract_parser_limit(mirror_src, name)
        if a is None:
            errors.append(f"{canon_path}: missing PARSER_LIMITS.{name}")
            continue
        if b is None:
            errors.append(f"{mirror_path}: missing PARSER_LIMITS.{name}")
            continue
        if _normalise(a) != _normalise(b):
            errors.append(
                f"shim drift: PARSER_LIMITS.{name}\n"
                f"  canonical ({canon_path}): {a}\n"
                f"  mirror    ({mirror_path}): {b}"
            )
    return errors


def main():
    all_errors = []
    # Sort by mirror path for deterministic output.
    for manifest in sorted(MIRRORS, key=lambda m: str(m["path"])):
        all_errors.extend(_check(CANON, manifest))
    if all_errors:
        sys.stderr.write("FAIL  check_shim_parity:\n")
        for e in all_errors:
            sys.stderr.write("  " + e + "\n")
        sys.stderr.write(
            "\nMirrored constant / function blocks in the worker shims must\n"
            "stay byte-equivalent (modulo whitespace) with src/constants.js.\n"
            "Each shim's manifest in scripts/check_shim_parity.py names the\n"
            "subset it mirrors. Update the offending shim(s) to match the\n"
            "canonical source.\n"
        )
        sys.exit(1)
    parts = [f"{len(MIRRORS)} shim(s)"]
    ioc_count = sum(1 for m in MIRRORS if m.get("ioc_table"))
    if ioc_count:
        parts.append(f"{ioc_count} IOC table(s)")
    pl_count = sum(len(m.get("parser_limits", []) or []) for m in MIRRORS)
    if pl_count:
        parts.append(f"{pl_count} PARSER_LIMITS scalar(s)")
    print(f"OK  check_shim_parity: " + ", ".join(parts) + " match src/constants.js")


if __name__ == "__main__":
    main()
