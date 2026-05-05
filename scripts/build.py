#!/usr/bin/env python3
"""Build script: assembles loupe.html from source files.

Reproducible-build support
--------------------------
Given a fixed commit, `python scripts/build.py` produces byte-identical
output. The only time-derived byte in the bundle is the embedded
``LOUPE_VERSION`` string, which is resolved in this order:

  1. ``SOURCE_DATE_EPOCH``  (the reproducible-builds.org standard) — used
     verbatim if set. This is the path CI takes at release time.
  2. The commit-author timestamp of ``HEAD`` in the current git checkout —
     used automatically when step 1 is unset. This makes local contributor
     builds deterministic too (two contributors at the same commit get the
     same bundle bytes), without anyone having to remember an env var.
  3. Wall-clock ``datetime.now()`` — last-resort fallback for source
     archives that are not a git checkout.

See SECURITY.md § Reproducible Build for the full recipe and non-goals.
"""
import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone

# scripts/build.py → repo root is the parent of this file's directory.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── --test-api flag ──────────────────────────────────────────────────────────
# When set, the build:
#   * appends `src/app/app-test-api.js` to APP_JS_FILES so the
#     `window.__loupeTest` test surface is wired up,
#   * prepends `const __LOUPE_TEST_API__ = true;` to Block 1 so other code
#     can statically detect the test build (and so the leak-gate has a
#     unique sentinel string to search for in the released bundle),
#   * writes the output to `docs/index.test.html` instead of
#     `docs/index.html`.
#
# This bundle is NEVER deployed to Pages and NEVER signed for release — the
# release pipeline (.github/workflows/release.yml + signed Sigstore artefact)
# only ever consumes `docs/index.html`. See `_check_no_test_api_in_release`
# below for the defence-in-depth gate that confirms the test-api markers
# never reach the released bundle.
_argparser = argparse.ArgumentParser(
    description='Build Loupe — emits docs/index.html (release) or '
                'docs/index.test.html (with --test-api, never released).',
)
_argparser.add_argument(
    '--test-api', action='store_true',
    help='Emit docs/index.test.html with window.__loupeTest exposed. '
         'Never ship — see scripts/build.py header comment.',
)
# `parse_known_args` so a future `python make.py build` orchestrator pass-
# through still works (make.py invokes this script with no extra args today).
_args, _unknown = _argparser.parse_known_args()
TEST_API = bool(_args.test_api)

_epoch = os.environ.get('SOURCE_DATE_EPOCH')
if not _epoch:
    # Git-checkout fallback: use HEAD's commit-author timestamp so local
    # builds are reproducible without the contributor having to export
    # SOURCE_DATE_EPOCH themselves. Silently falls through to wall-clock
    # time if this isn't a git checkout or git isn't on PATH.
    try:
        _res = subprocess.run(
            ['git', 'log', '-1', '--format=%ct', 'HEAD'],
            cwd=BASE, capture_output=True, text=True, timeout=5, check=False,
        )
        _out = _res.stdout.strip()
        if _res.returncode == 0 and _out.isdigit():
            _epoch = _out
    except (OSError, subprocess.TimeoutExpired):
        pass

if _epoch:
    VERSION = datetime.fromtimestamp(int(_epoch), tz=timezone.utc).strftime('%Y%m%d.%H%M')
else:
    VERSION = datetime.now().strftime('%Y%m%d.%H%M')

def read(rel):
    with open(os.path.join(BASE, rel), 'r', encoding='utf-8') as f:
        return f.read()

jszip        = read('vendor/jszip.min.js')
xlsx_js      = read('vendor/xlsx.full.min.js')
pdf_js       = read('vendor/pdf.min.js')
pdf_wrk_js   = read('vendor/pdf.worker.min.js')
highlight_js = read('vendor/highlight.min.js')
utif_js      = read('vendor/utif.min.js')
exifr_js     = read('vendor/exifr.min.js')
tldts_js     = read('vendor/tldts.min.js')
# Strip the sourceMappingURL comment — the map file doesn't exist inside the
# single-file build, so the browser would 404 and log a console error.
import re as _re
tldts_js = _re.sub(r'\n?//[#@]\s*sourceMappingURL=\S+', '', tldts_js)
pako_js      = read('vendor/pako.min.js')
lzma_js      = read('vendor/lzma-d-min.js')
jsqr_js      = read('vendor/jsqr.min.js')

# ── Bundled GeoIP IPv4-country binary ───────────────────────────────────────
# `vendor/geoip-country-ipv4.bin` is a hand-rolled fixed-record binary
# produced by `scripts/fetch_geoip.py` from the five RIR delegated-stats
# files (a public-domain source — no licence friction). 850 KB raw → 1.13 MB
# base64. Inlined as a JS string constant so `src/geoip/bundled-geoip.js`
# can decode it at module load and answer IPv4 → ISO-2 lookups offline.
# See `VENDORED.md` (Generated vendored assets) for the regenerate vs
# upgrade distinction; see `scripts/fetch_geoip.py` for the pipeline.
import base64 as _base64
with open(os.path.join(BASE, 'vendor', 'geoip-country-ipv4.bin'), 'rb') as _gf:
    _geoip_b64 = _base64.b64encode(_gf.read()).decode('ascii')
geoip_bundle_js = f"const __GEOIP_BUNDLE_B64 = '{_geoip_b64}';\n"

# CSS files — concatenated in order.
# Each optional theme overlay lives in src/styles/themes/<id>.css and contains
# `body.theme-<id> { … }` rules that layer on top of the base palette.
# To add a new theme: drop a file here AND add a row to the THEMES array in
# src/app/app-ui.js. No other wiring required.
CSS_FILES = [
    'src/styles/core.css',
    'src/styles/viewers.css',
    'src/styles/themes/midnight.css',
    'src/styles/themes/solarized.css',
    'src/styles/themes/mocha.css',
    'src/styles/themes/latte.css',
]

css = ''.join(read(f) for f in CSS_FILES)

# Default YARA rules — split by category, concatenated and injected as a JS constant
YARA_FILES = [
    'src/rules/office-macros.yar',
    'src/rules/script-threats.yar',
    'src/rules/document-threats.yar',
    'src/rules/windows-threats.yar',
    'src/rules/archive-threats.yar',
    'src/rules/encoding-threats.yar',
    'src/rules/network-indicators.yar',
    'src/rules/suspicious-patterns.yar',
    'src/rules/file-analysis.yar',
    'src/rules/pe-threats.yar',
    'src/rules/elf-threats.yar',
    'src/rules/macho-threats.yar',
    'src/rules/jar-threats.yar',
    'src/rules/svg-threats.yar',
    'src/rules/osascript-threats.yar',
    'src/rules/plist-threats.yar',
    'src/rules/clickonce-threats.yar',
    'src/rules/msix-threats.yar',
    'src/rules/browserext-threats.yar',
    'src/rules/macos-installer-threats.yar',
    'src/rules/npm-threats.yar',
    'src/rules/wasm-threats.yar',
    'src/rules/pcap-threats.yar',
    'src/rules/discovery-threats.yar',
    'src/rules/reassembled-payloads.yar',
]

YARA_CATEGORIES = {
    'src/rules/office-macros.yar': 'Office Macros',
    'src/rules/script-threats.yar': 'Script',
    'src/rules/document-threats.yar': 'Document',
    'src/rules/windows-threats.yar': 'Windows',
    'src/rules/archive-threats.yar': 'Archive',
    'src/rules/encoding-threats.yar': 'Encoding',
    'src/rules/network-indicators.yar': 'Network Indicators',
    'src/rules/suspicious-patterns.yar': 'Suspicious Patterns',
    'src/rules/file-analysis.yar': 'File Analysis',
    'src/rules/pe-threats.yar': 'PE',
    'src/rules/elf-threats.yar': 'ELF',
    'src/rules/macho-threats.yar': 'Mach-O',
    'src/rules/jar-threats.yar': 'JAR',
    'src/rules/svg-threats.yar': 'SVG',
    'src/rules/osascript-threats.yar': 'AppleScript/JXA',
    'src/rules/plist-threats.yar': 'Property List',
    'src/rules/clickonce-threats.yar': 'ClickOnce',
    'src/rules/msix-threats.yar': 'MSIX / APPX',
    'src/rules/browserext-threats.yar': 'Browser Extension',
    'src/rules/macos-installer-threats.yar': 'macOS Installer',
    'src/rules/npm-threats.yar': 'npm',
    'src/rules/wasm-threats.yar': 'WebAssembly',
    'src/rules/pcap-threats.yar': 'Packet Capture',
    'src/rules/discovery-threats.yar': 'Discovery',
    'src/rules/reassembled-payloads.yar': 'Reassembled Payloads',
}

# ── File-level `applies_to` injection ──────────────────────────────────────
#
# `YaraEngine` (src/yara-engine.js) supports `meta: applies_to = "..."` per-rule
# gates that short-circuit a rule when the host-detected file format
# (`formatTag`, computed in `render-route.js`) doesn't match. Rule files where
# every rule applies to the same format register a single value here and the
# build script auto-injects `applies_to = "<value>"` into each rule's meta
# block at concatenation time. This avoids 50+ duplicated meta lines across
# files like `plist-threats.yar` / `jar-threats.yar` / `osascript-threats.yar`
# without violating the no-`//`-comments-in-.yar constraint (the injection
# happens in build.py — the source files stay comment-free).
#
# Per-rule override: if a rule already declares its own `applies_to` value the
# injection is a no-op for that rule. Rules with no `meta:` block at all get a
# fresh `meta:` block prepended with the `applies_to` line.
#
# Empty by default. Populated as rule-migration PRs land for each format-bound
# file. Group aliases (`office`, `office_ooxml`, `script`, etc.) are accepted
# — see `YaraEngine.FORMAT_PREDICATES`.
YARA_APPLIES_TO = {
    # Native binaries — every rule is anchored on the format magic. Engine-
    # level gating skips them entirely on unrelated content.
    'src/rules/pe-threats.yar':              'pe',
    'src/rules/file-analysis.yar':           'pe',
    'src/rules/elf-threats.yar':             'elf',
    'src/rules/macho-threats.yar':           'macho',
    # Format-bound document/manifest/script files. Each rule's strings are
    # specific to the named format but lacked an anchored magic-byte gate;
    # `applies_to` provides that gate at the engine level.
    'src/rules/jar-threats.yar':             'jar',
    'src/rules/svg-threats.yar':             'svg',
    'src/rules/plist-threats.yar':           'plist',
    'src/rules/osascript-threats.yar':       'scpt',
    'src/rules/clickonce-threats.yar':       'clickonce',
    'src/rules/msix-threats.yar':            'msix',
    'src/rules/browserext-threats.yar':      'browserext',
    'src/rules/npm-threats.yar':             'npm',
    # Office-macro rules cover legacy OLE (doc/xls/ppt/msg), OOXML
    # (docx/xlsx/pptx) and ODF (odt/ods/odp) hosts plus RTF (the third
    # magic 0x74725C7B in most rules). `is_office` expands to the 12
    # office-host formats; `rtf` is appended as a bare formatTag so the
    # RTF-specific OLE-object / DDE rules in the file still fire on .rtf
    # input. Without this gate the rules' `uint16(0) == 0x4B50` clause
    # would also accept any non-office ZIP container (jar/msix/npm/etc).
    'src/rules/office-macros.yar':           'is_office, rtf',
    # NB: `wasm-threats.yar` is intentionally NOT in YARA_APPLIES_TO. The
    # `Info_Contains_WebAssembly` rule must fire on embedded WASM blobs in
    # *any* container (script, PE overlay, archive entry, etc.); gating the
    # whole file with `applies_to: wasm` would suppress that. Each rule
    # already short-circuits on `uint32(0) == 0x6d736100`, so the cost on
    # non-WASM input is one i32 read per rule.
    # Mixed files — the file-level value covers the majority case; the
    # exceptional rules carry their own `applies_to` in source which the
    # injector treats as a no-op (already-set ⇒ skip).
    'src/rules/macos-installer-threats.yar': 'dmg',     # PKG_Xar_Archive overrides to "pkg"
    'src/rules/archive-threats.yar':         'zip_plain', # RAR/7z/ISO rules override
}


# Inject `applies_to = "<value>"` into every rule body in `raw` that doesn't
# already declare its own. Pure source transformation — deterministic for any
# given (raw, value) pair. No regex backtracking pathologies (uses iterative
# brace-balance scanning). Rules without a `meta:` block get one inserted as
# the first section (before `strings:` / `condition:`).
def _inject_applies_to(raw: str, value: str) -> str:
    if not value:
        return raw
    out = []
    pos = 0
    n = len(raw)
    # Match `rule <name> [: tags] {` exactly the way the engine does. We
    # walk each rule block by brace balance because the rule body itself
    # contains `{ … }` for hex strings — a naive regex would mis-end at
    # the first `}`.
    import re
    rule_hdr = re.compile(r'\brule\s+\w+\s*(?::\s*[\w\s]+)?\s*\{', re.MULTILINE)
    for m in rule_hdr.finditer(raw):
        # Emit text up to and including the opening `{`.
        out.append(raw[pos:m.end()])
        # Find the matching `}` by brace balance, skipping over string
        # literals (where braces are data, not structure). Hex-pattern
        # braces (`{ AA BB CC }`) are part of `= { … }` assignments — they
        # legitimately balance because the YARA grammar always pairs them.
        depth = 1
        i = m.end()
        in_str = False
        in_regex = False
        while i < n and depth > 0:
            ch = raw[i]
            if in_str:
                if ch == '\\' and i + 1 < n:
                    i += 2
                    continue
                if ch == '"':
                    in_str = False
            elif in_regex:
                if ch == '\\' and i + 1 < n:
                    i += 2
                    continue
                if ch == '/':
                    in_regex = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        break
                elif ch == '/' and i + 1 < n and raw[i + 1] not in ('/', '*'):
                    # Only treat `/` as a regex delimiter when it follows
                    # an `=` (string assignment) — anything else (e.g. a
                    # division-like token in a YARA condition) doesn't
                    # exist in this engine's grammar.
                    j = i - 1
                    while j >= 0 and raw[j] in (' ', '\t'):
                        j -= 1
                    if j >= 0 and raw[j] == '=':
                        in_regex = True
            i += 1
        if depth != 0:
            # Malformed rule block — bail and emit the rest unmodified.
            out.append(raw[m.end():])
            return ''.join(out)
        body = raw[m.end():i]
        body = _inject_applies_to_into_body(body, value)
        out.append(body)
        out.append('}')
        pos = i + 1
    out.append(raw[pos:])
    return ''.join(out)


def _inject_applies_to_into_body(body: str, value: str) -> str:
    """Insert `applies_to = "<value>"` into a single rule's body. Skips the
    rule if it already declares its own applies_to. Adds a meta: block when
    none exists. Used by `_inject_applies_to`.

    The inserted line's indent matches the surrounding meta block (some rule
    files use 4-space indent, most use 8-space) and the line is placed
    immediately after the last meta entry — any trailing blank line in the
    meta block is preserved between applies_to and strings:/condition:, so
    house style is unchanged."""
    import re
    # Already has applies_to anywhere in the body — leave the rule alone.
    if re.search(r'\bapplies_to\s*=\s*"', body):
        return body
    meta_match = re.search(r'(\bmeta\s*:)([\s\S]*?)(?=\bstrings\s*:|\bcondition\s*:|$)',
                           body, re.IGNORECASE)
    if not meta_match:
        # No meta block — synthesise one as the first section. The opening
        # newline keeps us off whatever whitespace the rule body started
        # with.
        return f'\n    meta:\n        applies_to = "{value}"\n' + body
    meta_kw = meta_match.group(1)
    meta_inner = meta_match.group(2)
    # Detect the indent used by the first existing meta entry — fall back
    # to 8 spaces when the meta block is empty. Also detect the `=` column
    # used by surrounding entries so applies_to lines up visually.
    indent = '        '
    eq_col = None  # column index where `=` should land (None ⇒ 1 space pad)
    for ln in meta_inner.splitlines():
        stripped = ln.lstrip(' \t')
        if stripped:
            cur_indent = ln[:len(ln) - len(stripped)]
            if eq_col is None:
                indent = cur_indent
            # Track the column where `=` itself sits on any meta entry;
            # this is the column the source file aligns to.
            if '=' in stripped:
                col = len(cur_indent) + stripped.index('=')
                if eq_col is None or col > eq_col:
                    eq_col = col
    if eq_col is not None:
        pad_len = max(1, eq_col - len(indent) - len('applies_to'))
    else:
        pad_len = 1
    line = f'{indent}applies_to{" " * pad_len}= "{value}"\n'
    # Split the meta block into the last non-blank line and any trailing
    # whitespace-only suffix (typically a blank line + indented spaces
    # leading to `strings:`). Insert applies_to after the content, before
    # the trailing whitespace, so the file's house style is preserved.
    m_tail = re.search(r'\n([ \t]*(?:\n[ \t]*)*)$', meta_inner)
    if m_tail:
        head = meta_inner[:m_tail.start()] + '\n'
        tail = m_tail.group(0)[1:]  # drop the leading \n we kept on `head`
        new_meta = meta_kw + head + line + tail
    else:
        new_meta = meta_kw + meta_inner + line
    return body[:meta_match.start()] + new_meta + body[meta_match.end():]


_missing_applies_to = [f for f in YARA_APPLIES_TO if f not in YARA_FILES]
if _missing_applies_to:
    raise SystemExit(
        'YARA_APPLIES_TO references files not in YARA_FILES: '
        + ', '.join(_missing_applies_to)
    )


# H8 — Category-marker robustness.
#
# The pre-H8 marker was a `// @category: <NAME>` line comment matched
# by `app-yara.js` with a free-text regex. Two failure modes:
#
#   1. A rule string literal (e.g. `$s = "// @category: Hacked"`) anywhere
#      in any concatenated `.yar` file silently truncated the previous
#      category and started a new one with the wrong name.
#   2. A rule file added to `YARA_FILES` but missing from
#      `YARA_CATEGORIES` was silently labelled `Other`.
#
# Fix: emit a sentinel block comment that the rule files are statically
# verified not to contain (`@loupe-category` is a forbidden substring in
# `.yar` source — `_check_yara_category_sentinel` enforces it), and make
# the missing-category case a hard build failure.
_YARA_CATEGORY_SENTINEL = '@loupe-category'  # must never appear in .yar source

# Every file we concatenate must have an explicit category — silent fall-
# back to "Other" hides bugs (file added to YARA_FILES but the contributor
# forgot to add it to YARA_CATEGORIES). H8.
_missing_categories = [f for f in YARA_FILES if f not in YARA_CATEGORIES]
if _missing_categories:
    raise SystemExit(
        'YARA_CATEGORIES is missing entries for: '
        + ', '.join(_missing_categories)
        + '\nAdd a row to YARA_CATEGORIES in scripts/build.py.'
    )

yar_parts = []
for f in YARA_FILES:
    cat = YARA_CATEGORIES[f]
    raw = read(f)
    # Defence in depth: refuse to emit a bundle if any rule file already
    # contains the sentinel substring (an attacker-authored rule with a
    # `$s = "/*! @loupe-category: Spoofed */"` literal would otherwise
    # spoof the category split). H8.
    if _YARA_CATEGORY_SENTINEL in raw:
        raise SystemExit(
            f'{f} contains the reserved category sentinel '
            f'"{_YARA_CATEGORY_SENTINEL}". Rule files must not embed '
            'this token in any string, identifier, or (forbidden)'
            ' comment — see scripts/build.py:_YARA_CATEGORY_SENTINEL.'
        )
    # Optional file-level `applies_to` injection. Pure source rewrite;
    # deterministic for a given (raw, value) input pair.
    applies_to_val = YARA_APPLIES_TO.get(f)
    if applies_to_val:
        raw = _inject_applies_to(raw, applies_to_val)
    yar_parts.append(f'/*! @loupe-category: {cat} */')
    yar_parts.append(raw)
yar_rules = '\n'.join(yar_parts)

# Escape backticks and backslashes for JS template literal
yar_rules_escaped = yar_rules.replace('\\', '\\\\').replace('`', '\\`').replace('${', '\\${')
default_yara_js = f'const DEFAULT_YARA_RULES = `{yar_rules_escaped}`;\n'

# `EncodedContentDetector` is split across `src/encoded-content-detector.js`
# (the class root with constructor / static tables / scan orchestrator) and
# nine helper modules under `src/decoders/` that attach instance methods via
# `Object.assign(EncodedContentDetector.prototype, {...})` and one static
# (`unwrapSafeLink`). Order matters — the class root MUST load first; the
# helpers can load in any order after that, but we keep the listing
# deterministic for byte-reproducible builds. This list is splatted into
# `JS_FILES` (main bundle) and concatenated into `_encoded_worker_bundle_src`
# (worker bundle) so the two stay in sync. See CONTRIBUTING.md →
# Encoded-content split.
_DETECTOR_FILES = [
    'src/encoded-content-detector.js',
    'src/decoders/safelinks.js',
    'src/decoders/whitelist.js',
    'src/decoders/entropy.js',
    # xor-bruteforce.js depends on entropy.js (`_tryDecodeUTF8`,
    # `_shannonEntropyBytes`) and is consumed from `_processCandidate`
    # to emit a synthetic XOR-cleartext inner finding when the surrounding
    # source mentions an XOR operator. See PLAN.md → D1.
    'src/decoders/xor-bruteforce.js',
    'src/decoders/ioc-extract.js',
    'src/decoders/base64-hex.js',
    'src/decoders/zlib.js',
    'src/decoders/encoding-finders.js',
    'src/decoders/encoding-decoders.js',
    'src/decoders/cmd-obfuscation.js',
    # ps-mini-evaluator.js depends on cmd-obfuscation.js (it emits
    # `cmd-obfuscation` candidates that flow through
    # `_processCommandObfuscation`). See PLAN.md → D3.
    'src/decoders/ps-mini-evaluator.js',
    # js-assembly.js — JS string-array obfuscation resolver (obfuscator.io
    # / javascript-obfuscator npm package shape). Same `cmd-obfuscation`
    # candidate emission contract as ps-mini-evaluator.js, so the
    # `_processCommandObfuscation` pipeline (severity, IOC extraction,
    # deobfuscated-command sidebar shape) is reused unchanged. Must load
    # AFTER cmd-obfuscation.js (it consumes `_processCommandObfuscation`).
    # See PLAN.md → D6.
    'src/decoders/js-assembly.js',
    # bash-obfuscation.js — POSIX-shell obfuscation/deobfuscation:
    # ${V:n:m} parameter slicing, $'…' ANSI-C quoting, printf '\xNN'
    # chains, curl|sh / base64-pipe-to-shell, eval $(…) command
    # substitution unrolling, IFS / brace-expansion fragmentation,
    # /dev/tcp reverse shells. Emits `cmd-obfuscation` candidates so
    # the `_processCommandObfuscation` pipeline (severity scoring, IOC
    # mirroring, ClickFix marks) is reused unchanged. Must load AFTER
    # cmd-obfuscation.js (consumes _processCommandObfuscation). No
    # cross-decoder state — independent of ps-mini-evaluator.js /
    # js-assembly.js load order.
    'src/decoders/bash-obfuscation.js',
    # python-obfuscation.js — Python obfuscation/deobfuscation:
    # exec(zlib.decompress(b64decode(b'…'))) carriers, marshal.loads
    # bytecode, codecs.decode rot13/hex/base64/zlib, char-array
    # reassembly (chr-join / bytes-list / chr-concat), builtin
    # string-concat lookup (getattr(__builtins__, 'e'+'val')),
    # subprocess/os.system/pty.spawn/socket sinks. Emits
    # `cmd-obfuscation` candidates so the `_processCommandObfuscation`
    # pipeline is reused unchanged. Must load AFTER cmd-obfuscation.js.
    # Calls Decompressor.inflateSync (defined in src/decompressor.js,
    # loaded earlier in JS_FILES) to unpack zlib-wrapped payloads.
    'src/decoders/python-obfuscation.js',
    # php-obfuscation.js — PHP webshell / dropper detection: PHP1
    # eval(gzinflate(base64_decode(...))) decoder onion (b374k / WSO /
    # r57 family), PHP2 variable-variables ($$x with concatenated
    # symbol-table lookup), PHP3 chr/pack reassembly resolving to
    # PHP_DANGEROUS_FNS names, PHP4 preg_replace('/.../e') deprecated
    # exec primitive, PHP5 superglobal callable patterns
    # ($_GET[0]($_POST[1]) and eval($_REQUEST[...])), PHP6
    # data://text/plain;base64,... and php://filter stream-wrapper
    # includes. Emits `cmd-obfuscation` candidates so the
    # `_processCommandObfuscation` pipeline is reused unchanged. Calls
    # Decompressor.inflateSync (deflate-raw / zlib / gzip) to unwrap
    # gzinflate / gzuncompress / gzdecode chains.
    'src/decoders/php-obfuscation.js',
    # interleaved-separator.js — finds + decodes interleaved-separator
    # obfuscation (`$\x00W\x00C\x00=\x00…` → `$WC=…`). Two-pass finder:
    # (1) single-character separator at strides 2/3/4 (e.g. `a.b.c.d`),
    # (2) multi-character literal separator (`\x00`, `\u0000`, `&#0;`,
    # `&nbsp;`, `&#x00;`). Loaded last because it's a pure
    # `Object.assign(...prototype, …)` mixin with no internal deps
    # beyond `_tryDecodeUTF8` (entropy.js), and the `_decodeCandidate`
    # dispatch in `encoding-decoders.js` already routes
    # `Interleaved Separator` candidate types here via prefix match.
    'src/decoders/interleaved-separator.js',
]


# ── Three-group JS load order (Tier 3 reorder) ───────────────────────────────
# The bundle is emitted as **three** separate `<script>` blocks (instead of
# one mega-block sitting after every vendor) so the App's drag-and-drop
# listeners can be wired before the slowest vendor compiles. The breakdown:
#
#   • EARLY_JS_FILES   — pre-App essentials. Capture-phase drag/drop/paste
#                        glue that buffers files into
#                        `window.__loupePendingDrop` /
#                        `window.__loupePendingPaste` during the cold-load
#                        window. Must beat every other inline `<script>` to
#                        the parser. Today the only entry is
#                        `src/app/early-drop-bootstrap.js`.
#   • APP_JS_FILES     — the App bundle itself (constants, helpers, every
#                        renderer, the App class + Object.assign mixins).
#                        `Object.assign(App.prototype, …)` ordering is
#                        load-bearing inside this list — see the comments
#                        on individual entries. The trailing
#                        `new App().init();` call lives at the end of
#                        `app-breadcrumbs.js` — the LAST file in this list
#                        (synchronous — no DOMContentLoaded wrapper, see
#                        comment there) so it fires after every
#                        `Object.assign(App.prototype, …)` mixin has
#                        landed its methods on the prototype.
#   • Group C — heavy renderer-only vendors (JSZip / SheetJS / pdf.js /
#                        highlight.js / UTIF / exifr / tldts / pako / LZMA
#                        / jsQR). Emitted *after* the App `<script>` so
#                        their compile cost no longer blocks
#                        `App._setupDrop()` from binding listeners. They
#                        live as plain `read()` constants in this file —
#                        see the HTML template at the bottom for ordering.
#                        `pushIOC` and the renderer dispatch are the only
#                        consumers and both fire post-load (asynchronous
#                        FileReader → RenderRoute pipeline), so by the
#                        time any of them reach into a vendor global
#                        every Group C `<script>` has parsed.
#
# Build gates iterate `EARLY_JS_FILES + APP_JS_FILES` so coverage is
# preserved across the split.
EARLY_JS_FILES = [
    # early-drop-bootstrap.js — pre-App drag-and-drop / paste capture.
    # Tiny IIFE (≈ 60 LOC of pure event-listener glue, < 1 ms compile)
    # that registers capture-phase `dragover` / `drop` / `paste` listeners
    # **before** the heavy vendor inlines (JSZip / SheetJS / pdf.js) and
    # the App `<script>` compile. Drops captured during the cold-load
    # window land on `window.__loupePendingDrop` (or `__loupePendingPaste`)
    # and are drained by `App._setupDrop()` once the constructor runs.
    # MUST stay the only entry in EARLY_JS_FILES — the whole point is to
    # beat every other inline `<script>` to the parser. See file header
    # for the contract and `App._setupDrop()` for the drain.
    'src/app/early-drop-bootstrap.js',
]

APP_JS_FILES = [
    'src/constants.js',

    # util/url-normalize.js — pure deobfuscator for URL strings (unicode /
    # hex inline escapes, percent-encoding in host+path, hex/octal/decimal
    # encoded IPs). Consumed by `src/ioc-extract.js::processUrl` and
    # `src/decoders/ioc-extract.js` to surface the canonical URL alongside
    # the original obfuscated form, and to emit a sibling `IOC.IP` when
    # the decoded host is a dotted-quad. Worker-safe (no DOM, no globals
    # beyond `UrlNormalizeUtil`); concatenated into the encoded-content and
    # IOC-extract worker bundles too. Must load BEFORE `src/ioc-extract.js`
    # and BEFORE the encoded-content split (which carries
    # `src/decoders/ioc-extract.js`).
    'src/util/url-normalize.js',

    # ioc-extract.js — pure regex-based IOC extraction core. Defines
    # `extractInterestingStringsCore(text, opts)` plus the `_unwrapSafeLink`
    # / `_refangString` worker-safe helpers. Loaded as a host module here AND
    # concatenated into `__IOC_EXTRACT_WORKER_BUNDLE_SRC` so the worker can
    # call the same core. Must load AFTER constants.js (uses IOC,
    # `_trimPathExtGarbage`, `looksLikeIpVersionString`, `stripDerTail`) and
    # BEFORE any consumer (`app-load.js` shim, EML / MSG renderers that share
    # `_refangString`). See CONTRIBUTING.md → Worker subsystem and
    # plans/2026-04-27-loupe-perf-redos-followup-finish-v1.md (Batch A).
    'src/ioc-extract.js',

    # storage.js — single chokepoint for every `localStorage.*` access in the
    # bundle. Exposes `window.safeStorage.{get,set,remove,getJSON,setJSON,
    # keys,removeMatching}`. Pure ceremony — try/catch + JSON serialise. Must
    # load AFTER constants.js (no constant deps today, but the namespacing
    # convention `loupe_*` lives there) and BEFORE any consumer that touches
    # storage. The build-gate `_check_storage_access()` allow-lists this file
    # plus `scripts/build.py` itself (FOUC theme bootstrap is hand-written
    # inline JS in <head>, not a `src/` module).
    'src/storage.js',

    # util/ipv4.js — strict IPv4 parser + non-routable-range classifier.
    # Single source of truth for "is this string a strict dotted-quad?"
    # and "is this address private / loopback / multicast / CGNAT?".
    # Consumed by:
    #   • src/app/timeline/timeline-view-geoip.js  (timeline GeoIP enrichment)
    #   • src/app/app-sidebar.js                   (sidebar IOC enrichment)
    #   • src/app/app-ui.js                        (Summary + JSON/CSV exports)
    # Pure JS, no dependencies. Must load BEFORE every consumer above.
    'src/util/ipv4.js',

    # nicelist.js — known-good global infrastructure (NICELIST) used by the
    # sidebar IOC table to demote / hide benign cloud / registry / CA /
    # XML-namespace surfaces. Pure data + string helpers, no dependencies,
    # must load after constants.js (for the type-string contract) and before
    # app-sidebar.js (which consumes `isNicelisted`).
    'src/nicelist.js',
    # nicelist-user.js — user-defined nicelists (custom "known-good" lists
    # managed from Settings → Nicelists). Exposes `_NicelistUser` as a
    # singleton with load/save/match/parse/export/import helpers. Must load
    # AFTER nicelist.js (built-in takes priority for the "Default Nicelist"
    # label) and BEFORE app-sidebar.js / app-settings.js (both consume it).
    'src/nicelist-user.js',
    # nicelist-annotate.js — single canonical IOC tagger. Walks every
    # `findings.externalRefs` / `interestingStrings` entry and stamps
    # `_nicelisted` / `_nicelistSource` so downstream consumers (sidebar
    # IOC table, Copy Analysis Summary, STIX bundle, MISP event, IOC CSV)
    # share a single source of truth instead of recomputing tags each
    # time. Must load AFTER nicelist.js and nicelist-user.js (consumes
    # both) and BEFORE app-load.js / app-sidebar.js / app-ui.js.
    'src/nicelist-annotate.js',

    'src/parser-watchdog.js',
    # file-download.js — single home for the Blob → <a download> → revoke
    # ceremony. Exposes `window.FileDownload.{downloadBlob, downloadText,
    # downloadBytes, downloadJson}`. Must load BEFORE any renderer or
    # app-* file that emits a download (every `_downloadText` /
    # `_downloadBytes` / renderer-local Save button funnels through this).
    # No dependencies — pure DOM + Blob ceremony.
    'src/file-download.js',
    # sandbox-preview.js — shared sandboxed-iframe + drag-shield helper
    # used by html-renderer.js and svg-renderer.js. Exposes
    # `window.SandboxPreview.create({...})`
    # which builds the `iframe` (with `sandbox='allow-same-origin'` +
    # inner CSP `<meta>` tag) and the overlay drag-shield `<div>` that
    # forwards wheel/touch scroll deltas and re-dispatches drag/drop
    # as `loupe-*` CustomEvents. Must load BEFORE the renderers that
    # consume it (`html-renderer.js`, `svg-renderer.js`). No
    # dependencies — pure DOM + closures.
    'src/sandbox-preview.js',
    # hashes.js — shared non-cryptographic fingerprint hashes (imphash
    # helpers, Rich-header hash, Mach-O symhash). Must load BEFORE any
    # native-binary renderer (pe/elf/macho) so they can call
    # `computeImportHashFromList`, `computeRichHash`, `computeSymHash`
    # without redefining their own MD5.
    'src/hashes.js',
    # mitre.js — canonical MITRE ATT&CK technique registry + rollup
    # helpers used by the sidebar "MITRE ATT&CK Coverage" section, the
    # Tier-A capability strip, and `Copy Analysis`. Exposes `window.MITRE`
    # with `lookup`, `rollupByTactic`, `primaryTactic`, `urlFor`,
    # `tacticMeta`. Must load BEFORE `capabilities.js` (and BEFORE the
    # three native-binary renderers) so every emit site can cite a
    # canonical technique id instead of rolling its own table.
    'src/mitre.js',
    'src/evtx-event-ids.js',
    # trusted-cas.js — curated public-CA recognition for Authenticode /
    # Mach-O code-sig trust tier classification. Exposes `TrustedCAs` with
    # `classifyTrustTier(certs) → 'unsigned'|'self-signed'|'signed'|'signed-trusted'`
    # and `trustBoostForTier(tier) → -1|0|+1|+2`. Consumed by binary-class.js
    # and the PE / Mach-O renderers. Must load BEFORE binary-class.js and
    # the native-binary renderers.
    'src/trusted-cas.js',
    # binary-class.js — shared binary-classification helper (size · trust ·
    # kind · family). Drives the `_weight()` and `_surface()` gates inside
    # the PE / ELF / Mach-O renderers so ubiquitous-API capability noise
    # (anti-debug, generic networking, dynamic loading) gets demoted on
    # large signed-trusted SDK / system / compiler-toolchain binaries while
    # critical capabilities (process injection, credential theft,
    # ransomware-class crypto) keep full weight. Must load BEFORE
    # capabilities.js consumers AND AFTER trusted-cas.js.
    'src/binary-class.js',
    # capabilities.js — static capability tagging (capa-lite). Consumed by
    # PE / ELF / Mach-O renderers via `Capabilities.detect({imports,strings,dylibs})`
    # to turn a wall of suspicious APIs into named behaviours with MITRE
    # ATT&CK IDs. Must load BEFORE the native-binary renderers.
    'src/capabilities.js',

    # binary-overlay.js — shared overlay detection + clickable drill-down
    # used by PE / ELF / Mach-O renderers. Exposes BinaryOverlay on window.
    # Must load BEFORE the native-binary renderers.
    'src/binary-overlay.js',
    # binary-strings.js — categorised string classification (mutex, named
    # pipe, PDB path, user-home/build-tree path, registry key) + Rust
    # panic-source mining. Consumed by PE / ELF / Mach-O renderers. Must
    # load BEFORE the native-binary renderers and AFTER constants.js so
    # it can reach pushIOC / IOC.* at emit-time.
    'src/binary-strings.js',
    # binary-exports.js — export-anomaly flags (DLL side-loading host,
    # forwarded / proxy-DLL exports, ordinal-only exports). Consumed by
    # PE / ELF / Mach-O renderers via `BinaryExports.emit(findings,
    # {isLib, fileName, exportNames, forwardedExports, ordinalOnlyCount})`.
    # Must load BEFORE the native-binary renderers and AFTER constants.js
    # (pushIOC / IOC.*).
    'src/binary-exports.js',
    # binary-summary.js — shared "binary pivot" triage card (file hash
    # trio, import hash / RichHash / SymHash, signer, compile timestamp
    # with "faked?" flag, entry-point + anomaly, overlay Y/N, packer
    # verdict). Consumed by PE / ELF / Mach-O renderers via
    # `BinarySummary.renderCard({...})`. Must load AFTER hashes.js (needs
    # `md5`) and BEFORE the native-binary renderers.
    'src/binary-summary.js',
    # binary-verdict.js — Tier-A verdict one-liner + coarse 0..100 risk
    # score derived from the parsed object, findings, and MITRE-tagged
    # capability counts. Exposes `window.BinaryVerdict.summarize({parsed,
    # findings, format, fileSize})`. Pure presentation — never mutates.
    # Must load AFTER binary-summary.js and BEFORE the native renderers.
    'src/binary-verdict.js',
    # binary-anomalies.js — anomaly-ribbon feeder + "should this card
    # auto-open?" predicate. Tier-C reference cards collapse by default
    # on clean samples and auto-open when this module flags them.
    # Exposes `window.BinaryAnomalies.detect({parsed, findings, format})`.
    # Must load AFTER binary-summary.js / binary-verdict.js and BEFORE
    # the native renderers.
    'src/binary-anomalies.js',
    # binary-triage.js — Tier-A "verdict band" composer. Glues
    # BinaryVerdict (one-liner + 0-100 risk), BinaryAnomalies (coloured
    # ribbon), and MITRE.rollupByTactic (tactic-grouped capability strip)
    # into a single DOM node the three native-binary renderers append
    # above the Binary Pivot card. Pure presentation — never mutates.
    # Must load AFTER binary-anomalies.js and BEFORE the native renderers.
    'src/binary-triage.js',
    'src/vba-utils.js',
    # lolbas-map.js — Living-Off-The-Land Binaries → ATT&CK lookup. Static
    # data + a small literal-substring scanner used by any renderer that
    # surfaces a Windows command-line / executable reference. Pure, no
    # dependencies, must load BEFORE any renderer that consults it (none
    # do mandatorily today — adoption is opportunistic).
    'src/lolbas-map.js',
    # email-spoof.js — display-name / brand-mismatch heuristics for the
    # `From:` header. Used by both eml-renderer and msg-renderer to flag
    # the canonical "PayPal Support <attacker@evil.tld>" phishing pretext
    # (the existing T2.4 freemail-only check misses non-freemail throwaway
    # domains; this closes that gap). Pure data + regex, no dependencies.
    'src/email-spoof.js',
    # xlsx-extras.js — XLSX-only scanners that probe attack surfaces not
    # reachable through `_rels/*.rels`: xl/connections.xml (external data
    # connections — OLEDB/ODBC/web/text, with refreshOnLoad gating) and
    # xl/customXml/item*.xml (Power Query DataMashup payloads). Used by
    # XlsxRenderer in addition to OoxmlRelScanner. Must load BEFORE
    # xlsx-renderer.js (the renderer references the helper classes).
    'src/xlsx-extras.js',

    'src/yara-engine.js',
    # worker-manager.js — central host-side spawner for src/workers/*.worker.js.
    # The build-gate `_check_worker_spawn_allowlist()` allow-lists this file
    # plus `src/workers/*.worker.js`; every other call site must funnel through
    # `window.WorkerManager.{runYara,…}`. Must load AFTER yara-engine.js (it
    # references the build-injected `__YARA_WORKER_BUNDLE_SRC` constant which
    # carries a copy of the engine's source) and BEFORE app-yara.js / app-load.js
    # (which call WorkerManager.runYara / WorkerManager.cancelYara at runtime).
    # See CONTRIBUTING.md → Worker subsystem.
    'src/worker-manager.js',

    'src/decompressor.js',
    # ── GeoIP providers — bundled IPv4-country (offline, public-domain RIR
    #    derivation) + user-uploaded MMDB override (IndexedDB-backed). Both
    #    expose the same provider contract — `lookupIPv4(ipStr) → {country,
    #    iso, region?, city?} | null`, `formatRow(rec) → string`,
    #    `getFieldName() → 'geo'`, `vintage`, `providerKind`. Resolved by
    #    `App.init()` in src/app/app-core.js into `app.geoip` (sync default
    #    = BundledGeoip; async hydrates to MmdbReader if one is persisted).
    #    Consumed by the Timeline GeoIP enrichment mixin
    #    (timeline-view-geoip.js) — every other surface ignores them.
    #    Must load AFTER decompressor.js (mmdb-reader uses Decompressor
    #    for `.mmdb.gz`) and BEFORE app-core.js (init() reads the
    #    providers). Independent of every renderer.
    'src/geoip/bundled-geoip.js',
    'src/geoip/mmdb-reader.js',
    'src/geoip/geoip-store.js',
    # tar-parser.js — shared TAR archive parser with PAX extended header,
    # GNU long-name/link, GNU sparse, and base-256 numeric support.
    # Consumed by ZipRenderer (tar/tar.gz) and NpmRenderer (tgz tarballs).
    # Must load AFTER constants.js (PARSER_LIMITS) and BEFORE both renderers.
    'src/tar-parser.js',
    # encoded-content-detector.js is the class root; the helper modules under
    # src/decoders/ attach instance methods via Object.assign(...prototype, ...)
    # and one static (`unwrapSafeLink`). They MUST load AFTER the class root and
    # in the order below — see `_DETECTOR_FILES` for the canonical list, which
    # is reused by `_encoded_worker_bundle_src` to keep the worker bundle in
    # sync. See CONTRIBUTING.md → Encoded-content split.
    *_DETECTOR_FILES,
    # decoded-yara-filter.js — second-pass YARA gate for decoded encoded-
    # content payloads (Phase 1 of the deobfuscation-triage work). Reads
    # `window.WorkerManager.runDecodedYara` and exposes
    # `window.DecodedYaraFilter.applyDecodedYaraGate`. Must load AFTER
    # `_DETECTOR_FILES` (the EncodedContentDetector class root + helpers
    # are what produces the findings tree this gate walks) and AFTER
    # `worker-manager.js` (whose `runDecodedYara` is the only thing the
    # filter calls). The host site is `src/app/app-load.js`'s post-encoded
    # block; see the call site there for the integration shape.
    'src/decoded-yara-filter.js',
    # encoded-reassembler.js — whole-file reconstruction of scripts whose
    # obfuscation is spread across MULTIPLE parallel techniques (Phase 1
    # of the parallel-obfuscation UX improvement). Pure helper that takes
    # the detector's `encodedFindings` tree + the file's analysisText
    # and splices each deepest-decoded span back into the source at its
    # byte offset. Exposes `window.EncodedReassembler.build()` for the
    # host-side caller in `app-load.js`, and `mapReconToSource` /
    # `stripSentinels` helpers for the sidebar composite card.
    #
    # Must load AFTER `_DETECTOR_FILES` (needs the detector's finding
    # shape documented via `_pickDeepestTextNode`) and AFTER
    # `decoded-yara-filter.js` (same phase ordering — yara-gate runs
    # first so reassembly sees the YARA-retained subset) and BEFORE
    # `src/app/app-load.js` (the host integration site). No worker
    # bundle duplication — reassembly is main-thread only (Phase 1).
    'src/encoded-reassembler.js',
    'src/qr-decoder.js',

    'src/docx-parser.js',
    'src/style-resolver.js',
    'src/numbering-resolver.js',
    'src/content-renderer.js',
    'src/security-analyzer.js',
    'src/renderers/protobuf-reader.js',
    'src/renderers/ole-cfb-parser.js',
    'src/renderers/xlsx-renderer.js',
    'src/renderers/pptx-renderer.js',
    'src/renderers/odt-renderer.js',
    'src/renderers/odp-renderer.js',
    'src/renderers/ppt-renderer.js',
    'src/renderers/rtf-renderer.js',
    # archive-budget.js — aggregate archive-expansion budget shared across
    # every archive renderer in the recursive drill-down chain (PLAN H5).
    # Each renderer consults `app._archiveBudget` before pushing each row;
    # when the entry-count or aggregate-decompressed-bytes cap fires the
    # renderer breaks its enumeration loop and surfaces a single
    # `IOC.INFO` row. Reset by `App._handleFiles` (top-level loads only —
    # drill-downs intentionally share the budget). Must load AFTER
    # constants.js (reads PARSER_LIMITS) and BEFORE every archive
    # renderer (archive-tree.js + cab/rar/seven7/zip/jar/msix/browserext/
    # npm/iso/dmg/pkg).
    'src/archive-budget.js',
    # FolderFile — synthetic top-level "file" object for drag-dropped
    # directories, multi-file loose drops, and `webkitdirectory` picker
    # ingestion (see `App._handleFiles` in `src/app/app-core.js`). Holds
    # a flat `_loupeFolderEntries` list of leaf metadata + back-refs to
    # real `File` objects; carries a zero-byte `arrayBuffer()`. The
    # `FolderFile.fromEntries(rootName, sources)` static walker reads
    # `webkitGetAsEntry()` directories asynchronously up to
    # `PARSER_LIMITS.MAX_FOLDER_ENTRIES`. Used by `FolderRenderer`
    # (registered at the top of `RendererRegistry.ENTRIES`) and routed
    # through the standard drill-down path on click. Must load AFTER
    # constants.js (reads PARSER_LIMITS) and BEFORE app-core.js (the
    # ingress site that constructs FolderFile instances).
    'src/folder-file.js',
    # archive-tree.js — shared collapsible / searchable / sortable archive
    # browser. Must load BEFORE every renderer that uses `ArchiveTree`
    # (zip, jar, msix, browserext) so the class exists at construction time.
    'src/renderers/archive-tree.js',
    # FolderRenderer — synthetic root for drag-dropped directories +
    # multi-file loose drops + `webkitdirectory` picker (see
    # `src/folder-file.js`). Uses `ArchiveTree` for the body, so it MUST
    # load AFTER `archive-tree.js`. The renderer is registered at the
    # TOP of `RendererRegistry.ENTRIES` (magic predicate keyed on
    # `_loupeFolderEntries`), so order vs other renderers within this
    # block is not load-bearing — but it MUST be present BEFORE
    # `renderer-registry.js` runs `_bootstrap`, like every other entry.
    'src/renderers/folder-renderer.js',
    'src/renderers/zip-renderer.js',
    # Archive sub-formats that share the ArchiveTree browser but own their
    # own container parsers. Must load AFTER archive-tree.js (like zip) and
    # BEFORE renderer-registry.js so the registry's `_bootstrap` can attach
    # `static EXTS` / `canHandle()` to each class by global name.
    'src/renderers/cab-renderer.js',
    'src/renderers/rar-renderer.js',
    'src/renderers/seven7-renderer.js',

    'src/renderers/iso-renderer.js',
    'src/renderers/dmg-renderer.js',
    'src/renderers/pkg-renderer.js',
    'src/renderers/url-renderer.js',
    'src/renderers/onenote-renderer.js',
    'src/renderers/iqy-slk-renderer.js',
    'src/renderers/scf-renderer.js',
    'src/renderers/library-ms-renderer.js',
    'src/renderers/mof-renderer.js',
    'src/renderers/xslt-renderer.js',
    'src/renderers/wasm-renderer.js',
    'src/renderers/pcap-renderer.js',
    'src/renderers/wsf-renderer.js',
    'src/renderers/reg-renderer.js',
    'src/renderers/inf-renderer.js',
    'src/renderers/msi-renderer.js',
    # json-tree.js — shared lightweight collapsible JSON tree.
    # Exposes `window.JsonTree` with {render, pathGet, pathLabel,
    # maybeJson, tryParse, collectLeafPaths}. Used by GridViewer's drawer
    # (for auto-detected JSON cells in CSV / EVTX / SQLite / XLSX rows)
    # and by Timeline's "ƒx Extract" raw-cell popup. Must load BEFORE
    # grid-viewer.js (which references JsonTree at render time) and
    # BEFORE app-timeline.js (which replaced its local tree with this
    # shared one).
    'src/json-tree.js',
    # row-store.js — flat-buffer immutable row container shared by GridViewer
    # and the Timeline pipeline (worker + main thread). Fixes the OOM-tab-
    # crash failure mode the legacy `string[][]` accumulator hit on multi-
    # hundred-MB CSVs by replacing it with `{bytes: Uint8Array, offsets:
    # Uint32Array, rowCount}` chunks transferred zero-copy across the
    # worker boundary. Exposes `RowStore`, `RowStoreBuilder`, and the
    # `packRowChunk(rows, colCount)` helper the timeline worker uses to
    # pack `_parseCsv` batches before posting them. Must load AFTER
    # constants.js (consumes RENDER_LIMITS shape implicitly via callers)
    # and BEFORE grid-viewer.js (which reads RowStore via `setRows`) and
    # the renderers that build it (csv / sqlite / evtx). Same dual-bundle
    # pattern as `src/ioc-extract.js` — also concatenated into the
    # timeline parse-only worker bundle below.
    'src/row-store.js',
    # grid-viewer.js — bulletproof shared virtual-scroll grid (fixed-height
    # rows, absolute-positioned rows, right-side resizable drawer, unified
    # highlight state machine, chunked cooperative parse, mandatory
    # destroy()). Must load BEFORE every renderer that consumes it
    # (csv-renderer.js today; future evtx / xlsx / sqlite / json adopters).
    'src/renderers/grid-viewer.js',
    'src/renderers/csv-renderer.js',
    'src/renderers/json-renderer.js',
    'src/renderers/evtx-renderer.js',
    # evtx-detector.js — analysis-only EVTX threat-detection / IOC-extraction.
    # Extracted from evtx-renderer.js so the Timeline parse-only worker
    # bundle stays small: the worker never references this file,
    # and the analyzer runs on the main thread after the worker streams
    # parsed events back. EvtxRenderer.analyzeForSecurity now forwards to
    # EvtxDetector.analyzeForSecurity. Must load AFTER evtx-renderer.js
    # because the detector falls back to `new EvtxRenderer()._parse(bytes)`
    # when the caller doesn't supply prebuilt events.
    'src/evtx-detector.js',
    'src/renderers/sqlite-renderer.js',
    'src/renderers/doc-renderer.js',
    'src/renderers/msg-renderer.js',
    'src/renderers/eml-renderer.js',
    'src/renderers/lnk-renderer.js',
    'src/renderers/hta-renderer.js',
    'src/renderers/html-renderer.js',
    'src/renderers/pdf-renderer.js',
    'src/renderers/pe-renderer.js',
    'src/renderers/elf-renderer.js',
    'src/renderers/macho-renderer.js',
    'src/renderers/x509-renderer.js',
    'src/renderers/pgp-renderer.js',
    'src/renderers/jar-renderer.js',
    'src/renderers/svg-renderer.js',
    'src/renderers/osascript-renderer.js',
    'src/renderers/plist-renderer.js',
    'src/renderers/image-renderer.js',
    # virtual-text-view.js — virtual-scroll line-numbered text viewer used
    # by PlainTextRenderer. Must load BEFORE plaintext-renderer.js so the
    # `class VirtualTextView` global is defined when the renderer's
    # `_buildTextPane()` constructs it.
    'src/renderers/virtual-text-view.js',
    'src/renderers/plaintext-renderer.js',
    'src/renderers/clickonce-renderer.js',
    'src/renderers/msix-renderer.js',
    'src/renderers/browserext-renderer.js',
    'src/renderers/npm-renderer.js',
    # Registry — concatenated AFTER every renderer so its `_bootstrap()`
    # can attach `static EXTS` + `static canHandle()` to each class by
    # name, and BEFORE app-core.js so `App._loadFile` can call
    # `RendererRegistry.detect()` / `RendererRegistry.makeContext()`.
    'src/renderer-registry.js',
    # render-route.js — central renderer dispatch helper. Exposes
    # `window.RenderRoute.run(file, buf, app, rctx?)` which calls
    # `RendererRegistry.detect()`, invokes the matched
    # `App._rendererDispatch[id]` handler under the parser-watchdog
    # (`PARSER_LIMITS.RENDERER_TIMEOUT_MS`), normalises the renderer's
    # return into the canonical `RenderResult` shape (centralised
    # `lfNormalize` of `_rawText`/`textContent`), and stamps
    # `app.currentResult`. Must load AFTER renderer-registry.js (the
    # detect/makeContext entrypoints) and AFTER parser-watchdog.js (read
    # via the global), and BEFORE app-core.js so `App._loadFile` can call
    # `RenderRoute.run(...)` without a forward reference. The
    # `_rendererDispatch` table itself lives in `app-load.js`.
    'src/render-route.js',
    # app-bg.js — subtle per-theme animated landing-surface background
    # (plasma drift on light/dark, floating hearts on mocha, floating
    # kittens on latte, golden-ratio phyllotaxis spiral on solarized,
    # nothing at all on midnight / prefers-reduced-motion). Exposes
    # `window.BgCanvas = { init, setTheme }`. Must load BEFORE
    # app-core.js (which calls `BgCanvas.init()` inside `App.init()`)
    # and BEFORE app-ui.js (which calls `BgCanvas.setTheme(id)` from
    # `_setTheme()` after applying the body class).
    'src/app/app-bg.js',
    'src/app/app-core.js',

    # src/app/timeline/ — Timeline mode (CSV / TSV / EVTX / SQLite browser
    # history), split into 7 cohesive modules under src/app/timeline/.
    # Must load AFTER app-core.js (defines `App`) and AFTER grid-viewer.js /
    # csv-renderer.js / evtx-renderer.js / sqlite-renderer.js (all under
    # src/renderers/, already concatenated above) since TimelineView reuses
    # them directly. Load order within the group matters:
    #   1. timeline-helpers.js       — TIMELINE_* constants + `_tl*` pure helpers
    #   2. timeline-query.js         — query language tokenizer / parser /
    #                                  compiler (consumes helpers)
    #   3. timeline-query-editor.js  — `TimelineQueryEditor` class (consumes
    #                                  query module)
    #   4. timeline-view.js          — `class TimelineView` core: DOM, state,
    #                                  scroll grid, scrubber, histogram, plus
    #                                  the `static fromCsvAsync / fromEvtx /
    #                                  fromSqlite` factories
    #   5. timeline-detections.js    — TimelineView.prototype mixin: Detections
    #                                  + Entities (EVTX-only, in-view only)
    #   6. timeline-summary.js       — TimelineView.prototype mixin: AI/LLM-ready
    #                                  Markdown "⚡ Summarize" export covering
    #                                  the whole EVTX file (entities, detections,
    #                                  relationships, time clusters, plus an
    #                                  active-view sub-section). EVTX-only.
    #   7. timeline-drawer.js        — TimelineView.prototype mixin: JSON
    #                                  drawer + extracted-column helpers
    #   8. timeline-router.js        — App.prototype mixin: `_timelineTryHandle`
    #                                  / `_loadFileInTimeline` /
    #                                  `_clearTimelineFile` (the analyser-bypass
    #                                  routing entrypoint).
    # **Analysis-bypass property.** Nothing in src/app/timeline/ pushes IOCs,
    # mutates `app.findings`, runs `EncodedContentDetector`, or invokes
    # `pushIOC`. EVTX is the sole controlled exception: the router calls
    # `EvtxDetector.analyzeForSecurity` and threads the result into
    # TimelineView purely to feed the in-view Detections + Entities sections.
    'src/app/timeline/timeline-helpers.js',
    'src/app/timeline/timeline-query.js',
    'src/app/timeline/timeline-query-editor.js',
    # timeline-row-view.js — RowStore-shaped adapter wrapping
    # `{ baseStore, extractedCols, baseLen, idx }` so GridViewer can
    # consume Timeline rows without an intermediate `string[][]`
    # materialisation. Loads before timeline-view.js (which builds an
    # instance per render) and after row-store.js (already in
    # APP_JS_FILES; provides the `RowStore` class type the adapter
    # delegates to).
    'src/app/timeline/timeline-row-view.js',
    # timeline-dataset.js — owns the four parallel-array slots
    # (`store` / `_timeMs` / `_evtxEvents` / `_extractedCols`) and
    # enforces the `length === store.rowCount` invariant on every
    # mutation. Pure data class; no DOM, no globals beyond
    # `Float64Array`/`Array`. Loads AFTER row-store.js (uses RowStore
    # shape) and BEFORE timeline-view.js (which holds an instance and
    # forwards reads through it). NOT in the worker bundle — the
    # worker builds RowStore + timeMs + evtx events as separate
    # transferables and posts them; the dataset wrapper is consumed
    # only on the main thread when the view is constructed.
    'src/app/timeline/timeline-dataset.js',
    # timeline-wheel.js — outer-host scroll-continuation handler. Loads
    # before timeline-view.js so the installer (`window.installTimeline-
    # WheelContinuation`) is in scope when `_buildDOM` mounts `.tl-host`.
    'src/app/timeline/timeline-wheel.js',
    'src/app/timeline/timeline-view.js',
    # timeline-view-factories.js — TimelineView static-method mixin
    # (B2a). Hosts `TimelineView.fromCsvAsync` / `fromEvtx` /
    # `fromSqlite`; attaches via `Object.assign(TimelineView, {...})`.
    # MUST load AFTER timeline-view.js so the class identifier exists.
    'src/app/timeline/timeline-view-factories.js',
    # timeline-view-persist.js — TimelineView static-method mixin
    # (B2b). Hosts the ~30 `_loadXxx` / `_saveXxx` localStorage
    # helpers (bucket pref, grid/chart heights, sections, per-file
    # card widths/order/pinned cols, entities pinned/order, regex
    # extracts, autoextract-done marker, pivot spec, query, sus
    # marks). All keys live in `TIMELINE_KEYS` (timeline-helpers.js)
    # and are documented in the **Persistence Keys** table in
    # CONTRIBUTING.md — never rename without bumping that table.
    # Loads AFTER timeline-view.js for the same reason as factories.
    'src/app/timeline/timeline-view-persist.js',
    # timeline-view-filter.js — TimelineView prototype mixin (B2c).
    # Hosts the filter + chart-data pipeline: timestamp parsing,
    # `_applyQueryString`, `_recomputeFilter`, sus + detection bitmap
    # rebuilds, the window-only fast path, sync + cooperative-async
    # column stats, distinct-values lookup, the ignore-one-column
    # index helper, the bucket-size resolver, and `_computeChartData`
    # (the histogram bucketer). Hot paths — bodies are byte-identical
    # with the pre-B2c `timeline-view.js`. Loads AFTER timeline-view.js.
    'src/app/timeline/timeline-view-filter.js',
    # timeline-view-popovers.js — TimelineView prototype mixin (B2d).
    # Hosts the Add-Sus popover, right-click row context menu, the
    # generic single-slot popover/dialog teardowns
    # (`_closePopover` / `_closeDialog`), the Excel-style column
    # header menu, and the multi-tab Extraction dialog (Smart-scan
    # + Regex + Clicker). The tiny utilities `_ellipsis`,
    # `_copyToClipboard`, `_positionFloating` remain in
    # timeline-view.js because the chart and grid mixins also call
    # them. Loads AFTER timeline-view.js.
    'src/app/timeline/timeline-view-popovers.js',
    # timeline-view-render-chart.js — TimelineView prototype mixin
    # (B2f1). Hosts the entire chart paint stack: scrubber rendering
    # + drag, the histogram canvas paint (`_renderChartInto` and its
    # stable-stack-color cache), the red-line "you are here" cursor
    # (paint, drag, grid-scroll sync), the rubber-band selection
    # (`_installChartDrag`), the chart-only height grab-bar, and the
    # legend click/dbl-click/context handlers. Hot paths — bodies
    # are byte-identical with pre-B2f1 `timeline-view.js`. Loads
    # AFTER timeline-view.js.
    'src/app/timeline/timeline-view-render-chart.js',
    # timeline-view-render-grid.js — TimelineView prototype mixin
    # (B2f2). Twin to render-chart but for the lower half of the
    # timeline UI: the grid table mount (`_renderGridInto`) and the
    # column top-values "cards" strip (`_paintColumnCards` and its
    # drag/resize/sus-resolve helpers). Hot paths — bodies are
    # byte-identical with the pre-B2f2 `timeline-view.js`. Loads
    # AFTER timeline-view.js.
    'src/app/timeline/timeline-view-render-grid.js',
    # timeline-view-query-chips.js — TimelineView prototype mixin
    # (B2f3). Hosts the query-AST manipulation surface (the
    # click-pivot mutators every Include/Exclude/Only/Pin path
    # routes through), the chips strip renderer, the
    # `_addOrToggleChip` and friends thin wrappers, and the
    # Ctrl+Click multi-select helpers. The query bar is the single
    # source of truth for row filtering, so this mixin is the
    # central point where UI clicks become AST edits. Loads AFTER
    # timeline-view.js.
    'src/app/timeline/timeline-view-query-chips.js',
    # timeline-view-export.js — TimelineView prototype mixin (B2f4).
    # Hosts the pivot-table auto-pick + builder, the per-section
    # "⋯" / export menu dispatcher (`_onSectionAction`), the
    # `_forensic*` filename helpers, and every CSV / PNG exporter.
    # All five exporters route through `FileDownload.downloadText`
    # / `downloadBlob` and share the
    # `<source-stem>__<section>__<UTC>.<ext>` naming convention
    # — keeping them in one mixin is what makes that convention a
    # single locked-down place. Loads AFTER timeline-view.js.
    'src/app/timeline/timeline-view-export.js',
    'src/app/timeline/timeline-detections.js',
    'src/app/timeline/timeline-summary.js',
    'src/app/timeline/timeline-drawer.js',
    # timeline-view-autoextract.js — TimelineView prototype mixin (B2e).
    # Hosts the silent best-effort auto-extract pass that runs on first
    # open (`_autoExtractBestEffort`), its per-proposal applier
    # (`_applyAutoProposal`), and the read-only heuristic scanner
    # (`_autoExtractScan`) used both there AND by the Auto tab inside
    # the Extraction dialog. MUST load AFTER `timeline-drawer.js`
    # because it calls `_addJsonExtractedColNoRender` /
    # `_addRegexExtractNoRender` / `_rebuildExtractedStateAndRender`
    # (all hosted there).
    'src/app/timeline/timeline-view-autoextract.js',
    # timeline-view-geoip.js — TimelineView prototype mixin that adds a
    # `<ipcol>.geo` enrichment column next to each detected IPv4 column on
    # first open. Reads `this._app.geoip` (resolved in App.init()) for the
    # active provider — `BundledGeoip` (RIR IPv4→ISO-2) by default,
    # `MmdbReader` if the user has uploaded one via Settings. Idempotent
    # via a `kind: 'geoip'` sentinel + the same `_loadAutoExtractDoneFor`
    # marker the auto-extract pass uses (so deletion is sticky).
    # Must load AFTER timeline-view-autoextract.js so its constructor
    # call sequence remains the canonical "post-mount enrichment" tail.
    # Pure mixin via Object.assign(TimelineView.prototype, …).
    'src/app/timeline/timeline-view-geoip.js',
    'src/app/timeline/timeline-router.js',

    'src/app/app-load.js',
    'src/app/app-sidebar.js',
    # app-sidebar-focus.js holds the click-to-focus / highlighting engine:
    # _navigateToFinding, _findIOCMatches, _highlightMatchesInline, the
    # TreeWalker fallback, the 5 s idle clear, plus the Binary Metadata +
    # MITRE ATT&CK sections (their rows hang off the same navigation
    # plumbing). Split out of app-sidebar.js to keep the rendering half
    # below ~2 K lines. Must load AFTER app-sidebar.js because
    # _renderFindingsTableSection attaches click handlers that call into
    # _navigateToFinding defined here — but only by name (via `this`), so
    # the order is load-time, not lookup-time, and the Object.assign merge
    # simply lands both halves onto App.prototype.
    'src/app/app-sidebar-focus.js',
    'src/app/app-yara.js',
    'src/app/app-ui.js',
    # app-copy-analysis.js holds the 28 per-format _copyAnalysisXxx markdown
    # builders plus the _copyAnalysisFormatSpecific dispatcher they're called
    # from. Split out of app-ui.js to keep that file below ~2K lines. Must
    # load AFTER app-ui.js (which defines _formatMetadataValue + _sCaps that
    # these builders consume) and BEFORE app-settings.js (which overrides
    # _copyAnalysis itself with the Summary-budget variant).
    'src/app/app-copy-analysis.js',
    # app-settings.js attaches unified Settings/Help dialog methods onto
    # App.prototype. Must load AFTER app-ui.js because the Settings tab's
    # theme picker references the THEMES registry + _setTheme defined there.
    'src/app/app-settings.js',
    # app-selection-decode.js — the floating "🔍 Decode selection" chip that
    # spawns when the analyst click-drags a selection inside a supported text
    # viewer (`.plaintext-scroll`, `.html-source-pane`, `.hta-source-pane`,
    # `.url-source`, `.iqy-source`, `.eml-body`, `.json-tree`, `.csv-view`,
    # `.ps1-source`). Clicking the chip wraps the highlighted bytes in a
    # synthetic .txt File and dispatches via `App.openInnerFile(syn, null,
    # { _aggressiveDecode: true, … })` so the encoded-content pipeline runs
    # against just the selection — the deobfuscation sidebar then renders the
    # result like any other drill-down. Aggressive mode lowers finder
    # thresholds (consumed in `app-load.js`'s encoded-content scan block, then
    # threaded into `WorkerManager.runEncoded({ aggressive: true })` and the
    # `EncodedContentDetector` constructor). Pure mixin; no cross-mixin
    # dependencies; persistence key `loupe_deobf_selection_enabled`. Must
    # load AFTER `app-core.js` (defines `extendApp`) — the canonical late-
    # mixin slot.
    'src/app/app-selection-decode.js',
    # Dev-mode debug breadcrumbs ribbon. Pure mixin
    # (`Object.assign(App.prototype, {...})`) with no cross-mixin
    # dependencies; every consumer (`_initBreadcrumbs`, `_breadcrumb`,
    # `_toggleDevBreadcrumbs`) is guarded with
    # `typeof this._breadcrumb === 'function'` at the call sites
    # (`app-core.js::_reportNonFatal`, `app-load.js::_loadFile`,
    # `render-route.js`, `worker-manager.js`) so load order relative to
    # the other late mixins doesn't matter — only that it loads AFTER
    # `app-core.js` defines the `App` constructor. Kept last so the
    # diagnostics layer never hides a real bootstrap dependency.
    'src/app/app-breadcrumbs.js',
]

# `--test-api` builds append the `window.__loupeTest` surface AFTER every
# regular App mixin so it can reuse `extendApp(...)` and
# `_resetNavStack` / `_loadFile` / `_yaraScanInProgress`. Strictly opt-in:
# release builds never include this file. The leak-gate
# `_check_no_test_api_in_release` (run when TEST_API is False) re-validates
# the released bundle does not contain the `__loupeTest` /
# `__LOUPE_TEST_API__` markers.
#
# Note: `new App().init();` lives at the END of `app-breadcrumbs.js` and is
# already statically embedded in that file's source — so the test-api file
# loads AFTER the kick-off statement parsed, but BEFORE the app's first
# microtask resolves (everything is synchronous on the page-load tick), so
# the `(function(){ window.__loupeTest = … })()` IIFE at the bottom of
# `app-test-api.js` is guaranteed to see `window.app` already populated.
# That's why the IIFE polls instead of capturing once — the `init()` call
# may schedule a setTimeout / requestIdleCallback before the App handle is
# observable on the timeline; polling is cheap and tolerant.
if TEST_API:
    APP_JS_FILES.append('src/app/app-test-api.js')

# Group A — pre-App essentials. Emitted as a standalone <script> block
# *before* the heavy renderer vendors so its drag/drop/paste handlers
# beat the slowest vendor compile to the parser. See EARLY_JS_FILES
# above for the contract.
early_drop_js = '\n'.join(read(f) for f in EARLY_JS_FILES)


# ── Worker bundles ───────────────────────────────────────────────────────────
# `src/workers/*.worker.js` modules run inside `WorkerGlobalScope` (no DOM,
# no `window`, no `app.*`). They cannot share a `<script>` block with the
# main bundle, so each worker is read here, concatenated with the helpers
# it needs (in C1: `yara-engine.js`), and emitted as a single JS template-
# literal constant. `src/worker-manager.js` materialises a Worker at
# runtime via `URL.createObjectURL(new Blob([__YARA_WORKER_BUNDLE_SRC]))`.
#
# The worker files are deliberately NOT in `JS_FILES`:
#   • They must not run on the main thread.
#   • Excluding them keeps the existing build gates (risk pre-stamping,
#     bare-IOC types, `_rawText` LF-normalisation, worker-spawn allow-list)
#     from iterating worker-only code that has no business obeying any of
#     those rules.
# Worker source itself is still subject to the same `.clinerules` ban on
# `eval` / `new Function` / network — review at the file level, not via a
# build gate.
#
# These are defined here (before the Tier 5 block split below) so the
# `_block_srcs[0]` prepend sequence can reference them.
#
# See CONTRIBUTING.md → Worker subsystem.
def _esc_for_template(s: str) -> str:
    """Escape a string for a JS template literal (backticks, backslashes, ${)."""
    return s.replace('\\', '\\\\').replace('`', '\\`').replace('${', '\\${')

_yara_worker_bundle_src = read('src/yara-engine.js') + '\n' + read('src/workers/yara.worker.js')
yara_worker_js = (
    'const __YARA_WORKER_BUNDLE_SRC = `'
    + _esc_for_template(_yara_worker_bundle_src)
    + '`;\n'
)

# Timeline parse-only worker.
# Bundle order matters — the shim defines `RENDER_LIMITS`, `EVTX_COLUMN_ORDER`,
# `TIMELINE_MAX_ROWS`, the `IOC` proxy, and the `escalateRisk` / `pushIOC` /
# `lfNormalize` no-op stubs the renderer sources reach for at module load.
# `row-store.js` sits between the shim and the renderers so the worker-side
# `packRowChunk` / `RowStore` / `RowStoreBuilder` symbols are defined before
# `timeline.worker.js::_parseCsv` calls them; the SAME file is also in
# APP_JS_FILES (main bundle) so the host receives the chunks the worker
# packs and assembles them into a `RowStore` of its own.
# The renderers then concatenate in the same order the main bundle uses
# (csv → sqlite → evtx → pcap). The timeline.worker.js trailer carries the
# parse functions and the `self.onmessage` dispatcher. EvtxDetector and
# `PcapRenderer._analyzePcapInfo` are deliberately NOT invoked from the
# worker — analysis runs on the main thread (the analyser path uses
# `pushIOC` / `IOC.*` / `escalateRisk` globals that only the main bundle
# defines). The worker only calls `PcapRenderer._parsePcap` /
# `_parsePcapng` (pure parsers) plus `_streamPacketRows` / `_pktToRow`
# (pure formatters).
_timeline_worker_bundle_src = (
    read('src/workers/timeline-worker-shim.js') + '\n'
    + read('src/row-store.js') + '\n'
    + read('src/renderers/csv-renderer.js') + '\n'
    + read('src/renderers/sqlite-renderer.js') + '\n'
    + read('src/renderers/evtx-renderer.js') + '\n'
    + read('src/renderers/pcap-renderer.js') + '\n'
    + read('src/workers/timeline.worker.js')
)

# ── Dual-bundle invariant: row-store.js MUST be in BOTH bundles ─────────────
# `src/row-store.js` defines `RowStore` / `RowStoreBuilder` / `packRowChunk`,
# which are referenced by main-thread consumers (GridViewer, every grid
# renderer, the Timeline route) AND by the timeline parse-only worker
# (which packs rows into chunks via `packRowChunk` and posts them as
# transferable typed-array buffers). The two copies must stay in sync —
# they're literally the same source file concatenated into both bundles.
#
# These asserts make a future "let's split row-store into a worker-only
# fork" PR fail loudly at build time rather than silently producing a
# main bundle without the class (no Timeline) or a worker bundle without
# `packRowChunk` (no streaming). Cheap: the asserts run once per build,
# the strings have already been read into memory.
assert 'src/row-store.js' in APP_JS_FILES, (
    'BUILD INVARIANT: src/row-store.js must be present in APP_JS_FILES '
    '(main bundle). It is the sole producer of the RowStore class type '
    'every grid renderer hands to GridViewer; without it the main '
    'bundle has no row container and Timeline + every grid view fails '
    'to mount.'
)
_ROW_STORE_SRC_FOR_ASSERT = read('src/row-store.js')
assert _ROW_STORE_SRC_FOR_ASSERT in _timeline_worker_bundle_src, (
    'BUILD INVARIANT: src/row-store.js must be concatenated into '
    '_timeline_worker_bundle_src (timeline parse-only worker bundle). '
    'The worker calls packRowChunk to pack streamed CSV/EVTX/SQLite '
    'rows into transferable typed-array chunks; without the file in '
    'the worker bundle the worker throws ReferenceError on the first '
    "rows-chunk post and Timeline receives a zero-row store. See the "
    'comment block above this assertion for the dual-home rationale.'
)
del _ROW_STORE_SRC_FOR_ASSERT

timeline_worker_js = (
    'const __TIMELINE_WORKER_BUNDLE_SRC = `'
    + _esc_for_template(_timeline_worker_bundle_src)
    + '`;\n'
)

# EncodedContentDetector worker.
# Bundle order matters — the shim defines the IOC table, the
# `PARSER_LIMITS.MAX_UNCOMPRESSED` cap, and the `_trimPathExtGarbage` helper
# the detector reads at module load. pako is the Decompressor sync fallback
# (DecompressionStream isn't always present in WorkerGlobalScope on every
# browser); JSZip is used by the detector to validate embedded ZIP candidates
# and prune false-positive zlib hits. The encoded.worker.js trailer carries
# the `self.onmessage` dispatcher that drives `EncodedContentDetector.scan()`
# and eagerly fires `lazyDecode()` on every cheap finding.
# `_DETECTOR_FILES` (defined above) lists the class root + nine helper
# modules under `src/decoders/`; concatenating them in that order is
# equivalent to what `JS_FILES` does on the main thread.
_encoded_worker_bundle_src = (
    read('src/workers/encoded-worker-shim.js') + '\n'
    + pako_js + '\n'
    + jszip + '\n'
    + read('src/decompressor.js') + '\n'
    # url-normalize.js — pure helper consumed by `src/decoders/ioc-extract.js`
    # (inside _DETECTOR_FILES) for the obfuscated-URL deobfuscation pass.
    # Mirrors the host-bundle wiring; must load BEFORE the detector files.
    + read('src/util/url-normalize.js') + '\n'
    + '\n'.join(read(f) for f in _DETECTOR_FILES) + '\n'
    + read('src/workers/encoded.worker.js')
)

encoded_worker_js = (
    'const __ENCODED_WORKER_BUNDLE_SRC = `'
    + _esc_for_template(_encoded_worker_bundle_src)
    + '`;\n'
)

# IOC mass-extract worker.
# Bundle order matters — the shim defines the IOC table plus the host-side
# helpers (`looksLikeIpVersionString`, `stripDerTail`, `_trimPathExtGarbage`)
# that `src/ioc-extract.js` reads at module load. The shim AND the host
# `src/ioc-extract.js` are mirrored into the worker bundle: the host bundle
# already loads `src/ioc-extract.js` as a regular `JS_FILES` entry (so the
# `_extractInterestingStrings` shim can call into the same core
# synchronously), and the worker bundle re-includes it here. The
# `ioc-extract.worker.js` trailer carries the `self.onmessage` dispatcher.
#
# `scripts/check_shim_parity.py` diffs the shim's IOC table / helper bodies
# against `src/constants.js` so silent drift is caught at build time.
_ioc_extract_worker_bundle_src = (
    read('src/workers/ioc-extract-worker-shim.js') + '\n'
    # url-normalize.js — pure helper consumed by `src/ioc-extract.js`'s
    # processUrl for the obfuscated-URL deobfuscation pass. Mirrors the
    # host-bundle wiring; must load BEFORE `src/ioc-extract.js`.
    + read('src/util/url-normalize.js') + '\n'
    + read('src/ioc-extract.js') + '\n'
    + read('src/workers/ioc-extract.worker.js')
)
ioc_extract_worker_js = (
    'const __IOC_EXTRACT_WORKER_BUNDLE_SRC = `'
    + _esc_for_template(_ioc_extract_worker_bundle_src)
    + '`;\n'
)


# ── Tier 5 — split the App bundle into FOUR inline `<script>` blocks ─────────

# Browsers can yield to layout / paint / event delivery **between**
# `<script>` tags. Splitting the App into four smaller blocks keeps total
# CPU the same but eliminates the single ≥50 ms compile task that drags
# TBT. Same load order as before — only the **emission shape** changes
# (one `<script>` per block instead of one mega-block).
#
# Boundary rules:
#   • Block 1 (primitives & shared helpers) — every entry up to but not
#     including the first docx renderer dep. Gets the worker-bundle
#     constants (`__YARA_WORKER_BUNDLE_SRC` / `__TIMELINE_WORKER_BUNDLE_SRC`
#     / `__ENCODED_WORKER_BUNDLE_SRC`), `LOUPE_VERSION`, and
#     `DEFAULT_YARA_RULES` prepended at the very top so `worker-manager.js`
#     and `app-core.js` find them at module-eval time.
#   • Block 2 (renderers + dispatch) — every renderer plus the docx
#     helper chain (`docx-parser.js`, `style-resolver.js`,
#     `numbering-resolver.js`, `content-renderer.js`,
#     `security-analyzer.js`), `renderer-registry.js`, `render-route.js`.
#   • Block 3 (App shell, part 1) — `app-bg.js`, `app-core.js`, every
#     `src/app/timeline/*.js`, `app-load.js`, `app-sidebar.js`,
#     `app-sidebar-focus.js`.
#   • Block 4 (App shell, part 2 + kick-off) — `app-yara.js`,
#     `app-ui.js`, `app-copy-analysis.js`, `app-settings.js`,
#     `app-breadcrumbs.js`. The trailing `new App().init();` lives at the
#     end of `app-breadcrumbs.js` — the LAST file in `APP_JS_FILES` and
#     therefore the LAST line of Block 4 — so every
#     `Object.assign(App.prototype, …)` mixin has landed its methods on
#     the prototype before `App.init()` runs.
#
# `Object.assign(App.prototype, …)` ordering invariants preserved by
# construction: every override sits **later** in `APP_JS_FILES` than the
# methods it overrides, and `APP_JS_FILES` is split here by **index range**
# (not re-ordered), so the across-block sequence is identical to today's
# single-block sequence. The block boundaries are aligned to natural
# subsystem seams so no Object.assign mixin straddles a boundary in a way
# that matters: `app-bg.js` (defines `BgCanvas`) is the first entry of
# Block 3; `app-core.js` and `app-ui.js` (both call into `BgCanvas`) are
# in Blocks 3 and 4 respectively, both after Block 3 starts. ✅
#
# Build gates (`_check_risk_pre_stamping`, `_check_bare_ioc_types`,
# `_check_raw_text_normalisation`, `_check_worker_spawn_allowlist`)
# iterate `EARLY_JS_FILES + APP_JS_FILES` so coverage is preserved across
# the split — they read the source list, not the emitted blocks.
def _index_of(rel):
    """Locate a file in `APP_JS_FILES`. Fails the build if missing — keeps
    the boundary anchors honest if a future refactor removes / renames
    one of the boundary files."""
    try:
        return APP_JS_FILES.index(rel)
    except ValueError:
        raise SystemExit(
            f"Tier-5 block split: boundary anchor {rel!r} missing from "
            "APP_JS_FILES. Re-pick a boundary or update _index_of() callers."
        )

_BLOCK2_START = _index_of('src/docx-parser.js')
_BLOCK3_START = _index_of('src/app/app-bg.js')
_BLOCK4_START = _index_of('src/app/app-yara.js')

APP_BLOCKS = [
    APP_JS_FILES[:_BLOCK2_START],                # Block 1 — primitives
    APP_JS_FILES[_BLOCK2_START:_BLOCK3_START],   # Block 2 — renderers + dispatch
    APP_JS_FILES[_BLOCK3_START:_BLOCK4_START],   # Block 3 — App shell, part 1
    APP_JS_FILES[_BLOCK4_START:],                # Block 4 — App shell, part 2 + kick-off
]

# Sanity check — the four slices must cover every entry exactly once.
_covered = APP_BLOCKS[0] + APP_BLOCKS[1] + APP_BLOCKS[2] + APP_BLOCKS[3]
assert _covered == APP_JS_FILES, (
    "Tier-5 block split: APP_BLOCKS slices don't cover APP_JS_FILES exactly."
)

_block_srcs = ['\n'.join(read(f) for f in g) for g in APP_BLOCKS]

# Stamp `LOUPE_VERSION`, the YARA-rules constant, and the three worker-
# bundle constants at the top of Block 1. Order matters at runtime:
# `worker-manager.js` (inside Block 1) reads the bundle constants at
# module-eval time, and `app-core.js` (inside Block 3) reads
# `LOUPE_VERSION` and `DEFAULT_YARA_RULES`.
_block_srcs[0] = (
    f"const LOUPE_VERSION = '{VERSION}';\n"
    + (f"const __LOUPE_TEST_API__ = true;\n" if TEST_API else '')
    + default_yara_js
    + geoip_bundle_js          # __GEOIP_BUNDLE_B64 — read by src/geoip/bundled-geoip.js
    + yara_worker_js
    + timeline_worker_js
    + encoded_worker_js
    + ioc_extract_worker_js
    + _block_srcs[0]
)

# Emit one `<script>` tag per block. The `\n` padding around each block's
# content keeps the rendered HTML legible without affecting JS semantics.
app_blocks_html = '\n'.join(f'  <script>\n{src}\n  </script>' for src in _block_srcs)


# ── Build gate: risk pre-stamping ─────────────────────────────────────────────
# `.clinerules` forbids writing `findings.risk = '<tier>'` directly outside the
# `escalateRisk()` helper in `src/constants.js`. Pre-stamping produces
# false-positive risk colouring on benign samples — every escalation must come
# from evidence pushed onto `externalRefs` / `interestingStrings`. See
# CONTRIBUTING.md → Risk Tier Calibration / Tripwires.
_RISK_PRE_STAMP_RE = _re.compile(r"""\.risk\s*=\s*['"](low|medium|high|critical|info)['"]""")
_RISK_GATE_ALLOWLIST = { 'src/constants.js' }

def _check_risk_pre_stamping():
    violations = []
    for rel in EARLY_JS_FILES + APP_JS_FILES:
        if rel in _RISK_GATE_ALLOWLIST:
            continue
        text = read(rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            # Skip pure comment lines so reference snippets in docstrings don't trip the gate.
            stripped = line.lstrip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            m = _RISK_PRE_STAMP_RE.search(line)
            if m:
                violations.append(f"{rel}:{lineno}: {line.strip()}")
    if violations:
        msg = (
            "Build gate failed — direct risk pre-stamping detected. Use "
            "`escalateRisk(findings, tier)` from src/constants.js instead.\n"
            "Offending sites:\n  " + "\n  ".join(violations)
        )
        raise SystemExit(msg)

_check_risk_pre_stamping()


# ── Build gate: bare-string IOC `type:` values ────────────────────────────────
# `.clinerules` requires every IOC entry's `type` field to be an `IOC.*`
# constant from the table in `src/constants.js` (e.g. `IOC.URL`, not the bare
# string `'URL'` or `'url'`). Bare-string types silently break sidebar
# filtering — the Detections / IOCs filter is keyed on the `IOC.*` token, so a
# bare string yields a row that exists in `findings` but never appears under
# any sidebar tab.
#
# The gate matches the canonical IOC-entry shape: an object literal that
# carries BOTH a `type:` key with a bare string AND a `severity:` key on the
# same source line. That two-key fingerprint is unique to IOC pushes — it
# does not appear in:
#   • YaraEngine string-kind objects (`{ type: 'text', ... }`, no `severity`)
#   • plist `_type` discriminators (different key, no `severity`)
#   • SheetJS `XLSX.read({ type: 'array' })` (no `severity`)
#   • STIX 2.1 / MISP export schema (`type: 'indicator'`, no `severity` key)
#   • renderer-internal display DTOs in wsf-renderer / x509-renderer (no
#     `severity` key — those structs are re-fanned out into real `IOC.*`
#     pushes by the same renderer)
#
# So the gate is the conjunction `type: '<string>' ... severity:` on a single
# line. False positives can be silenced by either:
#   (a) replacing the bare string with the `IOC.*` constant (the spec-correct
#       fix in the overwhelming majority of cases), or
#   (b) renaming the discriminator field if it genuinely is a non-IOC DTO.
#
# Allow-list: only `src/constants.js` is exempt — that's where the `IOC.*`
# table itself defines the canonical strings.
_BARE_IOC_TYPE_RE = _re.compile(
    r"""\btype:\s*['"][A-Za-z][A-Za-z _]*['"][^}\n]*?\bseverity\s*:"""
)
_IOC_GATE_ALLOWLIST = { 'src/constants.js' }

def _check_bare_ioc_types():
    violations = []
    for rel in EARLY_JS_FILES + APP_JS_FILES:
        if rel in _IOC_GATE_ALLOWLIST:
            continue
        text = read(rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            # Skip pure comment lines so reference snippets in docstrings don't trip the gate.
            stripped = line.lstrip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            # Only single-line IOC entries — the multi-line case routes through
            # `pushIOC()` which centralises validation in src/constants.js.
            m = _BARE_IOC_TYPE_RE.search(line)
            if m:
                violations.append(f"{rel}:{lineno}: {line.strip()}")
    if violations:
        msg = (
            "Build gate failed — bare-string IOC `type:` value detected.\n"
            "Use the canonical `IOC.*` constant from src/constants.js (e.g. "
            "`IOC.URL`, `IOC.IP`, `IOC.PATTERN`) instead of a bare string —\n"
            "bare-string types silently break sidebar IOC filtering. See "
            "CONTRIBUTING.md → Renderer Contract item #5 / IOC Push Checklist.\n"
            "Offending sites:\n  " + "\n  ".join(violations)
        )
        raise SystemExit(msg)

_check_bare_ioc_types()


# ── Build gate: `_rawText` LF-normalisation ───────────────────────────────────
# `.clinerules` and `CONTRIBUTING.md` (Tripwires + Renderer Contract rule #3)
# require every `*._rawText = <expr>` write to route through `lfNormalize()`
# from `src/constants.js`. The sidebar's click-to-focus engine searches the
# post-render DOM for IOC strings using offsets computed from `_rawText`; the
# browser collapses bare-CR / CRLF sequences in the rendered DOM, so any CR
# leaking into `_rawText` desynchronises every match offset after the first
# CR. `lfNormalize(s) = s.replace(/\r\n?/g, '\n')` is idempotent for
# already-LF-only inputs and cheap enough to apply unconditionally.
#
# The gate matches `<lhs>._rawText = <rhs>` and rejects any RHS that does not
# begin with `lfNormalize(`. The accepted shape is deliberately narrow: empty
# strings (`''`), join-on-`\n` (`arr.join('\n')`), and pure passthroughs from
# another `_rawText` MUST also be wrapped (every renderer site already does so
# — see `src/constants.js::lfNormalize` docstring).
#
# Allow-list: only `src/constants.js` is exempt, since it defines the helper.
_RAW_TEXT_LHS_RE = _re.compile(r"\._rawText\s*=\s*(.+?)\s*;?\s*$")
_RAW_TEXT_GATE_ALLOWLIST = { 'src/constants.js' }

def _check_raw_text_normalisation():
    violations = []
    for rel in EARLY_JS_FILES + APP_JS_FILES:
        if rel in _RAW_TEXT_GATE_ALLOWLIST:
            continue
        text = read(rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            # Skip pure comment lines so reference snippets in docstrings don't trip the gate.
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            m = _RAW_TEXT_LHS_RE.search(line)
            if not m:
                continue
            rhs = m.group(1).lstrip()
            if not rhs.startswith('lfNormalize('):
                violations.append(f"{rel}:{lineno}: {line.strip()}")
    if violations:
        msg = (
            "Build gate failed — `_rawText` write not LF-normalised.\n"
            "Wrap the RHS in `lfNormalize(...)` from src/constants.js — bare\n"
            "CRLF / CR sequences leaking into `_rawText` desynchronise every\n"
            "click-to-focus offset after the first CR. See CONTRIBUTING.md →\n"
            "Tripwires and Renderer Contract rule #3.\n"
            "Offending sites:\n  " + "\n  ".join(violations)
        )
        raise SystemExit(msg)

_check_raw_text_normalisation()


# ── Build gate: worker-spawn allow-list ───────────────────────────────────────
# `.clinerules` and `CONTRIBUTING.md` (Architecture & Signal Chain → Worker
# subsystem) require every Web Worker spawn to live inside an allow-listed
# module — either a worker module itself (`src/workers/*.worker.js`) or the
# central host-side spawner (`src/worker-manager.js`).
#
# The gate matches `new Worker(` over every entry in `JS_FILES`. pdf.js
# spawns its own worker from vendored code, which `build.py` reads
# separately and never lists in `JS_FILES`, so the gate cannot
# false-positive on it. The gate keeps stray `new Worker(...)` calls
# outside the worker subsystem from sneaking into the bundle.
_NEW_WORKER_RE = _re.compile(r"\bnew\s+Worker\s*\(")
def _is_worker_allowlisted(rel: str) -> bool:
    # Allow worker modules and the central spawner.
    if rel == 'src/worker-manager.js':
        return True
    if rel.startswith('src/workers/') and rel.endswith('.worker.js'):
        return True
    return False

def _check_worker_spawn_allowlist():
    violations = []
    for rel in EARLY_JS_FILES + APP_JS_FILES:
        if _is_worker_allowlisted(rel):
            continue
        text = read(rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            # Skip pure comment lines so reference snippets in docstrings don't trip the gate.
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            m = _NEW_WORKER_RE.search(line)
            if m:
                violations.append(f"{rel}:{lineno}: {line.strip()}")
    if violations:
        msg = (
            "Build gate failed — `new Worker(` outside the worker-spawn allow-list.\n"
            "Worker modules must live in src/workers/<name>.worker.js and be\n"
            "spawned only from src/worker-manager.js. See CONTRIBUTING.md →\n"
            "Architecture & Signal Chain → Worker subsystem and SECURITY.md →\n"
            "Full Content-Security-Policy (`worker-src blob:`).\n"
            "Offending sites:\n  " + "\n  ".join(violations)
        )
        raise SystemExit(msg)

_check_worker_spawn_allowlist()


# ── Build gate: silent-catch sweep ───────────────────────────────────────────
# `catch (...) {}` (an empty body) inside the file-load chain swallows parser
# faults: the renderer dies in async work, the catch eats the error, and the
# sidebar paints from a half-built `findings` object with no breadcrumb in
# console / IOC list. The canonical replacement is `App._reportNonFatal(where,
# err, opts?)` (defined in src/app/app-core.js) which:
#   • console.warn's a structured `[loupe] <where>: <message>` breadcrumb
#   • optionally pushes an `IOC.INFO` row so the analyst can see it failed
#   • re-schedules a microtask-coalesced sidebar refresh
# The gate is scoped to the load chain (`src/app/app-load.js`,
# `src/app/app-yara.js`) — renderers, cosmetic UI, and settings are out of
# scope and continue to use their existing `try { … } catch (_) { /* … */ }`
# patterns. Renderer-side breadcrumbs are picked up by the dev-mode debug
# breadcrumbs ribbon (`src/app/app-breadcrumbs.js`) instead.
#
# Escape hatch: append `// loupe-allow:silent-catch` to a line that legitimately
# wants an empty body (we don't have any today; the marker is forward-looking).
LOAD_CHAIN_FILES = ('src/app/app-load.js', 'src/app/app-yara.js')
_SILENT_CATCH_RE = _re.compile(r"\bcatch\s*\([^)]*\)\s*\{\s*\}")

def _check_silent_catches():
    violations = []
    for rel in LOAD_CHAIN_FILES:
        text = read(rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            # Skip pure comment lines so reference snippets in docstrings
            # don't trip the gate.
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            if '// loupe-allow:silent-catch' in line:
                continue
            if _SILENT_CATCH_RE.search(line):
                violations.append(f"{rel}:{lineno}: {line.strip()}")
    if violations:
        msg = (
            "Build gate failed — empty `catch (...) {}` in load chain. "
            "Route non-fatal failures through App._reportNonFatal(where, err, opts?) "
            "so the breadcrumb reaches console + (optionally) the sidebar IOC list. "
            "See CONTRIBUTING.md → Tripwires & Build Gates → Silent-catch sweep.\n"
            "Offending sites:\n  " + "\n  ".join(violations)
        )
        raise SystemExit(msg)

_check_silent_catches()


# ── Build gate: localStorage access must funnel through `safeStorage` ─────────
# `src/storage.js` exposes `window.safeStorage.{get,set,remove,getJSON,
# setJSON,keys,removeMatching}`, which centralises the try/catch ceremony and
# JSON parse/stringify dance every storage call site used to repeat. Direct
# `localStorage.*` access outside that file (a) duplicates the boilerplate,
# (b) silently varies its error handling between consumers, and (c) blocks any
# future migration to IndexedDB / encrypted profile export.
#
# The gate matches `\blocalStorage\b` over every entry in `EARLY_JS_FILES +
# APP_JS_FILES`. Allow-listed: only `src/storage.js` itself, which IS the
# wrapper. The FOUC theme bootstrap in `scripts/build.py` is hand-written
# inline JS in `<head>` and runs BEFORE any `src/` module — it stays direct
# (`localStorage.getItem('loupe_theme')`), is wrapped in its own try/catch,
# and lives outside `src/` so the gate doesn't see it.
#
# Escape hatch: append `// loupe-allow:safe-storage` to a line that has a
# legitimate reason to bypass the wrapper (we don't have any today; the
# marker is forward-looking and consistent with the silent-catch gate's
# escape hatch).
_LOCAL_STORAGE_RE = _re.compile(r"\blocalStorage\b")
_STORAGE_GATE_ALLOWLIST = { 'src/storage.js' }

def _check_storage_access():
    violations = []
    for rel in EARLY_JS_FILES + APP_JS_FILES:
        if rel in _STORAGE_GATE_ALLOWLIST:
            continue
        text = read(rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            # Skip pure comment lines so docstring references don't trip the gate.
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            if '// loupe-allow:safe-storage' in line:
                continue
            if _LOCAL_STORAGE_RE.search(line):
                violations.append(f"{rel}:{lineno}: {line.strip()}")
    if violations:
        msg = (
            "Build gate failed — direct `localStorage` access detected.\n"
            "Use `safeStorage.{get,set,remove,getJSON,setJSON,keys,removeMatching}`\n"
            "from src/storage.js instead — it centralises the try/catch ceremony\n"
            "and JSON parse/stringify dance. See CONTRIBUTING.md →\n"
            "Persistence keys / safeStorage.\n"
            "Offending sites:\n  " + "\n  ".join(violations)
        )
        raise SystemExit(msg)

_check_storage_access()


# ── Build gate: App.prototype mixins must funnel through `extendApp` ──────────
# `src/app/app-core.js` defines the global `extendApp(obj)` helper which:
#   • runs `Object.assign(App.prototype, obj)` like the old pattern, and
#   • throws if `obj` carries a key that is already defined on `App.prototype`,
#     catching the silent late-bind override that two mixins on the same
#     method name produced before. Today no two mixins collide, but the
#     bundle has 9 of them and the dependency-by-load-order convention is
#     fragile under refactoring. The gate keeps any future
#     `Object.assign(App.prototype, …)` from sneaking in and bypassing the
#     collision check.
#
# Allow-listed: only `src/app/app-core.js` itself, which IS the helper plus
# the place where `App` is constructed.
_APP_PROTOTYPE_ASSIGN_RE = _re.compile(r"Object\.assign\s*\(\s*App\.prototype\b")
_APP_MIXIN_GATE_ALLOWLIST = { 'src/app/app-core.js' }

def _check_app_mixin_collisions():
    violations = []
    for rel in EARLY_JS_FILES + APP_JS_FILES:
        if rel in _APP_MIXIN_GATE_ALLOWLIST:
            continue
        text = read(rel)
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            # Skip pure comment lines so docstring references don't trip the gate.
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            if _APP_PROTOTYPE_ASSIGN_RE.search(line):
                violations.append(f"{rel}:{lineno}: {line.strip()}")
    if violations:
        msg = (
            "Build gate failed — bare `Object.assign(App.prototype, …)` detected.\n"
            "Use `extendApp({...})` from src/app/app-core.js instead — it runs\n"
            "the same Object.assign but throws if any key already exists on\n"
            "App.prototype, catching silent late-bind overrides between mixins.\n"
            "See CONTRIBUTING.md → Gotchas / App.prototype mixin pattern.\n"
            "Offending sites:\n  " + "\n  ".join(violations)
        )
        raise SystemExit(msg)

_check_app_mixin_collisions()


# ── Build gate: no `*/` inside backtick spans of block comments ───────────────
# Block comments in JS are terminated by `*/` regardless of what surrounds
# them — backticks DO NOT make `*/` an inert sub-string. The H8 work added
# JSDoc reference paragraphs that cite the YARA category marker as
# `` `/*! @loupe-category: <NAME> */` ``; the `*/` inside that backtick
# span closed the JSDoc early, the parser then read the rest of the line
# as live code, hit the next backtick (a real template literal further
# down the file), and bombed with
#       `Uncaught SyntaxError: expected property name, got template literal`
# at runtime. The build doesn't run a JS parser over the bundle, so all
# four `make.py` steps stayed green while the emitted page was broken.
#
# This gate walks each JS source file with a tiny block-comment tracker
# and bails on any line that, while inside a `/* … */` block comment,
# contains a backtick-span (`…`) whose contents include `*/`. The
# canonical fix is to escape one of the slashes (`*\/`) — readable in
# editors and JSDoc tooling, not the comment terminator token.
#
# Escape hatch: `// loupe-allow:backtick-comment-term` on the offending
# line. None today.
_BACKTICK_COMMENT_TERM_RE = _re.compile(r"`[^`\n]*\*/[^`\n]*`")

def _check_backtick_comment_terminator():
    violations = []
    for rel in EARLY_JS_FILES + APP_JS_FILES:
        text = read(rel)
        in_block = False
        for lineno, line in enumerate(text.splitlines(), start=1):
            # Track block-comment open/close at line granularity. Good enough
            # for this gate — multi-line block comments (the JSDoc shape that
            # bit us) are exactly what we want to scan.
            i = 0
            line_in_block = in_block
            while i < len(line):
                if not in_block:
                    j = line.find('/*', i)
                    if j < 0:
                        break
                    in_block = True
                    i = j + 2
                else:
                    j = line.find('*/', i)
                    if j < 0:
                        break
                    in_block = False
                    i = j + 2

            # Was any portion of this line inside a block comment? If so,
            # check it for the offending backtick-span pattern.
            if (line_in_block or in_block) and _BACKTICK_COMMENT_TERM_RE.search(line):
                if '// loupe-allow:backtick-comment-term' in line:
                    continue
                violations.append(f"{rel}:{lineno}: {line.strip()}")
    if violations:
        msg = (
            "Build gate failed — `*/` inside a backtick span within a block\n"
            "comment closes the comment early and turns subsequent backticks\n"
            "into a real template literal at runtime. Escape the slash so\n"
            "the comment doesn't terminate (e.g. `*\\/` instead of `*/`).\n"
            "See CONTRIBUTING.md → Tripwires & Build Gates → Backtick comment\n"
            "terminator.\n"
            "Offending sites:\n  " + "\n  ".join(violations)
        )
        raise SystemExit(msg)

_check_backtick_comment_terminator()


# File extensions accepted by the open-file input. Keep as a list for sanity.
ACCEPT_EXTS = [
    '.docx','.docm','.xlsx','.xlsm','.xls','.ods','.pptx','.pptm','.ppt','.odt','.odp',
    '.csv','.tsv','.doc','.msg','.eml','.lnk','.hta','.rtf','.pdf',
    '.zip','.gz','.gzip','.tar','.tgz','.rar','.7z','.cab','.iso','.img','.one',
    '.dmg','.pkg','.mpkg',
    '.url','.webloc','.website','.iqy','.slk','.wsf','.wsc','.wsh','.reg','.inf','.sct','.msi',
    '.html','.htm','.mht','.mhtml','.xhtml','.xml','.vbs','.vbe','.js','.jse','.ps1','.bat','.cmd',
    '.ics','.vcf','.txt','.log','.json','.ndjson','.jsonl','.ini','.cfg','.yml','.yaml',
    '.jpg','.jpeg','.png','.gif','.bmp','.webp','.ico','.tif','.tiff','.avif','.svg',
    '.evtx','.sqlite','.db','.exe','.dll','.sys','.scr','.cpl','.ocx','.drv','.com','.xll',
    '.elf','.so','.o','.dylib','.bundle',
    '.pem','.der','.crt','.cer','.p12','.pfx','.key',
    '.pgp','.gpg','.asc','.sig',
    '.jar','.war','.ear','.class',
    '.applescript','.jxa','.scpt','.scptd','.plist',
    '.application','.manifest',
    '.msix','.msixbundle','.appx','.appxbundle','.appinstaller',
    '.crx','.xpi',
]
accept_attr = ','.join(ACCEPT_EXTS)

HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data: blob:; frame-src blob:; worker-src blob:; form-action 'none'; base-uri 'none'; object-src 'none';">
  <meta name="description" content="Loupe — a 100% offline, single-file security analyser for suspicious files. No server, no uploads, no tracking.">
  <title>Loupe</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🕵🏻</text></svg>">
  <style>{css}</style>
  <!-- ── FOUC-prevention theme bootstrap ──────────────────────────────────
       Runs synchronously before <body> is painted so the correct theme
       class lives on <body> from the very first frame. Without this the
       page would flash the default light palette for a few hundred ms
       while app-ui.js loaded, even for users who had saved a dark theme.
       Logic mirrors _initTheme in src/app/app-ui.js:
         1. saved `localStorage.loupe_theme`  (if valid)
         2. OS `prefers-color-scheme: light`   (first boot only)
         3. hard-coded fallback ('dark')
       The theme IDs must be kept in sync with the THEMES array in
       src/app/app-ui.js — a stale entry here just means the bootstrap
       refuses to apply that theme and _initTheme does so one tick later.
       Allowed by CSP: `script-src 'unsafe-inline'` is already granted for
       the rest of the single-file bundle, so no extra relaxation. -->
  <script>
    (function () {{
      try {{
        var THEME_IDS = ['light','dark','midnight','solarized','mocha','latte'];
        var DARK_THEMES = {{ dark:1, midnight:1, solarized:1, mocha:1 }};
        var saved = null;
        try {{ saved = localStorage.getItem('loupe_theme'); }} catch (_) {{}}
        var id;
        if (saved && THEME_IDS.indexOf(saved) !== -1) {{
          id = saved;
        }} else {{
          var prefersLight = false;
          try {{
            prefersLight = !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches);
          }} catch (_) {{}}
          id = prefersLight ? 'light' : 'dark';
        }}
        var b = document.body || document.documentElement;
        // <body> doesn't exist yet — stash on <html> and re-apply once body lands
        var applyTo = function (el) {{
          for (var i = el.classList.length - 1; i >= 0; i--) {{
            var cls = el.classList[i];
            if (cls.indexOf('theme-') === 0) el.classList.remove(cls);
          }}
          el.classList.add('theme-' + id);
          el.classList.toggle('dark', !!DARK_THEMES[id]);
        }};
        // Once <body> exists we need the classes there, not on <html>.
        // If this script runs before </head> we schedule a one-shot
        // observer that copies the classes across the moment <body> is parsed.
        if (document.body) {{
          applyTo(document.body);
        }} else {{
          applyTo(document.documentElement);
          var mo = new MutationObserver(function () {{
            if (document.body) {{
              applyTo(document.body);
              document.documentElement.classList.remove('dark');
              for (var i = document.documentElement.classList.length - 1; i >= 0; i--) {{
                var cls = document.documentElement.classList[i];
                if (cls.indexOf('theme-') === 0) document.documentElement.classList.remove(cls);
              }}
              mo.disconnect();
            }}
          }});
          mo.observe(document.documentElement, {{ childList: true }});
        }}
      }} catch (_) {{ /* never let theme bootstrap break the page */ }}
    }})();
  </script>
</head>
<body>


  <!-- ── Toolbar ─────────────────────────────────────────────────────── -->
  <div id="toolbar">
    <span id="app-title"><span class="logo">🕵🏻 Loupe</span></span>
    <div class="tb-separator"></div>
    <!-- File operations group -->
    <div class="tb-group" id="file-ops">
      <button class="tb-btn" id="btn-open" title="Open file (or drag &amp; drop)">📁 Open File</button>
      <button class="tb-btn hidden" id="btn-close" title="Close file (Esc)">✕</button>
      <nav class="hidden" id="breadcrumbs" aria-label="File path"></nav>
    </div>
    <div class="tb-spacer"></div>
    <div class="tb-separator"></div>
    <button class="tb-btn tb-icon-btn" id="btn-security" title="Toggle security sidebar (S)">🛡</button>
    <div class="tb-separator"></div>
    <button class="tb-btn tb-icon-btn" id="btn-yara" title="YARA rule editor (Y)">📐</button>
    <button class="tb-btn tb-icon-btn" id="btn-settings" title="Settings (,) · Help (?)">⚙</button>
    <input type="file" id="file-input" accept="{accept_attr}" style="display:none">

  </div>

  <!-- ── Main area (viewer + sidebar side-by-side) ──────────────────── -->
  <div id="main-area">

    <!-- viewer -->
    <div id="viewer">
      <div id="viewer-toolbar" class="hidden">
        <div class="vt-group">
          <button class="tb-btn tb-action-btn tb-accent-btn" id="btn-copy-analysis" title="Copy AI/SOC summary to clipboard (Ctrl+Enter)">⚡ Summarize</button>
          <div class="tb-menu-wrap">
            <button class="tb-btn tb-action-btn" id="btn-export" aria-haspopup="menu" aria-expanded="false" title="Export analysis in various formats">📤 Export <span class="tb-caret">▾</span></button>
            <div class="tb-menu hidden" id="export-menu" role="menu"></div>
          </div>
        </div>
        <div class="vt-search">
          <input type="text" id="doc-search" placeholder="Search content…" spellcheck="false">
          <button class="vt-search-nav" id="doc-search-prev" title="Previous match (Shift+Enter)">◀</button>
          <button class="vt-search-nav" id="doc-search-next" title="Next match (Enter)">▶</button>
          <span id="doc-search-count"></span>
        </div>
        <div class="vt-spacer"></div>
        <div class="vt-zoom">
          <button class="tb-btn vt-zoom-btn" id="btn-zoom-out" title="Zoom out">−</button>
          <span id="zoom-level">100%</span>
          <button class="tb-btn vt-zoom-btn" id="btn-zoom-in" title="Zoom in">+</button>
        </div>
      </div>
      <div id="drop-zone">
        <span class="dz-icon">📄</span>
        <div class="dz-text">Drop a file here to analyse</div>
        <div class="dz-sub">Extracts IOCs, decodes obfuscated payloads, runs 500+ YARA rules, and renders 60+ formats — 100% offline in your browser.</div>
      </div>
      <div id="page-container"></div>
    </div>

    <!-- sidebar resize handle -->
    <div id="sidebar-resize" class="hidden"></div>

    <!-- sidebar -->
    <div id="sidebar" class="hidden">
      <div id="sb-risk" class="sb-risk risk-low">
        <span id="sb-risk-title">No threats detected</span>
      </div>
      <div id="sb-body"></div>
    </div>

    <!-- Timeline root — sibling of #viewer. Shown whenever a CSV / TSV /
         EVTX is loaded (the analyser surface hides via body.has-timeline).
         Populated by src/app/app-timeline.js::_loadFileInTimeline(). -->
    <div id="timeline-root"></div>

  </div><!-- /#main-area -->

  <!-- ── Loading overlay ─────────────────────────────────────────────── -->
  <!-- The overlay has two phrase pools: the default analyser pool (`.lm`)
       and a decode-specific pool (`.lm-decode`) shown when the overlay's
       `data-mode` attribute is `decode`. The selection-decode flow
       (src/app/app-selection-decode.js) sets `data-mode="decode"` before
       calling `_setLoading(true)`; `_setLoading(false)` clears it. CSS
       in src/styles/core.css toggles which set is visible. -->
  <div id="loading" class="hidden">
    <div class="loading-content">
      <span class="spinner"></span>
      <div class="loading-msg">
        <span class="lm" style="--i:0">Bonking it with a stick</span>

        <span class="lm" style="--i:1">Dusting for fingerprints</span>
        <span class="lm" style="--i:2">Connecting the dots</span>
        <span class="lm" style="--i:3">Putting it under the microscope</span>
        <span class="lm" style="--i:4">Running it through the centrifuge</span>
        <span class="lm" style="--i:5">Calibrating the instruments</span>
        <span class="lm" style="--i:6">Giving it a firm talking-to</span>
        <span class="lm" style="--i:7">Asking it nicely to explain itself</span>
        <span class="lm" style="--i:8">Staring at it until it blinks</span>
        <span class="lm" style="--i:9">Reading its diary</span>
        <span class="lm" style="--i:10">Asking it about its feelings</span>
        <span class="lm" style="--i:11">Casting a revealing spell</span>
        <span class="lm" style="--i:12">Whispering to the bytes</span>
        <span class="lm" style="--i:13">Waving the wand</span>
        <span class="lm" style="--i:14">Letting it simmer</span>
        <span class="lm" style="--i:15">Marinating the sample</span>
        <span class="lm" style="--i:16">Slow-roasting the results</span>
        <span class="lm" style="--i:17">Letting it breathe</span>
        <span class="lm" style="--i:18">Warming up the engines</span>
        <span class="lm" style="--i:19">Smoothing the edges</span>
        <span class="lm" style="--i:20">Piecing it together</span>
        <span class="lm" style="--i:21">Nearly there</span>
        <span class="lm" style="--i:22">Hang tight</span>
        <span class="lm" style="--i:23">On the case</span>
        <span class="lm" style="--i:24">Prodding it with a longer stick</span>
        <span class="lm" style="--i:25">Tapping it to see if it's hollow</span>
        <span class="lm" style="--i:26">Flipping it over to check underneath</span>
        <span class="lm" style="--i:27">Knocking to see if anyone's home</span>
        <span class="lm" style="--i:28">Squeezing it gently</span>
        <span class="lm" style="--i:29">Pinching it to see if it's real</span>
        <span class="lm" style="--i:30">Rattling the container</span>
        <span class="lm" style="--i:31">Pressing all the buttons</span>
        <span class="lm" style="--i:32">Following the money</span>
        <span class="lm" style="--i:33">Bringing it in for questioning</span>
        <span class="lm" style="--i:34">Building a psychological profile</span>
        <span class="lm" style="--i:35">Taking careful measurements</span>
        <span class="lm" style="--i:36">Weighing it on the scale</span>
        <span class="lm" style="--i:37">Checking under the cushions</span>
        <span class="lm" style="--i:38">Interrogating the metadata</span>
        <span class="lm" style="--i:39">Consulting the magic 8-ball</span>
        <span class="lm" style="--i:40">Shaking it like a snow globe</span>
        <span class="lm" style="--i:41">Holding it up to the light</span>
        <span class="lm" style="--i:42">Sniffing for anomalies</span>
        <span class="lm" style="--i:43">Polishing the magnifying glass</span>
        <span class="lm" style="--i:44">Unfolding the treasure map</span>
        <span class="lm" style="--i:45">Asking the rubber duck</span>
        <span class="lm" style="--i:46">Lifting the carpet</span>
        <span class="lm" style="--i:47">Peeling back the layers</span>
        <span class="lm" style="--i:48">Tuning the antenna</span>
        <span class="lm" style="--i:49">Deciphering the runes</span>
        <span class="lm" style="--i:50">Counting the breadcrumbs</span>
        <span class="lm" style="--i:51">Putting on the detective hat</span>
        <span class="lm" style="--i:52">Adjusting the monocle</span>
        <span class="lm" style="--i:53">Leafing through the evidence</span>
        <span class="lm" style="--i:54">Shining the UV light</span>
        <span class="lm" style="--i:55">Pulling the thread</span>
        <span class="lm" style="--i:56">Turning over every stone</span>
        <span class="lm" style="--i:57">Recalibrating the flux capacitor</span>

        <!-- Decode-selection phrase pool. Hidden by default; shown only
             when `#loading[data-mode="decode"]` is set by the
             selection-decode flow (src/app/app-selection-decode.js). The
             default `.lm` pool above is then hidden by the corresponding
             rule in src/styles/core.css. -->
        <span class="lm-decode" style="--i:0">Throwing every key at the lock</span>
        <span class="lm-decode" style="--i:1">Bruteforcing the XOR key</span>
        <span class="lm-decode" style="--i:2">Trying ROT-1 through ROT-25</span>
        <span class="lm-decode" style="--i:3">Walking the column cribs</span>
        <span class="lm-decode" style="--i:4">Peeling Base64 off Base64</span>
        <span class="lm-decode" style="--i:5">Reversing reversed reverses</span>
        <span class="lm-decode" style="--i:6">Sniffing for hidden separators</span>
        <span class="lm-decode" style="--i:7">Stripping interleaved nulls</span>
        <span class="lm-decode" style="--i:8">Unwrapping safe-link wrappers</span>
        <span class="lm-decode" style="--i:9">Rebuilding the char-array</span>
        <span class="lm-decode" style="--i:10">Inflating zlib payloads</span>
        <span class="lm-decode" style="--i:11">Dechunking the hex escapes</span>
        <span class="lm-decode" style="--i:12">Concatenating the fragments</span>
        <span class="lm-decode" style="--i:13">Defanging the IOCs</span>
        <span class="lm-decode" style="--i:14">Cycling Caesar shifts</span>
        <span class="lm-decode" style="--i:15">Splitting on every delimiter</span>
        <span class="lm-decode" style="--i:16">Comparing key-length 2, 3, 4</span>
        <span class="lm-decode" style="--i:17">Scoring against the dictionary</span>
        <span class="lm-decode" style="--i:18">Looking for the magic word</span>
        <span class="lm-decode" style="--i:19">Asking the cipher to confess</span>
        <span class="lm-decode" style="--i:20">Recursing one layer deeper</span>
        <span class="lm-decode" style="--i:21">Chaining decode pipelines</span>
        <span class="lm-decode" style="--i:22">Pulling at every loose thread</span>
        <span class="lm-decode" style="--i:23">Hunting for plaintext</span>
        <span class="lm-decode" style="--i:24">Reading between the bytes</span>
        <span class="lm-decode" style="--i:25">Spotting the powershell</span>
        <span class="lm-decode" style="--i:26">Catching the IEX in the act</span>
        <span class="lm-decode" style="--i:27">Holding it under UV</span>
        <span class="lm-decode" style="--i:28">Comparing every shift</span>
        <span class="lm-decode" style="--i:29">Trying the obvious passwords</span>
        <span class="lm-decode" style="--i:30">Brute-forcing politely</span>
        <span class="lm-decode" style="--i:31">Decoding all the way down</span>
      </div>
      <!-- Optional progress subtitle. Empty by default; populated by
           callers that have a meaningful progress signal (e.g.
           `timeline-router.js` sets "1.2M rows…" as RowStore chunks
           stream in from the worker). Lives below the rotating phrase
           pool so the existing animation keeps running unchanged. -->
      <div id="loading-subtitle" class="loading-subtitle"></div>
    </div>
  </div>


  <!-- ── Toast ───────────────────────────────────────────────────────── -->
  <div id="toast" class="hidden"></div>

  <!-- ── Noscript ────────────────────────────────────────────────────── -->
  <noscript>
    <div class="noscript-msg">
      <h2>🕵🏻 Loupe requires JavaScript</h2>
      <p>This is a client-side security analysis tool — all processing happens locally in your browser. Please enable JavaScript to continue.</p>
    </div>
  </noscript>

  <!-- ── Group A: pre-App essentials (Tier 3 reorder) ────────────────────
        Capture-phase drag/drop/paste glue. Buffers files into
        `window.__loupePendingDrop` / `window.__loupePendingPaste` during
        the cold-load window so a drop arriving before the App's own
        listeners are wired isn't lost to the browser's default
        navigate-to-file behaviour. Drained + torn down by
        `App._setupDrop()` once the constructor runs. Must beat every
        other inline `<script>` to the parser — see EARLY_JS_FILES in
        scripts/build.py and the file header in
        src/app/early-drop-bootstrap.js. -->
  <script>
{early_drop_js}
  </script>

  <!-- ── Application — emitted as FOUR `<script>` blocks (Tier 5 split) ───
        The App bundle is split into four inline `<script>` tags so the
        browser can yield to layout / paint / event delivery between
        compiles. Same load order as before — only the emission shape
        changed (one `<script>` per block instead of one mega-block).
        Block 1 prepends `LOUPE_VERSION`, `DEFAULT_YARA_RULES`, and the
        three `__*_WORKER_BUNDLE_SRC` constants so `worker-manager.js`
        (also in Block 1) and `app-core.js` (Block 3) find them at
        module-eval time.
        These blocks are emitted AHEAD of the heavy renderer vendors
        below (JSZip / SheetJS / pdf.js / pako / LZMA / jsQR / tldts /
        utif / exifr / hljs) — Tier 3 invariant — so the App owns
        drag/drop end-to-end before any vendor compiles. The trailing
        `new App().init();` lives at the end of `app-breadcrumbs.js`,
        the LAST entry in `APP_JS_FILES` and therefore the last line of
        Block 4, so every `Object.assign(App.prototype, …)` mixin has
        landed its methods on the prototype before `App.init()` fires.
        Synchronous call (no DOMContentLoaded wrapper) — every DOM id
        the App queries is already in the document above. -->
{app_blocks_html}


  <!-- ── Group C: heavy renderer-only vendors (Tier 3 reorder) ────────────
        These compiled AHEAD of the App before Tier 3, blocking
        `App._setupDrop()` from binding listeners until the slowest
        vendor (SheetJS, ~30 ms) finished parsing. Now they trail the
        App `<script>` so the App owns drag/drop end-to-end before any
        of them touch the parser. The early-drop bootstrap above
        remains as defence-in-depth for the sub-millisecond gap
        between the App `<script>` parsing and `_setupDrop()`
        running. -->

  <!-- ── JSZip (inlined) ─────────────────────────────────────────────── -->
  <script>
{jszip}
  </script>

  <!-- ── SheetJS (inlined) ──────────────────────────────────────────── -->
  <script>
{xlsx_js}
  </script>

  <!-- ── pdf.js worker (inlined — must load before pdf.js) ───────────── -->
  <script>
{pdf_wrk_js}
  </script>

  <!-- ── pdf.js (inlined) ────────────────────────────────────────────── -->
  <script>
{pdf_js}
  </script>

  <!-- ── highlight.js (inlined) ──────────────────────────────────────── -->
  <script>
{highlight_js}
  </script>

  <!-- ── UTIF.js (inlined — TIFF decoder used by image-renderer) ─────── -->
  <script>
{utif_js}
  </script>

  <!-- ── exifr (inlined — EXIF / XMP / IPTC / GPS parser for images) ──── -->
  <script>
{exifr_js}
  </script>

  <!-- ── tldts (inlined — public-suffix-aware domain extractor,
        used by pushIOC() to auto-derive IOC.DOMAIN from every URL) ──── -->
  <script>
{tldts_js}
  </script>

  <!-- ── pako (inlined — synchronous zlib/deflate/gzip fallback used by
        Decompressor when DecompressionStream is unavailable or the
        caller needs a sync inflate) ──────────────────────────────── -->
  <script>
{pako_js}
  </script>

  <!-- ── LZMA-JS (decoder-only, inlined — used by SevenZRenderer to
        decompress LZMA-encoded 7z end-headers so the file listing is
        available even for large archives that compress their own
        metadata) ───────────────────────────────────────────────── -->
  <script>
{lzma_js}
  </script>

  <!-- ── jsQR (inlined — QR-code decoder shared by QrDecoder; consumers
        are ImageRenderer, PdfRenderer, SvgRenderer, OneNoteRenderer,
        EmlRenderer — any raster surface Loupe renders is scanned for
        QR payloads and the decoded contents land in findings.metadata
        / interestingStrings as IOCs via pushIOC()) ─────────────── -->
  <script>
{jsqr_js}
  </script>
</body>
</html>"""

# Output path:
#   • release build → docs/index.html (served by GitHub Pages, signed at release)
#   • --test-api    → docs/index.test.html (NEVER deployed, NEVER signed)
docs = os.path.join(BASE, 'docs')
os.makedirs(docs, exist_ok=True)
out_filename = 'index.test.html' if TEST_API else 'index.html'
out = os.path.join(docs, out_filename)
with open(out, 'w', encoding='utf-8') as _f:
    _f.write(HTML)

size = os.path.getsize(out)
print(f"OK  Built {out}  ({size:,} bytes / {size//1024} KB)"
      + ('  [test-api]' if TEST_API else ''))


# ── Build gate: test-API markers must NEVER appear in release bundles ─────────
# Defence-in-depth against the test-API leaking into a shipped release. The
# `--test-api` flag is the only path that ever embeds these markers, and the
# CI release path never passes that flag — but if a future contributor edits
# the orchestrator wrong, this gate catches the leak before it reaches Pages
# / Sigstore signing.
#
# We re-read the just-written release bundle and assert neither
# `__LOUPE_TEST_API__` nor `__loupeTest` (the public surface name) appears
# in it. Both strings are unique enough that a false positive in vendored
# code or YARA rules is not a concern (we sanity-check that assumption on
# every build by greping rules + vendor for the same tokens — the gate
# prints a clear error if anyone introduces such a substring).
def _check_no_test_api_in_release():
    if TEST_API:
        return  # Only run when emitting the release bundle.
    with open(out, 'r', encoding='utf-8') as _f:
        bundle = _f.read()
    leaks = []
    for marker in ('__LOUPE_TEST_API__', '__loupeTest'):
        if marker in bundle:
            leaks.append(marker)
    if leaks:
        raise SystemExit(
            'Build gate failed — test-API marker(s) leaked into release bundle: '
            + ', '.join(leaks) + '\n'
            'The `--test-api` flag must never be set when emitting '
            'docs/index.html. See scripts/build.py header comment.'
        )

_check_no_test_api_in_release()


# ── Build gate: fuzz-harness paths must NEVER appear in any built bundle ──────
# `tests/fuzz/` lives entirely outside `JS_FILES` / `CSS_FILES` /
# `_DETECTOR_FILES` — `scripts/build.py` does not enumerate it and never
# concatenates anything from there. This gate is the defence-in-depth net:
# we re-read the just-written bundle and assert no `tests/fuzz/` substring
# appears in it. A leak would only happen if a future contributor added a
# fuzz path to one of the file lists, or to a vendored / generated file
# whose source-of-truth contains a fuzz path comment. Either way, the gate
# fires before the bundle reaches Pages / Sigstore signing.
#
# Unlike `_check_no_test_api_in_release`, this gate runs for BOTH the
# release and `--test-api` builds — fuzz code must never enter either
# bundle, since the test bundle is what Playwright drives.
def _check_no_fuzz_path_in_bundle():
    with open(out, 'r', encoding='utf-8') as _f:
        bundle = _f.read()
    leaks = []
    # Match the directory prefix only — a YARA rule matching the literal
    # `tests/fuzz` substring would be exotic but possible; the path-form
    # markers below are unambiguous.
    for marker in ('tests/fuzz/helpers/', 'tests/fuzz/targets/'):
        if marker in bundle:
            leaks.append(marker)
    if leaks:
        raise SystemExit(
            'Build gate failed — fuzz harness path(s) leaked into bundle: '
            + ', '.join(leaks) + '\n'
            'tests/fuzz/ must never enter docs/index.html or '
            'docs/index.test.html. Check JS_FILES / CSS_FILES / '
            '_DETECTOR_FILES in scripts/build.py for an erroneous entry.'
        )

_check_no_fuzz_path_in_bundle()
