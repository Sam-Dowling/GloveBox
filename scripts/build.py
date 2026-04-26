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
import os
import subprocess
from datetime import datetime, timezone

# scripts/build.py → repo root is the parent of this file's directory.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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
}

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
    'src/decoders/ioc-extract.js',
    'src/decoders/base64-hex.js',
    'src/decoders/zlib.js',
    'src/decoders/encoding-finders.js',
    'src/decoders/encoding-decoders.js',
    'src/decoders/cmd-obfuscation.js',
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

    # storage.js — single chokepoint for every `localStorage.*` access in the
    # bundle. Exposes `window.safeStorage.{get,set,remove,getJSON,setJSON,
    # keys,removeMatching}`. Pure ceremony — try/catch + JSON serialise. Must
    # load AFTER constants.js (no constant deps today, but the namespacing
    # convention `loupe_*` lives there) and BEFORE any consumer that touches
    # storage. The build-gate `_check_storage_access()` allow-lists this file
    # plus `scripts/build.py` itself (FOUC theme bootstrap is hand-written
    # inline JS in <head>, not a `src/` module).
    'src/storage.js',

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
    # archive-tree.js — shared collapsible / searchable / sortable archive
    # browser. Must load BEFORE every renderer that uses `ArchiveTree`
    # (zip, jar, msix, browserext) so the class exists at construction time.
    'src/renderers/archive-tree.js',
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
    #   6. timeline-drawer.js        — TimelineView.prototype mixin: JSON
    #                                  drawer + extracted-column helpers
    #   7. timeline-router.js        — App.prototype mixin: `_timelineTryHandle`
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
    'src/app/timeline/timeline-view.js',
    'src/app/timeline/timeline-detections.js',
    'src/app/timeline/timeline-drawer.js',
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
# The renderers then concatenate in the same order the main bundle uses
# (csv → sqlite → evtx). The timeline.worker.js trailer carries the parse
# functions and the `self.onmessage` dispatcher. EvtxDetector is deliberately
# NOT included — analysis runs on the main thread.
_timeline_worker_bundle_src = (
    read('src/workers/timeline-worker-shim.js') + '\n'
    + read('src/renderers/csv-renderer.js') + '\n'
    + read('src/renderers/sqlite-renderer.js') + '\n'
    + read('src/renderers/evtx-renderer.js') + '\n'
    + read('src/workers/timeline.worker.js')
)
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
    + '\n'.join(read(f) for f in _DETECTOR_FILES) + '\n'
    + read('src/workers/encoded.worker.js')
)

encoded_worker_js = (
    'const __ENCODED_WORKER_BUNDLE_SRC = `'
    + _esc_for_template(_encoded_worker_bundle_src)
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
    + default_yara_js
    + yara_worker_js
    + timeline_worker_js
    + encoded_worker_js
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
          <button class="tb-btn tb-action-btn tb-accent-btn" id="btn-copy-analysis" title="Copy AI/SOC summary to clipboard">⚡ Summarize</button>
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
        <div class="dz-sub">Office · PDFs · executables · emails · archives · certificates · scripts · binaries · Java · SVG · and 60+ formats · 100% offline</div>
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
      </div>
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

# docs/index.html — served by GitHub Pages
docs = os.path.join(BASE, 'docs')
os.makedirs(docs, exist_ok=True)
out = os.path.join(docs, 'index.html')
with open(out, 'w', encoding='utf-8') as _f:
    _f.write(HTML)

size = os.path.getsize(out)
print(f"OK  Built {out}  ({size:,} bytes / {size//1024} KB)")
