# Contributing to Loupe

> Developer guide for Loupe.
> - For end-user documentation see [README.md](README.md).
> - For the full format / capability / example reference see [FEATURES.md](FEATURES.md).
> - For the threat model and vulnerability reporting see [SECURITY.md](SECURITY.md).
> - For AI coding agents see [`CODEMAP.md`](CODEMAP.md).

---

## Building from Source

Requires **Python 3.8+** (standard library only — no `pip install` needed).

```bash
python build.py                  # Concatenates src/ → docs/index.html
python generate-codemap.py       # Regenerates CODEMAP.md (run after code changes)
```

The build script reads CSS files from `src/styles/`, YARA rules from `src/rules/`, and JS source files, inlining all CSS and JavaScript (including vendor libraries) into a single self-contained HTML document:

| Output | Purpose |
|---|---|
| `docs/index.html` | GitHub Pages deployment (sole build output) |

### CSS Concatenation Order

```
src/styles/core.css                    # Base theme, toolbar, sidebar, dialogs ("Midnight Glass")
src/styles/viewers.css                 # All format-specific viewer styles
src/styles/themes/midnight.css         # Optional theme overlay — Midnight (OLED pure-black)
src/styles/themes/solarized.css        # Optional theme overlay — Solarized Dark
src/styles/themes/mocha.css            # Optional theme overlay — Catppuccin Mocha (dark, mauve accent)
src/styles/themes/latte.css            # Optional theme overlay — Catppuccin Latte (light, mauve accent)
```

Light and Dark are the baseline palettes and live in `core.css` (`body` / `body.dark`
selectors). Each extra theme is a pure-overlay file under `src/styles/themes/<id>.css`
scoped to `body.theme-<id>` and layered on top of `body.dark`. Register a new theme in
the `THEMES` array in `src/app/app-ui.js` and add the CSS path to `CSS_FILES` in
`build.py` — see the "Add a new theme" recipe below.

### YARA Rule Files

```
src/rules/office-macros.yar            # Office/VBA macro detection (36 rules)
src/rules/script-threats.yar           # Script threats: PS, JS, VBS, CMD, Python (61 rules)
src/rules/document-threats.yar         # PDF, RTF, OLE, HTML, SVG, OneNote (41 rules)
src/rules/windows-threats.yar          # LNK, HTA, MSI, registry, LOLBins (129 rules)
src/rules/archive-threats.yar          # Archive format threats (14 rules)
src/rules/encoding-threats.yar         # Base64, hex, obfuscation patterns (28 rules)
src/rules/network-indicators.yar       # UNC, WebDAV, credential theft (10 rules)
src/rules/suspicious-patterns.yar      # General suspicious patterns (10 rules)
src/rules/file-analysis.yar            # PE, image, forensic analysis (3 rules)
src/rules/pe-threats.yar               # PE executable threats: packers, malware toolkits (31 rules)
src/rules/elf-threats.yar              # ELF binary threats: Mirai, cryptominers, rootkits (18 rules)
src/rules/macho-threats.yar            # Mach-O binary threats: macOS stealers, RATs, persistence (17 rules)
src/rules/jar-threats.yar              # JAR/Java threats: deserialization, JNDI, reverse shells (17 rules)
src/rules/svg-threats.yar              # SVG threats: script injection, phishing, XXE (18 rules)
src/rules/osascript-threats.yar        # AppleScript/JXA threats: shell injection, persistence (18 rules)
src/rules/plist-threats.yar            # Property list threats: LaunchAgent, persistence keys (21 rules)
src/rules/clickonce-threats.yar        # ClickOnce deployment threats: AppDomainManager, HTTP deploy, full trust (4 rules)
src/rules/msix-threats.yar             # MSIX / APPX / App Installer threats: full-trust capabilities, startup tasks, silent auto-update (9 rules)
src/rules/browserext-threats.yar       # Browser extension (.crx / .xpi) threats: native messaging, all_urls, unsafe-eval CSP, debugger, externally_connectable (12 rules)
src/rules/macos-installer-threats.yar  # macOS installer threats: xar / UDIF magic, DMG encrypted envelopes, app-bundle launchers, hidden bundles (5 rules)
```

### JS Concatenation Order

The application code is concatenated in dependency order:

```
src/constants.js                       # Namespace constants, DOM helpers, unit converters, PARSER_LIMITS
src/parser-watchdog.js                 # ParserWatchdog — wraps sync/async parsers with a 60s timeout guard
src/vba-utils.js                       # Shared VBA binary decoder + auto-exec pattern scanner
src/yara-engine.js                     # YaraEngine — in-browser YARA rule parser + matcher
src/decompressor.js                    # Decompressor — gzip/deflate/raw decompression via DecompressionStream
src/encoded-content-detector.js        # EncodedContentDetector — Base64/hex/Base32/compressed blob scanner
src/docx-parser.js                     # DocxParser — ZIP extraction for DOCX/DOCM
src/style-resolver.js                  # StyleResolver — resolves run/paragraph styles
src/numbering-resolver.js              # NumberingResolver — list counters and markers
src/content-renderer.js                # ContentRenderer — DOCX DOM → HTML elements
src/security-analyzer.js               # SecurityAnalyzer — findings, metadata, external refs
src/renderers/protobuf-reader.js       # ProtobufReader — minimal protobuf wire-format decoder (CRX v3 CrxFileHeader)
src/renderers/ole-cfb-parser.js        # OleCfbParser — CFB/OLE2 compound file reader
src/renderers/archive-tree.js          # ArchiveTree — shared collapsible / searchable / sortable archive browser (zip, msix, crx/xpi, jar/war/ear, iso/img, pkg/mpkg)

src/renderers/xlsx-renderer.js         # XlsxRenderer — spreadsheet view (SheetJS)
src/renderers/pptx-renderer.js         # PptxRenderer — slide canvas renderer
src/renderers/odt-renderer.js          # OdtRenderer — OpenDocument text renderer
src/renderers/odp-renderer.js          # OdpRenderer — OpenDocument presentation renderer
src/renderers/ppt-renderer.js          # PptRenderer — legacy .ppt slide extraction
src/renderers/rtf-renderer.js          # RtfRenderer — RTF text + OLE/exploit analysis
src/renderers/zip-renderer.js          # ZipRenderer — archive listing + threat flagging
src/renderers/cab-renderer.js          # CabRenderer — Microsoft Cabinet (MSCF) parser w/ MSZIP extraction via pako
src/renderers/rar-renderer.js          # RarRenderer — RAR v4 + v5 header walker (listing-only)
src/renderers/seven7-renderer.js       # SevenZRenderer — 7-Zip header walker (plain + LZMA-encoded via vendored LZMA-JS) + AES coder detection
src/renderers/iso-renderer.js          # IsoRenderer — ISO 9660 filesystem listing
src/renderers/dmg-renderer.js          # DmgRenderer — Apple Disk Image (UDIF) koly/mish parser + encrypted envelope detector
src/renderers/pkg-renderer.js          # PkgRenderer — macOS flat PKG / xar installer (TOC + Distribution/PackageInfo + dangerous-script scan)

src/renderers/url-renderer.js          # UrlRenderer — .url / .webloc shortcut parser
src/renderers/onenote-renderer.js      # OneNoteRenderer — .one embedded object extraction
src/renderers/iqy-slk-renderer.js      # IqySlkRenderer — Internet Query + Symbolic Link files
src/renderers/wsf-renderer.js          # WsfRenderer — Windows Script File parser
src/renderers/reg-renderer.js          # RegRenderer — Windows Registry File (.reg) parser
src/renderers/inf-renderer.js          # InfSctRenderer — .inf setup info + .sct scriptlet parser
src/renderers/msi-renderer.js          # MsiRenderer — Windows Installer (.msi) analyser
src/renderers/csv-renderer.js          # CsvRenderer — CSV/TSV table view
src/renderers/evtx-renderer.js         # EvtxRenderer — Windows Event Log parser
src/renderers/sqlite-renderer.js       # SqliteRenderer — SQLite + browser history
src/renderers/doc-renderer.js          # DocBinaryRenderer — legacy .doc text extraction
src/renderers/msg-renderer.js          # MsgRenderer — Outlook .msg email view
src/renderers/eml-renderer.js          # EmlRenderer — RFC 5322/MIME email parser
src/renderers/lnk-renderer.js          # LnkRenderer — Windows Shell Link (.lnk) parser
src/renderers/hta-renderer.js          # HtaRenderer — HTA source viewer + security scanner
src/renderers/html-renderer.js         # HtmlRenderer — sandboxed HTML preview + source view
src/renderers/pdf-renderer.js          # PdfRenderer — PDF page renderer + security scanner
src/renderers/pe-renderer.js           # PeRenderer — PE32/PE32+ executable analyser
src/renderers/elf-renderer.js          # ElfRenderer — ELF32/ELF64 binary analyser
src/renderers/macho-renderer.js        # MachoRenderer — Mach-O / Universal Binary analyser
src/renderers/x509-renderer.js         # X509Renderer — X.509 certificate / PEM / DER / PKCS#12 viewer
src/renderers/pgp-renderer.js          # PgpRenderer — OpenPGP ASCII-armored / binary packet parser
src/renderers/jar-renderer.js          # JarRenderer — JAR/WAR/EAR archive + .class file analyser
src/renderers/svg-renderer.js          # SvgRenderer — SVG sandboxed preview + security analyser
src/renderers/osascript-renderer.js    # OsascriptRenderer — AppleScript / JXA source + compiled binary analyser
src/renderers/plist-renderer.js        # PlistRenderer — macOS .plist (XML + binary) tree view + security analyser
src/renderers/image-renderer.js        # ImageRenderer — image preview + stego/polyglot detection
src/renderers/plaintext-renderer.js    # PlainTextRenderer — catch-all text/hex viewer
src/renderers/clickonce-renderer.js    # ClickOnceRenderer — .application / .manifest deployment analyser
src/renderers/msix-renderer.js         # MsixRenderer — .msix / .msixbundle / .appx / .appxbundle / .appinstaller analyser
src/renderers/browserext-renderer.js   # BrowserExtRenderer — Chrome .crx (v2/v3) / Firefox .xpi WebExtension analyser
src/renderer-registry.js               # RendererRegistry — single source of truth for renderer auto-detection (magic → ext → text-sniff)
src/app/app-core.js                    # App class — constructor, init, drop-zone, toolbar

src/app/app-load.js                    # File loading, hashing (MD5/SHA), IOC extraction
src/app/app-sidebar.js                 # Sidebar rendering — risk bar + collapsible panes
src/app/app-yara.js                    # YARA rules dialog — upload, validate, save, scan, result display
src/app/app-ui.js                      # UI helpers (zoom, theme, pan, toast) + bootstrap
src/app/app-settings.js                # Unified ⚙ Settings / Help modal (theme tiles + Summary-budget slider + shortcuts)
```

`app-settings.js` must load **after** `app-ui.js` because it reuses the `THEMES`
registry and `_setTheme()` method defined there, and overrides the unbudgeted
`_buildAnalysisText` call path in `_copyAnalysis` with the user's configured
Summary-budget step.

Vendor libraries (`vendor/jszip.min.js`, `vendor/xlsx.full.min.js`, `vendor/pdf.min.js`, `vendor/pdf.worker.min.js`, `vendor/highlight.min.js`, `vendor/utif.min.js`, `vendor/exifr.min.js`, `vendor/tldts.min.js`, `vendor/pako.min.js`, `vendor/lzma-d-min.js`) are inlined into separate `<script>` blocks before the application code. `exifr` drives EXIF/GPS/XMP extraction inside `ImageRenderer`; `tldts` powers the public-suffix-list domain derivation wired into the shared `pushIOC` helper (every `IOC.URL` auto-emits a sibling `IOC.DOMAIN` when tldts resolves a registrable domain, plus a sibling `IOC.HOSTNAME` for punycode / IDN homograph hosts and an `IOC.PATTERN` row for abuse-associated TLDs / dynamic-DNS suffixes); `pako` is the synchronous gzip / deflate / zlib fallback used by `Decompressor` when the native `DecompressionStream` is unavailable or a caller needs the bytes synchronously (e.g. the PKG TOC inflate path, eager Base64 / hex payload classification); `lzma-d-min.js` is the decoder-only build of nmrugg/LZMA-JS used by `SevenZRenderer` to decompress LZMA-encoded 7z end-headers so the file listing survives `kEncodedHeader` archives (see **Architecture → 7-Zip LZMA-header decode** below).

---

## Project Structure

```
Loupe/
├── build.py                         # Build script — reads src/, writes docs/index.html
├── generate-codemap.py              # Generates CODEMAP.md (AI agent navigation map)
├── CODEMAP.md                       # Auto-generated code map with line-level symbol index
├── README.md                        # Public landing page — hero, quick start, compact formats table
├── FEATURES.md                      # Long-form reference — every format, capability, shortcut
├── SECURITY.md                      # Threat model, security boundaries, disclosure policy, PGP key
├── CONTRIBUTING.md                  # Developer guide — this file
├── VENDORED.md                      # SHA-256 pins for every file in vendor/
├── docs/
│   └── index.html                   # Built output (GitHub Pages) — DO NOT EDIT
├── vendor/
│   ├── jszip.min.js                 # JSZip — ZIP parsing for DOCX/XLSX/PPTX
│   ├── xlsx.full.min.js             # SheetJS — spreadsheet parsing
│   ├── pdf.min.js                   # pdf.js — PDF rendering (Mozilla)
│   ├── pdf.worker.min.js            # pdf.js worker — PDF parsing backend
│   └── highlight.min.js             # highlight.js — syntax highlighting
├── src/
│   ├── styles/                      # CSS (split for manageable file sizes)
│   │   ├── core.css                 # Base theme (Light + Dark), toolbar, sidebar, dialogs
│   │   ├── viewers.css              # Format-specific viewer styles
│   │   └── themes/                  # Optional theme overlays (body.theme-<id>)
│   │       ├── midnight.css         # Midnight (OLED pure-black) — dark-based
│   │       ├── solarized.css        # Solarized Dark — warm low-glare, dark-based
│   │       ├── mocha.css            # Catppuccin Mocha — dark, mauve-accented
│   │       └── latte.css            # Catppuccin Latte — light, mauve-accented
│   ├── rules/                       # YARA rules (split by threat category)
│   │   ├── office-macros.yar        # Office/VBA macro detection
│   │   ├── script-threats.yar       # PS, JS, VBS, CMD, Python threats
│   │   ├── document-threats.yar     # PDF, RTF, OLE, HTML, SVG threats
│   │   ├── windows-threats.yar      # LNK, HTA, MSI, registry, LOLBins
│   │   ├── archive-threats.yar      # Archive format threats
│   │   ├── encoding-threats.yar     # Encoding/obfuscation patterns
│   │   ├── network-indicators.yar   # UNC, WebDAV, credential theft
│   │   ├── suspicious-patterns.yar  # General suspicious patterns
│   │   ├── file-analysis.yar        # PE, image, forensic analysis
│   │   ├── pe-threats.yar           # PE executable threats
│   │   ├── elf-threats.yar          # ELF binary threats
│   │   ├── macho-threats.yar        # Mach-O binary threats
│   │   ├── jar-threats.yar          # JAR/Java threats
│   │   ├── svg-threats.yar          # SVG threats
│   │   ├── osascript-threats.yar    # AppleScript/JXA threats
│   │   ├── plist-threats.yar        # Property list threats
│   │   ├── clickonce-threats.yar    # ClickOnce deployment threats
│   │   ├── msix-threats.yar         # MSIX / APPX / App Installer threats
│   │   ├── browserext-threats.yar   # Browser extension (.crx / .xpi) threats
│   │   └── macos-installer-threats.yar # macOS installer threats (.dmg / .pkg)
│   ├── constants.js                 # Shared constants, DOM helpers, unit converters, PARSER_LIMITS
│   ├── parser-watchdog.js           # ParserWatchdog — 60s timeout guard for parser invocations
│   ├── vba-utils.js                 # Shared VBA binary decoder + auto-exec pattern scanner
│   ├── yara-engine.js               # YaraEngine — in-browser YARA rule parser + matcher
│   ├── decompressor.js              # Decompressor — gzip/deflate/raw via DecompressionStream
│   ├── encoded-content-detector.js  # EncodedContentDetector — encoded blob scanner
│   ├── docx-parser.js               # DocxParser class
│   ├── style-resolver.js            # StyleResolver class
│   ├── numbering-resolver.js        # NumberingResolver class
│   ├── content-renderer.js          # ContentRenderer class
│   ├── security-analyzer.js         # SecurityAnalyzer class
│   ├── renderer-registry.js         # RendererRegistry — auto-detection (magic → ext → text-sniff)
│   ├── renderers/
│   │   ├── ole-cfb-parser.js        # OleCfbParser — CFB compound file parser
│   │   ├── archive-tree.js          # ArchiveTree — shared collapsible/searchable/sortable archive browser (zip/msix/crx/xpi/jar/iso/pkg)
│   │   ├── xlsx-renderer.js         # XlsxRenderer
│   │   ├── pptx-renderer.js         # PptxRenderer
│   │   ├── odt-renderer.js          # OdtRenderer — OpenDocument text
│   │   ├── odp-renderer.js          # OdpRenderer — OpenDocument presentation
│   │   ├── ppt-renderer.js          # PptRenderer — legacy .ppt
│   │   ├── rtf-renderer.js          # RtfRenderer — RTF + OLE analysis
│   │   ├── zip-renderer.js          # ZipRenderer — archive listing
│   │   ├── cab-renderer.js          # CabRenderer — Microsoft Cabinet (MSCF) parser + MSZIP extraction
│   │   ├── rar-renderer.js          # RarRenderer — RAR v4 / v5 header walker (listing-only)
│   │   ├── seven7-renderer.js       # SevenZRenderer — 7-Zip container (listing-only; decodes LZMA-encoded end-headers via vendored lzma-d-min.js)
│   │   ├── iso-renderer.js          # IsoRenderer — ISO 9660 filesystem
│   │   ├── dmg-renderer.js          # DmgRenderer — Apple Disk Image (UDIF) parser
│   │   ├── pkg-renderer.js          # PkgRenderer — macOS flat PKG / xar installer

│   │   ├── url-renderer.js          # UrlRenderer — .url / .webloc shortcuts
│   │   ├── onenote-renderer.js      # OneNoteRenderer — .one files
│   │   ├── iqy-slk-renderer.js      # IqySlkRenderer — .iqy / .slk files
│   │   ├── wsf-renderer.js          # WsfRenderer — Windows Script Files
│   │   ├── reg-renderer.js          # RegRenderer — .reg registry files
│   │   ├── inf-renderer.js          # InfSctRenderer — .inf / .sct files
│   │   ├── msi-renderer.js          # MsiRenderer — .msi installer packages
│   │   ├── csv-renderer.js          # CsvRenderer
│   │   ├── evtx-renderer.js         # EvtxRenderer — .evtx parser
│   │   ├── sqlite-renderer.js       # SqliteRenderer — SQLite + browser history
│   │   ├── doc-renderer.js          # DocBinaryRenderer
│   │   ├── msg-renderer.js          # MsgRenderer
│   │   ├── eml-renderer.js          # EmlRenderer
│   │   ├── lnk-renderer.js          # LnkRenderer
│   │   ├── hta-renderer.js          # HtaRenderer
│   │   ├── html-renderer.js         # HtmlRenderer — sandboxed HTML preview
│   │   ├── pdf-renderer.js          # PdfRenderer
│   │   ├── pe-renderer.js           # PeRenderer — PE32/PE32+ executable analyser
│   │   ├── elf-renderer.js          # ElfRenderer — ELF32/ELF64 binary analyser
│   │   ├── macho-renderer.js        # MachoRenderer — Mach-O / Universal Binary analyser
│   │   ├── x509-renderer.js         # X509Renderer — X.509 certificate viewer
│   │   ├── pgp-renderer.js          # PgpRenderer — OpenPGP packet parser (RFC 4880 / RFC 9580)
│   │   ├── jar-renderer.js          # JarRenderer — JAR/WAR/EAR + .class analyser
│   │   ├── svg-renderer.js          # SvgRenderer — SVG preview + security analyser
│   │   ├── osascript-renderer.js    # OsascriptRenderer — AppleScript / JXA analyser
│   │   ├── plist-renderer.js        # PlistRenderer — macOS .plist viewer + security analyser
│   │   ├── image-renderer.js        # ImageRenderer — image preview + stego detection
│   │   ├── plaintext-renderer.js    # PlainTextRenderer
│   │   ├── clickonce-renderer.js    # ClickOnceRenderer — .application / .manifest deployment analyser
│   │   ├── msix-renderer.js         # MsixRenderer — MSIX/APPX ZIP packages + .appinstaller XML analyser
│   │   └── browserext-renderer.js   # BrowserExtRenderer — Chrome .crx (v2/v3) / Firefox .xpi WebExtension analyser
│   └── app/
│       ├── app-core.js              # App class definition + setup methods
│       ├── app-load.js              # File loading, hashing, IOC extraction
│       ├── app-sidebar.js           # Sidebar rendering (risk bar + collapsible panes)
│       ├── app-yara.js              # YARA rules dialog (upload/validate/save/scan)
│       ├── app-ui.js                # UI helpers + DOMContentLoaded bootstrap
│       └── app-settings.js          # Unified ⚙ Settings / Help modal (theme tiles + Summary-budget slider)
└── examples/                        # Sample files for testing various formats
```

---

## Gotchas & Tripfalls

This is where the explanations and the "why" live. 
If you skip reading this section your change will
probably still build, then subtly misbehave.

### Build artefacts & source of truth

- **`docs/index.html` is a build artefact — never edit it.** Every edit you
  make in `docs/index.html` is discarded by the next `python build.py`. Always
  edit `src/` and rebuild.
- **`CODEMAP.md` is auto-generated.** Don't touch it by hand — regenerate with
  `python generate-codemap.py` after code changes.
- **The `JS_FILES` order in `build.py` is load-bearing.** The
  `Object.assign(App.prototype, …)` pattern means later files override
  earlier ones' methods. `app-settings.js` must load **after** `app-ui.js`
  because it reuses the `THEMES` array defined there and overrides the
  unbudgeted `_copyAnalysis` call path with the configured Summary-budget
  step. Renderers must load before `renderer-registry.js`, which must load
  before `app-core.js`.

### CSP & runtime safety

- **No `eval`, no `new Function`, no network.** The Content-Security-Policy
  (`default-src 'none'` + `script-src 'unsafe-inline'` only for the
  single-file bundle) will reject anything you add that needs a fetch, a
  `<script src>`, or a dynamic code constructor. Don't relax the CSP to
  make a feature work — find another way.
- **Images / blobs only from `data:` and `blob:` URLs.** Anything else will
  be blocked at load.
- **Sandboxed previews** (`<iframe sandbox>` for HTML / SVG / MHT) have
  their own inner `default-src 'none'` CSP. Don't assume a preview iframe
  can load any resource that the host page can — it can't.

### YARA rule files

- **YARA rule files contain no comments.** `build.py` concatenates
  `YARA_FILES` with `// @category: <name>` separator lines inserted
  between files — those are the **only** `//` lines the in-browser YARA
  engine expects to tolerate. Any inline `//` or `/* */` comment you
  author inside a `.yar` file goes straight into the engine as rule
  source and will either break the parse or produce a no-match rule. If
  you need to explain a rule, write the explanation in `meta:` fields.
- **Category labels are inserted by `build.py`**, not authored by hand —
  do not add `// @category:` lines to the source files yourself.

### Renderer conventions

- **IOC types must use `IOC.*` constants** from `src/constants.js` — never
  bare strings like `type: 'url'`, `type: 'ip'`, `type: 'domain'`. The
  sidebar filters by exact type string to separate IOCs from detections;
  a bare string silently breaks filtering, sidebar grouping, STIX / MISP
  export mapping, and the `ioc-conformity-audit` skill.
- **Renderer `findings.risk` starts `'low'`.** Only escalate from evidence
  you've actually pushed onto `externalRefs`. Pre-stamping `'high'` or
  `'medium'` produces false-positive risk colouring on benign samples and
  fails `cross-renderer-sanity-check`. See the **Risk Tier Calibration**
  subsection below for the canonical escalation tail.
- **Prefer `pushIOC()` over hand-rolling `interestingStrings.push(...)`.**
  `pushIOC` pins the on-wire shape and — crucially — auto-emits a sibling
  `IOC.DOMAIN` row when `tldts` resolves the URL to a registrable domain.
  If you're already emitting a manual domain row, pass
  `_noDomainSibling: true` to suppress the auto-emitted one.
- **`_rawText` must be `\n`-normalised.** The sidebar's click-to-focus uses
  character offsets into `_rawText`; a single CRLF anywhere in the buffer
  misaligns every offset after it by one byte, so every highlight after the
  first CR will land on the wrong token.
- **Long IOC lists must end with an `IOC.INFO` truncation marker.** When a
  renderer walks a large space and caps at (say) 500 entries, push exactly
  one `IOC.INFO` row after the cap explaining the reason and the cap count
  — the Summary / Share exporters read this row, and without it the analyst
  has no way to know they are looking at a truncated view.

### Docs & persistence

- **Long single-line table cells break `replace_in_file`.** Cap table-cell
  content at ~140 characters / one sentence. If you need more room, split
  the row or move the deep detail here, leaving a one-liner pointer in
  `FEATURES.md`.
- **New `localStorage` keys must use the `loupe_` prefix** and be added to
  the persistence-keys table in the **Persistence Keys** section below.
  Agents auditing preference state grep for `loupe_` — keys outside that
  namespace are invisible.

---

## Persistence Keys

Every user preference lives in `localStorage` under the `loupe_` prefix so
state is (a) easy to grep for, (b) easy to clear with a single filter, and
(c) auditable against this table. If you add a new key, add a row here.

| Key | Type | Written by | Values / shape | Notes |
|---|---|---|---|---|
| `loupe_theme` | string | `_setTheme()` in `src/app/app-ui.js` | one of `light` / `dark` / `midnight` / `solarized` / `mocha` / `latte` | Canonical list is the `THEMES` array at the top of `app-ui.js`. Applied before first paint by the inline `<head>` bootstrap in `build.py`; missing / invalid value falls back to OS `prefers-color-scheme`, then `dark`. |
| `loupe_summary_target` | string | `_setSummaryTarget()` in `src/app/app-settings.js` | one of `default` / `large` / `unlimited` (from the `SUMMARY_TARGETS` array — character budgets `64 000` / `200 000` / `Infinity` respectively) | Drives the build-full → measure → shrink-to-fit assembler in `_buildAnalysisText()`. `unlimited` short-circuits truncation entirely; the two bounded phases first build at full fidelity and only fall back to the SCALE ladder (`[4, 2, 1, 0.5, 0.25]`) when the assembled report exceeds the target. Legacy `loupe_summary_chars` values (1-10 stop index from the retired slider) are one-shot migrated to `default`/`large`/`unlimited` on first read and the old key is deleted. |
| `loupe_yara_rules` | string | `app-yara.js` (YARA dialog "Save" action) | raw concatenated `.yar` rule text | User-uploaded rules are merged with the default ruleset at scan time. Cleared when the user clicks "Reset to defaults" in the YARA dialog. |

**Adding a new key**

1. Use the `loupe_<feature>` prefix.
2. Read and write through a named accessor (`_getMyThing()` / `_setMyThing(value)`)
   in the owning `app-*.js` file so the write site is auditable.
3. Validate on read — never trust the stored value. If it's outside the
   expected range, fall back to a hard-coded default.
4. Add a row to this table in the same PR.

---

## AI Agent Support

Loupe is optimised for AI coding agents (Cline, Cursor, Copilot Workspace, etc.):

- **`CODEMAP.md`** — Auto-generated code map with precise line numbers for every class, method, CSS section, and YARA rule. Agents can read this file first (~24K tokens) and then use `read_file(path, start_line=X, end_line=Y)` for surgical edits without consuming their entire context window.
- **`generate-codemap.py`** — Regenerate `CODEMAP.md` after any code changes: `python generate-codemap.py`
- **Split CSS/YARA** — CSS and YARA rules are split into multiple files by category, keeping each file manageable. No single file dominates the context budget.

---

## Architecture

- **Single output file** — `build.py` inlines all CSS and JavaScript so the viewer works by opening one `.html` file with zero external dependencies.
- **No eval, no network** — the Content-Security-Policy (`default-src 'none'`) blocks all external fetches; images are rendered only from `data:` and `blob:` URLs.
- **App class split** — `App` is defined in `app-core.js`; additional methods are attached via `Object.assign(App.prototype, {...})` in `app-load.js`, `app-sidebar.js`, `app-yara.js`, `app-ui.js`, and `app-settings.js`, keeping each file focused.
- **User preferences** — user-configurable settings persist via `localStorage` under the `loupe_*` namespace. Current keys: `loupe_theme` (one of `light` / `dark` / `midnight` / `solarized` / `mocha` / `latte`, written by `_setTheme()` in `app-ui.js` — the canonical list lives in the `THEMES` array at the top of that file, so adding a new `src/styles/themes/<id>.css` overlay plus a `THEMES` row is all it takes to extend the set) and `loupe_summary_target` (one of `default` / `large` / `unlimited`, written by `_setSummaryTarget()` in `app-settings.js`; the three phases live in the `SUMMARY_TARGETS` array at the top of that file, with character budgets `64 000` / `200 000` / `Infinity` respectively — `unlimited` means "emit full fidelity, no truncation"). The Summarize pipeline is build-full → measure → shrink-to-fit: sections are first assembled at `SCALE=Infinity`, and only when the total exceeds the target does `_buildAnalysisText()` walk sections from most expendable downward and rebuild each along the `[4, 2, 1, 0.5, 0.25]` SCALE ladder until the total fits. The YARA dialog owns its own key (`loupe_yara_rules`) documented in `app-yara.js`. New preference keys should follow the `loupe_<feature>` prefix so they are easy to audit and clear. The theme picker itself is exposed only through the ⚙ Settings dialog's tile grid — there is no toolbar theme dropdown.
- **YARA-based detection** — all threat detection is driven by YARA rules. Default rules are split across `src/rules/*.yar` by threat category and auto-scanned on file load. Users can upload (or drag-and-drop) their own `.yar` files, validate them, and save the combined rule set back out via the YARA dialog (`Y` key). There is no in-browser rule-editing surface — rule source is authored in an external editor and loaded as files; uploaded rules persist in `localStorage`.
- **Shared VBA helpers** — `parseVBAText()` and `autoExecPatterns` live in `vba-utils.js` and are reused by `DocxParser`, `XlsxRenderer`, and `PptxRenderer`.
- **OLE/CFB parser** — `OleCfbParser` is shared by `DocBinaryRenderer` (`.doc`), `MsgRenderer` (`.msg`), and `PptRenderer` (`.ppt`) for reading compound binary files.
- **PDF rendering** — `PdfRenderer` uses Mozilla's pdf.js for canvas rendering plus raw-byte scanning for dangerous PDF operators. Hidden text layers enable IOC extraction from rendered pages. JavaScript bodies from `/JS` actions (literal, hex, and indirect-stream with `/FlateDecode`) are extracted with per-script trigger / size / SHA-256 / suspicious-API hints; XFA form packets are pulled out for inspection; and `/EmbeddedFile` / `/Filespec` attachments emit `open-inner-file` CustomEvents handled by `app-load.js` — the same mechanism `ZipRenderer` uses for recursive drill-down, so analysts can click a PDF attachment and have it re-analysed in a new frame with Back navigation preserved. `analyzeForSecurity()` additionally calls pdf.js's `getPermissions()` / `getOpenAction()` / annotation walker: restrictive permission flags surface as `IOC.PATTERN`, `/OpenAction` URIs emit a `high` URL (non-URL actions emit a `medium` pattern), and annotation subtypes are tiered — `Movie` / `Sound` / `Screen` / `FileAttachment` are `medium`, `RichMedia` / `3D` are `high`. AcroForm fields matching credential-style name regex (`pass`/`pwd`/`ssn`/`cvv`/…) push a `medium` pattern so weaponised pre-filled forms don't look harmless. The page text pass also spots PDF-embedded credential prompts for phishing lures.
- **EML parsing** — Full RFC 5322/MIME parser with multipart support, quoted-printable and base64 decoding, attachment extraction, and authentication header analysis.
- **LNK parsing** — Implements the MS-SHLLINK binary format, extracting target paths, arguments, timestamps, and environment variable paths. Flags dangerous executables and evasion patterns.
- **HTA analysis** — Treats `.hta` files as inherently high-risk, extracting embedded scripts, `<HTA:APPLICATION>` attributes, and scanning against 40+ suspicious patterns including obfuscation techniques.
- **HTML rendering** — `HtmlRenderer` provides a sandboxed iframe preview (with all scripts and network disabled) and a source-code view with line numbers.
- **Image analysis** — `ImageRenderer` renders image previews and checks for steganography indicators, polyglot file structures, and suspicious embedded data. `exifr` is invoked with the expanded option bag `{icc:true, makerNote:true, userComment:true, interop:true, multiSegment:true, ifd1:true}` so MakerNote, ICC profile, UserComment, Interop, and IFD1 tag groups are surfaced; `exifr.thumbnail()` runs alongside metadata extraction and `_applyThumbnail()` renders the embedded JPEG thumbnail into the viewer (polyglot payloads often disagree with the main image and jump out visually). For TIFF files the vendored `UTIF` library is decoded twice — once in `render()` for pixel display, once in `analyzeForSecurity()` so the `_applyTiffTags()` walker can lift IFD tag numbers commonly abused as covert channels: 270 (ImageDescription), 271 / 272 (Make / Model), 305 / 306 (Software / DateTime), 315 / 316 (Artist / HostComputer), 33432 (Copyright), 700 (XMP), and 33723 (IPTC). Each lifted tag pushes a metadata row plus a classic-pivot IOC where applicable.
- **Spreadsheet formula analysis** — `XlsxRenderer` runs a per-cell formula scan over every workbook before any VBA extraction, capped at 200 000 cells. Formulas whose call tree contains `WEBSERVICE`, `IMPORTDATA`, `CALL`, `REGISTER`, or `EXEC` escalate to a `high` externalRef (`Excel_High_Risk_Formula_Function` — these are the in-cell exfiltration / code-exec primitives that weaponise `.xlsx` without needing `.xlsm`); `HYPERLINK`, `RTD`, `DDE` push `medium`. Hidden sheets (`workbook.xml` `sheet[@state='hidden'|'veryHidden']`) and `DefinedName` entries whose name matches `Auto_Open` / `Workbook_Open` / `Auto_Close` push `medium` patterns (`Excel_AutoOpen_Defined_Name`) because the legacy Excel 4.0 macro `Auto_Open` defined-name trick still triggers on modern Office and was the canonical "formula-only dropper" vector. The 200 k cap is enforced via a shared counter and ends with the standard `IOC.INFO` truncation marker.
- **Archive entry metadata** — `ZipRenderer` surfaces per-entry risk signals that classic archive viewers hide: the archive-level zip `.comment`, per-entry `comment`, `unixPermissions` (suid / sgid / world-writable bits escalate to `medium`), and a `compressed/uncompressed > 1000×` ratio detector that flags zip-bomb layers as `high` (`Zip_Bomb_Nested_Archive`). Stale mtimes (< 1995 or in the future by > 1 year) push a `medium` pattern because these are the canonical trust-model-breaking timestamps attackers use to forge signatures or fake archive-age provenance.
- **Archive drill-down** — `ZipRenderer` lists archive contents with threat flagging, and allows clicking individual entries to extract and open them for full analysis, with Back navigation. The listing UI itself is delegated to the shared `ArchiveTree` component (`src/renderers/archive-tree.js`), which provides the collapsible folder tree, flat sortable view, instant search, keyboard navigation, and per-entry risk badges. `MsixRenderer`, `BrowserExtRenderer`, `JarRenderer` (Archive Contents pane), `IsoRenderer`, and `PkgRenderer` all reuse the same component so every archive-like surface behaves identically. Entries passed in are the shape `{ path, dir, size, compressed?, date?, encrypted?, linkName?, danger?, dangerLabel? }` — the `danger`/`dangerLabel` fields let callers (e.g. `PkgRenderer` for `preinstall` / `postinstall` scripts) flag entries that no extension-based classifier would catch. The component emits an `onOpen(entry)` callback that each host renderer wires back to its own `open-inner-file` CustomEvent dispatch. `IsoRenderer` extracts each file via a bounds-clamped slice at `lba * blockSize` (ISO 9660 files are stored uncompressed as contiguous byte runs) and dispatches it back through the same event for recursive analysis.

- **Encoded content detection** — `EncodedContentDetector` scans file text for Base64, hex, and Base32 encoded blobs plus embedded compressed streams (gzip/deflate). High-confidence patterns (PE headers, gzip magic, PowerShell `-EncodedCommand`) are decoded eagerly; other candidates offer a manual "Decode" button. Decoded payloads are classified, IOCs are extracted, and a "Load for analysis" button feeds decoded content back through the full analysis pipeline with breadcrumb navigation.
- **PE analysis** — `PeRenderer` parses PE32/PE32+ binaries (EXE, DLL, SYS, DRV, OCX, CPL, COM, `.xll`) — headers, sections, imports (~140 flagged APIs), exports, resources, Rich header, strings, and security features (ASLR, DEP, CFG, SEH, Authenticode). Also surfaces "what is this binary?" heuristics (XLL, compiled AutoHotkey, Inno Setup, NSIS, Go), emitted as flat `pe.*` fields and backed by `pe-threats.yar`. See `FEATURES.md` for the full capability list.
- **ELF analysis** — `ElfRenderer` parses ELF32/ELF64 binaries (LE/BE) — ELF header, program headers, section headers, dynamic linking (NEEDED, SONAME, RPATH/RUNPATH), symbol tables with suspicious symbol flagging, note sections, and security feature detection (RELRO, Stack Canary, NX, PIE, FORTIFY_SOURCE). Also performs Go binary detection via `.go.buildinfo` section parsing (module path + Go version), surfaced in the `⚡ Summary` and backed by an `ELF_Go_Binary` YARA rule.
- **Mach-O analysis** — `MachoRenderer` parses Mach-O 32/64-bit and Fat/Universal binaries — header, load commands, segments with section-level entropy, symbol tables with suspicious symbol flagging (~30 macOS APIs), dynamic libraries, RPATH, code signature (CodeDirectory, entitlements, CMS), and security feature detection (PIE, NX, Stack Canary, ARC, Hardened Runtime, Library Validation).
- **X.509 certificate analysis** — `X509Renderer` provides a pure-JS ASN.1/DER parser with ~80 OID mappings. Parses PEM/DER certificates and PKCS#12 containers — subject/issuer DN, validity period, public key details, extensions (SAN, Key Usage, EKU, CRL Distribution Points, AIA), fingerprints. Flags self-signed, expired, weak keys/signatures, and extracts IOCs from SANs and CRL/AIA URIs.
- **OpenPGP analysis** — `PgpRenderer` parses OpenPGP data (RFC 4880 / RFC 9580) in both ASCII-armored and binary forms. It enumerates packets, extracts key IDs, fingerprints, user IDs, subkeys, self-signatures and subkey bindings, decodes public-key algorithm / key size / ECC curve, and validates armor CRC-24 checksums. Flags unencrypted secret keys, weak key sizes, deprecated Elgamal-sign-or-encrypt, v3 legacy keys, revoked/expired keys, long-lived keys without expiry, and SHA-1 as preferred hash. Parse-only — no signature verification, no secret-key decryption. The `.key` extension is disambiguated between OpenPGP and X.509 PEM private keys via `_looksLikePgp()` in `app-load.js`, which inspects ASCII-armor headers and OpenPGP packet-tag bytes (0x99/0xC6 Public-Key, 0x95/0xC5 Secret-Key, etc.).
- **JAR / Java analysis** — `JarRenderer` parses JAR/WAR/EAR archives and standalone `.class` files — class file headers, MANIFEST.MF, package tree, dependency extraction, constant pool string analysis with ~45 suspicious Java API patterns mapped to MITRE ATT&CK, and obfuscation detection. Viewer UI details (tabbed layout, global tab- and tree-aware search) live in `FEATURES.md`. Clickable inner file extraction emits `open-inner-file` CustomEvents handled by `app-load.js`.
- **SVG analysis** — `SvgRenderer` provides a sandboxed iframe preview and source-code view with line numbers. `analyzeForSecurity()` performs deep SVG-specific analysis: `<script>` extraction, `<foreignObject>` detection, event handler scanning, Base64/data URI payload analysis, SVG-specific vectors (`<use>`, `<animate>`/`<set>` href manipulation, `<feImage>` external filters), XXE detection, and JavaScript obfuscation patterns. Augmented buffer is stored separately in `_yaraBuffer` to avoid contaminating Copy/Save.
- **AppleScript / JXA analysis** — `OsascriptRenderer` handles `.applescript` source files (syntax-highlighted display), compiled `.scpt` binaries (string extraction from binary data), and `.jxa` JavaScript for Automation files. Security analysis flags shell command execution (`do shell script`), application targeting, file system access, and macOS-specific persistence/privilege escalation patterns.
- **Property list analysis** — `PlistRenderer` parses both XML and binary `.plist` formats into an interactive tree view with expandable nested structures. Security analysis detects LaunchAgent/LaunchDaemon persistence, suspicious URL schemes, shell command execution, and privacy-sensitive entitlement keys. 21 dedicated YARA rules cover plist-specific threat patterns.
- **macOS installer analysis** — `DmgRenderer` handles Apple Disk Image (`.dmg`) UDIF containers: reads the 512-byte BE `koly` trailer at end-of-file, enumerates partitions via the XML plist (`blkx` entries), decodes base64 `mish` partition blocks to count block-type frequencies, and detects encrypted envelopes by sniffing `AEA1` / `encrcdsa` / `cdsaencr` at offset 0 (a hard-encrypted DMG renders its header + encryption verdict without attempting to walk the inaccessible filesystem). Because HFS+ / APFS filesystem parsing is out of scope for a browser tool, embedded `.app` bundle paths are recovered via the shared `extractAsciiAndUtf16leStrings` scanner and listed as sidebar IOCs. `PkgRenderer` handles flat PKG (`.pkg` / `.mpkg`) xar archives: parses the 28-byte BE header, inflates the zlib-compressed TOC XML via `Decompressor.inflate(…, 'deflate')`, and extracts `Distribution` / `PackageInfo` metadata. Inner files are clickable and emit `open-inner-file` CustomEvents (same wiring as `ZipRenderer`). A static `DANGEROUS_SCRIPT_NAMES` set (`preinstall` / `postinstall` / `preflight` / `postflight` / `preupgrade` / `postupgrade` / `InstallationCheck` / `VolumeCheck`) drives the risk calibration — any matching script entry pushes a `high` externalRef. Both renderers are backed by `macos-installer-threats.yar` (5 rules).
- **ClickOnce analysis** — `ClickOnceRenderer` parses `.application` deployment manifests and `.manifest` application manifests. `app-load.js` routes them via a root-element sniff (`assembly` → ClickOnce, otherwise falls through to `PlainTextRenderer` so side-by-side assembly / SxS / vcpkg manifests still render). Extracts identity, deployment settings, entry point, trust level, `appDomainManager*` overrides, signature presence, and `dependentAssembly` chains. Emits `findings.clickOnceInfo`, surfaced in `⚡ Summary`, and backed by `clickonce-threats.yar`.
- **MSIX / APPX / App Installer analysis** — `MsixRenderer` handles `.msix` / `.msixbundle` / `.appx` / `.appxbundle` ZIP containers plus standalone `.appinstaller` XML (extension dispatch in `app-load.js`). For package containers, `JSZip` extracts `AppxManifest.xml` / `AppxBundleManifest.xml`; parses identity, capabilities (tiered), and application extensions (full-trust process, startup task, app-execution alias, protocol, COM, background tasks). For `.appinstaller` XML, parses `Uri`, main package / bundle, dependencies, and `UpdateSettings`. All namespaces are read via `getElementsByTagNameNS("*", local)` so prefix variations don't break extraction. The `AppxSignature.p7x` signature envelope is parsed by `_parseP7x` — a deliberately conservative DER token-scan (no full ASN.1 walker) that confirms the `PKCX` magic, scans for the `AppxSipInfo` (1.3.6.1.4.1.311.84.2.1) and `SpcIndirectDataContent` OIDs, and extracts the signer Subject CN / O via the `id-at-commonName` / `id-at-organizationName` OIDs (handles UTF8String / PrintableString / BMPString tags + 0x81 / 0x82 long-form lengths). The signer CN is then compared against the manifest's `Identity/@Publisher` DN (parsed by `_parsePublisherDN`); a mismatch is the canonical re-signed / repackaged tell and is flagged `high` in both `_assess` and the summary card. `_computePublisherId` derives the canonical 13-character Windows PublisherId (SHA-256 of UTF-16LE publisher → first 8 bytes → 65-bit stream → 13 × 5-bit groups in the Crockford-style `0..9 + a..z minus i/l/o/u` alphabet) so `PackageFamilyName` lookups can be done without installation. Inner files emit `open-inner-file` CustomEvents (same wiring as `ZipRenderer`). Emits `findings.msixInfo`, surfaced in `⚡ Summary`, and backed by `msix-threats.yar`. See `FEATURES.md` for the full parsed-field list.
- **Browser extension analysis** — `BrowserExtRenderer` handles Chrome `.crx` (v2 and v3) and Firefox `.xpi` archives. Extension dispatch in `app-load.js` routes by extension, with a `Cr24` magic sniff fallback. For `.crx`, the v2/v3 envelope is unwrapped (v2 carries a raw RSA public key + signature; v3 carries a protobuf `CrxFileHeader` decoded via the in-tree `ProtobufReader` — `_parseCrxV3Header` walks the header to pull every `AsymmetricKeyProof.public_key` (RSA field 2, ECDSA field 3) plus the nested `SignedData.crx_id` (field 10000 → field 1, expected 16 bytes), then `_decorateCrxV3` SHA-256s each public key and remaps the first 16 bytes via `_crxIdFromBytes` to produce the canonical Chrome extension ID for comparison against the declared `crx_id`) and the embedded ZIP payload is extracted with `JSZip`; for `.xpi`, the ZIP is read directly. The summary card surfaces `Chrome Extension ID (declared)`, one `Chrome Extension ID (computed, RSA-SHA256 / ECDSA-SHA256)` row per key, an `ID match: ✓ / ✗` verdict, and a signature count line; `_assess` raises `high` risks for malformed or empty headers, zero signatures, or a declared-vs-computed ID mismatch, and `medium` for a non-16-byte declared crx_id. Parses `manifest.json` (MV2 / MV3), extracts identity, permissions (tiered via static `PERM_HIGH` / `PERM_MEDIUM` / `BROAD_HOST_PATTERNS`), content scripts, background worker / service worker, externally_connectable, content_security_policy, and Firefox `applications.gecko` / legacy `install.rdf`. CRX v2 public keys produce the canonical Chrome extension ID (SHA-256 → first 16 bytes → nibble remap `0..f → a..p`); CRX v3 reuses the same remap on every parsed `AsymmetricKeyProof`. Inner files emit `open-inner-file` CustomEvents (same wiring as `ZipRenderer`). Emits `findings.browserExtInfo`, surfaced in `⚡ Summary`, and backed by `browserext-threats.yar`.

- **Catch-all viewer** — `PlainTextRenderer` accepts any file type. Text files get line-numbered display; binary files get a hex dump. Both paths run IOC extraction and YARA scanning.

---

## Renderer Contract

Renderers are self-contained classes exposing a static `render(file, arrayBuffer, app)` that returns a DOM element (the "view container"). To participate in sidebar click-to-highlight (the yellow/blue `<mark>` cycling users see when clicking an IOC or YARA hit) a text-based renderer should attach the following optional hooks to the container element it returns:

| Property | Type | Purpose |
|---|---|---|
| `container._rawText` | `string` | The normalised source text backing the view. Used by `app-sidebar.js::_findIOCMatches()` and `_highlightMatchesInline()` to locate every occurrence of an IOC value and by the encoded-content scanner to compute line numbers. Line endings should be normalised to `\n` so offsets line up with the rendered `.plaintext-table` rows. |
| `container._showSourcePane()` | `function` | Invoked before highlighting on renderers that have a Preview/Source toggle (e.g. HTML, SVG, URL). Must synchronously (or via a short `setTimeout(…, 0)`) expose the source pane so a subsequent `scrollIntoView()` on a `<mark>` actually lands on a visible element. Optional — renderers without a toggle simply omit it. |
| `container._yaraBuffer` | `Uint8Array` | Optional. When set, the YARA engine scans this buffer instead of the raw file bytes. Used by SVG/HTML to include an augmented representation (e.g. decoded Base64 payloads) without contaminating Copy/Save. |

If the renderer also emits a `.plaintext-table` (one `<tr>` per line with a `.plaintext-code` cell per line) the sidebar automatically gets character-level match highlighting, line-background cycling, and the 5-second auto-clear behaviour for free. Renderers that do not provide a plaintext surface fall back to a best-effort TreeWalker highlight on the first match found anywhere in the DOM.

### Risk Tier Calibration

A renderer's `analyzeForSecurity()` must emit a `findings.risk` value in the
canonical set `'low' | 'medium' | 'high' | 'critical'` (no `'info'`, no
bespoke strings). The tier is **evidence-based**, not format-based — an empty
`.hta` with no scripts and no IOCs is `'low'`, a weaponised `.png` with an
embedded PE is `'high'`. To stay consistent with the rest of the codebase:

1. **Initialise `f.risk = 'low'`.** Do not pre-stamp renderers with `'medium'`
   or `'high'` on the grounds that the format "can be abused". The risk bar
   in the sidebar and the Summary exporter both read `findings.risk`
   directly; a pre-stamped floor produces false-positive risk colouring on
   benign samples.
2. **Escalate from `externalRefs`.** The end of `analyzeForSecurity()` should
   look at the severities it just pushed onto `f.externalRefs` (detections
   mirrored in as `IOC.PATTERN`, plus any format-specific escalations you
   already wrote) and lift `f.risk` accordingly. The canonical tail is:
   ```js
   const highs   = f.externalRefs.filter(r => r.severity === 'high').length;
   const hasCrit = f.externalRefs.some(r => r.severity === 'critical');
   const hasMed  = f.externalRefs.some(r => r.severity === 'medium');
   if      (hasCrit)      f.risk = 'critical';
   else if (highs >= 2)   f.risk = 'high';
   else if (highs >= 1)   f.risk = 'medium';
   else if (hasMed)       f.risk = 'low';
   ```
3. **Never silently downgrade.** If your renderer already has a hand-rolled
   escalation path (e.g. `if (dangerousContent) f.risk = 'high';`), gate the
   calibration block with a monotonic rank check so later evidence only ever
   lifts the tier:
   ```js
   const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
   if ((rank[tier] || 0) > (rank[f.risk] || 0)) f.risk = tier;
   ```
4. **Detections must be mirrored first.** The calibration block only works
   if every `Detection` has already been pushed into `externalRefs` as an
   `IOC.PATTERN` (see item 5 in the IOC Push Checklist below). Otherwise a
   YARA-only finding stays invisible to the risk calculation.

The `cross-renderer-sanity-check` skill grades new renderers against this
contract; a renderer that stamps `'high'` without evidence, or stays `'low'`
despite pushing high-severity externalRefs, will fail that audit.

### IOC Push Helpers

`src/constants.js` ships two helpers every renderer should prefer over
hand-rolling `findings.interestingStrings.push({...})`:

- **`pushIOC(findings, {type, value, severity?, highlightText?, note?, bucket?})`**
  writes a canonical IOC row into `interestingStrings` (or `externalRefs` when
  `bucket: 'externalRefs'` is passed). It pins the on-wire shape
  (`{type, url, severity, _highlightText?, note?}`) and — crucially — **auto-emits
  a sibling `IOC.DOMAIN` row** whenever `type === IOC.URL` and vendored `tldts`
  resolves the URL to a registrable domain. Renderers should therefore push URLs
  through `pushIOC`; the domain pivot falls out for free and the audit surface
  is identical across formats. Pass `_noDomainSibling: true` in rare cases where
  you already emit a manual domain row.

- **`mirrorMetadataIOCs(findings, {metadataKey: IOC.TYPE, ...}, opts?)`** is a
  metadata → IOC mirror. The sidebar IOC table is fed *only* from
  `externalRefs + interestingStrings` — a value that lives on
  `findings.metadata` alone never reaches the analyst's pivot list. Call this
  at the end of `analyzeForSecurity()` to mirror the **classic pivot** fields
  (hashes, paths, GUIDs, MAC, emails, cert fingerprints) into the sidebar.
  Array-valued metadata (e.g. a `dylibs[]` list) emits one IOC per element.

**Option-B rule**: mirror only classic pivots. Do **not** mirror attribution
fluff — `CompanyName`, `FileDescription`, `ProductName`, `SubjectName` etc.
stay on `metadata` and are visible in the viewer, but they are noise in a
pivot list and fatten `📤 Export`'s CSV/STIX/MISP output for no operational
gain.

### IOC Push Checklist

Every IOC the renderer emits — whether onto `findings.externalRefs` or `findings.interestingStrings` — must obey this contract. The `ioc-conformity-audit` skill grades pull requests against these rules; drift here is what the audit exists to catch.

1. **Type is always an `IOC.*` constant** from `src/constants.js`. Never a bespoke string literal (`type: 'url'`, `type: 'ioc'`, `type: 'email'`) — those slip past the sidebar's copy/filter/share wiring. The canonical set is `IOC.URL`, `IOC.EMAIL`, `IOC.IP`, `IOC.FILE_PATH`, `IOC.UNC_PATH`, `IOC.ATTACHMENT`, `IOC.YARA`, `IOC.PATTERN`, `IOC.INFO`, `IOC.HASH`, `IOC.COMMAND_LINE`, `IOC.PROCESS`, `IOC.HOSTNAME`, `IOC.USERNAME`, `IOC.REGISTRY_KEY`, `IOC.MAC`, `IOC.DOMAIN`, `IOC.GUID`, `IOC.FINGERPRINT`.

2. **Severity comes from `IOC_CANONICAL_SEVERITY`** (also in `src/constants.js`) unless you have a renderer-specific reason to escalate. Escalations are fine — a URL becomes `high` in a phishing EML with `authTripleFail`, a command line lifted from a LNK trigger warrants `critical` — but they must be *escalations* from the canonical floor, not reductions.
3. **Carry `_highlightText`, never raw offsets into a synthetic buffer.** The sidebar's click-to-focus mechanism uses `_sourceOffset` / `_sourceLength` / `_highlightText` to scroll and highlight. Offsets are only meaningful when they are true byte offsets into the rendered surface. If you extracted the value from a joined-string buffer (`strings.join('\n')`), set only `_highlightText: <value>` — the sidebar will locate it in the plaintext table at display time.
4. **Cap large IOC lists with an `IOC.INFO` truncation marker.** When a renderer walks a large space (PE/ELF/Mach-O string tables, EVTX event fields, ZIP attachments), enforce a cap (`URL_CAP=50`, `IOC_CAP=500`, …) and *after* the cap push exactly one `IOC.INFO` row whose `url:` field explains the reason and the cap count. The Summary / Share exporters read this row — without it the analyst has no way to know they are looking at a truncated view.
5. **Mirror every `Detection` into `externalRefs` as `IOC.PATTERN`.** The standard tail in `analyzeForSecurity` is `findings.externalRefs = findings.detections.map(d => ({ type: IOC.PATTERN, url: `${d.name} — ${d.description}`, severity: d.severity }))`. Without this, a detection shows up in the banner but is invisible to Summary, Share, and the STIX/MISP exporters.
6. **Every IOC value must be click-to-focus navigable.** When the sidebar fires a navigation event for your IOC, the renderer's container should react: `_rawText` present for plaintext renderers, `_showSourcePane()` for toggle-driven ones (HTML/SVG/URL), or a custom click handler that softscrolls the relevant row/card into view and flashes a highlight class.

**Docs to update (required) when adding a new renderer that emits IOCs:**

- Regenerate `CODEMAP.md` (`python generate-codemap.py`).
- No hand-edits to the docs are required for IOC plumbing alone — but the next `ioc-conformity-audit` run should come back 🟢 on your diff.

---

## Adding a New Export Format


The toolbar's **📤 Export** dropdown is driven by a declarative menu in `src/app/app-ui.js`. All exporters are offline, synchronous (or `async` + `await` for `crypto.subtle` hashing only), and must never reach the network. **Default to the clipboard** — every menu item except `💾 Save raw file` writes to the clipboard so the analyst can paste straight into a ticket / TIP / jq pipeline. Plaintext and Markdown report exports live behind the separate `⚡ Summary` toolbar button; do not add a clipboard-Markdown or download-Markdown item to the dropdown, that duplication was deliberately removed.

Adding a new format is a three-step change:

1. **Write the builder.** Add `_buildXxx(model)` + a thin `_exportXxx()` wrapper (or fold both into one `_exportXxx()`) to the `Object.assign(App.prototype, {...})` block in `src/app/app-ui.js`. Reuse the shared helpers:
   - `this._collectIocs()` — normalised IOC list (each entry has `type`, `value`, `severity`, `note`, `source`, `stixType`).
   - `this._fileMeta`, `this.fileHashes`, `this.findings` — canonical input surface.
   - `this._fileSourceRecord()` — identical `{name,size,detectedType,magic,entropy,hashes{…}}` block that every threat-intel exporter embeds so the file is unambiguously identified.
   - `this._copyToClipboard(text)` + `this._toast('Xxx copied to clipboard')` — **the default destination**.
   - `this._buildAnalysisText(Infinity)` — unbudgeted plaintext report (same content as the ⚡ Summary button), for anything that legitimately needs a human-readable blob.
   - `this._downloadText(text, filename, mime)` / `this._downloadJson(obj, filename)` / `this._exportFilename(suffix, ext)` — only for the rare case where the output is genuinely a file (e.g. `💾 Save raw file`). Never call `URL.createObjectURL` directly.
2. **Register the menu item.** Add an entry to the array returned by `_getExportMenuItems()` — `{ id, icon, label, action: () => this._exportXxx() }`. Use `{ separator: true }` to add a divider. Prefix the label with `Copy ` when the action writes to the clipboard so the destination is visible without hovering. Order the array in the order items should render.
3. **Wrap it.** The click dispatcher in `_openExportMenu()` already wraps every action in `try { … } catch (err) { console.error(…); this._toast('Export failed — see console', 'error'); }`. Your exporter just needs to `_toast('Xxx copied to clipboard')` (or similar) on success.

**Docs to update (required):**

- `FEATURES.md` → add a column to the format × contents matrix in the **📤 Exports** section, plus a row to the menu-actions table.
- `README.md` → only if the new format belongs in the capabilities one-liner under **What It Finds**.
- `CODEMAP.md` → regenerate with `python generate-codemap.py`.

**Do not:**

- Pull in a new vendored library just for an export format — if the spec needs SHA-1/SHA-256, use `crypto.subtle`; if it needs UUIDv5, use the existing `_uuidv5()` helper.
- Fabricate vendor-specific custom extensions (e.g. `x_loupe_*` STIX properties) — either map to a standard field or skip the IOC.
- Add network calls, `eval`, `new Function`, or anything that would require a CSP relaxation.

---

## Adding a New Theme

All six built-in themes are driven by the same set of CSS custom properties
("design tokens") defined in `src/styles/core.css`. A new theme is a pure
overlay — it only re-defines the tokens and does not touch any selector, layout
rule, or component style elsewhere in the codebase. `src/styles/viewers.css`
and every renderer's inline styles read exclusively from these tokens so a
single overlay file flips every surface in the app.

### The token contract

The canonical tokens every theme must define live at the top of
`src/styles/core.css`. The non-negotiable ones are:

| Token | Purpose |
|---|---|
| `--accent` / `--accent-rgb` / `--accent-hover` / `--accent-deep` | Primary brand colour (buttons, focus rings, links). `--accent-rgb` is the **space-separated** RGB channel triplet (`"r g b"`, not `"r,g,b"`) used by CSS Colors 4 `rgb(var(--accent-rgb) / .12)` syntax for themed transparency |
| `--risk-high` / `--risk-high-rgb` / `--risk-med` / `--risk-low` / `--risk-info` | Four-tier risk palette consumed by the risk bar, detection chips, and every `container.style.color = 'var(--risk-high)'` site inside renderers |
| `--hairline-soft` / `--hairline` / `--hairline-strong` / `--hairline-bold` | Four-tier border palette used by all dividers, table grids, and card outlines |
| `--panel-bg` / `--panel-bg-inset` / `--panel-bg-raised` / `--panel-bg-section` | Four-tier panel surface palette used by every per-format renderer. `--panel-bg` is the main viewer pane; `--panel-bg-inset` is deeper (hex dumps, raw XML, code blocks); `--panel-bg-raised` lifts a level (search bars, chips, side cards); `--panel-bg-section` is the section-header / `<th>` / subheading tier |
| `--panel-border` / `--input-border` | Solid-colour borders for panels and form controls respectively (used alongside the hairline tokens for renderer chrome) |
| `--input-bg` / `--row-hover` | Form control background; table-row and list-item hover tint |
| `--text` / `--text-muted` / `--text-faint` | Three-tier foreground palette: primary body text, labels / secondary info, and placeholders / gutter numerals |
| `--banner-warn-*` / `--banner-danger-*` / `--banner-info-*` / `--banner-ok-*` | Per-severity banner tints. Each family has `-bg`, `-text` (where applicable), and `-border` so warnings, danger bars, info callouts, and success notices all retint with the theme's palette instead of the default yellow/red/blue/green |

The full list is enumerated in the `:root` / `body.dark` blocks at the top
of `core.css` — any token used by `viewers.css` must have a value in every
overlay, or the Light / Dark baseline will leak through. **In practice
this means you never reach for a hardcoded hex or `rgba(255, 255, 255, …)`
in a `body.dark` rule; there is a semantic token for every renderer-chrome
surface.** A one-off CI-style check: `grep -nE '#[0-9a-f]{3,8}|rgba\('
src/styles/viewers.css | grep -v 'var(--' | grep 'body\.dark'` should only
return `.hljs-*` syntax-highlighting rules (which are intentionally fixed).

### Recipe

1. **Create the overlay** — add `src/styles/themes/<id>.css` scoped to
   `body.theme-<id>`. Only re-declare the tokens; never write component-level
   selectors. Example:

   ```css
   body.theme-foo {
     --accent: #ffb454;
     --accent-rgb: 255 180 84;
     --accent-hover: #ffc673;
     --accent-deep: #cc8f43;
     --risk-high: #f26d6d;
     --risk-high-rgb: 242 109 109;
     /* …every token from the contract… */
   }
   ```

2. **Register in `CSS_FILES`** — append the overlay path to the
   `CSS_FILES` list in `build.py` so the bytes are inlined into
   `docs/index.html`.

3. **Register in `THEMES`** — add a `{ id, label, icon, dark }` row to the
   `THEMES` array at the top of `src/app/app-ui.js`. Set `dark: true` for
   any theme whose tokens target a dark baseline — the runtime toggles
   `body.dark` so `core.css`'s dark-baseline rules apply under the overlay.

4. **Update the FOUC bootstrap** — add the new id to the `THEME_IDS` array
   in the inline `<script>` in `build.py` (just after the `<style>` block).
   If the theme is dark, also add its id to the `DARK_THEMES` map. Without
   this the FOUC bootstrap will refuse to apply the saved theme and the
   user will see a one-frame flash of Light/Dark before `_initTheme()` in
   `app-ui.js` catches up.

5. **Rebuild and test** — `python build.py`, then open
   `docs/index.html` and click through every tile in ⚙ Settings → Theme.
   Every panel, chip, border, and risk colour should flip; no hard-coded
   hex should leak through.

6. **Regenerate the code map** — `python generate-codemap.py`.

**Docs to update (required):**

- `FEATURES.md` — update the "Theme picker" row to mention the new theme
  in the tile list.
- `README.md` — only if the new theme is promoted to the compact theme
  list under **🎨 Themes** (add a screenshot to `screenshots/` as well).
- `CONTRIBUTING.md` — no update needed; this recipe is generic.

### FOUC prevention

The inline `<script>` in `build.py` (`<head>`, immediately after the
`<style>` block) applies the saved theme class to `<body>` before the
first paint so users never see a flash of the default palette. The logic
mirrors `_initTheme()` in `src/app/app-ui.js` and is covered by CSP's
`script-src 'unsafe-inline'` (which is already required by the rest of the
single-file bundle, so no relaxation is added). If `<body>` has not been
parsed yet, the bootstrap stashes the classes on `<html>` and copies them
across via a one-shot `MutationObserver` the moment `<body>` appears.

First-boot fallback order:
1. Saved `localStorage['loupe_theme']` (if a valid id).
2. OS `prefers-color-scheme: light` → Light, else Dark.
3. Hard-coded `'dark'` if both of the above fail.

---

## How to Contribute

1. Fork the repo
2. Make your changes in `src/`
3. Run `python build.py` to rebuild
4. Test by opening `docs/index.html` in a browser
5. Run `python generate-codemap.py` to update the code map
6. Submit a pull request

YARA rule submissions, new format parsers, and build-process improvements are especially welcome.

The codebase is intentionally vanilla JavaScript (no frameworks, no bundlers beyond the simple `build.py` concatenator) to keep the tool auditable and easy to understand.
