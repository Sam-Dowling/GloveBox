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
```

Light and Dark are the baseline palettes and live in `core.css` (`body` / `body.dark`
selectors). Each extra theme is a pure-overlay file under `src/styles/themes/<id>.css`
scoped to `body.theme-<id>` and layered on top of `body.dark`. Register a new theme in
the `THEMES` array in `src/app/app-ui.js` and add the CSS path to `CSS_FILES` in
`build.py` — see the "Add a new theme" recipe below.

### YARA Rule Files

```
src/rules/office-macros.yar            # Office/VBA macro detection (33 rules)
src/rules/script-threats.yar           # Script threats: PS, JS, VBS, CMD, Python (61 rules)
src/rules/document-threats.yar         # PDF, RTF, OLE, HTML, SVG, OneNote (41 rules)
src/rules/windows-threats.yar          # LNK, HTA, MSI, registry, LOLBins (129 rules)
src/rules/archive-threats.yar          # Archive format threats (10 rules)
src/rules/encoding-threats.yar         # Base64, hex, obfuscation patterns (28 rules)
src/rules/network-indicators.yar       # UNC, WebDAV, credential theft (8 rules)
src/rules/suspicious-patterns.yar      # General suspicious patterns (10 rules)
src/rules/file-analysis.yar            # PE, image, forensic analysis (3 rules)
src/rules/pe-threats.yar               # PE executable threats: packers, malware toolkits (26 rules)
src/rules/elf-threats.yar              # ELF binary threats: Mirai, cryptominers, rootkits (17 rules)
src/rules/macho-threats.yar            # Mach-O binary threats: macOS stealers, RATs, persistence (17 rules)
src/rules/jar-threats.yar              # JAR/Java threats: deserialization, JNDI, reverse shells (17 rules)
src/rules/svg-threats.yar              # SVG threats: script injection, phishing, XXE (18 rules)
src/rules/osascript-threats.yar        # AppleScript/JXA threats: shell injection, persistence (18 rules)
src/rules/plist-threats.yar            # Property list threats: LaunchAgent, persistence keys (21 rules)
src/rules/clickonce-threats.yar        # ClickOnce deployment threats: AppDomainManager, HTTP deploy, full trust (4 rules)
src/rules/msix-threats.yar             # MSIX / APPX / App Installer threats: full-trust capabilities, startup tasks, silent auto-update (9 rules)
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
src/renderers/ole-cfb-parser.js        # OleCfbParser — CFB/OLE2 compound file reader
src/renderers/xlsx-renderer.js         # XlsxRenderer — spreadsheet view (SheetJS)
src/renderers/pptx-renderer.js         # PptxRenderer — slide canvas renderer
src/renderers/odt-renderer.js          # OdtRenderer — OpenDocument text renderer
src/renderers/odp-renderer.js          # OdpRenderer — OpenDocument presentation renderer
src/renderers/ppt-renderer.js          # PptRenderer — legacy .ppt slide extraction
src/renderers/rtf-renderer.js          # RtfRenderer — RTF text + OLE/exploit analysis
src/renderers/zip-renderer.js          # ZipRenderer — archive listing + threat flagging
src/renderers/iso-renderer.js          # IsoRenderer — ISO 9660 filesystem listing
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
src/app/app-core.js                    # App class — constructor, init, drop-zone, toolbar
src/app/app-load.js                    # File loading, hashing (MD5/SHA), IOC extraction
src/app/app-sidebar.js                 # Sidebar rendering — risk bar + collapsible panes
src/app/app-yara.js                    # YARA rules dialog — upload, validate, save, scan, result display
src/app/app-ui.js                      # UI helpers (zoom, theme, pan, toast) + bootstrap
```

Vendor libraries (`vendor/jszip.min.js`, `vendor/xlsx.full.min.js`, `vendor/pdf.min.js`, `vendor/pdf.worker.min.js`, `vendor/highlight.min.js`) are inlined into separate `<script>` blocks before the application code.

---

## Project Structure

```
Loupe/
├── build.py                         # Build script — reads src/, writes docs/index.html
├── generate-codemap.py              # Generates CODEMAP.md (AI agent navigation map)
├── CODEMAP.md                       # Auto-generated code map with line-level symbol index
├── README.md
├── CONTRIBUTING.md
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
│   │       └── solarized.css        # Solarized Dark — warm low-glare, dark-based
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
│   │   └── msix-threats.yar         # MSIX / APPX / App Installer threats
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
│   ├── renderers/
│   │   ├── ole-cfb-parser.js        # OleCfbParser — CFB compound file parser
│   │   ├── xlsx-renderer.js         # XlsxRenderer
│   │   ├── pptx-renderer.js         # PptxRenderer
│   │   ├── odt-renderer.js          # OdtRenderer — OpenDocument text
│   │   ├── odp-renderer.js          # OdpRenderer — OpenDocument presentation
│   │   ├── ppt-renderer.js          # PptRenderer — legacy .ppt
│   │   ├── rtf-renderer.js          # RtfRenderer — RTF + OLE analysis
│   │   ├── zip-renderer.js          # ZipRenderer — archive listing
│   │   ├── iso-renderer.js          # IsoRenderer — ISO 9660 filesystem
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
│   │   └── msix-renderer.js         # MsixRenderer — MSIX/APPX ZIP packages + .appinstaller XML analyser
│   └── app/
│       ├── app-core.js              # App class definition + setup methods
│       ├── app-load.js              # File loading, hashing, IOC extraction
│       ├── app-sidebar.js           # Sidebar rendering (risk bar + collapsible panes)
│       ├── app-yara.js              # YARA rules dialog (upload/validate/save/scan)
│       └── app-ui.js                # UI helpers + DOMContentLoaded bootstrap
└── examples/                        # Sample files for testing various formats
```

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
- **App class split** — `App` is defined in `app-core.js`; additional methods are attached via `Object.assign(App.prototype, {...})` in `app-load.js`, `app-sidebar.js`, `app-yara.js`, and `app-ui.js`, keeping each file focused.
- **YARA-based detection** — all threat detection is driven by YARA rules. Default rules are split across `src/rules/*.yar` by threat category and auto-scanned on file load. Users can upload (or drag-and-drop) their own `.yar` files, validate them, and save the combined rule set back out via the YARA dialog (`Y` key). There is no in-browser rule-editing surface — rule source is authored in an external editor and loaded as files; uploaded rules persist in `localStorage`.
- **Shared VBA helpers** — `parseVBAText()` and `autoExecPatterns` live in `vba-utils.js` and are reused by `DocxParser`, `XlsxRenderer`, and `PptxRenderer`.
- **OLE/CFB parser** — `OleCfbParser` is shared by `DocBinaryRenderer` (`.doc`), `MsgRenderer` (`.msg`), and `PptRenderer` (`.ppt`) for reading compound binary files.
- **PDF rendering** — `PdfRenderer` uses Mozilla's pdf.js for canvas rendering plus raw-byte scanning for dangerous PDF operators. Hidden text layers enable IOC extraction from rendered pages. JavaScript bodies from `/JS` actions (literal, hex, and indirect-stream with `/FlateDecode`) are extracted with per-script trigger / size / SHA-256 / suspicious-API hints; XFA form packets are pulled out for inspection; and `/EmbeddedFile` / `/Filespec` attachments emit `open-inner-file` CustomEvents handled by `app-load.js` — the same mechanism `ZipRenderer` uses for recursive drill-down, so analysts can click a PDF attachment and have it re-analysed in a new frame with Back navigation preserved.
- **EML parsing** — Full RFC 5322/MIME parser with multipart support, quoted-printable and base64 decoding, attachment extraction, and authentication header analysis.
- **LNK parsing** — Implements the MS-SHLLINK binary format, extracting target paths, arguments, timestamps, and environment variable paths. Flags dangerous executables and evasion patterns.
- **HTA analysis** — Treats `.hta` files as inherently high-risk, extracting embedded scripts, `<HTA:APPLICATION>` attributes, and scanning against 40+ suspicious patterns including obfuscation techniques.
- **HTML rendering** — `HtmlRenderer` provides a sandboxed iframe preview (with all scripts and network disabled) and a source-code view with line numbers.
- **Image analysis** — `ImageRenderer` renders image previews and checks for steganography indicators, polyglot file structures, and suspicious embedded data.
- **Archive drill-down** — `ZipRenderer` lists archive contents with threat flagging, and allows clicking individual entries to extract and open them for full analysis, with Back navigation.
- **Encoded content detection** — `EncodedContentDetector` scans file text for Base64, hex, and Base32 encoded blobs plus embedded compressed streams (gzip/deflate). High-confidence patterns (PE headers, gzip magic, PowerShell `-EncodedCommand`) are decoded eagerly; other candidates offer a manual "Decode" button. Decoded payloads are classified, IOCs are extracted, and a "Load for analysis" button feeds decoded content back through the full analysis pipeline with breadcrumb navigation.
- **PE analysis** — `PeRenderer` parses PE32/PE32+ binaries (EXE, DLL, SYS, DRV, OCX, CPL, COM, and `.xll` Excel add-ins) — DOS/COFF/Optional headers, section table with entropy analysis, imports with suspicious API flagging (~140 APIs), exports, resources, Rich header, string extraction, and security feature detection (ASLR, DEP, CFG, SEH, Authenticode). Additionally surfaces "what is this binary?" heuristics: XLL Excel add-in detection (xlAutoOpen export + Excel-DNA managed-loader recognition), compiled AutoHotkey script detection with embedded-script offset extraction, installer-family fingerprinting (Inno Setup, NSIS), and Go binary detection with `go.buildinfo` parsing (module path + Go version). These are emitted as flat `pe.*` fields, surfaced in the `⚡ Summary`, and backed by dedicated YARA rules in `pe-threats.yar`.
- **ELF analysis** — `ElfRenderer` parses ELF32/ELF64 binaries (LE/BE) — ELF header, program headers, section headers, dynamic linking (NEEDED, SONAME, RPATH/RUNPATH), symbol tables with suspicious symbol flagging, note sections, and security feature detection (RELRO, Stack Canary, NX, PIE, FORTIFY_SOURCE). Also performs Go binary detection via `.go.buildinfo` section parsing (module path + Go version), surfaced in the `⚡ Summary` and backed by an `ELF_Go_Binary` YARA rule.
- **Mach-O analysis** — `MachoRenderer` parses Mach-O 32/64-bit and Fat/Universal binaries — header, load commands, segments with section-level entropy, symbol tables with suspicious symbol flagging (~30 macOS APIs), dynamic libraries, RPATH, code signature (CodeDirectory, entitlements, CMS), and security feature detection (PIE, NX, Stack Canary, ARC, Hardened Runtime, Library Validation).
- **X.509 certificate analysis** — `X509Renderer` provides a pure-JS ASN.1/DER parser with ~80 OID mappings. Parses PEM/DER certificates and PKCS#12 containers — subject/issuer DN, validity period, public key details, extensions (SAN, Key Usage, EKU, CRL Distribution Points, AIA), fingerprints. Flags self-signed, expired, weak keys/signatures, and extracts IOCs from SANs and CRL/AIA URIs.
- **OpenPGP analysis** — `PgpRenderer` parses OpenPGP data (RFC 4880 / RFC 9580) in both ASCII-armored and binary forms. It enumerates packets, extracts key IDs, fingerprints, user IDs, subkeys, self-signatures and subkey bindings, decodes public-key algorithm / key size / ECC curve, and validates armor CRC-24 checksums. Flags unencrypted secret keys, weak key sizes, deprecated Elgamal-sign-or-encrypt, v3 legacy keys, revoked/expired keys, long-lived keys without expiry, and SHA-1 as preferred hash. Parse-only — no signature verification, no secret-key decryption. The `.key` extension is disambiguated between OpenPGP and X.509 PEM private keys via `_looksLikePgp()` in `app-load.js`, which inspects ASCII-armor headers and OpenPGP packet-tag bytes (0x99/0xC6 Public-Key, 0x95/0xC5 Secret-Key, etc.).
- **JAR / Java analysis** — `JarRenderer` parses JAR/WAR/EAR archives and standalone `.class` files — class file headers, MANIFEST.MF, package tree, dependency extraction, constant pool string analysis with ~45 suspicious Java API patterns mapped to MITRE ATT&CK, and obfuscation detection. The viewer uses a fixed-width column layout that eliminates reflow between sections: a Manifest / Security Findings two-column header grid (bounded-height scrollable panes), a large tab container for Classes / Dependencies / Strings / Resources / web.xml (each tab shows an entry-count badge plus a search-hit badge when filtered), and an expandable file tree replacing the old flat "All Entries" table. A single global search bar is tab- and tree-aware: it hides non-matching rows, highlights matching tree files, auto-expands ancestor folders, auto-switches to the first tab that contains hits if the active tab has none, and shows a live match count. Clickable inner file extraction still emits `open-inner-file` CustomEvents handled by `app-load.js`.
- **SVG analysis** — `SvgRenderer` provides a sandboxed iframe preview and source-code view with line numbers. `analyzeForSecurity()` performs deep SVG-specific analysis: `<script>` extraction, `<foreignObject>` detection, event handler scanning, Base64/data URI payload analysis, SVG-specific vectors (`<use>`, `<animate>`/`<set>` href manipulation, `<feImage>` external filters), XXE detection, and JavaScript obfuscation patterns. Augmented buffer is stored separately in `_yaraBuffer` to avoid contaminating Copy/Save.
- **AppleScript / JXA analysis** — `OsascriptRenderer` handles `.applescript` source files (syntax-highlighted display), compiled `.scpt` binaries (string extraction from binary data), and `.jxa` JavaScript for Automation files. Security analysis flags shell command execution (`do shell script`), application targeting, file system access, and macOS-specific persistence/privilege escalation patterns.
- **Property list analysis** — `PlistRenderer` parses both XML and binary `.plist` formats into an interactive tree view with expandable nested structures. Security analysis detects LaunchAgent/LaunchDaemon persistence, suspicious URL schemes, shell command execution, and privacy-sensitive entitlement keys. 21 dedicated YARA rules cover plist-specific threat patterns.
- **ClickOnce analysis** — `ClickOnceRenderer` parses `.application` deployment manifests and `.manifest` application manifests — both are XML that the renderer routes from `app-load.js` via a root-element sniff (`assembly` → ClickOnce, otherwise falls through to `PlainTextRenderer`). Extracts identity, description, deployment settings (provider URL, install vs run-from-source, update policy), entry-point command/parameters, requested trust level, `appDomainManagerAssembly` / `appDomainManagerType` overrides (a documented ClickOnce hijack vector), Authenticode signature presence, and `dependentAssembly` chains. Emits `findings.clickOnceInfo` which is surfaced in the `⚡ Summary` via `_copyAnalysisClickOnce`, and backed by four dedicated YARA rules in `clickonce-threats.yar` (`ClickOnce_AppDomainManager_Override`, `ClickOnce_HTTP_Deployment`, `ClickOnce_FullTrust_Requested`, `ClickOnce_Suspicious_Codebase_TLD`).
- **MSIX / APPX / App Installer analysis** — `MsixRenderer` handles `.msix` / `.msixbundle` / `.appx` / `.appxbundle` ZIP containers plus standalone `.appinstaller` XML; dispatch is by extension from `app-load.js`. For package containers it uses `JSZip` to extract `AppxManifest.xml` (or `AppxBundleManifest.xml`), then parses `<Identity>`, `<Properties>`, `<TargetDeviceFamily>`, `<Capabilities>` (split by tier: restricted `rescap:*` such as `runFullTrust` / `broadFileSystemAccess`; device; ordinary), and `<Applications>` with their `<Extensions>` — including `windows.fullTrustProcess`, `windows.startupTask`, `windows.appExecutionAlias` (alias-squatting check against common OS command names), `windows.protocol`, COM server/proxy/treatAs, background tasks, and services. Checks presence of `AppxSignature.p7x`, `AppxBlockMap.xml`, and `AppxMetadata/CodeIntegrity.cat`. Inner files (nested `.msix`, PE executables, scripts) emit the shared `open-inner-file` CustomEvent for recursive analysis, reusing the same wiring as `ZipRenderer`. For `.appinstaller` XML it parses root `Uri`, `MainPackage` / `MainBundle`, `Dependencies`, and `UpdateSettings` (flags silent `ShowPrompt="false"` + `ForceUpdateFromAnyVersion` auto-updates). All namespaces (`uap`, `uap3`, `uap5`, `rescap`, `desktop`) are read via `getElementsByTagNameNS("*", local)` so manifest prefix variations do not break extraction. Emits `findings.msixInfo` which is surfaced in the `⚡ Summary` via `_copyAnalysisMsix`, and backed by nine dedicated YARA rules in `msix-threats.yar` (`MSIX_Capability_RunFullTrust`, `MSIX_Capability_BroadFileSystem`, `MSIX_Extension_FullTrustProcess`, `MSIX_Extension_StartupTask`, `MSIX_AppExecutionAlias_CommonName`, `MSIX_AppInstaller_HTTP`, `MSIX_AppInstaller_Suspicious_TLD`, `MSIX_AppInstaller_Silent_AutoUpdate`, `MSIX_Protocol_Claim_Common`).
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

## How to Contribute

1. Fork the repo
2. Make your changes in `src/`
3. Run `python build.py` to rebuild
4. Test by opening `docs/index.html` in a browser
5. Run `python generate-codemap.py` to update the code map
6. Submit a pull request

YARA rule submissions, new format parsers, and build-process improvements are especially welcome.

The codebase is intentionally vanilla JavaScript (no frameworks, no bundlers beyond the simple `build.py` concatenator) to keep the tool auditable and easy to understand.
