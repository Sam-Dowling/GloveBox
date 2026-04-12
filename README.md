# 🧤📦 GloveBox

**A 100% offline, single-file security analyser for suspicious files.**  
No server, no uploads, no tracking — just drop a file and inspect it.

> **[▶ Try it here](https://sam-dowling.github.io/GloveBox/)**

---

## Why GloveBox?

SOC analysts, incident responders, and security-conscious users need a way to safely inspect suspicious files without uploading them to third-party services or spinning up a sandbox. GloveBox runs entirely in your browser — **nothing ever leaves your machine**.

- **Zero network access** — a strict Content-Security-Policy blocks all external fetches.
- **Single HTML file** — no install, no dependencies, works on any OS with a modern browser.
- **Broad format coverage** — Office documents, PDFs, emails, archives, images, scripts, and more.

---

## Features

### Supported Formats

| Category | Extensions |
|---|---|
| **Office (modern)** | `.docx` `.docm` `.xlsx` `.xlsm` `.pptx` `.pptm` `.ods` |
| **Office (legacy)** | `.doc` `.xls` `.ppt` |
| **OpenDocument** | `.odt` (text) · `.odp` (presentation) |
| **RTF** | `.rtf` — text extraction + OLE/exploit analysis |
| **PDF** | `.pdf` |
| **Email** | `.eml` `.msg` |
| **HTML** | `.html` `.htm` `.mht` — sandboxed preview + source view |
| **Archives** | `.zip` `.rar` `.7z` `.cab` — content listing, threat flagging, clickable entry extraction, ZipCrypto decryption |
| **Disk images** | `.iso` `.img` — ISO 9660 filesystem listing |
| **OneNote** | `.one` — embedded object extraction + phishing detection |
| **Windows** | `.lnk` (Shell Link) · `.hta` (HTML Application) · `.url` `.webloc` (Internet shortcuts) · `.reg` (Registry) · `.inf` (Setup Information) · `.sct` (Script Component) · `.msi` (Installer) |
| **Scripts** | `.wsf` `.wsc` `.wsh` (Windows Script Files — parsed) · `.vbs` `.ps1` `.bat` `.cmd` `.js` |
| **Forensics** | `.evtx` (Windows Event Log) · `.sqlite` `.db` (SQLite — Chrome/Firefox/Edge history auto-detect) |
| **Data** | `.csv` `.tsv` · `.iqy` (Internet Query) · `.slk` (Symbolic Link) |
| **Images** | `.jpg` `.jpeg` `.png` `.gif` `.bmp` `.webp` `.ico` `.tif` `.tiff` `.avif` `.svg` — preview + steganography/polyglot detection |
| **Catch-all** | *Any file* — plain-text view with line numbers, or hex dump for binary data |

### Security Analysis

| Capability | Detail |
|---|---|
| **Risk assessment** | Colour-coded risk bar (low / medium / high / critical) with finding summary |
| **Document search** | In-toolbar search with match highlighting, match counter, and `Enter`/`Shift+Enter` navigation (`Ctrl+F` to focus) |
| **YARA rule engine** | In-browser YARA rule parser and matcher — load/edit/save `.yar` rules, scan any loaded file with text, hex, and regex string support. Ships with default detection rules that auto-scan on file load |
| **File hashes** | MD5 · SHA-1 · SHA-256 computed in-browser, with one-click VirusTotal lookup |
| **IOC extraction** | URLs, email addresses, IP addresses, file paths, and UNC paths pulled from document content and VBA source |
| **VBA / macro analysis** | Extracts and syntax-highlights VBA source; flags auto-execute entry points (`AutoOpen`, `Workbook_Open`, `Shell`, etc.) |
| **Macro download** | Download decoded VBA as `.txt`, or the raw `vbaProject.bin` for offline analysis with olevba / oledump |
| **PDF scanning** | Detects `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, URIs, XFA forms, and other risky operators via YARA rules |
| **EML / email analysis** | Full RFC 5322/MIME parser — headers, multipart body, attachments, SPF/DKIM/DMARC auth results, tracking pixel detection |
| **LNK inspection** | MS-SHLLINK binary parser — target path, arguments, timestamps, dangerous-command detection, UNC credential-theft patterns |
| **HTA analysis** | Script extraction, `<HTA:APPLICATION>` attribute parsing, obfuscation detection, 40+ suspicious pattern checks |
| **Script scanning** | Catch-all viewer scans `.vbs`, `.ps1`, `.bat`, `.rtf` and other script types for dangerous execution patterns + YARA matching |
| **Image analysis** | Steganography indicators, polyglot file detection, and hex header inspection for embedded payloads |
| **EVTX analysis** | Parses Windows Event Log binary format (ElfFile header, chunks, BinXml records); extracts Event ID, Level, Provider, Channel, Computer, timestamps, and EventData; flags suspicious events (4688, 4624/4625, 1102, 7045, 4104); extracts IOCs: usernames (`DOMAIN\User`), hostnames, IPs, process paths, command lines, hashes, URLs, file/UNC paths; Copy/Download as CSV |
| **SQLite / browser history** | Reads SQLite binary format (B-tree pages, schema, cell data); auto-detects Chrome/Edge/Firefox history databases; extracts URLs, titles, visit counts, timestamps; generic table browser for non-history SQLite files; Copy/Download as CSV |
| **Encoded content detection** | Scans for Base64, hex, Base32 encoded blobs and compressed streams (gzip/zlib/deflate); decodes, classifies payloads (PE, script, URL list, etc.), extracts IOCs, and offers "Load for analysis" to drill into decoded content |
| **Archive drill-down** | Click entries inside ZIP/archive listings to open and analyse inner files, with Back navigation |
| **Document metadata** | Author, title, dates, revision count extracted from `docProps/core.xml` |

### User Interface

| Feature | Detail |
|---|---|
| **Midnight Glass theme** | Premium dark mode with frosted-glass panels, gradient surfaces, and cyan accent highlights |
| **Light / dark toggle** | Switch between dark and light themes with one click (🌙 / ☀) |
| **Floating zoom controls** | Zoom 50–200% via a floating control that stays out of the way |
| **Click-and-drag panning** | Grab and drag to pan around rendered documents |
| **Collapsible sidebar** | Single-pane sidebar with collapsible `<details>` sections: File Info, Macros, Signatures & IOCs |
| **Resizable sidebar** | Drag the sidebar edge to resize (33–50% of the viewport) |
| **Keyboard shortcuts** | `S` toggle sidebar · `Y` YARA dialog · `?`/`H` help & about · `Ctrl+F` search document · `Ctrl+V` paste file for analysis |
| **Loading overlay** | Spinner with status message while parsing large files |
| **Toast notifications** | Non-intrusive feedback for downloads, clipboard operations, and errors |

---

## Quick Start

1. **Open** `glovebox.html` in any modern browser (Chrome, Firefox, Edge, Safari).
2. **Drop** a file onto the drop zone, or click **📁 Open File** (or paste with **Ctrl+V**).
3. The file renders in the viewer — use click-and-drag to pan, and the floating ± buttons to zoom.
4. Click **🛡 Toggle Sidebar** (or press **S**) to open the security panel — a single scrollable pane with collapsible sections:
   - **📋 File Info** — file format, MD5/SHA-1/SHA-256 hashes, VBA project hash, document metadata.
   - **⚡ Macros** — VBA module source with syntax highlighting, auto-execute warnings, and download options (only shown when macros are detected).
   - **🔍 Signatures & IOCs** — YARA rule matches and IOCs (URLs, emails, IPs, file paths, UNC paths), sorted by severity, filterable, and downloadable as `.txt`.
5. Press **Y** to open the YARA rule editor — load custom rules, edit, validate, and scan the current file.
6. Use **🌙** to toggle between dark and light themes.

---

## Building from Source

Requires **Python 3.8+** (standard library only — no `pip install` needed).

```bash
python build.py
```

The build script reads `src/styles.css` and the JS source files listed below, inlines all CSS and JavaScript (including vendor libraries) into a single self-contained HTML document, and writes two identical copies:

| Output | Purpose |
|---|---|
| `glovebox.html` | Root-level convenience copy for local use |
| `docs/index.html` | GitHub Pages deployment |

### JS Concatenation Order

The application code is concatenated in dependency order:

```
src/constants.js                       # Namespace constants, DOM helpers, unit converters
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
src/renderers/image-renderer.js        # ImageRenderer — image preview + stego/polyglot detection
src/renderers/plaintext-renderer.js    # PlainTextRenderer — catch-all text/hex viewer
src/app/app-core.js                    # App class — constructor, init, drop-zone, toolbar
src/app/app-load.js                    # File loading, hashing (MD5/SHA), IOC extraction
src/app/app-sidebar.js                 # Sidebar rendering — risk bar + collapsible panes
src/app/app-yara.js                    # YARA rule editor dialog, scanning, result display
src/app/app-ui.js                      # UI helpers (zoom, theme, pan, toast) + bootstrap
```

Default YARA rules (`src/default-rules.yar`) are escaped and injected as a JS constant before the application code.

Vendor libraries (`vendor/jszip.min.js`, `vendor/xlsx.full.min.js`, `vendor/pdf.min.js`, `vendor/pdf.worker.min.js`) are inlined into separate `<script>` blocks before the application code.

---

## Project Structure

```
GloveBox/
├── build.py                       # Build script — reads src/, writes HTML outputs
├── glovebox.html                  # Built output (root convenience copy)
├── README.md
├── docs/
│   └── index.html                 # Built output (GitHub Pages)
├── vendor/
│   ├── jszip.min.js               # JSZip — ZIP parsing for DOCX/XLSX/PPTX
│   ├── xlsx.full.min.js           # SheetJS — spreadsheet parsing
│   ├── pdf.min.js                 # pdf.js — PDF rendering (Mozilla)
│   └── pdf.worker.min.js          # pdf.js worker — PDF parsing backend
├── src/
│   ├── styles.css                 # All UI CSS (Midnight Glass theme, toolbar, sidebar, views)
│   ├── constants.js               # Shared constants, DOM helpers, unit converters, sanitizers
│   ├── vba-utils.js               # Shared VBA binary decoder + auto-exec pattern scanner
│   ├── yara-engine.js             # YaraEngine — in-browser YARA rule parser + matcher
│   ├── decompressor.js            # Decompressor — gzip/deflate/raw via DecompressionStream
│   ├── encoded-content-detector.js # EncodedContentDetector — encoded blob scanner
│   ├── default-rules.yar          # Default YARA detection rules (auto-loaded)
│   ├── docx-parser.js             # DocxParser class
│   ├── style-resolver.js          # StyleResolver class
│   ├── numbering-resolver.js      # NumberingResolver class
│   ├── content-renderer.js        # ContentRenderer class
│   ├── security-analyzer.js       # SecurityAnalyzer class
│   ├── renderers/
│   │   ├── ole-cfb-parser.js      # OleCfbParser — CFB compound file parser
│   │   ├── xlsx-renderer.js       # XlsxRenderer
│   │   ├── pptx-renderer.js       # PptxRenderer
│   │   ├── odt-renderer.js        # OdtRenderer — OpenDocument text
│   │   ├── odp-renderer.js        # OdpRenderer — OpenDocument presentation
│   │   ├── ppt-renderer.js        # PptRenderer — legacy .ppt
│   │   ├── rtf-renderer.js        # RtfRenderer — RTF + OLE analysis
│   │   ├── zip-renderer.js        # ZipRenderer — archive listing
│   │   ├── iso-renderer.js        # IsoRenderer — ISO 9660 filesystem
│   │   ├── url-renderer.js        # UrlRenderer — .url / .webloc shortcuts
│   │   ├── onenote-renderer.js    # OneNoteRenderer — .one files
│   │   ├── iqy-slk-renderer.js    # IqySlkRenderer — .iqy / .slk files
│   │   ├── wsf-renderer.js        # WsfRenderer — Windows Script Files
│   │   ├── reg-renderer.js        # RegRenderer — .reg registry files
│   │   ├── inf-renderer.js        # InfSctRenderer — .inf / .sct files
│   │   ├── msi-renderer.js        # MsiRenderer — .msi installer packages
│   │   ├── csv-renderer.js        # CsvRenderer
│   │   ├── evtx-renderer.js       # EvtxRenderer — .evtx parser
│   │   ├── sqlite-renderer.js     # SqliteRenderer — SQLite + browser history
│   │   ├── doc-renderer.js        # DocBinaryRenderer
│   │   ├── msg-renderer.js        # MsgRenderer
│   │   ├── eml-renderer.js        # EmlRenderer
│   │   ├── lnk-renderer.js        # LnkRenderer
│   │   ├── hta-renderer.js        # HtaRenderer
│   │   ├── html-renderer.js       # HtmlRenderer — sandboxed HTML preview
│   │   ├── pdf-renderer.js        # PdfRenderer
│   │   ├── image-renderer.js      # ImageRenderer — image preview + stego detection
│   │   └── plaintext-renderer.js  # PlainTextRenderer
│   └── app/
│       ├── app-core.js            # App class definition + setup methods
│       ├── app-load.js            # File loading, hashing, IOC extraction
│       ├── app-sidebar.js         # Sidebar rendering (risk bar + collapsible panes)
│       ├── app-yara.js            # YARA rule editor, scanning, result display
│       └── app-ui.js              # UI helpers + DOMContentLoaded bootstrap
└── examples/                      # Sample files for testing various formats
```

---

## Architecture

- **Single output file** — `build.py` inlines all CSS and JavaScript so the viewer works by opening one `.html` file with zero external dependencies.
- **No eval, no network** — the Content-Security-Policy (`default-src 'none'`) blocks all external fetches; images are rendered only from `data:` and `blob:` URLs.
- **App class split** — `App` is defined in `app-core.js`; additional methods are attached via `Object.assign(App.prototype, {...})` in `app-load.js`, `app-sidebar.js`, `app-yara.js`, and `app-ui.js`, keeping each file focused.
- **YARA-based detection** — all threat detection is driven by YARA rules. A set of default rules (`src/default-rules.yar`) ships with the tool and is auto-scanned on file load. Users can edit, load, and save custom rules via the built-in YARA editor (`Y` key).
- **Shared VBA helpers** — `parseVBAText()` and `autoExecPatterns` live in `vba-utils.js` and are reused by `DocxParser`, `XlsxRenderer`, and `PptxRenderer`.
- **OLE/CFB parser** — `OleCfbParser` is shared by `DocBinaryRenderer` (`.doc`), `MsgRenderer` (`.msg`), and `PptRenderer` (`.ppt`) for reading compound binary files.
- **PDF rendering** — `PdfRenderer` uses Mozilla's pdf.js for canvas rendering plus raw-byte scanning for dangerous PDF operators. Hidden text layers enable IOC extraction from rendered pages.
- **EML parsing** — Full RFC 5322/MIME parser with multipart support, quoted-printable and base64 decoding, attachment extraction, and authentication header analysis.
- **LNK parsing** — Implements the MS-SHLLINK binary format, extracting target paths, arguments, timestamps, and environment variable paths. Flags dangerous executables and evasion patterns.
- **HTA analysis** — Treats `.hta` files as inherently high-risk, extracting embedded scripts, `<HTA:APPLICATION>` attributes, and scanning against 40+ suspicious patterns including obfuscation techniques.
- **HTML rendering** — `HtmlRenderer` provides a sandboxed iframe preview (with all scripts and network disabled) and a source-code view with line numbers.
- **Image analysis** — `ImageRenderer` renders image previews and checks for steganography indicators, polyglot file structures, and suspicious embedded data.
- **Archive drill-down** — `ZipRenderer` lists archive contents with threat flagging, and allows clicking individual entries to extract and open them for full analysis, with Back navigation.
- **Encoded content detection** — `EncodedContentDetector` scans file text for Base64, hex, and Base32 encoded blobs plus embedded compressed streams (gzip/deflate). High-confidence patterns (PE headers, gzip magic, PowerShell `-EncodedCommand`) are decoded eagerly; other candidates offer a manual "Decode" button. Decoded payloads are classified, IOCs are extracted, and a "Load for analysis" button feeds decoded content back through the full analysis pipeline with breadcrumb navigation.
- **Catch-all viewer** — `PlainTextRenderer` accepts any file type. Text files get line-numbered display; binary files get a hex dump. Both paths run IOC extraction and YARA scanning.

---

## Security Model

GloveBox is designed to be safe to use on potentially malicious files:

| Layer | Protection |
|---|---|
| **No network** | CSP `default-src 'none'` — zero external requests, ever |
| **No eval** | No dynamic code execution; all parsing is structural |
| **No file system** | Browser sandbox — cannot read or write anything beyond the dropped file |
| **Sanitised rendering** | HTML content is escaped and sanitised; images use `data:` / `blob:` URLs only |
| **Sandboxed HTML** | HTML files are rendered in a heavily sandboxed iframe with scripts and network disabled |
| **Offline by design** | Works identically with Wi-Fi off or in an air-gapped environment |

> ⚠️ GloveBox is a **triage and inspection tool**, not a sandbox. It does not execute macros, JavaScript from PDFs, or scripts embedded in files — it extracts and displays them for human review.

---

## Browser Compatibility

Tested and working in:

- Google Chrome / Chromium 90+
- Mozilla Firefox 90+
- Microsoft Edge 90+
- Safari 15+

Requires support for Web Crypto API (SHA-1/SHA-256), `async`/`await`, and `<canvas>`.

---

## Contributing

Contributions are welcome! The codebase is intentionally vanilla JavaScript (no frameworks, no bundlers beyond the simple `build.py` concatenator) to keep the tool auditable and easy to understand.

1. Fork the repo
2. Make your changes in `src/`
3. Run `python build.py` to rebuild
4. Test by opening `glovebox.html` in a browser
5. Submit a pull request

---

## Licence

This project is licensed under the [GNU General Public License v3.0](LICENSE).
