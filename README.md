# 🐡 PhishFinder

**A 100% offline, single-file security analyser for suspicious files.**  
No server, no uploads, no tracking — just drop a file and inspect it.

> **[▶ Try it live on GitHub Pages](https://sam-dowling.github.io/PhishFinder/)**

---

## Why PhishFinder?

Phishing attachments are the #1 initial access vector. SOC analysts, incident responders, and security-conscious users need a way to safely inspect suspicious files without uploading them to third-party services or spinning up a sandbox. PhishFinder runs entirely in your browser — **nothing ever leaves your machine**.

- **Zero network access** — a strict Content-Security-Policy blocks all external fetches.
- **Single HTML file** — no install, no dependencies, works on any OS with a modern browser.
- **Broad format coverage** — Office documents, PDFs, emails, Windows shortcuts, scripts, and more.

---

## Features

### Supported Formats

| Category | Extensions |
|---|---|
| **Office (modern)** | `.docx` `.docm` `.xlsx` `.xlsm` `.pptx` `.pptm` `.ods` |
| **Office (legacy)** | `.doc` `.xls` |
| **PDF** | `.pdf` |
| **Email** | `.eml` `.msg` |
| **Windows** | `.lnk` (Shell Link) · `.hta` (HTML Application) |
| **Data** | `.csv` `.tsv` |
| **Catch-all** | *Any file* — plain-text view with line numbers, or hex dump for binary data |

### Security Analysis

| Capability | Detail |
|---|---|
| **Risk assessment** | Colour-coded risk bar (low / medium / high) with finding summary |
| **Threat signatures** | 84+ scored signatures across 6 categories: PDF, Office VBA, JavaScript, PowerShell, PE binaries, and general obfuscation — each with severity scores (1–3) |
| **YARA rule engine** | In-browser YARA rule parser and matcher — load/edit/save `.yar` rules, scan any loaded file with text, hex, and regex string support |
| **File hashes** | MD5 (pure-JS) · SHA-1 · SHA-256 computed in-browser, with one-click VirusTotal lookup |
| **IOC extraction** | URLs, email addresses, IP addresses, file paths, and UNC paths pulled from document content and VBA source |
| **VBA / macro analysis** | Extracts and syntax-highlights VBA source; flags auto-execute entry points (`AutoOpen`, `Workbook_Open`, `Shell`, etc.) |
| **Macro download** | Download decoded VBA as `.txt`, or the raw `vbaProject.bin` for offline analysis with olevba / oledump |
| **PDF scanning** | Detects `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, URIs, XFA forms, and other risky operators via signature engine |
| **EML / email analysis** | Full RFC 5322/MIME parser — headers, multipart body, attachments, SPF/DKIM/DMARC auth results, tracking pixel detection |
| **LNK inspection** | MS-SHLLINK binary parser — target path, arguments, timestamps, dangerous-command detection, UNC credential-theft patterns |
| **HTA analysis** | Script extraction, `<HTA:APPLICATION>` attribute parsing, obfuscation detection, 40+ suspicious pattern checks |
| **Script scanning** | Catch-all viewer scans `.vbs`, `.ps1`, `.bat`, `.rtf` and other script types for ~30 dangerous execution patterns + signature matching |
| **Document metadata** | Author, title, dates, revision count extracted from `docProps/core.xml` |

### User Interface

| Feature | Detail |
|---|---|
| **Midnight Glass theme** | Premium dark mode with frosted-glass panels, gradient surfaces, and cyan accent highlights |
| **Light / dark toggle** | Switch between dark and light themes with one click (🌙 / ☀) |
| **Floating zoom controls** | Zoom 50–200% via a floating control that stays out of the way |
| **Click-and-drag panning** | Grab and drag to pan around rendered documents |
| **Resizable sidebar** | Drag the sidebar edge to resize (33–60% of the viewport) |
| **Keyboard shortcuts** | `S` toggle sidebar · `1` / `2` / `3` switch tabs |
| **Loading overlay** | Spinner with status message while parsing large files |
| **Toast notifications** | Non-intrusive feedback for downloads, clipboard operations, and errors |

---

## Quick Start

1. **Open** `phishfinder.html` in any modern browser (Chrome, Firefox, Edge, Safari).
2. **Drop** a file onto the drop zone, or click **📁 Open File**.
3. The file renders in the viewer — use click-and-drag to pan, and the floating ± buttons to zoom.
4. Click **🛡 Toggle Sidebar** (or press **S**) to open the security panel:
   - **📋 Summary** — file format, MD5/SHA-1/SHA-256 hashes, VBA project hash, document metadata.
   - **🔍 Extracted** — IOCs (URLs, emails, IPs, file paths, UNC paths), searchable and downloadable as `.txt`.
   - **⚡ Macros** — VBA module source with syntax highlighting, auto-execute warnings, and download options.
5. Use **🌙** to toggle between dark and light themes.

---

## Building from Source

Requires **Python 3.8+** (standard library only — no `pip install` needed).

```bash
python build.py
```

The build script reads `src/styles.css` and the JS source files listed below, inlines all CSS and JavaScript (including vendor libraries) into a single self-contained HTML document, and writes three identical copies:

| Output | Purpose |
|---|---|
| `phishfinder.html` | Root-level convenience copy for local use |
| `dist/phishfinder.html` | Distribution artefact |
| `docs/index.html` | GitHub Pages deployment |

### JS Concatenation Order

The application code is concatenated in dependency order:

```
src/constants.js                       # Namespace constants, DOM helpers, unit converters
src/vba-utils.js                       # Shared VBA binary decoder + auto-exec pattern scanner
src/threat-signatures.js               # ThreatSignatures database + ThreatScanner engine
src/yara-engine.js                     # YaraEngine — in-browser YARA rule parser + matcher
src/docx-parser.js                     # DocxParser — ZIP extraction for DOCX/DOCM
src/style-resolver.js                  # StyleResolver — resolves run/paragraph styles
src/numbering-resolver.js              # NumberingResolver — list counters and markers
src/content-renderer.js                # ContentRenderer — DOCX DOM → HTML elements
src/security-analyzer.js               # SecurityAnalyzer — findings, metadata, external refs
src/renderers/ole-cfb-parser.js        # OleCfbParser — CFB/OLE2 compound file reader
src/renderers/xlsx-renderer.js         # XlsxRenderer — spreadsheet view (SheetJS)
src/renderers/pptx-renderer.js        # PptxRenderer — slide canvas renderer
src/renderers/csv-renderer.js          # CsvRenderer — CSV/TSV table view
src/renderers/doc-renderer.js          # DocBinaryRenderer — legacy .doc text extraction
src/renderers/msg-renderer.js          # MsgRenderer — Outlook .msg email view
src/renderers/eml-renderer.js          # EmlRenderer — RFC 5322/MIME email parser
src/renderers/lnk-renderer.js         # LnkRenderer — Windows Shell Link (.lnk) parser
src/renderers/hta-renderer.js          # HtaRenderer — HTA source viewer + security scanner
src/renderers/pdf-renderer.js          # PdfRenderer — PDF page renderer + security scanner
src/renderers/plaintext-renderer.js    # PlainTextRenderer — catch-all text/hex viewer
src/app/app-core.js                    # App class — constructor, init, drop-zone, toolbar
src/app/app-load.js                    # File loading, hashing (MD5/SHA), IOC extraction
src/app/app-sidebar.js                 # Sidebar rendering — risk bar + 3 tab panes
src/app/app-ui.js                      # UI helpers (zoom, theme, pan, toast) + bootstrap
```

Vendor libraries (`vendor/jszip.min.js`, `vendor/xlsx.full.min.js`, `vendor/pdf.min.js`, `vendor/pdf.worker.min.js`) are inlined into separate `<script>` blocks before the application code.

---

## Project Structure

```
phishfinder/
├── build.py                       # Build script — reads src/, writes HTML outputs
├── phishfinder.html               # Built output (root convenience copy)
├── README.md
├── dist/
│   └── phishfinder.html           # Built output (distribution)
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
│   ├── threat-signatures.js       # ThreatSignatures database + ThreatScanner engine
│   ├── yara-engine.js             # YaraEngine — in-browser YARA rule parser + matcher
│   ├── docx-parser.js             # DocxParser class
│   ├── style-resolver.js          # StyleResolver class
│   ├── numbering-resolver.js      # NumberingResolver class
│   ├── content-renderer.js        # ContentRenderer class
│   ├── security-analyzer.js       # SecurityAnalyzer class
│   ├── renderers/
│   │   ├── ole-cfb-parser.js      # OleCfbParser — CFB compound file parser
│   │   ├── xlsx-renderer.js       # XlsxRenderer
│   │   ├── pptx-renderer.js       # PptxRenderer
│   │   ├── csv-renderer.js        # CsvRenderer
│   │   ├── doc-renderer.js        # DocBinaryRenderer
│   │   ├── msg-renderer.js        # MsgRenderer
│   │   ├── eml-renderer.js        # EmlRenderer
│   │   ├── lnk-renderer.js        # LnkRenderer
│   │   ├── hta-renderer.js        # HtaRenderer
│   │   ├── pdf-renderer.js        # PdfRenderer
│   │   └── plaintext-renderer.js  # PlainTextRenderer
│   └── app/
│       ├── app-core.js            # App class definition + setup methods
│       ├── app-load.js            # File loading, hashing, IOC extraction
│       ├── app-sidebar.js         # Sidebar rendering (risk bar + 3 tab panes)
│       └── app-ui.js              # UI helpers + DOMContentLoaded bootstrap
└── examples/
    ├── example.doc
    ├── example.docx
    ├── example.pdf
    ├── example.xls
    └── example.xlsm
```

---

## Architecture

- **Single output file** — `build.py` inlines all CSS and JavaScript so the viewer works by opening one `.html` file with zero external dependencies.
- **No eval, no network** — the Content-Security-Policy (`default-src 'none'`) blocks all external fetches; images are rendered only from `data:` and `blob:` URLs.
- **App class split** — `App` is defined in `app-core.js`; additional methods are attached via `Object.assign(App.prototype, {...})` in `app-load.js`, `app-sidebar.js`, and `app-ui.js`, keeping each file focused.
- **Shared VBA helpers** — `parseVBAText()` and `autoExecPatterns` live in `vba-utils.js` and are reused by `DocxParser`, `XlsxRenderer`, and `PptxRenderer`.
- **OLE/CFB parser** — `OleCfbParser` is shared by `DocBinaryRenderer` (`.doc`) and `MsgRenderer` (`.msg`) for reading compound binary files.
- **PDF rendering** — `PdfRenderer` uses Mozilla's pdf.js for canvas rendering plus raw-byte scanning for dangerous PDF operators. Hidden text layers enable IOC extraction from rendered pages.
- **EML parsing** — Full RFC 5322/MIME parser with multipart support, quoted-printable and base64 decoding, attachment extraction, and authentication header analysis.
- **LNK parsing** — Implements the MS-SHLLINK binary format, extracting target paths, arguments, timestamps, and environment variable paths. Flags dangerous executables and evasion patterns.
- **HTA analysis** — Treats `.hta` files as inherently high-risk, extracting embedded scripts, `<HTA:APPLICATION>` attributes, and scanning against 40+ suspicious patterns including obfuscation techniques.
- **Catch-all viewer** — `PlainTextRenderer` accepts any file type. Text files get line-numbered display; binary files get a hex dump. Both paths run IOC extraction and script-pattern scanning.

---

## Security Model

PhishFinder is designed to be safe to use on potentially malicious files:

| Layer | Protection |
|---|---|
| **No network** | CSP `default-src 'none'` — zero external requests, ever |
| **No eval** | No dynamic code execution; all parsing is structural |
| **No file system** | Browser sandbox — cannot read or write anything beyond the dropped file |
| **Sanitised rendering** | HTML content is escaped and sanitised; images use `data:` / `blob:` URLs only |
| **Offline by design** | Works identically with Wi-Fi off or in an air-gapped environment |

> ⚠️ PhishFinder is a **triage and inspection tool**, not a sandbox. It does not execute macros, JavaScript from PDFs, or scripts embedded in files — it extracts and displays them for human review.

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
4. Test by opening `phishfinder.html` in a browser
5. Submit a pull request

---

## Licence

This project is open source. See the repository for licence details.
