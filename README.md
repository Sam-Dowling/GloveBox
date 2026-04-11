# 🔒 PhishFinder

A **100% offline**, single-file HTML viewer and security analyser for suspicious files.  
No server, no upload, no tracking — just drop a file and inspect it.

---

## Features

| Capability | Detail |
|---|---|
| **Formats** | `.docx` `.docm` `.xlsx` `.xlsm` `.xls` `.ods` `.pptx` `.pptm` `.csv` `.tsv` `.doc` `.msg` `.eml` `.lnk` `.hta` `.pdf` + **any file** (plain-text / hex catch-all) |
| **Offline** | Fully self-contained single HTML file — works without internet access |
| **Security sidebar** | Risk bar · Summary · Extracted strings · Macros tabs (toggle with **S**, switch with **1 / 2 / 3**) |
| **File hashes** | MD5 (pure-JS) · SHA-1 · SHA-256 computed in-browser with VirusTotal link |
| **VBA analysis** | Extracts and syntax-highlights VBA source; flags auto-execute patterns (`AutoOpen`, `Shell`, etc.) |
| **Macro download** | Download decoded VBA as `.txt` or raw binary as `.bin` |
| **IOC extraction** | Scans rendered text and VBA for URLs, emails, IP addresses, file paths, UNC paths |
| **PDF analysis** | Renders pages via pdf.js; scans for `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, URIs, XFA forms and more |
| **EML parsing** | RFC 5322/MIME email parser — headers, multipart body, attachments, auth results, tracking pixel detection |
| **LNK parsing** | Windows Shell Link binary parser — target path, arguments, timestamps, dangerous-command detection, UNC credential theft |
| **HTA analysis** | HTML Application source viewer — danger banner, script extraction, obfuscation detection, 40+ suspicious pattern checks |
| **Catch-all viewer** | Opens *any* file — shows plain text with line numbers, or hex dump for binary; scans scripts for dangerous patterns |
| **Metadata** | Shows author, title, dates, revision from `docProps/core.xml` |
| **Zoom / theme** | 50–200 % zoom · dark / light toggle |

---

## Building

Requires Python 3.8+ (standard library only).

```bash
python build.py
```

The script reads `src/styles.css` and the JS source files listed below, then concatenates them into a single `<script>` block inside the HTML template, producing three identical output files:

| Output | Purpose |
|---|---|
| `phishfinder.html` | Root-level convenience copy |
| `dist/phishfinder.html` | Distribution artefact |
| `docs/index.html` | GitHub Pages deployment |

### JS concatenation order

```
src/constants.js                       # namespace constants, DOM helpers, unit converters
src/vba-utils.js                       # shared parseVBAText + autoExecPatterns
src/docx-parser.js                     # DocxParser — extracts ZIP parts for DOCX/DOCM
src/style-resolver.js                  # StyleResolver — resolves run/paragraph styles
src/numbering-resolver.js              # NumberingResolver — list counters and markers
src/content-renderer.js                # ContentRenderer — DOCX DOM → HTML elements
src/security-analyzer.js               # SecurityAnalyzer — findings, metadata, external refs
src/renderers/ole-cfb-parser.js        # OleCfbParser — CFB/OLE2 compound file reader
src/renderers/xlsx-renderer.js         # XlsxRenderer — spreadsheet view (SheetJS)
src/renderers/pptx-renderer.js         # PptxRenderer — slide canvas renderer
src/renderers/csv-renderer.js          # CsvRenderer — CSV/TSV table view
src/renderers/doc-renderer.js          # DocBinaryRenderer — legacy .doc text extraction
src/renderers/msg-renderer.js          # MsgRenderer — Outlook .msg email view
src/renderers/eml-renderer.js          # EmlRenderer — RFC 5322/MIME email parser
src/renderers/lnk-renderer.js         # LnkRenderer — Windows Shell Link (.lnk) binary parser
src/renderers/hta-renderer.js          # HtaRenderer — HTA source viewer + security scanner
src/renderers/pdf-renderer.js          # PdfRenderer — PDF page renderer + security scanner
src/renderers/plaintext-renderer.js    # PlainTextRenderer — catch-all text/hex viewer
src/app/app-core.js                    # App class — constructor, init, drop-zone, toolbar
src/app/app-load.js                    # _md5 function + App._loadFile, _hashFile, _extractInterestingStrings
src/app/app-sidebar.js                 # App._renderSidebar + three tab-pane renderers
src/app/app-ui.js                      # App UI helpers + DOMContentLoaded bootstrap
```

Vendor libraries (`vendor/jszip.min.js`, `vendor/xlsx.full.min.js`, `vendor/pdf.min.js`, `vendor/pdf.worker.min.js`) are inlined into separate `<script>` blocks before the application code.

---

## Usage

1. Open `phishfinder.html` in any modern browser (Chrome, Firefox, Edge, Safari).
2. **Drop** a file onto the drop zone, or click **📁 Open**.
3. The document renders in the viewer area.
4. Click **🛡 Security** (or press **S**) to open the security sidebar:
   - **📋 Summary** — file format, MD5/SHA-1/SHA-256 hashes, VBA project hash, document metadata.
   - **🔍 Extracted** — URLs, emails, IPs, file paths and UNC paths found in the document and VBA source, searchable and downloadable as `.txt`.
   - **⚡ Macros** — VBA module source with dangerous-pattern highlighting, auto-execute warning, and download option.
5. Use **🔍−** / **🔍+** to zoom and **🌙** to toggle dark mode.

---

## Project Structure

```
phishfinder/
├── build.py                      # Build script — reads src/, writes HTML outputs
├── phishfinder.html              # Built output (root convenience copy)
├── dist/
│   └── phishfinder.html          # Built output (distribution)
├── docs/
│   └── index.html                # Built output (GitHub Pages)
├── vendor/
│   ├── jszip.min.js              # JSZip — ZIP parsing for DOCX/XLSX/PPTX
│   ├── xlsx.full.min.js          # SheetJS — spreadsheet parsing
│   ├── pdf.min.js                # pdf.js — PDF rendering (Mozilla)
│   └── pdf.worker.min.js         # pdf.js worker — PDF parsing backend
├── src/
│   ├── styles.css                # All UI CSS (toolbar, sidebar, page simulation, views)
│   ├── constants.js              # Shared constants, DOM helpers, unit converters, sanitizers
│   ├── vba-utils.js              # Shared VBA binary decoder + auto-exec pattern scanner
│   ├── docx-parser.js            # DocxParser class
│   ├── style-resolver.js         # StyleResolver class
│   ├── numbering-resolver.js     # NumberingResolver class
│   ├── content-renderer.js       # ContentRenderer class (~440 lines)
│   ├── security-analyzer.js      # SecurityAnalyzer class
│   ├── renderers/
│   │   ├── ole-cfb-parser.js     # OleCfbParser — CFB compound file parser
│   │   ├── xlsx-renderer.js      # XlsxRenderer
│   │   ├── pptx-renderer.js      # PptxRenderer
│   │   ├── csv-renderer.js       # CsvRenderer
│   │   ├── doc-renderer.js       # DocBinaryRenderer
│   │   ├── msg-renderer.js       # MsgRenderer
│   │   ├── eml-renderer.js       # EmlRenderer — RFC 5322/MIME email parser
│   │   ├── lnk-renderer.js       # LnkRenderer — Windows Shell Link parser
│   │   ├── hta-renderer.js       # HtaRenderer — HTA source viewer + scanner
│   │   ├── pdf-renderer.js       # PdfRenderer — PDF viewer + security analysis
│   │   └── plaintext-renderer.js # PlainTextRenderer — catch-all text/hex viewer
│   └── app/
│       ├── app-core.js           # App class definition (constructor + setup methods)
│       ├── app-load.js           # _md5 function + file loading, hashing, IOC extraction
│       ├── app-sidebar.js        # Sidebar rendering (risk bar + 3 tab panes)
│       └── app-ui.js             # UI helpers + DOMContentLoaded bootstrap
└── examples/
    ├── example.docx
    ├── example.doc
    ├── example.pdf
    ├── example.xlsx
    └── example.xlsm
```

---

## Architecture Notes

- **Single output file** — `build.py` inlines all CSS and JS so the viewer works by opening a single `.html` file with no external dependencies.
- **No eval / no network** — the Content-Security-Policy header blocks all external fetches; images are rendered only from `data:` and `blob:` URLs.
- **App class split** — `App` is defined as a class in `app-core.js`; additional methods are attached via `Object.assign(App.prototype, {...})` in `app-load.js`, `app-sidebar.js`, and `app-ui.js`, keeping each file focused and under ~200 lines.
- **Shared VBA helpers** — `parseVBAText` and `autoExecPatterns` live in `vba-utils.js` and are used by `DocxParser`, `XlsxRenderer`, and `PptxRenderer`, eliminating duplication.
- **OLE/CFB parser** — `OleCfbParser` is shared by `DocBinaryRenderer` (`.doc`) and `MsgRenderer` (`.msg`).
- **PDF rendering** — `PdfRenderer` uses Mozilla's pdf.js (vendor-inlined) for canvas rendering plus raw-byte scanning for dangerous PDF operators (`/JavaScript`, `/OpenAction`, `/Launch`, etc.). Hidden text layers enable IOC extraction from rendered pages.
- **EML parsing** — `EmlRenderer` implements a full RFC 5322/MIME parser with multipart support, quoted-printable and base64 decoding, attachment extraction, and authentication header analysis.
- **LNK parsing** — `LnkRenderer` implements the MS-SHLLINK binary format, extracting target paths, command-line arguments, timestamps, and environment variable paths. Flags dangerous executables and evasion patterns.
- **HTA analysis** — `HtaRenderer` treats `.hta` files as inherently high-risk, extracting embedded scripts, `<HTA:APPLICATION>` attributes, and scanning against 40+ suspicious patterns including obfuscation techniques.
- **Catch-all viewer** — `PlainTextRenderer` accepts *any* file type. Text files get line-numbered display; binary files get a hex dump. Both paths run IOC extraction and, for known script types (`.vbs`, `.ps1`, `.bat`, `.rtf`, etc.), scan for ~30 dangerous execution patterns.
