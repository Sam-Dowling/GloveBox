# 🔒 Office Viewer

A **100% offline**, single-file HTML viewer and security analyser for common Microsoft Office and email formats.  
No server, no upload, no tracking — just drop a file and inspect it.

---

## Features

| Capability | Detail |
|---|---|
| **Formats** | `.docx` `.docm` `.xlsx` `.xlsm` `.xls` `.ods` `.pptx` `.pptm` `.csv` `.tsv` `.doc` `.msg` |
| **Offline** | Fully self-contained single HTML file — works without internet access |
| **Security sidebar** | Risk bar · Summary · Extracted strings · Macros tabs (toggle with **S**, switch with **1 / 2 / 3**) |
| **File hashes** | MD5 (pure-JS) · SHA-1 · SHA-256 computed in-browser with VirusTotal link |
| **VBA analysis** | Extracts and syntax-highlights VBA source; flags auto-execute patterns (`AutoOpen`, `Shell`, etc.) |
| **Macro download** | Download decoded VBA as `.txt` or raw binary as `.bin` |
| **IOC extraction** | Scans rendered text and VBA for URLs, emails, IP addresses, file paths, UNC paths |
| **Metadata** | Shows author, title, dates, revision from `docProps/core.xml` |
| **Zoom / theme** | 50–200 % zoom · dark / light toggle |

---

## Building

Requires Python 3.8+ (standard library only).

```bash
python build.py
```

The script reads `src/styles.css` and the 17 JS source files listed below, then concatenates them into a single `<script>` block inside the HTML template, producing three identical output files:

| Output | Purpose |
|---|---|
| `docx-viewer.html` | Root-level convenience copy |
| `dist/docx-viewer.html` | Distribution artefact |
| `docs/index.html` | GitHub Pages deployment |

### JS concatenation order

```
src/constants.js                  # namespace constants, DOM helpers, unit converters
src/vba-utils.js                  # shared parseVBAText + autoExecPatterns
src/docx-parser.js                # DocxParser — extracts ZIP parts for DOCX/DOCM
src/style-resolver.js             # StyleResolver — resolves run/paragraph styles
src/numbering-resolver.js         # NumberingResolver — list counters and markers
src/content-renderer.js           # ContentRenderer — DOCX DOM → HTML elements
src/security-analyzer.js          # SecurityAnalyzer — findings, metadata, external refs
src/renderers/ole-cfb-parser.js   # OleCfbParser — CFB/OLE2 compound file reader
src/renderers/xlsx-renderer.js    # XlsxRenderer — spreadsheet view (SheetJS)
src/renderers/pptx-renderer.js    # PptxRenderer — slide canvas renderer
src/renderers/csv-renderer.js     # CsvRenderer — CSV/TSV table view
src/renderers/doc-renderer.js     # DocBinaryRenderer — legacy .doc text extraction
src/renderers/msg-renderer.js     # MsgRenderer — Outlook .msg email view
src/app/app-core.js               # App class — constructor, init, drop-zone, toolbar
src/app/app-load.js               # _md5 function + App._loadFile, _hashFile, _extractInterestingStrings
src/app/app-sidebar.js            # App._renderSidebar + three tab-pane renderers
src/app/app-ui.js                 # App UI helpers + DOMContentLoaded bootstrap
```

Vendor libraries (`vendor/jszip.min.js`, `vendor/xlsx.full.min.js`) are inlined into separate `<script>` blocks before the application code.

---

## Usage

1. Open `docx-viewer.html` in any modern browser (Chrome, Firefox, Edge, Safari).
2. **Drop** a supported file onto the drop zone, or click **📁 Open**.
3. The document renders in the viewer area.
4. Click **🛡 Security** (or press **S**) to open the security sidebar:
   - **📋 Summary** — file format, MD5/SHA-1/SHA-256 hashes, VBA project hash, document metadata.
   - **🔍 Extracted** — URLs, emails, IPs, file paths and UNC paths found in the document and VBA source, searchable and downloadable as `.txt`.
   - **⚡ Macros** — VBA module source with dangerous-pattern highlighting, auto-execute warning, and download option.
5. Use **🔍−** / **🔍+** to zoom and **🌙** to toggle dark mode.

---

## Project Structure

```
office-viewer/
├── build.py                      # Build script — reads src/, writes HTML outputs
├── docx-viewer.html              # Built output (root convenience copy)
├── dist/
│   └── docx-viewer.html          # Built output (distribution)
├── docs/
│   └── index.html                # Built output (GitHub Pages)
├── vendor/
│   ├── jszip.min.js              # JSZip — ZIP parsing for DOCX/XLSX/PPTX
│   └── xlsx.full.min.js          # SheetJS — spreadsheet parsing
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
│   │   └── msg-renderer.js       # MsgRenderer
│   └── app/
│       ├── app-core.js           # App class definition (constructor + setup methods)
│       ├── app-load.js           # _md5 function + file loading, hashing, IOC extraction
│       ├── app-sidebar.js        # Sidebar rendering (risk bar + 3 tab panes)
│       └── app-ui.js             # UI helpers + DOMContentLoaded bootstrap
└── examples/
    ├── example.docx
    ├── example.doc
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
