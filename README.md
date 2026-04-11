# 🔒 Secure Office Viewer

A **single-file, fully offline** viewer for common Microsoft Office and email formats. Open any supported file by dragging it onto the page — no server, no cloud, no dependencies at runtime. All processing happens entirely in your browser.

> 🌐 **[Try it online →](https://sam-dowling.github.io/office-viewer/)**  
> *(No install needed — runs entirely in your browser)*

---

## Features

- **Multi-format support** — `.docx`, `.docm`, `.xlsx`, `.xlsm`, `.xls`, `.ods`, `.pptx`, `.pptm`, `.csv`, `.tsv`, `.doc`, `.msg`
- **Security analysis** — macro detection (VBA), SHA-256 hash of VBA project, auto-execute pattern highlighting, external reference scanning
- **Download decoded macros** — one-click export of all VBA module source to a `.txt` file when macros are present
- **Dark mode by default** — toggle between dark and light themes
- **Zoom** — 50 %–200 % scaling via toolbar
- **Zero network access** — enforced by Content Security Policy (`default-src 'none'`)
- **No `innerHTML` for user content** — all document content rendered via `createElement` / `createTextNode`

---

## Supported Formats

| Format | Extensions | Engine |
|---|---|---|
| Word (modern) | `.docx` `.docm` | Custom OOXML parser (JSZip + DOMParser) |
| Excel (modern) | `.xlsx` `.xlsm` `.ods` | SheetJS |
| Excel (legacy) | `.xls` | SheetJS |
| PowerPoint | `.pptx` `.pptm` | Custom DrawingML parser (JSZip) |
| Delimited text | `.csv` `.tsv` | RFC-4180 parser (built-in) |
| Word (legacy) | `.doc` | OLE CFB text extraction |
| Outlook message | `.msg` | OLE CFB / MAPI property reader |

---

## Building

Requires **Python 3** only. No pip packages needed.

```bash
python build.py
```

This assembles `dist/docx-viewer.html` (~1 MB) by inlining:
- `vendor/jszip.min.js` — ZIP parsing
- `vendor/xlsx.full.min.js` — SheetJS (Excel / ODS)
- `src/renderers.js` — XLSX, PPTX, CSV, DOC, MSG renderers
- `src/app.js` — DOCX parser, security analyser, application shell

---

## Usage

1. Open `dist/docx-viewer.html` in any modern browser (Chrome, Edge, Firefox, Safari)
2. Drag & drop an Office file onto the page, or click **📁 Open**
3. The **🛡 Security** panel shows macro status, SHA-256 hash, auto-execute risks, and external references
4. If macros are decoded, click **💾 Download Macros (.txt)** to save VBA source
5. Use **🔍−** / **🔍+** to zoom, and **☀ / 🌙** to toggle theme

> The file works entirely offline. You can copy `dist/docx-viewer.html` anywhere and open it directly — no web server required.

---

## Project Structure

```
docx_viewer/
├── build.py              # Build script (Python 3, no dependencies)
├── README.md
│
├── src/
│   ├── app.js            # DOCX parser, security analyser, App class
│   └── renderers.js      # XlsxRenderer, PptxRenderer, CsvRenderer,
│                         # OleCfbParser, DocBinaryRenderer, MsgRenderer
│
├── vendor/
│   ├── jszip.min.js      # JSZip 3.x  (ZIP / OOXML extraction)
│   └── xlsx.full.min.js  # SheetJS    (Excel / ODS parsing)
│
├── examples/
│   ├── example.docx
│   ├── example.doc
│   ├── example.xls
│   └── example.xlsm
│
└── dist/
    └── docx-viewer.html  # Built output (single self-contained file)
```

---

## Security Notes

- **No `eval`, no `Function()`, no dynamic script loading**
- SVG images rendered as `<img src="data:image/svg+xml;base64,...">` — never inlined as DOM
- External URLs sanitised: only `http:`, `https:`, `mailto:` permitted
- CSP: `default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data: blob:`
- Formula-injection detection in CSV/TSV (cells starting with `=`, `+`, `-`, `@`)
- VBA auto-execute patterns flagged: `AutoOpen`, `Document_Open`, `Shell`, `WScript.Shell`, `PowerShell`, `URLDownloadToFile`, etc.

---

## Requirements

| | |
|---|---|
| **Build** | Python 3.6+ |
| **Runtime** | Any modern browser (no extensions, no server) |
| **Network** | None — works fully offline |
