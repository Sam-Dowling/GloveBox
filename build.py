#!/usr/bin/env python3
"""Build script: assembles dist/docx-viewer.html from source files."""
import os, sys

BASE = os.path.dirname(os.path.abspath(__file__))

def read(rel):
    with open(os.path.join(BASE, rel), 'r', encoding='utf-8') as f:
        return f.read()

jszip     = read('vendor/jszip.min.js')
xlsx_js   = read('vendor/xlsx.full.min.js')
renderers = read('src/renderers.js')
app       = read('src/app.js')

CSS = r"""
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: #525659; color: #222;
  display: flex; flex-direction: column; min-height: 100vh;
}
body.dark { background: #1c1c1c; color: #e0e0e0; }

/* ── Toolbar ── */
#toolbar {
  position: sticky; top: 0; z-index: 100;
  background: #f4f4f4; border-bottom: 1px solid #ddd;
  padding: 6px 12px; display: flex; align-items: center;
  gap: 6px; flex-wrap: wrap;
  box-shadow: 0 1px 4px rgba(0,0,0,.12);
}
body.dark #toolbar { background: #2a2a2a; border-color: #3a3a3a; color: #ddd; }
#app-title { font-weight: 700; font-size: 15px; color: #333; margin-right: 4px; white-space: nowrap; }
body.dark #app-title { color: #ccc; }
#file-info { font-size: 12px; color: #666; flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
body.dark #file-info { color: #999; }
.tb-btn {
  padding: 4px 10px; border: 1px solid #ccc; border-radius: 4px;
  background: white; cursor: pointer; font-size: 12px;
  transition: background .15s; white-space: nowrap;
}
.tb-btn:hover { background: #e0e8f0; }
body.dark .tb-btn { background: #3a3a3a; border-color: #555; color: #ccc; }
body.dark .tb-btn:hover { background: #4a4a4a; }
#zoom-level { font-size: 12px; min-width: 36px; text-align: center; }

/* ── Security panel ── */
#security-panel { margin: 0 16px 8px; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.15); }
#security-panel.hidden { display: none; }
.security-header {
  padding: 10px 16px; cursor: pointer; display: flex; align-items: center; gap: 8px;
  font-weight: 600; font-size: 13px; user-select: none;
}
.toggle-arrow { margin-left: auto; font-size: 11px; opacity: .7; }
.risk-low  { background: #d4edda; color: #155724; }
.risk-medium { background: #fff3cd; color: #856404; }
.risk-high { background: #f8d7da; color: #721c24; }
.security-body {
  padding: 12px 16px; background: white;
  border: 1px solid rgba(0,0,0,.1); border-top: none; font-size: 13px;
}
.security-body.collapsed { display: none; }
body.dark .security-body { background: #2a2a2a; border-color: #3a3a3a; color: #ddd; }
.security-body h3 { font-size: 13px; font-weight: 700; margin: 0 0 8px; }
.security-body ul { margin: 4px 0 4px 20px; }
.security-body details { margin-top: 8px; }
.security-body summary { cursor: pointer; font-weight: 600; font-size: 12px; padding: 2px 0; }
.security-table { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }
.security-table th { text-align: left; padding: 5px 8px; background: #f8f9fa; border: 1px solid #dee2e6; font-weight: 600; }
.security-table td { padding: 5px 8px; border: 1px solid #dee2e6; }
body.dark .security-table th { background: #333; border-color: #444; }
body.dark .security-table td { border-color: #444; }
.badge { display: inline-block; padding: 1px 7px; border-radius: 10px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
.badge-high   { background: #f8d7da; color: #721c24; }
.badge-medium { background: #fff3cd; color: #856404; }
.badge-low    { background: #d4edda; color: #155724; }
.badge-info   { background: #d1ecf1; color: #0c5460; }

/* ── Viewer ── */
#viewer { flex: 1; padding: 20px; display: flex; flex-direction: column; align-items: center; overflow: auto; }
#page-container { display: flex; flex-direction: column; align-items: center; gap: 20px; transform-origin: top center; }

/* ── Drop zone ── */
#drop-zone {
  border: 3px dashed #777; border-radius: 12px; padding: 60px 40px;
  text-align: center; cursor: pointer; color: #ccc;
  background: rgba(255,255,255,.05); transition: all .2s;
  max-width: 500px; width: 100%;
}
#drop-zone:hover, #drop-zone.drag-over { border-color: #4a90e2; background: rgba(74,144,226,.1); color: #90c0ff; }
#drop-zone.drag-over { border-style: solid; }
#drop-zone.has-document {
  padding: 10px 20px; border-style: solid; border-color: #888;
  border-radius: 6px; font-size: 13px; color: #aaa; max-width: 100%;
}
.dz-icon { font-size: 48px; display: block; margin-bottom: 12px; }
.dz-text { font-size: 18px; margin-bottom: 6px; }
.dz-sub  { font-size: 12px; opacity: .6; }

/* ── Spinner / Loading ── */
.spinner {
  display: inline-block; width: 18px; height: 18px;
  border: 2px solid rgba(255,255,255,.4); border-top-color: white;
  border-radius: 50%; animation: spin .7s linear infinite; vertical-align: middle;
}
@keyframes spin { to { transform: rotate(360deg); } }
#loading {
  position: fixed; inset: 0; background: rgba(0,0,0,.5);
  display: flex; align-items: center; justify-content: center;
  z-index: 1000; color: white; font-size: 16px; gap: 10px;
}
#loading.hidden { display: none; }

/* ── Toast ── */
#toast {
  position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
  background: #333; color: white; padding: 10px 20px; border-radius: 8px;
  z-index: 2000; font-size: 14px; transition: opacity .3s; pointer-events: none;
}
#toast.hidden { opacity: 0; }
.toast-error { background: #c0392b !important; }

/* ── Error box ── */
.error-box {
  background: #fff3f3; border: 1px solid #f5c6cb;
  border-radius: 8px; padding: 24px; max-width: 500px; text-align: center;
}
.error-box h3 { color: #721c24; margin-bottom: 10px; }
.error-box p  { color: #666; font-size: 14px; margin-top: 6px; }

/* ══════════════════════════════════════════════════════
   PAGE SIMULATION
   ══════════════════════════════════════════════════════ */
.page {
  background: white;
  box-shadow: 0 2px 12px rgba(0,0,0,.35);
  position: relative; overflow: hidden;
}

/* Document typography defaults */
.page {
  font-family: 'Calibri', 'Cambria', Georgia, 'Times New Roman', serif;
  font-size: 11pt; color: #000; line-height: 1.15;
}
.page .para, .page p { margin: 0 0 8px; }
.page h1 { font-size: 24pt; font-weight: 700; margin: 12pt 0 6pt; }
.page h2 { font-size: 18pt; font-weight: 700; margin: 10pt 0 5pt; }
.page h3 { font-size: 14pt; font-weight: 700; margin:  8pt 0 4pt; }
.page h4 { font-size: 12pt; font-weight: 700; margin:  6pt 0 3pt; }
.page h5, .page h6 { font-size: 11pt; font-weight: 700; margin: 5pt 0 2pt; }
.page a.doc-link { color: #0563C1; text-decoration: underline; }
.page a.doc-link:hover { color: #003a8c; }
/* Hyperlinks are rendered as non-clickable spans in the viewer */
.page span.doc-link { color: #0563C1; text-decoration: underline; cursor: default; }

/* Tab stop */
.tab { display: inline-block; width: .5in; }

/* List items */
.list-item { position: relative; margin: 1pt 0; }
.list-marker { position: absolute; text-align: right; }

/* Tables */
.doc-table { border-collapse: collapse; margin: 4pt 0; }
.doc-table td, .doc-table th {
  padding: 3px 6px; border: 1px solid #ccc;
  vertical-align: top; min-width: 12px;
}
.doc-table .para { margin: 1pt 0; }

/* Error inline */
.error-inline { color: #cc0000; font-style: italic; font-size: 9pt; }

/* Page header / footer */
.page-header {
  font-size: 9pt; color: #555;
  padding: 4px 0; border-bottom: 1px solid #ddd; margin-bottom: 4px;
}
.page-footer {
  font-size: 9pt; color: #555;
  padding: 4px 0; border-top: 1px solid #ddd; margin-top: 4px;
}

/* VBA code display */
.vba-code {
  font-family: 'Consolas', 'Courier New', monospace; font-size: 11px;
  background: #1e1e1e; color: #d4d4d4; padding: 10px; border-radius: 4px;
  overflow: auto; white-space: pre-wrap; max-height: 400px; margin-top: 6px;
}
.vba-danger { background: #e53e3e; color: white; border-radius: 2px; padding: 0 2px; }

/* ── Copy URL button ── */
.copy-url-btn {
  display: inline-block; margin-left: 6px; padding: 0 4px;
  font-size: 11px; line-height: 1.4; border: 1px solid #ccc;
  border-radius: 3px; background: transparent; cursor: pointer;
  opacity: .55; vertical-align: middle; transition: opacity .15s;
}
.copy-url-btn:hover { opacity: 1; background: rgba(0,0,0,.06); }
body.dark .copy-url-btn { border-color: #555; }
body.dark .copy-url-btn:hover { background: rgba(255,255,255,.08); }

/* ══════════════════════════════════════════════════════
   XLSX / SPREADSHEET VIEW
   ══════════════════════════════════════════════════════ */
.xlsx-view {
  width: 100%; max-width: 1100px;
  background: white; box-shadow: 0 2px 12px rgba(0,0,0,.35);
  border-radius: 4px; overflow: hidden; display: flex; flex-direction: column;
}
body.dark .xlsx-view { background: #1e1e1e; }

.sheet-tab-bar {
  display: flex; flex-wrap: wrap; gap: 2px; padding: 6px 8px 0;
  background: #e8e8e8; border-bottom: 1px solid #ccc;
}
body.dark .sheet-tab-bar { background: #2a2a2a; border-color: #3a3a3a; }

.sheet-tab {
  padding: 4px 14px; border: 1px solid #bbb; border-bottom: none;
  border-radius: 4px 4px 0 0; cursor: pointer; font-size: 12px;
  background: #d4d4d4; color: #444; user-select: none;
  transition: background .15s;
}
.sheet-tab.active { background: white; font-weight: 600; color: #000; }
.sheet-tab:hover:not(.active) { background: #c0c0c0; }
body.dark .sheet-tab { background: #333; border-color: #555; color: #aaa; }
body.dark .sheet-tab.active { background: #1e1e1e; color: #fff; }
body.dark .sheet-tab:hover:not(.active) { background: #3a3a3a; }

.sheet-content-area {
  overflow: auto; flex: 1; max-height: 70vh;
}

.xlsx-table {
  border-collapse: collapse; font-size: 12px;
  font-family: 'Calibri', Arial, sans-serif; white-space: nowrap;
}
.xlsx-col-header, .xlsx-row-header {
  background: #f2f2f2; border: 1px solid #ccc;
  padding: 3px 8px; font-weight: 600; color: #555;
  position: sticky; z-index: 2; text-align: center; font-size: 11px;
  user-select: none;
}
.xlsx-col-header { top: 0; }
.xlsx-row-header { left: 0; }
body.dark .xlsx-col-header, body.dark .xlsx-row-header {
  background: #2a2a2a; border-color: #444; color: #999;
}
.xlsx-cell {
  border: 1px solid #d0d0d0; padding: 3px 8px; min-width: 64px;
  vertical-align: middle; max-width: 240px; overflow: hidden;
  text-overflow: ellipsis;
}
body.dark .xlsx-cell { border-color: #3a3a3a; color: #ddd; }
.xlsx-row:nth-child(even) .xlsx-cell { background: #fafafa; }
body.dark .xlsx-row:nth-child(even) .xlsx-cell { background: #222; }
.xlsx-cell-num  { text-align: right; font-variant-numeric: tabular-nums; }
.xlsx-cell-bold { font-weight: 700; }
.xlsx-cap-notice {
  padding: 8px 16px; font-size: 12px; color: #888; background: #fafafa;
  border-top: 1px solid #eee; text-align: center;
}
body.dark .xlsx-cap-notice { background: #181818; border-color: #333; color: #666; }

/* ══════════════════════════════════════════════════════
   CSV / TSV VIEW
   ══════════════════════════════════════════════════════ */
.csv-view {
  width: 100%; max-width: 1100px;
  background: white; box-shadow: 0 2px 12px rgba(0,0,0,.35);
  border-radius: 4px; overflow: hidden;
}
body.dark .csv-view { background: #1e1e1e; }

.csv-info {
  padding: 8px 16px; font-size: 12px; color: #666;
  background: #f8f8f8; border-bottom: 1px solid #e0e0e0;
}
body.dark .csv-info { background: #252525; border-color: #333; color: #888; }

.csv-scroll { overflow: auto; max-height: 70vh; }

.csv-table {
  border-collapse: collapse; font-size: 12px; width: 100%;
  font-family: 'Consolas', 'Courier New', monospace;
}
.csv-table th {
  background: #f0f0f0; border: 1px solid #ccc; padding: 4px 10px;
  font-weight: 700; text-align: left; position: sticky; top: 0; z-index: 1;
  white-space: nowrap;
}
.csv-table td {
  border: 1px solid #e0e0e0; padding: 3px 10px; white-space: pre; max-width: 300px;
  overflow: hidden; text-overflow: ellipsis;
}
.csv-table tr:nth-child(even) td { background: #fafafa; }
body.dark .csv-table th { background: #2a2a2a; border-color: #444; color: #ccc; }
body.dark .csv-table td { border-color: #333; color: #ddd; }
body.dark .csv-table tr:nth-child(even) td { background: #1a1a1a; }
.csv-formula-warn { background: #fff3cd !important; }
body.dark .csv-formula-warn { background: #3a2a00 !important; }

/* ══════════════════════════════════════════════════════
   PPTX VIEW
   ══════════════════════════════════════════════════════ */
.pptx-view {
  width: 100%; max-width: 800px; display: flex; flex-direction: column; gap: 16px;
}
.pptx-slide-counter {
  text-align: center; font-size: 12px; color: #aaa;
  padding: 4px; letter-spacing: .5px;
}
.pptx-slide {
  background: white; box-shadow: 0 2px 12px rgba(0,0,0,.35);
  width: 720px; height: 405px; position: relative; overflow: hidden;
  flex-shrink: 0; border-radius: 3px;
}
body.dark .pptx-slide { background: #1e1e1e; }
.pptx-slide-num {
  position: absolute; bottom: 6px; right: 10px;
  font-size: 10px; color: rgba(0,0,0,.3);
}
body.dark .pptx-slide-num { color: rgba(255,255,255,.25); }

/* ══════════════════════════════════════════════════════
   DOC BINARY TEXT VIEW
   ══════════════════════════════════════════════════════ */
.doc-text-view {
  width: 100%; max-width: 820px;
  background: white; box-shadow: 0 2px 12px rgba(0,0,0,.35);
  border-radius: 4px; overflow: hidden;
}
body.dark .doc-text-view { background: #1e1e1e; }

.doc-extraction-banner {
  padding: 8px 16px; font-size: 12px; font-weight: 600;
  background: #fff3cd; color: #856404; border-bottom: 1px solid #ffc107;
}
body.dark .doc-extraction-banner {
  background: #3a2a00; color: #ffc107; border-color: #5a4000;
}
.doc-text-content {
  padding: 24px 32px;
  font-family: 'Calibri', 'Cambria', Georgia, serif;
  font-size: 11pt; line-height: 1.6; white-space: pre-wrap;
  word-break: break-word;
}
body.dark .doc-text-content { color: #ddd; }

/* ══════════════════════════════════════════════════════
   MSG EMAIL VIEW
   ══════════════════════════════════════════════════════ */
.msg-view {
  width: 100%; max-width: 820px;
  background: white; box-shadow: 0 2px 12px rgba(0,0,0,.35);
  border-radius: 4px; overflow: hidden;
}
body.dark .msg-view { background: #1e1e1e; }

.msg-header-table {
  width: 100%; border-collapse: collapse; font-size: 13px;
  border-bottom: 2px solid #e0e0e0;
}
.msg-header-table td {
  padding: 6px 14px; border: none; vertical-align: top;
}
.msg-header-table .lbl {
  font-weight: 700; color: #555; white-space: nowrap; width: 80px;
}
body.dark .msg-header-table { border-color: #3a3a3a; }
body.dark .msg-header-table .lbl { color: #999; }
body.dark .msg-header-table td { color: #ddd; }

.msg-page { padding: 20px 24px; }
.msg-subject { font-size: 17px; font-weight: 700; padding: 12px 14px 8px; }
body.dark .msg-subject { color: #eee; }

.msg-body-frame {
  margin: 0 14px 14px; padding: 16px;
  border: 1px solid #e8e8e8; border-radius: 4px;
  font-size: 13px; line-height: 1.6;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  white-space: pre-wrap; word-break: break-word;
}
body.dark .msg-body-frame { border-color: #333; color: #ccc; }

.msg-attach-list { margin: 0 14px 16px; }
.msg-attach-list h4 { font-size: 12px; font-weight: 700; color: #666; margin-bottom: 6px; }
body.dark .msg-attach-list h4 { color: #999; }
.msg-attach-item {
  display: inline-flex; align-items: center; gap: 6px;
  background: #f0f0f0; border: 1px solid #ddd; border-radius: 16px;
  padding: 3px 10px; font-size: 12px; margin: 2px 4px 2px 0;
}
body.dark .msg-attach-item { background: #2a2a2a; border-color: #444; color: #ccc; }
"""

HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data: blob:;">
  <title>Secure DOCX Viewer</title>
  <style>{CSS}</style>
</head>
<body>

  <!-- ── Toolbar ─────────────────────────────────────────────────────── -->
  <div id="toolbar">
    <span id="app-title">🔒 Office Viewer</span>
    <span id="file-info"></span>
    <button class="tb-btn" id="btn-open" title="Open file (or drag &amp; drop)">📁 Open</button>
    <button class="tb-btn" id="btn-security" title="Toggle security panel">🛡 Security</button>
    <button class="tb-btn" id="btn-zoom-out" title="Zoom out">🔍−</button>
    <span id="zoom-level">100%</span>
    <button class="tb-btn" id="btn-zoom-in" title="Zoom in">🔍+</button>
    <button class="tb-btn" id="btn-theme" title="Toggle dark mode">🌙</button>
    <input type="file" id="file-input" accept=".docx,.docm,.xlsx,.xlsm,.xls,.ods,.pptx,.pptm,.csv,.tsv,.doc,.msg" style="display:none">
  </div>

  <!-- ── Security panel ──────────────────────────────────────────────── -->
  <div id="security-panel" class="hidden">
    <div id="security-header" class="security-header risk-low">
      <span id="security-title">No threats detected</span>
      <span class="toggle-arrow">▼</span>
    </div>
    <div id="security-body" class="security-body collapsed"></div>
  </div>

  <!-- ── Main viewer ─────────────────────────────────────────────────── -->
  <div id="viewer">
    <div id="drop-zone">
      <span class="dz-icon">📄</span>
      <div class="dz-text">Drop an Office file here to preview</div>
      <div class="dz-sub">docx · xlsx · xls · pptx · csv · doc · msg · and more · 100% offline</div>
    </div>
    <div id="page-container"></div>
  </div>

  <!-- ── Loading overlay ─────────────────────────────────────────────── -->
  <div id="loading" class="hidden">
    <span class="spinner"></span>
    <span>Parsing document…</span>
  </div>

  <!-- ── Toast ───────────────────────────────────────────────────────── -->
  <div id="toast" class="hidden"></div>

  <!-- ── JSZip (inlined) ─────────────────────────────────────────────── -->
  <script>
{jszip}
  </script>

  <!-- ── SheetJS (inlined) ──────────────────────────────────────────── -->
  <script>
{xlsx_js}
  </script>

  <!-- ── Extra renderers (xlsx/pptx/csv/doc/msg) ────────────────────── -->
  <script>
{renderers}
  </script>

  <!-- ── Application ─────────────────────────────────────────────────── -->
  <script>
{app}
  </script>
</body>
</html>"""

# dist/ copy
dist = os.path.join(BASE, 'dist')
os.makedirs(dist, exist_ok=True)
with open(os.path.join(dist, 'docx-viewer.html'), 'w', encoding='utf-8') as _f:
    _f.write(HTML)

# docs/index.html — served by GitHub Pages
docs = os.path.join(BASE, 'docs')
os.makedirs(docs, exist_ok=True)
with open(os.path.join(docs, 'index.html'), 'w', encoding='utf-8') as _f:
    _f.write(HTML)

# root copy — convenient for local use
out = os.path.join(BASE, 'docx-viewer.html')
with open(out, 'w', encoding='utf-8') as f:
    f.write(HTML)

size = os.path.getsize(out)
print(f"OK  Built {out}  ({size:,} bytes / {size//1024} KB)")
print(f"     docs/index.html ready for GitHub Pages")
