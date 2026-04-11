#!/usr/bin/env python3
"""Build script: assembles dist/docx-viewer.html from source files."""
import os

BASE = os.path.dirname(os.path.abspath(__file__))

def read(rel):
    with open(os.path.join(BASE, rel), 'r', encoding='utf-8') as f:
        return f.read()

jszip   = read('vendor/jszip.min.js')
xlsx_js = read('vendor/xlsx.full.min.js')
css     = read('src/styles.css')

# JS files concatenated in dependency order
JS_FILES = [
    'src/constants.js',
    'src/vba-utils.js',
    'src/docx-parser.js',
    'src/style-resolver.js',
    'src/numbering-resolver.js',
    'src/content-renderer.js',
    'src/security-analyzer.js',
    'src/renderers/ole-cfb-parser.js',
    'src/renderers/xlsx-renderer.js',
    'src/renderers/pptx-renderer.js',
    'src/renderers/csv-renderer.js',
    'src/renderers/doc-renderer.js',
    'src/renderers/msg-renderer.js',
    'src/app/app-core.js',
    'src/app/app-load.js',
    'src/app/app-sidebar.js',
    'src/app/app-ui.js',
]

app_js = '\n'.join(read(f) for f in JS_FILES)

HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data: blob:;">
  <title>Secure DOCX Viewer</title>
  <style>{css}</style>
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

  <!-- ── Main area (viewer + sidebar side-by-side) ──────────────────── -->
  <div id="main-area">

    <!-- viewer -->
    <div id="viewer">
      <div id="drop-zone">
        <span class="dz-icon">📄</span>
        <div class="dz-text">Drop an Office file here to preview</div>
        <div class="dz-sub">docx · xlsx · xls · pptx · csv · doc · msg · and more · 100% offline</div>
      </div>
      <div id="page-container"></div>
    </div>

    <!-- sidebar resize handle -->
    <div id="sidebar-resize" class="hidden"></div>

    <!-- sidebar -->
    <div id="sidebar" class="hidden">
      <!-- risk bar -->
      <div id="sb-risk" class="sb-risk risk-low">
        <span id="sb-risk-title">No threats detected</span>
      </div>
      <!-- tab strip (S=toggle, 1/2/3=switch tabs) -->
      <div id="sb-tabs">
        <button class="stab active" data-tab="summary"  title="Summary (key 1)">📋 Summary</button>
        <button class="stab"        data-tab="extracted" title="Extracted (key 2)">🔍 Extracted<span id="stab-badge-extracted" class="stab-badge hidden"></span></button>
        <button class="stab"        data-tab="macros"    title="Macros (key 3)">⚡ Macros<span id="stab-badge-macros" class="stab-badge hidden"></span></button>
      </div>
      <!-- pane container -->
      <div id="sb-body">
        <div id="stab-summary"   class="stab-pane"></div>
        <div id="stab-extracted" class="stab-pane hidden"></div>
        <div id="stab-macros"    class="stab-pane hidden"></div>
      </div>
    </div>

  </div><!-- /#main-area -->

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

  <!-- ── Application ─────────────────────────────────────────────────── -->
  <script>
{app_js}
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
