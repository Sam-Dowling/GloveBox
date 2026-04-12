#!/usr/bin/env python3
"""Build script: assembles dist/glovebox.html from source files."""
import os

BASE = os.path.dirname(os.path.abspath(__file__))

def read(rel):
    with open(os.path.join(BASE, rel), 'r', encoding='utf-8') as f:
        return f.read()

jszip      = read('vendor/jszip.min.js')
xlsx_js    = read('vendor/xlsx.full.min.js')
pdf_js     = read('vendor/pdf.min.js')
pdf_wrk_js = read('vendor/pdf.worker.min.js')
css        = read('src/styles.css')

# Default YARA rules — injected as a JS constant
yar_rules  = read('src/default-rules.yar')
# Escape backticks and backslashes for JS template literal
yar_rules_escaped = yar_rules.replace('\\', '\\\\').replace('`', '\\`').replace('${', '\\${')
default_yara_js = f'const DEFAULT_YARA_RULES = `{yar_rules_escaped}`;\n'

# JS files concatenated in dependency order
JS_FILES = [
    'src/constants.js',
    'src/vba-utils.js',
    'src/yara-engine.js',
    'src/decompressor.js',
    'src/encoded-content-detector.js',
    'src/docx-parser.js',
    'src/style-resolver.js',
    'src/numbering-resolver.js',
    'src/content-renderer.js',
    'src/security-analyzer.js',
    'src/renderers/ole-cfb-parser.js',
    'src/renderers/xlsx-renderer.js',
    'src/renderers/pptx-renderer.js',
    'src/renderers/odt-renderer.js',
    'src/renderers/odp-renderer.js',
    'src/renderers/ppt-renderer.js',
    'src/renderers/rtf-renderer.js',
    'src/renderers/zip-renderer.js',
    'src/renderers/iso-renderer.js',
    'src/renderers/url-renderer.js',
    'src/renderers/onenote-renderer.js',
    'src/renderers/iqy-slk-renderer.js',
    'src/renderers/wsf-renderer.js',
    'src/renderers/csv-renderer.js',
    'src/renderers/doc-renderer.js',
    'src/renderers/msg-renderer.js',
    'src/renderers/eml-renderer.js',
    'src/renderers/lnk-renderer.js',
    'src/renderers/hta-renderer.js',
    'src/renderers/html-renderer.js',
    'src/renderers/pdf-renderer.js',
    'src/renderers/image-renderer.js',
    'src/renderers/plaintext-renderer.js',
    'src/app/app-core.js',
    'src/app/app-load.js',
    'src/app/app-sidebar.js',
    'src/app/app-yara.js',
    'src/app/app-ui.js',
]

app_js = '\n'.join(read(f) for f in JS_FILES)

HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data: blob:; frame-src blob:;">
  <title>GloveBox</title>
  <style>{css}</style>
</head>
<body>

  <!-- ── Toolbar ─────────────────────────────────────────────────────── -->
  <div id="toolbar">
    <span id="app-title">🧤📦 GloveBox</span>
    <button class="tb-btn" id="btn-open" title="Open file (or drag &amp; drop)">📁 Open File</button>
    <div id="file-info-wrap">
      <span id="file-info"></span>
      <button class="tb-close hidden" id="btn-close" title="Close file">✕</button>
    </div>
    <button class="tb-btn" id="btn-security" title="Toggle security sidebar (S)">🛡 Toggle Sidebar</button>
    <button class="tb-btn" id="btn-yara" title="YARA rule editor (Y)">📐 YARA Rules</button>
    <button class="tb-btn" id="btn-theme" title="Toggle dark mode">🌙</button>
    <input type="file" id="file-input" accept=".docx,.docm,.xlsx,.xlsm,.xls,.ods,.pptx,.pptm,.ppt,.odt,.odp,.csv,.tsv,.doc,.msg,.eml,.lnk,.hta,.rtf,.pdf,.zip,.rar,.7z,.cab,.iso,.img,.one,.url,.webloc,.iqy,.slk,.wsf,.wsc,.wsh,.html,.htm,.mht,.xml,.vbs,.vbe,.js,.jse,.ps1,.bat,.cmd,.ics,.vcf,.txt,.log,.json,.ini,.cfg,.yml,.yaml,.jpg,.jpeg,.png,.gif,.bmp,.webp,.ico,.tif,.tiff,.avif,.svg" style="display:none">
  </div>

  <!-- ── Main area (viewer + sidebar side-by-side) ──────────────────── -->
  <div id="main-area">

    <!-- viewer -->
    <div id="viewer">
      <div class="zoom-fab">
        <button class="tb-btn" id="btn-zoom-out" title="Zoom out">−</button>
        <span id="zoom-level">100%</span>
        <button class="tb-btn" id="btn-zoom-in" title="Zoom in">+</button>
      </div>
      <div id="drop-zone">
        <span class="dz-icon">📄</span>
        <div class="dz-text">Drop a file here to analyse</div>
        <div class="dz-sub">docx · xlsx · pptx · pdf · doc · eml · rtf · zip · iso · odt · one · lnk · hta · and any file · 100% offline</div>
      </div>
      <div id="doc-search-wrap" class="hidden">
        <input type="text" id="doc-search" placeholder="Search content…" spellcheck="false">
        <span id="doc-search-count"></span>
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

  <!-- ── pdf.js worker (inlined — must load before pdf.js) ───────────── -->
  <script>
{pdf_wrk_js}
  </script>

  <!-- ── pdf.js (inlined) ────────────────────────────────────────────── -->
  <script>
{pdf_js}
  </script>

  <!-- ── Application ─────────────────────────────────────────────────── -->
  <script>
{default_yara_js}
{app_js}
  </script>
</body>
</html>"""

# dist/ copy
dist = os.path.join(BASE, 'dist')
os.makedirs(dist, exist_ok=True)
with open(os.path.join(dist, 'glovebox.html'), 'w', encoding='utf-8') as _f:
    _f.write(HTML)

# docs/index.html — served by GitHub Pages
docs = os.path.join(BASE, 'docs')
os.makedirs(docs, exist_ok=True)
with open(os.path.join(docs, 'index.html'), 'w', encoding='utf-8') as _f:
    _f.write(HTML)

# root copy — convenient for local use
out = os.path.join(BASE, 'glovebox.html')
with open(out, 'w', encoding='utf-8') as f:
    f.write(HTML)

size = os.path.getsize(out)
print(f"OK  Built {out}  ({size:,} bytes / {size//1024} KB)")
print(f"     docs/index.html ready for GitHub Pages")
