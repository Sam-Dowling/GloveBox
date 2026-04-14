#!/usr/bin/env python3
"""Build script: assembles glovebox.html from source files."""
import os
from datetime import datetime

VERSION = datetime.now().strftime('%Y%m%d.%H%M')

BASE = os.path.dirname(os.path.abspath(__file__))

def read(rel):
    with open(os.path.join(BASE, rel), 'r', encoding='utf-8') as f:
        return f.read()

jszip        = read('vendor/jszip.min.js')
xlsx_js      = read('vendor/xlsx.full.min.js')
pdf_js       = read('vendor/pdf.min.js')
pdf_wrk_js   = read('vendor/pdf.worker.min.js')
highlight_js = read('vendor/highlight.min.js')
css          = read('src/styles.css')

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
    'src/renderers/reg-renderer.js',
    'src/renderers/inf-renderer.js',
    'src/renderers/msi-renderer.js',
    'src/renderers/csv-renderer.js',
    'src/renderers/evtx-renderer.js',
    'src/renderers/sqlite-renderer.js',
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
        content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data: blob:; frame-src blob:; worker-src blob:;">
  <meta name="description" content="GloveBox — a 100% offline, single-file security analyser for suspicious files. No server, no uploads, no tracking.">
  <title>GloveBox</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 100'><text y='.9em' font-size='90'>🧤📦</text></svg>">
  <style>{css}</style>
</head>
<body>

  <!-- ── Toolbar ─────────────────────────────────────────────────────── -->
  <div id="toolbar">
    <span id="app-title">🧤📦 GloveBox</span>
    <div class="tb-separator"></div>
    <!-- File operations group -->
    <div class="tb-group" id="file-ops">
      <button class="tb-btn" id="btn-open" title="Open file (or drag &amp; drop)">📁 Open File</button>
      <span id="file-info"></span>
      <button class="tb-btn hidden" id="btn-nav-back" title="Return to parent archive">← Back</button>
      <button class="tb-btn hidden" id="btn-close" title="Close file">✕</button>
    </div>
    <div class="tb-spacer"></div>
    <div class="tb-separator"></div>
    <button class="tb-btn" id="btn-yara" title="YARA rule editor (Y)">📐 YARA Rules</button>
    <div class="tb-separator"></div>
    <button class="tb-btn tb-icon-btn" id="btn-security" title="Toggle security sidebar (S)">🛡</button>
    <button class="tb-btn tb-icon-btn" id="btn-help" title="Help &amp; About (?)">?</button>
    <button class="tb-btn tb-icon-btn" id="btn-theme" title="Toggle dark mode">🌙</button>
    <input type="file" id="file-input" accept=".docx,.docm,.xlsx,.xlsm,.xls,.ods,.pptx,.pptm,.ppt,.odt,.odp,.csv,.tsv,.doc,.msg,.eml,.lnk,.hta,.rtf,.pdf,.zip,.gz,.gzip,.tar,.tgz,.rar,.7z,.cab,.iso,.img,.one,.url,.webloc,.iqy,.slk,.wsf,.wsc,.wsh,.reg,.inf,.sct,.msi,.html,.htm,.mht,.xml,.vbs,.vbe,.js,.jse,.ps1,.bat,.cmd,.ics,.vcf,.txt,.log,.json,.ini,.cfg,.yml,.yaml,.jpg,.jpeg,.png,.gif,.bmp,.webp,.ico,.tif,.tiff,.avif,.svg,.evtx,.sqlite,.db" style="display:none">
  </div>

  <!-- ── Main area (viewer + sidebar side-by-side) ──────────────────── -->
  <div id="main-area">

    <!-- viewer -->
    <div id="viewer">
      <div id="viewer-toolbar" class="hidden">
        <div class="vt-group">
          <button class="tb-btn tb-action-btn" id="btn-save" title="Save source content">💾 Save</button>
          <button class="tb-btn tb-action-btn" id="btn-copy" title="Copy source content">📋 Copy</button>
        </div>
        <div class="vt-search">
          <input type="text" id="doc-search" placeholder="Search content…" spellcheck="false">
          <button class="vt-search-nav" id="doc-search-prev" title="Previous match (Shift+Enter)">◀</button>
          <button class="vt-search-nav" id="doc-search-next" title="Next match (Enter)">▶</button>
          <span id="doc-search-count"></span>
        </div>
        <div class="vt-spacer"></div>
        <div class="vt-zoom">
          <button class="tb-btn vt-zoom-btn" id="btn-zoom-out" title="Zoom out">−</button>
          <span id="zoom-level">100%</span>
          <button class="tb-btn vt-zoom-btn" id="btn-zoom-in" title="Zoom in">+</button>
        </div>
      </div>
      <div id="drop-zone">
        <span class="dz-icon">📄</span>
        <div class="dz-text">Drop a file here to analyse</div>
        <div class="dz-sub">docx · xlsx · pptx · pdf · doc · eml · rtf · zip · iso · odt · one · lnk · hta · and any file · 100% offline</div>
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

  <!-- ── Noscript ────────────────────────────────────────────────────── -->
  <noscript>
    <div class="noscript-msg">
      <h2>🧤📦 GloveBox requires JavaScript</h2>
      <p>This is a client-side security analysis tool — all processing happens locally in your browser. Please enable JavaScript to continue.</p>
    </div>
  </noscript>

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

  <!-- ── highlight.js (inlined) ──────────────────────────────────────── -->
  <script>
{highlight_js}
  </script>

  <!-- ── Application ─────────────────────────────────────────────────── -->
  <script>
const GLOVEBOX_VERSION = '{VERSION}';
{default_yara_js}
{app_js}
  </script>
</body>
</html>"""

# docs/index.html — served by GitHub Pages
docs = os.path.join(BASE, 'docs')
os.makedirs(docs, exist_ok=True)
with open(os.path.join(docs, 'index.html'), 'w', encoding='utf-8') as _f:
    _f.write(HTML)

# root copy
out = os.path.join(BASE, 'glovebox.html')
with open(out, 'w', encoding='utf-8') as f:
    f.write(HTML)

size = os.path.getsize(out)
print(f"OK  Built {out}  ({size:,} bytes / {size//1024} KB)")
