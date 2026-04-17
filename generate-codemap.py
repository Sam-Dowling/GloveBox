#!/usr/bin/env python3
"""
generate-codemap.py — Generates CODEMAP.md for AI coding agents.

Creates a detailed index of every source file, class, method, function,
CSS section, and YARA rule with precise line numbers, enabling AI agents
to make surgical edits using read_file(start_line, end_line) without
consuming full files into their context window.

Usage:  python generate-codemap.py          # writes CODEMAP.md
        python generate-codemap.py --json   # writes codemap.json (machine-readable)
"""
import os, re, sys, json
from datetime import datetime

# Fix Windows console encoding
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

BASE = os.path.dirname(os.path.abspath(__file__))

# ─── File I/O helpers ──────────────────────────────────────────────────────

def read_lines(rel):
    with open(os.path.join(BASE, rel), 'r', encoding='utf-8') as f:
        return f.readlines()

def fsize(rel):
    return os.path.getsize(os.path.join(BASE, rel))

def fmt_kb(b):
    return f"{b // 1024} KB" if b >= 1024 else f"{b} B"

# ─── JS parser ─────────────────────────────────────────────────────────────

SKIP_IDENTS = frozenset({
    'if', 'for', 'while', 'switch', 'catch', 'return', 'new', 'throw',
    'typeof', 'function', 'else', 'try', 'delete', 'void', 'await',
    'case', 'break', 'continue', 'do', 'finally', 'with', 'yield',
    'import', 'export', 'default', 'let', 'const', 'var', 'class',
})

def parse_js(rel_path):
    """Parse a JS file → dict with classes, methods, functions, sections."""
    lines = read_lines(rel_path)
    total = len(lines)
    size = fsize(rel_path)

    info = dict(path=rel_path, lines=total, bytes=size,
                description='', classes=[], functions=[], sections=[])

    # ── Extract file-header description (first non-decorator comment) ──
    for line in lines[:15]:
        s = line.strip()
        if s.startswith("'use strict'") or s == '':
            continue
        if s.startswith('//'):
            text = s.lstrip('/ ').strip()
            if text and not re.match(r'^[─═━╌─]+$', text):
                info['description'] = text
                break
        else:
            break

    # ── State tracking ──
    current_class = None       # reference into info['classes']
    in_prototype = False       # inside Object.assign(X.prototype, { ... })

    for i, raw_line in enumerate(lines):
        ln = i + 1
        s = raw_line.strip()

        # Section markers: // ── Name ── or // ═══ NAME ═══
        m = re.match(r'^//\s*[─═━╌]{2,}\s+(.+?)\s+[─═━╌]{2,}', s)
        if m:
            name = m.group(1).strip()
            if name:
                info['sections'].append(dict(name=name, line=ln))

        # ── Major section comment blocks in CSS style: /* ═══ NAME ═══ */
        m2 = re.match(r'^/\*\s*[═]{3,}\s+(.+?)\s+[═]{3,}', s)
        if m2:
            name = m2.group(1).strip()
            if name:
                info['sections'].append(dict(name=name, line=ln))

        # Skip pure comment lines for symbol extraction
        if s.startswith('//') or s.startswith('/*') or s.startswith('*'):
            continue

        # ── Class definition ──
        m = re.match(r'^class\s+(\w+)', s)
        if m:
            current_class = dict(name=m.group(1), line=ln, methods=[])
            info['classes'].append(current_class)
            in_prototype = False
            continue

        # ── Object.assign(Foo.prototype, { ... }) ──
        m = re.match(r'^Object\.assign\(\s*(\w+)\.prototype\s*,\s*\{', s)
        if m:
            target = m.group(1)
            # Attach to existing class if found
            found = None
            for c in info['classes']:
                if c['name'] == target:
                    found = c
                    break
            if found:
                current_class = found
            else:
                current_class = dict(name=target, line=ln, methods=[], note='prototype extension')
                info['classes'].append(current_class)
            in_prototype = True
            continue

        # ── End of Object.assign block ──
        if in_prototype and s.startswith('});'):
            in_prototype = False
            continue

        # ── Method inside class or Object.assign ──
        if current_class is not None:
            indent = len(raw_line) - len(raw_line.lstrip())
            if indent >= 2:  # methods are indented
                # Match: methodName(args) {  or  async methodName(args) {
                m = re.match(r'^\s+(static\s+)?(?:async\s+)?(\w+)\s*\(', raw_line)
                if m:
                    name = m.group(2)
                    if name not in SKIP_IDENTS:
                        prefix = 'static ' if m.group(1) else ''
                        current_class['methods'].append(
                            dict(name=f"{prefix}{name}", line=ln))

        # ── Standalone function ──
        m = re.match(r'^(?:async\s+)?function\s+(\w+)\s*\(', s)
        if m:
            info['functions'].append(dict(name=m.group(1), line=ln))

    # ── Compute method end-lines (approx: line before next symbol) ──
    for cls in info['classes']:
        methods = cls['methods']
        for j, method in enumerate(methods):
            if j + 1 < len(methods):
                method['line_end'] = methods[j + 1]['line'] - 1
            elif cls.get('line'):
                method['line_end'] = total

    return info


# ─── CSS parser ────────────────────────────────────────────────────────────

def parse_css(rel_path):
    """Parse CSS file → dict with section names and line ranges."""
    lines = read_lines(rel_path)
    total = len(lines)
    size = fsize(rel_path)
    sections = []

    for i, line in enumerate(lines):
        ln = i + 1
        # Multi-line markers: /* ═══...═══ \n   SECTION NAME \n   ═══...═══ */
        if '═══' in line and '/*' in line and i + 1 < total:
            name = lines[i + 1].strip()
            if name and not name.startswith('═') and not name.startswith('*/'):
                sections.append(dict(name=name, line=ln))
        # Single-line markers: /* ═══ SECTION ═══ */
        elif '═══' in line:
            m = re.search(r'[═]{3,}\s+(.+?)\s+[═]{3,}', line)
            if m:
                name = m.group(1).strip().rstrip('*/').strip()
                if name:
                    sections.append(dict(name=name, line=ln))

    for j, sec in enumerate(sections):
        sec['line_end'] = sections[j + 1]['line'] - 1 if j + 1 < len(sections) else total

    return dict(path=rel_path, lines=total, bytes=size, sections=sections)


# ─── YARA parser ───────────────────────────────────────────────────────────

def parse_yara(rel_path):
    """Parse YARA rule file → dict with rule names, line ranges, and categories."""
    lines = read_lines(rel_path)
    total = len(lines)
    size = fsize(rel_path)
    rules = []

    for i, line in enumerate(lines):
        ln = i + 1
        m = re.match(r'^rule\s+(\w+)', line.strip())
        if m:
            name = m.group(1)
            # Derive category from rule name prefix
            parts = name.split('_')
            category = parts[0] if parts else 'Other'
            rules.append(dict(name=name, line=ln, category=category))

    for j, rule in enumerate(rules):
        rule['line_end'] = rules[j + 1]['line'] - 1 if j + 1 < len(rules) else total

    return dict(path=rel_path, lines=total, bytes=size, rules=rules)


# ─── Discover all source files ─────────────────────────────────────────────

def discover_files():
    """Walk src/ and return categorised file lists."""
    js_files = []
    css_files = []
    yar_files = []

    for dirpath, _, filenames in os.walk(os.path.join(BASE, 'src')):
        for fn in sorted(filenames):
            rel = os.path.relpath(os.path.join(dirpath, fn), BASE).replace('\\', '/')
            if fn.endswith('.js'):
                js_files.append(rel)
            elif fn.endswith('.css'):
                css_files.append(rel)
            elif fn.endswith('.yar'):
                yar_files.append(rel)

    return js_files, css_files, yar_files


# ─── Cross-reference analysis ──────────────────────────────────────────────

def find_cross_refs(js_infos):
    """Analyse which classes are referenced from which files."""
    # Build class → file map
    class_to_file = {}
    for info in js_infos:
        for cls in info['classes']:
            class_to_file[cls['name']] = info['path']

    # Find references: "new ClassName" or "ClassName." in each file
    refs = {}  # file → set of class names used
    for info in js_infos:
        lines = read_lines(info['path'])
        used = set()
        for line in lines:
            for cname in class_to_file:
                if cname in line:
                    # Verify it's a real reference, not the definition itself
                    if class_to_file[cname] != info['path']:
                        used.add(cname)
        if used:
            refs[info['path']] = sorted(used)

    return refs


# ─── Markdown generation ───────────────────────────────────────────────────

def generate_markdown(js_infos, css_infos, yar_infos, cross_refs):
    md = []
    w = md.append

    w('# 🗺️ Loupe Code Map')
    w('')
    w(f'> Auto-generated by `generate-codemap.py` on {datetime.now().strftime("%Y-%m-%d %H:%M")}.')
    w('> **Re-run `python generate-codemap.py` after any code changes.**')
    w('')
    w('This file gives AI coding agents a complete index of every source file,')
    w('class, method, CSS section, and YARA rule with precise line numbers.')
    w('Use `read_file(path, start_line=X, end_line=Y)` for surgical reads.')
    w('')

    # ── Quick stats ──
    all_infos = js_infos + css_infos + yar_infos
    total_lines = sum(i.get('lines', 0) for i in all_infos)
    total_bytes = sum(i.get('bytes', 0) for i in all_infos)
    w('## Quick Stats')
    w('')
    w(f'- **{len(all_infos)} source files** — {total_lines:,} lines — {fmt_kb(total_bytes)}')
    w(f'- **{len(js_infos)} JavaScript** — {sum(i["lines"] for i in js_infos):,} lines')
    w(f'- **{len(css_infos)} CSS** — {sum(i["lines"] for i in css_infos):,} lines')
    w(f'- **{len(yar_infos)} YARA** — {sum(i["lines"] for i in yar_infos):,} lines')
    # Highlight large files
    large = sorted(all_infos, key=lambda x: x.get('lines', 0), reverse=True)[:5]
    w(f'- **Largest files:** ' + ', '.join(
        f'`{os.path.basename(f["path"])}` ({f["lines"]:,} lines)'
        for f in large))
    w('')

    # ── File inventory table ──
    w('---')
    w('')
    w('## File Inventory')
    w('')
    w('| File | Lines | Size | Purpose |')
    w('|------|------:|-----:|---------|')

    # Sort: src/ root first, then renderers/, then app/
    def sort_key(info):
        p = info['path']
        if '/app/' in p:
            return (2, p)
        elif '/renderers/' in p:
            return (1, p)
        elif '/styles/' in p:
            return (0.5, p)
        elif '/rules/' in p:
            return (0.6, p)
        else:
            return (0, p)

    for info in sorted(all_infos, key=sort_key):
        desc = info.get('description', '')
        # For CSS/YARA, add a description
        if not desc:
            p = info['path']
            if p.endswith('.css'):
                desc = 'Stylesheet'
            elif p.endswith('.yar'):
                desc = f'YARA rules ({len(info.get("rules", []))} rules)'
        w(f'| `{info["path"]}` | {info["lines"]:,} | {fmt_kb(info["bytes"])} | {desc} |')

    w('')

    # ── Cross-references ──
    if cross_refs:
        w('---')
        w('')
        w('## Cross-References (class usage)')
        w('')
        w('| File | Uses classes from |')
        w('|------|-------------------|')
        for filepath in sorted(cross_refs.keys()):
            classes = cross_refs[filepath]
            refs_str = ', '.join(f'`{c}`' for c in classes)
            w(f'| `{filepath}` | {refs_str} |')
        w('')

    # ── Detailed JS symbol maps ──
    w('---')
    w('')
    w('## JavaScript Symbol Map')
    w('')

    for info in sorted(js_infos, key=sort_key):
        lines_str = f"{info['lines']:,} lines, {fmt_kb(info['bytes'])}"
        w(f'### `{info["path"]}` ({lines_str})')
        if info['description']:
            w(f'> {info["description"]}')
        w('')

        # Sections
        if info['sections']:
            w('<details><summary>Section markers</summary>')
            w('')
            w('| Section | Line |')
            w('|---------|-----:|')
            for sec in info['sections']:
                w(f'| {sec["name"]} | {sec["line"]} |')
            w('')
            w('</details>')
            w('')

        # Classes and methods
        for cls in info['classes']:
            note = f' *(prototype extension)*' if cls.get('note') else ''
            w(f'**Class `{cls["name"]}`**{note} — line {cls["line"]}')
            w('')
            if cls['methods']:
                w('| Method | Lines |')
                w('|--------|------:|')
                for m in cls['methods']:
                    end = m.get('line_end', '?')
                    w(f'| `{m["name"]}()` | {m["line"]}–{end} |')
                w('')

        # Standalone functions
        if info['functions']:
            w('**Standalone functions:**')
            w('')
            for f in info['functions']:
                w(f'- `{f["name"]}()` — line {f["line"]}')
            w('')

    # ── CSS section map ──
    if css_infos:
        w('---')
        w('')
        w('## CSS Section Map')
        w('')
        for info in sorted(css_infos, key=lambda x: x['path']):
            w(f'### `{info["path"]}` ({info["lines"]:,} lines)')
            w('')
            if info['sections']:
                w('| Section | Lines |')
                w('|---------|------:|')
                for sec in info['sections']:
                    w(f'| {sec["name"]} | {sec["line"]}–{sec["line_end"]} |')
                w('')

    # ── YARA rule map ──
    if yar_infos:
        w('---')
        w('')
        w('## YARA Rule Map')
        w('')
        for info in sorted(yar_infos, key=lambda x: x['path']):
            rules = info.get('rules', [])
            w(f'### `{info["path"]}` ({info["lines"]:,} lines, {len(rules)} rules)')
            w('')
            # Group by category
            categories = {}
            for r in rules:
                cat = r['category']
                categories.setdefault(cat, []).append(r)

            for cat in sorted(categories.keys()):
                cat_rules = categories[cat]
                w(f'<details><summary><strong>{cat}</strong> ({len(cat_rules)} rules)</summary>')
                w('')
                w('| Rule | Lines |')
                w('|------|------:|')
                for r in cat_rules:
                    w(f'| `{r["name"]}` | {r["line"]}–{r["line_end"]} |')
                w('')
                w('</details>')
                w('')

    # ── How-to recipes for AI agents ──
    w('---')
    w('')
    w('## How-To Recipes for AI Agents')
    w('')
    w('### Add a new file format renderer')
    w('')
    w('1. Create `src/renderers/foo-renderer.js` with a class:')
    w('   ```js')
    w("   'use strict';")
    w('   class FooRenderer {')
    w('     render(buffer, fileName) { /* returns DOM element */ }')
    w('     analyzeForSecurity(buffer, fileName) { /* returns findings object */ }')
    w('   }')
    w('   ```')
    w('2. Add format detection in `src/app/app-load.js` — find the extension-to-renderer')
    w('   switch/if-chain and add your format.')
    w('3. Add `src/renderers/foo-renderer.js` to `JS_FILES` in `build.py` (before `app-core.js`).')
    w('4. Add viewer CSS (if needed) to the appropriate CSS file under `src/styles/`.')
    w('5. Add file extensions to `file-input accept` attribute in `build.py`.')
    w('6. Run `python build.py` and test with a sample file.')
    w('7. Run `python generate-codemap.py` to update this map.')
    w('')
    w('### Add a new YARA rule')
    w('')
    w('1. Choose the appropriate `.yar` file under `src/rules/` by category.')
    w('2. Add your rule following the existing pattern (rule name, meta, strings, condition).')
    w('3. Run `python build.py` to rebuild.')
    w('4. Run `python generate-codemap.py` to update this map.')
    w('')
    w('### Modify sidebar content')
    w('')
    w('1. Read `src/app/app-sidebar.js` — the main entry point is `_renderSidebar()`.')
    w('2. Each sidebar section has its own method (`_renderFileInfoSection`, `_renderMacrosSection`, etc.).')
    w('3. Use the symbol map above for precise line ranges.')
    w('')
    w('### Modify CSS styles')
    w('')
    w('1. Check the CSS Section Map above to find which file and line range contains the styles.')
    w('2. CSS files under `src/styles/` are concatenated in order by `build.py`.')
    w('3. Use the section markers in the CSS files to navigate to the right area.')
    w('')
    w('### Modify the build process')
    w('')
    w('1. Edit `build.py` — it reads source files, concatenates them, and writes `docs/index.html`.')
    w('2. `JS_FILES` list controls the concatenation order (dependency order matters).')
    w('3. CSS files are listed in `CSS_FILES`; YARA rules in `YARA_FILES`.')
    w('')
    w('### Add IOCs / security findings from a renderer')
    w('')
    w('The `analyzeForSecurity(buffer, fileName)` method must return a findings object:')
    w('```js')
    w('{')
    w('  detections: [],         // Array of { name, description, severity }')
    w('  interestingStrings: [], // Array of IOC items (see below)')
    w('  riskLevel: "low",       // "low" | "medium" | "high" | "critical"')
    w('  riskScore: 0,           // Numeric — thresholds: ≥10 medium, ≥30 high, ≥50 critical')
    w('  summary: "",            // Human-readable summary string')
    w('  formatSpecific: [],     // Array of { label, value } metadata pairs')
    w('}')
    w('```')
    w('')
    w('**IOC item structure** — each item in `interestingStrings` or `externalRefs`:')
    w('```js')
    w('{')
    w('  type: IOC.URL,          // REQUIRED — must use IOC.* constants from constants.js')
    w('  url: "value",           // REQUIRED — the display value (URL, IP, email, path, etc.)')
    w('  severity: "medium",     // REQUIRED — "critical" | "high" | "medium" | "info"')
    w('  note: "SAN (DNS)",      // Optional — shown as sub-line with "↳" prefix')
    w('}')
    w('```')
    w('')
    w('**IOC type constants** (defined in `src/constants.js`):')
    w('| Constant | Value | Use for |')
    w('|----------|-------|---------|')
    w('| `IOC.URL` | `"URL"` | URLs, domains, hostnames |')
    w('| `IOC.EMAIL` | `"Email"` | Email addresses |')
    w('| `IOC.IP` | `"IP Address"` | IPv4/IPv6 addresses |')
    w('| `IOC.FILE_PATH` | `"File Path"` | File system paths |')
    w('| `IOC.UNC_PATH` | `"UNC Path"` | UNC network paths |')
    w('| `IOC.HASH` | `"Hash"` | File hashes |')
    w('| `IOC.COMMAND_LINE` | `"Command Line"` | Command line strings |')
    w('| `IOC.PROCESS` | `"Process"` | Process names |')
    w('| `IOC.HOSTNAME` | `"Hostname"` | Host/computer names |')
    w('| `IOC.USERNAME` | `"Username"` | User account names |')
    w('| `IOC.REGISTRY_KEY` | `"Registry Key"` | Windows registry keys |')
    w('| `IOC.YARA` | `"YARA Match"` | YARA rule matches (shown in Detections, not IOCs) |')
    w('| `IOC.PATTERN` | `"Pattern"` | Pattern matches (shown in Detections, not IOCs) |')
    w('| `IOC.INFO` | `"Info"` | Informational findings (shown in Detections, not IOCs) |')
    w('')
    w('**⚠ Common pitfall:** Never use bare strings like `"url"`, `"ip"`, `"domain"`, `"email"` —')
    w('always use `IOC.*` constants. The sidebar filters by exact type string to separate')
    w('IOCs from detections. Items with `IOC.YARA`, `IOC.PATTERN`, or `IOC.INFO` types are')
    w('shown in the "Detections" section; all other types appear in the "IOCs" section.')
    w('')
    w('---')
    w('')
    w('*This file is generated — do not edit manually. Run `python generate-codemap.py` to regenerate.*')

    return '\n'.join(md) + '\n'


# ─── JSON generation ───────────────────────────────────────────────────────

def generate_json(js_infos, css_infos, yar_infos, cross_refs):
    return {
        'generated': datetime.now().isoformat(),
        'js': js_infos,
        'css': css_infos,
        'yara': yar_infos,
        'cross_refs': cross_refs,
    }


# ─── Main ──────────────────────────────────────────────────────────────────

def main():
    js_files, css_files, yar_files = discover_files()

    print(f"Parsing {len(js_files)} JS, {len(css_files)} CSS, {len(yar_files)} YARA files...")

    js_infos  = [parse_js(f) for f in js_files]
    css_infos = [parse_css(f) for f in css_files]
    yar_infos = [parse_yara(f) for f in yar_files]

    print("Analysing cross-references...")
    cross_refs = find_cross_refs(js_infos)

    if '--json' in sys.argv:
        data = generate_json(js_infos, css_infos, yar_infos, cross_refs)
        out = os.path.join(BASE, 'codemap.json')
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        print(f"OK  Wrote {out}")
    else:
        md = generate_markdown(js_infos, css_infos, yar_infos, cross_refs)
        out = os.path.join(BASE, 'CODEMAP.md')
        with open(out, 'w', encoding='utf-8') as f:
            f.write(md)
        size = len(md.encode('utf-8'))
        print(f"OK  Wrote {out}  ({size:,} bytes / ~{size // 4:,} tokens)")

if __name__ == '__main__':
    main()
