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

def read_text(rel):
    with open(os.path.join(BASE, rel), 'r', encoding='utf-8') as f:
        return f.read()

def fsize(rel):
    return os.path.getsize(os.path.join(BASE, rel))

def fmt_kb(b):
    return f"{b // 1024} KB" if b >= 1024 else f"{b} B"

def approx_tokens(byte_len):
    """Rough GPT-style token estimate: ~4 bytes / token for source code."""
    return byte_len // 4

# ─── JS parser ─────────────────────────────────────────────────────────────

SKIP_IDENTS = frozenset({
    'if', 'for', 'while', 'switch', 'catch', 'return', 'new', 'throw',
    'typeof', 'function', 'else', 'try', 'delete', 'void', 'await',
    'case', 'break', 'continue', 'do', 'finally', 'with', 'yield',
    'import', 'export', 'default', 'let', 'const', 'var', 'class',
})

def _extract_header_description(lines):
    """Return the first non-decorator comment at the top of a JS file.

    Handles both `//` line comments and `/* */` block comments, skipping
    past `'use strict';`, shebangs, and blank lines. Rule-of-thumb rulers
    made of box-drawing characters are ignored. Returns '' if no usable
    description is found in the first ~15 lines.
    """
    # Join first 30 lines so we can match multi-line block comments.
    head = ''.join(lines[:30])

    # Strip leading noise: shebang, 'use strict', blank lines.
    head = re.sub(r"(?m)^\s*(#!.*|'use strict';?)\s*\n", '', head)
    head = head.lstrip()

    # Block comment: /* … */  (capture first paragraph of inner text)
    m = re.match(r'/\*(.*?)\*/', head, re.DOTALL)
    if m:
        body = m.group(1)
        # Strip leading '*', collapse whitespace.
        body_lines = []
        for raw in body.splitlines():
            t = raw.strip().lstrip('*').strip()
            # Skip ruler lines like ══════ or ─────
            if re.match(r'^[─═━╌]+$', t):
                continue
            if not t:
                if body_lines:  # first blank ends paragraph
                    break
                continue
            body_lines.append(t)
            if len(body_lines) >= 2:  # one-liner preferred, two tops
                break
        if body_lines:
            return ' '.join(body_lines)

    # Run of // line comments at start.
    out = []
    for line in lines[:15]:
        s = line.strip()
        if s.startswith("'use strict'") or s == '' or s.startswith('#!'):
            continue
        if s.startswith('//'):
            text = s.lstrip('/ ').strip()
            if text and not re.match(r'^[─═━╌─]+$', text):
                out.append(text)
                if len(out) >= 2:
                    break
        else:
            break
    return ' '.join(out)


def parse_js(rel_path):
    """Parse a JS file → dict with classes, methods, functions, sections."""
    lines = read_lines(rel_path)
    total = len(lines)
    size = fsize(rel_path)

    info = dict(path=rel_path, lines=total, bytes=size,
                description='', classes=[], functions=[], sections=[])

    info['description'] = _extract_header_description(lines)

    # ── State tracking ──
    current_class = None       # reference into info['classes']
    in_prototype = False       # inside Object.assign(X.prototype, { ... })
    class_depth = 0            # brace depth inside current class body
    proto_depth = 0            # brace depth inside Object.assign block

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

        # ── Close an open class/prototype block when we return to column 0 ──
        # (heuristic: a lone '}' at start-of-line closes the class body)
        if current_class is not None and not in_prototype:
            if s == '}' and class_depth == 1:
                current_class['line_end'] = ln
                current_class = None
                class_depth = 0
                # fall through to continue comment/symbol handling on same line
                continue

        # Skip pure comment lines for symbol extraction
        if s.startswith('//') or s.startswith('/*') or s.startswith('*'):
            continue

        # ── Class definition ──
        m = re.match(r'^class\s+(\w+)', s)
        if m:
            current_class = dict(name=m.group(1), line=ln, methods=[])
            info['classes'].append(current_class)
            in_prototype = False
            class_depth = 1 if '{' in s else 0
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
                current_class = dict(name=target, line=ln, methods=[],
                                     note='prototype extension')
                info['classes'].append(current_class)
            in_prototype = True
            proto_depth = 1
            continue

        # ── End of Object.assign block ──
        if in_prototype:
            # Track braces crudely (ignoring strings/regex — good enough for
            # well-formatted code).
            proto_depth += s.count('{') - s.count('}')
            if s.startswith('});') or proto_depth <= 0:
                if current_class is not None:
                    # Only stamp line_end if we don't already have a tighter
                    # one from a prior class-body close.
                    current_class.setdefault('proto_end', ln)
                in_prototype = False
                proto_depth = 0
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

    # ── Compute method end-lines ──
    # For each method, the end-line is: (next method's line - 1) if there is
    # a next method in this class; otherwise the class's closing-brace line
    # (or the Object.assign close line) — NOT the end of file.
    for cls in info['classes']:
        methods = cls['methods']
        boundary = cls.get('line_end') or cls.get('proto_end') or total
        for j, method in enumerate(methods):
            if j + 1 < len(methods):
                method['line_end'] = methods[j + 1]['line'] - 1
            else:
                method['line_end'] = boundary

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

_YARA_META_RE = re.compile(
    r'^\s*(description|severity|category|mitre|author|reference)\s*=\s*"([^"]*)"',
    re.IGNORECASE,
)

def parse_yara(rel_path):
    """Parse YARA rule file → dict with rule names, line ranges, categories,
    and per-rule metadata (description / severity / mitre / category).
    """
    lines = read_lines(rel_path)
    total = len(lines)
    size = fsize(rel_path)
    rules = []

    current = None
    in_meta = False
    for i, line in enumerate(lines):
        ln = i + 1
        m = re.match(r'^rule\s+(\w+)', line.strip())
        if m:
            if current is not None:
                rules.append(current)
            name = m.group(1)
            parts = name.split('_')
            category = parts[0] if parts else 'Other'
            current = dict(name=name, line=ln, category=category, meta={})
            in_meta = False
            continue

        if current is not None:
            st = line.strip()
            if st.startswith('meta:'):
                in_meta = True
                continue
            if st.startswith('strings:') or st.startswith('condition:'):
                in_meta = False
                continue
            if in_meta:
                mm = _YARA_META_RE.match(line)
                if mm:
                    current['meta'][mm.group(1).lower()] = mm.group(2)

    if current is not None:
        rules.append(current)

    for j, rule in enumerate(rules):
        rule['line_end'] = rules[j + 1]['line'] - 1 if j + 1 < len(rules) else total

    # Roll the category up from meta if present (authoritative over the
    # prefix-derived value).
    for r in rules:
        if r['meta'].get('category'):
            r['category'] = r['meta']['category']

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
    class_to_file = {}
    for info in js_infos:
        for cls in info['classes']:
            class_to_file[cls['name']] = info['path']

    refs = {}  # file → set of class names used
    for info in js_infos:
        lines = read_lines(info['path'])
        used = set()
        for line in lines:
            for cname in class_to_file:
                if cname in line:
                    if class_to_file[cname] != info['path']:
                        used.add(cname)
        if used:
            refs[info['path']] = sorted(used)

    return refs


# ─── Renderer dispatch extraction ──────────────────────────────────────────

_REG_ENTRY_RE = re.compile(
    r"\{\s*"
    r"id:\s*'([^']+)'\s*,\s*"
    r"className:\s*'([^']+)'\s*,\s*"
    r"exts:\s*\[([^\]]*)\]",
    re.DOTALL,
)

def parse_renderer_registry():
    """Extract dispatch entries from src/renderer-registry.js.

    Returns a list of dicts: {id, className, exts, description, has_magic,
    has_textSniff}. The registry is the single source of truth for dispatch
    in Loupe, so mirroring it into the codemap is high value for agents.
    """
    path = 'src/renderer-registry.js'
    if not os.path.exists(os.path.join(BASE, path)):
        return []
    txt = read_text(path)
    entries = []
    # Split on entry boundaries by matching top-level `{ id: '…', …` blocks.
    # The regex above is non-greedy and only needs id/className/exts; we then
    # look ahead in the same chunk for description / magic / textSniff.
    for m in _REG_ENTRY_RE.finditer(txt):
        ident = m.group(1)
        classname = m.group(2)
        exts_raw = m.group(3)
        exts = re.findall(r"'([^']+)'", exts_raw)
        # Find the closing brace of this entry (balance-match from m.start()).
        start = m.start()
        depth = 0
        end = start
        for i in range(start, min(start + 4000, len(txt))):
            c = txt[i]
            if c == '{': depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        block = txt[start:end]
        desc_m = re.search(r"description:\s*'([^']+)'", block)
        desc = desc_m.group(1) if desc_m else ''
        entries.append(dict(
            id=ident,
            className=classname,
            exts=exts,
            description=desc,
            has_magic='magic:' in block,
            has_textSniff='textSniff:' in block,
            has_extDisambiguator='extDisambiguator:' in block and 'extDisambiguator: null' not in block,
        ))
    return entries


# ─── IOC type usage map ────────────────────────────────────────────────────

_IOC_USE_RE = re.compile(r'\bIOC\.([A-Z_]+)\b')

def parse_ioc_constants():
    """Read src/constants.js for the canonical IOC.* name list."""
    path = 'src/constants.js'
    if not os.path.exists(os.path.join(BASE, path)):
        return []
    txt = read_text(path)
    m = re.search(r'const\s+IOC\s*=\s*Object\.freeze\(\{(.*?)\}\)', txt, re.DOTALL)
    if not m:
        return []
    names = re.findall(r'^\s*([A-Z_]+)\s*:', m.group(1), re.MULTILINE)
    return names


def find_ioc_usage(js_files):
    """For each IOC.* constant, list which files reference it."""
    uses = {}  # name → sorted list of files
    for rel in js_files:
        # Don't count the definition file.
        if rel.endswith('/constants.js') or rel.endswith('\\constants.js'):
            continue
        try:
            txt = read_text(rel)
        except Exception:
            continue
        found = set(_IOC_USE_RE.findall(txt))
        for name in found:
            uses.setdefault(name, set()).add(os.path.basename(rel))
    return {k: sorted(v) for k, v in uses.items()}


# ─── Markdown generation ───────────────────────────────────────────────────

def generate_markdown(js_infos, css_infos, yar_infos, cross_refs,
                      registry_entries, ioc_constants, ioc_usage):
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
    w('For *how* to make changes (recipes, gotchas, docs-update requirements)')
    w('see `CONTRIBUTING.md`. This file is pure reference.')
    w('')

    # ── Quick stats ──
    all_infos = js_infos + css_infos + yar_infos
    total_lines = sum(i.get('lines', 0) for i in all_infos)
    total_bytes = sum(i.get('bytes', 0) for i in all_infos)
    total_classes = sum(len(i.get('classes', [])) for i in js_infos)
    total_methods = sum(len(c.get('methods', []))
                        for i in js_infos for c in i.get('classes', []))
    total_fns = sum(len(i.get('functions', [])) for i in js_infos)
    total_rules = sum(len(i.get('rules', [])) for i in yar_infos)
    renderer_count = sum(1 for i in js_infos if '/renderers/' in i['path']
                         and 'archive-tree' not in i['path'])

    w('## Quick Stats')
    w('')
    w(f'- **{len(all_infos)} source files** — {total_lines:,} lines — '
      f'{fmt_kb(total_bytes)} — ~{approx_tokens(total_bytes):,} tokens')
    w(f'- **{len(js_infos)} JavaScript** — {sum(i["lines"] for i in js_infos):,} lines, '
      f'{total_classes} classes, {total_methods} methods, {total_fns} standalone functions')
    w(f'- **{len(css_infos)} CSS** — {sum(i["lines"] for i in css_infos):,} lines')
    w(f'- **{len(yar_infos)} YARA** files — {sum(i["lines"] for i in yar_infos):,} lines — '
      f'{total_rules} rules')
    w(f'- **{renderer_count} format renderers** registered in `renderer-registry.js`')
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
    w('Token estimates are rough (≈ 4 bytes / token). Use these to decide')
    w('whether to read a file in full vs. target a line range from the')
    w('symbol map below.')
    w('')
    w('| File | Lines | Size | ~Tokens | Purpose |')
    w('|------|------:|-----:|--------:|---------|')

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
        if not desc:
            p = info['path']
            if p.endswith('.css'):
                desc = 'Stylesheet'
            elif p.endswith('.yar'):
                desc = f'YARA rules ({len(info.get("rules", []))} rules)'
        # Keep descriptions short so the table stays readable.
        if len(desc) > 120:
            desc = desc[:117] + '…'
        toks = approx_tokens(info["bytes"])
        w(f'| `{info["path"]}` | {info["lines"]:,} | {fmt_kb(info["bytes"])} | '
          f'~{toks:,} | {desc} |')

    w('')

    # ── Renderer Dispatch Map ──
    if registry_entries:
        w('---')
        w('')
        w('## Renderer Dispatch Map')
        w('')
        w('Every entry in `src/renderer-registry.js` — **the single source of')
        w('truth for format detection**. Order is significant: within each pass')
        w('(magic → extension → text sniff) the first match wins, so highly')
        w('specific sub-formats appear before their container parents.')
        w('')
        w('| # | Id | Renderer class | Extensions | M | S | X | Description |')
        w('|--:|----|----------------|------------|:-:|:-:|:-:|-------------|')
        for idx, e in enumerate(registry_entries, 1):
            exts = ', '.join(f'`.{x}`' for x in e['exts']) or '—'
            mg = '✓' if e['has_magic'] else ''
            sn = '✓' if e['has_textSniff'] else ''
            ex = '✓' if e['has_extDisambiguator'] else ''
            desc = e['description']
            if len(desc) > 70:
                desc = desc[:67] + '…'
            w(f'| {idx} | `{e["id"]}` | `{e["className"]}` | {exts} | '
              f'{mg} | {sn} | {ex} | {desc} |')
        w('')
        w('Legend: **M** = has magic-byte predicate · **S** = has text-head sniff · '
          '**X** = has `extDisambiguator` (extension alone not trusted).')
        w('')

    # ── IOC constants & usage ──
    if ioc_constants:
        w('---')
        w('')
        w('## IOC Constants & Usage')
        w('')
        w('Every renderer must emit IOCs using these constants from')
        w('`src/constants.js`. Bare strings (e.g. `type: "url"`) silently break')
        w('sidebar filtering.')
        w('')
        w('| Constant | Used in (file count) | Files |')
        w('|----------|---------------------:|-------|')
        for name in ioc_constants:
            files = ioc_usage.get(name, [])
            # Trim the file list if it's long.
            if len(files) > 8:
                file_str = ', '.join(f'`{f}`' for f in files[:8]) + f', … (+{len(files)-8})'
            else:
                file_str = ', '.join(f'`{f}`' for f in files) if files else '*(unused)*'
            w(f'| `IOC.{name}` | {len(files)} | {file_str} |')
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
        w('Severity column is pulled from each rule\'s `meta:` block; blank')
        w('cells indicate a rule that omits the field (style nit — '
          '`yara-rule-audit` skill will flag it).')
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
                w('| Rule | Sev | Lines | Description |')
                w('|------|-----|------:|-------------|')
                for r in cat_rules:
                    sev = r['meta'].get('severity', '')
                    desc = r['meta'].get('description', '')
                    if len(desc) > 70:
                        desc = desc[:67] + '…'
                    w(f'| `{r["name"]}` | {sev} | {r["line"]}–{r["line_end"]} | {desc} |')
                w('')
                w('</details>')
                w('')

    # ── Footer ──
    w('---')
    w('')
    w('*This file is generated — do not edit manually. Run ')
    w('`python generate-codemap.py` to regenerate after code changes.*')

    return '\n'.join(md) + '\n'


# ─── JSON generation ───────────────────────────────────────────────────────

def generate_json(js_infos, css_infos, yar_infos, cross_refs,
                  registry_entries, ioc_constants, ioc_usage):
    return {
        'generated': datetime.now().isoformat(),
        'js': js_infos,
        'css': css_infos,
        'yara': yar_infos,
        'cross_refs': cross_refs,
        'renderer_registry': registry_entries,
        'ioc_constants': ioc_constants,
        'ioc_usage': ioc_usage,
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

    print("Extracting renderer dispatch registry...")
    registry_entries = parse_renderer_registry()

    print("Indexing IOC constants & usage...")
    ioc_constants = parse_ioc_constants()
    ioc_usage = find_ioc_usage(js_files)

    if '--json' in sys.argv:
        data = generate_json(js_infos, css_infos, yar_infos, cross_refs,
                             registry_entries, ioc_constants, ioc_usage)
        out = os.path.join(BASE, 'codemap.json')
        with open(out, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        print(f"OK  Wrote {out}")
    else:
        md = generate_markdown(js_infos, css_infos, yar_infos, cross_refs,
                               registry_entries, ioc_constants, ioc_usage)
        out = os.path.join(BASE, 'CODEMAP.md')
        with open(out, 'w', encoding='utf-8') as f:
            f.write(md)
        size = len(md.encode('utf-8'))
        print(f"OK  Wrote {out}  ({size:,} bytes / ~{size // 4:,} tokens)")

if __name__ == '__main__':
    main()
