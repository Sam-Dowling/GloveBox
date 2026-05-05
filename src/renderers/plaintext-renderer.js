'use strict';
// ════════════════════════════════════════════════════════════════════════════
// plaintext-renderer.js — Catch-all viewer for unsupported file types
// Shows plain text (with line numbers) or hex dump depending on content.
// Supports encoding auto-detection (UTF-8, UTF-16LE, UTF-16BE, Latin-1),
// a best-efforts code-formatting toggle (`loupe_plaintext_format`) and a
// word-wrap on/off toggle (`loupe_plaintext_wrap`). Syntax highlighting
// is always on (when possible) — there's no user-facing toggle because
// the rich-render gate already makes the feature unavailable long before
// it becomes a perf problem, and a "disable highlighting" switch would
// only be useful on files where it's already disabled automatically.
//
// Both rich-rendering toggles share a single feasibility gate
// (`_canEnhance` → `RICH_MAX_*`) so they appear/disappear in lock-step.
// Files that exceed the gate fall back to the plain virtualised viewer.
//
// Minified-JS footgun: a single logical line can be multiple megabytes.
// `VirtualTextView` splits absurdly long lines into display-only chunks
// (`SOFT_WRAP_CHUNK`) so the browser does not choke on a single 2 MB
// <td>, and the shared rich-render gate excludes any file with a line
// over `RICH_MAX_LINE_LEN` from both highlight and wrap modes (hljs
// produces a gigantic span tree on one long line even if the byte total
// is modest, and pre-wrap rows of that width paint catastrophically).
//
// Best-efforts code formatter (Format toggle): visual-only — runs
// `CodeFormatter.format(text, lang)` before the source is split into
// rows for display. `_rawText` (used by click-to-focus and IOC/YARA
// offsets) is left pointing at the original source, so offset-derived
// highlights may land on slightly shifted lines when formatting is on.
// This is an explicit, documented trade-off of the "no recomputation"
// design: toggling Format never re-runs any analysis.
//
// Language-detection strategy (drives both the Format button's visibility
// and the lang label passed to `CodeFormatter.format` / `hljs.highlight`):
//   1. Extension lookup in `LANG_MAP` (fast path — drives button visible
//      at first paint for known extensions).
//   2. MIME-type lookup in `MIME_TO_LANG` (fast path fallback).
//   3. If 1+2 miss: `hljs.highlightAuto()` runs during `_buildTextPane`
//      (it already ran anyway for highlighting). If the auto-detected
//      language is in `_FORMATTABLE_LANGS` AND the relevance score is
//      ≥ `_AUTO_DETECT_MIN_RELEVANCE`, the Format button is revealed
//      and the lang is cached on `this._effectiveLang` so the toggle-
//      rebuild path can pass it to the formatter. This makes Format
//      work on pasted / extensionless content (clipboard.txt paste,
//      extensionless downloads). See `src/code-formatter.js`.
// ════════════════════════════════════════════════════════════════════════════
class PlainTextRenderer {

  // Extensions treated as known script / config types for keyword highlighting
  static SCRIPT_EXTS = new Set([
    'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'ps1', 'psm1', 'psd1',
    'bat', 'cmd', 'sh', 'bash', 'py', 'rb', 'pl',
    'hta', 'htm', 'html', 'mht', 'mhtml', 'xhtml', 'svg',
    'xml', 'xsl', 'xslt', 'xaml',
    'reg', 'inf', 'ini', 'cfg', 'conf', 'yml', 'yaml', 'toml', 'json',
    'rtf', 'eml', 'ics', 'vcf', 'url', 'desktop', 'lnk',
    'sql', 'php', 'asp', 'aspx', 'jsp', 'cgi',
    'txt', 'log', 'md', 'csv', 'tsv',
  ]);

  // Supported encodings for the selector
  static ENCODINGS = [
    { value: 'utf-8',     label: 'UTF-8' },
    { value: 'utf-16le',  label: 'UTF-16LE' },
    { value: 'utf-16be',  label: 'UTF-16BE' },
    { value: 'latin1',    label: 'Latin-1 (ISO 8859-1)' },
  ];

  // Map file extensions to highlight.js language names.
  // Backed by the vendored v11.9.0 bundle (44 languages — the upstream
  // "Common" set of 36 plus `powershell`, `dos`, `vbscript`,
  // `dockerfile`, `nginx`, `apache`, `x86asm`, `properties`, each
  // appended as a self-registering IIFE; see `vendor/highlight.min.js`
  // and the parity assertion in `tests/unit/highlight-bundle.test.js`).
  // Anything not registered with hljs is silently skipped at highlight
  // time, so any LANG_MAP value below MUST appear in `hljs.listLanguages()`
  // or the parity test will fail.
  static LANG_MAP = {
    // PowerShell
    'ps1': 'powershell', 'psm1': 'powershell', 'psd1': 'powershell',
    // VBScript / VBA / VB.NET
    'vbs': 'vbscript', 'vbe': 'vbscript',
    'vb': 'vbnet', 'vba': 'vbnet', 'bas': 'vbnet',
    // JavaScript
    'js': 'javascript', 'jse': 'javascript', 'mjs': 'javascript', 'cjs': 'javascript',
    // TypeScript
    'ts': 'typescript', 'tsx': 'typescript', 'mts': 'typescript', 'cts': 'typescript',
    // Batch / CMD
    'bat': 'dos', 'cmd': 'dos',
    // Shell / Bash / POSIX
    'sh': 'bash', 'bash': 'bash', 'zsh': 'bash', 'ksh': 'bash', 'ash': 'bash',
    'dash': 'bash', 'profile': 'bash', 'bashrc': 'bash', 'zshrc': 'bash',
    // Python
    'py': 'python', 'pyw': 'python', 'pyi': 'python', 'pyx': 'python',
    // Ruby / Perl / PHP
    'rb': 'ruby', 'rake': 'ruby', 'gemspec': 'ruby',
    'pl': 'perl', 'pm': 'perl', 't': 'perl',
    'php': 'php', 'php3': 'php', 'php4': 'php', 'php5': 'php', 'phtml': 'php',
    // XML / HTML / SVG
    'xml': 'xml', 'html': 'xml', 'htm': 'xml', 'xhtml': 'xml',
    'svg': 'xml', 'xsl': 'xml', 'xslt': 'xml', 'xaml': 'xml',
    'mht': 'xml', 'mhtml': 'xml', 'plist': 'xml', 'rss': 'xml', 'atom': 'xml',
    // JSON
    'json': 'json', 'jsonl': 'json', 'jsonc': 'json',
    // YAML
    'yml': 'yaml', 'yaml': 'yaml',
    // Config / INI
    'ini': 'ini', 'cfg': 'ini', 'conf': 'ini', 'toml': 'ini',
    'reg': 'ini', 'inf': 'ini',
    // Java .properties (purpose-built grammar rather than falling back to ini)
    'properties': 'properties',
    // SQL
    'sql': 'sql',
    // CSS family
    'css': 'css',
    'scss': 'scss', 'sass': 'scss',
    'less': 'less',
    // C-family
    'c': 'c', 'h': 'c',
    'cpp': 'cpp', 'cc': 'cpp', 'cxx': 'cpp', 'hpp': 'cpp', 'hxx': 'cpp', 'c++': 'cpp',
    'cs': 'csharp',
    'java': 'java', 'jsp': 'java',
    'go': 'go',
    'rs': 'rust',
    'swift': 'swift',
    'kt': 'kotlin', 'kts': 'kotlin',
    // Objective-C
    'm': 'objectivec', 'mm': 'objectivec',
    // Markdown
    'md': 'markdown', 'markdown': 'markdown', 'mdown': 'markdown', 'mkd': 'markdown',
    // Makefile / build
    'makefile': 'makefile', 'mk': 'makefile', 'mak': 'makefile',
    // Lua
    'lua': 'lua',
    // R
    'r': 'r',
    // GraphQL
    'graphql': 'graphql', 'gql': 'graphql',
    // WebAssembly text format
    'wat': 'wasm', 'wast': 'wasm',
    // Diff / patch
    'diff': 'diff', 'patch': 'diff',
    // Dockerfile / Containerfile (no canonical extension; matched by
    // filename in `_detectLanguage` below, plus `.dockerfile` for rare cases)
    'dockerfile': 'dockerfile', 'containerfile': 'dockerfile',
    // x86 / x86-64 assembly listings
    'asm': 'x86asm', 's': 'x86asm', 'nasm': 'x86asm', 'inc': 'x86asm',
  };

  // Map MIME types to highlight.js language names (fallback when extension is unknown)
  static MIME_TO_LANG = {
    // JavaScript
    'text/javascript': 'javascript',
    'application/javascript': 'javascript',
    'application/x-javascript': 'javascript',
    'text/ecmascript': 'javascript',
    'application/ecmascript': 'javascript',
    // TypeScript
    'text/typescript': 'typescript',
    'application/typescript': 'typescript',
    // JSON
    'application/json': 'json',
    'text/json': 'json',
    // XML / HTML
    'text/xml': 'xml',
    'application/xml': 'xml',
    'text/html': 'xml',
    'application/xhtml+xml': 'xml',
    'image/svg+xml': 'xml',
    // CSS
    'text/css': 'css',
    // Python
    'text/x-python': 'python',
    'application/x-python': 'python',
    'text/x-python-script': 'python',
    // Shell / Bash
    'text/x-sh': 'bash',
    'application/x-sh': 'bash',
    'text/x-shellscript': 'bash',
    // PHP
    'text/x-php': 'php',
    'application/x-php': 'php',
    // Ruby
    'text/x-ruby': 'ruby',
    'application/x-ruby': 'ruby',
    // Perl
    'text/x-perl': 'perl',
    'application/x-perl': 'perl',
    // C / C++
    'text/x-c': 'c',
    'text/x-csrc': 'c',
    'text/x-c++': 'cpp',
    'text/x-c++src': 'cpp',
    // Java
    'text/x-java': 'java',
    'text/x-java-source': 'java',
    // C#
    'text/x-csharp': 'csharp',
    // YAML
    'text/yaml': 'yaml',
    'text/x-yaml': 'yaml',
    'application/x-yaml': 'yaml',
    // SQL
    'text/x-sql': 'sql',
    'application/sql': 'sql',
    // Markdown
    'text/markdown': 'markdown',
    'text/x-markdown': 'markdown',
    // Less / SCSS / Sass
    'text/x-less': 'less',
    'text/x-scss': 'scss',
    'text/x-sass': 'scss',
    // Lua / R / Go / Rust / Swift / Kotlin
    'text/x-lua': 'lua',
    'application/x-lua': 'lua',
    'text/x-r': 'r',
    'application/x-r': 'r',
    'text/x-go': 'go',
    'text/x-rustsrc': 'rust',
    'text/x-swift': 'swift',
    'text/x-kotlin': 'kotlin',
    // Objective-C
    'text/x-objc': 'objectivec',
    'text/x-objective-c': 'objectivec',
    // GraphQL
    'application/graphql': 'graphql',
    'application/graphql+json': 'graphql',
    // Diff / patch
    'text/x-diff': 'diff',
    'text/x-patch': 'diff',
    // INI / config / TOML
    'text/x-toml': 'ini',
    'application/toml': 'ini',
    'text/x-ini': 'ini',
    // PowerShell / Batch / VBScript (Windows scripting)
    'application/x-powershell': 'powershell',
    'text/x-powershell': 'powershell',
    'application/x-msdos-program': 'dos',
    'text/x-msdos-batch': 'dos',
    'text/x-vbscript': 'vbscript',
    'application/x-vbscript': 'vbscript',
    // Dockerfile
    'text/x-dockerfile': 'dockerfile',
    // Web-server configs (nginx / Apache)
    'text/x-nginx-conf': 'nginx',
    'application/x-nginx-conf': 'nginx',
    'text/x-apache-conf': 'apache',
    // x86 / x86-64 assembly
    'text/x-asm': 'x86asm',
    'text/x-x86asm': 'x86asm',
    'text/x-nasm': 'x86asm',
    // Java .properties
    'text/x-java-properties': 'properties',
    'text/x-properties': 'properties',
  };

  // Languages the `CodeFormatter` helper actually knows how to format.
  // MUST be a subset of the labels `CodeFormatter.format()` accepts — if
  // a label is in this set but `CodeFormatter` treats it as unsupported
  // the Format button will be a visible no-op (harmless but noisy).
  //
  // Kept as a literal (not `new Set([...CodeFormatter._BRACE_LANGS, …])`)
  // so evaluation order during bundle concatenation is load-order
  // independent and doesn't require `CodeFormatter` to be defined first.
  //
  // Parity is asserted by `tests/unit/plaintext-format-autodetect.test.js`.
  static _FORMATTABLE_LANGS = new Set([
    // C-family brace langs (matches CodeFormatter._BRACE_LANGS)
    'javascript', 'typescript', 'json', 'css', 'scss', 'less',
    'c', 'cpp', 'csharp', 'java', 'go', 'rust', 'swift', 'kotlin', 'php',
    // XML block-tag splitter
    'xml',
    // Indent-only shells
    'powershell', 'bash', 'dos',
  ]);

  // Minimum `hljs.highlightAuto()` relevance score required to accept an
  // auto-detected language as the effective lang for the Format button.
  // hljs relevance is a heuristic; 5 is a low floor that accepts short
  // code snippets while still rejecting the vast majority of prose /
  // log lines. Because Format defaults to Off, a false-positive button
  // is cheap: the user must click before any formatter work happens,
  // and `CodeFormatter.format()` bails closed on unbalanced input.
  static _AUTO_DETECT_MIN_RELEVANCE = 5;

  // ── Shared "rich rendering" gate ────────────────────────────────────────
  // Both the syntax-highlight and word-wrap toggles share these thresholds
  // so they appear/disappear in lock-step — a file is either eligible for
  // both forms of enhancement or for neither.
  //
  // Sized in raw bytes so a UTF-16 file is judged by its on-disk size, not
  // by the JS-string length post-decode (which is ~2× shorter for ASCII
  // content). Three caps protect against three distinct DOM/CPU shapes:
  //   - RICH_MAX_BYTES     → bounds hljs CPU and per-row DOM count
  //   - RICH_MAX_LINES     → bounds wrap-mode all-rows-in-DOM cost
  //   - RICH_MAX_LINE_LEN  → bounds hljs span-tree on a single line
  //                          AND wrap-mode pre-wrap row width
  // Wrap mode forfeits the `VirtualTextView` virtualisation that keeps
  // sidebar-resize at native FPS, so its cost dominates the choice of
  // ceilings (hljs is comfortable up to several hundred KB).
  static RICH_MAX_BYTES     = 1024 * 1024;
  static RICH_MAX_LINES     = 20_000;
  static RICH_MAX_LINE_LEN  = 10_000;

  // Display-only chunk size for soft-wrap (characters). Used by
  // `VirtualTextView` to chunk pathologically long lines when wrap is
  // OFF (the virtualised path can't render a single 2 MB <td>).
  static SOFT_WRAP_CHUNK = 2000;
  // Hard cap on total lines rendered to the DOM (independent of the
  // rich-render gate above — files above this still render, just
  // truncated).
  static MAX_LINES = RENDER_LIMITS.MAX_TEXT_LINES;
  // Storage keys for the toggle preferences.
  // NB: the legacy `loupe_plaintext_highlight` key is no longer read or
  // written — syntax highlighting is now always on when the rich-render
  // gate allows it. Stale values in `localStorage` are harmless (no
  // migration needed; `safeStorage` simply ignores unknown keys).
  static FORMAT_PREF_KEY    = 'loupe_plaintext_format';
  static WRAP_PREF_KEY      = 'loupe_plaintext_wrap';

  // ── Preference accessors ────────────────────────────────────────────────

  /** Read the user's best-efforts code-formatting preference (default: off). */
  static _readFormatPref() {
    const v = safeStorage.get(PlainTextRenderer.FORMAT_PREF_KEY);
    return v === 'on';
  }

  /** Persist the user's best-efforts code-formatting preference. */
  static _writeFormatPref(enabled) {
    safeStorage.set(PlainTextRenderer.FORMAT_PREF_KEY, enabled ? 'on' : 'off');
  }

  /** Read the user's word-wrap preference (default: on). */
  static _readWrapPref() {
    const v = safeStorage.get(PlainTextRenderer.WRAP_PREF_KEY);
    return v !== 'off';
  }

  /** Persist the user's word-wrap preference. */
  static _writeWrapPref(enabled) {
    safeStorage.set(PlainTextRenderer.WRAP_PREF_KEY, enabled ? 'on' : 'off');
  }

  // ── Render ──────────────────────────────────────────────────────────────

  render(buffer, fileName, mimeType) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const detected = this._detectEncoding(bytes);
    const isTextByDefault = detected.isText;
    // Store mimeType for language detection
    this._mimeType = mimeType || '';

    // Build wrapper that holds both views + controls
    const wrap = document.createElement('div');
    wrap.className = isTextByDefault ? 'plaintext-view' : 'hex-view';

    // Decode text using detected encoding — normalised to \n so downstream
    // consumers (sidebar click-to-focus offsets, YARA scan buffer, IOC
    // extraction) don't drift on CRLF files. See `.clinerules` gotcha.
    const decodedText = this._normalizeNewlines(this._decodeAs(bytes, detected.encoding));

    // Pre-compute whether the rich-rendering toggles (Format + Wrap) are
    // possible at all for this file. Both toggles share a single gate
    // (`_canEnhance`) so they appear/disappear in lock-step. Highlighting
    // uses the same gate but has no user-facing toggle — it just runs
    // whenever it's feasible (hljs loaded + gate passes).
    //
    // Format has an extra requirement: a language must be known. The
    // fast path uses `_detectLangForFile` (extension/MIME lookup). If
    // that misses, `_buildTextPane` falls back to `hljs.highlightAuto()`
    // and — when the auto-detected language is in `_FORMATTABLE_LANGS`
    // and scores ≥ `_AUTO_DETECT_MIN_RELEVANCE` — calls the reveal
    // callback below to un-hide the Format button. This is the path
    // that makes Format work on pasted / extensionless content.
    const richPossible = isTextByDefault && this._canEnhance(decodedText, bytes);
    const wrapPossible = richPossible;
    const detectedLangForFormat = richPossible
      ? this._detectLangForFile(fileName, this._mimeType)
      : null;
    // `formatPossible` now only requires the rich-gate + CodeFormatter
    // bundle presence — the language check moved to per-render
    // visibility (initially hidden when lang is unknown, revealed by
    // `_buildTextPane` via auto-detect if it finds a formattable lang).
    const formatPossible = richPossible
                           && (typeof CodeFormatter !== 'undefined');
    // Effective language for the formatter — seeded from the static
    // fast-path lookup, updated by the auto-detect reveal callback.
    // The Format-toggle rebuild path reads this via `_buildTextPane`'s
    // first argument preference: if `this._effectiveLang` is truthy,
    // `_buildTextPane` uses it instead of re-running `_detectLangForFile`.
    this._effectiveLang = detectedLangForFormat;

    // ── Info bar with toggle + encoding selector ──────────────────────
    const info = document.createElement('div');
    info.className = 'plaintext-info';

    const infoText = document.createElement('span');
    infoText.className = 'plaintext-info-text';
    // Info text will be updated after building textPane to include detected language
    if (!isTextByDefault) {
      infoText.textContent = `${this._fmtBytes(bytes.length)}  ·  Binary file  ·  Hex dump view`;
    }
    info.appendChild(infoText);

    // Spacer
    const spacer = document.createElement('span');
    spacer.style.flex = '1';
    info.appendChild(spacer);

    // Best-efforts code-formatter toggle (persisted). Rendered whenever
    // the rich-render gate passes and `CodeFormatter` is bundled. The
    // button may start *hidden* when no language has been detected yet
    // via the extension/MIME fast path — `_buildTextPane` will un-hide
    // it (via `_revealFormatButton`) if `hljs.highlightAuto()` matches a
    // `_FORMATTABLE_LANGS` member with sufficient relevance. This is
    // what makes Format work on pasted / extensionless content.
    //
    // Formatting is visual-only: `_rawText` continues to point at the
    // original source so sidebar click-to-focus, YARA offsets, and IOC
    // extraction all see unchanged bytes. See file header.
    let formatEnabled = PlainTextRenderer._readFormatPref();
    let fmtLabel = null;
    let fmtBtn = null;
    if (formatPossible) {
      fmtLabel = document.createElement('label');
      fmtLabel.className = 'plaintext-enc-label';
      fmtLabel.textContent = 'Format:';
      // Hide the label until we know there's a formattable language —
      // either via the fast path or via auto-detect inside
      // `_buildTextPane`. Kept as `visibility:hidden` would preserve
      // layout space; `display:none` is fine because the label lives
      // between a flex-spacer and the encoding selector (no alignment
      // dependency).
      if (!detectedLangForFormat) fmtLabel.style.display = 'none';
      info.appendChild(fmtLabel);

      fmtBtn = document.createElement('button');
      fmtBtn.className = 'plaintext-toggle-btn';
      fmtBtn.textContent = formatEnabled ? 'On' : 'Off';
      fmtBtn.title = 'Toggle best-efforts code formatting (visual only, persisted). ' +
                     'Re-indents braces/brackets and splits long lines at statement ' +
                     'boundaries — no analysis is re-run. Click-to-focus offsets map ' +
                     'to the original source so highlights may land on shifted lines ' +
                     'while Format is on.';
      if (!detectedLangForFormat) fmtBtn.style.display = 'none';
      info.appendChild(fmtBtn);

      // If no lang is known yet, force format off on this first build —
      // otherwise the `_buildTextPane` call below would run the
      // formatter with `lang=null` and no-op, which is harmless, but
      // we also want the subsequent auto-detect reveal to land on an
      // "Off" button the user can click. The pref itself is untouched
      // (no `_writeFormatPref` call), so a future file with a known
      // extension still honours the user's stored preference.
      if (!detectedLangForFormat) formatEnabled = false;
    } else {
      // Force format off when the button would be hidden, so a stale
      // `"on"` pref from a prior rich-gated file doesn't try to run the
      // formatter on a file we know it can't help with.
      formatEnabled = false;
    }

    // Word-wrap toggle (persisted). Only rendered when the file is
    // small enough that putting every row in the DOM is bounded —
    // larger files keep the virtualised, no-wrap experience to
    // preserve native sidebar-drag FPS.
    let wrapEnabled = PlainTextRenderer._readWrapPref();
    let wrapLabel = null;
    let wrapBtn = null;
    if (wrapPossible) {
      wrapLabel = document.createElement('label');
      wrapLabel.className = 'plaintext-enc-label';
      wrapLabel.textContent = 'Wrap:';
      info.appendChild(wrapLabel);

      wrapBtn = document.createElement('button');
      wrapBtn.className = 'plaintext-toggle-btn';
      wrapBtn.textContent = wrapEnabled ? 'On' : 'Off';
      wrapBtn.title = 'Toggle word-wrap (persisted). Hidden for very large files where wrapping every line would re-introduce sidebar-drag lag.';
      info.appendChild(wrapBtn);
    } else {
      // Force wrap off so a stale `"on"` from a prior small file
      // doesn't leak the all-rows-in-DOM cost into a large file.
      wrapEnabled = false;
    }


    // Encoding selector
    const encLabel = document.createElement('label');
    encLabel.className = 'plaintext-enc-label';
    encLabel.textContent = 'Encoding:';
    info.appendChild(encLabel);

    const encSelect = document.createElement('select');
    encSelect.className = 'plaintext-enc-select';
    encSelect.title = 'Change text encoding';
    for (const enc of PlainTextRenderer.ENCODINGS) {
      const opt = document.createElement('option');
      opt.value = enc.value;
      opt.textContent = enc.label;
      if (enc.value === detected.encoding) opt.selected = true;
      encSelect.appendChild(opt);
    }
    info.appendChild(encSelect);

    // Text/Hex toggle button
    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'plaintext-toggle-btn';
    toggleBtn.textContent = isTextByDefault ? '⬡ Hex' : '🔡 Text';
    toggleBtn.title = isTextByDefault ? 'Switch to hex dump view' : 'Switch to plain text view';
    info.appendChild(toggleBtn);

    wrap.appendChild(info);

    // ── Content area ─────────────────────────────────────────────────────
    const contentArea = document.createElement('div');
    contentArea.className = 'plaintext-content-area';

    // Build both views.
    //
    // `_revealFormatButton` is a side-channel used by `_buildTextPane`'s
    // auto-detect fallback: if hljs detects a formattable language with
    // sufficient relevance, it calls this to un-hide the Format button.
    // Stashed on the renderer instance so both the initial build and
    // subsequent rebuilds (encoding / format / wrap toggles) can reach it.
    this._revealFormatButton = (autoLang) => {
      if (!fmtBtn || !autoLang) return;
      if (this._effectiveLang === autoLang) return; // already revealed
      this._effectiveLang = autoLang;
      if (fmtLabel) fmtLabel.style.display = '';
      fmtBtn.style.display = '';
    };

    const textPane = this._buildTextPane(decodedText, bytes, fileName, this._mimeType, formatEnabled, wrapEnabled);
    const hexPane = this._buildHexPane(bytes, fileName);

    // Show the correct one by default
    textPane.style.display = isTextByDefault ? '' : 'none';
    hexPane.style.display = isTextByDefault ? 'none' : '';

    contentArea.appendChild(textPane);
    contentArea.appendChild(hexPane);
    wrap.appendChild(contentArea);

    // ── State tracking ───────────────────────────────────────────────────
    let showingText = isTextByDefault;
    let currentEncoding = detected.encoding;
    let currentText = decodedText;
    let detectedLang = textPane._detectedLang || null;

    // Update initial info text now that we have the detected language
    if (isTextByDefault) {
      this._updateInfoText(infoText, true, bytes, currentEncoding, detectedLang, textPane._lineCount);
    }

    // Store raw decoded text for analysis pipeline (IOC extraction, encoded content detection)
    wrap._rawText = lfNormalize(currentText);
    wrap._rawBytes = bytes;

    // Mutable reference to the current text pane (may be replaced on re-render)
    contentArea._textPane = textPane;

    // Rebuild helper — used by both encoding change and format/wrap toggles
    const rebuildTextPane = () => {
      const oldTextPane = contentArea._textPane;
      const newTextPane = this._buildTextPane(currentText, bytes, fileName, this._mimeType, formatEnabled, wrapEnabled);
      newTextPane.style.display = oldTextPane.style.display;
      contentArea.replaceChild(newTextPane, oldTextPane);
      // Tear down the old VirtualTextView so its rAFs / ResizeObserver
      // / event listeners don't leak across rebuilds (encoding switch,
      // format / wrap toggle).
      if (oldTextPane && oldTextPane._virtualView) {
        try { oldTextPane._virtualView.destroy(); } catch (_) { /* ignore */ }
      }
      contentArea._textPane = newTextPane;
      detectedLang = newTextPane._detectedLang || null;
      this._updateInfoText(infoText, showingText, bytes, currentEncoding, detectedLang, newTextPane._lineCount);
    };

    // ── Toggle handler (text ⇄ hex) ──────────────────────────────────────
    toggleBtn.addEventListener('click', () => {
      showingText = !showingText;
      const currentTextPane = contentArea._textPane;
      currentTextPane.style.display = showingText ? '' : 'none';
      hexPane.style.display = showingText ? 'none' : '';
      toggleBtn.textContent = showingText ? '⬡ Hex' : '🔡 Text';
      toggleBtn.title = showingText ? 'Switch to hex dump view' : 'Switch to plain text view';
      wrap.className = showingText ? 'plaintext-view' : 'hex-view';
      // Show/hide encoding selector + format + wrap toggles (only relevant
      // for text view). `fmtLabel` / `fmtBtn` may be null when formatting is
      // impossible for this file (no language detected, gate failed, etc).
      encLabel.style.display = showingText ? '' : 'none';
      encSelect.style.display = showingText ? '' : 'none';
      if (fmtLabel) fmtLabel.style.display = showingText ? '' : 'none';
      if (fmtBtn) fmtBtn.style.display = showingText ? '' : 'none';
      if (wrapLabel) wrapLabel.style.display = showingText ? '' : 'none';
      if (wrapBtn) wrapBtn.style.display = showingText ? '' : 'none';
      this._updateInfoText(infoText, showingText, bytes, currentEncoding, detectedLang, contentArea._textPane._lineCount);
    });

    // ── Encoding change handler ──────────────────────────────────────────
    encSelect.addEventListener('change', () => {
      currentEncoding = encSelect.value;
      currentText = this._normalizeNewlines(this._decodeAs(bytes, currentEncoding));
      wrap._rawText = lfNormalize(currentText);
      rebuildTextPane();
    });

    // ── Format toggle handler ────────────────────────────────────────────
    // Only wire up the handler when the button was actually rendered —
    // for files where formatting is impossible (no language detected,
    // outside the rich-render gate, or `CodeFormatter` not bundled) the
    // button is omitted from the info bar entirely.
    if (fmtBtn) {
      fmtBtn.addEventListener('click', () => {
        formatEnabled = !formatEnabled;
        PlainTextRenderer._writeFormatPref(formatEnabled);
        fmtBtn.textContent = formatEnabled ? 'On' : 'Off';
        rebuildTextPane();
      });
    }

    // ── Wrap toggle handler ──────────────────────────────────────────────
    // Only wired when the Wrap button was actually rendered (file is
    // small enough). `rebuildTextPane()` already destroys the old
    // `VirtualTextView` so there are no rAF / observer leaks across
    // wrap-mode switches.
    if (wrapBtn) {
      wrapBtn.addEventListener('click', () => {
        wrapEnabled = !wrapEnabled;
        PlainTextRenderer._writeWrapPref(wrapEnabled);
        wrapBtn.textContent = wrapEnabled ? 'On' : 'Off';
        rebuildTextPane();
      });
    }

    return wrap;
  }

  // ── Security analysis ───────────────────────────────────────────────────

  analyzeForSecurity(buffer, fileName) {
    const ext = (fileName || '').split('.').pop().toLowerCase();
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const detected = this._detectEncoding(bytes);

    if (!detected.isText) {
      // For binary files, note that this is an unsupported binary format
      f.externalRefs.push({
        type: IOC.INFO,
        url: `Binary file rendered as hex dump (.${ext})`,
        severity: 'info'
      });
    }

    // Pattern detection is handled entirely by YARA (auto-scan on file load)
    return f;
  }

  // ── Rich-render feasibility ─────────────────────────────────────────────

  /**
   * Shared gate for the "rich rendering" toggles (Highlight + Wrap).
   * Returns true iff the file is small enough on every relevant axis
   * that both toggles can do their work without tanking sidebar-drag
   * FPS or freezing the hljs span-tree pass. When this returns false
   * the info-bar omits *both* toggles entirely so they appear and
   * disappear in lock-step.
   *
   * Three independent thresholds:
   *   1. `RICH_MAX_BYTES` on raw on-disk size (bounds hljs CPU and
   *      total per-row DOM count).
   *   2. `RICH_MAX_LINES` on logical line count (bounds wrap-mode
   *      all-rows-in-DOM cost).
   *   3. `RICH_MAX_LINE_LEN` on the longest single line — the hljs
   *      span tree for one multi-megabyte minified-JS line can freeze
   *      or OOM the tab regardless of total size, and wrap-mode rows
   *      with a 50K-char pre-wrap cell paint catastrophically slowly.
   *
   * `bytes` is the raw decoded buffer (Uint8Array). `text` is the
   * normalised JS string used by both renderers — passing both lets us
   * gate UTF-16 files on their on-disk size while still walking the
   * decoded text for line-count / longest-line.
   */
  _canEnhance(text, bytes) {
    if (bytes.length > PlainTextRenderer.RICH_MAX_BYTES) return false;

    // Single pass: count lines and find longest line simultaneously.
    // Early-exit keeps this O(n) with a very small constant for normal
    // files.
    let lines = 1;
    let runStart = 0;
    const lineLimit = PlainTextRenderer.RICH_MAX_LINE_LEN;
    const maxLines  = PlainTextRenderer.RICH_MAX_LINES;
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 0x0A /* \n */) {
        if (i - runStart > lineLimit) return false;
        runStart = i + 1;
        lines++;
        if (lines > maxLines) return false;
      }
    }
    if (text.length - runStart > lineLimit) return false;
    return true;
  }

  // ── Encoding auto-detection ─────────────────────────────────────────────

  /**
   * Detect the most likely text encoding for the given bytes.
   * Returns { encoding: string, isText: boolean }
   */
  _detectEncoding(bytes) {
    if (bytes.length < 2) return { encoding: 'utf-8', isText: this._isTextContent(bytes, 'utf-8') };

    // Check for BOM markers
    if (bytes[0] === 0xFF && bytes[1] === 0xFE) {
      return { encoding: 'utf-16le', isText: true };
    }
    if (bytes[0] === 0xFE && bytes[1] === 0xFF) {
      return { encoding: 'utf-16be', isText: true };
    }
    if (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) {
      return { encoding: 'utf-8', isText: true };
    }

    // Heuristic: check for UTF-16LE pattern (every other byte is 0x00 for ASCII text)
    if (bytes.length >= 8) {
      const sampleLen = Math.min(64, bytes.length);
      // Must be even length for UTF-16
      if (sampleLen % 2 === 0 || bytes.length % 2 === 0) {
        let nullHighCount = 0;
        let nullLowCount = 0;
        const checkLen = Math.min(sampleLen, bytes.length) & ~1; // ensure even
        for (let i = 0; i < checkLen; i += 2) {
          if (bytes[i + 1] === 0x00 && bytes[i] >= 0x20 && bytes[i] <= 0x7E) nullHighCount++;
          if (bytes[i] === 0x00 && bytes[i + 1] >= 0x20 && bytes[i + 1] <= 0x7E) nullLowCount++;
        }
        const pairs = checkLen / 2;
        if (pairs > 0 && nullHighCount / pairs >= 0.6) {
          return { encoding: 'utf-16le', isText: true };
        }
        if (pairs > 0 && nullLowCount / pairs >= 0.6) {
          return { encoding: 'utf-16be', isText: true };
        }
      }
    }

    // Standard UTF-8 text check
    if (this._isTextContent(bytes, 'utf-8')) {
      return { encoding: 'utf-8', isText: true };
    }

    // Not clearly text — default to UTF-8 but mark as non-text (hex dump default)
    return { encoding: 'utf-8', isText: false };
  }

  // ── Text decoding ───────────────────────────────────────────────────────

  /**
   * Decode bytes using the given encoding.
   * Falls back gracefully to replacement characters on errors.
   */
  _decodeAs(bytes, encoding) {
    try {
      if (encoding === 'latin1') {
        // TextDecoder doesn't always support 'latin1', use 'iso-8859-1'
        return new TextDecoder('iso-8859-1', { fatal: false }).decode(bytes);
      }
      return new TextDecoder(encoding, { fatal: false }).decode(bytes);
    } catch (_) {
      // Ultimate fallback
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    }
  }

  /**
   * Normalise CRLF / CR to LF. Required because `_rawText` is used by the
   * sidebar click-to-focus highlighter which indexes by character offset —
   * CR bytes left in the buffer misalign every offset after the first one.
   */
  _normalizeNewlines(text) {
    return text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  }

  // ── Build text pane (line-numbered view with syntax highlighting) ────────

  /**
   * Resolve the highlight.js language label for this file from extension,
   * MIME type, or extensionless filename patterns. Factored out of
   * `_buildTextPane` so the outer `render()` can decide whether to show
   * the Format button before building the text pane.
   *
   * Returns `null` when no language could be inferred — both the Format
   * button (`render()`) and the formatter call (`_buildTextPane`) treat
   * `null` as "no-op, render as plain text."
   */
  _detectLangForFile(fileName, mimeType) {
    const ext = (fileName || '').split('.').pop().toLowerCase();
    // Try extension first, then fall back to MIME type
    let lang = PlainTextRenderer.LANG_MAP[ext];
    if (!lang && mimeType) {
      lang = PlainTextRenderer.MIME_TO_LANG[mimeType];
    }
    // Extensionless filename matches (Dockerfile / Containerfile /
    // Makefile / Jenkinsfile). Compared case-insensitively against the
    // basename (strip path separators) — tolerates variants like
    // `Dockerfile.build`.
    if (!lang && fileName) {
      const base = String(fileName).split(/[\\/]/).pop().toLowerCase();
      if (base === 'dockerfile' || base === 'containerfile' || base.startsWith('dockerfile.')) {
        lang = 'dockerfile';
      } else if (base === 'makefile' || base === 'gnumakefile') {
        lang = 'makefile';
      }
    }
    return lang || null;
  }

  _buildTextPane(text, bytes, fileName, mimeType, formatEnabled, wrapEnabled) {
    // Resolve the language up-front — drives both the formatter (when
    // enabled) and the hljs highlight call further down. Prefer the
    // cached effective lang (set by a prior auto-detect pass on the
    // same file) over re-running `_detectLangForFile`; that way a
    // Format-toggle rebuild after auto-detect has already succeeded
    // doesn't need a second detection round-trip.
    let lang = (this && this._effectiveLang)
      || this._detectLangForFile(fileName, mimeType);

    // Decide whether rich-mode features (highlight + format) are feasible.
    // Re-evaluated here rather than trusting an outer flag so encoding
    // switches (which can shift line count / longest-line shape) don't
    // let a stale pre-check leak through.
    const richAllowed = this._canEnhance(text, bytes);

    // Optional visual-only formatter pass. Runs BEFORE we split the
    // source into display rows so the formatted text drives the line
    // count, `_lineToFirstRow`, and the hljs span tree. `_rawText` is
    // stamped by the outer `render()` on the wrapper element and still
    // points at the original (unformatted) source — see file header
    // for the offset-drift trade-off this makes.
    //
    // The formatter has its own internal bailouts (input > 2 MiB,
    // output amp > 3×, unmatched brackets, etc.) and returns the input
    // verbatim on any issue, so a failed format pass is indistinguishable
    // from Format-off.
    let displayText = text;
    if (formatEnabled && richAllowed && lang && typeof CodeFormatter !== 'undefined') {
      try {
        const formatted = CodeFormatter.format(text, lang);
        if (typeof formatted === 'string' && formatted.length > 0) {
          displayText = formatted;
        }
      } catch (_) {
        // Any throw → fall back to unformatted display. Formatting is a
        // visual nicety, never a correctness invariant.
        displayText = text;
      }
    }

    const lines = displayText.split('\n');

    // Detect any pathologically long line — common in minified JS, CSS, JSON.
    // Drives `VirtualTextView`'s soft-wrap chunking when wrap is OFF (the
    // virtualised path can't render a single 2 MB <td> in one row). Runs
    // against the DISPLAY text (post-format) because that's what the view
    // actually has to render; formatting strictly shortens longest lines
    // when it runs at all.
    let maxLineLen = 0;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].length > maxLineLen) maxLineLen = lines[i].length;
      if (maxLineLen > PlainTextRenderer.RICH_MAX_LINE_LEN) break;
    }
    const hasLongLine = maxLineLen > PlainTextRenderer.RICH_MAX_LINE_LEN;

    // Syntax highlighting is always on when feasible (no user toggle).
    // Gate on `richAllowed` (same shared rich-render gate the Format /
    // Wrap buttons use) so the hljs span tree can't blow up on a file
    // that already exceeds the rich-mode envelope.
    const shouldHighlight = richAllowed && typeof hljs !== 'undefined';

    let highlightedLines = null;
    let detectedLang = null;

    if (shouldHighlight) {
      try {
        let result;
        if (lang) {
          // Known language — use specific highlighting on the DISPLAY text.
          result = hljs.highlight(displayText, { language: lang, ignoreIllegals: true });
          detectedLang = lang;
        } else {
          // Unknown — try auto-detection.
          result = hljs.highlightAuto(displayText);
          detectedLang = result.language || null;

          // Auto-detect reveal: if hljs returned a formattable language
          // with sufficient relevance, promote it to the effective lang
          // and reveal the Format button (which the outer `render()`
          // left hidden because the fast-path lookup found nothing).
          // `result.relevance` is an hljs-internal heuristic; floor
          // defined by `_AUTO_DETECT_MIN_RELEVANCE`. This is the code
          // path that makes Format work on pasted / extensionless
          // content (e.g. a clipboard.txt paste of a PowerShell
          // snippet). The formatter itself is never invoked here —
          // `formatEnabled` was forced to false by `render()` when
          // the button started hidden, so the user has to click
          // before any formatting work happens.
          const autoRel = (result && typeof result.relevance === 'number')
                            ? result.relevance
                            : 0;
          if (detectedLang
              && autoRel >= PlainTextRenderer._AUTO_DETECT_MIN_RELEVANCE
              && PlainTextRenderer._FORMATTABLE_LANGS.has(detectedLang)) {
            // Cache as the effective lang so a subsequent Format
            // toggle (which triggers a rebuild) uses this lang for
            // the formatter call path.
            if (this && typeof this._revealFormatButton === 'function') {
              try { this._revealFormatButton(detectedLang); } catch (_) { /* non-fatal UI */ }
            } else if (this) {
              this._effectiveLang = detectedLang;
            }
          }
        }
        // Split highlighted HTML by lines
        highlightedLines = result.value.split('\n');
      } catch (_) {
        // Fallback to plain text on error
        highlightedLines = null;
      }
    } else if (lang) {
      // Not highlighting but still advertise the detected language
      detectedLang = lang;
    }

    const maxLines    = PlainTextRenderer.MAX_LINES;
    const count       = Math.min(lines.length, maxLines);
    const chunkSize   = PlainTextRenderer.SOFT_WRAP_CHUNK;
    const gutterDigits = String(Math.max(1, count)).length;

    // Build the virtual viewer. `lines` is sliced to `count` so callers
    // like the highlight pipeline can address every visible logical line
    // (rows beyond MAX_LINES are excluded from `_lineToFirstRow`, matching
    // the legacy table's "… truncated" footer behaviour).
    //
    // Note on `wrap`: when `wrapEnabled` is true `VirtualTextView` switches
    // into all-rows-in-DOM mode and ignores `chunkSize` / `hasLongLine`.
    // The shared rich-render gate (`_canEnhance`) excludes any file with
    // a line longer than `RICH_MAX_LINE_LEN` from both toggles, so when
    // `wrapEnabled` is true `hasLongLine` is guaranteed false and the
    // wrap path never has to soft-wrap chunks.
    //
    // `rawText` passed to the view is the DISPLAY text (post-format), so
    // `_lineToFirstRow` aligns with the rows the user sees. The outer
    // wrapper's `_rawText` (used by sidebar click-to-focus) is the
    // ORIGINAL source — see the note in the formatter branch above.
    const view = new VirtualTextView({
      lines:            count === lines.length ? lines : lines.slice(0, count),
      highlightedLines: highlightedLines || null,
      chunkSize,
      hasLongLine,
      maxLineCount:     count,
      detectedLang,
      lineCount:        lines.length,
      truncationMessage: lines.length > maxLines
        ? `… truncated (${lines.length - maxLines} more lines)`
        : '',
      gutterDigits,
      rawText: displayText,
      wrap:    !!wrapEnabled,
    });

    // The virtualised root *is* the scroll container. Stash the
    // info-bar metadata on it so `_updateInfoText` keeps working without
    // touching the underlying view object.
    const scr = view.rootEl;
    scr._detectedLang = detectedLang;
    scr._lineCount    = lines.length;
    scr._hasLongLine  = hasLongLine;

    return scr;
  }

  // ── Build hex pane ──────────────────────────────────────────────────────

  _buildHexPane(bytes, fileName) {
    const scr = document.createElement('div');
    scr.className = 'plaintext-scroll';

    const pre = document.createElement('pre');
    pre.className = 'hex-dump';

    const maxBytes = 128 * 1024; // 128 KB cap
    const cap = Math.min(bytes.length, maxBytes);
    const lines = [];

    for (let off = 0; off < cap; off += 16) {
      const hex = [];
      const ascii = [];
      for (let j = 0; j < 16; j++) {
        if (off + j < cap) {
          const b = bytes[off + j];
          hex.push(b.toString(16).padStart(2, '0'));
          ascii.push(b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.');
        } else {
          hex.push('  ');
          ascii.push(' ');
        }
      }
      const addr = off.toString(16).padStart(8, '0');
      lines.push(`${addr}  ${hex.slice(0, 8).join(' ')}  ${hex.slice(8).join(' ')}  |${ascii.join('')}|`);
    }
    if (bytes.length > maxBytes) {
      lines.push(`\n… truncated at ${maxBytes.toLocaleString()} bytes (file is ${bytes.length.toLocaleString()} bytes)`);
    }

    pre.textContent = lines.join('\n');
    scr.appendChild(pre);
    return scr;
  }

  // ── Update info text helper ─────────────────────────────────────────────

  _updateInfoText(infoText, showingText, bytes, encoding, detectedLang, cachedLineCount) {
    if (showingText) {
      // Use the cached line count from the current text pane to avoid
      // re-decoding the entire buffer on every toggle / encoding change.
      const lineCount = (typeof cachedLineCount === 'number')
        ? cachedLineCount
        : this._normalizeNewlines(this._decodeAs(bytes, encoding)).split('\n').length;
      const encLabel = PlainTextRenderer.ENCODINGS.find(e => e.value === encoding);
      const encName = encLabel ? encLabel.label : encoding;
      let info = `${lineCount} line${lineCount !== 1 ? 's' : ''}  ·  ${this._fmtBytes(bytes.length)}  ·  ${encName}`;
      if (detectedLang) {
        // Capitalize first letter and prettify language name
        const langDisplay = this._prettifyLangName(detectedLang);
        info += `  ·  ${langDisplay}`;
      }
      infoText.textContent = info;
    } else {
      infoText.textContent = `${this._fmtBytes(bytes.length)}  ·  Binary file  ·  Hex dump view`;
    }
  }

  /** Prettify highlight.js language name for display */
  _prettifyLangName(lang) {
    const nameMap = {
      'javascript': 'JavaScript',
      'typescript': 'TypeScript',
      'powershell': 'PowerShell',
      'vbscript': 'VBScript',
      'vbnet': 'VB.NET',
      'csharp': 'C#',
      'cpp': 'C++',
      'objectivec': 'Objective-C',
      'dos': 'Batch',
      'bash': 'Shell',
      'shell': 'Shell',
      'python': 'Python',
      'python-repl': 'Python REPL',
      'ruby': 'Ruby',
      'perl': 'Perl',
      'php': 'PHP',
      'php-template': 'PHP Template',
      'java': 'Java',
      'kotlin': 'Kotlin',
      'swift': 'Swift',
      'go': 'Go',
      'rust': 'Rust',
      'sql': 'SQL',
      'css': 'CSS',
      'scss': 'SCSS',
      'less': 'Less',
      'xml': 'XML/HTML',
      'json': 'JSON',
      'yaml': 'YAML',
      'ini': 'INI/Config',
      'markdown': 'Markdown',
      'makefile': 'Makefile',
      'lua': 'Lua',
      'r': 'R',
      'graphql': 'GraphQL',
      'wasm': 'WebAssembly',
      'diff': 'Diff',
      'plaintext': 'Plain Text',
      'c': 'C',
      'dockerfile': 'Dockerfile',
      'nginx': 'nginx',
      'apache': 'Apache',
      'x86asm': 'x86 Assembly',
      'properties': 'Properties',
    };
    return nameMap[lang] || (lang.charAt(0).toUpperCase() + lang.slice(1));
  }

  // ── Helpers ─────────────────────────────────────────────────────────────

  /** Heuristic: check if the first 8 KB is mostly printable in the given encoding. */
  _isTextContent(bytes, encoding) {
    if (!encoding || encoding === 'utf-8') {
      const sample = bytes.subarray(0, 8192);
      let printable = 0;
      for (let i = 0; i < sample.length; i++) {
        const b = sample[i];
        // Printable ASCII, common whitespace, or high bytes (UTF-8 continuation)
        if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d || b >= 0x80) {
          printable++;
        }
      }
      return sample.length > 0 && (printable / sample.length) >= 0.90;
    }
    // For other encodings, try decoding and check for control chars
    try {
      const text = this._decodeAs(bytes.subarray(0, 8192), encoding);
      const controlCount = [...text].filter(c => {
        const cp = c.codePointAt(0);
        return cp < 32 && cp !== 9 && cp !== 10 && cp !== 13;
      }).length;
      return text.length > 0 && (controlCount / text.length) < 0.10;
    } catch (_) {
      return false;
    }
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
