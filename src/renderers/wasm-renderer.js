'use strict';
// ════════════════════════════════════════════════════════════════════════════
// wasm-renderer.js — WebAssembly binary module (.wasm) parser and analyser.
//
// WASM is a stack-based virtual ISA whose binary format is small, simple,
// and entirely self-describing — section-tagged, length-prefixed, no
// pointers — which makes it cheap to parse without a vendored library.
//
// We parse:
//
//   • Header (magic 0x00 'asm' + 4-byte LE version)
//   • Section-id sequence (count, sizes, offsets) — useful even when we
//     don't decode the section's payload because section-id distribution
//     is itself a fingerprint (e.g. obfuscated WASM packers tend to pad
//     custom sections aggressively)
//   • Type section — function signatures (param types → result types)
//   • Import section — `(module, field, kind, desc)` tuples. The most
//     important section for triage: imports name every native primitive
//     the module needs the host to provide (memory, JS callbacks, WASI
//     syscalls). A WASM module can do almost nothing on its own — its
//     reach is determined by what it imports.
//   • Memory section — initial / maximum page count (1 page = 64 KiB)
//   • Export section — `(field, kind, idx)` tuples; what the module
//     exposes back to the host
//   • Custom sections — name, producers, sourceMappingURL, dylink, … —
//     surfaced as a table with the section name + size + first-bytes
//     preview
//
// We do NOT decode function bodies (the `code` section) — that's a full
// disassembly job and outside scope. The signature + import / export view
// is what an analyst needs to triage a sample (matches the
// `wasm-objdump --headers --details` triage workflow).
//
// Detection layer:
//
//   • Suspicious-import heuristic — flags imports indicating in-browser
//     keylogging (`addEventListener` capture), clipboard reads, dynamic
//     code generation (`eval`, `Function`, `WebAssembly.compile`), or
//     hashing primitives in volume (cryptominer signature). See
//     SUSPICIOUS_IMPORTS table.
//   • WASI imports — flagged at `medium` because WASI exposes system-call
//     surface (file open, network connect, process spawn) and outside a
//     trusted-runtime context (Wasmtime / Wasmer with capability-based
//     gating) is uncommon in browser-delivered WASM.
//   • Cryptominer signature — `_emscripten_random` + `cryptonight_*` /
//     `argon2_*` / `keccak*` / `scrypt*` exports or imports — high.
//   • Unusually-large initial memory (> 16 MiB) — medium (memory-mining
//     primitive). Maximum-memory > 1 GiB — high.
//   • Module-shape hash (`modulehash`) — Loupe-specific SHA-256 over the
//     normalised import vector ("module|field|kind" sorted, joined by
//     '\n', UTF-8). Independent of code-section perturbations so a
//     repacked-but-functionally-identical sample has the same hash —
//     useful for cluster pivots that file-hash misses.
//
// All numeric reads use little-endian + LEB128 per the WASM spec. We
// guard every read against the byte-length cap and bail to a partial-
// parse result instead of throwing — malformed WASM is a real input
// in the threat-hunting use case.
//
// Depends on: constants.js (IOC, escHtml, escalateRisk, lfNormalize,
//             pushIOC); mitre.js for technique tagging.
// ════════════════════════════════════════════════════════════════════════════

class WasmRenderer {

  // ── Section IDs (WebAssembly Core spec §5.5) ─────────────────────────────
  static SECTION_NAMES = Object.freeze({
    0: 'custom',
    1: 'type',
    2: 'import',
    3: 'function',
    4: 'table',
    5: 'memory',
    6: 'global',
    7: 'export',
    8: 'start',
    9: 'element',
    10: 'code',
    11: 'data',
    12: 'datacount',
    13: 'tag',     // exception-handling proposal
  });

  // ── Import-kind labels ───────────────────────────────────────────────────
  static IMPORT_KINDS = Object.freeze(['function', 'table', 'memory', 'global', 'tag']);

  // ── Suspicious-import heuristic (M2.3) ───────────────────────────────────
  //
  // Maps `module/field` (or just `module`) substrings to a triage signal.
  // Severity floors here: 'medium' is the default; 'high' for capabilities
  // that map directly to attacker primitives; 'critical' for the
  // unmistakable cryptominer / keylogger signature.
  //
  // Each entry returns { severity, technique?, note }. Lookup is
  // case-sensitive and prefix-matched on module + '/' + field so an entry
  // like 'wasi_snapshot_preview1/sock_connect' fires only on that exact
  // import.
  static SUSPICIOUS_IMPORTS = Object.freeze([
    // ── WASI system-call surface ─────────────────────────────────────────
    // The whole `wasi_*` family is medium by default — it's legitimate
    // for server-side / desktop-runtime samples but unusual in a browser
    // delivery channel. Specific syscalls escalate.
    { match: 'wasi_snapshot_preview1/proc_exec',  severity: 'high',
      technique: 'T1059', note: 'WASI proc_exec — process spawn from WASM' },
    { match: 'wasi_snapshot_preview1/sock_open',  severity: 'high',
      technique: 'T1071', note: 'WASI sock_open — outbound network from WASM' },
    { match: 'wasi_snapshot_preview1/sock_connect', severity: 'high',
      technique: 'T1071', note: 'WASI sock_connect — outbound network from WASM' },
    { match: 'wasi_snapshot_preview1/path_open',  severity: 'medium',
      technique: 'T1083', note: 'WASI path_open — filesystem access' },
    { match: 'wasi_snapshot_preview1/fd_write',   severity: 'medium',
      note: 'WASI fd_write — writes via host file descriptors' },
    { match: 'wasi_snapshot_preview1/random_get', severity: 'medium',
      note: 'WASI random_get — entropy source (crypto / nonce / RNG)' },
    { match: 'wasi_unstable',                     severity: 'medium',
      note: 'WASI (legacy unstable) — system-call surface' },
    { match: 'wasi_snapshot_preview1',            severity: 'medium',
      note: 'WASI — system-call surface' },

    // ── In-browser-attacker primitives via JS bridge ─────────────────────
    // These are usually wired up by an Emscripten / wasm-bindgen glue
    // that exposes raw JS-side capabilities to the WASM module.
    { match: 'env/eval',                  severity: 'critical',
      technique: 'T1059.007', note: 'env.eval — direct host-side eval bridge (T1059.007)' },
    { match: 'env/Function',              severity: 'critical',
      technique: 'T1027', note: 'env.Function — host-side Function constructor (dynamic code)' },
    { match: 'env/exec',                  severity: 'high',
      technique: 'T1059', note: 'env.exec — host-side command execution bridge' },
    { match: 'env/spawn',                 severity: 'high',
      technique: 'T1059', note: 'env.spawn — host-side process spawn bridge' },
    { match: 'env/system',                severity: 'high',
      technique: 'T1059', note: 'env.system — host-side shell bridge' },
    { match: 'env/document_addEventListener', severity: 'high',
      technique: 'T1056.001', note: 'event-listener bridge — keylogger primitive' },
    { match: 'env/document_querySelector',    severity: 'medium',
      note: 'DOM-query bridge — page-content scraping primitive' },
    { match: 'env/clipboard',             severity: 'high',
      technique: 'T1115', note: 'clipboard bridge — credential / 2FA token exfil' },
    { match: 'env/fetch',                 severity: 'high',
      technique: 'T1071.001', note: 'fetch bridge — outbound HTTP from WASM' },
    { match: 'env/XMLHttpRequest',        severity: 'high',
      technique: 'T1071.001', note: 'XHR bridge — outbound HTTP from WASM' },
    { match: 'env/WebSocket',             severity: 'high',
      technique: 'T1071.001', note: 'WebSocket bridge — outbound C2 channel from WASM' },

    // ── Wasm-bindgen / Emscripten dynamic-loader hooks ───────────────────
    { match: 'env/__wbindgen_eval',       severity: 'critical',
      technique: 'T1059.007', note: 'wasm-bindgen eval — runtime JS construction' },
    { match: 'env/emscripten_run_script', severity: 'critical',
      technique: 'T1059.007', note: 'emscripten_run_script — runtime JS exec' },
    { match: 'env/emscripten_asm_const',  severity: 'medium',
      note: 'emscripten EM_ASM — inline JS bridge (low-grade dynamic exec)' },

    // ── Cryptominer signatures ──────────────────────────────────────────
    // The strings below ride alongside the `cryptonight_*` / `argon2*` /
    // `keccak*` / `_emscripten_random` import bundle to catch in-browser
    // miners (Coinhive, CryptoNight web wrappers, Monero browser-mining
    // forks).
    { match: 'env/cryptonight',           severity: 'critical',
      technique: 'T1496', note: 'CryptoNight import — in-browser cryptominer (T1496)' },
    { match: 'env/argon2',                severity: 'high',
      technique: 'T1496', note: 'Argon2 KDF import — likely cryptominer (T1496)' },
    { match: 'env/keccak',                severity: 'medium',
      note: 'Keccak hash import — common cryptominer primitive' },
    { match: 'env/scrypt',                severity: 'high',
      technique: 'T1496', note: 'scrypt KDF import — likely cryptominer (T1496)' },
  ]);

  // ── Suspicious export-name signatures ────────────────────────────────────
  static SUSPICIOUS_EXPORTS = Object.freeze([
    { match: /^cryptonight_/,             severity: 'critical',
      technique: 'T1496', note: 'CryptoNight export — in-browser cryptominer (T1496)' },
    { match: /^argon2_/,                  severity: 'high',
      technique: 'T1496', note: 'Argon2 export — likely cryptominer (T1496)' },
    { match: /^keylogger/i,               severity: 'critical',
      technique: 'T1056.001', note: 'keylogger export — credential capture primitive' },
    { match: /^stealer/i,                 severity: 'critical',
      technique: 'T1555', note: 'stealer export — credential exfil primitive' },
  ]);

  // ── Limits ────────────────────────────────────────────────────────────────
  static MAX_SECTIONS         = 256;     // hard cap on sections to enumerate
  static MAX_IMPORTS          = 4096;    // hard cap on import entries
  static MAX_EXPORTS          = 4096;    // hard cap on export entries
  static MAX_TYPES            = 4096;    // hard cap on signatures
  static CUSTOM_NAME_PREVIEW  = 64;      // bytes of custom-section preview
  static MEMORY_LARGE_INITIAL = 256;     // 256 pages = 16 MiB initial
  static MEMORY_HUGE_MAX      = 16384;   // 16 384 pages = 1 GiB maximum

  // ════════════════════════════════════════════════════════════════════════
  // Render
  // ════════════════════════════════════════════════════════════════════════

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const parsed = WasmRenderer._parse(bytes);

    const wrap = document.createElement('div');
    wrap.className = 'wasm-view';

    // ── Banner ──────────────────────────────────────────────────────────
    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    const strong = document.createElement('strong');
    strong.textContent = '⚠ WebAssembly Module (.wasm)';
    banner.appendChild(strong);
    banner.appendChild(document.createTextNode(
      ' — Stack-based virtual ISA. Reach is determined entirely by what the ' +
      'module imports from the host (memory, JS callbacks, WASI syscalls); ' +
      'review the Imports table below for capability-bearing names.'
    ));
    wrap.appendChild(banner);

    // ── Summary line ───────────────────────────────────────────────────
    const info = document.createElement('div');
    info.className = 'plaintext-info';
    if (parsed.error) {
      info.textContent = `${parsed.error}  ·  ${this._fmtBytes(bytes.length)}`;
    } else {
      const v = parsed.version;
      info.textContent =
        `WASM v${v}  ·  ${parsed.sections.length} section(s)  ·  ` +
        `${parsed.imports.length} import(s)  ·  ${parsed.exports.length} export(s)  ·  ` +
        `${parsed.types.length} signature(s)  ·  ${this._fmtBytes(bytes.length)}`;
    }
    wrap.appendChild(info);

    // ── Header card ────────────────────────────────────────────────────
    const headerCard = document.createElement('div');
    headerCard.className = 'wasm-card';
    const hh = document.createElement('h4');
    hh.textContent = 'Header';
    headerCard.appendChild(hh);
    const ht = document.createElement('table');
    ht.className = 'meta-table';
    const addRow = (tbody, k, v) => {
      const tr = document.createElement('tr');
      const tk = document.createElement('td'); tk.textContent = k;
      const tv = document.createElement('td'); tv.textContent = v;
      tr.appendChild(tk); tr.appendChild(tv); tbody.appendChild(tr);
    };
    const htBody = document.createElement('tbody');
    addRow(htBody, 'Magic', '\\0asm (0x00 0x61 0x73 0x6d)');
    addRow(htBody, 'Version', String(parsed.version || '?'));
    // `_modulehash` is set by analyzeForSecurity(), which app-load.js
    // dispatches before render(). For direct render-only callers (e.g.
    // tests, or an integration that skips the analyser) we show the
    // short-form "—" rather than blocking on a synchronous hash here.
    addRow(htBody, 'Module hash (modulehash)',
      (this._modulehash || parsed.modulehash) || '—');
    ht.appendChild(htBody);
    headerCard.appendChild(ht);
    wrap.appendChild(headerCard);

    // ── Sections card ──────────────────────────────────────────────────
    if (parsed.sections.length) {
      wrap.appendChild(this._sectionsCard(parsed));
    }

    // ── Imports card ───────────────────────────────────────────────────
    if (parsed.imports.length) {
      wrap.appendChild(this._importsCard(parsed));
    }

    // ── Memory card ────────────────────────────────────────────────────
    if (parsed.memory) {
      wrap.appendChild(this._memoryCard(parsed.memory));
    }

    // ── Exports card ───────────────────────────────────────────────────
    if (parsed.exports.length) {
      wrap.appendChild(this._exportsCard(parsed));
    }

    // ── Custom-sections card ───────────────────────────────────────────
    if (parsed.customSections.length) {
      wrap.appendChild(this._customCard(parsed));
    }

    wrap._rawText = lfNormalize(WasmRenderer._renderTextDigest(parsed));
    return wrap;
  }

  _sectionsCard(parsed) {
    const card = document.createElement('div');
    card.className = 'wasm-card';
    const h = document.createElement('h4');
    h.textContent = `Sections (${parsed.sections.length})`;
    card.appendChild(h);
    const tbl = document.createElement('table');
    tbl.className = 'wasm-table';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>#</th><th>ID</th><th>Name</th><th>Size</th><th>Offset</th></tr>';
    tbl.appendChild(thead);
    const tbody = document.createElement('tbody');
    parsed.sections.forEach((s, i) => {
      const tr = document.createElement('tr');
      const cells = [
        String(i),
        String(s.id),
        WasmRenderer.SECTION_NAMES[s.id] || `(unknown ${s.id})`,
        this._fmtBytes(s.size),
        '0x' + s.offset.toString(16),
      ];
      for (const c of cells) {
        const td = document.createElement('td');
        td.textContent = c;
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    card.appendChild(tbl);
    return card;
  }

  _importsCard(parsed) {
    const card = document.createElement('div');
    card.className = 'wasm-card';
    const h = document.createElement('h4');
    h.textContent = `Imports (${parsed.imports.length})`;
    card.appendChild(h);
    const tbl = document.createElement('table');
    tbl.className = 'wasm-table';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>#</th><th>Module</th><th>Field</th><th>Kind</th><th>Desc</th></tr>';
    tbl.appendChild(thead);
    const tbody = document.createElement('tbody');
    parsed.imports.forEach((imp, i) => {
      const tr = document.createElement('tr');
      const cells = [String(i), imp.module, imp.field, imp.kindName, imp.desc || ''];
      for (const c of cells) {
        const td = document.createElement('td');
        td.textContent = c;
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    card.appendChild(tbl);
    return card;
  }

  _exportsCard(parsed) {
    const card = document.createElement('div');
    card.className = 'wasm-card';
    const h = document.createElement('h4');
    h.textContent = `Exports (${parsed.exports.length})`;
    card.appendChild(h);
    const tbl = document.createElement('table');
    tbl.className = 'wasm-table';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>#</th><th>Name</th><th>Kind</th><th>Index</th></tr>';
    tbl.appendChild(thead);
    const tbody = document.createElement('tbody');
    parsed.exports.forEach((exp, i) => {
      const tr = document.createElement('tr');
      const cells = [String(i), exp.name, exp.kindName, String(exp.index)];
      for (const c of cells) {
        const td = document.createElement('td');
        td.textContent = c;
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    card.appendChild(tbl);
    return card;
  }

  _memoryCard(mem) {
    const card = document.createElement('div');
    card.className = 'wasm-card';
    const h = document.createElement('h4');
    h.textContent = 'Memory';
    card.appendChild(h);
    const tbl = document.createElement('table');
    tbl.className = 'meta-table';
    const tbody = document.createElement('tbody');
    const PAGE = 65536;
    const initialBytes = mem.initial * PAGE;
    const r = (k, v) => {
      const tr = document.createElement('tr');
      const tk = document.createElement('td'); tk.textContent = k;
      const tv = document.createElement('td'); tv.textContent = v;
      tr.appendChild(tk); tr.appendChild(tv); tbody.appendChild(tr);
    };
    r('Initial pages', `${mem.initial}  (${this._fmtBytes(initialBytes)})`);
    if (mem.maximum != null) {
      r('Maximum pages', `${mem.maximum}  (${this._fmtBytes(mem.maximum * PAGE)})`);
    } else {
      r('Maximum pages', '(unbounded)');
    }
    if (mem.shared) r('Shared', 'true (SharedArrayBuffer)');
    tbl.appendChild(tbody);
    card.appendChild(tbl);
    return card;
  }

  _customCard(parsed) {
    const card = document.createElement('div');
    card.className = 'wasm-card';
    const h = document.createElement('h4');
    h.textContent = `Custom Sections (${parsed.customSections.length})`;
    card.appendChild(h);
    const tbl = document.createElement('table');
    tbl.className = 'wasm-table';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th>#</th><th>Name</th><th>Size</th><th>Offset</th><th>Preview</th></tr>';
    tbl.appendChild(thead);
    const tbody = document.createElement('tbody');
    parsed.customSections.forEach((c, i) => {
      const tr = document.createElement('tr');
      const cells = [String(i), c.name, this._fmtBytes(c.size), '0x' + c.offset.toString(16), c.preview];
      for (const v of cells) {
        const td = document.createElement('td');
        td.textContent = v;
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    card.appendChild(tbl);
    return card;
  }

  // ════════════════════════════════════════════════════════════════════════
  // analyzeForSecurity
  // ════════════════════════════════════════════════════════════════════════

  async analyzeForSecurity(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const parsed = WasmRenderer._parse(bytes);
    const f = {
      risk: 'low',
      externalRefs: [],
      detections: [],
      capabilities: [],
      interestingStrings: [],
    };

    if (parsed.error) {
      pushIOC(f, {
        type: IOC.INFO,
        value: `WASM parse error: ${parsed.error}`,
        severity: 'info',
        bucket: 'externalRefs',
      });
      return f;
    }

    // ── Module-shape hash (modulehash) ───────────────────────────────────
    // Cached on the renderer instance so `render()` can read it back
    // (it re-parses the buffer and so loses the in-flight `parsed`
    // local). app-load.js dispatches `analyzeForSecurity` before
    // `render` on the same instance.
    parsed.modulehash = await WasmRenderer._modulehash(parsed.imports);
    this._modulehash = parsed.modulehash;
    // Stash full parsed-module shape on the findings object so
    // `_copyAnalysisWasm` (in app-copy-analysis.js) can render the
    // header/sections/imports/exports tables without re-parsing.
    // Mirrors the `findings.peInfo` / `findings.elfInfo` /
    // `findings.machoInfo` pattern.
    f.wasmInfo = parsed;
    pushIOC(f, {
      type: IOC.HASH,
      value: parsed.modulehash,
      severity: 'info',
      note: 'modulehash — SHA-256 over normalised import vector (cluster pivot)',
      bucket: 'externalRefs',
    });

    // ── Suspicious-import scan ───────────────────────────────────────────
    const seenTechniques = new Set();
    for (const imp of parsed.imports) {
      const path = `${imp.module}/${imp.field}`;
      const hit = WasmRenderer.SUSPICIOUS_IMPORTS.find(
        (h) => path === h.match || path.startsWith(h.match + '/') || imp.module === h.match
      );
      if (!hit) continue;
      pushIOC(f, {
        type: IOC.PATTERN,
        url: `${path} — ${hit.note}`,
        severity: hit.severity,
        _highlightText: imp.field,
      bucket: 'externalRefs' });
      if (hit.technique && !seenTechniques.has(hit.technique)) {
        seenTechniques.add(hit.technique);
        f.capabilities.push({ id: hit.technique, source: 'wasm-import' });
      }
      if (hit.severity === 'critical') escalateRisk(f, 'critical');
      else if (hit.severity === 'high') escalateRisk(f, 'high');
      else if (hit.severity === 'medium' && f.risk === 'low') escalateRisk(f, 'medium');
    }

    // ── Suspicious-export scan ───────────────────────────────────────────
    for (const exp of parsed.exports) {
      const hit = WasmRenderer.SUSPICIOUS_EXPORTS.find((h) => h.match.test(exp.name));
      if (!hit) continue;
      pushIOC(f, {
        type: IOC.PATTERN,
        url: `export ${exp.name} — ${hit.note}`,
        severity: hit.severity,
        _highlightText: exp.name,
      bucket: 'externalRefs' });
      if (hit.technique && !seenTechniques.has(hit.technique)) {
        seenTechniques.add(hit.technique);
        f.capabilities.push({ id: hit.technique, source: 'wasm-export' });
      }
      if (hit.severity === 'critical') escalateRisk(f, 'critical');
      else if (hit.severity === 'high') escalateRisk(f, 'high');
    }

    // ── Memory anomalies ─────────────────────────────────────────────────
    if (parsed.memory) {
      if (parsed.memory.initial >= WasmRenderer.MEMORY_LARGE_INITIAL) {
        pushIOC(f, {
          type: IOC.PATTERN,
          url: `Large initial memory — ${parsed.memory.initial} pages (${this._fmtBytes(parsed.memory.initial * 65536)}) — possible memory-mining or buffer-allocation attack primitive`,
          severity: 'medium',
        bucket: 'externalRefs' });
        if (f.risk === 'low') escalateRisk(f, 'medium');
      }
      if (parsed.memory.maximum != null && parsed.memory.maximum >= WasmRenderer.MEMORY_HUGE_MAX) {
        pushIOC(f, {
          type: IOC.PATTERN,
          url: `Huge maximum memory — ${parsed.memory.maximum} pages (≥ 1 GiB) — DoS / memory-exhaustion primitive`,
          severity: 'high',
        bucket: 'externalRefs' });
        escalateRisk(f, 'high');
      }
    }

    // ── Custom-section sourceMappingURL — points at original .wat / .c ───
    for (const cs of parsed.customSections) {
      if (cs.name === 'sourceMappingURL' && cs.urlPreview) {
        pushIOC(f, {
          type: IOC.URL,
          value: cs.urlPreview,
          severity: 'info',
          note: 'WASM sourceMappingURL — original-source map reference',
        });
      }
    }

    // The `producers` custom section is not a security signal on its
    // own; if present it shows up generically in the Custom Sections
    // card alongside any other custom name. No separate IOC emission.

    return f;
  }

  // ════════════════════════════════════════════════════════════════════════
  // Parser (static — pure function over bytes)
  // ════════════════════════════════════════════════════════════════════════

  static _parse(bytes) {
    const out = {
      version: 0,
      sections: [],
      types: [],
      imports: [],
      exports: [],
      memory: null,
      customSections: [],
      modulehash: null,
      error: null,
    };

    if (bytes.length < 8) {
      out.error = 'Buffer too small to be a WASM module';
      return out;
    }
    if (bytes[0] !== 0x00 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) {
      out.error = 'Bad magic — not a WASM binary';
      return out;
    }

    // Version — 4 bytes LE.
    out.version = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24);

    let p = 8;
    let sectionCount = 0;

    while (p < bytes.length) {
      if (sectionCount++ >= WasmRenderer.MAX_SECTIONS) {
        out.error = `Section cap reached (${WasmRenderer.MAX_SECTIONS}) — partial parse`;
        break;
      }
      const id = bytes[p++];
      const sizeRead = WasmRenderer._readU32(bytes, p);
      if (!sizeRead) { out.error = 'Truncated section size'; break; }
      const size = sizeRead.value;
      p = sizeRead.next;
      if (p + size > bytes.length) {
        out.error = 'Truncated section payload';
        break;
      }
      const section = { id, size, offset: p };
      out.sections.push(section);
      const end = p + size;
      try {
        if (id === 0) {
          // Custom section: name-len LEB128, name bytes, then opaque.
          const cs = WasmRenderer._parseCustom(bytes, p, end);
          out.customSections.push(cs);
        } else if (id === 1) {
          out.types = WasmRenderer._parseTypes(bytes, p, end);
        } else if (id === 2) {
          out.imports = WasmRenderer._parseImports(bytes, p, end);
        } else if (id === 5) {
          out.memory = WasmRenderer._parseMemory(bytes, p, end);
        } else if (id === 7) {
          out.exports = WasmRenderer._parseExports(bytes, p, end);
        }
      } catch (e) {
        // Don't bail — record and keep walking.
        out.error = `Section ${id} parse error: ${e.message || e}`;
      }
      p = end;
    }

    return out;
  }

  // ── LEB128 helpers ─────────────────────────────────────────────────────

  /** Read unsigned LEB128 → { value, next } or null on truncation/overflow. */
  static _readU32(bytes, offset) {
    let value = 0, shift = 0, i = offset;
    while (i < bytes.length) {
      const b = bytes[i++];
      value |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) {
        // 5 LEB128 bytes max for u32; cap shift defensively.
        if (shift > 28) return null;
        return { value: value >>> 0, next: i };
      }
      shift += 7;
      if (shift >= 35) return null;
    }
    return null;
  }

  /** Read length-prefixed UTF-8 string → { value, next } or null. */
  static _readName(bytes, offset, end) {
    const lenRead = WasmRenderer._readU32(bytes, offset);
    if (!lenRead) return null;
    const len = lenRead.value;
    const start = lenRead.next;
    if (start + len > end) return null;
    const name = new TextDecoder('utf-8', { fatal: false })
      .decode(bytes.subarray(start, start + len));
    return { value: name, next: start + len };
  }

  // ── Section-payload parsers ────────────────────────────────────────────

  static _parseCustom(bytes, p, end) {
    const out = { name: '(invalid)', size: end - p, offset: p, preview: '', urlPreview: null };
    const nameRead = WasmRenderer._readName(bytes, p, end);
    if (!nameRead) return out;
    out.name = nameRead.value;
    const bodyStart = nameRead.next;
    const bodyLen = end - bodyStart;
    out.size = bodyLen;
    // Preview: first N bytes as UTF-8 (or hex if non-printable).
    const previewLen = Math.min(WasmRenderer.CUSTOM_NAME_PREVIEW, bodyLen);
    const previewBytes = bytes.subarray(bodyStart, bodyStart + previewLen);
    let printable = true;
    for (const b of previewBytes) {
      if (b < 0x09 || (b > 0x0d && b < 0x20) || b > 0x7e) { printable = false; break; }
    }
    out.preview = printable
      ? new TextDecoder('utf-8', { fatal: false }).decode(previewBytes)
      : Array.from(previewBytes).slice(0, 16).map((b) => b.toString(16).padStart(2, '0')).join(' ') + (previewLen > 16 ? '…' : '');
    // sourceMappingURL: payload is itself a length-prefixed UTF-8 string.
    if (out.name === 'sourceMappingURL') {
      const urlRead = WasmRenderer._readName(bytes, bodyStart, end);
      if (urlRead) out.urlPreview = urlRead.value;
    }
    return out;
  }

  static _parseTypes(bytes, p, end) {
    const out = [];
    const countRead = WasmRenderer._readU32(bytes, p);
    if (!countRead) return out;
    let i = countRead.next;
    const count = Math.min(countRead.value, WasmRenderer.MAX_TYPES);
    for (let n = 0; n < count && i < end; n++) {
      // form byte (0x60 for func), then params vec, then results vec.
      const form = bytes[i++];
      const ptype = form === 0x60 ? 'func' : `0x${form.toString(16)}`;
      const pCount = WasmRenderer._readU32(bytes, i);
      if (!pCount) break;
      i = pCount.next;
      const params = [];
      for (let pi = 0; pi < pCount.value && i < end; pi++) {
        params.push(bytes[i++]);
      }
      const rCount = WasmRenderer._readU32(bytes, i);
      if (!rCount) break;
      i = rCount.next;
      const results = [];
      for (let ri = 0; ri < rCount.value && i < end; ri++) {
        results.push(bytes[i++]);
      }
      out.push({ form: ptype, params, results });
    }
    return out;
  }

  static _parseImports(bytes, p, end) {
    const out = [];
    const countRead = WasmRenderer._readU32(bytes, p);
    if (!countRead) return out;
    let i = countRead.next;
    const count = Math.min(countRead.value, WasmRenderer.MAX_IMPORTS);
    for (let n = 0; n < count && i < end; n++) {
      const modRead = WasmRenderer._readName(bytes, i, end);
      if (!modRead) break;
      i = modRead.next;
      const fldRead = WasmRenderer._readName(bytes, i, end);
      if (!fldRead) break;
      i = fldRead.next;
      const kind = bytes[i++];
      const kindName = WasmRenderer.IMPORT_KINDS[kind] || `(unknown ${kind})`;
      let desc = '';
      if (kind === 0) {
        // function: typeidx
        const idxRead = WasmRenderer._readU32(bytes, i);
        if (!idxRead) break;
        i = idxRead.next;
        desc = `type[${idxRead.value}]`;
      } else if (kind === 1) {
        // table: elemtype + limits
        const elem = bytes[i++];
        const flag = bytes[i++];
        const min = WasmRenderer._readU32(bytes, i);
        if (!min) break;
        i = min.next;
        let max = null;
        if (flag & 1) {
          const m = WasmRenderer._readU32(bytes, i);
          if (!m) break;
          i = m.next;
          max = m.value;
        }
        desc = `elem 0x${elem.toString(16)} min=${min.value}` + (max != null ? ` max=${max}` : '');
      } else if (kind === 2) {
        // memory: limits
        const flag = bytes[i++];
        const min = WasmRenderer._readU32(bytes, i);
        if (!min) break;
        i = min.next;
        let max = null;
        if (flag & 1) {
          const m = WasmRenderer._readU32(bytes, i);
          if (!m) break;
          i = m.next;
          max = m.value;
        }
        desc = `min=${min.value}` + (max != null ? ` max=${max}` : '') + (flag & 2 ? ' shared' : '');
      } else if (kind === 3) {
        // global: type + mut
        const t = bytes[i++];
        const mut = bytes[i++];
        desc = `type 0x${t.toString(16)}` + (mut ? ' mut' : '');
      } else {
        // unknown — skip gracefully by bailing
        break;
      }
      out.push({ module: modRead.value, field: fldRead.value, kind, kindName, desc });
    }
    return out;
  }

  static _parseExports(bytes, p, end) {
    const out = [];
    const countRead = WasmRenderer._readU32(bytes, p);
    if (!countRead) return out;
    let i = countRead.next;
    const count = Math.min(countRead.value, WasmRenderer.MAX_EXPORTS);
    for (let n = 0; n < count && i < end; n++) {
      const nameRead = WasmRenderer._readName(bytes, i, end);
      if (!nameRead) break;
      i = nameRead.next;
      const kind = bytes[i++];
      const idxRead = WasmRenderer._readU32(bytes, i);
      if (!idxRead) break;
      i = idxRead.next;
      out.push({
        name: nameRead.value,
        kind,
        kindName: WasmRenderer.IMPORT_KINDS[kind] || `(unknown ${kind})`,
        index: idxRead.value,
      });
    }
    return out;
  }

  static _parseMemory(bytes, p, end) {
    // memory section is `vec(memtype)`. We surface the first entry.
    const countRead = WasmRenderer._readU32(bytes, p);
    if (!countRead || countRead.value === 0) return null;
    let i = countRead.next;
    const flag = bytes[i++];
    const min = WasmRenderer._readU32(bytes, i);
    if (!min) return null;
    i = min.next;
    let max = null;
    if (flag & 1) {
      const m = WasmRenderer._readU32(bytes, i);
      if (m) { max = m.value; i = m.next; }
    }
    return { initial: min.value, maximum: max, shared: !!(flag & 2) };
  }

  // ── modulehash (M2.4) ──────────────────────────────────────────────────
  //
  // SHA-256 of the normalised import vector — sorted "module|field|kind"
  // lines joined by '\n', UTF-8 encoded. Independent of code-section
  // perturbations: a sample that's been re-emitted by a different toolchain
  // (Emscripten vs wasm-pack) but expects the same host capabilities will
  // get the same modulehash, so analysts can pivot on shape.
  //
  // Returns a 64-char lowercase hex string. Async because crypto.subtle.
  static async _modulehash(imports) {
    if (!imports.length) return '0'.repeat(64); // empty-import marker
    const lines = imports
      .map((imp) => `${imp.module}|${imp.field}|${imp.kindName}`)
      .sort();
    const data = new TextEncoder().encode(lines.join('\n'));
    const buf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  // ── Text digest for sidebar focus ──────────────────────────────────────
  static _renderTextDigest(parsed) {
    const lines = [];
    lines.push(`WASM v${parsed.version}`);
    lines.push(`Sections: ${parsed.sections.length}`);
    if (parsed.modulehash) lines.push(`modulehash: ${parsed.modulehash}`);
    if (parsed.imports.length) {
      lines.push('--- Imports ---');
      for (const imp of parsed.imports) {
        lines.push(`  ${imp.module}.${imp.field}  (${imp.kindName})  ${imp.desc}`);
      }
    }
    if (parsed.exports.length) {
      lines.push('--- Exports ---');
      for (const exp of parsed.exports) {
        lines.push(`  ${exp.name}  (${exp.kindName})  → ${exp.index}`);
      }
    }
    if (parsed.memory) {
      lines.push(`--- Memory --- initial=${parsed.memory.initial} max=${parsed.memory.maximum ?? '∞'}`);
    }
    if (parsed.customSections.length) {
      lines.push('--- Custom Sections ---');
      for (const cs of parsed.customSections) {
        lines.push(`  ${cs.name}  (${cs.size} bytes)`);
      }
    }
    return lfNormalize(lines.join('\n'));
  }

  _fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
}
