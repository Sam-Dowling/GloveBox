'use strict';
// ════════════════════════════════════════════════════════════════════════════
// npm-renderer.js — npm package (.tgz / package.json / lockfile) analyser
//
// Accepts three input shapes, sniffed internally — callers always dispatch
// via `RendererRegistry.detect()` so a renamed file still lands here:
//
//   1. npm pack tarball  — gzip-wrapped POSIX TAR whose first entry is
//      `package/<something>` and which contains `package/package.json`.
//      Tarball is inflated via Decompressor.inflate('gzip'), walked with
//      an inline TAR parser, and every inner file is exposed through the
//      shared ArchiveTree component (click-to-drill-down).
//   2. Bare package.json — a plain JSON manifest with `name` + one of
//      (`version` / `scripts` / `dependencies` / `main` / `bin`). A
//      random JSON blob never gets hijacked because the
//      `extDisambiguator` in the registry insists on the npm shape.
//   3. Bare package-lock.json / npm-shrinkwrap.json — lockfile listing
//      with dependency fanout + integrity hashes.
//
// Surfaces:
//   • Identity block (name, version, license, engines, author, repo…)
//   • Lifecycle-hook table (preinstall / install / postinstall / prepare /
//     prepublish / prepublishOnly / prepack / postpack / preuninstall /
//     postuninstall) with per-hook severity from command-content pattern
//     matching.
//   • Entry points (main / module / exports / bin / man / browser).
//   • Dependencies — deps / devDeps / peer / optional / bundled, with
//     per-entry typosquat flagging.
//   • File tree (for tarballs) with click-to-drill-down via
//     `open-inner-file` events.
//   • Raw manifest viewer (collapsible, clickable-IOC target).
//
// Depends on: constants.js (IOC, escHtml, pushIOC, mirrorMetadataIOCs,
//             sanitizeUrl, PARSER_LIMITS), Decompressor (gzip),
//             ArchiveTree (file browser). All globals assumed loaded first
//             via the JS_FILES order in scripts/build.py.
// ════════════════════════════════════════════════════════════════════════════

class NpmRenderer {

  // ── Lifecycle hook names (npm docs: "scripts" field). Order is semantic —
  //    execution-time order is how these ship, so we table them this way.
  static LIFECYCLE_HOOKS = [
    'preinstall', 'install', 'postinstall',
    'prepublish', 'prepublishOnly', 'prepack', 'postpack',
    'prepare', 'preuninstall', 'postuninstall',
  ];

  // ── Commands that are effectively "download and run". A hook whose body
  //    matches any of these patterns gets escalated to critical severity.
  //    Case-insensitive. Expanded from common supply-chain-malware reports.
  static CRITICAL_CMD_RE = /(?:\bcurl\s+[^|&;]*(?:https?:|\|)|\bwget\s+[^|&;]*https?:|\bnode\s+-e\b|\beval\s*\(|\bnew\s+Function\s*\(|\bbash\s+-c\b|\bsh\s+-c\b|\bpowershell\s|\bpwsh\s|\binvoke-expression\b|\biex\s*\(|\biwr\s+|\binvoke-webrequest\b|\bbase64\s+-d\b|\batob\s*\(|\bchild_process\b|\bspawn\s*\(|\bexec\s*\(|\brequire\s*\(\s*['"]child_process|\bBuffer\.from\s*\([^)]*['"]base64)/i;

  // Commands that *download* / *write* something but aren't yet eval. Still
  // worth flagging as high — supply-chain droppers often stage first, eval
  // second.
  static HIGH_CMD_RE = /(?:\bcurl\b|\bwget\b|\bfetch\b|\bhttps?:\/\/|\bnpm\s+install\s+https?|\bgit\s+clone\b|\bpip\s+install\b|\bwget\s|\bdownload\b|\bwriteFile\b|\bwriteFileSync\b|\bchmod\s+\+x)/i;

  // "Benign-ish" — presence of *any* hook bumps risk at least to medium
  // because hook-scripts run with the user's shell on `npm install`, and
  // the burden of proof shifts to the reviewer.
  static BENIGN_CMD_RE = /^(?:echo\s|true\s*$|exit\s+0|:)/i;

  // Bundled binary artefacts — a published npm package shipping pre-built
  // native code raises the bar on "what actually runs".
  static NATIVE_ARTEFACT_RE = /\.(node|so|dylib|a|exe|wasm)$/i;

  // Known typosquat-of-popular list. Intentionally narrow — YARA does the
  // pattern work; this is just the short-list that renderers flag inline.
  // Entries are LOWERCASE, exact match against the resolved dependency
  // name (case-insensitively via toLowerCase()).
  static TYPOSQUATS = new Set([
    // colors & friends
    'colrs', 'colorss', 'colours', 'colorsjs', 'colored',
    // lodash
    'lodahs', 'lowdash', 'lodashs', 'loadsh',
    // react
    'reakt', 'reactjs', 'reactt', 'reacct',
    // chalk
    'chalks', 'chlk', 'chalck',
    // express
    'expres', 'expresss', 'expressjs',
    // commander
    'commnder', 'comander', 'comannder',
    // jsonwebtoken
    'jsonwebtokens', 'jwttoken', 'jwtoken',
    // cross-env
    'cross-evn', 'crossenv',
    // debug
    'debuge', 'debugg',
    // axios
    'axois', 'axsios', 'axiosss',
    // discord.js
    'discordjs', 'discord-js', 'discord_js',
    // dotenv
    'dotnev', 'dotennv', 'dotenvv',
    // request
    'requestt', 'request-core',
  ]);

  // Registries that aren't the official npm registry. Any "resolved" URL
  // in a lockfile or explicit `registry` / `publishConfig.registry` that
  // doesn't match these gets flagged.
  static OFFICIAL_REGISTRY_RE = /^https:\/\/(?:registry\.npmjs\.org|registry\.yarnpkg\.com|registry\.npmmirror\.com)\b/i;

  // Known webhook / exfil surfaces frequently used by npm dropper bundles.
  // Kept in sync with the YARA `Npm_Webhook_Beacon_Site` rule.
  static EXFIL_HOST_RE = /\b(?:webhook\.site|pipedream\.net|requestbin\.com|requestbin\.net|ngrok\.io|ngrok-free\.app|trycloudflare\.com|discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com\/services|oast\.(?:fun|live|pro|me|site|online)|burpcollaborator\.net|eo[a-z0-9]{10,}\.m\.pipedream\.net)\b/i;

  // ════════════════════════════════════════════════════════════════════════
  // Public render
  // ════════════════════════════════════════════════════════════════════════
  async render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const parsed = await this._parseInput(bytes, fileName);

    const wrap = document.createElement('div');
    wrap.className = 'npm-view clickonce-view';
    wrap._npmParsed = parsed;

    // ── Banner ────────────────────────────────────────────────────────────
    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    const kindLabel = parsed.kind === 'tarball' ? 'npm Package Tarball'
                   : parsed.kind === 'lockfile' ? 'npm Lockfile'
                   : 'npm package.json';
    const headline = parsed.manifest && parsed.manifest.name
      ? ` — <code>${this._esc(parsed.manifest.name)}${parsed.manifest.version ? '@' + this._esc(parsed.manifest.version) : ''}</code>`
      : '';
    banner.innerHTML = `<strong>${this._esc(kindLabel)}</strong>${headline}`;
    wrap.appendChild(banner);

    // ── Parse error box — show the parser message; don't bail (the raw
    //    viewer is still useful to an analyst staring at the bytes).
    if (parsed.parseError) {
      const err = document.createElement('div');
      err.className = 'clickonce-risks';
      const e = document.createElement('div');
      e.className = 'clickonce-risk clickonce-risk-high';
      e.textContent = `manifest parse error: ${parsed.parseError}`;
      err.appendChild(e);
      wrap.appendChild(err);
    }

    // ── Summary card ─────────────────────────────────────────────────────
    wrap.appendChild(this._buildSummaryCard(parsed));

    // ── Install-time execution (lifecycle hooks) ─────────────────────────
    const lifecycleSection = this._buildLifecycleSection(parsed);
    if (lifecycleSection) wrap.appendChild(lifecycleSection);

    // ── Entry points ─────────────────────────────────────────────────────
    const entrySection = this._buildEntryPointsSection(parsed, wrap);
    if (entrySection) wrap.appendChild(entrySection);

    // ── Dependencies ─────────────────────────────────────────────────────
    const depsSection = this._buildDependenciesSection(parsed);
    if (depsSection) wrap.appendChild(depsSection);

    // ── Risk indicators ──────────────────────────────────────────────────
    const risks = this._assess(parsed);
    if (risks.length) {
      const section = document.createElement('div');
      section.className = 'clickonce-section';
      const h = document.createElement('h3');
      h.textContent = `Risk Indicators (${risks.length})`;
      section.appendChild(h);
      const container = document.createElement('div');
      container.className = 'clickonce-risks';
      for (const r of risks) {
        const d = document.createElement('div');
        d.className = 'clickonce-risk clickonce-risk-' + r.sev;
        d.textContent = r.msg;
        container.appendChild(d);
      }
      section.appendChild(container);
      wrap.appendChild(section);
    }

    // ── File tree (tarball drill-down) ───────────────────────────────────
    if (parsed.kind === 'tarball' && parsed.tarEntries && parsed.tarEntries.length) {
      const section = document.createElement('div');
      section.className = 'clickonce-section';
      const h = document.createElement('h3');
      h.textContent = `Files (${parsed.tarEntries.filter(e => !e.dir).length})`;
      section.appendChild(h);

      // Mark install-script / native-binary rows with the shared `danger`
      // flag so ArchiveTree renders its warning badge. Paths that match a
      // lifecycle-hook script body are marked with an INSTALL SCRIPT badge;
      // everything else defaults to the ArchiveTree extension classifier.
      const hookPaths = new Set();
      if (parsed.manifest && parsed.manifest.scripts) {
        for (const [, cmd] of Object.entries(parsed.manifest.scripts)) {
          // Pull out a plausible script path from "node ./scripts/foo.js"
          const m = String(cmd || '').match(/(?:^|\s)(\.{0,2}\/?[\w\-./@]+\.(?:js|cjs|mjs|ts|sh|bash|py))/);
          if (m) hookPaths.add(('package/' + m[1].replace(/^\.\//, '')).replace(/\/+/g, '/'));
        }
      }

      const archEntries = parsed.tarEntries.map(e => {
        const isNative = NpmRenderer.NATIVE_ARTEFACT_RE.test(e.path);
        const isHook = hookPaths.has(e.path);
        return {
          path: e.path,
          dir: e.dir,
          size: e.size,
          date: e.mtime || null,
          _tarRef: e,
          danger: isNative || isHook ? true : undefined,
          dangerLabel: isNative ? 'NATIVE' : (isHook ? 'INSTALL SCRIPT' : undefined),
        };
      });

      const tree = ArchiveTree.render({
        entries: archEntries,
        onOpen: (entry) => this._extractTarEntry(bytes, entry._tarRef || entry, parsed, wrap),
        showDate: true,
      });
      section.appendChild(tree);
      wrap.appendChild(section);
    }

    // ── Raw manifest viewer (collapsible, plaintext-table for highlighting) ──
    const rawDetails = document.createElement('details');
    rawDetails.className = 'clickonce-raw-details';
    const summary = document.createElement('summary');
    summary.textContent = parsed.kind === 'lockfile' ? 'Raw lockfile' : 'Raw package.json';
    rawDetails.appendChild(summary);

    const sourcePane = document.createElement('div');
    sourcePane.className = 'clickonce-source plaintext-scroll';
    const table = document.createElement('table');
    table.className = 'plaintext-table';

    const rawText = parsed.manifestText || '';
    const lines = rawText.split('\n');
    const maxLines = RENDER_LIMITS.MAX_TEXT_LINES_SMALL;
    const count = Math.min(lines.length, maxLines);

    let highlightedLines = null;
    if (typeof hljs !== 'undefined' && rawText.length <= 200000) {
      try {
        const result = hljs.highlight(rawText, { language: 'json', ignoreIllegals: true });
        highlightedLines = result.value.split('\n');
      } catch (_) { /* fallback */ }
    }

    for (let i = 0; i < count; i++) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td');
      tdNum.className = 'plaintext-ln'; tdNum.textContent = i + 1;
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
    if (lines.length > maxLines) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td');
      tdNum.className = 'plaintext-ln'; tdNum.textContent = '…';
      const tdCode = document.createElement('td');
      tdCode.className = 'plaintext-code';
      tdCode.textContent = `[${lines.length - maxLines} more line${lines.length - maxLines === 1 ? '' : 's'} truncated]`;
      tr.appendChild(tdNum); tr.appendChild(tdCode);
      table.appendChild(tr);
    }
    sourcePane.appendChild(table);
    rawDetails.appendChild(sourcePane);
    wrap.appendChild(rawDetails);

    // Click-to-focus hooks consumed by the sidebar highlighter. `_rawText`
    // must match the string every `_sourceOffset` / `_sourceLength` in
    // findings refers to, so we normalize CRLF and use the same buffer
    // here, in `analyzeForSecurity`, and in every `locate()` call.
    wrap._rawText = rawText;
    wrap._showSourcePane = () => {
      rawDetails.open = true;
      setTimeout(() => rawDetails.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0);
    };

    return wrap;
  }

  // ════════════════════════════════════════════════════════════════════════
  // Security analysis
  // ════════════════════════════════════════════════════════════════════════
  async analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], interestingStrings: [],
      metadata: {}, signatureMatches: [],
      npmInfo: null,
    };
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const parsed = await this._parseInput(bytes, fileName);
    f.npmInfo = parsed;

    const manifestText = parsed.manifestText || '';
    const locate = (needle) => {
      if (!needle || !manifestText) return null;
      const idx = manifestText.indexOf(needle);
      return idx === -1 ? null : { offset: idx, length: needle.length };
    };

    // ── Metadata ────────────────────────────────────────────────────────
    const md = f.metadata;
    const m = parsed.manifest || {};
    md['Manifest Kind'] = parsed.kind === 'tarball' ? 'npm package tarball'
                       : parsed.kind === 'lockfile' ? 'npm lockfile'
                       : 'npm package.json';
    if (m.name)        md['Package Name'] = m.name;
    if (m.version)     md['Version'] = m.version;
    if (m.description) md['Description'] = m.description;
    if (m.license)     md['License'] = typeof m.license === 'string' ? m.license : (m.license.type || JSON.stringify(m.license));
    if (m.engines && typeof m.engines === 'object') {
      const parts = [];
      for (const [k, v] of Object.entries(m.engines)) parts.push(`${k}: ${v}`);
      if (parts.length) md['Engines'] = parts.join('  •  ');
    }
    if (parsed.authorName)  md['Author'] = parsed.authorName;
    if (parsed.authorEmail) md['Author Email'] = parsed.authorEmail;
    if (m.homepage)    md['Homepage'] = m.homepage;
    if (parsed.repoUrl) md['Repository'] = parsed.repoUrl;
    if (parsed.bugsUrl) md['Bug Tracker'] = parsed.bugsUrl;
    if (typeof m.private === 'boolean') md['Private'] = String(m.private);
    if (m._resolved) md['Resolved URL'] = m._resolved;
    if (m._integrity) md['Integrity'] = m._integrity;

    if (parsed.kind === 'tarball') {
      md['Tarball Bytes'] = String(bytes.length);
      if (parsed.unpackedSize != null) md['Unpacked Size'] = String(parsed.unpackedSize);
      if (parsed.tarEntries) md['File Count'] = String(parsed.tarEntries.filter(e => !e.dir).length);
      if (parsed.sha512Integrity) md['Tarball SHA-512'] = parsed.sha512Integrity;
    }

    // Dependency counts — cheap pivot + feeds the Summary block directly.
    const depCounts = this._depCounts(m);
    for (const [k, v] of Object.entries(depCounts)) {
      if (v) md[k] = String(v);
    }
    if (m.bin) {
      const bins = typeof m.bin === 'string' ? 1 : Object.keys(m.bin).length;
      if (bins) md['Executables (bin)'] = String(bins);
    }

    // Script hooks — surface every lifecycle hook with its command.
    const hooks = this._collectHooks(m);
    if (hooks.length) {
      md['Lifecycle Hooks'] = String(hooks.length);
    }

    // ── Risks → externalRefs (with click-to-focus targets) ───────────────
    const risks = this._assess(parsed);
    let score = 0;
    for (const r of risks) {
      const ref = { type: IOC.PATTERN, url: r.msg, severity: r.sev };
      if (r.highlight) {
        ref._highlightText = r.highlight;
        const loc = locate(r.highlight);
        if (loc) { ref._sourceOffset = loc.offset; ref._sourceLength = loc.length; }
      }
      f.externalRefs.push(ref);
      if (r.sev === 'critical') score += 5;
      else if (r.sev === 'high') score += 3;
      else if (r.sev === 'medium') score += 1.5;
      else score += 0.5;
    }

    // ── Per-hook IOC rows (always emit — even benign hooks matter for
    //    supply-chain review). Severity derived by `_classifyCommand()`.
    for (const h of hooks) {
      const ref = {
        type: IOC.PATTERN,
        url: `hook ${h.name}: ${h.cmd}`,
        severity: h.sev,
      };
      const needle = `"${h.name}"`;
      const loc = locate(needle);
      if (loc) { ref._highlightText = needle; ref._sourceOffset = loc.offset; ref._sourceLength = loc.length; }
      f.interestingStrings.push(ref);
    }

    // ── Per-bin row — global CLI binaries installed on `npm i -g` ────────
    if (m.bin) {
      const binMap = typeof m.bin === 'string'
        ? { [m.name || '(default)']: m.bin }
        : m.bin;
      for (const [name, p] of Object.entries(binMap || {})) {
        pushIOC(f, {
          type: IOC.FILE_PATH,
          value: String(p),
          severity: 'info',
          note: `bin: ${name}`,
          highlightText: typeof p === 'string' ? JSON.stringify(p) : undefined,
        });
      }
    }

    // ── Entry-point IOCs (main / module / exports / browser) ─────────────
    const entryPaths = this._collectEntryPoints(m);
    for (const [label, p] of entryPaths) {
      if (!p) continue;
      const sv = String(p);
      const ref = {
        type: IOC.FILE_PATH,
        url: sv,
        severity: 'info',
        note: label,
      };
      const needle = JSON.stringify(sv);
      const loc = locate(needle);
      if (loc) { ref._highlightText = needle; ref._sourceOffset = loc.offset; ref._sourceLength = loc.length; }
      f.interestingStrings.push(ref);
    }

    // ── URL IOCs from the manifest — repo / homepage / bugs / funding /
    //    lockfile `resolved` entries.
    const urls = new Set();
    if (parsed.repoUrl) urls.add(parsed.repoUrl);
    if (m.homepage && typeof m.homepage === 'string') urls.add(m.homepage);
    if (parsed.bugsUrl) urls.add(parsed.bugsUrl);
    if (m.funding) {
      const f2 = m.funding;
      if (typeof f2 === 'string') urls.add(f2);
      else if (f2 && typeof f2 === 'object' && typeof f2.url === 'string') urls.add(f2.url);
      else if (Array.isArray(f2)) for (const x of f2) {
        if (typeof x === 'string') urls.add(x);
        else if (x && typeof x.url === 'string') urls.add(x.url);
      }
    }
    if (parsed.lockfileResolvedUrls) for (const u of parsed.lockfileResolvedUrls) urls.add(u);
    for (const u of urls) {
      if (!/^(?:https?|git(?:\+https?)?|ssh|git\+ssh):\/\//i.test(u)) continue;
      const httpUrl = u.replace(/^git\+/i, '').replace(/^git:/i, 'https:').replace(/^ssh:/i, 'https:');
      let sev = 'info';
      if (/^http:\/\//i.test(httpUrl)) sev = 'medium';
      if (NpmRenderer.EXFIL_HOST_RE.test(httpUrl)) sev = 'high';
      const ref = { type: IOC.URL, url: httpUrl, severity: sev };
      const loc = locate(u);
      if (loc) { ref._highlightText = u; ref._sourceOffset = loc.offset; ref._sourceLength = loc.length; }
      f.externalRefs.push(ref);
    }

    // ── Author email (if present) ────────────────────────────────────────
    if (parsed.authorEmail) {
      const ref = { type: IOC.EMAIL, url: parsed.authorEmail, severity: 'info' };
      const loc = locate(parsed.authorEmail);
      if (loc) { ref._highlightText = parsed.authorEmail; ref._sourceOffset = loc.offset; ref._sourceLength = loc.length; }
      f.interestingStrings.push(ref);
    }

    // ── Integrity hash (if the manifest embeds it — npm pack writes
    //    `_integrity: "sha512-…"` into packed manifests). Both the raw
    //    ssri form and the hex form are useful pivots.
    if (parsed.sha512Integrity) {
      pushIOC(f, { type: IOC.HASH, value: parsed.sha512Integrity, severity: 'info', note: 'tarball SHA-512' });
    }

    // ── Per-dependency IOC rows (flag typosquats). Emit each dep only
    //    once per bucket, cap the total so mega-lockfiles don't flood
    //    the sidebar.
    const depSeen = new Set();
    const depCap = 500;
    let depEmitted = 0;
    for (const [bucket, map] of Object.entries(this._allDeps(m, parsed))) {
      for (const depName of Object.keys(map || {})) {
        if (depEmitted >= depCap) break;
        if (depSeen.has(depName)) continue;
        depSeen.add(depName);
        const typosquat = NpmRenderer.TYPOSQUATS.has(String(depName).toLowerCase());
        const ref = {
          type: IOC.PACKAGE_NAME,
          url: depName,
          severity: typosquat ? 'high' : 'info',
          note: typosquat ? `${bucket} — possible typosquat-of-popular` : bucket,
        };
        const needle = `"${depName}"`;
        const loc = locate(needle);
        if (loc) { ref._highlightText = needle; ref._sourceOffset = loc.offset; ref._sourceLength = loc.length; }
        f.interestingStrings.push(ref);
        depEmitted++;
      }
    }

    // ── Bundled native artefacts (tarball-only) ──────────────────────────
    if (parsed.tarEntries) {
      for (const e of parsed.tarEntries) {
        if (e.dir) continue;
        if (NpmRenderer.NATIVE_ARTEFACT_RE.test(e.path)) {
          pushIOC(f, {
            type: IOC.FILE_PATH,
            value: e.path,
            severity: 'medium',
            note: 'pre-built native artefact inside package',
          });
        }
      }
    }

    // ── Risk bucket — same ladder MsixRenderer / BrowserExtRenderer use ──
    if (score >= 8) f.risk = 'critical';
    else if (score >= 5) f.risk = 'high';
    else if (score >= 2) f.risk = 'medium';
    else f.risk = 'low';

    // ── Classic-pivot IOC mirroring from metadata ────────────────────────
    mirrorMetadataIOCs(f, {
      'Package Name':       IOC.PACKAGE_NAME,
      'Author Email':       IOC.EMAIL,
      'Repository':         IOC.URL,
      'Homepage':           IOC.URL,
      'Bug Tracker':        IOC.URL,
      'Resolved URL':       IOC.URL,
      'Tarball SHA-512':    IOC.HASH,
    });

    // ── augmentedBuffer — YARA scans the manifest text AND the contents
    //    of every lifecycle-hook script file inside the tarball, so rules
    //    for obfuscated stealers inside the bundle actually fire even
    //    when the manifest itself looks clean. Same pattern SvgRenderer
    //    and OsascriptRenderer use.
    let augmented = manifestText;
    if (parsed.tarEntries && parsed.hookScriptContents && parsed.hookScriptContents.length) {
      augmented += '\n\n/* ---- LOUPE npm lifecycle-hook script bodies ---- */\n';
      for (const hs of parsed.hookScriptContents) {
        augmented += `\n/* file: ${hs.path} */\n${hs.text}\n`;
      }
    }
    if (augmented !== manifestText) {
      try { f.augmentedBuffer = new TextEncoder().encode(augmented).buffer; }
      catch (_) { /* augmentedBuffer is optional */ }
    }

    return f;
  }

  // ════════════════════════════════════════════════════════════════════════
  // Risk assessment
  // ════════════════════════════════════════════════════════════════════════
  _assess(parsed) {
    const risks = [];
    const m = parsed.manifest || {};
    if (!m || typeof m !== 'object') return risks;

    // ── Lifecycle-hook content-class risk ────────────────────────────────
    const hooks = this._collectHooks(m);
    for (const h of hooks) {
      if (h.sev === 'critical') {
        risks.push({
          sev: 'critical',
          msg: `⚠ ${h.name} runs a download/eval primitive: ${this._truncate(h.cmd, 120)}`,
          highlight: `"${h.name}"`,
        });
      } else if (h.sev === 'high') {
        risks.push({
          sev: 'high',
          msg: `⚠ ${h.name} hook reaches the network or writes files: ${this._truncate(h.cmd, 120)}`,
          highlight: `"${h.name}"`,
        });
      } else if (h.sev === 'medium') {
        risks.push({
          sev: 'medium',
          msg: `${h.name} hook present — runs on every install of this package`,
          highlight: `"${h.name}"`,
        });
      }
    }

    // ── Repository URL plain HTTP / non-GitHub-style exfil host ─────────
    if (parsed.repoUrl) {
      if (/^http:\/\//i.test(parsed.repoUrl)) {
        risks.push({
          sev: 'medium',
          msg: `repository.url uses plain HTTP — update MITM surface: ${parsed.repoUrl}`,
          highlight: parsed.repoUrl,
        });
      }
      if (NpmRenderer.EXFIL_HOST_RE.test(parsed.repoUrl)) {
        risks.push({
          sev: 'high',
          msg: `repository.url points to a low-reputation / tunnelling host: ${parsed.repoUrl}`,
          highlight: parsed.repoUrl,
        });
      }
    }

    // ── Custom `publishConfig.registry` outside the official npm path ──
    if (m.publishConfig && m.publishConfig.registry) {
      if (!NpmRenderer.OFFICIAL_REGISTRY_RE.test(m.publishConfig.registry)) {
        risks.push({
          sev: 'medium',
          msg: `publishConfig.registry points outside the official npm registries: ${m.publishConfig.registry}`,
          highlight: m.publishConfig.registry,
        });
      }
    }

    // ── `bin` exposes global CLI — each bin becomes a globally-installed
    //    shortcut on `npm i -g`; treat mere presence as medium if it
    //    points at a .sh or is unusually large.
    if (m.bin && typeof m.bin === 'object') {
      for (const [name, p] of Object.entries(m.bin)) {
        if (typeof p !== 'string') continue;
        if (/\.(sh|bash|py)$/i.test(p)) {
          risks.push({
            sev: 'medium',
            msg: `bin entry "${name}" resolves to a shell script (${p}) — globally installed on \`npm i -g\``,
            highlight: p,
          });
        }
      }
    }

    // ── Dependency-count outliers. A single-purpose utility with 500
    //    transitive deps is a supply-chain-blast-radius red flag.
    const counts = this._depCounts(m);
    const runtimeDeps = counts['Dependencies'] || 0;
    if (runtimeDeps >= 200) {
      risks.push({
        sev: 'medium',
        msg: `${runtimeDeps} runtime dependencies declared — large transitive surface`,
      });
    }

    // ── Bundled native artefacts ────────────────────────────────────────
    let nativeCount = 0;
    if (parsed.tarEntries) {
      for (const e of parsed.tarEntries) {
        if (e.dir) continue;
        if (NpmRenderer.NATIVE_ARTEFACT_RE.test(e.path)) nativeCount++;
      }
      if (nativeCount >= 1) {
        risks.push({
          sev: 'medium',
          msg: `${nativeCount} pre-built native artefact${nativeCount === 1 ? '' : 's'} bundled in the tarball (.node/.so/.dylib/.exe/.wasm)`,
        });
      }
    }

    // ── `files` missing while a giant tarball is shipped. When a
    //    maintainer forgets a `files` whitelist *and* .npmignore, secrets
    //    from .env / .git / test/ end up published. Heuristic: tarball
    //    has >1 MB unpacked AND no `files` array AND contains any of the
    //    classic danger paths.
    if (parsed.kind === 'tarball') {
      const hasFiles = Array.isArray(m.files) && m.files.length > 0;
      const dangerPaths = (parsed.tarEntries || []).filter(e => !e.dir && /(?:^|\/)(?:\.env$|\.env\.|\.git\/|\.npmrc$|id_rsa$|id_ed25519$|\.ssh\/|test\/|tests?\/fixtures?\/)/i.test(e.path));
      if (!hasFiles && dangerPaths.length) {
        risks.push({
          sev: 'high',
          msg: `no "files" whitelist and ${dangerPaths.length} potentially-secret path${dangerPaths.length === 1 ? '' : 's'} present in the tarball (.env / .git / .npmrc / .ssh)`,
          highlight: '"files"',
        });
      } else if (dangerPaths.length) {
        risks.push({
          sev: 'medium',
          msg: `${dangerPaths.length} sensitive path${dangerPaths.length === 1 ? '' : 's'} inside the published tarball (.env / .git / .npmrc / .ssh)`,
        });
      }
    }

    // ── Shai-Hulud-style indicators (manifest level — YARA handles the
    //    bundle-body depth). Any of these on their own are enough for the
    //    analyst to pivot.
    if (parsed.tarEntries) {
      for (const e of parsed.tarEntries) {
        if (e.dir) continue;
        if (/^package\/\.github\/workflows\/(?:shai-hulud|shai-hulud-workflow)\.ya?ml$/i.test(e.path)) {
          risks.push({
            sev: 'critical',
            msg: `Shai-Hulud worm workflow inside tarball: ${e.path}`,
          });
        }
        if (/bundle\.js$/i.test(e.path) && e.size && e.size > 500 * 1024) {
          risks.push({
            sev: 'medium',
            msg: `Large bundled JS at ${e.path} (${this._fmtBytes(e.size)}) — worth a manual review`,
          });
        }
      }
    }

    // ── Lockfile: `resolved` URLs pointing outside the official registry
    if (parsed.kind === 'lockfile' && parsed.lockfileResolvedUrls) {
      const nonOfficial = parsed.lockfileResolvedUrls.filter(u => !NpmRenderer.OFFICIAL_REGISTRY_RE.test(u));
      if (nonOfficial.length) {
        risks.push({
          sev: 'medium',
          msg: `${nonOfficial.length} lockfile "resolved" URL${nonOfficial.length === 1 ? '' : 's'} point outside the official npm registries`,
          highlight: nonOfficial[0],
        });
      }
    }

    // ── Typosquat direct-dep flagging (cheap; mirrors the YARA rule)
    for (const [, map] of Object.entries(this._allDeps(m, parsed))) {
      for (const depName of Object.keys(map || {})) {
        if (NpmRenderer.TYPOSQUATS.has(String(depName).toLowerCase())) {
          risks.push({
            sev: 'high',
            msg: `dependency "${depName}" matches the typosquat-of-popular list`,
            highlight: `"${depName}"`,
          });
        }
      }
    }

    return risks;
  }

  // ════════════════════════════════════════════════════════════════════════
  // Summary card
  // ════════════════════════════════════════════════════════════════════════
  _buildSummaryCard(parsed) {
    const card = document.createElement('div');
    card.className = 'clickonce-card';
    const m = parsed.manifest || {};

    const addRow = (label, value, cls) => {
      if (value == null || value === '') return;
      const row = document.createElement('div');
      row.className = 'clickonce-field' + (cls ? ' ' + cls : '');
      const lbl = document.createElement('span'); lbl.className = 'clickonce-label';
      lbl.textContent = label + ':';
      const val = document.createElement('span'); val.className = 'clickonce-value';
      val.textContent = value;
      row.appendChild(lbl); row.appendChild(document.createTextNode(' ')); row.appendChild(val);
      card.appendChild(row);
    };

    if (m.name)        addRow('Name', m.name);
    if (m.version)     addRow('Version', m.version);
    if (m.description) addRow('Description', this._truncate(String(m.description), 300));
    if (m.license) {
      const lic = typeof m.license === 'string' ? m.license : (m.license.type || JSON.stringify(m.license));
      addRow('License', lic);
    }
    if (m.engines && typeof m.engines === 'object') {
      const parts = [];
      for (const [k, v] of Object.entries(m.engines)) parts.push(`${k}: ${v}`);
      if (parts.length) addRow('Engines', parts.join('  •  '));
    }
    if (parsed.authorName || parsed.authorEmail) {
      addRow('Author', [parsed.authorName, parsed.authorEmail ? '<' + parsed.authorEmail + '>' : ''].filter(Boolean).join(' '));
    }
    if (parsed.repoUrl) addRow('Repository', parsed.repoUrl,
      /^http:\/\//i.test(parsed.repoUrl) ? 'clickonce-warn' : null);
    if (m.homepage) addRow('Homepage', m.homepage);
    if (parsed.bugsUrl) addRow('Bug Tracker', parsed.bugsUrl);
    if (m.publishConfig && m.publishConfig.registry) {
      addRow('Publish Registry', m.publishConfig.registry,
        NpmRenderer.OFFICIAL_REGISTRY_RE.test(m.publishConfig.registry) ? null : 'clickonce-warn');
    }
    if (typeof m.private === 'boolean') addRow('Private', String(m.private));

    // Tarball-only stats.
    if (parsed.kind === 'tarball') {
      if (parsed.tarEntries) {
        addRow('Files', String(parsed.tarEntries.filter(e => !e.dir).length));
      }
      if (parsed.unpackedSize != null) {
        addRow('Unpacked Size', this._fmtBytes(parsed.unpackedSize));
      }
      if (parsed.sha512Integrity) {
        addRow('SHA-512 Integrity', this._truncate(parsed.sha512Integrity, 90));
      }
    }

    // Dependency fanout.
    const counts = this._depCounts(m);
    const depParts = [];
    for (const [k, v] of Object.entries(counts)) if (v) depParts.push(`${k.toLowerCase()}: ${v}`);
    if (depParts.length) addRow('Dependencies', depParts.join('  •  '));

    return card;
  }

  // ════════════════════════════════════════════════════════════════════════
  // Lifecycle-hook section
  // ════════════════════════════════════════════════════════════════════════
  _buildLifecycleSection(parsed) {
    const m = parsed.manifest || {};
    const hooks = this._collectHooks(m);
    if (!hooks.length) return null;

    const section = document.createElement('div');
    section.className = 'clickonce-section';
    const h = document.createElement('h3');
    h.textContent = `Install-time Execution (${hooks.length})`;
    section.appendChild(h);

    const table = document.createElement('table');
    table.className = 'clickonce-dep-list';
    table.style.width = '100%';
    table.style.borderCollapse = 'collapse';

    for (const row of hooks) {
      const tr = document.createElement('tr');
      tr.className = 'npm-hook-row npm-hook-row-' + row.sev;
      const tdHook = document.createElement('td');
      tdHook.style.cssText = 'padding:4px 10px 4px 0;vertical-align:top;white-space:nowrap';
      tdHook.innerHTML = `<strong>${this._esc(row.name)}</strong>`;
      const tdSev = document.createElement('td');
      tdSev.style.cssText = 'padding:4px 10px;vertical-align:top;text-transform:uppercase;font-size:11px;letter-spacing:0.05em;white-space:nowrap';
      tdSev.textContent = row.sev;
      const tdCmd = document.createElement('td');
      tdCmd.style.cssText = 'padding:4px 0;vertical-align:top;word-break:break-all;font-family:var(--font-mono,monospace)';
      tdCmd.textContent = row.cmd;
      tr.appendChild(tdHook); tr.appendChild(tdSev); tr.appendChild(tdCmd);
      table.appendChild(tr);
    }
    section.appendChild(table);
    return section;
  }

  // ════════════════════════════════════════════════════════════════════════
  // Entry-points section
  // ════════════════════════════════════════════════════════════════════════
  _buildEntryPointsSection(parsed, wrap) {
    const m = parsed.manifest || {};
    const entries = this._collectEntryPoints(m);
    const binMap = m.bin ? (typeof m.bin === 'string' ? { [m.name || '(default)']: m.bin } : m.bin) : null;

    if (!entries.length && !binMap) return null;
    const section = document.createElement('div');
    section.className = 'clickonce-section';
    const h = document.createElement('h3');
    h.textContent = 'Entry Points';
    section.appendChild(h);

    const list = document.createElement('ul');
    list.className = 'clickonce-dep-list';

    const makeRow = (label, path) => {
      const li = document.createElement('li');
      const targetPath = ('package/' + String(path).replace(/^\.\//, '')).replace(/\/+/g, '/');
      const canClick = parsed.kind === 'tarball'
        && (parsed.tarEntries || []).some(e => !e.dir && e.path === targetPath);
      li.innerHTML = `<strong>${this._esc(label)}</strong>: `;
      if (canClick) {
        const a = document.createElement('a');
        a.href = '#';
        a.className = 'npm-entry-link';
        a.textContent = path;
        a.addEventListener('click', (ev) => {
          ev.preventDefault();
          const entry = parsed.tarEntries.find(e => !e.dir && e.path === targetPath);
          if (entry && wrap) {
            const parentBytes = new Uint8Array(parsed._bytes);
            this._extractTarEntry(parentBytes, entry, parsed, wrap);
          }
        });
        li.appendChild(a);
      } else {
        const span = document.createElement('span');
        span.textContent = path;
        li.appendChild(span);
      }
      return li;
    };

    for (const [label, p] of entries) {
      if (p) list.appendChild(makeRow(label, p));
    }
    if (binMap) {
      for (const [name, p] of Object.entries(binMap)) {
        if (typeof p === 'string') list.appendChild(makeRow(`bin: ${name}`, p));
      }
    }
    section.appendChild(list);
    return section;
  }

  // ════════════════════════════════════════════════════════════════════════
  // Dependencies section
  // ════════════════════════════════════════════════════════════════════════
  _buildDependenciesSection(parsed) {
    const m = parsed.manifest || {};
    const groups = this._allDeps(m, parsed);
    const any = Object.values(groups).some(g => g && Object.keys(g).length > 0);
    if (!any) return null;

    const section = document.createElement('div');
    section.className = 'clickonce-section';
    const h = document.createElement('h3');
    const totalDeps = Object.values(groups).reduce((s, g) => s + Object.keys(g || {}).length, 0);
    h.textContent = `Dependencies (${totalDeps})`;
    section.appendChild(h);

    for (const [label, map] of Object.entries(groups)) {
      const keys = Object.keys(map || {});
      if (!keys.length) continue;
      const sub = document.createElement('div');
      sub.className = 'npm-dep-group';

      const hdr = document.createElement('div');
      hdr.className = 'clickonce-field';
      hdr.innerHTML = `<span class="clickonce-label">${this._esc(label)}:</span> <span class="clickonce-value">${keys.length}</span>`;
      sub.appendChild(hdr);

      const list = document.createElement('ul');
      list.className = 'clickonce-dep-list';
      const cap = 200;
      let count = 0;
      for (const k of keys) {
        if (count >= cap) {
          const li = document.createElement('li');
          li.textContent = `… (${keys.length - cap} more)`;
          list.appendChild(li);
          break;
        }
        const li = document.createElement('li');
        const typosquat = NpmRenderer.TYPOSQUATS.has(k.toLowerCase());
        const ver = map[k];
        li.innerHTML = `<code>${this._esc(k)}</code>` +
          (ver ? ` <span class="clickonce-value">${this._esc(String(ver))}</span>` : '');
        if (typosquat) {
          li.className = 'clickonce-warn';
          li.title = 'matches typosquat-of-popular list';
        }
        list.appendChild(li);
        count++;
      }
      sub.appendChild(list);
      section.appendChild(sub);
    }
    return section;
  }

  // ════════════════════════════════════════════════════════════════════════
  // Input parsing — dispatch on first bytes
  // ════════════════════════════════════════════════════════════════════════
  async _parseInput(bytes, fileName) {
    const parsed = this._emptyParsed();
    parsed._bytes = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);

    // gzip magic → tarball
    if (bytes.length >= 2 && bytes[0] === 0x1F && bytes[1] === 0x8B) {
      parsed.kind = 'tarball';
      await this._parseTarball(bytes, parsed);
      return parsed;
    }

    // Plain TAR (no gzip) — an npm-shaped TAR still starts with "package/" in
    // the first filename field, which lives at offset 0 of the first 512-byte
    // header. We sniff it so `npm pack --dry-run` output / already-unpacked
    // tarballs still route here instead of ZipRenderer's generic tar branch.
    if (bytes.length >= 512) {
      const firstName = TarParser._readString(bytes, 0, 100);
      if (firstName.startsWith('package/') && this._looksLikeTar(bytes)) {
        parsed.kind = 'tarball';
        await this._parseTarBytes(bytes, parsed);
        return parsed;
      }
    }

    // Otherwise treat as a raw JSON manifest / lockfile.
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const normalised = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    parsed.manifestText = normalised;

    let obj = null;
    try { obj = JSON.parse(normalised); }
    catch (e) { parsed.parseError = e && e.message || String(e); return parsed; }
    if (!obj || typeof obj !== 'object') return parsed;

    if (obj.lockfileVersion != null || (obj.packages && typeof obj.packages === 'object') || obj.dependencies && this._looksLikeLockfileDeps(obj.dependencies)) {
      parsed.kind = 'lockfile';
      parsed.manifest = obj;
      this._fillAuthorRepo(parsed);
      parsed.lockfileResolvedUrls = this._collectLockResolvedUrls(obj);
    } else {
      parsed.kind = 'manifest';
      parsed.manifest = obj;
      this._fillAuthorRepo(parsed);
    }
    return parsed;
  }

  _emptyParsed() {
    return {
      kind: null,           // 'tarball' | 'manifest' | 'lockfile'
      manifest: null,       // parsed package.json object
      manifestText: '',     // text the sidebar highlighter operates over
      parseError: null,
      tarEntries: null,     // tarball: [{ path, dir, size, mtime, offset }]
      hookScriptContents: null, // tarball: scripts referenced by hooks
      unpackedSize: null,   // tarball: sum of entry sizes
      sha512Integrity: null,// tarball: ssri-style sha512 of the whole tarball
      authorName: null,
      authorEmail: null,
      repoUrl: null,
      bugsUrl: null,
      lockfileResolvedUrls: null,
      _bytes: null,         // the raw input bytes (ArrayBuffer) for drill-down
    };
  }

  _fillAuthorRepo(parsed) {
    const m = parsed.manifest || {};
    const a = m.author;
    if (typeof a === 'string') {
      const r = a.match(/^([^<]+?)(?:\s+<([^>]+)>)?(?:\s+\(([^)]+)\))?\s*$/);
      if (r) { parsed.authorName = (r[1] || '').trim() || null; parsed.authorEmail = r[2] || null; }
      else { parsed.authorName = a; }
    } else if (a && typeof a === 'object') {
      parsed.authorName = a.name || null;
      parsed.authorEmail = a.email || null;
    }
    if (m.repository) {
      const r = m.repository;
      let u = null;
      if (typeof r === 'string') u = r;
      else if (r && typeof r === 'object') u = r.url || null;
      if (u) {
        u = String(u).replace(/^git\+/i, '').replace(/^git:\/\//i, 'https://');
        parsed.repoUrl = u;
      }
    }
    if (m.bugs) {
      if (typeof m.bugs === 'string') parsed.bugsUrl = m.bugs;
      else if (m.bugs && typeof m.bugs === 'object' && typeof m.bugs.url === 'string') parsed.bugsUrl = m.bugs.url;
    }
  }

  // ── Tarball: inflate gzip → walk TAR entries → extract package.json ──
  async _parseTarball(bytes, parsed) {
    if (typeof Decompressor === 'undefined' || !Decompressor.inflate) {
      parsed.parseError = 'Decompressor unavailable — cannot inflate gzip';
      return;
    }
    let inflated;
    try { inflated = await Decompressor.inflate(bytes, 'gzip'); }
    catch (e) { parsed.parseError = 'gzip inflate failed: ' + (e && e.message || e); return; }
    if (!inflated || !inflated.length) { parsed.parseError = 'empty gzip stream'; return; }

    await this._parseTarBytes(inflated, parsed);

    // SHA-512 over the ORIGINAL gzip bytes (not the inflated payload) —
    // that's what npm / the registry sign as the package integrity.
    try {
      if (typeof crypto !== 'undefined' && crypto.subtle) {
        const digest = await crypto.subtle.digest('SHA-512', bytes);
        const b64 = this._arrayBufferToBase64(digest);
        parsed.sha512Integrity = 'sha512-' + b64;
      }
    } catch (_) { /* integrity hash is best-effort */ }
  }

  async _parseTarBytes(tarBytes, parsed) {
    const entries = TarParser.parse(tarBytes);
    parsed.tarEntries = entries;
    parsed.unpackedSize = entries.reduce((s, e) => s + (e.dir ? 0 : (e.size || 0)), 0);

    // Pull package.json out of the tarball — the conventional path is
    // `package/package.json` but a user may have packed with a different
    // prefix, so fall back to any entry ending in `/package.json`.
    const preferred = entries.find(e => !e.dir && e.path === 'package/package.json');
    const fallback = preferred || entries.find(e => !e.dir && /(?:^|\/)package\.json$/.test(e.path));
    if (fallback) {
      const data = TarParser.extractEntry(tarBytes, fallback);
      const text = data ? new TextDecoder('utf-8', { fatal: false }).decode(data) : '';
      const normalised = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      parsed.manifestText = normalised;
      try { parsed.manifest = JSON.parse(normalised); }
      catch (e) { parsed.parseError = 'package.json: ' + (e && e.message || e); parsed.manifest = {}; }
      this._fillAuthorRepo(parsed);
    } else {
      parsed.parseError = 'no package.json found inside tarball';
      parsed.manifest = {};
    }

    // Pull hook-script contents for YARA augmentedBuffer.
    const hookPaths = new Set();
    if (parsed.manifest && parsed.manifest.scripts) {
      for (const [, cmd] of Object.entries(parsed.manifest.scripts)) {
        const m = String(cmd || '').match(/(?:^|\s)(\.{0,2}\/?[\w\-./@]+\.(?:js|cjs|mjs|ts|sh|bash|py))/);
        if (m) hookPaths.add(('package/' + m[1].replace(/^\.\//, '')).replace(/\/+/g, '/'));
      }
    }
    parsed.hookScriptContents = [];
    const HOOK_CAP_BYTES = 2 * 1024 * 1024; // cap hook-bundle aggregate at 2 MB
    let used = 0;
    for (const p of hookPaths) {
      const entry = entries.find(e => !e.dir && e.path === p);
      if (!entry) continue;
      const size = entry.size || 0;
      if (used + size > HOOK_CAP_BYTES) break;
      try {
        const data = TarParser.extractEntry(tarBytes, entry);
        const text = data ? new TextDecoder('utf-8', { fatal: false }).decode(data) : '';
        parsed.hookScriptContents.push({ path: entry.path, text });
        used += size;
      } catch (_) { /* skip unreadable */ }
    }
  }

  _parseTar(bytes) {
    return TarParser.parse(bytes);
  }

  _looksLikeTar(bytes) {
    return TarParser.isTar(bytes);
  }

  _extractTarEntry(tarBytes, entry, parsed, wrap) {
    // If `tarBytes` is the ORIGINAL gzip buffer (render path) we need to
    // re-inflate before slicing. The `parsed._bytes` arrayBuffer stash
    // keeps the original gzip; we inflate-on-demand to avoid keeping two
    // copies of large tarballs in memory.
    const doExtract = (inflated) => {
      if (entry.dir || !entry.size) return;
      const data = TarParser.extractEntry(inflated, entry);
      if (!data) return;
      const name = entry.path.split('/').pop();
      const file = new File([data], name, { type: 'application/octet-stream' });
      wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
    };

    if (tarBytes.length >= 2 && tarBytes[0] === 0x1F && tarBytes[1] === 0x8B) {
      if (typeof Decompressor === 'undefined' || !Decompressor.inflate) return;
      Decompressor.inflate(tarBytes, 'gzip').then(doExtract).catch(() => {});
    } else {
      doExtract(tarBytes);
    }
  }

  // ════════════════════════════════════════════════════════════════════════
  // Small helpers
  // ════════════════════════════════════════════════════════════════════════
  _collectHooks(m) {
    const hooks = [];
    if (!m || !m.scripts || typeof m.scripts !== 'object') return hooks;
    for (const name of NpmRenderer.LIFECYCLE_HOOKS) {
      const cmd = m.scripts[name];
      if (typeof cmd === 'string' && cmd.trim()) {
        hooks.push({ name, cmd, sev: this._classifyCommand(cmd) });
      }
    }
    return hooks;
  }

  _classifyCommand(cmd) {
    if (!cmd || typeof cmd !== 'string') return 'low';
    const s = cmd.trim();
    if (NpmRenderer.CRITICAL_CMD_RE.test(s)) return 'critical';
    if (NpmRenderer.HIGH_CMD_RE.test(s)) return 'high';
    if (NpmRenderer.BENIGN_CMD_RE.test(s)) return 'low';
    return 'medium';
  }

  _depCounts(m) {
    const o = {};
    const pairs = [
      ['Dependencies',        m && m.dependencies],
      ['Dev Dependencies',    m && m.devDependencies],
      ['Peer Dependencies',   m && m.peerDependencies],
      ['Optional Dependencies', m && m.optionalDependencies],
      ['Bundled Dependencies', Array.isArray(m && m.bundledDependencies) ? Object.fromEntries((m.bundledDependencies || []).map(x => [x, '*'])) : (m && m.bundleDependencies)],
    ];
    for (const [k, v] of pairs) {
      if (!v || typeof v !== 'object') continue;
      o[k] = Object.keys(v).length;
    }
    return o;
  }

  _allDeps(m, parsed) {
    const out = {
      'Dependencies':        (m && m.dependencies) || {},
      'Dev Dependencies':    (m && m.devDependencies) || {},
      'Peer Dependencies':   (m && m.peerDependencies) || {},
      'Optional Dependencies': (m && m.optionalDependencies) || {},
    };
    if (Array.isArray(m && m.bundledDependencies)) {
      out['Bundled Dependencies'] = Object.fromEntries(m.bundledDependencies.map(x => [x, '*']));
    } else if (m && m.bundleDependencies && typeof m.bundleDependencies === 'object') {
      out['Bundled Dependencies'] = m.bundleDependencies;
    }
    // Lockfiles flatten everything into `packages` / `dependencies`.
    if (parsed && parsed.kind === 'lockfile' && m) {
      const lockDeps = {};
      if (m.packages && typeof m.packages === 'object') {
        for (const key of Object.keys(m.packages)) {
          if (!key) continue; // root entry
          const name = key.startsWith('node_modules/')
            ? key.slice('node_modules/'.length)
            : key;
          lockDeps[name] = m.packages[key] && m.packages[key].version || '*';
        }
      } else if (m.dependencies && this._looksLikeLockfileDeps(m.dependencies)) {
        const walk = (deps) => {
          for (const [n, d] of Object.entries(deps || {})) {
            lockDeps[n] = (d && d.version) || '*';
            if (d && d.dependencies) walk(d.dependencies);
          }
        };
        walk(m.dependencies);
      }
      if (Object.keys(lockDeps).length) out['Lockfile Packages'] = lockDeps;
    }
    return out;
  }

  _looksLikeLockfileDeps(deps) {
    if (!deps || typeof deps !== 'object') return false;
    // A lockfile's deps-values are objects with `version`/`resolved`/etc.;
    // a manifest's deps-values are version strings.
    for (const v of Object.values(deps)) {
      if (v && typeof v === 'object' && (typeof v.version === 'string' || typeof v.resolved === 'string' || typeof v.integrity === 'string')) {
        return true;
      }
      // First non-object value ⇒ definitely a manifest.
      if (typeof v === 'string') return false;
    }
    return false;
  }

  _collectLockResolvedUrls(obj) {
    const urls = new Set();
    const walk = (node) => {
      if (!node || typeof node !== 'object') return;
      if (typeof node.resolved === 'string') urls.add(node.resolved);
      if (node.packages && typeof node.packages === 'object') {
        for (const v of Object.values(node.packages)) walk(v);
      }
      if (node.dependencies && typeof node.dependencies === 'object') {
        for (const v of Object.values(node.dependencies)) walk(v);
      }
    };
    walk(obj);
    return Array.from(urls);
  }

  _collectEntryPoints(m) {
    const rows = [];
    if (!m) return rows;
    if (typeof m.main === 'string')    rows.push(['main', m.main]);
    if (typeof m.module === 'string')  rows.push(['module', m.module]);
    if (typeof m.browser === 'string') rows.push(['browser', m.browser]);
    else if (m.browser && typeof m.browser === 'object') {
      for (const [k, v] of Object.entries(m.browser)) {
        if (typeof v === 'string') rows.push([`browser[${k}]`, v]);
      }
    }
    if (typeof m.types === 'string')      rows.push(['types', m.types]);
    if (typeof m.typings === 'string')    rows.push(['typings', m.typings]);
    if (typeof m.unpkg === 'string')      rows.push(['unpkg', m.unpkg]);
    if (typeof m.jsdelivr === 'string')   rows.push(['jsdelivr', m.jsdelivr]);
    if (Array.isArray(m.man))             m.man.forEach((p, i) => typeof p === 'string' && rows.push([`man[${i}]`, p]));
    else if (typeof m.man === 'string')   rows.push(['man', m.man]);

    // `exports` can be a string, an array, or a conditional-subpath map.
    if (typeof m.exports === 'string') {
      rows.push(['exports', m.exports]);
    } else if (m.exports && typeof m.exports === 'object') {
      const walk = (node, prefix) => {
        if (typeof node === 'string') { rows.push([prefix || 'exports', node]); return; }
        if (Array.isArray(node)) { for (const n of node) walk(n, prefix); return; }
        if (node && typeof node === 'object') {
          for (const [k, v] of Object.entries(node)) {
            const childPrefix = prefix ? `${prefix}[${k}]` : `exports[${k}]`;
            walk(v, childPrefix);
          }
        }
      };
      walk(m.exports, '');
    }
    return rows;
  }



  _arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return typeof btoa === 'function' ? btoa(bin) : '';
  }

  _truncate(s, n) {
    s = String(s == null ? '' : s);
    return s.length > n ? s.slice(0, n - 1) + '…' : s;
  }

  _fmtBytes(n) {
    if (n == null || isNaN(n)) return '';
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
    return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
  }

  _esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}
