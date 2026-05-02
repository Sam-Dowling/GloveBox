'use strict';
// ════════════════════════════════════════════════════════════════════════════
// msix-renderer.js — MSIX / APPX / .appinstaller analyzer
//
// Three input shapes are accepted — the renderer sniffs content internally:
//
//   1. MSIX / APPX packages  (.msix, .appx)
//        ZIP container with AppxManifest.xml at the root. Optionally ships a
//        detached signature at AppxSignature.p7x and a code-integrity catalog
//        under AppxMetadata/CodeIntegrity.cat.
//
//   2. Bundles  (.msixbundle, .appxbundle)
//        ZIP of ZIPs; AppxBundleManifest.xml at the root lists the contained
//        packages (application vs resource). We list them and let the user
//        click through — we do not recursively crack them at render time.
//
//   3. App Installer files  (.appinstaller)
//        Standalone XML with a <AppInstaller Uri="…"> root that points to a
//        MainPackage / MainBundle download URI, optional UpdateSettings, and
//        Dependencies. The common abuse pattern here is plain-HTTP MainPackage
//        URIs (trivially MITM'd into a silent auto-update swap).
//
// Core detection logic is identical across the three shapes: surface the
// identity, capability set, entry points / extensions, and flag anything in
// the "dangerous default-allowed" subset of capabilities (runFullTrust,
// allowElevation, broadFileSystemAccess, packageManagement, …) plus the
// common manifest-hijack patterns (AppExecutionAlias claiming `python.exe`
// et al., fullTrustProcess helpers, startupTask auto-run).
//
// Depends on: constants.js (IOC, escHtml), JSZip (vendor), DOMParser (built-in)
// ════════════════════════════════════════════════════════════════════════════
class MsixRenderer {

  // Restricted capabilities (<rescap:Capability>) — these require a special
  // Store declaration and are the primary reason an MSIX would warrant a
  // second look. `runFullTrust` alone effectively disables the MSIX sandbox.
  static RESCAP_HIGH = new Set([
    'runFullTrust',
    'allowElevation',
    'broadFileSystemAccess',
    'packageManagement',
    'packageQuery',
    'packagePolicySystem',
    'unvirtualizedResources',
    'confirmAppClose',
    'enterpriseDataPolicy',
    'enterpriseAuthentication',
    'previewStore',
    'localSystemServices',
    'extendedExecutionUnconstrained',
  ]);

  // Device / filesystem capabilities that warrant medium-severity mention.
  static DEVCAP_MEDIUM = new Set([
    'documentsLibrary', 'picturesLibrary', 'videosLibrary', 'musicLibrary',
    'removableStorage', 'sharedUserCertificates',
    'enterpriseAuthentication', 'userAccountInformation',
    'phoneCall', 'voipCall',
    'blockedChatMessages', 'chat', 'smsSend',
    'appCaptureServices', 'backgroundMediaPlayback',
  ]);

  // Execution-alias names attackers love to claim (so `python` typed at
  // an admin prompt launches their package instead of the real binary).
  static ALIAS_HIJACK_NAMES = new Set([
    'python.exe', 'python3.exe', 'pip.exe', 'py.exe',
    'node.exe', 'npm.exe', 'npx.exe',
    'wget.exe', 'curl.exe', 'ssh.exe', 'scp.exe', 'sftp.exe',
    'git.exe', 'where.exe', 'which.exe',
    'pwsh.exe', 'powershell.exe', 'cmd.exe',
    'notepad.exe', 'code.exe', 'explorer.exe',
    'openssl.exe', 'java.exe', 'javac.exe', 'ruby.exe', 'perl.exe',
  ]);

  // Low-reputation / tunnelling hosts copied from clickonce-threats.yar.
  static SUSPICIOUS_HOST_RE =
    /\.(?:trycloudflare\.com|ngrok\.io|ngrok-free\.app|serveo\.net|loca\.lt|duckdns\.org|sytes\.net|zapto\.org|hopto\.org|serveftp\.com|top|xyz|tk|ml|cf|ga|gq|zip|mov|click|country|work)(?:[/:?]|$)/i;

  // `AppxSignature.p7x` starts with a four-byte `PKCX` magic, immediately
  // followed by a DER-encoded PKCS#7 SignedData. We check the magic and
  // scan for the two Appx-specific ASN.1 OIDs plus the signer Subject CN /
  // O so the summary card can surface a computed-vs-declared-publisher
  // verdict. This is *not* a full ASN.1 parser — it's a token scan that
  // degrades cleanly to "present but not parseable" on malformed or
  // stub signatures (Loupe's own synthetic sample is a `PKCX\0`-fill).
  static P7X_MAGIC = [0x50, 0x4B, 0x43, 0x58]; // "PKCX"
  // 1.3.6.1.4.1.311.2.1.4 — Microsoft SpcIndirectDataContent
  static OID_SPC_INDIRECT_DATA = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];
  // 1.3.6.1.4.1.311.84.2.1  — AppxSipInfo (identifies the p7x SIP)
  static OID_APPX_SIP_INFO    = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x54, 0x02, 0x01];
  // 2.5.4.3  — id-at-commonName
  static OID_AT_COMMON_NAME   = [0x55, 0x04, 0x03];
  // 2.5.4.10 — id-at-organizationName
  static OID_AT_ORGANIZATION  = [0x55, 0x04, 0x0a];

  // 5-bit Crockford-style alphabet used by Windows for PublisherId
  // derivation (`0..9` + `a..z` with `i`, `l`, `o`, `u` removed). Packed
  // as a lookup string so we can index into it directly.
  static PUBLISHER_ID_ALPHA = '0123456789abcdefghjkmnpqrstvwxyz';

  // ═══════════════════════════════════════════════════════════════════════
  // Entry point — shape-matches the other renderers
  //
  // Wraps the whole dispatch in a try/catch envelope so a malformed
  // manifest (unparsable XML, missing Identity / Capabilities / Applications
  // / Packages, surprise DOM shapes in _parseExtension, …) surfaces as a
  // readable fallback notice instead of a blank pane — and crucially still
  // returns a `wrap` with `_rawText` populated so sidebar IOC extraction and
  // YARA scanning keep running on the raw bytes.
  // ═══════════════════════════════════════════════════════════════════════
  async render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    const wrap = document.createElement('div');
    wrap.className = 'clickonce-view msix-view';

    // Content sniff: ZIP vs XML. `.appinstaller` is always XML; `.msix` etc.
    // are always ZIP. Trust content, not extension.
    const isZip = bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04;

    try {
      if (isZip) {
        return await this._renderPackage(wrap, buffer, fileName);
      }
      return this._renderAppInstaller(wrap, buffer, fileName);
    } catch (err) {
      // Drop whatever was partially appended; render a fallback notice.
      while (wrap.firstChild) wrap.removeChild(wrap.firstChild);
      const notice = document.createElement('div');
      notice.className = 'bin-fallback-notice';
      notice.innerHTML =
        `<div class="bin-fallback-title"><strong>⚠ MSIX / App Installer parsing failed — showing raw fallback view</strong></div>` +
        `<div class="bin-fallback-reason"><code>${this._esc(err && err.message || String(err))}</code></div>` +
        `<div class="bin-fallback-sub">The package or manifest appears to be malformed, so structural analysis isn't available. ` +
        `IOC extraction and YARA rules can still run against whatever text could be decoded.</div>`;
      wrap.appendChild(notice);
      // Best-effort _rawText so sidebar IOC / YARA keeps working.
      if (!isZip) {
        try {
          wrap._rawText = lfNormalize(new TextDecoder('utf-8', { fatal: false }).decode(bytes));
        } catch (_) { wrap._rawText = lfNormalize(''); }
      } else {
        wrap._rawText = lfNormalize('');
      }
      return wrap;
    }
  }


  // ═══════════════════════════════════════════════════════════════════════
  // ZIP path — .msix / .appx / .msixbundle / .appxbundle
  // ═══════════════════════════════════════════════════════════════════════
  async _renderPackage(wrap, buffer, fileName) {
    let zip;
    try {
      zip = await JSZip.loadAsync(buffer);
    } catch (e) {
      const err = document.createElement('div');
      err.style.cssText = 'color:var(--risk-high);padding:20px;';
      err.textContent = 'Unable to open package ZIP: ' + (e && e.message || e);
      wrap.appendChild(err);
      return wrap;
    }
    this._zip = zip;

    const hasBundle = !!zip.file('AppxBundleManifest.xml') || !!zip.file('AppxMetadata/AppxBundleManifest.xml');
    const manifestPath = hasBundle
      ? (zip.file('AppxBundleManifest.xml') ? 'AppxBundleManifest.xml' : 'AppxMetadata/AppxBundleManifest.xml')
      : (zip.file('AppxManifest.xml') ? 'AppxManifest.xml' : null);

    let manifestText = null;
    if (manifestPath) {
      try { manifestText = await zip.file(manifestPath).async('string'); }
      catch (e) { /* fall through */ }
    }

    // Signature detection — presence only; we do not parse the PKCS#7.
    const hasSignature = !!zip.file('AppxSignature.p7x');
    const hasCat = !!zip.file('AppxMetadata/CodeIntegrity.cat');
    const hasBlockMap = !!zip.file('AppxBlockMap.xml');

    const parsed = this._parseManifest(manifestText, hasBundle);
    parsed.hasSignature = hasSignature;
    parsed.hasCodeIntegrityCat = hasCat;
    parsed.hasBlockMap = hasBlockMap;
    parsed.containerKind = hasBundle ? 'bundle' : 'package';

    // ── Decorate with parsed AppxSignature.p7x + computed Publisher ID ─
    // Done up here (before the banner/card/risks) so `_buildSummaryCard`
    // and `_assess` see the signer-CN / publisher-id fields. Both helpers
    // are best-effort: a stub p7x or DN we can't parse just leaves the
    // corresponding fields null, and the summary card / risks degrade.
    try {
      parsed.signature = await this._loadP7x(zip);
    } catch (_) { parsed.signature = null; }
    if (parsed.identity && parsed.identity.publisher) {
      try {
        parsed.publisherIdComputed = await this._computePublisherId(parsed.identity.publisher);
      } catch (_) { parsed.publisherIdComputed = null; }
      parsed.publisherDN = this._parsePublisherDN(parsed.identity.publisher);
    }


    // ── Banner ────────────────────────────────────────────────────────
    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    const kindLabel = hasBundle
      ? 'MSIX / APPX Bundle (.msixbundle / .appxbundle)'
      : 'MSIX / APPX Package (.msix / .appx)';
    banner.innerHTML =
      `<strong>${this._esc(kindLabel)}</strong> — Windows app package; the ` +
      `manifest declares the entry points, required capabilities, and any ` +
      `fullTrust or AppExecutionAlias extensions that can affect the host.`;
    wrap.appendChild(banner);

    // ── Summary card ──────────────────────────────────────────────────
    const card = this._buildSummaryCard(parsed);
    wrap.appendChild(card);

    // ── Capabilities section ──────────────────────────────────────────
    if (parsed.capabilities && parsed.capabilities.length) {
      wrap.appendChild(this._buildCapsSection(parsed.capabilities));
    }

    // ── Entry points / extensions ─────────────────────────────────────
    if (parsed.applications && parsed.applications.length) {
      wrap.appendChild(this._buildAppsSection(parsed.applications));
    }

    // ── Bundle package list ───────────────────────────────────────────
    if (parsed.bundlePackages && parsed.bundlePackages.length) {
      wrap.appendChild(this._buildBundleList(parsed.bundlePackages));
    }

    // ── File tree (clickable) ─────────────────────────────────────────
    wrap.appendChild(await this._buildFileTree(zip, wrap));

    // ── Raw AppxManifest / AppxBundleManifest XML ─────────────────────
    // Mirrors the ClickOnceRenderer plaintext-table pattern so the sidebar's
    // click-to-focus pipeline (_navigateToFinding → _highlightMatchesInline)
    // finds both `wrap._rawText` and a `.plaintext-table` to highlight into.
    // Without this hook every MSIX IOC / risk produced above carried a
    // _sourceOffset/_sourceLength against manifestText but had nowhere to
    // land, silently breaking click-to-focus for the whole format family.
    const normalizedManifest = (manifestText || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    if (normalizedManifest) {
      const rawDetails = document.createElement('details');
      rawDetails.className = 'clickonce-raw-details';
      const sum = document.createElement('summary');
      sum.textContent = hasBundle ? 'Raw AppxBundleManifest.xml' : 'Raw AppxManifest.xml';
      rawDetails.appendChild(sum);

      const sourcePane = document.createElement('div');
      sourcePane.className = 'clickonce-source plaintext-scroll';
      const table = document.createElement('table');
      table.className = 'plaintext-table';
      const lines = normalizedManifest.split('\n');
      const maxLines = RENDER_LIMITS.MAX_TEXT_LINES_SMALL;
      const count = Math.min(lines.length, maxLines);
      let highlightedLines = null;
      if (typeof hljs !== 'undefined' && normalizedManifest.length <= 200000) {
        try {
          const result = hljs.highlight(normalizedManifest, { language: 'xml', ignoreIllegals: true });
          highlightedLines = result.value.split('\n');
        } catch (_) { /* fallback to plain textContent */ }
      }
      for (let i = 0; i < count; i++) {
        const tr = document.createElement('tr');
        const tdNum = document.createElement('td'); tdNum.className = 'plaintext-ln'; tdNum.textContent = i + 1;
        const tdCode = document.createElement('td'); tdCode.className = 'plaintext-code';
        if (highlightedLines && highlightedLines[i] !== undefined) {
          tdCode.innerHTML = highlightedLines[i] || '';
        } else {
          tdCode.textContent = lines[i];
        }
        tr.appendChild(tdNum); tr.appendChild(tdCode);
        table.appendChild(tr);
      }
      sourcePane.appendChild(table);
      rawDetails.appendChild(sourcePane);
      wrap.appendChild(rawDetails);

      // Hooks for the sidebar highlight pipeline — identical to ClickOnce.
      wrap._rawText = lfNormalize(normalizedManifest);
      wrap._showSourcePane = () => {
        rawDetails.open = true;
        setTimeout(() => rawDetails.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0);
      };
    } else {
      // Even without a manifest (bare ZIP), stash an empty _rawText so the
      // sidebar doesn't try to highlight against undefined.
      wrap._rawText = lfNormalize('');
    }

    return wrap;
  }


  // ═══════════════════════════════════════════════════════════════════════
  // XML path — .appinstaller
  // ═══════════════════════════════════════════════════════════════════════
  _renderAppInstaller(wrap, buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const normalizedText = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

    const parsed = this._parseAppInstaller(normalizedText);
    parsed.containerKind = 'appinstaller';

    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    banner.innerHTML =
      `<strong>App Installer File (.appinstaller)</strong> — XML descriptor ` +
      `that points Windows at a package Uri for one-click install and ` +
      `optional auto-update; plain-HTTP or suspicious-host Uris are MITM ` +
      `/ downgrade vectors.`;
    wrap.appendChild(banner);

    wrap.appendChild(this._buildSummaryCard(parsed));

    // Raw XML (collapsible, same pattern as ClickOnceRenderer)
    const rawDetails = document.createElement('details');
    rawDetails.className = 'clickonce-raw-details';
    const sum = document.createElement('summary');
    sum.textContent = 'Raw XML';
    rawDetails.appendChild(sum);

    const sourcePane = document.createElement('div');
    sourcePane.className = 'clickonce-source plaintext-scroll';
    const table = document.createElement('table');
    table.className = 'plaintext-table';
    const lines = normalizedText.split('\n');
    const maxLines = RENDER_LIMITS.MAX_TEXT_LINES_SMALL;
    const count = Math.min(lines.length, maxLines);
    let highlightedLines = null;
    if (typeof hljs !== 'undefined' && normalizedText.length <= 200000) {
      try {
        const result = hljs.highlight(normalizedText, { language: 'xml', ignoreIllegals: true });
        highlightedLines = result.value.split('\n');
      } catch (_) { /* fallback to plain textContent */ }
    }
    for (let i = 0; i < count; i++) {
      const tr = document.createElement('tr');
      const tdNum = document.createElement('td'); tdNum.className = 'plaintext-ln'; tdNum.textContent = i + 1;
      const tdCode = document.createElement('td'); tdCode.className = 'plaintext-code';
      if (highlightedLines && highlightedLines[i] !== undefined) {
        tdCode.innerHTML = highlightedLines[i] || '';
      } else {
        tdCode.textContent = lines[i];
      }
      tr.appendChild(tdNum); tr.appendChild(tdCode);
      table.appendChild(tr);
    }
    sourcePane.appendChild(table);
    rawDetails.appendChild(sourcePane);
    wrap.appendChild(rawDetails);

    // Hooks for sidebar highlight pipeline.
    wrap._rawText = lfNormalize(normalizedText);
    wrap._showSourcePane = () => {
      rawDetails.open = true;
      setTimeout(() => rawDetails.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0);
    };

    return wrap;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Summary card — shared by all three shapes
  // ═══════════════════════════════════════════════════════════════════════
  _buildSummaryCard(parsed) {
    const card = document.createElement('div');
    card.className = 'clickonce-card msix-card';

    const addRow = (label, value, cls) => {
      if (value == null || value === '') return;
      const row = document.createElement('div');
      row.className = 'clickonce-field' + (cls ? ' ' + cls : '');
      const lbl = document.createElement('span'); lbl.className = 'clickonce-label'; lbl.textContent = label + ':';
      const val = document.createElement('span'); val.className = 'clickonce-value'; val.textContent = value;
      row.appendChild(lbl); row.appendChild(document.createTextNode(' ')); row.appendChild(val);
      card.appendChild(row);
    };

    if (parsed.containerKind === 'bundle') addRow('Format', 'MSIX / APPX Bundle');
    else if (parsed.containerKind === 'package') addRow('Format', 'MSIX / APPX Package');
    else if (parsed.containerKind === 'appinstaller') addRow('Format', 'App Installer File');

    if (parsed.identity) {
      addRow('Identity', this._fmtIdentity(parsed.identity));
      if (parsed.identity.processorArchitecture) addRow('Architecture', parsed.identity.processorArchitecture);
    }
    if (parsed.properties) {
      if (parsed.properties.displayName) addRow('Display Name', parsed.properties.displayName);
      if (parsed.properties.publisherDisplayName) addRow('Publisher (Display)', parsed.properties.publisherDisplayName);
    }
    if (parsed.identity && parsed.identity.publisher) addRow('Publisher (CN)', parsed.identity.publisher);

    // Signature state — only meaningful for ZIP packages.
    if (parsed.containerKind === 'package' || parsed.containerKind === 'bundle') {
      const sigTxt = parsed.hasSignature
        ? (parsed.hasCodeIntegrityCat ? 'Signed (AppxSignature.p7x + CI catalog)' : 'Signed (AppxSignature.p7x)')
        : 'Unsigned / sideload-only';
      addRow('Signature', sigTxt, parsed.hasSignature ? null : 'clickonce-warn');
      addRow('Block Map', parsed.hasBlockMap ? 'Present' : 'Missing',
             parsed.hasBlockMap ? null : 'clickonce-warn');

      // ── Parsed AppxSignature.p7x ────────────────────────────────────
      // Surface signer-CN / signer-O extracted from the PKCS#7 SignedData
      // and a manifest-vs-signer verdict so the user can see at a glance
      // whether the .p7x's certificate Subject lines up with the
      // Identity/@Publisher DN it claims to belong to.
      const sig = parsed.signature;
      if (sig && sig.present) {
        if (sig.hasPkcxMagic === false) {
          addRow('p7x Magic', 'missing PKCX header (likely truncated / not a real Appx signature)', 'clickonce-warn');
        }
        if (sig.signerCN) addRow('Signer CN (p7x)', sig.signerCN);
        if (sig.signerO)  addRow('Signer O (p7x)',  sig.signerO);
        // Compare against the manifest's parsed CN / O. Mismatch is the
        // strongest single-shot indicator of repackaged / re-signed
        // tampering, so flag it loudly.
        if (sig.signerCN && parsed.publisherDN && parsed.publisherDN.cn) {
          const manifestCN = parsed.publisherDN.cn.trim();
          const signerCN = sig.signerCN.trim();
          const match = manifestCN.toLowerCase() === signerCN.toLowerCase();
          addRow('Signer ↔ Manifest CN', match ? '✓ match' : `✗ mismatch (manifest: "${manifestCN}")`,
                 match ? null : 'clickonce-warn');
        }
        // Sanity-check the SIP marker. Real Appx signatures always carry
        // the AppxSipInfo OID; absence is either a stub sample or a
        // signature copied from a non-Appx PKCS#7.
        if (sig.hasPkcxMagic && sig.hasAppxSipInfo === false) {
          addRow('AppxSipInfo OID', 'missing — signature payload is not an Appx SIP', 'clickonce-warn');
        }
      }

      // Computed PublisherId — the 13-char tail of every PackageFamilyName.
      if (parsed.publisherIdComputed) {
        addRow('Publisher ID (computed)', parsed.publisherIdComputed);
      }
    }


    if (parsed.targetDeviceFamilies && parsed.targetDeviceFamilies.length) {
      addRow('Target Device Families', parsed.targetDeviceFamilies
        .map(t => `${t.name}${t.minVersion ? ' ≥ ' + t.minVersion : ''}`).join(', '));
    }

    // App-installer specific fields
    if (parsed.containerKind === 'appinstaller') {
      if (parsed.uri) {
        const isHttp = /^http:\/\//i.test(parsed.uri);
        addRow('Self Uri', parsed.uri, isHttp ? 'clickonce-warn' : null);
      }
      if (parsed.mainPackage) {
        const mp = parsed.mainPackage;
        addRow('Main Package', this._fmtIdentity(mp));
        if (mp.uri) {
          const isHttp = /^http:\/\//i.test(mp.uri);
          addRow('Main Package Uri', mp.uri, isHttp ? 'clickonce-warn' : null);
        }
      }
      if (parsed.mainBundle) {
        const mb = parsed.mainBundle;
        addRow('Main Bundle', this._fmtIdentity(mb));
        if (mb.uri) {
          const isHttp = /^http:\/\//i.test(mb.uri);
          addRow('Main Bundle Uri', mb.uri, isHttp ? 'clickonce-warn' : null);
        }
      }
      if (parsed.updateSettings) {
        const us = parsed.updateSettings;
        if (us.onLaunch) {
          const bits = [];
          if (us.onLaunch.hoursBetweenUpdateChecks != null) bits.push(`every ${us.onLaunch.hoursBetweenUpdateChecks}h`);
          if (us.onLaunch.updateBlocksActivation === true) bits.push('blocks activation');
          if (us.onLaunch.showPrompt === false) bits.push('silent (no prompt)');
          addRow('On-Launch Update', bits.length ? bits.join(', ') : 'enabled',
                 us.onLaunch.showPrompt === false ? 'clickonce-warn' : null);
        }
        if (us.automaticBackgroundTask) addRow('Auto Background Update', 'enabled');
        if (us.forceUpdateFromAnyVersion === true) addRow('Force Update', 'any prior version', 'clickonce-warn');
      }
    }

    // ── Risk indicators ────────────────────────────────────────────────
    const risks = this._assess(parsed);
    if (risks.length) {
      const riskDiv = document.createElement('div');
      riskDiv.className = 'clickonce-risks';
      for (const r of risks) {
        const d = document.createElement('div');
        d.className = 'clickonce-risk clickonce-risk-' + r.sev;
        d.textContent = r.msg;
        riskDiv.appendChild(d);
      }
      card.appendChild(riskDiv);
    }

    return card;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Capabilities table
  // ═══════════════════════════════════════════════════════════════════════
  _buildCapsSection(caps) {
    const sec = document.createElement('div'); sec.className = 'clickonce-section';
    const h = document.createElement('h3'); h.textContent = `Declared Capabilities (${caps.length})`;
    sec.appendChild(h);

    const list = document.createElement('ul'); list.className = 'clickonce-dep-list';
    for (const c of caps) {
      const li = document.createElement('li');
      const sev = this._capSeverity(c);
      const tag = c.restricted ? 'rescap' : (c.device ? 'device' : 'general');
      li.textContent = `[${tag}] ${c.name}${sev === 'high' ? '  — requires Store declaration / unsandboxed' : sev === 'medium' ? '  — broad user-data access' : ''}`;
      if (sev !== 'low') li.className = 'clickonce-warn';
      list.appendChild(li);
    }
    sec.appendChild(list);
    return sec;
  }

  _capSeverity(c) {
    if (c.restricted || MsixRenderer.RESCAP_HIGH.has(c.name)) return 'high';
    if (MsixRenderer.DEVCAP_MEDIUM.has(c.name)) return 'medium';
    return 'low';
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Applications / entry points / extensions
  // ═══════════════════════════════════════════════════════════════════════
  _buildAppsSection(apps) {
    const sec = document.createElement('div'); sec.className = 'clickonce-section';
    const h = document.createElement('h3');
    h.textContent = `Applications / Entry Points (${apps.length})`;
    sec.appendChild(h);

    for (const a of apps) {
      const li = document.createElement('div');
      li.style.cssText = 'margin:6px 0;padding:6px 10px;border-left:3px solid #4a89dc;';
      const head = document.createElement('div');
      head.style.cssText = 'font-weight:600;';
      head.textContent = `${a.id || '(app)'} — ${a.executable || '(no exe)'}`;
      if (a.entryPoint === 'Windows.FullTrustApplication') {
        const warn = document.createElement('span');
        warn.style.cssText = 'margin-left:8px;color:#c15;font-weight:bold;';
        warn.textContent = '[FullTrust entry]';
        head.appendChild(warn);
      }
      li.appendChild(head);

      if (a.displayName) {
        const sub = document.createElement('div');
        sub.style.cssText = 'color:#888;font-size:0.9em;';
        sub.textContent = a.displayName;
        li.appendChild(sub);
      }

      if (a.extensions && a.extensions.length) {
        const ul = document.createElement('ul');
        ul.style.cssText = 'margin:4px 0 0 16px;font-size:0.9em;';
        for (const ex of a.extensions) {
          const eli = document.createElement('li');
          eli.textContent = this._fmtExtension(ex);
          if (ex.severity === 'high' || ex.severity === 'medium') {
            eli.style.color = ex.severity === 'high' ? '#c15' : '#b25000';
          }
          ul.appendChild(eli);
        }
        li.appendChild(ul);
      }
      sec.appendChild(li);
    }
    return sec;
  }

  _fmtExtension(ex) {
    switch (ex.category) {
      case 'windows.fullTrustProcess':
        return `fullTrustProcess: ${ex.executable || '(no exe)'}`;
      case 'windows.startupTask':
        return `startupTask: ${ex.taskId || ''} (${ex.enabled === true ? 'enabled' : 'disabled'}) → ${ex.executable || ex.displayName || ''}`;
      case 'windows.appExecutionAlias':
        return `appExecutionAlias: ${(ex.aliases || []).join(', ') || '(empty)'}`;
      case 'windows.protocol':
        return `protocol handler: ${(ex.protocols || []).join(', ')}`;
      case 'windows.fileTypeAssociation':
        return `fileTypeAssociation: ${(ex.fileTypes || []).join(', ')} (${ex.name || ''})`;
      case 'windows.service':
        return `service: ${ex.executable || '(no exe)'}`;
      case 'windows.backgroundTasks':
        return `backgroundTask: ${(ex.triggers || []).join(', ')} → ${ex.entryPoint || ex.executable || ''}`;
      case 'windows.comServer':
      case 'windows.comInterface':
      case 'com.Extension':
        return `COM extension (${ex.category})`;
      default:
        return ex.category + (ex.executable ? ` → ${ex.executable}` : '');
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Bundle inner-package list
  // ═══════════════════════════════════════════════════════════════════════
  _buildBundleList(pkgs) {
    const sec = document.createElement('div'); sec.className = 'clickonce-section';
    const h = document.createElement('h3'); h.textContent = `Bundled Packages (${pkgs.length})`;
    sec.appendChild(h);
    const ul = document.createElement('ul'); ul.className = 'clickonce-dep-list';
    for (const p of pkgs.slice(0, 200)) {
      const li = document.createElement('li');
      const size = p.size ? `  — ${this._fmtBytes(p.size)}` : '';
      li.textContent = `[${p.type || 'application'}] ${p.fileName || '(no filename)'}${p.architecture ? '  ' + p.architecture : ''}${p.resourceId ? '  resource:' + p.resourceId : ''}${size}`;
      ul.appendChild(li);
    }
    sec.appendChild(ul);
    return sec;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // File tree — reuses zip-table styling and the `open-inner-file` event
  // ═══════════════════════════════════════════════════════════════════════
  async _buildFileTree(zip, wrap) {
    const sec = document.createElement('div'); sec.className = 'clickonce-section';
    const h = document.createElement('h3'); h.textContent = 'Package Contents';
    sec.appendChild(h);

    const entries = [];
    // Aggregate archive-expansion budget shared across every renderer in
    // the recursive drill-down chain (H5). When exhausted we stop pushing
    // entries and surface a small notice in this section.
    const aggBudget = (typeof window !== 'undefined' && window.app)
      ? window.app._archiveBudget
      : null;
    let aggExhausted = false;
    // Cap package entry enumeration at PARSER_LIMITS.MAX_ENTRIES to keep a
    // hostile MSIX / APPX (hand-crafted 1 M-entry central directory) from
    // chewing through the main thread here — the rest of the renderer is
    // fine, we just don't want to materialise every entry descriptor.
    zip.forEach((path, entry) => {
      if (entries.length >= PARSER_LIMITS.MAX_ENTRIES) return;
      const uncompSize = entry._data ? (entry._data.uncompressedSize || 0) : 0;
      const compSize = entry._data ? (entry._data.compressedSize || 0) : 0;
      if (aggBudget && !aggBudget.consume(1, uncompSize)) { aggExhausted = true; return; }
      entries.push({ path, dir: entry.dir, size: uncompSize, compressed: compSize, date: entry.date || null });
    });
    if (aggExhausted && aggBudget && aggBudget.exhausted) {
      const warn = document.createElement('div');
      warn.className = 'zip-warning zip-warning-high';
      warn.textContent = `⚠ ${aggBudget.reason}`;
      sec.appendChild(warn);
    }

    // Shared ArchiveTree component — tree + flat + search + column sort.
    const EXEC_EXTS = new Set(['exe', 'dll', 'scr', 'sys', 'msi', 'ps1', 'bat', 'cmd', 'vbs', 'js', 'hta']);
    const tree = ArchiveTree.render({
      entries,
      execExts: EXEC_EXTS,
      showCompressed: true,
      showDate: true,
      onOpen: async (entry) => {
        try {
          const data = await zip.file(entry.path).async('arraybuffer');
          const name = entry.path.split('/').pop();
          const file = new File([data], name, { type: 'application/octet-stream' });
          wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
        } catch (err) {
          console.warn('Failed to extract from MSIX:', entry.path, err && err.message);
        }
      },
      expandAll: 'auto',
    });
    sec.appendChild(tree);
    return sec;
  }


  // ═══════════════════════════════════════════════════════════════════════
  // Security analysis
  // ═══════════════════════════════════════════════════════════════════════
  async analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: [],
      msixInfo: null,
    };
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const isZip = bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04;

    let parsed;
    let manifestText = '';
    if (isZip) {
      try {
        const zip = await JSZip.loadAsync(buffer);
        const hasBundle = !!zip.file('AppxBundleManifest.xml') || !!zip.file('AppxMetadata/AppxBundleManifest.xml');
        const manifestPath = hasBundle
          ? (zip.file('AppxBundleManifest.xml') ? 'AppxBundleManifest.xml' : 'AppxMetadata/AppxBundleManifest.xml')
          : (zip.file('AppxManifest.xml') ? 'AppxManifest.xml' : null);
        if (manifestPath) manifestText = await zip.file(manifestPath).async('string');
        parsed = this._parseManifest(manifestText, hasBundle);
        parsed.hasSignature = !!zip.file('AppxSignature.p7x');
        parsed.hasCodeIntegrityCat = !!zip.file('AppxMetadata/CodeIntegrity.cat');
        parsed.hasBlockMap = !!zip.file('AppxBlockMap.xml');
        parsed.containerKind = hasBundle ? 'bundle' : 'package';
        // Mirror the render path: decorate with parsed p7x + computed
        // PublisherId so `_assess` (called below) emits the same
        // signer-mismatch / malformed-envelope risks here that the
        // summary card surfaces in the renderer.
        try { parsed.signature = await this._loadP7x(zip); } catch (_) { parsed.signature = null; }
        if (parsed.identity && parsed.identity.publisher) {
          try {
            parsed.publisherIdComputed = await this._computePublisherId(parsed.identity.publisher);
          } catch (_) { parsed.publisherIdComputed = null; }
          parsed.publisherDN = this._parsePublisherDN(parsed.identity.publisher);
        }
      } catch (e) {
        parsed = { containerKind: 'package', capabilities: [], applications: [] };
      }

    } else {
      manifestText = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      parsed = this._parseAppInstaller(manifestText);
      parsed.containerKind = 'appinstaller';
    }
    f.msixInfo = parsed;

    // ── Metadata for the generic Summary block ────────────────────────
    const md = f.metadata;
    md['Format'] = parsed.containerKind === 'bundle' ? 'MSIX/APPX Bundle'
                 : parsed.containerKind === 'package' ? 'MSIX/APPX Package'
                 : 'App Installer File';
    if (parsed.identity) md['Package Identity'] = this._fmtIdentity(parsed.identity);
    if (parsed.identity && parsed.identity.publisher) md['Publisher'] = parsed.identity.publisher;
    if (parsed.identity && parsed.identity.version) md['Version'] = parsed.identity.version;
    if (parsed.identity && parsed.identity.processorArchitecture) md['Architecture'] = parsed.identity.processorArchitecture;
    if (parsed.properties && parsed.properties.publisherDisplayName) md['Publisher (Display)'] = parsed.properties.publisherDisplayName;
    if (parsed.properties && parsed.properties.displayName) md['Display Name'] = parsed.properties.displayName;
    if (parsed.targetDeviceFamilies && parsed.targetDeviceFamilies.length) {
      md['Target Device Families'] = parsed.targetDeviceFamilies.map(t => t.name).join(', ');
    }
    if (parsed.containerKind === 'package' || parsed.containerKind === 'bundle') {
      md['Signed'] = parsed.hasSignature ? 'Yes (AppxSignature.p7x)' : 'No';
      // Surface the parsed signer Subject + the computed PublisherId so
      // they show up in the generic Summary block alongside everything
      // else, not just inside the renderer's bespoke MSIX card.
      if (parsed.signature && parsed.signature.signerCN) md['Signer CN (p7x)'] = parsed.signature.signerCN;
      if (parsed.signature && parsed.signature.signerO)  md['Signer O (p7x)']  = parsed.signature.signerO;
      if (parsed.publisherIdComputed) md['Publisher ID (computed)'] = parsed.publisherIdComputed;
      if (parsed.signature && parsed.signature.signerCN && parsed.publisherDN && parsed.publisherDN.cn) {
        const matches = parsed.publisherDN.cn.trim().toLowerCase() === parsed.signature.signerCN.trim().toLowerCase();
        md['Signer ↔ Manifest CN'] = matches ? 'match' : 'mismatch';
      }
    }

    if (parsed.capabilities && parsed.capabilities.length) {
      md['Capabilities'] = String(parsed.capabilities.length);
    }
    if (parsed.applications && parsed.applications.length) {
      const names = parsed.applications.map(a => a.executable || a.id).filter(Boolean);
      md['Entry Points'] = names.join(', ');
    }
    if (parsed.containerKind === 'appinstaller' && parsed.mainPackage && parsed.mainPackage.uri) {
      md['Main Package Uri'] = parsed.mainPackage.uri;
    }

    // ── Risk assessment ────────────────────────────────────────────────
    const risks = this._assess(parsed);
    const locate = (needle) => {
      if (!needle || !manifestText) return null;
      const idx = manifestText.indexOf(needle);
      return idx === -1 ? null : { offset: idx, length: needle.length };
    };
    let score = 0;
    for (const r of risks) {
      const ref = { type: IOC.PATTERN, url: r.msg, severity: r.sev };
      if (r.highlight) {
        ref._highlightText = r.highlight;
        const loc = locate(r.highlight);
        if (loc) { ref._sourceOffset = loc.offset; ref._sourceLength = loc.length; }
      }
      f.externalRefs.push(ref);
      if (r.sev === 'high') score += 3;
      else if (r.sev === 'medium') score += 1.5;
      else score += 0.5;
    }

    // ── URL IOCs from the manifest ────────────────────────────────────
    const urls = new Set();
    if (parsed.uri) urls.add(parsed.uri);
    if (parsed.mainPackage && parsed.mainPackage.uri) urls.add(parsed.mainPackage.uri);
    if (parsed.mainBundle && parsed.mainBundle.uri) urls.add(parsed.mainBundle.uri);
    for (const d of (parsed.dependencies || [])) if (d.uri) urls.add(d.uri);
    for (const u of urls) {
      if (!/^https?:\/\//i.test(u)) continue;
      const sev = /^http:\/\//i.test(u) ? 'medium' : 'info';
      const ref = { type: IOC.URL, url: u, severity: sev };
      const loc = locate(u);
      if (loc) { ref._sourceOffset = loc.offset; ref._sourceLength = loc.length; }
      f.externalRefs.push(ref);
    }

    // ── Per-capability and per-alias entries in interestingStrings ────
    f.interestingStrings = f.interestingStrings || [];
    for (const c of (parsed.capabilities || [])) {
      const sev = this._capSeverity(c);
      if (sev === 'high' || sev === 'medium') {
        f.interestingStrings.push({
          type: IOC.PATTERN,
          url: `${c.restricted ? 'rescap' : 'capability'}: ${c.name}`,
          severity: sev,
        });
      }
    }
    for (const a of (parsed.applications || [])) {
      for (const ex of (a.extensions || [])) {
        if (ex.category === 'windows.appExecutionAlias' && ex.aliases) {
          for (const al of ex.aliases) {
            if (MsixRenderer.ALIAS_HIJACK_NAMES.has(al.toLowerCase())) {
              f.interestingStrings.push({
                type: IOC.PATTERN,
                url: `AppExecutionAlias hijack: ${al}`,
                severity: 'high',
              });
            }
          }
        }
      }
    }

    // Critical bucket aligns this renderer's tiering with inf / reg / pdf /
    // jar, which all escalate to 'critical' once multiple unambiguously
    // high-severity indicators stack (e.g. runFullTrust + silent install +
    // HTTP MainPackage Uri + fullTrustProcess helper + AppExecutionAlias
    // hijack). Without the critical bucket, those stacks topped out at
    // 'high', visibly under-calling peer formats.
    if (score >= 8) escalateRisk(f, 'critical');
    else if (score >= 5) escalateRisk(f, 'high');
    else if (score >= 2) escalateRisk(f, 'medium');
    else escalateRisk(f, 'low');

    // Mirror classic-pivot metadata into the IOC table. Publisher DN +
    // computed PublisherId are the two fields every incident responder
    // pivots on for MSIX packages.
    mirrorMetadataIOCs(f, {
      'Publisher':              IOC.PATTERN,
      'Publisher ID (computed)': IOC.PATTERN,
      'Signer CN (p7x)':        IOC.PATTERN,
    });

    return f;
  }


  // ═══════════════════════════════════════════════════════════════════════
  // AppxManifest.xml / AppxBundleManifest.xml parser
  // Uses getElementsByTagNameNS('*', local) to dodge the `uap/uap3/desktop/
  // rescap/com` namespace-prefix swamp.
  // ═══════════════════════════════════════════════════════════════════════
  _parseManifest(text, isBundle) {
    const parsed = {
      identity: null,
      properties: null,
      targetDeviceFamilies: [],
      capabilities: [],
      applications: [],
      dependencies: [],
      bundlePackages: [],
      raw: text || '',
    };
    if (!text) return parsed;

    let doc;
    try { doc = new DOMParser().parseFromString(text, 'application/xml'); }
    catch (e) { return parsed; }
    if (doc.getElementsByTagName('parsererror')[0]) return parsed;

    const root = doc.documentElement;
    if (!root) return parsed;

    const first = (parent, local) => {
      if (!parent) return null;
      const els = parent.getElementsByTagNameNS('*', local);
      return els.length ? els[0] : null;
    };
    const all = (parent, local) => {
      if (!parent) return [];
      return Array.from(parent.getElementsByTagNameNS('*', local));
    };
    const attr = (el, name) => (el && el.getAttribute(name)) || null;

    // ── Identity ──────────────────────────────────────────────────────
    const idEl = first(root, 'Identity');
    if (idEl) {
      parsed.identity = {
        name: attr(idEl, 'Name'),
        publisher: attr(idEl, 'Publisher'),
        version: attr(idEl, 'Version'),
        processorArchitecture: attr(idEl, 'ProcessorArchitecture'),
        resourceId: attr(idEl, 'ResourceId'),
      };
    }

    // ── Properties ────────────────────────────────────────────────────
    const propsEl = first(root, 'Properties');
    if (propsEl) {
      const getText = (name) => {
        const el = first(propsEl, name);
        return el ? el.textContent.trim() : null;
      };
      parsed.properties = {
        displayName: getText('DisplayName'),
        publisherDisplayName: getText('PublisherDisplayName'),
        logo: getText('Logo'),
        description: getText('Description'),
      };
    }

    // ── Dependencies → TargetDeviceFamily ────────────────────────────
    for (const t of all(root, 'TargetDeviceFamily')) {
      parsed.targetDeviceFamilies.push({
        name: attr(t, 'Name'),
        minVersion: attr(t, 'MinVersion'),
        maxVersionTested: attr(t, 'MaxVersionTested'),
      });
    }

    // ── Capabilities (general / rescap / device) ──────────────────────
    const capsEl = first(root, 'Capabilities');
    if (capsEl) {
      for (const c of Array.from(capsEl.children)) {
        const local = c.localName;                 // Capability | DeviceCapability
        const prefix = (c.prefix || '').toLowerCase();
        parsed.capabilities.push({
          name: attr(c, 'Name'),
          restricted: prefix === 'rescap',
          device: local === 'DeviceCapability',
          custom: local === 'CustomCapability',
          raw: (c.prefix ? c.prefix + ':' : '') + local,
        });
      }
    }

    // ── Applications → Entry points + Extensions ─────────────────────
    for (const a of all(root, 'Application')) {
      const app = {
        id: attr(a, 'Id'),
        executable: attr(a, 'Executable'),
        entryPoint: attr(a, 'EntryPoint'),
        startPage: attr(a, 'StartPage'),
        displayName: null,
        extensions: [],
      };
      const visual = first(a, 'VisualElements');
      if (visual) app.displayName = attr(visual, 'DisplayName') || attr(visual, 'displayName');

      const extsEl = first(a, 'Extensions');
      if (extsEl) {
        for (const ex of Array.from(extsEl.children)) {
          if (ex.localName !== 'Extension') continue;
          app.extensions.push(this._parseExtension(ex, first, all, attr));
        }
      }
      parsed.applications.push(app);
    }

    // ── Bundle package list (only present when isBundle) ─────────────
    if (isBundle) {
      for (const p of all(root, 'Package')) {
        // The bundle manifest's <Package> under <Packages> carries these
        // attributes; filter out any stray <Package> elsewhere.
        if (!p.hasAttribute('FileName')) continue;
        parsed.bundlePackages.push({
          type: attr(p, 'Type'),
          fileName: attr(p, 'FileName'),
          architecture: attr(p, 'Architecture'),
          resourceId: attr(p, 'ResourceId'),
          version: attr(p, 'Version'),
          size: Number(attr(p, 'Size') || 0) || null,
          offset: attr(p, 'Offset'),
        });
      }
    }

    return parsed;
  }

  // ── Flatten one <Extension Category="…">  into a normalised record ───
  _parseExtension(ex, first, all, attr) {
    const category = attr(ex, 'Category') || ex.localName;
    const rec = { category, raw: ex.outerHTML && ex.outerHTML.slice(0, 240) || '' };

    switch (category) {
      case 'windows.fullTrustProcess': {
        rec.executable = attr(ex, 'Executable');
        rec.severity = 'high';
        break;
      }
      case 'windows.startupTask': {
        // <uap5:Extension Category="windows.startupTask"><uap5:StartupTask .../></uap5:Extension>
        const st = first(ex, 'StartupTask');
        rec.taskId = st ? attr(st, 'TaskId') : null;
        rec.enabled = st ? (attr(st, 'Enabled') === 'true') : null;
        rec.displayName = st ? attr(st, 'DisplayName') : null;
        rec.executable = attr(ex, 'Executable') || (st ? attr(st, 'Executable') : null);
        rec.severity = 'medium';
        break;
      }
      case 'windows.appExecutionAlias': {
        const aliases = [];
        for (const a of all(ex, 'ExecutionAlias')) {
          const n = attr(a, 'Alias');
          if (n) aliases.push(n);
        }
        rec.aliases = aliases;
        const hijack = aliases.some(a => MsixRenderer.ALIAS_HIJACK_NAMES.has(a.toLowerCase()));
        rec.severity = hijack ? 'high' : 'medium';
        break;
      }
      case 'windows.protocol': {
        const protos = [];
        for (const p of all(ex, 'Protocol')) {
          const n = attr(p, 'Name');
          if (n) protos.push(n);
        }
        rec.protocols = protos;
        // Claiming a well-known scheme (http/https/ftp/file) is unusual.
        const suspicious = protos.some(p => ['http', 'https', 'ftp', 'file', 'ms-appinstaller'].includes(p.toLowerCase()));
        rec.severity = suspicious ? 'high' : 'low';
        break;
      }
      case 'windows.fileTypeAssociation': {
        const fta = first(ex, 'FileTypeAssociation');
        rec.name = fta ? attr(fta, 'Name') : null;
        const types = [];
        for (const t of all(ex, 'FileType')) {
          const v = t.textContent && t.textContent.trim();
          if (v) types.push(v);
        }
        rec.fileTypes = types;
        rec.severity = 'low';
        break;
      }
      case 'windows.service': {
        rec.executable = attr(ex, 'Executable');
        rec.severity = 'medium';
        break;
      }
      case 'windows.backgroundTasks': {
        const triggers = [];
        for (const t of all(ex, 'Task')) {
          const v = attr(t, 'Type');
          if (v) triggers.push(v);
        }
        rec.triggers = triggers;
        rec.entryPoint = attr(ex, 'EntryPoint');
        rec.executable = attr(ex, 'Executable');
        rec.severity = 'low';
        break;
      }
      case 'com.Extension':
      case 'windows.comServer':
      case 'windows.comInterface': {
        rec.executable = attr(ex, 'Executable');
        rec.severity = 'medium';
        break;
      }
      default:
        rec.executable = attr(ex, 'Executable');
        rec.entryPoint = attr(ex, 'EntryPoint');
        rec.severity = 'low';
    }
    return rec;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // AppInstaller XML parser
  // ═══════════════════════════════════════════════════════════════════════
  _parseAppInstaller(text) {
    const parsed = {
      uri: null,
      version: null,
      identity: null,          // mirror of mainPackage for generic summary rendering
      properties: null,
      mainPackage: null,
      mainBundle: null,
      dependencies: [],
      updateSettings: null,
      raw: text || '',
    };
    if (!text) return parsed;

    let doc;
    try { doc = new DOMParser().parseFromString(text, 'application/xml'); }
    catch (e) { return parsed; }
    if (doc.getElementsByTagName('parsererror')[0]) return parsed;

    const root = doc.documentElement;
    if (!root) return parsed;

    const first = (parent, local) => {
      if (!parent) return null;
      const els = parent.getElementsByTagNameNS('*', local);
      return els.length ? els[0] : null;
    };
    const attr = (el, name) => (el && el.getAttribute(name)) || null;

    parsed.uri = attr(root, 'Uri');
    parsed.version = attr(root, 'Version');

    const readPkg = (el) => el ? {
      name: attr(el, 'Name'),
      publisher: attr(el, 'Publisher'),
      version: attr(el, 'Version'),
      processorArchitecture: attr(el, 'ProcessorArchitecture'),
      uri: attr(el, 'Uri'),
    } : null;

    parsed.mainPackage = readPkg(first(root, 'MainPackage'));
    parsed.mainBundle = readPkg(first(root, 'MainBundle'));
    parsed.identity = parsed.mainPackage || parsed.mainBundle;

    const depsEl = first(root, 'Dependencies');
    if (depsEl) {
      for (const p of Array.from(depsEl.children)) {
        parsed.dependencies.push(readPkg(p));
      }
    }

    const usEl = first(root, 'UpdateSettings');
    if (usEl) {
      const us = { onLaunch: null, automaticBackgroundTask: false, forceUpdateFromAnyVersion: null };
      const ol = first(usEl, 'OnLaunch');
      if (ol) {
        us.onLaunch = {
          hoursBetweenUpdateChecks: Number(attr(ol, 'HoursBetweenUpdateChecks') || 0) || null,
          updateBlocksActivation: attr(ol, 'UpdateBlocksActivation') === 'true',
          showPrompt: attr(ol, 'ShowPrompt') === null ? null : attr(ol, 'ShowPrompt') === 'true',
        };
      }
      if (first(usEl, 'AutomaticBackgroundTask')) us.automaticBackgroundTask = true;
      const fu = first(usEl, 'ForceUpdateFromAnyVersion');
      if (fu) us.forceUpdateFromAnyVersion = (fu.textContent || '').trim().toLowerCase() === 'true';
      parsed.updateSettings = us;
    }

    return parsed;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Risk assessment — returns [{ sev, msg, highlight? }]
  // ═══════════════════════════════════════════════════════════════════════
  _assess(parsed) {
    const risks = [];

    // ── Capability-based risks (package / bundle only) ────────────────
    for (const c of (parsed.capabilities || [])) {
      if (c.restricted || MsixRenderer.RESCAP_HIGH.has(c.name)) {
        risks.push({
          sev: 'high',
          msg: `⚠ Restricted capability requested: ${c.name}${c.restricted ? ' (rescap)' : ''} — typically requires Store approval and grants unsandboxed behaviour`,
          highlight: `Name="${c.name}"`,
        });
      } else if (MsixRenderer.DEVCAP_MEDIUM.has(c.name)) {
        risks.push({
          sev: 'medium',
          msg: `Broad user-data capability: ${c.name}`,
          highlight: `Name="${c.name}"`,
        });
      }
    }

    // ── Per-application extensions ────────────────────────────────────
    for (const a of (parsed.applications || [])) {
      if (a.entryPoint === 'Windows.FullTrustApplication') {
        risks.push({
          sev: 'high',
          msg: `⚠ Application "${a.id || '?'}" uses EntryPoint="Windows.FullTrustApplication" — bypasses the AppContainer sandbox`,
          highlight: 'Windows.FullTrustApplication',
        });
      }
      for (const ex of (a.extensions || [])) {
        if (ex.category === 'windows.fullTrustProcess') {
          risks.push({
            sev: 'high',
            msg: `⚠ fullTrustProcess extension spawns helper "${ex.executable || '(no exe)'}" outside the sandbox`,
            highlight: ex.executable || 'windows.fullTrustProcess',
          });
        }
        if (ex.category === 'windows.startupTask' && ex.enabled === true) {
          risks.push({
            sev: 'medium',
            msg: `startupTask "${ex.taskId || '?'}" launches automatically on sign-in`,
            highlight: ex.taskId ? `TaskId="${ex.taskId}"` : 'windows.startupTask',
          });
        }
        if (ex.category === 'windows.appExecutionAlias' && ex.aliases) {
          for (const al of ex.aliases) {
            if (MsixRenderer.ALIAS_HIJACK_NAMES.has(al.toLowerCase())) {
              risks.push({
                sev: 'high',
                msg: `⚠ AppExecutionAlias claims "${al}" — hijacks a common CLI name on PATH`,
                highlight: `Alias="${al}"`,
              });
            }
          }
        }
        if (ex.category === 'windows.protocol' && ex.protocols) {
          for (const p of ex.protocols) {
            const lp = p.toLowerCase();
            if (['http', 'https', 'ftp', 'file'].includes(lp)) {
              risks.push({
                sev: 'high',
                msg: `⚠ Claims the "${p}" protocol handler — would be invoked for all ${p}:// links`,
                highlight: `Name="${p}"`,
              });
            } else if (lp === 'ms-appinstaller') {
              risks.push({
                sev: 'medium',
                msg: `Claims the "ms-appinstaller" protocol — mirrors CVE-2021-43890-style handler hijack`,
                highlight: `Name="${p}"`,
              });
            }
          }
        }
      }
    }

    // ── App-Installer risks ───────────────────────────────────────────
    const pkgUri = (parsed.mainPackage && parsed.mainPackage.uri) || (parsed.mainBundle && parsed.mainBundle.uri) || null;
    if (pkgUri && /^http:\/\//i.test(pkgUri)) {
      risks.push({
        sev: 'high',
        msg: '⚠ MainPackage/MainBundle Uri is plain HTTP — MITM swap on first install and every auto-update',
        highlight: pkgUri,
      });
    }
    if (pkgUri && MsixRenderer.SUSPICIOUS_HOST_RE.test(pkgUri)) {
      risks.push({
        sev: 'high',
        msg: 'MainPackage/MainBundle Uri points to a low-reputation / tunnelling host',
        highlight: pkgUri,
      });
    }
    if (parsed.uri && /^http:\/\//i.test(parsed.uri)) {
      risks.push({
        sev: 'medium',
        msg: 'App Installer Uri itself is HTTP (auto-update channel can be swapped)',
        highlight: parsed.uri,
      });
    }
    if (parsed.updateSettings && parsed.updateSettings.onLaunch && parsed.updateSettings.onLaunch.showPrompt === false) {
      risks.push({
        sev: 'medium',
        msg: 'OnLaunch auto-update has ShowPrompt="false" — updates apply silently without user confirmation',
        highlight: 'ShowPrompt="false"',
      });
    }
    if (parsed.updateSettings && parsed.updateSettings.forceUpdateFromAnyVersion === true) {
      risks.push({
        sev: 'medium',
        msg: 'ForceUpdateFromAnyVersion="true" — any prior version is forcibly replaced',
        highlight: 'ForceUpdateFromAnyVersion',
      });
    }
    for (const d of (parsed.dependencies || [])) {
      if (d && d.uri && /^http:\/\//i.test(d.uri)) {
        risks.push({
          sev: 'medium',
          msg: `Dependency "${d.name || '?'}" uses plain-HTTP Uri`,
          highlight: d.uri,
        });
      }
    }

    // ── Signature absence (package / bundle only) ─────────────────────
    if ((parsed.containerKind === 'package' || parsed.containerKind === 'bundle') && parsed.hasSignature === false) {
      risks.push({
        sev: 'medium',
        msg: 'Package is unsigned (no AppxSignature.p7x) — cannot be installed without developer mode / sideload policy',
      });
    }

    // ── AppxSignature.p7x conformity (parsed by _parseP7x) ────────────
    // These three checks turn the DER token-scan results into actionable
    // risks: a present-but-broken signature is more suspicious than no
    // signature at all (which is just sideload-only), a non-Appx PKCS#7
    // payload masquerading as a p7x is a tell for cribbed / repackaged
    // signatures, and a signer-CN that doesn't match the manifest's
    // Identity/@Publisher CN is the canonical re-sign / repackage tell.
    const sig = parsed.signature;
    if (sig && sig.present) {
      if (sig.hasPkcxMagic === false) {
        risks.push({
          sev: 'high',
          msg: '⚠ AppxSignature.p7x is present but missing the "PKCX" magic header — signature envelope is malformed or stubbed',
        });
      }
      if (sig.hasPkcxMagic && sig.hasAppxSipInfo === false) {
        risks.push({
          sev: 'medium',
          msg: 'AppxSignature.p7x lacks the AppxSipInfo OID (1.3.6.1.4.1.311.84.2.1) — payload is not a real Appx SIP signature',
        });
      }
      if (sig.signerCN && parsed.publisherDN && parsed.publisherDN.cn) {
        const manifestCN = parsed.publisherDN.cn.trim().toLowerCase();
        const signerCN = sig.signerCN.trim().toLowerCase();
        if (manifestCN !== signerCN) {
          risks.push({
            sev: 'high',
            msg: `⚠ Signer CN "${sig.signerCN}" does not match manifest Identity/@Publisher CN "${parsed.publisherDN.cn}" — package was re-signed or repackaged`,
            highlight: parsed.publisherDN.cn ? `CN=${parsed.publisherDN.cn}` : null,
          });
        }
      }
    }

    return risks;
  }


  // ═══════════════════════════════════════════════════════════════════════
  // AppxSignature.p7x parser (DER token scan)
  //
  // The p7x envelope layout (per the Windows SDK / `MakeAppx sign`) is:
  //   offset 0..3  : ASCII "PKCX" magic
  //   offset 4..   : DER-encoded PKCS#7 SignedData (ContentInfo)
  // Rather than implement a real ASN.1 walker we scan the body for a small
  // set of well-known OID byte sequences. This is enough to answer the
  // three questions the summary card cares about:
  //   1. Is this actually an Appx signature? → AppxSipInfo OID present.
  //   2. Who did Windows think signed it?     → id-at-commonName under the
  //      first Name structure (the signer's Subject CN).
  //   3. Does it look structurally plausible? → PKCX magic + SpcIndirectData.
  // The scan is deliberately conservative: missing OIDs flip the
  // corresponding bool but never throw, so a stub / synthetic p7x (the
  // examples/msix/example.msix sample is literally `PKCX\0PKCX\0…`) still
  // decorates cleanly without poisoning the render pipeline.
  //
  // Returned record:
  //   { present: bool,
  //     hasPkcxMagic: bool,
  //     hasSpcIndirectData: bool,
  //     hasAppxSipInfo: bool,
  //     signerCN: string | null,
  //     signerO:  string | null,
  //     size: bytes.length }
  // ═══════════════════════════════════════════════════════════════════════
  _parseP7x(bytes) {
    const out = {
      present: !!(bytes && bytes.length),
      hasPkcxMagic: false,
      hasSpcIndirectData: false,
      hasAppxSipInfo: false,
      signerCN: null,
      signerO: null,
      size: bytes ? bytes.length : 0,
    };
    if (!out.present) return out;

    // PKCX magic (4 bytes, ASCII).
    const M = MsixRenderer.P7X_MAGIC;
    out.hasPkcxMagic = bytes.length >= 4 &&
      bytes[0] === M[0] && bytes[1] === M[1] &&
      bytes[2] === M[2] && bytes[3] === M[3];

    // indexOfBytes: cheap Boyer-Moore-style scan over Uint8Array for a
    // short DER OID pattern. OIDs we look for are 3–10 bytes; we don't
    // need anything fancy.
    const indexOfBytes = (needle, from) => {
      const haystack = bytes;
      const nLen = needle.length;
      const hLen = haystack.length;
      for (let i = from; i + nLen <= hLen; i++) {
        let match = true;
        for (let j = 0; j < nLen; j++) {
          if (haystack[i + j] !== needle[j]) { match = false; break; }
        }
        if (match) return i;
      }
      return -1;
    };

    out.hasSpcIndirectData = indexOfBytes(MsixRenderer.OID_SPC_INDIRECT_DATA, 0) !== -1;
    out.hasAppxSipInfo     = indexOfBytes(MsixRenderer.OID_APPX_SIP_INFO, 0)    !== -1;

    // Extract the first Subject CN / O by walking every CN / O OID and
    // reading the immediately-following tagged string. The DER encoding
    // for an AttributeTypeAndValue is:
    //   SEQUENCE { OID id-at-commonName, DirectoryString "Contoso…" }
    // so the string tag (UTF8String 0x0C / PrintableString 0x13 /
    // TeletexString 0x14 / BMPString 0x1E) lands two bytes after the
    // OID-value end (OID tag 0x06 + length byte + N OID bytes +
    // string-tag + string-length + N string bytes).
    const readStringAfterOid = (oidBytes) => {
      let pos = 0;
      while (pos < bytes.length) {
        const hit = indexOfBytes(oidBytes, pos);
        if (hit === -1) return null;
        // The byte before the OID bytes is the OID length; the byte
        // before that is the OID tag (0x06). If that isn't 0x06 we're
        // inside an unrelated structure — skip past this hit and
        // continue scanning.
        if (hit < 2 || bytes[hit - 2] !== 0x06 || bytes[hit - 1] !== oidBytes.length) {
          pos = hit + 1;
          continue;
        }
        const valStart = hit + oidBytes.length;
        if (valStart + 2 > bytes.length) return null;
        const strTag = bytes[valStart];
        // Directory-string tag set the signer Name may use (PrintableString,
        // UTF8String, TeletexString, BMPString, IA5String).
        if (![0x0C, 0x13, 0x14, 0x1E, 0x16].includes(strTag)) {
          pos = hit + 1;
          continue;
        }
        let strLen = bytes[valStart + 1];
        let strBodyStart = valStart + 2;
        // Long-form length (0x81 / 0x82) — very common for long CNs.
        if (strLen === 0x81) {
          if (strBodyStart >= bytes.length) return null;
          strLen = bytes[strBodyStart];
          strBodyStart += 1;
        } else if (strLen === 0x82) {
          if (strBodyStart + 1 >= bytes.length) return null;
          strLen = (bytes[strBodyStart] << 8) | bytes[strBodyStart + 1];
          strBodyStart += 2;
        } else if (strLen > 0x80) {
          // Longer than 2-byte lengths are possible but vanishingly rare
          // for directory strings; skip and keep scanning.
          pos = hit + 1;
          continue;
        }
        const strEnd = strBodyStart + strLen;
        if (strEnd > bytes.length || strLen === 0 || strLen > 256) {
          pos = hit + 1;
          continue;
        }
        // BMPString is big-endian UTF-16; everything else is effectively
        // ASCII / UTF-8 for the purposes of a Subject CN.
        let str;
        if (strTag === 0x1E) {
          let s = '';
          for (let i = strBodyStart; i + 1 < strEnd; i += 2) {
            s += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
          }
          str = s;
        } else {
          str = new TextDecoder('utf-8', { fatal: false }).decode(
            bytes.subarray(strBodyStart, strEnd),
          );
        }
        return str;
      }
      return null;
    };

    try { out.signerCN = readStringAfterOid(MsixRenderer.OID_AT_COMMON_NAME); } catch (_) { }
    try { out.signerO  = readStringAfterOid(MsixRenderer.OID_AT_ORGANIZATION); } catch (_) { }

    return out;
  }

  // Extract `CN=…` / `O=…` from an MSIX Identity/@Publisher DN string so
  // we can compare against the signer certificate's Subject fields. The
  // format is a comma-separated RFC 2253-ish DN; individual AVA values
  // may be quoted or backslash-escaped. We keep this deliberately lax.
  _parsePublisherDN(publisher) {
    const out = { cn: null, o: null, ou: null, c: null };
    if (!publisher) return out;
    // Strip surrounding whitespace; split on unescaped commas.
    const parts = [];
    let buf = '';
    let esc = false;
    for (const ch of publisher) {
      if (esc) { buf += ch; esc = false; continue; }
      if (ch === '\\') { esc = true; continue; }
      if (ch === ',') { parts.push(buf); buf = ''; continue; }
      buf += ch;
    }
    if (buf) parts.push(buf);
    for (const p of parts) {
      const m = p.trim().match(/^([A-Za-z]+)\s*=\s*(.+)$/);
      if (!m) continue;
      const key = m[1].toLowerCase();
      let val = m[2].trim();
      if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
      if (key === 'cn') out.cn = val;
      else if (key === 'o') out.o = val;
      else if (key === 'ou') out.ou = val;
      else if (key === 'c') out.c = val;
    }
    return out;
  }

  // Windows PackageFamilyName publisher-ID derivation:
  //   1. Encode the Identity/@Publisher DN as UTF-16 little-endian.
  //   2. SHA-256 it, take the first 8 bytes.
  //   3. Pack those 64 bits + one trailing zero bit into a 65-bit
  //      stream, then split into 13 groups of 5 bits. Each group
  //      indexes into PUBLISHER_ID_ALPHA to give the canonical
  //      13-character Publisher ID printed in every package family
  //      name (e.g. Contoso.Demo_8wekyb3d8bbwe).
  // This is what you'd compare against a `PackageFamilyName`, a p7x
  // signer CN, or the `Name` → `PackageId` resolution Windows does at
  // install time. Returns null on crypto.subtle failure.
  async _computePublisherId(publisher) {
    if (!publisher || !crypto || !crypto.subtle) return null;
    try {
      // Encode as UTF-16LE — no BOM.
      const buf = new Uint8Array(publisher.length * 2);
      for (let i = 0; i < publisher.length; i++) {
        const code = publisher.charCodeAt(i);
        buf[i * 2] = code & 0xFF;
        buf[i * 2 + 1] = (code >> 8) & 0xFF;
      }
      const hashBuf = await crypto.subtle.digest('SHA-256', buf);
      const hash = new Uint8Array(hashBuf).subarray(0, 8);

      // Build a 65-bit string: 64 bits of the hash + one trailing 0 bit.
      let bits = '';
      for (let i = 0; i < 8; i++) bits += hash[i].toString(2).padStart(8, '0');
      bits += '0';

      // 13 × 5-bit groups.
      let id = '';
      for (let i = 0; i < 65; i += 5) {
        const group = parseInt(bits.substr(i, 5), 2);
        id += MsixRenderer.PUBLISHER_ID_ALPHA.charAt(group);
      }
      return id;
    } catch (_) { return null; }
  }

  // Convenience wrapper — load AppxSignature.p7x from an open JSZip and
  // pass the bytes through `_parseP7x`. Returns `null` (not "absent")
  // when the entry isn't in the zip so callers can distinguish "no
  // signature file" from "signature present but malformed".
  async _loadP7x(zip) {
    if (!zip) return null;
    const entry = zip.file('AppxSignature.p7x');
    if (!entry) return null;
    try {
      const buf = await entry.async('arraybuffer');
      return this._parseP7x(new Uint8Array(buf));
    } catch (_) { return { present: true, malformed: true, size: 0 }; }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Helpers
  // ═══════════════════════════════════════════════════════════════════════
  _fmtIdentity(id) {
    if (!id) return '';
    const parts = [];
    if (id.name) parts.push(id.name);
    if (id.version) parts.push('v' + id.version);
    if (id.processorArchitecture) parts.push(id.processorArchitecture);
    if (id.publisher) parts.push('(' + id.publisher + ')');
    return parts.join(' ');
  }

  _fmtBytes(n) {
    if (!n && n !== 0) return '';
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
