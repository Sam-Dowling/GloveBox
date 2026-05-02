'use strict';
// ════════════════════════════════════════════════════════════════════════════
// browserext-renderer.js — Chrome / Edge / Firefox WebExtension analyser
//
// Two input shapes are accepted — the renderer sniffs content internally:
//
//   1. Chrome / Edge extensions (.crx)
//        Cr24 magic (43 72 32 34) + version (2 or 3) + header block + ZIP.
//        v2:  pubkey_len (u32 LE) + sig_len (u32 LE) + pubkey + signature + ZIP
//        v3:  header_len (u32 LE) + protobuf header (signed data, per-key
//             signatures, claimed extension ID) + ZIP
//        We unwrap the CRX envelope to get at the inner ZIP and record the
//        signature block's presence. For v2 we additionally derive the
//        Chrome extension ID (SHA-256 of the SubjectPublicKeyInfo's first
//        16 bytes, re-coded onto the a-p alphabet). For v3 we decode the
//        protobuf `CrxFileHeader` (field 2: sha256_with_rsa, field 3:
//        sha256_with_ecdsa, field 10000: signed_header_data → SignedData
//        → field 1: crx_id (16 bytes)), compute the Chrome ID from each
//        embedded public key, and flag a "declared ≠ computed" mismatch —
//        Chromium itself aborts the install in that case.
//
//   2. Firefox XPI (.xpi) / unpacked WebExtension / packed JAR-style add-on
//        Plain ZIP. `META-INF/mozilla.rsa` and/or `META-INF/cose.sig` signal
//        an AMO-signed package. `manifest.json` at the root is the universal
//        MV2/MV3 manifest. Legacy XUL / bootstrapped add-ons instead carry
//        `install.rdf` + `chrome.manifest`; we flag those as legacy.
//
// Core detection logic is identical across both shapes: surface the
// identity, manifest_version, content scripts, host permissions and API
// permissions split by risk tier, and flag manifest-hijack patterns
// (unsafe-eval CSP, <all_urls> host grants, externally_connectable wide
// open, non-Store update_url, nativeMessaging + broad-host combos).
//
// Depends on: constants.js (IOC, escHtml), JSZip (vendor), DOMParser
// ════════════════════════════════════════════════════════════════════════════
class BrowserExtRenderer {

  // ── Permissions that meaningfully escalate the extension's reach ────
  // High-tier: these alone can exfiltrate data, install native code,
  // replay cookies, tamper with network requests, or hand the attacker a
  // debugger handle over any tab.
  static PERM_HIGH = new Set([
    'nativeMessaging',
    'debugger',
    'management',
    'proxy',
    'privacy',
    'webRequestBlocking',
    'webRequestAuthProvider',
    'declarativeNetRequestWithHostAccess',
    'enterprise.hardwarePlatform',
    'enterprise.deviceAttributes',
    'enterprise.platformKeys',
    'enterprise.networkingAttributes',
    'systemLog',
    'certificateProvider',
    'vpnProvider',
    'platformKeys',
  ]);

  // Medium-tier: sensitive data access but still sandboxed to the browser.
  static PERM_MEDIUM = new Set([
    'cookies',
    'history',
    'tabs',
    'tabCapture',
    'desktopCapture',
    'pageCapture',
    'downloads',
    'downloads.open',
    'clipboardRead',
    'clipboardWrite',
    'webRequest',
    'declarativeNetRequest',
    'declarativeWebRequest',
    'storage',
    'bookmarks',
    'topSites',
    'identity',
    'identity.email',
    'geolocation',
    'notifications',
    'system.cpu',
    'system.memory',
    'system.storage',
    'system.display',
    'processes',
    'sessions',
    'browsingData',
  ]);

  // Host-permission patterns that grant read/write access to every site
  // the user visits. Any one of these moves the extension into the
  // "effectively full-trust against the open web" bucket.
  static BROAD_HOST_PATTERNS = [
    '<all_urls>',
    '*://*/*',
    'http://*/*',
    'https://*/*',
    'file:///*',
    '*://*/',
    '<all-urls>',
  ];

  // Known-legitimate auto-update infrastructure. Anything outside this
  // list is an arbitrary update channel the attacker controls.
  static STORE_UPDATE_URL_RE =
    /^https:\/\/(?:clients2\.google\.com\/service\/update2\/crx|addons\.mozilla\.org\/|versioncheck\.addons\.mozilla\.org\/|versioncheck-bg\.addons\.mozilla\.org\/|edge\.microsoft\.com\/extensionwebstorebase\/)/i;

  // Low-reputation / tunnelling hosts copied from the MSIX / ClickOnce
  // vocabulary so we flag the same abuse patterns in both places.
  static SUSPICIOUS_HOST_RE =
    /\.(?:trycloudflare\.com|ngrok\.io|ngrok-free\.app|serveo\.net|loca\.lt|duckdns\.org|sytes\.net|zapto\.org|hopto\.org|serveftp\.com|top|xyz|tk|ml|cf|ga|gq|zip|mov|click|country|work)(?:[/:?]|$)/i;

  // ═══════════════════════════════════════════════════════════════════════
  // Entry point — shape-matches the other renderers. Wraps the whole
  // dispatch in a try/catch envelope so a malformed CRX header or an
  // unparseable manifest.json still lands on a readable fallback with a
  // best-effort `_rawText` populated for sidebar IOC / YARA scanning.
  // ═══════════════════════════════════════════════════════════════════════
  async render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const wrap = document.createElement('div');
    wrap.className = 'clickonce-view msix-view browserext-view';

    try {
      const isCrx = bytes.length >= 8 && bytes[0] === 0x43 && bytes[1] === 0x72 && bytes[2] === 0x32 && bytes[3] === 0x34;
      const isZip = bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04;

      if (isCrx) {
        const crx = this._unwrapCrx(bytes);
        if (!crx) throw new Error('CRX header could not be parsed');
        return await this._renderPackage(wrap, crx.zipBuffer, fileName, crx);
      }
      if (isZip) {
        return await this._renderPackage(wrap, buffer, fileName, null);
      }
      throw new Error('Not a .crx (Cr24) or ZIP-based (.xpi) browser extension');
    } catch (err) {
      while (wrap.firstChild) wrap.removeChild(wrap.firstChild);
      const notice = document.createElement('div');
      notice.className = 'bin-fallback-notice';
      notice.innerHTML =
        `<div class="bin-fallback-title"><strong>⚠ Browser extension parsing failed — showing raw fallback view</strong></div>` +
        `<div class="bin-fallback-reason"><code>${this._esc(err && err.message || String(err))}</code></div>` +
        `<div class="bin-fallback-sub">The package or manifest appears to be malformed, so structural analysis isn't available. ` +
        `IOC extraction and YARA rules can still run against whatever text could be decoded.</div>`;
      wrap.appendChild(notice);
      wrap._rawText = lfNormalize('');
      return wrap;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // CRX envelope unwrap — returns { zipBuffer, crxVersion, pubKeyLen,
  // sigLen, headerLen, crxId, crxV3Header? } or null on parse failure.
  // For v3 we additionally decode the protobuf `CrxFileHeader` so the
  // caller can cross-check declared_crx_id against SHA-256(SPKI).
  // ═══════════════════════════════════════════════════════════════════════
  _unwrapCrx(bytes) {
    if (bytes.length < 16) return null;
    const u32 = (o) => (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0;
    const version = u32(4);

    if (version === 2) {
      const pubKeyLen = u32(8);
      const sigLen = u32(12);
      const zipOff = 16 + pubKeyLen + sigLen;
      if (zipOff > bytes.length) return null;
      // Quick sanity check on the inner ZIP magic.
      if (!(bytes[zipOff] === 0x50 && bytes[zipOff + 1] === 0x4B &&
        bytes[zipOff + 2] === 0x03 && bytes[zipOff + 3] === 0x04)) return null;

      const pubKey = bytes.subarray(16, 16 + pubKeyLen);
      return {
        zipBuffer: bytes.slice(zipOff).buffer,
        crxVersion: 2,
        pubKeyLen,
        sigLen,
        headerLen: null,
        crxId: this._deriveChromeIdFromPubKey(pubKey),
        crxV3Header: null,
      };
    }

    if (version === 3) {
      const headerLen = u32(8);
      const zipOff = 12 + headerLen;
      if (zipOff > bytes.length) return null;
      if (!(bytes[zipOff] === 0x50 && bytes[zipOff + 1] === 0x4B &&
        bytes[zipOff + 2] === 0x03 && bytes[zipOff + 3] === 0x04)) return null;
      const headerBytes = bytes.subarray(12, 12 + headerLen);
      // Parse the protobuf envelope best-effort. Malformed headers degrade
      // to `null` here and the caller falls back to "envelope present, not
      // decodable" — we never want a bad header to kill rendering.
      let v3Header = null;
      try {
        v3Header = this._parseCrxV3Header(headerBytes);
      } catch (_) { v3Header = { malformed: true }; }
      return {
        zipBuffer: bytes.slice(zipOff).buffer,
        crxVersion: 3,
        pubKeyLen: null,
        sigLen: null,
        headerLen,
        // For v3 the declared ID comes from the protobuf-embedded
        // SignedData.crx_id; we hand it straight through so the caller
        // treats "declared" and "computed" as two distinct values.
        crxId: null,
        crxV3Header: v3Header,
      };
    }

    return null;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // CRX v3 `CrxFileHeader` protobuf decoder
  //
  // Schema (components/crx_file/crx3.proto):
  //   message AsymmetricKeyProof { bytes public_key = 1; bytes signature = 2; }
  //   message CrxFileHeader {
  //     repeated AsymmetricKeyProof sha256_with_rsa    = 2;
  //     repeated AsymmetricKeyProof sha256_with_ecdsa  = 3;
  //     optional bytes             signed_header_data = 10000;
  //   }
  //   message SignedData { optional bytes crx_id = 1; }   // 16 raw bytes
  //
  // Returns a structured record:
  //   { rsaKeys: [Uint8Array], ecdsaKeys: [Uint8Array],
  //     declaredCrxId: "abcd…" | null,
  //     declaredCrxIdBytes: Uint8Array | null,
  //     malformed: false | true,
  //     reason?: string }
  // ═══════════════════════════════════════════════════════════════════════
  _parseCrxV3Header(headerBytes) {
    if (!headerBytes || headerBytes.length === 0) {
      return {
        rsaKeys: [], ecdsaKeys: [],
        declaredCrxId: null, declaredCrxIdBytes: null,
        malformed: false, empty: true,
      };
    }
    const fields = ProtobufReader.decode(headerBytes);

    const extractKeys = (proofs) => {
      const keys = [];
      for (const proofBytes of ProtobufReader.asArray(proofs)) {
        try {
          const inner = ProtobufReader.decode(proofBytes);
          // AsymmetricKeyProof.public_key (field 1)
          const pk = inner[1];
          if (pk instanceof Uint8Array && pk.length > 0) keys.push(pk);
        } catch (_) { /* skip malformed proof */ }
      }
      return keys;
    };

    const rsaKeys = extractKeys(fields[2]);
    const ecdsaKeys = extractKeys(fields[3]);

    // SignedData lives at field 10000 as length-delimited bytes; its
    // only populated sub-field is SignedData.crx_id at field 1 (16 bytes).
    let declaredCrxIdBytes = null;
    const sd = fields[10000];
    if (sd instanceof Uint8Array) {
      try {
        const signedData = ProtobufReader.decode(sd);
        const id = signedData[1];
        if (id instanceof Uint8Array && id.length === 16) {
          declaredCrxIdBytes = id;
        } else if (id instanceof Uint8Array) {
          // Technically malformed — crx_id is always 16 bytes — but surface
          // whatever we have; the caller flags any length anomaly.
          declaredCrxIdBytes = id;
        }
      } catch (_) { /* leave declaredCrxIdBytes null */ }
    }
    const declaredCrxId = declaredCrxIdBytes
      ? this._crxIdFromBytes(declaredCrxIdBytes)
      : null;

    return {
      rsaKeys, ecdsaKeys,
      declaredCrxId, declaredCrxIdBytes,
      malformed: false, empty: false,
    };
  }

  // Encode 16 raw bytes → Chrome extension ID (0..f remapped to a..p over
  // the first 16 bytes). Works for both the declared-from-protobuf case
  // and the SHA-256(SPKI) → first-16-bytes → remap pipeline used for
  // computed IDs, so it's shared between both callers.
  _crxIdFromBytes(bytes) {
    if (!bytes || bytes.length < 16) return null;
    let id = '';
    for (let i = 0; i < 16; i++) {
      id += String.fromCharCode(0x61 + (bytes[i] >> 4));
      id += String.fromCharCode(0x61 + (bytes[i] & 0x0F));
    }
    return id;
  }

  // Async: SHA-256 each embedded public key, first 16 bytes → crx_id.
  // Returns [{ kind: 'rsa' | 'ecdsa', keyLen, computedId }].
  async _computeCrxIdsFromKeys(rsaKeys, ecdsaKeys) {
    const out = [];
    const hashOne = async (key, kind) => {
      try {
        const h = await crypto.subtle.digest('SHA-256', key);
        const id = this._crxIdFromBytes(new Uint8Array(h));
        out.push({ kind, keyLen: key.length, computedId: id });
      } catch (_) { /* skip */ }
    };
    for (const k of (rsaKeys || [])) await hashOne(k, 'rsa');
    for (const k of (ecdsaKeys || [])) await hashOne(k, 'ecdsa');
    return out;
  }

  // Chrome extension ID derivation — SHA-256 of the raw SubjectPublicKeyInfo
  // bytes, first 16 bytes, each nibble remapped `0..f → a..p`. Async in
  // principle but we emit a placeholder and fill it in after render() has
  // handed the wrap back; the ID is a metadata nicety, not a security signal.
  // We compute it synchronously via a non-crypto helper so the summary card
  // renders in one pass.
  _deriveChromeIdFromPubKey(pubKey) {
    // SHA-256 is browser-provided but async; caller falls back to length-only
    // display if we can't resolve it here. We return a placeholder marker and
    // let analyzeForSecurity fill in the real ID asynchronously.
    if (!pubKey || !pubKey.length) return null;
    return { _pending: true, _pubKeyBytes: pubKey };
  }

  async _resolveChromeId(pending) {
    if (!pending || !pending._pending || !pending._pubKeyBytes) return null;
    try {
      const hash = await crypto.subtle.digest('SHA-256', pending._pubKeyBytes);
      const bytes = new Uint8Array(hash);
      let id = '';
      for (let i = 0; i < 16; i++) {
        id += String.fromCharCode(0x61 + (bytes[i] >> 4));
        id += String.fromCharCode(0x61 + (bytes[i] & 0x0F));
      }
      return id;
    } catch (_) { return null; }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // CRX v3 post-processing — takes the raw protobuf header result and
  // populates `parsed` with the declared ID, the list of computed IDs
  // (one per embedded key), the match verdict, and the signature counts
  // so the summary card + _assess can render them without re-parsing.
  // ═══════════════════════════════════════════════════════════════════════
  async _decorateCrxV3(parsed, v3Header) {
    // Default values so the summary card can assume these keys exist.
    parsed.crxV3HeaderMalformed = false;
    parsed.crxV3HeaderEmpty = false;
    parsed.crxDeclaredId = null;
    parsed.crxComputedIds = [];
    parsed.crxIdMatches = null;
    parsed.crxRsaSigCount = 0;
    parsed.crxEcdsaSigCount = 0;
    parsed.crxDeclaredIdLen = null;

    if (!v3Header) return;
    if (v3Header.malformed) {
      parsed.crxV3HeaderMalformed = true;
      return;
    }
    if (v3Header.empty) {
      parsed.crxV3HeaderEmpty = true;
      return;
    }

    parsed.crxRsaSigCount = (v3Header.rsaKeys || []).length;
    parsed.crxEcdsaSigCount = (v3Header.ecdsaKeys || []).length;
    parsed.crxDeclaredId = v3Header.declaredCrxId || null;
    parsed.crxDeclaredIdLen = v3Header.declaredCrxIdBytes
      ? v3Header.declaredCrxIdBytes.length
      : null;

    parsed.crxComputedIds = await this._computeCrxIdsFromKeys(
      v3Header.rsaKeys, v3Header.ecdsaKeys,
    );

    // Declared-vs-computed — Chromium requires at least one match.
    if (parsed.crxDeclaredId && parsed.crxComputedIds.length) {
      parsed.crxIdMatches = parsed.crxComputedIds
        .some(k => k.computedId === parsed.crxDeclaredId);
    }

    // Surface the canonical ID in the generic `crxId` slot so downstream
    // callers (summary "Chrome Extension ID" row, metadata table, IOC
    // extraction) see a single consistent value regardless of version.
    if (!parsed.crxId) {
      if (parsed.crxIdMatches === true) {
        parsed.crxId = parsed.crxDeclaredId;
      } else if (parsed.crxDeclaredId) {
        parsed.crxId = parsed.crxDeclaredId;
      } else if (parsed.crxComputedIds[0]) {
        parsed.crxId = parsed.crxComputedIds[0].computedId;
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Package path — JSZip the inner payload, locate manifest.json,
  // render everything from the parsed manifest tree.
  // ═══════════════════════════════════════════════════════════════════════
  async _renderPackage(wrap, zipBuffer, fileName, crxInfo) {
    let zip;
    try { zip = await JSZip.loadAsync(zipBuffer); }
    catch (e) {
      const err = document.createElement('div');
      err.style.cssText = 'color:var(--risk-high);padding:20px;';
      err.textContent = 'Unable to open extension ZIP: ' + (e && e.message || e);
      wrap.appendChild(err);
      return wrap;
    }
    this._zip = zip;

    // ── Find manifest.json (WebExtension) or install.rdf (legacy Firefox) ─
    const manifestFile = zip.file('manifest.json');
    const installRdfFile = zip.file('install.rdf');
    const hasMozillaSig = !!zip.file('META-INF/mozilla.rsa') || !!zip.file('META-INF/mozilla.sf');
    const hasCoseSig = !!zip.file('META-INF/cose.sig') || !!zip.file('META-INF/cose.manifest');
    const hasChromeManifest = !!zip.file('chrome.manifest');

    let manifestText = '';
    let parsed;

    if (manifestFile) {
      try { manifestText = await manifestFile.async('string'); } catch (_) { manifestText = ''; }
      parsed = this._parseManifest(manifestText);
    } else if (installRdfFile) {
      try { manifestText = await installRdfFile.async('string'); } catch (_) { manifestText = ''; }
      parsed = this._parseInstallRdf(manifestText);
    } else {
      parsed = this._emptyParsed();
      parsed.containerKind = crxInfo ? 'crx' : 'xpi';
    }

    // ── Decorate with envelope metadata ────────────────────────────────
    if (crxInfo) {
      parsed.containerKind = 'crx';
      parsed.crxVersion = crxInfo.crxVersion;
      parsed.crxHeaderLen = crxInfo.headerLen;
      parsed.crxPubKeyLen = crxInfo.pubKeyLen;
      parsed.crxSigLen = crxInfo.sigLen;
      // v2: pubkey is right there in the envelope; compute the ID.
      if (crxInfo.crxId && crxInfo.crxId._pending) {
        const v2Id = await this._resolveChromeId(crxInfo.crxId);
        parsed.crxId = v2Id;
        parsed.crxComputedId = v2Id;
      }
      // v3: merge the protobuf-derived declared ID + per-key computed IDs.
      await this._decorateCrxV3(parsed, crxInfo.crxV3Header);
    } else if (installRdfFile) {
      parsed.containerKind = 'xpi-legacy';
    } else {
      parsed.containerKind = 'xpi';
    }
    parsed.hasMozillaSig = hasMozillaSig;
    parsed.hasCoseSig = hasCoseSig;
    parsed.hasChromeManifest = hasChromeManifest;

    // ── Banner ─────────────────────────────────────────────────────────
    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    const kindLabel = this._containerLabel(parsed);
    banner.innerHTML =
      `<strong>${this._esc(kindLabel)}</strong> — browser extension; the ` +
      `manifest declares the permissions, host grants, content scripts, ` +
      `and background worker that can be run against every tab in the browser.`;
    wrap.appendChild(banner);

    // ── Summary card ───────────────────────────────────────────────────
    wrap.appendChild(this._buildSummaryCard(parsed));

    // ── Permissions split by tier ──────────────────────────────────────
    if ((parsed.permissions && parsed.permissions.length) ||
      (parsed.hostPermissions && parsed.hostPermissions.length) ||
      (parsed.optionalPermissions && parsed.optionalPermissions.length) ||
      (parsed.optionalHostPermissions && parsed.optionalHostPermissions.length)) {
      wrap.appendChild(this._buildPermissionsSection(parsed));
    }

    // ── Entry points (background / content scripts / popup / options) ─
    if (this._hasEntryPoints(parsed)) {
      wrap.appendChild(this._buildEntryPointsSection(parsed));
    }

    // ── File tree (clickable) ──────────────────────────────────────────
    wrap.appendChild(await this._buildFileTree(zip, wrap));

    // ── Raw manifest.json (collapsible) ────────────────────────────────
    const rawText = manifestText || '';
    const normalizedManifest = rawText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    if (normalizedManifest) {
      const rawDetails = document.createElement('details');
      rawDetails.className = 'clickonce-raw-details';
      const sum = document.createElement('summary');
      sum.textContent = installRdfFile ? 'Raw install.rdf' : 'Raw manifest.json';
      rawDetails.appendChild(sum);

      const sourcePane = document.createElement('div');
      sourcePane.className = 'clickonce-source plaintext-scroll';
      const table = document.createElement('table');
      table.className = 'plaintext-table';
      const lines = normalizedManifest.split('\n');
      const maxLines = RENDER_LIMITS.MAX_TEXT_LINES_SMALL;
      const count = Math.min(lines.length, maxLines);

      // Optional hljs syntax highlighting — JSON for manifest.json, XML for
      // install.rdf. Matches svg/hta/html/clickonce pattern with a 200 KB cap
      // for pathological inputs.
      const hlLang = installRdfFile ? 'xml' : 'json';
      let highlightedLines = null;
      if (typeof hljs !== 'undefined' && normalizedManifest.length <= 200000) {
        try {
          const result = hljs.highlight(normalizedManifest, { language: hlLang, ignoreIllegals: true });
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

      // Hooks for the sidebar click-to-focus pipeline.
      wrap._rawText = lfNormalize(normalizedManifest);
      wrap._showSourcePane = () => {
        rawDetails.open = true;
        setTimeout(() => rawDetails.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0);
      };
    } else {
      wrap._rawText = lfNormalize('');
    }

    return wrap;
  }

  _containerLabel(parsed) {
    if (parsed.containerKind === 'crx') {
      return `Chrome / Edge Extension (.crx v${parsed.crxVersion || '?'})`;
    }
    if (parsed.containerKind === 'xpi-legacy') {
      return 'Firefox Legacy Add-on (install.rdf)';
    }
    if (parsed.gecko) return 'Firefox Extension (.xpi)';
    return 'WebExtension (.xpi / unpacked)';
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Summary card
  // ═══════════════════════════════════════════════════════════════════════
  _buildSummaryCard(parsed) {
    const card = document.createElement('div');
    card.className = 'clickonce-card msix-card browserext-card';

    const addRow = (label, value, cls) => {
      if (value == null || value === '') return;
      const row = document.createElement('div');
      row.className = 'clickonce-field' + (cls ? ' ' + cls : '');
      const lbl = document.createElement('span'); lbl.className = 'clickonce-label'; lbl.textContent = label + ':';
      const val = document.createElement('span'); val.className = 'clickonce-value'; val.textContent = value;
      row.appendChild(lbl); row.appendChild(document.createTextNode(' ')); row.appendChild(val);
      card.appendChild(row);
    };

    addRow('Format', this._containerLabel(parsed));
    if (parsed.name) addRow('Name', parsed.name);
    if (parsed.version) addRow('Version', parsed.version);
    if (parsed.manifestVersion != null) addRow('Manifest Version', 'MV' + parsed.manifestVersion);
    if (parsed.author) addRow('Author', typeof parsed.author === 'string' ? parsed.author : (parsed.author.name || ''));
    if (parsed.description) addRow('Description', parsed.description);
    if (parsed.homepageUrl) addRow('Homepage URL', parsed.homepageUrl);

    // Gecko / Chrome identity hints
    if (parsed.geckoId) addRow('Gecko ID', parsed.geckoId);

    // Chrome extension ID — for v3 we split "declared" (from the protobuf
    // SignedData.crx_id) and "computed" (SHA-256 of each embedded public
    // key, first 16 bytes) so an operator can spot envelope tampering.
    // Chromium itself requires at least one computed ID to match the
    // declared one, and rejects the install otherwise.
    if (parsed.containerKind === 'crx' && parsed.crxVersion === 3) {
      if (parsed.crxDeclaredId) {
        addRow('Chrome Extension ID (declared)', parsed.crxDeclaredId);
      }
      if (Array.isArray(parsed.crxComputedIds) && parsed.crxComputedIds.length) {
        for (const k of parsed.crxComputedIds) {
          addRow(
            `Chrome Extension ID (computed, ${k.kind.toUpperCase()}-SHA256)`,
            `${k.computedId}  [SPKI ${k.keyLen} B]`,
          );
        }
      } else if (!parsed.crxV3HeaderMalformed && !parsed.crxV3HeaderEmpty) {
        addRow('Chrome Extension ID (computed)', '(no public keys in signed header)', 'clickonce-warn');
      }
      if (parsed.crxDeclaredId && parsed.crxComputedIds && parsed.crxComputedIds.length) {
        if (parsed.crxIdMatches === true) {
          addRow('ID match', '✓ declared crx_id matches a computed key ID');
        } else if (parsed.crxIdMatches === false) {
          addRow('ID match', '✗ declared crx_id does not match any computed key ID', 'clickonce-warn');
        }
      }
    } else if (parsed.crxId) {
      // CRX v2 — one ID derived from the embedded SPKI, no separate declared value.
      addRow('Chrome Extension ID', parsed.crxId);
    }

    // Signature state
    if (parsed.containerKind === 'crx') {
      let sigTxt;
      if (parsed.crxVersion === 2) {
        sigTxt = `CRX v2 — RSA pubkey (${parsed.crxPubKeyLen || 0} B) + signature (${parsed.crxSigLen || 0} B)`;
      } else if (parsed.crxVersion === 3) {
        const parts = [`CRX v3 — signed header block (${parsed.crxHeaderLen || 0} B protobuf)`];
        if (parsed.crxV3HeaderMalformed) parts.push('[malformed protobuf header]');
        else if (parsed.crxV3HeaderEmpty) parts.push('[empty header — no signatures]');
        else {
          const rsa = parsed.crxRsaSigCount || 0;
          const ecdsa = parsed.crxEcdsaSigCount || 0;
          parts.push(`${rsa} × RSA-SHA256 + ${ecdsa} × ECDSA-SHA256`);
        }
        sigTxt = parts.join(' — ');
      } else {
        sigTxt = 'CRX envelope';
      }
      // Flag malformed / empty / unmatched envelopes on the signature row.
      const sigCls = (parsed.crxVersion === 3 && (
        parsed.crxV3HeaderMalformed ||
        parsed.crxV3HeaderEmpty ||
        (parsed.crxIdMatches === false) ||
        ((parsed.crxRsaSigCount + parsed.crxEcdsaSigCount) === 0 && !parsed.crxV3HeaderEmpty)
      )) ? 'clickonce-warn' : null;
      addRow('Signature', sigTxt, sigCls);
    } else if (parsed.containerKind === 'xpi' || parsed.containerKind === 'xpi-legacy') {
      const bits = [];
      if (parsed.hasMozillaSig) bits.push('META-INF/mozilla.rsa (JAR-style)');
      if (parsed.hasCoseSig) bits.push('META-INF/cose.sig (COSE)');
      addRow('Signature', bits.length ? bits.join(' + ') : 'Unsigned (no META-INF/mozilla.rsa)',
        bits.length ? null : 'clickonce-warn');
    }

    // Update URL — flag HTTP, non-store, suspicious host.
    if (parsed.updateUrl) {
      const isHttp = /^http:\/\//i.test(parsed.updateUrl);
      const isStore = BrowserExtRenderer.STORE_UPDATE_URL_RE.test(parsed.updateUrl);
      const suspicious = BrowserExtRenderer.SUSPICIOUS_HOST_RE.test(parsed.updateUrl);
      addRow('Update URL', parsed.updateUrl,
        (isHttp || !isStore || suspicious) ? 'clickonce-warn' : null);
    }

    // Permission counts as a quick-glance summary.
    if (parsed.permissions && parsed.permissions.length) {
      addRow('Permissions', String(parsed.permissions.length));
    }
    if (parsed.hostPermissions && parsed.hostPermissions.length) {
      addRow('Host Permissions', String(parsed.hostPermissions.length));
    }
    if (parsed.contentScripts && parsed.contentScripts.length) {
      addRow('Content Scripts', String(parsed.contentScripts.length));
    }

    // ── Risk indicators ───────────────────────────────────────────────
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
  // Permissions section — split into three tiers + host permissions
  // ═══════════════════════════════════════════════════════════════════════
  _buildPermissionsSection(parsed) {
    const sec = document.createElement('div'); sec.className = 'clickonce-section';
    const h = document.createElement('h3');
    const total = (parsed.permissions || []).length + (parsed.hostPermissions || []).length
      + (parsed.optionalPermissions || []).length + (parsed.optionalHostPermissions || []).length;
    h.textContent = `Declared Permissions (${total})`;
    sec.appendChild(h);

    const tierList = (label, items, iconClass) => {
      if (!items || !items.length) return;
      const wrap = document.createElement('div');
      wrap.style.cssText = 'margin:6px 0;';
      const t = document.createElement('div');
      t.style.cssText = 'font-weight:600;margin-bottom:4px;';
      t.textContent = label + ` (${items.length})`;
      wrap.appendChild(t);
      const ul = document.createElement('ul'); ul.className = 'clickonce-dep-list';
      for (const p of items) {
        const li = document.createElement('li');
        li.textContent = p;
        if (iconClass) li.className = iconClass;
        ul.appendChild(li);
      }
      wrap.appendChild(ul);
      sec.appendChild(wrap);
    };

    // Split API permissions by tier.
    const perms = parsed.permissions || [];
    const high = perms.filter(p => BrowserExtRenderer.PERM_HIGH.has(p));
    const medium = perms.filter(p => BrowserExtRenderer.PERM_MEDIUM.has(p));
    const low = perms.filter(p => !BrowserExtRenderer.PERM_HIGH.has(p) && !BrowserExtRenderer.PERM_MEDIUM.has(p));

    // Host permissions — anything matching a broad pattern is HIGH.
    const hosts = parsed.hostPermissions || [];
    const broadHosts = hosts.filter(h => this._isBroadHost(h));
    const narrowHosts = hosts.filter(h => !this._isBroadHost(h));

    tierList('⚠ High — sensitive APIs', high, 'clickonce-warn');
    tierList('⚠ High — broad host permissions', broadHosts, 'clickonce-warn');
    tierList('Medium — data-access APIs', medium);
    tierList('Medium — narrow host permissions', narrowHosts);
    tierList('Low — standard APIs', low);

    if (parsed.optionalPermissions && parsed.optionalPermissions.length) {
      tierList('Optional permissions', parsed.optionalPermissions);
    }
    if (parsed.optionalHostPermissions && parsed.optionalHostPermissions.length) {
      tierList('Optional host permissions', parsed.optionalHostPermissions);
    }

    return sec;
  }

  _isBroadHost(pattern) {
    if (!pattern) return false;
    const p = String(pattern);
    if (BrowserExtRenderer.BROAD_HOST_PATTERNS.includes(p)) return true;
    // Patterns like `*://*.example/*` or `https://*/*` — the scheme is
    // wildcarded or the host is `*`, not a specific domain.
    if (/^\*:\/\/\*\/\*$/.test(p)) return true;
    if (/^https?:\/\/\*\/\*?$/i.test(p)) return true;
    return false;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Entry points — background / content scripts / popup / options / commands
  // ═══════════════════════════════════════════════════════════════════════
  _hasEntryPoints(p) {
    return (p.backgroundScripts && p.backgroundScripts.length)
      || p.serviceWorker
      || (p.contentScripts && p.contentScripts.length)
      || p.browserActionPopup || p.pageActionPopup || p.actionPopup
      || p.optionsPage || p.optionsUiPage
      || (p.commands && p.commands.length)
      || (p.webAccessibleResources && p.webAccessibleResources.length)
      || p.contentSecurityPolicy
      || p.externallyConnectable;
  }

  _buildEntryPointsSection(p) {
    const sec = document.createElement('div'); sec.className = 'clickonce-section';
    const h = document.createElement('h3'); h.textContent = 'Entry Points / Extension Surface';
    sec.appendChild(h);

    const block = (label, body, warn) => {
      const d = document.createElement('div');
      d.style.cssText = 'margin:6px 0;padding:6px 10px;border-left:3px solid ' + (warn ? '#c15' : '#4a89dc') + ';';
      const head = document.createElement('div'); head.style.cssText = 'font-weight:600;';
      head.textContent = label;
      if (warn) {
        const w = document.createElement('span');
        w.style.cssText = 'margin-left:8px;color:#c15;font-weight:bold;';
        w.textContent = '[' + warn + ']';
        head.appendChild(w);
      }
      d.appendChild(head);
      if (body instanceof Node) d.appendChild(body);
      else if (typeof body === 'string' && body) {
        const sub = document.createElement('div'); sub.style.cssText = 'color:#888;font-size:0.9em;';
        sub.textContent = body;
        d.appendChild(sub);
      }
      sec.appendChild(d);
    };

    if (p.serviceWorker) {
      block(`Background service worker → ${p.serviceWorker}`);
    }
    if (p.backgroundScripts && p.backgroundScripts.length) {
      block(`Background scripts (MV2): ${p.backgroundScripts.join(', ')}`);
    }
    if (p.contentScripts && p.contentScripts.length) {
      for (const cs of p.contentScripts.slice(0, 20)) {
        const matches = (cs.matches || []).join(', ') || '(no matches)';
        const js = (cs.js || []).join(', ');
        const css = (cs.css || []).join(', ');
        const runAt = cs.run_at || cs.runAt || 'document_idle';
        const allFrames = cs.all_frames === true || cs.allFrames === true;
        const broad = (cs.matches || []).some(m => this._isBroadHost(m));
        const body = `matches: ${matches}${js ? '  •  js: ' + js : ''}${css ? '  •  css: ' + css : ''}  •  run_at: ${runAt}${allFrames ? '  •  all_frames' : ''}`;
        block('Content script', body, broad ? 'ALL URLS' : null);
      }
      if (p.contentScripts.length > 20) {
        block(`… and ${p.contentScripts.length - 20} more content scripts`);
      }
    }
    if (p.actionPopup) block(`action popup → ${p.actionPopup}`);
    if (p.browserActionPopup) block(`browser_action popup → ${p.browserActionPopup}`);
    if (p.pageActionPopup) block(`page_action popup → ${p.pageActionPopup}`);
    if (p.optionsPage) block(`options_page → ${p.optionsPage}`);
    if (p.optionsUiPage) block(`options_ui → ${p.optionsUiPage}`);
    if (p.commands && p.commands.length) {
      block(`commands (keyboard shortcuts): ${p.commands.join(', ')}`);
    }
    if (p.webAccessibleResources && p.webAccessibleResources.length) {
      for (const w of p.webAccessibleResources.slice(0, 10)) {
        const res = (w.resources || []).join(', ');
        const matches = (w.matches || []).join(', ');
        const broad = (w.matches || []).some(m => this._isBroadHost(m));
        block('web_accessible_resources',
          `resources: ${res}${matches ? '  •  matches: ' + matches : ''}`,
          broad ? 'EXPOSED TO ALL URLS' : null);
      }
    }
    if (p.contentSecurityPolicy) {
      const unsafe = /unsafe-eval|unsafe-inline/i.test(p.contentSecurityPolicy);
      const remoteHttp = /http:\/\//i.test(p.contentSecurityPolicy);
      block('content_security_policy', p.contentSecurityPolicy,
        unsafe ? 'UNSAFE-EVAL / UNSAFE-INLINE' : remoteHttp ? 'HTTP SOURCE' : null);
    }
    if (p.externallyConnectable) {
      const matches = (p.externallyConnectable.matches || []).join(', ');
      const ids = (p.externallyConnectable.ids || []).join(', ');
      const broad = (p.externallyConnectable.matches || []).some(m => this._isBroadHost(m))
        || (p.externallyConnectable.ids || []).includes('*');
      block('externally_connectable',
        (matches ? 'matches: ' + matches : '') + (ids ? '  •  ids: ' + ids : ''),
        broad ? 'OPEN TO ALL ORIGINS' : null);
    }

    return sec;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // File tree (reuses .zip-table + open-inner-file event)
  // ═══════════════════════════════════════════════════════════════════════
  async _buildFileTree(zip, wrap) {
    const sec = document.createElement('div'); sec.className = 'clickonce-section';
    const h = document.createElement('h3'); h.textContent = 'Package Contents';
    sec.appendChild(h);

    const entries = [];
    // Aggregate archive-expansion budget shared across the recursive
    // drill-down chain (H5).
    const aggBudget = (typeof window !== 'undefined' && window.app)
      ? window.app._archiveBudget
      : null;
    let aggExhausted = false;
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
    // Flag executables and native-messaging helper binaries shipped inside
    // the package — the "extension bundles a native host" pattern.
    const EXEC_EXTS = new Set(['exe', 'dll', 'scr', 'sys', 'msi', 'ps1', 'bat', 'cmd',
      'vbs', 'hta', 'so', 'dylib', 'sh', 'bash', 'app']);
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
          console.warn('Failed to extract from browser extension:', entry.path, err && err.message);
        }
      },
      expandAll: 'auto',
    });
    sec.appendChild(tree);
    return sec;
  }


  // ═══════════════════════════════════════════════════════════════════════
  // Security analysis — mirrors MsixRenderer.analyzeForSecurity
  // ═══════════════════════════════════════════════════════════════════════
  async analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: [],
      interestingStrings: [],
      browserExtInfo: null,
    };

    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const isCrx = bytes.length >= 8 && bytes[0] === 0x43 && bytes[1] === 0x72 && bytes[2] === 0x32 && bytes[3] === 0x34;
    const isZip = bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04;

    let zipBuffer = buffer;
    let crxInfo = null;
    if (isCrx) {
      crxInfo = this._unwrapCrx(bytes);
      if (crxInfo) zipBuffer = crxInfo.zipBuffer;
    } else if (!isZip) {
      // Not recognisably a browser extension container — bail.
      return f;
    }

    let parsed;
    let manifestText = '';
    try {
      const zip = await JSZip.loadAsync(zipBuffer);
      const manifestFile = zip.file('manifest.json');
      const installRdfFile = zip.file('install.rdf');
      if (manifestFile) {
        manifestText = await manifestFile.async('string');
        parsed = this._parseManifest(manifestText);
      } else if (installRdfFile) {
        manifestText = await installRdfFile.async('string');
        parsed = this._parseInstallRdf(manifestText);
      } else {
        parsed = this._emptyParsed();
      }
      parsed.hasMozillaSig = !!zip.file('META-INF/mozilla.rsa') || !!zip.file('META-INF/mozilla.sf');
      parsed.hasCoseSig = !!zip.file('META-INF/cose.sig') || !!zip.file('META-INF/cose.manifest');
      parsed.hasChromeManifest = !!zip.file('chrome.manifest');
    } catch (e) {
      parsed = this._emptyParsed();
    }

    if (crxInfo) {
      parsed.containerKind = 'crx';
      parsed.crxVersion = crxInfo.crxVersion;
      parsed.crxHeaderLen = crxInfo.headerLen;
      parsed.crxPubKeyLen = crxInfo.pubKeyLen;
      parsed.crxSigLen = crxInfo.sigLen;
      if (crxInfo.crxId && crxInfo.crxId._pending) {
        const v2Id = await this._resolveChromeId(crxInfo.crxId);
        parsed.crxId = v2Id;
        parsed.crxComputedId = v2Id;
      }
      // Decode the CRX v3 protobuf header here too so the security pass
      // surfaces the same declared-vs-computed verdict as the viewer. The
      // helper is idempotent — skipping it for v2 leaves fields at their
      // emptyParsed defaults.
      await this._decorateCrxV3(parsed, crxInfo.crxV3Header);
    } else {
      parsed.containerKind = parsed.containerKind || (parsed.hasChromeManifest ? 'xpi-legacy' : 'xpi');
    }
    f.browserExtInfo = parsed;

    // ── Metadata ───────────────────────────────────────────────────────
    const md = f.metadata;
    md['Format'] = this._containerLabel(parsed);
    if (parsed.name) md['Extension Name'] = parsed.name;
    if (parsed.version) md['Version'] = parsed.version;
    if (parsed.manifestVersion != null) md['Manifest Version'] = 'MV' + parsed.manifestVersion;
    if (parsed.author) md['Author'] = typeof parsed.author === 'string' ? parsed.author : (parsed.author.name || '');
    if (parsed.geckoId) md['Gecko ID'] = parsed.geckoId;
    if (parsed.crxId) md['Chrome Extension ID'] = parsed.crxId;
    // CRX v3 specifics: declared-vs-computed so the summary export and
    // sidebar metadata both surface the mismatch verdict.
    if (parsed.containerKind === 'crx' && parsed.crxVersion === 3) {
      if (parsed.crxDeclaredId) md['CRX ID (declared)'] = parsed.crxDeclaredId;
      if (Array.isArray(parsed.crxComputedIds) && parsed.crxComputedIds.length) {
        md['CRX ID (computed)'] = parsed.crxComputedIds
          .map(k => `${k.kind.toUpperCase()}:${k.computedId}`).join(', ');
      }
      if (parsed.crxIdMatches === true) md['CRX ID Match'] = '✓ match';
      else if (parsed.crxIdMatches === false) md['CRX ID Match'] = '✗ mismatch';
    }
    if (parsed.updateUrl) md['Update URL'] = parsed.updateUrl;
    if (parsed.containerKind === 'crx') {
      md['Signed'] = parsed.crxVersion === 2
        ? `CRX v2 (pubkey ${parsed.crxPubKeyLen || 0} B + sig ${parsed.crxSigLen || 0} B)`
        : `CRX v3 (header ${parsed.crxHeaderLen || 0} B)`;
    } else {
      const bits = [];
      if (parsed.hasMozillaSig) bits.push('mozilla.rsa');
      if (parsed.hasCoseSig) bits.push('cose.sig');
      md['Signed'] = bits.length ? bits.join(' + ') : 'No';
    }
    if (parsed.permissions) md['Permissions'] = String(parsed.permissions.length);
    if (parsed.hostPermissions) md['Host Permissions'] = String(parsed.hostPermissions.length);
    if (parsed.contentScripts) md['Content Scripts'] = String(parsed.contentScripts.length);

    // ── Risks → externalRefs ──────────────────────────────────────────
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
      if (r.sev === 'critical') score += 5;
      else if (r.sev === 'high') score += 3;
      else if (r.sev === 'medium') score += 1.5;
      else score += 0.5;
    }

    // ── URL IOCs from the manifest ────────────────────────────────────
    const urls = new Set();
    if (parsed.updateUrl) urls.add(parsed.updateUrl);
    if (parsed.homepageUrl) urls.add(parsed.homepageUrl);
    if (parsed.hostPermissions) {
      for (const h of parsed.hostPermissions) {
        // Only push concrete URLs, not match patterns.
        if (/^https?:\/\/[A-Za-z0-9.-]+/i.test(h) && !h.includes('*')) urls.add(h);
      }
    }
    for (const u of urls) {
      if (!/^https?:\/\//i.test(u)) continue;
      let sev = 'info';
      if (/^http:\/\//i.test(u)) sev = 'medium';
      if (BrowserExtRenderer.SUSPICIOUS_HOST_RE.test(u)) sev = 'high';
      const ref = { type: IOC.URL, url: u, severity: sev };
      const loc = locate(u);
      if (loc) { ref._sourceOffset = loc.offset; ref._sourceLength = loc.length; }
      f.externalRefs.push(ref);
    }

    // ── Per-permission interestingStrings rows ────────────────────────
    for (const p of (parsed.permissions || [])) {
      if (BrowserExtRenderer.PERM_HIGH.has(p)) {
        f.interestingStrings.push({ type: IOC.PATTERN, url: `permission: ${p}`, severity: 'high' });
      } else if (BrowserExtRenderer.PERM_MEDIUM.has(p)) {
        f.interestingStrings.push({ type: IOC.PATTERN, url: `permission: ${p}`, severity: 'medium' });
      }
    }
    for (const h of (parsed.hostPermissions || [])) {
      if (this._isBroadHost(h)) {
        f.interestingStrings.push({ type: IOC.PATTERN, url: `host permission: ${h}`, severity: 'high' });
      }
    }

    // ── Risk bucket — matches MsixRenderer's critical / high / medium / low ladder
    if (score >= 8) escalateRisk(f, 'critical');
    else if (score >= 5) escalateRisk(f, 'high');
    else if (score >= 2) escalateRisk(f, 'medium');
    else escalateRisk(f, 'low');

    // Mirror classic-pivot metadata into the IOC table. CRX ID + Gecko ID +
    // update URL are the standard pivots for browser-extension hunting.
    mirrorMetadataIOCs(f, {
      'Chrome Extension ID':  IOC.PATTERN,
      'CRX ID (declared)':    IOC.PATTERN,
      'Gecko ID':             IOC.PATTERN,
      'Update URL':           IOC.URL,
    });

    return f;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Risk assessment — returns [{ sev, msg, highlight? }]
  // ═══════════════════════════════════════════════════════════════════════
  _assess(parsed) {
    const risks = [];
    const perms = parsed.permissions || [];
    const hosts = parsed.hostPermissions || [];

    // ── Tier-1 permissions ─────────────────────────────────────────────
    for (const p of perms) {
      if (BrowserExtRenderer.PERM_HIGH.has(p)) {
        risks.push({
          sev: 'high',
          msg: `⚠ High-risk permission requested: ${p}`,
          highlight: `"${p}"`,
        });
      }
    }
    // nativeMessaging + broad-host combo → native-code bridge exposed to any site.
    const hasNative = perms.includes('nativeMessaging');
    const hasBroadHost = hosts.some(h => this._isBroadHost(h));
    if (hasNative && hasBroadHost) {
      risks.push({
        sev: 'critical',
        msg: '⚠ nativeMessaging + <all_urls> — browser extension can bridge any site to a native helper binary',
        highlight: '"nativeMessaging"',
      });
    }

    // ── Broad host permissions ────────────────────────────────────────
    for (const h of hosts) {
      if (this._isBroadHost(h)) {
        risks.push({
          sev: 'high',
          msg: `⚠ Broad host permission: ${h} — reads / modifies every page the user visits`,
          highlight: `"${h}"`,
        });
      }
    }
    // Match patterns on content scripts — the same risk applies even if
    // the API permission list is clean.
    for (const cs of (parsed.contentScripts || [])) {
      for (const m of (cs.matches || [])) {
        if (this._isBroadHost(m)) {
          risks.push({
            sev: 'high',
            msg: `⚠ Content script injected into every page: matches "${m}"`,
            highlight: `"${m}"`,
          });
          break;
        }
      }
    }

    // ── CSP downgrades ────────────────────────────────────────────────
    if (parsed.contentSecurityPolicy) {
      if (/unsafe-eval/i.test(parsed.contentSecurityPolicy)) {
        risks.push({
          sev: 'high',
          msg: '⚠ content_security_policy allows `unsafe-eval` — dynamic code evaluation',
          highlight: 'unsafe-eval',
        });
      }
      if (/unsafe-inline/i.test(parsed.contentSecurityPolicy)) {
        risks.push({
          sev: 'medium',
          msg: 'content_security_policy allows `unsafe-inline`',
          highlight: 'unsafe-inline',
        });
      }
      if (/\bhttp:\/\//i.test(parsed.contentSecurityPolicy)) {
        risks.push({
          sev: 'high',
          msg: '⚠ content_security_policy lists a plain-HTTP remote script source',
          highlight: 'http://',
        });
      }
    }

    // ── Externally connectable opened to the web ──────────────────────
    if (parsed.externallyConnectable) {
      const matches = parsed.externallyConnectable.matches || [];
      const ids = parsed.externallyConnectable.ids || [];
      if (matches.some(m => this._isBroadHost(m))) {
        risks.push({
          sev: 'high',
          msg: '⚠ externally_connectable allows messaging from <all_urls> — any site can pipe into the extension',
          highlight: '"externally_connectable"',
        });
      }
      if (ids.includes('*')) {
        risks.push({
          sev: 'high',
          msg: '⚠ externally_connectable ids: ["*"] — any other extension can send messages',
          highlight: '"*"',
        });
      }
    }

    // ── web_accessible_resources open to the web ──────────────────────
    for (const w of (parsed.webAccessibleResources || [])) {
      if ((w.matches || []).some(m => this._isBroadHost(m))) {
        risks.push({
          sev: 'medium',
          msg: 'web_accessible_resources exposed to <all_urls> — content-script hijack / fingerprint surface',
          highlight: '"web_accessible_resources"',
        });
        break;
      }
    }

    // ── update_url risks ──────────────────────────────────────────────
    if (parsed.updateUrl) {
      if (/^http:\/\//i.test(parsed.updateUrl)) {
        risks.push({
          sev: 'high',
          msg: '⚠ update_url is plain HTTP — MITM swap of every future update',
          highlight: parsed.updateUrl,
        });
      } else if (!BrowserExtRenderer.STORE_UPDATE_URL_RE.test(parsed.updateUrl)) {
        risks.push({
          sev: 'medium',
          msg: `update_url points outside the official Chrome/Edge/Firefox stores: ${parsed.updateUrl}`,
          highlight: parsed.updateUrl,
        });
      }
      if (BrowserExtRenderer.SUSPICIOUS_HOST_RE.test(parsed.updateUrl)) {
        risks.push({
          sev: 'high',
          msg: 'update_url points to a low-reputation / tunnelling host',
          highlight: parsed.updateUrl,
        });
      }
    }

    // ── Legacy XUL / bootstrapped add-ons ─────────────────────────────
    if (parsed.containerKind === 'xpi-legacy') {
      risks.push({
        sev: 'medium',
        msg: 'Legacy Firefox add-on (install.rdf) — pre-WebExtensions model with full XPCOM access; only ancient Firefox forks still load these',
      });
    }

    // ── Unsigned XPI ──────────────────────────────────────────────────
    if ((parsed.containerKind === 'xpi' || parsed.containerKind === 'xpi-legacy')
      && !parsed.hasMozillaSig && !parsed.hasCoseSig) {
      risks.push({
        sev: 'medium',
        msg: 'XPI is unsigned (no META-INF/mozilla.rsa / cose.sig) — Firefox release/ESR will refuse to install it',
      });
    }

    // ── CRX v3 signature envelope anomalies (from protobuf) ───────────
    // Chromium itself aborts install if the declared crx_id inside
    // SignedData doesn't SHA-256 to one of the embedded public keys —
    // mismatch means either a corrupt envelope or active tampering.
    if (parsed.containerKind === 'crx' && parsed.crxVersion === 3) {
      if (parsed.crxV3HeaderMalformed) {
        risks.push({
          sev: 'high',
          msg: '⚠ CRX v3 signed header protobuf is malformed — envelope cannot be validated and Chromium will refuse to install',
        });
      } else if (parsed.crxV3HeaderEmpty) {
        risks.push({
          sev: 'high',
          msg: '⚠ CRX v3 signed header is empty (0 B) — package is effectively unsigned and cannot be installed without developer mode',
        });
      } else {
        if ((parsed.crxRsaSigCount || 0) + (parsed.crxEcdsaSigCount || 0) === 0) {
          risks.push({
            sev: 'high',
            msg: '⚠ CRX v3 header declares zero AsymmetricKeyProof signatures — package is unsigned',
          });
        }
        if (parsed.crxIdMatches === false) {
          risks.push({
            sev: 'high',
            msg: '⚠ CRX v3 extension ID mismatch — declared SignedData.crx_id does not match any embedded public key (envelope tampering or substitution)',
          });
        }
        if (parsed.crxDeclaredIdLen != null && parsed.crxDeclaredIdLen !== 16) {
          risks.push({
            sev: 'medium',
            msg: `CRX v3 SignedData.crx_id has non-standard length ${parsed.crxDeclaredIdLen} (expected 16 bytes)`,
          });
        }
      }
    }

    return risks;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // manifest.json parser
  // ═══════════════════════════════════════════════════════════════════════
  _parseManifest(text) {
    const parsed = this._emptyParsed();
    if (!text) return parsed;
    let m;
    try { m = JSON.parse(text); }
    catch (e) { parsed.parseError = e && e.message || String(e); return parsed; }
    if (!m || typeof m !== 'object') return parsed;

    parsed.name = m.name || null;
    parsed.version = m.version || null;
    parsed.description = m.description || null;
    parsed.author = m.author || null;
    parsed.homepageUrl = m.homepage_url || null;
    parsed.manifestVersion = typeof m.manifest_version === 'number' ? m.manifest_version : null;
    parsed.updateUrl = m.update_url || null;

    // Gecko identity — MV3 uses browser_specific_settings; MV2 used applications.
    const bss = m.browser_specific_settings || m.applications;
    if (bss && bss.gecko) {
      parsed.gecko = true;
      parsed.geckoId = bss.gecko.id || null;
      parsed.geckoStrictMinVersion = bss.gecko.strict_min_version || null;
    }

    // Permissions — MV3 splits host_permissions out; MV2 mixed them into permissions.
    const rawPerms = Array.isArray(m.permissions) ? m.permissions.slice() : [];
    const rawOptional = Array.isArray(m.optional_permissions) ? m.optional_permissions.slice() : [];
    const rawHost = Array.isArray(m.host_permissions) ? m.host_permissions.slice() : [];
    const rawOptionalHost = Array.isArray(m.optional_host_permissions) ? m.optional_host_permissions.slice() : [];

    // In MV2, host match patterns show up in `permissions`. Pull them out.
    const apiPerms = [];
    for (const p of rawPerms) {
      if (typeof p !== 'string') continue;
      if (this._looksLikeMatchPattern(p)) rawHost.push(p);
      else apiPerms.push(p);
    }
    const optionalApi = [];
    for (const p of rawOptional) {
      if (typeof p !== 'string') continue;
      if (this._looksLikeMatchPattern(p)) rawOptionalHost.push(p);
      else optionalApi.push(p);
    }
    parsed.permissions = apiPerms;
    parsed.optionalPermissions = optionalApi;
    parsed.hostPermissions = rawHost;
    parsed.optionalHostPermissions = rawOptionalHost;

    // Background — MV3 service_worker or MV2 scripts[].
    if (m.background && typeof m.background === 'object') {
      if (typeof m.background.service_worker === 'string') {
        parsed.serviceWorker = m.background.service_worker;
      }
      if (Array.isArray(m.background.scripts)) {
        parsed.backgroundScripts = m.background.scripts.filter(s => typeof s === 'string');
      }
      if (typeof m.background.page === 'string') {
        parsed.backgroundPage = m.background.page;
      }
    }

    // Content scripts.
    if (Array.isArray(m.content_scripts)) {
      parsed.contentScripts = m.content_scripts.filter(cs => cs && typeof cs === 'object');
    }

    // Action / browser_action / page_action popups.
    if (m.action && typeof m.action === 'object' && m.action.default_popup) {
      parsed.actionPopup = m.action.default_popup;
    }
    if (m.browser_action && typeof m.browser_action === 'object' && m.browser_action.default_popup) {
      parsed.browserActionPopup = m.browser_action.default_popup;
    }
    if (m.page_action && typeof m.page_action === 'object' && m.page_action.default_popup) {
      parsed.pageActionPopup = m.page_action.default_popup;
    }

    // Options page.
    if (typeof m.options_page === 'string') parsed.optionsPage = m.options_page;
    if (m.options_ui && typeof m.options_ui === 'object' && m.options_ui.page) {
      parsed.optionsUiPage = m.options_ui.page;
    }

    // Commands (keyboard shortcuts).
    if (m.commands && typeof m.commands === 'object') {
      parsed.commands = Object.keys(m.commands);
    }

    // web_accessible_resources — MV2 was a flat array, MV3 is [{resources,matches}].
    if (Array.isArray(m.web_accessible_resources)) {
      if (m.web_accessible_resources.length && typeof m.web_accessible_resources[0] === 'string') {
        parsed.webAccessibleResources = [{ resources: m.web_accessible_resources, matches: ['<all_urls>'] }];
      } else {
        parsed.webAccessibleResources = m.web_accessible_resources
          .filter(w => w && typeof w === 'object');
      }
    }

    // Content security policy — MV2 is a string, MV3 is an object with
    // extension_pages / sandbox.
    if (typeof m.content_security_policy === 'string') {
      parsed.contentSecurityPolicy = m.content_security_policy;
    } else if (m.content_security_policy && typeof m.content_security_policy === 'object') {
      const bits = [];
      if (m.content_security_policy.extension_pages) bits.push('extension_pages: ' + m.content_security_policy.extension_pages);
      if (m.content_security_policy.sandbox) bits.push('sandbox: ' + m.content_security_policy.sandbox);
      parsed.contentSecurityPolicy = bits.join('  •  ');
    }

    // externally_connectable.
    if (m.externally_connectable && typeof m.externally_connectable === 'object') {
      parsed.externallyConnectable = {
        matches: Array.isArray(m.externally_connectable.matches) ? m.externally_connectable.matches : [],
        ids: Array.isArray(m.externally_connectable.ids) ? m.externally_connectable.ids : [],
      };
    }

    // devtools / sidebar / chrome_url_overrides — touched briefly for
    // completeness in the entry-points section; we surface presence but not
    // every sub-field.
    if (typeof m.devtools_page === 'string') parsed.devtoolsPage = m.devtools_page;
    if (m.sidebar_action && typeof m.sidebar_action === 'object') {
      parsed.sidebarActionPanel = m.sidebar_action.default_panel || null;
    }

    return parsed;
  }

  // Match-pattern heuristic — MV2 mixed these into `permissions`.
  _looksLikeMatchPattern(s) {
    return /^(?:https?|\*|file|ftp):\/\//i.test(s) || s === '<all_urls>';
  }

  // ── Legacy install.rdf (Firefox bootstrapped add-ons) ────────────────
  _parseInstallRdf(text) {
    const parsed = this._emptyParsed();
    parsed.containerKind = 'xpi-legacy';
    if (!text) return parsed;
    let doc;
    try { doc = new DOMParser().parseFromString(text, 'application/xml'); }
    catch (e) { return parsed; }
    if (doc.getElementsByTagName('parsererror')[0]) return parsed;

    const root = doc.documentElement;
    if (!root) return parsed;

    const firstText = (tag) => {
      const els = root.getElementsByTagNameNS('*', tag);
      return els.length && els[0].textContent ? els[0].textContent.trim() : null;
    };

    parsed.name = firstText('name');
    parsed.version = firstText('version');
    parsed.description = firstText('description');
    parsed.homepageUrl = firstText('homepageURL');
    parsed.geckoId = firstText('id');
    parsed.updateUrl = firstText('updateURL') || null;
    const bootstrap = firstText('bootstrap');
    parsed.bootstrap = bootstrap && bootstrap.toLowerCase() === 'true';
    parsed.manifestVersion = null;
    parsed.raw = text;
    return parsed;
  }

  _emptyParsed() {
    return {
      containerKind: null,
      name: null, version: null, description: null, author: null,
      homepageUrl: null,
      manifestVersion: null,
      updateUrl: null,
      gecko: false, geckoId: null, geckoStrictMinVersion: null,
      permissions: [], optionalPermissions: [],
      hostPermissions: [], optionalHostPermissions: [],
      backgroundScripts: [], serviceWorker: null, backgroundPage: null,
      contentScripts: [],
      actionPopup: null, browserActionPopup: null, pageActionPopup: null,
      optionsPage: null, optionsUiPage: null,
      commands: [],
      webAccessibleResources: [],
      contentSecurityPolicy: null,
      externallyConnectable: null,
      devtoolsPage: null, sidebarActionPanel: null,
      crxVersion: null, crxPubKeyLen: null, crxSigLen: null,
      crxHeaderLen: null, crxId: null,
      hasMozillaSig: false, hasCoseSig: false, hasChromeManifest: false,
      bootstrap: false,
      raw: '',
    };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Helpers
  // ═══════════════════════════════════════════════════════════════════════
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
