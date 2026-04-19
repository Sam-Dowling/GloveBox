'use strict';
// ════════════════════════════════════════════════════════════════════════════
// pkg-renderer.js — macOS Installer Package (.pkg / .mpkg) analyser
//
// A flat PKG is an xar archive. The xar header is 28 bytes at offset 0:
//
//   [0..3]   magic          'xar!' (0x78 0x61 0x72 0x21)
//   [4..5]   header size    (big-endian, always 28 in practice)
//   [6..7]   version        (big-endian, 1)
//   [8..15]  toc_length_comp   (big-endian uint64) — deflate-compressed TOC
//   [16..23] toc_length_unc    (big-endian uint64) — uncompressed TOC
//   [24..27] cksum_alg      0=none, 1=SHA-1, 2=MD5, 3=other (named in TOC)
//
// The compressed TOC (zlib/deflate) immediately follows the header. Inside
// the TOC's <xar><toc>…</toc></xar> XML every file entry carries its
// offset (relative to the heap), size, zlib-compressed encoding, sha1
// checksums, and a <name> — plus the critical <pkg-ref>/<pax>/<data>
// children that name pre/post-install scripts and the BOM (Bill of
// Materials). See xar(5) and Apple's pkgbuild(1).
//
// macOS malware overwhelmingly delivers payload through preinstall /
// postinstall shell or AppleScript, so those are the single most
// important artefacts to surface for triage. We extract them verbatim
// and offer a click-to-open drill-down using the shared
// `open-inner-file` event that app-load.js wires up.
//
// Depends on: constants.js (IOC, escHtml, fmtBytes), decompressor.js
// ════════════════════════════════════════════════════════════════════════════

class PkgRenderer {

  // Signals of high-risk content inside a flat PKG's heap.
  static DANGEROUS_SCRIPT_NAMES = new Set([
    'preinstall', 'postinstall',
    'preupgrade', 'postupgrade',
    'preflight', 'postflight',
    'InstallationCheck', 'VolumeCheck',
  ]);

  async render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const wrap = document.createElement('div'); wrap.className = 'zip-view pkg-view';

    // Banner
    const banner = document.createElement('div'); banner.className = 'doc-extraction-banner';
    banner.innerHTML = '<strong>macOS Installer Package (.pkg)</strong> — flat PKG (xar archive). ' +
      'Installer packages run pre/post-install scripts with root privileges and are a common ' +
      'delivery mechanism for macOS malware.';
    wrap.appendChild(banner);

    // Parse xar container
    let pkg;
    try {
      pkg = await this._parse(bytes);
    } catch (e) {
      const err = document.createElement('p');
      err.style.cssText = 'color:var(--risk-high);padding:20px';
      err.textContent = `Could not parse xar archive: ${e.message}`;
      wrap.appendChild(err);
      return wrap;
    }

    // Summary
    const summ = document.createElement('div'); summ.className = 'zip-summary';
    const partLabel = pkg.isDistribution ? 'distribution (mpkg)' : 'component';
    summ.textContent = `${pkg.files.length} file(s) · ${partLabel} · ${this._fmtBytes(bytes.length)} · xar v${pkg.version}`;
    wrap.appendChild(summ);

    // Warnings
    const warnings = this._checkWarnings(pkg);
    if (warnings.length) {
      const warnDiv = document.createElement('div'); warnDiv.className = 'zip-warnings';
      for (const w of warnings) {
        const d = document.createElement('div'); d.className = `zip-warning zip-warning-${w.sev}`;
        d.textContent = w.msg; warnDiv.appendChild(d);
      }
      wrap.appendChild(warnDiv);
    }

    // Key metadata (identifier / version / signature)
    if (pkg.meta.identifier || pkg.meta.version || pkg.signature) {
      const tbl = document.createElement('table');
      tbl.className = 'lnk-info-table';
      tbl.style.cssText = 'margin:4px 20px 12px;';
      const addRow = (k, v) => {
        if (!v) return;
        const tr = document.createElement('tr');
        const tdL = document.createElement('td'); tdL.className = 'lnk-lbl'; tdL.textContent = k;
        const tdV = document.createElement('td'); tdV.className = 'lnk-val'; tdV.textContent = v;
        tr.appendChild(tdL); tr.appendChild(tdV); tbl.appendChild(tr);
      };
      addRow('Package identifier', pkg.meta.identifier);
      addRow('Version',            pkg.meta.version);
      addRow('Install location',   pkg.meta.installLocation);
      addRow('Auth',               pkg.meta.auth);
      addRow('Signature',          pkg.signature ? `${pkg.signature.style} (${this._fmtBytes(pkg.signature.size)})` : '');
      if (tbl.childNodes.length) wrap.appendChild(tbl);
    }

    // Distribution / PackageInfo XML (collapsible)
    if (pkg.distributionXml) {
      const det = document.createElement('details');
      det.style.cssText = 'margin:4px 20px 12px;';
      const sum = document.createElement('summary');
      sum.style.cssText = 'cursor:pointer;font-weight:600;padding:4px 0;';
      sum.textContent = pkg.isDistribution ? 'Distribution XML' : 'PackageInfo XML';
      det.appendChild(sum);
      const pre = document.createElement('pre');
      pre.style.cssText = 'margin:8px 0;padding:12px;background:rgba(0,0,0,0.2);max-height:400px;overflow:auto;white-space:pre-wrap;word-break:break-all;font-size:12px;';
      pre.textContent = pkg.distributionXml.slice(0, 32768);
      if (pkg.distributionXml.length > 32768) pre.textContent += '\n\n… (truncated)';
      det.appendChild(pre);
      wrap.appendChild(det);
    }

    // Files table
    if (pkg.files.length) {
      const scr = document.createElement('div');
      scr.style.cssText = 'overflow:auto;max-height:calc(100vh - 260px)';
      const tbl = document.createElement('table'); tbl.className = 'zip-table';
      const thead = document.createElement('thead');
      const hr = document.createElement('tr');
      for (const h of ['', 'Path', 'Size', 'Compressed', 'Encoding', '']) {
        const th = document.createElement('th'); th.textContent = h; hr.appendChild(th);
      }
      thead.appendChild(hr); tbl.appendChild(thead);
      const tbody = document.createElement('tbody');

      // Sort: scripts first (alarming), then dirs/files alphabetically
      const sorted = pkg.files.slice().sort((a, b) => {
        if (a.isScript !== b.isScript) return a.isScript ? -1 : 1;
        return a.path.localeCompare(b.path);
      });

      for (const f of sorted) {
        const tr = document.createElement('tr');
        if (f.isScript) tr.className = 'zip-row-danger';
        if (!f.dir) tr.classList.add('zip-row-clickable');

        const tdIcon = document.createElement('td'); tdIcon.className = 'zip-icon';
        tdIcon.textContent = f.dir ? '📁' : (f.isScript ? '⚠️' : this._getFileIcon(f.path));
        tr.appendChild(tdIcon);

        const tdPath = document.createElement('td'); tdPath.className = 'zip-path';
        tdPath.textContent = f.path;
        if (f.isScript) {
          const badge = document.createElement('span'); badge.className = 'zip-badge-danger';
          badge.textContent = 'INSTALL SCRIPT'; tdPath.appendChild(badge);
        }
        tr.appendChild(tdPath);

        const tdSize = document.createElement('td'); tdSize.className = 'zip-size';
        tdSize.textContent = f.dir ? '—' : this._fmtBytes(f.uncompSize);
        tr.appendChild(tdSize);

        const tdComp = document.createElement('td'); tdComp.className = 'zip-size';
        tdComp.textContent = f.dir ? '—' : this._fmtBytes(f.compSize);
        tr.appendChild(tdComp);

        const tdEnc = document.createElement('td'); tdEnc.className = 'zip-date';
        tdEnc.textContent = f.dir ? '—' : (f.encoding || 'none');
        tr.appendChild(tdEnc);

        const tdAction = document.createElement('td'); tdAction.className = 'zip-action';
        if (!f.dir) {
          const openBtn = document.createElement('span'); openBtn.className = 'zip-badge-open';
          openBtn.textContent = '🔍 Open';
          openBtn.title = `Open ${f.path.split('/').pop()} for analysis`;
          openBtn.addEventListener('click', (ev) => {
            ev.stopPropagation();
            this._extractAndOpen(bytes, pkg, f, wrap);
          });
          tdAction.appendChild(openBtn);
        }
        tr.appendChild(tdAction);

        tbody.appendChild(tr);
      }
      tbl.appendChild(tbody); scr.appendChild(tbl); wrap.appendChild(scr);
    }

    return wrap;
  }

  // ── Security analysis ─────────────────────────────────────────────────────

  async analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: []
    };
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);

    // PKG baseline — installer executes with root on the target Mac
    f.externalRefs.push({
      type: IOC.PATTERN,
      url: 'macOS Installer Package — scripts execute with root privileges during install',
      severity: 'medium'
    });

    let pkg;
    try { pkg = await this._parse(bytes); } catch (e) { return f; }

    // Metadata for the Summary block
    f.metadata = {
      title:   pkg.meta.identifier || '',
      subject: pkg.meta.version ? `version ${pkg.meta.version}` : '',
      creator: pkg.signature ? `Signed (${pkg.signature.style})` : 'Unsigned',
    };

    // Pre/post-install scripts are the malware delivery vector. We split
    // "modern" (preinstall/postinstall) from "legacy" (preflight/postflight/
    // InstallationCheck/VolumeCheck) because the legacy family is pre-
    // PackageMaker and warrants its own badge.
    const scripts = pkg.files.filter(x => x.isScript);
    const LEGACY_NAMES = new Set(['preflight', 'postflight', 'InstallationCheck', 'VolumeCheck', 'preupgrade', 'postupgrade']);
    const legacy  = scripts.filter(s => LEGACY_NAMES.has(s.name));
    const modern  = scripts.filter(s => !LEGACY_NAMES.has(s.name));
    if (modern.length) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${modern.length} install script(s): ${modern.map(s => s.path.split('/').pop()).join(', ')}`,
        severity: 'high'
      });
      f.risk = 'high';
    }
    if (legacy.length) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${legacy.length} legacy install script(s) (pre-PackageMaker delivery path): ${legacy.map(s => s.name).join(', ')}`,
        severity: 'medium'
      });
      if (f.risk === 'low') f.risk = 'medium';
    }
    for (const s of scripts) {
      f.externalRefs.push({ type: IOC.FILE_PATH, url: s.path, severity: 'high' });
    }

    // Unsigned installer is a real (if mundane) red flag. Lift baseline
    // risk so the sidebar surfaces "medium" even when no scripts ship —
    // an unsigned installer is still a publisher-verification failure.
    if (!pkg.signature) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'Installer package is unsigned — cannot verify publisher',
        severity: 'medium'
      });
      if (f.risk === 'low') f.risk = 'medium';
    }

    // Root auth + scripts = macOS malware's signature combo
    if (pkg.meta.auth && /root/i.test(pkg.meta.auth) && scripts.length) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: 'Scripts run as root (auth="Root") — elevated malware execution path',
        severity: 'high'
      });
      f.risk = 'high';
    }

    // LaunchDaemon / LaunchAgent payload drop — macOS persistence path
    // (T1543.001 / T1543.004). Look at file paths in the heap manifest.
    const launchPaths = pkg.files.filter(x => !x.dir &&
      /\/(LaunchDaemons|LaunchAgents)\/[^/]+\.plist$/i.test(x.path));
    if (launchPaths.length) {
      f.externalRefs.push({
        type: IOC.PATTERN,
        url: `${launchPaths.length} LaunchDaemon/LaunchAgent plist(s) installed — macOS persistence mechanism`,
        severity: 'high'
      });
      f.risk = 'high';
      for (const lp of launchPaths.slice(0, 20)) {
        f.externalRefs.push({ type: IOC.FILE_PATH, url: lp.path, severity: 'high' });
      }
    }

    // Scan script bodies for curl|bash / wget|sh download-and-execute.
    // Scripts are small (bytes to low KB) and ship gzip'd in the heap —
    // decompressing them here is cheap and is the only way to surface
    // the pattern (YARA only sees compressed heap bytes).
    for (const s of scripts.slice(0, 16)) {
      try {
        const body = await this._readScriptBody(bytes, pkg, s);
        if (!body) continue;
        if (/\b(curl|wget)\b[^\n|]*\|\s*(ba)?sh\b/i.test(body)) {
          f.externalRefs.push({
            type: IOC.PATTERN,
            url: `Install script "${s.name}" uses curl|bash / wget|sh download-and-execute`,
            severity: 'high'
          });
          f.risk = 'high';
        }
        const urls = body.match(/https?:\/\/[^\s"'<>`]+/g) || [];
        for (const u of urls.slice(0, 20)) {
          if (/apple\.com|opensource\.apple\.com/.test(u)) continue;
          f.externalRefs.push({ type: IOC.URL, url: u, severity: 'medium' });
          if (f.externalRefs.length > 200) break;
        }
      } catch (e) { /* keep going — one failed script shouldn't kill the analysis */ }
      if (f.externalRefs.length > 200) break;
    }

    // Harvest URLs from distribution XML (installer-check callouts, update
    // URLs, license servers) — very often the C2 in malicious packages.
    if (pkg.distributionXml) {
      const urls = (pkg.distributionXml.match(/https?:\/\/[^\s"'<>]+/g) || [])
        .filter(u => !/apple\.com|opensource\.apple\.com/.test(u));
      const seen = new Set();
      for (const u of urls) {
        if (seen.has(u)) continue; seen.add(u);
        f.externalRefs.push({ type: IOC.URL, url: u, severity: 'medium' });
        if (f.externalRefs.length > 200) break;
      }
    }

    return f;
  }

  // Decompress a single TOC file entry from the heap. Used by the security
  // analyser to peek inside install-script bodies. Returns a string or null.
  async _readScriptBody(bytes, pkg, fileEntry) {
    if (fileEntry.dir) return null;
    if (!fileEntry.compSize || fileEntry.uncompSize > 256 * 1024) return null;
    const slice = bytes.subarray(
      pkg.heapOffset + fileEntry.offset,
      pkg.heapOffset + fileEntry.offset + fileEntry.compSize
    );
    let data = slice;
    if (fileEntry.encoding === 'gzip') {
      data = await Decompressor.inflate(slice, 'gzip') || slice;
    } else if (fileEntry.encoding !== 'none' && fileEntry.encoding !== 'raw') {
      data = await Decompressor.inflate(slice, 'deflate')
        || await Decompressor.inflate(slice, 'deflate-raw')
        || slice;
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(data);
  }

  // ── xar parsing ────────────────────────────────────────────────────────────

  async _parse(bytes) {
    if (bytes.length < 28) throw new Error('file too small');
    // Magic
    if (!(bytes[0] === 0x78 && bytes[1] === 0x61 && bytes[2] === 0x72 && bytes[3] === 0x21)) {
      throw new Error("not a xar archive (missing 'xar!' magic)");
    }

    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const headerSize  = dv.getUint16(4, false);
    const version     = dv.getUint16(6, false);
    // 64-bit lengths — use BigInt only for the unlikely big-archive case
    const tocComp     = Number(dv.getBigUint64(8, false));
    const tocUnc      = Number(dv.getBigUint64(16, false));
    const cksumAlg    = dv.getUint32(24, false);

    if (headerSize > bytes.length || tocComp > bytes.length - headerSize) {
      throw new Error('truncated xar header');
    }

    // Extract and inflate TOC (zlib / deflate)
    const compSlice = bytes.subarray(headerSize, headerSize + tocComp);
    let tocBytes = await Decompressor.inflate(compSlice, 'deflate');
    if (!tocBytes) {
      // Some older writers wrote raw deflate with no zlib wrapper
      tocBytes = await Decompressor.inflate(compSlice, 'deflate-raw');
    }
    if (!tocBytes) throw new Error('TOC decompression failed');

    const tocXml = new TextDecoder('utf-8', { fatal: false }).decode(tocBytes);

    // Heap starts immediately after the compressed TOC
    const heapOffset = headerSize + tocComp;

    // Parse the TOC XML
    const parser = new DOMParser();
    const doc = parser.parseFromString(tocXml, 'application/xml');
    const parseErr = doc.getElementsByTagName('parsererror')[0];
    if (parseErr) throw new Error('TOC XML parse error');

    const tocEl = doc.getElementsByTagName('toc')[0];
    if (!tocEl) throw new Error('no <toc> in xar archive');

    // Collect files recursively (xar <file> elements can nest)
    const files = [];
    const walk = (el, prefix) => {
      for (const child of Array.from(el.children)) {
        if (child.tagName !== 'file') continue;
        const nameEl = child.querySelector(':scope > name');
        const typeEl = child.querySelector(':scope > type');
        const name = nameEl ? nameEl.textContent.trim() : '(unnamed)';
        const fullPath = prefix ? prefix + '/' + name : name;
        const isDir = typeEl && typeEl.textContent.trim() === 'directory';

        const dataEl = child.querySelector(':scope > data');
        let uncompSize = 0, compSize = 0, offset = 0, encoding = 'none';
        if (dataEl) {
          const szEl = dataEl.querySelector(':scope > size');
          const lenEl = dataEl.querySelector(':scope > length');
          const offEl = dataEl.querySelector(':scope > offset');
          const encEl = dataEl.querySelector(':scope > encoding');
          if (szEl)  uncompSize = parseInt(szEl.textContent, 10)  || 0;
          if (lenEl) compSize   = parseInt(lenEl.textContent, 10) || 0;
          if (offEl) offset     = parseInt(offEl.textContent, 10) || 0;
          if (encEl) {
            // Encoding is expressed as a MIME style attribute, e.g.
            // style="application/x-gzip"
            const style = encEl.getAttribute('style') || '';
            if (/gzip/i.test(style))       encoding = 'gzip';
            else if (/bzip2/i.test(style)) encoding = 'bzip2';
            else if (/octet-stream/i.test(style)) encoding = 'raw';
            else encoding = style || 'unknown';
          }
        }

        // Heuristic: script if parent path is 'Scripts' OR name matches a
        // known install-phase script name. xar writers (pkgbuild) place
        // preinstall/postinstall under a `Scripts` directory.
        const baseName = name;
        const isScript = PkgRenderer.DANGEROUS_SCRIPT_NAMES.has(baseName)
          || /(^|\/)Scripts\/[^/]+$/.test(fullPath);

        files.push({
          path: fullPath,
          name: baseName,
          dir: !!isDir,
          uncompSize, compSize, offset, encoding,
          isScript: !isDir && isScript,
        });

        if (isDir) walk(child, fullPath);
      }
    };
    walk(tocEl, '');

    // Signature (optional)
    let signature = null;
    const sigEl = tocEl.querySelector(':scope > signature')
      || tocEl.querySelector(':scope > x-signature');
    if (sigEl) {
      const szEl  = sigEl.querySelector(':scope > size');
      const offEl = sigEl.querySelector(':scope > offset');
      signature = {
        style:  sigEl.getAttribute('style') || 'unknown',
        size:   szEl  ? parseInt(szEl.textContent, 10)  || 0 : 0,
        offset: offEl ? parseInt(offEl.textContent, 10) || 0 : 0,
      };
    }

    // Metadata from Distribution XML or PackageInfo
    const meta = {};
    let distributionXml = null;
    let isDistribution = false;

    // Modern flat PKGs usually expose a top-level <pkg-ref> + <options auth=…>.
    // Read these off the Distribution/PackageInfo file in the heap.
    const distFile = files.find(f => f.name === 'Distribution');
    const pkgInfoFile = files.find(f => f.name === 'PackageInfo');
    const xmlFile = distFile || pkgInfoFile;
    if (xmlFile && xmlFile.uncompSize && xmlFile.uncompSize < 1024 * 1024) {
      try {
        const heapSlice = bytes.subarray(
          heapOffset + xmlFile.offset,
          heapOffset + xmlFile.offset + xmlFile.compSize
        );
        let xmlBytes = heapSlice;
        if (xmlFile.encoding === 'gzip') {
          xmlBytes = await Decompressor.inflate(heapSlice, 'gzip');
        } else if (xmlFile.encoding === 'deflate' || xmlFile.encoding === 'unknown') {
          xmlBytes = await Decompressor.inflate(heapSlice, 'deflate')
            || await Decompressor.inflate(heapSlice, 'deflate-raw')
            || heapSlice;
        }
        if (xmlBytes) {
          distributionXml = new TextDecoder('utf-8', { fatal: false }).decode(xmlBytes);
          isDistribution = !!distFile;

          const distDoc = parser.parseFromString(distributionXml, 'application/xml');
          const pkgRef = distDoc.getElementsByTagName('pkg-ref')[0];
          if (pkgRef) {
            meta.identifier = pkgRef.getAttribute('id') || '';
            meta.version    = pkgRef.getAttribute('version') || '';
            if (!meta.installLocation) {
              const il = pkgRef.getAttribute('install-location');
              if (il) meta.installLocation = il;
            }
            if (!meta.auth) {
              const authAttr = pkgRef.getAttribute('auth');
              if (authAttr) meta.auth = authAttr;
            }
          }
          // PackageInfo root also carries identifier / version / auth
          const piRoot = distDoc.getElementsByTagName('pkg-info')[0];
          if (piRoot) {
            if (!meta.identifier) meta.identifier = piRoot.getAttribute('identifier') || '';
            if (!meta.version)    meta.version    = piRoot.getAttribute('version') || '';
            if (!meta.installLocation) {
              const il = piRoot.getAttribute('install-location');
              if (il) meta.installLocation = il;
            }
            if (!meta.auth) {
              const authAttr = piRoot.getAttribute('auth');
              if (authAttr) meta.auth = authAttr;
            }
          }
        }
      } catch (e) { /* leave distributionXml null — renderer tolerates that */ }
    }

    return {
      version, cksumAlg, heapOffset, headerSize, tocComp, tocUnc,
      files, signature, meta, distributionXml, isDistribution,
    };
  }

  // ── File extraction ───────────────────────────────────────────────────────

  async _extractAndOpen(bytes, pkg, fileEntry, wrap) {
    if (fileEntry.dir) return;

    const slice = bytes.subarray(
      pkg.heapOffset + fileEntry.offset,
      pkg.heapOffset + fileEntry.offset + fileEntry.compSize
    );
    let data = slice;

    try {
      if (fileEntry.encoding === 'gzip') {
        data = await Decompressor.inflate(slice, 'gzip') || slice;
      } else if (fileEntry.encoding === 'bzip2') {
        // No bzip2 in DecompressionStream — leave compressed and let the
        // fallback viewer hex-dump it. Still useful for triage.
      } else if (fileEntry.encoding !== 'none' && fileEntry.encoding !== 'raw') {
        // Try deflate/zlib for "unknown" or other styles
        data = await Decompressor.inflate(slice, 'deflate')
          || await Decompressor.inflate(slice, 'deflate-raw')
          || slice;
      }
    } catch (e) { data = slice; }

    const name = fileEntry.path.split('/').pop() || fileEntry.name || 'file';
    const file = new File([data], name, { type: 'application/octet-stream' });
    wrap.dispatchEvent(new CustomEvent('open-inner-file', { bubbles: true, detail: file }));
  }

  // ── UI helpers ────────────────────────────────────────────────────────────

  _checkWarnings(pkg) {
    const w = [];
    const scripts = pkg.files.filter(f => f.isScript);
    if (scripts.length) {
      w.push({
        sev: 'high',
        msg: `⚠ ${scripts.length} install script(s) detected — click to inspect: ` +
          scripts.slice(0, 5).map(s => s.name).join(', ') + (scripts.length > 5 ? ' …' : ''),
      });
    }
    if (!pkg.signature) {
      w.push({ sev: 'medium', msg: '⚠ Installer package is not cryptographically signed' });
    }
    if (pkg.meta.auth && /root/i.test(pkg.meta.auth) && scripts.length) {
      w.push({ sev: 'high', msg: '⚠ Install scripts run as root (auth="Root")' });
    }
    return w;
  }

  _getFileIcon(path) {
    const name = (path || '').split('/').pop();
    const ext = (name.includes('.') ? name.split('.').pop() : '').toLowerCase();
    if (['sh', 'bash', 'zsh', 'command'].includes(ext)) return '📜';
    if (['plist'].includes(ext)) return '🧾';
    if (['pkg', 'mpkg'].includes(ext)) return '📦';
    if (name === 'Distribution' || name === 'PackageInfo') return '🧾';
    if (name === 'Bom') return '📋';
    if (name === 'Payload' || name === 'Scripts') return '📦';
    if (PkgRenderer.DANGEROUS_SCRIPT_NAMES.has(name)) return '📜';
    return '📄';
  }

  _fmtBytes(n) {
    if (typeof fmtBytes === 'function') return fmtBytes(n);
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1073741824).toFixed(1) + ' GB';
  }
}
