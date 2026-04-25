'use strict';
// ════════════════════════════════════════════════════════════════════════════
// clickonce-renderer.js — ClickOnce deployment manifest analysis
//   (.application / .manifest XML with asmv1/asmv2 namespaces)
//
// ClickOnce is Microsoft's web-deployable .NET runtime format. A .application
// file is a small deployment descriptor that points at a code-base URL and an
// application manifest (.manifest). An attacker-controlled .application can:
//   • point `deploymentProvider codebase=…` at an HTTP URL — silent
//     over-the-air install with one-click user consent
//   • request full-trust via <trustInfo><requestedPermissions><PermissionSet
//     Unrestricted="true"> — effectively unsandboxed .NET code
//   • hijack startup via <AppDomainManagerAssembly>/<AppDomainManagerType>
//     (AppDomainManager injection, MITRE T1574.014)
//
// Depends on: constants.js (IOC, escHtml)
// ════════════════════════════════════════════════════════════════════════════
class ClickOnceRenderer {

  render(buffer, fileName) {
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const normalizedText = lfNormalize(text);
    const parsed = this._parseManifest(text);

    const wrap = document.createElement('div');
    wrap.className = 'clickonce-view';

    // ── Banner ────────────────────────────────────────────────────────
    const banner = document.createElement('div');
    banner.className = 'doc-extraction-banner';
    const kindLabel = parsed.kind === 'deployment' ? 'ClickOnce Deployment (.application)'
                    : parsed.kind === 'application' ? 'ClickOnce Application (.manifest)'
                    : 'ClickOnce / .NET Manifest';
    banner.innerHTML =
      `<strong>${this._esc(kindLabel)}</strong> — XML deployment descriptor for the .NET ClickOnce runtime; ` +
      `attacker-controlled manifests can silently install and escalate to full-trust .NET code.`;
    wrap.appendChild(banner);

    // ── Summary card (headline fields) ─────────────────────────────────
    const card = document.createElement('div');
    card.className = 'clickonce-card';

    const addRow = (label, value, extraClass) => {
      if (value == null || value === '') return;
      const row = document.createElement('div');
      row.className = 'clickonce-field' + (extraClass ? ' ' + extraClass : '');
      const lbl = document.createElement('span'); lbl.className = 'clickonce-label';
      lbl.textContent = label + ':';
      const val = document.createElement('span'); val.className = 'clickonce-value';
      val.textContent = value;
      row.appendChild(lbl); row.appendChild(document.createTextNode(' ')); row.appendChild(val);
      card.appendChild(row);
    };

    if (parsed.identity) {
      addRow('Identity', this._fmtIdentity(parsed.identity));
    }
    if (parsed.description && parsed.description.publisher) {
      addRow('Publisher', parsed.description.publisher);
    }
    if (parsed.description && parsed.description.product) {
      addRow('Product', parsed.description.product);
    }

    if (parsed.deployment) {
      const d = parsed.deployment;
      if (d.codebase) {
        addRow('Deployment Codebase', d.codebase,
          /^https?:\/\//i.test(d.codebase) && !/^https:/i.test(d.codebase) ? 'clickonce-warn' : null);
      }
      if (d.install != null) addRow('Install', String(d.install));
      if (d.mapFileExtensions != null) addRow('Map File Extensions', String(d.mapFileExtensions));
      if (d.minimumRequiredVersion) addRow('Minimum Required Version', d.minimumRequiredVersion);
    }

    if (parsed.entryPoint && parsed.entryPoint.dependentAssembly) {
      const ep = parsed.entryPoint;
      addRow('Entry Point', `${ep.commandLineFile || ''} → ${this._fmtIdentity(ep.dependentAssembly)}`);
    }

    if (parsed.trust) {
      const t = parsed.trust;
      const trustMsg = t.fullTrust ? 'FullTrust (Unrestricted — equivalent to native code)'
                    : t.permissionSet ? `PermissionSet: ${t.permissionSet}`
                    : 'Declared (see Requested Permissions)';
      addRow('Requested Trust', trustMsg, t.fullTrust ? 'clickonce-warn' : null);
    }

    if (parsed.appDomainManager) {
      addRow('AppDomainManager Assembly', parsed.appDomainManager.assembly || '(unset)',
        'clickonce-warn');
      if (parsed.appDomainManager.type) {
        addRow('AppDomainManager Type', parsed.appDomainManager.type, 'clickonce-warn');
      }
    }

    if (parsed.signature) {
      const s = parsed.signature;
      const label = s.hasCertificate ? 'Authenticode signed'
                  : s.hasSignature ? 'XMLDSig signed (unverifiable offline)'
                  : 'Unsigned';
      addRow('Signature', label, s.hasSignature ? null : 'clickonce-warn');
      if (s.subjectName) addRow('Subject', s.subjectName);
    }

    // ── Risk indicators ─────────────────────────────────────────────────
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

    wrap.appendChild(card);

    // ── Dependent assemblies ────────────────────────────────────────────
    if (parsed.dependentAssemblies && parsed.dependentAssemblies.length) {
      const dep = document.createElement('div');
      dep.className = 'clickonce-section';
      const h = document.createElement('h3');
      h.textContent = `Dependent Assemblies (${parsed.dependentAssemblies.length})`;
      dep.appendChild(h);
      const list = document.createElement('ul');
      list.className = 'clickonce-dep-list';
      for (const d of parsed.dependentAssemblies.slice(0, 50)) {
        const li = document.createElement('li');
        li.textContent = this._fmtIdentity(d) + (d.codebase ? '  [codebase: ' + d.codebase + ']' : '');
        if (d.codebase && /^https?:\/\//i.test(d.codebase) && !/^https:/i.test(d.codebase)) {
          li.className = 'clickonce-warn';
        }
        list.appendChild(li);
      }
      dep.appendChild(list);
      wrap.appendChild(dep);
    }

    // ── Raw XML viewer (collapsible, plaintext-table for search highlights) ──
    const rawDetails = document.createElement('details');
    rawDetails.className = 'clickonce-raw-details';
    const summary = document.createElement('summary');
    summary.textContent = 'Raw XML';
    rawDetails.appendChild(summary);

    const sourcePane = document.createElement('div');
    sourcePane.className = 'clickonce-source plaintext-scroll';
    const table = document.createElement('table');
    table.className = 'plaintext-table';
    const lines = normalizedText.split('\n');
    const maxLines = RENDER_LIMITS.MAX_TEXT_LINES_SMALL;
    const count = Math.min(lines.length, maxLines);

    // Optional hljs XML syntax highlighting — matches svg/hta/html renderers.
    // ClickOnce manifests are typically <20 KB; the 200 KB cap is defensive
    // parity with SvgRenderer so pathological inputs stay snappy.
    let highlightedLines = null;
    if (typeof hljs !== 'undefined' && normalizedText.length <= 200000) {
      try {
        const result = hljs.highlight(normalizedText, { language: 'xml', ignoreIllegals: true });
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
    rawDetails.appendChild(sourcePane);
    wrap.appendChild(rawDetails);

    // Hooks for the sidebar highlight pipeline — same pattern as url-renderer.
    wrap._rawText = lfNormalize(text);
    wrap._showSourcePane = () => {
      rawDetails.open = true;
      setTimeout(() => rawDetails.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0);
    };

    return wrap;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Security analysis
  // ═══════════════════════════════════════════════════════════════════════
  analyzeForSecurity(buffer, fileName) {
    const f = {
      risk: 'low', hasMacros: false, macroSize: 0, macroHash: '',
      autoExec: [], modules: [], externalRefs: [], metadata: {},
      signatureMatches: [],
      clickOnceInfo: null,
    };
    const bytes = new Uint8Array(buffer instanceof ArrayBuffer ? buffer : buffer.buffer);
    const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    const normalizedText = lfNormalize(text);
    const parsed = this._parseManifest(text);
    f.clickOnceInfo = parsed;

    const locate = (needle) => {
      if (!needle) return null;
      const idx = normalizedText.indexOf(needle);
      if (idx === -1) return null;
      return { offset: idx, length: needle.length };
    };

    // ── Metadata summary (surfaces in the generic Summary block) ────────
    const md = f.metadata;
    md['Manifest Kind'] = parsed.kind === 'deployment' ? 'ClickOnce Deployment (.application)'
                       : parsed.kind === 'application' ? 'ClickOnce Application (.manifest)'
                       : 'ClickOnce / .NET Manifest';
    if (parsed.identity) md['Identity'] = this._fmtIdentity(parsed.identity);
    if (parsed.description) {
      if (parsed.description.publisher) md['Publisher'] = parsed.description.publisher;
      if (parsed.description.product) md['Product'] = parsed.description.product;
    }
    if (parsed.deployment && parsed.deployment.codebase) md['Deployment Codebase'] = parsed.deployment.codebase;
    if (parsed.deployment && parsed.deployment.install != null) md['Install'] = String(parsed.deployment.install);
    if (parsed.entryPoint && parsed.entryPoint.commandLineFile) {
      md['Entry Point'] = parsed.entryPoint.commandLineFile;
    }
    if (parsed.trust) {
      md['Requested Trust'] = parsed.trust.fullTrust ? 'FullTrust (Unrestricted)'
        : parsed.trust.permissionSet || 'Declared';
    }
    if (parsed.appDomainManager && parsed.appDomainManager.assembly) {
      md['AppDomainManager'] = `${parsed.appDomainManager.assembly}${parsed.appDomainManager.type ? ' / ' + parsed.appDomainManager.type : ''}`;
    }
    if (parsed.signature) {
      md['Signature'] = parsed.signature.hasCertificate ? 'Authenticode'
        : parsed.signature.hasSignature ? 'XMLDSig' : 'Unsigned';
    }
    if (parsed.dependentAssemblies && parsed.dependentAssemblies.length) {
      md['Dependent Assemblies'] = String(parsed.dependentAssemblies.length);
    }

    // ── Risk assessment ────────────────────────────────────────────────
    const risks = this._assess(parsed);
    let score = 0;
    for (const r of risks) {
      const loc = locate(r.highlight);
      const ref = { type: IOC.PATTERN, url: r.msg, severity: r.sev };
      if (r.highlight) ref._highlightText = r.highlight;
      if (loc) { ref._sourceOffset = loc.offset; ref._sourceLength = loc.length; }
      f.externalRefs.push(ref);
      if (r.sev === 'high') score += 3;
      else if (r.sev === 'medium') score += 1.5;
      else score += 0.5;
    }

    // ── URL IOCs from manifest ─────────────────────────────────────────
    const urls = [];
    if (parsed.deployment && parsed.deployment.codebase) urls.push(parsed.deployment.codebase);
    for (const d of (parsed.dependentAssemblies || [])) {
      if (d.codebase) urls.push(d.codebase);
    }
    for (const u of urls) {
      if (!/^https?:\/\//i.test(u)) continue;
      const loc = locate(u);
      const ref = {
        type: IOC.URL,
        url: u,
        severity: /^http:/i.test(u) ? 'medium' : 'info',
      };
      if (loc) { ref._sourceOffset = loc.offset; ref._sourceLength = loc.length; }
      f.externalRefs.push(ref);
    }

    // ── Final risk bucket ──────────────────────────────────────────────
    if (score >= 8) escalateRisk(f, 'critical');
    else if (score >= 5) escalateRisk(f, 'high');
    else if (score >= 2) escalateRisk(f, 'medium');
    else escalateRisk(f, 'low');

    return f;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // XML parser — tolerant of both asmv1 and asmv2 manifests
  //
  // We read the document via DOMParser but then walk it with
  // getElementsByTagNameNS('*', local) so we don't have to care which prefix
  // (asmv1, asmv2, cov1, cov2…) a given element uses. All security-relevant
  // elements have stable local-names.
  // ═══════════════════════════════════════════════════════════════════════
  _parseManifest(text) {
    const parsed = {
      kind: null,
      identity: null,
      description: null,
      deployment: null,
      entryPoint: null,
      trust: null,
      appDomainManager: null,
      signature: null,
      dependentAssemblies: [],
      raw: text,
    };

    let doc;
    try {
      doc = new DOMParser().parseFromString(text, 'application/xml');
    } catch (e) { return parsed; }
    const errNode = doc.getElementsByTagName('parsererror')[0];
    if (errNode) return parsed;

    const root = doc.documentElement;
    if (!root) return parsed;

    const pick = (parent, local) => {
      if (!parent) return null;
      const els = parent.getElementsByTagNameNS('*', local);
      return els.length ? els[0] : null;
    };
    const pickAll = (parent, local) => {
      if (!parent) return [];
      return Array.from(parent.getElementsByTagNameNS('*', local));
    };
    const attr = (el, name) => (el && el.getAttribute(name)) || null;

    // Determine kind: a <deployment> child indicates a .application
    // (deployment manifest); otherwise it's an application manifest.
    const deployEl = pick(root, 'deployment');
    parsed.kind = deployEl ? 'deployment' : 'application';

    // Identity (asm.v*:assemblyIdentity)
    const idEl = pick(root, 'assemblyIdentity');
    if (idEl) {
      parsed.identity = {
        name: attr(idEl, 'name'),
        version: attr(idEl, 'version'),
        publicKeyToken: attr(idEl, 'publicKeyToken'),
        processorArchitecture: attr(idEl, 'processorArchitecture'),
        type: attr(idEl, 'type'),
        language: attr(idEl, 'language'),
      };
    }

    // Description
    const descEl = pick(root, 'description');
    if (descEl) {
      parsed.description = {
        publisher: attr(descEl, 'publisher'),
        product: attr(descEl, 'product'),
        suiteName: attr(descEl, 'suiteName'),
        supportUrl: attr(descEl, 'supportUrl'),
      };
    }

    // Deployment (.application)
    if (deployEl) {
      const dp = pick(deployEl, 'deploymentProvider');
      parsed.deployment = {
        install: this._parseBool(attr(deployEl, 'install')),
        mapFileExtensions: this._parseBool(attr(deployEl, 'mapFileExtensions')),
        trustUrlParameters: this._parseBool(attr(deployEl, 'trustURLParameters')),
        minimumRequiredVersion: attr(deployEl, 'minimumRequiredVersion'),
        codebase: dp ? attr(dp, 'codebase') : null,
      };
    }

    // Entry point (commandLine file + dependent assembly identity)
    const epEl = pick(root, 'entryPoint');
    if (epEl) {
      const cmd = pick(epEl, 'commandLine');
      const dep = pick(epEl, 'dependentAssembly');
      const depId = dep ? pick(dep, 'assemblyIdentity') : null;
      parsed.entryPoint = {
        commandLineFile: cmd ? attr(cmd, 'file') : null,
        commandLineParameters: cmd ? attr(cmd, 'parameters') : null,
        dependentAssembly: depId ? {
          name: attr(depId, 'name'),
          version: attr(depId, 'version'),
          publicKeyToken: attr(depId, 'publicKeyToken'),
          processorArchitecture: attr(depId, 'processorArchitecture'),
        } : null,
      };
    }

    // Trust info — the whole point of ClickOnce's security model.
    const trustEl = pick(root, 'trustInfo');
    if (trustEl) {
      const reqEl = pick(trustEl, 'requestedPermissions');
      const psEl = reqEl ? pick(reqEl, 'PermissionSet') : null;
      parsed.trust = {
        fullTrust: psEl ? this._parseBool(attr(psEl, 'Unrestricted')) === true : false,
        permissionSet: psEl ? (attr(psEl, 'class') || attr(psEl, 'ID') || null) : null,
      };
      // Also flag defaultAssemblyRequest references.
      const defReq = reqEl ? pick(reqEl, 'defaultAssemblyRequest') : null;
      if (defReq) parsed.trust.defaultAssemblyRequest = attr(defReq, 'permissionSetReference');
    }

    // AppDomainManager override — lives on the root <assembly> element in
    // application manifests, under the `runtime`/`AppDomainManager*`
    // attributes, or as explicit elements. Check both.
    const adA = root.getAttribute('AppDomainManagerAssembly');
    const adT = root.getAttribute('AppDomainManagerType');
    const adAEl = pick(root, 'AppDomainManagerAssembly');
    const adTEl = pick(root, 'AppDomainManagerType');
    if (adA || adT || adAEl || adTEl) {
      parsed.appDomainManager = {
        assembly: adA || (adAEl ? adAEl.textContent.trim() : null),
        type: adT || (adTEl ? adTEl.textContent.trim() : null),
      };
    }

    // Signature — <Signature> under the XMLDSig namespace.
    const sigEls = root.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature');
    const sig = sigEls.length ? sigEls[0] : null;
    if (sig) {
      const certEls = sig.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'X509Certificate');
      const x509Subj = sig.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'X509SubjectName');
      parsed.signature = {
        hasSignature: true,
        hasCertificate: certEls.length > 0,
        subjectName: x509Subj.length ? x509Subj[0].textContent.trim() : null,
      };
    } else {
      parsed.signature = { hasSignature: false, hasCertificate: false, subjectName: null };
    }

    // Dependent assemblies (excluding the entry-point one, already captured).
    const deps = pickAll(root, 'dependentAssembly');
    for (const dep of deps) {
      const idE = pick(dep, 'assemblyIdentity');
      if (!idE) continue;
      const info = {
        name: attr(idE, 'name'),
        version: attr(idE, 'version'),
        publicKeyToken: attr(idE, 'publicKeyToken'),
        processorArchitecture: attr(idE, 'processorArchitecture'),
        codebase: attr(dep, 'codebase'),
      };
      parsed.dependentAssemblies.push(info);
    }

    return parsed;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // Risk assessment — returns array of { sev, msg, highlight? }
  // ═══════════════════════════════════════════════════════════════════════
  _assess(parsed) {
    const risks = [];

    // HTTP (not HTTPS) deployment codebase — trivial MITM hijack vector.
    const cb = parsed.deployment && parsed.deployment.codebase;
    if (cb && /^http:\/\//i.test(cb)) {
      risks.push({
        sev: 'high',
        msg: '⚠ Deployment codebase is HTTP (not HTTPS) — MITM can swap the payload',
        highlight: cb,
      });
    }

    // Suspicious TLDs / IP-based codebase.
    if (cb && /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(cb)) {
      risks.push({
        sev: 'medium',
        msg: 'Deployment codebase uses a raw IP — no domain validation',
        highlight: cb,
      });
    }
    if (cb && /\.(?:top|xyz|tk|ml|cf|ga|gq|zip|mov|click|country|work)(?:[/:]|$)/i.test(cb)) {
      risks.push({
        sev: 'medium',
        msg: 'Deployment codebase uses a low-reputation / abuse-heavy TLD',
        highlight: cb,
      });
    }

    // FullTrust requested — grants unrestricted .NET execution.
    if (parsed.trust && parsed.trust.fullTrust) {
      risks.push({
        sev: 'high',
        msg: '⚠ Manifest requests FullTrust (Unrestricted) — unsandboxed .NET execution',
        highlight: 'Unrestricted="true"',
      });
    }

    // AppDomainManager override — MITRE T1574.014.
    if (parsed.appDomainManager && (parsed.appDomainManager.assembly || parsed.appDomainManager.type)) {
      risks.push({
        sev: 'high',
        msg: '⚠ AppDomainManager override — MITRE T1574.014; runs attacker code in every CLR process loading this config',
        highlight: parsed.appDomainManager.assembly || parsed.appDomainManager.type,
      });
    }

    // Unsigned manifest.
    if (parsed.signature && !parsed.signature.hasSignature) {
      risks.push({
        sev: 'medium',
        msg: 'Manifest is unsigned — any tamper goes undetected',
      });
    }

    // install="true" + HTTP codebase is especially bad.
    if (parsed.deployment && parsed.deployment.install === true && cb && /^http:\/\//i.test(cb)) {
      risks.push({
        sev: 'high',
        msg: '⚠ Silent install (install="true") with HTTP codebase — one-click compromise',
        highlight: 'install="true"',
      });
    }

    // trustURLParameters — allows runtime args to flow from the launching URL.
    if (parsed.deployment && parsed.deployment.trustUrlParameters === true) {
      risks.push({
        sev: 'medium',
        msg: 'trustURLParameters="true" — URL query string is passed to the app as command-line args',
        highlight: 'trustURLParameters="true"',
      });
    }

    // Dependent assemblies with HTTP codebases — same MITM concern.
    for (const d of (parsed.dependentAssemblies || [])) {
      if (d.codebase && /^http:\/\//i.test(d.codebase)) {
        risks.push({
          sev: 'medium',
          msg: `Dependent assembly "${d.name || '?'}" loaded from HTTP codebase`,
          highlight: d.codebase,
        });
      }
    }

    return risks;
  }

  // ── Helpers ───────────────────────────────────────────────────────────

  _parseBool(v) {
    if (v == null) return null;
    const s = String(v).trim().toLowerCase();
    if (s === 'true' || s === '1' || s === 'yes') return true;
    if (s === 'false' || s === '0' || s === 'no') return false;
    return null;
  }

  _fmtIdentity(id) {
    if (!id) return '';
    const parts = [];
    if (id.name) parts.push(id.name);
    if (id.version) parts.push('v' + id.version);
    if (id.processorArchitecture) parts.push(id.processorArchitecture);
    if (id.publicKeyToken) parts.push('pkt=' + id.publicKeyToken);
    return parts.join(' ');
  }

  _esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}
