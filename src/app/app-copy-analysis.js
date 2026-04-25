// ════════════════════════════════════════════════════════════════════════════
// App — "Copy analysis" markdown builders (per-format summary blocks).
// Split out of app-ui.js to keep that file honest; see CONTRIBUTING.md
// project-structure section for the full JS_FILES ordering.
//
// The dispatcher _copyAnalysisFormatSpecific is the entry point; it calls
// one _copyAnalysisXxx helper per format. Each helper is tolerant of its
// target data being absent and silently no-ops, so ordering is cosmetic.
// ════════════════════════════════════════════════════════════════════════════

Object.assign(App.prototype, {

  // ── Format-specific section builder for _copyAnalysis ─────────────────
  _copyAnalysisFormatSpecific(f, tp) {
    const parts = [];

    // ── Metadata ──
    if (f.metadata && typeof f.metadata === 'object' && Object.keys(f.metadata).length) {
      parts.push('\n## Metadata');
      for (const [k, v] of Object.entries(f.metadata)) {
        if (v === null || v === undefined || v === '' || v === '—') continue;
        const rendered = this._formatMetadataValue(v, 0);
        if (!rendered) continue;
        parts.push(`- **${k}:** ${rendered}`);
      }
    }

    // ── Security issues (autoExec for PE/ELF/Mach-O, osascript) ──
    if (f.autoExec && f.autoExec.length && !f.hasMacros) {
      parts.push('\n## Security Issues');
      for (const issue of f.autoExec) {
        let text;
        if (typeof issue === 'string') {
          text = issue;
        } else if (issue && issue.label) {
          // osascript auto-exec: {label, hit}
          text = issue.label;
        } else if (issue && issue.module) {
          // PE/ELF/Mach-O macro-style auto-exec: {module, patterns}
          text = `${issue.module}: ${(issue.patterns || []).join(', ')}`;
        } else {
          text = String(issue);
        }
        parts.push(`- ⚠ ${text}`);
      }
    }

    // ── Binary Triage (PE / ELF / Mach-O) ──
    // Triage-first summary: a single verdict line, tier + risk score,
    // badge list, and any anomaly ribbon chips. Mirrors the Tier-A band
    // the main-pane renderer draws so a pasted analysis ticket opens with
    // the same "is this bad?" gloss the analyst saw on screen.
    // read binary triage stash + buffer through `currentResult`.
    const _crBin = (this.currentResult && this.currentResult.binary) || null;
    const _binFormat = _crBin ? _crBin.format : null;
    const _binParsed = _crBin ? _crBin.parsed : null;
    const _crBuffer  = (this.currentResult && this.currentResult.buffer) || null;
    if ((f.peInfo || f.elfInfo || f.machoInfo)
        && typeof BinaryVerdict !== 'undefined'
        && _binParsed && _binFormat) {
      const fmtLabel = _binFormat === 'pe' ? 'PE'
        : _binFormat === 'elf' ? 'ELF'
        : _binFormat === 'macho' ? 'Mach-O' : '';
      const fileSize = (this._fileMeta && this._fileMeta.size)
        || (_crBuffer && _crBuffer.byteLength) || 0;
      let verdict = null;
      try {
        verdict = BinaryVerdict.summarize({
          parsed: _binParsed,
          findings: f,
          format: fmtLabel,
          fileSize,
        });
      } catch (_e) { /* non-fatal — clipboard output only */ }

      if (verdict) {
        parts.push('\n## Binary Triage');
        parts.push(`- **Verdict:** ${verdict.headline || '—'}`);
        parts.push(`- **Tier:** ${verdict.tier || '—'} (risk ${verdict.risk != null ? verdict.risk : '—'}/100)`);
        if (verdict.signer) parts.push(`- **Signer:** ${verdict.signer}`);
        if (Array.isArray(verdict.badges) && verdict.badges.length) {
          const labels = verdict.badges.map(b => b && b.label).filter(Boolean);
          if (labels.length) parts.push(`- **Badges:** ${labels.join(', ')}`);
        }
        const caps = verdict.capabilityCounts;
        if (caps && caps.total) {
          const breakdown = [];
          if (caps.critical) breakdown.push(caps.critical + ' critical');
          if (caps.high) breakdown.push(caps.high + ' high');
          if (caps.medium) breakdown.push(caps.medium + ' medium');
          if (caps.low) breakdown.push(caps.low + ' low');
          parts.push(`- **Capabilities:** ${caps.total}${breakdown.length ? ' (' + breakdown.join(', ') + ')' : ''}`);
        }
        if (typeof BinaryAnomalies !== 'undefined') {
          let anoms = null;
          try {
            anoms = BinaryAnomalies.detect({
              parsed: _binParsed,
              findings: f,
              format: fmtLabel,
            });

          } catch (_e) { /* non-fatal */ }
          if (anoms && Array.isArray(anoms.ribbon) && anoms.ribbon.length) {
            parts.push('- **Anomalies:**');
            for (const chip of anoms.ribbon) {
              if (!chip || !chip.label) continue;
              const sev = chip.severity && chip.severity !== 'info' ? ` [${chip.severity}]` : '';
              const mitre = chip.mitre ? ` (${chip.mitre})` : '';
              parts.push(`  - ${chip.label}${sev}${mitre}`);
            }
          }
        }
      }

      // ── MITRE ATT&CK Coverage ──
      // Extract [Tnnnn(.nnn)?] tokens from every capability row
      // (externalRefs[type='pattern']) and roll them up by tactic. Output
      // mirrors the sidebar's MITRE section so an analyst pasting into a
      // ticket gets a clean tactic-grouped technique list.
      if (typeof MITRE !== 'undefined' && Array.isArray(f.externalRefs) && f.externalRefs.length) {
        const seen = new Map();
        const techRe = /\[(T\d{4}(?:\.\d{3})?)\]/g;
        for (const r of f.externalRefs) {
          if (!r) continue;
          const type = (r.type || '').toLowerCase();
          if (type !== 'pattern') continue;
          const hay = String(r.value || r.name || '');
          const sev = (r.severity || 'medium').toLowerCase();
          let m;
          techRe.lastIndex = 0;
          while ((m = techRe.exec(hay)) !== null) {
            const id = m[1];
            const prev = seen.get(id);
            const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
            if (!prev || (SEV_RANK[sev] || 0) > (SEV_RANK[prev.severity] || 0)) {
              seen.set(id, { id, severity: sev, evidence: (r.name || r.value || '') });
            }
          }
        }
        if (seen.size) {
          const rollup = MITRE.rollupByTactic(Array.from(seen.values()));
          if (Array.isArray(rollup) && rollup.length) {
            parts.push('\n## MITRE ATT&CK Coverage');
            for (const t of rollup) {
              parts.push(`\n### ${t.tacticLabel}`);
              for (const tech of t.techniques) {
                const sev = tech.severity && tech.severity !== 'info' && tech.severity !== 'medium'
                  ? ` (${tech.severity})` : '';
                parts.push(`- **${tech.id}** ${tech.name}${sev}`);
              }
            }
          }
        }
      }
    }


    // ── PE Binary ──
    if (f.peInfo) this._copyAnalysisPE(f.peInfo, parts, tp);

    // ── ELF Binary ──
    if (f.elfInfo) this._copyAnalysisELF(f.elfInfo, parts, tp);

    // ── Mach-O Binary ──
    if (f.machoInfo) this._copyAnalysisMachO(f.machoInfo, parts, tp);

    // ── X.509 Certificates ──
    if (f.x509Certs) this._copyAnalysisX509(f, parts, tp);

    // ── JAR / Java ──
    if (f.jarInfo) this._copyAnalysisJAR(f, parts, tp);

    // ── LNK-specific ──
    // The legacy writer only emitted target/args/workingDir; the LNK
    // renderer actually fills metadata with many more rich fields
    // (machineId, dropletMac, droidFile, msiProductCode, created,
    // modified, hotKey, iconLocation). Those come through the generic
    // metadata loop, but we also surface the three "headline" shortcut
    // pointers here as quotable inline values for analysts pasting into
    // a ticket.
    if (f.lnkTarget) parts.push(`\n## LNK Details\n- **Target:** \`${f.lnkTarget}\``);
    if (f.lnkArgs) parts.push(`- **Arguments:** \`${f.lnkArgs}\``);
    if (f.lnkWorkingDir) parts.push(`- **Working Dir:** \`${f.lnkWorkingDir}\``);

    // ── Email-specific ──
    if (f.authResults || f.spf || f.dkim || f.dmarc) {
      parts.push('\n## Email Authentication');
      if (f.authResults) parts.push(`- **Auth-Results:** ${f.authResults}`);
      if (f.spf) parts.push(`- **SPF:** ${f.spf}`);
      if (f.dkim) parts.push(`- **DKIM:** ${f.dkim}`);
      if (f.dmarc) parts.push(`- **DMARC:** ${f.dmarc}`);
    }

    // ── Format-family dispatch. Each helper is tolerant of its target
    //     data being absent; they only emit a section if something
    //     interesting is present, so ordering here is purely cosmetic. ──
    this._copyAnalysisPDF(f, parts, tp);
    this._copyAnalysisMSI(f, parts, tp);
    this._copyAnalysisOneNote(f, parts, tp);
    this._copyAnalysisRTF(f, parts, tp);
    this._copyAnalysisEML(f, parts, tp);
    this._copyAnalysisMSG(f, parts, tp);
    this._copyAnalysisHTML(f, parts, tp);
    this._copyAnalysisHTA(f, parts, tp);
    this._copyAnalysisSVG(f, parts, tp);
    this._copyAnalysisEVTX(f, parts, tp);
    this._copyAnalysisSQLite(f, parts, tp);
    this._copyAnalysisZIP(f, parts, tp);
    this._copyAnalysisISO(f, parts, tp);
    this._copyAnalysisDMG(f, parts, tp);
    this._copyAnalysisPKG(f, parts, tp);
    this._copyAnalysisImage(f, parts, tp);
    this._copyAnalysisPGP(f, parts, tp);
    this._copyAnalysisPlist(f, parts, tp);
    this._copyAnalysisOsascript(f, parts, tp);
    this._copyAnalysisOOXMLRels(f, parts, tp);
    this._copyAnalysisClickOnce(f, parts, tp);
    this._copyAnalysisMsix(f, parts, tp);
    this._copyAnalysisBrowserExt(f, parts, tp);

    return parts.length ? parts.join('\n') + '\n' : '';
  },

  // ── ClickOnce manifest detail ─────────────────────────────────────────
  //   Surfaces the parsed .application / .manifest so SOC paste-ups have
  //   the headline fields (codebase, trust level, AppDomainManager hijack,
  //   signature state) without having to re-open the file.
  _copyAnalysisClickOnce(f, parts, tp) {
    const co = f && f.clickOnceInfo;
    if (!co) return;

    parts.push('\n## ClickOnce Manifest Details');

    if (co.kind) {
      const kindLabel = co.kind === 'deployment' ? 'Deployment manifest (.application)'
        : co.kind === 'application' ? 'Application manifest (.manifest)'
          : co.kind;
      parts.push(`- **Manifest Kind:** ${tp(kindLabel)}`);
    }
    if (co.identity) {
      const id = co.identity;
      const idParts = [];
      if (id.name) idParts.push(id.name);
      if (id.version) idParts.push('v' + id.version);
      if (id.processorArchitecture) idParts.push(id.processorArchitecture);
      if (id.publicKeyToken) idParts.push('pkt=' + id.publicKeyToken);
      if (idParts.length) parts.push(`- **Identity:** ${tp(idParts.join(' '))}`);
    }
    if (co.description) {
      if (co.description.publisher) parts.push(`- **Publisher:** ${tp(co.description.publisher)}`);
      if (co.description.product) parts.push(`- **Product:** ${tp(co.description.product)}`);
      if (co.description.supportUrl) parts.push(`- **Support URL:** ${tp(co.description.supportUrl)}`);
    }

    if (co.deployment) {
      const d = co.deployment;
      parts.push('\n### Deployment');
      if (d.codebase) {
        const isHttp = /^http:\/\//i.test(d.codebase);
        parts.push(`- **Codebase:** ${tp(d.codebase)}${isHttp ? ' ⚠ (HTTP — MITM risk)' : ''}`);
      }
      if (d.install != null) parts.push(`- **Install:** ${d.install}${d.install === true ? ' (silent install on download)' : ''}`);
      if (d.mapFileExtensions != null) parts.push(`- **Map File Extensions:** ${d.mapFileExtensions}`);
      if (d.trustUrlParameters != null) parts.push(`- **Trust URL Parameters:** ${d.trustUrlParameters}${d.trustUrlParameters === true ? ' ⚠ (URL query → argv)' : ''}`);
      if (d.minimumRequiredVersion) parts.push(`- **Minimum Required Version:** ${tp(d.minimumRequiredVersion)}`);
    }

    if (co.entryPoint) {
      const ep = co.entryPoint;
      if (ep.commandLineFile || ep.dependentAssembly) {
        parts.push('\n### Entry Point');
        if (ep.commandLineFile) parts.push(`- **Command Line File:** \`${tp(ep.commandLineFile)}\``);
        if (ep.commandLineParameters) parts.push(`- **Parameters:** \`${tp(ep.commandLineParameters)}\``);
        if (ep.dependentAssembly && ep.dependentAssembly.name) {
          const da = ep.dependentAssembly;
          const daParts = [da.name];
          if (da.version) daParts.push('v' + da.version);
          if (da.processorArchitecture) daParts.push(da.processorArchitecture);
          parts.push(`- **Dependent Assembly:** ${tp(daParts.join(' '))}`);
        }
      }
    }

    if (co.trust) {
      parts.push('\n### Requested Trust');
      if (co.trust.fullTrust) {
        parts.push('- ⚠ **FullTrust (Unrestricted="true")** — unsandboxed .NET execution');
      } else if (co.trust.permissionSet) {
        parts.push(`- **Permission Set:** ${tp(co.trust.permissionSet)}`);
      } else {
        parts.push('- Declared permission set (not FullTrust)');
      }
      if (co.trust.defaultAssemblyRequest) {
        parts.push(`- **Default Assembly Request:** ${tp(co.trust.defaultAssemblyRequest)}`);
      }
    }

    if (co.appDomainManager && (co.appDomainManager.assembly || co.appDomainManager.type)) {
      parts.push('\n### AppDomainManager Override ⚠ (MITRE T1574.014)');
      if (co.appDomainManager.assembly) parts.push(`- **Assembly:** \`${tp(co.appDomainManager.assembly)}\``);
      if (co.appDomainManager.type) parts.push(`- **Type:** \`${tp(co.appDomainManager.type)}\``);
    }

    if (co.signature) {
      parts.push('\n### Signature');
      if (co.signature.hasCertificate) {
        parts.push('- **Status:** Authenticode-signed (embedded X509 certificate)');
        if (co.signature.subjectName) parts.push(`- **Subject:** ${tp(co.signature.subjectName)}`);
      } else if (co.signature.hasSignature) {
        parts.push('- **Status:** XMLDSig-signed (no embedded certificate)');
      } else {
        parts.push('- ⚠ **Status:** Unsigned — any tamper goes undetected');
      }
    }

    if (co.dependentAssemblies && co.dependentAssemblies.length) {
      const N = this._sCaps.rowCap(30);
      parts.push(`\n### Dependent Assemblies (${co.dependentAssemblies.length})`);
      parts.push('| Name | Version | Arch | Codebase |');
      parts.push('|------|---------|------|----------|');
      for (const d of co.dependentAssemblies.slice(0, N)) {
        parts.push(`| ${tp(d.name || '?')} | ${tp(d.version || '—')} | ${tp(d.processorArchitecture || '—')} | ${tp(d.codebase || '—')} |`);
      }
      if (co.dependentAssemblies.length > N) {
        parts.push(`… and ${co.dependentAssemblies.length - N} more`);
      }
    }
  },



  // ── MSIX / APPX / .appinstaller manifest detail ──────────────────────
  //   Produces a paste-able SOC summary for Windows app packages and
  //   App Installer files: identity, publisher, signature state, capability
  //   set (split general / device / restricted), per-application entry
  //   points and extensions, and — for .appinstaller — the auto-update
  //   policy. The renderer fills findings.msixInfo with the full parsed
  //   manifest tree; this helper only formats what's already there.
  _copyAnalysisMsix(f, parts, tp) {
    const mx = f && f.msixInfo;
    if (!mx) return;

    const kindLabel = mx.containerKind === 'bundle' ? 'MSIX / APPX Bundle (.msixbundle / .appxbundle)'
      : mx.containerKind === 'package' ? 'MSIX / APPX Package (.msix / .appx)'
        : mx.containerKind === 'appinstaller' ? 'App Installer File (.appinstaller)'
          : mx.containerKind || 'MSIX';
    parts.push('\n## MSIX Package Details');
    parts.push(`- **Format:** ${tp(kindLabel)}`);

    // ── Identity / Publisher ──
    if (mx.identity) {
      const id = mx.identity;
      const bits = [];
      if (id.name) bits.push(id.name);
      if (id.version) bits.push('v' + id.version);
      if (id.processorArchitecture) bits.push(id.processorArchitecture);
      if (id.resourceId) bits.push('res=' + id.resourceId);
      if (bits.length) parts.push(`- **Identity:** ${tp(bits.join(' '))}`);
      if (id.publisher) parts.push(`- **Publisher (CN):** ${tp(id.publisher)}`);
    }
    if (mx.properties) {
      if (mx.properties.displayName) parts.push(`- **Display Name:** ${tp(mx.properties.displayName)}`);
      if (mx.properties.publisherDisplayName) parts.push(`- **Publisher (Display):** ${tp(mx.properties.publisherDisplayName)}`);
      if (mx.properties.description) parts.push(`- **Description:** ${tp(mx.properties.description)}`);
    }

    // ── Signature / Block Map (ZIP containers only) ──
    if (mx.containerKind === 'package' || mx.containerKind === 'bundle') {
      if (mx.hasSignature) {
        parts.push(`- **Signature:** Signed (AppxSignature.p7x${mx.hasCodeIntegrityCat ? ' + CodeIntegrity catalog' : ''})`);
      } else {
        parts.push('- ⚠ **Signature:** Unsigned / sideload-only — no Authenticode signature block');
      }
      parts.push(`- **Block Map:** ${mx.hasBlockMap ? 'Present' : '⚠ Missing'}`);
    }

    // ── Target device families ──
    if (mx.targetDeviceFamilies && mx.targetDeviceFamilies.length) {
      const list = mx.targetDeviceFamilies
        .map(t => `${t.name || '?'}${t.minVersion ? ' ≥ ' + t.minVersion : ''}`)
        .join(', ');
      parts.push(`- **Target Device Families:** ${tp(list)}`);
    }

    // ── Capabilities (split by severity class) ──
    if (mx.capabilities && mx.capabilities.length) {
      const rescap = mx.capabilities.filter(c => c.restricted);
      const device = mx.capabilities.filter(c => !c.restricted && c.device);
      const general = mx.capabilities.filter(c => !c.restricted && !c.device);
      parts.push(`\n### Declared Capabilities (${mx.capabilities.length})`);
      if (rescap.length) {
        parts.push(`- ⚠ **Restricted (rescap):** ${rescap.map(c => tp(c.name || '?')).join(', ')}`);
      }
      if (device.length) {
        parts.push(`- **Device:** ${device.map(c => tp(c.name || '?')).join(', ')}`);
      }
      if (general.length) {
        parts.push(`- **General:** ${general.map(c => tp(c.name || '?')).join(', ')}`);
      }
    }

    // ── Applications / Entry points / Extensions ──
    if (mx.applications && mx.applications.length) {
      const AN = this._sCaps.rowCap(20);
      parts.push(`\n### Applications / Entry Points (${mx.applications.length})`);
      for (const a of mx.applications.slice(0, AN)) {
        const head = `**${tp(a.id || '(app)')}** — \`${tp(a.executable || '(no exe)')}\``
          + (a.entryPoint === 'Windows.FullTrustApplication' ? ' ⚠ (FullTrust entry)' : '');
        parts.push(`\n- ${head}`);
        if (a.displayName) parts.push(`  - Display: ${tp(a.displayName)}`);
        if (a.startPage) parts.push(`  - StartPage: ${tp(a.startPage)}`);
        if (a.extensions && a.extensions.length) {
          for (const ex of a.extensions) {
            const line = this._formatMsixExtension(ex, tp);
            if (line) parts.push(`  - ${line}`);
          }
        }
      }
      if (mx.applications.length > AN) parts.push(`\n… and ${mx.applications.length - AN} more applications`);
    }

    // ── Bundle package list ──
    if (mx.bundlePackages && mx.bundlePackages.length) {
      const BN = this._sCaps.rowCap(30);
      parts.push(`\n### Bundle Contents (${mx.bundlePackages.length})`);
      parts.push('| Type | Architecture | Version | FileName |');
      parts.push('|------|--------------|---------|----------|');
      for (const p of mx.bundlePackages.slice(0, BN)) {
        parts.push(`| ${tp(p.type || '—')} | ${tp(p.architecture || '—')} | ${tp(p.version || '—')} | \`${tp(p.fileName || '?')}\` |`);
      }
      if (mx.bundlePackages.length > BN) parts.push(`… and ${mx.bundlePackages.length - BN} more`);
    }


    // ── App Installer fields ──
    if (mx.containerKind === 'appinstaller') {
      parts.push('\n### App Installer');
      if (mx.uri) {
        const isHttp = /^http:\/\//i.test(mx.uri);
        parts.push(`- **Self Uri:** \`${tp(mx.uri)}\`${isHttp ? ' ⚠ (HTTP — MITM risk)' : ''}`);
      }
      if (mx.version) parts.push(`- **Version:** ${tp(mx.version)}`);
      if (mx.mainPackage) {
        const mp = mx.mainPackage;
        const bits = [];
        if (mp.name) bits.push(mp.name);
        if (mp.version) bits.push('v' + mp.version);
        if (mp.processorArchitecture) bits.push(mp.processorArchitecture);
        if (bits.length) parts.push(`- **Main Package:** ${tp(bits.join(' '))}`);
        if (mp.uri) {
          const isHttp = /^http:\/\//i.test(mp.uri);
          parts.push(`- **Main Package Uri:** \`${tp(mp.uri)}\`${isHttp ? ' ⚠ (HTTP — MITM risk)' : ''}`);
        }
      }
      if (mx.mainBundle) {
        const mb = mx.mainBundle;
        const bits = [];
        if (mb.name) bits.push(mb.name);
        if (mb.version) bits.push('v' + mb.version);
        if (mb.processorArchitecture) bits.push(mb.processorArchitecture);
        if (bits.length) parts.push(`- **Main Bundle:** ${tp(bits.join(' '))}`);
        if (mb.uri) {
          const isHttp = /^http:\/\//i.test(mb.uri);
          parts.push(`- **Main Bundle Uri:** \`${tp(mb.uri)}\`${isHttp ? ' ⚠ (HTTP — MITM risk)' : ''}`);
        }
      }
      if (mx.dependencies && mx.dependencies.length) {
        const DN = this._sCaps.rowCap(10);
        parts.push(`- **Dependencies (${mx.dependencies.length}):**`);
        for (const d of mx.dependencies.slice(0, DN)) {

          const bits = [];
          if (d.name) bits.push(d.name);
          if (d.version) bits.push('v' + d.version);
          if (d.processorArchitecture) bits.push(d.processorArchitecture);
          parts.push(`  - ${tp(bits.join(' '))}${d.uri ? ` → \`${tp(d.uri)}\`` : ''}`);
        }
      }
      if (mx.updateSettings) {
        const us = mx.updateSettings;
        parts.push('- **Update Settings:**');
        if (us.onLaunch) {
          const bits = [];
          if (us.onLaunch.hoursBetweenUpdateChecks != null) bits.push(`every ${us.onLaunch.hoursBetweenUpdateChecks}h`);
          if (us.onLaunch.updateBlocksActivation === true) bits.push('blocks activation');
          if (us.onLaunch.showPrompt === false) bits.push('⚠ silent (no prompt)');
          parts.push(`  - OnLaunch: ${bits.length ? bits.join(', ') : 'enabled'}`);
        }
        if (us.automaticBackgroundTask) parts.push('  - AutomaticBackgroundTask: enabled');
        if (us.forceUpdateFromAnyVersion === true) parts.push('  - ⚠ ForceUpdateFromAnyVersion: true');
      }
    }
  },

  // ── Browser extension (CRX / XPI) detail ───────────────────────────────
  //   Surfaces the parsed manifest.json (or legacy install.rdf) so paste-up
  //   analysts see the container kind, signing state, Chrome Web Store /
  //   AMO ID, manifest version, permission + host-grant split, entry
  //   points (background worker / content scripts / action popup), CSP,
  //   externally_connectable, update channel, and legacy XUL flags. The
  //   renderer fills findings.browserExtInfo with the full parsed record;
  //   this helper only formats what's already there.
  _copyAnalysisBrowserExt(f, parts, tp) {
    const bx = f && f.browserExtInfo;
    if (!bx) return;

    const kindLabel = bx.containerKind === 'crx' ? 'Chrome / Edge Extension (.crx)'
      : bx.containerKind === 'xpi' ? 'Firefox WebExtension (.xpi)'
        : bx.containerKind === 'xpi-legacy' ? 'Legacy Firefox Add-on (.xpi, install.rdf)'
          : bx.containerKind || 'Browser Extension';
    parts.push('\n## Browser Extension Details');
    parts.push(`- **Format:** ${tp(kindLabel)}`);

    // ── Identity ──
    if (bx.name) parts.push(`- **Name:** ${tp(bx.name)}`);
    if (bx.version) parts.push(`- **Version:** ${tp(bx.version)}`);
    if (bx.description) parts.push(`- **Description:** ${tp(bx.description)}`);
    if (bx.author) parts.push(`- **Author:** ${tp(bx.author)}`);
    if (bx.homepageUrl) parts.push(`- **Homepage:** \`${tp(bx.homepageUrl)}\``);
    if (bx.manifestVersion != null) {
      parts.push(`- **Manifest Version:** ${bx.manifestVersion}${bx.manifestVersion === 2 ? ' (MV2 — deprecated)' : ''}`);
    }

    // ── CRX envelope / Mozilla signing ──
    if (bx.containerKind === 'crx') {
      const sigBits = [];
      if (bx.crxVersion) sigBits.push(`Cr24 v${bx.crxVersion}`);
      if (bx.crxVersion === 2) {
        sigBits.push(`pubKey=${bx.crxPubKeyLen || 0}B`);
        sigBits.push(`sig=${bx.crxSigLen || 0}B`);
      } else if (bx.crxVersion === 3) {
        sigBits.push(`header=${bx.crxHeaderLen || 0}B`);
        sigBits.push('protobuf (not parsed)');
      }
      parts.push(`- **CRX Envelope:** ${tp(sigBits.join(', '))}`);
      if (bx.crxId) parts.push(`- **Chrome Extension ID:** \`${tp(bx.crxId)}\``);
      // Surface the (large) CRX header if we have room — it contains the
      // developer's public key and signature and is evidence for pinning.
      if (bx.crxPublicKey && this._sCaps.SCALE >= 2) {
        const pk = bx.crxPublicKey;
        const cap = this._sCaps.charCap(400);
        parts.push(`- **CRX Public Key (base64):** \`${tp(pk.length > cap ? pk.slice(0, cap) + '…' : pk)}\``);
      }

    } else if (bx.containerKind === 'xpi' || bx.containerKind === 'xpi-legacy') {
      const sigBits = [];
      if (bx.hasMozillaSig) sigBits.push('META-INF/mozilla.rsa');
      if (bx.hasCoseSig) sigBits.push('META-INF/cose.sig');
      if (sigBits.length) parts.push(`- **Mozilla Signature:** ${tp(sigBits.join(' + '))}`);
      else parts.push('- ⚠ **Mozilla Signature:** Unsigned XPI (no META-INF/mozilla.rsa)');
      if (bx.geckoId) parts.push(`- **gecko.id:** \`${tp(bx.geckoId)}\``);
      if (bx.geckoStrictMinVersion) parts.push(`- **gecko.strict_min_version:** ${tp(bx.geckoStrictMinVersion)}`);
    }

    // ── Update channel ──
    if (bx.updateUrl) {
      const u = bx.updateUrl;
      const isStore = /(^|\.)google\.com\/|(^|\.)mozilla\.org\/|addons\.mozilla\.org/i.test(u);
      const isHttp = /^http:\/\//i.test(u);
      const tag = isHttp ? ' ⚠ (HTTP — MITM risk)'
        : !isStore ? ' ⚠ (off-store auto-update channel)'
          : '';
      parts.push(`- **Update URL:** \`${tp(u)}\`${tag}`);
    }

    // ── Permissions split by tier ──
    if ((bx.permissions && bx.permissions.length) ||
      (bx.optionalPermissions && bx.optionalPermissions.length) ||
      (bx.hostPermissions && bx.hostPermissions.length) ||
      (bx.optionalHostPermissions && bx.optionalHostPermissions.length)) {
      const HIGH = (BrowserExtRenderer.PERM_HIGH || new Set());
      const MED = (BrowserExtRenderer.PERM_MEDIUM || new Set());
      const hi = [], md = [], lo = [];
      for (const p of (bx.permissions || [])) {
        if (HIGH.has(p)) hi.push(p);
        else if (MED.has(p)) md.push(p);
        else lo.push(p);
      }
      parts.push(`\n### Permissions (${(bx.permissions || []).length})`);
      if (hi.length) parts.push(`- ⚠ **High-risk:** ${hi.map(p => '`' + tp(p) + '`').join(', ')}`);
      if (md.length) parts.push(`- **Medium-risk:** ${md.map(p => '`' + tp(p) + '`').join(', ')}`);
      if (lo.length) parts.push(`- **Standard:** ${lo.map(p => '`' + tp(p) + '`').join(', ')}`);
      if (bx.optionalPermissions && bx.optionalPermissions.length) {
        parts.push(`- **Optional:** ${bx.optionalPermissions.map(p => '`' + tp(p) + '`').join(', ')}`);
      }

      if (bx.hostPermissions && bx.hostPermissions.length) {
        const HP = this._sCaps.rowCap(20);
        const broadHosts = bx.hostPermissions.filter(h => /^<all_urls>$|^\*:\/\/\*\/\*$|^https?:\/\/\*\/\*$/i.test(h));
        parts.push(`- **Host Permissions (${bx.hostPermissions.length}):** ${bx.hostPermissions.slice(0, HP).map(h => '`' + tp(h) + '`').join(', ')}${bx.hostPermissions.length > HP ? `, … +${bx.hostPermissions.length - HP} more` : ''}`);
        if (broadHosts.length) {
          parts.push(`  - ⚠ Broad grant: ${broadHosts.map(h => '`' + tp(h) + '`').join(', ')} — content scripts / webRequest see every site the user visits`);
        }
      }
      if (bx.optionalHostPermissions && bx.optionalHostPermissions.length) {
        parts.push(`- **Optional Host Permissions:** ${bx.optionalHostPermissions.slice(0, this._sCaps.rowCap(20)).map(h => '`' + tp(h) + '`').join(', ')}`);
      }
    }


    // ── Entry points ──
    const entryBits = [];
    if (bx.serviceWorker) entryBits.push(`service_worker → \`${tp(bx.serviceWorker)}\``);
    if (bx.backgroundPage) entryBits.push(`background.page → \`${tp(bx.backgroundPage)}\``);
    if (bx.backgroundScripts && bx.backgroundScripts.length) {
      entryBits.push(`background.scripts: ${bx.backgroundScripts.map(s => '`' + tp(s) + '`').join(', ')}`);
    }
    if (bx.actionPopup) entryBits.push(`action.default_popup → \`${tp(bx.actionPopup)}\``);
    if (bx.browserActionPopup) entryBits.push(`browser_action.default_popup → \`${tp(bx.browserActionPopup)}\``);
    if (bx.pageActionPopup) entryBits.push(`page_action.default_popup → \`${tp(bx.pageActionPopup)}\``);
    if (bx.optionsPage) entryBits.push(`options_page → \`${tp(bx.optionsPage)}\``);
    if (bx.optionsUiPage) entryBits.push(`options_ui.page → \`${tp(bx.optionsUiPage)}\``);
    if (bx.devtoolsPage) entryBits.push(`devtools_page → \`${tp(bx.devtoolsPage)}\``);
    if (bx.sidebarActionPanel) entryBits.push(`sidebar_action.default_panel → \`${tp(bx.sidebarActionPanel)}\``);
    if (entryBits.length) {
      parts.push('\n### Entry Points');
      for (const e of entryBits) parts.push(`- ${e}`);
    }

    // ── Content scripts ──
    if (bx.contentScripts && bx.contentScripts.length) {
      const CN = this._sCaps.rowCap(20);
      const MN = this._sCaps.rowCap(6);
      parts.push(`\n### Content Scripts (${bx.contentScripts.length})`);
      for (const cs of bx.contentScripts.slice(0, CN)) {
        const matches = (cs.matches || []).slice(0, MN).map(m => '`' + tp(m) + '`').join(', ');
        const runAt = cs.runAt ? ` run_at=${tp(cs.runAt)}` : '';
        const world = cs.world ? ` world=${tp(cs.world)}` : '';
        const files = (cs.js || []).map(j => '`' + tp(j) + '`').join(', ');
        const css = (cs.css || []).map(c => '`' + tp(c) + '`').join(', ');
        const matchMore = (cs.matches || []).length > MN ? `, … +${cs.matches.length - MN}` : '';
        parts.push(`- matches: ${matches || '—'}${matchMore}${runAt}${world}`);
        if (files) parts.push(`  - js: ${files}`);
        if (css) parts.push(`  - css: ${css}`);
      }
      if (bx.contentScripts.length > CN) parts.push(`… and ${bx.contentScripts.length - CN} more`);
    }


    // ── CSP / externally connectable / WAR ──
    if (bx.contentSecurityPolicy) {
      const csp = bx.contentSecurityPolicy;
      const unsafe = /'unsafe-(?:eval|inline)'/i.test(csp);
      parts.push('\n### Content Security Policy');
      parts.push(`- ${unsafe ? '⚠ ' : ''}\`${tp(csp)}\``);
    }

    if (bx.externallyConnectable) {
      const ec = bx.externallyConnectable;
      const bits = [];
      if (ec.ids && ec.ids.length) bits.push(`ids: ${ec.ids.map(i => '`' + tp(i) + '`').join(', ')}`);
      if (ec.matches && ec.matches.length) bits.push(`matches: ${ec.matches.map(m => '`' + tp(m) + '`').join(', ')}`);
      if (ec.acceptsTlsChannelId) bits.push('acceptsTlsChannelId=true');
      if (bits.length) {
        parts.push('\n### Externally Connectable');
        parts.push(`- ${bits.join(' · ')}`);
      }
    }

    if (bx.webAccessibleResources && bx.webAccessibleResources.length) {
      const WN = this._sCaps.rowCap(15);
      const RN2 = this._sCaps.rowCap(8);
      const MN2 = this._sCaps.rowCap(6);
      parts.push(`\n### Web-Accessible Resources (${bx.webAccessibleResources.length})`);
      for (const war of bx.webAccessibleResources.slice(0, WN)) {
        const res = (war.resources || []).slice(0, RN2).map(r => '`' + tp(r) + '`').join(', ');
        const mt = (war.matches || []).slice(0, MN2).map(m => '`' + tp(m) + '`').join(', ');
        parts.push(`- resources: ${res || '—'}${mt ? ` — matches: ${mt}` : ''}`);
      }
      if (bx.webAccessibleResources.length > WN) parts.push(`… and ${bx.webAccessibleResources.length - WN} more`);
    }

    // ── Commands (keyboard shortcuts) ──
    if (bx.commands && bx.commands.length) {
      parts.push(`\n### Commands / Keyboard Shortcuts (${bx.commands.length})`);
      for (const cmd of bx.commands.slice(0, this._sCaps.rowCap(10))) {

        const key = cmd.suggestedKey ? ` → ${tp(cmd.suggestedKey)}` : '';
        parts.push(`- \`${tp(cmd.name || '?')}\`${key}${cmd.description ? ` — ${tp(cmd.description)}` : ''}`);
      }
    }

    // ── Legacy XUL / bootstrap flag ──
    if (bx.bootstrap) {
      parts.push('\n### Legacy Firefox XUL');
      parts.push('- ⚠ `em:bootstrap=true` — pre-WebExtension add-on with full XPCOM / chrome access');
    }
    if (bx.hasChromeManifest) {
      parts.push('- Legacy `chrome.manifest` present — classic XUL add-on shape');
    }
  },

  // Format one MSIX <Extension> entry as a single compact bullet. Returns
  // null if the extension carries no interesting attributes.
  _formatMsixExtension(ex, tp) {
    if (!ex) return null;
    const cat = ex.category || '(extension)';
    const sev = ex.severity === 'high' ? ' ⚠' : ex.severity === 'medium' ? ' ⚠' : '';
    switch (cat) {
      case 'windows.fullTrustProcess':
        return `${sev} fullTrustProcess → \`${tp(ex.executable || '?')}\``;
      case 'windows.startupTask':
        return `${sev} startupTask${ex.taskId ? ` (${tp(ex.taskId)})` : ''}${ex.enabled === true ? ' [enabled]' : ''}`
          + (ex.executable ? ` → \`${tp(ex.executable)}\`` : '');
      case 'windows.appExecutionAlias': {
        const list = (ex.aliases || []).map(a => '`' + tp(a) + '`').join(', ') || '—';
        return `${sev} appExecutionAlias: ${list}`;
      }
      case 'windows.protocol': {
        const list = (ex.protocols || []).map(p => '`' + tp(p) + '`').join(', ') || '—';
        return `${sev} protocol: ${list}`;
      }
      case 'windows.fileTypeAssociation': {
        const list = (ex.fileTypes || []).slice(0, this._sCaps.rowCap(10)).map(t => '`' + tp(t) + '`').join(', ');
        return `fileTypeAssociation${ex.name ? ` (${tp(ex.name)})` : ''}${list ? ': ' + list : ''}`;
      }

      case 'windows.service':
        return `${sev} service → \`${tp(ex.executable || '?')}\``;
      case 'windows.backgroundTasks': {
        const list = (ex.triggers || []).map(t => '`' + tp(t) + '`').join(', ') || '—';
        return `backgroundTasks: ${list}${ex.entryPoint ? ` (entry: ${tp(ex.entryPoint)})` : ''}`;
      }
      case 'com.Extension':
      case 'windows.comServer':
      case 'windows.comInterface':
        return `${sev} ${cat}${ex.executable ? ` → \`${tp(ex.executable)}\`` : ''}`;
      default:
        return `${cat}${ex.executable ? ` → \`${tp(ex.executable)}\`` : ''}`;
    }
  },


  // ── Go Build Info (shared by PE / ELF) ────────────────────────────────
  _copyAnalysisGoBuildInfo(parsed, parts, tp) {
    if (!parsed.isGoBinary) return;
    parts.push('\n### Go Build Info');
    const g = parsed.goBuildInfo || {};
    if (g.version) parts.push(`- **Go Version:** ${tp(g.version)}`);
    if (g.path) parts.push(`- **Main Package:** \`${tp(g.path)}\``);
    if (g.vcs) parts.push(`- **VCS:** ${tp(g.vcs)}`);
    if (g.revision) parts.push(`- **Revision:** \`${tp(g.revision)}\``);
    if (g.buildTime) parts.push(`- **Build Time:** ${tp(g.buildTime)}`);
    if (g.settings && Object.keys(g.settings).length) {
      const extra = Object.entries(g.settings)
        .filter(([k]) => k !== 'vcs' && k !== 'vcs.revision' && k !== 'vcs.time')
        .slice(0, 10);
      for (const [k, v] of extra) parts.push(`- **${tp(k)}:** ${tp(String(v))}`);
    }
    if (!g.version && !g.path) parts.push('- Go binary detected via section name (.gopclntab / .go.buildinfo); build info header was not parseable.');
  },

  // ── PE deep data ──────────────────────────────────────────────────────
  _copyAnalysisPE(pe, parts, tp) {
    parts.push('\n## PE Binary Details');

    // Headers
    if (pe.coff) {
      parts.push('\n### PE Headers');
      parts.push('| Field | Value |');
      parts.push('|-------|-------|');
      parts.push(`| Machine | ${tp(pe.coff.machineStr)} |`);
      parts.push(`| Sections | ${pe.coff.numSections} |`);
      parts.push(`| Timestamp | ${tp(pe.coff.timestampStr)} |`);
      if (pe.coff.characteristicsFlags) parts.push(`| Characteristics | ${tp(pe.coff.characteristicsFlags.join(', '))} |`);
      if (pe.optional) {
        parts.push(`| PE Format | ${tp(pe.optional.magicStr)} |`);
        parts.push(`| Entry Point | 0x${(pe.optional.entryPoint || 0).toString(16)} |`);
        parts.push(`| Image Base | 0x${(pe.optional.imageBase || 0).toString(16)} |`);
        parts.push(`| Subsystem | ${tp(pe.optional.subsystemStr)} |`);
        if (pe.optional.dllCharFlags) parts.push(`| DLL Characteristics | ${tp(pe.optional.dllCharFlags.join(', '))} |`);
      }
    }

    // Security features
    if (pe.security) {
      const s = pe.security;
      const feat = [];
      if (s.aslr !== undefined) feat.push(`ASLR: ${s.aslr ? '✅' : '❌'}`);
      if (s.dep !== undefined) feat.push(`DEP/NX: ${s.dep ? '✅' : '❌'}`);
      if (s.cfg !== undefined) feat.push(`CFG: ${s.cfg ? '✅' : '❌'}`);
      if (s.seh !== undefined) feat.push(`SEH: ${s.seh ? '✅' : '❌'}`);
      if (s.signed !== undefined) feat.push(`Signed: ${s.signed ? '✅' : '❌'}`);
      if (s.gs !== undefined) feat.push(`GS: ${s.gs ? '✅' : '❌'}`);
      if (s.highEntropyVA !== undefined) feat.push(`High Entropy VA: ${s.highEntropyVA ? '✅' : '❌'}`);
      if (feat.length) parts.push('\n### Security Features\n' + feat.join(', '));
    }

    // Version info / debug / imphash
    if (pe.versionInfo && Object.keys(pe.versionInfo).length) {
      parts.push('\n### Version Info');
      for (const [k, v] of Object.entries(pe.versionInfo)) parts.push(`- **${k}:** ${v}`);
    }
    if (pe.debugInfo && pe.debugInfo.pdbPath) parts.push(`\n**PDB Path:** \`${pe.debugInfo.pdbPath}\``);
    if (pe.debugInfo && pe.debugInfo.guid) parts.push(`**Debug GUID:** \`${pe.debugInfo.guid}\`${pe.debugInfo.age != null ? ` (age ${pe.debugInfo.age})` : ''}`);
    if (pe.imphash) parts.push(`**Imphash:** \`${pe.imphash}\``);
    // TLS callbacks — pointers to code that runs *before* the entry point,
    // a classic anti-debug / initial-exec hook. Surface the count so the
    // analyst knows to look at the TLS directory section.
    if (pe.tlsCallbacks && pe.tlsCallbacks.length) {
      parts.push(`**TLS Callbacks:** ${pe.tlsCallbacks.length}`);
    }
    // Overlay — bytes appended after the final PE section (often a
    // self-extracting payload or trailing signed blob).
    if (pe.overlayInfo && pe.overlayInfo.size) {
      parts.push(`**Overlay:** ${pe.overlayInfo.size} bytes at offset 0x${(pe.overlayInfo.offset || 0).toString(16)}${pe.overlayInfo.entropy != null ? ` (entropy ${pe.overlayInfo.entropy.toFixed(2)})` : ''}`);
    }

    // Section table
    if (pe.sections && pe.sections.length) {
      parts.push('\n### Sections');
      parts.push('| Name | VirtSize | RawSize | Entropy | Flags |');
      parts.push('|------|----------|---------|---------|-------|');
      for (const s of pe.sections) {
        const entropy = s.entropy !== undefined ? s.entropy.toFixed(2) : '—';
        const flags = (s.charFlags || []).join(', ') || tp(s.characteristics);
        parts.push(`| ${tp(s.name)} | 0x${(s.virtualSize || 0).toString(16)} | 0x${(s.rawSize || 0).toString(16)} | ${entropy} | ${tp(flags)} |`);
      }
    }

    // Imports (prioritize suspicious)
    if (pe.imports && pe.imports.length) {
      parts.push(`\n### Imports (${pe.imports.length} DLLs)`);
      const suspicious = [];
      const normal = [];
      for (const imp of pe.imports) {
        const dll = imp.dllName || imp.dll || imp.name || '?';
        const funcs = imp.functions || [];
        const susp = funcs.filter(fn => fn.isSuspicious);
        if (susp.length) {
          suspicious.push(`**${dll}** — ⚠ ${susp.map(fn => fn.name).join(', ')}${funcs.length > susp.length ? ` + ${funcs.length - susp.length} others` : ''}`);
        } else {
          normal.push(`**${dll}** (${funcs.length}) — ${funcs.slice(0, 8).map(fn => fn.name).join(', ')}${funcs.length > 8 ? '…' : ''}`);
        }
      }
      if (suspicious.length) {
        parts.push('\n**Suspicious imports:**');
        for (const s of suspicious) parts.push(`- ${s}`);
      }
      // Show normal imports if we have budget. Base import count scales
      // with the Summary budget — 30 at 64 K default, 60 at 128 K, ∞ at
      // MAX — so bigger reports list more vendor DLLs instead of hiding
      // them behind an ellipsis.
      const baseImportCap = this._sCaps.rowCap(30);
      const normalLimit = (baseImportCap === Infinity)
        ? Infinity
        : Math.max(5, baseImportCap - suspicious.length);
      if (normal.length) {
        parts.push('\n**Other imports:**');
        const takeN = normalLimit === Infinity ? normal.length : normalLimit;
        for (const n of normal.slice(0, takeN)) parts.push(`- ${n}`);
        if (normal.length > takeN) parts.push(`- … and ${normal.length - takeN} more DLLs`);
      }
    }

    // Exports
    if (pe.exports && pe.exports.names && pe.exports.names.length) {
      const ex = pe.exports;
      const EN = this._sCaps.rowCap(30);
      parts.push(`\n### Exports (${ex.numNames || ex.names.length} functions)`);
      if (ex.dllName) parts.push(`**DLL name:** ${ex.dllName}`);
      const names = ex.names.slice(0, EN).map(n => n.name || `Ordinal#${n.ordinal}`);
      parts.push(names.join(', ') + (ex.names.length > EN ? `… (+${ex.names.length - EN})` : ''));
    }

    // Rich Header
    if (pe.richHeader && pe.richHeader.entries && pe.richHeader.entries.length) {
      const RN = this._sCaps.rowCap(20);
      parts.push(`\n### Rich Header (XOR key: 0x${(pe.richHeader.xorKey || 0).toString(16)})`);
      parts.push('| CompID | BuildID | Count |');
      parts.push('|--------|---------|-------|');
      for (const e of pe.richHeader.entries.slice(0, RN)) {
        parts.push(`| ${e.compId} | ${e.buildId} | ${e.count} |`);
      }
      if (pe.richHeader.entries.length > RN) parts.push(`… and ${pe.richHeader.entries.length - RN} more`);
    }


    // Authenticode Certificates
    if (pe.certificates && pe.certificates.length) {
      parts.push(`\n### Authenticode Certificates (${pe.certificates.length})`);
      for (const c of pe.certificates) {
        const label = (c.subject && c.subject.CN) || (c.subject && c.subject.O) || 'Certificate';
        parts.push(`\n**${label}**`);
        parts.push('| Field | Value |');
        parts.push('|-------|-------|');
        if (c.subjectStr) parts.push(`| Subject | ${tp(c.subjectStr)} |`);
        if (c.issuerStr) parts.push(`| Issuer | ${tp(c.issuerStr)} |`);
        if (c.serialNumber) parts.push(`| Serial | ${tp(c.serialNumber)} |`);
        if (c.notBeforeStr) parts.push(`| Not Before | ${tp(c.notBeforeStr)} |`);
        if (c.notAfterStr) parts.push(`| Not After | ${tp(c.notAfterStr)} |`);
        let pk = c.publicKeyAlgorithm || '';
        if (c.publicKeySize) pk += ` ${c.publicKeySize}-bit`;
        if (pk) parts.push(`| Public Key | ${tp(pk)} |`);
        if (c.signatureAlgorithm) parts.push(`| Signature | ${tp(c.signatureAlgorithm)} |`);
        if (c.isSelfSigned) parts.push(`| Self-Signed | Yes |`);
        if (c.isCA) parts.push(`| CA | Yes |`);
      }
    }

    // Resources
    if (pe.resources && pe.resources.length) {
      const RC = this._sCaps.rowCap(20);
      parts.push(`\n### Resources (${pe.resources.length} types)`);
      for (const r of pe.resources.slice(0, RC)) {
        parts.push(`- ${r.typeName || 'Type#' + r.id}${r.count ? ' (' + r.count + ' entries)' : ''}`);
      }
      if (pe.resources.length > RC) parts.push(`… and ${pe.resources.length - RC} more`);
    }


    // Data Directories
    if (pe.dataDirectories && pe.dataDirectories.length) {
      const active = pe.dataDirectories.filter(d => d.size > 0);
      if (active.length) {
        parts.push('\n### Data Directories');
        parts.push('| Directory | RVA | Size |');
        parts.push('|-----------|-----|------|');
        for (const d of active) {
          parts.push(`| ${tp(d.name)} | 0x${(d.rva || 0).toString(16)} | 0x${(d.size || 0).toString(16)} |`);
        }
      }
    }

    // ── Format heuristics ──
    //   Populated by PeRenderer._detectFormatHeuristics. Each flag is a
    //   flat field on `pe`, so any combination can fire independently
    //   (e.g. a Go binary that is also an Inno wrapper). We emit a
    //   dedicated subsection per detected sub-format so analysts can
    //   paste the whole Summary into a ticket and have the headline
    //   classification jump out.
    if (pe.isXll) {
      parts.push('\n### XLL (Excel Add-in)');
      if (pe.xllIsExcelDna) parts.push('- **Runtime:** Excel-DNA managed add-in (.NET)');
      if (pe.xllExports && pe.xllExports.length) {
        parts.push(`- **XLL Hooks:** ${pe.xllExports.map(n => `\`${n}\``).join(', ')}`);
      }
      parts.push('- ⚠ Loaded into Excel as a DLL; `xlAutoOpen` runs automatically on load.');
    }
    if (pe.isAutoHotkey) {
      parts.push('\n### Compiled AutoHotkey Script');
      if (pe.autoHotkeyOffset != null) {
        parts.push(`- **Script Offset:** 0x${(pe.autoHotkeyOffset || 0).toString(16)}`);
      }
      if (pe.autoHotkeyScript) {
        parts.push(`- **Script Size:** ${pe.autoHotkeyScript.length.toLocaleString()} bytes`);
        const ahkMax = (this._sCaps && this._sCaps.charCap) ? this._sCaps.charCap(400) : 400;
        const preview = pe.autoHotkeyScript.slice(0, ahkMax).replace(/\r\n?/g, '\n');
        parts.push('- **Preview:**\n```\n' + preview + (pe.autoHotkeyScript.length > ahkMax ? '\n…' : '') + '\n```');
      }
    }
    if (pe.installerType) {
      parts.push(`\n### ${tp(pe.installerType)} Installer`);
      if (pe.installerVersion) parts.push(`- **Version:** ${tp(pe.installerVersion)}`);
      parts.push('- Payload archive is embedded as a PE overlay; Loupe does **not** unpack it — run the installer in an isolated sandbox and triage the extracted setup script separately.');
    }
    this._copyAnalysisGoBuildInfo(pe, parts, tp);
  },


  // ── ELF deep data ─────────────────────────────────────────────────────
  _copyAnalysisELF(elf, parts, tp) {
    parts.push('\n## ELF Binary Details');

    // Header
    if (elf.header || elf.ident) {
      parts.push('\n### ELF Header');
      parts.push('| Field | Value |');
      parts.push('|-------|-------|');
      if (elf.ident) {
        parts.push(`| Class | ${tp(elf.ident.classStr)} |`);
        parts.push(`| Endianness | ${tp(elf.ident.dataStr)} |`);
        if (elf.ident.osabiStr) parts.push(`| OS/ABI | ${tp(elf.ident.osabiStr)} |`);
      }
      if (elf.header) {
        parts.push(`| Type | ${tp(elf.header.typeStr)} |`);
        parts.push(`| Machine | ${tp(elf.header.machineStr)} |`);
        parts.push(`| Entry Point | 0x${(elf.header.entry || 0).toString(16)} |`);
      }
      if (elf.interpreter) parts.push(`| Interpreter | ${tp(elf.interpreter)} |`);
    }

    // Security features
    if (elf.security) {
      const s = elf.security;
      const feat = [];
      if (s.relro) feat.push(`RELRO: ${s.relro}`);
      if (s.nx !== undefined) feat.push(`NX: ${s.nx ? '✅' : '❌'}`);
      if (s.pie !== undefined) feat.push(`PIE: ${s.pie ? '✅' : '❌'}`);
      if (s.canary !== undefined) feat.push(`Stack Canary: ${s.canary ? '✅' : '❌'}`);
      if (s.fortify !== undefined) feat.push(`Fortify: ${s.fortify ? '✅' : '❌'}`);
      if (s.stripped !== undefined) feat.push(`Stripped: ${s.stripped ? 'Yes' : 'No'}`);
      if (feat.length) parts.push('\n### Security Features\n' + feat.join(', '));
    }

    // Sections
    if (elf.sections && elf.sections.length) {
      const SN = this._sCaps.rowCap(40);
      parts.push(`\n### Sections (${elf.sections.length})`);
      parts.push('| Name | Type | Size | Entropy | Flags |');
      parts.push('|------|------|------|---------|-------|');
      for (const s of elf.sections.slice(0, SN)) {
        const entropy = s.entropy !== undefined ? s.entropy.toFixed(2) : '—';
        parts.push(`| ${tp(s.name)} | ${tp(s.typeStr)} | 0x${(s.size || 0).toString(16)} | ${entropy} | ${tp(s.flagsStr)} |`);
      }
      if (elf.sections.length > SN) parts.push(`… and ${elf.sections.length - SN} more`);
    }

    // Segments
    if (elf.segments && elf.segments.length) {
      parts.push(`\n### Segments (${elf.segments.length})`);
      parts.push('| Type | Flags | FileSize | MemSize |');
      parts.push('|------|-------|----------|---------|');
      for (const s of elf.segments) {
        parts.push(`| ${tp(s.typeStr)} | ${tp(s.flagsStr)} | 0x${(s.filesz || 0).toString(16)} | 0x${(s.memsz || 0).toString(16)} |`);
      }
    }

    // Dynamic entries
    if (elf.dynamic && elf.dynamic.length) {
      const interesting = elf.dynamic.filter(d => d.tagName !== 'DT_NULL');
      const DN = this._sCaps.rowCap(40);
      parts.push(`\n### Dynamic Entries (${interesting.length})`);
      parts.push('| Tag | Value |');
      parts.push('|-----|-------|');
      for (const d of interesting.slice(0, DN)) {
        parts.push(`| ${tp(d.tagName)} | ${tp(d.valStr || d.val)} |`);
      }
      if (interesting.length > DN) parts.push(`… and ${interesting.length - DN} more`);
    }

    // Dynamic libraries
    if (elf.neededLibs && elf.neededLibs.length) {
      parts.push(`\n### Dynamic Libraries (${elf.neededLibs.length})`);
      parts.push(elf.neededLibs.join(', '));
    }

    // Symbols
    const allSyms = [...(elf.dynsyms || []), ...(elf.symtab || [])];
    if (allSyms.length) {
      const suspicious = allSyms.filter(s => s._suspicious || s._risky);
      const named = allSyms.filter(s => s.name && s.name.length > 0);
      const SUN = this._sCaps.rowCap(30);
      const NON = this._sCaps.rowCap(40);
      parts.push(`\n### Symbols (${named.length} named)`);
      if (suspicious.length) {
        parts.push('\n**Suspicious symbols:**');
        for (const s of suspicious.slice(0, SUN)) parts.push(`- ⚠ \`${s.name}\` (${s.type || ''} ${s.bind || ''})`);
        if (suspicious.length > SUN) parts.push(`… and ${suspicious.length - SUN} more`);
      }
      const otherNamed = named.filter(s => !s._suspicious && !s._risky).slice(0, NON);
      if (otherNamed.length) {
        parts.push('\n**Imported/Exported:**');
        parts.push(otherNamed.map(s => `\`${s.name}\``).join(', ') + (named.length > NON + suspicious.length ? '…' : ''));
      }
    }

    // Notes
    if (elf.notes && elf.notes.length) {
      parts.push(`\n### Notes (${elf.notes.length})`);
      for (const n of elf.notes.slice(0, this._sCaps.rowCap(10))) {
        parts.push(`- **${tp(n.name)}** (type ${n.type}): ${tp(n.desc || '')}`);
      }
    }

    // Version-needed entries (.gnu.version_r) — maps soname → required
    // symbol versions. Useful for matching a stripped binary to a distro's
    // glibc / libstdc++ release.
    if (elf.verneed && elf.verneed.length) {
      parts.push(`\n### Version Needs (${elf.verneed.length})`);
      for (const v of elf.verneed.slice(0, this._sCaps.rowCap(20))) {
        const versions = (v.versions || []).map(vv => vv.name).join(', ');
        parts.push(`- **${tp(v.file || '?')}**${versions ? `: ${tp(versions)}` : ''}`);
      }
    }


    // Extracted string count — quick proxy for "how much plaintext is in
    // this binary" without dumping every string (that would blow the
    // budget).
    if (elf.stringCount != null) parts.push(`\n**Strings extracted:** ${elf.stringCount}`);

    // ── Go build info (shared helper) ──
    this._copyAnalysisGoBuildInfo(elf, parts, tp);
  },


  // ── Mach-O deep data ──────────────────────────────────────────────────
  _copyAnalysisMachO(mo, parts, tp) {
    parts.push('\n## Mach-O Binary Details');

    // Fat/Universal
    if (mo.fatHeader) {
      parts.push(`\n### Universal Binary (${mo.fatHeader.nfat_arch} architectures)`);
      if (mo.fatHeader.archs) {
        for (const a of mo.fatHeader.archs) parts.push(`- ${tp(a.cputypeStr)} (${tp(a.cpusubtypeStr)}), offset ${a.offset}, size ${a.size}`);
      }
    }

    // Header
    parts.push('\n### Mach-O Header');
    parts.push('| Field | Value |');
    parts.push('|-------|-------|');
    parts.push(`| CPU Type | ${tp(mo.cputypeStr)} (${tp(mo.cpusubtypeStr)}) |`);
    parts.push(`| File Type | ${tp(mo.filetypeStr)} — ${tp(mo.filetypeDesc)} |`);
    parts.push(`| Load Commands | ${mo.ncmds} |`);
    if (mo.flagsList && mo.flagsList.length) parts.push(`| Flags | ${tp(mo.flagsList.join(', '))} |`);
    if (mo.uuid) parts.push(`| UUID | ${mo.uuid} |`);
    if (mo.entryPoint != null) parts.push(`| Entry Point | 0x${mo.entryPoint.toString(16)} |`);
    if (mo.buildVersion) {
      parts.push(`| Platform | ${tp(mo.buildVersion.platform)} |`);
      parts.push(`| Min OS | ${tp(mo.buildVersion.minos)} |`);
      parts.push(`| SDK | ${tp(mo.buildVersion.sdk)} |`);
    }

    // Security features
    if (mo.security) {
      const s = mo.security;
      const feat = [];
      if (s.pie !== undefined) feat.push(`PIE: ${s.pie ? '✅' : '❌'}`);
      if (s.arc !== undefined) feat.push(`ARC: ${s.arc ? '✅' : '❌'}`);
      if (s.stackCanary !== undefined) feat.push(`Stack Canary: ${s.stackCanary ? '✅' : '❌'}`);
      if (s.nx !== undefined) feat.push(`NX: ${s.nx ? '✅' : '❌'}`);
      if (s.codeSign !== undefined) feat.push(`Code Signed: ${s.codeSign ? '✅' : '❌'}`);
      if (s.encrypted !== undefined) feat.push(`Encrypted: ${s.encrypted ? 'Yes' : 'No'}`);
      if (s.fortify !== undefined) feat.push(`Fortify: ${s.fortify ? '✅' : '❌'}`);
      if (feat.length) parts.push('\n### Security Features\n' + feat.join(', '));
    }

    // Segments & Sections
    if (mo.segments && mo.segments.length) {
      parts.push(`\n### Segments (${mo.segments.length})`);
      parts.push('| Segment | VMSize | FileSize | MaxProt | Sections |');
      parts.push('|---------|--------|----------|---------|----------|');
      for (const seg of mo.segments) {
        parts.push(`| ${tp(seg.segname)} | 0x${(seg.vmsize || 0).toString(16)} | 0x${(seg.filesize || 0).toString(16)} | ${tp(seg.maxprot)} | ${(seg.sections || []).length} |`);
      }
      // List interesting sections
      const allSects = (mo.sections || []);
      if (allSects.length) {
        const SN = this._sCaps.rowCap(30);
        parts.push(`\n**Sections (${allSects.length}):** ` +
          allSects.slice(0, SN).map(s => `${s.segname},${s.sectname}`).join(' · ') +
          (allSects.length > SN ? '…' : ''));
      }
    }


    // Dynamic libraries
    if (mo.dylibs && mo.dylibs.length) {
      const DN = this._sCaps.rowCap(30);
      parts.push(`\n### Dynamic Libraries (${mo.dylibs.length})`);
      for (const d of mo.dylibs.slice(0, DN)) {
        parts.push(`- ${tp(d.name)}${d.currentVersion ? ' v' + d.currentVersion : ''}`);
      }
      if (mo.dylibs.length > DN) parts.push(`… and ${mo.dylibs.length - DN} more`);
    }

    // Symbols
    if (mo.symbols && mo.symbols.length) {
      const suspicious = mo.symbols.filter(s => s._suspicious || s.category === 'suspicious');
      const named = mo.symbols.filter(s => s.name && s.name.length > 1);
      const SUN = this._sCaps.rowCap(30);
      const NON = this._sCaps.rowCap(40);
      parts.push(`\n### Symbols (${named.length} named)`);
      if (suspicious.length) {
        parts.push('\n**Suspicious symbols:**');
        for (const s of suspicious.slice(0, SUN)) parts.push(`- ⚠ \`${s.name}\``);
        if (suspicious.length > SUN) parts.push(`… and ${suspicious.length - SUN} more`);
      }
      const others = named.filter(s => !s._suspicious && s.category !== 'suspicious').slice(0, NON);
      if (others.length) {
        parts.push('\n**Imported/Exported:**');
        parts.push(others.map(s => `\`${s.name}\``).join(', ') + (named.length > NON + suspicious.length ? '…' : ''));
      }
    }


    // Code Signature
    if (mo.codeSignature) {
      const cs = mo.codeSignature;
      parts.push('\n### Code Signature');
      if (cs.identifier) parts.push(`- **Identifier:** ${cs.identifier}`);
      if (cs.teamID) parts.push(`- **Team ID:** ${cs.teamID}`);
      if (cs.cdhash) parts.push(`- **CDHash:** ${cs.cdhash}`);
      if (cs.flags != null) parts.push(`- **Flags:** 0x${cs.flags.toString(16)}`);
    }

    // Code Signing Certificates (from codeSignatureInfo)
    const csInfo = mo.codeSignatureInfo || mo.codeSignature;
    const csCerts = csInfo && csInfo.certificates;
    if (csCerts && csCerts.length) {
      parts.push(`\n### Code Signing Certificates (${csCerts.length})`);
      for (const c of csCerts) {
        const label = (c.subject && c.subject.CN) || (c.subject && c.subject.O) || 'Certificate';
        parts.push(`\n**${label}**`);
        parts.push('| Field | Value |');
        parts.push('|-------|-------|');
        if (c.subjectStr) parts.push(`| Subject | ${tp(c.subjectStr)} |`);
        if (c.issuerStr) parts.push(`| Issuer | ${tp(c.issuerStr)} |`);
        if (c.serialNumber) parts.push(`| Serial | ${tp(c.serialNumber)} |`);
        if (c.notBeforeStr) parts.push(`| Not Before | ${tp(c.notBeforeStr)} |`);
        if (c.notAfterStr) parts.push(`| Not After | ${tp(c.notAfterStr)} |`);
        let pk = c.publicKeyAlgorithm || '';
        if (c.publicKeySize) pk += ` ${c.publicKeySize}-bit`;
        if (pk) parts.push(`| Public Key | ${tp(pk)} |`);
        if (c.signatureAlgorithm) parts.push(`| Signature | ${tp(c.signatureAlgorithm)} |`);
        if (c.isSelfSigned) parts.push(`| Self-Signed | Yes |`);
        if (c.isCA) parts.push(`| CA | Yes |`);
      }
    }

    // Entitlements — the raw XML plist. Entitlements are one of the most
    // analysis-critical surfaces on a Mach-O (app sandbox, keychain
    // access, camera/microphone, com.apple.security.* flags); truncating
    // them hides the actual behaviour. Scale the cap aggressively so a
    // 256 K Summary shows a ≥ 4 000-char blob, and MAX emits the whole
    // file.
    if (mo.entitlements) {
      const EN = this._sCaps.charCap(1000);
      parts.push('\n### Entitlements');
      parts.push('```xml');
      parts.push((EN !== Infinity && mo.entitlements.length > EN) ? mo.entitlements.slice(0, EN) + '\n… (truncated)' : mo.entitlements);
      parts.push('```');
    }

    // RPATHs
    if (mo.rpaths && mo.rpaths.length) {
      parts.push('\n### RPATHs');
      for (const r of mo.rpaths) parts.push(`- ${r}`);
    }

    // Exports trie — the count is a useful gauge of how public a dylib is.
    if (mo.exportsTrie && mo.exportsTrie.length != null) {
      const n = mo.exportsTrie.length;
      if (n) parts.push(`\n**Exports trie:** ${n} symbols`);
    }

    // Weak dylibs — loadable but not required; sometimes used to hide
    // optional persistence paths.
    if (mo.weakDylibs && mo.weakDylibs.length) {
      const WN = this._sCaps.rowCap(20);
      parts.push(`\n### Weak Dylibs (${mo.weakDylibs.length})`);
      for (const d of mo.weakDylibs.slice(0, WN)) {
        parts.push(`- ${tp(typeof d === 'string' ? d : (d.name || ''))}`);
      }
      if (mo.weakDylibs.length > WN) parts.push(`… and ${mo.weakDylibs.length - WN} more`);
    }


    // Linker options baked in via LC_LINKER_OPTION.
    if (mo.linkerOpts && mo.linkerOpts.length) {
      parts.push('\n### Linker Options');
      parts.push(mo.linkerOpts.join(' '));
    }
  },

  // ── X.509 deep data ───────────────────────────────────────────────────
  _copyAnalysisX509(f, parts, tp) {
    const certs = f.x509Certs || [];
    if (!certs.length) return;

    parts.push(`\n## X.509 Certificates (${certs.length})`);
    if (f.summary) parts.push(`*${f.summary}*`);

    for (let i = 0; i < certs.length; i++) {
      const c = certs[i];
      parts.push(`\n### Certificate ${i + 1}${c.subject.CN ? ': ' + c.subject.CN : ''}`);
      parts.push('| Field | Value |');
      parts.push('|-------|-------|');
      parts.push(`| Subject | ${tp(c.subjectStr)} |`);
      parts.push(`| Issuer | ${tp(c.issuerStr)} |`);
      parts.push(`| Version | v${c.version} |`);
      parts.push(`| Serial | ${tp(c.serialNumber)} |`);
      parts.push(`| Not Before | ${tp(c.notBeforeStr)} |`);
      parts.push(`| Not After | ${tp(c.notAfterStr)} |`);
      let pk = c.publicKeyAlgorithm;
      if (c.publicKeySize) pk += ` ${c.publicKeySize}-bit`;
      if (c.publicKeyCurve) pk += ` (${c.publicKeyCurve})`;
      parts.push(`| Public Key | ${tp(pk)} |`);
      parts.push(`| Signature | ${tp(c.signatureAlgorithm)} |`);
      if (c.isSelfSigned) parts.push('| Self-Signed | Yes |');
      if (c.isCA) parts.push('| CA | Yes |');

      // Extensions summary. Extension values are truncated at 800 chars
      // to keep the report compact, EXCEPT for Subject Alternative Name
      // (oid 2.5.29.17) which frequently carries 100+ hostnames — that
      // is the entire point of looking at the cert in DFIR, so we let
      // it run up to 2000 chars before truncating.
      if (c.extensions && c.extensions.length) {
        parts.push('\n**Extensions:**');
        for (const ext of c.extensions) {
          const isSAN = (ext.oid === '2.5.29.17') || (ext.name === 'Subject Alternative Name');
          const limit = isSAN ? this._sCaps.charCap(2000) : this._sCaps.charCap(800);
          let val = ext.value || '';
          if (limit !== Infinity && val.length > limit) val = val.slice(0, limit) + '…';
          parts.push(`- **${ext.name || ext.oid}**${ext.critical ? ' (CRITICAL)' : ''}: ${val}`);
        }
      }

    }

    // Detections from x509 findings
    if (f.detections && f.detections.length) {
      parts.push('\n### Certificate Issues');
      for (const d of f.detections) {
        parts.push(`- **${d.name}** [${(d.severity || 'info').toUpperCase()}]: ${d.description}`);
      }
    }
  },

  // ── JAR deep data ─────────────────────────────────────────────────────
  _copyAnalysisJAR(f, parts, tp) {
    const j = f.jarInfo;
    if (!j) return;

    parts.push('\n## JAR Details');

    // Manifest
    if (j.manifest && j.manifest.attrs && Object.keys(j.manifest.attrs).length) {
      parts.push('\n### MANIFEST.MF');
      for (const [k, v] of Object.entries(j.manifest.attrs)) {
        parts.push(`- **${k}:** ${v}`);
      }
    }

    // Suspicious APIs
    if (j.suspiciousAPIs && j.suspiciousAPIs.length) {
      const SA = this._sCaps.rowCap(30);
      parts.push(`\n### Suspicious APIs (${j.suspiciousAPIs.length})`);
      const seen = new Set();
      for (const s of j.suspiciousAPIs.slice(0, SA)) {
        const key = s.api;
        if (seen.has(key)) continue;
        seen.add(key);
        parts.push(`- ⚠ **${tp(s.api)}** [${(s.severity || 'medium').toUpperCase()}]: ${tp(s.desc)}${s.mitre ? ' (' + s.mitre + ')' : ''}`);
      }
      if (j.suspiciousAPIs.length > SA) parts.push(`… and ${j.suspiciousAPIs.length - SA} more`);
    }

    // Obfuscation
    if (j.obfuscation && j.obfuscation.length) {
      parts.push('\n### Obfuscation Indicators');
      for (const o of j.obfuscation) parts.push(`- 🔒 ${o}`);
    }

    // Classes
    if (j.classes && j.classes.length) {
      const CN = this._sCaps.rowCap(30);
      parts.push(`\n### Classes (${j.classes.length})`);
      const display = j.classes.slice(0, CN).map(c => `\`${c}\``);
      parts.push(display.join(', ') + (j.classes.length > CN ? `… (+${j.classes.length - CN})` : ''));
    }

    // Dependencies
    if (j.dependencies && j.dependencies.length) {
      const DN = this._sCaps.rowCap(30);
      parts.push(`\n### Dependencies (${j.dependencies.length})`);
      parts.push(j.dependencies.slice(0, DN).join(', ') + (j.dependencies.length > DN ? '…' : ''));
    }


    // Config files
    if (j.configFiles && j.configFiles.length) {
      parts.push('\n### Config Files');
      for (const c of j.configFiles) parts.push(`- ${c}`);
    }

    // Main-Class — the executable jar entry point is a detection primitive.
    if (j.manifest && j.manifest.mainClass) {
      parts.push(`\n**Main-Class:** \`${tp(j.manifest.mainClass)}\``);
    }

    // Entry count / total compressed size — quick sanity check against
    // filesize.
    if (j.entryCount != null) parts.push(`**Entries:** ${j.entryCount}`);

    // Embedded JARs (jar-in-jar, e.g. Spring Boot / Shaded) — each one
    // is a separately-analysable payload.
    if (j.embeddedJars && j.embeddedJars.length) {
      const EJN = this._sCaps.rowCap(20);
      parts.push(`\n### Embedded JARs (${j.embeddedJars.length})`);
      for (const ej of j.embeddedJars.slice(0, EJN)) {
        const name = typeof ej === 'string' ? ej : (ej.name || ej.path || '?');
        parts.push(`- \`${tp(name)}\``);
      }
      if (j.embeddedJars.length > EJN) parts.push(`… and ${j.embeddedJars.length - EJN} more`);
    }

    // Signing certificates — same shape as PE authenticode certs; print
    // fingerprints so the analyst can compare against known-good CAs.
    if (j.signingCerts && j.signingCerts.length) {
      parts.push(`\n### Signing Certificates (${j.signingCerts.length})`);
      for (const c of j.signingCerts) {
        const label = (c.subject && c.subject.CN) || c.subjectStr || 'Certificate';
        parts.push(`- **${tp(label)}**${c.issuerStr ? ` issued by ${tp(c.issuerStr)}` : ''}${c.sha256 ? ` (SHA-256: \`${c.sha256}\`)` : ''}`);
      }
    }
  },

  // ── PDF deep data ─────────────────────────────────────────────────────
  // PDF metadata is mostly scalars (encrypted/pages/acroFormPresent/xfa)
  // already visible in the generic metadata table; the value-add here is
  // the JavaScript bodies, embedded-file inventory, and the XFA packet
  // list — none of which render well via the generic formatter.
  _copyAnalysisPDF(f, parts, tp) {
    const m = f.metadata || {};
    // Only emit if there's at least one interesting PDF-specific field.
    if (!(m.pdfJavaScripts || m.embeddedFiles || m.xfa || m.xfaPackets ||
      m.acroFormPresent || m.encrypted || m.pages)) return;
    parts.push('\n## PDF Details');

    // JavaScript — the single most analysis-worthy surface in a PDF.
    //   Each script body truncation scales so high-budget Summary exports
    //   emit more of the script rather than snapping at 800.
    const js = m.pdfJavaScripts || [];
    if (js.length) {
      const SRC = this._sCaps.charCap(800);
      parts.push(`\n### JavaScript Scripts (${js.length})`);
      for (const s of js) {
        parts.push(`\n**${tp(s.trigger || 'script')}** — ${s.size || 0} bytes${s.hash ? ` · hash \`${s.hash}\`` : ''}`);
        if (s.suspicious && s.suspicious.length) {
          parts.push(`⚠ Suspicious patterns: ${s.suspicious.join(', ')}`);
        }
        if (s.source) {
          const src = (SRC !== Infinity && s.source.length > SRC) ? s.source.slice(0, SRC) + '\n… (truncated)' : s.source;
          parts.push('```javascript\n' + src + '\n```');
        }
      }
    }

    // Embedded files — attachments the PDF will offer to save/launch.
    const ef = m.embeddedFiles || [];
    if (ef.length) {
      const EN = this._sCaps.rowCap(30);
      parts.push(`\n### Embedded Files (${ef.length})`);
      parts.push('| Name | MIME | Size | Hash |');
      parts.push('|------|------|------|------|');
      for (const e of ef.slice(0, EN)) {
        parts.push(`| ${tp(e.name || '?')} | ${tp(e.mime || '—')} | ${e.size || 0} | ${e.hash ? '`' + e.hash + '`' : '—'} |`);
      }
      if (ef.length > EN) parts.push(`… and ${ef.length - EN} more`);
    }


    // XFA — dynamic forms use their own XFA packets; list them so the
    // analyst sees whether it's the form-stuffing or full-xfa variant.
    if (m.xfa || m.xfaPackets) {
      parts.push('\n### XFA Forms');
      if (m.xfa) parts.push(`- **Has XFA:** ${m.xfa}`);
      if (m.xfaPackets) {
        const pkts = Array.isArray(m.xfaPackets) ? m.xfaPackets : [m.xfaPackets];
        parts.push(`- **Packets:** ${pkts.map(p => typeof p === 'string' ? p : (p.name || '?')).join(', ')}`);
      }
    }
  },

  // ── MSI deep data ─────────────────────────────────────────────────────
  // MSI's CustomAction rows, authenticode string, and embedded CAB list
  // all go into externalRefs (note-tagged) rather than structured arrays
  // on metadata, so this helper filters externalRefs by note-prefix to
  // reconstruct the table the MSI viewer shows.
  _copyAnalysisMSI(f, parts, tp) {
    const m = f.metadata || {};
    const looksMsi = m.customActionCount != null || m.authenticode || m.binaryStreamCount != null ||
      m.embeddedCabs || m.binaryStreamSniff;
    if (!looksMsi) return;
    parts.push('\n## MSI Details');

    if (m.customActionCount != null) parts.push(`- **CustomAction rows:** ${m.customActionCount}`);
    if (m.binaryStreamCount != null) parts.push(`- **Binary streams:** ${m.binaryStreamCount}`);
    if (m.authenticode) parts.push(`- **Authenticode:** ${m.authenticode}`);

    // CustomAction rows — the note on externalRefs entries is the
    // `CustomAction:` prefix used by msi-renderer.
    const ca = (f.externalRefs || []).filter(r =>
      r && r.note && /custom\s*action/i.test(r.note));
    if (ca.length) {
      const CN = this._sCaps.rowCap(30);
      parts.push(`\n### Custom Actions (${ca.length})`);
      for (const e of ca.slice(0, CN)) {
        parts.push(`- [${(e.severity || 'info').toUpperCase()}] ${tp(e.note || '')}: \`${tp(e.url || '')}\``);
      }
      if (ca.length > CN) parts.push(`… and ${ca.length - CN} more`);
    }


    if (m.embeddedCabs) {
      parts.push('\n### Embedded CABs');
      const cabs = Array.isArray(m.embeddedCabs) ? m.embeddedCabs : [m.embeddedCabs];
      for (const c of cabs) parts.push(`- ${tp(typeof c === 'string' ? c : (c.name || JSON.stringify(c)))}`);
    }
  },

  // ── OneNote deep data ─────────────────────────────────────────────────
  _copyAnalysisOneNote(f, parts, tp) {
    const m = f.metadata || {};
    if (m.embeddedObjectCount == null && !m.fileDataStoreGuids && !m.sniffedBlobTypes) return;
    parts.push('\n## OneNote Details');
    if (m.embeddedObjectCount != null) parts.push(`- **Embedded objects:** ${m.embeddedObjectCount}`);
    if (m.sniffedBlobTypes) {
      const t = typeof m.sniffedBlobTypes === 'string' ? m.sniffedBlobTypes
        : Array.isArray(m.sniffedBlobTypes) ? m.sniffedBlobTypes.join(', ') : JSON.stringify(m.sniffedBlobTypes);
      parts.push(`- **Sniffed blob types:** ${tp(t)}`);
    }
    if (m.fileDataStoreGuids) {
      const g = Array.isArray(m.fileDataStoreGuids) ? m.fileDataStoreGuids : [m.fileDataStoreGuids];
      const GN = this._sCaps.rowCap(10);
      parts.push(`- **FileDataStore GUIDs (${g.length}):** ${g.slice(0, GN).join(', ')}${g.length > GN ? '…' : ''}`);
    }
  },

  // ── RTF deep data — OLE objects live on externalRefs ─────────────────
  _copyAnalysisRTF(f, parts, tp) {
    const ole = (f.externalRefs || []).filter(r =>
      r && r.note && /ole\s*object|objdata|objclass/i.test(r.note));
    if (!ole.length) return;
    const N = this._sCaps.rowCap(20);
    parts.push(`\n## RTF OLE Objects (${ole.length})`);
    for (const e of ole.slice(0, N)) {
      parts.push(`- [${(e.severity || 'info').toUpperCase()}] ${tp(e.note || '')}: \`${tp(e.url || '')}\``);
    }
    if (ole.length > N) parts.push(`… and ${ole.length - N} more`);
  },

  // ── EML deep data — Cc / Reply-To / attachment list ───────────────────
  _copyAnalysisEML(f, parts, tp) {
    const m = f.metadata || {};
    // Only emit if we actually have EML-specific fields beyond what the
    // generic email-auth block covers. (The metadata block above already
    // prints cc/replyTo/attachments via the recursive formatter; we add a
    // clean tabular attachment view here.)
    const atts = Array.isArray(m.attachments) ? m.attachments : null;
    if (!atts || !atts.length) return;
    const N = this._sCaps.rowCap(30);
    parts.push(`\n## Email Attachments (${atts.length})`);
    parts.push('| Name | Size |');
    parts.push('|------|------|');
    for (const a of atts.slice(0, N)) {
      parts.push(`| ${tp(a.name || '(unnamed)')} | ${a.size != null ? a.size : '—'} |`);
    }
    if (atts.length > N) parts.push(`… and ${atts.length - N} more`);
  },

  // ── MSG deep data — recipient / subject headline + attachments ───────
  _copyAnalysisMSG(f, parts, tp) {
    const m = f.metadata || {};
    // MSG renderers set title/creator/created on metadata; attachments
    // flow through externalRefs with type IOC.ATTACHMENT (string guard).
    const atts = (f.externalRefs || []).filter(r =>
      r && (r.type === (typeof IOC !== 'undefined' && IOC.ATTACHMENT) ||
        (r.note && /attachment/i.test(r.note))));
    if (!m.title && !m.creator && !atts.length) return;
    parts.push('\n## Outlook Message Details');
    if (m.title) parts.push(`- **Subject:** ${tp(m.title)}`);
    if (m.creator) parts.push(`- **Sender:** ${tp(m.creator)}`);
    if (m.created) parts.push(`- **Created:** ${tp(m.created)}`);
    if (atts.length) {
      const N = this._sCaps.rowCap(30);
      parts.push(`\n### Attachments (${atts.length})`);
      for (const a of atts.slice(0, N)) {
        parts.push(`- \`${tp(a.url || '')}\`${a.note ? ` — ${tp(a.note)}` : ''}`);
      }
      if (atts.length > N) parts.push(`… and ${atts.length - N} more`);
    }
  },

  // ── HTML deep data — forms, title ─────────────────────────────────────
  _copyAnalysisHTML(f, parts, tp) {
    const m = f.metadata || {};
    // Form entries live in externalRefs (PATTERN type) with notes like
    // "Form with password field" — scan for those.
    const forms = (f.externalRefs || []).filter(r =>
      r && r.url && /form/i.test(r.url + ' ' + (r.note || '')));
    if (!m.title && !forms.length) return;
    parts.push('\n## HTML Details');
    if (m.title) parts.push(`- **Title:** ${tp(m.title)}`);
    if (forms.length) {
      const N = this._sCaps.rowCap(20);
      parts.push(`\n### Forms / credential harvesting indicators (${forms.length})`);
      for (const fm of forms.slice(0, N)) {
        parts.push(`- [${(fm.severity || 'info').toUpperCase()}] ${tp(fm.url)}${fm.note ? ` — ${tp(fm.note)}` : ''}`);
      }
      if (forms.length > N) parts.push(`… and ${forms.length - N} more`);
    }
  },

  // ── HTA deep data — scripts / external refs ───────────────────────────
  _copyAnalysisHTA(f, parts, tp) {
    // HTA renderer doesn't set a distinctive top-level marker; only emit
    // when the file extension is .hta AND there are externalRefs flagged
    // as script-language indicators.
    const fileName = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase();
    if (!fileName.endsWith('.hta')) return;
    const scripts = (f.externalRefs || []).filter(r =>
      r && (r.note && /hta|script|vbscript|jscript/i.test(r.note)));
    if (!scripts.length) return;
    const N = this._sCaps.rowCap(20);
    parts.push(`\n## HTA Script Indicators (${scripts.length})`);
    for (const s of scripts.slice(0, N)) {
      parts.push(`- [${(s.severity || 'info').toUpperCase()}] ${tp(s.note || '')}: \`${tp(s.url || '')}\``);
    }
    if (scripts.length > N) parts.push(`… and ${scripts.length - N} more`);
  },


  // ── SVG deep data — script/handler/foreignObject counts ──────────────
  _copyAnalysisSVG(f, parts, tp) {
    const fileName = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase();
    if (!fileName.endsWith('.svg')) return;
    // SVG renderer emits notes like "script element", "event handler",
    // "foreignObject", "external reference" — bucket them.
    const refs = f.externalRefs || [];
    const buckets = { script: 0, handler: 0, external: 0, foreignObject: 0 };
    const samples = { script: [], handler: [], external: [], foreignObject: [] };
    for (const r of refs) {
      const note = String(r.note || '') + ' ' + String(r.url || '');
      let key = null;
      if (/\bscript\b/i.test(note)) key = 'script';
      else if (/handler|on[a-z]+\s*=/i.test(note)) key = 'handler';
      else if (/foreign\s*object/i.test(note)) key = 'foreignObject';
      else if (/xlink|external|href=/i.test(note)) key = 'external';
      if (key) {
        buckets[key]++;
        if (samples[key].length < 3) samples[key].push(r);
      }
    }
    const totals = Object.values(buckets).reduce((a, b) => a + b, 0);
    if (!totals) return;
    parts.push('\n## SVG Active-Content Inventory');
    parts.push(`- **Scripts:** ${buckets.script}`);
    parts.push(`- **Event handlers:** ${buckets.handler}`);
    parts.push(`- **foreignObject elements:** ${buckets.foreignObject}`);
    parts.push(`- **External references:** ${buckets.external}`);
    for (const [k, arr] of Object.entries(samples)) {
      if (arr.length) {
        parts.push(`\n**${k} samples:**`);
        for (const r of arr) parts.push(`- \`${tp(r.url || '')}\`${r.note ? ` — ${tp(r.note)}` : ''}`);
      }
    }
  },

  // ── EVTX deep data — event-id distribution from PATTERN entries ──────
  _copyAnalysisEVTX(f, parts, tp) {
    const m = f.metadata || {};
    if (m.eventCount == null && !m.channels && !m.providers) return;
    parts.push('\n## Windows Event Log Details');
    if (m.eventCount != null) parts.push(`- **Events:** ${m.eventCount}`);
    if (m.firstEvent) parts.push(`- **First event:** ${tp(m.firstEvent)}`);
    if (m.lastEvent) parts.push(`- **Last event:** ${tp(m.lastEvent)}`);
    if (m.channels) parts.push(`- **Channels:** ${tp(m.channels)}`);
    if (m.providers) parts.push(`- **Providers:** ${tp(m.providers)}`);

    // Derive the notable-event-ids table from PATTERN entries that match
    // the evtx-renderer's "Event NNNN: description" template.
    const evtRe = /^Event\s+(\d+)\s*:\s*(.+?)(?:\s*\((\d+)\s*events?\))?$/i;
    const hits = [];
    for (const r of (f.externalRefs || [])) {
      if (!r || !r.url) continue;
      const m2 = evtRe.exec(r.url);
      if (!m2) continue;
      hits.push({ id: m2[1], desc: m2[2], count: m2[3] ? parseInt(m2[3], 10) : 1, severity: r.severity || 'info' });
    }
    if (hits.length) {
      const N = this._sCaps.rowCap(40);
      parts.push(`\n### Notable Event IDs (${hits.length})`);
      parts.push('| ID | Count | Severity | Description |');
      parts.push('|----|-------|----------|-------------|');
      for (const h of hits.slice(0, N)) {
        parts.push(`| ${h.id} | ${h.count} | ${(h.severity || 'info').toUpperCase()} | ${tp(h.desc)} |`);
      }
      if (hits.length > N) parts.push(`… and ${hits.length - N} more`);
    }
  },


  // ── SQLite deep data — schema / version / browser-profile stats ──────
  _copyAnalysisSQLite(f, parts, tp) {
    const m = f.metadata || {};
    if (!m.sqliteVersion && m.tables == null && !m.browserType) return;
    parts.push('\n## SQLite Database Details');
    if (m.sqliteVersion) parts.push(`- **SQLite version:** ${tp(m.sqliteVersion)}`);
    if (m.pageSize != null) parts.push(`- **Page size:** ${m.pageSize}`);
    if (m.pageCount != null) parts.push(`- **Page count:** ${m.pageCount}`);
    if (m.browserType) parts.push(`- **Browser:** ${tp(m.browserType)}`);
    if (m.urlCount != null) parts.push(`- **URL count:** ${m.urlCount}`);

    // m.tables may be a number, a string ("42 tables"), or an array.
    if (Array.isArray(m.tables)) {
      const TN = this._sCaps.rowCap(30);
      parts.push(`\n### Tables (${m.tables.length})`);
      for (const t of m.tables.slice(0, TN)) {
        if (typeof t === 'string') parts.push(`- \`${tp(t)}\``);
        else parts.push(`- \`${tp(t.name || '?')}\`${t.rowCount != null ? ` (${t.rowCount} rows)` : ''}${t.columns ? ` — ${tp((t.columns || []).join(', '))}` : ''}`);
      }
      if (m.tables.length > TN) parts.push(`… and ${m.tables.length - TN} more`);
    } else if (m.tables != null) {
      parts.push(`- **Tables:** ${tp(m.tables)}`);
    }
  },


  // ── ZIP deep data — compression ratio (zip-bomb indicator), dangerous files ──
  _copyAnalysisZIP(f, parts, tp) {
    const m = f.metadata || {};
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (!['zip', 'jar', 'war', 'ear', 'apk'].includes(ext)) return;
    const hasInteresting = m.compressedSize != null || m.decompressedSize != null ||
      m.compressionRatio != null || m.zipEntries;
    const dangerFiles = (f.externalRefs || []).filter(r =>
      r && r.note && /danger|executable|macro|dropper/i.test(r.note));
    // .app bundle paths come through as IOC.FILE_PATH ending with "/" (see
    // ZipRenderer._analyzeArchiveEntries) — used for the "ZIP-wrapped macOS
    // app" shape that's the common delivery layout for unsigned .app malware.
    const apps = (f.externalRefs || [])
      .filter(r => r && r.type === IOC.FILE_PATH && /\.app\/$/i.test(r.url || ''));
    if (!hasInteresting && !dangerFiles.length && !apps.length) return;
    parts.push('\n## ZIP Archive Details');
    if (m.compressedSize != null) parts.push(`- **Compressed size:** ${m.compressedSize}`);
    if (m.decompressedSize != null) parts.push(`- **Decompressed size:** ${m.decompressedSize}`);
    if (m.compressionRatio != null) {
      const r = typeof m.compressionRatio === 'number' ? m.compressionRatio.toFixed(1) : m.compressionRatio;
      parts.push(`- **Compression ratio:** ${r}${typeof m.compressionRatio === 'number' && m.compressionRatio > 100 ? '×  ⚠ (zip-bomb indicator)' : ''}`);
    }
    if (dangerFiles.length) {
      const DN = this._sCaps.rowCap(30);
      parts.push(`\n### Suspicious Entries (${dangerFiles.length})`);
      for (const d of dangerFiles.slice(0, DN)) {
        parts.push(`- [${(d.severity || 'info').toUpperCase()}] \`${tp(d.url || '')}\`${d.note ? ` — ${tp(d.note)}` : ''}`);
      }
      if (dangerFiles.length > DN) parts.push(`… and ${dangerFiles.length - DN} more`);
    }
    if (apps.length) {
      const N = this._sCaps.rowCap(30);
      parts.push(`\n### .app Bundle Paths (${apps.length})`);
      for (const a of apps.slice(0, N)) {
        parts.push(`- \`${tp(a.url)}\``);
      }
      if (apps.length > N) parts.push(`… and ${apps.length - N} more`);
    }
  },



  // ── ISO deep data — volume info ───────────────────────────────────────
  _copyAnalysisISO(f, parts, tp) {
    const m = f.metadata || {};
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (!['iso', 'img'].includes(ext)) return;
    if (!m.title && !m.creator && !m.subject) return;
    parts.push('\n## ISO / Disk Image Details');
    if (m.title) parts.push(`- **Volume ID:** ${tp(m.title)}`);
    if (m.creator) parts.push(`- **Publisher:** ${tp(m.creator)}`);
    if (m.subject) parts.push(`- **Subject:** ${tp(m.subject)}`);
  },

  // ── DMG deep data — UDIF version, partition mix, .app bundle paths ────
  //   Mirrors _copyAnalysisISO but with the UDIF-specific fields the DMG
  //   renderer stashes on `metadata` (title=first-partition name, creator=
  //   `UDIF v<n>`, subject=`<n> partition(s) · <size>`) and the IOC.FILE_PATH
  //   entries it emits for every detected .app bundle.
  _copyAnalysisDMG(f, parts, tp) {
    const m = f.metadata || {};
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (ext !== 'dmg') return;
    if (!m.title && !m.creator && !m.subject && !(f.externalRefs || []).length) return;

    parts.push('\n## Apple Disk Image (DMG) Details');
    if (m.creator) parts.push(`- **Container:** ${tp(m.creator)}`);
    if (m.subject) parts.push(`- **Layout:** ${tp(m.subject)}`);
    if (m.title) parts.push(`- **First Partition:** ${tp(m.title)}`);

    // .app bundle paths come through as IOC.FILE_PATH on externalRefs.
    const apps = (f.externalRefs || [])
      .filter(r => r && r.type === IOC.FILE_PATH && /\.app(\/|$)/i.test(r.url || ''));
    if (apps.length) {
      const N = this._sCaps.rowCap(30);
      parts.push(`\n### .app Bundle Paths (${apps.length})`);
      for (const a of apps.slice(0, N)) {
        parts.push(`- \`${tp(a.url)}\``);
      }
      if (apps.length > N) parts.push(`… and ${apps.length - N} more`);
    }
  },

  // ── PKG deep data — xar header, signing state, install-script bodies ──
  //   The PKG renderer stashes the package identifier on metadata.title,
  //   the version as metadata.subject ("version X"), and the signing state
  //   on metadata.creator ("Signed (…)" / "Unsigned"). Install scripts
  //   show up as IOC.FILE_PATH entries (path always begins with a
  //   "Scripts/" segment or is a well-known script name).
  _copyAnalysisPKG(f, parts, tp) {
    const m = f.metadata || {};
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (!['pkg', 'mpkg'].includes(ext)) return;
    if (!m.title && !m.creator && !m.subject && !(f.externalRefs || []).length) return;

    parts.push('\n## macOS Installer Package (PKG) Details');
    if (m.title) parts.push(`- **Package Identifier:** ${tp(m.title)}`);
    if (m.subject) parts.push(`- **Version:** ${tp(m.subject)}`);
    if (m.creator) parts.push(`- **Signature:** ${tp(m.creator)}`);

    // Install scripts — any FILE_PATH entry inside a Scripts/ dir or with
    // a known pre/post-install / legacy-flight name is a script body.
    const SCRIPT_NAMES = /(^|\/)(preinstall|postinstall|preupgrade|postupgrade|preflight|postflight|InstallationCheck|VolumeCheck)$/;
    const scripts = (f.externalRefs || []).filter(r =>
      r && r.type === IOC.FILE_PATH && (/(^|\/)Scripts\//.test(r.url || '') || SCRIPT_NAMES.test(r.url || '')));
    if (scripts.length) {
      const N = this._sCaps.rowCap(20);
      parts.push(`\n### Install Scripts (${scripts.length})`);
      for (const s of scripts.slice(0, N)) {
        parts.push(`- \`${tp(s.url)}\``);
      }
      if (scripts.length > N) parts.push(`… and ${scripts.length - N} more`);
    }

    // LaunchDaemon / LaunchAgent persistence drops.
    const launch = (f.externalRefs || []).filter(r =>
      r && r.type === IOC.FILE_PATH && /\/(LaunchDaemons|LaunchAgents)\/[^/]+\.plist$/i.test(r.url || ''));
    if (launch.length) {
      const LN = this._sCaps.rowCap(10);
      parts.push(`\n### LaunchDaemon / LaunchAgent Plists (${launch.length})`);
      for (const lp of launch.slice(0, LN)) {
        parts.push(`- \`${tp(lp.url)}\``);
      }
      if (launch.length > LN) parts.push(`… and ${launch.length - LN} more`);
    }
  },

  // ── Image deep data — EXIF / dims / format ───────────────────────────
  _copyAnalysisImage(f, parts, tp) {
    const m = f.metadata || {};
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (!['png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'webp', 'ico', 'heic'].includes(ext)) return;
    if (!m.exif && !m.format && m.size == null) return;
    parts.push('\n## Image Details');
    if (m.format) parts.push(`- **Format:** ${tp(m.format)}`);
    if (m.size != null) parts.push(`- **Raw byte size:** ${m.size}`);
    if (m.exif) {
      const e = typeof m.exif === 'string' ? m.exif : JSON.stringify(m.exif);
      const XN = this._sCaps.charCap(200);
      parts.push(`- **EXIF preview:** ${tp(XN !== Infinity && e.length > XN ? e.slice(0, XN) + '…' : e)}`);
    }
  },


  // ── PGP deep data — non-standard detections[] / formatSpecific[] ─────
  _copyAnalysisPGP(f, parts, tp) {
    const fs = Array.isArray(f.formatSpecific) ? f.formatSpecific : null;
    const dets = Array.isArray(f.detections) ? f.detections : null;
    if (!fs && !dets) return;
    if (fs && fs.length) {
      parts.push('\n## PGP Key Info');
      parts.push('| Field | Value |');
      parts.push('|-------|-------|');
      for (const kv of fs) {
        parts.push(`| ${tp(kv.label || '')} | ${tp(kv.value || '')} |`);
      }
    }
    if (dets && dets.length) {
      parts.push('\n### PGP Detections');
      for (const d of dets) {
        parts.push(`- **${tp(d.name || '')}** [${(d.severity || 'info').toUpperCase()}]${d.description ? ': ' + tp(d.description) : ''}`);
      }
    }
  },

  // ── Plist deep data — LaunchAgent persistence, URL schemes, UTIs ─────
  _copyAnalysisPlist(f, parts, tp) {
    const m = f.metadata || {};
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (ext !== 'plist') return;
    const interesting = m.label || m.bundleIdentifier || m.bundleName ||
      m.executable || m.program || m.programArguments || m.runAtLoad != null ||
      m.keepAlive != null || (Array.isArray(m.watchPaths) && m.watchPaths.length);
    const sigs = Array.isArray(f.signatureMatches) ? f.signatureMatches : [];
    if (!interesting && !sigs.length) return;
    parts.push('\n## Property List Details');
    if (m.label) parts.push(`- **Label:** ${tp(m.label)}`);
    if (m.bundleIdentifier) parts.push(`- **Bundle ID:** ${tp(m.bundleIdentifier)}`);
    if (m.bundleName) parts.push(`- **Bundle Name:** ${tp(m.bundleName)}`);
    if (m.executable) parts.push(`- **Executable:** \`${tp(m.executable)}\``);
    if (m.program) parts.push(`- **Program:** \`${tp(m.program)}\``);
    if (m.programArguments) {
      const a = Array.isArray(m.programArguments) ? m.programArguments.join(' ') : m.programArguments;
      parts.push(`- **Program Arguments:** \`${tp(a)}\``);
    }
    if (m.runAtLoad != null) parts.push(`- **RunAtLoad:** ${m.runAtLoad}`);
    if (m.keepAlive != null) parts.push(`- **KeepAlive:** ${JSON.stringify(m.keepAlive)}`);
    if (m.watchPaths) {
      const wp = Array.isArray(m.watchPaths) ? m.watchPaths : [m.watchPaths];
      parts.push(`- **WatchPaths:** ${wp.join(', ')}`);
    }
    if (sigs.length) {
      const SN = this._sCaps.rowCap(20);
      parts.push('\n### Persistence / Behaviour Signatures');
      for (const s of sigs.slice(0, SN)) {
        const name = s.name || s.rule || s.id || '?';
        parts.push(`- **${tp(name)}**${s.severity ? ` [${s.severity.toUpperCase()}]` : ''}${s.description ? ': ' + tp(s.description) : ''}`);
      }
      if (sigs.length > SN) parts.push(`… and ${sigs.length - SN} more`);
    }
  },

  // ── Osascript deep data — decompiled source + signatures ─────────────

  _copyAnalysisOsascript(f, parts, tp) {
    const m = f.metadata || {};
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (!['scpt', 'applescript', 'jxa'].includes(ext)) return;
    const sigs = Array.isArray(f.signatureMatches) ? f.signatureMatches : [];
    if (!m.format && m.hasEmbeddedSource == null && m.lineCount == null && !sigs.length) return;
    parts.push('\n## Osascript Details');
    if (m.format) parts.push(`- **Format:** ${tp(m.format)}`);
    if (m.hasEmbeddedSource != null) parts.push(`- **Embedded source:** ${m.hasEmbeddedSource}`);
    if (m.lineCount != null) parts.push(`- **Lines:** ${m.lineCount}`);
    if (m.size != null) parts.push(`- **Size:** ${m.size}`);
    if (sigs.length) {
      parts.push(`\n### Behaviour Signatures (${sigs.length})`);
      for (const s of sigs.slice(0, 20)) {
        const name = s.name || s.rule || s.id || '?';
        parts.push(`- **${tp(name)}**${s.severity ? ` [${s.severity.toUpperCase()}]` : ''}${s.description ? ': ' + tp(s.description) : ''}`);
      }
    }
  },

  // ── OOXML relationship-scanner results (PPTX / XLSX) ─────────────────
  // These flow through externalRefs from OoxmlRelScanner, tagged with
  // notes like "OOXML Relationship (External)" — filter by that so the
  // scanner output is grouped separately from document-body IOCs.
  _copyAnalysisOOXMLRels(f, parts, tp) {
    const ext = ((this._fileMeta && this._fileMeta.name) || '').toLowerCase().split('.').pop();
    if (!['pptx', 'xlsx', 'pptm', 'xlsm'].includes(ext)) return;
    const rels = (f.externalRefs || []).filter(r =>
      r && r.note && /ooxml|relationship|external\s*target/i.test(r.note));
    if (!rels.length) return;
    const N = this._sCaps.rowCap(40);
    parts.push(`\n## OOXML Relationships (${rels.length})`);
    parts.push('| Severity | Note | Target |');
    parts.push('|----------|------|--------|');
    for (const r of rels.slice(0, N)) {
      parts.push(`| ${(r.severity || 'info').toUpperCase()} | ${tp(r.note || '')} | \`${tp(r.url || '')}\` |`);
    }
    if (rels.length > N) parts.push(`… and ${rels.length - N} more`);
  },
});
