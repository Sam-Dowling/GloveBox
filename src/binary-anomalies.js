// binary-anomalies.js — Anomaly ribbon feeder + "should this card auto-open?"
// predicate for PE / ELF / Mach-O renderers.
//
// Motivation
// ----------
// Tier-C reference cards (Sections, Segments, Load Commands, Data Directories,
// Rich Header, Resources, Strings) are collapsed by default so the viewer
// is not a wall of 3-deep tables on a benign sample. When something
// **is** wrong we want those cards to open automatically so the analyst
// doesn't miss the evidence. The same set of checks powers the Tier-A
// anomaly ribbon (a short list of coloured chips right under the verdict
// band linking to the card that triggered each chip).
//
// Contract
// --------
//   BinaryAnomalies.detect({
//     parsed,     // renderer's parsed object
//     findings,   // { externalRefs, metadata, riskScore, ... }
//     format,     // 'PE' | 'ELF' | 'Mach-O'
//   }) → {
//     ribbon: [{ label, severity, anchor, mitre? }],
//     shouldAutoOpen: Map<string, bool>,   // keyed by card id
//     isAnomalous: (cardId) => bool,
//   }
//
// Card ids are short kebab-case strings agreed with the renderer:
//   PE:      headers, sections, imports, exports, resources, rich, tls,
//            dotnet, certificates, data-dirs, overlay, strings
//   ELF:     header, segments, sections, dynamic, symbols, notes, overlay, strings
//   Mach-O:  header, segments, load-commands, dylibs, symbols, codesig,
//            entitlements, overlay, strings
//
// Pure presentation logic — reads the parsed object only. Never mutates.

(function () {
  'use strict';

  // ── Ribbon chip helpers ──────────────────────────────────────────────────
  function _chip(label, severity, anchor, mitre) {
    return { label, severity: severity || 'medium', anchor: anchor || '', mitre: mitre || null };
  }

  function _openAll(map, ids) {
    if (!Array.isArray(ids)) return;
    for (const id of ids) map.set(id, true);
  }

  // ── PE anomalies ─────────────────────────────────────────────────────────
  function _detectPe(pe, findings) {
    const ribbon = [];
    const open = new Map();
    if (!pe) return { ribbon, open };

    // Entry-point anomalies — directly mapped from _analyzeEntryPoint().
    const epi = pe.entryPointInfo || {};
    if (epi.orphaned) {
      ribbon.push(_chip('orphan entry-point', 'critical', 'pe-headers', 'T1027'));
      _openAll(open, ['headers', 'sections']);
    } else if (epi.inWX) {
      ribbon.push(_chip('EP in W+X section', 'high', 'pe-sections', 'T1027.002'));
      _openAll(open, ['sections']);
    } else if (epi.notInText) {
      ribbon.push(_chip('EP in ' + (epi.section && epi.section.name || 'non-.text'), 'medium', 'pe-sections'));
      _openAll(open, ['sections']);
    }

    // Section anomalies — packer / entropy / RWX / tiny raw.
    if (Array.isArray(pe.sections)) {
      const rwx = pe.sections.find(s => s && s.isWrite && s.isExecute);
      if (rwx) {
        ribbon.push(_chip('RWX section ' + (rwx.name || ''), 'high', 'pe-sections', 'T1027.002'));
        _openAll(open, ['sections']);
      }
      const packed = pe.sections.find(s => s && s.packerMatch);
      if (packed) {
        ribbon.push(_chip('packed (' + packed.packerMatch + ')', 'high', 'pe-sections', 'T1027.002'));
        _openAll(open, ['sections']);
      }
      const hiEntropy = pe.sections.find(s => s && typeof s.entropy === 'number' && s.entropy >= 7.2 && s.sizeOfRawData > 1024);
      if (hiEntropy && !packed) {
        ribbon.push(_chip('high-entropy ' + (hiEntropy.name || 'section'), 'medium', 'pe-sections', 'T1027.002'));
        _openAll(open, ['sections']);
      }
    }

    // TLS callbacks (pre-entry-point execution hook).
    if (pe.tls && Array.isArray(pe.tls.callbacks) && pe.tls.callbacks.length) {
      ribbon.push(_chip(pe.tls.callbacks.length + ' TLS callback' + (pe.tls.callbacks.length === 1 ? '' : 's'), 'medium', 'pe-tls', 'T1546.009'));
      _openAll(open, ['tls']);
    }

    // Authenticode missing / overlay-past-signature.
    const certs = pe.certificates || [];
    if (certs.length === 0) {
      ribbon.push(_chip('unsigned', 'medium', 'pe-certificates', 'T1553.002'));
    }
    const md = findings.metadata || {};
    if (Number(md['Overlay Bytes'] || 0) > 0) {
      const sev = md['Overlay Past Signature'] ? 'critical' : (md['Overlay Entropy'] && Number(md['Overlay Entropy']) >= 7.2 ? 'high' : 'medium');
      ribbon.push(_chip('overlay present', sev, 'pe-overlay', md['Overlay Past Signature'] ? 'T1553.002' : 'T1027.002'));
      _openAll(open, ['overlay']);
    }

    // .NET managed — informational only, doesn't auto-open (card is small).
    if (pe.dotnet) {
      ribbon.push(_chip('.NET managed', 'low', 'pe-dotnet', 'T1059.005'));
      _openAll(open, ['dotnet']);
    }

    // Embedded resource payloads surfaced by the PE resource-section walk.
    if (Number(md['Embedded Resource Payloads'] || 0) > 0) {
      ribbon.push(_chip(md['Embedded Resource Payloads'] + ' embedded resource payload' + (Number(md['Embedded Resource Payloads']) === 1 ? '' : 's'), 'high', 'pe-resources', 'T1027.009'));
      _openAll(open, ['resources']);
    }

    // Forwarded / ordinal-only exports.
    if (Number(md['Forwarded Exports'] || 0) > 0) {
      ribbon.push(_chip(md['Forwarded Exports'] + ' forwarded export' + (Number(md['Forwarded Exports']) === 1 ? '' : 's'), 'medium', 'pe-exports', 'T1574.002'));
      _openAll(open, ['exports']);
    }
    if (md['DLL Side-Load Host']) {
      ribbon.push(_chip('side-load target: ' + md['DLL Side-Load Host'], 'high', 'pe-exports', 'T1574.002'));
      _openAll(open, ['exports']);
    }
    if (Number(md['Ordinal-Only Exports'] || 0) > 0) {
      ribbon.push(_chip(md['Ordinal-Only Exports'] + ' ordinal-only export' + (Number(md['Ordinal-Only Exports']) === 1 ? '' : 's'), 'medium', 'pe-exports', 'T1027'));
      _openAll(open, ['exports']);
    }

    // Timestamp faked?
    if (md['Compile Timestamp Faked']) {
      ribbon.push(_chip('timestamp: ' + md['Compile Timestamp Faked'], 'low', 'pe-headers'));
      _openAll(open, ['headers']);
    }

    // Imports — always open if there's a capability hit cited to imports.
    const capHits = (findings.externalRefs || []).filter(r => r && (r.type || '').toLowerCase() === 'pattern');
    if (capHits.length) {
      _openAll(open, ['imports']);
    }

    return { ribbon, open };
  }

  // ── ELF anomalies ────────────────────────────────────────────────────────
  function _detectElf(elf, findings) {
    const ribbon = [];
    const open = new Map();
    if (!elf) return { ribbon, open };

    if (Array.isArray(elf.sections)) {
      const rwx = elf.sections.find(s => s && (s.flags & 0x1) && (s.flags & 0x4));
      if (rwx) {
        ribbon.push(_chip('RWX section ' + (rwx.name || ''), 'high', 'elf-sections', 'T1027.002'));
        _openAll(open, ['sections']);
      }
      if (elf.sections.find(s => s && s.name && (s.name === 'UPX0' || s.name === 'UPX1' || s.name === 'UPX!'))) {
        ribbon.push(_chip('UPX-packed', 'high', 'elf-sections', 'T1027.002'));
        _openAll(open, ['sections']);
      }
    }
    if (Array.isArray(elf.programHeaders)) {
      const gnuStack = elf.programHeaders.find(ph => ph && (ph.typeStr === 'PT_GNU_STACK' || ph.type === 0x6474e551));
      if (gnuStack && typeof gnuStack.flags === 'number' && (gnuStack.flags & 0x1)) {
        ribbon.push(_chip('executable stack', 'high', 'elf-segments', 'T1027'));
        _openAll(open, ['segments']);
      }
    }
    if (Array.isArray(elf.dynamic)) {
      if (elf.dynamic.find(d => d && d.tag === 'DT_RPATH')) {
        ribbon.push(_chip('DT_RPATH set (deprecated)', 'medium', 'elf-dynamic', 'T1574.006'));
        _openAll(open, ['dynamic']);
      }
      if (elf.dynamic.find(d => d && d.tag === 'DT_RUNPATH')) {
        ribbon.push(_chip('DT_RUNPATH set', 'low', 'elf-dynamic', 'T1574.006'));
        _openAll(open, ['dynamic']);
      }
    }
    if (elf.isStripped) {
      ribbon.push(_chip('stripped', 'low', 'elf-symbols'));
      // Don't auto-open — stripped is normal for release builds.
    }
    const md = findings.metadata || {};
    if (Number(md['Overlay Bytes'] || 0) > 0) {
      const sev = Number(md['Overlay Entropy'] || 0) >= 7.2 ? 'high' : 'medium';
      ribbon.push(_chip('overlay present', sev, 'elf-overlay', 'T1027.009'));
      _openAll(open, ['overlay']);
    }
    if (md['ELF Side-Load Host']) {
      ribbon.push(_chip('side-load target: ' + md['ELF Side-Load Host'], 'high', 'elf-dynamic', 'T1574.006'));
      _openAll(open, ['dynamic']);
    }

    const capHits = (findings.externalRefs || []).filter(r => r && (r.type || '').toLowerCase() === 'pattern');
    if (capHits.length) {
      _openAll(open, ['symbols']);
    }

    return { ribbon, open };
  }

  // ── Mach-O anomalies ─────────────────────────────────────────────────────
  function _detectMacho(mo, findings) {
    const ribbon = [];
    const open = new Map();
    if (!mo) return { ribbon, open };

    if (Array.isArray(mo.sections)) {
      // Mach-O VM_PROT flags: READ=0x1, WRITE=0x2, EXECUTE=0x4.
      // Flag only sections where *all three* bits are set on initProt.
      const rwx = mo.sections.find(s => s && (s.initProt !== undefined) && ((s.initProt & 0x7) === 0x7));
      if (rwx) {
        ribbon.push(_chip('RWX section ' + (rwx.sectname || ''), 'high', 'macho-segments', 'T1027.002'));
        _openAll(open, ['segments']);
      }
      if (mo.sections.find(s => s && s.sectname === '__XHDR')) {
        ribbon.push(_chip('UPX-packed (__XHDR)', 'high', 'macho-segments', 'T1027.002'));
        _openAll(open, ['segments']);
      }
    }
    if (Array.isArray(mo.encryptionInfo) && mo.encryptionInfo.find(e => e && e.cryptid)) {
      ribbon.push(_chip('encrypted segment (cryptid=1)', 'high', 'macho-load-commands', 'T1027'));
      _openAll(open, ['load-commands']);
    }
    const csi = mo.codeSignatureInfo || {};
    if (!csi.teamId && !csi.isAdHoc && !(Array.isArray(csi.certificates) && csi.certificates.length)) {
      ribbon.push(_chip('unsigned', 'high', 'macho-codesig', 'T1553.002'));
    } else if (csi.isAdHoc) {
      ribbon.push(_chip('ad-hoc signed', 'medium', 'macho-codesig', 'T1553.002'));
    }
    if (!csi.hardenedRuntime && (csi.teamId || csi.isAdHoc)) {
      ribbon.push(_chip('no hardened runtime', 'low', 'macho-codesig'));
    }
    if (mo.dangerousEntitlements && mo.dangerousEntitlements.length) {
      ribbon.push(_chip(mo.dangerousEntitlements.length + ' dangerous entitlement' + (mo.dangerousEntitlements.length === 1 ? '' : 's'), 'high', 'macho-entitlements', 'T1134'));
      _openAll(open, ['entitlements']);
    }
    if (Array.isArray(mo.rpaths) && mo.rpaths.length) {
      const dangerous = mo.rpaths.some(r => typeof r === 'string' && (r.indexOf('/tmp') === 0 || r.indexOf('/var/') === 0));
      if (dangerous) {
        ribbon.push(_chip('world-writable @rpath', 'high', 'macho-load-commands', 'T1574.006'));
        _openAll(open, ['load-commands']);
      }
    }
    const md = findings.metadata || {};
    if (Number(md['Overlay Bytes'] || 0) > 0) {
      const sev = Number(md['Overlay Entropy'] || 0) >= 7.2 ? 'high' : 'medium';
      ribbon.push(_chip('overlay present', sev, 'macho-overlay', 'T1027.009'));
      _openAll(open, ['overlay']);
    }
    if (md['Mach-O Side-Load Host'] || md['Dylib Side-Load Host']) {
      const host = md['Mach-O Side-Load Host'] || md['Dylib Side-Load Host'];
      ribbon.push(_chip('side-load target: ' + host, 'high', 'macho-dylibs', 'T1574.002'));
      _openAll(open, ['dylibs']);
    }

    const capHits = (findings.externalRefs || []).filter(r => r && (r.type || '').toLowerCase() === 'pattern');
    if (capHits.length) {
      _openAll(open, ['symbols']);
    }

    return { ribbon, open };
  }

  // ── Public API ───────────────────────────────────────────────────────────
  function detect(opts) {
    const parsed = (opts && opts.parsed) || {};
    const findings = (opts && opts.findings) || {};
    const format = (opts && opts.format) || '';

    let r = { ribbon: [], open: new Map() };
    if (format === 'PE') r = _detectPe(parsed, findings);
    else if (format === 'ELF') r = _detectElf(parsed, findings);
    else if (format === 'Mach-O') r = _detectMacho(parsed, findings);

    // Sort ribbon: critical > high > medium > low > info, then by label.
    const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    r.ribbon.sort((a, b) => {
      const sa = SEV_ORDER[a.severity] || 9, sb = SEV_ORDER[b.severity] || 9;
      if (sa !== sb) return sa - sb;
      return (a.label || '').localeCompare(b.label || '');
    });

    return {
      ribbon: r.ribbon,
      shouldAutoOpen: r.open,
      isAnomalous: (cardId) => !!r.open.get(cardId),
    };
  }

  window.BinaryAnomalies = {
    detect,
  };
})();
