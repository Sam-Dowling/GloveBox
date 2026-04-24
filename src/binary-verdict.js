// binary-verdict.js — Triage-first verdict banner for PE / ELF / Mach-O.
//
// The Binary Pivot card (binary-summary.js) is a structured facts table —
// great for pivoting, less great for the "is this bad?" question an
// analyst asks in the first two seconds. This module generates a single
// human sentence that answers that question by stitching together the
// handful of fields that actually move the needle:
//
//   "Unsigned PE32+ DLL · UPX-packed · orphan EP · 40 KB overlay past
//    signature · 8 capabilities (2 critical, 3 high)"
//
// And a coarse 0–100 confidence score driven by the same inputs. The
// score is used by the sidebar's Binary Metadata section to colour the
// triage pill and by Copy Analysis to print a single "verdict line".
//
// Pure presentation — never mutates `findings` or the parsed object.
//
// Contract
// --------
//   BinaryVerdict.summarize({
//     parsed,       // renderer's parsed object (pe / elf / mo)
//     findings,     // { externalRefs, riskScore, metadata, ... }
//     format,       // 'PE' / 'ELF' / 'Mach-O'
//     fileSize,     // bytes.length
//   }) → { headline:string, risk:0..100, tier:'clean|low|medium|high|critical',
//          badges:[{label,kind}] }
//
// Zero dependencies beyond MITRE (optional, for badge tooltips).

(function () {
  'use strict';

  function _countCapabilitiesBySeverity(findings) {
    const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    if (!findings || !Array.isArray(findings.externalRefs)) return out;
    for (const r of findings.externalRefs) {
      if (!r) continue;
      // Capability rows are emitted as IOC.PATTERN with a MITRE-tagged name
      // ("Process Injection (CreateRemoteThread) [T1055.002]"). Only count
      // pattern rows — URL / HASH / DOMAIN rows are pivot data, not verdict.
      const type = (r.type || '').toLowerCase();
      if (type !== 'pattern') continue;
      const sev = (r.severity || 'medium').toLowerCase();
      if (out[sev] !== undefined) out[sev]++;
      out.total++;
    }
    return out;
  }

  function _tierFromRisk(risk) {
    if (risk >= 80) return 'critical';
    if (risk >= 55) return 'high';
    if (risk >= 30) return 'medium';
    if (risk >= 10) return 'low';
    return 'clean';
  }

  // ── Per-format signal extraction ─────────────────────────────────────────
  function _peSignals(pe, fileSize, findings) {
    const s = {
      kind: 'Executable',
      archLabel: '',
      signed: false,
      signerLabel: '',
      authenticodeVerified: null, // Loupe cannot verify chains offline
      packer: null,
      orphanEp: false,
      nonTextEp: false,
      wxEp: false,
      tlsCallbacks: 0,
      overlayBytes: 0,
      overlayPastCert: false,
      isDotNet: false,
      isGo: false,
      isRust: false,
      isAutoHotkey: false,
      isXll: false,
      installerType: null,
    };
    if (!pe) return s;
    try {
      if (pe.coff) {
        if (pe.coff.isDLL) s.kind = 'DLL';
        else if (pe.coff.isSystem) s.kind = 'Driver';
      }
      if (pe.optional && pe.optional.magicStr) {
        s.archLabel = pe.optional.magicStr + (pe.coff && pe.coff.machineStr ? ' · ' + pe.coff.machineStr : '');
      }
      if (Array.isArray(pe.certificates) && pe.certificates.length > 0) {
        s.signed = true;
        const c = pe.certificates[0];
        s.signerLabel = (c.subject && c.subject.CN) || c.subjectStr || 'signed';
      }
      if (Array.isArray(pe.sections)) {
        const p = pe.sections.find(ss => ss && ss.packerMatch);
        if (p) s.packer = p.packerMatch;
      }
      const epi = pe.entryPointInfo || {};
      s.orphanEp = !!epi.orphaned;
      s.nonTextEp = !!epi.notInText && !epi.orphaned;
      s.wxEp = !!epi.inWX;
      if (pe.tls && Array.isArray(pe.tls.callbacks)) s.tlsCallbacks = pe.tls.callbacks.length;
      if (pe.dotnet) s.isDotNet = true;
      if (pe.isGoBinary) s.isGo = true;
      if (pe.isAutoHotkey) s.isAutoHotkey = true;
      if (pe.isXll) s.isXll = true;
      if (pe.installerType) s.installerType = pe.installerType;
      // Rust heuristic — panic paths surfaced by BinaryStrings into findings.metadata.
      const fmd = (findings && findings.metadata) || {};
      const rustCount = Number(fmd['Rust Panic Paths'] || 0);
      if (rustCount > 0) s.isRust = true;
    } catch (_) { /* best-effort */ }
    return s;
  }

  function _elfSignals(elf, fileSize) {
    const s = {
      kind: 'Executable',
      archLabel: '',
      signed: false, // ELF has no structural signer
      signerLabel: '— (ELF has no structural signer)',
      packer: null,
      stripped: false,
      staticallyLinked: false,
      isGo: false,
      isRust: false,
      hasRunpath: false,
      hasRpath: false,
      execStack: false,
    };
    if (!elf) return s;
    try {
      if (elf.fileType) {
        if (elf.fileType.indexOf('DYN') >= 0) s.kind = elf.soname ? 'Shared Object' : 'PIE Executable';
        else if (elf.fileType.indexOf('REL') >= 0) s.kind = 'Relocatable Object';
        else if (elf.fileType.indexOf('CORE') >= 0) s.kind = 'Core Dump';
      }
      if (elf.classStr || elf.machineStr) {
        s.archLabel = [elf.classStr, elf.machineStr].filter(Boolean).join(' · ');
      }
      if (elf.isStripped) s.stripped = true;
      if (elf.isStaticLinked || elf.staticallyLinked) s.staticallyLinked = true;
      if (elf.isGoBinary) s.isGo = true;
      if (Array.isArray(elf.dynamic)) {
        for (const d of elf.dynamic) {
          if (!d) continue;
          if (d.tag === 'DT_RPATH') s.hasRpath = true;
          if (d.tag === 'DT_RUNPATH') s.hasRunpath = true;
        }
      }
      if (Array.isArray(elf.programHeaders)) {
        const stk = elf.programHeaders.find(ph => ph && (ph.typeStr === 'PT_GNU_STACK' || ph.type === 0x6474e551));
        if (stk && typeof stk.flags === 'number' && (stk.flags & 0x1)) s.execStack = true;
      }
      // Packer hint — UPX / muxed sections.
      if (Array.isArray(elf.sections)) {
        for (const sec of elf.sections) {
          if (!sec || !sec.name) continue;
          const n = sec.name;
          if (n === 'UPX0' || n === 'UPX1' || n === 'UPX!') { s.packer = 'UPX'; break; }
        }
      }
    } catch (_) { /* best-effort */ }
    return s;
  }

  function _machoSignals(mo, fileSize) {
    const s = {
      kind: 'Executable',
      archLabel: '',
      signed: false,
      signerLabel: 'unsigned',
      isAdHoc: false,
      hasHardenedRuntime: false,
      hasEntitlements: false,
      dangerousEntitlements: false,
      isEncrypted: false,
      packer: null,
      isFat: false,
      isGo: false,
      isRust: false,
      hasRpath: false,
    };
    if (!mo) return s;
    try {
      if (mo.filetypeStr) {
        if (mo.filetype === 6) s.kind = 'Dylib';
        else if (mo.filetype === 8) s.kind = 'Bundle';
        else if (mo.filetype === 1) s.kind = 'Object';
        else if (mo.filetype === 2) s.kind = 'Executable';
        else s.kind = mo.filetypeStr;
      }
      if (mo.cpuTypeStr || mo.archLabel) {
        s.archLabel = (mo.archLabel || mo.cpuTypeStr) + (mo.bits ? ' · ' + mo.bits + '-bit' : '');
      }
      if (mo.codeSignatureInfo) {
        const csi = mo.codeSignatureInfo;
        if (csi.teamId) { s.signed = true; s.signerLabel = 'Team ID: ' + csi.teamId; }
        else if (csi.isAdHoc) { s.signed = true; s.isAdHoc = true; s.signerLabel = 'ad-hoc signed'; }
        else if (Array.isArray(csi.certificates) && csi.certificates.length) {
          s.signed = true;
          const c = csi.certificates[0];
          s.signerLabel = (c && (c.CN || c.subjectStr)) || 'signed';
        }
        if (csi.hardenedRuntime) s.hasHardenedRuntime = true;
      }
      if (Array.isArray(mo.entitlementKeys) && mo.entitlementKeys.length) s.hasEntitlements = true;
      if (mo.dangerousEntitlements && mo.dangerousEntitlements.length) s.dangerousEntitlements = true;
      if (mo.isFat) s.isFat = true;
      if (Array.isArray(mo.encryptionInfo)) {
        for (const e of mo.encryptionInfo) if (e && e.cryptid) { s.isEncrypted = true; break; }
      }
      if (mo.isGoBinary) s.isGo = true;
      if (Array.isArray(mo.rpaths) && mo.rpaths.length) s.hasRpath = true;
      if (Array.isArray(mo.sections)) {
        const xhdr = mo.sections.find(sec => sec && sec.sectname === '__XHDR');
        if (xhdr) s.packer = 'UPX';
      }
    } catch (_) { /* best-effort */ }
    return s;
  }

  const _fmtBytes = fmtBytes;

  // ── Verdict string + risk 0-100 ──────────────────────────────────────────
  function summarize(opts) {
    const parsed = (opts && opts.parsed) || {};
    const findings = (opts && opts.findings) || {};
    const format = (opts && opts.format) || '';
    const fileSize = (opts && opts.fileSize) || 0;

    let risk = Math.min(100, Math.max(0, Math.round((findings.riskScore || 0) * 6)));
    const badges = [];
    const parts = [];

    // ── Per-format signal block ───────────────────────────────────────────
    let sig = null;
    if (format === 'PE') sig = _peSignals(parsed, fileSize, findings);
    else if (format === 'ELF') sig = _elfSignals(parsed, fileSize);
    else if (format === 'Mach-O') sig = _machoSignals(parsed, fileSize);
    sig = sig || {};

    // Lead fragment: "Unsigned PE32+ DLL" / "Signed Mach-O Executable".
    const signPrefix = sig.signed ? 'Signed' : (format === 'ELF' ? '' : 'Unsigned');
    const leadBits = [signPrefix, sig.archLabel || format, sig.kind].filter(Boolean);
    parts.push(leadBits.join(' ').trim());

    if (!sig.signed && format !== 'ELF') {
      badges.push({ label: 'unsigned', kind: 'warn' });
      risk += 6;
    } else if (sig.signed) {
      badges.push({ label: 'signed', kind: 'ok' });
    }

    if (sig.packer) {
      parts.push(sig.packer + '-packed');
      badges.push({ label: sig.packer + ' packed', kind: 'warn' });
      risk += 10;
    }

    // PE-specific fragments
    if (format === 'PE') {
      if (sig.orphanEp) { parts.push('orphan entry-point'); badges.push({ label: 'orphan EP', kind: 'bad' }); risk += 12; }
      else if (sig.wxEp) { parts.push('EP in W+X section'); badges.push({ label: 'W+X EP', kind: 'bad' }); risk += 10; }
      else if (sig.nonTextEp) { parts.push('EP in non-.text section'); badges.push({ label: 'non-.text EP', kind: 'warn' }); risk += 5; }
      if (sig.tlsCallbacks) { parts.push(sig.tlsCallbacks + ' TLS callback' + (sig.tlsCallbacks === 1 ? '' : 's')); badges.push({ label: 'TLS ×' + sig.tlsCallbacks, kind: 'warn' }); risk += 4; }
      if (sig.isDotNet) parts.push('.NET managed');
      if (sig.isAutoHotkey) { parts.push('AutoHotkey'); badges.push({ label: 'AHK', kind: 'warn' }); }
      if (sig.isXll) { parts.push('XLL add-in'); badges.push({ label: 'XLL', kind: 'warn' }); }
      if (sig.installerType) { parts.push(sig.installerType + ' installer'); }
      if (sig.isGo) parts.push('Go');
      if (sig.isRust) parts.push('Rust');
    }

    // ELF-specific fragments
    if (format === 'ELF') {
      if (sig.stripped) badges.push({ label: 'stripped', kind: 'warn' });
      if (sig.staticallyLinked) { parts.push('static-linked'); badges.push({ label: 'static', kind: 'info' }); }
      if (sig.hasRunpath) { parts.push('DT_RUNPATH set'); badges.push({ label: 'RUNPATH', kind: 'warn' }); risk += 3; }
      if (sig.hasRpath) { parts.push('DT_RPATH set (deprecated)'); badges.push({ label: 'RPATH', kind: 'bad' }); risk += 5; }
      if (sig.execStack) { parts.push('exec-stack'); badges.push({ label: 'exec-stack', kind: 'bad' }); risk += 6; }
      if (sig.isGo) parts.push('Go');
    }

    // Mach-O-specific fragments
    if (format === 'Mach-O') {
      if (sig.isFat) badges.push({ label: 'universal', kind: 'info' });
      if (sig.isAdHoc) badges.push({ label: 'ad-hoc', kind: 'warn' });
      if (sig.hasHardenedRuntime) badges.push({ label: 'hardened', kind: 'ok' });
      if (sig.dangerousEntitlements) { parts.push('dangerous entitlements'); badges.push({ label: 'entitlements', kind: 'bad' }); risk += 10; }
      else if (sig.hasEntitlements) parts.push('entitlements');
      if (sig.isEncrypted) { parts.push('encrypted (cryptid=1)'); badges.push({ label: 'encrypted', kind: 'bad' }); risk += 10; }
      if (sig.hasRpath) badges.push({ label: '@rpath', kind: 'info' });
      if (sig.isGo) parts.push('Go');
    }

    // Overlay — read any "overlay present" hint off findings.metadata so we
    // don't re-walk the buffer here.
    const md = findings.metadata || {};
    const overlaySize = Number(md['Overlay Bytes'] || md['Overlay Size'] || 0);
    if (overlaySize > 0) {
      parts.push(_fmtBytes(overlaySize) + ' overlay');
      badges.push({ label: 'overlay', kind: 'warn' });
    }

    // Capability counts — the single strongest risk signal.
    const caps = _countCapabilitiesBySeverity(findings);
    if (caps.total > 0) {
      const breakdown = [];
      if (caps.critical) breakdown.push(caps.critical + ' critical');
      if (caps.high) breakdown.push(caps.high + ' high');
      if (caps.medium) breakdown.push(caps.medium + ' medium');
      const tail = breakdown.length ? ' (' + breakdown.join(', ') + ')' : '';
      parts.push(caps.total + ' capabilit' + (caps.total === 1 ? 'y' : 'ies') + tail);
      risk += Math.min(40, caps.critical * 10 + caps.high * 6 + caps.medium * 3);
    } else {
      parts.push('no capability hits');
    }

    risk = Math.min(100, Math.max(0, risk));
    const tier = _tierFromRisk(risk);

    return {
      headline: parts.filter(Boolean).join(' · '),
      risk,
      tier,
      badges,
      signer: sig.signerLabel || '',
      capabilityCounts: caps,
    };
  }

  // ── Public global ──────────────────────────────────────────────────────
  window.BinaryVerdict = {
    summarize,
  };
})();
