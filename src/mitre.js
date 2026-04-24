// mitre.js — MITRE ATT&CK technique registry for binary analysis.
//
// Loupe's PE / ELF / Mach-O renderers each emit MITRE technique IDs in a few
// places (capability tags, overlay flags, entry-point anomalies, side-loading,
// etc.). Up until now those IDs were bare strings scattered across the
// codebase with no canonical name, tactic grouping, or URL.
//
// This module centralises the taxonomy so every surface — the main-pane
// capability strip, the sidebar "MITRE ATT&CK Coverage" section, and the
// "Copy Analysis" clipboard output — can speak the same language and roll up
// by tactic.
//
// Coverage is deliberately narrow: only the techniques actually referenced
// somewhere in the binary-analysis pipeline are listed. Adding a new
// technique here is a two-step process:
//   1. Add the entry below with {name, tactic, parent?}.
//   2. Reference the technique ID from a capability, anomaly, or pattern
//      emission site. Callers should use MITRE.lookup(id) rather than
//      hand-writing technique strings.
//
// Zero dependencies. CSP-safe — no network; URLs are passive `href` targets.

(function () {
  'use strict';

  // ── Technique table ────────────────────────────────────────────────────
  // `tactic` is a comma-joined list when a technique legitimately spans
  // multiple tactics (e.g. T1055 is both defense-evasion and
  // privilege-escalation). The first listed tactic is treated as the
  // canonical grouping tactic for UI rollup purposes.
  const TECHNIQUES = {
    // ── Execution ─────────────────────────────────────────────────────
    'T1059':     { name: 'Command and Scripting Interpreter',     tactic: 'execution' },
    'T1059.001': { name: 'PowerShell',                            tactic: 'execution', parent: 'T1059' },
    'T1059.003': { name: 'Windows Command Shell',                 tactic: 'execution', parent: 'T1059' },
    'T1059.004': { name: 'Unix Shell',                            tactic: 'execution', parent: 'T1059' },
    'T1059.005': { name: 'Visual Basic / .NET Managed Assembly',  tactic: 'execution', parent: 'T1059' },
    'T1059.006': { name: 'Python',                                tactic: 'execution', parent: 'T1059' },
    'T1059.007': { name: 'JavaScript',                            tactic: 'execution', parent: 'T1059' },
    'T1106':     { name: 'Native API',                            tactic: 'execution' },
    'T1129':     { name: 'Shared Modules',                        tactic: 'execution' },
    'T1204.002': { name: 'Malicious File',                        tactic: 'execution', parent: 'T1204' },
    'T1559':     { name: 'Inter-Process Communication',           tactic: 'execution' },
    'T1559.001': { name: 'Component Object Model',                tactic: 'execution', parent: 'T1559' },
    'T1569.002': { name: 'Service Execution',                     tactic: 'execution', parent: 'T1569' },
    'T1047':     { name: 'Windows Management Instrumentation',    tactic: 'execution' },

    // ── Persistence ───────────────────────────────────────────────────
    'T1053':     { name: 'Scheduled Task/Job',                    tactic: 'persistence' },
    'T1053.003': { name: 'Cron',                                  tactic: 'persistence', parent: 'T1053' },
    'T1053.005': { name: 'Scheduled Task',                        tactic: 'persistence', parent: 'T1053' },
    'T1543':     { name: 'Create or Modify System Process',       tactic: 'persistence' },
    'T1543.001': { name: 'Launch Agent',                          tactic: 'persistence', parent: 'T1543' },
    'T1543.002': { name: 'systemd Service',                       tactic: 'persistence', parent: 'T1543' },
    'T1543.003': { name: 'Windows Service',                       tactic: 'persistence', parent: 'T1543' },
    'T1543.004': { name: 'Launch Daemon',                         tactic: 'persistence', parent: 'T1543' },
    'T1546':     { name: 'Event Triggered Execution',             tactic: 'persistence' },
    'T1546.009': { name: 'AppInit DLLs / TLS Callbacks',          tactic: 'persistence', parent: 'T1546' },
    'T1547':     { name: 'Boot or Logon Autostart Execution',     tactic: 'persistence' },
    'T1547.001': { name: 'Registry Run Keys / Startup Folder',    tactic: 'persistence', parent: 'T1547' },
    'T1547.006': { name: 'Kernel Modules and Extensions',         tactic: 'persistence', parent: 'T1547' },
    'T1546.003': { name: 'WMI Event Subscription',                tactic: 'persistence', parent: 'T1546' },
    'T1098':     { name: 'Account Manipulation',                  tactic: 'persistence' },
    'T1098.007': { name: 'Additional Local or Domain Groups',     tactic: 'persistence', parent: 'T1098' },
    'T1136':     { name: 'Create Account',                        tactic: 'persistence' },
    'T1136.001': { name: 'Local Account',                         tactic: 'persistence', parent: 'T1136' },

    // ── Privilege Escalation ──────────────────────────────────────────
    'T1134':     { name: 'Access Token Manipulation',             tactic: 'privilege-escalation' },
    'T1134.001': { name: 'Token Impersonation/Theft',             tactic: 'privilege-escalation', parent: 'T1134' },
    'T1548':     { name: 'Abuse Elevation Control Mechanism',     tactic: 'privilege-escalation' },
    'T1548.002': { name: 'Bypass UAC',                            tactic: 'privilege-escalation', parent: 'T1548' },
    'T1078':     { name: 'Valid Accounts',                        tactic: 'privilege-escalation,defense-evasion' },
    'T1078.002': { name: 'Domain Accounts',                       tactic: 'privilege-escalation', parent: 'T1078' },
    'T1078.003': { name: 'Local Accounts',                        tactic: 'privilege-escalation', parent: 'T1078' },

    // ── Defense Evasion ───────────────────────────────────────────────
    'T1027':     { name: 'Obfuscated Files or Information',       tactic: 'defense-evasion' },
    'T1027.002': { name: 'Software Packing',                      tactic: 'defense-evasion', parent: 'T1027' },
    'T1027.009': { name: 'Embedded Payloads',                     tactic: 'defense-evasion', parent: 'T1027' },
    'T1036':     { name: 'Masquerading',                          tactic: 'defense-evasion' },
    'T1036.001': { name: 'Invalid Code Signature',                tactic: 'defense-evasion', parent: 'T1036' },
    'T1055':     { name: 'Process Injection',                     tactic: 'defense-evasion' },
    'T1055.001': { name: 'DLL Injection',                         tactic: 'defense-evasion', parent: 'T1055' },
    'T1055.002': { name: 'Portable Executable Injection',         tactic: 'defense-evasion', parent: 'T1055' },
    'T1055.003': { name: 'Thread Execution Hijacking',            tactic: 'defense-evasion', parent: 'T1055' },
    'T1055.004': { name: 'Asynchronous Procedure Call',           tactic: 'defense-evasion', parent: 'T1055' },
    'T1055.008': { name: 'ptrace System Calls',                   tactic: 'defense-evasion', parent: 'T1055' },
    'T1055.012': { name: 'Process Hollowing',                     tactic: 'defense-evasion', parent: 'T1055' },
    'T1070':     { name: 'Indicator Removal',                     tactic: 'defense-evasion' },
    'T1070.001': { name: 'Clear Windows Event Logs',              tactic: 'defense-evasion', parent: 'T1070' },
    'T1070.004': { name: 'File Deletion',                         tactic: 'defense-evasion', parent: 'T1070' },
    'T1070.006': { name: 'Timestomp',                             tactic: 'defense-evasion', parent: 'T1070' },
    'T1112':     { name: 'Modify Registry',                       tactic: 'defense-evasion' },
    'T1140':     { name: 'Deobfuscate/Decode Files',              tactic: 'defense-evasion' },
    'T1218':     { name: 'System Binary Proxy Execution',         tactic: 'defense-evasion' },
    'T1480':     { name: 'Execution Guardrails',                  tactic: 'defense-evasion' },
    'T1497':     { name: 'Virtualization/Sandbox Evasion',        tactic: 'defense-evasion' },
    'T1497.001': { name: 'System Checks',                         tactic: 'defense-evasion', parent: 'T1497' },
    'T1497.003': { name: 'Time-Based Evasion',                    tactic: 'defense-evasion', parent: 'T1497' },
    'T1553':     { name: 'Subvert Trust Controls',                tactic: 'defense-evasion' },
    'T1553.002': { name: 'Code Signing',                          tactic: 'defense-evasion', parent: 'T1553' },
    'T1562':     { name: 'Impair Defenses',                       tactic: 'defense-evasion' },
    'T1562.001': { name: 'Disable or Modify Tools',               tactic: 'defense-evasion', parent: 'T1562' },
    'T1562.002': { name: 'Disable Windows Event Logging',         tactic: 'defense-evasion', parent: 'T1562' },
    'T1562.004': { name: 'Disable or Modify System Firewall',     tactic: 'defense-evasion', parent: 'T1562' },
    'T1562.006': { name: 'Indicator Blocking (ETW Patching)',     tactic: 'defense-evasion', parent: 'T1562' },
    'T1564':     { name: 'Hide Artifacts',                        tactic: 'defense-evasion' },
    'T1564.004': { name: 'NTFS File Attributes / ADS',            tactic: 'defense-evasion', parent: 'T1564' },
    'T1550':     { name: 'Use Alternate Authentication Material', tactic: 'defense-evasion' },
    'T1574':     { name: 'Hijack Execution Flow',                 tactic: 'defense-evasion,privilege-escalation' },
    'T1574.001': { name: 'DLL Search Order Hijacking',            tactic: 'defense-evasion', parent: 'T1574' },
    'T1574.002': { name: 'DLL Side-Loading',                      tactic: 'defense-evasion', parent: 'T1574' },
    'T1574.006': { name: 'Dynamic Linker Hijacking (LD_PRELOAD / DYLD_INSERT)', tactic: 'defense-evasion', parent: 'T1574' },
    'T1620':     { name: 'Reflective Code Loading',               tactic: 'defense-evasion' },
    'T1622':     { name: 'Debugger Evasion',                      tactic: 'defense-evasion' },

    // ── Credential Access ─────────────────────────────────────────────
    'T1110':     { name: 'Brute Force',                           tactic: 'credential-access' },
    'T1003':     { name: 'OS Credential Dumping',                 tactic: 'credential-access' },
    'T1003.001': { name: 'LSASS Memory',                          tactic: 'credential-access', parent: 'T1003' },
    'T1003.002': { name: 'Security Account Manager (SAM)',        tactic: 'credential-access', parent: 'T1003' },
    'T1003.008': { name: '/etc/passwd and /etc/shadow',           tactic: 'credential-access', parent: 'T1003' },
    'T1056':     { name: 'Input Capture',                         tactic: 'credential-access,collection' },
    'T1056.001': { name: 'Keylogging',                            tactic: 'credential-access,collection', parent: 'T1056' },
    'T1555':     { name: 'Credentials from Password Stores',      tactic: 'credential-access' },
    'T1555.001': { name: 'Keychain',                              tactic: 'credential-access', parent: 'T1555' },
    'T1555.003': { name: 'Credentials from Web Browsers',         tactic: 'credential-access', parent: 'T1555' },
    'T1555.004': { name: 'Windows Credential Manager',            tactic: 'credential-access', parent: 'T1555' },
    'T1558':     { name: 'Steal or Forge Kerberos Tickets',       tactic: 'credential-access' },
    'T1558.003': { name: 'Kerberoasting',                         tactic: 'credential-access', parent: 'T1558' },
    'T1558.004': { name: 'AS-REP Roasting',                       tactic: 'credential-access', parent: 'T1558' },

    // ── Lateral Movement ──────────────────────────────────────────────
    'T1021':     { name: 'Remote Services',                       tactic: 'lateral-movement' },
    'T1021.001': { name: 'Remote Desktop Protocol',               tactic: 'lateral-movement', parent: 'T1021' },
    'T1021.002': { name: 'SMB/Windows Admin Shares',              tactic: 'lateral-movement', parent: 'T1021' },

    // ── Defense Evasion (additional) ──────────────────────────────────
    'T1014':     { name: 'Rootkit',                               tactic: 'defense-evasion' },

    // ── Discovery ─────────────────────────────────────────────────────
    'T1057':     { name: 'Process Discovery',                     tactic: 'discovery' },
    'T1082':     { name: 'System Information Discovery',          tactic: 'discovery' },
    'T1083':     { name: 'File and Directory Discovery',          tactic: 'discovery' },
    'T1518':     { name: 'Software Discovery',                    tactic: 'discovery' },
    'T1518.001': { name: 'Security Software Discovery',           tactic: 'discovery', parent: 'T1518' },
    'T1087':     { name: 'Account Discovery',                     tactic: 'discovery' },
    'T1087.001': { name: 'Local Account Discovery',               tactic: 'discovery', parent: 'T1087' },
    'T1135':     { name: 'Network Share Discovery',               tactic: 'discovery' },

    // ── Collection ────────────────────────────────────────────────────
    'T1113':     { name: 'Screen Capture',                        tactic: 'collection' },
    'T1115':     { name: 'Clipboard Data',                        tactic: 'collection' },
    'T1123':     { name: 'Audio Capture',                         tactic: 'collection' },
    'T1125':     { name: 'Video Capture',                         tactic: 'collection' },

    // ── Command and Control ───────────────────────────────────────────
    'T1071':     { name: 'Application Layer Protocol',            tactic: 'command-and-control' },
    'T1071.001': { name: 'Web Protocols',                         tactic: 'command-and-control', parent: 'T1071' },
    'T1071.004': { name: 'DNS',                                   tactic: 'command-and-control', parent: 'T1071' },
    'T1090':     { name: 'Proxy',                                 tactic: 'command-and-control' },
    'T1095':     { name: 'Non-Application Layer Protocol',        tactic: 'command-and-control' },
    'T1105':     { name: 'Ingress Tool Transfer',                 tactic: 'command-and-control' },
    'T1571':     { name: 'Non-Standard Port',                     tactic: 'command-and-control' },
    'T1573':     { name: 'Encrypted Channel',                     tactic: 'command-and-control' },

    // ── Impact ────────────────────────────────────────────────────────
    'T1485':     { name: 'Data Destruction',                      tactic: 'impact' },
    'T1486':     { name: 'Data Encrypted for Impact',             tactic: 'impact' },
    'T1490':     { name: 'Inhibit System Recovery',               tactic: 'impact' },
    'T1496':     { name: 'Resource Hijacking',                    tactic: 'impact' }
  };

  // ── Tactic metadata (display-order preserved; left-to-right = ATT&CK kill-chain order) ──
  const TACTICS = {
    'execution':             { label: 'Execution',             icon: '▶',  order: 1 },
    'persistence':           { label: 'Persistence',           icon: '🔒', order: 2 },
    'privilege-escalation':  { label: 'Privilege Escalation',  icon: '⬆',  order: 3 },
    'defense-evasion':       { label: 'Defense Evasion',       icon: '🛡', order: 4 },
    'credential-access':     { label: 'Credential Access',     icon: '🔑', order: 5 },
    'discovery':             { label: 'Discovery',             icon: '🔍', order: 6 },
    'lateral-movement':      { label: 'Lateral Movement',      icon: '↔',  order: 7 },
    'collection':            { label: 'Collection',            icon: '📦', order: 8 },
    'command-and-control':   { label: 'Command & Control',     icon: '📡', order: 9 },
    'exfiltration':          { label: 'Exfiltration',          icon: '📤', order: 10 },
    'impact':                { label: 'Impact',                icon: '💥', order: 11 },
    'unknown':               { label: 'Unknown Tactic',        icon: '?',  order: 99 }
  };

  // ── Lookup helpers ─────────────────────────────────────────────────────
  function lookup(id) {
    if (!id) return null;
    const raw = TECHNIQUES[id];
    if (!raw) return { id, name: id, tactic: '', url: urlFor(id) };
    return {
      id,
      name: raw.name,
      tactic: raw.tactic,
      parent: raw.parent || null,
      url: urlFor(id)
    };
  }

  function primaryTactic(id) {
    const t = lookup(id);
    if (!t || !t.tactic) return '';
    return t.tactic.split(',')[0].trim();
  }

  function urlFor(id) {
    if (!id || !/^T\d{4}(\.\d{3})?$/.test(id)) return '';
    // MITRE URL format: /techniques/T1055/012/ for sub-techniques
    const dot = id.indexOf('.');
    if (dot < 0) return 'https://attack.mitre.org/techniques/' + id + '/';
    return 'https://attack.mitre.org/techniques/' + id.slice(0, dot) + '/' + id.slice(dot + 1) + '/';
  }

  function tacticMeta(tactic) {
    return TACTICS[tactic] || { label: tactic || '—', icon: '•', order: 99 };
  }

  // ── Rollup: group a set of technique IDs by tactic ─────────────────────
  // Input: array of {id, evidence?, severity?} or plain id strings
  // Output: [{tactic, tacticLabel, tacticIcon, techniques: [{id, name, evidence, severity, url}]}]
  //         sorted by ATT&CK kill-chain order, techniques within a tactic
  //         sorted by severity desc then id asc.
  function rollupByTactic(items) {
    if (!Array.isArray(items) || !items.length) return [];
    const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const byTactic = new Map();
    for (const raw of items) {
      const entry = typeof raw === 'string' ? { id: raw } : (raw || {});
      if (!entry.id) continue;
      const info = lookup(entry.id);
      if (!info) continue;
      const tactic = primaryTactic(entry.id) || 'unknown';
      if (!byTactic.has(tactic)) byTactic.set(tactic, []);
      byTactic.get(tactic).push({
        id: info.id,
        name: info.name,
        tactic,
        parent: info.parent,
        url: info.url,
        evidence: entry.evidence || '',
        severity: entry.severity || 'medium'
      });
    }
    const out = [];
    for (const [tactic, techniques] of byTactic) {
      // Dedup by id within a tactic, keep highest-severity evidence.
      const seen = new Map();
      for (const t of techniques) {
        const prev = seen.get(t.id);
        if (!prev || (SEV_RANK[t.severity] || 0) > (SEV_RANK[prev.severity] || 0)) {
          seen.set(t.id, t);
        }
      }
      const meta = tacticMeta(tactic);
      out.push({
        tactic,
        tacticLabel: meta.label,
        tacticIcon: meta.icon,
        order: meta.order,
        techniques: Array.from(seen.values()).sort((a, b) => {
          const sv = (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0);
          if (sv) return sv;
          return a.id.localeCompare(b.id);
        })
      });
    }
    out.sort((a, b) => a.order - b.order);
    return out;
  }

  // ── Public global ──────────────────────────────────────────────────────
  window.MITRE = {
    lookup,
    primaryTactic,
    urlFor,
    tacticMeta,
    rollupByTactic,
    // Exposed for ad-hoc iteration / test.
    TECHNIQUES,
    TACTICS
  };
})();
