'use strict';
// ════════════════════════════════════════════════════════════════════════════
// evtx-detector.js — EVTX threat-detection / IOC-extraction (analysis only)
//
// This file was extracted from `src/renderers/evtx-renderer.js` so that the
// Timeline worker (parse-only) can stay small: the worker bundle never
// references this file, and the analyzer runs on the main thread after the
// worker streams parsed events back.
//
// Public API:
//   EvtxDetector.analyzeForSecurity(buffer, fileName, prebuiltEvents)
//     → findings object (same shape as every other renderer's analyzer).
//     `prebuiltEvents` is the array `EvtxRenderer._parse()` / `_parseAsync()`
//     returns. When omitted the detector falls back to a sync parse via
//     `new EvtxRenderer()._parse(bytes)` so non-Timeline callers (e.g. the
//     analyser pipeline in `app-load.js`) keep working unchanged.
//
// The analyzer is intentionally pure / stateless — no DOM, no `app`. It only
// needs the `IOC.*` constants and the `escalateRisk()` helper from
// `src/constants.js`, both of which load before this file.
// ════════════════════════════════════════════════════════════════════════════

class EvtxDetector {

  static analyzeForSecurity(buffer, fileName, prebuiltEvents) {
    const bytes = new Uint8Array(buffer);
    const f = { risk: 'low', hasMacros: false, macroSize: 0, macroHash: '', autoExec: [], modules: [], externalRefs: [], metadata: {} };
    try {
      // When the Timeline view (or any caller that already parsed the file)
      // hands us its events array we re-use it; otherwise fall back to a
      // sync parse via the renderer. Cross-file dep is acceptable because
      // analyzers always run on the main thread where EvtxRenderer is in
      // scope — the worker never imports this file.
      const events = Array.isArray(prebuiltEvents)
        ? prebuiltEvents
        : new EvtxRenderer()._parse(bytes);
      f.metadata.eventCount = events.length;
      if (events.length) {
        const first = events[0], last = events[events.length - 1];
        if (first.timestamp) f.metadata.firstEvent = first.timestamp;
        if (last.timestamp) f.metadata.lastEvent = last.timestamp;
      }
      // Collect unique channels/providers
      const channels = new Set(), providers = new Set();
      for (const ev of events) {
        if (ev.channel) channels.add(ev.channel);
        if (ev.provider) providers.add(ev.provider);
      }
      if (channels.size) f.metadata.channels = [...channels].join(', ');
      if (providers.size) f.metadata.providers = [...providers].slice(0, 20).join(', ');

      // Flag suspicious event IDs — comprehensive threat-hunting patterns.
      const suspiciousPatterns = EvtxDetector._SUSPICIOUS_PATTERNS;

      // Build lookup of IDs to detect
      const suspiciousIds = new Set(suspiciousPatterns.map(p => p[0]));

      // Also track provider context to differentiate Sysmon EIDs from Security EIDs
      const foundByProvider = new Map(); // eid -> Set<provider>
      const found = new Set();
      for (const ev of events) {
        const eid = parseInt(ev.eventId, 10);
        if (suspiciousIds.has(eid)) {
          found.add(eid);
          if (!foundByProvider.has(eid)) foundByProvider.set(eid, new Set());
          if (ev.provider) foundByProvider.get(eid).add(ev.provider);
        }
      }

      // Count events per suspicious ID for enriched messages
      const eidCounts = {};
      for (const ev of events) {
        const eid = parseInt(ev.eventId, 10);
        if (found.has(eid)) eidCounts[eid] = (eidCounts[eid] || 0) + 1;
      }

      // Sysmon events (low EIDs 1-29) should only match when provider is Sysmon
      const sysmonEids = new Set([1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29]);

      for (const [eid, desc, severity, riskEsc] of suspiciousPatterns) {
        if (!found.has(eid)) continue;

        // For Sysmon EIDs, only report if the provider is actually Sysmon
        if (sysmonEids.has(eid)) {
          const provs = foundByProvider.get(eid);
          const isSysmon = provs && [...provs].some(p => /sysmon/i.test(p));
          if (!isSysmon) continue;
        }

        const count = eidCounts[eid] || 0;
        const countSuffix = count > 1 ? ` (${count} events)` : '';
        f.externalRefs.push({ type: IOC.PATTERN, url: desc + countSuffix, severity, eventId: eid, count });

        if (riskEsc) escalateRisk(f, riskEsc);
      }

      if (f.risk === 'low' && f.externalRefs.length > 0) escalateRisk(f, 'medium');

      // ── Extract IOCs from event data fields ─────────────────────────
      EvtxDetector._extractEvtxIOCs(events, f);
    } catch (e) {
      f.externalRefs.push({ type: IOC.INFO, url: 'EVTX parse warning: ' + e.message, severity: 'info' });
    }
    return f;
  }

  // ── Parse Event Data string into key-value pairs ────────────────────────
  // Intentionally duplicated from EvtxRenderer (which keeps its own copy
  // for view-side callers at lines 1819 / 1958). Pure 10-line helper —
  // duplicating is cheaper than a cross-file dep and keeps both files
  // self-contained for their respective contexts.
  static _parseEventDataPairs(eventData) {
    if (!eventData) return [];
    return eventData.split(' | ').map(part => {
      const eqIdx = part.indexOf('=');
      if (eqIdx > 0 && eqIdx < 60) {
        return { key: part.substring(0, eqIdx), val: part.substring(eqIdx + 1) };
      }
      return { key: '', val: part };
    });
  }

  // ── Extract IOCs from parsed EVTX events ────────────────────────────────
  static _extractEvtxIOCs(events, f) {
    const seen = new Set();
    // Cap the per-log IOC yield: forensic EVTX files can hold millions of
    // events, and a naïve dedup set still produces tens of thousands of
    // rows, which blows out the Summary pane. Once the cap is hit, emit a
    // single IOC.INFO so the analyst sees the truncation.
    const IOC_CAP = 1000;
    let truncated = false;
    const add = (type, val, sev) => {
      val = (val || '').trim();
      if (!val || val.length < 3 || val.length > 500 || seen.has(val.toLowerCase())) return;
      seen.add(val.toLowerCase());
      if (f.externalRefs.length >= IOC_CAP) {
        if (!truncated) {
          truncated = true;
          f.externalRefs.push({
            type: IOC.INFO,
            url: `EVTX IOC extraction truncated at ${IOC_CAP} unique values — log contains additional IOCs beyond cap`,
            severity: 'info',
          });
        }
        return;
      }
      f.externalRefs.push({ type, url: val, severity: sev });
    };

    // Keys in Sysmon / Security event data that contain process paths
    const processKeys = new Set([
      'Image', 'ParentImage', 'TargetImage', 'SourceImage',
      'ImageLoaded', 'Device', 'TargetFilename', 'SourceFilename',
      'Destination',
    ]);

    // Keys that contain command lines
    const cmdLineKeys = new Set([
      'CommandLine', 'ParentCommandLine',
    ]);

    // Keys that contain IP addresses
    const ipKeys = new Set([
      'SourceIp', 'DestinationIp', 'IpAddress',
    ]);

    // Keys that contain hostnames
    const hostnameKeys = new Set([
      'DestinationHostname', 'SourceHostname',
      'WorkstationName', 'Workstation', 'TargetServerName',
      'ComputerName', 'MachineName',
    ]);

    // Keys that contain usernames
    const usernameKeys = new Set([
      'TargetUserName', 'SubjectUserName', 'User', 'AccountName',
      'MemberName', 'UserName', 'RunAsUser',
      'TargetOutboundUserName', 'OldTargetUserName', 'NewTargetUserName',
      'SamAccountName',
    ]);

    // Keys that contain domain names (paired with usernames)
    const domainKeys = new Set([
      'TargetDomainName', 'SubjectDomainName',
    ]);

    // Username ↔ Domain pairing map: username key → domain key
    const userDomainPairs = {
      'TargetUserName': 'TargetDomainName',
      'SubjectUserName': 'SubjectDomainName',
      'TargetOutboundUserName': 'TargetDomainName',
    };

    // Noise filters — well-known system accounts and placeholders
    const boringUsers = new Set([
      'system', 'local service', 'network service',
      'anonymous logon', '-', 'n/a', '',
    ]);
    const boringUserPrefixes = ['dwm-', 'umfd-', 'font driver host'];
    // Well-known Windows built-in group names (not real user accounts)
    const boringGroups = new Set([
      'administrators', 'users', 'guests', 'power users', 'backup operators',
      'replicator', 'remote desktop users', 'network configuration operators',
      'performance monitor users', 'performance log users', 'distributed com users',
      'iis_iusrs', 'cryptographic operators', 'event log readers',
      'certificate service dcom access', 'rdp users', 'access control assistance operators',
      'hyper-v administrators', 'storage replica administrators',
      'device owners', 'none',
    ]);
    const boringDomains = new Set([
      'nt authority', 'nt service', 'font driver host',
      'window manager', '-', 'n/a', '',
    ]);
    const boringHosts = new Set([
      '-', 'localhost', 'n/a', '',
    ]);

    // Common system paths to skip (reduce noise)
    const boringPaths = new Set([
      'c:\\windows\\system32\\svchost.exe',
      'c:\\windows\\system32\\services.exe',
      'c:\\windows\\system32\\lsass.exe',
      'c:\\windows\\system32\\wininit.exe',
      'c:\\windows\\system32\\csrss.exe',
      'c:\\windows\\system32\\smss.exe',
      'c:\\windows\\system32\\winlogon.exe',
      'c:\\windows\\explorer.exe',
      'c:\\windows\\system32\\conhost.exe',
      'c:\\windows\\system32\\dwm.exe',
      'c:\\windows\\system32\\taskhostw.exe',
      'c:\\windows\\system32\\sihost.exe',
      'c:\\windows\\system32\\runtimebroker.exe',
      'c:\\windows\\system32\\dllhost.exe',
      'c:\\windows\\system32\\wuauclt.exe',
      'c:\\windows\\system32\\spoolsv.exe',
      'system',
    ]);

    // IP address pattern for filtering hostnames that are actually IPs
    const ipRe = /^(?:::ffff:)?(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$|^[0-9a-f:]+$/i;

    // Hash regex: matches SHA256, SHA1, MD5, IMPHASH patterns from Sysmon Hashes field
    const hashRe = /\b(?:SHA256|SHA1|MD5|IMPHASH|SHA384|SHA512)=([A-Fa-f0-9]{32,128})\b/g;
    // Helper: check if a username is noise
    const isBoringUser = (u) => {
      const lower = u.toLowerCase();
      if (boringUsers.has(lower)) return true;
      if (boringGroups.has(lower)) return true;
      if (lower.endsWith('$')) return true; // machine accounts
      for (const pfx of boringUserPrefixes) if (lower.startsWith(pfx)) return true;
      return false;
    };

    // Helper: check if a domain is noise
    const isBoringDomain = (d) => boringDomains.has(d.toLowerCase());

    // ── Extract unique Computer names from event system headers ──────────
    for (const ev of events) {
      if (ev.computer) {
        const host = ev.computer.trim();
        if (host && !boringHosts.has(host.toLowerCase())) {
          add(IOC.HOSTNAME, host, 'info');
        }
      }
    }

    for (const ev of events) {
      if (!ev.eventData) continue;
      const pairs = EvtxDetector._parseEventDataPairs(ev.eventData);

      // Build a quick lookup for this event's key→value pairs (for domain pairing)
      const kvMap = {};
      for (const p of pairs) {
        if (p.key) kvMap[p.key] = p.val;
      }

      for (const p of pairs) {
        const key = p.key;
        const val = p.val;
        if (!val) continue;

        // ── Hashes (from Sysmon "Hashes" field: SHA1=xxx,MD5=xxx,...) ──
        if (key === 'Hashes' || key === 'Hash') {
          let m;
          hashRe.lastIndex = 0;
          while ((m = hashRe.exec(val)) !== null) {
            const hashType = m[0].split('=')[0];
            const hashVal = m[1].toUpperCase();
            add(IOC.HASH, `${hashType}:${hashVal}`, 'medium');
          }
          continue;
        }

        // ── Process paths ──
        if (processKeys.has(key)) {
          const lower = val.toLowerCase().replace(/\0+$/, '');
          if (lower && !boringPaths.has(lower) && /^[a-z]:\\/i.test(val)) {
            add(IOC.PROCESS, val, 'medium');
          }
          continue;
        }

        // ── Command lines ──
        if (cmdLineKeys.has(key)) {
          const trimmed = val.replace(/\0+$/, '').trim();
          // Skip very short or boring command lines
          if (trimmed.length > 5 && !/^"?[A-Z]:\\Windows\\System32\\svchost\.exe"?\s*-k\s/i.test(trimmed)) {
            add(IOC.COMMAND_LINE, trimmed, 'medium');
          }
          continue;
        }

        // ── IP addresses ──
        if (ipKeys.has(key)) {
          const ip = val.trim();
          // Skip loopback/unspecified
          if (ip && ip !== '0.0.0.0' && ip !== '127.0.0.1' && ip !== '::1' && ip !== '::' && ip !== '-') {
            add(IOC.IP, ip, 'medium');
          }
          continue;
        }

        // ── Hostnames ──
        if (hostnameKeys.has(key)) {
          const host = val.trim();
          if (host && !boringHosts.has(host.toLowerCase()) && host.length > 2) {
            // If the value looks like an IP, add as IP instead
            if (ipRe.test(host)) {
              if (host !== '0.0.0.0' && host !== '127.0.0.1' && host !== '::1' && host !== '::') {
                add(IOC.IP, host, 'medium');
              }
            } else {
              add(IOC.HOSTNAME, host, 'info');
            }
          }
          continue;
        }

        // ── Usernames ──
        if (usernameKeys.has(key)) {
          const user = val.trim().replace(/\0+$/, '');
          if (!user || isBoringUser(user)) continue;

          // Try to pair with a domain field from the same event
          const domainKey = userDomainPairs[key];
          const domain = domainKey && kvMap[domainKey] ? kvMap[domainKey].trim().replace(/\0+$/, '') : '';

          if (domain && !isBoringDomain(domain)) {
            add(IOC.USERNAME, domain + '\\' + user, 'medium');
          } else {
            add(IOC.USERNAME, user, 'medium');
          }
          continue;
        }

        // ── Domain names (standalone, skip if already paired above) ──
        if (domainKeys.has(key)) {
          // Domain values are handled via username pairing above;
          // skip to avoid duplicate processing
          continue;
        }
      }

      // ── Scan entire eventData for URLs ──
      for (const m of ev.eventData.matchAll(/https?:\/\/[^\s"'<>()\[\]{}\x00-\x1F|]{6,}/g)) {
        add(IOC.URL, m[0].replace(/[.,;:!?)\]>]+$/, ''), 'medium');
      }

      // ── Scan for file paths not caught by key matching ──
      // ReDoS-hardened: bounded quantifiers on component (255) / depth
      // (32). See src/ioc-extract.js for the bounds rationale.
      for (const m of ev.eventData.matchAll(/[A-Za-z]:\\(?:[\w\-. ]{1,255}\\){1,32}[\w\-. ]{2,255}/g)) {
        const lower = m[0].toLowerCase();
        if (!boringPaths.has(lower) && !seen.has(lower)) {
          add(IOC.FILE_PATH, m[0], 'info');
        }
      }

      // ── Scan for UNC paths ──
      for (const m of ev.eventData.matchAll(/\\\\[\w.\-]{2,255}(?:\\[\w.\-]{1,255}){1,32}/g)) {
        add(IOC.UNC_PATH, m[0], 'medium');
      }

      // ── Scan for standalone hashes in unkeyed data ──
      // Only if the event has unstructured data that might contain hashes
      for (const p of pairs) {
        if (p.key) continue; // skip keyed pairs already processed
        let m;
        hashRe.lastIndex = 0;
        while ((m = hashRe.exec(p.val)) !== null) {
          const hashType = m[0].split('=')[0];
          const hashVal = m[1].toUpperCase();
          add(IOC.HASH, `${hashType}:${hashVal}`, 'medium');
        }
      }
    }
  }
}

// Each entry: [eventId, description, severity, riskEscalation]
EvtxDetector._SUSPICIOUS_PATTERNS = [
  [1100, 'Event 1100: Event logging service shut down', 'high', 'high'],
  [1102, 'Event 1102: Security audit log was cleared', 'high', 'high'],
  [104, 'Event 104: System log was cleared', 'high', 'high'],
  [4624, 'Event 4624: Successful logon events present', 'info', null],
  [4625, 'Event 4625: Failed logon attempts present', 'medium', null],
  [4634, 'Event 4634: Account logoff events present', 'info', null],
  [4648, 'Event 4648: Logon using explicit credentials (pass-the-hash indicator)', 'high', 'medium'],
  [4672, 'Event 4672: Special privilege logon events', 'medium', null],
  [4768, 'Event 4768: Kerberos TGT requested', 'info', null],
  [4769, 'Event 4769: Kerberos service ticket requested', 'info', null],
  [4771, 'Event 4771: Kerberos pre-authentication failed', 'medium', null],
  [4776, 'Event 4776: NTLM credential validation', 'info', null],
  [4688, 'Event 4688: Process creation events present', 'medium', null],
  [4689, 'Event 4689: Process termination events present', 'info', null],
  [4720, 'Event 4720: User account created', 'medium', null],
  [4722, 'Event 4722: User account enabled', 'medium', null],
  [4723, 'Event 4723: Password change attempt', 'info', null],
  [4724, 'Event 4724: Password reset attempt', 'medium', null],
  [4725, 'Event 4725: User account disabled', 'medium', null],
  [4726, 'Event 4726: User account deleted', 'medium', null],
  [4728, 'Event 4728: Member added to security-enabled global group', 'medium', null],
  [4732, 'Event 4732: Member added to security-enabled local group', 'medium', null],
  [4733, 'Event 4733: Member removed from security-enabled local group', 'medium', null],
  [4735, 'Event 4735: Security-enabled local group changed', 'medium', null],
  [4738, 'Event 4738: User account changed', 'medium', null],
  [4740, 'Event 4740: User account locked out', 'medium', null],
  [4756, 'Event 4756: Member added to universal security group', 'medium', null],
  [4656, 'Event 4656: Handle to an object was requested', 'info', null],
  [4657, 'Event 4657: Registry value was modified', 'medium', null],
  [4663, 'Event 4663: Attempt to access an object', 'info', null],
  [4697, 'Event 4697: Service installed in the system', 'medium', 'medium'],
  [4698, 'Event 4698: Scheduled task created', 'medium', 'medium'],
  [4699, 'Event 4699: Scheduled task deleted', 'medium', null],
  [4700, 'Event 4700: Scheduled task enabled', 'medium', null],
  [4701, 'Event 4701: Scheduled task disabled', 'info', null],
  [4702, 'Event 4702: Scheduled task updated', 'medium', null],
  [7034, 'Event 7034: Service crashed unexpectedly', 'medium', null],
  [7036, 'Event 7036: Service entered running/stopped state', 'info', null],
  [7040, 'Event 7040: Service start type changed (persistence indicator)', 'medium', 'medium'],
  [7045, 'Event 7045: New service installed in the system', 'medium', 'medium'],
  [5140, 'Event 5140: Network share object was accessed', 'medium', null],
  [5145, 'Event 5145: Network share object access checked', 'info', null],
  [5156, 'Event 5156: Windows Filtering Platform allowed a connection', 'info', null],
  [4103, 'Event 4103: PowerShell module logging', 'medium', 'medium'],
  [4104, 'Event 4104: PowerShell script block logging', 'medium', 'medium'],
  [40961, 'Event 40961: PowerShell console started', 'info', null],
  [40962, 'Event 40962: PowerShell console ready', 'info', null],
  [53504, 'Event 53504: PowerShell ISE session started', 'info', null],
  [1, 'Sysmon Event 1: Process created', 'medium', null],
  [2, 'Sysmon Event 2: File creation time changed (timestomping)', 'high', 'medium'],
  [3, 'Sysmon Event 3: Network connection detected', 'medium', null],
  [5, 'Sysmon Event 5: Process terminated', 'info', null],
  [6, 'Sysmon Event 6: Driver loaded', 'medium', null],
  [7, 'Sysmon Event 7: Image loaded (DLL)', 'info', null],
  [8, 'Sysmon Event 8: CreateRemoteThread (process injection indicator)', 'high', 'high'],
  [9, 'Sysmon Event 9: RawAccessRead (direct disk access)', 'high', 'medium'],
  [10, 'Sysmon Event 10: Process accessed (credential dumping indicator)', 'high', 'high'],
  [11, 'Sysmon Event 11: File created', 'info', null],
  [12, 'Sysmon Event 12: Registry object added or deleted', 'medium', null],
  [13, 'Sysmon Event 13: Registry value set', 'medium', null],
  [14, 'Sysmon Event 14: Registry object renamed', 'medium', null],
  [15, 'Sysmon Event 15: File stream created (Alternate Data Streams)', 'medium', 'medium'],
  [17, 'Sysmon Event 17: Pipe created', 'medium', null],
  [18, 'Sysmon Event 18: Pipe connected', 'medium', null],
  [19, 'Sysmon Event 19: WMI EventFilter activity detected', 'high', 'medium'],
  [20, 'Sysmon Event 20: WMI EventConsumer activity detected', 'high', 'medium'],
  [21, 'Sysmon Event 21: WMI EventConsumerToFilter activity detected', 'high', 'medium'],
  [22, 'Sysmon Event 22: DNS query', 'info', null],
  [23, 'Sysmon Event 23: File deleted', 'info', null],
  [24, 'Sysmon Event 24: Clipboard change', 'medium', null],
  [25, 'Sysmon Event 25: Process tampering (hollowing/herpaderping)', 'high', 'high'],
  [26, 'Sysmon Event 26: File delete logged', 'info', null],
  [27, 'Sysmon Event 27: File block executable', 'medium', null],
  [28, 'Sysmon Event 28: File block shredding', 'medium', null],
  [29, 'Sysmon Event 29: File executable detected', 'medium', null],
  [1006, 'Defender Event 1006: Malware or unwanted software detected', 'high', 'high'],
  [1007, 'Defender Event 1007: Action to protect system from malware', 'high', 'high'],
  [1008, 'Defender Event 1008: Failed to take action on malware', 'high', 'high'],
  [1009, 'Defender Event 1009: Item restored from quarantine', 'medium', null],
  [1116, 'Defender Event 1116: Detected malware or unwanted software', 'high', 'high'],
  [1117, 'Defender Event 1117: Performed action to protect from malware', 'high', 'high'],
  [5001, 'Defender Event 5001: Real-time protection disabled', 'high', 'high'],
  [5004, 'Defender Event 5004: Real-time protection config changed', 'medium', null],
  [5007, 'Defender Event 5007: Antimalware platform config changed', 'medium', null],
  [5010, 'Defender Event 5010: Scanning for malware disabled', 'high', 'medium'],
  [5012, 'Defender Event 5012: Scanning for viruses disabled', 'high', 'medium'],
  [5857, 'WMI Event 5857: Provider started', 'info', null],
  [5858, 'WMI Event 5858: Provider error', 'medium', null],
  [5859, 'WMI Event 5859: Subscription operation', 'medium', 'medium'],
  [5860, 'WMI Event 5860: Temporary event created', 'medium', null],
  [5861, 'WMI Event 5861: Permanent event subscription (persistence)', 'high', 'medium'],
  [8003, 'AppLocker Event 8003: Executable was allowed', 'info', null],
  [8004, 'AppLocker Event 8004: Executable was blocked', 'medium', null],
  [8006, 'AppLocker Event 8006: Script/MSI was allowed', 'info', null],
  [8007, 'AppLocker Event 8007: Script/MSI was blocked', 'medium', null],
  [1149, 'RDP Event 1149: User authentication succeeded (remote logon)', 'medium', null],
  [4778, 'Event 4778: Session reconnected to a window station', 'info', null],
  [4779, 'Event 4779: Session disconnected from a window station', 'info', null],
  [60, 'BITS Event 60: BITS transfer started (possible data exfil)', 'medium', null],
];
