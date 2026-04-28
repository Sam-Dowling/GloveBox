// ════════════════════════════════════════════════════════════════════════════
// App — YARA rule viewer dialog, scanning, and result display
// Depends on: yara-engine.js
// ════════════════════════════════════════════════════════════════════════════

// Keyword set for YARA syntax highlighting (module-level for reuse)
const _YARA_KW = new Set([
  'rule', 'meta', 'strings', 'condition', 'import', 'include', 'private', 'global',
  'and', 'or', 'not', 'any', 'all', 'of', 'them', 'true', 'false', 'at', 'in', 'for',
  'filesize', 'entrypoint', 'fullword', 'nocase', 'wide', 'ascii',
  'uint8', 'uint16', 'uint32', 'int8', 'int16', 'int32'
]);

// Storage key for user-uploaded YARA rules
const _YARA_UPLOAD_KEY = 'loupe_uploaded_yara';

// ─── YARA category reference dictionary ────────────────────────────────────
// Drives the category-info popup opened from sidebar pills and (future)
// anywhere else a category needs to be explained in plain English. Keys are
// the CSS-safe slugs produced by:
//
//     name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')
//
// Keep this in sync with the palette buckets in `core.css` (.yara-cat-pill-*)
// and with the category strings authored in `src/rules/*.yar` meta blocks.
// Adding a new category elsewhere without a row here is fine — the popup
// falls back to a generic "custom category" message. Linking to MITRE is
// best-effort: Loupe-specific buckets (malware, adware, packer, etc.) have
// no MITRE tactic and show as "Threat class" instead.
const _YARA_CATEGORY_INFO = (() => {
  // Standard MITRE ATT&CK enterprise tactic mapping. IDs link to the live
  // ATT&CK site; plain `<a>` links with rel=noopener are fine under Loupe's
  // CSP (only fetch / script / img / connect are blocked).
  const mitre = (id, name) => ({ id, name, url: `https://attack.mitre.org/tactics/${id}/` });
  return {
    // ── MITRE ATT&CK tactics ────────────────────────────────────────────
    'initial-access': {
      tactic: mitre('TA0001', 'Initial Access'),
      description: 'Techniques an adversary uses to get an initial foothold — phishing attachments, drive-by downloads, weaponised installers, supply-chain compromise.',
      indicators: ['Weaponised Office / PDF / HTA documents', 'Spear-phishing links to payload archives', 'Malicious browser extensions or MSIX installers', 'Trojanised software updates'],
    },
    'execution': {
      tactic: mitre('TA0002', 'Execution'),
      description: 'Adversary-controlled code running on a victim host — script interpreters, LOLBins, macro auto-exec, shell command invocations.',
      indicators: ['`powershell.exe -enc ...` / `rundll32` / `mshta` invocations', 'Auto-exec VBA entry points (AutoOpen, Document_Open)', 'Scheduled tasks or WMI event consumers that launch code', '`CreateProcess` / `ShellExecute` on suspicious paths'],
    },
    'persistence': {
      tactic: mitre('TA0003', 'Persistence'),
      description: 'Keeping a foothold across reboots, logins, or credential changes — Run keys, services, scheduled tasks, LaunchAgents, browser extensions.',
      indicators: ['`HKCU\\...\\CurrentVersion\\Run` / `RunOnce` writes', 'LaunchAgents / LaunchDaemons plist drops', 'Service installs (`sc create`, `New-Service`)', 'WMI `__EventFilter` + `CommandLineEventConsumer` pairs'],
    },
    'privilege-escalation': {
      tactic: mitre('TA0004', 'Privilege Escalation'),
      description: 'Elevating permissions — UAC bypasses, token theft, exploits of SUID binaries, driver loading, DLL hijacks resolved via a higher-integrity process.',
      indicators: ['`CMSTPLUA` / `ICMLuaUtil` COM abuse', 'Parent-PID spoofing / `SeDebugPrivilege` manipulation', 'Kernel driver loading (`sc create … type= kernel`)', 'macOS `AuthorizationExecuteWithPrivileges`'],
    },
    'defense-evasion': {
      tactic: mitre('TA0005', 'Defense Evasion'),
      description: 'Avoiding detection — AMSI / ETW patching, AV process kills, timestomp, indirect syscalls, reflective loaders, unhooking.',
      indicators: ['AMSI bypass strings (`amsiInitFailed`, `Amsi.dll` patches)', 'ETW provider disable calls', 'Indirect syscalls / syscall number resolution', 'Certutil / mshta / regsvr32 proxy execution'],
    },
    'evasion': {
      tactic: mitre('TA0005', 'Defense Evasion'),
      description: 'Sandbox / analyst evasion — VM detection, debugger checks, sleep-skipping, environmental keying, anti-emulation tricks.',
      indicators: ['CPUID-based hypervisor checks', '`IsDebuggerPresent` / `NtQueryInformationProcess`', 'Sleep-skip via `WaitForSingleObject` abuse', 'Mouse-movement / uptime-based gating'],
    },
    'credential-access': {
      tactic: mitre('TA0006', 'Credential Access'),
      description: 'Stealing credentials — LSASS memory reads, SAM/SECURITY hive exfil, browser password stores, Keychain dumps, DPAPI key extraction.',
      indicators: ['LSASS handle access (`MiniDumpWriteDump` on lsass.exe)', 'Reads of `Login Data` / `Cookies` / `Keychain`', 'DPAPI masterkey or Credential Manager access', 'Kerberos ticket requests with unusual encryption'],
    },
    'credential-theft': {
      tactic: mitre('TA0006', 'Credential Access'),
      description: 'Credential-theft-focused malware families — infostealers, keyloggers, clipboard hijackers, form-grabbers, and credential-harvester documents.',
      indicators: ['Browser profile paths (`Chrome\\User Data\\Default\\Login Data`)', 'Clipboard monitoring / `GetAsyncKeyState` polling', 'Crypto wallet / password-manager file reads', 'Keylogging DLL or hook installs'],
    },
    'discovery': {
      tactic: mitre('TA0007', 'Discovery'),
      description: 'Reconnaissance inside the target — host / domain / account / process / network enumeration, security tool detection, permission checks.',
      indicators: ['`systeminfo`, `whoami /all`, `net user /domain`', 'AD queries (`Get-ADUser`, LDAP searches)', 'Process listings looking for AV / EDR names', 'ARP / route / netstat enumeration'],
    },
    'lateral-movement': {
      tactic: mitre('TA0008', 'Lateral Movement'),
      description: 'Moving between hosts — SMB / WMI / WinRM execution, RDP hijacking, pass-the-hash, token impersonation, SSH pivoting.',
      indicators: ['`PsExec`-style remote service creation', 'WMI `Invoke-WMIMethod` / `wmic /node:`', 'WinRM / PowerShell Remoting targets', 'Named-pipe or admin-share writes to remote hosts'],
    },
    'collection': {
      tactic: mitre('TA0009', 'Collection'),
      description: 'Gathering data of interest prior to exfiltration — screenshots, clipboard scrapes, audio capture, file staging from documents folders.',
      indicators: ['Screenshot APIs (`BitBlt` / `CGWindowListCreateImage`)', 'Document / archive staging in `%TEMP%` or hidden folders', 'Clipboard and keylog output buffering', 'Audio / video device enumeration'],
    },
    'exfiltration': {
      tactic: mitre('TA0010', 'Exfiltration'),
      description: 'Sending collected data out — HTTP(S) / FTP / DNS tunnels, cloud-storage APIs, messaging-platform webhooks, removable media.',
      indicators: ['Long POST bodies to rare domains', 'DNS TXT / NULL queries with encoded payloads', 'API keys to Telegram / Discord / Pastebin / Dropbox', 'Large outbound transfers to non-business endpoints'],
    },
    'command-and-control': {
      tactic: mitre('TA0011', 'Command and Control'),
      description: 'Channels used to direct the compromised host — beacon HTTP(S), DNS, custom TCP/UDP, peer-to-peer, application-layer protocol abuse.',
      indicators: ['Hard-coded C2 URLs / domains / IPs', 'Beaconing jitter + sleep patterns', 'DNS DGA-style lookups', 'Telegram / Discord / Pastebin as dead-drops'],
    },
    'impact': {
      tactic: mitre('TA0040', 'Impact'),
      description: 'Final-stage destructive or disruptive actions — encryption (ransomware), wiping, defacement, resource hijacking, service denial.',
      indicators: ['Mass file enumeration followed by rename / rewrite', 'Ransom-note drop across user folders', 'Volume Shadow Copy deletion (`vssadmin delete shadows`)', 'MBR / GPT overwrite or bootloader tampering'],
    },

    // ── Loupe threat-class buckets (no direct MITRE tactic) ─────────────
    'malware': { description: 'Rules that identify specific malware families or generic malicious behaviour patterns that don\'t map cleanly to a single ATT&CK tactic.', indicators: ['Known family strings / mutexes', 'Characteristic imports or syscall chains', 'Family-specific config blobs'] },
    'backdoor': { description: 'Rules targeting remote-access backdoors that accept commands from an attacker — RATs, web shells, persistent agents.', indicators: ['Reverse-shell primitives (dup2 / WSASocket / CreateProcess)', 'Command-dispatch tables / opcode handlers', 'Persistent listen-port binding'] },
    'rootkit': { description: 'Rules targeting rootkits that hide their presence at the kernel or user-mode hook layer.', indicators: ['Kernel callback / SSDT hooking', 'Hidden-file / hidden-process tricks', 'Bootkit markers (MBR / UEFI)'] },
    'ransomware': { description: 'Rules targeting file-encrypting malware that extorts victims. A subset of Impact but high-priority enough to surface separately.', indicators: ['Bulk `CryptEncrypt` / `EncryptFile` calls', 'Extension rewrites (`.locked`, `.crypted`, random suffix)', 'Ransom-note templates across directories'] },
    'cryptominer': { description: 'Rules targeting cryptocurrency miners using victim CPU / GPU resources without consent.', indicators: ['Mining pool URLs (`stratum+tcp://`)', 'Wallet address strings (BTC / XMR / ETH)', 'CPU-affinity calls pinning to idle cores'] },
    'adware': { description: 'Rules targeting adware / PUA — unwanted installers, ad-injection, browser toolbar hijackers. Lower severity than malware but still unwanted.', indicators: ['Browser homepage / search-provider hijack', 'Injected ad tags in HTTP responses', 'Opt-in-buried bundler installers'] },
    'exploit': { description: 'Rules targeting exploitation of known vulnerabilities — CVE-specific payloads, exploit kits, shellcode stubs.', indicators: ['CVE-specific ROP gadgets / shellcode', 'Stack-pivot / heap-spray primitives', 'Patch-diff-derived magic values'] },
    'phishing': { description: 'Credential-harvesting pages, spoofed login forms, OAuth consent phishing, and HTML smuggling decoys.', indicators: ['Brand-logo strings in suspicious context', 'Password-form POSTs to non-brand origins', 'Base64-encoded HTML smuggling payloads'] },
    'delivery': { description: 'Loaders and droppers that stage the real payload — weaponised documents, LNK loaders, HTA smuggling, first-stage downloaders.', indicators: ['Second-stage URL fetch + execution', 'Embedded encoded blobs that unpack to executables', 'Multi-layer deobfuscation chains'] },
    'obfuscation': { description: 'Rules targeting obfuscation itself — heavy encoding, anti-analysis transformations, string scrambling, control-flow flattening.', indicators: ['Base64 / hex / char-code encoded payloads', 'XOR-decoder stubs with short keys', 'String-reversal / split-and-join patterns'] },
    'packer': { description: 'Commercial or custom binary packers — UPX, Themida, VMProtect, Enigma, ASPack. Not malicious on their own but raise the priority of surrounding signals.', indicators: ['Packer section names (`UPX0`, `.themida`)', 'High-entropy code sections', 'Tiny import table with dynamic resolution'] },
    'suspicious': { description: 'Behaviour that is unusual or notable but not proof of malice on its own — process hollowing primitives, rare API combinations, suspicious file paths.', indicators: ['`NtUnmapViewOfSection` + `WriteProcessMemory`', 'Script interpreters spawned from Office parents', 'Files written to `%APPDATA%\\Local\\Temp` then executed'] },
    'suspicious-api': { description: 'Rare or abuse-prone Windows / POSIX APIs whose presence in an unexpected context (e.g. inside an Office macro) warrants attention.', indicators: ['`VirtualAllocEx` / `CreateRemoteThread`', '`RtlMoveMemory` from VBA', '`GetProcAddress` over an encoded string'] },
    'anomaly': { description: 'Structural or semantic anomalies — mismatched headers, oversized metadata blocks, unexpected resource types, truncated sections.', indicators: ['PE with invalid section headers', 'Office file with a non-OOXML relationship target', 'Archive with zip-slip / directory-traversal entries'] },
    'info': { description: 'Informational rules that tag file characteristics or family attributes without asserting malice. Useful for triage and pivoting.', indicators: ['Language / locale markers', 'Compiler / linker signatures', 'Benign but noteworthy metadata'] },
    'file-type': { description: 'File-type identification rules — magic-byte and structural signatures used to classify content when the extension is missing or misleading.', indicators: ['Magic-byte matches (MZ, PK, ELF, %PDF, etc.)', 'Structural pattern checks (CFB, XAR, OLE, Mach-O)', 'Content-sniffing for plain-text script languages'] },
    'container-escape': { description: 'Rules targeting container / sandbox escape primitives — privileged-capability abuse, kernel-module tricks, CVE-specific runtime escapes.', indicators: ['`/proc/1/root` / host filesystem access', 'Capabilities check (`CAP_SYS_ADMIN`)', 'Docker socket (`/var/run/docker.sock`) writes'] },
    'msix-appx': { description: 'Windows MSIX / APPX packaging threats — installer hijacks, suspicious capabilities, app-installer URL abuse.', indicators: ['`.appinstaller` URLs pointing outside the Store', 'Unusually broad capabilities in `AppxManifest.xml`', 'Package-family-name collisions with trusted apps'] },
    'clickonce': { description: 'Windows ClickOnce deployment abuse — `.application` / `.manifest` files used for web-launched payload execution.', indicators: ['`deploymentProvider` pointing to rare origins', 'Mismatched publisher / signature metadata', 'Trust-prompt-suppressing manifest options'] },
    'browser-extension': { description: 'Browser extension threats — malicious manifests, excessive permissions, content-script injection, update-URL abuse.', indicators: ['`<all_urls>` host permissions', 'Content scripts that overwrite password fields', 'Update URLs outside the Chrome / Firefox store'] },
  };
})();

extendApp({

  // ═══════════════════════════════════════════════════════════════════════
  //  Category-aware YARA parser
  // ═══════════════════════════════════════════════════════════════════════

  /** Parse DEFAULT_YARA_RULES into categorized, sorted rule groups.
   *  @param {string} source — full YARA source with `/*! @loupe-category: <NAME> *\/`
   *                            block-comment markers injected by `scripts/build.py`.
   *                            (The trailing `*\/` is escaped so this JSDoc
   *                            block isn't terminated mid-sentence by the
   *                            literal `*\/` inside the backtick span — the
   *                            real marker is `*` followed by `/`.)
   *
   *  H8 — The marker is a block comment using a sentinel substring
   *  (`@loupe-category`) which `scripts/build.py` statically forbids
   *  from appearing anywhere in the rule source (no string literal,
   *  identifier, or comment may contain it). That removes the pre-H8
   *  attack window where a rule of the form
   *      `$s = "// @category: Hacked"`
   *  would silently truncate the previous category and start a new
   *  one with the wrong name.
   *
   *  @returns {Array<{name:string, rules:Array, isUploaded?:boolean}>} */
  _parseYaraCategories(source) {
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const validSevs = new Set(['critical', 'high', 'medium', 'low', 'info']);
    // The marker is `/*! @loupe-category: <NAME> */`. The capturing
    // group is the trimmed name. We don't anchor to line start (block
    // comments may sit on the tail of a rule's closing `}` line).
    const parts = source.split(/\/\*!\s*@loupe-category:\s*([^*]+?)\s*\*\//);


    // Fallback: no markers → one group
    if (parts.length <= 1) {
      return [{ name: 'All Rules', rules: this._extractRulesFromSource(source, sevOrder, validSevs) }];
    }

    const categories = [];
    for (let i = 1; i < parts.length; i += 2) {
      const catName = parts[i].trim();
      const catSource = parts[i + 1] || '';
      const rules = this._extractRulesFromSource(catSource, sevOrder, validSevs);
      if (rules.length) categories.push({ name: catName, rules });
    }
    categories.sort((a, b) => a.name.localeCompare(b.name));

    // Prepend uploaded rules category if any exist
    const uploaded = this._getUploadedYaraRules();
    if (uploaded) {
      const upRules = this._extractRulesFromSource(uploaded, sevOrder, validSevs);
      if (upRules.length) {
        categories.unshift({ name: 'Uploaded', rules: upRules, isUploaded: true });
      }
    }

    return categories;
  },

  /** Extract rules from a YARA source segment, returning parsed + raw source.
   *  @private */
  _extractRulesFromSource(catSource, sevOrder, validSevs) {
    const { rules: parsed } = YaraEngine.parseRules(catSource);
    // Bounded lazy classes (mirror src/yara-engine.js): tag list ≤128 chars,
    // body ≤64 KB, to prevent quadratic backtracking on malformed rules.
    const rawRx = /\brule\s+\w+\s*(?::\s*[\w\s]{1,128}?)?\s*\{[\s\S]{0,65536}?\n\}/g;
    const rawBlocks = [];
    let m;
    while ((m = rawRx.exec(catSource)) !== null) rawBlocks.push(m[0]);

    const rules = parsed.map((r, idx) => {
      const rawSev = (r.meta && r.meta.severity) ? r.meta.severity.toLowerCase() : 'high';
      return {
        name: r.name,
        tags: r.tags,
        meta: r.meta,
        severity: validSevs.has(rawSev) ? rawSev : 'high',
        description: (r.meta && r.meta.description) ? r.meta.description : '',
        rawSource: rawBlocks[idx] || ''
      };
    });
    rules.sort((a, b) => (sevOrder[a.severity] ?? 9) - (sevOrder[b.severity] ?? 9));
    return rules;
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  Uploaded rules persistence (via safeStorage)
  // ═══════════════════════════════════════════════════════════════════════

  /** Get user-uploaded YARA rules. */
  _getUploadedYaraRules() {
    return safeStorage.get(_YARA_UPLOAD_KEY) || '';
  },

  /** Set user-uploaded YARA rules. */
  _setUploadedYaraRules(source) {
    if (source) safeStorage.set(_YARA_UPLOAD_KEY, source);
    else safeStorage.remove(_YARA_UPLOAD_KEY);
  },

  /** Remove a single rule by name from uploaded rules. Returns true if removed. */
  _removeUploadedRule(ruleName) {
    const src = this._getUploadedYaraRules();
    if (!src) return false;
    /* safeRegex: builtin */
    const rx = new RegExp('\\brule\\s+' + ruleName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*(?::\\s*[\\w\\s]{1,128}?)?\\s*\\{[\\s\\S]{0,65536}?\\n\\}', 'g');
    const newSrc = src.replace(rx, '').trim();
    this._setUploadedYaraRules(newSrc || '');
    return newSrc !== src;
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  YARA syntax highlighter (tokenizer-based)
  // ═══════════════════════════════════════════════════════════════════════

  /** Syntax-highlight YARA rule source → HTML string. */
  _highlightYaraSyntax(source) {
    const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    let out = '';
    let i = 0;
    const n = source.length;
    const s = source;

    while (i < n) {
      const c = s[i];

      // ── Block comment /* … */ ────────────────────────────────────────
      if (c === '/' && s[i + 1] === '*') {
        const end = s.indexOf('*/', i + 2);
        const j = end < 0 ? n : end + 2;
        out += '<span class="yr-cmt">' + esc(s.slice(i, j)) + '</span>';
        i = j; continue;
      }

      // ── Line comment // … ───────────────────────────────────────────
      if (c === '/' && s[i + 1] === '/') {
        const end = s.indexOf('\n', i);
        const j = end < 0 ? n : end;
        out += '<span class="yr-cmt">' + esc(s.slice(i, j)) + '</span>';
        i = j; continue;
      }

      // ── String "…" ──────────────────────────────────────────────────
      if (c === '"') {
        let j = i + 1;
        while (j < n && s[j] !== '"') { if (s[j] === '\\') j++; j++; }
        if (j < n) j++; // closing quote
        out += '<span class="yr-str">' + esc(s.slice(i, j)) + '</span>';
        i = j; continue;
      }

      // ── Regex /pattern/flags (only after = on same line) ────────────
      if (c === '/') {
        let k = i - 1;
        while (k >= 0 && s[k] === ' ') k--;
        if (k >= 0 && s[k] === '=') {
          let j = i + 1;
          let escaped = false;
          while (j < n && (s[j] !== '/' || escaped) && s[j] !== '\n') {
            escaped = !escaped && s[j] === '\\';
            j++;
          }
          if (j < n && s[j] === '/') {
            j++; // closing slash
            while (j < n && /[ism]/.test(s[j])) j++; // flags
            out += '<span class="yr-rx">' + esc(s.slice(i, j)) + '</span>';
            i = j; continue;
          }
        }
        out += esc(c); i++; continue;
      }

      // ── Hex pattern { … } ──────────────────────────────────────────
      if (c === '{') {
        const end = s.indexOf('}', i + 1);
        if (end > 0 && end - i < 2000) {
          const inner = s.slice(i + 1, end);
          if (/^[\s0-9a-fA-F?|\[\]\-()~]+$/.test(inner) && inner.trim().length > 0) {
            out += '<span class="yr-hex">' + esc(s.slice(i, end + 1)) + '</span>';
            i = end + 1; continue;
          }
        }
        out += esc(c); i++; continue;
      }

      // ── Variable $name, #name, @name ────────────────────────────────
      if ((c === '$' || c === '#' || c === '@') && i + 1 < n && /\w/.test(s[i + 1])) {
        let j = i + 1;
        while (j < n && /\w/.test(s[j])) j++;
        out += '<span class="yr-var">' + esc(s.slice(i, j)) + '</span>';
        i = j; continue;
      }

      // ── Word (keyword or identifier) ────────────────────────────────
      if (/[a-zA-Z_]/.test(c)) {
        let j = i;
        while (j < n && /\w/.test(s[j])) j++;
        const word = s.slice(i, j);
        if (_YARA_KW.has(word)) {
          out += '<span class="yr-kw">' + esc(word) + '</span>';
        } else {
          out += esc(word);
        }
        i = j; continue;
      }

      // ── Number ──────────────────────────────────────────────────────
      if (/\d/.test(c)) {
        let j = i;
        if (c === '0' && i + 1 < n && /[xX]/.test(s[i + 1])) {
          j += 2;
          while (j < n && /[0-9a-fA-F]/.test(s[j])) j++;
        } else {
          while (j < n && /\d/.test(s[j])) j++;
        }
        out += '<span class="yr-num">' + esc(s.slice(i, j)) + '</span>';
        i = j; continue;
      }

      // ── Everything else ─────────────────────────────────────────────
      out += esc(c);
      i++;
    }
    return out;
  },

  /** Escape HTML for safe insertion. */
  _escHtmlYara(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  },

  /**
   * Escape a YARA condition expression and wrap each `$var` reference so
   * matched identifiers render bold and unmatched ones render dimmed.
   * Shared by the YARA results dialog and the sidebar IOC rows so the two
   * surfaces can't drift in how they describe the "reason for detection".
   *
   * @param {string} condition        Raw rule condition (e.g. "$a and #b > 2").
   * @param {Set<string>} matchedIds  Lowercased identifiers that produced hits.
   * @returns {string|null}           HTML fragment, or null when the condition
   *                                  is trivial (`any of them` / `N of them`)
   *                                  and wouldn't add explanatory value.
   */
  _yaraBoldCond(condition, matchedIds) {
    const raw = (condition || '').trim();
    if (!raw) return null;
    if (/^any\s+of\s+them$/i.test(raw)) return null;
    if (/^all\s+of\s+them$/i.test(raw)) return null;
    if (/^\d+\s+of\s+them$/i.test(raw)) return null;
    return this._escHtmlYara(raw).replace(/\$\w+\*?/g, (ref) => {
      const key = ref.replace(/\*$/, '').toLowerCase();
      if (matchedIds.has(key)) {
        return '<strong>' + ref + '</strong>';
      }
      return '<span class="yara-match-unmatched">' + ref + '</span>';
    });
  },


  // ═══════════════════════════════════════════════════════════════════════
  //  File helpers (save / upload / import)
  // ═══════════════════════════════════════════════════════════════════════

  /** Import YARA rules from a File object — shared by Upload button and drag-and-drop.
   *  Validates, merges with existing uploaded rules, shows status, and rebuilds dialog.
   *  @param {File} file */
  _yaraImportFile(file) {
    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result;
      const { valid, errors, warnings, ruleCount } = YaraEngine.validate(text);
      if (!valid) {
        this._yaraSetStatus('Upload failed: ' + (errors.length ? errors.join('; ') : 'No valid rules found'), 'error');
        return;
      }
      // Merge with existing uploaded rules
      const existing = this._getUploadedYaraRules();
      const merged = existing ? existing + '\n' + text : text;
      this._setUploadedYaraRules(merged);
      let uploadMsg = '\u2713 Uploaded ' + ruleCount + ' rule(s) from ' + file.name;
      if (warnings && warnings.length) {
        uploadMsg += ' \u2014 ' + warnings.length + ' warning(s): ' + warnings.join('; ');
      }
      this._yaraSetStatus(uploadMsg, warnings && warnings.length ? 'warning' : 'success');
      // Rebuild dialog
      this._closeYaraDialog();
      this._openYaraDialog();
    };
    reader.readAsText(file);
  },

  /** Download a string as a .yar file. */
  _yaraSaveFile(content, filename) {
    this._downloadText(content, filename, 'text/plain');
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  Combine all rules source (built-in + uploaded)
  // ═══════════════════════════════════════════════════════════════════════

  /** Get combined YARA rules source (built-in + uploaded). */
  _getAllYaraSource() {
    let src = YaraEngine.EXAMPLE_RULES || '';
    const uploaded = this._getUploadedYaraRules();
    if (uploaded) src += '\n' + uploaded;
    return src;
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  Dialog lifecycle
  // ═══════════════════════════════════════════════════════════════════════

  /** Open the YARA rules viewer dialog.
   *  @param {string} [filterRule] — optional rule name to auto-filter to */
  _openYaraDialog(filterRule) {
    // If already open, just update search filter
    if (document.getElementById('yara-dialog')) {
      if (filterRule) {
        const srch = document.getElementById('yara-search');
        if (srch) {
          srch.value = filterRule;
          srch.dispatchEvent(new Event('input'));
        }
      }
      return;
    }

    const overlay = document.createElement('div');
    overlay.id = 'yara-dialog';
    overlay.className = 'yara-overlay';

    const dialog = document.createElement('div');
    dialog.className = 'yara-dialog';

    // ── Parse rules into categories ──────────────────────────────────
    const source = YaraEngine.EXAMPLE_RULES;
    const categories = this._parseYaraCategories(source);
    const totalRules = categories.reduce((sum, c) => sum + c.rules.length, 0);

    // ── Header ──────────────────────────────────────────────────────
    const header = document.createElement('div');
    header.className = 'yara-header';
    const title = document.createElement('span');
    title.className = 'yara-title';
    title.id = 'yara-title';
    title.textContent = '\u{1F4D0} YARA Rules (' + totalRules + ')';
    header.appendChild(title);
    const closeBtn = document.createElement('button');
    closeBtn.className = 'yara-close';
    closeBtn.textContent = '\u2715';
    closeBtn.title = 'Close (Esc)';
    closeBtn.addEventListener('click', () => this._closeYaraDialog());
    header.appendChild(closeBtn);
    dialog.appendChild(header);

    // ── Toolbar (search + save + upload + scan) ─────────────────────
    const toolbar = document.createElement('div');
    toolbar.className = 'yara-toolbar';

    // ── Chip-style search with typeahead suggestions ────────────────
    // A single composable search bar that replaces the old static
    // "filter pill bar" + free-text input. Users can combine any number
    // of chips — file (the @category header the rule was defined under),
    // category (meta.category), severity (meta.severity), or raw text —
    // and the rule browser filters on the AND of all of them. See
    // `doSearch()` below for the predicate logic.
    //
    // Layout mirrors the rest of the toolbar (single flex row):
    //   [ chip | chip | <input> ] [◀] [▶] [count]
    // The input + chips live in one rounded container so the whole
    // affordance visually reads as a single searchbar.
    const searchWrap = document.createElement('div');
    searchWrap.className = 'yara-search-wrap';

    const chipBar = document.createElement('div');
    chipBar.className = 'yara-chipbar';

    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.id = 'yara-search';
    searchInput.className = 'yara-search';
    searchInput.placeholder = 'type to filter \u2014 try "execution", "critical", a filetype, or free text\u2026';
    searchInput.spellcheck = false;
    searchInput.autocomplete = 'off';
    chipBar.appendChild(searchInput);
    searchWrap.appendChild(chipBar);

    // Suggestions dropdown — anchored to the search wrap; rendered only
    // while the input is focused and non-empty-OR-just-clicked.
    const suggBox = document.createElement('div');
    suggBox.className = 'yara-sugg-box';
    suggBox.style.display = 'none';
    searchWrap.appendChild(suggBox);

    const prevBtn = document.createElement('button');
    prevBtn.className = 'yara-search-nav';
    prevBtn.textContent = '\u25C0';
    prevBtn.title = 'Previous match (Shift+Enter)';
    searchWrap.appendChild(prevBtn);

    const nextBtn = document.createElement('button');
    nextBtn.className = 'yara-search-nav';
    nextBtn.textContent = '\u25B6';
    nextBtn.title = 'Next match (Enter)';
    searchWrap.appendChild(nextBtn);

    const countSpan = document.createElement('span');
    countSpan.className = 'yara-search-count';
    countSpan.id = 'yara-search-count';
    searchWrap.appendChild(countSpan);

    toolbar.appendChild(searchWrap);

    const spacer = document.createElement('span');
    spacer.style.flex = '1';
    toolbar.appendChild(spacer);

    // ── Save dropdown button ────────────────────────────────────────
    const saveWrap = document.createElement('span');
    saveWrap.style.position = 'relative';
    saveWrap.style.display = 'inline-block';

    const saveBtn = document.createElement('button');
    saveBtn.className = 'tb-btn yara-tb-btn';
    saveBtn.textContent = '\u{1F4BE} Save';
    saveBtn.title = 'Save rules to .yar file';

    let saveMenuOpen = false;
    const saveMenu = document.createElement('div');
    saveMenu.className = 'yara-save-menu';
    saveMenu.style.display = 'none';

    const allItem = document.createElement('button');
    allItem.className = 'yara-save-menu-item';
    allItem.textContent = 'All Rules';
    allItem.addEventListener('click', () => {
      saveMenu.style.display = 'none';
      saveMenuOpen = false;
      this._yaraSaveFile(this._getAllYaraSource(), 'loupe-rules-all.yar');
    });
    saveMenu.appendChild(allItem);

    const upItem = document.createElement('button');
    upItem.className = 'yara-save-menu-item';
    upItem.textContent = 'Uploaded Only';
    const upSrc = this._getUploadedYaraRules();
    if (!upSrc) { upItem.disabled = true; }
    upItem.addEventListener('click', () => {
      saveMenu.style.display = 'none';
      saveMenuOpen = false;
      const u = this._getUploadedYaraRules();
      if (u) this._yaraSaveFile(u, 'loupe-rules-uploaded.yar');
    });
    saveMenu.appendChild(upItem);

    saveBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      saveMenuOpen = !saveMenuOpen;
      saveMenu.style.display = saveMenuOpen ? '' : 'none';
    });

    // Close save menu on any click outside
    const closeSaveMenu = () => { saveMenu.style.display = 'none'; saveMenuOpen = false; };
    overlay.addEventListener('click', closeSaveMenu);

    saveWrap.appendChild(saveMenu);
    saveWrap.appendChild(saveBtn);
    toolbar.appendChild(saveWrap);

    // ── Upload button ───────────────────────────────────────────────
    const uploadInput = document.createElement('input');
    uploadInput.type = 'file';
    uploadInput.accept = '.yar,.yara,.txt';
    uploadInput.style.display = 'none';

    const uploadBtn = document.createElement('button');
    uploadBtn.className = 'tb-btn yara-tb-btn';
    uploadBtn.textContent = '\u{1F4C2} Upload';
    uploadBtn.title = 'Upload .yar rules file';
    uploadBtn.addEventListener('click', () => uploadInput.click());

    uploadInput.addEventListener('change', () => {
      const file = uploadInput.files[0];
      if (!file) return;
      this._yaraImportFile(file);
      uploadInput.value = ''; // reset so same file can be re-uploaded
    });

    toolbar.appendChild(uploadInput);
    toolbar.appendChild(uploadBtn);

    // ── Info button (ℹ) ─────────────────────────────────────────────
    const infoBtn = document.createElement('button');
    infoBtn.className = 'yara-info-btn';
    infoBtn.textContent = 'i';
    infoBtn.title = 'YARA rule writing reference';
    infoBtn.addEventListener('click', () => this._openYaraInfoPopup(dialog));
    toolbar.appendChild(infoBtn);

    // ── Validate button ─────────────────────────────────────────────
    const validateBtn = document.createElement('button');
    validateBtn.className = 'tb-btn yara-validate-btn';
    validateBtn.textContent = '\u2714 Validate';
    validateBtn.title = 'Validate all rules (built-in + uploaded)';
    validateBtn.addEventListener('click', () => {
      const allSrc = this._getAllYaraSource();
      if (!allSrc.trim()) {
        this._yaraSetStatus('No rules to validate', 'error');
        return;
      }
      const { valid, errors, warnings, ruleCount } = YaraEngine.validate(allSrc);
      if (valid) {
        let msg = '\u2713 All ' + ruleCount + ' rule(s) validated successfully';
        if (warnings.length) {
          msg += ' \u2014 ' + warnings.length + ' warning(s): ' + warnings.join('; ');
        } else {
          msg += ' \u2014 no errors';
        }
        this._yaraSetStatus(msg, warnings.length ? 'warning' : 'success');
      } else {
        this._yaraSetStatus('\u2717 Validation failed: ' + errors.join('; '), 'error');
      }
    });
    toolbar.appendChild(validateBtn);

    // ── Scan button ─────────────────────────────────────────────────
    const scanBtn = document.createElement('button');
    scanBtn.className = 'tb-btn yara-scan-btn';
    scanBtn.textContent = '\u25B6 Run Scan';
    scanBtn.title = 'Scan loaded file against these rules';
    scanBtn.addEventListener('click', () => this._yaraRunScan());
    toolbar.appendChild(scanBtn);

    dialog.appendChild(toolbar);

    // ── Chip-search state ───────────────────────────────────────────
    // The chip bar replaces the old filter-pill row. Chips are
    // AND-combined; each chip has one of four kinds:
    //   file      — matches the @category bucket the rule was defined
    //               under (i.e. the filename-derived category authored
    //               in build.py's YARA_CATEGORIES map).
    //   category  — matches the rule's `meta.category` field.
    //   severity  — matches the rule's severity (critical/high/medium/
    //               low/info).
    //   text      — substring match against rule name + description +
    //               raw source.
    // Suggestions are drawn from the three structured sources; any
    // free-text the user commits becomes a `text:` chip.
    /** @type {Array<{kind:'file'|'category'|'severity'|'text', value:string}>} */
    const activeChips = [];
    const _slugify = (s) => String(s).toLowerCase()
      .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

    // Build suggestion sources up-front — cheap (<1k entries) and
    // avoids walking the DOM on every keystroke.
    const _fileNames = [];
    const _fileNameSet = new Set();
    for (const cat of categories) {
      if (!_fileNameSet.has(cat.name)) {
        _fileNameSet.add(cat.name);
        _fileNames.push(cat.name);
      }
    }
    const _metaCategorySet = new Set();

    // ── Rule browser (scrollable accordion) ─────────────────────────

    const browser = document.createElement('div');
    browser.className = 'yara-browser';

    // Track all rule detail elements for search
    const allRuleEls = [];
    let matchedEls = [];
    let matchIdx = -1;

    for (const cat of categories) {
      const catEl = document.createElement('details');
      catEl.className = 'yara-cat';
      // Stash category name so doSearch() can filter rules by their
      // parent category without walking the DOM back up.
      catEl.dataset.catName = cat.name;

      const catSum = document.createElement('summary');
      catSum.className = 'yara-cat-summary';
      const catNameSpan = document.createElement('span');
      catNameSpan.className = 'yara-cat-name';
      catNameSpan.textContent = cat.name;
      const catCountSpan = document.createElement('span');
      catCountSpan.className = 'yara-cat-count';
      catCountSpan.textContent = '(' + cat.rules.length + ')';
      catSum.appendChild(catNameSpan);
      catSum.appendChild(catCountSpan);

      // Red ✕ to clear all uploaded rules (on "Uploaded" category header)
      if (cat.isUploaded) {
        const catDelBtn = document.createElement('button');
        catDelBtn.className = 'yara-del-btn';
        catDelBtn.textContent = '\u2715';
        catDelBtn.title = 'Remove all uploaded rules';
        catDelBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          e.preventDefault();
          if (confirm('Remove all uploaded YARA rules?')) {
            this._setUploadedYaraRules('');
            this._yaraSetStatus('All uploaded rules removed', 'info');
            this._closeYaraDialog();
            this._openYaraDialog();
          }
        });
        catSum.appendChild(catDelBtn);
      }

      catEl.appendChild(catSum);

      const catBody = document.createElement('div');
      catBody.className = 'yara-cat-body';

      for (const rule of cat.rules) {
        const ruleEl = document.createElement('details');
        ruleEl.className = 'yara-rule-row';

        const ruleSum = document.createElement('summary');
        ruleSum.className = 'yara-rule-summary yara-rule-sev-' + rule.severity;

        const badge = document.createElement('span');
        badge.className = 'badge badge-' + rule.severity;
        badge.textContent = rule.severity;
        ruleSum.appendChild(badge);

        const nameSpan = document.createElement('span');
        nameSpan.className = 'yara-rule-name';
        nameSpan.textContent = rule.name;
        ruleSum.appendChild(nameSpan);

        if (rule.description) {
          const descSpan = document.createElement('span');
          descSpan.className = 'yara-rule-desc';
          descSpan.textContent = rule.description;
          ruleSum.appendChild(descSpan);
        }

        // Red ✕ to delete individual uploaded rule
        if (cat.isUploaded) {
          const delBtn = document.createElement('button');
          delBtn.className = 'yara-del-btn';
          delBtn.textContent = '\u2715';
          delBtn.title = 'Remove this uploaded rule';
          delBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            e.preventDefault();
            this._removeUploadedRule(rule.name);
            ruleEl.remove();
            // Update category count or remove category if empty
            const remaining = catBody.querySelectorAll('.yara-rule-row');
            if (remaining.length === 0) {
              catEl.remove();
              // Drop any `file:` chip pinned to this category so the chip
              // predicate logic (AND semantics) doesn't hide every remaining
              // rule after the only matching category has been removed.
              for (let ci = activeChips.length - 1; ci >= 0; ci--) {
                if (activeChips[ci].kind === 'file' && activeChips[ci].value === cat.name) {
                  activeChips.splice(ci, 1);
                }
              }
              renderChips();
            } else {
              catCountSpan.textContent = '(' + remaining.length + ')';
            }
            // Update total count
            const allRemaining = browser.querySelectorAll('.yara-rule-row');
            const titleEl = document.getElementById('yara-title');
            if (titleEl) titleEl.textContent = '\u{1F4D0} YARA Rules (' + allRemaining.length + ')';

          });
          ruleSum.appendChild(delBtn);
        }

        ruleEl.appendChild(ruleSum);

        // Lazy-load syntax highlighting on first expand
        let sourceRendered = false;
        ruleEl.addEventListener('toggle', () => {
          if (ruleEl.open && !sourceRendered) {
            const pre = document.createElement('pre');
            pre.className = 'yara-rule-source';
            const code = document.createElement('code');
            code.innerHTML = this._highlightYaraSyntax(rule.rawSource);
            pre.appendChild(code);
            ruleEl.appendChild(pre);
            sourceRendered = true;
          }
        });

        // Store refs for search
        ruleEl._catEl = catEl;
        ruleEl._rule = rule;
        ruleEl._searchText = (rule.name + ' ' + rule.description + ' ' + rule.rawSource).toLowerCase();
        ruleEl._ruleMetaCat = (rule.meta && rule.meta.category)
          ? String(rule.meta.category).toLowerCase() : '';
        ruleEl._ruleSeverity = rule.severity;
        if (ruleEl._ruleMetaCat) _metaCategorySet.add(ruleEl._ruleMetaCat);
        allRuleEls.push(ruleEl);


        catBody.appendChild(ruleEl);
      }

      catEl.appendChild(catBody);
      browser.appendChild(catEl);
    }

    dialog.appendChild(browser);

    // ── Status bar ──────────────────────────────────────────────────
    const status = document.createElement('div');
    status.id = 'yara-status';
    status.className = 'yara-status';
    status.textContent = 'Ready \u2014 load a file and click Run Scan';
    dialog.appendChild(status);

    // ── Results area ────────────────────────────────────────────────
    const results = document.createElement('div');
    results.id = 'yara-results';
    results.className = 'yara-results';
    dialog.appendChild(results);

    // ── Search logic ────────────────────────────────────────────────
    const scrollToMatch = () => {
      const prev = browser.querySelector('.yara-rule-active');
      if (prev) prev.classList.remove('yara-rule-active');
      if (matchIdx >= 0 && matchIdx < matchedEls.length) {
        const el = matchedEls[matchIdx];
        el.classList.add('yara-rule-active');
        el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        countSpan.textContent = (matchIdx + 1) + '/' + matchedEls.length;
      }
    };

    // Does a rule element satisfy a single chip predicate?
    const chipMatches = (re, chip) => {
      switch (chip.kind) {
        case 'file': {
          const catName = re._catEl && re._catEl.dataset ? re._catEl.dataset.catName : '';
          return catName === chip.value;
        }
        case 'category':
          return re._ruleMetaCat === chip.value;
        case 'severity':
          return re._ruleSeverity === chip.value;
        case 'text':
          return re._searchText.includes(chip.value);
        default:
          return true;
      }
    };

    const doSearch = () => {
      const typed = searchInput.value.trim().toLowerCase();
      const hasChips = activeChips.length > 0;
      const hasQuery = hasChips || !!typed;
      matchedEls = [];
      matchIdx = -1;

      // Remove active highlight
      const prevActive = browser.querySelector('.yara-rule-active');
      if (prevActive) prevActive.classList.remove('yara-rule-active');

      // No filters → default collapsed view (every category visible, closed)
      if (!hasQuery) {
        for (const re of allRuleEls) {
          re.style.display = '';
          re.open = false;
        }
        for (const catEl of browser.querySelectorAll('.yara-cat')) {
          catEl.style.display = '';
          catEl.open = false;
        }
        countSpan.textContent = '';
        return;
      }

      // AND across all chips; live-typed text is treated as an additional
      // text-substring predicate (but doesn't become a chip until the user
      // commits it).
      const catsWithMatches = new Set();
      for (const re of allRuleEls) {
        let pass = true;
        for (const ch of activeChips) {
          if (!chipMatches(re, ch)) { pass = false; break; }
        }
        if (pass && typed) pass = re._searchText.includes(typed);
        if (pass) {
          re.style.display = '';
          re.open = true;
          catsWithMatches.add(re._catEl);
          matchedEls.push(re);
        } else {
          re.style.display = 'none';
          re.open = false;
        }
      }

      // Show/hide categories. A category is visible iff it contains at least
      // one visible rule.
      for (const catEl of browser.querySelectorAll('.yara-cat')) {
        if (catsWithMatches.has(catEl)) {
          catEl.style.display = '';
          catEl.open = true;
        } else {
          catEl.style.display = 'none';
        }
      }

      if (matchedEls.length) {
        countSpan.textContent = matchedEls.length + ' rule' + (matchedEls.length === 1 ? '' : 's');
        matchIdx = 0;
        // Only scroll when the user is actively cycling matches, not on
        // every keystroke — we expose ◀/▶ for that.
      } else {
        countSpan.textContent = '0';
      }
    };

    // ── Chip rendering ──────────────────────────────────────────────
    // `chipBar` holds the chips *and* the input, so chips visually stack
    // to the left of the cursor. Every add / remove rebuilds the chip
    // DOM and re-runs the search predicate.
    const chipLabel = (ch) => {
      const prefix = (ch.kind === 'text') ? '' : (ch.kind.charAt(0).toUpperCase() + ch.kind.slice(1) + ': ');
      return prefix + ch.value;
    };
    const chipClassForKind = (ch) => {
      if (ch.kind === 'file') {
        return 'yara-chip yara-chip-file yara-cat-pill yara-cat-pill-' + _slugify(ch.value);
      }
      if (ch.kind === 'category') {
        return 'yara-chip yara-chip-category yara-cat-pill yara-cat-pill-' + _slugify(ch.value);
      }
      if (ch.kind === 'severity') {
        return 'yara-chip yara-chip-severity yara-chip-severity-' + ch.value;
      }
      return 'yara-chip yara-chip-text';
    };
    const renderChips = () => {
      // Remove existing chip nodes (input stays).
      const existing = chipBar.querySelectorAll('.yara-chip');
      existing.forEach(n => n.remove());
      // Re-insert chips before the input.
      for (let i = 0; i < activeChips.length; i++) {
        const ch = activeChips[i];
        const chipEl = document.createElement('span');
        chipEl.className = chipClassForKind(ch);
        chipEl.dataset.idx = String(i);

        const lbl = document.createElement('span');
        lbl.className = 'yara-chip-label';
        lbl.textContent = chipLabel(ch);
        chipEl.appendChild(lbl);

        const x = document.createElement('button');
        x.type = 'button';
        x.className = 'yara-chip-x';
        x.textContent = '\u2715';
        x.title = 'Remove filter';
        x.addEventListener('click', (e) => {
          e.stopPropagation();
          e.preventDefault();
          const idx = activeChips.indexOf(ch);
          if (idx >= 0) activeChips.splice(idx, 1);
          renderChips();
          doSearch();
          searchInput.focus();
        });
        chipEl.appendChild(x);

        chipBar.insertBefore(chipEl, searchInput);
      }
    };
    // Expose for external callers that tweak activeChips (delBtn handler).
    var _renderChipsRef = renderChips;   

    // ── Suggestion dropdown ─────────────────────────────────────────
    // Built fresh on every input event. Keyboard nav mirrors most IDE
    // typeaheads — ArrowDown/Up cycle `activeSugg`, Enter/Tab commit,
    // Escape closes without committing.
    /** @type {Array<{kind:string, value:string, label:string}>} */
    let currentSuggs = [];
    let activeSugg = -1;

    const hideSuggs = () => {
      suggBox.style.display = 'none';
      suggBox.innerHTML = '';
      currentSuggs = [];
      activeSugg = -1;
    };

    const renderSuggs = () => {
      suggBox.innerHTML = '';
      if (!currentSuggs.length) { suggBox.style.display = 'none'; return; }
      suggBox.style.display = '';
      currentSuggs.forEach((sg, i) => {
        const row = document.createElement('div');
        row.className = 'yara-sugg-item' + (i === activeSugg ? ' yara-sugg-item-active' : '');

        const kind = document.createElement('span');
        kind.className = 'yara-sugg-kind yara-sugg-kind-' + sg.kind;
        kind.textContent = sg.kind;
        row.appendChild(kind);

        const val = document.createElement('span');
        val.className = 'yara-sugg-value';
        val.textContent = sg.label || sg.value;
        row.appendChild(val);

        row.addEventListener('mousedown', (e) => {
          // mousedown (not click) so the input keeps focus; otherwise the
          // blur handler hides the dropdown before click fires.
          e.preventDefault();
          commitSugg(i);
        });
        suggBox.appendChild(row);
      });
    };

    const addChip = (kind, value) => {
      if (!value) return;
      // Dedupe: don't add the same (kind,value) twice.
      if (activeChips.some(c => c.kind === kind && c.value === value)) {
        searchInput.value = '';
        hideSuggs();
        doSearch();
        return;
      }
      activeChips.push({ kind, value });
      searchInput.value = '';
      hideSuggs();
      renderChips();
      doSearch();
    };

    const commitSugg = (idx) => {
      const sg = currentSuggs[idx];
      if (!sg) return;
      addChip(sg.kind, sg.value);
      searchInput.focus();
    };

    const buildSuggs = (raw) => {
      const q = raw.trim().toLowerCase();
      const out = [];
      const MAX_PER_KIND = 12;

      // File suggestions (filename-derived @category buckets).
      const fileHits = [];
      for (const name of _fileNames) {
        if (!q || name.toLowerCase().includes(q)) {
          if (!activeChips.some(c => c.kind === 'file' && c.value === name)) {
            fileHits.push({ kind: 'file', value: name, label: name });
            if (fileHits.length >= MAX_PER_KIND) break;
          }
        }
      }
      out.push(...fileHits);

      // Category suggestions (rule meta.category).
      const catHits = [];
      for (const mc of _metaCategorySet) {
        if (!q || mc.includes(q)) {
          if (!activeChips.some(c => c.kind === 'category' && c.value === mc)) {
            catHits.push({ kind: 'category', value: mc, label: mc });
            if (catHits.length >= MAX_PER_KIND) break;
          }
        }
      }
      // Stable alphabetical order for readability.
      catHits.sort((a, b) => a.value.localeCompare(b.value));
      out.push(...catHits);

      // Severity suggestions (fixed list).
      for (const sev of SEVERITIES) {
        if (!q || sev.includes(q)) {
          if (!activeChips.some(c => c.kind === 'severity' && c.value === sev)) {
            out.push({ kind: 'severity', value: sev, label: sev });
          }
        }
      }

      // Free-text chip hint — shown only when the user has typed anything.
      if (q) {
        out.push({ kind: 'text', value: q, label: '"' + raw.trim() + '"' });
      }
      return out;
    };

    let debounce;
    searchInput.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        currentSuggs = buildSuggs(searchInput.value);
        activeSugg = currentSuggs.length ? 0 : -1;
        renderSuggs();
        doSearch();
      }, 80);
    });

    searchInput.addEventListener('focus', () => {
      currentSuggs = buildSuggs(searchInput.value);
      activeSugg = currentSuggs.length ? 0 : -1;
      renderSuggs();
    });
    searchInput.addEventListener('blur', () => {
      // Slight delay so mousedown on a suggestion can fire first.
      setTimeout(hideSuggs, 150);
    });

    searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') {
        if (currentSuggs.length) {
          e.preventDefault();
          activeSugg = (activeSugg + 1) % currentSuggs.length;
          renderSuggs();
        }
        return;
      }
      if (e.key === 'ArrowUp') {
        if (currentSuggs.length) {
          e.preventDefault();
          activeSugg = (activeSugg - 1 + currentSuggs.length) % currentSuggs.length;
          renderSuggs();
        }
        return;
      }
      if (e.key === 'Enter' || e.key === 'Tab') {
        if (currentSuggs.length && activeSugg >= 0) {
          e.preventDefault();
          commitSugg(activeSugg);
          return;
        }
        // No suggestion selected → commit free-text as a text chip.
        const raw = searchInput.value.trim();
        if (raw) {
          e.preventDefault();
          addChip('text', raw.toLowerCase());
          return;
        }
      }
      if (e.key === 'Escape') {
        // Priority: close suggestions → clear typed text → remove last
        // chip → let dialog's outer Esc handler close the whole dialog.
        if (suggBox.style.display !== 'none' && currentSuggs.length) {
          e.stopPropagation();
          hideSuggs();
          return;
        }
        if (searchInput.value) {
          e.stopPropagation();
          searchInput.value = '';
          hideSuggs();
          doSearch();
          return;
        }
        if (activeChips.length) {
          e.stopPropagation();
          activeChips.pop();
          renderChips();
          doSearch();
          return;
        }
        // empty: fall through so dialog closes
        return;
      }
      if (e.key === 'Backspace' && !searchInput.value && activeChips.length) {
        // Quick-remove-last-chip affordance à la Gmail's To: field.
        e.preventDefault();
        activeChips.pop();
        renderChips();
        doSearch();
      }
    });

    // Clicking ◀ / ▶ cycles through the currently-filtered rules and
    // scrolls the chosen one into view. Useful when a filter narrows to
    // 20+ hits and the user wants to page through them.
    prevBtn.addEventListener('click', () => {
      if (matchedEls.length) {
        matchIdx = (matchIdx - 1 + matchedEls.length) % matchedEls.length;
        scrollToMatch();
      }
    });

    nextBtn.addEventListener('click', () => {
      if (matchedEls.length) {
        matchIdx = (matchIdx + 1) % matchedEls.length;
        scrollToMatch();
      }
    });


    // ── Drop hint overlay (shown during drag) ───────────────────────
    const dropHint = document.createElement('div');
    dropHint.className = 'yara-drop-hint';
    const dropHintSpan = document.createElement('span');
    dropHintSpan.textContent = '\u{1F4C2} Drop .yar / .yara file to upload rules';
    dropHint.appendChild(dropHintSpan);
    dialog.appendChild(dropHint);

    // ── Drag-and-drop .yar/.yara files onto dialog ──────────────────
    let _yaraDragCounter = 0;
    const _isYaraFile = (f) => /\.(yar|yara)$/i.test(f.name);

    dialog.addEventListener('dragenter', (e) => {
      e.preventDefault();
      _yaraDragCounter++;
      if (_yaraDragCounter === 1) dialog.classList.add('drag-over');
    });

    dialog.addEventListener('dragover', (e) => {
      e.preventDefault();
      if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy';
    });

    dialog.addEventListener('dragleave', () => {
      _yaraDragCounter--;
      if (_yaraDragCounter <= 0) {
        _yaraDragCounter = 0;
        dialog.classList.remove('drag-over');
      }
    });

    dialog.addEventListener('drop', (e) => {
      _yaraDragCounter = 0;
      dialog.classList.remove('drag-over');
      const mainDz = document.getElementById('drop-zone');
      if (mainDz) mainDz.classList.remove('drag-over');
      const files = e.dataTransfer?.files;
      if (!files || !files.length) return;
      const file = files[0];

      if (_isYaraFile(file)) {
        // YARA file → import as rules, stop event from reaching window handler
        e.preventDefault();
        e.stopPropagation();
        this._yaraImportFile(file);
      }
      // Non-YARA file → let event propagate to window drop handler for normal loading
    });

    // ── Assemble and mount ──────────────────────────────────────────
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    // Close on overlay click or Esc
    overlay.addEventListener('click', e => { if (e.target === overlay) this._closeYaraDialog(); });
    this._yaraEscHandler = e => { if (e.key === 'Escape') this._closeYaraDialog(); };
    document.addEventListener('keydown', this._yaraEscHandler);

    // If filterRule provided, pre-fill search; otherwise focus search
    if (filterRule) {
      searchInput.value = filterRule;
      setTimeout(doSearch, 50);
    } else {
      setTimeout(() => searchInput.focus(), 100);
    }
  },

  /** Close the YARA dialog. */
  _closeYaraDialog() {
    const el = document.getElementById('yara-dialog');
    if (el) el.remove();
    if (this._yaraEscHandler) {
      document.removeEventListener('keydown', this._yaraEscHandler);
      this._yaraEscHandler = null;
    }
    // Belt-and-braces: clear any stuck drag-over on the main drop-zone
    const mainDz = document.getElementById('drop-zone');
    if (mainDz) mainDz.classList.remove('drag-over');
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  Scanning
  // ═══════════════════════════════════════════════════════════════════════

  /** Run YARA scan against currently loaded file.
   *
   *  Worker-first — falls back to a synchronous main-thread scan when
   *  `Worker(blob:)` is denied (Firefox `file://` default). The manual tab
   *  has no size cap on either path; the user has explicitly asked to scan
   *  and accepts the latency cost. */
  _yaraRunScan() {
    const cr = this.currentResult;
    if (!cr || (!cr.buffer && !cr.yaraBuffer)) {
      this._yaraSetStatus('No file loaded \u2014 open a file first, then scan', 'error');
      return;
    }

    const source = this._getAllYaraSource();
    if (!source) {
      this._yaraSetStatus('No YARA rules available', 'error');
      return;
    }

    this._yaraSetStatus('Parsing rules\u2026', 'info');

    // Pre-parse on the main thread so parse errors get the same surface
    // (status bar with copy button) they had before C1 — and so we can
    // bail before spawning a worker for nothing.
    const { rules, errors } = YaraEngine.parseRules(source);
    if (errors.length) {
      this._yaraSetStatus('Parse errors: ' + errors.join('; '), 'error');
      return;
    }
    if (!rules.length) {
      this._yaraSetStatus('No rules found', 'error');
      return;
    }

    const buf = cr.yaraBuffer || cr.buffer;
    // `formatTag` is the host-detected file format (`dispatchId` from
    // `RendererRegistry.detect()`, or a script-language sniff for
    // plaintext). Threaded into both worker and sync paths so rule
    // conditions can use `is_*` predicates and `meta: applies_to` gates.
    const formatTag = (cr && typeof cr.formatTag === 'string') ? cr.formatTag : null;
    const wm  = window.WorkerManager;
    const useWorker = !!(wm && wm.workersAvailable && wm.workersAvailable());

    this._yaraSetStatus(
      'Scanning ' + rules.length + ' rule(s)\u2026' + (useWorker ? ' (worker)' : ''),
      'info'
    );

    // Mark scan in progress so the sidebar's Detections section can render
    // a "scanning rules…" indicator until results land. The sidebar will
    // already have painted by the time the analyst clicks Run Scan, so
    // re-render explicitly here to surface the indicator immediately.
    this._yaraScanInProgress = true;
    if (this.findings) {
      const fileName = (this._fileMeta && this._fileMeta.name) || '';
      this._renderSidebar(fileName, null);
    }

    const t0 = performance.now();

    const onSuccess = (results, scanErrors) => {
      this._yaraScanInProgress = false;
      const elapsed = ((performance.now() - t0) / 1000).toFixed(2);
      if (results.length === 0) {
        this._yaraSetStatus('\u2713 Scan complete in ' + elapsed + 's \u2014 no rules matched', 'success');
        this._yaraRenderResults([]);
      } else {
        this._yaraSetStatus('\u26A0 ' + results.length + ' rule(s) matched in ' + elapsed + 's', 'warning');
        this._yaraRenderResults(results);
      }
      this._yaraResults = results;
      // Surface per-string scan diagnostics (invalid regex, iter cap, time
      // cap) in the YARA results header. Hidden when nothing tripped so
      // ordinary clean scans don't sprout a "0 errors" line.
      this._yaraRenderScanErrors(scanErrors || []);
      if (this.findings) this._updateSidebarWithYara(results);
    };

    const runSync = () => {
      // setTimeout(50) lets the "Scanning…" status paint before the
      // synchronous scan blocks the main thread.
      setTimeout(() => {
        try {
          const scanErrors = [];
          const results = YaraEngine.scan(buf, rules, {
            errors: scanErrors,
            context: { formatTag },
          });
          onSuccess(results, scanErrors);
        } catch (e) {
          this._yaraScanInProgress = false;
          this._yaraSetStatus('Scan error: ' + e.message, 'error');
          // Drop the loading indicator now that the scan has aborted.
          if (this.findings) {
            const fileName = (this._fileMeta && this._fileMeta.name) || '';
            this._renderSidebar(fileName, null);
          }
        }
      }, 50);
    };

    if (useWorker) {
      let copy;
      try { copy = buf.slice(0); } catch (_) { copy = null; }
      if (copy) {
        wm.runYara(copy, source, { formatTag }).then((out) => {
          onSuccess((out && out.results) || [], (out && out.scanErrors) || []);
        }).catch((err) => {
          if (err && err.message === 'workers-unavailable') { runSync(); return; }
          // A newer scan superseded this one (or `_loadFile` cancelled
          // the channel for a new file). Bail silently — the caller has
          // already moved past these results. (The newer scan owns the
          // in-progress flag now; don't clear it here.)
          if (err && err.message === 'superseded') return;
          this._yaraScanInProgress = false;
          this._yaraSetStatus('Scan error: ' + (err && err.message ? err.message : String(err)), 'error');
          if (this.findings) {
            const fileName = (this._fileMeta && this._fileMeta.name) || '';
            this._renderSidebar(fileName, null);
          }
        });
        return;
      }
    }

    runSync();
  },

  /** Set YARA status bar text + style. For multi-item error lists, renders
   *  each item on its own line and adds a Copy button for the full text. */
  _yaraSetStatus(text, type) {
    const el = document.getElementById('yara-status');
    if (!el) return;
    el.className = 'yara-status yara-status-' + (type || 'info');
    el.innerHTML = '';

    // Split error/warning lists on "; " boundary (the separator every caller uses).
    // Anything after the first ":" in the summary header is treated as the item block.
    const splitColon = text.indexOf(': ');
    const isList = (type === 'error' || type === 'warning') &&
      splitColon !== -1 && text.indexOf('; ', splitColon) !== -1;

    if (!isList) {
      // Single-line status — keep the existing compact look
      const span = document.createElement('span');
      span.className = 'yara-status-text';
      span.textContent = text;
      el.appendChild(span);
      return;
    }

    // Multi-item status: summary + bulleted list + copy button
    const header = text.slice(0, splitColon);
    const items = text.slice(splitColon + 2).split('; ').filter(Boolean);

    const summary = document.createElement('div');
    summary.className = 'yara-status-summary';
    const summaryText = document.createElement('span');
    summaryText.textContent = header + ' \u2014 ' + items.length +
      (type === 'error' ? ' error' : ' warning') + (items.length === 1 ? '' : 's');
    summary.appendChild(summaryText);

    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'yara-status-copy-btn';
    copyBtn.textContent = '\u{1F4CB} Copy';
    copyBtn.title = 'Copy full error text to clipboard';
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const payload = header + '\n' + items.map(s => '  \u2022 ' + s).join('\n');
      const done = () => {
        if (this._toast) this._toast('Copied error to clipboard');
        const orig = copyBtn.textContent;
        copyBtn.textContent = '\u2713 Copied';
        setTimeout(() => { copyBtn.textContent = orig; }, 1500);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(payload).then(done, () => {
          // Fallback to execCommand if clipboard API is blocked
          const ta = document.createElement('textarea');
          ta.value = payload; ta.style.position = 'fixed'; ta.style.opacity = '0';
          document.body.appendChild(ta); ta.select();
          try { document.execCommand('copy'); done(); }
          catch (_) { if (this._toast) this._toast('Copy failed', 'error'); }
          finally { document.body.removeChild(ta); }
        });
      } else {
        const ta = document.createElement('textarea');
        ta.value = payload; ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        try { document.execCommand('copy'); done(); }
        catch (_) { if (this._toast) this._toast('Copy failed', 'error'); }
        finally { document.body.removeChild(ta); }
      }
    });
    summary.appendChild(copyBtn);
    el.appendChild(summary);

    const list = document.createElement('ul');
    list.className = 'yara-status-list';
    for (const it of items) {
      const li = document.createElement('li');
      li.textContent = it;
      list.appendChild(li);
    }
    el.appendChild(list);
  },


  /** Render the per-string scan diagnostics emitted by `YaraEngine.scan(...,
   *  { errors })` (invalid regex, iteration cap, wall-clock cap). One row
   *  per failed string is rendered into a banner that sits above the
   *  results card list; nothing is rendered when the diagnostics list is
   *  empty so a clean scan still looks clean.
   *
   *  Without this surface every one of these failures would be silently
   *  swallowed by the `catch(_)` blocks in `_findString`, so a single
   *  pathological rule could produce zero matches with no UI signal at
   *  all. */
  _yaraRenderScanErrors(scanErrors) {
    const container = document.getElementById('yara-results');
    if (!container) return;
    // Clear any stale banner from a previous scan.
    const stale = container.querySelector('.yara-scan-errors');
    if (stale) stale.remove();
    if (!scanErrors || !scanErrors.length) return;

    const banner = document.createElement('div');
    banner.className = 'yara-scan-errors';

    const heading = document.createElement('div');
    heading.className = 'yara-scan-errors-heading';
    heading.textContent = '\u26A0 ' + scanErrors.length +
      ' rule string(s) hit a runtime budget or failed to compile';
    banner.appendChild(heading);

    const list = document.createElement('ul');
    list.className = 'yara-scan-errors-list';
    // Cap the on-screen list so a buggy ruleset that emits thousands of
    // diagnostics doesn't blow out the dialog. The full list is still in
    // memory (`this._yaraResults` consumers can walk it) — this is purely
    // a presentation cap.
    const MAX_SHOWN = 50;
    const shown = scanErrors.slice(0, MAX_SHOWN);
    for (const e of shown) {
      const li = document.createElement('li');
      const head = (e.ruleName ? e.ruleName + ' ' : '') + (e.stringId || '');
      const tail = e.reason ? ' [' + e.reason + ']' : '';
      li.textContent = head + tail + ' \u2014 ' + (e.message || '');
      list.appendChild(li);
    }
    banner.appendChild(list);
    if (scanErrors.length > MAX_SHOWN) {
      const more = document.createElement('div');
      more.className = 'yara-scan-errors-more';
      more.textContent = '\u2026and ' + (scanErrors.length - MAX_SHOWN) + ' more';
      banner.appendChild(more);
    }
    // Insert at top of the results panel so it precedes the result cards.
    container.insertBefore(banner, container.firstChild);
  },

  /** Render YARA scan results into the results panel. */
  _yaraRenderResults(results) {

    const container = document.getElementById('yara-results');
    if (!container) return;
    container.innerHTML = '';

    if (!results.length) {
      const empty = document.createElement('div');
      empty.className = 'yara-no-results';
      empty.textContent = 'No matches';
      container.appendChild(empty);
      return;
    }

    for (const r of results) {
      const card = document.createElement('div');
      card.className = 'yara-result-card';

      const hdr = document.createElement('div');
      hdr.className = 'yara-result-header';
      const name = document.createElement('span');
      name.className = 'yara-result-rule-name';
      name.textContent = r.ruleName;
      hdr.appendChild(name);
      if (r.tags) {
        const tags = document.createElement('span');
        tags.className = 'yara-rule-tags';
        tags.textContent = r.tags;
        hdr.appendChild(tags);
      }
      const severity = (r.meta && r.meta.severity) ? r.meta.severity.toLowerCase() : 'high';
      const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
      const sevClass = validSeverities.includes(severity) ? severity : 'high';
      const badge = document.createElement('span');
      badge.className = 'badge badge-' + sevClass;
      badge.textContent = severity;
      hdr.appendChild(badge);
      card.appendChild(hdr);

      // Build the set of identifiers that actually produced hits — used to
      // emphasise matched $vars inside the condition expression on hover.
      const matchedIdSet = new Set(r.matches.map(m => m.id.toLowerCase()));
      const condHtml = this._yaraBoldCond(r.condition, matchedIdSet);


      // String matches
      for (const sm of r.matches) {
        const row = document.createElement('div');
        row.className = 'yara-match-row';
        // Preserve the rule's variable name as a native tooltip so it stays
        // recoverable without cluttering the column alignment.
        row.title = sm.id;

        const val = document.createElement('span');
        val.className = 'yara-match-val';
        val.textContent = sm.value;
        row.appendChild(val);

        const count = document.createElement('span');
        count.className = 'yara-match-count';
        count.textContent = sm.matches.length + ' hit' + (sm.matches.length !== 1 ? 's' : '');
        row.appendChild(count);

        // Hover-revealed detection reason: this row's $var + the rule's
        // condition with matched $vars emphasised.
        const reason = document.createElement('div');
        reason.className = 'yara-match-reason';
        const idChip = '<span class="yara-match-id">' + this._escHtmlYara(sm.id) + '</span>';
        if (condHtml) {
          reason.innerHTML = idChip + ' <span class="yara-match-sep">\u2192</span> ' + condHtml;
        } else {
          // Fallback for trivial conditions — still shows the $var name so
          // nothing is lost, just without a meaningful expression to bold.
          reason.innerHTML = idChip + ' <span class="yara-match-sep">\u00b7</span> <em>matched</em>';
        }
        row.appendChild(reason);

        card.appendChild(row);
      }

      container.appendChild(card);
    }
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  Auto-scan & sidebar integration
  // ═══════════════════════════════════════════════════════════════════════

  /** Auto-run YARA scan when a file is loaded (uses built-in + uploaded rules).
   *
   *  Runs in a Web Worker so a 100 MiB scan no longer freezes the UI. When
   *  `Worker(blob:)` is denied (e.g. Firefox `file://` default)
   *  `WorkerManager.runYara` rejects with `'workers-unavailable'` and we
   *  fall back to the synchronous in-tree path. The
   *  `PARSER_LIMITS.SYNC_YARA_FALLBACK_MAX_BYTES` size gate only applies on
   *  the fallback path — when the worker is available, scan time is no
   *  longer blocking and the cap is unnecessary.
   *
   *  Scan errors are routed through `App._reportNonFatal('auto-yara', err)`,
   *  which surfaces them as a sidebar `IOC.INFO` row plus a `console.warn`. */
  _autoYaraScan() {
    const cr = this.currentResult;
    if (!cr || (!cr.buffer && !cr.yaraBuffer)) return;
    const source = this._getAllYaraSource();
    if (!source) return;

    const buf = cr.yaraBuffer || cr.buffer;
    if (!buf) return;

    // `formatTag` (Loupe-detected file format) drives `is_*` predicates
    // and `meta: applies_to` short-circuits in the engine. Captured here
    // and threaded into both worker and sync paths.
    const formatTag = (typeof cr.formatTag === 'string') ? cr.formatTag : null;

    const wm = window.WorkerManager;
    const useWorker = !!(wm && wm.workersAvailable && wm.workersAvailable());

    // ── Worker path (no size gate — terminate() is real preemption) ────────
    if (useWorker) {
      let copy;
      try {
        copy = buf.slice(0);
      } catch (_) {
        // Detached / OOM — fall through to sync path below.
        copy = null;
      }
      if (copy) {
        // Surface a "scanning rules…" indicator in the sidebar Detections
        // section while the worker scan is in flight. Cleared on every
        // terminal branch below (success, late-veto handoff to sync,
        // supersession handoff, hard error). The sidebar has typically
        // already painted from `_loadFile` by the time we reach here, so
        // re-render explicitly to surface the indicator immediately.
        this._yaraScanInProgress = true;
        if (this.findings) {
          const fileName = (this._fileMeta && this._fileMeta.name) || '';
          this._renderSidebar(fileName, null);
        }
        wm.runYara(copy, source, { formatTag }).then((out) => {
          this._yaraScanInProgress = false;
          const results = (out && out.results) || [];
          this._yaraResults = results;
          // `_updateSidebarWithYara` re-renders the sidebar; no separate
          // call needed here.
          if (this.findings) this._updateSidebarWithYara(results);
        }).catch((err) => {
          if (err && err.message === 'workers-unavailable') {
            // Late veto — `_autoYaraScanSync` will own the in-progress
            // flag from this point onwards.
            this._autoYaraScanSync(buf, source, formatTag);
            return;
          }
          // A newer file load (or `_loadFile`'s entry-point cancel) has
          // already invalidated this scan's results. Bail silently — the
          // newer load will trigger its own auto-scan; surfacing the
          // supersession as a sidebar IOC.INFO would be noise. The newer
          // scan owns the in-progress flag now, so don't clear it here.
          if (err && err.message === 'superseded') return;
          this._yaraScanInProgress = false;
          this._reportAutoYaraError(err);
          if (this.findings) {
            const fileName = (this._fileMeta && this._fileMeta.name) || '';
            this._renderSidebar(fileName, null);
          }
        });
        return;
      }
    }

    // ── Synchronous fallback path ──────────────────────────────────────────
    this._autoYaraScanSync(buf, source, formatTag);
  },

  /** Synchronous main-thread fallback for `_autoYaraScan`. Used when
   *  `Worker(blob:)` is unavailable (e.g. Firefox `file://`) or the buffer
   *  copy for the worker transfer fails. The
   *  `SYNC_YARA_FALLBACK_MAX_BYTES` cap is enforced **only here** — see
   *  `src/constants.js` for the rationale.
   *
   *  `formatTag` is forwarded into `YaraEngine.scan(..., {context})` so
   *  format-aware rule features (`is_*`, `meta: applies_to`) work
   *  identically to the worker path. */
  _autoYaraScanSync(buf, source, formatTag) {
    const size = (buf && buf.byteLength) || 0;
    if (size > PARSER_LIMITS.SYNC_YARA_FALLBACK_MAX_BYTES) {
      // Size-cap skip is a terminal branch — clear any in-progress flag
      // set by the worker path before it handed off to us.
      this._yaraScanInProgress = false;
      if (this.findings) {
        const mb = (PARSER_LIMITS.SYNC_YARA_FALLBACK_MAX_BYTES / (1024 * 1024)) | 0;
        pushIOC(this.findings, {
          type: IOC.INFO,
          value: `YARA auto-scan skipped (file >${mb} MiB; open the YARA tab to scan manually)`,
          severity: 'info',
        });
        const fileName = (this._fileMeta && this._fileMeta.name) || '';
        this._renderSidebar(fileName, null);
      }
      return;
    }
    // Surface the "scanning rules…" indicator if the worker path didn't
    // already set the flag (e.g. workers unavailable from the start). The
    // synchronous scan below blocks the main thread, so the indicator
    // really only paints when this method is reached via a worker
    // late-veto handoff and an extra paint cycle squeezed in.
    if (!this._yaraScanInProgress) {
      this._yaraScanInProgress = true;
      if (this.findings) {
        const fileName = (this._fileMeta && this._fileMeta.name) || '';
        this._renderSidebar(fileName, null);
      }
    }
    try {
      const { rules } = YaraEngine.parseRules(source);
      if (!rules.length) {
        this._yaraScanInProgress = false;
        if (this.findings) {
          const fileName = (this._fileMeta && this._fileMeta.name) || '';
          this._renderSidebar(fileName, null);
        }
        return;
      }
      const results = YaraEngine.scan(buf, rules, {
        context: { formatTag: formatTag || null },
      });
      this._yaraScanInProgress = false;
      this._yaraResults = results;
      // `_updateSidebarWithYara` re-renders the sidebar; no separate call.
      if (this.findings) this._updateSidebarWithYara(results);
    } catch (err) {
      this._yaraScanInProgress = false;
      this._reportAutoYaraError(err);
      if (this.findings) {
        const fileName = (this._fileMeta && this._fileMeta.name) || '';
        this._renderSidebar(fileName, null);
      }
    }
  },

  /** Surface an auto-YARA error as a sidebar `IOC.INFO` note plus a console
   *  warning. Forwards to the canonical helper
   *  `App._reportNonFatal('auto-yara', err)` which handles both — kept as a
   *  thin per-call-site method so future call-site-specific instrumentation
   *  (timing, sampling, etc.) has a single seam to widen. */
  _reportAutoYaraError(err) {
    this._reportNonFatal('auto-yara', err);
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  YARA Info Reference Popup
  // ═══════════════════════════════════════════════════════════════════════

  /** Open the YARA rule-writing reference popup inside the dialog.
   *  @param {HTMLElement} dialogEl — the .yara-dialog container */
  _openYaraInfoPopup(dialogEl) {
    // Prevent duplicate
    if (dialogEl.querySelector('.yara-info-overlay')) return;

    // ── Overlay ──────────────────────────────────────────────────────
    const ov = document.createElement('div');
    ov.className = 'yara-info-overlay';

    // ── Card ─────────────────────────────────────────────────────────
    const card = document.createElement('div');
    card.className = 'yara-info-card';

    // ── Header ───────────────────────────────────────────────────────
    const hdr = document.createElement('div');
    hdr.className = 'yara-info-header';
    const h3 = document.createElement('h3');
    h3.textContent = '\u{1F4D6} YARA Rule Reference';
    hdr.appendChild(h3);
    const closeBtn = document.createElement('button');
    // Reuse the main YARA dialog's close-button styling so the info popup
    // has the same rounded-square, red-tinted affordance as the parent
    // dialog header.
    closeBtn.className = 'yara-close';
    closeBtn.textContent = '\u2715';
    closeBtn.title = 'Close';
    closeBtn.addEventListener('click', () => ov.remove());
    hdr.appendChild(closeBtn);
    card.appendChild(hdr);

    // ── Body (scrollable) ────────────────────────────────────────────
    const body = document.createElement('div');
    body.className = 'yara-info-body';

    // Helper: create a section heading
    const h = (text) => { const el = document.createElement('h4'); el.textContent = text; return el; };

    // Helper: build a table from header + rows arrays
    const table = (headers, rows, sevRow) => {
      const t = document.createElement('table');
      const thead = document.createElement('thead');
      const tr = document.createElement('tr');
      for (const h of headers) { const th = document.createElement('th'); th.textContent = h; tr.appendChild(th); }
      thead.appendChild(tr);
      t.appendChild(thead);
      const tbody = document.createElement('tbody');
      for (const row of rows) {
        const r = document.createElement('tr');
        if (sevRow) r.className = 'yara-info-sev-row';
        for (const cell of row) {
          const td = document.createElement('td');
          if (typeof cell === 'object' && cell._html) td.innerHTML = cell._html;
          else td.textContent = cell;
          r.appendChild(td);
        }
        tbody.appendChild(r);
      }
      t.appendChild(tbody);
      return t;
    };

    // Helper: inline <code> wrapper
    const c = (text) => ({ _html: '<code>' + this._escHtmlYara(text) + '</code>' });

    // ── 1. Rule Structure ────────────────────────────────────────────
    body.appendChild(h('Rule Structure'));
    const structPre = document.createElement('pre');
    structPre.innerHTML = this._highlightYaraSyntax(
      'rule Suspicious_PowerShell_Download\n' +
      '{\n' +
      '    meta:\n' +
      '        description = "What this rule detects"\n' +
      '        severity    = "high"\n' +
      '        category    = "execution"\n' +
      '        mitre       = "T1059.001"\n' +
      '\n' +
      '    strings:\n' +
      '        $text1 = "suspicious string"\n' +
      '        $hex1  = { 4D 5A 90 00 }\n' +
      '        $re1   = /eval\\(base64_decode/i\n' +
      '\n' +
      '    condition:\n' +
      '        any of them\n' +
      '}'
    );
    body.appendChild(structPre);

    const structNote = document.createElement('p');
    structNote.innerHTML = '<strong>Required:</strong> <code>rule NAME { condition: ... }</code> &mdash; '
      + '<code>meta:</code> and <code>strings:</code> are optional but recommended.';
    body.appendChild(structNote);

    // ── 2. String Types ──────────────────────────────────────────────
    body.appendChild(h('String Types'));
    body.appendChild(table(
      ['Type', 'Syntax', 'Example', 'Notes'],
      [
        ['Text', c('"..."'), c('$s = "cmd.exe"'), 'Exact byte match'],
        ['Hex', c('{ XX XX }'), c('$h = { 4D 5A 90 }'), 'Raw bytes; supports wildcards'],
        ['Regex', c('/pattern/flags'), c('$r = /eval\\(.{0,40}\\)/i'), 'RE after = sign; i s m flags'],
      ]
    ));

    // ── 3. Hex Pattern Features ──────────────────────────────────────
    body.appendChild(h('Hex Pattern Features'));
    body.appendChild(table(
      ['Feature', 'Syntax', 'Meaning'],
      [
        ['Wildcard byte', c('??'), 'Matches any single byte'],
        ['Nibble wildcard', c('4? or ?A'), 'Matches half-byte'],
        ['Jump (range)', c('[2-4]'), 'Skip 2 to 4 bytes'],
        ['Unbounded jump', c('[-]'), 'Skip any number of bytes'],
        ['Alternative', c('( AA | BB )'), 'Match either sequence'],
      ]
    ));

    // ── 4. String Modifiers ──────────────────────────────────────────
    body.appendChild(h('String Modifiers'));
    body.appendChild(table(
      ['Modifier', 'Effect', 'Example'],
      [
        [c('nocase'), 'Case-insensitive match', c('$s = "cmd" nocase')],
        [c('wide'), 'UTF-16LE encoding (2 bytes/char)', c('$s = "cmd" wide')],
        [c('ascii'), 'ASCII encoding (default, explicit)', c('$s = "cmd" ascii wide')],
        [c('fullword'), 'Must be delimited by non-alphanumeric', c('$s = "eval" fullword')],
      ]
    ));

    // ── 5. Condition Keywords ────────────────────────────────────────
    body.appendChild(h('Condition Keywords'));
    body.appendChild(table(
      ['Keyword / Operator', 'Example', 'Description'],
      [
        [c('any of them'), c('condition: any of them'), 'Any defined string matches'],
        [c('all of them'), c('condition: all of them'), 'Every defined string matches'],
        [c('N of them'), c('condition: 2 of them'), 'At least N strings match'],
        [c('any of ($a*)'), c('condition: any of ($a*)'), 'Any string starting with $a'],
        [c('#s > N'), c('condition: #s > 3'), 'String $s matches > N times'],
        [c('$s at N'), c('condition: $s at 0'), 'String $s at exact offset'],
        [c('$s in (X..Y)'), c('condition: $s in (0..256)'), 'String $s within byte range'],
        [c('filesize'), c('condition: filesize < 100KB'), 'Size of scanned data'],
        [c('and / or / not'), c('condition: $a and not $b'), 'Boolean logic'],
        [c('for N of ... : (...)'), c('for all of ($s*) : (# > 1)'), 'Iterate with sub-condition'],
      ]
    ));

    // ── 6. Severity Levels (Loupe-specific) ──────────────────────
    body.appendChild(h('Severity Levels (Loupe)'));
    const sevNote = document.createElement('p');
    sevNote.textContent = 'Set via meta: severity = "level". Controls badge colour and risk scoring.';
    body.appendChild(sevNote);
    body.appendChild(table(
      ['Level', 'Colour', 'Use for'],
      [
        ['critical', '\u{1F534} Red', 'Active exploitation, weaponised payloads'],
        ['high', '\u{1F7E0} Orange', 'Shellcode, obfuscated scripts, known malware'],
        ['medium', '\u{1F7E1} Yellow', 'Suspicious patterns, dual-use tools'],
        ['low', '\u{1F535} Blue', 'Informational artefacts, unusual but benign'],
        ['info', '\u26AA Grey', 'Metadata, structural markers, FYI only'],
      ],
      true // sevRow class
    ));

    // ── 7. Meta Fields (Loupe) ───────────────────────────────────
    body.appendChild(h('Meta Fields (Loupe)'));
    const metaNote = document.createElement('p');
    metaNote.textContent = 'Loupe recognises four standardised meta fields. All are optional but recommended.';
    body.appendChild(metaNote);
    body.appendChild(table(
      ['Field', 'Type', 'Example', 'Purpose'],
      [
        [c('description'), 'string', c('"Detects PowerShell download cradle"'), 'Shown in sidebar findings and scan results'],
        [c('severity'), 'string', c('"high"'), 'Badge colour & risk scoring (see Severity Levels above)'],
        [c('category'), 'string', c('"execution"'), 'Groups the rule logically (e.g. execution, persistence, evasion)'],
        [c('mitre'), 'string', c('"T1059.001"'), 'MITRE ATT&CK technique ID for cross-referencing'],
      ]
    ));

    // ── 8. Naming Convention ─────────────────────────────────────────
    body.appendChild(h('Naming Convention'));
    const nameNote = document.createElement('p');
    nameNote.innerHTML = 'Rule names use <code>Prefix_Words_With_Underscores</code>. '
      + 'Loupe automatically converts underscores to spaces for display in the '
      + '<strong>Detections</strong> sidebar &mdash; e.g. <code>Suspicious_PowerShell_Download</code> '
      + '&rarr; <em>Suspicious PowerShell Download</em>.';
    body.appendChild(nameNote);
    const nameTip = document.createElement('p');
    nameTip.innerHTML = '<strong>Tip:</strong> Use a descriptive prefix like '
      + '<code>Suspicious_</code>, <code>Malicious_</code>, or <code>Contains_</code> '
      + 'to give analysts quick context in the sidebar.';
    body.appendChild(nameTip);

    // ── 9. Complete Example ──────────────────────────────────────────
    body.appendChild(h('Complete Example'));
    const exPre = document.createElement('pre');
    exPre.innerHTML = this._highlightYaraSyntax(
      'rule Suspicious_PowerShell_Download\n' +
      '{\n' +
      '    meta:\n' +
      '        description = "Detects PowerShell download cradle patterns"\n' +
      '        severity    = "high"\n' +
      '        category    = "execution"\n' +
      '        mitre       = "T1059.001"\n' +
      '\n' +
      '    strings:\n' +
      '        $iwr  = "Invoke-WebRequest" nocase\n' +
      '        $iex  = "IEX" fullword nocase\n' +
      '        $net  = "Net.WebClient" nocase\n' +
      '        $dl   = "DownloadString" nocase\n' +
      '        $b64  = /FromBase64String\\(.{1,64}\\)/i\n' +
      '        $hex  = { 49 00 45 00 58 00 }\n' +
      '\n' +
      '    condition:\n' +
      '        2 of them\n' +
      '}'
    );
    body.appendChild(exPre);

    card.appendChild(body);
    ov.appendChild(card);

    // ── Dismiss handlers ─────────────────────────────────────────────
    ov.addEventListener('click', (e) => { if (e.target === ov) ov.remove(); });
    const escHandler = (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        ov.remove();
        document.removeEventListener('keydown', escHandler, true);
      }
    };
    document.addEventListener('keydown', escHandler, true);

    dialogEl.appendChild(ov);
  },

  /** Build a byte-offset → JS-char-offset map for the rendered rawText.
   *  YARA reports byte offsets into the UTF-8 encoded file buffer it was
   *  handed, but the text view (`plaintext-table`) works in JavaScript
   *  string (UTF-16 code unit) coordinates over `_rawText`. The two
   *  coordinate systems diverge in three ways:
   *
   *    1. Multi-byte UTF-8 characters (e.g. `──` U+2500 = 3 bytes / 1 JS
   *       char) make a naive 1:1 walk drift on every non-ASCII glyph.
   *    2. `_rawText` is `lfNormalize(text)` — every CR / CRLF in the
   *       source bytes is collapsed to a single LF, so a CRLF file shifts
   *       every match by +1 byte per preceding line.
   *    3. Renderers like HTML / SVG / Plist / Scpt feed YARA an
   *       *augmented* buffer (raw bytes + appended `=== RENDERED DOM
   *       TEXT ===` / `=== EXTRACTED … ===` sections) whose tail does
   *       not exist in `_rawText` at all.
   *
   *  Walking the actual scanned buffer in lock-step with `_rawText` is
   *  the only way to get all three right: CRLF skips advance the byte
   *  cursor without consuming a char, and the moment a byte fails to
   *  match (typically the start of an augmented `===` section) we stop
   *  emitting entries — `_updateSidebarWithYara` then drops every match
   *  whose byte offset has no char mapping, so we never highlight
   *  phantom locations from synthesised regions.
   *
   *  Returns a Map<byteOffset, charOffset> with entries at every aligned
   *  character boundary, plus a final entry at the last aligned position.
   *  Returns null if no rawText / scan buffer is available. */
  _buildYaraByteToCharMap() {
    const pc = document.getElementById('page-container');
    const docEl = pc && pc.firstElementChild;
    const rawText = docEl && docEl._rawText;
    if (typeof rawText !== 'string' || !rawText.length) return null;

    const cr = this.currentResult;
    const buf = cr && (cr.yaraBuffer || cr.buffer);
    if (!buf) return null;
    const bytes = new Uint8Array(buf);

    const map = new Map();
    let bi = 0, ci = 0;
    while (bi < bytes.length && ci < rawText.length) {
      const b = bytes[bi];
      const code = rawText.charCodeAt(ci);

      // ── CRLF → LF: byte buffer has \r\n, _rawText has just \n ────────
      // Skip the bare CR byte without consuming a char; the next loop
      // iteration consumes the LF byte as the LF char.
      if (b === 0x0D && bi + 1 < bytes.length && bytes[bi + 1] === 0x0A && code === 0x0A) {
        bi++; continue;
      }
      // Bare CR in buffer → LF in _rawText (lfNormalize replaces lone \r).
      if (b === 0x0D && code === 0x0A) {
        map.set(bi, ci); bi++; ci++; continue;
      }

      // ── Aligned ASCII fast path ──────────────────────────────────────
      if (code < 0x80) {
        if (b !== code) break; // buffers diverged — stop mapping
        map.set(bi, ci); bi++; ci++; continue;
      }

      // ── Multi-byte UTF-8 ─────────────────────────────────────────────
      // Validate the leading byte of the encoded sequence matches what
      // `_rawText`'s code point would produce; bail on mismatch so we
      // don't paper over a real divergence with a guess.
      let cpLen, leadByte;
      if (code >= 0xD800 && code <= 0xDBFF) {
        // Supplementary plane: 4 UTF-8 bytes, 2 JS chars (surrogate pair).
        const low = rawText.charCodeAt(ci + 1);
        if (low < 0xDC00 || low > 0xDFFF) break;
        const cp = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
        leadByte = 0xF0 | (cp >> 18);
        cpLen = 4;
      } else if (code < 0x800) {
        leadByte = 0xC0 | (code >> 6);
        cpLen = 2;
      } else {
        leadByte = 0xE0 | (code >> 12);
        cpLen = 3;
      }
      if (b !== leadByte) break;
      map.set(bi, ci);
      bi += cpLen;
      ci += cpLen === 4 ? 2 : 1;
    }
    // Final entry at the last aligned position so end-offset lookups for
    // a match that ends exactly at the alignment boundary still resolve.
    map.set(bi, ci);
    return map;
  },

  /** Update sidebar extracted tab with YARA results. */
  _updateSidebarWithYara(results) {
    if (!this.findings) return;
    // Remove any previous YARA findings
    this.findings.externalRefs = (this.findings.externalRefs || []).filter(r => r.type !== IOC.YARA);
    // Add new YARA findings with severity from rule meta
    const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
    let maxSeverity = null;
    const sevRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

    // Convert YARA's byte offsets → JS char offsets so that downstream
    // highlighting (which works on _rawText char indices) lands on the
    // correct text even when the file contains multi-byte UTF-8 sequences.
    const byteToChar = this._buildYaraByteToCharMap();

    // Build a per-rule "structural finding present?" check: YARA_SUPPRESS_IF_
    // STRUCTURAL is a Map<ruleName, regex>; for each entry, if any existing
    // externalRef's `note` or `url` matches the regex, suppress the YARA rule
    // from the sidebar (it remains visible in the YARA results dialog).
    const refsForMatch = (this.findings.externalRefs || []).filter(r => r && r.type !== IOC.YARA);
    const ruleHasStructural = (ruleName) => {
      if (typeof YARA_SUPPRESS_IF_STRUCTURAL === 'undefined') return false;
      const re = YARA_SUPPRESS_IF_STRUCTURAL.get(ruleName);
      if (!re) return false;
      return refsForMatch.some(r =>
        (r.note && re.test(r.note)) || (r.url && re.test(r.url))
      );
    };

    for (const r of results) {
      // Suppress YARA rule if its structural equivalent already fired
      if (ruleHasStructural(r.ruleName)) continue;

      const desc = (r.meta && r.meta.description) ? r.meta.description : null;
      const severity = (r.meta && r.meta.severity) ? r.meta.severity.toLowerCase() : 'high';
      const sev = validSeverities.includes(severity) ? severity : 'high';
      const strings = r.matches.map(m => m.id + '=' + m.value).join(', ');

      // `url` is kept as a single flat line so that Markdown summary,
      // clipboard share, STIX / MISP exporters and the search index keep
      // working against the existing `ref.url` contract. The structured
      // `_yaraStrings` / `description` fields below are what the sidebar
      // renderer uses to build the pretty per-string table.
      let text = '';
      if (desc) text += desc + ' \u2014 ';
      text += r.matches.length + ' string(s) matched: ' + strings;

      // Structured per-string list for the sidebar's pretty renderer.
      // One entry per YARA string identifier ($a / $s1 / …), with its
      // matched value and number of hits.
      const yaraStrings = r.matches.map(m => ({
        id: m.id,
        value: m.value,
        hits: (m.matches && m.matches.length) || 0,
      }));

      // Build flat list of all match locations for click-to-highlight.
      //
      // Match offsets that don't translate cleanly into `_rawText`
      // coordinates are *dropped* rather than leaked through as raw byte
      // offsets. The previous fallback (use loc.offset as-is) caused
      // catastrophic mis-highlights on three classes of file:
      //   • CRLF files (every CRLF before the match shifts byte→char by +1)
      //   • Files with multi-byte UTF-8 where the match straddles a glyph
      //   • HTML/SVG/Plist/Scpt augmented-buffer matches whose offset
      //     points into the synthesised `=== RENDERED DOM TEXT ===` /
      //     `=== EXTRACTED … ===` tail that doesn't exist in `_rawText`.
      // The rule itself still appears in the sidebar; only the unmappable
      // *locations* are pruned. If every location for a string fails to
      // map, the click-to-cycle simply finds no matches to scroll to —
      // strictly better than scrolling to an unrelated line.
      const allMatches = [];
      for (const m of r.matches) {
        for (const loc of m.matches) {
          let offset = loc.offset;
          let length = loc.length;
          if (byteToChar) {
            const startChar = byteToChar.get(loc.offset);
            const endChar = byteToChar.get(loc.offset + loc.length);
            if (startChar === undefined || endChar === undefined) {
              // Unmappable — skip this location. See block comment above.
              continue;
            }
            offset = startChar;
            length = endChar - startChar;
          }
          allMatches.push({ offset, length, stringId: m.id, value: m.value });
        }
      }
      allMatches.sort((a, b) => a.offset - b.offset);
      this.findings.externalRefs.push({
        type: IOC.YARA,
        url: text,
        severity: sev,
        description: desc || '',       // exposed for Summary / STIX / MISP
        _yaraRuleName: r.ruleName,
        _yaraCategory: (r.meta && r.meta.category) ? r.meta.category : '',  // drives the sidebar's colour-coded category pill
        _yaraStrings: yaraStrings,     // structured per-string breakdown for the sidebar
        _yaraCondition: r.condition || '',  // raw condition expression for the sidebar's hover-revealed "reason for detection"
        _yaraMatches: allMatches       // For click-to-highlight cycling
      });

      if (!maxSeverity || sevRank[sev] > sevRank[maxSeverity]) maxSeverity = sev;
    }
    // Bump overall risk based on highest YARA severity
    if (results.length > 0) {
      const riskRank = { critical: 4, high: 3, medium: 2, low: 1 };
      const currentRank = riskRank[this.findings.risk] || 1;
      if (maxSeverity === 'critical' && currentRank < 4) escalateRisk(this.findings, 'critical');
      else if (maxSeverity === 'high' && currentRank < 3) escalateRisk(this.findings, 'high');
      else if (maxSeverity === 'medium' && currentRank < 2) escalateRisk(this.findings, 'medium');
    }
    // Re-render sidebar. Use _fileMeta as single source of truth for the
    // filename (legacy #file-info element was replaced by the breadcrumb trail).
    const fileName = (this._fileMeta && this._fileMeta.name) || '';
    this._renderSidebar(fileName, null);
  },

  // ═══════════════════════════════════════════════════════════════════════
  //  Category-info popup (opened from sidebar YARA category pills)
  // ═══════════════════════════════════════════════════════════════════════

  /** Open a plain-English explanation popup for a given YARA category.
   *  Called when the analyst clicks the colour-coded pill on a sidebar
   *  "YARA Match" row. Looks the category up in `_YARA_CATEGORY_INFO`
   *  and renders a small modal with description, MITRE tactic link (if
   *  present), and typical indicators. Unknown categories fall back to
   *  a generic "custom category" explanation. */
  _openYaraCategoryInfo(categoryName) {
    if (!categoryName) return;
    // Close any existing one first so repeated clicks always refresh.
    const existing = document.getElementById('yara-catinfo');
    if (existing) existing.remove();

    const key = String(categoryName).toLowerCase()
      .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    const info = _YARA_CATEGORY_INFO[key];

    // ── Overlay + card ──────────────────────────────────────────────
    const ov = document.createElement('div');
    ov.id = 'yara-catinfo';
    ov.className = 'yara-catinfo-overlay';

    const card = document.createElement('div');
    card.className = 'yara-catinfo-card';

    // ── Header (tinted with the category's palette colour) ───────────
    const hdr = document.createElement('div');
    // Reuse the `.yara-cat-pill-<key>` class on the header so the tint
    // matches the sidebar pill the user clicked — no new palette to
    // maintain.
    hdr.className = 'yara-catinfo-header yara-cat-pill yara-cat-pill-' + key;

    const hdrPill = document.createElement('span');
    hdrPill.className = 'yara-catinfo-pill';
    hdrPill.textContent = categoryName;
    hdr.appendChild(hdrPill);

    const hdrSub = document.createElement('span');
    hdrSub.className = 'yara-catinfo-sub';
    if (info && info.tactic) {
      hdrSub.textContent = 'MITRE ATT&CK \u2014 ' + info.tactic.id + ' ' + info.tactic.name;
    } else if (info) {
      hdrSub.textContent = 'Threat class';
    } else {
      hdrSub.textContent = 'Custom category';
    }
    hdr.appendChild(hdrSub);

    const closeBtn = document.createElement('button');
    closeBtn.className = 'yara-catinfo-close';
    closeBtn.type = 'button';
    closeBtn.textContent = '\u2715';
    closeBtn.title = 'Close (Esc)';
    hdr.appendChild(closeBtn);
    card.appendChild(hdr);

    // ── Body ─────────────────────────────────────────────────────────
    const body = document.createElement('div');
    body.className = 'yara-catinfo-body';

    const descP = document.createElement('p');
    descP.className = 'yara-catinfo-desc';
    if (info && info.description) {
      descP.textContent = info.description;
    } else {
      descP.textContent = 'This is a rule-author-defined category (' + categoryName + '). '
        + 'It has no built-in Loupe explanation, but typically groups rules that share a '
        + 'common analytical theme set by whoever wrote the rule.';
    }
    body.appendChild(descP);

    // MITRE link block — plain `<a target="_blank">` is CSP-safe because
    // the CSP only blocks fetch / script / img / connect, not navigation.
    if (info && info.tactic) {
      const tacBlock = document.createElement('div');
      tacBlock.className = 'yara-catinfo-tactic';

      const tacLabel = document.createElement('span');
      tacLabel.className = 'yara-catinfo-tactic-label';
      tacLabel.textContent = 'ATT&CK tactic';
      tacBlock.appendChild(tacLabel);

      const tacLink = document.createElement('a');
      tacLink.href = info.tactic.url;
      tacLink.target = '_blank';
      tacLink.rel = 'noopener noreferrer';
      tacLink.className = 'yara-catinfo-tactic-link';
      tacLink.textContent = info.tactic.id + ' \u00b7 ' + info.tactic.name + ' \u2197';
      tacBlock.appendChild(tacLink);

      body.appendChild(tacBlock);
    }

    // Typical indicators list.
    if (info && Array.isArray(info.indicators) && info.indicators.length) {
      const h = document.createElement('h5');
      h.className = 'yara-catinfo-indicators-heading';
      h.textContent = 'Typical indicators';
      body.appendChild(h);

      const ul = document.createElement('ul');
      ul.className = 'yara-catinfo-indicators';
      for (const ind of info.indicators) {
        const li = document.createElement('li');
        // `ind` may contain backtick-wrapped code spans — render them as
        // <code> without allowing arbitrary HTML.
        const parts = String(ind).split('`');
        for (let i = 0; i < parts.length; i++) {
          if (i % 2 === 0) {
            if (parts[i]) li.appendChild(document.createTextNode(parts[i]));
          } else {
            const codeEl = document.createElement('code');
            codeEl.textContent = parts[i];
            li.appendChild(codeEl);
          }
        }
        ul.appendChild(li);
      }
      body.appendChild(ul);
    }

    card.appendChild(body);
    ov.appendChild(card);

    // ── Dismiss handlers ─────────────────────────────────────────────
    const dismiss = () => {
      ov.remove();
      document.removeEventListener('keydown', escHandler, true);
    };
    const escHandler = (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        dismiss();
      }
    };
    closeBtn.addEventListener('click', dismiss);
    ov.addEventListener('click', (e) => { if (e.target === ov) dismiss(); });
    document.addEventListener('keydown', escHandler, true);

    document.body.appendChild(ov);
  },

});

