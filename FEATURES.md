# Loupe — Feature Reference

> What Loupe shows you, one format at a time. The user manual.
>
> - Quick overview → [README.md](README.md)
> - Threat model & vulnerability reporting → [SECURITY.md](SECURITY.md)
> - Build instructions, architecture, and contributor conventions → [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 📑 Contents

- [Supported Formats](#-supported-formats)
- [Security Analysis](#-security-analysis)
- [Timeline](#-timeline)
- [User Interface](#-user-interface)
- [Exports](#-exports)

Sample files for every supported format, with a guided tour, are in [`examples/README.md`](examples/README.md).

---

## 🛡 Supported Formats

Extensionless and renamed files are auto-routed via magic-byte sniff, extension match, and text-head sniff — so a mislabelled file still lands on the right renderer.

| Category | Extensions |
|---|---|
| **Office (modern)** | `.docx` `.docm` `.xlsx` `.xlsm` `.pptx` `.pptm` `.ods` |
| **Office (legacy)** | `.doc` `.xls` `.ppt` |
| **OpenDocument** | `.odt` (text) · `.odp` (presentation) |
| **RTF** | `.rtf` — text extraction + OLE/exploit analysis |
| **Document attack vectors** | `.iqy` (Internet Query — phishing-pulled URL → worksheet) · `.slk` (SYLK — DDE-injection / formula attack vector) · `.xsl` `.xslt` (XSLT — T1220 SquiblyTwo signed-binary proxy execution via wmic.exe / msxsl.exe) — Excel-readable script-like formats abused as macro-warning bypass |
| **PDF** | `.pdf` |
| **Email** | `.eml` `.msg` |
| **HTML** | `.html` `.htm` `.mht` `.mhtml` `.xhtml` — sandboxed preview + source view |
| **Archives** | `.zip` `.gz` `.gzip` `.tar` `.tar.gz` / `.tgz` `.rar` `.7z` `.cab` |
| **Folders** | Drop a directory (or several) onto the drop-zone, multi-select files in the picker, or use the open-folder picker — Loupe synthesises a single tree-view root and per-leaf drill-down works the same way archive entries do. Capped at 4 096 entries with a visible truncation row; analysis stays foreground-on-click. |
| **Disk images** | `.iso` `.img` — ISO 9660 filesystem listing; click any entry to extract and re-analyse |
| **OneNote** | `.one` — embedded object extraction + phishing detection |
| **Windows** | `.lnk` · `.hta` · `.url` `.webloc` `.website` · `.scf` (Explorer command — T1187 forced authentication) · `.library-ms` `.searchConnector-ms` (Library / Search Connector — T1187) · `.mof` `.mfl` (WMI schema — T1546.003 Event Subscription persistence) · `.reg` · `.inf` · `.sct` · `.msi` · PE executables (`.exe` `.dll` `.sys` `.scr` `.cpl` `.ocx` `.drv` `.com`) · `.xll` (Excel add-in DLL) · `.application` `.manifest` (ClickOnce) · `.msix` `.msixbundle` `.appx` `.appxbundle` · `.appinstaller` |
| **Browser extensions** | `.crx` (Chrome / Chromium / Edge) · `.xpi` (Firefox / Thunderbird) |
| **npm packages** | `.tgz` (npm-packed tarball) · `package.json` · `package-lock.json` / `npm-shrinkwrap.json` |
| **Linux / IoT** | ELF binaries — `.so`, `.o`, `.elf`, extensionless executables (ELF32 / ELF64, LE/BE) |
| **macOS (binaries)** | Mach-O — `.dylib`, `.bundle`, extensionless executables, Fat/Universal (32/64-bit) |
| **macOS (scripts)** | `.applescript` `.scpt` `.scptd` `.jxa` — source + compiled bytecode, highlighted |
| **macOS (system)** | `.plist` (XML and binary) — interactive tree view |
| **macOS (installers)** | `.dmg` `.pkg` `.mpkg` |
| **Certificates** | `.pem` `.der` `.crt` `.cer` · `.p12` `.pfx` (PKCS#12) |
| **OpenPGP** | `.pgp` `.gpg` `.asc` `.sig` — ASCII-armored & binary packet streams; `.key` auto-disambiguated against X.509 |
| **Java** | `.jar` `.war` `.ear` · `.class` |
| **WebAssembly** | `.wasm` — sections / imports / exports / memory parsed; suspicious WASI and JS-bridge imports plus cryptominer / keylogger exports flagged; `modulehash` (SHA-256 over normalised import vector) for cluster pivoting. |
| **Packet captures** | `.pcap` `.pcapng` `.cap` — Timeline view (Wireshark-style 9-column grid: `No. / Time / Source / Src Port / Destination / Dst Port / Protocol / Length / Info`) up to 1 M packets; auto Geo / ASN enrichment on both `Source` and `Destination` columns |
| **Scripts** | `.wsf` `.wsc` `.wsh` (parsed) · `.vbs` `.ps1` `.bat` `.cmd` `.js` |
| **Logs** | `.evtx` (Windows Event Log — binary EVTX parser) · `.log` (Apache CLF default + syslog / Zeek / JSONL / CEF / LEEF / logfmt / Apache error sniff) · `.cef` `.leef` |
| **Data** | `.csv` `.tsv` · `.json` `.ndjson` `.jsonl` (array-shaped → tabular grid) · `.sqlite` `.db` (Chrome / Firefox / Edge history auto-detect) |
| **Images** | `.jpg` `.jpeg` `.png` `.gif` `.bmp` `.webp` `.ico` `.tif` `.tiff` `.avif` — preview + steganography / polyglot detection |
| **SVG** | `.svg` — sandboxed preview + source view, deep SVG-specific security analysis |
| **Catch-all** | *Any file* — line-numbered text view (encoding auto-detect, 35-language syntax highlighting via vendored highlight.js v11.9.0 covering bash / sh / zsh / batch / cmd / PowerShell / JavaScript / TypeScript / Python / Perl / PHP / Ruby / Lua / Go / Rust / C / C++ / C# / Swift / Kotlin / Objective-C / Visual Basic / Java / Scala / R / SQL / Markdown / YAML / TOML / JSON / XML / HTML / CSS / SCSS / Less / GraphQL / Dockerfile / Makefile / diff / properties; toggle in the toolbar, soft-wraps minified single-line files) or hex dump for binary data |

---

## 🔬 Security Analysis

### Cross-cutting

| Capability | What you get |
|---|---|
| **Risk assessment** | Colour-coded risk bar (low / medium / high / critical) with a finding summary. |
| **YARA rule engine** | 500+ default rules covering scripts, documents, binaries, archives, and network indicators; auto-scans every file on load. Drag any `.yar` file onto Loupe to extend detection — rules are validated, saved locally, and rescans are instant. |
| **File hashes** | MD5, SHA-1, SHA-256 computed in-browser with one-click VirusTotal lookup. |
| **Document search** | In-toolbar search with match highlighting, match counter, `Enter`/`Shift+Enter` navigation (`F` to focus). |
| **Recursive deobfuscation** | Peels nested Base64 / hex / Base32 / gzip / zlib / deflate / single-byte XOR layers and PowerShell / JavaScript / Bash / Python / PHP obfuscation shapes (variable indirection, string-array lookups, `String.fromCharCode` chains, token-spaced and concat-split identifiers, `${V:N:M}` parameter slicing, ANSI-C `$'\xNN'` quoting, `$(curl…\|sh)` pipe-to-shell, `eval(zlib.decompress(b64))` / `eval(marshal.loads(...))` Python carriers, `eval(gzinflate(base64_decode(...)))` PHP webshell decoder onions, p.a.c.k.e.r / aaencode / `Function(atob('...'))()` JS wrappers). The sidebar shows the full nested-payload tree with hop pills and per-layer size deltas. |
| **Decoded-payload YARA gate** | Every retained decoded layer is re-scanned against rules tagged `applies_to = "decoded-payload"`. Matches surface as evidence chips on the encoded-content card. Additive only — never removes findings; bypassed in bruteforce mode. |
| **Decode selection** | Click-drag any text in a content viewer to surface a floating **🔍 Decode selection** chip — pipes the highlighted bytes through an aggressive variant of the deobfuscator (lower thresholds, deeper recursion, multi-byte XOR brute-force, interleaved-separator decoder). |
| **Document metadata** | Author, title, dates, revision count extracted from `docProps/core.xml` (and equivalents). |

### IOC extraction

| Capability | What you get |
|---|---|
| **Classic IOCs** | URLs, email addresses, IPv4 + IPv6 addresses (compressed, full, and bracketed-with-port; reserved ranges dropped), file paths, UNC paths, registry keys, command lines, hostnames — pulled from document content, VBA source, binary strings, decoded payloads, and format-specific metadata. |
| **Defanged-indicator refanging** | `hxxp://`, `1[.]2[.]3[.]4`, and similar obfuscations are refanged automatically before extraction. |
| **Obfuscated-URL deobfuscation** | URLs hiding behind inline `\uXXXX` / `\xHH` escapes, percent-encoded host/path bytes, or `inet_aton`-shape numeric hosts (integer, hex, octal, dotted-mixed) are normalised to their canonical form and emitted alongside the original — the decoded host also surfaces as a sibling IP IOC for GeoIP enrichment. |
| **Registrable-domain pivots** | Every extracted URL auto-emits a sibling registrable domain (via the public-suffix list) so you get a domain-level pivot without double-entering the URL. |
| **Punycode & IDN homograph flags** | URL hosts in punycode (`xn--`) or mixed-script IDN form emit a sibling Hostname IOC with the decoded Unicode label so homograph lookalikes surface in plain sight. |
| **Trojan Source / bidi unicode flags** | Flags Unicode bidi controls (CVE-2021-42574), zero-width characters splitting identifiers, and mixed-script Latin / Cyrillic / Greek identifiers — each emits a medium Pattern row with the offending codepoint. |
| **Crypto / dark-web / IPFS addresses** | Detects BTC (legacy P2PKH/P2SH and bech32 / taproot), ETH and other EVM-chain addresses, Monero (standard + integrated), Tor onion v3 hostnames, and IPFS CIDv0 / CIDv1 — each emits a medium Crypto Address IOC with the variant in the note for STIX / MISP / CSV pivot. |
| **Exposed credentials** | Flags AWS access key IDs (AKIA / ASIA / AGPA / AROA / AIDA), GitHub tokens (`ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` / `github_pat_`), Slack bot/app/user tokens, Stripe live secret + restricted keys, Google API keys, eight PEM private-key armours (RSA / DSA / EC / DH / OPENSSH / PGP / PRIVATE / ENCRYPTED), and JWTs — each emits a high-severity Secret IOC (JWT downgraded to medium) which escalates `findings.risk` automatically. |
| **Abuse-TLD & dynamic-DNS flags** | URLs pointing at dynamic-DNS suffixes and high-abuse TLDs (`.tk`, `.gq`, `.ml`, `.cf`, `.xyz`, `.top`, DuckDNS, no-ip, ngrok, trycloudflare, …) auto-emit a Pattern row with the suffix. |
| **GUID pivots** | LNK DROID file/volume IDs, MSI ProductCodes, PDF XMP DocumentID / InstanceID, Mach-O LC_UUID. |
| **Fingerprint pivots** | X.509 SHA-1 / SHA-256 thumbprints and OpenPGP key fingerprints / key IDs. |
| **Identity pivots** | Usernames (document author, PDF `/Author`, MSI Author / Last Author, EML/MSG creator) and MAC addresses (LNK TrackerDataBlock). |
| **Image-metadata pivots** | EXIF GPS coordinates, camera serial numbers, software/firmware strings, XMP DocumentID / InstanceID, full XMP tree. |
| **Nicelist demotion** | IOCs matching a "known-good" nicelist are dimmed and sorted to the bottom of the sidebar with an optional "Hide" toggle; never affects Detections. Ships with a curated **Default Nicelist** (global infrastructure, package registries, CA/OCSP, XML schemas) plus unlimited user-defined lists (MDR customer domains, employee emails, on-network assets) managed from ⚙ Settings → 🛡 Nicelists with CSV/JSON/TXT import + export. |

### Documents & Office

| Capability | What you get |
|---|---|
| **VBA / macro analysis** | Extracts and syntax-highlights VBA source; flags auto-execute entry points (`AutoOpen`, `Workbook_Open`, `Shell`, etc.). Download decoded VBA as `.txt`, or the raw `vbaProject.bin` for offline analysis with olevba / oledump. |
| **VBA stomping (T1564.007)** | Heuristic flag when a VBA project carries compiled P-code (`_VBA_PROJECT`) but no source-module markers (`Attribute VB_`) — covers both legacy `.doc`/`.ppt` and OOXML `.docm`/`.xlsm`/`.pptm`. |
| **OOXML relationship scan** | Deep walk of `_rels/*.rels` — surfaces external targets, remote-template injection (`attachedTemplate`), and embedded `oleObject` references that classic metadata extraction misses. |
| **OOXML DDE / field code analysis** | Field-code walker flags `DDEAUTO`, `DDE`, `INCLUDETEXT`, `INCLUDEPICTURE`, `IMPORT`, `QUOTE` in `w:instrText` / `w:fldSimple`; extracts URLs from field codes. |
| **OOXML custom property scanning** | Iterates `docProps/custom.xml` property values for stashed URLs, IP addresses, and Base64 blobs — a common second-stage hiding spot scanners miss. |
| **Excel formula scan** | Per-cell formula walker flags `WEBSERVICE`, `IMPORTDATA`, `CALL`, `REGISTER`, `EXEC`, `HYPERLINK`, `RTD`, `DDE` — catches formula-only droppers in pure `.xlsx` without needing macros. |
| **Excel external connections** | Parses `xl/connections.xml` for OLEDB / ODBC / web / text connections; surfaces remote `odcFile` references, web-query URLs, and `Data Source=` URLs from `connectionString`. `refreshOnLoad="1"` escalates one severity rank — open-and-execute bypass of the macro warning. |
| **Power Query DataMashup** | Detects M-language scripts embedded in `xl/customXml/item*.xml`; extracts `Web.Contents` / `File.Contents` URL and UNC references from the envelope. M code runs on workbook refresh without macro consent. |
| **Hidden sheets & Auto_Open names** | Surfaces `hidden` / `veryHidden` sheet states and `Auto_Open` / `Workbook_Open` / `Auto_Close` defined names — the classic Excel 4.0 macro trigger that still works today. |
| **PDF detection** | Flags `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, URIs, XFA forms, XMP metadata, and other risky operators via YARA. Surfaces `Movie` / `Sound` / `Screen` / `FileAttachment` / `RichMedia` / `3D` annotations and restrictive permission flags. |
| **PDF AcroForm credential sniff** | Form-field names matching `pass` / `pwd` / `ssn` / `cvv` / credential regex push a medium Pattern so weaponised pre-filled forms can't hide as benign templates. |
| **PDF extraction** | Pulls JavaScript bodies from `/JS` actions (literal, hex, and indirect-stream with `/FlateDecode`) with per-script trigger, size, SHA-256, and suspicious-API hints; extracts `/EmbeddedFile` attachments (recursively analysable in-place); extracts XFA form packets. |
| **EML / email analysis** | Full RFC 5322 / MIME parser — headers, multipart body, attachments, SPF / DKIM / DMARC auth results, tracking pixel detection. |
| **Phishing pretext detection** | EML and MSG flag display-name / sender-domain mismatch against a curated brand list (PayPal, Microsoft, Apple, banks, shippers, …) — catches the "PayPal Support &lt;attacker@evil.tld&gt;" pattern; also fires when the display-name embeds a domain literal that disagrees with the actual sender domain. |
| **OneNote analysis** | FileDataStoreObject parsing with MIME-sniffed embedded blobs, phishing-lure detection. |
| **RTF analysis** | Text extraction plus OLE-object and exploit-pattern detection. |

### Windows

| Capability | What you get |
|---|---|
| **LNK inspection** | MS-SHLLINK binary parser — target path, arguments, hotkey, shell-item chain, full ExtraData blocks, timestamps, dangerous-command detection, UNC credential-theft patterns, TrackerDataBlock machine-ID + MAC. Every path/argument surfaces as its own sidebar IOC. |
| **HTA analysis** | Script extraction, `<HTA:APPLICATION>` attribute parsing, obfuscation detection, 40+ suspicious-pattern checks, stealth-window combination detection (YARA). |
| **MSI analysis** | CustomAction row parsing, Binary stream magic-sniffing, embedded CAB detection, Authenticode verdict, clickable stream drill-down, lazy stream loading to avoid memory crashes on huge installers. |
| **ClickOnce** | Parses `.application` / `.manifest` — assembly identity, deployment codebase, entry point, trust info, signature subject + thumbprint, dependent assemblies. Flags AppDomainManager hijacking, plain-HTTP deployment, FullTrust requests, and disposable-infrastructure dependencies. |
| **MSIX / APPX / App Installer** | Parses `.msix` / `.msixbundle` / `.appx` / `.appxbundle` packages and standalone `.appinstaller` XML — identity, capabilities (tiered), applications, entry points, and extensions (full-trust process, startup task, app-execution alias, protocol, COM, background tasks). Verifies the package signer against the manifest's Publisher — a mismatch means the package was re-signed / repackaged. Flags silent auto-updates and suspicious update URIs. Inner files are clickable for recursive analysis. |

### Native binaries (PE / ELF / Mach-O)

| Capability | What you get |
|---|---|
| **Triage banner** | Above-the-fold verdict band on every PE / ELF / Mach-O view: one-line human verdict (e.g. *"Unsigned PE32+ DLL · UPX-packed · orphan EP · 40 KB overlay · 8 capabilities"*), coloured risk tier, risk score, and a short row of severity-coloured anomaly chips (orphan EP, W+X section, packed, RWX segment, exec-stack, ad-hoc-signed, dangerous entitlements …). Related detail cards auto-expand when a chip fires. Identical layout across the three formats. |
| **Pivot card** | Below the banner, a hash-and-attribution summary: file hashes, import-shape hash (imphash / telfhash / SymHash), RichHash, signer or "unsigned", compile timestamp with "faked?" detection, entry-point anomalies, overlay presence, packer verdict, plus optional team-ID / bundle-ID / build-ID / CLR runtime / SDK MinOS. |
| **Headers, sections, imports, exports** | PE32 / PE32+ headers, COFF, optional header, data directories, section table with entropy, imports with flagged suspicious APIs, exports, resources, Rich header, string extraction. ELF32 / ELF64 (LE/BE) headers, segments, sections, dynamic linking, symbol tables with suspicious-symbol flagging, note sections. Mach-O 32/64-bit and Fat/Universal header, load commands, segments with section-level entropy, symbol tables, dynamic libraries, RPATH, code signature and entitlements. |
| **Security features** | PE: ASLR, DEP, CFG, SEH, Authenticode. ELF: RELRO, Stack Canary, NX, PIE, FORTIFY_SOURCE. Mach-O: PIE, NX, Stack Canary, ARC, Hardened Runtime, Library Validation, Encrypted. |
| **MITRE ATT&CK rollup** | Capabilities, anomalies, and signer checks that carry a technique ID are grouped by tactic (Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → …) in a dedicated sidebar section and in the Summarize output, with clickable `attack.mitre.org` links per technique. |
| **Capability tagging** | Behavioural clusters flagged across PE / ELF / Mach-O with MITRE ATT&CK IDs: process injection, reverse shell, keylogging, credential theft, persistence, anti-debug, crypto/ransomware, network C2. |
| **LOLBAS → ATT&CK** | Bundled lookup for ~30 high-signal Living-Off-The-Land binaries (mshta, rundll32, regsvr32, certutil, msbuild, wmic, msxsl, hh, msdt, …) returning the canonical T1218.* / T1059.* / T1105 / T1220 / T1127 sub-techniques for any renderer that surfaces a Windows command-line. |
| **YARA coverage** | Rules for packers and malware toolkits across the three formats: Cobalt Strike, Mimikatz, Metasploit (PE); Mirai, cryptominers, reverse shells, LD_PRELOAD hijacking, rootkits, container escapes, packers (ELF); Atomic / AMOS stealers, RATs, reverse shells, persistence, anti-debug / VM detection (Mach-O). |
| **TLS callbacks + entry-point anomalies (PE)** | Lists every TLS callback with clickable hex-dump drill-down; flags anomalous entry points (orphan, W+X section). Callbacks paired with anti-debug imports escalate severity (T1546.009). |
| **Resource drill-down (PE)** | Lists every PE resource leaf with size and magic sniff. Clickable entries open in a fresh analysis. Embedded PE / ELF / Mach-O payloads flag as T1027.009 (high); embedded archives flag as medium; large high-entropy blobs flag as T1027.002. |
| **.NET CLR detection (PE)** | Managed .NET assemblies are recognised and surfaced with a dedicated **🔷 .NET CLR Header** card showing runtime version, IL-only / mixed-mode / strong-name flags, and entry-point. Mixed-mode (C++/CLI) assemblies are flagged separately. |
| **Export-anomaly flags** | Library exports are checked for: **DLL side-loading hosts** (basename matches a known hijack target like `version.dll` — flagged high, T1574.002); **forwarded / proxy-DLL exports** (non-platform forwarders flagged medium); **ordinal-only exports** (mostly nameless exports flagged as packer / loader tell, T1027). |
| **Binary pivot hashes** | PE imphash + RichHash, ELF telfhash-style import hash, Mach-O SymHash — cross-sample clustering pivots surfaced as clickable IOC hashes for VT / Malpedia lookup. |
| **Overlay drill-down** | Bytes appended past the declared end of the binary are surfaced as an Overlay card with size, entropy, magic sniff, and SHA-256. Click to re-analyse the overlay as a fresh file. High-entropy unrecognised overlays flag as T1027.002; PE bytes appended past the Authenticode blob flag as T1553.002 (critical). |
| **Categorised binary strings** | Extracted strings classified into mutex names, Windows named pipes, PDB paths, build-tree paths, registry keys, and Rust panic paths — each surfaced as its own sidebar IOC. Mutex names help cluster sibling samples; PDB and Rust-panic paths reveal build-host attribution. |
| **Graceful fallback** | If PE / ELF / Mach-O parsing fails on a truncated or malformed binary, the renderer switches to a strings-plus-hex fallback and keeps the extracted strings wired into the sidebar so IOC extraction, YARA scanning, and recursive decoding still work. |

### macOS scripts, property lists & installers

| Capability | What you get |
|---|---|
| **AppleScript / JXA** | Source files (`.applescript`, `.jxa`) with full syntax highlighting; compiled `.scpt` binaries mined for strings and embedded source; macOS-specific flags for `do shell script`, `display dialog`, `with administrator privileges`, and similar dangerous patterns. |
| **Property lists** | Parses both XML and binary plist into an interactive tree view — expandable nested structures, LaunchAgent / LaunchDaemon detection, persistence keys, suspicious URL schemes, privacy-sensitive entitlements. |
| **DMG (Apple Disk Image)** | Enumerates partitions, detects encrypted envelopes, and extracts embedded `.app` bundle paths even when full filesystem walking isn't possible. |
| **PKG (flat installer)** | Parses xar TOC + `Distribution` / `PackageInfo` XML; clickable entry drill-down; flags dangerous install-time script names (`preinstall`, `postinstall`, `preflight`, `postflight`, `InstallationCheck`, `VolumeCheck`). |
| **ZIP-wrapped `.app` bundles** | The ZIP listing also surfaces embedded macOS `.app` bundles — each bundle root is emitted as its own IOC, and hidden bundles (leading-dot dirs), unsigned bundles (no `_CodeSignature/`), and multi-bundle ZIPs are flagged high-severity. |
| **macOS installer detection** | YARA rules for xar / UDIF magic, encrypted-envelope heuristics, `.app` bundle launchers, hidden bundles. Dangerous install-time scripts (`preinstall`, `postinstall`, etc.) are flagged. |

### Browser extensions

| Capability | What you get |
|---|---|
| **CRX (Chrome / Chromium / Edge)** | Parses both v2 and v3 envelopes; derives the canonical Chrome extension ID, decodes declared-vs-computed IDs and flags mismatches, surfaces RSA-SHA256 / ECDSA-SHA256 signature counts, flags malformed or empty headers. |
| **XPI (Firefox / Thunderbird)** | Plain ZIP; parses WebExtension `manifest.json` or legacy `install.rdf`. |
| **Manifest analysis (MV2 & MV3)** | Name / version / ID / author / update URL / CSP / Key; MV3 service worker vs MV2 background scripts; content scripts with matched URL patterns; permissions tiered by risk (high: `nativeMessaging`, `<all_urls>`, `debugger`, `proxy`; medium: `cookies`, `history`, `management`, `webRequest` + `webRequestBlocking`, `declarativeNetRequest`, `tabCapture`, …); `externally_connectable`, `web_accessible_resources`, `content_security_policy` (flags `unsafe-eval` / `unsafe-inline` / remote script hosts); `chrome_url_overrides`; `update_url` off-store detection. |
| **Extension YARA coverage** | Rules for native-messaging bridges, broad host permissions, unsafe-eval CSP, wide externally-connectable, debugger / management APIs, proxy + cookies / history combos, non-store update URLs, legacy XUL bootstrap, wide `web_accessible_resources`, in-script `eval`. |
| **Inner-file drill-down** | Manifest, scripts, icons are clickable for recursive analysis. |

### npm packages

Accepts three input shapes — an `npm pack` gzip tarball (`.tgz`), a bare `package.json` manifest, or a `package-lock.json` / `npm-shrinkwrap.json`.

| Capability | What you get |
|---|---|
| **Manifest view** | Name / version / description / license / author / repository / homepage / bugs URL, declared entry points (`main`, `module`, `types`, `exports` map, `bin` targets), `engines`, publishConfig registry, `files` allowlist, workspaces. |
| **Lifecycle hook analysis** | Per-hook rows for `preinstall` / `install` / `postinstall` / `preuninstall` / `postuninstall` / `prepare` / `prepublish` / `postpublish`, each with severity. Hook script bodies are scanned by YARA so malicious patterns surface as detections. |
| **Dependency walk** | `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`, `bundledDependencies` listed per group; each package name is emitted as a clickable Package Name IOC. Non-registry `resolved` URLs (git / tarball / file / HTTP) are flagged. |
| **Lockfile scan** | `package-lock.json` / `npm-shrinkwrap.json` walked for `resolved` integrity, git-commit / tarball / filesystem / plain-HTTP sources, and mismatched registry hosts; each resolved package surfaces as its own IOC row. |
| **Permission & surface signals** | Plain-HTTP repository / bugs / homepage URLs, non-official `publishConfig.registry`, shell-wrapper `bin` targets, native `binding.gyp` / `.node` artefacts, dependency-count outliers, and entry-point outliers are flagged. |
| **npm YARA coverage** | Rules for lifecycle-hook downloaders, hook `eval` / `child_process` chains, repo-exfil / bundle-stealer staging, `.npmrc` token exfil, env-var / wallet / clipboard harvesting, webhook beacons, obfuscated code, native-binary droppers, typosquat lookalike strings, bin shell-wrappers, lockfile non-registry `resolved`. |
| **Inner-file drill-down** | For `.tgz` tarballs the archive browser lists every `package/*` entry; click any file to re-analyse it (manifest → JSON viewer, JS → script analysis, etc.). |

### Crypto

| Capability | What you get |
|---|---|
| **X.509** | Parses PEM / DER certificates and PKCS#12 containers — subject / issuer DN, validity with expiry status, public key details (algorithm, key size, curve), extensions (SAN, Key Usage, EKU, Basic Constraints, AKI / SKI, CRL DP, AIA, Certificate Policies), serial, signature algorithm, SHA-1 / SHA-256 fingerprints. Flags self-signed, expired / not-yet-valid, weak keys (<2048-bit RSA), weak signature algorithms (SHA-1 / MD5), long validity periods, missing SAN, embedded private keys. IOC extraction from SANs and CRL / AIA URIs. |
| **OpenPGP** | Parses ASCII-armored and binary data (RFC 4880 / RFC 9580) — packets, key IDs, fingerprints, User IDs + embedded emails, subkeys, self-signatures, subkey bindings; public-key algorithm (RSA / DSA / ECDSA / ECDH / EdDSA / X25519 / Ed25519), key size, ECC curve; validates ASCII-armor CRC-24. Flags unencrypted secret keys, weak key sizes, deprecated algorithms (Elgamal-sign-or-encrypt, v3 legacy), revoked / expired / long-lived keys, SHA-1 as preferred hash. Parse-only — no signature verification or secret-key decryption. |

### Scripts, Java, web & images

| Capability | What you get |
|---|---|
| **Script scanning** | `.vbs`, `.ps1`, `.bat`, `.js`, `.cmd`, `.sh`, `.py`, `.pl`, `.php`, `.rb`, `.lua`, and similar standalone script types are scanned for dangerous execution patterns alongside full YARA matching covering PowerShell, JScript, VBS, CMD, Bash (10 rules: `/dev/tcp` reverse-shell, bashrc / cron / sudoers / SSH-key persistence, IFS reassembly, heredoc-exec, dd pipe-to-shell, env -i masking), Python, and PHP (4 rules: webshell decoder onion, eval-superglobal one-liners, `preg_replace /e` modifier, variable-variables). Source is syntax-highlighted. |
| **JAR / Java** | Parses JAR / WAR / EAR archives and standalone `.class` files — MANIFEST.MF with Main-Class and permissions, class listing with package tree, dependency extraction, suspicious Java API pattern flagging (deserialization, JNDI, reflection, command execution, networking) mapped to MITRE ATT&CK. Obfuscation detection (Allatori, ZKM, ProGuard). Clickable inner file extraction. |
| **SVG security analysis** | `<script>` extraction, `<foreignObject>` detection (credential forms, password fields, embedded HTML), event handler scanning, Base64 / data URI payload analysis, SVG-specific vectors (`<use>` external refs, `<animate>` href manipulation, `<feImage>` external filters), XML entity / DTD / XXE detection, JavaScript obfuscation patterns. |
| **HTML phishing detection** | Cross-origin forms with password fields flagged critical; ClickFix / fake-captcha pattern detection (clipboard API + payload keywords + instructional text, T1204.001); data-URI iframe / embed / object smuggling detection. |
| **Image analysis** | Steganography indicators for JPEG / PNG / GIF / BMP (appended data past format terminators), polyglot detection, hex header inspection; EXIF field payload scanning (Base64 / PE magic / script patterns in UserComment, ImageDescription, etc.); PNG tEXt / iTXt / zTXt chunk scanning with non-standard keyword flagging and payload detection; embedded-thumbnail extraction; expanded EXIF coverage — MakerNote, ICC profile, UserComment, Interop, IFD1 tag groups. |
| **QR-code decoding** | Images, PDF pages, SVG embedded rasters, OneNote embedded images, and EML image attachments are scanned for QR payloads — decoded URL / Wi-Fi / OTP contents emitted as IOCs ("quishing" defence). |
| **TIFF tag metadata** | Full IFD walk surfacing ImageDescription, Make / Model, Software / DateTime, Artist / HostComputer, Copyright, XMP, IPTC — the tag numbers most commonly abused as covert channels. |

### Archive drill-down

Click any entry inside a ZIP / TAR / ISO / MSI / PKG / CRX / XPI / JAR / CAB listing to open and re-analyse it with Back navigation. ZipCrypto-encrypted entries get a lock icon; unsupported formats fall back to a hex dump but still feed YARA and IOC scanning.

ZIP listings additionally surface per-entry risk signals classic archive viewers hide: archive-level and per-entry `.comment` fields, Unix permission bits (suid / sgid / world-writable = medium), zip-bomb compression ratios (>1000× = high), stale / future mtimes (< 1995 or > 1 year ahead = medium), and Zip Slip / Tar Slip traversal entries (`..` segments, absolute prefixes, or symlink targets escaping the archive root = high, CWE-22).

| Format | What you get |
|---|---|
| **CAB (MSCF)** | Full MS-CAB parser with per-folder compression type detection, split-cabinet detection. Uncompressed and MSZIP entries are clickable for recursive analysis; LZX / Quantum entries are listed but locked (no in-browser decoder). |
| **RAR (v4 / v5)** | Listing-only — both RAR4 fixed-header and RAR5 vuint-encoded blocks are walked to surface file names, sizes, timestamps, solid / multi-volume / encrypted-headers flags, and recovery-record presence. Extraction is not attempted (RAR's LZSS / PPMd compression is proprietary); entries show a lock icon. |
| **7-Zip** | Full file-listing extraction with AES-256 encryption detection. Listing-only — per-file content decompression is not attempted. |
| **Folder (synthetic root)** | Drop a directory, drop multiple files at once, or pick via 📁 — Loupe walks the tree (up to 4 096 entries), bundles it under a synthetic top-level "file", and renders the same archive browser used for ZIP / MSIX / CRX. The dropped folder IS the root — paths inside the tree are relative to it (no redundant `<name>/<name>` nesting), and the tree opens fully expanded on first paint. Each leaf retains its real `File`, so drill-down click → full per-file analysis (YARA + IOC + encoded-content) without re-reading bytes. The folder root itself runs filename-heuristic checks (RTLO `\u202E`, double-extension decoys, ≥3 executables, ≥2 archives) but skips the per-byte sweeps a real archive does — those run organically when you click a leaf. Hard-capped to bound memory; the truncation message lives in the same Signatures & IOCs sidebar as every other finding. |

---

## 📈 Timeline

Every `.csv` / `.tsv` / `.evtx` / `.log` / `.jsonl` / `.ndjson` / `.cef` / `.leef` / `.pcap` / `.pcapng` / `.cap` file — and SQLite browser history databases (Chrome / Edge / Firefox) — opens directly in Timeline: scrubber, stacked-bar chart, virtual grid, and per-column top-value cards on one page. Extensionless drops are routed by magic-byte / text sniff. Generic (non-browser-history) SQLite databases use the tabbed-grid viewer.

`.log` files are dispatched by content sniff. Each format yields a stable column projection so filtering, sorting, and the histogram stack column behave consistently across vendor variants.

| Format | Recognised by | What you see |
|---|---|---|
| **Apache / Nginx access** (Common / Combined Log Format) | bracketed `[date timezone]` token | 9-col Combined / 7-col Common projection |
| **Syslog RFC 3164** | `<PRI>` + `MMM DD HH:MM:SS` header | 7 cols (Timestamp · Severity · Facility · Host · Program · PID · Message); year inferred from file mtime |
| **Syslog RFC 5424** | `<PRI>VER` + ISO 8601 timestamp | 9 cols incl. structured-data block preserved verbatim |
| **Zeek TSV** | `#separator \x09` directive | Per-`#path` schema (e.g. `conn.log` → 18 cols, `dns.log` → 23, `http.log` → 28); view labelled `Zeek (<path>)` |
| **JSONL / NDJSON** | `.jsonl` / `.ndjson` ext or ≥60 % JSON-object lines | Schema locked from first record's flattened keys; late keys spill into `_extra` |
| **AWS CloudTrail** | `eventName` + `eventTime` keys (incl. `{"Records":[…]}` wrapper) | Canonical CloudTrail projection; histogram pinned to `eventName`; service-specific blobs spill into `_extra` |
| **CEF** (ArcSight Common Event Format) | `CEF:0\|` / `CEF:1\|` (syslog wrapper auto-stripped) | 7 header fields + extension `key=value`; covers FortiGate · Palo Alto · Check Point · McAfee · Cisco · Trend Micro · F5 · Imperva · Juniper |
| **LEEF** (IBM Log Event Extended Format) | `LEEF:1.0\|` / `LEEF:2.0\|` (syslog wrapper auto-stripped) | 5 header fields + extension; covers QRadar · Juniper · Trend Micro · McAfee · Symantec · Cisco |
| **logfmt** | flat `key=value` lines (≥60 % of first 5 lines match) | Schema locked from first record; covers Heroku · Logrus · Vault · Consul · Nomad |
| **W3C Extended** | `#Software` / `#Fields:` directive | Dynamic per-`#Fields:` schema; auto-synthesised ISO 8601 `Timestamp` when `date` + `time` are declared. Source label: `IIS W3C` · `AWS ALB` · `AWS ELB` · `AWS CloudFront` · generic `W3C Extended` |
| **Apache `error_log`** | `[Day Mon DD HH:MM:SS YYYY] [module:level]` prefix | 8 cols (Timestamp · Module · Severity · PID · TID · Client · ErrorCode · Message); `AH<5digits>:` codes split out |

### Workflow

| Feature | What you get |
|---|---|
| **Triage toolkit** | Right-click any value → Filter · Exclude · Only-this · 🚩 Mark suspicious. Flagged rows get a red tint and a Suspicious section (chart + grid + top-values) with a red overlay on the main histogram. Chart legend: click = filter, dbl-click = only this, shift-click = exclude. Drag across charts to rubber-band a time window (shift-drag unions, double-click clears). |
| **Query language** | Boolean DSL with `AND` / `OR` / `NOT`, parentheses, per-column filters (`User=alice`, `Cmd~powershell`, `Level>=3`), set membership (`User IN (alice, bob)` / `Host NOT IN (…)`), and bare terms for any-column match. Syntax highlighting, Tab/arrow autocomplete, `↑`/`↓` query history, `Ctrl/⌘-Z` to undo a clear / history pick. 🚩 Sus marks are tracked separately and only tint rows — they never hide them. |
| **Event cursor** | Click any grid row to drop a red vertical cursor on the histogram at that timestamp. `Esc` clears (after closing any open dialog). |
| **Clear filter (Esc Esc)** | Double-tap `Esc` anywhere on the Timeline page to clear the current query. A hint toast confirms the first press; a second toast confirms the clear. |
| **Detections (EVTX)** | Sortable detection table with severity badge, rule description, Event ID (hover for the plain-English summary), channel / category, ATT&CK technique pills (linked to attack.mitre.org), and hit count. Severity summary strip aggregates totals — click any tier pill to filter the table to that severity, click again to clear. "Group by ATT&CK tactic" reorganises rows under tactic headers. Right-click any detection for filter / mark-sus / docs actions. |
| **Entities (EVTX)** | Extracted hosts, users, filenames, processes, hashes, IPs, URLs, UNC paths, registry keys, domains, emails, and command-lines — grouped by IOC type with per-card search / sort-cycle / pin / drag-to-reorder controls mirroring the Top-values cards. Click any entity to pivot. |
| **ATT&CK annotation** | Top-values "Event ID" cards, the EVTX detail drawer, the Detections table, and (where applicable) Entities all surface human-readable Event-ID summaries plus MITRE ATT&CK technique pills from the bundled offline EID → technique map — no network lookups. |
| **⚡ Summarize (EVTX / PCAP)** | Hybrid-Timeline toolbar button that copies a Markdown summary tuned for AI / LLM consumption. |

### Mechanics

| Feature | What you get |
|---|---|
| **Column menu** | Excel-style value checkboxes, "contains" filter, "Use as Timestamp", "Stack chart by this". Every section (chart, grid, top-values, suspicious, pivot) is collapsible and CSV/PNG exportable. |
| **Per-card search & sort** | Each top-value card has its own search box and sort button (count-desc → count-asc → A→Z → Z→A; Alt-click resets). Bar widths stay anchored to global max so filtering never rescales. |
| **Drag-to-reorder cards** | Grab any top-value card header to drag it to a new position. Card order persists per-file across sessions. |
| **Pin cards** | Click the 📌 pin button on any top-value card header to pin it to the top-left of the card grid. Pinned cards get a left accent border; click again to unpin. |
| **Ctrl+Click multi-select → IN filter** | Ctrl+Click (⌘-click on Mac) multiple rows across top-value cards to accumulate selections. On key release, all selected values commit as a single IN filter. Plain click clears pending selections. |
| **ƒx Extract values** | Create virtual columns from URLs, hostnames, JSON leaves, `Key=Value` fields, URL parts (host / path / query), or regex captures. Three-tab dialog: **Smart scan** (ranked proposals with bulk select and live preview), **Regex** (IPv4 / UUID / hash / email / path / PID presets), and **Clicker** (click a token in a sample row → Loupe classifies it, infers an anchored regex, and previews hits live). EVTX pre-selects forensic fields (CommandLine, TargetUserName, ProcessName, …); browser-history `url` columns emit host / path / query proposals. Extractions persist per-file. |
| **🌍 GeoIP + ASN enrichment** | Columns that are ≥80 % IPv4 addresses get up to two automatic companion columns: `<col>.geo` (Country / ISO2, or Country / ISO2 / Region / City with a richer geo MMDB) and `<col>.asn` (Org name and AS number). Lookups are 100 % offline — a bundled IPv4-country binary (≈830 KB, RIR-derived, refreshed monthly) ships inside `loupe.html` itself. ⚙ Settings → "GeoIP database" accepts user-uploaded MaxMind `.mmdb` / `.mmdb.gz` (or DB-IP / IP2Location) files in two independent slots: Geo (Country / City / Region) and ASN. Both are stored locally in IndexedDB and never uploaded. Right-click a column header → 🌍 **Enrich IP** to force enrichment on any column the auto-detector skipped. Reserved / private / multicast / CGNAT ranges are skipped silently. The same providers also enrich every IPv4 IOC elsewhere in Loupe — sidebar IOC rows, the ⚡ Summary report, and the IOC JSON / CSV clipboard exports all carry the geo / ASN fields. |
| **Pivot table** | Rows × Columns × Aggregate (count / count-distinct / sum) with heat colouring. Double-click any cell to drill down; CSV export. Right-click → 🧮 **Auto pivot** to instantly pivot against the chart-stack column. |

---

## 🎨 User Interface

| Feature | What you get |
|---|---|
| **Hosted-mode privacy notice** | When Loupe is served via HTTP/HTTPS (e.g. GitHub Pages) instead of opened locally from `file://`, an amber-tinted drop-zone warning and a floating bar remind you to [download Loupe](https://github.com/Loupe-tools/Loupe/releases/latest/download/loupe.html) for full offline privacy. The bar is dismissable (persisted); the drop-zone tint stays as a gentle reminder. Your files never leave the browser either way. |
| **Six-theme picker** | Light, Dark (default), Midnight OLED, Solarized, Mocha, Latte — chosen from the ◐ Themes tab. Your choice persists and is applied before first paint so you never see a flash of the wrong palette. First-boot users are matched to their OS `prefers-color-scheme`. |
| **Subtle animated backdrop** | Per-theme drop-zone backdrop: an aperiodic Penrose rhombic tiling on Light, a slow wandering-node network on Dark, a whisper-low Penrose tiling on Solarized, floating kittens on Mocha, floating hearts on Latte, and nothing at all on Midnight (pure-black stays pure-black for OLED). The animation is cosmetic only — it lives behind every chrome surface, hides the moment a file loads, and is suppressed entirely under `prefers-reduced-motion`. |
| **Settings / Themes / Nicelists / Help dialog** | `⚙` toolbar button (or `,` Settings, `T` Themes, `N` Nicelists, `?` / `H` Help) — a unified four-tabbed modal. ⚙ Settings carries the Summarize-size picker (Default / Large / Unlimited) and the GeoIP / ASN database row; ◐ Themes is the six-theme tile grid; 🛡 Nicelists toggles the built-in Default Nicelist and manages user-defined custom lists (create / import CSV-JSON-TXT / edit / export / delete); ? Help lists every keyboard shortcut and the offline / release links. |
| **Floating zoom** | 50 – 200 % zoom via a floating control that stays out of the way. |
| **Click-and-drag panning** | Grab and drag to pan around rendered documents. |
| **Resizable sidebar** | Drag the sidebar edge to resize it between 33 % and 60 % of the viewport. |
| **Collapsible sidebar sections** | Single-pane sidebar with collapsible `<details>`: File Info, Macros, Signatures & IOCs. |
| **Breadcrumb navigation** | Drill-down path as a clickable crumb trail (e.g. `📦 archive.zip ▸ 📄 doc.docm ▸ 🔧 Module1.bas`). Overflow `… ▾` dropdown keeps long trails on one line; the close button is anchored so its position never shifts with filename length. |
| **Archive browser** | Shared collapsible / searchable / sortable tree used by every archive-style renderer (ZIP, JAR / WAR / EAR, MSIX / APPX, CRX / XPI, TAR / `.tar.gz`, ISO / IMG, PKG / MPKG, CAB, RAR, 7z). Tree view with child counts and one-click drill-down; flat sortable table view; instant filter box; per-entry risk badges (executable, double-extension, ZipCrypto lock, tar-symlink target). Trees up to 256 entries open fully expanded on first paint; larger archives stay collapsed (use ⤵ Expand all to override). |
| **Keyboard shortcuts** | `Ctrl+Enter` Copy ⚡ Summary to clipboard · `S` sidebar · `Y` YARA dialog · `N` Nicelists · `T` Themes · `,` Settings · `?` / `H` Help · `F` search document · `Ctrl+C` copy raw file (when nothing is selected) · `Ctrl+V` paste file for analysis · `Esc` close dialog / clear search. **Archive browser:** `/` focus filter · `↑ ↓` navigate rows · `← →` collapse / expand folder · `Enter` / `Space` open selected file. |
| **Smart whole-token select** | Double-click in any monospace viewer selects the entire non-whitespace token — expanding past `/ . : = - _` and across visual line wraps — up to the nearest whitespace boundary. Great for URLs, hashes, base64 blobs, file paths, registry keys, PE imports, x509 fingerprints. |
| **Tabular grid (CSV / TSV / EVTX / XLSX / SQLite / JSON-array)** | Fixed-row virtual scroller renders million-row files without stutter. Streaming parse paints the first 1 000 rows immediately and fills the rest in the background with a progress chip. |
| **Row-details drawer** | Click any row to open a resizable right-hand drawer with per-column key/value view; drawer width persists per-browser and can be dragged almost to the full viewport width for wide EventData payloads. A top-bar search box (or `Ctrl+F` while the drawer is focused) smooth-scrolls and highlights matches within the drawer, with `Enter` / `Shift+Enter` to cycle hits and `Esc` to clear. JSON cells render as a first-class collapsible tree — every node has a ＋ pick button that promotes the leaf (or subtree) to a new virtual column in the grid. |
| **Column header menu** | Click any column header for Sort asc / desc / clear, Copy column (tab-separated to clipboard), Hide column, **Show hidden columns…** (when any are hidden), and **Top values…** — a mini bar chart of the 50 most frequent values with one-click filter-to-value. **Ctrl+Click** (or ⌘-click) any header is a shortcut for Hide; a `⊘ N hidden` chip in the filter bar lets you re-reveal them one-by-one or all at once. |
| **Drag-to-reorder columns (Timeline)** | Grab any column header in the Timeline grid and drag it to a new position; a 2 px accent-coloured bar shows the drop slot. The arrangement persists per-file. Sort, hide, top-values, GeoIP / ASN enrichment, and right-click filters all use the original column index, so behaviour stays stable regardless of the visible order. |
| **Malformed-row ribbon** | CSV / TSV parses flag rows with wrong cell counts or unbalanced quotes; the filter bar shows a ⚠ count chip with Next (jump to next malformed row) and Filter (show only malformed rows) buttons. |
| **Loading overlay** | Spinner with status message while parsing large files. |
| **Toast notifications** | Non-intrusive feedback for downloads, clipboard operations, and errors. |
| **Click-to-highlight** | Clicking any IOC or YARA match in the sidebar jumps to (and cycles through) matching occurrences in the viewer with yellow / blue `<mark>` highlights. |
| **Forensic-safe email links** | `<a href>` inside EML / MSG messages is rendered as an inert span — the visible anchor text and underlying URL (exposed as a hover tooltip) stay inspectable, but clicking does nothing. You can read and copy a phishing URL with zero risk of accidental navigation. |

<table align="center">
  <tr>
    <td align="center" width="25%">
      <img src="screenshots/settings.png" alt="Settings tab — Summarize target picker and GeoIP / ASN database row" width="240"><br>
      <sub><b>⚙ Settings tab</b> — Summarize target + GeoIP / ASN database.</sub>
    </td>
    <td align="center" width="25%">
      <img src="screenshots/themes.png" alt="Themes tab — six-theme tile grid" width="240"><br>
      <sub><b>◐ Themes tab</b> — six-theme tile grid with live preview swatches.</sub>
    </td>
    <td align="center" width="25%">
      <img src="screenshots/nicelist.png" alt="Nicelists tab — built-in toggle plus user-managed lists with CSV / JSON / TXT import and export" width="240"><br>
      <sub><b>🛡 Nicelists tab</b> — built-in Default Nicelist + user-managed lists.</sub>
    </td>
    <td align="center" width="25%">
      <img src="screenshots/help.png" alt="Help tab — keyboard shortcuts and offline / release links" width="240"><br>
      <sub><b>? Help tab</b> — keyboard shortcuts and offline / release links.</sub>
    </td>
  </tr>
</table>

---

## 📤 Exports

Loupe consolidates every "get this analysis out of the browser" action into a single **`📤 Export ▾`** dropdown in the viewer toolbar. Every export is generated entirely client-side — no network calls, no third-party services. The dropdown sits next to the one-shot **`⚡ Summarize`** button, which handles the plaintext / Markdown analysis report.

**Save raw file is the only true download in the dropdown — every other action writes to the clipboard** so your one-click flow is "Export → paste into ticket / TIP / jq pipeline".

### Format × contents matrix

Columns are export formats; rows are the sections of the analysis. A ✅ means the export carries that data; a blank cell means it's deliberately omitted because the target format has no idiomatic slot for it.

| Content section              | Summarize (clipboard) | IOCs JSON (clipboard) | IOCs CSV (clipboard) | STIX 2.1 bundle (clipboard) | MISP event (clipboard) |
|------------------------------|:-------------------:|:---------------------:|:--------------------:|:---------------------------:|:----------------------:|
| File metadata (name, size, type) | ✅              | ✅                    |                      | ✅ (file SCO)               | ✅ (filename attr)     |
| File hashes (MD5 / SHA-1 / SHA-256) | ✅             | ✅                    |                      | ✅ (file SCO)               | ✅ (md5 / sha1 / sha256 attrs) |
| Risk level + summary          | ✅                  |                       |                      | ✅ (report desc)            | ✅ (threat_level_id + tag) |
| YARA / pattern detections     | ✅                  |                       |                      | ✅ (report)                 | ✅ (yara attrs)        |
| IOCs (URL / IP / domain / email / hash / path) | ✅ | ✅                    | ✅                   | ✅ (indicators)             | ✅ (attributes)        |
| VBA macro source              | ✅ (trimmed)        |                       |                      |                             |                        |
| Deobfuscated payload layers   | ✅ (trimmed)        |                       |                      |                             |                        |
| Format-specific deep data (PE / ELF / Mach-O / X.509 / JAR, email auth, LNK) | ✅ (trimmed) |        |                      |                             |                        |
| Size budget                   | configurable target | unlimited             | unlimited            | unlimited                   | unlimited              |

### ⚡ Summarize button

Copies a Markdown-formatted analysis report to the clipboard — File Info, Risk, Detections, IOCs, Macros, Deobfuscated layers, and format-specific deep data (PE / ELF / Mach-O / X.509 / JAR / LNK, PDF JavaScripts + embedded files, MSI CustomActions, OneNote embedded objects, RTF OLE objects, EML / MSG attachments + auth results, HTML credential forms, HTA / SVG active-content inventory, EVTX notable event IDs, SQLite schema, ZIP compression-ratio / zip-bomb indicators, ISO volume info, image EXIF, PGP key info, plist LaunchAgent persistence, AppleScript source + signatures, OOXML external relationships).

The size is user-configurable in ⚙ Settings — **Default** (~16 K tokens / 64 000 chars), **Large** (~50 K tokens / 200 000 chars), or **Unlimited** (no truncation). Small files land in the report verbatim; larger files are intelligently trimmed section-by-section to fit the chosen budget. Unlimited gives you the full-fidelity output.

### Export menu actions

| # | Label | Destination | Notes |
|--:|---|---|---|
| 1 | 💾 Save raw file | **Download** | Writes the original loaded file back to disk. |
| 2 | 📋 Copy raw content | Clipboard | Copies the file's raw bytes to the clipboard as UTF-8 text. Automatically disabled for binary formats (PE, ELF, Mach-O, JAR, `.class`, compiled `.scpt`, PDF, MSI, OLE2 / legacy Office, OOXML / ODF containers, archives, disk images, EVTX, SQLite, images, OneNote, DER / P12 / PFX, binary plist) — the clipboard's text channel would truncate at the first NUL byte. For eligible text files the copy round-trips the exact original bytes so a follow-up `Ctrl+V` paste rehydrates the identical file (same SHA-256, original extension, original line endings). |
| 3 | 🧾 Copy STIX 2.1 bundle (JSON) | Clipboard | Self-contained STIX 2.1 bundle (`identity` + `file` SCO + `indicator` per IOC + `malware-analysis` `report` SDO). Deterministic UUIDv5 IDs so re-exports dedupe in TIPs. |
| 4 | 🎯 Copy MISP event (JSON) | Clipboard | MISP v2 Event JSON — file-level attributes, per-IOC attributes, `yara` attributes per rule hit, `tlp:clear` / `loupe:risk` / `loupe:detected-type` tags. |
| 5 | `{…}` Copy IOCs as JSON | Clipboard | Flat JSON — file source record + sorted `iocs[{type, value, severity, note, source}]`. Ideal for scripting / jq. |
| 6 | 🔢 Copy IOCs as CSV | Clipboard | RFC 4180 CSV — `type, value, severity, note, source`. Excel / LibreOffice friendly. |

### STIX 2.1 IOC → pattern mapping

| Loupe IOC type | STIX sub-type | Pattern |
|---|---|---|
| `URL` | `url` | `[url:value = '…']` |
| `IP Address` (IPv4 / IPv6) | `ipv4-addr` / `ipv6-addr` | `[ipv4-addr:value = '…']` / `[ipv6-addr:value = '…']` |
| `Hostname` | `domain-name` | `[domain-name:value = '…']` |
| `Email` | `email-addr` | `[email-addr:value = '…']` |
| `Hash` (MD5 / SHA-1 / SHA-256) | `file` | `[file:hashes.'MD5' = '…']` / `SHA-1` / `SHA-256` |
| `File Path` / `UNC Path` | `file` | `[file:name = '<basename>']` |
| Other (command lines, registry keys, usernames, MAC, `Crypto Address`, `Secret`) | — | omitted from STIX (still included in CSV / JSON / MISP) |

### MISP IOC → attribute mapping

| Loupe IOC type | MISP type | Category | `to_ids` |
|---|---|---|---|
| `URL` | `url` | Network activity | true |
| `IP Address` | `ip-dst` | Network activity | true |
| `Hostname` | `domain` | Network activity | true |
| `Email` | `email-src` | Payload delivery | true |
| `Hash` (md5 / sha1 / sha256) | `md5` / `sha1` / `sha256` | Payload delivery | true |
| `File Path` / `UNC Path` | `filename` | Payload delivery | false |
| `Crypto Address` (BTC / XMR) | `btc` / `xmr` | Financial fraud | true |
| `Crypto Address` (ETH / onion / IPFS) | `text` | Other | false |
| `Secret` (AWS / GitHub / Stripe / Google / PEM / JWT / Slack) | `text` | Payload delivery | false |
| YARA rule name | `yara` | Payload delivery | false |
| Any other type | `text` | Other | false |

IOCs with Loupe severity `info` always force `to_ids: false` regardless of type.

