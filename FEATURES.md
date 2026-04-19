# Loupe — Feature Reference

> What Loupe shows you, one format at a time. Every capability documented; implementation internals deliberately live in [CONTRIBUTING.md](CONTRIBUTING.md) so this reference stays readable.
>
> - Quick overview → [README.md](README.md)
> - Threat model & vulnerability reporting → [SECURITY.md](SECURITY.md)
> - Build instructions & architecture → [CONTRIBUTING.md](CONTRIBUTING.md)

---

## 📑 Contents

- [Supported Formats (full reference)](#-supported-formats-full-reference)
- [Security Analysis Capabilities](#-security-analysis-capabilities)
- [User Interface](#-user-interface)
- [Exports](#-exports)
- [Example Files (guided tour)](#-example-files-guided-tour)


---

## 🛡 Supported Formats (full reference)

> **Extensionless and renamed files are auto-routed.** A single `RendererRegistry` dispatches files through three passes — magic-byte sniff, extension match, text-head sniff — so a mislabelled file still lands on the right renderer.

| Pass | Signals |
|---|---|
| **1. Magic-byte sniff** | PE, ELF, Mach-O (incl. Fat/Universal), OLE2, ZIP, PDF, PNG / JPEG / GIF / BMP / WebP / TIFF / AVIF, ISO 9660, EVTX, SQLite, gzip, RAR, 7z, CAB, binary plist, OpenPGP packet tags, CRX, `PKCX` |
| **2. Extension match** | Standard extension-to-renderer lookup |
| **3. Text-head sniff** | RTF, HTML / SVG / XML roots, EML headers, AppleScript, `.url`/`.webloc`, `.reg`, `.inf`, `.sct`, `.iqy`/`.slk`, `.wsf`, ClickOnce `<assembly>`, `-----BEGIN PGP …-----` |

Container disambiguation uses lazy OLE-stream and ZIP-central-directory peeks to tell DOCX / XLSX / PPTX / ODT / ODP / MSIX / JAR / CRX / XPI / generic ZIP apart, and `.doc` / `.xls` / `.ppt` / `.msg` apart inside OLE2.

| Category | Extensions |
|---|---|
| **Office (modern)** | `.docx` `.docm` `.xlsx` `.xlsm` `.pptx` `.pptm` `.ods` |
| **Office (legacy)** | `.doc` `.xls` `.ppt` |
| **OpenDocument** | `.odt` (text) · `.odp` (presentation) |
| **RTF** | `.rtf` — text extraction + OLE/exploit analysis |
| **PDF** | `.pdf` |
| **Email** | `.eml` `.msg` |
| **HTML** | `.html` `.htm` `.mht` `.mhtml` `.xhtml` — sandboxed preview + source view |
| **Archives** | `.zip` `.gz` `.gzip` `.tar` `.tar.gz` / `.tgz` `.rar` `.7z` `.cab` |
| **Disk images** | `.iso` `.img` — ISO 9660 filesystem listing |
| **OneNote** | `.one` — embedded object extraction + phishing detection |
| **Windows** | `.lnk` · `.hta` · `.url` `.webloc` `.website` · `.reg` · `.inf` · `.sct` · `.msi` · PE executables (`.exe` `.dll` `.sys` `.scr` `.cpl` `.ocx` `.drv` `.com`) · `.xll` (Excel add-in DLL) · `.application` `.manifest` (ClickOnce) · `.msix` `.msixbundle` `.appx` `.appxbundle` · `.appinstaller` |
| **Browser extensions** | `.crx` (Chrome / Chromium / Edge) · `.xpi` (Firefox / Thunderbird) |
| **Linux / IoT** | ELF binaries — `.so`, `.o`, `.elf`, extensionless executables (ELF32 / ELF64, LE/BE) |
| **macOS (binaries)** | Mach-O — `.dylib`, `.bundle`, extensionless executables, Fat/Universal (32/64-bit) |
| **macOS (scripts)** | `.applescript` `.scpt` `.scptd` `.jxa` — source + compiled bytecode, highlighted |
| **macOS (system)** | `.plist` (XML and binary) — interactive tree view |
| **macOS (installers)** | `.dmg` `.pkg` `.mpkg` |
| **Certificates** | `.pem` `.der` `.crt` `.cer` · `.p12` `.pfx` (PKCS#12) |
| **OpenPGP** | `.pgp` `.gpg` `.asc` `.sig` — ASCII-armored & binary packet streams; `.key` auto-disambiguated against X.509 |
| **Java** | `.jar` `.war` `.ear` · `.class` |
| **Scripts** | `.wsf` `.wsc` `.wsh` (parsed) · `.vbs` `.ps1` `.bat` `.cmd` `.js` |
| **Forensics** | `.evtx` · `.sqlite` `.db` (Chrome / Firefox / Edge history auto-detect) |
| **Data** | `.csv` `.tsv` · `.iqy` (Internet Query) · `.slk` (Symbolic Link) |
| **Images** | `.jpg` `.jpeg` `.png` `.gif` `.bmp` `.webp` `.ico` `.tif` `.tiff` `.avif` — preview + steganography / polyglot detection |
| **SVG** | `.svg` — sandboxed preview + source view, deep SVG-specific security analysis |
| **Catch-all** | *Any file* — plain-text view with line numbers, or hex dump for binary data |

---

## 🔬 Security Analysis Capabilities

### Cross-cutting

| Capability | What you get |
|---|---|
| **Risk assessment** | Colour-coded risk bar (low / medium / high / critical) with a finding summary |
| **Document search** | In-toolbar search with match highlighting, match counter, `Enter`/`Shift+Enter` navigation (`F` to focus) |
| **YARA rule engine** | Ships with 493 default rules across 20 category files; auto-scans every file on load. Upload custom `.yar` files (or drag-and-drop), validate, save the combined set, rescan. |
| **File hashes** | MD5, SHA-1, SHA-256 computed in-browser with one-click VirusTotal lookup |
| **Parser safety limits** | Centralised caps on nesting depth, decompressed size, per-entry compression ratio (zip-bomb defeat), entry count, and a wall-clock watchdog that aborts runaway parsers |
| **Encoded content detection** | Scans for Base64, hex, Base32, gzip / zlib / deflate. Decodes, classifies the payload (PE, script, URL list, …), extracts IOCs, and offers "Load for analysis" to drill into the decoded layer. |
| **Deep deobfuscation drill-down** | Sidebar walks the full nested-payload tree so every layer (e.g. Base64 → gzip → PowerShell → Base64 → URL) gets its own section, with coloured hop pills showing the full lineage and a size-delta row making unusual expansion / shrinkage obvious. |
| **Document metadata** | Author, title, dates, revision count extracted from `docProps/core.xml` (and equivalents) |

### IOC extraction

| Capability | What you get |
|---|---|
| **Classic IOCs** | URLs, email addresses, IPs, file paths, UNC paths, registry keys, command lines, hostnames — pulled from document content, VBA source, binary strings, decoded payloads, and format-specific metadata |
| **Registrable-domain pivots** | Every extracted URL auto-emits a sibling registrable domain (via the public-suffix list) so you get a domain-level pivot without double-entering the URL |
| **GUID pivots** | LNK DROID file/volume IDs, MSI ProductCodes, PDF XMP DocumentID / InstanceID, Mach-O LC_UUID |
| **Fingerprint pivots** | X.509 SHA-1 / SHA-256 thumbprints and OpenPGP key fingerprints / key IDs |
| **Identity pivots** | Usernames (document author, PDF `/Author`, MSI Author / Last Author, EML/MSG creator) and MAC addresses (LNK TrackerDataBlock) |
| **Image-metadata pivots** | EXIF GPS coordinates, camera serial numbers, software/firmware strings, XMP DocumentID / InstanceID, full XMP tree |
| **Defanged-indicator refanging** | `hxxp://`, `1[.]2[.]3[.]4`, and similar obfuscations are refanged automatically before extraction |
| **Metadata → IOC mirroring** | Every renderer ships the same classic-pivot fields (hashes, paths, GUIDs, MAC, emails, cert fingerprints) to the sidebar. Attribution-only strings like `CompanyName` / `FileDescription` stay metadata-only by design. |

### Documents & Office

| Capability | What you get |
|---|---|
| **VBA / macro analysis** | Extracts and syntax-highlights VBA source; flags auto-execute entry points (`AutoOpen`, `Workbook_Open`, `Shell`, etc.) |
| **Macro download** | Download decoded VBA as `.txt`, or the raw `vbaProject.bin` for offline analysis with olevba / oledump |
| **OOXML relationship scan** | Deep walk of `_rels/*.rels` — surfaces external targets, remote-template injection (`attachedTemplate`), and embedded `oleObject` references that classic metadata extraction misses |
| **PDF detection** | Flags `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, URIs, XFA forms, XMP metadata, and other risky operators via YARA |
| **PDF extraction** | Pulls JavaScript bodies from `/JS` actions (literal, hex, and indirect-stream with `/FlateDecode`) with per-script trigger, size, SHA-256, and suspicious-API hints; extracts `/EmbeddedFile` attachments (recursively analysable in-place); extracts XFA form packets |
| **EML / email analysis** | Full RFC 5322 / MIME parser — headers, multipart body, attachments, SPF / DKIM / DMARC auth results, tracking pixel detection |
| **OneNote analysis** | FileDataStoreObject parsing with MIME-sniffed embedded blobs, phishing-lure detection |
| **RTF analysis** | Text extraction plus OLE-object and exploit-pattern detection |

### Windows

| Capability | What you get |
|---|---|
| **LNK inspection** | MS-SHLLINK binary parser — target path, arguments, hotkey, shell-item chain, full ExtraData blocks, timestamps, dangerous-command detection, UNC credential-theft patterns, TrackerDataBlock machine-ID + MAC. Every path/argument surfaces as its own sidebar IOC. |
| **HTA analysis** | Script extraction, `<HTA:APPLICATION>` attribute parsing, obfuscation detection, 40+ suspicious-pattern checks |
| **MSI analysis** | CustomAction row parsing, Binary stream magic-sniffing, embedded CAB detection, Authenticode verdict, clickable stream drill-down, lazy stream loading to avoid memory crashes on huge installers |
| **PE analysis** | Parses PE32 / PE32+ — DOS / COFF / Optional headers, section table with entropy, imports with ~140 flagged APIs, exports, resources, Rich header, string extraction; security features (ASLR, DEP, CFG, SEH, Authenticode); identifies XLL add-ins, compiled AutoHotkey, Inno Setup / NSIS installers, Go-compiled binaries. 31 YARA rules for packers and malware toolkits (Cobalt Strike, Mimikatz, Metasploit). |
| **ClickOnce** | Parses `.application` / `.manifest` — assembly identity, deployment codebase + `deploymentProvider`, entry point, trust info, signature subject + thumbprint, dependent assemblies. Flags AppDomainManager hijacking, plain-HTTP deployment, FullTrust requests, and disposable-infrastructure dependencies. 4 YARA rules. |
| **MSIX / APPX / App Installer** | Parses `.msix` / `.msixbundle` / `.appx` / `.appxbundle` packages and standalone `.appinstaller` XML — identity, capabilities (tiered: restricted / device / ordinary), applications, entry points, extensions (full-trust process, startup task, app-execution alias, protocol, COM, background tasks). Verifies the `AppxSignature.p7x` signer against the manifest's `Publisher` DN (mismatch ⇒ repackaged / re-signed), derives the canonical 13-character Windows PublisherId, flags silent auto-updates and suspicious update URIs. 9 YARA rules. Inner files clickable for recursive analysis. *Verification internals: see CONTRIBUTING → MSIX signature verification.* |

### Linux & macOS binaries

| Capability | What you get |
|---|---|
| **ELF analysis** | Parses ELF32 / ELF64 (LE/BE) — headers, segments, sections, dynamic linking (NEEDED, SONAME, RPATH/RUNPATH), symbol tables with suspicious-symbol flagging, note sections; security features (RELRO, Stack Canary, NX, PIE, FORTIFY_SOURCE); detects Go-compiled binaries (module path + version). 18 YARA rules: Mirai, cryptominers, reverse shells, LD_PRELOAD hijacking, rootkits, container escapes, packers. |
| **Mach-O analysis** | Parses Mach-O 32/64-bit and Fat/Universal — header, load commands, segments with section-level entropy, symbol tables (~30 flagged macOS APIs), dynamic libraries, RPATH, code signature (CodeDirectory, entitlements, CMS); security features (PIE, NX, Stack Canary, ARC, Hardened Runtime, Library Validation, Encrypted). 17 YARA rules for macOS stealers (Atomic, AMOS), RATs, reverse shells, persistence, anti-debug / VM detection. |
| **Graceful binary fallback** | If PE / ELF / Mach-O parsing fails on a truncated or malformed binary, the renderer switches to a strings-plus-hex fallback and keeps the extracted strings wired into the sidebar so IOC extraction, YARA scanning, and encoded-content detection still work. |

### macOS scripts, property lists & installers

| Capability | What you get |
|---|---|
| **AppleScript / JXA** | Source files (`.applescript`, `.jxa`) with full syntax highlighting; compiled `.scpt` binaries mined for strings and the embedded FasTX source block; macOS-specific flags for `do shell script`, `display dialog`, `with administrator privileges`, and friends. 18 YARA rules. |
| **Property lists** | Parses both XML and binary (`bplist00`) into an interactive tree view — expandable nested structures, LaunchAgent / LaunchDaemon detection, persistence keys, suspicious URL schemes, privacy-sensitive entitlements. 21 YARA rules. |
| **DMG (Apple Disk Image)** | Reads the UDIF trailer, enumerates partitions, decodes mish block-type frequencies, detects encrypted envelopes (AEA1 / `encrcdsa` / `cdsaencr`), and extracts embedded `.app` bundle paths even when filesystem walking isn't possible. |
| **PKG (flat installer)** | Parses xar TOC + `Distribution` / `PackageInfo` XML; clickable entry drill-down; flags dangerous install-time script names (`preinstall`, `postinstall`, `preflight`, `postflight`, `InstallationCheck`, `VolumeCheck`). |
| **ZIP-wrapped `.app` bundles** | The ZIP listing also surfaces embedded macOS `.app` bundles — each bundle root is emitted as its own IOC, and hidden bundles (leading-dot dirs), unsigned bundles (no `_CodeSignature/`), and multi-bundle ZIPs are flagged high-severity. |
| **macOS installer YARA** | 12 rules across DMG and PKG: install-time scripts, unsigned / root scripts, encrypted-envelope heuristics, app-bundle launcher patterns. |

### Browser extensions

| Capability | What you get |
|---|---|
| **CRX (Chrome / Chromium / Edge)** | Parses both v2 and v3 envelopes; derives the canonical Chrome extension ID, decodes declared-vs-computed IDs and flags mismatches, surfaces RSA-SHA256 / ECDSA-SHA256 signature counts, flags malformed or empty headers. *Protobuf decode details: see CONTRIBUTING → CRX v3 decode pipeline.* |
| **XPI (Firefox / Thunderbird)** | Plain ZIP; parses WebExtension `manifest.json` or legacy `install.rdf` |
| **Manifest analysis (MV2 & MV3)** | Name / version / ID / author / update URL / CSP / Key; MV3 service worker vs MV2 background scripts; content scripts with matched URL patterns; permissions tiered by risk (high: `nativeMessaging`, `<all_urls>`, `debugger`, `proxy`; medium: `cookies`, `history`, `management`, `webRequest` + `webRequestBlocking`, `declarativeNetRequest`, `tabCapture`, …); `externally_connectable`, `web_accessible_resources`, `content_security_policy` (flags `unsafe-eval` / `unsafe-inline` / remote script hosts); `chrome_url_overrides`; `update_url` off-store detection. |
| **YARA coverage** | 12 rules — native-messaging bridges, broad host permissions, unsafe-eval CSP, wide externally-connectable, debugger / management APIs, proxy + cookies / history combos, non-store update URLs, legacy XUL bootstrap, wide `web_accessible_resources`, in-script `eval`. |
| **Inner-file drill-down** | Manifest, scripts, icons are clickable for recursive analysis |

### Forensics

| Capability | What you get |
|---|---|
| **EVTX analysis** | Parses the Windows Event Log binary format (ElfFile header, chunks, BinXml records); extracts Event ID, Level, Provider, Channel, Computer, timestamps, and EventData; flags suspicious events (4688, 4624 / 4625, 1102, 7045, 4104); extracts IOCs: usernames (`DOMAIN\User`), hostnames, IPs, process paths, command lines, hashes, URLs, file / UNC paths. Copy / Download as CSV. |
| **SQLite / browser history** | Reads the SQLite binary format (B-tree pages, schema, cell data); auto-detects Chrome / Edge / Firefox history databases; extracts URLs, titles, visit counts, timestamps; generic table browser for non-history SQLite files. Copy / Download as CSV. |

### Crypto

| Capability | What you get |
|---|---|
| **X.509** | Parses PEM / DER certificates and PKCS#12 containers — subject / issuer DN, validity with expiry status, public key details (algorithm, key size, curve), extensions (SAN, Key Usage, EKU, Basic Constraints, AKI / SKI, CRL DP, AIA, Certificate Policies), serial, signature algorithm, SHA-1 / SHA-256 fingerprints. Flags self-signed, expired / not-yet-valid, weak keys (<2048-bit RSA), weak signature algorithms (SHA-1 / MD5), long validity periods, missing SAN, embedded private keys. IOC extraction from SANs and CRL / AIA URIs. |
| **OpenPGP** | Parses ASCII-armored and binary data (RFC 4880 / RFC 9580) — packets, key IDs, fingerprints, User IDs + embedded emails, subkeys, self-signatures, subkey bindings; public-key algorithm (RSA / DSA / ECDSA / ECDH / EdDSA / X25519 / Ed25519), key size, ECC curve; validates ASCII-armor CRC-24. Flags unencrypted secret keys, weak key sizes, deprecated algorithms (Elgamal-sign-or-encrypt, v3 legacy), revoked / expired / long-lived keys, SHA-1 as preferred hash. Parse-only — no signature verification or secret-key decryption. |

### Java, web & images

| Capability | What you get |
|---|---|
| **JAR / Java** | Parses JAR / WAR / EAR archives and standalone `.class` files — class file header, MANIFEST.MF with Main-Class and permissions, class listing with package tree, dependency extraction, constant pool string analysis with ~45 suspicious Java API patterns (deserialization, JNDI, reflection, command execution, networking) mapped to MITRE ATT&CK. Obfuscation detection (Allatori, ZKM, ProGuard, short-name heuristics). Clickable inner file extraction. 17 YARA rules. |
| **SVG security analysis** | `<script>` extraction (inline + external), `<foreignObject>` detection (credential forms, password fields, embedded HTML), event handler scanning (~30 `on*` attributes), Base64 / data URI payload analysis, SVG-specific vectors (`<use>` external refs, `<animate>` / `<set>` href manipulation, `<feImage>` external filters), XML entity / DTD / XXE detection, JavaScript obfuscation patterns, meta refresh redirects. 18 YARA rules. |
| **Image analysis** | Steganography indicators, polyglot file detection, hex header inspection for embedded payloads |
| **Script scanning** | `.vbs`, `.ps1`, `.bat`, `.rtf`, and similar script types are scanned for dangerous execution patterns alongside YARA matching |

### Archive drill-down

Click any entry inside a ZIP / TAR / ISO / MSI / PKG / CRX / XPI / JAR listing to open and re-analyse it with Back navigation. ZipCrypto-encrypted entries get a lock icon; unsupported formats fall back to a hex dump but still feed YARA and IOC scanning.

---

## 🎨 User Interface

| Feature | What you get |
|---|---|
| **Six-theme picker** | Light, Dark (default), Midnight OLED, Solarized, Mocha, Latte — chosen from the ⚙ Settings tile grid. Your choice persists and is applied before first paint so you never see a flash of the wrong palette. First-boot users are matched to their OS `prefers-color-scheme`. Theme tokens flip every surface at once. *Pluggable — see CONTRIBUTING → Adding a New Theme.* |
| **Settings / Help dialog** | `⚙` toolbar button (or `,` for Settings, `?` / `H` for Help) — a unified two-tabbed modal. Settings carries the theme picker and the 3-phase Summarize-size picker (Default / Large / Unlimited); Help lists every keyboard shortcut and the offline / release links. |
| **Floating zoom** | 50 – 200 % zoom via a floating control that stays out of the way |
| **Click-and-drag panning** | Grab and drag to pan around rendered documents |
| **Resizable sidebar** | Drag the sidebar edge to resize it between 33 % and 50 % of the viewport |
| **Collapsible sidebar sections** | Single-pane sidebar with collapsible `<details>`: File Info, Macros, Signatures & IOCs |
| **Breadcrumb navigation** | Drill-down path as a clickable crumb trail (e.g. `📦 archive.zip ▸ 📄 doc.docm ▸ 🔧 Module1.bas`). Overflow `… ▾` dropdown keeps long trails on one line; the close button is anchored so its position never shifts with filename length. |
| **Archive browser** | Shared collapsible / searchable / sortable tree used by every archive-style renderer (ZIP, JAR / WAR / EAR, MSIX / APPX, CRX / XPI, TAR / `.tar.gz`, ISO / IMG, PKG / MPKG). Tree view with child counts and one-click drill-down; flat sortable table view; instant filter box; per-entry risk badges (executable, double-extension, ZipCrypto lock, tar-symlink target). |
| **Keyboard shortcuts** | `S` sidebar · `Y` YARA dialog · `,` Settings · `?` / `H` Help · `F` search document · `Ctrl+C` / `⌘C` copy raw file (when nothing is selected) · `Ctrl+V` paste file for analysis · `Esc` close dialog / clear search. **Archive browser:** `/` focus filter · `↑ ↓` navigate rows · `← →` collapse / expand folder · `Enter` / `Space` open selected file. |
| **Smart whole-token select** | Double-click in any monospace viewer selects the entire non-whitespace token — expanding past `/ . : = - _` and across visual line wraps — up to the nearest whitespace boundary. Great for URLs, hashes, base64 blobs, file paths, registry keys, PE imports, x509 fingerprints. |
| **Loading overlay** | Spinner with status message while parsing large files |
| **Toast notifications** | Non-intrusive feedback for downloads, clipboard operations, and errors |
| **Click-to-highlight** | Clicking any IOC or YARA match in the sidebar jumps to (and cycles through) matching occurrences in the viewer with yellow / blue `<mark>` highlights |
| **Forensic-safe email links** | `<a href>` inside EML / MSG messages is rendered as an inert span — the visible anchor text and underlying URL (exposed as a hover tooltip) stay inspectable, but clicking does nothing. You can read and copy a phishing URL with zero risk of accidental navigation. |

---

## 📤 Exports

Loupe consolidates every "get this analysis out of the browser" action into a single **`📤 Export ▾`** dropdown in the viewer toolbar. Every export is generated entirely client-side — no network calls, no third-party services. The dropdown sits next to the one-shot **`⚡ Summarize`** button, which handles the plaintext / Markdown analysis report.

**Save raw file is the only true download in the dropdown — every other action writes to the clipboard** so your one-click flow is "Export → paste into ticket / TIP / jq pipeline".

### Export format × contents matrix

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
| Size budget                   | 3-phase target      | unlimited             | unlimited            | unlimited                   | unlimited              |

### ⚡ Summarize button

Copies a Markdown-formatted analysis report to the clipboard — File Info, Risk, Detections, IOCs, Macros, Deobfuscated layers, and format-specific deep data (PE / ELF / Mach-O / X.509 / JAR / LNK, PDF JavaScripts + embedded files, MSI CustomActions, OneNote embedded objects, RTF OLE objects, EML / MSG attachments + auth results, HTML credential forms, HTA / SVG active-content inventory, EVTX notable event IDs, SQLite schema, ZIP compression-ratio / zip-bomb indicators, ISO volume info, image EXIF, PGP key info, plist LaunchAgent persistence, AppleScript source + signatures, OOXML external relationships).

The size is user-configurable in ⚙ Settings via a three-phase picker — **Default** (~16 K tokens / 64 000 chars), **Large** (~50 K tokens / 200 000 chars), or **Unlimited** (no truncation). Rather than pre-shrinking every section to a fixed cap, Loupe builds the report at **full fidelity first** and only retrenches if the assembled total exceeds the chosen target: small files (a single raw script, a short config) land in the report verbatim regardless of the target. When the full build is over target, sections are walked from most expendable (format-specific deep data, deobfuscated payloads) down toward File Info / Risk and each one is re-emitted at progressively tighter row-count and text-truncation caps until the report fits. Unlimited skips every measurement — you always get the full-fidelity output.

### Export menu actions

| # | Label | Destination | Notes |
|--:|---|---|---|
| 1 | 💾 Save raw file | **Download** | Writes the original loaded file back to disk |
| 2 | 📋 Copy raw content | Clipboard | Copies the file's raw bytes to the clipboard as UTF-8 text. Automatically disabled for binary formats (PE, ELF, Mach-O, JAR, `.class`, compiled `.scpt`, PDF, MSI, OLE2 / legacy Office, OOXML / ODF containers, archives, disk images, EVTX, SQLite, images, OneNote, DER / P12 / PFX, binary plist) — the clipboard's text channel would truncate at the first NUL byte. For eligible text files the copy round-trips the exact original bytes so a follow-up `Ctrl+V` paste rehydrates the identical file (same SHA-256, original extension, original line endings). |
| 3 | 🧾 Copy STIX 2.1 bundle (JSON) | Clipboard | Self-contained STIX 2.1 bundle (`identity` + `file` SCO + `indicator` per IOC + `malware-analysis` `report` SDO). Deterministic UUIDv5 IDs so re-exports dedupe in TIPs. |
| 4 | 🎯 Copy MISP event (JSON) | Clipboard | MISP v2 Event JSON — file-level attributes, per-IOC attributes, `yara` attributes per rule hit, `tlp:clear` / `loupe:risk` / `loupe:detected-type` tags |
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
| Other (command lines, registry keys, usernames, MAC) | — | omitted from STIX (still included in CSV / JSON / MISP as text) |

### MISP IOC → attribute mapping

| Loupe IOC type | MISP type | Category | `to_ids` |
|---|---|---|---|
| `URL` | `url` | Network activity | true |
| `IP Address` | `ip-dst` | Network activity | true |
| `Hostname` | `domain` | Network activity | true |
| `Email` | `email-src` | Payload delivery | true |
| `Hash` (md5 / sha1 / sha256) | `md5` / `sha1` / `sha256` | Payload delivery | true |
| `File Path` / `UNC Path` | `filename` | Payload delivery | false |
| YARA rule name | `yara` | Payload delivery | false |
| Any other type | `text` | Other | false |

IOCs with Loupe severity `info` always force `to_ids: false` regardless of type.

---

## 🎬 Example Files (guided tour)


The [`examples/`](examples/) directory contains sample files for every supported format — grouped by category — try dropping them into Loupe to explore.

### Encoded payloads ([`examples/encoded-payloads/`](examples/encoded-payloads/))

- [`nested-double-b64-ip.txt`](examples/encoded-payloads/nested-double-b64-ip.txt) — double Base64-encoded PowerShell with hidden C2 IP
- [`encoded-zlib-base64.txt`](examples/encoded-payloads/encoded-zlib-base64.txt) — nested encoded content with compressed payloads
- [`mixed-obfuscations.txt`](examples/encoded-payloads/mixed-obfuscations.txt) — kitchen-sink sample combining many obfuscation techniques

### Office ([`examples/office/`](examples/office/))

- [`example.docm`](examples/office/example.docm) — macro-enabled Word document with AutoOpen + Shell VBA
- [`example.xlsm`](examples/office/example.xlsm) — macro-enabled Excel workbook with VBA
- [`example.pptm`](examples/office/example.pptm) — macro-enabled PowerPoint with VBA

### PDF & email ([`examples/pdf/`](examples/pdf/), [`examples/email/`](examples/email/))

- [`javascript-example.pdf`](examples/pdf/javascript-example.pdf) — PDF with `/OpenAction` triggering embedded JavaScript
- [`example.eml`](examples/email/example.eml) — email with MIME parts and headers
- [`phishing-example.eml`](examples/email/phishing-example.eml) — phishing email with SPF/DKIM/DMARC failures and a tracking pixel

### Windows scripts & shortcuts ([`examples/windows-scripts/`](examples/windows-scripts/))

- [`example.lnk`](examples/windows-scripts/example.lnk) — Windows shortcut with suspicious target path
- [`example.hta`](examples/windows-scripts/example.hta) — HTML Application with embedded scripts
- [`example.vbs`](examples/windows-scripts/example.vbs), [`example.js`](examples/windows-scripts/example.js), [`example.cmd`](examples/windows-scripts/example.cmd) — classic script-dropper bodies
- [`ps-obfuscation.ps1`](examples/windows-scripts/ps-obfuscation.ps1), [`cmd-obfuscation.bat`](examples/windows-scripts/cmd-obfuscation.bat), [`encoded-powershell.bat`](examples/windows-scripts/encoded-powershell.bat) — obfuscated PowerShell / cmd bodies
- [`example.reg`](examples/windows-scripts/example.reg), [`example.inf`](examples/windows-scripts/example.inf), [`example.sct`](examples/windows-scripts/example.sct), [`example.wsf`](examples/windows-scripts/example.wsf) / [`example.wsc`](examples/windows-scripts/example.wsc) / [`example.wsh`](examples/windows-scripts/example.wsh), [`example.url`](examples/windows-scripts/example.url) — Windows shell / scripting-host formats

### Windows installers ([`examples/windows-installers/`](examples/windows-installers/))

- [`example.msi`](examples/windows-installers/example.msi) — Windows Installer package (CustomAction rows, embedded CAB, Authenticode verdict)
- [`example.msix`](examples/windows-installers/example.msix), [`example.appinstaller`](examples/windows-installers/example.appinstaller) — MSIX package + App Installer XML
- [`example.application`](examples/windows-installers/example.application), [`malicious-example.application`](examples/windows-installers/malicious-example.application), [`example.manifest`](examples/windows-installers/example.manifest) — ClickOnce deployment / application manifests (benign + malicious)

### Forensics ([`examples/forensics/`](examples/forensics/))

- [`example.evtx`](examples/forensics/example.evtx) / [`example-security.evtx`](examples/forensics/example-security.evtx) — Windows Event Logs (general + security events)
- [`chromehistory-example.sqlite`](examples/forensics/chromehistory-example.sqlite) — Chrome browsing history database

### Native binaries ([`examples/pe/`](examples/pe/), [`examples/elf/`](examples/elf/), [`examples/macos-system/`](examples/macos-system/))

- [`pe/example.exe`](examples/pe/example.exe) — Windows PE executable with imports, sections, and security features
- [`pe/signed-example.dll`](examples/pe/signed-example.dll) — Authenticode-signed DLL
- [`elf/example`](examples/elf/example) — Linux ELF binary with symbols, segments, and security checks
- [`macos-system/example.dylib`](examples/macos-system/example.dylib) — macOS Mach-O binary with load commands and code signature

### macOS scripts ([`examples/macos-scripts/`](examples/macos-scripts/))

- [`example.applescript`](examples/macos-scripts/example.applescript) — AppleScript source with macOS-specific security analysis
- [`example.scpt`](examples/macos-scripts/example.scpt) — compiled AppleScript binary (string extraction from opaque bytecode)
- [`example.jxa`](examples/macos-scripts/example.jxa) — JavaScript for Automation

### macOS system & installers ([`examples/macos-system/`](examples/macos-system/))

- [`example.plist`](examples/macos-system/example.plist) — XML property list with LaunchAgent / persistence-key detection
- [`example-binary.plist`](examples/macos-system/example-binary.plist) — binary plist (`bplist00`) round-tripped through the tree viewer
- [`example.dmg`](examples/macos-system/example.dmg) — Apple Disk Image / UDIF with partition + `.app` bundle enumeration
- [`example.pkg`](examples/macos-system/example.pkg) — flat PKG (xar) installer with pre/post-install script flagging, curl|bash detection, and LaunchDaemon persistence drops
- [`example.app`](examples/macos-system/example.app) — `.app` bundle root illustrating the drop-delivery shape flagged by the ZIP / DMG renderers
- [`example.webloc`](examples/macos-system/example.webloc) — macOS internet shortcut

### Crypto — certificates & OpenPGP ([`examples/crypto/`](examples/crypto/))

- [`example-selfsigned.pem`](examples/crypto/example-selfsigned.pem) — self-signed X.509 certificate with suspicious SANs
- [`example-with-key.pem`](examples/crypto/example-with-key.pem) — certificate with embedded private key + weak 1024-bit RSA key
- [`example-expired.crt`](examples/crypto/example-expired.crt) — expired X.509 certificate
- [`example-san.pem`](examples/crypto/example-san.pem), [`example-ca.der`](examples/crypto/example-ca.der), [`google-chain.pem`](examples/crypto/google-chain.pem) — SAN / DER / full-chain variants
- [`example.p12`](examples/crypto/example.p12), [`example.pfx`](examples/crypto/example.pfx) — PKCS#12 containers
- [`example.pgp`](examples/crypto/example.pgp), [`example.gpg`](examples/crypto/example.gpg), [`example.asc`](examples/crypto/example.asc), [`example.sig`](examples/crypto/example.sig) — binary + ASCII-armored OpenPGP packet streams
- [`example.key`](examples/crypto/example.key) — OpenPGP key block (auto-detected via packet-header heuristics; `.key` is shared with X.509 PEM private keys)

### Web, Java & images ([`examples/web/`](examples/web/), [`examples/java/`](examples/java/), [`examples/images/`](examples/images/))

- [`example-malicious.svg`](examples/web/example-malicious.svg) — SVG with embedded scripts, foreignObject phishing form, event handlers, and data URI payloads
- [`example.jar`](examples/java/example.jar) — Java archive with class files, MANIFEST.MF, and constant pool analysis
- [`polyglot-example.png`](examples/images/polyglot-example.png) — PNG with a ZIP appended past the IEND marker

### Archives ([`examples/archives/`](examples/archives/))

- [`example.zip`](examples/archives/example.zip), [`example.tar`](examples/archives/example.tar), [`example.tar.gz`](examples/archives/example.tar.gz), [`example.gz`](examples/archives/example.gz), [`example.iso`](examples/archives/example.iso) — archive / disk-image samples
