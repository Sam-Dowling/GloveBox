# Loupe — Feature Reference

> Long-form, detail-heavy reference for every supported format, every analysis capability, and every UI affordance in Loupe.
>
> - For a quick overview, see [README.md](README.md).
> - For the threat model and vulnerability reporting, see [SECURITY.md](SECURITY.md).
> - For build instructions and developer docs, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📑 Contents

- [Supported Formats (full reference)](#-supported-formats-full-reference)
- [Security Analysis Capabilities](#-security-analysis-capabilities)
- [User Interface](#-user-interface)
- [Exports](#-exports)
- [Example Files (guided tour)](#-example-files-guided-tour)


---

## 🛡 Supported Formats (full reference)

> **Extensionless and renamed files are auto-routed.** Every format below is registered in a single `RendererRegistry` that dispatches files through three passes — a file with the wrong extension, no extension, or a misleading one (`.txt` on a PE, `.bin` on an ISO, `.dat` on an EVTX) still lands on the right renderer.

| Pass | Signals |
|---|---|
| **1. Magic-byte sniff** | PE `MZ` · ELF `\x7fELF` · Mach-O `FEEDFACE`/`FEEDFACF`/`CAFEBABE` · OLE2 `D0CF11E0` · ZIP `PK\x03\x04` · PDF `%PDF-` · PNG/JPEG/GIF/BMP/WebP/TIFF/AVIF · ISO 9660 `CD001` · EVTX `ElfFile` · SQLite `SQLite format 3` · gzip `1F 8B` · RAR `Rar!` · 7z `7z\xBC\xAF\x27\x1C` · CAB `MSCF` · `bplist00` · OpenPGP packet-tag bytes · `Cr24` · `PKCX` |
| **2. Extension match** | Standard extension-to-renderer lookup |
| **3. Text-head sniff** | RTF `{\rtf` · HTML/SVG/XML roots · EML headers · AppleScript · `.url`/`.webloc` · `.reg` · `.inf` · `.sct` · `.iqy`/`.slk` · `.wsf` · ClickOnce `<assembly>` · `-----BEGIN PGP ...-----` |

Container disambiguation uses lazy OLE-stream and ZIP-central-directory peeks — DOCX vs XLSX vs PPTX vs ODT vs ODP vs MSIX vs JAR vs CRX/XPI vs generic ZIP; `.doc` vs `.xls` vs `.ppt` vs `.msg` inside OLE2.

| Category | Extensions |
|---|---|
| **Office (modern)** | `.docx` `.docm` `.xlsx` `.xlsm` `.pptx` `.pptm` `.ods` |
| **Office (legacy)** | `.doc` `.xls` `.ppt` |
| **OpenDocument** | `.odt` (text) · `.odp` (presentation) |
| **RTF** | `.rtf` — text extraction + OLE/exploit analysis |
| **PDF** | `.pdf` |
| **Email** | `.eml` `.msg` |
| **HTML** | `.html` `.htm` `.mht` `.mhtml` `.xhtml` — sandboxed preview + source view |
| **Archives** | `.zip` `.gz` `.gzip` `.tar` `.tar.gz`/`.tgz` `.rar` `.7z` `.cab` — content listing, threat flagging, clickable entry extraction, gzip decompression, TAR parsing, ZipCrypto decryption, hex dump fallback for unsupported formats. ZIP listings additionally surface embedded macOS `.app` bundles (`<name>.app/Contents/...` layouts) — each bundle root is emitted as its own clickable `File Path` IOC, and hidden bundles (leading-dot `.app` dirs), unsigned bundles (Mach-O present but no `_CodeSignature/`), and multi-bundle ZIPs are flagged as high-severity warnings so ZIP-wrapped macOS payloads get the same surface area as the `.dmg` renderer |
| **Disk images** | `.iso` `.img` — ISO 9660 filesystem listing |
| **OneNote** | `.one` — embedded object extraction + phishing detection |
| **Windows** | `.lnk` (Shell Link) · `.hta` (HTML Application) · `.url` `.webloc` `.website` (Internet shortcuts) · `.reg` (Registry) · `.inf` (Setup Information) · `.sct` (Script Component) · `.msi` (Installer) · `.exe` `.dll` `.sys` `.scr` `.cpl` `.ocx` `.drv` `.com` (PE executables) · `.xll` (Excel add-in DLL) · `.application` `.manifest` (ClickOnce deployment / application manifests) · `.msix` `.msixbundle` `.appx` `.appxbundle` (MSIX / APPX packages) · `.appinstaller` (App Installer XML) |
| **Browser extensions** | `.crx` (Chrome / Chromium / Edge — CRX v2 SubjectPublicKeyInfo → extension ID; CRX v3 protobuf `CrxFileHeader` decoded — declared `crx_id` from `SignedData` and computed IDs from every RSA / ECDSA `AsymmetricKeyProof.public_key` are surfaced and compared) · `.xpi` (Firefox / Thunderbird — plain ZIP with WebExtension `manifest.json` or legacy `install.rdf`) |
| **Linux / IoT** | ELF binaries (`.so` shared libraries, `.o` object files, `.elf` binaries, extensionless executables) — ELF32/ELF64, LE/BE |
| **macOS** | Mach-O binaries (`.dylib` dynamic libraries, `.bundle` plugins, extensionless executables, Fat/Universal) — 32/64-bit |
| **macOS Scripts** | `.applescript` `.scpt` `.scptd` `.jxa` (AppleScript source, compiled AppleScript, AppleScript bundle, JavaScript for Automation) — source display with full AppleScript syntax highlighting (keywords, strings, comments, `do shell script` / `display dialog` / `with administrator privileges` etc. all coloured, including the embedded source block recovered from compiled `.scpt` FasTX binaries) and JXA highlighted as JavaScript, compiled binary string extraction, macOS-specific security analysis. |
| **macOS Property Lists** | `.plist` (XML and binary plist) — tree view with expandable nested structures, LaunchAgent/Daemon detection, persistence key analysis, suspicious pattern flagging, 21 YARA rules for plist threats |
| **macOS Installers** | `.dmg` (Apple Disk Image / UDIF — `koly` trailer, partition / mish block enumeration, AEA1 / `encrcdsa` / `cdsaencr` encrypted envelope detection, embedded `.app` bundle path extraction) · `.pkg` `.mpkg` (flat PKG / xar archive — zlib-decompressed TOC, `Distribution` / `PackageInfo` XML, clickable entry drill-down, dangerous-script-name flagging: `preinstall` / `postinstall` / `preflight` / `postflight` / `InstallationCheck` / `VolumeCheck`) — 5 YARA rules for macOS installer threats |
| **Certificates** | `.pem` `.der` `.crt` `.cer` (X.509 certificates) · `.p12` `.pfx` (PKCS#12 containers) |
| **OpenPGP** | `.pgp` `.gpg` `.asc` `.sig` — ASCII-armored & binary OpenPGP packet streams (RFC 4880 / RFC 9580); `.key` auto-disambiguated between OpenPGP and X.509 private keys |
| **Java** | `.jar` `.war` `.ear` (Java archives) · `.class` (Java bytecode) — MANIFEST.MF parsing, class file analysis, constant pool string extraction, dependency analysis |
| **Scripts** | `.wsf` `.wsc` `.wsh` (Windows Script Files — parsed) · `.vbs` `.ps1` `.bat` `.cmd` `.js` |
| **Forensics** | `.evtx` (Windows Event Log) · `.sqlite` `.db` (SQLite — Chrome/Firefox/Edge history auto-detect) |
| **Data** | `.csv` `.tsv` · `.iqy` (Internet Query) · `.slk` (Symbolic Link) |
| **Images** | `.jpg` `.jpeg` `.png` `.gif` `.bmp` `.webp` `.ico` `.tif` `.tiff` `.avif` — preview + steganography/polyglot detection |
| **SVG** | `.svg` — sandboxed preview + source view, deep SVG-specific security analysis (script extraction, foreignObject/form detection, event handlers, data URI payloads, animate href manipulation, XXE, obfuscation) |
| **Catch-all** | *Any file* — plain-text view with line numbers, or hex dump for binary data |

---

## 🔬 Security Analysis Capabilities

| Capability | Detail |
|---|---|
| **Risk assessment** | Colour-coded risk bar (low / medium / high / critical) with finding summary |
| **Document search** | In-toolbar search with match highlighting, match counter, and `Enter`/`Shift+Enter` navigation (`F` to focus) |
| **YARA rule engine** | In-browser YARA rule parser and matcher — upload custom `.yar` rule files (or drag-and-drop onto the dialog), validate them, save the combined rule set back out, and scan any loaded file with text, hex, and regex string support. Ships with 493 default detection rules (across 20 category files) that auto-scan on file load. Rule *source* must be authored in an external editor — there is no in-browser rule-editing surface |
| **File hashes** | MD5 · SHA-1 · SHA-256 computed in-browser, with one-click VirusTotal lookup |
| **IOC extraction** | URLs, email addresses, IP addresses, file paths, and UNC paths pulled from document content, VBA source, binary strings, and decoded payloads. Defanged indicators (`hxxp://`, `1[.]2[.]3[.]4`) are refanged automatically |
| **Parser safety limits** | Centralised `PARSER_LIMITS` enforces max nesting depth (32), max decompressed size (50 MB), per-entry compression-ratio abort (100×) to defeat zip bombs, archive entry cap (10 000), and a 60-second parser watchdog timeout that aborts runaway parsers |
| **VBA / macro analysis** | Extracts and syntax-highlights VBA source; flags auto-execute entry points (`AutoOpen`, `Workbook_Open`, `Shell`, etc.) |
| **Macro download** | Download decoded VBA as `.txt`, or the raw `vbaProject.bin` for offline analysis with olevba / oledump |
| **OOXML relationship scan** | Deep walk of `_rels/*.rels` across every OOXML part — surfaces external targets, remote-template injection (`attachedTemplate`), and embedded `oleObject` references that classic metadata extraction misses |
| **PDF scanning** | Detects `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, URIs, XFA forms, XMP metadata, explicit action lists (`/S /URI`, `/S /Launch`, etc.) and other risky operators via YARA rules. **Extracts JavaScript bodies** from `/JS` actions (literal strings, hex strings, and indirect stream references with `/FlateDecode`) with per-script trigger, size, SHA-256, and suspicious-API hints surfaced in the sidebar and a dedicated in-viewer banner; extract all scripts as a single `.js` file or individually. **Extracts embedded attachments** (`/EmbeddedFile` / `/Filespec`) keeping their raw bytes so you can download them or re-open them for recursive analysis in-place. **Extracts XFA form packets** (XML sub-streams of XFA-based forms) for inspection |
| **EML / email analysis** | Full RFC 5322/MIME parser — headers, multipart body, attachments, SPF/DKIM/DMARC auth results, tracking pixel detection |
| **LNK inspection** | MS-SHLLINK binary parser — target path, arguments, HotKey, shell-item chain, full ExtraData blocks, timestamps, dangerous-command detection, UNC credential-theft patterns, TrackerDataBlock machine-ID + MAC extraction, per-field IOC emission (each path/argument surfaces as its own sidebar row) |
| **HTA analysis** | Script extraction, `<HTA:APPLICATION>` attribute parsing, obfuscation detection, 40+ suspicious pattern checks |
| **MSI analysis** | Windows Installer parsing — CustomAction row parsing, Binary stream magic-sniffing, embedded CAB detection, Authenticode verdict, clickable stream drill-down, lazy stream loading to avoid memory crashes on large installers |
| **OneNote analysis** | Proper FileDataStoreObject parsing with MIME-sniffed embedded blobs, phishing-lure detection |
| **Script scanning** | Catch-all viewer scans `.vbs`, `.ps1`, `.bat`, `.rtf` and other script types for dangerous execution patterns + YARA matching |
| **Image analysis** | Steganography indicators, polyglot file detection, and hex header inspection for embedded payloads |
| **EVTX analysis** | Parses Windows Event Log binary format (ElfFile header, chunks, BinXml records); extracts Event ID, Level, Provider, Channel, Computer, timestamps, and EventData; flags suspicious events (4688, 4624/4625, 1102, 7045, 4104); extracts IOCs: usernames (`DOMAIN\User`), hostnames, IPs, process paths, command lines, hashes, URLs, file/UNC paths; Copy/Download as CSV |
| **SQLite / browser history** | Reads SQLite binary format (B-tree pages, schema, cell data); auto-detects Chrome/Edge/Firefox history databases; extracts URLs, titles, visit counts, timestamps; generic table browser for non-history SQLite files; Copy/Download as CSV |
| **PE / executable analysis** | Parses PE32/PE32+ (EXE, DLL, SYS, `.xll`, etc.) — DOS/COFF/Optional headers, section table with entropy analysis, imports with suspicious API flagging (~140 APIs across injection, anti-debug, credential theft, networking categories), exports, resources, Rich header, string extraction; security feature detection (ASLR, DEP, CFG, SEH, Authenticode); identifies Excel XLL add-ins, compiled AutoHotkey scripts, Inno Setup / NSIS installers, and Go-compiled binaries via export and overlay heuristics; 31 YARA rules for packers, malware toolkits (Cobalt Strike, Mimikatz, Metasploit), and suspicious API patterns |
| **ELF / Linux binary analysis** | Parses ELF32/ELF64 (LE/BE) — ELF header, program headers (segments), section headers, dynamic linking (NEEDED libraries, SONAME, RPATH/RUNPATH), symbol tables (imported/exported with suspicious symbol flagging), note sections (.note.gnu.build-id, .note.ABI-tag); security feature detection (RELRO, Stack Canary, NX, PIE, FORTIFY_SOURCE, RPATH/RUNPATH); Go-compiled binary detection (`go.buildinfo` / `runtime.goexit` / `\xff Go buildinf:` markers with module path + version when present); 18 YARA rules for Mirai botnet, cryptominers, reverse shells, LD_PRELOAD hijacking, rootkits, container escapes, packed binaries, and Go-compiled binaries |
| **ClickOnce deployment analysis** | Parses `.application` / `.manifest` XML — assembly identity, deployment codebase + `deploymentProvider`, entry point, trust info, `<Signature>` subject + thumbprint, dependent assemblies. Flags AppDomainManager hijacking, plain-HTTP deployment codebases, FullTrust permission requests, and dependent-assembly codebases on disposable infrastructure (free TLDs, tunnelers, paste sites). Non-ClickOnce `.manifest` XML falls through to the plaintext renderer. 4 YARA rules |
| **MSIX / APPX / App Installer analysis** | Parses `.msix` / `.msixbundle` / `.appx` / `.appxbundle` ZIP containers plus standalone `.appinstaller` XML — package Identity (Name, Publisher DN, Version, Architecture), Properties, Target Device Families, `<Capabilities>` split by risk tier (restricted `rescap:` such as `runFullTrust` / `broadFileSystemAccess`; device such as `webcam` / `microphone`; ordinary), Applications with Entry Points and Extensions (`windows.fullTrustProcess`, `windows.startupTask`, `windows.appExecutionAlias` — flags aliases squatting common OS commands like `powershell.exe`/`cmd.exe` — `windows.protocol`, `windows.fileTypeAssociation`, COM registrations, `windows.backgroundTasks`, services); for `AppxSignature.p7x` confirms the `PKCX` magic + DER PKCS#7 envelope, scans for the `AppxSipInfo` / `SpcIndirectDataContent` OIDs, extracts the signer Subject CN / O and compares them against the manifest's `Identity/@Publisher` DN (mismatch ⇒ repackaged / re-signed); also computes the canonical 13-character Windows PublisherId (SHA-256 of UTF-16LE publisher → first 8 bytes → 13 × 5-bit groups in the Crockford-style `0..9 a..z` alphabet) so the package's `PackageFamilyName` tail can be derived without installation; checks for `AppxBlockMap.xml` / `CodeIntegrity.cat`; for `.appinstaller` flags silent forced auto-updates and HTTP / suspicious-TLD update URIs. 9 YARA rules. Inner files are clickable for recursive analysis |
| **Browser extension analysis** | Parses Chrome `.crx` (v2 and v3 envelopes) and Firefox `.xpi` archives. For CRX v2, parses the `Cr24` header to extract the SubjectPublicKeyInfo public key and derives the Chrome extension ID (SHA-256 of SPKI, first 16 bytes, remapped to the `a..p` alphabet). For CRX v3, decodes the protobuf `CrxFileHeader` with a minimal in-tree wire-format reader — surfaces RSA-SHA256 / ECDSA-SHA256 signature counts, extracts the declared `crx_id` from the nested `SignedData` message, computes a Chrome extension ID from every embedded `AsymmetricKeyProof.public_key` (RSA and ECDSA), and flags any computed-vs-declared ID mismatch, malformed / empty headers, zero-signature headers, or non-16-byte declared IDs as risks. Both formats unwrap to a standard ZIP and parse `manifest.json` (Manifest V2 **or** V3) or legacy `install.rdf` — extension Name / Version / ID / author / description / update URL / CSP / Key, Manifest V3 `background.service_worker` vs V2 `background.scripts` / `persistent`, content scripts with matched URL patterns, `permissions` / `optional_permissions` / `host_permissions` tiered by risk (`nativeMessaging`, `<all_urls>`, `debugger`, `proxy`, `cookies`, `history`, `management`, `webRequest` + `webRequestBlocking`, `declarativeNetRequest`, `tabCapture`, etc.), `externally_connectable`, `web_accessible_resources`, `content_security_policy` (flags `unsafe-eval` / `unsafe-inline` / remote script hosts), `chrome_url_overrides`, and `update_url` (flags non-Chrome Web Store / non-Mozilla AMO update URLs). 12 YARA rules for native-messaging bridges, broad host permissions, unsafe-eval CSP, wide externally-connectable, debugger/management APIs, proxy + cookies/history combos, non-store update URLs, legacy XUL bootstrap, wide `web_accessible_resources`, and in-script `eval`. Inner files (manifest, scripts, icons) are clickable for recursive analysis |
| **Mach-O / macOS binary analysis** | Parses Mach-O 32/64-bit and Fat/Universal binaries — header, load commands, segments with section-level entropy, symbol tables (imported/exported with suspicious symbol flagging for ~30 macOS APIs), dynamic libraries, RPATH, code signature (CodeDirectory, entitlements, CMS), LC_BUILD_VERSION; security feature detection (PIE, NX Stack/Heap, Stack Canary, ARC, Code Signature, Hardened Runtime, Library Validation, Encrypted); 17 YARA rules for macOS stealers (Atomic, AMOS), reverse shells, RATs, privilege escalation, persistence (LaunchAgent/LoginItem), anti-debug/VM detection, and packed binaries |
| **Graceful binary fallback** | If PE / ELF / Mach-O parsing fails on a truncated or malformed file (bad header, missing sections, corrupted load commands), the renderer switches to a fallback view that still extracts ASCII strings and dumps the raw bytes — crucially, the extracted strings remain wired into the sidebar so IOC extraction, YARA scanning, and encoded-content detection keep running instead of the analyst being shown a bare "parsing error" |
| **X.509 certificate analysis** | Parses PEM/DER X.509 certificates and PKCS#12 containers — subject/issuer DN, validity period with expiry status, public key details (algorithm, key size, curve), extensions (SAN, Key Usage, Extended Key Usage, Basic Constraints, AKI/SKI, CRL Distribution Points, Authority Info Access, Certificate Policies), serial number, signature algorithm, SHA-1/SHA-256 fingerprints; flags self-signed certificates, expired/not-yet-valid, weak keys (<2048-bit RSA), weak signature algorithms (SHA-1/MD5), long validity periods, missing SAN, embedded private keys; IOC extraction from SANs, CRL/AIA URIs |
| **OpenPGP key analysis** | Parses ASCII-armored and binary OpenPGP data (RFC 4880 / RFC 9580) — enumerates packets, extracts key IDs, fingerprints, User IDs + embedded emails, subkeys, self-signatures and subkey bindings; decodes public-key algorithm (RSA/DSA/ECDSA/ECDH/EdDSA/X25519/Ed25519), key size and ECC curve; validates ASCII-armor CRC-24; flags unencrypted secret keys, weak key sizes, deprecated algorithms (Elgamal-sign-or-encrypt, v3 legacy), revoked/expired/long-lived keys, and SHA-1 as preferred hash. Parse-only — no signature verification or secret-key decryption |
| **JAR / Java analysis** | Parses JAR/WAR/EAR archives and standalone `.class` files — Java class file header (magic, version, constant pool), MANIFEST.MF with Main-Class and permissions, class listing with package tree, dependency extraction, constant pool string analysis with ~45 suspicious Java API patterns (deserialization, JNDI, reflection, command execution, networking) mapped to MITRE ATT&CK; obfuscation detection (Allatori, ZKM, ProGuard, short-name heuristics); clickable inner file extraction; 17 YARA rules for deserialization gadgets, JNDI injection, reverse shells, RAT patterns, cryptominers, security manager bypass, and credential theft |
| **SVG security analysis** | Parses SVG as XML with regex fallback — embedded `<script>` extraction (inline + external href), `<foreignObject>` detection (credential harvesting forms, password fields, iframes, embedded HTML), event handler scanning (~30 on* attributes), Base64/data URI payload analysis (script MIME types, decoded content inspection), URL extraction from attributes + `<style>` blocks, SVG-specific vectors (`<use>` external refs, `<animate>`/`<set>` href manipulation, `<feImage>` external filters), XML entity/DTD/XXE detection, JavaScript obfuscation patterns (eval, atob, fromCharCode, document.cookie, location redirect, fetch/XHR), meta refresh redirects; 18 YARA rules for SVG phishing (script injection, foreignObject forms, credential harvesting, Base64 payloads, event handlers, obfuscation, cookie theft, redirects, external resource loading, animate href manipulation, XXE, multi-indicator phishing) |
| **Encoded content detection** | Scans for Base64, hex, Base32 encoded blobs and compressed streams (gzip/zlib/deflate); decodes, classifies payloads (PE, script, URL list, etc.), extracts IOCs, and offers "Load for analysis" to drill into decoded content with breadcrumb navigation |
| **Deep deobfuscation drill-down** | The sidebar "Deobfuscated Findings" section walks the full `innerFindings` tree so every layer of a nested payload (e.g. Base64 → gzip → PowerShell → Base64 → URL) gets its own section labelled with the full decode chain. Identical layers (same chain + first 120 chars of decoded text) are deduped so re-wrapped payloads aren't emitted twice |
| **Archive drill-down** | Click entries inside ZIP/archive listings to open and analyse inner files, with Back navigation |
| **Document metadata** | Author, title, dates, revision count extracted from `docProps/core.xml` |

---

## 🎨 User Interface

| Feature | Detail |
|---|---|
| **Midnight Glass theme** | Premium dark mode with frosted-glass panels, gradient surfaces, and cyan accent highlights |
| **Theme picker** | Tile grid inside the ⚙ Settings dialog (`,`) exposing 6 themes — **Light**, **Dark** (default), **Midnight (OLED)** pure-black, **Solarized Dark** (warm low-glare), **Catppuccin Mocha** (dark, mauve-accented), and **Catppuccin Latte** (light, mauve-accented). Every surface in the app — renderers, sidebar, dialogs, risk chips, inline per-file colour hints — reads from a single set of CSS custom-property tokens (`--accent`, `--accent-rgb`, `--risk-high`, `--risk-high-rgb`, `--hairline-*`, `--bg-*`, `--text-*`) so a theme overlay flips the whole app with zero per-renderer work. Selection persists across reloads via `localStorage['loupe_theme']` and is applied **before first paint** by an inline `<head>` bootstrap that mirrors `_initTheme()` — no flash of unstyled / default-themed content when opening the file. First-boot users with no saved preference are matched to their OS `prefers-color-scheme` (Light / Dark), falling back to Dark. Themes are pluggable: each overlay lives in its own `src/styles/themes/<id>.css` file and is registered in the `THEMES` array in `src/app/app-ui.js` — no toolbar dropdown, the Settings dialog is the sole picker surface |
| **Settings / Help dialog** | `⚙` toolbar button (or `,` for Settings, `?` / `H` for Help) opens a unified two-tabbed modal. The **Settings** tab carries the theme picker and a **10-stop logarithmic Summary-size slider** (4 K → ∞ chars, default ~64 000 chars / ~16 K tokens) whose current budget is shown as a live chip inside the `⚡ Summary` button. The **Help** tab lists all keyboard shortcuts and offline/release links. Persistence keys: `localStorage['loupe_theme']`, `localStorage['loupe_summary_chars']`. The YARA rule dialog (`Y`) stays a separate surface so the rule viewer keeps its full-screen footprint |
| **Floating zoom controls** | Zoom 50–200% via a floating control that stays out of the way |
| **Click-and-drag panning** | Grab and drag to pan around rendered documents |
| **Collapsible sidebar** | Single-pane sidebar with collapsible `<details>` sections: File Info, Macros, Signatures & IOCs |
| **Resizable sidebar** | Drag the sidebar edge to resize (33–50% of the viewport) |
| **Breadcrumb navigation** | Drill-down path is shown as a clickable breadcrumb trail in the toolbar (e.g. `📦 archive.zip ▸ 📄 doc.docm ▸ 🔧 Module1.bas`). Click any crumb to jump directly to that layer; an overflow `… ▾` dropdown collapses deep trails so the trail stays on one line. The `✕` close button is anchored left of the trail so its position never shifts with filename length |
| **Keyboard shortcuts** | `S` toggle sidebar · `Y` YARA dialog · `,` Settings · `?` / `H` Help · `F` search document · `Ctrl+V` paste file for analysis · `Esc` close dialog / clear search |
| **Summary button** | `⚡ Summary` toolbar button copies a Markdown-formatted analysis report to the clipboard — File Info / Risk / Detections / IOCs / Macros / Deobfuscated layers / Format-specific deep data (PE/ELF/Mach-O/X.509/JAR/LNK · PDF JavaScripts + embedded files · MSI CustomActions · OneNote embedded objects · RTF OLE objects · EML/MSG attachments + auth-results · HTML credential forms · HTA/SVG active-content inventory · EVTX notable event IDs · SQLite schema · ZIP compression-ratio / zip-bomb indicators · ISO volume info · image EXIF · PGP key info · plist LaunchAgent persistence · osascript source + signatures · OOXML external relationships) — ready to paste into a ticket or LLM. The character budget is user-configurable in ⚙ Settings via a 10-stop logarithmic slider (4 K → ∞ chars, default ~64 000 chars / ~16 K tokens); the current budget is shown as a live chip inside the button (`16K`, `32K`, … `MAX`) and is persisted as `localStorage['loupe_summary_chars']`. The slider does more than raise the final truncation ceiling — a single `SCALE = budget / 64 K` multiplier is threaded through every per-renderer helper, so row caps (PE imports / exports / resources, ELF symbols / sections / dynamic, Mach-O symbols / dylibs / entitlements, EVTX events, SQLite rows, archive entries, JAR classes / dependencies / embedded JARs, X.509 SANs, EXIF tags, OOXML relationships, etc.), per-field text truncations, and metadata-tree depth all scale with the budget. At 4 K the report stays compact (depth-3 tree, short tables); at 64 K (default) you get the current report; at MAX (∞) nothing is truncated |
| **Export dropdown** | `📤 Export ▾` menu consolidates six actions: **Save raw file** (download) · **Copy raw content** · **Copy STIX 2.1 bundle (JSON)** · **Copy MISP event (JSON)** · **Copy IOCs as JSON** · **Copy IOCs as CSV**. Every action except Save-raw-file writes to the clipboard so you can paste straight into a ticket or TIP — the plaintext/Markdown report is already on the `⚡ Summary` button and isn't duplicated here. See the [Exports](#-exports) section for the format-by-content matrix |
| **Smart whole-token select** | Double-click inside any monospace viewer (URLs, hashes, base64 blobs, file paths, registry keys, PE imports, x509 fingerprints, plist leaves, etc.) selects the entire non-whitespace token — expanding past punctuation like `/`, `.`, `:`, `=`, `-`, `_` and across visual line wraps introduced by `word-break: break-all` — up to the nearest whitespace or block boundary |
| **Loading overlay** | Spinner with status message while parsing large files |
| **Toast notifications** | Non-intrusive feedback for downloads, clipboard operations, and errors |
| **Click-to-highlight** | Clicking any IOC or YARA match in the sidebar jumps to (and cycles through) matching occurrences in the viewer with yellow/blue `<mark>` highlights |
| **Forensic-safe email links** | `<a href>` inside EML / MSG messages is deliberately rendered as an inert `<span class="eml-link-inert">` — the visible anchor text and the underlying URL (exposed only as a hover `title` tooltip) stay inspectable, but clicking does nothing. Phishing URLs can be read and copied without the risk of accidental navigation |

---

## 📤 Exports

Loupe consolidates every "get this analysis out of the browser" action into a single **`📤 Export ▾`** dropdown in the viewer toolbar. All exports are generated entirely client-side — no network calls, no third-party services. The dropdown sits next to the one-shot **`⚡ Summary`** button, which handles the plaintext/Markdown analysis report (a 50 KB analyst-friendly summary with full per-format deep data) and stays separate so the dropdown doesn't have to duplicate it.

**Save raw file is the only true download in the dropdown — every other action writes to the clipboard** so the analyst's one-click flow is "Export → paste into ticket / TIP / jq pipeline".

### Export format × contents matrix

Columns are export formats; rows are the sections of the analysis. A ✅ means the export carries that data; a blank cell means it's deliberately omitted (usually because the target format has no idiomatic slot for it). Everything in this matrix other than the first two rows of "Summary" is emitted from the 📤 Export dropdown into the clipboard.

| Content section              | Summary (clipboard) | IOCs JSON (clipboard) | IOCs CSV (clipboard) | STIX 2.1 bundle (clipboard) | MISP event (clipboard) |
|------------------------------|:-------------------:|:---------------------:|:--------------------:|:---------------------------:|:----------------------:|
| File metadata (name, size, type) | ✅              | ✅                    |                      | ✅ (file SCO)               | ✅ (filename attr)     |
| File hashes (MD5/SHA-1/SHA-256) | ✅                | ✅                    |                      | ✅ (file SCO)               | ✅ (md5/sha1/sha256 attrs) |
| Risk level + summary          | ✅                  |                       |                      | ✅ (report desc)            | ✅ (threat_level_id + tag) |
| YARA / pattern detections     | ✅                  |                       |                      | ✅ (report)                 | ✅ (yara attrs)        |
| IOCs (URL / IP / domain / email / hash / path) | ✅ | ✅                    | ✅                   | ✅ (indicators)             | ✅ (attributes)        |
| VBA macro source              | ✅ (trimmed)        |                       |                      |                             |                        |
| Deobfuscated payload layers   | ✅ (trimmed)        |                       |                      |                             |                        |
| Format-specific deep data (PE / ELF / Mach-O / X.509 / JAR, email auth, LNK) | ✅ (trimmed) |        |                      |                             |                        |
| Size budget                   | 50 KB (clipboard)   | unlimited             | unlimited            | unlimited                   | unlimited              |

### Export menu actions

| # | Label                                   | Destination  | Notes                                                                                          |
|--:|-----------------------------------------|--------------|------------------------------------------------------------------------------------------------|
| 1 | 💾 Save raw file                        | **Download** | Writes the original loaded file back to disk (same behaviour as the legacy Save pill button). |
| 2 | 📋 Copy raw content                     | Clipboard    | Copies the file's raw bytes to the clipboard as UTF-8 text. The menu row is **automatically disabled** for binary formats (PE / ELF / Mach-O executables, JAR / `.class`, compiled `.scpt`, PDF, MSI, OLE2 / legacy Office, OOXML / ODF containers, archives, disk images, EVTX, SQLite, images, OneNote, DER / P12 / PFX, binary plist `bplist00`) — use `💾 Save raw file` for those, since the Web Clipboard's text channel would otherwise truncate at the first NUL byte or corrupt non-UTF-8 bytes. Eligibility is decided by a UTF-8 `fatal:true` decode **plus** an explicit denylist by detected format + extension, so a binary that happens to be valid UTF-8 (e.g. the FasTX bytes of a compiled AppleScript) still routes to the denylist instead of dumping opaque bytecode plus the viewer's extracted-strings view. For eligible text files the copy stashes the source bytes + filename so a follow-up `Ctrl+V` paste rehydrates the **exact original file** (identical SHA-256, original extension, original CRLF line endings) — the Web Clipboard's text channel normally normalises CRLF→LF, so without this round-trip the paste would produce a different hash and drop the extension-based format detection. |
| 3 | 🧾 Copy STIX 2.1 bundle (JSON)          | Clipboard    | Self-contained STIX 2.1 bundle (`identity` + `file` SCO + `indicator` per IOC + `malware-analysis` `report` SDO). Deterministic UUIDv5 IDs so re-exports dedupe in TIPs. |
| 4 | 🎯 Copy MISP event (JSON)               | Clipboard    | MISP v2 Event JSON — file-level attributes + per-IOC attributes (mapped to native MISP types) + `yara` attributes per rule hit + `tlp:clear` / `loupe:risk` / `loupe:detected-type` tags. |
| 5 | `{…}` Copy IOCs as JSON                 | Clipboard    | Flat JSON — file source record + sorted `iocs[{type,value,severity,note,source}]`. Ideal for scripting / jq. |
| 6 | 🔢 Copy IOCs as CSV                     | Clipboard    | RFC 4180 CSV — `type,value,severity,note,source`. Excel / LibreOffice friendly.                 |

### STIX 2.1 IOC → pattern mapping

| Loupe IOC type | STIX sub-type | Pattern                             |
|---|---|---|
| `URL`          | `url`         | `[url:value = '…']`                 |
| `IP Address` (IPv4 / IPv6) | `ipv4-addr` / `ipv6-addr` | `[ipv4-addr:value = '…']` / `[ipv6-addr:value = '…']` |
| `Hostname`     | `domain-name` | `[domain-name:value = '…']`         |
| `Email`        | `email-addr`  | `[email-addr:value = '…']`          |
| `Hash` (MD5 / SHA-1 / SHA-256) | `file`        | `[file:hashes.'MD5' = '…']` / `SHA-1` / `SHA-256` |
| `File Path` / `UNC Path` | `file`    | `[file:name = '<basename>']`        |
| Other (command lines, registry keys, usernames, MAC) | —    | omitted from STIX (still included in CSV / JSON / MISP as text). |

### MISP IOC → attribute mapping

| Loupe IOC type | MISP type    | Category          | `to_ids` |
|---|---|---|---|
| `URL`          | `url`        | Network activity  | true     |
| `IP Address`   | `ip-dst`     | Network activity  | true     |
| `Hostname`     | `domain`     | Network activity  | true     |
| `Email`        | `email-src`  | Payload delivery  | true     |
| `Hash` (md5 / sha1 / sha256) | `md5` / `sha1` / `sha256` | Payload delivery  | true     |
| `File Path` / `UNC Path` | `filename` | Payload delivery  | false    |
| YARA rule name | `yara`       | Payload delivery  | false    |
| Any other type | `text`       | Other             | false    |

IOCs with Loupe severity `info` always force `to_ids:false` regardless of type.

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

### Windows shell & forensics ([`examples/windows-shell/`](examples/windows-shell/), [`examples/forensics/`](examples/forensics/))

- [`example.lnk`](examples/windows-shell/example.lnk) — Windows shortcut with suspicious target path
- [`example.hta`](examples/windows-shell/example.hta) — HTML Application with embedded scripts
- [`example.evtx`](examples/forensics/example.evtx) / [`example-security.evtx`](examples/forensics/example-security.evtx) — Windows Event Logs (general + security events)
- [`chromehistory-example.sqlite`](examples/forensics/chromehistory-example.sqlite) — Chrome browsing history database

### Native binaries ([`examples/pe/`](examples/pe/), [`examples/elf/`](examples/elf/), [`examples/macho/`](examples/macho/))

- [`pe/example.exe`](examples/pe/example.exe) — Windows PE executable with imports, sections, and security features
- [`pe/signed-example.dll`](examples/pe/signed-example.dll) — Authenticode-signed DLL
- [`elf/example`](examples/elf/example) — Linux ELF binary with symbols, segments, and security checks
- [`macho/example`](examples/macho/example) — macOS Mach-O binary with load commands and code signature

### macOS scripts ([`examples/macos-scripts/`](examples/macos-scripts/))

- [`example.plist`](examples/macos-scripts/example.plist) — macOS property list with LaunchAgent/persistence key detection
- [`example.applescript`](examples/macos-scripts/example.applescript) — AppleScript source with macOS-specific security analysis
- [`example.scpt`](examples/macos-scripts/example.scpt) — compiled AppleScript binary (string extraction from opaque bytecode)
- [`example.jxa`](examples/macos-scripts/example.jxa) — JavaScript for Automation

### Certificates & PGP ([`examples/certificates/`](examples/certificates/), [`examples/pgp/`](examples/pgp/))

- [`example-selfsigned.pem`](examples/certificates/example-selfsigned.pem) — self-signed X.509 certificate with suspicious SANs
- [`example-with-key.pem`](examples/certificates/example-with-key.pem) — certificate with embedded private key + weak 1024-bit RSA key
- [`example-expired.crt`](examples/certificates/example-expired.crt) — expired X.509 certificate
- [`example.key`](examples/pgp/example.key) — OpenPGP key block (auto-detected via packet-header heuristics; `.key` is shared with X.509 PEM private keys)

### Web, Java & images ([`examples/web/`](examples/web/), [`examples/java/`](examples/java/), [`examples/images/`](examples/images/))

- [`example-malicious.svg`](examples/web/example-malicious.svg) — SVG with embedded scripts, foreignObject phishing form, event handlers, and data URI payloads
- [`example.jar`](examples/java/example.jar) — Java archive with class files, MANIFEST.MF, and constant pool analysis
- [`polyglot-example.png`](examples/images/polyglot-example.png) — PNG with a ZIP appended past the IEND marker

### Archives & MSI ([`examples/archives/`](examples/archives/), [`examples/msi/`](examples/msi/))

- [`example.zip`](examples/archives/example.zip), [`example.tar`](examples/archives/example.tar), [`example.tar.gz`](examples/archives/example.tar.gz), [`example.gz`](examples/archives/example.gz), [`example.iso`](examples/archives/example.iso) — archive/disk-image samples
- [`example.msi`](examples/msi/example.msi) — Windows Installer package
