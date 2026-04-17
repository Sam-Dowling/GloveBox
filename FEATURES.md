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
- [Example Files (guided tour)](#-example-files-guided-tour)

---

## 🛡 Supported Formats (full reference)

| Category | Extensions |
|---|---|
| **Office (modern)** | `.docx` `.docm` `.xlsx` `.xlsm` `.pptx` `.pptm` `.ods` |
| **Office (legacy)** | `.doc` `.xls` `.ppt` |
| **OpenDocument** | `.odt` (text) · `.odp` (presentation) |
| **RTF** | `.rtf` — text extraction + OLE/exploit analysis |
| **PDF** | `.pdf` |
| **Email** | `.eml` `.msg` |
| **HTML** | `.html` `.htm` `.mht` — sandboxed preview + source view |
| **Archives** | `.zip` `.gz` `.tar` `.tar.gz`/`.tgz` `.rar` `.7z` `.cab` — content listing, threat flagging, clickable entry extraction, gzip decompression, TAR parsing, ZipCrypto decryption, hex dump fallback for unsupported formats |
| **Disk images** | `.iso` `.img` — ISO 9660 filesystem listing |
| **OneNote** | `.one` — embedded object extraction + phishing detection |
| **Windows** | `.lnk` (Shell Link) · `.hta` (HTML Application) · `.url` `.webloc` (Internet shortcuts) · `.reg` (Registry) · `.inf` (Setup Information) · `.sct` (Script Component) · `.msi` (Installer) · `.exe` `.dll` `.sys` `.scr` `.cpl` `.ocx` `.drv` (PE executables) |
| **Linux / IoT** | ELF binaries (`.so` shared libraries, `.o` object files, extensionless executables) — ELF32/ELF64, LE/BE |
| **macOS** | Mach-O binaries (`.dylib` dynamic libraries, `.bundle` plugins, extensionless executables, Fat/Universal) — 32/64-bit |
| **macOS Scripts** | `.applescript` `.scpt` `.jxa` (AppleScript source, compiled AppleScript, JavaScript for Automation) — source display, compiled binary string extraction, macOS-specific security analysis |
| **macOS Property Lists** | `.plist` (XML and binary plist) — tree view with expandable nested structures, LaunchAgent/Daemon detection, persistence key analysis, suspicious pattern flagging, 21 YARA rules for plist threats |
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
| **Document search** | In-toolbar search with match highlighting, match counter, and `Enter`/`Shift+Enter` navigation (`Ctrl+F` to focus) |
| **YARA rule engine** | In-browser YARA rule parser and matcher — upload custom `.yar` rule files (or drag-and-drop onto the dialog), validate them, save the combined rule set back out, and scan any loaded file with text, hex, and regex string support. Ships with 450+ default detection rules (across 16 category files) that auto-scan on file load. Rule *source* must be authored in an external editor — there is no in-browser rule-editing surface |
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
| **PE / executable analysis** | Parses PE32/PE32+ (EXE, DLL, SYS, etc.) — DOS/COFF/Optional headers, section table with entropy analysis, imports with suspicious API flagging (~140 APIs across injection, anti-debug, credential theft, networking categories), exports, resources, Rich header, string extraction; security feature detection (ASLR, DEP, CFG, SEH, Authenticode); 27 YARA rules for packers (UPX, Themida, VMProtect), malware toolkits (Cobalt Strike, Mimikatz, Metasploit), and suspicious API patterns |
| **ELF / Linux binary analysis** | Parses ELF32/ELF64 (LE/BE) — ELF header, program headers (segments), section headers, dynamic linking (NEEDED libraries, SONAME, RPATH/RUNPATH), symbol tables (imported/exported with suspicious symbol flagging), note sections (.note.gnu.build-id, .note.ABI-tag); security feature detection (RELRO, Stack Canary, NX, PIE, FORTIFY_SOURCE, RPATH/RUNPATH); 17 YARA rules for Mirai botnet, cryptominers, reverse shells, LD_PRELOAD hijacking, rootkits, container escapes, and packed binaries |
| **Mach-O / macOS binary analysis** | Parses Mach-O 32/64-bit and Fat/Universal binaries — header, load commands, segments with section-level entropy, symbol tables (imported/exported with suspicious symbol flagging for ~30 macOS APIs), dynamic libraries, RPATH, code signature (CodeDirectory, entitlements, CMS), LC_BUILD_VERSION; security feature detection (PIE, NX Stack/Heap, Stack Canary, ARC, Code Signature, Hardened Runtime, Library Validation, Encrypted); 18 YARA rules for macOS stealers (Atomic, AMOS), reverse shells, RATs, privilege escalation, persistence (LaunchAgent/LoginItem), anti-debug/VM detection, and packed binaries |
| **Graceful binary fallback** | If PE / ELF / Mach-O parsing fails on a truncated or malformed file (bad header, missing sections, corrupted load commands), the renderer switches to a fallback view that still extracts ASCII strings and dumps the raw bytes — crucially, the extracted strings remain wired into the sidebar so IOC extraction, YARA scanning, and encoded-content detection keep running instead of the analyst being shown a bare "parsing error" |
| **X.509 certificate analysis** | Parses PEM/DER X.509 certificates and PKCS#12 containers — subject/issuer DN, validity period with expiry status, public key details (algorithm, key size, curve), extensions (SAN, Key Usage, Extended Key Usage, Basic Constraints, AKI/SKI, CRL Distribution Points, Authority Info Access, Certificate Policies), serial number, signature algorithm, SHA-1/SHA-256 fingerprints; flags self-signed certificates, expired/not-yet-valid, weak keys (<2048-bit RSA), weak signature algorithms (SHA-1/MD5), long validity periods, missing SAN, embedded private keys; IOC extraction from SANs, CRL/AIA URIs |
| **OpenPGP key analysis** | Parses ASCII-armored and binary OpenPGP data (RFC 4880 / RFC 9580) — enumerates packets (Public-Key, Secret-Key, Public/Secret-Subkey, User ID, Signature, etc.), extracts key IDs and fingerprints, user IDs with embedded email addresses, subkeys, self-signatures and subkey bindings; decodes public-key algorithm (RSA/DSA/ECDSA/ECDH/EdDSA/X25519/Ed25519), key size and ECC curve; validates ASCII-armor CRC-24 checksums; flags unencrypted secret keys (S2K usage = 0), passphrase-protected private keys present in file, weak key sizes (<1024, <2048), deprecated Elgamal-sign-or-encrypt (algo 20), v3 legacy keys, revoked/expired primary keys, long-lived keys without expiry, SHA-1 as preferred hash; extracts email IOCs from User IDs. Parse-only — no signature verification, no decryption of protected secret keys |
| **JAR / Java analysis** | Parses JAR/WAR/EAR archives and standalone `.class` files — Java class file header (magic, version, constant pool), MANIFEST.MF with Main-Class and permissions, class listing with package tree, dependency extraction, constant pool string analysis with ~45 suspicious Java API patterns (deserialization, JNDI, reflection, command execution, networking) mapped to MITRE ATT&CK; obfuscation detection (Allatori, ZKM, ProGuard, short-name heuristics); clickable inner file extraction; 18 YARA rules for deserialization gadgets, JNDI injection, reverse shells, RAT patterns, cryptominers, security manager bypass, and credential theft |
| **SVG security analysis** | Parses SVG as XML with regex fallback — embedded `<script>` extraction (inline + external href), `<foreignObject>` detection (credential harvesting forms, password fields, iframes, embedded HTML), event handler scanning (~30 on* attributes), Base64/data URI payload analysis (script MIME types, decoded content inspection), URL extraction from attributes + `<style>` blocks, SVG-specific vectors (`<use>` external refs, `<animate>`/`<set>` href manipulation, `<feImage>` external filters), XML entity/DTD/XXE detection, JavaScript obfuscation patterns (eval, atob, fromCharCode, document.cookie, location redirect, fetch/XHR), meta refresh redirects; 19 YARA rules for SVG phishing (script injection, foreignObject forms, credential harvesting, Base64 payloads, event handlers, obfuscation, cookie theft, redirects, external resource loading, animate href manipulation, XXE, multi-indicator phishing) |
| **Encoded content detection** | Scans for Base64, hex, Base32 encoded blobs and compressed streams (gzip/zlib/deflate); decodes, classifies payloads (PE, script, URL list, etc.), extracts IOCs, and offers "Load for analysis" to drill into decoded content with breadcrumb navigation |
| **Deep deobfuscation drill-down** | The sidebar "Deobfuscated Findings" section walks the full `innerFindings` tree so every layer of a nested payload (e.g. Base64 → gzip → PowerShell → Base64 → URL) gets its own section labelled with the full decode chain. Identical layers (same chain + first 120 chars of decoded text) are deduped so re-wrapped payloads aren't emitted twice |
| **Archive drill-down** | Click entries inside ZIP/archive listings to open and analyse inner files, with Back navigation |
| **Document metadata** | Author, title, dates, revision count extracted from `docProps/core.xml` |

---

## 🎨 User Interface

| Feature | Detail |
|---|---|
| **Midnight Glass theme** | Premium dark mode with frosted-glass panels, gradient surfaces, and cyan accent highlights |
| **Theme picker** | Click the theme icon in the toolbar (🌙 / ☀ / 🌑 / 🟡) for a vertical dropdown of 4 themes — **Light**, **Dark** (default), **Midnight (OLED)** pure-black, and **Solarized Dark** (warm low-glare). Selection persists across reloads via `localStorage['loupe_theme']`. Themes are pluggable: each overlay lives in its own `src/styles/themes/<id>.css` file and is registered in the `THEMES` array in `src/app/app-ui.js` |
| **Floating zoom controls** | Zoom 50–200% via a floating control that stays out of the way |
| **Click-and-drag panning** | Grab and drag to pan around rendered documents |
| **Collapsible sidebar** | Single-pane sidebar with collapsible `<details>` sections: File Info, Macros, Signatures & IOCs |
| **Resizable sidebar** | Drag the sidebar edge to resize (33–50% of the viewport) |
| **Keyboard shortcuts** | `S` toggle sidebar · `Y` YARA dialog · `?`/`H` help & about · `Ctrl+F` search document · `Ctrl+V` paste file for analysis |
| **Smart whole-token select** | Double-click inside any monospace viewer (URLs, hashes, base64 blobs, file paths, registry keys, PE imports, x509 fingerprints, plist leaves, etc.) selects the entire non-whitespace token — expanding past punctuation like `/`, `.`, `:`, `=`, `-`, `_` and across visual line wraps introduced by `word-break: break-all` — up to the nearest whitespace or block boundary |
| **Loading overlay** | Spinner with status message while parsing large files |
| **Toast notifications** | Non-intrusive feedback for downloads, clipboard operations, and errors |
| **Click-to-highlight** | Clicking any IOC or YARA match in the sidebar jumps to (and cycles through) matching occurrences in the viewer with yellow/blue `<mark>` highlights |
| **Forensic-safe email links** | `<a href>` inside EML / MSG messages is deliberately rendered as an inert `<span class="eml-link-inert">` — the visible anchor text and the underlying URL (exposed only as a hover `title` tooltip) stay inspectable, but clicking does nothing. Phishing URLs can be read and copied without the risk of accidental navigation |

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
