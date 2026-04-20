# 🕵🏻 Loupe

**A 100% offline, single-file security analyser for suspicious files.**
No server, no uploads, no tracking — just drop a file and inspect it.

<p align="center">
  <a href="FEATURES.md">📖 Features</a> ·
  <a href="SECURITY.md">🔒 Security</a> ·
  <a href="CONTRIBUTING.md">🛠️ Contributing</a> ·
  <a href="VENDORED.md">📦 Vendored</a>
</p>

> **<a href="https://loupe.tools/" target="_blank" rel="noopener">▶ Launch the live demo</a>**


![License: MPL-2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)
![100% Offline](https://img.shields.io/badge/100%25-Offline-brightgreen)
![Single HTML File](https://img.shields.io/badge/Single_File-HTML-orange)
![Browser Based](https://img.shields.io/badge/Runs_In-Browser-blueviolet)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Loupe-tools/Loupe/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Loupe-tools/Loupe)

<p align="center">
<img src="screenshots/hero.png" alt="Loupe interface — 100% offline static analysis" width="800">
<br>
<em>Loupe — drop a file, inspect it safely, entirely in your browser.</em>
</p>

---

## 🤔 Why Loupe?

SOC analysts, incident responders, and security-conscious users need a way to safely inspect suspicious files without uploading them to third-party services or spinning up a sandbox. Loupe runs entirely in your browser — **nothing ever leaves your machine**.

- **Zero network access** — a strict Content-Security-Policy blocks all external fetches.
- **Single HTML file** — no install, no dependencies, works on any OS with a modern browser.
- **Broad format coverage** — Office documents, PDFs, emails, archives, native binaries (PE/ELF/Mach-O), certificates, scripts, images, and more.

---

## 🚀 Quick Start

[⬇️ **Download latest loupe.html**](https://github.com/Loupe-tools/Loupe/releases/latest/download/loupe.html)

1. **Download** — grab `loupe.html` from the release link above, or clone the repo and open `docs/index.html`.
2. **Open** — double-click the file in any modern browser (2023+: Chrome, Firefox, Edge, Safari). No server needed.
3. **Drop a file** — drag a suspicious file onto the drop zone, click **📁 Open File**, or paste with **Ctrl+V**.
4. **Inspect** — press **S** to toggle the security sidebar, **Y** for the YARA rules dialog, **?** for all shortcuts.

---

## ✅ Verify Your Download

Every release is signed with [Sigstore](https://www.sigstore.dev/) keyless signing — no long-lived key material, short-lived certificate issued by Fulcio to the release workflow's OIDC identity, transparency-log entry in Rekor. Each GitHub release ships three files:

| File | Purpose |
|---|---|
| `loupe.html` | The bundle itself |
| `loupe.html.sha256` | Plain-text SHA-256 for a quick eyeball check |
| `loupe.html.sigstore` | Sigstore bundle (certificate + signature + Rekor inclusion proof) |
| `loupe.cdx.json` | CycloneDX 1.5 SBOM — every vendored library with SHA-256 pin |
| `loupe.cdx.json.sigstore` | Sigstore bundle for the SBOM |

With [cosign](https://docs.sigstore.dev/cosign/installation/) installed, verify the bundle was built by the release workflow in this repository:

```bash
cosign verify-blob \
  --bundle loupe.html.sigstore \
  --certificate-identity "https://github.com/Loupe-tools/Loupe/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  loupe.html
```

A successful verification proves the exact bytes of `loupe.html` were produced by `.github/workflows/release.yml` in `Loupe-tools/Loupe` — it does **not** attest that the source is benign, only its provenance. See [SECURITY.md](SECURITY.md) for the full threat model.

You can also **rebuild the release yourself** from the tagged source and confirm your SHA-256 matches the signed asset — see [REPRODUCIBILITY.md](REPRODUCIBILITY.md) for the recipe.

---

## 🛡 Supported Formats

| Category | Extensions |
|---|---|
| **Office** | `.docx` `.docm` `.xlsx` `.xlsm` `.pptx` `.pptm` `.ods` `.doc` `.xls` `.ppt` `.odt` `.odp` `.rtf` |
| **Documents** | `.pdf` `.one` |
| **Email** | `.eml` `.msg` |
| **Web** | `.html` `.htm` `.mht` `.mhtml` `.xhtml` `.svg` |
| **Archives** | `.zip` `.gz` `.gzip` `.tar` `.tgz` `.rar` `.7z` `.cab` `.iso` `.img` |
| **Windows** | `.lnk` `.hta` `.url` `.webloc` `.website` `.reg` `.inf` `.sct` `.msi` `.exe` `.dll` `.sys` `.scr` `.cpl` `.ocx` `.drv` `.com` `.xll` `.application` `.manifest` `.msix` `.msixbundle` `.appx` `.appxbundle` `.appinstaller` |
| **Browser extensions** | `.crx` (Chrome / Chromium / Edge) · `.xpi` (Firefox / Thunderbird) |
| **Linux / IoT** | ELF binaries (`.so`, `.o`, `.elf`, extensionless) |
| **macOS** | Mach-O binaries (`.dylib`, `.bundle`, Fat/Universal) · `.applescript` `.scpt` `.scptd` `.jxa` `.plist` · `.dmg` `.pkg` `.mpkg` |
| **Certificates** | `.pem` `.der` `.crt` `.cer` `.p12` `.pfx` `.key` *(auto-disambiguated against PGP)* |
| **OpenPGP** | `.pgp` `.gpg` `.asc` `.sig` |
| **Java** | `.jar` `.war` `.ear` `.class` |
| **Scripts** | `.wsf` `.wsc` `.wsh` `.vbs` `.ps1` `.bat` `.cmd` `.js` |
| **Forensics** | `.evtx` `.sqlite` `.db` |
| **Data** | `.csv` `.tsv` `.iqy` `.slk` |
| **Images** | `.jpg` `.png` `.gif` `.bmp` `.webp` `.ico` `.tif` `.avif` |
| **Catch-all** | *Any file* — text or hex dump view |

Every format gets risk assessment, IOC extraction, and YARA scanning on top of the format-specific parser. See **[FEATURES.md](FEATURES.md)** for the full capability reference.

---

## 🔍 What It Finds

- **YARA rule engine** — 502 default rules auto-scan every file; drop in your own `.yar` files to extend detection.
- **IOCs** — URLs, IPs, emails, hostnames, domains, file paths, UNC paths, GUIDs, key fingerprints. Defanged indicators (`hxxp://`, `1[.]2[.]3[.]4`) are refanged automatically.
- **File hashes** — MD5, SHA-1, SHA-256 with one-click VirusTotal lookup.
- **Macros & scripts** — decoded VBA, PowerShell, JScript, HTA; auto-exec entry points flagged.
- **Encoded payload drill-down** — Base64 / hex / gzip / zlib layers decoded recursively with full lineage.
- **PDF internals** — embedded JavaScript, `/OpenAction`, `/Launch`, attachments, XFA forms.
- **Native binaries** — PE / ELF / Mach-O with imports, sections, entropy, security features, code signatures.
- **Certificates & keys** — X.509 and OpenPGP with weak-key and expiry flagging.
- **Archive drill-down** — click any entry inside a ZIP / TAR / ISO / MSI / PKG / CRX / CAB to open it with full analysis; RAR and 7-Zip listings surface filenames, flags and encryption signals.

- **Exports** — one-click clipboard brief for tickets or LLMs, plus STIX 2.1, MISP, and IOC JSON/CSV.

Plus six themes (Light / Dark / Midnight OLED / Solarized / Mocha / Latte), a resizable sidebar, in-toolbar document search, and click-to-highlight for every IOC and YARA match.

---

## 🎨 Themes

Six built-in themes, selectable from the **⚙ Settings** dialog — your choice persists.

<table align="center">
  <tr>
    <td align="center"><img src="screenshots/light_hero.png" alt="Loupe — Light theme" width="260"><br><b>☀️ Light</b></td>
    <td align="center"><img src="screenshots/dark_hero.png" alt="Loupe — Dark theme" width="260"><br><b>🌙 Dark</b></td>
    <td align="center"><img src="screenshots/midnight_hero.png" alt="Loupe — Midnight OLED theme" width="260"><br><b>🌑 Midnight OLED</b></td>
  </tr>
  <tr>
    <td align="center"><img src="screenshots/solarized_hero.png" alt="Loupe — Solarized theme" width="260"><br><b>🌅 Solarized</b></td>
    <td align="center"><img src="screenshots/mocha_hero.png" alt="Loupe — Mocha theme" width="260"><br><b>🌙 Mocha</b></td>
    <td align="center"><img src="screenshots/latte_hero.png" alt="Loupe — Latte theme" width="260"><br><b>☕ Latte</b></td>
  </tr>
</table>

<details>
<summary><sub>More screenshots — file viewer &amp; YARA dialog per theme</sub></summary>

<sub><b>☀️ Light</b></sub>
<p><img src="screenshots/light_1.png" alt="Light — file viewer 1" width="260"> <img src="screenshots/light_2.png" alt="Light — file viewer 2" width="260"> <img src="screenshots/light_yara.png" alt="Light — YARA dialog" width="260"></p>

<sub><b>🌙 Dark</b></sub>
<p><img src="screenshots/dark_1.png" alt="Dark — file viewer 1" width="260"> <img src="screenshots/dark_2.png" alt="Dark — file viewer 2" width="260"> <img src="screenshots/dark_yara.png" alt="Dark — YARA dialog" width="260"></p>

<sub><b>🌑 Midnight OLED</b></sub>
<p><img src="screenshots/midnight_1.png" alt="Midnight — file viewer 1" width="260"> <img src="screenshots/midnight_2.png" alt="Midnight — file viewer 2" width="260"> <img src="screenshots/midnight_yara.png" alt="Midnight — YARA dialog" width="260"></p>

<sub><b>🌅 Solarized</b></sub>
<p><img src="screenshots/solarized_1.png" alt="Solarized — file viewer 1" width="260"> <img src="screenshots/solarized_2.png" alt="Solarized — file viewer 2" width="260"> <img src="screenshots/solarized_yara.png" alt="Solarized — YARA dialog" width="260"></p>

<sub><b>🌙 Mocha</b></sub>
<p><img src="screenshots/mocha_1.png" alt="Mocha — file viewer 1" width="260"> <img src="screenshots/mocha_2.png" alt="Mocha — file viewer 2" width="260"> <img src="screenshots/mocha_yara.png" alt="Mocha — YARA dialog" width="260"></p>

<sub><b>☕ Latte</b></sub>
<p><img src="screenshots/latte_1.png" alt="Latte — file viewer 1" width="260"> <img src="screenshots/latte_2.png" alt="Latte — file viewer 2" width="260"> <img src="screenshots/latte_yara.png" alt="Latte — YARA dialog" width="260"></p>

</details>

---

## 🎬 Try It Yourself

Drop one of these into Loupe to see it in action — the [`examples/`](examples/) directory has many more.

- [`examples/encoded-payloads/nested-double-b64-ip.txt`](examples/encoded-payloads/nested-double-b64-ip.txt) — double Base64 hiding a C2 IP (recursive decode drill-down)
- [`examples/email/phishing-example.eml`](examples/email/phishing-example.eml) — SPF/DKIM/DMARC failures + tracking pixel
- [`examples/windows-scripts/example.lnk`](examples/windows-scripts/example.lnk) — Shell Link with per-field IOC extraction, MAC/MachineID
- [`examples/pe/signed-example.dll`](examples/pe/signed-example.dll) — Authenticode-signed DLL showing PE analysis + cert chain
- [`examples/forensics/example-security.evtx`](examples/forensics/example-security.evtx) — Windows security event log (auto-flags 4688 / 4624 / 1102)
- [`examples/macos-scripts/example.scpt`](examples/macos-scripts/example.scpt) — compiled AppleScript with string extraction from opaque bytecode
- [`examples/macos-system/example.pkg`](examples/macos-system/example.pkg) — flat macOS installer (xar) — install-script flagging, LaunchDaemon persistence detection
- [`examples/web/example-malicious.svg`](examples/web/example-malicious.svg) — script injection + foreignObject phishing form

Full guided tour: **[FEATURES.md → Example Files](FEATURES.md#-example-files-guided-tour)**.

---

## ⚠️ Limitations

Loupe is a **static-analysis triage tool** — it extracts, decodes, and displays file contents for human review but **does not execute** macros, JavaScript, scripts, or any embedded code. It is not a replacement for dynamic analysis sandboxes (e.g., Any.Run, Joe Sandbox) or full malware reverse-engineering workflows. For files that warrant deeper investigation, use Loupe for initial triage and IOC extraction, then escalate to a dedicated sandbox or disassembly environment.

---

## 🔒 Security Model

Loupe is designed to be safe to use on potentially malicious files:

- **Zero network** — strict `Content-Security-Policy` (`default-src 'none'`) blocks every outbound request. No telemetry, no CDNs, no analytics.
- **No code execution** — no `eval`, no `new Function`, no inline handlers from untrusted content.
- **Sandboxed previews** — HTML and SVG render inside `<iframe sandbox>` with an inner CSP, plus an always-active drag shield.
- **Zip-bomb & timeout defences** — centralised parser limits cap nesting depth, decompressed size, entry count, and wall-clock time per file.
- **Offline by design** — works identically with Wi-Fi off or in an air-gapped environment.

Full threat model, numeric limits, and vulnerability reporting: **[SECURITY.md](SECURITY.md)**.

---

## 🤝 Get Involved

Loupe is open source under the [Mozilla Public License 2.0](LICENSE).

- ⭐ **Star the repo** — helps others discover the project
- 🐛 **Open an issue** — bug reports, feature requests, and format support suggestions
- 🔀 **Submit a pull request** — YARA rule submissions, new format parsers, and improvements are especially welcome
- 📖 **See [CONTRIBUTING.md](CONTRIBUTING.md)** — build instructions, project structure, and architecture details for developers

The codebase is intentionally vanilla JavaScript (no frameworks, no bundlers) to keep the tool auditable and easy to understand.
