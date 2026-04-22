# 🕵🏻 Loupe

**A 100% offline, single-file security analyser for suspicious files.**
No server, no uploads, no tracking — just drop a file and inspect it.

<p align="center">
  <a href="FEATURES.md">📖 Features</a> ·
  <a href="SECURITY.md">🔒 Security</a> ·
  <a href="CONTRIBUTING.md">🛠️ Contributing</a>
</p>

> **<a href="https://loupe.tools/" target="_blank" rel="noopener">▶ Launch the live demo</a>**


![License: MPL-2.0](https://img.shields.io/badge/License-MPL%202.0-brightgreen.svg)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12604/badge)](https://www.bestpractices.dev/projects/12604)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Loupe-tools/Loupe/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Loupe-tools/Loupe)
![100% Offline](https://img.shields.io/badge/100%25-Offline-blueviolet)
![Single HTML File](https://img.shields.io/badge/Single_File-HTML-orange)



<p align="center">
<img src="screenshots/hero.png" alt="Loupe interface — 100% offline static analysis" width="800">
<br>
<em>Loupe — drop a file, inspect it safely, entirely in your browser.</em>
</p>

---

## 🤔 Why Loupe?

SOC analysts, MDR responders, phishing teams, and DFIR practitioners need a way to safely inspect suspicious files without uploading them to third-party services or spinning up a sandbox. Loupe runs entirely in your browser — **nothing ever leaves your machine**.

- **Zero network access** — a strict Content-Security-Policy blocks all external fetches.
- **Single HTML file** — no install, no dependencies, works on any OS with a modern browser.
- **Built for scripts and documents** — PowerShell, VBS, JScript, HTA, WSF, AppleScript / JXA, shell one-liners, Office, PDF, email, and archives get deep per-format analysis; recursive decoding peels nested Base64 / hex / gzip / zlib payloads layer by layer with the full lineage on screen.
- **Broad format coverage** — plus native binaries (PE / ELF / Mach-O), certificates, forensic artefacts (EVTX / SQLite), browser extensions, npm packages, and images.

---

## 🎯 When to reach for Loupe

- **Abuse mailbox:** a user-reported `.eml` / `.msg` lands in the queue — headers, SPF / DKIM / DMARC verdicts, tracking-pixel hosts, and every embedded URL are inspectable without a single click firing.
- **ClickFix / `osascript` paste:** an EDR alert surfaces an obfuscated one-liner — Base64 PowerShell, `curl … | sh`, or `osascript -e …`. Paste it straight in with `Ctrl+V` and Loupe peels every nested Base64 / hex / gzip / zlib layer with the full decode lineage on screen, surfacing the C2 URL, hashes, and file paths as one-click MISP / STIX attributes.
- **Host triage:** drop the `.evtx` from live response to auto-flag 4688 / 4624 / 1102 / 4104, or a browser `History.sqlite` to timeline a suspected compromise. Large CSV / TSV / EVTX auto-switch into **📈 Timeline mode** — scrubber, stacked-bar histogram, virtual grid and per-column top-value cards on one page.
- **Refang & pivot:** Just paste and Loupe will convert URL Defense / Safe links and refang `hxxp://` / `1[.]2[.]3[.]4` into live IOCs you can export without leaving the tab.
- **Airgap / compliance:** single HTML file, zero network — usable on a SCIF / classified / locked-down analyst VM where VirusTotal and Any.Run are off-limits.
- **Detection-content authoring:** drag a candidate `.yar` file onto Loupe to validate it against a corpus of samples before promoting to the production ruleset.

---

## 🚀 Quick Start


[⬇️ **Download latest loupe.html**](https://github.com/Loupe-tools/Loupe/releases/latest/download/loupe.html)

1. **Download** — grab `loupe.html` from the release link above, or clone the repo, run `python make.py`, and open `docs/index.html`.
2. **Open** — double-click the file in any modern browser (Chrome, Firefox, Edge, Safari). No server needed.
3. **Drop a file** — drag a suspicious file onto the drop zone, click **📁 Open File**, or paste with **Ctrl+V**.
4. *(optional)* **Verify it** — every release is Sigstore-signed and reproducible. See [SECURITY.md § Verify Your Download](SECURITY.md#verify-your-download).
5. **Inspect** — press **S** to toggle the security sidebar, **Y** for the YARA rules dialog, **?** for all shortcuts.

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
| **npm packages** | `.tgz` (npm-packed tarball) · `package.json` · `package-lock.json` / `npm-shrinkwrap.json` |
| **Linux / IoT** | ELF binaries (`.so`, `.o`, `.elf`, extensionless) |
| **macOS** | Mach-O binaries (`.dylib`, `.bundle`, Fat/Universal) · `.applescript` `.scpt` `.scptd` `.jxa` `.plist` · `.dmg` `.pkg` `.mpkg` |
| **Certificates** | `.pem` `.der` `.crt` `.cer` `.p12` `.pfx` `.key` |
| **OpenPGP** | `.pgp` `.gpg` `.asc` `.sig` |
| **Java** | `.jar` `.war` `.ear` `.class` |
| **Scripts** | `.wsf` `.wsc` `.wsh` `.vbs` `.ps1` `.bat` `.cmd` `.js` |
| **Forensics** | `.evtx` `.sqlite` `.db` |
| **Data** | `.csv` `.tsv` `.iqy` `.slk` |
| **Images** | `.jpg` `.png` `.gif` `.bmp` `.webp` `.ico` `.tif` `.avif` |
| **Catch-all** | *Any file* — text or hex dump view |

Every format gets risk assessment, IOC extraction, and YARA scanning on top of the format-specific parser. Full capability reference in **[FEATURES.md](FEATURES.md)**.

---

## 🔍 What It Finds

- **Scripts & one-liners** — PowerShell, VBS, JScript, HTA, WSF, AppleScript / JXA, and shell wrappers get syntax highlighting and are risk-scored against hundreds of dedicated YARA rules; auto-execute entry points are flagged.
- **Recursive decoder** — Base64 / hex / gzip / zlib layers unwind in-place with every hop visible as a coloured pill, so a ClickFix blob reveals its real payload without leaving the tab.
- **Office, PDF & email** — VBA and Excel-formula droppers decoded, OOXML external relationships surfaced, PDF `/JavaScript` / `/OpenAction` / `/Launch` / attachments extracted, `.eml` / `.msg` headers and SPF / DKIM / DMARC verdicts parsed.
- **IOCs** — URLs, IPs, emails, hostnames, domains, file paths, UNC paths, GUIDs, key fingerprints. Defanged indicators (`hxxp://`, `1[.]2[.]3[.]4`) are refanged automatically.
- **YARA rule engine** — 500+ default rules auto-scan every file; drop any `.yar` file onto Loupe to extend detection — rules are validated, saved locally, and rescans are instant.
- **File hashes** — MD5, SHA-1, SHA-256 with one-click VirusTotal lookup.
- **Native binaries** — PE / ELF / Mach-O with imports, sections, entropy, security features, and code-signature parsing for quick triage.
- **Certificates & keys** — X.509 and OpenPGP with weak-key and expiry flagging.
- **Recursive drill-down** — a macro inside a `.docm` inside a `.zip` inside a `.msi` — every layer gets its own full analysis with Back navigation and a breadcrumb trail.
- **Exports** — one-click clipboard brief for tickets or LLMs, plus STIX 2.1, MISP, and IOC JSON/CSV.
- **📈 Timeline mode** — a dedicated CSV / TSV / EVTX timeliner: scrubber, stacked-bar chart, virtual grid and per-column filter chips on one page, no sidebar.

Six themes, a resizable sidebar, in-toolbar document search, and click-to-highlight for every IOC and YARA match.

### Fits your workflow

Every export is generated client-side — paste directly into the next tool in your pipeline:

- **→ ticket / LLM:** one-shot **Summarize** copies a Markdown report to the clipboard, sized to ~16 K / 50 K / unlimited tokens.
- **→ TIP:** STIX 2.1 bundle or MISP event JSON, with deterministic UUIDs so re-imports dedupe cleanly.
- **→ CLI / spreadsheet:** flat JSON (jq-friendly) and RFC 4180 CSV for quick grep / pivot / triage runs.

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

- [`examples/encoded-payloads/nested-double-b64-ip.txt`](examples/encoded-payloads/nested-double-b64-ip.txt) — double Base64 hiding a C2 IP
- [`examples/email/phishing-example.eml`](examples/email/phishing-example.eml) — SPF/DKIM/DMARC failures + tracking pixel
- [`examples/windows-scripts/example.lnk`](examples/windows-scripts/example.lnk) — Shell Link with per-field IOC extraction
- [`examples/pe/signed-example.dll`](examples/pe/signed-example.dll) — Authenticode-signed DLL with PE analysis + cert chain
- [`examples/forensics/example-security.evtx`](examples/forensics/example-security.evtx) — Windows security event log (auto-flags 4688 / 4624 / 1102)
- [`examples/macos-system/example.pkg`](examples/macos-system/example.pkg) — flat macOS installer with install-script flagging
- [`examples/web/example-malicious.svg`](examples/web/example-malicious.svg) — script injection + foreignObject phishing form

Full guided tour: **[FEATURES.md → Example Files](FEATURES.md#-example-files-guided-tour)**.

---

## ⚠️ Limitations

Loupe is a **static-analysis triage tool** — it extracts, decodes, and displays file contents for human review but **does not execute** macros, JavaScript, scripts, or any embedded code. It is not a replacement for dynamic-analysis sandboxes (Any.Run, Joe Sandbox) or full reverse-engineering workflows. Use Loupe for initial triage and IOC extraction, then escalate to a sandbox or disassembly environment.

---

## 🔒 Security Model

- **Zero network** — strict `Content-Security-Policy` (`default-src 'none'`) blocks every outbound request. No telemetry, no CDNs, no analytics.
- **No code execution** — no `eval`, no `new Function`, sandboxed HTML/SVG previews.
- **Zip-bomb & timeout defences** — centralised parser limits cap nesting depth, decompressed size, entry count, and wall-clock time.

Full threat model, numeric limits, and vulnerability reporting: **[SECURITY.md](SECURITY.md)**.

---

## 🤝 Get Involved

Loupe is open source under the [Mozilla Public License 2.0](LICENSE).

- ⭐ **Star the repo** — helps others discover the project
- 🐛 **Open an issue** — bug reports, feature requests, and format support suggestions
- 🔀 **Submit a pull request** — YARA rules, new format parsers, and improvements are especially welcome
- 📖 **See [CONTRIBUTING.md](CONTRIBUTING.md)** — build instructions, gotchas, and conventions for developers

The codebase is vanilla JavaScript (no frameworks, no bundlers) to keep it auditable and easy to understand.
