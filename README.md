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

SOC analysts, MDR responders, phishing teams, and DFIR practitioners need to inspect suspicious files **without uploading them anywhere**. Loupe runs entirely in your browser — nothing ever leaves your machine.

- **Zero network, zero install.** A strict [Content-Security-Policy](SECURITY.md#full-content-security-policy) blocks every outbound request. One HTML file, double-click to open, works on any OS.
- **Forensics-grade depth in a triage tool.** [50+ formats](FEATURES.md#-supported-formats) with format-specific parsers, recursive deobfuscation, 500+ bundled YARA rules, and one-click STIX / MISP / clipboard export.
- **A timeline tool too.** CSV, TSV, EVTX, log files, packet captures, and browser-history SQLite open in the [📈 Timeline viewer](FEATURES.md#-timeline) — virtual grid for 1 M rows, scrubber + stacked-bar histogram, DSL query language, EVTX detections with MITRE ATT&CK pivots.
- **Verifiable supply chain.** Every release is [Sigstore-signed with SLSA v1.0 build provenance](SECURITY.md#verify-your-download), reproducible from source, and ships a CycloneDX SBOM.

---

## 🚀 Quick Start

[⬇️ **Download latest loupe.html**](https://github.com/Loupe-tools/Loupe/releases/latest/download/loupe.html)

1. **Download** — grab `loupe.html` from the release link above, or clone the repo, run `python make.py`, and open `docs/index.html`.
2. **Open** — double-click in any modern browser (Chrome, Firefox, Edge, Safari). No server.
3. **Drop a file** — drag a single file or a whole folder onto the drop zone, click **📁 Open File**, or paste with **Ctrl+V**. Multi-file drops and `webkitdirectory` picker selections are bundled into a single tree view; click any leaf to drill in.
4. *(optional)* **Verify** — every release is Sigstore-signed and reproducible. See [SECURITY.md § Verify Your Download](SECURITY.md#verify-your-download).
5. **Inspect** — press **S** for the security sidebar, **Y** for the YARA dialog, **?** for all shortcuts.

> Loupe is a **static-analysis triage tool** — it extracts, decodes, and displays file contents for human review. It does **not execute** macros, JavaScript, or embedded code. Use Loupe for initial triage and IOC extraction, then escalate to a sandbox or disassembly environment.

---

## 🎯 When to reach for Loupe

- **Abuse-mailbox triage** — drop a `.eml` or `.msg`; headers, SPF/DKIM/DMARC verdicts, tracking pixels, and embedded URLs are all inspectable, with anchors rendered inert so a hostile URL can't be navigated to by accident.
- **ClickFix / `osascript` paste** — paste an obfuscated one-liner with `Ctrl+V`; Loupe peels every nested Base64 / hex / gzip / zlib / XOR layer and surfaces the IOCs.
- **Host-triage timeline** — drop a `.evtx` to auto-flag 4688 / 4624 / 1102 / 4104 with MITRE ATT&CK pills. Browser `History.sqlite` opens into the same timeline.
- **Airgap / SCIF analyst VM** — single HTML, zero network, usable where VirusTotal and Any.Run are off-limits.

---

## 🛡 Supported Formats

Extensionless and renamed files are auto-routed by magic-byte sniff. Per-format detail in [FEATURES.md](FEATURES.md#-supported-formats).

| Category | Extensions |
|---|---|
| **Office** | `.docx` `.docm` `.xlsx` `.xlsm` `.pptx` `.pptm` `.doc` `.xls` `.ppt` `.ods` `.odt` `.odp` `.rtf` `.iqy` `.slk` |
| **PDF** | `.pdf` |
| **Email** | `.eml` `.msg` |
| **Web** | `.html` `.htm` `.mht` `.mhtml` `.xhtml` `.svg` |
| **Archives** | `.zip` `.gz` `.gzip` `.tar` `.tar.gz` `.tgz` `.rar` `.7z` `.cab` `.iso` `.img` |
| **OneNote** | `.one` |
| **Windows** | `.lnk` `.hta` `.url` `.webloc` `.website` `.reg` `.inf` `.sct` `.msi` `.exe` `.dll` `.sys` `.scr` `.cpl` `.ocx` `.drv` `.com` `.xll` `.application` `.manifest` `.msix` `.msixbundle` `.appx` `.appxbundle` `.appinstaller` |
| **Browser extensions** | `.crx` `.xpi` |
| **npm** | `.tgz` `package.json` `package-lock.json` `npm-shrinkwrap.json` |
| **Linux / IoT** | `.so` `.o` `.elf` |
| **macOS** | `.applescript` `.scpt` `.scptd` `.jxa` `.plist` `.dylib` `.bundle` `.dmg` `.pkg` `.mpkg` |
| **Certificates** | `.pem` `.der` `.crt` `.cer` `.p12` `.pfx` |
| **OpenPGP** | `.pgp` `.gpg` `.asc` `.sig` `.key` |
| **Java** | `.jar` `.war` `.ear` `.class` |
| **Scripts** | `.wsf` `.wsc` `.wsh` `.vbs` `.ps1` `.bat` `.cmd` `.js` |
| **Logs** | `.log` `.cef` `.leef` `.evtx` |
| **Network** | `.pcap` `.pcapng` `.cap` |
| **Data** | `.csv` `.tsv` `.json` `.ndjson` `.jsonl` `.sqlite` `.db` |
| **Images** | `.jpg` `.jpeg` `.png` `.gif` `.bmp` `.webp` `.ico` `.tif` `.tiff` `.avif` |

---

## 🎬 Try It Yourself

The [`examples/`](examples/) directory has a sample file for every supported format — see [`examples/README.md`](examples/README.md) for a guided tour.

---

## 🔍 What it looks like

<table align="center">
  <tr>
    <td align="center" width="50%">
      <a href="FEATURES.md#-security-sidebar"><img src="screenshots/analysis.png" alt="File analysis with security sidebar" width="400"></a><br>
      <b>🔬 File analysis</b><br>
      <sub>Security sidebar with format-specific findings, IOC clusters, and one-click STIX / MISP export.</sub>
    </td>
    <td align="center" width="50%">
      <a href="FEATURES.md#-yara-rules"><img src="screenshots/yara.png" alt="YARA rule editor" width="400"></a><br>
      <b>🔎 YARA rules</b><br>
      <sub>500+ bundled rules plus a live editor for your own rule packs — all evaluated in-browser.</sub>
    </td>
  </tr>
</table>

<p align="center">
  <a href="FEATURES.md#-timeline"><img src="screenshots/timeline.png" alt="Timeline view of a CSV with stacked-bar histogram" width="800"></a><br>
  <b>📈 Timeline</b><br>
  <sub>Million-row virtual grid for CSV / TSV / EVTX / PCAP / log files / browser SQLite, with stacked-bar histogram and a query DSL.</sub>
</p>

---

## 🎨 Themes

Six built-in themes, selectable from the **◐ Themes** tab (`T`) in the Settings dialog — your choice persists.

<table align="center">
  <tr>
    <td align="center"><img src="screenshots/light_hero.png" alt="Loupe — Light theme" width="260"><br><b>☀️ Light</b></td>
    <td align="center"><img src="screenshots/dark_hero.png" alt="Loupe — Dark theme" width="260"><br><b>🌙 Dark</b></td>
    <td align="center"><img src="screenshots/midnight_hero.png" alt="Loupe — Midnight OLED theme" width="260"><br><b>🌑 Midnight OLED</b></td>
  </tr>
  <tr>
    <td align="center"><img src="screenshots/solarized_hero.png" alt="Loupe — Solarized theme" width="260"><br><b>🟡 Solarized</b></td>
    <td align="center"><img src="screenshots/mocha_hero.png" alt="Loupe — Mocha theme" width="260"><br><b>🌺 Mocha</b></td>
    <td align="center"><img src="screenshots/latte_hero.png" alt="Loupe — Latte theme" width="260"><br><b>🍵 Latte</b></td>
  </tr>
</table>

---

## 🔒 Security Model

Strict CSP (`default-src 'none'`), no `eval` / `new Function`, sandboxed HTML & SVG previews, centralised parser limits against zip-bombs and runaway parsers. Full threat model, numeric limits, signature-verification recipe, and vulnerability reporting → **[SECURITY.md](SECURITY.md)**.

---

## 🤝 Get Involved

Loupe is open source under the [Mozilla Public License 2.0](LICENSE). The codebase is vanilla JavaScript — no frameworks, no bundlers — to keep it auditable.

- ⭐ **Star the repo** — helps others discover the project.
- 🐛 **Open an issue** — bug reports, feature requests, format support suggestions.
- 🔀 **Submit a pull request** — YARA rules, new format parsers, and improvements are especially welcome.
- 📖 **See [CONTRIBUTING.md](CONTRIBUTING.md)** — build instructions, gotchas, and conventions.
