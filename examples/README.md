# Loupe Examples — Guided Tour

This directory contains sample files for every supported format, grouped by category. Drag any of them into [`docs/index.html`](../docs/index.html) (or the released [`loupe.html`](https://github.com/Loupe-tools/Loupe/releases/latest/download/loupe.html)) to see Loupe in action — every analysis runs entirely in your browser, fully offline.

Headline samples are listed below; each subdirectory contains more.

## Encoded payloads ([`encoded-payloads/`](encoded-payloads/))

- [`nested-double-b64-ip.txt`](encoded-payloads/nested-double-b64-ip.txt) — double Base64-encoded PowerShell with hidden C2 IP
- [`encoded-zlib-base64.txt`](encoded-payloads/encoded-zlib-base64.txt) — nested encoded content with compressed payloads
- [`mixed-obfuscations.txt`](encoded-payloads/mixed-obfuscations.txt) — combined obfuscation techniques

## Office, PDF & email

- [`office/example.docm`](office/example.docm) — macro-enabled Word document with AutoOpen + Shell VBA
- [`office/example.xlsm`](office/example.xlsm) — macro-enabled Excel workbook
- [`pdf/javascript-example.pdf`](pdf/javascript-example.pdf) — PDF with `/OpenAction` triggering embedded JavaScript
- [`email/phishing-example.eml`](email/phishing-example.eml) — phishing email with SPF/DKIM/DMARC failures and a tracking pixel

## Windows scripts, shortcuts & installers

- [`windows-scripts/example.lnk`](windows-scripts/example.lnk) — Windows shortcut with suspicious target path
- [`windows-scripts/example.hta`](windows-scripts/example.hta) — HTML Application with embedded scripts
- [`windows-scripts/ps-obfuscation.ps1`](windows-scripts/ps-obfuscation.ps1), [`encoded-powershell.bat`](windows-scripts/encoded-powershell.bat) — obfuscated PowerShell / cmd
- [`windows-installers/example.msi`](windows-installers/example.msi) — Windows Installer (CustomActions, embedded CAB, Authenticode)
- [`windows-installers/malicious-example.application`](windows-installers/malicious-example.application) — ClickOnce deployment manifest with hijack indicators

## Forensics & native binaries

- [`forensics/example-security.evtx`](forensics/example-security.evtx) — Windows Security log (auto-flags 4688 / 4624 / 1102) — opens straight in Timeline
- [`forensics/chromehistory-example.sqlite`](forensics/chromehistory-example.sqlite) — Chrome browsing history → Timeline
- [`forensics/example-capture.pcap`](forensics/example-capture.pcap) — libpcap capture with DNS / HTTP / TLS-SNI hostname extraction
- [`pe/signed-example.dll`](pe/signed-example.dll) — Authenticode-signed DLL with PE analysis + cert chain
- [`pe/tls-callback.exe`](pe/tls-callback.exe) — minimal PE32 with a TLS callback (T1546.009)
- [`pe/rcdata-dropper.exe`](pe/rcdata-dropper.exe) — PE with a second PE embedded as a resource (T1027.009)
- [`pe/overlay-post-authenticode.exe`](pe/overlay-post-authenticode.exe) — signed PE with bytes appended *past* the Authenticode blob — flags **T1553.002 (critical)**
- [`elf/example`](elf/example) — Linux ELF with symbols, segments, security checks
- [`macos-system/example.dylib`](macos-system/example.dylib) — Mach-O with load commands and code signature

## macOS scripts, system & installers

- [`macos-scripts/example.applescript`](macos-scripts/example.applescript) — AppleScript source with macOS-specific security analysis
- [`macos-system/example.plist`](macos-system/example.plist) — XML property list with LaunchAgent / persistence detection
- [`macos-system/example.dmg`](macos-system/example.dmg) — Apple Disk Image with partition + `.app` enumeration
- [`macos-system/example.pkg`](macos-system/example.pkg) — flat PKG (xar) installer with pre/post-install script flagging

## Crypto, web, Java & images

- [`crypto/example-selfsigned.pem`](crypto/example-selfsigned.pem) — self-signed X.509 certificate with suspicious SANs
- [`crypto/example-with-key.pem`](crypto/example-with-key.pem) — certificate with embedded private key + weak 1024-bit RSA key
- [`crypto/example.pgp`](crypto/example.pgp), [`example.asc`](crypto/example.asc) — binary + ASCII-armored OpenPGP packet streams
- [`web/example-malicious.svg`](web/example-malicious.svg) — SVG with embedded scripts, `<foreignObject>` phishing form
- [`web/example.wasm`](web/example.wasm) — WebAssembly module with network/eval-bridge and WASI process-spawn imports
- [`java/example.jar`](java/example.jar) — Java archive with class files and constant pool analysis
- [`images/polyglot-example.png`](images/polyglot-example.png) — PNG with a ZIP appended past the IEND marker

## Browser extensions & archives

- [`browser-extensions/suspicious-chrome.crx`](browser-extensions/suspicious-chrome.crx) — `nativeMessaging`, `<all_urls>`, `unsafe-eval` CSP, non-store update URL
- [`browser-extensions/ublock-example.xpi`](browser-extensions/ublock-example.xpi) — real-world uBlock Origin XPI
- [`archives/recursive-example.zip`](archives/recursive-example.zip) — nested-archive ZIP (drill-down depth)
- [`archives/encrypted-example.zip`](archives/encrypted-example.zip) — ZipCrypto-encrypted entries
- [`archives/example.iso`](archives/example.iso) — ISO 9660 with clickable filesystem drill-down
