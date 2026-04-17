# Vendored Libraries

Loupe is **fully offline** — no npm, no lockfile, no CDN. Every third-party
JavaScript library is committed under [`vendor/`](vendor/) and inlined into
[`docs/index.html`](docs/index.html) at build time.

This file pins the **exact bytes** of each vendored library by SHA-256.
Any upgrade must rotate the corresponding hash here, so every supply-chain
change is visible in `git diff`.

| File | Version | Licence | SHA-256 | Upstream |
|---|---|---|---|---|
| `vendor/highlight.min.js` | Highlight.js **v11.9.0** (git `f47103d4f1`) | BSD-3-Clause | `d2581b9e0ea408beb5b73cd468eefff939f720979343c1d54c401a1c58395a0f` | https://github.com/highlightjs/highlight.js |
| `vendor/jszip.min.js` | JSZip **v3.10.1** | MIT **or** GPL-3.0 (dual) | `acc7e41455a80765b5fd9c7ee1b8078a6d160bbbca455aeae854de65c947d59e` | https://github.com/Stuk/jszip |
| `vendor/pdf.min.js` | pdf.js (Mozilla) **v3.11.174** | Apache-2.0 | `5b5799e6f8c680663207ac5b42ee14eed2a406fa7af48f50c154f0c0b1566946` | https://github.com/mozilla/pdf.js |
| `vendor/pdf.worker.min.js` | pdf.js worker **v3.11.174** | Apache-2.0 | `feabdf309770ed24bba31a5467836cdc8cf639c705af27d52b585b041bb8527b` | https://github.com/mozilla/pdf.js |
| `vendor/xlsx.full.min.js` | SheetJS Community Edition **v1.15.0** | Apache-2.0 | `c9506197caf809a075b6dee1da0d36fb19da7158ffe8a88e7b0c96c5d8623c99` | https://github.com/SheetJS/sheetjs |

## Verifying

Compare the live file hash against the table above:

```powershell
# Windows / PowerShell
Get-FileHash -Algorithm SHA256 vendor\*.js
```

```bash
# Linux / macOS
sha256sum vendor/*.js
```

A mismatch means a vendored file has been altered since its pinned release —
treat it as a potential supply-chain incident and investigate the diff before
building, shipping, or merging.

## Upgrading a library

1. Replace the file in `vendor/` with the new upstream release.
2. Recompute its SHA-256 with the command above.
3. Update the matching row here (version + hash).
4. Rebuild: `python build.py`.
5. Commit the vendor file, the `VENDORED.md` change, and the rebuilt
   `docs/index.html` together so reviewers see one atomic supply-chain update.

## Adding a new library

1. Place the upstream release bytes under `vendor/<name>.js` — **do not modify**.
2. Read and inline the file in `build.py` alongside the other vendor reads.
3. Add a new row to the table above with version, licence, SHA-256, and
   upstream URL. A vendor change without a `VENDORED.md` change is a broken
   commit.
