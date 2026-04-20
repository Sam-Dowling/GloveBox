# Security Policy

> - For end-user documentation see [README.md](README.md).
> - For the full format / capability / example reference see [FEATURES.md](FEATURES.md).
> - For build instructions and developer docs see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Threat Model

Loupe is a **100 % offline, single-file HTML security analyser**. Its threat
model is deliberately narrow:

| Property | Guarantee |
|----------|-----------|
| **No network access** | A strict `Content-Security-Policy` (`default-src 'none'`) blocks all outbound requests — fetch, XHR, WebSocket, `<img src="https://…">`, `<script src>`, etc. No telemetry, no analytics, no CDN loads. |
| **No server component** | The tool runs entirely inside a single HTML file opened with `file://` or a static host. There is no backend, no API, no database. |
| **No code evaluation** | `eval()`, `new Function()`, and inline event handlers from untrusted content are never used. |
| **Sandboxed previews** | HTML and SVG previews are rendered inside `<iframe sandbox="allow-same-origin" srcdoc="…">` with an inner CSP of `default-src 'none'`. `allow-same-origin` is kept only so the inner CSP meta tag can govern the frame's own origin; every other sandbox permission (scripts, forms, popups, top-navigation, pointer-lock, etc.) is revoked by omission. Script execution, form submission, and navigation are all blocked inside the preview frame. |
| **Parser safety limits** | Centralised `PARSER_LIMITS` constants enforce: max nesting depth (32, gated across every recursive traversal — `app-load` drill-down plus `archive-tree`, `cab`, `rar`, `seven7`, `iso`, and `plist`), max decompressed size (50 MB), per-entry compression-ratio abort (100×), archive entry cap (10 000, enforced in every archive-like renderer — `zip`, `iso`, `msix`, `cab`, `rar`, `seven7`, `browserext`), and a 60-second parser timeout. `ParserWatchdog.run()` wraps the entire renderer dispatch in `app-load.js`, not just the initial `file.arrayBuffer()` read, so every format parser inherits the timeout. |

### What Loupe does **not** protect against

- **Browser zero-days** — if the browser's own HTML/CSS/image parsers have
  vulnerabilities, Loupe inherits them (as does every web page).
- **Denial-of-service via CPU** — a synchronous parser that enters a tight
  loop cannot be interrupted by the main-thread timeout watchdog; it will
  eventually be killed by the browser's own tab-crash heuristics.
- **Side-channel attacks** — Spectre-class timing side-channels are out of
  scope for a file-analysis tool.

---

## Supported Versions

Only the **latest release** on the `main` branch (published to GitHub Pages)
receives security fixes. There are no LTS branches.

---

## Reporting a Vulnerability

Security reports are handled on a best-effort basis by a single person—
please allow reasonable time for triage.

Please report vulnerabilities **privately** via one of:

1. **GitHub Security Advisories (preferred)**
   → [Open a draft advisory](https://github.com/Loupe-tools/Loupe/security/advisories/new)

2. **Email** → `security@loupe.tools`
   Encryption with the PGP key below is encouraged for sensitive reports.

Please include:

- A clear description of the issue and its security impact.
- Steps to reproduce, or a proof-of-concept file if applicable.
- The Loupe version or commit hash you tested against.

Reporters will be credited in the release notes unless they prefer anonymity.
Please allow reasonable time for a fix before public disclosure — coordinated
disclosure is appreciated.

### PGP Public Key

Fingerprint: `D8F0 2D60 C620 0F36 81F9 385D 7D97 7413 62BE B570`
```
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEaeIpSBYJKwYBBAHaRw8BAQdAdoz/JXwpuFYGLjbxtxzztKAmQeKVca48
5CVcw9VvVAHNK3NlY3VyaXR5QGxvdXBlLnRvb2xzIDxzZWN1cml0eUBsb3Vw
ZS50b29scz7CwBEEExYKAIMFgmniKUgDCwkHCRB9l3QTYr61cEUUAAAAAAAc
ACBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMub3JnyLj9VpdXQ+HglRdVlIv8
S2BYnxJWOsRE3B2RLF+CbVMDFQoIBBYAAgECGQECmwMCHgEWIQTY8C1gxiAP
NoH5OF19l3QTYr61cAAAEfABAOcwmZf2BCsrWPIkJt1MxUCiUNmwGUl2gOgT
bgTfraBmAP95wE67+URHPOOwSkMOoxtAzzhv6cgbteW3s1oXqkgSDs44BGni
KUgSCisGAQQBl1UBBQEBB0DrCfs0hafJhkk/JfGS/8nUDKiOr2gezMEVvyvF
J08OfwMBCAfCvgQYFgoAcAWCaeIpSAkQfZd0E2K+tXBFFAAAAAAAHAAgc2Fs
dEBub3RhdGlvbnMub3BlbnBncGpzLm9yZzmMwPOCTte11fi9i8212wUGk9WX
dQBvj9U/P9mcnBXDApsMFiEE2PAtYMYgDzaB+ThdfZd0E2K+tXAAAGroAP0W
LCTQfYKVR/BsSTwCXga1BV1w3RMf1vaMWhB0nJQSRgEA2wjBKwwepSNHlarD
8GHT8gI55JyTOA2ar15Zi1pwMA8=
=2zDT
-----END PGP PUBLIC KEY BLOCK-----
```

---

## Security Design Decisions

| Decision | Rationale |
|----------|-----------|
| Vanilla JS, no npm runtime deps | Zero supply-chain surface from transitive dependencies |
| Vendored libraries pinned by SHA-256 in [`VENDORED.md`](VENDORED.md) | Tamper-evident; upgrades require hash rotation in review |
| Release artefacts signed with [Sigstore](https://www.sigstore.dev/) keyless OIDC | Short-lived Fulcio certificate tied to the release-workflow OIDC identity; entry logged in Rekor; no long-lived key material in the repo. See [README § Verify Your Download](README.md#-verify-your-download) |
| Reproducible build asserted in CI ([`reproducibility.yml`](.github/workflows/reproducibility.yml)) | `SOURCE_DATE_EPOCH` + fixed locale → byte-identical `docs/index.html` across independent runs. Lets auditors rebuild from the tagged source and confirm the SHA-256 of the signed release without trusting the build infrastructure. See [REPRODUCIBILITY.md](REPRODUCIBILITY.md) |
| CycloneDX 1.5 SBOM signed and attached to every release | `loupe.cdx.json` + `loupe.cdx.json.sigstore` enumerate every vendored library with SHA-256, licence, and upstream URL — machine-readable supply-chain inventory for Dependency-Track / Trivy / etc. Generated deterministically from [`VENDORED.md`](VENDORED.md) by [`scripts/generate_sbom.py`](scripts/generate_sbom.py) |
| OpenSSF Scorecard runs weekly ([`scorecard.yml`](.github/workflows/scorecard.yml)) | Automated scoring of pinned dependencies, branch protection, token permissions, signed releases, and SAST coverage. Results publish to the [public Scorecard API](https://securityscorecards.dev/) and the repo's Security tab |
| `Content-Security-Policy` meta tag | Defence-in-depth even when served from `file://` (no HTTP headers) |
| Inline theme-bootstrap `<script>` in `<head>` | Applies the saved theme class to `<body>` before first paint so a dark-theme user never sees a flash of the light palette. Logic is a pure mirror of `_initTheme()` in `src/app/app-ui.js`: reads `localStorage['loupe_theme']`, falls back to `prefers-color-scheme`, then to the hard-coded `'dark'` default. Covered by the pre-existing `script-src 'unsafe-inline'` CSP directive that already permits the rest of the single-file bundle — **no CSP relaxation added**. The script is static, build-time-generated, and contains zero user-controlled input. |
| `<iframe sandbox="allow-same-origin">` for untrusted previews | Strongest browser-native isolation for rendered HTML/SVG — only `allow-same-origin` is kept so the frame's own inner CSP meta tag applies |
| `PARSER_LIMITS` constants | Single source of truth for all safety thresholds; easy to audit and tighten |
| EML / MSG anchor tags rendered as inert `<span class="eml-link-inert">` with the original `href` preserved only in a `title` tooltip | Loupe is a forensic viewer — an analyst triaging a phishing sample must be able to inspect a hostile URL without the risk of accidentally navigating to it. `<a href>` is stripped during HTML sanitisation in `src/renderers/eml-renderer.js` |


