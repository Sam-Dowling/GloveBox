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
| **No network access** | A strict `Content-Security-Policy` (see [§ Full Content-Security-Policy](#full-content-security-policy)) blocks all outbound requests — fetch, XHR, WebSocket, `<img src="https://…">`, `<script src>`, etc. No telemetry, no analytics, no CDN loads. |
| **No server component** | The tool runs entirely inside a single HTML file opened with `file://` or a static host. There is no backend, no API, no database. |
| **No code evaluation** | `eval()`, `new Function()`, and inline event handlers from untrusted content are never used. |
| **Sandboxed previews** | HTML and SVG previews render inside `<iframe sandbox="allow-same-origin" srcdoc="…">` with an inner CSP of `default-src 'none'`. `allow-same-origin` is kept only so the inner CSP meta tag governs the frame's own origin; every other sandbox permission is revoked by omission. |
| **Parser safety limits** | Centralised `PARSER_LIMITS` cap nesting depth (32), decompressed size (50 MB), per-entry compression ratio (100×), archive entry count (10 000), buffer-read wall-clock (60 s), per-renderer wall-clock (30 s), and auto-YARA buffer size (32 MiB; **fallback-only post-PLAN C1**: the on-load auto-scan now runs in a Web Worker and the cap is enforced only when the browser refuses `Worker(blob:)` and Loupe drops back to the synchronous main-thread path — typically Firefox on `file://`. Worker scans are bracketed by `PARSER_LIMITS.WORKER_TIMEOUT_MS` (2 min, PLAN C5) — `WorkerManager` `terminate()`s any worker that exceeds the deadline, which is **real preemption** (the worker's JS engine is killed mid-iteration, unlike the post-hoc main-thread `ParserWatchdog`). The 2 min budget is intentionally larger than the 30 s renderer cap because workerised work is off-main-thread, so legitimate large-file scans don't false-positive at 30 s; on expiry the host falls back to the synchronous in-tree path, same shape as a `workers-unavailable` rejection. Manual YARA scans share the worker path and the same 2 min preemptive cap). Two `ParserWatchdog.run()` guards bracket every load: a 60 s `PARSER_LIMITS.TIMEOUT_MS` cap around the initial `file.arrayBuffer()` read, and a 30 s `PARSER_LIMITS.RENDERER_TIMEOUT_MS` cap around the per-renderer dispatch handler. When the inner cap fires, `app-load.js` resets any partial state the hung renderer may have written, falls back to `PlainTextRenderer`, and surfaces an `IOC.INFO` row in the sidebar pointing the analyst at the manual YARA tab — so a hostile file that stalls a structured viewer still produces a hex/strings view instead of a frozen tab. The watchdog cannot interrupt a synchronous parser stuck in a tight loop mid-iteration; it only kills the wrapping promise post-hoc, so the timed-out work is abandoned but the JS engine itself is not preempted. |

### Full Content-Security-Policy

The HTML bundle ships a single CSP `<meta http-equiv>` tag emitted by
`scripts/build.py` (search for `Content-Security-Policy` — currently one
line under the `<head>` template). That meta tag is the authoritative
source; this section documents every directive it carries so that
contributors can see the full invariant at a glance.

```
default-src 'none';
style-src 'unsafe-inline';
script-src 'unsafe-inline';
img-src data: blob:;
frame-src blob:;
worker-src blob:;
form-action 'none';
base-uri 'none';
frame-ancestors 'none';
object-src 'none';
```

| Directive | Value | Purpose |
|---|---|---|
| `default-src` | `'none'` | Deny every fetch class by default — network, fonts, media, manifests, workers, connect — so anything not explicitly re-enabled below is blocked. |
| `style-src` | `'unsafe-inline'` | Permit the single inline `<style>` block the build emits. No `url(http://…)` can load because `default-src 'none'` still denies network fetches for stylesheet resources. |
| `script-src` | `'unsafe-inline'` | Permit the bundled inline JavaScript (the whole app concatenated into one `<script>` block, plus the FOUC-prevention theme bootstrap in `<head>`). Still denies `src=` loads thanks to `default-src 'none'`. |
| `img-src` | `data: blob:` | Allow `data:` URIs (inline SVG/PNG icons, canvas exports) and `blob:` URIs (previews generated from uploaded files). No `http(s):` sources. |
| `frame-src` | `blob:` | Permit the HTML / SVG sandboxed-preview iframes, which are sourced from `blob:` URLs created at runtime. No remote frames. |
| `worker-src` | `blob:` | Permit workers spawned from `blob:` URLs — both vendored libraries (`pdf.js` already does this) and the in-tree `src/workers/*.worker.js` modules (currently `yara.worker.js`, `timeline.worker.js`, and `encoded.worker.js`; spawned exclusively from `src/worker-manager.js`). Workers run in `WorkerGlobalScope`: they have no DOM, no `window`, and inherit the host CSP, so `default-src 'none'` continues to deny network access from inside a worker too. The host ↔ worker boundary is `postMessage` only — buffers cross via *transferable* `ArrayBuffer` (the worker takes ownership, the main thread re-fetches from the original `File` if it needs the bytes again). The browser may refuse `new Worker(blob:URL)` from `file://` (Firefox's default); the in-tree spawner catches that and falls back to the synchronous main-thread path for the rest of the session. Unlike the post-hoc main-thread `ParserWatchdog`, `worker.terminate()` is real preemption — a runaway scan can be cancelled mid-loop. Every `WorkerManager.run*` job is bracketed by a `PARSER_LIMITS.WORKER_TIMEOUT_MS` (2 min, PLAN C5) preemptive deadline; on expiry the worker is automatically `terminate()`-d and the promise rejects with a watchdog-shaped error (`_watchdogTimeout`), so a hostile file that drives a worker into a tight loop is killed without analyst intervention. Hosts fall back to the synchronous in-tree path on any rejection (workers-unavailable, worker error, watchdog timeout) — same recovery shape as before C5. No remote workers. |
| `form-action` | `'none'` | Block any `<form action>` submission, including same-origin, to prevent untrusted content from exfiltrating via form POST. |
| `base-uri` | `'none'` | Block any `<base href>` injection, so untrusted HTML cannot re-root relative URLs in the host document. |
| `frame-ancestors` | `'none'` | Forbid the bundle from being embedded in any external frame (click-jacking defence). |
| `object-src` | `'none'` | Block `<object>` / `<embed>` / `<applet>` — these are legacy plugin hosts with their own security histories. |

Any change to any directive is a **security-relevant default** under
[CONTRIBUTING.md](CONTRIBUTING.md) § "Change a security-relevant default":
the change must update both `scripts/build.py` and the table above in a
single commit.

### What Loupe does **not** protect against

- **Browser zero-days** — if the browser's own HTML/CSS/image parsers have
  vulnerabilities, Loupe inherits them (as does every web page).
- **Denial-of-service via CPU** — a synchronous parser in a tight loop cannot
  be interrupted by the main-thread watchdog; the browser's own tab-crash
  heuristics handle it.
- **Side-channel attacks** — Spectre-class timing side-channels are out of
  scope for a file-analysis tool.

---

## Supported Versions

Only the **latest release** on the `main` branch (published to GitHub Pages)
receives security fixes. There are no LTS branches.

---

## Verify Your Download

Every release is signed with [Sigstore](https://www.sigstore.dev/) keyless
signing — short-lived Fulcio certificate issued to the release workflow's
OIDC identity, entry logged in Rekor, no long-lived key material. Each
release ships:

| File | Purpose |
|---|---|
| `loupe.html` | The bundle itself |
| `loupe.html.sha256` | Plain-text SHA-256 for a quick eyeball check |
| `loupe.html.sigstore` | Sigstore bundle (certificate + signature + Rekor inclusion proof) |
| `loupe.cdx.json` | CycloneDX 1.5 SBOM — every vendored library with SHA-256 pin |
| `loupe.cdx.json.sigstore` | Sigstore bundle for the SBOM |
| `loupe.intoto.jsonl` | SLSA v1.0 build-provenance attestation (Sigstore bundle, `slsaprovenance1` predicate) binding the release bytes to this workflow run |

With [cosign](https://docs.sigstore.dev/cosign/installation/) installed:

```bash
cosign verify-blob \
  --bundle loupe.html.sigstore \
  --certificate-identity "https://github.com/Loupe-tools/Loupe/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  loupe.html
```

A successful verification proves the bytes of `loupe.html` were produced by
`.github/workflows/release.yml` in `Loupe-tools/Loupe`. It attests
**provenance**, not that the source is benign.

### SLSA build provenance

In addition to the raw Sigstore signature above, every release ships a
[SLSA v1.0](https://slsa.dev/spec/v1.0/provenance) build-provenance
attestation (`loupe.intoto.jsonl`) that binds the release bytes to this
repo, this workflow file, the exact commit SHA, the trigger event, and
the runner identity. The attestation is issued by `actions/attest-build-provenance`
through the same Sigstore / Fulcio / Rekor infrastructure as the
signature above.

Verify it online with the GitHub CLI:

```bash
gh attestation verify loupe.html --owner Loupe-tools
```

Or fully offline with cosign against the bundled `.intoto.jsonl`:

```bash
cosign verify-blob-attestation \
  --bundle loupe.intoto.jsonl \
  --certificate-identity "https://github.com/Loupe-tools/Loupe/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --type slsaprovenance1 \
  loupe.html
```

This is the same provenance signal OpenSSF Scorecard inspects for its
Signed-Releases check, and is additive to the `.sigstore` bundles above —
both remain valid and required.

---

## Reproducible Build

Given the same commit, `python scripts/build.py` emits a byte-identical
`docs/index.html`. The release workflow rebuilds from source on a clean
runner with `SOURCE_DATE_EPOCH` pinned to HEAD's commit-author timestamp,
`TZ=UTC`, and `LC_ALL=C.UTF-8`, then Sigstore-signs the resulting bytes.
`docs/index.html` is not committed to the repository — it exists only as
CI output.

To verify a release corresponds to the tagged source:

```sh
git clone https://github.com/Loupe-tools/Loupe && cd Loupe
git checkout v20260420.1402        # the release tag
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD) \
  TZ=UTC LC_ALL=C.UTF-8 \
  python scripts/build.py
sha256sum docs/index.html loupe.html
```

Matching hashes means the signed asset corresponds exactly to the tagged
source. Only `LOUPE_VERSION` (the UI's version string) is time-derived;
everything else in the bundle is a deterministic concatenation in a fixed
order. `build.py` auto-derives `SOURCE_DATE_EPOCH` from HEAD in a git
checkout, so contributors don't need to export it.

Reproducibility proves **source → bytes**, not **source → benign**: it
confirms the signed bundle is what the public tree compiled to, not that
the tree itself is safe. Cross-check the Sigstore signature above for
provenance.

---

## Reporting a Vulnerability

Security reports are handled on a best-effort basis by a single person —
please allow reasonable time for triage.

Report privately via one of:

1. **GitHub Security Advisories (preferred)** →
   [Open a draft advisory](https://github.com/Loupe-tools/Loupe/security/advisories/new)
2. **Email** → `security@loupe.tools` (PGP key below encouraged for
   sensitive reports)

Please include:

- A clear description of the issue and its security impact.
- Steps to reproduce, or a proof-of-concept file if applicable.
- The Loupe version or commit hash you tested against.

Reporters are credited in release notes unless they prefer anonymity.
Coordinated disclosure is appreciated.

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
| Release artefacts signed with [Sigstore](https://www.sigstore.dev/) keyless OIDC | Short-lived Fulcio cert tied to the release-workflow OIDC identity; Rekor-logged; no long-lived key material. See [§ Verify Your Download](#verify-your-download) |
| Reproducible build, signed on the CI runner | Same commit → byte-identical bundle. See [§ Reproducible Build](#reproducible-build) |
| CycloneDX 1.5 SBOM signed and attached to every release | `loupe.cdx.json` + `loupe.cdx.json.sigstore` enumerate every vendored library with SHA-256, licence, and upstream URL. Generated deterministically from [`VENDORED.md`](VENDORED.md) by [`scripts/generate_sbom.py`](scripts/generate_sbom.py) |
| OpenSSF Scorecard runs weekly ([`scorecard.yml`](.github/workflows/scorecard.yml)) | Automated scoring of pinned dependencies, branch protection, token permissions, signed releases, SAST coverage |
| `Content-Security-Policy` meta tag | Defence-in-depth even when served from `file://` |
| Inline theme-bootstrap `<script>` in `<head>` | Applies the saved theme class to `<body>` before first paint. Static, build-time-generated, zero user-controlled input; covered by the same `script-src 'unsafe-inline'` the rest of the bundle already uses — no CSP relaxation added |
| `<iframe sandbox="allow-same-origin">` for untrusted previews | Strongest browser-native isolation for rendered HTML/SVG; only `allow-same-origin` is kept so the frame's own inner CSP meta applies |
| `PARSER_LIMITS` constants | Single source of truth for all safety thresholds; easy to audit and tighten |
| EML / MSG anchor tags rendered as inert `<span>` with `href` preserved only in `title` | An analyst must be able to inspect a hostile URL without accidentally navigating to it |
