# Security Policy

> - End-user docs: [README.md](README.md)
> - Format / capability reference: [FEATURES.md](FEATURES.md)
> - Build & developer docs: [CONTRIBUTING.md](CONTRIBUTING.md)

---

## Threat Model

Loupe is a **100 % offline, single-file HTML security analyser**. Its
threat model is deliberately narrow:

| Property | Guarantee |
|----------|-----------|
| **No network access** | The CSP meta tag (see [§ Full Content-Security-Policy](#full-content-security-policy)) blocks every fetch class — fetch, XHR, WebSocket, `<img src="https://…">`, `<script src>`, etc. No telemetry, no analytics, no CDN loads. |
| **No server component** | The tool runs entirely inside a single HTML file opened with `file://` or a static host. No backend, no API, no database. |
| **No code evaluation** | `eval()`, `new Function()`, and inline event handlers from untrusted content are never used. |
| **Sandboxed previews** | HTML and SVG previews render inside `<iframe sandbox="allow-same-origin" srcdoc="…">` with an inner CSP of `default-src 'none'`. `allow-same-origin` is kept only so the inner CSP meta tag governs the frame's own origin; every other sandbox permission is revoked by omission. |
| **Parser safety limits** | Centralised `PARSER_LIMITS` cap nesting depth, decompressed size, archive-entry count, parse wall-clock, and per-dispatch file size. See [§ Parser Limits](#parser-limits) for values. |

### What Loupe does **not** protect against

- **Browser zero-days** — if the browser's own HTML/CSS/image parsers
  have vulnerabilities, Loupe inherits them (as does every web page).
- **Denial-of-service via CPU** — a synchronous parser in a tight loop
  cannot be interrupted by the main-thread watchdog; the browser's own
  tab-crash heuristics handle it.
- **Side-channel attacks** — Spectre-class timing side-channels are out
  of scope for a file-analysis tool.

### Persisted user data (IndexedDB)

Most user state lives in `localStorage` under the `loupe_` prefix
(themes, sidebar widths, per-file extracted columns, etc.). One
exception: the **GeoIP MMDB overrides**.

If you upload a MaxMind-format MMDB via ⚙ Settings → "GeoIP database",
the file is stored in IndexedDB under database name `loupe-geoip` in
two independent slots — `geo` (Country / City / Region) and `asn`
(Autonomous System / Organisation), each capped at 256 MB. The DB is
per-browser-profile, per-origin, and opaque to the network — the CSP
`default-src 'none'` rule means even Loupe itself cannot exfiltrate
it. It survives page reloads but is wiped if you clear site data, use
a private window, or switch browser profiles. No telemetry; provider
info (filename, vintage) appears only in the Settings dialog and the
column tooltip. Each slot has its own "✕ Remove" button — removing
the geo slot reverts to the bundled IPv4-country fallback; removing
the ASN slot disables ASN enrichment.

The bundled IPv4-country binary (vendored in the HTML file itself,
≈830 KB) is **not** stored in IndexedDB and cannot be removed at
runtime. It is regenerated monthly by
`.github/workflows/refresh-geoip.yml` — see [`VENDORED.md`](VENDORED.md)
for the SHA-256 pin and refresh recipe.

---

## Parser Limits

Centralised in `src/constants.js` as the `PARSER_LIMITS` and
`RENDER_LIMITS` constants. **`PARSER_LIMITS` is the safety envelope** —
raising weakens defences. **`RENDER_LIMITS` caps how much parsed data
the UI renders** — raising affects only completeness / memory.

| Limit | Value | Purpose |
|---|---|---|
| `MAX_DEPTH` | 32 | Recursion cap (archives, encoded-content chains, OLE structured-storage walks) |
| `MAX_UNCOMPRESSED` | 256 MB | Per-stream decompressed-size cap (zip-bomb defence). The companion `MAX_RATIO` (100×) bounds amplification independently — a 256 MB cap with a 100× ratio cap means a hostile archive needs at least 2.56 MB of compressed payload to reach the cap, exceeding what any drive-by drop-target trickle-feeds. |
| `MAX_RATIO` | 100× | Per-entry compression ratio cap (zip-bomb defence) |
| `MAX_ENTRIES` | 10 000 | Archive entry-count cap |
| `TIMEOUT_MS` | 60 s | `ParserWatchdog` cap around the initial `file.arrayBuffer()` read |
| `RENDERER_TIMEOUT_MS` | 30 s | `ParserWatchdog` cap around each per-renderer dispatch handler. On expiry, `app-load.js` resets partial state, falls back to `PlainTextRenderer`, and surfaces an `IOC.INFO` row pointing at the manual YARA tab |
| `WORKER_TIMEOUT_MS` | 5 min | Preemptive deadline on every `WorkerManager.run*` job (Timeline scales with file size, capped 30 min). On expiry the worker is `terminate()`-d — real preemption, since the JS engine is killed mid-iteration. The host falls back to the synchronous in-tree path |
| `SYNC_YARA_FALLBACK_MAX_BYTES` | 32 MiB | Auto-YARA buffer cap, **fallback-only**: enforced when the browser refuses `Worker(blob:)` and Loupe drops to the synchronous main-thread path (typically Firefox on `file://`). Worker scans are unbounded — `worker.terminate()` is true preemption |
| `MAX_FILE_BYTES_BY_DISPATCH` | per-id table | Per-dispatch size cap consulted by `RenderRoute.run` *before* the renderer handler fires. PE/ELF/Mach-O/PDF: 256 MiB; archives + `pcap`: 512 MiB–1 GiB; lightweight markup/scripts: 8–64 MiB; `_DEFAULT` 128 MiB. Exceeding the cap routes to `PlainTextRenderer` and emits a single `IOC.INFO` naming the dispatch id and cap. The manual YARA tab still scans the unmodified buffer |
| `MAX_FOLDER_ENTRIES` | 4 096 | Drag-dropped folders, multi-file loose drops, and `webkitdirectory` picker selections are walked into a single synthetic `FolderFile` (`src/folder-file.js`) with a flat entry list. The walker stops at this cap and surfaces a visible `IOC.INFO` truncation row in the sidebar; the analyst is never silently shown a partial tree. The cap bounds memory + walk wall-clock — `webkitGetAsEntry()` is async per directory level, and a 100k-entry tree with deep nesting can easily run into the tens of seconds |

The two watchdog caps (`TIMEOUT_MS`, `RENDERER_TIMEOUT_MS`) cannot
interrupt a synchronous parser stuck mid-iteration — they only kill the
wrapping promise post-hoc. The worker timeout (`WORKER_TIMEOUT_MS`) is
the only preemptive cap because `worker.terminate()` kills the JS
engine itself. `MAX_FILE_BYTES_BY_DISPATCH` guards parser CPU cost, not
memory pressure (memory pressure is covered separately by
`RENDER_LIMITS.HUGE_FILE_WARN`); the buffer is already in memory at
check time.

For the implementation contract see
[CONTRIBUTING.md § Renderer Contract](CONTRIBUTING.md#renderer-contract).

### Heap-budget gate (Chromium-only)

CSV / TSV / EVTX / SQLite payloads decode into a `RowStore` (flat
chunked typed-array container — see
[CONTRIBUTING.md § RowStore container contract](CONTRIBUTING.md#rowstore-container-contract))
that holds every parsed cell on the JS heap until the user clears the
view. A 1 M-row CSV with ~80-character rows budgets ~880 MB after the
Phase 4 migration; older builds were ~4× heavier and reliably OOM'd
the renderer process on a 16 GB Chromium.

`src/app/timeline/timeline-router.js` consults Chromium's
non-standard `performance.memory.jsHeapSizeLimit` *before* the worker
starts streaming `rows-chunk` messages and rejects the parse with a
fail-soft toast if the projected RowStore exceeds the budget. Two
tunables in `RENDER_LIMITS`:

| Constant | Default | Meaning |
|---|---|---|
| `ROWSTORE_HEAP_BUDGET_FRACTION` | `0.6` | Maximum fraction of `jsHeapSizeLimit` the projected RowStore is allowed to occupy. |
| `ROWSTORE_HEAP_OVERHEAD_FACTOR` | `1.6` | Multiplier on the raw decoded-text byte size used to project the RowStore footprint (covers UTF-16 expansion + per-cell offset table). |
| `TIMELINE_COMPOSITE_HEAP_OVERHEAD_FACTOR` | `2.2` | Multiplier on the sum-of-`file.size` used to project the cumulative heap footprint of a merged Timeline (`_timelineAddFile` pre-flight). Higher than the single-file factor because each source keeps its own `baseStore` resident for fast toggle-off alongside the composite `store`, plus canonical column cells (string duplication for `__source` / `__format` / …) and the `_sourceOfRow` / `_sourceEnabledBitmap` parallel arrays. |
| `TIMELINE_SOURCE_CAP_SOFT` / `TIMELINE_SOURCE_CAP_HARD` | `8` / `16` | Drop-to-add emits an advisory toast beyond soft; refuses beyond hard. Bounds the linear-across-sources cost of re-sort, chip-bar render, and per-source detections aggregation. |

The gate is **Chromium-only**: Firefox and Safari don't ship
`performance.memory`, and the parse proceeds without the projection.
This is intentional fail-soft behaviour — the gate is a DoS mitigation
for malicious or accidentally-huge CSVs, not a hard correctness
requirement; parses on browsers without the API simply rely on the
existing `MAX_FILE_BYTES_BY_DISPATCH` cap (`csv` ≈ 512 MiB) and the
OS-level OOM-killer.

The gate is also **Timeline-route only**: it lives in
`_loadFileInTimeline` and never sees files that take the regular
analyser pipeline (PE / ELF / Office / archive / image …), which have
radically different memory profiles. The non-Timeline path is bounded
by `LARGE_FILE_THRESHOLD` (200 MB → switch to chunked decode) and the
per-dispatch `MAX_FILE_BYTES_BY_DISPATCH` ceiling.

When the gate fires the load is cancelled before the worker spawns,
no partial RowStore is built, and the user sees an error toast:

> "File too large for available memory: <file MB> MB needs
>  ~<projected MB> MB but only ~<budget MB> MB heap is available.
>  Close other tabs or split the file before loading."

---

## Full Content-Security-Policy

The HTML bundle ships a single CSP `<meta http-equiv>` tag emitted by
`scripts/build.py`. That meta tag is the authoritative source; the
table below documents every directive at a glance.

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
| `style-src` | `'unsafe-inline'` | Permit the single inline `<style>` block the build emits. No `url(http://…)` can load because `default-src 'none'` still denies stylesheet-resource fetches. |
| `script-src` | `'unsafe-inline'` | Permit the bundled inline JavaScript (the whole app concatenated into one `<script>` block, plus the FOUC-prevention theme bootstrap in `<head>`). Still denies `src=` loads thanks to `default-src 'none'`. |
| `img-src` | `data: blob:` | Allow `data:` URIs (inline icons, canvas exports) and `blob:` URIs (previews from uploaded files). No `http(s):` sources. |
| `frame-src` | `blob:` | Permit the HTML / SVG sandboxed-preview iframes, sourced from `blob:` URLs created at runtime. No remote frames. |
| `worker-src` | `blob:` | Permit workers spawned from `blob:` URLs — both vendored libraries (`pdf.js`) and the in-tree `src/workers/*.worker.js` modules. Workers run in `WorkerGlobalScope` and inherit the host CSP, so `default-src 'none'` continues to deny network access from inside a worker. See [CONTRIBUTING.md § Worker subsystem](CONTRIBUTING.md#worker-subsystem) for the spawn protocol, `postMessage` shapes, and timeout / preemption behaviour. |
| `form-action` | `'none'` | Block any `<form action>` submission, including same-origin, to prevent untrusted content from exfiltrating via form POST. |
| `base-uri` | `'none'` | Block `<base href>` injection so untrusted HTML cannot re-root relative URLs in the host document. |
| `frame-ancestors` | `'none'` | Forbid the bundle from being embedded in any external frame (click-jacking defence). |
| `object-src` | `'none'` | Block `<object>` / `<embed>` / `<applet>` — legacy plugin hosts with their own security histories. |

Any change to any directive is a **security-relevant default** under
[CONTRIBUTING.md § Changing a Security-Relevant Default](CONTRIBUTING.md#changing-a-security-relevant-default):
the change must update both `scripts/build.py` and the table above in a
single commit.

---

## Supported Versions

Only the **latest release** on the `main` branch (published to GitHub
Pages) receives security fixes. There are no LTS branches.

---

## Verify Your Download

Every release is signed with [Sigstore](https://www.sigstore.dev/)
keyless signing — short-lived Fulcio certificate issued to the release
workflow's OIDC identity, entry logged in Rekor, no long-lived key
material. Each release ships:

| File | Purpose |
|---|---|
| `loupe.html` | The bundle itself |
| `loupe.html.sha256` | Plain-text SHA-256 for a quick eyeball check |
| `loupe.html.sigstore` | Sigstore bundle (cert + signature + Rekor inclusion proof) |
| `loupe.cdx.json` | CycloneDX 1.5 SBOM — every vendored library with SHA-256 pin |
| `loupe.cdx.json.sigstore` | Sigstore bundle for the SBOM |
| `loupe.intoto.jsonl` | SLSA v1.0 build-provenance attestation binding the release bytes to this workflow run |

With [cosign](https://docs.sigstore.dev/cosign/installation/) installed:

```bash
cosign verify-blob \
  --bundle loupe.html.sigstore \
  --certificate-identity "https://github.com/Loupe-tools/Loupe/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  loupe.html
```

A successful verification proves the bytes of `loupe.html` were produced
by `.github/workflows/release.yml` in `Loupe-tools/Loupe`. It attests
**provenance**, not that the source is benign.

### SLSA build provenance

In addition to the raw Sigstore signature, every release ships a
[SLSA v1.0](https://slsa.dev/spec/v1.0/provenance) build-provenance
attestation (`loupe.intoto.jsonl`) that binds the release bytes to this
repo, the workflow file, the exact commit SHA, the trigger event, and
the runner identity. Issued by `actions/attest-build-provenance` through
the same Sigstore / Fulcio / Rekor infrastructure as the signature.

Verify online with the GitHub CLI:

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
Signed-Releases check, and is additive to the `.sigstore` bundles —
both remain valid and required.

---

## Reproducible Build

Given the same commit, `python scripts/build.py` emits a byte-identical
`docs/index.html`. The release workflow rebuilds from source on a clean
runner with `SOURCE_DATE_EPOCH` pinned to HEAD's commit-author timestamp,
`TZ=UTC`, and `LC_ALL=C.UTF-8`, then Sigstore-signs the resulting bytes.
`docs/index.html` is not committed to the repository.

To verify a release corresponds to the tagged source:

```sh
git clone https://github.com/Loupe-tools/Loupe && cd Loupe
git checkout v20260420.1402        # the release tag
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD) \
  TZ=UTC LC_ALL=C.UTF-8 \
  python scripts/build.py
sha256sum docs/index.html loupe.html
```

Matching hashes means the signed asset corresponds exactly to the
tagged source. Only `LOUPE_VERSION` (the UI's version string) is
time-derived; everything else is a deterministic concatenation in a
fixed order. `build.py` auto-derives `SOURCE_DATE_EPOCH` from HEAD in a
git checkout, so contributors don't need to export it.

Reproducibility proves **source → bytes**, not **source → benign**: it
confirms the signed bundle is what the public tree compiled to, not
that the tree itself is safe. Cross-check the Sigstore signature for
provenance.

The reproducibility guarantee covers `docs/index.html` only.
`scripts/build.py --test-api` produces a separate `docs/index.test.html`
sibling for the Playwright e2e suite — that file embeds the
`window.__loupeTest` test surface defined in `src/app/app-test-api.js`
and is **never** deployed to GitHub Pages, **never** Sigstore-signed,
and **never** a release artefact. A `_check_no_test_api_in_release()`
build gate inside `scripts/build.py` re-reads the just-emitted release
bundle and fails the build if the test-API markers
(`__LOUPE_TEST_API__` or `__loupeTest`) leak into it. See
`tests/README.md` for the full test-build / release-build separation.

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
| Release artefacts signed with [Sigstore](https://www.sigstore.dev/) keyless OIDC | Short-lived Fulcio cert tied to the release-workflow OIDC identity; Rekor-logged; no long-lived key material |
| Reproducible build, signed on the CI runner | Same commit → byte-identical bundle |
| CycloneDX 1.5 SBOM signed and attached to every release | `loupe.cdx.json` enumerates every vendored library with SHA-256, licence, and upstream URL. Generated deterministically from [`VENDORED.md`](VENDORED.md) |
| OpenSSF Scorecard runs weekly | Automated scoring of pinned dependencies, branch protection, token permissions, signed releases, SAST coverage |
| `Content-Security-Policy` meta tag | Defence-in-depth even when served from `file://` |
| Inline theme-bootstrap `<script>` in `<head>` | Applies the saved theme class to `<body>` before first paint. Static, build-time-generated, zero user-controlled input; covered by the same `script-src 'unsafe-inline'` the rest of the bundle uses — no CSP relaxation added |
| `<iframe sandbox="allow-same-origin">` for untrusted previews | Strongest browser-native isolation for rendered HTML/SVG; only `allow-same-origin` is kept so the frame's own inner CSP meta applies |
| `PARSER_LIMITS` constants | Single source of truth for all safety thresholds; easy to audit and tighten. See [§ Parser Limits](#parser-limits) |
| `safeRegex` user-regex harness | All UI-supplied regex (Timeline DSL, Timeline regex-extract, drawer extract, YARA editor) is compiled through `safeRegex` (`src/constants.js`). Patterns >2 KB or matching the duplicate-adjacent-quantified-group ReDoS shape are rejected; nested unbounded quantifiers (`(a+)+`, `(.*)*`, `(\w+){2,}`) raise a "pattern may be slow" warning. Timeline regex-extract additionally enforces a 250 ms wall-clock budget on the preview loop and refuses to commit a pattern that times out on a 1 K-row dry run |
| EML / MSG anchor tags rendered as inert `<span>` with `href` preserved only in `title` | An analyst must inspect a hostile URL without accidentally navigating to it |
