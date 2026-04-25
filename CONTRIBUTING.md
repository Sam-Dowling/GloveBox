# Contributing to Loupe

> Developer guide for Loupe.
> - For end-user documentation see [README.md](README.md).
> - For the full format / capability / example reference see [FEATURES.md](FEATURES.md).
> - For the threat model and vulnerability reporting see [SECURITY.md](SECURITY.md).
> - For the line-level index of every class, method, CSS section, and YARA rule see [CODEMAP.md](CODEMAP.md) (auto-generated).

---

## Building from Source

Requires **Python 3.8+** (standard library only — no `pip install` needed).

```bash
python make.py                   # One-shot: verify vendors, build, regenerate CODEMAP.md
```

`make.py` is a thin orchestrator that chains the stand-alone scripts under
`scripts/`. Invoke any subset by name, in any order:

```bash
python make.py verify            # just scripts/verify_vendored.py
python make.py build             # just scripts/build.py
python make.py codemap           # just scripts/generate_codemap.py
python make.py build codemap     # a subset, in the order given
python make.py sbom              # emit dist/loupe.cdx.json from VENDORED.md
```

Each underlying script remains independently runnable:

```bash
python scripts/build.py              # Concatenates src/ → docs/index.html
python scripts/generate_codemap.py   # Regenerates CODEMAP.md (run after code changes)
python scripts/verify_vendored.py    # Verifies vendor/*.js SHA-256 against VENDORED.md
python scripts/generate_sbom.py      # Emits dist/loupe.cdx.json (CycloneDX 1.5 SBOM)
```

`docs/index.html` is the single build output and is **not committed to git**.
It is produced locally for smoke-testing or by CI for Pages deployment and
release signing.

### Determinism & `SOURCE_DATE_EPOCH`

`build.py` is reproducible: given the same commit, the output is
byte-identical. Only the embedded `LOUPE_VERSION` string is time-derived,
resolved in this order:

1. `SOURCE_DATE_EPOCH` env var (the reproducible-builds.org standard) — CI uses this at release time.
2. `git log -1 --format=%ct HEAD` — auto-derived in a git checkout, so local `python make.py` is deterministic without any env-var fiddling.
3. `datetime.now()` — last-resort fallback for source archives (tarball / ZIP) that aren't a git checkout.

Contributors don't normally need to think about this. For the release-verification recipe see [SECURITY.md § Reproducible Build](SECURITY.md#reproducible-build).

### Continuous Integration

`.github/workflows/ci.yml` runs on every push and PR. CI scope stops at
static verification — Puppeteer / Playwright can't drive the native
file-picker or drag-and-drop, which are the only entry points into a
loaded file.

| Job | What it guarantees |
|---|---|
| `build` | `python scripts/build.py` succeeds and produces `docs/index.html`. SHA-256 and size are written to the job summary, and the bundle is uploaded as a retained artefact so reviewers can diff it against their own build. |
| `verify-vendored` | Every `vendor/*.js` matches the SHA-256 pin in `VENDORED.md`, no pinned file is missing, and no unpinned file has snuck into `vendor/`. |
| `static-checks` | On the **built** `docs/index.html`: CSP meta tag is present, `default-src 'none'` is still there, no inline HTML event-handler attributes (`onclick="…"` etc.), no `'unsafe-eval'`, no remote hosts in CSP directives. |
| `lint` | ESLint 9 over `src/**/*.js` using `eslint.config.mjs`. The ruleset targets real foot-guns (`no-eval`, `no-new-func`, `no-const-assign`, `no-unreachable`, …) rather than style. |

Two additional workflows run on push-to-main + weekly cron:

| Workflow | What it guarantees |
|---|---|
| `codeql.yml` | GitHub CodeQL static analysis over `src/**/*.js` and `scripts/**/*.py` with the `security-extended` query pack. Satisfies OpenSSF Scorecard's SAST check and surfaces real tainted-sink / deserialisation / weak-crypto findings in the Security tab. |
| `scorecard.yml` | Weekly OpenSSF Scorecard run. Results publish to the Security tab and to `api.securityscorecards.dev` (the README badge). |

`.github/workflows/release.yml` is chained off CI via `workflow_run` — it
only fires after a `push`-triggered CI run on `main` concludes
successfully, and it checks out the exact `head_sha` that CI validated
(not `main`'s current tip, which may have moved on). This gives the
repo a single shipping invariant:

> **A commit gets a GitHub Release ⇔ its CI run went green on `main`
> and its bundle was deployed to Pages.**

Consequently, Pages and Releases can't drift in LOUPE_VERSION: both
are downstream of the same CI run. Same-minute pushes collapse to one
Release thanks to the existing "tag already exists → skip" guard in
`release.yml`. The release job deliberately does **not** re-run
`verify-vendored` / `static-checks` / `lint` — those already gated CI,
and CI's success is this workflow's trigger.

The ESLint config is ESM (`eslint.config.mjs`) and uses `sourceType: 'script'`
because the `src/` files are concatenated into a single inline `<script>` at
build time. `no-undef` and `no-implicit-globals` are **off** — every
cross-file class reference (`XlsxRenderer`, `App`, `OleCfbParser`, …) and
every vendored global (`JSZip`, `XLSX`, `pdfjsLib`, `hljs`, `UTIF`, `exifr`,
`tldts`, `pako`, `LZMA`, `DEFAULT_YARA_RULES`) is an implicit global by
design.

### GitHub Actions — SHA pinning & Dependabot

Every `uses:` in `.github/workflows/*.yml` is pinned by **full 40-character
commit SHA**, with the human-readable version (`v4.2.2`, `v5.6.0`, …) in the
trailing `# vX.Y.Z` comment. This satisfies OpenSSF Scorecard's
Pinned-Dependencies check and stops a compromised or force-pushed tag from
silently swapping action source underneath the pipeline. Example:

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
```

`.github/dependabot.yml` watches the `github-actions` ecosystem weekly and
opens grouped PRs that rotate each SHA with the new version in the commit
message — so pins stay current without manual churn. There is deliberately
no `npm` / `pip` ecosystem entry: Loupe has zero runtime package
dependencies (vanilla browser JS), and vendored libraries under `vendor/`
are hand-pinned by SHA-256 in `VENDORED.md` with a bespoke upgrade recipe
— see `README.md` § Vendored libraries. Dependabot would have nothing to
do for either surface.

When upgrading an action manually (e.g. to land a security fix before the
weekly cron), resolve the new SHA with:

```
curl -s https://api.github.com/repos/<owner>/<repo>/git/ref/tags/<vX.Y.Z> \
  | jq -r .object.sha
```

and replace both the SHA and the trailing `# vX.Y.Z` comment.

---

## Architecture & Signal Chain

This section is the architectural map: the path a file takes from drop to
sidebar, who mutates what along the way, and the four cross-cutting
contracts that hold it all together. **Read this first** before making any
non-trivial change. It describes the **current de-facto state** of the code
— some of these contracts are not yet enforced. The roadmap that codifies
them lives in `PLAN.md`; the prescriptive renderer rules live in the
[Renderer Contract](#renderer-contract) section further down.

### Signal chain (ingress → render → sidebar)

```mermaid
flowchart TD
    %% Ingress
    subgraph INGRESS["File ingress"]
        A1[Drop zone]
        A2[File picker]
        A3["iframe drag-shield<br/>loupe-drop CustomEvent"]
        A1 --> H[App._handleFiles]
        A2 --> H
        A3 --> H
    end

    H --> L["App._loadFile<br/>(file, prefetchedBuffer?)"]
    L --> RB[FileReader.readAsArrayBuffer]
    RB --> SNIFF{Timeline<br/>3-probe sniff?}

    %% Timeline branch
    SNIFF -- "CSV / TSV / EVTX" --> TL["Timeline route<br/>app-timeline.js<br/>(monolith)"]

    %% Generic branch
    SNIFF -- other --> RR[RendererRegistry.dispatch]
    RR --> RM[magic pass]
    RR --> RX[ext + extDisambiguator]
    RR --> RT[text-head sniff]
    RM --> DT[_rendererDispatch table]
    RX --> DT
    RT --> DT

    DT --> RD["Renderer.render(file, buf, app)"]

    %% Renderer side-effects
    RD --> SE1[Build DOM container]
    RD --> SE2["Mutate app.findings:<br/>{ risk, externalRefs[],<br/>interestingStrings[],<br/>metadata, ... }"]
    RD --> SE3[Stamp app._fileBuffer<br/>app._yaraBuffer<br/>app._binaryParsed]
    RD --> SE4[Set container._rawText<br/>(must be LF-normalised)]
    RD --> SE5["pushIOC(findings, {type:IOC.X, value, severity})"]

    %% Mount + sidebar
    SE1 --> MOUNT["#page-container<br/>innerHTML='', appendChild"]
    SE2 --> SBR[App._renderSidebar]
    SE5 --> SBR

    %% YARA
    SBR --> YARA["App._autoYaraScan()<br/>worker (yara.worker.js);<br/>sync main-thread fallback"]
    YARA --> SBY[Sidebar YARA section]

    %% Drill-down
    subgraph DRILL["Drill-down (recursive)"]
        D1[archive-tree row click] --> DEV[open-inner-file CustomEvent]
        D2[binary-overlay re-dispatch] --> DEV
        D3["encoded-content-detector<br/>decoded blob"] --> D3a[synthetic File]
        D3a --> DEV
        DEV --> RR
    end

    %% Sidebar surfaces
    SBR --> S1[Detections]
    SBR --> S2[IOCs]
    SBR --> S3[File Info]
    S1 --> CTF[Click-to-focus<br/>app-sidebar-focus.js]
    S2 --> CTF
    CTF --> CTFs[String search inside<br/>container._rawText]
```

`CODEMAP.md` is the inverse-index: every box above maps to a file and line
range. Surgical anchors:

| Box | File · symbol |
|---|---|
| Drop zone | `src/app/app-core.js` · `_setupDrop` |
| `_loadFile` | `src/app/app-load.js` · `App._loadFile` |
| Registry dispatch | `src/renderer-registry.js` · `RendererRegistry.dispatch` |
| Per-renderer dispatch table | `src/app/app-load.js` · `_rendererDispatch` |
| Sidebar render | `src/app/app-sidebar.js` · `_renderSidebar` |
| Click-to-focus | `src/app/app-sidebar-focus.js` |
| Auto-YARA | `src/app/app-yara.js` · `_autoYaraScan` |
| `pushIOC` helper | `src/constants.js` · `pushIOC` |
| Encoded-content recursion | `src/encoded-content-detector.js` |

### Renderer side-effect contract (current de-facto state)

Every renderer's `static render(file, arrayBuffer, app)` performs the same
side-effects today, but **nothing enforces this contract** end-to-end and
the per-renderer drift is real. Use this table as the architectural map;
the prescriptive rules every renderer must obey are codified further down
in [Renderer Contract](#renderer-contract) and [IOC Push Checklist](#ioc-push-checklist).

| Step | Required? | What | Read site |
|---|---|---|---|
| 1 | required | Build a DOM container and return it (or `{ docEl }`) | `_rendererDispatch` mounts it under `#page-container` |
| 2 | required | Mutate `app.findings` (`risk`, `externalRefs[]`, `interestingStrings[]`, `metadata`, …) | Sidebar render |
| 3 | sometimes | Stamp `app._fileBuffer`, `app._yaraBuffer` | Auto-YARA prefers `_yaraBuffer`, else `_fileBuffer` |
| 4 | binary only | Stamp `app._binaryParsed`, `app._binaryFormat` | Copy-Analysis + verdict band |
| 5 | required | Set `container._rawText` (LF-normalised) | Click-to-focus string search |
| 6 | required | Use `pushIOC()` and `IOC.*` constants — never bare strings | Sidebar IOC filter |
| 7 | optional | Call `mirrorMetadataIOCs()` to surface metadata as clickable IOCs | File Info → IOCs |
| 8 | risk | Initialise `findings.risk = 'low'`; escalate only from evidence on `externalRefs` | Risk bar, Summary export |

See [Risk Tier Calibration](#risk-tier-calibration) for the formal escalation
ladder; pre-stamping `findings.risk = 'high'` is a `.clinerules` violation
(false-positive risk colouring on benign samples).

### IOC entry shape

The canonical pusher is `pushIOC(findings, opts)` at `src/constants.js`. Its
on-wire shape is the same regardless of bucket (`interestingStrings` vs.
`externalRefs`):

```js
{
  type: IOC.URL,            // string constant from IOC.* table
  url: '<value>',            // historical name; sidebar reads .url for any type
  severity: 'info'|'medium'|'high'|'critical',
  note?: string,
  _highlightText?: string,   // click-to-focus target; defaults to .url
  _sourceOffset?, _sourceLength?,
  _decodedFrom?, _encodedFinding?, ...
}
```

`pushIOC` enforces the `IOC.*` constants and **auto-emits siblings** off a
URL push via vendored `tldts`: a registrable `IOC.DOMAIN` for non-IP hosts,
an `IOC.IP` row when the URL embeds a literal IP, and `IOC.PATTERN` rows
for punycode/IDN homoglyphs and abuse-prone public suffixes. Pass
`_noDomainSibling: true` if the caller already emitted a domain manually.

Read sites: `src/app/app-sidebar.js`, `src/app/app-sidebar-focus.js`,
`src/app/app-copy-analysis.js`. Full per-field contract:
[IOC Push Checklist](#ioc-push-checklist).

### Drill-down: the `open-inner-file` event protocol

Recursive dispatch (open an archive entry, an attachment, a re-classified
binary overlay, a decoded payload) is plumbed through a single bubbling
CustomEvent named `open-inner-file`. The renderer that builds a child
view dispatches; `_loadFile` listens at the `App` shell and re-enters
the main load path.

| Field | Type | Meaning |
|---|---|---|
| `event.detail` | `File` | A real or synthetic `File` object — the inner entry to load |
| `event.detail.name` | `string` | Display name for the breadcrumb / nav stack |
| `event.detail._prefetchedBuffer` | `ArrayBuffer?` | Optional; lets the listener skip a re-read when the parent already has the bytes in memory |

**Dispatchers (today):**

- `archive-tree.js` row click (used by zip/7z/tar/cab/iso/jar/msi/msix/pkg/npm/browserext)
- `binary-overlay.js` re-dispatch button (PE/ELF/Mach-O appended payload)
- `pe-renderer.js` resource-tree row click (embedded PE/script/data resources)
- `eml-renderer.js`, `msg-renderer.js`, `pdf-renderer.js`, `onenote-renderer.js` attachment opens

**Listener:** `src/app/app-load.js` (one App-level handler). It pushes a
nav-stack frame, then re-enters `_loadFile(file, prefetchedBuffer)` which
re-runs the full `RendererRegistry.dispatch` chain. The Back button pops
the frame and replays the parent.

`encoded-content-detector` is a partial exception: it inline-classifies
decoded blobs today rather than going through `open-inner-file`. Roadmap
item D3 unifies both paths under a single `App.openInnerFile` helper.

### YARA cost model

| Path | Trigger | Thread | Failure mode | Gating |
|---|---|---|---|---|
| Auto-YARA (`_autoYaraScan`) | Every successful `_loadFile` | Worker (`yara.worker.js`); main-thread fallback when `Worker(blob:)` is denied | Visible `IOC.INFO` note on size-skip / scan error (interim shim until PLAN F2 introduces `App._reportNonFatal`) | Worker path: unbounded — `worker.terminate()` cancels mid-loop on Back navigation. Fallback path: skipped above `PARSER_LIMITS.MAX_AUTO_YARA_BYTES` (32 MiB) since the main thread cannot be preempted. Manual scan via the YARA tab is unrestricted on either path |
| Manual scan tab | User clicks the **YARA** sidebar tab | Worker (`yara.worker.js`); main-thread fallback when `Worker(blob:)` is denied | Surfaced via the panel's status line (suffixed `(worker)` when the worker path is active) | Manual only |
| Rules editor validate / preview | User edits in the rules dialog | Main, synchronous | Inline `valid` / `errors` summary | Manual only |

The engine itself (`src/yara-engine.js`) is pure JS and well-bounded; the
cost is the scheduling, not the parser. PLAN items B3 (size gate +
visible failure surface) and C1 (move scanning to a Web Worker) address
the main-thread freeze on multi-megabyte files.

### Worker subsystem

Loupe ships a single HTML file but still moves a few CPU-heavy passes off
the main thread by spawning Web Workers from inline `blob:` URLs. The
CSP `worker-src blob:` directive (see [SECURITY.md → Full
Content-Security-Policy](SECURITY.md#full-content-security-policy)) is
the only relaxation needed. Today `pdf.js`, the in-tree YARA scanner,
the Timeline parser, the EncodedContentDetector, and the binary-string
extractor (opt-in via `BinaryStrings.extractStringsAsync`) all run in
workers.

**Module shape — `src/workers/<name>.worker.js`.** A worker module runs
inside `WorkerGlobalScope`. It has **no DOM, no `window`, no `document`,
no `app.*` references**; the only globals it sees are
`self` / `postMessage` / `onmessage` plus whatever helpers it explicitly
imports via build-time concatenation. Workers are pure functions over
`ArrayBuffer` in / typed-message events out — never reach for
`document.createElement` or any renderer's container DOM.

**Build-time inlining.** `scripts/build.py` reads each
`src/workers/*.worker.js` and emits a single string constant per worker
into the bundle (e.g. `const __YARA_WORKER_SRC = "..."`). The spawner
materialises the worker at runtime via:

```js
const blob = new Blob([__YARA_WORKER_SRC], { type: 'text/javascript' });
const url  = URL.createObjectURL(blob);
const w    = new Worker(url);          // CSP allows `worker-src blob:`
URL.revokeObjectURL(url);              // safe: Worker keeps its own ref
```

This is the **only** sanctioned worker-spawn shape. A
`scripts/build.py` regex gate rejects any `new Worker(` outside the
allow-listed spawner / worker modules — see *Tripwires* below.

**Lifecycle and fallback contract.** Every spawn site wraps construction
in `try { new Worker(url) } catch (_) { … main-thread fallback … }`.
The browser may refuse `Worker(blob:)` from `file://` (Firefox's default
deny); when that happens the spawner persists "workers unavailable" for
the rest of the session and routes future calls to the synchronous
in-tree fallback. Each load increments a cancellation token; stale
`onmessage` deliveries from a terminated worker are dropped, and Back
navigation calls `worker.terminate()` to abandon any in-flight scan.

**postMessage protocol.** Workers post tagged events; the host
multiplexes on `event`:

| Event | Payload | When |
|---|---|---|
| `columns` | `{ columns: [...] }` | Once, at the top of a streamed parse (Timeline only) |
| `rows` | `{ rows: [...], offset: N }` | Streaming batches |
| `iocs` | `{ iocs: [...] }` | Interleaved as IOCs are extracted |
| `progress` | `{ progress: 0..1 }` | Optional UI hint |
| `done` | `{ stats: { rowCount, parseMs, ... } }` | Terminal success |
| `error` | `{ message }` | Terminal failure (host falls back to main-thread path) |

Buffers cross the boundary as **transferable** `ArrayBuffer`: the worker
takes ownership and the main thread loses access. If the host needs the
bytes again (e.g. for a re-scan after Back navigation), it re-reads them
from the original `File`.

**Timeout & preemption (PLAN C5).** Every `WorkerManager.run*` call is bracketed by a `PARSER_LIMITS.WORKER_TIMEOUT_MS` (2 min) deadline. On expiry, `worker.terminate()` is called — real preemption, since the worker's JS engine is killed mid-iteration, unlike the post-hoc main-thread `ParserWatchdog` which only kills the wrapping promise — and the call's promise rejects with a `ParserWatchdog`-shaped error (`err._watchdogTimeout = true`, `err._watchdogName` = the channel name such as `'yara'` / `'timeline'` / `'encoded'` / `'strings'`, `err._watchdogTimeoutMs`). The active-token bump that runs alongside `terminate()` prevents any in-flight `done` / `error` message from a superseded worker from reaching the host. The host's caller-side fallback contract is unchanged: any rejection (workers-unavailable, worker-reported `error`, watchdog timeout) drops the call to the synchronous main-thread path. The 2 min budget is intentionally larger than `RENDERER_TIMEOUT_MS` (30 s) because workerised work is off-main-thread — the UI stays responsive during long scans, so legitimate large-file YARA / encoded / timeline / strings jobs don't false-positive at 30 s — and is enforced uniformly across all four channels by the private `_runWorkerJob(spec)` helper in `src/worker-manager.js`.

**Tripwire — worker-spawn allow-list.** `scripts/build.py` runs a
build-time grep over every entry in `JS_FILES` and fails the build on any
`new Worker(` reference outside the allow-list (`src/workers/*.worker.js`
plus the future `src/worker-manager.js` spawner). pdf.js spawns its own
worker from vendored code, which is read separately and not part of
`JS_FILES`, so the gate doesn't false-positive on it. The gate also
keeps premature `new Worker(...)` calls out of the tree until each
PLAN Track C worker lands together with its host-side spawner.

**Implemented workers.**

| Worker | Host-side spawner | Purpose | postMessage shape |
|---|---|---|---|
| `src/workers/yara.worker.js` | `src/worker-manager.js` (`WorkerManager.runYara(buffer, source)` / `WorkerManager.cancelYara()` / `WorkerManager.workersAvailable()`) | Auto-YARA on every successful `_loadFile` and the manual YARA-tab scan. The bundle is concatenated `yara-engine.js` + worker glue, inlined as the `__YARA_WORKER_BUNDLE_SRC` string constant by `scripts/build.py`, materialised at runtime via `Blob` → `URL.createObjectURL` → `new Worker(url)`. Buffers cross as transferable `ArrayBuffer`; the host re-derives bytes from the original `File` for any subsequent re-scan. | Inbound: `{buffer, source}`. Outbound: `{event:'done', results, parseMs, scanMs, ruleCount}` or `{event:'error', message}`. Exactly one terminal event per scan; the worker never throws. Cancellation is `worker.terminate()` on the next `_loadFile` (PLAN C1). |
| `src/workers/timeline.worker.js` | `src/worker-manager.js` (`WorkerManager.runTimeline(buffer, kind, options)` / `WorkerManager.cancelTimeline()`) | **Parse-only** off-thread loader for the four timeline-tab kinds — `csv`, `tsv`, `evtx`, `sqlite` (Chrome history). The worker is composed by `scripts/build.py` from `src/workers/timeline-worker-shim.js` (stubs out `IOC`/`escalateRisk`/`pushIOC`/`lfNormalize`/`EVTX_EVENT_DESCRIPTIONS` so renderer code parses cleanly outside the App context) + the parse halves of `csv-renderer.js`, `sqlite-renderer.js`, and `evtx-renderer.js`, then `timeline.worker.js` itself, inlined as `__TIMELINE_WORKER_BUNDLE_SRC` and materialised the same `Blob` → `URL.createObjectURL` → `new Worker(url)` way as the YARA worker. **Analysis stays on the main thread:** the EVTX path runs `EvtxDetector.analyzeForSecurity(buffer, fileName, prebuiltEvents)` on the host after the rows arrive (the worker emits `events` alongside `rows` so the analyzer can reuse them without re-parsing); CSV/TSV obvious-malware sweeps and the per-cell `EncodedContentDetector` pass also stay host-side. The worker bundle deliberately excludes `EvtxDetector`, `EncodedContentDetector`, IOC plumbing, and any DOM. | Inbound: `{kind, buffer, options}` (one transferable `ArrayBuffer`; `options` carries kind-specific knobs such as the CSV delimiter override or the SQLite history `tableHint`). Outbound: a single terminal `{event:'done', kind, columns, rows, formatLabel, truncated, originalRowCount, parseMs, ...kindExtras}` (e.g. EVTX adds `events` for the main-thread analyzer; SQLite adds the resolved `tableHint`) or `{event:'error', message}`. Cancellation is `worker.terminate()` from `_loadFile` (alongside `cancelYara()`) and on the next `runTimeline` call. |
| `src/workers/encoded.worker.js` | `src/worker-manager.js` (`WorkerManager.runEncoded(buffer, textContent, options)` / `WorkerManager.cancelEncoded()`) | Off-thread `EncodedContentDetector.scan()` — the 2,114-line recursion that mines nested base64 / hex / zlib / chararray / Python-`bytes()` chains out of every loaded file's text view. The worker bundle is composed by `scripts/build.py` from `src/workers/encoded-worker-shim.js` (a tight prelude that defines just the `IOC.*` constants, the `PARSER_LIMITS.MAX_UNCOMPRESSED` cap, and `_trimPathExtGarbage` that the detector reads at module load) + `vendor/pako.min.js` (sync zlib fallback when `DecompressionStream` is missing) + `vendor/jszip.min.js` (used by the detector to validate embedded ZIP candidates and prune false-positive zlib hits) + `src/decompressor.js` + `src/encoded-content-detector.js`, then `encoded.worker.js` itself, inlined as `__ENCODED_WORKER_BUNDLE_SRC`. The worker eagerly drives `lazyDecode()` on every cheap finding before posting so the sidebar can render decoded previews without a second round-trip. **IOC merging stays on the main thread** — the host's `_loadFile` post-scan loop owns deduping decoded IOCs against `findings.interestingStrings`, stamping `_sourceOffset` / `_highlightText` / `_decodedFrom` / `_encodedFinding` back-references for click-to-focus, and re-attaching `_rawBytes` (stripped before postMessage to avoid detaching the host's buffer copy) on compressed findings whose decompression is deferred to user click. | Inbound: `{textContent, rawBytes (transferred ArrayBuffer), options:{fileType, mimeAttachments, maxRecursionDepth?, maxCandidatesPerType?}}`. Outbound: `{event:'done', findings, parseMs}` (findings have `_rawBytes` stripped — host re-stamps from its retained copy) or `{event:'error', message}`. Exactly one terminal event per scan. Cancellation is `worker.terminate()` from `_loadFile` (alongside `cancelYara()` / `cancelTimeline()`) and on the next `runEncoded` call. |
| `src/workers/strings.worker.js` | `src/worker-manager.js` (`WorkerManager.runStrings(buffer, opts)` / `WorkerManager.cancelStrings()`) | Off-thread ASCII + UTF-16LE printable-string extractor — the same two-pass sweep `extractAsciiAndUtf16leStrings()` performs on the main thread for PE / ELF / Mach-O / DMG. The worker bundle is composed by `scripts/build.py` from `src/workers/strings-worker-shim.js` (carries a verbatim copy of the extractor — the worker has no access to `src/constants.js`) + `strings.worker.js` itself, inlined as `__STRINGS_WORKER_BUNDLE_SRC`. **No in-tree caller migration ships with C4** — the three native-binary renderers and DMG still call `extractAsciiAndUtf16leStrings()` synchronously because their `static render(file, buffer, app)` paths cannot `await` until PLAN Track D1 (`renderRoute` + `RenderResult`) lands. The worker is exposed today as the opt-in `BinaryStrings.extractStringsAsync(buffer, opts)` helper so renderers can adopt it as soon as they go async; the helper falls back to the synchronous `extractAsciiAndUtf16leStrings()` whenever the worker probe fails or the worker rejects. The `cancelStrings()` cancellation hook is wired into `_loadFile` alongside the YARA / Timeline / Encoded hooks so nothing leaks across file loads once callers do migrate. | Inbound: `{buffer (transferred ArrayBuffer), opts:{start?, end?, asciiMin?, utf16Min?, cap?}}`. Outbound: `{event:'done', ascii, utf16, asciiCount, utf16Count, parseMs}` (same shape as the synchronous helper plus timing) or `{event:'error', message}`. Exactly one terminal event per scan. Cancellation is `worker.terminate()` from `_loadFile` (alongside `cancelYara()` / `cancelTimeline()` / `cancelEncoded()`) and on the next `runStrings` call. |
| `vendor/pdf.worker.js` | `pdfjsLib` (vendored) | Worker-side PDF page rendering for `PdfRenderer`. Spawns its own worker from the vendored bundle independently of `worker-manager.js`. | Internal pdf.js `postMessage` protocol — opaque to Loupe. |

The YARA worker is the canonical reference for new PLAN Track C
workers: a single worker module that owns one CPU-heavy pass, a thin
`worker-manager.js` host-side spawner that probes once, caches
"workers unavailable" for the rest of the session on probe failure,
and routes all callers through the same supersede-and-terminate
token. Auto-YARA's `MAX_AUTO_YARA_BYTES` size gate now applies only
on the synchronous main-thread fallback (Firefox `file://` denies
`Worker(blob:)`); the worker path has no buffer-size cap because
`worker.terminate()` is true preemption, and is instead bracketed
by the 2 min `PARSER_LIMITS.WORKER_TIMEOUT_MS` wall-clock deadline
(PLAN C5) shared by every `WorkerManager.run*` channel.

### Persistence keys

Every user-persisted preference lives under the `loupe_` namespace and is
catalogued in [Persistence Keys](#persistence-keys) below — that table is
the single source of truth. New keys must obey the rules in that section
(prefix, accessor pattern, validation on read).

---

## Gotchas & Tripfalls

If you skip this section your change will probably still build, then
subtly misbehave.

### Build artefacts & source of truth

- **`docs/index.html` is a build artefact — not tracked in git.** It's in
  `.gitignore`; do not commit it.
- **`CODEMAP.md` is auto-generated.** Regenerate with
  `python scripts/generate_codemap.py` after code changes.
- **The `JS_FILES` order in `scripts/build.py` is load-bearing.** The
  `Object.assign(App.prototype, …)` pattern means later files override
  earlier ones' methods. `app-copy-analysis.js` holds the 28 per-format
  `_copyAnalysisXxx` markdown builders and must load **after** `app-ui.js`
  (it consumes `_formatMetadataValue` / `_sCaps` defined there).
  `app-sidebar-focus.js` holds the click-to-focus / highlighting engine
  (`_navigateToFinding`, `_findIOCMatches`, `_highlightMatchesInline`, the
  TreeWalker fallback, plus the Binary Metadata + MITRE sections) and must
  load **after** `app-sidebar.js` so the rendering half's click handlers
  find the focus engine on `App.prototype`.
  `app-settings.js` must load **after** both `app-ui.js` and
  `app-copy-analysis.js` because it reuses the `THEMES` array from
  `app-ui.js` and overrides the unbudgeted `_copyAnalysis` call path with
  the configured Summary-budget step. `app-bg.js` must load **before**
  `app-core.js` and `app-ui.js` because it exposes the global
  `window.BgCanvas` singleton that `App.init()` and `_setTheme()` both
  invoke — the two call sites are guarded (`if (window.BgCanvas) …`) so
  the cosmetic background is optional, but the load order keeps that
  guard a no-op in production. `app-timeline.js` loads immediately
  after `app-core.js` and owns the **only** viewer path for CSV / TSV /
  EVTX files — there is no user-visible mode toggle, no `T` keybind, no
  📈 toolbar button, and no autoswitch threshold. When any CSV / TSV /
  EVTX is loaded the app adds `has-timeline` to `document.body.classList`
  so CSS in `core.css` swaps the sidebar/viewer stack for the timeline
  stack without re-mounting either; `_clearTimelineFile()` removes the
  class on file close. Routing is driven by three independent probes in
  `app-load.js::_loadFile()`, each guarded by a one-shot
  `this._skipTimelineRoute` escape-hatch so a failed parse can fall back
  without re-entering the router: (1) `_isTimelineExt(file)` — a cheap
  extension match (`.csv` / `.tsv` / `.evtx`); (2) a magic-byte EVTX
  sniff for extensionless files whose first 7 bytes spell `ElfFile`; (3)
  `_sniffTimelineContent(buffer)` — a text-head sniff that looks for
  delimiter-separated rows in the first few KiB. Any probe that matches
  calls `_loadFileInTimeline(file, buffer)`. The timeline path is
  deliberately narrower than the generic viewer — no YARA, no sidebar,
  no `EncodedContentDetector` — and it reuses `GridViewer` with
  `timeColumn: -1` so the grid never paints its own timeline strip (the
  outer `TimelineView` owns the scrubber + stacked-bar chart). For EVTX
  specifically, `TimelineView` also renders two new Timeline sections
  fed by the renderer's `externalRefs` array: **Detections**
  (`type: IOC.PATTERN` rows with `severity` + `eventId` + `count`, each
  clickable to filter the grid to that Event ID) and **Entities** (all
  other IOC types — `HOSTNAME` / `USERNAME` / `FILENAME` / `PROCESS` /
  `HASH` / `IP` / `URL` / `UNC_PATH` / `FILE_PATH` / `COMMAND_LINE` /
  `REGISTRY_KEY` / `DOMAIN` / `EMAIL` — grouped by type with per-value
  hit counts, `PATTERN` / `INFO` / `YARA` rows filtered out). EVTX events
  are parsed once: `app-timeline.js` passes the already-parsed event
  array to `EvtxDetector.analyzeForSecurity(buffer, fileName,
  prebuiltEvents)` so detection extraction doesn't re-parse the log.
  The analyzer was extracted from `evtx-renderer.js` into its own module
  `src/evtx-detector.js` so the Timeline worker bundle can ship the
  parser without dragging the threat-detection pass with it;
  `EvtxRenderer.analyzeForSecurity` is now a one-line forward to
  `EvtxDetector.analyzeForSecurity` for the non-Timeline (generic
  viewer) callsite. Renderers load before `renderer-registry.js`,
  which loads before `app-core.js`.

### CSP & runtime safety

- **No `eval`, no `new Function`, no network.** The Content-Security-Policy
  (`default-src 'none'` + `script-src 'unsafe-inline'` only for the
  single-file bundle) rejects anything you add that needs a fetch, a
  `<script src>`, or a dynamic code constructor. Don't relax the CSP to
  make a feature work — find another way.
- **Images / blobs only from `data:` and `blob:` URLs.** Anything else is
  blocked at load.
- **Sandboxed previews** (`<iframe sandbox>` for HTML / SVG / MHT) have
  their own inner `default-src 'none'` CSP. Don't assume a preview iframe
  can load any resource that the host page can — it can't.

### YARA rule files

- **YARA rule files contain no comments.** `scripts/build.py` concatenates
  `YARA_FILES` with `// @category: <name>` separator lines inserted
  between files — those are the **only** `//` lines the in-browser YARA
  engine expects to tolerate. Any inline `//` or `/* */` comment you
  author inside a `.yar` file goes into the engine as rule source and
  either breaks the parse or produces a no-match rule. Explanations go in
  `meta:` fields.
- **Category labels are inserted by `scripts/build.py`**, not authored by hand.

### Renderer conventions

- **IOC types must use `IOC.*` constants** from `src/constants.js` — never
  bare strings like `type: 'url'`, `type: 'ip'`, `type: 'domain'`. The
  sidebar filters by exact type string; a bare string silently breaks
  filtering, sidebar grouping, STIX / MISP export mapping, and the
  `ioc-conformity-audit` skill. Enforced by a build-time grep gate in
  `scripts/build.py` (paired with the risk-pre-stamp gate from B1) — any
  line containing both `type: '<bare>'` and `severity:` outside
  `src/constants.js` fails the build.
- **Renderer `findings.risk` starts `'low'`.** Only escalate via
  `escalateRisk(findings, tier)` from `src/constants.js`, which applies
  the rank-monotonic ladder so later evidence only ever lifts the tier.
  Direct `f.risk = 'high'` writes are rejected by a build-time grep gate
  in `scripts/build.py` (allow-listed only for `src/constants.js`, where
  the helper lives). Pre-stamping produces false-positive risk colouring
  on benign samples. See the **Risk Tier Calibration** subsection for
  the canonical escalation tail.

- **Prefer `pushIOC()` over hand-rolling `interestingStrings.push(...)`.**
  `pushIOC` pins the on-wire shape and auto-emits a sibling `IOC.DOMAIN`
  when `tldts` resolves the URL to a registrable domain. If you already
  emit a manual domain row, pass `_noDomainSibling: true`.
- **`_rawText` must be `\n`-normalised — wrap the RHS in `lfNormalize(...)`.**
  The sidebar's click-to-focus uses character offsets into `_rawText`; a
  single CRLF misaligns every offset after it. Use the canonical
  `lfNormalize(s)` helper from [`src/constants.js`](src/constants.js) on
  every `*._rawText = <expr>` write — `scripts/build.py` rejects any RHS
  that doesn't begin with `lfNormalize(` (allow-listed only for
  `src/constants.js`, where the helper lives).
- **Renderer roots must opt into full width.** `#viewer` is a flex column
  with `align-items: center`, which shrink-wraps any unconstrained child
  to its own content width. A `<table>` or `<pre>` that contains a
  multi-megabyte minified-JS line will happily size itself to the widest
  cell and push the whole viewer off-screen. A renderer root that holds
  wide content must declare `align-self: stretch; width: 100%; min-width: 0`
  (and, for tables, `table-layout: fixed`) so flex shrink can engage and
  the CSS wrap rules (`word-break: break-all`, `white-space: pre-wrap`)
  actually kick in.
- **Soft-wrap pathologically long lines in display.** When a renderer shows
  a line-numbered text view, any logical line over a few thousand
  characters should be split into display-only chunks before it reaches
  the DOM. A single 2 MB `<td>` tanks layout / paint / click-to-focus even
  with `table-layout: fixed`. See `PlainTextRenderer.LONG_LINE_THRESHOLD`
  / `SOFT_WRAP_CHUNK` for the canonical values.
- **Long IOC lists must end with an `IOC.INFO` truncation marker.** When a
  renderer walks a large space and caps at (say) 500 entries, push exactly
  one `IOC.INFO` row after the cap explaining the reason and the cap count
  — the Summary / Share exporters read this row.
- **Two limit constants, two different jobs.** `PARSER_LIMITS`
  (`src/constants.js`) is the *safety* envelope (`MAX_DEPTH`,
  `MAX_UNCOMPRESSED`, `MAX_RATIO`, `MAX_ENTRIES`, `TIMEOUT_MS`,
  `RENDERER_TIMEOUT_MS`, `MAX_AUTO_YARA_BYTES`) — raising
  it weakens zip-bomb / recursion / timeout defences. `RENDER_LIMITS`
  (same file) caps how much **parsed data** the UI renders
  (`MAX_TEXT_LINES`, `MAX_TEXT_LINES_SMALL`, `MAX_CSV_ROWS`,
  `MAX_TIMELINE_ROWS`, `MAX_EVTX_EVENTS`) — raising it only affects
  completeness / memory, not safety. New render caps should reference
   `RENDER_LIMITS.*` rather than invent a fresh magic number.
- **EVTX column names live in `EVTX_COLUMNS` / `EVTX_COLUMN_ORDER`**
  (`src/constants.js`). Use `EVTX_COLUMNS.EVENT_ID` etc. instead of bare
  `'Event ID'` strings when doing `indexOf` look-ups or building the
  column array in `evtx-renderer.js` and `app-timeline.js`.
- **Hot-path renderers must finish within `PARSER_LIMITS.RENDERER_TIMEOUT_MS`
  (30 s).** `_loadFile` wraps every per-id handler in `_rendererDispatch`
  with `ParserWatchdog.run(fn, { timeout, name })`; on timeout it resets
  `findings` / `_binaryParsed` / `_yaraBuffer`, falls back to
  `PlainTextRenderer`, and pushes an `IOC.INFO` row pointing the analyst
  at the manual YARA tab. Renderers should keep a single deterministic
  parse pass under that budget — if a format genuinely needs more (e.g.
  full-document re-decompression of a multi-hundred-MB OOXML), gate the
  expensive pass behind a user gesture rather than running it from
  `static render()`. Watchdog timeouts are distinguishable from genuine
  exceptions by the `_watchdogTimeout`, `_watchdogName`, and
  `_watchdogTimeoutMs` sentinel fields on the rejected error; the outer
  60 s `PARSER_LIMITS.TIMEOUT_MS` cap remains a separate budget around
  the initial `file.arrayBuffer()` read only.

### Determinism (for `scripts/build.py` and anything it runs)

- **No `datetime.now()`** in `scripts/build.py` or any generator it runs,
  except the one gated `SOURCE_DATE_EPOCH` fallback that already exists.
- **No file-system iteration order.** Enumerate files from an explicit
  hardcoded list (as `JS_FILES`, `CSS_FILES`, `YARA_FILES` do). Never walk
  a directory and trust OS iteration order.
- **No random IDs, UUIDs, or nonces** in the bundle. Derive stable
  identifiers from file contents (e.g. SHA-256 of the input, or the
  VENDORED.md pin list as `scripts/generate_sbom.py` does for the
  CycloneDX serial number).
- **No machine-local paths** embedded in output. `build.py` reads with
  relative paths — keep it that way.
- **No dict/set ordering that relies on hash randomisation.** Writing
  sets to the bundle is unsafe; sort first.

### Docs & persistence

- **Long single-line table cells break `replace_in_file`.** Cap
  table-cell content at ~140 characters / one sentence. If you need more
  room, split the row or move the deep detail here, leaving a one-liner
  pointer in `FEATURES.md`.
- **New `localStorage` keys must use the `loupe_` prefix** and be added
  to the [Persistence Keys](#persistence-keys) table below.

### Non-obvious renderer behaviour

- **EML / MSG `<a href>` is rendered inert.** An analyst must be able to
  inspect a hostile URL without accidentally navigating to it. The
  `href` is preserved only in a `title` tooltip.
- **MSIX `_parseP7x` is a deliberately conservative DER token-scan** —
  not a full ASN.1 walker. It confirms the `PKCX` magic, scans for the
  relevant OIDs, and extracts signer CN / O for comparison against the
  manifest's `Publisher` DN.
- **SVG / HTML `_yaraBuffer`** is an augmented representation (e.g.
  decoded Base64 payloads) used for YARA scanning only. Never
  contaminate Copy / Save with it.
- **`ImageRenderer` decodes TIFFs twice via `UTIF`** — once in `render()`
  for pixels, once in `analyzeForSecurity()` for IFD tag mining.
- **`QrDecoder` is the shared quishing entry point.** Any renderer that
  materialises a raster surface — standalone images, PDF page canvases,
  SVG-embedded `data:image/*` URIs, OneNote `FileDataStoreObject` blobs,
  EML `image/*` attachments — should funnel it through
  `QrDecoder.decodeRGBA()` (sync, for paths that already hold pixels,
  e.g. `UTIF`) or `QrDecoder.decodeBlob()` (async, for raw image bytes)
  and pass the result to `QrDecoder.applyToFindings(findings, result, source)`.
  Because `decodeBlob()` is async, **the renderer's `analyzeForSecurity`
  must itself be `async` and must `await` every decode before
  returning** — collect the promises (`const qrPromises = [];
  qrPromises.push(QrDecoder.decodeBlob(...).then(...));`) and
  `await Promise.all(qrPromises)` before the final `return findings`.
  The corresponding dispatch handler in `src/app/app-load.js` must also
  be marked `async` and use `await r.analyzeForSecurity(...)`.
  `_renderSidebar` paints from a one-shot snapshot of `findings` taken
  when `analyzeForSecurity` resolves — a fire-and-forget decode that
  mutates `findings` *after* that snapshot lands the `qrPayload` /
  auto-emitted IOC in an object nobody is rendering. `PdfRenderer` is
  the model: it already awaits `pdfjs` page rendering and calls the
  sync `decodeRGBA()` on pixels it already owns.
- **Binary overlay detection is shared across PE / ELF / Mach-O** via
  `src/binary-overlay.js` (`BinaryOverlay.compute()` + `renderCard()`).
  Overlay start is computed per-format: PE uses
  `max(section.PointerToRawData + section.SizeOfRawData)`; ELF uses
  `max(sh.sh_offset + sh.sh_size)` across non-`SHT_NOBITS` section
  headers with a `max(ph_offset + ph_filesz)` program-header fallback
  for stripped binaries; Mach-O uses `max(segment.fileoff + segment.filesize)`
  (plus a post-code-signature bound). Fat/Universal walks every slice
  and also checks for bytes past the Fat container's tail. The card
  dispatches an `open-inner-file` `CustomEvent` whose `detail` is a
  synthetic `File` — `app-load.js::pe()` / `elf()` / `macho()` each call
  `this._wireInnerFileListener(docEl, file.name)` so the overlay routes
  through the standard nav-stack drill-down path. **Authenticode
  exemption (PE only):** the overlay card passes
  `authenticodeRange: [certDD.rva, certDD.rva + certDD.size]` so the
  signature blob itself is excluded from the overlay's "unusual" flag.
  Bytes appended *past* the signature blob are the classic post-sign
  tamper and escalate to `critical` (T1553.002). SHA-256 is computed
  asynchronously via `crypto.subtle.digest` (CSP-safe) and is written
  back onto `findings.metadata['Overlay SHA-256']` after
  `analyzeForSecurity` has returned — it appears on the next sidebar
  refresh. Entropy is capped at a 2 MiB sample to avoid freezing on
  multi-GiB installers.
- **Shared binary-analysis modules (`src/hashes.js`, `src/capabilities.js`)**
  are loaded before the renderers and are the canonical path for
  cross-format pivots. `hashes.js` exposes `md5()`,
  `computeImportHashFromList(items)` (PE imphash),
  `computeRichHash(bytes, danSOff, richOff, xorKey)`, and
  `computeSymHash(importedSymbols, dylibs)` — used by `PeRenderer`,
  `ElfRenderer` (telfhash-style MD5 of sorted imported-symbol names),
  and `MachoRenderer` (SymHash of imported symbols + dylib basenames).
  `capabilities.js` exposes `Capabilities.detect({imports, dylibs, strings})`
  returning `[{id, name, severity, mitre, description, evidence}]` rows
  mapped to MITRE ATT&CK. Each renderer's `analyzeForSecurity` should
  call it inside a `try / catch` so a capability-match failure never
  aborts analysis, then push each hit onto `externalRefs` as
  `IOC.PATTERN` with `_noDomainSibling: true` (patterns never imply a
  registrable domain). Mirror the hash results via `mirrorMetadataIOCs`
  with `{RichHash: IOC.HASH, 'Import Hash (MD5)': IOC.HASH, SymHash: IOC.HASH}`
  so they reach the sidebar as clickable pivots.
- **PE TLS callbacks + entry-point sanity** are parsed during
  `PeRenderer._parse()` and attached to the parsed PE object as two
  independent shapes. `pe.tls = { callbacks: [{va, rva, fileOffset, section}],
  rawOffset, callbackArrayRva }` is produced by `_parseTlsCallbacks()`, which
  walks `IMAGE_DIRECTORY_ENTRY_TLS` (index 9) → `IMAGE_TLS_DIRECTORY` →
  the NULL-terminated `AddressOfCallBacks` VA array (hard-capped at 32
  entries to avoid pathological inputs). `pe.entryPointInfo = { rva,
  section, inText, notInText, inWX, orphaned, skipped }` is produced by
  `_analyzeEntryPoint()`, which classifies `AddressOfEntryPoint` against
  the section table — `TEXT_LIKE = new Set(['.text','CODE','.code','text','.itext','INIT','.init'])`
  is the canonical list of section names considered normal code hosts. The
  `render()` path adds a TLS Callbacks card immediately after the Rich
  Header section (each callback is a clickable row that expands into a
  64-byte hex-dump preview via `_renderHexDump(cb.fileOffset, 64)`) and
  annotates the Entry Point row in the header table with badges for
  orphaned / non-`.text` / W+X placement. `analyzeForSecurity()` folds
  these into the risk score **before** capability tagging so entry-point
  anomalies rank above generic capability hits: orphan EP → `IOC.PATTERN`
  high `+3` (T1027); EP landing in a W+X section → `IOC.PATTERN` high
  `+2.5` (T1027.002); TLS callbacks present → `IOC.PATTERN` medium `+1.5`
  (T1546.009), escalated to high `+2.5` when a callback itself resides in
  a W+X section **or** any anti-debug capability was detected in the same
  binary. The callback count is mirrored onto `findings.metadata['TLS Callbacks']`
  for the sidebar. The reference sample is `examples/pe/tls-callback.exe`
  — a 1 536-byte PE32 with a single ret-only TLS callback at
  `.text + 0x20`.
- **PE resource drill-down** is implemented in `PeRenderer._parseResources()`,
  which performs a full three-level walk (type → name → language) of the
  resource directory and attaches a flat `.leaves` array to the returned
  type-summary. Each leaf carries `{typeId, typeName, typeIsNamed, nameId,
  nameStr, langId, rva, size, fileOffset}` plus a pre-computed
  `BinaryOverlay.sniffMagic()` hit (`{label, extHint}`) against the first
  bytes of the leaf payload. Walk caps: 64 distinct types, 256 leaves in
  aggregate, 50 MB per leaf — anything beyond is dropped to bound the
  parser budget. `_renderResources()` emits a second table (below the
  existing type summary) where every non-inert leaf with a recognised
  magic, a named slot, or a known payload-carrying id (RCDATA / HTML /
  MANIFEST) becomes clickable and dispatches an `open-inner-file`
  `CustomEvent` with a synthetic `File` named
  `<parent>.res.<type>.<name>[.lang].<ext>`, which the listener wired
  by `_wireInnerFileListener()` in `app-load.js` re-dispatches through
  `RendererRegistry`. `analyzeForSecurity()` walks the leaves after the
  capability-tagging block and pushes `IOC.PATTERN` rows: embedded
  PE / ELF / Mach-O / SO / DYLIB magic → high `+2.5` (T1027.009);
  embedded archives (ZIP / 7z / RAR / gzip / CAB / TAR / XZ / BZ2) in
  stashing slots (RCDATA / HTML / MANIFEST / named) → medium `+1.5`
  (T1027.009); no-magic blobs > 64 KB with Shannon entropy > 7.2 in
  the same slots → medium `+1` (T1027.002). Inert resource types
  (icons, cursors, fonts, string / message tables, menus, dialogs,
  accelerators, version info — ids 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12,
  14, 16) are skipped entirely. The payload-candidate count is mirrored
  onto `findings.metadata['Embedded Resource Payloads']` for the
  sidebar. Reference sample: `examples/pe/rcdata-dropper.exe` — a
  3 072-byte PE32 whose single `RT_RCDATA` leaf (type 10, name 1,
  lang 1033) contains a 1 536-byte minimal PE32.
- **Categorised binary strings (`src/binary-strings.js`)** is the shared
  helper that pulls mutex names, Windows named pipes, PDB paths,
  user-home / build-tree paths, and registry keys out of the PE / ELF /
  Mach-O string corpus and pushes each category as its own `IOC.*` row.
  `BinaryStrings.classify(strings)` returns
  `{mutexes, namedPipes, pdbPaths, userPaths, registryPaths}` as
  de-duplicated arrays; `BinaryStrings.emit(findings, strings)` calls
  `classify()` then pushes every hit through `pushIOC()` with the right
  type — `IOC.PATTERN` (medium) for mutexes / named pipes,
  `IOC.FILE_PATH` (info) for PDB paths and build-host paths,
  `IOC.REGISTRY_KEY` (medium) for registry keys — honouring
  per-category caps (`CAPS = {mutex:30, pipe:30, pdb:20, userPath:30,
  registry:30}`) and emitting an `IOC.INFO` truncation marker when the
  cap trims the list. All rows carry `_noDomainSibling: true` because
  none of these IOC shapes imply a registrable domain. Each renderer's
  `analyzeForSecurity()` calls `BinaryStrings.emit` inside a
  `try / catch` after the URL / UNC extraction block (same `allStrings`
  corpus) and mirrors the returned counts onto
  `findings.metadata['Mutex Names']` / `['Named Pipes']` /
  `['PDB Paths (str)']` / `['Build-host Paths']` / `['Registry Keys']`
  for the sidebar summary. Regexes are tight and length-bounded
  (2..120 chars for mutex / pipe identifiers; drive-letter or
  absolute-POSIX anchoring for path captures) because the string dumps
  carry a lot of printable garbage (CLR resource-table fragments,
  version-info UTF-16 blobs) that a loose regex would flag. The
  Windows-specific categories (mutex / pipe / registry) are trivially
  empty on ELF / Mach-O — those renderers therefore only mirror the
  `pdbPaths` / `userPaths` counts into metadata.
- **Rust panic paths (`src/binary-strings.js`)** join the categorised
  string pass to mine build-host attribution leaks from Rust binaries.
  `CAPS.rustPanic = 20` bounds the per-file emit; `RUST_PANIC_RX` matches
  both the classic `panicked at '…', src/file.rs:nnn:mm` shape and the
  Rust ≥ 1.73 inverted form `panicked at src/file.rs:nnn:mm: '…'`. Each
  hit is pushed through `pushIOC()` as `IOC.FILE_PATH` info-tier with
  `_noDomainSibling: true` (a `src/foo/bar.rs` leak is never a
  registrable domain), and the count is mirrored onto
  `findings.metadata['Rust Panic Paths']` from each of the three binary
  renderers. Panic strings survive `strip` because they live in
  `.rodata` / `__TEXT,__cstring` — making them a durable attribution
  tell when PDB paths have been stripped.
- **.NET CLR header parsing (`PeRenderer._parseClrHeader`)** surfaces
  managed-assembly metadata directly from the PE. The parser reads
  `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR` (directory index 14) → the 72-
  byte CLR header at its RVA → the `COMIMAGE_FLAGS_*` bitfield (`0x01`
  IL-only, `0x02` requires 32-bit, `0x04` IL-library, `0x08` strong-name
  signed, `0x10` native-entrypoint, `0x10000` track-debug-data,
  `0x20000` prefer-32-bit) → the `MetaData` RVA/size, which is then
  resolved through the section table to locate the BSJB metadata root
  magic `0x424A5342` and the trailing NUL-terminated runtime-version
  string (e.g. `v4.0.30319`). Results are attached as `pe.dotnet =
  {cb, runtimeVersion, runtimeVersionString, flags, isILOnly,
  requires32Bit, isILLibrary, hasStrongName, hasNativeCode,
  hasNativeEntryPoint, trackDebugData, prefer32Bit, entryPointToken,
  metadataRva, metadataSize, resourcesRva, resourcesSize,
  strongNameRva, strongNameSize, metadataMajor, metadataMinor}` and
  rendered as the 🔷 .NET CLR Header card between TLS Callbacks and
  Authenticode Certificates via `_renderDotnet(pe)`.
  `analyzeForSecurity()` mirrors the salient bits onto
  `findings.metadata` (`'Format'`, `'CLR Runtime'`, `'IL Only'`,
  `'Mixed-Mode / Native'`, `'Strong-Name Signed'`, `'Prefer 32-bit'`)
  and pushes `IOC.PATTERN` medium `.NET Managed Assembly [T1059.005]`
  (with an optional info-tier strong-name-signed sibling row). Risk
  bumps: managed assembly `+1`; mixed-mode / native-hosted CLR `+0.5`
  on top because managed + native in one image is a common unmanaged-
  shellcode host.
- **Export-anomaly flags (`src/binary-exports.js`)** surface three
  well-known library-export triage signals across PE / ELF / Mach-O.
  `BinaryExports.emit(findings, {isLib, fileName, exportNames,
  forwardedExports, ordinalOnlyCount})` returns
  `{sideLoadHit, forwarderCount, ordinalOnly, ordinalOnlyRatio}` and
  is called from each binary renderer's `analyzeForSecurity()` inside
  a `try / catch` immediately after the `BinaryStrings.emit` block.
  Three checks, each gated so benign binaries stay quiet:
  1. **Side-loading host match** — `SIDE_LOADING` is a case-insensitive
     Set of ~40 canonical T1574.002 target basenames (`version.dll`,
     `winmm.dll`, `uxtheme.dll`, `winhttp.dll`, `dbghelp.dll`,
     `cryptbase.dll`, VC runtime redistributables, `libcurl.dll`,
     `libssl-1_1.dll`, …). Only fires when `isLib` is true — we never
     want to flag an EXE that happens to be named `version.dll`.
     Emits `IOC.PATTERN` high.
  2. **Forwarded / proxy-DLL exports** — each forwarder string in
     `forwardedExports` is emitted as its own medium-severity
     `IOC.PATTERN`. `_looksLikeSystemPathForwarder` filters Windows
     platform forwarders (`api-ms-win-*`, `ext-ms-win-*`, `kernel32.*`,
     `ntdll.*`, `kernelbase.*`, `ucrtbase.*`, …) so the signal
     represents *unusual* proxying. Cap: 30 forwarders; overflow
     marker pushed when more exist.
  3. **Ordinal-only exports** — flagged when
     `ordinalOnlyCount / (ordinalOnlyCount + exportNames.length)` ≥
     `ORDINAL_ONLY_ANOMALY_RATIO` (0.5) **and** the absolute count is
     at least `ORDINAL_ONLY_ABS_FLOOR` (4). Single medium-severity
     `IOC.PATTERN` with the ratio in the message.
  Per-format wiring:
  - **PE** — `_parseExports` walks the function-RVA table in addition
    to the name-ordinal table. A function RVA that falls inside
    `[dataDirs[0].rva, dataDirs[0].rva + dataDirs[0].size]` is a
    forwarder: the NUL-terminated string at `_rvaToOffset(funcRva,
    sections)` gives the `OtherDll.FuncName` target.
    `ordinalOnlyCount` is `NumberOfFunctions - NumberOfNames`,
    computed against a `namedOrdinals` Set.
    `isLib: !!(pe.coff && pe.coff.isDLL)`. Risk: `+2` side-load,
    `+0.5 × forwarderCount` (cap `+2`), `+1` ordinal-only anomaly.
    Metadata rows: `'DLL Side-Load Host'`, `'Forwarded Exports'`,
    `'Ordinal-Only Exports'`.
  - **Mach-O** — `isLib: mo.filetype === 6` (MH_DYLIB); the forwarder
    analogue is LC_REEXPORT_DYLIB (cmd `0x1F`), already captured during
    load-command parsing as `mo.dylibs[i].type === 'reexport'`. No
    ordinal concept. Metadata row: `'Re-exported Dylibs'`.
  - **ELF** — `isLib: !!(elf.isDyn && elf.soname)` — ET_DYN alone is
    ambiguous (PIE EXE vs .so), so `DT_SONAME` is required. No
    forwarded-export or ordinal concept; only the side-loading filename
    check contributes. `exportNames` is sourced from dynsyms with
    `shndx !== 0` and `STB_GLOBAL` / `STB_WEAK` binding.
- **Binary Pivot triage card (`src/binary-summary.js`)** is the shared
  above-the-fold summary card each native-binary renderer appends
  *before* its big header / section / import tables so the analyst sees
  the pivot fields first. `BinarySummary.renderCard({bytes, fileSize,
  format, formatDetail, importHash, richHash, symHash, signer,
  compileTimestamp, entryPoint, overlay, packer})` returns a single
  `HTMLElement` the caller appends to `wrap`. The helper is pure
  presentation — it never mutates `findings`; risk calibration and IOC
  emission remain each renderer's `analyzeForSecurity()` responsibility.
  File hashes are filled asynchronously: SHA-1 / SHA-256 via
  `crypto.subtle.digest` (CSP-safe, same path the overlay card uses),
  MD5 via the shared `md5()` in `hashes.js` wrapped in `setTimeout(…, 0)`
  so large samples don't stall paint. Fake-timestamp detection lives on
  `BinarySummary.detectFakedTimestamp(epoch)` and flags four buckets:
  the sentinel set `{0, 0xFFFFFFFF, 0x2A425E19 (Borland TLINK default)}`,
  future-dated (`> now + 86400`), pre-2000 (`< 946684800`), and the
  Feb 2006 reproducible-build sentinel (`[1139011200, 1139184000)`) —
  the fixed epoch rustc / lld / Wix stamp into reproducible builds.
  Loading order: `src/binary-summary.js` is appended to `JS_FILES` in
  `scripts/build.py` immediately after `binary-exports.js` and
  **before** the three native renderers so its `BinarySummary` global
  is available at render time. CSS lives in `src/styles/viewers.css`
  under `.bin-summary-card` / `.bin-summary-header` /
  `.bin-summary-body` / `.bin-summary-row` / `.bin-summary-label` /
  `.bin-summary-value` / `.bin-summary-hash` / `.bin-summary-muted` /
  `.bin-summary-badge[-ok|-warn]`. Per-format wiring:
  - **PE** — imphash from `pe.imphash`; RichHash from
    `pe.richHeader.richHash`; signer from `pe.certificates[0].subject.CN
    || .subjectStr` (falls back to `'unsigned'`); compile timestamp
    `{epoch: pe.coff.timestamp, displayStr: pe.coff.timestampStr}`; EP
    anomaly derived from `pe.entryPointInfo` (`.orphaned` / `.inWX` /
    `.notInText`); overlay via `_computeOverlayStart(pe)` +
    `BinaryOverlay.sniffMagic`; packer from
    `pe.sections.find(s => s.packerMatch)`.
  - **ELF** — telfhash-style import hash computed inline from
    `elf.dynsyms.filter(s.shndx === 0)` via
    `computeImportHashFromList()`; signer permanently `{present: false,
    label: '— (ELF has no structural signer)'}` (code signing on ELF is
    an external tooling convention, not a structural field);
    `compileTimestamp: null`; EP section via a section-address sweep of
    `elf.sections`; packer via an inline `ELF_PACKER_SECTIONS` map
    (`UPX0` / `UPX1` / `UPX!`) plus a strings-level `UPX!` fallback.
  - **Mach-O** — import hash computed inline from sorted deduped
    lowercased `dylib:symbol` pairs (matching the
    `analyzeForSecurity()` computation); SymHash via
    `computeSymHash(importedSymNames, dylibBasenames)`; signer derived
    from `mo.codeSignatureInfo.teamId` →
    `mo.codeSignatureInfo.certificates[0]` → `mo.codeSignature`
    (`'Ad-hoc signed'`) → `'unsigned'`; `compileTimestamp: null`
    (Mach-O has no compile timestamp in its structural header); EP
    section via an offset-in-range sweep of `mo.sections`; packer via
    an inline `MACHO_PACKER_SECTIONS` map (`__XHDR → UPX`).
  The whole card build in every renderer is inside a `try / catch` so a
  summary-card failure never aborts the normal render path; every call
  site also guards on `typeof BinarySummary !== 'undefined'` so the
  renderer keeps working defensively if the helper is stripped.
- **Triage-first binary module family** (`src/mitre.js`,
  `src/binary-verdict.js`, `src/binary-anomalies.js`,
  `src/binary-triage.js`) layers a triage-first UI on top of the Pivot
  card described above. All four are pure-presentation modules — none
  mutate `findings`; every call site guards on `typeof X !== 'undefined'`
  so stripping any one module degrades gracefully.
  - **`src/mitre.js`** — `window.MITRE = { lookup, primaryTactic, urlFor,
    tacticMeta, rollupByTactic, TECHNIQUES, TACTICS }`. Canonical registry
    of every technique ID referenced by the binary pipeline, keyed by
    `Tnnnn[.nnn]` with `{name, tactic, parent?}`. `rollupByTactic(items)`
    groups `[{id, evidence?, severity?}]` by primary tactic, dedupes
    within each tactic keeping the highest-severity evidence, and sorts
    techniques by severity then id and tactics by ATT&CK kill-chain
    order. This is the single source of truth for every "MITRE ATT&CK
    Coverage" surface (sidebar section, main-pane chips, Copy-Analysis
    block).
  - **`src/binary-verdict.js`** — `BinaryVerdict.summarize({parsed,
    findings, format, fileSize})` → `{headline, risk 0-100, tier:
    'clean|low|medium|high|critical', badges:[{label,kind:'ok|warn|bad|
    info'}], signer, capabilityCounts}`. Produces the single human
    sentence + risk score the Tier-A band draws. Risk is seeded from
    `findings.riskScore` and incremented by each present anomaly
    (unsigned +6, packer +10, orphan EP +12, W+X EP +10, TLS callbacks
    +4/ea, overlay presence, dangerous entitlements +10, exec-stack +6,
    capability bucket totals up to +40); `_tierFromRisk` then maps the
    clamped 0-100 score to the five-tier bucket. Format-specific signal
    extraction lives in `_peSignals` / `_elfSignals` / `_machoSignals`
    so the top-level `summarize()` is a small format-switch.
  - **`src/binary-anomalies.js`** — `BinaryAnomalies.detect({parsed,
    findings, format})` → `{ribbon:[{label, severity, anchor, mitre?}],
    shouldAutoOpen: Map<cardId, bool>, isAnomalous: (cardId)=>bool}`.
    Feeds both the anomaly-ribbon chips below the verdict band and the
    "should this Tier-C reference card auto-expand?" predicate each
    renderer consults. Card ids are short kebab-case strings agreed with
    the renderer (`PE: headers, sections, imports, exports, resources,
    rich, tls, dotnet, certificates, data-dirs, overlay, strings`;
    `ELF: header, segments, sections, dynamic, symbols, notes, overlay,
    strings`; `Mach-O: header, segments, load-commands, dylibs, symbols,
    codesig, entitlements, overlay, strings`). Ribbon is sorted
    `critical > high > medium > low > info` with alphabetical tiebreak.
  - **`src/binary-triage.js`** — `BinaryTriage.render({parsed, findings,
    format, fileSize, anchorFor?}) → HTMLElement`. Composes the Tier-A
    band (verdict line + tier chip + risk score + MITRE tactic rollup
    counts) and the anomaly ribbon into a single `<div>` the PE / ELF /
    Mach-O renderers prepend to `wrap`. CSS lives in
    `src/styles/viewers.css` under the `.bin-triage-*` namespace layered
    on top of `.bin-summary-*`.
  - **Load order (`scripts/build.py` → `JS_FILES`):** `mitre.js` →
    `binary-verdict.js` → `binary-anomalies.js` → `binary-triage.js` →
    `binary-summary.js` → the three native renderers. Triage reads
    MITRE / verdict / anomalies, renderers read all five, so each file
    must be fully loaded before any consumer.
  - **`BinarySummary` extensions:** the pivot card now also surfaces
    `teamId`, `bundleId`, `buildId`, `clrRuntime`, and `sdkMinOS`, plus
    a tri-state `signer.verified ∈ {true, false, null}` — `null` means
    "parser extracted a signer DN but Loupe cannot verify the chain
    offline", rendered as a `?` badge to distinguish it from the
    false / unsigned state.
  - **`src/binary-strings.js`** gains
    `renderCategorisedStringsTable(strings)` — a shared viewer helper
    every native-binary renderer calls for the categorised strings Tier-C
    card (mutexes / pipes / PDB paths / home paths / registry keys /
    Rust panics). CSS lives under `.bin-strings-cats`.
  - **`App` stash — `this._binaryParsed` + `this._binaryFormat`.** The
    Copy-Analysis ("⚡ Summarize") path and the sidebar's Binary Metadata
    + MITRE sections need the same `{parsed, format}` pair the main-pane
    triage band was drawn from, but neither has a pointer to the
    renderer. `app-load.js`'s pe / elf / macho dispatchers therefore
    stash `this._binaryParsed = r._parsed || null; this._binaryFormat =
    'pe' | 'elf' | 'macho';` after the renderer returns, and
    `_clearFile()` clears both back to `null` on file close so the next
    load — which may be any format — never sees stale parsed headers.
    Consumers guard with `if (this._binaryFormat && typeof BinaryVerdict
    !== 'undefined')` before calling into the module family.
  - **Renderer contract addition — `_parsed` / `_findings` stash on the
    result object.** `PeRenderer.render` / `ElfRenderer.render` /
    `MachoRenderer.render` now attach the fully-parsed structure to
    `result._parsed` (PE header tree, ELF struct, Mach-O struct) and the
    finalised findings to `result._findings` so the `app-load.js`
    dispatcher can stash both. New native-binary renderers in this
    family should follow the same two-field convention.
- **`NpmRenderer` accepts three input shapes** — gzip tarball (`.tgz`),
  a bare `package.json` manifest, or a `package-lock.json` /
  `npm-shrinkwrap.json` lockfile — routed by dedicated sniff helpers in
  `src/renderer-registry.js`. The `.tgz` sniff calls
  `Decompressor.inflateSync` (sync pako path) so `detect()` stays
  synchronous, and the npm entry is registered **before** the generic
  `zip` entry so it wins the `.tgz` extension match. The JSON sniff
  requires `name` plus one of `version` / `scripts` / `dependencies`,
  or a numeric `lockfileVersion`, so unrelated JSON is not hijacked.
  Lifecycle-hook script bodies are folded into `findings.augmentedBuffer`
  (capped at 2 MB) before YARA scans so hook source contributes rule
  matches without contaminating the Copy / Save path.
- **GridViewer timeline strip.** Every tabular viewer
  (`CsvRenderer`, `EvtxRenderer`, `XlsxRenderer`, `SqliteRenderer`,
  JSON-array via `JsonRenderer`) is backed by the shared `GridViewer`
  primitive in `src/renderers/grid-viewer.js`. The constructor accepts
  four opt-in timeline keys: `timeColumn: number` to force a specific
  column (otherwise `GridViewer` auto-sniffs via
  `_columnLooksTemporal(colIdx)` — ≥ 50 % of non-empty cells must round-
  trip through `Date.parse()`, ≥ 2 distinct values, and bare numeric
  identifiers < 10 digits with no date separators are rejected so a
  primary-key column never masquerades as a timestamp);
  `timeParser(cell, dataIdx) → ms | NaN` to override the default
  `_parseTimeCell` (which already handles ISO-8601, RFC-2822, Unix
  seconds / millis, and Windows FILETIME); `timelineBuckets: number` to
  change the histogram resolution (default 60); and
  `onFilterRecompute: () => void` to hand filter composition back to the
  caller. When `onFilterRecompute` is **unset**, the internal
  `_applyFilter()` intersects the text filter with `_timeWindow` via
  `_dataIdxInTimeWindow(dataIdx)` and paints the virtual grid itself.
  When `onFilterRecompute` is **set** (EVTX is the reference consumer —
  its Event ID / Level / Channel / Provider multi-select pipeline can't
  be expressed as a single substring match), `GridViewer` bypasses its
  own filter and simply calls the callback after any window change; the
  caller's pipeline must read `viewer._timeWindow` and intersect every
  candidate `dataIdx` via `viewer._dataIdxInTimeWindow(i)` before
  appending its own rows. Internal state is `_timeMs[]` (one entry per
  data row, `NaN` for unparseable cells), `_timeBuckets: Int32Array` of
  length `timelineBuckets` (density histogram), and `_timeWindow =
  {min, max}` (current selection, `null` when cleared). `_rebuildTimeline()`
  is the canonical refresh entry point and is called from the constructor
  tail, `endParseProgress()` (streaming-parse tail), and `setRows()`
  (external row replacement). Keyboard: `[` / `]` step the window by its
  own width (pan), `Esc` cascades drawer → window → nothing so the same
  key clears progressively without swallowing close-dialog state.
  Click-to-bucket selects one bucket; drag selects a range; double-click
  anywhere on the strip clears the window. The column-header popover
  grows a "Use as timeline" entry when `_columnLooksTemporal(colIdx)`
  passes — `_useColumnAsTimeline(colIdx)` then stamps `_timeColumn = colIdx`
  and re-runs `_rebuildTimeline()`. The timeline strip is hidden
  (`.grid-timeline.hidden`) when no column sniffs as temporal and the
  caller did not force one — nothing else in the grid changes, so viewers
  that ship without a timestamp column (e.g. the generic SQLite table
  browser) look identical to their pre-timeline layout. CSS lives in
  `src/styles/viewers.css` under the `.grid-timeline*` namespace and
  uses `rgb(var(--accent-rgb, 99 102 241) / …)` for bar + window fills
  so theme overlays that retune `--accent-rgb` (Solarized, Mocha, Latte,
  Midnight) pick up the change for free.
- **GridViewer column sizing — kind-aware auto-sizer + manual resize.**
  `_recomputeColumnWidths()` classifies every column into one of eight
  kinds — `timestamp` / `number` / `id` / `hash` / `enum` / `short` /
  `text` / `blob` — via `_classifyColumns()` and sizes each from its
  measured character width (`_measureCharWidth()` probes a hidden
  `.grid-cell` once per mount so the tunables `CELL_PAD_PX = 22`,
  `HEADER_EXTRA_PX = 24`, `SHORT_COL_MAX = 240`, `BLOB_BASE_MAX = 420`,
  `TIGHT_PAD = 8` stay theme-agnostic). Sampling is **stratified** (head
  + middle + tail, ≤ 300 rows) so EVTX's boot-chatter prefix does not
  under-size the late-file Event Data blobs. Slack is allocated in two
  phases: (1) any column tagged `blob` is **greedy** and absorbs 100 %
  of the leftover viewport width; (2) if no blob exists, remaining space
  is distributed proportionally across the `text` columns with a 2×
  soft cap. Fixed-shape kinds (`timestamp` / `number` / `id` / `hash` /
  `enum`) are pinned to their p100 content width + `TIGHT_PAD` and
  **never grow into slack** — a 20-char `TimeCreated` column stays
  narrow even on a 4K monitor. Callers that know their schema up-front
  skip the sniffer by passing `columnKinds: ['timestamp', 'id', 'enum',
  'short', 'short', 'short', 'blob']` at construction time (EVTX is the
  reference consumer). A caller hint wins per-cell — any array entry
  overrides the auto-detected kind for that column index, so
  `SqliteRenderer` could hint `['id', …]` for an `INTEGER PRIMARY KEY`
  without losing auto-detection on the other columns. Manual resize
  lives on the right edge of each `.grid-header-cell` as a 6-px-wide
  `.grid-col-resize-handle`; `_wireColumnResize()` drives the drag
  (live-updating the CSS template var for smooth feedback, committing on
  `mouseup`) and `_saveUserColumnWidth()` persists per-renderer under
  `loupe_grid_colW_<gridKey>` where `gridKey` defaults to the container
  `className` (`evtx-view`, `csv-view`, …) or an explicit `gridKey:
  'sqlite-<tableName>'` opt. Double-clicking the handle calls
  `_resetColumnWidth()` which deletes the stored override and re-runs
  the auto-sizer. User overrides take precedence over kind-based
  widths — `_applyColumnTemplate()` reads the Map returned by
  `_loadUserColumnWidths()` before falling back to the computed value.
- **GridViewer per-cell annotation hooks.** `GridViewer` accepts two optional callbacks so consumers can annotate specific cells without subclassing: `cellTitle(dataIdx, colIdx, rawValue) → string | null` returns a `title=` tooltip applied to every matching grid cell; `detailAugment(dataIdx, colIdx, value, {keyEl, valEl, colName}) → void` runs while the row-details drawer is built and can append chips / pills to the drawer's value element. The EVTX consumer in `src/app/app-timeline.js` uses both: a `cellTitle` hook that looks up `<Channel>:<EventID>` via `window.EvtxEventIds.lookup()` and returns a formatted multi-line tooltip (`4624: An account was successfully logged on.`), and a `detailAugment` hook that appends a `.tl-evtx-eid-pill` summary badge plus one `.tl-evtx-mitre-pill` per MITRE technique resolved through `window.MITRE.lookup()`. Both hooks are EVTX-only — the Timeline consumer checks `this._isEvtx` before wiring them so CSV / TSV / browser-history viewers get the untouched drawer.
- **GridViewer row-details drawer search box.** The drawer's topbar now carries an inline search input (`.grid-drawer-search`) built by `_wireDrawerSearch()`. As the analyst types, `_applyDrawerSearch()` walks the drawer body with a `TreeWalker` (skipping existing `.grid-drawer-hit` spans to avoid double-wrapping on re-apply), wraps each case-insensitive literal match in a `<span class="grid-drawer-hit">`, and smooth-scrolls the first hit into view. `Enter` / `Shift+Enter` cycle through hits (`_stepDrawerSearch`), `Esc` clears, `Ctrl/⌘+F` focuses the box when the drawer has focus. Hit count is capped at 400 to keep the TreeWalker bounded on pathologically large drawers; overflow is surfaced as `N+` in `.grid-drawer-search-count`. The search resets itself whenever the drawer opens onto a new row so stale highlights never carry over.
- **EVTX Event ID registry — `src/evtx-event-ids.js`.** `window.EvtxEventIds = {EVENTS, lookup(id, channel), formatTooltip(info, id), normChannel(raw)}` is the single source of truth for the plain-English name / description of ~80 forensically-relevant Windows Event IDs. Events are keyed by `<channel>:<id>` (e.g. `security:4624`, `sysmon:1`, `system:7045`) with a bare `<id>` fallback for logs where the channel is unknown; each entry is `{name, description, mitre?: string[]}`. `formatTooltip()` returns the short tooltip string the `cellTitle` hook applies to every Event ID grid cell. The file is listed in `JS_FILES` immediately after `src/mitre.js` so both globals are present before any timeline-consuming renderer loads. Adding a new Event ID is a single-file change — extend `EVENTS` with the channel-qualified key and, where applicable, an array of `Tnnnn[.nnn]` MITRE techniques that already exist in `src/mitre.js`'s `TECHNIQUES` table.
- **GridViewer row-details drawer — JSON-aware picker via
  `src/json-tree.js`.** The right-hand details drawer that opens on row
  click is built by `_buildDetailPaneElement(cols, row, dataIdx)`. For
  every cell whose value round-trips through `JsonTree.tryParse()`
  (quick textual sniff — first non-space char must be `{` or `[` — then
  a real `JSON.parse`) the drawer replaces the flat string view with an
  expandable tree rendered by `JsonTree.render({value, onPick})`. The
  drawer passes `autoOpenDepth: Infinity` so every nested object/array is
  pre-expanded on open (other `JsonTree.render` callers still default to
  root-only — only the drawer opts in). Every key span (`.json-tree-key`)
  accepts a **right-click context menu** that routes the chosen action
  through the consumer's `onPick(path, value, action)`. Left-click on a
  key still toggles expand / collapse. `path` is an array of string /
  number tokens (`['results', 0, 'userId']`) that
  `JsonTree.pathGet(obj, path)` and `JsonTree.pathLabel(path)` round-trip
  through. The module is a small shared primitive (`window.JsonTree`)
  with no GridViewer dependency. Loading order: `src/json-tree.js` is
  listed in `JS_FILES` **before** `grid-viewer.js` (and before every
  consumer) so the global is present at render time.
  - **Context-menu actions (`action` parameter).** The key menu adapts
    to the node kind: leaves get `extract` / `include` / `exclude`;
    composites (objects / arrays) get `extract` / `has` / `missing`
    (existence checks — a subtree has no comparable scalar value of its
    own, so Include / Exclude is omitted for composites). `extract`
    materialises the path as a virtual column without filtering;
    `include` / `exclude` auto-extract *and* chip-filter on the leaf
    value (`op: 'eq'` / `op: 'ne'`); `has` / `missing` auto-extract
    and chip-filter on the empty-string sentinel — an unresolved path
    extracts to `''`, so `ne:''` = "has this path" and `eq:''` =
    "missing this path".
  - **`onCellPick` constructor option.** GridViewer accepts an optional
    `onCellPick: (dataIdx, colIdx, path, leafValue, action) => void`
    callback. When set, the drawer wires every key-span context menu
    to `this._onCellPick(dataIdx, colIdx, path, leafValue, action)` —
    the consumer turns each action into the corresponding virtual
    column / chip. `TimelineView` passes one in from `_renderGridInto()`
    and switches on `action`: it always calls
    `_addJsonExtractedCol(colIdx, path, label)` (which returns the new
    column index and persists the entry into
    `loupe_timeline_regex_extracts` with `kind: 'json-leaf'` so the
    column survives a reload), then for `include` / `exclude` / `has`
    / `missing` chains `_addOrToggleChip(newColIdx, chipVal, {op})`
    with the mapped `{chipVal, op}` pair. Callers that do not supply
    `onCellPick` get an inert tree (no context menu wired), so adding
    JSON display to a new viewer is a zero-wiring change.

  - **Automatic JSON→CSV leaf flatten.** `TimelineView._autoExtractScan`
    already proposes URL / hostname extractions via the Auto tab of the
    ƒx Extract values dialog. It now also walks every cell whose text
    sniffs as JSON, collects the union of leaf paths via
    `JsonTree.collectLeafPaths(obj)`, and emits one `json-leaf`
    proposal per path (capped at 60 per source column to keep the
    dialog bounded). Accepting a proposal routes through the same
    `_addJsonExtractedCol` path as the drawer picker, so both entry
    points share the same virtual-column shape.

  - **ƒx Extract values dialog shape (two panes).** The dialog
    `_openExtractionDialog()` renders a tab strip — **Smart scan**
    (ranked `_autoExtractScan()` proposals) and **Manual** (a single
    unified pane that fuses the former Clicker click-to-pick UX with
    the preset / custom regex form). The Manual pane has one shared
    Column dropdown, one Preset dropdown, one Name field, ~30
    click-to-pick sample rows, the Pattern / Flags / Group inputs, an
    inline regex cheatsheet, one live preview, and one Test / Extract
    footer. Clicking or drag-selecting a token in a sample row
    classifies it (UUID, IPv4, MAC, hash, decimal, ISO timestamp,
    email, URL, hostname, path, identifier, quoted token, or fallback
    literal), generalises an `\b`-anchored regex by finding the
    shortest prefix / suffix shared by ≥70% of samples, writes the
    inferred pattern straight into the unified Pattern field (with
    `flags='i'`, `group='1'`), and re-runs the shared preview. Both
    presets and click-picked patterns commit through the same
    `_addRegexExtractNoRender` path so the store shape and rendering
    pipeline stay identical. When the dialog is opened from a column
    context menu (`_openExtractionDialog(preselectCol)`) the Manual
    pane's Column dropdown defaults to that column. The Smart-scan
    toolbar carries bulk
    `✓ All` / `☐ None` / `↔ Invert` buttons, a live `N of M selected`
    counter, kind facets (`All` / `URL` / `Host` / `Key=Value` / `JSON`),
    a filter input (`/` focuses it), and a sort dropdown. Each proposal
    row lays out as `[checkbox] [kind-pill] [sample:1fr] [col] [rate]`;
    a "Will create:" preview strip above the list shows up to five pill
    names of the columns that will be materialised on Extract.
    Keyboard: `Enter` extracts the selected set, `Space` toggles the
    focused row, `/` focuses the filter, `Esc` closes the dialog.

  - **Proposal kinds emitted by `_autoExtractScan()`.** Each proposal
    carries a `kind` used for the facet filter, the `kindRank` sort
    order, and the post-extract label. Current kinds: `text-url`,
    `text-host`, `json-url`, `json-host`, `json-leaf`, `kv-field`,
    `url-part`. `url-part` is emitted for columns whose header matches
    `/^url$/i` (typically browser-history SQLite `url` columns) and
    proposes one row each for host, path, and query — materialised via
    a regex extract that parses the URL client-side. `kv-field` is
    emitted for columns where a sizeable fraction of rows contain
    `Key=Value` pairs; the nudge strip's ranked preview uses the same
    `kindRank` ordering so the top four shown above the grid match the
    top four in the dialog.

  - **EVTX forensic preselect + relaxed kv thresholds.** When the
    active file is EVTX, `_autoExtractScan()` lowers the Key=Value
    detection floor (`kvDomFrac` 0.5 → 0.1, `minCount` scaled down) so
    sparse `EventData` fields surface as proposals, and pre-checks the
    forensic-relevant field names (`CommandLine`, `TargetUserName`,
    `SubjectUserName`, `ProcessName`, `ParentProcessName`, `Image`,
    `CommandLineHash`, `IpAddress`, `LogonType`, etc.) in the Smart-scan
    list so a one-click Extract gives you the canonical triage columns.
- **GridViewer hidden-columns chip + header menu entry.** Columns can
  be hidden interactively in two ways: (1) the existing "Hide column"
  item in the column-header ▾ menu, or (2) **Ctrl/Meta + Click** on the
  header cell itself. Both paths funnel through
  `_toggleHideColumn(colIdx)`, which adds the index to `this._hiddenCols`
  (a `Set<number>`) and repaints. Unhiding had no visible surface in the
  original design; the viewer now exposes two:
  - A compact `⊘ N hidden` chip (`.grid-hidden-chip`) rendered inside
    the filter bar whenever `_hiddenCols.size > 0`. Clicking it opens
    `.grid-hidden-popover` — a simple list of the currently hidden
    column labels, each with an ✕ button that calls `_unhideColumn(i)`,
    plus a "Show all" action that calls `_unhideAllColumns()`.
    `_updateHiddenChipUI()` is the single paint entry point and is
    called from every mutation site.
  - A "Show hidden columns… (N)" entry injected by `_openHeaderMenu`
    at the bottom of the column popover when `_hiddenCols.size > 0`.
    It simply opens the same popover via `_openHiddenColsPopover()`.
  Callers that reset their viewer (e.g. `TimelineView._reset()`) must
  call `grid._unhideAllColumns()` on both the main and suspicious
  grid instances so a fresh file load doesn't inherit stale hidden
  state from the previous file. `_unhideAllColumns()` is a safe no-op
  when the set is already empty. Timeline also wires **Ctrl/Meta +
  Click on a `.tl-col-card` heading** to the same `_toggleHideColumn`
  call on both grids so the per-column top-value card and the grid
  stay in sync.
- **Timeline-mode filter pipeline — two-phase drag + window-only fast
  path.** `TimelineView` in `src/app/app-timeline.js` composes a chip /
  range / text / sus filter over tens of thousands of rows and re-renders
  a scrubber + stacked-bar chart + virtual grid + per-column cards on
  every mutation. A naive rebuild on every pointermove from the scrubber
  or the chart rubber-band destroys interactivity, so the view splits
  filter state into **two indices** and all window-driven interactions
  use the cheap path:
  - `_chipFilteredIdx` — window-agnostic result of running every chip /
    range / text predicate over `rows[]`. Rebuilt only when a
    **predicate** changes (chip added / removed, text filter edited,
    sus bitmap flipped). `_recomputeFilter()` populates it and then
    calls `_applyWindowOnly()` to derive the window-clipped indices.
  - `_applyWindowOnly()` — fast re-derivation of `_filteredIdx` +
    `_susFilteredIdx` from `_chipFilteredIdx` + the current `_window`.
    O(visible rows), no per-cell predicate loop. Every code path whose
    only change is the time window (scrubber drag, chart click-drill,
    chart rubber-band, range-chip remove) calls this instead of
    `_recomputeFilter()`.
  - **Two-phase drag.** The scrubber handle drag and the
    `_installChartDrag` rubber-band share the same pattern: during the
    live drag (`pointermove`) we call `_applyWindowOnly()` and
    `_scheduleRender(['scrubber','chart'])` — grid / column-cards / sus
    are deliberately deferred. On commit (`pointerup`) we issue the
    full render pass (`['scrubber','chart','chips','grid','columns']`).
    `this._windowDragging = true` during the drag is the sentinel any
    renderer can consult if it wants to skip expensive work mid-drag.
  - **`_installChartDrag(canvas, chartWrap, tooltip, getData)` is the
    unified pointer handler** for both `.tl-chart-canvas` surfaces
    (main + sus). Click-vs-drag is disambiguated by
    `DRAG_THRESHOLD_PX = 4`: below threshold = single-bucket drill
    (`_onChartClick`); at or above = rubber-band a time-window with a
    `.tl-chart-selection` overlay `<div>` (absolutely positioned inside
    `.tl-chart`, snaps to bucket boundaries on commit). Shift-drag
    unions with the existing window; double-click anywhere on the
    chart clears the window. The handler mutates `_window`, calls
    `_applyWindowOnly()`, and uses the two-phase render schedule
    described above.
  - **Gotcha — class-name collisions on `.tl-colmenu-*`.** The
    per-row percentage-fill bar in the column-menu top-values list is
    `.tl-colmenu-valbar` (`position: absolute; pointer-events: none`).
    Anything else that lives in the same popover needs its own class
    — e.g. the All / None action row is `.tl-colmenu-valactions`
    (flex, interactive). Reusing `-valbar` on an interactive container
    silently black-holes clicks.
  - **Suspicious overlay on the main chart — parallel `susBuckets`
    array.** When the analyst flags rows via right-click → 🚩 Mark
    suspicious, the flagged section retains its own mini-chart **and**
    the main histogram is tinted to show which buckets contain
    suspicious rows. `_computeChartData()` builds an extra
    `susBuckets` `Int32Array` (same length as the main `buckets`
    totals) by counting `_susBitmap` hits over `predicateIdx`, but
    **only when** `role === 'main'` and the predicate index is the
    full `_filteredIdx` (so the sus mini-chart doesn't double-tint
    itself). `_renderChartInto()` then paints a single
    `rgba(220,38,38,0.55)` overlay rect per bucket after the stacked
    bars and before the cursor. The fill colour is hard-coded rather
    than sourced from `var(--risk-high)` because canvas 2D contexts
    cannot resolve CSS custom properties at `ctx.fillStyle` assignment
    time — if you ever re-theme the sus overlay, update the constant
    in `_renderChartInto` and the matching `.tl-chart-tooltip-sus`
    rule in `viewers.css` together.
  - **Event cursor — absolute-positioned `<div>` overlay, not a canvas
    stroke.** Clicking any grid row calls `_setCursorDataIdx(dataIdx)`
    which stores the row's original index on `this._cursorDataIdx`
    and schedules a cursor-only repaint. `_paintChartCursorFor()` and
    `_paintScrubberCursor()` position a single absolutely-positioned
    `.tl-chart-cursor` / `.tl-scrubber-cursor` element inside the
    chart / scrubber wrapper at the projected x-coordinate. This is
    deliberately *not* painted on the canvas — the cursor moves
    frequently (row selection, grid scroll) and a DOM element can be
    repositioned via `style.left` in O(1) without re-running the full
    bucket-paint loop. The colour is `var(--risk-high)` so theme
    overlays retune it for free. `Esc` clears the cursor **after**
    closing any open dialog / popover (keep that ordering in
    `_onDocKey` — if you flip it, Esc will start clearing the cursor
    while a modal is still up). `_reset()` also nulls
    `_cursorDataIdx` so re-loading a file doesn't leak a stale cursor.
  - **Auto pivot — `_autoPivotFromColumn(rowsCol, opts)` heuristic.**
    The row context menu and each column's ▾ menu grow a 🧮 **Auto
    pivot** entry that jumps the user into a pre-built pivot without
    forcing them to hand-pick Rows / Columns. The chosen `colsCol` is
    (in order of preference) an explicit `opts.colsCol`, then the
    current chart `_stackCol` when it's different from `rowsCol`,
    then the best-scoring neighbour by `_colStats` — scored by
    distinct-value count, favouring 5–30 distinct values and
    penalising columns with near-unique or near-constant cardinality.
    Numeric / timestamp columns are demoted. The resolved spec is
    written straight to the `pv-*` `<select>` elements, the pivot
    section is force-expanded (overriding
    `loupe_timeline_sections`), `_buildPivot()` runs, and the section
    is `scrollIntoView`'d with a one-shot `.tl-section-flash` class
    so the analyst visually tracks where the result landed. Because
    the function mutates the real pivot selectors, the last-used
    pivot persists to `loupe_timeline_pivot` just like a hand-built
    one — no separate persistence surface was added.
  - **Initial stack column — header-name heuristic with cardinality gate.**
    The stacked-bar chart's category split (`this._stackCol`) is picked at
    construction time. When the caller passes `opts.defaultStackColIdx`
    (EVTX hands in its `Level` column) that wins verbatim; otherwise
    `_tlAutoDetectStackCol(baseColumns, rows, timeCol)` runs over a
    2 000-row sample and scores candidates by (a) header-name match
    against the exact list `EventName` / `Event` / `EventID` / `Outcome` /
    `Result` / `Status` / `Action` / `Operation` / `Category` / `Type` /
    `Kind` / `Severity` / `Level` / `Channel` / `Provider` (plus a loose
    regex for compound names like `event_type`, `log_level`, …), and
    (b) a cardinality gate that requires `2 ≤ distinct ≤ 40` and
    `distinct / nonEmpty ≤ 0.5` so a `UserID` or free-text `Message`
    column can never win by accident. The time column itself is excluded
    from the candidate set. If nothing passes the gate the chart falls
    back to the single-series default (no split). Callers that want to
    force "no split" should pass `defaultStackColIdx: -1`.
  - **Selection-preserving search in the ƒx Extract → Smart scan pane.**
    The Smart-scan proposal list renames its filter box to **Search**
    ("Search proposals… ( / )") and backs every tick with a stable
    `_selection: Set<origIdx>` keyed by each proposal's original index
    in the un-filtered list. `renderList()` reads `_selection.has(origI)`
    when painting checkboxes, the row change listener mutates the Set
    (not a per-row `.checked` scan), and `updatePreview` / `updateCount`
    read `_selection.size` instead of walking the DOM — so ticks survive
    every Search / facet / sort mutation, including ones that scroll the
    ticked row off-screen. The **All / None / Invert** bulk-action
    buttons deliberately operate on `_visibleIndices` only (the rows
    currently passing the Search + facet filter), mutating the stable
    Set so an analyst can search for `host`, tick All, clear the search,
    search for `url`, and tick All again without losing the first batch.
    `runAuto()` seeds the initial Set from `proposal.preselect !== false`
    so high-confidence proposals stay ticked by default; the
    "Extract selected" button iterates `_selection` directly rather than
    re-filtering the visible list.
  - **DSL query editor (`TimelineQueryEditor` in `app-timeline.js`).** The
    textbox above the chip bar is a CSP-safe **overlay editor** — a
    transparent `<textarea>` painted on top of a `<pre><code>` syntax-
    highlighted layer — so users get pill-style token rendering, colouring,
    and caret positioning without `contenteditable` (which would require
    `unsafe-eval`-adjacent DOM-mutation paths the CSP already blocks). The
    pipeline is four stand-alone helpers that are pure functions and
    therefore trivially testable in isolation:
    1. **`_tlTokenize(str) → Token[]`** — recognises `AND` / `OR` / `NOT`
       (case-insensitive), parens, colon, operators (`=` / `!=` / `:` /
       `~` / `>` / `<` / `>=` / `<=`), quoted strings (single / double
       with `\\` escapes), and bare identifiers / values. Unterminated
       strings surface a `TokenError` at the unterminated offset.
    2. **`_tlParseQuery(tokens) → AST`** — recursive-descent parser for
       the grammar `expr := or (OR or)* ; or := and (AND and)* ; and :=
       NOT* atom ; atom := '(' expr ')' | pred | any ; pred := IDENT OP
       VALUE ; any := VALUE`. Node shapes are `{k:'and',children}`,
       `{k:'or',children}`, `{k:'not',child}`, `{k:'pred',colIdx,op,val,
       re?,num?}`, `{k:'any',needle}`, `{k:'empty'}`. Column names are
       resolved against `this.columns` at parse time so typos surface
       immediately rather than silently never matching.
    3. **`_tlCompileAst(ast) → (rowIdx) => bool`** — compiles the AST
       into a closure over the `rows[]` array. Regex predicates route
       through `new RegExp(pattern, flags)` with a whitelisted flag set
       `imsuy` (no `g` — global state across calls would break
       `.test()`); this is CSP-safe because `new RegExp` is a `Function`-
       free path that the `script-src` directive explicitly permits.
    4. **`_tlCompileAstExcluding(ast, excludeColIdx)`** — Excel-parity
       helper used by `_indexIgnoringColumn()` when a column's ▾-menu
       Values list is being rebuilt. Strips every predicate whose
       `colIdx === excludeColIdx` before compiling, so the Values list
       keeps showing every value the user has *un-ticked* (the standard
       Excel behaviour — hiding them would make re-ticking impossible).
    Click-pivot paths (right-click Include / Exclude, column-card click,
    column-menu Apply, pivot drill-down) funnel through
    `_queryToggleEqClause` / `_queryToggleNeClause`, both of which call
    `_queryDropContradictions()` before appending — so Include-after-
    Exclude (and the reverse, plus the `IN` / `NOT IN` variants) folds
    the opposing clause out instead of producing an unsatisfiable
    `col = v AND col != v`. Hand-typed queries are still honoured
    verbatim: the fold is scoped to the click-pivot path only.

    Composition with the existing chip plan happens in
    `_recomputeFilter()`: after the chip plan is applied, the compiled
    query predicate (`this._queryPred`) is ANDed in the hot loop. The
    short-circuit guard is `if (filterChips.length === 0 && !queryPred)
    return;` so a query-only filter (no chips) still runs the row loop.
    The `.tl-query-mount` node is inserted **before** `.tl-chips` in
    `_buildDOM()`; the editor instance is constructed in `_wireEvents()`
    and torn down in `destroy()`. `_reset()` clears the query via
    `this._queryEditor.setValue('')` + `_applyQueryString('')` so a file
    reload starts fresh. The clear (`✕`) / history (`▾`) / help (`?`)
    button cluster lives on the **left** edge of the editor (before the
    overlay textarea) so it sits next to where the analyst is typing —
    not flung to the opposite end of the bar. There is no clear button
    on the right anymore, and the old `🔍` lens glyph is gone.
    **Unified undo / redo ring.** Every value change — native typing,
    paste / cut / drop, IME composition commit, clear button, `Esc`-
    clear, history pick, programmatic `setValue()`, and the new
    clause-delete — is captured onto a **single session-only** ring
    `_hist` (cap `_HIST_MAX = 500` frames, each `{value, selStart,
    selEnd, kind}`). `Ctrl/⌘-Z` pops the ring in `_onKeyDown()` and
    `Ctrl/⌘-Shift-Z` (plus `Ctrl-Y` for muscle-memory parity) walks
    it forward; both routes go through `_applyHistFrame()` under an
    `_isUndoing` guard so the restore doesn't re-push itself. The
    ring is deliberately **not** persisted — closing the tab wipes
    history, matching VS Code's editor model. Coalescing is VS Code-
    style: consecutive word-character edits (`[A-Za-z0-9_]` runs)
    inside `_HIST_COALESCE_MS = 500` collapse into one frame so
    Ctrl-Z steps by word boundaries, not per-character; whitespace,
    operators, quotes, and parens always break the run so punctuation
    is always undoable independently. Paste / cut / drop are
    classified as `kind: 'replace'` via the `InputEvent.inputType`
    and never coalesce. `Ctrl/⌘-Backspace` / `Ctrl/⌘-Delete` route
    to `_deleteClause(dir)`, which uses `_tlTokenize` to find the
    enclosing DSL clause / operand left (or right) of the caret and
    wipes it as a single `_applyEdit()` atom — e.g. `AND ClientIP=5.90.40.3`
    → `AND `. The clause-delete edit snapshots as its own history
    frame so Ctrl-Z restores the whole wiped clause in one step. We
    deliberately **replace** (not merge with) the `<textarea>`'s
    native per-keystroke undo stack: once the ring is populated every
    Ctrl-Z goes through our handler, so the two stacks can never
    desync. `Alt`-modified variants still fall through untouched for
    future shortcuts.


---


## Persistence Keys

Every user preference lives in `localStorage` under the `loupe_` prefix so
state is (a) easy to grep for, (b) easy to clear with a single filter, and
(c) auditable against this table. If you add a new key, add a row here.

| Key | Type | Written by | Values / shape | Notes |
|---|---|---|---|---|
| `loupe_theme` | string | `_setTheme()` in `src/app/app-ui.js` | one of `light` / `dark` / `midnight` / `solarized` / `mocha` / `latte` | Canonical list is the `THEMES` array at the top of `app-ui.js`. Applied before first paint by the inline `<head>` bootstrap in `scripts/build.py`; missing / invalid value falls back to OS `prefers-color-scheme`, then `dark`. |
| `loupe_summary_target` | string | `_setSummaryTarget()` in `src/app/app-settings.js` | one of `default` / `large` / `unlimited` | Drives the build-full → measure → shrink-to-fit assembler in `_buildAnalysisText()`. Character budgets `64 000` / `200 000` / `Infinity` respectively. `unlimited` short-circuits truncation entirely. |
| `loupe_uploaded_yara` | string | `setUploadedYara()` in `src/app/app-yara.js` (YARA dialog "Save" action) | raw concatenated `.yar` rule text | User-uploaded rules are merged with the default ruleset at scan time. Cleared when the user clicks "Reset to defaults" in the YARA dialog. |
| `loupe_ioc_hide_nicelisted` | string | `_setHideNicelisted()` in `src/app/app-sidebar.js` | `"0"` (show, dimmed — default) or `"1"` (hide) | Controls the IOCs-section toggle that drops known-good global-infrastructure rows (`src/nicelist.js`) from the sidebar. Sort-to-bottom + dim is the default; hiding is opt-in and never affects the Detections section or the underlying `findings.externalRefs` array. |
| `loupe_nicelist_builtin_enabled` | string | `setBuiltinEnabled()` in `src/nicelist-user.js` (toggled from Settings → 🛡 Nicelists) | `"1"` (on — default) or `"0"` (off) | Master switch for the Default Nicelist shipped in `src/nicelist.js`. When `"0"`, `isNicelisted()` short-circuits to `false` so every curated global-infrastructure entry stops demoting rows. Missing / unparseable value is treated as on so first-time users still get the noise reduction. |
| `loupe_nicelists_user` | string (JSON) | `save()` / mutation helpers in `src/nicelist-user.js` (Settings → 🛡 Nicelists UI) | `{version:1, lists:[{id,name,enabled,createdAt,updatedAt,entries}]}` | User-defined nicelists (MDR customer domains, employee emails, on-network hostnames, …). Capped at 64 lists × 10 000 entries × 1 MB serialised to stay inside the localStorage quota; overflow writes are refused without corrupting the previous blob. Entries are normalised + deduplicated on save; matching uses the same label-boundary semantics as the built-in list. Exported / imported via the toolbar buttons in the Nicelists tab. |
| `loupe_plaintext_highlight` | string | `PlainTextRenderer._writeHighlightPref()` in `src/renderers/plaintext-renderer.js` (info-bar "Highlight" button in the plaintext / catch-all viewer) | `"on"` (default) or `"off"` | Syntax-highlighting master switch for the plaintext / catch-all renderer. When `"off"`, hljs is never invoked regardless of file size or language. Independent of the automatic per-file gates (`HIGHLIGHT_SIZE_LIMIT`, `LONG_LINE_THRESHOLD`) which always disable highlighting on minified / pathological inputs. |
| `loupe_grid_drawer_w` | string (integer) | `_saveDrawerWidth()` in `src/renderers/grid-viewer.js` (drag handle on the left edge of the detail drawer) | integer pixel width, lower-bound `280` on read; upper bound is dynamic (`viewport − DRAWER_MIN_GRID_W`) so the drawer can be dragged to nearly full-width on large monitors | Width of the right-hand row-details drawer used by every GridViewer-backed viewer. Default `420`. Persisted per-browser so analysts who prefer a wide drawer for deeply-nested EVTX events don't have to re-drag it on every file. The hard `900` px cap was removed in favour of `_drawerMaxW()` so wide EventData payloads and JSON trees have room to breathe. |
| `loupe_grid_colW_<gridKey>` | string (JSON object) | `_saveUserColumnWidth()` in `src/renderers/grid-viewer.js` (drag handle on the right edge of each `.grid-header-cell`) | `{ "<colIdx>": pixelWidth, … }` — integer pixel widths, clamped to `MIN_COL_W`–`1600` on read | Per-column manual width overrides that survive the kind-aware auto-sizer in `_recomputeColumnWidths()`. Namespaced per renderer via `gridKey` (e.g. `loupe_grid_colW_evtx`, `loupe_grid_colW_csv-view`) so resizing EVTX's Event Data blob column doesn't also bloat an unrelated CSV column 6. Double-clicking the handle deletes the entry (`_resetColumnWidth()`) to restore auto sizing. |
| `loupe_timeline_grid_h` | string (integer) | drag handle on the `.tl-splitter` between the timeline grid and the per-column cards | integer pixel height, clamped to a sensible min/max on read | Height of the virtual-grid pane inside the Timeline viewer. Persisted per-browser so analysts who prefer a tall grid (scrolling 10 k rows) or a tall column-cards pane don't have to re-drag it on every file. |
| `loupe_timeline_chart_h` | string (integer) | `.tl-chart-resize` grab-bar along the bottom edge of the stacked-bar histogram | integer pixel height, clamped on read to the chart's min/max (120 – 600 px) | Height of the Timeline histogram pane. Default is deliberately compact (220 px) so the events grid + top-values cards are visible on first paint; analysts who want more bar resolution drag it down and the preference sticks across reloads. |
| `loupe_timeline_bucket` | string | Timeline toolbar bucket picker | one of the supported bucket sizes (`1m` / `5m` / `1h` / `1d` / …) | Chart / scrubber bucket resolution for the stacked-bar histogram. Default is picked automatically from the file's time span on first load if the saved value is missing or invalid. |
| `loupe_timeline_sections` | JSON object | section-chevron clicks on collapsible `.tl-section` blocks | `{ chart: bool, grid: bool, columns: bool, pivot: bool, … }` — each flag = `true` when collapsed | Collapsed / expanded state of every top-level Timeline section (histogram, events grid, top-values cards, detections, entities, pivot). Lets analysts hide sections they don't use (e.g. pivot starts collapsed). Unknown / unparseable value → all expanded. |
| `loupe_timeline_card_widths` | JSON object | left / right edge resize handles on each `.tl-col-card` and `.tl-entity-group` | `{ "<fileKey>": { "<key>": { span: N } \| pixelWidth, … } }` — file key = `name|size|lastModified`; `<key>` is a column name for top-value cards or `entity:<IOC_TYPE>` for entity cards; `span` is a `grid-column: span N` integer; legacy integer pixel values are migrated to a span on read | Per-file manual width overrides for the top-value and entity cards, expressed as an integer `grid-column: span N` so the override cooperates with the `.tl-columns` / `.tl-entities-wrap` CSS Grid `auto-fill minmax()` layout. Scoped to a file so resizing a "User" card in one CSV doesn't re-size a same-named column in an unrelated one. |
| `loupe_timeline_card_order` | JSON object | drag-to-reorder top-value card headers | `{ "<fileKey>": ["colName1", "colName2", …] }` | Per-file column-name ordering for the 🏆 Top values cards. Columns not present in the saved array are appended at the end. Deleted when empty. |
| `loupe_timeline_pinned_cols` | JSON object | 📌 pin button on top-value card headers | `{ "<fileKey>": ["colName1", …] }` | Per-file list of pinned top-value card column names. Pinned cards sort to the top-left of the card grid. Deleted when empty. |
| `loupe_timeline_regex_extracts` | JSON object | ƒx Extract dialog → Manual / Smart-scan panes | `{ "<fileKey>": [{ name, col, pattern, flags, group, kind }, …] }` | Per-file list of extracted virtual columns created via the Manual pane (preset, custom regex, or click-to-pick) or the Smart-scan auto-proposal pane (URL / hostname / kv-field / json-leaf). Re-applied automatically next time the same file is loaded so long-form analyses survive a reload. JSON-path extractions are not persisted (they depend on in-memory parsed values). |
| `loupe_timeline_pivot` | JSON object | Pivot section ▸ Rows / Columns / Aggregate / Build | `{ rows: colIdx, cols: colIdx, aggOp: "count" \| "distinct" \| "sum", aggCol: colIdx }` | Last-used pivot spec. Re-populates the selectors on mount so "Build" reconstructs the same pivot without re-picking columns. Col indices can reference extracted virtual columns; if they no longer exist the selectors silently fall back to `-1`. |
| `loupe_timeline_query` | string | Timeline DSL query-editor textbox above the chip bar | arbitrary DSL query string (see the Timeline query-language grammar below); empty string = no query | Last-used query in the Timeline viewer's DSL query editor. Re-populated on mount so a saved filter survives a reload; an unparseable value is loaded verbatim but quietly falls back to "no query" until fixed. |
| `loupe_timeline_query_history` | JSON array | ⌄ history button on the Timeline DSL query editor | array of recent non-empty query strings, most recent first, capped at ~20 entries | Recent query history for the editor's ↑ / ↓ history menu. A committed query is pushed to the front and de-duplicated so the dropdown stays usable over long sessions without ballooning localStorage. |
| `loupe_timeline_sus_marks` | JSON object | right-click a cell → 🚩 Mark suspicious · `＋ Add Sus` chip-strip button | `{ "<fileKey>": [{ colName, val }, …] }` — file key = `name\|size\|lastModified` | Parallel 🚩 sus-mark list persisted **by column NAME** (not index) so an extracted column that rebuilds under a different index on reload still re-hydrates its marks. Sus marks **tint** matching rows red but do **not** filter them — row filtering is exclusively owned by the DSL query bar. Resolved to a live `colIdx` at filter-time via `_susMarksResolved()`; marks whose column has disappeared stay persisted and re-attach if the column returns. |
| `loupe_timeline_autoextract_nudged_hard` | string | "Don't show again" button on the post-load auto-extract nudge strip (above the Timeline query bar) | `"1"` when suppressed, absent otherwise | Hard-dismissal flag for the post-lazy-load auto-extract suggestion strip rendered by `_renderAutoExtractNudge()` in `src/app/app-timeline.js`. The strip previews up to four high-confidence virtual-column proposals (URL / host / JSON-leaf / kv-field) from `_autoExtractScan()`; "Dismiss" hides it for the session only, while "Don't show again" writes `"1"` here so the strip is permanently skipped on every future file load. Cleared by Timeline ↺ Reset along with the other `loupe_timeline_*` keys. |
| `loupe_hosted_dismissed` | string | `_checkHostedMode()` in `src/app/app-core.js` | `"1"` when dismissed, absent otherwise | Controls the floating hosted-mode privacy bar shown when Loupe is served via HTTP/HTTPS instead of `file://`. Once the user clicks ✕, the bar never reappears. |

**Timeline ↺ Reset wipes every Timeline preference.** The Reset button in
the Timeline toolbar (`TimelineView._reset()` in `src/app/app-timeline.js`)
deliberately clears **every** `loupe_timeline_*` key above — not only the
one matching the current file — plus `loupe_grid_drawer_w` and every
`loupe_grid_colW_tl-grid-inner_*` override written by the embedded
GridViewer. Scrubber window, bucket, histogram / grid heights, section
collapse state, pivot spec, regex extracts, card widths / order, query
text + history, and sus marks all return to first-run defaults in one
click. In-memory `_gridH` / `_chartH` / `_bucketId` / `_sections` /
`_cardWidths` / `_cardOrder` / `_queryEditor._history` are also reset,
the corresponding `--tl-grid-h` / `--tl-chart-h` CSS custom properties
on `_root` are cleared, and the GridViewer's `_userColWidths` Map is
emptied so the kind-aware auto-sizer repaints from scratch. Any new
`loupe_timeline_*` key added to the table above is covered by the same
prefix sweep and needs no additional wiring in `_reset()`.

**Adding a new key**

1. Use the `loupe_<feature>` prefix.
2. Read and write through a named accessor (`_getMyThing()` / `_setMyThing(value)`)
   in the owning `app-*.js` file so the write site is auditable.
3. Validate on read — never trust the stored value. If it's outside the
   expected range, fall back to a hard-coded default.
4. Add a row to this table in the same PR.

---

## Renderer Contract

Renderers are self-contained classes exposing a static `render(file, arrayBuffer, app)` that returns a DOM element (the "view container").

This section is the **prescriptive reference** for everything a renderer is
required (or merely permitted) to do. The architectural map of the same
contract — *who reads what, in which order* — lives in the
[Renderer side-effect contract](#renderer-side-effect-contract-current-de-facto-state)
table inside [Architecture & Signal Chain](#architecture--signal-chain). Read
the architectural map first if you need orientation; come back here for the
rules.

### Renderer Contract — Reference

The five rules below subsume every other "your renderer must…" instruction
elsewhere in this file. The deeper subsections (Risk Tier Calibration, IOC
Push Helpers / Checklist, click-to-highlight hooks) are the spelled-out forms
of rules 4, 5, and the table that follows this preamble respectively.

1. **Return shape.** Today, `render(file, buf, app)` returns a single
   `HTMLElement` — the view container that gets mounted under
   `#page-container`. Per [PLAN.md](../PLAN.md) Track D1 the canonical return
   will become an object:
   ```js
   { docEl: HTMLElement, findings?: Findings, rawText?: string,
     binary?: BinaryParsed, navTitle?: string }
   ```
   Both shapes will be accepted during the migration; the central
   `renderRoute` helper introduced by D1 normalises them. Until then, return
   the bare `HTMLElement` and continue mutating `app.findings` as today.

2. **Required `app.*` writes.** Mirroring the architectural side-effect table:

   | Field | When | Read by |
   |---|---|---|
   | `app.findings` | always | sidebar render, copy-analysis, exporters |
   | `app._fileBuffer` | always | auto-YARA fallback, copy-analysis |
   | `app._yaraBuffer` | when augmenting (e.g. SVG/HTML inject decoded payload) | auto-YARA prefers this over `_fileBuffer` |
   | `app._binaryParsed`, `app._binaryFormat` | binary renderers only (PE / ELF / Mach-O) | verdict band, copy-analysis |
   | `container._rawText` | every text-backed renderer | click-to-focus string search |

   Track D4 in PLAN.md replaces the scattered `app.*_buffer` globals with a
   single `app.currentResult`; until that lands, write the legacy fields.

3. **`container._rawText` must be LF-normalised — wrap the RHS in `lfNormalize(...)`.**
   Click-to-focus offsets misalign past the first CR otherwise — this is
   `.clinerules` Tripwire #11. Use the canonical `lfNormalize(s)` helper
   from [`src/constants.js`](src/constants.js) (single-pass `\r\n?` regex,
   idempotent for already-LF text, non-string inputs collapse to `''`).
   Direct writes whose RHS does not begin with `lfNormalize(` are rejected
   by a build-time grep gate in `scripts/build.py` (allow-listed only for
   `src/constants.js`, where the helper lives).

4. **Never pre-stamp `findings.risk`.** Initialise `f.risk = 'low'` and
   only escalate via `escalateRisk(findings, tier)` from
   [`src/constants.js`](src/constants.js), which applies the rank-monotonic
   ladder spelled out in [Risk Tier Calibration](#risk-tier-calibration).
   Direct writes (`f.risk = 'high'`) are rejected by a build-time grep
   gate in `scripts/build.py` (allow-listed only for `src/constants.js`,
   where the helper lives) — pre-stamping produces false-positive risk
   colouring on benign samples and is the single most-flagged
   `.clinerules` violation in code review.


5. **IOC `type` values must be `IOC.*` constants.** Bare strings
   (`type: 'url'`) silently break sidebar filtering — the read-side
   compares against the canonical `IOC.URL` etc. in
   [`src/constants.js`](src/constants.js). Push every IOC through
   `pushIOC()` so the canonical shape is enforced and the auto-emitted
   sibling rows (registrable domain via `tldts`, embedded IPs in URLs,
   punycode/IDN homoglyph patterns) come along for free. The full
   per-field rules are in [IOC Push Checklist](#ioc-push-checklist);
   the helpers themselves in [IOC Push Helpers](#ioc-push-helpers).
   Enforced by a build-time grep gate in `scripts/build.py` (paired
   with the risk-pre-stamp gate from Track B1) — any line containing
   both `type: '<bare>'` and `severity:` outside `src/constants.js`
   fails the build.

### Click-to-highlight hooks

To participate in sidebar click-to-highlight (the yellow/blue `<mark>` cycling users see when clicking an IOC or YARA hit) a text-based renderer should attach the following optional hooks to the container element it returns:

| Property | Type | Purpose |
|---|---|---|
| `container._rawText` | `string` | The normalised source text backing the view. Used by `app-sidebar.js::_findIOCMatches()` and `_highlightMatchesInline()` to locate every occurrence of an IOC value and by the encoded-content scanner to compute line numbers. Line endings must be normalised to `\n` so offsets line up with the rendered `.plaintext-table` rows. |
| `container._showSourcePane()` | `function` | Invoked before highlighting on renderers that have a Preview/Source toggle (e.g. HTML, SVG, URL). Must synchronously (or via a short `setTimeout(…, 0)`) expose the source pane so a subsequent `scrollIntoView()` on a `<mark>` lands on a visible element. Optional. |
| `container._yaraBuffer` | `Uint8Array` | Optional. When set, the YARA engine scans this buffer instead of the raw file bytes. Used by SVG/HTML to include an augmented representation (e.g. decoded Base64 payloads) without contaminating Copy/Save. |

If the renderer emits a `.plaintext-table` (one `<tr>` per line with a `.plaintext-code` cell per line) the sidebar automatically gets character-level match highlighting, line-background cycling, and the 5-second auto-clear behaviour for free. Renderers without a plaintext surface fall back to a best-effort TreeWalker highlight on the first match found anywhere in the DOM.

### Risk Tier Calibration

A renderer's `analyzeForSecurity()` must emit a `findings.risk` value in the
canonical set `'low' | 'medium' | 'high' | 'critical'` (no `'info'`, no
bespoke strings). The tier is **evidence-based**, not format-based — an empty
`.hta` with no scripts and no IOCs is `'low'`, a weaponised `.png` with an
embedded PE is `'high'`.

1. **Initialise `f.risk = 'low'`.** Do not pre-stamp on the grounds that a
   format "can be abused". The risk bar and Summary exporter both read
   `findings.risk` directly; a pre-stamped floor produces false-positive
   risk colouring on benign samples.
2. **Escalate from `externalRefs`.** The end of `analyzeForSecurity()`
   should look at the severities it pushed onto `f.externalRefs`
   (detections mirrored in as `IOC.PATTERN`, plus any format-specific
   escalations) and lift `f.risk` accordingly:
   ```js
   const highs   = f.externalRefs.filter(r => r.severity === 'high').length;
   const hasCrit = f.externalRefs.some(r => r.severity === 'critical');
   const hasMed  = f.externalRefs.some(r => r.severity === 'medium');
   if      (hasCrit)      f.risk = 'critical';
   else if (highs >= 2)   f.risk = 'high';
   else if (highs >= 1)   f.risk = 'medium';
   else if (hasMed)       f.risk = 'low';
   ```
3. **Never silently downgrade — use `escalateRisk()`.** The canonical
   helper in [`src/constants.js`](src/constants.js) applies the
   rank-monotonic ladder
   `{ info: 0, low: 1, medium: 2, high: 3, critical: 4 }` and is the
   only path the build gate (see `scripts/build.py`) allows for writing
   `findings.risk`:
   ```js
   escalateRisk(f, tier);   // never lowers; safe to call repeatedly
   ```
   The legacy hand-rolled rank-table pattern (`if ((rank[tier] || 0) >
   (rank[f.risk] || 0)) f.risk = tier`) is equivalent in semantics but
   is rejected by the build gate — every renderer now funnels through
   `escalateRisk()`.

4. **Detections must be mirrored first.** The calibration block only works
   if every `Detection` has already been pushed into `externalRefs` as an
   `IOC.PATTERN` (see item 5 in the IOC Push Checklist below). Otherwise a
   YARA-only finding is invisible to the risk calculation.

The `cross-renderer-sanity-check` skill grades new renderers against this
contract.

### IOC Push Helpers

`src/constants.js` ships two helpers every renderer should prefer over
hand-rolling `findings.interestingStrings.push({...})`:

- **`pushIOC(findings, {type, value, severity?, highlightText?, note?, bucket?})`**
  writes a canonical IOC row into `interestingStrings` (or `externalRefs`
  when `bucket: 'externalRefs'` is passed). It pins the on-wire shape
  (`{type, url, severity, _highlightText?, note?}`) and **auto-emits a
  sibling `IOC.DOMAIN` row** whenever `type === IOC.URL` and vendored
  `tldts` resolves the URL to a registrable domain. Pass
  `_noDomainSibling: true` if you already emit a manual domain row.

- **`mirrorMetadataIOCs(findings, {metadataKey: IOC.TYPE, ...}, opts?)`** is
  a metadata → IOC mirror. The sidebar IOC table is fed *only* from
  `externalRefs + interestingStrings` — a value that lives on
  `findings.metadata` alone never reaches the analyst's pivot list. Call
  this at the end of `analyzeForSecurity()` to mirror the **classic pivot**
  fields (hashes, paths, GUIDs, MAC, emails, cert fingerprints) into the
  sidebar. Array-valued metadata emits one IOC per element.

**Option-B rule**: mirror only classic pivots. Do **not** mirror attribution
fluff — `CompanyName`, `FileDescription`, `ProductName`, `SubjectName` etc.
stay on `metadata` and are visible in the viewer, but are noise in a
pivot list and fatten `📤 Export`'s CSV/STIX/MISP output for no gain.

### IOC Push Checklist

Every IOC the renderer emits — whether onto `findings.externalRefs` or `findings.interestingStrings` — must obey this contract. The `ioc-conformity-audit` skill grades pull requests against these rules.

1. **Type is always an `IOC.*` constant** from `src/constants.js`. The
   canonical set is `IOC.URL`, `IOC.EMAIL`, `IOC.IP`, `IOC.FILE_PATH`,
   `IOC.UNC_PATH`, `IOC.ATTACHMENT`, `IOC.YARA`, `IOC.PATTERN`, `IOC.INFO`,
   `IOC.HASH`, `IOC.COMMAND_LINE`, `IOC.PROCESS`, `IOC.HOSTNAME`,
   `IOC.USERNAME`, `IOC.REGISTRY_KEY`, `IOC.MAC`, `IOC.DOMAIN`, `IOC.GUID`,
   `IOC.FINGERPRINT`. Enforced by a build-time grep gate in
   `scripts/build.py` — any line containing both `type: '<bare>'` and
   `severity:` outside `src/constants.js` fails the build, so a copy-pasted
   `type: 'url'` is caught at `python make.py` time rather than silently
   dropping out of the sidebar IOC filter.
2. **Severity comes from `IOC_CANONICAL_SEVERITY`** (also in
   `src/constants.js`) unless you have a renderer-specific reason to
   escalate. Escalations must be *up* from the canonical floor, not
   reductions.
3. **Carry `_highlightText`, never raw offsets into a synthetic buffer.**
   Offsets are only meaningful when they are true byte offsets into the
   rendered surface. If you extracted the value from a joined-string
   buffer, set only `_highlightText: <value>` — the sidebar locates it
   in the plaintext table at display time.
4. **Cap large IOC lists with an `IOC.INFO` truncation marker.** When a
   renderer walks a large space (PE/ELF/Mach-O string tables, EVTX event
   fields, ZIP attachments), enforce a cap and *after* the cap push
   exactly one `IOC.INFO` row whose `url:` field explains the reason and
   the cap count.
5. **Mirror every `Detection` into `externalRefs` as `IOC.PATTERN`.** The
   standard tail in `analyzeForSecurity` is
   `findings.externalRefs = findings.detections.map(d => ({ type: IOC.PATTERN, url: `${d.name} — ${d.description}`, severity: d.severity }))`.
   Without this a detection shows up in the banner but is invisible to
   Summary, Share, and the STIX/MISP exporters.
6. **Every IOC value must be click-to-focus navigable.** When the sidebar
   fires a navigation event for your IOC, the renderer's container must
   react: `_rawText` present for plaintext renderers, `_showSourcePane()`
   for toggle-driven ones (HTML/SVG/URL), or a custom click handler that
   scrolls the relevant row/card into view and flashes a highlight class.
7. **Generic text extraction is capped per-type, not globally.**
   `_extractInterestingStrings` in `src/app/app-load.js` walks `_rawText`
   (or `textContent`) after renderer-specific IOCs are seeded, and
   enforces a `PER_TYPE_CAP` (currently 200) on each `IOC.*` type. Drops
   are surfaced via `findings._iocTruncation` → sidebar warning banner.
   Renderer-seeded IOCs (`findings.interestingStrings` populated by
   `analyzeForSecurity`) are **not** subject to this cap — renderers are
   responsible for their own truncation (see item 4).

---

## Adding a New File Format Renderer

1. Create `src/renderers/foo-renderer.js` with a `FooRenderer` class
   exposing `static render(file, arrayBuffer, app)`.
2. Add format detection in `src/renderer-registry.js` (+ a route in
   `src/app/app-load.js` if the extension needs it).
3. Add to `JS_FILES` in `scripts/build.py` (before `app-core.js`, after
   `renderer-registry.js` if the registry imports it).
4. Add viewer CSS to `src/styles/viewers.css` if needed.
5. Rebuild and regenerate codemap: `python make.py`.
6. **Docs to update:** add the extension + capability to the formats table
   in `FEATURES.md`; if it is a headline capability, also add it to the
   compact table in `README.md`.

---

## Adding a New YARA Rule

1. Choose the appropriate `.yar` file under `src/rules/` by category.
2. Add your rule; rebuild with `python scripts/build.py`.
3. **Never insert comments in YARA rule files.** `scripts/build.py`
   injects `// @category: <name>` lines during concatenation — those are
   the only `//` lines the engine tolerates.
4. **Docs to update:** if the rule flags a **new class of threat** not
   already covered, add a row to the security-analysis table in
   `FEATURES.md`. Ordinary new rules within an existing category need no
   doc change.

---

## Adding a New Export Format

The toolbar's **📤 Export** dropdown is driven by a declarative menu in `src/app/app-ui.js`. All exporters are offline, synchronous (or `async` + `await` for `crypto.subtle` hashing only), and must never reach the network. **Default to the clipboard** — every menu item except `💾 Save raw file` writes to the clipboard so the analyst can paste straight into a ticket / TIP / jq pipeline. Plaintext and Markdown report exports live behind the separate `⚡ Summary` toolbar button.

1. **Write the builder.** Add `_buildXxx(model)` + a thin `_exportXxx()` wrapper (or fold both into one `_exportXxx()`) to the `Object.assign(App.prototype, {...})` block in `src/app/app-ui.js`. Reuse the shared helpers:
   - `this._collectIocs()` — normalised IOC list (each entry has `type`, `value`, `severity`, `note`, `source`, `stixType`).
   - `this._fileMeta`, `this.fileHashes`, `this.findings` — canonical input surface.
   - `this._fileSourceRecord()` — identical `{name,size,detectedType,magic,entropy,hashes{…}}` block that every threat-intel exporter embeds so the file is unambiguously identified.
   - `this._copyToClipboard(text)` + `this._toast('Xxx copied to clipboard')` — the default destination.
   - `this._buildAnalysisText(Infinity)` — unbudgeted plaintext report (same content as the ⚡ Summary button).
   - `this._downloadText(text, filename, mime)` / `this._downloadBytes(bytes, filename, mime)` / `this._downloadJson(obj, filename)` / `this._exportFilename(suffix, ext)` — only when the output is genuinely a file (e.g. `💾 Save raw file`). These are thin delegates to `window.FileDownload.*` in `src/file-download.js`, which owns the sole `URL.createObjectURL → <a download> → revoke` ceremony in the codebase. **Never call `URL.createObjectURL` directly** — add a helper to `src/file-download.js` instead.
2. **Register the menu item.** Add an entry to the array returned by `_getExportMenuItems()` — `{ id, icon, label, action: () => this._exportXxx() }`. Use `{ separator: true }` to add a divider. Prefix the label with `Copy ` when the action writes to the clipboard.
3. **Wrap it.** The click dispatcher in `_openExportMenu()` wraps every action in `try { … } catch (err) { console.error(…); this._toast('Export failed — see console', 'error'); }`. Your exporter just needs to `_toast('Xxx copied to clipboard')` on success.

**Docs to update:** add a column to the format × contents matrix in `FEATURES.md § Exports`, plus a row to the menu-actions table.

**Do not:**

- Pull in a new vendored library just for an export format — if the spec needs SHA-1/SHA-256, use `crypto.subtle`; if it needs UUIDv5, use the existing `_uuidv5()` helper.
- Fabricate vendor-specific custom extensions (e.g. `x_loupe_*` STIX properties) — either map to a standard field or skip the IOC.
- Add network calls, `eval`, `new Function`, or anything that would require a CSP relaxation.

---

## Adding a New Theme

All built-in themes are driven by the same set of CSS custom properties
("design tokens") defined in `src/styles/core.css`. A new theme is a pure
overlay — it only re-defines the tokens and does not touch any selector,
layout rule, or component style. `src/styles/viewers.css` and every
renderer's inline styles read exclusively from these tokens.

### The token contract

The canonical tokens every theme must define live at the top of
`src/styles/core.css`. The non-negotiable ones are:

| Token | Purpose |
|---|---|
| `--accent` / `--accent-rgb` / `--accent-hover` / `--accent-deep` | Primary brand colour. `--accent-rgb` is the **space-separated** RGB triplet (`"r g b"`) for CSS Colors 4 `rgb(var(--accent-rgb) / .12)` syntax |
| `--risk-high` / `--risk-high-rgb` / `--risk-med` / `--risk-low` / `--risk-info` | Four-tier risk palette (risk bar, detection chips, renderer colour assignments) |
| `--hairline-soft` / `--hairline` / `--hairline-strong` / `--hairline-bold` | Four-tier border palette |
| `--panel-bg` / `--panel-bg-inset` / `--panel-bg-raised` / `--panel-bg-section` | Four-tier panel surface palette |
| `--panel-border` / `--input-border` | Solid-colour borders for panels and form controls |
| `--input-bg` / `--row-hover` | Form control background; row/list hover tint |
| `--text` / `--text-muted` / `--text-faint` | Three-tier foreground palette |
| `--banner-warn-*` / `--banner-danger-*` / `--banner-info-*` / `--banner-ok-*` | Per-severity banner tints (`-bg`, `-text`, `-border`) |

The full list is enumerated in the `:root` / `body.dark` blocks at the top
of `core.css`. **Never reach for a hardcoded hex or `rgba(255, 255, 255, …)`
in a `body.dark` rule** — there is a semantic token for every
renderer-chrome surface. Spot-check:
`grep -nE '#[0-9a-f]{3,8}|rgba\(' src/styles/viewers.css | grep -v 'var(--' | grep 'body\.dark'` should only return `.hljs-*` syntax-highlighting rules.

### Recipe

1. **Create the overlay** — add `src/styles/themes/<id>.css` scoped to
   `body.theme-<id>`. Only re-declare the tokens; never write
   component-level selectors:
   ```css
   body.theme-foo {
     --accent: #ffb454;
     --accent-rgb: 255 180 84;
     --accent-hover: #ffc673;
     --accent-deep: #cc8f43;
     --risk-high: #f26d6d;
     --risk-high-rgb: 242 109 109;
     /* …every token from the contract… */
   }
   ```
2. **Register in `CSS_FILES`** — append the overlay path to the
   `CSS_FILES` list in `scripts/build.py`.
3. **Register in `THEMES`** — add a `{ id, label, icon, dark }` row to
   the `THEMES` array at the top of `src/app/app-ui.js`. Set
   `dark: true` if the theme targets a dark baseline.
4. **Update the FOUC bootstrap** — add the new id to the `THEME_IDS`
   array in the inline `<script>` in `scripts/build.py`. If the theme is
   dark, also add its id to the `DARK_THEMES` map.
5. **(Optional) pick a backdrop engine** — `src/app/app-bg.js` paints a
   subtle per-theme animated backdrop on the landing drop-zone. Map your
   new id in the top-of-file `THEME_ENGINES` constant to one of the
   built-in engines — `penroseLight` (aperiodic P3 rhombic tiling in
   soft blue / warm lavender with larger tiles and faster breathing, the
   Light baseline), `penroseDark` (P3 tiling in cool white / accent cyan
   with lower alpha and slower breathing, the Dark baseline),
   `cuteHearts` (floating hearts, Latte), `cuteKitties` (floating kitten
   silhouettes, Mocha), `penrose` (P3 tiling in Solarized yellow / cyan
   with mid-range alpha and breathing, the Solarized baseline) — or to
   `null` to render nothing at all (Midnight's OLED-black stays OLED-
   black). Any id not listed in `THEME_ENGINES` falls through to the
   `penroseLight` baseline at runtime.
   If you also add a new engine, extend the `PALETTES` map with a
   hard-coded RGB tuple per theme so the animation never reads
   computed-style vars mid-frame. The backdrop is always suppressed by
   `prefers-reduced-motion` and whenever `#drop-zone` carries
   `.has-document` — no wiring required per theme.
6. **Rebuild and test** — `python scripts/build.py`, then open
   `docs/index.html` and click through every tile in ⚙ Settings → Theme.
7. **Regenerate the code map** — `python scripts/generate_codemap.py`.

**Docs to update:** `FEATURES.md` if the theme is added to the picker
row; `README.md` only if it is promoted to the compact theme list.

### FOUC prevention

The inline `<script>` in `scripts/build.py` (`<head>`, immediately after the
`<style>` block) applies the saved theme class to `<body>` before first
paint. The logic mirrors `_initTheme()` in `src/app/app-ui.js` and is
covered by `script-src 'unsafe-inline'` (already required by the rest of
the bundle — no CSP relaxation added). If `<body>` has not been parsed yet,
the bootstrap stashes the classes on `<html>` and copies them across via a
one-shot `MutationObserver`.

First-boot fallback order:
1. Saved `localStorage['loupe_theme']` (if a valid id).
2. OS `prefers-color-scheme: light` → Light, else Dark.
3. Hard-coded `'dark'` if both fail.

---

## Adding or Upgrading a Vendored Library

1. Place the upstream release bytes under `vendor/<name>.js` — **do not modify** the file.
2. Recompute its SHA-256
   (`Get-FileHash -Algorithm SHA256 vendor\<file>` on Windows,
   `sha256sum vendor/<file>` on Linux/macOS).
3. For a **new** library, read & inline it in `scripts/build.py` alongside the other vendor reads.
4. **Docs to update (required):** add or rotate the row in `VENDORED.md` — file path, version, licence, SHA-256, upstream URL. A vendor change without a `VENDORED.md` change is a broken commit.

---

## Changing a Security-Relevant Default

(CSP, parser limits, sandbox flags)

1. Make the change in the appropriate source file (`scripts/build.py` for
   CSP, `src/parser-watchdog.js` / `src/constants.js` for `PARSER_LIMITS`,
   etc.).
2. **Docs to update (required):** update the relevant row in `SECURITY.md`
   — either the threat-model property table or the Security Design
   Decisions table. Also note the change in `FEATURES.md` if it is
   user-visible.

---

## How to Contribute

1. Fork the repo.
2. Make your changes in `src/`.
3. Run `python make.py` — chains `verify_vendored.py` → `build.py` → `generate_codemap.py`.
4. Test by opening `docs/index.html` in a browser (the file is `.gitignore`d — build locally, never commit it).
5. Stage only your `src/` edits and the regenerated `CODEMAP.md`.
6. Submit a pull request.

YARA rule submissions, new format parsers, and build-process improvements
are especially welcome. The codebase is vanilla JavaScript (no frameworks,
no bundlers beyond the simple `scripts/build.py` concatenator) to keep it
auditable.
