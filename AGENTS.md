# AGENTS.md — Loupe

> Operating guide for AI/automation agents working in this repository.
> This file is the **first** thing an agent should read; it is intentionally
> denser and more action-oriented than `CONTRIBUTING.md`. When this doc
> conflicts with `CONTRIBUTING.md`, `CONTRIBUTING.md` wins (it is the
> authoritative developer guide); update this file in the same PR.

Loupe is a **single-file, 100% offline** browser-based static security
analyser. The shipped product is one HTML file (`docs/index.html` →
`loupe.html` at release time) opened over `file://` or served from any
static host; there is no backend, no module loader, no network at runtime.

**Authoritative-source priority for agents**
1. **This file (`AGENTS.md`)** — agent-facing operating instructions, command
   cheatsheet, recurring pain-points with commit refs.
2. **`CONTRIBUTING.md`** — full developer reference (renderer contract,
   IOC checklist, persistence keys, mermaid signal-chain diagrams).
3. **`SECURITY.md`** — threat model, full CSP, parser-limit table,
   reproducible-build recipe.
4. **`FEATURES.md`** — per-format capability matrix.
5. **`tests/README.md`** — test-API surface + Playwright provisioning.

**Agents must…**
- Use the **fff** MCP tools (`fff_find_files`, `fff_grep`, `fff_multi_grep`)
  for all in-repo file/content search instead of default tools.
- **Never** stage build artefacts: `docs/index.html`,
  `docs/index.test.html`, `dist/`, `loupe.html*`, `playwright-report/`,
  `test-results/`, `.opencode/`, `.agents/` — every one of these is
  gitignored and produced by CI/release/test runs. Edits to `scripts/`,
  `tests/`, `vendor/` (with VENDORED.md update), and the top-level docs
  (`README.md`, `FEATURES.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  `VENDORED.md`, `AGENTS.md`) are first-class — stage them as needed.
- **Keep this file alive, but lean.** Update `AGENTS.md` when you change
  behaviour, gates, or build steps that contradict it. New gotchas go
  under [Recurring pain-points](#recurring-pain-points--gotchas-with-commit-refs)
  as **a single line** with the fix's short-SHA — nothing more. Detail
  belongs in the commit message; that's what `git show <sha>` is for.
- **Do NOT write your life history into this file.** Every agent loads
  it on startup; bloat degrades agent performance and reviewer focus.
  Before adding more than one line: ask whether the next agent actually
  needs it, or whether it's better as a code comment, a commit message,
  or a `CONTRIBUTING.md` section. If in doubt, leave it out.

---

## Repository map

```
src/
  app/                          App.prototype mixin chain — load order in scripts/build.py is load-bearing
    early-drop-bootstrap.js     Captures drop / dragover / paste before App boots (e937d32)
    app-core.js                 Constructor; _navStack ownership; _reportNonFatal
    app-load.js                 _loadFile, _setRenderResult (the ONLY epoch++ site)
    app-ui.js                   Toolbar, dialogs, themes registry, exports menu
    app-bg.js                   Themed background canvas engines
    app-sidebar.js              Findings sidebar
    app-sidebar-focus.js        Click-to-focus engine; loads AFTER app-sidebar
    app-yara.js                 Auto-YARA, manual scan, decoded-payload gate
    app-copy-analysis.js        Summary-report builders; loads AFTER app-ui
    app-selection-decode.js     Floating "🔍 Decode selection" chip
    app-settings.js             Settings dialog; loads AFTER app-ui + app-copy-analysis
    app-breadcrumbs.js          Drill-down navigation strip
    app-test-api.js             ONLY appended in --test-api builds
    timeline/                   Self-contained Timeline route (~21 files)
  renderers/                    static render(file, buf, app) per format (~50 files)
    archive-tree.js             Helper used by zip/jar/msix/...; not a renderer itself
    grid-viewer.js              Helper for tabular renderers; consumes RowStore
    ole-cfb-parser.js           Helper for office formats
    protobuf-reader.js          Helper for protobuf-shaped formats
  decoders/                     EncodedContentDetector helpers (prototype mixins via _DETECTOR_FILES)
  workers/                      yara / encoded / timeline / ioc-extract bodies + shims
  geoip/                        geoip-store (IDB), mmdb-reader, bundled-geoip (IPv4-country)
  rules/*.yar                   YARA rule packs — NO comments, strict meta whitelist
  styles/                       core.css, viewers.css, themes/<id>.css
  constants.js                  PARSER_LIMITS, RENDER_LIMITS, IOC.*, pushIOC, escalateRisk,
                                safeRegex/safeExec/safeTest/safeMatchAll, lfNormalize,
                                throwIfAborted, IOC_CANONICAL_SEVERITY, EVTX_COLUMNS
  render-route.js               Dispatch wrapper, watchdog, epoch fence, plaintext fallback
  renderer-registry.js          Probe → renderer-class map
  parser-watchdog.js            AbortController-aware timeout helper
  worker-manager.js             Sole new Worker(blob:) spawner; cancellation, terminate
  sandbox-preview.js            Single source for HTML/SVG iframe sandbox + drag shield
  file-download.js              Single source for blob downloads
  archive-budget.js             Aggregate-recursion budget (50k entries / 256 MiB)
  binary-class.js, capabilities.js, binary-triage.js, binary-verdict.js
  nicelist.js, nicelist-user.js, nicelist-annotate.js
  ioc-extract.js, encoded-content-detector.js, security-analyzer.js, mitre.js
  parser-watchdog.js, hashes.js, lolbas-map.js, evtx-detector.js, ...

scripts/                        build, gates, test runners (all orchestrated by make.py)
  build.py                      JS_FILES / CSS_FILES / YARA_FILES / _DETECTOR_FILES — order matters
  verify_vendored.py            SHA-256 pin check vs VENDORED.md
  check_regex_safety.py         Every new RegExp(...) needs safeRegex or annotation within 3 lines
  check_shim_parity.py          Worker shims must mirror canonical PARSER_LIMITS / RENDER_LIMITS / IOC table
  lint_yara.py                  Comment-free, meta-key whitelist, canonical order; --fix autofixes
  check_renderer_contract.py    Static contract: class …Renderer + render( method
  generate_sbom.py              CycloneDX SBOM from VENDORED.md (release-time only)
  run_tests_unit.py, run_tests_e2e.py, run_perf.py, run_fuzz.py
  fetch_geoip.py                Regenerate vendor/geoip-country-ipv4.bin
  misc/                         One-shot fixture generators (NOT in main pipeline)

tests/
  unit/                         Node node:test in vm.Context (Node ≥ 20)
  e2e-fixtures/                 Playwright + docs/index.test.html driving __loupeTest.loadBytes
  e2e-ui/                       Playwright UI ingress (file picker, drag-drop, paste)
  perf/                         Opt-in, LOUPE_PERF=1 only
  fuzz/                         Opt-in, Jazzer.js + replay mutator + coverage/technique rollups; never enters bundle
  helpers/load-bundle.js        vm-context loader + Jazzer require-bundle helper for unit tests/fuzzing
  helpers/playwright-helpers.ts useSharedBundlePage + cross-load reset
  e2e-fixtures/expected.jsonl   Snapshot matrix (range-based assertions, regenerable)
  e2e-fixtures/yara-rules-fired.json  YARA rule-coverage manifest
  explore/dump-fixtures.spec.ts LOUPE_EXPLORE=1 → dumps for gen_expected.py

vendor/                         Pinned 3rd-party libs; SHA-256 in VENDORED.md
examples/                       Fixture corpus per renderer; used by e2e-fixtures
.github/workflows/              ci, release (chained), codeql, scorecard, refresh-geoip
docs/index.html                 BUILD ARTEFACT (gitignored). Never commit.
docs/index.test.html            TEST BUILD ARTEFACT (gitignored). Never commit.
dist/                           SBOM, perf reports, test-deps. Gitignored.
```

---

## Build / verify / test cheatsheet

```bash
# Default local edit-build-verify loop (zero-deps; Python 3.8+ stdlib only)
python make.py                          # verify → regex → parity → yara-lint → build → contract
python make.py build contract           # fastest re-verify after a src/ tweak
python make.py verify                   # vendor SHA-256 pin check
python make.py regex                    # ReDoS / safeRegex annotation gate
python make.py parity                   # worker-shim ↔ canonical PARSER_LIMITS / IOC table
python make.py yara-lint                # YARA house-style; --fix variant below
python scripts/lint_yara.py --fix       # autofix YARA meta-key order, comments, whitespace
python make.py contract                 # static renderer-contract check (class + render method)
python make.py sbom                     # opt-in; release-time only
python make.py perf                     # opt-in; sets LOUPE_PERF=1 internally
python make.py fuzz                     # opt-in; Jazzer.js coverage-guided over tests/fuzz/targets/ via loadModulesAsRequire()

# Test pipeline (opt-in; never blocks the default loop)
python make.py test                     # test-build → test-unit → test-e2e
python make.py test-build               # build docs/index.test.html with --test-api
python make.py test-unit                # node:test over tests/unit/
python make.py test-e2e                 # Playwright (e2e-fixtures + e2e-ui)

# Pass extra args to Playwright (make.py test-e2e does NOT forward them)
python scripts/run_tests_e2e.py --ui                                       # UI mode
python scripts/run_tests_e2e.py --grep "phishing"                          # filter
python scripts/run_tests_e2e.py tests/e2e-fixtures/email.spec.ts           # one spec
python scripts/run_tests_e2e.py --debug tests/e2e-fixtures/csv.spec.ts     # PWDEBUG

# Performance harness (opt-in; never in CI)
LOUPE_PERF=1 python scripts/run_perf.py                  # 100k rows × 3 runs
LOUPE_PERF=1 python scripts/run_perf.py --rows 10000 --runs 1   # smoke
# Output: dist/perf-report.json + dist/perf-report.md

# Fuzz harness (opt-in; never in CI; never enters the bundle)
python scripts/run_fuzz.py --replay --quick              # 5 s/target, no npm install
python scripts/run_fuzz.py --time 300 text/ioc-extract   # 5 min coverage-guided run
python scripts/run_fuzz.py --reproduce <crash>/input.bin # replay one specific crash
python scripts/fuzz_minimise.py <target> <crash-dir>     # shrink crashing input.bin → minimised.bin
python scripts/fuzz_promote.py  <target> <crash-dir>     # mint tests/unit/<slug>-fuzz-regress-<sha>.test.js
python scripts/run_fuzz.py --coverage --replay --quick   # also emit per-src/file line-coverage table
python scripts/fuzz_coverage_aggregate.py                # re-render coverage table from existing dumps
# Targets discoverable via `python scripts/run_fuzz.py --list`. Runbook:
# tests/fuzz/README.md. Pinned dep: @jazzer.js/core (Apache-2.0) staged
# under dist/test-deps/ alongside @playwright/test.

# Regenerate snapshot matrix after a deliberate baseline shift
LOUPE_EXPLORE=1 python scripts/run_tests_e2e.py tests/explore/dump-fixtures.spec.ts
python scripts/gen_expected.py
git diff tests/e2e-fixtures/expected.jsonl

# Regenerate YARA rule-coverage manifest
python scripts/gen_yara_coverage.py

# Lint locally exactly like CI (pinned ESLint version is the source of truth)
npx --yes eslint@9.39.4 --config eslint.config.mjs "src/**/*.js"

# Force fresh Playwright provisioning
rm -rf dist/test-deps                                    # next run reinstalls
PWBROWSER_DEPS=1 python make.py test-e2e                 # fresh-workstation Linux libs (sudo)

# Smoke-by-hand: rebuild then drop a file from examples/
python make.py build && xdg-open docs/index.html         # Linux
python make.py build && open docs/index.html             # macOS

# GitHub helpers (any mention of GitHub uses gh)
gh run list -L 5                                          # recent CI runs
gh run watch                                              # watch the latest run
gh run view --log                                         # full log
gh pr checks                                              # PR status
gh release view --json                                    # latest release
gh workflow run ci.yml --ref main                         # manual rebuild (force-Pages-deploy)

# Useful git probes
git log --oneline --grep="^fix" -- src/render-route.js    # area-scoped fixes
git show <sha>                                            # context for any pain-point SHA below
git log --pretty=fuller -1 <sha>                          # full body + author
```

---

## CI / GitHub workflow map

Five workflows in `.github/workflows/`:

| Workflow | Triggers | Notes |
|---|---|---|
| `ci.yml` | push to `main`, PRs, `workflow_dispatch` | Doc-only commits skip via `paths-ignore: '**/*.md', LICENSE`. `concurrency` cancels in-flight runs on same ref. |
| `release.yml` | `workflow_run` after green `ci.yml` on `main` | Checks out the **exact `head_sha` CI validated** → "release ⇔ green main CI". Sigstore-signs `loupe.html`. |
| `codeql.yml` | push to `main`, weekly | `security-extended` query pack. |
| `scorecard.yml` | weekly | OpenSSF Scorecard → Security tab + README badge endpoint. |
| `refresh-geoip.yml` | monthly | Auto-PR to refresh `vendor/geoip-country-ipv4.bin`. |

`ci.yml` jobs (all gating except where noted):

| Job | What it guarantees |
|---|---|
| `build` | `scripts/build.py` succeeds with `SOURCE_DATE_EPOCH` pinned to HEAD's commit-author timestamp; SHA-256 + size in job summary; bundle uploaded as artefact. |
| `verify-vendored` | Every `vendor/*.js` matches `VENDORED.md` SHA-256 (no missing, no unpinned). |
| `yara-lint` | Comment-free, meta-key whitelist, canonical order, severity values. |
| `static-checks` | On the built bundle: CSP meta present, `default-src 'none'` intact, no inline `on*=` attribute handlers, no `'unsafe-eval'`, no remote CSP hosts. |
| `lint` | ESLint **9.39.4** (pinned) over `src/**/*.js` — minimal config (`no-eval`, `no-new-func`, `no-const-assign`, …). Not a style enforcer. |
| `unit` | `python make.py test-unit` (Node 24, `node:test`, `vm.Context`). |
| `e2e` | Builds `docs/index.test.html` inline with `--test-api`; caches `@playwright/test` + Chromium browsers keyed by `PLAYWRIGHT_VERSION`. |
| `deploy-pages` | **Only on `main`**, only after `build` + `verify-vendored` + `static-checks` + `lint` + `yara-lint` pass. Replaces the historical "commit `docs/index.html` to git" dance. |

All third-party Actions are pinned by full 40-char commit SHA with the
human-readable version in a trailing comment (per OpenSSF Scorecard's
Pinned-Dependencies check); Dependabot rotates them weekly.

---

## Architecture TL;DR

- `src/` is concatenated into one inline `<script>` inside `docs/index.html`
  by `scripts/build.py`. **No bundler. No module system. Every class is an
  implicit global.** ESLint's `no-undef` / `no-redeclare` are intentionally
  disabled — references resolve at build time.
- `App` is a single class extended across `src/app/app-*.js` files via
  `Object.assign(App.prototype, {...})`. Later files override earlier
  methods; `JS_FILES` order in `scripts/build.py` is load-bearing.
- **Ingress:** drop / picker / iframe `loupe-drop` `CustomEvent` →
  `App._handleFiles` → `App._loadFile` → either Timeline 3-probe sniff
  bypass OR `RenderRoute.run` → `RendererRegistry.dispatch` →
  `static render(file, buf, app)` → mutate `app.findings` &
  `container._rawText` → `App._renderSidebar` → `App._autoYaraScan`.
- **Drill-down:** bubbling `open-inner-file` `CustomEvent` →
  `App.openInnerFile` (push nav frame, re-enter `_loadFile`). Unified in
  `22d1df1`.
- **Timeline route is bypass.** CSV / TSV / EVTX / PCAP / SQLite / structured logs
  go through `src/app/timeline/` and push **no** IOCs, mutate **no**
  `app.findings`, run **no** `EncodedContentDetector`. EVTX and PCAP are
  the two hybrids — the parser runs in the timeline worker, but the
  analyser (`EvtxDetector.analyzeForSecurity` / `PcapRenderer._analyzePcapInfo`)
  runs on the main thread because it touches `pushIOC` / `IOC.*` /
  `escalateRisk` globals absent from the worker bundle. Their findings
  land on the TimelineView's `_evtxFindings` / `_pcapFindings` side-channels
  and drive the ⚡ Summarize button.
- **Mutation model:** renderers mutate `app.findings` and `app.currentResult`
  **in place**, fenced by render-epoch.

---

## The 12 hard invariants

1. **No `eval` / `new Function` / network.** CSP rejects them; do not relax.
2. **`docs/index.html` is gitignored** — never commit it. CI rebuilds and
   deploys.
3. **`IOC.*` constants only**; never bare strings like `'url'` / `'ip'`.
4. **`pushIOC()` only**; not raw `findings.interestingStrings.push(...)`.
   URL pushes auto-emit sibling `IOC.DOMAIN` via vendored `tldts`. Pass
   `_noDomainSibling: true` if you've already emitted one manually.
5. **`escalateRisk(findings, tier)` only.** Never write
   `findings.risk = '<tier>'` directly. Risk is **evidence-derived** at
   the end of `analyzeForSecurity()` from `externalRefs` severities.
6. **`container._rawText = lfNormalize(...)`** always (`7ab62b7`). Offsets
   misalign past the first CR otherwise; build gate enforces.
7. **`safeRegex(...)` for user-input regex** (`ffd265e`). Every other
   `new RegExp(...)` needs `/* safeRegex: builtin */` within 3 lines above
   (`scripts/check_regex_safety.py`).
8. **No comments in `.yar` files**; strict meta-key whitelist in canonical
   order: `description, severity, category, mitre, applies_to`.
9. **All `localStorage` keys use `loupe_` prefix** and live in the
   Persistence Keys table in `CONTRIBUTING.md`. New key → table row in the
   same PR.
10. **Workers spawn only via `WorkerManager`**; downloads only via
    `FileDownload.*`; sandbox iframes only via `SandboxPreview.create()`.
11. **No silent `catch{}`** in load chain — use
    `App._reportNonFatal(where, err, opts?)` from `app-core.js`. Build gate
    enforces; escape-hatch comment is `// loupe-allow:silent-catch`
    (currently unused).
12. **Renderers must finish under `RENDERER_TIMEOUT_MS` (30 s).** Long
    outer loops poll `throwIfAborted()` amortised:
    `if ((i & 0xFF) === 0) throwIfAborted(opts?.signal);`. **Never** poll
    per-byte.

---

## Render-epoch contract — the single most-broken invariant

`app._renderEpoch` is a monotonic counter fencing each renderer dispatch
from late writes by an earlier one. Renderers mutate `app.findings` and
`app.currentResult` **in place**, so without it a hung renderer past the
watchdog paints over a fallback view's state.

```
App._loadFile / _restoreNavFrame / _clearFile
        │
        ▼
App._setRenderResult(result)        ← THE ONLY epoch++ site
   ++_renderEpoch
   swap currentResult
        │
        ▼
RenderRoute.run(file, buf, app, null, epoch)
   │  ParserWatchdog.run({timeout, name})
   │    ↓ parks AbortSignal on _activeSignal
   │  renderer.render(file, buf, app)
   │    ↓ throwIfAborted() in outer loops
   ├── resolves ── epoch === app._renderEpoch ?
   │                  yes → Object.freeze(findings); stamp final RenderResult
   │                  no  → return { _superseded: true }; _loadFile early-returns
   └── AbortError / timeout / thrown error
            ↓
       RenderRoute._orphanInFlight(app, buf)
         freeze old findings
         swap fresh findings + currentResult
         (epoch NOT bumped)        ← critical: never bump here (06cbb04)
            ↓
       fall back to PlainTextRenderer
```

**Why `_orphanInFlight` must NOT bump the epoch:** the entry of `run()`
captures `epoch == app._renderEpoch` and the end-of-run guard compares
`epoch !== app._renderEpoch`. If `_orphanInFlight` also bumped the counter,
the captured local epoch would no longer match → guard would fire →
`run()` would return `{ _superseded: true }` → `_loadFile` would
early-return → blank page on every fallback. Ship-stopper bug from
`06cbb04` (Phase-1/C3); see also caller-owned epoch + worker-channel
cancellation cleanup in `58b6778`.

**Worker-driven renderers** must capture `_renderEpoch` at job-dispatch
time and discard any `onmessage` payload whose captured epoch differs from
the live one.

---

## Renderer skeleton — the canonical shape

```js
// src/renderers/foo-renderer.js
class FooRenderer {
  // RenderRoute.run() has already:
  //   • bumped app._renderEpoch via App._setRenderResult
  //   • wrapped this dispatch in ParserWatchdog (RENDERER_TIMEOUT_MS, 30 s)
  //   • stamped app.currentResult.{docEl, findings, rawText, buffer, binary,
  //     yaraBuffer, navTitle, analyzer, dispatchId} BEFORE this runs
  //   • lf-normalised any returned `rawText` once
  static render(file, arrayBuffer, app /* , opts */) {
    const docEl = document.createElement('div');
    docEl.className = 'foo-view';

    // ── 1. Build the view ─────────────────────────────────────
    // Emit a `.plaintext-table` (one <tr> per line, a `.plaintext-code`
    // cell) for free char-level highlight + 5 s auto-clear.
    const rawText = /* … decode + render … */ '';

    // ── 2. Mutate findings IN PLACE ───────────────────────────
    const findings = app.findings;
    // NEVER: findings.risk = 'high';  ← rejected by build gate.
    //         Risk is evidence-derived; escalateRisk() at the end.

    // ── 3. Push IOCs through pushIOC — type MUST be IOC.* ─────
    pushIOC(findings, {
      type:     IOC.URL,
      value:    'https://example.com/payload',
      severity: 'medium',                     // defaults to IOC_CANONICAL_SEVERITY[type]
      note:     'embedded link',
      // _noDomainSibling: true               // if you already emitted manual IOC.DOMAIN
    });

    // ── 4. Mirror Detections into externalRefs as IOC.PATTERN ─
    //    Otherwise the detection shows in the banner but is invisible to
    //    risk calc / Summary / Share / STIX / MISP.
    if (findings.detections?.length) {
      for (const d of findings.detections) {
        pushIOC(findings, {
          type:     IOC.PATTERN,
          value:    `${d.name} — ${d.description}`,
          severity: d.severity,
          bucket:   'externalRefs',
        });
      }
    }

    // ── 5. Mirror metadata pivots (NOT attribution fluff) ─────
    mirrorMetadataIOCs(findings, {
      sha256:    IOC.HASH_SHA256,
      machineId: IOC.PATTERN,
      // NOT: CompanyName / FileDescription / ProductName / SubjectName
    });

    // ── 6. Click-to-focus: container._rawText must be LF-normalised ─
    docEl._rawText = lfNormalize(rawText);

    // ── 7. Escalate risk evidence-driven ─────────────────────
    const highs   = findings.externalRefs.filter(r => r.severity === 'high').length;
    const hasCrit = findings.externalRefs.some(r => r.severity === 'critical');
    const hasMed  = findings.externalRefs.some(r => r.severity === 'medium');
    if      (hasCrit)    escalateRisk(findings, 'critical');
    else if (highs >= 2) escalateRisk(findings, 'high');
    else if (highs >= 1) escalateRisk(findings, 'medium');
    else if (hasMed)     escalateRisk(findings, 'low');

    // ── 8. Long outer loops MUST poll the AbortSignal amortised ─
    // for (let i = 0; i < N; i++) {
    //   if ((i & 0xFF) === 0) throwIfAborted(opts?.signal);
    //   …
    // }

    // ── 9. Optional: wire drill-down for archive / multi-stream renderers
    // this._wireInnerFileListener(docEl, file.name);

    // ── 10. Return shape: bare HTMLElement OR
    //     { docEl, findings?, rawText?, binary?, navTitle?, analyzer? }
    //     (RenderRoute.run normalises both.)
    return docEl;
  }
}
```

**Wire-up checklist when adding a new renderer:**
1. `src/renderers/foo-renderer.js` (file above).
2. Probe + class entry in `src/renderer-registry.js`.
3. Add to `JS_FILES` in `scripts/build.py` **after** `renderer-registry.js`,
   **before** `app-core.js`. Read the comments — order is load-bearing.
4. If extension-driven, add a route in `src/app/app-load.js`.
5. Viewer styles → `src/styles/viewers.css`.
6. Per-dispatch size cap → entry in
   `PARSER_LIMITS.MAX_FILE_BYTES_BY_DISPATCH` (`8aebf3b`). Falling through
   to `_DEFAULT` (128 MiB) is rarely correct.
7. Docs: row in `FEATURES.md § Supported Formats`. Headline-grade
   capability also in `README.md`.
8. If you depend on async work (e.g. `QrDecoder.decodeBlob`), make
   `analyzeForSecurity` `async` and `await Promise.all(...)` before
   returning — the sidebar snapshots `findings` when the call resolves.

---

## Worker / cancellation contract

- All workers spawned via `WorkerManager` (`src/worker-manager.js`); a build
  gate rejects `new Worker(` outside the allow-listed spawner / worker
  modules.
- Each spawn site try/catches `new Worker(blob:)` (Firefox at `file://`
  denies it) and falls back to a sync main-thread path on probe failure.
- Buffers transfer as `ArrayBuffer` — the worker takes ownership; the main
  thread loses access. Re-read from the original `File` if needed.
- `WORKER_TIMEOUT_MS = 5 min` (Timeline scales 30 min). On expiry,
  `terminate()` real-preempts the JS engine — the only true preemption
  available; main-thread watchdog can only kill the wrapping promise
  post-hoc.
- Stale `onmessage` payloads from terminated/superseded workers must be
  discarded by epoch capture (`58b6778`).
- Worker shims (`src/workers/*-worker-shim.js`) and worker bodies share
  the same constants; `scripts/check_shim_parity.py` is the gate. See
  `b00ada6` (missing `throwIfAborted` stub broke auto-scan), `97fffb2`
  (`row-store.js` must be in BOTH bundles), `7d4861d` (worker-shim
  `RENDER_LIMITS` parity).

---

## PARSER_LIMITS vs RENDER_LIMITS — the two-budget rule

| Constant family | Job | Raising it… |
|---|---|---|
| `PARSER_LIMITS.{MAX_DEPTH, MAX_UNCOMPRESSED, MAX_RATIO, MAX_ENTRIES, MAX_AGGREGATE_*, TIMEOUT_MS, RENDERER_TIMEOUT_MS, WORKER_TIMEOUT_MS, SYNC_YARA_FALLBACK_MAX_BYTES, MAX_FILE_BYTES_BY_DISPATCH, FINDER_MAX_INPUT_BYTES}` | **Safety envelope** — abort if breached. | weakens defences; needs `SECURITY.md` update. |
| `RENDER_LIMITS.{MAX_TEXT_LINES, MAX_CSV_ROWS, MAX_TIMELINE_ROWS, MAX_EVTX_EVENTS, ROWSTORE_HEAP_BUDGET_FRACTION}` | UI-display caps. | only affects completeness/memory. |

The aggregate archive budget (`MAX_AGGREGATE_ENTRIES = 50_000`,
`MAX_AGGREGATE_DECOMPRESSED_BYTES = 256 MiB`, see `369c8e9`) is reset
**only at top-level `_handleFiles`** — drill-downs share one budget so a
ZIP-of-JAR-of-MSIX-of-7z chain cannot expand unboundedly.

---

## Recurring pain-points / gotchas (with commit refs)

`git show <sha>` for full context on any line below. **If you fix a class
of bug not yet listed here, add a one-line entry with the fix's short-SHA
in the same PR.**

### Render-epoch & fallback (the most subtle area)
- `06cbb04` — `_orphanInFlight` must NOT bump `_renderEpoch`; bumping made
  every fallback look superseded → blank page (Phase-1/C3 ship-stopper).
- `58b6778` — caller-owned epoch + worker-channel cancellation cleanup;
  workers capture epoch at dispatch and discard stale `onmessage`.
- `eb46706` — clear copy-content cache, sidebar highlight timers, stale
  view refs on file-clear.
- `0c306aa` — `setRows` without rowSearchText must invalidate the cache.
- `a214f20` — Timeline auto-extract grid flash → use in-place column
  swap, never destroy/rebuild.
- `f7bfb2d` — null-guard cross-view highlight refs and clear on Timeline
  reload.
- `8aebf3b` — per-dispatch `PARSER_LIMITS.MAX_FILE_BYTES_BY_DISPATCH`
  enforcement; missing entry silently falls through to 128 MiB default.
- `ccfdc94` — worker-managed parser-watchdog (terminate-on-timeout
  preemption); main-thread watchdog can't interrupt a tight sync loop.

### YARA engine
- `94117e8` — ascii/wide string semantics + per-scan lowercase view cache.
- `0437e1f` — multi-line string-modifier capture in parser.
- `1388c1c` — three rules rewritten for bounded quantifiers (ReDoS).
- `b00ada6` — worker bundle missing `throwIfAborted` stub broke auto-scan
  silently.
- `484d23d` — byte offsets must be mapped through the actual scanned
  buffer.
- `3b72e4d` — keep long YARA values in their column + flush stale IOC
  rows.
- `413c618` — Pattern detections must not be mis-cast as IOCs / decoded
  payloads.
- `676fa1e` — format-aware rule gating via `applies_to` predicates;
  reduces FPs on irrelevant formats.
- `2061b82` — preserve regex literals when stripping comments in the YARA
  parser.

### Encoded recursion
- `6a83848` — recursively stamp chain prefix onto the entire
  `innerFindings` subtree.
- `17d1a72` — UTF-16LE PowerShell unwrap unblocked + breadcrumb dropdown.
- `0f71338` — per-finder budget + tightened backtick/rot13 patterns
  (catastrophic backtracking).
- `15cc44c` — class root + `decoders/*.js` mixins; helpers must not
  depend on each other's load order.
- `9107360` — JS string-array obfuscator resolver; loads after
  `cmd-obfuscation.js` in `_DETECTOR_FILES`.
- `3d3f8e6` — aggressive FP suppression across the finder pipeline.
- `6a71ee7` — split per-candidate `_patternIocs` from generic
  `_executeOutput` so only the CMD `for /f` branch attaches the
  `for /f … do call %X` pattern; ClickFix mirror migrated to the same
  mechanism.
- `<pending>` — bash / python / php deobfuscators added (six branches each)
  + JS additions (packer / aaencode / Function-wrapper); all flow through
  `_processCommandObfuscation`; min decoded length 2 (was 3) so `'sh'`
  shell-launch atoms aren't suppressed; `_EXEC_INTENT_RE` extended with
  cross-shell vocabulary so decoded payloads survive `_pruneFindings`.
- `25f2e66` — cap CMD deobfuscated expansion at 32× raw / 8 KiB across
  variable-concat, delayed-expansion, and `for /f` indirect branches;
  Jazzer found raw=6 → deobf=410 and raw=94 → deobf=6165 within seconds
  of the sancov-instrumentation fix.
- `25f2e66` — PS backtick-escape regex couldn't bridge `` `-` `` (split
  `i\`n\`v\`o\`k\`e\`-\`e\`x\`p\`r\`e\`s\`s\`i\`o\`n` into two halves
  that both failed the keyword gate); rewrote to allow backticks +
  digits anywhere in the token including around the hyphen.
- `25f2e66` — added PS `-replace` sentinel-strip branch (single `.replace`),
  empty-arg format operator (`'{0}iex{1}' -f '',''`), standalone
  `%KNOWN_ENV:~N,M%` slicer, bare `%COMSPEC%` resolver, single-bang
  delayed-expansion under `setlocal enabledelayedexpansion`.
- `<pending>` — `25f2e66` twin: the CMD single-bang `!VAR!` delayed-expansion
  branch was missing the 32×-raw / 8 KiB amp cap its `!%X%!…!%Z%!` sibling
  already had; Jazzer found raw=5 → deobf=507 (107×). Promoted to
  `tests/unit/obfuscation-cmd-obfuscation-fuzz-regress-3b5994363eb12ea0.test.js`.
- `0b37971` — BASH `${CMD:-default}` on unset var resolves to default;
  every other param-expansion op still requires populated `vars[name]`.
- `0b37971` — BASH partial Variable Concatenation emits with placeholder
  markers when `unresolved > 0 && resolved >= 2` — partiality IS the
  obfuscation signal; full-resolution case still requires SENSITIVE_BASH_KEYWORDS.
- `0b37971` — BASH `exec N<>/dev/tcp/…` third alternation for the
  compact bi-directional bind-to-fd reverse-shell primitive.
- `b088604` — Python `''.join(chr(x) for x in [N,N,…])` generator form
  + `[chr(i) for i in [N,N,…]]` list-comp form — P4 chr-join only
  matched the adjacency form before.
- `be98aa5` — `EncodedReassembler.mapReconToSource` splice-region width
  used `sourceLength` (encoded width) instead of `strippedLength`
  (decoded-body width); verbose obfuscation like `p^o^w^e^r^s^h^e^l^l`
  → `powershell` produced a phantom tail past the real splice end that
  swallowed subsequent sourceMap entries' recon offsets, returning the
  wrong `sourceOffset`. Production-unused export (only `mapStrippedToSource`
  is consumed by `src/app/app-load.js`), so never user-visible — caught
  on first replay of the new `obfuscation/reassembly` fuzz target with
  a multi-technique pair-concat seed. Promoted to
  `tests/unit/obfuscation-reassembly-fuzz-regress-a7b7de6aa63cf197.test.js`.
- `bc7d048` — tightened obfuscation fuzz invariant 64× → 32× (matching the
  CMD `_AMP_RATIO` peer branches already self-impose) surfaced five cross-shell
  amp blowups where candidate emission sites lacked the cap. Extracted a
  shared `_clipDeobfToAmpBudget(deobf, raw)` helper in `cmd-obfuscation.js`
  (32× raw / 8 KiB, with `… [truncated]` marker reserved inside the budget
  so clipped output never itself trips the invariant) and applied it at
  five sites: CMD `ClickFix Wrapper` (payload pulled from sibling
  candidate), CMD `Env Var Substring (inline)` (sliced substring of long
  `set X=…` value), PS `Variable Resolution` (`resolvedCmd + ' ' +
  resolvedArgs` against long `$a=…` tables), Bash `Variable Expansion
  (single)` (`${V:off}` slicing remainder of long assignment), and Bash
  `Variable Concatenation (partial)` (`${A}${B}${C}` joined against long
  values). Promoted to
  `tests/unit/obfuscation-{bash-obfuscation-fuzz-regress-780839c3269f6761,powershell-obfuscation-fuzz-regress-7ca34fabcbfc7172,cmd-obfuscation-fuzz-regress-3eccbcdc9620bc84,cmd-obfuscation-fuzz-regress-07c717a024bff004,bash-obfuscation-fuzz-regress-dafcdf82fa0849ca}.test.js`.
- `e8a64d7` — Phase 1 CMD/PS decoder fill: 8 new branches (PS `-EncodedCommand` / `[char]N` reassembly / `[Convert]::FromBase64String` / `-bxor` inline-key / `[scriptblock]::Create` / AMSI-bypass; CMD `set /a` ASCII + `call :label` indirection) all gated on `_EXEC_INTENT_RE` or `SENSITIVE_*_KEYWORDS` (no "≥N printable" fallback — flagged benign base64'd version strings); `call :label` body extraction must walk to the next non-empty line (multi-line `.bat` labels are the norm, inline bodies are the exception); all paths route through `_clipDeobfToAmpBudget`.
- `dcf6bca` — Phase 2 Bash decoder fill: 4 new branches (B7 `echo -e` hex/octal escape chain, B8 `${!pointer}` two-hop indirect expansion, B9 inline `awk`/`perl`/`python{,3}`/`ruby`/`node`/`php` executors with post-decode exec-intent gate, B10 `tr` rot13 here-string); all gated on `SENSITIVE_BASH_KEYWORDS` or interpreter-specific exec vocabulary; `awk` inline form uses bare positional arg (no flag) so `interpRe` anchor accepts `\s+-[ercR]|\s+` — a separate `'BEGIN\{` anchor collided with the body's opening quote and never matched; `tr` only resolves the canonical rot13 set pairs (`A-Za-z`↔`N-ZA-Mn-za-m`, `a-zA-Z`↔`n-za-mN-ZA-M`) — arbitrary translate sets are unsound without a real tr(1) engine.

### IOC plumbing
- `dfc594c` — replace bespoke type literals with `IOC.*` constants
  (canonical migration).
- `b632626` — audit follow-up: `pushIOC` convention sweep.
- `1fadc6b` — IOC push checklist + canonical severity floor per type.
- `b685985` — Zip Slip / Tar Slip per-entry IOCs (CWE-22 / T1140).
- `992f83d` — crypto-address, secret-leak, IPv6 parity, Trojan Source.
- `1a0c330` — suppress low-confidence IP IOCs and DER-artifact URLs in
  binary strings.
- `986ff7a` — preserve 4-digit DNS IPs (8.8.8.8 / 1.1.1.1) in
  version-string filter.
- `6c0b024` — migrate plist / osascript / x509 IOC pushes to `pushIOC()`.

### Native-binary FPs (PE / ELF / Mach-O)
- `02b1592` — trust-tier + `binaryClass` gating to cut native-binary FPs.
- `3ab47db` — cut ELF/PE false-positive critical band on benign system
  tools.
- `5516ee3` — resource-only DLL packing-risk FP.
- `22a03d0` / `0b99a4c` — verdict reasons audit trail; drop dead reasons
  panel after dual-verdict contradiction.
- `<pending>` — pin `currentResult.yaraBuffer = buffer` in `pe()` /
  `elf()` / `macho()` routes (mirror `wasm()` / `pcap()`); without it
  YARA scans the renderer's `_rawText` extracted-strings list and
  every `uint16(0)==0x5A4D` magic gate fails, silently inerting ~70
  threat rules.
- `<pending>` — tighten 4 PE rules + gate `Confusable_Codepoint_Density`
  with `applies_to = !is_native_binary` so the yaraBuffer pin doesn't
  surface noise. `signed-example.{exe,dll}` are TPs not FPs (genuine
  UPX-pack / anti-debug+service-install+HTTP imports).


### Timeline route (highest churn area)
- `2487fe4` — parallelised e2e + Timeline state-leak fix; cross-load
  reset must clear `_extractedCols`, `_skipTimelineRoute`, etc.
- `9b10618` — align `_evtxEvents` to truncated row count on sync EVTX
  path.
- `a76eaae` — auto-extract is **ephemeral**; only Regex-tab extracts
  persist via `loupe_timeline_regex_extracts`.
- `d2a5d2a` — split GeoIP done-marker from auto-extract marker.
- `237eb7d` — preserve JSON auto-extracts across reopens; tighten
  text-host detection.
- `f656a09` — query popover must not render off-screen at caret column 0.
- `062c0d3` — history dropdown must not nuke the undo ring.
- `bc63eb8` — escape backslash in `CSS.escape` fallback selector.
- `22d8647` — RFC-4180 quote-aware CSV parser shared across all CSV/TSV
  paths.
- `4425400` — NOT IN filter for column filter on truncated sets with
  all-pass baseline.

### Archive / parser safety
- `369c8e9` — aggregate decompression budget across nested drill-down
  (50k entries / 256 MiB); reset only at top-level `_handleFiles`.
- `b291e2c` — `MAX_UNCOMPRESSED` 50 → 256 MB (modern .ipa/.appx
  legitimate).
- `fc0f1bd` — detect ZIP encryption via central-dir walk, not first
  local header.
- `7a4a169` — cap PCAPNG block walk to bound non-packet padding.
- `0d59b15` — anchor PK magic at file offset 0 in archive YARA rules.

### Regex safety (ReDoS)
- `42320f9` — regex-safety + worker-shim-parity build gates.
- `ffd265e` — `safeRegex / safeExec / safeTest / safeMatchAll` harness.
- `9f379f2` — bound nested quantifiers in path / UNC / domain regexes.
- `cc01dda` — bound scan windows + document sync-decode invariants.
- `f9413e2` — Timeline DSL filters and regex-extract route through
  `safeRegex`.
- `3457a09` — YARA editor rule import routes through `safeRegex`.
- `ecf78ae` — inline `safeRegex` helpers into worker shims (parity).
- `716d532` — bound `invisRe` to `\w{2,64}` + route every IOC `matchAll` through `safeMatchAll`; unbounded `\w{2,}` froze main thread for ~7 s on 165 KB single-line `.ps1`.

### Parser perf
- `81d5d0a` — memoise "next quote index" inside `CsvRenderer.parseChunk` so a quote-free CSV no longer rescans to EOF on every row; a 2 MB plain CSV dropped 383 → 14 ms, 10 MB one 472 → 4 ms on Node 24. Invariant: invalidate the memo (`nextQuoteIdx = -1`) whenever we consume a quote (open, close, `""` escape); do NOT consult it inside the `inQuotes` branch (every tick invalidates anyway, cache would thrash).
- `a87be39` — reuse a single `TextDecoder('utf-8', { fatal: false })` for all TEXT cell reads in `SqliteRenderer._readValue`; per-cell `new TextDecoder()` cost dominated small-cell workloads (example.sqlite 13.77 → 8.41 ms, −39 %). Decoder is instance-level (lazy-init), not class-static, so reentrant concurrent parses each get their own decoder.
- `9a0d2fb` — route EVTX `_readUtf16` strings > 32 code units through a shared lazy-init `TextDecoder('utf-16le', { fatal: false })`. Old `String.fromCharCode(...chars)` spread path crashed with "Maximum call stack size exceeded" between 125 k and 200 k args on V8 — reachable via a BinXml record's uint16 length prefix (records cap at 64 KB ≈ 32 k UTF-16 chars) and trivially via a corrupt EVTX. Short strings (≤32, the 99 % case: element / attribute names) keep the `String.fromCharCode.apply(null, chars)` fast-path byte-for-byte — concat variants were ~7× slower. Deliberate behaviour change: `fatal: false` turns malformed UTF-16 into `U+FFFD` rather than emitting lone surrogates that trip `JSON.stringify`.
- `93839b2` — fold EVTX Data.Name ↔ Data-text pairing in `_applyTemplate` and `_extractNestedEventData` from nested O(N × M) loops into a single monotonic forward cursor (O(N + M)). `_applyTemplate`: walk `dataNames` once, advance `dataTexts` cursor past indices `≤ dn.index`, record consumption in a `Uint8Array`, emit unpaired in template order. `_extractNestedEventData`: single scan with a `pendingName` slot; on consecutive Data.Name the earlier is dropped (matches old break-without-push); buffer unpaired Data-texts to flush after the walk to preserve the old Pass-1-then-Pass-2 output ordering. Semantic-equivalence pin: stable SHA-256 over `(eventId, channel, computer, provider, eventData)` on `examples/forensics/example-security.evtx`. example-security.evtx 5.03 → 4.16 ms (−17 %); saving scales with Data-field count per event (Sysmon / Security-log events with 20-40 Data fields benefit most).

### Build determinism / load order
- `8e4735a` — backtick-comment-terminator build gate.
- `0efb4cd` — block-comment YARA category sentinel + missing-category
  guard.
- `97fffb2` — `row-store.js` must be in BOTH main and worker bundles.
- `7d4861d` — assert worker-shim `RENDER_LIMITS` constants match
  canonical.
- `9bc2646` — strip `sourceMappingURL` from tldts; remove
  `frame-ancestors` CSP.
- `7ab62b7` — `lfNormalize()` helper + `_rawText` LF-normalisation build
  gate.
- `6c9f2b1` — `safeStorage` wrapper + migration; `extendApp` collision
  guard.
- `<pending>` — vendored highlight.js "Common" bundle never registered `powershell` / `dos` / `vbscript` despite FEATURES.md + LANG_MAP claiming them; appended eight upstream per-language IIFEs (`powershell, dos, vbscript, dockerfile, nginx, apache, x86asm, properties`) onto `vendor/highlight.min.js` + added `tests/unit/highlight-bundle.test.js` parity gate.

### Drag-drop & ingress
- `e937d32` — drag-and-drop files were captured by iframe → use
  `loupe-drop` `CustomEvent` re-dispatch.
- `e76ba0e` — defer vendor compile, add early drag-drop bootstrap,
  idle-init `BgCanvas`.
- `3b4aa78` — hosted-mode privacy bar; external-file drag gating.

### State leak & cleanup
- `eb46706` — clear copy-content cache, sidebar highlight timers, stale
  view refs on file-clear.
- `0c306aa` — invalidate `rowSearchText` cache when `setRows` omits it.
- `f030863` — clipboard + undo + drawer search + theming bug-fixes.
- `1c1d0ad` — snapshot clipboard `DataTransfer` on paste before
  invalidation.

### Worker-manager / lifecycle
- `2536d00` — `_reportNonFatal` helper + silent-catch gate; pdf.worker
  lifecycle.
- `88b011c` — stream CSV/TSV rows from worker; bump
  `WORKER_TIMEOUT_MS` to 5 min.

### Test suite gotchas
- `2487fe4` — tests must tolerate prior-load state because of
  `useSharedBundlePage`; UI specs use `beforeEach(gotoBundle)` for a
  virgin DOM.
- `8b2ee07` — pin schema assertions to immutable base columns
  (auto-extract is ephemeral).
- `075046f` — wait for grid paint before reading `_extra` cell text in
  Timeline e2e.
- `e8ab1b1` — permanent unit coverage for engine, rule perf, and regex
  shapes.
- `<pending>` — fuzz coverage aggregator must paint covered/uncovered
  per-process then union COVERED-wins-over-UNCOVERED across processes;
  inverted order produces 100% coverage everywhere.
- `4fc090a` — Jazzer.js v4 sancov instrumentation fires via
  `hookRequire` — `vm.runInContext` silently bypasses it, reducing
  coverage-guided fuzzing to blind random mutation (`corp: 1/1b`,
  `new_units_added: 0`). Added `loadModulesAsRequire` that emits a
  CommonJS bundle to `dist/fuzz-bundles/src/bundle-<hash>.js` (the
  `src/` segment is load-bearing — Jazzer's `--includes src/` is a
  plain substring match). Dropped `--excludes dist/` in bootstrap.

---

## Persistence keys & state

- All `localStorage` keys use the **`loupe_`** prefix. Canonical table is
  in `CONTRIBUTING.md § Persistence Keys` (45+ keys, last source of
  truth).
- New key MUST add a row to that table in the same PR.
- Reads must validate against documented values with a hard-coded default
  fallback.
- Timeline ↺ Reset wipes every `loupe_timeline_*` key + drawer width +
  `loupe_grid_colW_tl-grid-inner_*` overrides; new `loupe_timeline_*`
  keys are auto-covered by the prefix sweep.
- `loupe_timeline_*` keys are scoped by `fileKey =
  name|size|lastModified` — schema-level state (column order, pinned,
  regex extracts) survives reload.
- IndexedDB: only `loupe-geoip` (geo + asn slots, capped 256 MB each);
  v1→v2 migration moves the legacy `mmdb` key into the geo slot. Each
  new IDB store needs a `src/<feature>/<feature>-store.js` accessor and
  a row in `CONTRIBUTING.md`'s IndexedDB Stores table.

---

## PR / commit hygiene

- Stage source / test / script / doc edits as needed. Never stage build
  artefacts (see [Repository map](#repository-map)). `git status` should
  show **no** `docs/` or `dist/` paths.
- Run `python make.py` locally before pushing. If you touched a renderer
  also run at least `python make.py test-unit`; for renderer logic
  changes also run `python make.py test-e2e`.
- Conventional-commit-ish style this repo uses: `feat(area):`,
  `fix(area):`, `perf(area):`, `refactor(area):`, `test(area):`,
  `docs(area):`, `chore(area):`, `build(area):`, `ci(area):`.
- Update `FEATURES.md` + `README.md` in lockstep with user-visible
  behaviour; `SECURITY.md` for any CSP / parser-limit / sandbox-flag
  change; `VENDORED.md` in the **same commit** as any vendor change
  (CI `verify-vendored` will fail otherwise).
- Match existing doc voice: one sentence per row in `FEATURES.md`;
  longer rationale belongs in code comments or `CONTRIBUTING.md`.
- Vanilla JS by design — no frameworks, no bundlers (beyond
  `scripts/build.py`), no `npm install` for runtime, no new vendored
  libs without SHA-256 + `VENDORED.md` row.
- License is **MPL-2.0**; do not introduce GPL / LGPL / proprietary
  deps.
- Doc-only commits skip CI (`paths-ignore: '**/*.md', LICENSE`); use
  `gh workflow run ci.yml --ref main` if you need to force a Pages
  deploy after a doc-only edit.

---

## Common agent mistakes

Each line is a real regression. Audit your diff before opening a PR.
(Items already covered by [The 12 hard invariants](#the-12-hard-invariants)
are not repeated here.)

- **Forgetting `await Promise.all(...)`** in an `async analyzeForSecurity()`
  that uses `QrDecoder.decodeBlob()` → sidebar snapshots empty findings.
- **`datetime.now()` / `os.walk` / random IDs / unsorted set iteration**
  in `scripts/build.py` → breaks reproducible build.
- **Reordering `JS_FILES` / `CSS_FILES` / `YARA_FILES` / `_DETECTOR_FILES`**
  without reading `scripts/build.py` comments → silent override drift.
- **Adding a new dispatch id without `MAX_FILE_BYTES_BY_DISPATCH[id]`** →
  silent fall-through to 128 MiB default (`8aebf3b`).
- **Forgetting to mirror `Detection`s into `externalRefs` as `IOC.PATTERN`**
  → invisible to risk calc, Summary, STIX, MISP.
- **Forgetting `_noDomainSibling: true`** on a URL push that already
  emitted a manual domain → duplicate `IOC.DOMAIN` in sidebar.
- **Treating Timeline auto-extracted columns as persistent** — they are
  ephemeral; only Regex-tab extracts persist (`a76eaae`, `8b2ee07`).
- **Tests that mutate App state outside the file-load pipeline** —
  shared-bundle page reuses across tests; cross-load reset only clears
  the documented set (`_testApiResetCrossLoadState` in `app-test-api.js`).
- **Bumping a vendor file without rotating its SHA-256 in `VENDORED.md`
  in the same commit** → CI `verify-vendored` fails.

---

## Quick agent reminders

```text
fff_grep "pushIOC"              ← canonical IOC push sites
fff_grep "_setRenderResult"     ← the only epoch++ site
fff_grep "throwIfAborted"       ← cooperative-cancel call sites
fff_grep "_reportNonFatal"      ← non-fatal error reporting
fff_find_files "renderer.js"    ← every renderer module
git show <sha>                  ← context for any pain-point SHA above
git log --oneline --grep=<area> ← scoped history
```

**Mantras:**
- If you read `CONTRIBUTING.md § Renderer Contract` before opening a PR,
  you save the reviewer 50% of comments.
- If a renderer-level change doesn't touch tests, ask why.
- If you're adding a `localStorage` key, you owe a Persistence-Keys row.
- Reproducible build means `SOURCE_DATE_EPOCH` only — no other time
  bytes, no `datetime.now()`, no random IDs.
- **If this file taught you something out-of-date, fix it.** Update
  `AGENTS.md` in the same PR that introduces the change. The next
  agent will thank you.

---

## Further reading (in order of usefulness to an agent)

- `CONTRIBUTING.md` — Footguns Cheat-Sheet, Renderer Contract, IOC Push
  Helpers & Checklist, Persistence Keys table, Adding things recipes.
- `SECURITY.md` — threat model, full CSP, parser-limit table,
  reproducible-build recipe.
