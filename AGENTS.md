# AGENTS.md — Loupe

> Operating guide for AI/automation agents working in this repository.
> Keep it dense and action-oriented. `CONTRIBUTING.md` is authoritative when
> docs conflict; update this file in the same PR when behaviour, gates, or
> build steps change.

Loupe is a **single-file, 100% offline** browser-based static security
analyser. The shipped product is one HTML file (`docs/index.html` →
`loupe.html` at release time) opened over `file://` or served from any
static host; there is no backend, no module loader, no network at runtime.

**Authoritative sources:** `AGENTS.md` for agent workflow,
`CONTRIBUTING.md` for developer details, `SECURITY.md` for threat model / CSP /
limits, `FEATURES.md` for format capabilities, and `tests/README.md` for test
API + Playwright provisioning.

**Agents must…**
- Use the **fff** MCP tools (`fff_find_files`, `fff_grep`, `fff_multi_grep`)
  for all in-repo file/content search instead of default tools.
- **Never** stage build artefacts: `docs/index.html`,
  `docs/index.test.html`, `dist/`, `loupe.html*`, `playwright-report/`,
  `test-results/`, `.opencode/`, `.agents/`.
- Stage source / test / script / doc edits as needed. Vendor changes require a
  same-commit `VENDORED.md` hash update.
- **Keep this file lean.**

---

## Repository map

```text
src/
  app/                 App.prototype mixins; `scripts/build.py` load order matters.
  app/timeline/        Timeline route; bypasses normal renderer/finding pipeline. Merged-source registry (mapper, composite store, chip bar) enables multi-file coalescing.
  renderers/           Static `render(file, buf, app)` classes plus helpers.
  decoders/            EncodedContentDetector mixins via `_DETECTOR_FILES`.
  workers/             YARA / encoded / timeline / IOC extract bodies + shims.
  geoip/               IDB store, mmdb reader, bundled IPv4 country DB.
  rules/*.yar          Comment-free YARA rule packs with strict meta whitelist.
  styles/              Core, viewer, and theme CSS.
  constants.js         PARSER_LIMITS, RENDER_LIMITS, IOC.*, pushIOC, safeRegex,
                       lfNormalize, throwIfAborted, EVTX_COLUMNS.
  render-route.js      Dispatch wrapper, watchdog, epoch fence, plaintext fallback.
  renderer-registry.js Probe → renderer-class map.
  worker-manager.js    Sole Worker(blob:) spawner.
  sandbox-preview.js   Single HTML/SVG sandbox-iframe factory.
  file-download.js     Single blob-download helper.
  archive-budget.js    Nested aggregate archive budget.

scripts/               Build, gates, tests, fuzz/perf runners; `make.py` fronts them.
tests/                 Unit, e2e, perf, fuzz, helpers, fixture snapshots.
vendor/                Pinned third-party libs; hashes in `VENDORED.md`.
examples/              Fixture corpus.
.github/workflows/     ci, release, codeql, scorecard, refresh-geoip.
docs/index.html        BUILD ARTEFACT (gitignored). Never commit.
docs/index.test.html   TEST BUILD ARTEFACT (gitignored). Never commit.
dist/                  SBOM, perf reports, test deps. Gitignored.
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
python make.py contract                 # static renderer-contract check
python make.py sbom                     # opt-in; release-time only
python make.py perf                     # opt-in; writes dist/perf-report.{json,md}
python make.py fuzz                     # opt-in; Jazzer.js over tests/fuzz/targets/

# Test pipeline (opt-in; never blocks the default loop)
python make.py test                     # test-build → test-unit → test-e2e
python make.py test-build               # build docs/index.test.html with --test-api
python make.py test-unit                # node:test over tests/unit/
python make.py test-e2e                 # Playwright e2e-fixtures + e2e-ui
python scripts/run_tests_e2e.py --grep "phishing"
python scripts/run_tests_e2e.py tests/e2e-fixtures/email.spec.ts

# Perf / fuzz / fixtures
LOUPE_PERF=1 python scripts/run_perf.py --rows 10000 --runs 1
python scripts/run_fuzz.py --replay --quick
python scripts/run_fuzz.py --time 300 text/ioc-extract
python scripts/fuzz_promote.py <target> <crash-dir>
python scripts/run_fuzz.py --coverage --replay --quick
LOUPE_EXPLORE=1 python scripts/run_tests_e2e.py tests/explore/dump-fixtures.spec.ts
python scripts/gen_expected.py
python scripts/gen_yara_coverage.py
npx --yes eslint@9.39.4 --config eslint.config.mjs "src/**/*.js"
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
| `lint` | ESLint **9.39.4** (pinned) over `src/**/*.js`; minimal config, not a style enforcer. |
| `unit` | `python make.py test-unit` (Node 24, `node:test`, `vm.Context`). |
| `e2e` | Builds `docs/index.test.html` inline with `--test-api`; caches `@playwright/test` + Chromium browsers keyed by `PLAYWRIGHT_VERSION`. |
| `deploy-pages` | **Only on `main`**, after build + verify-vendored + static-checks + lint + yara-lint pass. |

All third-party Actions are pinned by full 40-char commit SHA; Dependabot rotates them weekly.

---

## Architecture TL;DR

- `src/` is concatenated into one inline `<script>` inside `docs/index.html` by `scripts/build.py`. No bundler, modules, runtime network, `eval`, or `new Function`.
- `App` is one class extended by `src/app/app-*.js` via `Object.assign(App.prototype, {...})`; `JS_FILES` order is load-bearing.
- Ingress: drop / picker / iframe `loupe-drop` → `App._handleFiles` → `_loadFile` → Timeline bypass or `RenderRoute.run` → renderer → sidebar → auto-YARA.
- Drill-down uses bubbling `open-inner-file` → `App.openInnerFile` (push nav frame, re-enter `_loadFile`; unified in `22d1df1`).
- Timeline CSV / TSV / EVTX / PCAP / SQLite / structured logs bypass normal findings/IOC/encoded recursion. EVTX and PCAP run analyzer side-channels for Summarize.
- Timeline can hold ≥1 "sources". A single-file load carries `_sources=null` and takes the legacy single-file path; dropping additional CSV/TSV/EVTX/structured-log files on top triggers `_timelineAddFile`, which builds a composite RowStore prefixed with `TIMELINE_CANONICAL_COLS` (the 9-entry trimmed schema: `__source`, `Timestamp`, `Host`, `User`, `EventID`, `Severity`, `Category`, `SourceIP`, `DestIP` — short identifier-shape values only, no `Process` / `Message` / `__format` slots; wide-narrative columns stay on each source's native plane, and format identity is conveyed by the source filename plus the per-chip format badge in the source-bar) and a `_sources` / `_sourceOfRow` / `_sourceEnabledBitmap` registry. Per-format projection lives in `src/app/timeline/timeline-mapper.js`; composite build in `src/app/timeline/timeline-composite.js`. Per-source colour (chip swatch, breadcrumb dot, `__source` cell tint) is derived from CURRENT array position via `timelineSourceColor(idx)` so all surfaces always share a hue and reshuffle in lockstep on add/remove. PCAP and SQLite are merge-INELIGIBLE (scope decision — their side-channels don't aggregate cleanly). Composite persistence is session-only (`TIMELINE_COMPOSITE_KEY_PREFIX`); per-source `_fileKey`s still work for solo reopen.
- Renderers mutate `app.findings` and `app.currentResult` in place, fenced by render-epoch.

---

## The hard invariants

1. **No `eval` / `new Function` / network.** CSP rejects them; do not relax.
2. **Never commit `docs/index.html`, `docs/index.test.html`, `dist/`, `loupe.html*`, reports, or test results.** CI/release/test runs produce them.
3. **`IOC.*` constants only**; never bare strings like `'url'` / `'ip'`.
4. **`pushIOC()` only**; never raw `findings.interestingStrings.push(...)`. Use `_noDomainSibling: true` if manually emitting a URL's domain.
5. **`escalateRisk(findings, tier)` only.** Never write `findings.risk = ...`; final risk is evidence-derived from `externalRefs`.
6. **`container._rawText = lfNormalize(...)`** always (`7ab62b7`), or click-to-focus offsets drift after CR.
7. **`safeRegex(...)` for user-input regex** (`ffd265e`). Other `new RegExp(...)` needs `/* safeRegex: builtin */` within 3 lines.
8. **No comments in `.yar` files**; meta key order is `description, severity, category, mitre, applies_to`.
9. **All `localStorage` keys use `loupe_` prefix** and must be documented in `CONTRIBUTING.md § Persistence Keys`.
10. **Workers spawn only via `WorkerManager`; downloads via `FileDownload.*`; sandbox iframes via `SandboxPreview.create()`.**
11. **No silent `catch{}` in load chain**; use `App._reportNonFatal(where, err, opts?)`. Escape hatch: `// loupe-allow:silent-catch`.
12. **Renderers must finish under `RENDERER_TIMEOUT_MS` (30 s).** Long loops poll `throwIfAborted(opts?.signal)` amortised, not per-byte.

---

## Render-epoch contract

`App._setRenderResult(result)` is the **only** epoch++ site. `RenderRoute.run(file, buf, app, null, epoch)` captures the caller-owned epoch and checks it before final writes.

`RenderRoute._orphanInFlight(app, buf)` must **not** bump `_renderEpoch`: bumping inside fallback makes the same dispatch look superseded, so `_loadFile` early-returns and fallback paints blank (`06cbb04`; worker-channel cleanup in `58b6778`).

Worker-driven renderers must capture `_renderEpoch` at job dispatch and discard `onmessage` payloads whose captured epoch differs from the live one.

---

## Renderer skeleton

```js
class FooRenderer {
  static render(file, arrayBuffer, app /* , opts */) {
    const docEl = document.createElement('div');
    const rawText = '';
    const findings = app.findings; // mutate in place
    pushIOC(findings, { type: IOC.URL, value: 'https://example.invalid/' });
    docEl._rawText = lfNormalize(rawText);
    return docEl; // or { docEl, findings?, rawText?, binary?, navTitle?, analyzer? }
  }
}
```

Full skeleton details live in `CONTRIBUTING.md § Renderer Contract` (detection mirrors, metadata pivots, evidence-derived risk, cancellation polling, drill-down wiring).

**Wire-up checklist:** renderer file; probe + class in `renderer-registry.js`; add to `JS_FILES` after registry and before `app-core.js`; extension route in `app-load.js` if needed; viewer CSS; `PARSER_LIMITS.MAX_FILE_BYTES_BY_DISPATCH` entry; docs in `FEATURES.md` + `README.md`; async analyzers must await all work before returning.

---

## Workers, limits, and storage

- Spawn workers only via `WorkerManager`; try/catch `new Worker(blob:)` and provide sync fallback for Firefox `file://` denial.
- Transfer buffers as `ArrayBuffer`; the worker takes ownership, so re-read from original `File` if needed.
- `WORKER_TIMEOUT_MS = 5 min` (Timeline scales 30 min); `terminate()` is the only real JS preemption.
- Worker shims and bodies must mirror canonical constants; `scripts/check_shim_parity.py` covers `throwIfAborted`, `row-store.js`, and `RENDER_LIMITS` parity (`b00ada6`, `97fffb2`, `7d4861d`).
- `PARSER_LIMITS` is the safety envelope; raising it weakens defenses and needs `SECURITY.md`.
- `RENDER_LIMITS` is UI display cap only; raising it affects completeness/memory.
- Aggregate archive budget is 50k entries / 256 MiB and resets only at top-level `_handleFiles` (`369c8e9`).
- `loupe_timeline_*` keys are scoped by `name|size|lastModified`; Timeline Reset wipes all `loupe_timeline_*` plus drawer/grid-width overrides.
- IndexedDB is only `loupe-geoip`; new stores need a `src/<feature>/<feature>-store.js` accessor and `CONTRIBUTING.md` row.

---

## PR / commit hygiene

- Run `python make.py` locally before pushing. Renderer changes should also run `python make.py test-unit`; renderer logic changes should run `python make.py test-e2e`.
- Commit style: `feat(area):`, `fix(area):`, `perf(area):`, `refactor(area):`, `test(area):`, `docs(area):`, `chore(area):`, `build(area):`, `ci(area):`.
- User-visible behaviour changes update `FEATURES.md` + `README.md`; CSP / parser-limit / sandbox changes update `SECURITY.md`; vendor changes update `VENDORED.md`.
- License is **MPL-2.0**; do not introduce GPL / LGPL / proprietary deps.
- Doc-only commits skip CI (`paths-ignore: '**/*.md', LICENSE`); use `gh workflow run ci.yml --ref main` to force Pages deploy after doc-only edits.

### Docs reflect the live state

Loupe is in development. There are no shipped users, no upgrade paths, no migration windows, no deprecation cycles. **Documentation describes what the code does today** — drop "previously…", "was…", "in earlier versions…", "for backwards compatibility…", "Commit X retired…" framing whenever you find it. If a feature is gone, the docs simply describe the current shape; if a constant changed, the docs name the current value. Refresh docs in the same commit as the code change so the two never drift. Source-comment headers describing per-module rationale follow the same rule: explain why the current design is correct, not why some prior design was wrong.

---

## Common agent mistakes

- Forgetting `await Promise.all(...)` in async analyzers using `QrDecoder.decodeBlob()` → sidebar snapshots empty findings.
- `datetime.now()` / `os.walk` / random IDs / unsorted sets in `scripts/build.py` → non-reproducible build.
- Reordering `JS_FILES` / `CSS_FILES` / `YARA_FILES` / `_DETECTOR_FILES` without reading comments → silent override drift.
- Adding a dispatch id without `MAX_FILE_BYTES_BY_DISPATCH[id]` → 128 MiB `_DEFAULT` fall-through.
- Forgetting to mirror Detections into `externalRefs` as `IOC.PATTERN` → invisible to risk calc, Summary, STIX, MISP.
- Forgetting `_noDomainSibling: true` on a URL push that already emitted a manual domain → duplicate domain IOC.
- Emitting `IOC.HOSTNAME` for a value that parses as a registrable domain — use `IOC.DOMAIN`. `IOC.HOSTNAME` is for structured-source host references (cert Subject CN, EVTX machine name, LNK TrackerDataBlock machineID, plist machine ID) where the bare host is the primary artefact, not a URL pivot. The `dedupeHostPivots(findings)` helper (runs at the end of `App._loadFile`) collapses HOSTNAME rows that overlap URL / DOMAIN coverage, but it's a safety net — emit the right type to start with.
- Emitting IOCs via bare `findings.interestingStrings.push({...})` / `findings.externalRefs.push({...})` instead of `pushIOC(findings, {type, value, severity, bucket?})`. Bare pushes skip auto-sibling emission (URL → DOMAIN / punycode / abuse-suffix), skip wire-shape validation, and diverge in field naming (`url:` vs `value:`). See `PLAN-pushIOC-compliance.md` for the ongoing migration scope and the staged build gate.
- Routing encoded-content IOCs manually instead of calling `this._mergeEncodedFindingIocs(ef, analysisText)` in `App._loadFile`. The helper owns cross-bucket dedupe, monotonic severity escalation, technique-scoped note stamping, and back-reference wiring for cross-flash UI.
- Emitting IOCs derived from partially-resolved decoder cleartext without running `hasUnresolvedSentinel(value)` first. AppleScript / cmd / bash obfuscation decoders embed `⟨unresolved:NAME⟩`, `⟨VAR:~start,length⟩`, and `⟨…⟩` placeholders (U+27E8 / U+27E9) for operands the resolver couldn't fill. These are load-bearing in the Deobfuscation viewer but must be filtered before any `pushIOC` / `_patternIocs` / `_dynamicFetchUrls` emission — a URL like `https://⟨unresolved:__iunw9unf⟩/` is not a real pivot. `hasUnresolvedSentinel` (constants.js) is the canonical gate; `_mergeEncodedFindingIocs` and `_extractIOCsFromDecoded` run it as the last-line defence.
- Treating Timeline auto-extracted columns as persistent; only Regex-tab extracts persist.
- Mutating App state outside the file-load pipeline in tests; shared-bundle pages reuse state.
- Bumping a vendor file without rotating its SHA-256 in `VENDORED.md` in the same commit.

---

## Quick reminders

```text
fff_grep "pushIOC"              ← canonical IOC push sites
fff_grep "_setRenderResult"     ← the only epoch++ site
fff_grep "throwIfAborted"       ← cooperative-cancel call sites
fff_grep "_reportNonFatal"      ← non-fatal error reporting
fff_find_files "renderer.js"    ← every renderer module
git log --oneline --grep=<area> ← scoped history
```

---

## Further reading

- `CONTRIBUTING.md` — Footguns Cheat-Sheet, Renderer Contract, IOC Push Helpers & Checklist, Persistence Keys table, Adding things recipes.
- `SECURITY.md` — threat model, full CSP, parser-limit table, reproducible-build recipe.
