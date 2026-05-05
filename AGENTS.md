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
- **Keep this file lean.** New gotchas go under
  [Recurring pain-points](#recurring-pain-points--gotchas-with-commit-refs) as
  **one line** with the fix's short-SHA; put detail in the commit message or
  `CONTRIBUTING.md`.

---

## Repository map

```text
src/
  app/                 App.prototype mixins; `scripts/build.py` load order matters.
  app/timeline/        Timeline route; bypasses normal renderer/finding pipeline.
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

## Recurring pain-points / gotchas (with commit refs)

`git show <sha>` for detail. New entries: one line, short-SHA, no incident narrative.

### Render-epoch & fallback
- `06cbb04` — `_orphanInFlight` must not bump `_renderEpoch`; doing so blanks fallback renders.
- `58b6778` — caller-owned epoch + worker-channel cleanup; workers discard stale `onmessage` payloads.
- `eb46706` — clear copy-content cache, sidebar highlight timers, and stale view refs on file-clear.
- `0c306aa` — `setRows` without `rowSearchText` must invalidate the cache.
- `a214f20` — Timeline auto-extract grid flash: swap columns in place, never destroy/rebuild.
- `f7bfb2d` — null-guard cross-view highlight refs and clear on Timeline reload.
- `8aebf3b` — every dispatch id needs `MAX_FILE_BYTES_BY_DISPATCH`; `_DEFAULT` is rarely correct.
- `ccfdc94` — worker-managed parser-watchdog terminates on timeout; main-thread watchdog cannot preempt loops.

### YARA engine
- `94117e8` — ascii/wide string semantics + per-scan lowercase view cache.
- `0437e1f` — multi-line string-modifier capture in parser.
- `1388c1c` — three rules rewritten for bounded quantifiers (ReDoS).
- `b00ada6` — worker bundle missing `throwIfAborted` stub broke auto-scan silently.
- `484d23d` — byte offsets must map through the actual scanned buffer.
- `3b72e4d` — keep long YARA values in their column and flush stale IOC rows.
- `413c618` — Pattern detections must not be mis-cast as IOCs / decoded payloads.
- `676fa1e` — format-aware `applies_to` predicates reduce FPs on irrelevant formats.
- `2061b82` — preserve regex literals when stripping comments in the YARA parser.

### Encoded recursion
- `6a83848` — recursively stamp chain prefix onto the whole `innerFindings` subtree.
- `17d1a72` — UTF-16LE PowerShell unwrap unblocked + breadcrumb dropdown.
- `0f71338` — per-finder budget + tightened backtick/rot13 patterns.
- `15cc44c` — decoder helpers are mixins; do not depend on helper load order.
- `9107360` — JS string-array obfuscator resolver loads after `cmd-obfuscation.js`.
- `3d3f8e6` — aggressive FP suppression across the finder pipeline.
- `6a71ee7` — split per-candidate `_patternIocs` from generic `_executeOutput`.
- `<pending>` — bash/python/php/JS deobfuscators route through `_processCommandObfuscation`; min decoded length is 2.
- `25f2e66` — cap CMD deobfuscated expansion at 32× raw / 8 KiB.
- `25f2e66` — PS backtick regex must bridge around hyphens and digits.
- `4372f30` — PS backtick-escape tick-count floor relaxed 2→1; whitelist is the real gate (recovers `pow\`ershell`, `Invoke\`-Expression`, `i\`ex`).
- `<pending>` — PS backtick regex char class widened `[a-zA-Z0-9\`]` → `[a-zA-Z0-9.\`]` so dotted .NET namespace chains (`Sy\`st\`em.Ne\`t.We\`b\`Cl\`ie\`nt`) match as a single token; `-replace` + backtick branches now share a single `_PS_SUSPICIOUS_KEYWORDS_RE` whitelist extended with curated weaponisation namespaces (`system.net.webclient`, `system.io.compression.*`, `system.reflection.assembly`, `system.diagnostics.process*`, `system.management.automation.scriptblock`, …). Fixes per-finding "Load for analysis" loading only the gated token and reassembled stitched script leaving the obfuscated tail on line 3.
- `25f2e66` — added PS sentinel-strip, empty-arg format, env slicer, `%COMSPEC%`, single-bang expansion.
- `<pending>` — CMD single-bang `!VAR!` branch also needs the 32× / 8 KiB amp cap.
- `0b37971` — BASH `${CMD:-default}` resolves default only when var is unset.
- `0b37971` — BASH partial variable concatenation emits when unresolved > 0 and resolved >= 2.
- `0b37971` — BASH `exec N<>/dev/tcp/...` compact bidirectional bind-to-fd primitive.
- `b088604` — Python chr-join detector handles generator and list-comprehension forms.
- `<pending>` — AppleScript char-code reassembly decoder (`src/decoders/applescript-obfuscation.js`): AS1 walks `&`-chains of `(ASCII character N)` / `(character id N)` / `(string id {N,N,…})` / "literal" operands; AS2 resolves standalone `string id {…}`. Emits `cmd-obfuscation` candidates gated on `SENSITIVE_APPLESCRIPT_KEYWORDS` (curl/wget/base64/security/launchctl/sudo/`/tmp/`/User-Agent/…). `OsascriptRenderer._reassembleCharCodeChains` is the synchronous un-gated sibling that appends reassembled strings to `augmentedBuffer` under `=== DEOBFUSCATED APPLESCRIPT LAYERS ===` so the existing `osascript_admin_shell_execution` / `osascript_shell_with_download` / `osascript_keychain_theft` rules fire on the reassembled command string.
- `<pending>` — AppleScript property-binding cross-reference resolver (`src/decoders/applescript-obfuscation.js`, rewritten): two-pass decoder collects every `property _X : <rhs>` / `set _X to <rhs>` / `global _X : <rhs>` / `local _X : <rhs>` binding, fixed-point resolves cross-references across ≤ 8 rounds with circular-reference placeholder output (`⟨_NAME⟩` U+27E8/U+27E9), then walks every `do shell script <expr>` sink substituting resolved bindings. Drops the sensitive-keyword gate on AS1/AS2 (fragments like 32-char hex bound to `property _WCXGBZ49Xh` are now surfaced) and replaces with a file-level plausibility gate (`do shell script` present, or ≥ 2 randomised `property _XXXXXX :` bindings, or ≥ 3 char-code primitives, or classic AppleScript surface). `OsascriptRenderer._reassembleBindingTable` is the synchronous sibling that emits `-- Binding: _NAME (kind) -> "<resolved>"` and `-- Reassembled: do shell script "<cleartext>"` lines into `augmentedBuffer`. Caps: 512 bindings, 64 KiB per resolved value, 1 MiB aggregate, 64 shell sinks. Three new YARA rules: `osascript_property_char_code_dropper` (high), `osascript_property_reassembled_shell_sink` (critical), `osascript_randomised_property_names` (medium).
- `<pending>` — YARA rules MUST NOT key on Loupe-synthetic `augmentedBuffer` sentinels. Rules that matched on injected markers (`-- Binding: _X ->`, `-- Reassembled: do shell script "…"`, `=== DEOBFUSCATED APPLESCRIPT LAYERS ===`) broke sidebar click-to-scroll because YARA-match offsets pointed at synthetic suffix bytes that don't exist in the Source viewer, so `_navigateToFinding` silently no-opped. Two rules deleted from `src/rules/osascript-threats.yar`: `osascript_property_reassembled_shell_sink` (critical, T1548.004) and `osascript_property_char_code_dropper` (high, T1027.013). Equivalent coverage is now emitted as in-renderer `signatureMatches` → `IOC.PATTERN` with `_firstMatch` / `_sourceOffset` / `_sourceLength` anchored at the REAL `property _X :` declaration or `do shell script` sink expression in raw source. Labels `AppleScript Reassembled Shell Sink` (critical) and `AppleScript Property Char-Code Dropper` (high). `_reassembleBindingTable(text)` now returns `{ lines, bindings, sinks }` with structured source-offset arrays instead of just a flat `-- …` line list. The mirror loop that stamps `signatureMatches` → `externalRefs` as `IOC.PATTERN` in `osascript-renderer.js` now runs AFTER all signatureMatch pushes, not before — otherwise the new emitters' patterns never reach the sidebar. `osascript_randomised_property_names` `^`-anchored regex rewritten to `\b`-anchored (YARA regex compile in `yara-engine.js:860` uses `g` + optional `i` flags only — no `m` flag — so `^` matches only at buffer start; this rule's pre-existing condition was effectively `#prop >= 0 and …` because it could never hit ≥ 3 on anything with a leading comment line). Three remaining rules (`osascript_char_code_obfuscation`, `osascript_char_code_admin_shell_reassembly`, `osascript_randomised_property_names`) all match on raw source bytes and fire with correct offsets.
- `<pending>` — AppleScript deobfuscation push-to-complete: Pass 4 anonymous-chain finder (`_findAppleScriptAnonymousChains`) now AppleScript-quotes its output so splicing at the chain's offset produces valid AS sub-expressions instead of bare strings that would wedge surrounding `&`-concatenation. AS1 `((ASCII character 104) & …)` → `"https://"`, AS2 `(string id {115,117,99,99,101,115,115})` → `"success"`. Bare resolved bytes preserved on `_resolvedValue` for IOC extraction. New Pass 4 lone-primitive finder catches trailing `(ASCII character N)` / `(character id N)` / `(string id {…})` that the AS1 chain-regex misses because the chain structure requires sibling operands; gated on an `&` operator within 8 chars of the primitive to avoid emitting on benign standalone primitives. Handler-local `set` bindings now admitted by `_collectAppleScriptBindings` when RHS is self-contained (no `_AS_RUNTIME_ACCESSOR_RE` keywords: `contents of` / `result` / `do shell script` on RHS / `call method` / `current application` / `system info` / `POSIX file` / `value of` / `return value of` / `item N of` / `first/last/every … of` / `count of`); tagged `_handlerScoped: true`. Handler-local bindings never override an existing file-scope binding — name-conflict → reject, file-scope value wins at file-scope resolution. `_asResolveOperands` now accepts partially-resolved ref targets (a value like `"https://⟨unresolved:_Runtime⟩/"` carries static prefix/suffix that would be lost if we discarded to `⟨unresolved:NAME⟩`); `rec.unresolvedRefs` persisted across fixed-point rounds for accurate dependency-closure propagation. `OsascriptRenderer._reassembleBindingTable` mirrors all four changes (self-contained handler-local admission, partial-ref acceptance, runtime-accessor gate, handler-never-overrides-file-scope). Net result on the in-the-wild osascript dropper: sinks inside handlers now resolve to the full static prefix (`curl --connect-timeout 5 … quoted form of https://⟨unresolved:__cViNLHc⟩/`) instead of `⟨unresolved:__WACaHqJOA0⟩`, trailing single primitives (`(ASCII character 47)`) now splice as `"/"`, and `(string id {…})` AS2 literals become `("success")` so `if x is ("success")` is valid AS.
- `<pending>` — AppleScript deobfuscation completeness pass (same files): binding candidates now emit **full valid AppleScript statements** as their `deobfuscated` field (`property _X : "resolved"` / `set _X to "resolved"` with AS-escape of `\` and `"`), shell-sink candidates preserve the `do shell script "<resolved>"` wrapper (with `with administrator privileges` modifier where present), so splicing back via `src/encoded-reassembler.js` produces copy-paste-runnable AppleScript instead of a bare payload fragment. Raw resolved text available on new `_resolvedValue` field for tests / IOC extraction. New `quoted form of <primary-expr>` unary operator parsed as a three-keyword lookahead token and resolved via POSIX single-quoting (`'arg'` with `'\''` escapes) instead of emitting three separate `⟨unresolved:…⟩` placeholders. Placeholder syntax unified: `⟨unresolved:NAME⟩` for binding not in map, `⟨circular:NAME⟩` for resolution-stack cycle, `⟨unknown:RAW⟩` for unparseable tokens. Handler-range detection (`on NAME() … end NAME` / `on NAME of X … end NAME`) excludes handler-local `set` from the binding map (runtime reassignments are statically unresolvable); top-level `if/try/repeat/tell` blocks remain in-scope. Empty-string placeholder properties (`property X : ""`) allow a later top-level `set X to ((chain…))` to override — common malware pattern where a property is forward-declared empty and populated later. Paren-matching loops in all four tokeniser sites (decoder + renderer, group parse + `quoted form of` operand) now track string-literal state so embedded `"(M"` / `"("` / `")"` in char-code chains don't corrupt the depth stack. Identifier regex widened from `_?[A-Za-z][A-Za-z0-9_]{0,63}` → `[_A-Za-z][A-Za-z0-9_]{0,63}` so double-underscore-prefixed names (`__cGSeFcXQnD`) parse as refs instead of three unresolved keyword tokens. Renderer's `_reassembleBindingTable` + `_reassembleCharCodeChains` mirror every decoder fix so YARA buffer sees the same cleartext.
- `<pending>` — AppleScript deobfuscation Tier A/B/C push-through (same files): three focused passes surface previously-opaque runtime-scoped state. **Tier A (loop-iterator expansion)**: `property _L : {e1, e2, e3}` now parses as a `list_literal` operand kind with per-element recursive resolution; when a handler body contains `repeat with <iter> in <listRef>` + `set <X> to (contents of <iter>)`, `_collectLoopIteratorBindings` maps `<X>` to the enumerated values. Pass 3 sink walker computes the transitive-ref closure of each sink via `unresolvedRefs` dependency walking; when any ref in the closure maps to a loop-iterator variable, the sink emits N candidates (one per list element) with the shadow binding map providing the concrete value. Cross-product capped at `_AS_MAX_LOOP_VARIANTS = 8` to prevent combinatorial blowup on nested loops. Each variant carries `_loopVariant.iteration` metadata naming the concrete assignment. **Tier B (handler post-condition propagation)**: `_propagateHandlerPostConditions` scans for file-scope `property _X : ""` (pure-empty literal) properties reassigned by exactly ONE self-contained `set _X to <rhs>` inside any handler body, promotes the handler's operand list to file-scope and re-runs fixed-point resolution. Conservative: multi-assignment handlers / non-empty file-scope properties / runtime-accessor RHSs skip promotion. **Tier C (dynamic-fetch IOC annotation)**: `_emitAppleScriptDynamicFetchCandidates` surfaces `set X to do shell script "<literal>"` patterns — rejected by the runtime-accessor gate for binding resolution — as `AppleScript Dynamic-Fetch Binding` candidates whose `_patternIocs` carry the embedded URLs. Pass 3 also attaches `_assignedTo` + `_dynamicFetchUrls` for char-code-chain shell sinks inside `set <var> to …` assignments, so URLs extracted from the resolved command surface as high-severity URL IOCs with the "dynamic C2 discovery" note. Net result on the in-the-wild fixture: 4 URL IOCs surface (3 C2 hosts + 1 Telegram discovery channel); handler sinks resolve to concrete `'https://<host>/'` POSIX-quoted forms instead of `⟨unresolved:__cViNLHc⟩`; `_lhfMIBr93U` list binding emits as `{"h1", "h2", "h3"}`.
- `be98aa5` — `mapReconToSource` splice width must use `strippedLength`, not `sourceLength`.
- `bc7d048` — shared `_clipDeobfToAmpBudget` caps five cross-shell amp blowups.
- `e8a64d7` — Phase 1 CMD/PS decoder fill; no generic printable fallback; `call :label` walks next non-empty line.
- `dcf6bca` — Phase 2 Bash decoder fill; interpreter gates and canonical rot13 sets only.
- `17e612c` — Phase 3 Python decoder fill; lambda regex uses `[\s\S]`; bytes prefix outside quote capture.
- `988d53b` — Phase 4 PHP decoder fill; backticks need PHP context + shell vocab; PHP amp caps added.
- `<pending>` — PHP5 sink-on-superglobal accepts up to 3 nested wrappers (`escapeshellarg`, `trim`/`urldecode`, `base64_decode`/`gzinflate` classes); extracts sink + wrapper-chain + key into `deobfuscated` (not raw match); severity uplift to critical on amplifying decoders or escapeshell* (option-injection reachable).
- `<pending>` — PHP5 two-pass local-var taint: `$c = $_GET[...]; sink($c);` bounded to 2 KiB bridging distance; new `PHP Superglobal Taint (local-var flow)` technique.
- `<pending>` — `PHP_Eval_Superglobal` YARA `$system_get` alternation now includes `SERVER|FILES` (parity with decoder); new wrapper-tolerant `$system_wrapped_sg` string; new rules `PHP_Webshell_Escapeshell_Taint`, `PHP_Superglobal_Taint_LocalVar`, `Bash_Live_Fetch_Pipe_Shell`, `JS_Aaencode_Kaomoji_Carrier`, `JS_Jjencode_Symbol_Carrier`, `Python_Socket_Revshell_Primitive`.
- `<pending>` — Bash `/dev/tcp` revshell and `curl|sh` live-fetch branches now extract host:port / upstream URL into `deobfuscated` + emit family-specific `_patternIocs` instead of returning raw match string.
- `<pending>` — PS Get-Command wildcard resolver: `&(gcm i*x)` / `.(Get-Command i?rest*)` globs match against curated `KNOWN_PS_CMDLETS_SENSITIVE` table; emits resolved cmdlet(s) + critical-severity `_patternIocs` when glob hits an execution sink; mixed-severity matches drop to avoid tier-inflation FPs.
- `<pending>` — PS comment injection: `I<##>nv<##>oke-Expression` strips `<#...#>` blocks before matching SENSITIVE_CMD_KEYWORDS; bounded comment body ≤ 256 chars, ≤ 8 inserts/candidate; companion `PS_Comment_Injection_Obfuscation` YARA rule (parity with `JS_Comment_Injection_Obfuscation`).
- `<pending>` — PS quote interruption: `i''e''x` / `p""o""w""e""r""s""h""e""l""l` single-token form strips adjacent empty-quote pairs inside identifier runs; gated on post-strip keyword hit; companion `PS_Quote_Interruption_Obfuscation` YARA rule.
- `<pending>` — ps-mini `[bool]` typecast + comparison evaluator: `_psResolveBoolValue` + `_psFlattenIfBlocks` pre-pass flatten truthy `if (<bool-expr>) { body }` blocks so body-scoped assignments become visible to the fixed-point resolver; unresolvable guards leave the block intact (conservative); negation chain bounded at 64.

### IOC plumbing
- `dfc594c` — replace bespoke type literals with `IOC.*` constants.
- `b632626` — audit follow-up: `pushIOC` convention sweep.
- `1fadc6b` — IOC push checklist + canonical severity floor per type.
- `b685985` — Zip Slip / Tar Slip per-entry IOCs.
- `992f83d` — crypto-address, secret-leak, IPv6 parity, Trojan Source.
- `1a0c330` — suppress low-confidence IP IOCs and DER-artifact URLs in binary strings.
- `986ff7a` — preserve 4-digit DNS IPs (8.8.8.8 / 1.1.1.1) in version-string filter.
- `6c0b024` — migrate plist / osascript / x509 IOC pushes to `pushIOC()`.
- `<pending>` — `extractInterestingStringsCore` runs tldts-free (worker bundle constraint); host backfills IOC.DOMAIN / IOC.IP-literal / PATTERN siblings via `App._backfillUrlSiblings` at every merge site (sync shim + worker success + worker fallback). Factored shared helper `emitUrlSiblings` in `src/constants.js`.
- `<pending>` — URL-in-query redirector pattern (`?a=https%3A%2F%2Fevil.com…`): `processUrl` percent-decodes the query and re-scans for inner URLs (depth capped at 1), emits them at medium severity with note `Nested URL (query param)`.

### Native-binary FPs
- `02b1592` — trust-tier + `binaryClass` gating to cut native-binary FPs.
- `3ab47db` — cut ELF/PE false-positive critical band on benign system tools.
- `5516ee3` — resource-only DLL packing-risk FP.
- `22a03d0` / `0b99a4c` — verdict reasons audit trail; remove dead reasons panel after contradiction.
- `<pending>` — pin `currentResult.yaraBuffer = buffer` in PE/ELF/Mach-O routes.
- `<pending>` — tighten 4 PE rules + gate `Confusable_Codepoint_Density` with `applies_to = !is_native_binary`.

### Timeline route
- `2487fe4` — parallel e2e + Timeline state-leak fix; cross-load reset clears Timeline internals.
- `9b10618` — align `_evtxEvents` to truncated row count on sync EVTX path.
- `a76eaae` — auto-extract is ephemeral; only Regex-tab extracts persist.
- `d2a5d2a` — split GeoIP done-marker from auto-extract marker.
- `237eb7d` — preserve JSON auto-extracts across reopens; tighten text-host detection.
- `f656a09` — query popover must not render off-screen at caret column 0.
- `062c0d3` — history dropdown must not nuke the undo ring.
- `bc63eb8` — escape backslash in `CSS.escape` fallback selector.
- `22d8647` — RFC-4180 quote-aware CSV parser shared across all CSV/TSV paths.
- `4425400` — NOT IN filter on truncated column-filter sets needs all-pass baseline.

### Archive / parser safety
- `369c8e9` — aggregate nested archive budget is 50k entries / 256 MiB; reset top-level only.
- `b291e2c` — `MAX_UNCOMPRESSED` 50 → 256 MB for legitimate modern .ipa/.appx.
- `fc0f1bd` — detect ZIP encryption via central-dir walk, not first local header.
- `7a4a169` — cap PCAPNG block walk to bound non-packet padding.
- `0d59b15` — anchor PK magic at file offset 0 in archive YARA rules.

### Regex safety
- `42320f9` — regex-safety + worker-shim-parity build gates.
- `ffd265e` — `safeRegex / safeExec / safeTest / safeMatchAll` harness.
- `9f379f2` — bound nested quantifiers in path / UNC / domain regexes.
- `cc01dda` — bound scan windows + document sync-decode invariants.
- `f9413e2` — Timeline DSL filters and regex-extract route through `safeRegex`.
- `3457a09` — YARA editor rule import routes through `safeRegex`.
- `ecf78ae` — inline `safeRegex` helpers into worker shims.
- `716d532` — bound `invisRe` to `\w{2,64}` and route IOC `matchAll` through `safeMatchAll`.

### Parser perf
- `81d5d0a` — memoise next-quote index in `CsvRenderer.parseChunk`; invalidate on every quote.
- `a87be39` — reuse lazy instance `TextDecoder('utf-8')` for SQLite TEXT cells.
- `9a0d2fb` — EVTX long UTF-16 strings use shared `TextDecoder('utf-16le')`; short strings keep fast path.
- `93839b2` — fold EVTX Data.Name ↔ Data-text pairing O(N×M) → O(N+M) with a forward cursor.

### Build determinism / load order
- `8e4735a` — backtick-comment-terminator build gate.
- `0efb4cd` — block-comment YARA category sentinel + missing-category guard.
- `97fffb2` — `row-store.js` must be in both main and worker bundles.
- `7d4861d` — worker-shim `RENDER_LIMITS` constants must match canonical.
- `9bc2646` — strip `sourceMappingURL` from tldts; remove `frame-ancestors` CSP.
- `7ab62b7` — `lfNormalize()` helper + `_rawText` LF-normalisation build gate.
- `6c9f2b1` — `safeStorage` wrapper + migration; `extendApp` collision guard.
- `<pending>` — vendored highlight.js bundle must register claimed languages; parity test covers it.

### Drag-drop & ingress
- `e937d32` — drag-and-drop files were captured by iframe; re-dispatch `loupe-drop` `CustomEvent`.
- `e76ba0e` — defer vendor compile, add early drag-drop bootstrap, idle-init `BgCanvas`.
- `3b4aa78` — hosted-mode privacy bar; external-file drag gating.
- `<pending>` — Chromium macOS `readEntries()` EncodingError on folder drops now surfaces on `FolderFile.fromEntries`'s `walkErrors` and falls back to loose-file ingest instead of dispatching an empty tree under a misleading "truncated at 4,096" toast.
- `<pending>` — macOS folder drops: `DataTransfer.files` carries the folder itself as a pseudo-File whose `arrayBuffer()` rejects with NotFoundError; `_filterReadableLooseFiles` (name-match + `slice(0,1).arrayBuffer()` probe) sanitises the loose-file fallback before `_loadFile` is ever called.
- `<pending>` — `_sniffAppleScript` cutoff 5→4 + new scoring signals (char-code `+3`, char-id `+2`, string-id `+2`, unquoted do-shell-script `+3`, quoted-form-of `+2`, Apache CLF line `-8`). Without this, an obfuscated AppleScript pasted without the `.applescript` extension scored only 4 under the old table (required `do\s+shell\s+script\s+"`) and fell through to `PlainTextRenderer` → hljs auto-detect → "Apache" grammar. Paste ⇔ drop parity restored.

### Plaintext / Format toggle
- `<pending>` — `CodeFormatter._formatIndentOnly` dispatches to language-specific walkers: `_formatPowershellIndent` / `_formatBashIndent` split top-level `;` statements (outside strings, comments, here-strings / here-docs, `$(…)` / `` `…` `` sub-shells, and `for (;;)` parens) AND re-indent `{` / `}` blocks. DOS keeps the legacy line-indent-only pass (`_formatDosIndentLegacy`). Fixes the "click Format on `$a=1;$b=2;IEX $a` one-liner → nothing happens" UX; hard-fails CLOSED on unbalanced braces / unterminated strings / here-strings / depth > 256 / amp > 3×.

### State leak & cleanup
- `eb46706` — clear copy-content cache, sidebar highlight timers, stale view refs on file-clear.
- `0c306aa` — invalidate `rowSearchText` cache when `setRows` omits it.
- `f030863` — clipboard + undo + drawer search + theming bug-fixes.
- `1c1d0ad` — snapshot clipboard `DataTransfer` on paste before invalidation.
- `<pending>` — `_loadFile` outer-catch drops the persistent `.error-box` popup; failure surfaces only as a 3 s toast. `#page-container` is still emptied so stale content doesn't linger.

### Worker-manager / lifecycle
- `2536d00` — `_reportNonFatal` helper + silent-catch gate; pdf.worker lifecycle.
- `88b011c` — stream CSV/TSV rows from worker; bump `WORKER_TIMEOUT_MS` to 5 min.

### Test suite gotchas
- `2487fe4` — tests must tolerate prior-load state; UI specs use `beforeEach(gotoBundle)`.
- `8b2ee07` — pin schema assertions to immutable base columns.
- `075046f` — wait for grid paint before reading `_extra` cell text in Timeline e2e.
- `e8ab1b1` — permanent unit coverage for engine, rule perf, and regex shapes.
- `<pending>` — fuzz coverage aggregation must union COVERED-wins-over-UNCOVERED across processes.
- `4fc090a` — Jazzer v4 sancov needs `hookRequire`; `vm.runInContext` bypasses instrumentation.

---

## PR / commit hygiene

- Run `python make.py` locally before pushing. Renderer changes should also run `python make.py test-unit`; renderer logic changes should run `python make.py test-e2e`.
- Commit style: `feat(area):`, `fix(area):`, `perf(area):`, `refactor(area):`, `test(area):`, `docs(area):`, `chore(area):`, `build(area):`, `ci(area):`.
- User-visible behaviour changes update `FEATURES.md` + `README.md`; CSP / parser-limit / sandbox changes update `SECURITY.md`; vendor changes update `VENDORED.md`.
- License is **MPL-2.0**; do not introduce GPL / LGPL / proprietary deps.
- Doc-only commits skip CI (`paths-ignore: '**/*.md', LICENSE`); use `gh workflow run ci.yml --ref main` to force Pages deploy after doc-only edits.

---

## Common agent mistakes

- Forgetting `await Promise.all(...)` in async analyzers using `QrDecoder.decodeBlob()` → sidebar snapshots empty findings.
- `datetime.now()` / `os.walk` / random IDs / unsorted sets in `scripts/build.py` → non-reproducible build.
- Reordering `JS_FILES` / `CSS_FILES` / `YARA_FILES` / `_DETECTOR_FILES` without reading comments → silent override drift.
- Adding a dispatch id without `MAX_FILE_BYTES_BY_DISPATCH[id]` → 128 MiB `_DEFAULT` fall-through.
- Forgetting to mirror Detections into `externalRefs` as `IOC.PATTERN` → invisible to risk calc, Summary, STIX, MISP.
- Forgetting `_noDomainSibling: true` on a URL push that already emitted a manual domain → duplicate domain IOC.
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
git show <sha>                  ← context for any pain-point SHA above
git log --oneline --grep=<area> ← scoped history
```

---

## Further reading

- `CONTRIBUTING.md` — Footguns Cheat-Sheet, Renderer Contract, IOC Push Helpers & Checklist, Persistence Keys table, Adding things recipes.
- `SECURITY.md` — threat model, full CSP, parser-limit table, reproducible-build recipe.
