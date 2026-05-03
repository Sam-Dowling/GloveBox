# Loupe fuzz harness

Opt-in, coverage-guided + replay-mode fuzzing for Loupe's pure-JS
parsers, decoders, and regex consumers. **Local-only**, never CI-gated,
never enters the shipped bundle.

The fuzz layer is invisible to `python make.py` and `python make.py
test`; it runs only when you ask for it via `python make.py fuzz` or
`python scripts/run_fuzz.py`. The shape mirrors `tests/perf/`: a
parallel test suite that exists to drive a specific kind of
investigation, not to gate every commit.

## Running

```bash
# Quickest possible smoke (no npm install — runs the deterministic
# replay mutator from harness.js):
python scripts/run_fuzz.py --replay --quick

# Provision @jazzer.js/core (~30 s on first run) and fuzz every
# discovered target for 60 s each:
python scripts/run_fuzz.py

# Single target, longer:
python scripts/run_fuzz.py --time 600 text/ioc-extract

# Reproduce a specific crash:
python scripts/run_fuzz.py --reproduce dist/fuzz-crashes/text/ioc-extract/<sha>/input.bin

# List discovered targets:
python scripts/run_fuzz.py --list

# Crash → permanent regression test (see § Crash workflow):
python scripts/fuzz_minimise.py text/ioc-extract dist/fuzz-crashes/text/ioc-extract/<sha>
python scripts/fuzz_promote.py  text/ioc-extract dist/fuzz-crashes/text/ioc-extract/<sha>

# Per-src/file line-coverage table (see § Coverage measurement):
python scripts/run_fuzz.py --replay --quick --coverage
python scripts/fuzz_coverage_aggregate.py
```

## Why a separate fuzz layer

Loupe is a single-file static analyser that takes adversarial input by
default. The unit tests in `tests/unit/` cover the happy path of every
parser; the e2e suite in `tests/e2e-fixtures/` covers a realistic
corpus. Neither catches the long tail of malformed-input behaviour —
ReDoS, integer overflow in length fields, infinite loops past the
parser watchdog, memory blowup, invariant drift (an IOC that escapes
the `IOC.*` enum, a `findings.risk` outside the canonical tier set).

Fuzzing is the right tool for that surface. Each target loads its
`src/` subset through `tests/helpers/load-bundle.js` — the same
`vm.Context` loader the unit tests use — so any crash a fuzzer finds
reproduces as a unit test by construction.

## Two execution modes

### Replay mode (default for development)

`--replay` drives every target through its declared seed corpus plus a
deterministic byte-mutator inside `helpers/harness.js::runReplay`.
Pure Node, **no npm install required**. Catches shape regressions,
invariant violations, and ReDoS via the per-iteration 2.5 s wall-clock
budget.

Use replay mode for:

- new-target smoke ("does my target even compile?")
- `--reproduce` invocations against a saved crash file
- the verifier inside `scripts/fuzz_minimise.py` (each candidate
  goes through `helpers/run-once.js`, which uses the same fuzz
  callback)
- ad-hoc "did this fix make the bug go away?" checks

### Coverage-guided mode (Jazzer.js)

The default when you don't pass `--replay`. `scripts/run_fuzz.py`
provisions `@jazzer.js/core@<JAZZER_VERSION>` (Apache-2.0) ephemerally
into `dist/test-deps/`, then drives each target via the Jazzer.js CLI
for `--time` seconds (default 60). Jazzer.js wraps libFuzzer's
mutator and grows its corpus alongside the replay seeds under
`dist/fuzz-corpus/<target>/`. Crashes land in
`dist/fuzz-crashes/<target>/`.

**Caveat — coverage signal across vm.Context.** The harness loads
target source into a fresh `vm.Context` (matching the unit-test
discipline). Jazzer.js's source instrumentation does not currently
reach across that boundary, so coverage-guided fuzzing today behaves
closer to a fast bytewise mutator than a true source-coverage feedback
loop. The trade-off is deliberate: `vm.Context` isolation matches
production worker semantics and keeps fuzz crashes reproducible as
unit tests. A "flat" target loading mode that skips `vm.Context` is
on the table whenever a real bug investigation needs source-coverage
drilldown.

(That's about Jazzer.js's *mutation*-guiding coverage. For *measuring*
which `src/` lines a fuzz run actually exercised, see
§ Coverage measurement.)

## Targets

```
tests/fuzz/targets/
├── binary/
│   ├── elf-renderer.fuzz.js     ← ElfRenderer.analyzeForSecurity
│   ├── evtx-renderer.fuzz.js    ← EvtxRenderer._parse (binary EVTX walker)
│   ├── lnk-renderer.fuzz.js     ← LnkRenderer.analyzeForSecurity
│   ├── macho-renderer.fuzz.js   ← MachoRenderer.analyzeForSecurity (thin + Fat)
│   ├── onenote-renderer.fuzz.js ← OneNoteRenderer.analyzeForSecurity (async)
│   ├── pcap-renderer.fuzz.js    ← PcapRenderer.analyzeForSecurity (libpcap + pcapng)
│   ├── pe-renderer.fuzz.js      ← PeRenderer.analyzeForSecurity
│   ├── plist-renderer.fuzz.js   ← PlistRenderer.analyzeForSecurity (binary + XML)
│   ├── sqlite-renderer.fuzz.js  ← SqliteRenderer.analyzeForSecurity
│   ├── wasm-renderer.fuzz.js    ← WasmRenderer.analyzeForSecurity (async)
│   └── x509-renderer.fuzz.js    ← X509Renderer.analyzeForSecurity (DER/PEM/CMS)
├── text/
│   ├── csv-rfc4180.fuzz.js      ← CsvRenderer.parseChunk state machine
│   ├── encoded-content.fuzz.js  ← EncodedContentDetector finder pipeline
│   ├── evtx-detector.fuzz.js    ← EvtxDetector key/value tokenizer
│   ├── ioc-extract.fuzz.js      ← extractIOCs / pushIOC plumbing
│   └── ooxml-rel.fuzz.js        ← OoxmlRelScanner._classifyTarget tokenizer
├── obfuscation/
│   ├── cmd-obfuscation.fuzz.js        ← _findCommandObfuscationCandidates (CMD branches)
│   ├── powershell-obfuscation.fuzz.js ← _findCommandObfuscationCandidates (PS branches)
│   │                                    + _findPsVariableResolutionCandidates
│   ├── bash-obfuscation.fuzz.js       ← _findBashObfuscationCandidates (B1–B6 + /dev/tcp)
│   ├── python-obfuscation.fuzz.js     ← _findPythonObfuscationCandidates
│   └── php-obfuscation.fuzz.js        ← _findPhpObfuscationCandidates
└── yara/
    ├── parse-rules.fuzz.js      ← YaraEngine.parseRules (grammar parser)
    └── scan.fuzz.js             ← YaraEngine.scan (rule execution engine)
```

Binary targets exercise `analyzeForSecurity(buffer, fileName)` only —
the `render()` companion needs DOM (`document.createElement`) which
the `vm.Context` sandbox doesn't provide. All deep parsing
(DOS/COFF/Optional header, ELF header/sections/dynamic, Mach-O
header/load-commands/Fat, libpcap+pcapng records, SQLite B-tree
pages, LNK header+LinkInfo+StringData+ExtraData, plist binary
trailer/XML, WASM section walker, X.509 ASN.1 DER/PEM/CMS, OneNote
FileDataStoreObject scanner) runs inside `analyzeForSecurity`'s
`try` block and feeds `findings.<format>Info` on the same instance
— so `render()`'s absence costs no parser coverage.

The exception is `binary/evtx-renderer`, which fuzzes `_parse(bytes)`
directly (the binary walker) rather than the 1-line
`analyzeForSecurity` delegate to `EvtxDetector` (already covered by
`text/evtx-detector`). `_parse` throws on bad magic / OOB length
fields; those are documented hard-fail paths and listed in
`isExpectedError`.

YARA targets fuzz `parseRules` and `scan` separately. The shapes are
orthogonal — rule text vs file bytes — so fuzzing them jointly would
double the search space without proportional bug-find gain.
`scan` pre-parses an 11-rule fixed corpus once at init that exercises
every engine feature (ascii/wide/nocase/fullword modifiers,
base64/xor, hex jumps, regex, `uint16(0)==0x5A4D` byte-fetch,
`for any of` predicates, `applies_to` short-circuit), then mutates
the buffer side.

## Architecture

```
tests/fuzz/
├── README.md                   (this file)
├── helpers/
│   ├── harness.js              defineFuzzTarget + runReplay; loads src/
│   │                           into vm.Context via tests/helpers/load-bundle.js
│   ├── crash-dedup.js          stack-hash digest (16-hex stable across runs)
│   ├── seed-corpus.js          deterministic walker over examples/<dir>/
│   ├── replay-runner.js        Node entry for --replay / --reproduce
│   ├── jazzer-bootstrap.js     Node entry for the Jazzer.js CLI
│   └── run-once.js             single-shot verifier for the minimiser
└── targets/                    one *.fuzz.js per fuzz surface
```

`@jazzer.js/core` is a test-time dep, NOT a vendored runtime lib —
treated identically to `@playwright/test`. Pinned via `JAZZER_VERSION`
in `scripts/run_fuzz.py`; bumping is a one-line PR.

## Adding a new target

1. Pick a target in `src/`. Good candidates: pure functions with byte
   inputs, regex-heavy paths, length-prefixed binary formats, anything
   that owns a header parser.
2. Create `tests/fuzz/targets/<area>/<name>.fuzz.js` modelled on the
   existing ones:
   ```js
   'use strict';
   const { defineFuzzTarget } = require('../../helpers/harness.js');
   const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');

   const fuzz = defineFuzzTarget({
     modules: ['src/constants.js', 'src/<your-module>.js'],
     // expose: ['MyClass', 'myFn'],   // optional override
     maxBytes: 1 * 1024 * 1024,
     perIterBudgetMs: 2_500,
     onIteration(ctx, data) {
       const text = new TextDecoder('utf-8', { fatal: false }).decode(data);
       const result = ctx.myFn(text);
       // Assert invariants — every assertion is a future bug.
       if (typeof result.foo !== 'string') {
         throw new Error('invariant: foo not string');
       }
     },
   });

   const seeds = [
     // Buffer per seed; pick from examples/<format>/, plus a handful
     // of hand-rolled adversarial shapes for known historical bugs.
     ...syntheticTextSeeds(8),
   ];

   module.exports = { fuzz, seeds, name: 'my-target' };
   ```
3. Smoke it: `python scripts/run_fuzz.py --replay --quick targets/<area>/<name>`.
4. Run a longer pass: `python scripts/run_fuzz.py --replay --iterations 1000 targets/<area>/<name>`.
5. Once green, commit. The next `python make.py fuzz` invocation
   automatically picks it up.

The harness reuses `tests/helpers/load-bundle.js` verbatim. Anything a
unit test can `loadModules([...])`, a fuzz target can. There is no
divergence in semantics by design.

## The 2.5 s per-iteration budget

`harness.js::DEFAULT_PER_ITER_BUDGET_MS = 2500`. Any iteration that
exceeds this — even if it eventually returns successfully — is
reported as a crash with code `LOUPE_FUZZ_BUDGET_EXCEEDED`. This is
the harness's ReDoS detector; production code paths the harness
fuzzes should never exceed `PARSER_LIMITS.FINDER_BUDGET_MS` (2500 ms
in `src/constants.js`). Targets can override via
`defineFuzzTarget({ perIterBudgetMs: <ms> })` when their entry point
legitimately processes large inputs.

The watchdog timeout (`err._watchdogTimeout === true`) is **not**
counted as a crash — it's the documented abort path of the renderer
under test. Targets with explicit "expected error" classes can
whitelist them via `cfg.isExpectedError` (e.g.
`err.message.startsWith('parser-limit:')`,
`err.message.startsWith('aggregate-budget:')`, EVTX magic-byte
rejection).

## Crash artefact layout

```
dist/                              (gitignored)
├── fuzz-corpus/<target>/          libFuzzer-format growing corpus
│   └── seed-<sha>                 our seeds + libFuzzer's discoveries
├── fuzz-crashes/<target>/<sha>/   one dir per stack-hash
│   ├── input.bin                  raw bytes that triggered the crash
│   ├── stack.txt                  normalised error + stack
│   └── minimised.bin              (optional) written by fuzz_minimise.py
└── fuzz-coverage/
    ├── summary.json
    └── summary.md
```

Stack-hash dedup (`tests/fuzz/helpers/crash-dedup.js`):

- Parses `err.stack` into structured frames.
- Drops harness frames (`tests/fuzz/helpers/`, `vm.runInContext`,
  Node internals, Jazzer.js internals).
- For each remaining frame, keeps `<fnName>@<basename>` only — line
  numbers are stripped so a `git pull` doesn't dedup-break the crash
  database.
- Concatenates with `err.name + ': ' + redactMessage(err.message)`
  (numbers and hex literals replaced with `<N>` / `<X>` so two
  crashes that differ only in offset hash to the same digest).
- SHA-256, first 16 hex chars (≈ 64 bits, > 1 M crash namespace).

## Crash workflow

A crash dir under `dist/fuzz-crashes/<target>/<sha>/` is **ephemeral**
(`dist/` is gitignored). Three commands turn a fresh finding into a
permanent regression test:

```bash
# 1. Run the fuzzer (or replay) until something crashes.
python scripts/run_fuzz.py --replay --quick text/ioc-extract
#   …writes input.bin + stack.txt under dist/fuzz-crashes/<target>/<sha>/

# 2. Minimise the crashing buffer while preserving the SAME stack hash.
python scripts/fuzz_minimise.py text/ioc-extract \
    dist/fuzz-crashes/text/ioc-extract/<sha>
#   …writes minimised.bin alongside input.bin

# 3. Synthesise a permanent reproducer under tests/unit/.
python scripts/fuzz_promote.py text/ioc-extract \
    dist/fuzz-crashes/text/ioc-extract/<sha>
#   …writes tests/unit/text-ioc-extract-fuzz-regress-<sha>.test.js
```

The promoted test:

- loads the target's existing `*.fuzz.js` module — the fuzz target is
  the single source of truth for which `src/` files to evaluate, which
  symbols to expose, and which invariants to assert; no logic is
  duplicated.
- inlines the (minimised) crashing bytes as a base64 constant — the
  test is self-contained and survives any cleanup of `dist/`.
- asserts `assert.doesNotReject(target.fuzz(INPUT))` — passing once
  the underlying bug is fixed, failing the moment the regression
  re-lands.

`fuzz_promote.py` flags:

- `--use {minimised,original,auto}` — pick the variant; `auto`
  (default) prefers `minimised.bin` if present.
- `--note '<text>'` — extra one-line note injected into the test
  header (e.g. linking to the fix commit).
- `--dry-run` — print the generated test to stdout for review.
- `--force` — overwrite an existing reproducer at the same sha.

`fuzz_minimise.py` shells to `tests/fuzz/helpers/run-once.js` for each
candidate and accepts a candidate iff it still throws with the same
16-hex stack hash. Reduction strategies, in order:

1. Halve from end / halve from start (binary slicing).
2. Sliding-window deletion at sizes 16, 8, 4, 2, 1 bytes.
3. Byte-replace pass (every byte → `0x20`).

A pass terminates when one full sweep produces no further improvement.
Pass `--time <seconds>` for a wall-clock cap when operating on a slow
target.

The minimiser's stack-hash discipline is what distinguishes it from
libFuzzer's `-minimize_crash=1`: libFuzzer collapses two distinct
bugs that share a target into one minimal input; Loupe's minimiser
preserves the find-time grouping by re-running the same
`crash-dedup.js` for every candidate.

## Coverage measurement

Pass `--coverage` to `python scripts/run_fuzz.py` to record V8 source
coverage per target and emit a per-`src/<file>.js` line-coverage table
in `dist/fuzz-coverage/summary.md`.

```bash
# Coverage-aware quick smoke across two targets:
python scripts/run_fuzz.py --replay --quick --coverage text/ioc-extract yara/scan

# Coverage on every target under Jazzer.js (slow — V8 coverage adds
# substantial overhead on heavy parsers, especially the binary ones):
python scripts/run_fuzz.py --coverage --time 30
```

This is a *measurement* layer, distinct from Jazzer.js's coverage-
guided mutation. The two answer different questions:

- **Jazzer.js coverage-guided mutation** — internal feedback loop the
  fuzzer uses to decide which inputs to mutate next. Currently
  degraded by `vm.Context` isolation (see caveat above).
- **`--coverage` line-coverage measurement** — external observation of
  which `src/<file>.js` lines a finished fuzz run actually
  exercised. Implemented via `NODE_V8_COVERAGE`, which V8 supports
  natively for `vm.runInContext` code without any of the
  instrumentation that Jazzer.js's mutation feedback needs.

How it works:

1. With `--coverage`, the orchestrator sets `NODE_V8_COVERAGE=<dir>`
   and `LOUPE_FUZZ_COVERAGE_DIR=<dir>` per target.
2. The harness (`tests/fuzz/helpers/harness.js`) loads the target's
   `src/` subset via `loadModulesWithManifest()` instead of
   `loadModules()`, writes the bundle's char-offset → `src/<file>.js`
   manifest into the same dir, and labels the bundle with a stable
   `loupe-fuzz-bundle://<target-id>` URL.
3. V8 dumps per-process source-coverage JSON into the dir at process
   exit (libFuzzer / replay runner alike).
4. `scripts/fuzz_coverage_aggregate.py` walks each target's dir,
   merges all per-process coverage entries with `count > 0` over
   `count == 0` (cross-process union), maps char ranges through the
   manifest, and projects covered/uncovered chars onto per-line
   counts. Lines that contain only whitespace, comments, or `*`
   block-comment continuation are excluded from the executable line
   count to keep the percentage meaningful.
5. The aggregator's Markdown output is appended to
   `dist/fuzz-coverage/summary.md`. JSON is available standalone via
   `python scripts/fuzz_coverage_aggregate.py --json`.

The `summary.md` output has three blocks:

- **Per-target rollup** — one line per target, total covered /
  uncovered / unknown / executable lines.
- **Per-target file detail** — one table per target showing
  per-`src/<file>.js` line counts.
- **Per-`src/` file rollup across all targets** — sorted by ascending
  coverage %, so the under-fuzzed files float to the top. Use this
  to decide which target to add or extend.

Caveats:

- Coverage data only includes files actually loaded by the target's
  `modules` list. A `src/foo-renderer.js` that no fuzz target loads
  contributes nothing to the rollup; that's not the same as "0%
  covered".
- The `unknown` column counts lines inside the bundle but outside
  any V8-tracked function range. In practice these are almost
  always top-level `const X = …` declarations attributed to the
  V8 implicit module function (which V8 reports without per-line
  attribution). Treat `covered + unknown` as the optimistic upper
  bound and `covered` as the conservative lower bound.
- V8 source coverage costs wall-clock — typically a few × slowdown
  on heavy binary parsers under `--coverage`. Skip the flag for
  pure crash-hunting runs; reach for it when investigating where
  the harness *isn't* reaching.

Standalone CLI for re-rendering after a manual fuzz run:

```bash
python scripts/fuzz_coverage_aggregate.py                       # all targets, Markdown
python scripts/fuzz_coverage_aggregate.py --json                # JSON
python scripts/fuzz_coverage_aggregate.py --target text/ioc-extract  # single target
python scripts/fuzz_coverage_aggregate.py --coverage-dir /tmp/cov    # custom dir
```

## Obfuscation deobfuscation iteration loop

The five `obfuscation/*` targets exist to drive an iterative
"fuzz → review → fix → repeat" workflow against the command-obfuscation
decoders (`src/decoders/{cmd,bash,python,php}-obfuscation.js` and
`src/decoders/ps-mini-evaluator.js`). Each iteration produces a
per-technique hit / decode-success / expected-miss table in
`dist/fuzz-coverage/summary.md` § _Obfuscation technique coverage_ —
rows with `hits = 0` are decoder branches the current seed corpus never
reaches; rows with non-zero `hits` and low `decode %` are branches that
fire but fail to produce usable `deobfuscated` output; non-zero `miss`
counts are grammar seeds where the decoder's output no longer contains
the expected substring (a silent wrong-decode signal).

The per-technique data comes from two sources that must stay in sync:

1. The decoder's `candidate.technique` string (emitted in
   `src/decoders/<shell>-obfuscation.js`).
2. The grammar's `TECHNIQUE_CATALOG` constant
   (`tests/fuzz/helpers/grammars/<shell>-grammar.js`) — parsed by
   `scripts/fuzz_coverage_aggregate.py` at render time, no `eval`.

A technique that fires in the decoder but is absent from the catalog
lands in the `__unknown__` row of the table; a catalog entry that
never fires has `hits = 0`. Either asymmetry is actionable.

### Four-command loop

```bash
# 1. Run the obfuscation targets under --coverage so both V8 line
#    coverage and technique counters are recorded.
python scripts/run_fuzz.py --replay --coverage \
    obfuscation/cmd-obfuscation obfuscation/powershell-obfuscation \
    obfuscation/bash-obfuscation obfuscation/python-obfuscation \
    obfuscation/php-obfuscation

# 2. Render dist/fuzz-coverage/summary.md (already done at the end of
#    step 1; re-run standalone after a manual tweak to the aggregator
#    or to regenerate after deleting artefacts).
python scripts/fuzz_coverage_aggregate.py

# 3. Inspect the "Obfuscation technique coverage" section.
#    Focus on rows where hits = 0, decode % < 50, or miss > 0.
#    Cross-reference against the per-src/ rollup — low line-coverage
#    on src/decoders/<shell>-obfuscation.js pinpoints the branch.
${PAGER:-less} dist/fuzz-coverage/summary.md

# 4. Act on the signal:
#    a. Branch exists in decoder but never fires → add a grammar seed
#       in tests/fuzz/helpers/grammars/<shell>-grammar.js that exercises
#       the structural pattern (generate 2–4 variants with
#       `_expectedSubstring` pinned).
#    b. Branch fires but decode % is low → the decoder's static parser
#       isn't resolving the pattern; edit
#       src/decoders/<shell>-obfuscation.js to extend the decoder.
#       Run `python make.py test-unit` afterwards to verify no
#       existing test regressed.
#    c. miss > 0 → the decoder emits a candidate but its `deobfuscated`
#       output no longer contains the expected payload token. Likely a
#       silent regression in the decoder's unwrapping logic.
#    Then loop to step 1.
```

Longer coverage-guided passes trade runtime for mutation diversity:

```bash
# 10 min per target under Jazzer.js libFuzzer mutation, with coverage.
python scripts/run_fuzz.py --coverage --time 600 \
    obfuscation/cmd-obfuscation \
    obfuscation/powershell-obfuscation \
    obfuscation/bash-obfuscation \
    obfuscation/python-obfuscation \
    obfuscation/php-obfuscation
```

Any crash found during the loop goes through the existing crash
workflow (see § _Crash workflow_): minimise → promote to a permanent
`tests/unit/<target>-fuzz-regress-<sha>.test.js`. The technique table
is advisory — it tells you _where_ to dig; it does not gate CI, it is
not a correctness signal on its own.

### Signal meaning cheat sheet

| Row | Likely cause | Action |
|---|---|---|
| `hits = 0` in catalog | Decoder branch exists, grammar seed doesn't trigger it | Add a grammar seed for the branch |
| `hits > 0`, `decode %` < 50 | Decoder fires but can't resolve | Extend static parser in `src/decoders/<shell>-obfuscation.js` |
| `miss > 0` on low-volume tech | Decoder output lost the payload token | Check recent changes to the branch's unwrapper |
| `__unknown__` > 0 | Decoder emits a `technique` string absent from the grammar catalog | Add the string to `TECHNIQUE_CATALOG` |
| A catalog entry is `__unknown__` only | Grammar catalog string doesn't match decoder emission verbatim | Fix the catalog string to match exactly |


## Reproducible build interaction

`tests/fuzz/` lives entirely outside `JS_FILES` / `CSS_FILES` /
`_DETECTOR_FILES`. Two build gates enforce that:

- `_check_no_test_api_in_release` — release bundle can't contain
  `__loupeTest`.
- `_check_no_fuzz_path_in_bundle` — neither the release nor the
  `--test-api` bundle can contain `tests/fuzz/helpers/` or
  `tests/fuzz/targets/`.

Keep this file aligned with reality — if the harness behaviour drifts
from what's documented here, fix the doc in the same PR.
