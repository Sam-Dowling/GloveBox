# Loupe test suite

Loupe ships as a single 100% offline static HTML file with no committed
`package.json` / `node_modules` / lockfile. The test pipeline preserves
that constraint while adding three independent layers of coverage:

| Layer            | Runner             | What it covers                                            |
|------------------|--------------------|-----------------------------------------------------------|
| `tests/unit/`    | Node `node:test`   | Pure modules from `src/` (no DOM, no App, no renderers).  |
| `tests/e2e-fixtures/` | Playwright    | Real fixtures from `examples/` → real renderer dispatch.  |
| `tests/e2e-ui/`  | Playwright         | UI ingress (file picker, drag-drop, paste) round-trips.   |

Everything is wired through `make.py`:

```bash
python make.py test          # full pipeline: test-build → test-unit → test-e2e
python make.py test-build    # rebuild docs/index.test.html (--test-api)
python make.py test-unit     # node:test under tests/unit/
python make.py test-e2e      # Playwright under tests/e2e-fixtures/ + tests/e2e-ui/
```

`python make.py` (no args) is **unchanged** — the test pipeline is opt-in
and never blocks the local edit-build-codemap loop.

## How the test build differs from the release build

| Output                       | Built by                                  | Has `window.__loupeTest`? | Shipped? |
|------------------------------|-------------------------------------------|---------------------------|----------|
| `docs/index.html`            | `python scripts/build.py`                 | No                        | Yes (Pages, Sigstore-signed) |
| `docs/index.test.html`       | `python scripts/build.py --test-api`      | Yes                       | **Never** — gitignored, blocked by build gate |

`scripts/build.py --test-api` does three things:

1. Appends `src/app/app-test-api.js` to the `App.prototype` mixin chain
   (which is what installs the methods that back `window.__loupeTest`).
2. Prepends `const __LOUPE_TEST_API__ = true;` to the bundle so any future
   consumer can feature-detect.
3. Writes to `docs/index.test.html` instead of `docs/index.html`.

A defence-in-depth gate — `_check_no_test_api_in_release()` in
`scripts/build.py` — re-reads the just-emitted `docs/index.html` and
fails the build if either marker (`__LOUPE_TEST_API__` or
`__loupeTest`) is found. This is independent of the `--test-api`
flag — the only way they get into the bundle is the flag, and the
release CI path never passes it, but if someone wires the orchestrator
wrong this gate catches the leak before Pages / signing.

## The test-API surface

`docs/index.test.html` exposes:

```js
window.__loupeTest = {
  ready,                  // Promise that resolves once App.init() has run
  loadBytes(name, u8, opts?),  // Wrap bytes as File → App._loadFile → wait idle → return findings snapshot
  loadFile(file, opts?),       // Same, but caller already has a File in hand
  waitForIdle(opts?),          // Resolve when App._yaraScanInProgress is false
  dumpFindings(),              // JSON-safe snapshot of app.findings + YARA hits
  dumpResult(),                // JSON-safe snapshot of app.currentResult metadata
};
```

The mixin methods live on `App.prototype` as `_testApi*` (so they don't
collide with regular App methods if the mixin file is somehow loaded
twice). The implementation is in `src/app/app-test-api.js`.

**Read-only contract**: this surface never mutates app state outside the
file-load pipeline that real ingress uses. Every test goes through
`App._loadFile` exactly the way drag-drop / file-picker / paste do.

## Unit tests — `tests/unit/`

Loupe's unit tests use Node's stdlib `node:test` runner (Node ≥ 20). No
Vitest, no Jest, no `npm install` — `python make.py test-unit` runs
straight from a Node binary.

The harness in `tests/helpers/load-bundle.js` reads a list of source
files, concatenates them, and evaluates the result inside a fresh
`vm.Context`. This faithfully reproduces the bundle's "all globals share
one script scope" model without dragging in the App shell or any DOM
shims. Tests then read named symbols from the populated sandbox:

```js
const { loadModules, host } = require('../helpers/load-bundle.js');
const ctx = loadModules(['src/constants.js', 'src/ioc-extract.js']);
const { extractInterestingStringsCore, IOC } = ctx;
```

Cross-realm gotcha: arrays / objects returned from the vm context have
the sandbox's `Array.prototype`, not the host runtime's. Use the
`host(value)` helper before passing to `assert.deepEqual` for
JSON-safe round-trips. (See the helper's docstring for caveats.)

To add a new unit test for an existing module:

1. Find the module's external symbol dependencies (`grep -nE '^(const|function|let|var)'`
   plus a quick scan for free identifiers).
2. Pick the minimum set of `src/`-relative files that satisfy them
   (`src/constants.js` covers `IOC`, `safeRegex`, `pushIOC`, etc.).
3. Pass them to `loadModules([...])` in your test file, drop into
   `tests/unit/<module>.test.js`, and you're done.

If a new test needs a public symbol not in `DEFAULT_EXPOSE` (in
`tests/helpers/load-bundle.js`), append it to that array — it's a
no-op for any names not actually declared by the loaded files, so
keep the list permissive.

## End-to-end tests — `tests/e2e-fixtures/` + `tests/e2e-ui/`

Both suites run in Playwright with a `file://` baseURL pointing at
`docs/index.test.html`. There is no web server: the production app is
opened straight from the filesystem (matching the threat model — Pages
delivery and signed-bundle delivery both apply the same CSP).

`tests/e2e-fixtures/` loads real binaries / text from `examples/`
through `__loupeTest.loadBytes` and asserts on the canonical findings
shape. These tests catch renderer-level regressions where a fixture
that used to surface IOC X stops surfacing it.

`tests/e2e-ui/` exercises the UI ingress paths — file picker (via
`page.setInputFiles`), drag-drop (synthesised `DragEvent` carrying a
`DataTransfer` with a `File`), and paste (synthesised `ClipboardEvent`
— planned, not yet covered). Earlier project notes claimed Playwright
cannot drive a file dialog; that's incorrect — `page.setInputFiles` is
exactly the right API for the hidden `<input type="file">` Loupe wires
its drop zone around.

### Playwright provisioning

Loupe deliberately ships without a committed `package.json` /
`node_modules`. The e2e test runner sets up an **ephemeral local
install** under `dist/test-deps/` (gitignored, covered by the existing
`dist/` rule):

* `scripts/run_tests_e2e.py` writes a tiny auto-generated
  `dist/test-deps/package.json` from the version pin in that script.
* It runs `npm install --prefix dist/test-deps` once (the install
  marker file makes warm runs no-op).
* It runs `playwright install chromium` once (ditto).
* It invokes the locally-staged `playwright` CLI with `NODE_PATH`
  pointing at `dist/test-deps/node_modules` so the test files'
  `import '@playwright/test'` resolves.

Bumping Playwright is a one-line change: edit `PLAYWRIGHT_VERSION` in
`scripts/run_tests_e2e.py`, run `python make.py test-e2e`, commit.
CI must use the same pin (single source of truth).

To force a clean re-install: `rm -rf dist/test-deps`.

To pass through extra Playwright args (UI mode, grep filter):

```bash
python scripts/run_tests_e2e.py --ui
python scripts/run_tests_e2e.py --grep "phishing"
python scripts/run_tests_e2e.py tests/e2e-fixtures/email.spec.ts
```

`make.py test-e2e` doesn't forward extra args (it's a pure orchestrator
step) — invoke `scripts/run_tests_e2e.py` directly when you need them.

## What the test suite does NOT cover (yet)

This is the foundation PR. A few obvious next-step gaps:

* **Renderer breadth.** Today we cover email + encoded-payloads + pe +
  web. The other 25-ish renderers should each have at least one
  fixture-driven smoke that asserts the right IOC types land.
* **Paste path.** Drag-drop and file-picker are covered; clipboard
  paste (synthesised `ClipboardEvent`) is not.
* **Worker-side parity.** `ioc-extract.worker.js` has its own
  parity-with-host check (`scripts/check_shim_parity.py`), but no
  unit test against the worker bundle's actual output. A focused
  Playwright test can probably exercise that directly.
* **Snapshot fixtures (`expected.jsonl`).** A future addition: a JSONL
  file pinning expected `iocTypes` / risk for ~25 representative
  fixtures, with one test that loops over them. Catches
  cross-renderer regressions cheaply.
* **YARA-rule coverage.** Each YARA rule should have a positive +
  negative fixture; a per-rule test loop reading `src/rules/*.yar` is
  a small follow-up.

## Troubleshooting

* **"docs/index.test.html not found"** — run `python make.py test-build`
  first. The e2e step does not auto-build the test bundle when invoked
  in isolation (so a tight test loop doesn't pay the build cost on
  every iteration).
* **`@playwright/test` not found** — delete `dist/test-deps/` and
  re-run; the marker-file logic occasionally gets out of sync if you
  manually editted the staged `package.json`.
* **Chromium fails to launch on Linux** — set
  `PWBROWSER_DEPS=1 python make.py test-e2e` once to install the
  Chromium runtime deps via apt (needs sudo). CI already provisions
  these in the `e2e` job; this is only relevant for fresh
  workstations.
* **Test-API leaks into release bundle** —
  `_check_no_test_api_in_release` in `scripts/build.py` will fail with
  a clear message. The only path that should be triggering this is a
  misconfigured make.py / orchestrator invocation; the gate is the
  defence-in-depth net.
