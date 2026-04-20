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
  earlier ones' methods. `app-settings.js` must load **after** `app-ui.js`
  because it reuses the `THEMES` array defined there and overrides the
  unbudgeted `_copyAnalysis` call path with the configured Summary-budget
  step. Renderers load before `renderer-registry.js`, which loads before
  `app-core.js`.

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
  `ioc-conformity-audit` skill.
- **Renderer `findings.risk` starts `'low'`.** Only escalate from evidence
  pushed onto `externalRefs`. Pre-stamping `'high'` or `'medium'` produces
  false-positive risk colouring on benign samples. See the **Risk Tier
  Calibration** subsection for the canonical escalation tail.
- **Prefer `pushIOC()` over hand-rolling `interestingStrings.push(...)`.**
  `pushIOC` pins the on-wire shape and auto-emits a sibling `IOC.DOMAIN`
  when `tldts` resolves the URL to a registrable domain. If you already
  emit a manual domain row, pass `_noDomainSibling: true`.
- **`_rawText` must be `\n`-normalised.** The sidebar's click-to-focus uses
  character offsets into `_rawText`; a single CRLF misaligns every offset
  after it.
- **Long IOC lists must end with an `IOC.INFO` truncation marker.** When a
  renderer walks a large space and caps at (say) 500 entries, push exactly
  one `IOC.INFO` row after the cap explaining the reason and the cap count
  — the Summary / Share exporters read this row.

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


---

## Persistence Keys

Every user preference lives in `localStorage` under the `loupe_` prefix so
state is (a) easy to grep for, (b) easy to clear with a single filter, and
(c) auditable against this table. If you add a new key, add a row here.

| Key | Type | Written by | Values / shape | Notes |
|---|---|---|---|---|
| `loupe_theme` | string | `_setTheme()` in `src/app/app-ui.js` | one of `light` / `dark` / `midnight` / `solarized` / `mocha` / `latte` | Canonical list is the `THEMES` array at the top of `app-ui.js`. Applied before first paint by the inline `<head>` bootstrap in `scripts/build.py`; missing / invalid value falls back to OS `prefers-color-scheme`, then `dark`. |
| `loupe_summary_target` | string | `_setSummaryTarget()` in `src/app/app-settings.js` | one of `default` / `large` / `unlimited` | Drives the build-full → measure → shrink-to-fit assembler in `_buildAnalysisText()`. Character budgets `64 000` / `200 000` / `Infinity` respectively. `unlimited` short-circuits truncation entirely. |
| `loupe_yara_rules` | string | `app-yara.js` (YARA dialog "Save" action) | raw concatenated `.yar` rule text | User-uploaded rules are merged with the default ruleset at scan time. Cleared when the user clicks "Reset to defaults" in the YARA dialog. |

**Adding a new key**

1. Use the `loupe_<feature>` prefix.
2. Read and write through a named accessor (`_getMyThing()` / `_setMyThing(value)`)
   in the owning `app-*.js` file so the write site is auditable.
3. Validate on read — never trust the stored value. If it's outside the
   expected range, fall back to a hard-coded default.
4. Add a row to this table in the same PR.

---

## Renderer Contract

Renderers are self-contained classes exposing a static `render(file, arrayBuffer, app)` that returns a DOM element (the "view container"). To participate in sidebar click-to-highlight (the yellow/blue `<mark>` cycling users see when clicking an IOC or YARA hit) a text-based renderer should attach the following optional hooks to the container element it returns:

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
3. **Never silently downgrade.** If your renderer already has a hand-rolled
   escalation path, gate the calibration block with a monotonic rank check
   so later evidence only ever lifts the tier:
   ```js
   const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
   if ((rank[tier] || 0) > (rank[f.risk] || 0)) f.risk = tier;
   ```
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
   `IOC.FINGERPRINT`.
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
   - `this._downloadText(text, filename, mime)` / `this._downloadJson(obj, filename)` / `this._exportFilename(suffix, ext)` — only when the output is genuinely a file (e.g. `💾 Save raw file`). Never call `URL.createObjectURL` directly.
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
5. **Rebuild and test** — `python scripts/build.py`, then open
   `docs/index.html` and click through every tile in ⚙ Settings → Theme.
6. **Regenerate the code map** — `python scripts/generate_codemap.py`.

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
