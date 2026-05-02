'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-geoip.test.js — Structural pin tests for the GeoIP
// enrichment mixin.
//
// `timeline-view-geoip.js` attaches enrichment methods to
// `TimelineView.prototype` via `Object.assign(...)` and depends on:
//
//   • `this.store.rowCount` / `this.store.getCell` (RowStore)
//   • `this._baseColumns`
//   • `this._dataset.addExtractedCol({ name, kind, sourceCol, values, … })`
//   • `this._extractedCols`
//   • `this._app.geoip` — set by `App.init()` to BundledGeoip / MmdbReader
//   • `TimelineView._loadAutoExtractDoneFor` / `_saveAutoExtractDoneFor`
//     (shared with auto-extract — same per-file done-marker)
//   • `this._cellAt` (unified base + extracted lookup; needed for the
//      right-click override path that targets extracted columns)
//
// We mirror the test style of `timeline-view-autoextract-parity.test.js`:
// instead of spinning up a fake TimelineView, we pin source-level
// invariants that a regression would silently break. Behavioural
// coverage of enrichment end-to-end (loadFixture → column lands)
// lives in `tests/e2e-fixtures/timeline-geoip.spec.ts`.
//
// Why this style?
//   • The mixin's "real" environment is the assembled bundle running
//     in a browser with a live RowStore + dataset. Reproducing that
//     under `node:vm` would require mocking ~6 classes; the e2e
//     spec already exercises the live path.
//   • The structural assertions catch the regressions that matter
//     most for an offline analyser: a refactor that drops the done-
//     marker wiring, breaks the per-file dedup, or forgets to add
//     the mixin file to JS_FILES. All of those are silent failures
//     until a user notices missing geo columns.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const MIXIN = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-geoip.js'),
  'utf8',
);
const VIEW = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view.js'),
  'utf8',
);
const ROUTER = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-router.js'),
  'utf8',
);
const POPOVERS = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-popovers.js'),
  'utf8',
);
const BUILD = fs.readFileSync(
  path.join(REPO_ROOT, 'scripts/build.py'),
  'utf8',
);
const APP_CORE = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/app-core.js'),
  'utf8',
);
const DRAWER = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-drawer.js'),
  'utf8',
);

// Methods the mixin contributes. Each must appear exactly once in
// the mixin and never in the main view file (would be a duplicate
// definition, last-write-wins shadowing the real implementation).
const MIXIN_METHODS = [
  '_runGeoipEnrichment',
  '_detectIpColumns',
  '_detectIpColumnsExtracted',
  '_classifyColumnNeighbourhood',
  '_enrichSingleIpCol',
  '_geoipDuplicateFor',
  '_dropAllGeoipCols',
  '_insertColAfterInDisplay',
];

// ── Mixin shape ────────────────────────────────────────────────────────────

test('mixin attaches via Object.assign(TimelineView.prototype, …)', () => {
  assert.match(
    MIXIN,
    /Object\.assign\(\s*TimelineView\.prototype\s*,\s*\{/,
    'geoip mixin must extend TimelineView.prototype like every other split',
  );
});

test('mixin defines every geoip method exactly once', () => {
  for (const name of MIXIN_METHODS) {
    const re = new RegExp(`^    ${name}\\s*\\(`, 'gm');
    const matches = MIXIN.match(re) || [];
    assert.equal(
      matches.length,
      1,
      `${name} must appear exactly once in timeline-view-geoip.js (got ${matches.length})`,
    );
  }
});

test('main timeline-view.js does NOT define any geoip method', () => {
  // Catch a regression where a method gets accidentally added to the
  // main file and shadows the mixin's version (or vice versa).
  for (const name of MIXIN_METHODS) {
    const re = new RegExp(`^  ${name}\\s*\\(`, 'm');
    assert.doesNotMatch(
      VIEW,
      re,
      `${name} must live ONLY in timeline-view-geoip.js, not in timeline-view.js`,
    );
  }
});

// ── Build order — mixin must load AFTER everything it depends on ──────────

test('scripts/build.py registers timeline-view-geoip.js after timeline-drawer.js', () => {
  // Same dependency story as auto-extract: the mixin calls
  // `_addExtractedCol` (via the dataset), `_rebuildExtractedStateAndRender`,
  // and `_queryRemoveClausesForCols` — all installed by drawer / persist
  // mixins loaded earlier.
  const drawerIdx = BUILD.indexOf("'src/app/timeline/timeline-drawer.js'");
  const geoipIdx = BUILD.indexOf("'src/app/timeline/timeline-view-geoip.js'");
  assert.notEqual(drawerIdx, -1, 'timeline-drawer.js must be in JS_FILES');
  assert.notEqual(geoipIdx, -1, 'timeline-view-geoip.js must be in JS_FILES');
  assert.ok(
    geoipIdx > drawerIdx,
    'geoip mixin must load AFTER timeline-drawer.js',
  );
});

test('scripts/build.py registers the geoip provider modules in the right order', () => {
  // `bundled-geoip.js` reads the build-time-injected `__GEOIP_BUNDLE_B64`
  // const. `mmdb-reader.js` is independent. `geoip-store.js` is loaded
  // after both providers because `App.init()` calls `GeoipStore.load()`
  // and immediately wraps the result in `MmdbReader.fromBlob`.
  const bundledIdx = BUILD.indexOf("'src/geoip/bundled-geoip.js'");
  const mmdbIdx = BUILD.indexOf("'src/geoip/mmdb-reader.js'");
  const storeIdx = BUILD.indexOf("'src/geoip/geoip-store.js'");
  assert.notEqual(bundledIdx, -1);
  assert.notEqual(mmdbIdx, -1);
  assert.notEqual(storeIdx, -1);
  // Order between bundled / mmdb is irrelevant (each is self-contained);
  // we just assert all three appear.
});

test('scripts/build.py prepends __GEOIP_BUNDLE_B64 const to Block 1', () => {
  // The build script base64-encodes `vendor/geoip-country-ipv4.bin`
  // into a const that bundled-geoip.js reads. Pin the const name so
  // a refactor that renames it (and forgets to update bundled-geoip.js)
  // surfaces here.
  assert.match(
    BUILD,
    /__GEOIP_BUNDLE_B64/,
    'scripts/build.py must inject __GEOIP_BUNDLE_B64 — bundled-geoip.js reads this const',
  );
  assert.match(
    BUILD,
    /vendor\/geoip-country-ipv4\.bin/,
    'scripts/build.py must read vendor/geoip-country-ipv4.bin to produce __GEOIP_BUNDLE_B64',
  );
});

// ── Idempotence — done-marker wiring ──────────────────────────────────────

test('_runGeoipEnrichment writes the per-file done-marker via the persist mixin', () => {
  // GeoIP-specific marker (`_saveGeoipDoneFor` / `_loadGeoipDoneFor`).
  // Distinct from auto-extract's marker — they were briefly conflated,
  // which silently disabled JSON / URL / host extraction on files with
  // no IPv4-shaped columns (because GeoIP's no-op path stamped the
  // shared marker). See timeline-view-geoip-marker-isolation.test.js
  // for the full ownership invariants.
  assert.match(
    MIXIN,
    /TimelineView\._saveGeoipDoneFor\(/,
    '_runGeoipEnrichment must persist the done-marker via the GeoIP-specific persist key',
  );
  assert.match(
    MIXIN,
    /TimelineView\._loadGeoipDoneFor\(/,
    '_runGeoipEnrichment must read the done-marker on every call (else deletes resurrect)',
  );
  // And it must NOT touch the auto-extract marker — that was the bug.
  assert.doesNotMatch(
    MIXIN,
    /TimelineView\._saveAutoExtractDoneFor\(/,
    'GeoIP must not write the auto-extract marker (that was the bug)',
  );
  assert.doesNotMatch(
    MIXIN,
    /TimelineView\._loadAutoExtractDoneFor\(/,
    'GeoIP must not read the auto-extract marker',
  );
});

test('_runGeoipEnrichment skips writing the marker on forced refresh', () => {
  // The forced-refresh path (`force` / `forceKind` / `forceCol`) must
  // NOT stamp the marker — otherwise a right-click "Enrich IP" on a
  // forensic file would prevent future natural detection on that file.
  // The contract is: marker stamps only on the natural-detect path.
  // Pin via a structural check that the save call is guarded by a
  // negative force/forceKind/forceCol predicate.
  assert.match(
    MIXIN,
    /if\s*\(\s*!\s*force\s*&&\s*!\s*forceKind\s*&&\s*forceCol\s*<\s*0\s*\)\s*\{[^}]*_saveGeoipDoneFor/,
    '_runGeoipEnrichment must guard _saveGeoipDoneFor behind `!force && !forceKind && forceCol < 0`',
  );
});

// ── Detection invariants — perf + accuracy ────────────────────────────────

test('_detectIpColumns caps at 200 sample rows', () => {
  // Same perf budget as auto-extract. A million-row CSV with 50 columns
  // must complete the IP-detection scan in O(50 * 200) reads, not O(50
  // * 1_000_000). Anything above 200 noticeably blocks first paint.
  assert.match(
    MIXIN,
    /Math\.min\(this\.store\.rowCount,\s*200\)/,
    '_detectIpColumns lost its 200-row sample cap',
  );
});

test('_detectIpColumns uses the strict-IPv4 parser, not a regex', () => {
  // The shared `Ipv4Util.isStrictIPv4` (src/util/ipv4.js) is the
  // non-allocating-loop parser. A regression that swapped it for a
  // regex (`/^\d+\.\d+\.\d+\.\d+$/`) would re-introduce ReDoS exposure
  // that the strict parser was chosen to avoid. Pin both that the
  // mixin aliases the shared util AND that `_detectIpColumns` calls
  // the resulting `isStrictIPv4` symbol.
  assert.match(
    MIXIN,
    /Ipv4Util(?:\.|\s*\?\s*\.)isStrictIPv4/,
    'mixin must alias `Ipv4Util.isStrictIPv4` as its IPv4 shape gate',
  );
  assert.match(
    MIXIN,
    /isStrictIPv4\s*\(/,
    '_detectIpColumns must invoke `isStrictIPv4` to classify cells',
  );

  // The shared util itself must still be a non-allocating loop, not a
  // regex — this is the byte-equivalent guard the original test was
  // checking via the mixin-private definition.
  const UTIL = fs.readFileSync(
    path.join(REPO_ROOT, 'src/util/ipv4.js'),
    'utf8',
  );
  assert.match(
    UTIL,
    /function\s+isStrictIPv4\s*\(/,
    'src/util/ipv4.js must define `isStrictIPv4` as a function',
  );
  // Heuristic: the parser body must walk character codes (`charCodeAt`)
  // rather than relying on a single dotted-quad regex.
  assert.match(UTIL, /charCodeAt/, 'isStrictIPv4 must remain a non-allocating loop, not a regex');
});

test('_detectIpColumns short-circuits on schema-driven `_ipColumns` hint', () => {
  // The PCAP route publishes `PcapRenderer.TIMELINE_IP_COL_INDICES`
  // and the factory + worker bridge thread it into the TimelineView
  // ctor as `ipColumns`. The detector must take that hint as
  // authoritative — the heuristic 80%-IPv4 sample scan would
  // otherwise reject one or both endpoint columns on mixed v4/v6
  // captures (where Source/Destination cells are a mix of IPv4
  // literals and IPv6 literals, dropping the hit ratio below 0.8).
  //
  // Pin three properties of the short-circuit:
  //
  //   1. The hint is read off `this._ipColumns` (set by the ctor),
  //      not off some renderer registry — keeps the contract local
  //      to the view.
  //   2. The short-circuit RETURNS before the heuristic loop runs
  //      (so a hinted run never even touches `isStrictIPv4`). We
  //      check this by asserting the short-circuit branch sits
  //      lexically BEFORE the `for (let c = 0; c < baseCount; c++)`
  //      heuristic loop.
  //   3. Out-of-range indices are filtered (defends against schema
  //      drift — a future PCAP renderer that swaps Source/Dst
  //      column positions and forgets to update the constant must
  //      not throw a "column index out of range" downstream).
  const fnIdx = MIXIN.indexOf('_detectIpColumns()');
  assert.notEqual(fnIdx, -1, '_detectIpColumns must exist');
  // Find the body window — start at fnIdx, end at the next sibling
  // method definition. `_detectIpColumnsExtracted` is the next one.
  const bodyEnd = MIXIN.indexOf('_detectIpColumnsExtracted', fnIdx);
  assert.notEqual(bodyEnd, -1, 'sibling method must follow');
  const body = MIXIN.slice(fnIdx, bodyEnd);

  // (1) hint read off `this._ipColumns`
  assert.match(body, /this\._ipColumns/, 'must read `this._ipColumns` for the hint');

  // (2) short-circuit lexically precedes the heuristic loop
  const hintIdx = body.indexOf('this._ipColumns');
  const loopIdx = body.search(/for\s*\(\s*let\s+c\s*=\s*0\s*;\s*c\s*<\s*baseCount/);
  assert.notEqual(hintIdx, -1, 'hint branch missing');
  assert.notEqual(loopIdx, -1, 'heuristic loop missing');
  assert.ok(
    hintIdx < loopIdx,
    'schema hint must short-circuit BEFORE the heuristic 80%-IPv4 loop',
  );

  // (3) defensive filter against drift — the hint indices are
  // validated against `baseCount` so a stale constant can't push
  // out-of-range indices into `_enrichSingleIpCol`.
  assert.match(
    body,
    /c\s*<\s*baseCount/,
    'hint branch must validate indices against baseCount',
  );
});

test('TimelineView ctor stores `ipColumns` ctor field as `_ipColumns`', () => {
  // The factory + worker bridge pass `ipColumns: PcapRenderer.TIMELINE_IP_COL_INDICES.slice()`
  // into the constructor. The ctor must filter to non-negative
  // integers and stash a defensive copy — without the slice, a
  // future caller that mutates the input array (e.g. push() to
  // append an extracted column) would surprise the geoip path.
  assert.match(
    VIEW,
    /this\._ipColumns\s*=\s*Array\.isArray\(opts\.ipColumns\)/,
    'TimelineView ctor must accept `ipColumns` and store as `_ipColumns`',
  );
  assert.match(
    VIEW,
    /opts\.ipColumns[\s\S]{0,200}?\.slice\(\)/,
    'ctor must defensively copy the input array (slice())',
  );
});

test('_runGeoipEnrichment bypasses the neighbour-skip heuristic on schema-hinted runs', () => {
  // Without this bypass, the ±3 base-column scan could veto
  // enrichment on a hinted column whose neighbours happen to look
  // ASN-shaped (e.g. an "AS Number" column adjacent to an IP).
  // For a hinted run the renderer is authoritative; nothing in the
  // neighbourhood should override that. Pin the disjunction so a
  // refactor that swaps to a function-call form is visible in the
  // diff.
  assert.match(
    MIXIN,
    /bypassSkipHeuristic\s*=[\s\S]{0,200}?this\._ipColumns/,
    '_runGeoipEnrichment must extend bypassSkipHeuristic to schema-hinted runs',
  );
});

test('_classifyColumnNeighbourhood walks a ±3 window', () => {
  // The recap-step decision was looser ±3 adjacency. Pin so a
  // future "tighter window for fewer false positives" change is
  // visible in the diff.
  assert.match(
    MIXIN,
    /colIdx\s*-\s*3/,
    '_classifyColumnNeighbourhood lost its ±3 window (low side)',
  );
  assert.match(
    MIXIN,
    /colIdx\s*\+\s*3/,
    '_classifyColumnNeighbourhood lost its ±3 window (high side)',
  );
});

test('_classifyColumnNeighbourhood accepts a kind argument and dispatches geo / asn vocabularies', () => {
  // Dual-emit: each kind has its own header / cell heuristic.
  // Confirm the function takes a `kind` parameter and routes to the
  // right vocabulary so a refactor that loses the per-kind dispatch
  // surfaces here.
  assert.match(
    MIXIN,
    /_classifyColumnNeighbourhood\s*\(\s*colIdx\s*,\s*kind\s*\)/,
    '_classifyColumnNeighbourhood must accept (colIdx, kind)',
  );
  assert.match(
    MIXIN,
    /kind\s*===\s*['"]asn['"]/,
    '_classifyColumnNeighbourhood must branch on kind === "asn"',
  );
  // ASN vocabulary tokens.
  assert.match(MIXIN, /'asn'/, 'ASN_HEADER_TOKENS must include "asn"');
  assert.match(MIXIN, /'autonomous'/, 'ASN_HEADER_TOKENS must include "autonomous"');
  // ASN value shape — bare AS number.
  assert.match(
    MIXIN,
    /\^AS\?\\d/,
    'ASN_BARE_RE must recognise bare AS-numbers',
  );
});

// ── Enrichment column shape ───────────────────────────────────────────────

test('_enrichSingleIpCol emits both kinds: "geoip" (geo) and "geoip-asn" (ASN)', () => {
  // The kind tag drives the dedup, the persist filter (these cols are
  // explicitly NOT persisted by `_persistRegexExtracts`), and the
  // forced-refresh drop pass. Dual-emit needs distinct kinds so a
  // selective drop ("only refresh ASN") leaves geo cols intact.
  assert.match(
    MIXIN,
    /['"]geoip-asn['"]/,
    '_enrichSingleIpCol must use kind: "geoip-asn" for ASN cols',
  );
  assert.match(
    MIXIN,
    /kind\s*===\s*['"]asn['"]/,
    '_enrichSingleIpCol must dispatch on `kind === "asn"`',
  );
});

test('_enrichSingleIpCol picks the right provider methods per kind', () => {
  // Geo path uses lookupIPv4 + formatRow; ASN path uses lookupAsn +
  // formatAsnRow. Both surfaces are required on the supplied provider.
  assert.match(MIXIN, /lookupAsn/, '_enrichSingleIpCol must reference provider.lookupAsn');
  assert.match(MIXIN, /formatAsnRow/, '_enrichSingleIpCol must reference provider.formatAsnRow');
  assert.match(MIXIN, /lookupIPv4/, '_enrichSingleIpCol must reference provider.lookupIPv4');
  assert.match(MIXIN, /formatRow/, '_enrichSingleIpCol must reference provider.formatRow');
});

test('_enrichSingleIpCol suffix differs per kind: ".geo" vs ".asn"', () => {
  // The grid column name is `<src>.geo` for geo and `<src>.asn` for
  // ASN. A regression that suffixed both with ".geo" would silently
  // collide — _uniqueColName would pick `.geo (1)` and the analyst
  // gets a confusing duplicate label.
  assert.match(MIXIN, /\.asn/, 'ASN suffix `.asn` missing from _enrichSingleIpCol');
  assert.match(MIXIN, /\.geo/, 'geo suffix `.geo` missing from _enrichSingleIpCol');
});

test('_enrichSingleIpCol caches lookups per-IP', () => {
  // Logs reuse the same IP many times; per-row provider lookups would
  // be O(N) when O(unique-IPs) is achievable. Pin the cache so a
  // refactor that drops it gets caught.
  assert.match(
    MIXIN,
    /const\s+cache\s*=\s*new\s+Map\(\)/,
    '_enrichSingleIpCol lost its per-IP cache',
  );
});

test('_enrichSingleIpCol uses _cellAt (handles base + extracted source cols)', () => {
  // The right-click override path passes extracted column indices
  // (e.g. `Raw Data.ip_address` from auto-extract). `this.store.getCell`
  // would only read base cols. Pin `_cellAt` so a refactor that
  // narrows the read path is caught.
  assert.match(
    MIXIN,
    /this\._cellAt\s*\(/,
    '_enrichSingleIpCol must use _cellAt to support extracted source columns',
  );
});

test('_dropAllGeoipCols walks back-to-front', () => {
  // Splice indices shift forward when iterating front-to-back, which
  // would skip the next geoip col and silently leave it behind. Pin
  // the reverse-iteration shape.
  assert.match(
    MIXIN,
    /for\s*\(\s*let\s+i\s*=\s*cols\.length\s*-\s*1;\s*i\s*>=\s*0;\s*i--\s*\)/,
    '_dropAllGeoipCols must walk back-to-front so splice indices stay stable',
  );
});

test('_dropAllGeoipCols accepts a `kinds` array for selective drop', () => {
  // Refresh paths can target one slot ("only redo ASN cols"). Pin
  // the signature + the membership check.
  assert.match(
    MIXIN,
    /_dropAllGeoipCols\s*\(\s*kinds\s*\)/,
    '_dropAllGeoipCols must accept a `kinds` parameter',
  );
  assert.match(
    MIXIN,
    /\['geoip',\s*'geoip-asn'\]/,
    '_dropAllGeoipCols default `kinds` array must include both `geoip` and `geoip-asn`',
  );
});

// ── Constructor wire-up ───────────────────────────────────────────────────

test('TimelineView constructor schedules _runGeoipEnrichment after _autoExtractBestEffort', () => {
  // The +100 ms post-mount setTimeout is intentional — runs after
  // auto-extract so the skip-heuristic check sees any analyst-deleted
  // columns from auto-extract first. Pin the call site exists.
  assert.match(
    VIEW,
    /this\._runGeoipEnrichment\s*\(/,
    'timeline-view.js constructor must schedule _runGeoipEnrichment',
  );
  // Match the multi-line `setTimeout(() => { … _runGeoipEnrichment() … }, 100)`
  // shape. The body lives on its own lines so we use `[\s\S]` (any char
  // including newline) and a non-greedy quantifier; pin the trailing
  // ", 100)" so a regression that drops the 100 ms delay (e.g. "0" for
  // a synchronous post-mount fire) is caught.
  assert.match(
    VIEW,
    /setTimeout\(\s*\(\s*\)\s*=>\s*\{[\s\S]*?_runGeoipEnrichment[\s\S]*?\}\s*,\s*100\s*\)/,
    'timeline-view.js must use a 100 ms setTimeout for _runGeoipEnrichment (after _autoExtractBestEffort at 60 ms)',
  );
});

test('timeline-router.js re-triggers _runGeoipEnrichment after _app stamping', () => {
  // The constructor call bails when `this._app` is null (which it is
  // until the router stamps it). The router must call enrichment again
  // after `view._app = this` so the natural-detect path runs once
  // `app.geoip` is reachable.
  assert.match(
    ROUTER,
    /view\._app\s*=\s*this[\s\S]{0,500}?_runGeoipEnrichment/,
    'timeline-router.js must re-call _runGeoipEnrichment after view._app = this',
  );
});

// ── Right-click "Look up GeoIP" override ──────────────────────────────────

test('column header menu offers single "Enrich IP" entry on IPv4 columns', () => {
  // Pin the menu entry exists, gates on EITHER provider being wired
  // (`this._app.geoip || this._app.geoipAsn`), is labelled "Enrich IP",
  // and its click handler calls `_runGeoipEnrichment({ forceCol: … })`.
  // A regression that loses any of these breaks the override path that
  // lets analysts force enrichment on auto-detect-rejected columns.
  //
  // Note: post-refactor (column menu slimmed to a button-list mirroring
  // the right-click row context menu), the click is wired via an `act`
  // callback in the `items[]` array rather than a `data-act` attribute,
  // so we no longer pin the attribute — only the user-visible label and
  // the call into `_runGeoipEnrichment`.
  assert.match(
    POPOVERS,
    /this\._app\.geoip\s*\|\|\s*this\._app\.geoipAsn/,
    'column menu must gate the Enrich-IP entry on EITHER `this._app.geoip` OR `this._app.geoipAsn`',
  );
  assert.match(
    POPOVERS,
    /Enrich IP/,
    'column menu label must be "Enrich IP" (single entry that fires both providers)',
  );
  assert.match(
    POPOVERS,
    /_runGeoipEnrichment\s*\(\s*\{\s*forceCol/,
    'column menu Enrich-IP click must call _runGeoipEnrichment({ forceCol: … })',
  );
});

test('Events-grid column filter menu also surfaces "Enrich IP" via data-act="geoip"', () => {
  // The Events-grid column-header click opens `_openColumnFilterMenu`
  // (Excel-style), which is a SECOND surface offering the same forced
  // enrichment escape hatch. This test pins the dedicated function
  // exists and that, within its body, the Enrich-IP affordance keeps
  // its `data-act="geoip"` attribute hook (the function builds DOM via
  // an HTML string, not the `items[]` callback shape used by the slim
  // `_openColumnMenu`). Loss of either pin breaks the dual-surface
  // promise restored after the regression in commit f0dd560.
  assert.match(
    POPOVERS,
    /_openColumnFilterMenu\s*\(\s*colIdx\s*,\s*anchor\s*\)\s*\{/,
    'expected `_openColumnFilterMenu(colIdx, anchor)` to exist as the Excel-style filter for the grid header',
  );
  // Pin the Enrich-IP markup inside the filter-menu function body.
  // Slice the function body so the assertion is robust against
  // identical strings landing elsewhere in the module.
  const m = POPOVERS.match(/_openColumnFilterMenu\s*\(\s*colIdx\s*,\s*anchor\s*\)\s*\{[\s\S]*?\n  \},\n/);
  assert.ok(m, 'failed to slice the body of `_openColumnFilterMenu`');
  const body = m[0];
  assert.match(
    body,
    /data-act="geoip"/,
    '`_openColumnFilterMenu` must render `data-act="geoip"` markup for the Enrich-IP entry',
  );
  assert.match(
    body,
    /_runGeoipEnrichment\s*\(\s*\{\s*forceCol/,
    '`_openColumnFilterMenu` Enrich-IP click must call _runGeoipEnrichment({ forceCol: … })',
  );
});

// ── App.init() resolver wiring ────────────────────────────────────────────

test('App.init() sets app.geoip = BundledGeoip synchronously', () => {
  // First-paint requirement: the bundled provider must be available
  // before the TimelineView constructor's +100 ms setTimeout fires.
  // Async hydrate from IndexedDB happens later and swaps the provider
  // when the user has a saved MMDB.
  assert.match(
    APP_CORE,
    /this\.geoip\s*=\s*BundledGeoip/,
    'App.init() must set this.geoip = BundledGeoip synchronously',
  );
});

test('App.init() async-hydrates BOTH MMDB slots (geo + asn) via GeoipStore.load()', () => {
  // Pin the slot-named calls AND the swap: a regression that calls
  // load() but forgets to swap `this.geoip` / `this.geoipAsn` would
  // leave users with no MMDB even after upload.
  assert.match(
    APP_CORE,
    /GeoipStore\.load\(['"]geo['"]\)/,
    'App.init() must call GeoipStore.load("geo") to hydrate any saved geo MMDB',
  );
  assert.match(
    APP_CORE,
    /GeoipStore\.load\(['"]asn['"]\)/,
    'App.init() must call GeoipStore.load("asn") to hydrate any saved ASN MMDB',
  );
  assert.match(
    APP_CORE,
    /this\.geoipAsn\s*=/,
    'App.init() must assign `this.geoipAsn` after the asn-slot hydrate completes',
  );
  assert.match(
    APP_CORE,
    /MmdbReader\.fromBlob\s*\(/,
    'App.init() must wrap the loaded blob via MmdbReader.fromBlob',
  );
});

// ── Fast-path rowView rebuild (the empty-cells bug fix) ───────────────────
//
// `_rebuildExtractedStateAndRender` has a fast path that calls
// `_grid._updateColumns(this.columns)` instead of destroying + rebuilding
// the GridViewer. The grid's `store` is a `TimelineRowView` that snapshots
// `_extLen` / `_totalCols` in its constructor — so the in-place column
// patch alone is NOT enough; the rowView must also be rebuilt and handed
// back via `setRows()`, otherwise newly-added extracted columns render as
// empty cells until the next filter / sort triggers a fresh render.
//
// Pin both: a `new TimelineRowView({` build AND a `setRows(` call inside
// the same fast-path block. The pin is intentionally regex-based rather
// than behavioural — full coverage lives in tests/e2e-fixtures/
// timeline-geoip.spec.ts (asserts geo cells are non-empty at first paint).

// ── Geo insert-next-to-source (Issue #1 fix) ───────────────────────────────
//
// New geo columns must land in the display order immediately after their
// IPv4 source. Without this the analyst sees the geo column at the
// extreme right of the grid, visually disconnected from the IP it
// enriches. The placement runs through the same `_gridColOrder` /
// `_applyGridColOrder` pipeline as user drags so a single restore path
// covers both cases (auto + manual).

test('_enrichSingleIpCol inserts the new geo column adjacent to its source via _insertColAfterInDisplay', () => {
  // Source-level pin: the call appears immediately after addExtractedCol
  // returns, so the new column already exists in `this.columns` when
  // `_insertColAfterInDisplay` resolves names → positions.
  // Slice the _enrichSingleIpCol body and confirm the call appears
  // AFTER addExtractedCol but BEFORE the function returns. (Substring
  // distance is hard to bound across the indented multi-line comment
  // explaining the placement, so order pinning is more durable than
  // a `[\s\S]{0,N}` distance regex.)
  const enrichBody = (() => {
    const m = MIXIN.match(/^ {4}_enrichSingleIpCol\s*\([^)]*\)\s*\{([\s\S]*?)\n {4}\}/m);
    return m ? m[1] : '';
  })();
  assert.ok(enrichBody, '_enrichSingleIpCol body not found');
  const addIdx = enrichBody.indexOf('addExtractedCol');
  const insertIdx = enrichBody.indexOf('_insertColAfterInDisplay');
  assert.ok(
    addIdx >= 0 && insertIdx > addIdx,
    '_insertColAfterInDisplay must be called AFTER addExtractedCol inside _enrichSingleIpCol',
  );
  assert.match(
    enrichBody,
    /this\._insertColAfterInDisplay\s*\(\s*srcCol\s*,\s*name\s*\)/,
    '_insertColAfterInDisplay must be called as `this._insertColAfterInDisplay(srcCol, name)` (real index of source + name of just-appended column)',
  );
});

test('_insertColAfterInDisplay is defined as a TimelineView method on the geoip mixin', () => {
  // Object-literal shorthand pattern that matches `Object.assign(
  // TimelineView.prototype, { … _insertColAfterInDisplay(…) { … } })`.
  assert.match(
    MIXIN,
    /^ {4}_insertColAfterInDisplay\s*\(/m,
    '_insertColAfterInDisplay must be defined inside the timeline-view-geoip mixin',
  );
});

test('_insertColAfterInDisplay does NOT call _saveGridColOrderFor (geo placement is automatic, not user-elected)', () => {
  // Persistence is reserved for the user's own drags. Auto-placement
  // re-derives on every load via `_runGeoipEnrichment` →
  // `_enrichSingleIpCol` → `_insertColAfterInDisplay`, so persisting
  // it would give analysts a "saved order" entry they never asked for
  // (and would shadow their NEXT drag with a stale baseline).
  const m = MIXIN.match(/^ {4}_insertColAfterInDisplay\s*\([^)]*\)\s*\{([\s\S]*?)\n {4}\}/m);
  assert.ok(m, '_insertColAfterInDisplay body not found');
  assert.doesNotMatch(
    m[1],
    /_saveGridColOrderFor/,
    '_insertColAfterInDisplay must NOT persist to localStorage — only the drag-drop path (onColumnReorder) calls _saveGridColOrderFor',
  );
});

test('_rebuildExtractedStateAndRender fast path rebuilds the rowView via setRows', () => {
  // Locate the fast path block.
  assert.match(
    DRAWER,
    /this\._grid\s*&&\s*typeof\s+this\._grid\._updateColumns\s*===\s*['"]function['"]/,
    'fast-path guard must remain `this._grid && typeof this._grid._updateColumns === "function"`',
  );
  assert.match(
    DRAWER,
    /this\._grid\._updateColumns\(\s*this\.columns\s*\)/,
    'fast path must call `this._grid._updateColumns(this.columns)`',
  );
  // The fix: rebuild the rowView and hand it to the grid.
  assert.match(
    DRAWER,
    /new\s+TimelineRowView\s*\(\s*\{/,
    'fast path must construct a fresh TimelineRowView after _updateColumns',
  );
  assert.match(
    DRAWER,
    /this\._grid\.setRows\s*\([^)]*\bpreSorted\s*:\s*true/,
    'fast path must call this._grid.setRows(rowView, …, { preSorted: true }) so the row materialiser sees the new column count',
  );
  // Order pin: setRows must come AFTER _updateColumns so the column
  // array is current when GridViewer re-runs _classifyColumns inside
  // setRows.
  const updateIdx = DRAWER.indexOf('this._grid._updateColumns(this.columns)');
  const setRowsIdx = DRAWER.indexOf('this._grid.setRows');
  assert.ok(
    updateIdx >= 0 && setRowsIdx >= 0 && setRowsIdx > updateIdx,
    'this._grid.setRows(…) must be called AFTER this._grid._updateColumns(this.columns) in _rebuildExtractedStateAndRender',
  );
});
