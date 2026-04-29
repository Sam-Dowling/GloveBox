'use strict';
// ════════════════════════════════════════════════════════════════════════════
// sidebar-ip-enrichment.test.js — structural pin tests for the geo / ASN
// enrichment lines under IOC.IP rows in the sidebar IOCs table.
//
// The "real" behavioural test would spin up a TimelineView-style fake App
// and walk the rendered DOM; that's brittle and requires mocking ~5
// classes. Mirroring `timeline-view-geoip.test.js`, this file pins
// source-level invariants that a regression would silently break:
//
//   • `_enrichIpForExport(ip)` is defined on App.prototype via extendApp
//     in app-sidebar.js.
//   • `_renderFindingsTableSection` calls it for IOC.IP rows.
//   • Render path emits `.ioc-geo-enrich` divs (CSS class).
//   • `_resetEnrichIpCache` is invoked at the start of `_renderSidebar`.
//   • `_collectIocs` resets the cache and attaches geo / asn for IPs.
//   • The IOC CSV header gained the geo_*/asn_* columns.
//   • The Summary IOCs markdown table gained an `Enrichment` column.
//   • The reEnrich() callback in app-core.js triggers a sidebar re-render
//     when an MMDB hydrates.
//   • `src/util/ipv4.js` is wired into JS_FILES BEFORE app-sidebar.js,
//     app-ui.js, and timeline-view-geoip.js (load-order is load-bearing).
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const SIDEBAR = fs.readFileSync(path.join(REPO_ROOT, 'src/app/app-sidebar.js'), 'utf8');
const APP_UI  = fs.readFileSync(path.join(REPO_ROOT, 'src/app/app-ui.js'), 'utf8');
const APP_CORE = fs.readFileSync(path.join(REPO_ROOT, 'src/app/app-core.js'), 'utf8');
const BUILD = fs.readFileSync(path.join(REPO_ROOT, 'scripts/build.py'), 'utf8');

test('_enrichIpForExport is defined exactly once on App.prototype via extendApp', () => {
  const re = /^\s*_enrichIpForExport\s*\(/gm;
  const matches = SIDEBAR.match(re) || [];
  assert.equal(matches.length, 1, '_enrichIpForExport must be defined exactly once in app-sidebar.js');
});

test('_enrichIpForExport gates on Ipv4Util.isStrictIPv4 + isPrivateIPv4', () => {
  // Pin the validator chain: strict-IPv4 first, then private-range
  // skip. A regression that drops either filter would either crash on
  // non-string input or emit empty cells for RFC1918 / loopback IPs.
  assert.match(SIDEBAR, /Ipv4Util\.isStrictIPv4/, '_enrichIpForExport must call Ipv4Util.isStrictIPv4');
  assert.match(SIDEBAR, /Ipv4Util\.isPrivateIPv4/, '_enrichIpForExport must skip private/loopback/CGNAT IPs');
});

test('_enrichIpForExport reads both geo and ASN provider surfaces', () => {
  // Pin the dual-provider wiring — geo via `lookupIPv4 + formatRow`,
  // ASN via `lookupAsn + formatAsnRow`. Same contract as the Timeline
  // mixin (see timeline-view-geoip.js header).
  const helper = SIDEBAR.match(/_enrichIpForExport\s*\(ip\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(helper, '_enrichIpForExport body must be locatable');
  const body = helper[0];
  assert.match(body, /this\.geoip/, '_enrichIpForExport must read this.geoip');
  assert.match(body, /this\.geoipAsn/, '_enrichIpForExport must read this.geoipAsn');
  assert.match(body, /lookupIPv4/, '_enrichIpForExport must call lookupIPv4 on the geo provider');
  assert.match(body, /lookupAsn/, '_enrichIpForExport must call lookupAsn on the ASN provider');
  assert.match(body, /formatRow/, '_enrichIpForExport must call formatRow on the geo provider');
  assert.match(body, /formatAsnRow/, '_enrichIpForExport must call formatAsnRow on the ASN provider');
});

test('_renderSidebar resets the IP enrichment cache at the start of every render', () => {
  // Without this the cache survives across renders and a re-render
  // after an MMDB hydrate would still emit the bundled-only data.
  const renderBlock = SIDEBAR.match(/_renderSidebar\s*\([^)]*\)\s*\{[\s\S]*?_clearEncodedHighlight[\s\S]*?_resetEnrichIpCache/);
  assert.ok(
    renderBlock,
    '_renderSidebar must call _resetEnrichIpCache near its top so cached lookups don\'t survive across re-renders',
  );
});

test('_renderFindingsTableSection emits geo/ASN lines for IOC.IP rows', () => {
  // Pin the render-path branch: gate on ref.type === IOC.IP, read
  // ref.url, call _enrichIpForExport, and emit `.ioc-geo-enrich` divs
  // for each provider hit.
  const findIp = /ref\.type\s*===\s*IOC\.IP[\s\S]{0,500}_enrichIpForExport/;
  assert.match(SIDEBAR, findIp, 'IOC table render must call _enrichIpForExport on IOC.IP rows');
  assert.match(SIDEBAR, /['"]ioc-geo-enrich['"]/, 'sidebar must emit .ioc-geo-enrich CSS class for the enrichment lines');
});

test('_collectIocs resets the cache and attaches geo / asn for IPv4 rows', () => {
  // The exporter pipeline (JSON + CSV) reads from `_collectIocs`. A
  // regression that drops the cache reset would leak state from the
  // previous file; a regression that drops the IP enrichment branch
  // would silently strip geo/asn from every TIP-bound export.
  const fnMatch = APP_UI.match(/_collectIocs\s*\(\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(fnMatch, '_collectIocs body must be locatable');
  const body = fnMatch[0];
  assert.match(body, /_resetEnrichIpCache/, '_collectIocs must reset the per-export cache');
  assert.match(body, /r\.type\s*===\s*IOC\.IP/, '_collectIocs must gate enrichment on IOC.IP');
  assert.match(body, /_enrichIpForExport\s*\(/, '_collectIocs must call _enrichIpForExport for IPv4 rows');
  assert.match(body, /row\.geo\s*=\s*enr\.geo/, '_collectIocs must propagate the geo record');
  assert.match(body, /row\.asn\s*=\s*enr\.asn/, '_collectIocs must propagate the asn record');
});

test('_buildIocsCsv header includes geo_*/asn_* columns', () => {
  // The CSV header is the load-bearing contract for downstream tools.
  // New columns are appended at the end (per AGENTS.md convention) so
  // tools that `head -1`'d v1 CSVs keep working.
  const csvFn = APP_UI.match(/_buildIocsCsv\s*\([^)]*\)\s*\{[\s\S]*?return lines\.join/);
  assert.ok(csvFn, '_buildIocsCsv body must be locatable');
  const body = csvFn[0];
  assert.match(body, /geo_country/, 'CSV header must include geo_country');
  assert.match(body, /geo_iso/, 'CSV header must include geo_iso');
  assert.match(body, /geo_region/, 'CSV header must include geo_region');
  assert.match(body, /geo_city/, 'CSV header must include geo_city');
  assert.match(body, /\basn\b/, 'CSV header must include asn');
  assert.match(body, /asn_org/, 'CSV header must include asn_org');
});

test('_exportIocsJson forwards geo/asn fields when present', () => {
  // Schema stays at version 1 — geo/asn are optional fields that v1
  // readers can ignore. A regression that bumps the schema or drops
  // the fields entirely would either break consumers or silently
  // strip enrichment from clipboard payloads.
  const jsonFn = APP_UI.match(/_exportIocsJson\s*\(\)\s*\{[\s\S]*?_copyToClipboard/);
  assert.ok(jsonFn, '_exportIocsJson body must be locatable');
  const body = jsonFn[0];
  assert.match(body, /schemaVersion:\s*1/, 'IOC JSON export must keep schemaVersion: 1');
  assert.match(body, /i\.geo/, '_exportIocsJson must propagate i.geo when present');
  assert.match(body, /i\.asn/, '_exportIocsJson must propagate i.asn when present');
});

test('_buildAnalysisText IOCs table has an Enrichment column', () => {
  // The Summary markdown — what the user copies via the ⚡ Summary
  // button — is the headline surface this PR targets. Pin the new
  // column header AND the per-row cell call.
  assert.match(
    APP_UI,
    /\|\s*Type\s*\|\s*Value\s*\|\s*Severity\s*\|\s*Enrichment\s*\|/,
    'Summary IOCs markdown table must declare a 4th Enrichment column',
  );
  assert.match(
    APP_UI,
    /Type\s*\|\s*Value\s*\|\s*Source\s*\|\s*Enrichment/,
    'Summary Nicelisted IOCs sub-table must also declare the Enrichment column',
  );
});

test('reEnrich() in app-core.js re-renders the sidebar after MMDB hydrate', () => {
  // The Timeline mixin already re-runs enrichment on hydrate; this
  // PR extends the same callback to cover the sidebar / Summary.
  // Without this, an analyst's uploaded MMDB would only enrich files
  // opened AFTER the IndexedDB hydrate completed — silently confusing.
  const reEnrich = APP_CORE.match(/const reEnrich = \(\) => \{[\s\S]*?\};/);
  assert.ok(reEnrich, 'reEnrich() closure must be locatable in app-core.js');
  const body = reEnrich[0];
  assert.match(body, /_renderSidebar/, 'reEnrich must trigger a sidebar re-render');
  assert.match(body, /_runGeoipEnrichment/, 'reEnrich must continue to refresh the timeline (regression guard)');
});

test('src/util/ipv4.js is wired into JS_FILES before every consumer', () => {
  // Load order is load-bearing per AGENTS.md / build.py comments. The
  // util must appear before timeline-view-geoip.js, app-sidebar.js,
  // and app-ui.js (all three reference Ipv4Util at runtime).
  const idxUtil = BUILD.indexOf("'src/util/ipv4.js'");
  const idxGeoipMixin = BUILD.indexOf("'src/app/timeline/timeline-view-geoip.js'");
  const idxSidebar = BUILD.indexOf("'src/app/app-sidebar.js'");
  const idxUi = BUILD.indexOf("'src/app/app-ui.js'");
  assert.ok(idxUtil > 0, 'src/util/ipv4.js must be listed in JS_FILES');
  assert.ok(idxGeoipMixin > 0, 'timeline-view-geoip.js must be listed (sanity)');
  assert.ok(idxSidebar > 0, 'app-sidebar.js must be listed (sanity)');
  assert.ok(idxUi > 0, 'app-ui.js must be listed (sanity)');
  assert.ok(idxUtil < idxGeoipMixin, 'src/util/ipv4.js must precede timeline-view-geoip.js');
  assert.ok(idxUtil < idxSidebar, 'src/util/ipv4.js must precede app-sidebar.js');
  assert.ok(idxUtil < idxUi, 'src/util/ipv4.js must precede app-ui.js');
});
