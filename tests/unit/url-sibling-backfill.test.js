'use strict';
// ════════════════════════════════════════════════════════════════════════════
// url-sibling-backfill.test.js — coverage for `emitUrlSiblings` (src/constants.js).
//
// Background: the IOC-extract core (src/ioc-extract.js) runs in both the
// main bundle and the IOC-extract worker bundle. To keep the worker
// self-contained it stays tldts-free, which means URL rows it produces
// arrive without the auto-derived `IOC.DOMAIN` / `IOC.IP` (raw literal) /
// `IOC.PATTERN` (punycode / abuse-suffix) siblings that `pushIOC`
// normally produces. `emitUrlSiblings` was factored out of `pushIOC` so
// the host-side backfill (`App._backfillUrlSiblings` in app-load.js) can
// retroactively derive the same siblings from URL rows produced by the
// worker.
//
// Tests below load vendored `tldts` alongside `src/constants.js` so the
// sibling derivation actually runs; without tldts the helper is a no-op
// by design (defensive bail in `_parseUrlHost`).
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

// tldts first (establishes the global), then constants (reads it via
// `typeof tldts !== 'undefined'`). The exposed globals the tests use are
// all top-level `const`s or `function`s in those files.
const ctx = loadModules(
  ['vendor/tldts.min.js', 'src/constants.js'],
  { expose: ['emitUrlSiblings', 'pushIOC', 'IOC', 'tldts', '_parseUrlHost'] }
);
const { emitUrlSiblings, IOC } = ctx;

function newFindings() {
  return { interestingStrings: [] };
}

test('emitUrlSiblings: plain URL emits IOC.DOMAIN sibling', () => {
  const f = newFindings();
  emitUrlSiblings(f, 'https://example.com/a/b.php?a=1', 'interestingStrings');
  const rows = host(f.interestingStrings);
  const domains = rows.filter(r => r.type === IOC.DOMAIN).map(r => r.url);
  assert.ok(domains.includes('example.com'),
    `expected IOC.DOMAIN 'example.com', got: ${JSON.stringify(domains)}`);
});

test('emitUrlSiblings: subdomain URL emits registrable domain only', () => {
  const f = newFindings();
  emitUrlSiblings(f, 'https://a.b.c.example.co.uk/p', 'interestingStrings');
  const rows = host(f.interestingStrings);
  const domains = rows.filter(r => r.type === IOC.DOMAIN).map(r => r.url);
  // tldts resolves `example.co.uk` as the registrable domain (public-suffix
  // aware). This anchors that we rely on tldts's suffix list, not a naive
  // "last two labels" heuristic.
  assert.deepEqual(domains, ['example.co.uk']);
});

test('emitUrlSiblings: IP-literal URL emits IOC.IP, no IOC.DOMAIN', () => {
  const f = newFindings();
  emitUrlSiblings(f, 'http://198.51.100.7/payload.exe', 'interestingStrings');
  const rows = host(f.interestingStrings);
  const ips = rows.filter(r => r.type === IOC.IP).map(r => r.url);
  const domains = rows.filter(r => r.type === IOC.DOMAIN).map(r => r.url);
  assert.ok(ips.includes('198.51.100.7'),
    `expected IP sibling 198.51.100.7, got: ${JSON.stringify(ips)}`);
  assert.deepEqual(domains, [],
    `expected no IOC.DOMAIN for raw-IP URL, got: ${JSON.stringify(domains)}`);
});

test('emitUrlSiblings: duplicate sibling suppressed on re-emit', () => {
  const f = newFindings();
  emitUrlSiblings(f, 'https://example.com/a', 'interestingStrings');
  emitUrlSiblings(f, 'https://example.com/b', 'interestingStrings');
  emitUrlSiblings(f, 'https://example.com/c', 'interestingStrings');
  const rows = host(f.interestingStrings);
  const domains = rows.filter(r => r.type === IOC.DOMAIN && r.url === 'example.com');
  assert.equal(domains.length, 1,
    `expected a single IOC.DOMAIN for example.com across three URL pushes, got ${domains.length}`);
});

test('emitUrlSiblings: no findings or empty URL is a no-op', () => {
  // Contract: callers on the load hot path may pass synthesised rows
  // with whatever shape the worker returned — defensive bails matter.
  assert.doesNotThrow(() => emitUrlSiblings(null, 'https://example.com', 'interestingStrings'));
  const f = newFindings();
  assert.doesNotThrow(() => emitUrlSiblings(f, '', 'interestingStrings'));
  assert.doesNotThrow(() => emitUrlSiblings(f, null, 'interestingStrings'));
  assert.equal(host(f.interestingStrings).length, 0);
});

test('emitUrlSiblings: defaults bucket to interestingStrings when omitted', () => {
  const f = newFindings();
  emitUrlSiblings(f, 'https://example.com/a');
  const rows = host(f.interestingStrings);
  const domains = rows.filter(r => r.type === IOC.DOMAIN).map(r => r.url);
  assert.ok(domains.includes('example.com'));
});

test('emitUrlSiblings: routes into externalRefs bucket when requested', () => {
  const f = { externalRefs: [], interestingStrings: [] };
  emitUrlSiblings(f, 'https://example.com/a', 'externalRefs');
  const rows = host(f.externalRefs);
  const domains = rows.filter(r => r.type === IOC.DOMAIN).map(r => r.url);
  assert.deepEqual(domains, ['example.com']);
  assert.equal(host(f.interestingStrings).length, 0,
    'sibling must land in the requested bucket, not the default');
});

test('emitUrlSiblings: derived-from-URL note present on DOMAIN sibling', () => {
  // The sidebar and export consumers filter on `note` to distinguish
  // derived siblings from domain IOCs pushed directly by renderers.
  const f = newFindings();
  emitUrlSiblings(f, 'https://example.com/a');
  const rows = host(f.interestingStrings);
  const dom = rows.find(r => r.type === IOC.DOMAIN && r.url === 'example.com');
  assert.ok(dom, 'IOC.DOMAIN entry must be present');
  assert.equal(dom.note, 'derived from URL');
});
