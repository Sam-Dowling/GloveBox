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
// and `stripDerTail` — all from `constants.js`. Loading constants first
// mirrors the bundle's load order in `scripts/build.py`.
const ctx = loadModules(['src/constants.js', 'src/ioc-extract.js']);

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
