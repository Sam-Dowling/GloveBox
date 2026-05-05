'use strict';
// dedupe-host-pivots.test.js — unit tests for `dedupeHostPivots(findings)`.
//
// The helper collapses redundant URL / DOMAIN / HOSTNAME rows so the
// sidebar IOC table shows each host exactly once at its highest-
// evidence severity. These tests pin every rule in the helper's
// docstring: DOMAIN dropped when a URL covers it; HOSTNAME dropped
// when URL or DOMAIN covers it; higher-severity rows survive
// collapse; structured-source HOSTNAMEs (no URL/DOMAIN overlap)
// retained; idempotency.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(
  ['vendor/tldts.min.js', 'src/constants.js'],
  { expose: ['IOC', 'dedupeHostPivots', 'pushIOC', '_parseUrlHost'] },
);
const { IOC, dedupeHostPivots } = ctx;

// Realm-cross-safe: re-serialize any cross-realm objects through JSON so
// `assert.deepEqual` comparing a host-realm literal against a vm-realm
// value doesn't trip on `Array` constructor identity.
const snap = (value) => JSON.parse(JSON.stringify(value));

function makeFindings() {
  return {
    risk: 'low',
    interestingStrings: [],
    externalRefs: [],
  };
}

// ── DOMAIN vs URL ──────────────────────────────────────────────────────────
//
// DOMAIN rows are the canonical registrable-domain pivot and are never
// collapsed against URL rows. An analyst hunting by registrable domain
// needs the DOMAIN row to survive even when a URL endpoint pushes the
// same host.

test('dedupeHostPivots: preserves DOMAIN row alongside a URL row for the same registrable domain', () => {
  const f = makeFindings();
  f.interestingStrings.push(
    { type: IOC.URL,    url: 'http://evil.example.com/x', severity: 'high' },
    { type: IOC.DOMAIN, url: 'example.com',               severity: 'info' },
  );
  dedupeHostPivots(f);
  const types = snap(f.interestingStrings.map(r => r.type)).sort();
  assert.deepEqual(types, ['Domain', 'URL'],
    'DOMAIN rows must survive alongside URL rows — they are complementary pivots, not duplicates');
});

// ── HOSTNAME vs URL ────────────────────────────────────────────────────────

test('dedupeHostPivots: drops HOSTNAME when a URL row covers the same host', () => {
  const f = makeFindings();
  f.externalRefs.push(
    { type: IOC.URL,      url: 'http://evil.example.com/x', severity: 'high' },
    { type: IOC.HOSTNAME, url: 'evil.example.com',           severity: 'info' },
  );
  dedupeHostPivots(f);
  const types = snap(f.externalRefs.map(r => r.type));
  assert.deepEqual(types, ['URL'],
    'HOSTNAME covered by URL must be dropped at equal-or-lower severity');
});

test('dedupeHostPivots: drops HOSTNAME when URL covers the registrable domain (subdomain match)', () => {
  // `example.com` as HOSTNAME is the registrable of `evil.example.com`.
  // The URL covers the registrable via tldts, so HOSTNAME is redundant.
  const f = makeFindings();
  f.interestingStrings.push(
    { type: IOC.URL,      url: 'http://evil.example.com/x', severity: 'high' },
    { type: IOC.HOSTNAME, url: 'example.com',                severity: 'info' },
  );
  dedupeHostPivots(f);
  const types = snap(f.interestingStrings.map(r => r.type));
  assert.deepEqual(types, ['URL'],
    'HOSTNAME matching URL registrable domain must be dropped');
});

// ── HOSTNAME vs DOMAIN ─────────────────────────────────────────────────────

test('dedupeHostPivots: drops HOSTNAME when a DOMAIN row covers it', () => {
  const f = makeFindings();
  f.interestingStrings.push(
    { type: IOC.DOMAIN,   url: 'example.com', severity: 'medium' },
    { type: IOC.HOSTNAME, url: 'example.com', severity: 'info' },
  );
  dedupeHostPivots(f);
  const types = snap(f.interestingStrings.map(r => r.type));
  assert.deepEqual(types, ['Domain'],
    'HOSTNAME covered by DOMAIN must be dropped');
});

// ── HOSTNAME severity escalation survives ──────────────────────────────────

test('dedupeHostPivots: keeps HOSTNAME row when its severity EXCEEDS the covering URL/DOMAIN', () => {
  // A decoder or metadata enricher escalated the HOSTNAME to critical
  // independently. Keep it — the escalated severity is the signal
  // worth surfacing.
  const f = makeFindings();
  f.interestingStrings.push(
    { type: IOC.URL,      url: 'http://example.com/', severity: 'info' },
    { type: IOC.HOSTNAME, url: 'example.com',          severity: 'critical' },
  );
  dedupeHostPivots(f);
  const types = snap(f.interestingStrings.map(r => r.type)).sort();
  assert.deepEqual(types, ['Hostname', 'URL'],
    'HOSTNAME with higher severity than covering URL must survive collapse');
});

// ── Structured-source HOSTNAME (no URL/DOMAIN overlap) ─────────────────────

test('dedupeHostPivots: preserves HOSTNAME rows that do not overlap any URL or DOMAIN', () => {
  // Typical case: a cert Subject CN or EVTX machine name with no
  // associated URL in the corpus. HOSTNAME is the canonical type.
  const f = makeFindings();
  f.externalRefs.push(
    { type: IOC.URL,      url: 'http://unrelated.test/',   severity: 'info' },
    { type: IOC.HOSTNAME, url: 'dc01.example.local',        severity: 'info', note: 'EVTX machine name' },
  );
  dedupeHostPivots(f);
  const hostnames = f.externalRefs.filter(r => r.type === IOC.HOSTNAME);
  assert.equal(hostnames.length, 1,
    `structured-source HOSTNAME must be preserved when no URL/DOMAIN covers it; got: ${JSON.stringify(f.externalRefs)}`);
});

// ── Cross-bucket coverage ──────────────────────────────────────────────────

test('dedupeHostPivots: URL in externalRefs drops HOSTNAME in interestingStrings (cross-bucket)', () => {
  const f = makeFindings();
  f.externalRefs.push({ type: IOC.URL, url: 'http://evil.com/', severity: 'high' });
  f.interestingStrings.push({ type: IOC.HOSTNAME, url: 'evil.com', severity: 'info' });
  dedupeHostPivots(f);
  assert.equal(f.interestingStrings.length, 0,
    'HOSTNAME in interestingStrings must be dropped when URL in externalRefs covers it');
  assert.equal(f.externalRefs.length, 1,
    'URL in externalRefs must survive');
});

// ── Idempotency ────────────────────────────────────────────────────────────

test('dedupeHostPivots: idempotent — calling twice yields the same result', () => {
  const f = makeFindings();
  f.interestingStrings.push(
    { type: IOC.URL,      url: 'http://evil.example.com/x', severity: 'high' },
    { type: IOC.DOMAIN,   url: 'example.com',                severity: 'info' },
    { type: IOC.HOSTNAME, url: 'evil.example.com',           severity: 'info' },
  );
  dedupeHostPivots(f);
  const afterFirst = JSON.stringify(f.interestingStrings);
  dedupeHostPivots(f);
  const afterSecond = JSON.stringify(f.interestingStrings);
  assert.equal(afterFirst, afterSecond, 'helper must be idempotent');
});

// ── Non-host IOC types unaffected ──────────────────────────────────────────

test('dedupeHostPivots: does not touch IP / EMAIL / PATTERN / FILE_PATH rows', () => {
  const f = makeFindings();
  f.interestingStrings.push(
    { type: IOC.IP,        url: '192.0.2.1',        severity: 'high' },
    { type: IOC.EMAIL,     url: 'a@example.com',     severity: 'info' },
    { type: IOC.FILE_PATH, url: '/etc/passwd',       severity: 'medium' },
  );
  f.externalRefs.push(
    { type: IOC.PATTERN, url: 'Suspicious pattern', severity: 'high' },
  );
  const before = JSON.stringify({ ints: f.interestingStrings, exts: f.externalRefs });
  dedupeHostPivots(f);
  const after = JSON.stringify({ ints: f.interestingStrings, exts: f.externalRefs });
  assert.equal(before, after, 'non-host IOC types must be untouched');
});

// ── Empty findings ─────────────────────────────────────────────────────────

test('dedupeHostPivots: no-op on empty findings or null input', () => {
  const f = makeFindings();
  dedupeHostPivots(f);
  assert.equal(f.interestingStrings.length, 0);
  assert.equal(f.externalRefs.length, 0);
  // Null-safe.
  dedupeHostPivots(null);
  dedupeHostPivots(undefined);
  dedupeHostPivots({});
  // Should not throw.
});
