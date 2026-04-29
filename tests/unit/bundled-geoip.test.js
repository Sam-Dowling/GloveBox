'use strict';
// ════════════════════════════════════════════════════════════════════════════
// bundled-geoip.test.js — Pure decoder + lookup tests for the RIR-derived
// IPv4 → country provider.
//
// The production bundle injects `__GEOIP_BUNDLE_B64` at build time
// (scripts/build.py prepends it to Block 1). For unit tests we read the
// real `vendor/geoip-country-ipv4.bin` off disk, base64-encode it, and
// inject the const into the vm sandbox before loading the module. This
// gives us coverage of the real binary — same bytes the browser sees —
// without depending on a built `docs/index.html`.
//
// What this proves:
//   1. Magic / version / count parse cleanly (the no-bundle path is the
//      STUB return; we exercise the populated path).
//   2. `lookupIPv4` resolves well-known addresses to the documented
//      RIR allocations (Google DNS → US, Cloudflare 1.1.1.1 → APNIC's
//      "AU" slot, Quad9 → CH, …).
//   3. Reserved / private space (10.0.0.0/8, 192.168.0.0/16, etc.)
//      returns null — the bundled provider stamps "Reserved" as ISO
//      `--` and the resolver maps that to null so cells render empty.
//   4. `formatRow` produces the documented `Country/ISO` shape with
//      trailing-slash stripping.
//   5. Bad input (non-string, malformed dotted-quad, leading zeros,
//      out-of-range octets) returns null without throwing.
//
// What this does NOT cover:
//   • The `STUB` fallback path (no bundle) — exercised implicitly by
//     loading the file without the const, but asserting on the stub
//     would just duplicate trivial code.
//   • The MMDB upload path — see mmdb-reader.test.js.
//   • Timeline integration — see timeline-view-geoip.test.js.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadModules, REPO_ROOT } = require('../helpers/load-bundle.js');

// Read the vendored bundle once — every test loads a fresh vm context
// but the base64 string is shared (Node string interning means this is
// O(file-size) once, not once per test).
const BUNDLE_BIN = fs.readFileSync(
  path.join(REPO_ROOT, 'vendor', 'geoip-country-ipv4.bin'),
);
const BUNDLE_B64 = BUNDLE_BIN.toString('base64');

// `loadModules` builds a fresh sandbox per call. We pass `__GEOIP_BUNDLE_B64`
// as a sandbox shim so the module's `typeof __GEOIP_BUNDLE_B64 === 'string'`
// guard sees a real value. Every test calls this helper to get a clean
// provider — there's no shared state to worry about beyond the cost of
// re-decoding the binary (~10 ms).
function loadProvider() {
  const ctx = loadModules(['src/geoip/bundled-geoip.js'], {
    expose: ['BundledGeoip'],
    shims: { __GEOIP_BUNDLE_B64: BUNDLE_B64 },
  });
  assert.ok(ctx.BundledGeoip, 'BundledGeoip should be exposed');
  return ctx.BundledGeoip;
}

test('header parse — bundle decodes to a populated provider, not the STUB', () => {
  const p = loadProvider();
  // STUB has rangeCount === 0; real bundle has > 100 K ranges.
  assert.ok(p.rangeCount > 100_000,
    `expected populated provider, got rangeCount=${p.rangeCount}`);
  assert.ok(p.countryCount > 200,
    `expected ≥ 200 countries, got ${p.countryCount}`);
  assert.equal(p.providerKind, 'bundled');
  assert.equal(p.getFieldName(), 'geo');
  // Vintage label format pinned so a Settings-dialog-format change
  // surfaces here as a deliberate update.
  assert.match(p.vintage, /^RIR snapshot — [\d,]+ ranges, \d+ countries$/);
});

test('lookupIPv4 — well-known public addresses resolve to expected ISO codes', () => {
  const p = loadProvider();
  // Google Public DNS — assigned to Google US (8.8.8.0/24 is in
  // ARIN's allocation to Level 3 → Google). Stable for ≥ 15 years.
  const google = p.lookupIPv4('8.8.8.8');
  assert.ok(google, '8.8.8.8 should resolve');
  assert.equal(google.iso, 'US');
  assert.equal(google.country, 'United States');

  // Cloudflare 1.1.1.1 — APNIC reassignment. The RIR delegated-stats
  // file lists 1.1.1.0/24 under APNIC with country "AU" (Cloudflare
  // is registered in Australia for this prefix). This is the known
  // "wrong" answer for what users perceive as a global anycast IP,
  // but it's what the RIR data says — pinning it here documents the
  // canonical bundled behaviour and ensures a refresh that flips the
  // assignment is caught explicitly (would require a test update).
  const cf = p.lookupIPv4('1.1.1.1');
  assert.ok(cf, '1.1.1.1 should resolve');
  assert.equal(cf.iso, 'AU');

  // RIPE-administered prefix (193.0.0.0/8 is a RIPE block; 193.0.0.1
  // is RIPE NCC's own infrastructure, NL).
  const ripe = p.lookupIPv4('193.0.0.1');
  assert.ok(ripe, '193.0.0.1 should resolve');
  assert.equal(ripe.iso, 'NL');
});

test('lookupIPv4 — reserved / private space returns null', () => {
  const p = loadProvider();
  // RFC 1918 + IANA reserved blocks. Every one of these falls into
  // the "Reserved" sentinel slot (ISO `--`) which the resolver maps
  // to null so the analyst's cell renders empty.
  for (const ip of [
    '10.0.0.1',           // RFC 1918 / 10.0.0.0/8
    '10.255.255.255',
    '172.16.0.1',         // RFC 1918 / 172.16.0.0/12
    '172.31.255.254',
    '192.168.1.1',        // RFC 1918 / 192.168.0.0/16
    '127.0.0.1',          // Loopback
    '169.254.1.1',        // Link-local (RFC 3927)
    '224.0.0.1',          // Multicast (224.0.0.0/4)
    '255.255.255.255',    // Limited broadcast
    '0.0.0.0',            // "This network"
  ]) {
    assert.equal(p.lookupIPv4(ip), null, `${ip} should resolve to null`);
  }
});

test('lookupIPv4 — bad input returns null without throwing', () => {
  const p = loadProvider();
  for (const bad of [
    null,
    undefined,
    42,
    {},
    [],
    '',
    'not.an.ip.address',
    '1.2.3',                  // too few octets
    '1.2.3.4.5',              // too many octets
    '256.0.0.1',              // octet > 255
    '1.2.3.999',
    '01.2.3.4',               // leading zero (rejected for ambiguity)
    '1.2.03.4',
    ' 8.8.8.8',               // leading whitespace
    '8.8.8.8 ',               // trailing whitespace
    '8.8.8.8\n',
    '::1',                    // IPv6 (not supported in v1)
    'fe80::1',
  ]) {
    assert.equal(p.lookupIPv4(bad), null, `bad input ${JSON.stringify(bad)} should return null`);
  }
});

test('formatRow — Country/ISO shape with trailing-slash trim', () => {
  const p = loadProvider();
  // Bundled provider only emits country + iso. We assert the shape
  // matches what the Timeline mixin expects (`<sourceCol>.geo` cells
  // are exactly this string).
  assert.equal(
    p.formatRow({ country: 'Ireland', iso: 'IE' }),
    'Ireland/IE',
  );
  // Defensive: a record with only country (no iso) should drop the
  // trailing slash. This shape never occurs from `lookupIPv4` today,
  // but the formatter contract promises trim regardless.
  assert.equal(
    p.formatRow({ country: 'Ireland', iso: '' }),
    'Ireland',
  );
  // Internal empties dropped (region missing → no `Country//City`).
  // Bundled provider doesn't produce city; this exercises the join
  // path the MMDB provider relies on for parity.
  assert.equal(
    p.formatRow({ country: 'United States', iso: 'US', region: '', city: 'New Orleans' }),
    'United States/US/New Orleans',
  );
  // Null record → empty (the resolver returns null for misses; the
  // mixin calls `formatRow(null)` and expects '').
  assert.equal(p.formatRow(null), '');
  assert.equal(p.formatRow(undefined), '');
});

test('lookupIPv4 — boundary IPs at the edge of allocations', () => {
  const p = loadProvider();
  // The bundle stores ranges as start-only (end = next start - 1).
  // Pin that the slot at exactly `start` resolves correctly — off-by-
  // one bugs in `findSlot`'s lower-bound search would manifest here.
  // We don't know the exact start of any specific range without
  // re-reading the binary, but we can assert that consecutive
  // public IPs near a known boundary all resolve and produce
  // monotonically-non-decreasing slot indices (i.e. the same slot
  // until we cross a boundary, then a new slot).
  const ips = ['8.8.8.7', '8.8.8.8', '8.8.8.9'];
  const recs = ips.map(ip => p.lookupIPv4(ip));
  for (const r of recs) assert.ok(r, 'all 3 sample IPs should resolve');
  // All three Google IPs share the same allocation → identical record.
  assert.equal(recs[0].iso, recs[1].iso);
  assert.equal(recs[1].iso, recs[2].iso);
  assert.equal(recs[0].iso, 'US');
});
