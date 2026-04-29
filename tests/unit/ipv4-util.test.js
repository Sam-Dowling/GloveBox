'use strict';
// ════════════════════════════════════════════════════════════════════════════
// ipv4-util.test.js — direct unit tests for the shared IPv4 helpers in
// src/util/ipv4.js (`Ipv4Util.isStrictIPv4`, `Ipv4Util.isPrivateIPv4`).
//
// The util is consumed by the Timeline GeoIP enrichment mixin AND the
// sidebar / Summary IOC enrichment surfaces. A regression that loosens
// the strict parser would re-introduce ReDoS exposure on the timeline
// detect path; a regression that drops a private-range case would
// emit empty enrichment cells in IOC exports for analyst-machine RFC1918
// addresses. Both are silent failures the unit test catches.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { Ipv4Util } = require(path.resolve(__dirname, '..', '..', 'src/util/ipv4.js'));

test('isStrictIPv4 — accepts canonical dotted-quads', () => {
  for (const ok of ['0.0.0.0', '1.1.1.1', '8.8.8.8', '127.0.0.1', '255.255.255.255', '192.168.1.1']) {
    assert.equal(Ipv4Util.isStrictIPv4(ok), true, `${ok} must validate`);
  }
});

test('isStrictIPv4 — rejects leading zeros', () => {
  // The strict parser explicitly disallows leading zeros so an octal
  // interpretation can't sneak in via downstream consumers.
  assert.equal(Ipv4Util.isStrictIPv4('01.2.3.4'), false);
  assert.equal(Ipv4Util.isStrictIPv4('1.02.3.4'), false);
  assert.equal(Ipv4Util.isStrictIPv4('1.2.3.04'), false);
});

test('isStrictIPv4 — rejects out-of-range octets', () => {
  assert.equal(Ipv4Util.isStrictIPv4('256.0.0.0'), false);
  assert.equal(Ipv4Util.isStrictIPv4('1.999.0.0'), false);
});

test('isStrictIPv4 — rejects malformed shapes', () => {
  for (const bad of ['', '1', '1.2.3', '1.2.3.4.5', 'a.b.c.d', '...', '1..2.3', '1.2..3.4', '1.2.3.', '.1.2.3.4', '1234.0.0.0']) {
    assert.equal(Ipv4Util.isStrictIPv4(bad), false, `${JSON.stringify(bad)} must NOT validate`);
  }
});

test('isStrictIPv4 — rejects non-string input', () => {
  for (const bad of [null, undefined, 0, 1234, [], {}, true]) {
    assert.equal(Ipv4Util.isStrictIPv4(bad), false);
  }
});

test('isPrivateIPv4 — RFC1918 ranges', () => {
  for (const ok of ['10.0.0.0', '10.255.255.255', '172.16.0.1', '172.31.255.254', '192.168.0.1', '192.168.255.255']) {
    assert.equal(Ipv4Util.isPrivateIPv4(ok), true, `${ok} must classify as private`);
  }
});

test('isPrivateIPv4 — loopback / link-local / CGNAT / multicast / broadcast / "this network"', () => {
  // Loopback (127/8)
  assert.equal(Ipv4Util.isPrivateIPv4('127.0.0.1'), true);
  assert.equal(Ipv4Util.isPrivateIPv4('127.255.255.254'), true);
  // Link-local
  assert.equal(Ipv4Util.isPrivateIPv4('169.254.1.1'), true);
  // CGNAT (RFC6598 100.64/10)
  assert.equal(Ipv4Util.isPrivateIPv4('100.64.0.1'), true);
  assert.equal(Ipv4Util.isPrivateIPv4('100.127.255.254'), true);
  // 0.0.0.0/8 — "this network"
  assert.equal(Ipv4Util.isPrivateIPv4('0.0.0.0'), true);
  // Multicast 224/4
  assert.equal(Ipv4Util.isPrivateIPv4('224.0.0.1'), true);
  assert.equal(Ipv4Util.isPrivateIPv4('239.255.255.255'), true);
  // 240.0.0.0/4 reserved + broadcast
  assert.equal(Ipv4Util.isPrivateIPv4('240.0.0.1'), true);
  assert.equal(Ipv4Util.isPrivateIPv4('255.255.255.255'), true);
});

test('isPrivateIPv4 — public IPs return false', () => {
  for (const ok of ['1.1.1.1', '8.8.8.8', '8.8.4.4', '203.0.113.1', '198.51.100.1', '192.0.2.1']) {
    assert.equal(Ipv4Util.isPrivateIPv4(ok), false, `${ok} must be classified as public`);
  }
});

test('isPrivateIPv4 — boundary check on 172.16/12', () => {
  // 172.15.x.x is OUTSIDE the RFC1918 range; 172.32.x.x is also outside.
  assert.equal(Ipv4Util.isPrivateIPv4('172.15.0.1'), false);
  assert.equal(Ipv4Util.isPrivateIPv4('172.32.0.1'), false);
  // Boundaries inside the range
  assert.equal(Ipv4Util.isPrivateIPv4('172.16.0.0'), true);
  assert.equal(Ipv4Util.isPrivateIPv4('172.31.255.255'), true);
});

test('isPrivateIPv4 — boundary check on 100.64/10', () => {
  // 100.63.x.x is below; 100.128.x.x is above.
  assert.equal(Ipv4Util.isPrivateIPv4('100.63.0.1'), false);
  assert.equal(Ipv4Util.isPrivateIPv4('100.128.0.1'), false);
});

test('isPrivateIPv4 — non-IPv4 input returns false', () => {
  for (const bad of [null, undefined, '', 'not.an.ip', '1.2.3', '256.0.0.0', '1.2.3.04']) {
    assert.equal(Ipv4Util.isPrivateIPv4(bad), false);
  }
});
