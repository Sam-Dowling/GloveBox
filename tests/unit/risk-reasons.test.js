'use strict';
// risk-reasons.test.js — `escalateRisk(findings, tier, reason?)` reason
// plumbing and the standalone `pushRiskReason(findings, row)` helper.
//
// Both surfaces feed the "Why this risk?" panel rendered under the
// in-content verdict band (binary-triage.js) and under the sidebar risk
// banner (app-sidebar.js). Two-arg `escalateRisk(findings, tier)` callers
// must keep working — only the new optional `reason` arg is novel.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

function fresh() {
  return loadModules(['src/constants.js'], {
    expose: ['escalateRisk', 'pushRiskReason'],
  });
}

test('escalateRisk: two-arg call still escalates and skips reasons', () => {
  const { escalateRisk } = fresh();
  const f = { risk: 'low' };
  escalateRisk(f, 'high');
  assert.equal(f.risk, 'high');
  assert.equal(Array.isArray(f.riskReasons), true, 'riskReasons should be lazy-initialised');
  assert.equal(f.riskReasons.length, 0, 'no reason pushed when arg omitted');
});

test('escalateRisk: string reason wraps into a {label, severity:tier, delta:0} row', () => {
  const { escalateRisk } = fresh();
  const f = { risk: 'low' };
  escalateRisk(f, 'high', 'Imports process injection APIs');
  assert.equal(f.risk, 'high');
  assert.equal(f.riskReasons.length, 1);
  const r = f.riskReasons[0];
  assert.equal(r.label, 'Imports process injection APIs');
  assert.equal(r.severity, 'high');
  assert.equal(r.delta, 0);
  assert.equal(r.category, '');
  assert.equal(r.source, '');
});

test('escalateRisk: object reason carries delta/category/source through', () => {
  const { escalateRisk } = fresh();
  const f = { risk: 'low' };
  escalateRisk(f, 'medium', {
    label: 'Imports networking APIs',
    delta: 1.5,
    severity: 'medium',
    category: 'networking',
    source: 'pe',
  });
  assert.equal(f.risk, 'medium');
  assert.equal(f.riskReasons.length, 1);
  // Field-by-field equality avoids cross-realm `Object` prototype mismatch
  // that `deepEqual` enforces (the row is constructed inside the
  // `node:vm` sandbox; tests run in the host realm).
  const r = f.riskReasons[0];
  assert.equal(r.label, 'Imports networking APIs');
  assert.equal(r.delta, 1.5);
  assert.equal(r.severity, 'medium');
  assert.equal(r.category, 'networking');
  assert.equal(r.source, 'pe');
});

test('escalateRisk: lower-tier call does not lower risk but still records reason', () => {
  const { escalateRisk } = fresh();
  const f = { risk: 'high' };
  escalateRisk(f, 'medium', 'A medium-severity finding');
  assert.equal(f.risk, 'high', 'tier never demotes');
  assert.equal(f.riskReasons.length, 1, 'reason recorded even when tier unchanged');
  assert.equal(f.riskReasons[0].severity, 'medium');
});

test('pushRiskReason: appends a normalised row without touching findings.risk', () => {
  const { pushRiskReason } = fresh();
  const f = { risk: 'low' };
  pushRiskReason(f, { label: 'No Authenticode signature', delta: 1, severity: 'medium', category: 'signing', source: 'pe' });
  assert.equal(f.risk, 'low', 'pushRiskReason does not escalate');
  assert.equal(f.riskReasons.length, 1);
  assert.equal(f.riskReasons[0].label, 'No Authenticode signature');
});

test('pushRiskReason: rejects rows without a label silently', () => {
  const { pushRiskReason } = fresh();
  const f = { risk: 'low' };
  pushRiskReason(f, { delta: 5 });
  pushRiskReason(f, null);
  pushRiskReason(f, undefined);
  assert.equal(Array.isArray(f.riskReasons) ? f.riskReasons.length : 0, 0);
});

test('pushRiskReason: defaults missing fields to safe values', () => {
  const { pushRiskReason } = fresh();
  const f = { risk: 'low' };
  pushRiskReason(f, { label: 'Some signal' });
  const r = f.riskReasons[0];
  assert.equal(r.delta, 0);
  assert.equal(r.severity, 'info');
  assert.equal(r.category, '');
  assert.equal(r.source, '');
});

test('escalateRisk: handles findings without a riskReasons array (lazy init)', () => {
  const { escalateRisk } = fresh();
  const f = { risk: 'low' }; // no riskReasons key at all
  escalateRisk(f, 'high', 'Test reason');
  assert.equal(Array.isArray(f.riskReasons), true);
  assert.equal(f.riskReasons.length, 1);
});

test('escalateRisk: ignores invalid arguments gracefully', () => {
  const { escalateRisk } = fresh();
  // null findings — should not throw.
  assert.doesNotThrow(() => escalateRisk(null, 'high', 'x'));
  // missing tier — no-op.
  const f = { risk: 'low' };
  escalateRisk(f, '', 'should not record');
  assert.equal(f.risk, 'low');
});
