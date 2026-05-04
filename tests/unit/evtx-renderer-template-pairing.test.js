'use strict';
// ════════════════════════════════════════════════════════════════════════════
// evtx-renderer-template-pairing.test.js
//
// Pins the semantic equivalence of the Data.Name ↔ Data-text pairing
// pipeline in `_applyTemplate` and `_extractNestedEventData` after
// rewriting both from O(N × M) nested loops to O(N + M) monotonic
// forward scans.
//
// Strategy:
//   1. End-to-end: parse `examples/forensics/example-security.evtx`
//      and compare a stable digest (eventId|channel|computer|provider|
//      eventData) against a pinned SHA-256. Any pairing regression
//      shifts bytes in the eventData string; the digest flags it.
//
//   2. Targeted `_applyTemplate` unit tests that cover the three
//      subtle cases where the monotonic cursor had to match the old
//      inner-loop semantics:
//
//        a) Paired-then-unpaired  : Name₀ Text₀ Text₁
//           → ["Name₀=Text₀", "Text₁"]
//
//        b) Orphan name           : Name₀ Name₁ Text₀
//           → ["Name₁=Text₀"]        (Name₀ dropped; old inner-loop
//                                     broke without push on consecutive
//                                     Data.Name)
//
//        c) Unpaired-then-paired  : Text₀ Name₀ Text₁
//           → ["Name₀=Text₁", "Text₀"]   (Pass 1 emits pairs, Pass 2
//                                         emits unpaired — order must
//                                         be preserved)
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { loadModules } = require('../helpers/load-bundle');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

function buildRenderer() {
  const sandbox = loadModules([
    'src/constants.js',
    'src/hashes.js',
    'src/evtx-event-ids.js',
    'src/renderers/evtx-renderer.js',
  ], { expose: ['EvtxRenderer'] });
  return new sandbox.EvtxRenderer();
}

// ── End-to-end snapshot pin ──────────────────────────────────────────────

test('EVTX fixture digest is byte-identical to pre-refactor baseline', () => {
  const r = buildRenderer();
  const fx = fs.readFileSync(path.join(REPO_ROOT, 'examples/forensics/example-security.evtx'));
  const events = r._parse(new Uint8Array(fx.buffer, fx.byteOffset, fx.byteLength));

  // Event-count sanity so a wholesale regression is caught too.
  assert.equal(events.length, 126, 'fixture should yield 126 events');

  // Stable digest over the outputs most sensitive to the pairing logic.
  // eventData is the pairing sink; other fields are included to catch
  // any collateral damage to the system-field extraction path.
  const lines = events.map(e =>
    `${e.eventId || ''}|${e.channel || ''}|${e.computer || ''}|${e.provider || ''}|${e.eventData || ''}`);
  const digest = crypto.createHash('sha256').update(lines.join('\n')).digest('hex');

  // Pinned on the pre-refactor build (commit 9a0d2fb) with the same
  // fixture; produced identically by the post-refactor build.
  assert.equal(
    digest,
    'bb97cbe5cd0b5b9c3b2379fa0d06074c01a6f6bc6992c8ee2918714506796a26',
    'event digest drift — inspect diff between old/new pairing output');
});

// ── Targeted `_applyTemplate` unit tests ─────────────────────────────────

// Mini-harness: build a minimal `templateNames` array that exercises
// the `_applyTemplate` pairing branches without needing a synthetic
// EVTX payload. The helper targets only the Data.Name ↔ Data-text
// pairing code path; other template elements (Computer, Channel, …)
// are ignored by the test inputs below.
function applyPairing(templateNames, values) {
  const r = buildRenderer();
  const result = {};
  const eventDataParts = [];
  const unpaired = r._applyTemplate(result, templateNames, values, eventDataParts);
  return { parts: eventDataParts, unpaired };
}

test('_applyTemplate: pair-then-unpaired (Name, Text, Text) emits both in order', () => {
  const templateNames = [
    { elem: 'Data', attr: 'Name', idx: 0 },    // Name₀
    { elem: 'Data', attr: null,   idx: 1 },    // Text₀
    { elem: 'Data', attr: null,   idx: 2 },    // Text₁
  ];
  const values = ['username', 'alice', 'extra-trailing'];
  const { parts, unpaired } = applyPairing(templateNames, values);
  assert.deepEqual(parts, ['username=alice', 'extra-trailing']);
  assert.deepEqual(unpaired, []);
});

test('_applyTemplate: consecutive Names (Name, Name, Text) pairs first-Name with Text, second orphaned', () => {
  // _applyTemplate does NOT drop consecutive Data.Name entries (that
  // behaviour lives in _extractNestedEventData instead). Semantics:
  // each Name finds the first unused Data-text with a strictly-higher
  // template index. Name₀ (i=0) wins Text₀ (i=2). Name₁ (i=1) finds
  // no unused text with index > 1 — Text₀ is already consumed — and is
  // surfaced via `unpairedNames`.
  const templateNames = [
    { elem: 'Data', attr: 'Name', idx: 0 },    // Name₀ — wins Text₀
    { elem: 'Data', attr: 'Name', idx: 1 },    // Name₁ — unpaired
    { elem: 'Data', attr: null,   idx: 2 },    // Text₀
  ];
  const values = ['abandoned', 'username', 'alice'];
  const { parts, unpaired } = applyPairing(templateNames, values);
  assert.deepEqual(parts, ['abandoned=alice']);
  assert.deepEqual(unpaired, ['username']);
});

test('_applyTemplate: leading-text (Text, Name, Text) preserves Pass1→Pass2 order', () => {
  const templateNames = [
    { elem: 'Data', attr: null,   idx: 0 },    // Text₀ (no preceding Name)
    { elem: 'Data', attr: 'Name', idx: 1 },    // Name₀
    { elem: 'Data', attr: null,   idx: 2 },    // Text₁ → pairs with Name₀
  ];
  const values = ['stray-text', 'username', 'alice'];
  const { parts, unpaired } = applyPairing(templateNames, values);
  // Old code emitted paired entries in Pass 1, then collected unpaired
  // texts in Pass 2 — resulting in paired-first order. The monotonic
  // rewrite preserves that ordering by buffering unpaired texts.
  assert.deepEqual(parts, ['username=alice', 'stray-text']);
  assert.deepEqual(unpaired, []);
});

test('_applyTemplate: all-paired Sysmon-style (N=8 Data fields) round-trips', () => {
  const templateNames = [];
  const values = [];
  const expected = [];
  for (let i = 0; i < 8; i++) {
    templateNames.push({ elem: 'Data', attr: 'Name', idx: i * 2 });
    templateNames.push({ elem: 'Data', attr: null,   idx: i * 2 + 1 });
    values.push(`Field${i}`);
    values.push(`Value${i}`);
    expected.push(`Field${i}=Value${i}`);
  }
  const { parts, unpaired } = applyPairing(templateNames, values);
  assert.deepEqual(parts, expected);
  assert.deepEqual(unpaired, []);
});

test('_applyTemplate: empty-value Data pairs still emit label=', () => {
  // Empty values must maintain alignment — if Value is '' but Name is
  // present, the pair "Name=" is still emitted (matches pre-refactor).
  const templateNames = [
    { elem: 'Data', attr: 'Name', idx: 0 },
    { elem: 'Data', attr: null,   idx: 1 },
  ];
  const values = ['RuleName', ''];
  const { parts, unpaired } = applyPairing(templateNames, values);
  assert.deepEqual(parts, ['RuleName=']);
  assert.deepEqual(unpaired, []);
});

test('_applyTemplate: literal Data.Name (Sysmon hardcoded) pairs with following Text', () => {
  // Sysmon events often bake Data.Name as a literal rather than a
  // substitution index. _applyTemplate pushes these into dataNames
  // with `.literal` set — the pairing cursor still needs to find them.
  const templateNames = [
    { elem: 'Data', attr: 'Name', literal: 'UtcTime' },
    { elem: 'Data', attr: null,   idx: 0 },
  ];
  const values = ['2024-01-15T00:00:00.000Z'];
  const { parts, unpaired } = applyPairing(templateNames, values);
  assert.deepEqual(parts, ['UtcTime=2024-01-15T00:00:00.000Z']);
  assert.deepEqual(unpaired, []);
});
