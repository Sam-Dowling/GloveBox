'use strict';
// timeline-relative.test.js — Minimal relative-time grammar parser used
// by the inline datetime range widget in the Timeline query bar.
//
// `_tlParseRelative('15m')` → 900_000 and `_tlFormatRelative(900_000)`
// → '15m'. The widget feeds parsed durations into "Last <N><unit>"
// presets, anchored to the data's max timestamp. Compound terms
// (`1d 6h`) are NOT supported on purpose — kept as a single-term
// grammar so analysts get an obvious error rather than a silent
// mis-parse. Round-trip is only guaranteed for inputs that are an
// exact multiple of the largest matching unit; mixed durations like
// `90s` round-trip via the second-of-minute (`90s` parses to
// 90_000 ms, which formats back as `90s`, not `1m 30s`).

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// `timeline-helpers.js` is pure — no DOM, no IOC plumbing — so it
// loads in isolation. We pull `constants.js` first because the helpers
// reference `RENDER_LIMITS`, `TIMELINE_BUCKETS_TARGET`, etc. via the
// top-level `const TIMELINE_MAX_ROWS = RENDER_LIMITS.MAX_TIMELINE_ROWS`
// declaration.
const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-helpers.js',
]);
const { _tlParseRelative, _tlFormatRelative } = ctx;

test('parseRelative: accepts <N><unit> for s/m/h/d/w', () => {
  assert.strictEqual(_tlParseRelative('30s'), 30_000);
  assert.strictEqual(_tlParseRelative('15m'), 900_000);
  assert.strictEqual(_tlParseRelative('2h'), 2 * 3_600_000);
  assert.strictEqual(_tlParseRelative('7d'), 7 * 86_400_000);
  assert.strictEqual(_tlParseRelative('1w'), 604_800_000);
});

test('parseRelative: tolerates whitespace + case', () => {
  assert.strictEqual(_tlParseRelative('  15M '), 900_000);
  assert.strictEqual(_tlParseRelative('1H'), 3_600_000);
});

test('parseRelative: rejects compound / malformed / non-positive', () => {
  // Compound rejected — single-term grammar by design.
  assert.strictEqual(_tlParseRelative('1d 6h'), null);
  assert.strictEqual(_tlParseRelative('1d6h'), null);
  // Bad units / missing parts.
  assert.strictEqual(_tlParseRelative(''), null);
  assert.strictEqual(_tlParseRelative('15'), null);
  assert.strictEqual(_tlParseRelative('m'), null);
  assert.strictEqual(_tlParseRelative('15x'), null);
  // Zero / negative.
  assert.strictEqual(_tlParseRelative('0m'), null);
  assert.strictEqual(_tlParseRelative('-5m'), null);
  // Non-string.
  assert.strictEqual(_tlParseRelative(null), null);
  assert.strictEqual(_tlParseRelative(undefined), null);
});

test('formatRelative: picks the largest exact unit', () => {
  assert.strictEqual(_tlFormatRelative(900_000), '15m');
  assert.strictEqual(_tlFormatRelative(3_600_000), '1h');
  assert.strictEqual(_tlFormatRelative(86_400_000), '1d');
  assert.strictEqual(_tlFormatRelative(604_800_000), '1w');
  // 90 sec doesn't divide cleanly into a minute → stays 90s.
  assert.strictEqual(_tlFormatRelative(90_000), '90s');
});

test('formatRelative: bails on non-positive / non-finite', () => {
  assert.strictEqual(_tlFormatRelative(0), '');
  assert.strictEqual(_tlFormatRelative(-5), '');
  assert.strictEqual(_tlFormatRelative(NaN), '');
  assert.strictEqual(_tlFormatRelative(Infinity), '');
});

test('round-trip: parseRelative ∘ formatRelative is identity for largest-unit inputs', () => {
  // Only inputs already at their largest matching unit round-trip to
  // themselves; e.g. `7d` would normalize to `1w` (since 7d == 1w),
  // and `120m` would normalize to `2h`. The widget always emits the
  // largest unit, so this is the contract that matters in practice.
  for (const term of ['1s', '30s', '1m', '15m', '1h', '6h', '1d', '6d', '1w']) {
    const ms = _tlParseRelative(term);
    assert.ok(ms != null, `parse failed for ${term}`);
    assert.strictEqual(_tlFormatRelative(ms), term);
  }
});

test('formatRelative: normalizes to a larger unit when input is exactly one', () => {
  // Documented normalisation behaviour — `7d` is the same span as `1w`,
  // so the formatter prefers `1w`. Same for `60m` → `1h`, `60s` → `1m`.
  assert.strictEqual(_tlFormatRelative(_tlParseRelative('7d')), '1w');
  assert.strictEqual(_tlFormatRelative(_tlParseRelative('60m')), '1h');
  assert.strictEqual(_tlFormatRelative(_tlParseRelative('60s')), '1m');
  assert.strictEqual(_tlFormatRelative(_tlParseRelative('24h')), '1d');
});
