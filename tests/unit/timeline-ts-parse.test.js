'use strict';
// timeline-ts-parse.test.js — `_tlParseTimestamp` / `_tlParseTimestampFast`
// timestamp-normalisation coverage.
//
// Scope:
//   • Regression guard for every shape the slow path already accepts
//     (epoch s/ms, ISO with bare Z / ±HHMM / ±HH:MM, " UTC" / " GMT"
//     space suffixes, Ivanti dashed, .NET JSON, date-only, year-month,
//     decimal year, YYYYMMDD, YYYY, Apache CLF).
//   • New tz-suffix shapes added to `_tlNormaliseIsoSuffix`:
//       – hyphen / underscore / no-separator `UTC`/`GMT`
//       – bracketed / parenthesised `(UTC)` / `[UTC]` / `(GMT)` / `[GMT]`
//       – space before a numeric offset (`… +0000`, `… -07:00`, `… Z`)
//   • Invalid inputs stay NaN (no accidental widening of the accept set).
//   • Fast path equals slow path for every ISO-shaped positive case.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-helpers.js',
], {
  expose: ['_tlParseTimestamp', '_tlParseTimestampFast', '_tlNormaliseIsoSuffix'],
});
const { _tlParseTimestamp, _tlParseTimestampFast, _tlNormaliseIsoSuffix } = ctx;

// Canonical reference timestamps used across the tables below.
const REF_NO_MS   = Date.UTC(2026, 3, 18, 12, 12, 40);       // 2026-04-18 12:12:40Z
const REF_WITH_MS = Date.UTC(2026, 3, 18, 12, 12, 40, 104);  // 2026-04-18 12:12:40.104Z

// ── 1. Regression guard: every already-supported shape still parses. ──
test('regression: epoch seconds / milliseconds', () => {
  assert.strictEqual(_tlParseTimestamp('1776470160'),    1776470160 * 1000);
  assert.strictEqual(_tlParseTimestamp('1776470160104'), 1776470160104);
  assert.strictEqual(_tlParseTimestamp('-1000000000'),   -1000000000 * 1000);
});

test('regression: ISO 8601 canonical forms', () => {
  assert.strictEqual(_tlParseTimestamp('2026-04-18T12:12:40Z'),          REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18T12:12:40.104Z'),      REF_WITH_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40Z'),          REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40.104Z'),      REF_WITH_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18T12:12:40+00:00'),     REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18T12:12:40.104+00:00'), REF_WITH_MS);
  // ±HHMM compact offset — V8 Date.parse accepts it.
  assert.strictEqual(_tlParseTimestamp('2026-04-18T12:12:40+0000'),      REF_NO_MS);
});

test('regression: " UTC" / " GMT" space suffix (pre-existing behaviour)', () => {
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40 UTC'),       REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40.104 UTC'),   REF_WITH_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40 GMT'),       REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40.104 GMT'),   REF_WITH_MS);
  // Lowercase tz name still normalised (case-insensitive flag).
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40 utc'),       REF_NO_MS);
});

test('regression: Ivanti dashed YYYY-MM-DD--HH-MM-SS', () => {
  assert.strictEqual(_tlParseTimestamp('2025-05-15--17-43-27'), Date.UTC(2025, 4, 15, 17, 43, 27));
  assert.ok(!Number.isFinite(_tlParseTimestamp('2025-13-01--00-00-00')));
  assert.ok(!Number.isFinite(_tlParseTimestamp('2025-01-01--25-00-00')));
});

test('regression: .NET JSON /Date(…)/ form', () => {
  assert.strictEqual(_tlParseTimestamp('/Date(1234567890123)/'),  1234567890123);
  assert.strictEqual(_tlParseTimestamp('/Date(-1234567890123)/'), -1234567890123);
});

test('regression: date-only / year-month / YYYYMMDD / YYYY', () => {
  assert.strictEqual(_tlParseTimestamp('2026-04-18'), Date.UTC(2026, 3, 18));
  assert.strictEqual(_tlParseTimestamp('2026/04/18'), Date.UTC(2026, 3, 18));
  assert.strictEqual(_tlParseTimestamp('2026.04.18'), Date.UTC(2026, 3, 18));
  assert.strictEqual(_tlParseTimestamp('2026-04'),    Date.UTC(2026, 3, 1));
  assert.strictEqual(_tlParseTimestamp('20260418'),   Date.UTC(2026, 3, 18));
  assert.strictEqual(_tlParseTimestamp('2026'),       Date.UTC(2026, 0, 1));
});

test('regression: Apache CLF bracketed/unbracketed', () => {
  // `20/Jun/2012:19:05:12 +0200` — offset subtracted to reach UTC.
  const clfMs = _tlParseTimestamp('20/Jun/2012:19:05:12 +0200');
  assert.strictEqual(clfMs, Date.UTC(2012, 5, 20, 17, 5, 12));
  assert.strictEqual(_tlParseTimestamp('[20/Jun/2012:19:05:12 +0200]'), clfMs);
  // No-offset form — treat wallclock as UTC.
  assert.strictEqual(_tlParseTimestamp('20/Jun/2012:19:05:12'),
                     Date.UTC(2012, 5, 20, 19, 5, 12));
});

// ── 2. New: hyphen / underscore / no-separator UTC/GMT suffixes. ────
test('new: hyphen-separated trailing UTC/GMT (reported bug)', () => {
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40.104-UTC'), REF_WITH_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40-UTC'),     REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18T12:12:40.104-UTC'), REF_WITH_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40.104-GMT'), REF_WITH_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40-GMT'),     REF_NO_MS);
});

test('new: underscore-separated trailing UTC/GMT', () => {
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40.104_UTC'), REF_WITH_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40_UTC'),     REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40_GMT'),     REF_NO_MS);
});

test('new: no-separator trailing UTC/GMT', () => {
  assert.strictEqual(_tlParseTimestamp('2026-04-18T12:12:40UTC'),      REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18T12:12:40.104UTC'),  REF_WITH_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18T12:12:40GMT'),      REF_NO_MS);
});

test('new: case-insensitive on new separator variants', () => {
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40.104-utc'), REF_WITH_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40-gmt'),     REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40-Utc'),     REF_NO_MS);
});

// ── 3. New: bracketed / parenthesised tz name. ──────────────────────
test('new: parenthesised (UTC)/(GMT)', () => {
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40 (UTC)'),      REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40.104 (UTC)'),  REF_WITH_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40(UTC)'),       REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40 (GMT)'),      REF_NO_MS);
});

test('new: bracketed [UTC]/[GMT]', () => {
  assert.strictEqual(_tlParseTimestamp('2026-04-18T12:12:40[UTC]'),       REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18T12:12:40.104[UTC]'),   REF_WITH_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40 [GMT]'),      REF_NO_MS);
});

// ── 4. New: space before numeric offset / trailing Z. ───────────────
test('new: space before ±HHMM / ±HH:MM offset', () => {
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40 +0000'),     REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40.104 +0000'), REF_WITH_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40 +00:00'),    REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40 -00:00'),    REF_NO_MS);
  // Non-zero offset: +02:00 means wallclock is 2h ahead of UTC.
  assert.strictEqual(_tlParseTimestamp('2026-04-18 14:12:40 +02:00'),    REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 10:12:40 -02:00'),    REF_NO_MS);
});

test('new: space before trailing Z', () => {
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40 Z'),         REF_NO_MS);
  assert.strictEqual(_tlParseTimestamp('2026-04-18 12:12:40.104 Z'),     REF_WITH_MS);
});

// ── 5. Invalid inputs stay NaN. ─────────────────────────────────────
test('invalid: nothing the new branches unlocked leaks a silent accept', () => {
  // Calendar-invalid day with new -UTC suffix.
  assert.ok(!Number.isFinite(_tlParseTimestamp('2026-13-01 00:00:00-UTC')));
  // Clock-invalid hour.
  assert.ok(!Number.isFinite(_tlParseTimestamp('2026-04-18 25:00:00 UTC')));
  assert.ok(!Number.isFinite(_tlParseTimestamp('2026-04-18 12:60:00-UTC')));
  // Empty / null / garbage.
  assert.ok(!Number.isFinite(_tlParseTimestamp('')));
  assert.ok(!Number.isFinite(_tlParseTimestamp(null)));
  assert.ok(!Number.isFinite(_tlParseTimestamp(undefined)));
  assert.ok(!Number.isFinite(_tlParseTimestamp('garbage')));
});

// ── 6. Normaliser pure-function properties. ─────────────────────────
test('normaliser: idempotent on already-canonical ISO', () => {
  const canon = '2026-04-18T12:12:40.104Z';
  assert.strictEqual(_tlNormaliseIsoSuffix(canon), canon);
  assert.strictEqual(_tlNormaliseIsoSuffix(_tlNormaliseIsoSuffix(canon)), canon);
});

test('normaliser: only touches the trailing tz; leaves body intact', () => {
  // Value fragment contains "UTC" earlier in the string — must not rewrite.
  const s = '2026-04-18 12:12:40 (notUTC actually)';
  const out = _tlNormaliseIsoSuffix(s);
  // No trailing tz marker → only the first space→T rewrite fires.
  assert.strictEqual(out, '2026-04-18T12:12:40 (notUTC actually)');
});

// ── 7. Fast path ≡ slow path for every ISO-shaped positive case. ────
test('fast path equals slow path for all ISO-shaped positive inputs', () => {
  const isoInputs = [
    '2026-04-18T12:12:40Z',
    '2026-04-18T12:12:40.104Z',
    '2026-04-18 12:12:40Z',
    '2026-04-18 12:12:40.104Z',
    '2026-04-18T12:12:40+00:00',
    '2026-04-18T12:12:40.104+00:00',
    '2026-04-18T12:12:40+0000',
    '2026-04-18 12:12:40 UTC',
    '2026-04-18 12:12:40.104 UTC',
    '2026-04-18 12:12:40 GMT',
    '2026-04-18 12:12:40.104-UTC',
    '2026-04-18 12:12:40-UTC',
    '2026-04-18 12:12:40.104_UTC',
    '2026-04-18T12:12:40UTC',
    '2026-04-18T12:12:40.104UTC',
    '2026-04-18 12:12:40 (UTC)',
    '2026-04-18T12:12:40[UTC]',
    '2026-04-18 12:12:40 +0000',
    '2026-04-18 12:12:40 +00:00',
    '2026-04-18 12:12:40 -02:00',
    '2026-04-18 12:12:40 Z',
    '2026-04-18 12:12:40.104 Z',
  ];
  for (const s of isoInputs) {
    const slow = _tlParseTimestamp(s);
    const fast = _tlParseTimestampFast(s, 'iso');
    assert.ok(Number.isFinite(slow), `slow path NaN for ${JSON.stringify(s)}`);
    assert.strictEqual(fast, slow, `fast/slow disagree for ${JSON.stringify(s)}`);
  }
});

test('fast path: invalid ISO-shaped inputs fall back to slow path (stay NaN)', () => {
  assert.ok(!Number.isFinite(_tlParseTimestampFast('2026-13-01 00:00:00-UTC', 'iso')));
  assert.ok(!Number.isFinite(_tlParseTimestampFast('2026-04-18 25:00:00 UTC', 'iso')));
  assert.ok(!Number.isFinite(_tlParseTimestampFast('', 'iso')));
});
