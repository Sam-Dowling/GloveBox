'use strict';
// timeline-syslog-3164.test.js — RFC 3164 syslog tokeniser + PRI decode.
//
// Covers the `_tl*` helpers that drive the Timeline structured-log
// path for `<PRI>MMM DD HH:MM:SS host program[pid]: message` lines.
// All helpers are pure (no DOM, no fetch), so they load in a fresh
// `vm.Context` alongside `constants.js`.
//
// The worker bundle hosts a second copy of these helpers (in
// `src/workers/timeline-worker-shim.js`) — the final test in this
// file diff-checks the two copies tokenise identical lines into
// identical row arrays so the sync and async parse paths can never
// silently disagree on a row's column count or cell contents.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-helpers.js',
], {
  expose: [
    '_tlDecodePri', '_tlInferYear', '_tlTokenizeSyslog3164',
    '_TL_SYSLOG3164_COLS',
  ],
});
const {
  _tlDecodePri,
  _tlInferYear,
  _tlTokenizeSyslog3164,
  _TL_SYSLOG3164_COLS,
} = ctx;

test('PRI decode: facility/severity for facility=1 (user) severity=5 (notice) → PRI 13', () => {
  const d = _tlDecodePri(13);
  // Cross-realm: object came from vm sandbox so prototype differs.
  // Compare the four documented fields explicitly.
  assert.strictEqual(d.facility, 1);
  assert.strictEqual(d.severity, 5);
  assert.strictEqual(d.severityName, 'notice');
  assert.strictEqual(d.facilityName, 'user');
});

test('PRI decode: kern.emerg = 0', () => {
  const d = _tlDecodePri(0);
  assert.strictEqual(d.facility, 0);
  assert.strictEqual(d.severity, 0);
  assert.strictEqual(d.facilityName, 'kern');
  assert.strictEqual(d.severityName, 'emergency');
});

test('PRI decode: local7.debug = 191 (max valid)', () => {
  const d = _tlDecodePri(191);
  assert.strictEqual(d.facility, 23);
  assert.strictEqual(d.severity, 7);
  assert.strictEqual(d.facilityName, 'local7');
  assert.strictEqual(d.severityName, 'debug');
});

test('PRI decode: rejects out-of-range / non-numeric values', () => {
  assert.strictEqual(_tlDecodePri(-1), null);
  assert.strictEqual(_tlDecodePri(192), null);
  assert.strictEqual(_tlDecodePri(1.5), null);
  assert.strictEqual(_tlDecodePri('abc'), null);
  assert.strictEqual(_tlDecodePri(null), null);
});

test('inferYear: uses file lastModified when finite/positive', () => {
  // 2021-06-15T12:00:00Z
  const ms = Date.UTC(2021, 5, 15, 12);
  assert.strictEqual(_tlInferYear(ms), 2021);
});

test('inferYear: falls back to current UTC year for 0 / undefined / non-finite', () => {
  const nowYear = new Date().getUTCFullYear();
  assert.strictEqual(_tlInferYear(0), nowYear);
  assert.strictEqual(_tlInferYear(undefined), nowYear);
  assert.strictEqual(_tlInferYear(NaN), nowYear);
  assert.strictEqual(_tlInferYear(-1), nowYear);
});

// Reference mtime used across the tokenise tests below — mid-October
// 2024 mid-day UTC. Picked to be well past Oct 11 (so the standard
// case below resolves to 2024) and well before Dec 31 (so the
// future-roll case has room to fire). Deterministic — the tests
// don't depend on the test runner's wall clock.
const _MTIME_2024 = Date.UTC(2024, 9, 15, 12); // 2024-10-15 12:00 UTC

test('tokenize: standard line with program + pid', () => {
  const line = '<34>Oct 11 22:14:15 mymachine su[1234]: \'su root\' failed for lonvick on /dev/pts/8';
  const cells = _tlTokenizeSyslog3164(line, _MTIME_2024);
  // [Timestamp, Severity, Facility, Host, Program, PID, Message]
  assert.strictEqual(cells.length, 7);
  assert.strictEqual(cells[0], '2024-10-11 22:14:15');
  assert.strictEqual(cells[1], 'critical');     // PRI 34 → fac=4 (auth) sev=2 (critical)
  assert.strictEqual(cells[2], 'auth');
  assert.strictEqual(cells[3], 'mymachine');
  assert.strictEqual(cells[4], 'su');
  assert.strictEqual(cells[5], '1234');
  assert.strictEqual(cells[6], "'su root' failed for lonvick on /dev/pts/8");
});

test('tokenize: program without pid', () => {
  // Line says "Jan 3" — assumes January of the file's mtime year. Use
  // a Feb-2024 mtime to keep the test outside the future-roll buffer.
  const mtimeFeb2024 = Date.UTC(2024, 1, 1, 12);
  const line = '<13>Jan  3 09:05:00 host01 cron: ran job rotate';
  const cells = _tlTokenizeSyslog3164(line, mtimeFeb2024);
  assert.strictEqual(cells[0], '2024-01-03 09:05:00');
  assert.strictEqual(cells[3], 'host01');
  assert.strictEqual(cells[4], 'cron');
  assert.strictEqual(cells[5], '');
  assert.strictEqual(cells[6], 'ran job rotate');
});

test('tokenize: tag with neither program nor pid (free message)', () => {
  // Some appliances log without a tag at all — message starts straight
  // after the host. The tokeniser should keep the host but leave
  // program/pid empty and drop the entire residue into the message
  // column.
  const line = '<14>Feb 28 00:00:01 router1 link state changed to UP';
  const cells = _tlTokenizeSyslog3164(line, _MTIME_2024);
  assert.strictEqual(cells[3], 'router1');
  assert.strictEqual(cells[4], '');
  assert.strictEqual(cells[5], '');
  assert.strictEqual(cells[6], 'link state changed to UP');
});

test('tokenize: IPv6 host renders intact in Host column', () => {
  const line = '<38>Mar 15 03:14:07 fe80::1%eth0 sshd[5577]: Accepted publickey for root';
  const cells = _tlTokenizeSyslog3164(line, _MTIME_2024);
  assert.strictEqual(cells[3], 'fe80::1%eth0');
  assert.strictEqual(cells[4], 'sshd');
  assert.strictEqual(cells[5], '5577');
});

test('tokenize: rejects malformed PRI / missing brackets', () => {
  assert.strictEqual(_tlTokenizeSyslog3164('<999>Oct 11 22:14:15 host x: y', _MTIME_2024), null); // PRI > 191
  assert.strictEqual(_tlTokenizeSyslog3164('<>Oct 11 22:14:15 host x: y', _MTIME_2024), null);
  assert.strictEqual(_tlTokenizeSyslog3164('Oct 11 22:14:15 host x: y', _MTIME_2024), null);
  assert.strictEqual(_tlTokenizeSyslog3164('', _MTIME_2024), null);
});

test('tokenize: future-month rolls back one year (Dec log opened in Jan)', () => {
  // File mtime is mid-January 2025; a "Dec 31 23:59:59" log line
  // would naively resolve to 2025-12-31 (eleven months in the future
  // relative to the file's mtime). The 30-day future-roll heuristic
  // should flip this back to 2024.
  const mtimeJan2025 = Date.UTC(2025, 0, 15, 12);
  const line = '<14>Dec 31 23:59:59 host kernel: shutdown';
  const cells = _tlTokenizeSyslog3164(line, mtimeJan2025);
  assert.strictEqual(cells[0], '2024-12-31 23:59:59');
});

test('tokenize: timestamp ≤30 days past mtime stays in mtime year', () => {
  // Edge case for the 30-day buffer: a log line dated ~2 weeks after
  // mtime should NOT roll back (clock-skew tolerance, not a year
  // flip). mtime = 2024-10-15; line = 2024-10-25 → stays in 2024.
  const line = '<14>Oct 25 09:00:00 host x: y';
  const cells = _tlTokenizeSyslog3164(line, _MTIME_2024);
  assert.strictEqual(cells[0], '2024-10-25 09:00:00');
});

test('tokenize: column header constant matches tokenised width', () => {
  assert.strictEqual(_TL_SYSLOG3164_COLS.length, 7);
  const cells = _tlTokenizeSyslog3164(
    '<13>Jan  3 09:05:00 host01 cron[1]: x', Date.UTC(2024, 1, 1, 12));
  assert.strictEqual(cells.length, _TL_SYSLOG3164_COLS.length);
});

// ── Cross-bundle parity ────────────────────────────────────────────────
//
// `timeline-worker-shim.js` carries an independent copy of
// `_tlTokenizeSyslog3164` because the worker bundle does not include
// `timeline-helpers.js`. The two copies MUST agree on every line
// shape — otherwise the same file would parse differently on
// Chrome (worker path) and Firefox `file://` (sync fallback path).
test('worker-shim copy of _tlTokenizeSyslog3164 matches main-bundle copy', () => {
  // Load the shim through the same `loadModules` harness so its top-
  // level `const` bindings get projected onto the sandbox via the
  // expose-block trick documented in `tests/helpers/load-bundle.js`.
  const shimCtx = loadModules(['src/workers/timeline-worker-shim.js'], {
    expose: ['_tlTokenizeSyslog3164', '_TL_SYSLOG3164_COLS', '_tlDecodePri'],
  });
  const shimTokenize = shimCtx._tlTokenizeSyslog3164;
  const shimCols = shimCtx._TL_SYSLOG3164_COLS;
  assert.strictEqual(typeof shimTokenize, 'function',
    'shim must export _tlTokenizeSyslog3164');
  // Cross-realm — element-wise comparison, see comment in samples loop.
  assert.strictEqual(shimCols.length, _TL_SYSLOG3164_COLS.length,
    'column count must match between main bundle and worker shim');
  for (let i = 0; i < shimCols.length; i++) {
    assert.strictEqual(shimCols[i], _TL_SYSLOG3164_COLS[i],
      'column ' + i + ' must match between main bundle and worker shim');
  }
  const samples = [
    '<34>Oct 11 22:14:15 mymachine su[1234]: \'su root\' failed for lonvick',
    '<13>Jan  3 09:05:00 host01 cron: ran job rotate',
    '<14>Feb 28 00:00:01 router1 link state changed to UP',
    '<38>Mar 15 03:14:07 fe80::1%eth0 sshd[5577]: Accepted publickey for root',
    '<14>Dec 31 23:59:59 host kernel: shutdown',
  ];
  // Use a fixed mtime so the "no mtime → Date.now()" fallback can't
  // make the two copies disagree on day-roll edge cases. Mid-Oct 2024
  // is well inside the body of every sample line below.
  const mtime = Date.UTC(2024, 9, 15, 12);
  for (const s of samples) {
    // Cross-realm Arrays have different `Array.prototype` identities,
    // which `deepStrictEqual` rejects even when contents match. Compare
    // length + element-wise instead.
    const a = shimTokenize(s, mtime);
    const b = _tlTokenizeSyslog3164(s, mtime);
    assert.strictEqual(a.length, b.length, `width must match for: ${s}`);
    for (let i = 0; i < a.length; i++) {
      assert.strictEqual(a[i], b[i],
        `cell ${i} must match for: ${s} (got '${a[i]}' vs '${b[i]}')`);
    }
  }
});
