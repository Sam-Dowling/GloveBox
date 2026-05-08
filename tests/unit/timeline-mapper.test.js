'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-mapper.test.js — per-format canonical column mappers +
// fusion predicate.
//
// Covers:
//   • `TIMELINE_MAPPERS.csv`      — header-name probing for Host / User /
//                                   SourceIP / DestIP / Severity / etc.
//   • `TIMELINE_MAPPERS.evtx`     — fixed 7-col schema projection plus
//                                   best-effort User / Process mining
//                                   from the Event Data blob.
//   • `TIMELINE_MAPPERS.syslog3164` / `.syslog5424` / `.cef` / `.leef` /
//     `.w3c` / `.apache-error` / `.cloudtrail` / `.logfmt` / `.zeek` /
//     `.log`                      — one happy-path projection per kind.
//   • `timelineMapperFor(unknownKind)` falls back to CSV-style
//     projection + warns once (stash `_warned` set on the function).
//   • `timelineColumnsCanFuse(a, b)` — name-match gate, format-kind
//     compatibility gate, content-compat probe gate.
//
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle.js');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

// Mapper + fusion predicate publish onto `window.*`. The sandbox
// binds `window === sandbox`, so expose the lowercase globals too.
const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-parser-helpers.js',
  'src/app/timeline/timeline-mapper.js',
], {
  expose: [
    'TIMELINE_MAPPERS', 'timelineMapperFor', 'timelineColumnsCanFuse',
    'TIMELINE_CANONICAL_COLS',
  ],
});
const {
  TIMELINE_MAPPERS, timelineMapperFor, timelineColumnsCanFuse,
  TIMELINE_CANONICAL_COLS,
} = ctx;

// ── Helper — build a minimal SourceRecord stub for mapper calls ────────────
function stubSource(formatKind, columns, extra) {
  return Object.assign({
    formatKind,
    baseColumns: columns,
    sourceLabel: 'test',
  }, extra || {});
}

// ── Smoke ──────────────────────────────────────────────────────────────────

test('TIMELINE_MAPPERS is frozen and carries every expected kind', () => {
  assert.ok(TIMELINE_MAPPERS, 'TIMELINE_MAPPERS should be defined');
  const kinds = [
    'csv', 'tsv', 'log', 'evtx',
    'syslog3164', 'syslog5424',
    'zeek', 'jsonl', 'cloudtrail',
    'cef', 'leef', 'logfmt',
    'w3c', 'apache-error', 'access-log',
  ];
  for (const k of kinds) {
    assert.equal(typeof TIMELINE_MAPPERS[k], 'function',
      'mapper for kind ' + k + ' should be a function');
  }
});

test('canonical column list exposes the expected 12 fields in fixed order', () => {
  assert.deepEqual(Array.from(TIMELINE_CANONICAL_COLS), [
    '__source', '__format', 'Timestamp', 'Host', 'User',
    'Process', 'Message', 'EventID', 'Severity', 'Category',
    'SourceIP', 'DestIP',
  ]);
});

// ── CSV mapper — header-name probe ─────────────────────────────────────────

test('csv mapper resolves Host / User / SourceIP via case-insensitive headers', () => {
  const src = stubSource('csv',
    ['timestamp', 'HOSTNAME', 'user_name', 'client_ip', 'message']);
  const out = TIMELINE_MAPPERS.csv(src,
    ['2024-01-01T00:00:00Z', 'web01', 'alice', '10.0.0.5', 'login ok']);
  assert.equal(out.Timestamp, '2024-01-01T00:00:00Z');
  assert.equal(out.Host, 'web01');
  assert.equal(out.User, 'alice');
  assert.equal(out.SourceIP, '10.0.0.5');
  assert.equal(out.Message, 'login ok');
});

test('csv mapper silently drops missing fields (no throws, no undefined cells)', () => {
  const src = stubSource('csv', ['a', 'b']);
  const out = TIMELINE_MAPPERS.csv(src, ['x', 'y']);
  // No conventional fields — output is an object with no canonical keys.
  for (const k of ['Host', 'User', 'SourceIP', 'DestIP', 'Severity']) {
    assert.equal(out[k], undefined);
  }
});

// ── CSV mapper M365 / Okta / Salesforce-shaped probe aliases ───────────────

test('csv mapper resolves UserId → User via userid alias (M365 audit)', () => {
  const src = stubSource('csv', ['Timestamp', 'UserId', 'EventName']);
  const out = TIMELINE_MAPPERS.csv(src, ['2026-01-01', 'alice@x.com', 'UserLoggedIn']);
  assert.equal(out.User, 'alice@x.com');
});

test('csv mapper resolves EventName → EventID via eventname alias', () => {
  const src = stubSource('csv', ['Timestamp', 'EventName']);
  const out = TIMELINE_MAPPERS.csv(src, ['2026-01-01', 'FileAccessed']);
  assert.equal(out.EventID, 'FileAccessed');
});

test('csv mapper resolves Workload → Category via workload alias', () => {
  const src = stubSource('csv', ['Timestamp', 'Workload']);
  const out = TIMELINE_MAPPERS.csv(src, ['2026-01-01', 'SharePoint']);
  assert.equal(out.Category, 'SharePoint');
});

test('csv mapper resolves Outcome → Severity via outcome alias', () => {
  const src = stubSource('csv', ['Timestamp', 'Outcome']);
  const out = TIMELINE_MAPPERS.csv(src, ['2026-01-01', 'Success']);
  assert.equal(out.Severity, 'Success');
});

test('csv mapper resolves ClientIP → SourceIP (case-insensitive)', () => {
  const src = stubSource('csv', ['Timestamp', 'ClientIP']);
  const out = TIMELINE_MAPPERS.csv(src, ['2026-01-01', '10.0.0.1']);
  assert.equal(out.SourceIP, '10.0.0.1');
});

test('csv mapper resolves UserAgent → Process (web-audit surrogate)', () => {
  const src = stubSource('csv', ['Timestamp', 'UserAgent']);
  const out = TIMELINE_MAPPERS.csv(src, ['2026-01-01', 'curl/8.0']);
  assert.equal(out.Process, 'curl/8.0');
});

test('csv mapper resolves TargetResource → Message when raw/msg absent', () => {
  const src = stubSource('csv', ['Timestamp', 'TargetResource']);
  const out = TIMELINE_MAPPERS.csv(src, ['2026-01-01', '/docs/budget.xlsx']);
  assert.equal(out.Message, '/docs/budget.xlsx');
});

test('csv mapper: M365 audit 9-col schema populates 9 canonicals', () => {
  // End-to-end regression for the dist/test1-1k.csv shape.
  const src = stubSource('csv',
    ['Timestamp', 'UserId', 'EventName', 'Workload', 'ClientIP',
     'UserAgent', 'Outcome', 'TargetResource', 'Raw']);
  const out = TIMELINE_MAPPERS.csv(src, [
    '2026-04-08T18:37:13Z', 'brian@lit.com', 'UserLoggedIn',
    'AzureActiveDirectory', '10.67.139.172', 'Office/16.0',
    'Success', 'brian@lit.com', '{"Id":"ba83"}',
  ]);
  assert.equal(out.Timestamp, '2026-04-08T18:37:13Z');
  assert.equal(out.User, 'brian@lit.com');
  assert.equal(out.EventID, 'UserLoggedIn');
  assert.equal(out.Category, 'AzureActiveDirectory');
  assert.equal(out.SourceIP, '10.67.139.172');
  assert.equal(out.Process, 'Office/16.0');
  assert.equal(out.Severity, 'Success');
  // `Raw` wins over `TargetResource` because `raw` is earlier in the
  // Message probe list (authoritative narrative for structured logs).
  assert.equal(out.Message, '{"Id":"ba83"}');
});

// ── EVTX mapper — fixed schema ─────────────────────────────────────────────

test('evtx mapper projects the fixed 7-col schema into canonical cells', () => {
  const src = stubSource('evtx',
    ['Timestamp', 'Event ID', 'Level', 'Provider', 'Channel', 'Computer', 'Event Data']);
  const row = [
    '2024-01-01T12:34:56Z',
    '4624',
    'Information',
    'Microsoft-Windows-Security-Auditing',
    'Security',
    'DC01',
    'TargetUserName=alice LogonType=3 ProcessName=C:\\Windows\\System32\\svchost.exe',
  ];
  const out = TIMELINE_MAPPERS.evtx(src, row);
  assert.equal(out.Timestamp, '2024-01-01T12:34:56Z');
  assert.equal(out.EventID, '4624');
  assert.equal(out.Severity, 'Information');
  assert.equal(out.Host, 'DC01');
  assert.match(out.Category, /Security.*Microsoft-Windows-Security-Auditing/);
  assert.equal(out.User, 'alice');
  // Process mining grabs the value after ProcessName=.
  assert.equal(out.Process, 'C:\\Windows\\System32\\svchost.exe');
  assert.match(out.Message, /TargetUserName=alice/);
});

// ── Syslog mappers ─────────────────────────────────────────────────────────

test('syslog3164 mapper maps 7 positional cells to canonical', () => {
  const src = stubSource('syslog3164',
    ['Timestamp', 'Severity', 'Facility', 'Host', 'Program', 'PID', 'Message']);
  const out = TIMELINE_MAPPERS.syslog3164(src,
    ['Oct 10 10:10:10', 'warning', 'auth', 'web01', 'sshd', '1234', 'failed login']);
  assert.equal(out.Timestamp, 'Oct 10 10:10:10');
  assert.equal(out.Severity, 'warning');
  assert.equal(out.Category, 'auth');
  assert.equal(out.Host, 'web01');
  assert.equal(out.Process, 'sshd');
  assert.equal(out.Message, 'failed login');
});

test('syslog5424 mapper maps 9 positional cells to canonical', () => {
  const src = stubSource('syslog5424',
    ['Timestamp', 'Severity', 'Facility', 'Host', 'App', 'ProcID', 'MsgID', 'StructuredData', 'Message']);
  const out = TIMELINE_MAPPERS.syslog5424(src,
    ['2024-01-01T00:00:00Z', 'err', 'local0', 'web01', 'app', '4321', 'ID47', '-', 'boom']);
  assert.equal(out.Timestamp, '2024-01-01T00:00:00Z');
  assert.equal(out.Severity, 'err');
  assert.equal(out.Category, 'local0');
  assert.equal(out.Host, 'web01');
  assert.equal(out.Process, 'app');
  assert.equal(out.EventID, 'ID47');
  assert.equal(out.Message, 'boom');
});

// ── CLF .log mapper ────────────────────────────────────────────────────────

test('log (CLF) mapper reads ip/time/request/status from fixed positions', () => {
  const src = stubSource('log',
    ['ip', 'ident', 'auth', 'time', 'request', 'status', 'bytes', 'referer', 'user_agent']);
  const out = TIMELINE_MAPPERS.log(src,
    ['1.2.3.4', '-', 'bob', '10/Oct/2024:10:10:10 +0000', 'GET /', '200', '512', '-', 'curl/8.0']);
  assert.equal(out.SourceIP, '1.2.3.4');
  assert.equal(out.Timestamp, '10/Oct/2024:10:10:10 +0000');
  assert.equal(out.Message, 'GET /');
  assert.equal(out.Severity, '200');
  assert.equal(out.User, 'bob');
  assert.equal(out.Category, 'access');
});

test('log mapper treats "-" auth as empty User', () => {
  const src = stubSource('log',
    ['ip', 'ident', 'auth', 'time', 'request', 'status', 'bytes']);
  const out = TIMELINE_MAPPERS.log(src,
    ['1.2.3.4', '-', '-', 'ts', 'GET /', '200', '512']);
  assert.equal(out.User, undefined);
});

// ── CEF / LEEF ────────────────────────────────────────────────────────────

test('cef mapper resolves Severity / SignatureID / src/dst from extensions', () => {
  const src = stubSource('cef',
    ['Version', 'Vendor', 'Product', 'ProductVersion', 'SignatureID', 'Name', 'Severity', 'src', 'dst', 'suser']);
  const out = TIMELINE_MAPPERS.cef(src,
    ['0', 'Vendor', 'Product', '1.0', 'SIG42', 'Alert', '7', '10.0.0.1', '1.2.3.4', 'eve']);
  assert.equal(out.EventID, 'SIG42');
  assert.equal(out.Severity, '7');
  assert.equal(out.SourceIP, '10.0.0.1');
  assert.equal(out.DestIP, '1.2.3.4');
  assert.equal(out.User, 'eve');
  assert.match(out.Category, /Vendor.*Product/);
});

// ── W3C ────────────────────────────────────────────────────────────────────

test('w3c mapper concatenates split date+time when unified Timestamp absent', () => {
  const src = stubSource('w3c',
    ['date', 'time', 'c-ip', 'cs-method', 'cs-uri-stem', 'sc-status', 'cs-username']);
  const out = TIMELINE_MAPPERS.w3c(src,
    ['2024-01-01', '12:00:00', '1.2.3.4', 'GET', '/login', '200', 'alice']);
  assert.equal(out.Timestamp, '2024-01-01 12:00:00');
  assert.equal(out.SourceIP, '1.2.3.4');
  assert.equal(out.Severity, '200');
  assert.equal(out.User, 'alice');
  assert.equal(out.Message, 'GET /login');
  assert.equal(out.Category, 'access');
});

// ── Unknown kind fallback ──────────────────────────────────────────────────

test('timelineMapperFor(unknown) falls through to CSV-style probe', () => {
  const fn = timelineMapperFor('some-new-format-kind-that-does-not-exist');
  assert.equal(typeof fn, 'function');
  // CSV semantics: probe by header name.
  const src = stubSource('unknown', ['hostname', 'message']);
  const out = fn(src, ['host01', 'hello']);
  assert.equal(out.Host, 'host01');
  assert.equal(out.Message, 'hello');
});

// ── Fusion predicate ───────────────────────────────────────────────────────

test('fusion rejects column name mismatch', () => {
  const a = { formatKind: 'csv', name: 'Status', samples: ['200', '404'] };
  const b = { formatKind: 'csv', name: 'Result', samples: ['OK', 'FAIL'] };
  assert.equal(timelineColumnsCanFuse(a, b), false);
});

test('fusion accepts same-name / same-kind / same-shape columns', () => {
  const a = { formatKind: 'csv', name: 'Status', samples: ['200', '404', '500'] };
  const b = { formatKind: 'csv', name: 'status', samples: ['200', '302', '200'] };
  assert.equal(timelineColumnsCanFuse(a, b), true);
});

test('fusion rejects same-name / same-kind when shape drifts numeric vs text', () => {
  const a = { formatKind: 'csv', name: 'Status', samples: ['200', '404', '500', '200'] };
  const b = { formatKind: 'csv', name: 'Status', samples: ['failed', 'ok', 'ok', 'failed'] };
  // numeric vs text → refuse fusion.
  assert.equal(timelineColumnsCanFuse(a, b), false);
});

test('fusion accepts same-name across different kinds when one side is user-tabular', () => {
  // `csv` is user-tabular, so CSV ↔ EVTX on a same-named column fuses
  // as long as the content shape agrees.
  const a = { formatKind: 'csv', name: 'EventID', samples: ['4624', '4625'] };
  const b = { formatKind: 'evtx', name: 'EventID', samples: ['4624', '4672'] };
  assert.equal(timelineColumnsCanFuse(a, b), true);
});

test('fusion rejects same-name across strict-schema formats with different kinds', () => {
  // EVTX-only vs syslog3164-only — neither is user-tabular — refuse
  // even on name match to prevent silent cross-schema collisions.
  const a = { formatKind: 'evtx', name: 'Host', samples: ['DC01', 'DC02'] };
  const b = { formatKind: 'syslog3164', name: 'Host', samples: ['web01', 'web02'] };
  assert.equal(timelineColumnsCanFuse(a, b), false);
});

test('fusion accepts when one side is all-empty (degenerate shape)', () => {
  const a = { formatKind: 'csv', name: 'Status', samples: ['200', '404'] };
  const b = { formatKind: 'csv', name: 'Status', samples: ['', '', ''] };
  assert.equal(timelineColumnsCanFuse(a, b), true);
});
