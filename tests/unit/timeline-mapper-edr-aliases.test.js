'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-mapper-edr-aliases.test.js — pin the EDR / endpoint-export
// alias coverage in the CSV mapper's probe lists.
//
// Loupe's CSV mapper projects native columns into the canonical Timeline
// schema by header-name probing (case-insensitive Map lookups). The probe
// lists in `src/app/timeline/timeline-mapper.js` recognise the column-
// name conventions used by:
//   • CrowdStrike Falcon (`aid`, `ComputerName`, `event_simpleName`,
//     `LocalAddressIP4`, `RemoteAddressIP4`, `UserName`)
//   • Microsoft Defender for Endpoint / Advanced Hunting (`DeviceName`,
//     `ActionType`, `AccountName`, `RemoteIP`,
//     `InitiatingProcessAccountName`)
//   • SentinelOne Deep Visibility (dotted `agent.name`, `event.type`,
//     `src.ip.address`, `dst.ip.address`, `src.process.user`)
//   • Cortex XDR (`_time`, `agent_hostname`, `event_type`,
//     `action_local_ip`, `action_remote_ip`)
//   • Microsoft 365 audit / Okta system log / Elastic ECS — already
//     covered by the existing alias set; one regression test re-pins
//     the ECS shape (`@timestamp`, `host.name`, `user.name`,
//     `event.action`, `event.category`, `source.ip`, `destination.ip`)
//     so a future trim doesn't accidentally drop the ECS overlap.
//
// What this test pins:
//   • Per-vendor happy path: a stub source with the vendor's
//     distinctive header set + a synthetic row produces the right
//     canonical projection.
//   • Probe ordering: when a row carries BOTH a simple alias
//     (`AccountName`) and a more-specific one
//     (`InitiatingProcessAccountName`), the simpler / earlier-listed
//     one wins. Pin so a future "let me reorder for Cortex priority"
//     refactor doesn't silently shadow MDE's primary actor.
//   • Native-plane guard: wide-narrative columns
//     (`ProcessCommandLine`, `process.command_line`,
//     `actor_process_command_line`, `CommandLine`) do NOT land in any
//     canonical slot. Belt-and-braces guard for the trim policy.
//
// Static stubs (not real exports) — every row is hand-crafted with
// privacy-safe placeholder identities (`alice@example.invalid`,
// `WIN-DC01`, `10.0.0.5` / `203.0.113.7`, etc.).
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle.js');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
void REPO_ROOT;

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-parser-helpers.js',
  'src/app/timeline/timeline-mapper.js',
], {
  expose: ['TIMELINE_MAPPERS', 'TIMELINE_CANONICAL_COLS'],
});
const { TIMELINE_MAPPERS, TIMELINE_CANONICAL_COLS } = ctx;

// ── Helper — build a minimal SourceRecord stub for mapper calls ────────────
function stubSource(formatKind, columns) {
  return {
    formatKind,
    baseColumns: columns,
    sourceLabel: 'edr-test',
  };
}

// ── CrowdStrike Falcon ────────────────────────────────────────────────────

test('CrowdStrike Falcon: full-shape row populates Host / EventID / User / SourceIP / DestIP', () => {
  // Falcon Event Search / Real Time Response timeline export columns.
  // `aid` is the agent ID (UUID-shaped); `LocalAddressIP4` /
  // `RemoteAddressIP4` are the agent-perspective socket endpoints.
  const src = stubSource('csv', [
    'timestamp', 'aid', 'ComputerName', 'event_simpleName',
    'UserName', 'CommandLine', 'LocalAddressIP4', 'RemoteAddressIP4',
    'SHA256HashData',
  ]);
  const out = TIMELINE_MAPPERS.csv(src, [
    '2026-04-08T18:37:13.550Z',
    '11111111-2222-3333-4444-555555555555',
    'WIN-DC01',
    'ProcessRollup2',
    'alice@example.invalid',
    'C:\\Windows\\System32\\cmd.exe /c whoami',
    '10.0.0.5',
    '203.0.113.7',
    'a'.repeat(64),
  ]);
  assert.equal(out.Timestamp, '2026-04-08T18:37:13.550Z');
  assert.equal(out.Host, 'WIN-DC01');                    // ComputerName → Host
  assert.equal(out.EventID, 'ProcessRollup2');           // event_simpleName → EventID
  assert.equal(out.User, 'alice@example.invalid');       // UserName → User
  assert.equal(out.SourceIP, '10.0.0.5');                // LocalAddressIP4 → SourceIP
  assert.equal(out.DestIP, '203.0.113.7');               // RemoteAddressIP4 → DestIP
  // Wide-narrative stays native:
  assert.equal(out.Process, undefined);
  assert.equal(out.Message, undefined);
});

// ── Microsoft Defender for Endpoint / Advanced Hunting ────────────────────

test('MDE Advanced Hunting: full-shape row populates canonicals from MDE column names', () => {
  // MDE Advanced Hunting Kusto query export. `ActionType` is the
  // primary action discriminator (e.g. `ProcessCreated`, `FileCreated`,
  // `LogonSuccess`); `RemoteIP` is the destination from the agent's
  // perspective; `AccountName` is the simple actor name.
  const src = stubSource('csv', [
    'Timestamp', 'DeviceId', 'DeviceName', 'ActionType',
    'AccountName', 'AccountDomain',
    'FileName', 'ProcessCommandLine', 'InitiatingProcessFileName',
    'InitiatingProcessCommandLine', 'RemoteIP', 'ReportId', 'SHA256',
  ]);
  const out = TIMELINE_MAPPERS.csv(src, [
    '2026-04-08T18:38:00.000Z',
    'd77f8a2f-d30e-5fa4-9ad5-31b1cc9cee9f',
    'WIN-WS-007',
    'ProcessCreated',
    'bob',
    'CONTOSO',
    'powershell.exe',
    'powershell.exe -EncodedCommand …',
    'cmd.exe',
    'cmd.exe /c powershell …',
    '198.51.100.42',
    '4242',
    'b'.repeat(64),
  ]);
  assert.equal(out.Timestamp, '2026-04-08T18:38:00.000Z');
  assert.equal(out.Host, 'WIN-WS-007');                  // DeviceName → Host
  assert.equal(out.EventID, 'ProcessCreated');           // ActionType → EventID
  assert.equal(out.User, 'bob');                         // AccountName → User
  assert.equal(out.DestIP, '198.51.100.42');             // RemoteIP → DestIP
  // Native plane (every command-line and file-name column):
  assert.equal(out.Process, undefined);
  assert.equal(out.Message, undefined);
});

test('MDE probe ordering: AccountName wins over InitiatingProcessAccountName when both present', () => {
  // The MDE schema can carry BOTH `AccountName` (the actor of the
  // event) AND `InitiatingProcessAccountName` (the user under which
  // the parent process ran). The simpler `accountname` is earlier in
  // the User probe list so a row with both populates User from the
  // primary actor — pin so a future reorder doesn't accidentally
  // shadow it with the long, more-specific alias.
  const src = stubSource('csv', [
    'Timestamp', 'DeviceName', 'AccountName', 'InitiatingProcessAccountName',
  ]);
  const out = TIMELINE_MAPPERS.csv(src, [
    '2026-04-08T18:39:00.000Z',
    'WIN-WS-007',
    'bob',
    'SYSTEM',
  ]);
  assert.equal(out.User, 'bob',
    'AccountName must win over InitiatingProcessAccountName (probe-list order)');
});

test('MDE: InitiatingProcessAccountName fills User when AccountName is empty', () => {
  // Fallback path: a row that's just a parent-process record without
  // a primary actor still resolves User via the longer alias. Pin
  // both branches.
  const src = stubSource('csv', [
    'Timestamp', 'DeviceName', 'AccountName', 'InitiatingProcessAccountName',
  ]);
  const out = TIMELINE_MAPPERS.csv(src, [
    '2026-04-08T18:39:30.000Z',
    'WIN-WS-007',
    '',
    'SYSTEM',
  ]);
  assert.equal(out.User, 'SYSTEM',
    'InitiatingProcessAccountName must fill User when AccountName is empty');
});

// ── SentinelOne Deep Visibility ────────────────────────────────────────────

test('SentinelOne Deep Visibility: dotted-path columns populate canonicals', () => {
  // Deep Visibility queries export with dotted Elastic-ECS-style
  // column names. `agent.name` is the endpoint hostname,
  // `src.process.user` is the actor name (often a username, not a
  // command line), `event.type` is the action-class discriminator.
  const src = stubSource('csv', [
    'eventTime', 'agent.uuid', 'agent.name', 'event.type',
    'src.process.image.path', 'src.process.cmdline', 'src.process.user',
    'tgt.process.image.path', 'tgt.file.path', 'tgt.file.sha256',
    'src.ip.address', 'dst.ip.address',
  ]);
  const out = TIMELINE_MAPPERS.csv(src, [
    '2026-04-08T18:40:00.000Z',
    '99999999-aaaa-bbbb-cccc-dddddddddddd',
    'mac-laptop-13',
    'Process Creation',
    '/bin/zsh',
    'zsh -c curl http://example.invalid/',
    'carol',
    '/usr/bin/curl',
    '/tmp/payload.bin',
    'c'.repeat(64),
    '10.0.0.42',
    '203.0.113.99',
  ]);
  // `eventTime` is in the existing Timestamp probe (`time` substring
  // doesn't apply — _tlmCol is exact-match on lowercased name —
  // verify by lowercase comparison: `eventtime` ∈ probe list).
  assert.equal(out.Timestamp, '2026-04-08T18:40:00.000Z');
  assert.equal(out.Host, 'mac-laptop-13');               // agent.name → Host
  assert.equal(out.EventID, 'Process Creation');         // event.type → EventID
  assert.equal(out.User, 'carol');                       // src.process.user → User
  assert.equal(out.SourceIP, '10.0.0.42');               // src.ip.address → SourceIP
  assert.equal(out.DestIP, '203.0.113.99');              // dst.ip.address → DestIP
  // Native plane:
  assert.equal(out.Process, undefined);
  assert.equal(out.Message, undefined);
});

// ── Palo Alto Cortex XDR ──────────────────────────────────────────────────

test('Cortex XDR: investigation-timeline shape populates canonicals', () => {
  // Cortex XDR investigation timeline export. `_time` is the canonical
  // event timestamp; `event_type` is the action discriminator;
  // `action_local_ip` / `action_remote_ip` are the agent-perspective
  // network endpoints.
  const src = stubSource('csv', [
    '_time', 'agent_hostname', 'event_type',
    'actor_process_image_name', 'actor_process_command_line',
    'causality_actor_process_image_name', 'causality_actor_process_command_line',
    'action_local_ip', 'action_remote_ip',
    'action_file_path', 'action_file_sha256', 'actor_user',
  ]);
  const out = TIMELINE_MAPPERS.csv(src, [
    '2026-04-08T18:41:00.000Z',
    'host-cortex-01',
    'NETWORK_CONNECTION',
    'svchost.exe',
    'C:\\Windows\\System32\\svchost.exe -k netsvcs',
    'services.exe',
    'C:\\Windows\\System32\\services.exe',
    '10.0.0.77',
    '203.0.113.21',
    'C:\\temp\\payload.dll',
    'd'.repeat(64),
    'NT AUTHORITY\\SYSTEM',
  ]);
  assert.equal(out.Timestamp, '2026-04-08T18:41:00.000Z');
  assert.equal(out.Host, 'host-cortex-01');              // agent_hostname → Host
  assert.equal(out.EventID, 'NETWORK_CONNECTION');       // event_type → EventID
  assert.equal(out.User, 'NT AUTHORITY\\SYSTEM');        // actor_user → User
  assert.equal(out.SourceIP, '10.0.0.77');               // action_local_ip → SourceIP
  assert.equal(out.DestIP, '203.0.113.21');              // action_remote_ip → DestIP
  // Native plane (process-image columns are tracked by their original
  // column names, NOT projected into a canonical slot):
  assert.equal(out.Process, undefined);
  assert.equal(out.Message, undefined);
});

// ── Elastic ECS / Kibana export ───────────────────────────────────────────

test('Elastic ECS: dotted-path host.name / user.name / event.* / source.ip / destination.ip', () => {
  // Pin the ECS overlap so a future trim of the alias list doesn't
  // accidentally drop ECS coverage (Kibana Discover CSV exports use
  // these column names verbatim).
  const src = stubSource('csv', [
    '@timestamp', 'host.name', 'user.name',
    'event.action', 'event.category', 'event.severity',
    'source.ip', 'destination.ip',
  ]);
  const out = TIMELINE_MAPPERS.csv(src, [
    '2026-04-08T18:42:00.000Z',
    'ecs-host-1',
    'eve',
    'logged-in',
    'authentication',
    'low',
    '10.0.0.99',
    '203.0.113.55',
  ]);
  assert.equal(out.Timestamp, '2026-04-08T18:42:00.000Z');
  assert.equal(out.Host, 'ecs-host-1');                  // host.name → Host
  assert.equal(out.User, 'eve');                         // user.name → User
  assert.equal(out.EventID, 'logged-in');                // event.action → EventID
  assert.equal(out.Category, 'authentication');          // event.category → Category
  assert.equal(out.Severity, 'low');                     // event.severity → Severity
  assert.equal(out.SourceIP, '10.0.0.99');               // source.ip → SourceIP
  assert.equal(out.DestIP, '203.0.113.55');              // destination.ip → DestIP
});

// ── Cross-cutting: native-plane guards (no Process / Message ever) ────────

test('No EDR-shape row produces canonical Process / Message cells', () => {
  // Build a synthetic mega-row carrying every command-line / message
  // alias from every supported vendor + the wide-narrative columns
  // we deliberately don't probe. None of them must land in canonical
  // Process / Message — those slots are not part of the trimmed
  // canonical schema and the mapper's contract is that they stay
  // undefined.
  const src = stubSource('csv', [
    'Timestamp',
    // Falcon:
    'CommandLine',
    // MDE:
    'ProcessCommandLine', 'InitiatingProcessCommandLine', 'FileName',
    // S1:
    'src.process.cmdline', 'tgt.process.image.path', 'process.command_line',
    // Cortex:
    'actor_process_command_line', 'causality_actor_process_command_line',
    // CBC / general:
    'process_cmdline', 'process_name', 'parent_cmdline',
    // ECS-shape:
    'process.executable',
    // Generic narrative:
    'message', 'msg', 'body', 'description', 'event_data', 'raw',
  ]);
  const row = new Array(src.baseColumns.length).fill('NON_EMPTY_VALUE');
  row[0] = '2026-04-08T18:43:00.000Z';
  const out = TIMELINE_MAPPERS.csv(src, row);
  assert.equal(out.Timestamp, '2026-04-08T18:43:00.000Z');
  // The canonical schema does not carry Process or Message slots.
  assert.equal(out.Process, undefined,
    'no canonical Process even when every conceivable command-line column is populated');
  assert.equal(out.Message, undefined,
    'no canonical Message even when every conceivable message-shape column is populated');
});

// ── Probe-ordering: pre-existing aliases must still win over EDR aliases ──

test('Pre-existing aliases retain their priority (M365 UserId before MDE AccountName)', () => {
  // The M365 audit shape carries `UserId` (in the User probe list);
  // some MDE-flavoured exports also carry `AccountName`. When BOTH
  // are present, `UserId` must win because `userid` appears earlier
  // in the User probe list — that's what the existing M365 unit test
  // suite (timeline-mapper.test.js) pins, and the EDR alias additions
  // must not have shifted that.
  const src = stubSource('csv', [
    'Timestamp', 'UserId', 'AccountName',
  ]);
  const out = TIMELINE_MAPPERS.csv(src, [
    '2026-04-08T18:44:00.000Z',
    'alice@example.invalid',
    'alice-local',
  ]);
  assert.equal(out.User, 'alice@example.invalid',
    'UserId must still win over AccountName after the EDR alias expansion');
});

// ── Sanity: TIMELINE_CANONICAL_COLS unchanged by this expansion ───────────

test('TIMELINE_CANONICAL_COLS is still the trimmed 10-entry list', () => {
  // The EDR alias expansion is purely additive to probe lists; it
  // must NOT have re-introduced Process / Message canonicals.
  assert.equal(TIMELINE_CANONICAL_COLS.length, 10);
  assert.equal(TIMELINE_CANONICAL_COLS.includes('Process'), false);
  assert.equal(TIMELINE_CANONICAL_COLS.includes('Message'), false);
});
