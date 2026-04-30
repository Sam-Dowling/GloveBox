'use strict';
// timeline-syslog-5424.test.js — RFC 5424 syslog tokeniser.
//
// RFC 5424 lines look like:
//   <PRI>VER TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
// where any field except PRI/VER may be `-` (NILVALUE), TIMESTAMP is
// ISO 8601, and SD is `-` or one-or-more `[ID k="v" k="v"]` blocks
// back-to-back. The tokeniser handles escaped `\"`, `\\`, `\]`
// inside quoted PARAM-VALUEs, multiple SD blocks, and a UTF-8 BOM
// prefix on MSG.
//
// As with the 3164 suite, the worker bundle ships its own copy of
// the tokeniser; the final test in this file enforces cross-realm
// parity so the sync (Firefox file://) and async (worker) paths can
// never disagree on row contents.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-helpers.js',
], {
  expose: [
    '_tlDecodePri', '_tlTokenizeSyslog5424',
    '_TL_SYSLOG5424_COLS',
  ],
});
const {
  _tlTokenizeSyslog5424,
  _TL_SYSLOG5424_COLS,
} = ctx;

test('5424 column constant: 9 canonical columns', () => {
  // Cross-realm: `_TL_SYSLOG5424_COLS` is an Array allocated inside
  // the vm sandbox, so its prototype identity differs from the test
  // realm's `Array.prototype`. Compare element-wise to dodge the
  // `deepStrictEqual` reference check.
  const expected = ['Timestamp', 'Severity', 'Facility', 'Host',
                    'App', 'ProcID', 'MsgID', 'StructuredData', 'Message'];
  assert.strictEqual(_TL_SYSLOG5424_COLS.length, expected.length);
  for (let i = 0; i < expected.length; i++) {
    assert.strictEqual(_TL_SYSLOG5424_COLS[i], expected[i]);
  }
});

// RFC 5424 § 6.5 example 1 — minimal, no SD, no MSG body beyond a
// short text. PRI 34 = auth.critical; VER=1.
test('tokenize: RFC 5424 § 6.5 example 1 (no SD, plain MSG)', () => {
  const line = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8";
  const cells = _tlTokenizeSyslog5424(line, 0);
  assert.strictEqual(cells.length, 9);
  assert.strictEqual(cells[0], '2003-10-11T22:14:15.003Z');
  assert.strictEqual(cells[1], 'critical');
  assert.strictEqual(cells[2], 'auth');
  assert.strictEqual(cells[3], 'mymachine.example.com');
  assert.strictEqual(cells[4], 'su');
  assert.strictEqual(cells[5], '');                   // PROCID NILVALUE
  assert.strictEqual(cells[6], 'ID47');
  assert.strictEqual(cells[7], '');                   // SD NILVALUE
  assert.strictEqual(cells[8], "BOM'su root' failed for lonvick on /dev/pts/8");
});

// RFC 5424 § 6.5 example 2 — empty MSG body, multiple NILVALUEs.
test('tokenize: NILVALUE host/app/procid/msgid', () => {
  const line = '<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It\'s time to make the do-nuts.';
  const cells = _tlTokenizeSyslog5424(line, 0);
  assert.strictEqual(cells[0], '2003-08-24T05:14:15.000003-07:00');
  assert.strictEqual(cells[1], 'notice');             // PRI 165 = local4.notice
  assert.strictEqual(cells[2], 'local4');
  assert.strictEqual(cells[3], '192.0.2.1');
  assert.strictEqual(cells[4], 'myproc');
  assert.strictEqual(cells[5], '8710');
  assert.strictEqual(cells[6], '');                   // MSGID NILVALUE
  assert.strictEqual(cells[7], '');                   // SD NILVALUE
  assert.strictEqual(cells[8], "%% It's time to make the do-nuts.");
});

// RFC 5424 § 6.5 example 3 — single SD element with multiple params.
test('tokenize: single structured-data block with multiple params', () => {
  const line = '<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOMAn application event log entry...';
  const cells = _tlTokenizeSyslog5424(line, 0);
  assert.strictEqual(cells[3], 'mymachine.example.com');
  assert.strictEqual(cells[4], 'evntslog');
  assert.strictEqual(cells[5], '');
  assert.strictEqual(cells[6], 'ID47');
  assert.strictEqual(cells[7], '[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]');
  assert.strictEqual(cells[8], 'BOMAn application event log entry...');
});

// RFC 5424 § 6.5 example 4 — multiple SD blocks back-to-back, no MSG.
test('tokenize: multiple SD blocks back-to-back with no MSG', () => {
  const line = '<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][examplePriority@32473 class="high"]';
  const cells = _tlTokenizeSyslog5424(line, 0);
  assert.strictEqual(cells[7],
    '[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][examplePriority@32473 class="high"]');
  assert.strictEqual(cells[8], '');                   // no MSG body
});

test('tokenize: escaped "]" inside a quoted PARAM-VALUE does not terminate SD', () => {
  // The `]` inside `arr="[1,2]"` is escaped per § 6.3.3. The
  // tokeniser must keep walking until the unescaped `]` at the end.
  const line = '<14>1 2024-10-15T12:00:00Z host app - msgid [exa@1 v="a\\]b" arr="\\[1,2\\]"] payload';
  const cells = _tlTokenizeSyslog5424(line, 0);
  assert.strictEqual(cells[7], '[exa@1 v="a\\]b" arr="\\[1,2\\]"]');
  assert.strictEqual(cells[8], 'payload');
});

test('tokenize: escaped backslash and double-quote inside SD', () => {
  const line = '<14>1 2024-10-15T12:00:00Z host app - msgid [x@1 q="he said \\"hi\\"" path="C:\\\\Win"] body';
  const cells = _tlTokenizeSyslog5424(line, 0);
  assert.strictEqual(cells[7], '[x@1 q="he said \\"hi\\"" path="C:\\\\Win"]');
  assert.strictEqual(cells[8], 'body');
});

test('tokenize: PRI=0 (kern.emergency)', () => {
  const line = '<0>1 2024-10-15T12:00:00Z host app - - - panic: out of memory';
  const cells = _tlTokenizeSyslog5424(line, 0);
  assert.strictEqual(cells[1], 'emergency');
  assert.strictEqual(cells[2], 'kern');
});

test('tokenize: PRI=191 (local7.debug, max valid)', () => {
  const line = '<191>1 2024-10-15T12:00:00Z host app - - - debugging';
  const cells = _tlTokenizeSyslog5424(line, 0);
  assert.strictEqual(cells[1], 'debug');
  assert.strictEqual(cells[2], 'local7');
});

test('tokenize: rejects PRI > 191', () => {
  assert.strictEqual(
    _tlTokenizeSyslog5424('<999>1 2024-10-15T12:00:00Z h a - - - x', 0),
    null);
});

test('tokenize: rejects 3164-shaped lines (no version digit)', () => {
  // The 5424 sniff puts this format ahead of 3164 in the router; the
  // tokeniser MUST refuse 3164 input outright (different shape, no
  // VERSION token after PRI) so a misclassified file produces zero
  // rows rather than garbled cells.
  const line = '<34>Oct 11 22:14:15 mymachine su[1234]: payload';
  assert.strictEqual(_tlTokenizeSyslog5424(line, 0), null);
});

test('tokenize: rejects empty / non-PRI input', () => {
  assert.strictEqual(_tlTokenizeSyslog5424('', 0), null);
  assert.strictEqual(_tlTokenizeSyslog5424('not a syslog line', 0), null);
  assert.strictEqual(_tlTokenizeSyslog5424('<>1 2024-10-15T12:00:00Z h a - - - x', 0), null);
});

test('tokenize: strips UTF-8 BOM at start of MSG', () => {
  // Some senders include a BOM at the start of the MSG to advertise
  // UTF-8 encoding (§ 6.4). It should not appear in the Message cell.
  const line = '<14>1 2024-10-15T12:00:00Z host app - - - \uFEFFhello world';
  const cells = _tlTokenizeSyslog5424(line, 0);
  assert.strictEqual(cells[8], 'hello world');
});

test('tokenize: VERSION=2 still parses (forward-compat)', () => {
  // RFC 5424 currently mandates VERSION=1 but the tokeniser accepts
  // any 1-2 digit version to avoid false negatives if the spec ever
  // revs. The cell shape stays identical.
  const line = '<14>2 2024-10-15T12:00:00Z host app - - - future';
  const cells = _tlTokenizeSyslog5424(line, 0);
  assert.strictEqual(cells.length, 9);
  assert.strictEqual(cells[3], 'host');
  assert.strictEqual(cells[8], 'future');
});

test('tokenize: column header constant matches tokenised width', () => {
  assert.strictEqual(_TL_SYSLOG5424_COLS.length, 9);
  const cells = _tlTokenizeSyslog5424(
    '<14>1 2024-10-15T12:00:00Z host app pid msgid [a@1 k="v"] body', 0);
  assert.strictEqual(cells.length, _TL_SYSLOG5424_COLS.length);
});

// ── Cross-bundle parity ────────────────────────────────────────────────
//
// `timeline-worker-shim.js` carries an independent copy of
// `_tlTokenizeSyslog5424` because the worker bundle does not include
// `timeline-helpers.js`. Same parity guarantee as the 3164 sibling
// test — every sample must produce identical row contents in both
// realms or the sync (Firefox file://) and async (worker) parse
// paths will silently diverge.
test('worker-shim copy of _tlTokenizeSyslog5424 matches main-bundle copy', () => {
  const shimCtx = loadModules(['src/workers/timeline-worker-shim.js'], {
    expose: ['_tlTokenizeSyslog5424', '_TL_SYSLOG5424_COLS', '_tlDecodePri'],
  });
  const shimTokenize = shimCtx._tlTokenizeSyslog5424;
  const shimCols = shimCtx._TL_SYSLOG5424_COLS;
  assert.strictEqual(typeof shimTokenize, 'function',
    'shim must export _tlTokenizeSyslog5424');
  assert.strictEqual(shimCols.length, _TL_SYSLOG5424_COLS.length,
    'column count must match between main bundle and worker shim');
  for (let i = 0; i < shimCols.length; i++) {
    assert.strictEqual(shimCols[i], _TL_SYSLOG5424_COLS[i],
      'column ' + i + ' must match between main bundle and worker shim');
  }
  const samples = [
    "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8",
    '<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% donuts',
    '<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] BOMAn application event log entry...',
    '<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3"][examplePriority@32473 class="high"]',
    '<14>1 2024-10-15T12:00:00Z host app - msgid [exa@1 v="a\\]b" arr="\\[1,2\\]"] payload',
  ];
  for (const s of samples) {
    const a = shimTokenize(s, 0);
    const b = _tlTokenizeSyslog5424(s, 0);
    assert.strictEqual(a.length, b.length, `width must match for: ${s}`);
    for (let i = 0; i < a.length; i++) {
      assert.strictEqual(a[i], b[i],
        `cell ${i} must match for: ${s} (got '${a[i]}' vs '${b[i]}')`);
    }
  }
});
