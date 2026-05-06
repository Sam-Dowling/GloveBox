'use strict';
// timeline-w3c.test.js — W3C Extended Log File Format tokeniser.
//
// W3C Extended is the schema-on-disk format used by Microsoft
// IIS, AWS ELB / ALB / CloudFront, and a long tail of HTTP-
// adjacent services. Files start with `#`-prefixed directives:
//
//   #Software: Microsoft Internet Information Services 10.0
//   #Version: 1.0
//   #Date: 2024-04-30 00:00:00
//   #Fields: date time s-ip cs-method cs-uri-stem … sc-status time-taken
//   2024-04-30 12:34:56 10.0.0.5 GET /default.aspx … 200 42
//
// What we verify:
//   • `#Fields:` defines (and resets) the schema.
//   • Comment / metadata directives (`#Software`, `#Version`,
//     `#Date`, `#Start-Date`, `#End-Date`, `#Remark`) are ignored
//     for row data.
//   • Data rows arriving before `#Fields:` are skipped.
//   • `-` substitutes to the empty string per W3C convention.
//   • IIS `+`-encoded spaces decode back to space.
//   • Field names with parens (`cs(User-Agent)`, `cs(Referer)`)
//     are preserved.
//   • Synthesised `Timestamp` column at index 0 when both `date`
//     and `time` are present in the schema.
//   • Tab-vs-space delimiter detection per `#Fields:` directive
//     (IIS = space, ALB / CloudFront = tab).
//   • Source-label detection: IIS / ALB / ELB / CloudFront /
//     generic.
//   • Default stack column candidate probe.
//   • Width-mismatched rows handled gracefully.
//   • Cross-realm parity with the worker-shim copy.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-parser-helpers.js',
  'src/app/timeline/timeline-helpers.js',
], {
  expose: ['_tlMakeW3CTokenizer'],
});
const { _tlMakeW3CTokenizer } = ctx;

// ── Construction ────────────────────────────────────────────────────
test('factory: returns the expected closure shape', () => {
  const tk = _tlMakeW3CTokenizer();
  assert.strictEqual(typeof tk.tokenize, 'function');
  assert.strictEqual(typeof tk.getColumns, 'function');
  assert.strictEqual(typeof tk.getDefaultStackColIdx, 'function');
  assert.strictEqual(typeof tk.getFormatLabel, 'function');
  // Default label before any `#Fields:` directive is the generic
  // form.
  assert.strictEqual(tk.getFormatLabel(), 'W3C Extended');
});

// ── Directive handling ──────────────────────────────────────────────
test('comment / metadata directives produce no row data', () => {
  const tk = _tlMakeW3CTokenizer();
  assert.strictEqual(tk.tokenize('#Software: Microsoft Internet Information Services 10.0', 0), null);
  assert.strictEqual(tk.tokenize('#Version: 1.0', 0), null);
  assert.strictEqual(tk.tokenize('#Date: 2024-04-30 00:00:00', 0), null);
  assert.strictEqual(tk.tokenize('#Start-Date: 2024-04-30 00:00:00', 0), null);
  assert.strictEqual(tk.tokenize('#End-Date: 2024-04-30 23:59:59', 0), null);
  assert.strictEqual(tk.tokenize('#Remark: anything goes here', 0), null);
});

test('data rows before any `#Fields:` are skipped (return null)', () => {
  const tk = _tlMakeW3CTokenizer();
  assert.strictEqual(tk.tokenize('2024-04-30 12:34:56 10.0.0.5 GET /', 0), null);
});

test('`#Fields:` defines the schema; subsequent data rows project', () => {
  const tk = _tlMakeW3CTokenizer();
  assert.strictEqual(
    tk.tokenize('#Fields: date time s-ip cs-method cs-uri-stem sc-status', 0),
    null);
  const cells = tk.tokenize('2024-04-30 12:34:56 10.0.0.5 GET /default.aspx 200', 0);
  const cols = tk.getColumns();
  // Synthesised Timestamp + 6 declared cols.
  assert.strictEqual(cols.length, 7);
  assert.strictEqual(cols[0], 'Timestamp');
  assert.strictEqual(cells[0], '2024-04-30T12:34:56Z');
  assert.strictEqual(cells[cols.indexOf('s-ip')], '10.0.0.5');
  assert.strictEqual(cells[cols.indexOf('cs-method')], 'GET');
  assert.strictEqual(cells[cols.indexOf('sc-status')], '200');
});

// ── `-` and `+` substitutions ──────────────────────────────────────
test('`-` substitutes to the empty cell per W3C convention', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: date time s-ip cs-username sc-status', 0);
  const cells = tk.tokenize('2024-04-30 12:34:56 10.0.0.5 - 200', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells[cols.indexOf('cs-username')], '');
});

test('IIS `+`-encoded spaces decode back to space inside values', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: date time cs(User-Agent)', 0);
  const cells = tk.tokenize('2024-04-30 12:34:56 Mozilla/5.0+(Windows+NT+10.0;+x64)', 0);
  const cols = tk.getColumns();
  assert.strictEqual(
    cells[cols.indexOf('cs(User-Agent)')],
    'Mozilla/5.0 (Windows NT 10.0; x64)');
});

// ── Paren'd field names ────────────────────────────────────────────
test('field names with parens (cs(User-Agent), cs(Referer)) round-trip', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize(
    '#Fields: date time cs(User-Agent) cs(Referer) cs(Cookie)',
    0);
  const cols = tk.getColumns();
  assert.ok(cols.includes('cs(User-Agent)'));
  assert.ok(cols.includes('cs(Referer)'));
  assert.ok(cols.includes('cs(Cookie)'));
});

// ── Synthesised Timestamp ──────────────────────────────────────────
test('Timestamp column synthesised at index 0 when date+time present', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: date time s-ip', 0);
  const cells = tk.tokenize('2024-04-30 12:34:56 10.0.0.5', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cols[0], 'Timestamp');
  assert.strictEqual(cells[0], '2024-04-30T12:34:56Z');
  // Original `date` and `time` cols are preserved at their
  // declared positions (shifted right by one).
  assert.strictEqual(cells[cols.indexOf('date')], '2024-04-30');
  assert.strictEqual(cells[cols.indexOf('time')], '12:34:56');
});

test('no Timestamp synthesised when only one of date/time is present', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: time s-ip cs-method', 0);
  const cells = tk.tokenize('12:34:56 10.0.0.5 GET', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cols[0], 'time');           // no Timestamp prefix
  assert.strictEqual(cells.length, cols.length);
});

// ── Schema reset ───────────────────────────────────────────────────
test('a second `#Fields:` directive resets the schema mid-file', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: date time s-ip', 0);
  tk.tokenize('2024-04-30 12:34:56 10.0.0.5', 0);
  // Reset.
  tk.tokenize('#Fields: date time cs-method cs-uri-stem sc-status', 0);
  const cells = tk.tokenize('2024-04-30 12:35:01 GET /api 404', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cols.length, 6);            // Timestamp + 5
  assert.strictEqual(cells[cols.indexOf('cs-method')], 'GET');
  assert.strictEqual(cells[cols.indexOf('sc-status')], '404');
});

// ── Tab vs space delimiter detection ───────────────────────────────
test('tab-delimited rows (ALB-style) are detected automatically', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: type time elb client_port target_port request_processing_time target_status_code', 0);
  const cells = tk.tokenize(
    'http\t2024-04-30T12:34:56.000000Z\tapp/web/abc\t10.0.0.5:51234\t10.0.0.10:8080\t0.001\t200',
    0);
  const cols = tk.getColumns();
  assert.strictEqual(cells[cols.indexOf('elb')], 'app/web/abc');
  assert.strictEqual(cells[cols.indexOf('target_status_code')], '200');
});

test('space-delimited rows (IIS-style) are detected automatically', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: date time s-ip cs-method', 0);
  const cells = tk.tokenize('2024-04-30 12:34:56 10.0.0.5 GET', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells[cols.indexOf('cs-method')], 'GET');
});

// ── Source-label detection ─────────────────────────────────────────
test('label: IIS once `#Software` line is seen', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Software: Microsoft Internet Information Services 10.0', 0);
  tk.tokenize('#Fields: date time s-ip', 0);
  assert.strictEqual(tk.getFormatLabel(), 'IIS W3C');
});

test('label: AWS ALB when target_status_code is present', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: type time elb client_port target_port target_status_code', 0);
  assert.strictEqual(tk.getFormatLabel(), 'AWS ALB');
});

test('label: AWS ELB when backend_status_code is present (and no target_*)', () => {
  const tk = _tlMakeW3CTokenizer();
  // Real ELB Classic schema — `backend_status_code` is the
  // discriminator; `request_processing_time` lives in ALB only,
  // so we deliberately omit it here.
  tk.tokenize('#Fields: timestamp elb client:port backend:port elb_status_code backend_status_code', 0);
  assert.strictEqual(tk.getFormatLabel(), 'AWS ELB');
});

test('label: AWS CloudFront when x-edge-location is present', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: date time x-edge-location sc-bytes c-ip cs-method', 0);
  assert.strictEqual(tk.getFormatLabel(), 'AWS CloudFront');
});

test('label: generic W3C Extended when no fingerprint matches', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: date time foo bar baz', 0);
  assert.strictEqual(tk.getFormatLabel(), 'W3C Extended');
});

// ── Default stack column ───────────────────────────────────────────
test('default stack column: sc-status (IIS canonical status field)', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: date time s-ip cs-method sc-status time-taken', 0);
  const cols = tk.getColumns();
  const idx = tk.getDefaultStackColIdx();
  assert.strictEqual(cols[idx], 'sc-status');
});

test('default stack column: target_status_code (ALB)', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: type time elb target_status_code', 0);
  const cols = tk.getColumns();
  const idx = tk.getDefaultStackColIdx();
  assert.strictEqual(cols[idx], 'target_status_code');
});

test('default stack column: returns null when no candidate matches', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: date time foo bar baz', 0);
  assert.strictEqual(tk.getDefaultStackColIdx(), null);
});

// ── Robustness ─────────────────────────────────────────────────────
test('width-mismatched rows: short rows pad with empty cells', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: date time s-ip cs-method cs-uri-stem sc-status', 0);
  const cells = tk.tokenize('2024-04-30 12:34:56 10.0.0.5', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells.length, cols.length);
  assert.strictEqual(cells[cols.indexOf('cs-method')], '');
  assert.strictEqual(cells[cols.indexOf('sc-status')], '');
});

test('width-mismatched rows: long rows truncate to schema width', () => {
  const tk = _tlMakeW3CTokenizer();
  tk.tokenize('#Fields: date time s-ip', 0);
  const cells = tk.tokenize('2024-04-30 12:34:56 10.0.0.5 extra1 extra2', 0);
  const cols = tk.getColumns();
  assert.strictEqual(cells.length, cols.length);
});

test('returns null for empty / blank lines', () => {
  const tk = _tlMakeW3CTokenizer();
  assert.strictEqual(tk.tokenize('', 0), null);
});

test('tolerates a leading UTF-8 BOM on the first line', () => {
  const tk = _tlMakeW3CTokenizer();
  assert.strictEqual(
    tk.tokenize('\uFEFF#Software: Microsoft Internet Information Services 10.0', 0),
    null);
  tk.tokenize('#Fields: date time s-ip', 0);
  assert.strictEqual(tk.getFormatLabel(), 'IIS W3C');
});

// ── Cross-realm parity ────────────────────────────────────────────
test('worker-shim copy of _tlMakeW3CTokenizer matches main-bundle copy', () => {
  const shimCtx = loadModules(['src/app/timeline/timeline-parser-helpers.js', 'src/workers/timeline-worker-shim.js'], {
    expose: ['_tlMakeW3CTokenizer'],
  });
  const shimMake = shimCtx._tlMakeW3CTokenizer;
  assert.strictEqual(typeof shimMake, 'function',
    'shim must export _tlMakeW3CTokenizer');
  const drive = (factory) => {
    const tk = factory();
    const lines = [
      '#Software: Microsoft Internet Information Services 10.0',
      '#Version: 1.0',
      '#Date: 2024-04-30 00:00:00',
      '#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken',
      '2024-04-30 12:34:56 10.0.0.5 GET /default.aspx - 443 - 185.220.101.33 Mozilla/5.0+(Windows+NT+10.0) - 200 0 0 42',
      '2024-04-30 12:34:57 10.0.0.5 POST /api/login - 443 alice 10.0.0.6 curl/7.81 - 401 0 0 8',
      '#Fields: type time elb client_port target_port target_status_code',
      'http\t2024-04-30T12:35:00Z\tapp/web\t10.0.0.5:51234\t10.0.0.10:8080\t200',
      '',
    ];
    return {
      out: lines.map(l => tk.tokenize(l, 0)),
      cols: tk.getColumns(),
      label: tk.getFormatLabel(),
      stackIdx: tk.getDefaultStackColIdx(),
    };
  };
  const a = drive(_tlMakeW3CTokenizer);
  const b = drive(shimMake);
  assert.strictEqual(a.out.length, b.out.length);
  for (let i = 0; i < a.out.length; i++) {
    const ai = a.out[i], bi = b.out[i];
    if (ai === null || bi === null) {
      assert.strictEqual(ai, bi, `line ${i} null parity`);
      continue;
    }
    assert.strictEqual(ai.length, bi.length, `line ${i} width`);
    for (let j = 0; j < ai.length; j++) {
      assert.strictEqual(ai[j], bi[j], `line ${i} cell ${j}`);
    }
  }
  assert.strictEqual(a.cols.length, b.cols.length);
  for (let i = 0; i < a.cols.length; i++) {
    assert.strictEqual(a.cols[i], b.cols[i], 'col ' + i);
  }
  assert.strictEqual(a.label, b.label);
  assert.strictEqual(a.stackIdx, b.stackIdx);
});
