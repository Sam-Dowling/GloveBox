'use strict';
// timeline-cef.test.js — CEF (Common Event Format / ArcSight) tokeniser.
//
// CEF is the ArcSight-originated SIEM event format used by every
// security appliance that talks to a SIEM: Palo Alto firewalls,
// Check Point, Fortinet, McAfee ESM, Imperva WAF, Cisco ASA / FTD,
// Trend Micro, F5 ASM, Juniper SRX, etc. Lines are:
//
//   CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|ext
//
// where the first 7 fields are pipe-delimited (with `\\` and `\|`
// escaping inside) and the 8th is a space-separated `key=value`
// extension block. CEF is overwhelmingly tunnelled inside syslog
// (RFC 3164 or 5424), so the tokeniser strips any text before the
// literal `CEF:` marker.
//
// What we verify:
//   • Header field split (with backslash escapes).
//   • Extension key=value parsing — including values with spaces
//     up to the next ` <ident>=` boundary, escape sequences (`\=`,
//     `\\`, `\n`).
//   • Schema lock-in from the first record's extension keys;
//     subsequent records spill unknown keys into `_extra`.
//   • Syslog wrapper stripping — any `<…>` / RFC 5424 prefix is
//     ignored when locating the `CEF:` marker.
//   • Stack column = `Severity` (col 6, always present).
//   • Format label = `'CEF'`.
//   • Cross-realm parity with the worker-shim copy.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-parser-helpers.js',
  'src/app/timeline/timeline-helpers.js',
], {
  expose: [
    '_tlMakeCEFTokenizer', '_TL_CEF_HEADER_COLS',
    '_TL_CEF_MAX_EXT_COLUMNS',
  ],
});
const {
  _tlMakeCEFTokenizer, _TL_CEF_HEADER_COLS,
  _TL_CEF_MAX_EXT_COLUMNS,
} = ctx;

// ── Construction ──────────────────────────────────────────────────────
test('factory: returns the expected closure shape', () => {
  const tk = _tlMakeCEFTokenizer();
  assert.strictEqual(typeof tk.tokenize, 'function');
  assert.strictEqual(typeof tk.getColumns, 'function');
  assert.strictEqual(typeof tk.getDefaultStackColIdx, 'function');
  assert.strictEqual(typeof tk.getFormatLabel, 'function');
  assert.strictEqual(tk.getFormatLabel(), 'CEF');
});

test('factory: each instance is independent (no shared mutable state)', () => {
  const a = _tlMakeCEFTokenizer();
  const b = _tlMakeCEFTokenizer();
  a.tokenize('CEF:0|Vendor|Product|1.0|100|Login|3|src=10.0.0.1 act=login', 0);
  // Before B has tokenised anything, its schema must be just the
  // 7 header columns + `_extra` (no ext keys).
  const colsB = b.getColumns(0);
  assert.strictEqual(colsB.length, _TL_CEF_HEADER_COLS.length + 1);
  assert.strictEqual(colsB[colsB.length - 1], '_extra');
});

// ── Header field parsing ─────────────────────────────────────────────
test('parses the 7 canonical header fields', () => {
  const tk = _tlMakeCEFTokenizer();
  const cells = tk.tokenize(
    'CEF:0|FortiGate|FortiOS|7.4.1|22001|firewall accept|3|src=10.0.0.1 dst=8.8.8.8', 0);
  const cols = tk.getColumns(0);
  // Header columns first, in canonical order.
  assert.strictEqual(cols[0], 'Version');
  assert.strictEqual(cols[1], 'Vendor');
  assert.strictEqual(cols[2], 'Product');
  assert.strictEqual(cols[3], 'ProductVersion');
  assert.strictEqual(cols[4], 'SignatureID');
  assert.strictEqual(cols[5], 'Name');
  assert.strictEqual(cols[6], 'Severity');
  assert.strictEqual(cells[0], '0');         // Version (CEF:0 → "0")
  assert.strictEqual(cells[1], 'FortiGate');
  assert.strictEqual(cells[2], 'FortiOS');
  assert.strictEqual(cells[3], '7.4.1');
  assert.strictEqual(cells[4], '22001');
  assert.strictEqual(cells[5], 'firewall accept');
  assert.strictEqual(cells[6], '3');
});

test('honours backslash escapes in header fields (\\| and \\\\)', () => {
  const tk = _tlMakeCEFTokenizer();
  // Vendor name contains a literal `|` (escaped) and a literal `\`
  // (escaped). After unescaping the cell should carry the literal
  // characters.
  const cells = tk.tokenize(
    'CEF:0|Acme\\\\Corp|Pipe\\|Product|1.0|100|x|3|', 0);
  assert.strictEqual(cells[1], 'Acme\\Corp');
  assert.strictEqual(cells[2], 'Pipe|Product');
});

test('strips a leading syslog wrapper before the CEF marker', () => {
  const tk = _tlMakeCEFTokenizer();
  // RFC 3164 wrapper:
  const cells1 = tk.tokenize(
    '<134>Oct 15 22:14:15 fw01 vendor: CEF:0|Vendor|Product|1.0|100|Login|3|src=10.0.0.1', 0);
  assert.strictEqual(cells1[1], 'Vendor');
  assert.strictEqual(cells1[5], 'Login');
  // RFC 5424 wrapper:
  const tk2 = _tlMakeCEFTokenizer();
  const cells2 = tk2.tokenize(
    '<134>1 2024-10-15T22:14:15Z host app - - - CEF:0|V|P|1.0|100|N|3|', 0);
  assert.strictEqual(cells2[1], 'V');
  assert.strictEqual(cells2[5], 'N');
});

test('returns null for non-CEF lines (no CEF: marker)', () => {
  const tk = _tlMakeCEFTokenizer();
  assert.strictEqual(tk.tokenize('', 0), null);
  assert.strictEqual(tk.tokenize('this is not CEF', 0), null);
  // Random pipe-delimited line.
  assert.strictEqual(tk.tokenize('a|b|c|d|e|f|g|h', 0), null);
});

test('returns null when fewer than 7 pipe-separated header fields are present', () => {
  const tk = _tlMakeCEFTokenizer();
  // Only 5 pipes — malformed.
  assert.strictEqual(tk.tokenize('CEF:0|V|P|1.0|100', 0), null);
});

// ── Extension parsing ────────────────────────────────────────────────
test('parses simple key=value pairs', () => {
  const tk = _tlMakeCEFTokenizer();
  const cells = tk.tokenize(
    'CEF:0|V|P|1.0|100|N|3|src=10.0.0.1 dst=8.8.8.8 spt=443', 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cells[cols.indexOf('src')], '10.0.0.1');
  assert.strictEqual(cells[cols.indexOf('dst')], '8.8.8.8');
  assert.strictEqual(cells[cols.indexOf('spt')], '443');
});

test('extension values may contain spaces (run up to the next ` ident=` boundary)', () => {
  const tk = _tlMakeCEFTokenizer();
  // `msg` carries spaces; `act` follows.
  const cells = tk.tokenize(
    'CEF:0|V|P|1.0|100|N|3|src=10.0.0.1 msg=hello world how are you act=allow', 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cells[cols.indexOf('msg')], 'hello world how are you');
  assert.strictEqual(cells[cols.indexOf('act')], 'allow');
});

test('honours backslash escapes in ext values (\\=, \\\\, \\n)', () => {
  const tk = _tlMakeCEFTokenizer();
  // `msg=key\=val\nline2` should unescape to `key=val\nline2` (with
  // a real newline). `tag=back\\slash` → `back\slash`.
  const cells = tk.tokenize(
    'CEF:0|V|P|1.0|100|N|3|msg=key\\=val\\nline2 tag=back\\\\slash', 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cells[cols.indexOf('msg')], 'key=val\nline2');
  assert.strictEqual(cells[cols.indexOf('tag')], 'back\\slash');
});

test('empty extension block produces only the 7 header cells + _extra', () => {
  const tk = _tlMakeCEFTokenizer();
  const cells = tk.tokenize('CEF:0|V|P|1.0|100|N|3|', 0);
  const cols = tk.getColumns(0);
  // No ext keys locked in.
  assert.strictEqual(cols.length, _TL_CEF_HEADER_COLS.length + 1);
  assert.strictEqual(cols[cols.length - 1], '_extra');
  assert.strictEqual(cells.length, cols.length);
  assert.strictEqual(cells[cells.length - 1], '');
});

// ── Schema lock-in & _extra spill ────────────────────────────────────
test('first record locks the extension schema', () => {
  const tk = _tlMakeCEFTokenizer();
  tk.tokenize('CEF:0|V|P|1.0|100|N|3|src=10.0.0.1 dst=8.8.8.8 act=allow', 0);
  const cols = tk.getColumns(0);
  // Header (7) + ext from first record (3: src, dst, act) + _extra.
  assert.strictEqual(cols.length, _TL_CEF_HEADER_COLS.length + 3 + 1);
  assert.strictEqual(cols[7], 'src');
  assert.strictEqual(cols[8], 'dst');
  assert.strictEqual(cols[9], 'act');
  assert.strictEqual(cols[10], '_extra');
});

test('subsequent records project onto the locked schema', () => {
  const tk = _tlMakeCEFTokenizer();
  tk.tokenize('CEF:0|V|P|1.0|100|N|3|src=10.0.0.1 dst=8.8.8.8 act=allow', 0);
  // Record without `dst` and reordered keys — width must stay
  // identical, missing key blank.
  const cells = tk.tokenize('CEF:0|V|P|1.0|101|N|2|act=block src=10.0.0.2', 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cells.length, cols.length);
  assert.strictEqual(cells[cols.indexOf('src')], '10.0.0.2');
  assert.strictEqual(cells[cols.indexOf('dst')], '');
  assert.strictEqual(cells[cols.indexOf('act')], 'block');
});

test('unknown ext keys spill into _extra as JSON', () => {
  const tk = _tlMakeCEFTokenizer();
  tk.tokenize('CEF:0|V|P|1.0|100|N|3|src=10.0.0.1 dst=8.8.8.8', 0);
  const cells = tk.tokenize(
    'CEF:0|V|P|1.0|101|N|2|src=10.0.0.2 dst=9.9.9.9 user=alice cs1=session-42', 0);
  const cols = tk.getColumns(0);
  const extraIdx = cols.indexOf('_extra');
  const extra = JSON.parse(cells[extraIdx]);
  assert.strictEqual(extra.user, 'alice');
  assert.strictEqual(extra.cs1, 'session-42');
});

test('column count is fixed up front (header + ext + _extra)', () => {
  const tk = _tlMakeCEFTokenizer();
  tk.tokenize('CEF:0|V|P|1.0|100|N|3|src=10.0.0.1', 0);
  // _extra is ALWAYS appended, even if no record has spilled keys
  // — same fixed-width contract as JSONL.
  const cols = tk.getColumns(0);
  assert.strictEqual(cols.includes('_extra'), true);
});

// ── Default stack column ─────────────────────────────────────────────
test('default stack column is Severity (col 6)', () => {
  const tk = _tlMakeCEFTokenizer();
  const idx = tk.getDefaultStackColIdx();
  assert.strictEqual(idx, _TL_CEF_HEADER_COLS.indexOf('Severity'));
  assert.strictEqual(idx, 6);
});

// ── Robustness ───────────────────────────────────────────────────────
test('tolerates a leading UTF-8 BOM on the first line', () => {
  const tk = _tlMakeCEFTokenizer();
  const cells = tk.tokenize(
    '\uFEFFCEF:0|V|P|1.0|100|N|3|src=10.0.0.1', 0);
  assert.strictEqual(cells[1], 'V');
});

test('skips invalid lines without poisoning the locked schema', () => {
  const tk = _tlMakeCEFTokenizer();
  // Lock schema with a valid record.
  tk.tokenize('CEF:0|V|P|1.0|100|N|3|src=10.0.0.1 dst=8.8.8.8', 0);
  // Garbage line — returns null, schema unchanged.
  assert.strictEqual(tk.tokenize('not CEF at all', 0), null);
  // Schema remains intact.
  const cols = tk.getColumns(0);
  assert.strictEqual(cols.length, _TL_CEF_HEADER_COLS.length + 2 + 1);
});

// ── Cross-realm parity ───────────────────────────────────────────────
test('worker-shim copy of _tlMakeCEFTokenizer matches main-bundle copy', () => {
  const shimCtx = loadModules(['src/app/timeline/timeline-parser-helpers.js', 'src/workers/timeline-worker-shim.js'], {
    expose: ['_tlMakeCEFTokenizer'],
  });
  const shimMake = shimCtx._tlMakeCEFTokenizer;
  assert.strictEqual(typeof shimMake, 'function',
    'shim must export _tlMakeCEFTokenizer');
  const drive = (factory) => {
    const tk = factory();
    const lines = [
      'CEF:0|FortiGate|FortiOS|7.4.1|22001|firewall accept|3|src=10.0.0.1 dst=8.8.8.8 spt=443',
      '<134>Oct 15 22:14:18 fw01 vendor: CEF:0|FortiGate|FortiOS|7.4.1|22002|firewall deny|6|src=10.0.0.2 dst=9.9.9.9 act=block',
      'not-CEF',
      '',
      'CEF:0|FortiGate|FortiOS|7.4.1|22003|ips alert|9|src=10.0.0.3 dst=8.8.8.8 user=eve cs1=signature-XYZ',
      'CEF:0|V\\|Q|P\\\\1|1.0|escape-test|low|3|msg=key\\=val with spaces act=ok',
    ];
    return {
      out: lines.map(l => tk.tokenize(l, 0)),
      cols: tk.getColumns(0),
      label: tk.getFormatLabel(),
      stackIdx: tk.getDefaultStackColIdx(),
    };
  };
  const a = drive(_tlMakeCEFTokenizer);
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

test('schema is capped at MAX_EXT_COLUMNS to avoid OOM', () => {
  const tk = _tlMakeCEFTokenizer();
  // Build a record with way more ext keys than the cap.
  const pairs = [];
  for (let i = 0; i < _TL_CEF_MAX_EXT_COLUMNS + 50; i++) {
    pairs.push('k' + i + '=v' + i);
  }
  tk.tokenize('CEF:0|V|P|1.0|100|N|3|' + pairs.join(' '), 0);
  const cols = tk.getColumns(0);
  // Header (7) + capped ext + _extra.
  assert.strictEqual(cols.length, _TL_CEF_HEADER_COLS.length + _TL_CEF_MAX_EXT_COLUMNS + 1);
});
