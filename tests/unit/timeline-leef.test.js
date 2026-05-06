'use strict';
// timeline-leef.test.js — LEEF (IBM QRadar Log Event Extended
// Format) tokeniser.
//
// LEEF is QRadar's analogue to ArcSight CEF. Two on-disk shapes:
//   • LEEF 1.0:  LEEF:1.0|Vendor|Product|Ver|EventID|<TAB>k=v<TAB>k=v
//   • LEEF 2.0:  LEEF:2.0|Vendor|Product|Ver|EventID|<delim>|k=v<delim>k=v
//
// LEEF 1.0 hard-codes the extension delimiter to TAB. LEEF 2.0
// adds an optional 6th header field declaring the delimiter
// character (single char, or `\xHH` / `0xHH` hex escape). Like
// CEF, LEEF is overwhelmingly tunnelled inside syslog — the
// tokeniser strips any text before the literal `LEEF:` marker.
//
// What we verify:
//   • Header field split for both LEEF 1.0 (5 fields) and LEEF
//     2.0 (5 emitted fields + delimiter spec consumed internally).
//   • Tab-delimited extension parsing for LEEF 1.0.
//   • Custom-delimiter extension parsing for LEEF 2.0 (literal
//     char and hex escape).
//   • Backslash escapes in ext values (`\=`, `\\`, `\n`, `\<delim>`).
//   • Schema lock-in from first record; later records spill
//     unknown keys to `_extra`.
//   • Default stack column heuristic (`sev` first, then `cat`).
//   • Format label = `'LEEF'`.
//   • Cross-realm parity with the worker-shim copy.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-parser-helpers.js',
  'src/app/timeline/timeline-helpers.js',
], {
  expose: ['_tlMakeLEEFTokenizer', '_TL_LEEF_HEADER_COLS'],
});
const { _tlMakeLEEFTokenizer, _TL_LEEF_HEADER_COLS } = ctx;

// ── Construction ──────────────────────────────────────────────────────
test('factory: returns the expected closure shape', () => {
  const tk = _tlMakeLEEFTokenizer();
  assert.strictEqual(typeof tk.tokenize, 'function');
  assert.strictEqual(typeof tk.getColumns, 'function');
  assert.strictEqual(typeof tk.getDefaultStackColIdx, 'function');
  assert.strictEqual(typeof tk.getFormatLabel, 'function');
  assert.strictEqual(tk.getFormatLabel(), 'LEEF');
});

// ── LEEF 1.0 header parsing ──────────────────────────────────────────
test('LEEF 1.0: parses the 5 canonical header fields', () => {
  const tk = _tlMakeLEEFTokenizer();
  const cells = tk.tokenize(
    'LEEF:1.0|IBM|QRadar|7.4|EVT100|\tsrc=10.0.0.1\tdst=8.8.8.8\tsev=5', 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cols[0], 'Version');
  assert.strictEqual(cols[1], 'Vendor');
  assert.strictEqual(cols[2], 'Product');
  assert.strictEqual(cols[3], 'ProductVersion');
  assert.strictEqual(cols[4], 'EventID');
  assert.strictEqual(cells[0], '1.0');
  assert.strictEqual(cells[1], 'IBM');
  assert.strictEqual(cells[2], 'QRadar');
  assert.strictEqual(cells[3], '7.4');
  assert.strictEqual(cells[4], 'EVT100');
});

test('LEEF 1.0: tab-delimited ext parses to schema columns', () => {
  const tk = _tlMakeLEEFTokenizer();
  const cells = tk.tokenize(
    'LEEF:1.0|IBM|QRadar|7.4|EVT100|\tsrc=10.0.0.1\tdst=8.8.8.8\tsev=5', 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cells[cols.indexOf('src')], '10.0.0.1');
  assert.strictEqual(cells[cols.indexOf('dst')], '8.8.8.8');
  assert.strictEqual(cells[cols.indexOf('sev')], '5');
});

// ── LEEF 2.0 with custom delimiter ───────────────────────────────────
test('LEEF 2.0: literal-char custom delimiter (caret)', () => {
  const tk = _tlMakeLEEFTokenizer();
  const cells = tk.tokenize(
    'LEEF:2.0|IBM|QRadar|7.4|EVT200|^|src=10.0.0.1^dst=8.8.8.8^sev=7', 0);
  const cols = tk.getColumns(0);
  // Delimiter spec field is CONSUMED, not emitted.
  assert.strictEqual(cells.length, _TL_LEEF_HEADER_COLS.length + 3 + 1);
  assert.strictEqual(cells[cols.indexOf('src')], '10.0.0.1');
  assert.strictEqual(cells[cols.indexOf('dst')], '8.8.8.8');
  assert.strictEqual(cells[cols.indexOf('sev')], '7');
});

test('LEEF 2.0: hex-escape custom delimiter (\\x09 → tab)', () => {
  const tk = _tlMakeLEEFTokenizer();
  const cells = tk.tokenize(
    'LEEF:2.0|IBM|QRadar|7.4|EVT201|\\x09|src=10.0.0.1\tdst=9.9.9.9\tsev=6', 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cells[cols.indexOf('src')], '10.0.0.1');
  assert.strictEqual(cells[cols.indexOf('dst')], '9.9.9.9');
  assert.strictEqual(cells[cols.indexOf('sev')], '6');
});

test('LEEF 2.0: empty delimiter spec defaults to tab', () => {
  const tk = _tlMakeLEEFTokenizer();
  const cells = tk.tokenize(
    'LEEF:2.0|IBM|QRadar|7.4|EVT202||src=10.0.0.1\tdst=8.8.8.8\tsev=4', 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cells[cols.indexOf('src')], '10.0.0.1');
  assert.strictEqual(cells[cols.indexOf('sev')], '4');
});

test('LEEF 2.0: delimiter spec field NOT emitted as a column', () => {
  const tk = _tlMakeLEEFTokenizer();
  tk.tokenize('LEEF:2.0|IBM|QRadar|7.4|EVT200|^|src=10.0.0.1^sev=3', 0);
  const cols = tk.getColumns(0);
  // No "Delimiter" or similar in the canonical header.
  assert.strictEqual(cols.length, _TL_LEEF_HEADER_COLS.length + 2 + 1);
  assert.strictEqual(cols.indexOf('Delimiter'), -1);
});

// ── Header-field escapes ─────────────────────────────────────────────
test('LEEF: honours backslash escapes in header fields', () => {
  const tk = _tlMakeLEEFTokenizer();
  const cells = tk.tokenize(
    'LEEF:1.0|Acme\\\\Corp|Pipe\\|Product|1.0|EVT|\tsev=3', 0);
  assert.strictEqual(cells[1], 'Acme\\Corp');
  assert.strictEqual(cells[2], 'Pipe|Product');
});

// ── Syslog wrapper stripping ─────────────────────────────────────────
test('LEEF: strips a leading syslog wrapper before the LEEF marker', () => {
  const tk = _tlMakeLEEFTokenizer();
  const cells = tk.tokenize(
    '<134>Oct 15 22:14:15 fw01 vendor: LEEF:1.0|IBM|QRadar|7.4|EVT|\tsrc=10.0.0.1\tsev=5', 0);
  assert.strictEqual(cells[1], 'IBM');
  assert.strictEqual(cells[2], 'QRadar');
  const cols = tk.getColumns(0);
  assert.strictEqual(cells[cols.indexOf('src')], '10.0.0.1');
});

// ── Ext value escapes ────────────────────────────────────────────────
test('LEEF: backslash escapes in ext values (\\=, \\\\, \\n, \\<delim>)', () => {
  const tk = _tlMakeLEEFTokenizer();
  const cells = tk.tokenize(
    'LEEF:2.0|IBM|QRadar|7.4|EVT|^|msg=key\\=val\\nline2^tag=back\\\\slash^embed=tab\\^char', 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cells[cols.indexOf('msg')], 'key=val\nline2');
  assert.strictEqual(cells[cols.indexOf('tag')], 'back\\slash');
  assert.strictEqual(cells[cols.indexOf('embed')], 'tab^char');
});

// ── Schema lock-in & _extra spill ────────────────────────────────────
test('first record locks the extension schema; later records project', () => {
  const tk = _tlMakeLEEFTokenizer();
  tk.tokenize(
    'LEEF:1.0|IBM|QRadar|7.4|EVT100|\tsrc=10.0.0.1\tdst=8.8.8.8\tsev=5', 0);
  // Record reordered + missing one key + adding one new key.
  const cells = tk.tokenize(
    'LEEF:1.0|IBM|QRadar|7.4|EVT101|\tsev=7\tsrc=10.0.0.2\tnewKey=bonus', 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cells[cols.indexOf('src')], '10.0.0.2');
  assert.strictEqual(cells[cols.indexOf('dst')], '');     // missing → blank
  assert.strictEqual(cells[cols.indexOf('sev')], '7');
  // newKey not in locked schema → spills to _extra.
  const extra = JSON.parse(cells[cols.indexOf('_extra')]);
  assert.strictEqual(extra.newKey, 'bonus');
});

// ── Default stack column ─────────────────────────────────────────────
test('default stack column: sev (first ext-key candidate)', () => {
  const tk = _tlMakeLEEFTokenizer();
  tk.tokenize('LEEF:1.0|IBM|QRadar|7.4|EVT|\tsrc=10.0.0.1\tsev=5\tcat=auth', 0);
  const cols = tk.getColumns(0);
  const idx = tk.getDefaultStackColIdx();
  assert.strictEqual(cols[idx], 'sev');
});

test('default stack column: falls back to cat when sev absent', () => {
  const tk = _tlMakeLEEFTokenizer();
  tk.tokenize('LEEF:1.0|IBM|QRadar|7.4|EVT|\tsrc=10.0.0.1\tcat=firewall', 0);
  const cols = tk.getColumns(0);
  const idx = tk.getDefaultStackColIdx();
  assert.strictEqual(cols[idx], 'cat');
});

test('default stack column: returns null when no candidate matches', () => {
  const tk = _tlMakeLEEFTokenizer();
  tk.tokenize('LEEF:1.0|IBM|QRadar|7.4|EVT|\tsrc=10.0.0.1\tdst=8.8.8.8', 0);
  assert.strictEqual(tk.getDefaultStackColIdx(), null);
});

// ── Robustness ───────────────────────────────────────────────────────
test('returns null for non-LEEF lines', () => {
  const tk = _tlMakeLEEFTokenizer();
  assert.strictEqual(tk.tokenize('', 0), null);
  assert.strictEqual(tk.tokenize('not LEEF at all', 0), null);
  assert.strictEqual(tk.tokenize('CEF:0|V|P|1.0|100|N|3|src=1.1.1.1', 0), null);
});

test('returns null when fewer than 5 pipe-separated header fields are present (LEEF 1.0)', () => {
  const tk = _tlMakeLEEFTokenizer();
  assert.strictEqual(tk.tokenize('LEEF:1.0|IBM|QRadar|7.4', 0), null);
});

test('tolerates a leading UTF-8 BOM on the first line', () => {
  const tk = _tlMakeLEEFTokenizer();
  const cells = tk.tokenize(
    '\uFEFFLEEF:1.0|IBM|QRadar|7.4|EVT|\tsrc=10.0.0.1\tsev=5', 0);
  assert.strictEqual(cells[1], 'IBM');
});

// ── Cross-realm parity ───────────────────────────────────────────────
test('worker-shim copy of _tlMakeLEEFTokenizer matches main-bundle copy', () => {
  const shimCtx = loadModules(['src/app/timeline/timeline-parser-helpers.js', 'src/workers/timeline-worker-shim.js'], {
    expose: ['_tlMakeLEEFTokenizer'],
  });
  const shimMake = shimCtx._tlMakeLEEFTokenizer;
  assert.strictEqual(typeof shimMake, 'function',
    'shim must export _tlMakeLEEFTokenizer');
  const drive = (factory) => {
    const tk = factory();
    const lines = [
      'LEEF:1.0|IBM|QRadar|7.4|EVT100|\tsrc=10.0.0.1\tdst=8.8.8.8\tsev=5\tcat=auth',
      '<134>Oct 15 22:14:18 fw01 vendor: LEEF:1.0|IBM|QRadar|7.4|EVT101|\tsrc=10.0.0.2\tdst=9.9.9.9\tsev=7\tact=block',
      'not-LEEF',
      '',
      'LEEF:2.0|IBM|QRadar|7.4|EVT200|^|src=10.0.0.3^dst=1.1.1.1^sev=9^user=eve',
      'LEEF:2.0|IBM|QRadar|7.4|EVT201|\\x09|src=10.0.0.4\tdst=8.8.4.4\tsev=3\tcat=traffic',
    ];
    return {
      out: lines.map(l => tk.tokenize(l, 0)),
      cols: tk.getColumns(0),
      label: tk.getFormatLabel(),
      stackIdx: tk.getDefaultStackColIdx(),
    };
  };
  const a = drive(_tlMakeLEEFTokenizer);
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
