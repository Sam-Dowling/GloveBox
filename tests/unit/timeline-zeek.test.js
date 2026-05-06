'use strict';
// timeline-zeek.test.js — Zeek TSV tokeniser (stateful schema).
//
// Zeek (formerly Bro) emits one log file per protocol/path with a
// 7-line `#`-prefixed header preamble that defines the column list
// inline:
//
//   #separator \x09
//   #path	conn
//   #fields	ts	uid	id.orig_h	id.orig_p	...
//   <tab-separated data>
//   #close	2024-...
//
// Because the schema is per-file and per-`#path`, the tokeniser is
// stateful: `_tlMakeZeekTokenizer()` returns a closure that
// remembers `#fields` / `#path` / `#unset_field` / `#empty_field`
// from the header and applies them to subsequent data rows.
//
// As with the syslog suites, the worker bundle ships its own copy
// of the tokeniser and cross-realm parity is enforced by the final
// test in this file.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-parser-helpers.js',
  'src/app/timeline/timeline-helpers.js',
], {
  expose: [
    '_tlMakeZeekTokenizer', '_TL_ZEEK_STACK_BY_PATH',
  ],
});
const {
  _tlMakeZeekTokenizer,
  _TL_ZEEK_STACK_BY_PATH,
} = ctx;

// ── Tokeniser construction ────────────────────────────────────────────
test('factory: returns the expected closure shape', () => {
  const tk = _tlMakeZeekTokenizer();
  assert.strictEqual(typeof tk.tokenize, 'function');
  assert.strictEqual(typeof tk.getColumns, 'function');
  assert.strictEqual(typeof tk.getDefaultStackColIdx, 'function');
  assert.strictEqual(typeof tk.getFormatLabel, 'function');
});

test('factory: returns independent instances (state cannot leak)', () => {
  // Drive instance A through a `#fields` header, then check instance B
  // sees its own empty state. A bug in the factory closure (e.g.
  // module-level state) would manifest as B seeing A's columns.
  const a = _tlMakeZeekTokenizer();
  a.tokenize('#path\tconn', 0);
  a.tokenize('#fields\tts\tuid\tid.orig_h', 0);
  const b = _tlMakeZeekTokenizer();
  // Trigger getColumns on B with no header — synthetic names.
  const cols = b.getColumns(3);
  assert.strictEqual(cols[0], 'col 1');
  assert.strictEqual(cols[2], 'col 3');
  assert.strictEqual(b.getFormatLabel(), 'Zeek');
});

// ── Header directive handling ─────────────────────────────────────────
test('tokenize: # directive lines return null and do not produce data rows', () => {
  const tk = _tlMakeZeekTokenizer();
  assert.strictEqual(tk.tokenize('#separator \\x09', 0), null);
  assert.strictEqual(tk.tokenize('#set_separator\t,', 0), null);
  assert.strictEqual(tk.tokenize('#empty_field\t(empty)', 0), null);
  assert.strictEqual(tk.tokenize('#unset_field\t-', 0), null);
  assert.strictEqual(tk.tokenize('#path\tconn', 0), null);
  assert.strictEqual(tk.tokenize('#open\t2024-10-15-12-00-00', 0), null);
  assert.strictEqual(tk.tokenize(
    '#fields\tts\tuid\tid.orig_h\tid.orig_p', 0), null);
  assert.strictEqual(tk.tokenize(
    '#types\ttime\tstring\taddr\tport', 0), null);
  assert.strictEqual(tk.tokenize('#close\t2024-10-15-13-00-00', 0), null);
});

test('getColumns: returns the schema parsed from #fields', () => {
  const tk = _tlMakeZeekTokenizer();
  tk.tokenize('#path\tconn', 0);
  tk.tokenize('#fields\tts\tuid\tid.orig_h\tid.orig_p\tproto', 0);
  const cols = tk.getColumns(5);
  assert.strictEqual(cols.length, 5);
  assert.strictEqual(cols[0], 'ts');
  assert.strictEqual(cols[1], 'uid');
  assert.strictEqual(cols[2], 'id.orig_h');
  assert.strictEqual(cols[3], 'id.orig_p');
  assert.strictEqual(cols[4], 'proto');
});

test('getColumns: returns synthetic names when #fields was not seen', () => {
  // Defensive — the sniff guarantees we'll see `#fields`, but the
  // tokeniser must stay safe if a malformed file slips through.
  const tk = _tlMakeZeekTokenizer();
  const cols = tk.getColumns(3);
  assert.strictEqual(cols[0], 'col 1');
  assert.strictEqual(cols[1], 'col 2');
  assert.strictEqual(cols[2], 'col 3');
});

// ── Data row tokenisation + NILVALUE handling ────────────────────────
test('tokenize: data row splits on tabs and replaces NILVALUEs with empty strings', () => {
  const tk = _tlMakeZeekTokenizer();
  tk.tokenize('#unset_field\t-', 0);
  tk.tokenize('#empty_field\t(empty)', 0);
  tk.tokenize('#fields\tts\tuid\tservice\tduration\torig_bytes', 0);
  const cells = tk.tokenize(
    '1697371200.123456\tCabc\t-\t0.001\t(empty)', 0);
  assert.strictEqual(cells.length, 5);
  assert.strictEqual(cells[0], '1697371200.123456');
  assert.strictEqual(cells[1], 'Cabc');
  assert.strictEqual(cells[2], '');           // unset_field replaced
  assert.strictEqual(cells[3], '0.001');
  assert.strictEqual(cells[4], '');           // empty_field replaced
});

test('tokenize: respects custom #unset_field / #empty_field overrides', () => {
  const tk = _tlMakeZeekTokenizer();
  // Some Zeek deployments customise these via Zeek script; the
  // tokeniser must honour the in-file override.
  tk.tokenize('#unset_field\t<unset>', 0);
  tk.tokenize('#empty_field\t<empty>', 0);
  tk.tokenize('#fields\tts\tuid\tservice', 0);
  const cells = tk.tokenize('1697371200.000\tCxyz\t<unset>', 0);
  assert.strictEqual(cells[2], '');
  // The default `-` should NOT be treated as NILVALUE once the
  // override is in effect.
  const cells2 = tk.tokenize('1697371200.001\tCxyz\t-', 0);
  assert.strictEqual(cells2[2], '-');
});

// ── Format label + default stack column ───────────────────────────────
test('getFormatLabel: defaults to "Zeek" when no #path was seen', () => {
  const tk = _tlMakeZeekTokenizer();
  assert.strictEqual(tk.getFormatLabel(), 'Zeek');
});

test('getFormatLabel: uses #path value when present', () => {
  const tk = _tlMakeZeekTokenizer();
  tk.tokenize('#path\tconn', 0);
  assert.strictEqual(tk.getFormatLabel(), 'Zeek (conn)');
});

test('getDefaultStackColIdx: resolves to "proto" index for #path conn', () => {
  const tk = _tlMakeZeekTokenizer();
  tk.tokenize('#path\tconn', 0);
  tk.tokenize('#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice', 0);
  // Schema must be resolved before the stack-col probe.
  tk.getColumns(8);
  assert.strictEqual(tk.getDefaultStackColIdx(), 6);  // index of 'proto'
});

test('getDefaultStackColIdx: resolves to "qtype_name" for #path dns', () => {
  const tk = _tlMakeZeekTokenizer();
  tk.tokenize('#path\tdns', 0);
  tk.tokenize('#fields\tts\tuid\tid.orig_h\tquery\tqtype\tqtype_name\trcode', 0);
  tk.getColumns(7);
  assert.strictEqual(tk.getDefaultStackColIdx(), 5);  // index of 'qtype_name'
});

test('getDefaultStackColIdx: returns null when #path is not in the heuristic table', () => {
  const tk = _tlMakeZeekTokenizer();
  tk.tokenize('#path\tcustom_app', 0);
  tk.tokenize('#fields\tts\tx\ty', 0);
  tk.getColumns(3);
  assert.strictEqual(tk.getDefaultStackColIdx(), null);
});

test('stack-by-path table: covers the well-known Zeek log paths', () => {
  // Documents the heuristic table — if an entry is renamed in
  // production, this test fails loudly rather than silently misroute
  // a histogram default.
  assert.strictEqual(_TL_ZEEK_STACK_BY_PATH.conn, 'proto');
  assert.strictEqual(_TL_ZEEK_STACK_BY_PATH.dns, 'qtype_name');
  assert.strictEqual(_TL_ZEEK_STACK_BY_PATH.http, 'method');
  assert.strictEqual(_TL_ZEEK_STACK_BY_PATH.ssl, 'version');
});

// ── Cross-bundle parity ──────────────────────────────────────────────
test('worker-shim copy of _tlMakeZeekTokenizer matches main-bundle copy', () => {
  const shimCtx = loadModules(['src/app/timeline/timeline-parser-helpers.js', 'src/workers/timeline-worker-shim.js'], {
    expose: ['_tlMakeZeekTokenizer', '_TL_ZEEK_STACK_BY_PATH'],
  });
  const shimMake = shimCtx._tlMakeZeekTokenizer;
  assert.strictEqual(typeof shimMake, 'function',
    'shim must export _tlMakeZeekTokenizer');
  // Drive both tokenisers through the same input sequence and verify
  // every step produces the same output. A divergence here means the
  // sync (Firefox file://) and async (worker) parse paths would emit
  // different rows for the same Zeek file.
  const driver = (factory) => {
    const tk = factory();
    const lines = [
      '#separator \\x09',
      '#set_separator\t,',
      '#empty_field\t(empty)',
      '#unset_field\t-',
      '#path\tconn',
      '#open\t2024-10-15-12-00-00',
      '#fields\tts\tuid\tid.orig_h\tid.orig_p\tproto',
      '#types\ttime\tstring\taddr\tport\tenum',
      '1697371200.123456\tCabc\t10.0.0.1\t1234\ttcp',
      '1697371201.000\tCdef\t-\t(empty)\tudp',
      '#close\t2024-10-15-13-00-00',
    ];
    const out = lines.map(l => tk.tokenize(l, 0));
    const cols = tk.getColumns(5);
    return {
      out,
      cols,
      label: tk.getFormatLabel(),
      stackIdx: tk.getDefaultStackColIdx(),
    };
  };
  const a = driver(_tlMakeZeekTokenizer);
  const b = driver(shimMake);
  // Compare line-by-line outputs.
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
  // Compare the resolved schema.
  assert.strictEqual(a.cols.length, b.cols.length);
  for (let i = 0; i < a.cols.length; i++) {
    assert.strictEqual(a.cols[i], b.cols[i], 'col ' + i);
  }
  assert.strictEqual(a.label, b.label);
  assert.strictEqual(a.stackIdx, b.stackIdx);
});
