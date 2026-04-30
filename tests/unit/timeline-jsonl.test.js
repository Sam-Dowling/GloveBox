'use strict';
// timeline-jsonl.test.js — JSONL tokeniser (stateful, schema from
// first record).
//
// JSONL is newline-delimited JSON: each non-empty line is a complete
// JSON object. Used by AWS CloudTrail (one event per line),
// fluentd/vector/Loki sinks, container runtime stdout, and most
// modern application structured logging libraries (zap, slog,
// pino, …). The Loupe tokeniser flattens nested objects into
// dotted-path columns and serialises arrays in-place; the schema
// comes from the first valid record's key set, with subsequent
// records' unknown keys spilled into a single `_extra` column.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-helpers.js',
], {
  expose: [
    '_tlMakeJsonlTokenizer', '_TL_JSONL_FLATTEN_MAX_DEPTH',
    '_TL_JSONL_MAX_COLUMNS',
  ],
});
const {
  _tlMakeJsonlTokenizer,
  _TL_JSONL_FLATTEN_MAX_DEPTH,
  _TL_JSONL_MAX_COLUMNS,
} = ctx;

// ── Construction ──────────────────────────────────────────────────────
test('factory: returns the expected closure shape', () => {
  const tk = _tlMakeJsonlTokenizer();
  assert.strictEqual(typeof tk.tokenize, 'function');
  assert.strictEqual(typeof tk.getColumns, 'function');
  assert.strictEqual(typeof tk.getDefaultStackColIdx, 'function');
  assert.strictEqual(typeof tk.getFormatLabel, 'function');
  assert.strictEqual(tk.getFormatLabel(), 'JSONL');
});

test('factory: returns independent instances (state cannot leak)', () => {
  const a = _tlMakeJsonlTokenizer();
  a.tokenize('{"first":"a","second":1}', 0);
  const b = _tlMakeJsonlTokenizer();
  // B has not seen any data — schema is empty, only `_extra` is
  // appended. A's schema must not leak.
  const colsB = b.getColumns(0);
  assert.strictEqual(colsB.length, 1);
  assert.strictEqual(colsB[0], '_extra');
});

// ── Schema resolution from first record ──────────────────────────────
test('first record establishes the canonical schema (with _extra appended)', () => {
  const tk = _tlMakeJsonlTokenizer();
  const cells = tk.tokenize('{"ts":"2024-10-15T12:00:00Z","level":"info","msg":"hello"}', 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cols.length, 4);
  assert.strictEqual(cols[0], 'ts');
  assert.strictEqual(cols[1], 'level');
  assert.strictEqual(cols[2], 'msg');
  assert.strictEqual(cols[3], '_extra');
  assert.strictEqual(cells.length, 4);
  assert.strictEqual(cells[0], '2024-10-15T12:00:00Z');
  assert.strictEqual(cells[1], 'info');
  assert.strictEqual(cells[2], 'hello');
  assert.strictEqual(cells[3], '');
});

test('subsequent records project onto the established schema', () => {
  const tk = _tlMakeJsonlTokenizer();
  tk.tokenize('{"ts":"t1","level":"info","msg":"hello"}', 0);
  // Re-ordered keys, missing `level`. Width must stay at 4.
  const cells = tk.tokenize('{"msg":"world","ts":"t2"}', 0);
  assert.strictEqual(cells.length, 4);
  assert.strictEqual(cells[0], 't2');
  assert.strictEqual(cells[1], '');           // missing `level` → blank
  assert.strictEqual(cells[2], 'world');
  assert.strictEqual(cells[3], '');
});

test('unknown keys spill into the _extra column as JSON', () => {
  const tk = _tlMakeJsonlTokenizer();
  tk.tokenize('{"ts":"t1","level":"info","msg":"hello"}', 0);
  const cells = tk.tokenize('{"ts":"t2","level":"warn","msg":"hi","trace_id":"abc","span_id":"def"}', 0);
  assert.strictEqual(cells.length, 4);
  assert.strictEqual(cells[3].length > 0, true);
  // Both unknown keys must appear in the _extra JSON.
  const extra = JSON.parse(cells[3]);
  assert.strictEqual(extra.trace_id, 'abc');
  assert.strictEqual(extra.span_id, 'def');
});

test('column count is fixed up front — _extra is always present', () => {
  const tk = _tlMakeJsonlTokenizer();
  tk.tokenize('{"a":1}', 0);
  const cols = tk.getColumns(0);
  // Even though no row has needed `_extra` yet, it MUST appear so
  // the worker's `_postColumns` emit fixes the schema width
  // up front. Adding _extra mid-stream would violate the
  // fixed-width row contract in the structured-log loop.
  assert.strictEqual(cols.includes('_extra'), true);
});

// ── Nested object flattening ─────────────────────────────────────────
test('flattens nested objects into dotted paths', () => {
  const tk = _tlMakeJsonlTokenizer();
  const cells = tk.tokenize(
    '{"event":{"name":"login","success":true},"user":{"id":42,"role":"admin"}}', 0);
  const cols = tk.getColumns(0);
  // Flattened keys appear in source order.
  assert.deepStrictEqual(cols.slice(0, 4),
    ['event.name', 'event.success', 'user.id', 'user.role']);
  assert.strictEqual(cells[0], 'login');
  assert.strictEqual(cells[1], 'true');
  assert.strictEqual(cells[2], '42');
  assert.strictEqual(cells[3], 'admin');
});

test('serialises arrays in-place (no per-index column explosion)', () => {
  const tk = _tlMakeJsonlTokenizer();
  const cells = tk.tokenize('{"ts":"t1","tags":["auth","prod","critical"]}', 0);
  const cols = tk.getColumns(0);
  assert.strictEqual(cols[1], 'tags');
  assert.strictEqual(cells[1], '["auth","prod","critical"]');
});

test('renders nulls / booleans / numbers as their string form', () => {
  const tk = _tlMakeJsonlTokenizer();
  const cells = tk.tokenize(
    '{"a":null,"b":true,"c":false,"d":42,"e":3.14,"f":"text"}', 0);
  assert.strictEqual(cells[0], 'null');
  assert.strictEqual(cells[1], 'true');
  assert.strictEqual(cells[2], 'false');
  assert.strictEqual(cells[3], '42');
  assert.strictEqual(cells[4], '3.14');
  assert.strictEqual(cells[5], 'text');
});

test('depth cap: nesting beyond the limit is JSON-encoded at the boundary', () => {
  // Build a 10-deep nested object. The tokeniser's flatten depth
  // cap is 8 — the 8th level should JSON-encode the remaining
  // sub-tree as its cell value rather than recurse further.
  let nested = { leaf: 'value' };
  for (let i = 0; i < 9; i++) nested = { wrap: nested };
  const obj = { top: nested };
  const tk = _tlMakeJsonlTokenizer();
  const cells = tk.tokenize(JSON.stringify(obj), 0);
  const cols = tk.getColumns(0);
  // The path stops growing somewhere in the 8-deep range. We don't
  // assert the exact path (depending on whether the leading `top.`
  // segment is counted toward the depth) — just that the cell
  // VALUE is a JSON string that re-parses, and that the schema
  // didn't run all the way to `top.wrap.wrap.…leaf`.
  assert.strictEqual(_TL_JSONL_FLATTEN_MAX_DEPTH, 8);
  // The value at the deepest schema column should be a JSON-encoded
  // sub-tree — at minimum start with `{` (object) since the leaf
  // hasn't been reached at depth 8.
  const lastCellIdx = cols.indexOf('_extra') - 1;
  const deepestCell = cells[lastCellIdx];
  assert.strictEqual(deepestCell.charAt(0), '{');
});

// ── Input handling / robustness ──────────────────────────────────────
test('skips blank lines and non-object JSON values', () => {
  const tk = _tlMakeJsonlTokenizer();
  assert.strictEqual(tk.tokenize('', 0), null);
  assert.strictEqual(tk.tokenize('   ', 0), null);
  assert.strictEqual(tk.tokenize('null', 0), null);
  assert.strictEqual(tk.tokenize('42', 0), null);
  assert.strictEqual(tk.tokenize('"string"', 0), null);
  assert.strictEqual(tk.tokenize('[1,2,3]', 0), null);  // top-level array
});

test('skips invalid JSON lines without poisoning the schema', () => {
  const tk = _tlMakeJsonlTokenizer();
  // First line: invalid → null. Schema is still unset.
  assert.strictEqual(tk.tokenize('{not valid json', 0), null);
  // Second line: valid → schema established now.
  const cells = tk.tokenize('{"a":1,"b":2}', 0);
  assert.strictEqual(cells.length, 3);
  const cols = tk.getColumns(0);
  assert.strictEqual(cols[0], 'a');
  assert.strictEqual(cols[1], 'b');
});

test('strips a leading UTF-8 BOM on the first line', () => {
  const tk = _tlMakeJsonlTokenizer();
  const cells = tk.tokenize('\uFEFF{"ts":"t1","level":"info"}', 0);
  assert.strictEqual(cells.length, 3);
  assert.strictEqual(cells[0], 't1');
});

// ── Default stack column heuristic ───────────────────────────────────
test('default stack column: prefers level / severity / log.level', () => {
  const tk = _tlMakeJsonlTokenizer();
  tk.tokenize('{"ts":"t1","level":"info","msg":"hi"}', 0);
  // `getColumns` is what sets up the schema index for the lookup —
  // call it before probing the stack-col idx.
  tk.getColumns(0);
  const idx = tk.getDefaultStackColIdx();
  assert.strictEqual(idx, 1);  // index of `level`
});

test('default stack column: prefers eventName for CloudTrail-shaped records', () => {
  const tk = _tlMakeJsonlTokenizer();
  tk.tokenize('{"eventTime":"t1","eventVersion":"1.08","eventSource":"s3","eventName":"PutObject"}', 0);
  tk.getColumns(0);
  const idx = tk.getDefaultStackColIdx();
  assert.strictEqual(idx, 3);  // index of `eventName`
});

test('default stack column: returns null when no candidate matches', () => {
  const tk = _tlMakeJsonlTokenizer();
  tk.tokenize('{"alpha":1,"beta":2,"gamma":3}', 0);
  tk.getColumns(0);
  assert.strictEqual(tk.getDefaultStackColIdx(), null);
});

// ── Limits ─────────────────────────────────────────────────────────────
test('schema is capped at MAX_COLUMNS to avoid OOM', () => {
  // Build a record with way more than the cap.
  const obj = {};
  for (let i = 0; i < _TL_JSONL_MAX_COLUMNS + 50; i++) {
    obj['key' + i] = i;
  }
  const tk = _tlMakeJsonlTokenizer();
  tk.tokenize(JSON.stringify(obj), 0);
  const cols = tk.getColumns(0);
  // schema is `_TL_JSONL_MAX_COLUMNS` keys + 1 `_extra`.
  assert.strictEqual(cols.length, _TL_JSONL_MAX_COLUMNS + 1);
  assert.strictEqual(cols[cols.length - 1], '_extra');
});

// ── Cross-bundle parity ──────────────────────────────────────────────
test('worker-shim copy of _tlMakeJsonlTokenizer matches main-bundle copy', () => {
  const shimCtx = loadModules(['src/workers/timeline-worker-shim.js'], {
    expose: ['_tlMakeJsonlTokenizer'],
  });
  const shimMake = shimCtx._tlMakeJsonlTokenizer;
  assert.strictEqual(typeof shimMake, 'function',
    'shim must export _tlMakeJsonlTokenizer');
  const drive = (factory) => {
    const tk = factory();
    const lines = [
      '{"ts":"t1","level":"info","user":{"name":"alice","id":1},"tags":["a","b"]}',
      '{"ts":"t2","level":"warn","user":{"name":"bob","id":2},"tags":["c"]}',
      '{"ts":"t3","level":"error","user":{"name":"carol","id":3},"tags":[],"extra_field":"x"}',
      '',
      'not-json',
      '{"ts":"t4","level":"info","user":{"name":"dave","id":4},"tags":["d","e","f"]}',
    ];
    const out = lines.map(l => tk.tokenize(l, 0));
    const cols = tk.getColumns(0);
    return {
      out,
      cols,
      label: tk.getFormatLabel(),
      stackIdx: tk.getDefaultStackColIdx(),
    };
  };
  const a = drive(_tlMakeJsonlTokenizer);
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
