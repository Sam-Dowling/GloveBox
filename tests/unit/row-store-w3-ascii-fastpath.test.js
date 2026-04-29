'use strict';
// ════════════════════════════════════════════════════════════════════════════
// row-store-w3-ascii-fastpath.test.js — pin the W3 packRowChunk
// ASCII-cell fast-path optimisation.
//
// CONTEXT — what W3 does and why:
//   Pre-fix: `packRowChunk(rows, colCount)` called `encoder.encode(s)`
//   on EVERY non-empty cell, allocating a fresh `Uint8Array` per cell.
//   On a 100k×30 forensic-log CSV that's 2.4M Uint8Array allocations
//   per pack — the dominant source of worker-side GC churn (~1.2 s of
//   `TextEncoder.encode` self-time + downstream tenuring on the
//   reference profile).
//
//   Post-fix: pass 1 probes each cell with a `s.charCodeAt(i) >= 128`
//   loop. Pure-ASCII cells (the common case in forensic logs — IPs,
//   timestamps, ASCII identifiers) are stored AS the source string.
//   Pass 2 then writes ASCII cells via a `bytes[pos+i] = s.charCodeAt(i)`
//   loop — no per-cell allocation. UTF-8 cells take the legacy
//   `encoder.encode` + `bytes.set` path.
//
//   The chunk-level `allAscii` flag is now derived from the Pass 1
//   probe (`!anyNonAscii`) instead of by ORing every emitted byte —
//   side benefit, not the headline win.
//
// What this test pins:
//   • Code-shape: `s.charCodeAt(i) >= 128` probe loop in pass 1;
//     `bytes[pos + i] = e.charCodeAt(i)` write loop in pass 2;
//     `allAscii: !anyNonAscii` in the return literal.
//   • Round-trip: ASCII-only cells decode to the same string via
//     `RowStore.getCell` and `getRow`.
//   • Round-trip: mixed ASCII + UTF-8 chunks decode correctly (the
//     ASCII fast-path must not corrupt downstream reads of UTF-8
//     siblings in the same chunk).
//   • Round-trip: edge cases — empty string, single ASCII char,
//     ASCII control chars (\t, \n), DEL (0x7F, the highest ASCII).
//   • allAscii flag: true for pure-ASCII chunks (so the read-side
//     `_decodeAsciiSlice` fast-path engages); false the moment one
//     cell goes UTF-8.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle.js');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const ROW_STORE_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/row-store.js'), 'utf8');

const ctx = loadModules(['src/row-store.js'], {
  expose: ['RowStore', 'RowStoreBuilder', 'packRowChunk'],
});
const { RowStore, packRowChunk } = ctx;

// ── Code-shape pins ────────────────────────────────────────────────────────

test('pass 1 contains an `s.charCodeAt(i) >= 128` ASCII probe loop', () => {
  // The probe is the load-bearing part of W3 — drop it and we'd
  // either re-encode every cell (regressing performance) or skip
  // encoding non-ASCII cells (corrupting them). Pin the literal.
  assert.ok(
    /s\.charCodeAt\(\s*i\s*\)\s*>=\s*128/.test(ROW_STORE_SRC),
    'expected `s.charCodeAt(i) >= 128` ASCII probe in packRowChunk pass 1'
  );
});

test('pass 2 writes ASCII cells via a `bytes[pos + i] = e.charCodeAt(i)` loop', () => {
  // The byte-write loop is the actual saving — no Uint8Array
  // allocation, just a tight `charCodeAt` → typed-array store.
  // Truncating-to-byte semantics (`& 0xff`) are implicit in the
  // Uint8Array write but only correct because the probe filtered out
  // any code unit >= 128.
  assert.ok(
    /bytes\[\s*pos\s*\+\s*i\s*\]\s*=\s*e\.charCodeAt\(\s*i\s*\)/.test(ROW_STORE_SRC),
    'expected `bytes[pos + i] = e.charCodeAt(i)` ASCII write loop in ' +
    'packRowChunk pass 2'
  );
});

test('return literal derives allAscii from `!anyNonAscii`, not byte-OR scan', () => {
  // Side benefit of W3: the chunk-level ASCII flag falls out of the
  // probe results, no extra OR-every-byte loop needed in pass 2.
  // Pin the new shape so a refactor doesn't accidentally re-introduce
  // the redundant scan.
  assert.ok(
    /allAscii\s*:\s*!anyNonAscii/.test(ROW_STORE_SRC),
    'expected `allAscii: !anyNonAscii` in the packRowChunk return ' +
    'literal'
  );
  // And the legacy `highBitSeen` byte-OR mask must be GONE — it was
  // the per-byte OR loop in the old pass 2 that we've replaced.
  assert.ok(
    !/highBitSeen/.test(ROW_STORE_SRC),
    'expected `highBitSeen` mask variable to be REMOVED — it was ' +
    'the byte-OR scan in the legacy pass 2, now derived from the ' +
    'pass-1 probe'
  );
});

// ── Round-trip — ASCII-only chunks ─────────────────────────────────────────

test('W3 round-trip: pure ASCII chunk decodes byte-for-byte', () => {
  // The most-common forensic-log shape: timestamps, IPs, identifiers,
  // status codes. Every cell takes the W3 fast-path — bytes are
  // written via charCodeAt loop, then read back via RowStore.getCell
  // (which uses _decodeAsciiSlice, the read-side ASCII fast-path).
  const cols = ['ts', 'ip', 'method', 'path', 'status'];
  const rows = [
    ['2026-04-29T16:51:00Z', '192.168.1.1',  'GET',  '/index.html', '200'],
    ['2026-04-29T16:51:01Z', '10.0.0.42',    'POST', '/api/login',  '401'],
    ['2026-04-29T16:51:02Z', '203.0.113.55', 'GET',  '/robots.txt', '404'],
  ];
  const store = RowStore.fromStringMatrix(cols, rows);
  // Round-trip every cell.
  for (let r = 0; r < rows.length; r++) {
    for (let c = 0; c < cols.length; c++) {
      assert.equal(store.getCell(r, c), rows[r][c],
        `mismatch at (${r}, ${c}): expected ${JSON.stringify(rows[r][c])}, ` +
        `got ${JSON.stringify(store.getCell(r, c))}`);
    }
  }
  // Chunk-level allAscii flag should be true for an all-ASCII corpus.
  // (RowStore stores chunks on `this.chunks`; pure-ASCII corpus → all
  // chunks have allAscii === true.)
  for (const ch of store.chunks) {
    assert.equal(ch.allAscii, true,
      'expected chunk.allAscii === true for pure-ASCII corpus');
  }
});

test('W3 round-trip: pack→unpack preserves ASCII control chars and DEL', () => {
  // Edge cases inside the [0, 127] range — \t, \n, \r, and 0x7F (DEL,
  // the highest ASCII byte). These are common in CSV cells (escaped
  // delimiters in JSON blobs, stray DEL bytes from malformed input)
  // and the fast-path must handle every byte ≤ 127 identically.
  const tab = '\t', lf = '\n', cr = '\r', del = '\x7f';
  const cols = ['controls'];
  const rows = [
    [tab + 'hello' + lf],
    [cr + del + 'x'],
    ['\x00\x01\x7f'],            // null byte + SOH + DEL
  ];
  const store = RowStore.fromStringMatrix(cols, rows);
  assert.equal(store.getCell(0, 0), tab + 'hello' + lf);
  assert.equal(store.getCell(1, 0), cr + del + 'x');
  assert.equal(store.getCell(2, 0), '\x00\x01\x7f');
  for (const ch of store.chunks) {
    assert.equal(ch.allAscii, true,
      'control chars and DEL are still pure-ASCII; allAscii must be true');
  }
});

test('W3 round-trip: single-char ASCII cells', () => {
  // Smallest non-empty cell — pin that the byte-write loop handles
  // length-1 strings correctly (off-by-one in `eLen` would corrupt
  // these immediately).
  const cols = ['a'];
  const rows = [['x'], ['Y'], ['7'], [' '], ['!']];
  const store = RowStore.fromStringMatrix(cols, rows);
  for (let r = 0; r < rows.length; r++) {
    assert.equal(store.getCell(r, 0), rows[r][0]);
  }
});

// ── Round-trip — mixed ASCII + UTF-8 ───────────────────────────────────────

test('W3 round-trip: mixed ASCII + UTF-8 chunk decodes both correctly', () => {
  // ASCII cells must still decode to the same string when a UTF-8
  // sibling is in the same chunk (the chunk's `allAscii` flag will
  // be false, so reads go through TextDecoder, but the ASCII bytes
  // we wrote must still be valid UTF-8 — which they are, since
  // 7-bit ASCII is a strict subset of UTF-8).
  const cols = ['name', 'note', 'count'];
  const rows = [
    ['alice', 'plain ASCII',         '42'],
    ['café',  'UTF-8 in this row',   '7'],
    ['bob',   '日本語',                '1'],
    ['eve',   'mixed: 🚀 plus text', '99'],
    ['sam',   'pure ASCII again',    '0'],
  ];
  const store = RowStore.fromStringMatrix(cols, rows);
  for (let r = 0; r < rows.length; r++) {
    for (let c = 0; c < cols.length; c++) {
      assert.equal(store.getCell(r, c), rows[r][c],
        `mismatch at (${r}, ${c})`);
    }
  }
  // At least one chunk has allAscii === false because of the UTF-8
  // cells; this is what triggers the chunk-level decoder dispatch.
  const anyNonAscii = store.chunks.some(ch => ch.allAscii === false);
  assert.equal(anyNonAscii, true,
    'expected at least one chunk to have allAscii === false (UTF-8 ' +
    'cells in the corpus)');
});

test('W3 round-trip: getRow on mixed-ASCII row materialises full string[]', () => {
  // `RowStore.getRow` has its own per-row decode loop separate from
  // `getCell`. Pin that the W3 changes don't break the row-bulk path.
  const cols = ['x', 'y', 'z'];
  const rows = [
    ['ASCII1', 'café',  'plain'],
    ['ASCII2', '日本語', 'plain'],
  ];
  const store = RowStore.fromStringMatrix(cols, rows);
  for (let r = 0; r < rows.length; r++) {
    const row = store.getRow(r);
    assert.equal(row.length, cols.length);
    for (let c = 0; c < cols.length; c++) {
      assert.equal(row[c], rows[r][c]);
    }
  }
});

// ── packRowChunk direct shape ──────────────────────────────────────────────

test('packRowChunk reports allAscii: true for pure-ASCII rows', () => {
  const rows = [
    ['hello',         'world',  '42'],
    ['quick brown',   'fox',    'jumps'],
  ];
  const out = packRowChunk(rows, 3);
  assert.equal(out.allAscii, true);
});

test('packRowChunk reports allAscii: false the moment ONE cell is UTF-8', () => {
  // Sibling ASCII cells in the same chunk must not flip the flag back
  // to true — pin that a single non-ASCII cell anywhere in the batch
  // is sufficient.
  const rows = [
    ['hello',  'world',   '42'],
    ['plain',  'café',    'still plain'],   // single UTF-8 cell
    ['final',  'ascii',   'row'],
  ];
  const out = packRowChunk(rows, 3);
  assert.equal(out.allAscii, false);
});

test('packRowChunk total bytes = sum of cell byte lengths (ASCII = string length)', () => {
  // Pin that the pass-1 byte counter agrees with pass-2's actual
  // writes. For ASCII this is simply `s.length`; getting this wrong
  // would either over-allocate (waste) or under-allocate (corrupt).
  const rows = [
    ['hi',  'there'],     // 2 + 5 = 7
    ['ok',  ''],          // 2 + 0 = 2
    ['',    'go'],        // 0 + 2 = 2
  ];
  const out = packRowChunk(rows, 2);
  assert.equal(out.bytes.byteLength, 7 + 2 + 2);
});
