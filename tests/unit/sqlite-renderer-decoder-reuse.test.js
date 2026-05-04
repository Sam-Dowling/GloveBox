'use strict';
// ════════════════════════════════════════════════════════════════════════════
// sqlite-renderer-decoder-reuse.test.js
//
// Regression test for the shared-TextDecoder perf fix in
// `src/renderers/sqlite-renderer.js::_readValue`.
//
// Background: before the fix, every TEXT serial type (13, 15, 17, …) inside
// a leaf-cell record allocated a fresh `new TextDecoder('utf-8', { fatal:
// false })` — on a 20 k-row Chrome history DB with ~4 TEXT columns per
// row, that's ~80 k decoder instances and the associated GC pressure.
//
// The fix caches a single decoder on the renderer instance at
// `this._utf8Decoder`. This test:
//   1. Patches the sandbox `TextDecoder` to count constructor calls.
//   2. Parses a real fixture DB.
//   3. Asserts the constructor fires ≤ 1 time total (the only legitimate
//      construction is the lazy-init on the first TEXT cell).
//   4. Correctness pin: round-trip UTF-8 strings with non-ASCII chars and
//      assert the decoded values are exact.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

function buildSandbox() {
  let constructorCalls = 0;
  const RealDecoder = TextDecoder;
  class CountingDecoder extends RealDecoder {
    constructor(...args) {
      super(...args);
      constructorCalls++;
    }
  }
  const sandbox = loadModules([
    'src/constants.js',
    'src/hashes.js',
    'src/renderers/sqlite-renderer.js',
  ], {
    expose: ['SqliteRenderer'],
    shims: {
      TextDecoder: CountingDecoder,
      _parseUrlHost: () => null,
      pushIOC: () => {},
      IOC: { URL: 'url', DOMAIN: 'domain', INFO: 'info' },
    },
  });
  return { sandbox, counter: () => constructorCalls };
}

test('sqlite _readValue reuses a single TextDecoder across all TEXT cells', () => {
  const { sandbox, counter } = buildSandbox();
  const renderer = new sandbox.SqliteRenderer();

  const fx = fs.readFileSync(path.join(REPO_ROOT, 'examples/forensics/chromehistory-example.sqlite'));
  const buf = fx.buffer.slice(fx.byteOffset, fx.byteOffset + fx.byteLength);

  const beforeParse = counter();
  const db = renderer._parseDb(new Uint8Array(buf));
  const afterParse = counter();

  const spawned = afterParse - beforeParse;

  // The _readValue hot path must spawn at most one decoder per renderer
  // (lazy init on first TEXT cell). The Chrome fixture contains thousands
  // of TEXT cells, so any regression would push `spawned` well above 1.
  //
  // NOTE: other code paths in sqlite-renderer.js may legitimately
  // construct one more decoder (none currently do — verified by grep —
  // but we leave a safety margin of 2 to avoid fragility against future
  // unrelated changes that add a second unrelated decoder).
  assert.ok(spawned <= 2,
    `expected ≤ 2 TextDecoder constructions during _parseDb, got ${spawned} — regression in _readValue cell loop`);

  // The fixture should parse successfully — if the decoder were broken,
  // historyRows would be empty or garbled.
  assert.ok(db.historyRows && db.historyRows.length > 0,
    'Chrome history fixture should produce history rows');
  // URL column contains real URLs with schemes.
  const urlCol = db.historyColumns.findIndex(c => /^url$/i.test(c));
  assert.ok(urlCol >= 0, 'history schema should include a URL column');
  const firstUrl = db.historyRows[0][urlCol];
  assert.match(String(firstUrl), /^https?:\/\//, 'first URL should be well-formed');
});

test('sqlite _readValue round-trips non-ASCII UTF-8 exactly', () => {
  // Synthetic probe: build a minimal sqlite-like record and assert the
  // decoded TEXT comes back byte-exact. Uses the renderer's _readValue
  // helper directly via the varint+serial-type protocol.
  const { sandbox } = buildSandbox();
  const renderer = new sandbox.SqliteRenderer();

  const samples = [
    'hello',
    'café',                       // Latin-1 supplement
    'jalapeño',                   // combined forms
    'привет',                      // Cyrillic
    '日本語',                      // CJK
    '🔥 fire',                     // supplementary plane
    '',                           // empty
  ];

  for (const s of samples) {
    const utf8 = Buffer.from(s, 'utf-8');
    const bytes = new Uint8Array(utf8);
    // TEXT serial type = (len * 2) + 13.
    const serialType = (utf8.length * 2) + 13;
    const ctx = { pos: 0 };
    const got = renderer._readValue(bytes, ctx, serialType);
    assert.equal(got, s, `round-trip mismatch for "${s}"`);
    assert.equal(ctx.pos, utf8.length, `cursor should advance by ${utf8.length} bytes`);
  }
});

test('sqlite _utf8Decoder is lazy-initialised (not constructed until first TEXT cell)', () => {
  const { sandbox, counter } = buildSandbox();
  const renderer = new sandbox.SqliteRenderer();

  // Instance has no decoder before any parse work.
  assert.equal(renderer._utf8Decoder, undefined,
    'decoder should not exist before first _readValue call');

  const before = counter();
  // Drive a single TEXT read — this should construct the one-and-only decoder.
  const utf8 = Buffer.from('x', 'utf-8');
  renderer._readValue(new Uint8Array(utf8), { pos: 0 }, (utf8.length * 2) + 13);
  const after = counter();

  assert.equal(after - before, 1, 'exactly one TextDecoder constructed on first TEXT read');
  assert.ok(renderer._utf8Decoder, 'decoder should be attached to the instance');

  // A second TEXT read must NOT construct another decoder.
  const before2 = counter();
  renderer._readValue(new Uint8Array(Buffer.from('y', 'utf-8')), { pos: 0 }, (Buffer.from('y', 'utf-8').length * 2) + 13);
  const after2 = counter();
  assert.equal(after2 - before2, 0, 'no TextDecoder constructed on subsequent TEXT reads');
});
