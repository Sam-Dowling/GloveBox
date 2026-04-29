'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-worker-w4-columns-event.test.js — pin the W4 worker
// "early columns event" optimisation.
//
// CONTEXT — what W4 does and why:
//   Pre-fix: the streaming worker emitted `{event:'rows-chunk'}`
//   batches during parse, then the column list ONLY in the terminal
//   `{event:'done'}` payload. The host's `timeline-router.js` had to
//   buffer every chunk in `pendingChunks[]` until `done` arrived, then
//   construct `RowStoreBuilder`, replay all chunks, and finalise — a
//   serial post-`done` "assemble" phase that blocked anything
//   downstream of the RowStore.
//
//   Post-fix: the worker emits `{event:'columns', columns}` AHEAD of
//   the first `rows-chunk`. The host constructs `RowStoreBuilder`
//   immediately on that event and calls `addChunk` directly as
//   chunks arrive — no buffering, no post-`done` replay. The
//   `done` handler becomes a single `finalize()` call.
//
//   Defensive fallback: chunks that race the columns event (rare —
//   should not happen with the current worker but the postMessage
//   ordering contract isn't strict on event interleaving) buffer in
//   `pendingChunks[]` and are replayed when `columns` finally lands
//   (or by the post-`done` block if `columns` never arrives, e.g.
//   an older worker bundle or an empty-header file).
//
// What this test pins (static-text only):
//   • Worker: `_postColumns(columns)` helper exists, posts a
//     `{event:'columns', columns}` message, no-ops on empty input.
//   • Worker: all four ingest paths (CSV, CLF — both header sites,
//     EVTX, SQLite) call `_postColumns(columns)` after resolving
//     the schema.
//   • Router: `onBatch` handles `m.event === 'columns'` by
//     constructing `RowStoreBuilder` and replaying any pre-event
//     pending chunks.
//   • Router: `onBatch` rows-chunk path takes the builder fast path
//     (`builder.addChunk(chunk)`) when the builder is set, falls
//     back to `pendingChunks.push(chunk)` otherwise.
//   • Router: post-`done` assembly does NOT unconditionally
//     construct a fresh builder — it reuses the one built during
//     streaming. The `if (!builder) { ... }` guard pins this.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const WORKER_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/workers/timeline.worker.js'), 'utf8');
const ROUTER_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-router.js'), 'utf8');

// ── Worker side ────────────────────────────────────────────────────────────

test('_postColumns helper is defined and posts {event:"columns", columns}', () => {
  // Helper centralises the message shape so all four ingest paths can
  // call a single function. Empty-array columns must be a no-op (the
  // host's terminal-`done` fallback path handles the empty-header
  // file case).
  const re = /function\s+_postColumns\s*\(\s*columns\s*\)\s*\{[\s\S]*?if\s*\(\s*!Array\.isArray\(columns\)\s*\|\|\s*!columns\.length\s*\)\s*return\s*;[\s\S]*?self\.postMessage\(\s*\{\s*event\s*:\s*'columns'\s*,\s*columns\s*:\s*columns\s*,?\s*\}\s*\)\s*;[\s\S]*?\}/;
  assert.ok(re.test(WORKER_SRC),
    'expected `function _postColumns(columns) { ... self.postMessage({event:\'columns\', columns}) ... }` ' +
    'with an early no-op return on empty/non-array columns input'
  );
});

test('all four ingest paths call _postColumns after resolving the schema', () => {
  // CSV header site (in `ingestRows`), CLF body site (first non-blank
  // line), CLF tail-flush site (single-line file with no terminator),
  // EVTX (fixed schema), SQLite (resolved schema). 5 expected call
  // sites; if a future ingest path forgets to announce its columns
  // it'd silently regress to the post-`done` buffering path.
  const matches = WORKER_SRC.match(/_postColumns\s*\(\s*columns\s*\)\s*;/g);
  assert.ok(matches && matches.length >= 5,
    `expected >= 5 \`_postColumns(columns);\` call sites in ` +
    `timeline.worker.js (CSV header + CLF body + CLF tail-flush + ` +
    `EVTX + SQLite), got ${matches ? matches.length : 0}`);
});

// ── Router side ────────────────────────────────────────────────────────────

test('router onBatch handles m.event === "columns" with early RowStoreBuilder construction', () => {
  // The columns branch must:
  //  (a) build `new RowStoreBuilder(cols)` when one isn't already
  //      live (`!builder` guard prevents a double-construct if the
  //      worker ever re-emits the event)
  //  (b) replay any chunks that landed before the event into the
  //      newly-built builder
  // Pin both together with a multi-line regex.
  const re = /if\s*\(\s*m\.event\s*===\s*'columns'\s*\)\s*\{[\s\S]*?builder\s*=\s*new\s+RowStoreBuilder\(\s*cols\s*\)[\s\S]*?for\s*\([\s\S]*?builder\.addChunk\(\s*pendingChunks\[\s*i\s*\]\s*\)/;
  assert.ok(re.test(ROUTER_SRC),
    'expected `if (m.event === \'columns\')` branch in router onBatch ' +
    'that builds `new RowStoreBuilder(cols)` and replays buffered ' +
    'chunks via `builder.addChunk(pendingChunks[i])`'
  );
});

test('router onBatch rows-chunk path uses builder.addChunk when builder is live', () => {
  // Fast path: chunks land directly in the builder instead of being
  // buffered. Pin the conditional pattern explicitly so a refactor
  // that re-introduces unconditional buffering would fail this test.
  const re = /if\s*\(\s*builder\s*\)\s*\{[\s\S]{0,800}?builder\.addChunk\(\s*chunk\s*\)\s*;[\s\S]{0,400}?\}\s*else\s*\{[\s\S]{0,400}?pendingChunks\.push\(\s*chunk\s*\)\s*;/;
  assert.ok(re.test(ROUTER_SRC),
    'expected `if (builder) { builder.addChunk(chunk); } else { ' +
    'pendingChunks.push(chunk); }` in router onBatch rows-chunk handler'
  );
});

test('router post-done assembly reuses the streaming builder when present', () => {
  // The `if (!builder) { ... }` guard around `new RowStoreBuilder(cols)`
  // is the load-bearing W4 invariant: if a refactor drops it, every
  // load constructs a fresh empty builder post-`done` and adds the
  // already-applied chunks to it twice. Pin the guard.
  assert.ok(
    /if\s*\(\s*!builder\s*\)\s*\{\s*\n\s*const\s+cols\s*=\s*Array\.isArray\(\s*msg\.columns\s*\)/.test(ROUTER_SRC),
    'expected `if (!builder) { const cols = Array.isArray(msg.columns) ... }` ' +
    'guard in the router\'s post-`done` assembly block (W4 reuses the ' +
    'streaming builder; the guard is the load-bearing invariant)'
  );
});

test('router post-done assembly drops the builder reference after finalize()', () => {
  // Post-`finalize` we set `builder = null;` so the lexical reference
  // doesn't keep the (now-rebuilt-into-RowStore) chunk arrays alive
  // longer than necessary. Cheap belt-and-braces — the surrounding
  // promise scope would drop it anyway when it resolves.
  assert.ok(
    /msg\.rowStore\s*=\s*builder\.finalize\(\)\s*;\s*\n\s*builder\s*=\s*null\s*;/.test(ROUTER_SRC),
    'expected `msg.rowStore = builder.finalize();` followed by ' +
    '`builder = null;` in the post-`done` assembly block'
  );
});
