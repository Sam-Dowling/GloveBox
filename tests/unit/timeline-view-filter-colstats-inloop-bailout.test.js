// timeline-view-filter-colstats-inloop-bailout.test.js
//
// _computeColumnStatsAsync used to only check `_colStatsGen` between 50k-row
// chunks. On a wide grid (30 cols × 50k rows) one chunk is already a
// multi-hundred-millisecond slab of work, and during the auto-extract apply
// pump fresh column-stats computations are queued in rapid succession —
// each previous one would run to completion of its current chunk before
// noticing it had been superseded.
//
// A1 (the apply-pump suppression commit) eliminates most of these queued
// computations, but the in-loop bailout is the safety net for the cases
// that still race (manual extract while pump runs, settle-time cascades,
// etc.) and for keeping the post-pump deferred sweep cancellable when the
// view is destroyed mid-flight.
//
// These are pure source-text assertions — the same style as
// `timeline-view-autoextract-uncapped.test.js` — to avoid stubbing the
// filter pipeline. The behavioural contract is narrow enough that the
// shape of the gate is the contract.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const SRC = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view-filter.js'),
  'utf8'
);

test('_computeColumnStatsAsync samples generation every 4096 rows inside the chunk loop', () => {
  // The bailout token. `4095` is `4096 - 1` — a power-of-two mask is the
  // canonical cheap sample-every-N idiom (one AND, no division).
  assert.match(SRC, /\(i & 4095\) === 0/,
    'expected `(i & 4095) === 0` mask inside the inner row loop');
});

test('in-loop bailout checks both _colStatsGen and _destroyed', () => {
  // Two conditions, both required for the bailout to mean "another
  // newer computation is in flight OR the view is gone." Either one
  // alone would leave a leak (stale work post-destroy or ignoring the
  // newer generation).
  const re = /\(i & 4095\) === 0\s*&&\s*\(self\._colStatsGen !== generation \|\| self\._destroyed\)/;
  assert.match(SRC, re,
    'expected the in-loop bailout to OR generation-staleness with _destroyed');
});

test('in-loop bailout returns null (matches the post-yield bailout contract)', () => {
  // The async function returns `null` when superseded; callers check
  // for falsy and skip the apply. Anything else (undefined, throw)
  // would break the cascade.
  const idx = SRC.indexOf('(i & 4095) === 0');
  assert.ok(idx > 0, 'in-loop bailout marker not found');
  // Look at the next ~200 chars for a `return null;`.
  const slice = SRC.slice(idx, idx + 400);
  assert.match(slice, /return null;/,
    'expected `return null;` immediately following the in-loop bailout test');
});

test('in-loop bailout sits BEFORE the per-row column scan (cheap-first ordering)', () => {
  // The bailout has to be the first thing the loop body does — the
  // whole point is to skip the 30-cell scan when the work is stale.
  // Find the bailout, then assert the inner-cell loop comes after.
  const bailoutIdx = SRC.indexOf('(i & 4095) === 0');
  const innerLoopIdx = SRC.indexOf('for (let c = 0; c < cols; c++) {', bailoutIdx);
  assert.ok(bailoutIdx > 0 && innerLoopIdx > bailoutIdx,
    'expected the inner column-scan loop to follow the bailout, not precede it');

  // And the bailout must be inside the chunked outer loop, not the
  // outer while. Verify by checking the surrounding `for (; i < end;`.
  const chunkLoopIdx = SRC.lastIndexOf('for (; i < end; i++)', bailoutIdx);
  assert.ok(chunkLoopIdx > 0 && chunkLoopIdx < bailoutIdx,
    'expected the bailout to live inside the `for (; i < end; i++)` chunk loop');
});

test('post-yield bailout is preserved (in-loop is additive, not a replacement)', () => {
  // The original post-yield check still has to fire — for the case
  // where a newer generation is requested AT the chunk boundary
  // (unlikely but possible), and as a defence-in-depth for the
  // 4095-row sampling window.
  assert.match(SRC,
    /await yieldTick\(\);\s*\/\/[^\n]*\n\s*if \(self\._colStatsGen !== generation \|\| self\._destroyed\) return null;/,
    'expected the original post-yield bailout to remain intact');
});
