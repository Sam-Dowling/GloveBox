// timeline-view-autoextract-per-src-cap.test.js
//
// C2 — cap the auto-extract apply pump at 12 proposals per `sourceCol`.
//
// Without the cap a single JSON-blob column with 30+ leaves blooms
// into 30+ extracted columns from one source, which wastes apply-pump
// budget on diminishing-returns leaves and clutters the grid past the
// point of usefulness. The historical `HUGE_FILE_CAP = 12` (which
// fires globally on files ≥ LARGE_FILE_THRESHOLD) sets the precedent
// that "12 columns is the upper bound on useful auto-extract output"
// — applying that same number per-source on smaller files keeps the
// behaviour consistent.
//
// Order matters: the per-source cap is applied AFTER the file-size
// cap. On a huge file the global 12-total semantics survive (the
// per-source counter never gets a chance to fire). On smaller files
// the per-source cap is the only one that runs.
//
// Static-text assertions only — no need to spin up a fake apply pump
// to verify a counter that lives in 8 lines of source.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const SRC = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view-autoextract.js'),
  'utf8'
);

test('PER_SRC_CAP is 12 (matches HUGE_FILE_CAP precedent)', () => {
  // The two caps share a number on purpose — see the block comment
  // in `_autoExtractBestEffort`. If a future refactor splits them,
  // both values need to be re-justified together.
  assert.match(SRC, /const PER_SRC_CAP = 12;/,
    'expected `const PER_SRC_CAP = 12;`');
});

test('per-source cap applies AFTER the file-size cap (fileCapped → capped)', () => {
  // The file-size cap produces `fileCapped`; the per-source cap walks
  // `fileCapped` and produces `capped`. Reversing the order would
  // change the semantics on huge files (per-source would over-trim
  // before the global cap could fire).
  const fileCappedDecl = SRC.indexOf('const fileCapped =');
  const perSrcCapDecl  = SRC.indexOf('const PER_SRC_CAP =');
  assert.ok(fileCappedDecl > 0 && perSrcCapDecl > fileCappedDecl,
    'expected `fileCapped` to be declared before `PER_SRC_CAP`');

  // The per-source loop reads from `fileCapped` (post file-size cap),
  // not `eligible` (the raw scanner output).
  assert.match(SRC, /for \(const p of fileCapped\) \{[\s\S]*?perSrcCounts\.get\(p\.sourceCol\)/,
    'expected the per-source cap loop to iterate `fileCapped`');
});

test('per-source counter is keyed on p.sourceCol via Map', () => {
  // `Map` (not plain object) so numeric keys stay numeric and don't
  // get string-coerced. Counts are the only content — anything more
  // structured would suggest a future refactor missed this site.
  assert.match(SRC, /const perSrcCounts = new Map\(\);/,
    'expected `perSrcCounts = new Map()` for the per-source counter');

  // Get-with-default-zero pattern: `Map.get` returns `undefined` for
  // unseen keys, so the `|| 0` is the correct fallback. Anything
  // else (e.g. `?? 0`) works but the project's existing patterns
  // use `||` for numeric default-zero.
  assert.match(SRC, /const n = perSrcCounts\.get\(p\.sourceCol\) \|\| 0;/,
    'expected `perSrcCounts.get(p.sourceCol) || 0` count read');
});

test('per-source cap skips a proposal when its source has hit PER_SRC_CAP', () => {
  // The skip is `continue`, NOT `break` — a later proposal targeting
  // a different (under-cap) source column must still get through.
  // Anything else would silently truncate the cascade once the first
  // hot source filled up.
  assert.match(SRC, /if \(n >= PER_SRC_CAP\) continue;/,
    'expected `if (n >= PER_SRC_CAP) continue;` skip gate (not break)');
});

test('counter increments BEFORE pushing to the capped list', () => {
  // Increment-then-push is the canonical "did this slot consume
  // budget" pattern. If the order were reversed, a future refactor
  // that adds a side-effect between push and increment could cause
  // drift between the counter and the list.
  const re = /perSrcCounts\.set\(p\.sourceCol, n \+ 1\);\s*capped\.push\(p\);/;
  assert.match(SRC, re,
    'expected `perSrcCounts.set(...)` to precede `capped.push(p)`');
});

test('downstream code (grouping, apply pump) reads `capped`, not `fileCapped`', () => {
  // The grouping step (`bySource = new Map()`) and everything that
  // flows from it has to operate on the per-source-capped list,
  // otherwise the cap would just be cosmetic.
  assert.match(SRC, /for \(const p of capped\) \{\s*let bucket = bySource\.get\(p\.sourceCol\);/,
    'expected the bucket-fill loop to iterate `capped`');
});
