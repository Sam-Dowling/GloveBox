'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-autoextract-replay-rerun.test.js — pin the structural
// contract that lets auto-extract recover from the persistence asymmetry
// between regex extracts (persisted) and JSON extracts (not persisted).
//
// CONTEXT — the bug this test exists to prevent regressing:
//   `_persistRegexExtracts` (timeline-drawer.js) writes only entries whose
//   `kind` is `'regex'` or `'auto'`. JSON-leaf / json-host / json-url
//   extractions emitted by the auto-extract scanner have `kind: 'json'`
//   and are never persisted. On reopen, the constructor replays the
//   persisted regex extracts; the auto-extract pass then sees a non-empty
//   `_extractedCols` and (in the buggy version) bailed at an
//   `_extractedCols.length > 0` guard — silently losing every JSON-shaped
//   column on every reopen.
//
//   The fix narrows the bail to "true analyst work": entries whose
//   `kind !== 'auto'`. Replayed `kind:'auto'` entries are treated as
//   "previous auto-extract residue" and the scanner re-runs, with
//   `_findDuplicateExtractedCol` deduplicating any replayed columns.
//
// What this test pins:
//   • The early-return guard reads a non-`'auto'` predicate, not a raw
//     length check. A regression that re-introduces `length > 0` lights
//     up here.
//   • `_persistRegexExtracts`'s filter remains `kind === 'regex' ||
//     kind === 'auto'`. If someone "fixes" the asymmetry by adding
//     `kind: 'json'` to the persister without revisiting the early-
//     return predicate (which would then start firing on every reopen
//     and re-break the bug), this test catches the change so it's a
//     conscious decision, not a silent regression.
//
// These are static-text checks rather than behavioural — the behavioural
// regression is already pinned by `timeline-view-autoextract-real-fixture`
// (which re-runs the scanner against the real CSV). This file's job is
// to make sure the two coupled lines of source code don't drift apart
// silently.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const AUTOEXTRACT_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-autoextract.js'),
  'utf8');
const DRAWER_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-drawer.js'),
  'utf8');

test('_autoExtractBestEffort early-return guard predicates on kind, not length', () => {
  // The PRE-fix line was a raw length check:
  //   if (this._extractedCols.length > 0) { … return; }
  // The POST-fix line conditions on the entry shape:
  //   const hasAnalystWork = this._extractedCols.some(
  //     e => e && e.kind !== 'auto');
  //   if (hasAnalystWork) { … return; }
  //
  // Pin the predicate substring so a refactor that reverts to a raw
  // length check (or any guard that doesn't discriminate on `kind`)
  // breaks this test loudly.
  // Match the method definition specifically (`_autoExtractBestEffort()`
  // with parens) — the bare identifier also appears in the file's
  // header doc comment.
  const fnStart = AUTOEXTRACT_SRC.indexOf('_autoExtractBestEffort()');
  assert.ok(fnStart >= 0,
    '_autoExtractBestEffort() method definition must exist');
  // Look at the first ~3000 chars of the function body — the early-
  // return is preceded by a long explanatory comment block.
  const slice = AUTOEXTRACT_SRC.slice(fnStart, fnStart + 3000);
  assert.ok(slice.includes("kind !== 'auto'"),
    `_autoExtractBestEffort early-return must predicate on ` +
    `\`kind !== 'auto'\` so replayed auto-extract entries don't suppress ` +
    `re-running the scanner. The bug this guards against is JSON-shaped ` +
    `columns silently disappearing on every reopen because their ` +
    `\`kind:'json'\` entries aren't persisted by _persistRegexExtracts.`);
  assert.ok(!/this\._extractedCols\.length\s*>\s*0\s*\)\s*\{\s*[^}]*_saveAutoExtractDoneFor/.test(slice),
    `_autoExtractBestEffort must not bail on a raw ` +
    `\`_extractedCols.length > 0\` check — that's the pre-fix guard ` +
    `that silently dropped JSON-leaf columns on reopen.`);
});

test('_persistRegexExtracts filter stays `kind === regex || kind === auto`', () => {
  // The persister INTENTIONALLY drops `kind:'json'` entries — the JSON
  // branch reconstructs them via the auto-extract re-run on reopen.
  // If someone adds `kind:'json'` to the persister without also
  // tightening the early-return guard above, the bug returns: replayed
  // JSON entries become `kind:'json'` (i.e. `!== 'auto'`), the new
  // guard treats them as analyst work, the auto-extract pass bails,
  // and any json-host / text-host proposals never surface.
  //
  // This test forces a coupled change: bumping the persister's filter
  // requires breaking this test, which forces the author to read the
  // comment above and update the early-return guard in lockstep.
  // Match `_persistRegexExtracts() {` (with trailing brace) so we land
  // on the method DEFINITION, not its call sites elsewhere in the file.
  const fnStart = DRAWER_SRC.indexOf('_persistRegexExtracts() {');
  assert.ok(fnStart >= 0,
    '_persistRegexExtracts() { … } method definition must exist');
  const slice = DRAWER_SRC.slice(fnStart, fnStart + 1000);
  // Two independent checks: 'regex' string is in the filter, 'auto'
  // string is in the filter. Looser than a full-expression regex but
  // robust to formatting changes.
  const filterMatch0 = slice.match(/\.filter\([^)]+\)/);
  assert.ok(filterMatch0,
    '_persistRegexExtracts must contain a .filter(…) call');
  assert.ok(filterMatch0[0].includes("'regex'"),
    `_persistRegexExtracts.filter(…) must include 'regex' kind. ` +
    `Got: ${filterMatch0[0]}`);
  assert.ok(filterMatch0[0].includes("'auto'"),
    `_persistRegexExtracts.filter(…) must include 'auto' kind. ` +
    `Got: ${filterMatch0[0]}`);
  // Belt-and-braces: 'json' must NOT appear in the FIRST .filter(...)
  // call. (There's a second `.filter(e => e.pattern)` below that drops
  // entries with no regex pattern; that one's irrelevant here.)
  assert.ok(!filterMatch0[0].includes("'json'"),
    `_persistRegexExtracts.filter(…) must NOT include 'json'. ` +
    `JSON extracts are recovered via auto-extract re-run on reopen. ` +
    `Adding 'json' here without tightening _autoExtractBestEffort's ` +
    `guard re-introduces the silent-drop bug. Got: ${filterMatch0[0]}`);
});

test('text-host detection in _autoExtractScan uses anchored TL_HOSTNAME_RE', () => {
  // Issue 2 fix: the unanchored `TL_HOSTNAME_INLINE_RE` matched the
  // millisecond fragment `21.271Z` inside ISO-8601 timestamps and
  // flagged Timestamp as a hostname column. Detection switched to
  // anchored `TL_HOSTNAME_RE.test(s.v.trim())`.
  //
  // The EXTRACTION regex (the `pattern: TL_HOSTNAME_INLINE_RE.source`
  // passed to `_addRegexExtractNoRender`) stays unanchored — that's
  // intentional, see the comment in source. This test only pins the
  // detection-side change.
  //
  // Locate the plain-text detection block by searching for the
  // distinctive comment we left in source.
  const detectionAnchor = AUTOEXTRACT_SRC.indexOf(
    'Plain-text column: test URL + hostname patterns directly.');
  assert.ok(detectionAnchor >= 0,
    'plain-text detection block anchor comment must exist');
  // Look at the ~1500 chars after the anchor — covers the for-loop
  // that increments hostHits / urlHits.
  const slice = AUTOEXTRACT_SRC.slice(detectionAnchor, detectionAnchor + 1500);
  assert.ok(/TL_HOSTNAME_RE\.test\(/.test(slice),
    `text-host detection must call \`TL_HOSTNAME_RE.test(...)\` ` +
    `(anchored) instead of \`TL_HOSTNAME_INLINE_RE.exec(...)\` ` +
    `(unanchored). The unanchored variant matches hostname-shaped ` +
    `fragments inside structured cells (notably the millisecond ` +
    `fragment of ISO-8601 timestamps).`);
  // The unanchored variant must not appear in the detection scan
  // (it's still allowed in the EXTRACTION regex passed to
  // _addRegexExtractNoRender, but that's a different code path).
  // We assert the detection branch specifically — the `for (const s
  // of samples)` loop that increments hostHits.
  const detectionLoopMatch = slice.match(
    /for\s*\(\s*const\s+s\s+of\s+samples\s*\)\s*\{[\s\S]*?\}/);
  assert.ok(detectionLoopMatch,
    'detection for-loop over samples must exist in plain-text branch');
  assert.ok(!detectionLoopMatch[0].includes('TL_HOSTNAME_INLINE_RE'),
    `detection for-loop must NOT reference TL_HOSTNAME_INLINE_RE — ` +
    `that's the unanchored variant that caused Timestamp false ` +
    `positives. Got: ${detectionLoopMatch[0]}`);
});
