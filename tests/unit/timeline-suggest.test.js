'use strict';
// timeline-suggest.test.js — `_tlSuggestContext` regression tests for the
// Timeline query bar's caret-aware completion resolver.
//
// Background: a user reported that with `user IN (bob, john) AND ISP:"abc"`
// in the box, selecting `user IN (bob, john) AND ` and pressing Backspace
// (so the value collapses to `ISP:"abc"` with the caret at position 0)
// then clicking at the end and pressing Enter rewrote the query to
// `any:"abc"`. Two issues conspired:
//
//   (a) `_tlSuggestContext`'s forward-walk over the bareword at caret 0
//       didn't break on DSL operator characters (`:`), so the field-token
//       range it reported swallowed the colon. The popover that opened
//       therefore had `replaceEnd === 4`, and accepting an item replaced
//       `ISP:` rather than just `ISP`.
//   (b) The editor never closed a stale popover when the caret jumped to
//       a different token via mouse — see the e2e regression in
//       tests/e2e-ui.
//
// This file pins (a). It exercises `_tlSuggestContext` directly: a pure
// function with no DOM dependency, so node:test + the `loadModules`
// vm harness is the right tool.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// `timeline-query.js` is pure — no DOM, no view state. It needs
// `timeline-helpers.js` for `_tlEsc` / `_tlMaybeJson` and `constants.js`
// for the parser-limits regex constants. Same load order as the
// production bundle (see scripts/build.py JS_FILES).
const ctx = loadModules([
  'src/constants.js',
  'src/app/timeline/timeline-helpers.js',
  'src/app/timeline/timeline-query.js',
], { expose: ['_tlSuggestContext', '_tlTokenize'] });
const { _tlSuggestContext } = ctx;

test('caret at start of `ISP:"abc"` gives a field context bounded by the colon', () => {
  // Repro of the original bug: the forward walk previously scanned past
  // the `:` (only ` `, `\t`, `\n`, `(`, `)`, `"` were break-chars), so
  // replaceEnd was 4 and accepting a field suggestion would clobber the
  // operator. With the fix it must end at index 3 — just `ISP`.
  const c = _tlSuggestContext('ISP:"abc"', 0);
  assert.strictEqual(c.kind, 'field');
  assert.strictEqual(c.tokenStart, 0);
  assert.strictEqual(c.replaceStart, 0);
  assert.strictEqual(c.replaceEnd, 3, 'should stop at the `:` operator, not swallow it');
  assert.strictEqual(c.prefix, '');
});

test('caret in middle of a field name still bounds at the operator', () => {
  // Caret after `IS` in `ISP:"abc"` — completing the field still must
  // not swallow the `:`. replaceEnd === 3 (the `P`'s end).
  const c = _tlSuggestContext('ISP:"abc"', 2);
  assert.strictEqual(c.kind, 'field');
  assert.strictEqual(c.replaceEnd, 3);
  assert.strictEqual(c.prefix, 'IS');
});

test('caret immediately after `:` switches to value context', () => {
  // Existing behaviour preserved — the back-walk's operator detection
  // (the `for (const op of _TL_QUERY_OPS)` loop further down in the
  // resolver) still kicks in when the caret sits past an operator.
  const c = _tlSuggestContext('ISP:', 4);
  assert.strictEqual(c.kind, 'value');
  assert.strictEqual(c.fieldName, 'ISP');
  assert.strictEqual(c.prefix, '');
});

test('caret inside a quoted value is non-completable', () => {
  // Sanity: a caret strictly inside the quotes returns kind:'none', so
  // the editor will close any popover regardless of any boundary
  // changes above.
  const c = _tlSuggestContext('ISP:"abc"', 6);
  assert.strictEqual(c.kind, 'none');
});

test('forward walk also breaks on `=`, `!`, `~`, `<`, `>`, `,`', () => {
  // Each non-`:` operator must terminate the field-token range too,
  // mirroring the tokenizer's bareword break-set in `_tlTokenize`. This
  // pins the parity so a future operator add doesn't silently regress
  // one direction.
  for (const ch of ['=', '!', '~', '<', '>', ',']) {
    const src = `foo${ch}bar`;
    const c = _tlSuggestContext(src, 0);
    assert.strictEqual(c.kind, 'field', `kind for ${JSON.stringify(src)}`);
    assert.strictEqual(c.replaceEnd, 3, `replaceEnd for ${JSON.stringify(src)} (got ${c.replaceEnd})`);
  }
});

test('IN-clause cleanup: caret 0 of `ISP:"abc"` after deleting prefix yields a clean field range', () => {
  // The exact post-Backspace state from the user's reproduction: query
  // shrunk from `user IN (bob, john) AND ISP:"abc"` to `ISP:"abc"`, caret
  // collapsed to 0. The popover opens here on the input event, so its
  // ctx must be sane: tokenStart === 0, replaceEnd === 3 (just `ISP`).
  const c = _tlSuggestContext('ISP:"abc"', 0);
  assert.strictEqual(c.tokenStart, 0);
  assert.strictEqual(c.replaceEnd, 3);
});
