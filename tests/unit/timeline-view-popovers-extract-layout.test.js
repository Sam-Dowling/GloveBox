// timeline-view-popovers-extract-layout.test.js
//
// Extract Values dialog UX shake-up — sticky footer + dedicated proposal-
// list scroll region. Pins the contract so a future markup refactor can't
// silently regress the "primary action stays in view" property that
// motivated the redesign.
//
// Background: pre-redesign the dialog had `<footer>` (with the
// "Extract selected" button) nested inside the same scroll container
// as the proposal list. On a long auto-scan the analyst saw the list
// fill the viewport and had to scroll all the way down to extract.
// The fix:
//
//   1. Scope `overflow:auto` to `.tl-auto-body` only, give the auto
//      pane a flex column with `min-height: 0`, and pin toolbar /
//      preview / footer with `flex: 0 0 auto` so the primary CTA
//      stays in view regardless of list scroll position.
//   2. Reset `autoBody.scrollTop = 0` after each `renderList()` so a
//      fresh open / rescan / facet/search/sort change always reveals
//      the first proposal.
//
// (An earlier iteration also added a duplicate `.tl-dialog-head-cta`
// button in the dialog header. That was removed once the sticky-
// footer leg made it redundant — the footer button is now always in
// view, so the header duplicate was pure noise.)
//
// Both surviving legs are asserted via static text on the source files
// — same convention as the sibling `…-extract-selected-srcvalues` test.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const POPOVERS = readFileSync(
  join(__dirname, '..', '..', 'src', 'app', 'timeline', 'timeline-view-popovers.js'),
  'utf8'
);
const CSS = readFileSync(
  join(__dirname, '..', '..', 'src', 'styles', 'viewers.css'),
  'utf8'
);

// ── Markup contract ────────────────────────────────────────────────────────

test('renderList resets scroll-to-top after each render', () => {
  // Avoids the "dialog opens already-scrolled" jarring effect on a
  // long auto-scan.
  assert.match(POPOVERS, /autoBody\.scrollTop = 0/,
    'expected `autoBody.scrollTop = 0` reset inside renderList');
});

// ── CSS contract — sticky toolbar/footer + dedicated scroll region ────────

test('CSS: only .tl-auto-body scrolls inside the auto pane', () => {
  // Pane is flex column with `overflow:hidden` on the body so the
  // primary action stays in view; the proposal list is the sole
  // overflow:auto child.
  assert.match(CSS,
    /\.tl-dialog-extract \.tl-dialog-body \{[^}]*overflow:\s*hidden/,
    'expected `.tl-dialog-extract .tl-dialog-body { overflow: hidden }`');
  assert.match(CSS,
    /\.tl-auto-body \{[^}]*overflow:\s*auto/,
    'expected `.tl-auto-body { overflow: auto }` as the dedicated scroll region');
});

test('CSS: auto pane is a flex column with min-height:0', () => {
  // Without `min-height: 0` on a flex column the child's overflow
  // does nothing — the pane just grows to fit the list.
  assert.match(CSS,
    /\.tl-dialog-extract \.tl-dialog-pane-auto[\s\S]{0,200}min-height:\s*0/,
    'expected `min-height: 0` on the auto pane (flex scroll fix)');
});
