// ════════════════════════════════════════════════════════════════════════════
// timeline-query-popover.spec.ts — Regression for a Timeline query bar bug
// where a stale suggestion popover survived a mouse-driven caret jump.
//
// Reproduction (from the original report):
//   1. Active query: `Department IN (Sales, Marketing) AND Active:"TRUE"`
//   2. Select `Department IN (Sales, Marketing) AND ` and press Backspace
//      → query collapses to `Active:"TRUE"`, caret is at position 0.
//   3. The `input` handler opens the suggestion popover on this caret
//      position. Pre-fix, `_tlSuggestContext` reported a field-token
//      range whose `replaceEnd` swallowed the colon (token ended at the
//      `"` because the forward walk only broke on whitespace / paren /
//      quote). The popover's first item, `any:`, was selected.
//   4. User clicks at the end of the textarea. The caret moves to
//      position 9 but the popover stays open with stale `ctx`.
//   5. User presses Enter. `_isSuggestOpen()` is true, so `_onKeyDown`
//      calls `_applySuggest(true)` against the stale range and rewrites
//      `Active:"TRUE"` → `any:"TRUE"`.
//
// This spec asserts the post-fix behaviour: pressing Enter at step 5
// commits the query as-is (`Active:"TRUE"`), not a mutated form.
//
// Two fixes interact here:
//   • `_tlSuggestContext` forward walk now breaks on operator chars
//     (`:`, `=`, `!`, `~`, `<`, `>`, `,`). Pinned by the unit test in
//     tests/unit/timeline-suggest.test.js.
//   • The editor now closes a stale popover on click / non-typing keyup
//     when the caret leaves the popover's anchor token. Pinned here.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import { gotoBundle, loadFixture } from '../helpers/playwright-helpers';

// `examples/office/example.csv` is small (8 rows, 6 columns:
// Name, Department, Email, Start Date, Salary, Active) and routes
// through the Timeline. We use `Department` + `Active` because they're
// stable, single-token names so the query prefix is unambiguous.
const FIXTURE = 'examples/office/example.csv';
const ORIGINAL_QUERY = 'Department IN (Sales, Marketing) AND Active:"TRUE"';
const PREFIX_TO_DELETE = 'Department IN (Sales, Marketing) AND ';
const EXPECTED_AFTER_DELETE = 'Active:"TRUE"';

test('Timeline query: caret jump after selection-delete keeps subsequent Enter from being hijacked by stale popover', async ({ page }) => {
  await gotoBundle(page);
  await loadFixture(page, FIXTURE);

  // Wait for the Timeline view + query editor to mount. The editor's
  // `<textarea class="tl-query-input">` is part of the TimelineView's
  // initial DOM (built by `TimelineView._buildDOM`).
  const input = page.locator('.tl-query-input');
  await expect(input).toBeVisible({ timeout: 10_000 });

  // Set the original query directly via the editor's public API and
  // close any popover up-front. Going through `input.fill` would fire
  // an `input` event that opens a keyword-suggestion popover at the
  // trailing quote and the subsequent `Enter` would accept the first
  // item (`AND `), polluting our starting state. The bug we're
  // chasing is about the popover that opens AFTER the prefix-delete,
  // not the one that opens on initial typing — so we bypass the
  // typing-driven open here.
  await page.evaluate((args) => {
    type AppShape = {
      _timelineCurrent?: { _queryEditor?: { setValue(v: string): void; getValue(): string } };
    };
    const w = window as unknown as { app: AppShape };
    const ed = w.app && w.app._timelineCurrent && w.app._timelineCurrent._queryEditor;
    if (!ed) throw new Error('TimelineView._queryEditor not found');
    ed.setValue(args.q);
  }, { q: ORIGINAL_QUERY });
  await expect(input).toHaveValue(ORIGINAL_QUERY);

  // Reproduce the user's action — select the prefix and dispatch a
  // Backspace as if from a real keystroke. The selection MUST persist
  // until the input event fires, so we do everything inside one
  // `page.evaluate` block: focus → select → splice the value → fire
  // an `input` event with `inputType: 'deleteContentBackward'`. This
  // matches exactly what the browser produces for a user pressing
  // Backspace over a selection — Playwright's `input.press('Backspace')`
  // sometimes refocuses the element and clears `selectionStart` /
  // `selectionEnd` before the keypress reaches the textarea, which
  // makes the selection-then-delete pattern impossible to drive from
  // the outside.
  await page.evaluate((args) => {
    const el = document.querySelector('.tl-query-input') as HTMLTextAreaElement | null;
    if (!el) throw new Error('tl-query-input not found');
    el.focus();
    el.setSelectionRange(0, args.prefixLen);
    // Splice out the selection.
    const before = el.value.slice(0, el.selectionStart || 0);
    const after = el.value.slice(el.selectionEnd || 0);
    el.value = before + after;
    el.setSelectionRange(before.length, before.length);
    // Fire a real `InputEvent` so the editor's listener runs the
    // `_refreshSuggest({allowOpen: true})` path the bug depends on.
    const ev = new InputEvent('input', {
      inputType: 'deleteContentBackward',
      bubbles: true,
      cancelable: false,
    });
    el.dispatchEvent(ev);
  }, { prefixLen: PREFIX_TO_DELETE.length });
  await expect(input).toHaveValue(EXPECTED_AFTER_DELETE);

  // Move the caret to the end of the textarea. Use a programmatic
  // selection update + a click on the input element — together they
  // simulate the user clicking at the end position. The click event
  // is what triggers the new `_revalidateSuggestForCaret` listener
  // that closes the stale popover.
  await page.evaluate(() => {
    const el = document.querySelector('.tl-query-input') as HTMLTextAreaElement | null;
    if (!el) throw new Error('tl-query-input not found');
    el.focus();
    el.setSelectionRange(el.value.length, el.value.length);
  });
  // Dispatch a real `click` event so the editor's click listener
  // fires. (Playwright's `input.click()` would re-target the centre
  // of the element and reset the caret to 0; a synthetic click that
  // preserves the programmatic caret position is what we want.)
  await page.evaluate(() => {
    const el = document.querySelector('.tl-query-input') as HTMLTextAreaElement | null;
    if (!el) throw new Error('tl-query-input not found');
    el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
  });

  // After the caret-jump revalidation, the popover MUST be closed.
  // (If the fix regresses, the popover's element with class
  // `tl-query-suggest` will still be in the DOM.) The popover is
  // portalled to <body>, not nested inside the editor.
  const popover = page.locator('body > .tl-query-suggest');
  await expect(popover).toHaveCount(0);

  // Press Enter at the new caret position. The editor's keydown
  // handler should hit the "popover closed" Enter branch which
  // commits the query value verbatim — NOT the popover-open branch
  // which would call `_applySuggest(true)` and rewrite the value.
  await input.press('Enter');

  // The query value must remain `Active:"TRUE"`. Pre-fix this was
  // `any:"TRUE"` (the popover replaced range [0, 4) — `Active:` —
  // with the first field-suggestion item, `any:`).
  await expect(input).toHaveValue(EXPECTED_AFTER_DELETE);
});

// ════════════════════════════════════════════════════════════════════════════
// Second bug — typing-driven repro of the same family. User builds a query
// like ` Severity:INFO` (leading space) by deleting earlier characters,
// places the caret between the space and `S`, presses Backspace then Enter.
// Pre-fix the editor rewrote the value to `any::INFO` because:
//   • Backspace fires an `input` event that opens a field-suggestion
//     popover at caret 0 with replaceRange covering `Severity` (0..8).
//   • The popover element ends up not visible to the user (whatever the
//     exact mechanism — layout race / scroll / clipping), but `_sugg` is
//     still set with items.
//   • Enter then accepts `any:` against the stale-feeling range,
//     yielding `'' + 'any:' + ':INFO'` = `'any::INFO'`.
//
// The new visibility gate (`_isSuggestVisible`) makes Tab/Enter only
// accept when the popover is actually visible. We force the invisible
// state synthetically (`display:none`) to keep the test deterministic
// across browsers and viewport sizes.
// ════════════════════════════════════════════════════════════════════════════

const QUERY_CSV = 'examples/office/example.csv';

test('Timeline query: Enter on a hidden-but-state-open popover submits, does not insert any:', async ({ page }) => {
  await gotoBundle(page);
  await loadFixture(page, QUERY_CSV);

  const input = page.locator('.tl-query-input');
  await expect(input).toBeVisible({ timeout: 10_000 });

  // Seed the value via the editor API (no popover spawned yet).
  await page.evaluate(() => {
    type AppShape = { _timelineCurrent?: { _queryEditor?: { setValue(v: string): void } } };
    const w = window as unknown as { app: AppShape };
    const ed = w.app && w.app._timelineCurrent && w.app._timelineCurrent._queryEditor;
    if (!ed) throw new Error('TimelineView._queryEditor not found');
    ed.setValue(' Severity:INFO');
  });
  await expect(input).toHaveValue(' Severity:INFO');

  // Place caret between the leading space and `S` (position 1), then
  // synthesise a Backspace input event — same technique the existing
  // selection-delete test uses. This opens the field-suggestion popover.
  await page.evaluate(() => {
    const el = document.querySelector('.tl-query-input') as HTMLTextAreaElement | null;
    if (!el) throw new Error('tl-query-input not found');
    el.focus();
    el.setSelectionRange(1, 1);
    const before = el.value.slice(0, 0);   // delete the space
    const after = el.value.slice(1);
    el.value = before + after;
    el.setSelectionRange(0, 0);
    el.dispatchEvent(new InputEvent('input', {
      inputType: 'deleteContentBackward', bubbles: true, cancelable: false,
    }));
  });
  await expect(input).toHaveValue('Severity:INFO');

  // Force the popover element invisible — this synthesises whatever
  // mechanism (scroll race, layout reflow, etc.) puts the user-visible
  // dropdown out of sight while leaving `_sugg` populated. The fix MUST
  // detect this and not let Enter accept the highlighted item.
  const wasOpen = await page.evaluate(() => {
    type AppShape = { _timelineCurrent?: { _queryEditor?: { _sugg?: { el: HTMLElement } | null } } };
    const w = window as unknown as { app: AppShape };
    const ed = w.app && w.app._timelineCurrent && w.app._timelineCurrent._queryEditor;
    if (!ed || !ed._sugg || !ed._sugg.el) return false;
    ed._sugg.el.style.display = 'none';
    return true;
  });
  expect(wasOpen).toBe(true);

  // Press Enter. With the visibility gate, this must hit the
  // popover-closed Enter branch and commit the value verbatim.
  await input.press('Enter');

  // Pre-fix this was `any::INFO`.
  await expect(input).toHaveValue('Severity:INFO');
});

test('Timeline query: visible popover still accepts on Enter (regression guard)', async ({ page }) => {
  await gotoBundle(page);
  await loadFixture(page, QUERY_CSV);

  const input = page.locator('.tl-query-input');
  await expect(input).toBeVisible({ timeout: 10_000 });
  await input.focus();

  // Type a single letter that uniquely matches one column. The fixture
  // has columns Name, Department, Email, Start Date, Salary, Active —
  // typing `Sa` matches `Salary` and a few other things; we just need a
  // visible popover here to verify Enter still accepts when visible.
  await page.keyboard.type('Sa');

  // Wait for the popover to appear in the DOM and have a real layout box.
  const popover = page.locator('body > .tl-query-suggest');
  await expect(popover).toHaveCount(1);
  await expect(popover).toBeVisible();

  // Sanity-check the visibility helper agrees.
  const visible = await page.evaluate(() => {
    type AppShape = { _timelineCurrent?: { _queryEditor?: { _isSuggestVisible(): boolean } } };
    const w = window as unknown as { app: AppShape };
    const ed = w.app && w.app._timelineCurrent && w.app._timelineCurrent._queryEditor;
    return !!(ed && ed._isSuggestVisible());
  });
  expect(visible).toBe(true);

  // Press Enter — the highlighted suggestion should be accepted, mutating
  // the input value (the exact value depends on item order, but it MUST
  // differ from the raw typed text).
  await input.press('Enter');

  const finalValue = await input.inputValue();
  expect(finalValue).not.toBe('Sa');
  // Field accepts append `:` (or `[name]:` if the field name needs
  // bracketing). Either way, the result contains a `:` separator.
  expect(finalValue).toContain(':');
});

test('Timeline query: Tab on a hidden-but-state-open popover does not accept', async ({ page }) => {
  await gotoBundle(page);
  await loadFixture(page, QUERY_CSV);

  const input = page.locator('.tl-query-input');
  await expect(input).toBeVisible({ timeout: 10_000 });
  await input.focus();

  // Type something to spawn a popover.
  await page.keyboard.type('Sa');
  const popover = page.locator('body > .tl-query-suggest');
  await expect(popover).toHaveCount(1);

  // Hide it.
  await page.evaluate(() => {
    type AppShape = { _timelineCurrent?: { _queryEditor?: { _sugg?: { el: HTMLElement } | null } } };
    const w = window as unknown as { app: AppShape };
    const ed = w.app && w.app._timelineCurrent && w.app._timelineCurrent._queryEditor;
    if (ed && ed._sugg && ed._sugg.el) ed._sugg.el.style.display = 'none';
  });

  // Tab must NOT accept. The current value should remain `Sa`. We don't
  // assert on focus movement — Playwright's keyboard.press('Tab') with
  // the textarea focused may or may not move focus depending on the
  // surrounding tab-stops, but the textarea VALUE is the contract here.
  await input.press('Tab');

  // Verify the value didn't get rewritten by an accept.
  const finalValue = await input.inputValue();
  expect(finalValue).toBe('Sa');
});

// ════════════════════════════════════════════════════════════════════════════
// Third bug — off-screen popover at column 0. Same family as the
// hidden-popover case above, but with a much sneakier mechanism:
//   • User builds a query like ` Severity=INFO` (leading space) by
//     deleting earlier characters; caret ends up at column 0.
//   • An `input` event there opens the field-suggestion popover.
//   • `_caretScreenPos` historically used a fallback `if (probeWidth <= 0)
//     return anchorRect` — but at column 0 with no text before the caret,
//     `probeWidth === 0` is the CORRECT measurement, not a failure.
//     `anchorRect` is the rect of a zero-width <span> living inside the
//     off-screen probe (parked at left:-99999), so the popover ended up
//     positioned at (~6, ~-99615): visually invisible, but with a
//     non-zero size and `display: block` / `visibility: visible` so the
//     `_isSuggestVisible` gate still considered it "visible".
//   • Enter on that "visible" popover would call `_applySuggest(true)`
//     and prepend `any:` to the user's in-progress query.
//
// The fix lives in `_caretScreenPos` itself: only fall back when `x` is
// non-finite (display:none ancestor → all rects collapse to NaN), and
// fall back to the textarea's own padding-box origin — never to the
// off-screen probe's anchor rect.
//
// This test verifies the popover renders ON-SCREEN at column 0, which is
// the most direct behavioural assertion of the fix. Pre-fix, the rect
// would be at y ≈ -99615.
// ════════════════════════════════════════════════════════════════════════════
test('Timeline query: popover at caret column 0 renders within the viewport (regression: off-screen probe fallback)', async ({ page }) => {
  await gotoBundle(page);
  await loadFixture(page, QUERY_CSV);

  const input = page.locator('.tl-query-input');
  await expect(input).toBeVisible({ timeout: 10_000 });

  // Seed a query that has content but with the caret at column 0. Use
  // the editor API to avoid spawning a popover from typing — we want to
  // control exactly when the popover opens (via the `input` event we
  // synthesise below).
  await page.evaluate(() => {
    type AppShape = { _timelineCurrent?: { _queryEditor?: { setValue(v: string): void } } };
    const w = window as unknown as { app: AppShape };
    const ed = w.app && w.app._timelineCurrent && w.app._timelineCurrent._queryEditor;
    if (!ed) throw new Error('TimelineView._queryEditor not found');
    ed.setValue(' Severity=INFO');
  });
  await expect(input).toHaveValue(' Severity=INFO');

  // Place the caret at column 0 and synthesise a `Delete` (forward
  // delete) — it removes the leading space, leaves the caret at 0, and
  // fires the `input` event that opens the popover. This matches the
  // exact path from the user's bug transcript.
  await page.evaluate(() => {
    const el = document.querySelector('.tl-query-input') as HTMLTextAreaElement | null;
    if (!el) throw new Error('tl-query-input not found');
    el.focus();
    el.setSelectionRange(0, 0);
    // Splice out the leading space (forward-delete from column 0).
    el.value = el.value.slice(1);
    el.setSelectionRange(0, 0);
    el.dispatchEvent(new InputEvent('input', {
      inputType: 'deleteContentForward', bubbles: true, cancelable: false,
    }));
  });
  await expect(input).toHaveValue('Severity=INFO');

  // The popover MUST open at column 0.
  const popover = page.locator('body > .tl-query-suggest');
  await expect(popover).toHaveCount(1);
  await expect(popover).toBeVisible();

  // Critical assertion: the popover is on-screen. Pre-fix it would render
  // at y ≈ -99615 (way above the viewport).
  const rect = await popover.evaluate((el) => {
    const r = (el as HTMLElement).getBoundingClientRect();
    return { left: r.left, top: r.top, right: r.right, bottom: r.bottom };
  });
  const viewport = page.viewportSize() || { width: 1280, height: 720 };
  // Allow a small negative tolerance for sub-pixel rounding.
  expect(rect.top, 'popover top must be inside the viewport').toBeGreaterThanOrEqual(-1);
  expect(rect.left, 'popover left must be inside the viewport').toBeGreaterThanOrEqual(-1);
  expect(rect.bottom, 'popover bottom must be inside the viewport').toBeLessThanOrEqual(viewport.height + 1);
  expect(rect.right, 'popover right must be inside the viewport').toBeLessThanOrEqual(viewport.width + 1);
});
