// ════════════════════════════════════════════════════════════════════════════
// deobfuscation-layer-picker.spec.ts — UI-interaction e2e for the
// Deobfuscation card's layer-picker (▾) caret menu.
//
// The menu replaced the legacy "All the way ⏩" button (which silently
// drilled to the highest-severity leaf). The new contract is:
//
//   • Primary button on each Deobfuscation card drills to the IMMEDIATE
//     decoded layer (`Decode & Analyse` / `Load for analysis`). No
//     heuristics — predictable one-layer drill.
//
//   • Caret (▾) button, rendered only when the card has pickable layers
//     or `findings.reconstructedScript` is present, opens a menu of
//     alternative destinations. The stitched-script entry is pinned at
//     the top when present; layer entries follow, in detector-emitted
//     sibling order.
//
//   • The menu is keyboard-dismissable (Escape), outside-click-
//     dismissable (pointerdown anywhere outside the menu + its anchor),
//     and arrow-key navigable.
//
//   • Return-focus from any drill-down target flashes the originating
//     Deobfuscation card (existing contract — we assert it still works
//     through the new code path).
//
// Fixture: `examples/encoded-payloads/nested-b64-hex-url.txt` — a
// plaintext file carrying an outer Base64 that, once decoded, contains
// a hex-encoded URL. The detector emits a top-level encoded-content
// finding whose `innerFindings` holds the inner Hex node, so the caret
// renders and the menu has a real layer entry to offer.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import { gotoBundle, loadFixture } from '../helpers/playwright-helpers';

test.describe.configure({ mode: 'serial' });

test.describe('Deobfuscation layer-picker menu', () => {
  test.beforeEach(async ({ page }) => {
    await gotoBundle(page);
    await loadFixture(page, 'examples/encoded-payloads/nested-b64-hex-url.txt');
  });

  test('legacy "All the way" button no longer exists', async ({ page }) => {
    // Regression guard: the old button's class was `enc-btn-alltheway`.
    // If anyone re-introduces it via copy-paste, this fails fast.
    await expect(page.locator('.enc-btn-alltheway')).toHaveCount(0);
  });

  test('caret button renders on multi-layer Deobfuscation cards', async ({ page }) => {
    // The fixture guarantees at least one encoded-content finding with
    // inner layers (three Base64 peels). We don't pin the exact count —
    // the detector may emit per-line findings or collapse them — but
    // at least one caret must exist.
    const carets = page.locator('.enc-btn-caret');
    await expect(carets.first()).toBeVisible();
    const count = await carets.count();
    expect(count).toBeGreaterThan(0);
  });

  test('caret button carries aria-haspopup + aria-expanded=false on mount', async ({ page }) => {
    const caret = page.locator('.enc-btn-caret').first();
    await expect(caret).toHaveAttribute('aria-haspopup', 'menu');
    await expect(caret).toHaveAttribute('aria-expanded', 'false');
  });

  test('clicking the caret opens a .tb-menu--layer popover with layer entries', async ({ page }) => {
    const caret = page.locator('.enc-btn-caret').first();
    await caret.click();

    // Menu is a child of the caret's `.enc-finding-actions` parent
    // (see app-sidebar.js::_openLayerPickerMenu).
    const menu = page.locator('.tb-menu--layer');
    await expect(menu).toBeVisible();
    await expect(caret).toHaveAttribute('aria-expanded', 'true');

    // At least one menu item — the pickable layer from the triple-B64
    // chain. Role selector guards against a future regression that
    // renders the items as raw <div>s without proper ARIA.
    const items = menu.locator('[role="menuitem"]');
    const itemCount = await items.count();
    expect(itemCount).toBeGreaterThan(0);
  });

  test('Escape dismisses the menu and flips aria-expanded back to false', async ({ page }) => {
    const caret = page.locator('.enc-btn-caret').first();
    await caret.click();
    await expect(page.locator('.tb-menu--layer')).toBeVisible();
    // Wait for the menu's keyboard listener to install (setTimeout(0)
    // inside _openLayerPickerMenu — avoids racing an Escape before
    // dismissal is armed). The focus on the first menu item happens
    // via rAF, which fires after the setTimeout(0) in practice.
    await expect(page.locator('.tb-menu--layer [role="menuitem"]').first()).toBeFocused();

    await page.keyboard.press('Escape');
    await expect(page.locator('.tb-menu--layer')).toHaveCount(0);
    await expect(caret).toHaveAttribute('aria-expanded', 'false');
  });

  test('outside click dismisses the menu', async ({ page }) => {
    const caret = page.locator('.enc-btn-caret').first();
    await caret.click();
    await expect(page.locator('.tb-menu--layer')).toBeVisible();
    await expect(page.locator('.tb-menu--layer [role="menuitem"]').first()).toBeFocused();

    // Click on the main viewer area — any non-menu, non-anchor region
    // trips the outside-click dismissal closure.
    await page.locator('#viewer').click({ position: { x: 10, y: 10 } });
    await expect(page.locator('.tb-menu--layer')).toHaveCount(0);
  });

  test('ArrowDown moves focus between menu items', async ({ page }) => {
    const caret = page.locator('.enc-btn-caret').first();
    await caret.click();
    const menu = page.locator('.tb-menu--layer');
    await expect(menu).toBeVisible();

    // Menu auto-focuses its first item via requestAnimationFrame.
    const firstItem = menu.locator('[role="menuitem"]').first();
    await expect(firstItem).toBeFocused();

    const itemCount = await menu.locator('[role="menuitem"]').count();
    if (itemCount > 1) {
      await page.keyboard.press('ArrowDown');
      const secondItem = menu.locator('[role="menuitem"]').nth(1);
      await expect(secondItem).toBeFocused();
    }
  });

  test('clicking a layer entry drills down through _drillDownToSynthetic', async ({ page }) => {
    // Capture pre-click nav-stack depth (should be 0: fresh top-level
    // fixture load). Post-click must be 1 — the drill pushed a frame.
    const depthBefore = await page.evaluate(() => {
      const w = window as unknown as { app: { _navStack: unknown[] } };
      return w.app._navStack.length;
    });
    expect(depthBefore).toBe(0);

    const caret = page.locator('.enc-btn-caret').first();
    await caret.click();
    const menu = page.locator('.tb-menu--layer');
    await expect(menu).toBeVisible();

    // Click the first layer entry (NOT a stitched entry — the triple-
    // b64 fixture shouldn't produce one with ≥2 spans, but skip any
    // stitched item defensively).
    const firstLayer = menu.locator(
      '[role="menuitem"]:not(.tb-menu-item-stitched)').first();
    await firstLayer.click();

    // Drill happened: menu dismissed, nav-stack grew, sidebar re-rendered.
    await expect(page.locator('.tb-menu--layer')).toHaveCount(0);

    // Wait for the inner load to settle through the __loupeTest idle
    // barrier.
    await page.evaluate(async () => {
      const w = window as unknown as {
        __loupeTest: { waitForIdle(): Promise<void> };
      };
      await w.__loupeTest.waitForIdle();
    });

    const depthAfter = await page.evaluate(() => {
      const w = window as unknown as { app: { _navStack: unknown[] } };
      return w.app._navStack.length;
    });
    expect(depthAfter).toBeGreaterThanOrEqual(1);
  });

  test('toggling the caret twice closes the menu', async ({ page }) => {
    const caret = page.locator('.enc-btn-caret').first();
    await caret.click();
    await expect(page.locator('.tb-menu--layer')).toBeVisible();
    // Wait for aria-expanded to flip — belts and braces so the second
    // click sees the expected state rather than racing the open.
    await expect(caret).toHaveAttribute('aria-expanded', 'true');

    // Second click on the same caret should close the menu (single-slot
    // contract — _toggleLayerPickerMenu checks aria-expanded).
    await caret.click();
    await expect(page.locator('.tb-menu--layer')).toHaveCount(0);
    await expect(caret).toHaveAttribute('aria-expanded', 'false');
  });

  test('menu anchors under the caret, not at the sidebar right edge', async ({ page }) => {
    // Regression guard for a bug where the menu was appended to the
    // caret's `.enc-finding-actions` parent (a full-width flex row)
    // instead of to a dedicated `.tb-menu-wrap` — so `right: 0` on the
    // menu anchored to the action-row's right edge and the menu popped
    // out at the sidebar's right edge instead of under the caret.
    //
    // The fix is that the caret button is wrapped in a `.tb-menu-wrap`
    // so the menu's `position: absolute` + `right: 0` anchors to the
    // wrap's (== caret's) right edge. This assertion catches a DOM
    // refactor that accidentally drops the wrap.
    const caret = page.locator('.enc-btn-caret').first();
    await caret.click();
    const menu = page.locator('.tb-menu--layer');
    await expect(menu).toBeVisible();

    const caretBox = await caret.boundingBox();
    const menuBox = await menu.boundingBox();
    if (!caretBox || !menuBox) {
      throw new Error('Expected bounding boxes for caret and menu');
    }
    // Menu's right edge should sit close to the caret's right edge
    // (tb-menu has a 1px border + 4px shadow spread, so allow a small
    // cushion). If the menu spilled to the sidebar's right edge the
    // delta would be hundreds of pixels.
    const delta = Math.abs((menuBox.x + menuBox.width) - (caretBox.x + caretBox.width));
    expect(delta).toBeLessThan(30);
  });

  test('menu is not clipped — fully inside the viewport on both axes', async ({ page }) => {
    // Regression guard for the "obscured by the page container" bug:
    // before the portal-to-document.body fix, `#sidebar` /
    // `#sb-body`'s `overflow: hidden|auto` clipped the menu when it
    // overflowed their rectangles. The fix portals the menu to
    // `document.body` with `position: fixed`, so the only clip
    // boundary is the viewport itself.
    const caret = page.locator('.enc-btn-caret').first();
    await caret.click();
    const menu = page.locator('.tb-menu--layer');
    await expect(menu).toBeVisible();

    const menuBox = await menu.boundingBox();
    if (!menuBox) throw new Error('Expected menu bounding box');
    const vw = await page.evaluate(() => window.innerWidth);
    const vh = await page.evaluate(() => window.innerHeight);

    // Menu must sit entirely inside the viewport — no clipping.
    expect(menuBox.x).toBeGreaterThanOrEqual(0);
    expect(menuBox.y).toBeGreaterThanOrEqual(0);
    expect(menuBox.x + menuBox.width).toBeLessThanOrEqual(vw);
    expect(menuBox.y + menuBox.height).toBeLessThanOrEqual(vh);
  });

  test('menu portals to document.body (escapes sidebar overflow clipping)', async ({ page }) => {
    // Pins the portal-to-body architecture. The menu must NOT live
    // inside `#sidebar` — if it did, `#sidebar { overflow: hidden }`
    // would crop it whenever its right/bottom edges extended past the
    // sidebar rectangle (exactly the bug the user reported).
    const caret = page.locator('.enc-btn-caret').first();
    await caret.click();
    await expect(page.locator('.tb-menu--layer')).toBeVisible();

    const portalTarget = await page.evaluate(() => {
      const m = document.querySelector('.tb-menu--layer');
      if (!m) return null;
      return {
        parentId: m.parentElement?.id || '',
        parentTag: m.parentElement?.tagName || '',
        insideSidebar: !!m.closest('#sidebar'),
        positionStyle: getComputedStyle(m as Element).position,
      };
    });
    expect(portalTarget).not.toBeNull();
    expect(portalTarget!.insideSidebar).toBe(false);
    expect(portalTarget!.parentTag).toBe('BODY');
    // `position: fixed` is what lets the menu escape every ancestor's
    // scroll/overflow rectangle — the second half of the fix.
    expect(portalTarget!.positionStyle).toBe('fixed');
  });

  test('menu flips upward when caret is near the bottom of the viewport', async ({ page }) => {
    // The fixture yields exactly one caret in the default sidebar
    // scroll position; we force-scroll the sidebar so the caret lands
    // near the bottom of the viewport, then open the menu and assert
    // it grew upward (menu.top < caret.top).
    const caret = page.locator('.enc-btn-caret').first();
    await expect(caret).toBeVisible();

    // Scroll the sidebar body so the caret is near the bottom of the
    // viewport. We use scrollIntoView with `block: 'end'` which aligns
    // the element to the scroll container's bottom edge — plus a
    // small extra offset to push the caret as close to the viewport
    // bottom as the layout allows.
    await caret.evaluate((el) => {
      el.scrollIntoView({ block: 'end', inline: 'nearest' });
      // Nudge a bit further — scrollIntoView leaves ~ element height
      // of space below on some layouts. Scroll the sidebar a bit more.
      const sbBody = document.getElementById('sb-body');
      if (sbBody) sbBody.scrollBy(0, 200);
    });
    // Let the scroll settle.
    await page.waitForTimeout(50);

    const caretBox = await caret.boundingBox();
    if (!caretBox) throw new Error('Expected caret bounding box');
    const vh = await page.evaluate(() => window.innerHeight);

    // Only run the upward-flip assertion if the caret actually ended
    // up in the bottom half of the viewport. If the layout doesn't
    // produce enough content to push the caret down (tiny fixture,
    // huge viewport), skip the strict assertion — the menu will just
    // open downward, which is also correct behaviour. This keeps the
    // test robust across browser / viewport-size variations.
    const caretInBottomHalf = caretBox.y > vh * 0.5;

    await caret.click();
    const menu = page.locator('.tb-menu--layer');
    await expect(menu).toBeVisible();
    const menuBox = await menu.boundingBox();
    if (!menuBox) throw new Error('Expected menu bounding box');

    if (caretInBottomHalf) {
      // Menu should have flipped upward: its top edge sits above the
      // caret's top edge. Upward-flip positioning is
      //   menuTop = anchorRect.top - GAP - menuRect.height
      // so strict <, not <=.
      expect(menuBox.y).toBeLessThan(caretBox.y);
    }
    // Either way, the menu must not clip the viewport's bottom edge.
    expect(menuBox.y + menuBox.height).toBeLessThanOrEqual(vh);
  });

  test('scrolling the sidebar dismisses an open menu', async ({ page }) => {
    // The portal + `position: fixed` architecture means the menu
    // stays glued to the viewport while the sidebar scrolls beneath
    // it — so we close the menu on any sidebar scroll, matching
    // native <select> UX. Pins the scroll-dismissal contract.
    const caret = page.locator('.enc-btn-caret').first();
    await caret.click();
    await expect(page.locator('.tb-menu--layer')).toBeVisible();
    // Wait for listener install (setTimeout(0) inside _openLayerPickerMenu).
    await expect(page.locator('.tb-menu--layer [role="menuitem"]').first()).toBeFocused();

    // Scroll the sidebar body — direction depends on current scroll
    // position. Playwright's `caret.click()` may auto-scroll the
    // sidebar to bring the caret into view, so we can't assume
    // `scrollTop = 0`. Pick whichever direction has headroom so a
    // scroll event actually fires.
    await page.evaluate(() => {
      const sb = document.getElementById('sb-body');
      if (!sb) return;
      const maxScroll = sb.scrollHeight - sb.clientHeight;
      // If we have room to scroll down, go down; otherwise up.
      if (sb.scrollTop < maxScroll - 20) sb.scrollTop += 50;
      else sb.scrollTop = Math.max(0, sb.scrollTop - 50);
    });

    await expect(page.locator('.tb-menu--layer')).toHaveCount(0);
    await expect(caret).toHaveAttribute('aria-expanded', 'false');
  });
});
