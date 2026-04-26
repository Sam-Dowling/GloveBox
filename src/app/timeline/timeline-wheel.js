/* timeline-wheel.js — Outer-scroll continuation for the Timeline page.
 *
 * Why this exists
 * ───────────────
 * The Timeline surface is a single scrollable host (`.tl-host`) holding a
 * vertical stack of sections — toolbar, scrubber, chart, the virtual
 * GridViewer (`.tl-grid`, fixed-height with its own internal scroller),
 * a row of top-value column cards (each with its own internal list), the
 * Suspicious table, and the pivot table at the bottom.
 *
 * That means at least four classes of nested scroll container live between
 * a wheel event and the outer host: the GridViewer's `.grid-scroll`, each
 * `.tl-col-card` body, the row-detail drawer when open, and any tall sus-
 * picious / pivot section. Browsers send wheel events to the *innermost*
 * scrollable ancestor first and only chain to the parent when that inner
 * element is saturated (already at top / bottom). On a touchpad the
 * scrolling momentum + 2-axis input papers over this; on a mouse-wheel
 * the user has to literally hunt for a non-scrolling pixel between cards
 * just to keep the page moving toward the pivot.
 *
 * What this fixes
 * ───────────────
 * Implements the "scroll-continuation" pattern used by Notion, Sheets,
 * GitHub diffs, etc.: while the user is mid-wheel-session on the outer
 * host (last outer scroll < CONTINUATION_MS ago) AND the wheel would
 * otherwise be consumed by a nested scroller, redirect that wheel back
 * to the outer host. Once the user pauses for the cooldown, normal
 * inner-scroll behaviour resumes — so working with the GridViewer or a
 * column card directly is unaffected.
 *
 * Honoured modifiers
 * ──────────────────
 *   ctrl / cmd            — browser zoom, never intercepted.
 *   alt                   — pass-through (some apps use it for h-scroll).
 *   shift                 — pass-through (horizontal-wheel convention).
 *   horizontal-only wheel — pass-through (deltaY === 0).
 *
 * Idempotent: a flag on the host element guards against double-install
 * if `_buildDOM` is ever called twice on the same node.
 */
(function () {
    'use strict';

    // How long after an outer-host scroll we keep hijacking wheel events
    // from inner scrollers. 250 ms is enough to span the gap between
    // discrete wheel-clicks (typical mouse wheels emit ~10–20 events per
    // second under sustained scrolling) without trapping the user past
    // the point where they actually wanted to interact with an inner
    // surface.
    const CONTINUATION_MS = 250;

    /**
     * Walk from `target` up to (but not including) `host`, returning the
     * nearest ancestor that is BOTH a vertical scroll container AND has
     * room to move in the requested direction. If we reach `host`
     * without finding one, returns null — meaning the wheel will end up
     * scrolling `host` itself (or a saturated ancestor), which is
     * exactly what we want and requires no intervention.
     */
    function findInnerScroller(target, host, dy) {
        let el = target;
        while (el && el !== host && el.nodeType === 1) {
            const cs = getComputedStyle(el);
            const oy = cs.overflowY;
            if ((oy === 'auto' || oy === 'scroll' || oy === 'overlay') &&
                el.scrollHeight > el.clientHeight) {
                // Inner scroller. Does it have room to move further in
                // the requested direction? If so it would consume the
                // wheel; if it's saturated, native scroll-chaining will
                // forward to the host on its own.
                if (dy > 0 && el.scrollTop < el.scrollHeight - el.clientHeight - 1) return el;
                if (dy < 0 && el.scrollTop > 0) return el;
                return null;
            }
            el = el.parentNode;
        }
        return null;
    }

    function installTimelineWheelContinuation(host) {
        if (!host || host.__loupeWheelContinuation) return;
        host.__loupeWheelContinuation = true;

        // Refresh the continuation timer on ANY movement of the host —
        // wheel, keyboard PgDn/PgUp, programmatic scrollIntoView, drag
        // of the host scrollbar, etc. Without this, only wheels we
        // explicitly routed would extend the window, which would break
        // continuation immediately after a keyboard scroll.
        let lastOuterTs = 0;
        host.addEventListener('scroll', () => {
            lastOuterTs = performance.now();
        }, { passive: true });

        host.addEventListener('wheel', (e) => {
            // Browser zoom and platform horizontal-scroll modifiers
            // must be left intact.
            if (e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;
            const dy = e.deltaY;
            if (!dy) return;

            const inner = findInnerScroller(e.target, host, dy);
            if (!inner) {
                // Wheel will land on the host (or a saturated chain).
                // Stamp the timestamp so subsequent wheels stay in
                // continuation mode.
                lastOuterTs = performance.now();
                return;
            }

            // An inner scroller would consume the wheel. If we're
            // within the continuation window, redirect it to the host
            // instead.
            const now = performance.now();
            if ((now - lastOuterTs) < CONTINUATION_MS) {
                e.preventDefault();
                host.scrollTop += dy;
                lastOuterTs = now;
            }
            // Else: let the inner scroller have the event normally.
        }, { passive: false, capture: true });
    }

    if (typeof window !== 'undefined') {
        window.installTimelineWheelContinuation = installTimelineWheelContinuation;
    }
})();
