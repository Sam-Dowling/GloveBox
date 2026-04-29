'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-autoextract-pump-suppress-columns.test.js — pin the
// performance fixes (A1 + D1) that suppress per-proposal render tasks
// during the auto-extract apply pump.
//
// CONTEXT — the regressions this test exists to prevent:
//   `_autoExtractBestEffort` applies eligible proposals one per idle
//   tick. Each apply calls `_rebuildExtractedStateAndRender` which —
//   pre-fix — scheduled the full task list on every tick:
//     • `'columns'` triggered `_computeColumnStatsAsync`, an O(rows ×
//       cols) sweep that superseded itself N times (A1 — ~28 s wasted
//       on a 100k-row file).
//     • `'chart'` re-rendered the histogram with identical data on
//       every proposal (filter / window / stack-col are unchanged
//       during the pump) — D1, ~1.28 s wasted on a 100k-row file.
//     • `'scrubber'` / `'chips'` are cheap but suppressed for visual
//       coherence (no flicker as columns slide in).
//
//   The fix:
//     1. `TimelineView` declares `this._autoExtractApplying = false`
//        in its constructor and clears it in `destroy()`.
//     2. `_autoExtractBestEffort` sets the flag to `true` immediately
//        before scheduling the FIRST `applyStep` tick (after the
//        `if (!eligible.length) return;` early-exit) and clears it in
//        the terminating `idx >= ranked.length` branch BEFORE the
//        existing GeoIP retry block, then schedules
//        `['columns', 'chart', 'scrubber', 'chips']` exactly once so
//        every suppressed surface refreshes from the final column set.
//     3. `_rebuildExtractedStateAndRender` consults the flag:
//        - fast-path (in-place `_grid._updateColumns`) → schedule
//          NOTHING during pump (grid is already updated; everything
//          else is deferred to terminus). Guarded with
//          `if (fastTasks.length)` to avoid an empty-array schedule.
//        - cold-path (destroy + rebuild) and in-place-failure fallback
//          → schedule ONLY `'grid'` during pump (the grid actually
//          needs to be (re)mounted; chart/scrubber/chips/columns are
//          deferred to terminus).
//
// What this test pins (static-text only — the runtime behaviour is
// covered by `timeline-view-autoextract-real-fixture.test.js` and the
// e2e CSV-load smoke):
//
//   • `_autoExtractApplying` is initialised to `false` in
//     `timeline-view.js` and cleared in `destroy()`.
//   • The flag is set to `true` exactly ONCE in
//     `timeline-view-autoextract.js`, immediately before the FIRST
//     `schedule(applyStep)` call.
//   • The flag is cleared in the apply-pump terminus (the
//     `idx >= ranked.length` branch) BEFORE any toast / GeoIP-retry
//     work and that branch schedules `['columns']` exactly once.
//   • `_rebuildExtractedStateAndRender` reads the flag and dispatches
//     a tasks list WITHOUT `'columns'` while the pump is running.
//
// These are static-source assertions, mirroring the pattern in
// `timeline-view-autoextract-uncapped.test.js`. Runtime / vm-based
// integration would require stubbing the entire grid + dataset stack;
// the static checks catch the regression class we care about (a
// future "let's just put 'columns' back in the per-proposal schedule"
// edit) without that machinery.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const VIEW_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view.js'), 'utf8');
const AUTOEXTRACT_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-autoextract.js'), 'utf8');
const DRAWER_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-drawer.js'), 'utf8');

// ── Constructor + destroy invariants (timeline-view.js) ────────────────────

test('TimelineView constructor initialises _autoExtractApplying = false', () => {
  // The flag MUST be defined as a primitive `false` on every fresh
  // view so `_rebuildExtractedStateAndRender` can read it
  // unconditionally without a `typeof` guard. Pin the literal
  // assignment.
  assert.ok(
    /this\._autoExtractApplying\s*=\s*false\s*;/.test(VIEW_SRC),
    'expected `this._autoExtractApplying = false;` in TimelineView constructor'
  );
});

test('TimelineView.destroy() clears _autoExtractApplying', () => {
  // Belt-and-braces — defensively clear the flag on destroy so a
  // recycled prototype slot or a leaked reference never carries a
  // stale `true` into a future view's `_rebuildExtractedStateAndRender`.
  // Two assignments are expected (constructor + destroy), so use a
  // global match count and assert >= 2.
  const matches = VIEW_SRC.match(/this\._autoExtractApplying\s*=\s*false\s*;/g);
  assert.ok(matches && matches.length >= 2,
    `expected >= 2 \`this._autoExtractApplying = false;\` lines in ` +
    `timeline-view.js (constructor + destroy), got ${matches ? matches.length : 0}`);
});

// ── Apply-pump bracketing (timeline-view-autoextract.js) ───────────────────

test('_autoExtractBestEffort sets _autoExtractApplying = true exactly once', () => {
  // Set on the apply-pump entry; cleared by the terminus + by destroy.
  // If a refactor accidentally moves the set higher (above the
  // `if (!eligible.length) return;` early-exit) the flag would stick
  // for files with no eligible proposals — guard against that by
  // pinning the count.
  const setMatches = AUTOEXTRACT_SRC.match(/this\._autoExtractApplying\s*=\s*true\s*;/g);
  assert.ok(setMatches && setMatches.length === 1,
    `expected exactly 1 \`this._autoExtractApplying = true;\` in ` +
    `timeline-view-autoextract.js, got ${setMatches ? setMatches.length : 0}`);
});

test('the `true` set sits immediately before the first schedule(applyStep) call', () => {
  // Ordering matters: the set must come AFTER the
  // `if (!eligible.length) return;` early-exit (so a no-eligible-
  // proposals file doesn't leave the flag stuck `true`) but BEFORE
  // the first `applyStep` schedule (so the very first idle tick sees
  // the flag set when it lands in `_rebuildExtractedStateAndRender`).
  // Pin the relative order with an in-line regex.
  const re = /this\._autoExtractApplying\s*=\s*true\s*;\s*\n\s*this\._autoExtractIdleHandle\s*=\s*schedule\(applyStep\)\s*;/;
  assert.ok(re.test(AUTOEXTRACT_SRC),
    'expected `this._autoExtractApplying = true;` to immediately precede ' +
    'the first `this._autoExtractIdleHandle = schedule(applyStep);` in ' +
    'timeline-view-autoextract.js');
});

test('apply-pump terminus clears the flag and schedules deferred surfaces once', () => {
  // The terminating branch (`idx >= ranked.length`) must:
  //   (a) clear `_autoExtractApplying` so subsequent
  //       `_rebuildExtractedStateAndRender` calls (e.g. from the GeoIP
  //       retry below, or from any future user action) re-include the
  //       full task list in their schedule;
  //   (b) schedule the full deferred-surface list exactly once so the
  //       Top Values strip, histogram, scrubber, and chip overlays all
  //       refresh from the final column set. Per D1, the chart task is
  //       suppressed during the pump (the histogram re-renders with
  //       identical data on every proposal — pure waste) so the
  //       terminus must include 'chart' alongside 'columns'.
  // Both lines must appear inside the terminus branch — assert their
  // co-location with a multi-line regex.
  const re = /this\._autoExtractApplying\s*=\s*false\s*;\s*\n\s*this\._scheduleRender\(\[\s*'columns'\s*,\s*'chart'\s*,\s*'scrubber'\s*,\s*'chips'\s*\]\)\s*;/;
  assert.ok(re.test(AUTOEXTRACT_SRC),
    'expected `this._autoExtractApplying = false;` followed by ' +
    '`this._scheduleRender([\'columns\', \'chart\', \'scrubber\', \'chips\']);` ' +
    'in the apply-pump terminus branch of timeline-view-autoextract.js');
});

// ── Per-proposal schedule suppression (timeline-drawer.js) ─────────────────

test('fast-path schedules NOTHING during apply pump (D1)', () => {
  // The fast-path branch (in-place `_grid._updateColumns`) updates the
  // grid synchronously then schedules render tasks for the OTHER
  // surfaces. Per D1, every one of those (chart / scrubber / chips /
  // columns) is suppressed during the pump — the chart re-renders
  // identical data, columns triggers an O(rows×cols) stats sweep, and
  // scrubber/chips are cosmetic. So the fast-path conditional must
  // produce an empty `fastTasks` array under the flag, and the call
  // site must guard `if (fastTasks.length)` to avoid an empty-array
  // schedule (which would queue an empty RAF callback for no reason).
  const re = /const\s+fastTasks\s*=\s*this\._autoExtractApplying\s*\?\s*\[\s*\]\s*:\s*\[\s*'chart'\s*,\s*'scrubber'\s*,\s*'chips'\s*,\s*'columns'\s*\]\s*;\s*\n\s*if\s*\(\s*fastTasks\.length\s*\)\s*this\._scheduleRender\(fastTasks\)\s*;/;
  assert.ok(re.test(DRAWER_SRC),
    'expected fast-path to compute `fastTasks` as `[]` under ' +
    '`_autoExtractApplying`, full list otherwise, and to guard the ' +
    'schedule with `if (fastTasks.length)`');
});

test('cold-path and fallback branches schedule ONLY \'grid\' during apply pump (D1)', () => {
  // Cold path (no live grid) and the in-place-failure fallback both
  // need to (re)mount the grid, so they MUST keep `'grid'` in the task
  // list — but every other surface is suppressed during the pump
  // (per D1) and refreshed once at the terminus. Pin the literal
  // ternary `_autoExtractApplying ? ['grid'] : full-list` for both
  // branches.
  const matches = DRAWER_SRC.match(
    /this\._autoExtractApplying\s*\?\s*\[\s*'grid'\s*\]\s*:\s*\[\s*'chart'\s*,\s*'scrubber'\s*,\s*'chips'\s*,\s*'grid'\s*,\s*'columns'\s*\]/g);
  assert.ok(matches && matches.length >= 2,
    `expected >= 2 cold/fallback branches with the literal ternary ` +
    `\`_autoExtractApplying ? ['grid'] : ['chart', 'scrubber', 'chips', ` +
    `'grid', 'columns']\`, got ${matches ? matches.length : 0}. ` +
    `One protects the destroy/rebuild cold path; one protects the ` +
    `in-place-update failure fallback.`);
});

test('post-fix drawer no longer emits unconditional per-proposal schedules', () => {
  // Guard against re-introduction of the pre-fix lines:
  //   _scheduleRender(['chart', 'scrubber', 'chips', 'columns'])           // fast-path
  //   _scheduleRender(['chart', 'scrubber', 'chips'])                      // A1 fast-path
  //   _scheduleRender(['chart', 'scrubber', 'chips', 'grid', 'columns'])   // cold path
  //   _scheduleRender(['chart', 'scrubber', 'chips', 'grid'])              // A1 cold path
  // Each of these would re-introduce per-proposal redundant chart
  // redraws (D1) or column-stats sweeps (A1).
  const forbidden = [
    /_scheduleRender\(\[\s*'chart'\s*,\s*'scrubber'\s*,\s*'chips'\s*,\s*'columns'\s*\]\)/,
    /_scheduleRender\(\[\s*'chart'\s*,\s*'scrubber'\s*,\s*'chips'\s*\]\)/,
    /_scheduleRender\(\[\s*'chart'\s*,\s*'scrubber'\s*,\s*'chips'\s*,\s*'grid'\s*,\s*'columns'\s*\]\)/,
    /_scheduleRender\(\[\s*'chart'\s*,\s*'scrubber'\s*,\s*'chips'\s*,\s*'grid'\s*\]\)/,
  ];
  for (const re of forbidden) {
    assert.ok(!re.test(DRAWER_SRC),
      `forbidden literal ${re} found in timeline-drawer.js — D1/A1 ` +
      `regression: chart/columns must be deferred to the apply-pump ` +
      `terminus, not scheduled per proposal.`);
  }
});
