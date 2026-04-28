'use strict';
// ════════════════════════════════════════════════════════════════════════════
// grid-viewer-update-columns.test.js — pin the in-place column-swap API.
//
// `GridViewer._updateColumns(newColumns)` is the canonical path for
// adding / removing columns on a LIVE grid (auto-extract, manual
// Extract dialog, drawer right-click extract, Timeline column delete).
// Without it, the only option is `viewer.destroy()` followed by a
// fresh GridViewer mount, which produces a visible "flash" of the
// table — the original symptom that motivated this helper.
//
// Pins:
//   • the method exists in `src/renderers/grid-viewer.js`
//   • it calls the four follow-up methods that turn a column-array
//     swap into a fully repainted grid: `_recomputeColumnWidths`,
//     `_buildHeaderCells`, `_applyColumnTemplate`, `_forceFullRender`.
//     Missing any of them would leave the grid half-updated (e.g.
//     widths right but no header cells, or new columns rendered with
//     stale char-width samples from the old shape).
//   • the shrink path prunes per-index state (`_hiddenCols`,
//     `_userColWidths`, `_sortSpec`) so a future `removeExtractedCol`
//     that drops the active sort column can't crash the render.
//   • Timeline's `_rebuildExtractedStateAndRender` actually wires the
//     helper in — the in-place path must be reachable from the only
//     in-tree caller, otherwise the destroy/rebuild "flash" comes
//     back the moment someone touches the timeline drawer.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const GV = fs.readFileSync(
  path.join(REPO_ROOT, 'src/renderers/grid-viewer.js'),
  'utf8',
);
const DRAWER = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-drawer.js'),
  'utf8',
);

// ── Method presence ────────────────────────────────────────────────────────

test('GridViewer defines _updateColumns(newColumns)', () => {
  // Match either `_updateColumns(newColumns)` or any single-arg signature
  // — we're pinning the API surface, not the parameter name.
  assert.match(
    GV,
    /^\s{2}_updateColumns\s*\(\s*\w+\s*\)\s*\{/m,
    '_updateColumns must be defined as a class method on GridViewer',
  );
});

// ── Repaint chain ──────────────────────────────────────────────────────────

test('_updateColumns runs the full repaint chain', () => {
  // Slice the method body — from the opening `_updateColumns(` to the
  // matching closing brace at the same indent. We use a coarse regex
  // (any text up to the next top-level `}\n`) which is good enough
  // because the helper is short and self-contained.
  const m = GV.match(/^ {2}_updateColumns\s*\([^)]*\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_updateColumns body not found');
  const body = m[1];
  for (const fn of [
    '_recomputeColumnWidths',
    '_buildHeaderCells',
    '_applyColumnTemplate',
    '_forceFullRender',
  ]) {
    assert.match(
      body,
      new RegExp(`this\\.${fn}\\s*\\(`),
      `_updateColumns must call this.${fn}() to fully repaint after a column swap`,
    );
  }
});

// ── Shrink-path pruning ────────────────────────────────────────────────────

test('_updateColumns prunes per-index state on shrink', () => {
  const m = GV.match(/^ {2}_updateColumns\s*\([^)]*\)\s*\{([\s\S]*?)\n {2}\}/m);
  assert.ok(m, '_updateColumns body not found');
  const body = m[1];
  // Hidden cols beyond the new tail are dropped.
  assert.match(
    body,
    /_hiddenCols[\s\S]*?delete/,
    '_updateColumns must prune _hiddenCols on column shrink',
  );
  // User-resized widths beyond the new tail are dropped.
  assert.match(
    body,
    /_userColWidths[\s\S]*?delete/,
    '_updateColumns must prune _userColWidths on column shrink',
  );
  // Active sort on a now-deleted column is cleared.
  assert.match(
    body,
    /_sortSpec\s*=\s*null/,
    '_updateColumns must clear _sortSpec when the sort column was deleted',
  );
});

// ── Timeline integration ──────────────────────────────────────────────────

test('Timeline _rebuildExtractedStateAndRender wires the in-place path', () => {
  // The whole point of the helper. Must be reachable from
  // `_rebuildExtractedStateAndRender` so auto-extract / Extract
  // dialog / drawer right-click flows all benefit from the no-flash
  // path. A regression that removes this call falls back to the
  // destroy/rebuild path and the visible "auto-extract flash" returns.
  assert.match(
    DRAWER,
    /this\._grid\._updateColumns\s*\(/,
    '_rebuildExtractedStateAndRender must call this._grid._updateColumns(...) when a grid is alive',
  );
});

test('Timeline _rebuildExtractedStateAndRender keeps a destroy/rebuild fallback', () => {
  // If `_updateColumns` ever throws (e.g. on a future GridViewer
  // implementation without the helper, or a panic inside it) the
  // grid must still recover by going through the legacy
  // destroy/rebuild path rather than ending up in a half-updated
  // state. Pin both branches so a "simplification" that removes the
  // fallback gets caught.
  assert.match(
    DRAWER,
    /this\._grid\.destroy\s*\(\s*\)/,
    '_rebuildExtractedStateAndRender must keep a destroy() fallback for cold-path / error recovery',
  );
});
