'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-render-grid-canonical.test.js — pin the canonical-
// column differentiator wiring in the Timeline's GridViewer setup.
//
// When a Timeline holds ≥2 sources, every row carries a canonical
// `__source` column stamping the originating filename.  That column
// is Loupe-provided bookkeeping, not data from the user's file —
// so the merged Timeline applies a soft visual differentiator at
// three DOM surfaces:
//
//   1. Grid header cell  → `grid-header-canonical` class
//      (wired via GridViewer's `headerClass` opt)
//   2. Grid data cells   → `tl-canonical-cell` class
//      (wired via the existing `cellClass` closure — extended to
//      emit the class when `colIdx` indexes a column literally named
//      `__source`)
//   3. Top-Values card   → `tl-col-card-canonical` class
//      (applied at card build time next to `tl-col-card-extracted`
//      / `tl-col-card-pinned`)
//
// These pins lock the source-level integration shape so a refactor
// that renames the helper opt, drops the class, or narrows the
// check to a different column name surfaces immediately.
//
// End-to-end behavioural coverage (that the classes actually render
// in the DOM and carry the expected CSS) lives in
// `tests/e2e-fixtures/timeline-merge.spec.ts`.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

const RG = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-view-render-grid.js'),
  'utf8',
);

test('GridViewer opts include a headerClass callback returning "grid-header-canonical" for __source', () => {
  // The callback is inlined into the `new GridViewer({...})` block
  // to avoid noise — search for the combined signature + body shape.
  assert.match(
    RG,
    /headerClass\s*:\s*\(\s*colIdx\s*,\s*colName\s*\)\s*=>\s*\{[\s\S]{0,200}?colName\s*===\s*['"]__source['"][\s\S]{0,100}?['"]grid-header-canonical['"]/,
    'Timeline GridViewer must pass a headerClass callback that tags __source with grid-header-canonical',
  );
});

test('cellClass closure emits tl-canonical-cell for the __source column', () => {
  // The cellClass closure already handles stack-text tagging —
  // this extension must compose with that, not replace it.
  assert.match(
    RG,
    /baseColumns\s*&&\s*baseColumns\[colIdx\]\s*===\s*['"]__source['"]/,
    'cellClass closure must check `baseColumns[colIdx] === "__source"`',
  );
  assert.match(
    RG,
    /['"]tl-canonical-cell['"]/,
    'cellClass closure must emit the tl-canonical-cell class string',
  );
});

test('cellClass closure emits tl-source-bg-N driven by cell text for __source cells', () => {
  // Per-row source-colour background tint is the actual
  // "differentiate between files" signal — the dashed border marks
  // the column as canonical, and the background hue marks which
  // source the row came from. Derivation MUST use the cell text
  // (the sourceLabel the composite builder stamped into the
  // `__source` column at row-build time) rather than indirecting
  // through `_sourceOfRow` + `_filteredIdx`, because any mapping
  // through the grid's dataIdx / rowView permutation is fragile
  // across concurrent re-renders. Text-driven derivation is
  // always in sync with what the grid actually displays.
  assert.match(
    RG,
    /sourceIdxByLabel/,
    'cellClass closure must build a sourceLabel→index map for the source tint lookup',
  );
  assert.match(
    RG,
    /sourceIdxByLabel\.get\(String\(rawCell\)\)/,
    'cellClass must look the source-index up via `sourceIdxByLabel.get(String(rawCell))` so it matches the displayed cell text',
  );
  assert.match(
    RG,
    /tl-source-bg-['"]\s*\+/,
    'cellClass closure must emit class prefix tl-source-bg- for __source cells',
  );
  // Modulo against TIMELINE_SOURCE_PALETTE length (or a 32 fallback)
  // so N never exceeds the number of CSS rules defined.
  assert.match(
    RG,
    /sIdx\s*%\s*SRC_BG_PALETTE_SIZE/,
    'emitted source-bg index must be taken modulo palette length',
  );
});

test('top-values card render tags __source card with tl-col-card-canonical', () => {
  // The card-render loop sits further down in the same file; the
  // tag is applied after the extracted-card check so a canonical
  // column that was ALSO somehow extracted (never happens in
  // practice — canonical cols can't be extracted from themselves)
  // would carry both classes.
  assert.match(
    RG,
    /cols\[c\]\s*===\s*['"]__source['"][\s\S]{0,200}?['"]tl-col-card-canonical['"]/,
    'Top-Values card loop must tag __source card with tl-col-card-canonical',
  );
});

test('canonical check uses STRICT equality, not an __-prefix match', () => {
  // Only `__source` is a canonical bookkeeping column today; the
  // strict-equality check guards against a future refactor that
  // broadens the differentiator to any `__`-prefixed column. The
  // canonical-cell tint and source-bg shading are tied specifically
  // to `__source`'s row-origin semantics, so a prefix-broadening
  // would silently apply the treatment to any future `__`-prefixed
  // schema column and must surface here.
  //
  // Positive pin — the strict comparison MUST be present.
  assert.match(
    RG,
    /===\s*['"]__source['"]/,
    'canonical check must use `=== "__source"` strict equality',
  );
  // Negative pin — no `startsWith` / `slice` / `substring` / regex
  // match against the `__` prefix should gate the canonical
  // treatment.  Scan for any line near `tl-canonical-cell` or
  // `grid-header-canonical` that uses those constructs.
  const lines = RG.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!/tl-canonical-cell|grid-header-canonical|tl-col-card-canonical/.test(line)) continue;
    // Check ±3 lines around any canonical mention for prefix-checks.
    for (let j = Math.max(0, i - 3); j <= Math.min(lines.length - 1, i + 3); j++) {
      assert.equal(
        /startsWith\s*\(\s*['"]__['"]\s*\)/.test(lines[j]), false,
        'canonical treatment must not be gated on a `.startsWith("__")` prefix check; line: ' + lines[j],
      );
    }
  }
});
