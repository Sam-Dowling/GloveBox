'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-source-palette-parity.test.js — pin the JS↔CSS palette mirror.
//
// `TIMELINE_SOURCE_PALETTE` (declared in `src/app/timeline/timeline-sources.js`)
// supplies the per-source colour applied to:
//   • the chip-bar swatch (inline `style.backgroundColor`),
//   • the breadcrumb popover dot (inline `style.backgroundColor`),
//   • the `__source` cell tint via the CSS rules
//     `.tl-grid .grid-cell.tl-source-bg-N { background: rgb(... / .12); }`
//     in `src/styles/viewers.css`.
//
// The CSS rules table is a 1-to-1 mirror of the JS palette by index —
// `tl-source-bg-0` carries the same hue as `TIMELINE_SOURCE_PALETTE[0]`,
// `tl-source-bg-1` matches `[1]`, and so on. If the two arrays drift
// (someone tweaks one without the other) the swatch and the cell tint
// for the same source will visibly disagree, defeating the whole point
// of the unification.
//
// What this test pins:
//   1. The CSS rules cover indices [0, palette.length).
//   2. Every CSS rule's RGB triple matches the corresponding palette
//      hex value (alpha is allowed to differ — the cells use .12, the
//      swatch uses 1.0).
//   3. `timelineSourceColor(idx)` is exported on `window` and returns
//      `palette[idx % length]` for any integer.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle.js');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

// Parse the CSS file once and extract the `tl-source-bg-N` rules.
// Each palette entry has TWO rules: a light-theme rule (alpha .12) and
// a dark-theme rule (`body.dark` prefix, alpha .22). The RGB triple is
// identical between the two — the dark variant just bumps alpha for
// readability against the dark panel. We collect one entry per index
// and assert pairing afterwards.
function readSourceBgCssRules() {
  const css = fs.readFileSync(
    path.join(REPO_ROOT, 'src', 'styles', 'viewers.css'), 'utf8');
  const RE = /(body\.dark\s+)?\.tl-grid\s+\.grid-cell\.tl-source-bg-(\d+)\s*\{[^}]*background\s*:\s*rgb\(\s*(\d+)\s+(\d+)\s+(\d+)\s*\/\s*[^)]+\)\s*;?[^}]*\}/g;
  const lightByIdx = new Map();
  const darkByIdx = new Map();
  let m;
  while ((m = RE.exec(css)) !== null) {
    const isDark = !!m[1];
    const entry = {
      idx: parseInt(m[2], 10),
      r: parseInt(m[3], 10),
      g: parseInt(m[4], 10),
      b: parseInt(m[5], 10),
    };
    (isDark ? darkByIdx : lightByIdx).set(entry.idx, entry);
  }
  // Light is the canonical pin; dark must mirror its RGB.
  const out = Array.from(lightByIdx.values()).sort((a, b) => a.idx - b.idx);
  return { light: out, dark: darkByIdx };
}

function hexToRgb(hex) {
  const h = hex.replace('#', '').toLowerCase();
  return {
    r: parseInt(h.slice(0, 2), 16),
    g: parseInt(h.slice(2, 4), 16),
    b: parseInt(h.slice(4, 6), 16),
  };
}

const ctx = loadModules([
  'src/app/timeline/timeline-sources.js',
], {
  expose: ['TIMELINE_SOURCE_PALETTE', 'timelineSourceColor'],
});

const PALETTE = Array.from(ctx.TIMELINE_SOURCE_PALETTE);
const { light: RULES, dark: DARK_RULES } = readSourceBgCssRules();

test('CSS tl-source-bg-N rules cover indices [0, palette.length)', () => {
  // Every JS palette index needs a matching CSS rule. If the palette
  // is extended (e.g. 32 → 48) without adding rules, sources beyond
  // the rule count would render uncoloured — silent visual desync.
  assert.equal(RULES.length, PALETTE.length,
    `expected ${PALETTE.length} CSS rules to mirror palette; got ${RULES.length}`);
  for (let i = 0; i < PALETTE.length; i++) {
    assert.equal(RULES[i].idx, i,
      `CSS rules must be contiguous from 0; missing or misordered at idx=${i}`);
  }
});

test('every CSS rule RGB matches the corresponding palette hex', () => {
  // Pin the JS↔CSS palette mirror. RGB triples must match exactly;
  // alpha is intentionally allowed to differ (cells use .12 to stay
  // readable, swatches use 1.0 inline).
  for (let i = 0; i < PALETTE.length; i++) {
    const expected = hexToRgb(PALETTE[i]);
    const actual = RULES[i];
    assert.deepEqual(
      { r: actual.r, g: actual.g, b: actual.b },
      expected,
      `CSS rule tl-source-bg-${i} RGB must match TIMELINE_SOURCE_PALETTE[${i}] (${PALETTE[i]})`,
    );
  }
});

test('dark-theme tl-source-bg-N rules mirror RGB of the light rules', () => {
  // The dark-theme variant must mirror the SAME RGB triple, only
  // alpha may differ. A drift here means the dark theme paints a
  // chip and its rows different hues — same failure mode as the
  // JS↔CSS drift, surfaced separately so the diagnostic points at
  // the right rule.
  for (let i = 0; i < PALETTE.length; i++) {
    const dark = DARK_RULES.get(i);
    assert.ok(dark,
      `body.dark variant for tl-source-bg-${i} is missing — dark theme would render uncoloured`);
    assert.deepEqual(
      { r: dark.r, g: dark.g, b: dark.b },
      { r: RULES[i].r, g: RULES[i].g, b: RULES[i].b },
      `body.dark .tl-source-bg-${i} RGB must mirror its light-theme rule`,
    );
  }
});

test('timelineSourceColor(idx) returns palette[idx % length]', () => {
  // Regression guard for the helper that drives chip swatches and
  // breadcrumb dots. Negatives + values past the palette length must
  // wrap into a valid index.
  const n = PALETTE.length;
  for (let i = 0; i < n; i++) {
    assert.equal(ctx.timelineSourceColor(i), PALETTE[i]);
  }
  // Wrap-around.
  assert.equal(ctx.timelineSourceColor(n), PALETTE[0]);
  assert.equal(ctx.timelineSourceColor(n + 1), PALETTE[1]);
  // Negatives normalise.
  assert.equal(ctx.timelineSourceColor(-1), PALETTE[n - 1]);
  assert.equal(ctx.timelineSourceColor(-n), PALETTE[0]);
  // Non-integer / NaN coerce to 0 via `idx | 0`.
  assert.equal(ctx.timelineSourceColor(0.7), PALETTE[0]);
  assert.equal(ctx.timelineSourceColor(NaN), PALETTE[0]);
});
