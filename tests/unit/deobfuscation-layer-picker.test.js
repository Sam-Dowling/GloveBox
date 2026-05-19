'use strict';
// ════════════════════════════════════════════════════════════════════════════
// deobfuscation-layer-picker.test.js — unit tests for the Deobfuscation
// card's layer-picker (▾) menu contract.
//
// Two helpers under test:
//
//   • `App.prototype._flattenFindingLayers(finding)`
//       — defined in src/app/app-sidebar-focus.js
//       — walks the innerFindings tree and returns an array of pickable
//         layer entries in detector-emitted sibling order. Replaces the
//         old "All the way ⏩" button's silent severity-ranked leaf pick
//         with an explicit, user-visible enumeration of every layer the
//         analyst can open. Stubs (`finder-budget`, `depth-exceeded`)
//         carry neither decodedBytes nor rawCandidate and must be
//         filtered out.
//
//   • `App.prototype._buildLayerPickerEntries(finding, findings, fileName)`
//       — defined in src/app/app-sidebar.js
//       — composes the menu's items: optional pinned stitched-script
//         entry (when `findings.reconstructedScript.spans.length >= 2`),
//         separator, then one entry per flattened layer. Caret button
//         should not be rendered when the returned `items` array is empty.
//
// The tests below EXERCISE `_flattenFindingLayers` directly through a
// minimal vm context (just app-core + app-sidebar-focus) because the
// function is pure — no DOM, no host APIs beyond `Array` and
// `Object.prototype`. `_buildLayerPickerEntries` depends on
// `document.createElement` for no method but DOES call
// `_drillDownToSynthetic` / `_drillDownToStitched` which touch the DOM;
// we pin it at the SOURCE level (regex over the file body) instead —
// the behavioural projection is the stitched-pin ordering + separator
// placement + empty-array fall-through, all of which are expressible as
// textual structure in the method body.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadModules, host } = require('../helpers/load-bundle.js');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const SIDEBAR_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/app-sidebar.js'), 'utf8');
const FOCUS_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/app-sidebar-focus.js'), 'utf8');
const CSS_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/styles/core.css'), 'utf8');

// Minimal vm load: constants (not strictly needed but cheap) + app-core
// (defines App + extendApp) + app-sidebar-focus (installs
// `_getDeepestFinding` and `_flattenFindingLayers` on App.prototype).
// app-sidebar.js is NOT loaded — the methods it defines either require
// DOM or call into other mixins; we only need the focus-file helpers
// here.
const ctx = loadModules([
  'src/constants.js',
  'src/archive-budget.js',
  'src/app/app-core.js',
  'src/app/app-sidebar-focus.js',
], { expose: ['App', 'extendApp'] });
const { App } = ctx;

// ────────────────────────────────────────────────────────────────────────────
// _flattenFindingLayers — behavioural tests
// ────────────────────────────────────────────────────────────────────────────

test('_flattenFindingLayers exists on App.prototype', () => {
  assert.equal(typeof App.prototype._flattenFindingLayers, 'function',
    '_flattenFindingLayers must be defined by app-sidebar-focus.js');
});

test('_flattenFindingLayers returns [] when finding has no innerFindings', () => {
  const app = new App();
  const finding = {
    type: 'encoded-content', severity: 'medium', encoding: 'Base64',
    innerFindings: [],
  };
  const out = app._flattenFindingLayers(finding);
  assert.ok(Array.isArray(out));
  assert.equal(out.length, 0);
});

test('_flattenFindingLayers returns [] for null / missing / malformed input', () => {
  const app = new App();
  assert.deepEqual(host(app._flattenFindingLayers(null)), []);
  assert.deepEqual(host(app._flattenFindingLayers(undefined)), []);
  assert.deepEqual(host(app._flattenFindingLayers({})), []);
  assert.deepEqual(host(app._flattenFindingLayers({ innerFindings: null })), []);
});

test('_flattenFindingLayers walks a linear chain and reports depths 1..N', () => {
  const app = new App();
  // Build a 3-deep chain: root → Base64 → Hex → text.
  const leaf = {
    encoding: 'Hex', classification: { type: 'text' }, severity: 'high',
    decodedBytes: new Uint8Array([1, 2, 3]), decodedSize: 3,
    innerFindings: [],
  };
  const mid = {
    encoding: 'Base64', classification: { type: 'Hex' }, severity: 'medium',
    decodedBytes: new Uint8Array([4, 5]), decodedSize: 2,
    innerFindings: [leaf],
  };
  const root = {
    encoding: 'Outer', classification: { type: 'Base64' }, severity: 'info',
    decodedBytes: new Uint8Array([6]), decodedSize: 1,
    innerFindings: [mid],
  };
  const out = app._flattenFindingLayers(root);
  assert.equal(out.length, 2, 'root is excluded; only descendants emitted');
  assert.equal(out[0].encoding, 'Base64');
  assert.equal(out[0].depth, 1);
  assert.equal(out[1].encoding, 'Hex');
  assert.equal(out[1].depth, 2);
});

test('_flattenFindingLayers preserves detector-emitted sibling order', () => {
  const app = new App();
  // encoded-content-detector.js prepends synthetic XOR first, then
  // synthetic decomp, ahead of recursive children. The helper MUST
  // preserve that order — the menu reads the list verbatim.
  const xorSyn = {
    encoding: 'XOR (key 0x42)', classification: { type: 'text' }, severity: 'high',
    decodedBytes: new Uint8Array([1]), decodedSize: 1, innerFindings: [],
  };
  const decompSyn = {
    encoding: 'gzip', classification: { type: 'PowerShell' }, severity: 'high',
    decodedBytes: new Uint8Array([2]), decodedSize: 1, innerFindings: [],
  };
  const recA = {
    encoding: 'Base64', classification: { type: 'text' }, severity: 'medium',
    decodedBytes: new Uint8Array([3]), decodedSize: 1, innerFindings: [],
  };
  const recB = {
    encoding: 'Hex', classification: { type: 'text' }, severity: 'info',
    decodedBytes: new Uint8Array([4]), decodedSize: 1, innerFindings: [],
  };
  const root = {
    encoding: 'Outer', innerFindings: [xorSyn, decompSyn, recA, recB],
  };
  const out = app._flattenFindingLayers(root);
  assert.equal(out.length, 4);
  assert.deepEqual(
    host(out.map(e => e.encoding)),
    ['XOR (key 0x42)', 'gzip', 'Base64', 'Hex'],
    'sibling order must match detector output — synthetics first, then recursive'
  );
});

test('_flattenFindingLayers filters out stubs (no decodedBytes AND no rawCandidate)', () => {
  const app = new App();
  const depthExceeded = {
    // depth-exceeded stub from encoded-content-detector.js:691
    encoding: 'depth-exceeded', severity: 'info', innerFindings: [],
    // No decodedBytes, no rawCandidate.
  };
  const budgetStub = {
    encoding: 'finder-budget', severity: 'info', innerFindings: [],
  };
  const pickable = {
    encoding: 'Base64', severity: 'medium',
    decodedBytes: new Uint8Array([1]), decodedSize: 1, innerFindings: [],
  };
  const root = {
    encoding: 'Outer',
    innerFindings: [depthExceeded, budgetStub, pickable],
  };
  const out = app._flattenFindingLayers(root);
  assert.equal(out.length, 1, 'stubs must be filtered out');
  assert.equal(out[0].encoding, 'Base64');
});

test('_flattenFindingLayers marks synthetic siblings (XOR + decompression)', () => {
  const app = new App();
  const xorSyn = {
    encoding: 'XOR (key 0x1A)', severity: 'high',
    decodedBytes: new Uint8Array([1]), decodedSize: 1, innerFindings: [],
  };
  const decompSyn = {
    encoding: 'zlib', severity: 'medium',
    decodedBytes: new Uint8Array([2]), decodedSize: 1, innerFindings: [],
  };
  const regular = {
    encoding: 'Base64', severity: 'info',
    decodedBytes: new Uint8Array([3]), decodedSize: 1, innerFindings: [],
  };
  const root = { encoding: 'Outer', innerFindings: [xorSyn, decompSyn, regular] };
  const out = app._flattenFindingLayers(root);
  assert.equal(out[0].isSynthetic, true, 'XOR is synthetic');
  assert.equal(out[1].isSynthetic, true, 'zlib/gzip/deflate/brotli are synthetic');
  assert.equal(out[2].isSynthetic, false, 'plain Base64 is NOT synthetic');
});

test('_flattenFindingLayers emits needsLazyDecode for raw-candidate-only nodes', () => {
  const app = new App();
  const lazy = {
    encoding: 'Base64', severity: 'medium',
    rawCandidate: 'SGVsbG8=',                   // no decodedBytes yet
    innerFindings: [],
  };
  const root = { encoding: 'Outer', innerFindings: [lazy] };
  const out = app._flattenFindingLayers(root);
  assert.equal(out.length, 1);
  assert.equal(out[0].needsLazyDecode, true);
  assert.equal(out[0].decodedSize, 0);
});

test('_flattenFindingLayers caps recursion at depth 20', () => {
  const app = new App();
  // Build a pathological 30-deep linear chain; the helper must stop at 20.
  let leaf = null;
  for (let i = 30; i >= 1; i--) {
    leaf = {
      encoding: `L${i}`, severity: 'info',
      decodedBytes: new Uint8Array([i & 0xff]), decodedSize: 1,
      innerFindings: leaf ? [leaf] : [],
    };
  }
  const root = { encoding: 'Root', innerFindings: [leaf] };
  const out = app._flattenFindingLayers(root);
  // Exact count depends on when the depth cap kicks in. The guarantee
  // we pin is: the helper terminates and returns fewer entries than the
  // unbounded walk would.
  assert.ok(out.length <= 20, `depth cap must bound output ≤ 20 (got ${out.length})`);
  assert.ok(out.length >= 5, 'must still emit a reasonable prefix of the chain');
});

test('_flattenFindingLayers carries severity through verbatim', () => {
  const app = new App();
  const root = {
    encoding: 'Root',
    innerFindings: [
      { encoding: 'A', severity: 'critical', decodedBytes: new Uint8Array([1]), innerFindings: [] },
      { encoding: 'B', severity: 'high',     decodedBytes: new Uint8Array([1]), innerFindings: [] },
      { encoding: 'C', severity: 'medium',   decodedBytes: new Uint8Array([1]), innerFindings: [] },
      { encoding: 'D', severity: 'info',     decodedBytes: new Uint8Array([1]), innerFindings: [] },
    ],
  };
  const out = app._flattenFindingLayers(root);
  assert.deepEqual(
    host(out.map(e => e.severity)),
    ['critical', 'high', 'medium', 'info']
  );
});

// ────────────────────────────────────────────────────────────────────────────
// _flattenFindingLayers — runaway-tree cap + overflow sentinel
//
// The detector in bruteforce / kitchen-sink mode can produce a tree
// with O(10^5) pickable descendants on benign source-code inputs
// (every short alphanumeric word in the decoded text matches the
// lowered-floor finders, each recursing). Without a hard cap on
// `_flattenFindingLayers` output, the caret menu builds one DOM
// <button> per node and hangs the renderer thread. The cap lives at
// `App.LAYER_PICKER_MAX_ITEMS` (200) and is enforced inside the
// flatten walker; anything beyond the cap is summarised by a single
// trailing { kind: 'overflow' } sentinel.
// ────────────────────────────────────────────────────────────────────────────

test('App.LAYER_PICKER_MAX_ITEMS is defined and reasonable', () => {
  assert.equal(typeof App.LAYER_PICKER_MAX_ITEMS, 'number',
    'App.LAYER_PICKER_MAX_ITEMS must be defined as a tunable static field');
  assert.ok(App.LAYER_PICKER_MAX_ITEMS >= 50,
    'cap must be high enough to not truncate realistic trees');
  assert.ok(App.LAYER_PICKER_MAX_ITEMS <= 1000,
    'cap must be low enough to render instantly');
});

test('_flattenFindingLayers caps wide trees at App.LAYER_PICKER_MAX_ITEMS + overflow sentinel', () => {
  const app = new App();
  // Build a fan-out tree: root has N direct children, each pickable.
  // This is the shape bruteforce mode produces when scanning text
  // with many short candidate substrings.
  const CAP = App.LAYER_PICKER_MAX_ITEMS;
  const FANOUT = CAP + 50;
  const children = [];
  for (let i = 0; i < FANOUT; i++) {
    children.push({
      encoding: `Cand${i}`, severity: 'info',
      decodedBytes: new Uint8Array([i & 0xff]), decodedSize: 1,
      innerFindings: [],
    });
  }
  const root = { encoding: 'Root', innerFindings: children };
  const out = app._flattenFindingLayers(root);
  // Exactly CAP regular entries + 1 overflow sentinel.
  assert.equal(out.length, CAP + 1,
    `must return CAP (${CAP}) entries + 1 overflow sentinel (got ${out.length})`);
  // Last entry is the sentinel.
  const sentinel = out[out.length - 1];
  assert.equal(sentinel.kind, 'overflow',
    'last entry must be an overflow sentinel');
  assert.equal(sentinel.truncatedCount, FANOUT - CAP,
    'truncatedCount must equal pre-cap total minus surfaced count');
  assert.equal(sentinel.totalPickable, FANOUT,
    'totalPickable must equal the full pre-cap pickable count');
  // None of the surfaced entries are overflow sentinels.
  for (let i = 0; i < CAP; i++) {
    assert.notEqual(out[i].kind, 'overflow',
      `entry ${i} must be a real layer, not an overflow sentinel`);
  }
});

test('_flattenFindingLayers does NOT emit overflow sentinel when tree fits within cap', () => {
  const app = new App();
  const children = [];
  for (let i = 0; i < 10; i++) {
    children.push({
      encoding: `Cand${i}`, severity: 'info',
      decodedBytes: new Uint8Array([i & 0xff]), decodedSize: 1,
      innerFindings: [],
    });
  }
  const root = { encoding: 'Root', innerFindings: children };
  const out = app._flattenFindingLayers(root);
  assert.equal(out.length, 10, 'small tree must surface every layer');
  for (const e of out) {
    assert.notEqual(e.kind, 'overflow',
      'no overflow sentinel when tree fits within the cap');
  }
});

test('_flattenFindingLayers counts truncated descendants across recursion (not just direct children)', () => {
  const app = new App();
  // Two-level tree: 50 mid-level nodes, each with CAP/4 children. Total
  // pickable = 50 + 50 * (CAP/4); the cap must trim while still counting
  // every truncated grandchild for the sentinel total.
  const CAP = App.LAYER_PICKER_MAX_ITEMS;
  const PER_BRANCH = Math.floor(CAP / 4);
  const branches = [];
  for (let i = 0; i < 50; i++) {
    const grandchildren = [];
    for (let j = 0; j < PER_BRANCH; j++) {
      grandchildren.push({
        encoding: `G${i}_${j}`, severity: 'info',
        decodedBytes: new Uint8Array([1]), decodedSize: 1, innerFindings: [],
      });
    }
    branches.push({
      encoding: `B${i}`, severity: 'info',
      decodedBytes: new Uint8Array([1]), decodedSize: 1,
      innerFindings: grandchildren,
    });
  }
  const root = { encoding: 'Root', innerFindings: branches };
  const out = app._flattenFindingLayers(root);
  const sentinel = out[out.length - 1];
  assert.equal(sentinel.kind, 'overflow');
  const expectedTotal = 50 + 50 * PER_BRANCH;
  assert.equal(sentinel.totalPickable, expectedTotal,
    `totalPickable must include every pickable descendant across recursion (expected ${expectedTotal})`);
});

// ────────────────────────────────────────────────────────────────────────────
// _buildLayerPickerEntries — overflow sentinel handling
// ────────────────────────────────────────────────────────────────────────────

test('_buildLayerPickerEntries handles trailing overflow sentinel from flatten', () => {
  // Pin that the overflow sentinel emitted by _flattenFindingLayers is
  // detected, pulled out of the layers list, and re-emitted as a
  // distinct kind:'overflow' menu row with a localised label.
  const body = SIDEBAR_SRC.match(/_buildLayerPickerEntries\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body, '_buildLayerPickerEntries body must be locatable');
  const src = body[0];
  assert.match(src, /kind\s*===\s*['"]overflow['"]/,
    'must detect the trailing overflow sentinel');
  assert.match(src, /kind:\s*['"]overflow['"]/,
    'must emit a kind:"overflow" menu row');
  assert.match(src, /truncatedCount/,
    'must surface the truncatedCount in the overflow label');
});

test('_openLayerPickerMenu renders the overflow row as non-clickable', () => {
  const body = SIDEBAR_SRC.match(/_openLayerPickerMenu\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body, '_openLayerPickerMenu body must be locatable');
  const src = body[0];
  assert.match(src, /it\.kind\s*===\s*['"]overflow['"]/,
    'must branch on kind:"overflow"');
  assert.match(src, /tb-menu-item-overflow/,
    'must apply the .tb-menu-item-overflow CSS class to the row');
});

test('_openLayerPickerMenu has a defensive DOM-render cap', () => {
  const body = SIDEBAR_SRC.match(/_openLayerPickerMenu\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body);
  // Pin the belt-and-braces guard so a future bypass of the flatten
  // cap can't synchronously build tens of thousands of buttons.
  assert.match(body[0], /HARD_DOM_CAP|LAYER_PICKER_MAX_ITEMS/,
    'must reference the hard DOM-render cap');
});

test('.tb-menu-item-overflow rule exists in core.css', () => {
  assert.match(CSS_SRC, /\.tb-menu-item-overflow\s*\{/);
});

test('.tb-menu-item-overflow overrides the inherited grid layout with a block stack', () => {
  // The base `.tb-menu--layer .tb-menu-item` rule uses `display: grid`
  // with `grid-template-columns: 18px 1fr auto`. The overflow row's
  // sublabel inherits `white-space: nowrap` from `.tb-menu-sublabel`;
  // in the grid layout the nowrap forces column 3 to claim the full
  // menu width, collapsing the label column to ~0 px and wrapping the
  // label character-by-character via the inherited `word-break:
  // break-word`. The overflow row resets both: `display: block` on
  // the row, plus `white-space: normal` on the sublabel.
  const rule = CSS_SRC.match(/\.tb-menu--layer\s+\.tb-menu-item-overflow\s*\{[^}]*\}/);
  assert.ok(rule, '.tb-menu-item-overflow rule must exist');
  assert.match(rule[0], /display\s*:\s*block/,
    'overflow row must reset display to block (overrides the inherited grid)');
  const subRule = CSS_SRC.match(
    /\.tb-menu--layer\s+\.tb-menu-item-overflow\s+\.tb-menu-sublabel\s*\{[^}]*\}/
  );
  assert.ok(subRule, 'overflow-row sublabel override rule must exist');
  assert.match(subRule[0], /white-space\s*:\s*normal/,
    'overflow-row sublabel must reset white-space to normal so the text wraps');
});

// ────────────────────────────────────────────────────────────────────────────
// _buildLayerPickerEntries — structural source-level pins
// These pin the stitched-first-then-separator-then-layers assembly
// contract by regex-anchoring the method body. The method body runs
// under DOM-requiring code paths (action closures call
// `_drillDownToSynthetic` which builds a Blob + File), so we do NOT
// spin up jsdom here — we just structurally verify the ordering.
// ────────────────────────────────────────────────────────────────────────────

test('_buildLayerPickerEntries is declared in app-sidebar.js', () => {
  assert.match(
    SIDEBAR_SRC,
    /_buildLayerPickerEntries\s*\(\s*finding\s*,\s*findings\s*,\s*fileName\s*\)/,
    '_buildLayerPickerEntries must be a method on the App mixin'
  );
});

test('_buildLayerPickerEntries pins the stitched entry FIRST when present', () => {
  // The stitched entry is pushed BEFORE any layer entries are iterated,
  // so the items array always has it at index 0 when it exists. Anchor
  // the push order to prevent a future refactor reordering without
  // thinking about menu priority.
  const body = SIDEBAR_SRC.match(/_buildLayerPickerEntries\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body, '_buildLayerPickerEntries body must be locatable');
  const src = body[0];
  const stitchedIdx = src.search(/kind:\s*['"]stitched['"]/);
  const layerIdx    = src.search(/kind:\s*['"]layer['"]/);
  assert.ok(stitchedIdx > -1, 'stitched kind must be emitted');
  assert.ok(layerIdx > -1, 'layer kind must be emitted');
  assert.ok(stitchedIdx < layerIdx,
    'stitched entry must be pushed BEFORE layer entries');
});

test('_buildLayerPickerEntries gates stitched on spans.length >= 2', () => {
  assert.match(
    SIDEBAR_SRC,
    /recon\.spans\.length\s*>=\s*2/,
    'stitched entry must require at least two spans (matches reassembler contract)'
  );
});

test('_buildLayerPickerEntries inserts a separator between stitched and layers', () => {
  const body = SIDEBAR_SRC.match(/_buildLayerPickerEntries\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body, '_buildLayerPickerEntries body must be locatable');
  const src = body[0];
  assert.match(src, /kind:\s*['"]sep['"]/,
    'must emit at least one kind:"sep" entry');
  // Separator must be gated on hasStitched AND (layers present OR
  // an overflow sentinel present — the trailing truncation row also
  // benefits from visual separation from the stitched entry).
  assert.match(src, /hasStitched\s*&&\s*\(hasLayerRows\s*\|\|\s*overflow\)|hasStitched\s*&&\s*layers\.length/,
    'separator must be gated on stitched-present and (layer-rows-or-overflow-present)');
});

test('_buildLayerPickerEntries returns { items, hasStitched, hasLayers }', () => {
  const body = SIDEBAR_SRC.match(/_buildLayerPickerEntries\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body);
  // Return shape includes items + hasStitched + hasLayers (and may
  // include an optional `overflow` sentinel — added when the flatten
  // cap truncated the tree). Match permissively so adding optional
  // fields doesn't break this pin.
  assert.match(
    body[0],
    /return\s*\{\s*items\s*,\s*hasStitched\s*,\s*hasLayers\b/,
    'return shape must include items + hasStitched + hasLayers (overflow optional)'
  );
});

// ────────────────────────────────────────────────────────────────────────────
// Menu primitive — structural pins for the toolbar-style dismissal pattern
// ────────────────────────────────────────────────────────────────────────────

test('_openLayerPickerMenu uses the toolbar mousedown + Escape dismissal pattern', () => {
  // Same contract the #btn-open / #btn-export menus use in app-ui.js.
  // Pin the two listeners so a future refactor can't silently drop
  // outside-click dismissal.
  const body = SIDEBAR_SRC.match(/_openLayerPickerMenu\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body, '_openLayerPickerMenu body must be locatable');
  assert.match(body[0], /addEventListener\(\s*['"]mousedown['"]/);
  assert.match(body[0], /addEventListener\(\s*['"]keydown['"]/);
  assert.match(body[0], /['"]Escape['"]/);
});

test('_openLayerPickerMenu handles arrow-key navigation', () => {
  const body = SIDEBAR_SRC.match(/_openLayerPickerMenu\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body);
  // Down / Up / Home / End are the a11y-baseline set for a single-
  // column menu. Pin them so the helper doesn't regress on keyboard
  // users.
  assert.match(body[0], /['"]ArrowDown['"]/);
  assert.match(body[0], /['"]ArrowUp['"]/);
  assert.match(body[0], /['"]Home['"]/);
  assert.match(body[0], /['"]End['"]/);
});

test('_openLayerPickerMenu sets aria-haspopup-equivalent aria-expanded on trigger', () => {
  const body = SIDEBAR_SRC.match(/_openLayerPickerMenu\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body);
  assert.match(body[0], /aria-expanded['"]\s*,\s*['"]true['"]/,
    'opening the menu must flip aria-expanded to "true" on the anchor');
});

test('caret button carries aria-haspopup="menu" + aria-expanded="false" on mount', () => {
  // The caret button wiring lives inside _renderEncodedContentSection
  // (line ~2090+). Anchor the aria attrs so keyboard / AT users get a
  // proper hint that the button opens a menu.
  assert.match(SIDEBAR_SRC, /aria-haspopup['"]\s*,\s*['"]menu['"]/);
  assert.match(SIDEBAR_SRC, /aria-expanded['"]\s*,\s*['"]false['"]/);
});

// ────────────────────────────────────────────────────────────────────────────
// _flattenFindingLayers — focus-file source-level pins
// ────────────────────────────────────────────────────────────────────────────

test('_flattenFindingLayers declared in app-sidebar-focus.js', () => {
  assert.match(FOCUS_SRC, /_flattenFindingLayers\s*\(\s*finding\s*\)/);
});

test('_flattenFindingLayers co-located with _getDeepestFinding', () => {
  // Co-location is deliberate — they're sibling tree-walkers and
  // future authors should find them together.
  const deepIdx = FOCUS_SRC.indexOf('_getDeepestFinding(');
  const flatIdx = FOCUS_SRC.indexOf('_flattenFindingLayers(');
  assert.ok(deepIdx > -1 && flatIdx > -1);
  // Within 3 KB of each other (arbitrary but tight enough to guard
  // against them being split into different files without an AGENTS
  // update).
  assert.ok(Math.abs(flatIdx - deepIdx) < 3000,
    'helpers must be co-located in the same source region');
});

// ────────────────────────────────────────────────────────────────────────────
// Removal pins — "All the way" button must be gone
// ────────────────────────────────────────────────────────────────────────────

test('enc-btn-alltheway class is gone from app-sidebar.js (button replaced by caret menu)', () => {
  // The old button's class identifier is the most reliable removal
  // marker — if any future re-introduction sneaks in, the regression
  // surfaces here. Historical mentions inside block comments are
  // permitted; pattern guards against active DOM creation.
  assert.doesNotMatch(
    SIDEBAR_SRC,
    /className\s*=\s*['"][^'"]*enc-btn-alltheway/,
    'enc-btn-alltheway must not be assigned as a className anywhere'
  );
});

test('atwBtn identifier is gone from app-sidebar.js', () => {
  assert.doesNotMatch(
    SIDEBAR_SRC,
    /\batwBtn\b/,
    'the atwBtn variable must be fully removed'
  );
});

test('enc-btn-alltheway + enc-btn-primary CSS selectors are removed', () => {
  assert.doesNotMatch(
    CSS_SRC,
    /\.enc-btn-alltheway\s*[,{]/,
    '.enc-btn-alltheway must be removed from core.css'
  );
  assert.doesNotMatch(
    CSS_SRC,
    /\.enc-btn-primary\s*[,{]/,
    '.enc-btn-primary (the only consumer was .enc-btn-alltheway) must be removed'
  );
});

test('new .enc-btn-caret + .tb-menu--layer rules exist in core.css', () => {
  assert.match(CSS_SRC, /\.enc-btn-caret\s*\{/);
  assert.match(CSS_SRC, /\.tb-menu--layer\s*\{/);
  assert.match(CSS_SRC, /\.tb-menu-sep\s*\{/);
});
