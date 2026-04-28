'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-view-mixin-syntax.test.js — backstop for B2 chunk-merger drift.
//
// During the B2 split, `timeline-view.js` was carved into nine
// `Object.assign(TimelineView.prototype, {...})` mixins. The class-
// method → object-literal-shorthand conversion is mechanical
// punctuation: every method body's closing `}` must be followed by
// a `,` separator (or by the closing `});` of the mixin).
//
// A bug in the conversion script emitted bare `}` (no comma) when a
// method's `}` was followed directly by another method signature OR
// by a section comment (`  // ── …`). Twelve occurrences shipped in
// B2d / B2e / B2f1 / B2f3, producing `Uncaught SyntaxError: missing
// } after property list` at browser load time. The build pipeline
// (byte-concatenation + static-HTML checks) does not parse JS; the
// stale `docs/index.test.html` masked it from e2e too.
//
// This test parses each mixin file via Node's `vm.Script` after
// wrapping the body in a stub `(function(TimelineView){…})(class
// TimelineView{});` shim. Any unbalanced punctuation, missing
// comma, or stray brace inside an `Object.assign(TimelineView.
// prototype, {…})` block becomes a hard test failure.
//
// Adding new `timeline-view-*.js` mixins picks up the check
// automatically — the file list is globbed at test time.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const MIXIN_DIR = path.join(REPO_ROOT, 'src/app/timeline');

// All sibling mixins. `timeline-view.js` itself is the core class
// (not a mixin) and is excluded. `timeline-view-factories.js` uses
// `static` methods on the class, not `Object.assign`, so it is
// excluded too — the syntax shape this test guards is specific to
// the `Object.assign(TimelineView.prototype, {…})` pattern.
const MIXIN_FILES = fs
  .readdirSync(MIXIN_DIR)
  .filter((f) => f.startsWith('timeline-view-') && f.endsWith('.js'))
  .filter((f) => f !== 'timeline-view-factories.js')
  .sort();

test('every B2 mixin file is in the discovery list', () => {
  // If a future commit adds a new `timeline-view-*.js` mixin, it
  // gets picked up automatically — but if the directory is empty
  // we want a hard failure rather than a green vacuous test.
  assert.ok(
    MIXIN_FILES.length >= 8,
    `expected ≥ 8 timeline-view-*.js mixins, found ${MIXIN_FILES.length}`,
  );
});

for (const filename of MIXIN_FILES) {
  test(`${filename} parses as valid JavaScript`, () => {
    const src = fs.readFileSync(path.join(MIXIN_DIR, filename), 'utf8');

    // Wrap in a stub that supplies a `TimelineView` global so the
    // file's top-level `Object.assign(TimelineView.prototype, …)`
    // call has a target to attach to. We never EXECUTE the script
    // (which would require the full app's global soup); we only
    // ask `vm.Script` to PARSE it, which is sufficient to surface
    // missing-comma / unbalanced-brace defects.
    const wrapped = `
      (function(TimelineView){
        ${src}
      })(class TimelineView{});
    `;

    assert.doesNotThrow(
      () => new vm.Script(wrapped, { filename }),
      (err) => {
        // Re-throw with the original mixin filename + line
        // pointer (the wrapper adds a few lines of offset, but
        // V8's error message still names the offending token).
        throw new Error(
          `${filename} failed to parse — ${err.message}\n` +
          `(this usually means a method body's closing \`}\` is ` +
          `missing the trailing \`,\` separator required by ` +
          `Object.assign object-literal syntax)`,
        );
      },
    );
  });
}

test('Object.assign mixin blocks have matching property commas', () => {
  // Belt-and-braces structural check: scan every mixin file for
  // the `\n  }\n` pattern (bare two-space-indented closing brace,
  // no trailing comma). The ONLY legitimate occurrence is the
  // last property before the mixin's closing `});`. Anywhere else
  // is a missing-comma bug.
  for (const filename of MIXIN_FILES) {
    const src = fs.readFileSync(path.join(MIXIN_DIR, filename), 'utf8');
    const lines = src.split('\n');
    const offenders = [];
    for (let i = 0; i < lines.length; i++) {
      if (lines[i] !== '  }') continue;
      const next = (lines[i + 1] || '').trim();
      // Acceptable: end-of-mixin closer, or a blank line preceding
      // the closer (matches the formatting some mixins use). Any
      // other follower indicates a missing comma.
      if (next === '});' || next === '') continue;
      offenders.push(i + 1);
    }
    assert.deepEqual(
      offenders,
      [],
      `${filename}: bare \`  }\` (no trailing comma) at line(s) ` +
      `${offenders.join(', ')} — expected \`  },\` because the ` +
      `next non-blank line is another property or comment, not ` +
      `the mixin's closing \`});\``,
    );
  }
});
