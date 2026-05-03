'use strict';
// ════════════════════════════════════════════════════════════════════════════
// highlight-bundle.test.js — Parity gate for highlight.js vendored bundle.
//
// `PlainTextRenderer.LANG_MAP` / `PlainTextRenderer.MIME_TO_LANG` promise
// the user a detected language for a file extension or MIME type. If the
// grammar behind that promise is not registered with `hljs`, the
// renderer silently falls back to auto-detect + plain text and the info
// bar lies about the detected language. That exact class of drift
// shipped undetected for a while — the vendored "Common" bundle didn't
// register `powershell`, `dos`, or `vbscript` despite every .ps1/.bat/.vbs
// extension mapping to them. The fix vendored upstream per-language
// IIFEs onto the tail of `vendor/highlight.min.js`; this test is the
// drift-guard that prevents the same footgun from recurring the next
// time we bump the bundle.
//
// The test asserts three properties:
//
//   1. The vendored bundle registers every grammar referenced by
//      `PlainTextRenderer.LANG_MAP` (extension lookups).
//   2. The vendored bundle registers every grammar referenced by
//      `PlainTextRenderer.MIME_TO_LANG` (MIME fallback).
//   3. A curated floor of Windows-scripting / DevOps grammars is
//      present — a positive acceptance check so a future bundle that
//      shed languages (say, dropped `powershell`) fails loudly even if
//      someone "fixed" the symptom by removing the LANG_MAP row.
//
// Load strategy: `vendor/highlight.min.js` exposes `module.exports=hljs`
// when run under CommonJS, so we `require()` it directly — no DOM, no
// shim-heavy vm context. PlainTextRenderer is loaded through the shared
// `load-bundle.js` harness because it depends on RENDER_LIMITS from
// `src/constants.js` at class-body evaluation time.
// ════════════════════════════════════════════════════════════════════════════
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { loadModules, REPO_ROOT } = require('../helpers/load-bundle.js');

// Load the vendored hljs bundle directly. The bundle ends with a
// `module.exports=hljs` assignment guarded by a typeof-check, so a
// plain `require()` gives us the singleton.
const HLJS_PATH = path.join(REPO_ROOT, 'vendor', 'highlight.min.js');
const hljs = require(HLJS_PATH);

// Load PlainTextRenderer via the shared harness. `RENDER_LIMITS` comes
// from constants.js; PlainTextRenderer's `static MAX_LINES =
// RENDER_LIMITS.MAX_TEXT_LINES;` runs at class-body time and would
// throw otherwise. `VirtualTextView`, `safeStorage`, `lfNormalize`,
// `hljs`, `document` are method-body references only — never touched
// during class initialisation — so we don't need to stub them.
const sandbox = loadModules(
  ['src/constants.js', 'src/renderers/plaintext-renderer.js'],
  { expose: ['PlainTextRenderer', 'RENDER_LIMITS'] },
);
const { PlainTextRenderer } = sandbox;

const REGISTERED = new Set(hljs.listLanguages());

// Canonical floor — these eight grammars were the motivating cases for
// adding this test. Check them explicitly so a future bundle swap that
// sheds any of them fails with a clear reason.
const REQUIRED_GRAMMARS = [
  'powershell',  // .ps1 / .psm1 / .psd1 (Windows scripting)
  'dos',         // .bat / .cmd          (Windows scripting)
  'vbscript',    // .vbs / .vbe          (Windows scripting)
  'dockerfile',  // Dockerfile / Containerfile
  'nginx',       // nginx.conf
  'apache',      // httpd.conf / .htaccess
  'x86asm',      // .asm / .S / .nasm
  'properties',  // .properties          (Java)
];

test('highlight.js bundle registers every canonical required grammar', () => {
  for (const name of REQUIRED_GRAMMARS) {
    assert.ok(
      REGISTERED.has(name),
      `vendor/highlight.min.js is missing grammar "${name}". ` +
      `Appended per-language IIFEs must survive any bundle refresh — ` +
      `see VENDORED.md + CONTRIBUTING.md for the refresh recipe.`,
    );
  }
});

test('every value in PlainTextRenderer.LANG_MAP is registered by hljs', () => {
  const langMap = PlainTextRenderer.LANG_MAP;
  const missing = [];
  for (const [ext, lang] of Object.entries(langMap)) {
    if (!REGISTERED.has(lang)) {
      missing.push(`  .${ext} → "${lang}"`);
    }
  }
  assert.equal(
    missing.length,
    0,
    `LANG_MAP references ${missing.length} language(s) not registered by hljs:\n` +
    missing.join('\n') +
    `\n\nEither add the grammar to vendor/highlight.min.js (see the ` +
    `per-language IIFE append recipe in VENDORED.md) or point the ` +
    `mapping at a registered grammar.`,
  );
});

test('every value in PlainTextRenderer.MIME_TO_LANG is registered by hljs', () => {
  const mimeMap = PlainTextRenderer.MIME_TO_LANG;
  const missing = [];
  for (const [mime, lang] of Object.entries(mimeMap)) {
    if (!REGISTERED.has(lang)) {
      missing.push(`  ${mime} → "${lang}"`);
    }
  }
  assert.equal(
    missing.length,
    0,
    `MIME_TO_LANG references ${missing.length} language(s) not registered by hljs:\n` +
    missing.join('\n'),
  );
});

test('hljs.listLanguages() reports a sane grammar count', () => {
  // Not an equality check (we don't want the test to fail every time
  // someone ADDS a grammar legitimately), just a sanity floor that
  // catches the "bundle accidentally replaced with the 10-language core"
  // regression. v11.9.0 common bundle is 36; our appended 8 makes 44.
  assert.ok(
    REGISTERED.size >= 40,
    `Expected >= 40 registered grammars, got ${REGISTERED.size}. ` +
    `Suspected truncation of vendor/highlight.min.js.`,
  );
});
