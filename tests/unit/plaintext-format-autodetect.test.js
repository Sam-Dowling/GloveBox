'use strict';
// ════════════════════════════════════════════════════════════════════════════
// plaintext-format-autodetect.test.js — the Format button must appear on
// pasted / extensionless content via hljs auto-detection.
//
// `PlainTextRenderer.render()` builds the Format button hidden whenever
// the extension/MIME fast path fails to identify a language. The
// `_buildTextPane` method then runs `hljs.highlightAuto()` (which it
// already runs to drive highlighting on unknown files) and — if the
// auto-detected language is in `PlainTextRenderer._FORMATTABLE_LANGS`
// and scores ≥ `PlainTextRenderer._AUTO_DETECT_MIN_RELEVANCE` — calls
// `_revealFormatButton` to un-hide the UI.
//
// This test covers the *detection primitives*, not the DOM plumbing
// (which would require a full document stub, VirtualTextView, etc.).
// Specifically:
//
//   1. `PlainTextRenderer._FORMATTABLE_LANGS` contains the languages
//      we claim to format (powershell, bash, dos, xml, and the brace-
//      family members) and every member is accepted by
//      `CodeFormatter.format()` (i.e. produces a string on valid input).
//
//   2. Every `_FORMATTABLE_LANGS` member is registered with the vendored
//      `hljs` bundle — otherwise `highlightAuto()` could never return it,
//      making the reveal path unreachable.
//
//   3. `hljs.highlightAuto()` on the user-reported PowerShell paste —
//      `$chars = @(…); $url = -join (…); Start-Process $url` —
//      returns `language === 'powershell'` (or at least a member of
//      `_FORMATTABLE_LANGS`) with relevance ≥ `_AUTO_DETECT_MIN_RELEVANCE`.
//      Without this, the issue the user reported would still reproduce.
//
//   4. `hljs.highlightAuto()` on short bash / javascript / xml snippets
//      produces formattable-lang results at sufficient relevance —
//      representative regression coverage.
//
//   5. `hljs.highlightAuto()` on English prose returns a non-formattable
//      lang OR a relevance below the floor — the reveal path rejects.
//
// Load strategy: vendored `hljs` bundle via `require()` (it exposes
// `module.exports = hljs` under CommonJS). `PlainTextRenderer` +
// `CodeFormatter` via the shared `load-bundle.js` harness.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { loadModules, REPO_ROOT } = require('../helpers/load-bundle.js');

// Vendored hljs bundle — pure CommonJS export, no DOM required.
const HLJS_PATH = path.join(REPO_ROOT, 'vendor', 'highlight.min.js');
const hljs = require(HLJS_PATH);

const sandbox = loadModules(
  ['src/constants.js', 'src/code-formatter.js', 'src/renderers/plaintext-renderer.js'],
  { expose: ['PlainTextRenderer', 'CodeFormatter', 'RENDER_LIMITS'] },
);
const { PlainTextRenderer, CodeFormatter } = sandbox;

// ─── 1. Parity: every _FORMATTABLE_LANGS entry is format()-accepted ────────

test('every _FORMATTABLE_LANGS entry survives CodeFormatter.format()', () => {
  // Tiny, syntactically valid sample for each lang. We don't assert the
  // output shape (format output varies by lang) — only that the
  // formatter returns a non-empty string and doesn't throw.
  const samples = {
    'javascript': 'var x = 1;',
    'typescript': 'const x: number = 1;',
    'json':       '{"a": 1}',
    'css':        'body { color: red; }',
    'scss':       '.a { .b { color: red; } }',
    'less':       '.a { .b { color: red; } }',
    'c':          'int main(){return 0;}',
    'cpp':        'int main(){return 0;}',
    'csharp':     'class C { }',
    'java':       'class C { }',
    'go':         'package main\nfunc main(){}',
    'rust':       'fn main(){}',
    'swift':      'func main(){}',
    'kotlin':     'fun main(){}',
    'php':        '<?php echo 1; ?>',
    'xml':        '<a><b/></a>',
    'powershell': '$x = 1\nWrite-Host $x',
    'bash':       'x=1\necho $x',
    'dos':        '@echo off\nset X=1',
  };

  for (const lang of PlainTextRenderer._FORMATTABLE_LANGS) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(samples, lang),
      `_FORMATTABLE_LANGS contains "${lang}" but this test has no sample for it — ` +
      `add one to the \`samples\` map above or remove the language from _FORMATTABLE_LANGS.`,
    );
    const src = samples[lang];
    const out = CodeFormatter.format(src, lang);
    assert.equal(typeof out, 'string', `format("${lang}") returned non-string`);
    assert.ok(out.length > 0, `format("${lang}") returned empty string`);
  }
});

// ─── 2. Parity: every _FORMATTABLE_LANGS entry is registered with hljs ────

test('every _FORMATTABLE_LANGS entry is a registered hljs grammar', () => {
  const registered = new Set(hljs.listLanguages());
  for (const lang of PlainTextRenderer._FORMATTABLE_LANGS) {
    assert.ok(
      registered.has(lang),
      `_FORMATTABLE_LANGS contains "${lang}" but the vendored hljs bundle does ` +
      `not register it. Either drop the entry from _FORMATTABLE_LANGS or add ` +
      `the grammar to vendor/highlight.min.js (per the tail-IIFE pattern — ` +
      `see highlight-bundle.test.js).`,
    );
  }
});

// ─── 3. AUTO_DETECT_MIN_RELEVANCE is a sane non-zero integer ───────────────

test('_AUTO_DETECT_MIN_RELEVANCE is a positive integer', () => {
  const rel = PlainTextRenderer._AUTO_DETECT_MIN_RELEVANCE;
  assert.equal(typeof rel, 'number');
  assert.ok(Number.isInteger(rel), '_AUTO_DETECT_MIN_RELEVANCE should be an integer');
  assert.ok(rel > 0, '_AUTO_DETECT_MIN_RELEVANCE should be > 0');
  assert.ok(rel <= 20, '_AUTO_DETECT_MIN_RELEVANCE should be ≤ 20 (hljs relevance rarely exceeds this)');
});

// ─── 4. User-reported PowerShell paste auto-detects to a formattable lang ──

test('hljs auto-detects the user-reported PowerShell paste as a formattable lang', () => {
  // Verbatim from the user issue:
  //   "when i paste the following into Loupe, no format button appears"
  const src =
    '$chars = @(104,116,116,112,58,47,47,112,104,105,115,104,105,110,103,46,' +
    '101,120,97,109,112,108,101,46,99,111,109,47,108,111,103,105,110,46,' +
    '104,116,109,108);$url = -join ($chars | ForEach-Object { [char]$_ });' +
    'Start-Process $url\n';

  const result = hljs.highlightAuto(src);
  assert.ok(result && result.language, `hljs.highlightAuto() returned no language for the snippet`);
  assert.ok(
    PlainTextRenderer._FORMATTABLE_LANGS.has(result.language),
    `auto-detected "${result.language}" is not in _FORMATTABLE_LANGS — ` +
    `the Format button will not appear. Top candidate relevance: ${result.relevance}`,
  );
  assert.ok(
    result.relevance >= PlainTextRenderer._AUTO_DETECT_MIN_RELEVANCE,
    `auto-detected "${result.language}" scored relevance ${result.relevance}, ` +
    `below the floor ${PlainTextRenderer._AUTO_DETECT_MIN_RELEVANCE}`,
  );
});

// ─── 5. Representative regression coverage for other shells ─────────────────

test('hljs auto-detects a bash snippet at sufficient relevance', () => {
  const src = '#!/usr/bin/env bash\nset -euo pipefail\nfor i in 1 2 3; do echo $i; done\n';
  const result = hljs.highlightAuto(src);
  assert.ok(result && result.language);
  assert.ok(
    PlainTextRenderer._FORMATTABLE_LANGS.has(result.language),
    `bash snippet auto-detected as "${result.language}" — not formattable`,
  );
  assert.ok(result.relevance >= PlainTextRenderer._AUTO_DETECT_MIN_RELEVANCE);
});

test('hljs auto-detects a JavaScript snippet at sufficient relevance', () => {
  const src = 'function add(a, b) { return a + b; }\nconst x = add(1, 2);\nconsole.log(x);\n';
  const result = hljs.highlightAuto(src);
  assert.ok(result && result.language);
  assert.ok(
    PlainTextRenderer._FORMATTABLE_LANGS.has(result.language),
    `JS snippet auto-detected as "${result.language}" — not formattable`,
  );
  assert.ok(result.relevance >= PlainTextRenderer._AUTO_DETECT_MIN_RELEVANCE);
});

test('hljs auto-detects an XML snippet at sufficient relevance', () => {
  const src = '<?xml version="1.0"?>\n<root>\n  <child attr="value">text</child>\n</root>\n';
  const result = hljs.highlightAuto(src);
  assert.ok(result && result.language);
  assert.ok(
    PlainTextRenderer._FORMATTABLE_LANGS.has(result.language),
    `XML snippet auto-detected as "${result.language}" — not formattable`,
  );
  assert.ok(result.relevance >= PlainTextRenderer._AUTO_DETECT_MIN_RELEVANCE);
});

// ─── 6. Negative case: prose must NOT trigger the reveal ────────────────────

test('prose text does not cross the auto-detect reveal threshold', () => {
  // Mundane English — no punctuation patterns that any hljs grammar
  // would score highly on. If this ever starts returning a formattable
  // language above the floor, the floor is too low.
  const src =
    'The quick brown fox jumps over the lazy dog. ' +
    'Alice sent a letter to Bob yesterday morning. ' +
    'We drove home after watching the movie. ' +
    'It was raining heavily in the valley. ' +
    'She read the book twice before giving it back.';

  const result = hljs.highlightAuto(src);
  // Either (a) no language at all, (b) not formattable, or (c) relevance
  // below the floor. Any of those means `_buildTextPane` will NOT call
  // `_revealFormatButton` — the button stays hidden. Pass if any of the
  // three holds.
  const autoLang = result && result.language;
  const autoRel  = (result && typeof result.relevance === 'number') ? result.relevance : 0;
  const wouldReveal = !!autoLang
    && PlainTextRenderer._FORMATTABLE_LANGS.has(autoLang)
    && autoRel >= PlainTextRenderer._AUTO_DETECT_MIN_RELEVANCE;
  assert.ok(
    !wouldReveal,
    `Prose text would spuriously reveal Format button: detected "${autoLang}" ` +
    `with relevance ${autoRel}. Consider raising _AUTO_DETECT_MIN_RELEVANCE ` +
    `or pruning _FORMATTABLE_LANGS.`,
  );
});
