'use strict';
// code-formatter.test.js — smoke tests for the best-efforts code formatter.
//
// `CodeFormatter.format(text, lang)` is a pure visual-only pretty-printer
// used by `PlainTextRenderer`'s Format toggle. It runs over files that
// already passed the rich-render gate (≤ 1 MB, ≤ 20 000 lines, longest
// line ≤ 10 000 chars) so the test inputs are deliberately small. What
// we guarantee here:
//
//   1. No bracket rewrites on round-trip for a balanced input.
//   2. Minified JS / JSON / CSS split onto multiple lines.
//   3. Strings, comments, and regex literals are not re-formatted.
//   4. Unknown languages → verbatim passthrough.
//   5. Over-budget / unbalanced input → verbatim passthrough (no throw).

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/code-formatter.js',
]);
const { CodeFormatter } = ctx;

test('code-formatter: passthrough on unknown language', () => {
  const src = 'print("hello")\nprint("world")\n';
  assert.equal(CodeFormatter.format(src, 'perl'), src);
});

test('code-formatter: passthrough on empty / non-string', () => {
  assert.equal(CodeFormatter.format('', 'javascript'), '');
  assert.equal(CodeFormatter.format(null, 'javascript'), '');
  assert.equal(CodeFormatter.format(undefined, 'javascript'), '');
});

test('code-formatter: minified JS splits at braces and semicolons', () => {
  const src = 'function f(){var x=1;var y=2;return x+y;}';
  const out = CodeFormatter.format(src, 'javascript');
  // Output should have multiple lines now.
  assert.ok(out.split('\n').length >= 4,
    `expected multi-line output, got:\n${out}`);
  // Structural chars survive.
  assert.ok(out.includes('function f('));
  assert.ok(out.includes('return x+y'));
  assert.ok(out.trim().endsWith('}'));
});

test('code-formatter: minified JSON splits and indents', () => {
  const src = '{"a":1,"b":[1,2,3],"c":{"d":"e"}}';
  const out = CodeFormatter.format(src, 'json');
  const lines = out.split('\n');
  // Expect at least one line per structural element.
  assert.ok(lines.length >= 5, `expected multi-line JSON, got:\n${out}`);
  // Indentation present.
  assert.ok(lines.some(l => l.startsWith('  ')),
    `expected indented lines, got:\n${out}`);
  // Values are preserved (strings intact).
  assert.ok(out.includes('"a"'));
  assert.ok(out.includes('"e"'));
});

test('code-formatter: minified CSS splits rules', () => {
  const src = '.a{color:red;font-size:12px;}.b{margin:0;}';
  const out = CodeFormatter.format(src, 'css');
  assert.ok(out.split('\n').length >= 4,
    `expected multi-line CSS, got:\n${out}`);
  assert.ok(out.includes('color:'));
  assert.ok(out.includes('margin:'));
});

test('code-formatter: preserves string contents (no interior splits)', () => {
  // A string literal containing brace / semicolon characters must not
  // trigger structural newlines inside the quotes.
  const src = 'var s = "{a;b}";';
  const out = CodeFormatter.format(src, 'javascript');
  assert.ok(out.includes('"{a;b}"'),
    `string literal contents must survive verbatim, got:\n${out}`);
});

test('code-formatter: preserves block comments', () => {
  const src = 'function f(){/* keep {me;} intact */return 1;}';
  const out = CodeFormatter.format(src, 'javascript');
  assert.ok(out.includes('/* keep {me;} intact */'),
    `block comment must survive verbatim, got:\n${out}`);
});

test('code-formatter: preserves line comments', () => {
  const src = 'var x = 1; // trailing {} comment\nvar y = 2;';
  const out = CodeFormatter.format(src, 'javascript');
  assert.ok(out.includes('// trailing {} comment'),
    `line comment must survive verbatim, got:\n${out}`);
});

test('code-formatter: preserves regex literal (no interior splits)', () => {
  const src = 'var re = /\\{\\}/; var x = 1;';
  const out = CodeFormatter.format(src, 'javascript');
  assert.ok(out.includes('/\\{\\}/'),
    `regex literal must survive verbatim, got:\n${out}`);
});

test('code-formatter: unbalanced brackets → passthrough', () => {
  // A dangling `{` with no close must not mangle the input — the
  // formatter bails to the original string.
  const src = 'function f() { var x = 1;';
  const out = CodeFormatter.format(src, 'javascript');
  assert.equal(out, src,
    `unbalanced input must passthrough, got:\n${out}`);
});

test('code-formatter: mismatched close → passthrough', () => {
  const src = 'var arr = [1, 2, 3};';
  const out = CodeFormatter.format(src, 'javascript');
  assert.equal(out, src,
    `mismatched close must passthrough, got:\n${out}`);
});

test('code-formatter: input over MAX_INPUT_BYTES → passthrough', () => {
  // 2 MiB + 1 byte input. Must not even start the walk.
  const src = '{'.repeat(CodeFormatter.MAX_INPUT_BYTES + 1);
  const out = CodeFormatter.format(src, 'javascript');
  assert.equal(out, src,
    'over-budget input must passthrough unchanged');
});

test('code-formatter: XML block-tag splitter', () => {
  const src = '<a><b>x</b><c/></a>';
  const out = CodeFormatter.format(src, 'xml');
  const lines = out.split('\n');
  // Each tag on its own line.
  assert.ok(lines.length >= 4,
    `expected tag-per-line output, got:\n${out}`);
  assert.ok(out.includes('<a>'));
  assert.ok(out.includes('</a>'));
  assert.ok(out.includes('<c/>'));
});

test('code-formatter: XML preserves CDATA verbatim', () => {
  const src = '<r><![CDATA[<b>x</b>]]></r>';
  const out = CodeFormatter.format(src, 'xml');
  assert.ok(out.includes('<![CDATA[<b>x</b>]]>'),
    `CDATA must be preserved verbatim, got:\n${out}`);
});

test('code-formatter: PowerShell indent-only preserves content', () => {
  const src = 'if ($x) {\nGet-Foo\nif ($y) {\nGet-Bar\n}\n}\n';
  const out = CodeFormatter.format(src, 'powershell');
  // Content preserved line-by-line (indent only).
  assert.ok(out.includes('Get-Foo'));
  assert.ok(out.includes('Get-Bar'));
  // Nested `Get-Bar` should end up more indented than `Get-Foo`.
  const lines = out.split('\n');
  const fooIndent = lines.find(l => l.includes('Get-Foo')).match(/^ */)[0].length;
  const barIndent = lines.find(l => l.includes('Get-Bar')).match(/^ */)[0].length;
  assert.ok(barIndent > fooIndent,
    `nested line must indent deeper (foo=${fooIndent}, bar=${barIndent})`);
});

test('code-formatter: output is a string (never throws on weird input)', () => {
  // Randomish unicode / control / escape salad — must not throw.
  const src = '\u0000\u0001"{\\"}[\\\\]`//*/';
  const out = CodeFormatter.format(src, 'javascript');
  assert.equal(typeof out, 'string');
});
