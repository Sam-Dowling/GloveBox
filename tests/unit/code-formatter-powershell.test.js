'use strict';
// ════════════════════════════════════════════════════════════════════════════
// code-formatter-powershell.test.js — structural pass for PowerShell.
//
// Before this pass existed, `CodeFormatter.format(src, 'powershell')` only
// rewrote leading whitespace per line based on `{` / `}` depth. Pasting a
// semicolon-joined one-liner (the common obfuscated-PowerShell malware
// shape) produced an output byte-identical to the input — so the user
// clicked the Format button and nothing visible changed. These tests pin
// the new behaviour: split top-level `;` statements (outside strings /
// comments / here-strings / `$(…)` sub-expressions / `for (;;)` parens),
// indent `{` / `}` blocks by 2 spaces, and hard-fail CLOSED (return the
// input verbatim) on any anomaly.
//
// See `src/code-formatter.js` header comment for the full contract.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');

const { loadModules } = require('../helpers/load-bundle.js');

const sandbox = loadModules(
  ['src/constants.js', 'src/code-formatter.js'],
  { expose: ['CodeFormatter'] },
);
const { CodeFormatter } = sandbox;

// Convenience: assert that every string in `expectedLines` occurs on its
// own line in the formatter output. Looser than a full `===` match so
// small tweaks to the brace/paren layout rules don't churn every test.
function assertLines(out, expectedLines, msg) {
  const lines = out.split('\n');
  for (const expected of expectedLines) {
    assert.ok(
      lines.includes(expected),
      `${msg || 'output'} missing expected line: ${JSON.stringify(expected)}\n` +
      `full output:\n${out}`,
    );
  }
}

// ─── The user-reported paste: `;`-joined one-liner. ───────────────────────

test('user-reported paste: semicolon-joined one-liner splits across lines', () => {
  const src =
    '$mqd6a = @(104,116,116,112,58,47,47,112,104,105,115,104,105,110,103,46,' +
    '101,120,97,109,112,108,101,46,99,111,109,47,108,111,103,105,110,46,' +
    '104,116,109,108);$Zb5a8vyy = -join ($mqd6a | ForEach-Object ' +
    '{ [char]$_ });Start-Process $Zb5a8vyy';

  const out = CodeFormatter.format(src, 'powershell');
  assert.notEqual(out, src,
    'formatter produced a byte-identical output — the Format button would ' +
    'appear to do nothing (this is the exact UX regression this test guards).');

  // Three top-level statements — each must land on its own line.
  // The $mqd6a assignment is one full line terminated by `;`.
  const lines = out.split('\n');
  assert.ok(
    lines.some(l => l.startsWith('$mqd6a = @(104,116,116')),
    'first statement (`$mqd6a = @(…)`) should start a line',
  );
  assert.ok(
    lines.some(l => l.startsWith('$Zb5a8vyy = -join ')),
    'second statement (`$Zb5a8vyy = -join …`) should start a line',
  );
  assert.ok(
    lines.some(l => l.startsWith('Start-Process $Zb5a8vyy')),
    'third statement (`Start-Process $Zb5a8vyy`) should start a line',
  );
});

// ─── Core splitting behaviour. ────────────────────────────────────────────

test('splits trivial ;-joined statements', () => {
  const out = CodeFormatter.format('$x=1;$y=2;Write-Host $x', 'powershell');
  assertLines(out, ['$x=1;', '$y=2;', 'Write-Host $x']);
});

test('no-op on input without ; or {}', () => {
  const src = '$x = 1\nWrite-Host $x';
  const out = CodeFormatter.format(src, 'powershell');
  assert.equal(out, src);
});

test('empty input returns empty string', () => {
  assert.equal(CodeFormatter.format('', 'powershell'), '');
});

// ─── String context — `;` must NOT split inside. ──────────────────────────

test('; inside double-quoted string is not a split point', () => {
  const out = CodeFormatter.format('$a="hello;world";Write-Host $a', 'powershell');
  assertLines(out, ['$a="hello;world";', 'Write-Host $a']);
  // The string literal itself must survive verbatim.
  assert.ok(out.includes('"hello;world"'));
});

test('; inside single-quoted string is not a split point', () => {
  const out = CodeFormatter.format("$a='hello;world';Write-Host $a", 'powershell');
  assertLines(out, ["$a='hello;world';", 'Write-Host $a']);
  assert.ok(out.includes("'hello;world'"));
});

test('backtick-escaped ; inside double-quoted string is preserved', () => {
  // PS backtick-escape: `"a`;b"` is a 3-char string `a;b`.
  const src = '$a = "a`;b";Write-Host $a';
  const out = CodeFormatter.format(src, 'powershell');
  assert.ok(out.includes('"a`;b"'),
    'backtick-escaped `;` inside "…" must not confuse the tokeniser');
  assertLines(out, ['$a = "a`;b";', 'Write-Host $a']);
});

test('; inside $(…) sub-expression (within "…") is not a split point', () => {
  const src = 'Write-Host "$(Get-Date; Get-Host)";$b=2';
  const out = CodeFormatter.format(src, 'powershell');
  assert.ok(out.includes('"$(Get-Date; Get-Host)"'),
    'sub-expression content must survive byte-for-byte');
  assertLines(out, ['Write-Host "$(Get-Date; Get-Host)";', '$b=2']);
});

// ─── Comments. ────────────────────────────────────────────────────────────

test('; inside # line comment is not a split point', () => {
  const src = '# a;b;c\nWrite-Host $x';
  const out = CodeFormatter.format(src, 'powershell');
  assert.equal(out, '# a;b;c\nWrite-Host $x');
});

test('; inside <# … #> block comment is not a split point', () => {
  const src = '<# a;b;c #>;Write-Host $x';
  const out = CodeFormatter.format(src, 'powershell');
  assertLines(out, ['<# a;b;c #>;', 'Write-Host $x']);
  // The block comment body must survive verbatim.
  assert.ok(out.includes('<# a;b;c #>'));
});

// ─── Here-strings — must be emitted byte-for-byte. ────────────────────────

test('here-string @"…"@ is emitted verbatim and ; after it still splits', () => {
  const src = '$a = @"\nhello;world\n"@;Write-Host $a';
  const out = CodeFormatter.format(src, 'powershell');
  assert.ok(out.includes('@"\nhello;world\n"@'),
    'double-quoted here-string body must survive unchanged');
  assertLines(out, ['Write-Host $a']);
});

test('here-string @\'…\'@ is emitted verbatim', () => {
  const src = "$a = @'\nhello;world\n'@;Write-Host $a";
  const out = CodeFormatter.format(src, 'powershell');
  assert.ok(out.includes("@'\nhello;world\n'@"),
    'single-quoted here-string body must survive unchanged');
});

test('unterminated here-string bails closed (returns input verbatim)', () => {
  const src = '$a = @"\nno terminator';
  const out = CodeFormatter.format(src, 'powershell');
  assert.equal(out, src, 'malformed input must round-trip unchanged');
});

// ─── `for (;;)` — semicolons inside parens stay on-line. ──────────────────

test('for (;;) does not split inside the parens', () => {
  const src = 'for ($i=0;$i -lt 5;$i++) { Write-Host $i }';
  const out = CodeFormatter.format(src, 'powershell');
  assert.ok(out.includes('for ($i=0;$i -lt 5;$i++)'),
    '`;` inside `( … )` must never be a split point');
});

// ─── Brace-block indentation. ─────────────────────────────────────────────

test('balanced {} block gets 2-space indent on body', () => {
  const src = 'function Do-Work { Write-Host "hi";$x=1 }';
  const out = CodeFormatter.format(src, 'powershell');
  // Body statements must each appear on their own indented line.
  assertLines(out, ['function Do-Work {', '  Write-Host "hi";', '  $x=1']);
});

test('empty block {} opens and immediately closes', () => {
  const src = 'function f { }';
  const out = CodeFormatter.format(src, 'powershell');
  // Either `{}` or `{\n}` is acceptable; both are valid PS syntax.
  // Just check the function keyword survives and braces are balanced.
  assert.ok(out.includes('function f'));
  const opens = (out.match(/\{/g) || []).length;
  const closes = (out.match(/\}/g) || []).length;
  assert.equal(opens, 1);
  assert.equal(closes, 1);
});

test('unbalanced `}` returns input verbatim (hard-fail closed)', () => {
  const src = 'Write-Host a } Write-Host b';
  const out = CodeFormatter.format(src, 'powershell');
  assert.equal(out, src);
});

test('unbalanced `{` returns input verbatim (hard-fail closed)', () => {
  const src = 'if (x) { Write-Host a';
  const out = CodeFormatter.format(src, 'powershell');
  assert.equal(out, src);
});

// ─── Bailouts: size, amp, depth. ──────────────────────────────────────────

test('over-MAX_INPUT_BYTES input is a no-op', () => {
  const big = '$x=1;'.repeat(CodeFormatter.MAX_INPUT_BYTES / 5 + 2);
  assert.ok(big.length > CodeFormatter.MAX_INPUT_BYTES);
  const out = CodeFormatter.format(big, 'powershell');
  assert.equal(out, big);
});

test('runaway brace depth bails closed', () => {
  // MAX_DEPTH is 256. An input with 300 nested `{` must return verbatim.
  const nest = 300;
  let src = '';
  for (let i = 0; i < nest; i++) src += '{';
  for (let i = 0; i < nest; i++) src += '}';
  const out = CodeFormatter.format(src, 'powershell');
  assert.equal(out, src, 'depth overflow must round-trip unchanged');
});

// ─── Output invariant: every `_FORMATTABLE_LANGS` case still produces a ──
// non-empty string (same contract the format-autodetect test enforces).

test('format() always returns a non-empty string for valid PS input', () => {
  const samples = [
    '$x=1',
    '$x=1;$y=2',
    'function f { }',
    'Get-ChildItem | Where-Object { $_.Length -gt 100 }',
    'if ($true) { Write-Host a } else { Write-Host b }',
  ];
  for (const s of samples) {
    const out = CodeFormatter.format(s, 'powershell');
    assert.equal(typeof out, 'string');
    assert.ok(out.length > 0, `format() returned empty string on: ${JSON.stringify(s)}`);
  }
});
