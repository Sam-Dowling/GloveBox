'use strict';
// ════════════════════════════════════════════════════════════════════════════
// code-formatter-bash.test.js — structural pass for Bash.
//
// Companion to `code-formatter-powershell.test.js`. Same contract
// (split on top-level `;`, indent by `{` / `}` depth, hard-fail CLOSED
// on anomaly) but with bash-specific lex rules: here-docs, `$(…)` /
// `` `…` `` sub-shells, backslash-escape, and the `foo#bar`-isn't-a-
// comment edge case.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');

const { loadModules } = require('../helpers/load-bundle.js');

const sandbox = loadModules(
  ['src/constants.js', 'src/code-formatter.js'],
  { expose: ['CodeFormatter'] },
);
const { CodeFormatter } = sandbox;

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

// ─── Core splitting. ──────────────────────────────────────────────────────

test('splits trivial ;-joined bash commands', () => {
  const out = CodeFormatter.format('echo a;echo b;echo c', 'bash');
  assertLines(out, ['echo a;', 'echo b;', 'echo c']);
});

test('no-op on input without ; or {}', () => {
  const src = 'echo hi\nls -la';
  const out = CodeFormatter.format(src, 'bash');
  assert.equal(out, src);
});

// ─── String context. ──────────────────────────────────────────────────────

test('; inside "…" is not a split point', () => {
  const out = CodeFormatter.format('echo "a;b;c";echo d', 'bash');
  assertLines(out, ['echo "a;b;c";', 'echo d']);
  assert.ok(out.includes('"a;b;c"'));
});

test("; inside '…' is not a split point", () => {
  const out = CodeFormatter.format("echo 'a;b;c';echo d", 'bash');
  assertLines(out, ["echo 'a;b;c';", 'echo d']);
});

test('\\-escaped char inside "…" is not confused', () => {
  // Bash: `\"` inside "…" is a literal `"` and must not close the string.
  const src = 'echo "a\\"b;c";echo d';
  const out = CodeFormatter.format(src, 'bash');
  assert.ok(out.includes('"a\\"b;c"'),
    'backslash-escape must not close the string prematurely');
});

// ─── Sub-shells. ──────────────────────────────────────────────────────────

test('; inside $(…) is not a split point', () => {
  const out = CodeFormatter.format('X=$(echo a; echo b);echo $X', 'bash');
  assert.ok(out.includes('$(echo a; echo b)'),
    'sub-shell body must survive byte-for-byte');
  assertLines(out, ['X=$(echo a; echo b);', 'echo $X']);
});

test('; inside `…` backtick sub-shell is not a split point', () => {
  const out = CodeFormatter.format('X=`echo a; echo b`;echo $X', 'bash');
  assert.ok(out.includes('`echo a; echo b`'));
  assertLines(out, ['X=`echo a; echo b`;', 'echo $X']);
});

test('(( arithmetic )) shift operator is not mistaken for a here-doc', () => {
  // `$((1 << 2))` — the `<<` here is the arithmetic shift, NOT a here-doc.
  const src = 'x=$((1 << 2));echo $x';
  const out = CodeFormatter.format(src, 'bash');
  assert.ok(out.includes('$((1 << 2))'),
    'arithmetic `<<` inside `$((…))` must not trigger here-doc scan');
  assertLines(out, ['x=$((1 << 2));', 'echo $x']);
});

// ─── Comments. ────────────────────────────────────────────────────────────

test('# line comment swallows ; to EOL', () => {
  const src = '# hi;there\necho ok';
  const out = CodeFormatter.format(src, 'bash');
  assert.equal(out, '# hi;there\necho ok');
});

test('foo#bar (no preceding whitespace) is NOT a comment; trailing ; still splits', () => {
  // Bash: `#` only starts a comment when preceded by whitespace, SOL,
  // or a token separator. `VAR=foo#bar` is a single assignment.
  const out = CodeFormatter.format('VAR=foo#bar;echo done', 'bash');
  assertLines(out, ['VAR=foo#bar;', 'echo done']);
  assert.ok(out.includes('foo#bar'), '`foo#bar` must survive intact');
});

// ─── Here-docs. ───────────────────────────────────────────────────────────

test('here-doc body is emitted byte-for-byte; inner ; does not split', () => {
  const src = 'cat <<EOF\nfoo;bar\nEOF\necho done';
  const out = CodeFormatter.format(src, 'bash');
  assert.ok(out.includes('<<EOF\nfoo;bar\nEOF'),
    'here-doc body must survive unchanged');
  assert.ok(out.includes('echo done'));
});

test("quoted here-doc terminator (<<'EOF') is supported", () => {
  const src = "cat <<'EOF'\nfoo;bar\nEOF\necho done";
  const out = CodeFormatter.format(src, 'bash');
  assert.ok(out.includes("<<'EOF'\nfoo;bar\nEOF"),
    'quoted-terminator here-doc body must survive unchanged');
});

test('<<- tab-stripped here-doc is supported', () => {
  const src = 'cat <<-EOF\n\tfoo;bar\n\tEOF\necho done';
  const out = CodeFormatter.format(src, 'bash');
  assert.ok(out.includes('<<-EOF\n\tfoo;bar\n\tEOF'),
    'tab-indented here-doc terminator must be detected');
});

test('unterminated here-doc falls back to literal `<<` handling (no infinite loop)', () => {
  // If the walker can't find the terminator, `consumeHereDoc` returns
  // null and we fall through to treating `<<` as regular chars.
  const src = 'cat <<EOF\nnever closed';
  const out = CodeFormatter.format(src, 'bash');
  // No assertion about exact output; just guarantee termination and a
  // non-empty string back.
  assert.equal(typeof out, 'string');
  assert.ok(out.length > 0);
});

// ─── `;;` case terminator. ────────────────────────────────────────────────

test(';; case terminator does not produce two splits', () => {
  const src = 'case x in\n  a) echo a;;\n  b) echo b;;\nesac';
  const out = CodeFormatter.format(src, 'bash');
  // `;;` must stay together; no stray `;` on a line by itself.
  assert.ok(out.includes(';;'), '`;;` should remain as a two-char token');
  assert.ok(!/\n;\n/.test(out), 'must not split a `;` out of `;;`');
});

// ─── Line continuation. ───────────────────────────────────────────────────

test('\\-at-EOL line continuation is preserved', () => {
  const src = 'echo hi \\\n&& echo next';
  const out = CodeFormatter.format(src, 'bash');
  assert.ok(out.includes('\\\n'),
    'line-continuation sequence must be preserved verbatim');
});

// ─── Brace blocks. ────────────────────────────────────────────────────────

test('unbalanced `}` returns input verbatim', () => {
  const src = 'echo a } echo b';
  const out = CodeFormatter.format(src, 'bash');
  assert.equal(out, src);
});

// ─── Bailouts. ────────────────────────────────────────────────────────────

test('over-MAX_INPUT_BYTES input is a no-op', () => {
  const big = 'echo a;'.repeat(CodeFormatter.MAX_INPUT_BYTES / 7 + 2);
  assert.ok(big.length > CodeFormatter.MAX_INPUT_BYTES);
  const out = CodeFormatter.format(big, 'bash');
  assert.equal(out, big);
});

test('runaway brace depth bails closed', () => {
  const nest = 300;
  let src = '';
  for (let i = 0; i < nest; i++) src += '{';
  for (let i = 0; i < nest; i++) src += '}';
  const out = CodeFormatter.format(src, 'bash');
  assert.equal(out, src);
});

test('empty input returns empty string', () => {
  assert.equal(CodeFormatter.format('', 'bash'), '');
});
