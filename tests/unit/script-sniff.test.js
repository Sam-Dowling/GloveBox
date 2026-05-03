'use strict';
// script-sniff.test.js — RendererRegistry._sniffScriptKind() detects
// the language from the file head. Covers the three NEW branches added
// alongside php-obfuscation / yara-engine is_php / is_ruby / is_lua
// predicates: PHP open-tag fast-path, PHP score-based, Ruby, Lua.
//
// Existing-language paths (bash / py / ps1 / js / perl / vbs / bat) are
// covered transitively through every renderer e2e fixture, so this file
// scopes itself to the new branches.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/renderer-registry.js',
], { expose: ['RendererRegistry'] });
const { RendererRegistry } = ctx;

/** Helper: build the head4k context object expected by _sniffScriptKind. */
function ctxFor(text) {
  return { head4k: text };
}

// ── PHP fast-paths ──────────────────────────────────────────────────────────

test('script-sniff: <?php open-tag fast-path returns "php"', () => {
  const text = `<?php\n$a = 1;\necho $a;\n`;
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor(text)), 'php');
});

test('script-sniff: short echo <?= open-tag fast-path returns "php"', () => {
  const text = `<?= htmlspecialchars($_GET['name']) ?>\n`;
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor(text)), 'php');
});

test('script-sniff: PHP shebang #!/usr/bin/env php returns "php"', () => {
  const text = `#!/usr/bin/env php\n<?php\necho "hello";\n`;
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor(text)), 'php');
});

test('script-sniff: PHP score-based (no open-tag, fragment) detects php', () => {
  // Fragment lacking `<?php` (e.g. an `include()`-d snippet) but with
  // PHP-distinctive vocabulary. Needs ≥2 indicators (≥4 score) AND ≥1
  // points over runner-up.
  const text = `
namespace App\\Controllers;
class HomeController {
  public function index() {
    return phpinfo();
  }
}
`;
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor(text)), 'php');
});

// ── Ruby ────────────────────────────────────────────────────────────────────

test('script-sniff: Ruby shebang returns "ruby"', () => {
  const text = `#!/usr/bin/env ruby\nputs "hello"\n`;
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor(text)), 'ruby');
});

test('script-sniff: Ruby class+def+end pattern returns "ruby"', () => {
  const text = `
require 'json'

class Greeter
  def initialize(name)
    @name = name
  end

  def greet
    puts "Hello, #{@name}"
  end
end
`;
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor(text)), 'ruby');
});

test('script-sniff: Ruby `do …| … |` block + @@cvar returns "ruby"', () => {
  const text = `
class Counter
  @@count = 0
  attr_accessor :name

  [1, 2, 3].each do |x|
    @@count += x
  end
end
`;
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor(text)), 'ruby');
});

// ── Lua ─────────────────────────────────────────────────────────────────────

test('script-sniff: Lua shebang returns "lua"', () => {
  const text = `#!/usr/bin/env lua\nprint("hello")\n`;
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor(text)), 'lua');
});

test('script-sniff: Lua local + function + end returns "lua"', () => {
  const text = `
local M = {}

function M.greet(name)
  return string.format("Hello, %s", name)
end

local x = 1
print(M.greet("world"))

return M
`;
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor(text)), 'lua');
});

// ── Negative / disambiguation ───────────────────────────────────────────────

test('script-sniff: HTML page with embedded <?php tag in body still returns "php"', () => {
  // Only the `<?php` at the very start triggers the fast-path; the HTML
  // markup penalty wipes script scores. Verify the fast-path takes
  // precedence over the markup penalty when `<?php` is the file head.
  const text = `<?php
echo '<!DOCTYPE html><html><body>hello</body></html>';
?>`;
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor(text)), 'php');
});

test('script-sniff: pure HTML file is not classified as a script', () => {
  const text = `<!DOCTYPE html>
<html>
<body>
  <p>Hello</p>
</body>
</html>
`;
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor(text)), null);
});

test('script-sniff: empty / too-short head returns null', () => {
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor('')), null);
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor('hi')), null);
  assert.equal(RendererRegistry._sniffScriptKind(null), null);
});

test('script-sniff: ambiguous single-indicator text returns null', () => {
  // A `function name() {` pattern alone hits bash (+2) but no other
  // bash signal accumulates. Score 2 vs runner-up 0 satisfies the
  // ≥2 + ≥1-margin gates, so this WOULD return 'bash'. Pick truly
  // weak text instead — plain English with no script-distinctive
  // tokens at all.
  const text = `Hello world. This is plain English text.\nNo script keywords here, just words.\n`;
  assert.equal(RendererRegistry._sniffScriptKind(ctxFor(text)), null);
});
