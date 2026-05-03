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
  'PHP preg_replace /e modifier',
  'PHP Superglobal Callable',
  'PHP eval/system on Superglobal',
  'PHP data:/php:// stream wrapper include',
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
  ];
}

module.exports = { generatePhpSeeds, PHP_TECHNIQUE_CATALOG };
