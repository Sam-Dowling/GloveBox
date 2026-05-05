'use strict';
// php-obfuscation.test.js — PHP webshell / dropper detection &
// deobfuscation. Six branches:
//   PHP1  Webshell decoder onion — eval(gzinflate(base64_decode("…")))
//         + str_rot13 / gzuncompress / gzdecode / hex2bin variants.
//   PHP2  Variable-variables — $a='sys'.'tem'; $$a('id'); / ${'a'.'b'}().
//   PHP3  chr() / pack('H*', '…') reassembly to PHP_DANGEROUS_FNS names.
//   PHP4  preg_replace('/.../e', $code, $subj) deprecated /e modifier.
//   PHP5  Superglobal callable — $_GET[0]($_POST[1]) / eval($_REQUEST[...]).
//   PHP6  data: / php:// stream-wrapper include.

const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/php-obfuscation.js',
]);

// Decompressor stub for PHP1 chain (gzinflate / gzuncompress / gzdecode).
ctx.Decompressor = {
  inflateSync(bytes, format) {
    try {
      const buf = Buffer.from(bytes.buffer || bytes, bytes.byteOffset || 0, bytes.byteLength || bytes.length);
      if (format === 'gzip') return new Uint8Array(zlib.gunzipSync(buf));
      if (format === 'deflate-raw') return new Uint8Array(zlib.inflateRawSync(buf));
      // 'zlib' / 'deflate' default to zlib-wrapped inflate
      return new Uint8Array(zlib.inflateSync(buf));
    } catch (_) { return null; }
  },
};

const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

/** Helper: collect every candidate matching `pred` and project across realms. */
function pick(candidates, pred) {
  return host(candidates.filter(pred));
}

// ── PHP1: webshell decoder onion ────────────────────────────────────────────

test('php-obfuscation: PHP1 eval(base64_decode(…)) bare form decodes', () => {
  // 'system($_GET[0]);' base64 = c3lzdGVtKCRfR0VUWzBdKTs=
  const payload = 'system($_GET[0]);';
  const b64 = Buffer.from(payload).toString('base64');
  const text = `<?php eval(base64_decode('${b64}'));`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval\(base64_decode/.test(c.technique));
  assert.ok(hits.length >= 1, `expected PHP1 hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, payload);
  assert.equal(hits[0]._executeOutput, true);
});

test('php-obfuscation: PHP1 eval(gzinflate(base64_decode(…))) decodes', () => {
  const payload = '<?php system($_REQUEST["c"]); ?>';
  const compressed = zlib.deflateRawSync(Buffer.from(payload));
  const b64 = compressed.toString('base64');
  const text = `eval(gzinflate(base64_decode("${b64}")));`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /gzinflate/.test(c.technique));
  assert.ok(hits.length >= 1, `expected gzinflate hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, payload);
});

test('php-obfuscation: PHP1 eval(str_rot13(gzinflate(base64_decode(…)))) decodes', () => {
  // rot13 of payload, then deflate, then base64.
  const payload = '<?php echo shell_exec($_POST["c"]); ?>';
  const rot = payload.replace(/[A-Za-z]/g, ch => {
    const c = ch.charCodeAt(0);
    const base = c < 97 ? 65 : 97;
    return String.fromCharCode(((c - base + 13) % 26) + base);
  });
  const compressed = zlib.deflateRawSync(Buffer.from(rot));
  const b64 = compressed.toString('base64');
  const text = `eval(str_rot13(gzinflate(base64_decode("${b64}"))));`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /str_rot13/.test(c.technique));
  assert.ok(hits.length >= 1, `expected rot13+gzinflate hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, payload);
});

test('php-obfuscation: PHP1 eval(gzuncompress(base64_decode(…))) decodes', () => {
  const payload = 'phpinfo();';
  const compressed = zlib.deflateSync(Buffer.from(payload)); // zlib-wrapped
  const b64 = compressed.toString('base64');
  const text = `eval(gzuncompress(base64_decode('${b64}')));`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /gzuncompress/.test(c.technique));
  assert.ok(hits.length >= 1, `expected gzuncompress hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, payload);
});

test('php-obfuscation: PHP1 assert(base64_decode(…)) variant emits', () => {
  // Older webshells use assert() instead of eval() (it accepted code
  // strings in PHP < 8.0).
  const payload = 'echo "pwned";';
  const b64 = Buffer.from(payload).toString('base64');
  const text = `assert(base64_decode('${b64}'));`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /base64_decode/.test(c.technique));
  assert.ok(hits.length >= 1, 'assert(base64_decode(…)) must fire');
  assert.equal(hits[0].deobfuscated, payload);
});

// ── PHP2: variable-variables ────────────────────────────────────────────────

test('php-obfuscation: PHP2 $$var with symbol-table lookup resolves', () => {
  const text = `<?php $a = 'sys' . 'tem'; $$a('id');`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => c.technique === 'PHP Variable-Variables');
  assert.ok(hits.length >= 1, `expected PHP2 hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /^system\(/);
  assert.equal(hits[0]._executeOutput, true);
});

test('php-obfuscation: PHP2 ${\'a\'.\'b\'}() anonymous form resolves', () => {
  const text = `<?php \${'sys' . 'tem'}('whoami');`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /anonymous/.test(c.technique));
  assert.ok(hits.length >= 1, 'PHP2 anonymous form must fire');
  assert.match(hits[0].deobfuscated, /^system\(/);
});

test('php-obfuscation: PHP2 non-dangerous resolved name suppressed', () => {
  // 'pri' + 'ntf' = 'printf' — not in PHP_DANGEROUS_FNS, no emission.
  const text = `<?php $a = 'pri' . 'ntf'; $$a('hello');`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Variable-Variables/.test(c.technique));
  assert.equal(hits.length, 0, 'printf must not fire (not dangerous)');
});

// ── PHP3: chr / pack reassembly ─────────────────────────────────────────────

test('php-obfuscation: PHP3 chr.chr.chr… resolves to dangerous fn name', () => {
  // 'eval' = chr(101).chr(118).chr(97).chr(108)
  const target = 'eval';
  const concat = [...target].map(c => `chr(${c.charCodeAt(0)})`).join('.');
  const text = `<?php $f = ${concat}; $f($_GET[0]);`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /chr-concat/.test(c.technique));
  assert.ok(hits.length >= 1, `expected chr-concat hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, target);
  assert.equal(hits[0]._executeOutput, true,
    'dangerous-fn match must mark _executeOutput');
});

test('php-obfuscation: PHP3 pack(\'H*\', hex) decodes to dangerous fn', () => {
  // 'system' hex = '73797374656d'
  const hex = Buffer.from('system').toString('hex');
  const text = `<?php $f = pack('H*', '${hex}'); $f('id');`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /pack\(H\*\)/.test(c.technique));
  assert.ok(hits.length >= 1, `expected pack(H*) hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, 'system');
  assert.equal(hits[0]._executeOutput, true);
});

test('php-obfuscation: PHP3 chr-concat to benign name suppressed', () => {
  // 'hello' — not a dangerous fn, no emission.
  const target = 'hello';
  const concat = [...target].map(c => `chr(${c.charCodeAt(0)})`).join('.');
  const text = `<?php echo ${concat};`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /chr-concat/.test(c.technique));
  assert.equal(hits.length, 0, 'benign chr-concat must not fire');
});

// ── PHP4: preg_replace /e ───────────────────────────────────────────────────

test('php-obfuscation: PHP4 preg_replace with /e modifier flagged', () => {
  const text = `<?php preg_replace('/(.+)/e', 'system("\\\\1")', $_GET['c']);`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /preg_replace \/e/.test(c.technique));
  assert.ok(hits.length >= 1, `expected /e hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0]._executeOutput, true);
});

test('php-obfuscation: PHP4 preg_replace without /e not flagged', () => {
  // No /e flag — legitimate text replacement.
  const text = `<?php $r = preg_replace('/foo/i', 'bar', $input);`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /preg_replace/.test(c.technique));
  assert.equal(hits.length, 0, 'preg_replace without /e must not fire');
});

// ── PHP5: superglobal callable ──────────────────────────────────────────────

test('php-obfuscation: PHP5 $_GET[0]($_POST[1]) one-line shell flagged', () => {
  const text = `<?php $_GET['fn']($_POST['arg']);`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Superglobal Callable/.test(c.technique));
  assert.ok(hits.length >= 1, `expected one-line shell; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0]._executeOutput, true);
});

test('php-obfuscation: PHP5 eval($_REQUEST[…]) flagged', () => {
  const text = `<?php eval($_REQUEST['c']);`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval\/system on Superglobal/.test(c.technique));
  assert.ok(hits.length >= 1, 'eval($_REQUEST) must fire');
  assert.equal(hits[0]._executeOutput, true);
});

test('php-obfuscation: PHP5 system($_POST[…]) flagged', () => {
  const text = `<?php system($_POST['cmd']);`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval\/system on Superglobal/.test(c.technique));
  assert.ok(hits.length >= 1, 'system($_POST) must fire');
});

// ── PHP6: data:/php:// stream-wrapper include ───────────────────────────────

test('php-obfuscation: PHP6 include(data://…;base64,…) decodes inner payload', () => {
  // Cleartext: <?php phpinfo(); ?>
  const inner = '<?php phpinfo(); ?>';
  const b64 = Buffer.from(inner).toString('base64');
  const text = `<?php include('data://text/plain;base64,${b64}');`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /stream wrapper/.test(c.technique));
  assert.ok(hits.length >= 1, `expected data:// include; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /phpinfo/);
  assert.equal(hits[0]._executeOutput, true);
});

test('php-obfuscation: PHP6 include(php://input) flagged without decode', () => {
  // php://input is a shell-by-POST primitive — no payload to decode,
  // but the wrapper itself is the signal.
  const text = `<?php include('php://input');`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /stream wrapper/.test(c.technique));
  assert.ok(hits.length >= 1, 'php://input include must fire');
});

test('php-obfuscation: PHP6 file_get_contents(php://filter…) flagged', () => {
  // The classic LFI-to-RCE primitive.
  const text = `<?php $c = file_get_contents('php://filter/convert.base64-decode/resource=hello.php');`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /stream wrapper/.test(c.technique));
  assert.ok(hits.length >= 1, 'php://filter must fire');
});

// ── Empty-input + non-PHP-text contract ─────────────────────────────────────

test('php-obfuscation: returns empty for short or non-PHP text', () => {
  assert.deepEqual(host(d._findPhpObfuscationCandidates('hi', {})), []);
  assert.deepEqual(host(d._findPhpObfuscationCandidates('', {})), []);
  assert.deepEqual(host(d._findPhpObfuscationCandidates(
    'The quick brown fox jumps over the lazy dog.', {})), []);
});

test('php-obfuscation: caps at maxCandidatesPerType', () => {
  // Flood of one-line shells; cap should bind.
  const line = `$_GET['fn']($_POST['arg']);\n`;
  const flood = line.repeat(d.maxCandidatesPerType + 50);
  const cands = d._findPhpObfuscationCandidates(flood, {});
  const shells = pick(cands, c => /Superglobal Callable/.test(c.technique));
  assert.ok(shells.length <= d.maxCandidatesPerType,
    `expected ≤ ${d.maxCandidatesPerType} candidates, got ${shells.length}`);
});

// ── PHP5 (5a): Superglobal Callable must extract KEY into deobfuscated ──────
//
// Regression guard: prior to this fix the `deobfuscated` field was just
// the raw source match, so the analyst never saw the dispatched
// parameter name. Now the resolved form `call $_GET['fn'] with args: …`
// surfaces the key explicitly.

test('php-obfuscation: 5a extracts superglobal + key + args into deobfuscated', () => {
  const text = `<?php $_GET['fn']($_POST['arg']);`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Superglobal Callable/.test(c.technique));
  assert.ok(hits.length >= 1, 'expected 5a candidate');
  const d0 = hits[0].deobfuscated;
  assert.match(d0, /\$_GET\[['"]fn['"]\]/, `key not extracted: ${d0}`);
  assert.match(d0, /\$_POST\[['"]arg['"]\]/, `args not extracted: ${d0}`);
  // _patternIocs mirror must carry a critical-severity T1059 pointer.
  const mirror = (hits[0]._patternIocs || [])[0];
  assert.ok(mirror && /user-input function dispatch/i.test(mirror.url || ''),
    `expected T1059 mirror; got: ${JSON.stringify(hits[0]._patternIocs)}`);
});

// ── PHP5 (5b): wrapped sink-on-superglobal (user's reported miss) ───────────
//
// The canonical gap before this fix: literal-adjacency regexes required
// sink and superglobal to touch, so `shell_exec(escapeshellarg(...))`
// was invisible despite being a critical web-shell primitive. These
// tests pin the wrapper-tolerant extraction.

test('php-obfuscation: 5b shell_exec(escapeshellarg($_SERVER[...])) is flagged critical', () => {
  const text = `<?php echo shell_exec(escapeshellarg($_SERVER['HTTP_X']));?>`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval\/system on Superglobal/.test(c.technique));
  assert.ok(hits.length >= 1,
    `user's exact reported miss must fire; got: ${JSON.stringify(host(cands))}`);
  const cand = hits[0];
  // Sink + wrapper + superglobal + key all present in deobfuscated:
  const dd = cand.deobfuscated;
  assert.match(dd, /shell_exec/, `sink not surfaced: ${dd}`);
  assert.match(dd, /escapeshellarg/, `wrapper not surfaced: ${dd}`);
  assert.match(dd, /\$_SERVER/, `superglobal not surfaced: ${dd}`);
  assert.match(dd, /HTTP_X/, `key not surfaced: ${dd}`);
  // escapeshellarg-wrapped case must uplift to critical via _patternIocs.
  const criticalMirror = (cand._patternIocs || []).find(
    p => p.severity === 'critical' && /ineffective sanitiser/i.test(p.url || '')
  );
  assert.ok(criticalMirror,
    `expected critical severity mirror for escapeshellarg wrapper; got: ${JSON.stringify(cand._patternIocs)}`);
});

test('php-obfuscation: 5b amplifying decoder wrapper (base64_decode) uplifts to critical', () => {
  const text = `<?php eval(base64_decode($_POST['p'])); ?>`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval\/system on Superglobal/.test(c.technique));
  assert.ok(hits.length >= 1, 'eval(base64_decode($_POST[...])) must fire');
  const cand = hits[0];
  assert.match(cand.deobfuscated, /base64_decode/, 'wrapper name must be in deobfuscated');
  const criticalMirror = (cand._patternIocs || []).find(
    p => p.severity === 'critical' && /amplifying decoder/i.test(p.url || '')
  );
  assert.ok(criticalMirror,
    `expected critical amplifying-decoder mirror; got: ${JSON.stringify(cand._patternIocs)}`);
});

test('php-obfuscation: 5b 2-level sanitiser chain system(trim(urldecode($_GET[...])))', () => {
  const text = `<?php system(trim(urldecode($_GET['cmd']))); ?>`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval\/system on Superglobal/.test(c.technique));
  assert.ok(hits.length >= 1, '2-level wrapper must fire');
  const dd = hits[0].deobfuscated;
  assert.match(dd, /system/, `sink missing: ${dd}`);
  assert.match(dd, /trim/, `outer wrapper missing: ${dd}`);
  assert.match(dd, /urldecode/, `inner wrapper missing: ${dd}`);
  assert.match(dd, /\$_GET\[['"]cmd['"]\]/, `superglobal access missing: ${dd}`);
});

test('php-obfuscation: 5b 3-level max-depth chain exec(htmlspecialchars(strip_tags(base64_decode($_COOKIE[...]))))', () => {
  const text = `<?php exec(htmlspecialchars(strip_tags(base64_decode($_COOKIE['k'])))); ?>`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval\/system on Superglobal/.test(c.technique));
  assert.ok(hits.length >= 1, 'max-depth (3-level) wrapper chain must fire');
  const cand = hits[0];
  // base64_decode in the chain must uplift to critical.
  const critMirror = (cand._patternIocs || []).find(p => p.severity === 'critical');
  assert.ok(critMirror, `expected critical mirror via base64_decode wrapper`);
});

test('php-obfuscation: 5b bare eval($_REQUEST[...]) — direct form still critical', () => {
  const text = `<?php eval($_REQUEST['c']); ?>`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval\/system on Superglobal/.test(c.technique));
  assert.ok(hits.length >= 1, 'bare eval on superglobal must fire');
  const critMirror = (hits[0]._patternIocs || []).find(
    p => p.severity === 'critical' && /direct eval\/assert/.test(p.url || '')
  );
  assert.ok(critMirror,
    `direct-eval path must uplift to critical; got: ${JSON.stringify(hits[0]._patternIocs)}`);
});

test('php-obfuscation: 5b negative — getenv without superglobal must not fire', () => {
  const text = `<?php shell_exec(strtolower(getenv('HTTP_X'))); ?>`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval\/system on Superglobal/.test(c.technique));
  assert.equal(hits.length, 0,
    `getenv is not a superglobal; must not fire; got: ${JSON.stringify(host(cands))}`);
});

test('php-obfuscation: 5b negative — escapeshellarg on literal must not fire', () => {
  const text = `<?php shell_exec(escapeshellarg('static-value')); ?>`;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /eval\/system on Superglobal/.test(c.technique));
  assert.equal(hits.length, 0,
    `no superglobal in escapeshellarg(); must not fire; got: ${JSON.stringify(host(cands))}`);
});

// ── PHP5 (5c): local-var taint flow (Layer-2) ───────────────────────────────

test('php-obfuscation: 5c $c = $_GET[...]; shell_exec($c); two-pass taint flow', () => {
  const text = `<?php
    $c = $_GET['x'];
    shell_exec($c);
  `;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Superglobal Taint/.test(c.technique));
  assert.ok(hits.length >= 1,
    `expected 5c local-var taint candidate; got: ${JSON.stringify(host(cands))}`);
  const dd = hits[0].deobfuscated;
  assert.match(dd, /shell_exec\(\$c\)/, `sink-call not surfaced: ${dd}`);
  assert.match(dd, /\$_GET\[['"]x['"]\]/, `assignment source not surfaced: ${dd}`);
});

test('php-obfuscation: 5c respects 2 KiB bridging bound', () => {
  const gap = 'x'.repeat(3000);
  const text = `<?php
    $c = $_SERVER['HTTP_X'];
    ${gap}
    shell_exec($c);
  `;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Superglobal Taint/.test(c.technique));
  assert.equal(hits.length, 0,
    `3 KiB gap must exceed bridging bound; got: ${JSON.stringify(host(cands))}`);
});

test('php-obfuscation: 5c negative — static-literal assignment does not fire', () => {
  const text = `<?php
    $c = 'static-value';
    shell_exec($c);
  `;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Superglobal Taint/.test(c.technique));
  assert.equal(hits.length, 0, 'no taint source; must not fire');
});

test('php-obfuscation: 5c tolerates wrapper between sink and tainted $c', () => {
  const text = `<?php
    $c = $_POST['cmd'];
    shell_exec(escapeshellarg($c));
  `;
  const cands = d._findPhpObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Superglobal Taint/.test(c.technique));
  assert.ok(hits.length >= 1, 'wrapper between sink and tainted $var must still fire');
});
