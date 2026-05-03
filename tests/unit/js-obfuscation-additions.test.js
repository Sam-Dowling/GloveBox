'use strict';
// js-obfuscation-additions.test.js — extra JS-obfuscator resolvers
// added on top of the existing string-array pipeline:
//
//   * Dean Edwards p.a.c.k.e.r — eval(function(p,a,c,k,e,d){…}('PAYLOAD',
//     <radix>,<dictlen>,'k0|k1|…'.split('|'),0,{})). Static decoder
//     re-implements packer.js v3 substitution.
//   * aaencode / jjencode — Hasegawa pure-symbol JS encoders. Detection-
//     only because static decode requires a JS-engine VM (we won't eval).
//   * Function-wrapper carriers — Function(atob('…'))() /
//     Function(unescape('%XX…'))() / Function.constructor('…')().
//
// Each emits the same `cmd-obfuscation` candidate shape consumed by
// `_processCommandObfuscation`.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/js-assembly.js',
]);
const { EncodedContentDetector } = ctx;
const d = new EncodedContentDetector();

function pick(candidates, pred) { return host(candidates.filter(pred)); }

// ── packer.js ───────────────────────────────────────────────────────────────

test('js-additions: packer.js carrier with 1-token dictionary decodes', () => {
  // Hand-built packer fixture. Payload `0(1)` with dict ['alert','1'] and
  // radix 36 expands to `alert(1)` (token "0" → dict[0]="alert", "1" →
  // dict[1]="1" but since dict[1]==='1' the substitution is identical).
  // For a more interesting case use dict ['alert','"pwned"'] so we see
  // a real substitution.
  // Build the call payload: '0(1)' where dict[0]=alert, dict[1]='"pwned"'
  // Note: packer dict literals can't contain `|` (it's the splitter) or
  // un-escaped quotes — escape via single-quote outer string.
  const payload = `0(1)`;
  const dict = `alert|"pwned"`;
  const dictLen = 2;
  const text = `eval(function(p,a,c,k,e,d){return p}('${payload}',36,${dictLen},'${dict}'.split('|'),0,{}))`;
  const cands = d._findJsPackerCandidates(text, {});
  const hits = pick(cands, c => /p\.a\.c\.k\.e\.r/.test(c.technique));
  assert.ok(hits.length >= 1, `expected packer hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, 'alert("pwned")');
  assert.equal(hits[0]._executeOutput, true);
});

test('js-additions: packer.js with multi-token payload decodes', () => {
  // dict [0]=function [1]=hello [2]=world; payload "0 1 2" → "function hello world"
  const dict = `function|hello|world`;
  const payload = `0 1 2`;
  const text = `eval(function(p,a,c,k,e,d){…}('${payload}',36,3,'${dict}'.split('|'),0,{}))`;
  const cands = d._findJsPackerCandidates(text, {});
  const hits = pick(cands, c => /p\.a\.c\.k\.e\.r/.test(c.technique));
  assert.ok(hits.length >= 1);
  assert.equal(hits[0].deobfuscated, 'function hello world');
});

test('js-additions: packer.js with empty dict slot preserves token', () => {
  // dict [0]=foo [1]=<empty> [2]=bar; payload "0 1 2" → "foo 1 bar"
  // (empty slots cause packer to leave the index token verbatim — same
  // as the original packer.js v3 behaviour: `if (k[c]) p = …`).
  const dict = `foo||bar`;
  const payload = `0 1 2`;
  const text = `eval(function(p,a,c,k,e,d){…}('${payload}',36,3,'${dict}'.split('|'),0,{}))`;
  const cands = d._findJsPackerCandidates(text, {});
  const hits = pick(cands, c => /p\.a\.c\.k\.e\.r/.test(c.technique));
  assert.ok(hits.length >= 1);
  assert.equal(hits[0].deobfuscated, 'foo 1 bar');
});

test('js-additions: packer.js radix=62 (mixed case) base correctly indexed', () => {
  // Radix 62 uses 0-9 a-z A-Z. Index 10 = 'a'; index 36 = 'A'.
  const dict = new Array(62).fill('').map((_, i) => `t${i}`).join('|');
  const text = `eval(function(p,a,c,k,e,d){return p}('a A',62,62,'${dict}'.split('|'),0,{}))`;
  const cands = d._findJsPackerCandidates(text, {});
  const hits = pick(cands, c => /p\.a\.c\.k\.e\.r/.test(c.technique));
  assert.ok(hits.length >= 1);
  assert.equal(hits[0].deobfuscated, 't10 t36');
});

test('js-additions: non-packer text returns empty', () => {
  const text = `function add(a, b) { return a + b; }`;
  assert.deepEqual(host(d._findJsPackerCandidates(text, {})), []);
});

// ── aaencode / jjencode ─────────────────────────────────────────────────────

test('js-additions: aaencode kaomoji burst flagged as detection-only', () => {
  // Synthetic aaencode-shaped opening — long Japanese-kana / fullwidth
  // run followed by `(ﾟДﾟ)` token. Real samples are ~2-5 KB; we only
  // need the signature to fire.
  const text =
    `var ﾟωﾟﾉ = /｀ｍ´）ﾉ ~┻━┻;\n` +
    `(ﾟДﾟ)['ﾟεﾟ'] = '\\\\';\n` +
    `(ﾟДﾟ)[ﾟωﾟ] = (ﾟДﾟ);` +
    `// payload follows…`;
  const cands = d._findJsAaJjEncodeCandidates(text, {});
  const hits = pick(cands, c => /aaencode/.test(c.technique));
  assert.ok(hits.length >= 1, `expected aaencode hit; got: ${JSON.stringify(host(cands))}`);
  assert.match(hits[0].deobfuscated, /sandbox required/);
  assert.equal(hits[0]._executeOutput, true);
});

test('js-additions: jjencode opener with dense-symbol body flagged', () => {
  // jjencode body is an explosion of `[]{}()+!_/$.\\` — synthesise 500
  // chars of those, prefixed with the canonical opener.
  const symbols = '[]{}()+!_/$.\\';
  let body = '';
  for (let i = 0; i < 500; i++) body += symbols[i % symbols.length];
  const text = `$=~[];$={___:++$,$$$$:(![]+'')[$],__$:++$,${body}`;
  const cands = d._findJsAaJjEncodeCandidates(text, {});
  const hits = pick(cands, c => /jjencode/.test(c.technique));
  assert.ok(hits.length >= 1, `expected jjencode hit; got: ${JSON.stringify(host(cands))}`);
});

test('js-additions: minified-JS that *looks* like jjencode opener but is dense in alphanums is rejected', () => {
  // `x=~[];x={a:1,b:2,c:3}` — has the opening shape but the body is
  // mostly identifiers, not jjencode symbols. The 0.4 ratio gate must
  // suppress it.
  const text = `var x=~[];x={a:1,b:2,c:3,d:4,e:5,foo:6,bar:7,baz:8}; for (let i=0;i<100;i++) doSomething(i);`;
  const cands = d._findJsAaJjEncodeCandidates(text, {});
  const hits = pick(cands, c => /jjencode/.test(c.technique));
  assert.equal(hits.length, 0, 'minified JS must not fire jjencode');
});

// ── Function-wrapper carriers ───────────────────────────────────────────────

test('js-additions: Function(atob(...))() decodes inner code', () => {
  // 'alert(1)' → 'YWxlcnQoMSk='
  const inner = `alert(1)`;
  const b64 = (typeof Buffer !== 'undefined')
    ? Buffer.from(inner).toString('base64')
    : 'YWxlcnQoMSk=';
  const text = `Function(atob('${b64}'))()`;
  const cands = d._findJsFunctionWrapperCandidates(text, {});
  const hits = pick(cands, c => /Function\(atob/.test(c.technique));
  assert.ok(hits.length >= 1, `expected hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, inner);
  assert.equal(hits[0]._executeOutput, true);
});

test('js-additions: new Function(atob(...))() variant decodes', () => {
  const inner = `eval(unescape("%61%6c%65%72%74%28%31%29"))`;
  const b64 = Buffer.from(inner).toString('base64');
  const text = `new Function(atob("${b64}"))();`;
  const cands = d._findJsFunctionWrapperCandidates(text, {});
  const hits = pick(cands, c => /Function\(atob/.test(c.technique));
  assert.ok(hits.length >= 1);
  assert.equal(hits[0].deobfuscated, inner);
});

test('js-additions: Function(unescape(\'%XX\'))() decodes inner code', () => {
  // 'alert(1)' as %XX = '%61%6c%65%72%74%28%31%29'
  const text = `Function(unescape('%61%6c%65%72%74%28%31%29'))()`;
  const cands = d._findJsFunctionWrapperCandidates(text, {});
  const hits = pick(cands, c => /Function\(unescape/.test(c.technique));
  assert.ok(hits.length >= 1, `expected hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, 'alert(1)');
});

test('js-additions: Function.constructor("payload")() flagged', () => {
  // The `[].constructor.constructor("…")()` shape (used to dodge naive
  // CSP scanners that look for the literal `Function` token) — our
  // pattern matches `<NAME>.constructor("…")()` directly.
  const text = `[].constructor.constructor("alert(document.cookie)")()`;
  const cands = d._findJsFunctionWrapperCandidates(text, {});
  const hits = pick(cands, c => /constructor RCE/.test(c.technique));
  assert.ok(hits.length >= 1, `expected hit; got: ${JSON.stringify(host(cands))}`);
  assert.equal(hits[0].deobfuscated, 'alert(document.cookie)');
});

test('js-additions: legitimate Function() declaration without IIFE not flagged', () => {
  // A `Function('a','return a*2')` reference assigned to a variable but
  // never IIFE-invoked — not the wrapper-shell carrier (it's a hand-
  // built dynamic function, not a self-executing payload). The trailing
  // `()` is what we require.
  const text = `var doubler = Function('a', 'return a*2');`;
  const cands = d._findJsFunctionWrapperCandidates(text, {});
  const hits = pick(cands, c => /Function/.test(c.technique));
  assert.equal(hits.length, 0, 'non-IIFE Function() must not fire wrapper-shell');
});

// ── Empty / cap contract ────────────────────────────────────────────────────

test('js-additions: returns empty for short or non-JS text', () => {
  assert.deepEqual(host(d._findJsPackerCandidates('hi', {})), []);
  assert.deepEqual(host(d._findJsAaJjEncodeCandidates('hi', {})), []);
  assert.deepEqual(host(d._findJsFunctionWrapperCandidates('hi', {})), []);
});
