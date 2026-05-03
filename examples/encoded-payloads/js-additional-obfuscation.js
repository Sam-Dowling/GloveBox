// js-additional-obfuscation.js — fixture for the new JS deobfuscator
// branches in js-assembly.js: packer.js, aaencode/jjencode (detection-
// only), and Function-wrapper carriers.
//
// All payloads are synthetic and reference RFC-2606 / TEST-NET hosts so
// the fixture is safe to commit.

// ── packer.js (Dean Edwards) ───────────────────────────────────────────────
// Hand-built packer carrier. Payload "0(1)" + dict ['alert','"pwned"']
// expands to alert("pwned"). Real packer dumps are hundreds of KB; this
// minimal form is sufficient to fire _findJsPackerCandidates.
eval(function (p, a, c, k, e, d) {
  return p
}('0(1)', 36, 2, 'alert|"pwned"'.split('|'), 0, {}));

// Multi-token dict expansion → 'function hello world'.
eval(function (p, a, c, k, e, d) {
  return p
}('0 1 2', 36, 3, 'function|hello|world'.split('|'), 0, {}));

// ── aaencode (Hasegawa kaomoji obfuscation) ─────────────────────────────────
// Detection-only: aaencode payloads are statically opaque (recovery
// requires JS-engine semantics we won't reproduce). We only assert the
// carrier is flagged. Synthetic short-form here; real aaencode dumps
// span 5-50 KB.
var ﾟωﾟﾉ = /｀ｍ´）ﾉ ~┻━┻/;
(ﾟДﾟ)['ﾟεﾟ'] = '\\';
(ﾟДﾟ)[ﾟωﾟ] = (ﾟДﾟ);
(ﾟДﾟ)['c'] = 'cookie';

// ── jjencode (Hasegawa symbol-only obfuscation) ─────────────────────────────
// Canonical opener `$=~[];$={…}` — body is dense `[]{}()+!_/$.\\` symbols.
// Full encoded body would be hundreds of chars; we include enough to
// trigger the symbol-density gate.
$=~[];$={___:++$,$$$$:(![]+'')[$],__$:++$,$_$_:(![]+'')[$],_$_:++$,
  $_$$:({}+'')[$],$$_$:($[$]+'')[$],_$$:++$,$$$_:(!''+'')[$],$__:++$,
  $_$:++$,$$__:({}+'')[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};
$.$_=($.$_=$+'')[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+'')[$.__$])+
  ((!$)+'')[$._$$]+($.__=$.$_[$.$$_])+($.$=(!''+'')[$.__$])+
  ($._=(!''+'')[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;

// ── Function(atob(...))() — base64 code carrier ─────────────────────────────
// Cleartext after atob:  eval(unescape("%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2e%74%65%73%74"))
// → eval(unescape(...)) → 'evil.example.test' string evaluation.
Function(atob('ZXZhbCh1bmVzY2FwZSgiJTY1JTc2JTY5JTZjJTJlJTY1JTc4JTYxJTZkJTcwJTZjJTY1JTJlJTc0JTY1JTczJTc0Iikp'))();

// new Function(atob(...))()  variant — same thing, different keyword.
new Function(atob('YWxlcnQoJ3B3bmVkJyk='))();

// ── Function(unescape('%XX%XX…'))() ─────────────────────────────────────────
// Cleartext: alert('evil.example.test')
Function(unescape('%61%6c%65%72%74%28%27%65%76%69%6c%2e%65%78%61%6d%70%6c%65%2e%74%65%73%74%27%29'))();

// ── Function.constructor("…")() — CSP-bypass-shaped wrapper ─────────────────
// `[].constructor.constructor("…")()` reaches Function.prototype.constructor
// without a literal `Function` token — used to dodge naive CSP scanners.
[].constructor.constructor('alert(document.cookie)')();
