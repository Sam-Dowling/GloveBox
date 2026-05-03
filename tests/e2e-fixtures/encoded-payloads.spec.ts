// ════════════════════════════════════════════════════════════════════════════
// encoded-payloads.spec.ts — Fixture-driven smoke for the encoded-content
// decoder pipeline (base64 / hex / zlib / nested combinations).
//
// The encoded-payloads renderer is one of Loupe's signature features:
// nested decoders unwrap layered obfuscations and re-feed the decoded
// payload back through the IOC extractor. We assert that a small
// hand-picked subset of fixtures still surface the IOC types we expect
// after one or two decode hops.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('encoded-payloads renderer (fixture-driven)', () => {
  const ctx = useSharedBundlePage();

  test('nested-b64-hex-url surfaces a URL after layered decode', async () => {
    // Fixture: outer base64 → inner hex → URL string. Tests the
    // decoder's ability to drive recursive decode hops and re-extract
    // IOCs from the innermost text. A regression where the recursive
    // step stops firing would zero out URL findings here.
    const findings = await loadFixture(
      ctx.page, 'examples/encoded-payloads/nested-b64-hex-url.txt');
    expect(findings.iocTypes).toContain('URL');
  });

  test('encoded-base64-pe yields PE detection and at least one finding', async () => {
    // Fixture: a base64-encoded PE binary embedded in plain text. The
    // decoder should detect the embedded PE and dispatch a sub-render —
    // surfacing detections / metadata even though the outer file is
    // text. Asserting `findings.iocCount + externalRefCount > 0` is a
    // permissive smoke; exact PE-side counts vary by build.
    const findings = await loadFixture(
      ctx.page, 'examples/encoded-payloads/encoded-base64-pe.txt');
    expect(findings.iocCount + findings.externalRefCount).toBeGreaterThan(0);
    // Risk should not be 'low' — an embedded PE in obfuscated text is a
    // textbook dropper shape that the renderer's externalRefs should
    // escalate.
    expect(findings.risk).not.toBe('low');
  });

  test('js-string-array-obfuscation surfaces a URL after JS resolver runs', async () => {
    // Fixture: obfuscator.io-shaped JS — string-array literal +
    // indexer function + two sink calls (eval, setTimeout). The
    // `js-assembly` decoder resolves both sinks and feeds them to
    // `_processCommandObfuscation`, which extracts the URL IOC and
    // escalates risk on PowerShell-cradle keywords (`IEX`,
    // `DownloadString`). A regression where the resolver doesn't fire
    // would zero out URL findings and drop risk back to baseline.
    const findings = await loadFixture(
      ctx.page, 'examples/encoded-payloads/js-string-array-obfuscation.js');
    expect(findings.iocTypes).toContain('URL');
    // PowerShell + DownloadString is a textbook download cradle; risk
    // should escalate beyond `low`.
    expect(findings.risk).not.toBe('low');
  });

  test('defanged-iocs.txt refangs hxxp:// → http://', async () => {
    // Direct fixture for the refanging path tested in unit-land. End-to-end
    // version verifies the renderer-level wiring (extractor result →
    // findings.interestingStrings → sidebar projection) works.
    const findings = await loadFixture(
      ctx.page, 'examples/encoded-payloads/defanged-iocs.txt');
    expect(findings.iocTypes).toContain('URL');
    // At least one URL entry should carry the 'Refanged' note when
    // the source has hxxp[://] / [.] obfuscations in it.
    const refangedNote = findings.iocs.some(
      i => i.type === 'URL' && (i.note || '').toLowerCase().includes('refang'),
    );
    expect(refangedNote).toBe(true);
  });

  test('bash-obfuscation-suite.sh surfaces deobfuscated commands and escalates risk', async () => {
    // Multi-branch bash fixture (B1–B6 + /dev/tcp). The bash-obfuscation
    // decoder unwraps every branch, the post-processor escalates severity
    // via dangerousPatterns + _executeOutput, and the renderer mutates
    // findings in-place. We assert the fixture: (1) generates ≥1 finding,
    // (2) generates ≥1 URL or IP IOC (real-world endpoints land in the
    // decoded cleartext), and (3) escalates risk above 'low' (multiple
    // ClickFix-grade payloads + a /dev/tcp reverse-shell can't be 'low').
    const findings = await loadFixture(
      ctx.page, 'examples/encoded-payloads/bash-obfuscation-suite.sh');
    expect(findings.iocCount + findings.externalRefCount).toBeGreaterThan(0);
    expect(['medium', 'high', 'critical']).toContain(findings.risk);
  });

  test('python-obfuscation-suite.py surfaces deobfuscated sinks and escalates risk', async () => {
    // Multi-branch Python fixture (P1–P6). The python-obfuscation
    // decoder unwraps zlib/marshal/codecs/chr/builtin/sink branches and
    // emits cmd-obfuscation candidates; the post-processor scores
    // dangerousPatterns hits (subprocess / os.system / pty.spawn / socket
    // reverse-shell). Same shape of assertion as bash: ≥1 finding, risk
    // beyond 'low'.
    const findings = await loadFixture(
      ctx.page, 'examples/encoded-payloads/python-obfuscation-suite.py');
    expect(findings.iocCount + findings.externalRefCount).toBeGreaterThan(0);
    expect(['medium', 'high', 'critical']).toContain(findings.risk);
  });

  test('php-webshell-suite.php surfaces decoder-onion cleartext and escalates risk', async () => {
    // Multi-branch PHP webshell fixture (PHP1–PHP6). The php-obfuscation
    // decoder unwraps the eval(gzinflate(base64_decode(...))) chain (real
    // bytes inflated via Decompressor.inflateSync), emits cmd-obfuscation
    // candidates for variable-variables / chr-pack / preg_replace /e /
    // superglobal callable / data:// stream wrapper. Multiple PHP YARA
    // rules (PHP_Webshell_Decoder_Onion, PHP_Eval_Superglobal,
    // PHP_Preg_Replace_E_Modifier, PHP_Variable_Variable_Obfuscation)
    // should fire, pushing risk to at least 'high'.
    const findings = await loadFixture(
      ctx.page, 'examples/encoded-payloads/php-webshell-suite.php');
    expect(findings.iocCount + findings.externalRefCount).toBeGreaterThan(0);
    expect(['high', 'critical']).toContain(findings.risk);
  });

  test('js-additional-obfuscation.js surfaces packer / Function-wrapper cleartext', async () => {
    // packer.js + aaencode / jjencode + Function(atob(...))() variants.
    // The packer carrier inflates statically (re-implementing packer.js's
    // dictionary-substitution loop), aaencode / jjencode are detection-
    // only (statically opaque without a JS engine — we surface the
    // carrier as _executeOutput high-confidence). Function-wrapper
    // carriers decode the inner code via atob() / unescape().
    const findings = await loadFixture(
      ctx.page, 'examples/encoded-payloads/js-additional-obfuscation.js');
    expect(findings.iocCount + findings.externalRefCount).toBeGreaterThan(0);
    expect(['medium', 'high', 'critical']).toContain(findings.risk);
  });
});
