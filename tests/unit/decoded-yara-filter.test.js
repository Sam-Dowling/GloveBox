'use strict';
// decoded-yara-filter.test.js — unit coverage for the host-side YARA gate
// that runs over decoded encoded-content payloads.
//
// The module under test (`src/decoded-yara-filter.js`) is mostly orchestration
// — it walks a findings tree, filters candidates by size, dispatches them to
// `WorkerManager.runDecodedYara`, and stamps `_yaraHits` onto the matching
// findings. We exercise it with a fake `workerManager` so the tests stay pure
// (no Web Worker spin-up, no YARA engine inside the harness).
//
// What we cover
// -------------
//   1. Bruteforce mode is a no-op (never calls the worker).
//   2. Findings under MIN_PAYLOAD_BYTES are filtered out before dispatch.
//   3. Findings over MAX_PAYLOAD_BYTES are filtered out before dispatch.
//   4. Findings already classified as PE / ELF / Mach-O are skipped (the
//      structured renderers own those — we only YARA-gate script-shaped
//      decodes).
//   5. innerFindings are walked recursively (depth-first), and the
//      MAX_PAYLOADS_PER_FILE cap stops the walk.
//   6. A worker `hits` postback stamps `_yaraHits` + `_retainedByYara`
//      on the matching findings (and only those).
//   7. The function is idempotent: a second call with the same
//      worker response does not duplicate hits.
//   8. A worker rejection is a silent no-op (findings tree unchanged).
//   9. An empty `source` short-circuits before the worker call.
//  10. `workersAvailable() === false` short-circuits before the worker
//      call (so the gate never freezes the main thread on hundreds of
//      tiny payloads in a worker-disabled context).

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

// `decoded-yara-filter.js` only touches `window.DecodedYaraFilter`. No
// other source files are required (the worker reference is injected
// per-call via `opts.workerManager`).
const ctx = loadModules(['src/decoded-yara-filter.js'], {
  expose: ['DecodedYaraFilter'],
});
const { DecodedYaraFilter } = ctx;

// ── Test fixtures ─────────────────────────────────────────────────────────

/** Build a fake `workerManager` that captures the dispatched payloads and
 *  returns the prepared response. Setting `reject: true` makes the
 *  promise reject (used for the silent-no-op test). */
function fakeWorkerManager({ response = { hits: [] }, reject = false, available = true } = {}) {
  const calls = [];
  return {
    calls,
    workersAvailable() { return available; },
    runDecodedYara(payloads, source, opts) {
      // Capture a copy of the dispatch shape so post-call assertions
      // can inspect it without seeing later mutations from the host.
      calls.push({
        payloadIds: payloads.map(p => p.id),
        payloadSizes: payloads.map(p => p.bytes.byteLength),
        sourceLen: source ? source.length : 0,
        opts: opts || null,
      });
      return reject ? Promise.reject(new Error('synthetic')) : Promise.resolve(response);
    },
  };
}

/** Build a finding with decoded bytes filled with a recognisable byte (so a
 *  by-eye dump of `_collectScanCandidates` output is easier to read). */
function makeFinding({ id, size, fillByte = 0x41, classificationType = null, inner = null }) {
  const f = {
    _id: id,
    decodedBytes: new Uint8Array(size).fill(fillByte),
  };
  if (classificationType) f.classification = { type: classificationType };
  if (inner) f.innerFindings = inner;
  return f;
}

// ── 1. Bruteforce mode is a no-op ─────────────────────────────────────────

test('decoded-yara-filter: bruteforce mode never calls the worker', async () => {
  const findings = [makeFinding({ id: 'a', size: 64 })];
  const wm = fakeWorkerManager();
  await DecodedYaraFilter.applyDecodedYaraGate(findings, {
    bruteforce: true,
    source: 'rule X { condition: true }',
    workerManager: wm,
  });
  assert.equal(wm.calls.length, 0, 'worker must not be invoked in bruteforce');
  assert.equal(findings[0]._yaraHits, undefined, 'no stamp should appear');
});

// ── 2. Tiny payloads are filtered out ────────────────────────────────────

test('decoded-yara-filter: payloads under MIN_PAYLOAD_BYTES are skipped', async () => {
  const findings = [
    makeFinding({ id: 'tiny', size: DecodedYaraFilter.MIN_PAYLOAD_BYTES - 1 }),
    makeFinding({ id: 'ok',   size: DecodedYaraFilter.MIN_PAYLOAD_BYTES + 4 }),
  ];
  const wm = fakeWorkerManager();
  await DecodedYaraFilter.applyDecodedYaraGate(findings, { source: 'X', workerManager: wm });
  assert.equal(wm.calls.length, 1);
  // payloadIds are the index INTO THE CANDIDATE LIST (not the findings
  // tree). The tiny finding is filtered out before dispatch, so the
  // single survivor occupies candidate slot 0. The post-call assertion
  // on the worker payload sizes anchors which finding is meant.
  assert.deepEqual(wm.calls[0].payloadIds, [0]);
  assert.deepEqual(wm.calls[0].payloadSizes, [DecodedYaraFilter.MIN_PAYLOAD_BYTES + 4]);
});

// ── 3. Huge payloads are filtered out ────────────────────────────────────

test('decoded-yara-filter: payloads over MAX_PAYLOAD_BYTES are skipped', async () => {
  const findings = [
    makeFinding({ id: 'huge', size: DecodedYaraFilter.MAX_PAYLOAD_BYTES + 1 }),
    makeFinding({ id: 'ok',   size: 64 }),
  ];
  const wm = fakeWorkerManager();
  await DecodedYaraFilter.applyDecodedYaraGate(findings, { source: 'X', workerManager: wm });
  assert.equal(wm.calls.length, 1);
  assert.deepEqual(wm.calls[0].payloadIds, [0]);
  assert.deepEqual(wm.calls[0].payloadSizes, [64]);
});

// ── 4. PE/ELF/Mach-O classifications are skipped ──────────────────────────

test('decoded-yara-filter: pre-classified binary payloads are skipped', async () => {
  const findings = [
    makeFinding({ id: 'pe',   size: 64, classificationType: 'PE Executable (Windows)' }),
    makeFinding({ id: 'elf',  size: 64, classificationType: 'ELF binary' }),
    makeFinding({ id: 'macho', size: 64, classificationType: 'Mach-O binary' }),
    makeFinding({ id: 'java', size: 64, classificationType: 'Java class file' }),
    makeFinding({ id: 'script', size: 64, classificationType: 'PowerShell script' }),
  ];
  const wm = fakeWorkerManager();
  await DecodedYaraFilter.applyDecodedYaraGate(findings, { source: 'X', workerManager: wm });
  // Only the PowerShell-script finding (originally at index 4 in the
  // findings tree) should reach the worker — and as the SOLE survivor it
  // becomes candidate slot 0. The PE / ELF / Mach-O / Java findings are
  // owned by the binary renderers' own pipelines and should never enter
  // the decoded-payload YARA pass.
  assert.equal(wm.calls.length, 1);
  assert.deepEqual(wm.calls[0].payloadIds, [0]);
  // Stamp evidence: only that surviving finding could possibly be matched.
  // (We don't supply hits in this test, so just verify nothing got
  // stamped on the skipped findings.)
  for (const f of findings) {
    assert.equal(f._yaraHits, undefined);
  }
});

// ── 5. innerFindings recursion + MAX_PAYLOADS_PER_FILE cap ───────────────

test('decoded-yara-filter: walks innerFindings depth-first', async () => {
  const findings = [
    makeFinding({
      id: 'outer',
      size: 64,
      inner: [
        makeFinding({ id: 'inner-1', size: 64 }),
        makeFinding({
          id: 'inner-2',
          size: 64,
          inner: [makeFinding({ id: 'inner-2-1', size: 64 })],
        }),
      ],
    }),
  ];
  const wm = fakeWorkerManager();
  await DecodedYaraFilter.applyDecodedYaraGate(findings, { source: 'X', workerManager: wm });
  assert.equal(wm.calls.length, 1);
  // Order matters: the gate should walk parents before children so that
  // the cap (when it fires) drops the deepest-nested findings first
  // rather than truncating mid-tree.
  assert.deepEqual(wm.calls[0].payloadIds, [0, 1, 2, 3]);
});

test('decoded-yara-filter: MAX_PAYLOADS_PER_FILE caps the candidate count', async () => {
  // Build a flat list of (cap + 5) findings; the cap is exposed on the
  // module so the test stays in-sync with any future tuning changes.
  const cap = DecodedYaraFilter.MAX_PAYLOADS_PER_FILE;
  const findings = [];
  for (let i = 0; i < cap + 5; i++) {
    findings.push(makeFinding({ id: 'f' + i, size: 64 }));
  }
  const wm = fakeWorkerManager();
  await DecodedYaraFilter.applyDecodedYaraGate(findings, { source: 'X', workerManager: wm });
  assert.equal(wm.calls[0].payloadIds.length, cap);
});

// ── 6. Worker hits stamp _yaraHits + _retainedByYara ─────────────────────

test('decoded-yara-filter: stamps _yaraHits on matched findings only', async () => {
  const findings = [
    makeFinding({ id: 'a', size: 64 }),
    makeFinding({ id: 'b', size: 64 }),
    makeFinding({ id: 'c', size: 64 }),
  ];
  const wm = fakeWorkerManager({
    response: {
      hits: [
        // id 0 (finding 'a') matches two rules.
        { id: 0, results: [
          { ruleName: 'PowerShell_Encoded_Command', meta: { severity: 'high' }, tags: 'pwsh' },
          { ruleName: 'Obfuscated_IEX_Invocation',  meta: { severity: 'medium' }, tags: '' },
        ]},
        // id 2 (finding 'c') matches one rule. id 1 doesn't appear ⇒ no match.
        { id: 2, results: [
          { ruleName: 'Hex_Shellcode_Pattern', meta: { severity: 'critical' }, tags: 'shellcode' },
        ]},
      ],
    },
  });
  await DecodedYaraFilter.applyDecodedYaraGate(findings, { source: 'X', workerManager: wm });

  // Cross-realm comparison: arrays/objects produced inside the vm sandbox
  // fail prototype-identity checks against host-realm Array. JSON-roundtrip
  // via `host()` projects them into the test realm for deepEqual.
  assert.deepEqual(host(findings[0]._yaraHits.map(h => h.ruleName)),
    ['PowerShell_Encoded_Command', 'Obfuscated_IEX_Invocation']);
  assert.equal(findings[0]._retainedByYara, true);
  assert.equal(findings[1]._yaraHits, undefined, 'unmatched finding stays untouched');
  assert.equal(findings[1]._retainedByYara, undefined);
  assert.deepEqual(host(findings[2]._yaraHits.map(h => h.ruleName)), ['Hex_Shellcode_Pattern']);
  assert.equal(findings[2]._yaraHits[0].severity, 'critical');
});

// ── 7. Idempotency ───────────────────────────────────────────────────────

test('decoded-yara-filter: a second call does not duplicate hits', async () => {
  const findings = [makeFinding({ id: 'a', size: 64 })];
  const response = { hits: [{ id: 0, results: [
    { ruleName: 'PS_Char_Casting_Obfuscation', meta: { severity: 'medium' }, tags: '' },
  ]}]};
  const wm = fakeWorkerManager({ response });
  await DecodedYaraFilter.applyDecodedYaraGate(findings, { source: 'X', workerManager: wm });
  await DecodedYaraFilter.applyDecodedYaraGate(findings, { source: 'X', workerManager: wm });
  assert.equal(findings[0]._yaraHits.length, 1, 'second call should dedupe by ruleName');
});

// ── 8. Worker rejection is silent ────────────────────────────────────────

test('decoded-yara-filter: a rejected dispatch is a silent no-op', async () => {
  const findings = [makeFinding({ id: 'a', size: 64 })];
  const wm = fakeWorkerManager({ reject: true });
  await DecodedYaraFilter.applyDecodedYaraGate(findings, { source: 'X', workerManager: wm });
  assert.equal(findings[0]._yaraHits, undefined);
  assert.equal(findings[0]._retainedByYara, undefined);
});

// ── 9. Empty source short-circuits ───────────────────────────────────────

test('decoded-yara-filter: empty source skips the worker entirely', async () => {
  const findings = [makeFinding({ id: 'a', size: 64 })];
  const wm = fakeWorkerManager();
  await DecodedYaraFilter.applyDecodedYaraGate(findings, { source: '', workerManager: wm });
  assert.equal(wm.calls.length, 0);
});

// ── 10. workersAvailable=false short-circuits ────────────────────────────

test('decoded-yara-filter: skips when workers are unavailable', async () => {
  const findings = [makeFinding({ id: 'a', size: 64 })];
  const wm = fakeWorkerManager({ available: false });
  await DecodedYaraFilter.applyDecodedYaraGate(findings, { source: 'X', workerManager: wm });
  assert.equal(wm.calls.length, 0);
  assert.equal(findings[0]._yaraHits, undefined);
});

// ── 11. _collectScanCandidates is exposed and matches the gate's view ────
//
// The internal helper is exported intentionally for tests like this one;
// it lets us verify the candidate-selection rules without a worker mock.
test('decoded-yara-filter: _collectScanCandidates honours the size + class gates', () => {
  const findings = [
    makeFinding({ id: 'tiny', size: 4 }),
    makeFinding({ id: 'ok',   size: 64 }),
    makeFinding({ id: 'pe',   size: 64, classificationType: 'PE Executable' }),
  ];
  const out = DecodedYaraFilter._collectScanCandidates(findings);
  assert.equal(out.length, 1, 'only the size-ok, non-binary finding should be selected');
  assert.equal(out[0]._id, 'ok');
});
