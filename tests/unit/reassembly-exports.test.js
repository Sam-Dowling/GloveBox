'use strict';
// ════════════════════════════════════════════════════════════════════════════
// reassembly-exports.test.js — structural pins for the Phase-4 export /
// summary plumbing that carries `EncodedReassembler` provenance out of
// `findings.reconstructedScript` and onto the user-facing outputs.
//
// We deliberately pin at the source level (same shape as
// `sidebar-ip-enrichment.test.js` and the nicelist structural tests).
// The behavioural surface is:
//
//   • `_buildAnalysisText` emits a "## Reassembled Script" section at
//     priority 5.5 (between Macros = 5 and Deobfuscated Findings = 6),
//     only when `findings.reconstructedScript.spans.length >= 2`.
//   • The section strips reassembly sentinels via
//     `EncodedReassembler.stripSentinels` before dumping the stitched
//     body, respects `charCap(12000)` on the body and `charCap(14000)`
//     on the whole section.
//   • `_collectIocs` forwards `_fromReassembly` / `_reconstructedHash`
//     onto the returned row as `fromReassembly` / `reconstructedHash`
//     (so CSV / JSON / STIX / MISP all see it).
//   • `_buildStixBundle` stamps `x_loupe_source = 'reassembly'`
//     + `x_loupe_reconstructed_hash` + the `loupe-reassembly-derived`
//     label on the indicator SDO for reassembly-derived IOCs.
//   • `_buildMispEvent` prefixes `[loupe-reassembly:<hash>]`
//     (or `[loupe-reassembly]` when the hash is absent) onto the
//     attribute's `comment`.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const APP_UI = fs.readFileSync(path.join(REPO_ROOT, 'src/app/app-ui.js'), 'utf8');

// ── _buildAnalysisText: Reassembled Script section ────────────────────────

test('_buildAnalysisText emits a "## Reassembled Script" heading', () => {
  assert.match(APP_UI, /##\s*Reassembled Script/,
    'the analysis-text builder must emit a "## Reassembled Script" heading');
});

test('Reassembled Script section gates on spans.length >= 2', () => {
  // The per-finding Deobfuscated Findings cards already cover the
  // single-span case; reassembly only earns a dedicated section once
  // there are at least two spliced spans (the whole point of the
  // reconstruction).
  assert.match(
    APP_UI,
    /_recon\.spans\.length\s*>=\s*2/,
    'reassembly section must require at least two spans'
  );
});

test('Reassembled Script section sits at priority 5.5 (between Macros and Deobfuscated Findings)', () => {
  // Anchor the section so any future renumbering breaks the test
  // instead of silently reordering the copy-analysis output.
  assert.match(
    APP_UI,
    /priority:\s*5\.5,\s*maxLen:\s*charCap\(14000\)/,
    'reassembly section must be emitted at priority 5.5 with maxLen charCap(14000)'
  );
});

test('Reassembled Script section strips sentinels via EncodedReassembler.stripSentinels', () => {
  // The stitched text carries U+2063 sentinels around spliced regions.
  // The copy-analysis output is plain Markdown — sentinels would show
  // as invisible garbage in rendered exports and confuse downstream
  // LLM consumers. Pin the strip call.
  assert.match(
    APP_UI,
    /window\.EncodedReassembler[\s\S]{0,200}?stripSentinels/,
    'reassembly section must invoke EncodedReassembler.stripSentinels'
  );
});

test('Reassembled Script section clips stitched body with charCap(12000)', () => {
  // The stitched body can be megabytes on pathological inputs; the
  // shrink ladder clips at 12 000 chars before the section-level
  // maxLen(14000) takes over.
  assert.match(
    APP_UI,
    /const\s+stitchedMax\s*=\s*charCap\(12000\)/,
    'stitched body must be capped at charCap(12000)'
  );
});

test('Reassembled Script section caps novel-IOC listing at 12', () => {
  // Up to 12 novel IOCs inline; overflow is redirected to the
  // Signatures & IOCs table below. 12 is the documented cap.
  assert.match(
    APP_UI,
    /_recon\.novelIocs\.slice\(0,\s*12\)/,
    'novel IOC listing must slice at 12 entries'
  );
});

// ── _collectIocs: propagate reassembly provenance onto the row ────────────

test('_collectIocs forwards _fromReassembly onto row.fromReassembly', () => {
  const fnMatch = APP_UI.match(/_collectIocs\s*\(\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(fnMatch, '_collectIocs body must be locatable');
  const body = fnMatch[0];
  assert.match(body, /r\._fromReassembly/,
    '_collectIocs must read r._fromReassembly from the finding');
  assert.match(body, /row\.fromReassembly\s*=\s*true/,
    '_collectIocs must write row.fromReassembly on reassembly-derived IOCs');
  assert.match(body, /row\.reconstructedHash\s*=\s*r\._reconstructedHash/,
    '_collectIocs must forward the reconstructed-script hash');
});

// ── _buildStixBundle: x_loupe_source + label on indicator SDO ────────────

test('_buildStixBundle stamps x_loupe_source = "reassembly" on reassembly-derived indicators', () => {
  // STIX 2.1 custom properties MUST be prefixed `x_` (§ 11.3).
  // `x_loupe_source` is Loupe's namespaced provenance slot — receivers
  // that want to separately triage reassembly-only indicators key on
  // this field.
  assert.match(
    APP_UI,
    /ind\.x_loupe_source\s*=\s*['"]reassembly['"]/,
    'STIX indicator SDO must carry x_loupe_source = "reassembly"'
  );
});

test('_buildStixBundle optionally attaches x_loupe_reconstructed_hash', () => {
  assert.match(
    APP_UI,
    /ind\.x_loupe_reconstructed_hash\s*=\s*ioc\.reconstructedHash/,
    'STIX indicator must carry the reconstructed-script hash when available'
  );
});

test('_buildStixBundle attaches "loupe-reassembly-derived" label to indicator', () => {
  // Labels are the STIX-canonical way to filter indicator consumers;
  // the custom `x_loupe_source` field is the rigorous key, but a
  // simple label means a SIEM operator without custom-property
  // support can still triage on a single string.
  assert.match(
    APP_UI,
    /['"]loupe-reassembly-derived['"]/,
    'STIX indicator must attach a "loupe-reassembly-derived" label'
  );
});

// ── _buildMispEvent: tag attribute comment with [loupe-reassembly:<hash>] ─

test('_buildMispEvent prefixes attribute comment with [loupe-reassembly:<hash>]', () => {
  // Format is `[loupe-reassembly:<hash>] <prior comment>`. A single
  // substring means downstream MISP users can filter with a trivial
  // `attribute.comment LIKE '%[loupe-reassembly%'`.
  assert.match(
    APP_UI,
    /\[loupe-reassembly:\$\{ioc\.reconstructedHash\}\]/,
    'MISP attribute comment must use [loupe-reassembly:<hash>] when the hash is present'
  );
  assert.match(
    APP_UI,
    /['"]\[loupe-reassembly\]['"]/,
    'MISP attribute comment must fall back to bare [loupe-reassembly] when the hash is absent'
  );
});

test('_buildMispEvent reassembly branch does NOT force to_ids=0', () => {
  // Nicelisting is a downweight (to_ids := '0'); reassembly is a
  // provenance marker only — the IOC is just as actionable regardless
  // of how it was discovered. Pin that we only mutate `.comment`.
  const reassemblyBranch = APP_UI.match(
    /if\s*\(ioc\.fromReassembly\)\s*\{[\s\S]{0,800}?\}\s*pushAttr\(a\);/
  );
  assert.ok(reassemblyBranch, 'MISP reassembly branch must be locatable');
  assert.doesNotMatch(
    reassemblyBranch[0],
    /a\.to_ids\s*=/,
    'MISP reassembly branch must not mutate to_ids'
  );
});
