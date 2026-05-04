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

// ── _renderReassembledScriptCard: visual parity with per-finding cards ────
//
// The reassembled-script card must look and behave like every other
// `.enc-finding-card` in the Deobfuscation section. Earlier iterations
// fabricated their own CSS classes (`.enc-preview`, `.enc-chain-pills`,
// `.enc-chain-pill`, `.enc-action-btn`, `.enc-finding-novel-iocs`,
// `.enc-chain-count`) — none of which are defined in `src/styles/` so
// they rendered unstyled. These pins keep the card on the canonical
// class set.

const SIDEBAR = fs.readFileSync(path.join(REPO_ROOT, 'src/app/app-sidebar.js'), 'utf8');

test('_renderReassembledScriptCard uses canonical .enc-snippet (not .enc-preview)', () => {
  const body = SIDEBAR.match(/_renderReassembledScriptCard\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body, '_renderReassembledScriptCard body must be locatable');
  assert.match(
    body[0],
    /className\s*=\s*['"]enc-snippet['"]/,
    'preview block must use .enc-snippet — the canonical encoded-content snippet class'
  );
  assert.doesNotMatch(
    body[0],
    /['"]enc-preview['"]/,
    '.enc-preview is undefined in core.css; must not be used'
  );
});

test('_renderReassembledScriptCard uses canonical .enc-finding-chain + .enc-chain-hop (not .enc-chain-pills)', () => {
  const body = SIDEBAR.match(/_renderReassembledScriptCard\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body, '_renderReassembledScriptCard body must be locatable');
  assert.match(
    body[0],
    /className\s*=\s*['"]enc-finding-chain['"]/,
    'techniques row must wrap in .enc-finding-chain — the canonical chain-wrapper class'
  );
  assert.match(
    body[0],
    /className\s*=\s*['"]enc-chain-hop[^'"]*['"]/,
    'each technique pill must use .enc-chain-hop — the canonical hop-pill class'
  );
  assert.doesNotMatch(
    body[0],
    /['"]enc-chain-pills['"]|['"]enc-chain-pill['"]/,
    '.enc-chain-pills / .enc-chain-pill are undefined in core.css; must not be used'
  );
});

test('_renderReassembledScriptCard uses canonical .enc-finding-iocs[data-clickable]', () => {
  const body = SIDEBAR.match(/_renderReassembledScriptCard\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body, '_renderReassembledScriptCard body must be locatable');
  assert.match(
    body[0],
    /className\s*=\s*['"]enc-finding-iocs['"]/,
    'novel-IOC line must use .enc-finding-iocs — the canonical click-to-flash footer'
  );
  assert.match(
    body[0],
    /setAttribute\s*\(\s*['"]data-clickable['"]/,
    'the line must carry the data-clickable attribute that styles the hover affordance'
  );
  assert.doesNotMatch(
    body[0],
    /['"]enc-finding-novel-iocs['"]/,
    '.enc-finding-novel-iocs is undefined in core.css; must not be used'
  );
});

test('_renderReassembledScriptCard IOC line matches "IOCs: N <TYPE>" format', () => {
  const body = SIDEBAR.match(/_renderReassembledScriptCard\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body, '_renderReassembledScriptCard body must be locatable');
  assert.match(
    body[0],
    /['"]IOCs:\s*['"]\s*\+/,
    'IOC line text must start with "IOCs: " — matches the per-finding card footer'
  );
});

test('_renderReassembledScriptCard drill-down button uses canonical tb-btn enc-btn-load', () => {
  const body = SIDEBAR.match(/_renderReassembledScriptCard\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body, '_renderReassembledScriptCard body must be locatable');
  assert.match(
    body[0],
    /className\s*=\s*['"]tb-btn\s+enc-btn-load['"]/,
    'drill-down button must use tb-btn enc-btn-load — the canonical green "Load for analysis" styling'
  );
  assert.match(
    body[0],
    /textContent\s*=\s*['"]▶\s*Load stitched script['"]/,
    'button label must use the ▶ prefix like every other "Load for analysis" button'
  );
  assert.doesNotMatch(
    body[0],
    /['"]enc-action-btn['"]/,
    '.enc-action-btn is undefined in core.css; must not be used'
  );
});

test('_renderReassembledScriptCard IOC click delegates to _flashIocRows via recon._iocRows side-channel', () => {
  const body = SIDEBAR.match(/_renderReassembledScriptCard\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(body, '_renderReassembledScriptCard body must be locatable');
  assert.match(
    body[0],
    /this\._flashIocRows\s*\(\s*\{\s*_iocRows:\s*recon\._iocRows[^)]*\}\s*\)/,
    'IOC line click must delegate to _flashIocRows with the composite recon._iocRows array'
  );
});

// ── Sidebar IOC-table: register reassembly rows into recon._iocRows ───────

test('sidebar IOC-table registers _fromReassembly <tr>s into findings.reconstructedScript._iocRows', () => {
  // Without this registration the composite card's "IOCs: N URL" click
  // handler has nothing to flash — `_iocRows` would be empty. The
  // registration sits alongside the per-finding `_encodedFinding._iocRows`
  // push so both patterns follow the same lazy-init convention.
  assert.match(
    SIDEBAR,
    /ref\._fromReassembly[\s\S]{0,300}?this\.findings\.reconstructedScript\._iocRows[\s\S]{0,80}?\.push\s*\(\s*tr\s*\)/,
    'IOC-table row builder must push reassembly-derived <tr>s into findings.reconstructedScript._iocRows'
  );
});

test('_renderSidebar resets findings.reconstructedScript._iocRows per render pass', () => {
  // Lifecycle parity with `ef._iocRows = []` for encoded findings: each
  // render cycle starts with an empty array so repeat renders don't
  // leave stale detached <tr>s in the click-target list.
  assert.match(
    SIDEBAR,
    /f\.reconstructedScript[\s\S]{0,200}?f\.reconstructedScript\._iocRows\s*=\s*\[\s*\]/,
    '_renderSidebar must null out findings.reconstructedScript._iocRows at the start of each render'
  );
});

// ── app-sidebar-focus: verbatim-fallback short-circuit for reassembly IOCs ─

const SIDEBAR_FOCUS = fs.readFileSync(path.join(REPO_ROOT, 'src/app/app-sidebar-focus.js'), 'utf8');

test('_findIOCMatches short-circuits verbatim fallback when ref._fromReassembly', () => {
  // Reassembly-derived IOCs have a `_sourceOffset` / `_sourceLength`
  // pointing at the ENCODED source region that produced the bytes.
  // Their `value` never appears verbatim in `_rawText` — running the
  // substring fallback would find no match (best case) or land on an
  // unrelated plaintext occurrence of the same literal (worst case,
  // and what prompted the bug report).
  const fn = SIDEBAR_FOCUS.match(/_findIOCMatches\s*\([^)]*\)\s*\{[\s\S]*?\n  \},/);
  assert.ok(fn, '_findIOCMatches body must be locatable');
  assert.match(
    fn[0],
    /if\s*\(\s*ref\._fromReassembly\s*\)\s*return\s+matches/,
    '_findIOCMatches must short-circuit after the authoritative-offset push when ref._fromReassembly is true'
  );
});

// ── Bug fix: per-finding preview rejects binary/marshal synopsis envelopes ─

const SIDEBAR_SRC = fs.readFileSync(path.join(REPO_ROOT, 'src/app/app-sidebar.js'), 'utf8');

test('_extractTextPreview guards _deobfuscatedText through EncodedReassembler._isPlaceholderStub', () => {
  // Decoder-emitted synopsis envelopes like
  //   `<binary 45B (likely marshal/pickle): 789c2b4a…>`
  // (see src/decoders/python-obfuscation.js:177,192 and
  // src/decoders/php-obfuscation.js:131,143) are analyst breadcrumbs for
  // non-printable payloads — they are NOT the decoded text. The
  // reassembler already rejects them via `_isPlaceholderStub` when
  // picking the deepest text node; the sidebar's per-finding preview
  // must reject them too, otherwise the green-tier `.enc-decoded-preview`
  // block renders the envelope verbatim.
  //
  // We pin the source-level wiring rather than the DOM output because
  // `app-sidebar.js` is a mixin file that can't be loaded in isolation.
  // The pin has two halves:
  //   1. a local `_isPlaceholderStub` resolves off
  //      `window.EncodedReassembler._isPlaceholderStub` (single source of
  //      truth with the reassembler);
  //   2. `_extractTextPreview` gates its `_deobfuscatedText` return on
  //      `!_isPlaceholderStub(f._deobfuscatedText)` so stub envelopes
  //      fall through to the `decodedBytes` branch.
  assert.match(
    SIDEBAR_SRC,
    /const\s+_isPlaceholderStub\s*=\s*\(\s*window\.EncodedReassembler[\s\S]{0,80}?window\.EncodedReassembler\._isPlaceholderStub\s*\)/,
    '_extractTextPreview must resolve _isPlaceholderStub off window.EncodedReassembler'
  );
  const fn = SIDEBAR_SRC.match(/const\s+_extractTextPreview\s*=\s*\([^)]*\)\s*=>\s*\{[\s\S]*?\n\s{6}\};/);
  assert.ok(fn, '_extractTextPreview helper must be locatable in app-sidebar.js');
  assert.match(
    fn[0],
    /_deobfuscatedText[\s\S]*?!\s*_isPlaceholderStub\s*\(\s*f\._deobfuscatedText\s*\)/,
    '_extractTextPreview must gate its _deobfuscatedText return on !_isPlaceholderStub(...)'
  );
});

// ── Bug fix: analyze() remaps stripped-text _sourceOffset/_sourceLength ───

const REASSEMBLER_SRC = fs.readFileSync(path.join(REPO_ROOT, 'src/encoded-reassembler.js'), 'utf8');

test('analyze() rewrites stripped-text _sourceOffset via mapStrippedToSource', () => {
  // Before the fix, `analyze()` branched on `typeof row.offset === 'number'`
  // — a field `extractInterestingStringsCore` never populates. The core
  // stamps `_sourceOffset`/`_sourceLength` as STRIPPED-text coordinates;
  // without the remap those leaked through as "source" offsets, so the
  // sidebar click-to-focus highlighted unrelated byte ranges. The fix
  // must read the stripped offset from either `row.offset` or
  // `row._sourceOffset`, feed it to `mapStrippedToSource`, and rewrite
  // (or clear) the pair on the row.
  assert.match(
    REASSEMBLER_SRC,
    /const\s+strippedOff\s*=\s*\(typeof\s+row\.offset\s*===\s*['"]number['"]\)\s*\?\s*row\.offset\s*:\s*\(typeof\s+row\._sourceOffset\s*===\s*['"]number['"]\s*\?\s*row\._sourceOffset\s*:\s*null\)/,
    'analyze() must read the stripped offset from row.offset OR row._sourceOffset'
  );
  assert.match(
    REASSEMBLER_SRC,
    /mapStrippedToSource\s*\(\s*reconstructed\s*,\s*strippedOff\s*\)/,
    'analyze() must remap the stripped offset through mapStrippedToSource'
  );
  assert.match(
    REASSEMBLER_SRC,
    /delete\s+row\._sourceOffset[\s\S]{0,80}?delete\s+row\._sourceLength/,
    'analyze() must clear _sourceOffset/_sourceLength on mapping failure (never leak stale stripped-text offsets)'
  );
});

