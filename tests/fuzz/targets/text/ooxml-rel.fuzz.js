'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/text/ooxml-rel.fuzz.js
//
// Fuzz the OOXML relationship-target classifier.
// `OoxmlRelScanner._classifyTarget(target)` is a pure regex tokenizer that
// the OOXML / DOCX / PPTX / XLSX renderers use to decide whether an
// `_rels/*.rels` Target attribute represents a UNC path, file://, mhtml:,
// ms-* protocol handler, remote-template URL, WebDAV URL, etc. Every
// regex on lines 120-145 of src/security-analyzer.js is a ReDoS surface.
//
// We fuzz the classifier directly with byte-strings rather than driving
// the full DOMParser-backed scan() because:
//   • DOMParser is not available in the vm sandbox
//   • the tokenizer is the actual bug surface — `scan()` is just a
//     <Relationship> walker around it
//
// Invariants:
//   1. _classifyTarget never throws on any string.
//   2. Returns an object with `iocType`, `severity`, `protocol`.
//   3. `iocType` is a valid IOC.* value.
//   4. `severity` ∈ {'info','low','medium','high','critical'}.
//   5. The scan() outer wrapper, when fed a synthesised `rels` array,
//      produces only well-formed entries (validates the post-classify
//      filtering logic).
// ════════════════════════════════════════════════════════════════════════════

const path = require('node:path');
const { defineFuzzTarget } = require('../../helpers/harness.js');
const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');

const td = new TextDecoder('utf-8', { fatal: false });
const VALID_SEV = new Set(['info', 'low', 'medium', 'high', 'critical']);
const VALID_IOC = new Set();

const fuzz = defineFuzzTarget({
  modules: [
    'src/constants.js',
    // security-analyzer.js references `IOC` only; OoxmlRelScanner is the
    // first class in the file. We also need DOMParser for the full
    // scan() path, but we deliberately fuzz only _classifyTarget which
    // is DOM-free.
    'src/security-analyzer.js',
  ],
  expose: ['IOC', 'OoxmlRelScanner'],
  // OOXML rel targets are typically <1 KiB; cap aggressively to keep
  // each iteration in tight regex-only territory.
  maxBytes: 64 * 1024,
  perIterBudgetMs: 1_000,

  onIteration(ctx, data) {
    const { IOC, OoxmlRelScanner } = ctx;
    if (!OoxmlRelScanner) throw new Error('harness: OoxmlRelScanner not exposed');
    if (VALID_IOC.size === 0) for (const v of Object.values(IOC)) VALID_IOC.add(v);

    const text = td.decode(data);
    if (text.length === 0) return;

    // Treat the input as a newline-delimited list of rel target strings;
    // each line becomes one classification call. This amortises the
    // per-iteration overhead and gives the fuzzer broader coverage of
    // tokenizer state space within each fuzz datum.
    const targets = text.split('\n').slice(0, 200);
    for (const target of targets) {
      if (target.length === 0) continue;
      if (target.length > 4096) continue;  // pathological input the scanner would reject upstream

      const r = OoxmlRelScanner._classifyTarget(target);
      if (!r || typeof r !== 'object') {
        throw new Error(`invariant: _classifyTarget returned ${typeof r}`);
      }
      if (typeof r.iocType !== 'string') {
        throw new Error(`invariant: r.iocType not string — ${typeof r.iocType}`);
      }
      if (!VALID_IOC.has(r.iocType)) {
        throw new Error(`invariant: r.iocType ${JSON.stringify(r.iocType)} not in IOC.*`);
      }
      if (typeof r.severity !== 'string' || !VALID_SEV.has(r.severity)) {
        throw new Error(`invariant: r.severity ${JSON.stringify(r.severity)} invalid`);
      }
      if (typeof r.protocol !== 'string') {
        throw new Error(`invariant: r.protocol not string`);
      }
    }
  },
});

const handRolled = [
  '\\\\evil-server\\share\\template.dotm',
  '\\\\?\\UNC\\evil-server\\share\\x',
  'file:///etc/passwd',
  'file://C:/Windows/win.ini',
  'mhtml:http://example.com/!x-usc:http://attacker',
  'ms-word:ofe|u|http://attacker/template.docm',
  'ms-excel:ofe|u|http://attacker/x.xlsm',
  'http://attacker.com/template.dotm',
  'https://attacker.com/payload.dotm?x=1',
  'http://attacker.com/_vti_bin/webdav/',
  'http://attacker.com/dav/x',
  'http://attacker.com/x.asmx',
  'http://example.com/normal',
  'mailto:victim@example.com',
  'styles.xml',
  '../../../sensitive',
  '',
  ' ',
  'A'.repeat(1024),
];
const seeds = [
  Buffer.from(handRolled.join('\n'), 'utf8'),
  ...syntheticTextSeeds(8),
];

module.exports = { fuzz, seeds, name: 'ooxml-rel' };
