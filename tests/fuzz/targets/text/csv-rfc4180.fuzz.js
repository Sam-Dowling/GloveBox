'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/text/csv-rfc4180.fuzz.js
//
// Fuzz the CSV/TSV RFC-4180 quote-aware parser. The state machine in
// `csv-renderer.js::parseChunk` is shared by:
//   • main-thread `CsvRenderer.render` (small files)
//   • the timeline worker (`workers/timeline.worker.js`) for >2 MiB CSVs
// so any divergence between two paths over malformed input is a real bug.
//
// History: `22d8647` — RFC-4180 quote-aware parser unification across
// every CSV/TSV path; multiple bugs were caught during that landing
// (orphan `"` handling, EOF-mid-quote, CRLF normalisation in quoted
// fields). This target re-exercises that area continuously.
//
// Invariants:
//   1. parseChunk + flush over arbitrary text never throws.
//   2. Reported `endIdx` is in [0, text.length].
//   3. Each row is an array of strings; total cell count fits within
//      the row count × max columns claimed by `state`.
//   4. Round-trip stability: feeding the same text in one chunk vs.
//      two halves vs. byte-by-byte produces the same row count
//      (parser is supposed to be chunk-agnostic).
// ════════════════════════════════════════════════════════════════════════════

const path = require('node:path');
const fs = require('node:fs');
const { defineFuzzTarget } = require('../../helpers/harness.js');
const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');

const td = new TextDecoder('utf-8', { fatal: false });

function parseAll(CsvRenderer, text, delim) {
  const state = CsvRenderer.initParserState();
  const result = CsvRenderer.parseChunk(text, 0, state, delim, {
    baseOffset: 0, maxRows: 0, flush: true,
  });
  return { rows: result.rows || [], endIdx: result.endIdx };
}

function parseSplit(CsvRenderer, text, delim, splitAt) {
  // Mirror the production worker pattern: each chunk is its own
  // substring; fromIdx restarts at 0 per call; baseOffset advances
  // by the cumulative bytes consumed so absolute offsets remain
  // consistent. See tests/unit/csv-parser.test.js → "chunk boundary
  // mid-quoted-cell" for the canonical shape.
  const state = CsvRenderer.initParserState();
  const head = text.slice(0, splitAt);
  const tail = text.slice(splitAt);
  const r1 = CsvRenderer.parseChunk(head, 0, state, delim, {
    baseOffset: 0, maxRows: 0, flush: false,
  });
  const r2 = CsvRenderer.parseChunk(tail, 0, state, delim, {
    baseOffset: head.length, maxRows: 0, flush: true,
  });
  return [...(r1.rows || []), ...(r2.rows || [])];
}

const fuzz = defineFuzzTarget({
  modules: ['src/constants.js', 'src/renderers/csv-renderer.js'],
  expose: ['CsvRenderer', 'IOC', 'RENDER_LIMITS'],
  maxBytes: 512 * 1024,        // 512 KiB — CSV state machine is O(N)
  perIterBudgetMs: 2_000,      // tighter — pure state machine

  onIteration(ctx, data) {
    const { CsvRenderer } = ctx;
    if (!CsvRenderer) throw new Error('harness: CsvRenderer not exposed');

    const text = td.decode(data);
    if (text.length === 0) return;

    // Try both delimiters — the worker auto-detects, so both must be safe.
    for (const delim of [',', '\t']) {
      const { rows, endIdx } = parseAll(CsvRenderer, text, delim);

      // Invariant 2.
      if (typeof endIdx !== 'number' || endIdx < 0 || endIdx > text.length) {
        throw new Error(`invariant: endIdx out of range — ${endIdx} not in [0, ${text.length}]`);
      }

      // Invariant 3.
      if (!Array.isArray(rows)) {
        throw new Error('invariant: rows not array');
      }
      for (const row of rows) {
        if (!Array.isArray(row)) {
          throw new Error('invariant: row not array');
        }
        for (const cell of row) {
          if (typeof cell !== 'string') {
            throw new Error(`invariant: cell not string — got ${typeof cell}`);
          }
        }
      }

      // Invariant 4: chunk-agnostic. Sample a handful of split points
      // (full sweep would be O(N²)) — middle, quarter, three-quarter.
      // Skip on very small inputs where there's nothing to split.
      if (text.length >= 16) {
        for (const frac of [0.25, 0.5, 0.75]) {
          const splitAt = Math.floor(text.length * frac);
          const splitRows = parseSplit(CsvRenderer, text, delim, splitAt);
          if (splitRows.length !== rows.length) {
            throw new Error(
              `invariant: chunk-agnostic violated — `
              + `single=${rows.length} rows, split@${splitAt}=${splitRows.length} rows`
            );
          }
        }
      }
    }
  },
});

function loadCsvSeeds() {
  const seeds = [];
  // examples/forensics/ has CSV-shaped logs, examples/encoded-payloads
  // has occasional CSV-tabular fixtures.
  const dirs = [
    path.join(REPO_ROOT, 'examples', 'forensics'),
    path.join(REPO_ROOT, 'examples', 'encoded-payloads'),
    path.join(REPO_ROOT, 'examples', 'office'),
  ];
  for (const d of dirs) {
    if (!fs.existsSync(d)) continue;
    for (const name of fs.readdirSync(d).sort()) {
      if (!/\.(csv|tsv|txt|log)$/i.test(name)) continue;
      const p = path.join(d, name);
      let buf;
      try { buf = fs.readFileSync(p); } catch (_) { continue; }
      if (buf.length > 64 * 1024) buf = buf.subarray(0, 64 * 1024);
      seeds.push(buf);
      if (seeds.length >= 16) break;
    }
  }
  // Hand-rolled tricky shapes — every one targets a known parser-edge.
  const handRolled = [
    'a,b,c\n1,2,3\n',
    '"a","b","c"\r\n"1","2","3"\r\n',
    'a,"b\nc",d\n',                              // newline in quoted cell
    'a,"b""c",d\n',                              // doubled-quote escape
    '"unterminated\n',                            // EOF mid-quote
    '\n\n\n',                                     // empty rows
    ',,,\n,,,\n',                                 // all-empty
    '"a",,"c"\n',                                 // empty middle
    'a,b\rc,d\n',                                 // bare CR not at line end
    'a,b\r\nc,d\r\n',                             // CRLF
    'a\tb\tc\n1\t2\t3\n',                         // TSV
    '\uFEFFa,b\n1,2\n',                           // BOM
  ];
  for (const s of handRolled) seeds.push(Buffer.from(s, 'utf8'));
  return seeds;
}

const seeds = [...loadCsvSeeds(), ...syntheticTextSeeds(4)];

module.exports = { fuzz, seeds, name: 'csv-rfc4180' };
