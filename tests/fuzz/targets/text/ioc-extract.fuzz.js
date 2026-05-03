'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/text/ioc-extract.fuzz.js
//
// Fuzz the regex-only IOC extraction core. This is the same function the
// production worker bundle (`src/workers/ioc-extract.worker.js`) calls
// from the main thread; it has ~15 regex families covering URL / email /
// IPv4 / IPv6 / UNC / Win-path / Unix-path / registry-key / defang
// variants / crypto-addr / secrets.
//
// Why this target exists:
//   • Historical ReDoS pain — see commit refs in AGENTS.md:
//       716d532  bound `invisRe` to {2,64}
//       0f71338  per-finder budget + tightened backtick/rot13 patterns
//       1388c1c  three rules rewritten for bounded quantifiers
//       b685985  Zip Slip / Tar Slip per-entry IOCs
//   • Pure function, no DOM, no async — ideal Jazzer.js shape.
//
// Invariants asserted per iteration:
//   1. Function returns within `defineFuzzTarget`'s wall-clock budget
//      (default 2 500 ms). A budget violation surfaces as a crash even
//      if the function eventually returns successfully.
//   2. Every emitted IOC has `type` in `IOC.*` (frozen enum) and a
//      non-empty `url` (legacy field name; carries the IOC value).
//   3. Per-type cap (200) is honoured — `results.length` ≤ Σ caps.
//   4. The function never throws on a UTF-8 string of length ≤ MAX_BYTES.
//      Watchdog timeouts ARE acceptable (they're the safety envelope).
// ════════════════════════════════════════════════════════════════════════════

const path = require('node:path');
const { defineFuzzTarget } = require('../../helpers/harness.js');
const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');
const fs = require('node:fs');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');

// Decode bytes to a JS string for the IOC scanner. Inputs longer than
// 1 MiB are truncated by the harness (maxBytes); within that, we tolerate
// arbitrary byte sequences by using TextDecoder('utf-8', {fatal:false}),
// matching the production path (`extractInterestingStringsCore` is fed
// `_rawText` which is already lf-normalised UTF-8 from the renderer).
const td = new TextDecoder('utf-8', { fatal: false });

const VALID_IOC_TYPES = new Set();  // populated lazily after first iter

const fuzz = defineFuzzTarget({
  modules: [
    'src/constants.js',
    'src/util/url-normalize.js',
    'src/ioc-extract.js',
  ],
  // 1 MiB — half of FINDER_MAX_INPUT_BYTES. Plenty for ReDoS surface;
  // larger inputs stop being interesting (regex engines win) and slow
  // the corpus iteration rate.
  maxBytes: 1 * 1024 * 1024,
  perIterBudgetMs: 2_500,

  onIteration(ctx, data) {
    const { extractInterestingStringsCore, IOC } = ctx;
    if (typeof extractInterestingStringsCore !== 'function') {
      throw new Error('harness: extractInterestingStringsCore not exposed by load-bundle');
    }
    if (!IOC || typeof IOC !== 'object') {
      throw new Error('harness: IOC enum not exposed by load-bundle');
    }
    if (VALID_IOC_TYPES.size === 0) {
      for (const v of Object.values(IOC)) VALID_IOC_TYPES.add(v);
    }

    const text = td.decode(data);

    // Call the function under test. Any thrown error (other than the
    // documented watchdog abort) propagates out and is treated as a
    // crash by the harness.
    const result = extractInterestingStringsCore(text, {
      existingValues: [],
      vbaModuleSources: [],
    });

    // Invariant 1: shape.
    if (!result || typeof result !== 'object') {
      throw new Error(`invariant: result not object — got ${typeof result}`);
    }
    if (!Array.isArray(result.findings)) {
      throw new Error('invariant: result.findings not array');
    }

    // Invariant 2: every emitted IOC has a valid type and value.
    for (const f of result.findings) {
      if (!f || typeof f !== 'object') {
        throw new Error(`invariant: finding entry not object — got ${typeof f}`);
      }
      if (!VALID_IOC_TYPES.has(f.type)) {
        throw new Error(`invariant: emitted IOC type ${JSON.stringify(f.type)} not in IOC.*`);
      }
      if (typeof f.url !== 'string' || f.url.length === 0) {
        throw new Error(`invariant: IOC.${f.type} has empty/missing value`);
      }
      if (f.url.length > 400) {
        throw new Error(`invariant: IOC.${f.type} value exceeds 400 chars (${f.url.length}) — add() should reject`);
      }
    }

    // Invariant 3: per-type cap (200) honoured.
    const counts = new Map();
    for (const f of result.findings) {
      counts.set(f.type, (counts.get(f.type) || 0) + 1);
    }
    for (const [type, n] of counts) {
      if (n > 200) {
        throw new Error(`invariant: per-type cap exceeded — IOC.${type} has ${n} > 200 entries`);
      }
    }
  },
});

// ── Seeds ───────────────────────────────────────────────────────────────────
// Pull text-shaped fixtures from a few directories that historically
// triggered IOC pushes, plus a handful of synthetic shapes covering
// edge categories (defanged URLs, IPv6, UNC, base64-as-text, etc.).
function loadTextSeeds() {
  const seeds = [];
  const dirs = [
    path.join(REPO_ROOT, 'examples', 'encoded-payloads'),
    path.join(REPO_ROOT, 'examples', 'windows-scripts'),
    path.join(REPO_ROOT, 'examples', 'email'),
    path.join(REPO_ROOT, 'examples', 'web'),
  ];
  const exts = new Set([
    '.txt', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.html', '.htm',
    '.eml', '.csv', '.log', '.json', '.url',
  ]);
  for (const d of dirs) {
    if (!fs.existsSync(d)) continue;
    for (const name of fs.readdirSync(d).sort()) {
      const p = path.join(d, name);
      let st;
      try { st = fs.statSync(p); } catch (_) { continue; }
      if (!st.isFile()) continue;
      if (!exts.has(path.extname(name).toLowerCase())) continue;
      let buf;
      try { buf = fs.readFileSync(p); } catch (_) { continue; }
      if (buf.length > 256 * 1024) buf = buf.subarray(0, 256 * 1024);
      seeds.push(buf);
      if (seeds.length >= 24) return seeds;
    }
  }
  return seeds;
}

const seeds = [...loadTextSeeds(), ...syntheticTextSeeds(8)];

module.exports = { fuzz, seeds, name: 'ioc-extract' };
