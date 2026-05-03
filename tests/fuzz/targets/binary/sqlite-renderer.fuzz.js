'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/binary/sqlite-renderer.fuzz.js
//
// Fuzz `SqliteRenderer.prototype.analyzeForSecurity(buffer, fileName)` —
// invokes `_parseDb(bytes)` which walks the SQLite file format: 100-byte
// header → page-size-determined B-tree pages → schema (`sqlite_master`)
// → known browser-history tables. Length-field arithmetic on every page;
// classic fuzz target.
//
// Only `analyzeForSecurity` is in scope — `render()` builds DOM. The
// renderer also has a separate `_renderTable` path but that's render-side.
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { loadSeeds } = require('../../helpers/seed-corpus.js');

const VALID_RISK = new Set(['safe', 'low', 'medium', 'high', 'critical']);
const VALID_IOC_VALUES = new Set();

const fuzz = defineFuzzTarget({
  modules: [
    'src/constants.js',
    'src/renderers/sqlite-renderer.js',
  ],
  expose: ['IOC', 'SqliteRenderer'],

  maxBytes: 8 * 1024 * 1024,
  perIterBudgetMs: 5_000,

  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    if (err.message.startsWith('parser-limit:')) return true;
    if (err.message.startsWith('aggregate-budget:')) return true;
    return false;
  },

  onIteration(ctx, data) {
    const { IOC, SqliteRenderer } = ctx;
    if (!SqliteRenderer) throw new Error('harness: SqliteRenderer not exposed');
    if (VALID_IOC_VALUES.size === 0) {
      for (const v of Object.values(IOC)) VALID_IOC_VALUES.add(v);
    }

    const r = new SqliteRenderer();
    const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    const findings = r.analyzeForSecurity(buf, 'fuzz.sqlite');

    if (!findings || typeof findings !== 'object') {
      throw new Error('invariant: analyzeForSecurity returned non-object');
    }
    if (typeof findings.risk !== 'string' || !VALID_RISK.has(findings.risk)) {
      throw new Error(`invariant: findings.risk ${JSON.stringify(findings.risk)} invalid`);
    }
    for (const k of ['externalRefs', 'autoExec', 'modules']) {
      if (!Array.isArray(findings[k])) {
        throw new Error(`invariant: findings.${k} not array (got ${typeof findings[k]})`);
      }
    }
    if (findings.metadata && typeof findings.metadata !== 'object') {
      throw new Error('invariant: findings.metadata not object');
    }
    for (const ref of findings.externalRefs) {
      if (!ref || typeof ref !== 'object') {
        throw new Error('invariant: externalRef not object');
      }
      if (ref.type !== undefined && !VALID_IOC_VALUES.has(ref.type)) {
        throw new Error(
          `invariant: externalRef.type ${JSON.stringify(ref.type)} not in IOC.*`,
        );
      }
    }
  },
});

const seeds = loadSeeds({
  dirs: ['forensics'],
  extensions: ['sqlite', 'sqlite3', 'db'],
  perFileMaxBytes: 2 * 1024 * 1024,
  totalMaxBytes: 8 * 1024 * 1024,
  maxSeeds: 16,
});

// Synthetic minimal SQLite file: 100-byte header with magic
// "SQLite format 3\0" + page_size=4096 + everything-else=0. No real
// pages follow — drives the early-bailout path.
function syntheticSqliteHeader() {
  const buf = Buffer.alloc(100);
  buf.write('SQLite format 3\0', 0, 'binary');
  buf.writeUInt16BE(4096, 16);  // page_size
  // All other fields zero.
  return buf;
}

seeds.push(syntheticSqliteHeader());

module.exports = { fuzz, seeds, name: 'sqlite-renderer' };
