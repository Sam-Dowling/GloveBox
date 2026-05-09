'use strict';
// ════════════════════════════════════════════════════════════════════════════
// timeline-mapper-no-message-process.test.js — pin the trimmed canonical
// schema for merged Timelines.
//
// The canonical schema (`TIMELINE_CANONICAL_COLS`) is intentionally narrow:
// every entry holds short identifier-shape values (filenames, hostnames,
// usernames, event IDs, severities, IPs). Wide-narrative slots —
// `Message` (multi-KB Event Data / `body` / `description` cells) and
// `Process` (process command lines) — are NOT canonical. Their data
// stays on each source's native column plane where the original column
// name preserves the semantic.
//
// Rationale:
//   1. Multi-KB blobs duplicated row-for-row in a synthetic canonical
//      column balloon the composite store, slow the O(rows × cols)
//      top-values sweep, and saturate the row-search-text cache.
//   2. Forcing every shape through one synthetic Process column produced
//      misclassifications (a CSV's `userAgent` column being pulled into
//      `Process` — UA strings aren't process names).
//   3. The cross-source pivot affordance is preserved by the auto-extract
//      pump's KV-field pass, which surfaces the same fields as named
//      virtual columns the analyst pivots on by name.
//
// What this test pins:
//   • `TIMELINE_CANONICAL_COLS` is exactly the 9 expected entries, in
//     order, with `Process` / `Message` / `__format` absent.
//   • `src/app/timeline/timeline-mapper.js` does not emit
//     `out.Message = …` or `out.Process = …` anywhere — a static-source
//     scan against the file source.
//   • UA aliases (`useragent` / `user_agent` / `user-agent`) are not
//     present as probe-list entries — only as documentation prose
//     explaining why they're NOT probed.
//
// Static-source style mirrors `timeline-view-autoextract-pump-suppress-
// columns.test.js`. A regression that "let me re-add Message" or "let me
// pull UA into User" lights up here without spinning up the full
// Timeline/DOM stack.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { loadModules } = require('../helpers/load-bundle.js');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const MAPPER_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/app/timeline/timeline-mapper.js'), 'utf8');
const CONSTANTS_SRC = fs.readFileSync(
  path.join(REPO_ROOT, 'src/constants.js'), 'utf8');

// Strip line-comments and block-comments (and string literals) from a JS
// source so prose mentioning the forbidden tokens doesn't trip the
// assertions below. Keeps the test focused on executable code.
function stripCommentsAndStrings(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"`])\/\/[^\n]*/g, '$1')
    // Plain double / single / backtick strings on a single line —
    // good enough for the executable-code shape we want to scan
    // (mapper file has no multi-line strings).
    .replace(/"[^"\n]*"/g, '""')
    .replace(/'[^'\n]*'/g, "''")
    .replace(/`[^`\n]*`/g, '``');
}

// ── Constants surface ──────────────────────────────────────────────────────

test('TIMELINE_CANONICAL_COLS is exactly the trimmed 9-entry list, in order', () => {
  const ctx = loadModules(['src/constants.js'], {
    expose: ['TIMELINE_CANONICAL_COLS'],
  });
  assert.deepEqual(Array.from(ctx.TIMELINE_CANONICAL_COLS), [
    '__source', 'Timestamp', 'Host', 'User',
    'EventID', 'Severity', 'Category', 'SourceIP', 'DestIP',
  ]);
  assert.equal(ctx.TIMELINE_CANONICAL_COLS.length, 9);
});

test('TIMELINE_CANONICAL_COLS does NOT include Process or Message', () => {
  const ctx = loadModules(['src/constants.js'], {
    expose: ['TIMELINE_CANONICAL_COLS'],
  });
  assert.equal(ctx.TIMELINE_CANONICAL_COLS.includes('Process'), false,
    '`Process` must NOT be a canonical column — UA / process command lines stay native');
  assert.equal(ctx.TIMELINE_CANONICAL_COLS.includes('Message'), false,
    '`Message` must NOT be a canonical column — multi-KB blobs stay native');
});

test('src/constants.js does NOT declare Process / Message as canonical members', () => {
  // Belt-and-braces source-level pin: the literal `'Process',` /
  // `'Message',` membership lines (or any `'Process'` / `'Message'`
  // string token) must be absent from the executable region of
  // constants.js. (Comments may reference them in prose explaining
  // the trim — those are stripped before the scan.)
  const code = stripCommentsAndStrings(CONSTANTS_SRC);
  assert.ok(!/\bProcess\b/.test(code) || !/canonical/i.test(CONSTANTS_SRC),
    'constants.js code section must not carry a `Process` identifier inside the canonical block');
  // The dedicated TIMELINE_CANONICAL_COLS array literal — scan its
  // raw text (stripped) for the forbidden names.
  const arrMatch = CONSTANTS_SRC.match(/TIMELINE_CANONICAL_COLS\s*=\s*Object\.freeze\(\[([^\]]*)\]\)/);
  assert.ok(arrMatch, 'failed to locate TIMELINE_CANONICAL_COLS array literal in constants.js');
  const arrBody = arrMatch[1];
  assert.ok(!/'Process'/.test(arrBody),
    'TIMELINE_CANONICAL_COLS must not include the `Process` literal');
  assert.ok(!/'Message'/.test(arrBody),
    'TIMELINE_CANONICAL_COLS must not include the `Message` literal');
});

// ── Mapper source — no Process / Message emissions ────────────────────────

test('timeline-mapper.js does not emit `out.Process = …` anywhere', () => {
  // Strip prose so the comment block explaining the trim doesn't
  // trip the scan, then look for the executable shape `out.Process =`.
  // The CSV / EVTX / CloudTrail / CEF / syslog mappers used to set
  // this slot; every site must be gone after the trim.
  const code = stripCommentsAndStrings(MAPPER_SRC);
  assert.ok(
    !/\bout\.Process\s*=/.test(code),
    '`out.Process = …` must not appear in timeline-mapper.js — the canonical schema does not carry a Process slot',
  );
});

test('timeline-mapper.js does not emit `out.Message = …` anywhere', () => {
  // Same shape: every `out.Message =` site (CSV probe, EVTX Event
  // Data assign, CloudTrail err/name, CEF Name + msg ext, LEEF msg,
  // syslog 3164/5424 message column, W3C method+uri, apache-error
  // narrative, Apache CLF request, logfmt msg) must be gone.
  const code = stripCommentsAndStrings(MAPPER_SRC);
  assert.ok(
    !/\bout\.Message\s*=/.test(code),
    '`out.Message = …` must not appear in timeline-mapper.js — wide-narrative columns stay on the native plane',
  );
});

// ── UA aliases — must not appear as probe-list entries ────────────────────

test('UA aliases are not probe-list entries in timeline-mapper.js', () => {
  // Strip strings + comments and verify the executable-code region
  // carries no `'useragent'` / `'user_agent'` / `'user-agent'` token.
  // Comment prose explaining "we deliberately do NOT probe UA" is
  // allowed (and present) — strings + comments are stripped before
  // the scan so only probe-list literals would trigger.
  //
  // Approach: keep the raw source's STRING LITERALS but strip
  // comments. If any of `'useragent'` / `'user_agent'` / `'user-agent'`
  // appears as a quoted string in executable code, the scan trips.
  const noComments = MAPPER_SRC
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"`])\/\/[^\n]*/g, '$1');
  // Probe-list quote characters in this codebase are single quotes.
  for (const alias of ['useragent', 'user_agent', 'user-agent']) {
    const re = new RegExp("'" + alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + "'");
    assert.ok(
      !re.test(noComments),
      `'${alias}' must not appear as a probe-list literal — UA strings stay on the native plane`,
    );
  }
});

// ── Mapper kinds — every entry still resolves ─────────────────────────────

test('every TIMELINE_MAPPERS kind still resolves to a function (no accidental drops)', () => {
  const ctx = loadModules([
    'src/constants.js',
    'src/app/timeline/timeline-parser-helpers.js',
    'src/app/timeline/timeline-mapper.js',
  ], {
    expose: ['TIMELINE_MAPPERS', 'timelineMapperFor'],
  });
  const kinds = [
    'csv', 'tsv', 'log', 'evtx',
    'syslog3164', 'syslog5424',
    'zeek', 'jsonl', 'cloudtrail',
    'cef', 'leef', 'logfmt',
    'w3c', 'apache-error', 'access-log',
  ];
  for (const k of kinds) {
    assert.equal(typeof ctx.TIMELINE_MAPPERS[k], 'function',
      `mapper for kind ${k} must still be defined after the canonical-set trim`);
  }
});

// ── Behavioural pin — round-trip a UA-bearing CSV through the mapper ───────

test('CSV with userAgent + body columns produces no canonical Process / Message cells', () => {
  // End-to-end behavioural guard — even if a future refactor accidentally
  // re-introduces a probe alias, the mapper's output contract must keep
  // Process / Message empty.
  const ctx = loadModules([
    'src/constants.js',
    'src/app/timeline/timeline-parser-helpers.js',
    'src/app/timeline/timeline-mapper.js',
  ], {
    expose: ['TIMELINE_MAPPERS'],
  });
  const src = {
    formatKind: 'csv',
    sourceLabel: 'audit.csv',
    baseColumns: ['Timestamp', 'UserId', 'userAgent', 'body', 'message', 'description'],
  };
  const out = ctx.TIMELINE_MAPPERS.csv(src, [
    '2026-04-08T18:37:13Z',
    'alice@example.com',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
    '{"http":{"method":"GET"}}',
    'login ok',
    'short narrative',
  ]);
  // Canonical surface for this row:
  assert.equal(out.Timestamp, '2026-04-08T18:37:13Z');
  assert.equal(out.User, 'alice@example.com');
  // Every wide-narrative slot stays empty on the canonical plane:
  assert.equal(out.Process, undefined);
  assert.equal(out.Message, undefined);
});
