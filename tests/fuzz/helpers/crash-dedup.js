'use strict';
// ════════════════════════════════════════════════════════════════════════════
// crash-dedup.js — stack-hash deduplication for fuzz crashes.
//
// Goal: turn a thrown Error into a stable 16-hex digest so two crashes
// from the same root cause share a directory under
// `dist/fuzz-crashes/<target>/<sha>/`. The hash MUST be:
//
//   • stable across runs of the same checkout (no line-number drift)
//   • stable across machines (no absolute paths)
//   • stable across input sizes (no input-derived strings in the message)
//   • unstable across truly different bugs (different throw site → different
//     hash, even within the same target)
//
// We achieve that by:
//   1. Reading `err.stack`, splitting into frames.
//   2. Dropping any frame whose path contains `/tests/fuzz/` or
//      `node:internal/` or `vm.runInContext` — those are harness frames,
//      not the bug.
//   3. For each remaining frame, keeping only the function name +
//      basename of the source file. Line + column numbers are dropped
//      because a `git pull` shifts every line number by ±N and would
//      otherwise dedup-break the entire crash database.
//   4. Concatenating the residue with `err.name + ': ' + err.message`
//      (with input-derived numbers redacted), SHA-256 hashing the result,
//      and returning the first 16 hex chars.
//
// 16 hex chars = 64 bits of namespace. Birthday-collision risk at 1 M
// distinct crashes ≈ 1 in 2^32, well below any plausible per-target
// crash count.
// ════════════════════════════════════════════════════════════════════════════

const crypto = require('node:crypto');
const path = require('node:path');

// Frames to ignore when computing the hash. Each entry is a substring;
// any frame whose `frame.text` contains it is dropped. Order doesn't
// matter — this is a set membership test.
const IGNORED_FRAME_SUBSTRINGS = [
  '/tests/fuzz/helpers/',
  'node:internal/',
  'load-bundle.js',
  'vm.runInContext',
  'runMicrotasks',
  'processTicksAndRejections',
  '/node_modules/@jazzer.js/',
];

// Numbers in error messages are usually input-derived (offsets, lengths,
// codepoints). Replace them with `<N>` so two crashes that differ only
// in offset hash to the same digest.
const NUMERIC_RE = /\b\d+\b/g;
// Hex literals (0xABCD, byte sequences) are also input-derived.
const HEX_RE = /\b0x[0-9a-fA-F]+\b/g;

/**
 * Parse a V8 stack string into structured frames. We intentionally use
 * regex parsing rather than `Error.prepareStackTrace` because the latter
 * is process-global and would interfere with Node's default stack
 * formatting elsewhere in the test suite.
 *
 * @param {string} stack
 * @returns {Array<{text:string, fnName:string, file:string}>}
 */
function parseStack(stack) {
  if (typeof stack !== 'string' || stack.length === 0) return [];
  const lines = stack.split('\n');
  const frames = [];
  // Skip the first line if it looks like the error message (V8 prepends
  // "Foo: bar" before the stack frames).
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!/^\s*at\s/.test(line)) continue;
    // Two shapes:
    //   "    at Foo.bar (/abs/path/to/file.js:12:34)"
    //   "    at /abs/path/to/file.js:12:34"
    const m1 = /^\s*at\s+(.+?)\s+\((.+):\d+:\d+\)\s*$/.exec(line);
    const m2 = /^\s*at\s+(.+):\d+:\d+\s*$/.exec(line);
    let fnName = '<anon>';
    let file = '';
    if (m1) {
      fnName = m1[1];
      file = m1[2];
    } else if (m2) {
      file = m2[1];
    } else {
      // Unknown shape — keep the whole line text (verbatim) so two
      // identical exotic frames still dedup to the same hash.
      frames.push({ text: line, fnName: '<exotic>', file: '' });
      continue;
    }
    frames.push({ text: line, fnName, file });
  }
  return frames;
}

/**
 * Reduce a frame to its hash-relevant tokens. Keeps function name +
 * basename of the source file. Drops absolute path + line + column.
 */
function frameDigestToken(frame) {
  const base = frame.file ? path.basename(frame.file).replace(/:\d+(?::\d+)?$/, '') : '';
  return `${frame.fnName}@${base}`;
}

/**
 * Determine whether a stack frame should contribute to the hash.
 */
function frameIsRelevant(frame) {
  for (const sub of IGNORED_FRAME_SUBSTRINGS) {
    if (frame.text.indexOf(sub) !== -1) return false;
  }
  return true;
}

/**
 * Redact input-derived tokens from an error message before hashing.
 */
function redactMessage(msg) {
  if (typeof msg !== 'string') return '';
  return msg.replace(HEX_RE, '<X>').replace(NUMERIC_RE, '<N>');
}

/**
 * Compute a stable 16-hex stack digest for an Error.
 *
 * @param {Error} err
 * @param {object} [opts]
 * @param {number} [opts.maxFrames=8]  cap how many frames participate
 * @returns {string} 16 lowercase hex chars
 */
function hashStack(err, opts) {
  const o = opts || {};
  const maxFrames = (typeof o.maxFrames === 'number' && o.maxFrames > 0)
    ? o.maxFrames : 8;

  const name = (err && err.name) ? String(err.name) : 'Error';
  const message = (err && err.message) ? String(err.message) : '';
  const stack = (err && err.stack) ? String(err.stack) : '';

  const frames = parseStack(stack)
    .filter(frameIsRelevant)
    .slice(0, maxFrames)
    .map(frameDigestToken);

  const digestInput = [
    name,
    redactMessage(message),
    ...frames,
  ].join('\n');

  return crypto.createHash('sha256').update(digestInput).digest('hex').slice(0, 16);
}

/**
 * Pull a normalised "abort signal" view off an Error. Watchdog timeouts
 * carry `_watchdogTimeout=true`; AbortError instances carry `name`. Both
 * count as "expected aborts" and are NOT crashes the harness reports.
 */
function normaliseError(err) {
  const n = {
    _watchdogTimeout: !!(err && err._watchdogTimeout),
    name: (err && err.name) ? String(err.name) : 'Error',
    code: err && err.code ? String(err.code) : null,
  };
  if (n.name === 'AbortError') n._watchdogTimeout = true;
  return n;
}

module.exports = {
  hashStack,
  normaliseError,
  parseStack,
  redactMessage,
};
