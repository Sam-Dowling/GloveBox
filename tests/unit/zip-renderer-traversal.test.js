'use strict';
// zip-renderer-traversal.test.js
//
// Coverage for `ZipRenderer._findTraversalEntries(entries)` — the
// canonical Zip-Slip / Tar-Slip classifier shared between
// `_checkWarnings` (aggregate sidebar warning) and
// `_analyzeArchiveEntries` (per-entry IOC.FILE_PATH push).
//
// Three classes of escape are recognised:
//
//   • parent-traversal  literal `..` segment after slash-normalisation
//                       (`../etc/passwd`, `foo/../../bar`, `..\\evil`)
//   • absolute-path     leading `/`, `\`, or drive-letter prefix
//   • symlink-traversal tar entry whose `linkName` itself escapes
//
// Crucially, plain filenames containing `..` as a non-segment substring
// (e.g. `foo..bar.txt`, `..hidden`) MUST NOT be flagged — that's the
// regression we're guarding against from the historical
// `p.includes('../')` shape.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/constants.js', 'src/archive-analysis.js', 'src/renderers/zip-renderer.js'], {
  expose: ['ZipRenderer', 'ArchiveAnalysis'],
});
const { ZipRenderer } = ctx;

test('zip-renderer: parent-traversal segments flagged', () => {
  const hits = ZipRenderer._findTraversalEntries([
    { path: '../etc/passwd', dir: false },
    { path: 'foo/../../bar', dir: false },
    { path: '..\\..\\evil.exe', dir: false },
    { path: 'a/b/..', dir: false },
    { path: '..', dir: false },
  ]);
  assert.equal(hits.length, 5);
  for (const h of hits) assert.equal(h.kind, 'parent-traversal');
});

test('zip-renderer: absolute paths flagged', () => {
  const hits = ZipRenderer._findTraversalEntries([
    { path: '/etc/passwd', dir: false },
    { path: '\\Windows\\System32\\evil.dll', dir: false },
    { path: 'C:\\Users\\victim\\evil.bat', dir: false },
    { path: 'D:/share/payload.exe', dir: false },
  ]);
  assert.equal(hits.length, 4);
  for (const h of hits) assert.equal(h.kind, 'absolute-path');
});

test('zip-renderer: tar symlink-traversal flagged', () => {
  const hits = ZipRenderer._findTraversalEntries([
    { path: 'pkg/link', dir: false, linkName: '../../etc/passwd' },
    { path: 'pkg/abs', dir: false, linkName: '/etc/shadow' },
    { path: 'pkg/winabs', dir: false, linkName: 'C:\\Windows\\evil' },
    { path: 'pkg/inside', dir: false, linkName: 'sibling-file' },     // benign
  ]);
  assert.equal(hits.length, 3);
  for (const h of hits) assert.equal(h.kind, 'symlink-traversal');
  // Targets are surfaced for analyst pivot.
  assert.equal(hits[0].target, '../../etc/passwd');
});

test('zip-renderer: false-positive shapes left alone', () => {
  // Historical `p.includes('../')` flagged any of these. The segment-
  // aware classifier must NOT.
  const hits = ZipRenderer._findTraversalEntries([
    { path: 'foo..bar.txt', dir: false },
    { path: '..hidden/readme', dir: false },
    { path: 'archive..backup/data', dir: false },
    { path: 'normal/path/file.txt', dir: false },
    { path: 'a/b/c.tar.gz', dir: false },
    { path: '.dotfile', dir: false },
    { path: '..', dir: true },                  // a directory entry literally named `..`
  ]);
  // `..` as a directory entry IS a traversal attempt regardless of the
  // dir bit — extractors that follow it write to the parent. The other
  // six are pure-substring false positives that must stay clean.
  assert.equal(hits.length, 1);
  assert.equal(hits[0].path, '..');
});

test('zip-renderer: empty/missing inputs handled', () => {
  assert.equal(ZipRenderer._findTraversalEntries([]).length, 0);
  assert.equal(ZipRenderer._findTraversalEntries(null).length, 0);
  assert.equal(ZipRenderer._findTraversalEntries(undefined).length, 0);
});

test('zip-renderer: cap-aware aggregation is the caller\'s job', () => {
  // The classifier itself does not cap — `_analyzeArchiveEntries` does.
  // 100 traversal entries should all come back; the cap of 40 is
  // enforced one level up.
  const many = [];
  for (let i = 0; i < 100; i++) many.push({ path: `../evil-${i}`, dir: false });
  const hits = ZipRenderer._findTraversalEntries(many);
  assert.equal(hits.length, 100);
});
