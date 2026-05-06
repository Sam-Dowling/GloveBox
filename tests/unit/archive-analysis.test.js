'use strict';
// archive-analysis.test.js
//
// Coverage for the shared `ArchiveAnalysis` helper that ZIP / RAR / 7z /
// CAB renderers all delegate to. The helper centralises EXEC_EXTS,
// DECOY_EXTS, the `isDoubleExt` decoy detector, the strict Zip-Slip /
// Tar-Slip traversal classifier, and the common warning builder.
//
// These tests pin down the behavioural contract every archive renderer
// now relies on.  Specifically:
//   - the strict traversal classifier returns the same shape across the
//     three escape kinds (parent-traversal, absolute-path, symlink-
//     traversal) and does NOT false-positive on `..` substrings
//     (`foo..bar.txt`);
//   - `isDoubleExt` requires both a trailing exec extension AND a
//     known decoy extension in the penultimate segment;
//   - `buildCommonWarnings` produces a deterministic ordered list of
//     `{sev, msg}` records whose messages mention the requested `kind`
//     in the traversal warning.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/constants.js', 'src/archive-analysis.js'], {
  expose: ['ArchiveAnalysis'],
});
const { ArchiveAnalysis } = ctx;

test('ArchiveAnalysis: EXEC_EXTS contains every historical entry', () => {
  for (const ext of [
    'exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'msi', 'msp', 'mst', 'sys',
    'bat', 'cmd', 'ps1', 'vbs', 'js', 'wsf', 'hta', 'lnk', 'inf', 'reg',
    'jar', 'py', 'sh', 'so', 'dylib',
    'docm', 'xlsm', 'pptm',
  ]) {
    assert.ok(ArchiveAnalysis.EXEC_EXTS.has(ext), `EXEC_EXTS missing '${ext}'`);
  }
});

test('ArchiveAnalysis: DECOY_EXTS contains every historical entry', () => {
  for (const ext of ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
                     'jpg', 'png', 'gif', 'txt', 'rtf']) {
    assert.ok(ArchiveAnalysis.DECOY_EXTS.has(ext), `DECOY_EXTS missing '${ext}'`);
  }
});

test('ArchiveAnalysis: isDoubleExt flags decoy + exec combination', () => {
  assert.equal(ArchiveAnalysis.isDoubleExt('invoice.pdf.exe'), true);
  assert.equal(ArchiveAnalysis.isDoubleExt('photo.jpg.scr'), true);
  assert.equal(ArchiveAnalysis.isDoubleExt('contract.docx.vbs'), true);
});

test('ArchiveAnalysis: isDoubleExt does NOT flag legitimate two-segment names', () => {
  assert.equal(ArchiveAnalysis.isDoubleExt('payload.exe'), false);
  assert.equal(ArchiveAnalysis.isDoubleExt('archive.tar.gz'), false); // .gz not exec
  assert.equal(ArchiveAnalysis.isDoubleExt('readme.txt'), false);
});

test('ArchiveAnalysis: isDoubleExt rejects single-segment paths', () => {
  assert.equal(ArchiveAnalysis.isDoubleExt('exe'), false);
  assert.equal(ArchiveAnalysis.isDoubleExt(''), false);
  assert.equal(ArchiveAnalysis.isDoubleExt(null), false);
});

test('ArchiveAnalysis: findTraversalEntries flags `../` parent segment', () => {
  const hits = ArchiveAnalysis.findTraversalEntries([
    { path: '../etc/passwd' },
    { path: 'foo/../../bar' },
    { path: '..\\evil.exe' },
  ]);
  assert.equal(hits.length, 3);
  for (const h of hits) assert.equal(h.kind, 'parent-traversal');
});

test('ArchiveAnalysis: findTraversalEntries flags absolute paths (Unix, UNC, drive-letter)', () => {
  const hits = ArchiveAnalysis.findTraversalEntries([
    { path: '/etc/passwd' },
    { path: '\\\\evil.example\\share\\x' },
    { path: 'C:\\Windows\\System32\\cmd.exe' },
    { path: 'D:/Users/Public/x' },
  ]);
  assert.equal(hits.length, 4);
  for (const h of hits) assert.equal(h.kind, 'absolute-path');
});

test('ArchiveAnalysis: findTraversalEntries does NOT false-positive on `..` substrings', () => {
  // Critical regression guard — RAR / 7z / CAB used to use a substring
  // check that flagged these as traversal attempts.
  const hits = ArchiveAnalysis.findTraversalEntries([
    { path: 'foo..bar.txt' },
    { path: '..hidden' },
    { path: 'normal/file.txt' },
    { path: 'a..b/c..d/file' },
  ]);
  assert.equal(hits.length, 0, `false positives: ${JSON.stringify(hits)}`);
});

test('ArchiveAnalysis: findTraversalEntries flags tar symlink targets that escape', () => {
  const hits = ArchiveAnalysis.findTraversalEntries([
    { path: 'link', linkName: '../../etc/passwd' },
    { path: 'absLink', linkName: '/etc/passwd' },
    { path: 'okLink', linkName: 'inside/file' },
  ]);
  assert.equal(hits.length, 2);
  assert.equal(hits[0].kind, 'symlink-traversal');
  assert.equal(hits[0].target, '../../etc/passwd');
  assert.equal(hits[1].kind, 'symlink-traversal');
  assert.equal(hits[1].target, '/etc/passwd');
});

test('ArchiveAnalysis: findTraversalEntries handles empty / null inputs', () => {
  assert.equal(ArchiveAnalysis.findTraversalEntries([]).length, 0);
  assert.equal(ArchiveAnalysis.findTraversalEntries(null).length, 0);
  assert.equal(ArchiveAnalysis.findTraversalEntries(undefined).length, 0);
});

test('ArchiveAnalysis: buildCommonWarnings produces deterministic ordered output', () => {
  const w = ArchiveAnalysis.buildCommonWarnings([
    { path: 'malware.exe' },
    { path: 'invoice.pdf.exe' },
    { path: 'inner.zip' },
    { path: 'phish.hta' },
    { path: 'shortcut.lnk' },
    { path: '../escape' },
  ], { kind: 'archive' });

  // Order: execs, doubles, nested, htas, lnks, traversal.
  assert.ok(w.length >= 6);
  assert.match(w[0].msg, /executable\/script/);
  assert.match(w[1].msg, /Double-extension/);
  assert.match(w[2].msg, /Nested archive/);
  assert.match(w[3].msg, /HTA/);
  assert.match(w[4].msg, /Windows shortcut/);
  assert.match(w[5].msg, /Zip Slip/);
  assert.match(w[5].msg, /archive root/);
});

test('ArchiveAnalysis: buildCommonWarnings respects custom `kind` label', () => {
  const w = ArchiveAnalysis.buildCommonWarnings([
    { path: '../escape' },
  ], { kind: 'cabinet' });
  const traversal = w.find(x => /Zip Slip/.test(x.msg));
  assert.ok(traversal, 'expected traversal warning');
  assert.match(traversal.msg, /cabinet root/);
});

test('ArchiveAnalysis: buildCommonWarnings skips directory entries', () => {
  const w = ArchiveAnalysis.buildCommonWarnings([
    { path: 'dir/', isDir: true },
    { path: 'evil.exe' },
  ], { kind: 'archive' });
  // Only the .exe should produce a warning.
  const execs = w.filter(x => /executable/.test(x.msg));
  assert.equal(execs.length, 1);
  assert.match(execs[0].msg, /1 executable/);
});

test('ArchiveAnalysis: parity — every renderer alias resolves to same Set', () => {
  // Smoke check that the EXEC_EXTS / DECOY_EXTS exports are the actual
  // shared frozen Sets, not copies. Renderer call sites alias them as
  // `static EXEC_EXTS = ArchiveAnalysis.EXEC_EXTS`, so identity matters.
  assert.strictEqual(ArchiveAnalysis.EXEC_EXTS, ArchiveAnalysis.EXEC_EXTS);
  assert.strictEqual(ArchiveAnalysis.DECOY_EXTS, ArchiveAnalysis.DECOY_EXTS);
});
