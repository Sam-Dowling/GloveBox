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
  // Full enumeration — must match the source of truth in archive-analysis.js.
  // Ordered roughly by platform: Windows PE/scripts → PowerShell family →
  // Windows Script Host family → Windows config/shortcuts → cross-platform
  // runtimes → *nix shared objects → Office macro-enabled formats.
  const EXPECTED = [
    'exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'msi', 'msp', 'mst', 'sys',
    'bat', 'cmd', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'js', 'jse',
    'wsf', 'wsh', 'wsc', 'hta', 'lnk', 'inf', 'reg', 'sct',
    'jar', 'py', 'rb', 'sh', 'bash', 'so', 'dylib',
    'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm', 'ppam', 'xlam',
  ];
  for (const ext of EXPECTED) {
    assert.ok(ArchiveAnalysis.EXEC_EXTS.has(ext), `EXEC_EXTS missing '${ext}'`);
  }
  // Silent-removal guard — if the source ever loses an entry without the
  // test being updated, the size mismatch catches it.
  assert.equal(ArchiveAnalysis.EXEC_EXTS.size, EXPECTED.length,
    `EXEC_EXTS size ${ArchiveAnalysis.EXEC_EXTS.size} != expected ${EXPECTED.length}; ` +
    `something was added or removed in archive-analysis.js without the test being updated.`);
});

test('ArchiveAnalysis: DECOY_EXTS contains every historical entry', () => {
  const EXPECTED = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
                    'jpg', 'png', 'gif', 'txt', 'rtf'];
  for (const ext of EXPECTED) {
    assert.ok(ArchiveAnalysis.DECOY_EXTS.has(ext), `DECOY_EXTS missing '${ext}'`);
  }
  assert.equal(ArchiveAnalysis.DECOY_EXTS.size, EXPECTED.length,
    `DECOY_EXTS size ${ArchiveAnalysis.DECOY_EXTS.size} != expected ${EXPECTED.length}`);
});

test('ArchiveAnalysis: extOf returns trailing extension, lower-cased', () => {
  // Canonical happy path — the hot call site in `buildCommonWarnings`.
  assert.equal(ArchiveAnalysis.extOf('file.txt'), 'txt');
  assert.equal(ArchiveAnalysis.extOf('FILE.EXE'), 'exe');
  assert.equal(ArchiveAnalysis.extOf('dir/sub/file.pdf'), 'pdf');
  // Multi-dot names take only the trailing segment.
  assert.equal(ArchiveAnalysis.extOf('a.b.c.d'), 'd');
  // Dots in parent segments are ignored — only the final basename matters.
  assert.equal(ArchiveAnalysis.extOf('a.b/c.d'), 'd');
});

test('ArchiveAnalysis: extOf returns empty string for paths with no extension', () => {
  // No dot at all → empty string, never throws.
  assert.equal(ArchiveAnalysis.extOf('Makefile'), '');
  assert.equal(ArchiveAnalysis.extOf('dir/README'), '');
  // Trailing dot → empty (nothing after the dot).
  assert.equal(ArchiveAnalysis.extOf('foo.'), '');
  // Directory-style path (trailing slash → basename is empty).
  assert.equal(ArchiveAnalysis.extOf('dir/'), '');
});

test('ArchiveAnalysis: extOf handles null / undefined / empty without throwing', () => {
  // Guard contract — every caller passes `e.path || e.name` which can
  // be undefined on malformed archive entries.
  assert.equal(ArchiveAnalysis.extOf(null), '');
  assert.equal(ArchiveAnalysis.extOf(undefined), '');
  assert.equal(ArchiveAnalysis.extOf(''), '');
});

test('ArchiveAnalysis: extOf on leading-dot names treats the dot as separator', () => {
  // `.hidden` → `lastIndexOf('.')` is 0, `slice(1)` is `'hidden'`. This
  // matches Unix "dotfile" convention where the name IS the extension
  // if that's all there is — benign for the EXEC_EXTS lookup
  // (`'hidden'` isn't in the set). Pinned here so a future refactor
  // that switches to a regex doesn't silently change the shape.
  assert.equal(ArchiveAnalysis.extOf('.hidden'), 'hidden');
  assert.equal(ArchiveAnalysis.extOf('.gitignore'), 'gitignore');
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

test('ArchiveAnalysis: parity — every archive renderer aliases the shared Set (not a copy)', () => {
  // Pins the contract that each archive renderer's `static EXEC_EXTS` /
  // `static DECOY_EXTS` is an IDENTITY alias of the shared frozen Set.
  //
  // The previous version of this test compared `ArchiveAnalysis.EXEC_EXTS`
  // to itself (`assert.strictEqual(X, X)`) and was therefore a no-op —
  // it could never catch alias drift. Loading the actual renderer JS
  // under node:vm is not viable either: these renderers pull in heavy
  // deps (archive-tree, decompressor, pako, JSZip) that aren't on the
  // unit-test harness surface.
  //
  // Instead, assert at the source-text level that each archive renderer
  // declares the alias in its canonical shape:
  //
  //     static EXEC_EXTS = ArchiveAnalysis.EXEC_EXTS;
  //     static DECOY_EXTS = ArchiveAnalysis.DECOY_EXTS;
  //
  // A copy (`new Set(ArchiveAnalysis.EXEC_EXTS)`), a manual literal
  // (`new Set(['exe', ...])`), or any other divergent form fails this
  // regex check. Drift is caught at the one place that matters: the
  // renderer file itself.
  const fs = require('node:fs');
  const path = require('node:path');
  const REPO_ROOT = path.resolve(__dirname, '..', '..');
  const RENDERERS = [
    'src/renderers/zip-renderer.js',
    'src/renderers/rar-renderer.js',
    'src/renderers/seven7-renderer.js',
    'src/renderers/cab-renderer.js',
  ];
  const EXEC_ALIAS_RE = /^\s*static\s+EXEC_EXTS\s*=\s*ArchiveAnalysis\.EXEC_EXTS\s*;\s*$/m;
  const DECOY_ALIAS_RE = /^\s*static\s+DECOY_EXTS\s*=\s*ArchiveAnalysis\.DECOY_EXTS\s*;\s*$/m;
  for (const rel of RENDERERS) {
    const text = fs.readFileSync(path.join(REPO_ROOT, rel), 'utf8');
    assert.match(text, EXEC_ALIAS_RE,
      `${rel}: missing canonical \`static EXEC_EXTS = ArchiveAnalysis.EXEC_EXTS;\` alias`);
    assert.match(text, DECOY_ALIAS_RE,
      `${rel}: missing canonical \`static DECOY_EXTS = ArchiveAnalysis.DECOY_EXTS;\` alias`);
  }
});
