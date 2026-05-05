'use strict';
// ════════════════════════════════════════════════════════════════════════════
// app-core-filter-readable-loose-files.test.js — pin the contract of
// `App.prototype._filterReadableLooseFiles`.
//
// Why this test matters
// ---------------------
// `_filterReadableLooseFiles` is the guard that stops `_ingestFolderFromEntries`
// from dispatching a non-readable "folder pseudo-File" into `_loadFile`. It
// fires on the Chromium-macOS folder-drop path where:
//
//   • `fsEntries` contains a FileSystemDirectoryEntry that rejects
//     `readEntries()` with `EncodingError`, and
//   • `DataTransfer.files` carries the folder itself as a synthesised
//     File whose `.arrayBuffer()` / `.slice(0,1).arrayBuffer()` rejects
//     with `NotFoundError: A requested file or directory could not be found…`.
//
// Without the filter, `_ingestFolderFromEntries`'s fallback branch calls
// `_loadFile(folderPseudoFile)` → `await file.arrayBuffer()` throws the
// uncaught NotFoundError we observed on the user's macOS Chrome
// (regression surfaced the day after the EncodingError fallback landed).
//
// Contract invariants guarded here:
//
//   1. A File whose `name` matches a directory-kind fsEntry is filtered
//      out (name-correlation filter, no I/O).
//   2. A File whose `slice(0,1).arrayBuffer()` rejects is filtered out
//      (probe filter).
//   3. A healthy File (name not in dir-set AND probe resolves) survives.
//   4. The function preserves input ORDER among survivors.
//   5. Non-`File`-shaped entries (missing `slice` / `arrayBuffer`) are
//      treated as un-probeable and filtered.
//   6. An empty / missing input returns `[]` without calling anything.
//   7. Arrays and FileList-like iterables both work.
// ════════════════════════════════════════════════════════════════════════════

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

// Same load order as app-load-set-render-result.test.js — app-core
// defines `App` + `extendApp`; app-load then mixes
// `_reportNonFatal` onto App.prototype (the helper we optionally use
// for dev breadcrumbs).
const ctx = loadModules(
  [
    'src/constants.js',
    'src/archive-budget.js',
    'src/app/app-core.js',
    'src/app/app-load.js',
  ],
  { expose: ['App', 'extendApp'] },
);
const { App } = ctx;

// Minimal File-like shim. We can't use Node's `File` (Node 18+ has it
// but its `slice().arrayBuffer()` never rejects the way Chromium's
// pseudo-File does). Construct a plain object quacking like File.
function makeFile(name, { rejectProbe = false, bytes = null } = {}) {
  const buf = bytes || new Uint8Array([0x41]); // 'A'
  return {
    name,
    size: bytes ? bytes.byteLength : 1,
    type: '',
    lastModified: Date.now(),
    slice(start, end) {
      // Return a blob-ish object with a rejecting or resolving arrayBuffer.
      return {
        async arrayBuffer() {
          if (rejectProbe) {
            const err = new Error(
              'A requested file or directory could not be found at the time an operation was processed.'
            );
            err.name = 'NotFoundError';
            throw err;
          }
          return buf.buffer.slice(
            start || 0,
            end == null ? buf.byteLength : Math.min(end, buf.byteLength),
          );
        },
      };
    },
    async arrayBuffer() {
      if (rejectProbe) {
        const err = new Error('NotFoundError');
        err.name = 'NotFoundError';
        throw err;
      }
      return buf.buffer.slice(0);
    },
  };
}

// Minimal FileSystemEntry shim. Only `isDirectory` / `isFile` / `name`
// matter to the helper.
function dirEntry(name) { return { isFile: false, isDirectory: true,  name }; }
function fileEntry(name) { return { isFile: true,  isDirectory: false, name }; }

test('_filterReadableLooseFiles exists on App.prototype', () => {
  assert.equal(typeof App.prototype._filterReadableLooseFiles, 'function',
    '_filterReadableLooseFiles must be defined on App.prototype after app-core.js loads');
});

test('filters out a File whose name matches a directory-kind fsEntry', async () => {
  const app = new App();
  const pseudoFolder = makeFile('forensics'); // probe would resolve, but the
                                              // name matches a dir entry.
  const realFile = makeFile('file.txt');
  const out = await app._filterReadableLooseFiles(
    [pseudoFolder, realFile],
    [dirEntry('forensics')],
  );
  assert.equal(out.length, 1, 'name-matched pseudo-folder removed');
  assert.equal(out[0].name, 'file.txt', 'healthy sibling survives');
});

test('filters out a File whose slice().arrayBuffer() rejects (Chromium macOS pseudo-File)', async () => {
  const app = new App();
  // Simulates the Chromium-macOS folder pseudo-File: reads reject with
  // NotFoundError, and we DO NOT name-match (drop handler fsEntries list
  // may be empty or unrelated in some edge cases).
  const pseudo = makeFile('Archive', { rejectProbe: true });
  const real = makeFile('note.txt');
  const out = await app._filterReadableLooseFiles([pseudo, real], []);
  assert.equal(out.length, 1, 'probe-rejecting pseudo-File removed');
  assert.equal(out[0].name, 'note.txt');
});

test('healthy File (no name collision, probe resolves) survives', async () => {
  const app = new App();
  const out = await app._filterReadableLooseFiles(
    [makeFile('one.txt'), makeFile('two.txt')],
    [fileEntry('one.txt'), fileEntry('two.txt')],
  );
  assert.equal(out.length, 2, 'both healthy files survive');
  assert.deepEqual(host(out.map(f => f.name)), ['one.txt', 'two.txt'],
    'input order preserved');
});

test('preserves input order among survivors', async () => {
  const app = new App();
  const out = await app._filterReadableLooseFiles(
    [
      makeFile('dropMe'),  // name-match → filter
      makeFile('keep-a.txt'),
      makeFile('pseudo', { rejectProbe: true }), // probe-reject → filter
      makeFile('keep-b.txt'),
    ],
    [dirEntry('dropMe')],
  );
  assert.deepEqual(host(out.map(f => f.name)), ['keep-a.txt', 'keep-b.txt'],
    'surviving order matches input order');
});

test('non-File-shaped entries (missing slice / arrayBuffer) are filtered out', async () => {
  const app = new App();
  const shapeless = { name: 'weird', size: 0 }; // no slice, no arrayBuffer
  const real = makeFile('real.txt');
  const out = await app._filterReadableLooseFiles([shapeless, real], []);
  assert.equal(out.length, 1, 'shapeless entry dropped');
  assert.equal(out[0].name, 'real.txt');
});

test('empty / missing input returns []', async () => {
  const app = new App();
  assert.deepEqual(host(await app._filterReadableLooseFiles([], [])), []);
  assert.deepEqual(host(await app._filterReadableLooseFiles(null, [])), []);
  assert.deepEqual(host(await app._filterReadableLooseFiles(undefined, undefined)), []);
});

test('accepts FileList-like iterable (Array.from-able)', async () => {
  const app = new App();
  const fileListLike = {
    0: makeFile('a.txt'),
    1: makeFile('folder-pseudo', { rejectProbe: true }),
    length: 2,
    [Symbol.iterator]: function* () { yield this[0]; yield this[1]; },
  };
  // Array.isArray(fileListLike) is false — the helper must still accept it.
  const out = await app._filterReadableLooseFiles(fileListLike, []);
  assert.equal(out.length, 1);
  assert.equal(out[0].name, 'a.txt');
});

test('does not throw when fsEntries is undefined / empty / non-Array', async () => {
  const app = new App();
  const healthy = makeFile('ok.txt');
  // Undefined
  assert.deepEqual(
    host((await app._filterReadableLooseFiles([healthy], undefined)).map(f => f.name)),
    ['ok.txt']);
  // Empty array
  assert.deepEqual(
    host((await app._filterReadableLooseFiles([healthy], [])).map(f => f.name)),
    ['ok.txt']);
  // Malformed (not an array) — helper should not crash.
  assert.deepEqual(
    host((await app._filterReadableLooseFiles([healthy], /*weird*/ 42)).map(f => f.name)),
    ['ok.txt']);
});

test('regression: macOS folder-drop shape (single-folder with single child) is fully filtered', async () => {
  // This is the exact user report: a folder "fold" dragged from Finder,
  // containing a single "file.txt". The drop handler calls
  // `webkitGetAsEntry()` → one directory entry `fold`. `DataTransfer.files`
  // carries the folder itself as a pseudo-File whose reads reject with
  // NotFoundError. The folder walker's `readEntries` also rejects with
  // EncodingError on Chromium macOS (simulated at the caller level in
  // `folder-file.test.js`). Here we just verify that the fallback path's
  // loose-file list is sanitised to empty — preventing the uncaught
  // NotFoundError from `_loadFile`.
  const app = new App();
  const folderPseudo = makeFile('fold', { rejectProbe: true });
  const out = await app._filterReadableLooseFiles(
    [folderPseudo],
    [dirEntry('fold')],
  );
  assert.equal(out.length, 0,
    'sole entry (folder pseudo-File) is filtered; caller will hit the ' +
    'actionable "use the Open button" toast instead of calling _loadFile');
});
