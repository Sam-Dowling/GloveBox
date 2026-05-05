'use strict';
// folder-file.test.js — synthetic-folder ingest walker.
//
// `FolderFile.fromEntries` walks an array of `FileSystemEntry`-shaped
// objects (real ones come from `webkitGetAsEntry()` on a folder drop),
// flattens the tree into `{path, dir, size, file?, mtime?}` rows, and
// returns `{folder, truncated, walkedCount, walkErrors}`. The contract
// points that matter for safety / resilience and are the focus of these
// tests:
//
//   1. Per-leaf `entry.file(…)` failures (AV-blocked, permission denied,
//      dead symlink, transient FS error) MUST be caught and the leaf
//      skipped with `truncated = true`. Healthy siblings keep flowing.
//      Without this a single bad file in a 4 000-entry tree throws away
//      the other 3 999.
//   2. Walk halts at `PARSER_LIMITS.MAX_FOLDER_ENTRIES` with
//      `truncated = true`. Both directory and file pushes count toward
//      the cap.
//   3. `readEntries` rejections (Chromium macOS `EncodingError` on
//      folder drops — fatal-for-descriptor browser bug) MUST be caught
//      and recorded on `walkErrors` with `kind: 'dir'` so the caller
//      can distinguish "browser refused to enumerate" from "hit 4 096
//      cap" and fall back to loose-file ingest appropriately.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

// `folder-file.js` reads `PARSER_LIMITS.MAX_FOLDER_ENTRIES` for the cap;
// load constants.js first so the module sees the production value
// (4 096) rather than its 4 096 fallback. Expose list is explicit
// because `FolderFile` isn't in the default expose set in the harness.
const ctx = loadModules(
  ['src/constants.js', 'src/folder-file.js'],
  { expose: ['FolderFile', 'PARSER_LIMITS'] }
);
const { FolderFile, PARSER_LIMITS } = ctx;

// ── Mock helpers ────────────────────────────────────────────────────────
// FileSystem API entries are callback-shaped (legacy WHATWG draft). The
// production walker calls:
//   • `dirEntry.createReader()` → reader with `readEntries(success, error)`
//   • `fileEntry.file(success, error)`
// Our mocks mirror that surface exactly so the walker can't tell them
// apart from real entries.

/** Build a callback-shaped file entry. `readResult` is one of:
 *    - a `File`-shaped object → resolves with it
 *    - an Error → rejects with it (per-leaf failure path)
 */
function makeFileEntry(name, readResult) {
  return {
    isFile: true,
    isDirectory: false,
    name,
    file(onSuccess, onError) {
      // Match real FileSystem behaviour — async resolution via setTimeout
      // so the walker actually awaits a microtask boundary, not a
      // synchronous-callback short-circuit.
      setTimeout(() => {
        if (readResult instanceof Error) onError(readResult);
        else onSuccess(readResult);
      }, 0);
    },
  };
}

/** Build a callback-shaped directory entry. `children` is the static
 *  array `readEntries` returns; the second call returns `[]` to signal
 *  exhaustion (matches real browser behaviour for small directories).
 */
function makeDirEntry(name, children) {
  return {
    isFile: false,
    isDirectory: true,
    name,
    createReader() {
      let drained = false;
      return {
        readEntries(onSuccess, _onError) {
          setTimeout(() => {
            if (drained) onSuccess([]);
            else { drained = true; onSuccess(children.slice()); }
          }, 0);
        },
      };
    },
  };
}

/** Minimal File-shaped object for `pushFile` to read `size` /
 *  `lastModified` off. Production code never reads bytes here; size is
 *  a number, lastModified an epoch ms. Type field is ignored by the
 *  walker — included for shape parity. */
function fakeFile(name, size) {
  return { name, size, lastModified: 1700000000000, type: '' };
}

// ── Tests ───────────────────────────────────────────────────────────────

test('FolderFile.fromEntries: flat single-dir walk — every leaf surfaces', async () => {
  // Sanity-baseline: a small healthy tree must produce one entry per
  // leaf plus the directory rows themselves. Walker uses BFS via
  // `readEntries` batches; for this 3-leaf single-dir case the order
  // is deterministic.
  const root = makeDirEntry('forensics', [
    makeFileEntry('a.txt', fakeFile('a.txt', 10)),
    makeFileEntry('b.txt', fakeFile('b.txt', 20)),
    makeFileEntry('c.txt', fakeFile('c.txt', 30)),
  ]);
  const { folder, truncated, walkedCount } = await FolderFile.fromEntries(
    'forensics', [{ entry: root, asRoot: true }]);
  assert.equal(truncated, false, 'no failures + under cap → not truncated');
  assert.equal(walkedCount, 3, 'three file pushes (asRoot skips the dir push itself)');
  assert.equal(folder.name, 'forensics');
  assert.equal(folder.entries.length, 3);
  assert.equal(folder.entries.every(e => !e.dir), true);
  assert.equal(folder.size, 60, 'size is the sum of leaf sizes');
});

test('FolderFile.fromEntries: per-leaf entry.file() rejection skips just that leaf', async () => {
  // The contract this test pins: a single AV-blocked / permission-denied
  // leaf must NOT abort the whole walk. The rejection bubbles into the
  // walker's per-leaf try/catch, the leaf is dropped, `truncated = true`
  // is latched, and the sibling leaves still appear in the result.
  // Pre-fix behaviour: the rejection would unwind walkDir, then the
  // outer `try { await walkDir(...) }` in fromEntries would catch it
  // and abort the entire subtree — losing every healthy sibling that
  // followed the bad leaf. Verify the bad leaf is missing while the
  // healthy ones survive.
  const dirChildren = [
    makeFileEntry('healthy-1.txt', fakeFile('healthy-1.txt', 11)),
    makeFileEntry('av-blocked.exe', new Error('NotReadableError: scanned by AV')),
    makeFileEntry('healthy-2.txt', fakeFile('healthy-2.txt', 22)),
    makeFileEntry('healthy-3.txt', fakeFile('healthy-3.txt', 33)),
  ];
  const root = makeDirEntry('mixed', dirChildren);
  const { folder, truncated } = await FolderFile.fromEntries(
    'mixed', [{ entry: root, asRoot: true }]);

  assert.equal(truncated, true, 'per-leaf failure must latch truncated=true');

  const names = folder.entries.map(e => e.path).sort();
  assert.deepEqual(host(names), ['healthy-1.txt', 'healthy-2.txt', 'healthy-3.txt'],
    'three healthy siblings present, blocked leaf dropped');
  assert.equal(folder.entries.length, 3);
  assert.equal(folder.size, 66);
});

test('FolderFile.fromEntries: walk halts at MAX_FOLDER_ENTRIES with truncated=true', async () => {
  // Synthesise more leaves than the cap and confirm the walker stops
  // exactly at the cap. We deliberately use cap+8 so a regression that
  // off-by-one counted only files-not-dirs (or vice versa) produces a
  // detectably wrong total.
  const cap = PARSER_LIMITS.MAX_FOLDER_ENTRIES;
  const overflow = cap + 8;
  const children = [];
  for (let i = 0; i < overflow; i++) {
    children.push(makeFileEntry('f' + i + '.txt', fakeFile('f' + i + '.txt', 1)));
  }
  const root = makeDirEntry('huge', children);
  const { folder, truncated, walkedCount } = await FolderFile.fromEntries(
    'huge', [{ entry: root, asRoot: true }]);
  assert.equal(truncated, true);
  assert.equal(folder.entries.length, cap, 'flat list capped at MAX_FOLDER_ENTRIES');
  assert.equal(walkedCount, cap);
});

test('FolderFile.fromEntries: nested directory walk preserves relative paths', async () => {
  // Confirm that `walkDir`'s `prefix` propagation produces correct
  // root-relative paths. Important regression guard: an off-by-one in
  // the prefix concat would drop the directory name or duplicate the
  // root name (a bug we fixed historically — see contract block in
  // folder-file.js about `asRoot` skipping the redundant top-level
  // subfolder).
  const inner = makeDirEntry('sub', [
    makeFileEntry('inner.txt', fakeFile('inner.txt', 5)),
  ]);
  const root = makeDirEntry('outer', [
    makeFileEntry('top.txt', fakeFile('top.txt', 9)),
    inner,
  ]);
  const { folder } = await FolderFile.fromEntries(
    'outer', [{ entry: root, asRoot: true }]);
  const paths = folder.entries.map(e => e.path).sort();
  assert.deepEqual(host(paths), ['sub', 'sub/inner.txt', 'top.txt'],
    'nested leaf carries `sub/inner.txt`, top-level leaf bare; root NOT prefixed');
});

test('FolderFile.fromEntries: directory walk that throws via readEntries records walkError', async () => {
  // Whole-directory failure (e.g. denied recursion permission, or
  // Chromium macOS EncodingError). The walker's inner try/catch around
  // the `readEntries` promise should capture the error onto
  // `walkErrors` so the caller can distinguish this from a cap-hit
  // truncation. Healthy siblings must still appear in the flat list.
  const failingDir = {
    isFile: false,
    isDirectory: true,
    name: 'denied',
    createReader() {
      return {
        readEntries(_onSuccess, onError) {
          setTimeout(() => onError(
            Object.assign(new Error('NotAllowedError'), { name: 'NotAllowedError' })), 0);
        },
      };
    },
  };
  // Pair the failing dir with one healthy sibling at the synthetic-root
  // level (NOT asRoot: true, so each entry sits one tier under the root).
  const okFile = makeFileEntry('ok.txt', fakeFile('ok.txt', 7));
  const sources = [
    { entry: failingDir, path: 'denied' },
    { entry: okFile, path: 'ok.txt' },
  ];
  const { folder, truncated, walkErrors } = await FolderFile.fromEntries('mixed', sources);

  // The directory ROW itself is pushed before walkDir is called, so it
  // appears in the flat list even though its children were unreachable.
  // The healthy sibling file must still be present.
  const paths = folder.entries.map(e => e.path).sort();
  assert.deepEqual(host(paths), ['denied', 'ok.txt']);
  // Regression: walkErrors surfaces the dir-kind failure so the caller
  // can differentiate from cap-hit truncation.
  assert.ok(Array.isArray(walkErrors), 'walkErrors is an array');
  assert.ok(walkErrors.some(w => w && w.kind === 'dir' && w.name === 'NotAllowedError'),
    'walkErrors records the dir-kind failure with its DOMException name');
  // `truncated` stays false: no entries were enumerated-then-dropped
  // (no cap hit, no per-leaf failure). Dir-walk failures route through
  // walkErrors, not through the truncation flag.
  assert.equal(truncated, false,
    'pure dir-walk failure with zero leaves enumerated keeps truncated=false');
});

test('FolderFile.fromEntries: Chromium EncodingError on root walk yields empty tree + dir walkError', async () => {
  // Regression: Chromium macOS throws
  //   EncodingError: A URI supplied to the API was malformed...
  // from `createReader().readEntries(...)` on otherwise-valid folder
  // drops (known browser bug, fatal for the descriptor). Pre-fix the
  // walker swallowed the error, latched `truncated = true`, and
  // returned an empty flat list — the analyst saw an empty tree under
  // a misleading "truncated at 4,096" toast. Fix contract: record on
  // `walkErrors` with `kind: 'dir'` and the real error name/message so
  // the caller can fall back to loose-file ingest and surface an
  // accurate toast.
  const encErr = Object.assign(
    new Error('A URI supplied to the API was malformed or resulting Data URL ' +
              'has exceeded the URL length limitations for Data URLs'),
    { name: 'EncodingError' },
  );
  const failingRoot = {
    isFile: false,
    isDirectory: true,
    name: 'Archive',
    createReader() {
      return {
        readEntries(_onSuccess, onError) {
          setTimeout(() => onError(encErr), 0);
        },
      };
    },
  };
  const { folder, truncated, walkErrors } = await FolderFile.fromEntries(
    'Archive', [{ entry: failingRoot, asRoot: true }]);

  // Zero leaves reach the flat list — the descriptor was dead on arrival.
  assert.equal(folder.entries.length, 0, 'empty tree on root-walk EncodingError');
  // Truncated stays false: no entries were enumerated-then-dropped.
  // The cap-hit branch is reserved for legitimate 4 096-entry overflows.
  assert.equal(truncated, false,
    'root-walk failure with zero leaves must NOT latch cap-hit truncation');
  assert.ok(Array.isArray(walkErrors) && walkErrors.length >= 1,
    'walkErrors records the root-walk failure');
  const dirErr = walkErrors.find(w => w && w.kind === 'dir');
  assert.ok(dirErr, 'walkErrors contains a dir-kind entry');
  assert.equal(dirErr.name, 'EncodingError',
    'real DOMException name propagated to caller for diagnostic toast');
  assert.ok(/malformed/i.test(dirErr.message),
    'real error message propagated for the "(${errTag})" toast fragment');
});

test('FolderFile.fromEntries: partial walk — one subtree fails, siblings and outer leaves survive', async () => {
  // Chromium's EncodingError typically kills a specific subtree, not
  // the whole drop. Confirm that when one nested dir's `readEntries`
  // rejects, the outer walk still surfaces every readable leaf AND
  // records the failure on `walkErrors` so the caller can emit a
  // "partial failure" toast rather than the cap-hit one.
  const failingSub = {
    isFile: false,
    isDirectory: true,
    name: 'unreadable',
    createReader() {
      return {
        readEntries(_onSuccess, onError) {
          setTimeout(() => onError(
            Object.assign(new Error('malformed URI'), { name: 'EncodingError' })), 0);
        },
      };
    },
  };
  const root = makeDirEntry('outer', [
    makeFileEntry('top.txt', fakeFile('top.txt', 1)),
    failingSub,
    makeFileEntry('also.txt', fakeFile('also.txt', 2)),
  ]);
  const { folder, truncated, walkErrors } = await FolderFile.fromEntries(
    'outer', [{ entry: root, asRoot: true }]);

  const paths = folder.entries.map(e => e.path).sort();
  // The subdir ROW is pushed before walkDir is called, so it appears
  // in the flat list even though its children were unreachable.
  assert.deepEqual(host(paths), ['also.txt', 'top.txt', 'unreadable'],
    'readable siblings + the subdir row survive the failed subtree');
  // Caller-visible: at least one dir-kind walkError recorded.
  assert.ok(walkErrors.some(w => w && w.kind === 'dir' && w.name === 'EncodingError'),
    'subtree EncodingError recorded on walkErrors with kind=dir');
  // `truncated` is left untouched by a dir-kind failure from inside
  // walkDir (the 4 096 cap wasn't hit). The ingest caller keys off
  // `walkErrors.length > 0` to branch the toast, not on `truncated`.
  assert.equal(truncated, false,
    'partial walk with zero cap hits and zero per-leaf failures keeps truncated=false');
});
