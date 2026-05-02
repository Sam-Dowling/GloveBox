'use strict';
// folder-file.test.js — synthetic-folder ingest walker.
//
// `FolderFile.fromEntries` walks an array of `FileSystemEntry`-shaped
// objects (real ones come from `webkitGetAsEntry()` on a folder drop),
// flattens the tree into `{path, dir, size, file?, mtime?}` rows, and
// returns `{folder, truncated, walkedCount}`. Three contract points
// matter for safety / resilience and are the focus of these tests:
//
//   1. Per-leaf `entry.file(…)` failures (AV-blocked, permission denied,
//      dead symlink, transient FS error) MUST be caught and the leaf
//      skipped with `truncated = true`. Healthy siblings keep flowing.
//      Without this a single bad file in a 4 000-entry tree throws away
//      the other 3 999. Was the FF/Windows cold-cache crash trigger.
//   2. Walk halts at `PARSER_LIMITS.MAX_FOLDER_ENTRIES` with
//      `truncated = true`. Both directory and file pushes count toward
//      the cap.
//   3. Cooperative event-loop yield happens at least once for trees
//      large enough to cross the 64-entry threshold. We can't assert on
//      `setTimeout` directly under the vm harness without instrumenting
//      it, but the trees we walk here resolve via real `setTimeout` —
//      if the yield were broken (e.g. infinite-await), these tests
//      would hang and fail under `node:test`'s default timeout.

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

test('FolderFile.fromEntries: cooperative yield does not deadlock for >64-entry walks', async () => {
  // Pure liveness check: walking 200 healthy leaves crosses the
  // every-64-entries `setTimeout(0)` yield boundary three times. If the
  // yield were misimplemented (e.g. awaited a never-resolving promise),
  // this test would wedge until node:test's default timeout (60 s) and
  // surface as a hang. A successful resolution under the harness
  // confirms the yield is well-formed AND a 200-entry tree finishes
  // promptly — the latter is the property that prevents FF/Windows
  // from killing the content process under cold-cache load.
  const N = 200;
  const children = [];
  for (let i = 0; i < N; i++) {
    children.push(makeFileEntry('f' + i + '.bin', fakeFile('f' + i + '.bin', 4)));
  }
  const root = makeDirEntry('two-hundred', children);
  const start = Date.now();
  const { folder, truncated } = await FolderFile.fromEntries(
    'two-hundred', [{ entry: root, asRoot: true }]);
  const elapsed = Date.now() - start;
  assert.equal(truncated, false);
  assert.equal(folder.entries.length, N);
  // 200 leaves with a 1ms timer per file + a 0ms yield every 64 should
  // resolve well under a second on any sane runner. If we ever exceed
  // 5 s here the yield strategy has regressed.
  assert.ok(elapsed < 5000, `walk completed in ${elapsed} ms (must be < 5 000)`);
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

test('FolderFile.fromEntries: directory walk that throws via readEntries marks truncated', async () => {
  // Whole-directory failure (e.g. denied recursion permission). The
  // walker's outer try/catch should swallow the error and mark
  // truncated = true so the analyst sees the warning toast / IOC.INFO
  // row but the rest of the ingest continues.
  const failingDir = {
    isFile: false,
    isDirectory: true,
    name: 'denied',
    createReader() {
      return {
        readEntries(_onSuccess, onError) {
          setTimeout(() => onError(new Error('DOMException: NotAllowedError')), 0);
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
  const { folder, truncated } = await FolderFile.fromEntries('mixed', sources);
  assert.equal(truncated, true, 'directory-walk failure latches truncated');
  // The directory ROW itself is pushed before walkDir is called, so it
  // appears in the flat list even though its children were unreachable.
  // The healthy sibling file must still be present.
  const paths = folder.entries.map(e => e.path).sort();
  assert.deepEqual(host(paths), ['denied', 'ok.txt']);
});
