'use strict';
// hashes.test.js — sanity coverage for src/hashes.js's MD5 and the two
// imphash-style fingerprints. These are pure functions over already-parsed
// inputs, so we can run them in a vm sandbox without any worker shim.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/hashes.js']);

test('hashes.js: md5 of empty input matches RFC 1321 vector', () => {
  // Empty MD5 vector is one of the canonical RFC 1321 fixtures —
  // verifies the byte-level _md5Bytes round-trip and the Uint8Array path.
  const out = ctx.md5(new Uint8Array(0));
  assert.equal(out, 'd41d8cd98f00b204e9800998ecf8427e');
});

test('hashes.js: md5 of "abc" matches RFC 1321 vector', () => {
  const enc = new TextEncoder();
  const out = ctx.md5(enc.encode('abc'));
  assert.equal(out, '900150983cd24fb0d6963f7d28e17f72');
});

test('hashes.js: md5 string-input vs byte-input agree on ASCII', () => {
  // The string overload encodes byte-by-byte (charCodeAt & 0xFF), so an
  // ASCII string and its UTF-8 encoding must produce the same digest.
  // This guards against a regression where someone routes the string
  // path through TextEncoder (which would diverge on non-ASCII).
  const enc = new TextEncoder();
  assert.equal(ctx.md5('abc'), ctx.md5(enc.encode('abc')));
});

test('hashes.js: computeImportHashFromList returns null for empty list', () => {
  // Caller responsibility: imphash inputs are pre-normalised. Empty list
  // returns null so renderers cheaply skip the metadata row — verified
  // here so a future "default to MD5('')" change announces itself.
  assert.equal(ctx.computeImportHashFromList([]), null);
});

test('hashes.js: computeImportHashFromList is order-sensitive', () => {
  // imphash's "faithful" ordering is the call-table order, not sorted.
  // The renderers rely on the function preserving order; sorting is a
  // separate `computeImportHashFromList(list.slice().sort())` call site.
  const a = ctx.computeImportHashFromList(['kernel32.loadlibrarya', 'kernel32.getprocaddress']);
  const b = ctx.computeImportHashFromList(['kernel32.getprocaddress', 'kernel32.loadlibrarya']);
  assert.notEqual(a, b);
  assert.match(a, /^[0-9a-f]{32}$/);
});

test('hashes.js: computeSymHash dedupes + lowercases + sorts', () => {
  // Anomali-style Mach-O symhash spec: dedupe, lowercase, sort, comma-join,
  // then concatenate sorted dylib basenames. Hash should be invariant under
  // case / order / duplicates of the input symbol list.
  const a = ctx.computeSymHash(['_objc_release', '_OBJC_release', '_objc_retain'], ['/usr/lib/libSystem.B.dylib']);
  const b = ctx.computeSymHash(['_objc_retain', '_objc_release'],                  ['/usr/lib/libSystem.B.dylib']);
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{32}$/);
});

test('hashes.js: computeSymHash returns null when both inputs empty', () => {
  // Renderers depend on this null return to skip the metadata row when
  // a Mach-O has no imports + no dylibs (e.g. a static-linked stub).
  assert.equal(ctx.computeSymHash([], []), null);
});

test('hashes.js: normalizePeImportToken lowercases + strips DLL suffix', () => {
  // imphash canonicalisation rule: drop .dll/.ocx/.sys, lowercase. Must
  // match the wire format the PE renderer feeds into computeImportHashFromList.
  assert.equal(ctx.normalizePeImportToken('Kernel32.DLL', { name: 'CreateProcessA' }), 'kernel32.createprocessa');
  assert.equal(ctx.normalizePeImportToken('user32.OCX',   { name: 'MessageBoxA'   }), 'user32.messageboxa');
});

test('hashes.js: normalizePeImportToken handles ordinal-only imports', () => {
  // PE imports without a name are encoded as `dll.ord<N>` per imphash spec.
  // The renderer marks these by setting fn.name === 'Ordinal #N' AND
  // fn.ordinal === N — both must be present to take the ordinal branch.
  const tok = ctx.normalizePeImportToken('Kernel32.DLL', { name: 'Ordinal #17', ordinal: 17 });
  assert.equal(tok, 'kernel32.ord17');
});
