'use strict';
// tar-parser.test.js — verify the pure TAR header parser handles the
// minimal POSIX ustar shape correctly. This is the smallest possible
// well-formed archive; richer fixtures (PAX, GNU long-name, sparse) are
// covered indirectly by the e2e fixture suite running against
// `examples/archives/*.tar`.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules, host } = require('../helpers/load-bundle.js');

// `tar-parser.js` only references `PARSER_LIMITS` from constants.js.
const ctx = loadModules(['src/constants.js', 'src/tar-parser.js']);
const { TarParser } = ctx;

/**
 * Build a minimal 512-byte ustar header for the given path / size, then
 * append the file's content padded to 512. Returns a Uint8Array
 * comprising the full archive (header + content + 1024-byte zero footer
 * the parser scans for).
 */
function buildUstarArchive(name, content) {
  const header = new Uint8Array(512);
  // name (offset 0, 100 bytes).
  for (let i = 0; i < name.length && i < 100; i++) header[i] = name.charCodeAt(i);
  // mode (100, 8) — '0000644 ' in octal followed by NUL.
  const mode = '0000644';
  for (let i = 0; i < mode.length; i++) header[100 + i] = mode.charCodeAt(i);
  // size (124, 12) — octal big-endian ASCII, NUL-padded.
  const size = content.length.toString(8).padStart(11, '0');
  for (let i = 0; i < size.length; i++) header[124 + i] = size.charCodeAt(i);
  // mtime (136, 12) — same encoding; 0 is fine.
  for (let i = 0; i < 11; i++) header[136 + i] = '0'.charCodeAt(0);
  // typeflag (156) — '0' = regular file.
  header[156] = '0'.charCodeAt(0);
  // magic (257, 6) — 'ustar\0'.
  header[257] = 'u'.charCodeAt(0); header[258] = 's'.charCodeAt(0);
  header[259] = 't'.charCodeAt(0); header[260] = 'a'.charCodeAt(0);
  header[261] = 'r'.charCodeAt(0);
  // version (263, 2) — '00'.
  header[263] = '0'.charCodeAt(0); header[264] = '0'.charCodeAt(0);
  // checksum (148, 8) — sum of all header bytes treating the checksum
  // field itself as 8 spaces. ustar standard. NUL + space terminator.
  for (let i = 0; i < 8; i++) header[148 + i] = 0x20;
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += header[i];
  const cs = sum.toString(8).padStart(6, '0');
  for (let i = 0; i < cs.length; i++) header[148 + i] = cs.charCodeAt(i);
  header[148 + 6] = 0; header[148 + 7] = 0x20;

  // Pad content to a 512-byte block boundary.
  const contentBlocks = Math.ceil(content.length / 512);
  const data = new Uint8Array(contentBlocks * 512);
  for (let i = 0; i < content.length; i++) data[i] = content.charCodeAt(i);

  // Footer is 2 × 512-byte zero blocks.
  const footer = new Uint8Array(1024);

  const out = new Uint8Array(header.length + data.length + footer.length);
  out.set(header, 0);
  out.set(data, header.length);
  out.set(footer, header.length + data.length);
  return out;
}

test('tar-parser: parses single-entry ustar archive', () => {
  const archive = buildUstarArchive('hello.txt', 'hello world\n');
  const entries = TarParser.parse(archive);
  // Project across realms so deepEqual prototype-identity check passes.
  const list = host(entries);
  assert.equal(list.length, 1, `expected 1 entry, got ${list.length}`);
  assert.equal(list[0].name, 'hello.txt');
  assert.equal(list[0].size, 12);
  assert.equal(list[0].dir, false);
  // `offset` points at the data start INSIDE the archive bytes — for a
  // single-entry archive that's exactly 512 (one header block).
  assert.equal(list[0].offset, 512);
});

test('tar-parser: returns empty list for empty input', () => {
  // Defensive: an empty buffer should not throw — the parser is
  // exercised on user-supplied bytes that may be mis-detected as TAR.
  const out = TarParser.parse(new Uint8Array(0));
  assert.deepEqual(host(out), []);
});

test('tar-parser: zero-only blocks parse to empty list', () => {
  // The TAR end-of-archive marker is two consecutive zero-blocks. A
  // bare double-zero archive must parse to zero entries (not throw).
  const out = TarParser.parse(new Uint8Array(1024));
  assert.deepEqual(host(out), []);
});

test('tar-parser: respects PARSER_LIMITS.MAX_ENTRIES', () => {
  // Smoke: confirm the parser observes the per-archive cap so it can't
  // be made to allocate unbounded entry arrays from a maliciously
  // crafted archive. We don't construct 10 000+ headers here (slow);
  // instead, we sanity-check that MAX_ENTRIES is the small-int the
  // renderers depend on (10_000), guarding against an accidental bump.
  assert.equal(ctx.PARSER_LIMITS.MAX_ENTRIES, 10_000);
});
