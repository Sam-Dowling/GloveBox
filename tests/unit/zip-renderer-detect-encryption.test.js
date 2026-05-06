'use strict';
// zip-renderer-detect-encryption.test.js
//
// Regression coverage for `ZipRenderer._detectEncryption(bytes)`. The
// historical implementation only inspected the GP-flag bit on the first
// local file header — which is wrong whenever the archive opens with
// an unencrypted directory record (e.g. `Foo/`, compSize=0). Tools that
// emit explicit directory entries (Info-ZIP, 7-Zip, macOS Archive
// Utility, pyminizip, …) leave the encryption bit clear on those
// entries even when every payload entry is encrypted, because there is
// no data to encrypt. The user-visible symptom was the renderer falling
// through to `_nonZip` ("Unknown archive — this archive format cannot
// be fully extracted in-browser. Showing file info and hex dump.")
// instead of the password-cracking UI.
//
// The fix walks the central directory and returns `true` if any entry
// has the encryption bit set; this test pins down the correct behaviour
// on three shapes:
//   1. encrypted ZIP whose first local header is a (cleartext) directory
//      record followed by an encrypted file entry — the regression case;
//   2. encrypted ZIP whose first local header is the encrypted file
//      itself — the previously-working shape, must keep working;
//   3. fully unencrypted ZIP — must remain detected as non-encrypted.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/constants.js', 'src/archive-analysis.js', 'src/renderers/zip-renderer.js'], {
  expose: ['ZipRenderer', 'PARSER_LIMITS', 'IOC'],
});
const { ZipRenderer } = ctx;

// ── Tiny ZIP builder ────────────────────────────────────────────────────
//
// We hand-roll the minimum of the .ZIP format the detector inspects.
// Real archives are interpreted by `JSZip` / our own central-dir parser;
// for `_detectEncryption` we only need the local file headers, the
// central directory records, and a valid End-of-Central-Directory record.
// Compressed payload contents are irrelevant — the detector never
// inflates anything.

function u16(n) { return new Uint8Array([n & 0xff, (n >>> 8) & 0xff]); }
function u32(n) {
  return new Uint8Array([
    n & 0xff,
    (n >>> 8) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 24) & 0xff,
  ]);
}
function concat(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
function asciiBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

/**
 * Build a ZIP buffer from a list of entries.
 *
 * @param {Array<{name: string, encrypted?: boolean, payload?: Uint8Array, dir?: boolean}>} entries
 * @returns {Uint8Array}
 */
function buildZip(entries) {
  const localHeaders = [];
  const cdRecords = [];
  const localOffsets = [];
  let cursor = 0;

  for (const e of entries) {
    const payload = e.payload || new Uint8Array(0);
    const compSize = payload.length;
    const uncompSize = compSize; // method=0 (store): equal
    const flags = e.encrypted ? 0x0001 : 0x0000;
    const nameBytes = asciiBytes(e.name);

    // Local file header (PK\x03\x04 + 26 fixed bytes).
    const lfh = concat([
      asciiBytes('PK\x03\x04'),
      u16(20),               // version needed
      u16(flags),
      u16(0),                // method = store
      u16(0),                // mod time
      u16(0),                // mod date
      u32(0),                // crc32 (irrelevant for detector)
      u32(compSize),
      u32(uncompSize),
      u16(nameBytes.length),
      u16(0),                // extra field length
      nameBytes,
      payload,
    ]);
    localOffsets.push(cursor);
    cursor += lfh.length;
    localHeaders.push(lfh);

    const cdr = concat([
      asciiBytes('PK\x01\x02'),
      u16(20),               // version made by
      u16(20),               // version needed
      u16(flags),
      u16(0),                // method = store
      u16(0),                // mod time
      u16(0),                // mod date
      u32(0),                // crc32
      u32(compSize),
      u32(uncompSize),
      u16(nameBytes.length),
      u16(0),                // extra
      u16(0),                // comment
      u16(0),                // disk number start
      u16(0),                // internal attrs
      u32(e.dir ? 0x10 : 0), // external attrs (dir bit on directory entries)
      u32(localOffsets[localOffsets.length - 1]),
      nameBytes,
    ]);
    cdRecords.push(cdr);
  }

  const localBlock = concat(localHeaders);
  const cdBlock = concat(cdRecords);
  const cdOffset = localBlock.length;

  const eocd = concat([
    asciiBytes('PK\x05\x06'),
    u16(0),                  // disk number
    u16(0),                  // disk with central dir
    u16(entries.length),     // entries on this disk
    u16(entries.length),     // total entries
    u32(cdBlock.length),
    u32(cdOffset),
    u16(0),                  // comment length
  ]);

  return concat([localBlock, cdBlock, eocd]);
}

// ── Tests ───────────────────────────────────────────────────────────────

test('zip-renderer: detects encryption when leading entry is an unencrypted directory record', () => {
  // Reproduces the user-reported shape: a 100-file archive whose first
  // local header is `Foo/` (compSize=0, encryption bit clear) followed
  // by encrypted payload files. The old single-header heuristic would
  // miss this; the central-directory walk catches it.
  const bytes = buildZip([
    { name: 'Foo/', encrypted: false, dir: true },
    { name: 'Foo/secret.bin', encrypted: true, payload: new Uint8Array(64) },
  ]);
  const r = new ZipRenderer();
  assert.equal(r._detectEncryption(bytes), true,
    'directory-leading encrypted ZIP must be detected as encrypted');
});

test('zip-renderer: still detects encryption when first entry is the encrypted file itself', () => {
  // Existing-behaviour case: encryption bit on the first local header.
  // Must keep working after the fix.
  const bytes = buildZip([
    { name: 'secret.bin', encrypted: true, payload: new Uint8Array(64) },
  ]);
  const r = new ZipRenderer();
  assert.equal(r._detectEncryption(bytes), true,
    'first-entry-encrypted ZIP must be detected as encrypted');
});

test('zip-renderer: returns false for a fully unencrypted ZIP', () => {
  const bytes = buildZip([
    { name: 'Foo/', encrypted: false, dir: true },
    { name: 'Foo/readme.txt', encrypted: false, payload: asciiBytes('hello') },
  ]);
  const r = new ZipRenderer();
  assert.equal(r._detectEncryption(bytes), false,
    'fully cleartext ZIP must not be flagged as encrypted');
});

test('zip-renderer: returns false on non-ZIP input (PK signature missing)', () => {
  const bytes = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
  const r = new ZipRenderer();
  assert.equal(r._detectEncryption(bytes), false);
});

test('zip-renderer: returns false on too-short input', () => {
  const r = new ZipRenderer();
  assert.equal(r._detectEncryption(new Uint8Array(0)), false);
  assert.equal(r._detectEncryption(new Uint8Array(10)), false);
});

test('zip-renderer: defensive local-header fallback when central directory is missing', () => {
  // Truncate the EOCD-bearing tail off a directory-leading encrypted
  // archive so `_parseCentralDirectory` returns []. The detector should
  // walk local headers instead and still return true. This locks the
  // defensive fallback in place against future refactors.
  const full = buildZip([
    { name: 'Foo/', encrypted: false, dir: true },
    { name: 'Foo/secret.bin', encrypted: true, payload: new Uint8Array(32) },
  ]);
  // Find the central directory signature and chop everything from there.
  let cdOff = -1;
  for (let i = 0; i + 4 <= full.length; i++) {
    if (full[i] === 0x50 && full[i + 1] === 0x4B
      && full[i + 2] === 0x01 && full[i + 3] === 0x02) { cdOff = i; break; }
  }
  assert.notEqual(cdOff, -1, 'test fixture: central directory signature must exist');
  const truncated = full.slice(0, cdOff);
  const r = new ZipRenderer();
  assert.equal(r._detectEncryption(truncated), true,
    'fallback local-header walk must catch encrypted entry when central dir is unparseable');
});
