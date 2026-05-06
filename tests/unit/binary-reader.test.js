'use strict';
// binary-reader.test.js — coverage for the shared BinaryReader helper
// that PE / ELF / Mach-O renderers all delegate their endian-aware
// byte reads to.

const test = require('node:test');
const assert = require('node:assert/strict');
const { loadModules } = require('../helpers/load-bundle.js');

const ctx = loadModules(['src/binary-reader.js'], {
  expose: ['BinaryReader'],
});
const { BinaryReader } = ctx;

test('BinaryReader: u8 reads single byte', () => {
  const b = new Uint8Array([0x12, 0x34, 0xAB, 0xFF]);
  assert.equal(BinaryReader.u8(b, 0), 0x12);
  assert.equal(BinaryReader.u8(b, 3), 0xFF);
});

test('BinaryReader: u16le / u16be read 16-bit values', () => {
  const b = new Uint8Array([0x12, 0x34, 0xAB, 0xCD]);
  assert.equal(BinaryReader.u16le(b, 0), 0x3412);
  assert.equal(BinaryReader.u16be(b, 0), 0x1234);
  assert.equal(BinaryReader.u16le(b, 2), 0xCDAB);
  assert.equal(BinaryReader.u16be(b, 2), 0xABCD);
});

test('BinaryReader: u32le / u32be read 32-bit values (unsigned)', () => {
  const b = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0xFF, 0xFF, 0xFF, 0xFF]);
  assert.equal(BinaryReader.u32le(b, 0), 0x78563412);
  assert.equal(BinaryReader.u32be(b, 0), 0x12345678);
  // Top-bit-set value MUST be unsigned (>= 2^31).
  assert.equal(BinaryReader.u32le(b, 4), 0xFFFFFFFF);
  assert.equal(BinaryReader.u32be(b, 4), 0xFFFFFFFF);
});

test('BinaryReader: u64le / u64be read 64-bit values (Number, lossy above 2^53)', () => {
  // 0x0102030405060708 little-endian => bytes 08 07 06 05 04 03 02 01
  const le = new Uint8Array([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
  assert.equal(BinaryReader.u64le(le, 0), 0x0102030405060708);
  // Same value big-endian => bytes 01 02 03 04 05 06 07 08
  const be = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
  assert.equal(BinaryReader.u64be(be, 0), 0x0102030405060708);
});

test('BinaryReader: cstring reads null-terminated ASCII with length cap', () => {
  const b = new Uint8Array([0x66, 0x6F, 0x6F, 0x00, 0x62, 0x61, 0x72]);
  assert.equal(BinaryReader.cstring(b, 0, 16), 'foo');
  assert.equal(BinaryReader.cstring(b, 4, 16), 'bar');
});

test('BinaryReader: cstring respects maxLen cap', () => {
  const b = new Uint8Array([0x68, 0x65, 0x6C, 0x6C, 0x6F]);
  assert.equal(BinaryReader.cstring(b, 0, 3), 'hel');
  assert.equal(BinaryReader.cstring(b, 0, 100), 'hello');
});

test('BinaryReader: cstring stops at buffer end without overrunning', () => {
  const b = new Uint8Array([0x61, 0x62]);
  // No null terminator — must stop at end-of-buffer rather than read OOB.
  assert.equal(BinaryReader.cstring(b, 0, 100), 'ab');
});

test('BinaryReader: hex pads and uppercases', () => {
  assert.equal(BinaryReader.hex(0xAB, 4), '0x00AB');
  assert.equal(BinaryReader.hex(0xDEAD, 8), '0x0000DEAD');
  assert.equal(BinaryReader.hex(0, 4), '0x0000');
  // Non-number input returns sentinel.
  assert.equal(BinaryReader.hex(undefined, 4), '0x0');
});

test('BinaryReader: entropy returns 0 for empty / OOB ranges', () => {
  const b = new Uint8Array([1, 2, 3, 4]);
  assert.equal(BinaryReader.entropy(b, 0, 0), 0);
  assert.equal(BinaryReader.entropy(b, 5, 1), 0);
  assert.equal(BinaryReader.entropy(b, 0, -1), 0);
});

test('BinaryReader: entropy returns ~0 for uniform input', () => {
  const b = new Uint8Array(256).fill(0x42);
  assert.ok(BinaryReader.entropy(b, 0, 256) < 0.001);
});

test('BinaryReader: entropy returns ~8 for evenly-distributed input', () => {
  const b = new Uint8Array(256);
  for (let i = 0; i < 256; i++) b[i] = i;
  assert.ok(Math.abs(BinaryReader.entropy(b, 0, 256) - 8) < 0.001);
});

test('BinaryReader: entropy rounds when round arg supplied', () => {
  const b = new Uint8Array(256);
  for (let i = 0; i < 256; i++) b[i] = i;
  const raw = BinaryReader.entropy(b, 0, 256);
  const rounded = BinaryReader.entropy(b, 0, 256, 1000);
  assert.equal(rounded, Math.round(raw * 1000) / 1000);
});

test('BinaryReader: esc escapes all four HTML metacharacters', () => {
  assert.equal(
    BinaryReader.esc('<a href="x">&y</a>'),
    '&lt;a href=&quot;x&quot;&gt;&amp;y&lt;/a&gt;',
  );
  // & must be escaped first to avoid double-escaping injected entities.
  assert.equal(BinaryReader.esc('&amp;'), '&amp;amp;');
  // Falsy input is safe.
  assert.equal(BinaryReader.esc(null), '');
  assert.equal(BinaryReader.esc(''), '');
});
