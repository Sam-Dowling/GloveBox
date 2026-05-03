'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/binary/wasm-renderer.fuzz.js
//
// Fuzz `WasmRenderer.prototype.analyzeForSecurity(buffer, fileName)` —
// async (uses crypto.subtle for module hash). Walks the WebAssembly
// binary spec: 8-byte magic + version → section loop (Type, Import,
// Function, Memory, Global, Export, Element, Code, Data, Custom).
// LEB128 length decoding throughout.
//
// `crypto.subtle` is available in our vm.Context sandbox (load-bundle
// shims `node:crypto.webcrypto`).
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { loadSeeds } = require('../../helpers/seed-corpus.js');

const VALID_RISK = new Set(['safe', 'low', 'medium', 'high', 'critical']);
const VALID_IOC_VALUES = new Set();

const fuzz = defineFuzzTarget({
  modules: [
    'src/constants.js',
    'src/renderers/wasm-renderer.js',
  ],
  expose: ['IOC', 'WasmRenderer'],

  maxBytes: 4 * 1024 * 1024,
  perIterBudgetMs: 5_000,

  isExpectedError(err) {
    if (!err || typeof err.message !== 'string') return false;
    if (err.message.startsWith('parser-limit:')) return true;
    return false;
  },

  // analyzeForSecurity is async — harness awaits the returned promise.
  async onIteration(ctx, data) {
    const { IOC, WasmRenderer } = ctx;
    if (!WasmRenderer) throw new Error('harness: WasmRenderer not exposed');
    if (VALID_IOC_VALUES.size === 0) {
      for (const v of Object.values(IOC)) VALID_IOC_VALUES.add(v);
    }

    const r = new WasmRenderer();
    const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    const findings = await r.analyzeForSecurity(buf, 'fuzz.wasm');

    if (!findings || typeof findings !== 'object') {
      throw new Error('invariant: analyzeForSecurity returned non-object');
    }
    if (typeof findings.risk !== 'string' || !VALID_RISK.has(findings.risk)) {
      throw new Error(`invariant: findings.risk ${JSON.stringify(findings.risk)} invalid`);
    }
    for (const k of ['externalRefs', 'detections', 'capabilities', 'interestingStrings']) {
      if (!Array.isArray(findings[k])) {
        throw new Error(`invariant: findings.${k} not array (got ${typeof findings[k]})`);
      }
    }
    for (const ref of findings.externalRefs) {
      if (!ref || typeof ref !== 'object') {
        throw new Error('invariant: externalRef not object');
      }
      if (ref.type !== undefined && !VALID_IOC_VALUES.has(ref.type)) {
        throw new Error(
          `invariant: externalRef.type ${JSON.stringify(ref.type)} not in IOC.*`,
        );
      }
    }
  },
});

const seeds = loadSeeds({
  dirs: ['web'],
  extensions: ['wasm'],
  perFileMaxBytes: 1 * 1024 * 1024,
  totalMaxBytes: 4 * 1024 * 1024,
  maxSeeds: 16,
});

// Synthetic minimal valid WASM module: 8-byte magic+version, no sections.
//   magic: 0x00 0x61 0x73 0x6D ('\0asm')
//   version: 0x01 0x00 0x00 0x00 (v1)
function syntheticMinimalWasm() {
  const buf = Buffer.alloc(8);
  buf[0] = 0x00; buf[1] = 0x61; buf[2] = 0x73; buf[3] = 0x6D;
  buf[4] = 0x01; buf[5] = 0x00; buf[6] = 0x00; buf[7] = 0x00;
  return buf;
}

seeds.push(syntheticMinimalWasm());

module.exports = { fuzz, seeds, name: 'wasm-renderer' };
