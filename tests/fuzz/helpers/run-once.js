#!/usr/bin/env node
'use strict';
// ════════════════════════════════════════════════════════════════════════════
// run-once.js — execute a fuzz target against ONE input and report.
//
// This is the per-iteration primitive the Python minimiser
// (scripts/fuzz_minimise.py) shells to. A single Python invocation may
// run this script hundreds or thousands of times across the lifetime of
// a minimisation pass; each call:
//
//   • requires the target *.fuzz.js once (vm.Context init amortises in
//     the harness across iterations within ONE process — but cannot
//     amortise across separate node processes)
//   • runs the target's `fuzz(buf)` exactly once on the supplied bytes
//   • writes a small JSON result to stdout
//   • exits 0 on a "successful" run (clean OR threw the expected hash)
//   • exits 1 on a different exception OR a watchdog timeout
//
// We deliberately keep the IPC contract narrow: stdout is a single
// JSON object, stderr is human-readable diagnostics. The minimiser
// parses stdout and ignores stderr unless it needs to debug.
//
// IPC contract — JSON keys (all required):
//   ok          true  if the target threw with hash === targetHash
//               false if the target ran cleanly OR threw a different hash
//   threw       true if any exception escaped fuzz()
//   stackHash   16-hex digest, '' if !threw
//   errName     err.name, '' if !threw
//   errMessage  err.message (truncated 240 chars), '' if !threw
//   wallMs      observed iteration time in ms
//
// CLI:
//   node run-once.js <target.fuzz.js> <input.bin> [--target-hash <16hex>]
// ════════════════════════════════════════════════════════════════════════════

const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');

const { hashStack } = require('./crash-dedup.js');

function parseArgs(argv) {
  const args = { target: null, input: null, targetHash: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--target-hash') args.targetHash = String(argv[++i] || '').toLowerCase();
    else if (!args.target) args.target = a;
    else if (!args.input) args.input = a;
    else { process.stderr.write(`run-once: unexpected arg ${JSON.stringify(a)}\n`); process.exit(2); }
  }
  if (!args.target || !args.input) {
    process.stderr.write('usage: run-once <target.fuzz.js> <input.bin> [--target-hash <16hex>]\n');
    process.exit(2);
  }
  return args;
}

function emit(obj) {
  // Serialise to a single line so a partial write can't corrupt the
  // Python JSON parser. The Python side reads ONE line.
  process.stdout.write(JSON.stringify(obj) + '\n');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!fs.existsSync(args.target)) {
    process.stderr.write(`run-once: target not found: ${args.target}\n`);
    process.exit(2);
  }
  if (!fs.existsSync(args.input)) {
    process.stderr.write(`run-once: input not found: ${args.input}\n`);
    process.exit(2);
  }

  const mod = require(path.resolve(args.target));
  if (typeof mod.fuzz !== 'function') {
    process.stderr.write(`run-once: target ${args.target} must export module.exports.fuzz\n`);
    process.exit(2);
  }

  const buf = fs.readFileSync(args.input);
  const t0 = performance.now();
  let threw = false;
  let errName = '';
  let errMessage = '';
  let stackHash = '';

  try {
    await mod.fuzz(buf);
  } catch (err) {
    threw = true;
    errName = err && err.name ? String(err.name) : 'Error';
    errMessage = err && err.message ? String(err.message).slice(0, 240) : '';
    // Prefer the harness-attached hash (pre-computed on the original
    // throw site, before normalisation) over re-hashing here. They agree
    // when the harness path was taken; rehash on the rare exotic-error
    // path that bypassed harness.js's defineFuzzTarget wrapper.
    stackHash = (err && err._loupeFuzzStackHash) || hashStack(err);
  }

  const wallMs = performance.now() - t0;
  const ok = threw && (args.targetHash === null || stackHash === args.targetHash);

  emit({ ok, threw, stackHash, errName, errMessage, wallMs });
  // Process exit code: 0 if "still crashing with the target hash", 1 otherwise.
  // The Python minimiser only checks this — JSON is for diagnostics.
  process.exit(ok ? 0 : 1);
}

main().then(() => {}, (err) => {
  // Catastrophic failure inside this script (NOT the target). Surface
  // loud — the minimiser will treat exit 2 as "abort minimisation, not
  // a normal not-still-crashing signal".
  process.stderr.write(`run-once: harness crashed: ${err && err.stack || err}\n`);
  process.exit(2);
});
