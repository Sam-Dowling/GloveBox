#!/usr/bin/env node
'use strict';
// ════════════════════════════════════════════════════════════════════════════
// replay-runner.js — Node-only fuzz target driver.
//
// When Jazzer.js isn't installed (smoke runs, --reproduce, regression
// tests), `scripts/run_fuzz.py` shells out to this script. It:
//
//   1. Loads the target module (a `*.fuzz.js` file)
//   2. Pulls `module.exports.fuzz` (the Jazzer.js-shaped fuzz function)
//      and `module.exports.seeds` (Buffer[] from seed-corpus.js)
//   3. Runs `runReplay(fuzz, seeds)` from harness.js
//   4. Writes any failures to dist/fuzz-crashes/<target>/<sha>/
//   5. Exits non-zero on any failure
//
// CLI flags mirror run_fuzz.py:
//   --iterations <N>         per-seed mutation iterations (default 200)
//   --quick                  20 iterations per seed (smoke mode)
//   --continue-on-error      collect every failure rather than stopping
//   --reproduce <file>       run one specific input verbatim, no mutation
// ════════════════════════════════════════════════════════════════════════════

const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const CRASHES_DIR = path.join(REPO_ROOT, 'dist', 'fuzz-crashes');

const { runReplay } = require('./harness.js');
const { hashStack } = require('./crash-dedup.js');

function parseArgs(argv) {
  const args = {
    target: null,
    iterations: 200,
    quick: false,
    continueOnError: false,
    reproduce: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--iterations') args.iterations = parseInt(argv[++i], 10) || 200;
    else if (a === '--quick') { args.quick = true; args.iterations = 20; }
    else if (a === '--continue-on-error') args.continueOnError = true;
    else if (a === '--reproduce') args.reproduce = argv[++i];
    else if (!args.target) args.target = a;
    else { console.error(`replay-runner: unexpected arg ${JSON.stringify(a)}`); process.exit(2); }
  }
  if (!args.target) { console.error('replay-runner: target path required'); process.exit(2); }
  return args;
}

function loadTarget(target) {
  if (!fs.existsSync(target)) {
    console.error(`replay-runner: target not found: ${target}`);
    process.exit(2);
  }
  const mod = require(path.resolve(target));
  if (typeof mod.fuzz !== 'function') {
    console.error(`replay-runner: target ${target} must export module.exports.fuzz`);
    process.exit(2);
  }
  const seeds = Array.isArray(mod.seeds) ? mod.seeds : [];
  if (seeds.length === 0) {
    console.error(`replay-runner: target ${target} declared no seeds`);
    process.exit(2);
  }
  return { fuzz: mod.fuzz, seeds, name: mod.name || path.basename(target, '.fuzz.js') };
}

function relTargetId(targetPath) {
  const rel = path.relative(path.join(REPO_ROOT, 'tests', 'fuzz', 'targets'), targetPath);
  return rel.replace(/\\/g, '/').replace(/\.fuzz\.js$/, '');
}

function dumpFailure(targetId, failure) {
  const sha = hashStack(failure.err);
  const dir = path.join(CRASHES_DIR, targetId, sha);
  fs.mkdirSync(dir, { recursive: true });
  const inputFile = path.join(dir, 'input.bin');
  if (!fs.existsSync(inputFile)) {
    fs.writeFileSync(inputFile, failure.input);
  }
  const stackFile = path.join(dir, 'stack.txt');
  const stackLines = [
    `kind=${failure.kind}`,
    `inputBytes=${failure.input.length}`,
    `error.name=${failure.err.name}`,
    `error.message=${failure.err.message}`,
    '',
    failure.err.stack || '<no stack>',
  ].join('\n');
  fs.writeFileSync(stackFile, stackLines);
  return { sha, dir };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const { fuzz, seeds, name } = loadTarget(args.target);
  const targetId = relTargetId(path.resolve(args.target));

  if (args.reproduce) {
    if (!fs.existsSync(args.reproduce)) {
      console.error(`replay-runner: reproduce file not found: ${args.reproduce}`);
      process.exit(2);
    }
    const buf = fs.readFileSync(args.reproduce);
    console.log(`replay: reproducing ${args.reproduce} (${buf.length} bytes) on ${name}`);
    try {
      await fuzz(buf);
      console.log('OK    target ran cleanly on the supplied input.');
      return 0;
    } catch (err) {
      console.error(`FAIL  ${err.name}: ${err.message}`);
      console.error(err.stack);
      const out = dumpFailure(targetId, { kind: 'reproduce', input: buf, err });
      console.error(`crash recorded at ${path.relative(REPO_ROOT, out.dir)} (sha=${out.sha})`);
      return 1;
    }
  }

  console.log(`replay: ${name} — ${seeds.length} seed(s), `
    + `${args.iterations} iterations${args.quick ? ' [quick]' : ''}`);
  const t0 = Date.now();
  const result = await runReplay(fuzz, seeds, {
    iterations: args.iterations,
    continueOnError: args.continueOnError,
    onProgress: (p) => {
      // Throttle: emit every 4 096 iters.
      if ((p.count & 0xFFF) === 0) {
        process.stderr.write(`  …iter=${p.count} failures=${p.failures}\n`);
      }
    },
  });
  const dt = (Date.now() - t0) / 1000;

  if (result.failures.length === 0) {
    console.log(`OK    ${result.iterations} iterations in ${dt.toFixed(1)}s, no failures.`);
    return 0;
  }
  console.error(`FAIL  ${result.failures.length} failure(s) across `
    + `${result.iterations} iterations (${dt.toFixed(1)}s):`);
  // Dedup by stack hash to avoid spamming a thousand near-identical lines.
  const bySha = new Map();
  for (const f of result.failures) {
    const sha = hashStack(f.err);
    if (!bySha.has(sha)) bySha.set(sha, { sha, failure: f, count: 0 });
    bySha.get(sha).count++;
  }
  for (const { sha, failure, count } of bySha.values()) {
    const out = dumpFailure(targetId, failure);
    console.error(`  [${sha}]  ×${count}  ${failure.err.name}: ${failure.err.message}`);
    console.error(`    crash dir: ${path.relative(REPO_ROOT, out.dir)}`);
  }
  return 1;
}

main().then((rc) => process.exit(rc), (err) => {
  console.error('replay-runner crashed:', err);
  process.exit(2);
});
