'use strict';
// ════════════════════════════════════════════════════════════════════════════
// load-bundle.js — Node:vm harness for Loupe unit tests.
//
// Loupe ships as a single concatenated inline <script>; everything is
// implicit globals at build time. For unit tests we don't want to load the
// full ~9 MB bundle into a fake DOM — we want to load the minimal subset
// of `src/` files needed to exercise a pure module, and assert against the
// resulting globals.
//
// `loadModules(filenames)` reads each file as text, concatenates them in
// the given order, evaluates the result inside a fresh `vm.Context` with
// just enough host shims (TextEncoder/Decoder, console) for the source
// to run, and returns the populated context. Tests then read named
// globals straight off the returned object.
//
// Why not just `require()` each file? Because the source uses `const X =`
// at file scope (not `module.exports`) — exactly the shape it has inside
// the inline <script> tag. `vm.runInContext` faithfully reproduces that
// scope without us having to retrofit a CommonJS / ESM façade onto every
// source file.
//
// Determinism:
//   • Files are read with the project root resolved relative to THIS
//     file, not `process.cwd()`. Tests behave identically whether they
//     are launched from the repo root or from `tests/`.
//   • The context is re-created for every `loadModules` call. Tests never
//     leak state into each other.
// ════════════════════════════════════════════════════════════════════════════

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const REPO_ROOT = path.resolve(__dirname, '..', '..');

/**
 * Resolve `relPath` (e.g. `'src/constants.js'`) against the repo root.
 * Throws if the file is missing — silent fall-through would mask a typo
 * with confusing "X is not defined" downstream.
 */
function resolveSrc(relPath) {
  const abs = path.join(REPO_ROOT, relPath);
  if (!fs.existsSync(abs)) {
    throw new Error(`load-bundle: source file not found: ${relPath}`);
  }
  return abs;
}

/**
 * Build the host shim object exposed as the vm sandbox. Mirrors the
 * subset of browser globals the pure modules under test actually touch:
 *   • `console`            — diagnostic only; tests assert nothing on it.
 *   • `TextEncoder/Decoder`— Node has them globally since v11; we still
 *                            re-expose explicitly so the contract is clear.
 *   • `Uint8Array`/etc     — standard ES built-ins, cross-realm-safe to
 *                            use directly; tests passing a Uint8Array
 *                            constructed in this realm to a function
 *                            evaluated in the sandbox realm works because
 *                            `vm` shares the V8 heap.
 *   • `setTimeout/clear*`  — `safeRegex` uses `setTimeout(0)` for its
 *                            wall-clock budget probe in some paths.
 * No DOM, no `window`, no `localStorage` — those modules belong in
 * Playwright tests, not unit tests.
 */
function makeSandbox(extra) {
  const sb = {
    console,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    Uint16Array,
    Uint32Array,
    Int8Array,
    Int16Array,
    Int32Array,
    Float32Array,
    Float64Array,
    DataView,
    ArrayBuffer,
    SharedArrayBuffer: typeof SharedArrayBuffer === 'function' ? SharedArrayBuffer : undefined,
    Promise,
    Symbol,
    Map,
    Set,
    WeakMap,
    WeakSet,
    Date,
    Math,
    JSON,
    RegExp,
    Error,
    TypeError,
    RangeError,
    SyntaxError,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    queueMicrotask,
    Object,
    Array,
    Number,
    String,
    Boolean,
    parseInt,
    parseFloat,
    isFinite,
    isNaN,
    // Some pure modules call `crypto.subtle` (none of the ones unit-tested
    // today, but harmless to expose). `node:crypto.webcrypto` matches the
    // browser API surface.
    crypto: require('node:crypto').webcrypto,
    // `AbortController` / `AbortSignal` — used by `parser-watchdog.js` and
    // any signal-aware renderer code under test.
    AbortController: typeof AbortController === 'function' ? AbortController : undefined,
    AbortSignal: typeof AbortSignal === 'function' ? AbortSignal : undefined,
    // `atob` / `btoa` — used by `base64-hex.js::_decodeBase64`.
    atob: typeof atob === 'function' ? atob : undefined,
    btoa: typeof btoa === 'function' ? btoa : undefined,
    // `URL` / `URLSearchParams` — used by `safelinks.js` to parse the
    // wrapped URLs into searchParams.
    URL: typeof URL === 'function' ? URL : undefined,
    URLSearchParams: typeof URLSearchParams === 'function' ? URLSearchParams : undefined,
    // `throwIfAborted` — Loupe's render-epoch / watchdog poll site, defined
    // in `src/render-route.js`. The YARA engine (and a handful of other
    // modules) call it once per outer-loop iteration. The production worker
    // bundles ship a no-op stub (see `src/workers/yara.worker.js`); the unit
    // harness mirrors that stub so tests don't have to ship the whole
    // render-route just to drive a scan.
    throwIfAborted: () => {},
  };
  // Most Loupe modules publish their public surface onto `window.<Name>`
  // (e.g. `window.MITRE`, `window.EvtxEventIds`, `window.safeStorage`,
  // `window.ArchiveBudget`). For unit tests we want those assignments to
  // succeed — and the most direct way is to make `window` an alias of the
  // sandbox itself, so `window.MITRE = …` is the same as `globalThis.MITRE
  // = …`. The `expose` block at the end of `loadModules` then projects
  // those `window.*` properties onto the sandbox naturally.
  sb.window = sb;
  // Tiny in-memory `localStorage` shim. `safeStorage` (src/storage.js)
  // funnels every persisted-key access through this; nicelist.js consults
  // `loupe_nicelist_builtin_enabled` at lookup time. The shim is fresh
  // per `loadModules` call so tests never leak state.
  const _store = new Map();
  sb.localStorage = {
    getItem(k) { return _store.has(String(k)) ? _store.get(String(k)) : null; },
    setItem(k, v) { _store.set(String(k), String(v)); },
    removeItem(k) { _store.delete(String(k)); },
    key(i) { return Array.from(_store.keys())[i] ?? null; },
    get length() { return _store.size; },
    clear() { _store.clear(); },
  };
  if (extra) Object.assign(sb, extra);
  return sb;
}

/**
 * Concatenate and evaluate the listed `src/`-relative files inside a
 * fresh `vm.Context`. Returns the sandbox object so tests can read the
 * populated globals (e.g. `ctx.IOC`, `ctx.extractInterestingStringsCore`).
 *
 * IMPORTANT — `const`/`let` hoisting under `vm`:
 * ----------------------------------------------
 * `const X = …` at top level of a script does NOT become a property of
 * the sandbox object — that's standard ES semantics, not a vm quirk.
 * (In the production bundle this is fine: all `const`s live at the same
 * script scope, so they see each other.) For unit tests we need to
 * project named bindings onto the sandbox so the test can read them
 * after evaluation. We do this by concatenating ALL source files into a
 * single script PLUS a trailing snippet that does
 *   `globalThis.<name> = (typeof <name> !== 'undefined') ? <name> : undefined;`
 * for every requested name. The whole thing runs in one `vm.runInContext`
 * call, so every file sees every other file's bindings exactly as they
 * do in the browser bundle.
 *
 * @param {string[]} relPaths  e.g. `['src/constants.js', 'src/ioc-extract.js']`
 * @param {object}   [opts]
 * @param {string[]} [opts.expose]  names to surface onto the sandbox after
 *                                  evaluation. Defaults to a sensible
 *                                  superset covering every public symbol
 *                                  the existing unit tests touch (cheap).
 * @param {object}   [opts.shims]   extra shims merged into the sandbox
 *                                  before evaluation (rarely needed).
 * @returns {object} the sandbox after evaluation.
 */
function loadModules(relPaths, opts) {
  const result = loadModulesWithManifest(relPaths, opts);
  return result.sandbox;
}

/**
 * Variant of `loadModules` that also returns a sidecar manifest
 * describing each loaded `src/` file's character-offset region inside
 * the combined script that was handed to `vm.runInContext`. Used by
 * the fuzz harness's coverage feedback (`tests/fuzz/helpers/harness.js`
 * + `scripts/run_fuzz.py`) to attribute V8 source-coverage ranges back
 * to individual `src/<file>.js` paths.
 *
 * Manifest shape:
 *   {
 *     filename: string,                   // the `filename` passed to vm
 *     totalChars: number,                 // length of the combined source
 *     files: [
 *       { rel, abs, start, end, lines },  // half-open [start, end)
 *       …
 *     ],
 *     // The trailing exposure block sits at [exposeStart, totalChars).
 *     exposeStart: number,
 *   }
 *
 * `start` / `end` are CHARACTER offsets (UTF-16 code units, same
 * numbering as `String.prototype.charAt`) — that's the indexing V8's
 * source-coverage report uses for its `startOffset` / `endOffset`
 * fields. ASCII-clean source maps these 1:1 to bytes, but the few
 * non-ASCII glyphs in our header comments are handled correctly here
 * regardless.
 *
 * Unit tests should keep using `loadModules`; only callers that need
 * the manifest pay the (negligible) cost of building it.
 *
 * @param {string[]} relPaths
 * @param {object}   [opts]   same shape as loadModules's opts
 * @returns {{sandbox: object, manifest: object}}
 */
function loadModulesWithManifest(relPaths, opts) {
  if (!Array.isArray(relPaths) || relPaths.length === 0) {
    throw new Error('load-bundle: relPaths must be a non-empty array');
  }
  const o = opts || {};
  const expose = Array.isArray(o.expose) ? o.expose : DEFAULT_EXPOSE;
  const filename = (typeof o.filename === 'string' && o.filename)
    ? o.filename
    : 'load-bundle:concatenated';
  const sandbox = makeSandbox(o.shims);
  vm.createContext(sandbox);

  // Concatenate every source file into one script, separated by sentinel
  // comments so a stack trace on a syntax error still localises to the
  // right file. As a side-effect we record each file's character region
  // for the optional coverage manifest.
  let combined = '';
  const manifestFiles = [];
  for (const rel of relPaths) {
    const abs = resolveSrc(rel);
    combined += `\n// ─── load-bundle: ${rel} ───\n`;
    const start = combined.length;
    const text = fs.readFileSync(abs, 'utf8');
    combined += text;
    const end = combined.length;
    manifestFiles.push({
      rel,
      abs,
      start,
      end,
      // Cheapest accurate line count: count `\n` in the file body and
      // add 1 if the file doesn't end on a newline (so the last line
      // is counted). Fuzz coverage attribution divides covered chars
      // by line offsets within this region.
      lines: text.length === 0
        ? 0
        : (text.match(/\n/g) || []).length + (text.endsWith('\n') ? 0 : 1),
    });
  }

  // Trailing exposure block: project requested top-level bindings onto
  // `globalThis`. The `typeof X !== 'undefined'` guard means a name not
  // declared by any of the loaded files surfaces as `undefined` rather
  // than throwing a ReferenceError, which keeps `expose` lists permissive
  // (tests only assert on the names they care about).
  const exposeStart = combined.length;
  combined += '\n// ─── load-bundle: expose ───\n';
  for (const name of expose) {
    // Whitelist identifier shape so we never inject a hostile name.
    if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name)) {
      throw new Error(`load-bundle: refusing to expose non-identifier name: ${JSON.stringify(name)}`);
    }
    combined += `try { globalThis[${JSON.stringify(name)}] = (typeof ${name} !== 'undefined') ? ${name} : undefined; } catch (_) {}\n`;
  }

  vm.runInContext(combined, sandbox, {
    filename,
    displayErrors: true,
  });

  return {
    sandbox,
    manifest: {
      filename,
      totalChars: combined.length,
      files: manifestFiles,
      exposeStart,
    },
  };
}

// Default expose set: every public symbol the unit tests in this repo
// touch today, plus a few obvious neighbours (cheap to add — projecting
// a name that isn't declared is a no-op). Keep this list sorted; if a
// new test needs a symbol, add it here in the same PR.
const DEFAULT_EXPOSE = [
  // src/archive-budget.js
  'ArchiveBudget',
  // src/constants.js
  'IOC',
  'IOC_CANONICAL_SEVERITY',
  'IOC_COPYABLE',
  'PARSER_LIMITS',
  'lfNormalize',
  'looksLikeIpVersionString',
  'pushIOC',
  'safeExec',
  'safeMatchAll',
  'safeRegex',
  'safeTest',
  'stripDerTail',
  // src/encoded-content-detector.js (root class — decoders mount onto its prototype)
  'EncodedContentDetector',
  // src/evtx-event-ids.js (publishes onto window.EvtxEventIds)
  'EvtxEventIds',
  // src/hashes.js
  'computeImportHashFromList',
  'computeRichHash',
  'computeSymHash',
  'md5',
  'normalizePeImportToken',
  // src/ioc-extract.js
  'extractInterestingStringsCore',
  // src/mitre.js (publishes onto window.MITRE)
  'MITRE',
  // src/nicelist.js
  'NICELIST',
  'isNicelisted',
  // src/numbering-resolver.js
  'NumberingResolver',
  // src/parser-watchdog.js
  'ParserWatchdog',
  // src/storage.js
  'safeStorage',
  // src/tar-parser.js
  'TarParser',
  // src/util/ipv4.js
  'Ipv4Util',
  // src/util/url-normalize.js
  'UrlNormalizeUtil',
  // src/yara-engine.js
  'YaraEngine',
];

/**
 * Project an arbitrary vm-realm value into the host realm via a JSON
 * round-trip. The default `node:assert/strict` comparators check
 * prototype identity, so an Array returned from `vm.runInContext` fails
 * `deepEqual` against a host-realm Array even when their contents are
 * identical. Tests that need structural equality should wrap the value
 * with `host(value)` before passing it to `assert.deepEqual` /
 * `assert.deepStrictEqual`.
 *
 * Note: only valid for JSON-safe values. Maps, Sets, BigInts, functions,
 * etc. lose information through this round-trip — but the surfaces this
 * harness covers (findings, IOC entries, TAR entries) are deliberately
 * JSON-safe in the production code, so this is fine.
 */
function host(value) {
  return JSON.parse(JSON.stringify(value));
}

module.exports = { loadModules, loadModulesWithManifest, resolveSrc, REPO_ROOT, DEFAULT_EXPOSE, host };
