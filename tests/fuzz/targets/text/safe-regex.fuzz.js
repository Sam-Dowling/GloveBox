'use strict';
// ════════════════════════════════════════════════════════════════════════════
// targets/text/safe-regex.fuzz.js
//
// Fuzz the regex-safety helpers in `src/constants.js`:
//
//   safeRegex(pattern, flags)   compile a user-supplied regex with a
//                               heuristic ReDoS reject + plain catch.
//   safeMatchAll(re, str, ...)  exec a regex with a wall-clock budget;
//                               returns {matches, truncated, timedOut}.
//   safeExec(re, str, ...)      single-shot wall-clock wrapper for exec.
//   safeTest(re, str, ...)      single-shot wall-clock wrapper for test.
//
// These four functions are the choke point for every place in Loupe
// that compiles a user-controlled regex (Timeline DSL, YARA editor
// import, IOC extractor, etc.). Catastrophic backtracking regressions
// historically land here (716d532, ffd265e, 9f379f2, cc01dda), and
// the new --coverage table shows `src/constants.js` at 39% — exactly
// because no target hits these helpers directly.
//
// Two modes alternated by the first byte of each fuzz datum:
//   • even byte → fuzz the PATTERN, run against a fixed input corpus
//   • odd byte  → fuzz the INPUT,   run against a fixed pattern corpus
//
// The pattern axis is the more interesting half — that's where ReDoS
// hides. Inputs are exercised too because some bugs only show up at
// the input × pattern intersection.
//
// Invariants asserted per iteration:
//   1. safeRegex(p, f) returns {ok, regex, warning, error}; never null.
//      ok===true ↔ regex is a RegExp instance; ok===false ↔ regex===null
//      and error is a non-empty string.
//   2. safeMatchAll(...) returns {matches, truncated, timedOut} with
//      Array / boolean / boolean shape regardless of input.
//   3. safeExec / safeTest never throw — both swallow errors and
//      return null / false respectively.
//   4. The harness's 2.5s wall-clock budget catches any helper call
//      that exceeds the documented per-call budget by an order of
//      magnitude — that's the ReDoS detector.
//
// History references — pin these as known bug shapes the seeds
// reproduce:
//   • 716d532 — invisRe was unbounded `\w{2,}`; froze main thread
//                ~7s on 165 KB single-line .ps1.
//   • ffd265e — initial safeRegex / safeMatchAll harness landing.
//   • 9f379f2 — bound nested quantifiers in path / UNC / domain regexes.
//   • cc01dda — bound scan windows + sync-decode invariants.
// ════════════════════════════════════════════════════════════════════════════

const { defineFuzzTarget } = require('../../helpers/harness.js');
const { syntheticTextSeeds } = require('../../helpers/seed-corpus.js');

// ── Pattern corpus (used when fuzzing the INPUT side) ────────────────────
// Two corpora because the two modes have asymmetric safety needs:
//
//   • In PATTERN mode we control the input (≤25 chars per INPUT_CORPUS),
//     so ReDoS-trap patterns are safe to exercise — even worst-case
//     exponential backtracking finishes in <500 ms on a tiny input.
//
//   • In INPUT mode the fuzzer controls the input, so patterns must
//     have polynomial worst-case complexity. Any nested-quantifier
//     pattern combined with a fuzzer-grown 'a'×N input would hang for
//     minutes on N=64 and is unrecoverable (JS regex exec is not
//     preemptible). PATTERN_CORPUS_SAFE keeps to plain quantifiers.
//
// History references:
//   • 716d532 — invisRe was unbounded `\w{2,}`; froze main thread
//                ~7s on 165 KB single-line .ps1.
//   • ffd265e — initial safeRegex / safeMatchAll harness landing.
//   • 9f379f2 — bound nested quantifiers in path / UNC / domain regexes.
//   • cc01dda — bound scan windows + sync-decode invariants.
const PATTERN_CORPUS_REDOS = [
  // ReDoS-canonical traps — the harness expects these to either be
  // rejected by `looksRedosProne` or budget out cleanly, never hang.
  // INPUT_CORPUS bounds inputs to ≤25 chars so even worst-case 2^25
  // ops finishes in <300 ms.
  '(a+)+$',
  '(a|a)*$',
  '(a|aa)+$',
  '([a-z]+)+$',
  '([a-z]*)*$',
  '(x|xx|xxx)+y',
];
const PATTERN_CORPUS_SAFE = [
  // Benign baselines + production-shaped patterns. All polynomial,
  // safe to drive against fuzzer-controlled inputs without a hang.
  '^[a-z]+$',
  '\\d{1,4}',
  '[A-Za-z0-9]+',
  '\\w{2,64}',                       // 716d532: bound after the fix
  '(\\d{1,3}\\.){3}\\d{1,3}',         // IPv4
  '[a-z][\\w-]{0,62}\\.[a-z]{2,32}',  // domain
  '\\p{L}+',
  '\\u0041+',
];
// Pattern-side seeds also explicitly include the pre-fix `\w{2,}`
// shape so we exercise the heuristic-rejection / warn path on it.
const PATTERN_CORPUS_PATTERN_MODE = [
  ...PATTERN_CORPUS_SAFE,
  ...PATTERN_CORPUS_REDOS,
  '\\w{2,}',                          // 716d532 pre-fix shape
];

// ── Fixed input corpus (used when fuzzing the PATTERN side) ───────────────
// Inputs are deliberately SHORT (≤25 chars). Reason: JS regex execution
// is not preemptible mid-call, and `(a+)+$` against an input of 50 'a's
// runs in 2^50 steps — well past anyone's wall-clock budget. The
// safeMatchAll budget guard can only fire BETWEEN matches; one runaway
// exec hangs the harness. We keep inputs short so even worst-case
// exponential backtracking finishes in <500 ms, leaving the harness
// budget to catch genuinely bad regressions in the budget plumbing
// itself rather than fighting documented JS engine limitations.
const INPUT_CORPUS = [
  '',                                      // empty
  'aaaaaaaaaaaaaaaaaa!',                   // 19 chars: ~500k worst-case ops
  'aaaaaaaaaaaaaaaaaaaaaa',                // 22 chars (no anchor mismatch)
  '0'.repeat(20),
  'https://example.com/p',
  '192.168.1.1',
  'The quick brown fox.',
  'a'.repeat(10) + 'X' + 'a'.repeat(10),
  '\u202e\u202d\u200buniA',
  '\\\\share\\path\\with',
];

// Decode a Buffer slice as a JS pattern string. `String.fromCharCode`
// preserves every byte as a code unit, including non-printable / high
// bytes — the regex parser will reject most of these, exercising the
// `safeRegex` catch path. The slice is capped to 256 bytes; anything
// longer is wasted exec time on a regex pattern domain.
function bufToPattern(buf) {
  const slice = buf.subarray(0, Math.min(buf.length, 256));
  let s = '';
  for (let i = 0; i < slice.length; i++) s += String.fromCharCode(slice[i]);
  return s;
}

function bufToInput(buf) {
  // Inputs are capped to 256 bytes — same reasoning as INPUT_CORPUS:
  // JS regex execution isn't preemptible mid-call, and a fuzzer-
  // generated buffer combined with one of the ReDoS-trap patterns in
  // PATTERN_CORPUS would otherwise hang for minutes on any halfway
  // adversarial input. 256 bytes keeps worst-case exponential
  // backtracking exec time inside the harness budget while still
  // exercising the budget guard amortised across many short matches.
  const slice = buf.subarray(0, Math.min(buf.length, 256));
  let s = '';
  for (let i = 0; i < slice.length; i++) s += String.fromCharCode(slice[i]);
  return s;
}

const fuzz = defineFuzzTarget({
  modules: ['src/constants.js'],
  // safeRegex / safeMatchAll / safeExec / safeTest are already in
  // load-bundle.js DEFAULT_EXPOSE — no override needed.
  maxBytes: 64 * 1024,
  perIterBudgetMs: 2_500,

  onIteration(ctx, data) {
    const { safeRegex, safeMatchAll, safeExec, safeTest } = ctx;
    if (typeof safeRegex !== 'function'
        || typeof safeMatchAll !== 'function'
        || typeof safeExec !== 'function'
        || typeof safeTest !== 'function') {
      throw new Error('harness: safe-regex helpers not exposed');
    }

    if (data.length === 0) return;
    const pickPattern = (data[0] & 1) === 0;

    if (pickPattern) {
      // ── Mode 1: fuzz pattern ────────────────────────────────
      const pat = bufToPattern(data);
      const flags = ['g', 'i', 'gm', 'gi', 'gim', ''][data.length & 0x05];

      const result = safeRegex(pat, flags);
      // Invariant 1: safeRegex shape.
      if (!result || typeof result !== 'object') {
        throw new Error(`invariant: safeRegex returned ${typeof result}`);
      }
      if (typeof result.ok !== 'boolean') {
        throw new Error(`invariant: safeRegex.ok is ${typeof result.ok}`);
      }
      if (result.ok) {
        if (!(result.regex instanceof ctx.RegExp || result.regex instanceof RegExp)) {
          // The vm.Context realm has its own RegExp; cross-realm
          // instanceof can fail. Fall back to duck typing.
          if (!result.regex || typeof result.regex.exec !== 'function') {
            throw new Error('invariant: safeRegex.ok=true but regex is not RegExp-shaped');
          }
        }
        // Compile-only path for warned regexes — `looksRedosProne` flags
        // them as nested-unbounded-quantifier and `safeRegex` returns
        // `warning != null`. JS regex exec is not preemptible, so
        // running such a regex against any non-trivial input could
        // hang past `safeMatchAll`'s between-match budget. Restrict
        // exec to the empty string in that case (still exercises the
        // budget plumbing once) and skip the longer inputs.
        const inputs = result.warning ? [''] : INPUT_CORPUS;
        for (const inp of inputs) {
          const ma = safeMatchAll(result.regex, inp);
          // Invariant 2: safeMatchAll shape.
          if (!ma || typeof ma !== 'object'
              || !Array.isArray(ma.matches)
              || typeof ma.truncated !== 'boolean'
              || typeof ma.timedOut !== 'boolean') {
            throw new Error('invariant: safeMatchAll shape violated');
          }
          // Invariants 3a/3b: safeExec / safeTest never throw.
          // (We swallow the result — only the absence of throw matters.)
          safeExec(result.regex, inp);
          safeTest(result.regex, inp);
        }
      } else {
        // Reject path — error must be a non-empty string, regex must be null.
        if (result.regex !== null) {
          throw new Error('invariant: safeRegex.ok=false but regex is non-null');
        }
        if (typeof result.error !== 'string' || result.error.length === 0) {
          throw new Error(`invariant: safeRegex error empty on reject (pat=${JSON.stringify(pat).slice(0, 60)})`);
        }
      }
    } else {
      // ── Mode 2: fuzz input ──────────────────────────────────
      // Only PATTERN_CORPUS_SAFE here — fuzzer-controlled inputs of
      // arbitrary length combined with a ReDoS-prone pattern would
      // hang the harness (see file-header note on JS regex preemption).
      const inp = bufToInput(data);
      for (const pat of PATTERN_CORPUS_SAFE) {
        const result = safeRegex(pat);
        if (!result.ok) continue;          // tested in mode 1
        const ma = safeMatchAll(result.regex, inp);
        if (!Array.isArray(ma.matches)
            || typeof ma.truncated !== 'boolean'
            || typeof ma.timedOut !== 'boolean') {
          throw new Error('invariant: safeMatchAll shape violated (mode 2)');
        }
        safeExec(result.regex, inp);
        safeTest(result.regex, inp);
      }
    }
  },
});

// Seeds: a few realistic adversarial bytes plus synthetic text. The
// pattern-mode seeds intentionally include literal ReDoS-trap byte
// sequences so the parser-side reject path gets exercised
// deterministically from iteration 1.
const seeds = [
  // Pattern-mode (even first byte: 0x00 / 0x02 / 0x04 / …)
  Buffer.from([0x00].concat(Buffer.from('(a+)+$', 'utf8').toJSON().data)),
  Buffer.from([0x00].concat(Buffer.from('([a-z]*)*$', 'utf8').toJSON().data)),
  Buffer.from([0x00].concat(Buffer.from('\\w{2,}', 'utf8').toJSON().data)),
  Buffer.from([0x00].concat(Buffer.from('^[A-Z][a-z]+$', 'utf8').toJSON().data)),
  Buffer.from([0x02].concat(Buffer.from('(\\d{1,3}\\.){3}\\d{1,3}', 'utf8').toJSON().data)),
  Buffer.from([0x04].concat(Buffer.from('[invalid', 'utf8').toJSON().data)),  // unterminated class
  Buffer.from([0x06].concat(Buffer.from('\\', 'utf8').toJSON().data)),       // dangling backslash
  // Input-mode (odd first byte: 0x01 / 0x03 / …)
  // Inputs deliberately short — see bufToInput() and INPUT_CORPUS comments.
  Buffer.from([0x01].concat(Array.from(Buffer.from('aaaaaaaaaaaaa!', 'utf8')))),
  Buffer.from([0x03].concat(Array.from(Buffer.from('a'.repeat(20), 'utf8')))),
  Buffer.from([0x05].concat(Array.from(Buffer.from('https://example.com/p?q=' + 'x'.repeat(40), 'utf8')))),
  // Synthetic mix — gives the mutator something to chew on for both
  // modes; first byte is fuzz-controlled so both modes get hit.
  ...syntheticTextSeeds(8),
];

module.exports = { fuzz, seeds, name: 'safe-regex' };
