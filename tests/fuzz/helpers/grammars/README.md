# tests/fuzz/helpers/grammars/

Deterministic seed generators for the obfuscation fuzz targets under
`tests/fuzz/targets/obfuscation/`. Each grammar produces a small fixed
set of structurally-valid seeds per technique branch — byte-level
mutation alone rarely enters niche branches (bash IFS fragmentation,
CMD `%COMSPEC:~N,M%` substring abuse, PHP `preg_replace /e`), so these
seeds exist to put the fuzzer inside each branch's accept path from
iteration 1.

## Module shape

Each grammar module is a CommonJS file that exports two names:

```js
const X_TECHNIQUE_CATALOG = Object.freeze([
  // every `candidate.technique` string the decoder can emit
]);

function generateXSeeds() {
  // returns an Array<Buffer>; each Buffer may carry a non-enumerable
  // `_expectedSubstring` property consumed by the target as a soft
  // roundtrip check:
  //   • candidates fired but token missing  → technique `expectedMiss`
  //   • zero candidates at all              → per-module `empty-miss`
}

module.exports = { generateXSeeds, X_TECHNIQUE_CATALOG };
```

The `TECHNIQUE_CATALOG` constant name MUST match the
`/const [A-Z_]+_TECHNIQUE_CATALOG\s*=\s*Object\.freeze\(\[([\s\S]*?)\]\)/`
pattern so `scripts/fuzz_coverage_aggregate.py` can parse the entry list
without evaluating the file.

## Seed construction

```js
function makeSeed(text, expectedSubstring) {
  const buf = Buffer.from(text, 'utf8');
  if (expectedSubstring) {
    Object.defineProperty(buf, '_expectedSubstring', {
      value: expectedSubstring,
      enumerable: false,  // must stay non-enumerable — JSON round-trip
                          // in crash-dedup normalisation drops it
                          // silently, which is fine
    });
  }
  return buf;
}
```

## Determinism

Grammars use a tiny xorshift32 PRNG seeded from a per-file constant.
`Math.random`, `Date.now`, and `os.*` are banned — the seed corpus must
be bit-identical across runs so coverage deltas are meaningful.

## Adding a new technique

1. Add the exact `candidate.technique` string to `X_TECHNIQUE_CATALOG`
   (copy it verbatim from the `src/decoders/x-obfuscation.js` emission
   site — the aggregator does no normalisation).
2. Write a `genNewTechnique()` function that returns 2-4 seeds, each
   with `_expectedSubstring` set to a token that proves the decoder
   ran to completion.
3. Extend `generateXSeeds()` to include the new generator's output.
4. Smoke:
   `python scripts/run_fuzz.py --replay --quick obfuscation/x-obfuscation`
5. Verify the new technique appears in
   `dist/fuzz-coverage/summary.md § Obfuscation technique coverage`
   after running with `--coverage`, and that the per-module footnotes
   stay free of surprising `empty-miss` / `__unknown__` signal.

## multi-technique-grammar.js (reassembly target)

`multi-technique-grammar.js` is the odd grammar out. The per-shell
grammars each target one decoder branch per seed and use a string-level
`_expectedSubstring` probe; `multi-technique-grammar.js` exists to feed
`obfuscation/reassembly.fuzz.js`, whose unit under test is
`src/encoded-reassembler.js` — the module that stitches ≥2 independent
findings from different byte offsets into one composite script.

Two consequences for seed shape:

- Seeds must be **multi-technique**. Each seed contains at least two
  top-level encoded spans (possibly different shells, definitely
  different finder branches) because `EncodedReassembler.build()`
  returns `{ skipReason: 'findings-below-min' }` on fewer than 2.
- The soft roundtrip signal is **`_expectedIocs`**, not
  `_expectedSubstring`. Each element is `{ type, value }` where `type`
  is an `IOC.*` enum value and `value` is the exact string the atom
  should materialise as once reassembled + re-extracted through
  `ioc-extract.js`. The target records a technique `miss` entry for
  every atom missing from both the sentinel-stripped stitched body and
  the novel-IOC re-extract tally. Seeds can still carry
  `_expectedSubstring` on top for the structural build-did-something
  probe.

Seeds come from two composers that feed the same array:

- **Curated** — ten hand-rolled classic droppers (PS
  `IEX(DownloadString)` + `frombase64string`, `cmd /c for /f`-chain with
  caret+`%COMSPEC:~N,M%`, `<script language="VBScript">` HTA mix, bash
  `eval` + `\x..` `printf` concat, Python `exec` + `chr-join`, PHP
  `eval(base64_decode)` + chr-dot chain, etc.). Each has a handcrafted
  `_expectedIocs` array.
- **Pair-concat** — `pairConcat()` takes one seed from each of two
  different per-shell grammars (e.g. one from
  `cmd-grammar.generateCmdSeeds()`, one from
  `powershell-grammar.generatePowershellSeeds()`), joins them with a
  random neutral separator, and plants two fresh RFC-5737 doc IPs
  (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or attacker-shaped
  FQDNs as the `_expectedIocs`. Pair-concat composes freshly each run —
  the joined text is **not** guaranteed to carry the parents'
  `_expectedSubstring`, so the pair-concat seeds set only
  `_expectedIocs`.

The catalog describes reassembly **outcomes** — `build-empty`,
`build-skip-findings-below-min`, `build-skip-below-coverage`,
`build-truncated`, `build-overlap-collision`, `build-succeeded`,
`analyze-no-worker-manager`, `analyze-no-novel-iocs`,
`analyze-yielded-novel-ioc`, `expected-ioc-missed` — not decoder
techniques. This is deliberate: the per-shell grammars already cover
decoder branches; the reassembly target's job is to surface structural
build results and the whole-file-stitching win-condition.

IOC atoms use RFC-5737 doc-range IPs and fake but attacker-shaped
FQDNs (`evil-c2.example.org`, `dropper.invalid`) so they do not collide
with the `src/nicelist.js` whitelist and unambiguously attribute to the
seed rather than the host page or another finder.
