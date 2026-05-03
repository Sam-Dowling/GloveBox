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
  // roundtrip check (expectedMiss++ when the decoder's output no
  // longer contains the named token)
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
   after running with `--coverage`.
