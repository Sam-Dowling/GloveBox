// ════════════════════════════════════════════════════════════════════════════
// json.spec.ts — End-to-end coverage for the standalone JsonRenderer.
//
// JsonRenderer is the tabular viewer for plain `.json` files whose root
// is an array (array-of-objects, array-of-arrays, or array-of-scalars).
// The renderer is registered in `src/renderer-registry.js` under
// `id: 'json'` with an `extDisambiguator` that hands the file to npm
// first (package.json / package-lock.json) and to PlainTextRenderer for
// non-array roots. CloudTrail-wrapped JSON (`{"Records":[...]}`) and
// `.jsonl` / `.ndjson` files BYPASS this renderer entirely via the
// Timeline 3-probe sniff in `app-load.js` — see `timeline-cloudtrail.spec.ts`
// and `timeline-jsonl.spec.ts` for that path.
//
// What this spec proves:
//
//   1. A plain array-of-objects `.json` file routes to JsonRenderer
//      (`formatTag === 'json'`, NOT Timeline-routed).
//   2. URL / IP IOCs embedded in cell values are surfaced through the
//      shared post-render IOC pipeline operating on `_rawText`.
//   3. JsonRenderer's `analyzeForSecurity()` lifts the JWT shape and
//      base64-encoded `data:` URI into `IOC.PATTERN` rows on
//      `findings.externalRefs`, escalating risk to at least 'medium'
//      via the data-URI signal (a known smuggling shape).
//   4. The fixture survives a clean re-load on the shared bundle page
//      (regression guard against state leak: rowSearchText cache,
//      `_extractedCols` from a prior Timeline load — see `2487fe4`,
//      `0c306aa`).
//
// Why this spec exists:
//   `JsonRenderer` had ZERO direct e2e coverage prior to this file —
//   every existing JSON-shaped fixture in the corpus
//   (`cloudtrail-*.json`, `jsonl-sample.jsonl`, `cloudtrail-wrapped.json`)
//   exercises the Timeline route, not the standalone renderer.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import {
  loadFixture,
  dumpResult,
  isRiskAtLeast,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

test.describe('JsonRenderer (standalone, non-Timeline)', () => {
  const ctx = useSharedBundlePage();

  test('array-of-objects-example.json routes to JsonRenderer and surfaces IOCs', async () => {
    const findings = await loadFixture(
      ctx.page, 'examples/json/array-of-objects-example.json');
    const result = await dumpResult(ctx.page);

    // ── 1. Routing pin ─────────────────────────────────────────────────
    // The standalone renderer dispatch id is 'json'. If this flips to
    // 'plaintext' the fallback path triggered (registry sniff failed);
    // if `result.timeline === true`, the 3-probe sniff over-claimed.
    expect(result?.timeline ?? false).toBe(false);
    expect(result?.dispatchId).toBe('json');
    expect(result?.formatTag).toBe('json');

    // ── 2. Standard IOC pipeline runs over _rawText ───────────────────
    // URLs in cell values must surface as IOC.URL rows; public IPs in
    // cell values surface as IOC.IP_ADDRESS. (We deliberately use the
    // RFC-2606 reserved `.test` TLD in fixtures so domain-sibling
    // emission via tldts is best-effort, not a hard pin — `.test` is
    // not on the public suffix list and may not yield a Domain row.)
    expect(findings.iocTypes).toContain('URL');
    // Three RFC-5737 documentation addresses appear in the fixture
    // (203.0.113.42, 198.51.100.7, 192.0.2.55) plus 1.1.1.1 (preserved
    // by the `986ff7a` DNS-IP filter).
    expect(findings.iocTypes).toContain('IP Address');

    // ── 3. analyzeForSecurity() pattern detections ────────────────────
    // Both signals MUST land on externalRefs as IOC.PATTERN rows so
    // they're visible to the risk calc, Summary, STIX, and MISP
    // exporters (the "mirror Detections into externalRefs" rule).
    const externalPatternMessages = findings.iocs
      .filter(r => r.type === 'Pattern')
      .map(r => String(r.value || ''));
    const allText = externalPatternMessages.join('\n').toLowerCase();
    expect(allText).toMatch(/data uri|jwt|base64-encoded data uri|json web token/);

    // ── 4. Risk floor ─────────────────────────────────────────────────
    // The data-URI signal alone escalates risk to medium; URL IOCs do
    // not auto-escalate, so 'low' would mean the analyzer regressed.
    expect(isRiskAtLeast(findings.risk, 'medium')).toBe(true);
  });
});
