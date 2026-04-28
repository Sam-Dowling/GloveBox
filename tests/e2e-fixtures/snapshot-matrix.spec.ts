// ════════════════════════════════════════════════════════════════════════════
// snapshot-matrix.spec.ts — Coarse-grained regression net across the
// entire fixture corpus.
//
// Every record in `expected.jsonl` carries range-based assertions for
// one fixture: format-tag pin, Timeline-route bool, risk floor, IOC
// type subset, IOC count lower bound, and a small set of must-include
// YARA rules. The matrix walks the corpus and asserts each fixture
// against its record.
//
// Why ranges, not exact pins?
//
//   • Renderer evolution: a renderer that adds a new IOC row (e.g. a
//     URL parsed from an additional certificate field) shouldn't
//     break the matrix. Lower-bound assertions absorb growth.
//
//   • Risk floor escalation: most fixtures are at the lowest band
//     they'll ever be at — a future high-severity Pattern row may
//     bump 'medium' to 'high'. Floor assertions absorb upward drift.
//     The exception is `riskFloor: 'any'` for clean-baseline fixtures
//     where any escalation would still be an acceptable change.
//
//   • Rule pinning: only family-anchor rules
//     (`BAT_Download_Execute`, `MSIX_AppInstaller_HTTP`, etc) are
//     pinned. `Info_*` and `Embedded_Compressed_Stream` are dropped
//     during generation — they're too volatile to anchor cleanly.
//
// Why ONE Playwright test that walks all records (rather than one
// test per record)?
//
//   The 138 fixtures share a single page (`useSharedBundlePage`) and
//   a single browser context. Running them as separate Playwright
//   tests pays per-test bookkeeping (timeouts, reporter, fixture
//   setup, retries) ~138 times — that overhead dominated the spec's
//   wall-time. Walking inside one test, with `test.step` per record
//   and `expect.soft` per assertion, keeps the per-record diagnostic
//   granularity (the GitHub reporter still shows a step-level tree)
//   while collapsing the runner overhead. A regression names the
//   failing fixture and the exact assertion that fired; multiple
//   regressions all surface in the same run instead of stopping at
//   the first one.
//
// To regenerate after a deliberate baseline shift:
//
//     LOUPE_EXPLORE=1 python scripts/run_tests_e2e.py tests/explore/dump-fixtures.spec.ts
//     python scripts/gen_expected.py
//     git diff tests/e2e-fixtures/expected.jsonl
//
// Eyeball the diff. Every flipped line should map to a real renderer
// change. A line that drops IOC types, drops rules, or demotes a
// risk floor IS a regression.
// ════════════════════════════════════════════════════════════════════════════

import * as fs from 'fs';
import * as path from 'path';
import { test, expect } from '@playwright/test';
import {
  REPO_ROOT,
  loadFixture,
  dumpResult,
  isRiskAtLeast,
  ruleNames,
  useSharedBundlePage,
} from '../helpers/playwright-helpers';

interface ExpectedRecord {
  path: string;
  formatTag: string | null;
  timeline: boolean;
  riskFloor: 'low' | 'medium' | 'high' | 'critical' | 'any' | null;
  iocTypeMustInclude: string[];
  iocCountAtLeast: number;
  yaraRulesMustInclude: string[];
}

function loadExpected(): ExpectedRecord[] {
  const expectedPath = path.join(
    REPO_ROOT, 'tests', 'e2e-fixtures', 'expected.jsonl');
  if (!fs.existsSync(expectedPath)) {
    throw new Error(
      `expected.jsonl not found at ${expectedPath} — `
      + 'regenerate with `python scripts/gen_expected.py`');
  }
  const lines = fs.readFileSync(expectedPath, 'utf-8').split('\n');
  return lines
    .filter(l => l.trim().length > 0)
    .map((l, i) => {
      try {
        return JSON.parse(l) as ExpectedRecord;
      } catch (e) {
        throw new Error(`expected.jsonl: parse error on line ${i + 1}: ${e}`);
      }
    });
}

// ── Sanity-check the file early so a malformed line shows up at
//    discover-time rather than mid-run.
const RECORDS = loadExpected();

test.describe('snapshot matrix', () => {
  const ctx = useSharedBundlePage();

  // Single test. Each record runs as a `test.step` so the GitHub
  // reporter tree (and Playwright's `--list` / HTML reporter) still
  // shows a per-fixture row. `expect.soft` collects every failing
  // assertion across the corpus instead of bailing on the first one
  // — a renderer change that affects ten fixtures surfaces all ten
  // failures in a single run.
  //
  // Per-record budget: ~15s test-API timeout per loadBytes; the
  // overall test timeout is bumped accordingly to accommodate the
  // full walk under any one worker. Playwright's default test
  // timeout is 30s — well below what 138 fixtures need.
  test(`walks ${RECORDS.length} fixture records`, async () => {
    test.setTimeout(10 * 60 * 1000); // 10 min wall budget for the full walk

    for (const rec of RECORDS) {
      await test.step(rec.path, async () => {
        const findings = await loadFixture(ctx.page, rec.path);
        const result = await dumpResult(ctx.page);

        // ── 1. Routing assertion: Timeline vs renderer.
        if (rec.timeline) {
          expect.soft(result, `${rec.path}: dumpResult must not be null`).not.toBeNull();
          expect.soft(
            result?.timeline,
            `${rec.path}: expected Timeline route`,
          ).toBe(true);
        } else {
          // Renderer route. `result` may legitimately be null only when
          // the fixture failed to load entirely — that's a regression.
          expect.soft(result, `${rec.path}: dumpResult must not be null`).not.toBeNull();
          expect.soft(
            result?.timeline,
            `${rec.path}: expected renderer route, got Timeline`,
          ).toBe(false);
        }

        // ── 2. Format tag pin.
        if (rec.formatTag !== null && result) {
          expect.soft(
            result.formatTag,
            `${rec.path}: formatTag drift`,
          ).toBe(rec.formatTag);
        }

        // ── 3. Risk floor.
        if (rec.riskFloor !== null && rec.riskFloor !== 'any') {
          expect.soft(
            isRiskAtLeast(findings.risk, rec.riskFloor),
            `${rec.path}: risk '${findings.risk}' below floor '${rec.riskFloor}'`,
          ).toBe(true);
        }

        // ── 4. IOC count lower bound.
        expect.soft(
          findings.iocCount,
          `${rec.path}: iocCount ${findings.iocCount} < floor ${rec.iocCountAtLeast}`,
        ).toBeGreaterThanOrEqual(rec.iocCountAtLeast);

        // ── 5. IOC type subset.
        for (const t of rec.iocTypeMustInclude) {
          expect.soft(
            findings.iocTypes,
            `${rec.path}: missing IOC type '${t}'`,
          ).toContain(t);
        }

        // ── 6. Must-include YARA rules.
        const seenRules = ruleNames(findings);
        for (const rule of rec.yaraRulesMustInclude) {
          expect.soft(
            seenRules,
            `${rec.path}: missing YARA rule '${rule}'`,
          ).toContain(rule);
        }
      });
    }
  });
});
