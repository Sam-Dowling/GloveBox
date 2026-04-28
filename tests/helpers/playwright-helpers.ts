// ════════════════════════════════════════════════════════════════════════════
// playwright-helpers.ts — Shared utilities for Loupe e2e tests.
//
// These helpers wrap the `window.__loupeTest` surface (defined in
// `src/app/app-test-api.js`, included only by `--test-api` builds) so test
// code reads like an analyst's workflow:
//
//   const findings = await loadFixture(page, 'examples/email/phishing-example.eml');
//   expect(findings.iocTypes).toContain('url');
//
// `loadFixture` reads bytes off the filesystem (Node-side), then forwards
// them to the page via `evaluate(...)` and `__loupeTest.loadBytes(name, u8)`.
// This mirrors the fixture-driven smoke we want: real files from
// `examples/`, real ingress through `App._loadFile`, real renderer
// dispatch, real auto-YARA scan, real findings table.
// ════════════════════════════════════════════════════════════════════════════

import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from '@playwright/test';
import type { Page } from '@playwright/test';

export const REPO_ROOT = path.resolve(__dirname, '..', '..');
export const TEST_BUNDLE = path.join(REPO_ROOT, 'docs', 'index.test.html');

/** Shape of the snapshot returned by `__loupeTest.dumpFindings()`. Mirror
 *  of the object literal returned by `_testApiDumpFindings` in
 *  `src/app/app-test-api.js`. Tests assert against this projection rather
 *  than against `app.findings` directly — the projection is JSON-safe and
 *  serialises across the worker bridge. */
export interface FindingsSnapshot {
  risk: string | null;
  iocTypes: string[];
  iocs: Array<{ type: string; value: string; severity?: string; note?: string }>;
  iocCount: number;
  externalRefCount: number;
  interestingStringCount: number;
  detectionCount: number;
  metadata: Record<string, unknown>;
  yaraHits: Array<{ rule?: string; tags: string[]; severity?: string }>;
  yaraInProgress: boolean;
}

/**
 * Open the test bundle in `page`, then wait for `window.__loupeTest`
 * to appear. The test bundle's IIFE installs `__loupeTest` immediately
 * — so this resolves on the first paint — but we still gate on it so a
 * test never races a stale `window` from a previous navigation.
 */
export async function gotoBundle(page: Page): Promise<void> {
  // Navigate to file:// of docs/index.test.html. The `baseURL` set in
  // `playwright.config.ts` makes the empty path resolve to the bundle.
  await page.goto('');
  await page.waitForFunction(() => {
    const w = window as unknown as { __loupeTest?: { ready: Promise<void> } };
    return !!(w.__loupeTest && w.__loupeTest.ready);
  });
  await page.evaluate(() => {
    const w = window as unknown as { __loupeTest: { ready: Promise<void> } };
    return w.__loupeTest.ready;
  });
}

/**
 * Install a `beforeAll`/`afterAll` pair that opens the test bundle in a
 * single shared `Page` for the enclosing `describe`. Tests then reuse
 * that page via `ctx.page` instead of taking a fresh `{ page }` fixture
 * — the 9 MB bundle navigates once per file rather than once per test.
 *
 * Caller MUST also configure `test.describe.configure({ mode: 'serial' })`
 * (or pass `serial: true` to this helper) to ensure tests in the
 * describe run sequentially in the same worker. Otherwise concurrent
 * tests will race on the shared `app.findings` / `app.currentResult`
 * state inside the bundle.
 *
 * Across describes / files Playwright still parallelises on the
 * worker pool — see `playwright.config.ts`.
 *
 * Usage:
 *
 *     test.describe('email renderer', () => {
 *       const ctx = useSharedBundlePage();
 *       test('phishing fixture', async () => {
 *         const findings = await loadFixture(ctx.page, 'examples/...');
 *       });
 *     });
 *
 * `_testApiLoadBytes` already calls `_resetNavStack()` and runs a
 * fresh `_loadFile` per call, so successive loads on the same page
 * are functionally equivalent to fresh navs for the assertions Loupe's
 * e2e suite makes today.
 */
export function useSharedBundlePage(opts?: { serial?: boolean }) {
  if (opts?.serial !== false) {
    test.describe.configure({ mode: 'serial' });
  }
  // We expose the page via a property on a stable object so callers
  // can write `ctx.page` (the `beforeAll` runs lazily — the property
  // is populated before any test body executes).
  const ctx = { page: null as unknown as Page };
  test.beforeAll(async ({ browser }) => {
    ctx.page = await browser.newPage();
    await gotoBundle(ctx.page);
  });
  test.afterAll(async () => {
    if (ctx.page) {
      await ctx.page.close();
      ctx.page = null as unknown as Page;
    }
  });
  return ctx as { readonly page: Page };
}

/**
 * Read `relPath` (relative to the repo root, e.g. `'examples/email/phishing-example.eml'`)
 * from the host filesystem and feed its bytes through the page's
 * `__loupeTest.loadBytes(name, u8)`. Returns the findings snapshot.
 *
 * The bytes are transported over the CDP bridge as a base64-encoded
 * string, then decoded inside the page. Playwright's argument
 * serialisation supports `Uint8Array` directly, but we encode to base64
 * to avoid relying on that convenience and to make the bytes visible in
 * a `--debug` trace as plain text.
 */
export async function loadFixture(
  page: Page,
  relPath: string,
  filename?: string,
): Promise<FindingsSnapshot> {
  const abs = path.join(REPO_ROOT, relPath);
  if (!fs.existsSync(abs)) {
    throw new Error(`loadFixture: fixture not found: ${relPath}`);
  }
  const bytes = fs.readFileSync(abs);
  const b64 = bytes.toString('base64');
  const name = filename || path.basename(abs);

  return page.evaluate(async ({ b64, name }) => {
    // Decode base64 → Uint8Array inside the page realm.
    const bin = atob(b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    const w = window as unknown as {
      __loupeTest: {
        loadBytes(name: string, bytes: Uint8Array): Promise<unknown>;
      };
    };
    return (await w.__loupeTest.loadBytes(name, u8)) as unknown;
  }, { b64, name }) as Promise<FindingsSnapshot>;
}

/**
 * Re-fetch the current findings snapshot without loading a new file.
 * Useful for assertions that must run after a known-async post-paint
 * mutation (e.g. PE overlay-hash compute).
 */
export async function dumpFindings(page: Page): Promise<FindingsSnapshot> {
  return page.evaluate(() => {
    const w = window as unknown as {
      __loupeTest: { dumpFindings(): unknown };
    };
    return w.__loupeTest.dumpFindings() as unknown;
  }) as Promise<FindingsSnapshot>;
}

/**
 * Re-fetch `app.currentResult` (minus heavy buffers). Mirrors the
 * `_testApiDumpResult` shape in `src/app/app-test-api.js`.
 */
export interface ResultSnapshot {
  filename: string | null;
  dispatchId: string | null;
  formatTag: string | null;
  hasBuffer: boolean;
  hasYaraBuffer: boolean;
  bufferLength: number;
  rawTextLength: number;
  // Timeline-routed loads (CSV/TSV/EVTX/SQLite) surface a synthetic
  // `currentResult` shape — see `_testApiDumpResult` in
  // `src/app/app-test-api.js`. `timeline` is `false` for renderer
  // routes; `true` when the Timeline fast-path mounted the view.
  timeline?: boolean;
  timelineRowCount?: number;
}
export async function dumpResult(page: Page): Promise<ResultSnapshot | null> {
  return page.evaluate(() => {
    const w = window as unknown as {
      __loupeTest: { dumpResult(): unknown };
    };
    return w.__loupeTest.dumpResult() as unknown;
  }) as Promise<ResultSnapshot | null>;
}

// ── Severity / risk band assertions ──────────────────────────────────────────
// Loupe's risk floor escalates from 'low' through 'medium' / 'high' /
// 'critical' as `externalRefs` severities accumulate. Tests should
// assert on band membership, not exact strings — the floors retune
// over time and an exact match on 'medium' would flake when a renderer
// adds a new high-severity Pattern row that pushes the same fixture to
// 'high'. Use `expectRiskAtLeast` / `expectRiskInBand` to encode this
// posture once.
export const RISK_ORDER: Record<string, number> =
  { low: 0, medium: 1, high: 2, critical: 3 };

/** Assert `risk` is at least `floor`. `low`/`medium`/`high`/`critical`. */
export function isRiskAtLeast(risk: string | null | undefined, floor: string): boolean {
  if (risk == null) return false;
  if (!(risk in RISK_ORDER) || !(floor in RISK_ORDER)) return false;
  return RISK_ORDER[risk] >= RISK_ORDER[floor];
}

/** Assert `risk` is in the named band set. */
export function isRiskInBand(
  risk: string | null | undefined,
  bands: string[],
): boolean {
  if (risk == null) return bands.includes('low'); // null tolerated as 'low'
  return bands.includes(risk);
}

/**
 * Helper for renderers that produce text. Returns the set of YARA rule
 * names the page picked up — handy for cross-fixture assertions
 * without boilerplate. Reads from `findings.yaraHits` (which projects
 * `r.ruleName || r.rule || r.meta.id`).
 */
export function ruleNames(findings: FindingsSnapshot): string[] {
  return Array.from(new Set(
    (findings.yaraHits || [])
      .map(h => (h && h.rule) || '')
      .filter(Boolean),
  )).sort();
}
