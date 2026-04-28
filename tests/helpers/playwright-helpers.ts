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
