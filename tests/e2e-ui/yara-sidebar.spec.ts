// ════════════════════════════════════════════════════════════════════════════
// yara-sidebar.spec.ts — Regression for the collapsed Detections section
// during an in-flight YARA scan.
//
// The sidebar already renders a `.sb-yara-loading` row while `_yaraScanInProgress`
// is true, but pre-fix that row could sit inside a closed
// `details[data-sb-section="detections"]` when there were still zero detection
// rows. To the analyst this looked identical to "scan finished with no hits".
//
// This spec loads a clean plaintext file with auto-YARA disabled, stubs the
// manual-scan worker path so the scan stays pending, and asserts:
//   1. Detections expands while the scan is in flight.
//   2. The loading row is visible.
//   3. When the held scan resolves to zero matches, the section collapses again.
//
// We drive the manual scan directly through `app._yaraRunScan()` rather than
// opening the YARA dialog: the dialog widgets are irrelevant to this bug, while
// the sidebar rerender path is the production code we need to pin.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import { gotoBundle } from '../helpers/playwright-helpers';

test('Detections expands while YARA is pending and collapses again after zero matches', async ({ page }) => {
  await gotoBundle(page);

  // Seed a benign plaintext load with auto-YARA disabled so the starting
  // sidebar state is the "empty detections" case this regression targets.
  await page.evaluate(async () => {
    type AppShape = {
      _getAllYaraSource: () => string;
    };
    const w = window as unknown as {
      app: AppShape;
      __loupeTest: { loadBytes(name: string, bytes: string): Promise<unknown> };
    };
    const app = w.app;
    if (!app) throw new Error('window.app not ready');
    const originalGetAllYaraSource = app._getAllYaraSource;
    app._getAllYaraSource = () => '';
    try {
      await w.__loupeTest.loadBytes('clean.txt', 'just some harmless prose');
    } finally {
      app._getAllYaraSource = originalGetAllYaraSource;
    }
  });

  const detections = page.locator('details[data-sb-section="detections"]');
  const loading = detections.locator('.sb-yara-loading');
  await expect(detections).toHaveCount(1);
  await expect.poll(async () => (
    detections.evaluate(el => (el as HTMLDetailsElement).open)
  )).toBe(false);

  // Hold the worker result open so `_yaraScanInProgress` stays true long
  // enough for the test to inspect the live sidebar state deterministically.
  await page.evaluate(() => {
    type HeldResult = { results: unknown[]; scanErrors: unknown[] };
    type WorkerManagerShape = {
      workersAvailable?: () => boolean;
      runYara?: (buf: ArrayBuffer, source: string, opts?: unknown) => Promise<HeldResult>;
    };
    type AppShape = {
      _getAllYaraSource: () => string;
      _yaraRunScan: () => void;
    };
    type TestControls = {
      release(out: HeldResult): void;
      restore(): void;
    };
    const w = window as unknown as {
      app: AppShape;
      WorkerManager?: WorkerManagerShape;
      __yaraSidebarTest?: TestControls;
    };
    const app = w.app;
    if (!app || typeof app._yaraRunScan !== 'function') {
      throw new Error('app._yaraRunScan not available');
    }
    const wm = w.WorkerManager || (w.WorkerManager = {});
    const originalGetAllYaraSource = app._getAllYaraSource;
    const originalWorkersAvailable = wm.workersAvailable;
    const originalRunYara = wm.runYara;
    let resolvePending: ((out: HeldResult) => void) | null = null;

    w.__yaraSidebarTest = {
      release(out) {
        if (!resolvePending) throw new Error('No pending held YARA scan');
        const resolve = resolvePending;
        resolvePending = null;
        resolve(out);
      },
      restore() {
        app._getAllYaraSource = originalGetAllYaraSource;
        if (originalWorkersAvailable) wm.workersAvailable = originalWorkersAvailable;
        else delete wm.workersAvailable;
        if (originalRunYara) wm.runYara = originalRunYara;
        else delete wm.runYara;
      },
    };

    app._getAllYaraSource = () => [
      'rule Sidebar_Yara_No_Match',
      '{',
      '  condition:',
      '    false',
      '}',
    ].join('\n');
    wm.workersAvailable = () => true;
    wm.runYara = () => new Promise(resolve => {
      resolvePending = resolve;
    });

    app._yaraRunScan();
  });

  await expect.poll(async () => (
    detections.evaluate(el => (el as HTMLDetailsElement).open)
  )).toBe(true);
  await expect(loading).toBeVisible();

  await page.evaluate(async () => {
    type HeldResult = { results: unknown[]; scanErrors: unknown[] };
    type TestControls = {
      release(out: HeldResult): void;
      restore(): void;
    };
    const w = window as unknown as {
      __loupeTest: { waitForIdle(): Promise<void> };
      __yaraSidebarTest?: TestControls;
    };
    if (!w.__yaraSidebarTest) throw new Error('Held YARA scan controls missing');
    try {
      w.__yaraSidebarTest.release({ results: [], scanErrors: [] });
      await w.__loupeTest.waitForIdle();
    } finally {
      w.__yaraSidebarTest.restore();
      delete w.__yaraSidebarTest;
    }
  });

  await expect.poll(async () => (
    detections.evaluate(el => (el as HTMLDetailsElement).open)
  )).toBe(false);
  await expect(loading).toHaveCount(0);
});
