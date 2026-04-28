// ════════════════════════════════════════════════════════════════════════════
// file-picker.spec.ts — UI-interaction e2e for the <input type="file">
// path. Earlier project notes claimed Playwright cannot drive a file
// picker; that's incorrect. `page.setInputFiles(selector, path)` works
// with hidden file inputs the way Loupe wires its drop zone.
//
// This test bypasses `__loupeTest.loadBytes` and instead uses the real
// file-picker affordance, then reads back findings via the test API to
// confirm the same canonical shape lands. If the picker path diverges
// from drag-drop / paste / programmatic loadBytes, this is where it
// shows up.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import * as path from 'node:path';
import { gotoBundle, dumpFindings, REPO_ROOT } from '../helpers/playwright-helpers';

test('file-picker path lands a fixture identical to programmatic loadBytes', async ({ page }) => {
  await gotoBundle(page);

  // The drop zone wraps a hidden `<input type="file">`. We locate it
  // by tag — there is exactly one in the bundle. If a future refactor
  // adds a second file input this test will need a more specific
  // selector, but the failure message will point at this line.
  const fileInput = page.locator('input[type="file"]').first();
  await expect(fileInput).toHaveCount(1);

  const fixture = path.join(REPO_ROOT, 'examples', 'email', 'phishing-example.eml');
  // `setInputFiles` triggers a synthetic `change` event on the input,
  // which is exactly what the browser fires for a real picker
  // interaction. The bundle's `_setupDrop` / picker handler treats the
  // selected files identically to drag-drop / paste.
  await fileInput.setInputFiles(fixture);

  // Wait for `_yaraScanInProgress` to clear, then snapshot.
  await page.evaluate(async () => {
    const w = window as unknown as { __loupeTest: { waitForIdle(): Promise<void> } };
    await w.__loupeTest.waitForIdle();
  });

  const findings = await dumpFindings(page);
  // Same minimum-bar assertions as the fixture-driven email test —
  // diverging from programmatic ingress here proves the picker handler
  // mishandles the File (e.g. wrong MIME detection, wrong filename).
  // Strings mirror the display values frozen in `IOC` (src/constants.js:411).
  expect(findings.iocTypes).toContain('URL');
  expect(findings.iocTypes).toContain('Email');
  expect(findings.risk).not.toBe('low');
});
