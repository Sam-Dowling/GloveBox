// ════════════════════════════════════════════════════════════════════════════
// drag-drop.spec.ts — UI-interaction e2e for the drag-and-drop ingress
// path.
//
// Playwright doesn't ship a first-class drag-and-drop helper that
// supplies `event.dataTransfer.files` (it has `page.dragAndDrop` for
// element drag, which is a different shape). We synthesise a `drop`
// event directly with a `DataTransfer` carrying a `File` — this is the
// exact event shape Chrome emits for a real OS drag. Loupe's
// `_setupDrop` listens for `'drop'` on the document body and forwards
// the file list to `_handleFiles`, the same entrypoint the file-picker
// uses, so this round-trip exercises the production code path without
// requiring an OS-level drag.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { gotoBundle, dumpFindings, REPO_ROOT } from '../helpers/playwright-helpers';

test('drag-drop synthesised drop event lands a fixture through the same path', async ({ page }) => {
  await gotoBundle(page);

  const fixture = path.join(REPO_ROOT, 'examples', 'email', 'phishing-example.eml');
  const bytes = fs.readFileSync(fixture);
  const b64 = bytes.toString('base64');
  const name = path.basename(fixture);

  // Synthesise the drop. The `DataTransfer` constructor exists in
  // modern Chromium (which is what Playwright drives); we attach a File
  // and dispatch `dragenter` → `dragover` → `drop` on `window`, which
  // is where `_setupDrop` (src/app/app-core.js:166) installs its
  // listeners. The listener gates on `dataTransfer.types.includes('Files')`
  // — which is set automatically when a File is added to a DataTransfer.
  await page.evaluate(async ({ b64, name }) => {
    const bin = atob(b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    const file = new File([u8], name, { type: 'message/rfc822' });

    const dt = new DataTransfer();
    dt.items.add(file);

    // Sanity-check the gate condition our test relies on. If a future
    // Chromium release stops auto-populating `types` for synthetic
    // DataTransfers, this assertion fails loudly here rather than as
    // a confusing "zero IOCs" downstream.
    if (!Array.from(dt.types).includes('Files')) {
      throw new Error('DataTransfer.types missing "Files"; cannot synthesise external file drag');
    }

    for (const evtName of ['dragenter', 'dragover', 'drop']) {
      const e = new DragEvent(evtName, {
        bubbles: true, cancelable: true, dataTransfer: dt,
      });
      window.dispatchEvent(e);
    }

    // Drop dispatch is synchronous, but the load chain it kicks off is
    // async. Wait for `__loupeTest.waitForIdle` to settle. We give the
    // microtask queue a tick first so the synchronous handler chain
    // has time to call `_handleFiles`.
    await new Promise(r => setTimeout(r, 0));
    const w = window as unknown as {
      __loupeTest: { waitForIdle(): Promise<void> };
    };
    await w.__loupeTest.waitForIdle();
  }, { b64, name });

  const findings = await dumpFindings(page);
  // Same minimum bar as the file-picker path. If drag-drop diverges
  // from picker / programmatic ingress this is where it surfaces —
  // typically as zero IOC findings because the drop handler dropped
  // the file on the floor.
  expect(findings.iocTypes).toContain('URL');
  expect(findings.iocTypes).toContain('Email');
  expect(findings.risk).not.toBe('low');
});
