// ════════════════════════════════════════════════════════════════════════════
// paste.spec.ts — UI-interaction e2e for the paste-into-page ingress
// path.
//
// The handler lives in `src/app/app-core.js:334` and forks based on
// what's on the clipboard:
//
//   1. `clipboardData.files[0]`            → load as a File
//   2. `clipboardData.items[*].type` is
//      `image/*`                           → load `getAsFile()` blob
//   3. `clipboardData.getData('text/plain')` → load as `clipboard.txt`
//   4. `clipboardData.getData('text/html')`  → load as `clipboard.html`
//
// We can't construct a real `ClipboardEvent` with a populated
// `clipboardData` attribute (it's read-only and not init-dict-settable
// per spec), and `navigator.clipboard.write` is permission-gated on
// `file://` URLs. The simplest reliable approach is to dispatch an
// event whose shape the handler accepts — `_handlePasteEvent(e)` only
// reads `e.clipboardData`, never `e instanceof ClipboardEvent`. We
// build a plain `Event('paste')` and assign a fake `clipboardData`
// object that mirrors the `DataTransfer` interface the handler uses
// (`files`, `items`, `getData`, `types`).
//
// This faithfully exercises the full paste handler chain
// (`_handlePasteEvent` → `_loadPastePayload` → `_loadFile`), guarding
// against regressions like:
//
//   • A future refactor that gates on `e instanceof ClipboardEvent`
//     would silently drop the synthetic event AND every legitimate
//     non-Chromium browser's paste — failing this test is the right
//     signal.
//   • Routing the text fork through a different `File` constructor
//     (e.g., dropping the `'clipboard.txt'` filename) would change
//     the renderer registry's dispatch and likely zero out IOCs.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { gotoBundle, dumpFindings, REPO_ROOT } from '../helpers/playwright-helpers';

test.describe('paste ingress', () => {
  test.beforeEach(async ({ page }) => {
    await gotoBundle(page);
  });

  test('plain-text paste lands a defanged-IOC fixture', async ({ page }) => {
    // Use `defanged-iocs.txt` — short, deterministic, and the
    // renderer-registry route is `plaintext`, which guarantees the
    // text fork was taken (a file-fork would produce a different
    // formatTag / extension dispatch).
    const fixture = path.join(
      REPO_ROOT, 'examples', 'encoded-payloads', 'defanged-iocs.txt');
    const text = fs.readFileSync(fixture, 'utf8');

    await page.evaluate(async ({ text }) => {
      // Fake DataTransfer surface — the handler only touches the four
      // members below. Crucially `files` is empty AND `items` is
      // empty (no image fork), so the handler falls through to the
      // text fork.
      const dt = {
        files: [] as File[],
        items: [] as DataTransferItem[],
        types: ['text/plain'],
        getData(kind: string) {
          if (kind === 'text/plain') return text;
          return '';
        },
      };
      const e = new Event('paste', { bubbles: true, cancelable: true });
      // `clipboardData` on a real ClipboardEvent is read-only — but
      // we're synthesising onto a plain Event whose own properties
      // are writable.
      Object.defineProperty(e, 'clipboardData', { value: dt });
      document.dispatchEvent(e);

      // Paste handler is synchronous through `_loadPastePayload`,
      // which calls `_loadFile` (async). Yield, then await idle.
      await new Promise(r => setTimeout(r, 0));
      const w = window as unknown as {
        __loupeTest: { waitForIdle(): Promise<void> };
      };
      await w.__loupeTest.waitForIdle();
    }, { text });

    const findings = await dumpFindings(page);
    // `defanged-iocs.txt` defangs URLs / emails — the renderer must
    // un-defang them and surface both as IOCs. Zero results means
    // the paste path failed to dispatch.
    expect(findings.iocTypes).toContain('URL');
    expect(findings.iocTypes).toContain('Email');
  });

  test('paste with both text/plain and text/html prefers plain', async ({ page }) => {
    // Regression guard: the handler MUST prefer `text/plain` over
    // `text/html` (see `app-core.js` comment "Prefer plain text over
    // HTML so that pasting from apps like Slack gives the actual
    // text content"). Build a clipboard that carries both — if the
    // handler ever inverts the priority, the renderer dispatch
    // changes (HTML → html renderer, plain → plaintext renderer)
    // and the assertion below fails.
    const plainText = 'http://example.com/from-plain-paste';
    const htmlText = '<a href="http://example.com/from-html-paste">link</a>';

    await page.evaluate(async ({ plainText, htmlText }) => {
      const dt = {
        files: [],
        items: [],
        types: ['text/plain', 'text/html'],
        getData(kind: string) {
          if (kind === 'text/plain') return plainText;
          if (kind === 'text/html') return htmlText;
          return '';
        },
      } as unknown as DataTransfer;
      const e = new Event('paste', { bubbles: true, cancelable: true });
      Object.defineProperty(e, 'clipboardData', { value: dt });
      document.dispatchEvent(e);
      await new Promise(r => setTimeout(r, 0));
      const w = window as unknown as {
        __loupeTest: { waitForIdle(): Promise<void> };
      };
      await w.__loupeTest.waitForIdle();
    }, { plainText, htmlText });

    const findings = await dumpFindings(page);
    // The plain text contains `from-plain-paste`. We don't pin the
    // exact URL list (the IOC extractor may normalise), but if the
    // handler routed the html fork the URL would carry
    // `from-html-paste` instead. Assert via substring.
    const urlValues = findings.iocs
      .filter(i => i.type === 'URL')
      .map(i => i.value)
      .join('|');
    expect(urlValues).toContain('from-plain-paste');
    expect(urlValues).not.toContain('from-html-paste');
  });

  test('paste falls through to text/html when text/plain is absent', async ({ page }) => {
    // Symmetric guard: if the handler can't get plain text, the
    // html fork MUST be taken. Without this the paste of an
    // HTML-only clipboard (e.g. Outlook copy-of-cell) silently
    // drops with a "Nothing to paste" toast.
    const htmlText = '<html><body><a href="http://example.com/html-only">x</a></body></html>';
    await page.evaluate(async ({ htmlText }) => {
      const dt = {
        files: [],
        items: [],
        types: ['text/html'],
        getData(kind: string) {
          if (kind === 'text/html') return htmlText;
          return '';
        },
      } as unknown as DataTransfer;
      const e = new Event('paste', { bubbles: true, cancelable: true });
      Object.defineProperty(e, 'clipboardData', { value: dt });
      document.dispatchEvent(e);
      await new Promise(r => setTimeout(r, 0));
      const w = window as unknown as {
        __loupeTest: { waitForIdle(): Promise<void> };
      };
      await w.__loupeTest.waitForIdle();
    }, { htmlText });

    const findings = await dumpFindings(page);
    // The HTML renderer extracts hrefs as URLs.
    expect(findings.iocTypes).toContain('URL');
  });

  test('paste inside a textarea is NOT intercepted (focus gate)', async ({ page }) => {
    // The handler bails out early for paste events whose target is
    // an `<input>` or `<textarea>` (so the YARA editor / search
    // bars work normally). Exercise this gate: focus the YARA
    // editor textarea (if it exists) and fire a paste — the page
    // must NOT load any file.
    await page.evaluate(async () => {
      // Inject a temporary textarea and focus it. Using a fresh
      // element keeps the test independent of UI surface changes.
      const ta = document.createElement('textarea');
      ta.id = '__paste_test_textarea__';
      document.body.appendChild(ta);
      ta.focus();

      const dt = {
        files: [],
        items: [],
        types: ['text/plain'],
        getData() { return 'http://example.com/should-not-load'; },
      } as unknown as DataTransfer;
      const e = new Event('paste', { bubbles: true, cancelable: true });
      Object.defineProperty(e, 'clipboardData', { value: dt });
      Object.defineProperty(e, 'target', { value: ta });
      ta.dispatchEvent(e);
      await new Promise(r => setTimeout(r, 50));
      ta.remove();
    });

    // Read findings — should remain at the empty-page state, NOT
    // the result of loading `http://example.com/should-not-load`.
    const findings = await dumpFindings(page);
    expect(findings.iocCount).toBe(0);
    expect(findings.risk).toBeNull();
  });

  test('paste while drilled-in resets the nav stack (no stale parent crumbs)', async ({ page }) => {
    // Regression guard for the bug where pasting a new file while the
    // user was drilled into an inner-child (zip member, decoded
    // payload, reassembled script, "All the way" chain) replaced the
    // visible view via `_loadFile` but left `_navStack` populated —
    // so the breadcrumb trail kept linking back to an unrelated
    // parent file whose buffer no longer matched the current
    // findings. Every other top-level ingress (drag-drop, file
    // picker, folder walkers, `_clearFile`) calls `_resetNavStack()`
    // first; paste was the outlier. The fix is four explicit
    // `_resetNavStack()` calls in `_loadPastePayload` (one per
    // successful-load branch, leaving the "Nothing to paste" branch
    // untouched). See `src/app/app-core.js`.

    // 1. Load a plaintext "parent" file through the normal ingress.
    await page.evaluate(async () => {
      const w = window as unknown as {
        __loupeTest: {
          loadBytes(name: string, bytes: Uint8Array): Promise<unknown>;
        };
      };
      const parent = new TextEncoder().encode('parent-file http://parent.example/');
      await w.__loupeTest.loadBytes('parent.txt', parent);
    });

    // 2. Simulate a drill-down by calling `openInnerFile` directly
    //    with a synthetic inner File. This pushes a frame onto
    //    `_navStack` and re-enters `_loadFile` — the same path
    //    taken by zip-row clicks, Deobfuscation "Load stitched
    //    script" buttons, etc.
    await page.evaluate(async () => {
      const w = window as unknown as {
        app: {
          openInnerFile(f: File, parentBuf: ArrayBuffer | null, ctx: unknown): void;
        };
        __loupeTest: { waitForIdle(): Promise<void> };
      };
      const innerBytes = new TextEncoder().encode('inner-file http://inner.example/');
      const innerFile = new File([innerBytes], 'inner.txt', { type: 'text/plain' });
      w.app.openInnerFile(innerFile, null, { parentName: 'parent.txt' });
      await w.__loupeTest.waitForIdle();
    });

    // Sanity: `_navStack` now holds exactly the parent frame so the
    // drill-down is genuine. Without this baseline the post-paste
    // assertion could pass trivially on an already-empty stack.
    const navDepthBefore = await page.evaluate(() => {
      const w = window as unknown as { app: { _navStack: unknown[] } };
      return w.app._navStack.length;
    });
    expect(navDepthBefore).toBe(1);

    // Also confirm the breadcrumb trail actually rendered a clickable
    // ancestor — the fix point of the bug is the visible trail, not
    // just the internal stack. Ancestor crumbs render as
    // `button.crumb` (not `.crumb-current`, which is the current
    // page's non-clickable span); a drilled-in state must surface at
    // least one such button.
    const ancestorCrumbsBefore = await page.evaluate(() => {
      const nav = document.getElementById('breadcrumbs');
      if (!nav) return 0;
      return nav.querySelectorAll('button.crumb:not(.crumb-current)').length;
    });
    expect(ancestorCrumbsBefore).toBeGreaterThan(0);

    // 3. Paste a fresh plaintext payload. Same synthetic-event shape
    //    used throughout this spec file.
    await page.evaluate(async () => {
      const dt = {
        files: [] as File[],
        items: [] as DataTransferItem[],
        types: ['text/plain'],
        getData(kind: string) {
          return kind === 'text/plain'
            ? 'pasted-after-drill http://pasted.example/'
            : '';
        },
      };
      const e = new Event('paste', { bubbles: true, cancelable: true });
      Object.defineProperty(e, 'clipboardData', { value: dt });
      document.dispatchEvent(e);
      await new Promise(r => setTimeout(r, 0));
      const w = window as unknown as {
        __loupeTest: { waitForIdle(): Promise<void> };
      };
      await w.__loupeTest.waitForIdle();
    });

    // 4. `_navStack` must be empty — paste is a fresh top-level
    //    load and any drill-down context from before belongs to a
    //    different analysis.
    const navDepthAfter = await page.evaluate(() => {
      const w = window as unknown as { app: { _navStack: unknown[] } };
      return w.app._navStack.length;
    });
    expect(navDepthAfter).toBe(0);

    // Breadcrumb nav must render only the current crumb (non-clickable
    // span) and no clickable ancestor buttons. Before the fix, the
    // parent/inner ancestors stayed linked and `_navJumpTo` could
    // navigate back into a buffer unrelated to the current findings.
    const ancestorCrumbsAfter = await page.evaluate(() => {
      const nav = document.getElementById('breadcrumbs');
      if (!nav) return -1;
      return nav.querySelectorAll('button.crumb:not(.crumb-current)').length;
    });
    expect(ancestorCrumbsAfter).toBe(0);

    // 5. The current findings must reflect the PASTED content, not
    //    the parent or the inner child. `_renderBreadcrumbs` derives
    //    the visible trail from `_navStack` + `_fileMeta`, so this
    //    doubles as a check that no stale ancestor is reachable.
    const findings = await dumpFindings(page);
    const urlValues = findings.iocs
      .filter(i => i.type === 'URL')
      .map(i => i.value)
      .join('|');
    expect(urlValues).toContain('pasted.example');
    expect(urlValues).not.toContain('parent.example');
    expect(urlValues).not.toContain('inner.example');
  });
});
