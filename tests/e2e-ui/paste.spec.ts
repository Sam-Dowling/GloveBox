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
    // payload, reassembled script, layer-picker ▾ menu entry) replaced
    // the visible view via `_loadFile` but left `_navStack` populated —
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
    //    taken by zip-row clicks, Deobfuscation "Analyse Deobfuscated
    //    Script" buttons, etc.
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

  test('file fork: paste with dt.files[0] loads as a File', async ({ page }) => {
    // The first branch of `_loadPastePayload` (app-core.js:615): if
    // `dt.files.length > 0`, the first File is loaded directly and
    // the function returns. Every other fork (image / text / HTML)
    // is skipped. This is the highest-priority paste path and was
    // previously untested entirely.
    //
    // Synthetic DataTransfer with a real `File` in `files` exercises
    // the branch end-to-end: a fresh top-level load must reset the
    // nav stack AND route the buffer through the renderer registry
    // by filename.
    await page.evaluate(async () => {
      // Build a real File with a defanged URL so the plaintext
      // renderer surfaces an IOC — proves the dispatch went through.
      const bytes = new TextEncoder().encode('http://file-fork.example/ and some text');
      const file = new File([bytes], 'pasted-file.txt', { type: 'text/plain' });
      const dt = {
        files: [file],
        items: [],
        types: ['Files'],
        getData() { return ''; },
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

    const findings = await dumpFindings(page);
    const urlValues = findings.iocs
      .filter(i => i.type === 'URL')
      .map(i => i.value)
      .join('|');
    expect(urlValues).toContain('file-fork.example');
    // File-fork takes priority over text — fixture had no text/plain
    // so the text fork could NOT have satisfied this. This assertion
    // confirms the dispatch specifically came from dt.files.
    expect(urlValues).not.toContain('clipboard.txt');

    // Nav-stack reset also applies to this branch (one of the four
    // `_resetNavStack()` call sites). Paste from a drilled-in state
    // is equivalent to paste from fresh — asserted separately in the
    // dedicated nav-reset test above.
    const navDepth = await page.evaluate(() => {
      const w = window as unknown as { app: { _navStack: unknown[] } };
      return w.app._navStack.length;
    });
    expect(navDepth).toBe(0);
  });

  test('image fork: paste with items[*].type=image/png loads via getAsFile()', async ({ page }) => {
    // The second branch of `_loadPastePayload` (app-core.js:627):
    // iterate `dt.items`, find one whose type starts with `image/`,
    // call `item.getAsFile()`, wrap as a File named
    // `clipboard.<subtype>`. Previously untested.
    //
    // The image is a minimal 1×1 PNG — the image renderer surfaces
    // a metadata entry ("PNG · 1×1 …") in `findings.metadata`, which
    // is a reliable signal that the dispatch took the image path.
    // A text dispatch would land `text/plain` and produce no image
    // metadata.
    await page.evaluate(async () => {
      // 1×1 transparent PNG (67 bytes). Deterministic, standards-conformant.
      const pngBytes = new Uint8Array([
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
        0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41,
        0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
        0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
        0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
        0x42, 0x60, 0x82,
      ]);
      const blob = new Blob([pngBytes], { type: 'image/png' });
      // Synthetic DataTransferItem — the handler reads `.type` and
      // calls `.getAsFile()`. No need to mimic the full spec; the
      // handler's surface is narrow.
      const item = {
        type: 'image/png',
        getAsFile() { return new File([blob], 'pasted.png', { type: 'image/png' }); },
      };
      const dt = {
        files: [],
        items: [item],
        types: ['image/png'],
        getData() { return ''; },
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

    // The image dispatched — the breadcrumb current-crumb carries
    // the synthesised `clipboard.png` filename (the handler wraps
    // the blob as `clipboard.<ext>`), and the renderer registry
    // routed to the image renderer. `_fileMeta.name` is the most
    // direct witness for the fork choice.
    const fileMetaName = await page.evaluate(() => {
      const w = window as unknown as { app: { _fileMeta: { name?: string } | null } };
      return (w.app._fileMeta && w.app._fileMeta.name) || '';
    });
    expect(fileMetaName).toMatch(/^clipboard\.png$/);

    // Nav-stack reset invariant — one of the four reset call sites.
    const navDepth = await page.evaluate(() => {
      const w = window as unknown as { app: { _navStack: unknown[] } };
      return w.app._navStack.length;
    });
    expect(navDepth).toBe(0);
  });

  test('cached-copy roundtrip: same-session paste restores original bytes + filename', async ({ page }) => {
    // Regression guard for the CRLF / extension silent-rewrite bug
    // (`app-core.js:654`). When `_copyContent` stashes the source
    // buffer + filename in `_lastCopiedMeta`, a subsequent paste of
    // text that matches the cached `normText` (modulo CRLF → LF)
    // must reload the ORIGINAL File — same name, same SHA-256 —
    // not a freshly-built `clipboard.txt` with a different
    // extension and a CRLF-stripped body.
    //
    // Without the cache check the pasted text's renderer dispatch
    // falls through to highlight.js language auto-detect, which is
    // a confusing result for a security tool where the file hash
    // is the identity.
    await page.evaluate(async () => {
      const w = window as unknown as {
        app: {
          _lastCopiedMeta: { name: string; buffer: ArrayBuffer; normText: string } | null;
        };
      };
      // Simulate `_copyContent` having populated the cache. Use a
      // .applescript name so the round-trip path MUST restore the
      // extension (falling through to `clipboard.txt` would drop
      // the `.applescript` and pin the bug).
      const originalText = 'osascript -e "tell application \\"Safari\\" to activate"';
      const buffer = new TextEncoder().encode(originalText).buffer;
      w.app._lastCopiedMeta = {
        name: 'payload.applescript',
        buffer,
        normText: originalText,
      };

      // Paste the same text — handler must match on `normText` and
      // reload `buffer` under the original name.
      const dt = {
        files: [],
        items: [],
        types: ['text/plain'],
        getData(kind: string) {
          return kind === 'text/plain' ? originalText : '';
        },
      };
      const e = new Event('paste', { bubbles: true, cancelable: true });
      Object.defineProperty(e, 'clipboardData', { value: dt });
      document.dispatchEvent(e);
      await new Promise(r => setTimeout(r, 0));
      const wt = window as unknown as {
        __loupeTest: { waitForIdle(): Promise<void> };
      };
      await wt.__loupeTest.waitForIdle();
    });

    // Filename preserved — NOT `clipboard.txt`.
    const fileMetaName = await page.evaluate(() => {
      const w = window as unknown as { app: { _fileMeta: { name?: string } | null } };
      return (w.app._fileMeta && w.app._fileMeta.name) || '';
    });
    expect(fileMetaName).toBe('payload.applescript');
  });

  test('nothing-to-paste: empty clipboard surfaces the error toast', async ({ page }) => {
    // The terminal branch of `_loadPastePayload` (app-core.js:681):
    // no files, no image items, no text/plain, no text/html →
    // `_toast('Nothing to paste', 'error')`. This branch intentionally
    // skips `_resetNavStack()` (no-op on a no-op paste). The toast
    // is the user's only feedback that the paste was seen at all.
    await page.evaluate(async () => {
      const dt = {
        files: [],
        items: [],
        types: [],
        getData() { return ''; },
      };
      const e = new Event('paste', { bubbles: true, cancelable: true });
      Object.defineProperty(e, 'clipboardData', { value: dt });
      document.dispatchEvent(e);
      // Toast is set synchronously via setTimeout-hidden after 3s;
      // a small yield is enough to let the handler run.
      await new Promise(r => setTimeout(r, 0));
    });

    // The toast element receives the error text + `.toast-error`
    // class. Read both; either changing independently breaks the
    // user-visible contract.
    const toastState = await page.evaluate(() => {
      const el = document.getElementById('toast');
      return {
        text: el ? el.textContent : null,
        cls: el ? el.className : null,
        hidden: el ? el.classList.contains('hidden') : null,
      };
    });
    expect(toastState.text).toBe('Nothing to paste');
    expect(toastState.cls).toContain('toast-error');
    expect(toastState.hidden).toBe(false);

    // No file was loaded — findings must remain at the empty state.
    const findings = await dumpFindings(page);
    expect(findings.iocCount).toBe(0);
  });

  test('line-wrapped Base64 payload decodes as a single block (not per-line garbage)', async ({ page }) => {
    // Regression guard for the bug where a MIME / PEM / here-string
    // style wrapped Base64 payload (newlines every 50-76 chars)
    // surfaced as either (a) no Base64 finding at all (every chunk
    // below the 64-char default floor) or (b) a swarm of per-line
    // short candidates that each decoded at a misaligned boundary,
    // producing high-entropy junk and hiding the real PE payload.
    //
    // The fix is the `_scanWrappedBlocks` pre-pass in
    // `src/decoders/base64-hex.js` plus a defensive `\s+` strip in
    // `_decodeBase64`. When a wrapped block starts with one of the
    // HIGH_CONFIDENCE_B64 prefixes (`TVqQ` here for PE-MZ), the
    // candidate is auto-decoded and the Deobfuscation card surfaces
    // the classification.
    //
    // We drive the load via the public `__loupeTest.loadBytes` test
    // API rather than the synthetic paste path. The handler fork
    // that builds a `clipboard.txt` File (see the earlier paste
    // tests in this file) is identical from `_loadFile` onwards —
    // this test's concern is the detector's wrapped-block pipeline,
    // not the clipboard event plumbing.
    await page.evaluate(async () => {
      // 104-byte PE header + DOS stub. Starts with 4D 5A so the b64
      // form begins with `TVqQ` (PE high-confidence prefix).
      const header = new Uint8Array([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
        0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
        0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
        0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
      ]);
      // Browser btoa over the raw byte string.
      let bin = '';
      for (let i = 0; i < header.length; i++) bin += String.fromCharCode(header[i]);
      const clean = btoa(bin);
      // Wrap at 60 cols with CRLF — typical here-string / MIME shape.
      const wrapped = (clean.match(/.{1,60}/g) || []).join('\r\n');
      const text = `# sample payload\n# pasted from a write-up\n\n${wrapped}\n`;

      // Load the same way the paste handler does — as a `clipboard.txt`
      // File, but through the public `loadBytes` test API so we don't
      // race the paste handler's sync-before-async step.
      const w = window as unknown as {
        __loupeTest: {
          loadBytes(name: string, bytes: Uint8Array): Promise<unknown>;
          waitForIdle(): Promise<void>;
        };
      };
      await w.__loupeTest.loadBytes('clipboard.txt', new TextEncoder().encode(text));
      await w.__loupeTest.waitForIdle();
    });

    // Read the encoded-content findings directly from app.findings.
    // `dumpFindings` doesn't project the full encoded tree, so reach
    // into the sidebar-facing structure via a page-side evaluate.
    const enc = await page.evaluate(() => {
      const w = window as unknown as {
        app: {
          findings: { encodedContent?: Array<Record<string, unknown>> };
        };
      };
      const list = w.app.findings.encodedContent || [];
      return list.map(f => ({
        encoding: f.encoding,
        chain: f.chain,
        classification: f.classification,
        severity: f.severity,
        offset: f.offset,
        length: f.length,
        decodedSize: f.decodedSize,
        autoDecoded: f.autoDecoded,
      }));
    });

    // Expect at least one Base64 finding whose decoded classification
    // identifies the PE executable. Without the wrapped-block fix
    // the detector either emits no finding (sub-64-char chunks) or
    // emits per-line junk findings (misaligned-boundary garbage
    // never classifies as PE).
    const peHit = enc.find(f =>
      f.encoding === 'Base64' &&
      f.classification && (f.classification as { type?: string }).type &&
      String((f.classification as { type?: string }).type).includes('PE')
    );
    expect(peHit,
      `expected a Base64 finding classified as PE Executable; got: ${JSON.stringify(enc)}`
    ).toBeTruthy();
    expect((peHit as { autoDecoded: boolean }).autoDecoded).toBe(true);
  });
});
