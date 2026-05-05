// ════════════════════════════════════════════════════════════════════════════
// folder-drag.spec.ts — UI-interaction e2e for folder / multi-file drag-drop
// + `webkitdirectory` picker ingest paths.
//
// The 4-way `App._handleFiles` ingress router (`src/app/app-core.js`) picks
// among:
//
//   1. Directory drop  — `dataTransfer.items` carries
//      `webkitGetAsEntry()` results; one or more `isDirectory` entries
//      → `FolderFile.fromEntries(rootName, sources)` async walker.
//   2. `webkitdirectory` picker — `FileList` whose every leaf carries a
//      `webkitRelativePath`; we group by the first path segment.
//   3. Loose multi-file drop / multi-select picker — bundled under a
//      synthetic "Dropped files" root (fixes the historic `files[0]`
//      truncation that silently lost files 1..N).
//   4. Single file — falls through to the regular `_loadFile` path.
//
// Playwright cannot synthesise an OS-level directory drag (the
// `FileSystemEntry` interface is browser-instantiated only), so we
// exercise paths 1 / 2 / 3 by calling `app._handleFiles(...)` directly
// with hand-rolled inputs:
//   • Path 1 — pass mock `FileSystemEntry` objects (the walker only
//     touches `.isDirectory`, `.isFile`, `.name`, `.fullPath`,
//     `.createReader().readEntries(cb, errCb)`, and `.file(cb,
//     errCb)`); shape parity with the real interface is the entire
//     contract.
//   • Path 2 — `Object.defineProperty` `webkitRelativePath` onto each
//     `File` (the picker is the only producer in production; can't
//     pass it via the constructor).
//   • Path 3 — a plain array of `File` objects with no other hints.
//
// Click-to-drill and Back-restore tests then exercise the
// `open-inner-file` CustomEvent recursion that the ArchiveTree row
// click handler bubbles up.
// ════════════════════════════════════════════════════════════════════════════

import { test, expect } from '@playwright/test';
import { gotoBundle } from '../helpers/playwright-helpers';

test.describe('folder ingest', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeEach(async ({ page }) => {
    await gotoBundle(page);
  });

  // ── Path 3: loose multi-file drop ──────────────────────────────────
  // Two text files dropped together. Should land on `FolderRenderer`,
  // produce a tree with both leaves, and skip auto-YARA + encoded
  // detection (the renderer's filename-heuristics analyser runs but
  // none of the heuristics fire for two clean .txt names).
  test('multi-file loose drop synthesises a folder root', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const w = window as unknown as {
        app: {
          _handleFiles(files: File[]): void;
          _testApiWaitForIdle(opts?: { timeoutMs?: number }): Promise<void>;
          _testApiDumpResult(): unknown;
          _testApiDumpFindings(): unknown;
          _fileMeta: { name?: string } | null;
          findings: { encodedContent: unknown[] } | null;
          currentResult: { yaraHits?: unknown[] } | null;
        };
      };
      const f1 = new File(['hello world\n'], 'one.txt', { type: 'text/plain' });
      const f2 = new File(['second file\n'], 'two.txt', { type: 'text/plain' });
      w.app._handleFiles([f1, f2]);
      await w.app._testApiWaitForIdle({ timeoutMs: 10000 });
      return {
        result: w.app._testApiDumpResult(),
        findings: w.app._testApiDumpFindings(),
        encodedContentLen: (w.app.findings?.encodedContent || []).length,
        // `currentResult.filename` is never populated by the load
        // pipeline (only `navTitle` is) — read the canonical
        // breadcrumb name from `_fileMeta.name` instead.
        fileMetaName: w.app._fileMeta && w.app._fileMeta.name,
      };
    });

    const r = result.result as { dispatchId: string };
    expect(r.dispatchId).toBe('folder');
    expect(result.fileMetaName).toBe('Dropped files');
    // Folder roots short-circuit encoded-content + auto-YARA — both
    // would produce noise on filename-only text. See `app-load.js`'s
    // `isFolderRoot` branch.
    expect(result.encodedContentLen).toBe(0);
    const f = result.findings as { yaraHits: unknown[] };
    expect(Array.isArray(f.yaraHits)).toBe(true);
    expect(f.yaraHits.length).toBe(0);

    // Tree should render both leaves.
    const rowCount = await page.locator('.folder-view .arch-tree-row').count();
    expect(rowCount).toBeGreaterThanOrEqual(2);
    const headerText = await page.locator('.folder-title').innerText();
    expect(headerText).toContain('Dropped files');
    // Regression: loose-file paths must NOT carry a `Dropped files/`
    // prefix — the synthetic root carries that label in its header
    // only. Without the strip, the tree showed `Dropped files →
    // Dropped files → one.txt`.
    const treeFolderNames = await page
      .locator('.folder-view .arch-tree-folder .arch-tree-name')
      .allInnerTexts();
    expect(treeFolderNames).not.toContain('Dropped files');
  });

  // ── Path 2: webkitdirectory-style picker ───────────────────────────
  // A picker configured with `webkitdirectory` flattens the directory
  // tree but stamps each File with `webkitRelativePath`. The router
  // recognises this and uses the first path segment ("Samples") as the
  // synthetic root name.
  test('webkitdirectory picker (relative paths) keeps the real root name', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const w = window as unknown as {
        app: {
          _handleFiles(files: File[]): void;
          _testApiWaitForIdle(opts?: { timeoutMs?: number }): Promise<void>;
          _testApiDumpResult(): unknown;
          _fileMeta: { name?: string } | null;
        };
      };
      const mk = (name: string, rel: string) => {
        const f = new File([`${name} body\n`], name, { type: 'text/plain' });
        Object.defineProperty(f, 'webkitRelativePath',
          { value: rel, configurable: true });
        return f;
      };
      const files = [
        mk('a.txt', 'Samples/a.txt'),
        mk('b.txt', 'Samples/sub/b.txt'),
        mk('c.txt', 'Samples/sub/c.txt'),
      ];
      w.app._handleFiles(files);
      await w.app._testApiWaitForIdle({ timeoutMs: 10000 });
      return {
        result: w.app._testApiDumpResult(),
        fileMetaName: w.app._fileMeta && w.app._fileMeta.name,
      };
    });
    const r = result.result as { dispatchId: string };
    expect(r.dispatchId).toBe('folder');
    expect(result.fileMetaName).toBe('Samples');
    const headerText = await page.locator('.folder-title').innerText();
    expect(headerText).toContain('Samples');
    // Regression: `webkitRelativePath` includes the root segment
    // (`Samples/sub/b.txt`); the ingress router must strip it so the
    // tree doesn't show a redundant `Samples` subfolder under the
    // renderer's `📁 Samples` header.
    const treeFolderNames = await page
      .locator('.folder-view .arch-tree-folder .arch-tree-name')
      .allInnerTexts();
    expect(treeFolderNames).not.toContain('Samples');
    expect(treeFolderNames).toContain('sub');
  });

  // ── Path 1: directory drop via mock FileSystemEntry tree ───────────
  // The walker (`FolderFile.fromEntries`) only consults the documented
  // FileSystemEntry surface — `.isDirectory`, `.isFile`, `.name`,
  // `.fullPath`, `.createReader().readEntries(cb, errCb)`, `.file(cb,
  // errCb)` — so a hand-rolled mock with the same shape is contract-
  // equivalent. We build a small two-leaf tree:
  //
  //     payload/
  //       inner/
  //         note.txt
  //       readme.txt
  test('directory drop walks via webkitGetAsEntry mocks', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const w = window as unknown as {
        app: {
          _handleFiles(files: unknown, opts: { fsEntries: unknown[] }): void;
          _testApiWaitForIdle(opts?: { timeoutMs?: number }): Promise<void>;
          _testApiDumpResult(): unknown;
          _fileMeta: { name?: string } | null;
        };
      };
      const mkFileEntry = (name: string, body: string, full: string) => ({
        isFile: true,
        isDirectory: false,
        name,
        fullPath: full,
        // FileSystemFileEntry.file: callback API.
        file(ok: (f: File) => void, _err?: (e: Error) => void) {
          const f = new File([body], name, { type: 'text/plain' });
          ok(f);
        },
      });
      const mkDirEntry = (name: string, full: string, kids: unknown[]) => ({
        isFile: false,
        isDirectory: true,
        name,
        fullPath: full,
        createReader() {
          let drained = false;
          return {
            // FileSystemDirectoryReader.readEntries: returns batch then
            // empty on subsequent calls. Production walker loops until
            // empty so a single batch is sufficient for test fixtures.
            readEntries(ok: (entries: unknown[]) => void) {
              if (drained) ok([]);
              else { drained = true; ok(kids); }
            },
          };
        },
      });
      const root = mkDirEntry('payload', '/payload', [
        mkFileEntry('readme.txt', 'top-level readme\n', '/payload/readme.txt'),
        mkDirEntry('inner', '/payload/inner', [
          mkFileEntry('note.txt', 'nested note\n', '/payload/inner/note.txt'),
        ]),
      ]);
      w.app._handleFiles(null, { fsEntries: [root] });
      await w.app._testApiWaitForIdle({ timeoutMs: 10000 });
      return {
        result: w.app._testApiDumpResult(),
        fileMetaName: w.app._fileMeta && w.app._fileMeta.name,
      };
    });
    const r = result.result as { dispatchId: string };
    expect(r.dispatchId).toBe('folder');
    // Single top-level dir → use its real name as the synthetic root.
    expect(result.fileMetaName).toBe('payload');
    // Both leaves should render in the tree (readme.txt + inner/note.txt).
    const rowPaths = await page
      .locator('.folder-view .arch-col-path')
      .allInnerTexts();
    const joined = rowPaths.join('\n');
    expect(joined).toContain('readme.txt');
    expect(joined).toContain('note.txt');

    // ── Regression: no redundant `payload/payload/...` nesting ────────
    // Historic bug — `FolderFile.fromEntries` prefixed every path with
    // the rootName, which combined with `entry.fullPath = '/payload'`
    // produced `payload/payload/readme.txt` and an extra subfolder
    // mirroring the root under the renderer's `📁 payload` header.
    // After the fix, the root IS the dropped directory: top-level
    // leaves carry bare basenames, subdirs carry `<dir>/<leaf>`. Assert
    // no `.arch-tree-name` element inside the tree spells `payload`.
    const treeFolderNames = await page
      .locator('.folder-view .arch-tree-folder .arch-tree-name')
      .allInnerTexts();
    expect(treeFolderNames).not.toContain('payload');
    // The `inner` subfolder SHOULD be present though.
    expect(treeFolderNames).toContain('inner');
  });

  // ── Click-to-drill ─────────────────────────────────────────────────
  // Verify the bubbled `open-inner-file` CustomEvent the ArchiveTree
  // row click handler emits drives `App.openInnerFile` and re-enters
  // `_loadFile` for the per-leaf scan. The renderer wires this in
  // `FolderRenderer.render` → `ArchiveTree.render({ onOpen })`.
  test('clicking a folder entry drills into the leaf file', async ({ page }) => {
    await page.evaluate(async () => {
      const w = window as unknown as {
        app: {
          _handleFiles(files: File[]): void;
          _testApiWaitForIdle(opts?: { timeoutMs?: number }): Promise<void>;
        };
      };
      const evil = new File(
        ['Subject: Click here http://malicious.example/login\n'],
        'phish.eml', { type: 'message/rfc822' });
      const benign = new File(['hi\n'], 'hi.txt', { type: 'text/plain' });
      w.app._handleFiles([evil, benign]);
      await w.app._testApiWaitForIdle({ timeoutMs: 10000 });
    });

    // The ArchiveTree row exposes the file name in `.arch-col-path`.
    // Find the row for `phish.eml` and trigger its open button. The
    // button is `opacity: 0` until row hover (CSS in viewers.css), so
    // Playwright's visibility-aware `.click()` refuses even with
    // `force: true`. The click protocol itself is what we're testing
    // — dispatch the synthetic click directly via DOM, which is what
    // every analyst's pointer eventually does once the row is hovered.
    await page.evaluate(() => {
      const row = Array.from(document.querySelectorAll<HTMLElement>(
        '.folder-view .arch-tree-row'))
        .find(r => r.textContent && r.textContent.includes('phish.eml'));
      if (!row) throw new Error('phish.eml row not found in tree');
      const btn = row.querySelector<HTMLButtonElement>('.arch-open-btn');
      if (!btn) throw new Error('open button missing on phish.eml row');
      btn.click();
    });

    // Wait for the inner load to settle. `_testApiWaitForIdle`'s
    // `while (!currentResult)` check returns immediately (the folder's
    // `currentResult` is still installed at this point), so a bare wait
    // here races against the inner `_loadFile` writing the leaf's
    // result. Poll for the dispatch transition explicitly.
    const result = await page.evaluate(async () => {
      const w = window as unknown as {
        app: {
          _testApiWaitForIdle(opts?: { timeoutMs?: number }): Promise<void>;
          _testApiDumpResult(): { dispatchId: string };
          _fileMeta: { name?: string } | null;
          currentResult: { dispatchId?: string } | null;
        };
      };
      const t0 = Date.now();
      while (Date.now() - t0 < 10000) {
        if (w.app.currentResult
            && w.app.currentResult.dispatchId
            && w.app.currentResult.dispatchId !== 'folder') break;
        await new Promise(r => setTimeout(r, 25));
      }
      await w.app._testApiWaitForIdle({ timeoutMs: 10000 });
      return {
        result: w.app._testApiDumpResult(),
        fileMetaName: w.app._fileMeta && w.app._fileMeta.name,
      };
    });
    expect(result.result.dispatchId).not.toBe('folder');
    expect(result.fileMetaName).toBe('phish.eml');
  });

  // ── Per-sibling budget reset on Back ──────────────────────────────
  // Confirms that `_restoreNavFrame` resets `_archiveBudget` when the
  // restored frame is a folder root — so opening sibling 1, going
  // Back, and opening sibling 2 doesn't bleed budget across them.
  // We don't actually exhaust the budget (256 MiB / 50k entries — too
  // expensive for an e2e); instead we drill in then back, and assert
  // that the budget's tracked entry count was reset.
  test('Back navigation from a folder leaf resets _archiveBudget', async ({ page }) => {
    await page.evaluate(async () => {
      const w = window as unknown as {
        app: {
          _handleFiles(files: File[]): void;
          _testApiWaitForIdle(opts?: { timeoutMs?: number }): Promise<void>;
        };
      };
      const a = new File(['a\n'], 'a.txt', { type: 'text/plain' });
      const b = new File(['b\n'], 'b.txt', { type: 'text/plain' });
      w.app._handleFiles([a, b]);
      await w.app._testApiWaitForIdle({ timeoutMs: 10000 });
    });

    // Drill into one leaf, then back via the nav-stack jump helper
    // (the user-facing Back button calls `_navJumpTo(depth - 1)`).
    // Click via DOM evaluation — same rationale as the previous test:
    // the open button is `opacity: 0` until row hover.
    await page.evaluate(() => {
      const row = Array.from(document.querySelectorAll<HTMLElement>(
        '.folder-view .arch-tree-row'))
        .find(r => r.textContent && r.textContent.includes('a.txt'));
      if (!row) throw new Error('a.txt row not found in tree');
      const btn = row.querySelector<HTMLButtonElement>('.arch-open-btn');
      if (!btn) throw new Error('open button missing on a.txt row');
      btn.click();
    });
    await page.evaluate(async () => {
      const w = window as unknown as {
        app: {
          _testApiWaitForIdle(opts?: { timeoutMs?: number }): Promise<void>;
          _navJumpTo(depth: number): void;
        };
      };
      await w.app._testApiWaitForIdle({ timeoutMs: 10000 });
      // Restore the folder root (depth 0) — same path the breadcrumb
      // / Back button takes.
      w.app._navJumpTo(0);
      await w.app._testApiWaitForIdle({ timeoutMs: 10000 });
    });

    // Folder root should be back on screen, and the budget reset.
    const state = await page.evaluate(() => {
      const w = window as unknown as {
        app: {
          _archiveBudget: { entries: number; bytes: number };
          _testApiDumpResult(): { dispatchId: string };
        };
      };
      return {
        dispatchId: w.app._testApiDumpResult().dispatchId,
        budgetEntries: w.app._archiveBudget.entries,
        budgetBytes: w.app._archiveBudget.bytes,
      };
    });
    expect(state.dispatchId).toBe('folder');
    expect(state.budgetEntries).toBe(0);
    expect(state.budgetBytes).toBe(0);
  });

  // ── Folder magic predicate fires from the registry ─────────────────
  // Sanity: a fresh `RendererRegistry.detect()` over a `FolderFile`
  // returns `{ id: 'folder', via: 'magic' }`. If anyone ever
  // re-orders the ENTRIES list and demotes the folder predicate
  // below, say, the OLE entry, the directory-drop test above would
  // pass (because the dispatch falls through correctly) but routing
  // becomes order-fragile — this test catches that regression
  // directly at the registry layer.
  test('RendererRegistry.detect identifies folder via magic predicate', async ({ page }) => {
    const decision = await page.evaluate(() => {
      // `class` declarations at script top level become global
      // bindings reachable as bare identifiers, but they are NOT
      // attached to `window` (that's `var`/`function`-only). Inside
      // `page.evaluate` the function body executes with the page's
      // global scope, so a bare `RendererRegistry` reference
      // resolves correctly. CSP forbids `eval`, so bare-identifier
      // access is the only path.
      // @ts-expect-error - RendererRegistry is a top-level class binding in the bundle
      const Registry = RendererRegistry as {
        makeContext(file: unknown, buf: ArrayBuffer): unknown;
        detect(ctx: unknown): { id: string; via: string };
      };
      const FolderFileCtor = (window as unknown as {
        FolderFile: new (name: string) => unknown }).FolderFile;
      const folder = new FolderFileCtor('Test');
      // FolderFile carries `_loupeFolderEntries` — a marker the
      // registry magic predicate at the top of ENTRIES keys on. With
      // an empty list the predicate still fires (`!!ctx.file._loupeFolderEntries`
      // is `true` for an empty array because the array is truthy).
      const ctx = Registry.makeContext(folder, new ArrayBuffer(0));
      return Registry.detect(ctx);
    });
    expect(decision.id).toBe('folder');
    expect(decision.via).toBe('magic');
  });

  // ── Auto-expand: folder roots open fully expanded ──────────────────
  // FolderRenderer passes `expandAll: true` to ArchiveTree so the
  // analyst sees the entire structure on first paint (the dropped
  // folder is hard-capped at MAX_FOLDER_ENTRIES = 4 096, bounding
  // first-paint cost). Reuse the `payload/inner/note.txt` fixture so
  // we know there's at least one nested folder to verify state on.
  test('folder roots render with every folder expanded on first paint', async ({ page }) => {
    await page.evaluate(async () => {
      const w = window as unknown as {
        app: {
          _handleFiles(files: unknown, opts: { fsEntries: unknown[] }): void;
          _testApiWaitForIdle(opts?: { timeoutMs?: number }): Promise<void>;
        };
      };
      const mkFileEntry = (name: string, body: string) => ({
        isFile: true,
        isDirectory: false,
        name,
        fullPath: '/' + name,
        file(ok: (f: File) => void) {
          ok(new File([body], name, { type: 'text/plain' }));
        },
      });
      const mkDirEntry = (name: string, kids: unknown[]) => ({
        isFile: false,
        isDirectory: true,
        name,
        fullPath: '/' + name,
        createReader() {
          let drained = false;
          return {
            readEntries(ok: (entries: unknown[]) => void) {
              if (drained) ok([]);
              else { drained = true; ok(kids); }
            },
          };
        },
      });
      const root = mkDirEntry('payload', [
        mkFileEntry('readme.txt', 'top\n'),
        mkDirEntry('inner', [mkFileEntry('note.txt', 'nested\n')]),
        mkDirEntry('alsoinner', [mkFileEntry('extra.txt', 'extra\n')]),
      ]);
      w.app._handleFiles(null, { fsEntries: [root] });
      await w.app._testApiWaitForIdle({ timeoutMs: 10000 });
    });

    // Every `<li class="arch-tree-folder">` should have its
    // `.arch-tree-folder-row` flagged `aria-expanded="true"`, and no
    // `.arch-tree-children` should carry the `[hidden]` attribute that
    // the default-collapsed render produces.
    const ariaCount = await page
      .locator('.folder-view .arch-tree-folder-row[aria-expanded="true"]')
      .count();
    expect(ariaCount).toBeGreaterThanOrEqual(2); // inner + alsoinner

    const collapsedAria = await page
      .locator('.folder-view .arch-tree-folder-row[aria-expanded="false"]')
      .count();
    expect(collapsedAria).toBe(0);

    const hiddenChildren = await page
      .locator('.folder-view .arch-tree-children[hidden]')
      .count();
    expect(hiddenChildren).toBe(0);

    // The deeper leaves (e.g. `inner/note.txt`) should be visible —
    // their `<li>` is reachable via DOM with no enclosing `[hidden]`
    // ancestor. Smoke-check by asserting the row is in the layout.
    const noteVisible = await page
      .locator('.folder-view .arch-tree-row:has-text("note.txt")')
      .first()
      .isVisible();
    expect(noteVisible).toBe(true);
  });

  // ── Chromium macOS EncodingError fallback ─────────────────────────
  // Chromium on macOS throws
  //   EncodingError: A URI supplied to the API was malformed...
  // from `createReader().readEntries(...)` on otherwise-valid folder
  // drops. It's a known browser bug with no JS-side recovery for the
  // descriptor (crbug.com tracker hits since Chrome 128+ on macOS).
  //
  // Pre-fix behaviour: the walker swallowed the error, latched
  // `truncated = true`, and dispatched an empty `FolderFile`. The
  // analyst saw an empty tree under a misleading "Folder ingest
  // truncated at 4,096 entries" toast.
  //
  // Post-fix contract:
  //   1. If the drop also carried loose top-level files
  //      (`DataTransfer.files`), fall back to the loose-file path so
  //      the analyst gets a tree with what WAS readable.
  //   2. If there were no loose files to fall back to, surface a clear
  //      toast pointing at the Open button. Never dispatch an empty
  //      folder view, never claim we "truncated at 4,096".
  test('Chromium EncodingError on folder walk falls back to loose files', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const w = window as unknown as {
        app: {
          _handleFiles(files: unknown, opts: { fsEntries: unknown[] }): void;
          _testApiWaitForIdle(opts?: { timeoutMs?: number }): Promise<void>;
          _testApiDumpResult(): unknown;
          _fileMeta: { name?: string } | null;
          currentResult: { dispatchId?: string } | null;
        };
      };
      // Mock an asRoot directory whose `readEntries` rejects
      // synchronously with EncodingError — exactly what Chromium
      // macOS produces.
      const failingRoot = {
        isFile: false,
        isDirectory: true,
        name: 'Archive',
        fullPath: '/Archive',
        createReader() {
          return {
            readEntries(_ok: (e: unknown[]) => void, err: (e: Error) => void) {
              const e = Object.assign(
                new Error('A URI supplied to the API was malformed or ' +
                          'resulting Data URL has exceeded the URL length ' +
                          'limitations for Data URLs'),
                { name: 'EncodingError' });
              setTimeout(() => err(e), 0);
            },
          };
        },
      };
      // Supply two loose sibling files in the `files` list — the
      // drop-handler forwards these to `_ingestFolderFromEntries` as
      // the fallback bucket.
      const loose = [
        new File(['sibling-one\n'], 'skin.js', { type: 'text/javascript' }),
        new File(['sibling-two\n'], 'readme.txt', { type: 'text/plain' }),
      ];
      w.app._handleFiles(loose, { fsEntries: [failingRoot] });
      await w.app._testApiWaitForIdle({ timeoutMs: 10000 });
      return {
        result: w.app._testApiDumpResult(),
        fileMetaName: w.app._fileMeta && w.app._fileMeta.name,
      };
    });

    // Fallback kicked in — the two loose files become a "Dropped files"
    // synthetic root, NOT an empty `Archive` tree.
    const r = result.result as { dispatchId: string };
    expect(r.dispatchId).toBe('folder');
    expect(result.fileMetaName).toBe('Dropped files');

    // Tree shows both loose siblings, neither of which was the
    // `Archive` directory row.
    const treePaths = await page
      .locator('.folder-view .arch-col-path')
      .allInnerTexts();
    const joined = treePaths.join('\n');
    expect(joined).toContain('skin.js');
    expect(joined).toContain('readme.txt');
    expect(joined).not.toContain('Archive');

    // Toast must NOT say "truncated at 4,096" — pre-fix regression.
    // Instead it explains the fallback. Toast hides after 3 s; we read
    // it synchronously after `_handleFiles` resolves.
    const toastText = await page.locator('#toast').innerText();
    expect(toastText).toContain("Couldn't read folder");
    expect(toastText).toContain('Archive');
    expect(toastText).not.toContain('truncated at 4,096');
  });

  // ── Chromium EncodingError with no loose fallback ─────────────────
  // When the drop carried ONLY the un-readable directory (no sibling
  // files), there's nothing to fall back to. The ingest must abort
  // cleanly with an actionable toast — never dispatch an empty tree.
  test('Chromium EncodingError with no loose files surfaces actionable toast', async ({ page }) => {
    const result = await page.evaluate(async () => {
      const w = window as unknown as {
        app: {
          _handleFiles(files: unknown, opts: { fsEntries: unknown[] }): void;
          _testApiWaitForIdle(opts?: { timeoutMs?: number }): Promise<void>;
          currentResult: { dispatchId?: string } | null;
          _fileMeta: { name?: string } | null;
        };
      };
      const failingRoot = {
        isFile: false,
        isDirectory: true,
        name: 'Archive',
        fullPath: '/Archive',
        createReader() {
          return {
            readEntries(_ok: (e: unknown[]) => void, err: (e: Error) => void) {
              setTimeout(() => err(Object.assign(
                new Error('malformed URI'), { name: 'EncodingError' })), 0);
            },
          };
        },
      };
      // Pre-condition: no file is currently loaded so any state change
      // below would reflect the failing ingest, not residual state.
      w.app._handleFiles(null, { fsEntries: [failingRoot] });
      // Wait for the toast to appear — `_ingestFolderFromEntries`
      // resolves synchronously on the error path.
      await new Promise(r => setTimeout(r, 100));
      return {
        // After the failed ingest, currentResult should still be null
        // (no file was ever loaded).
        afterDispatchId: w.app.currentResult
          ? w.app.currentResult.dispatchId || null
          : null,
        afterFileMetaName: w.app._fileMeta && w.app._fileMeta.name,
      };
    });

    // No empty-tree dispatch — currentResult is still null.
    expect(result.afterDispatchId).toBeNull();

    const toastText = await page.locator('#toast').innerText();
    expect(toastText).toContain("Couldn't read folder");
    expect(toastText).toContain('Archive');
    // Toast points the analyst at a recoverable action — specifically
    // the new "📁 Open ▾ → Open Folder…" menu that the folder-handle
    // fix introduced as the reliable escape hatch on Chromium macOS.
    expect(toastText).toMatch(/Open Folder…|Open ▾/);
    // Pre-fix regression: never claim a 4,096-entry truncation when
    // nothing was truncated.
    expect(toastText).not.toContain('truncated at 4,096');
  });

  // ── Chromium macOS folder pseudo-File regression ──────────────────
  // User report (day after the EncodingError fallback landed): dragging
  // a folder containing a single `file.txt` from macOS Finder threw
  //   NotFoundError: A requested file or directory could not be found at
  //   the time an operation was processed.
  // from inside `_loadFile`. Root cause: on Chromium macOS,
  // `DataTransfer.files` for a folder drop contains the **folder itself**
  // as a synthesised File whose `arrayBuffer()` / `slice().arrayBuffer()`
  // rejects with NotFoundError. The EncodingError fallback then called
  // `_loadFile(pseudoFolderFile)` → uncaught rejection.
  //
  // Post-fix contract: `_filterReadableLooseFiles` drops entries that
  // either (a) share a name with a directory-kind fsEntry, or (b) fail
  // a `slice(0,1).arrayBuffer()` probe. A folder-only drop whose
  // readEntries fails AND whose DataTransfer.files is the folder pseudo-
  // File must fall through to the actionable "use the Open button" toast
  // — no NotFoundError, no empty-tree dispatch.
  test('Chromium macOS folder pseudo-File in DataTransfer.files is filtered before _loadFile', async ({ page }) => {
    // Capture any uncaught page errors so a regression (NotFoundError
    // escaping `_loadFile`) is a hard test failure, not a silent pass.
    const pageErrors: string[] = [];
    page.on('pageerror', (e) => { pageErrors.push(String(e.message || e)); });

    const result = await page.evaluate(async () => {
      const w = window as unknown as {
        app: {
          _handleFiles(files: unknown, opts: { fsEntries: unknown[] }): void;
          _testApiWaitForIdle(opts?: { timeoutMs?: number }): Promise<void>;
          currentResult: { dispatchId?: string } | null;
          _fileMeta: { name?: string } | null;
        };
      };
      const failingRoot = {
        isFile: false,
        isDirectory: true,
        name: 'fold',
        fullPath: '/fold',
        createReader() {
          return {
            readEntries(_ok: (e: unknown[]) => void, err: (e: Error) => void) {
              setTimeout(() => err(Object.assign(
                new Error('malformed URI'), { name: 'EncodingError' })), 0);
            },
          };
        },
      };
      // Fabricate the Chromium macOS "folder pseudo-File" shape:
      // `name` matches the directory entry; `slice(...).arrayBuffer()`
      // rejects with NotFoundError (Node's File/Blob don't do this by
      // default, so we mint a plain object that quacks like File). The
      // `_filterReadableLooseFiles` probe should catch it via EITHER
      // the name-correlation filter OR the probe rejection.
      const pseudoFolder: unknown = {
        name: 'fold',
        size: 0,
        type: '',
        lastModified: Date.now(),
        slice() {
          return {
            async arrayBuffer() {
              throw Object.assign(
                new Error('A requested file or directory could not be found at ' +
                          'the time an operation was processed.'),
                { name: 'NotFoundError' });
            },
          };
        },
        async arrayBuffer() {
          throw Object.assign(
            new Error('A requested file or directory could not be found at ' +
                      'the time an operation was processed.'),
            { name: 'NotFoundError' });
        },
      };
      // Pre-condition: no file is currently loaded.
      w.app._handleFiles([pseudoFolder], { fsEntries: [failingRoot] });
      // The ingest resolves synchronously on the error path; give any
      // microtask queue a tick before sampling state.
      await new Promise(r => setTimeout(r, 250));
      return {
        afterDispatchId: w.app.currentResult
          ? w.app.currentResult.dispatchId || null
          : null,
        afterFileMetaName: w.app._fileMeta && w.app._fileMeta.name,
      };
    });

    // No NotFoundError escaped `_loadFile`. The pre-fix regression would
    // surface here as a synchronous pageerror fired from inside the
    // fallback's `await this._loadFile(loose[0])` call.
    expect(pageErrors.filter(m => /NotFoundError/i.test(m))).toEqual([]);
    // No empty-tree dispatch — the filter removed the pseudo-File before
    // the fallback tried to dispatch it.
    expect(result.afterDispatchId).toBeNull();

    const toastText = await page.locator('#toast').innerText();
    expect(toastText).toContain("Couldn't read folder");
    expect(toastText).toContain('fold');
    expect(toastText).toMatch(/Open Folder…|Open ▾/);
    expect(toastText).not.toContain('truncated at 4,096');
  });

  // ── Auto-expand threshold honoured by ArchiveTree.render('auto') ──
  // The `'auto'` mode used by every real archive renderer expands iff
  // `entries.length <= AUTO_EXPAND_MAX_ENTRIES` (256). Verify the
  // threshold directly against `ArchiveTree.render` so we're not
  // dependent on fabricating a 257-entry archive fixture.
  test('ArchiveTree expandAll: \"auto\" expands small trees and skips huge ones', async ({ page }) => {
    const result = await page.evaluate(() => {
      // @ts-expect-error - ArchiveTree is a top-level class binding in the bundle
      const Tree = ArchiveTree as {
        AUTO_EXPAND_MAX_ENTRIES: number;
        render(opts: unknown): HTMLElement;
      };
      const cap = Tree.AUTO_EXPAND_MAX_ENTRIES;
      const mk = (n: number) => {
        const entries: { path: string; dir: boolean; size: number }[] = [];
        entries.push({ path: 'big', dir: true, size: 0 });
        for (let i = 0; i < n - 1; i++) {
          entries.push({ path: 'big/file' + i + '.txt', dir: false, size: 1 });
        }
        return entries;
      };
      const small = Tree.render({ entries: mk(cap), expandAll: 'auto' });
      const large = Tree.render({ entries: mk(cap + 1), expandAll: 'auto' });
      return {
        cap,
        smallExpanded: small.querySelectorAll(
          '.arch-tree-folder-row[aria-expanded="true"]').length,
        smallCollapsed: small.querySelectorAll(
          '.arch-tree-folder-row[aria-expanded="false"]').length,
        largeExpanded: large.querySelectorAll(
          '.arch-tree-folder-row[aria-expanded="true"]').length,
        largeCollapsed: large.querySelectorAll(
          '.arch-tree-folder-row[aria-expanded="false"]').length,
      };
    });
    expect(result.cap).toBe(256);
    // Small tree (≤ cap): the `big` folder opens.
    expect(result.smallExpanded).toBeGreaterThanOrEqual(1);
    expect(result.smallCollapsed).toBe(0);
    // Large tree (> cap): folder stays collapsed.
    expect(result.largeExpanded).toBe(0);
    expect(result.largeCollapsed).toBeGreaterThanOrEqual(1);
  });
});
