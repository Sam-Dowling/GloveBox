'use strict';
// ════════════════════════════════════════════════════════════════════════════
// folder-renderer.js — synthetic-archive renderer for dropped folders
//
// Loupe receives folders (drag-drop of a directory, or a multi-file loose
// drop / file-picker selection) by synthesising a `FolderFile` —
// see `src/folder-file.js`. That synthetic File-like carries a flat
// `_loupeFolderEntries` list and zero on-disk bytes; the registry
// dispatches it to this renderer via the `folder` magic predicate that
// keys on `ctx.file._loupeFolderEntries`.
//
// Behaviour
// ─────────
//   • Reuses `ArchiveTree` (`src/renderers/archive-tree.js`) — same UI as
//     ZIP / MSIX / JAR / browserext, same tree/flat toggle, same search,
//     same keyboard navigation. Drill-down is the standard
//     `open-inner-file` `CustomEvent` already wired by
//     `App._wireInnerFileListener` (`app-load.js`).
//   • Risk model: folder roots themselves are inert (zero bytes, no
//     parser). Per-file YARA / encoded-content / IOC sweeps run when the
//     analyst opens a child via the tree — exactly the same code paths as
//     drilling into a ZIP entry. We DO emit a small set of folder-level
//     filename heuristics (executable count, archive depth, encoded-name
//     hints) as `IOC.PATTERN` rows mirrored into `externalRefs` so the
//     summary panel and `escalateRisk` ladder see them.
//   • Aggregate budget: the `_archiveBudget` on `App` is reset by
//     `_handleFiles` for the top-level folder load. Sibling navigation
//     (Back to folder root → click another child) re-resets the budget
//     in `App._restoreNavFrame` when the restored frame's
//     `currentResult.dispatchId === 'folder'` — without this, walking
//     six siblings sequentially would exhaust the 50 k-entry global cap.
//
// Contract is the canonical renderer skeleton (see CONTRIBUTING.md):
//   • `static render(file, buffer, app)` — mutates `app.findings` in
//     place, returns an `HTMLElement` (the wrap), and never bumps
//     `_renderEpoch` (only `_setRenderResult` is allowed to do that).
//   • `app._wireInnerFileListener(docEl, file.name)` is wired by
//     `app-load.js`'s `_rendererDispatch.folder` handler — this file
//     just builds the DOM and emits the standard `open-inner-file`
//     events on each `onOpen` click.
// ════════════════════════════════════════════════════════════════════════════

class FolderRenderer {

  /**
   * @param {FolderFile} file
   * @param {ArrayBuffer} buffer  Always zero bytes for folder roots.
   * @param {App} app
   * @returns {HTMLElement}
   */
  static render(file, buffer, app) {
    const wrap = document.createElement('div');
    wrap.className = 'folder-view';

    const entries = (file && file._loupeFolderEntries) || [];

    // ── Header ───────────────────────────────────────────────────────────
    // Single banner row above the ArchiveTree giving the analyst a hint
    // that this isn't a real on-disk archive but a synthetic root the
    // tool fabricated from a folder drop.
    const fileCount = entries.filter(e => !e.dir).length;
    const dirCount  = entries.filter(e =>  e.dir).length;
    const totalSize = entries.reduce(
      (n, e) => n + (e.dir ? 0 : (Number.isFinite(e.size) ? e.size : 0)), 0);
    const sizeLabel = (typeof fmtBytes === 'function')
      ? fmtBytes(totalSize)
      : (totalSize + ' B');

    const header = document.createElement('div');
    header.className = 'folder-header';
    const title = document.createElement('div');
    title.className = 'folder-title';
    title.textContent = '📁 ' + (file && file.name ? file.name : 'Folder');
    const summary = document.createElement('div');
    summary.className = 'folder-summary';
    summary.textContent =
      `${fileCount.toLocaleString()} file${fileCount === 1 ? '' : 's'}` +
      `${dirCount ? `, ${dirCount.toLocaleString()} folder${dirCount === 1 ? '' : 's'}` : ''}` +
      ` — ${sizeLabel} total`;
    const note = document.createElement('div');
    note.className = 'folder-note';
    note.textContent =
      'Synthetic folder root — no auto-analysis runs at this level. ' +
      'Click a file to load and analyse it; ⏎ on a focused row works too.';
    header.appendChild(title);
    header.appendChild(summary);
    header.appendChild(note);
    wrap.appendChild(header);

    // ── Tree ──────────────────────────────────────────────────────────────
    // ArchiveTree consumes our `{path, dir, size, file?}` shape directly.
    // The `_file` back-reference on each entry survives because
    // ArchiveTree treats unknown fields opaquely and hands the original
    // entry back to `onOpen`.
    const archEntries = entries.map(e => ({
      path: e.path,
      dir: !!e.dir,
      size: e.size || 0,
      date: e.mtime || null,
      _file: e.file || null,
    }));

    const tree = ArchiveTree.render({
      entries: archEntries,
      onOpen: (entry) => {
        const f = entry && entry._file;
        if (!f) return; // directory rows are no-op (ArchiveTree auto-skips)
        wrap.dispatchEvent(new CustomEvent('open-inner-file', {
          bubbles: true,
          detail: f,
        }));
      },
      showDate: true,
      emptyText: 'Folder is empty.',
      // Synthetic roots open fully expanded — the analyst just dropped
      // these in and wants the whole structure visible immediately.
      // Hard-capped at PARSER_LIMITS.MAX_FOLDER_ENTRIES (4 096) so a
      // first-paint expand-all is bounded by construction.
      expandAll: true,
    });
    wrap.appendChild(tree);

    // ── Findings: filename-heuristic IOCs + analyse hook ────────────────
    // analyzeForSecurity returns a fresh findings object; the dispatch
    // handler in app-load.js assigns it to `app.findings` BEFORE this
    // file's render() returns its HTMLElement (renderer-skeleton
    // contract: handler does `app.findings = analyze(...); return
    // render(...)`). Analyser is split out so it can be exercised
    // directly by unit tests without going through the DOM path.
    return wrap;
  }

  /**
   * Build a fresh findings object for a folder root. The folder itself is
   * inert — auto-YARA / encoded-content / IOC sweeps are SKIPPED on the
   * synthetic root. We do, however, surface filename-heuristic signal as
   * `IOC.PATTERN` rows mirrored into `externalRefs`, so:
   *   • the sidebar shows useful "what's worth opening?" hints,
   *   • `escalateRisk` sees high-severity rows when the folder contains
   *     known-bad shapes (RTLO, double-extension decoy, native binaries).
   *
   * Heuristic catalogue (kept deliberately small — analyst-as-source-of-truth):
   *   • RTL-override Unicode in any path  — high (T1036.002 mascot).
   *   • Double extension on a leaf
   *     (`*.{pdf,doc,docx,jpg,png,gif,txt}.{exe,scr,bat,ps1,vbs,js,cmd,
   *      cpl,com,pif,hta,jar,lnk}`) — high.
   *   • Executable count  ≥ 3 distinct exec-extension leaves — medium.
   *   • Archive count     ≥ 2 archive-extension leaves        — low.
   *   • Truncation INFO row when the walker hit MAX_FOLDER_ENTRIES.
   *
   * The folder root never emits `IOC.URL` / `IOC.IP` / etc. — those only
   * arise from byte content, which is the responsibility of each child's
   * own renderer when the analyst drills in.
   */
  static analyzeForSecurity(file, opts) {
    const findings = {
      risk: 'low',
      externalRefs: [],
      interestingStrings: [],
      metadata: {},
    };
    const entries = (file && file._loupeFolderEntries) || [];
    const truncated = !!(opts && opts.truncated);
    const walkErrors = (opts && Array.isArray(opts.walkErrors))
      ? opts.walkErrors : [];
    const dirWalkFailures = walkErrors.filter(w => w && w.kind === 'dir');
    const hasDirWalkFailure = dirWalkFailures.length > 0;

    const fileCount = entries.filter(e => !e.dir).length;
    const dirCount  = entries.filter(e =>  e.dir).length;
    findings.metadata = {
      'Folder name': file && file.name ? file.name : '(unnamed)',
      'File count': fileCount,
      'Directory count': dirCount,
    };

    // Distinguish "browser refused to enumerate a directory" from
    // "walker hit MAX_FOLDER_ENTRIES cap". The former is a Chromium
    // macOS `EncodingError` on `readEntries()` (fatal-for-descriptor
    // browser bug); the latter is the legitimate 4 096-entry cap. The
    // ingest caller (`App._ingestFolderFromEntries`) already surfaces a
    // toast on both paths; the sidebar IOC rows below give the analyst
    // a persistent audit trail in Summary / STIX / MISP exports.
    if (hasDirWalkFailure) {
      const first = dirWalkFailures[0] || {};
      const errTag = first.name
        ? `${first.name}: ${first.message || ''}`.trim()
        : 'the browser refused to enumerate';
      pushIOC(findings, {
        type: IOC.INFO,
        value:
          `Folder walk failed for ${dirWalkFailures.length.toLocaleString()} ` +
          `subdirector${dirWalkFailures.length === 1 ? 'y' : 'ies'} ` +
          `(${errTag}). This is a Chromium FileSystem API limitation on ` +
          'macOS — drill-down results reflect only the readable subset.',
        severity: 'info',
      });
    } else if (truncated) {
      pushIOC(findings, {
        type: IOC.INFO,
        value:
          `Folder ingest truncated at ${
            (PARSER_LIMITS.MAX_FOLDER_ENTRIES || 4096).toLocaleString()
          } entries — deeper / later siblings were skipped to bound memory. ` +
          'Re-drop a smaller subtree if you need full coverage.',
        severity: 'info',
      });
    }

    // Filename-heuristic helpers ──────────────────────────────────────
    const EXEC_EXTS = new Set([
      'exe', 'dll', 'scr', 'com', 'pif', 'cpl', 'msi', 'msp', 'mst', 'sys',
      'bat', 'cmd', 'ps1', 'psm1', 'psd1', 'vbs', 'vbe', 'js', 'jse',
      'wsf', 'wsh', 'wsc', 'hta', 'lnk', 'inf', 'reg', 'sct',
      'jar', 'class', 'py', 'rb', 'sh', 'bash',
    ]);
    const ARCHIVE_EXTS = new Set([
      'zip', 'rar', '7z', 'tar', 'gz', 'tgz', 'cab', 'iso', 'dmg', 'pkg',
      'msi', 'msix', 'msixbundle', 'appx', 'appxbundle',
      'jar', 'war', 'ear', 'crx', 'xpi',
    ]);
    const DECOY_LEFT_EXTS = new Set([
      'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
      'jpg', 'jpeg', 'png', 'gif', 'txt', 'rtf',
    ]);
    const DECOY_RIGHT_EXTS = new Set([
      'exe', 'scr', 'bat', 'ps1', 'vbs', 'js', 'cmd',
      'cpl', 'com', 'pif', 'hta', 'jar', 'lnk', 'wsf',
    ]);

    let execCount = 0;
    let archCount = 0;
    const sawExec = new Set();      // dedup by basename so 12 copies count once
    const rtloHits = [];
    const decoyHits = [];

    for (const e of entries) {
      if (e.dir) continue;
      const path = e.path || '';
      const lower = path.toLowerCase();
      const base  = path.split('/').pop() || '';
      const segs  = base.split('.');
      const ext   = segs.length > 1 ? segs[segs.length - 1].toLowerCase() : '';
      const ext2  = segs.length > 2 ? segs[segs.length - 2].toLowerCase() : '';

      // RTL override (U+202E) anywhere in the path.
      if (path.indexOf('\u202E') !== -1) rtloHits.push(path);

      // Double extension: <decoy>.<exec>
      if (ext2 && DECOY_LEFT_EXTS.has(ext2) && DECOY_RIGHT_EXTS.has(ext)) {
        decoyHits.push(path);
      }

      if (EXEC_EXTS.has(ext)) {
        if (!sawExec.has(lower)) { sawExec.add(lower); execCount++; }
      }
      if (ARCHIVE_EXTS.has(ext)) archCount++;
    }

    // ── Emit rows. Mirror Detection-class rows into externalRefs as
    //    IOC.PATTERN per the renderer-skeleton contract — without this
    //    they're invisible to risk-calc / Summary / STIX / MISP.
    for (const path of rtloHits.slice(0, 5)) {
      pushIOC(findings, {
        type: IOC.PATTERN,
        value: 'RTL-override in filename: ' + path,
        severity: 'high',
        bucket: 'externalRefs',
      });
    }
    for (const path of decoyHits.slice(0, 5)) {
      pushIOC(findings, {
        type: IOC.PATTERN,
        value: 'Double-extension decoy: ' + path,
        severity: 'high',
        bucket: 'externalRefs',
      });
    }
    if (execCount >= 3) {
      pushIOC(findings, {
        type: IOC.PATTERN,
        value: `${execCount} distinct executable-extension files in folder — review before opening`,
        severity: 'medium',
        bucket: 'externalRefs',
      });
    }
    if (archCount >= 2) {
      pushIOC(findings, {
        type: IOC.PATTERN,
        value: `${archCount} archive-extension files in folder — possible nested-payload chain`,
        severity: 'low',
        bucket: 'externalRefs',
      });
    }

    // Evidence-driven risk escalation — same ladder every renderer uses.
    const refs = findings.externalRefs;
    const hasHigh = refs.some(r => r.severity === 'high');
    const hasMed  = refs.some(r => r.severity === 'medium');
    const hasLow  = refs.some(r => r.severity === 'low');
    if      (hasHigh) escalateRisk(findings, 'high');
    else if (hasMed)  escalateRisk(findings, 'medium');
    else if (hasLow)  escalateRisk(findings, 'low');

    return findings;
  }
}

if (typeof window !== 'undefined') window.FolderRenderer = FolderRenderer;
